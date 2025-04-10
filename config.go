package logtoWrapper

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/logto-io/go/v2/client"
)

const (
	// 存储query指定的res和scopes以便保持再次创建LogtoClient
	SessionKeyQueryResources = "session_key_query_resources"
	SessionKeyQueryScopes    = "session_key_query_scopes"
)

type LoadLogtoConfigOptions struct {
	Ctx         context.Context // 上下文必须提供
	IsConfig    bool            // 是否根据项目的config.yaml配置文件来追加Resources和Scopes
	Resources   string          // 直接向Resources追加
	Scopes      string          // 直接向Scopes追加
	IsRequest   bool            // 是否从GET请求的res和scopes参数中对Resources和Scopes进行追加, 如果没有则从缓存中获取并追加
	IsStorage   bool            // 是否直接从缓存中获取并追加Resources和Scopes, 此时IsRequest必须为false
	StorageType string          // 存储类型session, redis
	SessionId   string          // 档StorageType=redis时使用, 不是必须
}

// 使用反射读取logtoClient受保护字段logtoConfig的Scopes字段的值并判断是否包含组织scope申请
func AuthStepScopeHasOrganizationsScope(logtoClient client.LogtoClient) (bool, error) {
	// 获取 LogtoClient 结构体的反射值
	value := reflect.ValueOf(logtoClient)
	// 获取 logtoConfig 字段的值
	logtoConfigField := value.FieldByName("logtoConfig")
	if !logtoConfigField.IsValid() {
		return false, errors.New("未找到 logtoConfig 字段")
	}
	// 如果 logtoConfig 是指针，需要解引用
	if logtoConfigField.Kind() == reflect.Ptr {
		if logtoConfigField.IsNil() {
			return false, errors.New("logtoConfig 字段为 nil")
		}
		logtoConfigField = logtoConfigField.Elem()
	}

	// 获取 Scopes 字段的值
	scopesField := logtoConfigField.FieldByName("Scopes")
	if !scopesField.IsValid() {
		return false, errors.New("未找到 Scopes 字段")
	}

	// 将 Scopes 字段的值转换为 []string 类型
	scopes := make([]string, scopesField.Len())
	for i := 0; i < scopesField.Len(); i++ {
		scopes[i] = scopesField.Index(i).String()
	}

	targetScope := "urn:logto:scope:organizations"
	scopeString := strings.Join(scopes, " ")
	// fmt.Printf("scopeString = %+v\n", scopeString)
	return strings.Contains(scopeString, targetScope), nil
}

// 根据opts参数要求创建一个LogtoConfig实例并返回
func GetLogtoConfig(opts LoadLogtoConfigOptions) (*client.LogtoConfig, error) {
	var ctx = gctx.WithCtx(opts.Ctx)
	cfg := g.Cfg()
	endPoint := cfg.MustGet(ctx, "logto.endpoint", "")
	appId := cfg.MustGet(ctx, "logto.appId", "")
	appSecret := cfg.MustGet(ctx, "logto.appSecret", "")
	if endPoint.String() == "" || appId.String() == "" || appSecret.String() == "" {
		return nil, errors.New("logto 必要配置缺失")
	}
	logtoConfig := &client.LogtoConfig{
		Endpoint:  endPoint.String(),
		AppId:     appId.String(),
		AppSecret: appSecret.String(),
		Scopes:    []string{"openid", "profile", "offline_access", "email", "phone"},
		Resources: []string{},
	}

	if opts.IsConfig {
		resources, resErr := cfg.Get(ctx, "logto.resources")
		if resErr == nil && resources.String() != "" {
			logtoConfig.Resources = strings.Split(resources.String(), ",")
		}

		scopesString, scopesErr := cfg.Get(ctx, "logto.scopes")
		if scopesErr == nil && scopesString.String() != "" {
			scopes := strings.Split(scopesString.String(), ",")
			logtoConfig.Scopes = append(logtoConfig.Scopes, scopes...)
		}
	}
	var paramRes, paramScope, reqRes, reqScope, storageRes, storageScope []string
	if opts.Resources != "" {
		paramRes = strings.Split(opts.Resources, ",")
		logtoConfig.Resources = append(logtoConfig.Resources, paramRes...)
	}
	if opts.Scopes != "" {
		paramScope = strings.Split(opts.Scopes, ",")
		logtoConfig.Scopes = append(logtoConfig.Scopes, paramScope...)
	}

	if opts.IsRequest {
		var req *ghttp.Request = g.RequestFromCtx(ctx)
		if qRes := req.GetQuery("res", ""); qRes.String() != "" {
			reqRes = strings.Split(qRes.String(), ",")
			req.Session.Set(SessionKeyQueryResources, qRes.String())
			logtoConfig.Resources = append(logtoConfig.Resources, reqRes...)
		} else if qRes := req.Session.MustGet(SessionKeyQueryResources, ""); qRes.String() != "" {
			storageRes = strings.Split(qRes.String(), ",")
			logtoConfig.Resources = append(logtoConfig.Resources, storageRes...)
		}
		if qScopes := req.GetQuery("scopes", ""); qScopes.String() != "" {
			reqScope = strings.Split(qScopes.String(), ",")
			req.Session.Set(SessionKeyQueryScopes, qScopes.String())
			logtoConfig.Scopes = append(logtoConfig.Scopes, reqScope...)
		} else if qScopes := req.Session.MustGet(SessionKeyQueryScopes, ""); qScopes.String() != "" {
			storageScope = strings.Split(qScopes.String(), ",")
			logtoConfig.Scopes = append(logtoConfig.Scopes, storageScope...)
		}
	}
	if opts.IsStorage && !opts.IsRequest {
		var req *ghttp.Request = g.RequestFromCtx(ctx)
		if len(reqRes) == 0 {
			qRes := req.Session.MustGet(SessionKeyQueryResources, nil)
			if qRes != nil {
				storageRes = strings.Split(qRes.String(), ",")
				logtoConfig.Resources = append(logtoConfig.Resources, storageRes...)
			}
		}
		if len(reqScope) == 0 {
			qScopes := req.Session.MustGet(SessionKeyQueryScopes, nil)
			if qScopes != nil {
				storageScope = strings.Split(qScopes.String(), ",")
				logtoConfig.Scopes = append(logtoConfig.Scopes, storageScope...)
			}
		}
	}
	return logtoConfig, nil
}

// 根据opts参数要求创建一个LogtoClient实例并返回
func GetLogtoClient(opts LoadLogtoConfigOptions) (*client.LogtoClient, error) {
	logtoConfig, cfgErr := GetLogtoConfig(opts)
	if cfgErr != nil {
		return nil, cfgErr
	}
	fmt.Printf("logtoConfig = %+v\n", logtoConfig)
	var storage client.Storage
	if opts.StorageType == "redis" {
		storage = InitHttpDefaultRedisStorage(opts.Ctx, opts.SessionId)
	} else {
		storage = InitHttpDefaultSessionStorage(opts.Ctx)
	}

	fmt.Printf("sessionStorage.idToken = %+v\n", storage.GetItem(client.StorageKeyIdToken))
	logtoClient := client.NewLogtoClient(logtoConfig, storage)
	return logtoClient, nil
}
