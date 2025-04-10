package logtoWrapper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/gclient"
)

type RequestInfo struct {
	Method        string
	URL           string
	Proto         string
	Header        http.Header
	ContentLength int64
	Body          string // 新增字段用于存储请求体信息
}
type ResponseInfo struct {
	StatusCode    int
	Status        string
	Proto         string
	Header        http.Header
	ContentLength int64
	Body          string
}

type M2MTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpireIn    int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// M2MTokenManager 单例结构体
type M2MAccessTokenManager struct {
	ctx   context.Context
	token *M2MTokenResponse
}

func (m *M2MAccessTokenManager) Init(ctx context.Context) {
	if m.token == nil {
		m.ctx = ctx
		m.token = &M2MTokenResponse{}
		m.token.InitAccessToken(ctx)
	}
}

func (m *M2MAccessTokenManager) InitCustom(opts InitCustomAccessTokenOptions) {
	if m.token == nil {
		m.ctx = opts.Ctx
		m.token = &M2MTokenResponse{}
		m.token.InitCustomAccessToken(opts)
	}
}

func (m *M2MAccessTokenManager) GetToken() *M2MTokenResponse {
	if m.token == nil {
		return nil
	}
	if isExped, _ := m.token.isExpired(); isExped {
		m.token.InitAccessToken(m.ctx)
	}
	return m.token
}
func (m *M2MAccessTokenManager) SendRequest(method string, api string, query url.Values, data interface{}) (*gclient.Response, error) {
	cfg := g.Cfg()
	endPoint := cfg.MustGet(m.ctx, "logto.m2mEndpoint", "").String()
	client := g.Client()
	apiUrl := fmt.Sprintf("%s"+api, endPoint)
	if len(query) > 0 {
		queryString := query.Encode()
		q := "?"
		if strings.Index(apiUrl, "?") > 0 {
			q = "&"
		}
		apiUrl = apiUrl + q + queryString
	}
	token := m.GetToken()
	client.SetHeader("Authorization", "Bearer "+token.AccessToken)
	client.SetHeader("Content-Type", "application/json")
	// g.Log().Debugf(m.ctx, "SendRequest: url = %+v; client = %+v", apiUrl, client)
	var response *gclient.Response
	var err error
	switch method {
	case "GET":
		response, err = client.Get(m.ctx, apiUrl, data)
	case "POST":
		response, err = client.Post(m.ctx, apiUrl, data)
	case "PATCH":
		response, err = client.Patch(m.ctx, apiUrl, data)
	case "PUT":
		response, err = client.Put(m.ctx, apiUrl, data)
	case "DELETE":
		response, err = client.Delete(m.ctx, apiUrl, data)
	}
	if err != nil {
		g.Log().Errorf(m.ctx, "发送请求出错: %v", err)
		return nil, err
	}
	// defer response.Close()
	return response, nil
}
func (m *M2MAccessTokenManager) GetRequest(api string, params url.Values) (*gclient.Response, error) {
	return m.SendRequest("GET", api, params, nil)
}
func (m *M2MAccessTokenManager) PostRequest(api string, params url.Values, data interface{}) (*gclient.Response, error) {
	return m.SendRequest("POST", api, params, data)
}
func (m *M2MAccessTokenManager) PatchRequest(api string, params url.Values, data interface{}) (*gclient.Response, error) {
	return m.SendRequest("PATCH", api, params, data)
}
func (m *M2MAccessTokenManager) PutRequest(api string, params url.Values, data interface{}) (*gclient.Response, error) {
	return m.SendRequest("PUT", api, params, data)
}
func (m *M2MAccessTokenManager) DeleteRequest(api string, params url.Values, data interface{}) (*gclient.Response, error) {
	return m.SendRequest("DELETE", api, params, data)
}

func (token *M2MTokenResponse) TokenFormat() ([]interface{}, error) {
	tokenParts := strings.Split(token.AccessToken, ".")
	var tokenPartsResult []interface{}
	for i, part := range tokenParts {
		// Base64 解码
		var decoded []byte
		var err1 error
		if i < 2 {
			decoded, err1 = base64.RawURLEncoding.DecodeString(part)
			if err1 != nil {
				return nil, errors.New("DecodeString error = " + err1.Error())
			}
		} else {
			decoded = []byte(part)
		}

		if i < 2 { // 假设前两个元素是 JSON 字符串
			var data interface{}
			// JSON 解析
			err2 := json.Unmarshal(decoded, &data)
			if err2 != nil {
				return nil, errors.New("DecodeString error = " + err2.Error())
			}
			tokenPartsResult = append(tokenPartsResult, data)
		} else {
			tokenPartsResult = append(tokenPartsResult, string(decoded))
		}
	}
	return tokenPartsResult, nil
}
func (token *M2MTokenResponse) isExpired() (bool, error) {
	if token == nil {
		return true, fmt.Errorf("token is nil")
	}
	parts := strings.Split(token.AccessToken, ".")
	if len(parts) != 3 {
		return true, fmt.Errorf("AccessToken format is invalid")
	}
	rawBody, decodeBodyErr := base64.RawURLEncoding.DecodeString(parts[1])
	/// fmt.Println("rawBody = ", string(rawBody))
	if decodeBodyErr != nil {
		return true, decodeBodyErr
	}
	var body struct {
		Exp int64 `json:"exp"`
	}
	unmarshalErr := json.Unmarshal(rawBody, &body)
	// fmt.Println("body = ", body)
	if unmarshalErr != nil {
		return true, unmarshalErr
	}
	now := time.Now().Unix()
	// fmt.Println("exp = ", body.Exp, "now = ", now, "isExp = ", body.Exp < now)
	if body.Exp > now {
		return false, nil
	} else {
		return true, nil
	}
}

func (token *M2MTokenResponse) InitAccessToken(ctx context.Context) error {
	return token.InitCustomAccessToken(InitCustomAccessTokenOptions{
		Ctx:         ctx,
		FromConfig:  true,
		EndPoint:    "logto.m2mEndpoint",
		AppId:       "logto.m2mAppId",
		AppSecret:   "logto.m2mAppSecret",
		Resources:   "logto.m2mResources",
		RedisPrefix: "m2mToken_",
		ApiScopes:   "all",
	})
}

type InitCustomAccessTokenOptions struct {
	Ctx         context.Context
	FromConfig  bool   // true
	EndPoint    string // logto.m2mEndpoint
	AppId       string // logto.m2mAppId
	AppSecret   string // logto.m2mAppSecret
	Resources   string // logto.m2mResources
	RedisPrefix string // m2mToken@
	ApiScopes   string // all

}

func (token *M2MTokenResponse) InitCustomAccessToken(opts InitCustomAccessTokenOptions) error {
	var endPoint, appId, appSecret, resources string
	if opts.FromConfig {
		cfg := g.Cfg()
		endPoint = cfg.MustGet(opts.Ctx, opts.EndPoint, "").String()
		appId = cfg.MustGet(opts.Ctx, opts.AppId, "").String()
		appSecret = cfg.MustGet(opts.Ctx, opts.AppSecret, "").String()
		resources = cfg.MustGet(opts.Ctx, opts.Resources, "").String()
		// resKey := base64.StdEncoding.EncodeToString([]byte(resources))
	} else {
		endPoint = opts.EndPoint
		appId = opts.AppId
		appSecret = opts.AppSecret
		resources = opts.Resources
	}

	resKey := resources
	redis := g.Redis()
	cM2MToken, _ := redis.Get(opts.Ctx, opts.RedisPrefix+resKey)
	if cM2MToken != nil && cM2MToken.String() != "" {
		json.Unmarshal([]byte(cM2MToken.String()), &token)
		expired, err := token.isExpired()
		if err != nil {
			return err
		}
		if !expired {
			result, _ := token.TokenFormat()
			formatted, _ := json.MarshalIndent(result, "", "  ")
			log.Printf("M2MToken Init From Cache: %+v = %s\n", resources, formatted)
			log.Printf("M2MToken = %s\n", token.AccessToken)
			return nil
		}
	}
	httpClient := &http.Client{}
	tokenEndpoint := endPoint + "/oidc/token"
	apiEndpoint := resources
	values := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {appId},
		"client_secret": {appSecret},
		"resource":      {apiEndpoint},
		"scope":         {opts.ApiScopes},
	}
	request, reqErr := http.NewRequest("POST", tokenEndpoint, strings.NewReader(values.Encode()))
	if reqErr != nil {
		return reqErr
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reader, _ := request.GetBody()
	requestBody, _ := io.ReadAll(reader)
	requestInfo := RequestInfo{
		Method:        request.Method,
		URL:           request.URL.String(),
		Proto:         request.Proto,
		Header:        request.Header,
		ContentLength: request.ContentLength,
		Body:          string(requestBody),
	}
	requestJSON, _ := json.MarshalIndent(requestInfo, "", "  ")
	log.Println("request = ", string(requestJSON))
	response, resErr := httpClient.Do(request)
	if resErr != nil {
		return resErr
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)
	responseInfo := ResponseInfo{
		StatusCode:    response.StatusCode,
		Status:        response.Status,
		Proto:         response.Proto,
		Header:        response.Header,
		ContentLength: response.ContentLength,
		Body:          string(responseBody),
	}
	responseJSON, _ := json.MarshalIndent(responseInfo, "", "  ")
	log.Println("response = ", string(responseJSON))
	json.Unmarshal(responseBody, &token)
	tokenJSONString, tokenJSONStrErr := json.Marshal(token)
	if tokenJSONStrErr != nil {
		return tokenJSONStrErr
	}
	redis.Set(opts.Ctx, opts.RedisPrefix+resKey, string(tokenJSONString))
	result, _ := token.TokenFormat()
	formatted, _ := json.MarshalIndent(result, "", "  ")
	log.Printf("M2MToken Init From Request: %+v = %s\n", resources, formatted)
	log.Printf("M2MToken = %s\n", token.AccessToken)
	return nil
}

// var M2MToken = &M2MTokenResponse{}
var M2MTokenManager = &M2MAccessTokenManager{}
