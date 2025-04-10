package logtoWrapper

import (
	"context"

	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/gsession"
)

type SessionStorage struct {
	session *gsession.Session
}

type RedisStorage struct {
	ctx       context.Context
	sessionId string
	prefix    string
	redis     *gredis.Redis
}

func InitHttpDefaultSessionStorage(pCtx context.Context) *SessionStorage {
	var ctx context.Context = gctx.WithCtx(pCtx)
	req := g.RequestFromCtx(ctx)
	session := SessionStorage{session: req.Session}
	return &session
}

func InitHttpDefaultRedisStorage(pCtx context.Context, sessionId string) *RedisStorage {
	var ctx context.Context = gctx.WithCtx(pCtx)
	redis := g.Redis()
	storage := RedisStorage{
		ctx:       ctx,
		prefix:    "RedisStorage_",
		sessionId: sessionId + "_",
		redis:     redis,
	}
	return &storage
}

func (storage *SessionStorage) GetItem(key string) string {
	value, err := storage.session.Get(key)
	if value.IsNil() || err != nil {
		return ""
	}
	// 将获取的值转换为字符串类型
	return value.String()
}

func (storage *SessionStorage) SetItem(key, value string) {
	// 使用 gsession 的 Set 方法设置值
	storage.session.Set(key, value)
	// GoFrame 会自动保存 Session，不需要显式调用 Save
}

func (storage *RedisStorage) GetItem(key string) string {
	finalKey := storage.prefix + storage.sessionId + key
	value, err := storage.redis.Get(storage.ctx, finalKey)
	if value.String() == "" || err != nil {
		return ""
	}
	return value.String()
	/*
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		redis := g.Redis()
		finalKey := "RedisStorage_" + key
		value, err := redis.Get(ctx, finalKey)
		if value.String() == "" || err != nil {
			return ""
		}
		return value.String()
	*/
}

func (storage *RedisStorage) SetItem(key, value string) {
	finalKey := storage.prefix + storage.sessionId + key
	storage.redis.Set(storage.ctx, finalKey, value)
	/*
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		redis := g.Redis()
		finalKey := "RedisStorage_" + key
		redis.Set(ctx, finalKey, value)
	*/
}
