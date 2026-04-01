# 数据库设计 - Redis降级策略

**文档版本**: v1.0  
**更新日期**: 2026-04-01

---

## 1. 降级策略

```go
// internal/storage/cache.go
type CacheWrapper struct {
    redis       *redis.Client
    localCache  *sync.Map  // 降级到本地内存
    degraded    atomic.Bool
}

func (c *CacheWrapper) Get(ctx context.Context, key string) (string, error) {
    // 优先使用Redis
    if !c.degraded.Load() {
        val, err := c.redis.Get(ctx, key).Result()
        if err == nil {
            return val, nil
        }
        
        // Redis故障，切换降级模式
        if isRedisError(err) {
            c.enterDegradedMode()
        }
    }
    
    // 降级模式：使用本地缓存
    if val, ok := c.localCache.Load(key); ok {
        return val.(string), nil
    }
    
    return "", errors.New("cache miss")
}

func (c *CacheWrapper) Set(ctx context.Context, key, value string, ttl time.Duration) error {
    // 同时写入Redis和本地缓存
    if !c.degraded.Load() {
        if err := c.redis.Set(ctx, key, value, ttl).Err(); err != nil {
            if isRedisError(err) {
                c.enterDegradedMode()
            }
        }
    }
    
    // 写入本地缓存
    c.localCache.Store(key, value)
    
    // 设置本地缓存过期（使用time.AfterFunc）
    if ttl > 0 {
        time.AfterFunc(ttl, func() {
            c.localCache.Delete(key)
        })
    }
    
    return nil
}
```

---

## 2. 自动恢复

```go
func (c *CacheWrapper) enterDegradedMode() {
    if c.degraded.CompareAndSwap(false, true) {
        log.Warn("Redis unavailable, entering degraded mode")
        go c.tryRecover()
    }
}

func (c *CacheWrapper) tryRecover() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        if c.redis.Ping(context.Background()).Err() == nil {
            c.degraded.Store(false)
            log.Info("Redis recovered, exiting degraded mode")
            return
        }
    }
}
```
