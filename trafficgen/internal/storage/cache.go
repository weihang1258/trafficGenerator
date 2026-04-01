// Package cache provides caching functionality.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Cache provides caching with Redis and local fallback.
type Cache struct {
	redis      *redis.Client
	localCache *sync.Map
	degraded   bool
	mu         sync.RWMutex
	ttl        time.Duration
}

// Config for cache.
type Config struct {
	Addr     string
	Password string
	DB       int
	PoolSize int
	TTL      time.Duration
}

// New creates a new cache instance.
func New(cfg Config) (*Cache, error) {
	c := &Cache{
		localCache: &sync.Map{},
		ttl:        cfg.TTL,
	}

	if cfg.TTL == 0 {
		c.ttl = 5 * time.Minute
	}

	// Try to connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		zap.L().Warn("redis connection failed, using local cache",
			zap.Error(err),
			zap.String("addr", cfg.Addr),
		)
		c.degraded = true
		rdb.Close()
	} else {
		c.redis = rdb
		zap.L().Info("redis connected",
			zap.String("addr", cfg.Addr),
		)
	}

	return c, nil
}

// Get retrieves a value from cache.
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	if c.IsDegraded() {
		// Use local cache
		if val, ok := c.localCache.Load(key); ok {
			if entry, ok := val.(*cacheEntry); ok {
				if time.Now().Before(entry.expires) {
					return entry.value, nil
				}
				c.localCache.Delete(key)
			}
		}
		return "", redis.Nil
	}

	return c.redis.Get(ctx, key).Result()
}

// Set stores a value in cache.
func (c *Cache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.ttl
	}

	if c.IsDegraded() {
		// Use local cache
		c.localCache.Store(key, &cacheEntry{
			value:   value,
			expires: time.Now().Add(ttl),
		})
		return nil
	}

	return c.redis.Set(ctx, key, value, ttl).Err()
}

// Delete removes a value from cache.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if c.IsDegraded() {
		c.localCache.Delete(key)
		return nil
	}

	return c.redis.Del(ctx, key).Err()
}

// Exists checks if a key exists.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	if c.IsDegraded() {
		_, ok := c.localCache.Load(key)
		return ok, nil
	}

	count, err := c.redis.Exists(ctx, key).Result()
	return count > 0, err
}

// SetNX sets a value if the key does not exist.
func (c *Cache) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	if ttl == 0 {
		ttl = c.ttl
	}

	if c.IsDegraded() {
		// Check if exists
		if _, ok := c.localCache.Load(key); ok {
			return false, nil
		}
		// Set
		c.localCache.Store(key, &cacheEntry{
			value:   value,
			expires: time.Now().Add(ttl),
		})
		return true, nil
	}

	return c.redis.SetNX(ctx, key, value, ttl).Result()
}

// GetOrSet gets a value or sets it using the provided function.
func (c *Cache) GetOrSet(ctx context.Context, key string, fn func() (string, error), ttl time.Duration) (string, error) {
	// Try to get from cache
	val, err := c.Get(ctx, key)
	if err == nil {
		return val, nil
	}

	if err != redis.Nil {
		return "", err
	}

	// Generate value
	val, err = fn()
	if err != nil {
		return "", err
	}

	// Cache it
	if err := c.Set(ctx, key, val, ttl); err != nil {
		zap.L().Debug("failed to cache value", zap.Error(err))
	}

	return val, nil
}

// IsDegraded returns true if using local cache.
func (c *Cache) IsDegraded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.degraded
}

// CheckRedis checks if Redis is available and switches mode.
func (c *Cache) CheckRedis() error {
	if c.redis == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := c.redis.Ping(ctx).Err()

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		if !c.degraded {
			zap.L().Warn("redis connection lost, degrading to local cache", zap.Error(err))
			c.degraded = true
		}
		return err
	}

	if c.degraded {
		zap.L().Info("redis connection restored")
		c.degraded = false
	}

	return nil
}

// Close closes the cache.
func (c *Cache) Close() error {
	if c.redis != nil {
		return c.redis.Close()
	}
	return nil
}

// Stats returns cache statistics.
func (c *Cache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := map[string]interface{}{
		"degraded": c.degraded,
	}

	if c.degraded {
		count := 0
		c.localCache.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		stats["local_cache_size"] = count
	}

	return stats
}

// cacheEntry represents a local cache entry.
type cacheEntry struct {
	value   string
	expires time.Time
}

// StartHealthCheck starts a periodic health check.
func (c *Cache) StartHealthCheck(interval time.Duration) chan struct{} {
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.CheckRedis()
			case <-stop:
				return
			}
		}
	}()

	return stop
}
