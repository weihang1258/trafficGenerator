# 数据库设计 - Redis缓存详细设计

**文档版本**: v1.0  
**更新日期**: 2026-04-01

---

## 1. 缓存策略

| 数据类型 | 缓存时间 | 更新策略 |
|---------|---------|---------|
| 任务状态 | 实时 | 主动更新 |
| 系统指标 | 5秒 | 定时刷新 |
| 任务统计 | 10秒 | 定时刷新 |
| 用户会话 | 24小时 | TTL过期 |

---

## 2. Key设计规范

```
# 任务状态
task:status:{task_id}           -> Hash
task:stats:{task_id}            -> Hash
task:list:running               -> Set
task:list:completed             -> Set

# 系统指标
metrics:realtime                -> Hash
metrics:history:{timestamp}     -> Hash

# 用户会话
session:{user_id}               -> String (JWT)

# 速率限制
ratelimit:{user_id}:{endpoint}  -> String (计数器)
```

---

## 3. 实现代码

```go
// internal/storage/redis.go
package storage

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/redis/go-redis/v9"
)

type RedisClient struct {
    client *redis.Client
}

func NewRedisClient(cfg RedisConfig) *RedisClient {
    client := redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
        Password: cfg.Password,
        DB:       cfg.DB,
        PoolSize: cfg.PoolSize,
    })
    
    return &RedisClient{client: client}
}

// 任务状态缓存
func (r *RedisClient) SetTaskStatus(ctx context.Context, taskID string, status TaskStatus) error {
    key := fmt.Sprintf("task:status:%s", taskID)
    data, _ := json.Marshal(status)
    return r.client.Set(ctx, key, data, 0).Err()
}

func (r *RedisClient) GetTaskStatus(ctx context.Context, taskID string) (*TaskStatus, error) {
    key := fmt.Sprintf("task:status:%s", taskID)
    data, err := r.client.Get(ctx, key).Bytes()
    if err != nil {
        return nil, err
    }
    
    var status TaskStatus
    json.Unmarshal(data, &status)
    return &status, nil
}

// 运行中任务列表
func (r *RedisClient) AddRunningTask(ctx context.Context, taskID string) error {
    return r.client.SAdd(ctx, "task:list:running", taskID).Err()
}

func (r *RedisClient) RemoveRunningTask(ctx context.Context, taskID string) error {
    return r.client.SRem(ctx, "task:list:running", taskID).Err()
}

func (r *RedisClient) GetRunningTasks(ctx context.Context) ([]string, error) {
    return r.client.SMembers(ctx, "task:list:running").Result()
}

// 实时指标缓存
func (r *RedisClient) SetRealtimeMetrics(ctx context.Context, metrics map[string]float64) error {
    return r.client.HSet(ctx, "metrics:realtime", metrics).Err()
}

func (r *RedisClient) GetRealtimeMetrics(ctx context.Context) (map[string]string, error) {
    return r.client.HGetAll(ctx, "metrics:realtime").Result()
}

// 速率限制
func (r *RedisClient) IncrRateLimit(ctx context.Context, userID, endpoint string) (int64, error) {
    key := fmt.Sprintf("ratelimit:%s:%s", userID, endpoint)
    pipe := r.client.Pipeline()
    
    incr := pipe.Incr(ctx, key)
    pipe.Expire(ctx, key, time.Second)
    
    _, err := pipe.Exec(ctx)
    if err != nil {
        return 0, err
    }
    
    return incr.Val(), nil
}
```

---

## 4. 缓存更新流程

```go
// 任务状态更新
func (e *Engine) updateTaskStatus(taskID string, status string) {
    // 1. 更新Redis
    ctx := context.Background()
    e.redis.SetTaskStatus(ctx, taskID, TaskStatus{
        ID:       taskID,
        Status:   status,
        Progress: e.getProgress(taskID),
    })
    
    // 2. 更新运行列表
    if status == "running" {
        e.redis.AddRunningTask(ctx, taskID)
    } else {
        e.redis.RemoveRunningTask(ctx, taskID)
    }
    
    // 3. 异步更新数据库
    go e.db.UpdateTaskStatus(taskID, status)
}
```

---

## 5. 缓存穿透保护

```go
func (r *RedisClient) GetTaskWithCache(ctx context.Context, taskID string) (*Task, error) {
    // 1. 尝试从缓存获取
    cached, err := r.GetTaskStatus(ctx, taskID)
    if err == nil {
        return cached, nil
    }
    
    // 2. 缓存未命中，查询数据库
    task, err := r.db.GetTask(taskID)
    if err != nil {
        // 3. 数据库也没有，缓存空值防止穿透
        r.client.Set(ctx, fmt.Sprintf("task:status:%s", taskID), "null", 5*time.Minute)
        return nil, err
    }
    
    // 4. 写入缓存
    r.SetTaskStatus(ctx, taskID, task)
    return task, nil
}
```
