# API设计 - REST API

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: internal/api/rest

---

## 1. API规范

- **协议**: HTTP/1.1, HTTP/2, HTTPS
- **格式**: JSON
- **认证**: JWT Token (Bearer)
- **版本**: `/api/v1/`
- **文档**: OpenAPI 3.0
- **限流**: 100 req/s per user, burst 200

### 1.1 认证

```
Authorization: Bearer <jwt_token>
```

### 1.2 限流响应头

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1617235200
```

---

## 2. 任务管理

### 创建任务
```
POST /api/v1/tasks
Content-Type: application/json

Request:
{
  "name": "Web压力测试",
  "spec": {
    "classes": [...]
  }
}

Response: 201
{
  "code": 0,
  "data": {
    "task_id": "task-123",
    "status": "created"
  }
}
```

### 启动任务
```
POST /api/v1/tasks/{id}/start

Response: 200
{
  "code": 0,
  "message": "Task started"
}
```

### 查询任务
```
GET /api/v1/tasks/{id}

Response: 200
{
  "code": 0,
  "data": {
    "task_id": "task-123",
    "status": "running",
    "progress": 45.5,
    "stats": {
      "packets_sent": 1234567,
      "bytes_sent": 987654321
    }
  }
}
```

---

## 3. 策略管理

### 创建策略
```
POST /api/v1/strategies

Request:
{
  "name": "HTTP测试",
  "protocol": "http",
  "config": {...}
}
```

### 获取策略列表
```
GET /api/v1/strategies?page=1&size=20
```

---

## 4. 系统管理

### 获取系统状态
```
GET /api/v1/system/status

Response:
{
  "code": 0,
  "data": {
    "running": true,
    "cpu_usage": 45.2,
    "memory_mb": 1024,
    "active_tasks": 5
  }
}
```

### 获取协议列表
```
GET /api/v1/system/protocols

Response:
{
  "code": 0,
  "data": ["tcp", "udp", "http", "dns"]
}
```

---

## 5. 监控接口

### 获取Prometheus指标
```
GET /api/v1/metrics

Response: 200 (Prometheus格式)
# HELP traffic_gen_packets_total Total packets generated
# TYPE traffic_gen_packets_total counter
traffic_gen_packets_total{protocol="tcp"} 1234567
```

### 健康检查
```
GET /health

Response: 200
{
  "status": "healthy"
}
```

### 就绪检查
```
GET /ready

Response: 200
{
  "status": "ready",
  "database": "connected",
  "redis": "connected"
}
```

---

## 6. 系统配置

### 获取配置
```
GET /api/v1/settings

Response: 200
{
  "code": 0,
  "data": {
    "max_tasks": 100,
    "buffer_size": 2048,
    "log_level": "info"
  }
}
```

### 更新配置
```
PUT /api/v1/settings

Request:
{
  "log_level": "debug",
  "max_tasks": 200
}

Response: 200
{
  "code": 0,
  "message": "Settings updated"
}
```

---

## 7. 错误码

```go
const (
    CodeSuccess         = 0
    CodeInvalidParam    = 400
    CodeUnauthorized    = 401
    CodeForbidden       = 403
    CodeNotFound        = 404
    CodeRateLimitExceed = 429
    CodeInternal        = 500
)
```

### 5.1 错误响应格式

```json
{
  "code": 401,
  "message": "unauthorized",
  "details": "invalid or expired token"
}
```

