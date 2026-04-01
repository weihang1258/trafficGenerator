# API设计 - WebSocket

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: internal/api/websocket

---

## 1. 连接端点

```
WS /ws/tasks/{task_id}
```

---

## 2. 消息格式

### 服务端推送

```json
{
  "type": "status_update",
  "data": {
    "task_id": "task-123",
    "status": "running",
    "progress": 50.5,
    "stats": {
      "packets_sent": 1234567,
      "bps": 987654321
    }
  },
  "timestamp": "2026-04-01T10:00:00Z"
}
```

### 消息类型

- `status_update`: 状态更新
- `stats_update`: 统计更新
- `error`: 错误通知
- `completed`: 任务完成

---

## 3. 实现

```go
// internal/api/websocket/handler.go
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, _ := upgrader.Upgrade(w, r, nil)
    defer conn.Close()
    
    taskID := mux.Vars(r)["task_id"]
    
    ticker := time.NewTicker(time.Second)
    for range ticker.C {
        status := engine.GetTaskStatus(taskID)
        msg := Message{
            Type: "status_update",
            Data: status,
            Timestamp: time.Now(),
        }
        conn.WriteJSON(msg)
    }
}
```

---

## 4. 前端使用

```typescript
const ws = new WebSocket(`ws://localhost:8080/ws/tasks/${taskId}`)

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data)
  if (msg.type === 'status_update') {
    updateUI(msg.data)
  }
}
```

