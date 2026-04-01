# API设计 - MCP Server

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: internal/api/mcp

---

## 1. MCP工具定义

```json
{
  "tools": [
    {
      "name": "create_traffic_task",
      "description": "创建流量生成任务",
      "inputSchema": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "protocol": {"type": "string", "enum": ["tcp", "udp", "http"]},
          "config": {"type": "object"}
        }
      }
    },
    {
      "name": "start_task",
      "description": "启动任务",
      "inputSchema": {
        "type": "object",
        "properties": {
          "task_id": {"type": "string"}
        }
      }
    },
    {
      "name": "get_task_status",
      "description": "获取任务状态",
      "inputSchema": {
        "type": "object",
        "properties": {
          "task_id": {"type": "string"}
        }
      }
    }
  ]
}
```

---

## 2. MCP资源定义

```json
{
  "resources": [
    {
      "uri": "task://tasks",
      "name": "任务列表",
      "mimeType": "application/json"
    },
    {
      "uri": "task://tasks/{id}",
      "name": "任务详情",
      "mimeType": "application/json"
    }
  ]
}
```

---

## 3. 服务实现

```go
// internal/api/mcp/server.go
type MCPServer struct {
    engine *core.Engine
}

func (s *MCPServer) HandleToolCall(name string, args map[string]interface{}) (interface{}, error) {
    switch name {
    case "create_traffic_task":
        return s.createTask(args)
    case "start_task":
        return s.startTask(args)
    case "get_task_status":
        return s.getTaskStatus(args)
    }
    return nil, fmt.Errorf("unknown tool: %s", name)
}
```

---

## 4. Claude使用示例

```
用户: 帮我创建一个TCP流量任务

Claude: [调用 create_traffic_task]
任务已创建，ID: task-abc-123

用户: 启动它

Claude: [调用 start_task]
任务已启动，当前进度: 0%
```

