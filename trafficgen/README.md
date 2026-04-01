# Traffic Generator

高性能网络流量生成器，支持多种协议和输出方式。

## 项目结构

```
trafficgen/
├── cmd/
│   └── server/          # 主程序入口
├── internal/
│   ├── api/
│   │   ├── rest/       # REST API
│   │   └── websocket/  # WebSocket
│   ├── core/           # 核心引擎
│   ├── output/         # 输出层
│   ├── protocol/       # 协议插件
│   │   ├── tcp/
│   │   ├── udp/
│   │   ├── http/
│   │   ├── dns/
│   │   └── icmp/
│   └── storage/        # 数据库
├── pkg/
│   ├── auth/          # 认证
│   ├── config/        # 配置
│   ├── logger/        # 日志
│   ├── metrics/       # 监控指标
│   └── netif/         # 网卡管理
├── web/               # Vue 3前端
├── configs/           # 配置文件
└── deployments/       # 部署配置
```

## 技术栈

### 后端
- Go 1.21+
- Gin (Web框架)
- GORM (ORM)
- gopacket (报文处理)
- WebSocket (实时推送)
- Prometheus (监控指标)
- Zap (日志)

### 前端
- Vue 3
- TypeScript
- Element Plus
- ECharts
- Pinia

## 快速开始

### 后端

```bash
cd trafficgen

# 安装依赖
go mod download

# 运行
go run ./cmd/server

# 构建
make build
```

### 前端

```bash
cd trafficgen/web

# 安装依赖
npm install

# 开发模式
npm run dev

# 构建
npm run build
```

### Docker

```bash
# 构建镜像
docker build -t trafficgen:latest .

# 运行
docker run -p 8080:8080 trafficgen:latest
```

## API 端点

### 任务管理
- `POST /api/v1/tasks` - 创建任务
- `GET /api/v1/tasks` - 任务列表
- `GET /api/v1/tasks/:id` - 任务详情
- `POST /api/v1/tasks/:id/start` - 启动任务
- `POST /api/v1/tasks/:id/stop` - 停止任务
- `DELETE /api/v1/tasks/:id` - 删除任务

### 系统管理
- `GET /api/v1/system/status` - 系统状态
- `GET /api/v1/system/protocols` - 支持的协议
- `GET /api/v1/interfaces` - 网卡列表

### 监控
- `GET /metrics` - Prometheus指标
- `GET /health` - 健康检查
- `GET /ready` - 就绪检查

## 支持的协议

- TCP (三次握手、数据传输、四次挥手)
- UDP (请求/响应)
- HTTP (GET/POST, Keep-Alive)
- DNS (A/AAAA查询)
- ICMP (Echo Request/Reply)

## 输出模式

- **网卡输出**: 直接发送到网络接口
- **PCAP文件**: 保存为Wireshark兼容格式
- **混合模式**: 同时输出到网卡和文件

## 配置

配置文件位于 `configs/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080

database:
  type: "sqlite"
  sqlite:
    path: "./data/trafficgen.db"

engine:
  config_workers: 4
  packet_workers: 8
  buffer_size: 4096

logging:
  level: "info"
  format: "json"
```

## 开发

### 运行测试

```bash
go test ./... -v
```

### 代码检查

```bash
golangci-lint run
```

## 许可证

MIT License
