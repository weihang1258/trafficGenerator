# Traffic Generator 配置说明

本文档详细介绍 Traffic Generator 的配置选项。

## 目录

1. [配置文件](#配置文件)
2. [服务器配置](#服务器配置)
3. [数据库配置](#数据库配置)
4. [引擎配置](#引擎配置)
5. [日志配置](#日志配置)
6. [监控配置](#监控配置)
7. [WebSocket配置](#websocket配置)
8. [环境变量](#环境变量)
9. [配置示例](#配置示例)

---

## 配置文件

### 配置文件位置

Traffic Generator 支持以下配置文件位置（按优先级排序）:

1. 命令行参数指定: `./server -config /path/to/config.yaml`
2. 环境变量: `TRAFFICGEN_CONFIG=/path/to/config.yaml`
3. 当前目录: `./config.yaml`
4. 默认配置: 内置默认值

### 配置文件格式

配置文件使用 YAML 格式:

```yaml
# 服务器配置
server:
  host: "0.0.0.0"
  port: 8080

# 数据库配置
database:
  type: "sqlite"
  dsn: "/data/trafficgen.db"

# 引擎配置
engine:
  config_workers: 4
  packet_workers: 8
  output_workers: 4
```

---

## 服务器配置

### 配置项说明

```yaml
server:
  # 监听地址
  # 类型: string
  # 默认值: "0.0.0.0"
  # 说明: 0.0.0.0 表示监听所有网卡，127.0.0.1 表示仅本机访问
  host: "0.0.0.0"

  # 监听端口
  # 类型: int
  # 默认值: 8080
  # 范围: 1-65535
  port: 8080

  # 读超时
  # 类型: duration
  # 默认值: 30s
  # 说明: HTTP 请求读取超时时间
  read_timeout: 30s

  # 写超时
  # 类型: duration
  # 默认值: 30s
  # 说明: HTTP 响应写入超时时间
  write_timeout: 30s

  # 空闲超时
  # 类型: duration
  # 默认值: 60s
  # 说明: Keep-Alive 连接空闲超时时间
  idle_timeout: 60s

  # 最大请求体大小
  # 类型: int
  # 默认值: 10485760 (10MB)
  # 说明: HTTP 请求体最大字节数
  max_header_bytes: 1048576
```

### 配置示例

#### 开发环境

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  read_timeout: 60s
  write_timeout: 60s
```

#### 生产环境

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
```

---

## 数据库配置

### SQLite 配置

```yaml
database:
  # 数据库类型
  type: "sqlite"

  # 数据源名称
  # 格式: 文件路径
  # 特殊值: ":memory:" 表示内存数据库
  dsn: "/data/trafficgen.db"

  # 最大打开连接数
  # 类型: int
  # 默认值: 25
  max_open_conns: 25

  # 最大空闲连接数
  # 类型: int
  # 默认值: 5
  max_idle_conns: 5

  # 连接最大生命周期
  # 类型: duration
  # 默认值: 5m
  conn_max_lifetime: 5m
```

### PostgreSQL 配置

```yaml
database:
  type: "postgres"

  # 数据源名称
  # 格式: host=<host> port=<port> user=<user> password=<password> dbname=<db> sslmode=<mode>
  dsn: "host=localhost port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=disable"

  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 10m
```

### MySQL 配置

```yaml
database:
  type: "mysql"

  # 数据源名称
  # 格式: <user>:<password>@tcp(<host>:<port>)/<db>?charset=utf8mb4&parseTime=True&loc=Local
  dsn: "trafficgen:secret@tcp(localhost:3306)/trafficgen?charset=utf8mb4&parseTime=True&loc=Local"

  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 10m
```

### 数据库选择建议

| 数据库 | 适用场景 | 优点 | 缺点 |
|--------|---------|------|------|
| SQLite | 开发、测试、小规模部署 | 零配置、易备份 | 并发写入性能差 |
| PostgreSQL | 生产环境、大规模部署 | 高性能、功能丰富 | 需要单独部署 |
| MySQL | 生产环境、大规模部署 | 广泛使用、生态好 | 需要单独部署 |

---

## 引擎配置

### 配置项说明

```yaml
engine:
  # 配置生成 Worker 数量
  # 类型: int
  # 默认值: 4
  # 建议: CPU 核心数的 1-2 倍
  # 说明: 负责生成数据包配置
  config_workers: 4

  # 数据包构建 Worker 数量
  # 类型: int
  # 默认值: 8
  # 建议: CPU 核心数的 2-4 倍
  # 说明: 负责构建二进制数据包（CPU 密集型）
  packet_workers: 8

  # 输出 Worker 数量
  # 类型: int
  # 默认值: 4
  # 建议: CPU 核心数的 1-2 倍
  # 说明: 负责输出数据包到网卡或文件
  output_workers: 4

  # 环形缓冲区大小
  # 类型: int
  # 默认值: 4096
  # 单位: 数据包数量
  # 说明: 存储已构建的数据包
  buffer_size: 4096

  # 任务队列大小
  # 类型: int
  # 默认值: 100
  # 说明: 待处理的任务数量
  queue_size: 100

  # 最大缓冲区字节数
  # 类型: int
  # 默认值: 104857600 (100MB)
  # 说明: 缓冲区最大字节数限制
  max_buffer_bytes: 104857600
```

### 性能调优建议

#### CPU 密集型场景

```yaml
engine:
  config_workers: 2
  packet_workers: 16  # 增加 CPU 密集型 Worker
  output_workers: 4
  buffer_size: 4096
```

#### I/O 密集型场景

```yaml
engine:
  config_workers: 8
  packet_workers: 4
  output_workers: 8   # 增加 I/O Worker
  buffer_size: 8192   # 增加缓冲区
```

#### 高吞吐量场景

```yaml
engine:
  config_workers: 8
  packet_workers: 16
  output_workers: 8
  buffer_size: 8192
  queue_size: 200
  max_buffer_bytes: 209715200  # 200MB
```

#### 低延迟场景

```yaml
engine:
  config_workers: 4
  packet_workers: 8
  output_workers: 4
  buffer_size: 2048   # 较小的缓冲区
  queue_size: 50      # 较小的队列
  max_buffer_bytes: 52428800  # 50MB
```

---

## 日志配置

### 配置项说明

```yaml
logging:
  # 日志级别
  # 类型: string
  # 可选值: debug, info, warn, error
  # 默认值: info
  level: "info"

  # 日志格式
  # 类型: string
  # 可选值: json, text
  # 默认值: json
  # 说明: json 适合生产环境，text 适合开发环境
  format: "json"

  # 输出路径
  # 类型: string
  # 可选值: 文件路径, stdout, stderr
  # 默认值: stdout
  output: "/var/log/trafficgen/app.log"

  # 单文件最大大小
  # 类型: int
  # 单位: MB
  # 默认值: 100
  max_size: 100

  # 最大备份数量
  # 类型: int
  # 默认值: 10
  max_backups: 10

  # 最大保留天数
  # 类型: int
  # 默认值: 30
  max_age: 30

  # 是否压缩旧日志
  # 类型: bool
  # 默认值: true
  compress: true
```

### 日志级别说明

| 级别 | 说明 | 适用场景 |
|------|------|---------|
| debug | 详细调试信息 | 开发、调试 |
| info | 一般信息 | 生产环境 |
| warn | 警告信息 | 生产环境 |
| error | 错误信息 | 生产环境 |

### 日志格式示例

#### JSON 格式

```json
{
  "level": "info",
  "ts": "2026-04-02T10:30:45.123+0800",
  "caller": "engine/engine.go:123",
  "msg": "task started",
  "task_id": "abc123",
  "protocol": "tcp"
}
```

#### Text 格式

```
2026-04-02T10:30:45.123+0800	INFO	engine/engine.go:123	task started	{"task_id": "abc123", "protocol": "tcp"}
```

---

## 监控配置

### 配置项说明

```yaml
monitoring:
  # 是否启用监控
  # 类型: bool
  # 默认值: true
  enabled: true

  # Prometheus 端口
  # 类型: int
  # 默认值: 9090
  # 说明: 如果与主服务同端口，则使用主服务端口
  prometheus_port: 9090

  # 指标路径
  # 类型: string
  # 默认值: /metrics
  metrics_path: "/metrics"

  # 是否启用 pprof
  # 类型: bool
  # 默认值: false
  # 说明: 仅用于调试，生产环境建议关闭
  enable_pprof: false
```

### 指标说明

#### 任务指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `trafficgen_packets_sent_total` | Counter | 发送的数据包总数 |
| `trafficgen_bytes_sent_total` | Counter | 发送的字节总数 |
| `trafficgen_packets_dropped_total` | Counter | 丢弃的数据包总数 |
| `trafficgen_active_tasks` | Gauge | 活跃任务数 |

#### 性能指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `trafficgen_buffer_usage_percent` | Gauge | 缓冲区使用率 |
| `trafficgen_buffer_size` | Gauge | 缓冲区大小 |
| `trafficgen_port_allocations` | Gauge | 端口分配数 |

---

## WebSocket配置

### 配置项说明

```yaml
websocket:
  # 是否启用 WebSocket
  # 类型: bool
  # 默认值: true
  enabled: true

  # Ping 间隔
  # 类型: duration
  # 默认值: 30s
  # 说明: 服务端发送 Ping 的间隔
  ping_interval: 30s

  # Pong 超时
  # 类型: duration
  # 默认值: 60s
  # 说明: 等待客户端 Pong 响应的超时时间
  pong_timeout: 60s

  # 最大消息大小
  # 类型: int
  # 默认值: 65536 (64KB)
  # 说明: WebSocket 消息最大字节数
  max_message_size: 65536

  # 写缓冲区大小
  # 类型: int
  # 默认值: 4096
  write_buffer_size: 4096

  # 读缓冲区大小
  # 类型: int
  # 默认值: 4096
  read_buffer_size: 4096
```

---

## 环境变量

所有配置项都可以通过环境变量覆盖。

### 环境变量命名规则

格式: `TRAFFICGEN_<SECTION>_<KEY>`

示例:
- `server.host` → `TRAFFICGEN_SERVER_HOST`
- `database.type` → `TRAFFICGEN_DATABASE_TYPE`
- `engine.config_workers` → `TRAFFICGEN_ENGINE_CONFIG_WORKERS`

### 常用环境变量

```bash
# 服务器配置
export TRAFFICGEN_SERVER_HOST="0.0.0.0"
export TRAFFICGEN_SERVER_PORT="8080"

# 数据库配置
export TRAFFICGEN_DATABASE_TYPE="postgres"
export TRAFFICGEN_DATABASE_DSN="host=localhost port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=disable"

# 引擎配置
export TRAFFICGEN_ENGINE_CONFIG_WORKERS="4"
export TRAFFICGEN_ENGINE_PACKET_WORKERS="8"
export TRAFFICGEN_ENGINE_OUTPUT_WORKERS="4"

# 日志配置
export TRAFFICGEN_LOGGING_LEVEL="info"
export TRAFFICGEN_LOGGING_FORMAT="json"
```

### 使用 .env 文件

创建 `.env` 文件:

```bash
TRAFFICGEN_SERVER_PORT=8080
TRAFFICGEN_DATABASE_TYPE=sqlite
TRAFFICGEN_LOGGING_LEVEL=info
```

Docker Compose 会自动读取 `.env` 文件。

---

## 配置示例

### 开发环境配置

```yaml
server:
  host: "127.0.0.1"
  port: 8080

database:
  type: "sqlite"
  dsn: ":memory:"

engine:
  config_workers: 2
  packet_workers: 4
  output_workers: 2
  buffer_size: 1024
  queue_size: 50

logging:
  level: "debug"
  format: "text"
  output: "stdout"
```

### 测试环境配置

```yaml
server:
  host: "0.0.0.0"
  port: 8080

database:
  type: "sqlite"
  dsn: "/data/trafficgen.db"

engine:
  config_workers: 4
  packet_workers: 8
  output_workers: 4
  buffer_size: 2048
  queue_size: 100

logging:
  level: "info"
  format: "json"
  output: "/var/log/trafficgen/app.log"

monitoring:
  enabled: true
  metrics_path: "/metrics"

websocket:
  enabled: true
```

### 生产环境配置

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

database:
  type: "postgres"
  dsn: "host=postgres port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=require"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 10m

engine:
  config_workers: 8
  packet_workers: 16
  output_workers: 8
  buffer_size: 8192
  queue_size: 200
  max_buffer_bytes: 209715200

logging:
  level: "info"
  format: "json"
  output: "/var/log/trafficgen/app.log"
  max_size: 100
  max_backups: 20
  max_age: 60
  compress: true

monitoring:
  enabled: true
  metrics_path: "/metrics"
  enable_pprof: false

websocket:
  enabled: true
  ping_interval: 30s
  pong_timeout: 60s
  max_message_size: 65536
```

---

## 配置验证

### 验证配置文件

```bash
# 检查配置文件语法
./server -config config.yaml -validate

# 查看实际使用的配置
./server -config config.yaml -print-config
```

### 常见配置错误

1. **端口被占用**
   ```
   Error: listen tcp 0.0.0.0:8080: bind: address already in use
   ```
   解决: 修改端口或停止占用端口的进程

2. **数据库连接失败**
   ```
   Error: database init: connection refused
   ```
   解决: 检查数据库地址、端口、用户名、密码

3. **权限不足**
   ```
   Error: open /var/log/trafficgen/app.log: permission denied
   ```
   解决: 检查文件权限或修改输出路径

---

## 参考链接

- [YAML 语法](https://yaml.org/spec/)
- [Go time.Duration](https://pkg.go.dev/time#Duration)
- [Prometheus 指标类型](https://prometheus.io/docs/concepts/metric_types/)
