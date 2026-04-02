# Traffic Generator 故障排查手册

## 目录

1. [常见错误](#常见错误)
2. [日志分析](#日志分析)
3. [性能调优](#性能调优)
4. [调试工具](#调试工具)

---

## 常见错误

### 启动错误

#### 错误: 端口已被占用

**错误信息**:
```
Error: listen tcp 0.0.0.0:8080: bind: address already in use
```

**原因**: 8080 端口已被其他进程占用

**解决方案**:

```bash
# 查找占用端口的进程
netstat -tlnp | grep :8080
# 或
lsof -i :8080

# 停止占用端口的进程
kill -9 <PID>

# 或修改配置使用其他端口
# config.yaml
server:
  port: 8081
```

#### 错误: 数据库连接失败

**错误信息**:
```
Error: database init: unable to open database file
```

**原因**: 数据库文件路径不存在或权限不足

**解决方案**:

```bash
# 创建数据目录
mkdir -p /data/trafficgen

# 检查权限
ls -la /data

# 修改权限
chown -R trafficgen:trafficgen /data/trafficgen
chmod -R 755 /data/trafficgen

# 检查磁盘空间
df -h /data
```

#### 错误: 配置文件解析失败

**错误信息**:
```
Error: Failed to load config: yaml: unmarshal errors
```

**原因**: 配置文件格式错误

**解决方案**:

```bash
# 验证 YAML 语法
python -m yaml config.yaml

# 或使用在线 YAML 验证器
# 检查缩进、引号、冒号等

# 使用最小配置启动
cat > config.yaml << EOF
server:
  host: "0.0.0.0"
  port: 8080
database:
  type: "sqlite"
  dsn: ":memory:"
EOF
```

### 运行时错误

#### 错误: 协议未找到

**错误信息**:
```
Error: protocol not found: tcp
```

**原因**: 协议未注册到引擎

**解决方案**:

检查 `cmd/server/main.go` 中是否注册了协议:

```go
// 确保以下代码存在
app.engine.RegisterPlanner(tcp.NewPlanner())
app.engine.RegisterPlanner(udp.NewPlanner())
app.engine.RegisterPlanner(httpprotocol.NewPlanner())
app.engine.RegisterPlanner(dns.NewPlanner())
app.engine.RegisterPlanner(icmp.NewPlanner())
app.engine.RegisterPlanner(arp.NewPlanner())
```

#### 错误: 缓冲区溢出

**错误信息**:
```
Error: buffer overflow: combined buffer is full
```

**原因**: 缓冲区已满，无法写入更多数据包

**解决方案**:

```bash
# 查看当前缓冲区状态
curl http://localhost:8080/api/v1/buffer/status

# 增加缓冲区大小
# config.yaml
engine:
  buffer_size: 8192  # 从 4096 增加到 8192
  max_buffer_bytes: 209715200  # 从 100MB 增加到 200MB

# 或减少任务提交速率
# 或增加 Output Workers 数量
engine:
  output_workers: 8  # 从 4 增加到 8
```

#### 错误: Worker panic

**错误信息**:
```
panic: runtime error: invalid memory address or nil pointer dereference
```

**原因**: 空指针引用，通常是配置数据不完整

**解决方案**:

```bash
# 查看完整错误堆栈
docker logs trafficgen 2>&1 | grep -A 20 "panic"

# 检查任务配置
curl http://localhost:8080/api/v1/tasks/<task-id>

# 确保所有必需字段都已设置
# 检查 config.Metadata 是否为 nil
```

#### 错误: 端口分配失败

**错误信息**:
```
Error: no available ports
```

**原因**: 所有端口已被分配

**解决方案**:

```bash
# 查看端口分配状态
curl http://localhost:8080/api/v1/ports/stats

# 等待端口自动释放 (默认 30 秒)
# 或手动释放端口
curl -X DELETE http://localhost:8080/api/v1/ports/release?task_id=<task-id>

# 增加端口范围
# 修改任务配置使用不同的端口范围
```

### 网络错误

#### 错误: 网卡未找到

**错误信息**:
```
Error: interface not found: eth0
```

**原因**: 指定的网卡不存在

**解决方案**:

```bash
# 列出所有可用网卡
ip link show

# 或通过 API 查询
curl http://localhost:8080/api/v1/interfaces

# 使用正确的网卡名称
# Linux: eth0, ens192, enp0s3
# Windows: Ethernet0, Wi-Fi
```

#### 错误: 权限不足

**错误信息**:
```
Error: operation not permitted
```

**原因**: 需要 root 权限或 CAP_NET_RAW 能力

**解决方案**:

```bash
# 使用 root 用户运行
sudo docker run --privileged ...

# 或添加网络能力
docker run --cap-add=NET_RAW --cap-add=NET_ADMIN ...

# Kubernetes Pod 安全上下文
securityContext:
  capabilities:
    add:
      - NET_RAW
      - NET_ADMIN
```

### 数据库错误

#### 错误: 数据库锁定

**错误信息**:
```
Error: database is locked
```

**原因**: SQLite 并发写入冲突

**解决方案**:

```bash
# 减少并发数据库操作
# 或切换到 PostgreSQL/MySQL

# config.yaml
database:
  type: "postgres"
  dsn: "host=localhost user=trafficgen password=secret dbname=trafficgen sslmode=disable"
```

#### 错误: 数据库损坏

**错误信息**:
```
Error: database disk image is malformed
```

**原因**: 数据库文件损坏

**解决方案**:

```bash
# 备份当前数据库
cp /data/trafficgen.db /data/trafficgen.db.corrupted

# 尝试修复
sqlite3 /data/trafficgen.db ".recover" | sqlite3 /data/trafficgen_fixed.db

# 恢复备份
mv /data/trafficgen_fixed.db /data/trafficgen.db

# 或从备份恢复
gunzip -c /backup/trafficgen_20260402_020000.db.gz > /data/trafficgen.db
```

---

## 日志分析

### 日志格式

#### JSON 格式日志

```json
{
  "level": "info",
  "ts": "2026-04-02T10:30:45.123+0800",
  "caller": "engine/engine.go:123",
  "msg": "task started",
  "task_id": "abc123",
  "protocol": "tcp",
  "rate": "1Gbps"
}
```

#### 字段说明

| 字段 | 说明 |
|------|------|
| level | 日志级别: debug, info, warn, error |
| ts | 时间戳 |
| caller | 调用位置 (文件:行号) |
| msg | 日志消息 |
| task_id | 任务 ID |
| protocol | 协议类型 |
| error | 错误信息 |

### 日志查询

#### 查看实时日志

```bash
# Docker
docker logs -f trafficgen

# Kubernetes
kubectl logs -f deployment/trafficgen -n trafficgen

# 文件
tail -f /var/log/trafficgen/app.log
```

#### 过滤特定级别

```bash
# 只看错误日志
docker logs trafficgen 2>&1 | grep '"level":"error"'

# 只看警告及以上
docker logs trafficgen 2>&1 | grep -E '"level":"(error|warn)"'
```

#### 查找特定任务

```bash
# 按任务 ID 查找
docker logs trafficgen 2>&1 | grep '"task_id":"abc123"'

# 按协议查找
docker logs trafficgen 2>&1 | grep '"protocol":"tcp"'
```

#### 统计错误数量

```bash
# 统计各类错误
docker logs trafficgen 2>&1 | grep '"level":"error"' | jq -r '.msg' | sort | uniq -c | sort -rn

# 示例输出:
#   15 buffer overflow
#   10 protocol not found
#    5 connection refused
```

### 日志分析案例

#### 案例 1: 任务启动失败

**日志**:
```json
{"level":"error","ts":"2026-04-02T10:30:45.123+0800","caller":"api/rest/handlers.go:45","msg":"failed to create task","error":"invalid config: src_ip is required"}
```

**分析**: 任务配置缺少 `src_ip` 字段

**解决**: 检查任务配置，确保所有必需字段都已设置

#### 案例 2: 性能下降

**日志**:
```json
{"level":"warn","ts":"2026-04-02T10:31:00.456+0800","caller":"core/buffer.go:78","msg":"buffer usage high","usage":95,"buffer":"combined"}
{"level":"error","ts":"2026-04-02T10:31:05.789+0800","caller":"core/buffer.go:89","msg":"buffer overflow","buffer":"combined"}
```

**分析**: 缓冲区使用率达到 95% 后溢出

**解决**: 增加缓冲区大小或减少任务提交速率

#### 案例 3: Worker 阻塞

**日志**:
```json
{"level":"info","ts":"2026-04-02T10:32:00.123+0800","caller":"core/worker.go:56","msg":"config worker started","worker_id":1}
{"level":"info","ts":"2026-04-02T10:32:00.124+0800","caller":"core/worker.go:56","msg":"config worker started","worker_id":2}
{"level":"warn","ts":"2026-04-02T10:35:00.456+0800","caller":"core/worker.go:89","msg":"config worker blocked","worker_id":1,"duration":"3m"}
```

**分析**: Config Worker 1 阻塞了 3 分钟

**解决**: 检查是否有死锁或长时间运行的操作

---

## 性能调优

### 性能指标

#### 关键指标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 吞吐量 | > 1 Gbps | 数据包生成速率 |
| API 响应时间 | < 50ms (P95) | API 请求延迟 |
| 任务启动延迟 | < 100ms | 任务启动时间 |
| CPU 使用率 | < 70% | CPU 使用率 |
| 内存使用 | < 1GB | 内存使用量 |
| 缓冲区使用率 | < 80% | 缓冲区使用率 |

#### 查看指标

```bash
# Prometheus 指标
curl http://localhost:8080/metrics | grep trafficgen

# 缓冲区状态
curl http://localhost:8080/api/v1/buffer/status

# 端口分配
curl http://localhost:8080/api/v1/ports/stats

# 活跃任务
curl http://localhost:8080/api/v1/tasks?status=running
```

### CPU 优化

#### 识别 CPU 热点

```bash
# CPU profiling
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -http=:8081 cpu.prof

# 查看 top 10 热点
go tool pprof -top cpu.prof | head -20
```

#### 常见优化

1. **增加 Worker 数量**

```yaml
# config.yaml
engine:
  config_workers: 8   # 增加 Config Workers
  packet_workers: 16  # 增加 Packet Workers
  output_workers: 8   # 增加 Output Workers
```

2. **减少锁竞争**

```go
// 使用 sync.Map 替代 map + mutex
var cache sync.Map

// 使用分段锁
type ShardedLock struct {
    locks [16]sync.RWMutex
}
```

3. **使用对象池**

```go
var packetPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1518)
    },
}

// 使用
pkt := packetPool.Get().([]byte)
defer packetPool.Put(pkt)
```

### 内存优化

#### 识别内存泄漏

```bash
# 内存 profiling
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof -http=:8081 heap.prof

# 查看内存分配
go tool pprof -alloc_space heap.prof

# 查看 in-use 内存
go tool pprof -inuse_space heap.prof
```

#### 常见优化

1. **减少内存分配**

```go
// 预分配切片
packets := make([][]byte, 0, 1000)

// 使用 strings.Builder
var builder strings.Builder
builder.Grow(1024) // 预分配
```

2. **重用缓冲区**

```go
// 全局缓冲区池
var bufferPool = sync.Pool{
    New: func() interface{} {
        return bytes.NewBuffer(make([]byte, 0, 4096))
    },
}

buf := bufferPool.Get().(*bytes.Buffer)
defer bufferPool.Put(buf)
buf.Reset()
```

3. **限制缓冲区大小**

```yaml
# config.yaml
engine:
  max_buffer_bytes: 104857600  # 100MB 限制
```

### I/O 优化

#### 减少 I/O 操作

1. **批量写入**

```go
// 批量写入数据包
batch := make([][]byte, 0, 100)
for _, pkt := range packets {
    batch = append(batch, pkt)
    if len(batch) >= 100 {
        writeBatch(batch)
        batch = batch[:0]
    }
}
```

2. **异步写入**

```go
// 使用 channel 异步写入
writeCh := make(chan []byte, 1000)

go func() {
    for pkt := range writeCh {
        writePacket(pkt)
    }
}()
```

3. **缓冲区调优**

```yaml
# config.yaml
engine:
  buffer_size: 8192  # 增加缓冲区大小
  queue_size: 200    # 增加队列大小
```

### 网络优化

#### 内核参数调优

```bash
# /etc/sysctl.conf

# 增加网络缓冲区
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# 增加连接跟踪
net.netfilter.nf_conntrack_max = 262144

# 应用配置
sysctl -p
```

#### 网卡调优

```bash
# 查看网卡队列
ethtool -l eth0

# 增加网卡队列
ethtool -L eth0 combined 8

# 查看网卡缓冲区
ethtool -g eth0

# 增加网卡缓冲区
ethtool -G eth0 rx 4096 tx 4096
```

### 数据库优化

#### SQLite 优化

```sql
-- 启用 WAL 模式
PRAGMA journal_mode = WAL;

-- 增加缓存大小
PRAGMA cache_size = 10000;

-- 同步模式
PRAGMA synchronous = NORMAL;

-- 创建索引
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_created_at ON tasks(created_at);
```

#### PostgreSQL 优化

```sql
-- 创建索引
CREATE INDEX idx_tasks_status_created ON tasks(status, created_at);

-- 分析查询计划
EXPLAIN ANALYZE SELECT * FROM tasks WHERE status = 'running';

-- 更新统计信息
ANALYZE tasks;
```

---

## 调试工具

### pprof 性能分析

#### CPU 分析

```bash
# 收集 30 秒 CPU profile
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof

# 交互式分析
go tool pprof cpu.prof
(pprof) top10
(pprof) list <function>
(pprof) web

# Web UI
go tool pprof -http=:8081 cpu.prof
```

#### 内存分析

```bash
# 收集 heap profile
curl http://localhost:8080/debug/pprof/heap > heap.prof

# 分析
go tool pprof heap.prof
(pprof) top10
(pprof) list <function>

# 查看分配对象数
go tool pprof -alloc_objects heap.prof
```

#### Goroutine 分析

```bash
# 收集 goroutine profile
curl http://localhost:8080/debug/pprof/goroutine > goroutine.prof

# 分析
go tool pprof goroutine.prof
(pprof) top10

# 或直接查看
curl http://localhost:8080/debug/pprof/goroutine?debug=1
```

### Prometheus 查询

#### 常用查询

```promql
# 吞吐量 (bps)
rate(trafficgen_bytes_sent_total[5m]) * 8

# 数据包速率 (pps)
rate(trafficgen_packets_sent_total[5m])

# 错误率
rate(trafficgen_packets_dropped_total[5m]) / rate(trafficgen_packets_sent_total[5m])

# 缓冲区使用率
trafficgen_buffer_usage_percent

# 活跃任务数
trafficgen_active_tasks

# P95 API 延迟
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# CPU 使用率
rate(process_cpu_seconds_total{job="trafficgen"}[5m])

# 内存使用
process_resident_memory_bytes{job="trafficgen"} / 1024 / 1024
```

### 网络调试

#### 抓包分析

```bash
# 抓取所有流量
tcpdump -i eth0 -w traffic.pcap

# 抓取特定端口
tcpdump -i eth0 port 8080 -w api.pcap

# 抓取特定协议
tcpdump -i eth0 tcp -w tcp.pcap

# 实时查看
tcpdump -i eth0 -nn -vv

# 分析 PCAP 文件
tshark -r traffic.pcap -Y "tcp.port == 8080"
```

#### 网络统计

```bash
# 查看网络连接
netstat -tunap

# 查看网络统计
netstat -s

# 查看网卡统计
ifconfig eth0
ethtool -S eth0

# 实时监控
iftop -i eth0
nload
```

### 系统调试

#### 进程状态

```bash
# 查看进程状态
ps aux | grep trafficgen

# 查看线程
ps -eLf | grep trafficgen

# 查看进程资源使用
top -H -p $(pgrep trafficgen)

# 查看打开的文件
lsof -p $(pgrep trafficgen)

# 查看网络连接
lsof -i -P -n | grep trafficgen
```

#### 系统调用跟踪

```bash
# 跟踪系统调用
strace -p $(pgrep trafficgen) -c

# 跟踪特定系统调用
strace -p $(pgrep trafficgen) -e trace=network

# 统计系统调用
strace -p $(pgrep trafficgen) -c -f
```

### 日志调试

#### 启用调试日志

```yaml
# config.yaml
logging:
  level: "debug"
  format: "json"
```

#### 结构化日志查询

```bash
# 使用 jq 查询 JSON 日志
docker logs trafficgen 2>&1 | jq 'select(.level=="error")'

# 按时间范围查询
docker logs trafficgen 2>&1 | jq 'select(.ts >= "2026-04-02T10:00:00" and .ts < "2026-04-02T11:00:00")'

# 统计错误类型
docker logs trafficgen 2>&1 | jq -r 'select(.level=="error") | .msg' | sort | uniq -c
```

---

## 快速诊断流程

### 1. 服务无法访问

```bash
# 检查服务状态
curl http://localhost:8080/health

# 检查端口
netstat -tlnp | grep 8080

# 检查防火墙
iptables -L -n

# 检查日志
docker logs trafficgen --tail 100
```

### 2. 性能下降

```bash
# 检查资源使用
top -H -p $(pgrep trafficgen)

# 检查缓冲区
curl http://localhost:8080/api/v1/buffer/status

# 检查活跃任务
curl http://localhost:8080/api/v1/tasks?status=running

# CPU profiling
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -top cpu.prof
```

### 3. 内存增长

```bash
# 检查内存使用
ps aux | grep trafficgen

# 内存 profiling
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof -top heap.prof

# 检查 goroutine 泄漏
curl http://localhost:8080/debug/pprof/goroutine?debug=1 | grep "goroutine" | wc -l
```

### 4. 任务失败

```bash
# 查看任务状态
curl http://localhost:8080/api/v1/tasks/<task-id>

# 查看错误日志
docker logs trafficgen 2>&1 | grep '"task_id":"<task-id>"' | grep error

# 检查配置
curl http://localhost:8080/api/v1/tasks/<task-id> | jq '.config'
```

---

## 联系支持

如果以上方法无法解决问题，请联系技术支持:

- **技术支持**: support@example.com
- **紧急联系**: +86-xxx-xxxx-xxxx
- **问题反馈**: https://github.com/your-org/traffic-generator/issues

提供以下信息以加快问题解决:

1. 完整的错误日志
2. 配置文件
3. 系统环境 (OS, Go version, Docker version)
4. 复现步骤
5. pprof 文件 (CPU, heap, goroutine)
