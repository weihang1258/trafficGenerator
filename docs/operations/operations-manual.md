# Traffic Generator 运维手册

## 目录

1. [部署指南](#部署指南)
2. [配置说明](#配置说明)
3. [监控告警](#监控告警)
4. [日常运维](#日常运维)
5. [故障处理](#故障处理)

---

## 部署指南

### 系统要求

#### 硬件要求

| 组件 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 4核 | 8核+ |
| 内存 | 8GB | 16GB+ |
| 存储 | 50GB SSD | 100GB SSD |
| 网卡 | 1Gbps | 10Gbps |

#### 软件要求

| 软件 | 版本 |
|------|------|
| 操作系统 | Linux (Ubuntu 20.04+, CentOS 8+) |
| Go | 1.21+ |
| Docker | 20.10+ |
| Kubernetes | 1.25+ (可选) |

### Docker 部署

#### 1. 构建镜像

```bash
# 克隆代码
git clone https://github.com/your-org/traffic-generator.git
cd traffic-generator

# 构建镜像
docker build -t trafficgen:latest -f trafficgen/Dockerfile trafficgen

# 查看镜像大小
docker images trafficgen:latest
```

#### 2. 配置文件

创建 `config.yaml`:

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
  buffer_size: 4096
  queue_size: 100

logging:
  level: "info"
  format: "json"
  output: "/var/log/trafficgen/app.log"
```

#### 3. 启动服务

```bash
# 单容器启动
docker run -d \
  --name trafficgen \
  --network host \
  -v /data/trafficgen:/data \
  -v /var/log/trafficgen:/var/log/trafficgen \
  -v /path/to/config.yaml:/app/config.yaml \
  trafficgen:latest \
  -config /app/config.yaml

# 查看日志
docker logs -f trafficgen
```

#### 4. Docker Compose 部署

创建 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  trafficgen:
    image: trafficgen:latest
    container_name: trafficgen
    restart: always
    network_mode: host
    volumes:
      - ./data:/data
      - ./logs:/var/log/trafficgen
      - ./config.yaml:/app/config.yaml
    command: -config /app/config.yaml
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: always
    ports:
      - "9090:9090"
    volumes:
      - ./deployments/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./deployments/prometheus/alerts.yml:/etc/prometheus/alerts.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: always
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deployments/grafana/dashboard.json:/etc/grafana/provisioning/dashboards/trafficgen.json
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

volumes:
  prometheus-data:
  grafana-data:
```

启动服务:

```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f trafficgen
```

### Kubernetes 部署

#### 1. 创建命名空间

```bash
kubectl create namespace trafficgen
```

#### 2. 创建 ConfigMap

```bash
kubectl create configmap trafficgen-config \
  --from-file=config.yaml \
  -n trafficgen
```

#### 3. 创建 Secret

```bash
kubectl create secret generic trafficgen-secret \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=db-password=$(openssl rand -base64 16) \
  -n trafficgen
```

#### 4. 部署应用

```bash
# 应用所有配置
kubectl apply -f trafficgen/deployments/k8s/ -n trafficgen

# 查看部署状态
kubectl get pods -n trafficgen
kubectl get services -n trafficgen
kubectl get ingress -n trafficgen

# 查看日志
kubectl logs -f deployment/trafficgen -n trafficgen
```

#### 5. 验证部署

```bash
# 端口转发
kubectl port-forward svc/trafficgen-service 8080:8080 -n trafficgen

# 健康检查
curl http://localhost:8080/health

# 查看指标
curl http://localhost:8080/metrics
```

#### 6. 扩容缩容

```bash
# 手动扩容
kubectl scale deployment trafficgen --replicas=5 -n trafficgen

# 自动扩容 (HPA)
kubectl autoscale deployment trafficgen \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n trafficgen

# 查看 HPA 状态
kubectl get hpa -n trafficgen
```

---

## 配置说明

### 配置文件结构

```yaml
# 服务器配置
server:
  host: "0.0.0.0"        # 监听地址
  port: 8080              # 监听端口
  read_timeout: 30s       # 读超时
  write_timeout: 30s      # 写超时
  idle_timeout: 60s       # 空闲超时

# 数据库配置
database:
  type: "sqlite"          # 数据库类型: sqlite, postgres, mysql
  dsn: "/data/trafficgen.db"  # 数据源名称
  max_open_conns: 25      # 最大连接数
  max_idle_conns: 5       # 最大空闲连接数
  conn_max_lifetime: 5m   # 连接最大生命周期

# 引擎配置
engine:
  config_workers: 4       # 配置生成 Worker 数量
  packet_workers: 8       # 数据包构建 Worker 数量
  output_workers: 4       # 输出 Worker 数量
  buffer_size: 4096       # 环形缓冲区大小
  queue_size: 100         # 任务队列大小
  max_buffer_bytes: 104857600  # 最大缓冲区字节数 (100MB)

# 日志配置
logging:
  level: "info"           # 日志级别: debug, info, warn, error
  format: "json"          # 日志格式: json, text
  output: "/var/log/trafficgen/app.log"  # 输出路径
  max_size: 100           # 单文件最大大小 (MB)
  max_backups: 10         # 最大备份数量
  max_age: 30             # 最大保留天数

# 监控配置
monitoring:
  enabled: true           # 是否启用监控
  prometheus_port: 9090   # Prometheus 端口
  metrics_path: "/metrics"  # 指标路径

# WebSocket 配置
websocket:
  enabled: true           # 是否启用 WebSocket
  ping_interval: 30s      # Ping 间隔
  pong_timeout: 60s       # Pong 超时
  max_message_size: 65536 # 最大消息大小
```

### 环境变量

配置可以通过环境变量覆盖:

```bash
# 服务器配置
export TRAFFICGEN_SERVER_HOST="0.0.0.0"
export TRAFFICGEN_SERVER_PORT="8080"

# 数据库配置
export TRAFFICGEN_DATABASE_TYPE="sqlite"
export TRAFFICGEN_DATABASE_DSN="/data/trafficgen.db"

# 引擎配置
export TRAFFICGEN_ENGINE_CONFIG_WORKERS="4"
export TRAFFICGEN_ENGINE_PACKET_WORKERS="8"
export TRAFFICGEN_ENGINE_OUTPUT_WORKERS="4"

# 日志配置
export TRAFFICGEN_LOGGING_LEVEL="info"
export TRAFFICGEN_LOGGING_FORMAT="json"
```

### 性能调优参数

#### Worker 数量配置

```yaml
# CPU 密集型场景
engine:
  config_workers: 2       # 配置生成较轻量
  packet_workers: 16      # 数据包构建较重
  output_workers: 4       # 输出适中

# I/O 密集型场景
engine:
  config_workers: 8       # 配置生成较多
  packet_workers: 4       # 数据包构建较少
  output_workers: 8       # 输出较多

# 平衡场景
engine:
  config_workers: 4
  packet_workers: 8
  output_workers: 4
```

#### 缓冲区配置

```yaml
# 高吞吐量场景
engine:
  buffer_size: 8192       # 更大的缓冲区
  queue_size: 200         # 更大的队列
  max_buffer_bytes: 209715200  # 200MB

# 低延迟场景
engine:
  buffer_size: 2048       # 较小的缓冲区
  queue_size: 50          # 较小的队列
  max_buffer_bytes: 52428800   # 50MB
```

---

## 监控告警

### Prometheus 配置

#### prometheus.yml

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - /etc/prometheus/alerts.yml

scrape_configs:
  - job_name: 'trafficgen'
    static_configs:
      - targets: ['trafficgen:8080']
    metrics_path: '/metrics'
```

### 关键指标

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
| `trafficgen_port_wait_queue` | Gauge | 端口等待队列长度 |

#### 系统指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `process_cpu_seconds_total` | Counter | CPU 使用时间 |
| `process_resident_memory_bytes` | Gauge | 内存使用量 |
| `trafficgen_websocket_connections` | Gauge | WebSocket 连接数 |

### Grafana 仪表盘

#### 导入仪表盘

1. 访问 Grafana UI: http://localhost:3000
2. 登录 (默认: admin/admin)
3. 点击 "+" → "Import"
4. 上传 `deployments/grafana/dashboard.json`
5. 选择 Prometheus 数据源
6. 点击 "Import"

#### 仪表盘面板

1. **Packets Sent** - 数据包发送总数
2. **Throughput** - 吞吐量 (bps)
3. **Active Tasks** - 活跃任务数
4. **Packets Dropped** - 丢弃数据包数
5. **Packet Rate** - 数据包速率
6. **Throughput Over Time** - 吞吐量时间序列
7. **Packets by Protocol** - 按协议分类的数据包
8. **Buffer Usage** - 缓冲区使用率

### 告警规则

#### 告警级别

| 级别 | 说明 | 响应时间 |
|------|------|---------|
| Critical | 严重故障，需要立即处理 | < 5分钟 |
| Warning | 警告，需要关注 | < 30分钟 |
| Info | 信息，供参考 | 无 |

#### 关键告警

1. **ServiceDown** - 服务宕机
   - 级别: Critical
   - 条件: `up{job="trafficgen"} == 0` 持续 1 分钟
   - 处理: 检查服务状态，重启服务

2. **HighCPUUsage** - CPU 使用率过高
   - 级别: Warning
   - 条件: CPU 使用率 > 80% 持续 5 分钟
   - 处理: 扩容或优化代码

3. **HighMemoryUsage** - 内存使用率过高
   - 级别: Warning
   - 条件: 内存使用 > 800MB 持续 5 分钟
   - 处理: 增加内存或优化内存使用

4. **BufferUsageCritical** - 缓冲区几乎满
   - 级别: Critical
   - 条件: 缓冲区使用率 > 95% 持续 1 分钟
   - 处理: 增加 buffer_size 或减少任务提交速率

5. **TaskFailureRate** - 任务失败率高
   - 级别: Warning
   - 条件: 失败率 > 0.1 packets/sec 持续 2 分钟
   - 处理: 检查任务配置，查看错误日志

### AlertManager 配置

#### alertmanager.yml

```yaml
global:
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'alertmanager@example.com'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'team-email'
  
  routes:
    - match:
        severity: critical
      receiver: 'team-email-critical'
    - match:
        severity: warning
      receiver: 'team-email'

receivers:
  - name: 'team-email'
    email_configs:
      - to: 'team@example.com'
        send_resolved: true

  - name: 'team-email-critical'
    email_configs:
      - to: 'oncall@example.com'
        send_resolved: true
    webhook_configs:
      - url: 'http://webhook.example.com/alert'
        send_resolved: true
```

---

## 日常运维

### 服务管理

#### 启动服务

```bash
# Docker
docker start trafficgen

# Kubernetes
kubectl rollout restart deployment/trafficgen -n trafficgen

# Systemd
systemctl start trafficgen
```

#### 停止服务

```bash
# Docker
docker stop trafficgen

# Kubernetes
kubectl scale deployment trafficgen --replicas=0 -n trafficgen

# Systemd
systemctl stop trafficgen
```

#### 重启服务

```bash
# Docker
docker restart trafficgen

# Kubernetes
kubectl rollout restart deployment/trafficgen -n trafficgen

# Systemd
systemctl restart trafficgen
```

### 日志管理

#### 查看日志

```bash
# Docker
docker logs -f trafficgen
docker logs --tail 100 trafficgen

# Kubernetes
kubectl logs -f deployment/trafficgen -n trafficgen
kubectl logs --tail 100 deployment/trafficgen -n trafficgen

# 文件日志
tail -f /var/log/trafficgen/app.log
```

#### 日志轮转

日志自动轮转配置 (logrotate):

```bash
# /etc/logrotate.d/trafficgen
/var/log/trafficgen/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 trafficgen trafficgen
    postrotate
        docker restart trafficgen
    endscript
}
```

### 数据备份

#### SQLite 备份

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/trafficgen"
DB_FILE="/data/trafficgen.db"

mkdir -p $BACKUP_DIR

# 备份数据库
cp $DB_FILE $BACKUP_DIR/trafficgen_$DATE.db

# 压缩备份
gzip $BACKUP_DIR/trafficgen_$DATE.db

# 删除 30 天前的备份
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: trafficgen_$DATE.db.gz"
```

#### 定时备份

```bash
# 添加到 crontab
crontab -e

# 每天凌晨 2 点备份
0 2 * * * /path/to/backup.sh >> /var/log/trafficgen/backup.log 2>&1
```

### 性能监控

#### 实时监控

```bash
# CPU 和内存
top -p $(pgrep trafficgen)

# 网络流量
iftop -i eth0

# 磁盘 I/O
iotop -p $(pgrep trafficgen)
```

#### 性能分析

```bash
# CPU profiling
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# 内存 profiling
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Goroutine 分析
curl http://localhost:8080/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof
```

---

## 故障处理

### 常见问题

#### 1. 服务无法启动

**症状**: 服务启动失败

**排查步骤**:

```bash
# 查看日志
docker logs trafficgen

# 检查端口占用
netstat -tlnp | grep 8080

# 检查配置文件
cat config.yaml

# 检查权限
ls -la /data
ls -la /var/log/trafficgen
```

**解决方案**:
- 释放占用的端口
- 修正配置文件语法
- 调整文件权限

#### 2. 数据库连接失败

**症状**: 数据库连接错误

**排查步骤**:

```bash
# 检查数据库文件
ls -la /data/trafficgen.db

# 检查数据库连接
sqlite3 /data/trafficgen.db "SELECT 1;"

# 检查磁盘空间
df -h /data
```

**解决方案**:
- 创建数据目录
- 检查磁盘空间
- 修复损坏的数据库文件

#### 3. 内存不足

**症状**: OOM (Out of Memory)

**排查步骤**:

```bash
# 查看内存使用
free -h
ps aux | grep trafficgen

# 查看缓冲区状态
curl http://localhost:8080/api/v1/buffer/status

# 查看活跃任务
curl http://localhost:8080/api/v1/tasks?status=running
```

**解决方案**:
- 增加 buffer_size
- 减少并发任务数
- 增加系统内存

#### 4. 性能下降

**症状**: 吞吐量下降，延迟增加

**排查步骤**:

```bash
# 查看 CPU 使用
top -H -p $(pgrep trafficgen)

# 查看 Goroutine 数量
curl http://localhost:8080/debug/pprof/goroutine?debug=1

# 查看缓冲区使用率
curl http://localhost:8080/api/v1/buffer/status

# 查看端口分配
curl http://localhost:8080/api/v1/ports/stats
```

**解决方案**:
- 增加 Worker 数量
- 调整缓冲区大小
- 优化任务配置

#### 5. 网络问题

**症状**: 无法访问 API

**排查步骤**:

```bash
# 检查服务状态
curl http://localhost:8080/health

# 检查防火墙
iptables -L -n

# 检查网络连接
netstat -tlnp | grep 8080
```

**解决方案**:
- 开放防火墙端口
- 检查网络配置
- 重启网络服务

### 应急响应

#### 服务宕机

1. **确认问题**
   ```bash
   curl http://localhost:8080/health
   docker ps | grep trafficgen
   ```

2. **查看日志**
   ```bash
   docker logs --tail 100 trafficgen
   ```

3. **重启服务**
   ```bash
   docker restart trafficgen
   ```

4. **验证恢复**
   ```bash
   curl http://localhost:8080/health
   ```

#### 数据丢失

1. **停止服务**
   ```bash
   docker stop trafficgen
   ```

2. **恢复备份**
   ```bash
   cp /backup/trafficgen/trafficgen_20260402_020000.db.gz /data/
   gunzip /data/trafficgen_20260402_020000.db.gz
   mv /data/trafficgen_20260402_020000.db /data/trafficgen.db
   ```

3. **启动服务**
   ```bash
   docker start trafficgen
   ```

4. **验证数据**
   ```bash
   curl http://localhost:8080/api/v1/tasks
   ```

### 联系方式

- **技术支持**: support@example.com
- **紧急联系**: +86-xxx-xxxx-xxxx
- **文档中心**: https://docs.example.com/trafficgen
- **问题反馈**: https://github.com/your-org/traffic-generator/issues
