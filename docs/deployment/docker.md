# Docker 部署指南

本文档介绍如何使用 Docker 和 Docker Compose 部署 Traffic Generator。

## 目录

1. [前置要求](#前置要求)
2. [快速开始](#快速开始)
3. [配置说明](#配置说明)
4. [服务管理](#服务管理)
5. [数据持久化](#数据持久化)
6. [监控配置](#监控配置)
7. [故障排查](#故障排查)

---

## 前置要求

### 软件要求

| 软件 | 版本要求 | 检查命令 |
|------|---------|---------|
| Docker | >= 20.10 | `docker --version` |
| Docker Compose | >= 2.0 | `docker compose version` |

### 硬件要求

| 资源 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 2核 | 4核+ |
| 内存 | 4GB | 8GB+ |
| 磁盘 | 20GB | 50GB+ |

### 网络要求

- 端口 8080: Traffic Generator API
- 端口 3000: Grafana Web UI
- 端口 9090: Prometheus Web UI
- 端口 9093: AlertManager (可选)

---

## 快速开始

### 1. 克隆代码

```bash
git clone https://github.com/your-org/traffic-generator.git
cd traffic-generator/trafficgen
```

### 2. 创建配置文件

创建 `config.yaml`:

```bash
cat > config.yaml << EOF
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
EOF
```

### 3. 创建必要目录

```bash
mkdir -p data logs
```

### 4. 启动服务

```bash
# 启动所有服务
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f trafficgen
```

### 5. 验证部署

```bash
# 健康检查
curl http://localhost:8080/health

# 查看指标
curl http://localhost:8080/metrics

# 访问 Grafana
open http://localhost:3000
# 默认用户名/密码: admin/admin
```

---

## 配置说明

### 基础配置

编辑 `config.yaml`:

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
  type: "sqlite"          # sqlite 或 postgres
  dsn: "/data/trafficgen.db"  # SQLite 文件路径
  # type: "postgres"
  # dsn: "host=postgres port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=disable"

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
  level: "info"           # debug, info, warn, error
  format: "json"          # json 或 text
  output: "/var/log/trafficgen/app.log"
```

### 环境变量配置

可以通过环境变量覆盖配置:

```bash
# 创建 .env 文件
cat > .env << EOF
TRAFFICGEN_SERVER_PORT=8080
TRAFFICGEN_DATABASE_TYPE=sqlite
TRAFFICGEN_LOGGING_LEVEL=info
EOF

# Docker Compose 会自动读取 .env 文件
docker compose up -d
```

### 使用 PostgreSQL

启用 PostgreSQL 服务:

```bash
# 使用 postgres profile 启动
docker compose --profile postgres up -d

# 修改 config.yaml
database:
  type: "postgres"
  dsn: "host=postgres port=5432 user=trafficgen password=trafficgen_secret dbname=trafficgen sslmode=disable"
```

### 使用 Redis

启用 Redis 服务:

```bash
# 使用 redis profile 启动
docker compose --profile redis up -d
```

---

## 服务管理

### 启动服务

```bash
# 启动所有服务
docker compose up -d

# 启动特定服务
docker compose up -d trafficgen

# 启动并查看日志
docker compose up -d && docker compose logs -f
```

### 停止服务

```bash
# 停止所有服务
docker compose down

# 停止特定服务
docker compose stop trafficgen

# 停止并删除数据卷
docker compose down -v
```

### 重启服务

```bash
# 重启所有服务
docker compose restart

# 重启特定服务
docker compose restart trafficgen
```

### 查看日志

```bash
# 查看所有服务日志
docker compose logs

# 查看特定服务日志
docker compose logs trafficgen

# 实时查看日志
docker compose logs -f trafficgen

# 查看最近 100 行日志
docker compose logs --tail 100 trafficgen
```

### 查看服务状态

```bash
# 查看所有服务状态
docker compose ps

# 查看容器资源使用
docker stats trafficgen
```

---

## 数据持久化

### 数据卷说明

Docker Compose 配置了以下数据卷:

| 数据卷 | 挂载点 | 说明 |
|--------|--------|------|
| `./data` | `/data` | 数据库文件 |
| `./logs` | `/var/log/trafficgen` | 日志文件 |
| `prometheus-data` | `/prometheus` | Prometheus 数据 |
| `grafana-data` | `/var/lib/grafana` | Grafana 数据 |

### 数据备份

#### SQLite 数据库备份

```bash
# 备份数据库
cp data/trafficgen.db data/trafficgen.db.backup

# 或使用 SQLite 在线备份
sqlite3 data/trafficgen.db ".backup 'data/trafficgen.db.backup'"
```

#### 数据卷备份

```bash
# 备份 Prometheus 数据
docker run --rm -v prometheus-data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-backup.tar.gz -C /data .

# 备份 Grafana 数据
docker run --rm -v grafana-data:/data -v $(pwd):/backup alpine tar czf /backup/grafana-backup.tar.gz -C /data .
```

### 数据恢复

```bash
# 恢复 Prometheus 数据
docker run --rm -v prometheus-data:/data -v $(pwd):/backup alpine tar xzf /backup/prometheus-backup.tar.gz -C /data

# 恢复 Grafana 数据
docker run --rm -v grafana-data:/data -v $(pwd):/backup alpine tar xzf /backup/grafana-backup.tar.gz -C /data

# 重启服务
docker compose restart prometheus grafana
```

---

## 监控配置

### Prometheus 配置

编辑 `deployments/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'trafficgen'
    static_configs:
      - targets: ['trafficgen:8080']
    metrics_path: '/metrics'
```

访问 Prometheus UI: http://localhost:9090

### Grafana 配置

1. 访问 Grafana: http://localhost:3000
2. 登录 (admin/admin)
3. 添加数据源:
   - Type: Prometheus
   - URL: http://prometheus:9090
4. 导入仪表盘:
   - 点击 "+" → "Import"
   - 上传 `deployments/grafana/dashboard.json`

### AlertManager 配置

启用 AlertManager:

```bash
# 使用 alertmanager profile 启动
docker compose --profile alertmanager up -d
```

编辑 `deployments/prometheus/alertmanager.yml` 配置邮件通知。

---

## 故障排查

### 容器无法启动

**问题**: 容器启动失败

**排查步骤**:

```bash
# 查看容器日志
docker compose logs trafficgen

# 查看容器状态
docker compose ps

# 检查容器配置
docker inspect trafficgen
```

**常见原因**:
- 端口被占用
- 配置文件错误
- 权限不足

### 网络问题

**问题**: 无法访问服务

**排查步骤**:

```bash
# 检查端口监听
netstat -tlnp | grep 8080

# 检查防火墙
iptables -L -n

# 检查容器网络
docker network ls
docker network inspect trafficgen-network
```

### 数据库连接失败

**问题**: 数据库连接错误

**排查步骤**:

```bash
# 检查数据库文件
ls -la data/

# 检查数据库连接
sqlite3 data/trafficgen.db "SELECT 1;"

# 查看日志
docker compose logs trafficgen | grep -i database
```

### 性能问题

**问题**: 性能下降

**排查步骤**:

```bash
# 查看容器资源使用
docker stats trafficgen

# 查看系统资源
top
free -h
df -h

# 查看应用指标
curl http://localhost:8080/metrics
```

---

## 高级配置

### 资源限制

编辑 `docker-compose.yml` 添加资源限制:

```yaml
services:
  trafficgen:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

### 健康检查

自定义健康检查:

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### 日志配置

配置日志驱动:

```yaml
services:
  trafficgen:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## 生产环境建议

### 安全配置

1. **修改默认密码**
   ```bash
   # 修改 Grafana 密码
   GF_SECURITY_ADMIN_PASSWORD=your-secure-password
   ```

2. **使用 HTTPS**
   - 配置反向代理 (Nginx/Traefik)
   - 使用 Let's Encrypt 证书

3. **网络隔离**
   - 使用 Docker 网络
   - 限制端口暴露

4. **定期备份**
   - 自动化备份脚本
   - 异地备份

### 性能优化

1. **调整 Worker 数量**
   ```yaml
   engine:
     config_workers: 8
     packet_workers: 16
     output_workers: 8
   ```

2. **增加缓冲区大小**
   ```yaml
   engine:
     buffer_size: 8192
     max_buffer_bytes: 209715200  # 200MB
   ```

3. **使用 SSD 存储**
   - 数据库文件
   - 日志文件

---

## 常用命令速查

```bash
# 启动服务
docker compose up -d

# 停止服务
docker compose down

# 重启服务
docker compose restart

# 查看日志
docker compose logs -f trafficgen

# 查看状态
docker compose ps

# 进入容器
docker compose exec trafficgen sh

# 备份数据
cp data/trafficgen.db data/trafficgen.db.backup

# 更新镜像
docker compose pull
docker compose up -d
```

---

## 参考链接

- [Docker 官方文档](https://docs.docker.com/)
- [Docker Compose 文档](https://docs.docker.com/compose/)
- [Prometheus 文档](https://prometheus.io/docs/)
- [Grafana 文档](https://grafana.com/docs/)
