# 生产环境部署指南

本文档提供 Traffic Generator 生产环境部署的完整指南，包括环境准备、灰度发布、回滚预案等内容。

## 目录

1. [生产环境准备](#生产环境准备)
2. [部署流程](#部署流程)
3. [灰度发布](#灰度发布)
4. [回滚预案](#回滚预案)
5. [监控验证](#监控验证)
6. [应急预案](#应急预案)

---

## 生产环境准备

### 硬件要求

| 组件 | 最低配置 | 推荐配置 | 说明 |
|------|---------|---------|------|
| **应用服务器** | 4核 CPU, 8GB 内存 | 8核 CPU, 16GB 内存 | 运行 Traffic Generator |
| **数据库服务器** | 2核 CPU, 4GB 内存 | 4核 CPU, 8GB 内存 | PostgreSQL/MySQL |
| **监控服务器** | 2核 CPU, 4GB 内存 | 4核 CPU, 8GB 内存 | Prometheus + Grafana |
| **存储** | 50GB SSD | 100GB SSD | 数据库和日志存储 |
| **网络** | 1Gbps 网卡 | 10Gbps 网卡 | 高吞吐量场景 |

### 软件要求

| 软件 | 版本要求 | 说明 |
|------|---------|------|
| 操作系统 | Ubuntu 20.04+ / CentOS 8+ | Linux 发行版 |
| Docker | 20.10+ | 容器运行时 |
| Docker Compose | 2.0+ | 容器编排工具 |
| Kubernetes | 1.25+ | 容器编排平台（可选） |
| PostgreSQL | 13+ | 生产数据库（推荐） |
| Redis | 6.0+ | 缓存服务（可选） |

### 网络配置

#### 防火墙规则

```bash
# 开放必要端口
# API 端口
sudo ufw allow 8080/tcp

# Prometheus 端口
sudo ufw allow 9090/tcp

# Grafana 端口
sudo ufw allow 3000/tcp

# 启用防火墙
sudo ufw enable
```

#### 网络隔离

- 应用服务器：可从内网访问
- 数据库服务器：仅允许应用服务器访问
- 监控服务器：仅允许运维团队访问

### 安全配置

#### 1. 修改默认密码

```bash
# 修改数据库密码
ALTER USER trafficgen WITH PASSWORD 'strong-password-here';

# 修改 Grafana 密码
GF_SECURITY_ADMIN_PASSWORD=your-secure-password

# 修改 JWT 密钥
JWT_SECRET=$(openssl rand -base64 32)
```

#### 2. SSL/TLS 证书

```bash
# 使用 Let's Encrypt 获取免费证书
sudo apt install certbot
sudo certbot certonly --standalone -d trafficgen.example.com

# 证书自动续期
sudo crontab -e
0 12 * * * /usr/bin/certbot renew --quiet
```

#### 3. 配置 HTTPS

```nginx
# Nginx 反向代理配置
server {
    listen 443 ssl http2;
    server_name trafficgen.example.com;

    ssl_certificate /etc/letsencrypt/live/trafficgen.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/trafficgen.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name trafficgen.example.com;
    return 301 https://$server_name$request_uri;
}
```

### 数据库配置

#### PostgreSQL 优化

```sql
-- 创建数据库和用户
CREATE DATABASE trafficgen;
CREATE USER trafficgen WITH ENCRYPTED PASSWORD 'strong-password';
GRANT ALL PRIVILEGES ON DATABASE trafficgen TO trafficgen;

-- 性能优化配置 (postgresql.conf)
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 8
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
```

### 备份策略

#### 数据库备份

```bash
#!/bin/bash
# backup-database.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/postgresql"
DB_NAME="trafficgen"
DB_USER="trafficgen"

mkdir -p $BACKUP_DIR

# 备份数据库
pg_dump -U $DB_USER $DB_NAME | gzip > $BACKUP_DIR/trafficgen_$DATE.sql.gz

# 删除 7 天前的备份
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Database backup completed: trafficgen_$DATE.sql.gz"
```

#### 文件备份

```bash
#!/bin/bash
# backup-files.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/files"
DATA_DIR="/data/trafficgen"

mkdir -p $BACKUP_DIR

# 备份数据文件
tar czf $BACKUP_DIR/trafficgen_data_$DATE.tar.gz -C $(dirname $DATA_DIR) $(basename $DATA_DIR)

# 删除 30 天前的备份
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "File backup completed: trafficgen_data_$DATE.tar.gz"
```

#### 定时备份

```bash
# 添加到 crontab
crontab -e

# 每天凌晨 2 点备份数据库
0 2 * * * /path/to/backup-database.sh >> /var/log/trafficgen/backup.log 2>&1

# 每天凌晨 3 点备份文件
0 3 * * * /path/to/backup-files.sh >> /var/log/trafficgen/backup.log 2>&1
```

---

## 部署流程

### 部署前检查清单

- [ ] 硬件资源满足要求
- [ ] 软件依赖已安装
- [ ] 网络配置完成
- [ ] 安全配置完成
- [ ] 数据库已备份
- [ ] 配置文件已准备
- [ ] 监控系统已部署
- [ ] 团队已通知

### 部署步骤

#### 1. 准备配置文件

```bash
# 创建配置目录
mkdir -p /opt/trafficgen/{data,logs,config}

# 创建配置文件
cat > /opt/trafficgen/config/config.yaml << EOF
server:
  host: "0.0.0.0"
  port: 8080

database:
  type: "postgres"
  dsn: "host=postgres port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=require"

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
EOF
```

#### 2. 拉取镜像

```bash
# 拉取最新镜像
docker pull your-registry/trafficgen:v1.0.0

# 验证镜像
docker images trafficgen:v1.0.0
```

#### 3. 启动服务

```bash
# 使用 Docker Compose 启动
cd /opt/trafficgen
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f trafficgen
```

#### 4. 健康检查

```bash
# 检查服务健康状态
curl http://localhost:8080/health

# 检查 API 可用性
curl http://localhost:8080/api/v1/tasks

# 检查监控指标
curl http://localhost:8080/metrics
```

#### 5. 验证部署

```bash
# 创建测试任务
curl -X POST http://localhost:8080/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-task",
    "protocol": "tcp",
    "config": {
      "src_ip": "192.168.1.1",
      "dst_ip": "192.168.1.2",
      "src_port": 12345,
      "dst_port": 80
    }
  }'

# 查看任务列表
curl http://localhost:8080/api/v1/tasks
```

---

## 灰度发布

### 灰度发布策略

Traffic Generator 支持以下灰度发布策略：

#### 1. 基于权重的流量分配

```yaml
# Kubernetes Ingress 金丝雀配置
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: trafficgen-canary
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "10"  # 10% 流量
spec:
  rules:
  - host: trafficgen.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: trafficgen-canary
            port:
              number: 8080
```

#### 2. 基于 Header 的流量分配

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: trafficgen-canary-header
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-by-header: "X-Canary"
spec:
  rules:
  - host: trafficgen.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: trafficgen-canary
            port:
              number: 8080
```

### 灰度发布流程

#### 阶段 1: 内部测试（10% 流量）

```bash
# 部署金丝雀版本
kubectl apply -f deployments/k8s/canary.yaml

# 设置 10% 流量
kubectl annotate ingress trafficgen-canary \
  nginx.ingress.kubernetes.io/canary-weight="10"

# 监控错误率
watch -n 5 'curl -s http://localhost:9090/api/v1/query?query=rate(http_requests_total{status=~"5.."}[5m])'

# 持续观察 1 小时
```

#### 阶段 2: 小规模测试（30% 流量）

```bash
# 增加到 30% 流量
kubectl annotate ingress trafficgen-canary \
  nginx.ingress.kubernetes.io/canary-weight="30" --overwrite

# 监控性能指标
watch -n 5 'curl -s http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,rate(http_request_duration_seconds_bucket[5m]))'

# 持续观察 2 小时
```

#### 阶段 3: 中等规模测试（50% 流量）

```bash
# 增加到 50% 流量
kubectl annotate ingress trafficgen-canary \
  nginx.ingress.kubernetes.io/canary-weight="50" --overwrite

# 全面监控
# - 错误率
# - 响应时间
# - 资源使用
# - 业务指标

# 持续观察 4 小时
```

#### 阶段 4: 全量发布（100% 流量）

```bash
# 切换全部流量到新版本
kubectl set image deployment/trafficgen trafficgen=trafficgen:v2.0.0

# 删除金丝雀部署
kubectl delete ingress trafficgen-canary
kubectl delete deployment trafficgen-canary

# 监控验证
# 持续观察 24 小时
```

### 灰度发布检查点

每个阶段需要检查以下指标：

| 指标 | 阈值 | 说明 |
|------|------|------|
| 错误率 | < 1% | HTTP 5xx 错误比例 |
| P95 延迟 | < 100ms | 95% 请求响应时间 |
| CPU 使用率 | < 70% | CPU 使用率 |
| 内存使用率 | < 80% | 内存使用率 |
| 任务成功率 | > 95% | 任务执行成功率 |

---

## 回滚预案

### 回滚触发条件

满足以下任一条件立即回滚：

1. **错误率飙升**: HTTP 5xx 错误率 > 5%
2. **性能下降**: P95 延迟 > 500ms
3. **资源耗尽**: CPU 或内存使用率 > 90%
4. **功能故障**: 核心功能不可用
5. **数据丢失**: 数据库数据丢失或损坏

### 快速回滚步骤

#### Docker 环境

```bash
#!/bin/bash
# rollback-docker.sh

# 1. 停止当前版本
docker compose down

# 2. 切换到上一个版本
docker tag trafficgen:v2.0.0 trafficgen:backup
docker tag trafficgen:v1.0.0 trafficgen:v2.0.0

# 3. 重启服务
docker compose up -d

# 4. 验证服务
sleep 10
curl -f http://localhost:8080/health || exit 1

echo "Rollback completed successfully"
```

#### Kubernetes 环境

```bash
#!/bin/bash
# rollback-k8s.sh

# 1. 查看部署历史
kubectl rollout history deployment/trafficgen -n trafficgen

# 2. 回滚到上一个版本
kubectl rollout undo deployment/trafficgen -n trafficgen

# 3. 监控回滚状态
kubectl rollout status deployment/trafficgen -n trafficgen

# 4. 验证服务
kubectl get pods -n trafficgen
kubectl logs -f deployment/trafficgen -n trafficgen

echo "Rollback completed successfully"
```

#### 回滚到指定版本

```bash
# 查看版本历史
kubectl rollout history deployment/trafficgen -n trafficgen

# 回滚到指定版本
kubectl rollout undo deployment/trafficgen --to-revision=3 -n trafficgen

# 监控回滚状态
kubectl rollout status deployment/trafficgen -n trafficgen
```

### 数据库回滚

```bash
#!/bin/bash
# rollback-database.sh

# 1. 停止应用服务
docker compose stop trafficgen

# 2. 备份当前数据库
pg_dump -U trafficgen trafficgen > /backup/trafficgen_before_rollback.sql

# 3. 恢复到之前版本
psql -U trafficgen trafficgen < /backup/trafficgen_20260402.sql

# 4. 重启应用服务
docker compose start trafficgen

# 5. 验证数据完整性
curl http://localhost:8080/api/v1/tasks

echo "Database rollback completed"
```

### 回滚验证

```bash
# 1. 检查服务状态
curl http://localhost:8080/health

# 2. 检查 API 功能
curl http://localhost:8080/api/v1/tasks

# 3. 检查监控指标
curl http://localhost:9090/api/v1/query?query=up{job="trafficgen"}

# 4. 检查日志
docker logs trafficgen --tail 100

# 5. 检查错误率
curl http://localhost:9090/api/v1/query?query=rate(http_requests_total{status=~"5.."}[5m])
```

---

## 监控验证

### 关键监控指标

#### 应用指标

| 指标 | 说明 | 告警阈值 |
|------|------|---------|
| `up{job="trafficgen"}` | 服务可用性 | == 0 持续 1 分钟 |
| `http_requests_total` | HTTP 请求总数 | - |
| `http_request_duration_seconds` | HTTP 请求延迟 | P95 > 100ms |
| `trafficgen_packets_sent_total` | 发送数据包总数 | - |
| `trafficgen_active_tasks` | 活跃任务数 | > 100 |

#### 系统指标

| 指标 | 说明 | 告警阈值 |
|------|------|---------|
| `process_cpu_seconds_total` | CPU 使用时间 | > 80% |
| `process_resident_memory_bytes` | 内存使用量 | > 80% |
| `disk_usage_percent` | 磁盘使用率 | > 85% |
| `network_receive_bytes_total` | 网络接收字节 | - |

### 监控大盘

#### Grafana Dashboard

1. **系统概览面板**
   - 服务状态
   - CPU/内存使用率
   - 网络流量
   - 磁盘 I/O

2. **应用性能面板**
   - 请求速率
   - 响应时间分布
   - 错误率
   - 活跃任务数

3. **业务指标面板**
   - 数据包发送速率
   - 吞吐量
   - 任务成功率
   - 协议分布

### 告警规则

#### Prometheus 告警配置

```yaml
groups:
  - name: trafficgen.rules
    interval: 30s
    rules:
      # 服务宕机
      - alert: ServiceDown
        expr: up{job="trafficgen"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Traffic Generator service is down"

      # 高错误率
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      # 高延迟
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"

      # CPU 使用率高
      - alert: HighCPUUsage
        expr: rate(process_cpu_seconds_total{job="trafficgen"}[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage"

      # 内存使用高
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes{job="trafficgen"} / 1024 / 1024 / 1024 > 8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
```

---

## 应急预案

### 应急响应流程

```
发现问题 → 评估影响 → 启动应急预案 → 执行修复 → 验证恢复 → 总结复盘
```

### 常见故障处理

#### 1. 服务无法启动

**症状**: 服务启动失败

**排查步骤**:
```bash
# 查看日志
docker logs trafficgen

# 检查端口占用
netstat -tlnp | grep 8080

# 检查配置文件
cat /opt/trafficgen/config/config.yaml

# 检查权限
ls -la /opt/trafficgen
```

**解决方案**:
- 释放占用的端口
- 修正配置文件错误
- 调整文件权限

#### 2. 数据库连接失败

**症状**: 数据库连接错误

**排查步骤**:
```bash
# 检查数据库状态
systemctl status postgresql

# 测试数据库连接
psql -U trafficgen -d trafficgen -h localhost

# 检查网络连接
telnet localhost 5432
```

**解决方案**:
- 启动数据库服务
- 检查数据库配置
- 检查网络连接

#### 3. 性能下降

**症状**: 响应时间变长，吞吐量下降

**排查步骤**:
```bash
# 检查资源使用
top
free -h
df -h

# 检查进程状态
ps aux | grep trafficgen

# 检查网络流量
iftop -i eth0
```

**解决方案**:
- 增加资源配额
- 优化配置参数
- 扩容服务实例

### 应急联系人

| 角色 | 姓名 | 电话 | 邮箱 |
|------|------|------|------|
| 技术负责人 | - | - | tech-lead@example.com |
| 运维负责人 | - | - | ops-lead@example.com |
| DBA | - | - | dba@example.com |
| 安全负责人 | - | - | security@example.com |

### 应急响应时间

| 级别 | 响应时间 | 解决时间 | 说明 |
|------|---------|---------|------|
| P0 - 紧急 | 5 分钟 | 1 小时 | 服务完全不可用 |
| P1 - 严重 | 15 分钟 | 4 小时 | 核心功能受影响 |
| P2 - 一般 | 30 分钟 | 24 小时 | 非核心功能受影响 |
| P3 - 轻微 | 2 小时 | 72 小时 | 优化建议 |

---

## 部署检查清单

### 部署前

- [ ] 硬件资源满足要求
- [ ] 软件依赖已安装
- [ ] 网络配置完成
- [ ] 安全配置完成
- [ ] 数据库已备份
- [ ] 配置文件已准备
- [ ] 监控系统已部署
- [ ] 告警规则已配置
- [ ] 团队已通知

### 部署中

- [ ] 服务启动成功
- [ ] 健康检查通过
- [ ] API 功能正常
- [ ] 监控指标正常
- [ ] 日志输出正常

### 部署后

- [ ] 功能测试通过
- [ ] 性能测试通过
- [ ] 监控大盘正常
- [ ] 告警测试通过
- [ ] 文档已更新
- [ ] 团队已培训

---

## 附录

### 配置文件模板

见 `docs/deployment/configuration.md`

### 运维手册

见 `docs/operations/operations-manual.md`

### 故障排查手册

见 `docs/operations/troubleshooting-manual.md`

---

## 更新记录

| 日期 | 版本 | 说明 | 作者 |
|------|------|------|------|
| 2026-04-02 | 1.0.0 | 初始版本 | - |
