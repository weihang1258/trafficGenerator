# TrafficGenerator - 高性能网络流量生成器

面向网络测试与性能评估场景的流量生成系统，提供 Web 管理界面、REST API、实时推送和完整可观测性。

## 功能列表

### 流量生成

- 创建 TCP/UDP/HTTP/DNS/ICMP/ARP 流量任务
- TCP：配置是否启用握手、挥手、MSS
- HTTP：配置请求方法(GET/POST等)、URI、Body、Keep-Alive、事务数、思考时间
- DNS：配置域名、查询类型(A/AAAA/CNAME/MX)
- 设置源/目的 IP、端口、MAC
- 设置输出模式：网卡发送 / PCAP 保存 / 双路同时
- 设置 VLAN 标签

### 流量策略

- 创建/编辑/删除策略模板（可复用的流量参数定义）
- 策略包含：协议类型、协议参数、流量控制（并发流数/连接速率/吞吐量/占比/时长）
- 策略可被多个任务引用

### 任务管理

- 创建任务：命名、选择策略、选择输出目标
- 启动/停止/删除任务
- 查看任务状态(pending/running/stopped/completed/error)和进度
- 批量启动/停止/删除
- 按状态和协议类型筛选
- 实时统计：已发报文数、字节数、当前 PPS/BPS

### 网卡与端口

- 查看系统网卡信息（名称、MAC、IP、状态）
- 重新发现网卡
- 创建端口组（多网卡聚合 + 权重负载均衡）
- 端口自动分配与释放

### 历史记录

- 按时间范围查询已完成任务
- 查看历史统计：报文数、字节数、持续时间

### 用户与权限

- 注册/登录/登出
- 角色权限：管理员(全权限) / 用户(任务和策略管理) / 访客(只读)
- 用户自管理：修改邮箱/密码、删除账户
- 管理员：创建/编辑/禁用/重置密码/删除用户

### 系统监控

- Dashboard：活跃任务数、吞吐量、协议分布图表
- 系统状态：引擎运行状态、CPU/内存、运行时长
- 健康检查与就绪检查

### 系统设置

- 语言切换(中/英)
- 最大并发任务数
- 缓冲区大小
- 日志级别

## 安装部署

### 源码编译

```bash
cd trafficgen

# 后端
go mod download
mkdir -p bin && go build -o bin/trafficgen ./cmd/server

# 前端
cd web && npm install && npm run build && cd ..

# 启动
./bin/trafficgen -config configs/config.yaml
```

默认管理员：`admin` / `admin`，访问 http://localhost:8080

### Docker 单容器

```bash
cd trafficgen
docker build -t trafficgen:latest .
docker run -d --network host -v ./data:/data trafficgen:latest
```

### Docker Compose（含监控套件）

```bash
cd trafficgen

# 核心服务（trafficgen + Prometheus + Grafana）
docker compose up -d

# 按需启用可选服务
docker compose --profile postgres up -d      # PostgreSQL
docker compose --profile redis up -d         # Redis
docker compose --profile alertmanager up -d  # Alertmanager
```

| 服务 | 地址 | 账号 |
|------|------|------|
| Web 界面 | http://localhost:8080 | admin / admin |
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | - |

### Kubernetes

```bash
cd trafficgen/deployments/k8s
kubectl apply -f secret.yaml,configmap.yaml,deployment.yaml,service.yaml
kubectl apply -f ingress.yaml  # 按需
kubectl apply -f hpa.yaml      # 按需
```

## 配置

主配置文件 `configs/config.yaml`，关键项：

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `server.port` | 8080 | 监听端口 |
| `database.type` | sqlite | sqlite / postgres |
| `engine.config_workers` | 4 | 配置生成协程数 |
| `engine.packet_workers` | 8 | 报文构造协程数 |
| `engine.buffer_size` | 4096 | 环形缓冲容量 |
| `auth.jwt_secret` | - | 生产环境务必修改 |
| `auth.admin.password` | admin | 生产环境务必修改 |

> 生产环境建议使用 `config.standalone.yaml`，通过环境变量注入敏感配置。