# trafficgen

**MCP 网络流量生成与 pcap 分析服务** —— AI 客户端（Claude Code 等）通过 MCP 协议连接后，用自然语言驱动 125 种协议的流量生成，产物为标准 pcap 或经物理网卡真实发帧，并可在同一个会话内对产物做逐流、逐包、逐字节的回读分析。

## MCP 能做什么

| 能力 | 工具 | 说明 |
|------|------|------|
| 协议配置查询 | `flowb_query_layers` | 每个协议的已验证配置示例（examples）与字段 schema，配置可直接复制使用 |
| 流量生成 | `flowb_generate_traffic` | 一步完成策略创建+任务启动，输出 pcap 文件或网卡真发 |
| 策略/任务管理 | `flowb_manage_strategies` / `flowb_manage_tasks` | 策略复用、任务启停/批量/进度/历史（list 支持 `name_prefix` 过滤） |
| 任务等待 | `flowb_wait_for_task` / `flowb_get_task_progress` | 终态等待与进度轮询 |
| pcap 分析 | `flowb_manage_pcaps` | 任务产物自动入库；流级统计 → 逐包头字段 → 原始字节/重组流；内容搜索、批量字段提取、全流文本导出；外部 pcap 一步导入 |
| pcap 回放 | `flowb_replay_pcap` | 任意 pcap 原样重放（支持 loop 循环） |
| 网卡真发 | `flowb_manage_port_groups` | 多网卡聚合 + 权重负载均衡的端口组，物理口实发 |
| 系统管理 | `flowb_manage_users` / `flowb_manage_auth` / `flowb_manage_settings` / `flowb_query_system` 等 | 用户/认证/配置/系统状态 |

远程优先设计：所有工具经 HTTP 调用（`X-MCP-Key` 认证），大结果自动导出为文件并返回下载链接，客户端无需知道服务器路径。另有 stdio 传输供本机集成。

> `flowb_run_protocol_case` / `flowb_run_protocol_suite` 是内部测试专用工具（协议回归驱动），正常业务场景不使用。

## 当前支持

- **125 种协议**：工业（Modbus/S7/IEC 104/DNP3/OPC UA…）、车联（JT808/JT809/GB32960…）、金融（ISO 8583 族/DCERPC…）、隧道（VXLAN/GRE/Geneve/SRV6…）、应用（HTTP/SMTP/FTP/MQTT/DNS/TLS…）与 TCP/UDP 载体。完整清单用 `flowb_query_system` `action=protocols` 获取，逐协议配置示例用 `flowb_query_layers` `action=examples&protocol=<proto>` 获取
- **输出方式**：pcap 文件 / 物理网卡实发 / 双路同时
- **平台**：Linux x86_64；网卡实发需 root 权限（CAP_NET_RAW）
- **协议清单、设计文档与用例文档**：见 [`docs/`](docs/)（核心记忆 [`docs/CORE_MEMORY.md`](docs/CORE_MEMORY.md)、协议花名册 [`docs/LAYERCHAIN_INDEX.md`](docs/LAYERCHAIN_INDEX.md)、逐协议设计+用例 [`docs/protocols/`](docs/protocols/)）

## 安装使用

### 安装（推荐离线包）

```bash
tar xzf trafficgen-vX.Y.Z-linux-amd64.tar.gz
cd trafficgen-vX.Y.Z-linux-amd64
sudo ./install.sh
```

单二进制 + systemd 托管，安装即启动、开机自启。内网 HTTP 服务器在线安装：

```bash
curl -fsSL http://<server>/install.sh | sudo bash
```

发布产物由 `trafficgen/` 下 `make` 打包（install.sh / tar.gz / SHA256SUMS）。

### 从源码构建

```bash
cd trafficgen
make build          # 产物见 Makefile
```

### 配置最小集

```yaml
mcp:
  api_key: "<长随机串>"            # MCP HTTP 认证
  transports:
    http:
      enabled: true
      listen: "0.0.0.0:8086"       # MCP 端点
database:
  sqlite:
    path: "./data/trafficgen.db"
```

完整模板见 [`trafficgen/configs/`](trafficgen/configs/)。

### 快速开始

MCP 客户端指向 `http://<host>:8086/mcp`（携带 api_key），然后：

1. `flowb_query_layers` `{"action":"examples","protocol":"mqtt"}` — 拿该协议的已验证配置
2. `flowb_generate_traffic` — 提交配置生成流量（pcap 或网卡输出）
3. `flowb_wait_for_task` → `flowb_manage_pcaps` `{"action":"list_flows"}` — 等待完成并分析产物

## 使用声明

仅用于授权网络环境下的测试（实验室 / 自有网络 / 客户委托测试）；对未授权网络使用本工具产生的一切责任由使用者承担。

## License

[AGPL-3.0](LICENSE) —— 本仓库以 GNU Affero General Public License v3.0 开源：任何通过网络提供服务或分发的衍生版本，须同样以 AGPL-3.0 开源其源码（第 13 条）。

**商业授权**：需要闭源集成、OEM 嵌入或豁免 AGPL 义务的商业场景，另行联系项目维护者获取商业许可（双重许可，版权人可同时提供）。

第三方依赖均为宽松许可（Apache-2.0 / MIT / BSD），与 AGPL-3.0 兼容，明细见 `trafficgen/go.mod`。
