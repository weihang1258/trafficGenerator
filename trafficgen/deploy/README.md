# trafficgen — MCP 流量生成服务

trafficgen 是一个高性能网络流量生成引擎，通过 **MCP（Model Context Protocol）**
对外提供服务：AI 客户端（Claude Code 等）或任何 MCP 客户端连接后，即可用自然语言
驱动 125+ 协议的流量生成任务（TCP/UDP/HTTP 会话、工业协议、隧道封装、raw-IP 帧…），
产物为标准 pcap 文件，或经物理网卡真实发帧。

- 单个静态二进制，零外部依赖（SQLite 内嵌）
- systemd 托管，安装即启动、开机自启、崩溃自动拉起
- v1 支持 Linux x86_64

## 安装

### 方式一：离线安装（推荐）

```bash
tar xzf trafficgen-v1.1.0-linux-amd64.tar.gz
cd trafficgen-v1.1.0-linux-amd64
sudo ./install.sh
```

### 方式二：在线一条命令（内网 HTTP 服务器）

把发布产物（`dist/` 里的 `install.sh`、`trafficgen-vX.Y.Z-linux-amd64.tar.gz`、
`SHA256SUMS` 三个文件）放到任意可匿名访问的 HTTP 服务器（nginx、minio、OSS、
内网镜像均可；调试时可在仓库 `trafficgen/` 下 `make serve-dist` 直接托管）：

```bash
curl -fsSL http://<服务器>/install.sh | sudo bash
```

零参数：下载地址与版本号已在 `make dist` 时烧入脚本（可用环境变量
`TRAFFICGEN_RELEASE_BASE` 或 `bash -s -- <base> <版本号>` 覆盖）。脚本自动
下载 tarball、SHA256 校验、解压安装。

安装脚本自动完成：安装到 `/opt/trafficgen` → 创建 `trafficgen` 系统用户 →
生成 `/etc/trafficgen/config.yaml`（**自动生成随机 API Key 并打印**）→
注册并启动 systemd 服务。结束后终端会显示：

```
✅ trafficgen v1.1.0 安装完成，服务已启动（开机自启）
   MCP 端点 :  http://192.168.1.10:8086/mcp
   API Key  :  3fa9c1…   （客户端请求头 X-MCP-Key）
```

## 日常操作（systemd）

| 操作 | 命令 |
|---|---|
| 查看状态 | `systemctl status trafficgen` |
| 启动 | `sudo systemctl start trafficgen` |
| 停止 | `sudo systemctl stop trafficgen` |
| 重启（改配置后） | `sudo systemctl restart trafficgen` |
| 实时日志 | `journalctl -u trafficgen -f` |
| 最近 100 行日志 | `journalctl -u trafficgen -n 100 --no-pager` |
| 开机自启 开 | `sudo systemctl enable trafficgen` |
| 开机自启 关 | `sudo systemctl disable trafficgen` |
| 查看版本 | `/opt/trafficgen/bin/trafficgen -version` |

## 客户端接入（MCP）

服务端点为 `http://<主机IP>:8086/mcp`，鉴权请求头 `X-MCP-Key: <API Key>`
（Key 在安装结束打印；忘了可查看配置文件 `sudo cat /etc/trafficgen/config.yaml | grep api_key`）。

**Claude Code：**

```bash
claude mcp add --transport http trafficgen http://<主机IP>:8086/mcp \
  --header "X-MCP-Key: <API Key>"
```

**通用 MCP 客户端（JSON 配置）：**

```json
{
  "mcpServers": {
    "trafficgen": {
      "type": "http",
      "url": "http://<主机IP>:8086/mcp",
      "headers": { "X-MCP-Key": "<API Key>" }
    }
  }
}
```

接入后即可用自然语言下发任务，例如：*“用 modbus 协议生成 100 个事务的流量，
写到 pcap 文件”*。可用工具包括流量生成（`flowb_generate_traffic`）、任务管理、
策略管理、端口组管理、pcap 资产管理等（`tools/list` 可枚举全部）。

## 配置

配置文件：`/etc/trafficgen/config.yaml`（修改后 `sudo systemctl restart trafficgen` 生效）。

| 想改什么 | 改哪里 |
|---|---|
| MCP 端口 | `mcp.transports.http.listen`（默认 `0.0.0.0:8086`；仅本机用改 `127.0.0.1:8086`） |
| API Key | `mcp.api_key`（任意长随机串；为空则服务拒绝启动） |
| 日志级别 | `logging.level`（`debug`/`info`/`warn`/`error`） |
| 换 PostgreSQL | `database.type: "postgres"` 并填 `database.postgres` 段 |

数据与产物（相对工作目录 `/var/lib/trafficgen`）：

| 路径 | 内容 |
|---|---|
| `/var/lib/trafficgen/data/trafficgen.db` | 任务/策略元数据（SQLite，WAL 模式） |
| `/var/lib/trafficgen/data/filesystem/` | pcap 产物与内容寻址文件系统 |
| `/var/lib/trafficgen/pcap/` | 引擎直接落盘的 pcap |

## 真实网卡发帧（可选）

默认所有流量写入 pcap 文件。要从物理网卡真实发帧：

1. 在配置的 `engine` 下确认端口组，经 MCP `flowb_manage_port_groups` 创建端口组，
   绑定发包网卡（如 `enp135s0f0np0`）；
2. 关闭网卡分片卸载，保证线上字节与引擎帧一致：
   ```bash
   sudo ethtool -K <网卡> tso off gso off
   ```
3. 系统服务已带 `CAP_NET_RAW + CAP_NET_ADMIN`（`AmbientCapabilities`），无需手动 setcap。

## 卸载

```bash
sudo /opt/trafficgen/uninstall.sh           # 卸载程序，保留配置与数据
sudo /opt/trafficgen/uninstall.sh --purge   # 连配置、数据、pcap 产物一起删除
```

## 故障排查

| 现象 | 排查 |
|---|---|
| 服务起不来 | `journalctl -u trafficgen -n 50 --no-pager`；最常见：`api_key` 为空（MCP HTTP 强制要求） |
| 客户端连不上 | 端口监听 `ss -tlnp \| grep 8086`；防火墙 `sudo firewall-cmd --add-port=8086/tcp --permanent && sudo firewall-cmd --reload` |
| 401/鉴权失败 | 请求头 `X-MCP-Key` 与配置 `mcp.api_key` 是否一致 |
| 磁盘涨满 | pcap 产物在 `/var/lib/trafficgen`，清理后 `sudo systemctl restart trafficgen` |
| 升级版本 | 重新跑新包的 `install.sh` 即可：替换二进制、保留配置与数据、自动重启 |

## 目录与文件清单

```
/opt/trafficgen/bin/trafficgen          # 程序本体（静态二进制）
/etc/trafficgen/config.yaml             # 配置（0600）
/var/lib/trafficgen/                    # 工作目录：DB、pcap 产物
/etc/systemd/system/trafficgen.service  # systemd 服务单元（install.sh 生成）
```
