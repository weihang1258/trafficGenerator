# trafficgen

**MCP 网络流量生成与 pcap 分析服务**——通过统一接口驱动 123 种协议的语义级报文生成：可保存为标准 pcap 文件，或经物理网卡真实发帧；产物自动入库并提供逐流、逐包、逐字节的回读分析。既支持 AI 客户端用自然语言驱动，也提供程序接口，可直接接入自动化测试 harness。

## 它能做什么

- **协议报文生成**：语义级仿真（含 TCP 握手/会话/事务序列），输出标准 pcap 文件
- **物理网卡实发**：多网卡聚合端口组、按权重负载均衡、真实线速发帧（需 CAP_NET_RAW）
- **pcap 回放**：任意 pcap 原样重放，支持循环
- **产物分析**：pcap 自动入库——流级统计 → 逐包头字段 → 原始字节/重组字节流逐层下钻；支持明文/十六进制内容搜索、批量字段提取、全流文本导出
- **外部 pcap 导入**：一步导入即可获得同等的分析能力
- **驱动方式**：AI 客户端自然语言驱动（MCP 协议），或任意语言直连 HTTP 接口——适合接入 pytest / robotframework / CI 流水线等测试 harness

## 支持的协议（123，另有 TCP/UDP 作为底层承载）

**车联网/汽车**：doip、gbt、gbt32960、jt808、jt809、jtt905、moxa、nmea、someip
**工控/电力**：ams、bacnet、dnp3、edp、enip、fins、goose、iec104、mms、modbus、opcua、s7、sv
**数据库**：cql、dameng、drda、mongodb、mysql、postgresql、redis、tds、tns
**隧道/封装**：geneve、gre、gtp、l2tp、mpls、nvgre、pppoe、pptp、srv6、vxlan
**路由/组播**：bgp、isis、ldp、ospf、pcep、pim、rip
**网络基础/载体**：arp、cflow、icmp、icmpv6、igmp、sctp、tcp
**安全/加密**：dtls、ike、ike_nat_t、kerberos、ntlm、ocsp、openvpn、shadowsocks、socks5、spnego、ssh、sstp、tls、vmess、wireguard
**媒体/实时通信**：h323、hds、hls、http_flv、megaco、rtmp、rtmfp、rtsp、sip、stun
**挖矿协议**：ethmining、getwork、stratum、swarm、xmrmining
**应用/服务**：a2a、amqp、coap、cwmp、dcerpc、dhcp、dhcpv6、dns、doh、ftp、gnutella、grpc、hl7、http、imap、ldap、mdns、mmse、mqtt、nfs、ngap、ntp、onvif、openwire、pop3、radius、rdp、smb、smtp、snmp、ssdp、syslog、telnet、tftp、thrift、vnc、xmpp、mcp

每个协议的逐字段配置方式，可通过配置查询接口获取已验证的示例与 schema（见下文"使用"）。

## 安装

Linux x86_64。推荐离线包（单二进制 + systemd，安装即启动）：

```bash
tar xzf trafficgen-vX.Y.Z-linux-amd64.tar.gz
cd trafficgen-vX.Y.Z-linux-amd64
sudo ./install.sh
```

内网 HTTP 服务器在线安装（把发布产物 install.sh / tar.gz / SHA256SUMS 放上任意 HTTP 服务）：

```bash
curl -fsSL http://<server>/install.sh | sudo bash
```

从源码构建：

```bash
cd trafficgen && make build
```

## 配置

最小配置（完整模板见 [`trafficgen/configs/`](trafficgen/configs/)）：

```yaml
mcp:
  api_key: "<长随机串>"            # 接口认证
  transports:
    http:
      enabled: true
      listen: "0.0.0.0:8086"       # MCP 服务端点
    stdio: false                   # 本机嵌入场景改 true
database:
  sqlite:
    path: "./data/trafficgen.db"
```

## 使用

### 方式一：AI 客户端（自然语言）

MCP 客户端指向 `http://<host>:8086/mcp`（认证头 `X-MCP-Key`），之后直接用自然语言操作，例如：

> 帮我生成 100 条 DNS 查询流量，保存为 pcap
> 用 jt808 协议向网卡 enp135s0f0 实发 2000 条注册请求
> 把刚才的 pcap 里目的端口 53 的流找出来，导出第一条流的完整字节

配置不用手写——先向服务端要目标协议的已验证示例（含全部字段说明），复制后按需改字段即可。

### 方式二：程序接口（对接测试 harness）

任何 MCP 客户端 SDK 均可直连，三步完成"生成→等待→取产物"：

```python
# pip install mcp
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def generate_dns_pcap():
    async with streamablehttp_client(
        "http://127.0.0.1:8086/mcp",
        headers={"X-MCP-Key": "<api_key>"},
    ) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            # 1. 生成：配置 = 层链（外层在前）+ 流控制
            r = await s.call_tool("flowb_generate_traffic", {
                "task_name": "harness-dns",
                "protocol": "dns",
                "config": {"layers": [
                    {"ip": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
                    {"udp": {"dst_port": 53}},
                    {"dns": {"name": "test.example", "query_type": 1}}],
                    "flow_control": {"type": "flows", "value": 100}},
                "output_type": "pcap",
                "output_config": {"pcap_path": "harness-dns.pcap"}})
            task_id = r.content[0].text  # 含 task_id
            # 2. 等待终态：flowb_wait_for_task
            # 3. 取产物：flowb_manage_pcaps（下载 pcap / 直接逐流分析）
```

能力面即 API 面：配置查询、生成、策略/任务管理、pcap 分析/回放、网卡端口组各有对应工具，接入 harness 时用 MCP 的 `tools/list` 获取全部接口签名与参数 schema——schema 即文档，无需另行查表。

## 文档

- 核心记忆与协议花名册：[`docs/CORE_MEMORY.md`](docs/CORE_MEMORY.md)、[`docs/LAYERCHAIN_INDEX.md`](docs/LAYERCHAIN_INDEX.md)
- 逐协议设计与用例：[`docs/protocols/`](docs/protocols/)
- 系统与模块设计：[`docs/design/`](docs/design/)、[`docs/api/openapi.yaml`](docs/api/openapi.yaml)

## 使用声明

仅用于授权网络环境下的测试（实验室 / 自有网络 / 客户委托测试）；对未授权网络使用本工具产生的一切责任由使用者承担。

## License

[AGPL-3.0](LICENSE)——以本协议开源；闭源集成、OEM 嵌入等场景可联系维护者获取商业授权（双重许可）。第三方依赖均为宽松许可（Apache-2.0 / MIT / BSD）。
