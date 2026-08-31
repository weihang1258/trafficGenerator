# 未实现协议清单

**生成时间**：2026-08-18
**来源**：对需求清单（约 145 项）与 `trafficgen/internal/protocol/`（60+ planner）及层链 registry（`internal/core/layers/registry.go`, 33 层）逐项核对后的差异清单。
**上一版（2026-08-03）说明**：该版列的 17 项（GBT32960/JT808/JT809/JTT905/DOIP/TFTP/SMB/NFS/TDS/RIP/DNP3/ENIP/MODBUS/MQTT/SRV6/MCP/A2A）现已全部实现，故整体重写。

## 未实现总数：63 项

按业务领域分组。标注"半实现"的表示存在载体或配置字段，但不能独立/组合生成目标协议流量。

### A. 流媒体 / 视频容器（3 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 1 | ~~HLS~~ | Apple 直播流（.m3u8 分片清单） | HTTP | ✅ 已实现 |
| 2 | HDS | Adobe HTTP 动态流 | HTTP |
| 3 | ~~RTMFP~~ | Flash P2P 实时媒体流（RTMP 的 UDP 变体） | UDP | ✅ 已实现 |

### B. 工控 / SCADA / 车载 / 电力（10 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 5 | FINS | 欧姆龙 PLC 通信协议 | UDP/TCP |
| 6 | OPC UA | 开放平台通信统一架构（工业互操作） | TCP |
| 7 | CoAP | 受约束应用协议（RFC 7252，物联网/嵌入式） | UDP |
| 8 | IEC 61850-GOOSE | 变电站快速事件报文 | 以太网组播 |
| 9 | IEC 61850-SV | 采样值报文 | 以太网组播 |
| 10 | IEC 61850-MMS | 制造报文规范 | TCP |
| 11 | S7 | 西门子 S7comm PLC 协议 | TCP(102) |
| 12 | ~~Moxa-Nport~~ | 串口服务器透传协议 | 串口/TCP | ✅ 已实现 |
| 13 | ~~SOME-IP~~ | 车载 SOA 中间件（AUTOSAR） | UDP/TCP | ✅ 已实现 |
| 14 | IEC104 | IEC 60870-5-104 电力远动规约 | TCP(2404) |

### C. 数据库（7 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 15 | ~~DRDA~~ | DB2 分布式关系数据库架构 | TCP | ✅ 已实现 |
| 16 | ~~Thrift~~ | Apache 跨语言 RPC 框架 | TCP | ✅ 已实现 |
| 17 | ~~TNS~~ | Oracle 网络服务（SQL*Net） | TCP(1521) | ✅ 已实现 |
| 18 | ~~MongoDB~~ | MongoDB wire protocol | TCP(27017) | ✅ 已实现 |
| 19 | ~~Dameng~~ | 达梦数据库 | TCP | ✅ 已实现 |
| 20 | ~~KingBase~~ | 人大金仓数据库 | TCP | ✅ 已实现 |
| 21 | ~~CQL~~ | Cassandra 查询语言协议 | TCP(9042) | ✅ 已实现 |

### D. 消息 / P2P（5 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 22 | ~~AMQP~~ | 高级消息队列协议（RabbitMQ） | TCP(5672) | ✅ 已实现 |
| 23 | ~~OpenWire~~ | ActiveMQ 原生态 wire 协议 | TCP | ✅ 已实现 |
| 24 | ~~AMS~~ | Apache ActiveMQ 管理协议 | TCP | ✅ 已实现 |
| 25 | ~~Swarm~~ | 去中心化 P2P 存储协议 | UDP/TCP | ✅ 已实现 |
| 26 | ~~Gnutella~~ | P2P 文件共享协议 | TCP | ✅ 已实现 |

### E. 路由 / 组播 / 信令 / 其他网络（13 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 27 | BGP | 边界网关协议（RFC 4271） | TCP(179) |
| 28 | OSPF | 开放最短路径优先（RFC 2328） | IP 协议号 89 |
| 29 | ISIS | 中间系统到中间系统路由协议 | L2 直接承载 |
| 30 | IGMP | 因特网组管理协议（组播成员管理） | IP 协议号 2 |
| 31 | PIM | 协议无关组播 | IP 协议号 103 |
| 32 | ~~LDP~~ | 标签分发协议（MPLS 控制面） | UDP/TCP(646) | ✅ 已实现 |
| 33 | ~~PCEP~~ | 路径计算元素通信协议 | TCP(4189) | ✅ 已实现 |
| 34 | cflow | NetFlow 变体流量统计 | UDP |
| 35 | STUN | NAT 会话穿越工具（RFC 5389） | UDP(3478) |
| 36 | TPKT | RFC 1006 传输封装（仅作 H.323 内部封装，无独立层） | TCP |
| 37 | echo | RFC 862（仅配置字段，无协议层） | UDP/TCP(7) |
| 38 | GIOP | CORBA ORB 互操作协议 | TCP |
| 39 | RDMA | 远程直接内存访问（InfiniBand/RoCE） | 特殊 |

### F. 隧道 / 封装 / 安全传输（5 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| ~~40~~ | ~~VXLAN~~ | 虚拟可扩展局域网（RFC 7348） | UDP(4789) |
| ~~41~~ | ~~NVGRE~~ | 网络虚拟化 GRE 封装 | GRE |
| ~~42~~ | ~~GENEVE~~ | 通用网络虚拟化封装 | UDP(6081) |
| 43 | SSTP | 安全套接字隧道协议（HTTPS 隧道 VPN） | TCP(443) |
| 44 | DTLS | 数据报传输层安全（RFC 6347） | UDP |

### G. 安全 / 认证（5 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 45 | KERBEROS | 网络认证协议（RFC 4120） | UDP/TCP(88) |
| 46 | ntlm | Windows NTLM 认证 | SMB/HTTP 等 |
| 47 | spnego | 简单受保护 GSS-API 协商机制 | 应用层协商 |
| 48 | ocsp | 在线证书状态协议（RFC 6960） | HTTP |
| 49 | dcerpc | 微软分布式计算环境 RPC（注意：与 NFS 的 RPC 无关） | TCP/UDP(135) |

### H. 应用 / 物联网 / 医疗 / 电信 / 管理（11 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 50 | Cwmp | TR-069 远端设备管理（CPE WAN 管理协议） | HTTP/SOAP |
| 51 | BACnet | 楼宇自动化控制网络 | UDP/TCP(47808) |
| 52 | DOH | DNS over HTTPS（RFC 8484） | HTTP |
| 53 | ONVIF | 安防摄像头开放接口 | HTTP/SOAP |
| 54 | HL7 | 医疗信息交换标准协议 | TCP/MLLP |
| 55 | NMEA | GPS/海用电子设备协议 | 串口/TCP |
| 56 | h248 | Megaco/H.248 语音网关控制 | UDP/TCP(2944) |
| 57 | mgcp | 媒体网关控制协议（Megaco 别称） | UDP(2427) |
| 58 | megaco | Megaco/H.248（与 56 等价） | UDP/TCP(2944) |
| 59 | mmse | 彩信（MMSE 协议） | WAP/HTTP |
| 60 | EDP | 物联网设备数据协议 | TCP |

### I. 挖矿（5 项）

| # | 协议 | 说明 | 载体 |
|---|------|------|------|
| 61 | ETHMining | 以太坊挖矿协议 | HTTP/JSON-RPC |
| 62 | XMRMining | 门罗币挖矿协议 | TCP |
| 63 | stratum | 矿池通信协议（仅配置字段，无 planner） | TCP |
| 64 | GetWork | 比特币挖矿工作分配协议 | 自定义 |
| 65 | GetBlockTemplate(GBT) | 比特币区块模板获取协议 | 自定义 |

### J. 半实现 / 需组合但当前组合不上（7 项）

| # | 协议 | 现状 | 差距 |
|---|------|------|------|
| 66 | SNTP | 仅 `default_sntp_servers` 配置字段（strategy_convert.go:1849），无独立 planner | SNTP 是 NTP 简化版，可复用 NTP；无独立实现 |
| 67 | RTP / RTCP | 无独立 planner/目录，仅在 RTSP 数据面内产生（rtsp.go:366 注释佐证） | 无独立入口，无法单独生成 RTP/RTCP 流 |
| 68 | POP3S | **已实现**（2026-08-31，cb397df）：pop3 层补 `OptionalOn: tls` + Fields + translate 分支，pop3_over_tls 用例 2/2 | — |
| 69 | MQTTS | **已实现**（2026-08-31，cb397df）：mqtt 层补 `OptionalOn: tls` + translate 分支，mqtt_over_tls 用例（mqtt 169/169） | — |
| 70 | SOCKS5 over TLS | **已实现**（2026-08-31）：socks5 层注册（OptionalOn: tls）+ SOCKS5Generator 层生成器 + translate 分支，socks5_over_tls 用例 2/2 | — |
| 71 | SFTP | 只有 SSH 载体，无 SFTP 子协议 planner | 需 SSH file transfer 子协议 |

## 备注

1. **别名/组合已覆盖项**（不在未实现清单内，避免误判）：
   - HTTPS = http 层 + `OptionalOn: tls`（registry.go:65）
   - SMTPS = smtp 层 + `OptionalOn: tls`（registry.go:247）
   - FTPS = ftp 层 + `OptionalOn: tls`（registry.go:239）
   - SOCKS4 / SOCKS4a 已含于 socks5 planner
   - RESP = redis；EtherNet/IP = enip（内嵌 CIP）；ISAKMP = ike
   - http2 = grpc planner 发出的 h2c 帧
   - SMB1/2/3 统一 smb
2. **TPKT / echo** 属于"有片段引用但无独立协议层"的边界项，列入 E 组，实现时需确认是否要做成独立层。
3. **h248 / mgcp / megaco** 三者语义重叠（同为 Megaco/H.248），实现时合并为一个 planner 覆盖全部三个名字。（已与需求方确认，2026-08-18）
4. 与上一版（2026-08-03）相比，该清单全部为新增项；上一版的 17 项已全部实现。

## 实现决策（经需求方确认，2026-08-18）

1. **范围**：全部 65 项（不含 7 项 J 组半实现）逐项完整新实现（planner + 层链注册 + 测试）。
2. **顺序**：按业务价值分批，每簇一个 MVP，先跑通再扩。
3. **合并同类**：h248 / mgcp / megaco 合并为一个 Megaco/H.248 planner，覆盖三个名字。
4. **组合层**：J 组 X-over-TLS 类（POP3S / MQTTS / SOCKS5-over-TLS）通过给现有层补 `OptionalOn: tls` 实现，成本低。

## 建议批次（供排期参考）

65 项按业务价值 × 实现难度分 6 批，每批一个 MVP，先跑通再扩：

| 批次 | 内容 | 项数 | 备注 |
|---|---|---|---|
| B1 工控/SCADA/电力 | FINS、OPC UA、CoAP、GOOSE、SV、MMS、S7、Moxa-Nport、SOME-IP、IEC104 | 10 | 与既有 dnp3/modbus/enip 同域，复用经验 |
| B2 数据库 | ~~DRDA~~、~~Thrift~~、~~TNS~~、~~MongoDB~~、~~Dameng~~、~~KingBase~~、~~CQL~~ | 7 | ✅ 全部实现 |
| B3 路由/组播/信令 | BGP、OSPF、ISIS、IGMP、PIM、~~LDP~~、~~PCEP~~、cflow、STUN、TPKT、echo、GIOP、RDMA | 13 | LDP/PCEP ✅ 已实现，其余 11 项待实现 |
| B4 流媒体+消息/P2P | ~~HLS~~、HDS、~~RTMFP~~、~~AMQP~~、~~OpenWire~~、~~AMS~~、~~Swarm~~、~~Gnutella~~ | 8 | HLS/RTMFP/AMQP/OpenWire/AMS/Swarm/Gnutella ✅ 已实现，其余（HDS）待实现 |
| B5 隧道/封装/安全 | VXLAN、NVGRE、GENEVE、SSTP、DTLS、KERBEROS、ntlm、spnego、ocsp、dcerpc | 10 | 隧道类与既有 vxlan/geneve 机制可复用 GRE/VXLAN 封装 |
| B6 应用/物联网/管理+挖矿 | Cwmp、BACnet、DOH、ONVIF、HL7、NMEA、h248/mgcp/megaco（1 planner）、mmse、EDP、ETHMining、XMRMining、stratum、GetWork、GBT | 16 | h248 合并后 14 个 planner；挖矿多基于 HTTP/JSON-RPC |

## 协议级文档、用例与对抗审查要求（2026-08-19 新增）

以下规则适用于清单中的全部 65 个完整实现协议，以及后续新增协议：

1. 每个协议必须同时产出 design（代码设计文档）、testcase（用例设计文档）和 `cases/<proto>.json`；三方 ID、场景、包数、偏移和断言必须一致。
2. 每个协议必须执行两条独立的对抗审查：
   - **代码设计逻辑审查**：对 design、testcase、cases JSON 三件套，审查设计文档中描述的 planner、builder、validator、registry、传输层、请求/响应派生、状态、多流、多会话、错误传播、MCP、pcap/NIC 输出和 tshark/FrameAssert 断言是否自洽、与规范一致、可实现；区分文档自洽、文档内部矛盾/与规范不一致和待实现边界。是否存在 Go 代码实现不属于文档阶段审查范围，记录为待实现边界。
   - **用例覆盖审查**：从 RFC/官方规范和 design 每一行反向推导用例，检查字段编码、边界、截断、溢出、载体、方向、状态迁移、异常、IPv4/IPv6、多流、多会话和每个错误分支。
3. 用例必须拆到不可再分的原子颗粒度：一个 case 只证明一个独立行为、规范分支或错误路径；综合冒烟 case 不能替代原子覆盖；每个 case 必须有可观察断言。
4. 每个 confirmed finding 必须先补最小失败用例/断言，再修改实现或三件套；修改后必须 review、测试并重新执行两条对抗审查，直到 confirmed findings 为零。
5. 设计行和待实现边界不得写入当前可执行 JSON ID 集合，也不得计入已覆盖完成度。
6. 子代理最多并发 2 个；每个子代理只处理一个协议、一个审查视角或一个 finding。

## 下一步

- [x] 与需求方沟通：确认本清单范围、优先级、以及"组合层"类（J 组）是否通过给既有层补 `OptionalOn: tls` 实现（2026-08-18 已确认，见上"实现决策"）。