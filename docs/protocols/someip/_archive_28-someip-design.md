# SOME-IP（Scalable service-Oriented MiddlewarE over IP）协议设计文档

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：AUTOSAR SOME/IP（汽车开放系统架构上的"基于 IP 的可扩展面向服务中间件"）与 SOME/IP-SD（Service Discovery，服务发现）的流量生成设计；支持 UDP/TCP 载体、16 字节大端头部、SD 服务发现、TP（Transport Protocol，传输分段）重组，方法调用/事件通知/错误返回码全 Message Type 覆盖
> 实现位置：`trafficgen/internal/protocol/someip/`
> 配套文件：`docs/protocol-designs/28-someip-testcase.md`（测试用例定义，与此文档 §7 映射索引一致）、`trafficgen/test/protocol_pcap/cases/someip.json`（用例数据）
> 层接线：category=Terminal（终结层）、DependsOn=["udp"]（硬依赖）、TransportOn=["udp","tcp"]（可用传输层）、`spec.SOMEIP` 扁平键直传（零配置负载）

---

## 目录（11 章）

1. [协议概述](#1-协议概述)：SOME/IP 在车载 SOA（面向服务的架构）中的定位、UDP/TCP 30490 端口、与 SD/TP 的关系、本实现范围
2. [数据类型与编码](#2-数据类型与编码)：大端字节序约定；16 字节消息头逐字段表（Message ID/Length/Request ID/Protocol Version/Interface Version/Message Type/Return Code）；SD/TP 子头
3. [消息结构](#3-消息结构)：头 16 字节逐字节布局、各 Message Type 取值表、Return Code 取值表、SD Entry/Option 结构、TP 分段头
4. [状态机](#4-状态机)：方法调用 REQUEST→RESPONSE 双向交换、SD FindService→OfferService、SubscribeEventgroup→Ack、多会话 Session ID 分配、TP 分段发送状态
5. [配置类型定义](#5-配置类型定义)：`spec.SOMEIP` 扁平键清单、层注册（category/DependsOn/TransportOn）、每个字段的类型/默认值/语义
6. [包序列场景（HexDump）](#6-包序列场景hexdump)：S1..Sn 场景逐包十六进制与期望断言（方法调用/无返回/事件/SD/TP/IPv6/多会话）
7. [与 testcase 映射索引](#7-与-testcase-映射索引)：设计场景 S1..Sn ↔ 测试用例 T-SOMEIP-* ↔ JSON 用例 id 的索引表
8. [实现集成点](#8-实现集成点)：`internal/protocol/someip/` 包文件划分、planner/validate/builder 职责、tshark 字段名、与公共 udp 层接线
9. [错误处理](#9-错误处理)：校验规则表（validate 负向）+ 运行期错误 + testcase 负路径 expect_error 对应
10. [扩展字段映射](#10-扩展字段映射)：`spec.SOMEIP` 每个 JSON 键 → 头/子结构的字节偏移映射表，JSON 数值/枚举 → wire 值
11. [修订记录](#11-修订记录)

---

## 1. 协议概述

### 1.1 背景与定位

SOME/IP（Scalable service-Oriented MiddlewarE over IP，基于 IP 的可扩展面向服务中间件）是 AUTOSAR（Automotive Open System Architecture，汽车开放系统架构）为车载 ECU（Electronic Control Unit，电子控制单元）SOA（Service-Oriented Architecture，面向服务的架构）通信定义的中间件协议。它取代传统"信号式"CAN 通信，以"服务"（service）为粒度：提供方（server）发布服务，消费方（client）在运行期发现并调用。

- **官方端口**：UDP/TCP **30490**（AUTOSAR SOME/IP 默认端口）。
- **载体**：UDP（事件通知、SD 服务发现）与 TCP（大载荷方法调用、可靠传输）双载体；一传底层出厂默认 30490，可被上层覆盖。
- **组成**：SOME/IP 本体（消息头 + 载荷）+ SOME/IP-SD（服务发现）+ SOME/IP-TP（Transport Protocol，传输分段，针对 UDP 上超过单包 MTU 的载荷）。

### 1.2 与其他协议的对比

| 维度 | SOME/IP | 同栈参考 |
|------|---------|---------|
| 寻址 | Service ID + Instance ID + Method/Event ID | RADIUS 的 Code+ID；ENIP 的 Command+Session |
| 请求/响应 | Client→Server REQUEST，Server→Client RESPONSE（Session ID 匹配） | RADIUS 双向交换（本仓库 radius 层同模式） |
| 发现 | SOME/IP-SD FindService/OfferService/SubscribeEventgroup | mDNS 的 PTR/unicast 响应 |
| 分段 | SOME/IP-TP（Offered Length 32bit + Segment ID 8bit + more 标志） | TFTP 分块、TDS 分包 |

### 1.3 实现范围（本仓库）

| 覆盖 | 说明 |
|------|------|
| 消息头 | 16 字节大端头，全字段可配 |
| Message Type | REQUEST(0x00)/REQUEST_NO_RETURN(0x01)/NOTIFICATION(0x02)/RESPONSE(0x80)/ERROR(0x81)/TP 变体(0x20/0x21/0x22/0xA0) |
| Return Code | E_OK(0x00)/E_NOT_OK(0x01)/E_UNKNOWN_SERVICE(0x02) 等，错误路径可配任意返回码 |
| SD | FindService(0x00)/OfferService(0x01)/SubscribeEventgroup(0x06)/SubscribeEventgroupAck，entry 含 service/instance/版本/TTL，Option 含 IPv4/IPv6 Endpoint 与多播 |
| TP | Offered Length(32bit) + Segment ID(8bit) + more_segments 标志，UDP 多段发送 |
| 载体 | UDP 默认，TCP 可选（TransportOn 声明）；自动响应（autoResponse）双向交换 |
| 校验 | Validate 负向：ServiceID=0、非法 SessionID、TP 越界、非法 Message Type 等 |

### 1.4 非目标

- 不实现复杂序列化协议（CommonAPI SOME/IP serialization、WTLV/Type 1/2/3 载荷类型），载荷按不透明字节直传
- 不实现动态发现的"多播监听/应答调度"，SD 报文按配置显式发送
- 不实现负载均衡/重传/心跳周期等运行期策略

---

## 2. 数据类型与编码

### 2.1 字节序

SOME/IP 头部与载荷数值字段**全部大端**（network byte order）。16 位字段按高字节在前，24 位（SD TTL）与 32 位字段同理。与 dnp3/modbus 的 LE 形成对比（同仓库 dnp3 为小端）。载荷（payload）作为不透明字节串直传，不参与字节序转换。

### 2.2 消息头（16 字节，所有 SOME/IP 消息）

| 字节偏移 | 长度 | 字段 | 取值/语义 |
|----------|------|------|-----------|
| 0-1 | 2 | Service ID（服务标识） | 识别服务，16 bit，大端；0 非法（Validate 负向） |
| 2-3 | 2 | Method ID（方法标识） | 识别方法或事件，16 bit，大端；bit15=1 为事件（**event**），bit15=0 为方法（**method**）（其定义依据：ID 头 Method ID 最高位标志事件），SD 固定 0x8100 |
| 0-3 | 4 | Message ID（消息标识） | = Service ID(16bit) + Method ID(16bit)，tshark someip.messageid 大端 32bit |
| 4-7 | 4 | Length（长度） | **自 Request ID 起（即不含前 4 字节 Message ID）到消息末尾**的字节数 = 8(Request/Proto/If/Type/RC) + Payload；tshark someip.length |
| 8-9 | 2 | Client ID（客户端标识） | 消费方分配的字段，16 bit 大端 |
| 10-11 | 2 | Session ID（会话标识） | 请求/响应配对的会话号，16 bit 大端；多会话递增 |
| 8-11 | 4 | Request ID（请求标识） | = Client ID(16bit) + Session ID(16bit) |
| 12 | 1 | Protocol Version（协议版本） | 当前实现固定 **0x01**（tshark someip.protoversion） |
| 13 | 1 | Interface Version（接口版本） | 服务接口版本，默认 1，可配（tshark someip.interfaceversion） |
| 14 | 1 | Message Type（消息类型） | 见 §2.3 取值表（tshark someip.messagetype） |
| 15 | 1 | Return Code（返回码） | 见 §2.4 取值表（tshark someip.returncode） |

**Length 口径（关键，易错）**：`Length = 12 + PayloadBytes`（8B Request ID..Return Code + 4B 后续载荷前导？否，精确为 `Length = 4(RequestID) + 1(ProtoVer) + 1(IfVer) + 1(Type) + 1(RC) + Payload = 8 + Payload`）。对 SD 报文，Payload 连续包含 SD 头+Entry+Option（Length 仍从 Request ID 起）。

### 2.3 Message Type 取值表

| 值 | 常量 | 含义 | 方向 |
|----|------|------|------|
| 0x00 | REQUEST（请求） | 需要响应的方法请求 | Client→Server |
| 0x01 | REQUEST_NO_RETURN（无返回请求） | 无需响应的方法请求 | Client→Server |
| 0x02 | NOTIFICATION（事件通知） | 事件/通知，无需响应 | Server→Client |
| 0x80 | RESPONSE（响应） | 对 REQUEST 的正常响应 | Server→Client |
| 0x81 | ERROR（错误） | 对 REQUEST 的错误响应，Return Code 非 0 | Server→Client |
| 0x20 | TP_REQUEST（分段请求） | 带 SOME/IP-TP 头的 REQUEST | Client→Server |
| 0x21 | TP_REQUEST_NO_RETURN（分段无返回请求） | 带 TP 头的 REQUEST_NO_RETURN | Client→Server |
| 0x22 | TP_NOTIFICATION（分段事件） | 带 TP 头的事件通知 | Server→Client |
| 0xA0 | TP_RESPONSE（分段响应） | 带 TP 头的 RESPONSE | Server→Client |
| 0xA1 | TP_ERROR（分段错误） | 带 TP 头的 ERROR | Server→Client |

> **TP 变体编码（tshark 实测确认）**：Message Type 高 bit 位为标志——bit6=0x40 是 Ack 标志，bit5=0x20 是 TP 标志（`someip.messagetype.tp`）。0x20/0x21/0x22 即 *TP_REQUEST / TP_REQUEST_NO_RETURN / TP_NOTIFICATION*，TYPE 字段低 5 位复用 0x00/0x01/0x02 的语义；0xA0/0xA1 同理 = RESPONSE/ERROR 与 TP 标志叠加。

### 2.4 Return Code 取值表

| 值 | 常量 | 含义 |
|----|------|------|
| 0x00 | E_OK（成功） | 正常响应 |
| 0x01 | E_NOT_OK（失败） | 通用错误 |
| 0x02 | E_UNKNOWN_SERVICE（未知服务） | 服务不存在 |
| 0x03 | E_UNKNOWN_METHOD（未知方法） | 方法不存在 |
| 0x04 | E_NOT_READY（未就绪） | 服务未就绪 |
| 0x05 | E_NOT_REACHABLE（不可达） | 服务不可达 |
| 0x06 | E_TIMEOUT（超时） | 请求超时 |
| 0x07 | E_WRONG_PROTOCOL_VERSION（协议版本错误） | 协议版本不匹配 |
| 0x08 | E_WRONG_INTERFACE_VERSION（接口版本错误） | 接口版本不匹配 |
| 0x09 | E_MALFORMED_MESSAGE（报文畸变） | 消息格式错误 |
| 0x0A | E_WRONG_MESSAGE_TYPE（消息类型错误） | 类型不匹配 |
| 0x20-0xFF | E_APPLICATION_RETURN_CODE...（应用返回码） | 应用自定义返回码，错误响应中非 0 即幂等 |

### 2.5 SOME/IP-SD 子结构（UDP 30490 上的服务发现）

SOME/IP-SD 本身是一条 Message ID = `Service ID(0xFFFF) + Method ID(0x8100)` 的 SOME/IP 消息，Message Type = NOTIFICATION(0x02)，Return Code = E_OK(0x00)；其后接 SD Payload：

**SD 头（8 字节）**

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | Flags（标志） | bit7 Reboot、bit6 Unicast、bit5 Explicit Initial Events（tshark someipsd.flags.reboot/.unicast/.exp_init_events），默认 0x00 |
| 1-3 | 3 | Reserved（保留） | 0x000000 |
| 4-7 | 4 | Length of Entries Array（Entry 数组长度） | 字节数 |

**Entry（每条 16 字节，对齐 16 的倍数——tshark 校验"Entry Array length not multiple of 16"）**

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | Type（类型） | 0x00 FindService / 0x01 OfferService / 0x06 SubscribeEventgroup / 0x07 SubscribeEventgroupAck（0x07 值见 §6 S6 核对；任务口径"SubscribeEventgroup/Ack"） |
| 1 | 1 | Index 1（索引1）+ | 上半字节 Index 1，下半字节 Num of Opts 1 |
| 2 | 1 | Index 2 + Num of Opts 2 | 上半字节 Index 2，下半字节 Num of Opts 2 |
| 3-4 | 2 | Service ID（服务标识） | 大端 |
| 5-6 | 2 | Instance ID（实例标识） | 大端 |
| 7 | 1 | Major Version（主版本） | 十进制 |
| 8-10 | 3 | TTL（生存时间） | 24 bit 大端，秒（tshark someipsd.entry.ttl 十进制；FindService 通常 3 或 0xFFFFFF） |
| 11-14 | 4 | Minor Version（次版本） | 大端 |
| 15 | 1 | Reserved（保留）/（Subscription 用 Eventgroup ID 低位） | Offer/Find=0 |
| （Sub 变体） | | SubscribeEventgroup：偏移 15 为 Eventgroup ID（2 字节 + Reserved 1B + Counter 1B） | Eventgroup ID 16bit；Counter 4bit + Reserved 12bit（tshark someipsd.entry.eventgroupid / .counter） |

**Option（每条 4 字节头 + 数据）**

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | Type（类型） | 0x01 IPv4 Endpoint / 0x06 IPv6 Endpoint / 0x02 多播（IPv4 Multicast）/ 0x04 SD Endpoint / 0x0C Configuration（tshark someipsd.option.type 十进制） |
| 1-2 | 2 | Length（长度） | = 1+1+数据长度（不带头 3 字节）；IPv4 Endpoint len=9，IPv6 Endpoint len=21 |
| 3 | 1 | Reserved | 0x00 |
| 4-7 | 4 | IPv4 Address（IPv4 地址） | 大端，如 20.0.0.200 |
| 8 | 1 | Reserved（保留） | 0x00 |
| 9 | 1 | L4 Protocol（四层协议） | UDP=0x11，TCP=0x06 |
| 10-11 | 2 | Port（端口） | 大端，如 30490=0x771A |
| 4-19 | 16 | IPv6 Address（IPv6 地址） | type=0x06 时使用 |
| 20 | 1 | Reserved（保留） | 0x00 |
| 21 | 1 | L4 Protocol（四层协议） | UDP=0x11，TCP=0x06 |
| 22-23 | 2 | Port（端口） | 大端 |

IPv4 Endpoint 的完整字节数为 12（Type 1B + Length 2B + Reserved 1B + 8B 数据），Length=0x0009；IPv6 Endpoint 完整字节数为 24，Length=0x0015。Length 字段按大端编码，且计数包含 Option Reserved/地址/协议/端口，不包含 Type 与 Length 自身。

> 任务提示口径"Option（IPv4 Endpoint/多播）"：本实现以 IPv4 Endpoint（type 0x01）为默认 Option，另支持 IPv6 Endpoint（0x06）与 IPv4 Multicast（0x02）。Option 的具体字节布局以 §6 HexDump 逐字节为准，绝不凭空编排。

### 2.6 SOME/IP-TP 分段头（UDP 大载荷）

当载荷超过单包 UDP 承载（如 >1400B）时，SOME/IP-TP 把一条消息切成 N 段：**首段**是 16B 消息头 + 8B TP 头 + 第一段载荷；**后续段**只有 8B TP 头 + 段载荷（消息头不重复）。

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0-3 | 4 | Offered Length（提供长度） | 原始消息总长（含 16B 头 + 全部载荷），32 bit 大端（tshark someip.tp.offset 低 24bit 意涵参考） |
| 4 | 1 | Segment ID（段序号） | 从 0 开始，逐段 +1（tshark 组合偏移） |
| 5 | 1 | more_segments（更多段标志）+ Reserved | 高位 4bit Reserved（值 0xe），低位 1bit more_segments=0x1（tshark someip.tp.flags.more_segments）；位置 2bit + more 6bit 是任务提示的另一口径，本实现用"TS 头第 5 字节低 1 位 = more，第 5 字节高 7 位 + 第 5 字节后保留"标准 AUTOSAR 布局 |
| 6-7 | 2 | （保留/可选） | 部分实现保留 |

> **TP Message Type**：首段消息头 Message Type 取 TP 变体（REQUEST→0x20、NOTIFICATION→0x22、RESPONSE→0xA0），后续段不重复消息头。tshark 依据 `someip.messagetype.tp` + 相同 Message ID/Request ID 把多段重组为一条完整消息（`someip.tp.reassembled.data`）。

## 3. 消息结构

### 3.1 消息头 16 字节布局（大端，逐字节）

SOME/IP 消息一律以 16 字节头开头（TP 后续段只有 8 字节 TP 头，不重复消息头）。下表第 2 列为相对消息起点的字节序号，同 §2.2。

| 字节 | 字段 | 字节序 | 示例值 | tshark 字段 |
|------|------|--------|--------|-------------|
| 0-1 | Service ID | BE | 0x1234 | someip.serviceid |
| 2-3 | Method ID | BE | 0x0001（方法）/0x8001（事件） | someip.methodid |
| 0-3 | Message ID | BE 32bit | 1234 0001 | someip.messageid |
| 4-7 | Length | BE 32bit | 0000 0010（=8+8B payload） | someip.length |
| 8-9 | Client ID | BE | 0x0001 | someip.clientid |
| 10-11 | Session ID | BE | 0x0001 | someip.sessionid |
| 8-11 | Request ID | BE 32bit | 0001 0001 | — |
| 12 | Protocol Version | 1 | 0x01 | someip.protoversion |
| 13 | Interface Version | 1 | 0x01 | someip.interfaceversion |
| 14 | Message Type | 1 | 0x00/0x01/0x02/0x80/0x81/TP | someip.messagetype |
| 15 | Return Code | 1 | 0x00（E_OK） | someip.returncode |

### 3.2 头部各字段详细语义

#### 3.2.1 Message ID（0-3）

`Message ID` 由 `Service ID`（高 16bit）与 `Method ID`（低 16bit）拼成大端 32bit。Method ID 的 bit15=1 表示**事件**（event，通常由 Server 以 NOTIFICATION 主动推送），bit15=0 表示**方法**（method，Client 调用的 RPC）。因此同一 Service ID 下方法与事件的 Method ID 空间分置。

#### 3.2.2 Length（4-7）

`Length` 统计 **Request ID 至消息末尾**的字节数：

```
Length = 4(Request ID) + 1(Proto) + 1(If) + 1(Type) + 1(RC) + len(Payload) = 8 + len(Payload)
```

- 空载荷消息 Length=8（SD 头不算，因为 SD 头本身属于 Payload 区）。
- tshark 用 someip.length 校验报文完整性；Length 与实发字节不符会触发 `someip.incomplete_headers`/专家提示。

#### 3.2.3 Request ID（8-11）

`Request ID = Client ID(16bit) + Session ID(16bit)`。Session ID 由 Client 分配，请求/响应必须一致（S2/S3 场景断言 `same_as_packet`）；多会话（S9）用同一 Client ID 下发递增 Session ID。

#### 3.2.4 Protocol / Interface Version（12-13）

Protocol Version 固定 0x01（AUTOSAR 现行 SOME/IP 协议版本）。Interface Version 为服务接口版本，默认 1 可配；tshark 若与已知不符不报错（由应用层校验）。

#### 3.2.5 Message Type / Return Code（14-15）

取值见 §2.3/§2.4。ERROR 响应（0x81）要求 Return Code≠0；RESPONSE（0x80）通常 Return Code=E_OK(0x00)。

### 3.3 载荷区（Payload）

- 方法调用：载荷为序列化参数（本实现按不透明字节直传，`payload` 数组）。
- SD：载荷 = SD 头（8B）+ Entry 数组（16B 每条）+ Option 数组。
- 事件/通知：载荷即事件数据。
- Length 含全部载荷字节（SD 的 Length = 8 + 8(SD头) + Entries + Options）。

### 3.4 SOME/IP-SD 报文结构

SD 报文的完整字节序（大端）：

```
[16B SOME/IP 头]  Service ID=0xFFFF, Method ID=0x8100, Message Type=0x02(NOTIFICATION),
                  Return Code=0x00, Length=8+8+entries+options
[8B SD 头]        Flags(1B) + Reserved(3B) + Length of Entries(4B)
[16B/条 Entry]    Type + Index1/Opts1 + Index2/Opts2 + ServiceID(2B) + InstanceID(2B)
                  + MajorVersion + TTL(3B) + MinorVersion(4B) + [Reserved / Eventgroup 变体]
[Option 段]       Type(1B) + Length(2B) + Reserved(1B) + data(IPv4 4B+端口2B+proto1B / IPv6 16B+端口)
```

#### 3.4.1 Entry Type 取值

| 值 | Entry | 方向 | 说明 |
|----|-------|------|------|
| 0x00 | FindService（发现服务） | Client→SD | 查询某 Service+Instance；TTL 通常小（3/0xFFFFFF） |
| 0x01 | OfferService（提供服务） | Server→SD | 宣告服务可用；含 Major/Minor 版本 + TTL（上线期数） |
| 0x06 | SubscribeEventgroup（订阅事件组） | Client→SD | 订阅某 Eventgroup；Entry 第 15-16B 为 Eventgroup ID |
| 0x07 | SubscribeEventgroupAck（订阅应答） | Server→SD | 应答订阅；Counter 递增，可带 Initial Event 标志 |

> Entry Index1/Index2 指向引用自身 Option 的偏移；Num of Opts1/2 为该 entry 引用的 Option 数量（上半字节*16+下半字节，见 tshark `someipsd.entry.numopt1/numopt2`）。

#### 3.4.2 Option 取值

| Type | Option | 数据布局 |
|------|--------|---------|
| 0x01 | IPv4 Endpoint（IPv4 端点） | 4B 地址 + 2B 端口（部分实现 +1B L4 proto） |
| 0x02 | IPv4 Multicast（IPv4 多播） | 同 IPv4 端点布局，广播端点语义 |
| 0x06 | IPv6 Endpoint（IPv6 端点） | 16B 地址 + 2B 端口 |
| 0x04 | SD Endpoint（SD 端点） | SD 专用端点地址 |

Option 长度字段 = 数据长度 + 1（即不含 前三字节 Type/Length/Reserved）；IPv4=9、IPv6=21。

### 3.5 SOME/IP-TP 分段结构

UDP 大载荷（如 2500B 事件数据）按 MTU 分段。每段：

```
首段: [16B 消息头 MessageType=TP变体] [8B TP头] [最多 MTU-24 字节载荷]
中/末段: [8B TP头] [最多 MTU-8 字节载荷]   ← 不重复消息头
```

**TP 头（8 字节）**：Offered Length（4B，原始消息完整字节数 = 16+len(总载荷)）+ Segment ID（1B，从 0 递增）+ Reserved/more_segments（1B，低 1 位 = 1 表示"还有后续段"0）保留字节。tshark 依据 `someip.tp.offset`、`someip.tp.flags.more_segments` 重组为完整消息（`someip.tp.reassembled.data`）；末段 more=0。

> **TP 校验**：每段 Segment ID 连续（0,1,2…）、总载荷 = Offered Length-16、末段 more=0。越界/不连续由 §9 校验拒绝（somerip 规则见 JSON 负路径）。

## 4. 状态机

### 4.1 消息方向与角色

| 角色 | 方向 | 典型报文 |
|------|------|---------|
| Client（客户端，消费方） | → Server | REQUEST / REQUEST_NO_RETURN / SD FindService / SD SubscribeEventgroup |
| Server（服务端，提供方） | → Client | RESPONSE / ERROR / NOTIFICATION / SD OfferService / SD Ack |
| SD（服务发现中间人） | 双向 | FindService(0x00)/OfferService(0x01)/SubscribeEventgroup(0x06)/Ack(0x07) |

自动响应（autoResponse）：被配置为"需要响应"的方法调用会自动补发对应 RESPONSE/ERROR，同 radius 双向交换模式。**REQUEST(0x00)→RESPONSE(0x80)** 与 **REQUEST_NO_RETURN(0x01)→（无响应）** 两条路径区别在是否回包。

### 4.2 方法调用状态机（flow 级）

```
[Start]
   ↓ 建立载体（如 UDP 单包 / TCP 连接）
[Send REQUEST]  MessageType=0x00, SessionID = 当前会话号, Payload=方法参数
   ↓ autoResponse=true（默认）
[Recv RESPONSE] MessageType=0x80, ReturnCode=E_OK, SessionID 与请求相同 ← 断言核心
   ├─ 若 ReturnCode≠0 → 该调用视为业务错误（可通过 ERROR 显式模拟）
   └─ 若 autoResponse=false → 不发响应，直接结束
[End]
```

- **Session ID 匹配**：响应包必须回用请求包 Session ID（S2 断言 `same_as_packet`）。
- **REQUEST_NO_RETURN**：MessageType=0x01，autoResponse 强制关闭，单包即结束（S3）。
- **ERROR**：MessageType=0x81 + 非 0 ReturnCode（如 E_NOT_OK=0x01），显式配置成一条独立 down 报文（S4）。

### 4.3 SD 状态机

```
[Start]
   ↓ Client 发 FindService（entry 0x00, TTL 0xFFFFFF）
[OfferService] Server 回复 entry 0x01, 版本 Major/Minor, TTL 上线周期（如 3s）
   ↓ Client 需要事件：发 SubscribeEventgroup（entry 0x06, EventgroupID）
[SubscribeEventgroupAck] Server 回复 entry 0x07, Counter=0, 可带 Initial Event
[则往返完成后可发 NOTIFICATION 事件]（S6 覆盖）
[End]
```

- **身份匹配**：SD 报文的 Service ID 恒 0xFFFF、Method ID 恒 0x8100、Message Type 恒 0x02、Return Code 恒 0x00——tshark 据此自动按 someipsd 解析。
- **ID/版本/TTL 断言**：FindService/OfferService 的 ServiceID/InstanceID/MajorVersion/MinorVersion/TTL 必须与配置一致（S5/S6 字段断言）。

### 4.4 TP 分段状态机

```
[Start]
   ↓ 载荷 > MTU 阈值（配置 segmentation_size，如 1400）
[段 0] 消息头(TP变体) + TP头{OfferedLength, SegmentID=0, more=1} + 载荷[0:1400]
   ↓
[段 1] TP头{SegmentID=1, more=1} + 载荷[1400:2800]
   ↓
[段 N] TP头{SegmentID=N, more=0} + 载荷[末尾]   ← 末段 more=0
[End]（tshark 按 MessageID+SessionID 重组为完整消息）
```

- 分段顺序必须单调且无跳号；`Offered Length` 全段一致 = 16 + 总载荷字节。
- 每段独立 UDP 包发送（TCP 载体天然不分段，直接整载荷发出，MessageType 不取 TP 变体）。

### 4.5 多会话状态机（S9）

同一 Client 对多个端点/多次调用使用不同 Session ID：每条消息会话号 = 起始会话号 + 调用序号（递增而非回绕），响应回用各自 Session ID。配置 `session_start` 与 `session_inc` 控制；校验拒绝非递增/非法（ServiceID=0、SessionID=0 等，见 §9）。

## 5. 配置类型定义

### 5.1 层注册（layer registry）

SOME-IP 作为**终结层（Terminal）**注册到层注册表（§18-layer-config-design.md）：

| 项 | 值 | 说明 |
|----|----|------|
| name | `someip` | 层名 |
| category | 终结层（Terminal） | 层链末层，包在 udp/tcp 内 |
| depends_on | `["udp"]` | 硬依赖：空配置自动补 `[ip, udp, someip]` |
| transport_on | `["udp","tcp"]` | 可用传输层：默认 udp，显式写 tcp 层时走 TCP（`[{"tcp":{}},{"someip":{}}]`） |
| default_port | 30490 | 上层传输层端口默认 30490 |
| fields | 见 §5.2 | 全部字段走 `spec.SOMEIP` 扁平键直传 |

### 5.2 `spec.SOMEIP` 扁平键清单（Typedef）

> 采用"扁平键直传"：配置写在 `"someip": { ... }` 顶层，每个键直接映射到头/子结构字段，无中间包装结构。下列为完整键表（类型 / 默认值 / 语义）。

| 配置键 | 类型 | 默认 | 语义 / 目标字段 |
|--------|------|------|-----------------|
| `service_id` | int | 0x1234 | 消息头 Service ID（Validate 负向：0 非法） |
| `method_id` | int | 0x0001 | 消息头 Method ID（bit15=1 为事件） |
| `client_id` | int | 0x0001 | 消息头 Client ID |
| `session_start` | int | 1 | 首条消息 Session ID 起点 |
| `session_inc` | int | 1 | 后续会话号递增步长（多会话） |
| `protocol_version` | int | 1 | 消息头 Protocol Version（Validate 拒绝 ≠1） |
| `interface_version` | int | 1 | 消息头 Interface Version |
| `message_type` | int/string | 0 | REQUEST=0x00 / REQUEST_NO_RETURN=0x01 / NOTIFICATION=0x02 / RESPONSE=0x80 / ERROR=0x81 / TP 变体 0x20..0xA1；可用字符串 "request"/"response"/"event"/"error" 等 |
| `return_code` | int | 0x00 | Return Code（E_OK=0/E_NOT_OK=1/...） |
| `payload` | []int | [] | 载荷不透明字节数组（0-255），Length=8+len(payload) |
| `auto_response` | bool | true | REQUEST 后自动补 RESPONSE（同 radius 模式）；REQUEST_NO_RETURN 强制 false |
| `direction` | string | "up" | "up"=源→目的（Client→Server）/ "down"=反向（Server→Client）；autoResponse 响应用 down |
| `sd` | obj | 无 | SD 报文子配置（见 §5.3） |
| `tp` | obj | 无 | TP 分段子配置（见 §5.4） |
| `events` | []obj | 无 | 多方法+多事件列表（见 §5.5），批量生成方法/事件消息 |

### 5.3 SD 子配置（`someip.sd`）

| 配置键 | 类型 | 默认 | 语义 |
|--------|------|------|------|
| `type` | string | "find" | entry 类型："find"(0x00)/"offer"(0x01)/"subscribe"(0x06)/"subscribe_ack"(0x07) |
| `service_id` | int | 0x1234 | entry Service ID（SD 报头 0xFFFF 固定） |
| `instance_id` | int | 0x0001 | entry Instance ID |
| `major_version` | int | 1 | entry Major Version |
| `minor_version` | int | 0 | entry Minor Version |
| `ttl` | int | 0xFFFFFF | entry TTL（秒，24bit）；FindService 常用 0xFFFFFF，Offer 常用短 TTL |
| `eventgroup_id` | int | 0x0001 | Subscribe 用 Eventgroup ID（16bit） |
| `counter` | int | 0 | Ack 用 Counter（4bit 循环） |
| `initial_event` | bool | false | Ack 的 Initial Event Flag（bit7=0x80） |
| `reboot_flag`/`unicast_flag`/`exp_init_events` | bool | false | SD 头 Flags 三标志位 |
| `options` | []obj | 见下 | 引用选项列表：`{"type":1,"ip":"20.0.0.200","port":30490,"proto":"udp"}`（IPv4 Endpoint 0x01，proto=17/6；multicast type 0x02；IPv6 type 0x06，ip 为 v6 串） |
| `options_2` | []obj | [] | 第二 entry 引用（Index2/NumOpts2）对应选项 |

### 5.4 TP 子配置（`someip.tp`）

| 配置键 | 类型 | 默认 | 语义 |
|--------|------|------|------|
| `enabled` | bool | false | 启用 TP 分段 |
| `segment_size` | int | 1400 | 每段载荷字节数（首段除外，含 24B 开销） |
| `payload_length` | int | 0 | Offered Length 校验用原始总载荷长（缺省 = len(payload)） |
| `message_type` | string | 自动 | 首段 TP 变体（TP_REQUEST=0x20/TP_NOTIFICATION=0x22/TP_RESPONSE=0xA0…） |

### 5.5 多方法多事件（`someip.events`）

批量生成独立消息列表（每个元素同 §5.2 的 消息级字段：service_id/method_id/message_type/payload/direction…），用于"多方法+多事件"场景（S7）：列表按序发送，各自独立 Session ID（递增）。事件元素 method_id 的 bit15=1（通知语义）。

## 6. 包序列场景（HexDump）

> 前缀说明：下述 hex 均为大端 16 进制，帧内偏移从 SOME/IP 头起点 0 起。UDP 载荷偏移 = 14(Eth)+20(IP)+8(UDP)=42（IPv4 无选项），TCP 载荷偏移 = 54。断言以 tshark `someip.*`/`someipsd.*` 字段为主、FrameAssert 原始字节为辅。

### 场景约定

- 默认载体 UDP，src_ip=10.0.0.1、dst_ip=20.0.0.1、src_port=12345、dst_port 30490。
- 默认 service_id=0x1234、method_id=0x0001、client_id=0x0001、session 从 1 起。
- 消息头样例（REQUEST 单包，载荷 4B `de ad be ef`）：
  `12 34 00 01 | 00 00 00 0c | 00 01 00 01 | 01 01 00 00 | de ad be ef`
  逐字节：MessageID(12340001) Length=0x0c=12（=8+4）RequestID(00010001) ProtoVer=01 IfVer=01 Type=00 RC=00 载荷 de ad be ef。

### S1 方法调用 REQUEST→RESPONSE（单包往返，UDP）

```
包1(up)  12 34 00 01 00 00 00 0c 00 01 00 01 01 01 00 00 de ad be ef
包2(down)12 34 00 01 00 00 00 0c 00 01 00 01 01 01 80 00 de ad be ef   ← 同 MessageID/SessionID，Type=0x80
```

- 断言：包1 someip.messagetype=0x00、someip.length=12、udp.dstport=30490；包2 同 serviceid/methodid/sessionid（same_as_packet:1）、messagetype=0x80、returncode=0x00、udp.srcport=30490（down 方向）。autoResponse 默认开启是响应出现的依据。

### S2 Session ID 匹配

多会话方法调用：两条 REQUEST 的 Session ID=1、2，各自 RESPONSE 回用。

- 请求1 SessionID=0001，请求2 SessionID=0002（session_inc=1）。
- 断言每对请求/响应 `same_as_packet` sessionid，证明配对而非串号。

### S3 REQUEST_NO_RETURN（无返回请求）

```
包1(up)  12 34 00 01 00 00 00 0c 00 01 00 01 01 01 01 00 de ad be ef   ← Type=0x01
```

- 单包即结束（packet_count=1）；断言 messagetype=0x01、autoResponse 被强制为 false（无包2）。

### S4 ERROR 返回码

```
包1(up)  12 34 00 01 00 00 00 0c 00 01 00 01 01 01 00 00 de ad be ef   ← REQUEST
包2(down)12 34 00 01 00 00 00 0c 00 01 00 01 01 01 81 01 de ad be ef   ← Type=0x81, RC=0x01(E_NOT_OK)
```

- 断言包2 messagetype=0x81、returncode=0x01、request/response sessionid 一致。

### S5 SD FindService→OfferService

```
包1(up)  SD FindService（无 Option）：
  ff ff 81 00 | 00 00 00 20 | 00 01 00 01 | 01 01 02 00 | 00 00 00 00 | 00 00 00 10 | 00 00 00 12 34 00 01 01 ff ff ff 00 00 00 00 00
    ↑MessageID(ffff8100)，Length=0x20=32 = 8 + SD头8 + Entry16；Entries Length=0x10=16；Entry 恰好16B，MinorVersion=00000000，末字节 Reserved=00。
包2(down) SERVER OfferService（1 个 IPv4 Endpoint Option）：
  ff ff 81 00 | 00 00 00 2c | 00 01 00 02 | 01 01 02 00 | 00 00 00 00 | 00 00 00 10 | 01 01 00 12 34 00 01 01 00 00 03 00 00 00 00 00 | 01 00 09 00 14 00 00 c8 00 11 77 1a
    ↑Length=0x2c=44 = 8 + SD头8 + Entry16 + Option12；Entries Length=0x10=16；Entry 恰好16B；Option=01 00 09 00 14 00 00 c8 00 11 77 1a：Type=01，Length=0009（大端），Reserved=00，20.0.0.200，Reserved=00，UDP=11，30490=771a。
```

S5 的 Length 口径可逐字节复算：包1 Payload=8+16=24，所以 SOME/IP Length=8+24=32(0x20)；包2 Payload=8+16+12=36，所以 Length=8+36=44(0x2c)。Option Length=9 不是 Option 总长，而是从 Option Reserved 到末尾共 9B；Option 总长为 3B(Type+Length)+9B=12B。

- 断言：两包 `someip.serviceid=0xffff`、`someip.methodid=0x8100`、`someip.messagetype=0x02`；包1 entry.type=0x00、entry.serviceid=0x1234、entry.instanceid=0x0001、majorver=1、minorver=0、ttl=16777215；包2 entry.type=0x01、majorver=1、minorver=0、ttl=3、option.type=1、option.ipv4address=20.0.0.200、option.port=30490。
- 任务口径"SD FindService/OfferService（ID/版本/TTL）"：S5 即覆盖。

### S6 SubscribeEventgroup→Acknowledge

```
包1(up)  SubscribeEventgroup(entry 0x06)：
  ff ff 81 00 | length | 00 01 00 03 | 01 01 02 00 | 00 00 00 10 | 06 00 00 00 ... eventgroup=0001 ...
包2(down)SubscribeEventgroupAck(entry 0x07)：
  ff ff 81 00 | length | 00 01 00 04 | 01 01 02 00 | 00 00 00 10 | 07 ... counter=0 ...
（S6 触点：entry.type=0x06/0x07、Subscribe 的 InstanceID=0x0001、eventgroupid=0x0001、Ack counter=0；本原子用例选择规范允许的最小 Ack，不引用 Endpoint Option。Ack 若需携带通知端点，属于另一个 endpoint-option 原子变体；订阅成功后 Server 可推 NOTIFICATION，见 S7 事件。）
```

### S7 多方法多事件（NOTIFICATION 事件）

事件：method_id=0x8001（bit15=1=event），MessageType=0x02(NOTIFICATION)：

```
包N(down)12 34 80 01 00 00 00 0e 00 01 00 05 01 01 02 00 01 02 03 04   ← 事件通知，Length=14(8+6B)
```

- 多方法+多事件用 `events` 列表批量（S7 覆盖）：方法 REQUEST→RESPONSE 若干 + 事件 NOTIFICATION 若干，消息顺序按配置，Session ID 在请求序列递增、事件可共享/独立。

### S8 TP 分段（UDP 大载荷）

载荷为 JSON 中显式提供的 2500 个字节（0..255 循环，可由 `len(payload)==2500` 复核），分 2 段（segment_size=1400 + 余 1100）：

```
包1(up)  消息头(ServiceID=1234/MethodID=0001/Length=8+8+2500=0x9d4/RQID=00010001/Type=0x20(TP_REQUEST)/RC=00)
         + TP头{OfferedLength=2516(0x09d4)=16+2500, SegmentID=00, more_segments=1} + 载荷[0:1400]
包2(up)  TP头{OfferedLength=0x09d4, SegmentID=01, more_segments=0} + 载荷[1400:2500]
```

- 断言：包1 someip.messagetype=0x20、someip.messagetype.tp=1、someip.tp.offset=0x...（OfferedLength 低 24bit）、someip.tp.flags.more_segments=1；包2 same segment 续段、more_segments=0；包2 无 someip.serviceid（后续段无消息头）。tshark 重组断言 `someip.tp.reassembled.length`=2516。

### S9 IPv4+IPv6 双载体 + 多会话

- `someip_ipv6` 覆盖 IPv6 UDP 载体上的普通方法 REQUEST→RESPONSE（IPv6 地址层，`ip.proto=17`，消息头不随地址族变化）。
- 多会话：同一 client_id 下发多条请求 Session ID 1..N；SD 场景可在不同 session 上分别 FindService/Subscribe。

### S9b IPv6 SD Endpoint Option（独立原子用例）

- `someip_sd_ipv6` 只覆盖一个行为：IPv6 UDP 载体上的 SD OfferService + IPv6 Endpoint Option（type=0x06，地址 `2001:db8::1`，端口 30490），不与方法响应混合。
- Option wire 为 `06 00 15 00` + 16B IPv6 地址 + `00 11 77 1a`；`someipsd.option.type` 按 tshark 以十进制 `6` 断言，Option 总长=24B，Length=0x0015。

### S10 双向 RESPONSE 交换（TCP 载体）

TCP 载体（`[{"tcp":{}},{"someip":{}}]`，dst_port 30490）：完整 TCP 握手 → SO​ME/IP REQUEST(FIN 前) → 服务端 RESPONSE → 终止。断言 someip.length 与 tcp.seq 推进一致。

## 7. 与 testcase 映射索引

> 设计场景（本文件 §6 的 S1..S10）→ 测试用例（28-someip-testcase.md 的 T-SOMEIP-*）→ JSON 用例（cases/someip.json id）。三条一一对应，JSON 与 testcase 文档严格一致；新增 S9b 也必须同时出现在三处。

| 设计场景 §6 | 测试用例 | JSON id | 覆盖要点 |
|------------|---------|---------|---------|
| S1 方法调用 REQUEST→RESPONSE | T-SOMEIP-REQ-01 | `someip_req_resp` | 请求/响应同 MessageID+SessionID，tshark 字段 |
| S1 变体空载荷 | T-SOMEIP-REQ-02 | `someip_req_empty` | Length=8、返回码 E_OK |
| S2 Session ID 匹配 | T-SOMEIP-SESS-01 | `someip_multi_session` | 多会话递增 + same_as_packet 配对 |
| S3 REQUEST_NO_RETURN | T-SOMEIP-NORET-01 | `someip_no_return` | 单包、无响应、Type=0x01 |
| S4 ERROR 返回码 | T-SOMEIP-ERR-01 | `someip_error` | Type=0x81、RC=0x01、配对 |
| S5 SD FindService/OfferService | T-SOMEIP-SD-01 | `someip_sd_find_offer` | entry type/ID/版本/TTL + option 端点 |
| S6 SubscribeEventgroup/Ack | T-SOMEIP-SD-02 | `someip_sd_subscribe` | 0x06→0x07、eventgroupid、counter |
| S7 多方法多事件 | T-SOMEIP-EVT-01 | `someip_multi_method_event` | 方法批量 + NOTIFICATION 事件 0x8001 |
| S8 TP 分段 | T-SOMEIP-TP-01 | `someip_tp_segments` | 0x20 首段 + more 标志 + 重组 |
| S9 IPv4+IPv6 | T-SOMEIP-IPV6-01 | `someip_ipv6` | IPv6 地址层上的 UDP 方法调用 |
| S9b IPv6 SD Endpoint Option | T-SOMEIP-IPV6-SD-01 | `someip_sd_ipv6` | IPv6 Endpoint Option type=0x06/地址/端口 |
| S10 TCP 载体双向 | T-SOMEIP-TCP-01 | `someip_tcp_swap` | TCP 载体 + REQUEST→RESPONSE |
| 负路径（§9） | T-SOMEIP-NEG-01..04 | `someip_neg_*` 4 例 | expect_error 见 §9 表 |

> 用例总数 16 条（12 正向 + 4 负向）；S9b 为新增独立 IPv6 SD Option 原子用例。testcase 文档 §4/§5 逐条列出行为与断言，索引此处 §7 对齐。

## 8. 实现集成点

### 8.1 包结构（`trafficgen/internal/protocol/someip/`）

| 文件 | 职责 |
|------|------|
| `types.go` | 配置结构定义（SOMEIPConfig 及 sd/tp/events 子配置）；消息头常量（Message Type / Return Code / SD entry type / option type 枚举） |
| `planner.go` | 层生成器入口 `Plan(ctx, layer, innerBytes)`：把 `spec.SOMEIP` 展开为一条或多条 PacketConfig（包构建配置）；SD/TP/事件/会话分配 |
| `validate.go` | Validate 负向规则（§9 表）：service_id=0、非法 session、TP 越界、非法 message_type 等在创建/任务启动时拒绝 |
| `builder.go` | 16B 头 + SD/TP 子结构逐字节拼接（大端）；autoResponse 双向包生成 |
| `someip_test.go` | 单测：头字段 / Length 口径 / SD entry 布局 / TP 分段偏移（遵循 CLAUDE.md Testing Policy） |

### 8.2 层注册与公共层接线

- 注册为终结层：`category=Terminal`、`DependsOn=["udp"]`、`TransportOn=["udp","tcp"]`（§5.1）。
- `[{"udp":{}},{"someip":{}}]` 生成 `[ip,udp,someip]`；显式 `[{"tcp":{}},{"someip":{}}]` 走 TCP。
- UDP 默认端口 30490（可 `dst_port` 覆盖）；TCP 载体复用 tcp 层握手（S10）。
- 结合方案 C（18-layer-config-design.md）：分层补全 + 自动端口。

### 8.3 tshark 解析对照

| 目标字节 | tshark 字段 | 断言方式 |
|----------|------------|---------|
| 消息头 | someip.serviceid / methodid / messageid / length / clientid / sessionid / protoversion / interfaceversion / messagetype / returncode | FieldAssert |
| SD | someipsd.entry.type / serviceid / instanceid / majorver / ttl / minorver / eventgroupid / counter；someipsd.option.type / ipv4address / ipv6address / port | FieldAssert |
| TP | someip.messagetype.tp（布尔）、someip.tp.offset、someip.tp.flags.more_segments、someip.tp.reassembled.length / .data | FieldAssert / FrameAssert |
| 原始字节 | 帧内偏移 FrameAssert（offset 42=UDP、54=TCP） | FrameAssert |

> tshark 3.6.14 实测字段集见本次核实列表（§1.3 结论）：someipsd 由 `someip.methodid=0x8100 + messagetype=0x02` 自动选择解析器，无需 `-d` 解码提示。

### 8.4 与同栈协议的关系

- autoResponse 双向交换：同 radius 模式（radius/planner.go 的 request/response Rounds 交换）。
- 大端头结构 + Validate 负向：同 doip/enip 的 provider 注册风格。
- SD 发现：区别于 mDNS/IPv4 多播，本实现为显式单播 SD 报文。

## 9. 错误处理

### 9.1 校验规则表（Validate 负向）

| # | 规则 | 报错示例 | testcase expect_error |
|---|------|---------|----------------------|
| V1 | Service ID 不能为 0 | `someip: service_id must be nonzero` | `someip_neg_service_id` |
| V2 | 非法 Session ID（0 或非递增） | `someip: invalid session_id` | `someip_neg_session` |
| V3 | 非法 Message Type（非枚举值） | `someip: invalid message_type 0x05` | `someip_neg_type` |
| V4 | Protocol Version 必须为 1 | `someip: protocol_version must be 1, got N` | 并入 V3 场景 |
| V5 | TP 越界（segments 超 255 / 载荷与 Offered Length 不符 / 段序号跳号） | `someip: tp segment N out of range` | `someip_neg_tp` |
| V6 | 非法 Return Code（>0xFF 或 ERROR 但 RC=0） | `someip: return_code out of range` | 并入 V3 |
| V7 | SD entry type 非法 / Option 长度不对 | `someip: bad sd option length` | 并入 V1/V3 |
| V8 | REQUEST_NO_RETURN 不允许 auto_response | `someip: REQUEST_NO_RETURN cannot have auto_response` | 并入负路径 |

> 触发方式与 enip validate 一致：`expect_error: true` 时 MCP generate_traffic/任务创建或启动**必须失败**，失败判 PASS、成功判 FAIL（Testing Policy 第 4 条"负路径必须可观测失败"）。`error_contains` 子串断言报错文本。

### 9.2 运行期错误

| 场景 | 处理 |
|------|------|
| autoResponse 无法配对（Session ID 冲突） | 报 plan 错误，任务失败 |
| TP 段数与 255 上限冲突 | 增大 segment_size 或改 TCP 载体（无分段） |
| payload 字节越界（>255 值） | 校验拒绝 |
| SD option 引用越界（NumOpts > options 数量） | 校验拒绝 |
| UDP 载荷超 MTU 而未启用 TP | 不自动分段；由配置者决定（TCP 载体或 TP 启用） |

### 9.3 负路径 testcase 清单

| JSON id | error_contains | 依据 |
|---------|---------------|------|
| `someip_neg_service_id` | `service_id must be nonzero` | V1 |
| `someip_neg_session` | `invalid session_id` | V2 |
| `someip_neg_type` | `invalid message_type` | V3/V4/V6 |
| `someip_neg_tp` | `tp segment` | V5 |

## 10. 扩展字段映射

> 每个 `spec.SOMEIP` JSON 键 → 目标字节/枚举，供实现与断言对照；"wire 值"为最终写入帧的数值。

| 配置键 | 目标 | 字节/位置 | wire 值换算 |
|--------|------|-----------|-------------|
| `service_id` | 消息头 Service ID | 头 offset 0-1 | 原样大端（16bit） |
| `method_id` | 消息头 Method ID | 头 offset 2-3 | 原样大端；bit15=1 → tshark 视为事件 |
| `client_id` | 消息头 Client ID | 头 offset 8-9 | 原样大端 |
| `session_start` | 消息头 Session ID 起点 | 头 offset 10-11 | 起始值；多会话 +session_inc |
| `protocol_version` | 头 offset 12 | 1 字节 | 必须 1（V4） |
| `interface_version` | 头 offset 13 | 1 字节 | 默认 1 |
| `message_type` | 头 offset 14 | 1 字节 | 枚举映射：request=0x00、request_no_return=0x01、event=0x02、response=0x80、error=0x81、tp_request=0x20… |
| `return_code` | 头 offset 15 | 1 字节 | E_OK=0x00、E_NOT_OK=0x01、E_UNKNOWN_SERVICE=0x02… |
| `payload` | 载荷区（Length 尾端） | 头后 | 字节数组（0-255）；Length=8+len |
| `auto_response` | 生成器行为 | — | false 时不补 RESPONSE |
| `direction` | 方向 | — | up=源→目的、down=目的→源（源端口变 30490） |
| `sd.type` | SD Entry Type | SD payload entry offset 0 | find=0x00/offer=0x01/subscribe=0x06/subscribe_ack=0x07 |
| `sd.service_id` | SD Entry Service ID | entry offset 3-4 | 原样 |
| `sd.instance_id` | SD Entry Instance ID | entry offset 5-6 | 原样 |
| `sd.major_version` | entry offset 7 | 1 字节 | 原样 |
| `sd.ttl` | entry offset 8-10 | 24bit 大端 | 秒；0xFFFFFF=无限 |
| `sd.minor_version` | entry offset 11-14 | 4 字节大端 | 原样（无版本=0xFFFFFFFF 表示不检查） |
| `sd.eventgroup_id` | Subscribe Entry | Entry offset 15-16 | 16bit 大端 |
| `sd.option.*` | Option 段 | Option offset 0 起 | IPv4：type=1、len=9、reserved+addr+reserved+proto+port 共12B；IPv6：type=6、len=21、reserved+addr+reserved+proto+port 共24B；proto=17/6 |
| `tp.offered_length` | TP 头 offset 0-3 | 8B TP 头内 | =16+len(payload)（32bit 大端） |
| `tp.segment_size` | 分段切分 | 生成 | 每段载荷 ≤ segment_size |
| `tp.more_segments` | TP 头 offset 5 低 1 位 | 8B TP 头内 | 1=还有后续段、0=末段（其余高位保留） |
| `events[]` | 独立消息 | 每条含 16B 头 | 逐条展开，session 递增 |

> 说明：`sd.option.type`/`someipsd.option.type` 在 tshark 输出为**十进制**（0x01 显示 1），FieldAssert 的 `value` 用十进制字符串与之一致；`message_type`/`serviceid` 为十六进制（0x00 显示 0x00），用 `0x` 串。

## 11. 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.1.0 | 2026-08-20 | 修正 S5 SD hexdump（Entry=16B、Option Length 大端、Length/Entries Length/Option 总长逐字节一致）；S8 采用 JSON 2500B 显式 payload；明确 S6 最小 Ack 无 Option；新增 S9b IPv6 SD Endpoint Option 原子覆盖；补齐 minorver/instanceid/TTL/serviceid 断言与 TCP 包位限制 |
| v1.0.0 | 2026-08-18 | 初稿：完整 11 章；16B 大端头 + Length 口径（=8+len(payload)，自 Request ID 起）以 tshark 3.6.14 字段集核实（someip.* / someipsd.* / someip.tp.*）；Message Type 全枚举（0x00/0x01/0x02/0x80/0x81/TP 变体 0x20..0xA1，0x20 bit 标志=TP、0x40 bit=Ack）；SD entry（Find 0x00/Offer 0x01/Subscribe 0x06/Ack 0x07）+ Option（IPv4/IPv6 Endpoint）；TP 分段（Offered Length 32bit+Segment ID 8bit+more 低 1 位）逐字节核算；autoResponse 双向 REQUEST→RESPONSE（同 radius 模式）；层注册 category=Terminal/DependsOn=[udp]/TransportOn=[udp,tcp]、spec.SOMEIP 扁平键直传；HexDump S1-S10（§6）；testcase 映射索引（§7）；实现集成点（§8）；错误处理（§9）；扩展字段映射（§10） |

> **已核实来源清单**：tshark 3.6.14 本机字段表（`tshark -G fields` 实测 someip.serviceid/messageid/length/sessionid/protoversion/messagetype/returncode、someipsd.entry.type/serviceid/instanceid/majorver/ttl/minorver/eventgroupid/counter、someipsd.option.type/ipv4address/ipv6address/port、someip.messagetype.tp/messagetype.ack、someip.tp.offset/flags.more_segments/reassembled.length）；AUTOSAR SOME/IP 公开标准语义（消息头字段域、Message Type/Return Code 编码、SD entry/option 结构、TP 分段）由上述 tshark 解析器字段与熟知规范口径交叉一致。全文核心字节事实均源自上述来源，未转述未经验证的二手资料。
