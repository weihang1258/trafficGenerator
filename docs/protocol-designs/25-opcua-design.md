# OPC UA（OPC Unified Architecture，统一架构，二进制协议 TCP 4840）设计文档

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：OPC UA（OPC Unified Architecture，OPC 统一架构）二进制协议（OPC UA Binary，Part 6 定义的机器可读线格式）流量的生成，承载于 TCP 4840；覆盖安全通道建立（HEL/ACK/OPN）、服务请求/响应（OpenSecureChannel、Read、Write、Browse、CreateSubscription、CreateMonitoredItems、Publish、CloseSecureChannel）以及周期性发布（Publish Notification Message，发布通知消息）
> 实现状态：**设计阶段，尚无 OPC UA Go 生成器或层注册**。下文出现的 `trafficgen/internal/protocol/opcua/`、`OPCUAConfig` 等路径和符号均是计划接口，不表示当前代码已经存在。
> 配套参考：层链配置架构（18-layer-config-design.md）；同栈建模参考 ENIP 终结层（07-enip-design.md）与 TDS（09-tds-design.md）；testcase 文档（25-opcua-testcase.md）。
> 线格式事实来源：OPC UA Part 6 与实现惯例（open62541、node-opcua、UA-.NETStandard）；未由当前仓库编码器验证的长度、随机值和密码学结果不得写成固定黄金字节。

---

## 目录

1. [概述](#1-概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景（HexDump S1-Sn）](#6-包序列场景hexdump-s1-sn)
7. [与 testcase 文档的映射索引](#7-与-testcase-文档的映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 OPC UA 定位

**OPC UA（OPC Unified Architecture，OPC 统一架构）** 是 OPC Foundation **独立于平台、面向服务架构（SOA，Service-Oriented Architecture）** 的工业互操作标准，替代早期的 OPC DA/AE/HDA（基于 Windows DCOM，分布式组件对象模型）。它把**地址空间（address space，服务器暴露的节点/变量/方法的对象模型）**、**信息模型（information model，对地址空间的语义扩展）** 与**传输（transport）** 解耦。

本设计只实现 **OPC UA Binary（OPC UA 二进制协议，Part 6 定制的紧凑线格式）** 承载于 **TCP 端口 4840**，即 OPC UA `opc.tcp://` 默认传输：

- 不实现 OPC UA HTTPS（`https://`，HTTP 承载）、WebSocket/WebService（`opc.ws://`）；
- 不实现发布/订阅（UADP 组播或 MQTT 承载的数据面 PubSub，PubSub）；
- 不实现 UA 安全策略的完整加密/签名计算链（本设计生成**无安全（None）**与**带签名（Sign）**两种策略的**结构正确**的握手，签名摘要字段以结构占位填充，见 §4.2 的 签名策略说明）。

### 1.2 分层的服务模型

OPC UA 应用层被切成**传输层**与**服务层**两层，本设计严格按此分层建模：

| 层 | 职责 | 对应 wire 结构 |
|----|------|----------------|
| 传输层（transport layer） | 建立/维护物理通道，分段与重组，消息大小协商 | MessageHeader（8B）+ 可选 SecureConversationMessageHeader（12B） |
| 安全层（security layer） | 安全通道、令牌、签名/加密 | AsymmetricAlgorithmSecurityHeader（非对称，OPN 前）+ SequenceHeader（8B） |
| 会话层（session layer） | 服务调用、请求/响应配对、诊断 | RequestHeader/ResponseHeader（会话可空） |
| 应用层（application layer） | 地址空间模型与业务语义 | 服务请求/响应正文（Read/Browse/Subscription 等） |

> 字节序说明：**OPC UA Binary 全部字段均为 little-endian（小端字节序）**——open62541 的 `UA_TcpMessageHeader` 将 MessageType 与 ChunkType 合入一个 raw uint32 后按主机序写出（x86/ARM 均为 LE），node-opcua 用 `writeUInt32LE`/`readUInt32LE` 编解码，UA-.NET 的 BinaryDecoder 默认小端。包括 MessageHeader 的 MessageSize（注意：不是 big-endian）。本设计所有 HexDump 均按小端标注。

### 1.3 一个完整会话的宏观视图

```
TCP 客户端(生成器)                                      TCP 服务器(被测系统/DUT)
     │  ─── SYN ───────────────────────────────────────▶ │
     │  ◀── SYN+ACK ──────────────────────────────────── │      TCP 三次握手（包 1-3）
     │  ─── ACK ───────────────────────────────────────▶ │
     │  ─── HEL (Hello) ───────────────────────────────▶ │      传输层问候（包 4）
     │  ◀── ACK (Acknowledge) ────────────────────────── │      传输层确认（包 5）
     │  ─── OPN (OpenSecureChannel) ────────────────────▶ │      非对称段，打开安全通道（包 6）
     │  ◀── OPN ← (OpenSecureChannelResponse) ────────── │      服务错误编码 0=Good（包 7）
     │  ─── MSG ReadRequest ────────────────────────────▶ │      对称段，服务调用（包 8）
     │  ◀── MSG ReadResponse ─────────────────────────── │      服务响应（包 9）
     │  ─── MSG CLO (CloseSecureChannel) ────────────────▶ │      关闭安全通道（包 10）
     │  ◀── TCP FIN/FIN-ACK/ACK ──────────────────────── │      TCP 关闭（包 11-12）
```

包索引（packet index，从 1 起，含握手）是 testcase 与 pcap 用例断言的**硬锚点**，见 §6。

### 1.4 服务清单与对应传输行为

本设计实现的 UA 服务及其 NodeId（服务类型标识，经 open62541 NodeIds.csv 核对）：

| 服务 | 服务类型 NodeId | 请求/响应 | 用途 |
|------|----------------|-----------|------|
| OpenSecureChannel | 446 | OPN 段 | 建立安全通道（含安全令牌） |
| CloseSecureChannel | 450 | OPN 段 | 关闭安全通道 |
| Browse | 525 | MSG 对称段 | 遍历地址空间节点/引用 |
| Read | 629 | MSG 对称段 | 读变量值/节点属性 |
| Write | 671 | MSG 对称段 | 写变量值/节点属性 |
| CreateSubscription | 785 | MSG 对称段 | 建立订阅（周期发布的前提） |
| CreateMonitoredItems | 749 | MSG 对称段 | 给订阅挂监视项 |
| SetPublishingMode | 797 | MSG 对称段 | 启用/暂停发布 |
| Publish | 824 | MSG 对称段 | 拉取/应答发布通知 |

> 注意：服务类型标识是 NodeId，不是“两个字节固定编码”。例如 ns=0 且数值不超过 65535 时可用 FourByte NodeId（掩码 `01` + namespaceIndex Byte + UInt16 id LE）；服务类型的实际编码由编码器选择，不能仅凭十进制值断言线字节。OpenSecureChannel=446、CloseSecureChannel=450 等数值应以对应版本的 NodeIds 表为准。

### 1.5 本设计的范围与不做的事

**实现：**
- 传输层 HELLO/ACKNOWLEDGE/ERROR 三段交换（含 MessageSize 协商与限制）；
- OPN 非对称安全通道建立（None 与 Sign 两种 SecurityMode，SecurityMode，安全模式）；
- MSG 对称段服务调用（Read/Write/Browse/Subscription 家族 + 周期性 Publish Notification）；
- CloseSecureChannel 优雅关闭 + TCP FIN 关闭；
- 多会话（`sessions>1`，同一 TCP 连接上的多个逻辑会话交错）与 IPv4/IPv6 双栈。

**不做：**
- TLS/加密（SignAndEncrypt）与真实签名计算（Sign 模式只保证结构正确，摘要区零填充，见 §4.2 表下注）；
- 分段/重组（每个 UA 消息都 < 发送缓冲区，恒为单个 final 消息块，ChunkType='F'）；
- 反向注入：本设计是**单向生成器**，`autoResponse:true` 时客户端侧的响应包体按固定模板回灌（见 §9 错误处理），不是真实对端实现。

---

## 2. 数据类型与编码

### 2.1 总体原则

OPC UA Binary 的编解码规则（Part 6 §5）：

1. **所有整数/浮点/时间均为 little-endian**；
2. 字符串/字节串带 **Int32 长度前缀**（`-1` 表示 null；`0` 表示空串/空字节串）；
3. 结构体（struct）：按字段声明顺序**顺序编码**，无对齐填充；
4. 联合/变体（Variant）：前置 **1 字节掩码**，见 §2.6；
5. 枚举（enum）：**按 Int32（4 字节）** 编码；
6. 数组：前置 **Int32 长度**（`-1`=null、`0`=空数组），后随元素；元素的 "None" 值（`UA_Variant_encodeBinary` 中的 `UA_Variant_ARRAYDIMENSIONS_NONE` 等）用 `null`/长度 `-1` 表示。

### 2.2 MessageHeader（消息头，8 字节，传输层）

所有 OPC UA 消息（HEL/ACK/ERR/OPN/CLO/MSG/RHE）以同一个 8 字节头开始：

| 偏移 | 字段 | 类型/尺寸 | 说明 |
|------|------|-----------|------|
| 0 | MessageType（消息类型） | 3 字节 ASCII | `'HEL'`、`'ACK'`、`'ERR'`、`'OPN'`、`'CLO'`、`'MSG'`、`'RHE'` |
| 3 | ChunkType（块类型） | 1 字节 ASCII | `'C'`=chunk（中间块）、`'S'`=最后块、`'F'`=final/完整块；**本设计恒为 `'F'`** |
| 4 | MessageSize（消息大小） | UInt32 **LE** | 整个消息（含 8B 头）的总字节数 |

open62541 把 MessageType+ChunkType 合成一个原始 uint32（`UA_BITMASK_MESSAGETYPE=0x00FFFFFF`、`UA_BITMASK_CHUNKTYPE=0xFF000000`），所以 **MessageSize 必须小端**；node-opcua 直接 `writeUInt32LE(size, 4)`。

### 2.3 SecureConversationMessageHeader（安全会话头，可变长）

紧跟 MessageHeader，随消息类型不同有两种形态：

- **非对称段（OPN 请求/响应，安全通道建立前）**：`SecureChannelId(UInt32)` + `AsymmetricAlgorithmSecurityHeader(结构体)` + `SequenceHeader(SequenceNumber UInt32, RequestId UInt32)`；
- **对称段（MSg/CLO，安全通道建立后）**：`SecureChannelId(UInt32)` + `SecurityTokenId(UInt32)` + `SequenceHeader`。

| 偏移（相对消息头） | 字段 | 尺寸 | 注释 |
|------|------|------|------|
| 8 | SecureChannelId（安全通道 ID） | UInt32 LE | OPN 请求可发送 `0`；响应回显服务器分配的 ID |
| 12 | AsymmetricAlgorithmSecurityHeader（非对称算法安全头） | 结构体 | 仅非对称段；对称段此处直接是 TokenId |
| – | SecurityPolicyUri（安全策略 URI） | String | 长度 Int32 + UTF-8；None 策略 `opc.tcp://opcfoundation.org/UA/SecurityPolicy#None`（70 字节） |
| – | SenderCertificate（发送者证书） | ByteString | 长度 Int32；None → `-1`（null） |
| – | ReceiverCertificateThumbprint（接收者证书指纹） | ByteString | 长度 Int32；None → `-1` |
| – | SequenceHeader | 结构体 | SequenceNumber UInt32 + RequestId UInt32，各 4B LE |
| – | SecurityTokenId | UInt32 | 仅对称段：OPN 响应携带的有效令牌 ID |

**长度常量**（open62541 `ua_securechannel.c`）：`MESSAGEHEADER_LENGTH=8`、`CHANNELHEADER_LENGTH=12`、`SEQUENCEHEADER_LENGTH=8`、`SYMMETRIC_SECURITYHEADER_LENGTH=4`、`OPERATIONAL_HEADER_LENGTH=16`（对称段：8 消息头 + 4 SecureChannelId + 4 TokenId）。

### 2.4 内置基础类型

| 类型 | 线格式 | 备注 |
|------|--------|------|
| Boolean（布尔） | 1 字节（`0`/`1`） | |
| SByte/Byte | 1 字节 | |
| Int16/UInt16 | 2 字节 LE | |
| Int32/UInt32 | 4 字节 LE | 也用于枚举、长度前缀 |
| Int64/UInt64 | 8 字节 LE | |
| Float/Double | 4/8 字节 IEEE-754 LE | |
| String（字符串） | Int32 长度 + UTF-8 字节 | `-1`=null |
| ByteString（字节串） | Int32 长度 + 原始字节 | `-1`=null |
| DateTime（时间戳） | Int64：**100ns 间隔**自 1601-01-01T00:00:00Z 起的偏移 | 见 §2.5 |
| Uuid（GUID） | 16 字节 | 见 §2.7 |
| NodeId（节点 ID） | 变长，1B 编码掩码前缀 | 见 §2.8 |
| QualifiedName（限定名） | UInt16 namespaceIndex + String name | 见 §2.10 |
| LocalizedText（本地化文本） | 编码掩码 + 可选 locale/text | 见 §2.10 |
| StatusCode（状态码） | UInt32 | 见 §9.1 |
| Variant（变体） | 1B 掩码 + 值 | 见 §2.6 |
| ExtensionObject（扩展对象） | 编码掩码 + TypeId(NodeId) + 可选正文 | 见 §2.11 |

### 2.5 DateTime（日期时间）

**DateTime 是 Int64，单位 100ns，自 1601-01-01T00:00:00 UTC 起**（Windows FILETIME 基准）。生成时把 Go `time.Now().UnixNano()` 折算：`Ticks = (unixNano/100) + 116444736000000000`（1601→1970 的 100ns 差额）。`0` 表示 "not specified"。

### 2.6 Variant（变体）

第一字节是 **编码掩码（encoding mask）**：

| 位 | 掩码值 | 含义 |
|----|--------|------|
| bit 7（0x80） | 1 | 值是数组（Array）；长度 Int32 + 元素 |
| bit 6（0x40） | 1 | 带 arrayDimensions（UInt32[]，Int32 长度前缀） |
| bits 0-5（0x3F） | 类型 ID | builtin 类型 ID，见下 |

类型 ID（小端 6 位）在 open62541 中为 `UA_DataTypeKind+1`（`UA_DATATYPEKIND_*` 从 0 起）：

| ID | 类型 | 尺寸 |
|----|------|------|
| 1 | Boolean | 1B |
| 2 | SByte | 1B |
| 3 | Byte | 1B |
| 4 | Int16 | 2B |
| 5 | UInt16 | 2B |
| 6 | Int32 | 4B |
| 7 | UInt32 | 4B |
| 8 | Int64 | 8B |
| 9 | UInt64 | 8B |
| 10 | Float | 4B |
| 11 | Double | 8B |
| 12 | String | 见 §2.4 |
| 13 | DateTime | 8B |
| 14 | Guid/Uuid | 16B |
| 15 | ByteString | 见 §2.4 |
| 16 | XmlElement | String 形式 |
| 17 | NodeId | 见 §2.8 |
| 18 | ExpandedNodeId | 见 §2.8 |
| 19 | StatusCode | 4B（UInt32） |
| 20 | QualifiedName | 见 §2.10 |
| 21 | LocalizedText | 见 §2.10 |
| 22 | ExtensionObject | 见 §2.11 |
| 23 | DataValue | 结构体（见 §2.11、§3.3） |
| 24 | Variant | 递归 |
| 25 | DiagnosticInfo | 见 §2.12 |

**枚举放 Variant 时按 Int32（ID 6）**；**自定义数据类型（结构体）放 Variant 时按 ExtensionObject（ID 22）**。数组：掩码加 `0x80`，先写 Int32 长度再写元素。

### 2.7 Uuid（GUID）

16 字节，**按 OPC UA 二进制规则存储：Data1（4B LE）+ Data2（2B LE）+ Data3（2B LE）+ Data4（8B 原序）**。即网络/文本形式的 `00112233-4455-6677-8899-aabbccddeeff` 在线上为 `33 22 11 00 55 44 77 66 88 99 aa bb cc dd ee ff`。

### 2.8 NodeId（节点 ID）

第一个字节是 **NodeIdType 编码掩码（encoding mask）**，决定后续布局：

| 掩码（第 1 字节） | 类型 | 布局 | 适用 |
|------|------|------|------|
| `0x00` | TwoByte（两字节） | id: Byte（1B，ns=0） | id ≤ 255 且 ns=0 |
| `0x01` | FourByte（四字节） | namespaceIndex: Byte（1B）+ id: UInt16（2B LE） | ns ≤ 255 且 id ≤ 65535 |
| `0x02` | Numeric（数值/完整） | namespaceIndex: UInt16（2B）+ id: UInt32（4B） | 任意数值 NodeId |
| `0x03` | String | ns: UInt16 + string: String（长度+UTF-8） | 字符串 NodeId（如 `ns=1;s=Server`） |
| `0x04` | Guid | ns: UInt16 + guid: 16B | GUID NodeId |
| `0x05` | Opaque/ByteString | ns: UInt16 + bytes: ByteString | 不透明 NodeId |

**ExpandedNodeId**（扩展节点标识）在上面的编码字节上加扩展标志：`0x80` 表示带 namespaceUri（String），`0x40` 表示带 serverIndex（UInt32）。附加字段按规范顺序追加为 `[namespaceUri?][serverIndex?]`；未设置标志时不出现对应字段。

**常见服务类型 NodeId 全部是 TwoByte（掩码 0x00 + 1 字节 id）**：Read=629 超 255 用 FourByte? 否——629 用 Numeric（掩码 0x02）或 FourByte（629 ≤ 65535 且 ns=0 → 掩码 0x01：`01 00 75 02`）。Browse=525（`01 00 0d 02`）、Write=671（`01 00 9f 02`）同理。本设计统一用 **FourByte 编码（掩码 0x01 + `00` + 2B id LE）** 表达 ns=0 且 id ≤ 65535 的服务/属性 NodeId。

### 2.9 NumericRange / 其它值类型

- NumericRange（数值范围，用于 Read/Write 的 IndexRange 参数）：String 形式 `"i0:j0,i1:j1"`，默认 `""`。

### 2.10 QualifiedName 与 LocalizedText

- **QualifiedName（限定名）**：`namespaceIndex: UInt16 LE` + `name: String`（长度 + UTF-8）；
- **LocalizedText（本地化文本）**：第 1 字节编码掩码——bit0=带 locale（UInt16 localeId String）、bit1=带 text（String）；`0x00` 表示 null/空。默认纯文本用 `0x02` + 长度 + UTF-8 文本。

### 2.11 ExtensionObject / DataValue

- **ExtensionObject（扩展对象）**：`TypeId: NodeId` + `encoding: Byte`（`0x00`=None、`0x01`=ByteString、`0x02`=XmlElement）+ 按编码类型出现的正文。空对象仍包含 NodeId 和 encoding 两部分；若 TypeId 使用空 TwoByte NodeId，最小编码为 `00 00 00`。
- **DataValue（数据值，Read/Write 的 Value）**：编码掩码 Byte——bit0=Value（Variant），bit1=StatusCode，bit2=SourceTimestamp（DateTime），bit3=SourcePicoseconds（UInt16），bit4=ServerTimestamp，bit5=ServerPicoseconds；本设计 `0x01`（仅 Value）。

### 2.12 DiagnosticInfo（诊断信息）

`ServiceResult != Good` 时才可选出现；本设计总是省略（生成 `1` 字节 null DiagnosticInfo，见 §3.3 响应头的固定尾部）。线格式为一串可选字段，默认全长度 -1/null。

### 2.13 编码示例汇总（可作单测黄金向量）

| 值 | 线字节（十六进制） | 依据 |
|----|-------------------|------|
| `Int32 1000` | `e8 03 00 00` | 小端 |
| `UInt32 28` | `1c 00 00 00` | 小端 |
| `UInt32 3600000` | `80 ee 36 00` | 0x0036EE80 小端 |
| `String "abc"` | `03 00 00 00 61 62 63` | 长度 3 + UTF-8 |
| `String null` | `ff ff ff ff` | -1 |
| `ByteString null` | `ff ff ff ff` | -1 |
| `DateTime now` 折算 | `xx …` | 1601 基准 100ns |
| `Boolean true` | `01` | |
| `NodeId ns=0;i=1` | `00 01` | TwoByte |
| `NodeId ns=0;i=1001` | `01 00 e9 03` | FourByte，id 1001=0x03E9 LE |
| `NodeId ns=1;s=Server` | `03 01 00 06 00 00 00 53 65 72 76 65 72` | String |
| `QualifiedName null` | `00 ff ff ff ff` | ns=0 + name null |
| `StatusCode BadNodeIdUnknown` | `00 00 34 80` | 0x80340000 |
| `StatusCode Good` | `00 00 00 00` | 0 |
| `Variant Int32 42` | `06 2a 00 00 00` | 掩码 6 + Int32 |
| `Variant Int32[] {1,2}` | `86 02 00 00 00 01 00 00 00 02 00 00 00` | 掩码 0x86 |
| `null ExtensionObject` | `00 00 00` | 空 TwoByte NodeId + encoding 0 |
| `null DiagnosticInfo` | `00` | 全空结构体 |
| `HEL`（空 EndpointUrl） | `48 45 4c 46 20 00 00 00` | HEL+F+32 LE |
| `ACK` | `41 43 4b 46 1c 00 00 00` | ACK+F+28 LE |

> 以上即 `opcua_test.go` 中 `TestEncodeXX` 系列黄金向量；任何实现改动不得破坏这些字节。


---

## 3. 消息结构

### 3.1 三种消息类别

OPC UA Binary 消息按**传输阶段**分三类，外层结构不同：

| 类别 | MessageType | 用途 | 外层结构 |
|------|-------------|------|----------|
| 传输层握手 | `'HEL'` / `'ACK'` / `'ERR'` | 建立/拒绝传输通道 | MessageHeader + 固定结构正文 |
| 安全通道非对称段 | `'OPN'` | OpenSecureChannel 请求/响应、CloseSecureChannel | MessageHeader + SecureChannelId + 非对称安全头 + SequenceHeader + 服务正文 |
| 应用对称段 | `'MSG'` | 其余所有服务（Read/Write/Browse/Subscription/Publish） | MessageHeader + SecureChannelId + TokenId + SequenceHeader + 服务正文 |

### 3.2 传输层消息（HEL/ACK/ERR）

**HEL（Hello，客户端→服务器）**，文件头 `'HEL'`+`'F'` + MessageSize=8+20+4=**32**：

| 偏移 | 字段 | 类型 | 值（示例） |
|------|------|------|-----------|
| 0-5 | MessageType + ChunkType | 'HEL'+'F' | `48 45 4c 46`（"HELF"） |
| 4-7 | MessageSize | UInt32 | `20 00 00 00`（32 LE） |
| 8-11 | ProtocolVersion（协议版本） | UInt32 | `00 00 00 00` |
| 12-15 | ReceiveBufferSize（接收缓冲区大小） | UInt32 | 生成端建议（如 65536） |
| 16-19 | SendBufferSize（发送缓冲区大小） | UInt32 | 生成端建议（如 65536） |
| 20-23 | MaxMessageSize（最大消息大小） | UInt32 | `00 00 00 00`（不限制） |
| 24-27 | MaxChunkCount（最大块数） | UInt32 | `00 00 00 00`（不限制） |
| 28-31 | EndpointUrl（端点 URL） | String | `00 00 00 00`（空串，4 字节长度前缀） |

> **EndpointUrl（端点 URL）**：OPC UA Part 6 §7.1.2.3 HelloMessage 的第 6 个字段，String 类型（Int32 长度前缀 + UTF-8 字节）。空串至少 4 字节长度前缀。因此 HEL MessageSize = 8 + 20 + 4 = **32**（JSON `20000000`）。

**ACK（Acknowledge，服务器→客户端）**，'ACK'+'F' + MessageSize=8+20=**28**；字段同 HEL 但不含 EndpointUrl（ProtocolVersion/ReceiveBufferSize/SendBufferSize/MaxMessageSize/MaxChunkCount），回显服务器协商结果。

**ERR（Error，双向）**：MessageSize 可变（8+4+String）。字段：`ErrorCode: UInt32` + `ErrorReason: String`（长度+UTF-8）。

### 3.3 服务消息的公共骨头（对称 MSG 段）

对称 MSG 段逐字节布局（全 LE）：

```
偏移        尺寸    字段
0           8       MessageHeader（'MSG'+'F'+MessageSize）
8           4       SecureChannelId（UInt32）
12          4       SecurityTokenId（UInt32）
16          4       SequenceNumber（UInt32，通道内递增）
20          4       RequestId（UInt32，与响应配对）
24          …       RequestHeader（若会话请求）或服务字段（无会话服务）
```

**RequestHeader（请求头）** 字段序：

| 字段 | 类型 | 说明 |
|------|------|------|
| AuthenticationToken（认证令牌） | NodeId | 无会话 → TwoByte 0（2B `00 00`）；有会话 → 会话 NodeId（例 `ns=1;i=1001` → 掩码 0x03...） |
| Timestamp（时间戳） | DateTime Int64 | 生成时刻，100ns 基准 1601 |
| RequestHandle（请求句柄） | UInt32 | 请求递增，用于配对 |
| ReturnDiagnostics（返回诊断） | UInt32 | 本设计 `0` |
| AuditEntryId（审计条目） | String | 长度 -1（null） |
| TimeoutHint（超时提示） | UInt32 | 毫秒，如 10000 |
| AdditionalHeader（附加头） | ExtensionObject | null → 线上 1B `00`（TwoByte NodeId 0）+ 1B `00`（encoding None） |

**ResponseHeader（响应头）** 之后总跟 **1 字节 null DiagnosticInfo**（`00`）：

| 字段 | 类型 | 说明 |
|------|------|------|
| Timestamp | DateTime | |
| RequestHandle | UInt32 | 回显请求句柄 |
| ServiceResult | StatusCode UInt32 | `0`=Good；`0x80340000`=BadNodeIdUnknown；`0x801F0000`=BadUserAccessDenied |
| ServiceDiagnostics | DiagnosticInfo（null→1B） | 本设计恒 `00` |
| StringTable | String[]（null→长度 -1 = `ff ff ff ff`） | |
| AdditionalHeader | ExtensionObject（null→`00 00`） | |

> 响应头以外的响应体（如 Read 返回的 DataValue[]），生成端**按请求模板回灌**（fixed/inc 值轮换），不对真实服务器做语义解析——见 §1.5 与 §9。

### 3.4 服务正文结构示例（wire order）

**OpenSecureChannelRequest（OPN 非对称段）**，紧跟 SequenceHeader（偏移 24 起）：

| 字段 | 类型 | 示例 |
|------|------|------|
| ClientProtocolVersion（客户端协议版本） | UInt32 | 1 |
| RequestType（请求类型：Issue=0/Renew=1） | 枚举 Int32 | 0（Issue） |
| SecurityMode（安全模式：Invalid=0/None=1/Sign=2/Encrypt=3） | 枚举 Int32 | 1（None）/ 2（Sign） |
| ClientNonce（客户端随机数） | ByteString | 长度 32 + 32B（None 可空） |
| RequestedLifetime（请求生命周期，毫秒） | UInt32 | 3600000 |

**OpenSecureChannelResponse**：`ClientProtocolVersion + ServerProtocolVersion` + `SecurityToken(SecureChannelId UInt32, TokenId UInt32, CreatedAt DateTime, RevisedLifetime UInt32)` + `ServerNonce ByteString`。**TokenId 在后续对称段作为偏移 12 处的 SecurityTokenId**。

**ReadRequest（对称段）** 请求正文：

| 字段 | 类型 | 说明 |
|------|------|------|
| RequestHeader | 结构体 | 见 §3.3 |
| MaxAge（最大时效） | Duration UInt32 | 本设计 0 |
| TimestampsToReturn（返回时间戳：Neither=0/Server=1/Source=2/Both=3） | 枚举 Int32 | 0（Neither） |
| NodesToRead（要读的节点） | ReadValueId[] | 数组：Int32 长度 + 元素 |

**ReadValueId**：`NodeId nodeId + AttributeId UInt32 + NumericRange String(null) + DataEncoding QualifiedName(null → `01`+`ff ff ff ff`...)`。AttributeId 取值见 §10.2。

**WriteRequest**：`RequestHeader + NodesToWrite: WriteValue[]`；**WriteValue**：`NodeId(nodeId) + AttributeId(UInt32) + NumericRange(String) + Value(DataValue)`。

**BrowseRequest**：

| 字段 | 类型 | 说明 |
|------|------|------|
| RequestHeader | 结构体 | |
| View | ViewDescription | `ViewId: NodeId(null→00) + Timestamp + ViewVersion(UInt32)` |
| RequestedMaxReferencesPerNode（每节点最大引用数） | UInt32 | 1000 |
| NodesToBrowse（要浏览的节点） | BrowseDescription[] | |
| BrowseDescription | 结构体 | `NodeId + BrowseDirection(枚举 Int32) + ReferenceTypeId(NodeId) + IncludeSubtypes(Boolean) + NodeClassMask(UInt32) + ResultMask(UInt32)` |

**CreateSubscriptionRequest**：`RequestHeader + RequestedPublishingInterval(Duration Double msec) + RequestedLifetimeCount(UInt32) + RequestedMaxKeepAliveCount(UInt32) + MaxNotificationsPerPublish(UInt32 0) + PublishingEnabled(Boolean true) + Priority(Byte 0)`。

**CreateMonitoredItemsRequest**：`RequestHeader + SubscriptionId(UInt32) + TimestampsToReturn(Int32) + ItemsToCreate: MonitoredItemCreateRequest[]`；内层 `ItemToMonitor: ReadValueId` + `MonitoringMode(Int32：0/1/2)` + `RequestedParameters: MonitoringParameters(ClientHandle UInt32 + SamplingInterval Double + Filter(null ExtObj→1B 00) + QueueSize UInt32)`。

**SetPublishingModeRequest**：`RequestHeader + PublishingEnabled(Boolean) + SubscriptionIds: UInt32[]`。

**PublishRequest**：`RequestHeader + SubscriptionAcknowledgements: SubscriptionAcknowledgement[]`（可空数组→长度 0 或 -1）。

### 3.5 大小计算与"F"块约束

每个 UA 消息都要满足 `MessageSize = 实际字节数`，且整包大小 < 协商的 ReceiveBufferSize。本设计所有消息均为 **final 块**（ChunkType='F'），即 `MessageSize` 恒等于（8 消息头 + 12/16 安全头 + SequenceHeader + 服务正文）的总和。生成时用 **两遍编码**：先编码全部字段到可增长 buffer，再回填 MessageSize（见 §8.2）。

各类消息的**完整包级布局**（含长度推导），是 §6 包索引与 testcase 包数断言的基础：

| 消息 | 消息头 | 附加头 | Sequence | 服务体 | MessageSize 合计（None，示例） |
|------|--------|--------|----------|--------|-------------------------------|
| HEL | 8 | – | – | 20（5×UInt32）+ 4（空 EndpointUrl String） | **32** |
| ACK | 8 | – | – | 20（5×UInt32，无 EndpointUrl） | **28** |
| OPN 请求（None） | 8 | 4 SecureChannelId + (4+70) PolicyUri + 4 + 4（双 null ByteString） | 8 | OpenSCReq ≈ 4+4+4+ (4+32) + 4 = 52 | **154** |
| OPN 响应（None） | 8 | 4 + (4+70) + 4 + 4 | 8 | OpenSCResp ≈ 4+4+ SecurityToken(4+4+8+4)+ (4+64) = 96 | **198** |
| MSG Read（None,1 节点） | 8 | 4+4 TokenId | 8 | 载荷 = 消息头 8 + 通道 4 + Token 4 + Sequence 8 + ReqHeader 27 + Read 体 29 | **80** |
| MSG Read 响应 | 8 | 4+4 | 8 | 载荷 = 消息头 8 + 通道 4 + Token 4 + Sequence 8 + RespHeader 23 + Results 11 | **≈ 58** |

> 表中是**结构推导**，实际以生成器两遍编码后的 MessageSize 为准；测试点（§7 T4 等）用 FrameAssert 抓 `MessageSize` 位置，不硬编码全长。

### 3.6 空响应/数组的占位写法

- 数组 null：`ff ff ff ff`；数组空：`00 00 00 00`；
- 字符串 null：`ff ff ff ff`；字符串空：`00 00 00 00`；
- 结构体 null（ExtensionObject）：`00 00`；
- `DataValue` 空值（无掩码）→ `00`；`DataValue`（值+状态）→ 掩码 `01`/`03`。

---

## 4. 状态机

### 4.1 状态总览

通道生命周期用有限状态机建模，状态与迁移如下：

```
   [Idle] ──TCP 三次握手──▶ [HelloSent]──HEL──▶ [WaitAck]──ACK──▶ [ChannelOpen]
                                                                    │
   [WaitAck] ── ERR/超时 ──────────────▶ [Closed]                  │（服务调用）
   [ChannelOpen] ── OPN 请求 ──────────▶ [OpenChannel]             │
   [ChannelOpen] ── MSG Read/Write/… ──▶ [Service]（读/写等）       │
   [Service] ── Publish/Notification ──▶ [Subscribe]（周期性发布）   │
   [ChannelOpen] ── CLO ────────────────▶ [CloseSecure] ──TCP FIN──▶ [Closed]
   [Subscribe]   ── CLO ────────────────▶ [CloseSecure] ──TCP FIN──▶ [Closed]
```

生成器的**四阶段推进**（`planOpcuaSession`）：

| 阶段 | 状态 | 产出包 | 内容 |
|------|------|--------|------|
| S1 传输层握手 | HelloSent → WaitAck → ChannelOpen | HEL + ACK | HEL(‘HEL’,size 28) → ACK(‘ACK’,size 28) |
| S2 安全通道打开 | ChannelOpen → OpenChannel | OPN 请求 + OPN 响应 | 非对称段 + OpenSecureChannelRequest/Response |
| S3 会话服务序列 | OpenChannel → Service → (Subscribe) | Read + (响应) / Write+（响应）/ Browse / CreateSubscription / CreateMonitoredItems / SetPublishingMode / Publish / Notification | MSG 对称段逐个服务 |
| S4 关闭 | Service/Subscribe → CloseSecure → Closed | CLO + 响应 | CloseSecureChannelRequest（非对称段）+ TCP FIN |

各用例（§6 S1-S8）即按阶段切分：`S1`=仅握手、`S2`=握手+OPN、`S3`=握手+OPN+一次服务调用、`S5`=完整订阅周期、`S6`=keep-alive、`S7`=错误注入、`S8`=多会话。

### 4.2 OPN（安全通道打开）细节

OPN 请求是**非对称段**，头部结构：`MessageHeader(8) + SecureChannelId(4) + AsymmetricAlgorithmSecurityHeader + SequenceHeader(8)`，其中非对称头含 SecurityPolicyUri/String、SenderCertificate、ReceiverCertificateThumbprint。

**SecurityPolicyUri（安全策略 URI）** 由 SecurityMode 决定（None 策略）：
- None：`opc.tcp://opcfoundation.org/UA/SecurityPolicy#None`（70 = 0x2E 字节）
- Sign / SignAndEncrypt（本设计只 Sign）：`.../SecurityPolicy#Basic256Sha256`（102 字节）

**SecurityMode × 非对称头字段矩阵**（None vs Sign）：

| 字段 | None | Sign（结构正确） |
|------|------|------------------|
| SecurityPolicyUri | 70B（None URI） | 102B（Basic256Sha256 URI） |
| SenderCertificate | -1（null） | ByteString：长度 512（占位 DER，零填充） |
| ReceiverCertificateThumbprint | -1（null） | ByteString：长度 20（SHA-1 占位，零填充） |
| SequenceNumber/RequestId | 4+4 | 4+4（同大小） |
| SecurityMode（请求体内） | 1（Int32） | 2（Int32） |

> **签名说明（Sign 只保证结构正确）**：Sign 模式下真实的 HeaderSignature 需要按 Basic256Sha256 对非对称头做 RSA-PSS 签名，本设计**不实现真实密码学**，SymmetricAlgorithmSecurityHeader 的 Signature 区以长度+零填充占位、Fake Sig 保证字节布局完整。IPv4+IPv6、测试点 pcap 只断言**结构**（偏移+长度+MessageSize），不校验签名可用性。意图是覆盖"带签名"的线格式路径，不是产出一条可被真实服务器验证签名的流。

**OPN 期间的请求体顺序**（接在 SequenceHeader 之后，偏移 24 起）：`ClientProtocolVersion(4) + RequestType(4) + SecurityMode(4) + ClientNonce(ByteString) + RequestedLifetime(4)`。Response 体中 SecurityToken 供应 `SecureChannelId` 与 `TokenId`——**TokenId 是后续对称 MSG 段偏移 12 处的固定值**。

### 4.3 HEL→ACK 协商与大小规则

传输层握手携带 4 个协商字段（§3.2）：`ReceiveBufferSize/SendBufferSize/MaxMessageSize/MaxChunkCount`。生成端：
- HEL 中 SendBufferSize/ReceiveBufferSize 取配置（默认 65536）；
- ACK（响应）中回显同款四个字段；
- 之后所有消息的 MessageSize 均不得超过协商值；本设计所有消息都远小于 65536，恒为 final 块 `'F'`，不做分段。

### 4.4 订阅与周期性发布

订阅（Subscription）是一条**发布轮询**链路：

```
CreateSubscription ──▶ CreateMonitoredItems ──▶ SetPublishingMode(true) ──▶Publish──▶Notification
   (785)                    (749)                       (797)                    (824)
```

- CreateSubscription 响应可带 RevisedPublishingInterval（毫秒 Double），本设计以固定 1000ms 示例；
- Publish 循环：`publish_count` 次 PublishRequest 之间，按 `publish_interval`（毫秒，最小 50ms 采样）**节流**；每条 Publish（请求+响应）之间**间隔一个订阅周期**；
- 周期性通知（Notification）：Publish 响应的 NotificationMessage 里 1 个 DataChangeNotification，`SequenceNumber` 递增；
- keep-alive：若 `keep_alive` 配置，在订阅空转时发 PublishRequest（不改变订阅），监视项计数不变。

### 4.5 多会话交错（sessions>1）

`session_count > 1` 时，同一个 TCP 连接 / 安全通道上创建**多个逻辑会话**。生成端为每个会话维持一份 `RequestHandle`/`SequenceNumber` 空间，按 `round_robin` 交错发请求（一次 Read 每个会话）。AuthenticationToken 各不相同（`ns=1;i=1001,s=SessionNNN`），各会话独立推进阶段机。

### 4.6 关闭序列

- **应用层**：发 `CloseSecureChannelRequest`（OPN 非对称段，MessageType 'CLO'），随后 TCP 关闭（FIN）；
- **传输层**：TCP FIN/FIN-ACK/ACK（包 11-13 S5）。

### 4.7 状态迁移表（驱动实现）

状态机的每个迁移都对应生成器的一个阶段函数，作为单测覆盖清单：

| 当前状态 | 事件 | 动作 | 下一状态 | 产出包 |
|----------|------|------|----------|--------|
| Idle | 任务启动 | 建立 TCP 连接（SYN） | SynSent | 1 |
| SynSent | SYN-ACK 收到 | ACK | HelloSent | 2-3 |
| HelloSent | send HEL | HEL 请求 | WaitAck | 4 |
| WaitAck | ACK 收到 | 校验 MessageSize | ChannelOpen | 5 |
| WaitAck | ERR 收到 | 记错误 | Closed | (ERR 包) |
| ChannelOpen | OPN 发送（None/Sign） | OpenSecureChannelRequest | OpenChannel | 6 |
| OpenChannel | OPN 响应收到 | 保存 SecureChannelId/TokenId | SessionInit | 7 |
| SessionInit | Read | ReadRequest | Service | 8 |
| Service | 响应 | 记录结果 | Service | 9 |
| Service | CreateSubscription | … | Subscribe | 12-13 |
| Subscribe | CreateMonitoredItems | … | Subscribe | 14-15 |
| Subscribe | SetPublishingMode(true) | … | Subscribe | 16-17 |
| Subscribe | Publish 循环 | … | Subscribe（publish_count 递减） | 18-21 |
| Subscribe/Service | CLO | CloseSecureChannelRequest | CloseSecure | 22 |
| CloseSecure | CLO 响应 + FIN | TCP FIN 关闭 | Closed | 23-26 |

> 多会话（sessions>1）：状态机矩阵不变，但**每会话**各持一份 Sequence/RequestHandle/AuthenticationToken 上下文，交错推进（§4.5）。


---

## 5. 配置类型定义

### 5.1 层注册与 flat 键

OPC UA 是 **tcp 终结层（terminal layer）**。在 `internal/core/layers/registry.go` 中的注册（对齐 enip 模式）：

```go
r.Register(LayerSchema{
    Name:       "opcua",
    Category:   CategoryTerminal,       // 终结层：层数组条目零负载
    DependsOn:  []string{"tcp"},        // 依赖 TCP 层提供 4 元组/端口
    Description: "OPC UA binary protocol over TCP 4840 (terminal generated stream)",
})
```

链规划 `internal/core/layers/chain_planner.go` 用 flat 键直接把配置放进 FlowMeta：

```go
OPCUA: spec.OPCUA,   // FlowMeta.OPCUA 由策略层经 spec.OPCUA 灌入
```

即**配置零负载**（layer 条目不携带字节），全部携带在 `spec.OPCUA` / `FlowMeta.OPCUA`（flat OPCUA 结构体），终结层生成器从 FlowMeta 读出并驱动一系列 `buildOPCUA*Packet`。`dst_port` 默认 **4840**。

### 5.2 OPCUAConfig 结构（Go 侧）

`internal/core/types.go`（对齐 `ENIPConfig`）：

```go
type OPCUAConfig struct {
    // —— 握手与安全 ——
    SecurityMode        string            `json:"security_mode,omitempty"`        // none|sign|signandencrypt（默认 none）
    SecurityPolicy      string            `json:"security_policy,omitempty"`
    ReceiveBufferSize   uint32            `json:"receive_buffer_size,omitempty"`   // 默认 65536
    SendBufferSize      uint32            `json:"send_buffer_size,omitempty"`      // 默认 65536
    MaxMessageSize      uint32            `json:"max_message_size,omitempty"`      // 默认 0（不限制）
    MaxChunkCount       uint32            `json:"max_chunk_count,omitempty"`       // 默认 0
    RequestedLifetime   uint32            `json:"requested_lifetime,omitempty"`    // 默认 3600000

    // —— 会话 ——
    SessionCount        int               `json:"sessions,omitempty"`              // 逻辑会话数，默认 1
    SequenceStart       uint32            `json:"sequence_start,omitempty"`        // 默认 1000
    RequestStart        uint32            `json:"request_handle_start,omitempty"`  // 默认 1000

    // —— 服务序列（s3）——
    Read                []OPCUAService    `json:"read,omitempty"`                  // Read 多 NodeId
    Write               []OPCUAService    `json:"write,omitempty"`
    Browse              []OPCUAService    `json:"browse,omitempty"`

    // —— 订阅 ——
    Subscription        *OPCUASubscription `json:"subscription,omitempty"`
    // —— 关闭 ——
    Close                bool             `json:"close,omitempty"`                 // 默认 true（贯通 CLO+TCP FIN）
}
```

`OPCUAService`（服务单步：nodeId + attributeId 等一个"调一次"的意图）：

```go
type OPCUAService struct {
    NodeIds     []strategy.Value        `json:"node_ids"`        // NodeId 复用现有 strategy.Value（§10.1）
    AttributeId uint32                  `json:"attribute_id,omitempty"` // 默认 13（Value）
}
```

`OPCUASubscription`：

```go
type OPCUASubscription struct {
    PublishingInterval   float64  `json:"publishing_interval_ms,omitempty"`   // 默认 1000
    LifetimeCount        uint32   `json:"lifetime_count,omitempty"`           // 默认 10000
    MaxKeepAliveCount    uint32   `json:"max_keep_alive_count,omitempty"`     // 默认 100
    PublishingEnabled    bool     `json:"publishing_enabled,omitempty"`       // 默认 true
    PublishCount         int      `json:"publish_count,omitempty"`            // Publish 周期数，默认 1
    PublishIntervalMs    int64    `json:"publish_interval_ms,omitempty"`      // 节流间隔，默认 1000
    KeepAlive            bool     `json:"keep_alive,omitempty"`               // 空转 keep-alive Publish
    MonitoredItems       []string `json:"monitored_nodes,omitempty"`          // 监视节点 NodeId
}
```

### 5.3 配置 JSON 形式与默认化

`strategy_convert.go` 的 `case "opcua"` 读取 `cfg["opcua"]` 子 map，调用 `parseOPCUAConfig(sub)` 生成 `*OPCUAConfig`。默认化规则：
- `security_mode` 缺省 → `none`；`sessions` 缺省 → 1；
- `close` 缺省 → true（若显式 `"close":false`，则停止在 CLO 前，不发关闭）；
- `read`/`write`/`browse`/`subscription` 全空时**至少产生一次 Read**（默认读 `ns=1;i=1001` Value），保证 session 尾部有业务载荷；
- 非法 `security_mode`（非 none/sign/signandencrypt）在 `Validate` 阶段报错（§9.5）。

### 5.4 校验（validate.go）

`ValidateOPCUAConfig` 检查：`security_mode` 枚举合法；`sessions ≥ 1`；`publishing_interval_ms ≥ 50`（若订阅启用）；`publish_count ≥ 1`（若订阅启用）；`publish_interval_ms ≥ 50`；nodeIds 非空且每个为 `ns=i=...` 或 `ns=s=...` 合法 NodeId 文本。错误返回 `[opcua] ...` 前缀。

### 5.5 默认化决策表（spec 行为清单）

| 配置项 | 未设置默认 | 影响 |
|--------|-----------|------|
| `security_mode` | `none` | 决定 PolicyUri 与签名/证书占位 |
| `sessions` | `1` | 多会话交错开关 |
| `close` | `true` | 是否发 CLO + TCP FIN |
| `read`/`write`/`browse` | 均空→至少 1 次 Read | 保证 S3 有业务载荷 |
| `subscription` | 无 | 无订阅则跳过 §4.4 |
| `request_handle_start` | `1000` | 请求处理手柄起点 |
| `sequence_start` | `1000` | SequenceNumber 起点 |
| `requested_lifetime` | `3600000` | OPN 里的生命周期毫秒 |
| `dst_port`（tcp 层） | `4840` | 四元组端口 |

### 5.6 完整 JSON 用例三例（与 testcase 文档 §2 逐字对应）

**T4 多节点 Read** 输入：

```json
{
  "strategy": { "type": "custom", "layers": ["tcp", "opcua"] },
  "spec": [
    { "tcp": { "dst_port": 4840, "initial_seq": 400000, "ack_seq": 1 } },
    { "opcua": {
        "security_mode": "none",
        "read": [
          { "node_ids": ["ns=0;i=1001", "ns=0;i=1002"], "attribute_id": 13 }
        ],
        "close": true
    } }
  ]
}
```

**T7 订阅周期** 输入：

```json
{
  "strategy": { "type": "custom", "layers": ["tcp", "opcua"] },
  "spec": [
    { "tcp": { "dst_port": 4840, "initial_seq": 700000 } },
    { "opcua": {
        "security_mode": "none",
        "subscription": {
          "publishing_interval_ms": 1000,
          "publish_count": 2,
          "publish_interval_ms": 1000,
          "monitored_nodes": ["ns=0;i=1001"]
        },
        "close": true
    } }
  ]
}
```

**T3 带签名** 输入：

```json
{
  "strategy": { "type": "custom", "layers": ["tcp", "opcua"] },
  "spec": [
    { "tcp": { "dst_port": 4840, "initial_seq": 300000 } },
    { "opcua": { "security_mode": "sign", "close": true } }
  ]
}
```

> 这三例与 testcase §2.4/§2.7/§2.3 的 `spec_json` 完全一致：实现后 `run_all_test.go` 用它们驱动生成，避免文档与用例「两套 spec」漂移。`strategy: custom` 仅示意终端用户入口，非 pcap 用例必需。

### 5.7 与 ENIP 终结层的差异点

| 维度 | ENIP（参照物） | OPC UA（本设计） |
|------|---------------|------------------|
| 承载 | TCP 44818 / UDP | TCP 4840（无 UDP） |
| 头部 | ENIP 报文头（Command/Length/Session） | MessageHeader（3ASCII+Chunk+Size） |
| 会话 | ENIP SessionHandle（UInt32） | UA 逻辑会话（AuthenticationToken NodeId） |
| 状态推进 | 每命令一个 plan 步骤 | 四阶段状态机（S1-S4）+ 订阅周期 |
| flat 键 | `spec.ENIP` | `spec.OPCUA` |
| 事件 | 每条命令一个包 | 服务调用 + 周期性 Publish 节流 |




---

## 6. 包序列场景（HexDump S1-Sn）

> 约定：包索引从 1 起**含 TCP 三次握手**（SYN=1、SYN-ACK=2、ACK=3）；`54` 为 TCP 载荷起点偏移（Eth14+IPv4 20+TCP 20）；所有多字节小端；带 `NA` 的为取决于配置的取值；`▸` 表示可配置变体。

### S1 传输层握手（HEL+ACK）

### S1 传输层握手（HEL+ACK）

#### S1R1 TCP 三次握手（包 1-3）

UA 消息之前必然先有 TCP 握手。`tcp.initial_seq` 可配置以锁定 ACK/seq 偏移，pcap 用例用 `HasHandshake` 做前置断言：

```
包 1  客户端 → 服务器   SYN：flags=0x002，seq=s0
包 2  服务器 → 客户端   SYN+ACK：flags=0x012，seq=r0+ack=s0+1
包 3  客户端 → 服务器   ACK：flags=0x010，seq=s0+1, ack=r0+1
```

> 三次握手 ts指标：tshark `tcp.flags.syn`=1（packet1-2）、`tcp.flags.ack`（packet3）等，见 §7 T1 的 `fields` 断言。真实对端若没回 SYN-ACK，`HasHandshake` 直接判 failure。

**包 4：HEL（客户端→服务器）**——MessageHeader 8B + 5×UInt32 + EndpointUrl（空串 4B）共 32B：

```
54  48 45 4c 46 20 00 00 00       'HEL' 'F' MessageSize=32（含空 EndpointUrl）
62  00 00 00 00                   ProtocolVersion=0
66  00 00 01 00                   ReceiveBufferSize=65536(0x00010000 LE)
70  00 00 01 00                   SendBufferSize=65536
74  00 00 00 00                   MaxMessageSize=0
78  00 00 00 00                   MaxChunkCount=0
7c  00 00 00 00                   EndpointUrl（长度 0 空串）
```

**包 5：ACK（服务器→客户端，回显，无 EndpointUrl——OPC UA Part 6 §7.1.2.4）**：

```
54  41 43 4b 46 1c 00 00 00       'ACK' 'F' MessageSize=28
62  00 00 00 00                   ProtocolVersion=0
66  00 00 01 00                   ReceiveBufferSize=65536
70  00 00 01 00                   SendBufferSize=65536
74  00 00 00 00                   MaxMessageSize=0
78  00 00 00 00                   MaxChunkCount=0
```
负载 20B；包长 Eth14+IP20+TCP20+20 = 74。

### S1R2 HEL 错误响应（ERR，负例）

服务器收到不匹配的 HEL 时回 `'ERR'`：`MessageSize=8+4+String`。示例（拒绝原因 "BadSequenceNumber"）：

```
54  45 52 52 46   …   'ERR' 'F' MessageSize=…
62  80 00 00 00        ErrorCode=BadDecodingError(0x80030000 截取见 §9.1)
66  … String           ErrorReason UTF-8
```

> testcase T13 用 `expect_error`+`error_contains:"ErrorCode"` 覆盖：生成端不产生 ERR，但**框架读包**时若 tshark 对 4840 无解码，会落到 FrameAssert 原始字节校验。


### S2 安全通道打开（OPN request/response）

#### S2R1 完整 OPN 请求 HexDump（SecurityMode=None，逐字节）

假设 `SequenceNumber=0x00010001`、`RequestId=0x00010002`、`RequestedLifetime=3600000`、`ClientNonce`=32 字节均 `0x11`。None 策略 URI=70 字节。正文字段：

```
偏移   内容                                    注释
54   4f 50 4e 46                               'OPN' 'F'
58   9a 00 00 00                               MessageSize=154（0x9A）
62   00 00 00 00                               SecureChannelId=0
66   46 00 00 00                                PolicyUri Len=70（0x46）
6a   6f 70 63 2e 74 63 70 3a 2f 2f 6f 70…     URI = "opc.tcp://opcfoundation.org/UA/SecurityPolicy#None"
      （共 70 字节：6f 70 63 2e 74 63 70 3a 2f 2f
        6f 70 63 66 6f 75 6e … / S e c u r i t y P o l i c y # N o n e）
…   ff ff ff ff                               SenderCertificate=null
…   ff ff ff ff                               ReceiverCertificateThumbprint=null
…   01 00 01 00                               SequenceNumber=0x00010001（LE）
…   02 00 01 00                               RequestId=0x00010002（LE）
…   01 00 00 00                               ClientProtocolVersion=1
…   00 00 00 00                               RequestType=0（Issue）
…   01 00 00 00                               SecurityMode=1（None）
…   20 00 00 00                               ClientNonce Len=32
…   11 11 11 11 …（32 次）                    ClientNonce
…   80 ee 36 00                               RequestedLifetime=3600000（0x0036EE80 LE）
```

> 合计：8（消息头）+4（SecureChannelId）+4（PolicyUri 长度）+70（URI）+4（SenderCert null）+4（Thumbprint null）+8（SequenceHeader）+4（ClientProtocolVersion）+4（RequestType）+4（SecurityMode）+4（ClientNonce 长度）+32（ClientNonce）+4（RequestedLifetime）= **154**=0x9A，与 MessageSize 一致。真实生成时长度由两遍编码回填，这里数值仅示教。

#### S2R2 OPN 响应（SecurityMode=None）

```
54   4f 50 4e 46                               'OPN' 'F'
58   c6 00 00 00                               MessageSize=198（0xC6）
62   01 00 00 00                               SecureChannelId=1
66   46 00 00 00                               PolicyUri Len=70
6a   6f 70 63 2e 74 63 70…                    URI（70B）
…   ff ff ff ff                               SenderCertificate=null
…   ff ff ff ff                               ReceiverCertificateThumbprint=null
…   ...4B SequenceNumber                      （服务端递增空间）
…   ...4B RequestId
…   01 00 00 00                               ClientProtocolVersion=1
…   01 00 00 00                               ServerProtocolVersion=1
…   01 00 00 00                               SecureChannelId（SecurityToken 内）=1
…   e8 03 00 00                               TokenId=1000（0x03E8）
…   ...8B DateTime                            CreatedAt（生成时刻）
…   80 ee 36 00                               RevisedLifetime=3600000
…   40 00 00 00                               ServerNonce Len=64
…   11 11 …（64 次）                          ServerNonce
```

> 响应里的 TokenId=1000 是**对称段的 SecurityTokenId**（偏移 12）。测试点要断言：`FrameAssert(包7, 62, "01 00 00 00")` + `FrameAssert(包6, 62, "00 00 00 00")` 的通道 ID 从 0→1 的转变，或直接断言包 8 偏移 62 处 `e8 03 00 00`。


### S3 服务调用（Read / Write / Browse）

**包 8：Read（'MSG','F'，对称段）**——8 消息头 + 4 SecureChannelId + 4 TokenId + 8 SequenceHeader + RequestHeader：

```
54  4d 53 47 46 <size>             'MSG' 'F'
62  01 00 00 00                    SecureChannelId=1
66  e8 03 00 00                    SecurityTokenId=1000(0x03E8)
6a  … 4B … 4B                     SequenceNumber(4B) + RequestId(4B)
6e  （RequestHeader：）
…  00                              AuthenticationToken=TwoByte NodeId 0（无会话）▸ ns=1;i=1001
…  …Timestamp(8B DateTime)…
…  01 00 00 00                    RequestHandle=1
…  00 00 00 00                    ReturnDiagnostics=0
…  ff ff ff ff                    AuditEntryId=null
…  10 27 00 00                    TimeoutHint=10000
…  00 00                          AdditionalHeader=null ExtensionObject（2B）
…  （ReadRequest 正文）：
…  00 00 00 00                    MaxAge=0
…  00 00 00 00                    TimestampsToReturn=0(Neither)
…  01 00 00 00                    NodesToRead Len=1
…  …  01 00 e9 03                ReadValueId: NodeId FourByte ns=0 id=1001(0x03E9)
…  …  0d 00 00 00                AttributeId=13(Value)
…  …  ff ff ff ff                IndexRange=null
…  …  00 00                      DataEncoding QualifiedName（ns=0 + name null 见下注）
```
> DataEncoding（QualifiedName）为 null 的线上形式：`00`（namespaceIndex）+ `ff ff ff ff`（name String null）＝ 5 字节。

**包 9：Read 响应（'MSG','F'）**：`ResponseHeader(Timestamp+RequestHandle回显+ServiceResult=0+DiagnosticInfo null 1B+StringTable null+AdditionalHeader null)` + `Results: DataValue[]（Len=1 + DataValue(掩码 0x01→Variant Int32 值 4B)）`。

#### S3R1 完整 Read 请求 HexDump（单 NodeId，逐字节）

前提：`SequenceNumber=0x00010003`、`RequestId=0x00010004`、RequestHandle=1、NodeId=`ns=0;i=1001`（FourByte）、AttributeId=13、无会话（AuthToken=TwoByte 0）、Timestamp 用生成时刻：

```
54  4d 53 47 46                               'MSG' 'F'
58  xx 00 00 00                               MessageSize（回填）
62  01 00 00 00                               SecureChannelId=1
66  e8 03 00 00                               SecurityTokenId=1000
6a  03 00 01 00                               SequenceNumber=0x00010003
6e  04 00 01 00                               RequestId=0x00010004
72  00 00                                     AuthToken = TwoByte NodeId 0，id=0（无会话；TwoByte = 掩码 `00` + 标识符 `00`）
74  … 8B                                      Timestamp（DateTime 100ns）
7c  01 00 00 00                               RequestHandle=1
80  00 00 00 00                               ReturnDiagnostics=0
84  ff ff ff ff                               AuditEntryId=null
88  10 27 00 00                               TimeoutHint=10000
8c  00 00                                     AdditionalHeader=null（NodeId0 + encoding0）
8e  00 00 00 00                               MaxAge=0
92  00 00 00 00                               TimestampsToReturn=0（Neither）
96  01 00 00 00                               NodesToRead Len=1
9a  01 00 e9 03                               ReadValueId.NodeId（FourByte ns0 id=1001）
9e  0d 00 00 00                               AttributeId=13（Value）
a2  ff ff ff ff                               IndexRange=null
a6  00 ff ff ff ff                            DataEncoding=QualifiedName null
（至此载荷 = 8（消息头）+4（SecureChannelId）+4（TokenId）+8（SequenceHeader）+2（AuthToken TwoByte）+8（Timestamp）+4（RequestHandle）+4（ReturnDiagnostics）+4（AuditEntry）+4（TimeoutHint）+2（AdditionalHeader）+4（MaxAge）+4（TimestampsToReturn）+4（NodesToRead 长度）+4（NodeId）+4（AttributeId）+4（IndexRange）+5（DataEncoding）= **81** 字节；整帧从偏移 54 起 → 帧尾 ≈ 135）
```

> 单条 Read 的载荷总长 = **80 字节**（§3.5 / S3R1 列表），加上前导 54 → 整帧 ≥ 134；MessageSize 由回填得到。测试点 T4 可 `FrameAssert(包8, 0x62, "e8 03 00 00")` 验证 TokenId 从 OPN 响应复用。


**包 10（写）：Write（'MSG','F'）**：`RequestHeader + NodesToWrite Len=1 + WriteValue(NodeId + AttributeId=13 + IndexRange=null + Value=DataValue(掩码0x01 + Variant typeId 6=Int32 + 值))`。响应为 WriteResponse `Results UInt32[]（Good=0）+ DiagnosticInfos[]`。

**包 11（浏览）：Browse（'MSG','F'）**：`RequestHeader + View(null)+RequestedMaxReferencesPerNode=1000+NodesToBrowse Len=1 + BrowseDescription(NodeId + BrowseDirection=0(Forward)+ReferenceTypeId=TwoByte 0+IncludeSubtypes=true→01 + NodeClassMask=0 + ResultMask=0x3F)`。

### S5 完整订阅周期（CreateSubscription →Notification →CLO）

```
包 12 CreateSubscription（MSG 对称）：RequestHeader + PublishingInterval=1000.0(Double LE 8B)
        + LifetimeCount=10000 + MaxKeepAlive=100 + MaxNotificationsPerPublish=0 + PubEnabled=true(01) + Priority=00
包 13 响应（含 RevisedPublishingInterval）
包 14 CreateMonitoredItems：RequestHeader + SubscriptionId=1 + TimestampsToReturn=0
        + ItemsToCreate Len=1 + (ItemToMonitor ReadValueId + MonitoringMode=1 + MonitoringParameters)
包 15 响应
包 16 SetPublishingMode(true, [1]) + 包 17 响应
包 18 Publish + 包 19 响应（NotificationMessage/DataChange：Value(Variant Int32) + Status(Good) + SequenceNumber）
包 20 Publish（keep-alive 空转 ▸）+ 包 21 响应
包 22 CLO(CloseSecureChannelRequest, 非对称 MessageType='CLO')
包 23 FIN / 24 FIN-ACK / 25 ACK
```

> **CLO 无响应（OPC UA Part 4 §5.13.3）**：CloseSecureChannel 是**单向服务**——客户端发送请求后服务器直接关闭 TCP 连接，没有 CLO 响应消息。上述序列已据此建模：CLO 后直接 FIN。
> 该完整序列固定 `publish_count=2`（一个数据通知 + 一个 keep-alive）占 **25 包**。单次 Publish 且无 keep-alive 时减为 23 包。

### S6 keep-alive（订阅空转）

SecurityMode None 下的 Publish 周期：`包 16 Publish → 包 17 响应（无 Notification，SequenceNumber 不变）`，间隔不推进计数。测试点只断言包数与 PublishRequest 存在（FrameAssert 'Publish' 消息头/Sequence 递增）。

### S6R1 keep-alive 时序表（Subscription KeepAlive）

`max_keep_alive_count=100`、`publish_count=3` 时（含 data publish + 2 keep-alive）：

| 包 | 方向 | 消息 | Notification 携带 | SequenceNumber |
|----|------|------|------------------|----------------|
| 18 | 客户端 | PublishRequest | – | 不变 |
| 19 | 服务器 | PublishResponse/DataChange | Value Int32（递增） | +1 |
| 20 | 客户端 | PublishRequest（keep-alive）| – | 不变 |
| 21 | 服务器 | PublishResponse keep-alive | 无 Notification | 不变 |
| 22 | 客户端 | PublishRequest（keep-alive）| – | 不变 |
| 23 | 服务器 | PublishResponse keep-alive | 无 Notification | 不变 |

> keep-alive 的判定点在"**响应没有 NotificationMessage 且计数不递增**"。帧断言用 `FrameAssert(包19/包21, 54, "4d 53 47 46 …")` 只做 MessageHeader 前缀匹配，通知序列号差异用 `nonzero` 字段或相对断言。


### S7 错误注入（UA 状态错误 + 负例）

| 场景 | 服务 | ServiceResult |
|------|------|---------------|
| BadNodeIdUnknown | Read 请求带非法 NodeId `ns=1;i=9999` → 响应 ServiceResult | `0x80340000`（LE `00 00 34 80`） |
| BadUserAccessDenied | Write 到只读节点 → 响应 ServiceResult | `0x801F0000`（LE `00 00 1f 80`） |

负例（expect_error 生效）：HEL 里 MessageSize 故意写小/错位（`00 00 00 00` 匹配不进），`packet_count`/`has_payload` 不全通过 → 引擎按 `expect_error`/`error_contains` 判定。

### S8 多会话（sessions>1）

`session_count=3, Read=3` 时，握手 OPN 连续完成后，`会话A Read → 会话B Read → 会话C Read` 用不同 AuthenticationToken 交错；RequestHandle 空间独立（A 用 1xx、B 用 2xx、C 用 3xx）。

### S8R1 多会话时序表

| 包 | 会话 | 方向 | 消息 | AuthenticationToken | RequestHandle |
|----|------|------|------|--------------------|---------------|
| 4 | – | 客户端 | HEL | – | – |
| 5 | – | 服务器 | ACK | – | – |
| 6 | – | 客户端 | OPN（通道级） | – | 1000 |
| 7 | – | 服务器 | OPN 响应（TokenId 1000） | – | 1000 |
| 8 | A | 客户端 | Read（SessionA） | ns=1;i=4001 | 1001 |
| 9 | A | 服务器 | Read 响应 | – | 1001 |
| 10 | B | 客户端 | Read（SessionB） | ns=1;i=4002 | 2001 |
| 11 | B | 服务器 | Read 响应 | – | 2001 |
| 12 | C | 客户端 | Read（SessionC） | ns=1;i=4003 | 3001 |
| 13 | C | 服务器 | Read 响应 | – | 3001 |
| 14 | – | 客户端 | CLO | – | 4001 |
| 15-16 | – | 客户端/服务器 | FIN / FIN-ACK / ACK | – | – |

> **CLO 无响应**：CloseSecureChannel 是单向服务（OPC UA Part 4 §5.13.3），无 CLO 响应消息。CLO 后直接 FIN。

> 会话级 NodeId（AuthenticationToken）用 `ns=1;i=40NN`（四字节 NodeId），与 Read 用 `ns=1;i=10NN` 区分，便于 FrameAssert 偏移区分。RequestHandle 空间按会话起始（`request_handle_start` + 会话索引偏移）。


### 6.1 包索引速查表

| 场景 | 包 4 | 5 | 6 | 7 | 8+ | 末段 |
|------|-----|---|---|---|----|------|
| S1 仅握手 | HEL | ACK | – | – | – | CLO 包 6 + FIN 7-8 |
| S2 OPN | HEL | ACK | OPN 请求 | OPN 响应 | 关闭 CLO 包 8 | FIN 包 9-11 |
| S3 Read | HEL | ACK | OPN | OPN 响应 | Read 8 / Read 响应 9 | CLO 包 10 + FIN 11-13 |
| S5 订阅 | HEL | ACK | OPN | OPN 响应 | 订阅服务 12-21 | CLO 22 + FIN 23-25 |

---

## 7. 与 testcase 文档的映射索引

testcase 文档（25-opcua-testcase.md）逐用例引用本文 § 小节，推荐顺序覆盖矩阵：

| testcase ID | 设计章节 | 覆盖点 |
|-------------|----------|--------|
| T1 opcua_hello_ack | §3.2、§6 S1 | HEL/ACK 传输层握手、HEL MessageSize=32（含空 EndpointUrl）/ ACK 28 |
| T2 opcua_open_none | §4.2、§6 S2 | OPN None 模式、非对称头、TokenId 复用 |
| T3 opcua_open_sign | §4.2、§6 S2 | OPN Sign 模式（占位签名+证书结构） |
| T4 opcua_read | §3.4、§6 S3 | Read 多 NodeId、ResponseHeader 回显 |
| T5 opcua_write | §3.4、§6 S3 | Write 单节点、UInt32[] 结果 |
| T6 opcua_browse | §3.4、§6 S3 | Browse 单节点、NodeClassMask/ResultMask |
| T7 opcua_subscribe | §4.4、§6 S5 | CreateSubscription+Monitored+SetPubMode+Publish |
| T8 opcua_keepalive | §4.4、§6 S6 | keep-alive 空转 Publish |
| T9 opcua_bad_node | §9.1、§6 S7 | BadNodeIdUnknown 0x80340000 |
| T10 opcua_denied | §9.2、§6 S7 | BadUserAccessDenied 0x801F0000 |
| T11 opcua_ipv6 | §6 S2/S3、§8.4 | IPv6 承载下的 OPN+Read |
| T12 opcua_multi_session | §4.5、§6 S8 | sessions>1 交错遍历 |
| T13 opcua_bad_size_neg | §9.3、§6 S7 | 负例：HEL MessageSize 错位 → expect_error |
| T14 opcua_no_channel_neg | §9.4、§6 S7 | 负例：未建通道即 Read → expect_error |

---

## 8. 实现集成点

### 8.1 层注册

- `trafficgen/internal/core/layers/registry.go`：`r.Register(LayerSchema{Name:"opcua", Category:CategoryTerminal, DependsOn:[]string{"tcp"}, ...})`——与 enip 同一模式（对 4840 端口透明的 tcp 终结层）。
- 默认端口：`dst_port` 缺省取 **4840**；经 `tcp` 层携带（`tcp.dstport`）。

### 8.2 生成器内部结构（internal/protocol/opcua/opcua.go）

```
planOpcuaSession(meta)  → 逐阶段 yield []PlannedPacket
 ├─ emitHEL()
 ├─ emitOPN(opnReq)     → buildOpenSecureChannelRequest（非对称）
 ├─ emitService(services)  → buildReadRequest / buildWriteRequest / buildBrowseRequest（对称）
 ├─ emitSubscription()  → CreateSubscription / CreateMonitoredItems / SetPublishingMode / Publish loop
 └─ emitClose()         → CloseSecureChannelRequest + FIN
```

#### 8.2.1 核心编码器签名（伪 Go）

```go
// uaBuffer 是小端写库，所有 Put* 均为 LE。
type uaBuffer struct{ b []byte }
func (w *uaBuffer) PutUInt16(v uint16) { ... }
func (w *uaBuffer) PutUInt32(v uint32) { binary.LittleEndian.PutUint32(...) }
func (w *uaBuffer) PutInt32(v int32)   { ... }
func (w *uaBuffer) PutInt64(v int64)   { ... }
func (w *uaBuffer) PutDouble(v float64) { binary.LittleEndian.PutUint64(math.Float64bits(v), ...) }

// 长度前缀的类型型（String/ByteString/数组）
func (w *uaBuffer) PutString(s string)          { if null { w.PutInt32(-1) } else { w.PutInt32(len); w.b=append(w.b, s...) } }
func (w *uaBuffer) PutStringNull()              { w.PutInt32(-1) }
func (w *uaBuffer) PutByteStringNull()          { w.PutInt32(-1) }
func (w *uaBuffer) PutArrayLen(n int)           { w.PutInt32(int32(n)) }  // 0=空，-1=null

func (w *uaBuffer) PutNodeId(n NodeId) {
    // TwoByte/FourByte/Numeric/String/Guid 依据 §2.8 掩码 0x00..0x05
}
func (w *uaBuffer) PutMessageHeader(msgType [3]byte, chunk byte) {
    w.b=append(w.b, msgType[:]...); w.b=append(w.b, chunk); w.PutUInt32(0) // 占位 MessageSize
}
func (w *uaBuffer) FinalizeMessageSize(start int) {
    binary.LittleEndian.PutUint32(w.b[start+4:], uint32(len(w.b)-start))
}
```

#### 8.2.2 两遍编码示例：HEL

```go
func buildHello(cfg *OPCUAConfig) []byte {
    b := make([]byte, 0, 28)
    w := &uaBuffer{b: b}
    w.PutMessageHeader([3]byte{'H','E','L'}, 'F')   // 占位 size（4B）
    w.PutUInt32(0)                                  // ProtocolVersion
    w.PutUInt32(65536)                              // ReceiveBufferSize
    w.PutUInt32(65536)                              // SendBufferSize
    w.PutUInt32(0)                                  // MaxMessageSize
    w.PutUInt32(0)                                  // MaxChunkCount
    w.FinalizeMessageSize(0)                        // -> 28
    return w.b
}
```

#### 8.2.3 真实 JSON 用例（testcase 能引用）

```json
{
  "opcua": {
    "security_mode": "none",
    "read": [{ "node_ids": ["ns=1;i=1001", "ns=1;i=1002"], "attribute_id": 13 }],
    "close": true
  },
  "tcp": { "dst_port": 4840, "initial_seq": 1000 }
}
```

订阅类：

```json
{
  "opcua": {
    "security_mode": "none",
    "subscription": {
      "publish_count": 2,
      "publish_interval_ms": 1000,
      "monitored_nodes": ["ns=1;i=1001"]
    }
  },
  "tcp": { "dst_port": 4840 }
}
```

- **两遍编码**：`uaBuffer` 先写全部字段（小端），最后在偏移 4 回填 `MessageSize`；
- **SequenceNumber/RequestId**：各自独立递增（SequenceStart/RequestStart 可配，默认 1000）；
- **状态字段**：`SecureChannelId`/`TokenId` 由 OPN 阶段写入连接上下文（`UAConnectionState`），供后续对称段引用；
- 每包 `Direction`：请求=客户端方向、注入的响应=服务器方向（`autoResponse`）。


### 8.3 策略层

- `strategy_convert.go`：新街 `case "opcua"` 解析 `cfg["opcua"]` → `parseOPCUAConfig` → `spec.OPCUA`（`FlowSpec.OPCUA *OPCUAConfig json:"opcua,omitempty"`）。
- `validate.go`：`ValidateOPCUAConfig`（§5.4）。

### 8.4 L3 承载体（IPv4/IPv6）

终结层不关心 IP 版本；`ipv4`/`ipv6` 由上游层提供。IPv6 下 TCP 载荷偏移为 **74**（Eth14 + IPv6 40 + TCP 20）——pcap 用例的 FrameAssert offset 需随 `ip.version` 切换：IPv4→54、IPv6→74。

### 8.5 自动响应（autoResponse）

`autoResponse:true`（pcap 测试默认）时，客户端侧的**响应包**（ACK/OPN 响应/各 Service 响应/CLO 响应）由生成器按模板回灌：Handler 维持 `ResponseHandle = RequestHandle` 回显，ServiceResult 按配置（S7）好/坏。真实服务器场景 `autoResponse:false` 时只生成客户端方向请求。

---

## 9. 错误处理

### 9.1 UA 状态码（StatusCode）

StatusCode 是 UInt32；**最高位 bit31（0x80000000）= Bad、bit30 = Uncertain、bit29 = 保留**。语义按服务分段。本设计使用两个常用坏码（来自官方 StatusCode.csv）：

| 名称 | 值 | 场景 |
|------|-----|------|
| Good | 0x00000000 | 成功 |
| BadUserAccessDenied | 0x801F0000 | Write 到无权限节点（T10） |
| BadNodeIdUnknown | 0x80340000 | Read/Browse 到未知 NodeId（T9） |
| BadSecurityModeRejected | 0x80890000 | 负例：SecurityMode 非法（可配触发） |
| BadSecureChannelIdInvalid | 0x80870000 | 负例：未建通道即服务调用（T14） |

### 9.2 生成端错误注入

`error_inject` 配置段（§5.2）用 `{op:"bad_node", node:"ns=1;i=9999"}` / `{op:"denied"}` 在对应服务**响应**中置 ServiceResult。请求仍结构完整；断言只在响应包上抓 StatusCode。

### 9.3 负例：错误字节（expect_error）

`bad_message_size:true` → HEL 的 MessageSize 字段写错（如 `00 00 00 05`）；`bad_length:true` → 某个 ByteString/String 长度前缀越界。此时**整条消息字节仍是完备的**（MessageSize 与正文一致），但 pcap 用例的 `expect_error`+`error_contains`（如 `"MessageSize"` / `"invalid length"`）在 tshark/FrameAssert 校验阶段捕获告警。这类用例故意不满足 `packet_count`/`has_payload`，靠负例判定。

### 9.4 负例：未建通道即服务调用

配置 `skip_channel:true` → 跳过 OPN，直接发 Read；生成器在 `MessageSize` 上仍合法，但 `Terminates=false`（无 CLO）。`expect_error` 配合 `secureChannelIdInvalid` 断言语义。

### 9.5 配置校验错误表

| 错误 | 触发 | 处理 |
|------|------|------|
| `invalid security_mode: %s` | 非 none/sign/signandencrypt | Validate 拒绝 |
| `sessions must be >= 1` | sessions<1 | Validate 拒绝 |
| `publishing_interval_ms must be >= 50` | 订阅启用且 <50 | Validate 拒绝 |
| `publish_count must be >= 1` | 订阅启用且 <1 | Validate 拒绝 |
| `publish_interval_ms must be >= 50` | 订阅启用且 <50 | Validate 拒绝 |
| `malformed node id %q` | NodeId 文本非法 | Validate 拒绝 |

### 9.6 错误注入全流程（S7R1 walkthrough）

以 T9（BadNodeIdUnknown）为例，`error_inject` 在 Read 响应注入：

1. 生成器按 S3 正常走：HEL→ACK→OPN→OPN 响应→Read 请求；
2. Read 请求的 NodeId 从配置 `error_inject.node="ns=1;i=9999"` 覆盖（`ns=1` → Numeric NodeId，`01 00` ns + `0f 27 00 00` id）；
3. 生成器密记该请求句柄；**响应包**的 ResponseHeader.ServiceResult 写 `0x80340000`；
4. 响应包的 Results DataValue 掩码 `0x03`（值+状态），Status=0x80340000（LE `00 00 34 80`）；
5. testcase T9 用 `FrameAssert` 在响应包偏移抓 ServiceResult=`00 00 34 80`，同时 `expect` 的 `packet_count` 保持完整（错误只在应用状态层面）。

### 9.7 负例错误处理表（expect_error 语义）

| 用例 | 错误字节注入 | pcap 断言结果 | error_contains 关键词 |
|------|--------------|---------------|------------------------|
| T13 坏消息大小 | HEL MessageSize=`00 00 00 05` | 不匹配 size=28 的前缀 / 长度超越帧尾 | `MessageSize` |
| T13b 坏长度 | String 长度前缀 > 剩余 | tshark 解码告警 | `invalid length` |
| T14 无通道服务 | 跳过 OPN 直发 Read，无 CLO，无 FIN | 包数偏少 / Terminates=false | `secureChannelIdInvalid` |

> 负例**不应当**当作"生成失败"处理：字节本身结构完整、能发出；只是**不符合协议语义**。验证层在 `expect_error` 分支把 tshark 告警 / FrameAssert 偏移越界转成"用例预期失败"而非引擎失败。

### 9.8 状态级错误（生成器内部）与用户可观测错误

生成器内部若出现不变量被破坏（如 `MessageSize` 算出的长度与 buffer 不一致、`SecurityTokenId` 在对称段前未知），记 `fatal` 引擎错误（沿用引擎 0-packet 守卫，见 memory）。用户侧可观测错误一律走 `expect_error`/`error_contains`，与真实服务器不参与时的降级方式一致。


---

## 10. 扩展字段映射

### 10.1 NodeId 文本 → 线格式

NodeId 在配置中用文本 `ns=<ns>;i=<id>` 或 `ns=<ns>;s=<str>`：
- `ns=0;i=NNN`（NNN≤255）→ **TwoByte**（掩码 `00` + 1B id）；
- `ns=0;i=NNN`（255<NNN≤65535）→ **FourByte**（掩码 `01` + `00` + 2B LE）；
- `ns=i=NNN*` 其余 → **Numeric**（掩码 `02` + ns UInt16 LE + id UInt32 LE）；
- `ns=N;s=Name` → **String**（掩码 `03` + ns UInt16 LE + String）。

### 10.2 AttributeId 表（官方 UA-.NETStandard Attributes.cs）

| 值 | 名称 | 值 | 名称 |
|----|------|----|------|
| 1 | NodeId | 15 | ValueRank |
| 2 | NodeClass | 17 | AccessLevel |
| 3 | BrowseName | 18 | UserAccessLevel |
| 4 | DisplayName | 19 | MinimumSamplingInterval |
| 5 | Description | 20 | Historizing |
| 6 | WriteMask | 21 | Executable |
| 7 | UserWriteMask | 22 | UserExecutable |
| 8 | IsAbstract | 23 | DataTypeDefinition |
| 9 | Symmetric | 27 | AccessLevelEx |
| 12 | EventNotifier | 13 | Value（默认） |

### 10.3 NodeClass 掩码

Object=1、Variable=2、Method=4、ObjectType=8、VariableType=16、ReferenceType=32、DataType=64、View=128。Browse 的 `node_class_mask` 例 `7` = Object|Variable|Method。

### 10.4 枚举映射表

| 枚举 | 值 | 备注 |
|------|-----|------|
| MessageSecurityMode | 0=Invalid,1=None,2=Sign,3=SignAndEncrypt | Int32 |
| SecurityTokenRequestType | 0=Issue,1=Renew | Int32 |
| TimestampsToReturn | 0=Neither,1=Server,2=Source,3=Both | Int32 |
| BrowseDirection | 0=Forward,1=Inverse,2=Both | Int32 |
| MonitoringMode | 0=Disabled,1=Sampling,2=Reporting | Int32 |
| FilterOperator | 0=Equals,… | 本设计未用 |
| NodeClass | 见 §10.3 | 掩码 UInt32 |

### 10.5 常量速查（open62541 对齐）

| 常量 | 值 |
|------|-----|
| MESSAGEHEADER_LENGTH | 8 |
| CHANNELHEADER_LENGTH | 12 |
| SEQUENCEHEADER_LENGTH | 8 |
| SYMMETRIC_SECURITYHEADER_LENGTH | 4 |
| OA_UA_ENCODING 默认端口 | 4840 |
| DateTime 0=1601-01-01 基准 | Int64 100ns |

---

## 11. 修订记录

| 版本 | 日期 | 作者 | 变更 |
|------|------|------|------|
| v1.0.0 | 2026-08-18 | 生成器子代理 | 初稿；线格式事实对齐 open62541/node-opcua/OPC Foundation（消息头 MessageSize 小端、服务 NodeId 表、StatusCode、AttributeId） |

### 附录 A：术语对照表

| 英文（中文解释） | 首现 |
|------|------|
| OPC Unified Architecture（OPC 统一架构） | §1.1 |
| address space（地址空间） | §1.1 |
| information model（信息模型） | §1.1 |
| SOA（服务导向架构） | §1.1 |
| transport layer（传输层）/session（会话）/application（应用） | §1.2 |
| secure channel（安全通道）/token（令牌） | §1.2 |
| Subscription（订阅）/Publish（发布） | §1.5、§4.4 |
| keep-alive（保活） | §4.4 |
| final block（最终块）/'F' chunk | §3.5 |
| autoResponse（自动响应回灌） | §8.5 |
| SecurityMode（安全模式） | §1.5 |
| NodeClass（节点类） | §10.3 |
| StatusCode（状态码） | §9.1 |

> 注：文中以（中文解释）标识的英文术语，均在**首次出现**处贴拼音/解释。正文其余位置不再重复挂号。
