# SMB2/SMB3 协议设计与测试用例

**协议名称**：SMB2 / SMB3（Server Message Block v2 / v3，服务器消息块 v2/v3，MS-SMB2）
**默认端口**：TCP 445（Direct TCP，直连 TCP），可选 139（NetBIOS Session Service，NBSS 会话服务）
**规范来源**：MS-SMB2（[MS-SMB2] Microsoft Open Specifications，§2.2 / §3.x）
**项目状态**：未实现（见 `docs/protocol-designs/00-unimplemented-list.md` #7）
**文档版本**：v2.1.0（2026-08-05）
**目标**：为 trafficgen 增加 SMB2/SMB3 流量生成能力，覆盖协商、认证、树连接、文件 I/O、目录枚举、断开会话全流程；不实现真正的签名/加密算法（生成占位字段）。

---

## 目录

1. [协议概述](#1-协议概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景（HexDump S1-S15）](#6-包序列场景hexdump-s1-s15)
7. [测试用例](#7-测试用例)
8. [Validate 规则](#8-validate-规则)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## §1. 协议概述

SMB（Server Message Block，服务器消息块）是局域网文件/打印共享的事实标准协议。SMB1 由 IBM/Microsoft 在 1980 年代设计，由于安全与性能缺陷（如 EternalBlue CVE-2017-0144），Microsoft 在 Windows Vista/Server 2008 引入 SMB2（dialect 0x0202 起算），并在 Windows 8/Server 2012 引入 SMB3（dialect 0x0300 起算）。本设计支持的全部 5 个 dialect：0x0202 (SMB2.002)、0x0210 (SMB2.1)、0x0300 (SMB3.0)、0x0302 (SMB3.0.2)、0x0311 (SMB3.1.1)。SMB2/SMB3 统称 "SMB2"，header 与 PDU 结构一致，差别仅在 dialect 与新增能力（加密、多通道、持久句柄、目录租赁）。

### 1.1 在 trafficgen 中的定位

SMB 是 **会话级协议（session-level protocol）**：一条 TCP 连接（4-tuple）承载完整的会话生命周期——协商、认证、树连接、文件操作、断开。这与 FTP/SOCKS5/RTSP 同类，区别在于：

- **命令链长**：完整会话至少 7 对请求/响应（1 轮认证：NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/CLOSE/TREE_DISCONNECT/LOGOFF），默认 NTLM 三阶段为 10 对（见 §4.4），多于 FTP 的 USER/PASS/SYST/QUIT 4 对。
- **二进制 PDU**：不像 FTP/RTSTP 的文本行，SMB2 是固定头（64 字节）+ 命令体二进制结构。
- **NetBIOS 前缀**：Direct TCP 模式（端口 445）每条 SMB2 PDU 前 4 字节 NBSS session 头（type=0x00 session message + 3 字节长度）。
- **状态依赖**：SessionId/TreeId/FileId 在会话内递增分配，后续命令必须复用前序响应分配的 ID。
- **认证复杂**：SESSION_SETUP 携带 GSS-API/SPNEGO blob，trafficgen 只生成占位（NTLM/Kerberos 真实加密不实现）。
- **方向标识**：SMB2 头 Flags 字段 bit0（SMB2_FLAGS_SERVER_TO_REDIR）标识响应方向，区别于 LDAP/VNC 的纯时序区分。

### 1.2 与已实现协议的关系

- 继承 **FTP/SOCKS5 的 TCP 会话模型**：3-way 握手 → 信令 PDU 序列 → 4-way 挥手；每个 PDU 作为一段 PSH-ACK 负载，MSS 超长分段。
- 借鉴 **LDAP/VNC 的二进制 PDU 构造**：固定头 + 命令体表驱动；字段名沿用 MS-SMB2 文档术语（StructureSize/CreditCharge/MessageId 等）。
- 借鉴 **RDP 的 dialects 协商模式**：NEGOTIATE 类似 RDP 的 RDP_NEG_REQ，dialects 列表协商选定版本。
- **关键差异**：SMB2 头有 Command + Flags 字段标识响应方向，LDAP/VNC 无此字段；SMB 响应包通过 Flags bit0（SERVER_TO_REDIR）标识方向。

### 1.3 不实现的能力

| 能力 | 原因 |
|------|------|
| 真正的 AES-CCM/GCM 加密 | 需要密钥派生（KDF）+ 完整 SMB3 加密上下文；超出流量生成范畴 |
| 真正的 HMAC-SHA256 签名 | 同上，需要会话密钥 |
| NTLM/Kerberos 真实认证 | 需要 NTLM hash / Kerberos 票据；SESSION_SETUP SecurityBlob 用占位字节 |
| 多通道（Multichannel） | 需要 RDMA / 多 NIC 协调；trafficgen 只模拟单 TCP 通道 |
| 持久句柄（Persistent Handle） | 需要集群上下文；占位字段即可 |
| 目录租赁（Directory Leasing） | 需要服务端状态机；不实现 |
| SMB1（dialect 字符串 "NT LM 0.12"） | 已废弃，CVE 频发；只支持 SMB2+（dialect 数值 0x0202 起） |
| NetBIOS 名字服务（NBNS） | 与 SMB2 数据面无关 |
| SMB over QUIC | 仅生成 TCP 承载 |
| SMB2 ASYNC 头（Flags bit1 ASYNC_COMMAND） | 仅在异步命令时使用，本设计不实现异步命令 |
| Compounded 请求（NextCommand 字段非零） | 链式命令需服务端状态机协调；每 PDU 单命令 |

### 1.4 关键术语（gloss 中文解释）

- **Dialect（方言）**：SMB 协议版本号，0x0202=SMB2.002、0x0210=SMB2.1、0x0300=SMB3.0、0x0302=SMB3.0.2、0x0311=SMB3.1.1。
- **Credit（信用）**：服务端授予客户端的发送配额；CreditCharge 是请求消耗的信用数，CreditRequest/CreditResponse 是请求/授予数，CreditBalance 是当前余额。
- **Command（命令码）**：SMB2 头偏移 12-13 的 uint16 LE（小端），标识命令类型（NEGOTIATE=0x0000 ... OPLOCK_BREAK=0x0012）。
- **Flags（标志位）**：偏移 16-19 的 uint32 LE，bit0=SMB2_FLAGS_SERVER_TO_REDIR（响应标志）、bit1=SMB2_FLAGS_ASYNC_COMMAND（异步命令）、bit2=SMB2_FLAGS_RELATED_OPERATIONS（链式相关）、bit3=SMB2_FLAGS_SIGNED（已签名）。
- **CreditRequest/Response（信用请求/授予）**：偏移 14-15 的 uint16 LE，请求方填请求授予数，响应方填授予数。
- **MessageId（消息号）**：会话内单调递增的命令序号；响应对应请求的 MessageId。
- **SessionId（会话号）**：SESSION_SETUP 成功后服务端分配，后续命令必须复用。
- **TreeId（树号）**：TREE_CONNECT 成功后服务端分配，标识一个共享资源挂载点。
- **FileId（文件号）**：CREATE 成功后服务端分配，16 字节（8B persistent + 8B volatile），后续 READ/WRITE/CLOSE 复用。
- **SecurityBlob（安全 Blob）**：SESSION_SETUP 携带的 GSS-API/SPNEGO 认证 token。
- **Preauth Integrity（预认证完整性）**：SMB3.1.1 引入，协商后用 SHA-512 哈希所有后续 PDU 以防降级攻击。PreauthIntegrityHashValue 是会话级累积哈希（64B SHA-512），与消息签名 Signature（16B HMAC-SHA256）不同。
- **GSS-API/SPNEGO**：Generic Security Services API / Simple and Protected GSSAPI Negotiation Mechanism，封装 NTLM/Kerberos 认证交换。
- **MSS（Maximum Segment Size，最大分段大小）**：TCP 分段最大负载字节数，默认 1460 字节（以太网 MTU 1500 - IP 头 20 - TCP 头 20）。
- **FILETIME**：Windows 文件时间戳，1601-01-01 起 100ns 单位的 64 位值。
- **NTSTATUS**：Windows NT 状态码，32 位无符号整数，用于 SMB2 响应 Status 字段。
- **PDU（Protocol Data Unit，协议数据单元）**：SMB2 单条命令的完整报文（NBSS 头 + SMB2 头 + 命令体）。
- **TRANSFORM_HEADER**：SMB3 加密头，52 字节，包裹密文。
- **LE（Little-Endian，小端序）**：SMB2 全部多字节整数采用小端字节序。
- **BE（Big-Endian，大端序）**：仅 NBSS 长度字段采用大端序。

---

## §2. 数据类型与编码

### 2.1 字节序规则

SMB2 协议 **全部采用 little-endian（LE，小端序）**，例外仅 NBSS 长度字段（3 字节大端序）。所有多字节整数（uint16/uint32/uint64）写入时低字节在前。

| 数据类型 | 字节数 | 字节序 | 说明 |
|----------|--------|--------|------|
| uint8 | 1 | N/A | 单字节无符号整数 |
| uint16 LE | 2 | LE | 低字节在前（如 0x0210 → `10 02`） |
| uint32 LE | 4 | LE | 低字节在前（如 0xC0000016 → `16 00 00 C0`） |
| uint64 LE | 8 | LE | 低字节在前 |
| UTF-16LE | 2×N | LE | 每字符 2 字节低字节在前（如 "a" → `61 00`） |
| FILETIME | 8 | LE | uint64 LE，1601-01-01 起 100ns 单位 |
| GUID | 16 | 混合 | 4B LE + 2B LE + 2B LE + 8B BE（RFC 4122） |
| NTSTATUS | 4 | LE | uint32 LE 状态码 |

### 2.2 NBSS Session Service 前缀（4 字节）

Direct TCP 模式（端口 445）下，每条 SMB2 PDU 前必须有 4 字节 NBSS session message 头：

| 偏移 | 长度 | 字段 | 字节序 | 取值 | 说明 |
|------|------|------|--------|------|------|
| 0 | 1 | Type | - | 0x00 | Session Message（数据 PDU）；0x81=Session Request、0x82=Positive Response、0x83=Negative Response、0x84=Retarget Response、0x85=Session Keep Alive |
| 1 | 3 | Length | BE | - | 后接 SMB2 PDU 字节数，3 字节大端序（17 位有效，最高位恒 0，上限 2^24-1） |

总长度 = 后接 SMB2 PDU 字节数，最大 16,777,215（2^24-1）。trafficgen 默认开启 NBSS 前缀；用户可在 Config 里关闭（直连模式无前缀，仅极少数嵌入式 SMB 实现使用）。

**NBSS 长度字段字节序**：大端序（BE）。例如后接 SMB2 PDU 200 字节，NBSS 头 = `00 00 C8`（type=0x00, length=200=0x0000C8 BE）。

### 2.3 字符串编码（UTF-16LE）

SMB2 所有字符串（Path/FileName/搜索模式等）采用 UTF-16LE 编码。Length 字段以**字节数**计（非字符数）。例如 "a.txt" UTF-16LE = `61 00 2E 00 74 00 78 00 74 00`，长度 = 10 字节。

UNC 路径 `\\server\share` UTF-16LE = `5C 00 5C 00 73 00 65 00 72 00 76 00 65 00 72 00 5C 00 73 00 68 00 61 00 72 00 65 00`，长度 = 26 字节。

### 2.4 FILETIME 编码

FILETIME 是 1601-01-01 00:00:00 UTC 起 100ns 单位的 uint64 LE。例如 2026-01-01 00:00:00 UTC ≈ 133495296000000000 = `00 80 7E 41 5D 65 D9 01`（LE）。

### 2.5 NTSTATUS 编码

NTSTATUS 是 uint32 LE 状态码。成功 = 0x00000000，失败高位字节通常为 0xC0（如 STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034 → LE `34 00 00 C0`）。

---

## §3. 消息结构

### 3.1 SMB2 SYNC Header（64 字节，所有命令共用）

MS-SMB2 §2.2.1.2 定义 SMB2 SYNC 头共 64 字节，13 个具名字段。**所有偏移以下表为准**（已逐字段核对 MS-SMB2 §2.2.1.2 原文）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 4 | ProtocolId | uint32 LE | 固定魔数 0xFE534D42（little-endian: `FE 53 4D 42`，"\xFESMB"） |
| 4 | 2 | StructureSize | uint16 LE | 固定 64（0x0040，LE: `40 00`），整头大小 |
| 6 | 2 | CreditCharge | uint16 LE | 本请求消耗的信用数；SMB 2.0.2 dialect MUST 填 0；SMB 2.1+ 填实际消耗数（通常 1，超长 READ/WRITE 按段数计） |
| 8 | 4 | Status / ChannelSequence | uint32 LE | 请求：低 16 位 ChannelSequence（SMB3 多通道）+ 高 16 位 Reserved；响应：NT 状态码（STATUS_SUCCESS=0x00000000） |
| 12 | 2 | Command | uint16 LE | 命令码，取值见 §3.2（NEGOTIATE=0x0000 ... OPLOCK_BREAK=0x0012） |
| 14 | 2 | CreditRequest / CreditResponse | uint16 LE | 请求方填请求授予数；响应方填授予数 |
| 16 | 4 | Flags | uint32 LE | 标志位，取值见 §3.3（bit0=SERVER_TO_REDIR 等） |
| 20 | 4 | NextCommand | uint32 LE | 下一命令在本 PDU 内的偏移（chained 命令用）；0 = 本 PDU 单命令 |
| 24 | 8 | MessageId | uint64 LE | 会话内单调递增；响应对应请求 MessageId |
| 32 | 4 | Reserved / AsyncId(高 4B) | uint32 LE | 同步：0；异步：与下 4B 拼成 8B AsyncId |
| 36 | 4 | TreeId | uint32 LE | 树连接号；NEGOTIATE/SESSION_SETUP/ECHO/LOGOFF/CANCEL/OPLOCK_BREAK 为 0；TREE_CONNECT 请求本身为 0，响应分配后复用 |
| 40 | 8 | SessionId | uint64 LE | 会话号；NEGOTIATE 为 0，SESSION_SETUP 响应分配后复用 |
| 48 | 16 | Signature | [16]byte | HMAC-SHA256 签名（占位，trafficgen 全 0 除非用户显式给） |

**字段偏移速查表**（用于测试用例字节断言）：

```
偏移 0-3:    ProtocolId        = FE 53 4D 42
偏移 4-5:    StructureSize     = 40 00 (64 LE)
偏移 6-7:    CreditCharge      = 01 00 (默认 1)
偏移 8-11:   Status            = 00 00 00 00 (请求) / NT 状态码 (响应)
偏移 12-13:  Command           = 命令码 LE (如 00 00 = NEGOTIATE)
偏移 14-15:  CreditRequest     = 请求授予数 LE
偏移 16-19:  Flags             = 00 00 00 00 (请求) / 01 00 00 00 (响应 bit0)
偏移 20-23:  NextCommand       = 00 00 00 00 (单命令)
偏移 24-31:  MessageId         = uint64 LE
偏移 32-35:  Reserved          = 00 00 00 00
偏移 36-39:  TreeId            = uint32 LE
偏移 40-47:  SessionId         = uint64 LE
偏移 48-63:  Signature         = 16B 全 0 (占位)
```

**64 字节内存图**（Offset: Hex bytes）：

```
0000:  FE 53 4D 42 40 00 01 00 00 00 00 00 00 00 20 00
0010:  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
0020:  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
0030:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
> 上图示例为 TREE_CONNECT 请求（Command=0x0003, MessageId=1, TreeId=0, SessionId=1）。

**签名计算规则**（MS-SMB2 §3.3.4.2）：SMB2 签名 = HMAC-SHA256(SessionKey, Message)，其中 Message 是 SMB2 头（含 16B Signature 字段清零）+ 命令体。trafficgen 不实现真实 HMAC，仅生成 16B 全 0 或用户指定的占位字节。PreauthIntegrityHashValue（SHA-512 哈希值，64B）与会话签名（HMAC-SHA256，16B）是两个不同概念：前者是 SMB3.1.1 会话级累积哈希用于防降级，后者是单条消息认证码。

### 3.2 Command 命令码枚举（MS-SMB2 §2.2.1.2）

SMB2 头偏移 12-13 为 Command 字段（uint16 LE），取值如下（MS-SMB2 §2.2.1.2 Command 字段定义）：

| Command 值 | 命令名 | StructureSize (req/resp) | 用途 |
|-----------|--------|--------------------------|------|
| 0x0000 | NEGOTIATE | 36 / 65 | 协商 dialect 与能力 |
| 0x0001 | SESSION_SETUP | 25 / 9 | GSS-API 认证 |
| 0x0002 | LOGOFF | 4 / 4 | 关闭会话 |
| 0x0003 | TREE_CONNECT | 9 / 16 | 连接共享 |
| 0x0004 | TREE_DISCONNECT | 4 / 4 | 断开共享 |
| 0x0005 | CREATE | 57 / 89 | 打开/创建文件 |
| 0x0006 | CLOSE | 24 / 60 | 关闭句柄 |
| 0x0007 | FLUSH | 24 / 4 | 刷盘 |
| 0x0008 | READ | 49 / 17 | 读文件 |
| 0x0009 | WRITE | 49 / 17 | 写文件 |
| 0x000A | LOCK | 48 / 4 | 文件锁 |
| 0x000B | IOCTL | 57 / 49 | 设备/文件系统控制 |
| 0x000C | CANCEL | 4 / 4 | 取消异步请求 |
| 0x000D | ECHO | 4 / 4 | 保活 |
| 0x000E | QUERY_DIRECTORY | 33 / 9 | 列目录 |
| 0x000F | CHANGE_NOTIFY | 32 / 9 | 目录变更通知 |
| 0x0010 | QUERY_INFO | 41 / 9 | 查询文件/FS 信息 |
| 0x0011 | SET_INFO | 33 / 2 | 设置文件/FS 信息 |
| 0x0012 | OPLOCK_BREAK | 36 / 24 | 机会锁中断 |

> **Command 字段映射**：planner 按当前步骤从上表查 Command 值，写入 SMB2 头偏移 12-13（uint16 LE）。例如 NEGOTIATE 请求 = `00 00`，CREATE 请求 = `05 00`，READ 请求 = `08 00`。

### 3.3 Flags 字段位定义（MS-SMB2 §2.2.1.2）

SMB2 头偏移 16-19 为 Flags 字段（uint32 LE），位定义如下：

| 位 | 名称 | 值 | 说明 |
|----|------|----|------|
| bit0 | SMB2_FLAGS_SERVER_TO_REDIR | 0x00000001 | 服务端→客户端（响应包）；请求包不设 |
| bit1 | SMB2_FLAGS_ASYNC_COMMAND | 0x00000002 | 异步命令（使用 ASYNC 头）；本设计不实现 |
| bit2 | SMB2_FLAGS_RELATED_OPERATIONS | 0x00000004 | 链式相关命令；本设计不实现 compounded |
| bit3 | SMB2_FLAGS_SIGNED | 0x00000008 | 消息已签名 |
| bit4-31 | Reserved | 0x00000000 | 保留 |

**Flags 填充规则**：
- **请求包**（client→server，Direction=up）：Flags = 0x00000000（默认）；签名时 |= 0x00000008（SIGNED）。
- **响应包**（server→client，Direction=down）：Flags = 0x00000001（SERVER_TO_REDIR）；签名时 |= 0x00000008。

**Flags 字节值速查**：
- 请求未签名：偏移 16-19 = `00 00 00 00`
- 请求已签名：偏移 16-19 = `08 00 00 00`
- 响应未签名：偏移 16-19 = `01 00 00 00`
- 响应已签名：偏移 16-19 = `09 00 00 00`

### 3.4 CreditCharge 与 CreditRequest 语义

**CreditCharge（偏移 6-7，uint16 LE）**：
- SMB 2.0.2 dialect（0x0202）：MUST NOT be used, MUST be reserved（填 0）。
- SMB 2.1+ dialect（0x0210+）：表示本请求消耗的信用数。通常 1；超长 READ/WRITE 按段数计（如 1MB READ / 64KB 段 = 16 段 → CreditCharge=16）。

**CreditRequest/CreditResponse（偏移 14-15，uint16 LE）**：
- 请求方（client）：填请求授予数（如 32）。
- 响应方（server）：填授予数（如 32）。

**CreditBalance（会话级状态）**：初始 64（服务端在 NEGOTIATE 响应授予）；每个请求扣 CreditCharge，响应补 CreditRequest。trafficgen 不严格模拟信用记账（仅生成字段）。

### 3.5 NEGOTIATE 请求 PDU（Command=0x0000，StructureSize=36）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 36 (0x0024，LE: `24 00`) |
| 2 | 2 | DialectCount | uint16 LE | dialects 数组元素数 |
| 4 | 2 | SecurityMode | uint16 LE | bit0=SigningEnabled、bit1=SigningRequired |
| 6 | 2 | Reserved | uint16 LE | 0 |
| 8 | 4 | Capabilities | uint32 LE | bit0=SMB3 encryption、bit1=directory leasing、bit2=multichannel 等 |
| 12 | 16 | ClientGuid | GUID | 客户端 GUID（RFC 4122 混合字节序） |
| 28 | 4 | NegotiateContextOffset | uint32 LE | SMB3.1.1：从 SMB2 头起始算的偏移；非 3.1.1 填 0 |
| 32 | 2 | NegotiateContextCount | uint16 LE | SMB3.1.1：NegotiateContext 数；非 3.1.1 填 0 |
| 34 | 2 | Reserved2 | uint16 LE | 0 |
| 36 | 2×DialectCount | Dialects[] | uint16 LE[] | dialect 数组（如 0x0311 → `11 03`） |
| ... | ... | Padding | 8B 对齐 | SMB3.1.1，使 NegotiateContextOffset 8 字节对齐 |
| ... | var | NegotiateContextList | var | 仅 SMB3.1.1；含 Preauth Integrity、Encryption、Compression 等 |

**NegotiateContext 结构（MS-SMB2 §2.2.3.1）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | ContextType | uint16 LE | 0x0001=Preauth Integrity、0x0002=Encryption、0x0003=Compression |
| 2 | 2 | DataLength | uint16 LE | Data 字段字节数 |
| 4 | 4 | Reserved | uint32 LE | 0 |
| 8 | var | Data | var | ContextType 特定数据 |

**ContextType=0x0001 SMB2_PREAUTH_INTEGRITY_CAPABILITIES（§2.2.3.1.1）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | HashAlgorithmCount | uint16 LE | HashAlgorithms 数组元素数 |
| 2 | 2 | SaltLength | uint16 LE | Salt 字段字节数 |
| 4 | 2×HashAlgorithmCount | HashAlgorithms | uint16 LE[] | 0x0001=SHA-512（目前唯一合法值） |
| ... | SaltLength | Salt | byte[] | 客户端随机盐 |

**ContextType=0x0002 SMB2_ENCRYPTION_CAPABILITIES（§2.2.3.1.2）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | CipherCount | uint16 LE | Ciphers 数组元素数 |
| 2 | 2×CipherCount | Ciphers | uint16 LE[] | 0x0001=AES-128-CCM、0x0002=AES-128-GCM |

**ContextType=0x0003 SMB2_COMPRESSION_CAPABILITIES（§2.2.3.1.3）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | CompressionAlgorithmCount | uint16 LE | CompressionAlgorithms 数组元素数 |
| 2 | 2 | Padding | uint16 LE | 0 |
| 4 | 4 | Flags | uint32 LE | bit0=Chained |
| 8 | 2×CompressionAlgorithmCount | CompressionAlgorithms | uint16 LE[] | 0x0001=LZNT1、0x0003=LZ77、0x0004=LZ77+Huffman、0x0005=Pattern_V1 |

### 3.6 NEGOTIATE 响应 PDU（StructureSize=65）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 65 (0x0041，LE: `41 00`) |
| 2 | 2 | SecurityMode | uint16 LE | 服务端签名要求 |
| 4 | 2 | DialectRevision | uint16 LE | 选中的 dialect（如 0x0311 → `11 03`） |
| 6 | 2 | NegotiateContextCount | uint16 LE | SMB3.1.1 |
| 8 | 16 | ServerGuid | GUID | 服务端 GUID |
| 24 | 4 | Capabilities | uint32 LE | 服务端能力 |
| 28 | 4 | MaxTransactSize | uint32 LE | 最大事务大小（通常 1MB 或 8MB） |
| 32 | 4 | MaxReadSize | uint32 LE | 最大读大小 |
| 36 | 4 | MaxWriteSize | uint32 LE | 最大写大小 |
| 40 | 8 | SystemTime | FILETIME | 服务端当前时间 |
| 48 | 8 | BootTime | FILETIME | 服务端启动时间 |
| 56 | 2 | SecurityBufferOffset | uint16 LE | 从 SMB2 头起始算的偏移（默认 128） |
| 58 | 2 | SecurityBufferLength | uint16 LE | GSS-API blob 长度 |
| 60 | 4 | NegotiateContextOffset | uint32 LE | SMB3.1.1 |
| 64 | var | SecurityBuffer | byte[] | GSS-API/SPNEGO blob |
| ... | var | Padding | 8B 对齐 | SMB3.1.1 |
| ... | var | NegotiateContextList | var | SMB3.1.1 |

> **SecurityBufferOffset 说明**：MS-SMB2 §2.2.4 规定 SecurityBufferOffset 从 SMB2 头起始算。NEGOTIATE 响应固定体 64 字节（0-63），紧跟在 SMB2 头（64 字节）之后，故 SecurityBuffer 从 SMB2 头起算的偏移 = 64 + 64 = **128**（0x80）。注意：StructureSize=65 是奇数编码，固定体实为 64 字节（最后 1 字节并入 SecurityBuffer 前的 padding），勿按 65 字节排布缓冲区。本设计统一填 128。

### 3.7 SESSION_SETUP 请求 PDU（Command=0x0001，StructureSize=25）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 25 (0x0019，LE: `19 00`) |
| 2 | 1 | Flags | uint8 | bit0=SMB2_SESSION_FLAG_BINDING（SMB3 多通道绑定） |
| 3 | 1 | SecurityMode | uint8 | bit0=SigningEnabled、bit1=SigningRequired |
| 4 | 4 | Capabilities | uint32 LE | bit0=DFS |
| 8 | 4 | Channel | uint32 LE | 0=None、1=RDMA |
| 12 | 2 | SecurityBufferOffset | uint16 LE | 从 SMB2 头起始（固定体 24B，故 64+24=88；非"从命令体起始"） |
| 14 | 2 | SecurityBufferLength | uint16 LE | GSS-API blob 长度 |
| 16 | 8 | PreviousSessionId | uint64 LE | 上次会话 ID（断线重连用，否则 0） |
| 24 | var | SecurityBuffer | byte[] | GSS-API/SPNEGO token |

### 3.8 SESSION_SETUP 响应 PDU（StructureSize=9）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 9 (0x0009，LE: `09 00`) |
| 2 | 2 | SessionFlags | uint16 LE | bit0=IsGuest、bit1=IsNullSession、bit2=EncryptData |
| 4 | 2 | SecurityBufferOffset | uint16 LE | 从 SMB2 头起始 |
| 6 | 2 | SecurityBufferLength | uint16 LE | |
| 8 | var | SecurityBuffer | byte[] | GSS-API 响应 blob |

> SessionId 在 SMB2 头偏移 40 携带；客户端必须保存并在后续命令复用。STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) 表示认证多轮交互未完成，客户端需再次发送 SESSION_SETUP 携带新 blob。

### 3.9 TREE_CONNECT 请求 PDU（Command=0x0003，StructureSize=9）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 9 (LE: `09 00`) |
| 2 | 2 | Reserved | uint16 LE | 0 |
| 4 | 2 | PathOffset | uint16 LE | 从 SMB2 头起始（=64+8=72） |
| 6 | 2 | PathLength | uint16 LE | UTF-16LE 字节数 |
| 8 | var | Path | UTF-16LE | 如 `\\server\share` |

### 3.10 TREE_CONNECT 响应 PDU（StructureSize=16）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 16 (LE: `10 00`) |
| 2 | 1 | ShareType | uint8 | 0=DISK、1=PIPE、2=PRINT |
| 3 | 1 | Reserved | uint8 | 0 |
| 4 | 4 | ShareFlags | uint32 LE | 共享标志 |
| 8 | 4 | Capabilities | uint32 LE | bit1=SMB2_SHARE_CAP_PIPE 等 |
| 12 | 4 | MaximalAccess | uint32 LE | 最大访问权限 |

> TreeId 在响应的 SMB2 头偏移 36 携带，客户端保存并在后续命令复用。

### 3.11 CREATE 请求 PDU（Command=0x0005，StructureSize=57，MS-SMB2 §2.2.6.1）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 57 (0x0039，LE: `39 00`) |
| 2 | 1 | SecurityFlags | uint8 | 0 |
| 3 | 1 | RequestedOplockLevel | uint8 | 0=none、1=II、2=exclusive、3=Batch、4=Lease（SMB3） |
| 4 | 4 | ImpersonationLevel | uint32 LE | 0=Anonymous、1=Identification、2=Impersonation、3=Delegate |
| 8 | 8 | SmbCreateFlags | uint64 LE | 0 |
| 16 | 8 | RootDirectoryFid | uint64 LE | 0 |
| 24 | 4 | DesiredAccess | uint32 LE | FILE_READ_DATA 等；默认 0x00120089 |
| 28 | 4 | FileAttributes | uint32 LE | 0x80=NORMAL 等 |
| 32 | 4 | ShareAccess | uint32 LE | bit0=READ、bit1=WRITE、bit2=DELETE |
| 36 | 4 | CreateDisposition | uint32 LE | 0=supersede、1=open、2=create、3=open_if、4=overwrite、5=overwrite_if |
| 40 | 4 | CreateOptions | uint32 LE | bit0=directory、bit8=non_directory_file 等 |
| 44 | 2 | NameOffset | uint16 LE | 从 SMB2 头起始；无 CreateContexts 时 = 64+56 = **120** (LE: `78 00`) |
| 46 | 2 | NameLength | uint16 LE | UTF-16LE 字节数 |
| 48 | 4 | CreateContextsOffset | uint32 LE | |
| 52 | 4 | CreateContextsLength | uint32 LE | |
| 56 | var | Name | UTF-16LE | 文件名 |
| ... | var | CreateContexts | var | |

> 固定体共 56 字节（2+1+1+4+8+8+4+4+4+4+4+2+2+4+4），Name 从命令体偏移 56 开始（从 SMB2 头算 = 64+56 = 120）。

### 3.12 CREATE 响应 PDU（StructureSize=89）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 89 (0x0059，LE: `59 00`) |
| 2 | 1 | OplockLevel | uint8 | |
| 3 | 1 | Flags | uint8 | bit0=REPLY_OPER_STATUS 等 |
| 4 | 4 | CreateAction | uint32 LE | 0=superseded、1=opened、2=created、3=overwritten |
| 8 | 8 | CreationTime | FILETIME | |
| 16 | 8 | LastAccessTime | FILETIME | |
| 24 | 8 | LastWriteTime | FILETIME | |
| 32 | 8 | ChangeTime | FILETIME | |
| 40 | 8 | AllocationSize | uint64 LE | |
| 48 | 8 | EndOfFile | uint64 LE | |
| 56 | 4 | FileAttributes | uint32 LE | |
| 60 | 4 | Reserved | uint32 LE | 0 |
| 64 | 16 | FileId | [16]byte | 8B persistent + 8B volatile |
| 80 | 4 | CreateContextsOffset | uint32 LE | |
| 84 | 4 | CreateContextsLength | uint32 LE | |
| 88 | var | CreateContexts | var | |

### 3.13 READ 请求 PDU（Command=0x0008，StructureSize=49）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 49 (0x0031，LE: `31 00`) |
| 2 | 1 | Padding | uint8 | 0 |
| 3 | 1 | Flags | uint8 | bit0=READ_UNBUFFERED |
| 4 | 4 | Length | uint32 LE | 读取字节数 |
| 8 | 8 | Offset | uint64 LE | 文件偏移 |
| 16 | 16 | FileId | [16]byte | 8B persistent + 8B volatile |
| 32 | 4 | MinimumCount | uint32 LE | 最少读取字节数 |
| 36 | 4 | Channel | uint32 LE | 0=none、1=RDMA |
| 40 | 4 | RemainingBytes | uint32 LE | |
| 44 | 2 | ReadChannelInfoOffset | uint16 LE | |
| 46 | 2 | ReadChannelInfoLength | uint16 LE | |
| 48 | 1 | Buffer[] | uint8 | ReadChannelInfo，通常空 |

### 3.14 READ 响应 PDU（StructureSize=17）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 17 (0x0011，LE: `11 00`) |
| 2 | 1 | DataOffset | uint8 | 从 SMB2 头起始，=64+16=80 |
| 3 | 1 | Reserved | uint8 | 0 |
| 4 | 4 | DataLength | uint32 LE | 实际读取字节数 |
| 8 | 4 | DataRemaining | uint32 LE | 0 |
| 12 | 4 | Flags | uint32 LE | bit0=READ_FROM_CACHE 等 |
| 16 | var | Data | byte[] | 读取的数据 |

### 3.15 WRITE 请求 PDU（Command=0x0009，StructureSize=49）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 49 (0x0031，LE: `31 00`) |
| 2 | 2 | DataOffset | uint16 LE | 从 SMB2 头起始算，=64+48=**112** (LE: `70 00`) |
| 4 | 4 | Length | uint32 LE | 写入字节数 |
| 8 | 8 | Offset | uint64 LE | 文件偏移 |
| 16 | 16 | FileId | [16]byte | 8B persistent + 8B volatile |
| 32 | 4 | Channel | uint32 LE | 0=none、1=RDMA |
| 36 | 4 | RemainingBytes | uint32 LE | |
| 40 | 2 | WriteChannelInfoOffset | uint16 LE | |
| 42 | 2 | WriteChannelInfoLength | uint16 LE | |
| 44 | 4 | Flags | uint32 LE | bit0=WRITE_THROUGH 等 |
| 48 | var | Data | byte[] | 写入的数据 |

> **DataOffset 计算**：WRITE 请求 PDU 体共 48 字节，紧跟在 SMB2 头（64 字节）后，所以 Data 字段从 SMB2 头起始算的偏移 = 64 + 48 = **112**。MS-SMB2 不要求 WRITE 请求对齐到 72 字节边界。

### 3.16 WRITE 响应 PDU（StructureSize=17，MS-SMB2 §2.2.10.2）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 17 (LE: `11 00`) |
| 2 | 2 | Reserved | uint16 LE | 0 |
| 4 | 4 | Count | uint32 LE | 实际写入字节数 |
| 8 | 4 | Remaining | uint32 LE | 0 |
| 12 | 2 | WriteChannelInfoOffset | uint16 LE | |
| 14 | 2 | WriteChannelInfoLength | uint16 LE | |

> 固定体共 16 字节（2+2+4+4+2+2），17 = 16 + 1 奇数编码；WriteChannelInfo 从偏移 16 开始。

### 3.17 CLOSE 请求 PDU（Command=0x0006，StructureSize=24）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 24 (0x0018，LE: `18 00`) |
| 2 | 2 | Flags | uint16 LE | bit0=POSTQUERY_ATTRIB |
| 4 | 4 | Reserved | uint32 LE | 0 |
| 8 | 16 | FileId | [16]byte | 8B persistent + 8B volatile |

### 3.18 CLOSE 响应 PDU（StructureSize=60）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 60 (0x003C，LE: `3C 00`) |
| 2 | 2 | Flags | uint16 LE | |
| 4 | 4 | Reserved | uint32 LE | 0 |
| 8 | 8 | CreationTime | FILETIME | |
| 16 | 8 | LastAccessTime | FILETIME | |
| 24 | 8 | LastWriteTime | FILETIME | |
| 32 | 8 | ChangeTime | FILETIME | |
| 40 | 8 | AllocationSize | uint64 LE | |
| 48 | 8 | EndOfFile | uint64 LE | |
| 56 | 4 | FileAttributes | uint32 LE | |

### 3.19 TREE_DISCONNECT / LOGOFF / ECHO（轻量命令）

**TREE_DISCONNECT（Command=0x0004，StructureSize=4）**：仅 StructureSize(2B) + Reserved(2B)。

**LOGOFF（Command=0x0002，StructureSize=4）**：仅 StructureSize(2B) + Reserved(2B)。

**ECHO（Command=0x000D，StructureSize=4）**：仅 StructureSize(2B) + Reserved(2B)。

### 3.20 QUERY_DIRECTORY 请求 PDU（Command=0x000E，StructureSize=33，MS-SMB2 §2.2.15.1）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 33 (0x0021，LE: `21 00`) |
| 2 | 1 | FileInformationClass | uint8 | 1=DirectoryInformation、2=FullDirectoryInformation、3=BothDirectoryInformation、37=IdBothDirectoryInformation 等 |
| 3 | 1 | Flags | uint8 | bit0=RESTART_SCANS、bit1=RETURN_SINGLE_ENTRY、bit2=INDEX_SPECIFIED、bit3=REOPEN |
| 4 | 4 | FileIndex | uint32 LE | 未设 INDEX_SPECIFIED 时须为 0 |
| 8 | 16 | FileId | [16]byte | 目录句柄 |
| 24 | 2 | FileNameOffset | uint16 LE | 从 SMB2 头起始（=64+32=96） |
| 26 | 2 | FileNameLength | uint16 LE | UTF-16LE 字节数 |
| 28 | 4 | OutputBufferLength | uint32 LE | 输出缓冲区最大长度 |
| 32 | var | FileName | UTF-16LE | 通配符 `*` 或 `*.txt` |

> 固定体共 32 字节（2+1+1+4+16+2+2+4），33 = 32 + 1 奇数编码；FileName 从 SMB2 头起算的偏移 = 64 + 32 = **96**（0x60）。

### 3.21 QUERY_DIRECTORY 响应 PDU（StructureSize=9，MS-SMB2 §2.2.15.2）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 9 (LE: `09 00`) |
| 2 | 2 | OutputBufferOffset | uint16 LE | 从 SMB2 头起始算，固定 64 |
| 4 | 4 | OutputBufferLength | uint32 LE | OutputBuffer 字节数 |
| 8 | var | OutputBuffer | byte[] | ID_BOTH_DIR_INFO 数组 |

**ID_BOTH_DIR_INFO 结构（MS-FSCC §2.4.18，FileInformationClass=37）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 4 | NextEntryOffset | uint32 LE | 下一条目偏移，0 = 最后条目 |
| 4 | 4 | FileIndex | uint32 LE | |
| 8 | 8 | CreationTime | FILETIME | |
| 16 | 8 | LastAccessTime | FILETIME | |
| 24 | 8 | LastWriteTime | FILETIME | |
| 32 | 8 | ChangeTime | FILETIME | |
| 40 | 8 | EndOfFile | uint64 LE | |
| 48 | 8 | AllocationSize | uint64 LE | |
| 56 | 4 | FileAttributes | uint32 LE | |
| 60 | 4 | EaSize | uint32 LE | |
| 64 | 2 | ShortNameLength | uint16 LE | |
| 66 | 2 | Reserved | uint16 LE | 0 |
| 68 | 24 | ShortName | UTF-16LE | 12 字符 |
| 92 | 2 | FileId | uint16 LE | FileReferenceNumber 低 2B |
| 94 | 2 | Reserved2 | uint16 LE | 0 |
| 96 | 4 | FileNameLength | uint32 LE | UTF-16LE 字节数 |
| 100 | var | FileName | UTF-16LE | 文件名 |

### 3.22 QUERY_INFO 请求 PDU（Command=0x0010，StructureSize=41）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 41 (0x0029，LE: `29 00`) |
| 2 | 1 | InfoType | uint8 | 0=File、1=FileSystem、2=Security、3=Quota |
| 3 | 1 | FileInfoClass | uint8 | 如 4=FileBasicInfo、5=FileStandardInfo 等 |
| 4 | 4 | OutputBufferLength | uint32 LE | 输出缓冲区最大长度 |
| 8 | 2 | InputBufferOffset | uint16 LE | 从 SMB2 头起始 |
| 10 | 2 | Reserved | uint16 LE | 0 |
| 12 | 4 | InputBufferLength | uint32 LE | |
| 16 | 4 | AdditionalInformation | uint32 LE | |
| 20 | 4 | Flags | uint32 LE | |
| 24 | 16 | FileId | [16]byte | |
| 40 | 1 | Buffer[] | var | InputBuffer |

### 3.23 QUERY_INFO 响应 PDU（StructureSize=9）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 9 (LE: `09 00`) |
| 2 | 2 | OutputBufferOffset | uint16 LE | 从 SMB2 头起始 |
| 4 | 4 | OutputBufferLength | uint32 LE | |
| 8 | var | OutputBuffer | byte[] | 信息数据 |

### 3.24 LOCK 请求 PDU（Command=0x000A，StructureSize=48）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 48 (0x0030，LE: `30 00`) |
| 2 | 2 | LockCount | uint16 LE | Locks 数组元素数 |
| 4 | 4 | LockSequence | uint32 LE | |
| 8 | 16 | FileId | [16]byte | |
| 24 | var | Locks | LOCK_ELEMENT[] | 每元素 24B |

**LOCK_ELEMENT 结构（24 字节）**：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 8 | Offset | uint64 LE | 锁起始偏移 |
| 8 | 8 | Length | uint64 LE | 锁长度 |
| 16 | 4 | Flags | uint32 LE | bit0=SHARED_LOCK、bit1=EXCLUSIVE_LOCK、bit2=UNLOCK、bit3=FAIL_IMMEDIATELY |
| 20 | 4 | Reserved | uint32 LE | 0 |

### 3.25 IOCTL 请求 PDU（Command=0x000B，StructureSize=57）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 2 | StructureSize | uint16 LE | 57 (0x0039，LE: `39 00`) |
| 2 | 2 | Reserved | uint16 LE | 0 |
| 4 | 4 | CtlCode | uint32 LE | IOCTL 控制码 |
| 8 | 16 | FileId | [16]byte | |
| 24 | 4 | InputOffset | uint32 LE | 从 SMB2 头起始 |
| 28 | 4 | InputCount | uint32 LE | |
| 32 | 4 | MaxInputResponse | uint32 LE | |
| 36 | 4 | OutputOffset | uint32 LE | |
| 40 | 4 | OutputCount | uint32 LE | |
| 44 | 4 | MaxOutputResponse | uint32 LE | |
| 48 | 4 | Flags | uint32 LE | bit0=IS_IOCTL、bit1=FSCTL |
| 52 | 2 | Reserved2 | uint16 LE | 0 |
| 54 | 2 | Buffer[] | var | InputBuffer |

### 3.26 NT 状态码（Status 字段，响应）

| 值 | 名称 | 含义 |
|----|------|------|
| 0x00000000 | STATUS_SUCCESS | 成功 |
| 0xC0000016 | STATUS_MORE_PROCESSING_REQUIRED | 多轮认证未完 |
| 0xC0000022 | STATUS_ACCESS_DENIED | 访问拒绝 / 权限不足 |
| 0xC0000034 | STATUS_OBJECT_NAME_NOT_FOUND | 文件不存在 |
| 0xC0000035 | STATUS_OBJECT_NAME_COLLISION | 文件已存在 |
| 0xC000000D | STATUS_INVALID_PARAMETER | 参数无效 |
| 0xC0000120 | STATUS_CANCELLED | 已取消 |
| 0xC000007B | STATUS_INVALID_IMAGE_FORMAT | 协议格式错 |
| 0xC00000CC | STATUS_BAD_NETWORK_NAME | 共享名不存在（TREE_CONNECT 异常） |
| 0xC000006D | STATUS_LOGON_FAILURE | 登录失败（SESSION_SETUP 异常） |
| 0xC0000020 | STATUS_END_OF_FILE | 文件末尾（READ 超出 EOF） |
| 0xC0000021 | STATUS_FILE_LOCK_CONFLICT | 锁冲突 |
| 0xC00003E3 | STATUS_USER_SESSION_DELETED | 会话不存在/已删除（SessionId 错配异常） |
| 0xC0000080 | STATUS_INVALID_HANDLE | 句柄无效（FileId/TreeId 错配） |

### 3.27 TRANSFORM_HEADER（52 字节，SMB3 加密头，MS-SMB2 §3.1.4.3）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0 | 4 | ProtocolId | uint32 LE | 0xFD534D42（"FDSMB"，LE: `FD 53 4D 42`） |
| 4 | 16 | Signature | [16]byte | AES-GCM/AES-CCM 认证标签（占位，trafficgen 全 0） |
| 20 | 16 | Nonce | [16]byte | 加密随机数（占位，trafficgen 全 0 或随机） |
| 36 | 4 | OriginalMessageSize | uint32 LE | 原始（未加密）消息字节数 |
| 40 | 2 | Reserved | uint16 LE | 0x0000 |
| 42 | 2 | Flags | uint16 LE | bit0=Encrypted（必须为 1） |
| 44 | 8 | SessionId | uint64 LE | 加密会话的 SessionId |
| 52 | var | EncryptedMessage | byte[] | 密文占位（trafficgen 全 0 或随机字节，长度 = OriginalMessageSize） |

> **TRANSFORM_HEADER 大小 = 52 字节**（非 57 字节）。MS-SMB2 §3.1.4.3 明确定义 7 个字段共 52 字节，无 padding。Wireshark 按 52 字节解析。**TRANSFORM_HEADER（52B）替换原 SMB2 头（64B）**，原头+体作为密文载荷（EncryptedMessage）。

---

## §4. 状态机

SMB2 会话是严格的状态机，每个阶段必须按序执行：

```
TCP ESTABLISHED
       |
       v
+------------------+
| NEGOTIATE        |  <- 协商 dialect / 能力 / 安全机制
| (req + resp)     |
+--------+---------+
         | DialectRevision 确定
         v
+------------------+    多轮 (NTLM: 3 轮, Kerberos: 2 轮, anon: 1 轮)
| SESSION_SETUP xN |  <- GSS-API 认证交换
| (req + resp)     |
+--------+---------+
         | SessionId 分配, STATUS_SUCCESS
         v
+------------------+
| TREE_CONNECT     |  <- 连接共享 \\server\share
| (req + resp)     |
+--------+---------+
         | TreeId 分配
         v
+------------------+    (可选, 文件操作前)
| CREATE           |  <- 打开文件 / 创建目录
| (req + resp)     |
+--------+---------+
         | FileId 分配
         v
+------------------+
| READ / WRITE /   |  <- Operations[] 顺序执行
| QUERY_DIRECTORY  |
| xN (req + resp)  |
+--------+---------+
         |
         v
+------------------+
| CLOSE            |  <- 关闭 FileId
| (req + resp)     |
+--------+---------+
         |
         v
+------------------+
| TREE_DISCONNECT  |  <- 断开 TreeId
| (req + resp)     |
+--------+---------+
         |
         v
+------------------+
| LOGOFF           |  <- 关闭 SessionId
| (req + resp)     |
+--------+---------+
         |
         v
TCP TEARDOWN (FIN/ACK/ACK/FIN/ACK/ACK)
```

### 4.1 状态变量

会话内 planner 维护以下变量：

| 变量 | 初始 | 更新规则 |
|------|------|----------|
| MessageId | 0 | 每发一个请求 +1；响应对应请求 MessageId |
| SessionId | 0 | SESSION_SETUP 响应分配（planner 全局原子计数器从 1 开始递增，保证多会话唯一性） |
| TreeId | 0 | TREE_CONNECT 请求时填 0；TREE_CONNECT 响应分配（会话内递增，从 1 开始） |
| FileId | 全 0 | CREATE 响应分配（16B 随机，planner 保证多会话唯一性） |
| CreditBalance | 64 | 服务端授予；每个请求扣 CreditCharge，响应补 CreditRequest |
| DialectRevision | 0 | NEGOTIATE 响应确定 |
| PreauthHashValue | SHA-512() | SMB3.1.1 每 PDU 后更新（占位） |
| Command | 按 §3.2 表 | planner 按当前步骤从 §3.2 表查 Command 值，写入 SMB2 头偏移 12-13（uint16 LE） |
| Flags | 0 (请求) / 0x01 (响应) | 请求 Flags=0；响应 Flags |= 0x00000001（SERVER_TO_REDIR）；签名时 |= 0x00000008（SIGNED） |

> **SessionId 唯一性保障**（MS-SMB2 §3.3.4.5）：真实环境 SessionId 由服务端分配保证全局唯一。trafficgen 同时生成客户端和服务端流量，planner 内部维护全局原子计数器从 1 开始递增分配 SessionId，多 goroutine 并发调用 `atomic.AddUint64` 保证唯一性，避免随机碰撞。TreeId 是会话内状态（每条会话从 1 开始递增），跨会话 TreeId 重复合法。FileId 由 planner 用 `crypto/rand` 生成 16B 随机值，碰撞概率约 2^-128 可忽略。

> **生成顺序与 ID 回填**（trafficgen 双侧流量职责边界）：planner **顺序生成**一对 PDU（request→response→request→response...），不预先生成所有请求再回填响应。具体规则：
> 1. 对于每对 PDU，planner 先计算响应阶段才会确定的 ID（SessionId 在 SESSION_SETUP resp #1 时分配、TreeId 在 TREE_CONNECT resp 时分配、FileId 在 CREATE resp 时分配），再**回填**到该对的请求 PDU 与所有后续 PDU 中（请求 PDU 在生成时尚未"知道"该 ID，但 planner 已先算好）。
> 2. 例外：**SESSION_SETUP req #1** 的 SessionId 填 0（尚未分配），TREE_CONNECT req 的 TreeId 填 0（尚未分配）——这些"未知 ID"的请求 PDU 在响应分配后无需修改（已发出）。
> 3. **并发会话隔离**：SessionId 用全局原子计数器（天然跨会话唯一）；TreeId 计数器挂在**会话对象**上（每会话独立计数器，天然隔离，多 goroutine 间无共享状态）；FileId 用 crypto/rand（每会话独立随机源）。**TreeId 不用全局计数器**——若用全局计数器，两会话并发时会拿到相同 TreeId 再各自回填，引发 PDU 内 TreeId 与会话上下文不一致。

### 4.2 异常分支

- NEGOTIATE 响应 STATUS_INVALID_PARAMETER → 终止会话，跳过后续所有命令，直接 TCP teardown（无 LOGOFF——无 SessionId 可注销，见下方跳过规则表）。
- SESSION_SETUP 响应 STATUS_MORE_PROCESSING_REQUIRED → 多轮认证继续；STATUS_LOGON_FAILURE → 终止。
- TREE_CONNECT 响应 STATUS_BAD_NETWORK_NAME → 跳过 CREATE，直接 LOGOFF。
- CREATE 响应 STATUS_OBJECT_NAME_NOT_FOUND → 跳过 READ/WRITE/CLOSE，直接 TREE_DISCONNECT。
- 任意命令 ErrorResponseStatus 非零 → 该命令响应返回错误（ErrorResponseStatus 必须为 §3.26 表 14 个已知 NT 状态码之一，见 V30），命令体缩短为 §9.3 最小错误体（StructureSize 保持该命令的正常值），后续命令按 ErrorOnCommand 决定。

**错误注入跳过规则表**（ErrorOnCommand 按命令列出跳过的后续命令与保留的拆解命令）：

| ErrorOnCommand | 跳过的后续命令 | 保留的拆解命令 | Command 字段处理 |
|----------------|----------------|----------------|------------------|
| negotiate | SESSION_SETUP / TREE_CONNECT / CREATE / READ / WRITE / CLOSE | 无（直接 TCP teardown） | N/A |
| session_setup | TREE_CONNECT / CREATE / READ / WRITE / CLOSE | LOGOFF | LOGOFF Command=0x0002 写入偏移 12-13 |
| tree_connect | CREATE / READ / WRITE / CLOSE | LOGOFF（无 TreeId，跳过 TREE_DISCONNECT） | LOGOFF Command=0x0002 写入偏移 12-13 |
| create | READ / WRITE / CLOSE | TREE_DISCONNECT / LOGOFF | TREE_DISCONNECT Command=0x0004、LOGOFF Command=0x0002 写入偏移 12-13 |
| read | CLOSE 后续 READ/WRITE | CLOSE / TREE_DISCONNECT / LOGOFF | CLOSE Command=0x0006、TREE_DISCONNECT=0x0004、LOGOFF=0x0002 |
| write | CLOSE 后续 READ/WRITE | CLOSE / TREE_DISCONNECT / LOGOFF | 同上 |
| close | 无（CLOSE 本身是拆解） | TREE_DISCONNECT / LOGOFF | TREE_DISCONNECT=0x0004、LOGOFF=0x0002 |
| tree_disconnect | 无 | LOGOFF | LOGOFF Command=0x0002 |
| logoff | 无 | 无（直接 TCP teardown） | N/A |

> **规则**：错误注入跳过的是"依赖该命令的后续命令"，保留"会话拆解命令"（TREE_DISCONNECT / LOGOFF）以正确关闭会话状态。例外：`negotiate` 错误无法进入会话（无 SessionId），直接 TCP teardown 不发任何命令；`session_setup` 错误无 SessionId 关联的树，仅 LOGOFF（不 TREE_DISCONNECT）；`tree_connect` 错误无 TreeId，仅 LOGOFF（不 TREE_DISCONNECT）。**所有保留的拆解命令仍需正确写入 Command 字段到 SMB2 头偏移 12-13**。

### 4.3 MessageId 编号方案

```
NEGOTIATE req:        MessageId=0
NEGOTIATE resp:       MessageId=0 (对应请求)
SESSION_SETUP req #1: MessageId=1
SESSION_SETUP resp #1: MessageId=1
SESSION_SETUP req #2: MessageId=2  (NTLM 三阶段第二轮, NTLMSSP_AUTH)
SESSION_SETUP resp #2: MessageId=2
SESSION_SETUP req #3: MessageId=3  (NTLM 三阶段第三轮, 最终确认)
SESSION_SETUP resp #3: MessageId=3
TREE_CONNECT req:     MessageId=4
TREE_CONNECT resp:    MessageId=4
CREATE req:           MessageId=5
CREATE resp:          MessageId=5
READ req #1:          MessageId=6
READ resp #1:         MessageId=6
... (按 Operations[] 重复, N=操作数)
CLOSE req:             MessageId=5+N+1
CLOSE resp:            MessageId=5+N+1
TREE_DISCONNECT req:  MessageId=5+N+2
TREE_DISCONNECT resp: MessageId=5+N+2
LOGOFF req:           MessageId=5+N+3
LOGOFF resp:          MessageId=5+N+3
```

> **NTLM 三阶段（AuthRounds=3）**：3 对 SESSION_SETUP 占用 MessageId 1-3。NTLM 两阶段（AuthRounds=2）：2 对 SESSION_SETUP 占用 MessageId 1-2。Kerberos 两阶段：2 对 SESSION_SETUP。anonymous/guest 一阶段：1 对 SESSION_SETUP。后续 TREE_CONNECT 起始 MessageId 随 AuthRounds 调整。

### 4.4 包总数公式

完整会话包数（含 TCP 握手/挥手机器可见包）：

```
TCP 3-way 握手:    3 包
NEGOTIATE:         2 包 (req + resp)
SESSION_SETUP:    2 × AuthRounds 包
TREE_CONNECT:      2 包
CREATE:            2 包
Operations:        2 × N 包 (N = len(Operations))
CLOSE:             2 包
TREE_DISCONNECT:   2 包
LOGOFF:            2 包
TCP 4-way 挥手:    4 包
合计: 3 + 2 + 2×AuthRounds + 2 + 2 + 2×N + 2 + 2 + 2 + 4 = 19 + 2×AuthRounds + 2×N
```

**NTLM 三阶段默认（AuthRounds=3, N=1 READ）**：19 + 6 + 2 = **27 包**。
**NTLM 三阶段 + 1 READ + 1 WRITE（N=2）**：19 + 6 + 4 = **29 包**。

**SMB PDU 数**（不含 TCP 握手/挥手）：2 + 2×AuthRounds + 2 + 2 + 2×N + 2 + 2 + 2 = 12 + 2×AuthRounds + 2×N。
- NTLM 三阶段 + 1 READ：12 + 6 + 2 = **20 个 SMB PDU**（10 对请求/响应）。

---

## §5. 配置类型定义（Go struct）

```go
// SMBConfig holds SMB2/SMB3 protocol configuration.
type SMBConfig struct {
    // --- 传输层 ---

    // Transport (传输模式): "direct" (默认, 端口 445 Direct TCP) 或
    // "netbios" (端口 139, NBSS 前缀). 空默认 direct.
    Transport string `json:"transport,omitempty"`

    // --- 协商阶段 ---

    // Dialects (方言列表): 客户端支持的 dialect 列表，如
    // ["0x0202","0x0210","0x0300","0x0302","0x0311"]. 空默认
    // ["0x0202","0x0210","0x0300","0x0302","0x0311"] (覆盖
    // SMB2.002/2.1/3.0/3.0.2/3.1.1).
    // 服务端选中 dialect = 列表最后一个 (假设服务端支持最高版本).
    Dialects []string `json:"dialects,omitempty"`

    // SelectedDialect (选中方言): 服务端选中的 dialect; 空默认
    // Dialects 列表最后一个. 用于响应包生成.
    SelectedDialect string `json:"selected_dialect,omitempty"`

    // ClientGuid (客户端 GUID): 16 字节客户端标识; 空默认随机生成.
    ClientGuid [16]byte `json:"client_guid,omitempty"`

    // ServerGuid (服务端 GUID): 16 字节服务端标识; 空默认随机生成.
    ServerGuid [16]byte `json:"server_guid,omitempty"`

    // ClientCapabilities (客户端能力): bitmask; 0 默认
    // SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x03).
    // 注意: SelectedDialect < 0x0300 (0x0202/0x0210) 时自动清 bit0
    // (Encryption 仅 SMB3 有意义), 见 §5.2.
    ClientCapabilities uint32 `json:"client_capabilities,omitempty"`

    // ServerCapabilities (服务端能力): 同上.
    ServerCapabilities uint32 `json:"server_capabilities,omitempty"`

    // SecurityMode (安全模式): bit0=SigningEnabled, bit1=SigningRequired.
    // 0 默认 SigningEnabled (0x01).
    SecurityMode uint16 `json:"security_mode,omitempty"`

    // SigningRequired (要求签名): true 时 SecurityMode |= 0x02.
    SigningRequired bool `json:"signing_required,omitempty"`

    // --- 认证阶段 ---

    // AuthMechanism (认证机制): "ntlm" (默认) 或 "kerberos" 或 "anonymous"
    // 或 "guest". 决定 SESSION_SETUP SecurityBlob 占位内容.
    AuthMechanism string `json:"auth_mechanism,omitempty"`

    // Username (用户名): NTLM/Kerberos 用户名 (仅用于填充 NTLMSSP_AUTH 占位
    // 字段, 不做真实 hash 计算).
    Username string `json:"username,omitempty"`

    // Domain (域): NTLM 域名或 Kerberos realm.
    Domain string `json:"domain,omitempty"`

    // Password (密码): 仅用于占位字段, 不做真实加密.
    Password string `json:"password,omitempty"`

    // SecurityBlob (安全 Blob): 用户自定义 GSS-API/SPNEGO blob; 设置时
    // 覆盖 AuthMechanism 自动生成的占位. 用于复现真实 pcap.
    SecurityBlob []byte `json:"security_blob,omitempty"`

    // AuthRounds (认证轮数): SESSION_SETUP 交换轮数; 0 表示默认
    // (按机制换算: ntlm→3, kerberos→2, anonymous/guest→1, 见 V12);
    // 显式非 0 必须在 1-3 且与机制匹配 (ntlm 只能 2 或 3, 见 V16).
    AuthRounds int `json:"auth_rounds,omitempty"`

    // --- 树连接阶段 ---

    // TreeConnectShare (树连接共享): UNC 路径, 如 "\\server\share" 或
    // "\\server\IPC$" (命名管道). 空默认 "\\server\share".
    TreeConnectShare string `json:"tree_connect_share,omitempty"`

    // ShareType (共享类型): 0=DISK、1=PIPE、2=PRINT. 空默认 0.
    // IPC$ 自动设为 1.
    ShareType uint8 `json:"share_type,omitempty"`

    // --- 文件操作阶段 ---

    // FilePath (文件路径): CREATE 命令打开的文件名, UTF-8 字符串; planner
    // 自动转 UTF-16LE. 空默认 "file.txt".
    FilePath string `json:"file_path,omitempty"`

    // CreateDisposition (打开方式): 0=supersede、1=open、2=create、
    // 3=open_if、4=overwrite、5=overwrite_if. 空默认 1 (open).
    CreateDisposition uint8 `json:"create_disposition,omitempty"`

    // AccessMask (访问掩码): 0 默认 0x00120089 (GENERIC_READ +
    // FILE_READ_DATA + SYNCHRONIZE).
    AccessMask uint32 `json:"access_mask,omitempty"`

    // FileAttributes (文件属性): 0 默认 0x80 (NORMAL).
    FileAttributes uint32 `json:"file_attributes,omitempty"`

    // ShareAccess (共享访问): bit0=READ、bit1=WRITE、bit2=DELETE.
    // 0 默认 0x07 (RWX).
    ShareAccess uint8 `json:"share_access,omitempty"`

    // CreateOptions (创建选项): 0 默认 0 (普通文件).
    CreateOptions uint32 `json:"create_options,omitempty"`

    // FileId (文件号): CREATE 响应分配的 16 字节 FileId; 用于后续
    // READ/WRITE/CLOSE. 全 0 表示由 planner 在 CREATE 响应时随机分配.
    FileId [16]byte `json:"file_id,omitempty"`

    // --- 操作序列 ---

    // Operations (操作序列): 文件操作列表, 按顺序执行. 每个操作生成
    // 1 对请求/响应. 空默认 [{OpType:"read", Offset:0, Length:4096}].
    Operations []SMBOperation `json:"operations,omitempty"`

    // --- SMB3 高级 ---

    // PreauthIntegrityHashAlgorithms (预认证完整性算法列表): SMB3.1.1 才有;
    // 0x0001=SHA-512. 空默认 [0x0001].
    PreauthIntegrityHashAlgorithms []uint16 `json:"preauth_integrity_hash_algorithms,omitempty"`

    // PreauthIntegrityHashValue (预认证完整性哈希值): 会话内动态更新的 SHA-512
    // 哈希值 (64B), 用于防降级攻击. planner 占位全 0; 不真实计算.
    // 注意: 与 Signature (16B HMAC-SHA256 消息签名) 不同, 两者不可混淆.
    PreauthIntegrityHashValue [64]byte `json:"preauth_integrity_hash_value,omitempty"`

    // EncryptionAlgorithm (加密算法): SMB3.1.1 才有; 0x0001=AES-CCM、
    // 0x0002=AES-GCM. 0 默认 0x0001.
    EncryptionAlgorithm uint16 `json:"encryption_algorithm,omitempty"`

    // EncryptionRequired (要求加密): true 时 SessionFlags.EncryptData=1.
    EncryptionRequired bool `json:"encryption_required,omitempty"`

    // --- 业务控制 ---

    // MaxTransactSize (最大事务大小): 默认 65536 (64KB).
    MaxTransactSize uint32 `json:"max_transact_size,omitempty"`

    // MaxReadSize (最大读大小): 默认 1048576 (1MB).
    MaxReadSize uint32 `json:"max_read_size,omitempty"`

    // MaxWriteSize (最大写大小): 默认 1048576 (1MB).
    MaxWriteSize uint32 `json:"max_write_size,omitempty"`

    // IncludeNegotiate (包含协商): true 默认; false 跳过 NEGOTIATE 阶段
    // (测试用，假设已协商).
    IncludeNegotiate *bool `json:"include_negotiate,omitempty"`

    // PreviousSessionId (上次会话 ID): SESSION_SETUP 请求 PreviousSessionId
    // 字段（多通道重连时复用上次会话）；0 默认 0（独立会话无重连）.
    PreviousSessionId uint64 `json:"previous_session_id,omitempty"`

    // IncludeAuth (包含认证): true 默认; false 跳过 SESSION_SETUP.
    IncludeAuth *bool `json:"include_auth,omitempty"`

    // IncludeTreeConnect (包含树连接): true 默认; false 跳过 TREE_CONNECT.
    IncludeTreeConnect *bool `json:"include_tree_connect,omitempty"`

    // IncludeTeardown (包含会话拆解): true 默认; false 跳过
    // TREE_DISCONNECT/LOGOFF.
    IncludeTeardown *bool `json:"include_teardown,omitempty"`

    // --- 错误注入 (测试用) ---

    // ErrorResponseStatus (错误响应状态码): 非零时所有命令响应返回
    // 该 NT 状态码 (用于测试异常路径). 0 默认 STATUS_SUCCESS.
    ErrorResponseStatus uint32 `json:"error_response_status,omitempty"`

    // ErrorOnCommand (在指定命令返回错误): 命令名; 该命令的响应返回
    // ErrorResponseStatus, 后续命令按 §4.2 跳过规则表决定.
    // 合法值: "negotiate" / "session_setup" / "tree_connect" / "create" /
    // "read" / "write" / "close" / "tree_disconnect" / "logoff".
    ErrorOnCommand string `json:"error_on_command,omitempty"`
}

// SMBOperation 描述单个 SMB 文件操作.
type SMBOperation struct {
    // OpType (操作类型): "read" / "write" / "close" / "query_directory" /
    // "query_info" / "set_info" / "flush" / "echo".
    OpType string `json:"op_type"`

    // Offset (文件偏移): READ/WRITE 用; 0 默认 0.
    Offset uint64 `json:"offset,omitempty"`

    // Length (长度): READ 用; 0 默认 4096.
    Length uint32 `json:"length,omitempty"`

    // Data (数据): WRITE 用; 二进制数据.
    Data []byte `json:"data,omitempty"`

    // DataB64 (base64 数据): WRITE 用; 覆盖 Data.
    DataB64 string `json:"data_b64,omitempty"`

    // FileName (文件名): QUERY_DIRECTORY 用; 通配符如 "*" 或 "*.txt".
    FileName string `json:"file_name,omitempty"`

    // InfoClass (信息类): QUERY_INFO/QUERY_DIRECTORY 用; 如 37=IdBothDirectoryInformation.
    InfoClass uint8 `json:"info_class,omitempty"`

    // FileId (文件号): 全 0 表示使用上一个 CREATE 分配的 FileId; 非零覆盖.
    FileId [16]byte `json:"file_id,omitempty"`
}
```

### 5.1 FlowSpec 集成

在 `FlowSpec` 末尾追加：

```go
SMB *SMBConfig `json:"smb,omitempty"`
```

策略配置（`strategy_convert.go`）新增 `smb` 协议路由到 `internal/protocol/smb` 包。planner 根据每个操作的 OpType 查 §3.2 Command 表写入 SMB2 头偏移 12-13。

### 5.2 字段默认值汇总

| 字段 | 默认值 | 来源 |
|------|--------|------|
| Transport | "direct" | MS-SMB2 §2.1 |
| Dialects | ["0x0202","0x0210","0x0300","0x0302","0x0311"] | Windows 10 客户端典型集（含 SMB3.0） |
| SelectedDialect | Dialects 末位 | 假设服务端支持最高 |
| ClientGuid | 随机 16B | MS-SMB2 §2.2.1 |
| ServerGuid | 随机 16B | MS-SMB2 §2.2.1 |
| SecurityMode | 0x01 (SigningEnabled) | 默认开启签名能力，不强制 |
| ClientCapabilities | 0x03 (Encryption+DirLeasing)；SelectedDialect < 0x0300 时自动清 bit0（Encryption 在 SMB3 才有意义，0x0202/0x0210 下服务端忽略，Wireshark 显示能力与 dialect 不匹配） | Win10 默认 + dialect 降级 |
| AuthMechanism | "ntlm" | 最常见 |
| AuthRounds | 0 = 默认（ntlm→3 / anon/guest→1 / Kerberos→2） | 认证机制决定（V12） |
| TreeConnectShare | "\\server\share" | 占位 |
| FilePath | "file.txt" | 占位 |
| CreateDisposition | 1 (open) | 不创建新文件 |
| AccessMask | 0x00120089 | GENERIC_READ |
| FileAttributes | 0x80 (NORMAL) | 默认 |
| ShareAccess | 0x07 (RWX) | 默认共享 |
| MaxTransactSize | 65536 | 64KB |
| MaxReadSize | 1048576 | 1MB |
| MaxWriteSize | 1048576 | 1MB |
| PreauthIntegrityHashAlgorithms | [0x0001] (SHA-512) | SMB3.1.1 |
| PreauthIntegrityHashValue | 64B 全 0（占位） | SMB3.1.1 会话级累积哈希 |
| EncryptionAlgorithm | 0x0001 (AES-CCM) | SMB3.1.1 |
| Command | 按 §3.2 Command 表（每命令不同） | 写入 SMB2 头偏移 12-13 |
| Flags (请求) | 0x00000000 | 请求不设 SERVER_TO_REDIR |
| Flags (响应) | 0x00000001 | 响应必须设 bit0 SERVER_TO_REDIR |
| CreditCharge | 1（SMB 2.1+）/ 0（SMB 2.0.2） | MS-SMB2 §2.2.1.2 |

---

## §6. 包序列场景（HexDump S1-S15）

本章给出 15 个完整 HexDump 场景。每个场景包含：包序列总览表 + 关键 PDU 字节级 HexDump（NBSS 头 + SMB2 头 + 命令体）。所有偏移按 §3.1 SMB2 SYNC Header 标准 64 字节布局（ProtocolId=0、StructureSize=4、CreditCharge=6、Status=8、Command=12、CreditRequest=14、Flags=16、NextCommand=20、MessageId=24、Reserved=32、TreeId=36、SessionId=40、Signature=48）。

**HexDump 约定**：
- 每个 HexDump 块的偏移从 SMB2 PDU 起始算（不含 NBSS 头）；NBSS 头单独列出。
- 字节序全部 little-endian（LE），仅 NBSS 长度字段大端（BE）。
- `xx` 表示占位字节（随机/全 0）；`??` 表示长度依场景变化的可变字段。
- 签名 Signature 字段（偏移 48-63）默认全 0 占位。
- 请求包 Flags=0x00000000；响应包 Flags=0x00000001（bit0 SERVER_TO_REDIR）。

---

### S1. NEGOTIATE 协商阶段（默认 SMB3.1.1）

**场景**：客户端发起 NEGOTIATE，dialects=[0x0202,0x0210,0x0300,0x0302,0x0311]，服务端选中 0x0311。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | SessionId | TreeId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-----------|--------|-------|------|
| 1 | up | SYN | - | - | - | - | - | TCP 握手 #1 |
| 2 | down | SYN-ACK | - | - | - | - | - | TCP 握手 #2 |
| 3 | up | ACK | - | - | - | - | - | TCP 握手 #3 |
| 4 | up | PSH-ACK | NEGOTIATE req | 0 | 0 | 0 | 0x00000000 | 协商请求 |
| 5 | down | PSH-ACK | NEGOTIATE resp | 0 | 0 | 0 | 0x00000001 | 协商响应，DialectRevision=0x0311 |
| 6 | up | ACK | - | - | - | - | - | TCP ACK |

**PDU #4 NEGOTIATE req 字节级 HexDump**（NBSS 头 + SMB2 头 + 命令体）：

```
--- NBSS Header (4 bytes) ---
00 00 00 AC                              ; type=0x00, length=172 (BE, 64+36+10+2+46+2+12)

--- SMB2 Header (64 bytes, offset 0-63 from SMB2 PDU start) ---
FE 53 4D 42                              ; [0-3]   ProtocolId = 0xFE534D42
40 00                                    ; [4-5]   StructureSize = 64
01 00                                    ; [6-7]   CreditCharge = 1
00 00 00 00                              ; [8-11]  Status = 0 (请求)
00 00                                    ; [12-13] Command = 0x0000 (NEGOTIATE)
1F 00                                    ; [14-15] CreditRequest = 31
00 00 00 00                              ; [16-19] Flags = 0x00000000 (请求)
00 00 00 00                              ; [20-23] NextCommand = 0
00 00 00 00 00 00 00 00                  ; [24-31] MessageId = 0
00 00 00 00                              ; [32-35] Reserved = 0
00 00 00 00                              ; [36-39] TreeId = 0
00 00 00 00 00 00 00 00                  ; [40-47] SessionId = 0
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; [48-63] Signature = 全 0

--- NEGOTIATE Request Body (36 bytes fixed + dialects + contexts) ---
24 00                                    ; [0-1]   StructureSize = 36
05 00                                    ; [2-3]   DialectCount = 5
01 00                                    ; [4-5]   SecurityMode = 0x01 (SigningEnabled)
00 00                                    ; [6-7]   Reserved = 0
03 00 00 00                              ; [8-11]  Capabilities = 0x03 (Encryption|DirLeasing)
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; [12-27] ClientGuid (16B 随机)
70 00 00 00                              ; [28-31] NegotiateContextOffset = 112 (从 SMB2 头算，64+36+10+2)
02 00                                    ; [32-33] NegotiateContextCount = 2
00 00                                    ; [34-35] Reserved2 = 0

--- Dialects (10 bytes, 5 × uint16 LE) ---
02 02                                    ; 0x0202 SMB2.002
10 02                                    ; 0x0210 SMB2.1
00 03                                    ; 0x0300 SMB3.0
02 03                                    ; 0x0302 SMB3.0.2
11 03                                    ; 0x0311 SMB3.1.1

--- Padding (2 bytes, 8B 对齐) ---
00 00

--- NegotiateContextList (每个 context 8B 对齐，从 SMB2 头起算偏移 112 起) ---
; ContextType=0x0001 Preauth Integrity（8 头 + 38 Data = 46 字节）
01 00                                    ; ContextType = 0x0001
26 00                                    ; DataLength = 38
00 00 00 00                              ; Reserved
01 00                                    ; HashAlgorithmCount = 1
20 00                                    ; SaltLength = 32
01 00                                    ; HashAlgorithms[0] = 0x0001 (SHA-512)
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; Salt (32B 随机)
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx

; Padding (2 bytes, 8B 对齐：112+46=158 → 160)
00 00

; ContextType=0x0002 Encryption（8 头 + 4 Data = 12 字节）
02 00                                    ; ContextType = 0x0002
04 00                                    ; DataLength = 4
00 00 00 00                              ; Reserved
02 00                                    ; CipherCount = 2
01 00                                    ; Ciphers[0] = 0x0001 (AES-128-CCM)
02 00                                    ; Ciphers[1] = 0x0002 (AES-128-GCM)
```

**PDU #5 NEGOTIATE resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 01 3C                              ; type=0x00, length=316 (BE, 64+64+128+46+2+12)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
00 00                                    ; Command = 0x0000 (NEGOTIATE)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
00 00 00 00 00 00 00 00                  ; MessageId = 0
00 00 00 00                              ; Reserved = 0
00 00 00 00                              ; TreeId = 0
00 00 00 00 00 00 00 00                  ; SessionId = 0
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- NEGOTIATE Response Body (64 bytes fixed + SecurityBuffer + Contexts) ---
41 00                                    ; StructureSize = 65
01 00                                    ; SecurityMode = 0x01
11 03                                    ; DialectRevision = 0x0311
02 00                                    ; NegotiateContextCount = 2
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; ServerGuid (16B 随机)
03 00 00 00                              ; Capabilities = 0x03
00 00 01 00                              ; MaxTransactSize = 65536
00 00 10 00                              ; MaxReadSize = 1048576
00 00 10 00                              ; MaxWriteSize = 1048576
xx xx xx xx xx xx xx xx                  ; SystemTime (FILETIME)
xx xx xx xx xx xx xx xx                  ; BootTime (FILETIME)
80 00                                    ; SecurityBufferOffset = 128 (从 SMB2 头算，64 头 + 64 固定体)
80 00                                    ; SecurityBufferLength = 128 (GSS-API 占位)
00 01 00 00                              ; NegotiateContextOffset = 256 (从 SMB2 头算，128+128)

--- SecurityBuffer (128 bytes GSS-API/SPNEGO 占位，SMB2 头起算偏移 128-255) ---
xx xx ... (128 字节占位)

--- NegotiateContextList (每个 context 8B 对齐，SMB2 头起算偏移 256 起；同请求，Preauth + Encryption) ---
```

---

### S2. SESSION_SETUP 认证阶段（NTLM 三阶段）

**场景**：NEGOTIATE 后 NTLM 三阶段认证（AuthRounds=3）。SessionId 由服务端分配（如 0x0000000000000001）。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | SessionId | Status | Flags | 说明 |
|---|------|-----------|-----------|-----------|-----------|--------|-------|------|
| 1 | up | PSH-ACK | SESSION_SETUP req #1 | 1 | 0 | 0 | 0x00000000 | NTLMSSP_NEGOTIATE |
| 2 | down | PSH-ACK | SESSION_SETUP resp #1 | 1 | 1 | 0xC0000016 | 0x00000001 | NTLMSSP_CHALLENGE (MORE_PROCESSING_REQUIRED) |
| 3 | up | PSH-ACK | SESSION_SETUP req #2 | 2 | 1 | 0 | 0x00000000 | NTLMSSP_AUTH |
| 4 | down | PSH-ACK | SESSION_SETUP resp #2 | 2 | 1 | 0x00000000 | 0x00000001 | 认证成功（短 blob） |
| 5 | up | PSH-ACK | SESSION_SETUP req #3 | 3 | 1 | 0 | 0x00000000 | 最终确认（空 blob） |
| 6 | down | PSH-ACK | SESSION_SETUP resp #3 | 3 | 1 | 0x00000000 | 0x00000001 | 成功 |

**PDU #1 SESSION_SETUP req #1 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 A0                              ; type=0x00, length=160 (BE, 64+24+72)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
01 00                                    ; Command = 0x0001 (SESSION_SETUP)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
01 00 00 00 00 00 00 00                  ; MessageId = 1
00 00 00 00                              ; Reserved = 0
00 00 00 00                              ; TreeId = 0
00 00 00 00 00 00 00 00                  ; SessionId = 0 (尚未分配)
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- SESSION_SETUP Request Body (24 bytes fixed + SecurityBuffer) ---
19 00                                    ; StructureSize = 25
00                                       ; Flags = 0 (无 BINDING)
01                                       ; SecurityMode = 0x01
01 00 00 00                              ; Capabilities = 0x01 (DFS)
00 00 00 00                              ; Channel = 0 (None)
58 00                                    ; SecurityBufferOffset = 88 (从 SMB2 头算，64 头 + 24 固定体)
48 00                                    ; SecurityBufferLength = 72
00 00 00 00 00 00 00 00                  ; PreviousSessionId = 0

--- SecurityBuffer (72 bytes NTLMSSP_NEGOTIATE 占位) ---
4E 54 4C 4D 53 53 50 00                  ; "NTLMSSP\0"
01 00 00 00                              ; MessageType = 1 (NEGOTIATE)
97 82 08 E2                              ; Flags
xx xx xx xx                              ; DomainNameFields (Len/MaxLen/Offset)
xx xx xx xx                              ; WorkstationFields
xx xx xx xx xx xx xx xx                  ; Version
xx xx xx xx xx xx xx xx                  ; 占位
xx xx xx xx xx xx xx xx                  ; 占位
xx xx xx xx xx xx xx xx                  ; 占位
xx xx xx xx xx xx xx xx                  ; 占位
xx xx xx xx xx xx xx xx                  ; 占位
xx xx xx xx                              ; 占位
```

**PDU #2 SESSION_SETUP resp #1 字节级 HexDump**（STATUS_MORE_PROCESSING_REQUIRED）：

```
--- NBSS Header (4 bytes) ---
00 00 00 B8                              ; type=0x00, length=184 (BE, 64+8+112)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
16 00 00 C0                              ; Status = 0xC0000016 (MORE_PROCESSING_REQUIRED) LE
01 00                                    ; Command = 0x0001 (SESSION_SETUP)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
01 00 00 00 00 00 00 00                  ; MessageId = 1
00 00 00 00                              ; Reserved = 0
00 00 00 00                              ; TreeId = 0
01 00 00 00 00 00 00 00                  ; SessionId = 1 (服务端分配)
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- SESSION_SETUP Response Body (8 bytes fixed + SecurityBuffer) ---
09 00                                    ; StructureSize = 9
00 00                                    ; SessionFlags = 0
48 00                                    ; SecurityBufferOffset = 72 (从 SMB2 头算，64 头 + 8 固定体)
70 00                                    ; SecurityBufferLength = 112

--- SecurityBuffer (112 bytes NTLMSSP_CHALLENGE 占位) ---
4E 54 4C 4D 53 53 50 00                  ; "NTLMSSP\0"
02 00 00 00                              ; MessageType = 2 (CHALLENGE)
xx xx xx xx                              ; TargetNameFields
xx xx xx xx                              ; Flags
xx xx xx xx xx xx xx xx                  ; ServerChallenge (8B)
00 00 00 00 00 00 00 00                  ; Reserved
xx xx xx xx xx xx xx xx                  ; TargetInfoFields
xx xx xx xx xx xx xx xx                  ; Version
xx xx ... (剩余占位)
```

> **关键字段断言**：SessionId 在 SESSION_SETUP resp #1 偏移 40-47 = `01 00 00 00 00 00 00 00`（LE）；Status 在偏移 8-11 = `16 00 00 C0`（0xC0000016 LE）；Flags 在偏移 16-19 = `01 00 00 00`（SERVER_TO_REDIR）。

---

### S3. TREE_CONNECT 树连接阶段

**场景**：SESSION_SETUP 成功后，连接 `\\server\share`。TreeId 由服务端分配（如 1）。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | SessionId | TreeId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-----------|--------|-------|------|
| 1 | up | PSH-ACK | TREE_CONNECT req | 4 | 1 | 0 | 0x00000000 | 连接 \\server\share |
| 2 | down | PSH-ACK | TREE_CONNECT resp | 4 | 1 | 1 | 0x00000001 | ShareType=0 (DISK) |

**PDU #1 TREE_CONNECT req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 62                              ; type=0x00, length=98 (BE, 64+8+26)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
03 00                                    ; Command = 0x0003 (TREE_CONNECT)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
04 00 00 00 00 00 00 00                  ; MessageId = 4
00 00 00 00                              ; Reserved = 0
00 00 00 00                              ; TreeId = 0 (尚未分配)
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- TREE_CONNECT Request Body (8 bytes fixed + Path) ---
09 00                                    ; StructureSize = 9
00 00                                    ; Reserved = 0
48 00                                    ; PathOffset = 72 (64+8)
1A 00                                    ; PathLength = 26 (UTF-16LE 字节数, "\\server\share")

--- Path (26 bytes UTF-16LE) ---
5C 00 5C 00                              ; "\\" 
73 00 65 00 72 00 76 00 65 00 72 00      ; "server"
5C 00                                    ; "\"
73 00 68 00 61 00 72 00 65 00            ; "share"
```

**PDU #2 TREE_CONNECT resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 50                              ; type=0x00, length=80 (BE)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
03 00                                    ; Command = 0x0003 (TREE_CONNECT)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
04 00 00 00 00 00 00 00                  ; MessageId = 4
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1 (服务端分配)
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- TREE_CONNECT Response Body (16 bytes) ---
10 00                                    ; StructureSize = 16
00                                       ; ShareType = 0 (DISK)
00                                       ; Reserved = 0
00 00 00 00                              ; ShareFlags = 0
00 00 00 00                              ; Capabilities = 0
FF 1F 1F 00                              ; MaximalAccess = 0x001F1FFF
```

> **关键字段断言**：TreeId 在 TREE_CONNECT resp 偏移 36-39 = `01 00 00 00`（LE）；ShareType 在命令体偏移 2 = `00`（DISK）。

---

### S4. CREATE 文件打开阶段

**场景**：TREE_CONNECT 后打开 `file.txt`，CreateDisposition=1 (open)，获得 FileId。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | SessionId | TreeId | FileId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-----------|--------|--------|-------|------|
| 1 | up | PSH-ACK | CREATE req | 5 | 1 | 1 | - | 0x00000000 | 打开 file.txt |
| 2 | down | PSH-ACK | CREATE resp | 5 | 1 | 1 | 随机 | 0x00000001 | CreateAction=1 (opened) |

**PDU #1 CREATE req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 8A                              ; type=0x00, length=138 (BE, 64+56+16+2)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
05 00                                    ; Command = 0x0005 (CREATE)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
05 00 00 00 00 00 00 00                  ; MessageId = 5
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- CREATE Request Body (56 bytes fixed + Name) ---
39 00                                    ; StructureSize = 57
00                                       ; SecurityFlags = 0
00                                       ; RequestedOplockLevel = 0 (none)
02 00 00 00                              ; ImpersonationLevel = 2 (Impersonation)
00 00 00 00 00 00 00 00                  ; SmbCreateFlags = 0
00 00 00 00 00 00 00 00                  ; RootDirectoryFid = 0
89 00 12 00                              ; DesiredAccess = 0x00120089
80 00 00 00                              ; FileAttributes = 0x80 (NORMAL)
07 00 00 00                              ; ShareAccess = 0x07 (RWX)
01 00 00 00                              ; CreateDisposition = 1 (open)
00 00 00 00                              ; CreateOptions = 0
78 00                                    ; NameOffset = 120 (64+56)
10 00                                    ; NameLength = 16 ("file.txt" UTF-16LE = 8×2 = 16B)
00 00 00 00                              ; CreateContextsOffset = 0
00 00 00 00                              ; CreateContextsLength = 0

--- Name (16 bytes UTF-16LE, "file.txt") ---
66 00 69 00 6C 00 65 00 2E 00 74 00 78 00 74 00 ; "file.txt"
00 00                                    ; Padding (2B 对齐)
```

**PDU #2 CREATE resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 98                              ; type=0x00, length=152 (BE, 64+88)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
05 00                                    ; Command = 0x0005 (CREATE)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
05 00 00 00 00 00 00 00                  ; MessageId = 5
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- CREATE Response Body (88 bytes fixed) ---
59 00                                    ; StructureSize = 89
00                                       ; OplockLevel = 0
00                                       ; Flags = 0
01 00 00 00                              ; CreateAction = 1 (opened)
xx xx xx xx xx xx xx xx                  ; CreationTime (FILETIME)
xx xx xx xx xx xx xx xx                  ; LastAccessTime
xx xx xx xx xx xx xx xx                  ; LastWriteTime
xx xx xx xx xx xx xx xx                  ; ChangeTime
00 10 00 00 00 00 00 00                  ; AllocationSize = 4096
00 10 00 00 00 00 00 00                  ; EndOfFile = 4096
80 00 00 00                              ; FileAttributes = 0x80 (NORMAL)
00 00 00 00                              ; Reserved = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B 随机)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B 随机)
00 00 00 00                              ; CreateContextsOffset = 0
00 00 00 00                              ; CreateContextsLength = 0
```

> **关键字段断言**：FileId 在 CREATE resp 命令体偏移 64-79（16B）；NameOffset 在 CREATE req 命令体偏移 44-45 = `78 00`（120 LE）。

---

### S5. READ 读文件

**场景**：CREATE 后 READ 4096 字节，从 Offset=0 开始。FileId 复用 CREATE resp 分配的。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | FileId | Flags | 说明 |
|---|------|-----------|-----------|-----------|--------|-------|------|
| 1 | up | PSH-ACK | READ req | 6 | 复用 | 0x00000000 | Length=4096, Offset=0 |
| 2 | down | PSH-ACK | READ resp | 6 | - | 0x00000001 | DataLength=4096 |

**PDU #1 READ req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 71                              ; type=0x00, length=113 (BE, 64+48+1 Buffer)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
08 00                                    ; Command = 0x0008 (READ)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- READ Request Body (48 bytes fixed + 1B Buffer) ---
31 00                                    ; StructureSize = 49
00                                       ; Padding = 0
00                                       ; Flags = 0
00 10 00 00                              ; Length = 4096
00 00 00 00 00 00 00 00                  ; Offset = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
00 00 00 00                              ; MinimumCount = 0
00 00 00 00                              ; Channel = 0 (None)
00 00 00 00                              ; RemainingBytes = 0
00 00                                    ; ReadChannelInfoOffset = 0
00 00                                    ; ReadChannelInfoLength = 0
00                                       ; Buffer = 0 (空)
```

**PDU #2 READ resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 10 50                              ; type=0x00, length=4176 (BE, 64+16+4096)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
08 00                                    ; Command = 0x0008 (READ)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- READ Response Body (16 bytes fixed + Data) ---
11 00                                    ; StructureSize = 17
50                                       ; DataOffset = 80 (从 SMB2 头算，64 头 + 16 固定体)
00                                       ; Reserved = 0
00 10 00 00                              ; DataLength = 4096
00 00 00 00                              ; DataRemaining = 0
00 00 00 00                              ; Flags = 0

--- Data (4096 bytes) ---
xx xx xx xx ... (4096 字节文件内容)
```

> **关键字段断言**：DataOffset 在 READ resp 命令体偏移 2 = `50`（80）；DataLength 在偏移 4-7 = `00 10 00 00`（4096 LE）。

---

### S6. WRITE 写文件

**场景**：CREATE 后 WRITE 100 字节到 Offset=0。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | WRITE req | 6 | 0x00000000 | Length=100, Offset=0 |
| 2 | down | PSH-ACK | WRITE resp | 6 | 0x00000001 | Count=100 |

**PDU #1 WRITE req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 D4                              ; type=0x00, length=212 (BE, 64+48+100)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
09 00                                    ; Command = 0x0009 (WRITE)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- WRITE Request Body (48 bytes fixed + Data) ---
31 00                                    ; StructureSize = 49
70 00                                    ; DataOffset = 112 (64+48) LE
64 00 00 00                              ; Length = 100
00 00 00 00 00 00 00 00                  ; Offset = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
00 00 00 00                              ; Channel = 0 (None)
00 00 00 00                              ; RemainingBytes = 0
00 00                                    ; WriteChannelInfoOffset = 0
00 00                                    ; WriteChannelInfoLength = 0
00 00 00 00                              ; Flags = 0

--- Data (100 bytes) ---
xx xx xx xx ... (100 字节写入数据)
```

**PDU #2 WRITE resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 50                              ; type=0x00, length=80 (BE, 64+16)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
09 00                                    ; Command = 0x0009 (WRITE)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- WRITE Response Body (16 bytes) ---
11 00                                    ; StructureSize = 17
00 00                                    ; Reserved = 0
64 00 00 00                              ; Count = 100 (实际写入)
00 00 00 00                              ; Remaining = 0
00 00                                    ; WriteChannelInfoOffset = 0
00 00                                    ; WriteChannelInfoLength = 0
```

> **关键字段断言**：DataOffset 在 WRITE req 命令体偏移 2-3 = `70 00`（112 LE）；Count 在 WRITE resp 偏移 4-7 = `64 00 00 00`（100 LE）。

---

### S7. CLOSE 关闭句柄

**场景**：READ/WRITE 完成后 CLOSE 关闭 FileId。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | CLOSE req | 7 | 0x00000000 | 关闭 FileId |
| 2 | down | PSH-ACK | CLOSE resp | 7 | 0x00000001 | 返回文件属性 |

**PDU #1 CLOSE req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 58                              ; type=0x00, length=88 (BE, 64+24)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
06 00                                    ; Command = 0x0006 (CLOSE)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
07 00 00 00 00 00 00 00                  ; MessageId = 7
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- CLOSE Request Body (24 bytes) ---
18 00                                    ; StructureSize = 24
00 00                                    ; Flags = 0
00 00 00 00                              ; Reserved = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
```

**PDU #2 CLOSE resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 7C                              ; type=0x00, length=124 (BE, 64+60)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
06 00                                    ; Command = 0x0006 (CLOSE)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
07 00 00 00 00 00 00 00                  ; MessageId = 7
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- CLOSE Response Body (60 bytes) ---
3C 00                                    ; StructureSize = 60
00 00                                    ; Flags = 0
00 00 00 00                              ; Reserved = 0
xx xx xx xx xx xx xx xx                  ; CreationTime (FILETIME)
xx xx xx xx xx xx xx xx                  ; LastAccessTime
xx xx xx xx xx xx xx xx                  ; LastWriteTime
xx xx xx xx xx xx xx xx                  ; ChangeTime
00 10 00 00 00 00 00 00                  ; AllocationSize = 4096
00 10 00 00 00 00 00 00                  ; EndOfFile = 4096
80 00 00 00                              ; FileAttributes = 0x80 (NORMAL)
```

---

### S8. LOCK 文件锁

**场景**：CREATE 后对文件 [0, 4096) 加排他锁。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | LOCK req | 6 | 0x00000000 | 1 个 EXCLUSIVE_LOCK |
| 2 | down | PSH-ACK | LOCK resp | 6 | 0x00000001 | StructureSize=4 |

**PDU #1 LOCK req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 70                              ; type=0x00, length=112 (BE, 64+24+24，LOCK_ELEMENT 后无 padding)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
0A 00                                    ; Command = 0x000A (LOCK)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- LOCK Request Body (24 bytes fixed + Locks[]) ---
30 00                                    ; StructureSize = 48
01 00                                    ; LockCount = 1
00 00 00 00                              ; LockSequence = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)

--- LOCK_ELEMENT (24 bytes) ---
00 00 00 00 00 00 00 00                  ; Offset = 0
00 10 00 00 00 00 00 00                  ; Length = 4096
02 00 00 00                              ; Flags = 0x02 (EXCLUSIVE_LOCK)
00 00 00 00                              ; Reserved = 0
```

**PDU #2 LOCK resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 44                              ; type=0x00, length=68 (BE, 64+4)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
0A 00                                    ; Command = 0x000A (LOCK)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- LOCK Response Body (4 bytes) ---
04 00                                    ; StructureSize = 4
00 00                                    ; Reserved = 0
```

---

### S9. IOCTL 设备控制

**场景**：CREATE 后调用 FSCTL_DFS_GET_REFERRALS（CtlCode=0x00060194）。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | IOCTL req | 6 | 0x00000000 | CtlCode=0x00060194 |
| 2 | down | PSH-ACK | IOCTL resp | 6 | 0x00000001 | OutputBuffer 返回 referral |

**PDU #1 IOCTL req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 80                              ; type=0x00, length=128 (BE, 64+56+8)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
0B 00                                    ; Command = 0x000B (IOCTL)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- IOCTL Request Body (54 bytes fixed, 56 对齐 + InputBuffer) ---
39 00                                    ; StructureSize = 57
00 00                                    ; Reserved = 0
94 01 06 00                              ; CtlCode = 0x00060194 (FSCTL_DFS_GET_REFERRALS)
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
78 00 00 00                              ; InputOffset = 120 (64 头 + 56 固定体[54B+2B 对齐])
08 00 00 00                              ; InputCount = 8
00 00 00 00                              ; MaxInputResponse = 0
00 00 00 00                              ; OutputOffset = 0
00 00 00 00                              ; OutputCount = 0
00 10 00 00                              ; MaxOutputResponse = 4096
01 00 00 00                              ; Flags = 0x01 (IS_IOCTL)
00 00                                    ; Reserved2 = 0

--- InputBuffer (8 bytes) ---
xx xx xx xx xx xx xx xx                  ; 占位
```

---

### S10. QUERY_DIRECTORY 目录枚举

**场景**：CREATE 目录后 QUERY_DIRECTORY 列出 `*` 通配符下所有文件，FileInformationClass=37 (IdBothDirectoryInformation)。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | QUERY_DIRECTORY req | 6 | 0x00000000 | 通配符 `*` |
| 2 | down | PSH-ACK | QUERY_DIRECTORY resp | 6 | 0x00000001 | 2 个 ID_BOTH_DIR_INFO 条目 |

**PDU #1 QUERY_DIRECTORY req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 62                              ; type=0x00, length=98 (BE, 64+32+2)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
0E 00                                    ; Command = 0x000E (QUERY_DIRECTORY)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- QUERY_DIRECTORY Request Body (32 bytes fixed + FileName) ---
21 00                                    ; StructureSize = 33
25                                       ; FileInformationClass = 37 (IdBothDirectoryInformation)
00                                       ; Flags = 0
00 00 00 00                              ; FileIndex = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
60 00                                    ; FileNameOffset = 96 (从 SMB2 头算，64 头 + 32 固定体)
02 00                                    ; FileNameLength = 2 ("*" UTF-16LE = 2B)
00 10 00 00                              ; OutputBufferLength = 4096

--- FileName (2 bytes UTF-16LE, "*") ---
2A 00                                    ; "*"
```

**PDU #2 QUERY_DIRECTORY resp 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 01 30                              ; type=0x00, length=304 (BE, 64+8+116+116)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0 (SUCCESS)
0E 00                                    ; Command = 0x000E (QUERY_DIRECTORY)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- QUERY_DIRECTORY Response Body (8 bytes fixed + OutputBuffer) ---
09 00                                    ; StructureSize = 9
40 00                                    ; OutputBufferOffset = 64
xx xx xx xx                              ; OutputBufferLength (var)

--- ID_BOTH_DIR_INFO Entry #1 (固定体 100 字节 + FileName 16 字节 = 116 字节) ---
74 00 00 00                              ; NextEntryOffset = 116 (下一条目偏移，本条目 100+16)
00 00 00 00                              ; FileIndex = 0
xx xx xx xx xx xx xx xx                  ; CreationTime
xx xx xx xx xx xx xx xx                  ; LastAccessTime
xx xx xx xx xx xx xx xx                  ; LastWriteTime
xx xx xx xx xx xx xx xx                  ; ChangeTime
00 10 00 00 00 00 00 00                  ; EndOfFile = 4096
00 10 00 00 00 00 00 00                  ; AllocationSize = 4096
80 00 00 00                              ; FileAttributes = 0x80 (NORMAL)
00 00 00 00                              ; EaSize = 0
00 00                                    ; ShortNameLength = 0
00 00                                    ; Reserved
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; ShortName (24B 全 0)
01 00                                    ; FileId = 1
00 00                                    ; Reserved2
10 00 00 00                              ; FileNameLength = 16 ("file.txt" UTF-16LE = 8 字符 × 2 = 16B)
66 00 69 00 6C 00 65 00 2E 00 74 00 78 00 74 00 ; "file.txt" UTF-16LE (16B)

--- ID_BOTH_DIR_INFO Entry #2 (最后一条，固定体 100 字节 + FileName 16 字节 = 116 字节) ---
00 00 00 00                              ; NextEntryOffset = 0 (最后条目)
00 00 00 00                              ; FileIndex = 0
xx xx xx xx xx xx xx xx                  ; CreationTime
xx xx xx xx xx xx xx xx                  ; LastAccessTime
xx xx xx xx xx xx xx xx                  ; LastWriteTime
xx xx xx xx xx xx xx xx                  ; ChangeTime
00 10 00 00 00 00 00 00                  ; EndOfFile = 4096
00 10 00 00 00 00 00 00                  ; AllocationSize = 4096
80 00 00 00                              ; FileAttributes = 0x80 (NORMAL)
00 00 00 00                              ; EaSize = 0
00 00                                    ; ShortNameLength = 0
00 00                                    ; Reserved
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; ShortName (24B 全 0)
02 00                                    ; FileId = 2
00 00                                    ; Reserved2
10 00 00 00                              ; FileNameLength = 16 ("data.txt" UTF-16LE = 8 字符 × 2 = 16B)
64 00 61 00 74 00 61 00 2E 00 74 00 78 00 74 00 ; "data.txt" UTF-16LE (16B)
```

---

### S11. QUERY_INFO 查询文件信息

**场景**：CREATE 后 QUERY_INFO 查询 FileBasicInformation（InfoType=0, FileInfoClass=4）。

**包序列**：

| # | 方向 | TCP flags | SMB2 命令 | MessageId | Flags | 说明 |
|---|------|-----------|-----------|-----------|-------|------|
| 1 | up | PSH-ACK | QUERY_INFO req | 6 | 0x00000000 | FileBasicInfo |
| 2 | down | PSH-ACK | QUERY_INFO resp | 6 | 0x00000001 | 返回 40B FileBasicInfo |

**PDU #1 QUERY_INFO req 字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 69                              ; type=0x00, length=105 (BE, 64+40+1 Buffer)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
10 00                                    ; Command = 0x0010 (QUERY_INFO)
1F 00                                    ; CreditRequest = 31
00 00 00 00                              ; Flags = 0 (请求)
00 00 00 00                              ; NextCommand = 0
06 00 00 00 00 00 00 00                  ; MessageId = 6
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- QUERY_INFO Request Body (40 bytes fixed + InputBuffer) ---
29 00                                    ; StructureSize = 41
00                                       ; InfoType = 0 (File)
04                                       ; FileInfoClass = 4 (FileBasicInfo)
28 00 00 00                              ; OutputBufferLength = 40
68 00                                    ; InputBufferOffset = 104 (64+40)
00 00                                    ; Reserved = 0
00 00 00 00                              ; InputBufferLength = 0
00 00 00 00                              ; AdditionalInformation = 0
00 00 00 00                              ; Flags = 0
xx xx xx xx xx xx xx xx                  ; FileId.Persistent (8B)
xx xx xx xx xx xx xx xx                  ; FileId.Volatile (8B)
00                                       ; Buffer = 0 (空)
```

---

### S12. 多会话（M=2 并发）

**场景**：2 个独立会话并发，SessionId 通过原子计数器分配为 1 和 2，TreeId 在各自会话内从 1 开始。

**包序列**（两会话交织）：

| # | 方向 | 流 | SMB2 命令 | MessageId | SessionId | TreeId | 说明 |
|---|------|-----|-----------|-----------|-----------|--------|------|
| 1 | up | A | NEGOTIATE req | 0 | 0 | 0 | 会话 A 协商 |
| 2 | down | A | NEGOTIATE resp | 0 | 0 | 0 | DialectRevision=0x0311 |
| 3 | up | B | NEGOTIATE req | 0 | 0 | 0 | 会话 B 协商（独立 4-tuple） |
| 4 | down | B | NEGOTIATE resp | 0 | 0 | 0 | |
| 5 | up | A | SESSION_SETUP req #1 | 1 | 0 | 0 | A 开始认证 |
| 6 | down | A | SESSION_SETUP resp #1 | 1 | 1 | 0 | A 分配 SessionId=1 |
| 7 | up | B | SESSION_SETUP req #1 | 1 | 0 | 0 | B 开始认证 |
| 8 | down | B | SESSION_SETUP resp #1 | 1 | 2 | 0 | B 分配 SessionId=2（原子递增） |
| 9 | up | A | SESSION_SETUP req #2 | 2 | 1 | 0 | A NTLM_AUTH |
| 10 | down | A | SESSION_SETUP resp #2 | 2 | 1 | 0 | A 成功 |
| 11 | up | B | SESSION_SETUP req #2 | 2 | 2 | 0 | B NTLM_AUTH |
| 12 | down | B | SESSION_SETUP resp #2 | 2 | 2 | 0 | B 成功 |
| ... | ... | ... | ... | ... | ... | ... | 各自继续 TREE_CONNECT/CREATE/... |

> **SessionId 唯一性**：会话 A 的 SESSION_SETUP resp #1 偏移 40-47 SessionId = `01 00 00 00 00 00 00 00`；会话 B 的 SESSION_SETUP resp #1 偏移 40-47 SessionId = `02 00 00 00 00 00 00 00`。两会话独立 4-tuple（不同 TCP 连接），无 SessionId 冲突。

---

### S13. 多流关联（同会话多 TreeId）

**场景**：同一 SessionId 下连接 2 个共享（TreeId=1 和 TreeId=2），分别在两个共享上 CREATE 文件。

**包序列**（单会话）：

| # | 方向 | SMB2 命令 | MessageId | SessionId | TreeId | 说明 |
|---|------|-----------|-----------|-----------|--------|------|
| 1 | up | TREE_CONNECT req #1 | 4 | 1 | 0 | 连接 \\server\share1 |
| 2 | down | TREE_CONNECT resp #1 | 4 | 1 | 1 | 分配 TreeId=1 |
| 3 | up | TREE_CONNECT req #2 | 5 | 1 | 0 | 连接 \\server\share2 |
| 4 | down | TREE_CONNECT resp #2 | 5 | 1 | 2 | 分配 TreeId=2（会话内递增） |
| 5 | up | CREATE req (share1) | 6 | 1 | 1 | 在 share1 上打开 file1.txt |
| 6 | down | CREATE resp | 6 | 1 | 1 | FileId-A |
| 7 | up | CREATE req (share2) | 7 | 1 | 2 | 在 share2 上打开 file2.txt |
| 8 | down | CREATE resp | 7 | 1 | 2 | FileId-B |
| 9 | up | READ req (share1) | 8 | 1 | 1 | 用 FileId-A 读 |
| 10 | down | READ resp | 8 | 1 | 1 | DataLength=4096 |
| 11 | up | READ req (share2) | 9 | 1 | 2 | 用 FileId-B 读 |
| 12 | down | READ resp | 9 | 1 | 2 | DataLength=4096 |

> **TreeId 区分**：READ req #9 偏移 36-39 TreeId = `02 00 00 00`（LE，会话内第 2 个树）；READ req #8 偏移 36-39 = `01 00 00 00`。

---

### S14. 签名与加密

**场景**：SMB3.1.1 + SigningRequired=true，所有命令请求/响应 Flags |= 0x08（SIGNED），Signature 字段填占位（16B 非零）。部分 PDU 走 TRANSFORM_HEADER（52B）加密。

**包序列**（仅展示 NEGOTIATE 后的 SESSION_SETUP #1 签名 + 一条加密 WRITE）：

| # | 方向 | SMB2 命令 | MessageId | Flags | Signature | 说明 |
|---|------|-----------|-----------|-------|-----------|------|
| 1 | up | SESSION_SETUP req #1 | 1 | 0x00000008 | 占位 16B 非零 | SIGNED 请求 |
| 2 | down | SESSION_SETUP resp #1 | 1 | 0x00000009 | 占位 16B 非零 | SIGNED + SERVER_TO_REDIR 响应 |
| ... | ... | ... | ... | ... | ... | ... |
| 10 | up | (TRANSFORM_HEADER + 加密 WRITE req) | - | - | - | 52B 头 + 密文 |
| 11 | down | (TRANSFORM_HEADER + 加密 WRITE resp) | - | - | - | 52B 头 + 密文 |

**PDU #1 SESSION_SETUP req #1（签名版）字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 A0                              ; type=0x00, length=160 (BE, 64+24+72)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
00 00 00 00                              ; Status = 0
01 00                                    ; Command = 0x0001 (SESSION_SETUP)
1F 00                                    ; CreditRequest = 31
08 00 00 00                              ; Flags = 0x00000008 (SIGNED)
00 00 00 00                              ; NextCommand = 0
01 00 00 00 00 00 00 00                  ; MessageId = 1
00 00 00 00                              ; Reserved = 0
00 00 00 00                              ; TreeId = 0
00 00 00 00 00 00 00 00                  ; SessionId = 0
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; Signature (16B 占位非零)
```

> **Flags 断言**：偏移 16-19 = `08 00 00 00`（请求 SIGNED）或 `09 00 00 00`（响应 SIGNED+SERVER_TO_REDIR）。

**PDU #10 加密 WRITE req（TRANSFORM_HEADER 包裹）字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 01 0C                              ; type=0x00, length=268 (BE, 52+216 假设密文 216B)

--- TRANSFORM_HEADER (52 bytes, 替代原 SMB2 头) ---
FD 53 4D 42                              ; ProtocolId = 0xFD534D42 (加密标记)
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; Signature (16B AES-GCM 标签占位)
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx ; Nonce (16B 占位)
D8 00 00 00                              ; OriginalMessageSize = 216 (原 SMB2 头+体)
00 00                                    ; Reserved = 0
01 00                                    ; Flags = 0x0001 (Encrypted)
01 00 00 00 00 00 00 00                  ; SessionId = 1

--- EncryptedMessage (216 bytes 密文占位) ---
xx xx xx ... (216 字节密文，对应原 SMB2 头 64B + WRITE 体 48B + Data 104B)
```

> **TRANSFORM_HEADER 大小断言**：52 字节（非 57）；ProtocolId = `FD 53 4D 42`；Flags 偏移 42-43 = `01 00`（Encrypted=1）；SessionId 偏移 44-51。

---

### S15. 错误处理（CREATE 文件不存在）

**场景**：CREATE 打开不存在的文件，服务端返回 STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)。后续跳过 READ/WRITE/CLOSE，直接 TREE_DISCONNECT + LOGOFF。

**包序列**：

| # | 方向 | SMB2 命令 | MessageId | Status | Flags | 说明 |
|---|------|-----------|-----------|--------|-------|------|
| 1 | up | CREATE req | 5 | 0 | 0x00000000 | 打开 nonexistent.txt |
| 2 | down | CREATE resp | 5 | 0xC0000034 | 0x00000001 | OBJECT_NAME_NOT_FOUND |
| 3 | up | TREE_DISCONNECT req | 6 | 0 | 0x00000000 | 跳过 READ/CLOSE，直接拆解 |
| 4 | down | TREE_DISCONNECT resp | 6 | 0 | 0x00000001 | |
| 5 | up | LOGOFF req | 7 | 0 | 0x00000000 | |
| 6 | down | LOGOFF resp | 7 | 0 | 0x00000001 | |

**PDU #2 CREATE resp（错误）字节级 HexDump**：

```
--- NBSS Header (4 bytes) ---
00 00 00 48                              ; type=0x00, length=72 (BE, 64+8 错误响应体 8B)

--- SMB2 Header (64 bytes) ---
FE 53 4D 42                              ; ProtocolId
40 00                                    ; StructureSize = 64
01 00                                    ; CreditCharge = 1
34 00 00 C0                              ; Status = 0xC0000034 (OBJECT_NAME_NOT_FOUND) LE
05 00                                    ; Command = 0x0005 (CREATE)
1F 00                                    ; CreditResponse = 31
01 00 00 00                              ; Flags = 0x00000001 (SERVER_TO_REDIR)
00 00 00 00                              ; NextCommand = 0
05 00 00 00 00 00 00 00                  ; MessageId = 5
00 00 00 00                              ; Reserved = 0
01 00 00 00                              ; TreeId = 1
01 00 00 00 00 00 00 00                  ; SessionId = 1
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; Signature 全 0

--- CREATE Response Body (8 bytes 错误简化体) ---
59 00                                    ; StructureSize = 89 (CREATE 错误响应仍保持 89，与 §9.3 表一致)
00 00 00 00 00 00                        ; 6B 零（缩短体，对齐 §9.3 表）
```

> **错误断言**：Status 偏移 8-11 = `34 00 00 C0`（0xC0000034 LE）；CREATE 错误响应命令体 StructureSize 仍为 89（与 §9.3 表一致，错误响应只发头 + StructureSize + 必要零字段，不发完整 88 字节固定体）；后续 TREE_DISCONNECT Command = 0x0004 写入偏移 12-13；LOGOFF Command = 0x0002 写入偏移 12-13。

---

## §7. 测试用例

测试用例遵循 CLAUDE.md §Testing Policy 8 条强制规则：spec-driven（每条对应 §2-§6 的某个字段/状态机分支）、覆盖正向+负向+边界、断言可观察输出（包序列、字节、Direction、Command、Flags）。所有字节断言基于 §3.1 SMB2 SYNC Header 标准 64 字节布局（偏移：ProtocolId=0、StructureSize=4、CreditCharge=6、Status=8、Command=12、CreditRequest=14、Flags=16、NextCommand=20、MessageId=24、Reserved=32、TreeId=36、SessionId=40、Signature=48）。

### 7.1 协商阶段（T001-T020）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 SMB PDU 序列 | 期望字节/断言 |
|---------|------|----------------|-------------------|----------------|
| T001 | NEGOTIATE 默认 dialects | Dialects=[] (默认) | NEGOTIATE req + resp | req DialectCount=5；Dialects 数组含 02 02 / 10 02 / 00 03 / 02 03 / 11 03 |
| T002 | NEGOTIATE 自定义 dialects | Dialects=["0x0202","0x0210"] | req + resp | DialectCount=2；服务端选中 0x0210 |
| T003 | NEGOTIATE SMB 2.0.2 only | Dialects=["0x0202"] | req + resp | DialectRevision=0x0202；CreditCharge=0 (2.0.2 规则) |
| T004 | NEGOTIATE SMB3.1.1 + Preauth | Dialects=["0x0311"] | req + resp | NegotiateContextCount>=1；ContextType=0x0001 Preauth；HashAlgorithms=[0x0001] |
| T005 | NEGOTIATE SMB3.1.1 + Encryption ctx | Dialects=["0x0311"], EncryptionAlgorithm=0x0001 | req + resp | ContextType=0x0002 Encryption；Ciphers=[0x0001] |
| T006 | NEGOTIATE SecurityMode=SigningEnabled | SecurityMode=0x01 | req + resp | req SecurityMode 字节=01 |
| T007 | NEGOTIATE SecurityMode=SigningRequired | SigningRequired=true | req + resp | req SecurityMode 字节=03 (bit0+bit1) |
| T008 | NEGOTIATE ClientCapabilities=0x03 | ClientCapabilities=0x03 | req + resp | req Capabilities 字节=03 00 00 00 |
| T009 | NEGOTIATE ClientGuid 随机 | ClientGuid=全 0 (默认) | req + resp | req ClientGuid 16B 非全 0；两会话 ClientGuid 不同 |
| T010 | NEGOTIATE ClientGuid 固定 | ClientGuid=0x01...0x10 | req + resp | req ClientGuid = 01 02 03 ... 10 |
| T011 | NEGOTIATE resp DialectRevision | 默认 | resp | resp DialectRevision = 0x0311 (LE: 11 03) |
| T012 | NEGOTIATE resp ServerGuid 随机 | 默认 | resp | resp ServerGuid 16B 非全 0 |
| T013 | NEGOTIATE resp MaxTransactSize | MaxTransactSize=65536 | resp | resp MaxTransactSize = 00 00 01 00 (LE) |
| T014 | NEGOTIATE resp MaxReadSize | MaxReadSize=1048576 | resp | resp MaxReadSize = 00 00 10 00 (LE) |
| T015 | NEGOTIATE resp MaxWriteSize | MaxWriteSize=1048576 | resp | resp MaxWriteSize = 00 00 10 00 (LE) |
| T016 | NEGOTIATE resp SecurityBuffer 非空 | 默认 | resp | SecurityBufferLength > 0；SecurityBuffer 含 GSS-API 占位 |
| T017 | NEGOTIATE req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 00 00 (NEGOTIATE=0x0000 LE) |
| T018 | NEGOTIATE req Flags 字段 | 默认 | req | SMB2 头偏移 16-19 = 00 00 00 00 (请求不设 SERVER_TO_REDIR) |
| T019 | NEGOTIATE resp Flags 字段 | 默认 | resp | SMB2 头偏移 16-19 = 01 00 00 00 (SERVER_TO_REDIR bit0) |
| T020 | NEGOTIATE resp CreditResponse | 默认 | resp | SMB2 头偏移 14-15 非零（服务端授予信用） |

### 7.2 认证阶段（T021-T045）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T021 | SESSION_SETUP NTLM 三阶段 | AuthMechanism="ntlm", AuthRounds=3 | 3 对 req/resp | MessageId 1-3；resp #1 Status=0xC0000016 (MORE_PROCESSING_REQUIRED) |
| T022 | SESSION_SETUP NTLM 两阶段 | AuthRounds=2 | 2 对 req/resp | MessageId 1-2 |
| T023 | SESSION_SETUP Kerberos 两阶段 | AuthMechanism="kerberos", AuthRounds=2 | 2 对 req/resp | SecurityBlob 含 Kerberos 占位 (0x60 AP-REQ) |
| T024 | SESSION_SETUP anonymous 一阶段 | AuthMechanism="anonymous", AuthRounds=1 | 1 对 req/resp | SessionFlags.IsAnonymousSession=1 |
| T025 | SESSION_SETUP guest 一阶段 | AuthMechanism="guest", AuthRounds=1 | 1 对 req/resp | SessionFlags.IsGuest=1 |
| T026 | SESSION_SETUP req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 01 00 (SESSION_SETUP=0x0001 LE) |
| T027 | SESSION_SETUP req #1 SessionId=0 | 默认 | req #1 | SMB2 头偏移 40-47 = 00 00 00 00 00 00 00 00 (未分配) |
| T028 | SESSION_SETUP resp #1 SessionId 分配 | 默认 | resp #1 | SMB2 头偏移 40-47 非零（服务端分配，如 01 00 00 00 00 00 00 00） |
| T029 | SESSION_SETUP req #2 SessionId 复用 | 默认 | req #2 | SMB2 头偏移 40-47 == resp #1 的 SessionId |
| T030 | SESSION_SETUP resp #1 Status MORE_PROCESSING | 默认 NTLM | resp #1 | SMB2 头偏移 8-11 = 16 00 00 C0 (0xC0000016 LE) |
| T031 | SESSION_SETUP resp #2 Status SUCCESS | 默认 NTLM | resp #2 | SMB2 头偏移 8-11 = 00 00 00 00 |
| T032 | SESSION_SETUP SecurityBufferOffset | 默认 | req | 命令体偏移 12-13 = 58 00 (88 LE = 64+24) |
| T033 | SESSION_SETUP PreviousSessionId=0 | 默认 | req | 命令体偏移 16-23 = 00×8 |
| T034 | SESSION_SETUP PreviousSessionId 非零 | PreviousSessionId=0x1234（§5 配置字段） | req | 命令体偏移 16-23 = 34 12 00 00 00 00 00 00；仅多通道重连场景使用，独立会话填 0 |
| T035 | SESSION_SETUP resp SessionFlags | 默认 | resp | 命令体偏移 2-3 = 00 00 (无 Guest/Null/Encrypt) |
| T036 | SESSION_SETUP resp SessionFlags EncryptData | EncryptionRequired=true | resp | 命令体偏移 2-3 bit2=1 (0x04) |
| T037 | SESSION_SETUP Channel=None | Channel=0 | req | 命令体偏移 8-11 = 00 00 00 00 |
| T038 | SESSION_SETUP Capabilities DFS | Capabilities=0x01 | req | 命令体偏移 4-7 = 01 00 00 00 |
| T039 | SESSION_SETUP SecurityMode SigningEnabled | SecurityMode=0x01 | req | 命令体偏移 3 = 01 |
| T040 | SESSION_SETUP SecurityMode SigningRequired | SigningRequired=true | req | 命令体偏移 3 = 03 |
| T041 | SESSION_SETUP 自定义 SecurityBlob | SecurityBlob=0x60 0x82 ... | req | SecurityBuffer 内容=用户 blob；SecurityBufferLength 匹配 |
| T042 | SESSION_SETUP 失败 LOGON_FAILURE | ErrorResponseStatus=0xC000006D, ErrorOnCommand="session_setup" | resp #N Status=0xC000006D | SMB2 头偏移 8-11 = 6D 00 00 C0；后续 LOGOFF |
| T043 | SESSION_SETUP 多轮 NTLM CHALLENGE | AuthRounds=3 | resp #1 | SecurityBuffer 含 NTLMSSP_CHALLENGE (MessageType=2) |
| T044 | SESSION_SETUP NTLM_AUTH | AuthRounds=3 | req #2 | SecurityBuffer 含 NTLMSSP_AUTH (MessageType=3) |
| T045 | SESSION_SETUP 跳过认证 | IncludeAuth=false | 无 SESSION_SETUP | TREE_CONNECT 直接跟 NEGOTIATE |

### 7.3 树连接阶段（T046-T060）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T046 | TREE_CONNECT 默认共享 | TreeConnectShare="\\server\share" | req + resp | Path UTF-16LE = 5C 00 5C 00 ... 5C 00 ... |
| T047 | TREE_CONNECT IPC$ 命名管道 | TreeConnectShare="\\server\IPC$" | req + resp | resp ShareType=0x01 (PIPE) |
| T048 | TREE_CONNECT req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 03 00 (TREE_CONNECT=0x0003 LE) |
| T049 | TREE_CONNECT req TreeId=0 | 默认 | req | SMB2 头偏移 36-39 = 00 00 00 00 (尚未分配) |
| T050 | TREE_CONNECT resp TreeId 分配 | 默认 | resp | SMB2 头偏移 36-39 非零（服务端分配，如 01 00 00 00） |
| T051 | TREE_CONNECT req SessionId 复用 | 默认 | req | SMB2 头偏移 40-47 == SESSION_SETUP resp 的 SessionId |
| T052 | TREE_CONNECT PathOffset | 默认 | req | 命令体偏移 4-5 = 48 00 (72 LE = 64+8) |
| T053 | TREE_CONNECT PathLength | TreeConnectShare="\\server\share" (13 字符) | req | 命令体偏移 6-7 = 1A 00 (26 LE = 13×2) |
| T054 | TREE_CONNECT resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 10 00 (16 LE) |
| T055 | TREE_CONNECT resp ShareType DISK | TreeConnectShare="\\server\share" | resp | 命令体偏移 2 = 00 (DISK) |
| T056 | TREE_CONNECT resp ShareType PIPE | TreeConnectShare="\\server\IPC$" | resp | 命令体偏移 2 = 01 (PIPE) |
| T057 | TREE_CONNECT resp ShareType PRINT | ShareType=2 | resp | 命令体偏移 2 = 02 (PRINT) |
| T058 | TREE_CONNECT resp MaximalAccess | 默认 | resp | 命令体偏移 12-15 = FF 1F 1F 00 (0x001F1FFF LE) |
| T059 | TREE_CONNECT 失败 BAD_NETWORK_NAME | ErrorOnCommand="tree_connect" | resp Status=0xC00000CC | SMB2 头偏移 8-11 = CC 00 00 C0；跳过 CREATE |
| T060 | TREE_CONNECT 跳过 | IncludeTreeConnect=false | 无 TREE_CONNECT | CREATE 直接跟 SESSION_SETUP (TreeId=0) |

### 7.4 文件操作阶段（T061-T090）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T061 | CREATE 默认打开 | FilePath="file.txt", CreateDisposition=1 | req + resp | req NameOffset=120 (78 00)；Name="file.txt" UTF-16LE |
| T062 | CREATE req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 05 00 (CREATE=0x0005 LE) |
| T063 | CREATE req StructureSize | 默认 | req | 命令体偏移 0-1 = 39 00 (57 LE) |
| T064 | CREATE req ImpersonationLevel | ImpersonationLevel=2 | req | 命令体偏移 4-7 = 02 00 00 00 |
| T065 | CREATE req DesiredAccess | AccessMask=0x00120089 | req | 命令体偏移 24-27 = 89 00 12 00 |
| T066 | CREATE req FileAttributes | FileAttributes=0x80 | req | 命令体偏移 28-31 = 80 00 00 00 |
| T067 | CREATE req ShareAccess | ShareAccess=0x07 | req | 命令体偏移 32-35 = 07 00 00 00 |
| T068 | CREATE req CreateDisposition open | CreateDisposition=1 | req | 命令体偏移 36-39 = 01 00 00 00 |
| T069 | CREATE req CreateDisposition create | CreateDisposition=2 | req | 命令体偏移 36-39 = 02 00 00 00 |
| T070 | CREATE req CreateOptions | CreateOptions=0 | req | 命令体偏移 40-43 = 00 00 00 00 |
| T071 | CREATE req NameOffset | 默认 | req | 命令体偏移 44-45 = 78 00 (120 LE = 64+56) |
| T072 | CREATE req NameLength | FilePath="file.txt" (8 字符) | req | 命令体偏移 46-47 = 10 00 (16 LE = 8×2) |
| T073 | CREATE req TreeId 复用 | 默认 | req | SMB2 头偏移 36-39 == TREE_CONNECT resp 的 TreeId |
| T074 | CREATE resp FileId 分配 | 默认 | resp | 命令体偏移 64-79 (16B FileId) 非全 0 |
| T075 | CREATE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 59 00 (89 LE) |
| T076 | CREATE resp CreateAction opened | CreateDisposition=1 | resp | 命令体偏移 4-7 = 01 00 00 00 (opened) |
| T077 | CREATE resp EndOfFile | 默认 | resp | 命令体偏移 48-55 = 文件大小 LE |
| T078 | CREATE resp FileAttributes NORMAL | FileAttributes=0x80 | resp | 命令体偏移 56-59 = 80 00 00 00 |
| T079 | CREATE 失败 OBJECT_NAME_NOT_FOUND | ErrorOnCommand="create" | resp Status=0xC0000034 | SMB2 头偏移 8-11 = 34 00 00 C0；跳过 READ/WRITE/CLOSE |
| T080 | CREATE 失败 OBJECT_NAME_COLLISION | CreateDisposition=2 (create), 文件已存在 | resp Status=0xC0000035 | SMB2 头偏移 8-11 = 35 00 00 C0 |
| T081 | READ 默认 | Operations=[{OpType:"read", Offset:0, Length:4096}] | req + resp | req Length=4096 (00 10 00 00)；resp DataLength=4096 |
| T082 | READ req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 08 00 (READ=0x0008 LE) |
| T083 | READ req StructureSize | 默认 | req | 命令体偏移 0-1 = 31 00 (49 LE) |
| T084 | READ req Length | Length=4096 | req | 命令体偏移 4-7 = 00 10 00 00 |
| T085 | READ req Offset | Offset=0 | req | 命令体偏移 8-15 = 00×8 |
| T086 | READ req FileId 复用 | 默认 | req | 命令体偏移 16-31 == CREATE resp 的 FileId |
| T087 | READ resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 11 00 (17 LE) |
| T088 | READ resp DataOffset | 默认 | resp | 命令体偏移 2 = 50 (80 = 64 头 + 16 固定体) |
| T089 | READ resp DataLength | Length=4096 | resp | 命令体偏移 4-7 = 00 10 00 00 |
| T090 | READ 失败 END_OF_FILE | Offset 超出 EOF | resp Status=0xC0000020 | SMB2 头偏移 8-11 = 20 00 00 C0 |

### 7.5 写入与关闭（T091-T110）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T091 | WRITE 默认 | Operations=[{OpType:"write", Offset:0, Data:100B}] | req + resp | req Length=100 (64 00 00 00)；resp Count=100 |
| T092 | WRITE req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 09 00 (WRITE=0x0009 LE) |
| T093 | WRITE req StructureSize | 默认 | req | 命令体偏移 0-1 = 31 00 (49 LE) |
| T094 | WRITE req DataOffset | 默认 | req | 命令体偏移 2-3 = 70 00 (112 LE = 64+48) |
| T095 | WRITE req Length | Data=100B | req | 命令体偏移 4-7 = 64 00 00 00 |
| T096 | WRITE req Offset | Offset=0 | req | 命令体偏移 8-15 = 00×8 |
| T097 | WRITE req FileId 复用 | 默认 | req | 命令体偏移 16-31 == CREATE resp 的 FileId |
| T098 | WRITE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 11 00 (17 LE) |
| T099 | WRITE resp Count | Data=100B | resp | 命令体偏移 4-7 = 64 00 00 00 (100 LE) |
| T100 | WRITE DataOffset 对齐 112 | 默认 | req | 命令体偏移 2-3 = 70 00 (无 72 字节对齐要求) |
| T101 | CLOSE 默认 | Operations=[{OpType:"close"}] 或末尾 | req + resp | req FileId 复用；resp FileAttributes 返回 |
| T102 | CLOSE req Command 字段 | 默认 | req | SMB2 头偏移 12-13 = 06 00 (CLOSE=0x0006 LE) |
| T103 | CLOSE req StructureSize | 默认 | req | 命令体偏移 0-1 = 18 00 (24 LE) |
| T104 | CLOSE req FileId 复用 | 默认 | req | 命令体偏移 8-23 == CREATE resp 的 FileId |
| T105 | CLOSE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 3C 00 (60 LE) |
| T106 | CLOSE resp EndOfFile | 默认 | resp | 命令体偏移 48-55 = 文件大小 LE |
| T107 | WRITE_THROUGH 标志 | Operations=[{OpType:"write", Flags:0x01}] | req | 命令体偏移 44-47 = 01 00 00 00 |
| T108 | READ MinimumCount | Operations=[{OpType:"read", MinimumCount:1024}] | req | 命令体偏移 32-35 = 00 04 00 00 |
| T109 | WRITE 大数据分段 | Data=10KB, MSS=1460 | req 多 TCP 段 | SMB2 PDU 单条但 TCP 分多段；PDU 总长 > MSS |
| T110 | READ 大数据分段 | Length=10KB | resp 多 TCP 段 | resp DataLength=10240；TCP 分多段 |

### 7.6 状态机与序列（T111-T125）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T111 | 完整会话默认 | 默认 NTLM+1 READ | 27 包 | TCP 3 + NEGOTIATE 2 + SESSION_SETUP 6 + TREE_CONNECT 2 + CREATE 2 + READ 2 + CLOSE 2 + TREE_DISCONNECT 2 + LOGOFF 2 + TCP 4 = 27 |
| T112 | 完整会话 NTLM + 2 操作 | Operations=[read, write] | 29 包 | 19 + 6 + 4 = 29 |
| T113 | 完整会话 Kerberos | AuthMechanism="kerberos" | 25 包 | 19 + 4 + 2 = 25 |
| T114 | 完整会话 anonymous | AuthMechanism="anonymous" | 23 包 | 19 + 2 + 2 = 23 |
| T115 | MessageId 单调递增 | 默认 | 全序列 | SMB2 头偏移 24-31 每个请求递增 1 |
| T116 | MessageId 请求=响应 | 默认 | 每对 | req MessageId == resp MessageId |
| T117 | NEGOTIATE MessageId=0 | 默认 | req | SMB2 头偏移 24-31 = 00×8 |
| T118 | TREE_CONNECT MessageId | AuthRounds=3 | req | SMB2 头偏移 24-31 = 04 00 00 00 00 00 00 00 |
| T119 | CREATE MessageId | AuthRounds=3 | req | SMB2 头偏移 24-31 = 05 00 00 00 00 00 00 00 |
| T120 | LOGOFF MessageId | AuthRounds=3, N=1 | req | SMB2 头偏移 24-31 = 09 00 00 00 00 00 00 00（= 5+N+3 = 5+1+3 = 9） |
| T121 | 跳过 NEGOTIATE | IncludeNegotiate=false | 无 NEGOTIATE | 第一个 SMB2 PDU 是 SESSION_SETUP，MessageId=0 |
| T122 | 跳过 TREE_CONNECT | IncludeTreeConnect=false | 无 TREE_CONNECT | CREATE 直接跟 SESSION_SETUP，TreeId=0 |
| T123 | 跳过拆解 | IncludeTeardown=false | 无 TREE_DISCONNECT/LOGOFF | 最后一个 SMB2 PDU 是 CLOSE/READ |
| T124 | SMB PDU 数 NTLM+1READ | 默认 | 全序列 | 20 个 SMB PDU (10 对) |
| T125 | SMB PDU 数 NTLM+2OP | Operations=[read,write] | 全序列 | 22 个 SMB PDU (11 对) |

### 7.7 异常路径（T126-T140）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T126 | NEGOTIATE 错误 | ErrorResponseStatus=0xC000000D, ErrorOnCommand="negotiate" | resp Status=0xC000000D | 直接 TCP teardown，无 LOGOFF |
| T127 | SESSION_SETUP 错误 | ErrorOnCommand="session_setup" | resp Status=错误 | 仅 LOGOFF，无 TREE_DISCONNECT |
| T128 | TREE_CONNECT 错误 | ErrorOnCommand="tree_connect" | resp Status=0xC00000CC | 仅 LOGOFF，无 TREE_DISCONNECT |
| T129 | CREATE 错误 | ErrorOnCommand="create" | resp Status=0xC0000034 | TREE_DISCONNECT + LOGOFF |
| T130 | READ 错误 | ErrorOnCommand="read" | resp Status=错误 | CLOSE + TREE_DISCONNECT + LOGOFF |
| T131 | WRITE 错误 | ErrorOnCommand="write" | resp Status=错误 | CLOSE + TREE_DISCONNECT + LOGOFF |
| T132 | CLOSE 错误 | ErrorOnCommand="close" | resp Status=错误 | TREE_DISCONNECT + LOGOFF |
| T133 | TREE_DISCONNECT 错误 | ErrorOnCommand="tree_disconnect" | resp Status=错误 | 仅 LOGOFF |
| T134 | LOGOFF 错误 | ErrorOnCommand="logoff" | resp Status=错误 | 直接 TCP teardown |
| T135 | NEGOTIATE 错误后无后续 | ErrorOnCommand="negotiate" | 无 SESSION_SETUP | 跳过所有后续命令 |
| T136 | SESSION_SETUP LOGON_FAILURE | ErrorResponseStatus=0xC000006D, ErrorOnCommand="session_setup" | resp Status=0xC000006D | SMB2 头偏移 8-11 = 6D 00 00 C0 |
| T137 | CREATE 错误后 TREE_DISCONNECT Command | ErrorOnCommand="create" | TREE_DISCONNECT req | SMB2 头偏移 12-13 = 04 00 (TREE_DISCONNECT=0x0004) |
| T138 | CREATE 错误后 LOGOFF Command | ErrorOnCommand="create" | LOGOFF req | SMB2 头偏移 12-13 = 02 00 (LOGOFF=0x0002) |
| T139 | 错误响应 Flags | 任意错误 | resp | SMB2 头偏移 16-19 = 01 00 00 00 (SERVER_TO_REDIR 仍设) |
| T140 | 错误响应仍设 SessionId | ErrorOnCommand="create" | resp | SMB2 头偏移 40-47 = 已分配的 SessionId |
| T140a | CREATE 错误响应体 StructureSize | ErrorOnCommand="create" | CREATE resp | 命令体偏移 0-1 = 59 00（89 LE，错误响应仍保持 CREATE 的 StructureSize，见 §9.3 表与 S15） |
| T140b | SESSION_SETUP 错误响应体 StructureSize | ErrorOnCommand="session_setup" | resp | 命令体偏移 0-1 = 09 00（9 LE，§9.3 表）；SecurityBufferOffset/Length=0 |

### 7.8 边界场景（T141-T155）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T141 | 空文件名 | FilePath="" | req | NameLength=0；NameOffset 仍 = 120 |
| T142 | 超长文件名 | FilePath=255 字符 | req | NameLength=510（255×2）；PDU 总长 = 64+56+510+2 = 632B；NBSS = 00 00 02 78（632 BE） |
| T143 | 超长路径 | TreeConnectShare="\\server\verylongsharename20"（30 字符） | req | PathLength=60（30×2）；PDU 总长 = 64+8+60 = 132B；NBSS = 00 00 84（132 BE） |
| T144 | READ Length=0 | Operations=[{OpType:"read", Length:0}] | req | Length=0；resp DataLength=0 |
| T145 | READ Offset=EOF | Offset=文件大小 | resp | Status=0xC0000020 (END_OF_FILE) |
| T146 | WRITE Length=0 | Operations=[{OpType:"write", Data:[]}] | req | Length=0；resp Count=0 |
| T147 | DialectCount=1 | Dialects=["0x0311"] | req | DialectCount=1 |
| T148 | DialectCount=5 | 默认 | req | DialectCount=5 |
| T149 | AuthRounds=0 默认按机制换算 | AuthRounds=0, AuthMechanism="ntlm" | 3 对 SESSION_SETUP | 0 表示默认：ntlm→3、kerberos→2、anonymous/guest→1（与 V12 一致） |
| T150 | MaxTransactSize 最小 | MaxTransactSize=1024 | resp | resp MaxTransactSize = 00 04 00 00 |
| T151 | MaxReadSize 最小 | MaxReadSize=512 | resp | resp MaxReadSize = 00 02 00 00 |
| T152 | NBSS 长度最大 | 假设 PDU=16777215B（2^24-1） | NBSS | NBSS length = FF FF FF (2^24-1)；PDU 超 16777215B 时被 Validate 拒绝（见 V32-V34） |
| T153 | 单 dialect 0x0202 | Dialects=["0x0202"] | req + resp | CreditCharge=0 (2.0.2 规则)；无 NegotiateContextList |
| T154 | FileId 全 0 默认 | FileId=全 0 | CREATE resp | FileId 由 planner 随机分配，非全 0 |
| T155 | FileId 用户指定 | FileId=0x01...0x10 | CREATE resp | FileId = 用户指定值 |

### 7.9 多会话与多流（T156-T170）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T156 | 2 并发会话 SessionId 唯一 | Count=2 | 两会话 | 会话 A SessionId=1；会话 B SessionId=2 (atomic) |
| T157 | 10 并发会话 SessionId 唯一 | Count=10 | 10 会话 | SessionId 1-10 互不重复 |
| T158 | 多会话 TreeId 独立 | Count=2 | 两会话 | 会话 A TreeId=1；会话 B TreeId=1 (跨会话可重复) |
| T159 | 同会话多 TreeId | 2 个 TREE_CONNECT | 单会话 | TreeId 1 和 2 (会话内递增) |
| T160 | 同会话多 FileId | 2 个 CREATE | 单会话 | FileId-A 和 FileId-B 不同 |
| T161 | 多会话 ClientGuid 不同 | Count=2 | 两会话 | ClientGuid A != ClientGuid B |
| T162 | 多会话 ServerGuid 不同 | Count=2 | 两会话 | ServerGuid A != ServerGuid B |
| T163 | 并发 -race 无数据竞争 | Count=10, -race | 10 会话 | go test -race 无 DATA RACE 报告 |
| T164 | 并发 MessageId 独立 | Count=2 | 两会话 | 会话 A MessageId 0-9；会话 B MessageId 0-9 (各自独立) |
| T165 | 多流 READ 区分 TreeId | 同会话 2 TreeId | READ #1 | SMB2 头偏移 36-39 = TreeId-A |
| T166 | 多流 READ 区分 FileId | 同会话 2 FileId | READ #2 | 命令体偏移 16-31 = FileId-B |
| T167 | 多会话独立 4-tuple | Count=2 | 两会话 | TCP 流 src_port/dst_port 不同 |
| T168 | SessionId 原子计数器 | Count=100 | 100 会话 | SessionId 1-100 无重复无遗漏 |
| T169 | TreeId 会话内递增 | 同会话 3 TREE_CONNECT | 单会话 | TreeId 1, 2, 3 |
| T170 | FileId 随机唯一 | Count=100, 1 CREATE 每会话 | 100 会话 | 100 个 FileId 互不相同（概率上） |
| T170a | 并发多会话 TreeId 互不串扰 | Count=2, 并发（-race） | 两会话 | 会话 A 的 TREE_CONNECT resp TreeId=1；会话 B 的 resp TreeId=1（各自从 1 递增，无全局串扰；两会话内后续命令 TreeId 各自保持） |

### 7.10 SMB3 高级（T171-T185）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T171 | SMB3.1.1 Preauth Integrity | Dialects=["0x0311"] | NEGOTIATE | NegotiateContextList 含 ContextType=0x0001 |
| T172 | Preauth HashAlgorithms SHA-512 | PreauthIntegrityHashAlgorithms=[0x0001] | NEGOTIATE req | HashAlgorithms[0]=0x0001 |
| T173 | Preauth Salt 随机 | 默认 | NEGOTIATE req | Salt 32B 非全 0；两会话 Salt 不同 |
| T174 | SMB3.1.1 Encryption ctx | Dialects=["0x0311"] | NEGOTIATE | ContextType=0x0002；Ciphers=[0x0001,0x0002] |
| T175 | EncryptionAlgorithm AES-CCM | EncryptionAlgorithm=0x0001 | NEGOTIATE | Ciphers 含 0x0001 |
| T176 | EncryptionAlgorithm AES-GCM | EncryptionAlgorithm=0x0002 | NEGOTIATE | Ciphers 含 0x0002 |
| T177 | EncryptionRequired SessionFlags | EncryptionRequired=true | SESSION_SETUP resp | SessionFlags bit2=1 (EncryptData) |
| T178 | TRANSFORM_HEADER 大小 52 | EncryptionRequired=true, 加密 WRITE | 加密 PDU | TRANSFORM_HEADER 52B (非 57) |
| T179 | TRANSFORM_HEADER ProtocolId | 同上 | 加密 PDU | 偏移 0-3 = FD 53 4D 42 (0xFD534D42) |
| T180 | TRANSFORM_HEADER Flags | 同上 | 加密 PDU | 偏移 42-43 = 01 00 (Encrypted=1) |
| T181 | TRANSFORM_HEADER SessionId | 同上 | 加密 PDU | 偏移 44-51 = SessionId LE |
| T182 | TRANSFORM_HEADER OriginalMessageSize | 同上 | 加密 PDU | 偏移 36-39 = 原始消息字节数 LE |
| T183 | SigningRequired Flags SIGNED | SigningRequired=true | 所有 req/resp | Flags bit3=1 (SIGNED)；偏移 16-19 = 08 00 00 00 (req) 或 09 00 00 00 (resp) |
| T184 | Signature 占位非零 | SigningRequired=true | 所有 req/resp | 偏移 48-63 16B 占位非全 0 |
| T185 | PreauthIntegrityHashValue 64B | 默认 | 占位 | PreauthIntegrityHashValue 字段 64B 全 0 (占位) |

### 7.11 集成测试（T186-T195）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T186 | E2E: Plan → Worker → PCAP | T001 spec | PCAP 含 27 包 | tshark 解析显示 SMB2 协议；包 4=NEGOTIATE req, 包 5=NEGOTIATE resp |
| T187 | E2E: tshark 解析 SMB2 头 | T001 spec | tshark 输出 | smb2.cmd 字段正确（NEGOTIATE=0x00, SESSION_SETUP=0x01, ...） |
| T188 | E2E: tshark 解析 Command | T111 spec | tshark 输出 | 每个包 smb2.cmd 与 §3.2 表一致 |
| T189 | E2E: tshark 解析 Flags | T111 spec | tshark 输出 | 请求包 smb2.flags.server_to_redir=0；响应包=1 |
| T190 | E2E: tshark 解析 SessionId | T111 spec | tshark 输出 | SESSION_SETUP resp 后所有包 smb2.session_id 非零 |
| T191 | E2E: tshark 解析 TreeId | T111 spec | tshark 输出 | TREE_CONNECT resp 后所有包 smb2.tree_id 非零 |
| T192 | E2E: tshark 解析 MessageId | T111 spec | tshark 输出 | smb2.msg_id 单调递增 0-9 |
| T193 | E2E: 真实 NIC 发送 | T111 spec, enp135s0f0np0 | NIC 发出 27 包 | tcpdump 抓包与生成 PCAP 一致；**依赖硬件：无 enp135s0f0np0 网卡的环境（如 CI）跳过，用环境变量（如 SMB_NIC_TEST=1）显式开启** |
| T194 | E2E: NBSS 头正确 | T111 spec | tshark | 包 4 NBSS length == SMB2 PDU 字节数 |
| T195 | E2E: TCP 握手/挥手 | T111 spec | PCAP | 包 1-3 TCP 握手；最后 4 包 TCP 挥手 |
| T195a | E2E: 失败 spec 全链路拒绝 | Dialects=["0x9999"]（触发 V1 错误） | Plan() 返回错误 | 任务失败（非 completed-0 包）；错误消息含 V1 文案 "dialect 0x9999 不在 MS-SMB2 §3.2.1 允许列表"；无任何 SMB PDU 生成 |

### 7.12 字段级字节断言（T196-T210）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T196 | SMB2 头偏移 0-3 ProtocolId | 任意 PDU | 全部 PDU | 偏移 0-3 = FE 53 4D 42 |
| T197 | SMB2 头偏移 4-5 StructureSize | 任意 PDU | 全部 PDU | 偏移 4-5 = 40 00 (64 LE) |
| T198 | SMB2 头偏移 6-7 CreditCharge | SMB 2.1+ | req | 偏移 6-7 = 01 00 (默认 1) |
| T199 | SMB2 头偏移 6-7 CreditCharge 2.0.2 | Dialects=["0x0202"] | req | 偏移 6-7 = 00 00 (2.0.2 reserved) |
| T200 | SMB2 头偏移 8-11 Status 请求 | 任意请求 | req | 偏移 8-11 = 00 00 00 00 |
| T201 | SMB2 头偏移 8-11 Status 成功响应 | 任意成功响应 | resp | 偏移 8-11 = 00 00 00 00 |
| T202 | SMB2 头偏移 8-11 Status 错误响应 | ErrorOnCommand（ErrorResponseStatus 取 §3.26 表某错误码） | resp | 偏移 8-11 = 该 NT 状态码 LE（ErrorResponseStatus 必须为 §3.26 表 14 个之一，见 V30） |
| T203 | SMB2 头偏移 12-13 Command NEGOTIATE | 默认 | NEGOTIATE req | 偏移 12-13 = 00 00 |
| T204 | SMB2 头偏移 12-13 Command SESSION_SETUP | 默认 | SESSION_SETUP req | 偏移 12-13 = 01 00 |
| T205 | SMB2 头偏移 12-13 Command CREATE | 默认 | CREATE req | 偏移 12-13 = 05 00 |
| T206 | SMB2 头偏移 12-13 Command READ | 默认 | READ req | 偏移 12-13 = 08 00 |
| T207 | SMB2 头偏移 16-19 Flags 请求 | 默认 | req | 偏移 16-19 = 00 00 00 00 |
| T208 | SMB2 头偏移 16-19 Flags 响应 | 默认 | resp | 偏移 16-19 = 01 00 00 00 |
| T209 | SMB2 头偏移 24-31 MessageId | 默认 | NEGOTIATE req | 偏移 24-31 = 00×8 (MessageId=0) |
| T210 | SMB2 头偏移 36-39 TreeId | 默认 | TREE_CONNECT resp | 偏移 36-39 非零 (服务端分配) |

### 7.13 字段级字节断言续（T211-T225）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T211 | SMB2 头偏移 40-47 SessionId | 默认 | SESSION_SETUP resp #1 | 偏移 40-47 非零 (服务端分配) |
| T212 | SMB2 头偏移 48-63 Signature | 默认 | 任意 PDU | 偏移 48-63 = 16B 全 0 (占位) |
| T213 | SMB2 头偏移 14-15 CreditRequest | 默认 | req | 偏移 14-15 非零 (请求授予数) |
| T214 | SMB2 头偏移 14-15 CreditResponse | 默认 | resp | 偏移 14-15 非零 (授予数) |
| T215 | SMB2 头偏移 20-23 NextCommand | 默认 | 任意 PDU | 偏移 20-23 = 00 00 00 00 (单命令) |
| T216 | SMB2 头偏移 32-35 Reserved | 默认 | 同步 PDU | 偏移 32-35 = 00 00 00 00 |
| T217 | TREE_CONNECT resp TreeId 偏移 | 默认 | resp | TreeId 在 SMB2 头偏移 36-39 (非 28) |
| T218 | SESSION_SETUP resp SessionId 偏移 | 默认 | resp | SessionId 在 SMB2 头偏移 40-47 (非 32) |
| T219 | NEGOTIATE req MessageId 偏移 | 默认 | req | MessageId 在 SMB2 头偏移 24-31 (非 16) |
| T220 | CREATE req NameOffset | 默认 | req | 命令体偏移 44-45 = 78 00 (120 LE) |
| T221 | WRITE req DataOffset | 默认 | req | 命令体偏移 2-3 = 70 00 (112 LE) |
| T222 | READ resp DataOffset | 默认 | resp | 命令体偏移 2 = 50 (80 = 64 头 + 16 固定体) |
| T223 | NEGOTIATE resp SecurityBufferOffset | 默认 | resp | 命令体偏移 56-57 = 80 00 (128 LE = 64 头 + 64 固定体) |
| T224 | QUERY_DIRECTORY resp OutputBufferOffset | 默认 | resp | 命令体偏移 2-3 = 40 00 (64 LE) |
| T225 | TRANSFORM_HEADER 偏移 0-3 | 加密 PDU | 加密 PDU | 偏移 0-3 = FD 53 4D 42 (0xFD534D42) |

### 7.14 Validate 负向（T226-T240）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 Validate 错误 |
|---------|------|----------------|-------------------|
| T226 | Dialects 含非法值 | Dialects=["0x9999"] | "dialect 0x9999 不在 MS-SMB2 §3.2.1 允许列表（dialect 0x0202 起算）" |
| T227 | Dialects 空但 SelectedDialect 非空 | Dialects=[], SelectedDialect="0x0202" | "SelectedDialect 必须在 Dialects 列表中" |
| T228 | AuthMechanism 非法 | AuthMechanism="digest" | "auth_mechanism 必须是 ntlm/kerberos/anonymous/guest" |
| T229 | AuthRounds 与 AuthMechanism 不匹配 | AuthMechanism="anonymous", AuthRounds=3 | "anonymous 认证只能 1 轮" |
| T230 | AuthRounds 超范围 | AuthRounds=10 | "AuthRounds 必须 1-3（0 表示默认）" |
| T230a | ntlm + AuthRounds=1 非法 | AuthMechanism="ntlm", AuthRounds=1 | "ntlm 认证只能 2 或 3 轮" |
| T231 | CreateDisposition 超范围 | CreateDisposition=9 | "CreateDisposition 必须 0-5" |
| T232 | TreeConnectShare 格式错 | TreeConnectShare="share" | "TreeConnectShare 必须是 UNC 路径 \\\\server\\share" |
| T233 | Operations OpType 非法 | Operations=[{OpType:"delete"}] | "OpType 必须是 read/write/close/query_directory/query_info/set_info/flush/echo" |
| T234 | ErrorOnCommand 非法 | ErrorOnCommand="foo" | "ErrorOnCommand 必须是 negotiate/session_setup/tree_connect/create/read/write/close/tree_disconnect/logoff" |
| T235 | ErrorResponseStatus 非法 | ErrorResponseStatus=0x12345678（不在 §3.26 表） | "ErrorResponseStatus 必须是已知 NT 状态码（§3.26 表 14 个之一）" |
| T236 | MaxTransactSize 超限 | MaxTransactSize=0xFFFFFFFF | "MaxTransactSize 超过 16777215 (24 位 NBSS 上限)" |
| T237 | FileId 长度错 | FileId=[15]byte | "FileId 必须 16 字节" |
| T238 | ClientGuid 长度错 | ClientGuid=[15]byte | "ClientGuid 必须 16 字节" |
| T239 | Dialects 含 SMB1 | Dialects=["NT LM 0.12"] | "SMB1 dialect 字符串不支持，必须用 0x0202+ 数值" |
| T240 | SelectedDialect 不在 Dialects | Dialects=["0x0202"], SelectedDialect="0x0311" | "SelectedDialect 必须在 Dialects 列表中" |

### 7.15 查询与锁（T241-T255）

| 用例 ID | 场景 | 输入 spec 要点 | 期望序列 | 期望字节/断言 |
|---------|------|----------------|----------|----------------|
| T241 | QUERY_DIRECTORY 默认 | Operations=[{OpType:"query_directory", FileName:"*"}] | req + resp | req FileInformationClass=37 (25); FileName="*" UTF-16LE |
| T242 | QUERY_DIRECTORY req Command | 默认 | req | SMB2 头偏移 12-13 = 0E 00 (QUERY_DIRECTORY=0x000E LE) |
| T243 | QUERY_DIRECTORY req StructureSize | 默认 | req | 命令体偏移 0-1 = 21 00 (33 LE) |
| T244 | QUERY_DIRECTORY req FileInformationClass | InfoClass=37 | req | 命令体偏移 2 = 25 (37) |
| T245 | QUERY_DIRECTORY req FileNameOffset | 默认 | req | 命令体偏移 24-25 = 60 00 (96 LE = 64 头 + 32 固定体) |
| T246 | QUERY_DIRECTORY resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 09 00 (9 LE) |
| T247 | QUERY_DIRECTORY resp OutputBufferOffset | 默认 | resp | 命令体偏移 2-3 = 40 00 (64 LE) |
| T248 | QUERY_INFO req Command | 默认 | req | SMB2 头偏移 12-13 = 10 00 (QUERY_INFO=0x0010 LE) |
| T249 | QUERY_INFO req StructureSize | 默认 | req | 命令体偏移 0-1 = 29 00 (41 LE) |
| T250 | QUERY_INFO req InfoType | InfoType=0 (File) | req | 命令体偏移 2 = 00 |
| T251 | QUERY_INFO req FileInfoClass | FileInfoClass=4 (FileBasicInfo) | req | 命令体偏移 3 = 04 |
| T252 | QUERY_INFO resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 09 00 (9 LE) |
| T253 | LOCK req Command | 默认 | req | SMB2 头偏移 12-13 = 0A 00 (LOCK=0x000A LE) |
| T254 | LOCK req StructureSize | 默认 | req | 命令体偏移 0-1 = 30 00 (48 LE) |
| T255 | LOCK_ELEMENT Flags EXCLUSIVE | Flags=0x02 | req | LOCK_ELEMENT 偏移 16-19 = 02 00 00 00 |

### 7.16 NBSS 与传输层（T256-T270）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T256 | NBSS 头 type=0x00 | 默认 | 所有 PDU | NBSS 偏移 0 = 00 (Session Message) |
| T257 | NBSS 长度 BE | 默认 | 所有 PDU | NBSS 偏移 1-3 大端序长度 |
| T258 | NBSS 长度匹配 SMB2 PDU | 默认 | 所有 PDU | NBSS length == SMB2 PDU 字节数 |
| T259 | NBSS 长度 200 | PDU=200B | NBSS | NBSS = 00 00 C8 (200 BE) |
| T260 | NBSS 长度 268 | PDU=268B | NBSS | NBSS = 00 01 0C (268 BE) |
| T261 | Transport direct 默认 | Transport="" | 端口 445 | dst_port=445 |
| T262 | Transport netbios | Transport="netbios" | 端口 139 | dst_port=139 |
| T263 | NBSS 关闭前缀 | Transport="direct" | 所有 PDU | NBSS 前缀存在 (4B) |
| T264 | TCP 3-way 握手 | 默认 | 包 1-3 | SYN / SYN-ACK / ACK |
| T265 | TCP 4-way 挥手 | 默认 | 末尾 4 包 | FIN / ACK / FIN / ACK |
| T266 | TCP PSH-ACK 承载 SMB2 | 默认 | SMB2 PDU 包 | TCP flags=0x18 (PSH-ACK) |
| T267 | MSS 分段 | PDU > 1460B | 多 TCP 段 | 单个 SMB2 PDU 跨多 TCP 包 |
| T268 | TCP seq/ack 递增 | 默认 | 全序列 | seq 按字节数递增；ack=对端 seq+payload |
| T269 | NBSS 长度最大 | PDU=16777215B（2^24-1） | NBSS | NBSS = FF FF FF (2^24-1)；超过则 Validate 拒绝 |
| T270 | NBSS 长度 0 | 空 PDU (理论) | NBSS | NBSS = 00 00 00 (实际不会出现) |

### 7.17 命令体结构断言（T271-T285）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T271 | NEGOTIATE req StructureSize | 默认 | req | 命令体偏移 0-1 = 24 00 (36 LE) |
| T272 | NEGOTIATE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 41 00 (65 LE) |
| T273 | SESSION_SETUP req StructureSize | 默认 | req | 命令体偏移 0-1 = 19 00 (25 LE) |
| T274 | SESSION_SETUP resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 09 00 (9 LE) |
| T275 | TREE_CONNECT req StructureSize | 默认 | req | 命令体偏移 0-1 = 09 00 (9 LE) |
| T276 | TREE_CONNECT resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 10 00 (16 LE) |
| T277 | CREATE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 59 00 (89 LE) |
| T278 | CLOSE req StructureSize | 默认 | req | 命令体偏移 0-1 = 18 00 (24 LE) |
| T279 | CLOSE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 3C 00 (60 LE) |
| T280 | READ req StructureSize | 默认 | req | 命令体偏移 0-1 = 31 00 (49 LE) |
| T281 | READ resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 11 00 (17 LE) |
| T282 | WRITE req StructureSize | 默认 | req | 命令体偏移 0-1 = 31 00 (49 LE) |
| T283 | WRITE resp StructureSize | 默认 | resp | 命令体偏移 0-1 = 11 00 (17 LE) |
| T284 | TREE_DISCONNECT StructureSize | 默认 | req/resp | 命令体偏移 0-1 = 04 00 (4 LE) |
| T285 | LOGOFF StructureSize | 默认 | req/resp | 命令体偏移 0-1 = 04 00 (4 LE) |

### 7.18 综合与回归（T286-T300）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T286 | 完整会话字节级核对 | T111 spec | 全序列 | 所有 SMB2 头偏移 0-3 = FE 53 4D 42；偏移 4-5 = 40 00 |
| T287 | 完整会话 Command 序列 | T111 spec | 全序列 | Command 序列: 00 01 01 01 03 05 08 06 04 02 (NEGOTIATE/SESSION_SETUP×3/TREE_CONNECT/CREATE/READ/CLOSE/TREE_DISCONNECT/LOGOFF) |
| T288 | 完整会话 Flags 序列 | T111 spec | 全序列 | 请求 Flags=0；响应 Flags=0x01 (SERVER_TO_REDIR) |
| T289 | 完整会话 MessageId 序列 | T111 spec | 全序列 | 0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9 (10 对) |
| T290 | 完整会话 SessionId 持久 | T111 spec | 全序列 | SESSION_SETUP resp 后所有 PDU SessionId 相同 |
| T291 | 完整会话 TreeId 持久 | T111 spec | 全序列 | TREE_CONNECT resp 后所有 PDU TreeId 相同 |
| T292 | 完整会话 FileId 持久 | T111 spec | 全序列 | CREATE resp 后 READ/CLOSE FileId 相同 |
| T293 | NTLM 三阶段 SecurityBlob 变化 | AuthRounds=3 | 3 对 | req #1 NEGOTIATE (type=1); resp #1 CHALLENGE (type=2); req #2 AUTH (type=3) |
| T294 | NEGOTIATE 含 Preauth ctx | Dialects=["0x0311"] | req | NegotiateContextCount>=1；NegotiateContextOffset 8B 对齐 |
| T295 | NEGOTIATE 不含 Preauth ctx | Dialects=["0x0202"] | req | NegotiateContextCount=0；NegotiateContextOffset=0 |
| T296 | CREATE 后 READ FileId 偏移 | T111 spec | READ req | READ 命令体偏移 16-31 == CREATE resp 命令体偏移 64-79 |
| T297 | TREE_CONNECT Path UTF-16LE | TreeConnectShare="\\server\share" | req | Path = 5C 00 5C 00 73 00 65 00 ... (UTF-16LE) |
| T298 | CREATE Name UTF-16LE | FilePath="file.txt" | req | Name = 66 00 69 00 6C 00 65 00 2E 00 74 00 78 00 74 00 |
| T299 | 错误响应仍设 Flags | ErrorOnCommand="create" | CREATE resp | SMB2 头偏移 16-19 = 01 00 00 00 (SERVER_TO_REDIR 仍设) |
| T300 | 错误响应 Command 字段 | ErrorOnCommand="create" | CREATE resp | SMB2 头偏移 12-13 = 05 00 (Command 仍为 CREATE) |

### 7.19 dialect 与能力协商（T301-T315）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T301 | dialect 0x0202 CreditCharge=0 | Dialects=["0x0202"] | req | SMB2 头偏移 6-7 = 00 00 |
| T302 | dialect 0x0210 CreditCharge=1 | Dialects=["0x0210"] | req | SMB2 头偏移 6-7 = 01 00 |
| T303 | dialect 0x0300 CreditCharge=1 | Dialects=["0x0300"] | req | SMB2 头偏移 6-7 = 01 00 |
| T304 | dialect 0x0311 CreditCharge=1 | Dialects=["0x0311"] | req | SMB2 头偏移 6-7 = 01 00 |
| T305 | ClientCapabilities 0x00 | ClientCapabilities=0 | req | 命令体偏移 8-11 = 00 00 00 00 |
| T305a | 0x0202 响应 CreditCharge=0 | Dialects=["0x0202"] | 所有 resp | 偏移 6-7 = 00 00（与请求一致，SMB 2.0.2 响应也不消耗信用） |
| T305b | 0x0202 响应链 CreditCharge 恒 0 | Dialects=["0x0202"]，完整会话 | 所有 resp | NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/READ/CLOSE/TREE_DISCONNECT/LOGOFF resp 偏移 6-7 全部 = 00 00 |
| T305c | 0x0202 能力降级 | Dialects=["0x0202"], ClientCapabilities=0x03（默认） | req | 命令体偏移 8-11 = 02 00 00 00（SelectedDialect < 0x0300 时自动清 bit0 Encryption，保留 bit1 DirLeasing，见 §5.2） |
| T305d | 0x0311 能力不降级 | Dialects=["0x0311"], ClientCapabilities=0x03（默认） | req | 命令体偏移 8-11 = 03 00 00 00（SMB3.1.1 保留 bit0+bit1） |
| T306 | ClientCapabilities 0x03 | ClientCapabilities=0x03 | req | 命令体偏移 8-11 = 03 00 00 00 |
| T307 | ServerCapabilities 0x03 | ServerCapabilities=0x03 | resp | 命令体偏移 24-27 = 03 00 00 00 |
| T308 | NEGOTIATE resp DialectRevision 0x0311 | Dialects=["0x0311"] | resp | 命令体偏移 4-5 = 11 03 |
| T309 | NEGOTIATE resp DialectRevision 0x0202 | Dialects=["0x0202"] | resp | 命令体偏移 4-5 = 02 02 |
| T310 | SMB3.1.1 NegotiateContextOffset 8B 对齐 | Dialects=["0x0311"] | req | NegotiateContextOffset % 8 == 0 |
| T311 | Preauth SaltLength=32 | 默认 | req | SaltLength = 20 00 (32 LE) |
| T312 | Encryption CipherCount=2 | 默认 | req | CipherCount = 02 00 |
| T313 | Compression ctx 不实现 | 默认 | req | NegotiateContextCount 不含 0x0003 |
| T314 | dialect 0x0311 必须有 Preauth | Dialects=["0x0311"] | req | NegotiateContextList 含 ContextType=0x0001 |
| T315 | dialect 0x0202 无 NegotiateContext | Dialects=["0x0202"] | req | NegotiateContextCount=0；NegotiateContextOffset=0 |

---

**用例总数**：324 条（T001-T315 + T230a + T305a + T305b + T305c + T305d + T195a + T170a + T140a + T140b），覆盖：
- §7.1 协商阶段：20 条
- §7.2 认证阶段：25 条
- §7.3 树连接：15 条
- §7.4 文件操作：30 条
- §7.5 写入与关闭：20 条
- §7.6 状态机与序列：15 条
- §7.7 异常路径：17 条（含 T140a/T140b 错误响应体 StructureSize 断言）
- §7.8 边界场景：15 条
- §7.9 多会话与多流：16 条（含 T170a 并发 TreeId 隔离）
- §7.10 SMB3 高级：15 条
- §7.11 集成测试：11 条（含 T195a 失败 spec 注入）
- §7.12 字段级字节断言：15 条
- §7.13 字段级字节断言续：15 条
- §7.14 Validate 负向：16 条（含 T230a ntlm+AuthRounds=1）
- §7.15 查询与锁：15 条
- §7.16 NBSS 与传输层：15 条
- §7.17 命令体结构断言：15 条
- §7.18 综合与回归：15 条
- §7.19 dialect 与能力协商：19 条（含 T305a/T305b 0x0202 响应 CreditCharge=0、T305c/T305d 能力降级）

---

## §8. Validate 规则

`SMBConfig.Validate()` 在 `Plan()` 之前调用，返回错误则拒绝该 FlowSpec。规则按 MS-SMB2 spec 与 CLAUDE.md §Testing Policy 推导。

### 8.1 协商阶段规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V1 | Dialects 元素必须在允许列表 [0x0202, 0x0210, 0x0300, 0x0302, 0x0311] | "dialect %s 不在 MS-SMB2 §3.2.1 允许列表（dialect 0x0202 起算）" |
| V2 | Dialects 不能含 SMB1 字符串（"NT LM 0.12"） | "SMB1 dialect 字符串不支持，必须用 0x0202+ 数值" |
| V3 | SelectedDialect 必须在 Dialects 列表中（若两者都设置） | "SelectedDialect 必须在 Dialects 列表中" |
| V4 | Dialects 为空时按默认 5 元素填充 | （自动填充，不报错） |
| V5 | ClientGuid 必须 16 字节 | "ClientGuid 必须 16 字节" |
| V6 | ServerGuid 必须 16 字节 | "ServerGuid 必须 16 字节" |
| V7 | SecurityMode 仅 bit0/bit1 可设 | "SecurityMode 仅 bit0(SigningEnabled)/bit1(SigningRequired) 可设" |
| V8 | ClientCapabilities 仅 bit0-2 可设 | "ClientCapabilities 仅 bit0(Encryption)/bit1(DirLeasing)/bit2(Multichannel) 可设" |
| V9 | Dialects=["0x0311"] 时 NegotiateContextList 必须含 Preauth Integrity (ContextType=0x0001) | "SMB3.1.1 dialect 必须含 Preauth Integrity 协商上下文" |
| V10 | PreauthIntegrityHashAlgorithms 仅可含 0x0001 (SHA-512) | "PreauthIntegrityHashAlgorithms 仅支持 0x0001 (SHA-512)" |

### 8.2 认证阶段规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V11 | AuthMechanism 必须在 [ntlm, kerberos, anonymous, guest] | "auth_mechanism 必须是 ntlm/kerberos/anonymous/guest" |
| V12 | AuthRounds 为 0 表示默认（按机制换算：ntlm→3、kerberos→2、anonymous/guest→1）；显式非 0 时必须在 1-3 | "AuthRounds 必须 1-3（0 表示默认）" |
| V13 | AuthMechanism=anonymous 时 AuthRounds 必须 0（默认 1）或显式 1 | "anonymous 认证只能 1 轮" |
| V14 | AuthMechanism=guest 时 AuthRounds 必须 0（默认 1）或显式 1 | "guest 认证只能 1 轮" |
| V15 | AuthMechanism=kerberos 时 AuthRounds 必须 0（默认 2）或显式 2 | "kerberos 认证只能 2 轮" |
| V16 | AuthMechanism=ntlm 时 AuthRounds 必须 0（默认 3）或显式 2/3；显式 1 非法 | "ntlm 认证只能 2 或 3 轮" |
| V17 | SecurityBlob 设置时覆盖 AuthMechanism 自动生成 | （不报错，警告日志） |

### 8.3 树连接规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V18 | TreeConnectShare 必须是 UNC 路径格式 `\\server\share` | "TreeConnectShare 必须是 UNC 路径 \\\\server\\share" |
| V19 | ShareType 必须 0-2 | "ShareType 必须 0(DISK)/1(PIPE)/2(PRINT)" |
| V20 | TreeConnectShare 含 `IPC$` 时 ShareType 自动设为 1 (PIPE) | （自动设置，不报错） |

### 8.4 文件操作规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V21 | CreateDisposition 必须 0-5 | "CreateDisposition 必须 0-5" |
| V22 | FileId 必须 16 字节 | "FileId 必须 16 字节" |
| V23 | Operations OpType 必须在 [read, write, close, query_directory, query_info, set_info, flush, echo] | "OpType 必须是 read/write/close/query_directory/query_info/set_info/flush/echo" |
| V24 | Operations 为空时按默认 [{OpType:"read", Offset:0, Length:4096}] 填充 | （自动填充，不报错） |
| V25 | READ 操作 Length=0 时允许（测试空读） | （不报错） |
| V26 | WRITE 操作 Data 与 DataB64 不可同时设置 | "Data 与 DataB64 不可同时设置" |
| V27 | WRITE 操作 DataB64 设置时必须合法 base64 | "DataB64 必须是合法 base64 字符串" |

### 8.5 错误注入规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V28 | ErrorOnCommand 必须在 [negotiate, session_setup, tree_connect, create, read, write, close, tree_disconnect, logoff] | "ErrorOnCommand 必须是 negotiate/session_setup/tree_connect/create/read/write/close/tree_disconnect/logoff" |
| V29 | ErrorResponseStatus 非零时 ErrorOnCommand 必须设置 | "ErrorResponseStatus 非零时 ErrorOnCommand 必须指定哪条命令返回错误" |
| V30 | ErrorResponseStatus 必须是 §3.26 表的 14 个已知 NT 状态码之一（0x00000000 或 0xC0 开头的 13 个错误码） | "ErrorResponseStatus 必须是已知 NT 状态码（§3.26 表 14 个之一）" |
| V31 | ErrorOnCommand 设置时 ErrorResponseStatus 必须非零 | "ErrorOnCommand 设置时 ErrorResponseStatus 必须非零" |

### 8.6 业务控制规则

| # | 规则 | 错误消息 |
|---|------|----------|
| V32 | MaxTransactSize 不超过 16777215 (2^24-1，NBSS 长度上限) | "MaxTransactSize 超过 16777215 (24 位 NBSS 上限)" |
| V33 | MaxReadSize 不超过 16777215 | "MaxReadSize 超过 16777215" |
| V34 | MaxWriteSize 不超过 16777215 | "MaxWriteSize 超过 16777215" |
| V35 | Transport 必须是 "direct" 或 "netbios" | "Transport 必须是 direct 或 netbios" |
| V36 | EncryptionAlgorithm 必须 0x0001 或 0x0002 | "EncryptionAlgorithm 必须 0x0001(AES-CCM) 或 0x0002(AES-GCM)" |
| V37 | EncryptionRequired=true 时 Dialects 必须含 0x0300+ | "EncryptionRequired 需要 SMB3.0+ dialect" |

---

## §9. 错误处理

### 9.1 错误响应生成

`ErrorResponseStatus` 非零时，planner 在 `ErrorOnCommand` 指定的命令生成错误响应：

1. 该命令的**请求**正常生成（Command/MessageId/SessionId/TreeId/FileId 全部正确）。
2. 该命令的**响应**Status 字段填 `ErrorResponseStatus`，命令体缩短为最小错误体（StructureSize **保持该命令的正常值** + 必要字段，见 §9.3 表；如 CREATE 错误体 StructureSize 仍为 89）。
3. 后续命令按 §4.2 跳过规则表决定是否生成。

### 9.2 错误响应 SMB2 头字段

错误响应的 SMB2 头字段填充规则：
- **ProtocolId**：0xFE534D42（正常）
- **StructureSize**：64（正常）
- **CreditCharge**：与请求相同（通常 1）
- **Status**：ErrorResponseStatus（NT 状态码 LE）
- **Command**：与请求相同（如 CREATE 错误则 Command=0x0005）
- **CreditResponse**：服务端授予数（通常 31）
- **Flags**：0x00000001（SERVER_TO_REDIR，错误响应仍是响应）
- **NextCommand**：0（单命令）
- **MessageId**：与请求相同
- **Reserved**：0
- **TreeId**：与请求相同（若已分配）
- **SessionId**：与请求相同（若已分配）
- **Signature**：全 0 占位（不签名错误响应）

### 9.3 错误响应命令体

错误响应命令体缩短为最小结构（仅 StructureSize + 必要字段）：

| 命令 | 错误响应体大小 | 字段 |
|------|----------------|------|
| NEGOTIATE | 4 字节 | StructureSize=65 (41 00) + 2B 0 |
| SESSION_SETUP | 8 字节 | StructureSize=9 (09 00) + SessionFlags=0 + SecurityBufferOffset=0 + SecurityBufferLength=0 |
| TREE_CONNECT | 4 字节 | StructureSize=16 (10 00) + 2B 0 |
| CREATE | 8 字节 | StructureSize=89 (59 00) + 6B 0 |
| READ | 16 字节 | StructureSize=17 (11 00) + DataOffset=0 + Reserved + DataLength=0 + DataRemaining=0 + Flags=0 |
| WRITE | 16 字节 | StructureSize=17 (11 00) + Reserved + Count=0 + Remaining=0 + WriteChannelInfoOffset=0 + WriteChannelInfoLength=0 |
| CLOSE | 60 字节 | StructureSize=60 (3C 00) + 全 0（无文件属性） |
| TREE_DISCONNECT | 4 字节 | StructureSize=4 (04 00) + 2B 0 |
| LOGOFF | 4 字节 | StructureSize=4 (04 00) + 2B 0 |

### 9.4 错误注入示例

**示例：CREATE 失败（文件不存在）**

```yaml
smb:
  error_response_status: 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
  error_on_command: "create"
```

生成序列：
1. NEGOTIATE req/resp（正常）
2. SESSION_SETUP req/resp × 3（正常）
3. TREE_CONNECT req/resp（正常）
4. CREATE req（正常，打开 file.txt）
5. CREATE resp（Status=0xC0000034，命令体 8B）
6. TREE_DISCONNECT req/resp（跳过 READ/CLOSE）
7. LOGOFF req/resp

### 9.5 与现有模块复用

| 模块 | 复用方式 |
|------|----------|
| FTP/SOCKS5 emit() 闭包 | 复用 TCP PDU 序列生成框架；每个 SMB2 PDU 作为一段 PSH-ACK 负载 |
| LDAP/VNC 二进制 PDU 构造 | 复用固定头 + 命令体表驱动；字段名沿用 MS-SMB2 术语 |
| MSS 切段 | 复用超长 PDU 的 TCP 分段逻辑（PDU > MSS 时分多 TCP 段） |
| RDP dialects 协商 | 复用 dialects 列表协商模式 |
| **Command 字段处理**（SMB 特有） | planner 按命令查 §3.2 opcode 表写入 SMB2 头偏移 12-13（uint16 LE） |
| **Flags 字段处理**（SMB 特有） | 请求 Flags=0；响应 Flags |= 0x00000001（SERVER_TO_REDIR）；签名时 |= 0x00000008 |
| **CreditCharge 字段处理**（SMB 特有） | SMB 2.0.2 dialect 填 0；SMB 2.1+ 填 1（或按段数） |

---

## §10. 扩展字段映射

### 10.1 PacketConfig Metadata 映射

planner 生成的每个 SMB2 PDU 对应一个 `PacketConfig`，Metadata 字段映射如下：

| Metadata 键 | 来源 | 说明 |
|-------------|------|------|
| `smb_opcode` | §3.2 Command 表 | 命令码（0x0000-0x0012），写入 SMB2 头偏移 12-13（uint16 LE） |
| `smb_message_id` | §4.1 状态变量 | MessageId，写入 SMB2 头偏移 24-31（uint64 LE） |
| `smb_session_id` | §4.1 状态变量 | SessionId，写入 SMB2 头偏移 40-47（uint64 LE） |
| `smb_tree_id` | §4.1 状态变量 | TreeId，写入 SMB2 头偏移 36-39（uint32 LE） |
| `smb_file_id` | §4.1 状态变量 | FileId（16B），写入命令体对应偏移（CREATE resp 偏移 64-79；READ/WRITE/CLOSE 命令体偏移 16-31） |
| `smb_flags` | §3.3 Flags 定义 | Flags 值，写入 SMB2 头偏移 16-19（uint32 LE） |
| `smb_credit_charge` | §3.4 CreditCharge | CreditCharge，写入 SMB2 头偏移 6-7（uint16 LE） |
| `smb_credit_request` | §3.4 CreditRequest | CreditRequest/Response，写入 SMB2 头偏移 14-15（uint16 LE） |
| `smb_status` | §3.26 NT 状态码 | Status（仅响应），写入 SMB2 头偏移 8-11（uint32 LE） |
| `smb_dialect_revision` | §4.1 状态变量 | 选中的 dialect，写入 NEGOTIATE resp 命令体偏移 4-5 |
| `smb_direction` | 请求/响应 | "request" 或 "response"（决定 Flags bit0） |
| `smb_command_name` | §3.2 表 | 命令名（如 "NEGOTIATE"），用于日志 |
| `smb_auth_round` | §4.3 MessageId 方案 | NTLM 认证轮次（1-3），用于 SESSION_SETUP |

### 10.2 字段流向

```
SMBConfig ──> planner ──> PacketConfig.Metadata
                              │
                              v
                          builder ──> SMB2 PDU bytes
                              │
                              v
                          TCP segment ──> PCAP
```

planner 从 SMBConfig 读取配置，按 §4 状态机生成每个 PDU 的 Metadata；builder 从 Metadata 读取字段值，按 §3 偏移表写入 SMB2 头和命令体。

### 10.3 多会话 SessionId 分配

planner 内部维护全局原子计数器：

```go
var globalSessionID uint64 // 初始 0

func nextSessionID() uint64 {
    return atomic.AddUint64(&globalSessionID, 1) // 1, 2, 3, ...
}
```

每条会话的 SESSION_SETUP resp #1 调用 `nextSessionID()` 分配 SessionId，保证多会话唯一性。**TreeId 是会话内状态**：计数器挂在会话对象上（每会话从 1 开始递增），多 goroutine 并发下两会话互不串扰（无共享状态，天然隔离），跨会话 TreeId 重复合法；**严禁用全局计数器分配 TreeId**（两会话并发会冲突）。FileId 用 `crypto/rand` 生成 16B 随机值。

### 10.4 dialect 与 CreditCharge 关系

```go
func creditCharge(dialect uint16) uint16 {
    if dialect == 0x0202 {
        return 0  // SMB 2.0.2 MUST be reserved
    }
    return 1      // SMB 2.1+ 默认 1
}
```

### 10.5 Flags 填充

```go
func smbFlags(direction string, signed bool) uint32 {
    var flags uint32
    if direction == "response" {
        flags |= 0x00000001 // SMB2_FLAGS_SERVER_TO_REDIR
    }
    if signed {
        flags |= 0x00000008 // SMB2_FLAGS_SIGNED
    }
    return flags
}
```

### 10.6 Command 字段写入

```go
func writeCommand(buf []byte, opcode uint16) {
    binary.LittleEndian.PutUint16(buf[12:14], opcode) // SMB2 头偏移 12-13
}

// 查表
var commandOpcodes = map[string]uint16{
    "negotiate":         0x0000,
    "session_setup":     0x0001,
    "logoff":            0x0002,
    "tree_connect":      0x0003,
    "tree_disconnect":   0x0004,
    "create":            0x0005,
    "close":             0x0006,
    "flush":             0x0007,
    "read":              0x0008,
    "write":             0x0009,
    "lock":              0x000A,
    "ioctl":             0x000B,
    "cancel":            0x000C,
    "echo":              0x000D,
    "query_directory":   0x000E,
    "change_notify":     0x000F,
    "query_info":        0x0010,
    "set_info":          0x0011,
    "oplock_break":      0x0012,
}
```

---

## §11. 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| v1.0 | 2026-07-30 | 初稿：基于 MS-SMB2 编写设计文档，覆盖 19 种命令、NTLM 三阶段、SMB3.1.1 Preauth/Encryption |
| v1.1 | 2026-08-03 | 修复 v1.0 审计 26 项问题（TRANSFORM_HEADER 52B、WRITE DataOffset=112、NTLM 三阶段 28 包、默认 dialects 5 元素、SessionId 原子计数器、CREATE NameOffset=120、QUERY_DIRECTORY 响应 PDU 等）+ 新增 5 处字段错误修复 |
| v2.0.0 | 2026-08-05 | 基于深度审计报告 `audit/07-smb-audit-deep.md` 完整重写：修复 2 个 CRITICAL + 5 个 HIGH（SMB2 头 64 字节布局系统性偏移错误、Command/CreditRequest/Flags 字段缺失、TreeId 偏移 36 非 28、SessionId 偏移 40 非 32、MessageId 偏移 24 非 16、CreditCharge SMB 2.0.2 必须填 0、Flags 响应必须设 bit0）；新增 15 个 HexDump 场景（S1-S15）；测试用例扩展至 315 条（T001-T315）；所有偏移按 MS-SMB2 §2.2.1.2 原文逐字段核对 |
| v2.1.0 | 2026-08-05 | 基于复审报告 `audit/07-smb-audit-r1-v2.md` 修复 7 个 CRITICAL（NEGOTIATE resp SecurityBufferOffset 64→128、NEGOTIATE req NegotiateContextOffset 104→112、S1 resp 三段重叠重排为 128/128/256、8 处 NBSS 长度修正、READ resp DataOffset 64→80、QUERY_DIRECTORY req FileNameOffset 72→96、S10 目录条目 FileNameLength/NextEntryOffset/文件名三处统一为 file.txt=16B+116B）；S1 req 补 Preauth/Encryption 间 2B padding（8B 对齐）；新增本节 7 个 CRITICAL 修复明细 |

### 11.1 v2.0.0 修复的 CRITICAL 问题

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C-1 | SMB2 头 64 字节布局系统性偏移错误（缺失 Command/CreditRequest/Flags 字段） | §3.1 重写为 MS-SMB2 §2.2.1.2 标准布局：ProtocolId=0、StructureSize=4、CreditCharge=6、Status=8、Command=12、CreditRequest=14、Flags=16、NextCommand=20、MessageId=24、Reserved=32、TreeId=36、SessionId=40、Signature=48 |
| C-2 | Opcode 与 SMB2 头 Command 字段无映射关系 | §3.2 明确"Command 字段写入偏移 12-13（uint16 LE）"；§10.6 提供 `writeCommand` 函数 |

### 11.2 v2.0.0 修复的 HIGH 问题

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | Flags 字段缺失导致所有响应被误判为请求 | §3.3 新增 Flags 字段定义；§3.1 头表补 Flags @ 偏移 16-19；响应 Flags=0x00000001 |
| H-2 | CreditCharge 在 SMB 2.0.2 dialect 必须填 0 | §3.4 明确"SMB 2.0.2 dialect CreditCharge MUST 填 0"；§10.4 提供 `creditCharge` 函数 |
| H-3 | T61 TreeId/SessionId 字节断言偏移全错（差 +8） | §7 全部测试用例偏移修正：TreeId @ 36-39、SessionId @ 40-47 |
| H-4 | T57/T67 MessageId 偏移错误（差 +8） | §7 全部测试用例 MessageId 偏移修正为 24-31 |
| H-5 | T32 操作序列 MessageId 断言偏移错误 | §7.6 T115-T120 MessageId 偏移修正为 24-31 |

### 11.3 v2.0.0 新增内容

1. **15 个 HexDump 场景（S1-S15）**：§6 完整字节级 HexDump，覆盖 NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/READ/WRITE/CLOSE/LOCK/IOCTL/QUERY_DIRECTORY/QUERY_INFO/多会话/多流/签名加密/错误处理。
2. **315 条测试用例（T001-T315）**：§7 按 19 个类别分组，覆盖协商/认证/树连接/文件操作/写入关闭/状态机/异常/边界/多会话/SMB3 高级/集成/字段断言/Validate 负向/查询锁/NBSS/命令体/dialect。
3. **Command/Flags/CreditCharge 字段处理**：§3.2/§3.3/§3.4 明确字段位置与填充规则；§10.4-§10.6 提供 Go 函数。
4. **包总数公式**：§4.4 给出完整会话包数公式（19 + 2×AuthRounds + 2×N）。
5. **错误响应命令体大小表**：§9.3 列出每个命令错误响应的最小体大小。
6. **字段流向图**：§10.2 给出 SMBConfig → planner → PacketConfig.Metadata → builder → SMB2 PDU 的完整流向。

### 11.4 v2.1.0 修复的 CRITICAL 问题（7 项）

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C-1 | NEGOTIATE 响应 SecurityBufferOffset 错误填 64，规范必须从 SMB2 头起算 = 128 | §3.6 字段表与说明改 128（0x80）；S1 resp 行改 `80 00`；T223 断言改 `80 00 (128 LE)` |
| C-2 | NEGOTIATE 请求 NegotiateContextOffset 示例 104，正确 112 | S1 req 改 `70 00 00 00`（= 64 头 + 36 固定体 + 10 dialects + 2 padding） |
| C-3 | S1 resp 的 SecBufOffset=64/104、SecBufLen=128、NegoCtxOffset=104 三者重叠，不可能同时成立 | 重排为 SecurityBufferOffset=128、SecurityBufferLength=128、NegotiateContextOffset=256（SMB2 头起算） |
| C-4 | 8 处 NBSS 长度系统性错误 | S1 req 164→172（0xAC）、S1 resp 268→316（0x13C）、S2 req#1 136→160（0xA0）、S2 resp#1 192→184（0xB8）、S3 req 80→98（0x62）、S4 req 126→138（0x8A）、S6 req 176→212（0xD4）、S7 resp 132→124（0x7C）；实现时以 `len(pdu)` 计算，禁止硬编码 |
| C-5 | READ 响应 DataOffset 示例 64，正确 80 | §3.14 字段表改 80；S5 resp 改 `50`；T088/T222 断言改 `50 (80)` |
| C-6 | QUERY_DIRECTORY 请求 FileNameOffset 示例 72，正确 96 | §3.20 字段表改 96；S10 req 改 `60 00`；T245 断言改 `60 00 (96 LE)`；S10 req NBSS 88→98 |
| C-7 | S10 响应条目 NextEntryOffset=104 与 FileNameLength=8 与 "file.txt"=16B 三处互斥 | 统一为 FileName="file.txt"：FileNameLength=`10 00`（16）、NextEntryOffset=`74 00 00 00`（116）；条目 #2 补全（"data.txt"，FileNameLength=16，NextEntryOffset=0）；resp NBSS = 64+8+116+116 = 304（0x130） |

### 11.5 v2.1.0 联动修正

1. **S1 req padding 补充**：Preauth 上下文（46B）与 Encryption 上下文之间补 2B padding，满足 MS-SMB2 §2.2.3.1 每个 context 8 字节对齐；两处注释修正（Preauth 上下文 46 字节、Encryption 上下文 12 字节）。
2. **偏移注释统一**：S2/S3/S5/S10 等 HexDump 的 Offset 字段注释统一改为"从 SMB2 头算"表述，避免"从命令体起始"误解。
3. **NBSS 长度全部按 PDU 实际字节数核算**：S5 resp 4176（0x1050 = 64+16+4096）、S6 resp 80（64+16）、S7 req 88（64+24）、S3 resp 80（64+16）等经复核自洽，未改动。

### 11.6 与 v2.0.0 的兼容性

v2.0.0 是**不兼容重写**：
- SMB2 头偏移全部修正（TreeId 28→36、SessionId 32→40、MessageId 16→24、Signature 40→48）。
- 新增 Command/Flags/CreditRequest 三个必需字段。
- 测试用例编号重新分配（T001-T315 vs v1.1 的 T1-T79）。
- HexDump 场景重新编号（S1-S15 vs v1.1 的 §6 业务场景）。

实现者必须按 v2.0.0 偏移表编写代码，不可混用 v1.1 偏移。

### 11.7 v2.1.0 阶段二：修复 HIGH/MEDIUM/LOW 问题（22 项）

基于复审报告 `audit/07-smb-audit-r1-v2.md` 的 HIGH（10）/MEDIUM（7）/LOW（5）问题清单（7 个 CRITICAL 已在阶段一修复，见 §11.4）。

**HIGH 问题（10 项）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | SESSION_SETUP 请求 SecurityBufferOffset=88 正确但"64+24"注释误导 | §3.7 字段表注释改为"从 SMB2 头起始（固定体 24B，故 64+24=88；非从命令体起始）"；S2 req 值 88 与 T032 断言保留 |
| H-2 | TREE_CONNECT 请求 PathOffset=72 与 PathLength=26、NBSS=80 三方矛盾 | PathOffset=72 本身正确（§3.9 与 S3 req 一致）；NBSS 已在阶段一 C-4 修正为 98（64+8+26），确认自洽 |
| H-3 | CREATE 请求 NameLength=18 错误（"file.txt" 8 字符 = 16B） | S4 req 改 NameLength=`10 00`（16）；Name 段注释改 16 字节；T072 断言 16 与 S4 统一 |
| H-4 | S1 Preauth 上下文缺 8B 对齐 padding | 阶段一已补 2B padding + 注释修正（46/12 字节），确认无遗漏 |
| H-5 | §4.3 公式与 T120 LOGOFF MessageId 矛盾（8 应为 9） | T120 断言改 `09 00 00 00 00 00 00 00`（= 5+N+3 = 5+1+3 = 9），与 §4.3 公式及 T289 序列一致 |
| H-6 | 会话状态机"服务端分配 SessionId/TreeId"与双侧流量生成职责边界未定义；并发 TreeId 隔离无机制说明 | §4.1 新增"生成顺序与 ID 回填"说明（planner 顺序生成 request→response，响应阶段先算 ID 再回填请求；SESSION_SETUP req#1/TREE_CONNECT req 的 ID 填 0 属例外）；§10.3 明确 TreeId 计数器挂会话对象（严禁全局计数器）；新增 T170a 并发 TreeId 隔离用例 |
| H-7 | S15 CREATE 错误体误用 SESSION_SETUP 的 StructureSize=9 | S15 错误体改 `59 00`（89 = CREATE 正常 StructureSize）+ 6B 零；NBSS 68→72（64+8）；§4.2/§9.1 补充"错误响应命令体 StructureSize 保持该命令正常值"；新增 T140a/T140b 错误响应体断言 |
| H-8 | AuthRounds 规则 V12/V16/T149 互相矛盾 | 统一语义"AuthRounds=0 表示默认（按机制换算 ntlm→3/kerberos→2/anonymous/guest→1）；显式非 0 必须在 1-3 且与机制匹配"；V12-V16 改写；T149/T229/T230 同步；新增 T230a（ntlm+AuthRounds=1 负向） |
| H-9 | Validate 引用章节号错误（V1 引 §2.2.3 实为 NEGOTIATE 结构章）；ErrorResponseStatus 合法集合未定义 | V1/T226 引用改 §3.2.1（dialect 定义章）；V30/T235 明确合法集合 = §3.26 表 14 个已知码；T202 注明必须取 §3.26 表错误码；§4.2 异常分支同步引用 |
| H-10 | S14 加密/签名 PDU 缺 NBSS 头（违反 §6 约定） | S14 PDU #1（签名版 SESSION_SETUP）补 NBSS 头（160 = 64+24+72）；PDU #10 已有 NBSS 头（268 = 52+216）确认 |

**MEDIUM 问题（7 项）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M-1 | NEGOTIATE 响应 65 奇数编码未解释 | 阶段一已在 §3.6 说明"StructureSize=65 是奇数编码，固定体实为 64 字节（最后 1 字节并入 SecurityBuffer 前的 padding）"，确认无遗漏 |
| M-2 | NBSS"Length 分高低字节"表与"3 字节 BE"正文矛盾 | §2.2 表合并为一行"Length \| 3 \| BE"（17 位有效，上限 2^24-1） |
| M-3 | T152/T269 断言 16MB 超出 NBSS 24 位范围 | T152/T269 输入改 16777215B（2^24-1，NBSS=FF FF FF）；V32-V34 上限 16777216→16777215；T236 同步 |
| M-4 | T143 期望非量化；T142 未断言 PDU 总长 | T143 给具体 PathLength=60（30 字符）+ PDU 132B + NBSS 00 00 84；T142 补 PDU 总长 632B + NBSS 00 00 02 78 |
| M-5 | 响应侧 CreditCharge=0 无测试（0x0202） | 新增 T305a（0x0202 响应偏移 6-7 = 00 00）、T305b（0x0202 完整会话所有响应链 CreditCharge 恒 0） |
| M-6 | 集成测试无失败 spec 注入 | 新增 T195a（Dialects=["0x9999"] 驱动全链路，断言任务失败 + V1 文案 + 无 PDU 生成） |
| M-7 | ClientCapabilities 默认 0x03 与 0x0202 语义冲突 | §5.2 注明"SelectedDialect < 0x0300 时自动清 bit0（Encryption 仅 SMB3 有意义）"；§5 ClientCapabilities 字段注释同步；新增 T305c（0x0202 降级为 02 00 00 00）、T305d（0x0311 不降级） |

**LOW 问题（5 项）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L-1 | 行 37"7 对请求/响应"与默认 NTLM 三阶段 10 对矛盾 | 改为"至少 7 对（1 轮认证：NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/CLOSE/TREE_DISCONNECT/LOGOFF），默认 NTLM 三阶段为 10 对（见 §4.4）" |
| L-2 | 行 30 未列出全部 5 个 dialect | 概述补全 5 个 dialect（0x0202/0x0210/0x0300/0x0302/0x0311） |
| L-3 | （审计撤回）行 84 冗余表述 | 不动 |
| L-4 | T034 PreviousSessionId 测试不可达（§5 无配置入口） | §5 新增 `PreviousSessionId uint64` 配置字段；T034 注明"仅多通道重连场景使用，独立会话填 0" |
| L-5 | （审计撤回）行 33-34 重复表述 | 不动 |
| L-6 | T193 依赖真实 NIC 未标 skip | T193 标注"无 enp135s0f0np0 的环境（如 CI）跳过，用环境变量 SMB_NIC_TEST=1 显式开启" |

**审计补充项（测试质量专项评估）**：

| 项目 | 修复方式 |
|------|----------|
| 错误响应体内容（§9.3 表）无一条用例断言 | 新增 T140a（CREATE 错误体 StructureSize=89）、T140b（SESSION_SETUP 错误体 StructureSize=9 + SecBufOffset/Length=0） |
| 并发多会话 TreeId 隔离无测试 | 新增 T170a（并发 -race 下两会话 TreeId 各自从 1 递增，互不串扰） |

**联动修正（核算发现的其他 NBSS/Offset 错误，与审计同类）**：

| 位置 | 改前 | 改后 |
|------|------|------|
| S4 CREATE resp NBSS | 168（0xA8） | 152（0x98 = 64+88） |
| S5 READ req NBSS | 112（0x70） | 113（0x71 = 64+48+1 Buffer） |
| S5 resp NBSS 注释 | 4192（"64+16+4096+16"） | 4176（"64+16+4096"，值 0x1050 不变） |
| S8 LOCK req NBSS | 128（0x80，"64+24+24+padding"） | 112（0x70 = 64+24+24，LOCK_ELEMENT 后无 padding） |
| S9 IOCTL req InputOffset | 104（"64+56-16"） | 120（0x78 = 64 头 + 56 固定体[54B+2B 对齐]）；NBSS 128 不变 |
| S11 QUERY_INFO req NBSS | 112（0x70，"64+40+8"） | 105（0x69 = 64+40+1 Buffer） |

**用例数变化**：315 → **324 条**（新增 T230a、T305a、T305b、T305c、T305d、T195a、T170a、T140a、T140b 共 9 条）。

---

**文档结束**
