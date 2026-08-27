# CoAP（受限应用协议）协议设计

> 版本：v1.0.0（设计稿）
>
> 规范：RFC 7252、RFC 7959、RFC 7641、RFC 8323、RFC 9175
>
> 传输：UDP（User Datagram Protocol，用户数据报协议），默认端口 5683；CoAP over DTLS（Datagram Transport Layer Security，数据报传输层安全）使用 5684；CoAP over TCP/TLS 仅作为后续扩展。
>
> 范围：trafficgen（流量生成器）分层配置中的 CoAP（Constrained Application Protocol，受限应用协议）终结层设计与 pcap（packet capture，数据包捕获）测试契约。

## 目录

1. [概述](#1-概述)
2. [数据类型编码](#2-数据类型编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置 Typedef](#5-配置-typedef)
6. [包序列场景](#6-包序列场景)
7. [与 testcase 文档映射索引](#7-与-testcase-文档映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 协议定位

CoAP（受限应用协议）是面向受限节点和受限网络的轻量级应用协议。它提供类似 HTTP（Hypertext Transfer Protocol，超文本传输协议）的 REST（Representational State Transfer，表述性状态转移）资源模型，但使用紧凑二进制首部、短 Token（令牌）和 UDP 数据报，适合低功耗、低带宽或高丢包链路。

CoAP 的业务抽象是“方法作用于资源”：客户端用 GET（读取）、POST（创建或处理）、PUT（创建或替换）和 DELETE（删除）访问 URI（Uniform Resource Identifier，统一资源标识符）所指向的资源。请求和响应都携带 Message ID（消息标识符）及可选 Token；资源路径和查询参数使用重复的 Uri-Path（URI 路径段）与 Uri-Query（URI 查询段）选项表达。

本设计关注可重复生成的报文和可观察的包序列，不实现真实网络中的 socket（套接字）监听、缓存、资源数据库或时间等待。规划器只产生消息事件，UDP 层负责添加 IP（Internet Protocol，网际协议）和 UDP 头，worker（工作进程）负责节流和写出。

### 1.2 端口与承载

| 承载 | 默认端口 | 本设计状态 | 说明 |
|---|---:|---|---|
| CoAP/UDP | 5683 | 必选 | 常规明文 CoAP；默认目的端口为 5683 |
| CoAP/DTLS | 5684 | 兼容设计 | 由已有 DTLS 层完成握手和加密；CoAP 终结层只提供明文上层消息契约 |
| CoAP/TCP | 5683 | 后续扩展 | RFC 8323 改变消息边界和可靠性模型，不得直接复用 UDP 固定头 |
| CoAP/TLS | 5684 | 后续扩展 | 需要 TLS（Transport Layer Security，传输层安全）层，不属于本阶段 |

当层链为 `ip -> udp -> coap`（从外层到内层）时，CoAP 目的端口默认为 5683。若显式使用 DTLS 层，配置必须明确 `dst_port=5684`；5684 不是把普通 UDP 流量自动变成加密流量的开关。

### 1.3 与已有协议层的关系

- UDP（用户数据报协议）是 CoAP/UDP 的唯一直接承载层。CoAP 生成器向 UDP 层发出 `MessageEvent`（消息事件），不自行构造以太网、IP 或 UDP 头。
- HTTP（超文本传输协议）和 CoAP 都采用资源、方法、响应码和 URI 概念，但 HTTP 使用文本起始行/头字段，CoAP 使用 Code（代码）和 Option（选项）。两者的字段不能按字节互换。
- MQTT（Message Queuing Telemetry Transport，消息队列遥测传输）是主题和发布/订阅模型；CoAP 是请求/响应和资源模型。CoAP 的 Observe（观察）扩展可提供类似订阅的通知，但仍以资源 Token 和 Observe 序列为关联依据。
- DNS（Domain Name System，域名系统）与 CoAP 都常用 UDP，但 DNS 的消息 ID、问题区和资源记录布局与 CoAP 完全不同；不能把 DNS 的事务 ID 当作 CoAP MID。
- NTP（Network Time Protocol，网络时间协议）是固定字段的时间同步协议；CoAP 是可变 Option 和 Payload（负载）协议。

### 1.4 设计目标

1. 对 RFC 7252 基础消息提供无歧义的字节布局。
2. 对 RFC 7959 Blockwise（分块传输）和 RFC 7641 Observe（资源观察）给出可测试的状态约束。
3. 与分层配置架构一致：层条目为零负载，业务参数通过 `FlowMeta`（流元数据）传递。
4. 对 CON（Confirmable，可确认）消息给出确定的重传上限和序列语义。
5. 使每个测试用例能映射到设计条目和实际 Wireshark（网络协议分析器）字段。
6. 明确哪些行为是协议规定，哪些行为是 trafficgen 的确定性测试策略。

### 1.5 非目标

- 本阶段不注册 CoAP 层，不修改 registry（注册表）和任何 Go（编程语言）源文件。
- 本阶段不实现 DTLS 加密、不生成握手、不验证证书。
- 本阶段不实现 CoAP/TCP 的 RFC 8323 消息长度前缀。
- 本阶段不模拟真实时钟等待；重传序列由规划器离散生成，时间由测试元数据或 pacing（节拍控制）层解释。
- 本阶段不对服务器资源做持久化，也不把任意 URI 自动映射为真实文件。

### 1.6 术语表

| 术语 | 中文解释 | 在本文中的含义 |
|---|---|---|
| ACK（Acknowledgement） | 确认 | 对 CON 的确认消息类型，或携带响应的确认 |
| CON（Confirmable） | 可确认 | 需要对端确认并可按超时重传的消息类型 |
| NON（Non-confirmable） | 不可确认 | 不要求确认的消息类型 |
| RST（Reset） | 重置 | 表示消息无法处理或缺少上下文的消息类型 |
| MID（Message ID） | 消息标识符 | 16 位消息去重和 ACK 关联字段 |
| TKL（Token Length） | 令牌长度 | 固定头低四位，合法值为 0 至 8 |
| Option | 选项 | 按编号递增编码的可变字段 |
| Blockwise | 分块传输 | RFC 7959 的 Block1/Block2 机制 |
| Observe | 观察 | RFC 7641 的资源变化通知机制 |
| pcap | 数据包捕获 | 测试框架输出的抓包文件 |
| 4-tuple（四元组） | 源/目的 IP 和端口组合 | 会话隔离的网络端点标识 |

---

## 2. 数据类型编码

### 2.1 固定头

CoAP/UDP 每个消息以 4 字节固定头开始，所有多字节整数使用网络字节序（big-endian，大端序）。固定头不得因 Token 或 Option 数量而改变布局。

```text
Byte 0:  7 6 | 5 4 | 3 2 1 0
          Ver |  T  |    TKL
Byte 1:  Code（8 bit）
Byte 2:  Message ID 高字节
Byte 3:  Message ID 低字节
Byte 4+: Token（TKL 字节）
```

| 字段 | 位/长度 | 合法值 | 说明 |
|---|---:|---|---|
| Ver（Version，版本） | 2 bit | 1 | RFC 7252 当前版本；固定头高两位编码为 `01` |
| T（Type，类型） | 2 bit | 0、1、2、3 | CON、NON、ACK、RST |
| TKL | 4 bit | 0–8 | Token 长度；9–15 保留并视为格式错误 |
| Code | 8 bit | 方法或响应码 | 高 3 位为 class（类别），低 5 位为 detail（细节） |
| Message ID | 16 bit | 0–65535 | 网络字节序；CON/NON 去重，ACK/RST 回显关联 |

`Ver` 不等于 IP 版本。IPv4（Internet Protocol version 4，第四版网际协议）与 IPv6（Internet Protocol version 6，第六版网际协议）都可以承载 Ver=1 的 CoAP。

### 2.2 Type 编码

| T 值 | 名称 | 中文 | 主要语义 |
|---:|---|---|---|
| 0 | CON | 可确认 | 消息接收方应以 ACK 或 RST 响应；发送方允许重传 |
| 1 | NON | 不可确认 | 消息不要求 ACK；可用于低价值通知 |
| 2 | ACK | 确认 | 回显被确认 CON 的 MID；可携带响应或为空 |
| 3 | RST | 重置 | 回显无法处理消息的 MID；通常不带 Token、Option 或 Payload |

ACK 和 RST 的 MID 语义不同于普通请求：它们必须关联此前收到的 CON。若为独立响应，服务器可以发送新的 CON；该新消息有新的 MID，Token 通常沿用请求 Token。

### 2.3 Code 编码

Code 的数值为 `(class << 5) | detail`。例如 GET 的 `0.01` 数值为 `1`，2.05 Content（内容）的数值为 `(2<<5)|5 = 69`。

#### 2.3.1 请求方法

| Code 文本 | 数值 | 十六进制 | 方法 |
|---|---:|---:|---|
| 0.01 GET | 1 | 0x01 | 读取资源 |
| 0.02 POST | 2 | 0x02 | 创建子资源或执行处理 |
| 0.03 PUT | 3 | 0x03 | 创建或整体替换资源 |
| 0.04 DELETE | 4 | 0x04 | 删除资源 |

请求 Code 的 class 必须为 0，detail 只允许 RFC 定义的方法或未来明确注册的方法。保留方法 Code 不应默认为 GET。

#### 2.3.2 成功响应

| Code 文本 | 数值 | 十六进制 | 用途 |
|---|---:|---:|---|
| 2.01 Created（已创建） | 65 | 0x41 | POST/PUT 创建资源 |
| 2.02 Deleted（已删除） | 66 | 0x42 | DELETE 成功 |
| 2.03 Valid（有效） | 67 | 0x43 | 缓存或 Observe 通知有效 |
| 2.04 Changed（已改变） | 68 | 0x44 | PUT/POST 修改成功 |
| 2.05 Content（内容） | 69 | 0x45 | GET 返回内容；Observe 首响应和常规通知常用 |
|

#### 2.3.3 客户端错误响应

| Code 文本 | 数值 | 十六进制 | 触发 |
|---|---:|---:|---|
| 4.00 Bad Request（错误请求） | 128 | 0x80 | 格式或参数错误 |
| 4.01 Unauthorized（未授权） | 129 | 0x81 | 需要授权而未提供 |
| 4.02 Bad Option（错误选项） | 130 | 0x82 | 选项不支持或值非法 |
| 4.04 Not Found（未找到） | 132 | 0x84 | URI 资源不存在 |
| 4.05 Method Not Allowed（方法不允许） | 133 | 0x85 | 资源不支持该方法 |
| 4.08 Request Entity Incomplete（请求实体不完整） | 136 | 0x88 | 分块请求缺失 |
| 4.12 Precondition Failed（前置条件失败） | 140 | 0x8c | ETag 等前置条件失败 |
| 4.13 Request Entity Too Large（请求实体过大） | 141 | 0x8d | 资源或分块超过接收限制 |
|

#### 2.3.4 服务端错误响应

| Code 文本 | 数值 | 十六进制 | 触发 |
|---|---:|---:|---|
| 5.00 Internal Server Error（内部服务器错误） | 160 | 0xa0 | 未分类服务端故障 |
| 5.01 Not Implemented（未实现） | 161 | 0xa1 | 方法或扩展未实现 |
| 5.02 Bad Gateway（错误网关） | 162 | 0xa2 | 上游服务失败 |
| 5.03 Service Unavailable（服务不可用） | 163 | 0xa3 | 暂时不能处理请求 |
| 5.04 Gateway Timeout（网关超时） | 164 | 0xa4 | 上游响应超时 |
| 5.05 Proxying Not Supported（不支持代理） | 165 | 0xa5 | 代理能力不足 |

### 2.4 Token

Token 位于固定头之后，长度由 TKL 指定，合法范围为 0–8 字节。Token 是不透明的应用关联值；生成器不得把它解释成 MID，也不得因 Token 相同而忽略不同会话。

#### 2.4.1 JSON 字节编码契约

设计级 Go（编程语言）字段 `Token`、`Payload`、`ResponsePayload`、`ErrorPayload`、`ResponseBlockConfig.Payload` 和 `ErrorResponseConfig.Token/Payload` 均表示原始字节；对应 `spec_json`（规格 JSON）中的字符串统一使用 RFC 4648 base64（基 64）编码。这样避免 `encoding/json`（JSON 编码库）对 `[]byte`（字节切片）默认采用 base64 时产生隐式差异。空字符串表示空字节序列；禁止把普通文本或十六进制字符串按字段位置猜测为另一种编码。

例如 Token 字节 `01 02 03 04` 写为 `"AQIDBA=="`，文本负载 `{"v":23}` 写为 `"eyJ2IjoyM30="`。`TokenLength`（令牌长度）按解码后的字节数校验，不按 base64 字符串长度校验；`Payload` 的长度和 Payload Marker（负载标记）也按解码后的原始字节计算。Path、Query 和错误 Code 等非字节字段继续使用其各自的字符串或数值表示。

- 同一个请求与其响应必须保持 Token 相同。
- Observe 注册和之后的通知必须保持 Token 相同，直到观察关系终止。
- 不同并发会话默认生成不同 Token，除非用例显式要求相同 Token 进行跨流隔离测试。
- Token 长度 0 是合法值，响应也必须不带 Token。
- TKL=9–15 不是“长 Token”，而是保留编码；Validate（校验）应拒绝，或 pcap 负例直接要求生成失败。
- Token 的字节值可包含零字节；长度由 TKL 解析，不以 `0x00` 终止。

### 2.5 Option 通用编码

Option 按 Option Number（选项编号）递增排列。每个 Option 的首字节由 4 bit Delta（差值）和 4 bit Length（长度）组成：

```text
Byte 0: Delta nibble（高 4 bit） | Length nibble（低 4 bit）
Byte 1+: Delta 扩展值（当 nibble=13 或 14）
随后:    Length 扩展值（当 nibble=13 或 14）
随后:    Option Value（选项值）
```

当前 Option Number 等于前一个编号加 Delta；第一个 Option 的前一个编号为 0。Delta 和 Length 的 nibble 规则如下：

| nibble | 含义 |
|---:|---|
| 0–12 | 实际值等于 nibble |
| 13 | 后跟 1 字节 `x`，实际值为 `x + 13` |
| 14 | 后跟 2 字节网络序整数 `x`，实际值为 `x + 269` |
| 15 | 保留；Delta 的 15 用作 Payload Marker，Length 的 15 为格式错误 |

例如 Uri-Path（编号 11）后接 Uri-Query（编号 15）时 Delta 为 4；Block2（编号 23）后接 Block1（编号 27）时 Delta 为 4。Option 的排序是按编号，不是按用户配置字段的书写顺序。

### 2.6 常用 Option 编号与值

| 编号 | 名称 | 值类型 | 说明 |
|---:|---|---|---|
| 4 | ETag（实体标签） | opaque（不透明字节） | 缓存验证；长度通常 1–8 |
| 6 | Observe（观察） | uint（无符号整数） | 0 注册、1 注销；通知为 24 bit 序列值 |
| 11 | Uri-Path | UTF-8（Unicode 转换格式）字符串 | 每个路径段一个 Option，不含 `/` |
| 12 | Content-Format（内容格式） | uint | 例如 text/plain=0、application/json=50 |
| 14 | Max-Age（最大缓存年龄） | uint | 秒数；默认值由 RFC 7252 规定为 60 |
| 15 | Uri-Query | UTF-8 字符串 | 每个查询项一个 Option，不含 `?` 和 `&` 分隔符 |
| 17 | Accept（接受格式） | uint | 客户端可接受的响应格式 |
| 23 | Block2 | uint | 响应方向的分块编号、M、SZX |
| 27 | Block1 | uint | 请求方向的分块编号、M、SZX |
| 35 | Proxy-Uri（代理 URI） | UTF-8 字符串 | 代理请求；本阶段仅记录扩展 |
| 39 | Proxy-Scheme（代理方案） | UTF-8 字符串 | 代理请求；本阶段仅记录扩展 |
| 60 | Size1（请求大小） | uint | 请求实体总长度提示 |
| 28 | Size2（响应大小） | uint | 响应实体总长度提示 |

### 2.7 整数 Option 编码

uint Option 使用网络字节序，发送端应使用最短编码。值 0 可以编码为空值，接收端必须接受前导零；测试生成器为便于字节断言默认使用最短非空编码，除非场景专门测试零长度表示。

- `Content-Format=50` 的值为一个字节 `0x32`。
- `Observe=0` 可编码为零字节 Option value；`Observe=1` 编码为 `0x01`。
- Block2 的 NUM/M/SZX 按一个整数编码，不拆成多个 Option。
- uint 最大字节长度由协议字段定义；Observe 最多 3 字节，Block Option 最多 3 字节。
- 负数不是 uint；负值必须在 Validate 阶段拒绝。

### 2.8 Uri-Path 与 Uri-Query

路径 `/sensors/temp` 编码为三个语义段还是两个语义段取决于配置接口。本设计规定：配置 `Path: ["sensors", "temp"]` 表示两个 Uri-Path Option，生成器不得把 `/sensors/temp` 作为单个 Option。空路径表示根资源，不自动生成空 Uri-Path。

查询 `?unit=celsius&verbose=1` 配置为 `Query: ["unit=celsius", "verbose=1"]`，每项一个 Uri-Query Option。键和值保留原始 UTF-8 字节；百分号编码由调用方决定，生成器不重复转义。

路径和查询 Option 必须位于其他编号对应字段之前或按编号重新排序。典型顺序是 Uri-Path(11)、Content-Format(12)、Uri-Query(15)、Accept(17)、Block2(23)、Block1(27)，实际编码以编号排序为准。

### 2.9 Payload Marker 与负载

当消息有非空 Payload 时，Option 结束后必须写一个字节 `0xff`，然后紧跟 Payload。`0xff` 不是 Option，也不计入任何 Option 长度。

- 没有 Payload 时不写 `0xff`。
- `0xff` 后必须至少有一个 Payload 字节；只有 `0xff` 的消息是格式错误。
- Payload 可为任意二进制；若 Content-Format 指定文本或 JSON（JavaScript Object Notation，JavaScript 对象表示法），业务内容应符合对应格式。
- ACK、RST 空消息不能带 Payload。
- 错误响应可带诊断文本，但本设计默认只在 Notes（备注）中描述，不把错误文本误当作 Code。

### 2.10 Block Option 编码

Block1 和 Block2 是 0–3 字节 uint。其逻辑值布局为：

```text
bits 0..2   SZX（块大小指数）
bit 3       M（More，后续块标志）
bits 4..23  NUM（块编号，20 bit）
```

块大小为 `2^(SZX+4)` 字节。合法 SZX 为 0–6，对应 16、32、64、128、256、512、1024 字节；SZX=7 保留，必须拒绝。NUM 的协议范围为 `0..(2^20-1)`；设计字段可用 `uint32` 表示，但 Validate 必须拒绝超过 20 bit 的值。若实现施加更小的资源上限，必须单独标为实现限制。请求中的 Block2 指定客户端请求的响应块号，M 必须为 0；响应中的 Block2 返回服务器选择的 NUM、M、SZX。

实例：

- NUM=0、M=1、SZX=3 的逻辑值为 `(0<<4)|(1<<3)|3 = 0x0b`，表示第 0 块、还有后续、128 字节。
- NUM=4、M=1、SZX=1 的逻辑值为 `(4<<4)|(1<<3)|1 = 0x49`，表示第 4 块、还有后续、32 字节。

Option 缺失不表示显式的 16 字节块大小；只有 SZX=0 的值才明确指定 16 字节。

---

## 3. 消息结构

### 3.1 请求消息

请求消息由固定头、Token、排序后的 Option 和可选 Payload 组成。GET 通常无 Payload；POST 和 PUT 可以携带 Content-Format 与 Payload；DELETE 通常无 Payload，也可由资源定义接受条件。

请求的 Message ID（MID）由发送端选择。在同一个端点、交换生命周期内，CON/NON 的 MID 不应复用来表示不同未完成消息。测试生成器按 FlowID（流标识）建立独立 MID 序列，首个 MID 使用配置值或确定性默认值。

### 3.2 响应消息

响应 Code 位于同一固定头的 Byte 1。响应至少应保持请求 Token；若为 piggybacked response（捎带响应），响应是 ACK，MID 必须等于请求 MID。若为 separate response（独立响应），响应可为 CON 或 NON，MID 为新的值，Token 仍用于请求关联。

| 响应形式 | Type | MID | Token | 适用 |
|---|---|---|---|---|
| 捎带成功响应 | ACK | 回显请求 MID | 回显请求 Token | 服务端能立即完成请求 |
| 空确认 | ACK | 回显请求 MID | 空 | 服务端先确认、稍后返回响应 |
| 独立响应 | CON/NON | 新 MID | 通常回显请求 Token | 延迟响应或 Observe 通知 |
| 重置 | RST | 回显请求 MID | 空 | 无法处理或无上下文 |

### 3.3 空消息

空 ACK 的 Code=0、TKL=0、无 Option、无 Payload。空 RST 同样 Code=0、TKL=0、无 Option、无 Payload。空消息不是 GET，也不应被测试断言为业务响应。

### 3.4 Observe 消息

Observe 注册是带 `Observe=0` 的 GET。首个响应通常为 2.05 Content，并携带 `Observe=0` 或服务器选择的初始序列值；之后通知携带同一 Token 和新的 24 bit Observe 序列。通知可以是 NON，也可以是 CON。

注销使用带 `Observe=1` 的 GET，Token 可以沿用观察关系 Token。错误响应 4.xx/5.xx 不应携带 Observe Option；收到错误或 RST 可终止观察关系。

### 3.5 Blockwise 消息

Block2 用于客户端按块取得响应：客户端 GET 带 Block2 NUM=n、M=0，服务器响应带 Block2 NUM=n，并用 M=1 表示还有后续块。客户端再次请求 n+1，直到响应 M=0。每个块可以复用 Token，但每个消息使用新的 MID。

Block1 用于客户端分块上传 POST/PUT：每个请求带 Block1 NUM，M=1 表示还有数据；最后块 M=0。服务器可用 2.31 Continue（继续）确认中间块，也可按实现返回最终响应。

### 3.6 IPv4 与 IPv6

CoAP 消息字节与 IP 版本无关。IPv4 用 IPv4 头、UDP 校验和和 IPv4 地址；IPv6 用 IPv6 头、UDP 校验和和 IPv6 地址。测试必须从 UDP 负载偏移处断言 CoAP 字节，不把以太网/IP 头长度硬编码到协议布局中，除非 FrameAssert（帧字节断言）明确注明载体。

---

## 4. 状态机

### 4.1 交换状态

```text
客户端                              服务端
  | -- CON GET MID=a Token=t ------> |
  | <--- ACK 2.05 MID=a Token=t ---- |
  |                                  |
  | -- NON POST MID=b -------------->|
  | <--- NON/ACK 2.04（可选） -------|
```

CON 请求状态：`Created -> Sent -> AwaitingACK -> Completed`。收到 ACK 或匹配响应后完成；收到 RST 后进入 `Reset`；超过最大重传次数后进入 `Timeout`。

独立响应状态：`Sent -> EmptyACK -> AwaitingSeparateResponse -> Completed`。空 ACK 只确认传输，不等于业务请求已完成。

NON 请求状态：`Created -> Sent -> Completed`，不因没有 ACK 而重传。若应用选择响应，响应仍按 Token 关联。

### 4.2 CON 超时与重传

RFC 7252 默认参数：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| ACK_TIMEOUT | 2 秒 | 首次确认等待基准 |
| ACK_RANDOM_FACTOR | 1.5 | 初始等待随机范围上界 |
| MAX_RETRANSMIT | 4 | 最多重传 4 次，加初始发送共 5 次 |
| MAX_TRANSMIT_SPAN | 45 秒 | 从首次发送到最后一次发送的典型跨度上限 |
| MAX_TRANSMIT_WAIT | 93 秒 | 最后一次发送后的最大等待 |
| EXCHANGE_LIFETIME | 247 秒 | 交换状态可保留的寿命 |
| MAX_LATENCY | 100 秒 | 网络最大延迟假设 |
| PROCESSING_DELAY | ACK_TIMEOUT | 服务端处理延迟假设 |

首次超时为 `[2s, 3s]` 的随机值；每次重传等待时间翻倍。为使 pcap 测试可重现，trafficgen 可将随机抖动折叠为 `ack_timeout` 配置值，或者由种子生成稳定序列，但不得把重传次数和最大次数混淆：`MAX_RETRANSMIT=4` 表示总发送最多 5 个相同 MID 的 CON。

重传包应保持相同 MID、Token、Code、Option 和 Payload。Wireshark 可能标记 `coap.retransmitted`；测试可以断言该字段或通过 FrameAssert 检查 payload 相同。重传不应重复产生新的业务请求 ID。

### 4.3 ACK 处理

- ACK 的 MID 必须回显原 CON 的 MID。
- 捎带响应的 ACK 必须同时匹配 Token；Token 不匹配时不能完成原交换。
- 空 ACK 只完成传输确认，不能被当作 2.xx 业务结果。
- 重复 ACK 不应导致重复业务响应。
- ACK 不能携带另一个请求 Code。

### 4.4 RST 处理

RST 必须回显被拒绝消息的 MID，且为空消息。收到 RST 后，发送端停止该 CON 的重传并标记交换失败。服务端可以因格式错误、未知上下文或不支持的消息返回 RST；对于可表达的业务错误，优先返回 4.xx/5.xx 响应而不是 RST。

### 4.5 NON 处理

NON 不要求 ACK，不得因单次缺少 ACK 自动重传。若 NON 携带 Observe 通知，客户端可根据 Token 和 Observe 序列处理；若通知丢失，协议本身不提供确认，应用可重新注册 GET。

### 4.6 Observe 状态机

```text
None -- GET CON Observe=0 --> Registered
Registered -- 2.05 + Observe --> Observing
Observing -- NON/CON notification --> Observing
Observing -- GET Observe=1 --> Cancelling --> None
Observing -- 4.xx/5.xx or RST --> None
```

Observe 序列是 24 bit 无符号序列，按 RFC 1982 的 serial arithmetic（序列算术）比较新旧并允许回绕。实现不能简单用普通整数 `>` 判断跨回绕值。通知序列不要求每次恰好加 1，但 trafficgen 默认使用递增 1 便于测试。

### 4.7 Block2 状态机

```text
NeedBlock(0) -- GET Block2(0,M=0) --> HaveBlock(0,M=1)
HaveBlock(n,M=1) -- GET Block2(n+1,M=0) --> HaveBlock(n+1)
HaveBlock(n,M=0) --> Complete
```

若响应 NUM 与请求 NUM 不一致，测试应报告分块关联错误。若 SZX 改变，客户端应按服务器响应重新计算下一请求的块大小和编号；本阶段的基础场景固定 SZX，不隐式测试动态重分块。

### 4.8 Block1 状态机

```text
Upload(0,M=1) -- 2.31 Continue --> Upload(1,M=1)
Upload(last,M=0) -- 2.01/2.04 --> Complete
```

Block1 的中间块不能被当成完整 PUT/POST 业务操作执行。重复块应按 NUM 去重；乱序块和跳号块应返回 4.08 或由校验器拒绝。

### 4.9 多会话隔离

每个会话必须拥有独立 4-tuple（四元组）：源 IP、目的 IP、源端口、目的端口。会话状态包括 MID 序列、Token、Observe 序列、Block NUM 和重传计数；不得在 FlowID 之间共享。多会话用例必须断言端口或 Token 的 distinct_values（不同值集合），不能只断言包数量。

### 4.10 生成器时间策略

规划器不调用 `sleep`，不依赖墙上时钟。重传时间以消息元数据表达，worker 的 pacing 负责实际发送节奏。取消 context（上下文）时必须停止继续发出消息，并关闭或排空事件通道，避免调用方永久等待。

---

## 5. 配置 Typedef

### 5.1 分层声明

CoAP 应注册为 `category=Terminal`（终结层），并声明 `DependsOn=["udp"]`。本任务不修改注册表；以下是实现契约：

```text
LayerSchema{
    Name: "coap",
    Category: CategoryTerminal,
    DependsOn: []string{"udp"},
}
```

层链从外层到内层书写为：

```json
"layers": [
  {"udp": {}},
  {"coap": {}}
]
```

层条目保持零负载。协议参数放在 `spec.CoAP`（FlowSpec 中的 CoAP 配置）或 flat `FlowMeta`（流元数据）字段中，避免通用层字段把业务结构误判为未知字段。

### 5.2 CoAPConfig 定义

以下是设计级 Typedef（类型定义），字段名是 JSON（JavaScript Object Notation，JavaScript 对象表示法）配置契约；实际 Go 结构体需在代码实现任务中落地。

```go
CoAPConfig struct {
    Method                  string                `json:"method"`
    Path                    []string              `json:"path,omitempty"`
    Query                   []string              `json:"query,omitempty"`
    Payload                 []byte                `json:"payload,omitempty"`
    ContentFormat           uint16                `json:"content_format,omitempty"`
    Accept                  *uint16               `json:"accept,omitempty"`
    Confirmable             bool                  `json:"confirmable,omitempty"`
    Token                   []byte                `json:"token,omitempty"`
    TokenLength             uint8                 `json:"token_length,omitempty"`
    MessageID               uint16                `json:"message_id,omitempty"`
    Version                 *uint8                `json:"version,omitempty"`
    Code                    *uint8                `json:"code,omitempty"`
    Response                *bool                 `json:"response,omitempty"`
    ResponseCode            string                `json:"response_code,omitempty"`
    ResponsePayload         []byte                `json:"response_payload,omitempty"`
    ResponseContentFormat   *uint16               `json:"response_content_format,omitempty"`
    ResponseBlocks          []ResponseBlockConfig `json:"response_blocks,omitempty"`
    Block1                  *BlockConfig          `json:"block1,omitempty"`
    Block2                  *BlockConfig          `json:"block2,omitempty"`
    Observe                 *ObserveConfig        `json:"observe,omitempty"`
    Retransmit              *RetransmitConfig     `json:"retransmit,omitempty"`
    ErrorCode               string                `json:"error_code,omitempty"`
    ErrorPayload            []byte                `json:"error_payload,omitempty"`
    ErrorResponses          []ErrorResponseConfig `json:"error_responses,omitempty"`
    URIMaxLength            uint32                `json:"uri_max_length,omitempty"`
    Tokens                  []string              `json:"tokens,omitempty"`
    MessageIDs              []uint16              `json:"message_ids,omitempty"`
    SessionSrcIPs           []string              `json:"session_src_ips,omitempty"`
    SessionSrcPorts         []uint16              `json:"session_src_ports,omitempty"`
}
```

`Version`（版本）和 `Code`（代码）仅用于显式验证或设计级原始配置；正常方法仍由 `Method` 映射。`Response`（是否生成响应）用于明确关闭响应，`ResponseContentFormat`（响应内容格式）与请求的 `ContentFormat`（内容格式）相互独立，`ResponseBlocks`（响应分块序列）表达 Block2（响应分块）的多块负载。`ErrorResponses`（业务错误响应序列）用于测试多个合法的 4.xx/5.xx 响应；它们不是输入校验错误。

`URIMaxLength`（URI 最大长度）对应 JSON 标签 `uri_max_length`，只限制 Uri-Path（URI 路径段）组合长度，不改变 IP（网际协议）或 UDP（用户数据报协议）最大报文规则。`Tokens`（会话令牌数组）、`MessageIDs`（会话消息标识符数组）、`SessionSrcIPs`（会话源地址数组）和 `SessionSrcPorts`（会话源端口数组）仅在多会话场景使用；数组长度必须与顶层 `sessions`（会话数量）相等。

`Sessions`（会话数量）位于 `spec_json` 顶层，因为它描述 planner（规划器）需要生成的独立流数量，而不是单个 CoAP 消息字段。实现时必须同时校验顶层 `sessions` 与 `coap.tokens`、`coap.message_ids`、`coap.session_src_ips`、`coap.session_src_ports` 的长度和四元组唯一性；缺省数组时由规划器按确定性规则生成，不得把多个会话压成同一个四元组。

标识符解释：`Method`（方法）、`Path`（路径）、`Query`（查询）、`Payload`（负载）、`ContentFormat`（内容格式）、`Confirmable`（是否可确认）、`TokenLength`（令牌长度）、`MessageID`（消息标识符）、`ResponseCode`（响应代码）、`Retransmit`（重传控制）。

响应和错误项使用以下设计级结构：

```go
ResponseBlockConfig struct {
    Number  uint32 `json:"number"`
    More    bool   `json:"more"`
    SizeExp uint8  `json:"size_exp"`
    Payload []byte `json:"payload,omitempty"`
}

ErrorResponseConfig struct {
    Code    string   `json:"code"`
    Path    []string `json:"path,omitempty"`
    Token   []byte   `json:"token,omitempty"`
    Payload []byte   `json:"payload,omitempty"`
}
```

`ResponseBlockConfig` 的 `Payload`（负载）对应 JSON 用例中的每一块数据；`ErrorResponseConfig` 的 `Path`（路径）用于说明故障场景所访问的资源。上述结构是测试契约，不代表本阶段已经增加 Go 类型或注册 CoAP 层。

### 5.3 BlockConfig 与 ObserveConfig

```go
BlockConfig struct {
    Number     uint32 `json:"number"`
    More       bool   `json:"more"`
    SizeExp    uint8  `json:"size_exp"`
}

ObserveConfig struct {
    Register       bool   `json:"register"`
    NotifyCount    uint32 `json:"notify_count,omitempty"`
    StartSequence  uint32 `json:"start_sequence,omitempty"`
    Confirmable    bool   `json:"confirmable,omitempty"`
    NotificationTypes []string `json:"notification_types,omitempty"`
}
```

`NotificationTypes`（通知类型序列）可显式写成 ` ["NON", "CON"] `，用于表达先发 NON 再发 CON 的混合通知；当该数组为空时，`Confirmable` 作为所有通知的默认类型。`NotificationTypes` 长度若非零必须等于 `NotifyCount`，每项只能是 `NON` 或 `CON`；CON 通知必须有对应 ACK。

### 5.4 RetransmitConfig

```go
RetransmitConfig struct {
    AckTimeout       time.Duration `json:"ack_timeout,omitempty"`
    RandomFactor     float64       `json:"random_factor,omitempty"`
    MaxRetransmit    uint8         `json:"max_retransmit,omitempty"`
    ForceTimeout     bool          `json:"force_timeout,omitempty"`
}
```

默认 `AckTimeout=2s`、`RandomFactor=1.5`、`MaxRetransmit=4`。`ForceTimeout=true` 是测试策略，表示不注入响应并生成初始包加最多 4 次重传；不是 RFC 中的新消息类型。

### 5.5 默认值与校验

| 字段 | 默认 | 校验 |
|---|---|---|
| Method | GET | 只允许 GET/POST/PUT/DELETE |
| Confirmable | true | ACK/RST/错误响应配置不使用该请求开关 |
| TokenLength | 4 | 0–8；若 Token 非空必须等于实际长度 |
| MessageID | 0 | 0 表示按 FlowID 确定性生成；显式值可为 0 |
| ContentFormat | 未设置 | uint16；不自动把 Payload 变成 JSON |
| Path | 空 | 每段不得含 `/` 或 NUL；UTF-8 合法 |
| Query | 空 | 每段不得含 NUL；保留百分号编码 |
| Block SZX | 2 | 0–6；默认 64 字节块仅为测试策略 |
| Observe sequence | 0 | 0–0xffffff |
| UDP dst_port | 5683 | DTLS 场景显式使用 5684 |

Validate 只检查值和相互关系，不填充会改变 wire（线上字节）的默认字段；Plan（规划器）在 emit（发出）阶段应用默认值并保持确定性。

### 5.6 TCP 载体差异

若未来层链包含 TCP（Transmission Control Protocol，传输控制协议），不能使用本节 UDP 固定头。RFC 8323 的 CoAP/TCP 消息以变长长度前缀开始，没有 Type 和 MID 字段，可靠性由 TCP 提供；CoAP/TLS 还需要 TLS 会话。设计文档必须把该路径标为不同生成器或不同传输适配器，禁止 `DependsOn=["tcp"]` 后复用 UDP 编码。

### 5.7 零负载配置直传

测试用例中的层条目：

```json
{"udp": {}}
{"coap": {}}
```

业务配置位于同一 `spec_json` 的 `coap` 键，例如：

```json
"coap": {
  "method": "GET",
  "path": ["sensors", "temp"],
  "confirmable": true,
  "token_length": 4
}
```

该结构保证 layer planner（层规划器）可以按 `FlowMeta.CoAP` 取值，并保证 `layers` 仅表达依赖图。若实现选择扁平化 `FlowMeta`，字段名称必须保持上述 JSON 名称，不得把 `path` 转成未定义的 `uri_path` 别名而不提供兼容规则。

---

## 6. 包序列场景

### 6.1 CON GET 与捎带响应

目标：覆盖最常用的资源读取。

```text
P1  client -> server  CON GET, MID=100, Token=t, Uri-Path=sensors,temp
P2  server -> client  ACK 2.05, MID=100, Token=t, Content-Format=50, Payload=JSON
```

P1 和 P2 必须使用同一 4-tuple 的反向方向；P2 的 MID 必须等于 P1，Token 必须相等。P2 不能再次使用 CON，除非明确配置为独立响应。

### 6.2 NON POST

```text
P1  client -> server  NON POST, MID=101, Token=t, Uri-Path=events,
                      Content-Format=50, Payload=JSON
P2  server -> client  可选响应；若生成，按 Token 关联
```

NON POST 不因没有 ACK 重传。是否生成响应由 `response_code` 或场景配置决定；不应通过 `Confirmable=false` 误改变响应 Type。

### 6.3 PUT

PUT 用于整体替换资源。简单 PUT 序列为 CON PUT、ACK 2.04 Changed；资源不存在时可返回 2.01 Created。Payload 为空的 PUT 仍是合法方法请求，但测试应明确区分“无负载”与“缺少 Content-Format”。

### 6.4 DELETE

DELETE 通常为 CON DELETE、ACK 2.02 Deleted，响应无 Payload。不存在资源返回 4.04。测试应断言 Code 和 URI Path，而不是只断言 packet_count。

### 6.5 CON 重传超时

当 `ForceTimeout=true` 且服务端不回应：

```text
P1  CON GET MID=200 Token=t
P2  CON GET MID=200 Token=t  retransmission=1
P3  CON GET MID=200 Token=t  retransmission=2
P4  CON GET MID=200 Token=t  retransmission=3
P5  CON GET MID=200 Token=t  retransmission=4
```

P1–P5 的 CoAP 负载必须逐字节相同。不得产生 ACK、RST 或伪造成功响应。默认 `MAX_RETRANSMIT=4`，因此 `packet_count=5`；如果实现使用可配置更小上限，测试应显式设置并在摘要中说明。

### 6.6 Observe 首响应与通知

```text
P1  client -> server  CON GET, Observe=0, Token=t, Path=temperature
P2  server -> client  ACK 2.05, MID=P1.MID, Observe=100, Token=t, Payload=v1
P3  server -> client  NON 2.05, MID=new, Observe=101, Token=t, Payload=v2
P4  server -> client  CON 2.05, MID=new, Observe=102, Token=t, Payload=v3
P5  client -> server  ACK, MID=P4.MID, Token=empty
```

Observe 通知的 Token 必须与 P1 相等，序列按 RFC 1982 判断递增。P4 如果是 CON，P5 必须确认 P4 MID。通知不得带 4.xx/5.xx Code 与 Observe 同时出现。

### 6.7 Block2 两块响应

以 SZX=3（128 字节）为例：

```text
P1  CON GET MID=300 Token=t Block2(NUM=0,M=0,SZX=3)
P2  ACK 2.05 MID=300 Token=t Block2(NUM=0,M=1,SZX=3) Payload[0:128]
P3  CON GET MID=301 Token=t Block2(NUM=1,M=0,SZX=3)
P4  ACK 2.05 MID=301 Token=t Block2(NUM=1,M=0,SZX=3) Payload[128:]
```

P2 的 M=1 表示必须继续请求；P4 的 M=0 表示完成。每个请求 MID 递增但 Token 可保持相同。测试应断言 `coap.opt.block_number`、`coap.opt.block_mflag`、`coap.opt.block_size` 和 Payload 存在。

### 6.8 Block1 上传

至少两块的 PUT/POST：

```text
P1  CON PUT MID=400 Token=t Block1(NUM=0,M=1,SZX=2) Payload[0:64]
P2  ACK 2.31 MID=400 Token=t Block1(NUM=0,M=1,SZX=2)
P3  CON PUT MID=401 Token=t Block1(NUM=1,M=0,SZX=2) Payload[64:]
P4  ACK 2.04 MID=401 Token=t
```

中间块响应不能伪装成最终 2.04；若实现不生成 2.31，应在配置中明确采用批量响应策略并在测试文档中标注差异。

### 6.9 Uri-Path 多段和 Uri-Query

`Path=["api","v1","devices","7"]` 必须生成四个 Uri-Path Option。`Query=["unit=celsius","verbose=1"]` 必须生成两个 Uri-Query Option。路径段为空、包含 NUL 或非法 UTF-8 应由 Validate 拒绝。

### 6.10 Content-Format 与 Accept

POST/PUT 请求可带 Content-Format=50（application/json，JSON 应用格式），GET 可带 Accept=0（text/plain，纯文本）或 Accept=50。请求的 Content-Format 不等于响应的 Content-Format；响应需要独立生成该 Option。

### 6.11 错误响应

错误场景仍遵循 MID/Token 关联：

```text
CON GET unknown -> ACK 4.04 Not Found
CON POST too-large -> ACK 4.13 Request Entity Too Large
CON malformed -> RST 或 ACK 4.00 Bad Request（由配置决定）
CON server-failure -> ACK 5.00 Internal Server Error
```

可表达的业务错误优先使用 ACK + 错误 Code；格式无法解析或无上下文时使用 RST。错误响应不添加 Observe Option。

### 6.12 IPv4

IPv4 用例使用 `src_ip=10.0.0.1`、`dst_ip=20.0.0.1`，UDP 目的端口 5683。CoAP FrameAssert offset 应从 UDP payload 起点说明；以太网 IPv4 无选项时典型 CoAP payload 偏移是 42，但不应把该值当作所有 VLAN（Virtual Local Area Network，虚拟局域网）场景的协议常量。

### 6.13 IPv6

IPv6 用例使用文档地址 `2001:db8::1` 和 `2001:db8::2`，UDP 目的端口 5683。IPv6 没有 IPv4 头校验和；UDP 校验和仍必须存在。CoAP 固定头、Token、Option 和 Payload 与 IPv4 用例完全一致。

### 6.14 多会话

多会话至少生成两条独立 4-tuple：

```text
S1 10.0.0.1:56565 -> 20.0.0.1:5683 Token=01020304 MID=500
S2 10.0.0.2:56566 -> 20.0.0.1:5683 Token=05060708 MID=600
```

两条会话的 ACK 必须回到各自源端口；不得把 S1 的响应 Token 或 MID 用于 S2。测试用例应至少断言两组端口存在且 Token distinct_values。

### 6.15 取消与排空

生成期间取消 context 时，已生成的完整消息可以保留，未生成消息不得继续写出。规划器关闭输出后，UDP 层应能正常结束；错误路径要排空上游事件，避免管道阻塞。该行为属于实现集成测试，不改变 CoAP wire format。

---

## 7. 与 testcase 文档映射索引

### 7.1 场景到用例 ID

下表的 ID 必须与 `20-coap-testcase.md` 和 `cases/coap.json` 完全一致。`C` 表示基础正向，`N` 表示负路径。

| 场景 | 用例 ID | IPv4 | IPv6 | 多流/多会话 | 关键断言 |
|---|---|:---:|:---:|:---:|---|
| CON GET/ACK 2.05 | coap_con_get | 是 | 否 | 否 | version/type/code/MID/Token/path |
| NON POST JSON | coap_non_post | 是 | 否 | 否 | NON、POST、ctype、payload |
| PUT Changed | coap_put_changed | 是 | 否 | 否 | PUT、2.04、path |
| DELETE Deleted | coap_delete_deleted | 是 | 否 | 否 | DELETE、2.02、无 payload |
| CON 超时重传 | coap_con_timeout_retransmit | 是 | 否 | 否 | 5 包、MID/Token/bytes 相同 |
| 多段路径查询 | coap_uri_path_query | 是 | 否 | 否 | 多 Uri-Path、多 Uri-Query |
| Content-Format/Accept | coap_content_format_accept | 是 | 否 | 否 | ctype、accept |
| Block2 两块 | coap_block2_two_blocks | 是 | 否 | 否 | NUM/M/SZX、2 块负载 |
| Observe 首响应通知 | coap_observe_notifications | 是 | 否 | 否 | Token、Observe 序列、ACK |
| 4.xx/5.xx 错误 | coap_error_responses | 是 | 否 | 否 | 4.04、4.13、5.00 |
| IPv6 GET | coap_ipv6_get | 否 | 是 | 否 | ipv6.src/dst、CoAP 字段 |
| 两会话隔离 | coap_multi_session | 是 | 否 | 是 | 端口、Token、MID distinct |
| 非法版本 | coap_invalid_version | 是 | 否 | 否 | expect_error |
| TKL>8 | coap_invalid_tkl | 是 | 否 | 否 | expect_error |
| 非法 Code | coap_invalid_code | 是 | 否 | 否 | expect_error |
| URI 过长 | coap_uri_too_long | 是 | 否 | 否 | expect_error |

### 7.2 覆盖矩阵

| 规范/设计条目 | con_get | non_post | put | delete | retransmit | path_query | format | block2 | observe | errors | ipv6 | multi | negatives |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 固定头 Ver/T/MID | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Token 关联 | ✓ | ✓ | ✓ |  | ✓ |  |  | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| CON/ACK | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ | ✓ | ✓ | ✓ |  |  |
| NON |  | ✓ |  |  |  |  |  |  | ✓ |  |  |  |  |
| Uri-Path | ✓ | ✓ | ✓ | ✓ |  | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Uri-Query |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |
| Content-Format |  | ✓ | ✓ |  |  |  | ✓ | ✓ | ✓ |  | ✓ |  |  |
| Accept |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |
| Block2 NUM/M/SZX |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |
| Observe 序列 |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |
| 4.xx/5.xx |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |
| IPv4 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ |
| IPv6 |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| 多会话 4-tuple |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |

### 7.3 断言优先级

1. 优先断言 `coap.version`、`coap.type`、`coap.code`、`coap.mid`、`coap.token_len`。
2. 再断言 `coap.opt.uri_path`、`coap.opt.uri_query`、`coap.opt.ctype`、`coap.opt.accept`。
3. Blockwise 使用 `coap.opt.block_number`、`coap.opt.block_mflag`、`coap.opt.block_size`；不使用未经本地字段核实的层级字段名。
4. Observe 使用 `coap.opt.observe`，跨包用 `same_as_packet` 或 `distinct_values`。
5. 字节布局有争议时使用 FrameAssert；offset 必须说明是以太网帧、IP 负载还是 UDP 负载。
6. 负例使用 `expect_error` 和 `error_contains`，不把“生成了一个 malformed 包”误当作实现支持非法输入。

---

## 8. 实现集成点

### 8.1 配置类型

在代码实现阶段，向 `internal/core/types.go` 增加 `CoAPConfig`、`BlockConfig`、`ObserveConfig` 和 `RetransmitConfig`。字段需有 JSON tag（JSON 标签）并挂在 `FlowSpec.CoAP` 或等价 `FlowMeta.CoAP` 上。默认值应遵循 §5.5，不能在 Validate 阶段修改用户对象造成调用方观察到的副作用。

### 8.2 层注册

在 `internal/core/layers/registry.go` 的实现任务中注册：

- Name=`coap`。
- Category=`CategoryTerminal`。
- DependsOn=`[]string{"udp"}`。
- 业务配置字段不放入空的 layer entry。

当前文档任务不执行该修改；未注册状态下的 `coap.json` 是未来实现的契约骨架。

### 8.3 生成器

建议文件路径为 `internal/protocol/coap/layer_gen.go`。生成器应实现 `LayerGenerator`（层生成器）接口：

```go
Generate(ctx context.Context, req *layers.GenRequest) error
GenEvents() bool
```

生成器从 `req.Meta.CoAP` 读取配置，通过 `req.EmitMsg(layers.MessageEvent{Up: true, Bytes: payload})` 向 UDP 层发出纯 CoAP payload。不得直接调用底层 writer（写出器），不得重复构造 UDP 头。

### 8.4 Planner

Planner（规划器）负责：

1. 校验和默认化 Method、Token、MID、Option。
2. 按场景生成请求、响应、通知和重传事件。
3. 为每个事件附加方向和 FlowID。
4. 对 Block1/Block2 计算 NUM/M/SZX 和 M。
5. 对 Observe 生成稳定的 24 bit 序列。
6. 在取消时停止生成并正常关闭 channel（通道）。

Planner 不负责：

- Ethernet（以太网）头、IP 头、UDP 头和 UDP 校验和。
- 实际 sleep。
- DTLS/TLS 加密。
- 将业务 JSON 自动序列化为任意未声明格式。

### 8.5 Validator

Validator（校验器）至少检查：

- Method、Code 与响应 Code 的 class/detail 合法性。
- TokenLength 与 Token 字节长度一致，且不超过 8。
- Path、Query 的 UTF-8、NUL 和分段规则。
- Block SZX、NUM、M 和 Block1/Block2 使用方向。
- Observe 序列范围和注册/通知配置关系。
- ACK/RST 不带请求 Payload 或非法 Option。
- `dst_port=5684` 只有在 DTLS 载体场景下才允许作为 CoAP over DTLS 说明。
- TCP 载体不能复用 UDP CoAP 配置。

### 8.6 UDP 对接

UDP 层应将 CoAP MessageEvent 的 Bytes 作为一个应用 payload 发送。对于请求/响应方向，Up（上行）标志必须与 FlowSpec 的方向约定一致。UDP 层不解析 CoAP，也不重排 Option；所有 Option 排序和重传去重由 CoAP 生成器完成。

### 8.7 pcap 测试驱动

测试驱动读取 `cases/coap.json`，将 `spec_json` 提交给 MCP（Model Context Protocol，模型上下文协议）或 pcap runner（抓包运行器），再用 tshark 解析。测试层应：

- 校验 JSON 数组和 Case 结构。
- 对 `expect_error` 用例验证规划或校验阶段确实返回错误。
- 对正常用例验证 packet_count/min_packets 和字段值。
- 对多包用例保持抓包顺序，除非断言明确使用跨包聚合。
- 对 `frames` 断言先确认 offset 基准，避免把 IP 选项或 VLAN 误算为 CoAP 头偏移。

### 8.8 注册前冒烟策略

在 CoAP 代码尚未注册前，运行全协议套件不应把 `coap.json` 当成已实现协议而报告“通过”。实现接入后，必须先运行 CoAP 单协议，再运行完整 pcap 套件。未注册阶段的预期结果是明确的 unsupported/unknown protocol 错误，不能吞掉错误并返回 0 包成功。

### 8.9 资源与并发

生成器不应将所有 Block2 Payload 预先聚合到内存；大响应必须按块流式产生。多个 worker 共享同一策略时，MID、Token 和 Observe 序列必须以 FlowID 分区，避免锁保护了内存却出现业务串流。所有 channel、timer（定时器）和 goroutine（轻量线程）在正常完成、取消和错误三条路径上都要释放。

### 8.10 可观测性

建议记录结构化字段：`flow_id`（流标识）、`coap_type`、`code`、`mid`、`token`、`block_num`、`observe_seq`、`retransmit_index`。日志中的 Token 可脱敏，但 pcap 字节必须保持原样。错误信息应指出字段名和实际值，例如 `coap token length 9 exceeds RFC 7252 maximum 8`。

---

## 9. 错误处理

### 9.1 错误分类

| 类别 | 示例 | 处理阶段 | 结果 |
|---|---|---|---|
| 配置错误 | Method=PATCH | Validate | 返回错误，不生成包 |
| 格式错误 | Ver=2、TKL=9 | Validate/构造 | 返回错误；负例使用 expect_error |
| 业务错误 | URI 不存在 | Planner 场景 | 生成 4.04 响应 |
| 请求过大 | Payload 超过资源限制 | Planner 场景 | 生成 4.13 响应 |
| 服务故障 | 显式 server_error | Planner 场景 | 生成 5.00 响应 |
| 传输失败 | CON 超时 | Planner/worker | 生成重传序列并最终失败 |
| 无上下文 | 收到未知 MID 的 ACK/RST | 状态机 | 忽略或按实现记录，不完成其他交换 |

### 9.2 4.00 Bad Request

适用于固定头、Option、Payload 或 URI 语义无法解析的请求。若错误发生在生成器输入校验阶段，trafficgen 应直接返回 Validate 错误，不生成一个声称来自服务端的 4.00；只有 `response_code="4.00"` 场景才生成业务错误响应。

4.00 响应应回显请求 MID 和 Token（若请求有 Token），并可携带诊断 Payload。错误响应不带 Observe Option，除非未来规范明确允许。

### 9.3 4.04 Not Found

URI Path 语法合法但资源不存在时返回 4.04。测试 `coap_error_responses` 使用 unknown path，并断言响应 Code=132、Type=ACK、MID 与请求相同、Token 相同。

### 9.4 4.13 Request Entity Too Large

请求实体或服务端可接受的最大资源大小不足时返回 4.13。Block1 传输也可在任意块返回该错误；若响应带 Size2（响应大小）或诊断信息，测试应单独断言。4.13 不能被写成 413 的 HTTP 文本码；CoAP Code 是 0x8d。

### 9.5 5.00 Internal Server Error

服务端发生未分类内部错误时返回 5.00。该响应属于应用层失败，仍应遵循 CoAP MID/Token 关联，不应把 Go error 字符串直接作为协议 Code。5.00 不附带 Observe Option。

### 9.6 RST 与格式错误

当固定头 Ver 非 1、TKL 在 9–15、Length nibble=15、Option 顺序逆序、Payload Marker 后无字节或保留 Code 无法处理时，可以在接收实现返回 RST。生成器 Validate 负例则必须返回明确错误。

负例契约：

| ID | 输入故障 | 最低错误信息 |
|---|---|---|
| coap_invalid_version | Ver=2 | `version` |
| coap_invalid_tkl | TKL=9 | `token` 或 `TKL` |
| coap_invalid_code | Code=0x1f | `code` |
| coap_uri_too_long | URI/Path 超过实现上限 | `uri` 或 `path` |

### 9.7 非法 URI

Path 段含 NUL、非法 UTF-8、单段超过实现上限或整体 URI 超过配置上限时，Validate 应返回错误。URI 过长不是自动截断；截断会改变资源语义，除非协议扩展明确定义，否则禁止静默截断。

### 9.8 非法 Option

- Option Number 未递增：构造器必须按编号排序或返回错误；不得发出逆序 Option。
- Length nibble=15：返回格式错误。
- Block SZX=7：返回非法 Block Option。
- Observe 长度大于 3：返回非法 Observe 值。
- ACK/RST 携带 Uri-Path 或 Payload：返回消息类型错误。

### 9.9 重传耗尽

达到初始包加 `MaxRetransmit` 次重传后，状态转为 Timeout。Timeout 不是 5.04 响应；前者是本地传输状态，后者是远端 CoAP 服务端响应。日志和测试摘要必须区分二者。

### 9.10 错误传播

Validate 或 Plan 失败必须通过 API/任务层向调用方传播；不能返回“任务完成但 0 包”。pacing、writer 和 collector（收集器）收到上游错误时应停止等待并释放资源。错误路径也应经过 goleak（泄漏检测）和 race（数据竞争）测试。

---

## 10. 扩展字段映射

### 10.1 Wireshark 字段

本地 tshark（命令行抓包解析器）字段核对结果如下，测试优先使用这些实际名称：

| 语义 | 字段 |
|---|---|
| 版本 | `coap.version` |
| 类型 | `coap.type` |
| Token 长度 | `coap.token_len` |
| Token | `coap.token` |
| MID | `coap.mid` |
| Code | `coap.code` |
| Payload | `coap.payload` |
| Payload 长度 | `coap.payload_length` |
| Uri-Path | `coap.opt.uri_path` |
| 重组路径 | `coap.opt.uri_path_recon` |
| Uri-Query | `coap.opt.uri_query` |
| Content-Format | `coap.opt.ctype` |
| Accept | `coap.opt.accept` |
| Observe | `coap.opt.observe` |
| Max-Age | `coap.opt.max_age` |
| ETag | `coap.opt.etag` |
| Block 编号 | `coap.opt.block_number` |
| Block M | `coap.opt.block_mflag` |
| Block 大小 | `coap.opt.block_size` |
| Option Delta | `coap.opt.delta` |
| Delta 扩展 | `coap.opt.delta_ext` |
| Option Length | `coap.opt.length` |
| Length 扩展 | `coap.opt.length_ext` |
| Payload Marker | `coap.opt.end_marker` |
| 重传标记 | `coap.retransmitted` |
| 响应关联 | `coap.response_in`、`coap.response_to` |
| 响应时间 | `coap.response_time` |

字段名特别说明：Content-Format 的本地字段是 `coap.opt.ctype`，不是未经核实的 `coap.opt.content_format`；Blockwise 本地字段是 `coap.opt.block_number`、`coap.opt.block_mflag` 和 `coap.opt.block_size`，不应假设存在 `coap.opt.block2.num.num`。

### 10.2 trafficgen 配置到 wire 映射

| 配置字段 | Wire（线上）语义 | Wireshark 字段 |
|---|---|---|
| `method` | Code 0.01–0.04 | `coap.code` |
| `confirmable` | Type=CON/NON | `coap.type` |
| `message_id` | Byte 2–3 MID | `coap.mid` |
| `token` | 固定头后 TKL 字节 | `coap.token` |
| `path[]` | 重复 Uri-Path Option | `coap.opt.uri_path` |
| `query[]` | 重复 Uri-Query Option | `coap.opt.uri_query` |
| `content_format` | Content-Format uint | `coap.opt.ctype` |
| `accept` | Accept uint | `coap.opt.accept` |
| `observe` | Observe uint | `coap.opt.observe` |
| `block1` | Block1 uint | Block 字段，方向由包决定 |
| `block2` | Block2 uint | Block 字段，方向由包决定 |
| `payload` | `0xff` 后字节 | `coap.payload` |

### 10.3 FrameAssert 基准

FrameAssert（帧字节断言）必须明确 offset（偏移）基准。推荐格式（以 C-001 的实际 TKL=4 头为例）：

```json
{
  "packet": 1,
  "offset": 42,
  "hex": "44 01 10 01"
}
```

这里的首字节 `0x44` 表示 Ver=1、Type=CON、TKL=4；它必须与实际 Token 长度一致。42 只适用于无 VLAN、无 IPv4 选项的 Ethernet+IPv4+UDP 典型帧，表示 UDP payload 的 CoAP 固定头；用例 notes 必须写明该假设。IPv6 典型偏移不同，VLAN、IPv4 options、扩展头也会改变偏移。跨承载测试更应使用 `coap.*` 字段断言。

### 10.4 DTLS 扩展

CoAP over DTLS 的抓包通常无法直接看到 `coap.*` 明文字段，除非提供解密密钥。测试只应断言 UDP 5684、DTLS 记录和层链关系；明文 CoAP 字节断言属于 DTLS 解密测试的后续范围。不得在无密钥的 pcap 上声称验证了 CoAP Code 或 Option。

### 10.5 RFC 8323 扩展

CoAP/TCP 的字段映射不能套用 `coap.version`、`coap.type`、`coap.mid` 的 UDP 语义。实现时应单独记录 length prefix（长度前缀）、Csm（能力和设置消息）和 TCP stream（TCP 流）关联。本文的 `coap.json` 只覆盖 UDP。

### 10.6 代理和缓存扩展

Proxy-Uri、Proxy-Scheme、ETag、Max-Age、If-Match（匹配条件）和 If-None-Match（非匹配条件）可在后续用例中加入。扩展要求：

1. 先在配置 Typedef 中定义类型和范围。
2. 在 Option 编号排序表中加入。
3. 在 Wireshark 字段核对后增加字段断言。
4. 增加至少一个正向和一个非法值用例。
5. 不以 HTTP Header（头字段）名称替代 CoAP Option 编号。

### 10.7 自定义内容格式

Content-Format registry（内容格式注册表）中的数值由 IANA（互联网号码分配机构）维护。trafficgen 不应把未知数值自动拒绝为未知协议；只要 uint16 范围合法，可以作为 opaque content（不透明内容）发送，除非用例要求 Validate 约束已注册值。Payload 字节仍由调用方负责。

### 10.8 未来扩展边界

未来可加入：

- RFC 9175 的 Echo（回显）和 Request-Tag（请求标签）。
- RFC 7967 的 No-Response（无响应）Option。
- RFC 8323 的 TCP/TLS 传输。
- DTLS 1.2/1.3 的加密承载。
- Proxy、缓存、条件请求和大规模 Observe。

每个扩展必须保留 UDP 基础用例，不能以扩展用例替代核心固定头、MID、Token 和 Option 排序测试。

---

## 11. 修订记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1.0.0 | 2026-08-19 | 初稿：建立 CoAP/UDP 5683 分层契约；覆盖 RFC 7252 固定头、Option、CON/NON/ACK/RST、重传、Blockwise、Observe、IPv4/IPv6、多会话和负路径；给出 pcap 字段与用例索引。 |

### 11.1 本稿自审清单

- [x] 固定头按 Ver/T/TKL/Code/MID 逐字段描述。
- [x] 明确 TKL=9–15 和 Option nibble=15 的错误语义。
- [x] 明确 Payload Marker 不能单独出现。
- [x] 明确 Option 编号递增和扩展字节计算。
- [x] 明确 Block1/Block2 NUM/M/SZX 位布局和块大小。
- [x] 明确 Observe Token、24 bit 序列和错误响应限制。
- [x] 明确 ACK MID 回显、独立响应新 MID 和 RST 空消息。
- [x] 明确 ACK_TIMEOUT、随机因子和最多 5 次发送。
- [x] 明确生成器只发消息事件，不构造 UDP/IP/Ethernet。
- [x] 明确 CoAP 层尚未注册，本文不是 Go 代码修改。
- [x] 映射表使用本地已核实的 Wireshark 字段名。
- [x] testcase 索引与 `coap.json` ID 规划一致。

### 11.2 实现前复核要求

代码实现前必须重新核对 RFC 7252、RFC 7959、RFC 7641 和本地 tshark 字段；任何新增字段都要有 spec-driven（由规范驱动）正向和负向测试。实现后必须进行逐字段代码审查、`go vet`、相关单元测试、pcap/tshark 集成测试和 `-race` 测试。
