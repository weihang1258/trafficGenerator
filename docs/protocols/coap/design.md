# CoAP（受限应用协议）协议设计

> 版本：v2.0.0（P1–P3 完整产物）
> 日期：2026-09-26
> 状态：P1 八项规范矩阵（§12）+ 三子表 + 三路对照与候选方案对比（§12.4/§12.5）+ 门1 §1–§14 十四行表（§13，§1/§3/§12 强制展开）+ P2 D-COAP-1 代码设计草稿（§14）+ P3 对接清单与缺口立项（§15/§16）已落盘；**`coap` 层已注册、builder/planner/generator 已落码**（`registry.go:438-470`，29 个 Fields），且 `translateTerminalConfig` 已有 `case "coap"`（`chain_planner_translate.go:3393-3431`）。当前 cases 为 19 例：12 个正例、4 个协议输入负例和 3 个层链契约负例；未运行 suite。本契约不修改 Go 实现。
>
> 配套文件：`docs/protocols/coap/testcase.md`、`trafficgen/test/protocol_pcap/cases/coap.json`（19 例，当前 1616 行）
>
> 规范基线：RFC 7252（核心）、RFC 7959（Blockwise）、RFC 7641（Observe）、RFC 8323（TCP/TLS 传输，仅边界）。
>
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,udp,coap]`，IPv6 地址仍住 `ip` 层）；地址只住 `ip`、端口只住 `udp`。当前 19 例由 12 个业务正例、4 个协议输入负例和 3 个层链契约负例组成。三条契约负例故意保留违规顶层键或 TCP 载体，用于验证框架拒绝路径；未运行 suite。
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
3. 与分层配置架构一致：`ip`、`udp`、`coap` 层条目分别承载地址、端口和业务参数，数量由 case 顶层策略字段传递。
4. 对 CON（Confirmable，可确认）消息给出确定的重传上限和序列语义。
5. 使每个测试用例能映射到设计条目和实际 Wireshark（网络协议分析器）字段。
6. 明确哪些行为是协议规定，哪些行为是 trafficgen 的确定性测试策略。

### 1.5 非目标

- 本文不修改 registry（注册表）或任何 Go（编程语言）源文件；CoAP 层已注册，相关生成器代码已落地，但层链业务键接线仍登记在 G-COAP-1。
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
  {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
  {"udp": {"src_port": 56565, "dst_port": 5683}},
  {"coap": {
    "method": "GET",
    "path": ["sensors", "temp"],
    "confirmable": true,
    "token_length": 4
  }}
]
```

`ip`/`udp`/`coap` 层条目分别承载地址、端口和 CoAP 业务参数；层链是配置真相，翻译阶段再映射到 `spec.CoAP`/`FlowMeta`，避免重复的顶层业务键。当前翻译接线尚未完成，见 G-COAP-1。

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

`Tokens`（会话令牌数组）、`MessageIDs`（会话消息标识符数组）、`SessionSrcIPs`（会话源地址数组）和 `SessionSrcPorts`（会话源端口数组）仅在多会话场景使用；数组长度必须彼此对齐。数量由 case 顶层 `strategy_fc.value` 承载，不使用未消费的顶层 `sessions`。

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

### 5.7 层内业务配置

当前用例的目标形状是严格层链，层内业务键直接位于 `coap` 层条目：

```json
"layers": [
  {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
  {"udp": {"src_port": 56565, "dst_port": 5683}},
  {"coap": {
    "method": "GET",
    "path": ["sensors", "temp"],
    "confirmable": true,
    "token_length": 4
  }}
]
```

`ip` 层承载地址，`udp` 层承载端口，`coap` 层承载业务字段；层条目不是空配置。该形状是文档与 JSON 的配置权威，但当前 `translateTerminalConfig` 尚无 `case "coap"`，因此尚未宣称端到端 suite 可运行，见 G-COAP-1。

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

CoAP 层已注册并已有 builder/planner/generator；本轮仅保留层链业务键接线缺口 G-COAP-1，不在本文修改 Go 实现。

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

CoAP 层当前已注册，但层链业务键尚未完成 `translateTerminalConfig` 接线（G-COAP-1），因此本轮未运行 suite、服务或 MCP，也不宣称端到端通过。接线完成后，必须先运行 CoAP 单协议，再运行完整 pcap 套件；任何规划错误都必须传播为明确错误，不能吞掉并返回 0 包成功。

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
- [x] 明确 CoAP 层已注册；本文不修改 Go 代码，层链业务键接线缺口单列 G-COAP-1。
- [x] 映射表使用本地已核实的 Wireshark 字段名。
- [x] testcase 索引与 `coap.json` ID 规划一致。

### 11.2 实现前复核要求

代码实现前必须重新核对 RFC 7252、RFC 7959、RFC 7641 和本地 tshark 字段；任何新增字段都要有 spec-driven（由规范驱动）正向和负向测试。实现后必须进行逐字段代码审查、`go vet`、相关单元测试、pcap/tshark 集成测试和 `-race` 测试。

### 11.3 v1.0.0 过期声明勘误（P1 实测，本版以 §1 与本节为准）

v1.0.0 全文的「不注册 CoAP 层、不修改 registry 和任何 Go 源文件」「未注册状态下的 `coap.json` 是未来实现的契约骨架」**已由当前实现勘误**（2026-09-26）：

| v1.0.0 声明 | 实测真相 | 证据 |
|---|---|---|
| 不注册 CoAP 层 | 已注册 `coap` 终结层（`CategoryTerminal`、`DependsOn ["udp"]`、29 个 `Fields`、无 `TransportOn`/`FieldContract`/`OptionalOn`） | `trafficgen/internal/core/layers/registry.go:343-379` |
| 不修改 Go 源文件 | `internal/protocol/coap/` 非测试四文件 715 行（builder 219 / layer_gen 314 / planner 172 / types 10，另 `internal/core/coap.go` 116；测试三文件 333 行）+ 15 个测试函数；服务端已注册链式 planner 与空导入 | `internal/protocol/coap/`、`cmd/server/main.go:23`、`cmd/server/main.go:496` |
| 层条目零负载、业务参数住 flat `FlowMeta` | 层注册表已给 coap 29 个业务 `Fields`；但**链路径无 `translateTerminalConfig` case**，层内业务键今天到不了 `spec.CoAP`（flat 键路径才通）——「层链 + 层内业务键」今天跑不通，需先补代码（§1.9 声明，G-COAP-1） | `chain_planner_translate.go:689-2584` 无 `case "coap"`；flat 读取在 `strategy_convert.go:1397` |
| `coap.json` 当前契约 | 19 例：12 正例、4 协议输入负例、3 层链契约负例；正例与协议输入负例为严格层链形，契约负例故意违规 | `cases/coap.json` 1616 行，实际形状见 testcase §14 |

## 12. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①事件×交换状态矩阵（§12.2）②数据形态变体表（§12.3）③商业行为→用例映射表（§13.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **UDP 载体铁律（逐矩阵行重申）**：coap 坐 udp（registry `DependsOn ["udp"]`，`registry.go:344`）——链中夹 `tcp` 层今天报 `transport layer duplicated`（实测：`[ip,tcp,coap]` 补全成 `[ip,tcp,udp,coap]` 后两个传输层），**不是** `carrier` 锚词（coap 无 `TransportOn`，`complete.go:465/475` 的专用 carrier 分支不触发）→ 载体负例的锚词口径见 §14 与 G-COAP-3。
> **端口住处铁律**：5683 缺省**不住 `FieldContract`**（registry coap 行无该键），住 `chain_planner.go:918-919` 的 `validateSpecBase` 端口 switch；flat 路径由 `strategy_convert.go` 的报文配置解析块承接。§5.1 原稿写的 `LayerSchema{... DependsOn: []string{"udp"}}` 与实测一致，但「层条目零负载」与实测不符（29 个 Fields 已登记）。

### 12.1 八项规范矩阵

| # | 规范要求（RFC + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：UDP 无连接请求/响应；CON（可确认）需 ACK、NON 不需；一 COAP 消息 = 一 UDP 数据报；无握手、无挥手（RFC 7252 §2/§4.2；本契约 §3/§6） | 受限设备读/写资源、事件上报 | 已实现：生成器逐事件 Emit（`layer_gen.go:16-239`，请求+响应两事件），wire 由 `BuildMessage` 纯函数产出（`builder.go:26-128`） | UDP 语义（报长/checksum）由 udp 层生成器承载；P4 只做层链整形+链级红例+casegen（§14） |
| 2 | 命令消息表：方法 Code 0.01–0.04（GET/POST/PUT/DELETE）+ 响应码 2.01/2.02/2.04/2.05、4.00/4.04/4.13、5.00（RFC 7252 §5.9/§12.1；本契约 §2.3） | 四方法全量 + 成功/客户端/服务端三类响应 | 已实现：`methodCode`（`builder.go:130-142`）+ `responseCode`（`:143-163`，**8 个码值**：65/66/68/69/128/132/141/160，即 2.01/2.02/2.04/2.05 + 4.00/4.04/4.13 + 5.00） | **响应码全集缺口**：未登记 2.03 Valid(67) 与 4.01/4.02/4.05/4.08/4.12、5.01/5.02/5.03/5.04/5.05（15 个规范码中已登记 8 个）；2.01 Created(65) 已登记但无用例 → G-COAP-2（A′ 补例面） |
| 3 | 状态机：请求 →（ACK 捎带 | 空 ACK → 独立响应 | RST）→ 完成；CON 超时按 ACK_TIMEOUT×随机因子翻倍重传，至多 MAX_RETRANSMIT=4（总发送 5）；Observe 注册→通知→注销；Block2 逐块请求（RFC 7252 §4.2/§5.2/§5.3；RFC 7641 §3；本契约 §4） | 超时重传序列、空 ACK 后独立响应、通知序列、分块续取 | 已实现：重传分支（`layer_gen.go:35-46`，1+MaxRetransmit 次同字节重发）、错误响应序列（`:49-82`）、Block2 逐块（`:85-111`）、Observe 注册/通知/空 ACK（`:114-174`）；校验器 `Planner.Validate`（`planner.go:20-101`） | 超时参数 `ack_timeout`/`random_factor`/`force_timeout` **零消费**（只有 `max_retransmit` 被读）→ G-COAP-2；`observe.register` 零消费（注册恒发）→ G-COAP-2 |
| 4 | 字段表：4 字节固定头 `Ver(2b)/T(2b)/TKL(4b)/Code(1)/MID(2)`；Token 0–8 字节；Option nibble 编码（13/14 扩展、15 保留）+ 编号递增；`0xff` Payload Marker；Block 值 `(NUM<<4)|(M<<3)|SZX`（RFC 7252 §3；RFC 7959 §2.2；本契约 §2） | 路径/查询/格式选项、Token 关联、分块值 | 已实现：固定头 `builder.go:73-77`、`optionNibble`（`:211-219`）、`uintBytes32` 最短编码（`:170-181`）、`block2Value`（`:186-195`）、Option 稳定排序 + 逆序守卫（`:109-118`） | Option 编号常量只登记 6/11/12/15/17/23 六个（`builder.go:9-16`）：**ETag(4)/Max-Age(14)/Block1(27)/Proxy-Uri(35)/Proxy-Scheme(39)/Size1(60)/Size2(28) 未接线** → G-COAP-2 |
| 5 | 错误处理：Ver≠1 / TKL>8 / Code 非法 / URI 超限 / 选项越界五类拒收，失败须传播为 task error（RFC 7252 §3/§5.9；本契约 §9） | 脏配置一律任务失败，零假成功 | 已实现：四负例锚词逐字实测——`version`（`planner.go:42-44`）、`token`（`:45-47` 与 `:48-50`）、`code`（`:54-56`）、`URI`（`planner.go:65-76` 的 `URI exceeds maximum length`） | 链级红例 P4 新增（presence/白名单/载体口径见 §14）；`Block SZX=7` 拒（`planner.go:95-99`）与 `retransmit>4` 拒（`:82-84`）**有用例缺口** → G-COAP-2 |
| 6 | 超时与活性：ACK_TIMEOUT=2s、ACK_RANDOM_FACTOR=1.5、MAX_RETRANSMIT=4、MAX_TRANSMIT_WAIT=93s（RFC 7252 §4.8；本契约 §4.2） | 弱网丢包下的重传兜底 | 已实现（部分）：`max_retransmit` 消费（`layer_gen.go:36`），<=4 有校验（`planner.go:82-84`）；重传包同字节（同 `cfg` 重调 `BuildMessage`） | **不做真实时间调度**：规划器不 sleep、不实现指数退避与随机因子（声明式回放族）→ 明确不支持；参数零消费面 → G-COAP-2 |
| 7 | NAT/代理：Proxy-Uri(35)/Proxy-Scheme(39) 是 CoAP 层选项；NAT 只改 IP/UDP 寻址，不改 CoAP 字节（RFC 7252 §5.7；本契约 §10.6） | 经 NAT 访问、正向代理 | **明确不支持**：`builder.go:9-16` 无 35/39 常量，无 proxy 配置键（显式声明，不用「待确认」逃逸） | 无缺口（显式不支持 ≠ 缺口）；未来扩 Proxy 面须先补 Option 常量再补例（§10.6 五步） |
| 8 | 版本方言：Ver 恒 1（RFC 7252 §3 保留其他值）；RFC 8323 的 CoAP over TCP/TLS 是**另一套 framing**（长度前缀、无 Type/MID）；CoAP over DTLS 5648 面另有载体（RFC 8323 §3；RFC 7252 §9） | 明文 UDP 5683 为唯一形态；DTLS（5684）/TCP（5683）另议 | 已实现：Ver 校验（`planner.go:42`）；**TCP/DTLS 载体未接线**（registry coap 行无 `TransportOn`/`OptionalOn`，链路径只认 udp） | RFC 8323 TCP/TLS → G-COAP-3（明确不支持，本轮不做）；DTLS 载体（`dtls` 层已注册 `registry.go:760`）→ G-COAP-3 另轮 |

### 12.2 子表①：事件×交换状态矩阵（逐格已覆/缺失）

行=消息/事件形状，列=状态前置面：

| 事件 \ 状态面 | 合法前置满足 | 前置缺失/参数越界 | 方向颠倒 | 重复/续取 |
|---|---|---|---|---|
| CON 请求 + 捎带 ACK（#1/#3/#4/#5） | 已覆 #1/#3/#4/#5 | 缺口→负例通道 #13–#15（版本/TKL/Code 拒） | 不适用（CON 请求恒 client→server） | 已覆 #5（同 MID 同字节重发 5 次） |
| NON 请求（#2） | 已覆 #2 | 不适用（NON 无 ACK 前置） | 不适用 | 缺口→A′（NON 不重传，无「重复」语义例） |
| 空 ACK / 独立响应 | 已覆 #9（CON 通知的空 ACK） | 缺口→B′（`response` 只有布尔开关，无独立响应事件形） | 不适用 | 缺口→B′（重复 ACK 去重面无实现） |
| RST | 缺口→B′（生成器无 RST 事件；`buildMessageTyped` 允许 type 3 但无调用点） | 不适用 | 不适用 | 不适用 |
| Observe 注册/通知/注销 | 已覆 #9（注册 + NON/CON 通知 + 空 ACK） | 缺口→G-COAP-2（`register` 键零消费） | 不适用 | 缺口→A′（`observe` 注销 Observe=1 无例） |
| Block2 逐块 | 已覆 #8 | 缺口→B′（GET 带 Block2 的 M 位由生成器固定 false，客户端续块仅靠数组顺序） | 不适用 | 已覆 #8（NUM 0→1、M 1→0、Token 保持） |
| Block1 上传 | 缺口→B′（**无 Block1 Option 常量**，`planner.go:111-119` 仅校验其 SZX；wire 不可产出） | 缺口→G-COAP-2（SZX=7 拒有用例缺口） | 不适用 | 缺口→B′ |

注：矩阵按**事件×状态前置轴**排——本引擎是声明式回放（事件序即时间线文本），不做对端动态应答。**逐格重数（7 行 × 4 列 = 28 格，逐格枚举，可复核）**：**已覆 7 格**（R1c1←#1/#3/#4/#5、R1c4←#5、R2c1←#2、R3c1←#9、R5c1←#9、R6c1←#8、R6c4←#8）；**缺口→负例通道 1 格**（R1c2←#13–#15）；**不适用 10 格**（R1c3、R2c2、R2c3、R3c3、R4c2、R4c3、R4c4、R5c3、R6c3、R7c3）；**A′/B′/立项承载 10 格**（R2c4、R3c2、R3c4、R4c1、R5c2、R5c4、R6c2、R7c1、R7c2、R7c4）。7 + 1 + 10 + 10 = 28 ✓ **逐格有结论、无空格**。

### 12.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 消息类型 Type | CON(0)/NON(1)/ACK(2) | #1/#3/#4/#5/#8/#9（CON+ACK）、#2（NON） | RST(3) 无例 → B′（§12.2 R4c1） |
| 方法 Code | GET(1)/POST(2)/PUT(3)/DELETE(4) | GET #1/#5/#6/#8–#12、POST #2/#7、PUT #3、DELETE #4 | 四方法全覆（实测逐例方法）；`validRequestCode` 1–4（`planner.go:103`） |
| 成功响应码 | 2.05(69)/2.04(68)/2.02(66) | 2.05→#1/#6/#7/#9/#11/#12、2.04→#3、2.02→#4 | 2.01 Created(65) **无例** → G-COAP-2；2.03 Valid(67) 未登记 |
| 错误响应码 | 4.04(132)/4.13(141)/5.00(160) | #10（三值同例，三请求三响应） | 其余 4.xx/5.xx 未登记 → G-COAP-2 |
| Token 面 | 4 字节显式 / 0 字节 / 跨包相等 / 跨会话 distinct | #1–#12（4 字节）、#10（`token: ""` 空）、#1/#8/#9（`same_as_packet`）、#12（`distinct_values`） | base64 契约见 §2.4.1；TKL 越界 → #14 |
| Option 面 | Uri-Path 多段 / Uri-Query 多段 / Content-Format / Accept | #1/#6/#8/#9/#11（路径）、#6（两条查询）、#2/#7（ctype=50）、#7（accept=50） | 断言字段 `coap.opt.uri_path/uri_query/ctype/accept` 全命中（§10.1） |
| Option 编码 | delta 直接值 / 编号排序 | #1–#12（`encodeOption` + 稳定排序 `builder.go:109-118`） | delta 扩展（13/14）面：最大 delta=23−0 直接值即可，**13/14 分支无用例** → G-COAP-2 |
| 分块面 | Block2 两块（NUM 0/1、M 1→0、SZX=3） | #8 | `coap.opt.block_size` tshark 读回 **3**（SZX 编码值，非 128 字节）——先跑后钉实测口径 |
| Observe 面 | 注册 Observe=0 → 通知序列 100/101/102（NON+CON 混合）+ 空 ACK | #9（`notification_types ["NON","CON"]`） | 断言 `coap.opt.observe` 四值 + 空 ACK 的 `coap.code=0`/`token_len=0` |
| 载荷面 | 有 Payload（`0xff` 后字节）/ 无 Payload | 有→#1/#2/#3/#7/#8/#9/#11/#12（8 例，`has_payload=true`）；无→#4/#5/#10（3 例，请求无 Payload）；#6 无显式 `has_payload` 键（对照面） | `has_payload` 布尔 + `coap.payload_length` nonzero |
| 地址族 | IPv4（10.0.0.1→20.0.0.1）/ IPv6（2001:db8::1→::2） | 15 例 IPv4、#11 IPv6 | IPv6 不复用 IPv4 offset=42（§6.13） |
| 端口面 | dst_port 5683 恒显式 / src_port 56565–56579 | 19 例 | 缺省 5683 住 `chain_planner.go:918`；P4 改写留显式值合法 |
| 多会话面 | `session_src_ports` 两条 + 逐会话 token/mid/源 IP | #12 | 数量由 case 顶层 `strategy_fc.value=2` 承载；不使用未消费的顶层 `sessions` |
| 负例面 | 版本/TKL/Code/URI 四类拒 | #13–#16 | 锚词 `version`/`token`/`code`/`URI` 逐字对 `planner.go` 实测 |

### 12.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：RFC 7252（核心）为「必须是什么」底线——4 字节固定头（§3）、Code 分类 `class<<5|detail`（§5.9/§12.1）、Option nibble 编码与 13/14/15 语义（§3.1）、`0xff` Payload Marker（§3）、ACK_TIMEOUT 2s / ACK_RANDOM_FACTOR 1.5 / MAX_RETRANSMIT 4（§4.8）、piggybacked 与 separate response（§5.2）、Uri-Path/Uri-Query 分段（§6.4/§6.5）、Max-Age 默认 60（§5.10.5）——本契约 §2/§3/§4 逐节落点。RFC 7959 §2.2（Block Option `(NUM<<4)|(M<<3)|SZX`、SZX=7 保留）、RFC 7641 §3（Observe 0 注册 / 1 注销、24 bit 序列）、RFC 8323 §3（TCP 长度前缀 framing，与 UDP 不兼容）。**章节号为 P1 依据 RFC 结构直接引用；未能联网向 rfc-editor.org 复读原文（本机 WebFetch 被安全策略拒绝）——逐条原文复核挂 G-COAP-4，按 §5.5 不把未复核细节写死进实现。**

**②现网行为**：受限设备生态以 CoAP/UDP 5683 明文为主流；Observe（RFC 7641）与 Blockwise（RFC 7959）是 LibCoAP/Californium/Eclipse Leshan 等主流栈的标配能力；大型响应普遍走 Block2（避免 IP 分片）。出处与确认方式：抓本机回环或现网 CoAP 包核对消息面（**立项 G-COAP-4**：现网级确认前相关条目按 §5.5 标「待确认」，不写死进实现）。

**③开源实现思路**：wireshark `packet-coap.c`（本机 3.6.14 实测 `coap.*` **72 个字段**，精确口径 `tshark -G fields | awk -F'\t' '$3 ~ /^coap\./'`；用例实际断言 15 个 `coap.*` 字段 + 4 个载体字段（`udp.srcport`/`udp.dstport`/`ipv6.src`/`ipv6.dst`）共 19 个去重字段，**19/19 全部命中**）；本仓库已落码 builder/planner/generator（`internal/protocol/coap/` 非测试 715 行 + 测试 333 行 + `internal/core/coap.go` 116 行）为 wire 真相——其取值面（methodCode/responseCode/block2Value/optionNibble）是断言校准基线；只借鉴字段语义与拆解思路。

**三路结论一致性**：三路在「4 字节固定头 + Ver=1、Code `class<<5|detail`（2.05=69/4.04=132）、Token ≤8、Option 编号递增 + `0xff` Marker、Block `(NUM<<4)|(M<<3)|SZX`、SZX=7 保留、UDP 5683、MAX_RETRANSMIT=4（总 5 次）」八点一致。不一致点与取舍：①`coap.opt.block_size` 的 tshark 读回值是 **SZX 编码值（3）**，不是块字节数（128）——以 tshark 实测为准写断言（§9.31）；②`coap.opt.ctype`/`coap.opt.accept` 在 tshark 里是**符号名**（`application/json`）而非数字 50——以实测字符串为准；③现网参数面（随机因子实现、独立响应时延、代理行为）未到确认级 → G-COAP-4，不写死。

### 12.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放（**已落码**） | `CoAPConfig` 结构（method/path/query/payload/token/observe/block2/retransmit/error_responses）+ wire 由 `BuildMessage` 纯函数产出；链形 `[ip,udp,coap]` | 字段可结构化断言；tshark 断言 19 字段全命中（15 个 `coap.*` + 4 载体）；与 dns/ntp 族同构 | 无独立响应/RST/Block1 事件形 | O(n) 流式；单请求单响应；UDP 单载体 | **采用（现状）** |
| B 完整状态机模拟器 | 内置 ACK_TIMEOUT 定时器、指数退避、随机因子、独立响应分离 | 最贴近 RFC 活性语义 | 需真实时钟（违反声明式回放族）、pcap 不可复现（随机因子）、超出 fixture 面 | 复杂度高；测试不确定性 | **不选**（§4.2 明示「规划器不 sleep」，由元数据表达） |
| C 生 hex 回放 | 整 packet hex 覆盖 | 最简单、可表达任意坏包 | 字段不可断言；method/option 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| D 双载体（UDP+TCP/RFC 8323） | 一套配置两套 framing | 覆盖 CoAP/TCP | framing 不兼容（长度前缀 vs Type/MID）；等于新协议工作量 | 复杂度翻倍；无 fixture 需求 | **明确不支持**（G-COAP-3，本轮不做） |

## 13. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 testcase §4/§5 当前对账：业务/协议例为严格 `[ip,udp,coap]` 层链形，3 条契约负例故意违规；数量由 case 顶层策略字段承载；非负例顶层键符合白名单 | testcase §14；G-COAP-1 接线状态另列 |
| §2 策略/任务 | 策略=单 CoAP 交换模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §12.1 #1 + §14 |
| §3 五件套 | 见 §13.3 强制展开：UDP 无连接族——会话表以 `session_src_ports[]` 多会话数组表达；事务序列 = 交换（请求→ACK/响应）而非握手；关联关系 = Token/MID 回显（无副流派生，诚实声明）；插入位置 = 终结层（UDP payload 起点 42）；时间线 = 事件序逐包 Emit（重传为重复事件，非定时器） | 本契约 §13.3 + 用例 #1/#8/#9/#12 |
| §4 查规范 | RFC 7252/7959/7641/8323（章节级引用；原文逐条复核挂 G-COAP-4）+ tshark 实测 72 个 `coap.*` 字段（用例断言 15 个 + 4 载体 = 19 全命中）+ 已落码 builder wire 真相 + §12 矩阵 8 行+三子表 + 三路对照（§12.4）+ 候选方案（§12.5） | 本契约 §12 |
| §5 依赖与错误 | `DependsOn ["udp"]`（`registry.go:344`，唯一载体；**无 FieldContract/TransportOn**——端口缺省走 `chain_planner.go:918-919` switch）；四锚词实测（`planner.go:42-44/45-50/54-56/65-76`）；失败返回 task error（零假成功） | 本契约 §2/§9 + §14 错误分支 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存数字待 P4 基准后定（§6.5 诚实待确认，不写承诺）；六类场景清单见 §14 | §14 性能设计与验收 |
| §7 三份文档 | 20-coap-{design,testcase}.md v2.0.0（行为面权威）+ D-COAP-1（本契约 §14 草稿，门1 获批=定稿）+ T-COAP（testcase §9 草稿）+ generated schema（coap 已在生成表内，29 键，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-COAP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 7252/7959/7641 条款（章节级；原文复核→G-COAP-4）+ D-COAP-1 + tshark 实测（72 个 `coap.*` 字段；用例 19 断言字段全命中）+ 已落码 builder wire 真相 + 现网形态（未确认级→G-COAP-4）；19 ID 正负对账 | T-COAP（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/72-coap/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §13.12 强制展开：四元组=ip/udp 层（五策略全支持，`layer_dyn.go:17-20` 顶层 allowlist 含 ip.src/dst/ttl + udp.src_port/dst_port）；业务字段逐个列开/不开+理由；序号算法位置 = `layer_dyn.go:770` `resolveLayerTuple`（实测行号，非「待 P4 定」） | 本契约 §13.12 |
| §13 schema 派生 | registry coap 行（29 键 Fields + `DependsOn ["udp"]`）→ 生成表 `schemas/v1/generated/layers.generated.json` coap 条目 `fields` 29 键、`depends_on ["udp"]`（实测一致）；schemagen 重跑验证无过期 | §14 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark 19 个断言字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/coap/` | 用例 §1/§6 |

### 13.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` + 本协议顶层子映射 `coap` + 存量出现的顶层 `sessions`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（IPv4 `10.0.0.1`、IPv6 例 #11 `2001:db8::1`，各例 fixture 值保留） |
| `dst_ip` | → `layers[0].ip.dst`（`20.0.0.1` / `2001:db8::2` 保留） |
| `src_port` | → `layers[1].udp.src_port`（各例 56565–56579 保留；多会话例另有 `coap.session_src_ports[]` 逐事件覆盖，`layer_gen.go:178-219`） |
| `dst_port` | → `layers[1].udp.dst_port`（`5683`；与 `chain_planner.go:918` 缺省同值，P4 改写保留显式值亦合规） |
| `count`（若有） | → 删除，走 `flow_control.flows`（存量 19 例均无此键，属「缺键补齐」非「旧键迁移」；单交换例 `flows=1`，多会话例 `flows=2`） |
| 顶层 `coap` 子映射 | → `layers[]` 中 `{"coap": {...}}` 条目（业务键全量迁入，零残留；registry Fields 29 键同名单） |
| 顶层 `sessions`（仅 #12 出现，`sessions: 2`） | → **删除**。实测零消费：全仓库无读取顶层 `sessions` 的代码（`strategy_convert.go`/`convert.go`/`chain_planner.go` 均无该键读取点；`chain_planner_translate.go:1544/1681` 读的是 h323 层内 `sessions`，另一个协议面）。多会话语义由 `coap.session_src_ports[]` 数组长度承载（`layer_gen.go:178`）；数量语义改走 `flow_control.flows`（§1.12 口径：字段不被消费 → 用例配置里删掉） |

**存量 19 例逐条去向（§9.14）**：12 个业务正例、4 个协议输入负例和 3 个层链契约负例均已登记；契约负例的故意违规形状见 G-COAP-1。

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_ip`/`dst_ip` | 删除顶层键；新增 `{"ip": {"src": ..., "dst": ...}}` 作为 `layers[0]`（**结构性新增**非仅挪值；#11 同款填 v6 地址） |
| 顶层 `src_port`/`dst_port` | 删除顶层键；写进 `layers` udp 条目（`{"udp": {"src_port": ..., "dst_port": ...}}`） |
| `layers` 内 `{"coap":{}}` 空条目 | 填入顶层 `coap` 子映射全部业务键（29 键同名单） |
| 顶层 `sessions`（#12） | 删除（零消费，见上表） |
| `flow_control` | 正例数量由顶层 `strategy_fc` 承载；负例不带成功封包断言 | |

改写后必须满足：用例顶层（case 级）仅含 `strategy_fc` 等用例框架键；`spec_json` 顶层仅 `layers` 等结构性键。7 个负例 `expect` 均为两键契约。

完整目标形状样例（**§1.9 声明：今天跑不通，需先补代码**——`translateTerminalConfig` 无 `case "coap"`，层内业务键到不了 `spec.CoAP`；补 `case "coap"`（镜像 `case "h323"` 的层 config → spec 映射）后本样例即为可跑形）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 56565, "dst_port": 5683}},
    {"coap": {
      "method": "GET",
      "path": ["sensors", "temp"],
      "confirmable": true,
      "token": "AQIDBA==",
      "message_id": 4097,
      "response_code": "2.05",
      "response_payload": "eyJ2YWx1ZSI6MjMuNX0=",
      "response_content_format": 50
    }}
  ],
  "strategy_fc": {"type": "flows", "value": 1}
}
```

多会话样例（`session_src_ports` 两条；顶层无 `sessions`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 56565, "dst_port": 5683}},
    {"coap": {
      "method": "GET", "path": ["session"], "confirmable": true,
      "tokens": ["AQIDBA==", "BQYHCA=="], "message_ids": [20481, 24577],
      "session_src_ips": ["10.0.0.1", "10.0.0.2"],
      "session_src_ports": [56565, 56566],
      "response_code": "2.05", "response_payload": "b2s="
    }}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

### 13.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | CON GET 读取资源并收捎带 2.05 内容（LibCoAP/Californium/Leshan 通用形态） | 现网通用形态（RFC 7252 §5.2 同构） | #1/#6/#11 | 已映射；**抓包级确认** → G-COAP-4（确认方式：抓本机回环或现网 CoAP 包核对消息面） |
| 2 | NON POST 事件上报（不要求 ACK，弱网省流量） | 现网通用形态 | #2 | 已映射；确认 → G-COAP-4 |
| 3 | PUT/DELETE 资源维护（2.04/2.02） | 现网通用形态 | #3/#4 | 已映射 |
| 4 | 弱网丢包下 CON 重传兜底（总发送 5 次） | RFC 7252 §4.8 + 现网形态 | #5 | 已映射；真实时间调度（退避/随机因子）**明确不支持**（§12.1 #6） |
| 5 | 大响应分块取回（Block2 续块） | RFC 7959 + 现网形态 | #8 | 已映射；Block1 上传面 → B′（G-COAP-2） |
| 6 | 资源变化订阅（Observe 注册 + 通知，NON/CON 混合） | RFC 7641 + 现网形态（Leshan/Californium 标配） | #9 | 已映射；注销（Observe=1）→ A′ 补例 |
| 7 | 资源不存在/实体过大/服务端故障的错误面（4.04/4.13/5.00） | RFC 7252 §5.9 + 现网形态 | #10 | 已映射；其余 4.xx/5.xx → G-COAP-2 |
| 8 | 多设备并发（多会话独立四元组 + Token 隔离） | 现网通用形态（LPWAN 多节点） | #12 | 已映射；聚合断言不能证明绑定（用例自认）→ A′/B′ 见 §14 |
| 9 | 脏配置拒收（版本/TKL/Code/URI 越界） | 引擎行为（planner 真实锚词行） | #13–#16 | 已映射 |
| 10 | CoAP over DTLS（5684）/ CoAP over TCP（RFC 8323）加密与流式承载 | 现网形态（DTLS 网关、CoAP-TCP 设备） | 无例 | **未实现** → G-COAP-3 |

注：本表凡记「现网通用形态」但未落抓包证据的，一律挂 G-COAP-4 且不写死进实现（§5.5）。

### 13.3 §3 强制展开：五件套（UDP 无连接族）

会话表：

| 会话 | 四元组 | 生命周期 |
|---|---|---|
| s1（单交换） | `ip.src/dst` + `udp.56565→5683` | 无建连——请求事件 → 响应/ACK 事件 → 结束（无挥手） |
| s2（#12 多会话） | `session_src_ips[i]` + `session_src_ports[i]` → 5683（逐事件覆盖，`layer_gen.go:196-219`） | 每会话各一组「请求→生成器用 `Down:false` 事件配 `SrcPort/SrcIP` 覆盖」，响应帧源端口落会话客户端口 |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 请求（CON/NON） | 无（UDP 无前置） | 发 0.01–0.04 方法 + Uri-Path/Query/Content-Format 选项（`builder.go:79-97`） | 得到 ACK/响应（#1/#3/#4）或按配置进入 t2/t3 | 超时 → t4；配置非法 → task error（#13–#16） |
| t2 捎带响应 | t1 完成且配置 `response_code` | ACK + 同 MID/同 Token + 响应码 + 可选 Payload（`builder.go:98-108`，`response=true`） | 交换完成 | 响应码未登记 → `response code %q is invalid`（`builder.go:162`）→ task error |
| t3 通知（Observe） | t1 带 `observe.start_sequence` | 首响应（ACK + Observe=seq）→ N×通知（NON/CON，MID 递增，Token 保持，`layer_gen.go:139-172`） | CON 通知追加客户端空 ACK（`:164-170`） | `notification_types` 长度≠`notify_count` → task error（`planner.go:86-88`） |
| t4 重传（CON 超时） | `retransmit` 块存在 | 同字节重发 `1+max_retransmit` 次（`layer_gen.go:35-46`） | 生成 5 包（MAX_RETRANSMIT=4） | `max_retransmit>4` → task error（`planner.go:82-84`） |
| t5 Block2 续取 | t1 带 `block2` 且 `response_blocks` 非空 | 逐块：GET(Block2 NUM=i,M=0) → ACK 2.05 + Block2(NUM=i,M=rb.More)，MID 递增 Token 保持（`layer_gen.go:85-111`） | 最后一块 M=0 完成 | `size_exp>6` → task error（`planner.go:95-99`） |
| t6 业务错误面 | t1 带 `error_responses[]` | 每项一对：GET(path_i) → ACK + err.Code（`layer_gen.go:49-82`） | 三对六包（#10） | 错误码未登记 → task error |

关联关系（§3.8–3.10 三件事）：本协议**无控制/数据分离与副流派生**（UDP 单数据报交换，无 `driven_by` 面）——诚实声明；关联锚点是 **Token 与 MID**：ACK/响应的 MID 必须回显请求 MID（`respCfg.MessageID = mid`，`layer_gen.go:70/99/127`）、Token 保持（`same_as_packet` 断言），多会话以 `session_src_ports[]` 索引关联（#12）。与 CWMP 范本差异：CWMP 是 `flows[] + driven_by` 的副连接编排，CoAP 是单报关联——**不使用 `driven_by`**（无副流，不虚构）。

插入位置：终结层——CoAP 消息字节经 udp 层包装为数据报（`L4 Protocol udp`；udp 层承载报长/checksum）；无 IP option 时 UDP payload 起点 42（IPv4）/ IPv6 不同（不复用 42）。

时间线：**顺序**——单会话内 t1→t2/t3/t4/t5/t6 严格事件序（`layer_gen.go` 逐事件 Emit）；重传是**重复事件而非定时器**（`ack_timeout`/`random_factor` 零消费，§12.1 #6）；多会话（#12）按 `session_src_ports[]` 顺序逐会话发两组事件，输出不假设全局包序，只断言流内 Token/MID 与四元组隔离（`distinct_values` 聚合）。§3.12 的调度方式在本协议落点为「事件序逐包 Emit」。

### 13.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多客户端并发锚点（顶层 allowlist `layer_dyn.go:18`） |
| `dst`（dst_ip） | ip 层 | 全开 | 同上（`layer_dyn.go:18` 同键） |
| `ttl` | ip 层 | 全开（allowlist 已登记） | 非 CoAP 语义，随层通用面 |
| `src_port` | udp 层 | 全开 + 未写动态保底 `12345+i` | §12.2/§2.8；多会话例 #12 走 `coap.session_src_ports` 静态数组（P4 不改语义，动态可选） |
| `dst_port` | udp 层 | 全开（fixture 恒 5683） | §12.2；5683 缺省由 `chain_planner.go:918` 承接 |
| `coap.*` 全部业务键（method/path/query/payload/token/observe/blocks/retransmit/error_responses/session_*） | coap 层 | **不开**（对象即拒） | coap 不在 `layerDynAllowlist`（`layer_dyn.go:17-76` 无 coap 行）→ 业务键写动态对象会被 `ValidateLayers` 判 `does not support dynamic`；业务变体靠多策略（§2.5），不用动态冒充 |

序号算法代码位置：**`internal/core/layer_dyn.go:770` `resolveLayerTuple(spec *FlowSpec, i int)`**（实测行号；`i` = 流序号，worker 在 Plan 前逐流解析写入 spec，`FlowIndex` 经 `flowMetaFor`（`chain_planner_chain.go:22`）传给生成器）。coap 层本身不参与动态解析（业务键不开动态）。

### 13-P2 presence 负例形状（链级红例必含①）与实测边界

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"udp":{}},{"coap":{}}],"coap":{}}` 的目标语义是 planner/validator 拒（`error_contains` 含 `top-level` 或 presence 锚词）。**P1 实测（临时探针，已删除）**：今天该形状**不被拒**——`CheckProtoFlat`（`strategy_convert.go:8322-8555`）对 coap 无自键分支（该函数已为 http 族 8 协议 + dns/mqtt/cwmp/megaco/hl7/mmse/edp/xmrmining/bacnet/smtp/pop3/sstp/imap/mcp/srv6/fins/goose/sv/icmpv6/h323/mpls/ngap/telnet/sip/radius/ntlm/pppoe/ldap/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905/arp/icmp 登记顶层子映射判死，**coap 未登记**），`checkLayerFlatConflict`（`schema/semantic.go:183-193`）只查 `src_ip/dst_ip/src_port/dst_port/src_mac/dst_mac` 六键。故 **coap 的 presence 负例在 P4 补 `CheckProtoFlat` coap 分支之前无法判死**——这正是 P4 接线件之一（§14 与 G-COAP-1）。

白名单外游离键（如顶层 `src_mac`/`ttl`）判死负例：`checkLayerFlatConflict` 已覆盖 `src_mac`/`dst_mac`；`ttl` 由 `pipe_gate.sh 门2-1` 拦（游离键清单含 ttl）。**载体负例锚词口径（实测）**：`[ip,tcp,coap]` 今天报 `layers: transport layer duplicated (2 transport layers: tcp, udp)`（补全插入 udp 在前，coap 无 `TransportOn` 故 carrier 专用分支不触发）——负例以完整错误中的 `transport` 作为设计口径（现有 fixture 用 `tcp` 子串，同样命中但更弱）；P4 若要 `carrier` 锚词须给 coap 加 `TransportOn ["udp"]`（镜像 bacnet 形态，`complete.go:475`）。P4 链级红例为 3 例（presence/白名单游离键/载体）；缺 ip 由依赖补全供给，不是错误，另有正向链级测试覆盖。

## 14. D-COAP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。coap wire 面已落码（`internal/protocol/coap/` 非测试 715 行 + 测试 333 行），D-COAP-1 覆盖「已落码对接 + P4 层链整形差量」，不重发明 wire。

**文件清单（已落码 4 + P4 新建 1 + 接线/守卫 4，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| `internal/protocol/coap/builder.go`（已落码，219 行） | wire 纯函数：Option 常量 `:9-16`（6/11/12/15/17/23）/`BuildMessage :26`/`buildMessageTyped :30-128`（固定头 `:73-77`、Option 收集 `:79-108`、排序+逆序守卫 `:109-118`、Payload Marker `:123-126`）/`methodCode :130-142`/`responseCode :143-163`（12 码值）/`uintBytes :164`/`uintBytes32 :170-181`/`block2Value :186-195`/`encodeOption :203-210`/`optionNibble :211-219` |
| `internal/protocol/coap/planner.go`（已落码，172 行） | `Planner.Validate :20-101`（IP/端口 `:21-35`、Ver `:42-44`、Token `:45-50`、Code `:51-59`、Path/Query NUL `:60-64`、URIMaxLength `:65-76`、ResponseCode `:77-81`、retransmit≤4 `:82-84`、Observe 一致性 `:85-94`、SZX≤6 `:95-99`）/`validRequestCode :103`/`Plan :122-165`（legacy 单请求单响应，默认端口 5683 `:126-128`）/`coapTTL :166-171`/`shouldRespond :172` |
| `internal/protocol/coap/layer_gen.go`（已落码，314 行） | 层生成器 `CoAPGenerator.Generate :16-239`：Retransmit `:35-46`/ErrorResponses `:49-82`/Block2 `:85-111`/Observe `:114-174`/多会话 `:178-221`/默认单交换 `:224-238`；`notificationType :243-254`；`configFromValue :267-292`（空配置默认化 GET+不响应）；`effectivePort :293-298`；`decodeToken :303-309`；注册 `:311-314` |
| `internal/core/coap.go`（已落码，116 行） | `CoAPConfig`（29 键，`:9-43`）+ `ResponseBlockConfig :49-54` + `BlockConfig :58-62` + `ObserveConfig :65-71` + `CoAPRetransmitConfig :74-79` + `Duration` JSON 双形（`:86-108`，接受 `"2s"` 与裸纳秒）+ `ErrorResponseConfig :111-116`；`FlowSpec.CoAP`（`types.go:1678`） |
| `internal/protocol/coap/types.go`（已落码，10 行） | `protocol/coap` 侧类型别名（= `core.*`） |
| `internal/protocol/coap/coap_casegen_test.go`（P4 NEW） | 一次性生成器：19 例（12 正+4 负）+ 4 链级红例契约计数逐例 add()，落 `test/protocol_pcap/cases/coap.json`（层链整形后形状） |
| 接线件（P4 新增，全部属**跨协议共享文件**→须主线程执行，车道不自改） | ①`chain_planner_translate.go` 加 `case "coap"`（层 config→`spec.CoAP`，**从原始 `term.Config` 只搬显式键，不走 `completedConfig`；理由是保留缺失键/空层默认的 presence 语义，先例为 tds/s7/cflow**）；②`strategy_convert.go` `CheckProtoFlat` 加 coap 顶层子映射判死分支（§13-P2）；③`coverage_gate.py` 加 `check_coap` + `CHECKS` 登记（当前未登记 → 出口 2，`coverage_gate.py:3291` 的 `CHECKS` 字典无 coap）；④（可选，载体锚词）`registry.go:343` coap 行加 `TransportOn ["udp"]`（镜像 bacnet `complete.go:475`） |
| 已落码接线（P4 只验证） | `registry.go:343-379`（29 键 Fields + `DependsOn ["udp"]`）；`protocols.go:23` 白名单 + `protocols_test.go:20` 同步；`chain_planner.go:918-919` 端口缺省 switch；`chain_planner.go:311-333` tcp/udp 层端口回填；`chain_planner_translate.go:100-103` + `generator.go:237-239` Meta 直传；`cmd/server/main.go:23` 空导入 + `:496` 注册 planner；schemagen 无过期（`layers.generated.json` coap = 29 fields + depends_on ["udp"]） |

**接口签名**（已落码，P4 落码钉死有无差量）：`BuildMessage(cfg *CoAPConfig, response bool) ([]byte, error)` / `buildMessageTyped(cfg *CoAPConfig, response bool, typeOverride *uint8) ([]byte, error)` / `methodCode(method string) uint8` / `responseCode(s string) (uint8, error)` / `block2Value(num uint32, more bool, szx uint8) []byte` / `encodeOption(delta, length uint16) []byte` / `optionNibble(v uint16) (byte, []byte)` / `(*Planner).Validate(spec core.FlowSpec) error` / `(*Planner).Plan(ctx, spec) (<-chan core.PacketConfig, error)` / `(*CoAPGenerator).Generate(ctx context.Context, req *layers.GenRequest) error` / `(*CoAPGenerator).GenEvents() layers.EventGenerator`。

**数据结构**：沿 `CoAPConfig`（`types.go:9-43` 29 键）；层链目标形状见 §13.1 样例（地址住 `ip`、端口住 `udp`、业务住 `coap` 层条目、数量只走 case 顶层 `strategy_fc`）。

**主流程**：`validateSpecBase`（IP/端口 5683 缺省）→ `translateTerminalConfig`（**P4 新增 case coap**）→ `flowMetaFor`（`CoAP: spec.CoAP`，`chain_planner_translate.go:103`）→ `CoAPGenerator.Generate` 分支选择（Retransmit → ErrorResponses → Block2 → Observe → 多会话 → 默认单交换）→ 逐事件 `BuildMessage` + `EmitMsg` → udp 层包壳 → worker → pcap/NIC。

**错误分支（§5.2）**：①`Validate` 自然守卫（Ver≠1 `:42`、Token>8 `:45`、TokenLength 不一致 `:48`、method/code 缺 `:51`、code∉1–4 `:54`、method 名未登记 `:57`、Path/Query 含 `/` 或 NUL `:60`、URI 超限 `:65`、ResponseCode 未登记 `:77`、`max_retransmit>4` `:82`、notification_types 长度/值 `:86-92`、SZX>6 `:95`）；②`BuildMessage` 构建期（config nil `:31`、version `:38`、token 长度 `:42/:45`、code 为 0 且非 ACK/RST `:70`、response code `:162`、options out of order `:113`）；③`configFromValue` 类型分支（`layer_gen.go:290`）；④P4 新增链级守卫（presence/白名单/载体，§13-P2）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `udp` 层（唯一载体：报长/checksum/端口）；依赖 `ip` 层（寻址，IPv6 同层）；无 `tcp` 依赖（RFC 8323 面 → G-COAP-3）；无外部服务端依赖；`dtls` 层为未来可选底座（今天不接线 → G-COAP-3）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 `EmitMsg`（`layer_gen.go` 六个分支各自 for 循环直发，无全量聚合；Block2 的 `response_blocks[]` Payload 由配置显式给出，属 fixture 尺寸）；确定性内存（单事件最大 = 单消息字节，fixture 级；无按包增长结构）；无锁无 sleep（事件驱动；重传为重复事件而非定时器，`ack_timeout` 零消费）；pcap 路实测 + NIC 路注记（过滤器 `udp port 5683`，测试网口按 testing-interface 记忆）；回归口径 = coap.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①**层内业务键接线必须保留 presence 语义**：`case "coap"` 从原始 `term.Config` 解码并逐键映射，不走 `completedConfig`；后者会把缺失键补成零值，压掉空层默认 GET、缺失 `response` 的响应默认及缺失 `accept` 的选项缺席语义。该差异与 tds/s7/cflow 同族，属必要裁定；②**presence 判死**已由 `CheckProtoFlat` 的 coap 分支覆盖；③**载体锚词口径**：`[ip,tcp,coap]` 报 `transport layer duplicated` 而非 `carrier`，负例按实测使用 `transport`（用例当前以 `tcp` 子串命中完整错误）；④载体/端口双轨：5683 缺省在 `chain_planner.go:918` 而非 registry `FieldContract`，用例保留显式 5683；⑤覆盖门的 mapToFlowSpec 判据必须唯一锚定其 coap 执法块，不能与 CheckProtoFlat 的同名条件混淆。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 19 例改写 + 4 链级红例 + 接线四件 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 15. P3 测试对接清单与缺口立项（T-COAP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接/同流内多轮操作→#8（Block2 两块两轮请求）、#9（Observe 注册+2 通知）、#10（三组错误交换）已覆；②非正常结束→#13–#16 四负例（版本/TKL/Code/URI 拒）已覆；③长保活→**无**：CoAP/UDP 无保活语义（无心跳、无长连接），Observe 通知需业务侧重注册（RFC 7641 §3.5），本引擎为声明式回放不内置周期——**明确不支持（显式声明，非「待确认」逃逸）**。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′ 补例建议：Observe 注销 Observe=1、NON 重复语义面、`coap.opt.uri_path_recon` 重组路径断言；B′：RST 事件形、独立响应分离式、Block1 wire、response 三元态、重复 ACK 去重）。
- 9.52 对账两行：见 testcase §9.3（清单出处声明 + 对账两行：总数 50 = 已覆 25 + 不适用 11 + A′/B′/立项 14）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议 UDP 无连接、**不主张任何豁免**：多会话 #12 已覆；单包多载荷=单报多 Option #6/#7 已覆；多事务 #8/#9/#10 已覆）。
- 三源回指行：见 testcase §9.5（第三源「已确认现网行为」当前=未确认级，挂 G-COAP-4）。
- 断言通道：19 个去重字段（`coap.*` 15 + `udp.srcport`/`udp.dstport`/`ipv6.src`/`ipv6.dst` 4，**19/19 实测命中**，§12.4 ③）+ frames hex（offset 42 单档，实测 8 条 frame 断言全部 offset=42）。

## 16. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-COAP-1 | **层内业务键不可达 + presence 判死缺失**（P4 接线四件）：①`translateTerminalConfig` 无 `case "coap"` → 目标形状跑不通；②`CheckProtoFlat` 无 coap 顶层子映射判死分支；③`coverage_gate.py` `CHECKS` 未登记 coap（出口 2）；④（可选）registry coap 行无 `TransportOn ["udp"]` → 载体负例锚词只能是 `transport` | 读 `chain_planner_translate.go:689-2584` / `strategy_convert.go:8287-8505` / `coverage_gate.py:3291` / `registry.go:343-379` 现状（P1 实测已证） | **P4 必做**（跨协议共享文件 → 主线程执行，车道不自改）；不补则门2 与目标形状均不成立 |
| G-COAP-2 | **代码覆盖缺口（A′ 补例面）**：`ack_timeout`/`random_factor`/`force_timeout` 零消费（只读 `max_retransmit`）；`observe.register` 零消费；响应码只登记 8 值（2.01 在列但无用例；缺 2.03 与其余 4.xx/5.xx）；Option 常量只 6 个（缺 ETag 4/Max-Age 14/Block1 27/Proxy 35/39/Size1 60/Size2 28）；`ErrorCode`/`ErrorPayload` 零消费（wire 不可产出）；SZX=7 拒与 `retransmit>4` 拒无用例 | 读 `internal/protocol/coap/` 与 `internal/core/coap.go` 逐键 grep 消费点（P1 实测已证） | 死配置四键已按 §1.12 从当前 fixture 删除（仅保留已消费的 `max_retransmit`；`observe` 不含 `register`）；剩余 Option/响应码面为 A′ 补例（并入与否由主线程定，不影响 19 ID 权威口径） |
| G-COAP-3 | **载体扩展（明确不支持，本轮不做）**：CoAP over TCP/TLS（RFC 8323 长度前缀 framing，与 UDP 不兼容）、CoAP over DTLS 5684（`dtls` 层已注册 `registry.go:760` 但 coap 无 `OptionalOn`） | 读 RFC 8323 §3 + registry 两行现状 | 本轮标「明确不支持」（§12.1 #7/#8）；未来扩面须先补 framing 与 `OptionalOn` 再补例 |
| G-COAP-4 | **现网证据升级 + RFC 原文逐条复核**：本机 WebFetch 被安全策略拒绝（`www.rfc-editor.org` 不可达），§12.4 ①的章节引用按 RFC 结构直接给出、未逐条回读原文；现网行为（主流栈 Observe/Blockwise 参数、弱网重传实况、代理部署）为「未确认」级 | 查 RFC 原文（联网或本地 RFC 副本）+ 抓包（本机回环或现网 CoAP 包核对消息面） | 确认前相关条目按 §5.5 标「待确认」，不写死进实现 |

**缺口数：4 项立项（G-COAP-1 必做接线 / G-COAP-2 覆盖缺口 / G-COAP-3 明确不支持 / G-COAP-4 证据升级）+ A′ 补例建议 3 条（Observe 注销、NON 重复语义、`uri_path_recon` 重组路径），无空项。**

## 17. P1/P2/P3 对抗自重审结论（10.11）

逐阶段逐轮记录见 `/tmp/pipe/72-coap/p123-report.md` §三——**P1 过 5 轮 / P2 过 3 轮 / P3 过 5 轮，末轮均干净**（修正合计 14 处 + 交付前复算 2 处，明细见报告）。

### 17.1 文档逐条自核对结论（10.1：对规范逐条核对）

- RFC 7252 核心面（4 字节固定头 Ver/T/TKL/Code/MID、Code `class<<5|detail`、Option nibble 13/14/15、`0xff` Marker、Token ≤8、ACK MID 回显、ACK_TIMEOUT 2s/随机因子 1.5/MAX_RETRANSMIT 4/MAX_TRANSMIT_WAIT 93s、piggybacked vs separate response、Uri-Path/Uri-Query 分段、Max-Age 默认 60、Proxy-Uri/Proxy-Scheme、错误码分类 2.xx/4.xx/5.xx）→ 本契约 §2/§3/§4/§9 逐条有落点；RFC 7959 §2.2（Block 值位布局、SZX 0–6 与 7 保留）→ §2.10/§3.5；RFC 7641 §3（Observe 0/1、24 bit 序列、错误响应不带 Observe）→ §3.4/§4.6；RFC 8323（TCP 长度前缀、无 Type/MID）→ §5.6/§10.5/§12.1 #8。章节号为 P1 依据 RFC 结构直接引用，逐条原文复核挂 G-COAP-4（§5.5 不写死）。
- 实现面逐条：`builder.go`/`planner.go`/`layer_gen.go` 每个校验分支与 wire 分支都在 §12.1/§14 有对应行（锚词 `version`/`token`/`code`/`URI` 逐字对 `planner.go:42-76` 实测）。

### 17.2 与旧文档逐条核对结论（10.2）

v1.0.0 §1–§11 逐条：§1 概述（保留；1.5 非目标「不注册/不改 Go」按 §11.3 实测勘误）、§2 数据类型编码（保留，逐字段与 builder 实测对齐）、§3 消息结构（保留）、§4 状态机（保留，参数面补「零消费」实测注记）、§5 配置 Typedef（保留，按 `core/coap.go:9-43` 实测对齐 29 键；`Sessions` 顶层段按「零消费」改为删除）、§6 包序列场景（保留，逐场景补用例号与实测值）、§7 testcase 映射索引（保留 19 ID 与顺序）、§8 实现集成点（保留，注册态按实测改写）、§9 错误处理（保留，锚词实测化）、§10 扩展字段映射（保留，字段数 72 实测化）、§11 修订记录（追加 v2.0.0 + §11.3 勘误）。无旧条目被静默删除。


### 15.2 文档轨自审结论（2026-09-30）

本轮两轮自审通过：第一轮逐条核对 CORE §1.11–§1.13 的层链唯一真相、顶层白名单、数量承载和负例保留形状；第二轮以实际 JSON 重新加载，确认 19 个唯一 ID、12 正例 + 7 负例、正例及协议负例的 `[ip,udp,coap]` 层链、`strategy_fc` 数量字段和三条契约负例的故意违规键均与本文 §18 一致。未运行 Go suite、服务或 MCP，未宣称链路已跑通。



截至本任务，`trafficgen/test/protocol_pcap/cases/coap.json` 实际为 **19 例 = 12 正 + 7 负**：C-001–C-012 的 12 个业务正例、N-001–N-004 的 4 个协议输入负例，以及 `coap_neg_presence_top_level_coap`、`coap_neg_stray_src_mac`、`coap_neg_carrier_tcp` 三个层链契约负例。三条新增负例是 CORE §1.11–§1.13 的判死形状，归入 G-COAP-1，不虚增业务覆盖。

正例和四条协议负例已使用严格 `[ip,udp,coap]` 层链；三条契约负例故意保留违规顶层键或 `tcp` 承载，以验证拒绝路径。负例均不含 `packet_count`/`frames` 等成功断言，仅含 `expect_error` 与 `error_contains`。本任务未修改 Go，未运行 suite；G-COAP-1 接线完成后仍需以真实错误文案和 pcap 校准。
