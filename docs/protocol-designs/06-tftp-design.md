# TFTP 协议设计与测试用例（v2.0.2）

**协议**：Trivial File Transfer Protocol（简单文件传输协议，TFTP）
**规范来源**：RFC 1350（TFTP Rev.2）、RFC 2347（TFTP Option Extension，选项扩展）、RFC 2348（TFTP Blocksize Option，块大小选项）、RFC 2349（TFTP Timeout Interval and Transfer Size Options，超时与传输大小选项）、RFC 7440（TFTP Windowsize Option，窗口选项）、RFC 6335（Service Name and Transport Protocol Port Number Registry，服务名与传输协议端口号注册表）
**传输层**：UDP（User Datagram Protocol，用户数据报协议）
**默认服务器端口**：69（well-known port，知名端口）
**默认客户端端口**：随机临时端口（ephemeral port，由 OS 分配或配置指定）
**文档版本**：v2.1.0-P1P3（2026-09-26，P-PIPE 并发管线文档轨 P1–P3 产物：新增 §12 规范矩阵八项+三子表+三路对照+候选方案、§13 门1 §1–§14 十四行表（§1/§3/§12 强制展开）、§14 D-TFTP-1 代码设计（八要素）、§15 P3 固定动作、§16 存量 226 例审计去向、§17 去扁平改写清单、§18 修订记录。**§1–§11（v2.0.2 wire 字节语义）原样保留**，为字节级权威；§12–§17 为层链/P-PIPE 契约权威，冲突时 wire 面以 §1–§11 为准、契约面以 §12–§17 为准）
**历史版本**：v2.0.2（2026-08-05，修复 v2.0.1 复审审计（06-tftp-audit-r2-v2.md）发现的 11 个问题：2 CRITICAL + 3 HIGH + 3 MEDIUM + 3 LOW；核心阻断项为删除错误的 RFC 1783 引用并重新定义 S9 语义为 trafficgen 扩展行为）
**适用项目**：trafficgen（Go 高性能流量生成器）
**层链状态（2026-09-26 实读）**：`tftp` 层已注册（`trafficgen/internal/core/layers/registry.go:187-192`，`CategoryTerminal`、`DependsOn ["udp"]` 单值、**无 `Fields`、无 `FieldContract`、无 `TransportOn`/`OptionalOn`**）；链路上经 `[ip,udp,tftp]`；配置面今日仍走**顶层 flat `tftp` 子映射**（`strategy_convert.go:1258-1262`（`case "tftp"`）→ `spec.TFTP` → `FlowMeta.TFTP`，`chain_planner_translate.go:69-71`（`TFTP: spec.TFTP` Meta 直传））——**与 CORE_MEMORY §1.11/1.12（顶层白名单：协议业务字段一律住层链）冲突，迁层为 G-TFTP-1**。生成表实测条目：`{"category":"terminal","depends_on":["udp"],"fields":{}}`（`trafficgen/schemas/v1/generated/layers.generated.json`）。

---

## §1 协议概述

TFTP（Trivial File Transfer Protocol，简单文件传输协议）是轻量级文件传输协议，常用于无盘工作站引导（PXE boot，Preboot eXecution Environment 预启动执行环境）、嵌入式设备固件升级、网络设备配置下发。与 FTP（File Transfer Protocol，文件传输协议）相比：无认证、无目录浏览、无命令交互，只支持读（RRQ, Read Request 读请求）与写（WRQ, Write Request 写请求）。RFC 1350 §7 明确："It cannot list directories, and currently has no provisions for user authentication"（不能列出目录，也没有用户认证机制）。

### 1.1 核心特性

| 特性 | 说明 |
|------|------|
| 传输层 | UDP（RFC 1350：TFTP 基于 UDP datagram 传输） |
| 默认端口 | 服务器初始监听 69；后续双方各用一个临时端口（TID, Transfer Identifier 传输标识，即 UDP 端口号） |
| 认证 | 无（RFC 1350 §7："TFTP includes no login or access control mechanisms"，无登录或访问控制机制） |
| 数据块大小 | 默认 512 字节（DATA 不含 4 字节 TFTP 头）；可通过 blksize 选项协商（8 ~ 65464） |
| 流控 | 停止-等待（stop-and-wait）：每发一个 DATA 必须收到对应 ACK；RFC 1350："the lock step acknowledgement provides flow control"（锁步确认提供流控） |
| 结束判定 | DATA 块大小 < blksize 表示结束；文件大小恰为 blksize 整数倍时追加 0 字节块（RFC 1350 §6） |
| 重传 | 单包超时重传（默认超时值由实现决定，RFC 1350 未规定具体秒数；可经 timeout 选项协商 1-255 秒） |
| 最大文件大小 | block#（块号）是 uint16（2 字节无符号整数），blksize=512 时理论 512×65535 ≈ 32 MB；blksize=65464 时理论 65535×65464 = 4,290,434,040 字节 ≈ 3.99 GiB（受 tsize 选项 uint32 上限 4 GiB-1 制约）。trafficgen 用 `BlocksCount`（uint32）计数，wire 上 Block# 字段仍为 uint16，超出 65535 时按用户配置回绕（wrap-around）或 Validate（校验）拒绝 |

### 1.2 业务场景

1. **S1 RRQ 简单下载**：客户端从服务器下载文件，服务器推送 DATA。
2. **S2 WRQ 简单上传**：客户端向服务器上传文件，客户端推送 DATA。
3. **S3 blksize 选项**：RRQ/WRQ 末尾追加 `blksize\0value\0`，服务器回 OACK（Option Acknowledgment，选项确认）。
4. **S4 timeout 选项**：协商单包重传超时（秒）。
5. **S5 tsize 选项**：协商文件总大小（RRQ 客户端写 "0"，服务器回实际大小；WRQ 客户端写实际大小，服务器回显）。
6. **S6 windowsize 选项**：协商滑动窗口大小（RFC 7440）。
7. **S7 OACK 选项协商**：服务器对 RRQ/WRQ 中的选项子集回 OACK。
8. **S8 ERROR 中断**：任一方发 ERROR 终止（文件不存在/权限拒绝/磁盘满等）。
9. **S9 TID 变更**：服务器中途切换 TID 端口，客户端发 ERROR code=5（不终止传输）——**trafficgen 扩展行为，非任何 RFC 定义**（详见 S9）。
10. **S10 超时重传**：模拟发送方超时重传 DATA/ACK。
11. **S11 多会话**：N 个文件同时传输，每流独立 UDP 4-tuple（四元组：src_ip/dst_ip/src_port/dst_port）。
12. **S12 多流关联**：同一策略下多流按 FlowID 分组，跨流不串扰。
13. **S13 边界值**：512 字节满块、65535 块、blksize 极值（8/65464）。
14. **S14 错误处理**：Validate 拒绝非法配置；ERROR 注入。
15. **S15 完整传输流程**：RRQ → OACK → ACK#0 → DATA×N → 末块 → ACK×N 完整链路。

### 1.3 在 trafficgen 中的位置

- 包路径：`internal/protocol/tftp/tftp.go`
- Planner（规划器）：`Planner`，实现 `Validate(spec core.FlowSpec) error` 与 `Plan(ctx, spec) (<-chan core.PacketConfig, error)`
- Config（配置）：`TFTPConfig` 定义于 `internal/core/types.go`，挂在 `FlowSpec.TFTP`（新增字段）
- L4（传输层）：UDP（`L4Config.Protocol = "udp"`），默认 DstPort=69

---

## §2 数据类型与编码

### 2.1 基础数据类型

| 类型 | 编码 | 说明 |
|------|------|------|
| Opcode（操作码） | uint16 大端序（big-endian，网络字节序） | 所有 TFTP 包的前 2 字节 |
| Block#（块号） | uint16 大端序 | DATA 的块编号、ACK 的确认编号 |
| ErrCode（错误码） | uint16 大端序 | ERROR 包的错误码 |
| 字符串（filename/mode/option/value/ErrMsg） | ASCII + 单个 `0x00` 结尾 | RFC 1350："terminated by a zero byte"（以零字节结尾）。ErrMsg 为 netascii（RFC 1350 "should be in netascii"）；netascii 的 CR/LF 转换在此不适用——trafficgen 对含字符串的字段一律按字节原样写入（不做 CR/LF 转换，见 §2.3） |
| 选项值 | ASCII 数字字符串 | RFC 2348/2349/7440："Values are specified in ASCII"（值以 ASCII 指定） |

### 2.2 字节序

所有多字节数值字段（Opcode、Block#、ErrCode）一律使用大端序（网络字节序），对应 Go 的 `binary.BigEndian.PutUint16`。**禁止**使用小端序（little-endian）。

### 2.3 字符串编码

- filename（文件名）：RFC 1350 §4 "a sequence of bytes in netascii terminated by a zero byte"（netascii 字节序列，以零字节终止）。trafficgen 按字节原样写入（不做 netascii 的 CR/LF 转换，见 §3.3 TransferMode）。
- mode（传输模式）："netascii"、"octet"、"mail"（已废弃，RFC 1350："The mail mode is obsolete and should not be implemented or used"），**大小写不敏感**（RFC 1350："any combination of upper and lower case"，大小写任意组合均可）。
- 选项名：RFC 2347："case in-sensitive"（大小写不敏感）。trafficgen 输出统一小写（`blksize`/`timeout`/`tsize`/`windowsize`）。
- 错误消息：RFC 1350："intended for human consumption, and should be in netascii"（供人类阅读，应为 netascii），以零字节终止。trafficgen 限制 ErrMsg ≤ 255 字节（超过截断）。

### 2.4 数值上限

| 字段 | 范围 | 依据 |
|------|------|------|
| BlkSize | 8 ~ 65464 | RFC 2348 §2："Valid values range between '8' and '65464' octets, inclusive" |
| Timeout | 1 ~ 255 秒 | RFC 2349 §2："Valid values range between '1' and '255' seconds, inclusive" |
| TSize | 0 ~ 2^32-1 | RFC 2349 未规定上限，wire 值以 ASCII 十进制表示 |
| WindowSize | 1 ~ 65535 块 | RFC 7440 §3："The valid values range MUST be between 1 and 65535 blocks, inclusive" |
| Block#（wire） | 0 ~ 65535（uint16） | RFC 1350 未定义回绕行为；trafficgen 默认拒绝超出 |
| BlocksCount（trafficgen 配置） | 0 ~ 2^32-1 | 用户配置字段（uint32），wire 上 Block# 回绕时使用 `(i mod 65536)` |

### 2.5 端口与 TID

RFC 1350 §4：
- 每个端点（endpoint）为自己选择 TID（即 UDP 端口号），TID "should be randomly chosen"（应随机选择）。
- 请求方将初始请求发给服务器的知名端口 69（十进制；RFC 1350 原文 "the known TID 69 decimal (105 octal)"）。
- 服务器收到 RRQ/WRQ 后，**换用自己新选的 TID 端口**应答（source = server TID，destination = client TID），此后双方均用各自 TID 通信，**不再使用 69**。
- 收到包后双方校验源 TID：RFC 1350 §4 "should make sure that the source TID matches the value that was agreed on"（应确认源 TID 与约定值一致）；不匹配时"the packet should be discarded as erroneously sent from somewhere else"（该包应视为来自他处而丢弃），并向错误源发 ERROR code=5（Unknown TID），**不终止当前传输**。
- trafficgen 端口默认化：`ServerTID=0` 时按 FNV-1a(FlowID) 确定性生成 49152-65535（RFC 6335 动态端口范围）；显式设置时 Validate 要求 1024-65535（排除知名端口 <1024）。

---

## §3 消息结构

### 3.1 Opcode 表

| Opcode | 名称 | 方向 | 含义 | RFC |
|--------|------|------|------|-----|
| 1 | RRQ（Read Request，读请求） | client → server | 请求下载文件 | RFC 1350 |
| 2 | WRQ（Write Request，写请求） | client → server | 请求上传文件 | RFC 1350 |
| 3 | DATA（数据块） | 双向（取决于模式） | 携带数据，长度 ≤ blksize（默认 512） | RFC 1350 |
| 4 | ACK（确认） | 双向 | 确认收到某 Block# 的 DATA | RFC 1350 |
| 5 | ERROR（错误） | 双向 | 错误通知 | RFC 1350 |
| 6 | OACK（Option Acknowledgment，选项确认） | server → client | 确认协商的选项（RFC 2347 引入） | RFC 2347 |

### 3.2 RRQ/WRQ 报文格式（Opcode 1/2）

RFC 1350 §4 定义（选项部分由 RFC 2347 扩展）：

```
+-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+-->
|  opc  |filename| 0 |  mode  | 0 |  opt1  | 0 | value1 | 0 | ...
+-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+-->
```

| 字段 | 长度 | 说明 |
|------|------|------|
| Opcode | 2 字节 | 1=RRQ，2=WRQ |
| Filename | 变长 + 1 字节 `0x00` | 文件名（不可含 `0x00`；可含路径分隔符 `/` 或 `\`；RFC 1350 未规定长度上限，trafficgen 限制 ≤ 255 字节） |
| Mode | 变长 + 1 字节 `0x00` | `netascii` / `octet`（`mail` 已废弃，Validate 拒绝）；输出统一小写 |
| Option/Value 对 | 变长 | 0 或多个：`option\0value\0`（RFC 2347） |

RFC 2347 关键规则：
- 每个选项**只能出现一次**（"may only be specified once"）。
- 选项顺序无意义（"The order in which options are specified is not significant"）；trafficgen 固定输出顺序 `blksize → timeout → tsize → windowsize`（与 struct 字段顺序一致，便于字节精确测试）。
- 只有客户端可以发起选项协商（"Only the client may initiate option negotiation"）。
- RRQ/WRQ 最大请求包 512 字节（RFC 2347：maximum request packet size is 512 octets）。超出时选项被截断或由实现决定（trafficgen 不截断，直接生成超长包供测试）。

### 3.3 DATA 报文格式（Opcode 3）

RFC 1350 §4：

```
+-------+--------+-----------+
|  opc  | Block# |   Data    |
+-------+--------+-----------+
  2B      2B BE    0 ~ blksize
```

| 字段 | 长度 | 说明 |
|------|------|------|
| Opcode | 2 字节 | 固定 3 |
| Block# | 2 字节大端 | 从 1 开始连续递增；ACK 回显同一编号 |
| Data | 0 ~ blksize 字节 | 长度 < blksize 表示末块（传输结束，RFC 1350 §6）；长度 = blksize 表示满块——若为末块则文件大小恰为 blksize 整数倍，trafficgen 默认自动追加 0 字节末块（AutoAppendFinalBlock，§5.1）；0 字节仅用于结束标记 |

RFC 1350 关键规则：
- "Data is sent in fixed length blocks of 512 bytes"（数据以 512 字节定长块发送；协商 blksize 后为 blksize 字节）。
- "The end of a transfer is marked by a DATA packet that contains between 0 and 511 bytes of data (i.e., Datagram length < 516)"（传输结束由包含 0-511 字节数据的 DATA 包标记）。
- "If the file is an exact multiple of 512 bytes, a final packet of 0 bytes must be sent"（若文件大小恰为 512 字节整数倍，必须发送 0 字节的最终包）。
- Block# 回绕：RFC 1350 **未定义**回绕行为（"This restriction allows the program to use a single number to discriminate between new packets and duplicates"）。trafficgen 默认拒绝 `BlocksCount > 65535`（Validate 报错）；`WrapBlockNumber=true` 时 Block# = `(i mod 65536)`，即 65535 → 0 → 1 → ...。

### 3.4 ACK 报文格式（Opcode 4）

RFC 1350 §4：

```
+-------+--------+
|  opc  | Block# |
+-------+--------+
  2B      2B BE
```

| 字段 | 长度 | 说明 |
|------|------|------|
| Opcode | 2 字节 | 固定 4 |
| Block# | 2 字节大端 | 所确认 DATA 的 Block#；Block#=0 是特例：RRQ+OACK 后客户端对 OACK 的确认、WRQ 无选项时服务器"准备好接收"的确认 |

RFC 1350 关键规则：
- "ACK packets echo the block number of the DATA packet being acknowledged"（ACK 回显所确认 DATA 包的块号）。
- "WRQ is acknowledged with an ACK having block number zero"（WRQ 以块号 0 的 ACK 确认）。
- RFC 2347 §2：RRQ 收到 OACK 后客户端发 ACK（块号 0）确认选项值。

### 3.5 ERROR 报文格式（Opcode 5）

RFC 1350 §4：

```
+-------+----------+-----------+
|  opc  | ErrorCode|  ErrMsg   |
+-------+----------+-----------+
  2B      2B BE      变长 + \0
```

| 字段 | 长度 | 说明 |
|------|------|------|
| Opcode | 2 字节 | 固定 5 |
| ErrorCode | 2 字节大端 | 见 §3.6 错误码表 |
| ErrMsg | 变长 + 1 字节 `0x00` | 人类可读错误描述；可为空字符串（仅 `\0`）；trafficgen 限制 ≤ 255 字节（截断） |

RFC 1350 关键规则：
- ERROR 包**不被确认、不被重传**（"Error packets are not acknowledged, and not retransmitted"）。
- ERROR 是终止信号（"If a request can not be granted, or some error occurs during the transfer, then an ERROR packet (opcode 5) is sent"）。
- **唯一例外**：ERROR code=5（Unknown TID，未知传输标识）**不终止传输**（RFC 1350："TFTP recognizes only one error condition that does not cause termination, the source port of a received packet being incorrect"——TFTP 只识别一个不导致终止的错误条件，即收到包的源端口不正确）。收到源 TID 不匹配的包时，向错误源发 ERROR code=5 并继续当前传输。

### 3.6 错误码表

| ErrCode | 含义 | 常见场景 | RFC |
|---------|------|----------|-----|
| 0 | Not defined（未定义，见 ErrMsg） | 通用错误 | RFC 1350 |
| 1 | File not found（文件不存在） | RRQ 时服务器找不到文件 | RFC 1350 |
| 2 | Access violation（访问违规） | 权限不足 / 只读文件系统 | RFC 1350 |
| 3 | Disk full or allocation exceeded（磁盘满或分配超限） | WRQ 时服务器无法写入 | RFC 1350 |
| 4 | Illegal TFTP operation（非法 TFTP 操作） | opcode 非法 / 包格式错误 | RFC 1350 |
| 5 | Unknown transfer ID（未知传输标识） | 源端口/TID 不匹配（**不终止传输**） | RFC 1350 |
| 6 | File already exists（文件已存在） | WRQ 时文件已存在且不可覆盖 | RFC 1350 |
| 7 | No such user（无此用户） | mail 模式专用（已废弃） | RFC 1350 |
| 8 | Failed to negotiate options（选项协商失败） | 客户端拒绝 OACK / OACK 含未请求选项 / 选项值非法且规范要求终止 | RFC 2347 |

RFC 2347 §2 关于 code=8 的说明：
- "If the client rejects the OACK, then it sends an ERROR packet, with error code 8, to the server and the transfer is terminated"（客户端拒绝 OACK 时向服务器发 error code 8 的 ERROR 包并终止传输）。
- 客户端收到含未请求选项的 OACK、或支持选项的值非法且该选项规范要求终止时，同样使用 code=8。

### 3.7 OACK 报文格式（Opcode 6）

RFC 2347 §2：

```
+-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
|  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
+-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
  2B      变长     1B  变长     1B   变长     1B  变长     1B
```

| 字段 | 长度 | 说明 |
|------|------|------|
| Opcode | 2 字节 | 固定 6 |
| Option/Value 对 | 变长 | 服务器接受的选项子集；未出现在 OACK 中的选项 = 服务器不支持/拒绝，按默认值处理 |

RFC 2347 关键规则：
- OACK **不含 filename/mode 字段**，仅 opcode + 选项对。
- "The server must not include in the OACK any option which had not been specifically requested by the client"（服务器不得在 OACK 中包含客户端未请求的选项）。
- 选项名从原请求复制（"copied from the original request"），值可以不同于客户端提议值（RFC 2348：服务器返回值必须 ≤ 客户端提议值；RFC 2349 timeout：服务器必须回显相同值；RFC 2349 tsize：服务器回实际文件大小（RRQ）或回显客户端值（WRQ）；RFC 7440 windowsize：服务器返回值必须 ≤ 客户端提议值）。
- 服务器不识别某选项时应从 OACK 中省略（"Options which the server does not support should be omitted from the OACK; they should not cause an ERROR packet to be generated"）。
- RRQ 场景：客户端收到 OACK 后发 ACK#0 确认，然后服务器发 DATA#1。
- WRQ 场景：客户端收到 OACK 后**直接发 DATA#1**（无 ACK#0，RFC 2347 §2）。
- 服务器不支持选项协商时，RRQ 直接回 DATA#1、WRQ 直接回 ACK#0（即选项被忽略）。

### 3.8 选项定义

| 选项名 | RFC | 含义 | 取值范围 | 默认值 | OACK 回显规则 |
|--------|-----|------|----------|--------|----------------|
| `blksize` | RFC 2348 | 块大小（DATA 中 Data 字段最大字节数；不含 4 字节 TFTP 头） | 8 ~ 65464 | 512 | 服务器值 ≤ 客户端提议值；trafficgen 回显原值 |
| `timeout` | RFC 2349 | 单包重传超时（秒） | 1 ~ 255 | 实现决定（trafficgen 默认 5，仅语义标记不实际重传） | 服务器必须回显与客户端相同的值 |
| `tsize` | RFC 2349 | 文件总大小（字节） | 0 ~ 2^32-1 | 不发送 | RRQ：服务器回实际文件大小；WRQ：服务器回显客户端值 |
| `windowsize` | RFC 7440 | 滑动窗口大小（一次连续发送的 DATA 块数；ACK 一次确认窗口末尾 Block#） | 1 ~ 65535 | 1（即标准锁步模式） | 服务器值 ≤ 客户端提议值；trafficgen 回显原值 |

### 3.9 windowsize 滑动窗口机制（RFC 7440）

RFC 7440 关键规则（trafficgen 支持生成该模式的包序列）：

- **发送方（DSND, Data Sender）**："MUST cyclically send to the DRCV the agreed windowsize consecutive data blocks before normally stopping and waiting for the ACK of the transferred window"（必须循环发送协商好的 windowsize 个连续数据块，然后停止并等待该窗口的 ACK）。
- **接收方（DRCV, Data Receiver）**："MUST send to the DSND the ACK of the last data block of the window"（必须发送该窗口最后一个数据块的 ACK）。
- 块编号跨窗口连续递增（windowsize=4 时：块 n+1 到 n+4 为第一窗口，n+5 到 n+8 为第二窗口，以此类推）。
- **超时/ACK 丢失**："the last received ACK SHALL set the beginning of the next windowsize data block window to be sent"（最后一个收到的 ACK 决定下一个窗口的起始块）。
- **序号错误**：接收方 ACK 最后一个正确收到的块，发送方以该 ACK 为起点重发窗口。
- **末窗口检测**："The reception of a data window with a number of blocks less than the negotiated windowsize is the final window"（收到的数据窗口块数小于协商 windowsize 即为末窗口）。
- **熔断**：实现应设置最大重传次数上限（"SHOULD always set a maximum number of retries"）。
- **wrap（块号回绕）与 windowsize 的交互**（R1-MED-4 修复）：`WrapBlockNumber=true` 时 Block# = `(i mod 65536)`（§3.3），与窗口机制叠加规则如下——
  - 窗口内的块编号以**发送序** i 计（1 起始），ACK 确认"窗口末块的发送序 i"对应的 Block# = `(i mod 65536)`。
  - 回绕窗口的 ACK Block# 可能回退（如首窗口末块 Block#=65535 → ACK#65535；次窗口末块发送序 131070 → Block#=65534 → ACK#65534），这是回绕语义下 ACK 编号随块号回绕的自然结果。
  - 该组合（windowsize>1 + wrap=true）在真实 TFTP 中无互操作性保证（RFC 1350 未定义回绕行为、RFC 7440 未定义回绕+窗口交互），trafficgen 仅用于生成器字节序列测试（T-202/T-203），接收方正确性判定由测试场景自行定义。
- **wrap=true 与 Block#=0 DATA 的互操作性警示（适用于所有 wrap=true 场景，不限于 windowsize>1）**：DATA 中 Block#=0 只在回绕后出现（发送序 i 为 65536 的倍数时 `i mod 65536 = 0`）；RFC 1350 §4 中 DATA 的 Block# 恒 ≥1（0 只出现在 ACK 中），回绕产生 Block#=0 的 DATA 属 trafficgen 生成器回绕语义（S13d/T-049/T-157/T-202/T-203/T-205）。该 DATA 在 RFC 1350 合规接收方眼中会被视为异常（某些实现可能基于 Block#=0 做特殊处理或丢弃），**不承诺与真实实现互操作，仅用于字节序列测试**。所有 wrap=true 的用例（无论 windowsize 是否 >1）均应明确此约束。
- trafficgen 的 `WindowSize` 字段仅控制**包序列模式**（窗口内连续 N 个 DATA + 1 个窗口末 ACK），不做真实计时重传。`WindowSize=1`（默认）即标准锁步模式。

---


## §4 状态机

### 4.1 RRQ（下载）状态机

```
            client                                server
              |                                     |
    [Mode=read]                                 listen :69
              |                                     |
              | --- RRQ(filename, mode, opts) --->  |  (dst_port=69)
              |                                     | (server allocates TID)
              |                                     |
              | <-- OACK(opts') ------------------- |  (src=server_tid, dst=client_port)
              |     [仅当 RRQ 含选项 或 IncludeOACK]  |
              |                                     |
              | --- ACK#0 ------------------------> |  (确认 OACK，RFC 2347 §2)
              |     [仅当收到 OACK]                  |
              |                                     |
              | <-- DATA#1 -----------------------  |  (src=server_tid)
              | --- ACK#1 ------------------------> |
              | <-- DATA#2 -----------------------  |
              | --- ACK#2 ------------------------> |
              | ...                                 |
              | <-- DATA#N (size < blksize) ------  |  (末块，传输结束)
              | --- ACK#N ------------------------> |
              |                                     |
            [done]                                [done]
```

**关键点**：
- 服务器收到 RRQ 后从其临时端口（ServerTID）发后续包，**不再用 69**（RFC 1350 §4）。
- 若 RRQ 含选项（或 `IncludeOACK=true`），服务器先发 OACK；客户端回 ACK#0 后服务器才发 DATA#1（RFC 2347 §2）。
- 若 RRQ 不含选项，服务器直接发 DATA#1（无 OACK、无 ACK#0）。
- 最后一个 DATA 块大小 < blksize 即结束；若文件大小恰为 blksize 整数倍，服务器追加一个 0 字节 DATA 块（RFC 1350 §6）。
- 无选项场景直接以 DATA#1 应答本身即"接受请求"的确认（RFC 1350：发送 DATA 即确认之前的 RRQ）。

### 4.2 WRQ（上传）状态机

```
            client                                server
              |                                     |
    [Mode=write]                                listen :69
              |                                     |
              | --- WRQ(filename, mode, opts) --->  |  (dst_port=69)
              |                                     | (server allocates TID)
              |                                     |
              | <-- OACK(opts') ------------------- |  (src=server_tid)
              |     [仅当 WRQ 含选项 或 IncludeOACK]  |
              |                                     |
              | --- DATA#1 -----------------------> |  (收到 OACK 直接发 DATA#1，无 ACK#0)
              | <-- ACK#1 ------------------------- |
              | --- DATA#2 -----------------------> |
              | <-- ACK#2 ------------------------- |
              | ...                                 |
              | --- DATA#N (size < blksize) ------> |  (末块)
              | <-- ACK#N ------------------------- |
              |                                     |
            [done]                                [done]
```

**关键点**：
- 服务器收到 WRQ 后：若含选项（或 `IncludeOACK=true`）则发 OACK；客户端收到 OACK 后**直接发 DATA#1**（无 ACK#0，RFC 2347 §2）。
- 若 WRQ 不含选项，服务器直接回 ACK#0（block#=0）确认"准备好接收"（RFC 1350 §4："WRQ is acknowledged with an ACK having block number zero"）；客户端收到 ACK#0 后发 DATA#1。
- DATA 由客户端发送，ACK 由服务器发送（与 RRQ 反向）。

### 4.3 ERROR 终止状态机

```
   任何状态
       |
       | --- ERROR(code, msg) --->   (任一方)
       |
   [传输终止，不再发任何包]  （除 ERROR code=5 例外）
```

**规则**（RFC 1350 §5）：
- ERROR 可在任一阶段发出：RRQ/WRQ 后立即（文件不存在）、传输中途（磁盘满/访问违规）、传输结束前（客户端主动取消）。
- 发出或收到 ERROR 后，planner 不再生成任何包。
- **唯一例外**：ERROR code=5（Unknown TID）**不终止传输**。RFC 1350 §4 的 TID 校验语义：收到源 TID 不匹配的包时，接收方向**错误源**发 ERROR code=5，然后**丢弃该包并继续原传输**（RFC 1350："recognizes only one error condition that does not cause termination"——只识别一个不导致终止的错误条件，即收到包的源端口不正确）。该语义下 ERROR 的接收方与当前传输的发送方是**不同**的 TID，ERROR 发向"包的实际来源"，之后传输仍在**约定 TID** 上进行。
- **trafficgen 扩展语义（非任何 RFC 标准）**：RFC 1350 未定义"服务器中途主动更换 TID"的行为，也无任何 RFC 定义此类机制（v2.0.1 曾误引 RFC 1783，但 RFC 1783 实际标题为 "TFTP Blocksize Option"，内容仅涉 blksize 选项协商，**完全不包含** TID 变更机制；v2.0.2 已删除该错误引用）。trafficgen 为模拟 NAT/中间件导致的 TID 漂移场景，自定义了 `ServerTIDChange=true` 扩展行为：服务器改用新 TID 后，客户端收到来自新 TID 的 DATA，向**新 TID** 回 ERROR code=5 表示"包源 TID 与约定不符、尚未完成迁移"，服务器继续用新 TID 发送，客户端最终接受新 TID 并继续以新 TID 应答。**此行为不符合 RFC 1350 §4 的校验语义**（RFC 1350 下客户端应丢弃新 TID 的包并向错误源回 ERROR(5) 后继续等待旧 TID 上的重传，不回 ACK），也**非任何 RFC 标准**，仅用于生成器字节序列测试。两种语义以 `ServerTIDChange` 字段区分：`ServerTIDChange=true` 走 trafficgen 扩展迁移语义（ERROR 后继续向新 TID 收发包）；`ErrorCode=5` 普通注入走 RFC 1350 终止语义（非 TID 校验场景的 code=5 仍终止，见 T-030/T-230）。
- ERROR 包不被确认、不被重传（RFC 1350）。

### 4.4 OACK 选项协商子状态机（RFC 2347）

```
   RRQ/WRQ 含 options?
       |
   ┌───┴───┐
   是      否（且 IncludeOACK=false）
   |       |
   |       └── RRQ: 直接 DATA#1 / WRQ: 直接 ACK#0（服务器不支持协商时同此）
   |
   server 接受选项子集
   |
   ┌───┴───────────┐
   OACK            拒绝全部（服务器不回 OACK 即视为拒绝；trafficgen 不支持此分支，
   |                OACK 总是回显客户端请求的全部选项）
   |
   RRQ: client 回 ACK#0 → server 发 DATA#1
   WRQ: client 收到 OACK 直接发 DATA#1（无 ACK#0）
```

**trafficgen 实现约定**：
- 选项出现且值非 0 即视为协商成功，OACK 回显全部请求选项（trafficgen 不做"部分拒绝"——所有选项都被接受并回显）。
- 选项值回显规则（RFC 2347：OACK 值可不同于请求值；trafficgen 的模拟约定）：
  - blksize：回显请求值（允许值域 8-65464）。
  - timeout：回显请求值（RFC 2349 强制相同）。
  - tsize：RRQ 模式回显 `ServerTSize`（服务器实际文件大小）；WRQ 模式回显 `ClientTSize`。
  - windowsize：回显请求值（RFC 7440 允许 ≤ 请求值）。
- 客户端拒绝 OACK → 发 ERROR code=8（Failed to negotiate options）并终止。trafficgen 通过 `ErrorCode=8` + `ErrorAfterBlock=0` 模拟此场景（见 S8/S14）。
- `IncludeOACK=true` 且 RRQ/WRQ 无选项时，服务器仍发空 OACK（仅 opcode `00 06`，2 字节），客户端按对应模式走 OACK 分支。

### 4.5 超时与重传状态机（RFC 1350 §6，模拟语义）

真实 TFTP 行为（RFC 1350 §6）：
- 包丢失时，"the intended recipient will timeout and may retransmit his last packet (which may be data or an acknowledgment)"（预期接收方将超时并可能重传其最后发送的包——数据或确认）。
- "The sender has to keep just one packet on hand for retransmission, since the lock step acknowledgment guarantees that all older packets have been received"（发送方只需保留一个待重传包）。
- **重传时序**：DATA#N 丢失 → 接收方无响应 → 发送方超时重发 DATA#N → 接收方回 ACK#N。重传的 DATA#N 出现在原 ACK#N 之前（原 ACK#N 未发出）。

**trafficgen 模拟语义（S10）**：
- trafficgen 是字节级流量生成器，**不模拟丢包**，只模拟"发送方超时后重发"的**结果序列**。
- `RetransmitBlocks=[N]` 的语义：**DATA#N 在初次发送时丢失（无原 DATA#N），仅重传的 DATA#N 出现**，随后接收方回 ACK#N（每个重传的 DATA#N 对应一个 ACK#N）。
- 该序列符合 RFC 1350 §6 重传时序（重传 DATA 先于其 ACK），且与真实 TFTP 客户端/服务器互操作。
- 重传只影响包序列，不改变 Block# 与字节内容（重传包与原包字节完全相同）。

---


## §5 配置类型定义（Go struct）

在 `internal/core/types.go` 新增 `TFTPConfig`，并加 `TFTP *TFTPConfig` 字段到 `FlowSpec`。字段类型以 v2.0.0 审计修复为准（**C1：BlocksCount 改 uint32**）。

```go
// TFTPConfig configures the TFTP (RFC 1350) planner. TFTP runs over UDP:
// the client picks an ephemeral source port and sends RRQ/WRQ to server
// port 69; the server picks its own ephemeral TID port for the rest. Both
// directions of the data plane share the same 4-tuple.
type TFTPConfig struct {
    // Mode: "read" (RRQ, 下载, server 发 DATA) or "write" (WRQ, 上传,
    // client 发 DATA). 大小写不敏感; empty defaults to "read".
    Mode string `json:"mode"`

    // Filename: file path in RRQ/WRQ. May contain "/" or "\". Empty rejected
    // by Validate. Max 255 bytes (trafficgen 限制; RFC 1350 未规定上限).
    Filename string `json:"filename"`

    // TransferMode: "netascii" or "octet" (RFC 1350 §4). 大小写不敏感,
    // 输出统一小写. "mail" deprecated, rejected. Empty defaults to "octet".
    TransferMode string `json:"transfer_mode"`

    // BlkSize: blksize option (RFC 2348). 0=do not send (use default 512).
    // Validate enforces 8 <= BlkSize <= 65464. OACK 回显请求值.
    BlkSize uint16 `json:"blksize,omitempty"`

    // Timeout: timeout option in seconds (RFC 2349). 0=do not send.
    // Validate enforces 1 <= Timeout <= 255. 仅语义标记 — trafficgen 不实际
    // 按超时起重传 (只生成重传序列 via RetransmitBlocks, 见 §4.5).
    Timeout uint8 `json:"timeout,omitempty"`

    // ClientTSize: tsize option value written into RRQ/WRQ (RFC 2349 §2).
    // RRQ 模式: RFC 2349 强制客户端写 "0"; 若 ClientTSize>0 或 ServerTSize>0,
    // RRQ 携带 tsize\0 0\0, 否则不发送 tsize 选项.
    // WRQ 模式: 客户端写实际文件大小 (ClientTSize).
    // 同时参与自动追加判定: auto-append 判定 TSize = (ClientTSize>0 ? ClientTSize
    // : ServerTSize) (非零者优先, 见 §5.1 自动追加规则).
    ClientTSize uint32 `json:"client_tsize,omitempty"`

    // ServerTSize: tsize value echoed by server in OACK.
    // RRQ 模式: 服务器回实际文件大小 (ServerTSize).
    // WRQ 模式: 服务器回显 ClientTSize, ServerTSize 应=0 或==ClientTSize.
    // 参与自动追加判定 (ClientTSize=0 时采用).
    ServerTSize uint32 `json:"server_tsize,omitempty"`

    // ServerTID: server's ephemeral port for packets after RRQ/WRQ.
    // 0=planner picks deterministic ephemeral (49152-65535, RFC 6335) via
    // FNV-1a(FlowID) so the same spec always yields the same port
    // (reproducible). When set, Validate enforces 1024 <= ServerTID <= 65535.
    ServerTID uint16 `json:"server_tid,omitempty"`

    // ErrorCode: inject an ERROR packet with ErrCode=ErrorCode at
    // ErrorAfterBlock. 统一语义 (R1-CRITICAL-2 修复):
    //   - ErrorCode>0: 注入 (ErrorAfterBlock=0 → RRQ/WRQ 后立即; >0 → N 块后).
    //   - ErrorCode==0 且 ErrorAfterBlock>0: 注入 code=0 (ErrorAfterBlock 显式
    //     表达了注入意图, S8d/T-227 场景).
    //   - ErrorCode==0 且 ErrorAfterBlock==0: 不注入 (json omitempty 下与"未设置"
    //     不可区分, 约定为不注入, T-228).
    // Wire 类型为 uint16 BE (0-8, 见 §3.6 错误码表, 含 RFC 2347 code=8);
    // Go 类型 uint8. Validate enforces 0 <= ErrorCode <= 8.
    // 互斥: ServerTIDChange=true 时 ErrorCode 必须=0 (见 §5.3).
    ErrorCode uint8 `json:"error_code,omitempty"`

    // ErrorMsg: human-readable text in injected ERROR. Empty allowed —
    // planner then uses the default ErrMsg for ErrCode (见 §5.4 ErrCode→ErrMsg
    // 表, 含 ErrorCode=0 → "Not defined"). Truncated to 255 bytes on wire.
    ErrorMsg string `json:"error_msg,omitempty"`

    // ErrorAfterBlock: DATA block# after which ERROR is injected.
    // 0=immediately after RRQ/WRQ (no DATA). N>0=emit DATA#1..N + ACK#1..N
    // then inject ERROR from ErrorSide. Validate: ErrorAfterBlock>0 时
    // BlocksCount 必须显式设 (不允许 derive), 且 ErrorAfterBlock <= BlocksCount.
    ErrorAfterBlock uint32 `json:"error_after_block,omitempty"`

    // ErrorSide: "server"=server→client (down), "client"=client→server (up).
    // Empty defaults to "server".
    ErrorSide string `json:"error_side,omitempty"`

    // BlocksCount: 实际 DATA 块数 (uint32, 允许 > 65535; wire Block# 按 §3.3
    // 回绕规则编码). 0=derive from data_payload_pattern/payload 数据规模推导
    // (规则见 §5.1). 不含自动追加的 0 字节末块.
    BlocksCount uint32 `json:"blocks_count,omitempty"`

    // AutoAppendFinalBlock: when true (default), planner appends a 0-byte
    // DATA terminator per RFC 1350 §6 whenever the LAST DATA block is a full
    // block (Data length == BlkSize), i.e. the file size is an exact multiple
    // of BlkSize — regardless of whether a tsize decision exists (R1-CRITICAL-3
    // 修复: 无 tsize 满块时默认也追加, 兑现 "默认 true = RFC 1350 §6 合规").
    // 判定: 末块 Data 长度 == BlkSize 即追加; FinalBlockZero=true 时末块为
    // 0 字节, 不满足"末块满块", 自动跳过 (§5.3). When false, no auto-append
    // (非 RFC 合规负向测试). nil = true (默认). 追加后实际块数 > 65535 且
    // 未开 wrap 时 Validate 报错 (V18).
    AutoAppendFinalBlock *bool `json:"auto_append_final_block,omitempty"`

    // FinalBlockZero: when true, the LAST DATA block (Block#=BlocksCount,
    // wire 上按回绕规则计算) carries 0 bytes — 显式 RFC 1350 §6 终止块.
    // 与 AutoAppendFinalBlock=false 搭配生成"半标准"流; 当自动追加条件也满足时
    // 不重复追加 (末块已显式). Validate requires BlocksCount >= 1 (derive 不允许).
    FinalBlockZero bool `json:"final_block_zero,omitempty"`

    // WrapBlockNumber: when true, Block# = (i mod 65536) 回绕 (65535 → 0 → 1),
    // 允许 BlocksCount > 65535. When false (default), Validate rejects
    // BlocksCount > 65535.
    WrapBlockNumber bool `json:"wrap_block_number,omitempty"`

    // DataPayloadPattern: DATA payload bytes. 每块填充为该 slice 循环重复至
    // BlkSize. 空且 BlocksCount>0 时用确定性 0x00..0xFF 模式. 空且 BlocksCount==0
    // (derive) 时要求 Payload/FileSource 提供数据规模 (见 §5.1).
    DataPayloadPattern []byte `json:"data_payload_pattern,omitempty"`

    // IncludeOACK: when true, server sends OACK even with no options
    // (OACK carries only opcode `00 06`, 2 bytes). Default false. RRQ 模式走
    // RRQ+OACK 分支 (client 发 ACK#0 后 server 发 DATA#1); WRQ 模式走 WRQ+OACK
    // 分支 (client 直接发 DATA#1, 无 ACK#0). 见 §4.4.
    IncludeOACK bool `json:"include_oack,omitempty"`

    // RetransmitBlocks: DATA 重传模拟 (S10). 语义: 列表中的 Block# 的 DATA 在
    // 初次发送时"丢失", 仅出现重传版本 (每个重传 DATA 后跟对应 ACK#N).
    // 符合 RFC 1350 §6 重传时序 (重传 DATA 先于其 ACK, 不出现"原 DATA+原 ACK"
    // 后再重传的异常序列). 每项必须在 [1, BlocksCount]. 互斥于 ServerTIDChange.
    RetransmitBlocks []uint32 `json:"retransmit_blocks,omitempty"`

    // ServerTIDChange: when true, simulates server switching to ServerTIDNew
    // at ServerTIDChangeAtBlock. 语义为 trafficgen 扩展行为 (非任何 RFC 标准):
    // 客户端 (接收方) 检测到源 TID 变为 ServerTIDNew 后, 向新 TID 发 ERROR code=5
    // (Unknown TID, 表示"包源 TID 与约定不符, 尚未完成迁移"), 随后继续向新 TID
    // 发 ACK — ERROR code=5 不终止传输 (trafficgen 扩展). 注意: 此行为不符合
    // RFC 1350 §4 的校验语义 (RFC 1350 下客户端应丢弃新 TID 的包并向错误源回
    // ERROR(5) 后继续等待旧 TID 上的重传, 不回 ACK; v2.0.1 曾误引 RFC 1783 为
    // 依据, 但 RFC 1783 实际是 "TFTP Blocksize Option" 与 TID 无关, v2.0.2 已
    // 撤回该引用). 也非任何 RFC 标准, 仅用于生成器字节序列测试 (模拟 NAT/中间件
    // 导致的 TID 漂移场景). 互斥于 ErrorCode>0 与 RetransmitBlocks.
    // 见 §4.3、S9.
    ServerTIDChange        bool   `json:"server_tid_change,omitempty"`
    ServerTIDChangeAtBlock uint32 `json:"server_tid_change_at_block,omitempty"`
    ServerTIDNew           uint16 `json:"server_tid_new,omitempty"`
}
```

### 5.1 字段默认化规则

按 `Validate` 中的优先级，所有字段遵循 **user-provided > derived default > zero value**：

| 字段 | 默认值 | 触发条件 |
|------|--------|----------|
| `Mode` | `"read"` | 空字符串（大小写归一为小写） |
| `TransferMode` | `"octet"` | 空字符串（大小写归一为小写） |
| `DstPort`（FlowSpec） | `69` | 0 |
| `ServerTID` | FNV-1a(FlowID) mod 16384 + 49152（范围 49152-65535，RFC 6335） | 0 |
| `ServerTIDNew` | 确定性端口（同 ServerTID 算法，避开与 ServerTID 相同） | 0 且 ServerTIDChange=true |
| `BlkSize` | 512（不发送 blksize 选项） | 0 |
| `Timeout` | 不发送 timeout 选项 | 0 |
| `ErrorCode` | 0；是否注入由 §5 struct 统一语义决定（0+ErrorAfterBlock>0 注入 code=0；0+ErrorAfterBlock=0 不注入） | 0 |
| `ErrorSide` | `"server"` | 空字符串 |
| `BlocksCount` | 由数据规模推导（见下） | 0 |
| `AutoAppendFinalBlock` | `true`（RFC 1350 §6 合规：满块末块默认追加 0 字节终止块，无 tsize 同样生效） | nil |
| `FinalBlockZero` | `false` | false |
| `WrapBlockNumber` | `false`（Validate 拒绝 BlocksCount > 65535） | false |
| `ClientTSize`/`ServerTSize` | 不发送 tsize 选项（§5.2） | 0 |
| `ServerTIDChange` | 不模拟 TID 变更 | false |
| `ServerTIDChangeAtBlock` | 不切换（要求 ServerTIDChange=true 才生效） | 0 |

**BlocksCount 推导规则**（`BlocksCount=0` 时）：
- `DataPayloadPattern` 非空：推导为 1 块（Data 长度 = BlkSize）。
- 否则要求 `Payload`/`FileSource`（FlowSpec 通用字段）提供数据规模：`BlocksCount = ceil(file_size / BlkSize)`。
- 两者皆空 → Validate 报错 `tftp: blocks_count=0 requires data_payload_pattern or payload source`。

**自动追加判定规则**（R1-CRITICAL-3 修复，RRQ/WRQ 统一）：
- 触发条件：`AutoAppendFinalBlock != false` 且 **末块 Data 长度 == BlkSize**（即文件大小恰为 BlkSize 整数倍，RFC 1350 §6 MUST）。
- **ERROR 注入时不追加**（R2-HIGH-2 修复）：`ErrorCode>0` 且 `ErrorAfterBlock == BlocksCount` 时，ERROR 在第 N 块（末块）后注入即终止传输，不生成自动追加的 0 字节末块——即使末块为满块（见 §5.3 ERROR 注入与自动追加优先级规则；T-022/T-034 覆盖此路径）。
- 判定与 tsize 解耦：**无 tsize 判定时同样追加**——只要末块是满块（Data 长度 == BlkSize），planner 默认追加 0 字节末块（否则生成无结束标记的不合规流）。判定 TSize 规则（`(ClientTSize > 0 ? ClientTSize : ServerTSize)`）仅用于**校验**（§5.3 警告类：判定TSize ≠ BlocksCount×BlkSize 时 Report），不再作为追加的触发条件。
- 触发后实际 DATA 数 = BlocksCount + 1（末块 0 字节）。`BlocksCount` 字段本身不变。
- 追加后实际块数 > 65535 且未开 wrap 时 Validate 报错（V18；如 S13e 的 `blocks_count=65535` 追加至 65536）。
- 末块 Data 长度 < BlkSize（非满块）时不追加（本身已标示结束，RFC 1350 §6）。
- `FinalBlockZero=true` 时末块强制 0 字节，不满足"末块满块"，自动跳过（§5.3）。
- **RRQ 模式下 `client_tsize` 参与判定但 RRQ 报文中 tsize 永远写 "0"**（RFC 2349 §2 强制）；`server_tsize` 仅在 OACK 中回显。§6.2/§6.10.1/T20/T62 用例中 `client_tsize=1024`（RRQ 模式）用于触发自动追加属合法用法——判定与报文写入是两条独立规则。

### 5.2 tsize 选项发送规则（H6 修复）

RRQ 模式发送 `tsize\0 0\0` 的条件（RFC 2349 §2：客户端 RRQ 时 tsize 写 "0"）：
- `ClientTSize > 0 || ServerTSize > 0` → 发送 `tsize\0 0\0`。
- 否则不发送 tsize 选项。

WRQ 模式发送 `tsize\0 <ClientTSize>\0` 的条件：
- `ClientTSize > 0` → 发送 `tsize\0 <ClientTSize>\0`。
- 否则（ClientTSize=0 且 ServerTSize>0）→ 发送 `tsize\0 0\0`（RFC 2349 未明确定义该组合，trafficgen 按"客户端无文件大小信息"语义写 0）。
- 两者皆 0 → 不发送。

OACK 回显 tsize 的条件：
- RRQ 模式：`ServerTSize > 0` → OACK 回 `tsize\0 <ServerTSize>\0`。
- WRQ 模式：`ClientTSize > 0` → OACK 回 `tsize\0 <ClientTSize>\0`（回显客户端值）。
- WRQ 模式：`ClientTSize == 0 && ServerTSize > 0` → OACK 回 `tsize\0 <ServerTSize>\0`。

**选项写入顺序**（固定，便于字节精确测试）：`blksize → timeout → tsize → windowsize`。

### 5.3 字段互斥与组合规则

- `ServerTIDChange` 与 `ErrorCode>0` 互斥：Validate 报错 `tftp: server_tid_change and error_code are mutually exclusive`。`ErrorCode=0`（未设置注入意图，与 ServerTIDChange 不冲突）不触发互斥（M3 修复）。
- `ServerTIDChange` 与 `RetransmitBlocks` 互斥：报错 `tftp: server_tid_change and retransmit_blocks are mutually exclusive`（重传块用旧 TID 还是新 TID 易混淆）。
- `ErrorCode>0` + `BlocksCount==0` + `ErrorAfterBlock==0`：错误立即注入（无 DATA）。
- `ErrorCode==0` + `ErrorAfterBlock==0`：不注入（R1-CRITICAL-2 统一语义，与"未设置"不可区分）。
- `ErrorCode==0` + `ErrorAfterBlock>0`：注入 ErrCode=0（ErrorAfterBlock 表达注入意图，S8d/T-227）。
- `ErrorCode>0` + `ErrorAfterBlock>0`：先发 N 个 DATA/ACK 再注入 ERROR。**Validate 强制**：`ErrorAfterBlock>0` 时 `BlocksCount` 必须显式设（>0）且 `ErrorAfterBlock <= BlocksCount`。
- `ErrorAfterBlock > 0` 时要求 DataPayloadPattern 或 Payload/FileSource 非空（否则无法填充 DATA 载荷）。
- `FinalBlockZero=true`：Validate 要求 `BlocksCount >= 1`（不允许 derive）；第 BlocksCount 块 Data 长度强制 0；末块为 0 字节（非满块），自动追加判定（末块满块）自然不触发，不重复追加（§5.1）。
- `WrapBlockNumber=false`：`BlocksCount > 65535` 报错 `tftp: blocks_count 65536 exceeds uint16 max (set wrap_block_number=true to allow)`。
- `WrapBlockNumber=true`：允许 `BlocksCount > 65535`（uint32）；Block# = `(i mod 65536)`。
- **ERROR 注入与自动追加的优先级**（R2-HIGH-2 修复）：`ErrorCode>0` 注入时，若 `ErrorAfterBlock == BlocksCount` 且末块为满块（Data 长度 == BlkSize），**ERROR 抑制自动追加**——ERROR 已终止传输（§4.3），不再生成 0 字节末块 DATA/ACK。即：正常情况下末块满块会触发 `DATA#(N+1)(0B)/ACK#(N+1)` 自动追加（§5.1）；但若 ERROR 在第 N 块后注入（`ErrorAfterBlock == BlocksCount == N`），planner 在生成 ERROR 后立即停止，不生成自动追加的 0 字节末块。此规则同步在 §5.1 自动追加判定中加注"ERROR 注入时不追加"。`ErrorAfterBlock < BlocksCount` 时 ERROR 在中途注入，DATA#(ErrorAfterBlock+1..BlocksCount) 不生成，自动追加判定更不触发。
- TFTP 流识别：`FlowSpec.TFTP != nil` 即视为 TFTP 流；MapToFlow 命中 `"tftp"` case 但转换后 `TFTPConfig == nil` → 报错 `tftp: TFTPConfig is required`。
- TFTP 流与 TCP/HTTP/DNS/FTP 等 L7 互斥；与 VLAN/PPPoE/GRE/MPLS 等 L2/L3 封装共存。

**Validate 错误/警告分类**：
- **错误类**（Validate 返回 error，任务失败）：非法 mode/transfer_mode、filename 空/NUL、blksize/timeout/error_code 越界、error_after_block 越界、server_tid 知名端口、mutual exclusion、BlocksCount 越界、derive 无源。
- **警告类**（Report 记录，不失败）：`BlocksCount×BlkSize == 判定TSize` 且自动追加后越 uint16 但未开 wrap 时、`判定TSize ≠ BlocksCount×BlkSize` 时（自动追加判定见 §5.1，仅依赖末块是否满块，不再受 TSize 是否等于 0 影响）。

### 5.4 ErrCode → 默认 ErrMsg 映射（M4 修复）

当 `ErrorMsg == ""` 且 planner 决定注入 ERROR（注入判定见 §5 struct ErrorCode 字段语义）时，planner 按下表自动填充默认 ErrMsg：

| ErrCode | 默认 ErrMsg（ASCII） | 字节数（含 `\0`） |
|---------|----------------------|-------------------|
| 0 | `Not defined` | 12 |
| 1 | `File not found` | 15 |
| 2 | `Access violation` | 17 |
| 3 | `Disk full or allocation exceeded` | 33 |
| 4 | `Illegal TFTP operation` | 23 |
| 5 | `Unknown transfer ID` | 20 |
| 6 | `File already exists` | 20 |
| 7 | `No such user` | 13 |
| 8 | `Failed to negotiate options` | 28 |

ErrMsg 在写入报文时强制以单个 `\0` 结尾；空 ErrMsg 时仅写 `\0`（1 字节）。用户设非空 `ErrorMsg` 时覆盖默认值（仍受 255 字节截断）。

---


## §6 包序列场景（HexDump S1-S15）

约定：
- 所有字节为十六进制，`\0` 表示单个 `0x00`。
- `UDP head` = 8 字节 UDP 头（SrcPort 2B + DstPort 2B + Len 2B + Checksum 2B），数据报总长 = 8 + TFTP 包长。
- 端口标注：`C` = 客户端端口（spec.SrcPort），`69` = 服务器初始端口，`TID` = 服务器临时端口（ServerTID），`TID2` = 变更后的服务器端口（ServerTIDNew）。
- **逐字节核算**：每个 HexDump 的字段长度已在场景内注明并核算（2B opcode + 字符串长度含 `\0` + 数据长度）。

### S1 RRQ 简单下载（无选项）

**输入 spec**：
```json
{
  "src_ip": "10.0.0.100", "dst_ip": "10.0.0.1",
  "src_port": 49152, "dst_port": 69, "udp": {},
  "tftp": { "mode": "read", "filename": "config.txt",
            "transfer_mode": "octet",
            "blocks_count": 1, "data_payload_pattern": "AA" }
}
```

**期望包序列（3 包）**：

包 1 **RRQ**（up, 10.0.0.100:49152 → 10.0.0.1:69）
```
UDP head:  c000 0045 001b 0000        ; Len = 8 + 19 = 0x1B = 27
TFTP:      00 01 63 6f 6e 66 69 67 2e 74 78 74 00 6f 63 74 65 74 00
           ├opcode(2)├──"config.txt"(10+1)───────├──"octet"(5+1)─────┤
核算: 2 + 11 + 6 = 19 字节
```

包 2 **DATA#1**（down, 10.0.0.1:TID → 10.0.0.100:49152）
```
UDP head:  <tid> c000 01f4 0000        ; Len = 8 + 4 + 100 = 0x1F4? 否 — 见下
TFTP:      00 03 00 01 [0xAA × 100]    ; 100 < 512 → 末块（传输结束）
核算: 2 + 2 + 100 = 104 字节; UDP Len = 8 + 104 = 112 (0x70)
```

包 3 **ACK#1**（up, 10.0.0.100:49152 → 10.0.0.1:TID）
```
TFTP:      00 04 00 01                 ; 4 字节
核算: 2 + 2 = 4 字节; UDP Len = 12 (0x0C)
```

**断言点**：总包数 3；DATA#1 Data=100B <512（末块）；ACK#1 回显 Block#=1；包 2/3 端口用 TID ≠ 69。

### S2 WRQ 简单上传（无选项）

**输入 spec**：
```json
{
  "src_ip": "10.0.0.100", "dst_ip": "10.0.0.1",
  "src_port": 49153, "dst_port": 69, "udp": {},
  "tftp": { "mode": "write", "filename": "upload.dat",
            "transfer_mode": "octet",
            "blocks_count": 1, "data_payload_pattern": "BB" }
}
```

**期望包序列（4 包）**：

包 1 **WRQ**（up, :49153 → :69）
```
TFTP:      00 02 75 70 6c 6f 61 64 2e 64 61 74 00 6f 63 74 65 74 00
           ├opcode(2)├──"upload.dat"(10+1)───────├──"octet"(5+1)─────┤
核算: 2 + 11 + 6 = 19 字节
```

包 2 **ACK#0**（down, :TID → :49153）— WRQ 无选项时的"准备好接收"确认
```
TFTP:      00 04 00 00                 ; Block#=0（RFC 1350 §4 WRQ 确认）
核算: 4 字节
```

包 3 **DATA#1**（up, :49153 → :TID）— 上传方向 DATA 由客户端发
```
TFTP:      00 03 00 01 [0xBB × 200]    ; 200 < 512 → 末块
核算: 4 + 200 = 204 字节; UDP Len = 212 (0xD4)
```

包 4 **ACK#1**（down, :TID → :49153）
```
TFTP:      00 04 00 01
核算: 4 字节
```

**断言点**：总包数 4；ACK#0 出现（WRQ 无选项分支）；DATA Direction=up；ACK Direction=down。

### S3 blksize 选项协商

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "large.bin",
            "transfer_mode": "octet",
            "blksize": 1428, "blocks_count": 2,
            "data_payload_pattern": "FF" }
}
```

**期望包序列（9 包）**：

包 1 **RRQ**（up, → :69）
```
TFTP:      00 01 6c 61 72 67 65 2e 62 69 6e 00 6f 63 74 65 74 00
           62 6c 6b 73 69 7a 65 00 31 34 32 38 00
           └──"large.bin"(9+1)──┘ └─"octet"(5+1)─┘ └─"blksize"(7+1)┘ └─"1428"(4+1)┘
核算: 2 + 10 + 6 + 8 + 5 = 31 字节
```

包 2 **OACK**（down, :TID → :49152）
```
TFTP:      00 06 62 6c 6b 73 69 7a 65 00 31 34 32 38 00
           ├opcode(2)├──"blksize"(7+1)───┼──"1428"(4+1)──┤
核算: 2 + 8 + 5 = 15 字节
```

包 3 **ACK#0**（up, :49152 → :TID）— RRQ+OACK 的选项确认
```
TFTP:      00 04 00 00
核算: 4 字节
```

包 4 **DATA#1**（down）`00 03 00 01 [0xFF × 1428]`；核算: 4 + 1428 = 1432 字节；UDP Len = 1440 (0x5A0)
包 5 **ACK#1**（up）`00 04 00 01`
包 6 **DATA#2**（down）`00 03 00 02 [0xFF × 1428]`（1428 = blksize，末块满块 → 触发自动追加）
包 7 **ACK#2**（up）`00 04 00 02`
包 8 **DATA#3**（down）`00 03 00 03`（0 字节末块，自动追加）
包 9 **ACK#3**（up）`00 04 00 03`

**断言点**：DATA 长度 = 1428（协商值，非 512）；OACK 回显同值；ACK#0 出现于 OACK 之后；末块满块触发自动追加（§5.1）。

### S4 timeout 选项协商

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "f.bin",
            "transfer_mode": "octet",
            "timeout": 10, "blocks_count": 1,
            "data_payload_pattern": "AA" }
}
```

**期望包序列（7 包）**：

包 1 **RRQ**（up）
```
TFTP:      00 01 66 2e 62 69 6e 00 6f 63 74 65 74 00 74 69 6d 65 6f 75 74 00 31 30 00
           ├opcode(2)├─"f.bin"(5+1)─┼─"octet"(5+1)─┼─"timeout"(7+1)──┼─"10"(2+1)─┤
核算: 2 + 6 + 6 + 8 + 3 = 25 字节
```

包 2 **OACK**（down）
```
TFTP:      00 06 74 69 6d 65 6f 75 74 00 31 30 00
核算: 2 + 8 + 3 = 13 字节
```

包 3 **ACK#0**（up）`00 04 00 00`
包 4 **DATA#1**（down）`00 03 00 01 [0xAA × 512]`（512 = blksize 默认值；末块满块 → 触发自动追加）
包 5 **ACK#1**（up）`00 04 00 01`
包 6 **DATA#2**（down）`00 03 00 02`（0 字节末块，自动追加：1×512=512，末块满块）
包 7 **ACK#2**（up）`00 04 00 02`

**断言点**：timeout value 是 ASCII 数字串（`31 30` = "10"，非 0x0A）；OACK 回显同值（RFC 2349 强制相同）；末块满块触发自动追加（§5.1）。

### S5 tsize 选项协商（RRQ 与 WRQ）

**场景 5a — RRQ**：客户端写 "0"，服务器 OACK 回实际大小 2048。

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "data.bin",
            "transfer_mode": "octet",
            "server_tsize": 2048, "blocks_count": 4,
            "data_payload_pattern": "FF" }
}
```

包 1 **RRQ**（up）
```
TFTP:      00 01 64 61 74 61 2e 62 69 6e 00 6f 63 74 65 74 00 74 73 69 7a 65 00 30 00
           ├opcode(2)├─"data.bin"(8+1)─┼─"octet"(5+1)─┼─"tsize"(5+1)──┼─"0"(1+1)─┤
核算: 2 + 9 + 6 + 6 + 2 = 25 字节（tsize value = "0"，RFC 2349 §2 强制）
```

包 2 **OACK**（down）
```
TFTP:      00 06 74 73 69 7a 65 00 32 30 34 38 00
           ├opcode(2)├─"tsize"(5+1)─┼─"2048"(4+1)──┤
核算: 2 + 6 + 5 = 13 字节
```

包 3 **ACK#0**（up）`00 04 00 00`
包 4-11 **DATA#1..#4 + ACK#1..#4**（DATA 各 512B `0xFF`）
包 12 **DATA#5**（down）`00 03 00 05`（**0 字节末块**，自动追加：4×512=2048=ServerTSize）核算: 4 字节
包 13 **ACK#5**（up）`00 04 00 05`

**场景 5b — WRQ**：客户端写实际大小 2048，服务器回显。

**输入 spec**：`mode=write, client_tsize=2048, blocks_count=4, data_payload_pattern="FF"`

包 1 **WRQ**（up）
```
TFTP:      00 02 77 64 61 74 61 2e 62 69 6e 00 6f 63 74 65 74 00 74 73 69 7a 65 00 32 30 34 38 00
           ├opcode(2)├─"wdata.bin"(9+1)─┼─"octet"(5+1)─┼─"tsize"(5+1)──┼─"2048"(4+1)──┤
核算: 2 + 10 + 6 + 6 + 5 = 29 字节（tsize value = ClientTSize）
```

包 2 **OACK**（down）`00 06 74 73 69 7a 65 00 32 30 34 38 00`（回显 ClientTSize；13 字节）
包 3-10 **DATA#1..#4 + ACK#1..#4**（**无 ACK#0**，WRQ+OACK 分支）
包 11 **DATA#5**（up）`00 03 00 05`（0 字节末块，自动追加：4×512=2048=ClientTSize）
包 12 **ACK#5**（down）`00 04 00 05`
**总包数 = 12**（WRQ + OACK + 4×2 + 2 = 12）

**断言点**：RRQ 中 tsize 永远 "0"；WRQ 中 tsize = ClientTSize；OACK 回显规则见 §5.2；自动追加判定 TSize 统一 = `(ClientTSize>0 ? ClientTSize : ServerTSize)`。

### S6 windowsize 选项协商（RFC 7440）

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "w.bin",
            "transfer_mode": "octet",
            "windowsize": 4, "blocks_count": 8,
            "data_payload_pattern": "FF" }
}
```

包 1 **RRQ**（up）
```
TFTP:      00 01 77 2e 62 69 6e 00 6f 63 74 65 74 00 77 69 6e 64 6f 77 73 69 7a 65 00 34 00
           ├opcode(2)├"w.bin"(5+1)─┼"octet"(5+1)─┼──"windowsize"(10+1)───┼─"4"(1+1)─┤
核算: 2 + 6 + 6 + 11 + 2 = 27 字节
```

包 2 **OACK**（down）`00 06 77 69 6e 64 6f 77 73 69 7a 65 00 34 00`；核算: 2 + 11 + 2 = 15 字节
包 3 **ACK#0**（up）`00 04 00 00`

**窗口 1**（块 1-4）：
包 4-7 **DATA#1..#4**（down，各 512B `0xFF`）—— 连续发送 4 块（windowsize=4）
包 8 **ACK#4**（up）`00 04 00 04` —— 只确认窗口末尾块（RFC 7440：DRCV 发末块 ACK）

**窗口 2**（块 5-8）：
包 9-12 **DATA#5..#8**（down，各 512B `0xFF`）
包 13 **ACK#8**（up）`00 04 00 08`

**末窗口规则**：块数为 8 的完整窗口（8 mod 4 == 0），末窗口块数 = windowsize（非"块数 < windowsize"的 RFC 7440 末窗口判定），结束需由 DATA 块内容标记：末块 #8 为满块（512B）→ 按 RFC 1350 §6 需 0 字节终止块。AutoAppendFinalBlock 默认 true（§5.1：末块满块即追加）→ **自动追加 DATA#9(0B)/ACK#9**，总包数 = 15（不含显式 FinalBlockZero；若用户设 auto_append_final_block=false 或 final_block_zero=true 则无自动追加，为 13 包负向流）。

**断言点**：窗口内 DATA 连续（无中间 ACK）；窗口边界只有 1 个 ACK（块号 = 窗口末块）；块号跨窗口连续递增（1..4, 5..8）。

### S7 多选项组合（blksize + timeout + tsize）

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "multi.bin",
            "transfer_mode": "octet",
            "blksize": 512, "timeout": 5, "server_tsize": 2048,
            "blocks_count": 4, "data_payload_pattern": "FF" }
}
```

包 1 **RRQ**（up）
```
TFTP:      00 01 6d 75 6c 74 69 2e 62 69 6e 00 6f 63 74 65 74 00
           62 6c 6b 73 69 7a 65 00 35 31 32 00 74 69 6d 65 6f 75 74 00 35 00
           74 73 69 7a 65 00 30 00
核算: 2 + 11 + 6 + 8+4 + 8+2 + 6+2 = 2+11+6+12+10+8 = 49? — 逐项: "multi.bin"(9+1)=10, "octet"(5+1)=6,
      "blksize\0"(8) + "512\0"(4) = 12, "timeout\0"(8) + "5\0"(2) = 10, "tsize\0"(6) + "0\0"(2) = 8
      合计 = 2 + 10 + 6 + 12 + 10 + 8 = 48 字节
```

包 2 **OACK**（down）选项顺序与 RRQ 一致（blksize → timeout → tsize）
```
TFTP:      00 06 62 6c 6b 73 69 7a 65 00 35 31 32 00 74 69 6d 65 6f 75 74 00 35 00 74 73 69 7a 65 00 32 30 34 38 00
核算: 2 + 12 + 10 + 11 = 35 字节（tsize="2048"=ServerTSize）
```

包 3 **ACK#0**（up）`00 04 00 00`
包 4-13 **DATA#1..#4 + ACK#1..#4**（各 512B）
包 14 **DATA#5**（down）`00 03 00 05`（0 字节，自动追加：4×512=2048=ServerTSize）
包 15 **ACK#5**（up）`00 04 00 05`
**总包数 = 15**

**断言点**：选项顺序固定 blksize → timeout → tsize；自动追加触发。

### S8 ERROR 中断（含 code=8 选项协商失败）

**场景 8a — RRQ 后立即 ERROR**（file not found）：
```
包 1 RRQ（up）:   00 01 6d 69 73 73 69 6e 67 2e 62 69 6e 00 6f 63 74 65 74 00   (20 字节)
包 2 ERROR（down）: 00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00
    核算: 2 + 2 + 15 = 19 字节（"File not found\0"=15B）
```
总包数 = 2。ErrCode=1（File not found）。

**场景 8b — WRQ 磁盘满（中途错误）**：
```
包 1 WRQ（up）:    00 02 <filename>\0 octet\0
包 2 ACK#0（down）: 00 04 00 00
包 3 DATA#1（up）: 00 03 00 01 [0xBB × 512]
包 4 ACK#1（down）: 00 04 00 01
包 5 ERROR（down）: 00 05 00 03 44 69 73 6b 20 66 75 6c 6c 20 6f 72 20 61 6c 6c 6f 63 61 74 69 6f 6e 20 65 78 63 65 65 64 65 64 00
    核算: 2 + 2 + 33 = 37 字节（"Disk full or allocation exceeded\0"=33B, 默认映射）
```
总包数 = 5（error_after_block=1, error_side=server）。

**场景 8c — 客户端拒绝 OACK（ERROR code=8, RFC 2347）**：
```
包 1 RRQ（up, 含 blksize 选项）: 00 01 <file>\0 octet\0 blksize\0 65464\0
包 2 OACK（down）:               00 06 blksize\0 65464\0
包 3 ERROR（up, 客户端发起）:     00 05 00 08 46 61 69 6c 65 64 20 74 6f 20 6e 65 67 6f 74 69 61 74 65 20 6f 70 74 69 6f 6e 73 00
    核算: 2 + 2 + 28 = 32 字节（"Failed to negotiate options\0"=28B, 默认映射）
```
总包数 = 3。error_code=8, error_after_block=0, error_side=client。

**场景 8d — 客户端取消下载（ERROR code=0, up 方向）**：
```
包 4 ERROR（up, 客户端发起）: 00 05 00 00 55 73 65 72 20 63 61 6e 63 65 6c 6c 65 64 00
    核算: 2 + 2 + 15 = 19 字节（用户自定义 ErrMsg "User cancelled\0"）
```
（error_code=0 + error_after_block=1 场景：RRQ → DATA#1 → ACK#1 → ERROR(0)，共 4 包）

**断言点**：ERROR 后不再生成任何包（除 code=5 例外）；ERROR 不被确认；默认 ErrMsg 映射含 code=8。

### S9 TID 变更（ERROR code=5 不终止传输 — trafficgen 扩展行为，非任何 RFC 定义）

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "x.bin",
            "transfer_mode": "octet",
            "blocks_count": 4, "data_payload_pattern": "AA",
            "server_tid": 60000,
            "server_tid_change": true, "server_tid_change_at_block": 3,
            "server_tid_new": 61000 }
}
```

**trafficgen 扩展语义说明**：本场景模拟 NAT/中间件导致的 TID 漂移（服务器中途切换 TID 端口），为 **trafficgen 自定义扩展行为，非任何 RFC 标准**（v2.0.1 曾以"RFC 1783 §3 TID 迁移机制"为依据，但 RFC 1783 实际标题是 "TFTP Blocksize Option"（RFC 2348 的前身），内容仅涉及 blksize 选项协商，**完全不包含** TID 变更机制——该引用系虚构，v2.0.2 已全部删除）。**注意：S9 序列不符合 RFC 1350 §4 的 TID 校验语义**——RFC 1350 下客户端收到源 TID 不匹配的 DATA#3（来自 61000）时应**丢弃该包并向错误源回 ERROR(5)、继续等待旧 TID 60000 上的重传**，不回 ACK#3，也不向新 TID 传输；S9 中"ERROR(5) 发向新 TID 后继续向新 TID 传输"是 trafficgen 自定义的 TID 变更行为，与 RFC 1350 合规客户端**不可互操作**，仅用于生成器字节序列测试（互操作负向分类，同 §9.4）。RFC 1350 的正确校验语义见 §4.3。

**期望包序列（10 包迁移核心 + 2 包自动追加 = 12 包）**：

| # | 包 | 方向 | 端口 | 字节 |
|---|-----|------|------|------|
| 1 | RRQ | up | C → 69 | `00 01 78 2e 62 69 6e 00 6f 63 74 65 74 00`（2+6+6=14 字节） |
| 2 | DATA#1 | down | 60000 → C | `00 03 00 01 [0xAA × 512]` |
| 3 | ACK#1 | up | C → 60000 | `00 04 00 01` |
| 4 | DATA#2 | down | 60000 → C | `00 03 00 02 [0xAA × 512]` |
| 5 | ACK#2 | up | C → 60000 | `00 04 00 02` |
| 6 | DATA#3 | down | **61000** → C | `00 03 00 03 [0xAA × 512]`（服务器主动切换到新 TID 61000） |
| 7 | ERROR(5) | up | C → **61000** | `00 05 00 05 55 6e 6b 6e 6f 77 6e 20 74 72 61 6e 73 66 65 72 20 49 44 00`（2+2+20=24 字节；客户端向新 TID 发，表示"包源 TID 与约定 TID 60000 不符，尚未完成迁移"——trafficgen 扩展迁移流程） |
| 8 | ACK#3 | up | C → 61000 | `00 04 00 03`（客户端接受新 TID，继续以新 TID 应答） |
| 9 | DATA#4 | down | 61000 → C | `00 03 00 04 [0xAA × 512]` |
| 10 | ACK#4 | up | C → 61000 | `00 04 00 04` |
| 11 | DATA#5 | down | 61000 → C | `00 03 00 05`（**0 字节末块，自动追加**：末块 #4 满块 512B，§5.1） |
| 12 | ACK#5 | up | C → 61000 | `00 04 00 05` |

**注**：S9 输入 blocks_count=4，末块 #4 为满块（512B）→ 按 §5.1 自动追加 DATA#5(0B)/ACK#5，实际生成 **12 包**（10 包迁移核心 + 2 包自动追加；T-110/T-149/T-229 的断言以此为准）。

**断言点**：ERROR code=5 **不终止传输**（后续仍有 DATA#4/ACK#4 及自动追加）；ERROR 方向 = up（客户端发起）；ERROR DstPort = 61000（新 TID）；DATA/ACK 严格成对；ERROR(5) 语义为 **trafficgen 扩展**（非 RFC 1350 校验语义、非任何 RFC 标准，与 RFC 1350 合规客户端不可互操作）。

### S10 超时重传（RFC 1350 §6 合规时序）

**输入 spec**：
```json
{
  "tftp": { "mode": "read", "filename": "rt.bin",
            "transfer_mode": "octet",
            "blocks_count": 3, "data_payload_pattern": "AA",
            "retransmit_blocks": [2] }
}
```

**语义**：DATA#2 初次发送丢失，仅出现重传的 DATA#2（RFC 1350 §6：发送方超时重传最后发送的包；重传 DATA 出现在其 ACK 之前）。

**期望包序列（9 包）**：

| # | 包 | 方向 | 字节 | 说明 |
|---|-----|------|------|------|
| 1 | RRQ | up | `00 01 72 74 2e 62 69 6e 00 6f 63 74 65 74 00` | 14 字节 |
| 2 | DATA#1 | down | `00 03 00 01 [0xAA × 512]` | 满块 |
| 3 | ACK#1 | up | `00 04 00 01` | |
| 4 | DATA#2 | down | `00 03 00 02 [0xAA × 512]` | **重传版本**（原 DATA#2 已丢，未出现） |
| 5 | ACK#2 | up | `00 04 00 02` | 对重传 DATA#2 的确认 |
| 6 | DATA#3 | down | `00 03 00 03 [0xAA × 512]` | 末块满块 → 触发自动追加（§5.1） |
| 7 | ACK#3 | up | `00 04 00 03` | |
| 8 | DATA#4 | down | `00 03 00 04` | 0 字节末块，自动追加（R1-CRITICAL-3 修复） |
| 9 | ACK#4 | up | `00 04 00 04` | |

**断言点**：Block#=2 的 DATA 只出现 **1** 次（重传版本）；不出现"原 DATA#2 → 原 ACK#2 → 重传 DATA#2 → 重传 ACK#2"的异常序列（该序列在真实 TFTP 中不会发生，v1.1 已废弃）；重传字节与原块相同；末块 #3 满块 → 自动追加 DATA#4(0B)/ACK#4（§5.1）。

### S11 多会话并发

**输入 spec**（顶层 strategy 数组，3 流）：
```json
{
  "flows": [
    { "src_ip": "10.0.0.100", "dst_ip": "10.0.0.1", "src_port": 50001, "dst_port": 69, "udp": {},
      "tftp": { "mode": "read", "filename": "f1.bin", "transfer_mode": "octet",
                "blocks_count": 1, "server_tid": 60001, "data_payload_pattern": "AA" } },
    { "src_ip": "10.0.0.100", "dst_ip": "10.0.0.1", "src_port": 50002, "dst_port": 69, "udp": {},
      "tftp": { "mode": "read", "filename": "f2.bin", "transfer_mode": "octet",
                "blocks_count": 1, "server_tid": 60002, "data_payload_pattern": "BB" } },
    { "src_ip": "10.0.0.101", "dst_ip": "10.0.0.1", "src_port": 50003, "dst_port": 69, "udp": {},
      "tftp": { "mode": "read", "filename": "f3.bin", "transfer_mode": "octet",
                "blocks_count": 1, "server_tid": 60003, "data_payload_pattern": "CC" } }
  ]
}
```

**期望**：3 个独立流，每流 3 包（RRQ + DATA#1 + ACK#1），共 9 包。
- 流 1：10.0.0.100:50001 ↔ 10.0.0.1:69/60001，DATA 载荷 0xAA
- 流 2：10.0.0.100:50002 ↔ 10.0.0.1:69/60002，DATA 载荷 0xBB
- 流 3：10.0.0.101:50003 ↔ 10.0.0.1:69/60003，DATA 载荷 0xCC

**断言点**：4-tuple 互异；每流 PacketIndex 连续递增；跨流包不串扰（流 1 的 ACK 不响应流 2 的 DATA）。

### S12 多流关联

**场景**：同一 batch（批次）内多流共享策略模板，按 FlowID 分组关联。

**期望**：
- 每流的 FlowID = `<src_ip>-<dst_ip>-<src_port>-<dst_port>`（dst_port 在 ServerTIDChange 时为变更后的 TID）。
- 同流内包的 Metadata：`tftp_opcode`、`tftp_block`、`tftp_filename` 一致；跨流 filename 不同。
- 服务器端口冲突检测：同一 batch 内两流的 ServerTID 相同 → Validate 报错 `tftp: server_tid 60000 conflicts with another flow in the same batch`（避免 TID 冲突导致会话无法区分）。

### S13 边界值

**13a — 512 字节满块 + 自动追加**：
`blocks_count=2, blksize=512, client_tsize=1024`（RRQ 模式）→ 2×512=1024=判定TSize → 自动追加 DATA#3(0B)/ACK#3。总包数 = 1 + 2×2 + 2 = 7。
```
DATA#1: 00 03 00 01 [0xFF × 512]    核算: 4 + 512 = 516 字节（UDP Len = 524 = 0x20C）
DATA#2: 00 03 00 02 [0xFF × 512]    核算: 516 字节
DATA#3: 00 03 00 03                 核算: 4 字节（0 字节 Data）
```

**13b — blksize 极值**：
- blksize=8（RFC 2348 最小）：DATA 4 + 8 = 12 字节；UDP Len = 20。
- blksize=65464（RFC 2348 最大）：DATA 4 + 65464 = 65468 字节；UDP Len = 65476（≤ 65507，合法）。

**13c — 65535 块（uint16 边界）**：
`blocks_count=65535, wrap_block_number=false` → 最后一个 DATA 的 Block#=65535（uint16 最大值，不溢出）。测试用 short-circuit（planner 只生成首末包，不实际生成 65535 个 DATA）。
**注**（R1-LOW-4 修复）：本场景无 tsize、无显式末块；全部 65535 块均为满块（512B）→ 按 §5.1 自动追加规则末块 #65535 满块 → 自动追加 0 字节末块（DATA#65536，Block# 回绕后 = 0，需 wrap_block_number=true，否则 V18 报错）。如需聚焦"不追加"的负向行为，显式设 auto_append_final_block=false（该流无结束标记，仅负向测试用）。

**13d — 65536 块（回绕）**：
`blocks_count=65536, wrap_block_number=true` → Block# 序列 = 1, 2, ..., 65535, 0。第 65536 个 DATA 的 Block# = (65536 mod 65536) = 0。**BlocksCount 字段为 uint32（C1 修复），65536 可正常表示与解析**。测试用 short-circuit 断言首末包。

**13e — 自动追加推至 65536**：
`blocks_count=65535, blksize=512, client_tsize=33553920`（65535×512=33553920）→ 自动追加后实际 65536 块；未开 wrap 时 Validate 报错 `tftp: auto-append pushes blocks_count to 65536, set wrap_block_number=true`；开 wrap 后正常生成，0 字节末块 Block#=0。

### S14 错误处理

| 输入 | Validate 错误（错误类） |
|------|------------------------|
| filename="" | `tftp: filename is required` |
| filename="a\0b" | `tftp: filename must not contain null byte` |
| mode="delete" | `tftp: invalid mode "delete" (must be read or write)` |
| transfer_mode="binary" | `tftp: invalid transfer_mode "binary" (must be netascii or octet)` |
| transfer_mode="mail" | `tftp: transfer_mode "mail" is deprecated and unsupported` |
| error_code=9 | `tftp: error_code 9 out of range (0-8)` |
| blksize=7 | `tftp: blksize 7 out of range (8-65464)` |
| blksize=65465 | `tftp: blksize 65465 out of range (8-65464)` |
| timeout=0（显式） | 不报错（等同未设置，不发送选项） |
| timeout=256 | `tftp: timeout 256 out of range (1-255)` |
| windowsize=0 | `tftp: windowsize 0 out of range (1-65535)` |
| windowsize=65536 | `tftp: windowsize 65536 out of range (1-65535)` |
| server_tid=80 | `tftp: server_tid 80 in well-known range (<1024)` |
| error_after_block=5, blocks_count=2 | `tftp: error_after_block 5 exceeds blocks_count 2` |
| error_after_block=3, blocks_count=0 | `tftp: error_after_block requires explicit blocks_count (cannot derive)` |
| retransmit_blocks=[99], blocks_count=2 | `tftp: retransmit_blocks entry 99 out of range` |
| server_tid_change=true, error_code=1 | `tftp: server_tid_change and error_code are mutually exclusive` |
| server_tid_change=true, retransmit_blocks=[2] | `tftp: server_tid_change and retransmit_blocks are mutually exclusive` |
| server_tid_change=true, server_tid_change_at_block=0 | `tftp: server_tid_change_at_block must be >= 1` |
| server_tid_change=true, server_tid_change_at_block=99, blocks_count=4 | `tftp: server_tid_change_at_block 99 out of range` |
| server_tid_new=80 | `tftp: server_tid_new 80 in well-known range (<1024)` |
| server_tid=60000, server_tid_new=60000 | `tftp: server_tid_new must differ from server_tid` |
| blocks_count=65536, wrap_block_number=false | `tftp: blocks_count 65536 exceeds uint16 max (set wrap_block_number=true to allow)` |
| blocks_count=0, 无 payload 来源 | `tftp: blocks_count=0 requires data_payload_pattern or payload source` |
| FlowSpec 标记 tftp 但 TFTPConfig=nil | `tftp: TFTPConfig is required` |

**断言点**：Validate 错误传播到任务失败（不静默成功）；错误信息含 `tftp:` 前缀与具体字段名。

### S15 完整传输流程

**场景 15a — RRQ 完整下载（含选项 + 自动追加）**：

```
包 1  RRQ（up, C → 69）      00 01 full.bin\0 octet\0 blksize\0 1024\0 timeout\0 5\0 tsize\0 0\0
包 2  OACK（down, TID → C）  00 06 blksize\0 1024\0 timeout\0 5\0 tsize\0 4096\0
包 3  ACK#0（up, C → TID）   00 04 00 00
包 4  DATA#1（down）          00 03 00 01 [0xFF × 1024]
包 5  ACK#1（up）             00 04 00 01
包 6  DATA#2（down）          00 03 00 02 [0xFF × 1024]
包 7  ACK#2（up）             00 04 00 02
包 8  DATA#3（down）          00 03 00 03 [0xFF × 1024]
包 9  ACK#3（up）             00 04 00 03
包 10 DATA#4（down）          00 03 00 04 [0xFF × 1024]
包 11 ACK#4（up）             00 04 00 04
包 12 DATA#5（down）          00 03 00 05（0 字节末块；4×1024=4096=ServerTSize 自动追加）
包 13 ACK#5（up）             00 04 00 05
```
输入：`mode=read, filename=full.bin, blksize=1024, timeout=5, server_tsize=4096, blocks_count=4, data_payload_pattern="FF"`。
总包数 = 3 + 2×4 + 2 = 13。

**场景 15b — WRQ 完整上传（无选项）**：

```
包 1  WRQ（up, C → 69）      00 02 full.dat\0 octet\0
包 2  ACK#0（down, TID → C） 00 04 00 00
包 3  DATA#1（up）           00 03 00 01 [0xBB × 512]
包 4  ACK#1（down）          00 04 00 01
包 5  DATA#2（up）           00 03 00 02 [0xBB × 512]
包 6  ACK#2（down）          00 04 00 02
包 7  DATA#3（up）           00 03 00 03 [0xBB × 200]（200 < 512 → 末块）
包 8  ACK#3（down）          00 04 00 03
```
输入：`mode=write, filename=full.dat, blocks_count=3, data_payload_pattern="BB"`（Data 长度由 payload 规模推导：末块 200 字节）。
总包数 = 2 + 2×3 = 8。

---


## §7 测试用例（T-001 ~ T-241）

测试用例遵循 CLAUDE.md §Testing Policy 8 条规则：spec-driven（每条对应 §2-§6 的字段/状态机分支）、覆盖正向+负向+边界、断言可观察输出（包序列、字节、Direction、Block#）、跨层集成、并发正确性。

### 7.1 正向用例（T-001 ~ T-020）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 UDP 包序列 | 断言（对应场景/字段） |
|---------|------|----------------|-----------------|----------------------|
| T-001 | RRQ octet 短文件（<512B） | mode=read, filename=config.txt, octet, blocks_count=1, data_payload_pattern=0xAA×100 | RRQ → DATA#1(100B) → ACK#1（3 包） | S1：RRQ=`00 01 63 6f 6e 66 69 67 2e 74 78 74 00 6f 63 74 65 74 00`（19B）；DATA#1 Block#=1, Data=100×0xAA（100<512 末块）；ACK#1=`00 04 00 01` |
| T-002 | RRQ 多块 + 自动追加 | mode=read, filename=image.bin, octet, blocks_count=2, blksize=512, client_tsize=1024, data_payload_pattern=0xFF | RRQ → DATA#1(512B)/ACK#1 → DATA#2(512B)/ACK#2 → DATA#3(0B)/ACK#3（7 包） | S13a/S15：判定TSize=ClientTSize=1024（RRQ 模式，§5.1）；DATA#3 0 字节；Block# 1,2,3 |
| T-003 | RRQ netascii 模式 | mode=read, filename=readme.txt, transfer_mode=netascii, blocks_count=1, data_payload_pattern=0x48656C6C6F | RRQ → DATA#1(5B) → ACK#1（3 包） | §3.2：mode 字段=`netascii`（小写）；DATA=`48656C6C6F`（"Hello"）；planner 不做 CR/LF 转换 |
| T-004 | WRQ 上传 200B | mode=write, filename=upload.dat, octet, blocks_count=1, data_payload_pattern=0xBB×200 | WRQ → ACK#0 → DATA#1(200B) → ACK#1（4 包） | S2：ACK#0 Block#=0（WRQ 无选项确认）；DATA Direction=up；ACK Direction=down |
| T-005 | blksize=1428 协商 | mode=read, filename=large.bin, blksize=1428, blocks_count=2, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA#1(1428B)/ACK#1 → DATA#2(1428B)/ACK#2 → DATA#3(0B)/ACK#3（9 包） | S3：RRQ 31B；OACK=`00 06 62 6c 6b 73 69 7a 65 00 31 34 32 38 00`（15B）；DATA 长度=1428；末块 #2 满块 → 自动追加（R1-CRITICAL-3 修复） |
| T-006 | timeout=10 协商 | mode=read, filename=f.bin, timeout=10, blocks_count=1, data_payload_pattern=0xAA | RRQ → OACK → ACK#0 → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（7 包） | S4：RRQ 25B；timeout value=ASCII "10"（`31 30`）；OACK 回显同值；末块 #1 满块 → 自动追加（R1-CRITICAL-3 修复） |
| T-007 | tsize 协商（RRQ 模式） | mode=read, filename=data.bin, server_tsize=2048, blocks_count=4, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA/ACK×4 → DATA#5(0B)/ACK#5（13 包） | S5a：RRQ tsize="0"（强制）；OACK tsize="2048"（ServerTSize）；自动追加 |
| T-008 | tsize 协商（WRQ 模式） | mode=write, filename=wdata.bin, client_tsize=2048, blocks_count=4, data_payload_pattern=0xFF | WRQ → OACK → DATA/ACK×4 → DATA#5(0B)/ACK#5（12 包） | S5b：WRQ tsize="2048"（ClientTSize）；OACK 回显；无 ACK#0；自动追加 |
| T-009 | windowsize=4 协商 | mode=read, filename=w.bin, windowsize=4, blocks_count=8, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA#1-4 → ACK#4 → DATA#5-8 → ACK#8 → DATA#9(0B)/ACK#9（15 包） | S6：窗口内 DATA 连续无中间 ACK；ACK 块号=窗口末块；跨窗口块号连续；末块 #8 满块 → 自动追加 DATA#9(0B)/ACK#9（R1-CRITICAL-3/R1-HIGH-4 修复） |
| T-010 | 三选项组合 + 自动追加 | mode=read, filename=multi.bin, blksize=512, timeout=5, server_tsize=2048, blocks_count=4, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA/ACK×4 → DATA#5(0B)/ACK#5（15 包） | S7：选项顺序 blksize→timeout→tsize；OACK 同序；自动追加 |
| T-011 | WRQ + OACK（无 ACK#0） | mode=write, filename=w.bin, blksize=512, blocks_count=1, data_payload_pattern=0xFF | WRQ → OACK → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（6 包） | §4.2/§4.4：WRQ+OACK 直接 DATA#1，无 ACK#0；末块 #1 满块 → 自动追加（R1-CRITICAL-3 修复） |
| T-012 | 默认值（mode/TM/dst_port） | tftp={filename=x.bin, data_payload_pattern=0xAA} | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §5.1：mode=read, transfer_mode=octet, dst_port=69 默认化；末块 #1 满块（默认 0x00..0xFF 循环至 BlkSize 512B）→ 自动追加（§5.1） |
| T-013 | 大写 mode/transfer_mode 输入 | mode="READ", transfer_mode="OCTET" | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §2.3：大小写不敏感接受（RFC 1350）；输出统一小写 `octet`；末块满块 → 自动追加 |
| T-014 | ServerTID 显式配置 | server_tid=60000, blocks_count=1, data_payload_pattern=0xAA | RRQ(→:69) → DATA#1(:60000→) → ACK#1(→:60000) → DATA#2(0B)/ACK#2（5 包） | §2.5：包 2/3 用 60000 而非 69；末块 #1 满块 → 自动追加（§5.1） |
| T-015 | ServerTID 确定性生成 | server_tid=0, blocks_count=1, data_payload_pattern=0xAA | 两次 Plan 相同 spec → ServerTID 相同 | §5.1：FNV-1a(FlowID) 确定性；端口 ∈ 49152-65535 且 ≠69 |
| T-016 | IncludeOACK=true + 无选项（RRQ） | include_oack=true, mode=read, filename=o.bin, blocks_count=1, data_payload_pattern=0xAA | RRQ → OACK(仅`00 06`) → ACK#0 → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（7 包） | §4.4：OACK 仅 opcode 2 字节（H4/L1 修复）；RRQ 分支走 ACK#0；末块 #1 满块 → 自动追加（§5.1） |
| T-017 | IncludeOACK=true + 无选项（WRQ） | include_oack=true, mode=write, filename=o.dat, blocks_count=1, data_payload_pattern=0xAA | WRQ → OACK(仅`00 06`) → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（6 包） | §4.4：WRQ 分支直接 DATA#1（无 ACK#0）；末块 #1 满块 → 自动追加（§5.1） |
| T-018 | FinalBlockZero 显式末块 | mode=read, filename=explicitterm.bin, blksize=512, blocks_count=3, auto_append_final_block=false, final_block_zero=true, data_payload_pattern=0xFF | RRQ → DATA#1(512B)/ACK#1 → DATA#2(512B)/ACK#2 → DATA#3(0B)/ACK#3（7 包） | §5.3：末块 Data=0（FinalBlockZero 触发而非自动追加）；跳过自动追加 |
| T-019 | FinalBlockZero + 自动追加不重复 | mode=read, filename=edgezero.bin, blksize=512, blocks_count=2, client_tsize=1024, final_block_zero=true, data_payload_pattern=0xFF | RRQ → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2（4 包） | §5.3：末块（#2）Data=0（FinalBlockZero 触发）；2×512=1024=判定TSize 但末块非满块，自动追加判定（末块满块）不触发，不重复追加 DATA#3（R1-MED-3 修复：调整 blocks_count=2 使末块恰好为 0 字节非满块，从而真正测试"FinalBlockZero 使末块非满块 → 自动追加跳过"） |
| T-020 | windowsize=1（默认锁步） | windowsize=1, blocks_count=4, data_payload_pattern=0xFF | 与无 windowsize 选项完全一致（锁步）+ 末块满块自动追加 DATA#5(0B)/ACK#5 | §3.9：RFC 7440 "windowsize=1 MUST be equivalent to RFC 1350"；每 DATA 一 ACK；末块 #4 满块 → 自动追加（§5.1） |

### 7.2 负向错误注入用例（T-021 ~ T-040）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-021 | RRQ 后立即 ERROR(1) | mode=read, filename=missing.bin, blocks_count=0, error_code=1, error_msg="File not found", error_after_block=0 | RRQ → ERROR(1)（2 包） | S8a：ERROR=`00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00`（19B）；Direction=down |
| T-022 | RRQ 中途 ERROR(2) | mode=read, blocks_count=3, data_payload_pattern=0xAA, error_code=2, error_msg="Access violation", error_after_block=3, error_side=server | RRQ → DATA/ACK×3 → ERROR(2)（8 包） | ERROR 于 ACK#3 后；ERROR 优先于自动追加（无 0 字节末块）——§5.3 ERROR 注入与自动追加优先级规则（R2-HIGH-2 修复：error_after_block=3=blocks_count=3 且末块 #3 满块，ERROR 终止传输，不追加 DATA#4(0B)） |
| T-023 | WRQ 中途 ERROR(3) | mode=write, blocks_count=2, data_payload_pattern=0xBB, error_code=3, error_msg="Disk full", error_after_block=2, error_side=server | WRQ → ACK#0 → DATA/ACK×2 → ERROR(3)（7 包） | S8b：ERROR 默认 ErrMsg="Disk full or allocation exceeded\0"（33B，M4 修复）；Direction=down |
| T-024 | 客户端取消下载 ERROR(0) | mode=read, blocks_count=1, data_payload_pattern=0xAA, error_code=0, error_msg="User cancelled", error_after_block=1, error_side=client | RRQ → DATA#1 → ACK#1 → ERROR(0)（4 包） | S8d：ERROR Direction=up；ErrCode=0；ErrMsg=用户自定义 |
| T-025 | ERROR 空消息 → 默认映射（RRQ 后） | error_code=4, error_msg="", error_after_block=0 | RRQ → ERROR(4)（2 包） | §5.4：ErrMsg=`Illegal TFTP operation\0`（23B，R1-MED-1 修复）；ERROR 总长 2+2+23=27B |
| T-026 | ERROR code=8 默认映射 | error_code=8, error_msg="", error_after_block=0 | RRQ → ERROR(8)（2 包） | §5.4：ErrMsg=`Failed to negotiate options\0`（28B，R1-MED-1 修复）；Validate 允许 0-8（H2 修复）；ERROR 总长 2+2+28=32B |
| T-027 | ERROR code=5 默认映射 | error_code=5, error_msg="", error_after_block=0 | RRQ → ERROR(5)（2 包） | §5.4：ErrMsg=`Unknown transfer ID\0`（20B，R1-MED-1 修复）；ERROR 总长 2+2+20=24B |
| T-028 | ERROR 消息超长截断 | error_msg=300×'A', error_code=0, error_after_block=1 | RRQ → DATA#1 → ACK#1 → ERROR(0)（4 包） | ErrMsg 截断到 255 字节 + `\0`（总 256 字节）；error_after_block=1 显式注入意图（R1-CRITICAL-2 修复：ErrorCode=0 + EAB=0 不注入，EAB>0 注入 code=0） |
| T-029 | ERROR 后不再生成包 | error_code=1, error_after_block=2, blocks_count=3 | RRQ → DATA#1/ACK#1 → DATA#2/ACK#2 → ERROR(1)（7 包） | §4.3：ERROR 后无 DATA#3/ACK#3（终止） |
| T-030 | ERROR code=5 不终止（独立注入） | error_code=5, error_after_block=1, blocks_count=2, error_side=client | RRQ → DATA#1 → ACK#1 → ERROR(5) → （终止，无 DATA#2） | §4.3：客户端主动发 code=5 仍是终止错误（"不终止"仅限 TID 校验场景，S9） |
| T-031 | ErrorAfterBlock=0 + ErrorCode>0 + BlocksCount>0 | error_code=2, error_after_block=0, blocks_count=5 | RRQ → ERROR(2)（2 包） | ErrorAfterBlock=0 优先：无 DATA 直接 ERROR |
| T-032 | ErrorSide=client + WRQ | mode=write, error_code=4, error_after_block=0, error_side=client | WRQ → ERROR(4)（2 包） | ERROR Direction=up（客户端发起）；无 ACK#0 |
| T-033 | ERROR 注入 + RetransmitBlocks 共存 | error_code=1, error_after_block=3, retransmit_blocks=[2], blocks_count=3 | RRQ → DATA#1/ACK#1 → DATA#2(重传)/ACK#2 → DATA#3/ACK#3 → ERROR(1)（9 包） | §5.3：先重传后注入；ERROR 终止 |
| T-034 | ERROR 注入 + 自动追加互斥 | error_code=1, error_after_block=3, blocks_count=3, client_tsize=1536 | RRQ → DATA/ACK×3 → ERROR(1)（8 包） | ERROR 优先：3×512=1536=TSize 但 ERROR 抑制自动追加——§5.3 ERROR 注入与自动追加优先级规则（R2-HIGH-2 修复：error_after_block=3=blocks_count=3，ERROR 终止传输，不追加 DATA#4(0B)） |
| T-035 | 客户端拒绝 OACK（code=8 完整流程） | mode=read, blksize=65464, error_code=8, error_after_block=0, error_side=client | RRQ → OACK → ERROR(8, up)（3 包） | S8c：RFC 2347 §2 完整流程；ERROR 向 TID 发；无 DATA |
| T-036 | 中途 ERROR 方向验证（8 种 code × 2 side） | error_code=K（K=0..8 各一例）, error_after_block=1, error_side=server/client | 18 个子用例，各 RRQ → DATA#1/ACK#1 → ERROR(K) | §3.6：全部 9 个 code（0-8）可注入；Direction 随 side |
| T-037 | ErrMsg 覆盖默认 | error_code=1, error_msg="Custom", error_after_block=0 | RRQ → ERROR(1) | ErrMsg=`Custom\0`（覆盖 "File not found"） |
| T-038 | ERROR 无 ErrMsg（空串） | error_code=3, error_msg="", error_after_block=0 | RRQ → ERROR(3) | 默认映射生效（M4 修复：ErrorMsg=="" 即映射，不要求 ErrorCode>0） |
| T-039 | ERROR 注入于 WRQ+OACK 后 | mode=write, blksize=512, error_code=6, error_after_block=0, error_side=server | WRQ → OACK → ERROR(6)（3 包） | WRQ+OACK 分支下 ERROR 紧跟 OACK |
| T-040 | ERROR 注入于 RRQ+OACK 后 | mode=read, blksize=512, error_code=7, error_after_block=0, error_side=server | RRQ → OACK → ERROR(7)（3 包） | RRQ+OACK 分支下 ERROR 紧跟 OACK（无 ACK#0） |

### 7.3 边界用例（T-041 ~ T-070）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-041 | blksize=8（最小） | blksize=8, blocks_count=1, data_payload_pattern=0xAA | RRQ → OACK → ACK#0 → DATA#1(8B) → ACK#1 → DATA#2(0B)/ACK#2（6 包） | S13b：DATA 4+8=12B；字节=`AA×8`；末块 #1 满块（8B）→ 自动追加（§5.1） |
| T-042 | blksize=65464（最大） | blksize=65464, blocks_count=1, data_payload_pattern=0xAA | RRQ → OACK → ACK#0 → DATA#1(65464B) → ACK#1 → DATA#2(0B)/ACK#2（6 包） | S13b：DATA 4+65464=65468B；UDP Len=65476≤65507；末块 #1 满块 → 自动追加（§5.1） |
| T-043 | 文件大小=blksize 整数倍（自动追加） | mode=read, blksize=512, client_tsize=1024, blocks_count=2, data_payload_pattern=0xFF | RRQ → DATA/ACK×2 → DATA#3(0B)/ACK#3（7 包） | S13a：自动追加规则（RFC 1350 §6） |
| T-044 | 自动追加禁用 | 同 T-043 但 auto_append_final_block=false | RRQ → DATA/ACK×2（5 包） | §5.3：无 0 字节末块（非 RFC 合规流） |
| T-045 | WRQ 自动追加 | mode=write, blksize=512, client_tsize=1024, blocks_count=2, data_payload_pattern=0xFF | WRQ → ACK#0 → DATA/ACK×2 → DATA#3(0B)/ACK#3（8 包） | 判定TSize=ClientTSize；WRQ 无选项分支含 ACK#0 |
| T-046 | filename 含路径分隔符 | filename="/etc/passwd", blocks_count=1, data_payload_pattern=0xAA | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | filename 字段=`/etc/passwd\0`；无 Validate 错误；末块满块 → 自动追加（§5.1） |
| T-047 | filename 含反斜杠 | filename="dir\\file.bin", blocks_count=1, data_payload_pattern=0xAA | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | filename 保留 `\`；末块满块 → 自动追加（§5.1） |
| T-048 | 大块号 65535（short-circuit） | blocks_count=65535, wrap_block_number=false, data_payload_pattern=0xAA | short-circuit：仅断言最后一个 DATA Block#=65535 | S13c：uint16 最大值不溢出；末块 #65535 满块 → 自动追加 0 字节末块（需 wrap=true 或 auto_append=false，见 S13c 注，R1-LOW-4 修复） |
| T-049 | 65536 块回绕（short-circuit） | blocks_count=65536, wrap_block_number=true, data_payload_pattern=0xAA | short-circuit：断言 Block# 序列 65535 → 0 | S13d：BlocksCount=65536 可解析（uint32，C1 修复）；第 65536 块 Block#=0；末块满块 → 自动追加 DATA#65537(0B, Block#=1)（wrap=true 合法，§5.1）；**回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅用于字节序列测试，R2-HIGH-3 修复）** |
| T-050 | 自动追加推至 65536（未开 wrap 拒绝） | blocks_count=65535, client_tsize=33553920, blksize=512, wrap_block_number=false | Validate 拒绝 | `tftp: auto-append pushes blocks_count to 65536, set wrap_block_number=true` |
| T-051 | 自动追加推至 65536（开 wrap） | 同 T-050 加 wrap_block_number=true | short-circuit 正常生成 | 末块（0 字节）Block#=0 |
| T-052 | 末块 0 字节判定（FinalBlockZero） | final_block_zero=true, blocks_count=1, blksize=512 | RRQ → DATA#1(0B) → ACK#1（3 包） | 首块即 0 字节（合法：0 ≤ blksize-1） |
| T-053 | 单块 512B（末块满块自动追加） | blocks_count=1, blksize=512, data_payload_pattern=0xFF | RRQ → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2（5 包） | 512=blksize → 末块满块 → AutoAppendFinalBlock 默认 true 自动追加 0 字节终止块（RFC 1350 §6，R1-CRITICAL-3 修复）；对照：auto_append_final_block=false 时无末块（3 包，负向，见 T-062） |
| T-054 | blksize 默认 512 不发送选项 | blksize=0（省略）, blocks_count=1, data_payload_pattern=0xAA | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §3.8：无 blksize 选项；无 OACK；DATA=512B；末块满块 → 自动追加（§5.1） |
| T-055 | timeout=0 不发送选项 | timeout=0, blocks_count=1, data_payload_pattern=0xAA | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §5.1：timeout=0 等同未设置；末块满块 → 自动追加（§5.1） |
| T-056 | tsize 双零不发送 | client_tsize=0, server_tsize=0, blocks_count=1 | RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §5.2：无 tsize 选项、无 OACK；末块满块（默认 0x00..0xFF 模式）→ 自动追加（§5.1） |
| T-057 | WRQ tsize=0（ClientTSize=0, ServerTSize>0） | mode=write, server_tsize=1024, blocks_count=1, data_payload_pattern=0xAA | WRQ(`tsize\0 0\0`) → OACK(`tsize\0 1024\0`) → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2（6 包） | §5.2：WRQ 写 "0"（客户端无大小信息）；OACK 回 ServerTSize；末块 #1 满块 → 自动追加（§5.1） |
| T-058 | RRQ 空 DATA（0 字节末块仅 4B 头） | mode=read, blksize=512, client_tsize=512, blocks_count=1, data_payload_pattern=0xAA | RRQ → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2（5 包） | 1×512=512=判定TSize → 自动追加 DATA#2(0B) |
| T-059 | 数据规模推导（Payload 来源） | blocks_count=0, payload 规模=1024B（FileSource）, blksize=512 | RRQ → DATA#1(512B)/ACK#1 → DATA#2(512B)/ACK#2 → DATA#3(0B)/ACK#3（7 包） | §5.1：BlocksCount=ceil(1024/512)=2（推导）；末块 #2 满块 → 自动追加（§5.1） |
| T-060 | 数据规模推导（DataPayloadPattern 空 + blocks_count=1） | blocks_count=1, data_payload_pattern=""（空）, 无 Payload | RRQ → DATA#1(512B 确定性模式) → ACK#1 → DATA#2(0B)/ACK#2（5 包） | §5.1：BlocksCount>0 时无需 payload 源；用确定性 0x00..0xFF 模式；末块满块 → 自动追加（§5.1） |
| T-061 | DataPayloadPattern 循环填充 | blocks_count=2, data_payload_pattern=0x01 0x02 | DATA#1/2 Data = 0x01 0x02 循环重复 + 自动追加 DATA#3(0B)/ACK#3 | §5：pattern 循环重复至 BlkSize；末块满块 → 自动追加（§5.1） |
| T-062 | 半标准流（无结束标记，负向） | blocks_count=1, blksize=512, auto_append_final_block=false, data_payload_pattern=0xFF | RRQ → DATA#1(512B) → ACK#1（3 包） | **不合规流**（R1-CRITICAL-3 修复）：显式禁用自动追加 → 末块满块无 0 字节终止块；真实 TFTP 客户端与之互操作将永久等待下一块（RFC 1350 §6 MUST 违反）；仅用于互操作负向测试（§9.4） |
| T-063 | RRQ + tsize=0 显式（ClientTSize>0, RRQ 模式） | mode=read, client_tsize=1024, blocks_count=2, data_payload_pattern=0xFF | RRQ(`tsize\0 0\0`) → OACK(空 `00 06`) → ACK#0 → DATA#1/2 → DATA#3(0B)/ACK#3 | §5.2：RRQ tsize 永远 "0"（RFC 2349）；ServerTSize=0 → OACK 不回声 tsize（§5.2 仅 `ServerTSize>0` 才回声） |
| T-064 | OACK 空（无选项 + IncludeOACK=true）字节 | include_oack=true, blocks_count=1 | OACK 仅 2 字节 `00 06` | H4 修复：`00 06`（2 字节，非 4） |
| T-065 | 请求包 512 字节上限（blksize 选项组合） | filename=200 字符 + blksize=65464 | RRQ 长度 = 2+201+6+14 = 223B < 512 通过 | RFC 2347：max request 512 octets；**超限子用例经 R2-LOW-2 重新核算后撤回**：原用例 filename=255 字符（V3 上限）+ 全 4 选项（blksize=65464 + timeout=255 + tsize=2^32-1 + windowsize=65535），逐字节核算 = 2（opcode）+ 256（filename+`\0`）+ 6（"octet"+`\0`）+ 14（blksize）+ 12（timeout）+ 17（tsize）+ 17（windowsize）= **324B < 512**，远未达 V23 警告阈值；在 filename≤255（V3）+ 4 选项（RFC 2347 每选项仅一次）约束下，RRQ 最大长度 324B 永远无法触发 V23 警告。V23（>512B 警告）在 trafficgen 字段约束下**不可达**，保留为防御性检查（用户若绕过 Validate 直接构造 JSON 仍可触发） |
| T-066 | 多流 ServerTID 冲突拒绝 | 两流 server_tid=60000 | Validate 拒绝 | `tftp: server_tid 60000 conflicts with another flow in the same batch`（S12） |
| T-067 | 空 option 组合（BlkSize=0+Timeout=0+TSize=0） | 全零选项 | RRQ 无选项（无 OACK、无 ACK#0 于 RRQ） | §3.2：无选项分支 |
| T-068 | WRQ 空选项 + FinalBlockZero | mode=write, final_block_zero=true, blocks_count=2, data_payload_pattern=0xAA | WRQ → ACK#0 → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2（6 包） | WRQ 显式末块（FinalBlockZero 于 WRQ 生效） |
| T-069 | RRQ 完整流程 13 包 | mode=read, blksize=1024, timeout=5, server_tsize=4096, blocks_count=4, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA/ACK×4 → DATA#5(0B)/ACK#5（13 包） | S15a 逐包字节断言 |
| T-070 | WRQ 完整流程 8 包 | mode=write, blocks_count=3, data_payload_pattern=0xBB（末块 200B） | WRQ → ACK#0 → DATA#1(512B)/ACK#1 → DATA#2(512B)/ACK#2 → DATA#3(200B)/ACK#3（8 包） | S15b 逐包字节断言 |

### 7.4 Validate 负向用例（T-071 ~ T-105）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 Validate 错误 |
|---------|------|----------------|---------------------|
| T-071 | filename 空字符串 | filename="" | `tftp: filename is required` |
| T-072 | filename 含 NUL 字节 | filename="a\0b" | `tftp: filename must not contain null byte` |
| T-073 | mode 非法 | mode="delete" | `tftp: invalid mode "delete" (must be read or write)` |
| T-074 | transfer_mode 非法 | transfer_mode="binary" | `tftp: invalid transfer_mode "binary" (must be netascii or octet)` |
| T-075 | transfer_mode=mail（已废弃） | transfer_mode="mail" | `tftp: transfer_mode "mail" is deprecated and unsupported` |
| T-076 | error_code 越界（>8） | error_code=9 | `tftp: error_code 9 out of range (0-8)`（H2 修复：上限 8） |
| T-077 | blksize < 8 | blksize=7 | `tftp: blksize 7 out of range (8-65464)` |
| T-078 | blksize > 65464 | blksize=65465 | `tftp: blksize 65465 out of range (8-65464)` |
| T-079 | timeout > 255 | timeout=256 | `tftp: timeout 256 out of range (1-255)` |
| T-080 | windowsize=0 | windowsize=0 | `tftp: windowsize 0 out of range (1-65535)`（RFC 7440 最小 1） |
| T-081 | windowsize > 65535 | windowsize=65536 | `tftp: windowsize 65536 out of range (1-65535)` |
| T-082 | server_tid 知名端口 | server_tid=80 | `tftp: server_tid 80 in well-known range (<1024)` |
| T-083 | server_tid=1024（合法边界） | server_tid=1024 | 通过（1024 为 registered 端口下界，合法） |
| T-084 | error_after_block > blocks_count | error_after_block=5, blocks_count=2 | `tftp: error_after_block 5 exceeds blocks_count 2` |
| T-085 | error_after_block>0 但 blocks_count=0（derive） | error_after_block=3, blocks_count=0 | `tftp: error_after_block requires explicit blocks_count (cannot derive)` |
| T-086 | error_after_block>0 但无 payload 源 | error_after_block=2, blocks_count=2, data_payload_pattern="" | `tftp: error_after_block requires data_payload_pattern or payload source` |
| T-087 | retransmit_blocks 越界 | retransmit_blocks=[99], blocks_count=2 | `tftp: retransmit_blocks entry 99 out of range` |
| T-088 | retransmit_blocks=0 | retransmit_blocks=[0], blocks_count=2 | `tftp: retransmit_blocks entry 0 out of range` |
| T-089 | ServerTIDChange 与 ErrorCode>0 共存 | server_tid_change=true, error_code=1 | `tftp: server_tid_change and error_code are mutually exclusive` |
| T-090 | ServerTIDChange 与 RetransmitBlocks 共存 | server_tid_change=true, retransmit_blocks=[2] | `tftp: server_tid_change and retransmit_blocks are mutually exclusive` |
| T-091 | ServerTIDChange + ErrorCode=0 合法 | server_tid_change=true, error_code=0 | 通过（M3 修复：ErrorCode=0 不触发互斥） |
| T-092 | ServerTIDChangeAtBlock=0 | server_tid_change=true, server_tid_change_at_block=0, blocks_count=4 | `tftp: server_tid_change_at_block must be >= 1` |
| T-093 | ServerTIDChangeAtBlock 越界 | server_tid_change=true, server_tid_change_at_block=99, blocks_count=4 | `tftp: server_tid_change_at_block 99 out of range` |
| T-094 | server_tid_new 知名端口 | server_tid_new=80 | `tftp: server_tid_new 80 in well-known range (<1024)` |
| T-095 | server_tid_new == server_tid | server_tid=60000, server_tid_new=60000, server_tid_change=true | `tftp: server_tid_new must differ from server_tid` |
| T-096 | blocks_count > 65535 未开 wrap | blocks_count=65536, wrap_block_number=false | `tftp: blocks_count 65536 exceeds uint16 max (set wrap_block_number=true to allow)` |
| T-097 | blocks_count=0 无 payload 源 | blocks_count=0, data_payload_pattern="" | `tftp: blocks_count=0 requires data_payload_pattern or payload source` |
| T-098 | TFTPConfig 缺失 | L7 标记 tftp 但 TFTPConfig=nil | `tftp: TFTPConfig is required` |
| T-099 | final_block_zero + blocks_count=0 | final_block_zero=true, blocks_count=0 | `tftp: final_block_zero requires blocks_count >= 1 (cannot derive)` |
| T-100 | auto_append + blocks_count=0（derive 判定） | auto_append_final_block=true, blocks_count=0, client_tsize=1024, 无 payload 源 | `tftp: blocks_count=0 requires data_payload_pattern or payload source`（先于自动追加判定） |
| T-101 | TFTP 与 TCP 共存 | tftp={...}, tcp={...} | `tftp: tcp field must not be set (TFTP is UDP-only)` |
| T-102 | TFTP 与 HTTP 共存 | tftp={...}, http={...} | `tftp: http field must not be set (TFTP is UDP-only)` |
| T-103 | FlowSpec.DstPort 非 69（显式） | dst_port=1069, tftp={filename=x.bin, blocks_count=1} | 通过（用户显式指定服务器端口；RRQ/WRQ 用 1069） |
| T-104 | ErrorAfterBlock 与 RetransmitBlocks 重叠 | error_after_block=3, retransmit_blocks=[3], blocks_count=3 | 通过（重传后 ERROR，不互斥） |
| T-105 | ErrorAfterBlock 与 FinalBlockZero 并存 | error_after_block=2, final_block_zero=true, blocks_count=3 | 通过（组合合法） | **R2-MED-4 修复**：Validate 通过（error_after_block=2 ≤ blocks_count=3，final_block_zero=true 要求 blocks_count≥1 满足）；运行时 ERROR 在 DATA#2/ACK#2 后注入，传输终止（§4.3），DATA#3（显式末块）**不生成**——FinalBlockZero 不生效；ERROR 注入时既不生成自动追加块也不生成显式末块 |

### 7.5 多流与异常用例（T-106 ~ T-125）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-106 | 多流并发（3 流） | 3 个 flow，blocks_count=1, server_tid 各异 | 9 包，3 独立 FlowID | S11：4-tuple 互异；按 FlowID 分组不串扰 |
| T-107 | 多流交错时序 | 3 流时序交错 | 9 包交错但分组正确 | S12：每流 PacketIndex 连续递增 |
| T-108 | 多流 ServerTID 冲突 | 两流 server_tid=60000 | Validate 拒绝 | `tftp: server_tid 60000 conflicts with another flow in the same batch` |
| T-109 | 多流不同 src_ip | 3 流 src_ip 各异 | 9 包 | FlowID 含 src_ip 互异 |
| T-110 | TID 变更完整序列 | mode=read, blocks_count=4, server_tid=60000, server_tid_change=true, server_tid_change_at_block=3, server_tid_new=61000 | 10 包迁移序列（见 S9 表）+ 自动追加 DATA#5(0B)/ACK#5 = 12 包 | S9（trafficgen 扩展 TID 迁移语义，非任何 RFC 标准，R2-CRITICAL-1 修复：删除 RFC 1783 引用）：DATA#1/2 SrcPort=60000；DATA#3/4=61000；ERROR(5) up → 61000；**传输继续**（C4 修复）；末块 #4 满块 → 自动追加（R1-CRITICAL-3 修复）；ERROR(5) 后继续向新 TID 传输的行为与 RFC 1350 合规客户端不可互操作 |
| T-111 | TID 变更 ERROR 字节 | 同 T-110 | ERROR(5) 字节 | `00 05 00 05 55 6e 6b 6e 6f 77 6e 20 74 72 61 6e 73 66 65 72 20 49 44 00`（24B） |
| T-112 | TID 变更后块号连续 | 同 T-110 | Block# 1,2,3,4 | B6：新 TID 不重置块号 |
| T-113 | 单块重传（S10） | retransmit_blocks=[2], blocks_count=3, data_payload_pattern=0xAA | RRQ → DATA#1/ACK#1 → DATA#2(重传)/ACK#2 → DATA#3/ACK#3 → DATA#4(0B)/ACK#4（9 包） | S10：DATA#2 仅重传版本出现 1 次（C5 修复）；无"原 DATA#2+原 ACK#2"；末块 #3 满块 → 自动追加（§5.1） |
| T-114 | 多块重传 | retransmit_blocks=[1,3], blocks_count=4, data_payload_pattern=0xAA | RRQ + 4 块（#1/#3 为重传版本）+ 自动追加 DATA#5(0B)/ACK#5 | DATA#1、DATA#3 各 1 次（重传）；DATA#2/#4 正常；末块 #4 满块 → 自动追加（§5.1） |
| T-115 | 重传字节与源块相同 | retransmit_blocks=[2], blocks_count=3 | DATA#2 字节 = 无重传时 DATA#2 字节 | §4.5：重传不改变字节 |
| T-116 | 重传 + 自动追加 | retransmit_blocks=[2], blocks_count=2, client_tsize=1024, data_payload_pattern=0xFF | RRQ → DATA#1/ACK#1 → DATA#2(重传)/ACK#2 → DATA#3(0B)/ACK#3（7 包） | 重传后自动追加仍触发 |
| T-117 | 重传 + 首块丢失 | retransmit_blocks=[1], blocks_count=2, data_payload_pattern=0xAA | RRQ → DATA#1(重传)/ACK#1 → DATA#2/ACK#2 → DATA#3(0B)/ACK#3（7 包） | 首块重传（第 1 块即重传版本）；末块 #2 满块 → 自动追加（§5.1） |
| T-118 | windowsize=4 + 中途 ERROR | windowsize=4, blocks_count=6, error_code=1, error_after_block=4 | RRQ → OACK → ACK#0 → DATA#1-4 → ACK#4 → ERROR(1)（8 包） | 窗口末 ACK#4 后 ERROR 终止 |
| T-119 | windowsize=4 + 重传 | windowsize=4, retransmit_blocks=[3], blocks_count=8 | RRQ → OACK → ACK#0 → DATA#1-4（#3 重传版本）→ ACK#4 → DATA#5-8 → ACK#8 → DATA#9(0B)/ACK#9 | 窗口内重传：DATA#3 仅重传版本；窗口 ACK 仍为 #4；末块 #8 满块 → 自动追加（§5.1） |
| T-120 | windowsize=4 + 自动追加 | windowsize=4, blocks_count=4, client_tsize=2048, data_payload_pattern=0xFF | RRQ → OACK → ACK#0 → DATA#1-4 → ACK#4 → DATA#5(0B)/ACK#5（10 包） | 末窗口块数=windowsize（4），末块 #4 满块 → 自动追加 0 字节末块（判定 TSize=2048，4×512=2048 一致）；R1-HIGH-5 修复：原 9 包核算漏算 ACK#0（1+1+1+5+2=10） |
| T-121 | 末窗口不足 windowsize | windowsize=4, blocks_count=6（末窗口 2 块） | DATA#1-4 → ACK#4 → DATA#5-6 → ACK#6（8 包）；若末块 #6 满块则追加 DATA#7(0B)/ACK#7（共 9 包） | §3.9：末窗口块数 < windowsize 时接收方知情（RFC 7440）；末块满块时仍按 §5.1 自动追加（与判定 TSize 无关） |
| T-122 | windowsize 与 tsize 组合 | windowsize=2, server_tsize=2048, blocks_count=4, mode=read | RRQ → OACK → ACK#0 → DATA#1-2 → ACK#2 → DATA#3-4 → ACK#4 → DATA#5(0B)/ACK#5（11 包） | 窗口 ACK + tsize 自动追加共存 |
| T-123 | 多流含 ERROR 流 | 3 流中 1 流 error_code=1 | 9 包（6 正常 + 2 ERROR 流包） | 错误流独立终止；其他流不受影响 |
| T-124 | 多流含 TID 变更流 | 3 流中 1 流 server_tid_change=true | 12+3+3=18 包 | TID 变更仅影响本流（T-110 口径，含自动追加） |
| T-125 | 多流含重传流 | 3 流中 1 流 retransmit_blocks=[1], blocks_count=2 | 7+3+3=13 包 | 重传仅影响本流（T-117 口径，含自动追加） |

### 7.6 字节精确用例（T-126 ~ T-140）

| 用例 ID | 场景 | 输入 spec 要点 | 期望字节（逐字节核算） |
|---------|------|----------------|------------------------|
| T-126 | RRQ 字节精确 | mode=read, filename=a.bin, transfer_mode=octet | `00 01 61 2e 62 69 6e 00 6f 63 74 65 74 00`（14B：2+6+6） |
| T-127 | WRQ 字节精确 | mode=write, filename=a.bin, transfer_mode=octet | `00 02 61 2e 62 69 6e 00 6f 63 74 65 74 00`（14B） |
| T-128 | OACK 字节精确（blksize） | blksize=1428 | `00 06 62 6c 6b 73 69 7a 65 00 31 34 32 38 00`（15B：2+8+5） |
| T-129 | OACK 字节精确（timeout） | timeout=10 | `00 06 74 69 6d 65 6f 75 74 00 31 30 00`（13B：2+8+3） |
| T-130 | OACK 字节精确（tsize） | server_tsize=2048, mode=read | `00 06 74 73 69 7a 65 00 32 30 34 38 00`（13B：2+6+5） |
| T-131 | OACK 字节精确（windowsize） | windowsize=4 | `00 06 77 69 6e 64 6f 77 73 69 7a 65 00 34 00`（15B：2+11+2） |
| T-132 | DATA 头字节精确 | data_payload_pattern=0xFF, blksize=512 | 头=`00 03 00 01`；Data=512×0xFF（516B 总） |
| T-133 | ACK#0 字节精确 | mode=write, 无选项 | `00 04 00 00`（4B） |
| T-134 | ERROR 字节精确（默认映射） | error_code=1, error_msg="" | `00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00`（19B：2+2+15） |
| T-135 | ERROR code=8 字节精确 | error_code=8, error_msg="" | `00 05 00 08 46 61 69 6c 65 64 20 74 6f 20 6e 65 67 6f 74 69 61 74 65 20 6f 70 74 69 6f 6e 73 00`（32B：2+2+28） |
| T-136 | 多选项 RRQ 字节精确 | mode=read, blksize=512, timeout=5, server_tsize=1024 | `00 01 <file>\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 0\0`（RRQ tsize 恒 "0"） |
| T-137 | 多选项 OACK 字节精确 | 同 T-136 | `00 06 62 6c 6b 73 69 7a 65 00 35 31 32 00 74 69 6d 65 6f 75 74 00 35 00 74 73 69 7a 65 00 31 30 32 34 00`（35B：2+12+10+11） |
| T-138 | 多选项 WRQ 字节精确 | mode=write, blksize=512, timeout=5, client_tsize=1024 | `00 02 <file>\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 1024\0`（WRQ tsize=ClientTSize） |
| T-139 | UDP 数据报长度核算 | blksize=512, blocks_count=1 | DATA 包 UDP Len = 8+516 = 524；RRQ 包 = 8+14 = 22 | 
| T-140 | 末块 0 字节仅头 | client_tsize=512, blocks_count=1, blksize=512 | 自动追加 DATA#2 = `00 03 00 02`（4B，0 字节 Data） |

### 7.7 端到端集成用例（T-141 ~ T-160）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-141 | E2E: Plan → Worker → PCAP（RRQ 短文件） | T-001 spec | PCAP 3 个 UDP 包 | tshark 解析为 TFTP：RRQ → DATA → ACK |
| T-142 | E2E: WRQ + OACK | T-011 spec | PCAP 6 个 UDP 包 | tshark：WRQ → OACK → DATA → ACK → DATA#2(0B) → ACK#2（末块满块自动追加，R1-CRITICAL-3） |
| T-143 | E2E: 错误注入传播 | T-021 spec | PCAP 2 个 UDP 包 | tshark 解析 ERROR ErrCode=1 |
| T-144 | E2E: 多流 → 单 PCAP | T-106 spec | PCAP 9 包按 4-tuple 分 3 组 | tshark 过滤可见 3 个独立 TFTP 会话 |
| T-145 | E2E: windowsize 窗口序列 | T-009 spec | PCAP 15 包 | tshark：4 DATA 后 1 ACK（窗口确认）；末块满块自动追加（R1-CRITICAL-3 修复） |
| T-146 | E2E: 真实 NIC 发送（enp135s0f0np0） | T-001 spec | NIC 发出 3 包 | tcpdump 抓包与生成 PCAP 一致 |
| T-147 | E2E: Validate 错误 → 任务失败 | T-071 spec（filename 空） | 任务 failed | error message 含 "filename is required"；不生成包 |
| T-148 | E2E: UDP 校验和与 IP 头 | T-001 spec | 包可被 tshark 完整解析 | tshark 不报 malformed；checksum 合法（或 offload） |
| T-149 | E2E: TID 变更流 | T-110 spec | PCAP 12 包 | tshark：ERROR(5) 后会话继续（DATA#4 存在）；末块 #4 满块自动追加 DATA#5(0B)/ACK#5（R1-CRITICAL-3）；本流为 trafficgen 扩展行为（非 RFC 标准，与 RFC 1350 合规客户端不可互操作，R2-CRITICAL-1 修复） |
| T-150 | E2E: 重传流 | T-113 spec | PCAP 9 包 | tshark：Block#2 DATA 后跟 ACK#2；末块 #3 满块自动追加（R1-CRITICAL-3） |
| T-151 | E2E: 参考 PCAP 比对（RRQ） | T-001 spec | 与 testdata 参考一致 | 字段级比对（opcode/Block#/ErrMsg/filename/options/Data 长度） |
| T-152 | E2E: 参考 PCAP 比对（多选项） | T-010 spec | 与 testdata 参考一致 | 选项对顺序与值一致 |
| T-153 | E2E: metadata 可观察性 | T-001 spec | PacketConfig.Metadata | 含 tftp_opcode/tftp_block/tftp_filename |
| T-154 | E2E: Direction 标记 | T-001 spec | 包 Direction | RRQ=up, DATA=down, ACK=up |
| T-155 | E2E: FlowSpec.TCP 被拒绝 | tftp + tcp 并存 | Validate 失败 | T-101 错误信息传播到任务 |
| T-156 | E2E: context 取消 | 大 blocks_count + ctx cancel | Plan 协程退出 | 无泄漏（goroutine 及时退出） |
| T-157 | E2E: 65536 块回绕生成 | blocks_count=65536, wrap_block_number=true | 生成 65536 个 DATA（流式，不聚合）+ 自动追加 DATA#65537(0B) | 首包 Block#=1；第 65536 块 Block#=0（回绕）；末块满块 → 自动追加 0 字节末块 Block#=1（wrap=true 合法，§5.1，R1-CRITICAL-3 修复）；**回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅用于字节序列测试，R2-HIGH-3 修复）** |
| T-158 | E2E: blksize=65464 大数据包 | blksize=65464, blocks_count=1 | PCAP 1 个 65468B TFTP 包 | UDP Len=65476 ≤ 65507 |
| T-159 | E2E: 半标准流（无末块，负向互操作） | auto_append_final_block=false, blocks_count=1, blksize=512 | PCAP 3 包 | 无 0 字节末块；**与真实 TFTP 客户端互操作将超时**（R1-CRITICAL-3 修复：明确断言不合规）；仅用于互操作负向测试 |
| T-160 | E2E: PCAP 轮转/文件名 | T-001 spec 多次 | PCAP 文件名含时间戳；轮转正确 | PCAPWriter 集成正常 |

### 7.8 并发正确性用例（T-161 ~ T-175）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-161 | 8 流并发每流 100 块 | 8 流 blocks_count=100 | 8×(1+200+2)=1624 包（每流含自动追加 0 字节末块+ACK） | 每流 Block# 严格 1..100 递增；跨流不串扰；-race clean；末块 #100 满块 → 自动追加（R1-CRITICAL-3 修复） |
| T-162 | 共享 Pacer 限速 | 8 流 + bps="1M" | 聚合吞吐 ≤ 1 Mbps | 实测 ≤ 1.05 Mbps（5% 容差） |
| T-163 | 并发 Plan 同 spec 确定性 | 8 goroutine 同 spec | 8 份包序列字节相同 | ServerTID 确定性（FNV-1a）无竞态；**依赖 FlowID 构成不变**（S12：`<src_ip>-<dst_ip>-<src_port>-<dst_port>`，无时间戳/随机后缀；若引擎层 FlowID 构成变化需同步本用例，R1-LOW-6 修复） |
| T-164 | 并发 Plan 不同 spec | 8 goroutine 8 个 spec | 8 份独立序列 | 无串扰；FlowID 唯一 |
| T-165 | 并发 + context 取消 | 8 goroutine + 中途 cancel | 全部退出 | -race clean；无 goroutine 泄漏 |
| T-166 | 共享 ServerTID 分配互斥 | 8 流 server_tid=0 | 8 个互异 TID（batch 内冲突检测） | 冲突时报错（S12）或重散列 |
| T-167 | 窗口模式并发正确性 | 8 流 windowsize=4 | 每流窗口结构正确 | ACK 块号=窗口末块；跨流不串扰 |
| T-168 | 多流重传并发 | 8 流 retransmit_blocks=[2] | 每流重传序列正确 | 重传仅出现在本流 |
| T-169 | 多流 TID 变更并发 | 8 流 server_tid_change=true | 每流 ERROR(5) 序列正确 | ERROR 方向/DstPort 正确（trafficgen 扩展 TID 迁移语义，R2-CRITICAL-1 修复：删除 RFC 1783 引用） |
| T-170 | 高并发 Plan 无死锁 | 16 goroutine | 全部完成 | 无超时；-race clean |
| T-171 | worker 消费速率 | 大 blocks_count 流经 worker | 无队列积压死锁 | 生产者-消费者稳定 |
| T-172 | 并发 Validate | 8 goroutine 同非法 spec | 8 个相同错误 | Validate 幂等无竞态 |
| T-173 | 并发 Validate + Plan | 混合 4 合法 + 4 非法 | 合法生成、非法报错 | 无交叉影响 |
| T-174 | 包序号连续性（多 worker） | 8 worker 1 流 1000 块 | PacketIndex 全局连续 | resequencer 正确（引擎层） |
| T-175 | 多流同 filename | 3 流同 filename=x.bin | 3 独立会话 | FlowID 区分（端口不同） |

### 7.9 选项组合矩阵用例（T-176 ~ T-205）

覆盖所有选项组合与状态机分支组合（2^4 = 16 种选项组合 × 关键状态分支）：

| 用例 ID | 场景 | 选项组合 | 期望包序列要点 |
|---------|------|----------|----------------|
| T-176 | 全选项（RRQ） | blksize+timeout+tsize+windowsize | RRQ → OACK(4 选项) → ACK#0 → 窗口 DATA → ... |
| T-177 | 全选项（WRQ） | blksize+timeout+tsize+windowsize | WRQ → OACK(4 选项) → DATA#1...（无 ACK#0） |
| T-178 | blksize+timeout | 仅两选项 | RRQ → OACK(2) → ACK#0 → DATA |
| T-179 | blksize+tsize | 仅两选项 | RRQ → OACK(2, tsize="0"→ServerTSize) → ACK#0 → DATA |
| T-180 | blksize+windowsize | 仅两选项 | RRQ → OACK(2) → ACK#0 → 窗口 DATA |
| T-181 | timeout+tsize | 仅两选项 | RRQ → OACK(2) → ACK#0 → DATA |
| T-182 | timeout+windowsize | 仅两选项 | RRQ → OACK(2) → ACK#0 → 窗口 DATA |
| T-183 | tsize+windowsize | 仅两选项 | RRQ → OACK(2) → ACK#0 → 窗口 DATA + 自动追加 |
| T-184 | 单选项 blksize（WRQ） | 仅 blksize | WRQ → OACK(1) → DATA#1（无 ACK#0） |
| T-185 | 单选项 timeout（WRQ） | 仅 timeout | WRQ → OACK(1) → DATA#1（无 ACK#0） |
| T-186 | 单选项 tsize（WRQ） | 仅 tsize | WRQ → OACK(1) → DATA#1（无 ACK#0） |
| T-187 | 单选项 windowsize（WRQ） | 仅 windowsize | WRQ → OACK(1) → DATA#1..（窗口）（无 ACK#0） |
| T-188 | 选项 + IncludeOACK=false | 任一选项 + include_oack=false | OACK 仍出现（选项触发） |
| T-189 | 无选项 + IncludeOACK=true | 无选项 + include_oack=true | 空 OACK `00 06` |
| T-190 | 选项 + ErrorAfterBlock=0 | blksize + error_code=1 | RRQ → OACK → ERROR(1)（无 ACK#0） |
| T-191 | 选项 + ErrorAfterBlock>0 | blksize + error_code=2 + error_after_block=1 | RRQ → OACK → ACK#0 → DATA#1/ACK#1 → ERROR(2) |
| T-192 | 选项 + RetransmitBlocks | blksize + retransmit_blocks=[1] | RRQ → OACK → ACK#0 → DATA#1(重传)/ACK#1 → ...（末块满块自动追加） | 重传与自动追加共存（末块满块时追加，§5.1） |
| T-193 | 选项 + FinalBlockZero | blksize + final_block_zero=true | RRQ → OACK → ACK#0 → ... → DATA#N(0B)/ACK#N |
| T-194 | 选项 + AutoAppendFinalBlock=false | blksize + auto_append=false | OACK 后正常块；无自动追加 |
| T-195 | 全选项 + 自动追加 | 4 选项 + client_tsize 判定 | 窗口 + 0 字节末块 |
| T-196 | 全选项 + 重传 + ERROR | 4 选项 + retransmit + error | 完整异常组合序列 |
| T-197 | blksize=8 + windowsize=2 | 极小块 + 窗口 | DATA 8B×2 → ACK#2 + 自动追加 DATA#3(0B)/ACK#3 | 末块 #2 满块（8B）→ 自动追加（§5.1） |
| T-198 | blksize=65464 + windowsize=2 | 极大块 + 窗口 | DATA 65464B×2 → ACK#2 + 自动追加 DATA#3(0B)/ACK#3 | 末块 #2 满块（65464B）→ 自动追加（§5.1） |
| T-199 | 选项顺序固定性 | 任意顺序输入字段 | 输出顺序恒 blksize→timeout→tsize→windowsize |
| T-200 | OACK 选项顺序与 RRQ 一致 | 4 选项 | OACK 顺序与 RRQ 相同（§4.4） |
| T-201 | windowsize=1 与无选项等价 | windowsize=1 vs 无选项 | 包序列相同（RFC 7440）+ 各自末块满块自动追加 | windowsize=1 等价于锁步（RFC 7440）；满块自动追加规则对两者一致（§5.1） |
| T-202 | windowsize=65535（最大） | windowsize=65535, blocks_count=70000, wrap=true | 窗口 65535 块；ACK#65535；次窗口 4465 块 | S13d/§3.3：70000-65535=4465（R1-HIGH-3 修复）；次窗口块号 65536..70000（回绕后 0..4464），末块满块 → 自动追加 DATA#4466(0B)/ACK#4466；**回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅用于字节序列测试，R2-HIGH-3 修复）** |
| T-203 | windowsize=65535 + 回绕 | windowsize=65535, blocks_count=131070, wrap=true | 块号回绕跨窗口 | §3.3/§3.9：第一窗口块 1..65535（Block# 1..65535）；第二窗口块 65536..131070（Block# 0..65534）；ACK 确认窗口末块 Block#（首窗口 ACK#65535、次窗口 ACK#65534）；窗口边界与回绕交互规则见 §3.9（R1-MED-4 修复）；**回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅用于字节序列测试，R2-HIGH-3 修复）** |
| T-204 | tsize + windowsize 自动追加边界 | windowsize=2, blocks_count=4, client_tsize=2048 | 末窗口后 0 字节末块（判定 TSize 与窗口无关） |
| T-205 | 全选项 + TID 变更 | 4 选项 + server_tid_change | OACK 用旧 TID；DATA#3 起新 TID；ERROR(5) up（trafficgen 扩展迁移语义，非任何 RFC 标准，R2-CRITICAL-1 修复） | 选项协商与 TID 迁移叠加；末块满块自动追加（§5.1）；**回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅用于字节序列测试，R2-HIGH-3 修复）** |

### 7.10 协议交互与互操作用例（T-206 ~ T-221）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言 |
|---------|------|----------------|------|------|
| T-206 | 真实 tftp 客户端互操作（下载） | 生成 RRQ 流 | 真实 tftp 服务器可应答 | 对端 tftpd 完成传输（若可部署）或包结构合规 |
| T-207 | 真实 tftp 服务器互操作（上传） | 生成 WRQ 流 | 真实 tftp 服务器可接收 | 同上 |
| T-208 | tshark 协议识别 | 各正向 spec | tshark 报 tftp 协议 | 不报 malformed |
| T-209 | tshark 选项解析 | T-010 spec | tshark 显示 blksize/timeout/tsize 选项 | 选项名值正确 |
| T-210 | tshark 错误码解析 | T-021 spec | tshark 显示 error code 1 | ErrCode 字段正确 |
| T-211 | tshark windowsize 解析 | T-009 spec | tshark 显示 windowsize 选项 | 值=4 |
| T-212 | PCAP 重放一致性 | 生成 PCAP 后重放 | 重放包与生成包一致 | 引擎 replay 集成 |
| T-213 | VLAN 封装共存 | tftp + vlan_id | 包含 VLAN 头 | L2 封装不影响 TFTP 载荷 |
| T-214 | GRE/PPPoE/MPLS 共存 | tftp + 隧道封装 | 包含隧道头 | 载荷字节不变 |
| T-215 | 与 DNS 流并发 | tftp + dns 混合 | 互不干扰 | 各自协议字节正确 |
| T-216 | 多任务混合流量 | 3 任务（tftp+dns+udp） | 任务隔离 | 各任务包正确 |
| T-217 | UDP 4-tuple 唯一性 | 同批次 100 流 | 100 个唯一 4-tuple | 无 TID 冲突 |
| T-218 | 大文件模拟（内存约束） | blocks_count=100000, wrap_block_number=true（流式） | 不聚合内存 | 峰值内存稳定（流式生成）；末块 #100000 满块 → 自动追加 DATA#100001(0B)（wrap=true 合法，§5.1） |
| T-219 | 方向统计 | RRQ 流 | up/down 计数正确 | up=1+N(ACK)+1(末块 ACK), down=N(DATA)+1(0 字节末块)（末块满块自动追加时，R1-CRITICAL-3） |
| T-220 | 速率控制 | bps 限速下 1000 块 | 聚合速率达标 | ≤1.05×bps |
| T-221 | 服务器端口非 69（显式） | dst_port=1069 | RRQ 发往 1069 | T-103 延伸：后续 DATA 用 TID 而非 1069 |

### 7.11 回归与审计追踪用例（T-222 ~ T-241）

| 用例 ID | 场景 | 输入 spec 要点 | 期望 | 断言（对应审计修复） |
|---------|------|----------------|------|----------------------|
| T-222 | BlocksCount=65536 可解析 | blocks_count=65536, wrap_block_number=true | 正常生成（short-circuit） | **C1 修复**：uint32 字段；JSON 解析不报错；Validate 通过 |
| T-223 | BlocksCount=65536 未开 wrap 拒绝 | blocks_count=65536, wrap_block_number=false | Validate 报错 | C1：错误信息 `exceeds uint16 max` 由 Validate 给出（非 JSON unmarshal 错误） |
| T-224 | RRQ + client_tsize 触发自动追加 | mode=read, client_tsize=1024, blocks_count=2 | 自动追加 DATA#3(0B) | **C2 修复**：判定 TSize = ClientTSize（非零者优先，RRQ 与 WRQ 统一） |
| T-225 | RRQ + server_tsize 触发自动追加 | mode=read, server_tsize=1024, blocks_count=2 | 自动追加 DATA#3(0B) | C2：判定 TSize = ServerTSize（ClientTSize=0 时） |
| T-226 | RRQ + 双 tsize 非零 | mode=read, client_tsize=512, server_tsize=1024, blocks_count=1 | 自动追加 DATA#2(0B)（1×512=512=ClientTSize） | C2：ClientTSize 优先判定；RRQ 报文 tsize 仍 "0"；OACK 回 ServerTSize |
| T-227 | ErrorCode=0 + ErrorAfterBlock>0 注入 code=0 | error_code=0, error_after_block=1, error_msg="" | RRQ → DATA#1/ACK#1 → ERROR(0, "Not defined")（4 包） | **C3/R1-CRITICAL-2 修复**：ErrorCode=0 + ErrorAfterBlock>0 → 注入 ErrCode=0（默认映射 "Not defined"）；语义精确化：注入与否由 ErrorAfterBlock 表达，ErrorCode=0 不再是"不注入"开关（§5 struct 统一语义） |
| T-228 | ErrorCode=0 + ErrorAfterBlock=0 不注入 | error_code=0, error_after_block=0 | 正常传输（无 ERROR） | C3/R1-CRITICAL-2：ErrorCode=0 + ErrorAfterBlock=0 无注入点不注入（json omitempty 下与"未设置"不可区分） |
| T-229 | ERROR code=5 不终止（TID 场景） | T-110 spec | 10 包迁移序列 + 自动追加 2 包 = 12 包全序列 | **C4 修复**：§4.3 例外成立（trafficgen 扩展 TID 迁移语义，非任何 RFC 标准，R2-CRITICAL-1/2 修复：删除 RFC 1783 引用）；ERROR(5) 后继续 |
| T-230 | ERROR code=5 终止（普通注入） | error_code=5, error_after_block=1 | ERROR(5) 后终止 | C4：非 TID 校验场景仍终止 |
| T-231 | 重传时序合规（S10） | retransmit_blocks=[2], blocks_count=3 | DATA#2 仅重传版本 1 次，前无原 ACK#2 | **C5 修复**：符合 RFC 1350 §6 时序 |
| T-232 | windowsize 引用统一 RFC 7440 | 文档一致性 | 全文无 RFC 3625 引用 | **H1 修复**：仅引用 RFC 7440 |
| T-233 | 错误码 8 注入与映射 | error_code=8, error_msg="" | ERROR(8, "Failed to negotiate options") | **H2 修复**：Validate 上限 0-8；映射表含 code=8 |
| T-234 | filename 255 字节边界 | filename=255×'a' | 生成正常 | **H3 修复**：255B 为 trafficgen 限制（非 UDP 上限）；256B 报错 |
| T-235 | IncludeOACK 空 OACK 字节 | include_oack=true | OACK = `00 06`（2 字节） | **H4/L1 修复** |
| T-236 | T62 场景修正（RRQ 合法） | mode=read, client_tsize=1024, final_block_zero=true, blocks_count=3 | DATA#3(0B)；无 DATA#4 | **H5 修复**：RRQ+client_tsize 合法（判定规则统一） |
| T-237 | RRQ tsize 发送规则 | mode=read, client_tsize=0, server_tsize=2048 | RRQ 含 `tsize\0 0\0` | **H6 修复**：ServerTSize>0 触发发送，值恒 "0" |
| T-238 | mode 大小写不敏感 | mode="READ", transfer_mode="NetAscii" | 接受并归一为小写 | **M1 修复** |
| T-239 | ServerTIDChange + ErrorCode=0 合法 | server_tid_change=true, error_code=0 | 通过 | **M3 修复** |
| T-240 | ErrMsg 默认映射条件 | error_code=0, error_msg="", error_after_block=1 | ERROR(0) 的 ErrMsg="Not defined" | **M4 修复**：ErrorMsg=="" 即映射（含 code=0）；error_after_block=1 触发注入（R1-CRITICAL-2：ErrorCode=0 单独不触发注入） |
| T-241 | Validate 端口范围一致性 | server_tid=4000（注册端口） | 通过（1024-65535） | **M2/M7 修复**：Validate 允许 1024-65535；默认生成 49152-65535 |

**用例总数：241 条**（T-001 ~ T-241），覆盖：正向 20 + 负向错误注入 20 + 边界 30 + Validate 拒绝 35 + 多流/异常 20 + 字节精确 15 + E2E 20 + 并发 15 + 选项组合矩阵 30 + 协议交互 16 + 回归审计 20。

---


## §8 Validate 规则

`Validate(spec core.FlowSpec) error` 在 Plan 之前执行；错误类返回 error（任务失败），警告类通过 Report 记录（任务继续）。字段默认化（§5.1）在 Validate 内完成（user-provided > derived > zero）。

### 8.1 字段校验规则表

| # | 字段 | 规则 | 错误信息（错误类）/ 警告（警告类） |
|---|------|------|-------------------------------------|
| V1 | Mode | 空→"read"；大小写不敏感归一；非法值拒绝 | `tftp: invalid mode "<v>" (must be read or write)` |
| V2 | TransferMode | 空→"octet"；大小写不敏感归一；`mail` 拒绝；非法值拒绝 | `tftp: invalid transfer_mode "<v>" (must be netascii or octet)`；`tftp: transfer_mode "mail" is deprecated and unsupported` |
| V3 | Filename | 非空；不含 `\0`；≤ 255 字节（trafficgen 限制，H3 修复） | `tftp: filename is required`；`tftp: filename must not contain null byte`；`tftp: filename exceeds 255 bytes` |
| V4 | BlkSize | 0 或 8-65464（RFC 2348） | `tftp: blksize <N> out of range (8-65464)` |
| V5 | Timeout | 0 或 1-255（RFC 2349） | `tftp: timeout <N> out of range (1-255)` |
| V6 | WindowSize | 0 或 1-65535（RFC 7440） | `tftp: windowsize <N> out of range (1-65535)` |
| V7 | ClientTSize/ServerTSize | uint32（0-2^32-1）；无额外约束 | — |
| V8 | ErrorCode | 0-8（RFC 1350 + RFC 2347 code=8，H2 修复） | `tftp: error_code <N> out of range (0-8)` |
| V9 | ErrorAfterBlock | 0 + ErrorCode=0 时不注入（json omitempty 下零值与未设置不可区分）；ErrorCode>0 或 (ErrorCode=0 + ErrorAfterBlock>0) 时要求 BlocksCount 显式设且 ErrorAfterBlock ≤ BlocksCount；要求 payload 源 | `tftp: error_after_block <N> exceeds blocks_count <N>`；`tftp: error_after_block requires explicit blocks_count (cannot derive)`；`tftp: error_after_block requires data_payload_pattern or payload source` |
| V10 | ErrorSide | 空→"server"；非法值拒绝 | `tftp: invalid error_side "<v>" (must be server or client)` |
| V11 | ServerTID | 0 或 1024-65535（排除知名端口） | `tftp: server_tid <N> in well-known range (<1024)` |
| V12 | ServerTIDNew | ServerTIDChange=false 时忽略；true 时 1024-65535 且 ≠ ServerTID | `tftp: server_tid_new <N> in well-known range (<1024)`；`tftp: server_tid_new must differ from server_tid` |
| V13 | ServerTIDChangeAtBlock | ServerTIDChange=true 时 ≥1 且 ≤ BlocksCount | `tftp: server_tid_change_at_block must be >= 1`；`tftp: server_tid_change_at_block <N> out of range` |
| V14 | RetransmitBlocks | 每项 1-65535 且 ≤ BlocksCount；与 ServerTIDChange 互斥 | `tftp: retransmit_blocks entry <N> out of range`；`tftp: server_tid_change and retransmit_blocks are mutually exclusive` |
| V15 | ServerTIDChange × ErrorCode | ErrorCode>0 时互斥（ErrorCode=0 不触发，M3 修复） | `tftp: server_tid_change and error_code are mutually exclusive` |
| V16 | BlocksCount | uint32；0=derive（需 payload 源）；>0 时若 >65535 要求 WrapBlockNumber=true | `tftp: blocks_count=0 requires data_payload_pattern or payload source`；`tftp: blocks_count <N> exceeds uint16 max (set wrap_block_number=true to allow)` |
| V17 | WrapBlockNumber | bool；false 时 BlocksCount ≤ 65535；true 时 Block# = (i mod 65536) | 见 V16 |
| V18 | AutoAppendFinalBlock | nil→true；自动追加判定见 §5.1；判定后实际块数 >65535 且未开 wrap → 错误 | `tftp: auto-append pushes blocks_count to 65536, set wrap_block_number=true` |
| V19 | FinalBlockZero | true 时 BlocksCount ≥ 1（不允许 derive） | `tftp: final_block_zero requires blocks_count >= 1 (cannot derive)` |
| V20 | 跨协议互斥 | TFTP 流禁止 TCP/HTTP/DNS/FTP/ICMP/SCTP 等字段 | `tftp: <field> field must not be set (TFTP is UDP-only)` |
| V21 | TFTPConfig 存在性 | MapToFlow 命中 tftp case 但 TFTPConfig=nil | `tftp: TFTPConfig is required` |
| V22 | batch 内 ServerTID 唯一 | 同 batch 两流 ServerTID 相同（显式或推导） | `tftp: server_tid <N> conflicts with another flow in the same batch` |
| V23 | 请求包 512 字节上限 | RRQ/WRQ 超 512 字节 | 警告类 Report（RFC 2347 max request 512 octets；trafficgen 不截断） |
| V24 | tsize 与 BlocksCount×BlkSize 一致性 | 判定TSize ≠ BlocksCount×BlkSize | 警告类 Report（不失败；自动追加按判定 TSize） |
| V25 | DataPayloadPattern 长度 | 任意；循环填充；空 + BlocksCount=0 需 payload 源 | 见 V16/V9 |

### 8.2 默认化与归一化

- 字符串字段（Mode/TransferMode/ErrorSide）：空 → 默认值；非空 → 小写归一（RFC 1350/2347 大小写不敏感，M1 修复）。
- 选项顺序：planner 固定输出 `blksize → timeout → tsize → windowsize`（§5.2），与输入顺序无关。
- 所有错误信息带 `tftp:` 前缀，便于任务失败日志定位。

### 8.3 Validate 执行顺序

1. TFTPConfig 存在性（V21）→ 2. 跨协议互斥（V20）→ 3. 字符串归一（V1/V2/V10）→ 4. 数值范围（V4-V8/V11/V12）→ 5. 组合规则（V9/V13-V15）→ 6. BlocksCount 推导与上限（V16-V19）→ 7. batch 级检查（V22）→ 8. 警告类（V23/V24）。

---

## §9 错误处理

### 9.1 Validate 错误传播

- Validate 返回 error → 任务状态 = failed，错误信息含 `tftp:` 前缀与具体字段（S14 全表）。
- 不生成任何包（Plan 不被调用）。
- MCP 层（`generate_traffic`）透传错误信息。

### 9.2 ERROR 注入（协议级错误）

| 场景 | 机制 | 后续行为 |
|------|------|----------|
| 文件不存在等（code 1-4, 6-8） | ErrorCode 注入于 ErrorAfterBlock | 终止（不再生成包） |
| code=0（Not defined） | ErrorCode=0 + ErrorAfterBlock>0 时注入 ErrCode=0（"Not defined" 默认映射）；ErrorCode=0 + ErrorAfterBlock=0 时不注入（R1-CRITICAL-2 统一语义，见 §5 struct） | 终止 |
| code=5（Unknown TID） | 两种语义：普通注入=终止；ServerTIDChange 场景=不终止（§4.3 例外，C4 修复；trafficgen 扩展行为，非任何 RFC 标准，R2-CRITICAL-1/2 修复） | 见 S9 |
| 客户端拒绝 OACK | code=8 + error_after_block=0 + error_side=client（RFC 2347 §2 完整流程） | 终止 |

### 9.3 错误消息处理

- `ErrorMsg == ""` → §5.4 默认映射（含 code=0/8）。
- `ErrorMsg` 非空 → 覆盖默认；截断到 255 字节 + `\0`（T-028）。
- 空 ErrMsg（仅 `\0`，即 1 字节终止符）无法通过 ErrorMsg 字段表达——`ErrorMsg == ""` 触发默认映射（§5.4），而 ErrorMsg 字段值不可包含 `\0`（否则编码后会与字段终止符叠加产生双 `\0`）。Validate 拒绝含 `\0` 的 ErrorMsg：`tftp: error_msg must not contain null byte`。

### 9.4 半标准流生成（负向测试）

默认配置（AutoAppendFinalBlock=true）下，只要末块是满块（Data 长度 == BlkSize）planner 就追加 0 字节终止块（§5.1），产出 RFC 1350 §6 合规流。以下组合显式产出**不合规**流（无结束标记，真实 TFTP 客户端与之互操作将永久等待下一块）：

| 组合 | 效果 |
|------|------|
| auto_append_final_block=false | 无 0 字节末块（文件整数倍时不发终止块；末块满块时流无结束标记） |
| final_block_zero=false + auto_append=false | 末块满 blksize（无结束标记） |
| wrap_block_number=false + blocks_count>65535 | Validate 拒绝 |
| ErrorAfterBlock == BlocksCount（末块后注入 ERROR）| ERROR 抑制自动追加（ERROR 已终止传输，不再生成 0 字节末块；R2-HIGH-2/MED-3 修复，见 §5.3） |

---

## §10 扩展字段映射

### 10.1 FlowSpec → PacketConfig 映射表

| FlowSpec 字段 | PacketConfig 字段 | 转换规则 |
|---------------|-------------------|----------|
| SrcIP/DstIP | L3.SrcIP/DstIP | 直接复制 |
| SrcPort | L4.SrcPort | RRQ/WRQ 及后续所有包（客户端端口不变） |
| DstPort | L4.DstPort | RRQ/WRQ=69（或显式值）；其余=ServerTID（或 ServerTIDNew） |
| TTL/TOS/DSCP/ECN | L3 对应字段 | 直接复制（TTL 默认 64） |
| SrcMAC/DstMAC/VLAN | L2 对应字段 | 直接复制 |
| TFTP.Mode | Payload opcode | read→1, write→2 |
| TFTP.Filename | Payload filename 字段 | 仅 RRQ/WRQ |
| TFTP.TransferMode | Payload mode 字段 | 仅 RRQ/WRQ；小写归一 |
| TFTP.BlkSize/Timeout/ClientTSize/ServerTSize/WindowSize | Payload 选项对 | RRQ/WRQ + OACK（§5.2 顺序与规则） |
| TFTP.ServerTID | L4.SrcPort/DstPort | OACK/DATA/ACK/ERROR 阶段 |
| TFTP.ServerTIDNew | L4.SrcPort（down）/DstPort（up） | ServerTIDChangeAtBlock 起 |
| TFTP.ErrorCode/ErrorMsg | Payload ERROR 包 | ErrorAfterBlock 处注入 |
| TFTP.BlocksCount/DataPayloadPattern | Payload DATA 块 | 块填充与计数 |

### 10.2 Metadata

每个 PacketConfig 携带：`{"tftp_opcode": <int>, "tftp_block": <int>, "tftp_filename": <string>}`；ServerTIDChange 场景追加 `"tftp_server_tid_new": <int>`。

### 10.3 Direction 规则

| 包 | RRQ 模式 | WRQ 模式 |
|----|----------|----------|
| RRQ/WRQ | up | up |
| OACK | down | down |
| ACK#0（OACK 确认） | up（客户端发） | —（无） |
| ACK#0（WRQ 无选项） | — | down（服务器发） |
| DATA | down | up |
| ACK | up | down |
| ERROR | 依 ErrorSide | 依 ErrorSide |

### 10.4 集成点

| 集成点 | 文件 | 改动 |
|--------|------|------|
| Config 结构 | `trafficgen/internal/core/types.go` | 新增 `TFTPConfig`（含 WindowSize 字段）；`FlowSpec.TFTP *TFTPConfig` |
| Strategy 解析 | `trafficgen/internal/core/strategy_convert.go` | 新增 `convertTFTP`（含 windowsize 解析） |
| Planner 注册 | `trafficgen/internal/core/engine.go` | 注册 `tftp.NewPlanner()` |
| Planner 实现 | `trafficgen/internal/protocol/tftp/tftp.go` | 新建包，实现 Validate/Plan |
| Builder | `trafficgen/internal/core/builder.go` | 无需改动（UDP 构建已存在） |
| MapToFlow | `strategy_convert.go` + `maptoflow_test.go` | `"tftp"` case 调用 `convertTFTP` |

### 10.5 测试文件布局

| 测试文件 | 内容 |
|----------|------|
| `tftp_test.go` | Validate（T-071~T-105）+ 包序列（T-001~T-040） |
| `tftp_byte_test.go` | 字节精确（T-126~T-140） |
| `tftp_options_test.go` | 选项协商（T-005~T-011, T-176~T-205） |
| `tftp_window_test.go` | windowsize 窗口序列（T-009, T-118~T-122, T-202~T-204） |
| `tftp_error_test.go` | 错误注入（T-021~T-040, T-227~T-230） |
| `tftp_multiflow_test.go` | 多流（T-106~T-109, T-161~T-175） |
| `tftp_anomaly_test.go` | TID 变更 + 重传（T-110~T-117, T-229, T-231） |
| `tftp_e2e_test.go` | E2E（T-141~T-160） |

---

## §11 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| v1.0 | 2026-08-03 | 初始版本 |
| v1.1 | 2026-08-03 | 修复 v1.0 对抗审计 35 个问题（8 CRITICAL + 10 HIGH + 10 MEDIUM + 7 LOW） |
| v2.0.0 | 2026-08-05 | **基于 RFC 官方规范全文重写**：修复 v1.1 深度对抗审计（06-tftp-audit-deep.md）全部 24 个问题（5 CRITICAL + 6 HIGH + 7 MEDIUM + 6 LOW）；新增 windowsize（RFC 7440）完整实现；测试用例 84 → 241；HexDump 场景 15 个 |
| v2.0.1 | 2026-08-05 | **修复 v2.0.0 复审审计（06-tftp-audit-r1-v2.md）17 个问题**（3 CRITICAL + 5 HIGH + 6 MEDIUM + 3 LOW）：S9 引入 RFC 1783 TID 迁移语义；ErrorCode=0 语义统一；AutoAppendFinalBlock 改为"末块满块即追加"；§5.4 表 9 行字节数修正；T-202/T-120 算术修正；详见下表 |
| v2.0.2 | 2026-08-05 | **修复 v2.0.1 复审审计（06-tftp-audit-r2-v2.md）11 个问题**（2 CRITICAL + 3 HIGH + 3 MEDIUM + 3 LOW）：**核心阻断项**——删除错误的 RFC 1783 引用（RFC 1783 实际是 "TFTP Blocksize Option"，不含 TID 变更机制，v2.0.1 误引导致 S9 语义基础崩塌）；S9 重新定义为 trafficgen 扩展行为（非任何 RFC 标准）；§4.3 二分法消除；§5.3 新增 ERROR vs AutoAppend 优先级规则；T-105 断言修正；T-065 算术修正（V23 不可达）；§1.1 单位 GB→GiB；详见下表 |

### v2.0.1 审计问题修复明细（06-tftp-audit-r1-v2.md，17 个问题）

**CRITICAL（3）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R1-CRITICAL-1 | S9 TID 变更场景改为引入"RFC 1783 §3 TID 迁移语义"（v2.0.1）——**该修复基于对 RFC 1783 的误解，v2.0.2 已撤回并重新定义为 trafficgen 扩展行为（见 v2.0.2 修订记录 R2-CRITICAL-1）** | §4.3、§5 struct ServerTIDChange、S9、T-110/T-229 |
| R1-CRITICAL-2 | ErrorCode=0 语义统一为：ErrorCode>0 恒注入；ErrorCode=0 + ErrorAfterBlock>0 注入 code=0（ErrorAfterBlock 表达注入意图）；ErrorCode=0 + ErrorAfterBlock=0 不注入。§5 struct 注释、§5.1、§5.3、§5.4、§8.1 V9、§9.2、T-028/T-227/T-228/T-240 六处对齐 | §5 struct、§5.1、§5.3、§5.4、§8.1 V9、§9.2、T-028/T-227/T-228/T-240 |
| R1-CRITICAL-3 | AutoAppendFinalBlock 语义统一为"**末块 Data 长度 == BlkSize 即追加 0 字节终止块**"，与 tsize 判定解耦（无 tsize 满块时默认也追加，兑现"默认 true = RFC 1350 §6 合规"）；T-053/T-062 重分类（默认追加正向 / 显式 auto_append=false 负向）；S4/S6/S9/S10 等场景与 T-005/T-006/T-009/T-011/T-012~T-017/T-041/T-042/T-046/T-047/T-049/T-054~T-057/T-059~T-061/T-110/T-113/T-114/T-117/T-119/T-120/T-124/T-125/T-145/T-150/T-161/T-197/T-198/T-201/T-218 期望包数联动修订 | §5 struct、§5.1、§5.3、§9.4、S3/S4/S6/S9/S10、T-053/T-062/T-159 等 |

**HIGH（5）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R1-HIGH-1 | §5.4 表 "Unknown transfer ID" 字节数 21→**20**；T-027 "21B"→"20B"（ERROR 总长 2+2+20=24B） | §5.4、T-027 |
| R1-HIGH-2 | S9 第 7 行注释改为 RFC 1783 迁移语义（随 R1-CRITICAL-1，v2.0.2 已撤回该 RFC 引用） | S9 |
| R1-HIGH-3 | T-202 次窗口 464→**4465** 块（70000-65535=4465）；补充末块满块自动追加说明 | T-202 |
| R1-HIGH-4 | RFC 7440 末窗口判定（块数 < windowsize）与 S6 默认追加行为统一：末块满块 → 自动追加；S6 13→15 包、T-009/T-145 同步 | S6、T-009/T-145 |
| R1-HIGH-5 | T-120 期望包数 9→**10**（1+1+1+5+2=10，逐包核算） | T-120 |

**MEDIUM（6）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R1-MED-1 | §5.4 表 9 行字节数全修正（12/15/17/33/23/20/20/13/28，原多算 1）；T-025/T-026/T-027 同步 | §5.4、T-025/T-026/T-027 |
| R1-MED-2 | §9.3 删除"用户可设 ErrorMsg="\0" 实现"矛盾表述；明确空 ErrMsg 无法通过字段表达、Validate 拒绝含 `\0` 的 ErrorMsg | §9.3 |
| R1-MED-3 | T-019 输入 blocks_count=3→**2**（client_tsize=1024 使"2×512=1024=判定TSize 但末块非满块 → 自动追加跳过"真正可测） | T-019 |
| R1-MED-4 | §3.9 新增 wrap 与 windowsize 交互规则（窗口内按发送序计、ACK 确认窗口末块 Block#=i mod 65536、回绕 ACK 编号回退属回绕语义自然结果、该组合无互操作性保证仅用于字节序列测试）；T-203 断言明确 | §3.9、T-202/T-203 |
| R1-MED-5 | S6 行 858 与 §5.1 默认追加矛盾消除（随 R1-CRITICAL-3） | S6、T-009 |
| R1-MED-7 | T-065 超限子用例改为 filename=255 + 全 4 选项（原核算总长 521B > 512）触发 V23 警告；删除 filename=500（先触发 V3 错误）——**该算术有误，v2.0.2 已按 R2-LOW-2 重新核算（实际 324B < 512，V23 不可达）** | T-065 |

**LOW（3）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R1-LOW-4 | S13c/T-048 注明末块满块 → 自动追加（需 wrap 或显式 auto_append=false） | S13c、T-048 |
| R1-LOW-5 | §2.4 表加注 ErrMsg netascii 原样写入（CR/LF 转换不适用） | §2.4 |
| R1-LOW-6 | T-163 断言注明依赖 FlowID 构成不变（S12：`<src_ip>-<dst_ip>-<src_port>-<dst_port>`） | T-163 |

（注：部分 v2.0.0 复审项经核实不构成问题，已撤回。）

### v2.0.0 审计问题修复明细

**CRITICAL（5）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| C1 | `BlocksCount` 字段类型 uint16 → **uint32**（0-2^32-1）；65536 可正常 JSON 解析与 Validate；wire Block# 仍 uint16，超限由 WrapBlockNumber 控制回绕 | §5 struct、§5.1、S13d、T-049/T-222/T-223 |
| C2 | 自动追加判定 TSize 统一为 `(ClientTSize>0 ? ClientTSize : ServerTSize)`（非零者优先），RRQ 与 WRQ 同一规则；RRQ 报文 tsize 恒 "0" 与判定相互独立；T62 场景合法 | §5.1、S5、T-224~T-226、T-236 |
| C3 | `ErrorCode=0` 语义明确：**ErrorCode=0 恒注入 ErrCode=0**（"Not defined"，默认映射）；ErrorAfterBlock=0 时无注入点则不注入；删除"0=no injection"歧义与悬空 EmptyErrorCode 引用 | §5 struct 注释、§5.4、S8d、T-227/T-228 |
| C4 | §4.3 明确 ERROR code=5 是唯一不终止传输的错误（RFC 1350）；普通注入 code=5 仍终止；ServerTIDChange 场景（S9）实现"不终止" | §4.3、S9、T-110/T-229/T-230 |
| C5 | 重传时序重写为 RFC 1350 §6 合规语义：`RetransmitBlocks=[N]` = DATA#N 初次发送丢失，仅重传版本出现（重传 DATA 先于其 ACK）；删除"原 DATA+原 ACK → 重传 DATA+重传 ACK"异常序列 | §4.5、S10、T-113、T-231 |

**HIGH（6）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| H1 | windowsize RFC 引用统一为 RFC 7440；删除 RFC 3625 引用 | 文档头、§3.8/3.9、T-232 |
| H2 | 错误码 8（Failed to negotiate options，RFC 2347）加入错误码表；ErrorCode Validate 上限 0-8；默认 ErrMsg 映射补 code=8 | §3.6、§5.4、S8c、T-026/T-135 |
| H3 | Filename 上限表述修正：Max 255 字节为 trafficgen 限制（RFC 1350 未规定上限），非"UDP datagram ceiling" | §3.2、§8.1 V3、T-234 |
| H4 | IncludeOACK 空 OACK 字节注释明确为 `00 06`（2 字节） | §5 struct、T-016/T-064/T-235 |
| H5 | T62 场景修正：RRQ + client_tsize 触发自动追加为合法用法（C2 判定规则统一后不再矛盾） | T-019/T-236 |
| H6 | tsize 发送规则明确：RRQ 模式 `ClientTSize>0 || ServerTSize>0` 时发 `tsize\0 0\0`；WRQ 模式按 §5.2 三种情况 | §5.2、S5、T-057/T-063/T-237 |

**MEDIUM（7）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| M1 | TransferMode/Mode 大小写不敏感（RFC 1350 "any combination of upper and lower case"）；Validate 接受大写，输出统一小写 | §2.3、§8.1 V1/V2、T-013/T-238 |
| M2 | ServerTID/ServerTIDNew 端口范围统一：Validate 允许 1024-65535；默认生成 49152-65535（RFC 6335） | §2.5、§5.1、T-083/T-241 |
| M3 | ServerTIDChange 与 ErrorCode>0 互斥；ErrorCode=0 不触发互斥 | §5.3、T-089~T-091、T-239 |
| M4 | ErrMsg 默认映射条件修正为 `ErrorMsg == ""`（含 ErrorCode=0）；表补 code=8 | §5.4、T-025/T-038/T-240 |
| M5 | BlocksCount 推导规则明确：DataPayloadPattern 非空 → 1 块；否则需 Payload/FileSource → ceil(size/blksize)；两者皆空报错 | §5.1、T-059/T-060/T-097 |
| M6 | §6.2/§6.10.1/T02/T20 的 RRQ+client_tsize 用例经 C2 判定规则统一后合法，全部保留并加注释 | §5.1、S5、T-002/T-043/T-224 |
| M7 | Validate 端口范围与默认值一致化（见 M2） | §8.1 V11/V12 |

**LOW（6）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| L1 | OACK 字节注释 `0006` → `00 06` | §5、T-064/T-235 |
| L2 | §1.1 文件大小上限表述修正：65535×65464 ≈ 3.99 GB（受 tsize uint32 上限 4 GB-1 制约） | §1.1 |
| L3 | §8/F3 类规则补 OACK 场景：ACK#0 是 OACK 确认（RRQ+OACK）或 WRQ 无选项确认的特例 | §3.4、§4.1/4.2 |
| L4 | T25 short-circuit 语义明确：planner 只生成首末包断言（大块数用例），不实际生成全部 | S13c/S13d、T-048/T-049 |
| L5 | 错误码 8 补注释与映射（同 H2） | §3.6、§5.4 |
| L6 | ServerTID 端口范围默认值描述统一（同 M2） | §2.5、§5.1 |

### v2.0.0 新增能力

| 能力 | 说明 | 位置 |
|------|------|------|
| windowsize 完整实现 | WindowSize 字段 + 窗口包序列（连续 N 块 + 窗口末 ACK）+ 末窗口判定 + 窗口与重传/ERROR/自动追加/TID 变更组合 | §3.9、S6、T-009/T-118~T-122/T-202~T-204 |
| 错误码 8 全流程 | Validate 0-8 + 默认映射 + 客户端拒绝 OACK 场景 | §3.6、S8c、T-026/T-035 |
| 重传时序重写 | RFC 1350 §6 合规（丢包语义） | §4.5、S10 |
| 测试用例 84 → 241 | 按 CLAUDE.md §Testing Policy 8 条规则全量扩充：正向 20 + 负向 20 + 边界 30 + Validate 35 + 多流/异常 20 + 字节精确 15 + E2E 20 + 并发 15 + 组合矩阵 30 + 交互 16 + 回归 20 | §7 |
| HexDump 15 场景 | S1-S15 全部逐字节核算（Python 验证字段长度） | §6 |

### v2.0.1 内部一致性自检（R1 复审后）

- 自动追加判定规则唯一：**末块 Data 长度 == BlkSize 即追加 0 字节终止块**（§5.1），与 tsize 判定解耦；S3/S4/S6/S7/S9/S10/S13a/S13e/S15 与 T-005/T-006/T-009/T-053 等全部一致。
- tsize 判定（`(ClientTSize>0 ? ClientTSize : ServerTSize)`）降级为校验/警告用途（V24），不再是自动追加触发条件——§5.1、S5、T-224~T-226 一致。
- ErrorCode 语义唯一：>0 注入；=0 时由 ErrorAfterBlock 表达注入意图（=0 不注入、>0 注入 code=0）；§5 struct、§5.1、§5.3、§5.4、§8.1 V9、§9.2、T-227/T-228 六处一致。
- ERROR code=5 语义唯一：trafficgen 扩展迁移场景（ServerTIDChange=true）不终止（S9，**非任何 RFC 标准**，R2-CRITICAL-1/2 修复：删除 RFC 1783 引用）；普通注入终止（T-030/T-230）；§4.3 明文区分两种语义。
- §5.4 默认 ErrMsg 表 9 行字节数与 S8a-c/T-025~T-027/T-134/T-135 全部一致（12/15/17/33/23/20/20/13/28）。
- 重传语义唯一：丢包式重传（S10），全文无"原包+重传包成对"描述。
- 错误码范围唯一：0-8（§3.6、§5.4、§8.1 V8）。
- 选项顺序唯一：blksize → timeout → tsize → windowsize（§5.2、S7、T-199/T-200）。
- 端口范围唯一：Validate 1024-65535；默认生成 49152-65535（§2.5、§8.1 V11/V12）。

### v2.0.2 审计问题修复明细（06-tftp-audit-r2-v2.md，11 个问题）

v2.0.1 复审（R2）发现 v2.0.1 修复 R1-CRITICAL-1 时引用了错误的 RFC（RFC 1783 实际是 "TFTP Blocksize Option"，不含 TID 变更机制），导致 S9 的整个语义基础崩塌。v2.0.2 修复全部 11 个问题（2 CRITICAL + 3 HIGH + 3 MEDIUM + 3 LOW）。

**CRITICAL（2）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R2-CRITICAL-1 | **删除全部 RFC 1783 引用**（v2.0.1 共 6 处：文档头部规范来源、§4.3、§5 ServerTIDChange 注释、S9 标题与说明、§11 修订记录、§9.2/T-110/T-149/T-169/T-205/T-229 等用例断言）。S9 语义重新定义为"**trafficgen 扩展行为，非任何 RFC 标准**"，明确说明：S9 不符合 RFC 1350 §4 校验语义（RFC 1350 下客户端应丢弃新 TID 的包并向错误源回 ERROR(5) 后继续等待旧 TID 重传，不回 ACK），仅用于生成器字节序列测试（模拟 NAT/中间件导致的 TID 漂移场景），与 RFC 1350 合规客户端不可互操作 | 文档头、§4.3、§5 struct、S9、§9.2、T-110/T-149/T-169/T-205/T-229、§11 修订记录 |
| R2-CRITICAL-2 | 随 R2-CRITICAL-1 一并处理 S9 序列——明确标注"ERROR(5) 发向新 TID 后继续向新 TID 传输"是 trafficgen 自定义 TID 变更行为，不符合 RFC 1350 §4 校验语义，也非任何 RFC 标准。S9 序列保持现状但移入"互操作负向测试"语义（同 §9.4 半标准流分类） | S9 |

**HIGH（3）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R2-HIGH-1 | §4.3 删除"RFC 1783 迁移语义"段落，改为"trafficgen 扩展语义（非任何 RFC 标准）"段落；明确"RFC 1350 校验语义 vs RFC 1783 迁移语义"二分法不成立——只有 RFC 1350 一种语义（向错误源回 ERROR(5) 后丢弃该包、继续旧 TID 传输），ServerTIDChange=true 走的是 trafficgen 扩展行为 | §4.3 |
| R2-HIGH-2 | §5.3 新增"ERROR 注入与自动追加的优先级"规则：`ErrorCode>0` 且 `ErrorAfterBlock == BlocksCount` 且末块为满块时，ERROR 抑制自动追加（ERROR 已终止传输，不生成 0 字节末块）；§5.1 自动追加判定中加注"ERROR 注入时不追加"；T-022/T-034 断言中明确引用该规则 | §5.1、§5.3、T-022/T-034 |
| R2-HIGH-3 | §3.9 将 wrap Block#=0 DATA 互操作性警示移至独立段落，适用于所有 wrap=true 场景（不限于 windowsize>1）；T-049/T-157/T-202/T-203/T-205 用例断言中明确"回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作，仅用于字节序列测试" | §3.9、T-049/T-157/T-202/T-203/T-205 |

**MEDIUM（3）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R2-MED-1 | S9 表标题改为"期望包序列（10 包迁移核心 + 2 包自动追加 = 12 包）"，表内直接列出 DATA#5(0B)/ACK#5 两行（标注"自动追加"），消除"10 包 vs 12 包"口径不一 | S9 |
| R2-MED-3 | §9.4 表格"ErrorCode 注入于末块后"改为"ErrorAfterBlock == BlocksCount（末块后注入 ERROR）"，明确为"末块后"而非"越界"（越界被 V9 拒绝） | §9.4 |
| R2-MED-4 | T-105 断言修正：原"ERROR 抑制自动追加但不抑制显式末块；ERROR 先发则无末块"与实际运行时行为相反——error_after_block=2 < blocks_count=3 时 ERROR 在 DATA#2/ACK#2 后注入、传输终止，DATA#3（显式末块）**不生成**，FinalBlockZero 不生效。改为"Validate 通过（组合合法）；运行时 ERROR 在 DATA#2/ACK#2 后注入，传输终止，DATA#3 不生成（FinalBlockZero 不生效）" | T-105 |

**LOW（3）**：

| ID | 修复要点 | 位置 |
|----|----------|------|
| R2-LOW-1 | §1.1 最大文件大小单位修正：3.99 GB → **3.99 GiB**（4,290,434,040 字节），符合 IEC 60027-2 单位规范（二进制语境用 GiB 而非 GB） | §1.1 |
| R2-LOW-2 | T-065 超限子用例算术错误修正：原"521B > 512"实际为 **324B < 512**（逐字节核算：2+256+6+14+12+17+17=324）；在 filename≤255（V3）+ 4 选项（RFC 2347 每选项仅一次）约束下 RRQ 最大 324B，**V23 警告（>512B）实际不可达**，保留为防御性检查；T-065 超限子用例撤回，改为"324B < 512，通过" | T-065 |
| R2-LOW-3 | §11 修订记录撤回说明简化：原"R1-MED-6/R1-MED-8/R1-LOW-1/2/3 经审计自纠撤回，不构成问题，无需修改。"简化为"部分 v2.0.0 复审项经核实不构成问题，已撤回。"（对实现者无信息量，简化提升文档简洁性） | §11 |

### v2.0.2 内部一致性自检（R2 复审后）

- 全文无作为语义依据的 RFC 1783 引用（v2.0.1 共 6 处已全部删除；仅保留"v2.0.1 曾误引、v2.0.2 已撤回"的历史说明文字）。
- S9 语义明确标注为"trafficgen 扩展行为，非任何 RFC 标准"，并明确不符合 RFC 1350 §4 校验语义。
- §4.3 二分法消除：只有 RFC 1350 一种 TID 校验语义；ServerTIDChange=true 是 trafficgen 扩展。
- §5.3 ERROR vs AutoAppend 优先级规则新增（§5.1/§5.3/T-022/T-034 一致）。
- §9.4 "ErrorAfterBlock == BlocksCount"表述精确（无歧义）。
- T-105 断言与实际运行时行为一致。
- T-065 算术修正后 324B < 512，V23 在 trafficgen 字段约束下不可达（防御性保留）。
- §3.9 wrap Block#=0 DATA 互操作性警示适用于所有 wrap=true 场景（T-049/T-157/T-202/T-203/T-205 断言一致）。
- §1.1 单位统一为 GiB。
- §11 撤回说明简化。

---

**文档结束**。v2.0.2 共 15 个 HexDump 场景（S1-S15）、241 条测试用例（T-001 ~ T-241）、逐字节核算通过（Python 验证 opcode/字符串/数据长度）、修复 v2.0.1 复审审计（06-tftp-audit-r2-v2.md）全部 11 个问题（2 CRITICAL + 3 HIGH + 3 MEDIUM + 3 LOW）；核心阻断项为删除错误的 RFC 1783 引用并重新定义 S9 语义为 trafficgen 扩展行为（非任何 RFC 标准）。

---

# P-PIPE 轮（v2.1.0-P1P3，2026-09-26）：层链契约补件

> 本节（§12–§18）为并发 P-PIPE 管线文档轨 P1–P3 产物。定位：**现状实现的设计契约回填（wire 语义已由 §1–§11 钉死）+ 层链/去扁平缺件补齐**。权威关系（方案 §2 m4）：append 进 `docs/CODE_DESIGN.md` / `docs/TEST_CASES.md` 的条目为唯一权威文本；本文与 `06-tftp-testcase.md` 为**草稿/历史层**。P1–P3 **零代码改动**（禁令：不碰任何 .go / cases/*.json / CODE_DESIGN.md / TEST_CASES.md）。

## §12. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：三张子表——①命令×响应码矩阵（§12.2）②数据形态变体表（§12.3）③商业行为→用例映射表（§12.5）；条目三选一：已实现 / 明确不支持 / 不适用，无留白。

### §12.0 「代码现状」列的口径（实读声明，2026-09-26）

| 事实 | 实读证据 |
|---|---|
| tftp 层已注册、`Fields` 为空 | `registry.go:187-192`（`CategoryTerminal` / `DependsOn ["udp"]` / 无 Fields·FieldContract·TransportOn·OptionalOn）；生成表 `layers.generated.json` 的 `tftp` = `{"category":"terminal","depends_on":["udp"],"fields":{}}`；注册表 `r.Register(LayerSchema` 计数 **123** |
| 层内写业务键**今日直接红** | `complete.go:271-328` 的 `ValidateLayerConfig`（函数 `:279`；未知字段拒 `:293`）：`s.Fields[k]` 未命中即 `layers: layer "tftp": unknown field "…"`（未知字段拒 `:293`） |
| 层 config 翻译**今日零走查** | `chain_planner_translate.go:742-744`：`if len(s.Fields) == 0 { return }` → tftp 层永不被 `translateTerminalConfig`（`:679`）翻译 |
| 配置唯一载体 = 顶层 flat `tftp` 子映射 | `strategy_convert.go:1258-1262`（`case "tftp"` → `parseTFTPConfig` `:7215-7245`）→ `spec.TFTP`（`internal/core/types.go:9195-9327`（`TFTPConfig` 23 个 json 键，`:9326-9327` 结构尾））→ `FlowMeta.TFTP`（`chain_planner_translate.go:69-71`（`TFTP: spec.TFTP` Meta 直传））→ 生成器 `layer_gen.go:34-44`（`cfg := req.Meta.TFTP` `:34` + spec 重组 `:38-44`） |
| 端口 | 目标形状端口住 `udp` 层（`udp` 层 Fields = src_port/dst_port，生成表同）；dst 缺省 69 由 `chain_planner.go:956`（DstPort switch）+ `:701`（`validateBaseDstPortHandled` 名单含 tftp，0 合法）；src 缺省由 `mapToFlowSpec` 的通用缺省 `DefaultSrcPort=12345`（`strategy_convert.go:49`；注入点 `:333`），多流走 worker `12345+i` 保底 |
| 生成器与引擎的关系 | 生成器复用 legacy `Planner.Plan`（`tftp.go:254`）产 `MessageEvent`（`layer_gen.go:30-86`（`Generate` 全函数）），端口已按方向解析 + `L4PortOverride=true` 防 udp 层二次交换（`:82-96`） |
| 存量用例形状 | `cases/tftp.json` **226 例**（实读）：186 正例（全部带 `layers: [{"udp":{}},{"tftp":{}}]` 且**同时带顶层旧键**）+ 40 负例（**全部无 `layers`，纯扁平形**）；顶层键 9 种（见 §13.1 表）。**即：226 例今日经真实流程（MCP `flowb_generate_traffic` → `ValidateStrategy`）全部 400**——`strategy_convert.go:8280-8285`（`CheckProtoFlat` 五键循环）经由 `schema/semantic.go:130` 调用；186 例另有 `schema/semantic.go:172` 调用的 `checkLayerFlatConflict`（`:179-190`）（layers 与顶层四元组并存）双杀。故本文件下方所有「存量用例」列均为**改写后**的承接点（§16/§17 清单）。 |

### §12.1 八项规范矩阵

| # | 规范要求（RFC/官方文档 + 章节） | 业务场景 | 代码现状（链上路经，行号实读） | 缺口 |
|---|---|---|---|---|
| 1 | **连接模型（双阶段 TID 语义）**：客户端向服务器**知名 TID 69** 发 RRQ/WRQ（RFC 1350 §4 "the known TID 69 decimal"）；服务器**换用自己新选的 TID**（临时端口）应答，此后双方只用各自 TID、**不再用 69**；每端校验收到包的**源 TID 是否等于约定 TID**，不匹配则该包"discarded as erroneously sent from somewhere else"并向**错误源**回 ERROR code=5，**不终止**当前传输（RFC 1350 §4："recognizes only one error condition that does not cause termination, the source port of a received packet being incorrect"） | PXE 预启动/嵌入式固件升级/网络设备配置下发；NAT/中间盒导致服务端可见 TID 漂移 | **已实现**：首包 dst=69（`chain_planner.go:956` 默认 + `:701` 0 合法），后续包 src=ServerTID / dst=客户端端口（`tftp.go:280-287`（ServerTID 缺省 `:280-282` / ServerTIDNew 缺省 `:283-287`）；`plan.go:51-53`（请求）/`:64-66`（OACK）/`:91-99`（ACK#0 双分支）/`:129-226`（DATA/ACK 对）逐包按方向写端口）；flowID 四元组 = `plan.go:24`；udp 层每事件一数据报、`L4PortOverride=true` 防二次交换（`layer_gen.go:62-74`（端口已解析 + `L4PortOverride=true`））；TID 变更扩展序列（非 RFC 语义）见 §4.3/S9 | ①RFC 1350 §4 **合规**的"丢包+向错误源回 ERROR(5)+继续旧 TID"序列**不实现**（只有 S9 扩展迁移语义）→ 明确不支持（G-TFTP-6）；②多 TID 并发（多会话）在链上是 `flow_control.flows` + 层动态，一链一流，无同链多 TID 扇出（G-TFTP-3 语境） |
| 2 | **命令/消息表**：6 opcode（RRQ=1/WRQ=2/DATA=3/ACK=4/ERROR=5/OACK=6），每条请求-响应、必选/可选字段（RFC 1350 §4 报文图；RFC 2347 §2 OACK） | 下载（RRQ）/上传（WRQ）/选项协商（OACK）/异常（ERROR） | **已实现（builder 全覆盖）**：`types.go:8-15` 六 opcode 常量；`builder.go:17`（RRQ/WRQ，filename+mode+选项对）、`:47`（DATA，Block#+Data）、`:58`（ACK，Block#）、`:68`（ERROR，ErrCode+ErrMsg）、`:85`（OACK，仅选项对）、`:142`（请求包 512B 上限核算 `validateRRQLength`）；解析器 `parser.go:33` Parse 六分支 | 无（`mail` 传输模式拒收=明确不支持，RFC 1350 已废弃） |
| 3 | **状态机**：RRQ 下载（RRQ→[OACK→ACK#0]→DATA#1/ACK#1→…→末块）、WRQ 上传（WRQ→[OACK→DATA#1 \| ACK#0→DATA#1]→…→末块）、ERROR 终止、OACK 子状态机、超时重传（RFC 1350 §4/§5/§6；RFC 2347 §2；RFC 7440 §3 窗口） | 完整传输/选项协商/中途取消/丢包重传 | **已实现**：`plan.go:15` `emit` 单入口按序编排——①请求 `:52` ②OACK `:57-67` ③请求后立即 ERROR `:73-86` ④ACK#0 双分支（RRQ+OACK 客户端确认 / WRQ 无选项服务器就绪）：`:88-100` ⑤DATA/ACK 对 + 窗口 + 重传 + TID 变更：`:129-226` ⑥自动追加末块 `:226`；默认化与 derive 在 `tftp.go:261-307`（默认化 `:261-287` + derive `:289-297` + autoAppend/errAtLast `:299-305` + chan `:307`） | 服务器侧「部分拒绝选项」（只回显子集）**明确不支持**——OACK 恒回显全部请求选项（§4.4 声明，非缺口） |
| 4 | **字段表**：opcode/Block#/ErrCode = uint16 大端；字符串 = netascii + `\0` 结尾；选项值 = ASCII 数字串；`blksize` 8-65464（RFC 2348 §2）；`timeout` 1-255（RFC 2349 §2）；`windowsize` 1-65535（RFC 7440 §3）；`tsize` 0-2^32-1 | 逐字段抓包校验；跨实现互操作 | **已实现**：`types.go:31-47` 常量域（MinBlkSize 8 / MaxBlkSize 65464 / MinTimeout 1 / MaxTimeout 255 / MinWindowSize 1 / MaxWindowSize 65535 / MaxFilenameBytes 255 / MaxErrMsgBytes 255 / DefaultServerPort 69）；字节序 §2.2（`binary.BigEndian`）；`plan.go:356` `wireBlockNum(i, wrap)` 回绕编码；§5/§6 逐字段 HexDump 已核算 | 无（`Block#` 回绕 RFC 未定义 → trafficgen 扩展语义，§3.3 已声明，互操作负向） |
| 5 | **错误处理表**：9 个错误码（0 Not defined / 1 File not found / 2 Access violation / 3 Disk full / 4 Illegal operation / 5 Unknown TID / 6 File exists / 7 No such user / 8 Option negotiation failed，RFC 1350 §4 + RFC 2347 §2）；ERROR **不被确认、不被重传**；唯一不终止 = code 5 | 文件缺失/权限/磁盘满/选项协商失败/客户端取消 | **已实现**：`types.go:18-28`（9 码）+ `:51-61`（默认 ErrMsg 映射）+ `:65` `DefaultErrMsg`；注入点 `plan.go:73-86`（EAB=0）与 `:117-126`（EAB>0，含"ERROR 抑制自动追加"R2-HIGH-2 语义）；`plan.go:365` `errMsgFor` | code=5 的**双重语义**（RFC 终止 vs S9 扩展不终止）已在 §4.3/§9.2 写死且有例；RFC 合规 TID 校验序列不实现（同 #1 缺口） |
| 6 | **超时与活性**：锁步流控"the lock step acknowledgement provides flow control"；发送方"has to keep just one packet on hand for retransmission"，超时后重传最后一包（RFC 1350 §6） | 丢包重传；长传输（多块）活性 | **部分实现（结构面）**：`retransmit_blocks` 生成"丢包式重传结果序列"（`plan.go:156-200`：仅重传版本出现、重传 DATA 先于其 ACK，RFC 1350 §6 时序合规）；`timeout` 选项**仅语义标记**（`internal/core/types.go:9212-9215` 注释：不按超时实际计时/重传）；无空闲超时/保活字段 | 真实计时重传与超时窗口：**明确不支持/不适用**（字节级生成器无时钟，C 类——旧 §4.5 已声明）；`timeout` 仅参与 OACK 回显 |
| 7 | **NAT/代理/被动模式**：TFTP 无被动模式、无反向连接，客户端恒主动发往 69；NAT 使服务端 TID 在客户端视角漂移 | 企业 NAT/中间盒下的传输中断与恢复 | **扩展实现（非 RFC）**：`server_tid_change` / `server_tid_change_at_block` / `server_tid_new`（`tftp.go:287-289` 确定性生成；`plan.go:129-141`（DATA 循环首 + TID 切换判定）起新 TID；ERROR(5) up 发向新 TID 后继续——**不符合 RFC 1350 §4 校验语义**，§4.3/S9 已声明为 trafficgen 扩展、互操作负向） | 真实 NAT 设备行为无出处（G-TFTP-5）；「代理中继/隧道形」不适用（TFTP 无代理协议面） |
| 8 | **版本/方言差异**：RFC 1350 Rev.2 单一版本；选项扩展 RFC 2347/2348/2349 + RFC 7440（windowsize）；端口注册 RFC 6335（动态/私有范围 49152-65535） | 与各厂商 tftp 客户端/服务器互操作 | **已实现**：选项四键（`types.go:75-89` 固定输出顺序 blksize→timeout→tsize→windowsize）；ServerTID 默认落 RFC 6335 动态范围 49152-65535（`tftp.go:365-376` 的 `deterministicTID`）；显式 TID 允许 1024-65535（`MinEphemeralPort`/`MaxEphemeralPort`） | ①Microsoft `windowsize` 方言（Wireshark 有 `tftp.msftwindow.unrecognized` 字段，实测存在）**明确不支持**；②IPv6 承载（UDP/IPv6 天然支持）**零存量例**（全库 `ipv6` 0 命中）→ A′ 补例（T-TFTP-V6）；③`mail` 模式拒收（正确） |

### §12.2 子表①：命令×响应码矩阵（逐格已覆/缺失）

8 行（6 opcode + DATA 按方向拆两行 + 非法/未知 opcode）× 3 面（正常应答 / 错误应答 / 无应答或异常面）= **24 格**。格子判据：**存量 226 例改写后**的承接（ID 实读，见 §16），非今日可跑状态（今日全红，§12.0）。

| 行（opcode / 方向） | 正常应答面 | 错误应答面（code 0-8） | 无应答 / 异常面 |
|---|---|---|---|
| RRQ（1，up→69） | 已覆（DATA#1 起，`tftp-rrq-short-aa100` 等 95 例 RRQ 族） | 已覆（请求后立即 ERROR：`tftp-rrq-error1-immediate` / `-error2-immediate` / `-error4-default` / `-error7-after-oack`；客户端拒绝 OACK 用 code=8：`tftp-rrq-reject-oack-code8`） | 已覆（重传：`tftp-rrq-retransmit-single` / `-multi` / `-first-block` / `-wire-bytes` / `-timing` / `-tsize-append`；TID 变更：`tftp-rrq-tid-change-12pkts` / `tftp-rrq-all4opts-tidchange`） |
| WRQ（2，up→69） | 已覆（ACK#0 与 OACK 双分支 + DATA#1 起，`tftp-wrq-upload-bb200` 等 21 例 WRQ 族） | 已覆（`tftp-wrq-error3-mid`（EAB>0 中途）/ `tftp-wrq-oack-error6`（OACK 后 code=6）/ `tftp-wrq-error4-client-immediate`（client 侧）） | **缺**（实读：WRQ 方向重传 0 例、WRQ + TID 变更 0 例）→ A′ 补例 T-TFTP-WRQ-RETX / T-TFTP-WRQ-TIDCHG |
| DATA（3，RRQ 方向 down） | 已覆（`tftp-data-header-ff` / `tftp-rrq-single-full-block` / `tftp-rrq-empty-data-tsize512`） | 不适用（DATA 无错误码字段，错误由 ERROR 承载，RFC 1350 §4） | 已覆（重传 DATA 族 6 例 + `tftp-rrq-retransmit-error`） |
| DATA（3，WRQ 方向 up） | 已覆（`tftp-wrq-upload-bb200` / `tftp-wrq-multiblock-append`） | 不适用 | **缺**（WRQ 重传 0 例，同上） |
| ACK（4） | 已覆（`tftp-rrq-winsize1-lockstep` 锁步 ACK；ACK#0 双分支 `tftp-wrq-upload-bb200`（WRQ 无选项）/ `tftp-rrq-blksize-1428`（RRQ+OACK）） | 不适用（ACK 无错误码字段） | 不适用（ACK 由对端 DATA 触发；生成器不模拟 ACK 丢失，重传语义只针对 DATA） |
| OACK（6，down） | 已覆（`tftp-oack-blksize-15b` / `-timeout-13b` / `-tsize-13b` / `-multiopt-35b` / 空 OACK `tftp-rrq-include-oack-empty`） | 已覆（客户端拒绝 → ERROR(8)，`tftp-rrq-reject-oack-code8`） | 已覆（服务器不支持选项协商=省略 OACK 直接 DATA#1/ACK#0：`tftp-rrq-allzero-options-no-oack` / `tftp-rrq-blksize-default-no-option` / `tftp-rrq-timeout-zero-no-option`） |
| ERROR（5） | 已覆（9 码注入 + 默认映射 + 自定义/超长截断：`tftp-rrq-error1-immediate` … `tftp-regress-err8-map` / `-err0-inject` / `-err0-noinject` / `tftp-rrq-error-truncated`） | 不适用（"Error packets are not acknowledged, and not retransmitted"，RFC 1350 §4） | 已覆（**扩展语义**：code=5 不终止，`tftp-rrq-tid-change-12pkts` / `tftp-tidchange-errorcode0`；**RFC 合规序列缺** → G-TFTP-6） |
| 非法/未知 opcode（0/7-65535） | **缺**（生成器无任意 opcode 注入入口，`plan.go` 全文件无 opcode 参数） | **缺**（合法应答应为 ERROR(4) Illegal TFTP operation，无例） | **缺**（应丢弃或回 ERROR(4)，无例）→ 三格同源缺口：需代码改动 → B′ 立项 G-TFTP-3 |

**格数算术**：24 = 已覆 **14** + 缺 **5** + 不适用 **5**（逐行实读核对：RRQ 3 + WRQ 2 + DATA_dn 2 + DATA_up 1 + ACK 1 + OACK 3 + ERROR 2 = 14 已覆；WRQ 1 + DATA_up 1 + 非法 opcode 3 = 5 缺；DATA_dn 1 + DATA_up 1 + ACK 2 + ERROR 1 = 5 不适用）。**按 §9.21 分支级口径**：错误码 0-8 的码值分支已由 RRQ 族 + regress 族全枚举（不逐 opcode × 逐码做笛卡尔）。

### §12.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 代码现状（实读） | 存量承接 / 缺口 |
|---|---|---|---|
| Opcode | 1/2/3/4/5/6 六值 | `types.go:8-15`；`parser.go:33` 六分支 | 已覆（六值各有例；非法 opcode → §12.2 三格缺口 G-TFTP-3） |
| 请求包结构 | filename（≤255B，可含 `/` `\`）+ mode + 选项对；512B 上限 | `builder.go:17` + `:142` `validateRRQLength` | 已覆（`tftp-rrq-14bytes` / `-filename-slash` / `-filename-backslash` / `tftp-regress-filename-255` / `tftp-rrq-max-request-324`） |
| Mode 值域 | read/write，大小写不敏感；他值拒 | `tftp.go:261-264`（mode 归一）+ Validate（`:50` 起） | 已覆（`tftp-rrq-defaults` / `-uppercase-normalize` / `tftp-validate-t073-invalid-mode`） |
| transfer_mode | netascii/octet；mail 拒 | `tftp.go:266-269`（transfer_mode 归一） | 已覆（`tftp-rrq-netascii-hello` / `tftp-validate-t074` / `-t075-mail-deprecated`） |
| 选项组合 | 2^4 = 16 组合（含全零/全四项/空 OACK） | 固定输出顺序 `types.go:75-80`；`buildRequestOptions` `plan.go:396` / `buildOACKOptions` `:427` | 已覆（按 §9.21 分支级口径：零/单/双/三/四选项五档各有例：`-allzero-options-no-oack` / `oack-*` 4 例 / `rrq-blksize-timeout` 等 6 对 / `rrq-3opts-autofull` / `rrq-all4opts`；未做 16 格笛卡尔） |
| 选项顺序 | blksize→timeout→tsize→windowsize 固定 | `types.go:75-80` 顺序常量 | 已覆（`tftp-rrq-optorder-fixed` / `-optorder-oack-match`） |
| 选项值域 | blksize 8/512/65464；timeout 1/10/255；tsize 0/2048/2^32-1；windowsize 1/4/65535 | `types.go:31-47` 边界常量 + Validate | 已覆（`tftp-blksize8-min` / `tftp-blksize65464-max` / `tftp-rrq-timeout-10` / `tftp-rrq-winsize65535-wrap`；负例 `t077`/`t078`/`t079`/`t081`） |
| tsize 发送规则 | RRQ 恒写 `0`；WRQ 写 ClientTSize；ServerTSize 只进 OACK | `plan.go:396-427`（§5.2） | 已覆（`tftp-rrq-tsize-send-rule` / `tftp-wrq-tsize-zero-oack-server` / `tftp-rrq-tsize0-client` / `tftp-rrq-double-tsize` / `tftp-regress-rrq-dual-tsize`） |
| DATA 块大小形态 | 满块 / 末块 < blksize / 0 字节显式末块 / 自动追加 0 字节 | `plan.go:226`（自动追加）+ `plan.go:375` `buildDataPayload`；判定 §5.1 | 已覆（`tftp-rrq-single-full-block` / `tftp-rrq-empty-data-tsize512` / `tftp-final-block-zero` / `tftp-auto-append-off` / `tftp-rrq-finalzero-no-dup-append`） |
| Block# 边界 | 1 / 65535 / 65536 回绕（Block#=0 DATA）/ 追加推越 65535 | `plan.go:356` `wireBlockNum` | 已覆（`tftp-blocks-65535-short` / `tftp-rrq-blocks-65535-head` / `tftp-rrq-blocks65536-parse` / `tftp-regress-blocks-65536-wrap` / `-blocks-wrap-seq` / `tftp-rrq-blksize65535-append-wrap`） |
| 窗口形态 | ws=1 锁步 / ws=4 整窗 / 末窗不足 / ws=65535 跨回绕 / 窗口+重传 / 窗口+ERROR | `plan.go:112-115`（默认 1）+ `:176-200`（窗口边界 ACK） | 已覆（`tftp-rrq-winsize1-lockstep(-explicit)` / `-winsize4-blocks8` / `-winsize4-partial-window` / `-winsize65535-wrap(-2)` / `-winsize4-retransmit` / `-winsize4-error` / `tftp-matrix-blk8-ws2` / `-blk65464-ws2`） |
| 重传形态 | 首块/中块/多块/与 ERROR 组合/字节一致 | `plan.go:156-200` 丢包式重传 | 已覆（10 例：`-retransmit-single` / `-multi` / `-first-block` / `-error` / `-wire-bytes` / `-timing` / `-tsize-append` / `-blksize-retransmit` / `-winsize4-retransmit` / `tftp-rrq-allopts-retransmit-error`；**WRQ 方向 0 例** → A′） |
| ERROR 码面 | 0-8 逐值 + 默认 ErrMsg 逐值 + 自定义 + 超长截断 | `types.go:51-61` 映射 + `plan.go:365` | 已覆（`tftp-error1-19b`（19B 逐字节）/ `tftp-rrq-error{0,1,2,3,4,5,7,8}-*` / `tftp-regress-err8-map` / `tftp-rrq-error-truncated`） |
| ERROR 注入位置/方向 | EAB=0 / EAB=N<bc / EAB=bc（抑制追加）/ client 侧 / 与 FinalBlockZero 并存 | `plan.go:73-86` + `:117-126` | 已覆（`-error1-immediate` / `-error1-after-2` / `tftp-rrq-opts-error1-mid` / `tftp-rrq-error-suppress-append` / `tftp-rrq-error-after-finalzero` / `tftp-rrq-error5-client-terminate` / `tftp-rrq-error0-client`） |
| TID 面 | 显式 / 确定性 FNV-1a / 1024 边界 / batch 冲突 / 变更（扩展） | `tftp.go:280-287`（ServerTID 缺省 `:280-282` / ServerTIDNew 缺省 `:283-287`）+ `:365-399`（`deterministicTID` `:365` / `deterministicTIDNew` `:381`） | 已覆（`tftp-server-tid-explicit` / `-server-tid-1024-boundary` / `tftp-tid-deterministic` / `tftp-tid-conflict-batch`（负）/ `tftp-rrq-tid-change-12pkts`） |
| 四元组与端口 | dst 默认 69 / 显式 1069 / 多流 src 保底 `12345+i` | `chain_planner.go:956` + `:701`；worker 保底注释 `chain_planner.go:894` | 已覆（`tftp-rrq-dstport-1069` / 默认族 / `tftp-multiflow-*`）；**src 端口语义在链上需 P5 校准**（层显式值优先，缺席走通用 12345） |
| 地址族 | IPv4（**IPv6 零存量例**） | `layer_gen.go` 经 udp 层走框架（`udp` 层 DependsOn `ip`；注册表只有 `ip`/`eth` 两个承载层，**无 `ipv6` 层**——IPv6 由 `ip` 层写 v6 字面量表达，hds_ipv6/dns 兜底族同款） | **缺** → A′ 补例 **T-TFTP-V6**（§9.24 对称覆盖） |
| L2/L3 封装共存 | VLAN / GRE 隧道 | 框架层（`vlan` 层 `registry.go:53-60` / `gre` 层） | 已覆（`tftp-rrq-vlan-100` / `tftp-e2e-vlan` / `tftp-e2e-gre`；**须迁 `vlan` 层**，§17） |
| 多流 / 并发 | 2/3/8/100 流；同 filename；跨流不串扰 | 链上一链一流；多流走 `flow_control.flows` + 层动态（`layer_dyn.go:17-23` allowlist ip/tcp/udp/eth） | 已覆（`tftp-multiflow-*` 8 例 + `tftp-concurrent-*` 5 例 + `tftp-e2e-multiflow`；**今日全红**：旧形顶层键 + `flows>1` 面须按 §17 改写为层动态） |

**行数实数：19 行**；**P1–P3 时点已覆 18 行 + 缺 1 行（地址族 IPv6）**；**P5 后 19 行全覆**（地址族由 `tftp-v6-basic` 落位，见 §15.3 P5 后口径）。

### §12.4 三路对照（CORE_MEMORY §4.12–4.15）

| 路 | 内容 | 出处 |
|---|---|---|
| ① 规范原文（定"必须是什么"） | RFC 1350（Rev.2：§4 报文格式与 TID 语义、§5 错误条件、§6 结束判定与重传、§7 无认证声明）；RFC 2347（选项扩展：OACK、每选项仅一次、仅客户端发起、512B 请求上限、code=8）；RFC 2348（blksize 8-65464）；RFC 2349（timeout 1-255、tsize）；RFC 7440（windowsize 1-65535、窗口 ACK、末窗口判定）；RFC 6335（动态端口范围） | 本设计 §2–§6 逐节引用（v2.0.2 口径，逐条标注章节号） |
| ② 现网真跑成什么样 | **诚实缺口（§4.13）**：本设计 v1.0–v2.0.2 四轮修订的证据面全部来自**规范原文 + 本机 tshark 实测**，无商业化产品（tftpd-hpa/atftpd/PXE dnsmasq/厂商客户端）行为出处；本节**不编造**产品行为 | **待确认**：确认方式（三选一）=抓现网 tftp 传输回环包 / 查厂商手册 / 问运维 → G-TFTP-5 立项。仅可代位的实测：本机 **Wireshark 3.6.14 dissector**（见路③）对真实引擎落盘 pcap 的解析（`/tmp/mcp-pcaps/tftp/tftp-rrq-short-aa100.pcap`：3 包 `tftp.opcode`=1/3/4、`tftp.block`=1、`tftp.source_file`=config.txt、`tftp.type`=octet、ServerTID=52994） |
| ③ 可靠开源实现思路 | **Wireshark `packet-tftp.c` dissector**（本机 tshark 3.6.14，`tshark -G fields` 实测 **31** 个 `tftp.*` 字段；dissector 行为探针见下）——作为 wire 裁判与字段命名权威；**RFC 文本内引用**替代二手实现细节（无本地 tftp 实现可比对：`which tftp/atftpd/in.tftpd/tftpd-hpa` 全部零命中，如实记录） | 探针实测（2026-09-26，自构 pcap + `tshark -T fields`）：①**块号回绕**：DATA#65535 → `tftp.block.full`=65535；DATA#0（回绕产物）→ `tftp.block.full`=**65536**（dissector 按回绕补偿，`tftp.block` 仍报 0）——trafficgen 的 wrap 语义可被 dissector 识别，`tftp.block` 与 `tftp.block.full` 两个口径都成立；②**Wireshark 有 `tftp.msftwindow.unrecognized` 字段**（Windows 方言旁证）；③`windowsize=0` → expert 报 `TFTP windowsize out of range`（`tftp.windowsize_range`=1），而 `blksize=70000` **不触发** `tftp.blocksize_range`（该字段用于 DATA 长度 vs 协商值，非选项值域）——即 RFC 2348/7440 值域**不能靠 dissector 兜底**，必须由 Validate 拦；④ERROR 包 → `tftp.error.code`=5 + `tftp.error.message` 明文可见 |

**三路结论一致项**：6 opcode、9 错误码、`\0` 结尾字符串、大端多字节字段、OACK 仅选项对、ACK#0 双分支语义、末块 < blksize 判结束。
**不一致与取舍（§4.15）**：①`retransmit_blocks` 的"丢包式"语义（无原包）是 trafficgen 的**生成器契约**而非 RFC 描述（RFC 只描述发送方行为）——取舍：以 RFC 1350 §6 时序（重传先于其 ACK）为底线、以"接收方可容忍"为准绳，§4.5 已声明；②`server_tid_change`（S9）**不符合 RFC 1350 §4 校验语义**（v2.0.1 的 RFC 1783 引用系虚构，v2.0.2 已撤回）→ 归类为互操作负向扩展，不得计入 RFC 合规覆盖；③`wrap_block_number` 产生的 Block#=0 DATA 在 RFC 1350 §4 下是异常包（DATA 的 Block# 恒 ≥1）→ 仅字节序列测试，dissector 侧以 `block.full` 兼容（路③探针①证实）。

### §12.5 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品 + 版本 + 出处） | 映射到存量用例 | 无映射项的确认方式（§4.16 三选一） |
|---|---|---|
| **无产品级出处可用**（路②，G-TFTP-5） | —（以本机 tshark 3.6.14 实测 + RFC 原文代位） | **抓现网包**：在企业网/PXE 环境抓 RRQ→DATA→ACK 一次完整传输（确认服务端 TID 选择与 ERROR(5) 触发条件）；或**查厂商手册**（tftpd-hpa man / PXE 部署文档）；不挡开工 |
| PXE 无盘启动（RRQ 短文件、blksize 协商 1428/1468） | `tftp-rrq-short-aa100` / `tftp-rrq-blksize-1428` / `tftp-e2e-rrq-short` | — |
| 嵌入式设备固件下发（WRQ 上传大文件、tsize 预告） | `tftp-wrq-tsize-client-2048` / `tftp-wrq-multiblock-append` / `tftp-e2e-wrq-oack` | — |
| 网络设备配置下发（长传输 >32MB 需回绕 / windowsize 提速） | `tftp-rrq-blocks65536-parse` / `tftp-rrq-winsize65535-wrap` / `tftp-rrq-winsize4-blocks8` | 现网 windowsize 支持面（Linux 客户端 tftp-hpa ≥5.2 支持 windowsize，**无本地出处**）→ 同 G-TFTP-5 抓包确认 |
| NAT 环境下传输中断（服务端 TID 漂移） | `tftp-rrq-tid-change-12pkts`（**扩展语义，非现网合规行为**——不得当作现网覆盖，只作字节序列覆盖） | 真实 NAT 行为需抓包（G-TFTP-5） |
| 文件不存在/权限拒绝（运维常见错误面） | `tftp-rrq-error1-immediate` / `tftp-rrq-error2-mid` / `tftp-rrq-error3-default-msg` | — |

### §12.6 候选方案对比（§4.17：至少两个真实走法）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 层链 + 生成器复用 legacy Planner（**现状**） | `tftp` 终结层生成器内直接调用 legacy `Planner.Plan`（`layer_gen.go:26-29` 注释（零序列逻辑复制）+ `Generate` `:30`「零序列逻辑复制，字节级一致」，P2b TLS 委托同架构先例），把 `PacketConfig` 流适配为 `MessageEvent`；udp 层每事件一数据报 | 字节零漂移；wire 语义唯一权威（§1–§11）已有四轮审计背书；改动面最小 | 生成器与 legacy 双入口（validator 兜底 `validateLayer` 委托 legacy Validate）；配置仍走 Meta 直传（层 config 零负载） | O(1) 每事件适配，无聚合；复杂度低 | **采用（现状保留）** |
| B 层内配置直读（`Fields` + `translateTerminalConfig` case） | 按 dns/mqtt/cwmp 先例：registry `Fields` 登记 23 键 → `translateTerminalConfig` 增 `case "tftp"` 把层 config 翻译进 `spec.TFTP`（`chain_planner_translate.go:1801` dns 范式）→ 生成器读 `Meta.TFTP` 不变 | 兑现 §1.11/1.12（业务字段住层链）；与 http/dns/mqtt/cwmp 已收官族同构；flat 子映射 presence 判死后**无双轨** | 需动 registry + translate + CheckProtoFlat + `checkTFTPServerTID`（读顶层 config 的旧路径必须同步改，`schema/semantic.go:446`）+ schema 形状（`strategy.json`（`properties/config/properties/tftp`，`grep -n '"tftp":' strategy.json` = `:288`））+ schemagen 重跑 | 复杂度中（一次性）；兼容性=存量 226 例必须同批改写（本就全红，§12.0） | **选定（G-TFTP-1，D-TFTP-1 主体）** |
| C 仅加 `Fields` 不迁翻译（半程） | 只登记 Fields 让 `ValidateLayerConfig` 放行，层 config 仍不被消费（`chain_planner_translate.go:742-744` 早退逻辑若保留则层内值静默丢弃） | 改动更小 | **制造"层内写了但不生效"的死配置**（重演 modbus G-MODBUS-2 教训） | — | 不选（明确排除） |
| D 保留顶层子映射 + 登记过渡 | 顶层 `tftp` 子映射继续承载，只在 D 条目"明确不解决"登记 | 零改动 | 违反 1.11/1.12（顶层白名单：协议业务字段一律住层链）；与"层链唯一配置真相"记忆条目直接冲突 | — | 不选（1.12 明令：没有可住的层必须立项补层，不许"登记保留/豁免"） |

**P4 遗留（并入 §17 缺口）**：方案 B 的落地顺序、`checkTFTPServerTID` 改造与 schema 形状迁移列 G-TFTP-1/G-TFTP-2，不阻塞本 P1。

---

## §13. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §13.1 强制展开：9 个顶层旧键逐个去向已写死（`src_ip/dst_ip/src_port/dst_port/tftp/tcp/http/vlan_id/vlan_priority`）；目标形状 `spec_json` 样例见 §13.2（顶层仅 `layers`+`flow_control`）；存量 226 例改写清单见 §16/§17 | 本契约 §13.1/§13.2；`cases/tftp.json`（226 例，当前旧形） |
| §2 策略/任务 | 策略=单一 TFTP 流量模板（数量/速率走 `flow_control` 的 flows/bps/time；`cases` 中 17 例已用 `strategy_fc`（14 正：11 例 flows>1 + 2 例 flows=1 + 1 例 bps；3 负）；任务=多策略合跑+总量封顶，框架语义**零改动** | 本契约 §13.2 样例的 `flow_control` 键；框架层未改（P1–P3 零代码） |
| §3 五件套 | 见 §13.3 强制展开：会话表/事务序列/关联关系/插入位置/时间线五件齐；TFTP **无长连接**但**不豁免多事务**（同 TID 内多块锁步轮次=多轮操作，§15.1①） | 本契约 §13.3 + `tftp-rrq-multiblock-append` / `tftp-concurrent-8flows-100blk` |
| §4 查规范 | 规范面=RFC 1350 + 2347 + 2348 + 2349 + 7440（+6335 端口）；八项矩阵 §12.1 + 三子表 §12.2/§12.3/§12.5；三路对照 §12.4；候选方案 §12.6 | 本契约 §12 |
| §5 依赖与错误 | 依赖：`DependsOn ["udp"]` 单值（`registry.go:190-192`）+ dst 默认 69（`chain_planner.go:956`）+ 0 合法名单（`:701`）；错误分支三层：①Validate 拒绝族（`tftp.go:50` 起，锚词全带 `tftp:` 前缀）②ERROR 注入与抑制（`plan.go:73-126`）③链级结构负例（层级/白名单，框架 `complete.go`）；失败传播=task error（**现状缺口**：生成器期 error 被链契约吞成空流的通用面见 G-TFTP-7 登记） | 本契约 §14 D-TFTP-1 错误分支 |
| §6 性能 | O(n) 流式：`plan.go:129-226` 逐块 emit 到 chan（缓冲 256，`tftp.go:307`），无全量聚合；pcap/NIC 双路验收（NIC 例缺）；吞吐/并发/内存目标数字**待 P6 基准后定**（诚实待确认，不写承诺，§6.5）；六类场景清单见 §15.7 | 本契约 §15.7「性能设计与验收」 |
| §7 三份文档 | 权威=append 进 `docs/CODE_DESIGN.md` 的 D-TFTP-1（本契约 §14 草稿，门1 获批=定稿）+ append 进 `docs/TEST_CASES.md` 的 T-TFTP 条目（`06-tftp-testcase.md` §6 草稿）；本文 + `06-tftp-testcase.md` 为草稿/历史层（方案 §2 m4） | 修订记录 §18 |
| §8 设计先行 | 实现**已存在**（legacy `tftp.go`/`plan.go`/`builder.go`/`parser.go` + P4a 层生成器 `layer_gen.go`）；本轮 P1–P3 定位=**现状实现的设计契约回填 + 层链缺件补齐**（方案 B 未落地前，目标形状为文档契约，1.9 口径） | 本契约 §14 八要素 |
| §9 测试三源 | 三源=①RFC 1350/2347/2348/2349/7440 条文（§2–§6 逐节引用）②D-TFTP-1（§14）③已确认现网行为（**诚实缺口**：无产品级出处，§12.4 路②；以本机 Wireshark 3.6.14 实测 + 真实引擎落盘 pcap 代位，G-TFTP-5）；三源回指行见 §15.5 | 本契约 §15.5 |
| §10 评审闭环 | 文档轮：P1/P2/P3 各阶段对抗自重审（结论入 `/tmp/pipe/54-tftp/p123-report.md` ②）+ 隔离复审；代码轮（P5 改写）红先绿后 | 报告文件 |
| §11 白话 | 汇报先一句白话结论，技术证据只贴路径与结论 | 报告 |
| §12 动态清单 | 见 §13.4 强制展开：四元组=ip/udp 层（五策略全支持，`layer_dyn.go:17-23` allowlist）；**tftp 业务 23 键全不开动态**（逐个列理由）+ 序号算法代码位置实读（`resolveLayerTuple` `layer_dyn.go:770` 族 + `genSmallInt` `:726`） | 本契约 §13.4 |
| §13 schema 派生 | `tftp` 层已在注册表（`registry.go:187-192`；`Fields` **空**）→ 生成表 `layers.generated.json` 实测 `{"category":"terminal","depends_on":["udp"],"fields":{}}`；注册表 `r.Register(LayerSchema` 计数 **123**；struct 标签字面量锁（`TestLayersGeneratedMatchesRegistry`）；**迁层后须重跑 schemagen**（G-TFTP-1） | 生成文件 + `internal/core/layers/schemagen` |
| §14 真实流程 | 用例经 MCP `flowb_generate_traffic` 建策略建任务 → 引擎真实生成（pcap 落 `/tmp/mcp-pcaps/tftp/`，现有 1 例实证 `tftp-rrq-short-aa100.pcap`）→ tshark **`tftp.*` 31 字段实测**逐字段校对 + `frames` hex 双通道；断言先跑后钉（P5 纪律，14.19/14.20） | 本契约 §15.6 + 存量 `fields`/`frames` 断言面 |

### §13.1 §1 强制展开：旧键逐个去向 + 顶层子映射 + 纯 layers 目标形状

存量 226 例 `spec_json` 顶层键全集（实读 `set(spec_json.keys())`，出现例数实测）：

| 旧键 | 出现例数 | 去向（目标形状） |
|---|---:|---|
| `src_ip` | 226 | → `layers[i]` 的 `{"ip":{"src":"10.0.0.100"}}` |
| `dst_ip` | 226 | → `layers[i]` 的 `{"ip":{"dst":"10.0.0.1"}}` |
| `src_port` | 212 | → `layers[i]` 的 `{"udp":{"src_port":<原值>}}`（原值实测全部 ≥49152 的显式端口）。**缺 14 例**：11 例 B 族多流（`strategy_fc.flows>1`，改写时写**层内动态对象**，否则 `checkLayerChainStaticCopy` 拒，`schema/semantic.go:198-219`）+ 3 例单流（`tftp-multiflow-srcip-skip` flows=1、`tftp-e2e-vlan`、`tftp-e2e-gre`，改写时补显式端口；缺省走通用 12345（`mapToFlowSpec` `strategy_convert.go:49`），多流走 worker `12345+i` 保底（`chain_planner.go:894` 注释）） |
| `dst_port` | 226 | → `layers[i]` 的 `{"udp":{"dst_port":69}}`（或缺省，由 `chain_planner.go:956` 补 69；显式 1069 例保留原值） |
| `tftp`（顶层子映射） | 226 | → `layers[]` 末位 `{"tftp":{...}}`：23 键全量迁入（`mode`/`filename`/`transfer_mode`/`blksize`/`timeout`/`client_tsize`/`server_tsize`/`server_tid`/`error_code`/`error_msg`/`error_after_block`/`error_side`/`blocks_count`/`auto_append_final_block`/`final_block_zero`/`wrap_block_number`/`data_payload_pattern`/`include_oack`/`retransmit_blocks`/`server_tid_change`/`server_tid_change_at_block`/`server_tid_new`/`windowsize`，`internal/core/types.go:9195-9310` json 标签逐字），**零残留**；同时 `CheckProtoFlat` 增 presence 判死（G-TFTP-1） |
| `tcp`（顶层子映射） | 2（`tftp-validate-t101-tcp-mutex`、`tftp-e2e-tcp-reject`） | → **删除**：跨协议互斥在纯 layers 形下不再是"可写配置"，而是顶层白名单判死（1.11）——两例改判读（锚词由 `tcp field must not be set` 漂移为白名单/游离键锚词）→ §16 E 族 |
| `http`（顶层子映射） | 1（`tftp-http-coexist-reject`） | → 同上（**注**：`CheckProtoFlat` 今日对**非** http 族协议放行顶层 `http` 子映射，故本例两阶段迁移：先随白名单判死翻转，再改锚词） |
| `vlan_id` + `vlan_priority` | 2（`tftp-rrq-vlan-100`、`tftp-e2e-vlan`） | → `layers[i]` 的 `{"vlan":{"id":100,"priority":<原值>}}`（`vlan` 层已注册：`registry.go:53-60`，`Fields id/priority`，`DependsOn ["eth"]` + `OptionalOn ["eth"]`） |
| `count` | **0**（实读：全库无此键） | 不适用（数量已走 `strategy_fc`→`flow_control`：17 例） |

**白名单判定（1.11–1.13）**：上表 9 键中仅 `layers` 属结构性键（放行；`flow_control` 由 `strategy_fc` 表达）；其余 8 键（`src_ip`/`dst_ip`/`src_port`/`dst_port`/顶层 `tftp`/`tcp`/`http`/`vlan_id`/`vlan_priority`）**全部不在白名单**，一律按 1.11 判违规、按 1.12 迁层——**不留"登记保留/顶层保留/豁免"**。验收口径（完成式）：**非负例用例顶层键 = `layers`（+ 驱动层写入的 `strategy_fc`），其余为 0**。

### §13.2 目标形状 `spec_json` 样例（纯 layers，顶层仅 layers+flow_control）

单流 RRQ + blksize 协商（对应存量 `tftp-rrq-blksize-1428` 改写后的目标形状）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.100", "dst": "10.0.0.1"}},
    {"udp": {"src_port": 49152, "dst_port": 69}},
    {"tftp": {"mode": "read", "filename": "large.bin", "transfer_mode": "octet",
              "blksize": 1428, "blocks_count": 2, "data_payload_pattern": "FF"}}
  ],
  "flow_control": {"flows": 1}
}
```

多流（`flows=100`，层内动态对象——§12.9 静态复制禁令的逃生口）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.100", "dst": "10.0.0.1"}},
    {"udp": {"src_port": {"strategy": "inc", "range": [49152, 49251], "step": 1}}},
    {"tftp": {"mode": "read", "filename": "f.bin", "transfer_mode": "octet",
              "blocks_count": 1, "data_payload_pattern": "AA"}}
  ],
  "flow_control": {"flows": 100}
}
```

> 注 1：`{"tftp":{}}` 今日是**唯一合法**的层内写法（`Fields` 空 → 写业务键即 `unknown field`）；上方两样例是**目标形状**，据 §12.0，今日经 MCP 提交会红（层内未知字段 + 顶层键判死双杀）——1.9 口径："目标形状，今天跑不通，需先补代码"（G-TFTP-1）。
> 注 2：端口写 `udp` 层（1.2）；`dst_port` 缺席时 69 由 `chain_planner.go:956` 补齐；`tftp` 层**恒为末层**（`DependsOn ["udp"]`，补全链 `[ip,udp,tftp]`）。

### §13.3 §3 强制展开：五件套

**会话表**（TFTP 无 `sessions[]` 结构：一笔传输 = 一条 UDP 流 = 一次请求/应答全周期；多笔传输 = 多条流，链上一链一流）：

| 会话 | 四元组 | 生命周期 | 备注 |
|---|---|---|---|
| s1 | `ip.src/dst` + `udp.src_port → udp.dst_port`(69) | RRQ/WRQ（dst=69）→ 服务器 **TID 交换**（src=ServerTID，dst=客户端端口）→ DATA/ACK 锁步 N 轮 → 末块（< blksize 或 0 字节）→ 结束 | 无挥手、无连接状态（UDP）；`server_tid_change` 时第三方端口 NewTID 加入（扩展语义，§4.3） |
| s2…sN | 各自独立四元组（`flow_control.flows=N` + 层动态） | 同上，互不串扰 | 8/100 流族在存量中已有（`tftp-concurrent-*` / `tftp-multiflow-100flows-tuple-unique`）；链上一链一流，并发由引擎 worker 展开 |

**事务序列**（单事务四件事 §3.4–3.7；TFTP 的事务 = 一次"请求→数据块→确认"轮次）：

| 事务 | 前置条件（§3.4） | 触发动作（§3.5） | 成功分支（§3.6） | 失败分支（§3.7） |
|---|---|---|---|---|
| t0 请求 | 无（首事务） | 发 `RRQ\|WRQ(filename, mode, [选项对])`（`plan.go:52`） | 有选项 → 等 OACK（t0b）；无选项 → RRQ 直接进 t1（DATA#1）、WRQ 等 ACK#0 后进 t1 | 服务器 ERROR（文件不存在/权限/磁盘满）→ 传输终止（`plan.go:73-86`）；配置非法 → Validate 拒绝、任务失败（`tftp.go:50`） |
| t0b OACK 协商（可选） | 请求携带选项或 `include_oack=true` | 服务器回 `OACK(选项子集)`（`plan.go:57-67`） | RRQ：客户端 ACK#0 确认后进 t1；WRQ：客户端**直接**发 DATA#1（无 ACK#0，RFC 2347 §2） | 客户端拒绝 OACK → `ERROR(8)` 终止（`tftp-rrq-reject-oack-code8`） |
| t1…tN 数据轮次 | 前一轮 ACK 已发出（锁步）；窗口模式（windowsize>1）时一轮 = N 块 + 1 个窗口末 ACK | 发送方发 `DATA#i`；接收方回 `ACK#i`（`plan.go:129-226`（DATA/ACK 对 + 窗口 + 追加判定）） | 进 t(i+1)；末块（Data 长度 < blksize 或 0 字节）后结束（自动追加见 §5.1） | ①ERROR 注入（`error_after_block=N`）→ 终止（且抑制自动追加）；②重传模拟（丢包式，`retransmit_blocks`）；③TID 变更（扩展）→ 客户端回 ERROR(5) 后继续 |

**关联关系**（§3.8–3.10）：TFTP **无"控制流关联数据流"结构**——无 `driven_by`、无派生副流（单通道协议，与 CWMP §3.16 范本差异**显式声明**，非漏写）。传输内关联由 **Block# 配对**承担：`DATA#i` ↔ `ACK#i`（`plan.go:176-200`（窗口边界 ACK；ACK 发射在 `:185-200` 段内））；跨流关联由四元组承担（`flowID` = `plan.go:24`）。

**插入位置**（§3.17 第四件）：终结层——`tftp` 层生成器产 `MessageEvent`（`layer_gen.go:62-74`（`MessageEvent` 构造 + `L4PortOverride`）），经 `udp` 层成数据报（每事件一 datagram，端口已解析 + `L4PortOverride=true`）；配置经 `FlowMeta.TFTP` 直传（`chain_planner_translate.go:69-71`（`TFTP: spec.TFTP` Meta 直传））。**无握手/挥手**（UDP 无连接语义）——与 tcp 族协议的差异点。

**时间线**（§3.11–3.13）：**单流严格顺序**（锁步流控：一 DATA 一 ACK，`plan.go:129`（`for i = 1; i <= bc; i++`）串行循环，窗口模式也只在窗口边界等 ACK）；**多流并发且可交错**（引擎 worker 各自 drive，跨流不保证到达序；`tftp-multiflow-3flows-interleave` 已断言"分组正确、流内 PacketIndex 连续"）。**不得以"同一模板连续重复发射"冒充编排**（§3.13）：TFTP 的"编排"=单流内 DATA/ACK 锁步轮次 + 选项协商轮 + 终止轮，三者在同一流内按序发生，非模板重复。

### §13.4 §12 强制展开：动态字段清单（序号算法代码位置实读）

| 字段 | 住处 | 动态策略 | 序号算法代码位置（实读行号） |
|---|---|---|---|
| `src`（源 IP） | `ip` 层 | 五策略（fixed/inc/rand/list/pattern），allowlist `layer_dyn.go:18`（`"ip": {"src","dst","ttl"}`） | `resolveLayerTuple`（`layer_dyn.go:770`）→ `ResolveIPValue`（层动态通用路径，非 tftp 专属）；形状门 `checkDynShape` `:369` / `CheckLayerDynShape` `:1037` / `LayerDynAllowlisted` `:1049` |
| `dst`（目的 IP） | `ip` 层 | 同上 | 同上 |
| `ttl` | `ip` 层 | 支持（int 面 `genSmallInt` `:726`） | 同上 |
| `src_port` | `udp` 层 | 五策略（allowlist `layer_dyn.go:19-20` 的 tcp/udp src_port/dst_port）；**未写动态时无自动递增保底**（多流走 worker `12345+i`，`chain_planner.go:894` 注释；写死静态值 + `flows>1` → `checkLayerChainStaticCopy` 拒，`schema/semantic.go:142` 调用，函数体 `:198-219`） | `layer_dyn.go:770` 内 `ResolvePortValue(ld.UDP.SrcPort, i)` 分支 |
| `dst_port` | `udp` 层 | 同上；缺省 69（`chain_planner.go:956`） | 同上（`ld.UDP.DstPort` 分支） |
| `src_mac`/`dst_mac` | `eth` 层 | 支持（allowlist `layer_dyn.go:21`） | `genMAC` `layer_dyn.go:654` |
| **tftp 业务 23 键（逐个列开/不开 + 理由）** | `tftp` 层（目标）／今日顶层子映射 | **全不开**——理由：TFTP 的业务键是"一笔传输的内容与行为"（文件名/模式/块数/选项/错误注入/重传表/TID 注入），**按流变化已由 `flow_control.flows` + 层四元组动态完整表达**（每流独立四元组=独立传输身份，`plan.go:24` flowID 即证据）；把 `filename`/`blocks_count` 等单列动态需新增 20+ allowlist 行与回填分支，而现网无"逐流换文件名又共用四元组"的真实场景（链上一链一流，四元组已区分）——YAGNI，登记为**明确不支持**（`layer_dyn.go` 不加 tftp 行；对象即 `does not support dynamic`，与 radius/sip/h323 等七度已批口径一致） | 不适用（不开即无序号算法）；tftp **协议内序号**（非动态字段）实读：Block# = `plan.go:356` `wireBlockNum(i, wrap)`；ServerTID = `tftp.go:365-376`（FNV-1a(四元组) mod 16384 + 49152）；ServerTIDNew = `tftp.go:381-399`（加盐迭代 → 回退 tid+1） |

> §12.9 静态复制禁令：链形状下 `flows>1` 且层内四元组写成标量 → `checkLayerChainStaticCopy` 拒（`schema/semantic.go:198-219`，逃生口=层内写动态对象）；flat 形状下顶层 `src_port` 标量 + flows>1 → `checkStaticCopy` 拒（`:421-440`）。TFTP 特有加严：`flows>1` + 顶层 `server_tid` 固定 → `checkTFTPServerTID` 拒（`schema/semantic.go:442-458`，锚词 `tftp: server_tid N conflicts with another flow in the same batch`）——**迁层后该检查必须改读层 config**（G-TFTP-2）。

### §13-P2 presence 负例形状（链级红例必含①）

**层链 + 顶层空子映射并存 = 判死负例**（非残留）：`{"layers":[{"ip":{}},{"udp":{}},{"tftp":{}}], "tftp":{}}` 必须被拒，`error_contains` 含 `presence` 或顶层键锚词。**实读现状（诚实）**：①存量 226 例中**无此形状**（实读：`tftp` 子映射非空 226/226、空子映射 0 例）；②**`CheckProtoFlat` 今日对 tftp 不判死顶层 `tftp` 子映射**——`strategy_convert.go:8273-8330` 的判死名单（ftp/http 族/dns/mqtt/cwmp/megaco/hl7/mmse/edp/xmrmining/bacnet/smtp/pop3/imap/mcp/…）**无 tftp 分支**（tftp 只被 `:8280-8285` 的通用五键判死）。故本形状今日**不红** → P5 必做两件：①`CheckProtoFlat` 增 tftp 分支（`no longer accepts a top-level tftp sub-config (move it into the tftp layer of an [ip,udp,tftp] layers chain)`，mqtt 先例（`strategy_convert.go:8305-8308` 的 presence 分支文案）同构）；②新增该 presence 负例（G-TFTP-1）。白名单外游离键（顶层 `src_mac`/`ttl`/`tcp`/`http`）判死负例同样 P5 新增（§17 G-TFTP-4）。

### §13.5 链路可达性断言（以实读 `complete.go` `validateChain` 为准，commit 0c355be 后）

目标链 `[ip, udp, tftp]`（§13.2 样例）逐关：

| 关 | 判定 | 行号 |
|---|---|---|
| V1 层名存在 | `ip`/`udp`/`tftp` 均注册（注册表 123 层） | `complete.go`（`r.Get` 未命中报 `unknown layer`） |
| V4 末层为终结层 | 末层 `tftp` = `CategoryTerminal` → 通过 | `complete.go:375-390`（V4/V5/V6 末层检查） |
| V2 终结层唯一 | 终结层仅 `tftp`；`udp` 为 `CategoryTransport`、`ip` 为 `CategoryNetwork` → 通过 | `complete.go:392-442`（第二遍唯一性；`terminalCount` `:398` / `transportCount` `:400` / `duplicated` 报 `:440-441`） |
| V3 传输层唯一 | 传输层仅 `udp` → 通过 | `complete.go:446` 起（`transportCount>1`；tftp 无 `TransportOn`，故走通用分支，非 carrier 专用锚词） |
| 终结层豁免（OptionalOn） | **不适用**——tftp 无 `OptionalOn`；`dependedOn`（`:405-418`）才把 `DependsOn`/`OptionalOn` 计入底座关系（commit 0c355be），本链无第二终结层可豁免 | `complete.go:412-441`（`dependedOn` `:412` / 豁免 `:431`） |
| 依赖补全 | 用户可简写 `[udp, tftp]`，`ip` 由 `DependsOn ["udp"]`→`udp` 的 `DependsOn ["ip"]` 自动外插；1.8 要求 fixture 写全三层 | `complete.go:137` `CompleteChain`（`:116-137` 注释 + `:137` 签名） |

**目标形状今日可达性结论（诚实）**：链路结构可达（三层合法），但**配置面不可达**——层内写业务键会被 `ValidateLayerConfig` 拒（§12.0），顶层写业务键会被 `CheckProtoFlat` 五键判死（但顶层 `tftp` 子映射今日放行，`checkLayerFlatConflict` 只拦四元组/MAC 六键）。即：**目标形状要"层链跑通"必须先把配置通道迁进层内（G-TFTP-1）**。

---

## §14. D-TFTP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：改哪几个文件 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 与现有逻辑冲突点 / 回滚方式。本轮 P1–P3 **不改实现**：D-TFTP-1 定位为「**现状实现的设计契约回填**（wire 语义见 §1–§11，P4a 层生成器已落地）+ **层链缺件补齐**（方案 B=G-TFTP-1 的 P5 动作）」，门1 获批 = D-TFTP-1 定稿 = P5 开工门。

### D-TFTP-1.1 改哪几个文件（§8.1）

| 文件 | 状态 | 职责（实读） |
|---|---|---|
| `trafficgen/internal/core/layers/registry.go:187-192` | 已存在 | tftp 注册（`CategoryTerminal` / `DependsOn ["udp"]` / **无 Fields**）；**P5 改**：增 23 键 `Fields`（键名对齐 `core.TFTPConfig` json 标签；`data_payload_pattern` 实测为 hex 字符串 `getByteSlice`（`strategy_convert.go:7236`）/ `getUint32Slice`（`:7238`，`parseTFTPConfig` `:7215-7245` 内）→ `{Type:"string"}`；`retransmit_blocks` → `{Type:"list"}`；数值键带 Min/Max 同 §8.1 V4–V8），改后重跑 `go run ./internal/core/layers/schemagen` |
| `trafficgen/internal/core/strategy_convert.go` | 已存在 | `:1258-1262` `case "tftp"` → `parseTFTPConfig`（`strategy_convert.go:7215-7245`）；`:8273` `CheckProtoFlat`（五键判死 `:8280-8285`，tftp 无 presence 分支）；**P5 改**：`parseTFTPConfig` 升为导出 `ParseTFTPConfigFromMap`（`ParseHTTPConfigFromMap` `strategy_convert.go:8553` 先例）作为**单一翻译真相**，`CheckProtoFlat` 增 tftp presence 判死分支 |
| `trafficgen/internal/core/layers/chain_planner_translate.go` | 已存在 | `:679` `translateTerminalConfig`；`:742-744` `len(Fields)==0` 早退（tftp 今日此地返回）；`:746` `switch term.Name`；`:1801` `case "dns"`（范式）；`p.chain` 原始链 vs `term.Config` 补全链的双读法（`:1787-1795` dns 注释）；**P5 改**：增 `case "tftp"`（层 config → `spec.TFTP`，用 `configString/configUint16/configUint8/configUint32/configBool`（`layers/generator.go:656-685`）等既有 helper） |
| `trafficgen/internal/protocol/tftp/layer_gen.go:41-47` | 已存在 | `cfg := req.Meta.TFTP`；**P5 零改动**（translate 写 `spec.TFTP` → `FlowMeta.TFTP` 续传；若改读层 config 则与 dns/mqtt 族分叉，不选） |
| `trafficgen/internal/core/layers/chain_planner.go:701` `:956` | 已存在 | dst 默认 69（`:956`）+ `validateBaseDstPortHandled` 名单（`:701`）；**裁定 A1：保留现状**（不引入 `FieldContract`——见 §14.7①） |
| `trafficgen/internal/core/schema/semantic.go:443-458` | 已存在 | `checkTFTPServerTID` 读**顶层** `config["tftp"]` → 迁层后失效；**P5 改**：改读层 config（`layers[]` 中 `{"tftp":{...}}` 的 `server_tid`），并同步其单测（`semantic_test.go:46-51`（tftp tid collision，`server_tid 5000 conflicts`）） |
| `trafficgen/schemas/v1/strategy.json:288` | 已存在 | 顶层 `config.properties.tftp` 子配置形状（mode/transfer_mode/error_side/blksize/…）；**P5 改**：按 13.17 迁为层形状（`layers` 数组项内 tftp 键），或登记为过渡（13.2 `strategy.json` 只管 config 平铺字段） |
| `trafficgen/test/protocol_pcap/cases/tftp.json` | 存在（226 例） | **P5 改写面**（本文只列清单，§16/§17） |
| **测试面（P5）** | 待办 | 新增：层内翻译单测（`chain_planner_*_test.go` 范式）、presence 负例、`checkTFTPServerTID` 层形单测、`tftp/layer_gen_test.go` 回归（356 行既有） |

### D-TFTP-1.2 接口签名（§8.2；实读）

`Validate(spec core.FlowSpec) error`（`tftp.go:50`）/ `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`tftp.go:254`）/ `Generate(ctx, req *layers.GenRequest) error`（`layer_gen.go:30`（`Generate`））/ `deriveBlocksCount(ctx, spec, blkSize) uint32`（`tftp.go:333`）/ `deterministicTID`（`tftp.go:365`）/ `deterministicTIDNew`（`tftp.go:381`）/ `emit(ctx, spec, cfg, bc uint32, autoAppend, errAtLast bool, ch chan<- PacketConfig)`（`plan.go:15`）/ `emitPacket(...)`（`plan.go:267`）/ `wireBlockNum(i uint32, wrap bool) uint16`（`plan.go:356`）/ 构建族 `buildRRQWRQ`(`builder.go:17`)、`buildDATA`(`:47`)、`buildACK`(`:58`)、`buildERROR`(`:68`)、`buildOACK`(`:85`) / `Parse(pkt []byte) (*ParsedPacket, error)`（`parser.go:33`）。**P5 新增**：`ParseTFTPConfigFromMap(m map[string]interface{}) *TFTPConfig`（导出，`strategy_convert.go`）。

### D-TFTP-1.3 数据结构（§8.3）

`FlowSpec.TFTP *TFTPConfig`（`internal/core/types.go:9195-9310`，23 键：`mode`/`filename`/`transfer_mode`/`blksize`(uint16)/`timeout`(uint8)/`client_tsize`/`server_tsize`(uint32)/`server_tid`(uint16)/`error_code`(uint8)/`error_msg`/`error_after_block`(uint32)/`error_side`/`blocks_count`(uint32)/`auto_append_final_block`(*bool)/`final_block_zero`/`wrap_block_number`(bool)/`data_payload_pattern`([]byte)/`include_oack`(bool)/`retransmit_blocks`([]uint32)/`server_tid_change`(bool)/`server_tid_change_at_block`(uint32)/`server_tid_new`(uint16)/`windowsize`(uint16)）。层链事件：`MessageEvent{Up, Bytes, SrcPort, DstPort, Metadata, L4PortOverride}`（`layer_gen.go:62-74`（`MessageEvent` 构造 + `L4PortOverride`））；Metadata 键 `tftp_opcode`/`tftp_block`/`tftp_filename`（§10.2 + `tftp-e2e-metadata`）。**P5 新增数据结构：无**（`Fields` 是注册表 map，非 struct）。

### D-TFTP-1.4 主流程（§8.4）

**现状（今日）**：MCP `flowb_generate_traffic` → `config` = `spec_json` → `ValidateStrategy`（形状 → `CheckProtoFlat` 五键判死 → tftp tid 检查）→ `mapToFlowSpec`（`strategy_convert.go:324`（`mapToFlowSpec`）；`:1258-1262`（`case "tftp"`）读顶层 `tftp` 子映射 → `spec.TFTP`）→ `ChainPlanner.ValidateSpec`（`chain_planner.go:149` `ValidateSpec`（`:149`）：`validateSpecBase`（`:747`：IP 解析、src/dst 端口、tftp dst 默认 69) → `translateTerminalConfig`（调用点 `chain_planner.go:175`；tftp 早退在 `chain_planner_translate.go:743-744`） → 补全链 → 协议 validator → 层值回填 spec（`chain_planner.go:308-333` 注释块 + 回填循环））→ `Plan` → `drive`（生成器读 `Meta.TFTP` → legacy `Planner.Plan` → `MessageEvent`）→ udp 层成帧 → pcap/NIC。

**目标（P5 后）**：`[{"ip":{"src","dst"}},{"udp":{"src_port","dst_port"}},{"tftp":{…23 键…}}]` → `ValidateStrategy`（`CheckProtoFlat` 拒顶层 `tftp`/四元组；`ValidateLayers` 校验层内容器形状 + 动态对象 allowlist）→ `mapToFlowSpec`（顶层无 tftp 子映射 → `spec.TFTP=nil`）→ `ValidateSpec`：`validateSpecBase`（端口默认/回填）→ **`translateTerminalConfig` 新增 `case "tftp"`**（层 config → `spec.TFTP`，含动态对象直解，dns `:1801` 范式）→ 协议 validator（沿用 legacy `Planner.Validate`）→ 生成器不变。

### D-TFTP-1.5 错误分支（§8.5；失败返回 task error，零假成功方向）

①Validate 拒绝族（`tftp.go:50` 起，锚词全带 `tftp:` 前缀；存量 40 负例已逐条钉）：filename 空/NUL、mode/transfer_mode 非法、blksize/timeout/windowsize 越界、server_tid 知名端口、error_code 越界、EAB 越界/缺 blocks_count/缺 payload 源、retransmit 越界、TID 变更互斥（error_code / retransmit）、server_tid_new 同值、blocks_count 越界（未开 wrap）、final_block_zero 缺 blocks_count、derive 无源、TFTPConfig 缺失（`tftp: TFTPConfig is required`）；②跨协议互斥（V20：`tcp/http/... field must not be set`）→ **迁层后该分支不可达**（顶层子映射判死先命中）→ E 族改判读；③ERROR 注入与抑制（`plan.go:73-126`，含 EAB=bc 抑制自动追加）；④链级结构负例（层名/层级/重复终结层/白名单，框架 `complete.go`）；⑤**现状缺口（诚实）**：生成器期 error 被链契约吞成空流的通用面（`layer_gen.go:75-83`（emit 失败排空-退出） + 引擎契约）→ 登记 G-TFTP-7，不属本协议本地改动。

### D-TFTP-1.6 性能边界（§8.6）

O(n) 流式：`plan.go:129-226` 逐块构造 + 立即写 chan（缓冲 **256**，`tftp.go:307`），无全量聚合；内存 O(1)/包（除 `data_payload_pattern` ≤ blksize 的构造缓冲）；无锁、无 sleep（速率由引擎 pacer 统一，`tftp-e2e-bps` 1 Mbps 例）；巨例（`blocks_count=65536`、`windowsize=65535`、100 流）为**设计文档级规模**，P5 执行面按需拆/跳（§16 F 族）。详见 §15.7（6.1–6.8 六要素）。

### D-TFTP-1.7 与现有逻辑的冲突点（§8.7）

①**端口默认双轨（已裁定 A1：保留现状）**：dst 69 由 `validateSpecBase` 的 DstPort switch 承接（`chain_planner.go:956`），未用 `FieldContract`（cwmp `registry.go:515` 是 FieldContract 先例，但那是"http 底座之上的应用层端口"，tftp 是直接 UDP 终结层，走 switch 与 dns/ntp 同族——选 A1 的一致性理由；**候选 A2 = FieldContract `{"udp.dst_port":"69"}` 登记为备选**，若后续统一收敛再改）。②**配置通道双轨（今日状态，P5 收敛）**：`spec.TFTP` flat 键是唯一载体，层内 `{"tftp":{…}}` 今日零负载（写业务键即 `unknown field`）→ G-TFTP-1。③**`checkTFTPServerTID` 读顶层 key**（`schema/semantic.go:446`）→ 迁层后必须同步改，否则 batch/TID 冲突检查静默失效 → G-TFTP-2。④**跨协议互斥负例依赖顶层子映射可写**（`tftp-validate-t101-tcp-mutex` / `tftp-http-coexist-reject`）→ 迁层后锚词漂移 → E 族改判读。⑤**legacy `Plan` 与层生成器同源**（`layer_gen.go:57-61` 委托）→ 无双份序列逻辑，无冲突；但 `Planner.Validate` 只校验不默认化（默认化在 `Plan` `tftp.go:261-307`（默认化 `:261-287` + derive `:289-297` + autoAppend/errAtLast `:299-305` + chan `:307`）），故 translate 期不得重复默认化（否则双份默认逻辑分叉）。

### D-TFTP-1.8 回滚方式（§8.8）

P1–P3 零代码改动，无回滚面。P5 改写面回滚 = `git revert` 改写提交（`registry.go` Fields + `strategy_convert.go` presence 分支 + `chain_planner_translate.go` case + `semantic.go` tid 检查 + `strategy.json` + `cases/tftp.json`）；层数 123 不变（tftp 已注册，无 schemagen 增量）；`allowedProtocols`（`internal/core/protocols.go`）无增量（实读 tftp 已在表内，无占位翻转面）。

### D-TFTP-1.9 补充（P6 修轮）：WRQ 侧 TID 变更叙事

§4.3/S9 以 RRQ（客户端为接收方）视角叙述 TID 变更："客户端检测新 TID → 回 ERROR(5) → 继续传输"。WRQ（客户端为发送方）方向实现不同：**切换块起客户端把 DATA 直接发往新 TID**（`plan.go:133` 判定 / `:142-146` WRQ 分支 `dataDstPort = ServerTIDNew`），随后客户端再以 **ERROR(5)（up，dst=新 TID）作迁移标记**（`:164-172`），服务器从新 TID 回 ACK（down，`src=新 TID`，`:186-190`），传输继续。两方向均由 `plan.go` 各自实现（`:129-226` 主循环 + 追加块 `:236-257` 同款判定）；此为 trafficgen 扩展语义（非 RFC 标准），用例 `tftp-wrq-tidchange` 标"互操作负向"（9 包落盘实测：WRQ / ACK#0(60000) / DATA#1(→61000) / ERROR(5)(→61000) / ACK#1(61000) / DATA#2 / ACK#2 / DATA#3(0B) / ACK#3）。

---

## §15. P3 固定动作（CORE_MEMORY §3.15/§9.52/§9.14/覆盖审计要求面）

### §15.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例 / 立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | TFTP 单流内的"多轮"= 锁步 DATA/ACK 轮次（`plan.go:129`（`for i = 1; i <= bc; i++`）循环）+ 选项协商轮（OACK→ACK#0）+ 终止轮；多轮代表：`tftp-rrq-multiblock-append`（多块）、`tftp-concurrent-8flows-100blk`（100 块）、`tftp-rrq-winsize4-blocks8`（窗口 2 轮）、`tftp-matrix-allopts-retx-err`（选项+重传+ERROR 交织） | 已覆（≥4 例） |
| ② | 非正常结束 | ERROR 终止族 36 例（`error_code` 断言）+ TID 变更扩展（2 例）+ 重传 10 例 + 半标准流 `tftp-auto-append-off` / `tftp-e2e-no-final-block` + 配置非法任务失败（40 负例，`expect_error` 面） | 已覆；**单点缺口**：WRQ 方向重传/TID 变更 0 例 → A′ 补例（§15.2） |
| ③ | 长保活 | TFTP **无长连接/无保活语义**（UDP 无状态，RFC 1350 无 keepalive/空闲超时字段）→ 形态对应物 = **同 TID 内长块序列**（`tftp-concurrent-8flows-100blk` 100 块 / `tftp-rrq-blocks-65535-head` 边界）；**空闲复用/超时值明确不支持**（§12.1-6，timeout 仅语义标记） | 已覆（代表例）+ **不适用项已声明**（非空白） |

无空项。②的单点缺口进 §17（A′ 补例），不删用例。

### §15.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族五类审计）

A′（**现有引擎可构建** → 存量已覆 / P5 改写或补例后并入）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | opcode 六值 / 请求包结构与 512B 上限 / mode·transfer_mode 值域 / 选项组合与固定顺序 / 选项值域四界 / tsize 三态发送规则 / DATA 块大小四形态 / Block# 三边界与回绕 / 窗口四形态 / 重传六形态 / ERROR 九码与默认映射 / 注入位置六态 / TID 五态 / 端口三态 / VLAN·GRE 封装 | 已覆（§12.3 19 行中 18 行有例；余 1 行=IPv6 → A′ 补例 T-TFTP-V6） |
| 业务 | 单事务四件事（§13.3 事务序列）/ RRQ 与 WRQ 双状态机 / OACK 协商与拒绝 / 锁步多轮 / 多流并发与交错 | 已覆；**缺** WRQ 重传（T-TFTP-WRQ-RETX）、WRQ+TID 变更（T-TFTP-WRQ-TIDCHG） |
| 现网 | PXE 短文件 / 固件升级 WRQ / 配置下发长传输 / 文件不存在与权限拒绝 / NAT TID 漂移（扩展语义） | 已覆（行为面）；**产品级出处缺** → G-TFTP-5 |
| 多流 | 3/8/100 流、同 filename、跨流不串扰、TID 冲突拒绝 | 已覆（改写为层动态后并入，§17） |
| 地址族 | IPv4 全族；**IPv6 零例**（全库 `ipv6` 0 命中） | A′ 补例 **T-TFTP-V6**（`[ip,udp,tftp]`——`ip` 层写 v6 字面量，注册表无 `ipv6` 层；断言 `ipv6.nxt=17` + `udp.dstport=69` + `tftp.opcode`） |
| 长保活 | 同 TID 长块序列（100 块代表） | 已覆（不适用项已声明） |

B′（**引擎结构缺口** → D-TFTP-1「明确不解决 + 迁入计划」，见 §17）：**G-TFTP-1**（业务 23 键迁层 + `CheckProtoFlat` presence 判死 + 层翻译 case）、**G-TFTP-2**（`checkTFTPServerTID` 改读层 config + `strategy.json`（`properties/config/properties/tftp`，`grep -n '"tftp":' strategy.json` = `:288`） 形状迁移）、**G-TFTP-3**（非法/未知 opcode 注入能力——需代码改动，§12.2 三格）、**G-TFTP-6**（RFC 1350 §4 合规 TID 校验序列不实现）、**G-TFTP-7**（驱动失败→空流的 task error 收敛，跨协议框架面）。

### §15.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（RFC 1350 §4/§5/§6 + RFC 2347 §2 + RFC 2348 §2 + RFC 2349 §2 + RFC 7440 §3 + RFC 6335），**非**引擎能力面反推（引擎侧仅作现状取证：本机 tshark 3.6.14 实测 `tftp.*` **31 字段**、`cases/tftp.json` 226 例 ID 实读、函数行号实读、Wireshark dissector dissector 行为探针 4 项）。
- **对账两行（粒度实读：八项按行、矩阵按格、变体按行）**：**规范逻辑点总数 = 51** = §12.1 八项 **8 行** + §12.2 命令×响应码矩阵 **24 格**（8 行 × 3 面）+ §12.3 数据形态变体表 **19 行**。**用例覆盖数 = 40** = 八项 8 + 矩阵 **14 格**（实读，§12.2 格数算术）+ 变体 **18 行**。**未覆盖 6** = 矩阵 **5 格**（WRQ 异常面 1 + DATA(up) 异常面 1 + 非法 opcode 三面 3）+ 变体 **1 行**（地址族 IPv6）。**不适用 5 格**（DATA/ACK/ERROR 的无错误码语义面，随行列已声明）。40 + 6 + 5 = 51 ✓ 无遗漏。反查 226 例（改写后）全绿 ≠ 覆盖全；此对账为覆盖审计的有效口径。
- **P5 后口径（as-built 复算，用例=224）**：**覆盖 43** = 八项 8 + 矩阵 **16 格**（14 + 2：WRQ 异常面→`tftp-wrq-retransmit`、DATA(up) 异常面→`tftp-wrq-tidchange`）+ 变体 **19 行**（地址族→`tftp-v6-basic`）；**未覆盖 3**（矩阵：非法/未知 opcode 三格，G-TFTP-3 已立项，出本车道）；**不适用 5 格**。43 + 3 + 5 = 51 ✓。
- **台账粒度声明（防误读）**：51 点按 §12 的行/格粒度计数；跨切面缺口（G-TFTP-1/2/3/5/6/7 去扁平与框架面、产品出处面）另登 §17，**不折进 51 点**、也**不冒充覆盖**。

### §15.4 3.14 豁免边界审计

本协议**无长连接、无 `sessions[]` 结构**（UDP 无状态，一笔传输=一条流，见 §13.3 会话表）：`sessions[]`/`flows[]` **豁免**（§3.14 前半句）——但**豁免 ≠ 豁免多流覆盖**（后半句）：①**多流并发**：存量 16 例多流（`tftp-multiflow-*` 8 + `tftp-concurrent-*` 5 + `tftp-e2e-multiflow` + `tftp-multiflow-100flows-tuple-unique`…）P5 改写为"层内动态对象 + `flows=N`"形（16 例全在改写清单，§17）；②**单包多载荷**：TFTP 单包恒单载荷（一个 opcode + 可选选项对；无多 question/多 RR 结构），对应形态 = **单包多选项对**（`tftp-oack-multiopt-35b` 4 选项 35B、`tftp-rrq-all4opts`）已有例。两项均有，**无豁免逃逸**。

### §15.5 三源回指行

RFC 1350 / 2347 / 2348 / 2349 / 7440（+6335 端口）→ D-TFTP-1（本文 §14）→ `trafficgen/test/protocol_pcap/cases/tftp.json`（226 例，ID 权威 = `06-tftp-testcase.md` §2 + 本文 §16 审计去向表）。本机 tshark 3.6.14 实测（`tftp.*` 31 字段 + 4 项dissector 行为探针）与真实引擎落盘 pcap（`/tmp/mcp-pcaps/tftp/tftp-rrq-short-aa100.pcap`）为 wire 旁证（§12.4 路③）。

### §15.6 断言通道与实测口径（`$3列 ^tftp\.` 实测）

- 实测命令与值：`tshark -G fields | awk -F'\t' '$3 ~ /^tftp\./' | wc -l` = **31**（本机 Wireshark 3.6.14）。**口径校准注**：不带 `-F'\t'` 的默认 awk 切分同一命令只得 **4**（多词字段名如 `Source File`/`Block` 抢占列位）——凡报数须带 `-F'\t'`，本文全部数字以 `-F'\t'` 口径为准。
- 存量断言面（13 个字段名，全部实测存在于本机字段表，无自创字段）：`tftp.opcode`(422 处) / `tftp.block`(357) / `tftp.option.value`(68) / `tftp.option.name`(32) / `tftp.error.code`(36) / `tftp.error.message`(8) + 载体 `udp.srcport`(39) / `udp.dstport`(15) / `udp.length`(29) / `udp.checksum.status`(3) / `ip.version`(1) / `vlan.id`(1) / `vlan.priority`(1)；固定帧走 `frames` hex（114 例），包数走 `packet_count`(188)/`min_packets`(6)。
- **P5 可用但今日未用**的 dissector 资产（探针实证）：`tftp.block.full`（回绕补偿块号，DATA#0 报 65536）、`tftp.type`（netascii/octet）、`tftp.source_file`/`tftp.destination_file`（会话跟踪）、`tftp.nextwindowsize`、expert 类 `tftp.windowsize_range`（windowsize=0 触发）。
- P5 纪律：改写后**先跑后钉**（14.19 全量绿 + 14.20 包号/端口基准从落盘 pcap 取，不许手算）。

### §15.7 性能设计与验收（CORE_MEMORY §6.1–6.8 六要素）

| 要素 | 内容（实读口径；无实测数字处诚实标注） |
|---|---|
| 6.1 性能目标/资源预算/规模边界 | **无实测数字 → 待 P6 基准后定（不写承诺，§6.5）**。结构面边界实读可给：单流最大报文 = blksize 65464 + 4B TFTP 头 + 8B UDP + 20B IP + 14B Eth = 65510B（UDP 载荷 65476 ≤ 65507，旧 §13b 已核算）；块数上限 = uint32（wire Block# 回绕，`plan.go:356`）；流数上限 = `flow_control.flows`（无协议级上限，受引擎与缓冲约束） |
| 6.2 指标清单 | 目标吞吐（包/秒、比特/秒）：**待确认**；并发流数：`flows=N`（存量已含 100 流例）；单流最大报文：65510B（上式）；内存上限：O(1)/包（`plan.go:129-226` 逐块 emit，无累计结构）+ pattern 缓冲 ≤ blksize；队列/缓冲：生成器 chan **256**（`tftp.go:307`）+ 引擎 worker/packet 队列；CPU 并行度：引擎 `PacketWorkers`（框架面，非本协议） |
| 6.3 双路验收 | ①pcap 路：suite 经 MCP 落盘 `/tmp/mcp-pcaps/tftp/<caseID>.pcap` + tshark 字段校对（实证 1 例已在库）；②**真实网卡路：缺**（无 tftp NIC 用例；框架面已有 `nic_drive_test.go`，补例列入 §17 相邻项） |
| 6.4 实现路径依据 | 全流式：legacy `Plan` 返回 chan（`tftp.go:307`（`make(chan core.PacketConfig, 256)`））→ 生成器逐事件适配（`layer_gen.go:56-86`：事件循环 `:56` + `MessageEvent` `:62` + 排空退出 `:75-83`）→ udp 层即发；无全量收集、无 sleep、无锁（ServerTID 由纯哈希 FNV-1a 确定性生成（`tftp.go:365`））；限速由引擎共享 pacer 统一（策略 `bps`，`tftp-e2e-bps` 1 Mbps 例）；`FlowMeta.TFTP` 指针直传无拷贝放大 |
| 6.5 数字待确认项 | 吞吐/延迟/内存/CPU 数字全部**待 P6 基准**；不得写成承诺 |
| 6.6 六类场景覆盖 | 基线（单流短文件）有例；目标规模（100 流/100 块）有例；**压力上限、长时间运行、资源耗尽/背压：无例 → 缺口登记**；并发交错有例（`tftp-multiflow-3flows-interleave`） |
| 6.7 断言面 | 包数与字段值（非"任务没报错"）；重传/窗口/回绕有字节级断言；**速率类断言缺**（`tftp-e2e-bps` 是否实断言聚合速率待 P5 校准） |
| 6.8 结论 | 现状：功能正确面证据充分（226 例改写后可全量跑）；**资源预算类指标未测** → 不得宣称"性能达标"（§6.8 认定不合格面：仅"能不能生成"已答，"跑多快/多大"待补） |

---

## §16. 存量 226 例审计去向分类（CORE_MEMORY §9.14：合入/等价覆盖/作废+原因）

> 审计方法：python3 实读 `cases/tftp.json`（`spec_json` 顶层键全集 + `layers` 形状 + `strategy_fc` + `expect` 键集 + 负例锚词 + spec 全等分组）。允许按族批量审计，但**每族点名**（本节逐族列 ID 或全量点名）。

**形状总览（实读）**：226 例 = **正例 186 + 负例 40**；**186 正例全部带 `layers: [{"udp":{}},{"tftp":{}}]` 且同时带顶层旧键**（混合形）；**40 负例全部无 `layers`（纯扁平形）**。顶层键 9 种（`src_ip` 226 / `dst_ip` 226 / `dst_port` 226 / `src_port` 212 / `tftp` 226 / `tcp` 2 / `http` 1 / `vlan_id` 2 / `vlan_priority` 2）；**`count` 0 例**；**空 `tftp` 子映射 0 例**（无 presence 负例形状）；**负例缺 `error_contains` 0 例**（40/40 带锚词）；**完全重复 0 组**（spec+expect 全等分组 = 0）、**同 spec 分组 = 0**；`strategy_fc` 17 例（flows 2/3/8/100 与 1 例 bps；其中 16 正 + 1 负 `tftp-concurrent-8flows-tid`）；断言字段 13 个（全在本机 tshark 字段表内，§15.6）。

### A 族：合入·单流正例（175 例；改写为纯 layers 形后并入）

改写 = 顶层 5 键按 §13.1 去向表迁层（`src_ip`/`dst_ip` → `ip` 层；`src_port`/`dst_port` → `udp` 层；顶层 `tftp` 23 键 → `layers[]` 末位 `{"tftp":{…}}`）+ `layers` 由两条目补全为 `[ip,udp,tftp]` 三层并填值。

`rrq` 族 **95**：`tftp-rrq-short-aa100`、`tftp-rrq-blksize-1428`、`tftp-rrq-timeout-10`、`tftp-rrq-tsize-server-2048`、`tftp-rrq-winsize4-blocks8`、`tftp-rrq-3opts-autofull`、`tftp-rrq-error1-immediate`、`tftp-rrq-error2-mid`、`tftp-rrq-error0-client`、`tftp-rrq-error4-default`、`tftp-rrq-error8-default`、`tftp-rrq-reject-oack-code8`、`tftp-rrq-full-13pkts`、`tftp-rrq-tid-change-12pkts`、`tftp-rrq-final-zero-first`、`tftp-rrq-pattern-cycle`、`tftp-rrq-include-oack-empty`、`tftp-rrq-error5-default`、`tftp-rrq-error-truncated`、`tftp-rrq-error-suppress-append`、`tftp-rrq-oack-winsize-15b`、`tftp-rrq-opts-error1-immediate`、`tftp-rrq-14bytes`、`tftp-rrq-multiopt-44b`、`tftp-rrq-all4opts`、`tftp-rrq-blksize-timeout`、`tftp-rrq-blksize-tsize`、`tftp-rrq-blksize-winsize`、`tftp-rrq-timeout-tsize`、`tftp-rrq-timeout-winsize`、`tftp-rrq-tsize-winsize`、`tftp-rrq-opts-noinclude-oack`、`tftp-rrq-opts-error1-mid`、`tftp-rrq-opts-finalzero`、`tftp-rrq-opts-noappend`、`tftp-rrq-blksize8-winsize2`、`tftp-rrq-blksize65464-winsize2`、`tftp-rrq-optorder-fixed`、`tftp-rrq-optorder-oack-match`、`tftp-rrq-winsize1-lockstep`、`tftp-rrq-all4opts-tidchange`、`tftp-rrq-winsize65535-wrap`、`tftp-rrq-winsize65535-wrap2`、`tftp-rrq-dstport-1069`、`tftp-rrq-multiblock-append`、`tftp-rrq-netascii-hello`、`tftp-rrq-defaults`、`tftp-rrq-uppercase-normalize`、`tftp-rrq-finalzero-no-dup-append`、`tftp-rrq-winsize1-lockstep-explicit`、`tftp-rrq-error1-after-2`、`tftp-rrq-error5-client-terminate`、`tftp-rrq-error2-immediate`、`tftp-rrq-error0-server-mid`、`tftp-rrq-error1-custom-msg`、`tftp-rrq-error3-default-msg`、`tftp-rrq-error7-after-oack`、`tftp-rrq-filename-slash`、`tftp-rrq-filename-backslash`、`tftp-rrq-single-full-block`、`tftp-rrq-blksize-default-no-option`、`tftp-rrq-timeout-zero-no-option`、`tftp-rrq-tsize-double-zero-no-option`、`tftp-rrq-vlan-100`、`tftp-rrq-filename-255`、`tftp-rrq-server-tsize-append`、`tftp-rrq-double-tsize`、`tftp-rrq-allzero-options-no-oack`、`tftp-rrq-retransmit-single`、`tftp-rrq-retransmit-multi`、`tftp-rrq-retransmit-first-block`、`tftp-rrq-retransmit-error`、`tftp-rrq-retransmit-wire-bytes`、`tftp-rrq-retransmit-tsize-append`、`tftp-rrq-winsize4-error`、`tftp-rrq-winsize4-retransmit`、`tftp-rrq-blksize-retransmit`、`tftp-rrq-allopts-retransmit-error`、`tftp-rrq-retransmit-timing`、`tftp-rrq-tsize-send-rule`、`tftp-rrq-mode-case-m1`、`tftp-rrq-include-oack-wrq-empty`、`tftp-rrq-blksize65535-append-wrap`、`tftp-rrq-blocks65536-parse`、`tftp-rrq-error-after-finalzero`、`tftp-rrq-winsize4-append`、`tftp-rrq-winsize4-partial-window`、`tftp-rrq-winsize2-tsize`、`tftp-rrq-derive-filesource-1024`、`tftp-rrq-empty-pattern-bc1`、`tftp-rrq-server-tid-4000-registered`、`tftp-rrq-blocks-65535-head`、`tftp-rrq-empty-data-tsize512`、`tftp-rrq-tsize0-client`、`tftp-rrq-max-request-324`（**95 例**）。

`wrq` 族 **21**：`tftp-wrq-upload-bb200`、`tftp-wrq-tsize-client-2048`、`tftp-wrq-blksize-512`、`tftp-wrq-error3-mid`、`tftp-wrq-oack-error6`、`tftp-wrq-short-noappend`、`tftp-wrq-14bytes`、`tftp-wrq-append-zero-4b`、`tftp-wrq-multiopt-47b`、`tftp-wrq-all4opts`、`tftp-wrq-timeout-only`、`tftp-wrq-tsize-only`、`tftp-wrq-winsize-only`、`tftp-wrq-all4opts-partial`、`tftp-wrq-tsize-winsize-append`、`tftp-wrq-include-oack-empty`、`tftp-wrq-error4-client-immediate`、`tftp-wrq-multiblock-append`、`tftp-wrq-tsize-zero-oack-server`、`tftp-wrq-finalzero`、`tftp-wrq-blksize-only-oack`（**21 例**）。

其余单流正例 **59**：`oack` 族 4（`tftp-oack-multiopt-35b` / `-blksize-15b` / `-timeout-13b` / `-tsize-13b`）、`matrix` 族 5（`tftp-matrix-allopts-retx-err` / `-blk8-ws2` / `-blk65464-ws2` / `-ws1-equiv` / `-allopts-tid`）、`regress` 族 13（`tftp-regress-err0-noinject` / `-err5-term` / `-err8-map` / `-filename-255` / `-include-oack` / `-err0-inject` / `-rrq-fbz-tsize` / `-rrq-client-tsize` / `-rrq-server-tsize` / `-rrq-dual-tsize` / `-tid-4000` / `-blocks-65536-wrap` / `-blocks-wrap-seq`）、`e2e` 族 22（`tftp-e2e-*` 除 `-validate-fail`/`-tcp-reject` 两负例外的全部，含 `-vlan`/`-gre` 两例须额外迁 `vlan` 层；另 `tftp-e2e-mixed-dns` / `tftp-multiflow-srcip-skip`（flows=1）/ `tftp-e2e-bps`（bps 形）三例归本族）、`validate` 族 3 正例（`tftp-validate-t080-windowsize-0-valid` / `-t083-server-tid-1024` / `-t104-error-afterblock-retransmit`）、单例族 10（`tftp-auto-append-off`、`tftp-blksize8-min`、`tftp-blksize65464-max`、`tftp-blocks-65535-short`、`tftp-data-header-ff`、`tftp-error1-19b`、`tftp-final-block-zero`、`tftp-udp-length-accounting`、`tftp-tidchange-errorcode0`、`tftp-tid-deterministic`）、`server` 族 2（`tftp-server-tid-explicit`、`tftp-server-tid-1024-boundary`）。**95 + 21 + 59 = 175 ✓**。

### B 族：合入·多流正例（11 例；改写 = 层内四元组动态对象）

`strategy_fc.flows>1` 的正例（实读 11 例）：`tftp-multiflow-3flows-9pkt`、`tftp-multiflow-3flows-interleave`、`tftp-multiflow-error-flow`、`tftp-multiflow-retransmit-flow`、`tftp-multiflow-100flows-tuple-unique`、`tftp-multiflow-same-filename`、`tftp-concurrent-8flows-100blk`、`tftp-concurrent-8flows-ws4`、`tftp-concurrent-8flows-retx`、`tftp-concurrent-tid-derived`、`tftp-e2e-multiflow`。**改写要点**：层内 `ip`/`udp` 四元组必须写成动态对象（否则 `checkLayerChainStaticCopy` 拒，`schema/semantic.go:198-219`）；静态 + `flows>1` 的现状在链上必红。**归属注**：`tftp-e2e-mixed-dns` 与 `tftp-multiflow-srcip-skip`（`flows=1`）归 A 族；`tftp-e2e-bps`（`bps` 形）归 A 族；`tftp-multiflow-tidchange-flow` / `tftp-concurrent-8flows-tid`（neg）归 C 族；`tftp-tid-conflict-batch`（neg）归 C 族。

### C 族：合入·负例（40 例；改写为 layers 形 + 保留锚词）

改写 = 层链补全 `[ip,udp,tftp]` + 业务键迁 `tftp` 层 + 锚词逐字保留（40/40 已有锚词）。族内点名：
- `validate` 族 34：`tftp-validate-t071-empty-filename`、`t072-filename-nul`、`t073-invalid-mode`、`t074-invalid-transfer-mode`、`t075-mail-deprecated`、`t076-error-code-9`、`t077-blksize-7`、`t078-blksize-65465`、`t079-timeout-256`、`t081-windowsize-65536`、`t082-server-tid-80`、`t084-eab-exceeds`、`t085-eab-no-blocks-count`、`t086-eab-no-payload`、`t087-retransmit-out-of-range`、`t088-retransmit-zero`、`t089-tidchange-errorcode-mutex`、`t090-tidchange-retransmit-mutex`、`t092-tidchange-atblock-0`、`t093-tidchange-atblock-99`、`t094-server-tid-new-80`、`t095-tid-new-equals-tid`、`t096-blocks-65536-no-wrap`、`t097-blocks-0-no-payload`、`t099-finalzero-no-blocks`、`t100-autoappend-no-payload`、`t101-tcp-mutex`、`t082-server-tid-wellknown`、`t090-tidchange-retransmit`、`t093-tidchange-atblock-exceed`、`t095-tidnew-equals-tid`、`t094-tidnew-wellknown`、`t050-append-push-65536`、`t223-blocks-65536-nowrap`（**34 例**）
- 其余 6：`tftp-multiflow-tidchange-flow`、`tftp-concurrent-8flows-tid`、`tftp-tid-conflict-batch`、`tftp-http-coexist-reject`、`tftp-e2e-validate-fail`、`tftp-e2e-tcp-reject`

> C 族点名注：①`tftp-e2e-validate-fail` / `tftp-concurrent-8flows-tid` 与 `validate` 族功能重叠（前者复跑 filename 空负例、后者复跑多流 TID 冲突）——按 §9.21 同分支代表口径可保留为 E2E/并发上下文例，但必须在 P5 注明"等价于 `t071` / `tftp-tid-conflict-batch`"；②`t082`/`t090`/`t093`/`t094`/`t095` 五组存在**同主题双例**（见 D 族）。

### D 族：等价覆盖（7 例，P5 删除；理由=同测试点重复，锚词粒度不同）

| 保留例（锚词更全） | 删除例 | 原因 |
|---|---|---|
| `tftp-validate-t082-server-tid-wellknown` | `tftp-validate-t082-server-tid-80` | 同一 Validate 分支（server_tid 知名端口）；后者锚词仅截断前缀 `server_tid 80` |
| `tftp-validate-t090-tidchange-retransmit-mutex` | `tftp-validate-t090-tidchange-retransmit` | 同上（互斥分支）；前者锚词更全 |
| `tftp-validate-t093-tidchange-atblock-exceed` | `tftp-validate-t093-tidchange-atblock-99` | 同上（`server_tid_change_at_block` 越界） |
| `tftp-validate-t094-tidnew-wellknown` | `tftp-validate-t094-server-tid-new-80` | 同上（`server_tid_new` 知名端口） |
| `tftp-validate-t095-tidnew-equals-tid` | `tftp-validate-t095-tid-new-equals-tid` | 同上（`server_tid_new == server_tid`） |
| `tftp-validate-t223-blocks-65536-nowrap` | `tftp-validate-t096-blocks-65536-no-wrap` | 同上（blocks>65535 未开 wrap）；保留例与 `t050`（append 推越）区分清晰 |
| `tftp-e2e-tcp-reject` | `tftp-validate-t101-tcp-mutex` | 同上（跨协议互斥）——**两例的存活值待 E 族改判读后重定**（迁层后锚词均要改） |

### E 族：改判读（4 例；迁层后锚词漂移/键位迁移，P5 必须处理）

| ID | 现状锚词 | 迁层后 | 处置 |
|---|---|---|---|
| `tftp-validate-t101-tcp-mutex`（若按 D 族删则免） | `tcp field must not be set` | 顶层 `tcp` 子映射在纯 layers 形下由白名单判死（1.11），锚词漂移为白名单/游离键文案 | 改锚词或删除（与 D 族去重后定一） |
| `tftp-http-coexist-reject` | `http field must not be set` | 同上（且 `CheckProtoFlat` 对 tftp 的 http 子映射今日放行，须随白名单判死一并翻转才能到锚词） | 改锚词 |
| `tftp-rrq-vlan-100`、`tftp-e2e-vlan` | 正例（`vlan.id` / `vlan.priority` 断言） | `vlan_id` / `vlan_priority` 顶层键判违规 → 迁 `{"vlan":{"id":100,"priority":…}}` 层 | 改写为 vlan 层（断言字段不变） |

### F 族：规模巨例（5 例；P5 执行面策略）

`tftp-rrq-winsize65535-wrap`（65535 块窗口）、`tftp-rrq-winsize65535-wrap2`（跨回绕）、`tftp-rrq-blocks65536-parse`、`tftp-regress-blocks-65536-wrap` / `tftp-regress-blocks-wrap-seq`：属**设计文档级规模**，P5 执行面按现状（short-circuit / `min_packets`）保留或拆分，**拆分须登记去向，不得静默删**（§9.14）。

**整数对账**：226 = 正例 186（A 175 + B 11）+ 负例 40（C 族 40，其中 D 族 7 例删除 → 改写后 33 + E 族 4 例改判读/迁层）→ **改写后预期 219 例** + A′ 补例 3（T-TFTP-V6 / T-TFTP-WRQ-RETX / T-TFTP-WRQ-TIDCHG）= **222 例**。D/E/F 三族为 C 族与 A/B 族的**子集标注**（不另计基数），仅 D 族 7 例改变基数。

---

## §17. 去扁平改写清单（P5 动作；本文 P1–P3 只列清单不动文件）

| # | 改写项 | 形状 | 验收 |
|---|---|---|---|
| G-TFTP-1 | 业务 23 键迁层：`registry.go:187-192` 增 `Fields`（23 键，键名=json 标签，数值键带 Min/Max）→ `schemagen` 重跑提交生成文件；`chain_planner_translate.go` 增 `case "tftp"` 层翻译（dns 分支 `chain_planner_translate.go:1801` 范式）；`strategy_convert.go` `parseTFTPConfig` 升为导出 `ParseTFTPConfigFromMap` 单一真相 + `CheckProtoFlat` 增 tftp presence 判死分支（mqtt 先例（`strategy_convert.go:8305-8308` 的 presence 分支文案）同构） | `registry.go` + `chain_planner_translate.go` + `strategy_convert.go` + 生成表 | 目标形状 spec_json（§13.2 样例）端到端跑通；顶层 `tftp` presence 负例（§13-P2）红→绿 |
| G-TFTP-2 | `checkTFTPServerTID`（`schema/semantic.go:442-459`（函数 `:442`；锚词 `:457`））改读层 config 的 `server_tid`（现读顶层 `config["tftp"]`，迁层后静默失效）+ `strategy.json`（`properties/config/properties/tftp`，`grep -n '"tftp":' strategy.json` = `:288`） 子配置形状按 13.17 迁移或登记过渡 | `semantic.go` + `schemas/v1/strategy.json` + `semantic_test.go` | `flows>1` + 层内 `server_tid` 固定 → 锚词不变；单测同步 |
| G-TFTP-3 | 非法/未知 opcode 注入能力（§12.2 矩阵三格缺）：生成器需支持"发任意 opcode 包"以覆盖 ERROR(4) 应答/丢弃面 | `tftp` 协议包（builder/plan/层 config 键） | 3 格用例红→绿；属**代码改动**，须先补 D 条目细则再开工 |
| G-TFTP-4 | 存量 226 例改写（§13.1 去向表 + §16 分族清单）：186 正例（A 175 + B 11 层动态化）+ 40 负例（C 33 保留改写 + D 7 删除 + E 4 改判读/迁 vlan 层）+ A′ 补例 3（**T-TFTP-V6** IPv6 对称例 / **T-TFTP-WRQ-RETX** / **T-TFTP-WRQ-TIDCHG**） | `cases/tftp.json` | 全量 suite 绿（`CASE_PROTO=tftp`）+ `pipe_gate.sh tftp` 门2-1 顶层旧键零残留（非负例顶层键=`layers`+`strategy_fc`，余 0） |
| G-TFTP-5 | 现网产品级出处（§4.13）：商业化 tftp 客户端/服务器（tftpd-hpa / atftpd / PXE dnsmasq / 厂商客户端）行为确认 | 抓包（三选一） | 结论写入 §12.4 路②/§12.5；不挡 P5 |
| G-TFTP-6 | RFC 1350 §4 合规的 TID 校验序列（丢包 + 向错误源回 ERROR(5) + 继续旧 TID）不实现——与 S9 扩展语义并存，须在文档/用例中标"互操作负向" | 设计注记（`06-tftp-testcase.md` §4 负例契约） | 声明落档；不新增代码 |
| G-TFTP-7 | 驱动期 error → 空流的 task error 收敛（跨协议框架面，modbus G-MODBUS-3 同款） | 框架（`layer_gen.go` / `chain_planner.go` 契约） | **上报主线程**（车道不得自改框架）；本文只登记 |
| G-TFTP-8 | `coverage_gate.py` 增 `check_tftp` 块（方案 §2 M1：登记归车道 B 在分支内编写；实读 `trafficgen/tools/coverage_gate.py` 今日 **0 处** tftp 命中） | `tools/coverage_gate.py` | 门2-4 覆盖反查出口 0（未登记黄灯=红） |

---

## §18. 修订记录（P-PIPE 轮）

| 版本 | 日期 | 内容 |
|---|---|---|
| v2.1.0-P1 | 2026-09-26 | P1：§12 规范矩阵（八项 8 行 + 子表① 24 格 + 子表② 19 行 + 三路对照 + 候选方案对比）＋ §12.0 现状口径（tftp 层已注册 `registry.go:187-192`、Fields 空、配置走顶层 flat 子映射、**226 例今日经 MCP 全红**）；`tshark -G fields` `tftp.*` **31 字段**实测 + 4 项 dissector dissector 行为探针 |
| v2.1.0-P2 | 2026-09-26 | P2：§13 门1 §1–§14 十四行表（§1/§3/§12 强制展开；§13.1 九键去向 + §13.2 两个 spec_json 样例 + §13.3 五件套 + §13.4 动态清单 + §13-P2 presence + §13.5 链路可达性）＋ §14 D-TFTP-1 八要素（接线行号实读：`registry.go:187-192` / `strategy_convert.go:1258-1262+7215-7245+8273` / `chain_planner_translate.go:69-71+679+742-746` / `chain_planner.go:149+701+956` / `semantic.go:442-459` / `strategy.json`（`properties/config/properties/tftp`，`grep -n '"tftp":' strategy.json` = `:288`）） |
| v2.1.0-P3 | 2026-09-26 | P3：§15 固定动作（§3.15 三项 + A′/B′ 五分类 + 9.52 对账 51 点 + 3.14 豁免审计 + 三源回指 + §15.6 断言通道与口径校准 + §15.7 性能六要素）＋ §16 存量 226 例审计（**实读整数分账 226 = 正 186（A 175 + B 11）+ 负 40（C 40，含 D 等价覆盖 7 删除 / E 改判读 4 / F 巨例 5）**）＋ §17 去扁平改写清单 G-TFTP-1…8 ＋ 新建 `06-tftp-testcase.md`（T-TFTP v1.0.0） |
| v2.1.0-P6 | 2026-09-27 | P6 终审修轮（M1/文案）：§12.3 行数实数订正 **20→19 行**（已覆 19→18）；§15.3 对账 **52/41 → 51/40**（40+6+5=51 ✓）+ 补 **P5 后口径 43/3/5**（43+3+5=51 ✓）；§15.2 同步 19/18；§12.3 地址族行订正（注册表无 `ipv6` 层——IPv6 经 `ip` 层 v6 字面量表达）；§14 补 WRQ 侧 TID 变更叙事（N6） |

**P1–P3 勘误汇总（对既有 v2.0.2 文档）**：①§7 的 T-001~T-241 为**历史设计层编号**（241 条），与 `cases/tftp.json` 的 226 例 `tftp-*` ID 非同一体系——ID 权威在 testcase 契约（`06-tftp-testcase.md` §2）+ 本文件 §16 去向表；②旧 §1.1/§5/§6 的配置示例含顶层扁平键（`src_ip`/`dst_port`/`tftp` 子映射），**按 1.4/1.5 属跑偏示例**——其 wire 语义仍有效（§6 HexDump 的字节序列不变），但**配置形状以 §13.2 目标形状为准**（1.9 口径：目标形状今天跑不通，需先补 G-TFTP-1）；③旧 §10.4「集成点」表（`types.go` / `strategy_convert.go` / `engine.go` / `tftp.go` / `builder.go` / `MapToFlow`）为 **P4a 之前的接线描述**，现状接线以 §12.0/§14.1 实读为准。

