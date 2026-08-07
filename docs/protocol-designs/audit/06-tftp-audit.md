# TFTP 设计文档对抗审计报告

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md`（v1.0，1329 行，60 测试用例）
**审计依据**：RFC 1350（TFTP Rev.2）、RFC 2347（选项扩展）、RFC 2348（blksize）、RFC 2349（timeout/tsize）、RFC 1783（multicast/TID change，Informational）、RFC 7440（windowsize，v2 扩展）、RFC 6335（端口范围）、CLAUDE.md §Testing Policy 8 条规则
**审计方法**：交叉对抗——逐节对照 RFC 原文尝试反驳设计正确性，默认"有 bug"除非证据确凿；测试用例按 CLAUDE.md 8 条规则逐条审核
**审计时间**：2026-08-03
**审计员**：主线程直接完成（子代理 3 次失败后改为主线程审计）

---

## 1. 审计概览

### 1.1 文档结构

| 章节 | 内容 | 行数 | 审计结论 |
|------|------|------|----------|
| §1 协议概述 | 特性、业务场景、项目位置 | 1-46 | 基本准确 |
| §2 报文格式 | opcode/RRQ/WRQ/DATA/ACK/ERROR/OACK | 47-167 | 多处错误 |
| §3 Config 结构体 | TFTPConfig 字段定义 | 168-279 | 字段语义混乱 |
| §4 状态机 | RRQ/WRQ/ERROR/OACK 子状态 | 280-381 | 状态机正确 |
| §5 Plan 输出 | 包序列、端口规则 | 382-460 | 端口规则正确 |
| §6 业务场景 | 12 个场景 + 边界 + 异常 | 461-1043 | 多处自相矛盾 |
| §7 测试用例 | 60 条用例 | 1044-1151 | 覆盖不全 + 错误用例 |
| §8 审计检查清单 | F/P/S/O/E/B/C/I 共 48 项 | 1152-1236 | 检查清单本身有缺陷 |
| §9 集成点 | 代码集成、测试文件 | 1237-1291 | 合理 |

### 1.2 问题汇总

| 严重度 | 数量 | 关键问题 |
|--------|------|----------|
| CRITICAL | 8 | BlocksCount 语义与 RFC 1350 冲突、自动追加规则自相矛盾、TID 变更方向反转 |
| HIGH | 10 | TSize 双语义、ErrorAfterBlock 推导缺失、重传 ACK 非标准 |
| MEDIUM | 10 | OACK 描述与状态机矛盾、默认 ErrMsg 映射缺失、IncludeOACK 语义模糊 |
| LOW | 7 | 最大文件大小描述不全、字段类型不一致、用例引用错误 |
| **总计** | **35** | — |

### 1.3 总体评级

**不合格（需返工）**。设计在状态机层面正确，但 Config 字段语义、BlocksCount 与 RFC 的兼容性、TID 变更场景、自动追加规则等核心环节存在 8 处 CRITICAL 问题，直接按此设计实现会导致生成的 TFTP 流无法与真实 TFTP 客户端/服务器互操作。测试用例 60 条数量充足但 6 条与设计自身规则冲突，CLAUDE.md §Testing Policy 第 1/2/4 条不达标。

---

## 2. CRITICAL 问题

### C1：BlocksCount 语义与 RFC 1350 不兼容

**位置**：§3 `BlocksCount` 字段（行 228-231）、§6.2（行 532）、§6.10.1（行 827）

**描述**：设计让 `BlocksCount` "直接控制 DATA 数量"，并在 §6.2 明确说 "trafficgen 的语义是 `BlocksCount=N` 直接控制 DATA 数量，**不**自动追加 0 字节块"。但 RFC 1350 §6 规定："The last packet... must be less than 512 bytes. If the file is an exact multiple of 512 bytes, a final packet of 0 bytes must be sent."

**问题**：当用户设 `BlocksCount=2, BlkSize=512` 且每块填满 512 字节时，trafficgen 只发 2 个 DATA（都 = 512B），不发 0 字节末块。真实 TFTP 接收方会因没收到 < blksize 的末块而继续等待，最终超时。这意味着 trafficgen 生成的"满块"流不是合法 TFTP 流。

**依据**：RFC 1350 §6 "If the file is an exact multiple of 512 bytes, a final packet of 0 bytes must be sent." 这是 MUST 级别要求。

**修复建议**：
1. 引入 `AutoAppendFinalBlock bool` 字段，默认 true，遵循 RFC 1350。
2. 当 `BlocksCount×BlkSize == TSize && TSize > 0` 时自动追加 0 字节块。
3. 当 `AutoAppendFinalBlock=false` 时允许用户显式禁用 RFC 行为（用于测试非标流）。
4. Validate 在 `BlocksCount>0 && TSize>0 && BlocksCount×BlkSize == TSize && AutoAppendFinalBlock` 时自动 +1 到实际 DATA 数。

---

### C2：§6.10.1 自动追加规则与 §6.2 显式不追加自相矛盾

**位置**：§6.2（行 532）vs §6.10.1（行 838）

**描述**：
- §6.2："按 RFC 1350 应追加 DATA#3（0 字节）。但 trafficgen 的语义是 `BlocksCount=N` 直接控制 DATA 数量，**不**自动追加 0 字节块。"
- §6.10.1："planner 应提供一种机制让用户指定'末块为 0 字节'——通过 `BlocksCount` + 推导：当 `BlocksCount×BlkSize == TSize` 且 `TSize > 0` 时自动追加 0 字节块。该规则在 Validate 中检查并附加。"

**问题**：同一文档两处规则完全相反。§6.2 说"不自动追加"，§6.10.1 说"自动追加"。规划者无法判断哪个为真，实现者会随机选一个，测试用例 T20（行 1083）按"自动追加"假设但 T02（行 1055）按"不自动追加"假设。

**依据**：文档内部一致性原则。同一字段语义不能在两节相互矛盾。

**修复建议**：统一为 C1 的方案（AutoAppendFinalBlock 字段 + 默认 true 遵循 RFC）。删除 §6.2 的"不自动追加"声明。

---

### C3：§6.10.1 输入 spec 与期望包序列不匹配

**位置**：§6.10.1（行 817-838）

**描述**：输入 spec：`blocks_count=3, blksize=512, tsize=1024, data_payload_pattern=0xFF`。期望包序列：`DATA#1(512B) → ACK#1 → DATA#2(512B) → ACK#2 → DATA#3(0B) → ACK#3`。

**问题**：
- 3×512 = 1536 ≠ TSize=1024，自动追加规则（"BlocksCount×BlkSize == TSize 时追加"）不触发。
- 但期望 DATA#3 是 0 字节，意味着 BlocksCount=3 中第 3 块就是 0 字节——这与 §3 BlocksCount "number of DATA blocks to emit (excluding trailing 0-byte terminator)" 矛盾。
- TSize=1024 表示文件 1024 字节，但 BlocksCount=3×512=1536 > 1024，超出文件大小。
- data_payload_pattern=0xFF 但 DATA#3 期望 0 字节——pattern 与实际 Data 不一致。

**依据**：字段语义逻辑一致性。

**修复建议**：
1. 改输入 spec 为 `blocks_count=2, tsize=1024`，触发 2×512=1024=TSize 自动追加 DATA#3(0B)。
2. 或引入 `FinalBlockZero bool` 字段显式控制末块为 0 字节。
3. Validate 检查 `BlocksCount×BlkSize >= TSize` 时报错（除非 FinalBlockZero=true）。

---

### C4：§6.11.1 ServerTID 变更场景的 ERROR 发起方反转

**位置**：§6.11.1（行 967-997）

**描述**：设计期望 "旧 TID 发 ERROR code=5（Unknown TID）告知客户端，新 TID 继续发 DATA"。包序列第 4 步："ERROR code=5（down, :60000 → client）→ 旧 TID 通知"。

**问题**：RFC 1783 §3 的 TID change 机制是：**接收方**检测到发送方 TID 变化时，**接收方**发 ERROR code=5 通知旧 TID 的发送方"我不再认你"。设计的"旧 TID 主动发 ERROR"是反向的——旧 TID 已经停止发送，不可能主动发 ERROR。

**实际 RFC 1783 §3 流程**：
1. 服务器用 TID_A 发 DATA#1, DATA#2。
2. 服务器切换到 TID_B 发 DATA#3。
3. 客户端收到 TID_B 的 DATA#3，检测到 TID 变化。
4. 客户端向 TID_A 发 ERROR code=5（Unknown TID）告知"旧 TID 已失效"。
5. 客户端继续向 TID_B 发 ACK#3。

**依据**：RFC 1783 §3 "If a TFTP endpoint receives a packet from a new source TID, it should send an error packet to that new source TID"。注意是"收到新 TID 的包后向新 TID 回 ERROR"，不是"旧 TID 主动发 ERROR"。

**修复建议**：
1. 重写 §6.11.1 包序列：
   ```
   1. RRQ（up, → :69）
   2. DATA#1（down, :60000 → client）, ACK#1（up）
   3. DATA#2（down, :60000 → client）, ACK#2（up, → :60000）
   4. DATA#3（down, :61000 → client）（新 TID）
   5. ERROR code=5（up, client → :61000）（客户端通知新 TID"我之前认的是 60000"）
   6. ACK#3（up, → :61000）（客户端接受新 TID 继续）
   7. DATA#4（down, :61000 → client）, ACK#4（up）
   ```
2. ERROR 方向改为 up（客户端发起），不是 down。
3. ERROR 的 DstPort 是新 TID（61000），不是旧 TID（60000）。

---

### C5：§6.11.1 包序列时序矛盾

**位置**：§6.11.1（行 984-992）

**描述**：期望包序列第 5 步注释："ACK#2（up, → :60000）（注：客户端在 ERROR 之前已发 ACK#2 响应 DATA#2）"。但包序列中 ACK#2 排在 ERROR（第 4 步）之后。

**问题**：注释与排序矛盾。如果 ACK#2 在 ERROR 之前已发，包序列应是 `DATA#2 → ACK#2 → ERROR`，而不是 `DATA#2 → ERROR → ACK#2`。这种时序混乱会导致实现者按错误顺序生成包。

**依据**：TFTP 是停止-等待协议，每个 DATA 后必须紧跟 ACK 才能发下一个 DATA。DATA#2 与 ACK#2 之间不能插入 ERROR。

**修复建议**：按 C4 的修复后的序列重排，确保 DATA#N → ACK#N 严格成对出现。

---

### C6：§2.3 Block# wrap-around 未定义且与最大文件大小矛盾

**位置**：§2.3（行 96）、§1.1（行 28）

**描述**：§2.3 说 "Block# 从 1 开始递增；wraps around at 65535 → 0（实际罕见，因文件大小限制）"。§1.1 说 "最大文件大小 512×65535 ≈ 32 MB（blksize=512）"。

**问题**：
- wrap-around 方向未定义：65535 → 0 还是 65535 → 1？
- "罕见"判断错误：blksize=8（最小值）时，524280 字节（512KB）文件就会触发 wrap，这在嵌入式固件升级场景并不罕见。
- blksize=65464（最大值）时，65535×65464 ≈ 4 GB，远超 uint32 TSize 上限（4 GB - 1 字节），实际不会 wrap 但 TSize 会溢出。
- 设计未提供 wrap-around 的测试用例（T25 只测 Block#=65535 不溢出，没测 wrap）。

**依据**：RFC 1350 未定义 wrap-around 行为（RFC 假设 block# 不会超过 65535，因为 TFTP 设计初衷是小文件传输）。trafficgen 作为流量生成器可以自定义 wrap 行为，但必须明确定义。

**修复建议**：
1. 明确 wrap 方向：`block# = (block# + 1) mod 65536`，即 65535 → 0。
2. 或拒绝 wrap：Validate 检查 `BlocksCount > 65535` 时报错。
3. 增加 T25b 测试用例：`blocks_count=65536`，期望 Block# wrap 到 0 或 Validate 拒绝。
4. §1.1 补充 blksize=65464 时的最大文件大小（受 TSize uint32 限制）。

---

### C7：§6.6 TSize 字段双语义导致用户困惑

**位置**：§3 `TSize` 字段（行 200-204）、§6.6（行 617-640）

**描述**：§3 字段说明："For RRQ: client writes 0, server echoes actual size in OACK. For WRQ: client writes actual size, server echoes." §6.6 输入 spec `tsize: 2048` + `mode: read`，期望 RRQ 中 tsize="0"，OACK 中 tsize="2048"。

**问题**：TSize 字段在 RRQ 模式下不是 RRQ 报文中写入的值（始终写 "0"），而是 OACK 回显的值；在 WRQ 模式下既是 WRQ 报文中写入的值也是 OACK 回显的值。这种双语义让用户困惑：用户设 `tsize: 2048` 时无法直观判断这个值会出现在哪个报文。

**依据**：字段语义应单一明确。RFC 2349 §2 区分了 "write request" 与 "read request" 的 tsize 语义，但 trafficgen 的 TSize 字段合并了两种语义。

**修复建议**：
1. 拆分为两个字段：`ClientTSize uint32`（WRQ 时写入 WRQ 报文，RRQ 时强制 0）+ `ServerTSize uint32`（OACK 回显值）。
2. 或保留单字段但在字段名上明确：`TSizeOackEcho uint32`，文档说明 "RRQ 模式下此值仅在 OACK 中出现；WRQ 模式下同时出现在 WRQ 和 OACK"。
3. 增加测试用例：`mode=write, tsize=2048`，期望 WRQ 中 tsize="2048"，OACK 中 tsize="2048"。

---

### C8：§3 ErrorAfterBlock 与 BlocksCount=0（derive）的交互未定义

**位置**：§3 `ErrorAfterBlock`（行 219-222）、§3 `BlocksCount`（行 228-231）

**描述**：BlocksCount=0 表示 "derive from Payload/FileSource + BlkSize"。ErrorAfterBlock=N 表示 "emit DATA#1..N + ACK#1..N then inject ERROR"。当 BlocksCount=0（derive）+ ErrorAfterBlock=N 时，planner 无法判断 N 是否合法（因为总块数未知）。

**问题**：§6.8.2 输入 spec 没提供 BlocksCount 也没提供 Payload/FileSource，但 ErrorAfterBlock=3。planner 应该推导出多少块？如果推导出 3 块，那 ErrorAfterBlock=3 == BlocksCount=3，发完 3 块再发 ERROR——但既然发完了为什么还要 ERROR？如果推导出 5 块，那 ErrorAfterBlock=3 中途发 ERROR——合理。但推导逻辑未定义。

**依据**：字段交互规则应完备。CLAUDE.md §Testing Policy 第 1 条要求"spec-driven"，但此处 spec 缺失。

**修复建议**：
1. Validate 强制：`ErrorAfterBlock > 0` 时必须显式设 `BlocksCount`（不允许 derive）。
2. 或 Validate 检查：`ErrorAfterBlock > 0 && BlocksCount == 0` 时报错 "error_after_block requires explicit blocks_count"。
3. 修复 §6.8.2/6.8.3/6.8.4 的输入 spec，显式设 BlocksCount。

---

## 3. HIGH 问题

### H1：§2.4 ACK Block# 字段说明不完整

**位置**：§2.4（行 111）

**描述**：表说 "Block# | uint16 BE | 所确认 DATA 的 block#；WRQ 场景下服务器收到 WRQ 后回 ACK#0 表示'准备好接收'"。但 §4.2 明确："WRQ+OACK 场景没有 ACK#0"。

**问题**：§2.4 的 "WRQ 场景" 未限定为 "WRQ 无 OACK 场景"，与 §4.2 矛盾。

**依据**：RFC 2347 §2.1 "If the server returns an OACK, the client should then begin the transfer with a DATA packet... no ACK#0 is sent."

**修复建议**：§2.4 改为 "WRQ 无 OACK 场景下服务器收到 WRQ 后回 ACK#0；WRQ+OACK 场景无 ACK#0，客户端直接发 DATA#1"。

---

### H2：§6.8.2 输入 spec 不完整导致期望无法实现

**位置**：§6.8.2（行 693-715）

**描述**：输入 spec 没提供 `blocks_count`、`data_payload_pattern`、`Payload`、`FileSource`。期望 8 包：RRQ + 3×(DATA+ACK) + ERROR。

**问题**：BlocksCount=0（derive）但无 Payload/FileSource 可推导。planner 无法生成 DATA#1/2/3 的 Data 内容。期望 8 包无法实现。

**依据**：CLAUDE.md §Testing Policy 第 1 条"spec-driven"——测试用例必须可执行。

**修复建议**：补充输入 spec：`blocks_count: 3, data_payload_pattern: "AA"`。

---

### H3：§6.8.3 同样存在输入 spec 不完整问题

**位置**：§6.8.3（行 717-738）

**描述**：与 H2 相同问题。输入 spec 缺 `blocks_count` 和 payload 来源。

**修复建议**：补充 `blocks_count: 2, data_payload_pattern: "BB"`。

---

### H4：§6.11.2 重传场景包含非标准的 ACK 重传

**位置**：§6.11.2（行 999-1024）

**描述**：期望包序列包含 "ACK#2（重传）"——客户端收到重传 DATA#2 后再次发 ACK#2。

**问题**：RFC 1350 §4 "If a packet is lost, the sender will timeout and retransmit." 发送方（DATA 发送方）重传 DATA，接收方收到后重传 ACK——这是标准行为。但 trafficgen 的 planner 是预先规划所有包的，"重传"只是把同一包发两次。如果重传 DATA#2 后客户端也重传 ACK#2，那 planner 必须在序列中插入两个 ACK#2——但 ACK#2 的"重传"是响应重传 DATA#2 的，时序上 ACK#2(重传) 必须在 DATA#2(重传) 之后。

**问题细节**：期望序列 "DATA#2(第一次) → ACK#2(第一次) → DATA#2(重传) → ACK#2(重传)" 是合理的。但 §3 RetransmitBlocks 字段说 "list of block#s to retransmit (same DATA emitted twice)"——只说重传 DATA，没说重传 ACK。期望序列与字段描述不一致。

**依据**：字段描述与测试期望应一致。

**修复建议**：
1. §3 RetransmitBlocks 字段说明改为 "list of block#s whose DATA and corresponding ACK are both emitted twice"。
2. 或增加 `RetransmitACKs bool` 字段控制是否重传 ACK。

---

### H5：§7.1 T08 与 §6.10.1 自动追加规则冲突

**位置**：§7.1 T08（行 1061）

**描述**：T08 输入 `blksize=1024, tsize=4096, blocks_count=4`。4×1024=4096=TSize，按 §6.10.1 自动追加规则应追加 DATA#5(0B)。但 T08 期望 "RRQ → OACK → ACK#0 → DATA/ACK×4"（11 包），没有 DATA#5。

**问题**：T08 与 §6.10.1 自动追加规则冲突。如果按 C1/C2 修复后（默认自动追加），T08 期望应是 13 包（含 DATA#5(0B) + ACK#5）。

**依据**：测试用例与设计规则一致性。

**修复建议**：T08 期望改为 13 包，或在 T08 输入 spec 加 `auto_append_final_block: false`。

---

### H6：§7.1 T11 缺少 BlocksCount 导致期望无法实现

**位置**：§7.1 T11（行 1064）

**描述**：T11 输入只说 `server_tid=60000`，没说 BlocksCount。期望 3 包（RRQ + DATA#1 + ACK#1）。

**问题**：缺省 BlocksCount=0（derive），无 Payload/FileSource 可推导。期望 3 包无法实现。

**修复建议**：T11 输入补充 `blocks_count: 1, data_payload_pattern: "AA"`。

---

### H7：§3 ServerTID 默认值 0 的 Validate 行为未定义

**位置**：§3 `ServerTID`（行 207-209）、§7.4 T35（行 1103）

**描述**：§3 说 "0=planner picks random ephemeral (49152-65535)"。§7.4 T35 只测 `server_tid=80` 拒绝，没测 `server_tid=0` 接受。

**问题**：Validate 是否接受 `server_tid=0`？设计未明说。如果接受，planner 在 Plan 阶段随机选端口——但 Plan 是确定性的（相同 spec 应产生相同包序列），随机端口会破坏可重现性。

**依据**：CLAUDE.md §Testing Policy 第 5 条"assert observable outcomes"——随机端口的测试无法断言具体值。

**修复建议**：
1. Validate 接受 `server_tid=0`，但 Plan 时用确定性伪随机（基于 FlowID 的 hash）选端口。
2. 或要求用户必须显式设 `server_tid`，0 视为 Validate 错误。
3. 增加 T12b 测试：`server_tid=0` 两次 Plan，断言两次产生的 ServerTID 相同（确定性）。

---

### H8：§7.2 T19 ErrCode=5 默认 ErrMsg 映射未定义

**位置**：§7.2 T19（行 1077）、§3 `ErrorMsg`（行 215-217）

**描述**：T19 期望 "ErrMsg 含 'Unknown TID'（默认）"。但 §3 ErrorMsg 字段说 "Empty allowed"，未说明 ErrCode 与默认 ErrMsg 的映射。

**问题**：当用户设 `error_code=5` 但 `error_msg=""` 时，planner 是否自动填 "Unknown TID"？设计未规定。如果自动填，那其他 ErrCode（1/2/3/4/6/7）的默认 ErrMsg 是什么？

**依据**：RFC 1350 §5 ErrMsg 是 "NetASCII string... may be omitted"。设计应明确默认值规则。

**修复建议**：增加 ErrCode → 默认 ErrMsg 映射表：
| ErrCode | 默认 ErrMsg |
|---------|-------------|
| 0 | "Not defined" |
| 1 | "File not found" |
| 2 | "Access violation" |
| 3 | "Disk full or allocation exceeded" |
| 4 | "Illegal TFTP operation" |
| 5 | "Unknown transfer ID" |
| 6 | "File already exists" |
| 7 | "No such user" |

当 `error_msg=""` 时使用默认值；当 `error_msg` 非空时覆盖默认值。

---

### H9：§6.10.2/6.10.3 blksize 边界用例缺 Data 内容来源

**位置**：§6.10.2（行 842-859）、§6.10.3（行 861-879）

**描述**：§6.10.2 输入 `blksize=8, blocks_count=1`，期望 "DATA#1 Data 长度 = 8（若文件 ≥ 8 字节）"。§6.10.3 类似。

**问题**：输入 spec 没提供 `data_payload_pattern` 或 Payload。planner 应如何填充 DATA#1 的 8 字节 Data？设计未说明。

**依据**：CLAUDE.md §Testing Policy 第 5 条"assert observable outcomes"——Data 内容必须可断言。

**修复建议**：补充输入 `data_payload_pattern: "AA"`，期望 "DATA#1 Data = 8×0xAA"。

---

### H10：§3 ServerTIDChange 与 RetransmitBlocks 共存规则未定义

**位置**：§3.2（行 273-278）

**描述**：§3.2 只说 "ServerTIDChange 与 ErrorCode 互斥"。但 ServerTIDChange + RetransmitBlocks 是否合法未规定。

**问题**：如果 ServerTIDChangeAtBlock=2 + RetransmitBlocks=[2]，重传的 DATA#2 用旧 TID 还是新 TID？设计未规定。

**修复建议**：
1. Validate 拒绝 ServerTIDChange + RetransmitBlocks 共存（报错 "server_tid_change and retransmit_blocks are mutually exclusive"）。
2. 或明确规定：重传块用原 TID（即 ServerTIDChangeAtBlock 之前的 TID）。

---

## 4. MEDIUM 问题

### M1：§2.7 OACK 描述与 §4.2 状态机矛盾

**位置**：§2.7（行 155）、§4.2（行 344）

**描述**：§2.7 说 "OACK 由服务器在 RRQ/WRQ 之后、第一个 DATA（RRQ）或 ACK#0（WRQ）之前发送"。但 §4.2 明确："WRQ+OACK 场景客户端收到 OACK 后直接发 DATA#1（不发 ACK#0）"。

**问题**：§2.7 说 WRQ+OACK 后有 ACK#0，§4.2 说没有。矛盾。

**修复建议**：§2.7 改为 "OACK 由服务器在 RRQ/WRQ 之后、第一个 DATA（RRQ）或第一个 DATA（WRQ+OACK）之前发送；WRQ 无 OACK 时服务器发 ACK#0 而非 OACK"。

---

### M2：§3 IncludeOACK 字段语义模糊

**位置**：§3 `IncludeOACK`（行 239-241）

**描述**："when true, server sends OACK even with no options (OACK carries just `0006`)"。

**问题**：当 IncludeOACK=true 且无选项时，客户端应如何响应？ACK#0？DATA#1？设计未说明。OACK 后的状态机分支未定义。

**修复建议**：
1. 明确 IncludeOACK=true + 无选项时，按 RRQ+OACK 状态机走（客户端发 ACK#0，服务器发 DATA#1）。
2. 或按 WRQ+OACK 状态机走（客户端直接发 DATA#1）。
3. 增加测试用例 T13b：IncludeOACK=true + 无选项 + mode=read，期望 5 包（RRQ + OACK + ACK#0 + DATA#1 + ACK#1）。

---

### M3：§3 ErrorCode 类型 uint8 与 §2.6 ErrCode 类型 uint16 不一致

**位置**：§3 `ErrorCode`（行 212）、§2.6（行 124）

**描述**：§2.6 说 "ErrCode | uint16 BE"。§3 ErrorCode 字段类型是 uint8。

**问题**：uint8 范围 0-255，足够表示 0-7，但与 §2.6 的 uint16 不一致。实际写入 ERROR 报文时需转 uint16，设计未说明转换规则。

**修复建议**：
1. §3 ErrorCode 类型改为 uint16（与 §2.6 一致）。
2. 或在 §3 字段说明加 "wire format: uint16 BE; Go type: uint8 (0-7)"。

---

### M4：§6.7 OPTIONS timeout 的输入 spec 缺少 BlocksCount

**位置**：§6.7（行 643-665）

**描述**：输入 spec `blocks_count=1`（隐含），但期望 5 包。

**问题**：输入 spec 明确写了 `blocks_count: 1`，但未提供 `data_payload_pattern`。DATA#1 的 Data 内容如何填充？

**修复建议**：补充 `data_payload_pattern: "AA"`。

---

### M5：§6.10.4 filename 空字符串的 Validate 错误未覆盖 `\0` 字节

**位置**：§6.10.4（行 881-895）

**描述**：设计只测 filename="" 拒绝。未测 filename 含 `\0` 字节的情况。

**问题**：filename 含 `\0` 会破坏 RRQ 报文格式（`\0` 是字段终止符）。Validate 应拒绝。

**依据**：RFC 1350 §4 "The filename is a sequence of bytes... terminated by a zero byte"——filename 内部不能含 `\0`。

**修复建议**：增加 T26b 测试：`filename="a\0b"`，期望 Validate 错误 "tftp: filename must not contain null byte"。

---

### M6：§6.10.5 filename 含路径分隔符未说明 `\0` 处理

**位置**：§6.10.5（行 899-913）

**描述**：设计说 "trafficgen 不解释路径，原样放入 RRQ"。

**问题**：未说明 filename 含 `\0` 字节时的处理（应拒绝，见 M5）。

**修复建议**：在 §6.10.5 加注 "filename 含 `\0` 字节时 Validate 拒绝（见 M5）"。

---

### M7：§7.4 T34 "TFTPConfig 缺失" 未说明触发条件

**位置**：§7.4 T34（行 1102）

**描述**：T34 期望 "tftp: TFTPConfig is required"。但 §3 没说 TFTPConfig 是必需的（FlowSpec.TFTP 是指针，可以是 nil）。

**问题**：当 spec.Protocol="tftp" 但 TFTPConfig=nil 时，应报错。但设计未说明 Protocol 字段如何与 TFTPConfig 关联。trafficgen 的 FlowSpec 是否有 Protocol 字段？设计未说明。

**修复建议**：
1. 明确 Validate 规则："当 FlowSpec.TFTP == nil 时报错"。
2. 或 "当 FlowSpec.L4Config.Protocol == "udp" 且 FlowSpec.TFTP == nil 且其他 L7 协议字段（DNS/DHCP）也为 nil 时，不报错（纯 UDP 流）"。
3. 明确 TFTP 流的识别条件：FlowSpec.TFTP != nil。

---

### M8：§8.1 F10 "tsize 在 RRQ 中永远写 '0'" 与字段语义易混淆

**位置**：§8.1 F10（行 1169）

**描述**：F10 检查项 "tsize 在 RRQ 中永远写 '0'（RFC 2349 §2），WRQ 中写实际大小"。

**问题**：检查项本身正确，但与 §3 TSize 字段的双语义（C7）叠加，容易让实现者误以为 "TSize 字段在 RRQ 模式下应设为 0"。实际上 TSize 字段在 RRQ 模式下是 OACK 回显值，不是 RRQ 报文中的值。

**修复建议**：F10 改为 "RRQ 报文中 tsize 选项值永远为 '0'（RFC 2349 §2）；OACK 中 tsize 值为 spec.TFTP.TSize"。

---

### M9：§7.6 T52 多选项 RRQ 字节精确的选项顺序未在 §3 强制

**位置**：§7.6 T52（行 1130）、§8.4 O4（行 1196）

**描述**：T52 期望 "字节 = `00 01 <file>\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 0\0`"——顺序是 blksize, timeout, tsize。§8.4 O4 检查项 "多选项时 RRQ 中的顺序 = `blksize, timeout, tsize`（固定顺序）"。

**问题**：设计要求固定顺序，但 §3 字段定义中 BlkSize/Timeout/TSize 的 struct 字段顺序是 BlkSize, Timeout, TSize（行 194-204），与期望顺序一致。但 Go struct 字段顺序不保证 JSON 解析顺序，planner 必须显式按 blksize→timeout→tsize 顺序写入。设计未在 §3 强制 planner 的写入顺序。

**修复建议**：§3 加注 "planner 写入 RRQ/OACK 选项时按 blksize→timeout→tsize 固定顺序，与 struct 字段顺序一致"。

---

### M10：§9.1 集成点 "MapToFlow" 引用未验证

**位置**：§9.1（行 1249）

**描述**：设计说 "MapToFlow | `trafficgen/internal/core/maptoflow*.go` | 添加 `"tftp"` case，调用 `convertTFTP`"。

**问题**：实际项目中是否所有协议都通过 MapToFlow 注册？设计未验证现有代码结构。

**修复建议**：审计实现时确认 `maptoflow*.go` 文件存在且其他协议（如 DNS/DHCP）的注册模式，TFTP 应遵循相同模式。

---

## 5. LOW 问题

### L1：§1.1 最大文件大小描述不全

**位置**：§1.1（行 28）

**描述**："最大文件大小 | block# 是 uint16，理论 512×65535 ≈ 32 MB（blksize=512）"。

**问题**：未说明 blksize=65464 时的最大文件大小（65535×65464 ≈ 4 GB，但受 TSize uint32 上限 4 GB-1 字节限制）。

**修复建议**：补充 "blksize=65464 时理论 4 GB-1 字节，但受 TSize uint32 上限制约"。

---

### L2：§2.2 RRQ/WRQ 报文格式图分隔符不一致

**位置**：§2.2（行 68-72）

**描述**：图中 Option1/Value1/OptionN/ValueN 之间用 `+---+` 分隔，Option 与 Value 之间也用 `+---+`。

**问题**：图形清晰度可改进——Option 和 Value 是配对的，可用空格分隔配对，`+---+` 分隔不同配对。

**修复建议**：重绘图形，配对内用空格，配对间用 `+---+`。

---

### L3：§6.11.3 引用错误（T27 应为 T46）

**位置**：§6.11.3（行 1042）

**描述**：§6.11.3 说 "仅在测试用例清单中列出（§7 用例 T27）"。但 §7 用例 T27 是 "mode 非法"（Validate 拒绝），不是 NAT 端口变化。§7.5 T46 才是 NAT 端口变化。

**修复建议**：§6.11.3 改为 "§7 用例 T46"。

---

### L4：§3 ServerTIDChange 三字段未在 §3.1 默认化规则表列出

**位置**：§3.1（行 257-270）

**描述**：§3 ServerTIDChange/ServerTIDChangeAtBlock/ServerTIDNew 三字段在 §3.1 默认化规则表未列出。

**问题**：ServerTIDNew=0 时是否随机生成？ServerTIDChangeAtBlock=0 时是否在 RRQ 后立即切换？设计未说明。

**修复建议**：§3.1 补充三字段的默认化规则。

---

### L5：§7.3 T25 "大 block#" 期望不完整

**位置**：§7.3 T25（行 1088）

**描述**：T25 输入 `blocks_count=65535`，期望 "RRQ + 65535×(DATA+ACK)"。

**问题**：131071 个包的测试会非常慢。设计未说明测试性能预算。另外 Block#=65535 后是否 wrap 到 0 未测（见 C6）。

**修复建议**：
1. T25 改为 `blocks_count=65535` 但只断言最后一个 DATA 的 Block#=65535，不实际生成所有包（用 short-circuit 测试）。
2. 或改为 `blocks_count=65536`，期望 Validate 拒绝（按 C6 修复方案 2）。

---

### L6：§9.4 PCAP 验证依赖 scapy 自构造

**位置**：§9.4（行 1271-1274）

**描述**：设计说 "参考 PCAP 来源：自构造（用 scapy 或 tftpd + tcpdump 抓包）"。

**问题**：scapy 构造的 PCAP 可能与 trafficgen 生成的字节不完全一致（如 IP 头选项、UDP 校验和）。tshark 字节比较可能失败。

**修复建议**：明确 "参考 PCAP 用 tshark 解析后的字段值比较，不做字节级 diff"。

---

### L7：§9.5 MCP 集成用例数偏少

**位置**：§9.5（行 1279-1283）

**描述**：MCP 用例数 ~10 条。

**问题**：60 条单元/集成测试 vs 10 条 MCP e2e 用例，比例偏低。CLAUDE.md §Testing Policy 第 4 条"integration tests"要求跨层覆盖。

**修复建议**：MCP 用例增至 ~20 条，覆盖每个 Validate 拒绝场景 + 每个 ERROR code + 多流并发。

---

## 6. 字段填充正确性审计（扩展表 tftpProtRpt）

扩展表 6（tftpProtRpt）的字段需与 trafficgen 生成的包对应。基于 RFC 1350/2347-2349 的典型 TFTP 上报字段：

| 扩展表字段 | 设计覆盖 | 审计结论 |
|------------|----------|----------|
| opcode | §2.1 opcode 表 | ✓ 覆盖（1-6 全部） |
| filename | §3 Filename + §6.1 | ✓ 覆盖 |
| transfer_mode | §3 TransferMode + §6.3 | ✓ 覆盖（netascii/octet，mail 拒绝） |
| blksize | §3 BlkSize + §6.5 | ✓ 覆盖（8-65464 范围校验） |
| timeout | §3 Timeout + §6.7 | ✓ 覆盖（1-255 范围校验） |
| tsize | §3 TSize + §6.6 | ⚠ 双语义问题（C7） |
| block# | §2.3 + §6.2 | ⚠ wrap-around 未定义（C6） |
| error_code | §2.6 + §3 ErrorCode | ⚠ 默认 ErrMsg 映射缺失（H8） |
| error_msg | §3 ErrorMsg | ⚠ 默认值规则未定义（H8） |
| server_tid | §3 ServerTID | ⚠ 0 的语义未定义（H7） |
| direction | §5.2 端口规则 | ✓ 覆盖 |
| options 顺序 | §8.4 O4 | ⚠ planner 写入顺序未强制（M9） |
| windowsize | §2.8（v2 扩展） | ✗ v1 不实现（可接受） |

**字段覆盖率**：12/13 已覆盖（92%），1 个 v2 扩展字段可接受。但 6 个字段存在语义/默认值问题需修复。

---

## 7. 测试用例质量审计（CLAUDE.md §Testing Policy 8 条）

| 规则 | 设计符合度 | 审计结论 |
|------|------------|----------|
| §1 spec-driven | ⚠ 部分符合 | 60 条用例对应 §2-§6 字段，但 6 条用例（T08/T11/T13/T14/T15/T20）与设计规则冲突 |
| §2 失败路径覆盖 | ✓ 符合 | T13-T19 错误注入 + T26-T40 Validate 拒绝，覆盖 7 个 ErrCode + 15 个 Validate 拒绝 |
| §3 单路径测试 | ⚠ 部分符合 | T20 同时测"自动追加"和"末块 0 字节"两个路径，应拆分 |
| §4 集成测试 | ✓ 符合 | T53-T58 E2E 覆盖 Plan→Worker→PCAP→tshark→NIC |
| §5 可观察断言 | ⚠ 部分符合 | T11/T13/T14 缺 BlocksCount，无法生成包；T19 默认 ErrMsg 未定义无法断言 |
| §6 并发正确性 | ✓ 符合 | T59/T60 测 8 流并发 + 共享 Pacer 限速 + -race |
| §7 失败测试先行 | ✗ 不符合 | 设计文档未包含失败测试，仅列期望。实现时需先写失败测试再实现 |
| §8 测试质量审查 | ⚠ 部分符合 | §8 检查清单 48 项，但 F10/M9 等检查项本身有缺陷 |

**测试用例质量评级**：**部分达标**。60 条数量充足但 6 条与设计规则冲突，§7/§8 不达标。

---

## 8. 多流场景正确性审计

### 8.1 §6.9 多流并发场景

**设计**：3 个 flow，每个独立 4-tuple（不同 src_port 或 src_ip），每流 3 包（RRQ+DATA+ACK），共 9 包。

**审计结论**：
- ✓ 4-tuple 隔离正确（每流 ServerTID 显式不同）
- ✓ FlowID 唯一性保证（含 src_ip/src_port）
- ⚠ 缺少跨流时序交错测试（T41 只测分组，没测交错）
- ⚠ 缺少共享 ServerTID 的冲突测试（两流 ServerTID 相同时 planner 行为未定义）

**修复建议**：
1. 增加 T41b：3 流交错时序（流1 RRQ → 流2 RRQ → 流1 DATA → 流3 RRQ → 流2 DATA ...）
2. 增加 T41c：两流 ServerTID 相同时 Validate 拒绝

### 8.2 §6.11.1 TID 变更场景

**审计结论**：见 C4/C5，ERROR 发起方反转 + 时序矛盾，**不合格**。

### 8.3 §6.11.3 NAT 端口变化场景

**审计结论**：标注为 v2 扩展可接受，但 §6.11.3 引用错误（L3）。

---

## 9. 总体评级与修复优先级

### 9.1 评级

| 维度 | 评级 | 说明 |
|------|------|------|
| RFC 合规性 | **不合格** | BlocksCount 语义违反 RFC 1350 §6（C1）；TID 变更方向反转（C4） |
| 文档内部一致性 | **不合格** | §6.2 与 §6.10.1 矛盾（C2）；§2.7 与 §4.2 矛盾（M1） |
| 字段语义清晰度 | **部分合格** | TSize 双语义（C7）；ErrorAfterBlock 与 BlocksCount 交互未定义（C8） |
| 测试用例质量 | **部分合格** | 60 条数量充足但 6 条冲突，§7/§8 不达标 |
| 集成点完整性 | **合格** | §9 集成点列表完整 |
| 多流场景 | **部分合格** | §6.9 基本正确但缺交错测试；§6.11.1 不合格 |

**总体**：**不合格，需返工**。8 处 CRITICAL 必须修复后方可进入实现阶段。

### 9.2 修复优先级

**P0（实现前必须修复）**：
- C1 + C2 + C3：BlocksCount 语义 + 自动追加规则统一
- C4 + C5：TID 变更场景重写
- C8：ErrorAfterBlock 与 BlocksCount 交互规则
- H2 + H3 + H6 + H9：补充输入 spec

**P1（实现中修复）**：
- C6：Block# wrap-around 定义
- C7：TSize 字段拆分
- H1 + M1：OACK/ACK#0 描述统一
- H4：RetransmitBlocks 字段说明修正
- H5 + H8：测试用例与规则对齐
- H7：ServerTID=0 行为定义
- H10：ServerTIDChange + RetransmitBlocks 互斥规则

**P2（实现后修复）**：
- M2-M10：字段语义细节
- L1-L7：文档清晰度

### 9.3 修复后重审建议

修复 P0 + P1 后需重新审计：
1. 确认 C1-C8 全部修复
2. 确认 H1-H10 全部修复
3. 重新跑 CLAUDE.md §Testing Policy 8 条规则对照
4. 重新评估字段覆盖率（目标 13/13 = 100%）
5. 重审后再进入实现阶段

---

**审计结束**。共发现 35 个问题（8 CRITICAL + 10 HIGH + 10 MEDIUM + 7 LOW），总体评级不合格，建议返工修复 P0 + P1 后重审。
