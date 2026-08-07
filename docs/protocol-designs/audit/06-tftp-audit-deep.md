# TFTP 设计文档深度对抗审计报告（v1.1）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md`（v1.1，1679 行，84 测试用例）
**审计依据**：RFC 1350（TFTP Rev.2）、RFC 2347（选项扩展）、RFC 2348（blksize）、RFC 2349（timeout/tsize）、RFC 1783（multicast/TID change，Informational）、RFC 7440（windowsize）、RFC 6335（端口范围）、CLAUDE.md §Testing Policy 8 条规则
**审计方法**：交叉对抗——逐节对照 RFC 原文尝试反驳设计正确性，默认"有 bug"除非证据确凿；测试用例按 CLAUDE.md 8 条规则逐条审核
**审计员**：独立审计员（与 v1.0 审计员不同）
**审计日期**：2026-08-04

---

## 1. 审计概览

### 1.1 v1.1 修复确认

v1.1 修复了 v1.0 的 35 个问题（8 CRITICAL + 10 HIGH + 10 MEDIUM + 7 LOW），核心改进：
- AutoAppendFinalBlock 字段默认 true（RFC 1350 §6 合规）
- TSize 拆分为 ClientTSize/ServerTSize
- ErrorAfterBlock 强制 BlocksCount 显式设
- ServerTIDChange 方向修正（客户端发 ERROR code=5）
- ErrCode→ErrMsg 默认映射表
- IncludeOACK 语义明确

### 1.2 v1.1 新发现的问题汇总

| 严重度 | 数量 | 关键问题 |
|--------|------|----------|
| CRITICAL | 5 | BlocksCount uint16 无法表示 65536；RRQ 模式自动追加 TSize 判定矛盾；ERROR code=0 语义歧义；ERROR code=5 不终止规则未明确；重传时序不合规 |
| HIGH | 6 | windowsize RFC 引用不一致；错误码 8 缺失；Filename Max 255 表述不准；IncludeOACK OACK 字节表述歧义；T62 RRQ+ClientTSize 矛盾；tsize 选项发送规则矛盾 |
| MEDIUM | 7 | TransferMode 大小写未明；ServerTID/ServerTIDNew 端口范围不一致；ErrorCode=0 与 ServerTIDChange 互斥未明；§3.3 ErrMsg 默认映射条件错误；BlocksCount 默认推导依赖条件未明；§6.2/§6.10.1 TSize 字段使用矛盾；Validate 端口范围不一致 |
| LOW | 6 | OACK 字节注释 `0006` 应为 `00 06`；§1.1 文件大小上限表述不精确；§8.1 F3 未涵盖 OACK 场景；T25 short-circuit 未定义语义；错误码 8 遗漏注释；ServerTID 端口范围默认值不一致 |
| **总计** | **24** | — |

### 1.3 总体评级

**有条件不合格（需返工修正 CRITICAL 和 HIGH 问题）**。v1.1 大幅改进了 v1.0 的状态机和字段语义，但引入了新的类型与语义矛盾（CRITICAL-1: BlocksCount uint16 与 65536 语义矛盾）、RRQ 模式自动追加 TSize 判定矛盾（CRITICAL-2）、ERROR code=0 语义歧义（CRITICAL-3）、ERROR code=5 不终止规则未在 §4.3 中明确（CRITICAL-4）、重传时序不符合真实 TFTP 行为（CRITICAL-5）。这些 CRITICAL 问题直接按此设计实现会导致生成的 TFTP 流无法与真实 TFTP 客户端/服务器互操作，或导致实现无法编译/解析。

---

## 2. CRITICAL 问题

### C1：`BlocksCount` 字段类型为 `uint16`（最大 65535），但设计要求支持 65536

**位置**：§3 `BlocksCount` 字段定义（行 249：`BlocksCount uint16 \`json:"blocks_count,omitempty"\``）、§3.2 行 343-344、§6.10.12 输入 spec（行 1107：`"blocks_count": 65536`）、T25b（行 1328）、T25c（行 1329）、T40c（行 1358）、T40d（行 1359）

**描述**：`BlocksCount` 字段类型为 `uint16`，范围 0-65535。但文档多处要求支持 `BlocksCount=65536`：
- §3.2 行 344："`WrapBlockNumber=true`：BlocksCount 允许达 65536"
- §6.10.12 输入 spec 用 `"blocks_count": 65536`
- T25b 期望 Validate 报错 `tftp: blocks_count 65536 exceeds uint16 max`
- T25c 用 `"blocks_count": 65536` 期望正常生成

**问题**：
1. Go 的 `json.Unmarshal` 对 uint16 字段接收 65536 会报 JSON 解析错误（`json: cannot unmarshal number 65536 into Go struct field`），根本到不了 Validate 阶段。
2. Validate 检查 `BlocksCount > 65535` 是死代码——uint16 永远不会 > 65535。
3. T25b 的期望行为（Validate 报错）在当前类型下无法实现——JSON 解析阶段就会失败，错误信息不会是 `tftp: blocks_count 65536 exceeds uint16 max` 而是 JSON unmarshal 错误。

**依据**：Go 语言规范 uint16 范围 0-65535；JSON 解析到 uint16 字段溢出报错。

**修复建议**：
- 方案 A：将 `BlocksCount` 改为 `uint32` 或 `int`，允许 0-65536（甚至更大）
- 方案 B：限制 `BlocksCount <= 65535`，移除所有 65536 相关描述（包括 WrapBlockNumber 的 65536 说法）
- 推荐方案 A，因为 wrap-around 场景需要 65536 块

---

### C2：RRQ 模式自动追加 TSize 判定依据多处矛盾

**位置**：§3 AutoAppendFinalBlock 注释（行 252-253："RRQ uses ServerTSize; WRQ uses ClientTSize"）、§3.1 ClientTSize 默认值（行 325）、§6.2（行 596、607、614）、§6.6（行 713、727）、§6.10.1（行 924、938）、T02（行 1287）、T20（行 1320）、T62（行 1331）

**描述**：文档在 RRQ 模式下自动追加 0 字节末块的 TSize 判定依据自相矛盾：

**矛盾点 1**（§3 vs §6.2/§6.10.1/T20）：
- §3 AutoAppendFinalBlock 注释（行 252-253）：RRQ uses ServerTSize
- §6.2（行 596）：`mode=read` + `client_tsize=1024` 触发自动追加（用 ClientTSize 判定）
- §6.10.1（行 924）：`mode=read` + `client_tsize=1024` 触发自动追加
- T20（行 1320）：`mode=read` + `client_tsize=1024` 触发自动追加，断言 "2×512==1024==ClientTSize"

**矛盾点 2**（§3.1 vs §6.6 vs §6.2）：
- §3.1 行 325：RRQ 模式下 ClientTSize 被强制重写为 0（"forces 0 regardless of this field"）
- §6.6（行 713）："ClientTSize 字段在 RRQ 模式被 Validate 忽略"
- §6.2（行 614）：RRQ 无 tsize 选项（因 ClientTSize 不写入 RRQ）

如果 §3.1 的"RRQ 模式下 ClientTSize 强制重写为 0"成立，那么 `client_tsize=1024` 在 RRQ 模式下被改写为 0，自动追加判定依据变成 ServerTSize=0（§6.2 没设 server_tsize），不应该触发自动追加。但 §6.2 期望触发自动追加。

如果 §6.6 的"ClientTSize 字段在 RRQ 模式被 Validate 忽略"成立，那么 ClientTSize=0，ServerTSize=0，不触发自动追加。但 §6.2 期望触发。

实际行为应该是其中之一：
- 方案 A：RRQ 模式下 ClientTSize 被忽略，自动追加用 ServerTSize 判定。那么 §6.2/§6.10.1/T20 应改为 `mode=read + server_tsize=1024`，且 §6.2 的 RRQ 字节应含 `tsize\0 0\0`（因为 ServerTSize>0 触发了 tsize 选项的发送）。
- 方案 B：RRQ 模式下自动追加用 ClientTSize 判定（即使 ClientTSize 被忽略用于 RRQ 报文）。那么 §3 注释应改为 "RRQ uses ClientTSize for auto-append; WRQ uses ClientTSize"。
- 方案 C：RRQ 模式下自动追加用 ClientTSize 和 ServerTSize 中非零者。那么 §3 注释应改为 "RRQ uses ClientTSize/ServerTSize (whichever non-zero); WRQ uses ClientTSize"。

**依据**：文档内部一致性；CLAUDE.md §Testing Policy 第 1 条（spec-driven test derivation）。

**修复建议**：
- 明确自动追加的 TSize 判定规则（推荐方案 C）
- 同步更新 §3、§6.2、§6.6、§6.10.1、T02、T20 的所有相关描述
- 如果选方案 A，删除所有 RRQ + ClientTSize 触发自动追加的用例

---

### C3：`ErrorCode=0` 语义歧义——无法区分"不注入"和"注入 ErrCode=0"

**位置**：§3 ErrorCode 字段注释（行 223-227）、§3.3 ErrMsg 默认映射条件（行 348）、T16（行 1310）、T17b（行 1312）

**描述**：`ErrorCode=0` 在文档中有两种相互矛盾的语义：

**矛盾点 1**（§3 注释 vs T16/T17b）：
- §3 ErrorCode 注释（行 226）："0=no injection (unless ErrorAfterBlock>0 + EmptyErrorCode=true)"
- §3.3 行 348："当 `ErrorCode > 0` 且 `ErrorMsg == ""` 时，planner 按下表自动填充默认 ErrMsg"
- T16：`error_code=0, error_after_block=1` → 期望注入 ERROR(0)（4 包）
- T17b：K=0 时 `error_code=0, error_after_block=0` → 期望注入 ERROR(0)

§3 说 `ErrorCode=0` 表示"不注入"。但 T16 和 T17b 都用 `ErrorCode=0` 注入 ERROR(0)。而且 §3 注释提到 `EmptyErrorCode` 这个字段，但 `TFTPConfig` 结构体中没有定义该字段（悬空引用）。

**矛盾点 2**（§3.3 默认映射条件 vs T17b）：
- §3.3 行 348：默认映射条件是 `ErrorCode > 0`
- T17b K=0 用例：期望 ErrMsg = "Not defined"（按 §3.3 表填充）

但 §3.3 说 `ErrorCode > 0` 才填默认，那 `ErrorCode=0` 时 ErrMsg 是什么？按 §3.3 逻辑，`ErrorCode=0` 不填默认，ErrMsg 为空。但 T17b K=0 用例期望填默认 "Not defined"。

**依据**：文档内部一致性；字段语义明确性。

**修复建议**：
- 方案 A：移除 §3 ErrorCode 注释中 `ErrorCode=0 = no injection` 的说法，统一 `ErrorCode>0` 才注入，`ErrorCode=0` 不注入
- 方案 B：定义 `EmptyErrorCode` 字段（或重命名为 `AllowErrorCode0`），当 `ErrorCode=0 + AllowErrorCode0=true` 时注入 ErrCode=0
- 方案 C：重新定义语义——`ErrorCode=0` 总是注入 ErrCode=0（"Not defined"），移除"不注入"语义
- 推荐方案 C，配合修改 T16/T17b 的断言（ErrMsg="Not defined" 用默认映射而非用户提供的 "User cancelled"）

---

### C4：ERROR code=5 不终止传输的规则未在 §4.3 中明确，与 §4.3 通用规则矛盾

**位置**：§4.3（行 431-441）、§6.11.1（行 1182-1224）、§8.3 S5（行 1443）

**描述**：
- §4.3（行 441）："发出或收到 ERROR 后，planner 不再生成任何包"——通用规则
- §8.3 S5（行 1443）："ERROR 后不再生成任何包（无论 ErrorSide、ErrorAfterBlock）"——检查清单复述
- §6.11.1（行 1208-1215）：ERROR code=5（TID change）后继续生成 ACK#3、DATA#4、ACK#4

**RFC 1350 明确规定**：ERROR code=5 (Unknown transfer ID) 是唯一**不终止传输**的错误（"TFTP recognizes only one error condition that does not cause termination, the source port of a received packet being incorrect"）。

**问题**：
1. §4.3 没有为 ERROR code=5 例外，违反 RFC 1350
2. §8.3 S5 明确说"无论 ErrorSide、ErrorAfterBlock"都不再生成任何包——直接与 §6.11.1 矛盾
3. 如果按 §4.3/§8.3 严格执行，TID change 场景（§6.11.1）无法实现——ERROR code=5 后 planner 停止，不再生成 ACK#3、DATA#4

**依据**：RFC 1350 §5（ERROR code 5 不终止传输）；文档内部一致性。

**修复建议**：
- §4.3 明确说明 ERROR code=5 是例外，不终止传输
- §8.3 S5 修改为"ERROR code=1-7 后不再生成任何包；ERROR code=5 不终止"
- §6.11.1 的 ERROR code=5 场景已符合 RFC 1350，无需修改

---

### C5：重传时序不符合真实 TFTP 行为

**位置**：§6.11.2（行 1226-1256）、T44（行 1371）

**描述**：
- §6.11.2 时序：DATA#2(原) → ACK#2(原) → DATA#2(重传) → ACK#2(重传)
- T44 期望：DATA#2(原)/ACK#2(原) → DATA#2(重传)/ACK#2(重传) → DATA#3/ACK#3

**真实 TFTP 重传行为**：
- 服务器发 DATA#2，客户端收到后发 ACK#2
- 服务器收到 ACK#2 后停止计时，不再重传
- 如果 DATA#2 丢失：服务器超时 → 重传 DATA#2 → 客户端收到 → 发 ACK#2
- 重传的 DATA#2 出现在**原 ACK#2 之前**（因为原 ACK#2 还没发）

文档描述的"DATA#2(原) → ACK#2(原) → DATA#2(重传) → ACK#2(重传)"意味着：
1. 客户端已收到 DATA#2 并发了 ACK#2
2. 服务器又重传了 DATA#2（但服务器已收到 ACK#2，不会重传）
3. 客户端又发了 ACK#2（重复 ACK）

这种时序在真实 TFTP 中不会出现。trafficgen 生成的这种流量无法与真实 TFTP 服务器/客户端互操作。

**依据**：RFC 1350 §6（超时重传机制）；CLAUDE.md §Testing Policy 第 2 条（覆盖真实行为路径）。

**修复建议**：
- 方案 A：改为"丢包后重传"语义——`RetransmitBlocks=[2]` 表示 DATA#2 第一次丢失，只有重传的 DATA#2 出现（无原 DATA#2）。但这与§6.11.2 的"两个 Block#=2 的 DATA"描述矛盾。
- 方案 B：明确标注"非标准重传模拟，仅用于测试重传检测逻辑"，不期望与真实 TFTP 互操作。
- 方案 C：实现"重复发送"语义——服务器在收到 ACK 后又发了一次 DATA（异常行为），客户端又回了 ACK。明确这是非标准场景。
- 推荐方案 C + 文档明确标注"此场景模拟的是'重复发送'异常（非丢包重传），不符合 RFC 1350 §6 标准重传机制"。

---

## 3. HIGH 问题

### H1：windowsize RFC 引用不一致

**位置**：§1 规范来源（行 4："RFC 3625（windowsize，仅参考）"）、§2.8 表格（行 166："windowsize | RFC 7440"）、附录 C（行 1616）

**描述**：第 4 行引用 RFC 3625 作为 windowsize 来源，但 §2.8 表格和附录 C 引用 RFC 7440。RFC 7440 才是 TFTP Windowsize Option 的正确 RFC。RFC 3625 与 windowsize 无关。

**修复建议**：删除第 4 行对 RFC 3625 的引用，统一为 RFC 7440。

---

### H2：错误码 8 (Failed to negotiate options) 缺失

**位置**：§2.6 错误码表（行 131-141）、§3 ErrorCode 字段（行 225："Validate enforces 0 <= ErrorCode <= 7"）

**描述**：RFC 2347 引入了错误码 8 ("Failed to negotiate options")，用于客户端拒绝 OACK 的场景。文档错误码表只列出 code 0-7，且 ErrorCode 字段 Validate 强制 <= 7。

**影响**：
- 无法模拟"客户端拒绝 OACK"场景（选项协商失败）
- RFC 2347 §2: "If the client rejects the OACK, then it sends an ERROR packet, with error code 8, to the server and the transfer is terminated."
- 缺少这个错误码意味着 TFTP 选项协商失败的完整流程无法模拟

**修复建议**：
- 错误码表补充 code=8（Failed to negotiate options，per RFC 2347）
- ErrorCode 字段 Validate 允许 0-8

---

### H3：Filename Max 255 bytes 表述不准

**位置**：§3 Filename 字段注释（行 187："Max 255 bytes (UDP datagram ceiling)"）

**描述**：文档说 filename 最大 255 字节是"UDP datagram ceiling"，但 UDP datagram 最大 payload 是 65507 字节（65535 - 8 UDP 头 - 20 IP 头最小）。255 字节不是 UDP 上限。

**修复建议**：改为 "Max 255 bytes（trafficgen 限制，RFC 1350 未规定最大长度）"，或删除 Max 255 bytes 限制（允许更长 filename）。

---

### H4：IncludeOACK=true 时 OACK 字节注释歧义

**位置**：§3 IncludeOACK 字段注释（行 283："OACK carries just `0006`"）

**描述**：`IncludeOACK=true` 且无选项时，OACK 仅含 opcode 2 字节。注释写 `0006` 是 4 个字符，容易误解为 4 字节。应明确为 `00 06`（2 字节）。

**修复建议**：改为 "OACK carries just opcode `00 06` (2 bytes)"。

---

### H5：T62 RRQ 模式 + ClientTSize 触发自动追加与 §3 矛盾

**位置**：T62（行 1331）

**描述**：T62 是 `mode=read`（RRQ），用 `client_tsize=1024` 触发自动追加（"2×512=1024=ClientTSize 触发条件被 FinalBlockZero 抑制"）。但 §3 AutoAppendFinalBlock 注释说 RRQ 用 ServerTSize，且 §6.6 说 RRQ 模式下 ClientTSize 被忽略。

**问题**：T62 的断言 "2×512=1024=ClientTSize" 与 §3 和 §6.6 矛盾。

**修复建议**：
- 方案 A：T62 改为 `mode=write`（WRQ），用 ClientTSize 触发自动追加（与 §3 一致）
- 方案 B：T62 改为 `mode=read + server_tsize=1024`，用 ServerTSize 触发自动追加（与 §3 一致）

---

### H6：tsize 选项在 RRQ 中的发送规则矛盾

**位置**：§3 ClientTSize 字段注释（行 205-207）、§6.2（行 614："无 tsize 选项"）、§6.6 T06（行 728："tsize\0 0\0"）

**描述**：
- §3 ClientTSize 注释（行 205-207）："For RRQ: RFC 2349 §2 mandates client writes '0'; trafficgen forces 0 regardless of this field"
- §6.2（行 614）："无 tsize 选项，因 client_tsize 仅用于触发自动追加，不写入 RRQ"
- §6.6 T06（行 728）：RRQ 报文含 `tsize\0 0\0`（ServerTSize=2048 触发）

**矛盾**：§3 说 RRQ 模式下 ClientTSize 强制写 "0"（即发送 tsize 选项），但 §6.2 说 RRQ 无 tsize 选项。

**修复建议**：
- 明确规则：RRQ 模式下，只有当 ClientTSize>0 或 ServerTSize>0 时，发送 `tsize\0 0\0`；否则不发送
- §3 注释修改为"For RRQ: if ClientTSize>0 or ServerTSize>0, RRQ carries `tsize\0 0\0` (per RFC 2349 §2); otherwise tsize option is not sent"
- §6.2 改为 `mode=read + server_tsize=1024` 以触发 tsize 选项发送，或删除 §6.2 的 tsize 描述

---

## 4. MEDIUM 问题

### M1：TransferMode 大小写处理未明确

**位置**：§3 TransferMode 字段注释（行 190-192）、§6.3（行 650："RRQ 的 mode 子字段 = `netascii`（小写，无大写）"）、§6.10.7（行 1075）

**描述**：RFC 1350 §4 说 mode 字段是大小写不敏感的（"any combination of upper and lower case"）。但文档：
- §6.3 断言输出总是小写
- §6.10.7 拒绝 "binary" 这种非法值
- 没说明 Validate 是否接受大写输入（如 "OCTET"、"NetAscii"）

**修复建议**：
- Validate 接受大小写不敏感的 mode 值（"NETASCII"/"NetAscii"/"octet" 都接受）
- 输出统一小写（per §6.3 断言）
- 添加测试用例覆盖大写输入

---

### M2：ServerTID/ServerTIDNew 端口范围验证不一致

**位置**：§3 ServerTID 字段注释（行 220："Validate enforces 1024 <= ServerTID <= 65535"）、§3.1 默认表（行 317："范围 49152-65535，RFC 6335"）、T35（行 1347："server_tid 80 in well-known range (<1024)"）、T40（行 1356："server_tid_new 80 in well-known range (<1024)"）

**描述**：
- §3 注释：ServerTID 范围 1024-65535
- §3.1 默认表：默认生成范围 49152-65535（RFC 6335 dynamic range）
- T35/T40：拒绝 <1024（知名端口范围）

**矛盾**：默认生成用 49152-65535（RFC 6335），但 Validate 允许 1024-49151（registered port range）。用户设 `server_tid=4000`（注册端口）会被接受，但默认生成不会产生这个范围。这不算严重 bug，但范围描述不一致。

**修复建议**：
- 统一为"默认生成 49152-65535；Validate 允许 1024-65535（覆盖注册端口和动态端口）"
- 或严格化为"默认生成和 Validate 都用 49152-65535（仅动态端口）"

---

### M3：`ErrorCode=0` 与 `ServerTIDChange` 互斥规则未明

**位置**：§3.2 行 337（"ServerTIDChange 与 ErrorCode 互斥"）、T38（行 1352："server_tid_change=true, error_code=1"）

**描述**：§3.2 说 ServerTIDChange 与 ErrorCode 互斥。T38 用 `error_code=1` 测试互斥。但 `ErrorCode=0`（按 §3 注释 = "不注入"）是否触发互斥？文档没说。如果 `ErrorCode=0` 表示"不注入"，那么 `ServerTIDChange=true + ErrorCode=0` 应该合法（没有实际注入 ERROR）。但 §3.2 的互斥规则没有区分 `ErrorCode>0` 和 `ErrorCode=0`。

**修复建议**：
- §3.2 明确："ServerTIDChange 与 ErrorCode>0 互斥；ErrorCode=0（不注入）不触发互斥"
- 或结合 C3 的修复方案定义 `ErrorCode=0` 的语义

---

### M4：§3.3 ErrMsg 默认映射条件错误

**位置**：§3.3（行 348："当 `ErrorCode > 0` 且 `ErrorMsg == ""` 时..."）

**描述**：§3.3 说默认映射条件是 `ErrorCode > 0`。但 §3.3 表包含 code=0 的默认映射（"Not defined"），且 T17b K=0 用例期望填默认。如果 `ErrorCode=0` 不填默认，那 §3.3 表的 code=0 行无意义。

**修复建议**：§3.3 改为"当 `ErrorMsg == ""` 时，planner 按下表自动填充默认 ErrMsg（包括 ErrorCode=0）"。

---

### M5：BlocksCount 默认推导依赖条件未明

**位置**：§3.1 BlocksCount 默认值（行 321）、T40e（行 1360）

**描述**：§3.1 说 BlocksCount=0 时由 Payload/FileSource + BlkSize 推导。T40e 说 `blocks_count=0, data_payload_pattern="", 无 Payload/FileSource` 报错。但 `data_payload_pattern` 是 `TFTPConfig.DataPayloadPattern`，与 Payload/FileSource 的关系未明。

**修复建议**：
- 明确 DataPayloadPattern 与 Payload/FileSource 的关系（DataPayloadPattern 是 TFTP 专用，Payload/FileSource 是 FlowSpec 通用）
- BlocksCount 推导规则：`data_payload_pattern` 非空 OR Payload/FileSource 非空才允许 BlocksCount=0

---

### M6：§6.2/§6.10.1 TSize 字段使用矛盾

**位置**：§6.2（行 607：`client_tsize=1024`）、§6.10.1（行 932：`client_tsize=1024`）、T02（行 1287：`client_tsize=1024`）、T20（行 1320：`client_tsize=1024`）

**描述**：所有这些 RRQ 模式用例用 `client_tsize` 触发自动追加。但 §3 说 RRQ 模式自动追加用 ServerTSize，§6.6 说 RRQ 模式 ClientTSize 被忽略。

**修复建议**：与 C2 联动修复——统一自动追加的 TSize 判定规则，更新所有相关用例的字段。

---

### M7：Validate 端口范围与默认值不一致

**位置**：§3 ServerTID 注释（行 220）、§3.1 默认表（行 317）

**描述**：见 M2。Validate 允许 1024-65535，默认生成用 49152-65535。这是不一致，但不算严重 bug。

---

## 5. LOW 问题

### L1：OACK 字节注释 `0006` 应为 `00 06`

**位置**：§3 IncludeOACK 注释（行 283）

**修复建议**：改为 `00 06`（2 字节 opcode）。

---

### L2：§1.1 文件大小上限表述不精确

**位置**：§1.1（行 28："blksize=65464 时理论 65535×65464 ≈ 4 GB-1 字节"）

**描述**：65535×65464 = 4,286,158,640 字节 ≈ 3.99 GB（不是 4 GB-1）。4 GB-1 = 4,294,967,295 字节。

**修复建议**：改为"blksize=65464 时理论 65535×65464 ≈ 3.99 GB（受 TSize uint32 上限 4 GB-1 制约）"。

---

### L3：§8.1 F3 未涵盖 OACK 场景

**位置**：§8.1 F3（行 1418："Block# 从 1 开始（不是 0），ACK#0 是 WRQ 无选项时的特例"）

**描述**：F3 只提了 WRQ 无选项场景的 ACK#0，没提 RRQ+OACK 场景的 ACK#0。

**修复建议**：F3 改为"Block# 从 1 开始（不是 0），ACK#0 是 OACK 确认（RRQ+OACK）或 WRQ 准备好接收确认（WRQ 无选项）的特例"。

---

### L4：T25 short-circuit 未定义语义

**位置**：T25（行 1327）

**描述**：T25 用 short-circuit 只断言最后一个包的 Block#，但 short-circuit 的具体实现未定义（是只生成最后一个包，还是生成所有包但只检查最后一个？）。

**修复建议**：明确 short-circuit 语义（如 "planner 只生成最后一个 DATA 和对应 ACK，不生成中间包"）。

---

### L5：错误码 8 遗漏注释

**位置**：§2.6（行 131-141）、§3 ErrorCode 字段（行 225）

**描述**：见 H2。错误码表和 ErrorCode 字段都遗漏了 RFC 2347 引入的错误码 8。

---

### L6：ServerTID 端口范围默认值描述不一致

**位置**：§3 ServerTID 注释（行 220）、§3.1 默认表（行 317）

**描述**：见 M2/M7。

---

## 6. HexDump 自洽性验证

逐条验证文档中给出的字节序列是否与字段定义一致：

| 用例 | 字节序列 | 验证结果 |
|------|----------|----------|
| T47 RRQ | `00 01 61 2e 62 69 6e 00 6f 63 74 65 74 00`（14B） | opcode(2) + "a.bin\0"(6) + "octet\0"(6) = 14B，正确 |
| T48 OACK | `00 06 62 6c 6b 73 69 7a 65 00 31 34 32 38 00`（15B） | opcode(2) + "blksize\0"(8) + "1428\0"(5) = 15B，正确 |
| T49 DATA#1 | `00 03 00 01` + 512B | opcode(2) + block#(2) + data(512) = 516B，正确 |
| T50 ACK#0 | `00 04 00 00`（4B） | opcode(2) + block#(2) = 4B，正确 |
| T51 ERROR | `00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00`（19B） | opcode(2) + ErrCode(2) + "File not found\0"(15) = 19B，正确 |
| T52 RRQ 多选项 | `00 01 <file>\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 0\0` | 选项顺序 blksize→timeout→tsize，与 §3.2 一致 |
| T52b OACK 多选项 | `00 06 62 6c 6b 73 69 7a 65 00 35 31 32 00 74 69 6d 65 6f 75 74 00 35 00 74 73 69 7a 65 00 31 30 32 34 00`（35B） | 选项顺序 blksize→timeout→tsize，正确 |
| T52c WRQ 多选项 | `00 02 <file>\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 1024\0` | WRQ 中 tsize=ClientTSize=1024，正确 |

**结论**：所有 HexDump 字节序列在字段定义层面是自洽的。但部分用例的输入 spec 与 §3 规则矛盾（如 T52 用 `blksize=512` 触发 OACK，虽然冗余但合规）。

---

## 7. RFC 合规性检查

| RFC 章节 | 要求 | 文档实现 | 合规性 |
|----------|------|----------|--------|
| RFC 1350 §4 | TID 由双方各自选择，服务器从新端口响应 | §3 ServerTID 字段、§5.2 端口规则 | 符合 |
| RFC 1350 §5 | ERROR code 5 不终止传输 | §4.3 未为 code=5 例外，§6.11.1 实现不终止 | **不符合（§4.3 矛盾）** |
| RFC 1350 §5 | 错误码 0-7 | §2.6 列出 0-7 | 符合（但遗漏 RFC 2347 引入的 code=8） |
| RFC 1350 §6 | 文件大小为 blksize 整数倍时追加 0 字节块 | AutoAppendFinalBlock 默认 true | 符合 |
| RFC 1350 §4 | mode 字段大小写不敏感 | §6.3 输出小写，Validate 未明 | **部分符合（Validate 未明）** |
| RFC 2347 §2 | 选项名和值大小写不敏感 | §8.1 F8 要求小写 | **不符合（强制小写）** |
| RFC 2347 §2 | 选项值是 ASCII 字符串 | §3 BlkSize/Timeout 字段为数字类型，planner 转为 ASCII | 符合 |
| RFC 2347 §2 | 服务器不识别选项应省略（不报错） | §4.4 不支持部分拒绝 | 部分符合 |
| RFC 2347 §2 | 客户端拒绝 OACK 发 ERROR code=8 | 错误码表无 code=8 | **不符合（遗漏 code=8）** |
| RFC 2347 §2 | RRQ+OACK 后客户端发 ACK#0 | §4.1 状态机 | 符合 |
| RFC 2347 §2 | WRQ+OACK 后客户端直接发 DATA#1（无 ACK#0） | §4.2 状态机 | 符合 |
| RFC 2348 §2 | blksize 范围 8-65464 | §3 BlkSize 验证 | 符合 |
| RFC 2349 §2 | RRQ 模式 tsize 写 "0" | §6.6 T06 | 符合 |
| RFC 2349 §2 | WRQ 模式 tsize 写 ClientTSize | §6.6 T06b | 符合 |
| RFC 2349 §2 | timeout 范围 1-255 | §3 Timeout 验证 | 符合 |
| RFC 1350 | block number 从 1 开始递增 | §2.3、§3 BlocksCount | 符合 |
| RFC 1350 | block number 没有定义 wrap-around | §3 WrapBlockNumber 字段 | 自定义扩展，非 RFC 行为 |

---

## 8. CLAUDE.md §Testing Policy 8 条规则审核

### 第 1 条：spec-driven test derivation（每个字段/行为都有测试）

**结论：部分达标**
- §3 字段定义覆盖：T26-T40（Validate）、T01-T12（正向）、T41-T46（多流）
- §4 状态机覆盖：T01-T12（正向）、T13-T19（错误）
- §6 业务场景覆盖：T01-T20（业务）、T21-T25（边界）
- 但 `EmptyErrorCode` 字段（§3 注释提到）无测试覆盖
- WrapBlockNumber 的 65536 边界（T25c）因 uint16 类型限制无法测试

### 第 2 条：覆盖失败路径

**结论：达标**
- T13-T19：ERROR 注入（8 种 ErrCode × ErrorSide × ErrorAfterBlock）
- T26-T40：Validate 拒绝（filename 空/NUL/mode 非法/blksize 越界/timeout 越界等）
- T41c：ServerTID 冲突
- 但 `WrapBlockNumber=true + BlocksCount=65536` 因 uint16 限制无法测试（失败路径缺失）

### 第 3 条：测试正确的函数/作用域

**结论：达标**
- Validate 单独测试（T26-T40）
- Plan 包序列测试（T01-T12）
- 字节精确测试（T47-T52c）

### 第 4 条：集成测试

**结论：达标**
- T53-T58：E2E（Plan → Worker → PCAP → tshark）
- T59-T60：并发正确性

### 第 5 条：断言可观察输出

**结论：达标**
- 包序列断言（总包数、opcode、Block#、Data 长度）
- 字节精确断言（T47-T52c）
- Direction/Port 断言

### 第 6 条：并发测试验证正确性

**结论：达标**
- T59：8 流并发，每流 Block# 严格 1..100 递增
- T60：共享 Pacer 限速下的聚合速率

### 第 7 条：failing-test-first for bug fixes

**结论：不适用**（v1.1 修复了 v1.0 的 35 个问题，但 v1.1 本身没有引入新的 bug 修复）

### 第 8 条：adversarial review of test quality

**结论：部分达标**
- 测试覆盖正向+负向+边界
- 但 T25b/T25c/T40c/T40d 因 uint16 类型限制无法实际执行（死测试）
- T62 与 §3 规则矛盾（RRQ + ClientTSize），是错误的测试
- §6.2/§6.10.1/T02/T20 用 `mode=read + client_tsize` 触发自动追加，与 §3 规则矛盾

---

## 9. 测试用例统计验证

文档声称 84 条用例（T01-T60 + 22 个补充用例 + 新增 T61/T62）。

**实际计数**：
- §7.1 正向：T01-T12b = 16 条（含 T02b/T06b/T08b/T12b）
- §7.2 负向错误：T13-T19 = 8 条（含 T17b）
- §7.3 边界：T20-T25c + T61 + T62 = 14 条（含 T20b/T20c/T25b/T25c）
- §7.4 Validate：T26-T40e = 24 条（含 T26b/T36b/T36c/T38b/T39b/T40b/T40c/T40d/T40e）
- §7.5 多流/异常：T41-T46 = 6 条（含 T41b/T41c）
- §7.6 字节精确：T47-T52c = 8 条（含 T52b/T52c）
- §7.7 E2E：T53-T58 = 6 条
- §7.8 并发：T59-T60 = 2 条
- **总计**：16+8+14+24+6+8+6+2 = **84 条**（与文档声称一致）

但其中：
- T25b/T25c/T40c/T40d 因 uint16 类型限制无法实际执行（4 条死测试）
- T62 与 §3 规则矛盾（1 条错误测试）
- **有效测试数**：84 - 4 - 1 = **79 条**

---

## 10. 业务场景覆盖检查

| 场景 | 文档要求 | 实际覆盖 | 结论 |
|------|----------|----------|------|
| RRQ 下载（短文件） | §1.2 | T01 | 覆盖 |
| RRQ 下载（多块 + 自动追加） | §1.2 | T02/T02b/T20/T20b | 覆盖 |
| RRQ 下载（netascii） | §6.3 | T03 | 覆盖 |
| WRQ 上传 | §1.2 | T04/T20c | 覆盖 |
| OPTIONS 协商 blksize | §6.5 | T05/T21/T22 | 覆盖 |
| OPTIONS 协商 tsize（RRQ/WRQ） | §6.6 | T06/T06b | 覆盖 |
| OPTIONS 协商 timeout | §6.7 | T07 | 覆盖 |
| OPTIONS 多选项组合 | §3.2 | T08/T08b | 覆盖 |
| ERROR 中断（RRQ/WRQ/中途/客户端取消） | §6.8 | T13-T16 | 覆盖 |
| ERROR 空消息默认映射 | §6.8 | T17/T17b | 覆盖 |
| ERROR 超长截断 | §6.8 | T18 | 覆盖 |
| 多流并发 | §1.2 | T41/T41b/T42/T59/T60 | 覆盖 |
| 重传场景 | §1.2 | T44/T45 | 覆盖（但时序不符合 RFC，见 C5） |
| TID 变更 | §1.2 | T43 | 覆盖（但 ERROR code=5 不终止规则未明，见 C4） |
| 跨 NAT 端口变化 | §6.11.3 | T46 | 标记为 v2 扩展，未实现 |
| IncludeOACK 无选项 | §4.4 | T12b | 覆盖 |
| FinalBlockZero 显式末块 | §6.10.14 | T61/T62 | 覆盖（但 T62 RRQ + ClientTSize 矛盾） |

**结论**：业务场景覆盖较完整，但部分场景的实现方式与 RFC 不一致（C4、C5）。

---

## 11. 必须返工的问题清单（按优先级排序）

### 必须返工（CRITICAL——实现将导致功能错误）

1. **C1**：`BlocksCount` uint16 类型与 65536 语义矛盾
2. **C2**：RRQ 模式自动追加 TSize 判定矛盾
3. **C3**：`ErrorCode=0` 语义歧义
4. **C4**：ERROR code=5 不终止规则未在 §4.3 明确
5. **C5**：重传时序不符合 RFC 1350

### 建议返工（HIGH——影响 RFC 合规性或场景完整性）

6. **H1**：windowsize RFC 引用不一致
7. **H2**：错误码 8 缺失
8. **H3**：Filename Max 255 表述不准
9. **H5**：T62 RRQ + ClientTSize 矛盾
10. **H6**：tsize 选项发送规则矛盾

### 建议改进（MEDIUM——影响文档清晰度）

11. **M1**：TransferMode 大小写处理
12. **M3**：ErrorCode=0 与 ServerTIDChange 互斥
13. **M4**：§3.3 ErrMsg 默认映射条件
14. **M6**：§6.2/§6.10.1 TSize 字段使用

### 可选改进（LOW——表述优化）

15. **L1**：OACK 字节注释
16. **L2**：文件大小上限表述
17. **L3**：§8.1 F3 覆盖 OACK

---

## 12. 最终结论

**本文档不可以直接进入实现阶段（否）**。

**必须先返工的问题编号**：
1. **C1**（BlocksCount uint16 无法表示 65536）
2. **C2**（RRQ 模式自动追加 TSize 判定矛盾）
3. **C3**（ErrorCode=0 语义歧义）
4. **C4**（ERROR code=5 不终止规则未明确）
5. **C5**（重传时序不符合 RFC 1350）

**建议同时返工**：
6. **H1**（windowsize RFC 引用不一致——容易发现的低级错误）
7. **H2**（错误码 8 缺失——影响 RFC 合规性）
8. **H5**（T62 与 §3 矛盾——测试用例错误）
9. **H6**（tsize 选项发送规则矛盾）

**返工范围**：
- 修改 `BlocksCount` 字段类型为 `uint32` 或 `int`
- 统一 RRQ/WRQ 模式自动追加的 TSize 判定规则
- 定义 `ErrorCode=0` 的语义（推荐："ErrorCode=0 总是注入 ErrCode=0"）
- §4.3 明确 ERROR code=5 不终止传输
- §6.11.2 重传场景明确标注"非标准重传模拟"
- 补充错误码 8
- 统一 windowsize RFC 引用为 RFC 7440
- 修复 T62 与 §3 的一致性
- 明确 tsize 选项发送规则

---

**审计报告结束**。