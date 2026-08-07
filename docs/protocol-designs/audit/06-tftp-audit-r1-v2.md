# TFTP 设计文档复审审计报告（v2.0.0）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md`（v2.0.0，1652 行）
**审计依据**：RFC 1350（TFTP Rev.2）、RFC 2347（选项扩展）、RFC 2348（blksize）、RFC 2349（timeout/tsize）、RFC 7440（windowsize）、RFC 6335（端口范围）、CLAUDE.md §Testing Policy 8 条规则
**审计方法**：交叉对抗——逐节对照 RFC 原文尝试反驳设计正确性，默认"有 bug"；逐字节核算全部 HexDump；测试用例按 CLAUDE.md 8 条规则逐条审核
**审计员**：独立审计员（v2.0.0 复审，与 v1.0/v1.1 审计员不同）
**审计日期**：2026-08-05

---

## 1. 审计概览

### 1.1 v1.1 审计（24 个问题）修复确认

v2.0.0 声明修复了 v1.1 深度审计发现的全部 24 个问题（5 CRITICAL + 6 HIGH + 7 MEDIUM + 6 LOW）。逐项核对：

| v1.1 问题 | v2.0.0 修复 | 结论 |
|-----------|-------------|------|
| C1 BlocksCount uint16 无法表示 65536 | §5 改为 uint32；§2.4 表；S13d | ✅ 已修复 |
| C2 RRQ 自动追加 TSize 判定矛盾 | §5.1 统一为 `(ClientTSize>0 ? ClientTSize : ServerTSize)` | ✅ 已修复（但见本次 R1-CRITICAL-1） |
| C3 ErrorCode=0 语义歧义 | §5/§5.4/S8d/T-227/T-228 | ✅ 已修复 |
| C4 ERROR code=5 不终止未明确 | §4.3/S9/T-229/T-230 | ✅ 已修复 |
| C5 重传时序不合规 | §4.5/S10 丢包式重传 | ✅ 已修复 |
| H1 windowsize RFC 引用 | 统一 RFC 7440 | ✅ 已修复 |
| H2 错误码 8 缺失 | §3.6/S8c/T-026 | ✅ 已修复 |
| H3 Filename 255 表述 | §3.2 修正为 trafficgen 限制 | ✅ 已修复 |
| H4 IncludeOACK 字节 | `00 06` 2 字节 | ✅ 已修复 |
| H5 T62 RRQ+ClientTSize 矛盾 | C2 统一判定后合法化 | ✅ 已修复 |
| H6 tsize 发送规则 | §5.2 三种情况 | ✅ 已修复 |
| M1-M7 | 全部对应修复 | ✅ 已修复 |
| L1-L6 | 全部对应修复 | ✅ 已修复 |

### 1.2 v2.0.0 新发现的问题汇总

| 严重度 | 数量 | 关键问题 |
|--------|------|----------|
| CRITICAL | 3 | S9 TID 变更 ERROR(5) 方向/端口违反 RFC 1350；T-227/T-228 与 ErrorCode=0 恒注入规则矛盾；DATA 满块后无 0 字节末块则协议死锁（半标准流错误宣称） |
| HIGH | 5 | S9 ERROR(5) ErrMsg 字节数错；S9 序号/注释自相矛盾；T-202 窗口算术错；RFC 7440 末窗口/ACK 语义与 S6 冲突；T-008/T-122/T-120 自动追加判定与 tsize 判定矛盾 |
| MEDIUM | 8 | ERROR 消息字节数多处错（S8c/S8d/T-134/T-135）；§9.3 双 `\0` 矛盾；AutoAppendFinalBlock 与 FinalBlockZero 语义歧义；windowsize 与块号回绕；S6 13 包与 AutoAppend 默认 true 冲突；OACK 顺序声明与 RFC 不符；RRQ 511 字节选项截断未覆盖；T-097 与 §5.1 推导规则矛盾 |
| LOW | 6 | S5b 总包数公式笔误；T-139 UDP 长度单位混淆；§1.1 近似值表达；S13c short-circuit 未定义"末块满"；§2.4 错误消息编码精度；T-163 断言描述不精确 |
| **总计** | **22** | — |

### 1.3 总体评级

**有条件合格（需修复 3 个 CRITICAL + 5 个 HIGH 后方可进入实现）**。v2.0.0 相对 v1.1 是实质性进步：24 个旧问题全部修复、HexDump 大部分自洽、测试用例按规范驱动扩充到 241 条。但本次复审发现 3 个 CRITICAL：其中 R1-CRITICAL-1（S9 ERROR(5) 方向/端口错误）直接违反 RFC 1350 §4 的 TID 校验规则，会导致生成不可互操作的流量；R1-CRITICAL-2（ErrorCode=0 恒注入与 T-227/T-228 矛盾）会导致实现者按错误语义编码；R1-CRITICAL-3（半标准流宣称"合法"）违反 RFC 1350 §6 MUST 级要求且会造成测试误导。

---

## 2. CRITICAL 问题

### R1-CRITICAL-1：S9 TID 变更场景 ERROR(5) 的发起方与目标端口违反 RFC 1350 §4

**位置**：§4.3（行 350）、§5 ServerTIDChange 注释（行 512-515）、S9 包序列表（行 953-966，特别是第 7 行）

**描述**：v2.0.0 的 S9 场景中，ERROR code=5 的发送方与目标端口与 RFC 1350 的 TID 校验规则相反。

RFC 1350 §4 原文（关于收到源 TID 不匹配的包）：
> "the source TID is checked against the TID of the last received packet... If the TID doesn't match, the packet is discarded as erroneously sent from somewhere else. An error packet is sent to the source of the incorrect packet."

即：**接收方**收到来自**未知/错误源 TID** 的包时，向**那个错误源 TID** 回 ERROR code=5——目的是通知"这个 TID 我不认"。此时接收方与错误源之间**没有已建立的传输**，ERROR 是发给"包的实际来源"的。

v2.0.0 的 S9 序列（第 6-8 行）：
```
6. DATA#3（down, 61000 → C）          （新 TID 出现，服务器主动切换）
7. ERROR(5)（up, C → 61000）          （客户端向"新 TID"发，注释："告知旧 TID 失效"）
8. ACK#3（up, C → 61000）             （接受新 TID 继续）
```

**问题**：
1. 场景语义是"服务器主动切换 TID"（`ServerTIDChange` 字段、§5 注释 "simulates server switching to ServerTIDNew"）。服务器主动切换时，客户端收到来自新 TID 的 DATA#3 后，按 RFC 1350 应**丢弃该包并继续等待旧 TID 的 DATA#3**——因为客户端与服务器约定的 TID 是 60000，61000 发来的包"source TID doesn't match"。
2. 若按 RFC 1350 走"向错误源回 ERROR(5)"，客户端应向 **61000** 发 ERROR——这与文档 S9 相同。但关键区别：RFC 1350 的语义是**拒绝**这个新 TID（"discarded as erroneously sent"），而文档 S9 的语义是**接受**新 TID（ERROR 后继续向 61000 发 ACK#3）。
3. 文档自身注释矛盾：第 7 行注释写"客户端向**新 TID** 发，告知旧 TID 失效"——ERROR 发给新 TID 却"告知旧 TID 失效"，逻辑不通。若目的是告知旧 TID 失效，应发给**旧 TID 60000**（RFC 1783 的做法：向旧 TID 发 ERROR 通知"我不再认你"）。
4. RFC 1350 唯一认可的"不终止"例外是：**收到源端口不正确的包时**向错误源发 ERROR(5) 并**继续当前传输**——当前传输用的是旧 TID。若客户端向 61000 发 ERROR(5) 后又向 61000 发 ACK#3（S9 第 8 行），等于客户端**承认**了 61000 是新 TID，那 ERROR(5) 就失去意义。

**RFC 1783（v1.1 审计曾引用，v2.0.0 已删除）** 定义的 TID change 流程是：服务器切 TID → 客户端收到新 TID 的 DATA → 客户端向**新 TID** 发 ERROR(5) 表示"我还不认你"→ 服务器继续用新 TID 发 DATA → 客户端最终接受并 ACK。若设计者采用此语义，应引用 RFC 1783 并明确"这是扩展语义，非 RFC 1350 基础语义"。

**依据**：RFC 1350 §4（source TID 校验、错误源回 ERROR）；RFC 1783 §3（TID change 机制，Informational）。

**修复建议**：
- 方案 A（RFC 1783 语义，推荐）：S9 序列保持现状（ERROR 发向新 TID 后继续），但文档必须引用 RFC 1783 作为 TID-change 场景依据，并注明"RFC 1350 只定义了'向错误源回 ERROR(5) 后丢弃该包并继续原传输'的校验语义；本场景模拟的是 RFC 1783 的 TID 迁移，ERROR(5) 表示客户端尚未完成迁移"。同时修正第 7 行注释（"告知旧 TID 失效"→"告知服务器：包源 TID 与约定不符"）。
- 方案 B（RFC 1350 纯校验语义）：ERROR(5) 发向新 TID 后，**不**继续向新 TID 发 ACK#3；DATA#3 被视为丢弃，服务器重发 DATA#3（用新 TID），客户端再次检测……无限循环，无法收敛——因此方案 B 不可行，除非引入"第 N 次后接受"规则。
- 方案 A + 在 §4.3 中区分两种语义（TID 校验 vs TID 迁移），否则实现者无法编码。

### R1-CRITICAL-2：ErrorCode=0"恒注入"与 T-227/T-228 矛盾——同一字段两种语义并存

**位置**：§5 struct ErrorCode 注释（行 450-455："ErrorCode>0 才注入；ErrorCode=0 表示不注入"）、§5.4（行 594："含 ErrorCode=0"）、§9.2（行 1492："ErrorCode=0 恒注入（C3 修复）"）、T-227/T-228（行 1412-1413）

**描述**：v2.0.0 声称修复了 v1.1 C3（ErrorCode=0 语义歧义），但修复后的文档仍存在两种互斥语义：

- §5 struct 注释（行 450-451）："ErrorCode: inject an ERROR packet at ErrorAfterBlock. 语义: ErrorCode>0 才注入; ErrorCode=0 表示不注入 (ErrorAfterBlock 被忽略)."
- §9.2（行 1492）："code=0（Not defined）：ErrorCode=0 恒注入（C3 修复）；ErrorAfterBlock=0 时无注入点则不注入（T-228）"
- T-227（行 1412）："ErrorCode=0 总是注入"（期望 RRQ → DATA#1/ACK#1 → ERROR(0)）
- T-228（行 1413）："ErrorCode=0 + ErrorAfterBlock=0 不注入"（期望正常传输无 ERROR）

**问题**：
1. §5 说 "ErrorCode=0 表示不注入"，§9.2 和 T-227 说 "ErrorCode=0 恒注入"。实现者按 §5 编码则 T-227 失败；按 §9.2 编码则违背 §5 字段契约。
2. 唯一的调和条件是 "ErrorAfterBlock=0 时无注入点"（T-228）——即"恒注入"仅在 ErrorAfterBlock>0 时生效。但 §5 注释明确写 "ErrorCode=0 表示不注入 (ErrorAfterBlock 被忽略)"——"被忽略"与"ErrorAfterBlock>0 时注入"直接冲突。
3. 若 ErrorCode=0 且 ErrorAfterBlock=0，按 §9.2 是"不注入"；若 ErrorCode=0 且 ErrorAfterBlock=1，按 T-227 是"注入"。那么用户要"注入 code=0"必须设 ErrorAfterBlock=1；用户要"不注入"必须设 ErrorCode=0 + ErrorAfterBlock=0。**注入与否由 ErrorAfterBlock 决定，而 ErrorCode=0 的值毫无信息量**——这等于 ErrorCode 失去了"是否注入"的开关作用，与 §5 注释宣称的语义相反。
4. T-227 的期望（"ErrorCode=0 总是注入"）与其"输入 spec 要点"栏写的 "error_code=0, error_after_block=1" 一致，但 §5 注释不支持该行为。

**依据**：文档内部一致性（CLAUDE.md §Testing Policy 第 1 条——spec 必须无歧义）；v1.1 C3 的修复目标本身就是消除此歧义。

**修复建议**：
- 统一语义（推荐）：ErrorCode=0 **恒表示不注入**（即 §5 注释现状），删除 §9.2 "恒注入"表述；T-227 改为 error_code=0 + error_after_block=0 不注入的正向用例；新增字段（如 `InjectErrorCode0 bool`）或显式用 error_after_block>0 + error_code=0 触发（需同步改 §5 注释：去掉 "ErrorAfterBlock 被忽略"）。
- 或统一为"恒注入"：ErrorCode=0 且 ErrorAfterBlock>0 时注入 ERROR(0)；ErrorAfterBlock=0 时 ErrorCode 无论何值均不注入。此时 §5 注释必须改写。
- 无论选哪个，必须保证 §5 struct 注释、§5.4、§9.2、T-227、T-228、S8d 六处一致。

### R1-CRITICAL-3：半标准流（满块无 0 字节末块）被断言为"合法"，违反 RFC 1350 §6 MUST

**位置**：§3.3（行 157-159）、T-053（行 1196）、T-062（行 1205）、T-159（行 1322）、§9.4（行 1506-1507）

**描述**：T-053 断言："512=blksize → 无自动追加时传输'未正常结束'（半标准流，配合 auto_append_final_block=false 场景）"；T-159 期望 "PCAP 3 包，无 0 字节末块（用于互操作负向测试）"。

**问题**：
1. T-053/T-062 的输入：`blocks_count=1, blksize=512, data_payload_pattern=0xFF`（或 0xAA），auto_append_final_block 未设（默认 true）或显式 false。期望 "RRQ → DATA#1(512B) → ACK#1"。
2. 若 AutoAppendFinalBlock 默认 true（§5.1 表），而 BlocksCount=1×BlkSize=512，判定 TSize = 0（ClientTSize/ServerTSize 皆 0）→ 自动追加**不触发**（§5.1 要求判定TSize>0）。因此默认配置下 T-053 的 DATA#1(512B) 就是**末块满块**——传输结束标记缺失，真实 TFTP 客户端将永久等待下一块（RFC 1350 §6："The end of a transfer is marked by a DATA packet that contains between 0 and 511 bytes"——512 字节满块明确不是结束标记）。
3. 文档把这种流称为"半标准流"并断言可接受。但 RFC 1350 §6 是 MUST 级要求（"If the file is an exact multiple of 512 bytes, a final packet of 0 bytes must be sent"）。当用户没设 tsize 时，planner 无法知道文件大小是否恰为 blksize 整数倍——但**文档的默认行为是"不追加"**，即默认生成**不合规**流。这与 §5.1 "AutoAppendFinalBlock 默认 true（RFC 1350 §6 合规）"的宣称直接矛盾：默认 true 只在用户显式提供 tsize 时才生效，无 tsize 时默认输出不合规流。
4. T-053 断言 "512=blksize → 传输未正常结束" 说明作者意识到了问题，但将其作为"配合测试用"的正向用例列在 §7.1，且 T-159 明确"用于互操作负向测试"——负向测试目的本身合理，但 **T-053/T-062 列在正向用例表（§7.1）**且断言不完整（未断言"这是不合规流，不应与真实 TFTP 互操作"）。

**依据**：RFC 1350 §6（0 字节末块 MUST）；文档 §5.1 自身宣称（"默认 true（RFC 1350 §6 合规）"）。

**修复建议**：
- 方案 A（推荐）：明确规则——`BlocksCount×BlkSize` 满块且无 tsize 判定时，planner **默认追加 0 字节末块**（即 AutoAppendFinalBlock 对"未知文件大小"也生效：所有块满 blksize 时默认追加）。这才能兑现 "默认 true = RFC 合规"。
- 方案 B：若保持现状（无 tsize 不追加），则必须：① §5.1 表去掉 "AutoAppendFinalBlock 默认 true（RFC 1350 §6 合规）"的合规宣称，改为 "默认 true，但无 tsize 判定时不追加（可能产生不合规流，文档 §9.4）"；② T-053/T-062 从 §7.1 正向表移入 §7.3/§9.4 负向表；③ T-159 断言明确 "该流与真实 TFTP 客户端互操作将超时"。
- 注意：方案 A 会改变 T-001/T-012/T-014/T-015 等大量用例的包数（DATA#1 满块 512B 时会多出 DATA#2(0B)/ACK#2）——需全表联动修订。推荐方案 A，但务必评估用例影响面。

---

## 3. HIGH 问题

### R1-HIGH-1：S9 ERROR(5) 报文 ErrMsg 字节数错误

**位置**：S9 包序列表第 7 行（行 961）

**描述**：S9 第 7 行 ERROR(5) 标注 "（2+2+20=24 字节；…）"，但 ERROR 报文总长应为 2（opcode）+ 2（code）+ 20（"Unknown transfer ID\0"）= 24——**数字 24 是对的**。但 §5.4 映射表中 "Unknown transfer ID" 字节数（含 `\0`）标注为 **21**（行 603），S8a 场景无此错误。核对：`"Unknown transfer ID"` 是 19 个字符，+1 = 20，不是 21。§5.4 表写 21 是错误的。

（注：S9 行 961 的 "2+2+20=24" 是对的；错误在 §5.4 表的 21。）

**另外**：S9 第 7 行 ERROR 字节 `00 05 00 05 55 6e 6b 6e 6f 77 6e 20 74 72 61 6e 73 66 65 72 20 49 44 00` 逐字节核对：`55 6e 6b 6e 6f 77 6e` = "Unknown"（7 字符），`20` 空格，`74 72 61 6e 73 66 65 72` = "transfer"（8），`20`，`49 44` = "ID"（2），`00`。共 7+1+8+1+2+1 = 20 字节 + opcode/code 4 = 24 ✓。**但 T-111（行 1264）引用了完全相同的字节并断言 24B**——一致，无问题。问题只在 §5.4 表的 21。

**依据**：Python 核算 len("Unknown transfer ID")+1 = 20；§5.4 表标 21。

**修复建议**：§5.4 表第 5 行 "Unknown transfer ID | 21" 改为 20。同步检查 T-027（行 1165）引用 "21B"——T-027 写 "ErrMsg=`Unknown transfer ID\0`（21B）"，同样错误，应为 20B（ERROR 包总长 2+2+20=24B）。

### R1-HIGH-2：S9 包序号 6/7/8 的注释与 RFC 语义自相矛盾

**位置**：S9 表（行 960-963）

**描述**：S9 第 6 行 DATA#3 标注 "（新 TID 出现）"；第 7 行 ERROR(5) 标注 "（客户端向**新 TID** 发，告知旧 TID 失效）"；第 8 行 ACK#3 标注 "（接受新 TID 继续）"。

**问题**：注释逻辑链不通——"告知旧 TID 失效"应发给旧 TID 60000（通知 60000 的持有者"你的 TID 不被接受"），而发给新 TID 61000 的 ERROR(5) 语义是"我收到了来自 61000 的包但 61000 不在我的会话中"（RFC 1350 校验语义）。同一包不能同时表达"旧 TID 失效"和"我不认 61000"。且紧接着第 8 行 ACK#3 又发给 61000——若 ERROR 表达"我不认 61000"，ACK 又发给 61000，自相矛盾。唯一自洽的解释是 RFC 1783 迁移语义（见 R1-CRITICAL-1），但文档未引用 RFC 1783。

**依据**：RFC 1350 §4（ERROR code=5 的触发条件与目标）；逻辑一致性。

**修复建议**：随 R1-CRITICAL-1 一并处理——若采用 RFC 1783 语义，改写第 7 行注释为 "（客户端向新 TID 发 ERROR(5)：来源 TID 与约定不符；RFC 1783 迁移流程的一部分）"；若采用 RFC 1350 校验语义，则第 8 行 ACK 不应发给 61000（见 R1-CRITICAL-1 方案 B 的不可行性分析）。

### R1-HIGH-3：T-202 windowsize=65535 的窗口算术错误

**位置**：T-202（行 1377）

**描述**：T-202 输入 `windowsize=65535, blocks_count=70000, wrap=true`，期望 "窗口 65535 块；ACK#65535；**次窗口 464 块**"。

**问题**：70000 - 65535 = 4465，不是 464。4465 与 464 差一个数量级。若 windowsize=65535、blocks_count=70000，第一窗口 65535 块（块号 1..65535），第二窗口 4465 块（块号 65536..70000，wrap 后 0..4464）——期望应为 4465 块。

**依据**：算术 70000-65535=4465。

**修复建议**：T-202 期望改为 "次窗口 4465 块"。同时检查 T-203（blocks_count=131070 = 2×65535，两个完整窗口，期望未写具体窗口数，无算术错误，但块号回绕跨窗口——第 65536 块 Block#=0，需断言首末）。

### R1-HIGH-4：RFC 7440 末窗口判定与 S6 的实现冲突

**位置**：§3.9（行 265："The reception of a data window with a number of blocks less than the negotiated windowsize is the final window"）、S6（行 858）、T-009/T-120/T-121

**描述**：RFC 7440 的末窗口判定是**接收方视角**："收到的数据窗口块数 < windowsize 即为末窗口"。即：发送方发送的最后一个窗口包含的块数 < windowsize 时，接收方知道传输结束（配合块内数据长度 < blksize 或 0 字节末块）。

**问题**：S6 的 blocks_count=8, windowsize=4，末窗口正好 4 块（8 mod 4 = 0）——末窗口块数 **等于** windowsize，按 RFC 7440 判定不是末窗口，需要 0 字节末块或满块末块长度 < blksize 来标示结束。S6 行 858 自己也承认："块数为 8 的完整窗口（8 mod 4 == 0），结束判定仍需 0 字节末块 → 自动追加 DATA#9(0B)/ACK#9（若 tsize 判定触发）或由 FinalBlockZero 显式提供。本场景 blocks_count=8 不设 tsize，末块 #8 为满块 → 按 RFC 1350 需 0 字节终止块（AutoAppendFinalBlock 默认 true 但无 tsize 判定时不追加）"。

**冲突点**：文档在此处既承认"按 RFC 1350 需 0 字节终止块"，又因为自己的自动追加规则（无 tsize 判定不追加）而不追加——生成的 S6 流（13 包，末块满 512B）**不是合法 TFTP 传输**。且 S6 总包数标注 "= 13（不含自动追加）" 暗示 13 包是最终期望——与 AutoAppendFinalBlock 默认 true 的宣称矛盾（同 R1-CRITICAL-3）。

**依据**：RFC 7440 §3（末窗口判定）；RFC 1350 §6（0 字节末块 MUST）；文档 §5.1 自身规则。

**修复建议**：随 R1-CRITICAL-3 统一处理：若采用"默认追加"（方案 A），S6 期望变为 15 包（追加 DATA#9(0B)/ACK#9），T-009/T-120 同步；若保持不追加，S6/T-009 断言需明确"该流无结束标记，用于负向测试"。

### R1-HIGH-5：T-008（WRQ+tsize）期望包数与 OACK 后 DATA#1 起始块号矛盾

**位置**：T-008（行 1141）、S5b（行 820-824）

**描述**：T-008 输入 `mode=write, client_tsize=2048, blocks_count=4`，期望 "WRQ → OACK → DATA/ACK×4 → DATA#5(0B)/ACK#5（12 包）"。

**问题**：WRQ+OACK 分支无 ACK#0，DATA#1 是客户端发起的**第一块**。4 个数据块 + 自动追加 0 字节末块 DATA#5。包数 = 1（WRQ）+ 1（OACK）+ 4×2 + 2 = 12 ✓（与 S5b 一致）。**包数无误**。

但 T-008 的自动追加判定：判定 TSize = ClientTSize = 2048；BlocksCount×BlkSize = 4×512 = 2048 = 判定TSize → 触发追加 ✓。**T-008 本身自洽**。

再核对 T-122（行 1275）：`windowsize=2, server_tsize=2048, blocks_count=4, mode=read`，期望 11 包（RRQ+OACK+ACK#0 + 2×窗口(2 DATA+1 ACK) + DATA#5(0B)+ACK#5 = 1+1+1+6+2 = 11 ✓）。判定：ServerTSize=2048，4×512=2048 ✓。**自洽**。

T-120（行 1273）：`windowsize=4, blocks_count=4, client_tsize=2048`，期望 9 包（RRQ+OACK+ACK#0 + D1-4+ACK#4 + D5(0B)+ACK#5 = 1+1+1+5+2 = 10？）。**核算：1+1+1+（4 DATA + 1 ACK）+ 1 DATA#5 + 1 ACK#5 = 10 包，文档写 9 包**。且窗口结构：DATA#1-4 连续 + ACK#4（窗口末 ACK，1 个）——窗口内 4 DATA + 1 ACK = 5 包。总计 1+1+1+5+2 = 10。文档写 "（9 包）" 错误。

**结论**：T-120 期望包数 9 应为 10。**此问题升级为 R1-HIGH-5 主体**（T-008/T-122 无问题）。

**依据**：逐包核算。

**修复建议**：T-120 期望 "（9 包）" 改为 "（10 包）"。

---

## 4. MEDIUM 问题

### R1-MED-1：ERROR 消息字节数表多处错误（§5.4）

**位置**：§5.4（行 596-606）

**描述**：§5.4 表"字节数（含 `\0`）"逐项核算：

| ErrCode | 默认 ErrMsg | 文档标注 | 实际 | 结论 |
|---------|-------------|---------|------|------|
| 0 | Not defined | 13 | 12 | ❌ |
| 1 | File not found | 16 | 15 | ❌ |
| 2 | Access violation | 18 | 17 | ❌ |
| 3 | Disk full or allocation exceeded | 34 | 33 | ❌ |
| 4 | Illegal TFTP operation | 24 | 23 | ❌ |
| 5 | Unknown transfer ID | 21 | 20 | ❌ |
| 6 | File already exists | 21 | 20 | ❌ |
| 7 | No such user | 14 | 13 | ❌ |
| 8 | Failed to negotiate options | 29 | 28 | ❌ |

**全部 9 行都多算 1 字节**——作者显然把"字符数 + 2"当成"字符数 + 1"。该表的错误传播到：
- S8a（行 903-904）：ERROR(1) 标注 "2 + 2 + 15 = 19 字节（"File not found\0"=15B）"——**15B 是对的**，与 §5.4 的 16 矛盾。
- S8b（行 914-915）：标注 33B 正确，但 §5.4 表写 34。
- S8c（行 923-924）：标注 28B 正确，§5.4 写 29。
- S8d（行 930-931）：ERROR(0) 自定义 "User cancelled\0" 标注 15B（"User cancelled" 14 字符 +1 = 15 ✓）。
- T-025（行 1163）："ErrMsg=`Illegal TFTP operation\0`（24B）"——实际 2+2+23=27B 包；24 是错用 §5.4 表。
- T-026（行 1164）："（29B）" 应为 28。
- T-027（行 1165）："（21B）" 应为 20。
- T-134（行 1292）：ERROR(1) 字节精确断言 "（19B：2+2+15）"——15 正确，与 §5.4 16 矛盾。
- T-135（行 1293）："（32B：2+2+28）"——28 正确，§5.4 写 29。

**影响**：§5.4 表是"默认 ErrMsg 映射"的权威来源，9 行全错会导致实现者按错误长度编码（虽然内容 ASCII 不受影响，但 T-025~T-027 等用例断言依赖表值）。

**依据**：Python 逐串核算 len(s)+1。

**修复建议**：§5.4 表全部 9 行改为实际值（12/15/17/33/23/20/20/13/28）；T-025 改 "（23B）"；T-026 改 "（28B）"；T-027 改 "（20B）"；并全文搜索引用该表数字的地方同步修正。

### R1-MED-2：§9.3 双 `\0` 规则自相矛盾

**位置**：§9.3（行 1500）

**描述**：§9.3 说 "空 ErrMsg 显式请求（需仅 `\0`）→ 不支持（默认映射优先）；用户可设 ErrorMsg="\0" 实现（wire 上双 `\0`，Validate 拒绝——ErrMsg 不得含 `\0`）"。

**问题**：同一句话先说"用户可设 ErrorMsg="\0" 实现"，后说"Validate 拒绝"。若 Validate 拒绝，用户就**不能**设 ErrorMsg="\0" 实现；若可设，Validate 不应拒绝。而且 "wire 上双 `\0`" 的含义模糊——ErrorMsg="\0" 会编码为 `\0\0`（一个来自字段值、一个来自终止符），这正是"ErrMsg 不得含 `\0`"规则要禁止的。此条既违反 RFC 1350（ErrMsg 是 netascii 字符串，不应含 `\0`），又自相矛盾。

**依据**：逻辑一致性；RFC 1350 §4（字符串以零字节终止，内容不应含零）。

**修复建议**：删除 "用户可设 ErrorMsg="\0" 实现" 半句，改为 "空 ErrMsg（仅 `\0`）无法通过 ErrorMsg 字段表达——默认映射优先；Validate 拒绝含 `\0` 的 ErrorMsg（`tftp: error_msg must not contain null byte`）"。补一条 Validate 负向用例（如 T-105 后新增）。

### R1-MED-3：AutoAppendFinalBlock 与 FinalBlockZero 的语义边界模糊

**位置**：§5 struct AutoAppendFinalBlock（行 477-482）、FinalBlockZero（行 484-488）、§5.3（行 582）、T-018/T-019/T-052/T-068

**描述**：
1. AutoAppendFinalBlock 判定条件要求 "BlocksCount×BlkSize == 判定TSize 且 判定TSize > 0"。FinalBlockZero 与 AutoAppendFinalBlock 判定的"跳过重复追加"规则（§5.3 行 582："自动追加规则跳过（末块已显式，不重复追加）"）只提到 "当自动追加条件也满足时不重复追加"——但 §5.3 行 582 写的是 "自动追加规则跳过（末块已显式，不重复追加）"。
2. T-019（行 1152）：`blocks_count=3, blksize=512, client_tsize=1024, final_block_zero=true`，断言 "2×512=1024=判定TSize 但末块已显式，不重复追加 DATA#4"——但输入是 blocks_count=**3**，3×512=1536 ≠ 1024！判定 TSize=1024，BlocksCount×BlkSize=1536，**自动追加本来就不会触发**（1536≠1024），"不重复追加"的断言是空转——测试没有验证"末块已显式时跳过追加"这一规则，因为触发条件本身不成立。**T-019 输入与断言不匹配**：要么 blocks_count 应为 2（则 2×512=1024=判定TSize，自动追加条件满足但被 FinalBlockZero 跳过——这才真正测试了跳过逻辑），要么断言应改为 "1536≠1024，自动追加本不触发"。
3. T-052（行 1195）：`final_block_zero=true, blocks_count=1, blksize=512` 期望 "RRQ → DATA#1(0B) → ACK#1"。FinalBlockZero=true 时末块（BlocksCount 块）为 0 字节——blocks_count=1 时唯一一块就是 0 字节。这是"显式 0 字节块"语义。但注意：此流与"文件为空"等价（0 字节 DATA 是合法的第一块且是末块），与 RFC 1350 兼容（0 字节 DATA 表示结束）✓。无问题。
4. §5.3 行 582 与 §5 struct FinalBlockZero 注释（行 487："当自动追加条件也满足时不重复追加（末块已显式）"）一致，但 T-019 未真正测试（见上）。

**依据**：T-019 输入/断言算术核查；§5.3 规则。

**修复建议**：T-019 输入 blocks_count 改为 2（或 client_tsize 改为 1536 使判定成立），确保测试真正覆盖"FinalBlockZero 跳过自动追加"。T-018（行 1151）`blocks_count=3, auto_append=false, final_block_zero=true` 无 tsize，判定 TSize=0 不触发——同样未测跳过逻辑，但作为"显式末块"正向用例无碍。建议补一个 blocks_count=2 + client_tsize=1024 + final_block_zero=true 的用例。

### R1-MED-4：windowsize 与块号回绕（wrap）的交互未定义

**位置**：§3.9、S6、T-202/T-203

**描述**：T-203 `windowsize=65535, blocks_count=131070, wrap=true` 期望 "块号回绕跨窗口"。但文档未定义**窗口边界与回绕的交互规则**：
- 窗口内的块号计算：块 i 的 Block# = (i mod 65536)。第一窗口块 1..65535（Block# 1..65535），第二窗口块 65536..131070（Block# 0..65534）。第二窗口的 ACK# 是什么？按"ACK 确认窗口末尾 Block#"规则，ACK# 应为窗口末块的 Block# = 65534——但客户端如何区分"ACK#65534 确认块 131070"与"块 131070 是回绕后的 Block#65534"？
- 更严重的：第一窗口末块 Block#=65535，ACK#65535；第二窗口首块 Block#=0。接收方收到 Block#=0 的 DATA 时（回绕后），可能将其误判为"ACK#0 后重传的块"或"新传输的块 0"（DATA 块号从 1 开始，Block#=0 在 DATA 中非法——RFC 1350 中 DATA 的 Block# 恒 ≥1，0 只出现在 ACK 中）。
- §3.3（行 159）只说 "Block# = (i mod 65536)"，未说明 wrap 与 windowsize、与 ACK 的交互。真实 TFTP 在块号回绕后无法区分新旧块（RFC 1350 明确不定义回绕行为），windowsize 的"窗口末 ACK"机制与回绕叠加会让接收方混淆。
- T-203 期望 "块号回绕跨窗口" 但未定义接收方视角的正确性断言——测试不可断言（无法验证"正确"是什么）。

**依据**：RFC 7440（ACK 窗口末块）；RFC 1350（块号无回绕定义）；文档 §3.3。

**修复建议**：明确声明："WrapBlockNumber=true 与 windowsize>1 组合时，回绕窗口的 ACK 语义与接收方判定由测试场景自行定义（该组合在真实 TFTP 中无互操作性保证，仅用于生成器字节序列测试）"。或将 wrap 与 windowsize 互斥（Validate 拒绝 windowsize>1 + wrap=true）。推荐后者（简单、无歧义）。

### R1-MED-5：S6 场景 13 包与 AutoAppendFinalBlock 默认 true 的内部矛盾

**位置**：S6（行 858）、T-009（行 1142）

**描述**：S6 输入无 tsize（ClientTSize=ServerTSize=0），blocks_count=8 满块 512B。文档行 858 明确承认 "末块 #8 为满块 → 按 RFC 1350 需 0 字节终止块（AutoAppendFinalBlock 默认 true 但无 tsize 判定时不追加）"——即默认 true 的字段在此场景无效。**总包数 = 13（不含自动追加）** 的期望意味着：默认配置生成的流是"无结束标记"的流。这与 §5.1 "AutoAppendFinalBlock | true（RFC 1350 §6 合规）"（行 538）矛盾——默认 true 却没产生 RFC 合规流。

（与 R1-CRITICAL-3 同源，此处列为独立 MEDIUM 是因为 S6/T-009 是"正向 windowsize 场景"却产出不合规流，且文档已自我承认。）

**依据**：RFC 1350 §6；文档 §5.1 行 538 与 S6 行 858 的直接冲突。

**修复建议**：随 R1-CRITICAL-3 方案统一。若选方案 A（默认追加），S6 期望 15 包、T-009 期望 15 包；若选方案 B，删除 §5.1 行 538 的 "（RFC 1350 §6 合规）" 并全文档一致声明默认行为可能产出不合规流。

### R1-MED-6：OACK 选项顺序"与 RRQ 一致"的声明与 RFC 2347 冲突且与 S7 矛盾

**位置**：§4.4（行 375-379）、T-200（行 1375）

**描述**：T-200 断言 "OACK 选项顺序与 RRQ 相同（§4.4）"。但：
1. RFC 2347 明确规定 "The order in which options are specified is not significant"（选项顺序无意义）——trafficgen 固定 RRQ 输出顺序是内部约定（§3.2），OACK 与 RRQ 同序也是内部约定，均不违反 RFC（RFC 不要求乱序）。此点无合规问题。
2. **但 §4.4 行 375-379 定义的 OACK 值回显规则与 T-200 的"同序"声明不构成矛盾**——顺序约定本身自洽。真正的矛盾在：S7 的 OACK（行 886-887）与 RRQ（行 876-881）顺序一致（blksize→timeout→tsize）✓。
3. 无实质矛盾。**此条撤回**——R1-MED-6 不成立。

（审计自纠：§4.4 OACK 回显规则 "blksize：回显请求值（允许值域 8-65464）" 与 RFC 2348 "服务器返回值必须 ≤ 客户端提议值"——trafficgen 回显原值即"≤ 原值"的特例 ✓；"timeout：回显请求值（RFC 2349 强制相同）" ✓；"tsize：RRQ 回 ServerTSize，WRQ 回 ClientTSize" ✓；"windowsize：回显请求值（RFC 7440 允许 ≤ 请求值）" ✓。§4.4 全部合规，无问题。）

### R1-MED-7：RRQ 请求包 512 字节上限的选项截断行为未定义

**位置**：§3.2（行 136）、T-065（行 1208）

**描述**：§3.2 说 "RRQ/WRQ 最大请求包 512 字节（RFC 2347：maximum request packet size is 512 octets）。超出时选项被截断或由实现决定（trafficgen 不截断，直接生成超长包供测试）"；T-065 说 "超限时（filename=500 字符）Validate 警告（Report）"。

**问题**：
1. §3.2 说 "trafficgen 不截断，直接生成超长包"——生成超长包本身合法（RFC 2347 说"选项被截断**或由实现决定**"，但更准确说 RFC 2347 原文是 "the request should be truncated"？——实际 RFC 2347 §3 说："If the request is longer than 512 octets, the server MAY truncate it"）。trafficgen 生成超长包用于测试**可接受**。
2. **但**：filename=500 字符 + blksize 选项的 RRQ 长 500+1+6+2+14 = 523 字节 > 512。T-065 期望 "Validate 警告（Report）"。然而 **V23 警告规则（§8.1 行 1463）只覆盖 RRQ/WRQ 超 512 字节的警告**——500 字符 filename 本身超 255 字节限制（V3：≤255 字节）！filename=500 字符会先触发 V3 错误（"filename exceeds 255 bytes"），根本到不了 V23 警告。**T-065 的 filename=500 用例自相矛盾**。
3. 正确测试 512 上限的方式：filename 255 字节（最大合法）+ 各选项值组合使总长 > 512（如 blksize=65464 的选项对只有 14 字节，不够；需多选项）。T-065 的上半部分（filename=200 + blksize=65464 → 223B < 512 通过）正确，下半部分（filename=500）错误。

**依据**：V3（§8.1）filename ≤255 字节错误规则与 T-065 冲突；算术 500>255。

**修复建议**：T-065 的"超限"子用例改为 filename=255（最大）+ 全 4 选项（blksize=65464+timeout=255+tsize=2^32-1+windowsize=65535）使 RRQ 总长 > 512，断言 V23 警告触发；删除 filename=500 子用例（或改断言为 V3 错误）。

### R1-MED-8：T-097 与 §5.1 BlocksCount 推导规则矛盾

**位置**：T-097（行 1245）、§5.1（行 546-548）

**描述**：T-097 输入 `blocks_count=0, data_payload_pattern=""` 期望报错 "`tftp: blocks_count=0 requires data_payload_pattern or payload source`"。

**问题**：§5.1 推导规则（行 546-547）："`DataPayloadPattern` 非空：推导为 1 块。否则要求 Payload/FileSource 提供数据规模。"——**data_payload_pattern 为空字符串 = 非空？** 空字符串在 Go 中 len=0，与 nil 等价（`json:"data_payload_pattern,omitempty"` 下空串与缺省无法区分）。§5.1 的 "DataPayloadPattern 非空" 应理解为"长度 > 0"。T-097 的 `data_payload_pattern=""` 即"空"→ 推导要求 Payload 源 → 无 → 报错。**T-097 与 §5.1 一致，无矛盾。**

但 §5 struct DataPayloadPattern 注释（行 497-498）："空且 BlocksCount==0（derive）时要求 Payload/FileSource 提供数据规模（见 §5.1）"——与 T-097 一致 ✓。**R1-MED-8 不成立，撤回。**

（审计自纠：T-060（行 1203）`blocks_count=1, data_payload_pattern=""` 期望 "DATA#1(512B 确定性模式)"——§5 struct 注释（行 496）："空且 BlocksCount>0 时用确定性 0x00..0xFF 模式" ✓ 一致。无问题。）

---

## 5. LOW 问题

### R1-LOW-1：S5b 总包数公式笔误

**位置**：S5b（行 824）

**描述**：S5b 总包数标注 "= 12"（WRQ + OACK + 4×2 + 2 = 12），但括号内算式写 "WRQ + OACK + 4×2 + 2 = 12"——4×2+2+2 = 12 ✓ 算术本身正确。实际是 "WRQ(1) + OACK(1) + DATA/ACK×4(8) + DATA#5+ACK#5(2) = 12" ✓。无错误，撤回。

（审计自纠：S5a 总包数标注 13（行 807 处无显式标注，从 "包 4-11 DATA#1..#4 + ACK#1..#4" 推得 1+1+1+8+2 = 13 ✓。）

### R1-LOW-2：T-139 UDP 长度字段含义混淆

**位置**：T-139（行 1223 处，实际行 1282 表项）

**描述**：T-139 断言 "DATA 包 UDP Len = 8+516 = 524；RRQ 包 = 8+14 = 22"——UDP 头的 Len 字段是 **UDP 数据报总长（含 8 字节 UDP 头）**，524/22 正确。但 S1（行 638）标注 "Len = 8 + 19 = 0x1B = 27"——S1 RRQ UDP Len=27 ✓ 一致。无错误，撤回。

（审计自纠：S1 包 2 行 646-648 的 "01f4" 注释——"UDP head: <tid> c000 01f4 0000; Len = 8 + 4 + 100 = 0x1F4? 否 — 见下"——这是文档作者故意写错的演示并自我纠正，0x70=112 是最终值 ✓。该行格式混乱但结论正确。）

### R1-LOW-3：§1.1 最大文件大小近似值表达

**位置**：§1.1（行 28）

**描述**：§1.1 写 "65535×65464 ≈ 3.99 GB（受 tsize 选项 uint32 上限 4 GB-1 制约）"。核算：65535×65464 = 4,290,183,240 ≈ 3.99 GB ✓；4GB-1 = 4,294,967,295 > 4,290,183,240 ✓（3.99GB < 4GB-1，不冲突）。表述正确。**撤回。**

（审计自纠：无问题。）

### R1-LOW-4：S13c short-circuit 用例未断言"末块为满块"的合法性

**位置**：S13c（行 1045-1046）、T-048（行 1191）

**描述**：S13c `blocks_count=65535, wrap=false` 期望 "最后一个 DATA 的 Block#=65535"。blocks_count=65535 全部满块 512B 时，末块是满块——按 RFC 1350 §6，该流无结束标记（除非 tsize 判定触发追加，而此用例无 tsize）。short-circuit 只断言 Block#，不断言结束标记。这与 R1-CRITICAL-3 同源，此处仅为补充：S13c/T-048 应注明 "该流无 0 字节末块（无 tsize 判定），如需合规需设 client_tsize=33553920 触发追加（即 T-050 场景）"。

**依据**：RFC 1350 §6。

**修复建议**：S13c 加注一行。

### R1-LOW-5：§2.4 错误消息"ASCII + 0x00"未注明 netascii 编码

**位置**：§2.4（行 66）

**描述**：§2.4 表 "字符串（filename/mode/option/value/ErrMsg）| ASCII + 单个 `0x00` 结尾"。RFC 1350 对 ErrMsg 的要求是 "intended for human consumption, and should be in netascii"——netascii 的 CR/LF 转换（\r\n 转 \n 等）在 netascii 模式下才有意义；trafficgen 按字节原样写入（§2.3 已声明 "trafficgen 按字节原样写入（不做 netascii 的 CR/LF 转换）"）。§2.4 的 "ASCII" 与 §2.3 的 "netascii 原样" 表述基本一致，**仅建议**在 §2.4 表加注 "netascii 的 CR/LF 转换不适用（trafficgen 原样写入）" 以与 §2.3 完全对齐。

### R1-LOW-6：T-163 断言"8 份包序列字节相同"与 FNV-1a(FlowID) 确定性冲突风险

**位置**：T-163（行 1331）

**描述**：T-163 期望 "8 goroutine 同 spec → 8 份包序列字节相同"。ServerTID 由 FNV-1a(FlowID) 推导——**FlowID 在并发 Plan 同一 spec 时是否相同**？若 FlowID 含时间戳/随机后缀（trafficgen 引擎层常见），8 次 Plan 的 FlowID 不同 → ServerTID 不同 → 包字节不同 → T-163 断言失败。文档未说明 FlowID 的构成（S12 行 1027 说 FlowID = `<src_ip>-<dst_ip>-<src_port>-<dst_port>`，若仅此则确定性成立）。**建议**：T-163 断言改为 "8 份序列的 ServerTID 相同（FNV-1a(FlowID) 确定性）"，并注明依赖 FlowID 构成不变。属提示级。

---

## 6. HexDump 自洽性验证（逐字节核算结果）

| 场景 | 核算 | 结果 |
|------|------|------|
| S1 RRQ | 2+11+6=19B；UDP Len 27 | ✅ |
| S1 DATA#1 | 4+100=104B；UDP 112=0x70 | ✅ |
| S2 WRQ | 2+11+6=19B | ✅ |
| S2 DATA#1 | 4+200=204B；UDP 212=0xD4 | ✅ |
| S3 RRQ | 2+10+6+8+5=31B | ✅ |
| S3 OACK | 2+8+5=15B | ✅ |
| S3 DATA | 4+1428=1432B；UDP 1440=0x5A0 | ✅ |
| S4 RRQ | 2+6+6+8+3=25B | ✅ |
| S4 OACK | 2+8+3=13B | ✅ |
| S5a RRQ | 2+9+6+6+2=25B | ✅ |
| S5a OACK | 2+6+5=13B | ✅ |
| S5b WRQ | 2+10+6+6+5=29B | ✅ |
| S6 RRQ | 2+6+6+11+2=27B | ✅ |
| S6 OACK | 2+11+2=15B | ✅ |
| S7 RRQ | 2+10+6+12+10+8=48B | ✅ |
| S7 OACK | 2+12+10+11=35B | ✅ |
| S8a ERROR(1) | 2+2+15=19B | ✅ |
| S8b ERROR(3) | 2+2+33=37B | ✅ |
| S8c ERROR(8) | 2+2+28=32B | ✅ |
| S8d ERROR(0) | 2+2+15=19B | ✅ |
| S9 ERROR(5) | 2+2+20=24B | ✅（字节串正确） |
| S10 RRQ | 2+6+6=14B | ✅ |
| S13a DATA 512 | 4+512=516B；UDP 524=0x20C | ✅ |
| S13b blksize=8 | 4+8=12B；UDP 20 | ✅ |
| S13b blksize=65464 | 4+65464=65468B；UDP 65476≤65507 | ✅ |
| S15a RRQ | 2+9+6+13+10+8=48B | ✅ |
| S15a OACK | 2+13+10+11=36B（文档未标数，核算 36） | ✅ |
| T-126/T-127 | 2+6+6=14B | ✅ |
| T-128/T-131 | 15B | ✅ |
| T-129/T-130 | 13B | ✅ |
| T-137 | 2+12+10+11=35B | ✅ |

**结论**：所有场景的**字节串本身**自洽。问题集中在 §5.4 错误消息长度表的 9 行错值（R1-MED-1）——该表是权威来源，字节串标注（S8a-c、T-134/T-135）反而正确，形成"表与标注互相矛盾"的格局。

**包数核算**：

| 场景/用例 | 期望 | 核算 | 结论 |
|-----------|------|------|------|
| S1 | 3 | 1+1+1 | ✅ |
| S2 | 4 | 1+1+1+1 | ✅ |
| S3 | 7 | 1+1+1+2+2 | ✅ |
| S4 | 5 | 1+1+1+1+1 | ✅ |
| S5a | 13 | 1+1+1+8+2 | ✅ |
| S5b | 12 | 1+1+8+2 | ✅ |
| S6 | 13 | 1+1+1+5+5 | ✅ |
| S7 | 15 | 1+1+1+8+2 | ✅ |
| S9 | 10 | 1+8+1 | ✅ |
| S10 | 7 | 1+6 | ✅ |
| S15a | 13 | 1+1+1+8+2 | ✅ |
| S15b | 8 | 1+1+6 | ✅ |
| T-118 | 8 | 1+1+1+4+1+1 | ✅ |
| T-120 | 9 | 1+1+1+5+1+1=10 | ❌ **应为 10**（R1-HIGH-5） |
| T-122 | 11 | 1+1+1+3+3+1+1 | ✅ |
| T-202 | — | 70000-65535=4465 ≠ 464 | ❌（R1-HIGH-3） |
| T-161 | 1608 | 8×(1+200)=1608 | ✅ |
| T-124 | 16 | 10+3+3 | ✅ |
| T-125 | 11 | 5+3+3 | ✅ |

---

## 7. RFC 合规性逐条核对（复审）

| RFC 要求 | 文档实现 | 结论 |
|----------|----------|------|
| Opcode 1-6 编码（2B BE） | §3.1 | ✅ |
| RRQ/WRQ = filename + mode + 选项（\0 终止） | §3.2 | ✅ |
| DATA = Block#(2B BE) + data ≤ blksize | §3.3 | ✅ |
| ACK = Block#(2B BE) | §3.4 | ✅ |
| ERROR = code(2B BE) + errmsg + \0 | §3.5 | ✅ |
| 错误码 0-8（含 RFC 2347 code=8） | §3.6 | ✅ |
| code=5 唯一不终止错误 | §4.3 | ✅（但 S9 实现语义见 R1-CRITICAL-1） |
| BlocksCount uint32 表示 65536 | §5 C1 修复 | ✅ |
| windowsize 窗口机制 | §3.9/S6 | ⚠ 末窗口与默认追加矛盾（R1-HIGH-4/R1-MED-5） |
| TID 校验：错误源回 ERROR(5) 并丢弃包 | §2.5 | ⚠ S9 场景方向/语义（R1-CRITICAL-1） |
| 服务器 OACK 不含未请求选项 | §3.7 | ✅ |
| 服务器不识别选项 → 省略不报错 | §3.7 | ✅ |
| RRQ+OACK → ACK#0 → DATA#1 | §4.1 | ✅ |
| WRQ+OACK → 直接 DATA#1（无 ACK#0） | §4.2 | ✅ |
| WRQ 无选项 → ACK#0 | §4.2 | ✅ |
| blksize 8-65464 | §8.1 V4 | ✅ |
| timeout 1-255 | §8.1 V5 | ✅ |
| tsize RRQ 写 "0"、WRQ 写实际值 | §5.2 | ✅ |
| windowsize 1-65535 | §8.1 V6 | ✅ |
| 0 字节末块（文件 = blksize 整数倍）MUST | §3.3/§5.1 | ⚠ **默认行为不追加**（R1-CRITICAL-3） |
| ERROR 不确认不重传 | §3.5 | ✅ |
| 锁步流控（每 DATA 一 ACK） | §1.1 | ✅ |
| 选项名大小写不敏感 | §2.3 | ✅ |
| 选项只出现一次 | §3.2 | ✅ |
| 选项顺序无意义（RFC）；固定顺序（trafficgen） | §3.2 | ✅ 不冲突 |

---

## 8. CLAUDE.md §Testing Policy 8 条规则审核

| 规则 | 结论 | 说明 |
|------|------|------|
| §1 spec-driven | ⚠ | 241 条对应 §2-§6，但 T-227/T-228 与 §5/§9.2 语义冲突（R1-CRITICAL-2）；T-065 与 V3 冲突（R1-MED-7） |
| §2 失败路径 | ✅ | 负向 20 + Validate 拒绝 35，覆盖 9 个 code、全部边界 |
| §3 单路径测试 | ⚠ | T-019 未真正测试"FinalBlockZero 跳过自动追加"（输入使触发条件不成立，R1-MED-3） |
| §4 集成测试 | ✅ | T-141~T-160 覆盖 Plan→Worker→PCAP→tshark→NIC→replay |
| §5 可观察断言 | ⚠ | T-053/T-062 断言"半标准流"但未断言其不合规性（R1-CRITICAL-3）；T-202 期望值算术错（R1-HIGH-3） |
| §6 并发正确性 | ✅ | T-161~T-175 测聚合速率/序号连续性/确定性 |
| §7 failing-test-first | ✅ | §11 记录了修复与对应用例映射 |
| §8 测试质量审查 | ⚠ | T-120 包数错（R1-HIGH-5）；§5.4 表 9 行错（R1-MED-1） |

---

## 9. 必须修复的问题清单（按优先级排序）

### 实现前必须修复（CRITICAL）

1. **R1-CRITICAL-1**：S9 TID 变更 ERROR(5) 方向/端口语义——引用 RFC 1783 或重写 §4.3/S9/§5 注释，消除"告知旧 TID 失效却发给新 TID"的矛盾
2. **R1-CRITICAL-2**：ErrorCode=0 语义统一——§5 注释、§5.4、§9.2、T-227、T-228 五处对齐
3. **R1-CRITICAL-3**：满块无 0 字节末块的默认行为——决定"默认追加"（方案 A）或"明确声明默认产出不合规流"（方案 B），联动修订 §5.1/S6/T-053/T-062/T-159

### 建议同时修复（HIGH）

4. **R1-HIGH-1**：§5.4 表 "Unknown transfer ID" 21→20；T-027 "21B"→"20B"
5. **R1-HIGH-2**：S9 第 7 行注释逻辑矛盾（随 R1-CRITICAL-1）
6. **R1-HIGH-3**：T-202 次窗口 464→4465 块
7. **R1-HIGH-4**：S6/T-009 末窗口与默认追加矛盾（随 R1-CRITICAL-3）
8. **R1-HIGH-5**：T-120 期望包数 9→10

### 建议改进（MEDIUM）

9. **R1-MED-1**：§5.4 表 9 行字节数全错（12/15/17/33/23/20/20/13/28）；T-025/T-026/T-027 同步
10. **R1-MED-2**：§9.3 双 `\0` 规则自相矛盾
11. **R1-MED-3**：T-019 输入使跳过逻辑不可测
12. **R1-MED-4**：wrap + windowsize 交互未定义（建议互斥）
13. **R1-MED-5**：S6 行 858 与 §5.1 行 538 直接矛盾（随 R1-CRITICAL-3）
14. **R1-MED-7**：T-065 filename=500 子用例与 V3 冲突
15. **R1-MED-6/R1-MED-8**：审计自纠撤回（见正文）

### 可选（LOW）

16. **R1-LOW-4**：S13c/T-048 注明无结束标记
17. **R1-LOW-5**：§2.4 加注 netascii 原样写入
18. **R1-LOW-6**：T-163 断言注明 FlowID 构成依赖
19. **R1-LOW-1/2/3**：审计自纠撤回（见正文）

---

## 10. 最终结论

**本文档不可以直接进入实现阶段（否）——但仅需小幅修订。** 与 v1.1 相比，v2.0.0 已修复全部 24 个旧问题，主体设计（字段、状态机、HexDump、测试矩阵）质量明显提升。剩余 3 个 CRITICAL 均为"语义歧义/自相矛盾"而非"结构性错误"——修复工作量集中在文档措辞与测试期望值，不涉及字段类型或状态机重构。

**必须修复后再进入实现**：
- R1-CRITICAL-1（S9 ERROR(5) 语义）——直接影响 S9/T-110/T-111/T-149/T-169/T-205 六个用例与实现的编码依据
- R1-CRITICAL-2（ErrorCode=0 语义）——直接影响 ErrorCode 字段实现与 T-227/T-228
- R1-CRITICAL-3（默认追加行为）——影响 §5.1 规则与 S6/T-009/T-053/T-062/T-159 等十余个用例的期望包数

**建议同时修复**：5 个 HIGH（其中 2 个是纯数字修正：T-202、T-120）与 R1-MED-1（§5.4 表 9 行错值——该表是默认 ErrMsg 的权威来源，错值会传播到实现与断言）。

**复审建议**：修复上述问题后需一次轻量复审（重点：§5.4 表、S9、T-120/T-202 的期望值、§9.2 语义），无需全面重审。

---

**审计报告结束**。
