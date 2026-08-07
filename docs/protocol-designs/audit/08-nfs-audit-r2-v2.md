# 08-NFS 设计文档复审报告（r2-v2）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/08-nfs-design.md`（v2.0.1，2197 行）
**规范**：RFC 7530 / RFC 7531 / RFC 1813（本次经 rfc-editor.org 原文核实 sattr3、wcc_data、read3resok、write3resok、writeverf3、dirlist3）/ RFC 5531 / RFC 5661（opcode 对照）
**审计日期**：2026-08-05
**审计员**：独立审计代理（复审）
**方法**：逐节对照 RFC 复核 + 全部 HexDump 逐字节核算 + 逐项验证第一份审计（r1，25 问题：7C+6H+7M+5L）的修复落地情况 + 按 CLAUDE.md §Testing Policy 8 条评估测试用例

---

## 审计结论摘要

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 3 |
| HIGH | 7 |
| MEDIUM | 10 |
| LOW | 5 |
| **合计** | **25** |

**最终结论：否（不能直接进入实现阶段）。** v2.0.1 正确修复了 r1 的 5-6 项问题（C1 opcode 38/39 表、C2 COMPOUND reply status→tag→resarray、C3 S9 改 READDIRPLUS、C5 cookieverf3 补齐、H4 fattr3 80→84、L1 T-046），并新增 sattrguard3（H2）与双 count READDIRPLUS（H3）。但 r1 的 **C-2（RM 长度）、C-3（AcceptState 偏移）、C-4（verf 编码）、C-6（clientid 三处矛盾）、C-7（测试复读错误值）、H-1（GETATTR result）、H-5（wcc_data）、M-1/M-3/M-4/M-5/M-7** 等 12 项仍未修复；且本次复审新发现 **sattr3 编码整体错误（全文档级，S3/S7 HexDump + §2.8 + 5 条测试断言）**、**S12 幽灵 component4 偏移错位**、**S9 缺 dirlist3 内层 eof** 等 6 项新问题。

---

## r1 修复落地验证（13 项逐一核对）

| r1 编号 | 问题 | 状态 | 说明 |
|---------|------|------|------|
| C-1 | opcode 38-40 错位 | ✅ 已修复 | 38=WRITE、39=RELEASE_LOCKOWNER、WANT_DELEGATION 删除；T-095=0x26、T-129=0x27 正确；EXCHANGE_ID=42/CREATE_SESSION=43/DESTROY_SESSION=44/BIND_CONN=41 经 RFC 5661 核实全部正确；修订记录称 WANT_DELEGATION=56 也正确 |
| C-2 | 全部 RM 长度少算 | ⚠️ 部分修复 | 仅 S11/S15 修对；S1 CALL（24 vs 40）、S1 REPLY（20 vs 24）、S2 CALL（36 vs 48）仍错；T-001/T-002/T-003 复读错误值 |
| C-3 | REPLY AcceptState 偏移声明 | ❌ 未修复 | §7.1 仍写 AcceptState=28（空 verifier 时应 @24）；§10.2 28-31 同错 |
| C-4 | writeverf3/verf4 带长度前缀 | ❌ 未修复 | S6 004C、S10 0044 仍画 "verf length=8" |
| C-5 | S9 缺 cookieverf3 | ✅ 已修复 | cookieverf3 @ 0078、value_follows @ 0080、eof @ 0084（但仍有问题，见 H-6） |
| C-6 | clientid 三处矛盾 | ❌ 未修复 | §4.3/§10.4 公式、§10.4 注释、S13 表、T-106/T-177 仍互相矛盾 |
| C-7 | 测试复读错误值 | ❌ 未修复 | T-001/T-002 仍断言错误 RM；T-006 "18 (24B)" 仍在 |
| H-1 | GETATTR result 无字节 | ❌ 未修复 | S11 REPLY 仍到 bitmap_len 为止 |
| H-2 | OPEN_CONFIRM 边界 | ⚠️ 部分 | 注释措辞修了，但 S12 与自动补全规则冲突仍在（见 H-7） |
| H-3 | OpenReplyStateid 接线 | ❌ 未修复 | 仍只说"通过此字段建立引用"，机制未定义 |
| H-4 | fattr3 80/84 | ✅ 已修复 | S2/S4/S5/S7 全部 84，偏移重算正确 |
| H-5 | wcc_data 结构/长度 | ❌ 未修复 | S6/S8/S10 仍标 [36 bytes] |
| H-6 | v3 错误 reply 无字节级定义 | ⚠️ 部分 | T-046 语义修了，但仍无 v3 错误 HexDump |
| M-1~M-7 / L-1~L-5 | 各 MEDIUM/LOW | ⚠️ 部分 | L-1（T-046）、L-3（cookieverf 注释）已修；M-1/M-3/M-4/M-5/M-7、L-2/L-4/L-5 未修；M-6 部分（规则 5 补充） |

---

## CRITICAL（3 项）

### C-1. RM 长度系统性少算仍未修复（r1 C-2 残留，S1/S2 + T-001/T-002/T-003）

**位置**：§6 S1（行 912 RM=0x80000018、行 929 RM=0x80000014、标题"28/24 字节"）、S2 CALL（行 949 RM=0x80000024=36）；§7.1 T-001（RM=0x80000018）、T-002（RM=0x80000014）、T-003（"CALL payload 28B"）。

**描述**：S11/S15 已按"RPC 头 40 字节"重算，但 S1 CALL 段长仍按 24 字节头（实际 40）、S1 REPLY 按 20（实际 24）、S2 CALL 按 36（实际 48，40 头+fh 8B）。S1 标题"28 字节"与 RM len=24 自洽但与 RPC 消息实际 40 字节矛盾。T-001/T-002 复读错误 RM 值，T-003 的 28B 同样少算 16——正是 r1 C-7 警告的"自证闭环"。

**依据**：RFC 5531 §8；§6 自身偏移行（S1 展开到 0x28=40 字节）。

**修复建议**：S1 CALL RM=0x80000028、S1 REPLY=0x80000018、S2 CALL=0x80000030；T-001/T-002 断言与 T-003 的 28B 同步修正；测试 RM 一律在代码中按实际 payload 长度计算，不硬编码。

### C-2. writeverf3 / verf4 仍带 4 字节长度前缀（r1 C-4 残留）

**位置**：§6 S6 reply（行 1120 "verf length=8 (writeverf3 opaque[8])"）、S10 reply（行 1233 "verf length=8"）。

**描述**：RFC 1813 `writeverf3 = opaque[NFS3_WRITEVERFSIZE]`（=8）与 RFC 7531 `verf4 = opaque[NFS4_VERIFIER_SIZE]` 均为**定长 opaque[8]，XDR 编码为 8 字节裸数据，无长度前缀**（本次已从 RFC 1813 原文核实）。文档 S6 在 committed 后仍画 4B 长度 + 8B 数据共 12 字节，reply 总长多 4，Wireshark 解析 WRITE/COMMIT reply 错位。

**修复建议**：S6/S10 删除 "verf length" 行，verf 直接 8 字节；并补一条"verf 无长度前缀"的字节级断言。

### C-3. sattr3 编码整体错误（新发现）：S3/S7 画成固定 52 字节（false 分支也写占位值），RFC 1813 是判别联合

**位置**：§6 S3（行 1001 "[52 bytes sattr3]" + 行 1008-1023 逐字段，set_uid=false 仍写 uid@0030、set_size=false 仍写 size 8B@0040、set_atime=false 仍写 atime@004C）、S7 CALL（行 1141 "[52 bytes sattr3]"）；§2.8（行 347 "mode/uid/gid/size/atime/mtime 各 1 字节 set 位 + 对应值"）；连带 T-029~T-035。

**描述**：RFC 1813 §3.3.2 原文（本次核实）：sattr3 的 mode/uid/gid/size 是 `union set_mode3 switch (bool set_it)`——**false 分支为 void，不写值**；atime/mtime 是 `union set_atime switch (time_how)`——判别值 **0=DONT_CHANGE（不写值）、1=SET_TO_SERVER_TIME（不写值）、2=SET_TO_CLIENT_TIME（写 nfstime3）**。文档 S3 场景（set_mode=true+mode=420，其余 false）实际 wire 为：set_mode=1+mode(4B)+set_uid=0+set_gid=0+set_size=0+set_atime=0+set_mtime=0 = **28 字节**（非 52），sattrguard3 在偏移 0044（非 0058）。§2.8 的"set 位 + 对应值"摘要与 S3/S7 HexDump、偏移行全部错误。

**依据**：RFC 1813 §2.6/§3.3.2（原文核实：time_how 枚举 DONT_CHANGE=0/SET_TO_SERVER_TIME=1/SET_TO_CLIENT_TIME=2）。

**修复建议**：按判别联合重写 S3/S7 的 sattr3 字节（false 分支仅 4 字节判别、SET_TO_CLIENT_TIME 才带 nfstime3），修正 §2.8 摘要；同步修正 T-032（"set=false 时 mode 字段在 wire 上仍存在"错误——false 分支无值）、T-033（DONT_CHANGE=2 错误——应为 0）、T-035（SET_TO_CLIENT_TIME 期望 set=01 错误——应为 2）；并明确定义 user 的 SetAtime/AtimeSecs 字段到 time_how 的映射规则。

---

## HIGH（7 项）

### H-1. S12 OPEN claim 后多画幽灵 component4，LOCK 块偏移整体错位 4 字节（新发现）

**位置**：§6 S12（行 1332 "0060 [component4: file name length + data] file (复用 LOOKUP name 或独立)"）。

**描述**：open_claim4 的 CLAIM_NULL 分支为 void（仅 claim_type 判别值 4 字节，RFC 7531 §5.2），**不含 file 字段**。文档在 claim_type @ 005C 后又画 4 字节 component4（0060-0063），使 LOCK opcode 标在 0064——真实偏移应为 0060，LOCK/LOCKU/CLOSE 全部后续偏移 -4。作者注释"复用 LOOKUP name 或独立"说明对 CLAIM_NULL 语义不确定。

**修复建议**：删除 0060 幽灵行，LOCK opcode 改 @ 0060，LOCKU 改 @ 00A8、CLOSE 改 @ 00D4（或按新基准整体重排并核算）。

### H-2. clientid 三处示例矛盾仍未修复（r1 C-6 残留）

**位置**：§4.3（行 821 公式 `uint64(0x10000)*uint64(i)+1`）、§10.4（行 2014-2018：同一公式但注释 "session 0: 0x10001 / 1: 0x20001 / 2: 0x30001"）、S13 表（行 1389-1391：0x10001/0x10002/0x10003）、T-106/T-177（session 0=0x10000+1、session 1=0x20000+1）。

**描述**：同一 session 1 出现 0x10001（§10.4 注释/公式 i=1）、0x20001（T-106/T-177）、0x10002（S13 表）三个值；且**公式本身与 §10.4 注释自相矛盾**（`0x10000*0+1=0x00001`，注释却写 0x10001）。

**修复建议**：三选一写死（建议 `0x10000*(i+1)+1`：session 0/1/2 = 0x10001/0x20001/0x30001），同步修正公式、注释、S13 表、T-106/T-177。

### H-3. wcc_data 长度与结构错误仍未修复（r1 H-5 残留）

**位置**：§6 S6（行 1117 "[36 bytes file_wcc]"）、S8（行 1178）、S10（行 1232），括号内写 "pre_op_attr 4 字节 + post_op_attr 4+84"。

**描述**：RFC 1813 wcc_data = pre_op_attr（bool 判别 + wcc_attr：size 8+mtime 8+ctime 8=24B）+ post_op_attr（bool + fattr3 84B）。文档"[36 bytes]"与括号内容（4+4+84=92）自相矛盾，且 pre_op_attr 漏了 wcc_attr 24 字节（S6 的 count @ 0044 也随之错位）。

**修复建议**：明确定义（建议简化：pre 不 follow 4B + post follow 88B = 92B），统一标签与结构，重算 S6/S8/S10 偏移，补 WRITE reply wcc_data 字节级断言。

### H-4. S11 GETATTR reply 仍无 result 字节（r1 H-1 残留）

**位置**：§6 S11 REPLY（行 1287 "[bitmap + fattr4 attrs] 由 builder 按 §2.7 规则完整编码"、行 1290 RM=56 仅到 bitmap_len）。

**描述**：GETATTR 成功 reply 必须含 bitmap（3 words 12B）+ size(8B) + mode(4B)，完整 reply 实际 76 字节，但文档以注释占位、RM=56 与完整长度不符；reply bitmap 与 call mask 的关系（回显/支持属性集）仍未定义。实现者无法断言完整 reply。

**修复建议**：展开 S11 REPLY 完整字节（bitmap_len+3 words+size 8B+mode 4B），RM 改 0x8000004C，明确"reply attrs 按 call mask 位序、bitmap 回显 call mask"。

### H-5. REPLY AcceptState 偏移声明仍错（r1 C-3/L-3 残留）

**位置**：§7.1（行 1467 "VerfBody=24、AcceptState=28"）、T-002/T-158（"AcceptState @ 1C-1F"）、§10.2（行 1981 "写入偏移 28-31"）。

**描述**：空 verifier 时 AcceptState 在偏移 24-27，文档自己的 §6 全部 reply HexDump（S1 @ 0x18、S2 @ 0x18、S11 @ 0x18、S15 @ 0x18）均为 24；§7.1 声明 28 与自身 15 个 HexDump 矛盾，测试按此断言会错位 4 字节。

**修复建议**：改为 "AcceptState = 24+verf_len（空 verifier 时 @ 24）"；T-002/T-158 改 @ 18-1B；§10.2 改 24-27。

### H-6. S9 READDIRPLUS reply 缺 dirlist3 内层 eof（新发现）

**位置**：§6 S9 REPLY（行 1204-1205：value_follows=0 后直接 eof=1 @ 0084）。

**描述**：readdir3resok/READDIRPLUS3resok = post_op_attr + cookieverf3 + **dirlist3{ entries<>, eof }** + eof（RFC 1813 §3.3.16/17，dirlist3 内部含 eof，resok 外层还有一个 eof）。wire 上应为 entries_len + **eof(dirlist3)** + **eof(resok)** 两个布尔；文档只画一个 eof @ 0084，reply 缺 4 字节，且 "value_follows" 是 NFSv2 术语（v3 应为 entries 数组长度）。eof 应 @ 0088。

**修复建议**：S9 reply 补第二个 eof（0084 内层 eof、0088 外层 eof），字段名改 "entries length"。

### H-7. S12 与 §4.1 规则 3 的 OPEN_CONFIRM 自动补全冲突（r1 H-2 残留）

**位置**：§4.1 规则 3（新 open-owner 首次 OPEN 自动追加 OPEN_CONFIRM）vs §6 S12（行 1302-1366：argarray length=6、无 OPEN_CONFIRM，注释自认"本例 OPEN_CONFIRM 自动补全未展示"）。

**描述**：S12 的 OPEN（owner {clientid:12345, owner:"AQ=="} 首次出现）按规则 3 应自动补 OPEN_CONFIRM（argarray=7）；且 OPEN_CONFIRM=2 后 LOCK 的 open_to_lock_owner.open_seqid 应为 2 而非文档的 1。规则与示例直接冲突，实现者照 S12 写测试必与自动补全逻辑打架。

**修复建议**：二选一——S12 显式纳入 OPEN_CONFIRM（argarray=7、open_seqid=2、CLOSE seqid=3），或声明 S12 属"user 已显式配置 OPEN_CONFIRM 之外的特殊透传场景"并说明为何跳过补全。

---

## MEDIUM（10 项）

### M-1. S9 cookieverf 字节与 Config 矛盾（新发现）
**位置**：S9（行 1192/1203 画 cookieverf3 = AA×8）vs Config `cookie_verf="AAAAAAAAAAA="`（= 8 字节全 0，S9 自己行 1211 也确认）。
**描述**：call 与 reply 的 cookieverf 都画成 0xAA×8，与 Config 值（8×00）及注释矛盾；reply cookieverf 应回显 call。
**修复**：HexDump 改 8×00。

### M-2. §2.5 行 228 "0/1/2：保留（INVALID_OP, ILLEGAL_OP, ILLEGAL_OP）" 命名错误（r1 M-1 残留）
**描述**：RFC 7531 §6.1 中 0-2 是未赋值空间，无 INVALID_OP/ILLEGAL_OP 名称；非法 op 由服务端以 op_status=NFS4ERR_OP_ILLEGAL（10044）表达，不是"自动转为 ILLEGAL4"。行 185 的 "0 | ILLEGAL4" 同错。
**修复**：改为"未分配（0-2 无名称，Validate 拒绝）"。

### M-3. S13 client.id 1-based 与 0-based 矛盾（r1 M-7 残留）
**位置**：S13 表 "trafficgen-client-1/2/3"（行 1389-1391）vs §4.3/T-179 "trafficgen-client-0/1"（0-based）。
**修复**：统一 0-based。

### M-4. T-148/T-066 的 PROC_UNAVAIL 期望与输入不匹配（新发现）
**位置**：T-148（期望 "reply AcceptState=3 (PROC_UNAVAIL)"）与 T-066（"真实服务端返回 PROC_UNAVAIL"），输入均无 `rpc_accept_state=3`。
**描述**：§9.1 定义 RPC 层错误由指针字段控制、nil=成功路径；合成流量不模拟真实服务端，T-148 输入缺 rpc_accept_state 却期望 AcceptState=3，测试自相矛盾。
**修复**：T-148 输入补 `rpc_accept_state:3`，或期望改"reply 正常 MSG_ACCEPTED+SUCCESS（透传）"。

### M-5. §2.2 READ 行关键返回顺序错误（新发现）
**位置**：§2.2 行 131 "READ ... 关键返回：eof, data, post_op_attr"。
**描述**：RFC 1813 read3resok = file_attributes → count → eof → data（data 在最后）；文档 §6 S5 画的是正确顺序（count@0078、eof@007C、data@0080），§2.2 表与自己的 HexDump 矛盾。
**修复**：表改为 "post_op_attr, count, eof, data"。

### M-6. §9.1 MSG_ACCEPTED 布局缺 PROG_MISMATCH 的 low/high 附带字段（新发现）
**位置**：§9.1 行 1794-1802（payload 布局到 AcceptState 为止，"[无 NFS body]"）vs 行 1807 表（"附带 low/high version 范围"）vs T-159（"含 low/high version"）。
**修复**：布局补 "AcceptState=2 时 + low(4B) + high(4B)"。

### M-7. bitmap 尾部 0 word 规范化未定义（r1 M-3 残留）
**位置**：T-073/T-140 传 attr_mask=[0x10,0x02,0] 断言 bitmap len=3，但 user 尾部 0 word 是否截断为 2-word 未定义。
**修复**：明确"保留原样"或"去尾部 0 word"，与测试断言一致。

### M-8. WRITE count≠len(data) 未校验（r1 M-5 残留）
**位置**：§3.2 Count、§7.2 T-047。
**描述**：RFC 1813 WRITE3args/7531 WRITE4args 的 count 必须等于 data 长度，文档未定义不一致时行为。
**修复**：Validate 加 "count 必须等于 len(data)" 规则 + 负向测试。

### M-9. ResultStatus≠0 多 op 行为表行混乱（r1 M-4 残留）
**位置**：§2.7 表第 4 行 "ResultStatus≠0（全局）= ResultStatus | 仅含第一个失败 op 之前的部分（含失败 op）| 失败 op = ResultStatus"；§9.2 的 v4 表只有 3 行、无 ResultStatus 行。
**描述**：ResultStatus≠0 时并无"失败 op"（所有 op 正常），oparray 应含全部 op 且每个 op_status=ResultStatus；表行语义矛盾且两处表不一致。
**修复**：统一为"顶层 status=ResultStatus、resarray 完整、每个 op_status=ResultStatus（不截断）"，§9.2 同步。

### M-10. OpenReplyStateid 引用接线未定义（r1 H-3 残留）
**位置**：§3.2 行 517、§3.5 行 691（"通过此字段建立引用"）、§4.1 规则 4（"Plan 只做透传"）。
**描述**：字段声称可建引用但 Plan 不接线，OPEN→WRITE 用同 stateid 的场景（T-090）无任何可执行机制。
**修复**：二选一写死（删除字段/明确由 user 显式填值，或实现 Plan 合成+填入），并补端到端测试。

---

## LOW（5 项）

### L-1. T-006 "CredLen=18 (24B)" 进制混写、T-193 "CredLen=18+" 含糊（r1 C-7 残留）
**修复**：统一写 "0x18=24"；T-193 给确定值。

### L-2. §5.6 reply 时间戳未定义（r1 L-5 残留）
**修复**：补一句 "reply 时间戳 = 对应 call 时间戳"。

### L-3. MOUNT proc=0 显式配置时头部补全行为仍含糊（r1 M-6 残留）
**位置**：§4.2 规则 1（仅排除 Procedure=1）与规则 5（NULL 不参与补全）对 user 显式配 proc=0 时是否还插入 MOUNT proc=1 未说清。
**修复**：明确 "显式 proc=0 时不重复插入 proc=1"。

### L-4. §2.5 表格缺 opcode 40 行（新发现）
**描述**：文字说 "40-62 为 NFSv4.1+"，表格从 41 起（40=WANT_DELEGATION 缺失）。
**修复**：表格补 40 行或文字改 "41-62"。

### L-5. T-155 未断言失败 op 的顶层 status（r1 M-4 相关残留）
**描述**：截断规则测试只断言 resarray len=2，未断言顶层 status=10025。
**修复**：补断言。

---

## 测试用例质量评估（CLAUDE.md §Testing Policy）

| 规则 | 评估 | 说明 |
|------|------|------|
| 1. Spec-driven | ⚠️ | T-001~T-200 与 §2-§6 一一对应，但 T-001/T-002/T-003 复读错误 RM 值（C-1）、T-032/T-033/T-035 复读错误 sattr3 语义（C-3），自证闭环未完全打破 |
| 2. 失败路径 | ⚠️ | V1-V38 负向用例齐全；缺 WRITE count≠len(data)（M-8）、MOUNT NULL（L-3）；T-148 输入输出不匹配（M-4） |
| 3. 正确 scope | ⚠️ | opcode 3-39 全部有对应用例且数值经本次复核正确；sattr3 编码是最大 scope 缺口（S3 与 T-032~T-035 互相矛盾） |
| 4. 集成测试 | ✅ | T-191~T-200 覆盖完整会话/分段/PCAP/失败传播 |
| 5. 可观察输出 | ⚠️ | T-006/T-193 进制含糊；S12/S9 HexDump 偏移错位使部分断言无可靠基准 |
| 6. 并发正确性 | ✅ | 多会话独立性 T-171~T-180 覆盖充分（除 clientid 期望值矛盾，见 H-2/M-3） |
| 7. Failing-test-first | N/A | 设计文档阶段 |
| 8. 测试质量对抗评审 | ⚠️ | 本次复审即此环节；发现 sattr3/双 eof/幽灵字段三类测试与 HexDump 联动错误 |

---

## 修复优先级建议

1. **立即修复（阻断实现）**：C-1（RM 残留）、C-2（verf 长度前缀）、C-3（sattr3 编码——S3/S7 HexDump + §2.8 + T-029~T-035 需整体重写）。
2. **实现前修复**：H-1（S12 幽灵字段）、H-2（clientid）、H-3（wcc_data）、H-4（GETATTR result）、H-5（AcceptState 偏移）、H-6（双 eof）、H-7（OPEN_CONFIRM 冲突）。
3. **随实现完善**：M-1~M-10、L-1~L-5。

---

## 最终结论

**否——本文档不能直接进入实现阶段。**

正面：v2.0.1 的核心修复（opcode 38/39、COMPOUND status→tag→resarray、READDIRPLUS、sattrguard3、cookieverf3、fattr3 84 字节）经 RFC 原文核实全部正确落地，S11/S15 的 RM 也修对了。

阻断项：**7 项 r1 CRITICAL 中仍有 4 项未修复**（RM 少算、verf 长度前缀、AcceptState 偏移、clientid 矛盾），且**新发现 sattr3 编码全文档级错误**（S3/S7 52 字节固定结构 vs RFC 判别联合 28 字节，波及 §2.8 与 5 条测试断言）。sattr3 是每次 SETATTR/CREATE 都会触发的核心编码，照当前文档实现生成的 SETATTR/CREATE 报文会被 Wireshark 标为 malformed。修复后需重写 S3/S7 字节与 T-029~T-035，重算 S1/S2 RM，删除 S6/S10 verf 长度前缀，统一 clientid 三处示例，方可进入实现。
