# #127 icmp（ICMP）测试用例契约

> 版本：v1.0.0（批次二文档车道，as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/127-icmp-design.md` v1.0.0
> 旧基线：**无独立用例稿**——文档基线 = ①内部契约 T-ICMP-1…8（`docs/TEST_CASES.md`，D-ICMP-1 P3 交付）；②结果产物 `trafficgen/docs/protocol-pcap-test/icmp.md`（tracked，**末次提交 `1b4e440` 2026-09-22 晚于判死提交 `0417be5` → 非过期产物**，但 pcap 目录缺失，设计 §14 G-ICMP-8）。本 #127 承 T-ICMP-1…8 的 8 ID / 锚词 / 断言思路，冲突处按代码与探针实测改正（设计 §0）。
> 机器契约：`trafficgen/test/protocol_pcap/cases/icmp.json`（**8/8 ID 与本版 §2 一致，顺序一致**，已机读实测）
> 白话一句：**八条检查：四条看正常收发（缺省 ping、头字节整钉、显式 id/seq/data、多轮 pattern），四条看胡来能不能被拦下（非 Echo 型、非零 code、顶层旧键、静态复制）；每条只查一件事，四个负例的 expect 都是干净的两键。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **8 个唯一语义 ID：4 正 + 4 负**（负例 N-1…N-4）。派生规则：设计 §3 每个字段条款、§5 每个自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：8/8 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×7（唯一键）+ `{layers,icmp}` ×1（t7 presence 负例特形，判死语义必含）**；链形 `[ip,icmp]` ×8（**无例外**）；4 正例 `expect` 含 `packet_count`（2/2/2/4）+ `fields`（4/1/2/3 条）+ `frames`（0/4/3/4 条）；**4 负例 `expect` 键集合 = `{expect_error, error_contains}` 严格两键**（无 `notes`，实测——比 opcua/rtsp 范式干净，**无收窄欠账**）；case 级 `strategy_fc` ×1（t8，非 spec_json 键）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`icmp.type/ident/seq`、`ip.proto/src`、offset 34/42 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**raw-IP 无连接**：`has_handshake`/`terminates` 对 icmp 不适用（存量 8/8 未使用，机读实测）。

**TSHARK 基线（本机 tshark 3.6.14 `-G fields` 实测）**：可用字段通道——① `icmp.type`（BASE_DEC，十进制串 "8"/"0"，t1–t4 实测命中）；② `icmp.code`；③ `icmp.ident` / `icmp.seq`（BASE_DEC_HEX，**fields 输出为十进制串**，t3 "7"/"9"、t4 "1"/"2" 实测命中）；④ `icmp.ident_le` / `icmp.seq_le`（小端对照面，今日零使用）；⑤ `icmp.checksum`（BASE_HEX，`0x192d` 形）与 `icmp.checksum.status`（Good/Bad——**今日零使用**，A′ 收编 G-ICMP-12）；⑥ `ip.proto`（"1"，t1 实测）/ `ip.src` / `ip.dst` / `ip.ttl`；⑦ frames 原始 hex（offset 34 头 / 42 data）。**禁钉令**：`ip.id` 随机起点（设计 §3.6）不得断言；`frame.time` 全帧同值（设计 §12.3）不得断时间差。

**断言基线**：今日 8 例用 `packet_count`（4 正例）+ `fields`（10 条）+ `frames`（11 条，逐条对反码复算 OK，设计 §3.2）；**负例零 frames 断言**（0 帧语义）。11 条 frames 中 6 条含校验和字节（@34 头），**全部通过 RFC 1071 独立复算对拍**（设计 §3.2 表，本车道脚本实测 6/6——t3 p2 的 data 断言缺失不影响复算，data="abc" 由 spec 推出）。

**包数约定（设计 §9 公式）**：单 ping type=8 = **2**；type=0 显式单发 = **1**（今日零例）；pattern = `2×(#type8步) + 1×(#type0步)`。负例无 `packet_count`（0 帧语义）。

**保活/重试/RST 口径**：全部不适用——ICMP 无连接无重传无传输层终结语义（设计 §10.2 T3 整列 N/A，D-ICMP-1 修轮 L2 天花板声明承接）；正例恒 2 帧或 2N 帧序列，无 FIN/RST 概念。

**今日实跑证据（本车道，2026-09-29）**：
1. **coverage_gate 反查 18/18 全绿**（`python3 tools/coverage_gate.py icmp` 复跑实测）。
2. **离线链执行器 6/8**：临时空导入 + chainSuiteProtos 临时加 icmp（**两处临时改动已回滚，零 `.go`/cases 改动**）跑 `TestLayerChainSuite`，t1–t6 PASS、t7/t8 FAIL（`negative case: expected generation error, got success`，layer_chain_suite_test.go:331）——**这是设计 G-ICMP-4 的直接实证**：t7/t8 的真实拦截面在 schema create-time（`ValidateStrategy` → `CheckProtoFlat`/`checkLayerChainStaticCopy`，semantic.go:130/142），离线执行器直调 `Engine.SubmitTask` 绕过该门。**icmp 的权威执行器 = MCP suite**（D-ICMP-1 P5 验收 8/8 ×2 于 2026-09-22；本车道未跑 MCP，不以任何形式声称"今日 8/8"）。
3. **探针 9 项**（临时测试文件已删，设计 §0 #8）：步 code 放行、v6 族混产帧、tcp/udp 夹层 0 包、type=0 单发 n=1、混型 pattern n=3、空 pattern n=2、V9 三锚、未知键锚、动态对象锚。

## 2. 原子用例索引（8 ID = 4 正 + 4 负，顺序为权威）

| # | ID | 类型 | 场景 | 依据链 | packet_count | 断言概要 |
|---:|---|---|---|---|---:|---|
| 1 | `icmp_t1_smoke` | 正 | 缺省 ping 配对 | RFC 792 Echo 节 + 设计 §3.1/§5 | 2 | `ip.proto=1`；type p1=8/p2=0；p2 `ip.src=20.0.0.1`（角色互换） |
| 2 | `icmp_t2_header_bytes` | 正 | 8B 头整钉 | RFC 792 + 设计 §3.1/§3.2 | 2 | frames@34 八字节 ×2（**校验和 0x192D/0x212D**）+ frames@42 data="ping" |
| 3 | `icmp_t3_explicit` | 正 | 显式 id/seq/data 覆盖 | RFC 792 + 设计 §3.3 | 2 | `icmp.ident=7`/`icmp.seq=9`；frames@34（**奇长补零校验和 0x338D/0x3B8D**）+ data "abc" |
| 4 | `icmp_t4_pattern` | 正 | Pattern 多轮 | RFC 792 会话语义 + 设计 §3.5 | 4 | 帧序 req1/rep1/req2/rep2；seq 1/2；frames@34/@42 逐字节（0x9698/0x9D96） |
| 5 | `icmp_t5_neg_type` | 负 | type=3 非 Echo 拒 | RFC 792 + 设计 §7 N-1 | — | `error_contains: icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3` |
| 6 | `icmp_t6_neg_code` | 负 | code=1 拒 | RFC 792 + 设计 §7 N-2 | — | `error_contains: icmp code must be 0 for Echo, got 1` |
| 7 | `icmp_t7_neg_presence` | 负 | 层链+顶层 icmp 并存判死 | 设计 §7 N-3/§12-P2 | — | `error_contains: rejects a top-level icmp` |
| 8 | `icmp_t8_neg_static_copy` | 负 | ip 层静态标量 + flows=2 | 设计 §7 N-4/§12.12 | — | `error_contains: static four-tuple` |

T-编号对照：T-ICMP-T1…T8 ≡ #1…#8（顺序一致，无虚例——旧稿无 T4/T8 合并类问题）。**序号以 cases JSON 顺序为权威**（机读实测一致）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每正例均含 `packet_count` + 至少一条 `fields` 或 `frames` 断言落在 ICMP 头（offset 34）；帧位由 §1 公式与反码复算双向确认。

### 3.1 `icmp_t1_smoke`（2）

`spec_json`：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"icmp":{}}]}`（**空 icmp 层 = 全缺省合法 ping**）。

- `packet_count=2`（单 ping type=8 → req+auto-reply）。
- fields：p1 `ip.proto=1`（FieldContract 承载面 + `L3Base(…,1,…)` 双证）；p1 `icmp.type=8`；p2 `icmp.type=0`；**p2 `ip.src=20.0.0.1`**（reply L3 换向的直接证据——legacy 已换向、Generator 防 double-swap，设计 §5.3）。
- 缺省值证据：type=8/code=0/seq=1/data="ping" 全部来自 translate 缺省镜像（决策 D1）；id=0 → 头内 id=seq=1（回退面，t2 frames 整钉承载）。

### 3.2 `icmp_t2_header_bytes`（2）

同 #1 spec。**头字节整钉（本协议最重断言）**：

- frames：p1 offset 34 `08 00 19 2d 00 01 00 01`（type/code/cs/id/seq 八字节）；p1 offset 42 `70 69 6e 67`（data "ping"）；p2 offset 34 `00 00 21 2d 00 01 00 01`；p2 offset 42 同 data。
- **校验和对拍（独立复算式，本车道 6/6 实测）**：p1 置零累加 `0x0800+0x0001+0x0001+0x7069+0x6e67 = 0xE6D2` → 取反 **0x192D** ✓；p2 去掉 Type 字 0x0800 → `0xDED2` → 取反 **0x212D** ✓（= 0x192D+0x0800，req/reply 只差 Type 字的算术证据）。
- **notes 陈旧值声明（G-ICMP-11，P4 必改）**：存量 notes[0] "reply(0000) → 0x192f" 与本用例 frames 钉值 `21 2d` **矛盾**；notes[1] 已自纠（"首算 192f 误 → pcap 实测 212d"）。正确值 = **0x212D**（本车道反码复算 + frames 双证）。
- id=seq=1 双写证据：头 @38-39 与 @40-41 同值——id=0 回退规则（设计 §3.3②）的整钉承载。

### 3.3 `icmp_t3_explicit`（2）

`icmp` 层 = `{"identifier":7,"sequence":9,"data":"abc"}`。

- fields：p1 `icmp.ident=7`、`icmp.seq=9`（显式值不走回退面——与 #1 的回退面对照构成该规则的两侧证据）。
- frames：p1 offset 34 `08 00 33 8d 00 07 00 09`；p1 offset 42 `61 62 63`；p2 offset 34 `00 00 3b 8d 00 07 00 09`。
- **奇长校验和路径（本用例独占）**：data 3B → 报文 11B 奇数 → 尾字节 `0x63` 左移补零（`6300`）参与累加：`0x0800+0x0007+0x0009+0x6162+0x6300 = 0xCC72` → 取反 **0x338D** ✓；reply **0x3B8D** ✓（RFC 792 "padded with one octet of zeros" 的可执行证据；`calculateChecksum` 奇长分支 icmp.go:330-32 的线面证明）。
- 存量缺口（如实）：**p2 无 frames@42 断言**（reply data 未钉——A′ 可补 `61 62 63`）。

### 3.4 `icmp_t4_pattern`（4）

`icmp` 层 = `{"identifier":5,"pattern":[{"type":8,"sequence":1,"data":"aa"},{"type":8,"sequence":2,"data":"bb"}]}`。

- `packet_count=4`（公式 2×2 echo 步）。
- fields：p1 `icmp.seq=1`；p3 `icmp.seq=2`（**帧位证据：p1=req1/p2=rep1/p3=req2/p4=rep2**——t4 notes 自述"首标 req2 误 → pcap 实测"，与设计 §5 事件序一致）；p4 `icmp.type=0`。
- frames：p1 offset 34 `08 00 96 98 00 05 00 01` + offset 42 `61 61`（"aa" 原始字节，**非 base64** 的直接证据）；p4 offset 34 `00 00 9d 96 00 05 00 02` + offset 42 `62 62`。
- 校验和对拍：p1 `0x0800+0x0005+0x0001+0x6161 = 0x6967` → **0x9698** ✓；p4 `0x0005+0x0002+0x6262 = 0x6269` → **0x9D96** ✓。
- identifier=5 显式共享证据：头 @38-39 两帧均 `00 05`（顶层 Identifier 共享，设计 §3.3③）。
- **未断言面（A′ 可收编）**：p2/p3 无 frames（rep1 `9e98`/req2 `9596` 可复算补钉）；identifier 逐帧同值断言走 p1 frames 已承载。

**正例总则**：四正例 = 缺省面（#1）+ 整钉面（#2）+ 显式面（#3）+ 多轮面（#4），彼此独立不可合并；每例 packet_count 精确钉帧数漂移。

## 4. 负例契约

负例必须在拦截面失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 假成功。锚词与设计 §7 表一一对应、同序。**真实拦截面（每负例标产地，本车道代码+实测双证）**：

| ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 拦截面 | 引擎直调可达 |
|---|---|---|---|---|---|
| `icmp_t5_neg_type` | `icmp.type=3` | `icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3` | `layer_gen.go:64-66` | 层 validator（translate 后判） | **是**（离线实测 PASS） |
| `icmp_t6_neg_code` | `icmp.code=1` | `icmp code must be 0 for Echo, got 1` | `layer_gen.go:67-69` | 层 validator | **是**（离线实测 PASS） |
| `icmp_t7_neg_presence` | 层链 + 顶层 `icmp:{}` | `rejects a top-level icmp` | `strategy_convert.go:9100/9107-9111`（rawWrapChains） | **create-time**（schema.ValidateStrategy，semantic.go:130；batch 同门 convert.go:166） | **否**（离线实测失守，G-ICMP-4） |
| `icmp_t8_neg_static_copy` | ip 层显式标量 + `strategy_fc flows=2` | `static four-tuple` | `semantic.go:285`（checkLayerChainStaticCopy） | **create-time**（semantic.go:142） | **否**（同上） |

**锚词口径**：`error_contains` 是子串判定；四例均命中代码文案（N-3/N-4 为前缀子串）。

**负例原子性**：每例单一故障注入。t7 的故障就是"顶层键存在"本身（presence 语义，空 map 也死）；t8 是"静态标量 + flows>1"组合故障（单一注入点 = strategy_fc）。

**expect 严格两键确认（本协议达标项）**：4/4 负例 `expect` = `{expect_error, error_contains}`，**无 notes 键**（机读实测）——与 opcua/rtsp 的"负例含 notes 待收窄"欠账不同，**本协议无此项 P4 动作**。

**引擎直调失守声明（G-ICMP-4，重要）**：t7/t8 在离线链执行器（直调 `Engine.SubmitTask`）下**假绿风险为真**——本车道临时空导入实测 6/8，两例报 `expected generation error, got success`。生产路径不受影响（strategy create 必过 schema 门，且 MapToFlowSpec 引擎侧无 icmp 旧键迁移需求——存量 0 行）。处置：**不建离线负例**、icmp 不补入 chainSuiteProtos、等框架级引擎侧门（设计 §14）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- 步 type 锚 `icmp pattern step %d type must be 8 or 0, got %d`（layer_gen.go:71-73；红④单测面在案，套件 0 例）；
- legacy IP 锚 `invalid source IP: %s` / `invalid destination IP: %s`（icmp.go:37-44；HasLayerDynIP 豁免面，红⑤单测）；
- V9 界锚（本车道探针实测锚词）：`layers: layer "icmp" field "type" = 256 invalid: out of range [0,255]`；`field "sequence" = 65536 invalid: out of range [0,65535]`；`field "type" = eight invalid: not a numeric value in [0,255]`；
- 未知键锚：`layers: layer "icmp": unknown field "bogus"`（探针实测）；
- 动态对象锚：`layers[1](icmp).data does not support dynamic`（探针实测；allowlist 无 icmp 行）；
- 步 code（**缺陷候选，需先修 G-ICMP-1**，失败用例先行——今日建例会假绿）；
- v6 族混（**缺陷候选，需先修 G-ICMP-2**，同上）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 792（本车道拉取原文：Echo 节 checksum 措辞 + Type/Code 全表）+ RFC 1071（算法）+ RFC 4443 §2.3（ICMPv6 对照）+ D-ICMP-1 as-built（设计 §11）+ tshark 3.6.14 字段表与探针实测 → 8 ID（本契约 §2）。

**8 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§5；#2←§3.1/§3.2；#3←§3.3；#4←§3.5；#5←§7 N-1；#6←§7 N-2；#7←§7 N-3；#8←§7 N-4。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 792/1071 原文（本车道拉取核对）+ 内部契约 D-ICMP-1（七裁定 as-built 复核）+ 仓库落码反推 + 本车道探针实测 9 项**，非纯规范反推（RFC 1122/1812 扩展 Code 未逐条核对 → G-ICMP-13）。
- **对账两行**：**要求逻辑点总数 = 50**（八项 8 行 + 矩阵① 8 格 + 变体② 27 行 + 商业③ 7 行）；**用例覆盖数 = 25**（八项 2 + ① 6 + ② 15 + ③ 2）；**不适用 = 9**（八项 2 + ① 1 + ② 2 + ③ 4）；**开放立项 = 16**（八项 4 + ① 1 + ② 10 + ③ 1）。25 + 9 + 16 = 50 ✓
  **粒度声明**：行/格粒度每点 1 计；G-ICMP-1…13 不折进 50。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 2 + 开放 4 + 不适用 2，缺口列反推）/§10.2（8 格 = 覆 6 + 立项 1 + 不适用 1，T3 整列 N/A 不折格）/§10.3（27 行 = 覆 15 + 立项 10 + 不适用 2）/§10.4（7 行 = 覆 2 + 立项 1 + 不适用 4）。
- **门3 抽查候选**：最复杂正例 = **#4 `icmp_t4_pattern`**（4 帧：交织维度 = 步(2)×方向(2)×type(2)×data(2)，帧位 req1/rep1/req2/rep2 曾首钉错一次——notes 自述实录）；**建议门3 抽 #4 + #8**（#8 补 create-time 框架门面）。

### 5.3 逐例断言强度评估（对抗审查用）

| # | 强度 | 说明 |
|---|---|---|
| 1 | 中 | fields 4 条覆盖 proto/type 换向/角色互换；缺 frames（头字节由 #2 整钉承接——语义重复非缺失） |
| 2 | **强** | 8B 头 ×2 帧 + data 全钉，6/6 校验和独立复算可验 |
| 3 | 强 | 显式 id/seq fields + 奇长校验和路径独占钉；p2 data 未钉（A′） |
| 4 | 强 | 帧位 fields 3 条 + 2 帧 hex；p2/p3 hex 未钉（可复算补钉） |
| 5–6 | 强 | 锚词逐字 + 拦截面产地 + 离线实测 PASS |
| 7–8 | 强 | 锚词逐字 + create-time 门面声明 + 引擎直调失守如实登记（G-ICMP-4） |

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 无连接协议的"多轮" = pattern 步序贯（seq 递增即会话推进） | 已覆 #4 |
| ② | 非正常结束 | **显式 N/A**——无连接 2 帧面，无 FIN/RST 概念（D-ICMP-1 修轮 L2 天花板声明，9.50/9.53 承接） | 不适用（如实声明，非遗漏） |
| ③ | 长保活 | **显式 N/A**——协议无重传/保活语义（设计 §10.1 第 6 行） | 不适用（如实声明） |

无空项：① 有 #4；②③ 为协议天花板豁免（无连接族同型 goose/sv/igmp 先例，非偷懒豁免）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 缺陷修复面 | G-ICMP-1 步 code 分支 + G-ICMP-2 v4 族守卫 + G-ICMP-3 夹层守卫（**失败用例先行**） | 设计 §14 |
| 合法路径面 | type=0 单发 / 混型 pattern / 空 pattern / data 空串 | G-ICMP-9（§3 候选） |
| 拒绝分支面 | 步 type 锚 / legacy IP 锚 / V9 三锚 / 未知键 / 动态对象锚 | G-ICMP-10（§4 已列） |
| 多流面 | ip.src range + flows=3 正例 | G-ICMP-7 |
| 断言面 | `icmp.checksum.status`/`ip.ttl`/p2-p3 hex 补钉/data 边界（上界需先修） | G-ICMP-12 |
| notes 面 | t2 notes[0] 陈旧值 0x192f 改写 | G-ICMP-11（**P4 必做**） |

**B′（框架面/明确不解决）**：引擎直调双门缝（G-ICMP-4，等框架级引擎侧门，不建离线负例）/ 非 Echo 型编排（G-ICMP-6，明确不解决）/ file_source 层链面（G-ICMP-5，明确不解决）/ 结果产物 pcap 留档（G-ICMP-8，P5 重跑再生）/ 第三源抓包对照（G-ICMP-13，待确认）。

### 6.3 3.14 豁免边界审计

**长连接载体**：无（raw-IP 无连接）→ `sessions[]` **豁免成立**（多会话层显式不适用，设计 §12.3）；多流并发由策略级 `flow_control` 承载（存量仅 #8 拒绝面）；**单包多载荷** = **不适用**（ICMP 每 Echo 一段 data，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先修 G-ICMP-1/2/3（失败用例先行：步 code 负例、v6 族负例、夹层负例各一）；②改写 t2 notes（G-ICMP-11）；③补 A′ 合法路径 4 例 + 拒绝分支例；④全量复跑 MCP suite 重生成结果产物 + pcap 留档（G-ICMP-8）。
2. **实测顺序**：先 #1（2 帧基线 + ip.proto=1），再 #2（头字节整钉 + 校验和对拍），再 #3（显式值 + 奇长校验和），再 #4（pattern 帧位），负例随时可跑（t5/t6 引擎面、t7/t8 create 面）。
3. **离线执行器纪律**：icmp 保持**不**补入 chainSuiteProtos/空导入（t7/t8 在该执行器必失守，G-ICMP-4）；如需引擎面回归，只跑 t1–t6 并注明 t7/t8 门面归属。
4. 任何扩展 Code（type 3 code 6–15 等）的具体引用须先拉 RFC 1122 §3.2.2 / RFC 1812 §4.3.3.1 原文（G-ICMP-13 纪律）。

## 8. 存量审计（8 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/icmp.json` **8 例**：4 正带 `packet_count`（2/2/2/4）+ `fields` 10 条 + `frames` 11 条（**6 条含校验和字节，独立反码复算 6/6 全 OK**）；4 负 `expect` 严格两键 `{expect_error, error_contains}`（**无 notes，零收窄欠账**）；spec_json 顶层 7/8 仅 `{layers}`（t7 负例特形）；链形 `[ip,icmp]` ×8；层内 `icmp` 6 键与 registry/生成表逐键一致（机读实测）。**t1–t6 离线实测 PASS；t7/t8 见 §1/§4 门面声明**。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **t2 notes[0] 陈旧值**（G-ICMP-11）："reply(0000) → 0x192f" 与帧钉 0x212D 矛盾（notes[1] 已自纠但首行残留）——本车道反码复算证实 0x212D 正确。
2. **t7/t8 引擎直调失守**（G-ICMP-4）：离线执行器实测两例 `expected generation error, got success`——create-time 门在 MCP 路径成立，离线路径不模拟。
3. **validator 分支缺失 2 处**（G-ICMP-1/2）：步 code 不查（探针放行 code=1 上包）；v6 族混不拒（探针产无效帧）。
4. **夹层链静默 0 包**（G-ICMP-3）：`[ip,{tcp,udp},icmp]` 探针双实证 n=0 无错。
5. **三条合法路径零套件例**（G-ICMP-9）：type=0 单发/混型 pattern/空 pattern（探针实证合法 n=1/3/2）。
6. **结果产物 pcap 缺失**（G-ICMP-8）：`icmp/` 目录不存在，4 条正例链接悬空；非过期产物（末次提交晚于 0417be5）。
7. **`icmp.checksum.status`/`ip.ttl` 断言零使用**（G-ICMP-12）：tshark 可验面未收编。
8. **p2 data / p2-p3 hex 未钉**（§5.3）：非缺失（fields/包数已承载），A′ 补强项。

### 8.3 逐条去向表（8 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `icmp_t1_smoke` | T1 | **保留** | 可补 p2 `icmp.type=0` 之外的 frames 面（A′） |
| `icmp_t2_header_bytes` | T2 | **改写** | **改写 notes[0]**（删 0x192f 陈旧值，G-ICMP-11）；断言本身全对 |
| `icmp_t3_explicit` | T3 | **保留** | 可补 p2 frames@42 `61 62 63`（A′） |
| `icmp_t4_pattern` | T4 | **保留** | 可补 p2/p3 frames（9e98/9596 可复算，A′） |
| `icmp_t5_neg_type` | T5 | **保留** | 无动作（锚词逐字对 layer_gen.go:64-66） |
| `icmp_t6_neg_code` | T6 | **保留** | 无动作 |
| `icmp_t7_neg_presence` | T7 | **保留** | 无动作（门面已声明，G-ICMP-4 归框架面） |
| `icmp_t8_neg_static_copy` | T8 | **保留** | 无动作（同上） |

无"作废不注原因"：0 作废，0 等价覆盖（8 例全部保留/改写 + A′ 新增）。**非负例 spec_json 顶层键 = 0 今日已成立**（7/7 机读实测）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

既有 `check_icmp` 18 项今日 18/18 绿（复跑实测），下表为**增量建议**（每条可从本契约与 cases JSON 直接机读，不需新造事实；红项如实标红）：

| # | 建议断言 | 依据 | 今日红/绿 |
|---:|---|---|---|
| 1 | 4 正例 `packet_count` ∈ {2,2,2,4} 且 == 公式 `2×(#type8步)+1×(#type0步)`（单 ping 视作 1 步 type8） | 设计 §9 公式 | **绿** |
| 2 | 8/8 例链形 == `[ip,icmp]` 且链内无 tcp/udp | 设计 §2/§8 | **绿** |
| 3 | 非负例 spec_json 顶层键 == `{layers}`（t7 负例豁免） | 设计 §12.1 | **绿** |
| 4 | 4 负例 `expect` 键 == `{expect_error, error_contains}` 严格两键 | 本契约 §1/§4 | **绿** |
| 5 | t2/t3/t4 每条 frames@34 的 8B 头：将 cs 两字节置零后 RFC 1071 复算 == 钉值（6/6 可机读复算） | 本契约 §3；设计 §3.2 | **绿** |
| 6 | t1 fields 含 `p2 ip.src == 20.0.0.1`（角色互换断言在场） | 本契约 §3.1 | **绿** |
| 7 | 8 例 `expect` 无 `has_handshake`/`terminates`/direction 类键（raw-IP 无连接 + 防双换 Direction 无判别力，断则假红） | 设计 §5.3/§12.3 | **绿** |
| 8 | 8 例无任何 `ip.id` 断言（随机起点禁钉令） | 设计 §3.6/§12.12 | **绿** |
| 9 | icmp 层内不出现 registry 6 键之外的字段（V9 unknown field 会拒，用例层自检） | 本契约 §4；探针实测锚 | **绿** |
| 10 | G-ICMP-1 修复后：pattern 步 `code` 键（若出现）必须 == 0，且新增步 code 负例存在 | 设计 §14/G-ICMP-1 | **红**（门今日不存在且无例，P4 后再登记） |

**红项汇总**：**1 条红**（#10，依赖 G-ICMP-1 修复，P4 后转绿）。其余 9 条今日即绿（静态机读可判）。

**另注意**：`trafficgen/docs/protocol-pcap-test/icmp.md` 的 "pass 8" 是 **2026-09-22 验收实录**（末次提交晚于判死提交 `0417be5`，**非过期产物**），但其 pcap 目录缺失、且**本车道未跑 MCP 套件**——不得据此声称"今日 8/8"；权威复跑 = MCP suite（G-ICMP-8 处置）。

## 10. 修订记录

- v1.0.0（2026-09-29，批次二文档车道）：**icmp 首份独立用例契约**（承 T-ICMP-1…8 的 8 ID/锚词/断言思路）。8 ID 逐项索引（§2，依据链逐条标注 RFC 792 章节 + 设计节）+ 正例逐项断言（§3，**6 帧校验和独立反码复算全 OK**，t3 奇长补零路径独占钉）+ 负例契约含**真实拦截面**（§4：t5/t6 引擎面、t7/t8 create-time 面，锚词逐字对代码行）+ 覆盖对账（§5，50 点 = 覆 25 + 不适用 9 + 开放 16）+ P3 固定动作（§6，②③ 为无连接族天花板豁免）+ 执行建议（§7，含离线执行器纪律）+ 存量审计（§8，**保留 7/改写 1（t2 notes 陈旧值）/作废 0**）+ 覆盖反查门增量建议 10 条（§9，**9 绿 1 红，如实标红**）。**本车道今日实跑**：离线链 6/8（t7/t8 引擎直调失守 = G-ICMP-4 直接实证；临时改动已回滚，零 `.go`/cases 落盘）+ coverage_gate 18/18 复跑 + 探针 9 项。自审 3 轮，末轮干净。
