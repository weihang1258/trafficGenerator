# #91 ethmining（EthereumStratum/1.0.0）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/91-ethmining-design.md` v1.0.0（D-ETHMINING-1）
> 旧基线：`docs/protocol-designs/73-ethmining-testcase.md` v2.0.2（32 例；思路参考不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ethmining.json`（32/32 ID 与本版 §2 一致，顺序一致，已实测；顶层旧键残留待 P4 迁移，G-EM-4）
> 白话一句：**三十二条检查：二十二条看正常对话（连上、要活、交活），十条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **32 个唯一语义 ID：22 正 + 10 负**（继承旧稿 v2.0.2 计数，负例编号 23–32）。派生规则：设计 §3 每个消息条款、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-27 机读实测）**：32/32 例顶层键 = `{layers, src_ip, dst_ip, src_port, dst_port, ethmining}`（旧扁平残留，P4 按设计 §12.1 迁严格层链形）；层形 `[tcp,ethmining]` ×30（4444）+ ×1（3353，`ethmining_custom_port`）+ `[{ethmining}]` ×1（`ethmining_neg_carrier` 刻意坏配置）；22 正例 `expect={packet_count}`；10 负例 `expect={expect_error,error_contains}`（键集合干净）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机无 ethash stratum dissector——**不得使用任何 `stratum.*`/`ethmining.*` 字段**；通用 JSON dissector 裸 TCP 不自动解析，`json.*` 不可用。可用通道：① `tcp.payload`（单段不跨段时即完整行含 `0a`）；② `tcp.len`/`tcp.srcport`/`tcp.dstport`/`tcp.stream`/`tcp.flags`；③ `ip.version`/`ipv6.nxt`/`frame.*`；④ frames `offset/hex`（行首 `7b`，IPv4 offset 54 / IPv6 offset 74）。跨段行按 `tcp.stream` 重组后断言；粘行段按 LF 拆行计数。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言。

**包数约定**（单行不跨段）：会话 = 3（握手）+ N（承载行段数，默认每行 1 段）+ 4（双向 FIN）。数据帧从帧 4 起；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

**保活/重试/RST 口径**：spec/ext 无 PING 类消息，不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言；正例恒 FIN 优雅终止。

## 2. 原子用例索引（32 ID = 22 正 + 10 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `ethmining_subscribe_ipv4` | 正 | §3.3：订阅全字段，IPv4 单流基线 | 9 |
| 2 | `ethmining_extranonce_subscribe` | 正 | §3.4：ext 请求 + result=true | 11 |
| 3 | `ethmining_authorize` | 正 | §3.5：授权请求/成功响应 | 11 |
| 4 | `ethmining_authorize_reject` | 正 | §3.5：拒绝路径（error[24]） | 11 |
| 5 | `ethmining_notify_job` | 正 | §3.7：notify 四元素（clean=false） | 13 |
| 6 | `ethmining_notify_clean_jobs` | 正 | §3.7：clean=true 变体 | 13 |
| 7 | `ethmining_set_difficulty` | 正 | §3.6：难度通知（最小通知行 60B） | 13 |
| 8 | `ethmining_set_difficulty_default` | 正 | §3.6：缺省兜底线序 | 12 |
| 9 | `ethmining_set_difficulty_update` | 正 | §3.6：会话中难度变更 | 15 |
| 10 | `ethmining_set_extranonce` | 正 | §3.8/§3.9：轮换 + 互补 | 18 |
| 11 | `ethmining_submit_accept` | 正 | §3.9：submit + result=true | 15 |
| 12 | `ethmining_submit_reject` | 正 | §3.9：submit + result=false（会话继续） | 15 |
| 13 | `ethmining_id_correlation` | 正 | §3.1/§5：id 任意起点、按值配对 | 15 |
| 14 | `ethmining_extranonce_max3` | 正 | §3.3/§8：3B 满值 + 5B 互补 | 15 |
| 15 | `ethmining_hex_prefix` | 正 | §1/§3.1：`0x` 方言变体 | 15 |
| 16 | `ethmining_long_username` | 正 | §3.5/§8：68 字符长用户名 | 15 |
| 17 | `ethmining_line_packing` | 正 | §2/§8：粘连单段 259B | 12 |
| 18 | `ethmining_mss_large_jobid` | 正 | §3.11/§8：1691B 跨段重组 | 14 |
| 19 | `ethmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture | 9 |
| 20 | `ethmining_multi_session` | 正 | §5/§8：双会话展开 | 30 |
| 21 | `ethmining_mining_lifecycle` | 正 | §4⑦/§5：单会话多事务全链 | 18 |
| 22 | `ethmining_custom_port` | 正 | §2：3353 显式合法通道 | 9 |
| 23 | `ethmining_neg_json` | 负 | §7：非法 JSON | — |
| 24 | `ethmining_neg_framing` | 负 | §7：组帧错 | — |
| 25 | `ethmining_neg_method` | 负 | §7：未知 method/方向违例 | — |
| 26 | `ethmining_neg_params` | 负 | §7：params 错 | — |
| 27 | `ethmining_neg_hex` | 负 | §7：hex 违例 | — |
| 28 | `ethmining_neg_state` | 负 | §7：状态机错 | — |
| 29 | `ethmining_neg_id_correlation` | 负 | §7：id 关联错 | — |
| 30 | `ethmining_neg_job_correlation` | 负 | §7：job 关联错 | — |
| 31 | `ethmining_neg_carrier` | 负 | §7：载体错 | — |
| 32 | `ethmining_neg_error_propagation` | 负 | §7：错误未传播 | — |

## 3. fixture 常量与行字节基线（承旧稿 testcase §3，全量有效）

IPv4 `192.0.2.73 → 198.51.100.73`、`src_port=4073`、`dst_port=4444`（IPv6 `2001:db8::73 → 2001:db8::100:73`）；user_agent=`MinerName/1.0.0`、protocol=`EthereumStratum/1.0.0`；订阅标识=`ae6812eb4cd7735a302a8a9dd95cf71f`（第二会话 `b7c31e0a55d29f7f1e9a04c8d2b6a3f4`）；extranonce 基线=`080c`（2B）、满值=`a2eea0`（3B）、第二会话=`1f0a`；用户名=`test`/`password`（第二会话 `test2`/`x`）；id 基线 1/2/3、关联用例 100/101/102；job A=`bf0488aa`、job B=`bf0488ab`；seedhash/headerhash spec verbatim（见设计 §3.11 上下文）；minernonce 6B=`6a909d9bbc0f`（配 2B）、5B=`cfae7df760`（配 3B）；difficulty=`0.5`/`5000012.0`/`2.0`（第二会话）；错误三元组：提交拒绝 `[-1,"Job not found",null]`、授权拒绝 `[24,"Unauthorized user",null]`。长用户名=`00112233445566778899aabbccddeeff00112233.rig-north-01-cabinet3-slot7`（68 字符；authorize 行 123B、submit 行 142B）。非默认端口用例 fixture：`dst_port=3353`，行字节与用例 1 一致。

**核心行字节基线**：subscribe 请求 90B / 订阅响应 117B（extranonce `080c`）/ extranonce.subscribe 请求 60B / authorize 请求 66B / authorize 响应 true 36B / false 62B / set_difficulty 0.5 行 60B（最小通知行；全族最小行 36B 响应由用例 3/11 承载）/ notify（job A，clean=false）199B / clean=true 198B / set_extranonce 65B / submit（6B nonce）78B / submit 响应 true 36B / false 58B。行 hex 锚定样本与 §3.11 公式见设计 §3.11；全行 hex verbatim 表以旧稿 testcase §3 表为准（思路参考，P4 先跑后钉复核）。

层链 `[tcp, ethmining]`（P4 迁 `[ip,tcp,ethmining]` 后行首 offset 不变：IPv4 54 / IPv6 74）。断言分层：① 载体与方向（`tcp.srcport/dstport`、`ip.version`/`ipv6.nxt`、`tcp.len`）；② stratum 行（`tcp.payload` + frames 双通道，行尾恒 `0a`）；③ 跨段重组（`tcp.stream`，首段前缀 + 末段后缀 + `tcp.len` 和 = 行长）；④ 多会话（`sessions[]` 整块回放，第二会话握手起点 = 前会话总包数 + 1；跨会话关联用 `tcp.stream` 区分）。

## 4. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload` + 行首/方法名 frames 断言；行 hex 均可由设计 §3.11 公式 + fixture 精确预算。

1. **`ethmining_subscribe_ipv4`**（9）：单事件 subscribe。帧 4（矿机→矿池，offset 54）`tcp.payload` = 90B 请求全行 hex、`tcp.len=90`；帧 5（矿池→矿机）= 117B 响应全行 hex、`tcp.len=117`；响应含协议串回带与 extranonce 段；`tcp.dstport=4444` 上行全程；挥手完整。
2. **`ethmining_extranonce_subscribe`**（11）：subscribe→extranonce.subscribe。帧 6 = 60B 扩展请求（params 空数组）；帧 7 = 36B `result=true` 响应；各响应 id 与各自请求同值。
3. **`ethmining_authorize`**（11）：subscribe→authorize。帧 6 = 66B 请求（`["test","password"]`）；帧 7 = 36B 成功响应。
4. **`ethmining_authorize_reject`**（11）：数据帧恰 4 段，`tcp.len` 序列 90/117/66/62；帧 7 = 62B 拒绝响应（含 `[24,"Unauthorized user",null]` 全段 hex）；挥手前无额外业务行。
5. **`ethmining_notify_job`**（13）：subscribe→authorize→set_difficulty→notify。帧 8 = 60B set_difficulty；帧 9 = 199B notify（后缀 `2c66616c73655d7d0a`，`tcp.len=199`）；notify 行首 `"id":null`；帧 8/9 均矿池→矿机。
6. **`ethmining_notify_clean_jobs`**（13）：同用例 5，notify clean=true。帧 9 = 198B、后缀 `2c747275655d7d0a`（与用例 5 后缀 distinct）。
7. **`ethmining_set_difficulty`**（13）：帧 8 = 60B 全行 hex（最小通知行）；difficulty 段 `[0.5]` 十进制定点，非科学计数法。
8. **`ethmining_set_difficulty_default`**（12）：subscribe→authorize→notify（**无 set_difficulty**，难度 1 兜底）。段序列 90/117/66/36/199；挥手前业务行恰 5 行；不存在 set_difficulty 行。
9. **`ethmining_set_difficulty_update`**（15）：set_difficulty(0.5)→notify(jobA)→set_difficulty(5000012.0)→notify(jobB)。第二条难度行位于两 notify 之间；jobB headerhash 为第二 fixture 值。
10. **`ethmining_set_extranonce`**（18）：extranonce.subscribe→authorize→set_difficulty→set_extranonce(a2eea0)→notify(jobB)→submit(5B nonce)→响应。帧 11 = 65B 全行 hex；轮换前 2B → 轮换后 3B，submit minernonce 5B 互补恒 8B；extranonce.subscribe 行先于 authorize 行。
11. **`ethmining_submit_accept`**（15）：notify(jobA)→submit(6B)→`result=true`。帧 10 = 78B submit 行（job 段与帧 9 notify 同值——`same_as_packet`）；帧 11 = 36B 接受响应；响应 id 与请求同值。
12. **`ethmining_submit_reject`**（15）：同用例 11，`result=false+[-1,"Job not found",null]`（58B）；**拒绝后会话继续**（正常挥手，非法化"拒绝=断连"误读）。
13. **`ethmining_id_correlation`**（15）：id 序列 100→101→102，响应按值回带；**id 起点非 1**；请求/响应形态 distinct（响应无 method、有 result）。
14. **`ethmining_extranonce_max3`**（15）：订阅 extranonce `a2eea0`（3B，119B 响应）→submit 5B nonce（76B）；3B+5B = 8B（spec §IV 组合）。
15. **`ethmining_hex_prefix`**（15）：`hex_prefix="0x"` 变体。全部 hex 数据字段带 `0x`；**会话内前缀统一**无混用；行长按公式 +每字段 2B 预算。
16. **`ethmining_long_username`**（15）：68 字符长用户名 authorize（123B）/submit（142B）同值（`same_as_packet`/fixture 钉死）；行长按公式核验。
17. **`ethmining_line_packing`**（12）：pack 开启，set_difficulty+notify 粘连。帧 8 `tcp.payload` 259B、恰 2 个 `0a`、前缀 = set_difficulty 行首、段内行尾后紧跟 notify 行首；`tcp.len` 序列 90/117/66/36/259；段边界 ≠ 行边界双向断言。
18. **`ethmining_mss_large_jobid`**（14）：job_id 1500 hex ⇒ notify 行 1691B 跨 2 段（1460+231）；首段前缀 + 末段后缀；`tcp.stream` 重组后完整行 1691B；`tcp.len` 和 = 1691。
19. **`ethmining_ipv6`**（9）：IPv6 独立 fixture；`ipv6.nxt=6`、行首 offset 74、行 hex 与用例 1 一致；不得出现 `ip.version=4`。
20. **`ethmining_multi_session`**（30）：双会话各完整链。`tcp.stream` 两值 distinct；第二会话握手起点由展开规则派生（不硬编码包号）；extranonce/用户名段 distinct；**同值 id 跨会话各自配对**（`tcp.stream` distinct）。
21. **`ethmining_mining_lifecycle`**（18）：单 stream 11 行业务序列，`tcp.len` 序列 90/117/66/36/60/199/78/36/199/78/36；方法名按序出现；第二次 submit job 段与第二次 notify 同值；无乱序。
22. **`ethmining_custom_port`**（9）：同用例 1 事件，`dst_port=3353`；行 hex 与 `tcp.len` 90/117 同用例 1；`tcp.dstport=3353` 上行 / `tcp.srcport=3353` 下行；无 DecodeAs 依赖；planner 不得静默改写端口。

**正例总则**：合法协议事件（submit/authorize 拒绝、难度缺省/变更、轮换、不支持响应、`0x` 统一变体、大 job_id）均为正例形态，只有配置/线格式/状态/关联/长度错误进入负例。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error, error_contains}`。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入（`wire_fault`/配置注入口） | `error_contains` |
|---|---|---|
| `ethmining_neg_json` | 截断/未闭合/非对象行 | `json`、`decode`、`line` |
| `ethmining_neg_framing` | 无 LF / CRLF / 长度前缀 | `newline`、`framing`、`line` |
| `ethmining_neg_method` | 未知 method / GetWork 混入 / 方向违例 | `method`、`unknown`、`direction` |
| `ethmining_neg_params` | 数量/类型/位置错 / set_extranonce 2 元素方言 | `params`、`field`、`type` |
| `ethmining_neg_hex` | 值域/长度/互补/前缀混用 | `hex`、`length`、`extranonce`、`prefix` |
| `ethmining_neg_state` | 首条非 subscribe / 未授权 submit / 关闭后续排 | `state`、`sequence`、`subscribe` |
| `ethmining_neg_id_correlation` | id 错配 / 伪 id / 重复 | `id`、`match`、`correlation` |
| `ethmining_neg_job_correlation` | job 非本会话 / 用户名不一致 | `job`、`worker`、`correlation` |
| `ethmining_neg_carrier` | 缺 tcp / UDP 载体 / 端口矛盾 / 混合地址族 | `carrier`、`tcp`、`port`、`ip`、`version` |
| `ethmining_neg_error_propagation` | 错误被吞 / 假成功 | `error`、`propagat`、`task`（三选一候选集，P4 钉死其一→ G-EM-3） |

**负例原子性**：各行故障输入为互斥候选集——每个负例 ID 选定其一钉死注入并同步两文档；单次执行不得混注；全量覆盖按原子原则拆子 ID。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多事务全链（接入→收任务→提交→新任务→再提交） | 已覆 #21（11 行业务序列） |
| ② | 非正常结束 | 正常 FIN 全正例；authorize 拒绝后关闭（#4）；submit 拒绝会话继续（#12）；**RST 异常中断** | 前半已覆；RST → 框架 tcp 层能力，**显式不适用**（设计 §4⑩），无缺口 |
| ③ | 长保活 | 协议层无 keepalive 语义；长会话 = 同连接多轮 + 多会话展开 | 已覆 #20/#21；周期 notify 维持为声明（设计 §4⑨） |

无空项：①③ 各有已覆例；② 有已覆例 + 显式不适用声明（非"无例无项"）。

### 6.2 A′/B′ 两分类表（要求面反推：数据 / 业务 / 现网 / 多流 / 地址族 / 断言通道 六类）

A′（P4 接线）：业务字段动态（`username`/`job_id` 逐流变，allowlist 未登记）/ 1B extranonce 例（validator 已支持，fixture 未取）/ 并发交错例（`concurrent:true` 启用时）/ 现网方言实证例（G-EM-2 关闭时）/ 顶层旧键迁层链（G-EM-4，32 例迁移）。B′（框架面）：`CheckProtoFlat` ethmining presence 分支（G-EM-4，等框架级 unknown-key 白名单，不单独立项）/ CancelRequest 类关联（不适用，无 B′）。另：G-EM-1（文档注记，已闭）/ G-EM-3（锚词钉死，P4）/ G-EM-5（动态全关 = A′ 候选）。

### 6.3 §3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2）；多流并发：顺序多会话展开已覆（#20），并发交错为例外路径（A′）；单包多载荷：粘连段（#17）+ 跨段重组（#18）双向已覆。三项各有结论，**无豁免逃逸**。

### 6.4 断言契约核对结论（与设计 §3/§3.11/§5 一致）

行长公式 13 行（设计 §3.11）与 packet_count 逐例复核一致（§2 表）；`tcp.len` 序列断言（#4/#8/#17/#21）与公式逐值一致；跨会话/跨段不断言硬编码全局包号（`tcp.stream` + 展开规则）；动态值只用存在与关联断言。旧稿全行 hex verbatim 表继承，P4 先跑后钉复核（§9.31/§14.20）。

## 7. 实现后执行建议（P4/P5）

1. P4 首动作：32 例迁严格层链形（顶层仅 `layers`+`flow_control`；`sessions[].src_port` 保留为层内事件面），收官自查「非负例顶层键 = 0」。
2. suite 经 `flowb_run_protocol_suite` 全量（`CASE_PROTO=ethmining`），pcap 落 `/tmp/mcp-pcaps/ethmining/`；先跑后钉复核行 hex 与包数。
3. 负例 32 锚词钉死其一并同步两文档（G-EM-3）。
4. 服务器二进制与 HEAD 同代确认后跑全量（门2-③）；反查绿后进 P6。

## 8. 存量用例逐条审计去向（§9.14 / §14.4）

存量 `cases/ethmining.json` 32/32 ID 与本版 §2 一致、顺序一致——**全部合入**，无等价覆盖替代、无作废。`ethmining_neg_unregistered` 占位已不存在（注册时已替换，无残留）。形状迁移量（G-EM-4）：32/32 例顶层旧键（`src_ip/dst_ip/src_port/dst_port` + 顶层 `ethmining` 子映射）待 P4 迁层链——非"作废"，为"合入 + 迁形"。

## 9. 修订记录

- v1.0.0（2026-09-27）：P-PIPE #91 文档轨 P1–P3。旧稿 73-* v2.0.2 的 32 ID / packet_count / 锚词 / fixture / 断言分层全量继承（思路参考不搬码）；新增形状基线机读实测（§1）、P3 固定动作（§6）、执行建议（§7）、存量审计（§8，32/32 合入）。P3 自审 2 轮，末轮干净（结论见 p123 报告 §3）。
