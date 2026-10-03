# Stratum（比特币 Stratum v1）测试用例契约

> 版本：v1.1.0（P4 层链收官对账；#89 stratum）
> 日期：2026-09-30
> 配套设计：`docs/protocols/stratum/design.md`（D-STRATUM-1，v1.1.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/stratum.json`（40 例：29 正 + 11 负；ID/顺序即本文件 §2）
> 旧基线：归档于 `docs/protocols/stratum/_archive_75-stratum-testcase.md`；本版保留行为契约并更新 P4 实测形状与缺口状态。
> 状态：P4 形状收官，尚未跑 suite；先跑后钉由 P5 执行。

## 1. 测试原则与形状基线

用例从设计 §3–§9 逐项派生，共 **40 个唯一语义 ID：29 正 + 11 负**。派生规则：设计 §3 每个消息条款（11 类消息、每响应态、每时序变体）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一份 cases JSON、同一 fields/frames 断言（`tcp.payload` 全行 hex、offset 54/74、`tcp.len`、`tcp.stream`），NIC 路径经 tcpdump 捕获（`nic_capture` 用例级开关；实测口 enp135s0f0np0），网卡 checksum offload 不影响本协议断言（不含校验和字段）；不设仅单路径可用的断言。

**保活/RST/重连口径**：无应用层 keepalive 帧、TCP keepalive 探测不产生——不设 keepalive 例亦不进负例；**RST 异常中断 = #27**（`tcp.flags.reset==1`、RST 后无业务行、无挥手）；**重连重订阅 = #28**（新连接、新 extranonce1、会话状态失效）；FIN 优雅终止由全部其余正例 `terminates` 承载。

**TSHARK 断言通道（本机 3.6.14 实测在案）**：`tcp.payload` / `tcp.len` / `tcp.srcport` / `tcp.dstport` / `tcp.stream` / `tcp.flags.reset` / `tcp.flags.fin` / `ip.version` / `ipv6.nxt` / `frame.number` / `frame.len` + frames `offset/hex`。**不使用任何 `stratum.*`/`json.*` 字段**（含 "stratum" 的 17 行全部无关，`ntp.stratum`/ptp/lte-rrc/nas 系；JSON dissector 裸 TCP 不解析且不可 decode-as）。

**动态字段禁止硬编码**：job_id/extranonce1/extranonce2/订阅标识/id 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 断言；本版 fixture 钉死常量（见 §3 头），行字节按设计 §3.13 公式可精确预算。

**包数约定**：会话 = 3（TCP 握手）+ N（承载行段数，默认每行 1 段；粘连/跨段按实际段数）+ 4（双向 FIN 挥手）。数据帧从帧 4 起；实现期以实际输出校准 packet_count（**#9/#18 以 JSON 实测 17 为准**，旧稿 15 系笔误）；负例无 packet_count。

**形状基线（P4 形状收官实测）**：机读实测 40/40 已为纯层链形：正例顶层仅 `{layers,flow_control}`，负例顶层仅 `{layers}`；39 例链为 `[ip,tcp,stratum]`，载体负例保留 `[ip,stratum]` 以验证拒绝；整形不改变 ID/顺序/语义。

## 2. 原子用例索引（40 ID = 29 正 + 11 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（JSON 实测） |
|---:|---|---|---|---:|
| 1 | `stratum_subscribe_ipv4` | 正 | §3.3：订阅请求/响应全字段（双订阅对+en1+size），v4 单流基线 | 9 |
| 2 | `stratum_extranonce_subscribe` | 正 | §3.4：extranonce 订阅 + `result=true` | 11 |
| 3 | `stratum_authorize` | 正 | §3.5：授权请求/成功响应 | 11 |
| 4 | `stratum_authorize_reject` | 正 | §3.5：拒绝路径（error[24]） | 11 |
| 5 | `stratum_notify_job` | 正 | §3.7：notify 九元素（clean=false） | 13 |
| 6 | `stratum_notify_clean_jobs` | 正 | §3.7：clean=true 变体 | 13 |
| 7 | `stratum_set_difficulty` | 正 | §3.6：难度通知 16384 | 12 |
| 8 | `stratum_set_difficulty_update` | 正 | §3.6：难度变更 16384→32768，作用后续 job | 15 |
| 9 | `stratum_set_extranonce` | 正 | §3.8：轮换（4→8）+ 后续 submit 16hex | **17**（旧稿 15 误） |
| 10 | `stratum_submit_accept` | 正 | §3.9：submit 五元素 + `true` | 15 |
| 11 | `stratum_submit_reject` | 正 | §3.9：submit + `false + error[21]`（会话继续） | 15 |
| 12 | `stratum_id_correlation` | 正 | §3.1/§5：id 任意起点 100/101/102，按值配对 | 15 |
| 13 | `stratum_prevhash_byteorder` | 正 | §3.1/§8：prevhash 字节反转（线序≠展示序） | 15 |
| 14 | `stratum_client_get_version` | 正 | §3.10：矿池→矿机反向请求 + 自动响应 | 13 |
| 15 | `stratum_client_show_message` | 正 | §3.10：矿池通知（id=null，无应答） | 12 |
| 16 | `stratum_configure_version_rolling` | 正 | §3.11：configure + 交集掩码（首条线序） | 11 |
| 17 | `stratum_set_version_mask` | 正 | §3.11：掩码推送（立即生效） | 12 |
| 18 | `stratum_submit_version_bits` | 正 | §3.11：激活态 submit 第 6 参（约束满足） | **17**（旧稿 15 误） |
| 19 | `stratum_notify_empty_merkle` | 正 | §3.7/§8：空 merkle（clean=true） | 13 |
| 20 | `stratum_extranonce2_size8` | 正 | §3.3/§8：订阅即 size=8 + submit 16hex | 15 |
| 21 | `stratum_line_packing` | 正 | §2/§8：粘连单段（449B 两行） | 12 |
| 22 | `stratum_mss_large_coinb1` | 正 | §3.13/§8：1444hex→1717B 跨 MSS 2 段 | 16 |
| 23 | `stratum_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） | 9 |
| 24 | `stratum_multi_session` | 正 | §5/§8：双会话整块展开 | 30 |
| 25 | `stratum_mining_lifecycle` | 正 | §4⑨/§5：单会话多事务全链 | 18 |
| 26 | `stratum_concurrent_sessions` | 正 | §4⑧/§5：三矿机并发交错 | 45 |
| 27 | `stratum_rst_pool_kick` | 正 | §5：RST 短路（无挥手） | 12 |
| 28 | `stratum_reconnect_resubscribe` | 正 | §5：重连重订阅（新 en1） | 30 |
| 29 | `stratum_port_nondefault` | 正 | §2/§8：非默认端口 4444（行字节同基线） | 9 |
| 30 | `stratum_neg_json` | 负 | §7：非法 JSON/截断/非对象 | — |
| 31 | `stratum_neg_framing` | 负 | §7：无 LF/CRLF/长度前缀 | — |
| 32 | `stratum_neg_method` | 负 | §7：未知 method/方言/方向违例 | — |
| 33 | `stratum_neg_params` | 负 | §7：params 数量/类型/位置错 | — |
| 34 | `stratum_neg_hex` | 负 | §7：hex 值域/长度/`0x`/TMask 宽度 | — |
| 35 | `stratum_neg_state` | 负 | §7：状态机错 | — |
| 36 | `stratum_neg_id_correlation` | 负 | §7：id 错配/伪 id/未完成事务复用 | — |
| 37 | `stratum_neg_job_correlation` | 负 | §7：job 来源/用户名不一致 | — |
| 38 | `stratum_neg_carrier` | 负 | §7：载体/端口/层链错 | — |
| 39 | `stratum_neg_address_family` | 负 | §7：混合地址族 | — |
| 40 | `stratum_neg_error_propagation` | 负 | §7：错误未传播/假成功 | — |

## 3. 正例逐项断言契约

fixture 常量：IPv4 `192.0.2.75 → 198.51.100.75`、`src_port=4075`、`dst_port=3333`（IPv6 `2001:db8::75 → 2001:db8::100:75`）；`MinerName/1.0.0`；en1 会话 1 `ea02567c` / 会话 2 `ea02567d`（G-ST-7：`multi_session` 会话 2 已改为 `ea02567d`）/ 矿机 C `ea02567e` / 轮换 `b3f10a44` / 重连 `ea02567f`；en2 基线 `1a2b3c4d`（8hex）/ size8 `1a2b3c4d5e6f7081`（16hex）；`alice.rig1/rig2/rig3` / `x`；id 基线 1/2/3、关联 100/101/102、get_version 8、configure 5；job `3`/`4`；prevhash 展示/线序对（线序线上值）；coinb1 114hex / coinb2 40hex / merkle 步 64hex；version/nbits/ntime `20000000`/`a13c2c17`/`64f50123`；nonce `9c5a2b1d`；difficulty 16384→32768；BIP310 矿机掩码 `ffffffff`/min-bit-count 16/交集 `1fffe000`/推送 `00003000`/version_bits `18000000`；错误 `[24,"Unauthorized worker",null]` / `[21,"Job not found",null]`；show `Maintenance in 10 minutes`。行字节基线（复算全中）：sub_req 66 / sub_resp 114 / 扩展请求 60 / true 响应 36 / auth_req 65 / auth_rej 64 / sd 62 / se 69 / sub5 95 / sub_rej 58 / 6参 106 / gv_req 51 / gv_resp 49 / show 82 / cfg_req 139 / cfg_resp 90 / svm 69 / notify 387（空 merkle 320）。

以下 fields/frames 为最低断言集，实现期可增不可减。除 #27（RST，`terminates` 不适用）外，每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload=true`。

1. **#1**（9）：帧 4（矿机→矿池，offset 54）`tcp.payload` = 66B 订阅请求全行、`tcp.len=66`；帧 5（矿池→矿机）= 114B 订阅响应全行、`tcp.len=114`；响应含**双订阅对**（两方法名 hex 各一次）、en1 段 `"ea02567c"`、尺寸段 `,4]`（number 非字符串）；上行 `tcp.dstport=3333` 全程。
2. **#2**（11）：帧 6 = 60B 扩展请求全行（`params=[]` 段 `5b5d`）；帧 7 = 36B true 响应全行；订阅响应 id=1、扩展响应 id=2——各响应与各自请求同值。
3. **#3**（11）：帧 6 = 65B authorize 请求全行（`["alice.rig1","x"]` 段）；帧 7 = 36B 成功响应全行（`74727565`）。**全族最小行 36B**（`35+len(id)+1`）由本例与 #10 承载 `tcp.len` 断言。
4. **#4**（11）：帧 7 = 64B 拒绝响应全行（`"result":false` + `[24,"Unauthorized worker",null]` 段）；**拒绝后无任何业务行**（挥手前 `tcp.len>0` 帧仅 4 行业务），随后关闭。
5. **#5**（13）：帧 8 = 62B set_difficulty 全行；帧 9 = 387B notify 行（前后缀分解 + `tcp.len=387`）；行首 `"id":null,` 段；帧 8/9 均矿池→矿机（`tcp.srcport=3333`）。
6. **#6**（13）：帧 9 = 386B notify 行、后缀 `,true]}`（与 #5 后缀 distinct——布尔二值边界）。
7. **#7**（12）：帧 8 = 62B set_difficulty 全行（`[16384]` 段，十进制定点非科学计数法）。
8. **#8**（15）：帧 10 = 62B 大难度行（`[32768]`）；帧 11 = 387B job 4 notify 行；**第二条难度行位于两 notify 之间**（帧序 8=16384、10=32768）。
9. **#9**（17）：帧 10 = 69B set_extranonce 全行（`,8]` 段）；帧 12 = 103B submit 行（16hex en2 段）；**长度匹配**：16hex = 2×新尺寸 8；set_extranonce 行前有 extranonce.subscribe 行（触发前提）。
10. **#10**（15）：帧 10 = 95B submit 全行（job 段与帧 9 notify 同值——`same_as_packet`；en2 8hex = 2×4）；帧 11 = 36B 接受响应；响应 id=3 与请求同值。
11. **#11**（15）：帧 11 = 58B 拒绝响应全行（`[21,"Job not found",null]` 段）；**拒绝后会话继续**（正常挥手）。
12. **#12**（15）：id 序列 100/101/102，请求与响应行 id 段 ASCII hex 各出现一次且同值配对；**起点非 1**；响应无 method、有 result（请求/响应形态 distinct）。
13. **#13**（15）：帧 9 notify prevhash 段 = **线序值**逐字节；断言线上值 ≠ 展示序（线序[i] = 展示序[63−i]）。
14. **#14**（13）：帧 6 = 51B get_version 请求全行——**方向矿池→矿机**；帧 7 = 49B 矿机响应全行（`result:"MinerName/1.0.0"` 段）——**自动应答**（同 id=8）；请求在前响应紧随。
15. **#15**（12）：帧 8 = 82B show_message 全行（矿池→矿机）；行首 `"id":null,` 在场；**其后无矿机→矿池响应行**。
16. **#16**（11）：帧 4 = 139B configure 请求全行（`["version-rolling"]` 段 + 矿机掩码段）；帧 5 = 90B 响应全行（交集掩码 `"1fffe000"` ⊆ `ffffffff`）；帧 6/7 = 订阅请求/响应（**configure 先于 subscribe 合法**）。注：存量事件另带 `version_rolling_mask`/`min_bit_count` 键（G-ST-2 已收官，事件键已消费，线字节由缺省 `FixtureCfgParams` 产出——断言仍按 139B 行）。
17. **#17**（12）：帧 8 = 69B set_version_mask 全行（`"00003000"` 段）；`"id":null,` 在场；**立即生效**语义（与"后续 job 生效"不同，断言行位置）。
18. **#18**（17）：帧 10 = 106B 6 参 submit 全行（`,\"18000000\"]` 段）；帧 11 = 36B 接受响应；**约束**：`18000000 & ~1fffe000 == 0`；6 参仅激活会话出现（未激活进负例 #33）。
19. **#19**（13）：帧 9 = 320B notify 行（merkle 段 `[]`，非 null 非缺席；后缀 true 形态）。
20. **#20**（15）：帧 5 = 114B 订阅响应（`,8]` 段，与 #1 `,4]` distinct）；帧 10 = 103B submit 行（16hex 段）；16hex = 2×8（无 set_extranonce 参与，与 #9 路径 distinct）。
21. **#21**（12）：帧 8 `tcp.payload` **449B**、恰 **2 个 `0a`**（前缀 = sd 行首、段内 sd 行尾后紧跟 notify 行首）；3 握手 + 5 数据段 + 4 挥手 = 12；**单段内两完整行**形态（跨段粘行不设例）。
22. **#22**（16）：notify 行 1717B 跨 **2 段**（1460+257）；帧 9 首段 offset 54 前缀 + 帧 10 末段后缀；**按 `tcp.stream` 重组后断言完整行** + 两段 `tcp.len` 和 = 1717；**不要求段界与行界对齐**。
23. **#23**（9）：`ipv6.nxt=6`、行首 offset **74**、行 hex 与 #1 完全一致；不得出现 `ip.version=4`。
24. **#24**（30）：`tcp.stream` 两值 distinct、**第二会话握手包号 = 16**、两会话 en1/订阅标识/用户名 distinct、各自响应 id 与本会话请求配对。注：存量会话 2 en1 已改为 `ea02567d`，与会话 1 distinct（G-ST-7 已收官）。
25. **#25**（18）：单 `tcp.stream` 11 行业务序列（subscribe→…→submit(3)→响应→notify(job 4,clean=true)→submit(4)→响应）；第二次 notify clean 段 true、第二次 submit job 段 `"4"` + id 段 4 递增（**job 轮换 + id 递增双断言**）；无乱序。
26. **#26**（45）：`tcp.stream` **三值 distinct**、业务行**交错出现**（源端口交替，非整块串行——与 #24 分立）、三 en1 distinct（`…67c/…67d/…67e`）、三订阅标识对 fixture 钉死（`7f1a2b3c/9d8e7f6a`、`1c2d3e4f/5a6b7c8d`、`3e4f5a6b/7c8d9e0f`）/ 用户名 distinct、响应不跨会话消费；单会话内事件序仍受状态机约束。
27. **#27**（12 = 3+8+1RST）：`tcp.flags.reset==1` 帧（矿池→矿机）、**RST 后无任何业务行**、**无 FIN 挥手**；`has_handshake=true`；`terminates` 不适用。注：`stratum.termination` 已从存量 JSON 删除；终止行为由 tcp 层 `rst:true` 承载（G-ST-2 已收官）。
28. **#28**（30）：两 `tcp.stream` distinct、**会话 2 首条应用行为 subscribe**、两 en1 distinct（`…67c` vs `…67f`）、会话 2 状态全新；第二会话握手包号 = 16。
29. **#29**（9）：行 hex 与 #1 **完全一致**（端口不进 stratum 行）；`tcp.dstport=4444`（上行）/`tcp.srcport=4444`（下行）；**无 DecodeAs 依赖**。注：P4 实测链内显式 4444 合法，不被 FieldContract 3333 拒（G-ST-3 已收官）。

**正例总则**：每条含 `packet_count` + 载体方向断言 + `has_payload` + 行首/方法名 frames 断言；动态值只用存在与关联断言。合法协议事件均为正例形态，只有配置/线格式/状态/关联/长度错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**单一注入纪律：每行恰注入一个故障**；`wire_fault` 注入口列与设计 §6/§7 三方一一对应（11 值），行序与设计 §7 同序：

| # | ID | `wire_fault` | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 30 | `stratum_neg_json` | `json` | subscribe 行截断、字符串未闭合、某行为数组/标量 | `json` |
| 31 | `stratum_neg_framing` | `framing` | 末行无 LF / `0d0a` / 4 字节长度前缀 | `framing` |
| 32 | `stratum_neg_method` | `method` | `mining.get_transactions` / 矿机发 `mining.notify` / 矿池发 `mining.submit` | `unknown` |
| 33 | `stratum_neg_params` | `params` | subscribe 空数组 / authorize 单参 / notify 8 元素 / submit 缺 nonce / set_extranonce 1 元素 / clean_jobs=1 / merkle 非数组 / size 字符串 / 未激活 6 参 | `params` |
| 34 | `stratum_neg_hex` | `hex` | prevhash 62hex / nonce 含 `g` / 奇数长 / `0x` 前缀 / merkle 步 63 字符 / version_bits 7 字符 | `hex` |
| 35 | `stratum_neg_state` | `state` | 首条 authorize / 未 authorize 先 submit / close 后追加 submit | `state` |
| 36 | `stratum_neg_id_correlation` | `id` | 响应 id=9 ≠ 请求 3 / notify 带 `"id":1` / subscribe(id=1) 未响应时 authorize 复用 id=1 | `id` |
| 37 | `stratum_neg_job_correlation` | `job` | job=`999` 非本会话 / 用户名 `alice.rig2` ≠ 已授权 `alice.rig1` | `job` |
| 38 | `stratum_neg_carrier` | `carrier` | 层链 `[stratum]` 直连（缺 tcp）/ UDP / 端口矛盾 | `carrier` |
| 39 | `stratum_neg_address_family` | `address_family` | IPv6 地址配 IPv4 层链或反向 | `ip` |
| 40 | `stratum_neg_error_propagation` | `propagation` | 已知错误被吞 / 假成功 / 0 包 | `propagat` |

合法协议事件不进负例（防误报）：submit 拒绝（#11）、authorize 拒绝（#4）、难度变更（#8）、轮换（#9）、空 merkle（#19）、size=8（#20）、大 coinb1（#22）、反向消息（#14/#15）、configure 先行（#16）、激活态 6 参（#18）、未发 set_difficulty 直接 notify（未约束自由度）。

## 5. 三源回指行与 9.52 对账

### 5.1 三源回指（§9.2–9.4）

Wiki《Stratum mining protocol》（方法签名/九参/五参/双参/错误码/三元组）+ BIP310（configure/掩码/第 6 参约束）+ slush0/node-stratum-pool（订阅构成/检查序/字面值）→ D-STRATUM-1（设计 §11）→ 40 ID（本文件 §2）。第三源"已确认现网行为" = Wiki 即现网口径级（⑤假设四点挂 G-ST-5，不冒充抓包级）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：来源 = **规范/官方文档反推**（Wiki + BIP310 + 两个参考实现逐消息/逐字段/逐错误码枚举），**非**引擎能力面反推。引擎侧只作现状取证。
- **对账两行**：**规范逻辑点总数 = 87**（八项 8 行 + 矩阵 55 格 + 变体 24 行）；**用例覆盖数 = 63**（八项 8 + 矩阵已覆 22 + 矩阵负例通道 9 + 变体 24）；**不适用 = 22**；**A′/立项 = 2**（矩阵缺口中无用例通道的 2 格；P4 已收官项 G-ST-1/2/3/4/6/7 不再计为当前缺口，G-ST-5 待确认）。63+22+2 = 87 ✓。**反查全绿 ≠ 覆盖全**。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP：Startup 式订阅→授权→难度→通知→提交→轮换→再提交 | 已覆 #25；A′ 补例 `stratum_multi_round_notify`（>2 轮） |
| ② | 非正常结束 | 正常 FIN（29 正例）；拒绝会话继续（#11）；授权拒绝关闭（#4）；RST（#27） | 前半已覆；后半 → 2 条 A′（`server_abort_after_reject` / `idle_timeout_kick`） |
| ③ | 长保活 | 协议层无 keepalive（显式不适用）；长会话 = 同连接多轮 notify | 已覆 #25 + #8；>2 轮随 ① 同批 |

### 6.2 A′/B′ 两分类表（要求面反推：数据 / 业务 / 现网 / 多流 / 地址族 / 断言通道 六类 + 动态面）

- **A′（引擎可构建 → 40 ID 内已覆）**：数据面 #5–#13/#17–#20（+ 非法形→负例 #30–#34）；业务面 #1–#11/#14–#18/#25；现网面 #1–#11/#16–#18 外壳；多流面 #26；地址族面 #1/#23/#39 三格；断言通道面全正例双通道（`tcp.payload` + frames hex）。
- **A′ 补例建议**：`stratum_multi_round_notify`（>2 轮 job 轮换）/ `stratum_server_abort_after_reject` / `stratum_idle_timeout_kick` / `username` 多用户逐流变候选——并入与否由主线程定，不影响 §2 的 40 ID 权威口径。
- **B′（当前待确认项）**：G-ST-5 现网文案/长度/序关系仍待抓包确认；不影响当前 40 例机器契约。

### 6.3 §3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1–s4）；多流并发 #26；单包多载荷两形态（粘连 #21 + 跨段 #22）；流关联（控制流派生数据流）**显式不适用**（单 TCP 长连接无副连接）。结论：多流 / 单包多载荷 / 多包序列三项各有结论，无逃逸。

### 6.4 断言契约核对结论（与设计 §3/§11 一致）

行字节 19 值复算全中（§3 头）；prevhash 反转实证 True；约束式 `18000000 & ~1fffe000 == 0` 成立；`#24/#26/#28` 的 stream-distinct 与包号规则（16 = 15+1）与设计 §5 一致；#22 重组断言不要求段界对齐（与设计 §8 一致）。

## 7. 实现后执行建议（P4/P5）

1. P4 形状收官：40 例为纯层链形（G-ST-1）+ 事件键已接线消费（G-ST-2）+ 会话区分度已修复（G-ST-7）；`python3 -m json.tool cases/stratum.json` 已通过，尚未跑 suite。
2. P5 执行时按 §2 顺序运行 40 ID 全量 suite（`CASE_PROTO=stratum`，负例检查锚词）；先跑后钉，pcap/NIC 使用同一断言集。
3. coverage gate 与全量 suite 出口需在 P5 实际执行中确认；本轮不宣称已运行。
4. 正例每条含 `packet_count` + `fields` + `frames`；负例 `expect` 键集合恰为 `{expect_error, error_contains}`。
5. 若实证现网 ⑤ 假设与本版不符，设计 §3 与本文 §3 对应断言同步校准，并在两文档修订记录登记。

## 8. 存量用例逐条审计去向（§9.14 / §14.4）

40/40 **合入**、作废 0、等价覆盖 0（ID/顺序/语义不变；整形只动形状）：#1–#29 正例逐条合入（#9/#18 packet_count 按 JSON 实测 17 落断言，旧稿 15 勘误；#16 事件 2 键 + #27 stratum 级 `termination` 已按 G-ST-2 修形；#24 会话 2 已按 G-ST-7 区分）；#30–#40 负例逐条合入（`wire_fault` 11 值三方同序，锚词单一钉死）。P4 迁移收官后形状见设计 §12.1（机读实测：正例顶层仅 `{layers,flow_control}`）。

## 9. 修订记录

- v1.1.0（2026-09-30）：P4 形状收官。40 例机读对账为 29 正 + 11 负；非负例顶层键为 0，39 例 `[ip,tcp,stratum]`、1 个载体负例 `[ip,stratum]`；G-ST-2 事件键与 G-ST-7 会话区分度已修复；G-ST-3 显式 4444 合法；未跑 suite，G-ST-5 待 P5/现网抓包确认。
