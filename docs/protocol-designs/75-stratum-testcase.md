# Stratum（比特币矿池 stratum 协议，Stratum v1 矿机-矿池工作分配）测试用例契约

> 版本：v2.1.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/75-stratum-design.md`（v2.1.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/stratum.json`（proto key：`stratum`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 docs-bacnet：20 findings 逐项修复，待复验关闭），本版 v2.1.0 为修复轮产物：35 → **40 例（29 正 + 11 负）**；v1.1 流程既有重写（v2.0.0）记录见 §9。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史；旧稿 14+6 用例基于已废弃的旧设计稿——submit 参数混入 ethash 方言命名、缺 set_extranonce，全部重排）。新稿 35 条（25 正 + 10 负），规范基线 Bitcoin Wiki《Stratum mining protocol》+ BIP310 + slush0/stratum-mining 与 node-stratum-pool 参考实现，断言以 tshark 3.6.14 本机实测 + 协议逻辑构造 pcap 为基线。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **40 个唯一语义 ID：29 个正例 + 11 个负例**（v2.1.0 新增正例 26-29、负例 39 `stratum_neg_address_family`；负例编号 26–35 → 30–40）。派生规则：设计 §3 每个消息条款（11 类消息、每响应态、每时序变体）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 wiki/BIP310/参考实现）声明范围。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）。

当前 JSON 只保留一个 `stratum_neg_unregistered` 注册前置占位：`proto=stratum`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 40 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 Stratum 行为通过。**占位端口 3333 与本版 fixture 一致，无需修正**；注册时需将 notes 旧计数改写（**v2.1.0 已同步修正 stratum.json notes 为 40/29+11——D-9**）。注册后移除占位，再按本文 §2 顺序补入 29 个正例与 11 个负例。

**输出契约（pcap/NIC 双输出，C-1）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 fields/frames 断言（`tcp.payload` 全行 hex、offset 54/74、`tcp.len`、`tcp.stream`），NIC 路径经 tcpdump 捕获（`nic_capture` 用例级开关；实测口 enp135s0f0np0），网卡 checksum offload 不影响本协议断言（不含校验和字段），L2 无 VLAN 前提下偏移与载荷提取稳定，不改变断言语义（与 64/66/67/68/70/65/73/74 号协议同形）；不设仅单路径可用的断言。

**保活/RST/重连口径（设计 §4 声明⑩、§5，C-5/D-7）**：无应用层 keepalive 帧、TCP keepalive 探测不产生（长连接活性由 notify 周期体现）——不设 keepalive 例亦不进负例；**RST 异常中断 = 正例 27**（`tcp.flags.reset==1`、RST 后无业务行、无挥手——`terminates` 不适用）；**重连重订阅 = 正例 28**（新连接、新 extranonce1、会话状态失效）；FIN 优雅终止由全部其余正例 `terminates=true` 承载——v1.3 §4 清单"FIN/RST 或异常中断"双形态闭合。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 按协议逻辑构造 pcap 实证，非臆造）**：本机**没有比特币 stratum 的 dissector（解析器）**——`tshark -G fields` 中含 "stratum" 的字段全部无关（`ntp.stratum` NTP 层级、`ptp.*stratum` 时钟层级、`lte-rrc.accessStratumRelease` 等，实测输出为空集对应本协议），**不得使用任何 `stratum.*` 字段**。通用 JSON dissector（协议名 "JSON"，字段 `json.*`）**在裸 TCP 上不自动解析**，且 `-d json.tcp.port` 不是 3.6.14 合法 decode-as 层类型（实测报错 "Unknown layer type"），**`json.*` 字段不可用**。可用断言通道（`-G fields` 实测存在）：① `tcp.payload`（FT_BYTES，TCP 载荷原始字节——单段不跨段时即**完整 stratum 行含行尾 `0a`**，构造 pcap 实证逐字节吻合）；② `tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.syn/ack/fin`；③ `ip.version`、`ipv6.nxt`、`frame.number`、`frame.len`；④ `frames` 数组 `offset/hex` 断言（行首字节 `7b`（`{`）起点 IPv4 offset 54 / IPv6 offset 74）。**TCP 分段边界不是 stratum 行边界**：跨段行按 `tcp.stream` 重组后再断言完整行；粘行段按 LF（`0a`）拆行计数。

**动态字段禁止硬编码**：job_id/extranonce1/extranonce2/订阅标识/id 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 断言；本版 fixture 把全部字段**钉死为 fixture 常量**（见 §3 fixture 常量），行字节按设计 §3.13 公式可精确预算（构造 pcap 已实证同构样本）。

**包数约定**（设计 §9 完成定义；单行不跨段时）：会话 = 3（TCP 握手）+ N（承载 stratum 行的 TCP 段数，默认每行 1 段；粘行/跨段按实际段数）+ 4（双向 FIN 挥手）。数据帧从帧 4 起（帧 1–3 握手）；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `stratum_subscribe_ipv4` | 正 | §3.3：订阅请求/响应全字段（双订阅对+extranonce1+extranonce2_size），IPv4 单流基线 | 9 |
| 2 | `stratum_extranonce_subscribe` | 正 | §3.4：extranonce 订阅请求 + result=true | 11 |
| 3 | `stratum_authorize` | 正 | §3.5：授权请求/成功响应 | 11 |
| 4 | `stratum_authorize_reject` | 正 | §3.5：拒绝路径（error[24]） | 11 |
| 5 | `stratum_notify_job` | 正 | §3.7：notify 九元素完整行（clean=false） | 13 |
| 6 | `stratum_notify_clean_jobs` | 正 | §3.7：clean_jobs=true 变体 | 13 |
| 7 | `stratum_set_difficulty` | 正 | §3.6：难度通知（16384；全族最小行 36B 响应由用例 3/10 承载） | 12 |
| 8 | `stratum_set_difficulty_update` | 正 | §3.6：会话中难度变更（16384→32768）作用于后续 job | 15 |
| 9 | `stratum_set_extranonce` | 正 | §3.8：extranonce 轮换（尺寸 4→8）+ 后续 submit extranonce2 16 hex | 15 |
| 10 | `stratum_submit_accept` | 正 | §3.9：submit 五元素 + result=true | 15 |
| 11 | `stratum_submit_reject` | 正 | §3.9：submit + result=false + error[21]（会话继续） | 15 |
| 12 | `stratum_id_correlation` | 正 | §3.1/§5：id 任意起点（100/101/102）、按值配对 | 15 |
| 13 | `stratum_prevhash_byteorder` | 正 | §3.1/§8：prevhash 字节反转（线序≠展示序） | 15 |
| 14 | `stratum_client_get_version` | 正 | §3.10：矿池→矿机反向请求 + 矿机自动响应 | 13 |
| 15 | `stratum_client_show_message` | 正 | §3.10：矿池通知（id=null，无应答） | 12 |
| 16 | `stratum_configure_version_rolling` | 正 | §3.11：mining.configure + 交集掩码响应（BIP310 首条线序） | 11 |
| 17 | `stratum_set_version_mask` | 正 | §3.11：掩码推送（`["00003000"]`，立即生效） | 12 |
| 18 | `stratum_submit_version_bits` | 正 | §3.11：激活态 submit 第 6 参 version_bits（`18000000` ⊆ `1fffe000`） | 15 |
| 19 | `stratum_notify_empty_merkle` | 正 | §3.7/§8：merkle_branch 空数组边界（clean=true） | 13 |
| 20 | `stratum_extranonce2_size8` | 正 | §3.3/§8：订阅即 size=8 + submit extranonce2 16 hex | 15 |
| 21 | `stratum_line_packing` | 正 | §2/§8：多行粘连单段（449B 一段两行） | 12 |
| 22 | `stratum_mss_large_coinb1` | 正 | §3.13/§8：coinb1 1444 hex ⇒ 行 1717B 跨 MSS 2 段 | 16 |
| 23 | `stratum_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） | 9 |
| 24 | `stratum_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开 | 30 |
| 25 | `stratum_mining_lifecycle` | 正 | §4⑨/§5：单会话多事务全链 | 18 |
| 26 | `stratum_concurrent_sessions` | 正 | §4⑧/§5：三矿机并发会话交错回放（互不串用，与 24 分立） | 45 |
| 27 | `stratum_rst_pool_kick` | 正 | §5：RST 异常中断（tcp.flags.reset，RST 后无业务行） | 12 |
| 28 | `stratum_reconnect_resubscribe` | 正 | §5：断线重连重订阅（新 extranonce1，状态失效语义） | 30 |
| 29 | `stratum_port_nondefault` | 正 | §2/§8：非默认端口 4444 显式声明（行字节同基线） | 9 |
| 30 | `stratum_neg_json` | 负 | §7：非法 JSON/截断/非对象行 | — |
| 31 | `stratum_neg_framing` | 负 | §7：无 LF/CRLF/长度前缀 | — |
| 32 | `stratum_neg_method` | 负 | §7：未知 method/方言混入/方向违例 | — |
| 33 | `stratum_neg_params` | 负 | §7：params 数量/类型/位置错 | — |
| 34 | `stratum_neg_hex` | 负 | §7：hex 值域/长度/0x 前缀/TMask 宽度 | — |
| 35 | `stratum_neg_state` | 负 | §7：状态机错 | — |
| 36 | `stratum_neg_id_correlation` | 负 | §7：id 错配/伪 id/未完成事务复用 | — |
| 37 | `stratum_neg_job_correlation` | 负 | §7：job 来源/用户名不一致 | — |
| 38 | `stratum_neg_carrier` | 负 | §7：载体/端口/层链错 | — |
| 39 | `stratum_neg_address_family` | 负 | §7：IPv6/v4 混合地址族 | — |
| 40 | `stratum_neg_error_propagation` | 负 | §7：错误未传播/假成功 | — |
| — | `stratum_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, stratum]`，无 VLAN/IP options/TCP options 时**每条 stratum 行首字节（`{`=`7b`）起点为 IPv4 offset 54、IPv6 offset 74**（构造 pcap 实证：`tcp.payload` 即完整行含行尾 `0a`）。断言分层：

1. **载体与方向（fields 权威断言）**：矿机帧 `tcp.srcport=<会话源端口>`、`tcp.dstport=3333`；矿池帧（订阅/授权/提交响应、set_difficulty/notify/set_extranonce/set_version_mask/show_message 通知、client.get_version 反向请求）端口互换。`ip.version=4`（或 IPv6 fixture 断言 `ipv6.nxt=6` 且不得出现 v4 地址）、`tcp.len` = 该段承载的行字节数（单行不跨段时）。
2. **stratum 行（tcp.payload + frames 双通道）**：单行不跨段时 `tcp.payload` 值 = 完整行 hex（短行全断，notify 387B 行断前缀+分解段+后缀）；frames 断言在 offset 54/74 校验行首 `7b` 与方法名 ASCII hex 子串（如 `6d696e696e672e737562736372696265` = `mining.subscribe`）。行尾恒 `0a`（断言后缀字节）。
3. **跨段重组**：跨 MSS 大行按 `tcp.stream` 重组后断言完整行（重组流起点 = 首段 offset 54）；**任何单段不构成完整行时不得按段断言整行 hex**，改为断言首段前缀 + 末段后缀 + 各段 `tcp.len` 之和 = 行长。
4. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。**并发回放（v2.1.0 C-3）**：`concurrent: true` 为多矿机交错回放模式（正例 26）——与按序整块展开（正例 24）分立；单会话内事件序仍受设计 §5 状态机约束。

**fixture 常量**（fixture 钉死；行字节可精确预算）：IPv4 `192.0.2.75 → 198.51.100.75`、`src_port=4075`、`dst_port=3333`（IPv6 `2001:db8::75 → 2001:db8::100:75`）；user_agent=`MinerName/1.0.0`；订阅标识：会话 1 `7f1a2b3c`（set_difficulty 对）/`9d8e7f6a`（notify 对），会话 2 `1c2d3e4f`/`5a6b7c8d`，会话 3（并发矿机 C，v2.1.1 R-10 补钉）`3e4f5a6b`/`7c8d9e0f`（fixture，distinct）；extranonce1：会话 1 基线 `ea02567c`、会话 2 `ea02567d`、轮换新值 `b3f10a44`（8 hex=4B，⑤长度未钉死取参考实现 4B）；extranonce2_size：基线 4、边界 8；extranonce2：基线 `1a2b3c4d`（8 hex）、尺寸 8 形态 `1a2b3c4d5e6f7081`（16 hex）；用户名 `alice.rig1`/`alice.rig2`、密码 `x`；id 基线 1/2/3、id 关联用例 100/101/102、get_version 请求 id=8、configure id=5；job：`3`（job A）与 `4`（job B，数字串形态）；**prevhash 展示序/线序对**：展示序 `0000000000000000000234c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4`、**线序（逐字节反转，线上携带值）** `b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5c43402000000000000000000`（参考实现 `util.reverse_hash` 行为）；coinb1=`01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1603aa1a0b2f706f6f6c2e746573742f`（114 hex）；coinb2=`1603018e0c2f706f6f6c2e746573742f00000000`（40 hex）；merkle 步=`aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233`（64 hex）；version=`20000000`、nbits=`a13c2c17`、ntime=`64f50123`（4B 内部小端形态，⑤）；nonce=`9c5a2b1d`；difficulty=`16384`→`32768`；BIP310：矿机掩码 `ffffffff`、min-bit-count=16、响应掩码 `1fffe000`、推送掩码 `00003000`、version_bits `18000000`；错误三元组：授权拒绝 `[24,"Unauthorized worker",null]`、提交拒绝 `[21,"Job not found",null]`（wiki 标题形态 fixture 钉死，⑤文案大小写实现阶段实证校准）。**MSS 压力值**：coinb1_long = coinb1 + `6d`×665（+1330 hex 字符 = 1444 hex）。**v2.1.0 新增 fixture**：并发三矿机 src_port=4075/4076/4077、extranonce1 `ea02567c`/`ea02567d`/`ea02567e`、用户名 alice.rig1/rig2/rig3、矿机 C 订阅标识 `3e4f5a6b`/`7c8d9e0f`（v2.1.1 R-10 补钉）；重连会话 2 新 extranonce1 `ea02567f`；RST 用例矿池侧 `termination:"rst"`；非默认端口用例 29 `dst_port=4444`（行字节与用例 1 完全一致——端口不进 stratum 行内容）。

**核心行字节基线**（紧凑 JSON + LF，脚本核验；正例断言直接引用）：

| 行 | 长度 | tcp.payload hex（全行或前缀/分解段/后缀） |
|---|---:|---|
| subscribe 请求 | 66B | `7b226964223a312c226d6574686f64223a226d696e696e672e737562736372696265222c22706172616d73223a5b224d696e65724e616d652f312e302e30225d7d0a` |
| subscribe 响应（size 4） | 114B | `7b226964223a312c22726573756c74223a5b5b5b226d696e696e672e7365745f646966666963756c7479222c223766316132623363225d2c5b226d696e696e672e6e6f74696679222c223964386537663661225d5d2c226561303235363763222c345d2c226572726f72223a6e756c6c7d0a` |
| subscribe 响应（size 8） | 114B | 同上前缀（…`226561303235363763222c` 处接 `38`），末尾 `5d2c226572726f72223a6e756c6c7d0a` |
| extranonce.subscribe 请求 | 60B | `7b226964223a322c226d6574686f64223a226d696e696e672e65787472616e6f6e63652e737562736372696265222c22706172616d73223a5b5d7d0a` |
| 响应 true（id=2） | 36B | `7b226964223a322c22726573756c74223a747275652c226572726f72223a6e756c6c7d0a` |
| authorize 请求（alice.rig1/x） | 65B | `7b226964223a322c226d6574686f64223a226d696e696e672e617574686f72697a65222c22706172616d73223a5b22616c6963652e72696731222c2278225d7d0a` |
| authorize 响应 false | 64B | `7b226964223a322c22726573756c74223a66616c73652c226572726f72223a5b32342c22556e617574686f72697a656420776f726b6572222c6e756c6c5d7d0a` |
| set_difficulty 16384 | 62B | `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e7365745f646966666963756c7479222c22706172616d73223a5b31363338345d7d0a` |
| set_difficulty 32768 | 62B | 同上方法名前缀 + `5b33323736385d7d0a` |
| notify（job 3，clean=false） | 387B | 前缀 `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e6e6f74696679222c22706172616d73223a5b2233222c22` + prevhash **线序**值 hex（线上携带值；展示序反转对见 fixture 常量，用例 13 断言——N-3 加注）`62346133663265316430633962386137663665356434633362326131663065396438633762366135633433343032303030303030303030303030303030303030` + 分隔 `222c22` + coinb1 值 hex `30313030303030303031303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303066666666666666663136303361613161306232663730366636663663326537343635373337343266` + 分隔 `222c22` + coinb2 值 hex `31363033303138653063326637303666366636633265373436353733373432663030303030303030` + 分隔 `222c22` + merkle 段 `5b22616131316262323263633333646434346565353566663636303031313232333334343535363637373838393961616262636364646565666630303131323233333235 5d`（`["<merkle 值 hex>"]`）+ 后缀 `2c223230303030303030222c226131336332633137222c223634663530313233222c66616c73655d7d0a` |
| notify（job 3，clean=true） | 386B | 同上分解，后缀 `…2c747275655d7d0a`（`false`→`true`） |
| notify（job 4，clean=false） | 387B | 同上，job 段 `223422`（`"4"`） |
| notify（空 merkle，clean=true） | 320B | 同上分解，merkle 段 `5b5d`（`[]`），后缀 true 形态 |
| set_extranonce（b3f10a44,4） | 69B | `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e7365745f65787472616e6f6e6365222c22706172616d73223a5b226233663130613434222c345d7d0a` |
| submit（alice.rig1/job 3/8hex en2，id=3） | 95B | `7b226964223a332c226d6574686f64223a226d696e696e672e7375626d6974222c22706172616d73223a5b22616c6963652e72696731222c2233222c223161326233633464222c223634663530313233222c223963356132623164225d7d0a` |
| submit（job 4/16hex en2，id=3） | 103B | 同上前缀（job 段 `223422`、extranonce2 段 `223161326233633464356536663730383122`） |
| submit 响应 true（id=3） | 36B | `7b226964223a332c22726573756c74223a747275652c226572726f72223a6e756c6c7d0a` |
| submit 响应 false（id=3） | 58B | `7b226964223a332c22726573756c74223a66616c73652c226572726f72223a5b32312c224a6f62206e6f7420666f756e64222c6e756c6c5d7d0a` |
| submit 6 参（version_bits 18000000，id=6） | 106B | `7b226964223a362c226d6574686f64223a226d696e696e672e7375626d6974222c22706172616d73223a5b22616c6963652e72696731222c2233222c223161326233633464222c223634663530313233222c223963356132623164222c223138303030303030225d7d0a` |
| client.get_version 请求（id=8） | 51B | `7b226964223a382c226d6574686f64223a22636c69656e742e6765745f76657273696f6e222c22706172616d73223a5b5d7d0a` |
| client.get_version 响应（id=8） | 49B | `7b226964223a382c22726573756c74223a224d696e65724e616d652f312e302e30222c226572726f72223a6e756c6c7d0a` |
| client.show_message | 82B | `7b226964223a6e756c6c2c226d6574686f64223a22636c69656e742e73686f775f6d657373616765222c22706172616d73223a5b224d61696e74656e616e636520696e203130206d696e75746573225d7d0a` |
| mining.configure 请求（id=5） | 139B | `7b226964223a352c226d6574686f64223a226d696e696e672e636f6e666967757265222c22706172616d73223a5b5b2276657273696f6e2d726f6c6c696e67225d2c7b2276657273696f6e2d726f6c6c696e672e6d61736b223a226666666666666666222c2276657273696f6e2d726f6c6c696e672e6d696e2d6269742d636f756e74223a31367d5d7d0a` |
| mining.configure 响应（id=5） | 90B | `7b226964223a352c22726573756c74223a7b2276657273696f6e2d726f6c6c696e67223a747275652c2276657273696f6e2d726f6c6c696e672e6d61736b223a223166666665303030227d2c226572726f72223a6e756c6c7d0a` |
| set_version_mask（00003000） | 69B | `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e7365745f76657273696f6e5f6d61736b222c22706172616d73223a5b223030303033303030225d7d0a` |

（notify 行 `tcp.payload` hex 总长 774 字符 = 387B×2；上表分解段拼接后逐字节等于全行。方法名 ASCII hex：`mining.authorize`=`6d696e696e672e617574686f72697a65`、`mining.notify`=`6d696e696e672e6e6f74696679`、`mining.submit`=`6d696e696e672e7375626d6974`、`mining.set_difficulty`=`6d696e696e672e7365745f646966666963756c7479`、`mining.set_extranonce`=`6d696e696e672e7365745f65787472616e6f6e6365`、`client.get_version`=`636c69656e742e6765745f76657273696f6e`、`client.show_message`=`636c69656e742e73686f775f6d657373616765`、`mining.configure`=`6d696e696e672e636f6e666967757265`、`mining.set_version_mask`=`6d696e696e672e7365745f76657273696f6e5f6d61736b`；通知行首段 `226964223a6e756c6c2c`（`"id":null,`）。）

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；行 hex 均按设计 §3.13 公式对 fixture 常量预算（构造 pcap 已实证同构样本）。除用例 27（RST 终止，`terminates` 断言不适用）外，每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload=true`。

1. **`stratum_subscribe_ipv4`**（9）：单事件 subscribe。帧 4（矿机→矿池，offset 54）`tcp.payload` = 66B 订阅请求全行 hex、`tcp.len=66`；帧 5（矿池→矿机，端口互换）= 114B 订阅响应全行 hex、`tcp.len=114`；响应行含**双订阅对**（`6d696e696e672e7365745f646966666963756c7479` 与 `6d696e696e672e6e6f74696679` 同帧各出现一次）、extranonce1 段 `22656130323536376322`（`"ea02567c"`）、尺寸段 `2c345d`（`,4]`，JSON number 非字符串）；`tcp.dstport=3333` 上行全程；挥手完整。
2. **`stratum_extranonce_subscribe`**（11）：事件 = subscribe→extranonce.subscribe。帧 6 = 60B 扩展请求全行 hex（params 空数组 `5b5d`）；帧 7 = 36B `{"id":2,"result":true,"error":null}` 全行 hex；订阅响应 id 段 `226964223a312c`、扩展响应 id 段 `226964223a322c`——各响应 id 与各自请求同值。
3. **`stratum_authorize`**（11）：事件 = subscribe→authorize。帧 6 = 65B authorize 请求全行 hex（params 段 `5b22616c6963652e72696731222c2278225d` = `["alice.rig1","x"]`）；帧 7 = 36B 授权成功响应全行 hex（`74727565`）。
4. **`stratum_authorize_reject`**（11）：事件 = subscribe→authorize(result=false)。帧 6 同用例 3；帧 7 = 64B 拒绝响应全行 hex（`726573756c74223a66616c7365` = `"result":false`、错误段 `5b32342c22556e617574686f72697a656420776f726b6572222c6e756c6c5d` = `[24,"Unauthorized worker",null]`）；**拒绝响应后无任何业务行**（挥手前 `tcp.len>0` 帧仅 4 行业务），随后连接关闭。
5. **`stratum_notify_job`**（13）：事件 = subscribe→authorize→set_difficulty→notify。帧 8 = 62B set_difficulty 全行 hex；帧 9 = 387B notify 行（前缀+prevhash/coinb1/coinb2/merkle 分解段+后缀 `2c66616c73655d7d0a`，`tcp.len=387`）；**notify 行无数字 id**（行首 `"id":null,` 段 `226964223a6e756c6c2c`）；方向：帧 8/9 均矿池→矿机（`tcp.srcport=3333`）。
6. **`stratum_notify_clean_jobs`**（13）：事件同用例 5，notify clean_jobs=true。帧 9 = 386B notify 行、`tcp.len=386`、后缀 `2c747275655d7d0a`（与用例 5 后缀 distinct——布尔二值边界）。
7. **`stratum_set_difficulty`**（12）：事件 = subscribe→authorize→set_difficulty。帧 8 = 62B set_difficulty 全行 hex、`tcp.len=62`；difficulty 段 `5b31363338345d` = `[16384]`（十进制定点，非科学计数法）；**全族最小行为响应 true 形态 36B**（`35+len(id)+1`，设计 §3.13），由用例 3/10 的响应行承载 `tcp.len` 断言。
8. **`stratum_set_difficulty_update`**（15）：事件 = subscribe→authorize→set_difficulty(16384)→notify(job 3)→set_difficulty(32768)→notify(job 4)。帧 10 = 62B 大难度行（`5b33323736385d`）；帧 11 = 387B job 4 notify 行（job 段 `223422`）；**第二条难度行位于两 notify 之间**（帧序 8=16384、10=32768），难度变更作用于后续 job（wiki §mining.set_difficulty 时序）。
9. **`stratum_set_extranonce`**（15）：事件 = subscribe→extranonce.subscribe→authorize→set_difficulty→**set_extranonce(b3f10a44, 8)**→notify(job 4)→submit(16hex extranonce2 `1a2b3c4d5e6f7081`)→submit 响应。帧 10 = 69B set_extranonce 全行 hex（尺寸段 `2c385d` = `,8]`）；帧 12 = 103B submit 行（16hex extranonce2 段 `223161326233633464356536663730383122`）；**长度匹配断言**：轮换后 submit extranonce2 = 16 hex = 2×新尺寸 8（设计 §3.8"后续 job 生效"）；set_extranonce 行前有 extranonce.subscribe 行（触发前提，wiki）。
10. **`stratum_submit_accept`**（15）：事件 = subscribe→authorize→set_difficulty→notify(job 3)→submit(8hex extranonce2, result=true)。帧 10 = 95B submit 行全 hex（job 段 `223322` 与帧 9 notify 的 job 段同值——`same_as_packet` 关联；extranonce2 段 `22316132623363346422` = 8 hex = 2×4）；帧 11 = 36B 接受响应全 hex（`74727565`）；响应 id 段 `226964223a332c` 与请求同值。
11. **`stratum_submit_reject`**（15）：事件同用例 10，result=false。帧 10 同用例 10；帧 11 = 58B 拒绝响应全 hex（错误段 `5b32312c224a6f62206e6f7420666f756e64222c6e756c6c5d` = `[21,"Job not found",null]`）；**拒绝后会话继续**（正常挥手，非法化"拒绝=断连"误读）。
12. **`stratum_id_correlation`**（15）：事件 id 序列 100(subscribe)→101(authorize)→102(submit)，矿池响应按值回带。断言各行 id 段 ASCII hex：`226964223a3130302c`（100）/`226964223a3130312c`（101）/`226964223a3130322c`（102）在请求与其响应行各出现一次且同值配对；**id 起点非 1**；响应与请求按 id 配对而非 TCP 位置（响应行的 method 缺席、result 在场——请求/响应形态 distinct）。
13. **`stratum_prevhash_byteorder`**（15）：事件同用例 10。帧 9 notify 行的 prevhash 段 = **线序值** `6234…3030`（fixture 常量表线序 hex 逐字节）；断言线上值 ≠ 展示序 `3030…6234`（字节反转关系逐字节互补：线序[i] = 展示序[63−i]）；submit 正常提交（矿机按线序上下文工作）。反转行为出处：参考实现 `util.reverse_hash`（设计 §3.1/§8）。
14. **`stratum_client_get_version`**（13）：事件 = subscribe→**get_version**→authorize。帧 6 = 51B get_version 请求行全 hex——**方向矿池→矿机**（`tcp.srcport=3333`，与通知同向）；帧 7 = 49B 矿机响应行全 hex（`tcp.dstport=3333`，result 段 `224d696e65724e616d652f312e302e3022` = `"MinerName/1.0.0"`）——**自动应答成分**（同 id=8 回带：请求与响应行 id 段 `226964223a382c` 同值）；帧序：请求在前、响应紧随（无其他行插入）。
15. **`stratum_client_show_message`**（12）：事件 = subscribe→authorize→show_message。帧 8 = 82B show_message 行全 hex（方向矿池→矿机）；行首 `"id":null,` 段在场（纯通知，无应答行）；**其后无任何矿机→矿池响应行**（挥手前业务行恰 5 行）。
16. **`stratum_configure_version_rolling`**（11）：事件 = **configure→subscribe**（BIP310 首条线序）。帧 4 = 139B configure 请求行全 hex（扩展段 `5b2276657273696f6e2d726f6c6c696e67225d` = `["version-rolling"]`、掩码段 `226666666666666622`）；帧 5 = 90B configure 响应行全 hex（结果映射 `2276657273696f6e2d726f6c6c696e67223a74727565` 与交集掩码段 `22316666666530303022` = `"1fffe000"` ⊆ `ffffffff`——BIP310 交集规则 `server_mask & miner_mask`）；帧 6/7 = 订阅请求/响应（**configure 先于 subscribe 合法**，设计 §5）。BIP310 verbatim 示例值（扩展名/掩码形态）佐证。
17. **`stratum_set_version_mask`**（12）：事件 = configure→subscribe→set_version_mask。帧 8 = 69B set_version_mask 行全 hex（掩码段 `22303030303330303022` = `"00003000"`，BIP310 verbatim 示例值）；行首 `"id":null,` 段在场；**立即生效语义**（BIP310 原文）与 set_difficulty/set_extranonce 的"后续 job 生效"不同——本用例断言掩码行为该会话当前值（后续无 job 依赖，时序断言仅行位置）。
18. **`stratum_submit_version_bits`**（15）：事件 = configure→subscribe→set_difficulty→notify→submit(**6 参**)→响应。帧 10 = 106B submit 行全 hex（第 6 参段 `2c223138303030303030225d` = `,"18000000"]`）；帧 11 = 36B 接受响应；**约束断言**：`18000000 & ~1fffe000 == 0`（version_bits ⊆ 当前掩码，BIP310 约束式；设计 §3.11）；6 参仅在 version-rolling 激活会话出现（未激活 6 参进负例 33）。
19. **`stratum_notify_empty_merkle`**（13）：事件 = subscribe→authorize→set_difficulty→notify(**空 merkle**, clean=true)。帧 9 = 320B notify 行、`tcp.len=320`（行长公式 §3.13 空 merkle 形态核验）；merkle 段 = `5b5d`（`[]`——数组类型保持，非 `null` 非缺席）；后缀 `2c747275655d7d0a`。空分支行为出处：参考实现 `merkletree._steps` 空表形态（设计 §3.7/§8）。
20. **`stratum_extranonce2_size8`**（15）：事件 = subscribe(**响应 size=8**)→authorize→set_difficulty→notify→submit(16hex extranonce2)。帧 5 = 114B 订阅响应（尺寸段 `2c385d` = `,8]`——与用例 1 的 `2c345d` distinct）；帧 10 = 103B submit 行（16hex extranonce2 段）；**长度匹配断言**：16 hex = 2×8（订阅期声明尺寸，无 set_extranonce 参与——与用例 9 的轮换路径 distinct）。
21. **`stratum_line_packing`**（12）：事件 = subscribe→authorize→[set_difficulty+notify **合并一段**]。断言：帧 8 `tcp.payload` 长度 **449B**、恰含 **2 个 `0a`**（行界）、前缀 = set_difficulty 行首 hex、段内 `31363338345d7d0a`（set_difficulty 行尾 `[16384]}\n`）之后紧跟 `7b226964223a6e75`（notify 行首）；帧数：3 握手 + 5 数据段（4 单行段 + 1 粘行段）+ 4 挥手 = 12——**段边界 ≠ 行边界双向断言**（一段含两行，且无行被段界切坏）；**形态声明（N-6）**：本例形态 = **单段内两完整行**（帧 8 恰 2 个 LF）；跨段粘行形态（行 1 尾与行 2 头分属两段）不设例（声明，避免与用例 22 跨段形态混淆）。
22. **`stratum_mss_large_coinb1`**（16）：事件 = subscribe→authorize→set_difficulty→notify(**coinb1_long = coinb1 + `6d`×665**，1444 hex)→submit→响应。notify 行 = `75+1+64+1444+40+64+8+8+8+5` = 1717B（§3.13 公式常量已含 LF），默认 MSS 1460 不压，跨 **2 段**（1460+257）；帧 9（首段）offset 54 起前缀 = notify 行首 40B hex（`7b226964223a6e756c6c2c…22706172`）；帧 10（末段）后缀 = `3233222c66616c73655d7d0a`；**按 `tcp.stream` 重组后断言完整行 1717B**、`tcp.len` 两段和 = 1717、分段边界不切坏 coinb1 hex 串（重组流中 padding 段 `363664` 重复体连续无断点）；packet_count = 3+9+4 = 16；**断言落点声明（N-5）**：断言 = 重组后单行 JSON 完整且行尾 `0a`（可加 `tcp.reassembled.length` 辅助）+ 各段 `tcp.len` 之和 = 1717——**不要求段边界与行边界对齐**（行协议段界任意落点合法，不得误写为"每段一行"）。
23. **`stratum_ipv6`**（9）：IPv6 独立 fixture（`2001:db8::75 → 2001:db8::100:75`，显式给出）。断言 `ipv6.nxt=6`、行首 offset **74**、subscribe 请求/响应行 hex 与用例 1 完全一致（同一逻辑行，仅外层 IP 头不同）；不得出现 `ip.version=4`。
24. **`stratum_multi_session`**（30 = 15+15）：会话 1（`src_port=4075`，alice.rig1/`ea02567c`/`7f1a2b3c`+`9d8e7f6a`/16384/job 3）与会话 2（`src_port=4076`，alice.rig2/**`ea02567d`**/**`1c2d3e4f`+`5a6b7c8d`**/job 4）各为完整挖矿事务链（subscribe→authorize→set_difficulty→notify→submit→响应）。断言 `tcp.stream` 两值 distinct、**第二会话握手包号 = 16**（= 前会话 15 包 + 1，多会话展开）、两会话 extranonce1 段 hex distinct（`22656130323536376322` vs `22656130323536376422`）、订阅标识段 distinct（`22376631613262336322` vs `22316332643365346622`）、用户名段 distinct（`22616c6963652e7269673122` vs `22616c6963652e7269673222`）、各自响应 id 与本会话请求配对（会话间状态不串用）。
25. **`stratum_mining_lifecycle`**（18）：单 `tcp.stream` 11 行业务序列：subscribe→订阅响应→authorize→授权响应→set_difficulty(16384)→notify(job 3)→submit(id3,job 3)→响应(id3,true)→notify(**job 4, clean=true**)→submit(**id4,job 4**)→响应(id4,true)。断言行类型与方法名 ASCII hex 按此顺序出现；第二次 notify 的 clean 段 `2c747275655d7d0a`（clean=true 清队列语义，wiki §mining.notify）；第二次 submit 的 job 段 `223422` 与第二次 notify 同值、id 段 `226964223a342c` 递增（**job 轮换 + id 递增双断言**）；无乱序（声明式按序回放）。

26. **`stratum_concurrent_sessions`**（45 = 15×3）：`concurrent: true` 三矿机（A `src_port=4075`/alice.rig1/`ea02567c`、B `src_port=4076`/alice.rig2/`ea02567d`、C `src_port=4077`/alice.rig3/`ea02567e`）交错回放各自 subscribe→authorize→set_difficulty→notify→submit→响应链（各 15 包）。断言 `tcp.stream` **三值 distinct**、三会话业务行**交错出现**（帧序源端口交替，非整块串行——与用例 24 按序展开分立）、各自 extranonce1 段 hex distinct（`22656130323536376322`/`…646`/`…656` 互异）、订阅标识三对 fixture 钉死（会话 1 `7f1a2b3c`/`9d8e7f6a`、会话 2 `1c2d3e4f`/`5a6b7c8d`、矿机 C `3e4f5a6b`/`7c8d9e0f`）/用户名 distinct、各自响应 id 与本会话请求配对（响应不跨会话消费）；单会话内事件序仍受设计 §5 状态机约束（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）。（v2.1.0 C-3）
27. **`stratum_rst_pool_kick`**（12 = 3 握手 + 8 数据段 + 1 RST）：事件 = subscribe→authorize→set_difficulty→notify→submit→响应(true)，随后矿池侧 **RST 短路终止**（tcp 层 `termination:"rst"` 配置——框架能力首次行使）。断言：出现 `tcp.flags.reset==1` 帧（矿池→矿机）、**RST 后无任何业务行**（其后无 `tcp.len>0` 帧）、**无 FIN 挥手**（无 `tcp.flags.fin==1` 的四步挥手——与全部 FIN 终止正例 distinct，"FIN 优雅终止 vs RST 异常中断"两形态分立）；`has_handshake=true`；`terminates` 断言不适用（RST 非挥手）。（v2.1.0 C-5）
28. **`stratum_reconnect_resubscribe`**（30 = 15+15）：会话 1 完整链（subscribe→…→submit→响应）FIN 关闭；会话 2 **断线重连**——新 TCP 连接全新握手、重新 subscribe（**新 extranonce1 `ea02567f`**）+ re-authorize + 收新任务。断言：两 `tcp.stream` distinct、**会话 2 首条应用行为 subscribe**（重连 = 重新订阅，非会话恢复——wiki 无恢复语义）、两会话 extranonce1 段 hex distinct（`22656130323536376322` vs `22656130323536376622`）、会话 2 状态全新（job/难度不继承）；会话间包序按多会话展开（第二会话握手包号 = 16）。（v2.1.0 C-5）
29. **`stratum_port_nondefault`**（9）：事件 = subscribe 单事件（同用例 1），显式声明 `src_port=4075`/`dst_port=**4444**`（公开矿池常用端口，设计 §2⑤）。订阅请求/响应行 hex 与用例 1 **完全一致**（端口不进 stratum 行内容，仅 TCP 头端口字段不同）；断言 `tcp.dstport=4444`（上行）、`tcp.srcport=4444`（下行）；**无 DecodeAs 依赖**——本机无 stratum dissector（§1 实测），断言全走 `tcp.payload`/frames，端口变化不改变任何断言通道（与 bacnet #46 DecodeAs 口径形不同因）；planner 不得静默改写端口（未显式声明的非 3333 端口拒绝——负例 38 校验）。（v2.1.0 C-2）

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload`（数据帧 `tcp.payload` nonzero）+ 行首/方法名 frames 断言；行 hex 均可由设计 §3.13 公式 + fixture 常量精确预算（本文已给出全部锚定样本）；动态值只用存在与关联断言。合法协议事件（submit 拒绝、authorize 拒绝、难度变更、extranonce 轮换、空 merkle、反向消息、BIP310 扩展、size=8）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**单一注入纪律（C-4/N-4）：每行恰注入一个故障（各行内多列为互斥候选集，实现期选定其一钉死注入并同步两文档）；主锚词为钉死的单一字面值**；`wire_fault` 注入口列与设计 §6 枚举/§7 表三方一一对应（11 值，D-3 显式映射），行序与设计 §7 同序（N-1）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 30 | `stratum_neg_json` | `json` | subscribe 行截断（`{"id":1,"method":"mining.subs`）、字符串未闭合、某行为 JSON 数组/标量 | `json` |
| 31 | `stratum_neg_framing` | `framing` | 末行无 LF 裸结束、行尾 `0d0a`（CRLF）、行前置 4 字节长度前缀（如 `0041` + 行） | `framing` |
| 32 | `stratum_neg_method` | `method` | 方法名 `mining.get_transactions`（声明不实现的 legacy 方法）、矿机事件发 `mining.notify`（方向违例）、矿池事件发 `mining.submit` | `unknown` |
| 33 | `stratum_neg_params` | `params` | subscribe params 空数组、authorize 单元素、notify 8 元素（缺 clean_jobs）、submit 4 元素（缺 nonce）、set_extranonce 1 元素（ethash 方言）、clean_jobs=1、merkle_branch 为字符串、extranonce2_size `"4"`、未激活 version-rolling 时 submit 6 参 | `params` |
| 34 | `stratum_neg_hex` | `hex` | prevhash 62 hex（非 64）、nonce 含 `g`、coinb2 奇数长度、任意 hex 字段带 `0x` 前缀（无方言）、merkle 步 63 字符、version_bits 7 字符 | `hex` |
| 35 | `stratum_neg_state` | `state` | 事件序列首条为 authorize、未 authorize 先 submit、close 事件后追加 submit | `state` |
| 36 | `stratum_neg_id_correlation` | `id` | submit 响应 id=9 ≠ 请求 id=3、notify 行携带 `"id":1`（伪 id）、**subscribe(id=1) 未收响应时 authorize 复用 id=1（未完成事务 id 重复——单一变异仅 id 复用，C-4 钉死）** | `id` |
| 37 | `stratum_neg_job_correlation` | `job` | submit 的 job_id=`999` 不来自本会话任何 notify、submit 用户名 `alice.rig2` ≠ 已授权 `alice.rig1` | `job` |
| 38 | `stratum_neg_carrier` | `carrier` | 层链 `[{"stratum":{}}]` 直连（缺 tcp）、UDP 载体、`dst_port` 与载体声明矛盾 | `carrier` |
| 39 | `stratum_neg_address_family` | `address_family` | IPv6 src/dst 地址配 IPv4 层链（`[ip, tcp, stratum]` + v6 地址）或反向——混合地址族拒绝（D-8 补） | `ip` |
| 40 | `stratum_neg_error_propagation` | `propagation` | validator 已知 hex/状态错误被吞、任务报 completed/0 packet 假成功 | `propagat` |

合法协议事件不进负例（防误报）：submit 拒绝（正例 11）、authorize 拒绝（正例 4）、难度变更（正例 8）、set_extranonce 轮换（正例 9）、空 merkle 数组（正例 19）、extranonce2_size=8（正例 20）、大 coinb1（正例 22）、client.get_version/show_message 反向消息（正例 14/15）、configure 先于 subscribe（正例 16）、激活态 6 参 submit（正例 18）、未发 set_difficulty 直接 notify（设计 §4⑥ 未约束自由度）。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–29（正）；30–40（负） | 11 类消息每类正例（subscribe/extranonce.subscribe/authorize×2 态/set_difficulty×2 时序/notify×2 布尔+空 merkle/set_extranonce/submit×2 态/get_version 反向/show_message/configure/set_version_mask）+ 多事务全链；负例 11 类锚词逐类与设计 §7 对应；client.reconnect、suggest_difficulty/target、get_transactions、capabilities/set_goal 为设计 §1/§4 声明不实现 |
| 性能 | 7、21、22、24、26 | 最小行边界（36B 响应由 3/10 承载）、多行粘连单段（449B 两行）、大 coinb1 行 1717B 跨 MSS 2 段重组、多会话展开（24）与并发交错（26）；行长无协议上界（设计 §3.13 公式约束）；发包速率由框架既有配置承载（v1.3 §10 口径） |
| 数据场景 | 5、6、7、8、9、13、18、19、20；负 33、34 | difficulty 值域（16384/32768 整数定点）、extranonce2 尺寸 4/8 与 2×长度匹配（违例负例）、prevhash 字节反转（展示序/线序对）、clean_jobs 二值、merkle 空数组/单步两态、version_bits 子集约束、TMask 恒 8 hex、0x 前缀禁用（负例）、hex 字符集/奇偶（负例） |
| 地址与流 | 1（v4 单流基线）、23（v6）、24（多会话双四元组按序）、26（三矿机并发交错）、28（重连双流）、29（非默认端口 4444） | v4+v6 必覆盖 + 并发会话（26，C-3）+ 重连（28）+ 非默认端口（29，C-2）；流关联与多流显式不适用（设计 §4 声明：单 TCP 行式长连接无副连接——多流≠并发会话） |
| 业务 | 1/2/3（接入）、4（鉴权拒绝）、5/6/7/8（收任务）、10/11（提交）、9（轮换）、14/15（矿池探测公告）、16/17/18（version-rolling）、25（完整生命周期）、24/26（多矿机按序/并发）、27（矿池踢线）、28（断线重连） | 现网挖矿日常场景优先（接入-收任务-提交链）；现代 ASIC version-rolling 为现网标配（BIP310） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/stratum.json` 通过；当前数组恰含 1 条 `stratum_neg_unregistered`：`proto=stratum`、层链 `[{"tcp":{}},{"stratum":{}}]`、`dst_port=3333`（与本版 fixture 一致，无需修正）、`expect_error=true`、`error_contains` 精确为 `unknown layer`（notes 已于 v2.1.0 修正为 40/29+11，注册时仅需按 §2 替换用例）。
2. 实现注册 `stratum` 层后：移除占位，按 §2 顺序补入 40 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
3. **计数自查（N-7）**：§2 表行数 = 40（29 正 + 11 负）+ 1 占位行；§8 一致性清单 ID 数 = 40；脚本断言三方同序。
4. **JSON notes 修正（D-9）**：stratum.json 占位 notes 已于 v2.1.0 同步改写为 40/29+11（旧稿"20 语义 ID/14 正 6 负"口径清除）；注册替换时按 §2 各行覆盖描述核对 packet_count。
5. **负例单一注入（C-4）**：§5 表 11 行每行恰注入一个故障（`wire_fault` 取值集合 = §5 注入口列 11 值，三方同序）；主锚词为单一钉死字面值，无候选列表。
6. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `stratum.*`/`json.*` 字段**（本机无本协议 dissector；JSON dissector 裸 TCP 不解析且不可 decode-as，实测确认）。
7. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields/frames。
8. 跨会话/跨段断言用 `tcp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
9. 若实现期实证现网矿池方言（错误文案大小写、 extranonce1 长度、端口约定、nbits/version 线序形态）与本版假设（设计 §1⑤/§3.5）不符，设计 §3 与本文 §3/§4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `stratum.json` 保持同一 40 个语义 ID、同一顺序（当前 JSON 另有占位 `stratum_neg_unregistered`，不计入——占位 ID 在此显式登记，与 §2 末行对齐，D-2）：

```text
stratum_subscribe_ipv4
stratum_extranonce_subscribe
stratum_authorize
stratum_authorize_reject
stratum_notify_job
stratum_notify_clean_jobs
stratum_set_difficulty
stratum_set_difficulty_update
stratum_set_extranonce
stratum_submit_accept
stratum_submit_reject
stratum_id_correlation
stratum_prevhash_byteorder
stratum_client_get_version
stratum_client_show_message
stratum_configure_version_rolling
stratum_set_version_mask
stratum_submit_version_bits
stratum_notify_empty_merkle
stratum_extranonce2_size8
stratum_line_packing
stratum_mss_large_coinb1
stratum_ipv6
stratum_multi_session
stratum_mining_lifecycle
stratum_concurrent_sessions
stratum_rst_pool_kick
stratum_reconnect_resubscribe
stratum_port_nondefault
stratum_neg_json
stratum_neg_framing
stratum_neg_method
stratum_neg_params
stratum_neg_hex
stratum_neg_state
stratum_neg_id_correlation
stratum_neg_job_correlation
stratum_neg_carrier
stratum_neg_address_family
stratum_neg_error_propagation
```

## 9. 修订记录

- v2.1.1（2026-09-01，复验残留修复轮）：docs-bacnet 复验后清零 11 处（2D+9N）：R-2 §7 条 1 占位 notes 指令更新；R-3 删 §5 旧引言段；R-5 §6 负例 10 类→11 类；R-6 §7 条目重排 1..9；R-8 §4 总则补"除用例 27（RST，terminates 不适用）外"；R-9 用例 28 会话 2 extranonce1 段 hex 多余空格；R-10 §3 fixture 补会话 3（并发矿机 C）订阅标识对 `3e4f5a6b`/`7c8d9e0f` + v2.1.0 新增 fixture 段与用例 26 同步（三矿机订阅标识全钉死）。

- v2.1.0（2026-09-01，v1.3 行为面全枚举重审修复轮）：docs-bacnet 重审 20 findings 逐项修复，35 → **40 例（29 正 + 11 负）**、负例编号 26–35 → 30–40。**C-1** §1 输出契约段（pcap/NIC 双输出六项）+ §7 验收项；**C-2** 用例 29 `stratum_port_nondefault`（4444，行字节同用例 1，无 dissector 无 DecodeAs）+ fixture 常量；**C-3** 并发翻案——用例 26 `stratum_concurrent_sessions`（三矿机交错、`tcp.stream` 三值 distinct）+ §3.4 并发回放段；**C-4** §5 负例 36 id 复用描述钉死单一变异 + 单一注入纪律声明；**C-5** 用例 27 `stratum_rst_pool_kick`（`tcp.flags.reset==1`、无挥手）+ 用例 28 `stratum_reconnect_resubscribe`（新 extranonce1 `ea02567f`）+ §1 保活/RST/重连口径段；**D-1/D-2/D-3** §2 补 4 正例行、§8 显式登记占位 ID、§5 表补 `wire_fault` 注入口列（11 值三方映射）；**D-4/D-5/D-6** 设计 §3.13 公式常量 55→57/42→43/30→31（本文 §3 基线表 hex 本就正确，两文档现在一致）；**D-7/D-8** 保活口径声明 + 负例 39 `stratum_neg_address_family`；**N-1/N-4** §5 行序与设计 §7 同序 + 主锚词单一钉死；**N-3** §3 基线表 notify 行 prevhash 加"线序"标注；**N-5/N-6** 用例 22 断言落点 = 重组后行完整（不要求段界对齐）、用例 21 形态声明 = 单段内两完整行；**N-7** §7 补计数/notes/单一注入三条静态检查；**D-9** stratum.json notes 本轮改写（40/29+11）；**N-8/F-001~F-003** 版本 v2.1.0 + v1.3 来源登记 + 设计侧八条验收对照与注入形状示例。审查报告反驳项：N-2 所称"§3 基线表缺 authz_rej/cfg_resp/notify_reject 三行"与现状不符（§3 表 L84 authorize 响应 false 64B、L95 submit 响应 false 58B、L101 configure 响应 90B 均在），该 finding 不成立；D-3 所称"testcase §2 负例 ID 与设计不一致"与现状不符（两侧均为 neg_json 族同序），仍采纳其 wire_fault 显式映射列建议。

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负，基于已废弃的旧设计稿：submit 参数混入 ethash 方言命名、缺 set_extranonce、subscribe 响应单订阅对形态）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史）。规范基线 Bitcoin Wiki《Stratum mining protocol》+ BIP310 + slush0/stratum-mining 与 node-stratum-pool 参考实现；用例从 20 条重排为 35 条（25 正 + 10 负）——每消息类型、每响应态、每时序变体、每长度边界（extranonce2 尺寸 4/8 与 2×长度匹配、最小行 36B、大 coinb1 1717B 跨 MSS）、每关联规则（id 配对/job 来源/用户名一致/version_bits 子集）、每错误分支各一例；索引表五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 实测固化"无本协议 dissector、JSON dissector 裸 TCP 不解析不可 decode-as、断言走 `tcp.payload` 全行 hex + offset 54/74 frames 双通道"基线，并按协议逻辑构造 pcap 实证（subscribe/authorize/set_difficulty/notify/submit 全行逐字节提取吻合，行尾 `0a`）；fixture 常量全部脚本核验（订阅标识双对/extranonce1 三值/job 3 与 4/prevhash 展示序-线序对/coinb1/coinb2/merkle/difficulty/掩码/version_bits/错误三元组）；新增 §3 核心行字节基线表（notify 分解段拼接）、§6 五层映射、§8 三方一致性表；占位端口 3333 与本版一致（无需修正，与 73-ethmining 占位端口错位情形不同）。状态：**待独立隔离审查**。
