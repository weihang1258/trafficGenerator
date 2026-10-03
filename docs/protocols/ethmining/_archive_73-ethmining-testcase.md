# ETHMining（以太坊挖矿 stratum 协议，EthereumStratum/1.0.0 ethash 矿池通信）测试用例契约

> 版本：v2.0.2（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/73-ethmining-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/ethmining.json`（proto key：`ethmining`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 review-ethmining：6 confirmed（4 MAJOR + 2 MINOR）+ 6 自洽 + 3 待实现边界），本版 v2.0.2 为修复轮产物：31 → **32 例（22 正 + 10 负）**，待复验关闭；v1.1 流程既有审查修复（v2.0.1）记录见 §9。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史；旧稿 14+6 用例基于已废弃的错误协议定位——节点侧 legacy JSON-RPC/HTTP 8545，全部重排）。新稿 31 条（21 正 + 10 负），规范基线 NiceHash EthereumStratum/1.0.0 R2 + extranonce subscribe extension，断言以 tshark 3.6.14 本机实测 + spec 逻辑构造 pcap 为基线。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **32 个唯一语义 ID：22 个正例 + 10 个负例**（v2.0.2 新增正例 22 `ethmining_custom_port`，负例编号 22–31 → 23–32、ID 不变）。派生规则：设计 §3 每个消息条款（7 类消息 + 1 扩展、每响应态、每时序变体）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 NiceHash spec/ext）声明范围。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）。

当前 JSON 只保留一个 `ethmining_neg_unregistered` 注册前置占位：`proto=ethmining`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 32 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 ETHMining 行为通过。**占位为旧稿遗留，注册时需一并修正**：`dst_port` 8545 → 4444、notes 中"20 语义 ID/14 正 6 负"的旧计数改为 32/22+10（本版不改 JSON 文件）。注册后移除占位，再按本文 §2 顺序补入 22 个正例与 10 个负例。

**输出契约（pcap/NIC 双输出，C1）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 fields/frames 断言（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames），NIC 路径仅经 tcpdump 捕获（`nic_capture` 用例级开关），L2 无 VLAN 前提下偏移与载荷提取稳定，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet 同形）；不设仅单路径可用的断言。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 按 spec 逻辑构造 pcap 实证，非臆造）**：本机**没有 ethash stratum 的 dissector（解析器）**——`tshark -G fields` 中含 "stratum" 的字段全部无关（`ntp.stratum` NTP 层级、`ptp.*stratum` 时钟层级、`lte-rrc.accessStratumRelease` 等，实测输出为空集对应本协议），**不得使用任何 `stratum.*`/`ethmining.*` 字段**。通用 JSON dissector（协议名 "JSON"，字段 `json.*`）**在裸 TCP 上不自动解析**，且 `-d json.tcp.port` 不是 3.6.14 合法 decode-as 层类型（实测报错 "Unknown layer type"），**`json.*` 字段不可用**。可用断言通道（`-G fields` 实测存在）：① `tcp.payload`（FT_BYTES，TCP 载荷原始字节——单段不跨段时即**完整 stratum 行含行尾 `0a`**，构造 pcap 实证逐字节吻合）；② `tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.syn/ack/fin`；③ `ip.version`、`ipv6.nxt`、`frame.number`、`frame.len`；④ `frames` 数组 `offset/hex` 断言（行首字节 `7b`（`{`）起点 IPv4 offset 54 / IPv6 offset 74）。**TCP 分段边界不是 stratum 行边界**：跨段行按 `tcp.stream` 重组后再断言完整行；粘行段按 LF（`0a`）拆行计数。

**动态字段禁止硬编码**：job_id/extranonce/minernonce/订阅标识/id 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 断言；本版 fixture 把全部字段**钉死为 spec verbatim 常量**（见 §3 fixture 常量），行字节按设计 §3.11 公式可精确预算（构造 pcap 已实证同构样本）。

**包数约定**（设计 §9 完成定义；单行不跨段时）：会话 = 3（TCP 握手）+ N（承载 stratum 行的 TCP 段数，默认每行 1 段；粘行段由 `pack` 开启产生——设计 §3.1 pack 条款，见用例 17；跨段按实际段数）+ 4（双向 FIN 挥手）。数据帧从帧 4 起（帧 1–3 握手）；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

**保活/重试/RST 口径（设计 §4 声明⑨⑩，C3）**：spec/ext 无 PING/保活/重试类消息（长连接由矿池周期 notify 维持），不设正例亦不得进负例；RST 异常中断为待实现边界（框架 tcp 层能力，本协议层不新增断言、不计入 ID 覆盖统计）——本版正例恒 FIN 优雅终止（`terminates=true`）。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `ethmining_subscribe_ipv4` | 正 | §3.3：订阅请求/响应全字段，IPv4 单流基线 | 9 |
| 2 | `ethmining_extranonce_subscribe` | 正 | §3.4：ext 扩展请求 + result=true | 11 |
| 3 | `ethmining_authorize` | 正 | §3.5：授权请求/成功响应 | 11 |
| 4 | `ethmining_authorize_reject` | 正 | §3.5：拒绝路径（error[24]） | 11 |
| 5 | `ethmining_notify_job` | 正 | §3.7：notify 四元素完整行（clean=false） | 13 |
| 6 | `ethmining_notify_clean_jobs` | 正 | §3.7：clean_jobs=true 变体 | 13 |
| 7 | `ethmining_set_difficulty` | 正 | §3.6：难度通知（0.5，最小通知行 60B；全族最小行 36B 响应由用例 3/11 承载） | 13 |
| 8 | `ethmining_set_difficulty_default` | 正 | §3.6：缺省难度兜底线序（无 set_difficulty 直接 notify） | 12 |
| 9 | `ethmining_set_difficulty_update` | 正 | §3.6：会话中难度变更作用于后续 job | 15 |
| 10 | `ethmining_set_extranonce` | 正 | §3.8/§3.9：extranonce 轮换 + minernonce 5B 互补 | 18 |
| 11 | `ethmining_submit_accept` | 正 | §3.9：submit + result=true | 15 |
| 12 | `ethmining_submit_reject` | 正 | §3.9：submit + result=false + error[-1]（会话继续） | 15 |
| 13 | `ethmining_id_correlation` | 正 | §3.1/§5：id 任意起点（100/101/102）、按值配对 | 15 |
| 14 | `ethmining_extranonce_max3` | 正 | §3.3/§8：extranonce 3B 满值 + minernonce 5B（全 nonce 8B） | 15 |
| 15 | `ethmining_hex_prefix` | 正 | §1/§3.1：`0x` 前缀方言变体（会话内统一） | 15 |
| 16 | `ethmining_long_username` | 正 | §3.5/§8：长用户名（68 字符）authorize/submit 同值 | 15 |
| 17 | `ethmining_line_packing` | 正 | §2/§8：多行粘连单段（259B 一段两行） | 12 |
| 18 | `ethmining_mss_large_jobid` | 正 | §3.11/§8：job_id 1500 hex ⇒ 行 1691B 跨 MSS 2 段 | 14 |
| 19 | `ethmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） | 9 |
| 20 | `ethmining_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开 | 30 |
| 21 | `ethmining_mining_lifecycle` | 正 | §4⑦/§5：单会话多事务全链 | 18 |
| 22 | `ethmining_custom_port` | 正 | §2/§3：非默认端口 3353 显式声明合法通道（端口不进 stratum 行内容，行字节与用例 1 一致） | 9 |
| 23 | `ethmining_neg_json` | 负 | §7：非法 JSON/截断/非对象行 | — |
| 24 | `ethmining_neg_framing` | 负 | §7：无 LF/CRLF/长度前缀 | — |
| 25 | `ethmining_neg_method` | 负 | §7：未知 method/GetWork 混入/方向违例 | — |
| 26 | `ethmining_neg_params` | 负 | §7：params 数量/类型/位置错 | — |
| 27 | `ethmining_neg_hex` | 负 | §7：hex 值域/长度/互补/前缀混用 | — |
| 28 | `ethmining_neg_state` | 负 | §7：状态机错 | — |
| 29 | `ethmining_neg_id_correlation` | 负 | §7：id 错配/伪 id/重复 | — |
| 30 | `ethmining_neg_job_correlation` | 负 | §7：job 来源/用户名不一致 | — |
| 31 | `ethmining_neg_carrier` | 负 | §7：载体/端口/层链错 | — |
| 32 | `ethmining_neg_error_propagation` | 负 | §7：错误未传播/假成功 | — |
| — | `ethmining_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, ethmining]`，无 VLAN/IP options/TCP options 时**每条 stratum 行首字节（`{`=`7b`）起点为 IPv4 offset 54、IPv6 offset 74**（构造 pcap 实证：`tcp.payload` 即完整行含行尾 `0a`）。断言分层：

1. **载体与方向（fields 权威断言）**：矿机帧 `tcp.srcport=<会话源端口>`、`tcp.dstport=4444`；矿池帧（订阅/授权/提交响应、set_difficulty/notify/set_extranonce 通知）端口互换。`ip.version=4`（或 IPv6 fixture 断言 `ipv6.nxt=6` 且不得出现 v4 地址）、`tcp.len` = 该段承载的行字节数（单行不跨段时）。
2. **stratum 行（tcp.payload + frames 双通道）**：单行不跨段时 `tcp.payload` 值 = 完整行 hex（短行全断，notify 199B 行断前缀+后缀）；frames 断言在 offset 54/74 校验行首 `7b` 与方法名 ASCII hex 子串（如 `6d696e696e672e737562736372696265` = `mining.subscribe`）。行尾恒 `0a`（断言后缀字节）。
3. **跨段重组**：跨 MSS 大行按 `tcp.stream` 重组后断言完整行（重组流起点 = 首段 offset 54）；**任何单段不构成完整行时不得按段断言整行 hex**，改为断言首段前缀 + 末段后缀 + 各段 `tcp.len` 之和 = 行长。
4. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。**并发回放（v2.0.2 C5）**：`concurrent: true` 为生成器例外路径本版不启用；多矿机并发连接的协议语义由顺序多会话展开承载（正例 20），与「多流（单连接内部并发流）显式不适用」分立。

**fixture 常量**（全部 spec verbatim 或标注 fixture 钉死；行字节可精确预算）：IPv4 `192.0.2.73 → 198.51.100.73`、`src_port=4073`、`dst_port=4444`（IPv6 `2001:db8::73 → 2001:db8::100:73`）；user_agent=`MinerName/1.0.0`、protocol=`EthereumStratum/1.0.0`；订阅标识=`ae6812eb4cd7735a302a8a9dd95cf71f`（spec §III verbatim；第二会话 `b7c31e0a55d29f7f1e9a04c8d2b6a3f4`，fixture 钉死）；extranonce 基线=`080c`（2B，spec §III verbatim）、满值=`a2eea0`（3B，spec §IV verbatim）、第二会话=`1f0a`（fixture）；用户名=`test`、密码=`password`（spec §IV verbatim；第二会话 `test2`/`x`，fixture）；id 基线 1/2/3、id 关联用例 100/101/102；job A=`bf0488aa`、seedhash=`abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c`、headerhash=`645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc`（spec §III verbatim）；job B=`bf0488ab`（fixture 钉死）、headerhash=`fc12eb20c58158071c956316cdcd12a22dd8bf126ac4aee559f0ffe4df11f279`（spec §IV verbatim）；minernonce 6B=`6a909d9bbc0f`（spec §III verbatim，配 2B extranonce）、5B=`cfae7df760`（spec §IV verbatim，配 3B extranonce）；difficulty=`0.5`（spec §III verbatim）/`5000012.0`（fixture 大值）/`2.0`（第二会话）；set_extranonce 新值=`a2eea0`；错误三元组：提交拒绝 `[-1,"Job not found",null]`（spec verbatim）、授权拒绝 `[24,"Unauthorized user",null]`（标准 stratum 惯例，fixture 钉死）。**长用户名**=`00112233445566778899aabbccddeeff00112233.rig-north-01-cabinet3-slot7`（40 hex ETH 地址无前缀 + `.矿机名`，共 68 字符，密码 `x`；authorize 行 123B、submit 行 142B，按 §3.11 公式 `53+len(id)+len(user)+len(pass)`/`53+len(id)+len(user)+8+12` 核验）。**0x 前缀变体**：hex 数据字段（订阅标识/extranonce/job_id/seedhash/headerhash/minernonce）统一带 `0x`。**非默认端口用例 22 fixture**：`dst_port=3353`（NiceHash Ethash 接入端口，设计 §2「公开资料 + 假设」标注）；行字节与用例 1 完全一致（端口不进 stratum 行内容，仅 TCP 端口字段不同）。

**核心行字节基线**（紧凑 JSON + LF，脚本核验；正例断言直接引用）：

| 行 | 长度 | tcp.payload hex（全行或前缀/后缀） |
|---|---:|---|
| subscribe 请求 | 90B | `7b226964223a312c226d6574686f64223a226d696e696e672e737562736372696265222c22706172616d73223a5b224d696e65724e616d652f312e302e30222c22457468657265756d5374726174756d2f312e302e30225d7d0a` |
| subscribe 响应（extranonce 080c） | 117B | `7b226964223a312c22726573756c74223a5b5b226d696e696e672e6e6f74696679222c226165363831326562346364373733356133303261386139646439356366373166222c22457468657265756d5374726174756d2f312e302e30225d2c2230383063225d2c226572726f72223a6e756c6c7d0a` |
| subscribe 响应（extranonce a2eea0） | 119B | 同上前缀（`…225d2c` 处接 `2261326565613022`），末尾 `2c226572726f72223a6e756c6c7d0a` |
| extranonce.subscribe 请求 | 60B | `7b226964223a322c226d6574686f64223a226d696e696e672e65787472616e6f6e63652e737562736372696265222c22706172616d73223a5b5d7d0a` |
| authorize 请求（test/password） | 66B | `7b226964223a322c226d6574686f64223a226d696e696e672e617574686f72697a65222c22706172616d73223a5b2274657374222c2270617373776f7264225d7d0a` |
| authorize 响应 true | 36B | `7b226964223a322c22726573756c74223a747275652c226572726f72223a6e756c6c7d0a` |
| authorize 响应 false | 62B | `7b226964223a322c22726573756c74223a66616c73652c226572726f72223a5b32342c22556e617574686f72697a65642075736572222c6e756c6c5d7d0a` |
| set_difficulty 0.5 | 60B | `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e7365745f646966666963756c7479222c22706172616d73223a5b302e355d7d0a` |
| set_difficulty 5000012.0 | 66B | 同上方法名前缀 + `5b353030303031322e305d7d0a`（params `[5000012.0]`） |
| notify（job A，clean=false） | 199B | 前缀 `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e6e6f74696679222c22706172616d73223a5b226266303438386161222c` + seedhash hex `61626164386639396633393138626639303363366139303964396262633066646661356132663462396362313139363137356563383235633636313031323663222c22` + headerhash hex `36343563663230313938633266333836316539343764346636376533616236336237623265323464633930393562643931323365376233333337316636636322` + 后缀 `2c66616c73655d7d0a` |
| notify（job A，clean=true） | 198B | 同上，后缀 `2c747275655d7d0a` |
| notify（job B，clean=false） | 199B | 前缀（job 段）`…226266303438386162222c` + 同 seedhash + headerhash hex `6663313265623230633538313538303731633935363331366364636431326132326464386266313236616334616565353539663066666534646631316632373922` + 后缀 `2c66616c73655d7d0a` |
| set_extranonce a2eea0 | 65B | `7b226964223a6e756c6c2c226d6574686f64223a226d696e696e672e7365745f65787472616e6f6e6365222c22706172616d73223a5b22613265656130225d7d0a` |
| submit（test/jobA/6B nonce，id=3） | 78B | `7b226964223a332c226d6574686f64223a226d696e696e672e7375626d6974222c22706172616d73223a5b2274657374222c226266303438386161222c22366139303964396262633066225d7d0a` |
| submit（test/jobA/5B nonce，id=3） | 76B | 同上前缀 + `2263666165376466373630225d7d0a`（`cfae7df760`） |
| submit（test/jobB/5B nonce，id=4） | 76B | 同上形态（`22626630343838616222` 为 job B 段） |
| submit 响应 true（id=3） | 36B | `7b226964223a332c22726573756c74223a747275652c226572726f72223a6e756c6c7d0a` |
| submit 响应 false（id=3） | 58B | `7b226964223a332c22726573756c74223a66616c73652c226572726f72223a5b2d312c224a6f62206e6f7420666f756e64222c6e756c6c5d7d0a` |

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；行 hex 均按设计 §3.11 公式对 fixture 常量预算（构造 pcap 已实证同构样本）。每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload=true`。

1. **`ethmining_subscribe_ipv4`**（9）：单事件 subscribe。帧 4（矿机→矿池，offset 54）`tcp.payload` = 90B 订阅请求全行 hex、`tcp.len=90`；帧 5（矿池→矿机，端口互换）= 117B 订阅响应全行 hex、`tcp.len=117`；响应行含协议串回带 `457468657265756d5374726174756d2f312e302e30`（`EthereumStratum/1.0.0`）与 extranonce 段 `223038306322`（`"080c"`）；`tcp.dstport=4444` 上行全程；挥手完整。
2. **`ethmining_extranonce_subscribe`**（11）：事件 = subscribe→extranonce.subscribe。帧 6 = 60B 扩展请求全行 hex（params 空数组 `5b5d`）；帧 7 = 36B `{"id":2,"result":true,"error":null}` 全行 hex；订阅响应（帧 5）id 段 `226964223a312c`（`"id":1,`）、扩展响应 id 段 `226964223a322c`（`"id":2,`）——各响应 id 与各自请求同值。
3. **`ethmining_authorize`**（11）：事件 = subscribe→authorize。帧 6 = 66B authorize 请求全行 hex（params 段 `5b2274657374222c2270617373776f7264225d` = `["test","password"]`）；帧 7 = 36B 授权成功响应全行 hex（`74727565`）。
4. **`ethmining_authorize_reject`**（11 = 3 握手 + 4 数据段 + 4 挥手）：事件 = subscribe→authorize(result=false)。**量化断言：数据帧恰 4 段，`tcp.len` 序列断言 90/117/66/62**（与设计 §3.11 行长公式逐值一致）；帧 6 同用例 3；帧 7 = 62B 拒绝响应全行 hex（`726573756c74223a66616c7365` = `"result":false`），frames 断言错误三元组全段 hex `5b32342c22556e617574686f72697a65642075736572222c6e756c6c5d`（= `[24,"Unauthorized user",null]`）；**挥手前无额外业务行**（`tcp.len>0` 帧恰上述 4 段，无第 5 业务段），随后连接关闭。
5. **`ethmining_notify_job`**（13）：事件 = subscribe→authorize→set_difficulty→notify。帧 8 = 60B set_difficulty 全行 hex；帧 9 = 199B notify 行（前缀+seedhash/headerhash hex 子串+后缀 `2c66616c73655d7d0a`，`tcp.len=199`）；**notify 行无数字 id**（行首 `"id":null,` 段 `226964223a6e756c6c2c`）；方向：帧 8/9 均矿池→矿机（`tcp.srcport=4444`）。
6. **`ethmining_notify_clean_jobs`**（13）：事件同用例 5，notify clean_jobs=true。帧 9 = 198B notify 行、`tcp.len=198`、后缀 `2c747275655d7d0a`（与用例 5 后缀 distinct——布尔二值边界）。
7. **`ethmining_set_difficulty`**（13）：事件同用例 5。帧 8 = 60B set_difficulty 全行 hex、`tcp.len=60`（**最小通知行**：通知类消息族无更短行，设计 §3.11 公式核验；全族最小行为响应 true 形态 36B，由用例 3/11 的响应行承载）；difficulty 段 `5b302e355d` = `[0.5]`（十进制定点，非科学计数法）。
8. **`ethmining_set_difficulty_default`**（12）：事件 = subscribe→authorize→notify（**无 set_difficulty 事件**，难度 1 兜底线序，设计 §3.6②）。**段序列断言：5 个数据段 `tcp.len` = 90/117/66/36/199**（与设计 §3.11 公式逐值一致）；断言挥手前业务行恰 5 行（subscribe/订阅响应/authorize/授权响应/notify）、**不存在 set_difficulty 行**（无 `6d696e696e672e7365745f646966666963756c7479` ASCII hex）；帧 8 = 199B notify 行——首条矿池推送即任务，线序合法。
9. **`ethmining_set_difficulty_update`**（15）：事件 = subscribe→authorize→set_difficulty(0.5)→notify(jobA)→set_difficulty(5000012.0)→notify(jobB)。帧 10 = 66B 大难度行（`5b353030303031322e305d`）；帧 11 = 199B jobB notify 行（job 段 `22626630343838616222`、headerhash 为 `fc12eb20…` 的 ASCII hex）；**第二条难度行位于两 notify 之间**（帧序 8=0.5、10=5000012.0），难度变更作用于后续 job（spec §III 时序）。
10. **`ethmining_set_extranonce`**（18）：事件 = subscribe(extranonce 080c)→extranonce.subscribe→authorize→set_difficulty→**set_extranonce(a2eea0)**→notify(jobB)→submit(minernonce **cfae7df760** 5B)→submit 响应。帧 11 = 65B set_extranonce 全行 hex（`22613265656130225d` = `"a2eea0"]`，`59+6` 按 §3.11 公式核验）；帧 13 = 76B submit 行（5B nonce 段 `226366616537646637363022`）；**长度互补断言**：轮换前 extranonce 2B（订阅响应段 `223038306322`）、轮换后 extranonce 3B，submit 的 minernonce 5 字节与当前（轮换后）extranonce 互补 = 全 nonce 恒 8B（设计 §3.9）；set_extranonce 行前有 extranonce.subscribe 行（触发前提，ext）。**frames 顺序断言**：extranonce.subscribe 请求/响应帧（帧 6/7）先于 authorize 请求/响应帧（帧 8/9）——设计 §5 `Subscribed` 可选事件时点，本版 fixture 取 authorize 之前。
11. **`ethmining_submit_accept`**（15）：事件 = subscribe→authorize→set_difficulty→notify(jobA)→submit(6B nonce, result=true)。帧 10 = 78B submit 行全 hex（job 段 `22626630343838616122` 与帧 9 notify 的 job 段同值——`same_as_packet` 关联）；帧 11 = 36B 接受响应全 hex（`74727565`）；响应 id 段 `226964223a332c` 与请求同值。
12. **`ethmining_submit_reject`**（15）：事件同用例 11，result=false。帧 10 同用例 11；帧 11 = 58B 拒绝响应全 hex（错误段 `5b2d312c224a6f62206e6f7420666f756e64222c6e756c6c5d` = `[-1,"Job not found",null]`）；**拒绝后会话继续**（无更多业务行但正常挥手，非法化"拒绝=断连"误读）。
13. **`ethmining_id_correlation`**（15）：事件 id 序列 100(subscribe)→101(authorize)→102(submit)，矿池响应按值回带。断言各行 id 段 ASCII hex：`226964223a3130302c`（100）/`226964223a3130312c`（101）/`226964223a3130322c`（102）在请求与其响应行各出现一次且同值配对；**id 起点非 1**（spec §III"任意起点"）；响应与请求按 id 配对而非 TCP 位置（响应行的 method 缺席、result 在场——请求/响应形态 distinct）。
14. **`ethmining_extranonce_max3`**（15）：事件 = subscribe(**extranonce a2eea0** 3B)→authorize→set_difficulty→notify(jobA)→submit(**cfae7df760** 5B)。帧 5 = 119B 订阅响应（extranonce 段 `2261326565613022`）；帧 10 = 76B submit 行（frames 断言 minernonce 段 hex `226366616537646637363022` = `"cfae7df760"`，5B nonce）；**互补断言**：3B extranonce + 5B minernonce = 全 nonce 8B（spec §IV verbatim 组合 `a2eea0cfae7df760`）。
15. **`ethmining_hex_prefix`**（15）：`hex_prefix="0x"` 变体。事件 = subscribe→authorize→set_difficulty→notify→submit。断言订阅响应 extranonce 段 `22307830386322`（`"0x080c"`）、notify 行 job 段 `223078626630343838616122`（`"0xbf0488aa"`）、seedhash/headerhash/minernonce 段均带 `3078`（`0x`）前缀；**会话内前缀统一**（全部 hex 数据字段带前缀，无混用）；行长度按 §3.11 公式 +每字段 2 字节预算（subscribe 响应 121B、notify 205B、submit 82B）。
16. **`ethmining_long_username`**（15）：事件 = subscribe→authorize(**长用户名**)→set_difficulty→notify→submit(**同一长用户名**)。帧 6 = 123B authorize 行（用户名段 = `00112233445566778899aabbccddeeff00112233.rig-north-01-cabinet3-slot7` 的 ASCII hex，68 字符）；帧 10 = 142B submit 行（用户名段与帧 6 同值——`same_as_packet`/fixture 钉死）；行长按 §3.11 公式核验：authorize = `53+len(id)+len(user)+len(pass)` = 53+1+68+1 = 123、submit = `53+len(id)+len(user)+8+12` = 142。
17. **`ethmining_line_packing`**（12）：事件 = subscribe→authorize→[set_difficulty+notify **合并一段**]。本例为**设计 §3.1 pack 条款的 pack 开启形态**：相邻同方向行合并为单一 TCP 段、方向交替处（请求/响应边界）不合并——前 4 行（两对请求/响应）方向逐行交替故各自成段，仅同方向相邻的 set_difficulty+notify 粘连。断言：帧 8 `tcp.payload` 长度 **259B**、恰含 **2 个 `0a`**（行界）、前缀 = set_difficulty 行首 hex、段内 `3a5b302e355d7d0a`（set_difficulty 行尾 `[0.5]}\n`）之后紧跟 `7b226964223a6e75`（notify 行首）；**逐段 `tcp.len` 序列断言 90/117/66/36/259**（与设计 §3.11 公式逐值一致：60+199=259）；帧数：3 握手 + 5 数据段（4 单行段 + 1 粘行段）+ 4 挥手 = 12——**段边界 ≠ 行边界双向断言**（一段含两行，且无行被段界切坏）。
18. **`ethmining_mss_large_jobid`**（14）：事件 = subscribe→authorize→set_difficulty→notify(**job_id = `a3`×750，1500 hex 字符**)。notify 行 = `58+1500+64+64+5` = 1691B（§3.11 公式常量已含 LF），默认 MSS 1460 不压，跨 **2 段**（1460+231）；帧 9（首段）offset 54 起前缀 = notify 行首 40B hex（`7b226964223a6e756c6c2c…22706172`）；帧 10（末段）后缀 = `373166366363222c66616c73655d7d0a`；**按 `tcp.stream` 重组后断言完整行 1691B**、`tcp.len` 两段和 = 1691、分段边界不切坏 job_id hex 串（重组流中行首 `{` 后第 48 字节起为 1500 个 hex 字符连续体）；packet_count = 3+7+4 = 14。
19. **`ethmining_ipv6`**（9）：IPv6 独立 fixture（`2001:db8::73 → 2001:db8::100:73`，显式给出）。断言 `ipv6.nxt=6`、行首 offset **74**、subscribe 请求/响应行 hex 与用例 1 完全一致（同一逻辑行，仅外层 IP 头不同）；不得出现 `ip.version=4`。
20. **`ethmining_multi_session`**（30 = 15+15）：会话 1（`src_port=4073`，test/080c/0.5/jobA）与会话 2（`src_port=4074`，test2/**1f0a**/**2.0**/jobB/订阅标识 distinct）各为完整挖矿事务链（subscribe→authorize→set_difficulty→notify→submit→响应）。断言 `tcp.stream` 两值 distinct、**第二会话握手起点由多会话展开规则派生**（= 前一会话总包数 + 1，§3.4，不硬编码具体包号）、两会话 extranonce 段 hex distinct（`223038306322` vs `223166306122`）、用户名段 distinct（`227465737422` vs `22746573743222`）、各自响应 id 与本会话请求配对（会话间状态不串用）；**同值 id 跨会话各自配对**：两会话 subscribe 请求行 id 段 hex 相同（`226964223a312c` = `"id":1,`）而 `tcp.stream` distinct——同值 id 在各自会话内与本会话响应配对，互不消费（设计 §5）。
21. **`ethmining_mining_lifecycle`**（18）：单 `tcp.stream` 11 行业务序列：subscribe→订阅响应→authorize→授权响应→set_difficulty(0.5)→notify(jobA)→submit(id3,jobA,6B)→响应(id3,true)→notify(jobB)→submit(id4,jobB,**6B `68765fccd712`**，fixture 钉死)→响应(id4,true)。**逐段 `tcp.len` 序列断言（11 个数据段）：90/117/66/36/60/199/78/36/199/78/36**（与设计 §3.11 公式逐值一致——两笔 submit 均为 6B minernonce ⇒ `53+1+4+8+12` = 78B，与 §3 基线表 submit 78B 行同值）。断言行类型与方法名 ASCII hex 按此顺序出现（`6d696e696e672e737562736372696265`→`6d696e696e672e617574686f72697a65`→`6d696e696e672e7365745f646966666963756c7479`→`6d696e696e672e6e6f74696679`→`6d696e696e672e7375626d6974`→…→第二次 notify/submit）；第二次 submit 的 job 段 `22626630343838616222` 与第二次 notify 同值、minernonce 6B 与会话 extranonce 2B 互补（**job 轮换 + 互补双断言**）；无乱序（声明式按序回放）。

22. **`ethmining_custom_port`**（9）：事件 = subscribe 单事件（同用例 1），显式声明 `src_port=4073`/`dst_port=**3353**`（设计 §2）。订阅请求/响应行 hex 与用例 1 **完全一致**（端口不进 stratum 行内容，仅 TCP 头端口字段不同）；断言 `tcp.dstport=3353`（上行全程）、`tcp.srcport=3353`（下行响应端口互换）、帧 4/5 行 hex 与 `tcp.len` 90/117 同用例 1；**无 DecodeAs 依赖**——本协议无 dissector、断言全走 `tcp.payload`/frames（§1 实测基线），端口变化不改变任何断言通道（与 bacnet #46 的 `bvlc` DecodeAs 口径形不同因：那里有 dissector 依赖端口自动解码，这里无 dissector 可言）；planner 不得静默改写端口（未显式声明的非 4444 端口拒绝——负例 31 校验）。

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload`（数据帧 `tcp.payload` nonzero）+ 行首/方法名 frames 断言；行 hex 均可由设计 §3.11 公式 + fixture 常量精确预算（本文已给出全部锚定样本）；动态值只用存在与关联断言。合法协议事件（submit 拒绝、authorize 拒绝、难度缺省/变更、extranonce 轮换、0x 方言）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `ethmining_neg_json` | subscribe 行截断（`{"id":1,"method":"mining.subs`）、字符串未闭合、或某行为 JSON 数组/标量（非对象） | `json`、`decode`、`line` |
| `ethmining_neg_framing` | 末行无 LF 裸结束、行尾 `0d0a`（CRLF）、行前置 4 字节长度前缀（如 `005a` + 行）取代换行定界 | `newline`、`framing`、`line` |
| `ethmining_neg_method` | 方法名 `eth_getWork`（GetWork 混入，未知 method）、矿机事件发 `mining.notify`（方向违例）、矿池事件发 `mining.submit` | `method`、`unknown`、`direction` |
| `ethmining_neg_params` | subscribe params 单元素（缺协议串）、authorize 单元素、notify 3 元素（缺 clean_jobs）、submit 2 元素（缺 minernonce）、set_difficulty params `["0.5"]`（字符串）、clean_jobs=1（非布尔）、set_extranonce 2 元素 `["080c",4]`（比特币方言） | `params`、`field`、`type` |
| `ethmining_neg_hex` | seed_hash 62 hex（非 64）、job_id 含 `g`（非 hex 字符）、extranonce 8 hex（>3B 上界）、extranonce 2B 时 minernonce 5B（互补违例）、minernonce 11 hex（奇数）、订阅响应带 `0x` 而 notify 行不带（前缀混用） | `hex`、`length`、`extranonce`、`prefix` |
| `ethmining_neg_state` | 首条应用消息非 subscribe（如 authorize/mining.notify/GetWork `eth_getWork` 混入——GetWork 同时命中 `ethmining_neg_method` 的 unknown 锚）、未 authorize 先 submit、close 事件后追加 submit | `state`、`sequence`、`subscribe` |
| `ethmining_neg_id_correlation` | submit 响应 id=9 ≠ 请求 id=3、notify 行携带 `"id":1`（通知伪 id）、subscribe 与 authorize 同 id=1（会话内重复） | `id`、`match`、`correlation` |
| `ethmining_neg_job_correlation` | submit 的 job_id=`deadbeef` 不来自本会话任何 notify、submit 用户名 `other` ≠ 已授权 `test` | `job`、`worker`、`correlation` |
| `ethmining_neg_carrier` | 层链 `[{"ethmining":{}}]` 直连（缺 tcp）、UDP 载体、`dst_port` 与载体声明矛盾、IPv6 层链配 IPv4 地址（混合地址族——框架 IP 层校验承载，C2） | `carrier`、`tcp`、`port`、`ip`、`version` |
| `ethmining_neg_error_propagation` | validator 已知 hex/状态错误被吞、任务报 completed/0 packet 假成功 | `error`、`propagat`、`task` |

锚词候选集说明：负例 `ethmining_neg_error_propagation` 的三个锚词（`error`/`propagat`/`task`）为**三选一候选集**，非并列断言——实现期按实际错误信息钉死其一后，同步更新本文表与设计 §7 表两处。

**负例原子性（C4，全表适用）**：上表各行故障输入为**互斥候选集**——每个负例 ID 实现期选定其一钉死注入并同步本文表/设计 §7 表两处；**单次执行不得混注两个及以上故障**（锚词命中不可归因）；如需全量覆盖按 v1.3 §7 原子原则拆子 ID（如 `ethmining_neg_hex` 可拆 `_seedlen`/`_nonhex`/`_exceed3b`/`_complement`/`_odd`/`_prefix`）。

合法协议事件不进负例（防误报）：submit 拒绝（正例 12）、authorize 拒绝（正例 4）、难度缺省线序（正例 8）、难度变更（正例 9）、extranonce 轮换（正例 10）、extranonce.subscribe 不支持响应与矿池忽略（设计 §4 声明②③）、0x 前缀统一变体（正例 15）、大 job_id（正例 18）。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–12、21、22（正）；23–32（负） | 7 类消息 + 1 扩展每类正例（subscribe/authorize×2 态/extranonce.subscribe/set_difficulty×3 时序/notify×2 布尔/set_extranonce/submit×2 态）+ 多事务全链 + 非默认端口（22）；负例 10 类锚词逐类与设计 §7 对应；协议版本不支持的矿池错误回包等自由裁量路径为设计 §4 声明不设例 |
| 性能 | 7、17、18、20 | 最小通知行边界（60B，tcp.len；全族最小行 36B 响应由 3/11 承载）、多行粘连单段（259B 两行）、大 job_id 行 1691B 跨 MSS 2 段重组、多会话展开（用例 20，v2.0.2 C5 措辞统一）；行长无协议上界（设计 §3.11 公式约束）；发包速率由框架既有配置承载（v1.3 §10 口径） |
| 数据场景 | 5、6、7、9、10、13、14、15、16；负 26、27 | difficulty 值域（0.5/5000012.0/缺省兜底）、extranonce 2B/3B 带（≤3B 上界，超界负例）、minernonce 互补 6B/5B（违例负例）、job_id 任意长度（8 hex/1500 hex）、clean_jobs 二值、id 任意起点、0x 前缀统一/混用负例、hex 字符集/奇偶（负例） |
| 地址与流 | 1（v4 单流基线）、19（v6）、20（多会话双四元组）、22（非默认端口 3353） | v4+v6 必覆盖 + 非默认端口显式声明合法通道（22，v2.0.2 C2）；流关联与多流显式不适用（设计 §4 声明：矿机-矿池单 TCP 行式长连接，无副连接） |
| 业务 | 1/2/3（接入）、4（鉴权拒绝）、5/6/7/8/9（收任务）、11/12（提交）、10（轮换）、21（完整生命周期）、20（多矿机） | 现网挖矿日常场景优先（接入-收任务-提交链，spec §IV 场景即此链路） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ethmining.json` 通过；当前数组恰含 1 条 `ethmining_neg_unregistered`：`proto=ethmining`、层链 `[{"tcp":{}},{"ethmining":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`（注册时把占位端口 8545 改为 4444、notes 旧计数同步修正，见 §1）。
2. 实现注册 `ethmining` 层后：移除占位，按 §2 顺序补入 32 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `stratum.*`/`json.*`/`ethmining.*` 字段**（本机无本协议 dissector；JSON dissector 裸 TCP 不解析且不可 decode-as，实测确认）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields/frames。
5. 跨会话/跨段断言用 `tcp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 若实现期实证现网矿池方言（`"jsonrpc":"2.0"` 成员、其他错误码文案、非 4444 端口约定）与本版假设（设计 §1④/§3.5）不符，设计 §3 与本文 §3/§4 对应断言同步校准，并在两文档修订记录登记。
7. **pcap/NIC 双输出（C1）**：两输出路径共用本契约（同一 cases JSON、同一 tshark 字段/frames 断言）；NIC 路径经 tcpdump 捕获、`nic_capture` 为用例级开关，断言通道不变（L2 无 VLAN 前提下 offset 54/74 与 `tcp.payload` 全行提取稳定），不设仅单路径可用的断言。
8. **负例原子性（C4）**：§5 表各行故障输入为互斥候选集，每个负例 ID 实现期选定其一钉死注入并同步两文档；单次执行不得混注；全量覆盖按 v1.3 §7 拆子 ID。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `ethmining.json` 保持同一 32 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
ethmining_subscribe_ipv4
ethmining_extranonce_subscribe
ethmining_authorize
ethmining_authorize_reject
ethmining_notify_job
ethmining_notify_clean_jobs
ethmining_set_difficulty
ethmining_set_difficulty_default
ethmining_set_difficulty_update
ethmining_set_extranonce
ethmining_submit_accept
ethmining_submit_reject
ethmining_id_correlation
ethmining_extranonce_max3
ethmining_hex_prefix
ethmining_long_username
ethmining_line_packing
ethmining_mss_large_jobid
ethmining_ipv6
ethmining_multi_session
ethmining_mining_lifecycle
ethmining_custom_port
ethmining_neg_json
ethmining_neg_framing
ethmining_neg_method
ethmining_neg_params
ethmining_neg_hex
ethmining_neg_state
ethmining_neg_id_correlation
ethmining_neg_job_correlation
ethmining_neg_carrier
ethmining_neg_error_propagation
```

## 9. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负，基于已废弃的错误协议定位：节点侧 legacy JSON-RPC/eth_getWork/HTTP 8545）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。协议定位纠正为 ethash stratum（EthereumStratum/1.0.0），规范基线 NiceHash spec R2 + extranonce subscribe extension；用例从 20 条重排为 31 条（21 正 + 10 负）——每消息类型、每响应态、每时序变体、每长度边界（extranonce 2B/3B、minernonce 互补、最小行 60B、大 job_id 1691B 跨 MSS）、每关联规则（id 配对/job 来源/用户名一致）、每错误分支各一例；索引表五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 实测固化"无本协议 dissector、JSON dissector 裸 TCP 不解析不可 decode-as、断言走 `tcp.payload` 全行 hex + offset 54/74 frames 双通道"基线，并按 spec 逻辑构造 pcap 实证（subscribe/authorize/set_difficulty/notify/submit 全行逐字节提取吻合，行尾 `0a`）；fixture 常量全部 spec verbatim（订阅标识/extranonce/job/seedhash/headerhash/minernonce/difficulty/错误三元组）；新增 §3 核心行字节基线表、§6 五层映射、§8 三方一致性表。状态：**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 23 项问题清单修复（9 MAJOR + 14 MINOR，T16 审查判定无缺陷不修），31 ID 与顺序不变（T02/T15 走设计 §4 声明，不新增用例）。关键项：用例 4 补量化断言（数据帧恰 4 段、`tcp.len` 序列 90/117/66/62、错误三元组全段 hex、挥手前无额外业务行）；用例 8 补段序列 90/117/66/36/199；用例 10 补 frames 顺序断言（extranonce.subscribe 先于 authorize）；用例 14 补 submit minernonce 段 hex；用例 17 引用设计 §3.1 pack 条款并补逐段 `tcp.len` 90/117/66/36/259；用例 20 删除"第二会话握手包号 = 16"硬编码（改由多会话展开起点规则派生）并补同值 id 跨会话各自配对断言；用例 21 补 11 段 `tcp.len` 序列 90/117/66/36/60/199/78/36/199/78/36（清单原值末笔 submit 76 为笔误，按 §3.11 公式两笔 submit 均 6B minernonce ⇒ 78B 修正）；§5 负例 26 锚词补 `prefix`、负例 27 首分支泛化（authorize/mining.notify/GetWork 混入）、负例 31 锚词注明三选一候选集；§1 包数约定补 pack 引用。

- v2.0.2（2026-09-01，v1.3 行为面全枚举重审修复轮）：review-ethmining 重审 6 confirmed（4 MAJOR + 2 MINOR）逐项修复，31 → **32 例（22 正 + 10 负）**、负例编号 22–31 → 23–32（ID 与故障语义不变）。**C1** §1 补输出契约段（pcap/NIC 双输出共用同一 cases JSON 与断言集，`nic_capture` 用例级开关）+ §7.7 验收项；**C2** 新增用例 22 `ethmining_custom_port`（3353，行字节与用例 1 完全一致，无 DecodeAs 依赖——本机无 dissector，断言通道与端口无关）+ §3 fixture 常量 + §5 负例 31 `ethmining_neg_carrier` 补混合地址族分支（锚 `ip`/`version`，框架 IP 层校验承载）+ §6 三行映射更新；**C3** §1 补保活/重试/RST 口径段（无 PING 类消息不设例；RST 待实现边界；正例恒 FIN）；**C4** §5 表尾补负例原子性注（互斥候选集、单次单一注入、拆子 ID 示例）+ §7.8；**C5** §6 性能行"多会话并发"改"多会话展开"（设计 §5 同步修正并发措辞）；**C6** 状态行与 §1 原子原则引用 v1.1 → v1.3（历史修订条目保留 v1.1 原口径）。
