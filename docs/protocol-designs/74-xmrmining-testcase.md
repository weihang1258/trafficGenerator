# XMRMining（门罗币挖矿 stratum 协议，Monero / RandomX 矿池通信）测试用例契约

> 版本：v2.0.2（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/74-xmrmining-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/xmrmining.json`（proto key：`xmrmining`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）双输出断言，不宣称当前测试套件可运行。按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 docs-xmrmining：7 confirmed + 2 note 逐项修复，待独立复验关闭），本版 v2.0.2 为复验修复轮产物：33 → 63（v2.0.1）→ **64 例（25 正 + 39 负）**；v1.1 流程既有重写（v2.0.0）记录见 §9。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史；旧稿 14+6 用例基于未钉死权威规范的混合 Stratum-like 形态，全部重排为 33 条 23 正 + 10 负）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **64 个唯一语义 ID：25 个正例 + 39 个负例**（v2.0.1 新增正例 24/25，负例按 C-04 逐故障输入原子拆分 10 → 38、编号 24–33 → 26–63，ID 全新；v2.0.2 复验轮 V-1 补负例 55 `result_id_missing`，原 55–63 顺移 56–64）。派生规则：设计 §3 每个编码条款（每消息类型、每响应态、每形态变体、blob/target/seed_hash/nonce 长度边界）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 xmrig STRATUM.md / XMRig 源码 / MoneroOcean 现网形态）声明范围。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）。

当前 JSON 只保留一个 `xmrmining_neg_unregistered` 注册前置占位：`proto=xmrmining`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 64 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 XMRMining 行为通过。注册后移除占位，再按本文 §2 顺序补入 25 个正例与 39 个负例。

**输出契约（pcap/NIC 双输出，C-06）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 fields/frames 断言（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames），NIC 路径仅经 tcpdump 捕获（`nic_capture` 用例级开关），L2 无 VLAN 前提下偏移与载荷提取稳定，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet/73-ethmining 同形）；不设仅单路径可用的断言。

**保活/RST 口径（设计 §4 声明⑤⑥，N-02）**：无应用层 PING/重试消息（keepalived 是业务方法，长连接活性由 job 周期承载），不设 keepalive 探测例亦不进负例；RST/异常中断不适用——所有会话以 FIN 挥手统一终止，生成器不构造 RST（框架 tcp 层能力，本协议层零断言零 ID），本版正例恒 `terminates=true`。**占位端口 18081 与主 profile 一致**（旧稿同值，注册时保持一致）。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 构造 pcap 实证，非臆造）**：本机**没有 Monero/XMR stratum 专用 dissector**——`tshark -G protocols` 无 `xmr`/`monero` 协议；`tshark -G fields` 无任何 `xmr.*`/`monero.*` 字段（实测 grep 为空）。可用字段（`-G fields` 实测存在）：`tcp.payload`（FT_BYTES，TCP 载荷原始字节——**即完整 stratum 行含行尾 `0a`**，构造 pcap 实证精确提取）、`tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.syn/ack/fin/push`、`ip.version`、`ipv6.nxt`、`frame.number`、`frame.len`。JSON 辅助字段（`-d tcp.port==18081,json` 时可用，`-G fields` 实测存在）：`json.key`、`json.value.string`、`json.value.number`、`json.object`——用于方法名/字段名存在性辅助断言；**主断言走 `tcp.payload` 全行 hex + offset 54/74 frames**（构造 pcap 实证 `json.value.string` 可提取 `mining.notify`/`bf0488aa` 等值，但多行/长行/粘连场景 JSON dissector 断字段不稳，故字段值断言以 `tcp.payload` 子串为准）。XMR 内容断言双通道：① `tcp.payload` 全行 hex 值断言（fields）；② raw frame（原始帧）行首字节起点（IPv4 offset 54 / IPv6 offset 74）的 `frames` `offset/hex` 断言。**TCP 分段边界不是 stratum 行边界**：跨段行按 `tcp.stream` 重组后再断言完整行。

**动态字段禁止硬编码**：会话 id/job_id/blob/target/seed_hash/nonce/result 为生成期值或 fixture 声明值时，用 `same_as_packet`/`distinct_values`/`nonzero` 或 fixture 钉死值断言；本版 fixture 把全部业务值钉死为常量（见 §3 fixture 常量），行字节按设计 §3.8 公式可精确预算（构造 pcap 已实证同构样本）。`submit` 的 `params.id`（会话 id）与 `params.job_id` 必须与同会话 login 响应 `result.id`、已收 job 的 `job_id` 关联（`same_as_packet`/fixture 钉死）。

**包数约定**（设计 §9 完成定义；单行不跨段时）：会话 = 3（TCP 握手）+ N（承载 stratum 行的 TCP 段数，通常每行 1 段）+ 4（双向 FIN 挥手）。login 事件含 login 请求 + 登录响应两帧；submit/keepalived/getjob 各含请求+响应两帧；job 通知单帧无应答。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `xmrmining_login_job_ipv4` | 正 | §3.3：login 请求/响应全字段（会话 id+现代 job+status OK），IPv4 单流基线 | 9 |
| 2 | `xmrmining_login_reject` | 正 | §3.3：login 错误响应 + 连接关闭 | 9 |
| 3 | `xmrmining_login_extensions` | 正 | §3.3：login 响应带 extensions | 9 |
| 4 | `xmrmining_login_rigid` | 正 | §3.3：login 带可选 rigid | 9 |
| 5 | `xmrmining_job_notify` | 正 | §3.4：job 通知（省略 id）+ 现代 job 全字段 | 10 |
| 6 | `xmrmining_job_notify_legacy` | 正 | §3.4：legacy 三字段 job 形态 | 10 |
| 7 | `xmrmining_submit_accept` | 正 | §3.5：submit 请求/响应 OK（会话+job 关联） | 12 |
| 8 | `xmrmining_submit_reject` | 正 | §3.5：submit + error 对象，会话继续 | 12 |
| 9 | `xmrmining_submit_algo` | 正 | §3.5：submit 带可选 algo | 12 |
| 10 | `xmrmining_submit_sig` | 正 | §3.5：submit 带可选 sig/commitment | 12 |
| 11 | `xmrmining_keepalived` | 正 | §3.6：keepalived 请求/响应 status KEEPALIVED | 11 |
| 12 | `xmrmining_keepalive_alias` | 正 | §3.6：keepalive 别名 method | 11 |
| 13 | `xmrmining_getjob` | 正 | §3.7：getjob 请求/响应 result=job 对象 | 11 |
| 14 | `xmrmining_id_correlation` | 正 | §3.1/§5：多事务 id 按值配对 | 14 |
| 15 | `xmrmining_blob_nonce_offset` | 正 | §3.9：blob nonce 偏移 39/4B + submit 关联 | 12 |
| 16 | `xmrmining_target_length` | 正 | §3.9：target 4/8 字节两态 | 12 |
| 17 | `xmrmining_nonce_boundary` | 正 | §3.9：nonce 0/满值边界 | 14 |
| 18 | `xmrmining_line_packing` | 正 | §2/§8：job+submit 多行粘连单段 | 11 |
| 19 | `xmrmining_mss_large_jobid` | 正 | §3.8/§8：job_id 1500 字符跨 MSS 2 段 | 11 |
| 20 | `xmrmining_blob_max` | 正 | §3.9/§8：blob 407B 合法上界 | 10 |
| 21 | `xmrmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture | 9 |
| 22 | `xmrmining_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开 | 24 |
| 23 | `xmrmining_lifecycle` | 正 | §4⑧/§5：单会话多事务全链 | 17 |
| 24 | `xmrmining_port_nondefault` | 正 | §2/§8：非默认端口 3333 显式声明合法通道（行字节与用例 1 一致） | 9 |
| 25 | `xmrmining_concurrent_sessions` | 正 | §4⑦/§5：双矿机并发会话交错回放（互不串用，与 22 分立） | 24 |
| 26 | `xmrmining_neg_json_truncated` | 负 | §7：行内容截断 | — |
| 27 | `xmrmining_neg_json_unclosed` | 负 | §7：字符串未闭合 | — |
| 28 | `xmrmining_neg_json_notobject` | 负 | §7：某行为 JSON 数组/标量 | — |
| 29 | `xmrmining_neg_framing_no_lf` | 负 | §7：末行无 LF 裸结束 | — |
| 30 | `xmrmining_neg_framing_crlf` | 负 | §7：行尾 `0d0a` | — |
| 31 | `xmrmining_neg_framing_length_prefix` | 负 | §7：行前置 4 字节长度前缀取代换行定界 | — |
| 32 | `xmrmining_neg_method_unknown` | 负 | §7：未知 method | — |
| 33 | `xmrmining_neg_method_direction` | 负 | §7：矿机事件发 `job` 通知 | — |
| 34 | `xmrmining_neg_method_btc_array` | 负 | §7：`mining.subscribe` 数组 params 混入 | — |
| 35 | `xmrmining_neg_params_login_missing` | 负 | §7：login 缺 `login` 字段 | — |
| 36 | `xmrmining_neg_params_login_type` | 负 | §7：login `login` 非字符串 | — |
| 37 | `xmrmining_neg_params_submit_missing` | 负 | §7：submit 缺 `nonce` 字段 | — |
| 38 | `xmrmining_neg_params_submit_type` | 负 | §7：submit `job_id` 非字符串 | — |
| 39 | `xmrmining_neg_params_getjob_missing` | 负 | §7：getjob 缺 `id` 字段 | — |
| 40 | `xmrmining_neg_params_keepalived_missing` | 负 | §7：keepalived 缺 `id` 字段 | — |
| 41 | `xmrmining_neg_hex_blob_odd` | 负 | §7：blob 奇数长度 hex | — |
| 42 | `xmrmining_neg_hex_blob_nonhex` | 负 | §7：blob 含非法 hex 字符 | — |
| 43 | `xmrmining_neg_hex_blob_short` | 负 | §7：blob 解码 <43B | — |
| 44 | `xmrmining_neg_hex_blob_overflow` | 负 | §7：blob 解码 ≥408B | — |
| 45 | `xmrmining_neg_hex_seed_hash` | 负 | §7：seed_hash 非 64 hex | — |
| 46 | `xmrmining_neg_hex_target` | 负 | §7：target 非 4/8 字节 | — |
| 47 | `xmrmining_neg_hex_nonce` | 负 | §7：nonce 非 8 hex | — |
| 48 | `xmrmining_neg_hex_result` | 负 | §7：submit result 非 64 hex | — |
| 49 | `xmrmining_neg_hex_prefix` | 负 | §7：hex 字段带 `0x` 前缀 | — |
| 50 | `xmrmining_neg_state_first_login` | 负 | §7：首条应用消息非 login | — |
| 51 | `xmrmining_neg_state_submit_before_login` | 负 | §7：未 login 成功先 submit | — |
| 52 | `xmrmining_neg_state_after_login_reject` | 负 | §7：login 失败后继续排业务事件 | — |
| 53 | `xmrmining_neg_state_after_close` | 负 | §7：会话关闭后继续排事件 | — |
| 54 | `xmrmining_neg_id_resp_mismatch` | 负 | §7：响应 id ≠ 请求 id | — |
| 55 | `xmrmining_neg_result_id_missing` | 负 | §7：login 响应缺 result.id | — |
| 56 | `xmrmining_neg_id_notify_fake` | 负 | §7：job 通知携带伪 `id` | — |
| 57 | `xmrmining_neg_id_reuse` | 负 | §7：同会话未完成事务复用同一 id | — |
| 58 | `xmrmining_neg_job_unknown` | 负 | §7：submit 的 job_id 不来自本会话已收 job | — |
| 59 | `xmrmining_neg_job_session_mismatch` | 负 | §7：submit/getjob/keepalived 的 params.id ≠ 本会话 session id | — |
| 60 | `xmrmining_neg_carrier_missing_tcp` | 负 | §7：层链缺 tcp | — |
| 61 | `xmrmining_neg_carrier_udp` | 负 | §7：UDP 载体声明 | — |
| 62 | `xmrmining_neg_carrier_port_conflict` | 负 | §7：端口与载体声明矛盾 | — |
| 63 | `xmrmining_neg_prop_swallowed` | 负 | §7：validator 已知 hex/状态错误被吞 | — |
| 64 | `xmrmining_neg_prop_fake_success` | 负 | §7：任务报 completed/0 packet 假成功 | — |
| — | `xmrmining_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, xmrmining]`，无 VLAN/IP options/TCP options 时 **stratum 行首字节（`{`，`0x7b`）起点为 IPv4 offset 54、IPv6 offset 74**（构造 pcap 实证：`tcp.payload` 即完整行含行尾 `0a`，帧偏移 54 处逐字节吻合）。断言分层：

1. **载体与方向（fields 权威断言）**：矿机帧 `tcp.srcport=<会话源端口>`、`tcp.dstport=18081`；矿池帧（login 响应/job 通知/submit 响应/keepalived 响应/getjob 响应）端口互换。`ip.version=4`（或 IPv6 fixture 断言 `ipv6.nxt=6` 且不得出现 v4 地址）、`tcp.len` = 该段承载的行字节数（单行不跨段时）。
2. **stratum 行（tcp.payload + frames 双通道）**：单行不跨段时 `tcp.payload` 值 = 完整行 hex（含行尾 `0a`）；frames 断言在 offset 54/74 处校验关键前缀——方法名字节串（`"login"`/`"job"`/`"submit"`/`"keepalived"`/`"getjob"` 的 ASCII hex）、字段名（`"jsonrpc"`/`"params"`/`"job_id"`/`"blob"`/`"target"`/`"seed_hash"`/`"nonce"`/`"result"`/`"status"`/`"session"` 等）。行尾必须为 `0a`。
3. **跨段重组**：大行（≥MSS）按 `tcp.stream` 重组后断言完整行（重组流起点 = 首段 offset 54）；**任何单段不构成完整行时不得按段断言整行 hex**。
4. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。**并发回放（v2.0.1 C-07）**：`concurrent: true` 为双矿机交错回放模式（正例 25）——与按序整块展开（正例 22）分立；单会话内事件序仍受设计 §5 状态机约束。

**fixture 常量**（行字节可精确预算；各用例只列差异项）：地址 `192.0.2.74 → 198.51.100.74`（IPv6 `2001:db8::74 → 2001:db8::100:74`）、`src_port=4074`、`dst_port=18081`；**非默认端口用例 24 fixture**：`dst_port=3333`（设计 §2，行字节与用例 1 完全一致——端口不进 stratum 行内容，仅 TCP 端口字段不同）；login 钱包（95 字符，spec verbatim）`48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD`、pass=`x`、agent=`XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0`（51 字符）、rigid=`rig-01`、会话 id=`1be0b7b6-b15a-47be-a17d-46b2911cf7d0`（36 字符）、blob1（76B，spec verbatim）`070780e6b9d60586ba419a0c224e3c6c3e134cc45c4fa04d8ee2d91c2595463c57eef0a4f0796c000000002fcc4d62fa6c77e76c30017c768be5c61d83ec9d3a085d524ba8053ecc3224660d`、blob2（76B，spec verbatim）`0707d5efb9d6057e95a35f868231780b3a8649c4e57f3c77eaf437329243eef0b9f4b6987d05b900000000cae7754cb85a0ad8eebf3e0bf55f3ec5e754a1d6b05d46e5c358f907dbcbb72b01`、job_id1=`q7PLUPL25UV0z5Ij14IyMk8htXbj`（28 字符）、job_id2=`4BiGm3/RgGQzgkTI/xV0smdA+EGZ`（28 字符）、target=`b88d0600`、seed_hash=`c9aa8bd62b73d8cb5f956956e3d5cbcf8dd13e17e1c2a1fcfa88c4d26b9815db`（64 hex）、height=2652853/2652854、algo=`rx/0`、nonce=`d0030040`、nonce0=`00000000`、nonce_max=`ffffffff`、result（32B）`e1364b8782719d7683e2ccd3d8f724bc59dfa780a9e960e7c0e0046acdb40100`、sig（64B）`11`×64、commitment（32B）`22`×32、extensions=`["algo","keepalive"]`。**job 对象现代形态成员顺序**（mo-pool `buildStandardJobPayload`）：`blob,algo,height,seed_hash,job_id,target,id`。**响应成员顺序**：`id,jsonrpc,error,result`；**请求成员顺序**：`id,jsonrpc,method,params`；**通知成员顺序**：`jsonrpc,method,params`（无 id 成员）。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；行 hex 均按设计 §3.8 公式 + fixture 常量预算（构造 pcap 已实证同构样本）。每例均含 `has_handshake=true`、`terminates=true`、数据行 `has_payload=true`。方向断言：矿机→矿池 `tcp.srcport=4074`；矿池→矿机 `tcp.srcport=18081`。

1. **`xmrmining_login_job_ipv4`**（9）：事件 = login。矿机帧（帧 4，offset 54）hex 前缀 `7b226964223a312c226a736f6e727063223a22322e30222c226d6574686f64223a226c6f67696e22`（`{"id":1,"jsonrpc":"2.0","method":"login"`）+ params 前缀 `7b226c6f67696e223a22`（`{"login":"`）；`tcp.len=232`；行尾 `0a`。矿池帧（帧 5）hex 前缀 `7b226964223a312c226a736f6e727063223a22322e30222c226572726f72223a6e756c6c2c22726573756c74223a7b226964223a2231626530623762362d`（`{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"1be0b7b6-`）+ job 前缀 `7b22626c6f62223a22`（`{"blob":"`）+ status 子串 `22737461747573223a224f4b227d7d`（`"status":"OK"}}`）；`tcp.len=491`；**login 响应 `result.id`（1be0b7b6-…）为会话 id**。`ip.version=4` 全程；挥手完整。
2. **`xmrmining_login_reject`**（9）：事件 = login（配置 status=error、code=-1、message="Invalid payment address provided"）。矿机帧同用例 1（login 请求）；矿池帧 hex 恰为 `7b226964223a312c226a736f6e727063223a22322e30222c226572726f72223a7b22636f6465223a2d312c226d657373616765223a22496e76616c6964207061796d656e7420616464726573732070726f7669646564227d7d0a`（`{"id":1,"jsonrpc":"2.0","error":{"code":-1,"message":"Invalid payment address provided"}}`，`tcp.len=90`）；**login 错误后无任何业务行**（断言挥手前 `tcp.len>0` 的帧仅 login 请求/错误响应两帧）；连接随后关闭。
3. **`xmrmining_login_extensions`**（9）：事件 = login（配置 extensions=`["algo","keepalive"]`）。login 请求同用例 1；矿池响应 hex 含 `22657874656e73696f6e73223a5b22616c676f222c226b656570616c697665225d`（`"extensions":["algo","keepalive"]`）；`tcp.len=525`；status OK 同用例 1。
4. **`xmrmining_login_rigid`**（9）：事件 = login（配置 rigid=`rig-01`）。矿机帧 hex 含 `227269676964223a227269672d303122`（`"rigid":"rig-01"`）；`tcp.len=249`（login 公式 + 11+len(rigid)，v2.0.1 N-01 修正）；其余同用例 1。
5. **`xmrmining_job_notify`**（10）：事件 = login + job（job_id2/blob2/target/seed_hash/height=2652854/id=会话 id）。job 通知帧（矿池→矿机）hex 前缀 `7b226a736f6e727063223a22322e30222c226d6574686f64223a226a6f62222c22706172616d73223a`（`{"jsonrpc":"2.0","method":"job","params":`）+ `7b22626c6f62223a22`（`{"blob":"`）+ blob2 起始 hex + seed_hash 子串 `22736565645f68617368223a226339616138626436322d`；`tcp.len=420`；**通知省略顶层 `id` 成员**（顶层形态断言：行首 `7b226a736f6e727063223a`（`{"jsonrpc":`）且 `"method":"job"` 顶层无 `"id":` 成员——**`params.id` 为 job 对象成员不受限**，现代 job 整行恰含 `22696422` 一次（会话 id 回带处）；不得用"整行不含 22696422"断言——该旧断言与 fixture 自相矛盾，v2.0.1 C-02 废除）；`method` 值子串 `226a6f6222`（`"job"`）。
6. **`xmrmining_job_notify_legacy`**（10）：事件 = login + job（legacy 形态：仅 blob1/job_id1/target，profile `xmrmining_job_legacy_v1`）。job 通知帧 hex 恰含 `7b22626c6f62223a22` + blob1 + `226a6f625f6964223a227137504c55504c32355556307a35496a313449794d6b38687458626a222c22746172676574223a226238386430363030227d`（`{"job_id":"q7PLUPL25UV0z5Ij14IyMk8htXbj","target":"b88d0600"}` 结尾，无 algo/height/seed_hash/id 成员）；`tcp.len=266`。
7. **`xmrmining_submit_accept`**（12）：事件 = login + job（job_id2）+ submit（status OK）。submit 请求（矿机→矿池）hex 前缀 `7b226964223a322c226a736f6e727063223a22322e30222c226d6574686f64223a227375626d6974222c22706172616d73223a7b226964223a2231626530623762362d`（`{"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"1be0b7b6-`）+ job_id 子串 `226a6f625f6964223a22344269476d332f526751477a676b54492f785630736d64412b45475a22`（`"job_id":"4BiGm3/RgGQzgkTI/xV0smdA+EGZ"`）+ nonce 子串 `226e6f6e6365223a22643030333030343022`（`"nonce":"d0030040"`）+ result 子串 `22726573756c74223a22653133363462383738`；`tcp.len=233`。提交响应（矿池→矿机）hex 恰为 `7b226964223a322c226a736f6e727063223a22322e30222c226572726f72223a6e756c6c2c22726573756c74223a7b22737461747573223a224f4b227d7d0a`（`tcp.len=63`）；**submit 的 `params.id` 与 login 响应 `result.id` 同值、`job_id` 与已收 job 同值**（`same_as_packet`/fixture 钉死）。
8. **`xmrmining_submit_reject`**（12）：事件 = login + job + submit（配置 status=error、code=-1、message="Low difficulty share"）。submit 请求同用例 7；提交响应 hex 恰为 `7b226964223a322c226a736f6e727063223a22322e30222c226572726f72223a7b22636f6465223a2d312c226d657373616765223a224c6f7720646966666963756c7479207368617265227d7d0a`（`tcp.len=78`）；**拒绝后会话继续**（响应后仍有挥手，且后续可再排事件——本用例在响应后直接挥手）。
9. **`xmrmining_submit_algo`**（12）：事件 = login + job + submit（配置 algo=`rx/0`）。submit 请求 hex 含 `2c22616c676f223a2272782f30227d`（`,"algo":"rx/0"}` 结尾）；`tcp.len=247`；响应同用例 7。
10. **`xmrmining_submit_sig`**（12）：事件 = login + job + submit（配置 sig=`11`×64、commitment=`22`×32）。submit 请求 hex 含 `22736967223a223131313131313131`（`"sig":"11111111…`）与 `22636f6d6d69746d656e74223a223232323232323232`（`"commitment":"22222222…`）；`tcp.len=450`；响应同用例 7。
11. **`xmrmining_keepalived`**（11）：事件 = login + keepalived（status KEEPALIVED）。keepalived 请求 hex 恰为 `7b226964223a332c226a736f6e727063223a22322e30222c226d6574686f64223a226b656570616c69766564222c22706172616d73223a7b226964223a2231626530623762362d623135612d343762652d613137642d343662323931316366376430227d7d0a`（`tcp.len=102`；**params.id=会话 id**）；keepalived 响应 hex 恰为 `7b226964223a332c226a736f6e727063223a22322e30222c226572726f72223a6e756c6c2c22726573756c74223a7b22737461747573223a224b454550414c49564544227d7d0a`（`tcp.len=71`；**status 值为 KEEPALIVED 非 OK**）。
12. **`xmrmining_keepalive_alias`**（11）：事件 = login + keepalived（配置 `keepalive_alias: true`）。请求 method 子串 `226d6574686f64223a226b656570616c69766522`（`"method":"keepalive"`，无 `d`；`tcp.len=101`）；响应同用例 11（status KEEPALIVED）。
13. **`xmrmining_getjob`**（11）：事件 = login + getjob。getjob 请求 hex 恰为 `7b226964223a342c226a736f6e727063223a22322e30222c226d6574686f64223a226765746a6f62222c22706172616d73223a7b226964223a2231626530623762362d623135612d343762652d613137642d343662323931316366376430227d7d0a`（`tcp.len=98`）；getjob 响应 hex 前缀 `7b226964223a342c226a736f6e727063223a22322e30222c226572726f72223a6e756c6c2c22726573756c74223a`（`{"id":4,"jsonrpc":"2.0","error":null,"result":`）+ job 对象（现代形态，同用例 5）；`tcp.len=425`；**响应 result 直接为 job 对象**。
14. **`xmrmining_id_correlation`**（14）：事件 = login（id=1）+ job + submit（id=2）+ keepalived（id=3）。断言四响应/请求 id 序列：login 响应 id 子串 `226964223a312c`、submit 请求与响应 id 同值 `226964223a322c`、keepalived 请求与响应 id 同值 `226964223a332c`；**各请求 id 与对应响应按值配对（非 TCP 位置）**——submit 响应出现在 login 响应之后、keepalived 响应之前；job 通知整行无 id 成员。
15. **`xmrmining_blob_nonce_offset`**（12）：事件 = login + job（blob1）+ submit。job 通知帧断言 blob 内 **offset 39 起 8 hex = `00000000`**（blob1 hex 串第 78–85 字符）：现代 job 通知的 `"blob":"` 前缀为 50 字节（`{"jsonrpc":"2.0","method":"job","params":{"blob":"`），故 blob 起点为载荷偏移 50、nonce 字段为载荷偏移 128–135、**帧偏移 182（IPv4，frames offset/hex 断言）**；submit nonce 恰 8 hex（`d0030040`）且与最近 job 关联（`same_as_packet`/fixture 钉死）。
16. **`xmrmining_target_length`**（12）：事件 = login + job（target 8 字节 `b88d060000000000`）+ submit。job 通知帧 hex 含 `22746172676574223a2262383864303630303030303030303022`（`"target":"b88d060000000000"`，16 hex）；`tcp.len=428`；另一变体 target 4 字节 `b88d0600` 由用例 5/7 承载。
17. **`xmrmining_nonce_boundary`**（14）：事件 = login + job + submit（nonce=`00000000`）+ submit（nonce=`ffffffff`）。两 submit 请求分别含 `226e6f6e6365223a22303030303030303022` 与 `226e6f6e6365223a226666666666666622`；两响应均 status OK；`tcp.len=233` 两例相同。
18. **`xmrmining_line_packing`**（11 = 3 握手 + 4 载荷段 + 4 挥手；v2.0.1 C-03 修正）：事件 = login + job（job_id2）+ submit（配置 `pack: true` 合并）。job 通知 + submit 请求**同一 TCP 段**（653B 载荷、段内恰 2 个 `0a`）：断言该段 `tcp.payload` hex = job 通知行 hex + `0a` + submit 行 hex（首字节 `7b226a736f6e727063`）；login 响应单独一段；段边界 ≠ 行边界两个方向都断言。
19. **`xmrmining_mss_large_jobid`**（11 校准）：事件 = login + job（job_id=`J`×1500）。job 通知行 1892B > 默认 MSS 1460 → **跨 2 段（1460+432）**；首段 offset 54 起前缀 `7b226a736f6e727063223a22322e30222c226d6574686f64223a226a6f62222c22706172616d73223a7b22626c6f62223a22`；按 `tcp.stream` 重组后断言完整行 1892B、行尾 `0a`、**分段边界不切坏行内容也不产生伪行界**（行内无 `0a`）；packet_count = 3（握手）+ 2（login 请求/响应）+ 2（job 通知跨 2 段）+ 4（挥手）= 11（实现期校准）。
20. **`xmrmining_blob_max`**（10）：事件 = login + job（blob **407B 合法上界**：39B 前缀 + `00000000` + `ab`×364，v2.0.1 C-01 修正）。job 通知行 1082B（< MSS）单段；断言 blob hex 长度 = **814 hex（407B）**、nonce 字段 offset 39 为 `00000000`、行尾 `0a`；`tcp.len=1082`。**≥408B 由负例 44（`xmrmining_neg_hex_blob_overflow`）拒绝，407 满值正例 + 408 超界负例边界对闭合**（合法域 [43,407]，xmrig `setBlob` 对 size≥408 拒绝）。
21. **`xmrmining_ipv6`**（9）：IPv6 独立 fixture（`2001:db8::74 → 2001:db8::100:74`，显式给出）；断言 `ipv6.nxt=6`、行首字节 offset **74**、login 请求/响应字节与用例 1 完全一致（同一逻辑行，仅外层 IP 头不同）；不得出现 `ip.version=4`。
22. **`xmrmining_multi_session`**（24 = 12+12）：会话 1（`src_port=4074`，session id `1be0b7b6-…`，job_id1）+ 会话 2（`src_port=4075`，session id `2cf1c8c7-c26b-58cf-b28e-57c3a02d08e1`，job_id3 `zZyYxXwWvV4eRtY6yTpQ2LmNoPqRsTuV`）各含 login+job+submit；断言 `tcp.stream` 两值 distinct、**第二会话握手包号 = 13**（= 前会话 12 包 + 1，多会话展开）、两会话 session id 字符串 distinct、各自 submit 的 `params.id` 与各自 login 响应 `result.id` 关联（不跨会话消费）、会话间状态不串用。
23. **`xmrmining_lifecycle`**（17）：单 `tcp.stream` 业务行序列：login 请求(`7b226964223a312c…6c6f67696e`)→login 响应(`…737461747573223a224f4b`)→job 通知(`…6a6f6222`)→submit 请求(`…7375626d6974`)→submit 响应(`…224f4b22`)→job 通知(job_id2)→submit 请求(job_id2)→submit 响应→keepalived 请求(`…6b656570616c69766564`)→keepalived 响应(`…4b454550414c49564544`)；断言各帧首成员按此顺序出现、job_id 轮换（`same_as_packet`/distinct）、id 序列 1→2→3 递增、会话 id 恒定（fixture 钉死）。

24. **`xmrmining_port_nondefault`**（9）：事件 = login 单事件（同用例 1），显式声明 `src_port=4074`/`dst_port=**3333**`（设计 §2：主流 XMR stratum 接入端口，"公开资料 + 假设"标注）。login 请求/响应行 hex 与用例 1 **完全一致**（端口不进 stratum 行内容，仅 TCP 头端口字段不同）；断言 `tcp.dstport=3333`（上行全程）、`tcp.srcport=3333`（下行端口互换）、帧 4/5 行 hex 与 `tcp.len` 同用例 1；**无 DecodeAs 依赖**——本协议无专用 dissector、断言全走 `tcp.payload`/frames（§1 实测基线），端口变化不改变任何断言通道（与 bacnet #46 DecodeAs 口径形不同因）；planner 不得静默改写端口（未显式声明的非 18081 端口拒绝——负例 62 校验）。（v2.0.1 C-05）
25. **`xmrmining_concurrent_sessions`**（24 = 12+12）：`concurrent: true` 双矿机（A `src_port=4074` / B `src_port=4075`）交错回放各自 login→job→submit 链。断言两会话**交错**（帧序源端口交替出现，非整块串行）、`tcp.stream` 两值 distinct、各自 session id/job_id/id 序列互不串用（A 会话 submit `params.id` 只与 A 会话 login 响应 `result.id` 配对，不跨会话消费）、响应按 id 值配对——单会话内事件序仍受设计 §5 状态机约束，并发只作用于生成器级多连接交错（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）；与正例 22 多会话按序整块展开分立。（v2.0.1 C-07）

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload`（数据行 `tcp.payload` nonzero）+ 行首字节 frames 断言；行 hex 均可由设计 §3.8 公式 + fixture 常量精确预算（本文已给出全部锚定样本）；动态值只用存在与关联断言。合法协议事件（login 拒绝、submit 拒绝、job 通知省略 id、keepalive 别名、target 8B、nonce 0/满值）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。锚词与设计 §7 表一一对应、同序：

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**逐故障输入原子拆分（C-04）：一行一例，钉死该行注入的单一 `wire_fault`；主锚词为钉死的单一字面值**（不再是候选列表），与设计 §7 表一一对应（39 行同序，`wire_fault` 39 值三方同序：设计 §6 枚举/§7 表/本文 §5 表）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 26 | `xmrmining_neg_json_truncated` | `json_truncated` | 行内容截断（`{"id":1,"jsonrpc":"2.0","method":"login` 无闭合，缺对象尾部） | `json` |
| 27 | `xmrmining_neg_json_unclosed` | `json_unclosed` | 字符串未闭合（login 行 params 字符串缺引号） | `json` |
| 28 | `xmrmining_neg_json_notobject` | `json_notobject` | 某行为 JSON 数组/标量（非对象顶层） | `json` |
| 29 | `xmrmining_neg_framing_no_lf` | `framing_no_lf` | 末行无 LF 裸结束 | `newline` |
| 30 | `xmrmining_neg_framing_crlf` | `framing_crlf` | 行尾 `0d0a`（CRLF，spec 统一裸 LF） | `crlf` |
| 31 | `xmrmining_neg_framing_length_prefix` | `framing_length_prefix` | 行前置 4 字节长度前缀取代换行定界 | `framing` |
| 32 | `xmrmining_neg_method_unknown` | `method_unknown` | 未知 method（含 `block_template` 混入，§1 边界） | `method` |
| 33 | `xmrmining_neg_method_direction` | `method_direction` | 矿机事件发 `job` 通知（方向违例） | `direction` |
| 34 | `xmrmining_neg_method_btc_array` | `method_btc_array` | `mining.subscribe` 数组 params 混入（比特币 stratum 形态，§1 边界） | `params` |
| 35 | `xmrmining_neg_params_login_missing` | `params_login_missing` | login 缺 `login` 字段 | `login` |
| 36 | `xmrmining_neg_params_login_type` | `params_login_type` | login `login` 非字符串（如数字） | `params` |
| 37 | `xmrmining_neg_params_submit_missing` | `params_submit_missing` | submit 缺 `nonce` 字段 | `submit` |
| 38 | `xmrmining_neg_params_submit_type` | `params_submit_type` | submit `job_id` 非字符串 | `params` |
| 39 | `xmrmining_neg_params_getjob_missing` | `params_getjob_missing` | getjob 缺 `id` 字段 | `getjob` |
| 40 | `xmrmining_neg_params_keepalived_missing` | `params_keepalived_missing` | keepalived 缺 `id` 字段 | `keepalived` |
| 41 | `xmrmining_neg_hex_blob_odd` | `hex_blob_odd` | blob 奇数长度 hex | `blob` |
| 42 | `xmrmining_neg_hex_blob_nonhex` | `hex_blob_nonhex` | blob 含非法 hex 字符（如 `g`） | `blob` |
| 43 | `xmrmining_neg_hex_blob_short` | `hex_blob_short` | blob 解码 <43B（39+4 nonceOffset+nonceSize 下界） | `blob` |
| 44 | `xmrmining_neg_hex_blob_overflow` | `hex_blob_overflow` | blob 解码 ≥408B（超上界 407B） | `blob` |
| 45 | `xmrmining_neg_hex_seed_hash` | `hex_seed_hash` | seed_hash 非 64 hex | `seed_hash` |
| 46 | `xmrmining_neg_hex_target` | `hex_target` | target 非 4/8 字节 | `target` |
| 47 | `xmrmining_neg_hex_nonce` | `hex_nonce` | nonce 非 8 hex | `nonce` |
| 48 | `xmrmining_neg_hex_result` | `hex_result` | submit result 非 64 hex | `result` |
| 49 | `xmrmining_neg_hex_prefix` | `hex_prefix` | hex 字段带 `0x` 前缀（本协议无前缀，spec 全部无前缀） | `hex` |
| 50 | `xmrmining_neg_state_first_login` | `state_first_login` | 首条应用消息非 login（如直接 job 通知） | `login` |
| 51 | `xmrmining_neg_state_submit_before_login` | `state_submit_before_login` | 未 login 成功先 submit | `submit` |
| 52 | `xmrmining_neg_state_after_login_reject` | `state_after_login_reject` | login 失败后继续排业务事件 | `login` |
| 53 | `xmrmining_neg_state_after_close` | `state_after_close` | 会话关闭后继续排事件 | `state` |
| 54 | `xmrmining_neg_id_resp_mismatch` | `id_resp_mismatch` | 响应 id ≠ 请求 id（按值配对，不得按 TCP 位置） | `id` |
| 55 | `xmrmining_neg_result_id_missing` | `result_id_missing` | login 响应 `result` 对象缺 `id` 成员（xmrig-impl `parseLogin` code=1） | `result` |
| 56 | `xmrmining_neg_id_notify_fake` | `id_notify_fake` | job 通知携带伪 `id`（本协议省略 id 成员，伪 id 非法） | `id` |
| 57 | `xmrmining_neg_id_reuse` | `id_reuse` | 同会话未完成事务复用同一 id | `id` |
| 58 | `xmrmining_neg_job_unknown` | `job_unknown` | submit 的 job_id 不来自本会话已收 job | `job` |
| 59 | `xmrmining_neg_job_session_mismatch` | `job_session_mismatch` | submit/getjob/keepalived 的 params.id ≠ 本会话 session id | `session` |
| 60 | `xmrmining_neg_carrier_missing_tcp` | `carrier_missing_tcp` | 层链缺 tcp（`[{"xmrmining":{}}]` 直连） | `carrier` |
| 61 | `xmrmining_neg_carrier_udp` | `carrier_udp` | UDP 载体声明 | `carrier` |
| 62 | `xmrmining_neg_carrier_port_conflict` | `carrier_port_conflict` | 端口与载体声明矛盾 | `port` |
| 63 | `xmrmining_neg_prop_swallowed` | `prop_swallowed` | validator 已知 hex/状态错误被吞 | `propagat` |
| 64 | `xmrmining_neg_prop_fake_success` | `prop_fake_success` | 任务报 completed/0 packet 假成功 | `task` |

合法协议事件不进负例（防误报）：login 拒绝、submit 拒绝、job 通知省略 id、keepalive 别名、keepalived 请求省略 jsonrpc、submit 可选字段（algo/sig/commitment）、target 8B、nonce 0/满值。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–25（正）；26–64（负） | 5 类方法 + 变体每类正例（login 三变体+拒绝路径/job 现代+legacy/submit 四变体+两响应态/keepalived+别名/getjob）+ id 关联 + 多事务全链；负例 39 行 6 类（值域 15/线格式 9/状态机 4/关联 6/配置载体 3/错误传播 2）逐行与设计 §7 对应；block_template/daemon HTTP/比特币 stratum 为设计 §1 边界不设用例 |
| 性能 | 18、19、20、22、25 | 大 job_id 行跨 MSS 分段重组（19，2 段）、blob 407B 合法上界（20，v2.0.1 C-01）、多行粘连单段（18）、多会话展开（22）与并发交错（25）；发包速率由框架既有配置承载（v1.3 §10 口径） |
| 数据场景 | 5、6、15–17、20；负 41–49 | blob 值域（nonce 偏移 39/4B/上界 407B）、target 4/8B 两态、seed_hash 恒 64、nonce 0/满值、result 64 hex、job_id 任意长度（28 基线/1500 压力）、session id 36 字符 opaque、height 递增、algo 变体；非法值拒绝 |
| 地址与流 | 1（v4 单流基线）、21（v6）、22（多会话双四元组）、24（非默认端口 3333）、25（并发交错） | v4+v6 必覆盖 + 非默认端口显式声明合法通道（24，C-05）+ 并发会话（25，C-07 翻案）；流关联与多流显式不适用（设计 §4 声明：单 TCP 连接行式协议、无副连接概念——多流≠并发会话） |
| 业务 | 1/3/4（接入）、2（登录拒绝）、5/6（收任务）、7–10（share 提交）、11/12（保活）、13（主动拉任务）、23（完整生命周期）、24/25（多矿机接入形态） | XMR 现网日常场景优先（接入-收任务-提交-保活链） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/xmrmining.json` 通过；当前数组恰含 1 条 `xmrmining_neg_unregistered`：`proto=xmrmining`、层链 `[{"tcp":{}},{"xmrmining":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `xmrmining` 层后：移除占位，按 §2 顺序补入 64 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
7. **pcap/NIC 双输出（C-06）**：两输出路径共用本契约（同一 cases JSON、同一 tshark 字段/frames 断言）；NIC 路径经 tcpdump 捕获、`nic_capture` 为用例级开关，断言通道不变（L2 无 VLAN 前提下 offset 54/74 与 `tcp.payload` 全行提取稳定），不设仅单路径可用的断言。
8. **负例原子性（C-04）**：39 行负例每行恰注入一个故障；`wire_fault` 取值集合 = §5 表 39 值（三方同序：设计 §6 枚举/§7 表/本文 §5 表）；主锚词为单一钉死字面值，无候选列表。
9. **注册时 JSON notes 同步修正**：当前 `xmrmining.json` 占位 notes 为旧稿口径统计，实现注册时须同步改写为 63/25+38 并核对 packet_count，不得保留陈旧 notes。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`ip.version`/`ipv6.nxt`/`frame.*`/`json.*` 辅助），**不使用任何 `xmr.*`/`monero.*` 字段**（本机无专用 dissector，实测无输出）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 跨会话/跨段断言用 `tcp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 若实现期实证矿池 job 通知是否携带 `id:null`、getjob 响应形态、keepalived 请求 jsonrpc 成员与本版假设（设计 §3.4/§3.7/§3.6）不符，设计 §3 与本文 §4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `xmrmining.json` 保持同一 64 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
xmrmining_login_job_ipv4
xmrmining_login_reject
xmrmining_login_extensions
xmrmining_login_rigid
xmrmining_job_notify
xmrmining_job_notify_legacy
xmrmining_submit_accept
xmrmining_submit_reject
xmrmining_submit_algo
xmrmining_submit_sig
xmrmining_keepalived
xmrmining_keepalive_alias
xmrmining_getjob
xmrmining_id_correlation
xmrmining_blob_nonce_offset
xmrmining_target_length
xmrmining_nonce_boundary
xmrmining_line_packing
xmrmining_mss_large_jobid
xmrmining_blob_max
xmrmining_ipv6
xmrmining_multi_session
xmrmining_lifecycle
xmrmining_port_nondefault
xmrmining_concurrent_sessions
xmrmining_neg_json_truncated
xmrmining_neg_json_unclosed
xmrmining_neg_json_notobject
xmrmining_neg_framing_no_lf
xmrmining_neg_framing_crlf
xmrmining_neg_framing_length_prefix
xmrmining_neg_method_unknown
xmrmining_neg_method_direction
xmrmining_neg_method_btc_array
xmrmining_neg_params_login_missing
xmrmining_neg_params_login_type
xmrmining_neg_params_submit_missing
xmrmining_neg_params_submit_type
xmrmining_neg_params_getjob_missing
xmrmining_neg_params_keepalived_missing
xmrmining_neg_hex_blob_odd
xmrmining_neg_hex_blob_nonhex
xmrmining_neg_hex_blob_short
xmrmining_neg_hex_blob_overflow
xmrmining_neg_hex_seed_hash
xmrmining_neg_hex_target
xmrmining_neg_hex_nonce
xmrmining_neg_hex_result
xmrmining_neg_hex_prefix
xmrmining_neg_state_first_login
xmrmining_neg_state_submit_before_login
xmrmining_neg_state_after_login_reject
xmrmining_neg_state_after_close
xmrmining_neg_id_resp_mismatch
xmrmining_neg_result_id_missing
xmrmining_neg_id_notify_fake
xmrmining_neg_id_reuse
xmrmining_neg_job_unknown
xmrmining_neg_job_session_mismatch
xmrmining_neg_carrier_missing_tcp
xmrmining_neg_carrier_udp
xmrmining_neg_carrier_port_conflict
xmrmining_neg_prop_swallowed
xmrmining_neg_prop_fake_success
```

## 9. 修订记录

- v2.0.2（2026-09-01，独立复验修复轮）：rr-bacnet3 复验首审 7C+2N 全部关闭（9/9），新出两条小 finding 修复——**V-1**：补负例 55 `xmrmining_neg_result_id_missing`（§5 表单一注入"login 响应 result 对象缺 id 成员"、锚 `result`；§2/§8 同步），原 55–63 顺移 56–64，总数 63 → **64（25 正 + 39 负）**；**V-2**：§6 功能行"负例 10 类"残留改"39 行 6 类（值域 15/线格式 9/状态机 4/关联 6/配置载体 3/错误传播 2）"。

- v2.0.1（2026-09-01，v1.3 行为面全枚举重审修复轮）：docs-xmrmining 重审 7 confirmed + 2 note 逐项修复，33 → **63 例（25 正 + 38 负）**、负例编号 24–33 → 26–63（原子拆分后 ID 全新）。**C-01** 用例 20 改 blob 407B 合法上界（814 hex/行 1082B，合法域 [43,407]）；**C-02** 用例 5 通知断言改"顶层无 id 成员"（`params.id` 不受限，废除"整行不含 22696422"矛盾断言）；**C-03** 用例 18 packet_count 10→11（3+4+4 分解补入）；**C-04** §5 表逐故障拆分 10 → 38 行（一行一例、主锚词单一钉死、`wire_fault` 三方同序）；**C-05** 新增用例 24 `xmrmining_port_nondefault`（3333、行字节同用例 1、无 DecodeAs 依赖）；**C-06** §1 输出契约段 + §7.7 验收项；**C-07** 并发翻案——用例 25 `xmrmining_concurrent_sessions`（交错回放、互不串用、与 22 分立）+ §3.4/§6 同步；**N-01** 用例 4 公式 +8→+11；**N-02** §1 保活/RST 口径段。§6 五层映射同步更新。

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负，基于未钉死权威规范的混合 Stratum-like/JSON-RPC 形态）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。以 xmrig STRATUM.md（官方规范）+ XMRig 源码 + MoneroOcean 现网形态为基线重排为 **33 条（23 正 + 10 负）**：每消息类型（login/job/submit/keepalived/getjob）、每响应态（OK/error）、每形态变体（现代/legacy job、algo/sig/commitment 可选、rigid、extensions、keepalive 别名）、每长度边界（blob 满值 408B/nonce 0-满值/target 4-8B/seed_hash 64/job_id 1500）、每关联规则（id 按值配对/session id 回带/job_id 来源）、每错误分支各一例；索引表为五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 实测固化"无 XMR 专用 dissector（禁用 `xmr.*` 字段）、断言走 `tcp.payload` 全行 hex + offset 54/74 frames 双通道、`json.*` 仅辅助"基线，并按 spec 逻辑构造 pcap 实证（`tcp.payload` 全行提取含行尾 `0a`、login 请求/响应/notify/submit 逐字节吻合）；fixture 常量全部取 spec verbatim + mo-pool 现代 job 形态；§2 五列索引、§3 线上编码与偏移、§6 五层映射、§8 三方一致性表；删除旧稿 tls/pcap_nic/multi_stream 等不适用项（设计 §1/§4 边界）。状态：**待独立隔离审查**。
