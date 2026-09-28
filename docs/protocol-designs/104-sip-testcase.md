# #104 sip（SIP，RFC 3261）测试用例契约

> 版本：v1.0.0（批次二文档轨 as-built 定稿）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/104-sip-design.md` v1.0.0（D-SIP-1 + D-SIP-2 as-built 定稿）
> 前身用例清单：`docs/TEST_CASES.md` **T-SIP-1…96**（本文档是其 as-built 契约化，不搬其状态行数字）
> 机器契约：`trafficgen/test/protocol_pcap/cases/sip.json`（**96 例**：ID 集合、顺序、包数、断言均与本文档 §2 机读一致）
> 白话一句：**九十六条检查——八十七条看正常收发（打电话、注册、发消息、转移、开会、发声音、加密、多路并行），九条看胡来能不能被拦下（配置写错、端口写死、媒体放错链上）；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **96 个唯一语义 ID：87 正 + 9 负**。派生规则：设计 §3 每个线格式条款、§5 每个事务/自动派生行为、§7 每行错误处理、§12.12 每个动态字段在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**（原子用例原则）。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 用例总数 | **96**（87 正 + 9 负） |
| `spec_json` 顶层键 | `{layers}` **94** / `{layers, sip}` **1**（`sip_flat_presence`，**判死负例对象**）/ `{group_id, layers}` **1**（`sip_port_dyn`，合法跨流绑定键） |
| 层链 | `[ip,sip]` **90** / `[ip,tcp,tls,sip]` **4** / `[ip,tcp,sip]` **2** |
| 负例 `expect` 键形 | 严格两键 `{expect_error, error_contains}` **7** / 含 `notes` **2**（`sip_flat_presence`/`sip_flat_static_port`，G-SIP-2） |
| 正例包数断言 | 精确 `packet_count` **28** / 下界 `min_packets` **59** |
| `strategy_fc` | **12** 例，全部 `{"type":"flows","value":2}` |
| `nic_capture` | **0** 例（NIC 路径今日零覆盖，G-SIP-6） |
| `fields` 断言 | **314** 条（`value` 284 / `distinct_values` 24 / 裸 field 4 / `same_as_packet` 1 / `distinct_exclude` 1） |
| `frames` 断言 | **8** 条，分布 5 例（#1 四条 / #4 / #11 / #14 / #15 各一条） |
| 断言字段种类 | **26**（`sip.*` **18** / `tcp.*` 4 / `udp.*` 2 / `ipv6.dst` / `tls.record.content_type`） |
| `negotiated` / `terminates` | **各 39** 例 |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.flags`/`tcp.dstport`/`tcp.srcport`/`udp.srcport`/`udp.dstport`/`sip.*`/`ipv6.dst`/`tls.record.content_type` 字段 + offset 54/74/42 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。**存量 96 例今日均未启用 `nic_capture`**（G-SIP-6）——契约兼容两路，但 NIC 一路**今日无用例证据**。

**TSHARK 基线（实测）**：`sip.*` 字段族可用且被 96 例广泛使用（18 种字段名，314 条断言）。**RTP 字段族不可用**——`rtp.*` 在本机 tshark 3.6.14 上无效（前身 T-SIP-1…57 记录，本版沿用），故 RTP 断言一律走 **frames pin**（offset 42，RTP 头首字节 `0x80` = V=2）。**该结论本版未取到新证据推翻，如实登记为 G-SIP-7 待确认**（确认方式：`tshark -G fields | grep '^rtp\.'`）。

**偏移基线（实测）**：IPv4 + TCP 载荷起点 **offset 54**；IPv6 + TCP 载荷起点 **offset 74**；IPv4 + UDP（RTP）载荷起点 **offset 42**。frames 断言逐条钉在这三个偏移上（§3）。

**动态字段禁止硬编码**：生成期随机值（TCP ISN、RTP seq/timestamp/ssrc、dialog 模式的 Via branch、自动生成的 Call-ID hex）**一律不钉值**；会话模式的 Via branch 是 **FNV-1a(callID)** 确定性值，可复现但不钉（用例只钉端口与 Call-ID 文本面）。

**包数约定（实测公式，设计 §9）**：

```
单流（raw [ip,sip]，dialog 形）  = 7 + Σ消息分段数 + Σ媒体帧数
单流（raw [ip,sip]，sessions 形）= Σ_sess (7 + Σ该会话消息分段数 + Σ该会话媒体帧数)
单流（事件面 [ip,tcp,sip]）      = 7 + Σ消息数
单流（事件面 [ip,tcp,tls,sip]）  = 7 + 7 + Σ消息数
总包数 = 单流 × flows（strategy_fc.value）
```

其中 `7 = 3（TCP 握手）+ 4（TCP 挥手）`；`Σ消息分段数 = Σ ⌈渲染长/MSS⌉`——**仅 #10 一条用例渲染长超 MSS**（其余 86 例 `Σ消息分段数 = Σ消息数`）。

**机读校验结果**：**28 例精确 `packet_count` 全部命中（28/28）**；59 例 `min_packets` 中 **56 例公式值 ≥ 下界**，**2 例下界低于公式值**（宽松下界：#55 `sip_status_enum_4xx` min=21 vs 公式 22、#56 `sip_status_enum_56xx` min=12 vs 公式 13），**1 例例外**（#10 `sip_mss_segment` min=11 vs 消息数公式 9——**差额来自 MSS 分段**，见 §3.7）。合计 **85/87 满足**。

**保活/重试/RST 口径**：①**保活**——引擎**无自动保活**；会话中探活由用户显式写 OPTIONS/UPDATE（#22/#34 承载语义）；②**重试**——引擎**无 Timer/重传**；重传由用户显式写第二条同 CSeq 请求表达（#44）；③**RST**——引擎**只产优雅 FIN**（4 帧挥手），RST 非正常结束**今日零用例** → A′ 立项（G-SIP-5）；④**非正常结束**——协议层的"异常"由**响应码**表达（486 Busy #21 / CANCEL+487 #20 / 302 #33 / 503 #94），全部仍以 TCP 优雅挥手收尾。

**负例纯净性**：`expect_error=true` 的 9 例执行期 expect **只有** `expect_error` 与 `error_contains`（其中 2 例另含 `notes`，属文档性键，见 G-SIP-2），**不产生成功 PCAP**。

## 2. 原子用例索引（96 ID = 87 正 + 9 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数 |
|---:|---|---|---|---:|
| 1 | `sip_basic_dialog` | 正 | §3.1/§3.2/§5.2：五消息基础对话（INVITE/200/ACK/BYE/200） | 12 |
| 2 | `sip_flat_presence` | 负 | §7 N-1：顶层 sip 子映射判死（空 map 也死） | — |
| 3 | `sip_flat_static_port` | 负 | §7 N-2：层内静态四元组 + flows=2 | — |
| 4 | `sip_hdr_completion` | 正 | §3.2：无头 INVITE → Call-ID/Via/CSeq/Max-Forwards 全生成 | 12 |
| 5 | `sip_hdr_user_wins` | 正 | §3.2：显式 CSeq:7 + Call-ID 保留 + 200 回显 | 9 |
| 6 | `sip_register` | 正 | §5.1：REGISTER 方法枚举 + 200 | 9 |
| 7 | `sip_options` | 正 | §5.1：OPTIONS 方法枚举 + 200 | 9 |
| 8 | `sip_status_codes` | 正 | §5.1：响应码 100/180/200/404 枚举 | 15 |
| 9 | `sip_sdp_body` | 正 | §3.1：SDP 体 + Content-Length 自动补 | 9 |
| 10 | `sip_mss_segment` | 正 | §3.7：3000B body → MSS 分段 3 段 | ≥11 |
| 11 | `sip_rtp_media` | 正 | §3.6：RTP 媒体子流（frames=2，PT 0） | 14 |
| 12 | `sip_rtp_down` | 正 | §3.6：RTP down 方向 + 显式端口线元组交换 | 10 |
| 13 | `sip_sdp_port` | 正 | §3.6：SDP `m=audio` 派生 RTP 端口 | 10 |
| 14 | `sip_rtp_filesource` | 正 | §3.6：FileSource 实字节优先 | 10 |
| 15 | `sip_v6` | 正 | §2：IPv6 载体（offset 74） | 12 |
| 16 | `sip_default_port` | 正 | §2：dst_port 缺省 5060 | 12 |
| 17 | `sip_port_dyn` | 正 | §12.12：层端口动态 inc + flows=2 | 24 |
| 18 | `sip_empty_dialog` | 正 | §5.3：空 dialog → 7 包最小联结 | 7 |
| 19 | `sip_reinvite_refresh` | 正 | §5.1：会话内 re-INVITE 刷新 | 15 |
| 20 | `sip_cancel` | 正 | §5.1：CANCEL 取消未应答呼叫 | 13 |
| 21 | `sip_busy_reject` | 正 | §5.1：486 Busy 拒绝（非 2xx 仍 ACK） | 10 |
| 22 | `sip_options_keepalive` | 正 | §5.1：会话内 OPTIONS 保活 | 14 |
| 23 | `sip_status_class_enum` | 正 | §5.1：5xx/6xx 大类枚举 | 13 |
| 24 | `sip_callflow_complete` | 正 | §5.1：PRACK/RAck 组合流 | 15 |
| 25 | `sip_register_digest_auth` | 正 | §1 边界③：REGISTER 401 → Authorization 重发 | 11 |
| 26 | `sip_register_expire0` | 正 | §5.1：REGISTER 刷新 + Expires:0 注销 | 11 |
| 27 | `sip_two_calls_sequential` | 正 | §5.1：同流两通连续呼叫（独立 Call-ID） | 15 |
| 28 | `sip_refer_transfer` | 正 | §4 场景⑩：REFER 盲转 + NOTIFY sipfrag | 16 |
| 29 | `sip_subscribe_notify_mwi` | 正 | §4 场景⑩：SUBSCRIBE/NOTIFY MWI | 13 |
| 30 | `sip_early_media_183` | 正 | §5.1：183 早媒体 + PRACK | 13 |
| 31 | `sip_hold_resume` | 正 | §3.6：HOLD/恢复（SDP 方向属性翻转） | 16 |
| 32 | `sip_info_dtmf` | 正 | §4 场景⑩：INFO 带 DTMF | 14 |
| 33 | `sip_302_redirect` | 正 | §1 边界⑥：302 呼转重定向 | 13 |
| 34 | `sip_update_session_timer` | 正 | §5.1：UPDATE 会话定时刷新 | 12 |
| 35 | `sip_invite_401_challenge` | 正 | §1 边界③：INVITE 401 质询重发 | 13 |
| 36 | `sip_message_im` | 正 | §4 场景⑩：MESSAGE 页模式 IM | 9 |
| 37 | `sip_compact_form` | 正 | §3.3：紧凑形头方言（`v=/f=/t=/i=/l=`） | 12 |
| 38 | `sip_via_chain` | 正 | §3.4：多跳 Via 链 + Record-Route/Route | 12 |
| 39 | `sip_long_auth_uri` | 正 | §6：超长头（512B 级）+ 长 URI | 9 |
| 40 | `sip_tel_uri_utf8` | 正 | §3.2：tel: URI + UTF-8 显示名 | 12 |
| 41 | `sip_sdp_video_multistream` | 正 | §3.6：SDP 双流（只取 `m=audio`） | 12 |
| 42 | `sip_body_multipart` | 正 | §3.1：multipart/mixed 双体 | 12 |
| 43 | `sip_hdr_case_mix` | 正 | §3.3：头名大小写混写透传 | 12 |
| 44 | `sip_100_trying_retrans` | 正 | §1 边界①：100 Trying + 同 CSeq 重传 | 13 |
| 45 | `sip_forked_invite` | 正 | §5.1：并行分叉 INVITE 竞速 | 13 |
| 46 | `sip_conference_join` | 正 | §4 场景⑪：会议加入 + 名册事件 | 12 |
| 47 | `sip_replaces_attended` | 正 | §4 场景⑩：Replaces 询转 | 16 |
| 48 | `sip_offerless_3pcc` | 正 | §3.6：offerless INVITE / 3PCC | 12 |
| 49 | `sip_publish_presence` | 正 | §4 场景⑩：PUBLISH 在线状态 | 11 |
| 50 | `sip_reason_q850` | 正 | §3.1：Reason: Q.850 释放原因 | 12 |
| 51 | `sip_ims_pheaders` | 正 | §3.1：IMS 私有头面板 | 12 |
| 52 | `sip_history_info_fwd` | 正 | §3.1：History-Info 呼转链 | 13 |
| 53 | `sip_491_glare` | 正 | §5.1：491 Request Pending glare | 13 |
| 54 | `sip_interleaved_two_calls` | 正 | §5.1：同连接两呼事务交错 | 18 |
| 55 | `sip_status_enum_4xx` | 正 | §5.1：4xx 长尾枚举（403/408/480/481/488） | 21 |
| 56 | `sip_status_enum_56xx` | 正 | §5.1：5xx/6xx 枚举（503/600） | 12 |
| 57 | `sip_v6_port_dyn` | 正 | §12.12：v6 × 动态端口 × flows=2 | 18 |
| 58 | `sip_sessions_two_dialogs` | 正 | §3.5：双会话独立面（独立 Call-ID/四元组） | 18 |
| 59 | `sip_sessions_derived_callid` | 正 | §3.5：Call-ID 缺省派生 | 18 |
| 60 | `sip_sessions_explicit_wins` | 正 | §3.5：显式三级赢 | 9 |
| 61 | `sip_neg_sessions_dialog_mutex` | 负 | §7 N-3：sessions × dialog 互斥 | — |
| 62 | `sip_neg_sessions_empty` | 负 | §7 N-4：空 sessions 数组（同锚词面） | — |
| 63 | `sip_neg_sessions_static` | 负 | §7 N-5：sessions 内标量端口 + flows=2 | — |
| 64 | `sip_sessions_port_inc` | 正 | §12.12：会话端口 inc | 18 |
| 65 | `sip_sessions_port_rand` | 正 | §12.12：会话端口 rand（seed=7 可复现） | 18 |
| 66 | `sip_sessions_port_list` | 正 | §12.12：会话端口 list 轮转 | 18 |
| 67 | `sip_sessions_port_fixed` | 正 | §12.12：会话端口 fixed | 18 |
| 68 | `sip_sessions_port_pattern` | 正 | §12.12：会话端口 pattern 替换 | 18 |
| 69 | `sip_sessions_callid_pattern` | 正 | §12.12：call_id pattern 逐流 | 18 |
| 70 | `sip_sessions_callid_fixed` | 正 | §12.12：call_id fixed 同值 | 18 |
| 71 | `sip_sessions_v6` | 正 | §2：IPv6 双会话对称 | 18 |
| 72 | `sip_medias_bidirectional` | 正 | §3.6：medias 双向交替 + 线元组交换 | 16 |
| 73 | `sip_medias_interleave` | 正 | §3.6：interleave 等分调度（T=4/G=3→2/1/1） | 14 |
| 74 | `sip_neg_medias_mutex` | 负 | §7 N-6：media × medias 互斥 | — |
| 75 | `sip_medias_port_dyn` | 正 | §12.12：medias 端口动态 inc | 22 |
| 76 | `sip_medias_filesource` | 正 | §3.6：medias FileSource 沿用 | 10 |
| 77 | `sip_nat_rport_fill` | 正 | §3.9：裸 `;rport` 回填 | 9 |
| 78 | `sip_nat_switch_forces` | 正 | §3.9：`nat.rport` 开关强制补参数对 | 9 |
| 79 | `sip_nat_default_passthrough` | 正 | §3.9：缺省透传零漂移 | 9 |
| 80 | `sip_nat_sessions_port` | 正 | §3.9：sessions 模式回填会话真值端口 | 8 |
| 81 | `sip_tls_options` | 正 | §5.5：SIPS OPTIONS over `[ip,tcp,tls,sip]` | 16 |
| 82 | `sip_tls_register` | 正 | §5.5：REGISTER over TLS | 16 |
| 83 | `sip_tcp_options` | 正 | §5.5：纯 tcp 事件面明文 | 9 |
| 84 | `sip_neg_tls_media` | 负 | §7 N-7：tls 链 media 判死 | — |
| 85 | `sip_neg_sips_no_tls` | 负 | §7 N-8：`sips:` URI 无 tls 层判死 | — |
| 86 | `sip_neg_tls_sessions` | 负 | §7 N-9：tls 链 sessions 判死 | — |
| 87 | `sip_conf_burst_3party` | 正 | §4 场景⑪：三方会议风暴（五类交织） | 42 |
| 88 | `sip_resp_202_refer` | 正 | §5.1：202 Accepted 分支值 | 9 |
| 89 | `sip_resp_300_contacts` | 正 | §5.1：300 Multiple Choices 多 Contact | 10 |
| 90 | `sip_resp_407_proxy_auth` | 正 | §5.1：407 代理鉴权头族 | 10 |
| 91 | `sip_resp_420_bad_extension` | 正 | §5.1：420 Bad Extension | 10 |
| 92 | `sip_resp_422_session_timer` | 正 | §5.1：422 会话定时器协商失败 | 10 |
| 93 | `sip_resp_489_bad_event` | 正 | §5.1：489 Bad Event（同码异上下文） | 9 |
| 94 | `sip_resp_503_retry_after` | 正 | §5.1：503 + Retry-After | 10 |
| 95 | `sip_hdr_cl_user_wins` | 正 | §3.1：用户自带 Content-Length 禁二次追加 | 9 |
| 96 | `sip_msg_empty_entry_skipped` | 正 | §5.3：dialog 空消息条目静默跳过 | 9 |

**T-编号对照**：`sip_<行为>` 的 T-编号 = 本表 # 号，与 `docs/TEST_CASES.md` 的 T-SIP-1…96 **一一对应、同序**（#1 ≡ T-SIP-1，…，#96 ≡ T-SIP-96）。**序号以 cases JSON 顺序为权威**。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` 或 `min_packets`；帧位由 §1 公式与实测双向确认。以下按用例族分组给出**关键断言**（完整 314 条见 cases JSON；本文档列出每例的**特征断言**）。

### 3.1 `sip_basic_dialog`（12）

`layers=[{ip:{src:10.0.0.1,dst:20.0.0.1}},{sip:{src_port:12001,dst_port:5060,dialog:[INVITE/200/ACK/BYE/200]}}]`

- **21 条 fields + 4 条 frames**（全例最丰富）：帧 1 `tcp.dstport=5060`；帧 4 `sip.Method=INVITE` + `sip.Request-Line="INVITE sip:callee@20.0.0.1 SIP/2.0"`；帧 5 `sip.Status-Code=200` + `sip.CSeq.seq=1` + `sip.CSeq.method=INVITE`；帧 6 `sip.Method=ACK` + `sip.CSeq.seq=1`（**ACK 复用 INVITE 号**，§13.2.2.4）+ `sip.CSeq.method=ACK`；帧 7 `sip.Method=BYE` + `sip.CSeq.seq=2`（**BYE 递增**）+ `sip.CSeq.method=BYE`。
- **frames（offset 54）**：帧 4 = `INVITE sip:… SIP/2.0` 字节；帧 5 = `SIP/2.0 200 OK\r\n` 字节；帧 6 = `ACK sip:…`；帧 7 = `BYE sip:…`。**四条 frame 断言直接证明"请求行/状态行按 §7 渲染且补全头在载荷起点"**。
- `negotiated=true`、`terminates=true`。

### 3.2 `sip_hdr_completion`（12）

`dialog=[INVITE, 200, ACK, BYE, 200]`（**五条消息，零头零 body**——只有 method+uri / status_code+status_text）

- **9 条 fields + 1 条 frame**：帧 4 frame 断言 = `INVITE sip:callee@20.0.0.1 SIP/2.0`——**证明无头请求仍渲染合法请求行**。
- fields 面：帧 4 `sip.Method=INVITE` + `sip.CSeq.seq=1`；帧 5 `sip.Status-Code=200`；帧 6 `sip.CSeq.method=ACK`（**ACK 复用 INVITE 号**）；帧 7 `sip.CSeq.seq=2`（**BYE 递增**）。**CSeq 计数器在无用户头时的自动编号链**（§3.2）是本例的核心断言面。
- 包数 12 = 7+5。**RFC 3261 §8.1.1.4 的"UAC 必须生成 Call-ID"** 由帧 4 的请求行 + 后续 CSeq 链间接证明（Call-ID 生成值随机，不钉）。

### 3.3 `sip_hdr_user_wins`（9）

显式 `CSeq: 7` + 显式 `Call-ID: fixed@host`。

- **11 条 fields**：帧 4 `sip.CSeq.seq=7`（**用户值赢，不被计数器改写**）+ `sip.Call-ID=fixed@host`；帧 5 `sip.Status-Code=200` + `sip.CSeq.seq=7` + `sip.CSeq.method=INVITE` + `sip.Call-ID=fixed@host`（**200 响应回显请求的 CSeq 号、方法名与 Call-ID**，§8.1.3.2）。
- 包数 9 = 7+2（两条消息）。**user > 补全 > 无 三态中的"user 态"**。

### 3.4 `sip_register` / `sip_options`（各 9）

- REGISTER：`sip.Method=REGISTER` + `sip.Status-Code=200`；7 条 fields。
- OPTIONS：`sip.Method=OPTIONS` + `sip.Status-Code=200`；6 条 fields。
- **方法枚举格**——引擎不枚举方法名，任意字符串透传；本两例钉"两个非 INVITE 方法可正常成对"。

### 3.5 `sip_status_codes`（15）

`dialog=[INVITE, 100, 180, 200, ACK, INVITE, 404, ACK]`（**八条消息 = 两笔 INVITE 事务**）

- **8 条 fields**：帧 1/2/3 `tcp.flags` = `0x002`/`0x012`/`0x010`（**握手 flags 序**）+ 帧 1 `tcp.dstport=5060`；`sip.Status-Code` 逐值断言：帧 5 `100`（Trying）、帧 6 `180`（Ringing）、帧 7 `200`（OK）、**帧 10 `404`**（Not Found，**第二笔事务**）。
- **多响应共存**：一笔 INVITE 可引多条临时响应（100/180）再收终响应（200）；第二笔 INVITE 收 404 后仍有 ACK——**§17.1.1.3 的"非 2xx 也须 ACK"** 由 8 条消息的完整序列表达。
- 包数 15 = 7+8。

### 3.6 `sip_sdp_body`（9）

`dialog=[INVITE{body:"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n"}, 200]`——**用户不写 Content-Length 头**。

- **6 条 fields**：帧 1/2/3 `tcp.flags` 序 + 帧 1 `tcp.dstport=5060`；**帧 4 `sip.Content-Length=30`**（**自动补 = body 字节数**，§3.1）+ 帧 4 `sip.Method=INVITE`。
- **字节证据**：body 实长 **30B**（`"v=0\r\n"` 5B + `"o=- 1 1 IN IP4 10.0.0.1\r\n"` 25B）——`\r\n` 计 2 字节（cases `notes` 记"P5 校准：body 实长 30B"）。

### 3.7 `sip_mss_segment`（≥11）

`dialog=[INVITE{body: 3000B}, 200]`。

- **7 条 fields**：帧 1/2/3 `tcp.flags` = `0x002`/`0x012`/`0x010`（**握手三帧 flags 序**）+ 帧 1 `tcp.dstport=5060`；帧 4 `tcp.len=1460`、帧 5 `tcp.len=1460`、帧 6 `tcp.len=315`（**三段分段长度，实测钉值**）。
- `min_packets=11` = 3 握手 + **3 段** + 1（200）+ 4 挥手。**渲染后总长 3235B → 1460+1460+315**。
- **本例是全 96 例中唯一"消息分段数 ≠ 消息数"的用例**（§1 公式校验段的唯一例外）。

### 3.8 `sip_rtp_media`（14）

`dialog=[INVITE, 200, ACK, BYE, 200{emit_media:true}]` + `media:{frames:2, payload_type:0}`——**EmitMedia 标在末条 200 上**。

- **7 条 fields + 1 条 frame**：帧 1/2/3 `tcp.flags` 序 + 帧 1 `tcp.dstport=5060` + 帧 4 `sip.Method=INVITE`；**帧 9 `udp.srcport=5004` + `udp.dstport=5004`**（RTP 端口缺省 5004）；**帧 9 frame offset 42 hex `80`**（**RTP 头首字节 V=2**——UDP 载荷起点 = 14+20+8 = 42，直接证明 RTP 帧结构）。
- 包数 14 = 3+5+2+4（**RTP 两帧插在末条 200 之后**）。**seq/timestamp/ssrc 随机，不钉**（RFC 3550 §5.1）。

### 3.9 `sip_rtp_down`（10）

`dialog=[INVITE, 200{emit_media:true}]` + `media:{frames:1, direction:"down", src_port:30000, dst_port:30001}`。

- **6 条 fields**：帧 1/2/3 `tcp.flags` 序 + 帧 1 `tcp.dstport=5060`；**帧 6 `udp.srcport=30001` / `udp.dstport=30000`**——**线元组交换的直接证据**（down 方向：声明 src=30000/dst=30001，上线为 src=30001/dst=30000，§3.6 `sip.go:1140-1150`）。
- 包数 10 = 3+2+1+4。

### 3.10 `sip_sdp_port`（10）

`dialog=[INVITE{body:"v=0\r\nm=audio 60070 RTP/AVP 0\r\n"}, 200{emit_media:true}]` + `media:{frames:1}`（**端口全部留空，靠 SDP 推导**）。

- **6 条 fields**：帧 1/2/3 `tcp.flags` 序 + 帧 1 `tcp.dstport=5060`；**帧 6 `udp.srcport=60070`**（**INVITE 的 `m=audio` 派生 caller 口**）+ **帧 6 `udp.dstport=5004`**（200 无 `m=` 行 → 缺省 5004）。
- **上界边界**：cases `notes` 记原值 6007020 **超 65535 被 `parseSDPMediaPort` 上界拒**（`sip.go:1281-1283`）→ 改为 60070——**SDP 端口上界拒绝是实测证据**（设计 §8）。
- **future-bleed 注记**：本例**单条 INVITE，不含 re-INVITE**，避开 G-SIP-3 的已知限制。

### 3.11 `sip_rtp_filesource`（10）

`dialog=[INVITE, 200{emit_media:true}]` + `media:{frames:1, file_source:{literal:"pay"}}`。

- **6 条 fields + 1 条 frame**：帧 1/2/3 `tcp.flags` 序 + 帧 1 `tcp.dstport=5060` + 帧 6 `udp.srcport=5004` / `udp.dstport=5004`；**帧 6 frame offset 54 hex `70 61 79`** = `"pay"` 三字节（**RTP 头 12B 之后的载荷起点 = 42+12 = 54**）——**FileSource 实字节优先于零填充合成**（§3.6 合同）。

### 3.12 `sip_v6`（12）

`layers[0].ip={src:2001:db8::1, dst:2001:db8::2}`，`dialog=[INVITE,200,ACK,BYE,200]`。

- **3 条 fields + 1 条 frame**：帧 1 `tcp.flags=0x002` + 帧 1 `tcp.dstport=5060` + 帧 2 `tcp.flags=0x012`；**帧 4 frame offset 74 hex `49 4e 56 49 54 45`** = `INVITE`——**IPv6 载荷起点偏移的直接证据**（协议与地址族解耦：消息字节不变，只有起点从 54 变 74）。

### 3.13 `sip_default_port`（12）

`sip` 层**不写 dst_port**，`dialog=[INVITE,200,ACK,BYE,200]`。

- **3 条 fields**：帧 1 `tcp.dstport=5060`（**translate 缺省补齐**，`chain_planner_translate.go:1722`）+ 帧 1 `tcp.flags=0x002` + **帧 2 `tcp.dstport=12345`**（**下行帧源端口 = worker 保底自增 12345**，`src_port` 缺席时的 `12345+i` 口径）。

### 3.14 `sip_port_dyn`（24）

`ip.src` inc + `sip.src_port` inc（20000→20001）+ `sip.dst_port` fixed(5060) + `flows=2`。

- **4 条 fields**：帧 1 `tcp.srcport=20000`；帧 1 `tcp.dstport=5060`；**帧 13** `tcp.srcport=20001`（**第 2 流起点 = 第 1 流 12 包 + 1**）；帧 13 `tcp.dstport=5060`。
- **顶层含 `group_id`**（合法跨流绑定键，非协议子映射）。

### 3.15 `sip_empty_dialog`（7）

`sip` 层空业务面（dialog 缺省）。

- **7 条 fields**（**全例只有 flags 断言**）：帧 1 `0x002` / 帧 2 `0x012` / 帧 3 `0x010`（**握手三帧**）+ 帧 4 `0x011` / 帧 5 `0x010` / 帧 6 `0x011` / 帧 7 `0x010`（**挥手四帧**）——**nil-config 合同**（`sip.go:120-123` 空配置回退空 dialog）：无消息仍产完整 TCP 联结 3+0+4=7。

### 3.16 场景族 #19–#57（**39 例**，各 9–21 包）

**38/39 例**含 `negotiated=true` + `terminates=true`；**每例 2–5 条** `sip.Method`/`sip.Status-Code` 特征断言（#1 的 21 条是全 96 例最多）。**逐例特征断言摘要**：

| # | 消息数 | 特征断言（机读逐例） |
|---:|---:|---|
| 19 | 8 | 帧 4 INVITE / 帧 7 INVITE + `CSeq.seq=2`（**re-INVITE 新事务号**）/ 帧 10 BYE |
| 20 | 6 | 帧 4 INVITE / 帧 5 `180` / 帧 6 CANCEL / 帧 8 `487` / 帧 9 ACK（**无 BYE**） |
| 21 | 3 | 帧 4 INVITE / 帧 5 `486` / 帧 6 ACK（**非 2xx 仍 ACK，无 BYE**） |
| 22 | 7 | 帧 4 INVITE / 帧 7 OPTIONS + `CSeq.seq=2` / 帧 9 BYE（**会话中保活**） |
| 23 | 6 | 帧 5 `500` / 帧 8 `603`（5xx/6xx 大类） |
| 24 | 8 | 帧 5 `180` / 帧 6 PRACK + **`sip.RAck.CSeq.seq=1`**（RFC 3262 关联）/ 帧 10 BYE |
| 25 | 4 | 帧 4 REGISTER / 帧 5 `401` / 帧 6 REGISTER + `CSeq.seq=2` / 帧 7 `200`（**质询后重发**） |
| 26 | 4 | 帧 4 REGISTER / 帧 6 REGISTER + `CSeq.seq=2` / 帧 7 `200`（**刷新/注销**） |
| 27 | 8 | 帧 4 `Call-ID=callA@10.0.0.1` / 帧 7 BYE / 帧 9 `Call-ID=callB@10.0.0.1` / 帧 10 `486`（**同流两呼独立 Call-ID、独立命运**） |
| 28 | 9 | 帧 7 REFER + `CSeq.seq=2` / 帧 9 NOTIFY / 帧 11 BYE（**盲转 + sipfrag 上报**） |
| 29 | 6 | 帧 6 SUBSCRIBE / 帧 8 NOTIFY + `CSeq.method=NOTIFY` / 帧 9 `200` |
| 30 | 6 | 帧 5 `183` / 帧 6 PRACK + `RAck.CSeq.seq=1` / 帧 8 `200`（**早媒体**） |
| 31 | 9 | 帧 7 INVITE + `CSeq.seq=2` / 帧 10 INVITE + `CSeq.seq=3`（**保持/恢复两轮 re-INVITE**） |
| 32 | 7 | 帧 7 INFO + `CSeq.seq=2` / 帧 9 BYE |
| 33 | 6 | 帧 5 `302` / 帧 7 INVITE + **`Request-Line="INVITE sip:3001@20.0.0.1 SIP/2.0"`** + `CSeq.seq=2`（**重定向到新目标**） |
| 34 | 5 | 帧 7 UPDATE + `CSeq.method=UPDATE` / 帧 8 `200` |
| 35 | 6 | 帧 5 `401` / 帧 6 ACK / 帧 7 INVITE + `CSeq.seq=2` / 帧 8 `200` |
| 36 | 2 | 帧 4 MESSAGE / 帧 5 `200`（**对话外单事务**） |
| 37 | 5 | 帧 4 INVITE / 帧 7 BYE（**紧凑形头承载**） |
| 38 | 5 | 帧 4 INVITE + `CSeq.seq=1` / 帧 7 BYE（**三跳 Via + RR/Route**） |
| 39 | 2 | 帧 4 REGISTER + **`Request-Line` 含 `;transport=udp;method=REGISTER;opaque=z9hG4bK…`（约 226B 参数化长 URI）** / 帧 5 `200` |
| 40 | 5 | 帧 4 **`Request-Line="INVITE tel:+861055556666 SIP/2.0"`** + INVITE / 帧 7 BYE（**tel: URI**） |
| 41 | 5 | 帧 4 INVITE + **`sip.Content-Length=248`**（**多 `m=` 行的体长**）/ 帧 7 BYE |
| 42 | 5 | 帧 4 INVITE / 帧 7 BYE（**multipart 体承载**） |
| 43 | 5 | 帧 4 **`Call-ID=mix@10.0.0.1`** + INVITE / 帧 7 BYE（**混写头名被正确识别**——`findHeader` 大小写不敏感的证据） |
| 44 | 6 | 帧 4 INVITE / 帧 5 `100` / **帧 6 INVITE + `CSeq.seq=1`**（**同 CSeq 重传**）/ 帧 7 `180` |
| 45 | 6 | 帧 5 `180` / 帧 6 `180`（**双支路**）/ 帧 7 `486` / 帧 8 `200`（**竞败 + 竞胜**） |
| 46 | 5 | 帧 4 **`Request-Line="INVITE sip:conf300@20.0.0.1;gruu SIP/2.0"`**（**焦点 URI**）/ 帧 7 NOTIFY + `CSeq.method=NOTIFY` |
| 47 | 9 | 帧 7 REFER + `CSeq.seq=2` / 帧 9 NOTIFY / 帧 11 BYE（**询转**） |
| 48 | 5 | 帧 4 INVITE / 帧 5 `200` / 帧 6 ACK / 帧 7 BYE（**offerless：无体 INVITE → 200 带 offer → ACK 带 answer**） |
| 49 | 4 | 帧 4 PUBLISH / 帧 6 PUBLISH + `CSeq.seq=2` / 帧 7 `200`（**软状态刷新**） |
| 50 | 5 | 帧 7 BYE + `CSeq.seq=2` / 帧 8 `200`（**双 Reason 头承载**） |
| 51 | 5 | 帧 4 INVITE / 帧 5 `200` / 帧 7 BYE（**P 头族承载**） |
| 52 | 6 | 帧 5 `302` / 帧 7 INVITE + `Request-Line="INVITE sip:3001@20.0.0.1 SIP/2.0"` / 帧 8 `200`（**带审计链的呼转**，与 #33 分面） |
| 53 | 6 | 帧 7 INVITE + `CSeq.seq=2` / 帧 8 `491` / 帧 9 ACK（**glare**） |
| 54 | 11 | 帧 4 `Call-ID=ia@10.0.0.1` / **帧 6 `Call-ID=ib@10.0.0.1`**（**两呼 Call-ID 在同连接内交错出现**）/ 帧 7 `200` / 帧 11 BYE |
| 55 | 15 | 帧 5 `403` / 帧 8 `408` / 帧 11 `480` / 帧 14 `481` / 帧 17 `488`（**五事务五码**） |
| 56 | 6 | 帧 5 `503` / 帧 8 `600` |
| 57 | 2 | `ipv6.dst` distinct = `[fd00::1, fd00::2]`；`sip.Method` distinct = `[OPTIONS]`；`tcp.srcport`/`tcp.dstport` distinct 各含 4 值（**双动态端口 × 2 流**） |

### 3.17 sessions 族 #58–#60、#64–#71（11 例）

| # | 包数 | 特征断言 |
|---:|---:|---|
| 58 | 18 | `tcp.srcport` distinct = `[22001,22002,5060]`；`sip.Call-ID` distinct = `[sess-a@10.0.0.1, sess-b@10.0.0.1]`——**每会话独立 TCP 连接 + 独立 Call-ID** |
| 59 | 18 | `sip.Call-ID` distinct = `[0-0@10.0.0.1, 0-1@10.0.0.1]`（**缺省派生 `{flowIdx}-{sessIdx}@{srcIP}` 实测值**）+ `tcp.srcport` distinct = `[12345,12346,5060]`（**端口派生 `12345+flowIdx×M+sessIdx`**） |
| 60 | 9 | `sip.Call-ID` distinct = `[explicit@10.0.0.1]`（显式赢）；单会话 |
| 64 | 18 | `tcp.srcport` distinct = `[23001,23002,5060]`（inc 逐流） |
| 65 | 18 | `[23187,23189,5060]`（**rand seed=7 落盘钉值，可复现**） |
| 66 | 18 | `[24001,24002,5060]`（list 轮转） |
| 67 | 18 | `[25001,5060]`（fixed 同值 = 用户显式声明语义） |
| 68 | 18 | `[2601,2602,5060]`（pattern `260{n}` 替换） |
| 69 | 18 | `sip.Call-ID` distinct = `[sip1@10.0.0.1, sip2@10.0.0.1]`（call_id pattern） |
| 70 | 18 | `[static@10.0.0.1]`（call_id fixed 同值） |
| 71 | 18 | v6 双会话对称（fd00 端点） |

**多会话 case 的独立状态证据（CORE_MEMORY §7「多会话 case 要求」）**：#58 用 **两个 distinct_values 断言**同时证明"四元组独立"（srcport 22001/22002）与"标识独立"（Call-ID sess-a/sess-b），**不是只证明包数增加**。**#64–#70 七格是 CORE_MEMORY §12.15 五策略整格矩阵的落点**（inc/rand/list/fixed/pattern × 端口与 call_id 两轨）。

### 3.18 medias 族 #72–#73、#75–#76（4 例）

| # | 包数 | 特征断言 |
|---:|---:|---|
| 72 | 16 | `udp.srcport` distinct = `[30004,30007]`；`udp.dstport` distinct = `[30006,30005]`——**down 帧线元组交换的直接证据**（up: src 30004→dst 30006；down: src 30007→dst 30005）；帧序 up,down,up,down,up,down（round-robin） |
| 73 | 14 | **帧位钉死**：帧 4 INVITE / 帧 5,6 RTP / 帧 7 200 / 帧 8 RTP / 帧 9 ACK / 帧 10 RTP——**T=4/G=3→gap 2/1/1 等分调度的直接证据**（§3.12 写死可复现） |
| 75 | 22 | `udp.srcport` distinct = `[31001,31002]`（**medias 端口 inc 逐流** + flows=2；22 = 2×(3 握+2 SIP+4 挥)+2×2 RTP） |
| 76 | 10 | 帧 5 `udp.srcport=5004`；FileSource 沿用（多流形态；literal 3B → 1 帧） |

### 3.19 NAT 族 #77–#80（4 例）

| # | 包数 | 特征断言 |
|---:|---:|---|
| 77 | 9 | 帧 4 `sip.Via` = `"SIP/2.0/TCP 10.0.0.1:9999;branch=z9hG4bKx;rport=12001;received=10.0.0.1"`（用户原文的 `;rport` 裸标记被填上**实际 src_port 12001**）+ 帧 5 `sip.Via` = `"…;rport=9999;received=10.0.0.1"`（**响应侧逐字回放用户原文**，零二次改写）——**无需开关即回填**（RFC 3581 §4 客户端行为） |
| 78 | 9 | Via 无 rport 参数 + `nat:{rport:true}` → 帧 4 `sip.Via` = `"SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKy;rport=12001;received=10.0.0.1"`（**追加参数对到尾部**——开关代客户端补标记） |
| 79 | 9 | 无 nat 无标记 → 帧 4 `sip.Via` = `"SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKz"`（**原样，零字节漂移线**） |
| 80 | 8 | **会话真值端口**：会话 `src_port=22001` → 帧 4 `sip.Via` = `"SIP/2.0/TCP 10.0.0.1:22001;branch=z9hG4bKs;rport=22001;received=10.0.0.1"`（**非 spec 的 12001**）；单条 OPTIONS 无响应 = 3+1+4 |

### 3.20 TLS/事件面族 #81–#83（3 例）

| # | 包数 | 特征断言 |
|---:|---:|---|
| 81 | 16 | 帧 1 `tcp.dstport=5061`（**用户显式写**，G-SIP-4）+ 帧 1 `tcp.srcport=12001` + `tls.record.content_type` distinct = `["22"]`（**握手 record**）；16 = 3 tcp 握手 + 7 TLS 握手 record（CH/SH/EE/Cert/CV/Fin×2）+ 2 app-data + 4 挥手。**诚实边界**：app-data 是加密态，tshark 无 content_type 字段，其 0x17 由**包数形状**钉而非字段断言 |
| 82 | 16 | REGISTER over TLS，同 81 形状（`tcp.dstport=5061` + `tls.record.content_type=["22"]`） |
| 83 | 9 | **纯 tcp 事件面明文**：帧 4 `sip.Method=OPTIONS`；帧 5 `sip.Status-Code=200`；帧 5 **`sip.Via` `same_as_packet: 4`**（响应 Via 回显请求 Via，§8.1.3.2——**唯一一条 `same_as_packet` 形态断言**） |

### 3.21 响应码补充族 #88–#94、#95–#96（9 例）

| # | 包数 | 特征断言 |
|---:|---:|---|
| 88 | 9 | 帧 4 `sip.Method=REFER` / 帧 5 `sip.Status-Code=202`（**2xx 非 200 分支值**） |
| 89 | 10 | 帧 5 `sip.Status-Code=300` / 帧 5 **`sip.Contact="<sip:a@20.0.0.2>,<sip:b@20.0.0.3>,<sip:c@20.0.0.4>"`**（**多 Contact 列表形**） |
| 90 | 10 | 帧 5 `sip.Status-Code=407` / 帧 5 **`sip.Proxy-Authenticate="Digest realm=\"proxy.example.com\", nonce=8a9f, qop=\"auth\""`**（**与 401 的 `WWW-Authenticate` 分面**） |
| 91 | 10 | 帧 5 `sip.Status-Code=420` / 帧 5 **`sip.Supported="timer,replaces"`**（**扩展协商失败**） |
| 92 | 10 | 帧 5 `sip.Status-Code=422` / 帧 5 **`sip.Min-SE="90"`**（RFC 4028 定时器协商失败） |
| 93 | 9 | 帧 4 `sip.Method=SUBSCRIBE` / 帧 5 `sip.Status-Code=489`（**同码异上下文**：489 只在 SUBSCRIBE 上下文有意义） |
| 94 | 10 | 帧 5 `sip.Status-Code=503` / 帧 5 **`sip.Retry-After="30"`** |
| 95 | 9 | 帧 4 **`sip.Content-Length=88`**（**用户自带值原样保留，引擎禁二次追加**——`renderSIPMessage` 的 `hasContentLength` 分支） |
| 96 | 9 | 帧 4 `sip.Method=OPTIONS` / 帧 5 `sip.Status-Code=200`；**dialog 含一条无 method 无 status 的空条目**，包数 9 = 3+2+4 **证明空条目未产包**（`inferDirection` 返回空串 → `continue`） |

### 3.22 `sip_conf_burst_3party`（42，最复杂例）

三会话（A：8 消息 + 双向 4 RTP 帧 / B：3 消息 486 / C：6 消息 CANCEL 链）+ `nat.rport=true`。

- **2 条 fields**：`tcp.srcport` distinct = `[22001,22002,22003]` **且** `distinct_exclude=["5060"]`（**排除服务端口**）；`udp.srcport` distinct = `[30004,30006]`（双向 RTP 的线元组交换后源口）。
- **包数 42 = (7+8+4) + (7+3) + (7+6)** = 19 + 10 + 13——**五类交织单例**：多会话 + 多事务 + 多流关联 + 异常分支（486/CANCEL+487）+ NAT。
- **会话 A 的 dialog** = INVITE/200/ACK/re-INVITE/200/ACK/BYE/200（**8 条 = 多事务**：首 INVITE 建立 + re-INVITE 重协商 + BYE 释放）；**会话 C** = INVITE/100/CANCEL/200/487/ACK（**CANCEL 链**：100 临时 → CANCEL → 200 对 CANCEL → 487 对 INVITE → ACK）。
- **注**：cases 自身 `notes` 写"19+9+13=41"与 `packet_count=42` **不一致**（会话 B 实为 10 包、会话 C 实为 13 包，19+10+13=42 与 `packet_count` 相符）——**`notes` 是文档性描述，`packet_count` 是权威**；该 `notes` 算术错误列缺口 G-SIP-2（与 `notes` 键收窄同批处理）。

**正例总则**：多节点一帧、多会话多连接、RTP 双向、interleave 插帧、NAT 回填、SIPS over TLS、空条目跳过均为正例形态；只有**配置错、载体错、URI 载体错、静态复制**进入负例。

## 4. 负例契约

负例必须在 schema（create 期 400）或 planner/生成器（task 期）阶段失败并传播为 task error，**不得产生成功 PCAP**。锚词与设计 §7 表一一对应、同序（代码逐字，机读实测行号）：

| ID | 故障输入 | JSON `error_contains` | 代码文案（逐字） | 代码行 |
|---|---|---|---|---|
| `sip_flat_presence` | 顶层 `"sip": {}`（空 map） | `top-level sip sub-config` | `protocol sip no longer accepts a top-level sip sub-config (move it into the sip layer of an [ip,sip] layers chain)` | `strategy_convert.go:8970` |
| `sip_flat_static_port` | `[ip{}, sip{src_port:12001,dst_port:5060}]` + `flows=2` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). Write the varying field as a dynamic object inside its layer (ip.src/ip.dst, tcp/udp src_port/dst_port)` | `semantic.go:285` |
| `sip_neg_sessions_dialog_mutex` | `sip{dialog:[…], sessions:[…]}` | `sip: sessions and dialog are mutually exclusive` | `sip: sessions and dialog are mutually exclusive (use sessions for the multi-session shape, dialog for the single-dialog shorthand)` | `semantic.go:311` + `sip.go:110` |
| `sip_neg_sessions_empty` | `sip{sessions: []}` | 同 N-3 | 同 N-3 | `semantic.go:314` |
| `sip_neg_sessions_static` | `sessions[{src_port:22001, dialog:[…]}]` + `flows=2` | `static four-tuple` | 同 N-2 | `semantic.go:273` |
| `sip_neg_medias_mutex` | `sip{media:{…}, medias:[{…}]}` | `sip: media and medias are mutually exclusive` | `sip: media and medias are mutually exclusive (use media for a single stream, medias for the multi-stream shape)` | `semantic.go:402` + `sip.go:115` |
| `sip_neg_tls_media` | `[ip,tcp,tls,sip]` + `media:{frames:2}` | `media is not supported on a tcp/tls sip chain` | `sip generator: media is not supported on a tcp/tls sip chain (RTP is a bare UDP stream outside the transport; use the self-drive [ip, sip] chain for media)` | `semantic.go:619` + `event_gen.go:41` |
| `sip_neg_sips_no_tls` | `[ip,tcp,sip]` + `uri:"sips:callee@20.0.0.1"` | `sip: sips uri requires a tls layer in the chain` | 同左 | `semantic.go:628` + `event_gen.go:48` |
| `sip_neg_tls_sessions` | `[ip,tcp,tls,sip]` + `sessions:[{src_port:22001,…}]` | `sessions are not supported on a tcp/tls sip chain` | `sip generator: sessions are not supported on a tcp/tls sip chain (one connection per chain; use the self-drive [ip, sip] chain for sessions)` | `semantic.go:616` + `event_gen.go:38` |

**锚词口径**：`error_contains` 是**子串**判定。9 例覆盖 **7 条独立锚词**（机读去重实测）：`top-level sip sub-config`（1 例）/ `static four-tuple`（**2 例，同锚词不同注入点**：层内端口 vs sessions 内嵌端口）/ `sip: sessions and dialog are mutually exclusive`（**2 例，同锚词不同形状**：同给 vs 空数组）/ `sip: media and medias are mutually exclusive`（1 例）/ 载体族 3 条（`media is not supported on a tcp/tls sip chain`、`sip: sips uri requires a tls layer in the chain`、`sessions are not supported on a tcp/tls sip chain`，各 1 例）。

**双路独立闭合（C 类）**：

| 负例 | create 期门 | task 期背 door |
|---|---|---|
| N-1 | `CheckProtoFlat` sip 分支（`strategy_convert.go:8968`） | —（create 期即拒） |
| N-2 / N-5 | `checkLayerChainStaticCopy`（`semantic.go:198`，含 sip 层与 sessions[] 嵌套扫描） | — |
| N-3 / N-4 | `checkSIPSessionsMutex`（`semantic.go:297`） | `Planner.Validate`（`sip.go:109`） |
| N-6 | `checkSIPMediasMutex`（`semantic.go:388`） | `Planner.Validate`（`sip.go:114`） |
| N-7 / N-8 / N-9 | `checkSIPEventPlane`（`semantic.go:588`） | `event_gen.go:37-49` |

**负例原子性**：每例**单一故障注入**，无混注。**expect 键形状注**：7 例严格两键 `{expect_error, error_contains}`；2 例（`sip_flat_presence`/`sip_flat_static_port`）含 `notes`（文档性键）——**与严格两键口径不符**，列缺口 G-SIP-2（A′ 收窄动作 = 删该 2 处 `notes`）。

**未入用例的拒绝/静默分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 代码行 | 状态 |
|---|---|---|
| `invalid source IP: %s` | `sip.go:91` | 层内**不可达**（schema 先拦 IP 语法） |
| `invalid destination IP: %s` | `sip.go:96` | 同上 |
| `MSS %d too small (min %d per RFC 879)` | `sip.go:102` | 层内**不可达**（MSS 住 `spec.TCP`，链路径恒 nil） |
| `sip generator: invalid request` | `layer_gen.go:58` | 防御性，生产不可达 |
| `sip generator: no config (spec.sip required)` | `event_gen.go:31` | translate 恒填非 nil，不可达 |
| `Method` 与 `StatusCode` 双给 → 请求行优先 | `sip.go:457-468` | **静默语义**（不报错），零用例 → A′ |
| `Direction` 非法值 → 静默跳过 | `sip.go:314-316` | **静默语义**，零用例 → A′ |
| 纯响应 dialog → 原文渲染 | `sip.go:588-590` | **静默语义**，零用例 → A′ |
| 响应先于请求 → 原文渲染 | 同上 | **静默语义**，零用例 → A′ |
| RST 非正常结束 | 框架 tcp 层能力，本层零断言 | 零用例 → A′ |

## 5. 覆盖与对账

### 5.1 三源回指行

**三源** = ①规范（RFC 3261 + 19 个配套 RFC，设计 §10.1/§10.5）+ ②设计（D-SIP-1/D-SIP-2 as-built，设计 §11）+ ③现网/实测（tshark 3.6.14 字段表 + 96 例断言面 + 前身 pcap 实证）→ **96 ID**（本契约 §2）。

**第三源的诚实边界**：本仓引擎产出的 96 例断言面是"抓包级"证据（字段名/取值格式以 tshark 实测为准），但**真实 UA/服务器（Kamailio/Asterisk/FreeSWITCH）的线字节未抓包核对**（§10.4 行 19–21 的行为映射出自官方文档）→ **G-SIP-8 待确认**。

**96 ID 逐项回指（设计 §9.1 全表摘要）**：#1←设计 §3.1/§3.2/§5.2；#2←§7 N-1；#3←§7 N-2；#4/#5←§3.2；#6–#8←§5.1；#9←§3.1；#10←§3.7；#11–#14←§3.6；#15/#16←§2；#17←§12.12；#18←§5.3；#19–#57←§5.1/§4 场景表；#58–#60/#64–#71←§3.5/§12.12；#61–#63←§7 N-3/N-4/N-5；#72/#73/#75/#76←§3.6；#74←§7 N-6；#77–#80←§3.9；#81–#83←§5.5；#84–#86←§7 N-7/N-8/N-9；#87←§4 场景⑪；#88–#94←§5.1；#95←§3.1；#96←§5.3。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 3261 及 19 个配套 RFC 公开语义 + 前身设计条目（D-SIP-1/D-SIP-2）+ 仓库落码反推 + tshark 3.6.14 字段表与 96 例断言面实测**，**非纯规范反推**（真实 UA 线字节未取到 → G-SIP-8）。
- **对账两行**：**要求逻辑点总数 = 105** = 设计 §10.1 八项 8 行 + §10.2 方法×终态 42 格 + §10.3 数据形态 30 行 + §10.4 商业映射 25 行。四分类（按需求文档 §3 的三分法 + 覆）：
  - **用例覆盖数 = 73**（八项已覆 **2** + 矩阵已覆 **28** + 变体已覆 **22** + 商业已覆 **21**）
  - **不适用 = 4**（商业 4：真实摘要鉴权 / SRTP-RTCP / SIP over UDP / Timer 族——显式声明本协议不涉）
  - **待实现边界（明确不解决）= 2**（八项 2：§10.1 行 3 事务状态机 Timer 族、行 6 自动保活/重传——按需求文档 §3 三分法③「显式标记、从已覆盖统计中排除、不算文档阶段缺陷」）
  - **开放立项（A′）= 26**（八项 **4** + 矩阵 A′ **14** + 变体立项 **8**）
  73 + 4 + 2 + 26 = 105 ✓
  **粒度声明**：行/格粒度每点 1 计。**五件套（§12.3）与动态整格（§12.12）不折进 105**——它们是"结构自洽性展开"（会话/事务/关联/插入/时间线是否写清），不是"规范要求点"，且其内容已被 §10.2/§10.3 的行格覆盖；**M-1 与 G-SIP-1…G-SIP-10 同样不折进 105**（缺陷/缺口登记，非要求逻辑点）。**反查全绿 ≠ 覆盖全**（CORE_MEMORY §9.52 原文）。逐表重数（**均机读实测**）：§10.1 八项 8 = 覆 2 + 立项 4 + 待实现边界 2；§10.2 42 格 = 覆 28 + A′ 14；§10.3 30 行 = 覆 22 + 立项 8；§10.4 25 行 = 覆 21 + 不适用 4。
- **门3 抽查候选**：最复杂用例 = **#87 `sip_conf_burst_3party`**（42 帧：3 会话 × 独立握手挥手 + 多事务 + 双向 RTP 4 帧 + NAT 回填 + 486/CANCEL 异常链；交织维度 = 会话(3)×事务(多)×媒体方向(2)×异常(2)×NAT(1)）；**建议门3 抽 #87 + #58 + #73**（#58 补多会话独立状态面、#73 补 interleave 调度面）。

### 5.3 前身编号对照

本表 # 号 = `docs/TEST_CASES.md` 的 T-SIP 编号（#N ≡ T-SIP-N），**96 行一一对应、同序**（前身 T-SIP-1…96 六段：1–18 / 19–24 / 25–43 / 44–57 / 58–71 / 72–96 与本表 # 号完全重合）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---:|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多笔事务：#1（5 消息 4 事务）、#19（re-INVITE 刷新）、#22（会话中 OPTIONS）、#55（**同 dialog 五事务五码**）、#54（同连接两呼交错） | **已覆** #1/#19/#22/#54/#55 |
| ② | 非正常结束 | 协议层异常 = **响应码**：486 Busy（#21）、CANCEL+487（#20）、302 重定向（#33）、503 Retry-After（#94）；**传输层异常 = RST 今日零用例** | **已覆** #20/#21/#33/#94；**RST A′ 立项**（G-SIP-5，本层零断言） |
| ③ | 长保活 | 引擎无自动保活；会话中探活 = 用户显式 OPTIONS（#22）与 UPDATE+Session-Expires（#34） | **已覆** #22/#34 |

无空项：① 五例已覆；② 四例已覆 + 1 条 A′ 立项；③ 两例已覆。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线/补例）**：

| 类 | 内容 | 落点 |
|---|---|---|
| L2 断言面 | 下行信令帧目的 MAC 断言（**M-1 修复后必加**——今日零 L2 断言是 M-1 未被捕获的直接原因） | M-1 / G-SIP-6 |
| NIC 路径面 | 至少一例启用 `nic_capture`（双输出契约的 NIC 一路今日零用例） | G-SIP-6 |
| RST 面 | `sip_abort_rst` 补例（§3.15②后半） | G-SIP-5 |
| 静默语义面 | `Method`+`StatusCode` 双给 / `Direction` 非法 / 纯响应 dialog / 响应先于请求（**四条均断"不产包/原文渲染"而非断错误**） | G-SIP-5 |
| 冷码长尾面 | 405/406/410/412/413/415/416/421/423/482–485/489/493/494/501/502/504/505/513/580/604/606 按需扩充 | G-SIP-5 |
| RTP 参数面 | `payload_type` 非 0 / `frame_size` 非缺省 / FileSource 二进制（单测已覆，cases 未覆） | G-SIP-7 |
| 动态整格补格 | `sessions[].dst_port` 动态（cases 只覆 src_port 五策略）+ 单数 `media.src_port` 动态（cases 只覆 `medias[].src_port`） | G-SIP-9 |
| 负例收窄 | 删 2 处负例 `notes` 键（严格两键口径） | G-SIP-2 |
| RTP 字段面 | 复核 tshark `rtp.*` 是否可用；可用则收编替代 frames pin | G-SIP-7 |

**B′（框架面）**：`CheckProtoFlat` 的**游离顶层未知键通用门**（G-SIP-1，等框架级 unknown-key 白名单，不单独立项）/ **SIPS 5061 FieldContract 双载口变体**（G-SIP-4，需框架支持单协议多缺省端口）/ **SDP future-bleed**（G-SIP-3，明确不解决）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免** ✓（设计 §12.3 会话表 s1/s2/s3；本协议 `sessions` 是**层内结构**（`SIPConfig.Sessions`），语义 = **每项一条独立 TCP 信令连接**，与 CORE_MEMORY §3.1「`sessions[]` 显式声明」**完全同形**——不是 opcua 那种"层内选择器"的形态差异，故**无形态声明缺口**）。

**多流并发**：由策略级 `strategy_fc {"type":"flows","value":N}` 承载（12 例用 N=2）；**并发交错**（`concurrent`）路径为例外不启用——多事务交错由 #54 的**顺序表达**覆盖（同连接内事务序重叠，非引擎并发）。

**单包多载荷**：**部分适用**——RFC 5621 multipart/mixed（#42）在**一条 SIP 消息内**承载两个体（SDP + application/octet-stream），是"单消息多载荷"的真实形态，**已覆**；RTP 帧则是"一帧一载荷"（无多载荷形态），**不适用**。**如实声明，不硬凑**。

**流关联（§3.8-3.10）**：**不豁免**——本协议是"一条信令关联零到多条媒体流"的典型（设计 §12.3 三件事全齐：归属=FlowID 前缀、触发=EmitMedia 消息、端口=SDP/显式/动态三路）。

## 7. 实现后执行建议

1. **修复顺序（代码阶段）**：①**先修 M-1**（`sip.go:338` 第二参数 `spec.DstMAC` → `spec.SrcMAC`），**同批加 L2 断言用例**（否则修复无证据）；②补 A′ 静默语义面 4 例 + RST 1 例；③补动态整格 2 空格；④补 RTP 参数面 3 例；⑤收窄 2 处负例 `notes`；⑥至少一例启用 `nic_capture`；⑦全量复跑。
2. **实测顺序**：先 #1（五消息基线 + 4 条 frame 断言），再 #4（头补全生成面），再 #10（MSS 三段 `tcp.len` 1460/1460/315），再 #11（RTP offset 42 `0x80`），再 #58（双会话独立 Call-ID/端口），再 #87（42 包复合大场景），最后 #81（TLS 16 包形状）。
3. **二进制与 HEAD 同代确认（门2③）**：`find trafficgen -name '*.go' -newer <server-binary>` 无输出；**M-1 修复后必须重编服务再跑**（否则跑的是旧二进制，L2 断言会红或假绿）。
4. **门2② 全量**：`CASE_PROTO=sip` 全量（96 例，不是增量）；门2④ 反查绿后进 P6。
5. **门2① 顶层旧键**：收官自查行「非负例顶层键 = 0」——机读口径 = 排除 `sip_flat_presence`（判死对象）后，96 例顶层键 ⊆ `{layers, strategy_fc, group_id}`。
6. **任何 RFC 条款号的具体引用须有规范原文证据**（G-SIP-8 纪律）。

## 8. 存量审计（96 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/sip.json` **96 例**：87 正 + 9 负；28 例精确 `packet_count`（全部命中包数公式 28/28）、59 例 `min_packets`（56 例公式值 ≥ 下界 + 2 例宽松下界 + 1 例 #10 分段例外）；9 例负例覆盖 **7 条独立锚词**；**314 条 fields + 8 条 frames** 断言；顶层键 **94 例纯 `{layers}`** + 2 例合法例外；`strategy_fc` 12 例；`nic_capture` **0 例**。

### 8.2 现状矛盾点（代码阶段前诚实登记）

1. **M-1：`sip.go:338` 下行信令包 L2 目的 MAC 取值错**（`spec.DstMAC, spec.DstMAC` 应为 `spec.DstMAC, spec.SrcMAC`）——影响全部 raw 链下行响应帧（**84 例**的帧内容，**帧数不变**——机读：90 例 raw 链中 84 例含下行响应消息）。**存量 96 例零 L2 断言 + raw-IP Emit 补偿逻辑只在空 MAC 时生效 + 唯一 L2 单测只查 EtherType**，三条独立原因叠加导致未被捕获。设计 §3.8 已给修复点与影响面。
2. **NIC 路径零覆盖**：`nic_capture` 计数 = 0。双输出契约在**文档层面成立**（同一 cases 与断言集），但 **NIC 一路今日无用例证据**（G-SIP-6）。
3. **RTP 字段面不可用**：`rtp.*` 在 tshark 3.6.14 上无效（前身记录，本版沿用），RTP 断言走 frames pin offset 42。**该结论待复核**（G-SIP-7）。
4. **动态整格 2 空格**：`sessions[].dst_port` 动态与单数 `media.src_port` 动态今日零用例（G-SIP-9）。
5. **负例 `notes` 键 2 处**：与严格两键口径不符（G-SIP-2）。
6. **SDP future-bleed**：`scanSDPMediaPorts`/`scanSDPDirection` 扫全 dialog，re-INVITE 后的端口/方向会前渗（G-SIP-3，**明确不解决**，代码自认）。
7. **静默语义 4 类零用例**：`Method`+`StatusCode` 双给 / `Direction` 非法 / 纯响应 dialog / 响应先于请求（G-SIP-5）。
8. **RTP 参数面零用例**：`payload_type`（恒 0）/`frame_size`（恒 160）/`sample_rate`/FileSource 二进制（G-SIP-7）。
9. **RST 零用例**：传输层异常结束无断言（G-SIP-5）。
10. **结果产物无 pcap 留档（G-SIP-10）**：`trafficgen/docs/protocol-pcap-test/sip.md`（**tracked**）写 "Cases: 96 — pass 96, fail 0, error 0"，末次提交 `bbf4f7c`（**2026-09-20**，**晚于**判死提交 `0417be5` 2026-09-13——故**不属**"早于判死提交"的过期情形）；但其链接的 `docs/protocol-pcap-test/sip/` 目录**不存在**（0 个 pcap，`.gitignore:88 *.pcap` 使 pcap 从不入库）。**故 96/96 数字无 pcap 留档佐证；本车道今日未复跑该套件**，不以任何形式引用该产物作为"今日已复跑"依据。归属**代码阶段**（P5 重跑后重生成）。口径对齐 pcep G-PCEP-11 / opcua G-OPCUA-10。

### 8.3 逐条去向表（96 行，按族归并）

| 族 | 用例 | 去向 | 代码阶段动作 |
|---|---|---|---|
| 基线 | #1 | **保留** | 可补 L2 断言（M-1 修复后） |
| 判死/静态 | #2/#3 | **保留** | 删 `notes`（G-SIP-2） |
| 头补全 | #4/#5 | **保留** | — |
| 方法枚举 | #6/#7 | **保留** | — |
| 响应码 | #8/#23/#55/#56/#88–#94 | **保留** | 冷码长尾 A′ 扩充（G-SIP-5） |
| 体/分段 | #9/#10/#42/#95 | **保留** | — |
| RTP | #11–#14/#72/#73/#75/#76 | **保留** | RTP 参数面 A′（G-SIP-7） |
| 地址族/端口 | #15/#16/#57/#71 | **保留** | — |
| 动态 | #17/#64–#70 | **保留** | 补 2 空格（G-SIP-9） |
| 空/边界 | #18/#96 | **保留** | — |
| 场景族 | #19–#57 | **保留** | — |
| sessions | #58–#60/#80 | **保留** | — |
| sessions 负例 | #61–#63 | **保留** | — |
| medias | #72/#73/#75/#76 | **保留** | — |
| medias 负例 | #74 | **保留** | — |
| NAT | #77–#80 | **保留** | — |
| TLS/事件面 | #81–#83 | **保留** | — |
| 载体负例 | #84–#86 | **保留** | — |
| 复合大场景 | #87 | **保留** | 可补 NIC 开关（G-SIP-6） |

**0 作废、0 等价覆盖**——96 例**全部保留**（无改写需求：ID/包数/断言均与实现一致；唯二动作是 M-1 修复后**新增** L2 断言与 G-SIP-2 的 `notes` 收窄，均为**加法/收窄**而非改写语义）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

现有 `check_sip`（`trafficgen/tools/coverage_gate.py:744`）已覆盖 96 例场景面 + 4 键覆盖 + 2 锚词面。建议在**主线程合入后**补登下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['sip']) == 96` 且 ID 集合 = §2 九十六项，顺序一致 | 本契约 §2 |
| 2 | 非负例 `spec_json` 顶层键 ⊆ `{layers, strategy_fc, group_id}`；**排除 `sip_flat_presence`**（判死对象）后非负例顶层非 `layers` 键计数 == 0 | 本契约 §1/§8.1；设计 §12.1 |
| 3 | 正例包数满足 §1 公式（28 例精确 `packet_count` 逐例相等；59 例 `min_packets` 公式值 ≥ 下界，**#10 与 #55/#56 三例为已登记例外**） | 设计 §9 |
| 4 | 9 负例 `error_contains` 集合 == **7 条锚词集**：`{"top-level sip sub-config", "static four-tuple", "sip: sessions and dialog are mutually exclusive", "sip: media and medias are mutually exclusive", "media is not supported on a tcp/tls sip chain", "sessions are not supported on a tcp/tls sip chain", "sip: sips uri requires a tls layer in the chain"}` | 本契约 §4；设计 §7 |
| 5 | 7 例负例 `expect` 键 == `{expect_error, error_contains}`（**今日 2 例含 `notes`，G-SIP-2 收窄后转真**） | 本契约 §4 |
| 6 | 层链分布 == `[ip,sip]` 90 / `[ip,tcp,tls,sip]` 4 / `[ip,tcp,sip]` 2 | 本契约 §1 |
| 7 | 12 例 `strategy_fc.value == 2` 且包数 == 2 × 单流公式 | 设计 §12.12 |
| 8 | 每正例至少一条断言落在 `sip.*` 或 `udp.*` 或 `tcp.*` 字段（**非仅 `negotiated`/`terminates`**） | 本契约 §3 |
| 9 | 动态五策略整格：`sessions[].src_port` 出现 inc/rand/list/fixed/pattern 各至少 1 例（#64–#68） | 设计 §12.12；CORE_MEMORY §12.15 |
| 10 | **M-1 修复后**：含下行响应消息的 raw 链用例**至少 1 例**断言下行帧 L2 目的 MAC == `spec.SrcMAC`（**今日为红**，如实标红） | 设计 §3.8；本契约 §6.2 |
| 11 | **NIC 路径**：至少 1 例含 `nic_capture`（**今日为红**，如实标红） | 本契约 §1；G-SIP-6 |

**红项如实标注**：第 10、11 条**今日为红**（M-1 未修 + `nic_capture` 零覆盖），**不得申报"今日已过"**；第 5 条**今日部分红**（2 例含 `notes`）。其余 8 条**今日可从 cases 直接机读判定为绿**。

**另注意**：`trafficgen/docs/protocol-pcap-test/sip.md` 的 "96/96 pass" 是**2026-09-20 的产物**，其链接的 `docs/protocol-pcap-test/sip/` 目录**不存在**（0 个 pcap，`.gitignore:88` 使 pcap 从不入库）——该数字**无 pcap 留档佐证，本车道今日未复跑**，**不得作为"今日已复跑"依据**（G-SIP-10，口径对齐 pcep G-PCEP-11 / opcua G-OPCUA-10）。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #104 sip as-built 定稿。**96 例机读全量审计**（形状分布 / 包数公式 85/87 满足 / 断言面 314 fields + 8 frames / 26 种字段）；§2 逐 ID 索引表（96 行，T-编号一一对应）；§3 正例逐族断言契约（含 8 条 frames 逐条 hex 含义）；§4 负例契约（9 例 **7 条独立锚词** + 双路闭合表 + 10 条未入例分支）；§5 三源回指 + 对账两行（**105 = 73 覆 + 4 不适用 + 2 待实现边界 + 26 立项**）；§6 P3 固定动作（§3.15 三项 + A′/B′ + 3.14 豁免）；§7 执行建议；§8 存量审计（**96/96 保留，0 作废**，10 条矛盾点）；§9 覆盖反查门建议 11 行（**第 10/11 条今日标红**）。**M-1 confirmed finding**（`sip.go:338` L2 目的 MAC）与 **G-SIP-1…G-SIP-10** 见配套设计 §14。仅文档，未动 JSON/代码。自审 3 轮，末轮干净。
