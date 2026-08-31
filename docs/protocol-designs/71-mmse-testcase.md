# MMSE（多媒体消息服务封装，Multimedia Messaging Service Encapsulation）测试用例契约

> 版本：v2.0.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/71-mmse-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/mmse.json`（proto key：`mmse`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：**独立隔离对抗审查已完成**（v2.0.1 定稿：独立审查 agent 三向审计 10 项清单（2M/8N）→ 修复 → 复验 9.5/10 → 复验新发现 R1 修复 → 抽查确认 clean；审查/修复记录见 §9 修订记录 v2.0.0/v2.0.1）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 38 个唯一语义 ID：27 个正例 + 11 个负例。派生规则：设计 §3 每个编码条款（原语/字段/PDU/值域）、§3.6 multipart 每条不变式、§5 每条事务关联取材规则、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 WAP-209/OMA-MMS-ENC）声明范围。**一个用例只验证一个协议行为**（v1.1 §7 原子原则）：8 类 PDU 各一例、每个值域组一例、每个编码原语形态一例、每条关联规则一例、每个错误分支一例。

当前 JSON 只保留一个 `mmse_neg_unregistered` 注册前置占位：`proto=mmse`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 38 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 MMSE 行为通过。注册后移除占位，按本文 §2 顺序补入 27 个正例与 11 个负例。

**TSHARK 实测基线（本机 3.6.14，构造 pcap 实证，非臆造）**：本机 tshark **有 MMSE 专用 dissector（解析器）**（`tshark -G protocols` 核验：MMSE/mmse），且 `Content-Type: application/vnd.wap.mms-message` 的 HTTP **请求体与响应体均自动内层解码**为 MMSE（实证：8 类 PDU + IPv6 各一帧全部解出）。实测可用断言字段：

- `mmse.message_type`（FT_UINT8，hex 显示，如 `0x80`）、`mmse.transaction_id`、`mmse.mms_version`（字符串 `1.2`）、`mmse.message_class.id`（`0x80`–`0x83`）、`mmse.priority`（`0x80`–`0x82`）、`mmse.delivery_report`/`mmse.read_report`/`mmse.report_allowed`/`mmse.sender_visibility`（`0x80`/`0x81`）、`mmse.response_status`、`mmse.response_text`、`mmse.status`、`mmse.read_status`、`mmse.message_id`、`mmse.message_size`（十进制）、`mmse.content_location`、`mmse.from`/`mmse.to`/`mmse.cc`/`mmse.bcc`/`mmse.subject`、`mmse.date`/`mmse.expiry.rel`/`mmse.expiry.abs`/`mmse.delivery_time.abs`（时间显示含本地时区——**值断言一律用 `nonzero`**，精确性走 frames hex）。
- multipart 体（实测经 WSP 解码器）：`wsp.header.content_type`、`wsp.header.content_id`、`wsp.header.content_location`、`wsp.parameter.name`、`wsp.parameter.start`、`wsp.parameter.charset`（显示 `UTF-8`）、`wsp.parameter.upart.type`（multipart/related 的 type 参数**值**，如 `application/smil`；勿与 `wsp.parameter.type`——参数**码**字段——混淆）、`wsp.multipart`（part 序号）。**注意**：一帧内多实例字段在 `tshark -T fields` 输出为**逗号拼接单串**（如 body 帧的 `wsp.header.content_type` = `application/vnd.wap.multipart.related,application/smil,text/plain,image/jpeg`），精确断言按整串匹配，part 数固定的 fixture 才可用。
- HTTP/IP：`http.request.method`、`http.request.uri`、`http.content_type`、`http.content_length`、`http.file_data`、`http.response.code`、`ip.version`、`ipv6.nxt`、`tcp.stream`、`tcp.len`、`tcp.flags`。

**实测 dissector 行为注意**：①PDU 携带 0x90 头且版本显式 ≥1.1 时字段名为 `mmse.read_report`（`mmse.read_reply` 仅在版本头缺失时出现，设计 §3.4）——本版断言一律用 `mmse.read_report`。②part 头 Content-ID 携带 RFC 2392 角括号（AOSP 形态）时 tshark 产生 **Warning 级** expert（"Quoted-string value has been encoded with a trailing quote"），实测**不置 `_ws.malformed`**，`pcaptest` expert 检查（只看 malformed）通过——该 warning 为 dissector 对合法帧的伪影，不入白名单也不算失败。③`mmse.oversized_uintvar` 为 expert 错误信号（超长 Uintvar），正例 fixture 不触发（设计 §3.3 生成器上限 4B）。

**动态字段禁止硬编码**：Transaction-ID、Message-ID、日期用 `same_as_packet`（关联）与 `nonzero`；multipart 附件内容用 `nonzero` + frames hex（magic bytes 前缀）；值域枚举与预配置文本（地址、URI、Subject、Response-Text）允许精确值断言。

**接收侧行为显式不适用**（设计 §3.7 声明）：未知 PDU → m-send-conf(Error-unsupported-message)、m-notifyresp-ind(Unrecognised)、忽略不识别字段——接收侧反应性互操作非本版生成器范围，无用例、不进负例；设计 §1 声明的"本版不产生"形态（空串 / Application-header / charset≠106）归口 `mmse_neg_value_range` 拒绝（§5）。

**包数约定**（设计 §9 完成定义；实现期以实际输出校准，约定数字不当规范消息数）：单事务会话 = 3（握手）+ N（HTTP 消息帧，单段时 = 消息数）+ 3（挥手 FIN+ACK、FIN+ACK、末 ACK）；POST+200 单事务 = 8；GET+200 = 8；多事务 keep-alive = 3 + 2M + 3（M 为事务数）；多会话 = 各会话之和，第二会话起点 = 前会话总包数 + 1（设计 §5 多会话展开）。单会话内包位约定：1–3 握手、4 = 请求（POST/GET）、5 = 响应、6–8 挥手。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `mmse_send_req_ipv4` | 正 | §3.5/§4①：m-send-req 必选集 + multipart 完整体（含 Sender-Visibility=Show） | 8 |
| 2 | `mmse_send_conf_ok` | 正 | §3.5/§5：Ok、TID same_as、Message-ID；200≠MMS 状态 | 8 |
| 3 | `mmse_send_conf_error` | 正 | §3.7/§4①：Response-Status 错误分支 + Response-Text | 8 |
| 4 | `mmse_notification_ind` | 正 | §3.5/§4②：通知必选集 + From（interval 形态 Expiry；content_length=99 逐字节复算） | 8 |
| 5 | `mmse_retrieve_conf_immediate` | 正 | §3.5/§4②：立即取回，TID 复用通知 | 16 |
| 6 | `mmse_notifyresp_deferred` | 正 | §3.5/§4③：Deferred + Report-Allowed | 16 |
| 7 | `mmse_acknowledge_ind` | 正 | §3.5/§4③：延迟链全链（Figure 5），新 TID 关联 | 32 |
| 8 | `mmse_delivery_ind_retrieved` | 正 | §3.5/§4④：递送报告必选集、MsgID 关联 | 16 |
| 9 | `mmse_delivery_ind_expired` | 正 | §3.7：Status=Expired 变体 | 8 |
| 10 | `mmse_read_rec_ind` | 正 | §3.5/§4⑤：读取报告 Read-Status=Read | 16 |
| 11 | `mmse_read_status_deleted` | 正 | §3.7：Read-Status=Deleted 变体 | 8 |
| 12 | `mmse_message_class_values` | 正 | §3.7：Message-Class 四值 | 8×4=32 |
| 13 | `mmse_encoding_text_string` | 正 | §3.3：Encoded-string-value 两形态 | 8+8 |
| 14 | `mmse_text_string_quote` | 正 | §3.3：Text-string Quote 形态（首字符分隔符前置 0x7F） | 8 |
| 15 | `mmse_encoding_long_integer` | 正 | §3.3：Long-integer 大端 4B/3B（定宽补零） | 8 |
| 16 | `mmse_encoding_value_length_uintvar` | 正 | §3.3：0x1F+Uintvar 长值长 | 8 |
| 17 | `mmse_time_absolute_form` | 正 | §3.3/§3.4：绝对 token 时间形态 | 8 |
| 18 | `mmse_send_req_optional_headers` | 正 | §3.4：可选头全集（Cc/Bcc/Visibility=Hide/Priority=High/Delivery-Time） | 8 |
| 19 | `mmse_from_insert_token` | 正 | §3.4/§3.5：From insert-address-token 形态 | 8 |
| 20 | `mmse_addressing_types` | 正 | §3.7：地址四形态（PLMN/IPv4/IPv6/邮箱） | 8 |
| 21 | `mmse_multipart_related_root` | 正 | §3.6：start/type 参数与 SMIL 根 | 8 |
| 22 | `mmse_multipart_part_headers` | 正 | §3.6：part 头（charset/name/ID/Location） | 8 |
| 23 | `mmse_multipart_media_part` | 正 | §3.6：媒体 part（well-known 码/magic bytes） | 8 |
| 24 | `mmse_http_keepalive_multi_transaction` | 正 | §5/§4⑥：同连接多事务 | 12 |
| 25 | `mmse_ipv6` | 正 | §2/§8：IPv6 单流 | 8 |
| 26 | `mmse_multi_session` | 正 | §5/§4⑦：多会话展开双四元组 | 24 |
| 27 | `mmse_mss_large_multipart` | 正 | §8：跨 MSS ≥3 段重组 | ≥12 校准 |
| 28 | `mmse_neg_carrier_config` | 负 | §7：配置错 | — |
| 29 | `mmse_neg_pdu_head_order` | 负 | §7：首三头顺序 | — |
| 30 | `mmse_neg_unknown_pdu_type` | 负 | §7：未分配或本版不产生 Message-Type（0x88–0x93） | — |
| 31 | `mmse_neg_missing_content_type` | 负 | §7：Content-Type 缺失/无体 PDU 带体 | — |
| 32 | `mmse_neg_multipart_structure` | 负 | §7：multipart 结构错 | — |
| 33 | `mmse_neg_mandatory_missing` | 负 | §7：必选字段缺失 | — |
| 34 | `mmse_neg_tid_correlation` | 负 | §7：TID 关联错配 | — |
| 35 | `mmse_neg_msgid_correlation` | 负 | §7：Message-ID 无来源 | — |
| 36 | `mmse_neg_sequence` | 负 | §7：事务顺序错 | — |
| 37 | `mmse_neg_length` | 负 | §7：长度错 | — |
| 38 | `mmse_neg_value_range` | 负 | §7：值域外取值、不产生形态/字段族 | — |
| — | `mmse_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

层链 `[tcp, http, mmse]`，无 VLAN/IP options/TCP options 时 HTTP 起行起点 IPv4 offset 54、IPv6 offset 74。断言分层：

1. **HTTP 骨架（fields 权威断言）**：`http.request.method=POST`（取回事务 `GET` 且 `http.request.uri` 等于通知 Content-Location 的路径）、`http.content_type=application/vnd.wap.mms-message`、`http.content_length` 等于 PDU 编码字节数（实测可精确断言，如 send-req 基线 326；通知 fixture 为逐字节复算值 99，见 §4.4）、响应 `http.response.code=200`。**HTTP 200 ≠ MMS 业务状态**：业务状态断言走 `mmse.response_status`/`mmse.status`。
2. **PDU 结构（fields + frames hex 双印证）**：PDU 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长（头集合由配置钉死，偏移可预算；实测样例：头集合 129B → PDU 起点 183）。PDU 首 3 字节固定 `8C <类型> 98`（Message-Type 码 0x8C + 类型值 + Transaction-ID 码 0x98，设计 §3.2 顺序规则），用 frames hex 在 PDU 起点断言：send-req `8c 80 98`、send-conf `8c 81 98`、notification `8c 82 98`、notifyresp `8c 83 98`、retrieve-conf `8c 84 98`、acknowledge `8c 85 98`、delivery `8c 86 8d`（无 TID，第三字节为版本码 0x8D）、read-rec `8c 87 98`。字段值断言走 `mmse.*`。
3. **multipart（fields + frames hex）**：父 Content-Type 断言 `wsp.header.content_type` 整串（part 数固定）；start 参数 `wsp.parameter.start`；part 头 `wsp.header.content_id`/`wsp.header.content_location`/`wsp.parameter.name`/`wsp.parameter.charset`；part 序号 `wsp.multipart`。媒体数据 magic bytes 用 frames hex（JPEG `ff d8 ff`）。**TCP 分段边界不是 PDU/multipart 边界**：跨段时先按 `tcp.stream` 重组再断言。
4. **has_payload 语义**：权威断言 = `http.file_data` nonzero + `mmse.message_type` 存在；不以包数或 PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放，第二会话 TCP 握手包号 = 前会话总包数 + 1；跨会话关联（TID/MsgID）用 `same_as_packet`（全局包位）断言，多会话 fixture 的包位按此推算。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；包位按 §1/§3 约定。

1. **`mmse_send_req_ipv4`**（8）：`192.0.2.71:40710 → 198.51.100.71:80`。包 4 断言 `http.request.method=POST`、`http.content_type=application/vnd.wap.mms-message`、`http.content_length` nonzero、`mmse.message_type=0x80`、`mmse.transaction_id` nonzero、`mmse.mms_version=1.2`、`mmse.date` nonzero、`mmse.from=+8613800138000/TYPE=PLMN`、`mmse.to=+8613911223344/TYPE=PLMN`、`mmse.message_class.id=0x80`、`mmse.expiry.rel` nonzero、`mmse.priority=0x81`、`mmse.sender_visibility=0x81`（Show，显式值例，设计 §6 fixture 同值）、`mmse.delivery_report=0x80`、`mmse.read_report=0x80`、frames hex PDU 起点 `8c 80 98`；包 5 响应（send-conf，本例只断 HTTP 骨架 `http.response.code=200`，conf 内容归用例 2）。
2. **`mmse_send_conf_ok`**（8）：同会话形状。包 5 断言 `mmse.message_type=0x81`、`mmse.transaction_id` `same_as_packet` 4（请求/确认同 TID，设计 §5 取材）、`mmse.response_status=0x80`（Ok）、`mmse.message_id` nonzero、frames hex `8c 81 98`。
3. **`mmse_send_conf_error`**（8）：包 5 断言 `mmse.response_status=0x82`（Error-service-denied，§3.7 值域）、`mmse.response_text` 精确配置串（如 `Err: service denied`）、`mmse.message_id` 缺省可接受（未接受时 Message-ID 非必须，表 2）；`http.response.code=200` 仍成立（HTTP 200 ≠ MMS 状态）。
4. **`mmse_notification_ind`**（8）：MMSC→MS 回放连接 `198.51.100.71:40711 → 192.0.2.72:80`。包 4 断言 `mmse.message_type=0x82`、`mmse.transaction_id` nonzero（配置值 `MMSC-N-0007`，11B）、`mmse.mms_version=1.2`、`mmse.from=+8613900139000/TYPE=PLMN`、`mmse.message_class.id=0x80`、`mmse.message_size=4800`、`mmse.expiry.rel` nonzero（interval 形态，表 3）、`mmse.content_location=http://mmsc.example/mms/MSG20260901001`、frames hex `8c 82 98`；`http.content_length=99`——**逐字节复算**（设计 §3.5 公式 + §3.3 定宽策略；TID 与可选头集合由 fixture 钉死：可选头仅 From、无 Subject）：类型 `8c 82` 2B + TID `98`+11+`00` 13B + 版本 `8d 92` 2B + From `89 1a 80`+24B+`00` 28B + Class `8a 80` 2B + Size `8e 03 00 12 c0` 5B（4800=0x0012C0，定宽 3B）+ Expiry `88 05 81 03 0e 10 00` 7B（921600=0x0E1000，定宽 3B，interval 形态）+ Content-Location `83`+38B+`00` 40B = **99B**（必选集 71B + From 28B），精确值证明无消息体。
5. **`mmse_retrieve_conf_immediate`**（16 = 通知 8 + 取回 8）：会话 1 同用例 4（TID=t2）；会话 2 包 12 为 GET：`http.request.method=GET`、`http.request.uri` 与通知 content_location 路径一致；包 13 断言 `mmse.message_type=0x84`、`mmse.transaction_id` `same_as_packet` 4（立即取回复用通知 TID，设计 §3.5/§5）、`mmse.date` nonzero（必选）、`mmse.message_id` nonzero、multipart 存在（`wsp.header.content_type` 整串含 `application/vnd.wap.multipart.related`）。
6. **`mmse_notifyresp_deferred`**（16 = 通知 8 + 确认 8）：会话 2 包 12 断言 `mmse.message_type=0x83`、`mmse.transaction_id` `same_as_packet` 4（通知→确认同 TID）、`mmse.status=0x83`（Deferred，§3.7）、`mmse.report_allowed=0x80`、frames hex `8c 83 98`。
7. **`mmse_acknowledge_ind`**（32 = 通知 8 + 确认 8 + 取回 8 + 确认 8，延迟链 Figure 5）：会话 3 包 20 为 GET、包 21 断言 `mmse.message_type=0x84`、`mmse.transaction_id` 为配置显式新 TID（延迟取回新事务，与通知 TID 取不同配置值，两值精确断言互异，设计 §3.5）；会话 4 包 28 断言 `mmse.message_type=0x85`、`mmse.transaction_id` `same_as_packet` 21（ack 取自紧邻前一个 M-Retrieve，表 6）、`mmse.report_allowed=0x80`、frames hex `8c 85 98`。
8. **`mmse_delivery_ind_retrieved`**（16 = 提交 8 + 递送报告 8）：会话 1（POST send-req=4、200 send-conf=5，Message-ID 生成）；会话 2 包 12 断言 `mmse.message_type=0x86`、`mmse.message_id` `same_as_packet` 5（跨事务回指 send-conf 的 Message-ID，设计 §5）、`mmse.to=+8613800138000/TYPE=PLMN`、`mmse.date` nonzero、`mmse.status=0x81`（Retrieved）；frames hex `8c 86 8d`——**第三字节即版本码 0x8D 证明 Message-Type 后无 Transaction-ID**（表 7 无此字段）。
9. **`mmse_delivery_ind_expired`**（8）：同形状（Message-ID 精确配置值断言），`mmse.status=0x80`（Expired，§3.7 值域）。
10. **`mmse_read_rec_ind`**（16 = 提交 8 + 读取报告 8）：会话 2 包 12 断言 `mmse.message_type=0x87`（OMA-MMS-ENC 1.1 PDU）、`mmse.transaction_id` nonzero、`mmse.message_id` `same_as_packet` 5（回指被读消息）、`mmse.read_status=0x80`（Read）、frames hex `8c 87 98`。
11. **`mmse_read_status_deleted`**（8）：同形状，`mmse.read_status=0x81`（Deleted-without-being-read）。
12. **`mmse_message_class_values`**（32 = 4 fixture × 8）：四个 m-send-req 分别 `mmse.message_class.id` = `0x80`/`0x81`/`0x82`/`0x83`（Personal/Advertisement/Informational/Auto）；Auto fixture 同时断言 `mmse.delivery_report=0x81` 且 `mmse.read_report=0x81`（表 1：class=Auto 时两报告必为 No，设计 §3.7）。
13. **`mmse_encoding_text_string`**（8+8）：fixture A 的 Subject 走裸 Text-string（`mmse.subject=MMSE check`）；fixture B 走 VL+charset 形态（`Value-length Char-set Text-string`，Char-set=Short-integer 106|0x80=0xEA，UTF-8 多字节文本）断言 `mmse.subject` 精确解码值 + frames hex Subject 值区前缀 `96 0c ea`（字段码 0x96 + 值长 12 + Char-set 0xEA，实测）。To/From 地址同为 Encoded-string-value 裸形态（设计 §3.4）。part 头内的 charset **参数**（`81 ea`，参数码 0x01）归用例 22 断言——两处编码不同形，勿混。
14. **`mmse_text_string_quote`**（8）：send-req fixture 的 Subject 文本首字符为分隔符（`"quoted"`，首字节 0x22）：frames hex 断言 Subject 值区前缀 `96 7f 22`（字段码 0x96 + Quote 0x7F + 分隔符首字符 0x22，设计 §3.3 Quote 规则）+ `mmse.subject` 精确值 `"quoted"`（0x7F 为传输层 Quote 前缀，解码时剥离，仅保留文本自身的引号字符）。
15. **`mmse_encoding_long_integer`**（8）：包 4 断言 `mmse.date` nonzero（4B Long-integer）+ frames hex PDU 内 Date 值区 `85 04 <大端 4B>`；通知侧 `mmse.message_size=4800`（3B Long-integer `8e 03 00 12 c0`，定宽补零策略见设计 §3.3）。
16. **`mmse_encoding_value_length_uintvar`**（8）：send-req 的 Content-Type 参数集使值长 >30：frames hex 断言 Content-Type 头 `84 1f <uintvar>`（0x1F+Uintvar 形态，实测样例 `84 1f 20`）；multipart partNum≥2 的 `dataLen` Uintvar 双字节形态（frames hex）。
17. **`mmse_time_absolute_form`**（8）：send-req 携带 `Expiry` 绝对形态与 `Delivery-Time` 绝对形态（均为 `Value-length 0x80 <4B Long-integer>`，设计 §3.3/§3.4）：断言 `mmse.expiry.abs` nonzero、`mmse.delivery_time.abs` nonzero + frames hex 值区前缀 `88 06 80 04`（Expiry，字段码 0x88 + 值长 6 + Absolute-token 0x80 + Long-integer 长度 4）与 `87 06 80 04`（Delivery-Time，字段码 0x87）。
18. **`mmse_send_req_optional_headers`**（8）：包 4 断言 `mmse.cc`/`mmse.bcc` 各一实例（多收件人）、`mmse.sender_visibility=0x80`（Hide）、`mmse.priority=0x82`（High，值域第二值例，§3.7）、`mmse.delivery_time.rel` nonzero（Delivery-Time 出现）。
19. **`mmse_from_insert_token`**（8）：send-req fixture 的 From 走 insert-address-token 形态（配置 `"from": {"insert_token": true}`，设计 §3.4/§6）：frames hex 断言 From 值区 `89 01 81`（字段码 0x89 + Value-length 0x01 + insert-token 0x81）；`mmse.message_type=0x80`、`mmse.to` 照常断言；`mmse.from` 对 insert-token 形态不作地址值断言（该形态无地址文本，字段渲染归实现期校准，frames hex 为权威断言）。
20. **`mmse_addressing_types`**（8）：同一 m-send-req 的 To 双实例 = `+358501234567/TYPE=PLMN` 与 `Joe User <joe@user.org>`、Cc=`195.153.199.30/TYPE=IPv4`、Bcc=`FEDC:BA98:7654:3210:FEDC:BA98:7654:3210/TYPE=IPv6`（四形态一次断言，§3.7 地址模型；多 To 实例合法，设计 §7）；`mmse.to` 按线上顺序整串匹配（多实例逗号拼接，§1）、`mmse.cc`/`mmse.bcc` 精确值。
21. **`mmse_multipart_related_root`**（8）：包 4 断言 `wsp.header.content_type` 整串以 `application/vnd.wap.multipart.related` 开头、`wsp.parameter.start=<smil.smil>`、`wsp.parameter.upart.type=application/smil`（type 参数值字段，实测）；SMIL 根 part `wsp.header.content_id=<smil.smil>` 与 start 一致（RFC 2387 关联，设计 §3.6）。
22. **`mmse_multipart_part_headers`**（8）：包 4 断言文本 part：`wsp.parameter.name=text_1.txt`、`wsp.parameter.charset=UTF-8`、`wsp.header.content_id=<text_1.txt>`、`wsp.header.content_location=text_1.txt`（逗号串含各值）；`wsp.multipart` 序号串（part 数固定）。
23. **`mmse_multipart_media_part`**（8）：包 4 断言 `wsp.header.content_type` 整串含 `image/jpeg`（well-known 码 0x9E，无 charset 参数）；frames hex 断言 part 数据区 JPEG magic `ff d8 ff`；`http.file_data` nonzero。
24. **`mmse_http_keepalive_multi_transaction`**（12 = 3+2×3+3）：单 `tcp.stream` 承载 3 笔事务（POST send-req→200 send-conf、GET→200 retrieve-conf、POST acknowledge→200），可执行判定字段：①无 `Connection: close`——`http.connection` 全帧无 `close` 值（fields `distinct_exclude`；未发送该头时字段全帧为空，同样满足）；②请求/响应严格交替（无 pipelining）——按包位断言：包 4/6/8 `http.request.method`=POST/GET/POST、包 5/7/9 `http.response.code`=200（每请求包位后紧跟响应包位，下一请求不得先于上一响应出现）；③Content-Length 自洽——每个承载 PDU 的 POST 请求帧与 200 响应帧 `http.content_length` 与对应 PDU 编码字节数精确相等（GET 请求无 body、无 Content-Length；三笔 PDU 长按设计 §3.5 公式在 fixture 内逐字节可复算）；send-req TID 与取回事务 TID 取不同配置值（互异），acknowledge TID `same_as_packet` retrieve-conf（表 6 关联）。
25. **`mmse_ipv6`**（8）：`2001:db8::71 → 2001:db8::1:80` 对端 80；断言 `ipv6.nxt=6`、`mmse.message_type=0x80` 与同值域字段解码同 v4 fixture、frames hex PDU 起点前缀 `8c 80 98`（PDU 字节与 v4 一致，仅外层 IP 头不同）。
26. **`mmse_multi_session`**（24 = 发送链 8 + 通知 8 + 取回 8）：会话 1（UA 提交，src_port=40710）、会话 2（MMSC→接收方通知，四元组独立）、会话 3（接收方 GET 取回）；断言三个 `tcp.stream` distinct、会话 2 握手包号 = 9（8+1）、发送链 TID 与接收链 TID `distinct_values`（互不串用）、MsgID 跨会话回指按 `same_as_packet` 全局包位。
27. **`mmse_mss_large_multipart`**（≥12，按段数校准）：multipart 附件 ≥3KB、MSS 压至 536 使 PDU 跨 ≥3 TCP 段。可执行判定字段：逐段 `tcp.len` 数值断言——请求侧满 MSS 段 `tcp.len`=536、请求侧末段 `tcp.len`=HTTP 请求消息总长−536×满段数（>0；请求消息总长 = 头集合字节长 + `http.content_length`，按 fixture 可复算）；Σ请求侧数据段 `tcp.len` = HTTP 请求消息总长；按 `tcp.stream` 重组后 `http.content_length` = 全部请求段 payload 之和、`wsp.header.content_type` 整串完整（multipart 重组后可解）、JPEG magic `ff d8 ff` 在末段 frames hex。

## 5. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，packet_count 为 `—`，不加 `notes`/`min_packets`/字段断言。锚词与设计 §7 表一一对应：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `mmse_neg_carrier_config` | 层链缺 http（tcp→mmse 直连）、承载 Content-Type 非 application/vnd.wap.mms-message、端口/载体矛盾 | `carrier`、`content-type`、`layer` 或 `port` |
| `mmse_neg_pdu_head_order` | Transaction-ID 先于 Message-Type、MMS-Version 缺失、首字段非 0x8C | `order`、`header` 或 `message-type` |
| `mmse_neg_unknown_pdu_type` | Message-Type 取未分配值（0x00–0x7F 或 >0x93），**或已分配但本版不产生值（0x88–0x93，设计 §1 边界）——两类同归口本行** | `message-type`、`unknown` 或 `pdu` |
| `mmse_neg_missing_content_type` | m-send-req/m-retrieve-conf 缺最后 Content-Type；无体 PDU 声明 content | `content-type` 或 `body` |
| `mmse_neg_multipart_structure` | headersLen/dataLen 越界、partNum=0 但有 parts、part 数不符、start 引用不存在 Content-ID | `multipart`、`part` 或 `start` |
| `mmse_neg_mandatory_missing` | To/Cc/Bcc 全缺或 From 缺失；通知缺 Class/Size/Expiry/Location；send-conf 缺 Response-Status；delivery-ind 缺 MsgID/To/Date/Status | `mandatory`、`missing` 或 `field` |
| `mmse_neg_tid_correlation` | send-conf/notifyresp/acknowledge 的 TID 与请求侧不一致 | `transaction`、`correlation` 或 `match` |
| `mmse_neg_msgid_correlation` | delivery-ind/read-rec-ind 的 Message-ID 无来源 send-conf | `message-id`、`correlation` 或 `match` |
| `mmse_neg_sequence` | acknowledge 先于 retrieve、notifyresp 无前置 notification、send-conf 无前置 send-req | `sequence`、`state` 或 `order` |
| `mmse_neg_length` | Content-Length≠PDU 字节、Long-integer 长度 >4 或 =0、Uintvar >4B、Value-length 与实际不符、TID >32B | `length`、`uintvar` 或 `overflow` |
| `mmse_neg_value_range` | Priority=0x83、Status=0x8F、Class=0x84、Response-Status=0x89 等域外值；**Reply-Charging 字段族（0x9C–0x9F）或本版不产生编码形态（空串 / Application-header / charset≠106，设计 §1 声明）出现在配置——同归口本行** | `value`、`range` 或 `status` |

合法协议事件不进负例（防误报）：m-send-conf 错误 Response-Status（正例 3）、Status=Expired/Deferred（正例 6/9）、From insert-token（正例 19）、Text-string Quote 形态（正例 14）、MMS 1.0/1.1 字段混用（§6.7 同主版本互通）、多 To/Cc/Bcc 实例（正例 20）、Content-ID 角括号 warning（§1 实测伪影）。接收侧互操作反应显式不适用（设计 §3.7 声明，无用例不进负例）；Application-header / 空串 / charset 高值按设计 §1 声明归口 `mmse_neg_value_range` 拒绝，不再列为本条合法事件。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–11（正，8 类 PDU 全覆盖）；28–38（负，五类错误全分支） | 提交/通知/取回/确认/递送/读取全链；流关联与多流显式不适用（设计 §4 声明：消息体在带内、HTTP/1.1 单连接串行） |
| 性能 | 27 | 大 multipart 跨 MSS 重组 + Value-length/Uintvar/Long-integer 上界断言 |
| 数据场景 | 3、6、9、11、12、13–20；负 38 | Response-Status 正/错、Status/Read-Status/Class/Priority 值域（实测集合，设计 §4 收窄声明）、编码变体（文本三形态含 Quote、insert-token、绝对时间、长值长）、地址四形态、域外值与不产生形态/字段族拒绝 |
| 地址与流 | 1（v4 基线）、25（v6）、26（多会话双四元组） | v4+v6 必覆盖；跨会话关联用全局包位 same_as_packet |
| 业务 | 1–3（提交）、4–7（通知-取回链：立即+延迟）、8–11（递送-读取报告链）、24（长连接多事务）、26（多终端并行） | 现网 AOSP 事务服务同款流程（WAP-206 Figure 3/4/5）优先于教科书全 PDU 遍历 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/mmse.json` 通过；当前数组恰含 1 条 `mmse_neg_unregistered`：`proto=mmse`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `mmse` 层后：移除占位，按 §2 顺序补入 38 个语义用例；ID、顺序与设计 §9 完全一致。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields`（+ 按需 `frames`）；`fields` 只用 §1 实测存在的 tshark 字段（`mmse.*`/`wsp.*`/`http.*`/`ip.*`/`ipv6.nxt`/`tcp.*`），不伪造；时间字段（date/expiry/delivery_time）值断言一律 `nonzero`，精确性走 frames hex。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 跨会话/跨连接包号引用用多会话展开起点规则（§3.5）或 `tcp.stream`，不硬编码运行期值；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 多实例字段（`wsp.header.content_type` 等）精确断言按整串匹配，仅 part 数固定的 fixture 使用。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `mmse.json` 保持同一 38 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
mmse_send_req_ipv4
mmse_send_conf_ok
mmse_send_conf_error
mmse_notification_ind
mmse_retrieve_conf_immediate
mmse_notifyresp_deferred
mmse_acknowledge_ind
mmse_delivery_ind_retrieved
mmse_delivery_ind_expired
mmse_read_rec_ind
mmse_read_status_deleted
mmse_message_class_values
mmse_encoding_text_string
mmse_text_string_quote
mmse_encoding_long_integer
mmse_encoding_value_length_uintvar
mmse_time_absolute_form
mmse_send_req_optional_headers
mmse_from_insert_token
mmse_addressing_types
mmse_multipart_related_root
mmse_multipart_part_headers
mmse_multipart_media_part
mmse_http_keepalive_multi_transaction
mmse_ipv6
mmse_multi_session
mmse_mss_large_multipart
mmse_neg_carrier_config
mmse_neg_pdu_head_order
mmse_neg_unknown_pdu_type
mmse_neg_missing_content_type
mmse_neg_multipart_structure
mmse_neg_mandatory_missing
mmse_neg_tid_correlation
mmse_neg_msgid_correlation
mmse_neg_sequence
mmse_neg_length
mmse_neg_value_range
```

## 9. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（与旧设计稿配套的 14+6 ID 索引，WAP/WSP 双载体口径）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。索引表按 v1.1 原子原则重排为 36 条（25 正 + 11 负）：8 类 PDU 各一例 + 值域分例 + 编码原语分例 + multipart 三例 + 多事务/IPv6/多会话/MSS；以本机 tshark 3.6.14 构造 pcap 实证固化断言基线——**本机存在 `mmse` 专用 dissector 且 HTTP 请求/响应体经 `application/vnd.wap.mms-message` 自动内层解码**（46 个 `mmse.*` 字段 + `wsp.*` multipart 字段实测可见，与旧稿"无专用 dissector、走 raw payload"的口径相反）；实测确认 `mmse.read_report`/`mmse.read_reply` 的版本条件显示、Content-ID 角括号 Warning 伪影（不置 malformed）、多实例字段逗号拼接形态；负例锚词与设计 §7 十一行一一对应；新增 §3 PDU 起点偏移公式与首三头 frames hex 断言、§6 五层覆盖映射、§8 三方一致性表。状态：**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 10 项问题清单逐项修复（2 MAJOR / 8 MINOR）：
  - **M01**：用例 4 `http.content_length=88` 与自身断言矛盾（按 fixture 必选集 71B + From 28B 应为 99）→ 修正为 `99` 并给出逐字节复算（TID=`MMSC-N-0007` 11B、可选头仅 From、Expiry interval 921600、Size 4800 定宽 3B 全部钉死）；§3 第 1 条增补"通知 fixture 为逐字节复算值"说明。
  - **M02**：新增 `mmse_text_string_quote`（#14，Subject 首字符分隔符 → `96 7f 22` frames hex + 剥离 Quote 后精确值）与 `mmse_from_insert_token`（#19，`89 01 81` frames hex）两条正例（36→38，27 正 + 11 负）；空串 / Application-header / charset 高值按设计 §1 声明"本版不产生"，归口 `mmse_neg_value_range`。
  - **M03**：随设计 §3.5 修复——retrieve-conf 的 Transaction-ID 为必选（WAP-209 表 5），用例 5/7 的 TID 断言不受影响（same_as / 显式新 TID 均兼容必选口径）。
  - **M05**：值域断言收窄与补值——用例 1 增 `mmse.sender_visibility=0x81`（Show）、用例 18 增 `mmse.priority=0x82`（High）、用例 20 地址扩为四形态（补 /TYPE=IPv6 与邮箱双 To 实例）；§6 数据场景行同步改"实测集合"表述。
  - **M06**：§1 增"接收侧行为显式不适用"声明（未知 PDU 应答 / notifyresp Unrecognised / 忽略未知字段无用例）。
  - **M07**：§5 `mmse_neg_unknown_pdu_type` 行扩列"已分配但本版不产生值（0x88–0x93）同归口"，锚词不变；`mmse_neg_value_range` 行同步扩列 Reply-Charging 与不产生形态。
  - **M08**：用例 24 三条判定改为可执行字段映射（`http.connection` distinct_exclude close、按包位 4/6/8 请求 + 5/7/9 响应判严格交替、逐帧 `http.content_length` 精确值）；用例 27 "`tcp.len` 分布"改为逐段数值断言（满段 536 / 末段余量 / Σ=消息总长）。
  - **M09**：用例 15 `8e 03 00 12 c0` 依据设计 §3.3 新增的定宽补零策略（Message-Size 恒 3B），断言文本同步标注。
  - **M10**：随设计 §3.6 修复（+len(Uintvar(partNum)) 与部件数上界 127），无独立用例变更。
  - 三方一致性：§2/§8 与设计 §9 同步 38 ID 同序。
