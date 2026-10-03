# MMSE（多媒体消息服务封装，Multimedia Messaging Service Encapsulation）测试用例契约

> 版本：v2.1.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocols/mmse/design.md`（v2.1.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/mmse.json`（proto key：`mmse`；当前 JSON 已含 100 条静态语义用例）
> 状态：**v2.1.0 修复稿——按独立隔离审查（rr，v1.3 行为面全枚举 138 点）逐项修复，38 → 100 条（45 正 + 55 负），待审查者复验关闭**（v2.0.1 轮已 clean 关单，本轮为新契约 v1.3 的扩量修复轮）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。

## 1. 测试原则和承载边界

用例从设计 §2–§8 逐项派生，按 v1.3 行为面全枚举扩量，共 **100 个唯一语义 ID：45 个正例 + 55 个负例**（对应 rr 审查枚举的 138 行为面点）。派生规则：设计 §3 每个编码条款（原语/字段/PDU/值域）、§3.6 multipart 每条不变式、§5 每条事务关联取材规则、§7 每行错误处理（逐故障输入）在本文有对应断言；断言不得超出设计（并追溯到 WAP-209/OMA-MMS-ENC）声明范围。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）：8 类 PDU 各一例、每个值域组一例、每个编码原语形态一例、每条关联规则一例、**每个故障输入各一例**（负例 55 行 = 设计 §7 逐行拆分）。

**pcap/NIC 双输出契约（C-2）**：pcap 与 `port_group`/NIC 两种输出路径使用同一份用例契约——同一组语义 ID、同一包数约定、同一断言集（fields/frames），不含输出路径专有断言（与 64-cwmp/66-doh/68-hl7 同形）。

**复合值域扫描例的 spec 形态（N-4）**：#12（4 fixture）、#13（2 fixture）、#38（7 fixture）实现期为**单 ID 单 spec**——一个 spec 的 `sessions[]` 内 N 个独立会话各一笔事务（N×8 包），不拆多条 JSON 条目。

当前 JSON 已包含完整的 100 个语义用例（45 正例、55 负例），不含 `mmse_neg_unregistered` 注册前置占位；MMSE 层已注册且 translator 已有对应 `case "mmse"`，所有案例均按 `layers[]` 层链表达。WSP/WTP/WAP Push 仍是本版不实现的承载边界，不是 MMSE 层注册缺口。

**TSHARK 实测基线（本机 3.6.14，构造 pcap 实证，非臆造）**：本机 tshark **有 MMSE 专用 dissector（解析器）**（`tshark -G protocols` 核验：MMSE/mmse），且 `Content-Type: application/vnd.wap.mms-message` 的 HTTP **请求体与响应体均自动内层解码**为 MMSE（实证：8 类 PDU + IPv6 各一帧全部解出）。实测可用断言字段：

- `mmse.message_type`（FT_UINT8，hex 显示，如 `0x80`）、`mmse.transaction_id`、`mmse.mms_version`（字符串 `1.2`）、`mmse.message_class.id`（`0x80`–`0x83`）、`mmse.priority`（`0x80`–`0x82`）、`mmse.delivery_report`/`mmse.read_report`/`mmse.report_allowed`/`mmse.sender_visibility`（`0x80`/`0x81`）、`mmse.response_status`、`mmse.response_text`、`mmse.status`、`mmse.read_status`、`mmse.message_id`、`mmse.message_size`（十进制）、`mmse.content_location`、`mmse.from`/`mmse.to`/`mmse.cc`/`mmse.bcc`/`mmse.subject`、`mmse.date`/`mmse.expiry.rel`/`mmse.expiry.abs`/`mmse.delivery_time.abs`（时间显示含本地时区——**值断言一律用 `nonzero`**，精确性走 frames hex）。
- multipart 体（实测经 WSP 解码器）：`wsp.header.content_type`、`wsp.header.content_id`、`wsp.header.content_location`、`wsp.parameter.name`、`wsp.parameter.start`、`wsp.parameter.charset`（显示 `UTF-8`）、`wsp.parameter.upart.type`（multipart/related 的 type 参数**值**，如 `application/smil`；勿与 `wsp.parameter.type`——参数**码**字段——混淆）、`wsp.multipart`（part 序号）。**注意**：一帧内多实例字段在 `tshark -T fields` 输出为**逗号拼接单串**（如 body 帧的 `wsp.header.content_type` = `application/vnd.wap.multipart.related,application/smil,text/plain,image/jpeg`），精确断言按整串匹配，part 数固定的 fixture 才可用。
- HTTP/IP：`http.request.method`、`http.request.uri`、`http.content_type`、`http.content_length`、`http.file_data`、`http.response.code`、`ip.version`、`ipv6.nxt`、`tcp.stream`、`tcp.len`、`tcp.flags`。

**实测 dissector 行为注意**：①PDU 携带 0x90 头且版本显式 ≥1.1 时字段名为 `mmse.read_report`（`mmse.read_reply` 仅在版本头缺失时出现，设计 §3.4）——本版断言一律用 `mmse.read_report`。②part 头 Content-ID 携带 RFC 2392 角括号（AOSP 形态）时 tshark 产生 **Warning 级** expert（"Quoted-string value has been encoded with a trailing quote"），实测**不置 `_ws.malformed`**，`pcaptest` expert 检查（只看 malformed）通过——该 warning 为 dissector 对合法帧的伪影，不入白名单也不算失败。③`mmse.oversized_uintvar` 为 expert 错误信号（超长 Uintvar），正例 fixture 不触发（设计 §3.3 生成器上限 4B）。

**动态字段禁止硬编码**：Transaction-ID、Message-ID、日期用 `same_as_packet`（关联）与 `nonzero`；multipart 附件内容用 `nonzero` + frames hex（magic bytes 前缀）；值域枚举与预配置文本（地址、URI、Subject、Response-Text）允许精确值断言。

- **配置形状约束**：每个正例 `spec_json` 的地址/端口必须只出现在 `layers` 中的 `ip`/`ipv6` 与 `tcp`/`udp` 映射；`sessions[]` 若表达多会话局部四元组，使用设计文档 §6 的 `layer_overrides`（覆盖项仍按层归属），不得使用 session 内 `src_ip`/`dst_ip`/`src_port`/`dst_port` 平铺键。

**接收侧行为显式不适用**（设计 §3.7 声明）：未知 PDU → m-send-conf(Error-unsupported-message)、m-notifyresp-ind(Unrecognised)、忽略不识别字段——接收侧反应性互操作非本版生成器范围，无用例、不进负例；设计 §1 声明的"本版不产生"形态（空串 / Application-header / charset≠106）归口 `mmse_neg_value_range` 拒绝（§5）。

**包数约定**（设计 §9 完成定义；实现期以实际输出校准，约定数字不当规范消息数）：单事务会话 = 3（握手）+ N（HTTP 消息帧，单段时 = 消息数）+ 3（挥手 FIN+ACK、FIN+ACK、末 ACK）；POST+200 单事务 = 8；GET+200 = 8；多事务 keep-alive = 3 + 2M + 3（M 为事务数）；多会话 = 各会话之和，第二会话起点 = 前会话总包数 + 1（设计 §5 多会话展开）。单会话内包位约定：1–3 握手、4 = 请求（POST/GET）、5 = 响应、6–8 挥手。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `mmse_send_req_ipv4` | 正 | §3.5/§4①：m-send-req 必选集 + multipart 完整体（含 Sender-Visibility=Show） | 9 |
| 2 | `mmse_send_conf_ok` | 正 | §3.5/§5：Ok、TID same_as、Message-ID；200≠MMS 状态 | 9 |
| 3 | `mmse_send_conf_error` | 正 | §3.7/§4①：Response-Status 错误分支（Error-service-denied）+ Response-Text | 9 |
| 4 | `mmse_notification_ind` | 正 | §3.5/§4②：通知必选集 + From（content_length=99 逐字节复算） | 8 |
| 5 | `mmse_retrieve_conf_immediate` | 正 | §3.5/§4②：立即取回，TID 复用通知 | 17 |
| 6 | `mmse_notifyresp_deferred` | 正 | §3.5/§4③：Deferred + Report-Allowed=Yes | 16 |
| 7 | `mmse_acknowledge_ind` | 正 | §3.5/§4③：延迟链全链（Figure 5），新 TID 关联 | 34 |
| 8 | `mmse_delivery_ind_retrieved` | 正 | §3.5/§4④：递送报告必选集、MsgID 关联 | 17 |
| 9 | `mmse_delivery_ind_expired` | 正 | §3.7：Status=Expired 变体 | 17 |
| 10 | `mmse_read_rec_ind` | 正 | §3.5/§4⑤：读取报告 Read-Status=Read | 17 |
| 11 | `mmse_read_status_deleted` | 正 | §3.7：Read-Status=Deleted 变体 | 17 |
| 12 | `mmse_message_class_values` | 正 | §3.7：Message-Class 四值（4 fixture，单 ID 单 spec） | 36 |
| 13 | `mmse_encoding_text_string` | 正 | §3.3：Encoded-string-value 两形态（2 fixture，单 ID 单 spec） | 18 |
| 14 | `mmse_text_string_quote` | 正 | §3.3：Text-string Quote 形态（首字符分隔符前置 0x7F） | 9 |
| 15 | `mmse_encoding_long_integer` | 正 | §3.3：Long-integer 大端 4B/3B（定宽补零） | 9 |
| 16 | `mmse_encoding_value_length_uintvar` | 正 | §3.3：0x1F+Uintvar 长值长 | 9 |
| 17 | `mmse_time_absolute_form` | 正 | §3.3/§3.4：绝对 token 时间形态 | 9 |
| 18 | `mmse_send_req_optional_headers` | 正 | §3.4：可选头全集（Cc/Bcc/Visibility=Hide/Priority=High/Delivery-Time） | 9 |
| 19 | `mmse_from_insert_token` | 正 | §3.4/§3.5：From insert-address-token 形态 | 9 |
| 20 | `mmse_addressing_types` | 正 | §3.7：地址四形态（PLMN/IPv4/IPv6/邮箱） | 9 |
| 21 | `mmse_multipart_related_root` | 正 | §3.6：start/type 参数与 SMIL 根 | 9 |
| 22 | `mmse_multipart_part_headers` | 正 | §3.6：part 头（charset/name/ID/Location） | 9 |
| 23 | `mmse_multipart_media_part` | 正 | §3.6：媒体 part jpeg（well-known 码 0x9E/magic bytes） | 9 |
| 24 | `mmse_http_keepalive_multi_transaction` | 正 | §5/§4⑥：同连接多事务严格配对 | 13 |
| 25 | `mmse_ipv6` | 正 | §2/§8：IPv6 单流 | 9 |
| 26 | `mmse_multi_session` | 正 | §5/§4⑦：多会话展开双四元组 | 26 |
| 27 | `mmse_mss_large_multipart` | 正 | §8：跨 MSS ≥3 段重组 | 16 |
| 28 | `mmse_concurrent_sessions` | 正 | §5：并发会话交错回放（concurrent:true，C-1 翻案纳入） | 18 |
| 29 | `mmse_port_nondefault` | 正 | §2：非默认端口 8002（Content-Type 触发解码、无 DecodeAs，C-5） | 9 |
| 30 | `mmse_tid_max_32` | 正 | §3.4/§8：Transaction-ID 恰 32B 策略上界 | 8 |
| 31 | `mmse_long_integer_max_4b` | 正 | §3.3/§8：Date 恰 4B 满值 0xFFFFFFFF | 9 |
| 32 | `mmse_uintvar_max_4b` | 正 | §3.3/§8：part dataLen 恰 4B 载荷（0x200000B fill part） | 1445 |
| 33 | `mmse_value_length_max_30` | 正 | §3.3/§8：Value-length 恰 30（短形态上界） | 9 |
| 34 | `mmse_partnum_max_127` | 正 | §3.6/§8：partNum 恰 127（部件数上界） | 9 |
| 35 | `mmse_priority_low` | 正 | §3.7：Priority=Low（值域第三值，三值闭合） | 9 |
| 36 | `mmse_version_10` | 正 | §3.4：MMS-Version=1.0（线码 0x90，N-1 口径） | 9 |
| 37 | `mmse_version_13` | 正 | §3.4：MMS-Version=1.3（线码 0x93，N-1 口径） | 9 |
| 38 | `mmse_response_status_error_values` | 正 | §3.7：1.0 其余 7 错误值（7 fixture，单 ID 单 spec） | 63 |
| 39 | `mmse_get_uri_auto_derived` | 正 | §5 自动派生③：GET URI 取自通知 content_location | 16 |
| 40 | `mmse_no_frames_after_fin` | 正 | §5：Closed 终态后无新帧、FIN×2 挥手、无 RST（C-3） | 9 |
| 41 | `mmse_multipart_length_invariant` | 正 | §3.6：长度自洽不变式独立断言 | 9 |
| 42 | `mmse_report_allowed_no` | 正 | §3.4/§3.7：Report-Allowed=No（0x81，Yes/No 闭合） | 16 |
| 43 | `mmse_send_req_cc_only` | 正 | §3.5：仅 Cc 收件人（To 缺席合法形态） | 9 |
| 44 | `mmse_notification_minimal` | 正 | §3.5：通知必选集最小体 71B 反向复算 | 8 |
| 45 | `mmse_multipart_media_gif` | 正 | §3.6：image/gif 媒体码 0x9D + GIF magic | 9 |
| — | （无） | 注册前置占位已移除 | 当前 100 个语义 ID 均可按层链表达 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, http, mmse]`，无 VLAN/IP options/TCP options 时 HTTP 起行起点 IPv4 offset 54、IPv6 offset 74。断言分层：

1. **HTTP 骨架（fields 权威断言）**：`http.request.method=POST`（取回事务 `GET` 且 `http.request.uri` 等于通知 Content-Location 的路径）、`http.content_type=application/vnd.wap.mms-message`、`http.content_length` 等于 PDU 编码字节数（实测可精确断言，如 send-req 基线 326；通知 fixture 为逐字节复算值 99，见 §4.4）、响应 `http.response.code=200`。**HTTP 200 ≠ MMS 业务状态**：业务状态断言走 `mmse.response_status`/`mmse.status`。
2. **PDU 结构（fields + frames hex 双印证）**：PDU 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长（头集合由配置钉死，偏移可预算；实测样例：头集合 129B → PDU 起点 183）。PDU 首 3 字节固定 `8C <类型> 98`（Message-Type 码 0x8C + 类型值 + Transaction-ID 码 0x98，设计 §3.2 顺序规则），用 frames hex 在 PDU 起点断言：send-req `8c 80 98`、send-conf `8c 81 98`、notification `8c 82 98`、notifyresp `8c 83 98`、retrieve-conf `8c 84 98`、acknowledge `8c 85 98`、delivery `8c 86 8d 92`（无 TID，第三字节为版本**字段码** 0x8D、第四字节为值 0x92——N-3：版本头两字节 `8d 92`）、read-rec `8c 87 98`。字段值断言走 `mmse.*`。
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
8. **`mmse_delivery_ind_retrieved`**（16 = 提交 8 + 递送报告 8）：会话 1（POST send-req=4、200 send-conf=5，Message-ID 生成）；会话 2 包 12 断言 `mmse.message_type=0x86`、`mmse.message_id` `same_as_packet` 5（跨事务回指 send-conf 的 Message-ID，设计 §5）、`mmse.to=+8613800138000/TYPE=PLMN`、`mmse.date` nonzero、`mmse.status=0x81`（Retrieved）；frames hex `8c 86 8d 92`（版本字段码 0x8D + 值 0x92，N-3）——**第三字节即版本字段码证明 Message-Type 后无 Transaction-ID**（表 7 无此字段）。
9. **`mmse_delivery_ind_expired`**（8）：同形状（Message-ID 精确配置值断言），`mmse.status=0x80`（Expired，§3.7 值域）。
10. **`mmse_read_rec_ind`**（16 = 提交 8 + 读取报告 8）：会话 2 包 12 断言 `mmse.message_type=0x87`（OMA-MMS-ENC 1.1 PDU）、`mmse.transaction_id` nonzero、`mmse.message_id` `same_as_packet` 5（回指被读消息）、`mmse.read_status=0x80`（Read）、frames hex `8c 87 98`。
11. **`mmse_read_status_deleted`**（8）：同形状，`mmse.read_status=0x81`（Deleted-without-being-read）。
12. **`mmse_message_class_values`**（32 = 4 fixture × 8）：四个 m-send-req 分别 `mmse.message_class.id` = `0x80`/`0x81`/`0x82`/`0x83`（Personal/Advertisement/Informational/Auto）；Auto fixture 同时断言 `mmse.delivery_report=0x81` 且 `mmse.read_report=0x81`（表 1：class=Auto 时两报告必为 No，设计 §3.7）。**单 ID 单 spec（N-4）**：一个 spec 的 `sessions[]` 内 4 个独立 UA 会话各一笔提交。
13. **`mmse_encoding_text_string`**（8+8）：fixture A 的 Subject 走裸 Text-string（`mmse.subject=MMSE check`）；fixture B 走 VL+charset 形态（`Value-length Char-set Text-string`，Char-set=Short-integer 106|0x80=0xEA，UTF-8 多字节文本）断言 `mmse.subject` 精确解码值 + frames hex Subject 值区前缀 `96 0c ea`（字段码 0x96 + 值长 12 + Char-set 0xEA，实测）。To/From 地址同为 Encoded-string-value 裸形态（设计 §3.4）。part 头内的 charset **参数**（`81 ea`，参数码 0x01）归用例 22 断言——两处编码不同形，勿混。**单 ID 单 spec（N-4）**：一个 spec 的 `sessions[]` 内 2 个独立会话（各 8 包）。
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
25. **`mmse_ipv6`**（8）：`2001:db8:bb::71 → 2001:db8:bb::1`（对端 80，N-2）；断言 `ipv6.nxt=6`、`mmse.message_type=0x80` 与同值域字段解码同 v4 fixture、frames hex PDU 起点前缀 `8c 80 98`（PDU 字节与 v4 一致，仅外层 IP 头不同）。
26. **`mmse_multi_session`**（24 = 发送链 8 + 通知 8 + 取回 8）：会话 1（UA 提交，src_port=40710）、会话 2（MMSC→接收方通知，四元组独立）、会话 3（接收方 GET 取回）；断言三个 `tcp.stream` distinct、会话 2 握手包号 = 9（8+1）、发送链 TID 与接收链 TID `distinct_values`（互不串用）、MsgID 跨会话回指按 `same_as_packet` 全局包位。
27. **`mmse_mss_large_multipart`**（≥12，按段数校准）：multipart 附件 ≥3KB、MSS 压至 536 使 PDU 跨 ≥3 TCP 段。可执行判定字段：逐段 `tcp.len` 数值断言——请求侧满 MSS 段 `tcp.len`=536、请求侧末段 `tcp.len`=HTTP 请求消息总长−536×满段数（>0；请求消息总长 = 头集合字节长 + `http.content_length`，按 fixture 可复算）；Σ请求侧数据段 `tcp.len` = HTTP 请求消息总长；按 `tcp.stream` 重组后 `http.content_length` = 全部请求段 payload 之和、`wsp.header.content_type` 整串完整（multipart 重组后可解）、JPEG magic `ff d8 ff` 在末段 frames hex。
28. **`mmse_concurrent_sessions`**（16）：`concurrent: true` 双 UA 会话（`192.0.2.71:40710`/`192.0.2.73:40713` 两独立四元组）并发交错回放（C-1 翻案纳入，cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47 同判例）：断言两个 `tcp.stream` distinct、总包数 16（8+8 交错）、各会话自身握手→POST→200→挥手配对完整、两链 Transaction-ID `distinct_values`、Message-ID 各自回指本会话 send-conf——HTTP/1.1 单连接严格配对约束的是会话内部，不约束生成器级多连接交错。
29. **`mmse_port_nondefault`**（8）：会话四元组 `192.0.2.71:40714 → 198.51.100.71:8002`，PDU/断言集同用例 1：断言 `tcp.dstport=8002`、`mmse.message_type=0x80`、`mmse.transaction_id` nonzero、multipart 存在——**MMSE 解码经 HTTP Content-Type 触发，与端口无关、无 DecodeAs 依赖**（实测：8002 端口 `frame.protocols=eth:ethertype:ip:tcp:http:mmse`，http+mmse 全自动解出，设计 §2/C-5）。
30. **`mmse_tid_max_32`**（8）：通知 fixture 的 TID 恰 32 字节（`T32`+28×`A`）：断言 `mmse.transaction_id` nonzero、frames hex TID 值区 `98`+32B+`00`（值区恰 32B，策略上界，§3.4/§8）、`http.content_length=120`（99B 工作例替换 TID 项：99−13+34=120，逐字节复算同法）。
31. **`mmse_long_integer_max_4b`**（8）：send-req fixture 的 date=0xFFFFFFFF（4B 满值上界）：断言 `mmse.date` nonzero + frames hex Date 值区 `85 04 ff ff ff ff`（长度字节 04、恰 4B，§3.3 定宽策略与上限；相邻值 05B 归负例 `mmse_neg_length_long_int_over`）。
32. **`mmse_uintvar_max_4b`**（7+ceil(消息总长/MSS)（MSS=1460 时 ≈1444，校准））：multipart 单 part、dataLen=0x200000（2 MiB 生成器 fill 字节）：断言 part 头 dataLen 值区 frames hex `80 80 80 01`（恰 4B Uintvar 载荷上界，§3.3；相邻值第 5 字节归负例 `mmse_neg_length_uintvar_over`）、按 `tcp.stream` 重组后 `http.content_length` = PDU 头长 + 1 + (1+1+2+2,097,152) = PDU 头长 + 2,097,157（逐字节复算）且 Σ请求侧数据段 `tcp.len` = HTTP 请求消息总长；packet_count = 3 + ceil(消息总长/MSS) + 1 + 3。
33. **`mmse_value_length_max_30`**（8）：Subject VL+charset 形态值长恰 30（charset 0xEA 1B + 文本 28B + NUL 1B）：断言 frames hex Subject 值区前缀 `96 1e ea`（字段码 + 值长 0x1E=30 + Char-set）+ `mmse.subject` 精确 28 字符配置值——短形态上界 30（§3.3；>30 走 0x1F 长形态归用例 16）。
34. **`mmse_partnum_max_127`**（8）：multipart 含 127 个最小 part（每 part = headersLen `02` + dataLen `01` + part 头 `01 83`（VL+text/plain 码）+ 1B data = 5B）：断言 `wsp.multipart` 序号整串 1–127 逗号拼接（127 元素，part 数固定）、`http.content_length` = PDU 头长 + 1 + 127×5 = PDU 头长 + 636（逐字节复算，§3.6 不变式）——partNum 恰 127 上界（§3.6；128 归负例 `mmse_neg_multipart_partnum_over`）。
35. **`mmse_priority_low`**（8）：send-req fixture priority=low：断言 `mmse.priority=0x80`（Low）——Priority 三值闭合：Normal 用例 1（0x81）/High 用例 18（0x82）/Low 本例（§3.7）。
36. **`mmse_version_10`**（8）：mms_version="1.0"：断言 `mmse.mms_version=1.0` + frames hex `8d 90`（版本字段码 0x8D + 线码 0x90 = 0x80|0x10，N-1 统一线码口径）。
37. **`mmse_version_13`**（8）：mms_version="1.3"：断言 `mmse.mms_version=1.3` + frames hex `8d 93`（线码 0x93 = 0x80|0x13）——版本值域三点闭合 1.0/1.2（基线）/1.3，同主版本互通合法性见 §6.7。
38. **`mmse_response_status_error_values`**（56（7 fixture × 8，单 ID 单 spec））：7 个 send-conf fixture 分别 `mmse.response_status` = `0x81`/`0x83`/`0x84`/`0x85`/`0x86`/`0x87`/`0x88`（Error-unspecified/format-corrupt/sending-address-unresolved/message-not-found/network-problem/content-not-accepted/unsupported-message，§3.7 1.0 值域其余分支）：各 fixture 断言精确值 + `http.response.code=200`（HTTP 200 ≠ MMS 业务状态——业务错误响应是正例形态）+ `mmse.transaction_id` same_as 本 fixture 请求。1.0 九值全闭合（Ok 用例 2/service-denied 用例 3）；1.1+ 瞬态/永久段（0xC0–0xC4/0xE0–0xEA）本版不产生（设计 §1 收窄声明）。
39. **`mmse_get_uri_auto_derived`**（16）：通知（8）+ 取回（8）两连接；取回会话事件**不显式给 URI**，引擎按设计 §5 自动派生③从引用的通知事件取 content_location：断言包 12 `http.request.method=GET`、`http.request.uri` 精确值 `/mms/MSG20260901001`（派生产物逐字符断言，非仅『与通知一致』）——自动派生规则独立可观测。
40. **`mmse_no_frames_after_fin`**（8）：单事务会话（同用例 1 形状）：断言包数恰 8（3 握手 + 2 消息 + 3 挥手）、包 6/7 `tcp.flags.fin=1`（FIN/ACK×2 正常挥手，设计 §5/C-3）、全帧 `tcp.flags.reset=0`（**不产生 RST**）、包 8（末 ACK）之后无 `tcp.len>0` 帧——`Closed` 终态后不产生新业务帧。
41. **`mmse_multipart_length_invariant`**（8）：复用用例 21 的 multipart fixture：**独立断言**设计 §3.6 长度自洽不变式——frames hex 逐 part 数值断言 headersLen/dataLen 字节、Σ各 part(headersLen 覆盖的头 + dataLen 数据) + len(Uintvar(partNum)) = body 总长 = `http.content_length` − PDU 头部长（PDU 头长按 §3.5 公式复算）——不变式与单 part 编码分例观测（不依赖用例 21 的字段断言）。
42. **`mmse_report_allowed_no`**（16）：通知（8）+ notifyresp（8）链：notifyresp `report_allowed=false`：断言包 12 `mmse.message_type=0x83`、`mmse.status=0x83`（Deferred）、`mmse.report_allowed=0x81`（No）——Yes/No 族闭合（Yes 用例 6/No 本例，§3.7）。
43. **`mmse_send_req_cc_only`**（8）：send-req 仅 Cc 收件人（To/Bcc 均缺席——表 1 "To|Cc|Bcc 至少一"的合法形态，§3.5）：断言 `mmse.cc` 精确值、`mmse.to`/`mmse.bcc` 无值（不出现即通过）、其余同基线骨架（`mmse.message_type=0x80`、frames `8c 80 98`）。
44. **`mmse_notification_minimal`**（8）：通知仅必选集（From/Subject 均缺席，§3.5 可选头零出现形态）：断言 `mmse.message_type=0x82`、`mmse.transaction_id` nonzero、`mmse.message_class.id=0x80`、`mmse.message_size=4800`、`mmse.expiry.rel` nonzero、`mmse.content_location` 精确值、frames `8c 82 98` + `http.content_length=71`（= 99B 工作例 − From 28B，必选集最小长度反向复算，§3.5 工作例）。
45. **`mmse_multipart_media_gif`**（8）：multipart 含 image/gif part（媒体码 0x9D，§3.6）：断言 `wsp.header.content_type` 整串含 `image/gif`（well-known 码、无 charset 参数）、frames hex part 数据区 GIF magic `47 49 46 38`（"GIF8"）——媒体码第二值例（jpeg 用例 23）。

## 5. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，不加 `notes`/`min_packets`/字段断言。**逐故障输入原子拆分（C-4）：一行一例，钉死该行注入的单一 `wire_fault` 值**；主锚词钉死字面值（备选括注，N-4 式），与设计 §7 表 55 行逐行同序同词：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 46 | `mmse_neg_carrier_no_http` | `carrier_no_http` | 层链缺 http（tcp→mmse 直连） | `layer`（carrier） |
| 47 | `mmse_neg_carrier_content_type` | `carrier_content_type` | 承载 Content-Type 非 application/vnd.wap.mms-message | `content-type`（carrier） |
| 48 | `mmse_neg_carrier_port` | `carrier_port` | 端口/载体矛盾（如 WSP 端口 9200 配 http 层） | `port`（carrier） |
| 49 | `mmse_neg_carrier_profile` | `carrier_profile` | profile 取未定义值（含 WSP 承载 profile） | `carrier`（profile） |
| 50 | `mmse_neg_head_order_tid_first` | `head_order_tid_first` | Transaction-ID 头先于 Message-Type（首三头缺序） | `order`（header） |
| 51 | `mmse_neg_head_order_version_missing` | `head_order_version_missing` | 首三头缺 MMS-Version | `header`（order） |
| 52 | `mmse_neg_head_first_not_8c` | `head_first_not_8c` | 首字段码非 0x8C | `message-type`（header） |
| 53 | `mmse_neg_pdu_type_unassigned` | `pdu_type_unassigned` | Message-Type 取未分配值（如 0x7F、>0x93） | `unknown`（message-type） |
| 54 | `mmse_neg_pdu_type_unsupported` | `pdu_type_unsupported` | 已分配但本版不产生值（如 0x8B m-mbox 系） | `message-type`（unsupported） |
| 55 | `mmse_neg_content_type_missing` | `content_type_missing` | m-send-req 缺最后的 Content-Type 头 | `content-type`（body） |
| 56 | `mmse_neg_body_on_bodyless` | `body_on_bodyless` | 无体 PDU（m-notifyresp-ind）声明 content 或 Content-Type | `body`（content-type） |
| 57 | `mmse_neg_mandatory_from` | `mandatory_from` | m-send-req 缺 From | `mandatory`（missing） |
| 58 | `mmse_neg_mandatory_recipients` | `mandatory_recipients` | m-send-req 的 To/Cc/Bcc 全缺 | `mandatory`（missing） |
| 59 | `mmse_neg_mandatory_notif_class` | `mandatory_notif_class` | m-notification-ind 缺 Message-Class | `mandatory`（missing） |
| 60 | `mmse_neg_mandatory_notif_size` | `mandatory_notif_size` | m-notification-ind 缺 Message-Size | `mandatory`（missing） |
| 61 | `mmse_neg_mandatory_notif_expiry` | `mandatory_notif_expiry` | m-notification-ind 缺 Expiry | `mandatory`（missing） |
| 62 | `mmse_neg_mandatory_notif_location` | `mandatory_notif_location` | m-notification-ind 缺 Content-Location | `mandatory`（missing） |
| 63 | `mmse_neg_mandatory_response_status` | `mandatory_response_status` | m-send-conf 缺 Response-Status | `response-status`（mandatory） |
| 64 | `mmse_neg_mandatory_delivery_msgid` | `mandatory_delivery_msgid` | m-delivery-ind 缺 Message-ID | `mandatory`（missing） |
| 65 | `mmse_neg_mandatory_delivery_to` | `mandatory_delivery_to` | m-delivery-ind 缺 To | `mandatory`（missing） |
| 66 | `mmse_neg_mandatory_delivery_date` | `mandatory_delivery_date` | m-delivery-ind 缺 Date | `mandatory`（missing） |
| 67 | `mmse_neg_mandatory_delivery_status` | `mandatory_delivery_status` | m-delivery-ind 缺 Status | `mandatory`（missing） |
| 68 | `mmse_neg_multipart_headers_len` | `multipart_headers_len` | part headersLen 越界（超出 body 剩余字节） | `multipart`（headers） |
| 69 | `mmse_neg_multipart_data_len` | `multipart_data_len` | part dataLen 越界（超出 body 剩余字节） | `data`（multipart） |
| 70 | `mmse_neg_multipart_partnum_zero` | `multipart_partnum_zero` | partNum=0 但声明了 parts | `part`（multipart） |
| 71 | `mmse_neg_multipart_partnum_mismatch` | `multipart_partnum_mismatch` | partNum 与实际 part 数不符 | `part`（multipart） |
| 72 | `mmse_neg_multipart_start_dangling` | `multipart_start_dangling` | start 参数引用不存在的 Content-ID | `start`（multipart） |
| 73 | `mmse_neg_multipart_partnum_over` | `multipart_partnum_over` | partNum=128（>127 部件数上界） | `overflow`（partnum） |
| 74 | `mmse_neg_tid_send_conf` | `tid_send_conf` | send-conf 的 Transaction-ID 与请求侧不一致 | `transaction`（correlation） |
| 75 | `mmse_neg_tid_notifyresp` | `tid_notifyresp` | notifyresp 的 Transaction-ID 与通知不一致 | `transaction`（correlation） |
| 76 | `mmse_neg_tid_acknowledge` | `tid_acknowledge` | acknowledge 的 Transaction-ID 与前一个 retrieve 不一致 | `transaction`（correlation） |
| 77 | `mmse_neg_msgid_delivery` | `msgid_delivery` | delivery-ind 的 Message-ID 无来源 send-conf（回指断裂） | `message-id`（correlation） |
| 78 | `mmse_neg_msgid_read_rec` | `msgid_read_rec` | read-rec-ind 的 Message-ID 无来源 send-conf | `message-id`（correlation） |
| 79 | `mmse_neg_sequence_ack_first` | `sequence_ack_first` | acknowledge 先于 retrieve | `sequence`（state） |
| 80 | `mmse_neg_sequence_notifyresp_orphan` | `sequence_notifyresp_orphan` | notifyresp 无前置 notification | `sequence`（state） |
| 81 | `mmse_neg_sequence_conf_orphan` | `sequence_conf_orphan` | send-conf 无前置 send-req | `sequence`（state） |
| 82 | `mmse_neg_sequence_response_first` | `sequence_response_first` | 同连接响应先于请求（违反严格配对） | `order`（sequence） |
| 83 | `mmse_neg_length_content_length` | `length_content_length` | HTTP Content-Length ≠ PDU 编码字节数 | `length`（content-length） |
| 84 | `mmse_neg_length_long_int_over` | `length_long_int_over` | Long-integer 长度字节 >4（如 05） | `long-integer`（length） |
| 85 | `mmse_neg_length_long_int_zero` | `length_long_int_zero` | Long-integer 长度字节 =0 | `long-integer`（length） |
| 86 | `mmse_neg_length_uintvar_over` | `length_uintvar_over` | Uintvar 载荷 >4B（第 5 字节） | `uintvar`（length） |
| 87 | `mmse_neg_length_value_length` | `length_value_length` | Value-length 与实际值长不符 | `value-length`（length） |
| 88 | `mmse_neg_length_tid_over` | `length_tid_over` | Transaction-ID 33B（>32B 策略上界） | `transaction-id`（overflow） |
| 89 | `mmse_neg_value_priority` | `value_priority` | Priority=0x83（域外） | `priority`（value） |
| 90 | `mmse_neg_value_status` | `value_status` | X-Mms-Status=0x8F（域外） | `status`（value） |
| 91 | `mmse_neg_value_message_class` | `value_message_class` | Message-Class=0x84（域外） | `message-class`（value） |
| 92 | `mmse_neg_value_response_status` | `value_response_status` | Response-Status=0x89（1.0 域外） | `response-status`（value） |
| 93 | `mmse_neg_value_read_status` | `value_read_status` | Read-Status=0x82（域外） | `read-status`（value） |
| 94 | `mmse_neg_value_yesno` | `value_yesno` | Delivery-Report=0x82（Yes/No 域外） | `delivery-report`（value） |
| 95 | `mmse_neg_value_reply_charging` | `value_reply_charging` | Reply-Charging 字段族（0x9C–0x9F）出现在配置 | `reply-charging`（value） |
| 96 | `mmse_neg_value_empty_string` | `value_empty_string` | Subject 空串（仅 0x00 终止，本版不产生形态） | `text-string`（value） |
| 97 | `mmse_neg_value_application_header` | `value_application_header` | Application-header 扩展头（本版不产生形态） | `application-header`（value） |
| 98 | `mmse_neg_value_charset` | `value_charset` | charset=1000（≠106，本版不产生形态） | `charset`（value） |
| 99 | `mmse_neg_value_previously_sent` | `value_previously_sent` | X-Mms-Previously-Sent-By/Forward-Count 头族出现在配置（本版不产生） | `previously-sent`（value） |
| 100 | `mmse_neg_value_notif_expiry_absolute` | `value_notif_expiry_absolute` | 通知 Expiry 用绝对形态（表 3 仅 interval） | `expiry`（value） |

合法协议事件不进负例（防误报）：m-send-conf 错误 Response-Status（正例 3/38——1.0 九值全合法）、Status=Expired/Deferred（正例 6/9）、From insert-token（正例 19）、Text-string Quote 形态（正例 14）、Priority=Low（正例 35）、Report-Allowed=No（正例 42）、MMS 1.0/1.1 版本混用（§6.7 同主版本互通；值例 36/37）、多 To/Cc/Bcc 实例与仅 Cc 收件人（正例 20/43）、非默认端口 8002（正例 29）、Content-ID 角括号 warning（§1 实测伪影）。接收侧互操作反应显式不适用（设计 §3.7 声明，无用例不进负例）；本版不产生形态/字段族（空串、Application-header、charset≠106、Reply-Charging、Previously-Sent-By 族、multipart/mixed）按设计 §1/§3.4/§3.6 声明归口对应负例行（#95–#99）拒绝。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–11（正，8 类 PDU 全覆盖）；46–100（负，55 行逐故障原子拆分） | 提交/通知/取回/确认/递送/读取全链；流关联与多流显式不适用（设计 §4 声明：消息体在带内、HTTP/1.1 单连接串行——并发会话已翻案纳入 #28，C-1） |
| 性能 | 27、32 | 大 multipart 跨 MSS 重组 + Value-length/Uintvar/Long-integer 上界断言 + 恰等上界五例（#30–#34） |
| 数据场景 | 3、6、9、11、12、13–20、35–38、42、44；负 89–100（值域与不产生形态族） | Response-Status 1.0 九值全、Status/Read-Status/Class/Priority 值域（Priority 三值闭合）、编码变体（文本三形态、insert-token、绝对时间、长值长）、地址四形态、域外值与不产生形态/字段族拒绝 |
| 地址与流 | 1（v4 基线）、25（v6）、26（多会话）、28（并发）、29（非默认端口 8002） | v4+v6 必覆盖；跨会话关联用全局包位 same_as_packet；并发/非默认端口为 C-1/C-5 翻案与新增 |
| 业务 | 1–3（提交）、4–7（通知-取回链：立即+延迟）、8–11（递送-读取报告链）、24（长连接多事务）、26/28（多终端/并发）、39–43（自动派生/终态/不变式/报告链变体） | 现网 AOSP 事务服务同款流程（WAP-206 Figure 3/4/5）优先于教科书全 PDU 遍历 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/mmse.json` 通过；当前数组恰含 100 条语义用例（45 正例、55 负例），不含 `mmse_neg_unregistered` 占位。
2. MMSE 层已注册且 translator 有 `case "mmse"`；100 个 ID、顺序与设计 §9（ID 权威声明）完全一致。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields`（+ 按需 `frames`）；`fields` 只用 §1 实测存在的 tshark 字段（`mmse.*`/`wsp.*`/`http.*`/`ip.*`/`ipv6.nxt`/`tcp.*`），不伪造；时间字段（date/expiry/delivery_time）值断言一律 `nonzero`，精确性走 frames hex。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 跨会话/跨连接包号引用用多会话展开起点规则（§3.5）或 `tcp.stream`，不硬编码运行期值；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 多实例字段（`wsp.header.content_type` 等）精确断言按整串匹配，仅 part 数固定的 fixture 使用。
7. pcap 与 port_group/NIC 两种输出路径共用本契约：同一 ID、同一断言集、同一包数约定，不含输出路径专有断言（设计 §1 输出契约段，C-2）。
8. 负例 `wire_fault` 注入与设计 §6 枚举 55 值、设计 §7 表 55 行三方同序（机器可核验：ID 列、注入口列逐一相等）。

## 8. 三方一致性表

设计 §9（ID 权威声明）、本文 §2（#1–#45 正例）+ §5（#46–#100 负例）、当前 `mmse.json` 保持同一 100 个语义 ID、同一顺序：

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
mmse_concurrent_sessions
mmse_port_nondefault
mmse_tid_max_32
mmse_long_integer_max_4b
mmse_uintvar_max_4b
mmse_value_length_max_30
mmse_partnum_max_127
mmse_priority_low
mmse_version_10
mmse_version_13
mmse_response_status_error_values
mmse_get_uri_auto_derived
mmse_no_frames_after_fin
mmse_multipart_length_invariant
mmse_report_allowed_no
mmse_send_req_cc_only
mmse_notification_minimal
mmse_multipart_media_gif
mmse_neg_carrier_no_http
mmse_neg_carrier_content_type
mmse_neg_carrier_port
mmse_neg_carrier_profile
mmse_neg_head_order_tid_first
mmse_neg_head_order_version_missing
mmse_neg_head_first_not_8c
mmse_neg_pdu_type_unassigned
mmse_neg_pdu_type_unsupported
mmse_neg_content_type_missing
mmse_neg_body_on_bodyless
mmse_neg_mandatory_from
mmse_neg_mandatory_recipients
mmse_neg_mandatory_notif_class
mmse_neg_mandatory_notif_size
mmse_neg_mandatory_notif_expiry
mmse_neg_mandatory_notif_location
mmse_neg_mandatory_response_status
mmse_neg_mandatory_delivery_msgid
mmse_neg_mandatory_delivery_to
mmse_neg_mandatory_delivery_date
mmse_neg_mandatory_delivery_status
mmse_neg_multipart_headers_len
mmse_neg_multipart_data_len
mmse_neg_multipart_partnum_zero
mmse_neg_multipart_partnum_mismatch
mmse_neg_multipart_start_dangling
mmse_neg_multipart_partnum_over
mmse_neg_tid_send_conf
mmse_neg_tid_notifyresp
mmse_neg_tid_acknowledge
mmse_neg_msgid_delivery
mmse_neg_msgid_read_rec
mmse_neg_sequence_ack_first
mmse_neg_sequence_notifyresp_orphan
mmse_neg_sequence_conf_orphan
mmse_neg_sequence_response_first
mmse_neg_length_content_length
mmse_neg_length_long_int_over
mmse_neg_length_long_int_zero
mmse_neg_length_uintvar_over
mmse_neg_length_value_length
mmse_neg_length_tid_over
mmse_neg_value_priority
mmse_neg_value_status
mmse_neg_value_message_class
mmse_neg_value_response_status
mmse_neg_value_read_status
mmse_neg_value_yesno
mmse_neg_value_reply_charging
mmse_neg_value_empty_string
mmse_neg_value_application_header
mmse_neg_value_charset
mmse_neg_value_previously_sent
mmse_neg_value_notif_expiry_absolute
```

## 9. 测试点清单、三源依据与存量审计（T1–T6）

### T1/T2：规范反推清单与矩阵

清单来源是 WAP-209 表1–8、WAP-206 Figure 3–5、WSP §8.4/§8.5、RFC 2387/7230，而不是从现有 JSON 反推。每个消息类型、字段编码、值域、边界、错误分支、地址族和会话形态均在 §2/§4/§5 有原子去向；D1–D3 的三张矩阵与本表共同作为遗漏检查表。

| 来源 | 逻辑点总数 | 已落到当前 ID | 待实现边界 |
|---|---:|---:|---|
| WAP-209 PDU/字段/值域 | 8 类 PDU + 规范字段和值域 | #1–11、#12、#18–20、#35–38、#43–45、#57–67、#89–100 | WSP/WTP/WAP Push 承载不实现，不影响当前语义 ID 执行 |
| WSP 编码/multipart | 7 个编码形态 + 4 个长度/part 边界族 | #13–17、#21–23、#27、#30–34、#41、#68–73、#83–87 | 已由 MMSE translator 配置路径承载，WSP 原生承载本版不实现 |
| WAP-206 事务/状态 | 4 类事务、关联和终态 | #5–11、#24、#26、#28、#39–40、#74–82 | 已由 MMSE translator 配置路径承载；WSP/WTP 事务层本版不实现 |

### T3：三类覆盖与 §3.15

- 数据场景：正常、空/缺失、上界、相邻溢出、非法枚举、编码与地址族分别见 #12–20、#30–38、#43–45、#83–100。
- 业务场景：提交、通知、立即/延迟取回、递送/读取报告、保活和并发见 #1–11、#24、#26、#28、#39–42；MMSE 没有规范定义的应用层重连/重试，设计已说明不适用。
- 复杂场景：#7（通知→确认→GET→retrieve→ACK，多个事务依赖）、#24（同连接多事务）、#28（独立连接交错）。流关联和会话内多流不适用，因为 multipart 在同一 HTTP 消息体内，没有控制流派生数据流。

### T4：现网映射与三项审计

WAP-206 Figure 3/4/5 分别映射提交（#1–3）、立即取回（#4–5）、延迟取回（#6–7）；AOSP 事务实现的 send/notifyresp/retrieve/ack 顺序映射 #1–7。HTTP `application/vnd.wap.mms-message`、SMIL related 和非默认 8002 作为现网可观察行为映射 #21、#24、#29。未映射 WSP Push/SMS 承载列为待实现边界，不计当前覆盖。

| 三项 | 结论 |
|---|---|
| 规范要求→ID | 8 类 PDU、编码原语、事务链、值域和错误分支均有 ID；MMSE 已注册，WSP/WTP/WAP Push 承载边界不冒充当前实现 |
| design→testcase→cases | 当前 100 个 ID、45 正+55 负同序；无注册前置占位，全部计入语义覆盖 |
| 现网行为→ID | HTTP MM1、SMIL related、keep-alive、多会话/并发、8002 均有映射；WSP/SMS 边界已登记 |

### T5：存量用例审计

原 `mmse.json` 的 100 条已逐条保留并迁入当前三件套：45 条正例对应本文 §2/§4，55 条负例对应本文 §5；无删除、无放宽阈值、无错误期望改写。负例执行契约严格为 `expect_error` + `error_contains` 两键，所有正例保留 packet/field/frame 可观察断言。当前 JSON 不含 `mmse_neg_unregistered` 占位（该占位属注册前历史，未进入 100 个语义 ID）。

### T6：覆盖对账与审查门

规范逻辑点总数（列在 T1）与用例覆盖数（100 个语义 ID）已逐项对账；覆盖审查需继续抽查最复杂的 #7、#24、#28，验证会话/事务/并发交织维度。独立审查必须检查：正例断言真实可观察、负例能触发单一故障且只含两键、JSON ID 顺序与本文一致；WSP/WTP/WAP Push 承载边界单独登记，不计入 HTTP MM1 语义覆盖。

## 10. 修订记录

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
- v2.1.0（2026-09-02，v1.3 重审修复轮）：独立隔离审查（rr，行为面全枚举 138 点：✓76/半10/✗52）后扩量修复，38 → **100 条（45 正 + 55 负）**。关键修复：
  - **C-4（CRITICAL）**：§5 负例表逐故障输入原子拆分 11 → **55 行**（一行一例单一 `wire_fault`、主锚词钉死、注入口列与设计 §6 枚举/§7 表三方同序）；负例 #46–#100。
  - **C-1**：并发会话翻案纳入——#28 `mmse_concurrent_sessions`（双 UA 四元组 concurrent:true 交错，TID/MsgID/tcp.stream 互不串用）；流关联/多流不适用声明保留。
  - **C-2**：§1 增 pcap/NIC 双输出契约声明；§7 检查项 7。
  - **C-5**：#29 `mmse_port_nondefault`（dst_port=8002，断言同 #1；解码经 Content-Type 触发、无 DecodeAs 依赖——审查员实测背书）。
  - **C-6**：扩量子项——恰等上界五例 #30–#34（TID 32B/Long-int 4B 满值/Uintvar 4B 载荷/Value-length 30/partNum 127）、Priority=Low #35、Response-Status 1.0 其余 7 错误值 #38（1.1+ 段收窄声明）、multipart/mixed 与重连/重试不适用声明（设计 §3.6/§5）、版本 1.0/1.3 值例 #36/#37、设计 §9 改 ID 权威 = 本文 §2/§5；另补 #39–#45（GET URI 自动派生/Closed 终态/长度不变式/Report-Allowed No/仅 Cc/通知最小体 71B/GIF 媒体码）。
  - **C-3/C-7/N-1/N-6**：随设计 §5/§3.4/§3.6 同步（RST 不产生声明、高码段头族声明、线码口径、part 头参数 VL 内警告）。
  - **N-2**：#25 v6 地址改 `2001:db8:bb::71`；**N-3**：§3/#8 改"版本字段码 0x8D（值 0x92）"；**N-4**：#12/#13/#38 单 ID 单 spec 形态钉死（§1）。
  - 三方一致性：§2（45 正）+ §5（55 负）+ §8 全列与设计 §9/§6/§7 同步 100 ID 同序。
