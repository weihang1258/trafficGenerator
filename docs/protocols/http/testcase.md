# #86 HTTP 测试用例契约

> 版本：v1.0.1（P-PIPE 文档轨批次二 as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocols/http/design.md` v1.0.1
> 机器契约：`trafficgen/test/protocol_pcap/cases/http.json`（**67/67 ID 与本文 §2 一致，JSON 顺序一致；59 正 + 8 负**；本版仅机读 JSON，未声称 pcap/NIC 复跑）
> 白话一句：**五十九条检查 HTTP 请求/响应、连接复用、编码和动态字段，八条检查错误形状是否被拒绝。**

## 1. 形状基线

机器读取 `http.json` 得 67 例，正例 59、负例 8。`spec_json` 顶层形状：纯 `{layers}` **65**；`{layers,src_ip}` **1**（`http_neg_flat_src_ip`，故意负例）；`{http,layers}` **1**（`http_neg_top_http`，故意负例）。因此非负例 59/59 均为 `{layers}`，游离键零残留；两种非纯形均是 G-HTTP-1/G-HTTP-2 的拒绝输入，不是旧配置残留。

层形：正例 59 均 `[ip,tcp,http]`；`http_neg_missing_carrier_gbt` 为 `[ip,tcp,gbt]` 的载体缺失负例；其余负例为 `[ip,tcp,http]`。实际 JSON 有 `strategy_fc` **19** 例（**17** 正例、`http_dyn_pattern_reject` 与 `http_neg_static_copy` 两个负例），均为 `flows` 数量封装；多流的地址/端口变化仍由 `tcp.src_port` 或 `ip.src` 上的动态 `list`/`inc`/`rand` 策略表达，不把 `strategy_fc` 当作动态值来源。正例 `expect` 为 `packet_count` **59**、`fields` **59**；其中 `http_req_chunk_size_multi` 另有 1 个 `frames` 断言。负例 `expect` 严格为 `{expect_error,error_contains}` **8/8**，无 packet_count/fields。

正例包数分布：9 包 **37**、10 包 **3**、13 包 **2**、14 包 **1**、18 包 **11**、27 包 **1**、36 包 **3**、45 包 **1**。总字段断言数按 JSON 逐条计为 **98**，另 1 个 frames 断言对象。

## 2. 原子用例索引（权威顺序）

|#|ID|类型|包数|主要覆盖|
|---:|---|---|---:|---|
|1|`http_get_baseline`|正|9|GET/Host/HTTP1.1/close/握手挥手|
|2|`http_post_body`|正|9|POST、Content-Length、JSON Content-Type|
|3|`http_keepalive_multi_transactions`|正|13|同连接 3 事务、keep-alive|
|4|`http_pipelined`|正|13|3 请求先行后 3 响应|
|5|`http_response_status_404`|正|9|404 响应|
|6|`http_gzip_response`|正|9|响应 gzip|
|7|`http_chunked_response`|正|9|响应 chunked|
|8|`http_version_10_no_auto_host`|正|9|HTTP/1.0 不自动 Host|
|9|`http_layer_version_bare`|正|9|裸 `1.1` 归一|
|10|`http_ipv6`|正|9|IPv6、Host 方括号|
|11|`http_nondefault_port`|正|9|TCP 8080|
|12|`http_req_headers_custom`|正|9|自定义请求头|
|13|`http_req_body_b64`|正|9|请求 base64 body|
|14|`http_req_gzip`|正|9|请求 gzip|
|15|`http_req_chunked`|正|9|请求 chunked|
|16|`http_req_chunk_size_multi`|正|9|chunk_size、frames offset 54|
|17|`http_resp_headers_override`|正|9|响应头覆盖|
|18|`http_resp_body_b64`|正|9|响应 base64 body|
|19|`http_resp_status_text_override`|正|9|418 自定义文本|
|20|`http_resp_unknown_status`|正|9|599 状态|
|21|`http_resp_empty_no_content_type`|正|9|空响应体|
|22|`http_file_source_literal`|正|9|literal 文件源|
|23|`http_mss_segments_long_response`|正|10|响应 MSS 分段|
|24|`http_put_method`|正|9|PUT|
|25|`http_delete_method`|正|9|DELETE|
|26|`http_head_method`|正|9|HEAD|
|27|`http_resp_301_location`|正|9|301|
|28|`http_resp_500`|正|9|500|
|29|`http_resp_201_created`|正|9|POST/201|
|30|`http_req_gzip_chunked_composite`|正|9|请求 gzip+chunked|
|31|`http_req_encoding_non_gzip`|正|9|br 仅写头|
|32|`http_req_body_invalid_b64_fallback`|正|9|非法 base64 回退文本|
|33|`http_mss_req_segments_long_body`|正|14|请求 MSS 分段|
|34|`http_conn_close_single`|正|9|显式 close|
|35|`http_multiflow_dynamic_sport`|正|18|端口动态、多流 2|
|36|`http_ttl_custom`|正|9|TTL 128|
|37|`http_req_headers_legacy`|正|9|legacy headers|
|38|`http_req_content_encoding_legacy`|正|9|legacy response encoding|
|39|`http_file_source_fill`|正|9|fill 文件源|
|40|`http_file_source_random`|正|9|random 文件源|
|41|`http_ipv6_multiflow_dynamic`|正|18|IPv6+端口多流|
|42|`http_ipv6_mss_segments`|正|10|IPv6 MSS|
|43|`http_req_chunked_mss`|正|10|请求 chunked MSS|
|44|`http_dyn_sport_rand`|正|36|端口 rand 4 流|
|45|`http_dyn_sport_list`|正|36|端口 list 4 流|
|46|`http_dyn_sport_fixed`|正|9|端口 fixed|
|47|`http_dyn_sport_inc_wrap`|正|45|端口 inc wrap 5 流|
|48|`http_dyn_sport_rand_repro`|正|36|rand 可复现|
|49|`http_dyn_sip_rand`|正|27|源 IP rand 3 流|
|50|`http_dyn_pattern_reject`|负|—|端口 pattern 拒绝|
|51|`http_neg_bad_mss`|负|—|MSS 100 拒绝|
|52|`http_neg_flat_src_ip`|负|—|flat src_ip 拒绝|
|53|`http_neg_static_copy`|负|—|静态四元组多流拒绝|
|54|`http_neg_missing_carrier_gbt`|负|—|GBT 缺 HTTP carrier|
|55|`http_dyn_uri_list`|正|18|URI list 2 流|
|56|`http_dyn_uri_pattern`|正|18|URI pattern 2 流|
|57|`http_dyn_uri_fixed`|正|9|URI fixed|
|58|`http_dyn_body_list`|正|18|body list|
|59|`http_dyn_respbody_list`|正|18|响应 body list|
|60|`http_dyn_status_list`|正|18|状态 list|
|61|`http_dyn_status_inc`|正|18|状态 inc|
|62|`http_dyn_status_rand_repro`|正|18|状态 rand 可复现|
|63|`http_dyn_body_b64_list`|正|18|base64 body list|
|64|`http_dyn_respbody_b64_list`|正|18|base64 响应 body list|
|65|`http_neg_dyn_uri_inc`|负|—|URI inc 拒绝|
|66|`http_neg_dyn_closed_method`|负|—|method 动态拒绝|
|67|`http_neg_top_http`|负|—|顶层 http 拒绝|

JSON 顺序是唯一编号依据；summary 中已有 T-HTTP-1…T-HTTP-72（历史编号不连续），本文不虚构缺失 ID。

## 3. 正例断言

所有正例都有 `packet_count` 和 `fields`。基线 `http_get_baseline`：packet 4 为 `GET / HTTP/1.1`、Host `198.51.100.20`，packet 8 响应 200，且 expect 明确 `has_handshake=true`、`terminates=true`、`directional=true`。请求/响应字段按 JSON 的 packet 索引断言，不能把请求字段移到响应帧。

动态例使用集合断言而非硬编码顺序：端口 rand 的 `distinct_values` 是 `43006,43008,43001,43004`；端口 list 是 `43100,43101`；inc wrap 是 `43300,43301,43302`；源 IP rand 是 `10.1.0.2,10.1.0.4,10.1.0.5`；URI list/pattern 分别是 `/a,/b` 与 `/u1,/u2`；状态 list/inc/rand 分别是 `200,404`、`200,201`、`200,201`。JSON 中 `None` 是动态字段集合断言的占位，不是字面线值。

HTTP 语义正例覆盖方法 GET/POST/PUT/DELETE/HEAD，状态 200/201/301/404/418/500/599，头自动/覆盖、body 文本/base64/file、gzip、chunked、编码、keep-alive、pipelining、IPv4/IPv6、TTL、MSS 和多种策略。唯一 frames 断言为 `http_req_chunk_size_multi` packet 4 offset 54，hex 前 24 字节是 `POST /chunks HTTP/1.1\r\n`。

## 4. 负例契约

负例必须在 planner/validator/链校验阶段失败，不能以成功任务或零包假成功替代错误；本版没有声称已复跑。8 条 JSON 锚词如下：

|ID|JSON `error_contains`|故障形状|
|---|---|---|
|`http_dyn_pattern_reject`|`pattern strategy is not supported`|TCP src_port 使用 pattern|
|`http_neg_bad_mss`|`mss`|TCP MSS=100|
|`http_neg_flat_src_ip`|`no longer accepts flat config field src_ip`|顶层 `src_ip` 与 layers 并存|
|`http_neg_static_copy`|`static four-tuple`|flows=2 且静态四元组|
|`http_neg_missing_carrier_gbt`|`requires the http carrier layer`|`[ip,tcp,gbt]` 无 http|
|`http_neg_dyn_uri_inc`|`not supported for string field`|URI 使用 inc|
|`http_neg_dyn_closed_method`|`does not support dynamic`|method 使用 list|
|`http_neg_top_http`|`no longer accepts a top-level http sub-config`|顶层 http 与 layers 并存|

8/8 的 expect 键形严格为 `{expect_error,error_contains}`；负例不设 packet_count、fields 或 frames。

## 5. 覆盖对账

设计 §4 的 HTTP 语义面由 59 正例逐项覆盖：消息默认值/版本 2、请求方法 5、状态 6、body 编码 8、头与连接 7、多事务/流水线 2、MSS 4、IPv4/IPv6/TTL/端口 6、文件源 3、动态字段 6；以上为行为分类，不对字段重复做跨表加总。动态字段 6 个的实际正例形状是：`uri` fixed/list/pattern，`body`/`response_body`/`body_b64`/`response_body_b64` 各 list，`response_status_code` fixed/list/inc/rand；HTTP 字符串字段的 inc/rand 以及 method 等关闭字段的动态对象没有正例，拒绝格见 §4。设计 §6 的 8 个拒绝面由 8 负例一一覆盖。机器层面对账：67 ID/67 JSON 顺序、59 正/8 负、65 `{layers}`/1 `{layers,src_ip}`/1 `{http,layers}`、59 正包数与 8 负无包数，均由临时 Python 机读确认。

没有 pcap、NIC 或 tshark 复跑证据，不能把 JSON 机器契约写成“测试通过”；执行状态为待 P5 重跑。

## 6. P3 固定动作

- 同连接多轮：`http_keepalive_multi_transactions`；流水线：`http_pipelined`。
- 非正常结束：HTTP 本身没有额外异常挥手语义，负例覆盖配置/校验拒绝；TCP 正常 FIN 由所有正例共同覆盖。
- 长保活：三事务 keep-alive 已覆盖；真实长时间保活不在 cases 中，待 P4。
- A′ 缺口：NIC 捕获、TLS 线证据、FileSource 注入缓存、动态拒绝全矩阵、HTTP-RPC carrier 联调，待 P4/P5；B′：顶层游离键仅两个故意负例，非负例无迁移残留。

## 7. 执行建议

先跑 `http_get_baseline` 校准 packet 4/8、Host、版本和 9 包公式；再跑 keep-alive/pipelined 与三种 MSS 例；随后跑编码、状态、IPv6/TTL、文件源；最后跑动态正例与 8 负例。负例必须检查 task error 和锚词，不能只断言无 panic。P5 需对正例保留 packet_count/fields/frames，对动态字段按集合比较，并单独保存负例错误输出；在此之前写“待 P5 重跑”。

## 8. 存量审计

`http.json` 67 例全部收编，无虚构 ID、无删除 ID。59 正例保留原包数与字段断言；8 负例保留原锚词。`http_neg_flat_src_ip` 与 `http_neg_top_http` 的非纯顶层形是 presence/flat 负例的故意输入，归为 G-HTTP-1/G-HTTP-2，不得在审计时误判为正例残留。`http_neg_missing_carrier_gbt` 的 GBT 层形是 carrier 缺失验证，归为 G-HTTP-3。真实结果产物/pcap 未作为本版证据引用。

## 9. 反查门断言

1. `len(http_cases)==67`，ID 集合与本 §2 完全一致且顺序一致。
2. 正/负分布为 59/8；正例 `packet_count` 59/59，负例 expect 键集合严格 `{expect_error,error_contains}`。
3. 非负例 `spec_json` 顶层键全为 `{layers}`；额外 `src_ip` 和顶层 `http` 只能出现在两个指定负例。
4. 正例层形为 `[ip,tcp,http]`；`http_neg_missing_carrier_gbt` 为 `[ip,tcp,gbt]`。
5. 正例 packet_count 分布为 9×37、10×3、13×2、14×1、18×11、27×1、36×3、45×1。
6. `http_req_chunk_size_multi` 唯一含 `frames`，offset=54、packet=4。
7. 业务动态 allowlist 只含 `uri/body/body_b64/response_body/response_body_b64/response_status_code`；动态值按 distinct 集合断言。
8. 不以 tracked 产物、pcap 或 NIC 文件缺失/存在推断通过；未复跑统一标待 P5。

## 10. 三源测试点清单与逐条去向（T1/T2/T3/T4/T5/T6）

测试点来源固定为 RFC 7230/7231/9112/879、HTTP planner/层翻译实现和已确认的常见 HTTP/1.1 行为；用例不是从现有 JSON 反推规范。逐项去向如下：

| 来源测试点 | 用例去向 | 状态 |
|---|---|---|
| 请求方法 GET/POST/PUT/DELETE/HEAD | `http_get_baseline`, `http_post_body`, `http_put_method`, `http_delete_method`, `http_head_method` | 已覆 |
| 状态 200/201/301/404/418/500/599 | `http_get_baseline`, `http_resp_201_created`, `http_resp_301_location`, `http_response_status_404`, `http_resp_status_text_override`, `http_resp_500`, `http_resp_unknown_status` | 已覆 |
| HTTP/1.0 与 HTTP/1.1 Host 差异 | `http_version_10_no_auto_host`, `http_get_baseline`, `http_ipv6` | 已覆 |
| Content-Length、空体、gzip、chunked、非 gzip encoding | `http_post_body`, `http_resp_empty_no_content_type`, `http_gzip_response`, `http_chunked_response`, `http_req_encoding_non_gzip` | 已覆 |
| base64、非法 base64 回退、file source | `http_req_body_b64`, `http_resp_body_b64`, `http_req_body_invalid_b64_fallback`, `http_file_source_literal`, `http_file_source_fill`, `http_file_source_random` | 已覆/缓存注入待 P5 |
| keep-alive、同连接多事务、pipelining、close | `http_keepalive_multi_transactions`, `http_pipelined`, `http_conn_close_single` | 已覆 |
| IPv4/IPv6、端口、TTL、MSS 与分段 | `http_get_baseline`, `http_ipv6`, `http_nondefault_port`, `http_ttl_custom`, `http_mss_segments_long_response`, `http_mss_req_segments_long_body`, `http_ipv6_mss_segments`, `http_req_chunked_mss` | 已覆 |
| 层地址/端口及 HTTP 业务动态 fixed/list/inc/rand/pattern | `http_dyn_sport_*`, `http_dyn_sip_rand`, `http_dyn_uri_*`, `http_dyn_body_list`, `http_dyn_respbody_list`, `http_dyn_status_*`, `http_dyn_body_b64_list`, `http_dyn_respbody_b64_list` | 已覆；拒绝格见负例 |
| pattern 端口、过小 MSS、flat 键、静态复制、缺 carrier、业务动态禁用 | `http_dyn_pattern_reject`, `http_neg_bad_mss`, `http_neg_flat_src_ip`, `http_neg_static_copy`, `http_neg_missing_carrier_gbt`, `http_neg_dyn_uri_inc`, `http_neg_dyn_closed_method`, `http_neg_top_http` | 8/8 负例 |

三类场景：数据边界由 body 空值、base64 非法、MSS 下界、未知状态码和动态回绕覆盖；业务流程由握手→请求→响应→挥手、keep-alive 三事务、pipelined 和拒绝分支覆盖；现网行为由 Host、Connection、Content-Length、chunked、gzip 组合例覆盖。多会话/多流/多事务审计：多事务为同连接 `transactions=3`，多流的流数由 19 条 `strategy_fc.type=flows`（其中 17 条正例、2 条负例）表达、具体四元组变化由动态策略表达，控制/数据派生流不适用；无长保活时间戳断言，登记 G-HTTP-4。

存量 67/67 逐条收编，未删除、未虚构 ID；59 正例均有 `packet_count` 与 `fields`，8 负例均为严格错误键形。按规范逻辑点对账：**9 个业务/数据逻辑组，9 组有用例；67 个机器 ID，67 个有去向**。反查只证明清单内项目已登记，不能替代 P5 的真实 pcap/NIC 执行。

## 11. 反查和执行状态

执行前按 §7 顺序运行完整 JSON；负例必须断言任务失败及锚词，正例必须校 packet_count、字段值和 frames。当前文档/用例契约未声称 pcap、NIC 或 tshark 已通过；P5 全量重跑后再回填真实结果。

## 12. 修订记录

- v1.1.0（2026-09-30）：补三源测试点清单、逐条去向、三类场景、§3.15 审计、性能执行边界与 P5 缺口；修正配套设计路径；自审 2 轮，末轮 clean。
- v1.1.2（2026-10-01）：按机器 JSON 重数动态业务字段为 6 个（原文误写 12），更新配套设计版本与依赖口径；未改 JSON、未运行任何测试。自审 2 轮，末轮 clean。
