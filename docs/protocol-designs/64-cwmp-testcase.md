# CWMP（CPE 广域网管理协议 / TR-069）测试用例契约

> 版本：v2.0.0（设计阶段）
> 日期：2026-08-31
> 配套设计：`docs/protocol-designs/64-cwmp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/cwmp.json`（proto key：`cwmp`）
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）断言。当前 JSON 仅含注册前置占位 `cwmp_neg_unregistered`，实现期按本文 §2 顺序替换为 20 个语义用例。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例 + 6 个负例。派生规则：设计 §3 每个编码条款、§5 每个状态/事务行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 TR-069）声明范围。

**断言字段以 tshark 3.6.14 实测为准**（`tshark -G fields` 已核验）：本机**没有 CWMP 专用 dissector（解析器）**，不存在任何 `cwmp.*` 字段，**不得臆造**。可用字段为：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.response.code`、`http.content_type`、`http.content_length`、`http.request.line`、`http.response.line`、`http.cookie`、`http.set_cookie`、`http.authorization`、`http.www_authenticate`、`http.file_data`、`tcp.stream`、`tcp.len`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。SOAP/XML 内容断言走两条路：① `http.file_data` 存在性（fields 断言 nonzero）；② raw frame（原始帧）稳定 ASCII 前缀的 hex 断言（`frames` 的 `offset/hex`，见 §3）。

动态字段禁止硬编码：`cwmp:ID` 计数、Cookie、DeviceId 四元组值、CommandKey、ParameterKey、URL、dateTime、digest nonce 用 `nonzero`、`distinct_values`、`same_as_packet` 或 frames hex 前缀断言；不声称设备真实身份、文件真实下载/上传、设备真实重启。HTTPS 未解密时只断言 TLS/TCP 外层，不解读密文为 HTTP/SOAP（本版无 HTTPS 语义用例，见设计 §1 边界）。

## 2. 原子用例索引

约定 packet_count（正例）按公式推导：3（握手）+ 2×HTTP 请求/响应对数（单段时）+ 4（挥手 FIN/ACK×2+ACK×2）；SOAP 体跨段每加 1 段 +1；多会话 = 各会话之和。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count（执行期 `expect` 严格只有 `expect_error`、`error_contains`）。

| # | ID | 正/负 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `cwmp_inform_ipv4` | 正 | v4 单流基线：Inform(2 PERIODIC)→InformResponse→空 POST→204 | POST/200/204、`urn:dslforum-org:cwmp-1-0`、ID same_as、MaxEnvelopes=1 |
| 2 | `cwmp_inform_event_codes` | 正 | 事件码值域与组合、DeviceId、ParameterList 边界 | EventCode ASCII hex、1 BOOT+M Reboot 同 Inform |
| 3 | `cwmp_connection_request` | 正 | ACS 主动 GET/401 digest/200 空体 + 新会话 6 CONNECTION REQUEST | GET→401→GET→200、`http.www_authenticate`/`http.authorization`、双连接四元组 |
| 4 | `cwmp_get_parameter_values` | 正 | GetParameterValues + GetParameterNames 两事务 | ParameterNames/ParameterList/`soap-enc:arrayType`/Writable |
| 5 | `cwmp_set_parameter_values` | 正 | SetParameterValues：ParameterKey、Status 0/1 | Status 0 与 1 两次、ParameterKey same_as |
| 6 | `cwmp_download_transfer_complete` | 正 | Download→DownloadResponse(1)→新会话 TransferComplete | CommandKey 跨会话 same_as、FaultStruct FaultCode=0 |
| 7 | `cwmp_download_flow_correlation` | 正 | 流关联：Download 驱动独立副连接 HTTP GET | 副连接四元组 distinct、GET uri 与 Download URL 一致 |
| 8 | `cwmp_upload_transfer_complete` | 正 | Upload→UploadResponse(1)→新会话 TransferComplete | Upload 参数形状、CommandKey 关联 |
| 9 | `cwmp_reboot_command_key` | 正 | Reboot→RebootResponse→新会话 Inform(1 BOOT+M Reboot) | CommandKey 同值、事件码组合 |
| 10 | `cwmp_fault_soap` | 正 | SOAP Fault/CWMP Fault 900x 且会话继续 | faultstring=`CWMP fault`、9003+9007 detail、后续事务存在 |
| 11 | `cwmp_http_keepalive_multi_transaction` | 正 | 同连接多事务（Inform→GetRPCMethods→SetParameterValues→空 POST→204） | ≥4 对请求/响应严格交替、Content-Length 自洽 |
| 12 | `cwmp_ipv6` | 正 | IPv6 单流 Inform 会话 | `ipv6.nxt=6`、offset 74、SOAP 字节同 v4 |
| 13 | `cwmp_multi_session` | 正 | 多会话展开双四元组、状态不串用 | 源端口 distinct、ID 序列独立、包号连续 |
| 14 | `cwmp_mss_large_soap` | 正 | 大 SOAP 体跨 MSS 分段重组 | 跨 3 段、重组后 envelope 完整、Content-Length=重组长 |
| 15 | `cwmp_neg_config` | 负 | 配置错（profile/namespace/层链/端口） | `profile`/`namespace`/`carrier`/`port` |
| 16 | `cwmp_neg_http_wire` | 负 | HTTP 线格式错（method/SOAPAction/Content-Type/长度/auth） | `http`/`method`/`auth`/`content-type` |
| 17 | `cwmp_neg_xml_soap` | 负 | SOAP/XML 线格式错（namespace/envelope/Fault 结构） | `xml`/`soap`/`envelope`/`fault` |
| 18 | `cwmp_neg_session_state` | 负 | 状态机错（首事务/空 POST 后续发/方向/Fault 后续） | `session`/`state`/`sequence` |
| 19 | `cwmp_neg_correlation` | 负 | 关联错（ID 错配/CommandKey 无来源/副连接主从不符） | `id`/`command`/`correlation` |
| 20 | `cwmp_neg_length` | 负 | 长度/值域错（上界越界/非法枚举/截断） | `length`/`parameter`/`value` |
| — | `cwmp_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

层链 `[tcp, http, cwmp]`，无 VLAN/IP options/TCP options 时 TCP payload 起点 IPv4 offset 54、IPv6 offset 74。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起为 ASCII `POST /acs HTTP/1.1\r\n`（hex `50 4F 53 54 20 …`）；响应帧起行 `HTTP/1.1 200 OK\r\n` 或 `HTTP/1.1 204 No Content\r\n`。头断言用 fields：`http.request.method=POST`、`http.content_type` 以 `text/xml` 开头、`http.content_length` 等于 SOAP body 实际字节长、空 POST 断言 `http.request.line` 中**无** `Content-Type:`/`SOAPAction:` 行、含 SOAP 响应的请求断言存在空值 `SOAPAction:` 行。
2. **SOAP envelope（frames hex + http.file_data）**：`http.file_data` nonzero 证明 body 存在；envelope 结构用 body 起点偏移（= 54 + 该 fixture 固定 HTTP 头长，头集合由配置钉死，偏移可预算）的稳定 ASCII 前缀断言：`3C 73 6F 61 70 3A 45 6E 76 65 6C 6F 70 65`（`<soap:Envelope`）、`63 77 6D 70 3A 49 6E 66 6F 72 6D`（`cwmp:Inform`）、`3C 63 77 6D 70 3A 49 44`（`<cwmp:ID`）、`43 57 4D 50 20 66 61 75 6C 74`（`CWMP fault`）等。TCP 分段边界不是 HTTP/SOAP 边界：跨段时先按 `tcp.stream` 重组，再对重组后末帧断言完整 envelope 与 Content-Length。
3. **认证字段**：401 挑战断言 `http.response.code=401` + `http.www_authenticate` 含 `Digest`；重发断言 `http.authorization` 含 `Digest` 与 `username=`；成功断言 `http.response.code=200` 且响应体零长度（`http.content_length=0` 或无 `http.file_data`）。
4. **has_payload 语义**：SOAP 帧经常远大于普通帧，`frame.len>80` 只作宽松代理；**权威断言是 `http.file_data` nonzero + 上述 hex 前缀**，二者齐备才算"有 SOAP 载荷"，不得以包数或 PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事务→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。断言跨会话关联（CommandKey/ID）时用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。

1. **`cwmp_inform_ipv4`**（11）：`192.0.2.65:50065 → 198.51.100.65:7547`。断言三次握手、`http.request.uri`、Inform 帧 `http.file_data` nonzero + `cwmp:Inform` hex 前缀、`<cwmp:ID` hex 前缀、DeviceId 四元素名 hex、`200`+InformResponse（ID same_as Packet 4 的 ID 值、MaxEnvelopes=1 文本 `>1<` 边界 hex）、空 POST 无 SOAPAction 行、`204`、挥手。RetryCount=0、`2 PERIODIC` 事件码 hex。
2. **`cwmp_inform_event_codes`**（11）：同一会话形状。两次 fixture 分别携带 `1 BOOT`+`M Reboot`（同 CommandKey same_as）与 `4 VALUE CHANGE`（ParameterList 非空）与 `7 TRANSFER COMPLETE`+`M Download`；断言 EventCode 字符串 hex、`DeviceId` 结构名 hex、空 ParameterList 时无 `ParameterValueStruct` hex。事件码不在 §3.5 值域的组合进负例 20。
3. **`cwmp_connection_request`**（22 = CR 连接 11 + Inform 连接 11）：连接 A（ACS `198.51.100.65:51000 → CPE 192.0.2.65:7547`）：`GET`（`http.request.method=GET`）→`401`+`http.www_authenticate` 含 `Digest`→`GET`+`http.authorization` 含 `username=`→`200` 零长度体。连接 B（CPE→ACS，源端口 distinct）：Inform 帧 `6 CONNECTION REQUEST` hex，`tcp.stream` distinct 断言两连接独立。
4. **`cwmp_get_parameter_values`**（15）：会话事务 Inform→空 POST→ACS GetParameterNames（响应承载）→CPE GetParameterNamesResponse→ACS GetParameterValues→CPE GetParameterValuesResponse→204。断言 `ParameterPath` 尾点 hex（`Device.DeviceInfo.`）、`NextLevel`、`soap-enc:arrayType="cwmp:ParameterInfoStruct[` 前缀 hex、Writable=`0/1`、ParameterValueStruct 的 Name/Value 与 `xsi:type` hex、每笔响应 ID same_as 对应请求。
5. **`cwmp_set_parameter_values`**（13）：ACS SetParameterValues（ParameterList+ParameterKey）→CPE SetParameterValuesResponse；Status 0 与 Status 1 各断言一次（`>0<`/`>1<` hex，1 时同会话无 Reboot 帧——重启由会话外表达）；ParameterKey same_as。
6. **`cwmp_download_transfer_complete`**（26 = 13+13 多会话展开）：会话 1 断言 Download 参数 hex（`CommandKey`/`"3 Vendor Configuration File"`/`URL`/`FileSize`）与 DownloadResponse `>1<`；会话 2 起点 = 13+1，断言 Inform 携带 `7 TRANSFER COMPLETE`+`M Download`、TransferComplete 帧 CommandKey same_as 会话 1、`FaultStruct` 内 `FaultCode` 为 `>0<`。
7. **`cwmp_download_flow_correlation`**（22 = 主会话 13 + 副连接 9）：主会话含 Download（URL=`http://203.0.113.10/fw/1.2.3.bin`）；副连接四元组 `192.0.2.65:50066 → 203.0.113.10:80`，断言 `GET`+`http.request.uri=/fw/1.2.3.bin` 与 Download URL 路径一致、`200`+文件字节（`http.file_data` nonzero）、副连接 `tcp.stream` 与主会话 distinct。主从驱动顺序：副连接 GET 帧号在 DownloadResponse 之后。
8. **`cwmp_upload_transfer_complete`**（26 = 13+13）：会话 1 ACS 发 Upload（参数形状同 Download）→UploadResponse `>1<`；会话 2 TransferComplete，CommandKey same_as。
9. **`cwmp_reboot_command_key`**（24 = 13+11）：会话 1 Reboot（CommandKey=`REBOOT-1`）→RebootResponse；会话 2 Inform 携带 `1 BOOT`+`M Reboot` 且 CommandKey same_as 会话 1。
10. **`cwmp_fault_soap`**（15）：ACS 发 GetParameterValues（含非法参数名）→CPE Fault 帧：`faultstring` 精确 hex `43 57 4D 50 20 66 61 75 6C 74`（`CWMP fault`）、`detail` 内 `FaultCode`=`9005` hex、SetParameterValuesFault 主码 `9003`+逐参数 `9007`；Fault 后会话继续（存在后续空 POST/204）；响应 ID same_as 请求。
11. **`cwmp_http_keepalive_multi_transaction`**（17）：单 `tcp.stream` 承载 ≥4 对请求/响应（Inform/InformResponse、空 POST/GetRPCMethods、GetRPCMethodsResponse/SetParameterValues、SetParameterValuesResponse/204、空 POST/204）；断言对间无 `Connection: close`、请求/响应严格交替（无 pipelining）、每帧 Content-Length 与 `http.file_data` 长度自洽、GetRPCMethods 响应 `MethodList` 含 `GetRPCMethods`/`Inform` hex。
12. **`cwmp_ipv6`**（11）：`2001:db8::65 → 2001:db8::7547 端口` 对端 `7547`；断言 `ipv6.nxt=6`、payload offset 74、Inform envelope 字节与用例 1 一致（外层 IP 头除外）。
13. **`cwmp_multi_session`**（26 = 13+13）：会话 1（周期 Inform+GetParameterValues）与会话 2（BOOT Inform+SetParameterValues）不同源端口；断言两 `tcp.stream`、各自 ID 从 1001/2001 起独立递增（distinct）、Cookie 仅在本会话内回带（`http.cookie` 值 distinct）、第二会话握手包号 = 14。
14. **`cwmp_mss_large_soap`**（≥12，按段数校准）：ParameterList ≥3000 字节、MSS 压到 536 使 Inform 跨 3 段；断言 `tcp.len` 分布、重组后（末段）envelope 完整且 Content-Length=body 实际长、`ParameterList` 成员数与配置一致。

## 5. 负例契约

负例必须在 planner/validator 失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。锚词与设计 §7 表一一对应：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `cwmp_neg_config` | profile 与 namespace 不匹配（如 SOAP 1.2 envelope 命名空间）、层链缺 http（tcp→cwmp 直连）、端口/载体矛盾 | `profile`、`namespace`、`carrier` 或 `port` |
| `cwmp_neg_http_wire` | 方法非 POST、SOAPAction 带值、Content-Type 非 text/xml、Content-Length≠实体长、401 后 Authorization 缺失仍继续 | `http`、`method`、`auth` 或 `content-type` |
| `cwmp_neg_xml_soap` | XML 截断、envelope 命名空间错、Body 缺失、响应缺 `Response` 后缀、faultstring≠`CWMP fault` 或 detail 缺 `cwmp:Fault` | `xml`、`soap`、`envelope` 或 `fault` |
| `cwmp_neg_session_state` | 首事务非 Inform、空 POST 后继续发请求、CPE 发送 ACS 方法、Fault 响应 Fault、未终止会话即重启 | `session`、`state` 或 `sequence` |
| `cwmp_neg_correlation` | 响应 ID≠请求 ID、TransferComplete CommandKey 无来源、`flows[].driven_by` 引用不存在的事务/字段 | `id`、`command` 或 `correlation` |
| `cwmp_neg_length` | 参数名 >256、CommandKey >32、Event 数组 >64、事件码/FaultCode/FileType 非法值、实体超长截断 | `length`、`parameter` 或 `value` |

合法协议事件不进负例（防误报）：401 挑战本身、DownloadResponse/UploadResponse Status=1、Status=0 直接成功、空 ParameterList/空 ParameterKey、FileSize=0、CPE 已在会话回 503、8005 Retry request 重发、Fault 响应本身。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1、2、4、5、6、8、9、10、11（正）；15–20（负） | baseline RPC 全主干 + Fault；五类错误各≥1 条负例；多流显式不适用（§3.4.6 禁 pipelining，设计 §4 声明） |
| 性能 | 14 | 大 SOAP 体跨 MSS 分段重组 + 32KB envelope 下限 + 长度上界断言 |
| 数据场景 | 2、5、10；负 20 | 事件码/FileType/FaultCode 枚举值域、Status 0/1、ParameterKey 空/非空、FileSize=0、上界越界拒绝 |
| 地址与流 | 1（v4 单流基线）、12（v6）、7（流关联副连接）、13（多会话双四元组） | v4+v6 必覆盖；流关联主从由 `driven_by` 与包序断言 |
| 业务 | 1（周期 Inform）、3（ACS 主动连接）、6（升级全流程）、8（日志上报）、9（远程重启）、11（长会话批量管理）、13（多设备并行管理） | 现网典型场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/cwmp.json` 通过；当前数组恰含 1 条 `cwmp_neg_unregistered`：`proto=cwmp`、层链 `[{"tcp":{}},{"http":{}},{"cwmp":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `cwmp` 层后：移除占位，按 §2 顺序补入 20 个语义用例；ID、顺序与设计 §9 完全一致。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段，不伪造 `cwmp.*`；SOAP 断言用 §3 的 hex 前缀约定。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 断言包号引用跨会话/跨连接时用 `tcp.stream`+会话起点规则（§3.5），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `cwmp.json` 保持同一 20 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
cwmp_inform_ipv4
cwmp_inform_event_codes
cwmp_connection_request
cwmp_get_parameter_values
cwmp_set_parameter_values
cwmp_download_transfer_complete
cwmp_download_flow_correlation
cwmp_upload_transfer_complete
cwmp_reboot_command_key
cwmp_fault_soap
cwmp_http_keepalive_multi_transaction
cwmp_ipv6
cwmp_multi_session
cwmp_mss_large_soap
cwmp_neg_config
cwmp_neg_http_wire
cwmp_neg_xml_soap
cwmp_neg_session_state
cwmp_neg_correlation
cwmp_neg_length
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（与旧设计稿配套的 14+6 ID 索引）。
- v2.0.0（2026-08-31）：**按 2026-08-31 需求契约重写取代旧稿**。索引表改为需求五列格式（正/负 + 实现后证据）；按 tshark 3.6.14 实测固化"无 `cwmp.*` 字段、fields 只用 `http.*`/`tcp.*`/`ipv6.nxt`、SOAP 走 frames hex 前缀"的断言基线；新增 §3 has_payload 语义与多会话包号规则、§6 五层覆盖映射；20 个 ID 与新设计稿 §9 对齐（删 pcap_nic_consistency/multi_flow/https_tls_opaque，新增流关联/多事务/多会话展开/MSS/v6 独立用例）。三向对抗审查 2 轮：第 1 轮（用例审设计）补 connection_request 的 200 空体断言与 fault_soap 的"会话继续"断言；第 2 轮（设计审用例 + 规范回对）修正 multi_session 会话 2 握手包号为 14（13+1）、核对 faultstring `CWMP fault` 与 FaultCode 9003+9007 组合出处（TR-069 §3.5 示例），结论 clean。
