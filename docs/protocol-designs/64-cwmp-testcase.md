# CWMP（CPE 广域网管理协议 / TR-069）测试用例契约

> 版本：v2.1.1（设计阶段）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/64-cwmp-design.md`（v2.1.1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/cwmp.json`（proto key：`cwmp`）
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）断言。当前 JSON 仅含注册前置占位 `cwmp_neg_unregistered`，实现期按本文 §2 顺序替换为 20 个语义用例。**独立隔离对抗审查已完成**（v2.1.1 定稿：独立审查 agent 三向审计 23 项清单（2C/8M/13N）→ 修复 → 复验发现 N01-N03 → 二轮修复 → 二轮复验 clean；审查/修复记录见 §9 修订记录 v2.0.0–v2.1.1）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例 + 6 个负例。派生规则：设计 §3 每个编码条款、§5 每个状态/事务行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 TR-069）声明范围。

**断言字段以 tshark 3.6.14 实测为准**（`tshark -G fields` 已核验）：本机**没有 CWMP 专用 dissector（解析器）**，不存在任何 `cwmp.*` 字段，**不得臆造**。可用字段为：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.response.code`、`http.content_type`、`http.content_length`、`http.request.line`、`http.response.line`、`http.cookie`、`http.set_cookie`、`http.authorization`、`http.www_authenticate`、`http.file_data`、`tcp.stream`、`tcp.len`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。SOAP/XML 内容断言走两条路：① `http.file_data` 存在性（fields 断言 nonzero）；② raw frame（原始帧）稳定 ASCII 前缀的 hex 断言（`frames` 的 `offset/hex`，见 §3）。

动态字段禁止硬编码：`cwmp:ID` 计数、Cookie、DeviceId 四元组值、CommandKey、ParameterKey、URL、dateTime、digest nonce 用 `nonzero`、`distinct_values`、`same_as_packet` 或 frames hex 前缀断言；不声称设备真实身份、文件真实下载/上传、设备真实重启。HTTPS 未解密时只断言 TLS/TCP 外层，不解读密文为 HTTP/SOAP（本版无 HTTPS 语义用例，见设计 §1 边界）。

**显式不适用声明（与设计 §4 末尾声明逐项一致，不设正例、不进负例）**：HTTP 重定向 302/307（生成器无重定向响应源）、HTTP chunked 传输编码（fixture 全部用 Content-Length 界定边界）、CPE 已在会话时对 CR 回 503（本版 CR 均取 CPE 空闲态成功路径）、失败会话重试（本版 Inform 会话均成功、RetryCount=0）、文件服务器 basic/digest 认证（副连接为公开 URL 无 401 挑战，用例 7）、`X_<VENDOR>_Method` 厂商扩展 RPC（无厂商扩展 fixture，设计 §1 仅声明透传能力）。

## 2. 原子用例索引

约定 packet_count（正例）按公式推导：**单会话块** = 3（握手）+ 2×HTTP 请求/响应对数（单段时）+ 4（挥手 FIN/ACK×2+ACK×2），**每个正常会话以空 POST/204 对收尾**；**副连接块**（`flows[]` 下载连接，流关联）= 3（握手）+ 2×GET/响应对 + 4（挥手），在多会话展开中的插入位置唯一：紧跟主会话 DownloadResponse 事务之后、主会话空 POST 之前发起并完成，主会话挥手是主会话块最后一帧组（设计 §5 流关联；主会话对 DownloadResponse 的应答同为 204——按设计 §5 收尾教义，应答非空 POST 的 204 不终止会话，会话以收尾的空 POST/204 对终止）；SOAP 体跨段每加 1 段 +1；**多会话 = 各块（会话块/副连接块）顺次之和**，下一块握手包号 = 前块总包数 + 1。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count（执行期 `expect` 严格只有 `expect_error`、`error_contains`）。

| # | ID | 正/负 | 覆盖 | 设计 § | 实现后证据 |
|---:|---|---|---|---|---|
| 1 | `cwmp_inform_ipv4` | 正 | v4 单流基线：Inform(2 PERIODIC)→InformResponse→空 POST→204 | §3.5、§4①、§5 | POST/200/204、`urn:dslforum-org:cwmp-1-0`、ID same_as、MaxEnvelopes=1 |
| 2 | `cwmp_inform_event_codes` | 正 | 事件码子集（0 BOOTSTRAP+1 BOOT、4 VALUE CHANGE、7 TRANSFER COMPLETE+M Download）、Event 满 64、DeviceId 上界、OUI/dateTime/XML 转义、空 ParameterList | §3.5、§8 | EventCode ASCII hex、`0 BOOTSTRAP` hex、64 事件 hex 计数、`&amp;` hex |
| 3 | `cwmp_connection_request` | 正 | ACS 主动 GET/401 digest(`qop="auth"`)/200 空体 + 新会话 6 CONNECTION REQUEST；用户名百分号编码 | §3.3、§4③、§5 | GET→401→GET→200、`http.www_authenticate` 含 `qop="auth"`、`http.authorization` 含 `%20`、双连接四元组 |
| 4 | `cwmp_get_parameter_values` | 正 | GetParameterValues + GetParameterNames 两事务、string(256) 参数名上界 | §3.5（A.3.2.2/A.3.2.3）、§4②、§8 | ParameterNames/ParameterList/`soap-enc:arrayType`/Writable、256 字符参数名不截断 |
| 5 | `cwmp_set_parameter_values` | 正 | 两笔 SetParameterValues：Status 0/1 各一次；ParameterKey 空/32 字符各一次 | §3.5（A.3.2.1）、§4②、§8 | Status `>0<`/`>1<`、空 ParameterKey hex、32 字符 ParameterKey 完整 |
| 6 | `cwmp_download_transfer_complete` | 正 | 下载完成三途径（段 A=①Status=0、段 B=②同会话 TC、段 C=③新会话 TC）；FileSize=0、DelaySeconds=0/非 0、FileType 1/3、CommandKey 32 上界 | §3.5（A.3.2.8）、§4④、§8 | Status hex、CommandKey 跨会话 same_as、FaultStruct FaultCode=0、FileType 代表值 hex |
| 7 | `cwmp_download_flow_correlation` | 正 | 流关联：Download 驱动独立副连接 HTTP GET；插入位置（DownloadResp 后、空 POST 前、主会话挥手最后） | §4④、§5、§8 | 副连接四元组 distinct、GET uri 与 Download URL 一致、GET 帧号在 DownloadResponse 之后 |
| 8 | `cwmp_upload_transfer_complete` | 正 | Upload→UploadResponse(1)→新会话 Inform(7+M Upload)→TransferComplete | §3.5（A.4.1.5）、§4⑤ | Upload 参数形状、CommandKey 关联、`M Upload` hex |
| 9 | `cwmp_reboot_command_key` | 正 | Reboot→RebootResponse→新会话 Inform(1 BOOT+M Reboot) | §3.5（A.3.2.9）、§4⑥ | CommandKey 同值、事件码组合 |
| 10 | `cwmp_fault_soap` | 正 | 段 A：Inform 收非 8005 Fault→会话失败终止；段 B：8005 原样重发→SetParameterValues 触发 SetParameterValuesFault（9003+9007）→会话继续；faultcode Client/Server 二值 | §3.4、§3.6、§5 | faultstring=`CWMP fault`、`<faultcode>Client`/`<faultcode>Server` hex、8002/8005/9003/9007 hex、重发 ID same_as |
| 11 | `cwmp_http_keepalive_multi_transaction` | 正 | 同连接多事务（Inform→GetRPCMethods→SetParameterValues→空 POST→204），无 pipelining | §2、§3.3、§5 | ≥4 对请求/响应严格交替（实际 5 对）、Content-Length 自洽 |
| 12 | `cwmp_ipv6` | 正 | IPv6 单流 Inform 会话（src `2001:db8::65` → dst `2001:db8::1`，dst_port=7547） | §2、§8 | `ipv6.nxt=6`、offset 74、SOAP 字节同 v4 |
| 13 | `cwmp_multi_session` | 正 | 多会话展开双四元组、状态不串用 | §5、§8 | 源端口 distinct、ID 序列独立、包号连续 |
| 14 | `cwmp_mss_large_soap` | 正 | 大 SOAP 体（envelope ≥32768 字节）跨 MSS 分段重组，默认 MSS 1460 | §3.5、§8 | ≈23 段、`http.content_length` ≥32768、重组后 envelope 完整 |
| 15 | `cwmp_neg_config` | 负 | 配置错（profile/namespace/层链/端口） | §7 | `profile`/`namespace`/`carrier`/`port` |
| 16 | `cwmp_neg_http_wire` | 负 | HTTP 线格式错（method/SOAPAction/Content-Type/长度/auth） | §7 | `http`/`method`/`auth`/`content-type` |
| 17 | `cwmp_neg_xml_soap` | 负 | SOAP/XML 线格式错（namespace/envelope/Fault 结构） | §7 | `xml`/`soap`/`envelope`/`fault` |
| 18 | `cwmp_neg_session_state` | 负 | 状态机错（首事务/空 POST 后续发/方向/Fault 后续/响应另一个响应） | §7 | `session`/`state`/`sequence` |
| 19 | `cwmp_neg_correlation` | 负 | 关联错（ID 错配/CommandKey 无来源/副连接主从不符） | §7 | `id`/`command`/`correlation` |
| 20 | `cwmp_neg_length` | 负 | 长度/值域错（上界越界/非法枚举/截断） | §7 | `length`/`parameter`/`value` |
| — | `cwmp_neg_unregistered` | 占位 | 当前层注册前置 | §1 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

层链 `[tcp, http, cwmp]`，无 VLAN/IP options/TCP options 时 TCP payload 起点 IPv4 offset 54、IPv6 offset 74。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起为 ASCII `POST /acs HTTP/1.1\r\n`（hex `50 4F 53 54 20 …`）；响应帧起行 `HTTP/1.1 200 OK\r\n` 或 `HTTP/1.1 204 No Content\r\n`。头断言用 fields：`http.request.method=POST`、`http.content_type` 以 `text/xml` 开头、`http.content_length` 等于 SOAP body 实际字节长、空 POST 断言 `http.request.line` 中**无** `Content-Type:`/`SOAPAction:` 行、含 SOAP 响应的请求断言存在空值 `SOAPAction:` 行。
2. **SOAP envelope（frames hex + http.file_data）**：`http.file_data` nonzero 证明 body 存在；envelope 结构用 body 起点偏移（= 54 + 该 fixture 固定 HTTP 头长，头集合由配置钉死，偏移可预算）的稳定 ASCII 前缀断言：`3C 73 6F 61 70 3A 45 6E 76 65 6C 6F 70 65`（`<soap:Envelope`）、`63 77 6D 70 3A 49 6E 66 6F 72 6D`（`cwmp:Inform`）、`3C 63 77 6D 70 3A 49 44`（`<cwmp:ID`）、`43 57 4D 50 20 66 61 75 6C 74`（`CWMP fault`）等。TCP 分段边界不是 HTTP/SOAP 边界：跨段时先按 `tcp.stream` 重组，再对重组后末帧断言完整 envelope 与 Content-Length。
3. **认证字段**：401 挑战断言 `http.response.code=401` + `http.www_authenticate` 含 `Digest` **且含 `qop="auth"`**（设计 §3.3/RFC 7616 必须支持项，frames 字节断言 `qop="auth"`）；重发断言 `http.authorization` 含 `Digest` 与 `username=`（用户名按 RFC 3986 百分号编码，如 `GW%20Room`）；成功断言 `http.response.code=200` 且响应体零长度（`http.content_length=0` 或无 `http.file_data`）。
4. **has_payload 语义**：SOAP 帧经常远大于普通帧，`frame.len>80` 只作宽松代理；**权威断言是 `http.file_data` nonzero + 上述 hex 前缀**，二者齐备才算"有 SOAP 载荷"，不得以包数或 PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事务→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。断言跨会话关联（CommandKey/ID）时用 `tcp.stream` 区分，不硬编码全局包号。
6. **副连接（流关联）插入规则**：`flows[]` 副连接不是独立的多会话块，而是**主会话块内的插入块**——紧跟主会话 DownloadResponse 事务之后、主会话空 POST 之前发起并完成（副连接自身握手→GET/200→挥手），随后主会话继续空 POST→204→挥手，**主会话挥手是主会话块的最后一帧组**；主会话对 DownloadResponse 的应答同为 204（应答非空 POST 的 204 不终止会话，见设计 §5 收尾教义）。断言：副连接 GET 帧号 > DownloadResponse 请求帧号、< 主会话空 POST 帧号；副连接 `tcp.stream` 与主会话 distinct（设计 §5 流关联）。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。

1. **`cwmp_inform_ipv4`**（11）：`192.0.2.65:50065 → 198.51.100.65:7547`。断言三次握手、`http.request.uri`、Inform 帧 `http.file_data` nonzero + `cwmp:Inform` hex 前缀、`<cwmp:ID` hex 前缀、DeviceId 四元素名 hex、`200`+InformResponse（ID same_as Packet 4 的 ID 值、MaxEnvelopes=1 文本 `>1<` 边界 hex）、空 POST 无 SOAPAction 行、`204`、挥手。RetryCount=0、`2 PERIODIC` 事件码 hex。
2. **`cwmp_inform_event_codes`**（44 = 4 次 fixture × 11，多会话展开）：每次 fixture 为一个完整 Inform 会话（握手 3 + Inform POST/InformResponse 2 + 空 POST/204 2 + 挥手 4 = 11 包，每会话以空 POST/204 对收尾）。fixture 1（`0 BOOTSTRAP`+`1 BOOT`，现网首次连接组合）：断言 `0 BOOTSTRAP` hex（`30 20 42 4F 4F 54 53 54 52 41 50`）与 `1 BOOT` hex 同帧、DeviceId 四元素名 hex、OUI 六位大写十六进制（含字母值如 `00AB12`，断言大写 `41 42` hex，`^[0-9A-F]{6}$`）、ProductClass/SerialNumber 64 字符上界完整 hex、CurrentTime 带时区偏移（如 `+08:00`，断言符号+`hh:mm` 尾 hex）、ParameterList 值含 XML 转义（`&amp;` hex `26 61 6D 70 3B`）。fixture 2（`4 VALUE CHANGE`）：EventCode hex、ParameterList 非空（含 `ParameterValueStruct` hex）。fixture 3（`7 TRANSFER COMPLETE`+`M Download`，CommandKey 随事件携带）：两个 EventCode 同帧 hex、空 ParameterList（无 `ParameterValueStruct` hex）。fixture 4（Event 数组满 64 上界）：断言 `EventStruct` 计 64 个（`EventCode` hex 出现计数 / `soap-enc:arrayType` 数组维度 hex）。事件码不在设计 §3.5 实现子集的组合进负例 20。
3. **`cwmp_connection_request`**（22 = CR 连接 11 + Inform 连接 11）：连接 A（ACS `198.51.100.65:51000 → CPE 192.0.2.65:7547`）：`GET`（`http.request.method=GET`）→`401`+`http.www_authenticate` 含 `Digest` **且含 `qop="auth"`**（frames 字节断言）→`GET`+`http.authorization` 含 `Digest`、`username=`，用户名按 RFC 3986 百分号编码（`ProductClass="GW Room"` → Authorization 中 `GW%20Room`，断言 `%20` hex `25 32 30`）→`200` 零长度体。连接 B（CPE→ACS，源端口 distinct）：Inform 帧 `6 CONNECTION REQUEST` hex，`tcp.stream` distinct 断言两连接独立。
4. **`cwmp_get_parameter_values`**（30 = 15+15，两会话块多会话展开；按需求 §7 原子拆分，每 RPC 独立会话，每会话以空 POST/204 对收尾）：会话 1（GetParameterNames，15 = 3+4 对×2+4）：Inform→空 POST→ACS GetParameterNames（响应承载）→CPE GetParameterNamesResponse→204（不关连接）→空 POST→204；断言 `ParameterPath` 尾点 hex（`Device.DeviceInfo.`）、`NextLevel`、`soap-enc:arrayType="cwmp:ParameterInfoStruct[` 前缀 hex、Writable=`0/1`、响应 ID same_as 请求。会话 2（GetParameterValues，15 包，握手包号 = 16）：Inform→空 POST→ACS GetParameterValues→CPE GetParameterValuesResponse→204（不关连接）→空 POST→204；断言 `ParameterNames` 尾点 hex（部分路径以 `.` 结尾）、`soap-enc:arrayType="cwmp:ParameterValueStruct[` 前缀 hex、ParameterValueStruct 的 Name/Value 与 `xsi:type` hex、响应 ID same_as 请求；ParameterNames 之一携带 string(256) 上界参数名（配置钉死），断言 `http.file_data` nonzero 且参数名首尾 hex 完整不截断（上界正例；负例 20 拒 >256）。
5. **`cwmp_set_parameter_values`**（17 = 3 握手 + 5 对×2 + 4 挥手）：5 对事务：Inform→InformResponse；空 POST→ACS SetParameterValues#1（ParameterList + **空 ParameterKey**，合法且必须保持为空）→CPE SetParameterValuesResponse（Status=`0`，`>0<` hex）→ACS SetParameterValues#2（ParameterKey **恰 32 字符上界**）→CPE SetParameterValuesResponse（Status=`1`，`>1<` hex；1 时同会话无 Reboot 帧——重启由会话外表达）→204（不关连接）→空 POST→204（收尾对）。断言：空 ParameterKey 为 `<ParameterKey></ParameterKey>` 开闭标签相邻、值为空（frames hex `3C 50 61 72 61 6D 65 74 65 72 4B 65 79 3E 3C 2F 50 61 72 61 6D 65 74 65 72 4B 65 79 3E`）、32 字符 ParameterKey 完整 hex（上界正例；负例 20 拒 >32）、Status `>0<`/`>1<` 各一次、每笔响应 ID same_as 请求。
6. **`cwmp_download_transfer_complete`**（69 = 段 A 15 + 段 B 26 + 段 C 28，四会话块多会话展开；**下载完成三途径全覆盖**，设计 §3.5/A.3.2.8；每会话以空 POST/204 对收尾）：段 A（途径① DownloadResponse Status=0 直接成功，15 = 3+4 对×2+4）：Inform→空 POST→ACS Download（FileType=`"3 Vendor Configuration File"`、FileSize=`0`（大小未知）、DelaySeconds=`0`）→CPE DownloadResponse（Status=`>0<`）→204（不关连接）→空 POST→204（收尾对）；断言 FileSize `>0<` hex、Status=0 后**无** TransferComplete 帧（途径①不需要补发）。段 B（途径② 同会话 TransferComplete，26 = 主会话 17 + 副连接 9）：主会话 Inform→空 POST→ACS Download（DelaySeconds=`0`）→DownloadResponse（Status=`>1<`）→**204（应答非空 POST，不关连接）**→**副连接插入**（握手→GET/200→挥手，§3.6 规则）→CPE 同会话 TransferComplete（CommandKey same_as、FaultStruct FaultCode=`>0<`）→TransferCompleteResponse→空 POST→204（收尾对）；断言 TransferComplete 帧与主会话同 `tcp.stream`。段 C（途径③ 新会话 TransferComplete，28 = 15+13）：会话 C1：Inform→空 POST→ACS Download（DelaySeconds=**非 0**（如 60）、FileType=`"1 Firmware Upgrade Image"`、CommandKey 恰 32 字符上界）→DownloadResponse（Status=`>1<`）→204（不关连接）→空 POST→204（收尾对）；断言**同会话无副连接 GET 帧、无 TransferComplete 帧**（DelaySeconds 非 0 禁止同会话执行）；会话 C2（起点 = C1 总包数+1）：Inform 携带 `7 TRANSFER COMPLETE`+`M Download` hex→TransferComplete（CommandKey same_as 会话 C1、FaultCode=`>0<`）→TransferCompleteResponse→空 POST→204（收尾对）。
7. **`cwmp_download_flow_correlation`**（24 = 主会话 15 + 副连接 9）：主会话（`192.0.2.65:50065 → 198.51.100.65:7547`，即设计 §6 typedef 示例的 session 0）：Inform→空 POST→ACS Download（URL=`http://203.0.113.10/fw/1.2.3.bin`、DelaySeconds=`0`）→CPE DownloadResponse（Status=`1`）→**204（应答非空 POST，不关连接）**→**副连接插入**：副连接四元组 `192.0.2.65:50066 → 203.0.113.10:80`（设计 §6 `flows[]` 示例），握手→`GET`+`http.request.uri=/fw/1.2.3.bin`（与 Download URL 路径一致）→`200`+文件字节（`http.file_data` nonzero）→挥手→主会话继续空 POST→204（收尾对）→**主会话挥手（主会话块最后一帧组）**。断言：副连接 `tcp.stream` distinct、GET 帧号在 DownloadResponse 请求帧之后且在主会话空 POST 之前、主会话挥手帧号在副连接挥手之后（§3.6 插入规则）。
8. **`cwmp_upload_transfer_complete`**（28 = 15+13）：会话 1 ACS 发 Upload（参数形状同 Download）→UploadResponse `>1<`→204（不关连接）→空 POST→204（收尾对）；会话 2 Inform 携带 `7 TRANSFER COMPLETE`+`M Upload`（事件 hex）→TransferComplete，CommandKey same_as→TransferCompleteResponse→空 POST→204（收尾对）。
9. **`cwmp_reboot_command_key`**（26 = 15+11）：会话 1 Reboot（CommandKey=`REBOOT-1`）→RebootResponse→204（不关连接）→空 POST→204（收尾对）；会话 2 Inform 携带 `1 BOOT`+`M Reboot` 且 CommandKey same_as 会话 1→空 POST→204（收尾对）。
10. **`cwmp_fault_soap`**（28 = 段 A 9 + 段 B 19，两段多会话展开）：**段 A（Inform 收非 8005 Fault→会话失败终止，9 = 3 握手 + 1 对×2 + 4 挥手；失败会话不走收尾对）**：新会话 Inform(2 PERIODIC)→ACS 200+SOAP Fault（`<faultcode>Server` hex `53 65 72 76 65 72`、faultstring=`CWMP fault` 精确 hex `43 57 4D 50 20 66 61 75 6C 74`、detail FaultCode=`8002`（非 8005）hex）→**无空 POST、无后续事务**，直接挥手；断言段 A 内 Inform 响应帧之后无 `http.request` 帧（会话失败终止，设计 §5 Faulted）。**段 B（8005 原样重发 + Fault 后会话继续，19 = 3 握手 + 5 对×2 + 4 挥手）**：5 对事务：① Inform POST→ACS 200+Fault 8005（Retry request，hex）；② Inform **原样重发**（`cwmp:ID` 与①同值 same_as、body 逐字节一致 frames hex）→ACS 200 InformResponse；③ 空 POST→ACS SetParameterValues（含非法参数值）；④ CPE Fault 帧→204（应答非空 POST，不关连接）：faultcode=`Client`（hex `43 6C 69 65 6E 74`）、faultstring=`CWMP fault` 精确 hex、主 FaultCode=`9003` hex、`SetParameterValuesFault` 逐参数 `ParameterName`/`FaultCode=9007` hex（**仅出现在响应 SetParameterValues 的 Fault，不得挂 GetParameterValues**，设计 §3.4）；⑤ 空 POST→204（收尾对）。断言：faultcode Client/Server 二值各一次、8002/8005/9003/9007 hex、重发 Inform ID same_as、Fault 后会话继续（④⑤ 存在、以收尾对正常收尾）。
11. **`cwmp_http_keepalive_multi_transaction`**（17 = 3 握手 + 5 对×2 + 4 挥手）：单 `tcp.stream` 承载 5 对请求/响应（Inform/InformResponse、空 POST/GetRPCMethods、GetRPCMethodsResponse/SetParameterValues、SetParameterValuesResponse/204（应答非空 POST，不关连接）、空 POST/204（收尾对））；断言对间无 `Connection: close`、请求/响应严格交替（无 pipelining）、每帧 Content-Length 与 `http.file_data` 长度自洽、GetRPCMethods 响应 `MethodList` 含 `GetRPCMethods`/`Inform` hex。
12. **`cwmp_ipv6`**（11）：源 IPv6 地址 `2001:db8::65`、**目的 IPv6 地址 `2001:db8::1`、`dst_port=7547`**（地址与端口分别显式声明，消除"`2001:db8::7547` 端口"歧义笔误）；断言 `ipv6.nxt=6`、payload offset 74、Inform envelope 字节与用例 1 一致（外层 IP 头除外）。
13. **`cwmp_multi_session`**（30 = 15+15）：会话 1（周期 Inform+GetParameterValues）与会话 2（BOOT Inform+SetParameterValues）不同源端口，每会话以空 POST/204 对收尾；断言两 `tcp.stream`、各自 ID 从 1001/2001 起独立递增（distinct）、Cookie 仅在本会话内回带（`http.cookie` 值 distinct）、第二会话握手包号 = 16。
14. **`cwmp_mss_large_soap`**（33 = 11 基线 + 22 额外分段，**默认 MSS 1460、不压 MSS**）：单会话，Inform envelope ≥32768 字节（其 ParameterList ≥32768 字节，覆盖设计 §3.5 "32 kilobytes" envelope 下限）；段数 = ceil(envelope 总长/1460) ≈ 23 段（旧稿"MSS 压 536 跨 3 段"自相矛盾——536×3=1608 容不下 3000B，已删除）。断言：`tcp.len` 每数据段 ≤1460、首段含 HTTP 头、`http.content_length` = envelope 实际字节长且 ≥32768（重组前即可从 Content-Length 头断言）、按 `tcp.stream` 重组后末段 envelope 完整（`</soap:Envelope>` 尾 hex `3C 2F 73 6F 61 70 3A 45 6E 76 65 6C 6F 70 65 3E`）、`ParameterList` 成员数与配置一致（`soap-enc:arrayType` 维度 hex）。

## 5. 负例契约

负例必须在 planner/validator 失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。锚词与设计 §7 表一一对应：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `cwmp_neg_config` | profile 与 namespace 不匹配（如 SOAP 1.2 envelope 命名空间）、层链缺 http（tcp→cwmp 直连）、端口/载体矛盾 | `profile`、`namespace`、`carrier` 或 `port` |
| `cwmp_neg_http_wire` | 方法非 POST、SOAPAction 带值、Content-Type 非 text/xml、Content-Length≠实体长、401 后 Authorization 缺失或摘要错仍继续 | `http`、`method`、`auth` 或 `content-type` |
| `cwmp_neg_xml_soap` | XML 截断、envelope 命名空间错、Body 缺失、响应缺 `Response` 后缀、faultstring≠`CWMP fault` 或 detail 缺 `cwmp:Fault` | `xml`、`soap`、`envelope` 或 `fault` |
| `cwmp_neg_session_state` | 首事务非 Inform、空 POST 后继续发请求、CPE 发送 ACS 方法、Fault 后继续同事务、Fault 响应 Fault、响应另一个响应、未终止会话即重启 | `session`、`state` 或 `sequence` |
| `cwmp_neg_correlation` | 响应 ID≠请求 ID、TransferComplete CommandKey 无来源、`flows[].driven_by` 引用不存在的事务/字段 | `id`、`command` 或 `correlation` |
| `cwmp_neg_length` | 参数名 >256、CommandKey >32、Event 数组 >64、事件码/FaultCode/FileType 非法值、实体超长截断 | `length`、`parameter` 或 `value` |

合法协议事件不进负例（防误报）：401 挑战本身、DownloadResponse/UploadResponse Status=1、Status=0 直接成功、空 ParameterList/空 ParameterKey、FileSize=0、CPE 已在会话回 503、8005 Retry request 重发、Fault 响应本身。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1、2、3、4、5、6、8、9、10、11（正）；15–20（负） | baseline RPC 全主干 + Fault（含 8005 重发与 Inform Fault 终止，用例 10 两段）+ 下载完成三途径（用例 6 三段）；五类错误各≥1 条负例；多流显式不适用（§3.4.6 禁 pipelining，设计 §4 声明） |
| 性能 | 14 | envelope ≥32768 字节跨 MSS 分段重组（默认 MSS 1460≈23 段）+ 32KB envelope 下限 `http.content_length` 断言 + 长度上界断言 |
| 数据场景 | 2、3、5、6、10；负 20 | 事件码 9 项子集 + `0 BOOTSTRAP` 正例、FileType 代表值 1/3、FaultCode 900x + faultcode Client/Server 二值、Status 0/1、ParameterKey 空/32 上界、FileSize=0、DelaySeconds 0/非 0、Event 满 64、OUI/dateTime/XML 转义/用户名百分号编码、上界越界拒绝 |
| 地址与流 | 1（v4 单流基线）、12（v6）、7（流关联副连接，插入位置断言）、13（多会话双四元组） | v4+v6 必覆盖；流关联主从由 `driven_by` 与包序断言（§3.6） |
| 业务 | 1（周期 Inform）、2（首次连接 BOOTSTRAP）、3（ACS 主动连接）、6（升级全流程三途径）、8（日志上报）、9（远程重启）、10（故障排查）、11（长会话批量管理）、13（多设备并行管理） | 现网典型场景优先；次要合法行为不适用清单见 §1 |

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
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1》三向对抗审查流程重写，取代 2026-08-20 旧契约稿（旧稿见 git 历史）。索引表改为需求五列格式（正/负 + 实现后证据）；按 tshark 3.6.14 实测固化"无 `cwmp.*` 字段、fields 只用 `http.*`/`tcp.*`/`ipv6.nxt`、SOAP 走 frames hex 前缀"的断言基线；新增 §3 has_payload 语义与多会话包号规则、§6 五层覆盖映射；20 个 ID 与新设计稿 §9 对齐（删 pcap_nic_consistency/multi_flow/https_tls_opaque，新增流关联/多事务/多会话展开/MSS/v6 独立用例）。三向对抗审查 2 轮：第 1 轮（用例审设计）补 connection_request 的 200 空体断言与 fault_soap 的"会话继续"断言；第 2 轮（设计审用例 + 规范回对）修正 multi_session 会话 2 握手包号为 14（13+1）、核对 faultstring `CWMP fault` 与 FaultCode 9003+9007 组合出处（TR-069 §3.5 示例），结论 clean。
- v2.1.0（2026-09-01）：依据《协议设计文档与用例文档需求文档 v1.1》（§3 独立子代理隔离对抗审查；64-cwmp 按 v1.0 完成后补本轮隔离审查），独立子代理隔离对抗审查 23 项问题清单（2 CRITICAL / 8 MAJOR / 13 MINOR）修复轮，CRITICAL/MAJOR 全部关闭、MINOR 关闭或显式声明。关键修复：**X01**（CRITICAL）`cwmp_fault_soap` 重构为两段：段 A（Inform 收非 8005 Fault 8002→会话失败终止，9 包）、段 B（Inform 收 8005→原样重发→SetParameterValues 触发 SetParameterValuesFault 9003+9007→会话继续，15 包 = 4 对事务）——SetParameterValuesFault 不再错挂在 GetParameterValues Fault 帧；**X02**（CRITICAL）`cwmp_mss_large_soap` 删除"MSS 压 536"矛盾配置，改默认 MSS 1460；**X03** §2 公式与 §3.6 新增副连接插入规则（DownloadResponse 之后、主会话空 POST 之前、主会话挥手最后），用例 7 改 24 包（主会话 200 空体保持会话）；**X04** envelope 拉到 ≥32768 字节并断言 `http.content_length`；**X05** 用例 6 改三段 fixture 全覆盖下载完成三途径（65 包）；**X06** 补 8005 原样重发正例（段 B ①②）与 Inform Fault 终止正例（段 A）；**X08/X14** 用例 2 改四次 fixture（0 BOOTSTRAP+1 BOOT / 4 VALUE CHANGE / 7+M Download / Event 满 64），36 包；**X09** 空 ParameterKey（用例 5）、FileSize=0 与 DelaySeconds 0/非 0（用例 6 三段）、Event 满 64（用例 2 fixture 4）、string(256/64/32) 上界（用例 4/2/5/6）逐项落断言；**X10** XML 转义/OUI 大写/dateTime 时区偏移（用例 2 fixture 1）、用户名百分号编码（用例 3）落断言；**X12** faultcode Client/Server 二值断言（用例 10 两段）；**X13** 用例 5 改 15 包（4 对，Status 0/1 各一笔）；**X15/X19** §5 负例输入与设计 §7 统一为并集（补"摘要错""Fault 后继续同事务""响应另一个响应"）；**X17** IPv6 目的地址明确 `2001:db8::1` + dst_port=7547；**X18/X20** §1 新增显式不适用声明（302/307、chunked、CR 忙 503、失败会话重试、文件服务器 basic/digest、X_ 厂商 RPC）；**X21** 索引表新增"设计 §"列，ID↔设计章节一对一引用，契约引用改 v1.1；**X22** digest 断言升级含 `qop="auth"`；**X11** FileType 断言代表值 1/3（用例 6 段 A/C）。**X23**（原子性拆分）case 4 已拆为两会话块（GetParameterNames/GetParameterValues 各一独立会话，26 包）；case 10 拆为两段（段 A Inform Fault 终止、段 B 8005 重发+SetParameterValuesFault）、用例 6 三段、用例 2 四次 fixture，均按段独立 packet_count 与断言。case 13 多维度合一拆不动：多会话展开是单一规格点（设计 §5），ID/cookie/DeviceId/状态不串用是同一行为的可观测断言面，且 20 个语义 ID 与设计 §9/本文 §2/§8 三方顺序契约为脚本核验的固定结构，拆分需新增 ID 破坏契约；按需求 §7"复合用例既是原子用例的顺次组合"处理并在此注明。
- v2.1.1（2026-09-01）：复验不通过修复轮（N01/N02/N03）。**N01**（CRITICAL）删除全部"200 空体（非 204）"提法（§2 公式、§3.6、§4.6 段 B、§4.7、§4.11 第 4 对），DownloadResponse/SetParameterValuesResponse/Fault 等非空 POST 的应答统一为 204——空 HTTP 响应必须 204（设计 §3.3 引 §3.4.6）；204 只有在应答空 POST 时才终止会话，应答非空 POST 的 204 会话继续（用例 11 中段 204 即为此模式）。Connection Request 的 200 空体保留（§3.2.2 CR 成功应答，非会话空响应范畴，设计 §4 场景③）。**N02**（MAJOR）统一会话收尾为"空 POST/204 对收尾"（设计 §5 教义），A 式（最后非空 POST 被 204 应答后直接挥手）全部改 B 式并全表重算 packet_count：用例 2 → 44（4 次 fixture × 11，每次补收尾对）、用例 4 → 30（两会话各 15）、用例 5 → 17（5 对）、用例 6 → 69（段 A 15、段 B 26、段 C 28=15+13）、用例 8 → 28、用例 9 → 26、用例 10 → 28（段 A 9 失败会话不走收尾对；段 B 19 补第 5 对——"不许两式混用"对 Fault POST→204 同样适用）、用例 13 → 30（第二会话握手包号 14→16）、用例 4 会话 2 握手包号 14→16；用例 7/11 包数不变（仅应答措辞改 204）；用例 1/3/12/14 收尾对已存在不变。**N03**（MINOR）v2.0.0 修订条目的需求文档引用改回 v1（该轮实际按 v1.0 完成提交），v1.1 引用仅保留于 v2.1.0 及本条目。
