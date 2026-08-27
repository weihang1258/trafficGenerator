# KERBEROS（Kerberos V5，网络认证协议）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/59-kerberos-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/kerberos.json`  
> 状态：`kerberos` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §3–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `kerberos_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

Kerberos V5 使用 UDP/TCP port（端口）88。UDP 保留 datagram（数据报）边界；TCP 每条 Kerberos message（消息）前必须有 4-byte big-endian（四字节网络序）长度，长度不包括自身。无 VLAN/IP options/IPv6 extension headers 时，IPv4/UDP 起点为 offset（偏移）42，IPv6/UDP 为 62，IPv4/TCP 为 54，IPv6/TCP 为 74。无解密 key（密钥）时，只断言外层载体、TCP framing（封装）、DER（可区分编码）顶层 tag/type、可见错误和 `EncryptedData`（加密数据）外壳；不得声称看见 ticket/session key/authenticator 内层。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier（载体）/DER 字段和稳定 raw frames（原始帧）；动态 nonce、ticket、session key、ctime/cusec、cipher bytes 使用 `presence`、`nonzero`、`distinct_values`、`same_as_packet`，不能猜测运行期随机常量。负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `kerberos_ipv4_udp_as_basic` | 正 | IPv4/UDP 88、V5 AS 基本交换 | 4 |
| 2 | `kerberos_ipv6_udp_as_basic` | 正 | IPv6/UDP 88 独立 AS fixture | 4 |
| 3 | `kerberos_tcp_record_framing` | 正 | TCP/88、4-byte length、合并/切分消息 | 8 |
| 4 | `kerberos_as_req_as_rep` | 正 | AS-REQ/AS-REP、nonce/realm/principal 外壳 | 4 |
| 5 | `kerberos_tgs_req_tgs_rep` | 正 | TGS-REQ/TGS-REP、krbtgt 与 service ticket 边界 | 6 |
| 6 | `kerberos_ap_req_ap_rep` | 正 | AP-REQ/AP-REP、ticket/authenticator opaque | 6 |
| 7 | `kerberos_krb_error_preauth_required` | 正 | KRB-ERROR PREAUTH_REQUIRED 与错误数据 | 4 |
| 8 | `kerberos_preauth_rfc6113` | 正 | RFC 6113 METHOD-DATA/PA-ENC-TIMESTAMP 边界 | 6 |
| 9 | `kerberos_ticket_principal_realm` | 正 | Ticket、realm、principal 组件与关联 | 6 |
| 10 | `kerberos_encrypteddata_opaque` | 正 | EncryptedData etype/长度可见、内层不可声称 | 6 |
| 11 | `kerberos_nonce_time_skew` | 正 | nonce 关联、时间窗口、合法 skew 边界 | 6 |
| 12 | `kerberos_replay_retransmission` | 正 | 请求重传去重、replay 检测和 timeout | 8 |
| 13 | `kerberos_multi_session_flow` | 正 | IPv4/IPv6、多会话/多流和 UDP↔TCP 隔离 | 12 |
| 14 | `kerberos_pcap_nic_consistency` | 正 | PCAP/NIC 方向、端口、record/DER 外壳一致 | 8 |
| 15 | `kerberos_neg_truncated_record` | 负 | UDP/TCP/DER 截断 | — |
| 16 | `kerberos_neg_tcp_length` | 负 | TCP length prefix 错误/溢出/串流 | — |
| 17 | `kerberos_neg_message_tag` | 负 | 版本、tag、msg-type、DER 非法 | — |
| 18 | `kerberos_neg_encrypted_boundary` | 负 | EncryptedData 边界或伪造内层 | — |
| 19 | `kerberos_neg_time_nonce_replay` | 负 | skew、nonce、replay 或重传状态错误 | — |
| 20 | `kerberos_neg_udp_carrier` | 负 | 传输协议/端口/checksum/载荷错误 | — |

## 3. 正例逐项断言契约

1. **`kerberos_ipv4_udp_as_basic`**：一条 IPv4/UDP/88 session，断言 `ip.proto=17`、record 起点 42、V5 顶层 AS-REQ/AS-REP tag（常见 `0x6a`/`0x6b`）、双向方向和 `packet_count=4`；nonce、ticket 和 enc-part 动态或 opaque。
2. **`kerberos_ipv6_udp_as_basic`**：outer `ipv6.nxt=17`、UDP/88，起点 62，V5 AS tag 与 IPv4 fixture 独立；IPv6 UDP checksum 非零且正确，`packet_count=4`。
3. **`kerberos_tcp_record_framing`**：建立 TCP/88，断言 TCP handshake，至少两条 Kerberos message 各有 4-byte big-endian length；一条长度前缀跨 TCP segments，或多个 messages 合并于一个 segment，按 length 重组，`packet_count=8`。
4. **`kerberos_as_req_as_rep`**：client→AS 的 AS-REQ 与 server→client 的 AS-REP 顶层 tag、pvno=5/msg-type、自洽 DER 长度和 realm/principal 明文外壳；nonce 用 presence/same-as 关联，`packet_count=4`。
5. **`kerberos_tgs_req_tgs_rep`**：TGS-REQ/TGS-REP 方向与顶层 tag，krbtgt 服务主体、目标 service principal 和两个 ticket 的 EncryptedData 外壳；不把加密 EncKDCRepPart 当明文，`packet_count=6`。
6. **`kerberos_ap_req_ap_rep`**：AP-REQ/AP-REP（mutual authentication fixture）方向、tag、ticket/authenticator etype/长度和 session 关联；cipher 与 authenticator 内层 opaque，`packet_count=6`。
7. **`kerberos_krb_error_preauth_required`**：AS-REQ 后收到 `[APPLICATION 30]` KRB-ERROR，断言错误码 `KDC_ERR_PREAUTH_REQUIRED`、e-data/METHOD-DATA 长度和后续重试关系；不可把 error ticket 当 AS-REP，`packet_count=4`。
8. **`kerberos_preauth_rfc6113`**：第二个 AS-REQ 携带 RFC 6113 PA-DATA，断言 padata-type、method-data 顺序、PA-ENC-TIMESTAMP EncryptedData etype/长度和 request nonce 关联；timestamp/cipher 明文不可见，`packet_count=6`。
9. **`kerberos_ticket_principal_realm`**：断言 Ticket `tkt-vno=5`、realm、sname name-type/name-string 组件和 client/service principal 独立；各 DER 长度精确，运行期 ticket 内容用 presence/nonzero，`packet_count=6`。
10. **`kerberos_encrypteddata_opaque`**：至少两种 etype/长度的 EncryptedData 外壳，断言 cipher 长度与 DER 边界、密文非零/动态且不同；不得写解密后的 flags、session key、authorization-data 或 authenticator 字段，`packet_count=6`。
11. **`kerberos_nonce_time_skew`**：合法 clock skew 窗口内 AS/TGS 请求-回复 nonce same-as；断言 ctime/cusec/till 仅 presence/范围，不能硬编码运行期时钟，`packet_count=6`。
12. **`kerberos_replay_retransmission`**：UDP 请求的合法重传复用相同 request bytes/nonce，不推进状态两次；重复 AP-REQ 触发 replay 错误或拒绝，timeout 最终可见且不是 completed/0 packet，`packet_count=8`。
13. **`kerberos_multi_session_flow`**：至少两个独立 session，覆盖 IPv4/IPv6 和 UDP/TCP 88；每 flow 的 nonce、realm/principal、ticket association、TCP record buffer/replay state 独立，`packet_count=12`，不假设全局顺序。
14. **`kerberos_pcap_nic_consistency`**：同一 fixture 输出 PCAP 并在指定 NIC 捕获；两方向 UDP/TCP/88、顶层 tag、TCP length prefix（若适用）和 packet count 一致。过滤器为 `udp port 88 or tcp port 88`，记录 checksum offload 和无解密边界，`packet_count=8`。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、completed/0 packet 或只剩 UDP/TCP 外壳的假成功。`expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `kerberos_neg_truncated_record` | UDP/TCP message、DER header 或字段截断 | `record`、`length` 或 `truncated` |
| `kerberos_neg_tcp_length` | TCP 4-byte length 与消息不符、溢出或跨连接拼接 | `tcp`、`length` 或 `framing` |
| `kerberos_neg_message_tag` | 非 V5、顶层 tag/msg-type 不匹配或非法 DER | `tag`、`version` 或 `message` |
| `kerberos_neg_encrypted_boundary` | EncryptedData 外壳/etype/cipher 长度截断或伪造内层 | `encrypted`、`cipher` 或 `boundary` |
| `kerberos_neg_time_nonce_replay` | nonce 关联错误、skew 超窗、重复 authenticator/replay | `time`、`nonce` 或 `replay` |
| `kerberos_neg_udp_carrier` | 非 UDP/TCP 88、错误 checksum、错误 IP family 或载荷边界 | `transport`、`port`、`udp` 或 `checksum` |

合法的 UDP/TCP、TCP segment 重组、KRB-ERROR、RFC 6113 pre-auth、动态 ticket/nonce、opaque cipher、合法重传和 IPv4/IPv6 由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §11、本文 §2、注册后的 JSON 和审计必须保持同一 20 个唯一语义 ID、同一顺序：14 个正例 + 6 个负例；当前 JSON 另有一个不计数的 `kerberos_neg_unregistered`。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、方向和稳定 carrier/DER 字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. 固定 offsets 为 IPv4/UDP Kerberos=42、IPv6/UDP=62、IPv4/TCP=54、IPv6/TCP=74；TCP record prefix 永远 4 bytes，长度不含 prefix。
4. DER raw frames 只固定 V5、顶层 tag/msg-type、TCP length prefix、错误码和稳定 realm/principal fixture；动态 nonce、ticket、session key、cipher 和时间使用 nonzero/distinct/same-as，禁止猜测常量。
5. `EncryptedData`/Ticket/Authenticator 内层不得在无 key evidence 时断言；`tshark` 的自动解析不能替代解密证据。
6. Kerberos 必须使用 UDP/TCP 88，不测试其他载体；IPv4 UDP checksum 可零或正确非零，IPv6 UDP checksum 必须非零且正确。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/kerberos.json` 应成功；当前数组只能含 `kerberos_neg_unregistered`，且 `proto=kerberos`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `kerberos` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、TCP record prefix/DER tag offsets 和 tshark 字段注册，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 `kerberos.*` 字段，使用稳定 raw frames 与通用 `udp`/`tcp`/`ip`/`ipv6` 字段，不自创字段名。当前阶段不得将唯一 placeholder 运行结果报告为 Kerberos suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Kerberos V5 正例和 6 个严格负例，覆盖 RFC 4120、RFC 6113 pre-auth、UDP/TCP 88、TCP record length、AS/TGS/AP、KRB-ERROR、ticket/principal/realm、EncryptedData opaque、nonce/time skew/replay、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
