# DTLS（数据报传输层安全，Datagram Transport Layer Security）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/58-dtls-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/dtls.json`
> 状态：`dtls` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §3–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `dtls_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

DTLS 是 UDP/4433 数据报协议。无 VLAN、IP options、IPv6 extension headers 时，IPv4/UDP record 起点为 offset（偏移）42，IPv6/UDP 为 62；每条 DTLS record 固定 13-byte header。加密 epoch 后 PCAP/NIC 只可断言 content type、版本、epoch、48-bit sequence、Length 和密文长度，不可声称看见明文 handshake、cookie、alert 或 application data。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier/record 字段和稳定 raw frames（原始帧）；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。动态端口、cookie、sequence 或加密字节使用 `nonzero`、`distinct_values`、`same_as_packet`，不能猜测运行期随机常量。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `dtls_ipv4_v12_basic` | 正 | IPv4/UDP 4433、DTLS 1.2 基本握手记录 | 12 |
| 2 | `dtls_ipv6_v12_basic` | 正 | IPv6/UDP 4433、DTLS 1.2 独立 fixture | 12 |
| 3 | `dtls_v10_legacy_record` | 正 | DTLS 1.0 `fe ff` record/version 边界 | 8 |
| 4 | `dtls_v12_cookie_exchange` | 正 | ClientHello、HelloVerifyRequest、带 cookie 的 ClientHello | 16 |
| 5 | `dtls_handshake_fragmentation` | 正 | 单握手消息跨 records 的 fragment header | 10 |
| 6 | `dtls_handshake_reassembly` | 正 | 分片乱序重组、message_seq/offset 完整性 | 10 |
| 7 | `dtls_epoch_sequence_transition` | 正 | epoch 0→1、每方向 48-bit sequence 独立递增 | 14 |
| 8 | `dtls_ccs_alert_application` | 正 | CCS、alert、application data 外层类型与关闭 | 16 |
| 9 | `dtls_retransmission_timeout` | 正 | flight 重传、超时、异常关闭/最终错误 | 18 |
| 10 | `dtls_multi_session_isolation` | 正 | 两个独立 session 的 cookie/epoch/sequence/关闭 | 24 |
| 11 | `dtls_multi_flow` | 正 | 多四元组、多方向流和不串用状态 | 12 |
| 12 | `dtls_record_boundary_lengths` | 正 | 空 record、最大附近 Length、UDP datagram 边界 | 6 |
| 13 | `dtls_pcap_nic_consistency` | 正 | PCAP/NIC 方向、4433、record header 一致 | 16 |
| 14 | `dtls_encrypted_opaque_boundary` | 正 | 加密后的外层字段可见、内层明文不可声称可见 | 10 |
| 15 | `dtls_neg_record_truncated` | 负 | record header/Length 截断 | — |
| 16 | `dtls_neg_version_epoch` | 负 | version/content type/epoch 非法 | — |
| 17 | `dtls_neg_sequence_overflow` | 负 | 48-bit sequence 溢出、回绕或重复 | — |
| 18 | `dtls_neg_fragment_bounds` | 负 | handshake 分片边界/重叠/拼接错误 | — |
| 19 | `dtls_neg_cookie_state` | 负 | cookie 状态、重传状态或握手顺序错误 | — |
| 20 | `dtls_neg_udp_carrier` | 负 | UDP/4433 载体、checksum 或 datagram 边界错误 | — |

## 3. 正例逐项断言契约

1. **`dtls_ipv4_v12_basic`**：一条 IPv4/UDP/4433 session，断言 `ip.proto=17`、record offset 42、版本 `fe fd`、type 22/20/23 的合法顺序、epoch 初始为 0，`packet_count=12`；不得断言加密后的握手 body。
2. **`dtls_ipv6_v12_basic`**：outer `ipv6.nxt=17`、UDP/4433，record offset 62，版本 `fe fd`、IPv6 地址与 IPv4 fixture 独立，`packet_count=12`；IPv6 UDP checksum 非零且正确。
3. **`dtls_v10_legacy_record`**：DTLS 1.0 record 版本 raw `fe ff`，type 22、13-byte header、epoch/sequence 合法，`packet_count=8`；不得套用 TLS `03 xx` 版本。
4. **`dtls_v12_cookie_exchange`**：至少观察 ClientHello（无 cookie）→ HelloVerifyRequest（type 22）→第二个 ClientHello（cookie length 与实际 bytes 相等）→继续握手，`packet_count=16`；cookie 用 presence/length/same-as 断言，不猜测值。
5. **`dtls_handshake_fragmentation`**：一个 handshake message 的 12-byte header 中完整 length、message_seq、fragment_offset/fragment_length；至少两条 type 22 records 携带不同片段，`packet_count=10`，不把 fragment length 当完整 message length。
6. **`dtls_handshake_reassembly`**：乱序片段按 message_seq/offset 重组后只推进一次状态；raw header 的 24-bit length/offset/fragment length 网络序正确，`packet_count=10`；不假设 datagram 全局顺序。
7. **`dtls_epoch_sequence_transition`**：每方向至少有 epoch 0 sequence 0、epoch 1 sequence 0/递增；断言 sequence 为 6-byte big-endian、epoch 不回退且双向独立；每个发送的 record 都递增，重传复用握手消息的 `message_seq` 但 record sequence 不复用，`packet_count=14`。
8. **`dtls_ccs_alert_application`**：明文 CCS type 20 后进入加密 epoch；外层随后出现 type 23 application data 和 type 21 alert/关闭，`packet_count=16`。加密 alert 只断言 type/epoch/Length，不断言 level/description。
9. **`dtls_retransmission_timeout`**：丢失或未确认 flight 时重复相同 message_seq/fragment 语义并增加可观察重传；超过 retry limit 后报告 timeout/error 或 alert close，`packet_count=18`；不得 completed/0 packet。
10. **`dtls_multi_session_isolation`**：两条独立 UDP session 各自完成 cookie/epoch/sequence/关闭，至少 24 packets；cookie、重传 flight、sequence 不跨 session 串用，使用 distinct/same-as 动态断言。
11. **`dtls_multi_flow`**：多四元组和双向流，至少 12 packets；每 flow 的 UDP port、session state、epoch/sequence 关联一致，跨 flow 不拼 handshake 片段，不假设全局顺序。
12. **`dtls_record_boundary_lengths`**：至少一条 Length=0 record 和一条最大支持值附近 record；断言 UDP datagram 与 13-byte header/Length 边界一致，`packet_count=6`，显式零不可被默认值替换。
13. **`dtls_pcap_nic_consistency`**：同一 fixture 输出 PCAP 并在指定 NIC capture；两条方向明确的 UDP/4433 records 的 version/type/epoch/Length 和稳定前缀一致，`packet_count=16`；过滤器为 `udp port 4433`，记录 checksum offload。
14. **`dtls_encrypted_opaque_boundary`**：加密 epoch records 仅断言 type/version/epoch/6-byte sequence/Length 和密文长度，`packet_count=10`；不能写 `dtls.handshake.type` 或明文 alert/application payload 的断言，除非提供 key log 解密证据。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、completed/0 packet 或只剩 UDP 外壳的假成功。`expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `dtls_neg_record_truncated` | record header 少于 13 bytes 或 Length 超出 UDP datagram | `record` 或 `length` |
| `dtls_neg_version_epoch` | 未知版本/content type、epoch 倒退或跨 session 复用 | `version`、`epoch` 或 `type` |
| `dtls_neg_sequence_overflow` | sequence 超过 48-bit、同 epoch 回绕或重复（含重传复制 sequence） | `sequence` 或 `overflow` |
| `dtls_neg_fragment_bounds` | handshake length/offset/fragment length 越界、重叠或错误拼接 | `fragment` 或 `handshake` |
| `dtls_neg_cookie_state` | cookie 缺失/长度不符、未验证即继续或重传推进状态 | `cookie` 或 `state` |
| `dtls_neg_udp_carrier` | TCP/裸 IP/错误 UDP port、checksum 或 datagram 边界错误 | `transport`、`udp` 或 `checksum` |

合法的空 record、epoch=0/1、DTLS 1.0 `fe ff`、IPv4 zero checksum、IPv6 non-zero checksum、cookie 重传、乱序 fragment、加密 opaque payload 和异常 timeout 由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §11、本文 §2、注册后的 JSON 和审计必须保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例，当前 JSON 另有一个 `dtls_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、方向和稳定 carrier/record 字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. 固定 offsets 为 IPv4/UDP DTLS=42、IPv6/UDP=62；record header 永远 13 bytes；Length 只覆盖 fragment。
4. Record raw frame 只固定可复核的 content type、`fe ff`/`fe fd`、epoch/sequence 宽度和稳定长度；cookie、端口、密文和运行期序列使用动态断言。
5. Handshake 12-byte header 的 length/offset/fragment length 均为 24-bit 网络序；重组按 message_seq/offset，不按 UDP/TCP stream（TCP 字节流）规则。
6. 加密 epoch 后不得声称看见明文握手、cookie、alert level/description 或 application payload；只有明文 fixture/key log 解密证据才可扩大断言。
7. DTLS 使用 UDP/4433，不测试 TCP handshake/MSS/FIN；IPv4 checksum 可零或正确非零，IPv6 checksum 必须非零且正确。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/dtls.json` 应成功；当前数组只能含 `dtls_neg_unregistered`，且 `proto=dtls`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `dtls` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、record offsets、epoch/sequence/fragment 字段和 tshark 字段注册，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 `dtls.*` 字段，使用稳定 raw frames 与通用 `udp`/`ip`/`ipv6` 字段，不自创解析字段。当前阶段不得将唯一 placeholder 运行结果报告为 DTLS suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 DTLS 1.0/1.2 正例和 6 个严格负例，覆盖 RFC 4347/6347 记录层、epoch/48-bit sequence、握手分片重组、cookie、重传/超时、CCS/alert/application data、加密边界、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
