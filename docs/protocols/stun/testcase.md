# STUN（NAT 穿越会话工具，Session Traversal Utilities for NAT）测试契约

> 版本：v1.1.0（2026-09-30）；T1–T6/C1–C6 层链迁移审计。
> 当前状态：`stun` layer 未注册；cases 是目标机器契约，suite 不可运行，不宣称通过。

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/44-stun-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/stun.json`
> 审查：`docs/protocol-designs/audit/44-stun-adversarial-audit.md`
> 状态：`stun` 层尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和 tshark 字段证据

本套件从设计 §2–§10 逐项派生，共 24 个唯一 ID，15 个正例、9 个负例；ID 顺序与设计 §9、JSON、audit（对抗审查）完全一致。生成四件套前执行了：

```text
tshark -G fields | grep -E '\tstun\.'
```

正例只使用已注册的 STUN 字段：`stun.type`、`stun.type.class`、`stun.type.method`、`stun.length`、`stun.cookie`、`stun.id`、`stun.tcp_frame_length`、`stun.att.type`、`stun.att.length`、`stun.att.family`、`stun.att.ipv4`、`stun.att.ipv6`、`stun.att.port`、`stun.att.username`、`stun.att.hmac`、`stun.att.error.class`、`stun.att.error`、`stun.att.error.reason`、`stun.att.realm`、`stun.att.nonce`、`stun.att.unknown`、`stun.att.ipv4-xord`、`stun.att.ipv6-xord`、`stun.att.port-xord`、`stun.att.crc32`，以及载体的 `udp.*`、`tcp.*`、`ipv6.nxt`、`tls.record.*`。不使用 `classicstun.*` 旧解析器字段。

每个正例均有 `packet_count`、`fields`、`frames`；`frames` 只固定可复核的 header/type/length/cookie、attribute type/length/family 等字节，不固定运行期 transaction ID、HMAC-SHA1、CRC-32、XOR 地址/端口、服务端 nonce 或映射地址。动态值使用 `nonzero=true` 或 `same_as_packet` 观察存在性/事务关联。负例的 `expect` 严格只有 `expect_error` 和 `error_contains`，不包含 packet count、fields、frames、has_payload 或错误 PCAP 断言。

无 VLAN、无 IP options 时，明文 STUN 起点为 UDP/IPv4 offset 42、UDP/IPv6 offset 62、TCP/IPv4 offset 54。TLS 未解密时只断言 TLS record，不对加密应用数据假定 STUN 字节。

## T1–T6 层链迁移审计

| 门 | 契约 | 证据/结论 |
|---|---|---|
| T1 | 24 个 ID 唯一且顺序稳定 | `stun.json` 机读校验；24/24 |
| T2 | 每条 `spec_json` 顶层仅 `layers` | 24/24；旧顶层地址、端口和协议映射已移除 |
| T3 | 地址只在 `ip` 层、端口只在 `udp`/`tcp` 层 | 24/24；IPv6 例保留其 `ip` 层 |
| T4 | STUN 业务字段只在 `stun` 层 | 24/24；负例 `wire_fault` 亦在 STUN 层 |
| T5 | 负例 expect 严格为 `expect_error` + `error_contains` | 9/9 |
| T6 | 未注册边界明确 | 当前不运行 suite；注册后按同一 JSON 经 MCP/pcap/NIC 校准 |

## C1–C6 覆盖与输出契约

| 项 | 结论 |
|---|---|
| C1 机器一致性 | design §9、本文 §2、JSON 24 个 ID 顺序一致；正 15、负 9 |
| C2 五层覆盖 | 功能、性能、数据、IPv4/IPv6、业务（重传/多事务）均有基线或待实现边界 |
| C3 负路径 | 9 个负例分别钉 header/type/length/cookie/attribute/integrity/transport/turn 锚词 |
| C4 动态与边界 | transaction ID、HMAC、CRC、XOR 值按 nonzero/same_as_packet；padding、长度、默认/非默认载体已列 |
| C5 pcap/NIC | 同一 `stun.json`、fields、frames 契约适用于 PCAP 与 port_group/NIC；NIC 需 tcpdump 捕获，偏移按实际 pcap 校准 |
| C6 实现边界 | 未注册 layer、planner、TLS 解密和错误传播均为待实现，不计入当前通过数 |



| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `stun_binding_udp_request` | 正 | UDP/IPv4 request、20-byte header、type/class/method/length/cookie | 1 |
| 2 | `stun_binding_udp_success_ipv4` | 正 | success、IPv4 XOR/MAPPED、response transaction ID | 2 |
| 3 | `stun_binding_udp_success_ipv6` | 正 | UDP/IPv6、IPv6 XOR-MAPPED-ADDRESS | 2 |
| 4 | `stun_binding_udp_error` | 正 | error、ERROR-CODE（401 Unauthorized；420/UNKNOWN-ATTRIBUTES 另行区分） | 2 |
| 5 | `stun_binding_tcp_request` | 正 | TCP carrier 和 STUN TCP framing | 8 |
| 6 | `stun_binding_tls_session` | 正 | TLS/TCP carrier；加密时不伪造 STUN fields | 15 |
| 7 | `stun_auth_attributes` | 正 | USERNAME、REALM、NONCE | 1 |
| 8 | `stun_integrity_fingerprint` | 正 | MESSAGE-INTEGRITY、FINGERPRINT 运行期计算 | 1 |
| 9 | `stun_attribute_padding` | 正 | Attribute Length 与 32-bit padding | 1 |
| 10 | `stun_retransmission` | 正 | 同 transaction 的 UDP 重传和 ID 相等 | 3 |
| 11 | `stun_multi_transaction_udp` | 正 | UDP 多 transaction/session | 4 |
| 12 | `stun_multi_transaction_tcp` | 正 | TCP 单 session 多 transaction | 11 |
| 13 | `stun_ipv6_address_attributes` | 正 | IPv6 outer、IPv4/IPv6 address attributes | 2 |
| 14 | `stun_rfc8489_profile` | 正 | RFC 8489 Binding profile | 1 |
| 15 | `stun_binding_mapped_both` | 正 | MAPPED 与 XOR-MAPPED 对照 | 2 |
| 16 | `stun_neg_header_short` | 负 | header 小于 20 bytes | — |
| 17 | `stun_neg_type_reserved_bits` | 负 | type 保留/低位错误 | — |
| 18 | `stun_neg_length_alignment` | 负 | Message Length 非 4 的倍数 | — |
| 19 | `stun_neg_length_overrun` | 负 | Message Length 超出 payload | — |
| 20 | `stun_neg_bad_cookie` | 负 | Magic Cookie 错误 | — |
| 21 | `stun_neg_attribute_length` | 负 | Attribute 长度/padding 越界 | — |
| 22 | `stun_neg_bad_integrity` | 负 | MESSAGE-INTEGRITY 校验失败 | — |
| 23 | `stun_neg_transport_mismatch` | 负 | UDP/TCP/TLS carrier 与 framing 不一致 | — |
| 24 | `stun_neg_turn_boundary` | 负 | RFC 5766/5780 扩展误入 Binding profile | — |

## 3. 正例逐项断言契约

1. `stun_binding_udp_request`：packet 1 的 `stun.type=0x0001`、class=0、method=1、length=0；offset 42 有 `00 01 00 00 21 12 a4 42`。transaction ID 只要求非零。
2. `stun_binding_udp_success_ipv4`：request/success 为 2 个 UDP datagram；success `type=0x0101`、class=0x0010、method=1，属性 type 0x0020、family=0x01，XOR address/port 非零；response ID `same_as_packet:1`。
3. `stun_binding_udp_success_ipv6`：IPv6 Next Header=17，success 的 XOR family=0x02、IPv6 XOR value 和 XOR port 非零；STUN 起点 62，header length=0x20 与 IPv6 address attribute 长度可复算。
4. `stun_binding_udp_error`：error `type=0x0111`、class=0x0011、method=1；ERROR-CODE class=4/code=1/reason=Unauthorized；UNKNOWN-ATTRIBUTES type=0x000a、value 0x8022；ID 与 request 相等。
5. `stun_binding_tcp_request`：完整 TCP handshake/termination 的约定 packet_count=8；第 4 包为 STUN request，观察 `stun.tcp_frame_length`、type、length、cookie、ID，offset 54 开始。TCP segment 边界不能替代 STUN framing。
6. `stun_binding_tls_session`：完整 TLS/TCP session 的当前目标 packet_count=15（不是 16）；只观察 TCP dstport=5349、TLS handshake record type=22 和 application-data record type=23/record length；无解密密钥时不观察 `stun.*`。注册实现后以真实 pcap 校准。
7. `stun_auth_attributes`：同一 request 中观察 USERNAME=alice、REALM=example.org、NONCE=server-nonce 以及非零 Message Length；nonce 不代表固定服务端实现值，只是此显式 fixture 的输入。
8. `stun_integrity_fingerprint`：属性 type 0x0008 的 20-byte HMAC-SHA1 非零，type 0x8028 的 CRC-32 非零；不把动态 HMAC/CRC 写入 `frames.hex`。实现单测必须另行复算 HMAC 的 Message Length 截止点及 fingerprint 的 CRC 截止点。
9. `stun_attribute_padding`：USERNAME bob 的 Attribute Length=3，Message Length=8，offset 62 观察 `00 06 00 03 62 6f 62 00`；最后 00 是 4-byte padding，不计入 Attribute Length。
10. `stun_retransmission`：3 个 datagram 依次 request、同语义 request retransmit、success；前两个 ID 相等，success ID 与首 request 相等；frames 只固定每个 header 的稳定部分，禁止固定动态 ID/HMAC。
11. `stun_multi_transaction_udp`：4 个 datagram 形成两条隔离 transaction；packet 3 success 关联 packet 1，packet 4 error 关联 packet 2；两个 request ID 都要求非零且不得由测试固定常量。
12. `stun_multi_transaction_tcp`：一个 TCP session 中两条顺序 transaction；观察第 4/6/8/10 个应用包的 type 和 ID 关联，同时保留 handshake/termination 断言。TCP packet index 只是 fixture 的包序，不是事务匹配依据。
13. `stun_ipv6_address_attributes`：IPv6 outer UDP Next Header=17；同一 success 观察 MAPPED family=1/IPv4 和 XOR-MAPPED family=2/IPv6，分别使用已注册字段；不把 outer IPv6 强行映射成 IPv4。
14. `stun_rfc8489_profile`：RFC 8489 profile 仍使用 Binding type/class/method、cookie 和注册的 USERNAME；不伪造未定义的 USERHASH/PASSWORD-ALGORITHM/MESSAGE-INTEGRITY-SHA256 字段。
15. `stun_binding_mapped_both`：success 同时带 MAPPED-ADDRESS type 0x0001 与 XOR-MAPPED-ADDRESS type 0x0020，观察两套 family/address/port 字段存在；XOR 结果由实现按 cookie/transaction ID 计算，不在 frame 中写动态结果。

## 4. 负例契约

以下每个 JSON 的 `wire_fault.kind` 都是设计阶段的显式失败注入口；它不是合法线上字段，也不能由实现忽略。每个错误只能以 task error（任务错误）终止：

| ID | 故障 | `expect` 唯一允许的结构 |
|---|---|---|
| `stun_neg_header_short` | header 小于 20 bytes | `expect_error=true`, `error_contains=header` |
| `stun_neg_type_reserved_bits` | type 保留位/低两位非零 | `expect_error=true`, `error_contains=type` |
| `stun_neg_length_alignment` | Message Length 非 4 对齐 | `expect_error=true`, `error_contains=length` |
| `stun_neg_length_overrun` | Message Length 超出 payload | `expect_error=true`, `error_contains=length` |
| `stun_neg_bad_cookie` | cookie 非 0x2112A442 | `expect_error=true`, `error_contains=cookie` |
| `stun_neg_attribute_length` | attribute value/padding 越界 | `expect_error=true`, `error_contains=attribute` |
| `stun_neg_bad_integrity` | HMAC 输入边界或值不符 | `expect_error=true`, `error_contains=integrity` |
| `stun_neg_transport_mismatch` | carrier 与 STUN framing 不匹配 | `expect_error=true`, `error_contains=transport` |
| `stun_neg_turn_boundary` | TURN Allocate/5780 扩展进入 Binding-only profile | `expect_error=true`, `error_contains=turn` |

负例不允许 `packet_count=0`、空 PCAP、fields 或 frames 作为“失败”替代。合法的 401/420 STUN error 是正例语义；非法配置/线格式负例则必须让任务错误，二者分层。

## 5. 三方一致性和静态检查

1. design §9、本文 §2、JSON 数组和 audit §4 均为同一 24 个 ID、同一顺序；正例 15、负例 9。
2. 正例 packet_count 序列为 `[1,2,2,2,8,15,1,1,1,3,4,11,2,1,2]`；负例均无 packet_count。
3. 14 个明文正例均有 `packet_count`、`fields`、`frames`；TLS 加密正例只断言 `packet_count`、`fields` 和载体状态；9 个负例的 `expect` 键集合恰为 `{'expect_error','error_contains'}`。
4. 所有 STUN 明文 frame offset 与外层头长度一致：IPv4/UDP=42、IPv6/UDP=62、IPv4/TCP=54；TLS 只断言 record 起点 54。
5. header 每例固定 cookie bytes 只在不含动态值的 frames 中观察；transaction ID 使用 nonzero/same_as_packet；HMAC、CRC、XOR 结果不固化。
6. 正例字段均来自 tshark -G fields 输出；不使用 classicstun 字段，不用自创字段名。
7. MESSAGE-INTEGRITY、FINGERPRINT 的 JSON 只证明属性类型和值出现；RFC 级字节复算属于实现单测完成定义，不能被 PCAP 的 nonzero 断言冒充。
8. RFC 5766 TURN 与 RFC 5780 NAT behavior discovery 独立边界，未将 TURN attributes 当作 Binding 正例。

## 7. D/T/C 三方对账

| 维度 | testcase | design | cases JSON |
|---|---|---|---|
| ID/顺序 | §2：24 个 ID，同一顺序 | §9：15 正 + 9 负 | 24 例，同一顺序 |
| 配置形状 | §1/T1–T4：顶层仅 `layers`，业务键在 `layers[].stun` | §2/D2：`ip`、`udp`/`tcp`、`tls`、`stun` 各守边界 | 24/24 无旧顶层 `stun`，层序正确 |
| 正例 | §2–§3：15 例有包数、fields/frames（TLS 仅载体字段） | §9–§10：同一场景与断言 | 15 例含 `packet_count`，真实锚词/偏移已写入 |
| 负例 | §4/T5：只允许 `expect_error` + `error_contains` | §10：同一错误契约 | 9 例恰为双键，锚词覆盖 header/type/length/cookie/attribute/integrity/transport/turn |
| 缺口 | §6/C6：未注册/未翻译时不运行、不宣称通过 | §12、G-STUN-1…5 | 静态目标契约，不伪造 suite 结果 |

registry 当前只有空 `stun` 层声明，`translateTerminalConfig` 没有 STUN 分支；这是 G-STUN-1 的登记，不机械迁移为“已实现”。

## 8. 复核记录

自审两轮，末轮干净：第一轮核对 24 个 ID、正负分类、层归属和 registry/translate 缺口；第二轮逐例对照 JSON 的 `packet_count`、fields/frames、offset、动态值约束及负例双键和真实 `error_contains` 锚词。
