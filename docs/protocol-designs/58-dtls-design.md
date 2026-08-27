# DTLS（数据报传输层安全，Datagram Transport Layer Security）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`dtls` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/58-dtls-testcase.md`、`trafficgen/test/protocol_pcap/cases/dtls.json`
> 规范基线：RFC 6347（DTLS 1.2）、RFC 4347（DTLS 1.0）、RFC 8446 §4.1/§5（TLS 1.3 记录/握手语义，仅作为边界参考）、RFC 768（UDP）。

## 1. 范围、证据等级和未注册边界

本版定义 DTLS over UDP（基于 UDP 的 DTLS）数据面：DTLS 1.0/1.2 记录层、epoch（密钥代际）、48-bit sequence number（序列号）、握手消息分片与重组、HelloVerifyRequest cookie（Cookie 验证）、flight retransmission（飞行重传）、ChangeCipherSpec、alert、application data，以及 IPv4/IPv6、多会话和多流隔离。

DTLS 的记录头在加密前可直接观察；进入加密 epoch 后，PCAP/NIC（网卡）只能观察 content type、版本、epoch、序列号和密文长度，不能把随机密文字节解释为明文握手字段、alert level 或应用数据内容。只有显式提供的解密 fixture（固定样本）/实现单测才可断言加密内层；不得以“tshark（抓包解析器）解析成功”替代密钥证据。

当前仓库没有注册 `dtls` layer、planner（规划器）、validator（校验器）或生成器。`cases/dtls.json` 只保留一个 `dtls_neg_unregistered` 注册前置占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 DTLS 行为通过。

## 2. 推荐配置和协议栈

推荐层链为 `[ip, udp, dtls]`；选择 IPv6 时使用 `[ipv6, udp, dtls]`。DTLS 的默认 destination port（目的端口）为 4433，source port（源端口）由 fixture 显式指定。配置是实现契约，不是当前注册承诺：

```json
{
  "layers": [{"ip": {}}, {"udp": {}}, {"dtls": {}}],
  "src_ip": "192.0.2.58",
  "dst_ip": "198.51.100.58",
  "src_port": 45058,
  "dst_port": 4433,
  "dtls": {
    "version": "1.2",
    "cookie": {"enabled": true},
    "ciphertext": {"opaque": true},
    "events": ["client_hello", "hello_verify_request", "client_hello_cookie", "server_hello"]
  }
}
```

| 配置键 | 约束 |
|---|---|
| `src_ip`/`dst_ip`、`src_port`/`dst_port` | UDP 四元组；正例默认目的端口 4433，不能把 DTLS 改成 TCP/TLS。 |
| `version` | `1.0` 线版本 `fe ff`，`1.2` 线版本 `fe fd`；版本字段和 ClientHello offered version 必须自洽。 |
| `epoch`/`sequence` | epoch 为 16-bit；record sequence 为 48-bit 大端，不能截断、回绕或跨会话共享。 |
| `cookie` | 仅在声明的 HelloVerifyRequest 交换中出现；ClientHello cookie 长度必须等于实际 cookie 字节数，Cookie 值不要硬编码运行期随机数。 |
| `handshake` | 消息头含 type、24-bit length、message_seq、fragment_offset、fragment_length；分片必须可重组且不重叠。 |
| `ciphertext` | 加密 epoch 的 payload 只声明长度/不透明字节；无密钥时禁止断言明文。 |
| `events` | 有序状态事件；握手、CCS、alert 和应用数据不得越序或跨会话引用。 |
| `flow_count`/`session_id` | 多会话/多流隔离；每个会话独立 epoch、sequence、重传计时器和关闭状态。 |
| `wire_fault` | 仅负例故障注入口：`record_length`、`version_epoch`、`sequence`、`fragment`、`cookie_state`、`carrier`。不是线上字段。 |
| `mss` | UDP/DTLS 不协商 TCP MSS；显式设置只能拒绝或标记不适用，不得生成 TCP handshake。 |

## 3. UDP 载体、数据报边界和固定偏移

DTLS 使用 UDP，不提供 TCP 字节流语义。一个 UDP datagram（数据报）可以携带一个或多个完整 DTLS records（记录），也可以因实现的分片策略承载一个完整记录；记录的 13-byte header（头部）中的 Length 才是记录边界。实现不得跨 session 拼接 datagram，也不得按 UDP payload 尾部默默截断记录。

无 Ethernet VLAN、IPv4 options（选项）或 IPv6 extension header（扩展头）时，DTLS record 起点为：

| 载体 | record 起点 | 计算 |
|---|---:|---|
| Ethernet + IPv4 + UDP | 42 | 14 + 20 + 8 |
| Ethernet + IPv6 + UDP | 62 | 14 + 40 + 8 |

UDP destination port 正例为 4433；IPv4 `ip.proto=17`，IPv6 `ipv6.nxt=17`。IPv4 UDP checksum 可为零或正确非零；IPv6 UDP checksum 必须非零且正确。NIC checksum offload（校验和卸载）差异只能改变观察方法，不能改变 wire bytes（线上字节）契约。

## 4. DTLS record header 逐字节布局

record 起点记为 `R`，固定头长 13 bytes，网络字节序：

```text
ContentType(1) | Version(2) | Epoch(2) | SequenceNumber(6) | Length(2) | Fragment(Length)
```

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Content Type | 20=ChangeCipherSpec、21=alert、22=handshake、23=application data；未知类型拒绝。 |
| 1 | 2 | Version | DTLS 1.0 为 `fe ff`，DTLS 1.2 为 `fe fd`；同一 session 不可无声明切换。 |
| 3 | 2 | Epoch | 初始明文 epoch=0；完成密钥切换后按状态递增。epoch 不能倒退或跨会话复用。 |
| 5 | 6 | Sequence Number | 48-bit big-endian；同一 epoch 单调递增，重传不得让它回绕；不同 epoch 可从 0 重新开始。 |
| 11 | 2 | Length | 仅覆盖 fragment 字节，不包含 13-byte record header；必须与 UDP 中实际 bytes 完全一致。 |
| 13 | n | Fragment | 明文 handshake/alert 等仅在未加密 fixture 可解码；加密后按 opaque payload 处理。 |

固定 raw prefix（原始前缀）示例（DTLS 1.2、epoch 0、sequence 0、空 fragment）：`16 fe fd 00 00 00 00 00 00 00 00 00 00`。示例仅用于稳定边界断言；运行期随机端口、cookie、加密内容不得硬编码。

## 5. Content Type、epoch 和序列空间

DTLS 1.0/1.2 初始握手记录使用 epoch 0。`ChangeCipherSpec` 是 content type 20 的独立记录；在传统 DTLS 1.2 profile 中，CCS 前后的加密状态切换使后续记录进入新的 epoch。Alert 为 type 21，application data 为 type 23；加密后只能断言外层记录头及长度，不能声称看到 alert 的两个明文字节或应用协议。

每个方向分别维护 epoch 与 48-bit record sequence。实现必须保证：

- 同一 epoch 内每个新发送的 record（包括重传）都必须使用严格递增、不回退的 record sequence；重传复用原 handshake message 的 `message_seq`/fragment 语义，但不能复用 record sequence。达到 `0xffffffffffff` 后不得静默回绕，必须报 overflow 或停止该 epoch。
- epoch 变化不能把旧 epoch 的 sequence、cipher state（密码状态）或 replay window（重放窗口）带入新 epoch。
- 多会话即使使用相同四元组模板，也必须独立计数；多流输出不以全局 sequence 代替会话 sequence。
- 加密 payload 的 Length 包括显式 nonce/认证标签等在线 profile 定义的密文字节，但不把 UDP/TLS 外层头算入。

## 6. Handshake header、fragmentation 和 reassembly

每个 handshake message（握手消息）在 record fragment 内使用 12-byte header：

```text
MessageType(1) | Length(3) | MessageSeq(2) | FragmentOffset(3) | FragmentLength(3) | Body(...)
```

`Length` 是完整消息 body 长度；`FragmentOffset`/`FragmentLength` 是本片在完整 body 中的偏移/长度。实现必须支持一个消息跨多个 records/datagrams，按 `message_seq` 和 offset 重组；片段不能越界、重叠或把不同 message_seq 拼接。完整 body 收齐前不能推进依赖该消息的状态。握手消息的 record content type 必须为 22，握手 header 的 24-bit 字段按网络序编码，不能用主机序 32-bit 值直接写入线。

正例至少覆盖 ClientHello、ServerHello、Certificate/ServerKeyExchange（按 profile）、Finished 的消息序号，以及一条跨 record 的分片和乱序到达后重组。DTLS 1.2 的 HelloVerifyRequest 属于服务端握手消息，cookie exchange 必须在第二个 ClientHello 中携带完整 cookie；DTLS 1.0 fixture 可显式关闭 cookie，不得因版本切换伪造 1.2-only 字段。

## 7. Cookie exchange、重传、超时和关闭

DTLS 1.2 无状态 cookie 流程为：客户端 ClientHello（无 cookie）→ 服务端 HelloVerifyRequest（含 cookie）→ 客户端带 cookie 的第二个 ClientHello → 正常 ServerHello/握手。Cookie 的长度前缀和实际 bytes 必须一致；服务端不能在 cookie 未验证时接受后续握手或产生 application data。为防止运行期随机性，PCAP 断言 cookie 只使用 presence、长度、前后相等或非零等动态断言，不猜测固定值。

握手以 flight 为重传单位。超时应重发未确认 flight，重传不得推进握手状态两次、重复分配 session 或产生跨 epoch 的非法记录；达到重试上限应报告 timeout/error，而不是 `completed` 且 0 packets。异常关闭可发送 alert 后关闭 UDP session；若 alert 已加密，PCAP 只断言 type=21、epoch 和长度，明文 reason 由解密 fixture/单测断言。

## 8. 加密边界和 RFC 8446 参考

DTLS 1.2 的 record payload 在握手密钥建立后可能为密文；明文 record header 仍携带 type/version/epoch/sequence/length。RFC 8446 的 TLS 1.3 内层 content type 保护语义不能直接冒充 DTLS 1.2 的外层 header；若未来支持 DTLS 1.3，应新增版本/profile，不得把 TLS 1.3 record 的末尾内层类型当作公开 DTLS 字段。

无解密密钥的 PCAP/NIC 证据仅包括 UDP/4433、方向、record header、epoch/sequence、长度、TCP 不存在，以及可观察的握手明文记录。不得断言 `handshake.type`、cookie 内容、alert level/description 或 application payload 出现在加密 record 中。提供解密 key log（密钥日志）时也必须记录解密条件和工具版本，避免把解析器推测当线上证据。

## 9. IPv4/IPv6、多会话和多流

outer IPv4 与 IPv6 是独立 fixture 维度，不能由 DTLS record version 或 inner 应用 payload 推导。每个 session 至少拥有独立 UDP 四元组、epoch/sequence、cookie 状态、重传计时器和 close 状态。多 flow 可以共享目的端口 4433，但必须以四元组或显式 `session_id` 隔离，不能串用握手片段、cookie、重传 flight 或 application data。

DTLS 没有 TCP handshake/MSS/FIN。UDP datagram 的顺序、丢失和重复是正常传输条件；验证器对重传按 message_seq/flight 语义去重，而不是把重复 datagram 当新握手。实现若提供 timeout fixture，必须可观察重传次数与最终错误，不能静默成功。

## 10. 边界、异常和错误传播

至少覆盖：record Length=0、Length 最大值附近、epoch=0/1、sequence=0/最大值附近、IPv4/IPv6、cookie 空/非空、握手单片与跨 record 分片、乱序重组、CCS→加密 alert/application data、重传超时、异常 alert close、多会话和 UDP 载体错误。显式 0 不能被默认值覆盖。

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `dtls_neg_record_truncated` | record header 少于 13 bytes 或 Length 超出 datagram | `record` 或 `length` |
| `dtls_neg_version_epoch` | 未声明版本、未知 content type、epoch 倒退/跨会话复用 | `version`、`epoch` 或 `type` |
| `dtls_neg_sequence_overflow` | sequence 超过 48-bit、同 epoch 回绕或重复（含重传复制 sequence） | `sequence` 或 `overflow` |
| `dtls_neg_fragment_bounds` | handshake 24-bit 长度/offset/fragment length 越界、重叠或错误拼接 | `fragment` 或 `handshake` |
| `dtls_neg_cookie_state` | cookie 缺失/长度不符、未验证即继续或重传推进状态 | `cookie` 或 `state` |
| `dtls_neg_udp_carrier` | TCP/裸 IP/错误 UDP 端口、UDP checksum/载荷边界错误 | `transport`、`udp` 或 `checksum` |

## 11. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 `58-dtls-testcase.md` §2 及未来注册后的 `dtls.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

## 12. PCAP/NIC 观察与实现完成定义

实现注册后先检查 `tshark -G fields | grep -E '\tdtls\.'`。若环境没有 DTLS dissector，使用通用 `udp.dstport`、`ip.proto`/`ipv6.nxt`、record raw bytes、长度和实际偏移；不自创 `dtls.*` 字段。明文 fixture 可使用 handshake header 字节断言，密文 fixture 只能使用外层 record 字段。

PCAP 正例必须断言方向、UDP/4433、record 数量/长度、版本、epoch、sequence、content type 和必要的 IPv4/IPv6 family。NIC 模式必须记录捕获接口和过滤器 `udp port 4433`，说明 checksum offload 与密文边界。多会话/多流不假设全局到达顺序，只断言每个 session 内的状态和序列关系。

完成定义：注册 `dtls` layer；逐字节验证 13-byte record header、48-bit sequence、12-byte handshake header 和 cookie/flight 状态；planner→worker→UDP output 完整路径能传播正负结果；-race（竞态检测）和集成测试覆盖多会话计数、重传计时器、关闭；无解密 PCAP/NIC 不声称看见加密内层。

三方契约必须保持本文 §11、`58-dtls-testcase.md` §2、未来 `dtls.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `dtls_neg_unregistered`，且唯一预期为 `unknown layer`。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 DTLS 1.0/1.2 正例和 6 个严格负例，覆盖 RFC 4347/6347 记录层、epoch/48-bit sequence、握手分片重组、cookie、重传/超时、CCS/alert/application data、加密边界、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
