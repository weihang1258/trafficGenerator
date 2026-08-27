# SSTP（安全套接字隧道协议，Secure Socket Tunneling Protocol）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/57-sstp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/sstp.json`  
> 状态：`sstp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `sstp_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

SSTP 只在 TCP/443 的 TLS（传输层安全）应用数据中承载。无解密密钥的 PCAP/NIC 只能断言 TCP 四元组、443、TCP handshake（握手）、TLS handshake/record（记录）、application-data（应用数据）方向和长度；不能把密文或 TLS record offset（偏移）声称为 SSTP header（头）、attribute（属性）或 PPP 字段。明文 fixture（固定样本）或实现 trace（跟踪）才可断言 SSTP/PPP 字节。

SSTP 明文 packet 先有 4-byte common header；C bit 为 1 时再有 2-byte Message Type 和 2-byte Num Attributes，因此 control packet 的固定 header 为 8 bytes（无属性时），data packet 不带 Message Type 或 Num Attributes。Length 覆盖整个 SSTP packet（包括 common header、control Message Type/Num Attributes 及 attributes/data），不覆盖 TLS/TCP 头；TLS record/TCP segment 边界不能替代 SSTP message 边界。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier（载体）字段和稳定 raw frames（原始帧）；未解密场景不得写 `sstp.*`/PPP 字段。负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `sstp_https_tls_handshake` | 正 | TCP/443、TLS handshake、application-data 载体 | 16 |
| 2 | `sstp_call_connect_request` | 正 | SSTP header、CALL CONNECT REQUEST、Protocol ID | 8 |
| 3 | `sstp_call_connect_ack` | 正 | ACK、Status Info Attribute、属性长度 | 10 |
| 4 | `sstp_call_connected` | 正 | CONNECTED 状态和顺序 | 10 |
| 5 | `sstp_call_abort` | 正 | CALL ABORT Message Type、Status Info Attribute、终止 | 12 |
| 6 | `sstp_attribute_protocol_id` | 正 | PPP Encapsulated Protocol ID Attribute | 8 |
| 7 | `sstp_attribute_status_crypto` | 正 | Status Info + Crypto Binding | 10 |
| 8 | `sstp_ppp_ipv4` | 正 | C=0 PPP IPv4 framing | 12 |
| 9 | `sstp_ppp_ipv6` | 正 | C=0 PPP IPv6 framing | 12 |
| 10 | `sstp_ppp_mppe_boundary` | 正 | MPPE block boundary、密文可见性 | 14 |
| 11 | `sstp_multi_connection` | 正 | 多独立 TLS/TCP/SSTP connections | 24 |
| 12 | `sstp_session_ordering` | 正 | control→connected→PPP→abort 顺序、保活/重连 | 16 |
| 13 | `sstp_length_record_segmentation` | 正 | SSTP Length 跨 TLS record/TCP segment | 18 |
| 14 | `sstp_pcap_nic_consistency` | 正 | PCAP/NIC 方向和 443/TLS 载体一致 | 16 |
| 15 | `sstp_neg_header_length` | 负 | common header 少于 4 bytes、control header 少于 8 bytes 或 Length 不一致 | — |
| 16 | `sstp_neg_attribute_length` | 负 | 属性头字段截断、`LengthPacket` 越界/非法重复、把 Message Type `0x0005`/`0x0006` 当作属性或未知 ID | — |
| 17 | `sstp_neg_state_transition` | 负 | 越序 CONNECTED/PPP/ABORT 后继续 | — |
| 18 | `sstp_neg_transport_carrier` | 负 | 非 TCP/443、无 TLS 或 UDP 载体 | — |
| 19 | `sstp_neg_ppp_framing` | 负 | PPP address/control/protocol/长度错误 | — |
| 20 | `sstp_neg_tls_boundary` | 负 | TLS record/明文 HTTP 冒充 SSTP 或跨连接串流 | — |

## 3. 载体和线格式断言

无 IP options、TCP options 和 TLS 解密时，外层 IPv4 TCP payload 起点仅可作为 carrier 参考：Ethernet 14 + IPv4 20 + TCP 20 = 54。SSTP 起点位于 TLS application data 内，不能直接断言 offset 54 是 SSTP 起点。明文 packet 起点记为 `S`，公共头为 4 bytes：

```text
Version(1) | Reserved(7)+C(1) | Reserved(4)+Length(12) | [control fields or PPP data]

C=1 时，`Message Type(2)` 位于 `S+4`，`Num Attributes(2)` 位于 `S+6`；这两个控制字段均不属于属性头。
```

- `Version=0x10`；控制消息 C bit 为 1，data packet C bit 为 0；保留位必须为 0。
- `Length` 覆盖整个 SSTP packet，包括 4-byte common header、控制包的 Message Type/Num Attributes/attributes 或 data 包的 PPP frame，不包括 TLS/TCP 头。
- C=1 时，4-byte common header 后为 `Message Type(2)|Num Attributes(2)|Attributes`，控制头最小为 8 bytes（无属性时）；C=0 时 4-byte header 后直接为 PPP frame，无 Message Type。
- 控制消息完整枚举为 `0x0001` REQUEST、`0x0002` ACK、`0x0003` NAK、`0x0004` CONNECTED、`0x0005` ABORT、`0x0006` DISCONNECT、`0x0007` DISCONNECT ACK、`0x0008` ECHO REQUEST、`0x0009` ECHO RESPONSE。
- 属性头为 `Reserved(1)|Attribute ID(1)|LengthPacket(16)|Value`；这是 1-byte Reserved、1-byte Attribute ID 加 2-byte LengthPacket 的 4-byte 属性头。LengthPacket 包括 4-byte 属性头，Value 长度为 `LengthPacket-4`。真实属性 ID 为 `0x01` Encapsulated Protocol ID、`0x02` Status Info、`0x03` Crypto Binding、`0x04` Crypto Binding Request；`0x0005`/`0x0006` 仅是 2-byte Message Type 值，不能作为属性 ID。

TLS record 或 TCP segment 边界不等于 SSTP Length 边界。解密验证端必须重组完整 Length 后再解析，不能把两个 message 拼接或把一个 message 截断。

## 4. 正例逐项断言契约

1. **`sstp_https_tls_handshake`**：建立 TCP/443 三次握手，完成 TLS client/server handshake，随后双向 application-data；断言 TCP 方向、443、TLS record content type/length、正常 FIN/close 和 `packet_count=16`。无密钥时只断言 TLS，不断言 SSTP 字段。
2. **`sstp_call_connect_request`**：解密 fixture 中 client 在 TLS established 后发送 Version/C=1、Length、Message Type `0x0001` 和 Num Attributes，至少有 Encapsulated Protocol ID Attribute；断言网络序 header、属性长度和事件顺序，`packet_count=8`。控制 packet 的 Message Type 位于 common header 之后。
3. **`sstp_call_connect_ack`**：server 返回 `CALL CONNECT ACK` 与 Status Info Attribute（变长规范结构）；断言 ACK 不被当作 CONNECTED、Length 覆盖属性、方向为 server→client，`packet_count=10`。
4. **`sstp_call_connected`**：client 仅在 ACK 后发送 CONNECTED；断言 CONNECTED 的 C bit、Message Type `0x0004` 和 Num Attributes/属性按 fixture 编码，且之后才允许 PPP，`packet_count=10`。
5. **`sstp_call_abort`**：在合法控制阶段由任一方向发送 Message Type `0x0005` 的 ABORT；如需状态原因，使用 Status Info Attribute，随后 TLS/TCP close；断言 ABORT 后无 PPP 或控制消息，`packet_count=12`。
6. **`sstp_attribute_protocol_id`**：至少一条 CONNECT REQUEST 携带 Attribute ID `0x01`、LengthPacket `0x0006`、Value `0x0001` 的完整 Encapsulated Protocol ID Attribute；断言属性顺序和完整长度，不以最后一项覆盖前项，`packet_count=8`。
7. **`sstp_attribute_status_crypto`**：ACK/NAK fixture 携带 Status Info Attribute（ID `0x02`）和 Crypto Binding（ID `0x03`）或 Crypto Binding Request（ID `0x04`）；按 MS-SSTP 总长度/Value 边界断言，运行期 binding/证书指纹可动态，不能硬编码随机字节，`packet_count=10`。
8. **`sstp_ppp_ipv4`**：CONNECTED 后发送 C=0 data，明文 PPP frame 为 `ff 03 00 21` 加 IPv4 payload；断言 PPP protocol、IPv4 version/length/checksum 和 SSTP Length，不能由 outer IP 偷换，`packet_count=12`。
9. **`sstp_ppp_ipv6`**：独立 fixture 使用 `ff 03 00 57` 加 IPv6 payload；断言 IPv6 version/payload length/Next Header 和 SSTP Length，与 IPv4 fixture 的地址族互不改写，`packet_count=12`。
10. **`sstp_ppp_mppe_boundary`**：PPP information 分别取恰好 MPPE block boundary 和跨 boundary 的长度；无解密 PCAP 只断言 TLS application-data、C=0 载荷长度和方向，不把密文识别为 IPv4/IPv6，`packet_count=14`。
11. **`sstp_multi_connection`**：至少两个独立 TCP/443+TLS session 并行，分别完成 CONNECT/CONNECTED/PPP；断言每条连接的状态、TLS session、PPP payload 和 close 独立，不能跨连接串流，`packet_count=24`。
12. **`sstp_session_ordering`**：覆盖 control→ACK→CONNECTED→PPP→可选 ABORT 的严格顺序，并在同一连接发送保活数据、关闭后以新 TLS/TCP connection 重连；断言旧连接不接收新状态，`packet_count=16`，不假设并行到达全局顺序。
13. **`sstp_length_record_segmentation`**：将一个 SSTP control 或 PPP data message 分割到多个 TLS records 和 TCP segments，再发送相邻 message；解密后按 Length 恢复两条独立 message，`packet_count=18`。
14. **`sstp_pcap_nic_consistency`**：同一 fixture 分别输出 PCAP 并在指定 NIC 捕获；两者均断言 TCP/443、TLS handshake/application-data、方向、握手与关闭数量一致。未解密捕获不要求 SSTP/PPP 字段；记录过滤器 `tcp port 443`、接口和 checksum offload，`packet_count=16`。

## 5. 负例契约

每个负例必须在 planner/validator 处失败并传播为 task error；不能生成成功 PCAP、completed/0 packet 或只有 TCP/TLS 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `sstp_neg_header_length` | common header 少于 4 bytes、control header 少于 8 bytes、Length 小于 header 或超过 message | `header` 或 `length` |
| `sstp_neg_attribute_length` | 属性头字段截断、`LengthPacket` 小于 4 或越界/回绕、把 Message Type `0x0005`/`0x0006` 当作属性或未知 Attribute ID | `attribute` 或 `length` |
| `sstp_neg_state_transition` | 未完成 ACK 即 CONNECTED/PPP、ABORT 后继续、跨连接引用 | `state` 或 `sequence` |
| `sstp_neg_transport_carrier` | UDP、错误端口、裸 TCP、明文 HTTP 或未完成 TLS | `transport` 或 `tls` |
| `sstp_neg_ppp_framing` | 缺少 `ff 03`/PPP protocol、IPv4/IPv6 protocol mismatch、长度错误 | `ppp` 或 `framing` |
| `sstp_neg_tls_boundary` | TLS record 截断、明文 SSTP 越过 TLS、跨连接拼接 message | `tls` 或 `boundary` |

合法的 TLS 密文、TLS record 分段、PPP IPv4/IPv6、MPPE block 边界、CALL CONNECT NAK 和允许的空属性控制头由正例覆盖，不能误报为负例。错误传播须保留原始原因，不能以通用“0 packets”替代验证错误。

## 6. PCAP/NIC 和静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/sstp.json`；当前 JSON 必须恰有一个 `sstp_neg_unregistered`，`proto=sstp`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前 ID 集合只有占位；注册后 JSON 必须按本文 §2 顺序补入 14 个正例和 6 个负例，且与设计 §10 同序。
3. 正例应使用实际注册的 `tcp.*`、`tls.record.*`、`ip.*`/`ipv6.*` 字段与稳定 carrier frames；未解密时不得伪造 `sstp.*` 或 PPP 字段。
4. 解密 fixture 或实现 trace 必须逐字节断言 4-byte common header、control packet 的 Message Type/Num Attributes（控制字段起点后至少 8 bytes）、Length、4-byte attribute header、属性顺序、状态顺序和 PPP framing；动态 binding、TLS nonce、证书指纹不得猜测常量。
5. `sstp_pcap_nic_consistency` 记录 PCAP 路径、NIC 接口、`tcp port 443` 过滤器和 checksum offload 观察边界；TLS 保密不能被当作测试失败，也不能放宽载体/方向/握手断言。
6. 负例 `expect` 只能含 `expect_error`、`error_contains`；占位的 `unknown layer` 不得冒充 20 个语义场景已经执行。

## 7. 三方一致性表

设计 §10、本文 §2 和未来 JSON 必须保持以下 20 个唯一语义 ID、同一顺序；当前 JSON 另有一个不计入覆盖的注册前置占位：

```text
sstp_https_tls_handshake
sstp_call_connect_request
sstp_call_connect_ack
sstp_call_connected
sstp_call_abort
sstp_attribute_protocol_id
sstp_attribute_status_crypto
sstp_ppp_ipv4
sstp_ppp_ipv6
sstp_ppp_mppe_boundary
sstp_multi_connection
sstp_session_ordering
sstp_length_record_segmentation
sstp_pcap_nic_consistency
sstp_neg_header_length
sstp_neg_attribute_length
sstp_neg_state_transition
sstp_neg_transport_carrier
sstp_neg_ppp_framing
sstp_neg_tls_boundary
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 SSTP/HTTPS 正例、6 个严格负例和 1 个未注册占位，覆盖 TLS/TCP/443、SSTP header/control 生命周期、attribute TLV、PPP IPv4/IPv6、MPPE 边界、多连接、保活/重连、分段重组、PCAP/NIC 和错误传播；当前仅提交设计与用例契约，不修改 Go 实现。
