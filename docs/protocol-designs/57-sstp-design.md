# SSTP（安全套接字隧道协议，Secure Socket Tunneling Protocol）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`sstp` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/57-sstp-testcase.md`、`trafficgen/test/protocol_pcap/cases/sstp.json`  
> 规范基线：MS-SSTP、RFC 1661（PPP，点对点协议）；TLS（传输层安全）边界按 HTTPS 载体处理。

## 1. 范围、证据等级和未注册边界

本设计定义 SSTP over HTTPS（基于 HTTPS 的 SSTP）会话：TCP destination port（目的端口）443，TLS 握手后承载 SSTP control message（控制消息）和 PPP（Point-to-Point Protocol，点对点协议）data frame（数据帧）。覆盖 CALL CONNECT、CALL CONNECTED、CALL ABORT 生命周期、属性 TLV（类型-长度-值）、PPP IPv4/IPv6、MPPE（Microsoft Point-to-Point Encryption，微软点对点加密）边界和多连接隔离。

SSTP 的明文协议语义只在 TLS 解密后的应用数据中可验证。没有解密密钥的 PCAP 只能断言 TCP/443、TLS handshake/record（记录）和方向，不能伪造或声称观察到 SSTP header、attribute 或 PPP 字段。NIC（网卡）捕获还必须说明校验和卸载和 TLS 保密边界。

当前仓库没有注册 `sstp` layer、planner（规划器）、validator（校验器）或生成器。`cases/sstp.json` 只保留一个 `sstp_neg_unregistered` 占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 SSTP 行为通过。

## 2. 推荐配置和层链

推荐层链为 `[ip, tcp, tls, sstp]`；若实现将 TLS 作为载体参数，则允许 `[ip, tcp, sstp]` 加 `tls` 配置，但不能把明文 SSTP 当成 UDP 或裸 TCP 应用。配置是实现契约，不是当前注册承诺：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"tls": {}}, {"sstp": {}}],
  "src_ip": "192.0.2.57",
  "dst_ip": "198.51.100.57",
  "src_port": 45000,
  "dst_port": 443,
  "tls": {"version": "1.2", "sni": "sstp.example.test"},
  "sstp": {
    "version": 16,
    "events": [{"kind": "call_connect_request", "direction": "c2s"}],
    "ppp": {"protocol": "ipv4", "payload_b64": ""}
  }
}
```

| 配置键 | 约束 |
|---|---|
| `src_ip`/`dst_ip`、`src_port`/`dst_port` | 外层 TCP 四元组；正例 destination 固定 443，SSTP 不另用 UDP 端口。 |
| `tls` | HTTPS 载体配置；至少声明版本、SNI（服务器名称指示）和证书 fixture。未解密时只验证 TLS record。 |
| `version` | SSTP 版本字节；本版正例固定 `0x10`（1.0），其他版本进入负例。 |
| `events` | 有序控制消息和 PPP data 事件；状态机必须拒绝越序、跨连接引用和缺失前置消息。 |
| `attributes` | 每个属性为 `Reserved(1)+Attribute ID(1)+LengthPacket(16)+Value`；`LengthPacket` 包含 4-byte 属性头，保留线上顺序。 |
| `ppp` | PPP framing、protocol、payload；IPv4/IPv6 独立声明，不能由 outer IP 推导。 |
| `mppe` | 仅声明加密边界和合法 MPPE payload fixture；密钥不可用时 PCAP 不断言解密后的 IP。 |
| `flow_count`/`connection_id` | 多连接隔离；每个连接拥有独立 SSTP 状态、PPP 序列和 TLS session。 |
| `wire_fault` | 仅负例故障注入口：`header_length`、`attribute_length`、`state`、`carrier`、`ppp_framing`、`tls_boundary`。不是线上字段。 |

## 3. SSTP header 和控制消息布局

解密后的 SSTP packet 起点记为 `S`。所有 packet 先有 4-byte common header；仅当 C bit 为 1 的 control packet 才追加 2-byte Message Type 和 2-byte Num Attributes；无属性 control packet 的完整固定部分为 8 bytes。

```text
Version(1) | Reserved(7)+C(1) | Reserved(4)+Length(12) | [Message Type(2)] | [Num Attributes(2)] | Attributes/Data...

`Message Type(2)` 是控制包在 `S+4` 的独立 2-byte 字段；`Num Attributes(2)` 是随后 `S+6` 的独立 2-byte 字段。二者都不是属性头。
```

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Version | 高 4 bits 为 major version `1`，低 4 bits 为 minor version `0`，线值为 `0x10`。 |
| 1 | 1 | Reserved(7)+C(1) | 保留 7 bits 必须为 0；C=1 表示 control packet，C=0 表示 data packet。 |
| 2 | 2 | Reserved(4)+Length(12) | 网络字节序；保留 4 bits 为 0；Length 覆盖整个 SSTP packet，不含 TLS/TCP 头。 |
| 4 | 2 | Message Type | 仅 C=1 存在；C=0 时此处直接是 PPP data。 |
| 6 | 2 | Num Attributes | 仅 C=1 存在；表示后续有序属性数量。 |
| 8 | n | Attributes | 仅 C=1 存在；每项遵循 4-byte attribute header。 |
| 4 | n | PPP data | 仅 C=0 存在；4-byte common header 后直接为 PPP frame。 |

本版控制消息类型完整枚举：`CALL CONNECT REQUEST=0x0001`、`CALL CONNECT ACK=0x0002`、`CALL CONNECT NAK=0x0003`、`CALL CONNECTED=0x0004`、`CALL ABORT=0x0005`、`CALL DISCONNECT=0x0006`、`CALL DISCONNECT ACK=0x0007`、`ECHO REQUEST=0x0008`、`ECHO RESPONSE=0x0009`。未知 Message Type 必须拒绝。

无 TCP options、TLS 解密应用数据可见的合成 fixture 中，外层 TCP payload 起点为 Ethernet 14 + IPv4 20 + TCP 20 = 54；但 SSTP 起点位于 TLS application data（应用数据）内部，真实 PCAP 不得把 offset 54 误标成明文 SSTP 起点。明文单元测试可以单独以 SSTP message 起点 S 断言 common header 或 control header。

## 4. Attribute（属性）线格式

控制消息的每个属性按 MS-SSTP 线格式编码：

```text
Reserved(1) | Attribute ID(1) | LengthPacket(16) | Attribute Value(LengthPacket - 4)
```

属性头固定 4 bytes：`Reserved(1)` 发送时为 0，`Attribute ID(1)` 为 1-byte 属性类型，`LengthPacket(2/16)` 为网络字节序的完整属性长度，包含 4-byte 属性头；因此属性 value 长度为 `LengthPacket-4`，不是单独的 value 长度。属性按控制消息中的 Num Attributes 顺序编码，不能隐式 padding、覆盖重复值或把控制 Message Type 字段误读为 Attribute ID。

| 属性 | Attribute ID | 线长度和值约束 |
|---|---:|---|
| Encapsulated Protocol ID | `0x01` | 完整属性 LengthPacket=`0x0006`；Value 为 2 bytes `0x0001`（PPP，RFC 1661）。 |
| Status Info | `0x02` | 变长；Value 包含被报告的 Attribute ID、Status 等规范字段，不能固定为固定长度 value。 |
| Crypto Binding | `0x03` | 完整 binding fixture；SHA-256 profile（档案）总属性 LengthPacket 为 `0x0068`，不得截断。 |
| Crypto Binding Request | `0x04` | 总属性 LengthPacket 为 `0x0028`，含 hash protocol bitmask 和 32-byte nonce。 |

CALL CONNECTED、CALL ABORT、CALL DISCONNECT 等是 Message Type（消息类型），不是 Attribute ID（属性 ID）；这些 2-byte 值 `0x0005`/`0x0006` 只能出现在 `S+4` 的 Message Type 字段，不能作为属性头首字节或属性 ID。
## 5. TLS/HTTPS 和会话载体

1. SSTP 必须建立 TCP 连接后进行 TLS handshake；正例 destination port 固定 443，TLS record content type（内容类型）使用已注册的 `tls.record.content_type`、`tls.record.length` 等字段。
2. TLS handshake 未完成、明文 HTTP 请求代替 SSTP、错误端口或把 SSTP 放在 UDP，必须在 validator/planner 阶段失败。
3. TLS application data 可以跨多个 TLS record 和 TCP segment；不能用 record 或 TCP segment 边界替代 SSTP Length。解密 fixture 必须按 Length 重组 SSTP message。
4. TLS record 中的 SSTP control/data 在无密钥 PCAP 中不可见。PCAP 正例至少断言 TCP SYN/SYN-ACK/FIN、443、TLS handshake 和 application-data record；不能对加密字节写 SSTP raw frames。
5. TLS 版本、SNI 和证书 fixture 属于载体配置；不把 SNI 当 SSTP attribute，也不把 HTTPS HTTP/2 stream 当 SSTP message。

## 6. Control 状态机

一个连接的最小合法路径为：`TLS established → CALL CONNECT REQUEST → CALL CONNECT ACK/NAK → CALL CONNECTED → PPP data → CALL ABORT（可选终止）→ TLS/TCP close`。NAK 是拒绝路径，不能继续发送 CONNECTED 或 PPP data。

- CALL CONNECT REQUEST 由客户端发送，包含 PPP Encapsulated Protocol ID 和可选 Crypto Binding。
- CALL CONNECT ACK 由服务端发送，状态成功；CALL CONNECT NAK 必须携带 Status Info，随后连接不能进入 PPP data。
- CALL CONNECTED 由客户端确认控制阶段完成；只有之后才能产生 PPP data。
- CALL ABORT 可由任一方向发送，携带稳定 reason/status；发送后不得继续该 connection 的控制或 PPP data。
- 连接 ID、transaction 状态和属性不能跨 TLS connection 复用；多连接可并行但每条流独立排序。

合法的错误响应/NAK 属于正例语义；配置状态越序、缺少 ACK、重复 CONNECTED、ABORT 后继续发送和跨连接引用属于负例，必须传播 task error。

## 7. PPP framing、IPv4/IPv6 和 MPPE

C=0 的 SSTP data packet 的 data 区是 PPP frame。默认 uncompressed PPP framing 为：

```text
0xff 0x03 | Protocol(2) | Information(payload) | [FCS(可选，按 profile)]
```

本契约正例固定断言 Address `ff`、Control `03`、protocol `00 21`（IPv4）或 `00 57`（IPv6），并按解码长度验证完整 payload；不把 outer IPv4/IPv6 地址族自动复制为 PPP protocol。若 profile 显式启用 address/control/protocol compression，必须单独声明并更新断言，不能隐式切换。

MPPE 只改变 PPP information 的加密表示，不改变 SSTP Length 或 PPP protocol 语义边界。无密钥 PCAP 只能断言 C=0、SSTP packet length 和不可解密的 TLS/application data，不能把随机密文解释为 IPv4/IPv6 header。明文 fixture 必须覆盖 payload 恰好在 MPPE block boundary、跨 SSTP/TLS record boundary 和长度变化。

## 8. 多连接、分段和长度边界

SSTP 没有 UDP datagram 边界；同一 TCP/TLS session 可将控制消息或 PPP data 分割到多个 segment/record。实现必须按 SSTP Length 重组，禁止按 segment 尾部截断或把两个消息拼成一个。大 PPP payload 可跨多个 TLS records，但不能跨 connection。

边界至少覆盖：Length=8 的无属性控制头、单个 2-byte PPP Protocol ID Value（属性总长度 6）、长度最大值附近、零长度 PPP information（若 profile 允许）、IPv4/IPv6 最小 payload、MPPE block 对齐/非对齐、多个 attribute、多个 TLS record、两个并行 connection。显式 0 不能被默认值覆盖。

## 9. PCAP/NIC 断言和字段证据

实现注册后先检查 `tshark -G fields | grep -E '\ttls\.'`。本版不预先假定 `sstp.*` dissector（解析器）字段；正例使用实际注册的 `tcp.*`、`tls.record.*`、`ip.*`/`ipv6.*` 和稳定 raw bytes。TLS 未解密时不得创造 `sstp.type`、`sstp.length` 或 PPP 字段。

PCAP 正例必须断言方向、TCP/443、完整 TCP handshake/termination、TLS handshake/application-data records、connection 数量和 event 顺序可从解密 fixture 或实现 trace 证明。NIC 模式必须记录捕获接口和建议过滤器 `tcp port 443`，并明确 checksum offload/TLS 保密限制。若只捕获密文，SSTP/PPP 字段断言转为实现单测，不降低任务成功标准。

## 10. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 testcase 及注册后的 JSON 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `sstp_https_tls_handshake` | 正 | TCP/443、TLS handshake、application-data 载体 | 16 |
| 2 | `sstp_call_connect_request` | 正 | SSTP header、CALL CONNECT REQUEST、Protocol ID | 8 |
| 3 | `sstp_call_connect_ack` | 正 | ACK、Status Info、属性长度 | 10 |
| 4 | `sstp_call_connected` | 正 | CONNECTED 状态和顺序 | 10 |
| 5 | `sstp_call_abort` | 正 | CALL ABORT、reason/status、终止 | 12 |
| 6 | `sstp_attribute_protocol_id` | 正 | PPP Protocol ID TLV | 8 |
| 7 | `sstp_attribute_status_crypto` | 正 | Status Info + Crypto Binding | 10 |
| 8 | `sstp_ppp_ipv4` | 正 | C=0 PPP IPv4 framing | 12 |
| 9 | `sstp_ppp_ipv6` | 正 | C=0 PPP IPv6 framing | 12 |
| 10 | `sstp_ppp_mppe_boundary` | 正 | MPPE block boundary、密文可见性 | 14 |
| 11 | `sstp_multi_connection` | 正 | 多独立 TLS/TCP/SSTP connections | 24 |
| 12 | `sstp_session_ordering` | 正 | control→connected→PPP→abort 顺序 | 16 |
| 13 | `sstp_length_record_segmentation` | 正 | SSTP Length 跨 TLS record/TCP segment | 18 |
| 14 | `sstp_pcap_nic_consistency` | 正 | PCAP/NIC 方向和 443/TLS 载体一致 | 16 |
| 15 | `sstp_neg_header_length` | 负 | common header 少于 4 bytes、control header 少于 8 bytes 或 Length 不一致 | — |
| 16 | `sstp_neg_attribute_length` | 负 | 属性头字段截断、`LengthPacket` 越界/非法重复、把 Message Type `0x0005`/`0x0006` 当作属性或未知 ID | — |
| 17 | `sstp_neg_state_transition` | 负 | 越序 CONNECTED/PPP/ABORT 后继续 | — |
| 18 | `sstp_neg_transport_carrier` | 负 | 非 TCP/443、无 TLS 或 UDP 载体 | — |
| 19 | `sstp_neg_ppp_framing` | 负 | PPP address/control/protocol/长度错误 | — |
| 20 | `sstp_neg_tls_boundary` | 负 | TLS record/明文 HTTP 冒充 SSTP 或跨连接串流 | — |

## 11. 负例和错误传播契约

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、completed/0 packet 或只剩 TCP/TLS 外壳的假成功。每个负例执行期 `expect` 只能包含 `expect_error`、`error_contains`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `sstp_neg_header_length` | common header 少于 4 bytes、control header 少于 8 bytes 或 Length 与 message 不一致 | `header` 或 `length` |
| `sstp_neg_attribute_length` | 属性头字段截断、`LengthPacket` 小于 4 或越界/回绕、把 Message Type `0x0005`/`0x0006` 当作属性或未知 Attribute ID | `attribute` 或 `length` |
| `sstp_neg_state_transition` | 未 ACK 即 CONNECTED/PPP、ABORT 后继续、跨连接引用 | `state` 或 `sequence` |
| `sstp_neg_transport_carrier` | UDP、错误端口、裸 TCP/HTTP 代替 TLS | `transport` 或 `tls` |
| `sstp_neg_ppp_framing` | PPP `ff 03`/protocol 缺失、IPv4/IPv6 protocol mismatch、长度错误 | `ppp` 或 `framing` |
| `sstp_neg_tls_boundary` | TLS record 截断、明文 SSTP 越过 TLS、跨连接拼接 message | `tls` 或 `boundary` |

合法的 TLS 密文、TLS record 分段、PPP IPv4/IPv6、MPPE block 边界、CALL CONNECT NAK 和空属性控制头（若 message type 允许）由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 12. 实现完成定义和三方检查

1. 注册 `sstp` layer，并严格声明版本、C bit、Length、控制 message type、attribute TLV、PPP framing、TLS carrier 和 `wire_fault`；未知类型/属性、错误载体和越序状态必须拒绝。
2. 逐字节验证 4-byte common header、控制包的 Message Type/Num Attributes、网络序 Length、属性头和 message boundary；Length 不得把 TLS/TCP 头或 segment padding 算入。
3. 独立单测覆盖 CALL CONNECT/ACK/NAK/CONNECTED/ABORT、属性长度、状态转移、PPP IPv4/IPv6、MPPE block boundary、TLS record/TCP segmentation 和多连接隔离。
4. 通过 planner → worker → TLS/TCP output 完整路径验证任务错误传播、方向、包数和关闭；不能只调用 builder 或以 0 包成功替代。
5. 无解密 PCAP/NIC 只断言 TCP/443、TLS records 和方向；明文 SSTP/PPP 字段须由解密 fixture 或实现单测证明，不可由密文 raw bytes 猜测。
6. 本文 §10、`57-sstp-testcase.md` §2、未来注册后的 `sstp.json` 必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计数的 `sstp_neg_unregistered`。
7. 当前未注册阶段只能运行唯一 placeholder，并期待 `unknown layer`；不得把占位计入 20 个语义场景或声称 suite 通过。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 SSTP/HTTPS 正例和 6 个严格负例，覆盖 TLS/TCP/443、4-byte common header/8-byte control fixed portion、control 生命周期、attribute TLV、PPP IPv4/IPv6、MPPE 边界、多连接、分段重组、PCAP/NIC 和错误传播；不修改 Go 实现。
