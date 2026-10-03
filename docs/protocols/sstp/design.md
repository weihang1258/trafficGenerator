# SSTP（安全套接字隧道协议，Secure Socket Tunneling Protocol）设计契约

> 版本：v1.1.2（P1–P6 产物；本次文档路径/版本/旧表述校正）  
> 日期：2026-10-01  
> 状态：P4 层链实现已落地，P5 用例契约已生成并覆盖 22 条（16 正例、6 负例）；本文记录当前实现边界、缺口和验收口径。`cases/sstp.json` 22 条 `spec_json` 已全量迁为纯 `layers` 形（非负例顶层键=0），v1.0.0 §2 的顶层扁平示例已按层链唯一真相改写为纯 layers 形（本版 §2）。  
> 配套文件：`docs/protocols/sstp/testcase.md`、`trafficgen/test/protocol_pcap/cases/sstp.json`  
> 规范基线：MS-SSTP、RFC 1661（PPP，点对点协议）；TLS（传输层安全）边界按 HTTPS 载体处理。

## 1. 范围、证据等级和未注册边界

本设计定义 SSTP over HTTPS（基于 HTTPS 的 SSTP）会话：TCP destination port（目的端口）443，TLS 握手后承载 SSTP control message（控制消息）和 PPP（Point-to-Point Protocol，点对点协议）data frame（数据帧）。覆盖 CALL CONNECT、CALL CONNECTED、CALL ABORT 生命周期、属性 TLV（类型-长度-值）、PPP IPv4/IPv6、MPPE（Microsoft Point-to-Point Encryption，微软点对点加密）边界和多连接隔离。

SSTP 的明文协议语义只在 TLS 解密后的应用数据中可验证。没有解密密钥的 PCAP 只能断言 TCP/443、TLS handshake/record（记录）和方向，不能伪造或声称观察到 SSTP header、attribute 或 PPP 字段。NIC（网卡）捕获还必须说明校验和卸载和 TLS 保密边界。

当前代码已注册 `sstp` layer、planner、validator 和生成器。`cases/sstp.json` 已承载 22 条语义用例（16 正例、6 负例）；负例必须拒绝并传播 task error，不能以 0 包或空 PCAP 冒充 SSTP 通过。

## 2. 推荐配置和层链

推荐层链为 `[ip, tcp, tls, sstp]`（TLS 底座已注册：`internal/core/layers/registry.go:1275`，`Name: "tls"`，Category tunnel，DependsOn `["tcp"]`，FieldContract `tcp.dst_port=443`；本机 `layers.generated.json` 同表）。备用 IPv6 链为 `[ipv6, tcp, tls, sstp]`。层链是实现集成契约，不表示当前注册。地址只住 `ip`/`ipv6` 层（`src`/`dst`），端口只住 `tcp` 层（`src_port`/`dst_port`），数量只走 `flow_control`；顶层只允许 `layers`/`flow_control`/`output`：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.57", "dst": "198.51.100.57"}},
    {"tcp": {"src_port": 45057, "dst_port": 443}},
    {"tls": {"version": "tls1.3", "sni": "sstp.example.test", "role": "client"}},
    {"sstp": {
      "version": 16,
      "events": [{"kind": "call_connect_request", "direction": "c2s"}],
      "ppp": {"protocol": "ipv4", "payload_b64": ""}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 约束 |
|---|---|
| `ip.src`/`ip.dst` | 外层地址；住 `ip`/`ipv6` 层内。正例 server 固定 TEST-NET 段 fixture。 |
| `tcp.src_port`/`tcp.dst_port` | 外层 TCP 四元组；住 `tcp` 层内。正例 destination 固定 443（tls 层 FieldContract），SSTP 不另用 UDP 端口。 |
| `tls`（层内） | HTTPS 载体配置（已注册层，底座依赖）；层内 `version` 只接受 `tls1.3`（链上结构性门：他版本 planner 拒，见接线件注）、`sni`（缺省空，fixture 钉 `sstp.example.test`，上限 253B）、`role` 只接受 `client`。未解密时只验证 TLS record。 |
| `version`（sstp 层内） | SSTP 版本字节；本版正例固定 `0x10`（1.0），其他版本进入负例。 |
| `events`（sstp 层内） | 有序控制消息和 PPP data 事件；状态机必须拒绝越序、跨连接引用和缺失前置消息。 |
| `attributes`（sstp 层内） | 每个属性为 `Reserved(1)+Attribute ID(1)+LengthPacket(16)+Value`；`LengthPacket` 包含 4-byte 属性头，保留线上顺序。 |
| `ppp`（sstp 层内） | PPP framing、protocol、payload；IPv4/IPv6 独立声明，不能由 outer IP 推导。 |
| `mppe`（sstp 层内） | 仅声明加密边界和合法 MPPE payload fixture；密钥不可用时 PCAP 不断言解密后的 IP。 |
| `flow_count`/`connection_id`（sstp 层内 `sessions[]`） | 多连接隔离；每个连接拥有独立 SSTP 状态、PPP 序列和 TLS session；数量只走 `flow_control.flows`。 |
| `wire_fault`（sstp 层内） | 仅负例故障注入口：`header_length`、`attribute_length`、`state`、`carrier`、`ppp_framing`、`tls_boundary`。不是线上字段。 |

**证据等级红线（无解密密钥）**：只能断言 TCP/TLS 载体（四元组、443、`tls.record.content_type`/`tls.record.length`、握手/关闭、application-data 方向与长度）；不得声称看见 SSTP/PPP 明文字段（`sstp.*`/`ppp.*` 一律止于解密 fixture 或实现单测）。本红线在 P1 矩阵（§14 行 4/5）与 D-条目（§17）中点名。

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

实现检查 `tshark -G fields | grep -P '\tsstp\.'` 的字段面；当前正例未解密时仍只断言 `tls.record.*`/TCP 载体。

PCAP 正例必须断言方向、TCP/443、完整 TCP handshake/termination、TLS handshake/application-data records、connection 数量和 event 顺序可从解密 fixture 或实现 trace 证明。NIC 模式必须记录捕获接口和建议过滤器 `tcp port 443`，并明确 checksum offload/TLS 保密限制。若只捕获密文，SSTP/PPP 字段断言转为实现单测，不降低任务成功标准。

## 10. 22 个语义场景和 packet_count 映射

共 22 个唯一语义 ID：16 个正例和 6 个负例；顺序必须与 testcase 及当前 `sstp.json` 完全一致。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `sstp_https_tls_handshake` | 正 | TCP/443、TLS handshake、application-data 载体 | 16 |
| 2 | `sstp_call_connect_request` | 正 | SSTP header、CALL CONNECT REQUEST、Protocol ID | 15 |
| 3 | `sstp_call_connect_ack` | 正 | ACK、Status Info、属性长度 | 16 |
| 4 | `sstp_call_connected` | 正 | CONNECTED 状态和顺序 | 18 |
| 5 | `sstp_call_abort` | 正 | CALL ABORT、reason/status、终止 | 19 |
| 6 | `sstp_attribute_protocol_id` | 正 | PPP Protocol ID TLV | 15 |
| 7 | `sstp_attribute_status_crypto` | 正 | Status Info + Crypto Binding | 17 |
| 8 | `sstp_ppp_ipv4` | 正 | C=0 PPP IPv4 framing | 18 |
| 9 | `sstp_ppp_ipv6` | 正 | C=0 PPP IPv6 framing | 18 |
| 10 | `sstp_ppp_mppe_boundary` | 正 | MPPE block boundary、密文可见性 | 19 |
| 11 | `sstp_multi_connection` | 正 | 多独立 TLS/TCP/SSTP connections | 36 |
| 12 | `sstp_session_ordering` | 正 | control→connected→PPP→abort 顺序 | 40 |
| 13 | `sstp_length_record_segmentation` | 正 | SSTP Length 跨 TLS record/TCP segment | 269 |
| 14 | `sstp_call_connect_nak` | 正 | NAK 拒绝分支、Status Info、sessions[] 形、expect 声明 | 16 |
| 15 | `sstp_group_coalesced_record` | 正 | group 同 record 双 message（一 record 多 message suite 级证据，record.length 64） | 18 |
| 16 | `sstp_pcap_nic_consistency` | 正 | PCAP/NIC 方向和 443/TLS 载体一致 | 16 |
| 17 | `sstp_neg_header_length` | 负 | common header 少于 4 bytes、control header 少于 8 bytes 或 Length 不一致 | — |
| 18 | `sstp_neg_attribute_length` | 负 | 属性头字段截断、`LengthPacket` 越界/非法重复、把 Message Type `0x0005`/`0x0006` 当作属性或未知 ID | — |
| 19 | `sstp_neg_state_transition` | 负 | 越序 CONNECTED/PPP/ABORT 后继续 | — |
| 20 | `sstp_neg_transport_carrier` | 负 | 非 TCP/443、无 TLS 或 UDP 载体 | — |
| 21 | `sstp_neg_ppp_framing` | 负 | PPP address/control/protocol/长度错误 | — |
| 22 | `sstp_neg_tls_boundary` | 负 | TLS record/明文 HTTP 冒充 SSTP 或跨连接串流 | — |

## 11. 负例和错误传播契约

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、completed/0 packet 或只剩 TCP/TLS 外壳的假成功。每个负例执行期 `expect` 必需键严格为 `expect_error`、`error_contains`：

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
6. 本文 §10、`docs/protocols/sstp/testcase.md` §2 与 `sstp.json` 保持同一 22 个语义 ID、同一顺序，16 正例 + 6 负例。
7. 当前可运行路径由已注册层链和 22 条 cases 共同定义；真实 MCP/NIC 套件若未复跑，不以历史占位结果宣称全绿。

## 13. 修订记录

- v1.1.1（2026-09-27）：P6 修轮 m3 文档同步。新增 #15 `sstp_group_coalesced_record` 正例（一 record 多 message suite 级证据：组首 group=2、两条 c2s PPP 同 record、record.length 64、双 `10 00 00 20 ff 03 00 21` frames）；§10 表 21→22 ID（16 正+6 负，NIC→#16、负例→#17–#22）；§14.3 变体表 +组帧合并行（9→10 行）；§14.2/§15/§16/§17/§18 计数与用例号同步（22 ID、#17–#22 负例、#15 group）。
- v1.1.2（2026-10-01）：文档校正（不改 cases/代码）。① 配套路径 `docs/protocol-designs/57-sstp-testcase.md` → `docs/protocols/sstp/testcase.md`（§16 门1 §7 行同改）；② 版本头 v1.1.0→v1.1.2；③ §16 门1 §1 行“占位（旧扁平形）随注册移除”“当前旧扁平形”等旧表述改为既成事实：`sstp.json` 22 条 `spec_json` 已全量迁为纯 `layers`，非负例顶层键=0、正例层链 `[ip,tcp,tls,sstp]`。JSON 无悬浮旧形。
- v1.1.0（2026-09-25）：P1–P3 产物。新增 §14 P1 八项规范矩阵、§15 三路对照与候选方案对比、§16 门1 §1–§14 十四行对照表（含 §1/§3/§12 强制展开与目标形状 spec_json 样例）、§17 D-SSTP-1 P2 代码设计草稿、§18 P3 测试对接清单。修复 §2 示例顶层旧扁平键（`src_ip/src_port/dst_ip/dst_port` 四键迁入 `ip`/`tcp` 层，数量走 `flow_control`；tls 键说明改为层内引用，已注册底座 registry.go:1275）。
- v1.0.0（2026-08-20）：建立 14 个 SSTP/HTTPS 正例和 6 个严格负例，覆盖 TLS/TCP/443、4-byte common header/8-byte control fixed portion、control 生命周期、attribute TLV、PPP IPv4/IPv6、MPPE 边界、多连接、分段重组、PCAP/NIC 和错误传播；不修改 Go 实现。

## 14. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①命令×响应码矩阵（§14.2）②数据形态变体表（§14.3）③商业行为→用例映射表（§15.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。

### 14.1 八项规范矩阵

| # | 规范要求（MS-SSTP/RFC 条款） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：先 TCP 建连→TLS 握手→SSTP over HTTPS（443）；单 TCP/TLS 连接承载控制+PPP 数据，无独立数据通道；谁主动：client 先发 CALL CONNECT REQUEST（MS-SSTP §1.3/§2.1；本契约 §5/§6） | 企业远程接入 VPN 拨号；Windows 客户端经 443 出站穿透防火墙 | 已实现层链 `[ip, tcp, tls, sstp]`、声明式生成器与 carrier 预检；22 条 JSON 用例已按目标形状落盘 | 服务端主动 DISCONNECT/中途 abort 与代理/IPv6 现网 fixture 仍见 G-SSTP-1/2/3 |
| 2 | 命令消息表：9 种控制消息 REQUEST 0x0001/ACK 0x0002/NAK 0x0003/CONNECTED 0x0004/ABORT 0x0005/DISCONNECT 0x0006/DISCONNECT ACK 0x0007/ECHO REQUEST 0x0008/ECHO RESPONSE 0x0009，每条带 4-byte common header + Message Type/Num Attributes + 有序 attributes（MS-SSTP §2.2；本契约 §3/§4） | 拨号建立/拒绝/确认/保活/异常终止/优雅断开全生命周期 | header/attribute builder 与 9 类控制消息已实现；请求、ACK、NAK、CONNECTED、ABORT、ECHO 已由 JSON/单测覆盖 | DISCONNECT 对仍属 G-SSTP-1 |
| 3 | 状态机：TLS established→REQUEST→ACK/NAK→CONNECTED→PPP data→ABORT（可选终止）/DISCONNECT（优雅）→TLS/TCP close；NAK 后禁 CONNECTED/PPP；ABORT 后禁一切（MS-SSTP §3.2/§3.3；本契约 §6） | 拨号成功上网；服务端拒接（证书/策略）；客户端挂断；保活超时断线 | `sstpWalker` 单权威状态机已实现，NAK/ABORT/越序/跨连接/expect 不一致均传播 task error；JSON 负例覆盖关键拒绝路径 | 服务端主动 DISCONNECT/FIN/RST 形态登记 G-SSTP-1 |
| 4 | 字段表：Version 1B（0x10）/Reserved7+C1B/Reserved4+Length12（2B 网络序，覆盖整 SSTP packet）/Attribute ID 1B（0x01–0x04）/LengthPacket 2B（含 4B 属性头）/Status 变长/Crypto Binding（SHA-256 总 0x0068）/Binding Request（0x0028+32B nonce）/PPP ff 03+protocol 00 21/00 57（MS-SSTP §2.2；RFC 1661；本契约 §3/§4/§7）。**证据红线：无解密密钥时只能断言 TCP/TLS 载体，不得声称看见 SSTP/PPP 明文** | 跨厂商互操作（Windows Server RRAS）；MPPE 加密边界对齐 | Version/C/Length、4 种属性、PPP 双族、MPPE 分界与状态双关已在 builder/planner 落地 | Crypto Binding 的服务端真实密码学验证仍走 opaque fixture，缺口登记 G-SSTP-1 |
| 5 | 错误处理：未知 Message Type 拒；未知 Attribute ID 拒；Length 越界/回绕拒；Status 错拒；越序 CONNECTED/PPP 拒；ABORT 后续发拒；跨连接引用拒；UDP/错端口/裸 TCP/明文 HTTP/未完成 TLS 拒；PPP framing 错拒；TLS record 截断/跨连接拼接拒（MS-SSTP §3.3；本契约 §11） | 弱网损坏包；错误配置端口；攻击面畸形包；代理误配明文 | 6 类错误分支均已落地：注入拒、自然守卫、carrier 预检；对应 6 条负例已在 JSON 中声明锚词 | 未知 Type 的拒绝锚词归入 header/length 行；后续可按需拆分 |
| 6 | 超时活性：ECHO REQUEST/RESPONSE 保活（hello timer）；空闲超时断开；CALL ABORT/DISCONNECT 终止后 TLS/TCP close；重连=新 TLS/TCP connection（MS-SSTP §3.2.4/§3.4 ECHO；本契约 §6） | 长时间 VPN 在线保活；NAT 会话超时续活；断线重拨 | ECHO 请求/响应、关闭后 flows=2 重连和 TCP/TLS close 已由 `sstp_session_ordering` 覆盖 | hello timer 数值与空闲超时的真实时序留待 G-SSTP-2/后续 fixture |
| 7 | NAT/代理：SSTP 设计目标即穿透——经 HTTPS 代理（CONNECT 隧道或明文转发）出站 443；NAT 只见 TCP/443 流；无被动端口通告（与 FTP 对比：零派生端口）（MS-SSTP §1.5；本契约 §5） | 酒店/企业网经代理拨 VPN；家用 NAT 后拨号 | 无 | 正例覆盖：代理 CONNECT 隧道形一例或立项（G-SSTP-3）；直连形为主（#1/#16）；裸 TCP/UDP 面为负例（#20），不做载体 |
| 8 | 版本方言：SSTP v1.0（Version 0x10）唯一版本；PPP 协议族 RFC 1661/1662（IPv4 0x0021/IPv6 0x0057）；MPPE（RFC 3078/MS-MPPE）加密边界；Crypto Binding hash protocol bitmask（SHA-256 profile）；Windows 客户端 dial 参考行为（MS-SSTP §1.7/§2.2.5） | Win10/11 内置 VPN 客户端互通；MPPE 128-bit 加密拨号 | v1.0、PPP 双族、MPPE 16/20B 边界和 Crypto Binding fixture 已实现；版本/属性/PPP 负例有错误锚词 | 他版本、真实 Windows 方言及密码学验证仍需 G-SSTP-1/2 |

### 14.2 子表①：命令×响应码矩阵（逐格已覆/缺失）

| 控制面 \ 对端响应 | ACK 0x0002 | NAK 0x0003 | CONNECTED 0x0004 | ABORT 0x0005 | DISCONNECT 0x0006/ACK 0x0007 | ECHO REQ/RSP 0x0008/0x0009 |
|---|---|---|---|---|---|---|
| REQUEST 0x0001 | 已覆 #2→#3 | 已覆 #14（sessions[] 形 NAK 正例；正例语义） | 已覆 #4（仅 ACK 后） | 已覆 #5 | 缺口 B′：优雅 DISCONNECT 对→G-SSTP-1（服务端主动面） | 不适用（保活只在 CONNECTED 后） |
| CONNECTED 后 PPP data | 不适用 | 不适用 | 已覆 #8/#9（C=0 data） | 已覆 #5（任一方向 ABORT） | G-SSTP-1（同上） | 已覆 #12（保活数据同连接） |
| ABORT 后 | 不适用 | 不适用 | 负例 #19（ABORT 后续发拒） | 已覆 #5（终止语义） | G-SSTP-1 | 负例 #19 |
| 非法 Message Type/越序 | 负例 #17（未知 Type 走 header/length 拒） | 负例 #17/#18（NAK 形非法走同门；0x0005/0x0006 冒充属性走 #18） | 负例 #19（未 ACK 即 CONNECTED/PPP） | 负例 #19 | G-SSTP-1 | 负例 #19 |

注：24 格=已覆 15 格（正例 8 + 负例 7）+ B′ 4 格（DISCONNECT 对服务端主动面×4→G-SSTP-1）+ 不适用 5 格（保活只在 CONNECTED 后×1、data 行 ACK/NAK 不适用×2、ABORT 后 ACK 不适用×2）。NAK 格证据已由“#12 内分支”（失实，P6 终审 M2）换为独立 #14 正例。客户端 ABORT 面 3 格已覆（#5+#19）。

### 14.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 地址族×载体 | IPv4/TCP443+TLS、IPv6/TCP443+TLS | #1/#16（IPv4 主；IPv6 形态 P4 fixture 加注，见 G-SSTP-2） | SSTP 无 UDP 面（#20 负例）；IPv6 对称见 §9.24 |
| 控制 header | 无属性 Length=8/C=1 8B 固定部/Version 非 0x10 | #2 + 负例 #17 | Length 覆盖整包，不含 TLS/TCP |
| Message Type | 9 种全枚举（0x0001–0x0009） | #2/#3/#4/#5/#12/#14 + 负例 #18/#19 | 0x0005/0x0006 非属性 ID |
| Attribute | 0x01（Len 6/Val 0001）/0x02 变长/0x03（总 0x0068）/0x04（总 0x0028+32B nonce）/多属性顺序/空属性头 | #6/#7 + 负例 #18 | Num Attributes 与实数一致 |
| PPP framing | ff 03+0021/IPv4、ff 03+0057/IPv6、压缩形（声明才用） | #8/#9 + 负例 #21 | 不由 outer IP 推导 |
| MPPE | block 对齐恰好/跨 boundary/密文 opaque | #10 | 无密钥不识别 IPv4/IPv6 |
| TLS record | 单 record 单 message/多 records 一 message/一 record 多 message/跨 TCP segment | #13/#15 | record/segment 边界≠message 边界 |
| 组帧合并 | group=2 组首声明/同组同方向合一条 record/跨方向拒/组未凑满拒 | #15 | 组首写 group，成员不得自带；跨方向合并走链级 (boundary) 拒；组内第二条边界由实现单测复算（chain_test `group_merges_same_direction` 同构） |
| 会话 | 单连接/双连接并行/保活+重连新连接 | #11/#12 | 跨连接不串流 |
| 长度边界 | Length=8 最小/属性总 6 最小/最大附近/零长 PPP information（profile 允许时） | #13/#15 + 负例 #17 | 显式 0 不被缺省覆盖 |

## 15. 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

### 15.1 三路对照

①规范原文：MS-SSTP（控制消息 §2.2：common header/Message Type/Num Attributes/4 属性；状态机 §3.2/§3.3；ECHO 保活 §3.2.4/§3.4；Crypto Binding §2.2.5）、RFC 1661/1662（PPP ff 03 framing、protocol 0x0021/0x0057）、RFC 3078（MPPE block 边界语义）、TLS 载体按 HTTPS（tcp 443 + tls 层 FieldContract）。
②现网行为：Windows 内置 SSTP 客户端（Win10/11 “VPN→SSTP”拨号：TCP 443→TLS 握手→HTTPS POST/长连接内 SSTP 控制；抓包形态=443 上双向 TLS application-data，无独立 UDP 流）+ Windows Server RRAS（服务端 ACK/NAK/CONNECTED 应答序列）——出处确认方式：P4 前在隔离环境抓 Windows 客户端→测试 RRAS 回环包核对 REQUEST→ACK→CONNECTED→PPP→ABORT 事件序与 Length（立项 G-SSTP-2）。
③开源实现思路：wireshark `packet-sstp.c`（本机 tshark 20 个 `sstp.*` 字段已实证：majorversion/minorversion/iscontrol/length/messagetype/numattrib/attribid/attriblength/encapsulatedprotocol/status/nonce/cert_hash/compoundmac 等，字段语义借鉴不搬码）+ `tls.record.*`（302 字段：content_type/length/app_data）+ `ppp.*`（16 字段：address/control/protocol）解析行为借鉴。

三路结论一致：443+TLS application-data 承载 + C bit 分 control/data + Length 整包覆盖 + PPP ff 03 明文面 + MPPE 只改 information 表示；取舍：HTTPS 内层究竟 HTTP 长轮询还是裸 TLS stream 属实现细节，本契约两者皆容（#13 分段面覆盖），不断言某一种为唯一真形；UDP/裸 TCP 不做载体（三路均无此形态→负例）。

### 15.2 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品+版本+出处） | 用例编号 | 无映射项+确认方式 |
|---|---|---|
| Windows 10/11 内置客户端拨号建立（REQUEST→ACK→CONNECTED→PPP） | #2/#3/#4/#8（控制+PPP 面） | — |
| 服务端 NAK 拒绝（证书/策略不合） | #14（sessions[] 形独立正例） | 服务端主动 NAK 码面细化→G-SSTP-1（查 MS-SSTP §3.3 + 抓包） |
| 客户端 ABORT 挂断（任一方向） | #5/#19 | — |
| ECHO 保活长连接（hello timer） | #12（含保活事务） | hello 间隔值→P4 fixture 定（查 MS-SSTP §3.2.4） |
| MPPE 加密拨号（128-bit） | #10 | 密钥协商内层→opaque，不做明文例 |
| 代理/CONNECT 隧道后拨号 | 缺口→G-SSTP-3（查 MS-SSTP §1.5 + 代理抓包） | 待确认，见缺口立项 |
| IPv6 网络拨号 | G-SSTP-2 内 IPv6 fixture | 待 P4 fixture 加注 |

### 15.3 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | header/attributes/PPP 外层结构化 + MPPE/证书指纹 opaque fixture（kerberos #44 D-KERBEROS-1 同族：EncryptedData 外壳结构化+内层 opaque） | 与已收官族同构（接线/builder/planner/casegen 可复用范式）；无密钥不伪造密码学语义 | 服务端主动语义需 B′ 立项 | O(n) 流式渲染；复杂度低；兼容 IPv4/IPv6 双族 | **采用** |
| B 完整 PPP/MPPE 协议栈仿真 | 内核 PPP 状态机全仿（借鉴 pppd 思路） | 语义最真 | 超 fixture 范围；MPPE 内层本就不可断言；引入状态机复杂度 | 复杂度高；性能无 Fixture 优势 | 不选 |
| C 生 hex 回放 | 整 SSTP message body hex 覆盖 | 最简单 | 字段不可结构化断言；动态面全失；Length 即死 | 动态零分 | 仅作负例/特殊形逃生口，不做主方案 |

## 16. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §16.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 四键迁入 `ip`/`tcp` 层；顶层 `tls`/`sstp` 子映射迁入 `layers[]` 对应条目；数量走 `flow_control`；目标形状 spec_json 样例见 §16.1；非负例顶层键=0（presence 负例见 §16-P2） | 本契约 §2（目标形状）+ §16.1 样例；`cases/sstp.json` 22 条 `spec_json` 已全量迁为纯 `layers`（正例 `[ip,tcp,tls,sstp]`，非负例顶层键=0） |
| §2 策略/任务 | 策略=单 SSTP 流量模板（自带 flow_control flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §1/§17 |
| §3 五件套 | 见 §16.3 强制展开：CALL CONNECT→CONNECTED→ABORT 会话表/事务序列/关联/插入位置/时间线，PPP 数据帧与控制消息分开；单 TLS 连接多事务在例 | 本契约 §16.3 + 用例 #12 |
| §4 查规范 | MS-SSTP + RFC 1661/1662 + RFC 3078 + 现网（Windows 客户端/RRAS）+ tshark sstp 20/tls 302/ppp 16 字段；P1 矩阵 8 行+三子表 | 本契约 §14/§15 |
| §5 依赖与错误 | DependsOn tls（已注册 registry.go:1275）；wire_fault 6 值=§2 键表逐字（header_length/attribute_length/state/carrier/ppp_framing/tls_boundary）+自然守卫；失败返回 task error（零假成功） | 本契约 §2/§11 + §17 错误分支 |
| §6 性能 | 声明式回放族：O(n) 流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（诚实待确认，不写承诺数字）；六类场景清单见 §17 | §17 性能设计与验收 |
| §7 三份文档 | docs/protocols/sstp/{design,testcase}.md v1.1.2（ID 权威=testcase §2）+ D-SSTP-1（本契约 §17 草稿，门1 获批=定稿）+ T-SSTP（testcase §9 草稿）+ generated schema（P4 重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批= D-SSTP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=MS-SSTP/RFC 条款+D-SSTP-1+tshark sstp.*/tls.*/ppp.* 字段（20/302/16 已实证）+现网 Windows 行为；22 ID 正负对账；三源回指行见 testcase §9 | T-SSTP（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+收官隔离复审+修轮；红先绿后 | /tmp/pipe/48-sstp/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §16.12 强制展开：四元组=ip/tcp 层（五策略全支持）；业务字段逐个列开/不开+理由；业务字段动态面本版明确不解决+迁入计划（P6 修轮） | 本契约 §16.12 |
| §13 schema 派生 | registry sstp 行（DependsOn ["tls"]/FieldContract 继承 443）→ schemagen 重跑；struct 标签字面量锁 | §17 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `sstp.*`（20 字段）+ `tls.record.*` + frames hex 三通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/sstp/` | 用例 §1/§6 |

### 16.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip/dst_ip/src_port/dst_port/count` + 本协议顶层子映射 `tls`/`sstp`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[i].ip.src`（`192.0.2.57`） |
| `dst_ip` | → `layers[i].ip.dst`（`198.51.100.57`） |
| `src_port` | → `layers[i].tcp.src_port`（`45057`） |
| `dst_port` | → `layers[i].tcp.dst_port`（`443`，tls 层 FieldContract） |
| `count`（若有） | → 删除，走 `flow_control.flows` |
| 顶层 `tls` 子映射 | → `layers[]` 中 `{"tls": {...}}` 条目（version/sni/role 全量迁入，零残留） |
| 顶层 `sstp` 子映射 | → `layers[]` 中 `{"sstp": {...}}` 条目（version/events/attributes/ppp/mppe/sessions 全量迁入，零残留） |

完整 CALL CONNECT 样例（目标形状，顶层键仅 `layers`+`flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.57", "dst": "198.51.100.57"}},
    {"tcp": {"src_port": 45057, "dst_port": 443}},
    {"tls": {"version": "tls1.3", "sni": "sstp.example.test", "role": "client"}},
    {"sstp": {"version": 16, "events": [{"kind": "call_connect_request", "direction": "c2s", "attributes": [{"id": 1, "value_b64": "AAE="}]}], "sessions": [{"id": "s1", "transactions": [{"id": "t1", "kind": "call_connect", "expect": "ack"}]}]}}
  ],
  "flow_control": {"flows": 1}
}
```

### 16.3 §3 强制展开：五件套（CALL CONNECT→CONNECTED→ABORT，PPP 数据帧与控制消息分开）

会话表（单 TLS 连接多事务；多连接隔离见 #11）：

| 会话 | 四元组 | 生命周期 |
|---|---|---|
| s1 | ip.src/dst + tcp.45057→443（TLS session 独立） | TLS established→REQUEST→ACK→CONNECTED→PPP data→可选 ABORT→TLS/TCP close |
| s2（#11 并行） | 同 s1 族，独立 src_port + 独立 TLS session | 同 s1，状态/PPP 序列/TLS session 全隔离 |
| s3（#12 重连） | 新 TCP/TLS connection | 旧连接 close 后新连接重走 REQUEST 起 |

事务序列（单事务四件事 §3.4–3.7；控制消息与 PPP 数据帧分开两类事务）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 REQUEST | s1 TLS established | client 发 CALL CONNECT REQUEST（C=1，Type 0x0001，Encapsulated Protocol ID 属性） | server 回 ACK→t2；NAK→拒绝分支（禁 CONNECTED/PPP，见 #14） | TLS 未建好/载体错→carrier 负例；header 非法→task error |
| t2 ACK | t1 已发 | server 发 CALL CONNECT ACK（Type 0x0002 + Status Info） | →t3 CONNECTED | NAK→中断会话+禁后续（#14 独立正例语义）；属性错→attribute 负例 |
| t3 CONNECTED | t2 ACK | client 发 CALL CONNECTED（Type 0x0004） | →t4 PPP data 许可 | 越序（未 ACK）→state 负例 #19 |
| t4 PPP data（C=0 帧） | t3 完成 | 任一方向发 C=0 data（ff 03 + 0021/IPv4 或 0057/IPv6；MPPE 形走 #10） | 继续 data 或 t5 保活/终止 | ABORT 后续发→#19；framing 错→#21 |
| t5 保活/终止 | t4 进行中 | ECHO REQ/RSP 保活；任一方向 ABORT（Type 0x0005 + Status）→close | ABORT 后连接关闭，无后续 | ABORT 后续发→#19；DISCONNECT 优雅面对→G-SSTP-1 |

关联关系：控制事务经 SSTP 会话状态机关联（三件事 §3.9：归属会话 sN、归属事务 tM、由 Message Type + 会话状态双字段决定）；PPP 数据帧归属由“CONNECTED 已完成”门限决定（无独立 `driven_by` 派生流——单通道协议，与 CWMP 范本差异点诚实声明：控制与数据共享同一 TLS 连接，无副流 ID）。
插入位置：终结层——控制/data 经 tls 层 application-data 透传（SSTP message 按 Length 切分，多 messages 可同 record，单 message 可跨 records；接收端按 Length 重组）。
时间线：顺序（t1→t2→t3→t4→t5 同连接串行；s1/s2 会话间并发交错，多会话输出不假设全局包序，只断言流内状态；重连 s3 在旧 close 之后）。

### 16.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 四元组必备；多流并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（多地址待 P4 立项） | responder 地址 fixture 钉死；多目标另立项 |
| `src_port` | tcp 层 | 全开 + 未写动态保底 `12345+i` | §12.2/§2.8 |
| `dst_port` | tcp 层 | fixed（443 fixture） | tls 层 FieldContract 约束；动态端口例顶层 `decode_as` 另议 |
| `version`（SSTP） | sstp 层 | 不开（fixture 钉 0x10） | 单版本协议；他版本面走负例 #17 |
| `events[].kind` | sstp 层 | list（9 种 Type 轮转） | 命令全覆盖；序号算法位置待 P4 定 |
| `attributes[].id` | sstp 层 | list（0x01–0x04 轮转） | 属性全覆盖；未知 ID 走负例 #17 |
| `nonce`（Crypto Binding） | sstp 层 | rand（seed+序号可复现）/fixed fixture | 请求/响应关联，会话间 distinct；算法位置待 P4 定 |
| `status`（Status Info） | sstp 层 | list（成功/拒绝码枚举轮转） | 状态码全覆盖；服务端主动面走 G-SSTP-1 |
| `ppp.protocol` | sstp 层 | list（ipv4/ipv6） | 地址族对称；与其余策略组合 P4 定 |
| `ppp.payload` | sstp 层 | pattern/inc（按流递增） | 多流 payload 区分；rand 可复现面 P4 定 |

序号算法代码位置：本版明确不解决（业务字段动态面未落码：实现全标量字段，零动态测试——P6 终审 m4）。迁入计划：D-SSTP-1 修订时按 `events[].kind`/`status`/`nonce` 逐字段落地 list/rand 策略 + 序号算法文件行号，届时本行回填；此处不编行号——§5.7。

### 16-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[...],"sstp":{}}`（顶层空 `sstp:{}` 与层链并存）必须 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`）判死负例见 §17。

## 17. D-SSTP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。tls 层作为底座依赖必须声明；PPP 帧与 MPPE 加密边界点名。

**文件清单（新建 5 + 接线 9）**：

| 文件 | 职责 |
|---|---|
| internal/core/sstp.go（NEW） | SSTPConfig/Session/Transaction/SSTPEvent/AttributeEntry/PPPEntry 结构 + 严格 UnmarshalJSON（递归 DisallowUnknownFields）+ 6 wire_fault 常量与 DescribeSSTPWireFault 锚词表 |
| internal/protocol/sstp/header.go（NEW） | header/attribute 编码原语：Version 0x10 恒定、C bit、Reserved4+Length12 网络序（覆盖整包恒定）、Message Type 9 枚举、Attribute ID 0x01–0x04、LengthPacket 含 4B 头恒定；**PPP 帧边界**：C=0 时 S+4 即 `ff 03`；**MPPE 边界**：只改 information 表示，不改 Length/protocol 语义 |
| internal/protocol/sstp/builder.go（NEW） | 控制/data builder（REQUEST/ACK/NAK/CONNECTED/ABORT/DISCONNECT 对/ECHO 对 + C=0 PPP 组帧）+ 经 tls 层 application-data 透传分帧（多 messages 同 record/单 message 跨 records 按 Length 切分）+ sstpWalker 会话状态单权威 + init() 注册 generator/validator |
| internal/protocol/sstp/planner.go（NEW） | validateSpec/validateSession（walk renderEvent 同路径单权威）+ validateWireFault + C bit↔Message Type 一致性守卫 + Length↔attributes/PPP 一致性守卫 + Num Attributes↔实数守卫 + presence/白名单预检 |
| internal/protocol/sstp/casegen_test.go（NEW） | 一次性生成器：22 例（16 正+6 负）契约计数逐例 add()，落 test/protocol_pcap/cases/sstp.json |
| 接线件 | types.go `SSTP *SSTPConfig`；FlowMeta.SSTP；translate `case "sstp"` + Meta 直传；strategy_convert `case "sstp"` + setDefaultDstPort 443；registry 行 DependsOn ["tls"]，FieldContract 继承 tcp.dst_port=443；validate_layers 预检（缺 tls 载体/裸 tcp+tls 并存拒/混合地址族拒/顶层旧键拒）；main.go 空白导入 + NewChainPlanner("sstp")；protocols.go 白名单 + protocols_test 同步（"sstp" 已在列 protocols_test.go:105）；schemagen 重跑。**链上结构性门（chain_planner.go:416–435 P2e T13）**：tls 层 `version` 只 `tls1.3`、`role` 只 `client`、SNI ≤253B，他值 planner 直接拒——D-SSTP-1 fixture 必须用 `tls1.3/client`，他版本走负例前先过此门 |
| tools/coverage_gate.py | check_sstp（准入接线/关键件/守卫/用例面四段） |

**接口签名**（示意，P4 落码钉死）：`GenerateSSTPControl(cfg) []byte` / `GenerateSSTPPPData(cfg) []byte` / `ValidateSSTPSpec(spec) error` / `DescribeSSTPWireFault(fault string) string`。
**数据结构**：Session{id, tls_session, transactions[]}；Transaction{id, kind, attributes[], ppp}；AttributeEntry{id, value}；PPPEntry{protocol, payload}。
**主流程**：validateSpec→逐会话 walker→逐事务 render（control 按 C=1 组帧 / PPP 按 C=0 组帧→tls application-data 透传→Length 切分）→EmitMsg→worker→pcap/NIC。
**错误分支（§5.2）**：①wire_fault 6 值注入拒（锚词进断言）；②自然守卫：C bit↔Type 不一致/Length↔内容不一致/Num↔实数不一致/未知 Type 或 Attribute/越序/跨连接引用/顶层旧键-presence 并存；③validate_layers 预检：缺 tls 载体、UDP/裸 TCP/错端口、混合地址族。全部传播为 task error，零假成功。**证据红线**：无密钥 PCAP 只走 carrier 断言分支（D-条目点名）。
**依赖声明（§5.1）**：依赖 `tls` 层（已注册 registry.go:1275：握手/application-data record 语义、version/sni/role）+ `tcp` 443（FieldContract）+ PPP framing 权威（RFC 1661）+ MPPE 边界权威（RFC 3078）；无外部密钥/证书依赖（opaque 面）。
**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事务渲染直发 EmitMsg 无全量聚合；确定性内存（无按包增长结构）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路注记（过滤器 `tcp port 443`）；回归口径=sstp.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。
**回滚方式（§8.8）**：全量 revert 新建文件 + 接线件回退（git revert 提交序）；registry/schemagen 生成文件随提交对齐回退；无数据迁移面。

## 18. P3 测试对接清单（T-SSTP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接多轮操作→#12 session_ordering 多事务+保活（已覆）；②非正常结束→NAK 拒绝分支（#14 独立正例）+ABORT 终止（#5；服务端主动 abort 面→G-SSTP-1）；③长保活→#12 ECHO 保活+重连（已覆）。逐项一例或立项，无空项。
- A′/B′ 两分类表：见 testcase §9（A′=引擎可构建→22 ID 内已覆；B′=引擎结构缺口→G-SSTP-1/2/3 进 D-条目“明确不解决+迁入计划”）。
- 9.52 对账两行：见 testcase §9（规范逻辑点总数 vs 用例覆盖数 + 清单出处声明）。
- 3.14 豁免边界审计：见 testcase §9（sessions[] 豁免≠多流豁免：多流并发 #11 + 单包多载荷批量属性 #6/#7 各一例，无豁免逃逸）。
- 三源回指行：见 testcase §9。
- 断言通道：fields 用 `sstp.*`（20 字段已实证：messagetype/numattrib/attribid/attriblength/encapsulatedprotocol/status/nonce/cert_hash/compoundmac 等，解密 fixture 方可用）+ 载体 `tls.record.*`（302 字段：content_type/length/app_data）+ `ppp.*`（16 字段，解密 fixture 方可用）；header/Length 走 frames hex 钉；动态 nonce/binding/证书指纹用 presence/nonzero/distinct/same_as。**无密钥时 sstp.*/ppp.* 不得用于密文断言（红线）**。

## 19. 缺口立项清单（有缺口写“缺口立项”，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-SSTP-1 | 服务端主动语义：DISCONNECT 对（0x0006/0x0007）服务端主动面、服务端 mid-transaction abort（FIN/RST）、NAK 细化码面 | 查 MS-SSTP §3.3 + 抓 Windows RRAS 过载/拒绝行为包 | B′→D-SSTP-1“明确不解决+迁入计划”（P4 fixture 可构建性待定） |
| G-SSTP-2 | 现网抓包核对：Windows 客户端→RRAS 回环 REQUEST→ACK→CONNECTED→PPP→ABORT 事件序与 Length + IPv6 fixture 加注 | 抓回环包（问谁：无，抓包即确认） | P4 前置确认项，不挡开工 |
| G-SSTP-3 | 代理 CONNECT 隧道形 fixture（企业网经代理拨号） | 查 MS-SSTP §1.5 + 代理抓包 | B′→D-SSTP-1 迁入计划 |

## 20. 层链迁移设计审计（D1-D8，2026-09-30）

| 项 | 定稿结论 | 证据 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`；端口只住 `layers[].tcp`；数量只住用例兄弟 `strategy_fc`/策略 `flow_control`；正例顶层无旧 flat 键 | `sstp.json` 22 条 `spec_json` 全量机读核对 |
| D2 | SSTP 是 TLS 终结层，标准链固定为 `[ip,tcp,tls,sstp]`；业务字段住同名 `sstp` 层 | `registry.go`/`chain_planner_translate.go` 已接线；正例层链审计 |
| D3 | 外层 TCP/443 与 TLS carrier 由 `ip`、`tcp`、`tls` 层表达；SSTP 不伪造 UDP 或第二传输层 | `resolveCarrier` 与 carrier 负例 |
| D4 | `events`/`sessions` 是 SSTP 层业务编排；多流由 `strategy_fc` 驱动；不从顶层 `count` 推导 | `sstp_multi_connection`、`sstp_session_ordering` |
| D5 | 顶层 `sstp` 只可作为 presence 判死负例，不作为正例配置入口；正例业务全部在终结层 | 全量正例顶层键集合均为 `layers`（负例故意错误形保留） |
| D6 | `strategy_fc` 是 cases 驱动字段，不属于 `spec_json`；`group`/`chunk` 仅作消息编排与记录边界 | `sstp_group_coalesced_record`、`sstp_length_record_segmentation` |
| D7 | 6 条负例保留故意错误输入和锚词，不清洗成正例 | §11 与 JSON 负例逐条对应 |
| D8 | 服务端主动 DISCONNECT、真实 Windows/RRAS、代理 CONNECT 和真实吞吐基准均登记缺口；不伪造支持或实测 | G-SSTP-1…G-SSTP-3；§17 性能说明 |

D1–D7 为当前文档/机器契约事实；D8 明确区分已实现生成器与尚未确认的现网/性能边界。
