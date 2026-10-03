# STUN（NAT 穿越会话工具，Session Traversal Utilities for NAT）设计契约

> 版本：v1.1.0（2026-09-30）
> 范围：D1–D8 设计核对；本轮只迁移文档与 cases 层链，不改 Go 实现。
> 当前状态：`stun` layer、planner 和 generator 尚未注册；本文是目标契约，不宣称 suite 已通过。

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；不修改 Go（编程语言）实现，不宣称 `stun` 层已注册或 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/44-stun-testcase.md`、`docs/protocol-designs/audit/44-stun-adversarial-audit.md`、`trafficgen/test/protocol_pcap/cases/stun.json`
> 规范基线：RFC 5389、RFC 8489；TURN（中继穿透，Traversal Using Relays around NAT）边界参考 RFC 5766、RFC 5780。

## 1. 范围、证据等级和载体边界

本设计只定义 STUN Binding（绑定）事务和其认证/诊断属性。Binding 是 RFC 5389/8489 的基础事务，不能把 STUN 识别成任意 UDP payload（载荷）。正例覆盖：

- UDP/IPv4、UDP/IPv6：通常端口 3478；
- TCP/IPv4：RFC 5389 TCP framing（帧长由 STUN Message Length（消息长度）确定），通常端口 3478；
- TLS over TCP（基于 TCP 的传输层安全）：通常端口 5349。TLS 记录的应用数据是加密的，未提供解密密钥时只能断言 TCP/TLS 载体和记录头，不能伪造或声称看见其中的 STUN header（头部）/attribute（属性）字段。

这是设计阶段机器契约，不是当前实现状态。`stun` 未注册时，运行结果只能记录为 rejected/not runnable（拒绝/不可运行），不能报告 suite 通过。所有错误必须在 planner（规划器）/validator（校验器）/task（任务）终态传播，不能输出 0 包却报告成功。

本版使用两个明确的配置 profile（档案）：

| profile | 含义 |
|---|---|
| `rfc5389_binding` | RFC 5389 基础 Binding request/success/error；属性使用 RFC 5389 名称和编码 |
| `rfc8489_binding` | RFC 8489 兼容 Binding；沿用本版已定义的 RFC 5389 属性，并明确新认证扩展的实现边界 |

RFC 8489 对 STUN 头和 Binding 方法的基本线格式没有改变；它补充了现代认证/算法规则。若实现尚未提供 MESSAGE-INTEGRITY-SHA256、USERHASH 或 PASSWORD-ALGORITHM 的完整字段表，不得把这些字段猜成 HMAC-SHA1 或加入正例；当前四件套只对明确注册且可复核的 `MESSAGE-INTEGRITY`（HMAC-SHA1）和 `FINGERPRINT` 做契约。

## 2. Wire（线上）不变式和配置

推荐配置外形如下；`events` 是有序事务事件，事件中每个动态值在一个事务内保持一致。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"udp": {"src_port": 40000, "dst_port": 3478}},
    {"stun": {
      "profile": "rfc5389_binding",
      "method": "binding",
      "events": [{"kind": "request", "direction": "c2s"}]
    }}
  ]
}
```

顶层只保留 `layers`、`flow_control`、策略框架字段和 `output`；地址、端口和 STUN 业务配置均在对应层内。

| 配置键 | 约束和语义 |
|---|---|
| `profile` | `rfc5389_binding` 或 `rfc8489_binding`；不是线上的字段 |
| `method` | 本版正例固定 `binding`；`allocate`、`refresh`、`send`、`data`、`connect`、`connection-bind` 属于 TURN 边界，不能静默当作 Binding |
| `events` | 有序 `request`、`success`、`error` 事件；`direction` 为 `c2s`/`s2c`；同一事务的 transaction ID（事务标识）必须相同 |
| `transaction_id` | 可选显式 96-bit 值，仅用于可复现 fixture（固定样本）；缺省时随机生成，不得在 JSON 断言中写固定动态值 |
| `attributes` | 仅放本节注册的属性；属性顺序保留，长度按编码结果计算 |
| `retransmit` | 同一 request 的再次发送必须完整复制 type、属性、长度、cookie 和 transaction ID；不得将重传伪装成新事务 |
| `wire_fault` | 仅负例的故障注入入口：`header_short`、`type_reserved_bits`、`length_alignment`、`length_overrun`、`cookie`、`attribute_length`、`integrity`、`transport`、`turn_boundary` |
| `mapped_address` | 仅 response fixture 的测试输入；地址可为 IPv4 或 IPv6，不从本地 IP 猜测公网映射 |
| `integrity` | `key`/认证配置是测试输入；HMAC 和 CRC 值由实现计算，不在 JSON 固化 |

不变式：

1. STUN message type 的低两位必须为 0；其余 type bits 按 RFC 5389 的 method/class 交错编码，不能直接把“method + class”拼成未编码整数。Binding request/success/error 的常用值分别为 `0x0001`、`0x0101`、`0x0111`。
2. Header 固定 20 字节：`Message Type(2) | Message Length(2) | Magic Cookie(4) | Transaction ID(12)`。所有整数网络字节序；Message Length 只计算 attributes，不含 20-byte header，且必须是 4 的倍数。
3. Magic Cookie 固定为 `0x2112A442`，位于 header offset（偏移）4；transaction ID 是 12 个字节，不能从 IP、端口、时间戳或 cookie 推导。
4. Header 的 Message Length 必须等于所有属性（含每个属性的 4-byte header、value 和 32-bit padding）的编码长度。属性 value 的 padding 不计入 Attribute Length，但计入 Message Length。
5. request/success/error 的 class（类别）和 method（方法）必须与 `stun.type.class`/`stun.type.method` 一致；未知或保留 type bits 必须拒绝。
6. UDP 每个 datagram（数据报）是一个完整 STUN message；TCP 以 STUN Message Length 推导消息边界，不把 TCP segment（分段）边界当作 STUN 边界；TLS 只在解密后才可验证 STUN message。
7. response 的 transaction ID 必须与对应 request 相等；多事务必须各自生成 ID；重传只能重复同一 ID。动态 ID、HMAC、FINGERPRINT 不能以未复核常量出现在 JSON frames（帧字节）中。

## 3. 20-byte header 逐字段布局

STUN message 起点记为 `S`：

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 2 | Message Type | 低两位 0；Binding request `0001`、success `0101`、error `0111` |
| 2 | 2 | Message Length | attributes 总字节数，4 的倍数 |
| 4 | 4 | Magic Cookie | `21 12 a4 42` |
| 8 | 12 | Transaction ID | 运行期随机或显式测试 fixture；事务内复制 |

Method/class 的 RFC 编码不是线性枚举。对 Binding 方法，编码后的三类值如下：

| 语义 | `stun.type` | class bits（类别位） | method bits（方法位） |
|---|---:|---:|---:|
| request | `0x0001` | `0x0000` | `0x0001` |
| indication（指示） | `0x0011` | `0x0010` | `0x0001` |
| success response | `0x0101` | `0x0010` | `0x0001` |
| error response | `0x0111` | `0x0011` | `0x0001` |

本版只生成 request/success/error；indication 作为未来独立场景，不由 Binding request 默认补发。`stun.type.class` 和 `stun.type.method` 是 tshark（抓包解析器）已注册字段；字段断言使用解析器实际格式，不把 `0x0001` 与十进制字符串混用。

## 4. 承载、offset 和包数契约

无 VLAN、无 IP options 时，应用起点如下：

| 载体 | STUN 起点 | 正例断言 |
|---|---:|---|
| UDP/IPv4 | 42 = Ethernet 14 + IPv4 20 + UDP 8 | `udp.dstport`/`stun.*`；header bytes 从 42 开始 |
| UDP/IPv6 | 62 = Ethernet 14 + IPv6 40 + UDP 8 | `ipv6.dst`/`stun.*`；header bytes 从 62 开始 |
| TCP/IPv4 | 54 = Ethernet 14 + IPv4 20 + TCP 20 | `tcp.dstport`、`stun.tcp_frame_length`、`stun.*`；header bytes从 54 开始 |
| TLS/TCP/IPv4 | 54 为 TLS record 起点 | `tcp.dstport=5349`、`tls.record.content_type`；未解密时不对 STUN header 作断言 |

TCP/TLS 的 `packet_count` 是完整载体包数（包括 handshake/termination）；当前 cases 约定 TCP 单事务=8、TLS 单事务=15。该数值是目标契约基线，注册实现后必须先跑真实 pcap 再校准；UDP packet_count 只计 STUN datagram。

## 5. Attributes（属性）和 padding

每个属性编码为 `Type(2) | Length(2) | Value(Length) | zero padding to 4-byte boundary`。本版注册、可观察的字段如下：

| Attribute | Type | Value 语义 | tshark 字段 |
|---|---:|---|---|
| MAPPED-ADDRESS | `0x0001` | reserved(1)、family(1)、port(2)、IPv4/IPv6 address | `stun.att.family`、`stun.att.ipv4`/`ipv6`、`stun.att.port` |
| USERNAME | `0x0006` | UTF-8 字节串；RFC 8489 profile 的 UTF-8/长度规则仍需校验 | `stun.att.username` |
| MESSAGE-INTEGRITY | `0x0008` | 20-byte HMAC-SHA1；值运行期计算 | `stun.att.hmac` |
| ERROR-CODE | `0x0009` | reserved(2)、class(1)、number(1)、reason phrase | `stun.att.error.class`、`stun.att.error`、`stun.att.error.reason` |
| UNKNOWN-ATTRIBUTES | `0x000a` | comprehension-required type 的 U16 数组 | `stun.att.unknown` |
| REALM | `0x0014` | UTF-8 realm；长期认证上下文 | `stun.att.realm` |
| NONCE | `0x0015` | server challenge；值可能随服务端变化，不固化动态常量 | `stun.att.nonce` |
| XOR-MAPPED-ADDRESS | `0x0020` | family、port/address 与 cookie/transaction ID 异或 | `stun.att.family`、`stun.att.ipv4-xord`/`ipv6-xord`、`stun.att.port-xord` |
| FINGERPRINT | `0x8028` | CRC-32 XOR `0x5354554e`；值运行期计算 | `stun.att.crc32` |

MAPPED-ADDRESS 和 XOR-MAPPED-ADDRESS 可以同现用于迁移/对照，但 success 正例至少覆盖 XOR 形式。IPv4 XOR address 以 cookie 为 32-bit mask；IPv6 XOR address 以 `cookie || transaction ID` 的 128-bit mask。XOR port 使用 cookie 高 16 位。JSON 只断言地址字段存在/非零和 type/length 前缀，不写运行期映射地址或异或结果常量。

### 5.1 MESSAGE-INTEGRITY

RFC 5389 HMAC-SHA1 的输入边界必须严格实现：把 Message Length 改为包含至 MESSAGE-INTEGRITY 属性末尾的长度，HMAC 覆盖从 message type 开始到 MESSAGE-INTEGRITY 属性之前的全部 message bytes；不包含该属性自身的 type/length/value；HMAC value 是 20 bytes。若 FINGERPRINT 位于 MESSAGE-INTEGRITY 之后，fingerprint 不进入 HMAC 输入。短期认证直接使用 password；长期认证使用 RFC 5389 的 `MD5(username:realm:password)` key 规则，RFC 8489 的现代认证扩展需另有明确 profile，不能混用。

### 5.2 FINGERPRINT

FINGERPRINT 必须是 message（不含 FINGERPRINT 本身）截至 FINGERPRINT attribute header/value 前的 CRC-32，再与 `0x5354554e` 异或。Message Length 仍包含 FINGERPRINT 的 8 bytes；因此实现必须先完成所有前置属性，再计算 fingerprint。`stun.att.crc32` 只以 nonzero（非零）观察，不能把动态 CRC 固定写入 frames。

### 5.3 ERROR-CODE 和 UNKNOWN-ATTRIBUTES

ERROR-CODE 的 class 只能为 3–6，number 为 0–99；例如 401 Unauthorized 的 class=4、number=1。reason phrase 是可读字符串，但不能用 reason 的字符数替代 Attribute Length。UNKNOWN-ATTRIBUTES 只出现在 420 Unknown Attribute error 等适用错误中；401 Unauthorized 不与其混用，value 长度必须是 2 的倍数，属性本身按 4 字节 padding。

## 6. Binding 事务、重传和会话

一个普通事务是 request → success 或 request → error；STUN 不因单个 request 自动生成 response，事件必须显式配置。request 和 response 使用相同 transaction ID，方向相反；error response 的 type/class 必须是 `0x0111`。401 challenge 可带 REALM/NONCE，后续 authenticated request 重新使用同一会话的认证上下文但生成新 transaction ID。

UDP 重传不是改变 ID 的新事务：每次重传完整复制作文，Message Length、cookie、属性顺序、HMAC/FINGERPRINT 和 transaction ID 都相同。若应用层在新事务中再次 Binding，必须生成另一个 ID。TCP 一个连接可以承载多个顺序 transaction；响应匹配靠 transaction ID，不靠 TCP packet index。TLS 一个会话同样可以承载多个应用 transaction，但在未解密 PCAP 中只能观察 TLS record，不应声称 STUN 属性可见。

IPv4/IPv6 是 outer IP 与 address attribute 的独立维度：IPv6 outer UDP 可以返回 IPv6 XOR-MAPPED-ADDRESS；IPv4 outer 不得携带截断的 IPv6 value。地址 family 字节必须为 0x01/0x02，reserved 字段必须为零。

## 7. RFC 5766 TURN / RFC 5780 边界（单独范围）

TURN 是 STUN 的扩展使用，不等于本版 Binding。RFC 5766 的 Allocate、Refresh、CreatePermission、ChannelBind、Send/Data indication 以及 `REQUESTED-TRANSPORT`、`LIFETIME`、`XOR-PEER-ADDRESS`、`CHANNEL-NUMBER`、`DATA` 等属性必须使用独立 TURN profile 和独立 type/method/状态机；本设计不生成这些报文，也不把 `stun.att.transport`、`stun.channelnum` 等字段误当作 Binding 字段。

RFC 5780 的 NAT behavior discovery（NAT 行为发现）使用 CHANGE-REQUEST、RESPONSE-ORIGIN、OTHER-ADDRESS 等扩展；它需要独立能力协商和返回地址语义。本版只在负例 stun_neg_turn_boundary 验证“TURN method/attribute 不能静默进入 Binding-only profile”，不声称实现 RFC 5766/5780。未来实现 TURN 时，必须另写设计、testcase、audit 和 JSON，且分别覆盖 allocation 生命周期、权限、channel data 与 XOR peer 地址。

## 8. tshark 字段证据

在编写四件套前执行：

```text
tshark -G fields | grep -E '\tstun\.'
```

目标环境注册了以下字段，本版正例只使用这些字段或载体字段：

```text
stun.type
stun.type.class
stun.type.method
stun.length
stun.cookie
stun.id
stun.tcp_frame_length
stun.attribute
stun.att.type
stun.att.length
stun.att.family
stun.att.ipv4
stun.att.ipv6
stun.att.port
stun.att.username
stun.att.hmac
stun.att.error.class
stun.att.error
stun.att.error.reason
stun.att.realm
stun.att.nonce
stun.att.unknown
stun.att.ipv4-xord
stun.att.ipv6-xord
stun.att.port-xord
stun.att.crc32
```

TLS 载体只使用已注册的 `tcp.dstport`、`tls.record.content_type` 和 `tls.record.length`。`classicstun.*` 是旧 Classic STUN dissector（解析器）字段，不混入本版 RFC 5389/8489 的 `stun.*` 断言。

## 9. 场景和 packet_count 映射

共 24 个唯一 ID，15 个正例、9 个负例；顺序必须与 testcase、JSON、audit 完全一致。

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `stun_binding_udp_request` | 正 | UDP/IPv4 Binding request、20-byte header、cookie/type/class/method/length | 1 |
| 2 | `stun_binding_udp_success_ipv4` | 正 | success、XOR/MAPPED IPv4 | 2 |
| 3 | `stun_binding_udp_success_ipv6` | 正 | UDP/IPv6、XOR-MAPPED IPv6 | 2 |
| 4 | `stun_binding_udp_error` | 正 | Binding error、ERROR-CODE、UNKNOWN-ATTRIBUTES | 2 |
| 5 | `stun_binding_tcp_request` | 正 | TCP carrier、TCP framing、request | 8 |
| 6 | `stun_binding_tls_session` | 正 | TLS carrier；未解密时只观察 TLS | 15 |
| 7 | `stun_auth_attributes` | 正 | USERNAME/REALM/NONCE、认证上下文 | 1 |
| 8 | `stun_integrity_fingerprint` | 正 | MESSAGE-INTEGRITY/FINGERPRINT 计算语义 | 1 |
| 9 | `stun_attribute_padding` | 正 | 属性长度与 4-byte padding | 1 |
| 10 | `stun_retransmission` | 正 | UDP 同事务重传、ID/字节相等 | 3 |
| 11 | `stun_multi_transaction_udp` | 正 | UDP 多 transaction、request/success/error | 4 |
| 12 | `stun_multi_transaction_tcp` | 正 | 单 TCP session 多 transaction | 11 |
| 13 | `stun_ipv6_address_attributes` | 正 | IPv6 outer 与 IPv4/IPv6 address attribute | 2 |
| 14 | `stun_rfc8489_profile` | 正 | RFC 8489 Binding 兼容 profile 边界 | 1 |
| 15 | `stun_binding_mapped_both` | 正 | MAPPED 与 XOR-MAPPED 对照 | 2 |
| 16 | `stun_neg_header_short` | 负 | 少于 20 bytes header | — |
| 17 | `stun_neg_type_reserved_bits` | 负 | type 低位/保留位错误 | — |
| 18 | `stun_neg_length_alignment` | 负 | Message Length 非 4 的倍数 | — |
| 19 | `stun_neg_length_overrun` | 负 | Message Length 超出 payload | — |
| 20 | `stun_neg_bad_cookie` | 负 | Magic Cookie 错误 | — |
| 21 | `stun_neg_attribute_length` | 负 | attribute length/padding 越界 | — |
| 22 | `stun_neg_bad_integrity` | 负 | HMAC 输入或值错误 | — |
| 23 | `stun_neg_transport_mismatch` | 负 | TCP/TLS/UDP carrier 不一致 | — |
| 24 | `stun_neg_turn_boundary` | 负 | TURN/5780 扩展误入 Binding profile | — |

## 10. 错误契约

所有负例 `expect` 严格只有 `expect_error` 和 `error_contains` 两个键；没有 `packet_count`、`fields`、`frames`、`has_payload` 或错误 PCAP 断言。稳定错误锚点如下：

| ID | `error_contains` 建议值 |
|---|---|
| `stun_neg_header_short` | `header` |
| `stun_neg_type_reserved_bits` | `type` |
| `stun_neg_length_alignment` | `length` |
| `stun_neg_length_overrun` | `length` |
| `stun_neg_bad_cookie` | `cookie` |
| `stun_neg_attribute_length` | `attribute` |
| `stun_neg_bad_integrity` | `integrity` |
| `stun_neg_transport_mismatch` | `transport` |
| `stun_neg_turn_boundary` | `turn` |

未知 attribute 的错误响应（例如 420）是合法 STUN error 的正例；负例是配置/线格式不合法，二者不能混淆。负例必须真正使 task error，不能用空输出绕过。

## 11. 实现完成定义

1. 注册 `stun` layer（层）并严格声明 Binding 字段、event、属性和 `wire_fault`；未知 method/attribute、TURN 扩展混入和错误 carrier 必须拒绝。
2. 对每个 message 先完成 type、attribute 顺序和 padding，再回填 Message Length；验证 header 恰为 20 bytes、长度为 4 的倍数、cookie 固定、transaction ID 12 bytes。
3. 独立单测逐字节复算 IPv4/IPv6 XOR-MAPPED-ADDRESS、HMAC-SHA1 MESSAGE-INTEGRITY 和 CRC-32 FINGERPRINT，覆盖属性增删、padding、长度变化和错误 key；不得只测 nonzero。
4. 通过 planner → worker → UDP/TCP/TLS output（输出）的完整路径验证包数、事务 ID 关联、重传等价和多事务隔离；TCP segmentation（分段）不改变 STUN message framing。
5. TLS 正例在无解密密钥时仅断言 TLS record；若未来提供解密验证，必须增加独立字段/密钥 fixture，不得复用明文 frames。
6. 运行 suite 前先确认 layer registry（层注册表）和 tshark 字段；未注册时报告 rejected/not runnable，不报告通过。

## D1–D8 设计核对与缺口

| 项 | 结论 |
|---|---|
| D1 范围/依据 | RFC 5389、RFC 8489 Binding；TURN RFC 5766/5780 仅作边界，不混入 Binding |
| D2 层链 | 地址在 `ip`，端口在 `udp`/`tcp`，TLS 在 `tls`，STUN 业务在 `stun`；顶层只保留结构性键 |
| D3 线格式 | 20-byte header、网络字节序、4-byte 对齐、cookie 和 transaction ID 规则已逐字段列出 |
| D4 载体/属性 | UDP/TCP/TLS、IPv4/IPv6、属性 padding、XOR/HMAC/CRC 规则已列出 |
| D5 会话/数量 | 事件序列、重传同 ID、多 transaction 隔离；多会话展开与 `flow_control` 作为框架能力，未注册前为缺口 |
| D6 错误 | 9 类 wire fault 必须传播 task error，不得空输出假成功 |
| D7 性能/输出 | 目标流式逐 message 生成、有界队列；PCAP 与 NIC 共用同一契约，吞吐/并发/内存待实现实测 |
| D8 实现/回滚 | 待注册 layer、schema、planner、builder 和断言；回滚仅撤实现提交，保留本契约及迁移后的 cases |

### 待实现缺口

| 编号 | 缺口 | 计划 |
|---|---|---|
| G-STUN-1 | `stun` layer/planner/generator 未注册 | 注册 schema 与层链消费者后重跑 24 例 |
| G-STUN-2 | header、属性、XOR、HMAC、CRC 编码消费者缺失 | 按 D3/D4 实现并补逐字节单测 |
| G-STUN-3 | 9 类 validator 错误传播未接通 | 建立 task error 锚词链，禁止 completed/0 packet |
| G-STUN-4 | TCP/TLS framing 与多事务输出未实测 | 注册后以实际 pcap 校准 packet_count/offset |
| G-STUN-5 | NIC、吞吐、并发、背压未实测 | 完成 PCAP 后执行 NIC 双输出和六类性能场景 |

## 13. 修订记录

- v1.1.0（2026-09-30）：按 D1–D8 补齐设计契约、严格层链目标形状、缺口计划与 PCAP/NIC 输出边界；24 个 cases 完成层链迁移，未改 Go。
- v1.0.0（2026-08-20）：建立 RFC 5389/8489 STUN Binding 设计。

## 14. D/T/C 三方对账

| 维度 | design（本文件） | testcase | cases JSON | 结论 |
|---|---|---|---|---|
| ID 集合与顺序 | §9：24 个 ID，正 15、负 9 | §2：同一 24 个 ID、同一顺序 | 数组 24 例 | 一致 |
| 配置形状 | §2：`spec_json` 顶层仅 `layers`；地址在 `ip`，端口在 `udp`/`tcp`，业务在 `stun` | §1/T1–T4：同一归属约束 | 24/24 顶层无旧 `stun`；层序为 `ip→udp/tcp[→tls]→stun` | 一致 |
| 正例断言 | §9、§10：15 例均有包数与可复核字段/帧；动态 ID、HMAC、CRC、XOR 不写常量 | §2–§3：逐例列断言 | 15/15 正例具 `packet_count`，负例不具正例断言 | 一致 |
| 负例结构 | §10：每个负例只允许 `expect_error`、`error_contains` | §4/T5：同一双键约束与真实锚词 | 9/9 负例恰含这两个键；锚词为 `header/type/length/cookie/attribute/integrity/transport/turn` | 一致 |
| 实现边界 | §12：registry/translate、planner、builder、错误传播和 TLS/多载体实测仍是缺口 | §1/C6：不可运行不宣称通过 | 当前不运行 suite；缺口登记为 G-STUN-1…5 | 一致 |

`trafficgen/internal/core/layers/registry.go` 已有名称为 `stun` 的空字段层声明，但尚无业务字段白名单；`chain_planner_translate.go` 没有 `stun` terminal translation 分支。因此本次仅保留静态层链目标契约，不把 cases 的机械迁移冒充为运行能力；补齐 registry 字段和 translate 后再以同一 24 例验证。

本版自审：两轮。第一轮逐项核对 D1–D8、D/T/C 三方口径、registry/translate 缺口和层归属；第二轮逐条对照 JSON 24 个 ID、顶层键、正负 expect 键、真实错误锚词、偏移与动态断言，末轮干净。