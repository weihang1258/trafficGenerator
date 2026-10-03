# LDP（标签分发协议，Label Distribution Protocol）设计与测试契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；`ldp` 层尚未注册，不宣称当前 MCP（模型上下文协议）套件或 PCAP（抓包文件）用例可运行。
> 配套文件：`docs/protocol-designs/41-ldp-testcase.md`、`trafficgen/test/protocol_pcap/cases/ldp.json`、`docs/protocol-designs/audit/41-ldp-adversarial-audit.md`
> 规范基线：RFC 5036（LDP Specification）；IPv4 FEC 语义参考 RFC 5036 §3.4/§3.5。

## 1. 范围、证据等级与 profile 边界

LDP（Label Distribution Protocol，标签分发协议）控制 MPLS（多协议标签交换）标签绑定。RFC 5036 将发现和会话分开：基本发现使用 UDP/646 Hello；LDP session（会话）使用 TCP/646。Hello 的目的地址、TTL 或 GTSM（广义 TTL 安全机制）策略不在本版伪造为单一固定值；每个用例明确载体、方向和端口。

本版只定义 RFC 5036 基础 IPv4 transport/profile：

| 证据等级 | 本版固定 | 不在本版声称 |
|---|---|---|
| UDP discovery（发现） | UDP/646、Hello 的 LDP PDU/common header（公共头）和 Hello Common Parameters（Hello 公共参数） | 真实多播邻居发现、TTL/GTSM 的部署策略 |
| TCP session | TCP/646、三次握手、LDP PDU 公共头、Initialization、KeepAlive、Address、Label Mapping/Request/Withdraw/Release、Notification | TCP MD5/AO、TLS、真实 LSP（标签交换路径）转发 |
| FEC（转发等价类） | IPv4 Prefix FEC、/24 与 /32 host route（主机路由） | IPv6 FEC、VPN/VC/PW FEC、流量工程扩展 |
| label（标签） | Generic Label TLV（通用标签 TLV（类型-长度-值））20-bit 范围 0–1048575；显式边界值 | 由平台保留/特殊标签的转发语义 |
| 地址族 | IPv4 transport 与 IPv4 FEC；IPv6 transport/profile 未定义则拒绝 | 不把 IPv6 outer IP（外层 IP）或 IPv6 TLV 假装成 RFC 5036 IPv4 profile |

`ldp_rfc5036_ipv4_basic` 是本版唯一正向 profile。IPv6 transport/profile 的负例必须独立拒绝，不能因为 LDP common header 相同而混入 IPv4 profile。未知消息、TLV 或 malformed（畸形）输入只作为拒绝契约，不是成功 PCAP。

## 2. 层链、载体、方向与配置

UDP discovery 层链为 `ip → udp → ldp`，TCP session 层链为 `ip → tcp → ldp`。IPv4 正例显式给出 `src_ip`/`dst_ip`、方向和端口：Hello 的源/目的端口均为 646；TCP 的客户端临时源端口为 50000、对端目的端口为 646，反向报文为 646→50000。端口不是“协议推断”的替代物，正例仍需写正确层链。

```json
{
  "layers": [{"tcp": {}}, {"ldp": {}}],
  "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2",
  "src_port": 50000, "dst_port": 646,
  "ldp": {"wire_profile": "ldp_rfc5036_ipv4_basic", "events": []}
}
```

| 配置键 | 约束 | 语义 |
|---|---|---|
| `wire_profile` | 正例固定 `ldp_rfc5036_ipv4_basic` | IPv4 LDP RFC 5036 基础线格式；未知/IPv6 profile 拒绝 |
| `carrier` | `udp_discovery`、`tcp_session` 或显式 aggregate schema 使用的 `dual_adjacency` | 载体和 packet（数据包）计数模型 |
| `events` | 数组，事件顺序显式 | `hello`、`initialization`、`keepalive`、`address`、`label_mapping`、`label_request`、`label_withdraw`、`label_release`、`notification` |
| `direction` | `c2s` 或 `s2c` | 应用事件方向；UDP Hello 也必须明确方向 |
| `lsr_id` | IPv4 地址 | LDP Identifier 的 LSR ID（标签交换路由器标识） |
| `label_space` | 0–65535 | LDP Identifier 的 Label Space ID（标签空间标识） |
| `version` | RFC 5036 profile 为 1 | PDU common header version |
| `hold_time` | 0–65535 秒；0 表示 RFC 默认值 | Hello Common Parameters 的 Hold Time |
| `targeted` | 布尔 | Hello targeted bit；不得同时误称 basic discovery |
| `hello_requested` | 布尔 | Hello Requested bit |
| `keepalive_time` | 1–65535 秒 | Initialization Common Session Parameters 的 KeepAlive Time |
| `label_control` | `independent` 或 `ordered` | 标签控制模式；只影响事件/状态约束，不虚构实现自动响应 |
| `label_advertisement` | `downstream_unsolicited` 或 `downstream_on_demand` | 下游标签分发纪律（DU/DoD） |
| `fec` | `ipv4_prefix` 或 `ipv4_host` + CIDR | 仅 IPv4 Prefix FEC，prefix length 0–32 |
| `label` | 0–1048575 | Generic Label TLV；超出范围拒绝 |
| `sessions` | 独立会话数组 | 多 session/parallel neighbors（并行邻居）按 TCP 四元组隔离 |
| `fault_kind` | 仅负例 | `pdu_length`、`message_length`、`tlv_length`、`label_bounds`、`unknown_message` 等故障注入；不生成合法报文 |

Initialization 的 Common Session Parameters TLV 必须携带协议版本、KeepAlive Time、标签分发纪律、Loop Detection（环路检测）位、Path Vector Limit（路径向量上限）、Max PDU Length、Receiver LSR Identifier 和 Receiver Label Space Identifier。无配置的 capability（能力）不自动添加。

## 3. RFC 5036 线格式

### 3.1 PDU common header（公共头）

每个 LDP PDU（协议数据单元）以 10 字节公共头开始：

```text
Version (2) | PDU Length (2) | LSR ID (4) | Label Space ID (2)
```

Version 在 RFC 5036 基础 profile 为 1；PDU Length 是后续 PDU（不含 Version、PDU Length 本身）的字节数，按实际编码回填。LSR ID 为 IPv4 地址，Label Space ID 为无符号 16-bit。Wireshark（网络分析器）已注册可使用字段：`ldp.hdr.version`、`ldp.hdr.pdu_len`、`ldp.hdr.ldpid.lsr`、`ldp.hdr.ldpid.lsid`。

### 3.2 Message header（消息头）与 TLV

每个消息为 `U bit + Message Type (15 bits) | Message Length (2) | Message ID (4) | Parameters`。Message Length 不含 4 字节 Type/Length，但含 Message ID 和参数；类型未知且 U=0 必须产生 Notification/错误或使输入拒绝，本设计的 unknown message 负例统一在 planner/validator 拒绝。TLV 为 `U/ F bits + Type (14 bits) | Length (2) | Value`，TLV Length 只计算 Value，不含 4 字节 TLV 头。

本机 tshark（抓包分析工具）注册并允许出现在正例断言的字段为：`ldp.msg.ubit`、`ldp.msg.type`、`ldp.msg.len`、`ldp.msg.id`、`ldp.msg.tlv.type`、`ldp.msg.tlv.len`、`ldp.msg.tlv.value`，以及下列具体 TLV 字段。设计和 JSON 不使用未在本机注册的 nested（嵌套）字段。

### 3.3 Discovery Hello

Hello 消息类型为 0x0100。Hello Common Parameters TLV 类型为 0x0400，Value 为 Hold Time、Targeted/Requested/GTSM bits 和保留位；Transport Address TLV 可声明 IPv4 transport address（运输地址），本版用 IPv4 地址。UDP/646 discovery 每条独立 PDU，方向由 UDP 四元组表示；targeted Hello 使用点对点目的地址，不把它写成基本多播发现。

### 3.4 Initialization 与 KeepAlive

Initialization 消息类型为 0x0200；其 Common Session Parameters TLV 类型为 0x0500，字段包括 Session Protocol Version、Session KeepAlive Time、Label Advertisement Discipline、Loop Detection、Path Vector Limit、Max PDU Length、Receiver LSR/Label Space。KeepAlive 消息类型为 0x0201，参数为空。TCP session 只有三次握手后才发送 LDP application（应用）事件；初始化通常为双向各一条，再由 KeepAlive 双向确认，但本版不自动填充未配置事件。

### 3.5 Address

Address 消息类型为 0x0300；Address List TLV 类型为 0x0101，Value 为 Address Family（地址族）和 IPv4 地址列表。正例只使用 Address Family IPv4=1。Wireshark 字段为 `ldp.msg.tlv.addrl.addr_family` 与 `ldp.msg.tlv.addrl.addr`。

### 3.6 Label Mapping、Request、Withdraw、Release

四类消息类型依次为：Label Mapping 0x0400、Label Request 0x0401、Label Withdraw 0x0402、Label Release 0x0403。IPv4 Prefix FEC TLV 使用 type=0x0100，其 Value 为 FEC Element Type=2、Address Family=1、prefix length 和 `ceil(prefix length/8)` 个前缀字节。/32 host route 仍是 Prefix FEC 的 prefix length=32，不另造 IPv4 host TLV。

Label Mapping 在 FEC TLV 后携带 Generic Label TLV type=0x0200，Label Request 只需 FEC。Withdraw/Release 的事件必须显式给出 FEC；若携带 label，断言 label 与原绑定一致。Label 只占 20-bit 有效值，线上的 Generic Label Value 为 32-bit 字段但高 12 bits 必须为零；常规范围和边界 0、1048575 纳入测试。

`independent` control（独立控制）允许先发送 Mapping，再收到 Request；`ordered` control（有序控制）要求先有上游/下游可达或请求状态，具体响应由实现 profile 定义。`downstream_unsolicited` 与 `downstream_on_demand` 必须在 Initialization 语义中可观察；不能把 DU 与 DoD 互换。基础 profile 不自动生成对端响应或标签分配。

### 3.7 Notification

Notification 消息类型为 0x0001，携带 Status TLV type=0x0300；Status Data 由 E/F bits 与 Status Code 构成，可用已定义的 No Error/Shutdown 等 RFC 5036 状态。Notification 是合法会话事件；未知消息、非法长度和非法标签输入则是 planner/validator 错误，不应以空 PCAP 成功结束。

## 4. 会话、邻接和状态约束

```text
UDP/646 Hello（basic 或 targeted discovery）
              ↓
TCP/646 connect
              ↓
Initialization（双方）→ KeepAlive（双方）
              ↓
Address / Label Request / Mapping / Withdraw / Release
              ↓
Notification（可选）或 TCP FIN
```

- UDP Hello 和 TCP session 是两种不同载体；不能用 UDP packet 代替 TCP 握手，也不能把 TCP PDU 当 discovery。
- 一条 TCP session 按四元组和 LDP Identifier 隔离；两个 parallel neighbors 可以共享目的端口 646，但源临时端口或 LSR ID 必须不同。
- `targeted=true` 只改变 Hello 的目标/标记语义；它不自动建立第二条 TCP session。
- Initialization 两方向完成后才允许 KeepAlive、Address 和标签消息；Notification 可作为最后事件。
- Label Mapping/Request/Withdraw/Release 的 FEC 必须在 IPv4 profile 内，/0–/32 边界合法；IPv6 前缀不是 IPv4 FEC 的替代写法。
- 所有 PDU/message/TLV length 按编码后实际长度回填；声明长度与边界不一致必须拒绝。
- 各事件方向必须在同一 session 的 transport 上编码；不要把一个方向的 LSR ID 或 label space 泄漏到另一 session。

## 5. Checksum、长度与传输断言

LDP 自身不定义独立 checksum；TCP/UDP checksum 属于传输层伪首部校验，IPv4 header checksum 属于 IP 层。正例可断言已注册的 `ip.proto`、`tcp.srcport`/`tcp.dstport`、`udp.srcport`/`udp.dstport`、`tcp.checksum` 或 `udp.checksum` 存在/非零（具体验证器是否呈现校验状态由 output backend（输出后端）决定），不能把“LDP checksum”写进协议字段。

IPv4 TCP application payload offset（载荷偏移）在无额外 option 时为 Ethernet 14 + IPv4 20 + TCP 20 = 54；UDP LDP payload offset 为 Ethernet 14 + IPv4 20 + UDP 8 = 42。固定 offset 仅用于未分段 frame（帧）；TCP MSS 分段必须按 stream 重组后检查，packet_count 计实际 segment。

在本版建议的无额外 TCP option、每个应用事件单独一个 segment 模型中：

- UDP 每个 Hello PDU 为 1 packet。
- TCP 每个 session 的 packet_count = 3（SYN/SYN-ACK/ACK）+ 应用事件数 + 4（FIN 终止）。
- 多 session 先按 session 求和，不假定调度交织顺序。

## 6. 错误处理

| 输入故障 | 必须拒绝 | 稳定关键词 |
|---|---|---|
| `ldp` 终结层缺 TCP/UDP 或 carrier 不匹配 | LDP 只允许本版明确载体 | `carrier` |
| UDP 非 646 或 TCP 非 646 | 端口不满足 RFC 5036 | `port` |
| 未定义 IPv6 transport/profile | 不能混用 IPv4 FEC/profile | `profile` |
| PDU Length 与实际 PDU 不一致/超出 | PDU 边界非法 | `pdu` |
| Message Length 与消息 body 不一致 | message 边界非法 | `message` |
| TLV Length 与 Value 不一致 | TLV 边界非法 | `tlv` |
| unknown Message Type（未知消息类型） | 不能伪造基础 profile 语义 | `unknown` |
| Generic Label 高位非零或 >1048575 | 20-bit label 越界 | `label` |
| FEC prefix length <0 或 >32 | IPv4 Prefix FEC 越界 | `prefix` |
| Initialization 前发送 KeepAlive/Address/label | 会话状态错误 | `state` |
| UDP 载体携带 TCP session-only event | 载体/事件冲突 | `carrier` |

错误必须由 planner/validator 传播到 task error（任务错误）终态，不得报告 completed with 0 packets（完成但 0 包）。负例 `expect` 不对失败 PCAP、packet count 或字段作断言。

## 7. 场景、包数与实现完成定义

四件套 ID 顺序闭环如下：

`ldp_tcp_initialization`、`ldp_tcp_keepalive`、`ldp_address_ipv4`、`ldp_label_mapping_ipv4`、`ldp_label_request_ipv4`、`ldp_label_withdraw_ipv4`、`ldp_label_release_ipv4`、`ldp_label_mapping_host32`、`ldp_udp_targeted_hello`、`ldp_udp_parallel_hellos`、`ldp_notification_shutdown`、`ldp_ordered_dod_allocation`、`ldp_tcp_multi_session`、`ldp_dual_adjacency`、`ldp_neg_carrier`、`ldp_neg_port`、`ldp_neg_ipv6_profile`、`ldp_neg_pdu_length`、`ldp_neg_message_length`、`ldp_neg_tlv_length`、`ldp_neg_unknown_message`、`ldp_neg_label_bounds`、`ldp_neg_prefix_bounds`、`ldp_neg_state`、`ldp_neg_checksum`。


本套件使用 25 个唯一 ID，顺序为 14 个正例 `S1–S14` 后 11 个负例 `N1–N11`。正例分别覆盖 basic/targeted Hello、Initialization 参数、KeepAlive、Address、四种标签消息、/32、双 session、双 adjacency 和 Notification；负例覆盖载体/端口/profile/各级长度/unknown message/label/FEC/state/checksum。每个正例在 testcase 与 JSON 中保持相同 packet_count、fields、frames；负例严格只有 `expect_error` 和 `error_contains`。

后续实现完成定义：注册 UDP/TCP→LDP 终结层；实现 common header、Hello/Initialization/KeepAlive/Address/label 消息/Notification；完成 IPv4 Prefix FEC /0–/32、20-bit label、DU/DoD 与 independent/ordered 配置验证；对两种载体、方向、TCP 多 session、targeted Hello 和 transport/profile 边界写集成测试；验证长度/状态/错误传播和 checksum 由真实 output 观察。IPv6 profile、VPN/VC FEC、capability、TCP MD5/AO、真实邻居发现和 MPLS forwarding 均明确待实现。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 5036 LDP IPv4 基础 profile、UDP/TCP 双载体、25 个闭环用例和待实现边界；字段名称以本机 `tshark -G fields` 注册结果为准。
