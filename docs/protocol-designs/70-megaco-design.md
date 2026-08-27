# Megaco/H.248（媒体网关控制协议）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`h248`、`mgcp`、`megaco` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前测试套件可运行。  
> 配套文件：`docs/protocol-designs/70-megaco-testcase.md`、`trafficgen/test/protocol_pcap/cases/megaco.json`  
> 任务：B6 应用/管理协议

## 1. 范围、规范基线和未注册边界

本契约覆盖 ITU-T H.248.1（媒体网关控制协议规范）/RFC 3525（Megaco 基线）中的版本协商、事务（transaction）、上下文（Context）、终结点（Termination）、命令（Add、Modify、Subtract、Move、Audit、Notify、ServiceChange）、回复（Reply）/返回码（ReturnCode）、通配符（wildcard）和媒体描述（media descriptor）。载体包括 UDP/TCP 2944、MGCP 兼容别名 UDP 2427、IPv4/IPv6、多会话/多流以及 PCAP/NIC 证据。

`h248`、`mgcp`、`megaco` 三个名字共用一个 planner（规划器）语义：差异只在入口别名和 carrier（载体）profile（档案）默认值；`megaco.json` 的占位 `proto` 必须是 `megaco`，不能用 `h248` 或 `mgcp`。实现时应由 alias（别名）归一化为同一语义模型，再由 profile 选择端口和文本/二进制承载，不得复制三套状态机。

当前没有注册层、planner、validator（校验器）或生成器。`cases/megaco.json` 只能有一个 `megaco_neg_unregistered` 注册前置占位，其 `expect_error=true` 且 `error_contains` 精确为 `unknown layer`。占位不计入下文 20 个语义 ID；注册前拒绝、0 包或空 PCAP 不是协议行为通过。

动态 transaction ID、Context ID、Termination ID、invoke/关联标识、会话 token（令牌）、媒体端口和时间值不能硬编码。实现后的断言使用 `presence`、`nonzero`、`same_as_packet`、`distinct`、类型/长度及同一会话关联；若需要引用，应使用运行期生成值的包间关系，而不是固定数字。

## 2. 推荐层链、配置和载体

推荐的未来层链为 `[ip, udp, megaco]`、`[ip, tcp, megaco]`、`[ipv6, udp, megaco]` 或 `[ipv6, tcp, megaco]`。层链仅为实现接入契约，不表示当前注册。示例：

```json
{
  "protocol": "megaco",
  "config": {
    "layers": [{"udp": {}}, {"megaco": {}}],
    "src_ip": "192.0.2.70",
    "dst_ip": "198.51.100.70",
    "src_port": 40070,
    "dst_port": 2944,
    "megaco": {
      "profile": "h248_rfc3525",
      "encoding": "text",
      "version": "1",
      "transactions": [{"commands": ["Add", "Modify", "Notify"]}]
    }
  }
}
```

| 配置项 | 约束 |
|---|---|
| `profile` | `h248_rfc3525`、`mgcp_alias`；三个入口别名仍归一到同一 planner 语义。MGCP 兼容 profile 默认 UDP 2427；H.248 默认 UDP/TCP 2944。 |
| `encoding` | `text` 为 H.248 文本编码；`ber` 为 ASN.1 BER（基本编码规则）编码。编码选择必须和实际 payload（载荷）一致，不得静默把 BER 当文本或反之。 |
| `version` | H.248.1/RFC 3525 版本字段；版本值由 fixture（固定样本）生成，断言存在、格式和请求/回复协商一致，不能固定运行期 transaction/context 值。 |
| `transactions` | 保留用户给出的事务顺序；每个事务有动态 ID、请求/回复方向和命令列表。响应必须关联同一事务，不得跨会话配对。 |
| `context`/`termination` | Context ID 与 Termination ID 由 planner 动态生成；ROOT、通配符和具体终结点的语义分开，禁止用固定数字冒充动态标识。 |
| `commands` | 支持 Add、Modify、Subtract、Move、Audit、Notify、ServiceChange；命令顺序是状态机输入，非法顺序必须失败。 |
| `media` | local/remote descriptor（本地/远端媒体描述）至少保留媒体类型、地址族、地址、端口、编解码器/方向和属性的结构与长度；地址/端口可动态化。 |
| `transport` | `udp` 或 `tcp`；H.248 端口为 2944，MGCP alias 默认 2427。TCP 是字节流，须按消息边界重组；UDP 保留数据报边界。 |
| `wire_fault` | 仅负例注入口：`ber-text`、`transaction`、`termination-context`、`command-order`、`length-truncation`、`carrier-port-family`。 |

## 3. 文本与 BER 编码

文本消息应可观察到版本行、事务起止、Context/Termination 标识、命令名、参数块和回复/返回码；空白、大小写和分隔符遵循 H.248 文本语法，不能因为能被宽松字符串搜索就跳过结构校验。文本中的动态 ID 使用运行期 token，测试只验证同一事务/上下文内的引用关系。

BER 消息应按 ASN.1 TLV（类型-长度-值）逐层编码，长度是实际编码字节数，嵌套结构的父长度必须覆盖全部子 TLV。测试应观察应用协议选择、事务、命令和返回码的 tag/length/value 关系；不能把 BER 的长度当字符数，也不能将 BER 字节直接按文本命令解析。截断、非法长度、未知关键 tag 或编码与 profile 冲突应在 validator 阶段失败并传播为任务错误。

## 4. H.248 状态和命令语义

事务请求由动态 transaction ID、Context 列表和命令列表组成；Reply 携带同一 transaction ID 与每个命令的 ReturnCode（返回码）。成功返回码、错误返回码和未完成/重试边界必须分别可观察，失败不能被 planner 静默改写为成功。

- **Add（添加）**：在 Context 中创建或加入 Termination，验证终结点引用、媒体描述和返回码。
- **Modify（修改）**：更新已存在 Termination 的媒体/事件属性，必须引用同一 Context/Termination。
- **Subtract（删除）**：移除 Termination 或 Context 成员；删除后不得继续把该终结点当作已存在对象。
- **Move（移动）**：把 Termination 从一个 Context 移到另一个 Context，前后 Context 关系和动态 ID 必须保持可关联。
- **Audit（审计）**：支持具体终结点与 wildcard 审计；回复必须说明请求范围和可观察属性集合。
- **Notify（通知）**：通知事件、原因和关联终结点，方向通常为网关到控制器，但测试以事件方向配置为准。
- **ServiceChange（业务变化）**：建立、恢复或终止服务状态；版本/原因/终结点范围和回复 ReturnCode 必须一致。

ROOT、`*`/wildcard 和具体 Termination 是不同匹配语义。wildcard 不得被静默替换成某个硬编码终结点；同一 Context 内多个 Termination 的返回顺序须与命令顺序一致，跨流只按会话/事务关联。

## 5. 媒体描述、地址族与多流

媒体描述至少覆盖媒体类型（如 audio）、local/remote descriptor、IPv4/IPv6 地址族、端口、编解码器列表、方向属性及可选事件/信号参数。媒体描述只是控制消息中的结构，不宣称真实 RTP（实时传输协议）媒体已发送；没有 RTP 层实现时只验证 descriptor 字节、长度、地址族和同一 Termination 的前后关联。

IPv4 和 IPv6 必须使用独立 fixture，分别断言 IP 版本、UDP/TCP next-header（下一报头）、地址族和载体端口，不得以替换地址字符串代替 IPv6 层。多会话/多流至少包含两个独立四元组或地址族，每个会话有独立 transaction/context/termination 映射；全局交织不能造成跨会话配对。一个 TCP session 可承载多个事务，必须先按字节流重组再按 H.248 消息边界解析。

## 6. 正例和 PCAP/NIC 证据

正例应观察 Ethernet/IP、方向、UDP/TCP 端口、消息编码、版本、动态 ID、命令顺序、Reply/ReturnCode、wildcard 和媒体 descriptor。`h248_tcp_2944_ipv6` 覆盖 TCP 2944 与 IPv6；`h248_rfc3525_text_udp_ipv4` 覆盖 UDP 2944 与 IPv4；`mgcp_alias_udp_2427` 覆盖别名 profile 的 UDP 2427。多流用例同时观察独立会话，不依赖全局包序。

`h248_pcap_nic_consistency` 使用同一 fixture 生成 PCAP 并进行 NIC 捕获，比较载体、方向、端口、消息边界、动态 ID 关联和命令/返回码结构。checksum offload（校验和卸载）只影响链路校验和显示，不改变 H.248/MGCP 应用 payload。没有专用 dissector（解析器）时，使用 TCP/UDP 字段、raw payload（原始载荷）、稳定 TLV/文本 token 边界和脚本重组；不得自创未注册的 tshark 字段。

## 7. 负例、错误传播和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不得生成成功 PCAP、`completed/0 packet` 或只有 UDP/TCP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error","error_contains"}`，packet_count 写 `—`，不添加 `notes`、`min_packets` 或字段断言。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `megaco_neg_ber_text_encoding` | BER TLV 截断/非法长度、文本语法字节却声明 BER，或 BER 字节却声明文本 | `encoding`、`ber` 或 `text` |
| `megaco_neg_transaction_response_mismatch` | Reply transaction ID、ReturnCode 所属事务或响应会话与请求不匹配 | `transaction`、`reply` 或 `match` |
| `megaco_neg_invalid_termination_context` | 不存在/重复 Termination、Context 引用错误、ROOT/wildcard 作用域非法 | `termination`、`context` 或 `wildcard` |
| `megaco_neg_command_order` | 未 Add 先 Modify/Subtract、Move 目标不存在、ServiceChange/Notify 顺序违反状态 | `command`、`order` 或 `state` |
| `megaco_neg_length_truncation` | 文本/BER 消息声明长度越界、TCP 截断、UDP 数据报尾部缺失 | `length`、`truncation` 或 `message` |
| `megaco_neg_carrier_port_family` | UDP/TCP 载体与 profile 不符、2944/2427 端口错误、IPv4/IPv6 层链冲突 | `carrier`、`port` 或 `address` |

错误必须保留最具体原因并从 planner 传到 task；不能自动分配缺失 ID、跨事务补回复、将非法命令重排成合法顺序，或用 0 包完成掩盖失败。

实现完成定义：三个 alias 归一到一个 planner；注册 layer；实现文本/BER、H.248.1/RFC 3525 事务与命令状态、Reply/ReturnCode、wildcard、媒体 descriptor、UDP/TCP 2944、MGCP 2427、IPv4/IPv6、多会话/多流和 PCAP/NIC；planner→worker→输出完整传播；20 个语义场景的正负集成测试与 `-race`（竞态检测）通过。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `70-megaco-testcase.md` §2 及未来注册后的 `megaco.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `h248_rfc3525_text_udp_ipv4` | 正 | H.248.1/RFC 3525 版本、文本事务、UDP 2944、IPv4 | 8 |
| 2 | `h248_ber_udp_ipv4` | 正 | 合法 BER TLV、事务与 Reply/ReturnCode、UDP 2944 | 8 |
| 3 | `h248_tcp_2944_ipv6` | 正 | TCP 2944、字节流重组、多消息、IPv6 | 12 |
| 4 | `h248_context_termination_commands` | 正 | Context/Termination 与 Add/Modify/Subtract/Move 生命周期 | 14 |
| 5 | `h248_audit_notify_servicechange` | 正 | Audit、Notify、ServiceChange 事务和方向 | 12 |
| 6 | `h248_reply_returncode` | 正 | Reply、成功/错误 ReturnCode 与请求关联 | 10 |
| 7 | `h248_wildcard_audit` | 正 | ROOT/通配符审计、具体终结点区分 | 8 |
| 8 | `h248_media_descriptor` | 正 | local/remote media descriptor（本地/远端媒体描述）、编解码器、属性和端口 | 10 |
| 9 | `h248_multi_session_transactions` | 正 | 多会话、多事务、动态 ID 隔离与关联 | 20 |
| 10 | `mgcp_alias_udp_2427` | 正 | MGCP 2427 别名 profile 与同一 planner 语义 | 8 |
| 11 | `h248_ipv4_ipv6_media` | 正 | IPv4/IPv6 地址族与媒体 descriptor 独立性 | 10 |
| 12 | `h248_multi_flow` | 正 | 多流/多终结点、交织顺序和状态隔离 | 18 |
| 13 | `h248_text_ber_alias_equivalence` | 正 | h248/mgcp/megaco 三名字共享事务/命令语义 | 12 |
| 14 | `h248_pcap_nic_consistency` | 正 | PCAP/NIC、方向、端口、边界和动态关联一致 | 12 |
| 15 | `megaco_neg_ber_text_encoding` | 负 | BER/文本编码声明、TLV/语法非法 | — |
| 16 | `megaco_neg_transaction_response_mismatch` | 负 | transaction/Reply/会话响应错配 | — |
| 17 | `megaco_neg_invalid_termination_context` | 负 | 非法 Termination/Context、ROOT/wildcard 作用域 | — |
| 18 | `megaco_neg_command_order` | 负 | Add/Modify/Subtract/Move/ServiceChange 顺序和状态错误 | — |
| 19 | `megaco_neg_length_truncation` | 负 | 消息长度越界、TCP/UDP 截断 | — |
| 20 | `megaco_neg_carrier_port_family` | 负 | 载体、2944/2427 端口和 IPv4/IPv6 地址族错误 | — |

三方契约必须保持本文 §8、`70-megaco-testcase.md` §2、注册后的 `megaco.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `megaco_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Megaco/H.248 正例和 6 个严格负例，覆盖 H.248.1/RFC 3525、文本/BER、事务与命令状态、Context/Termination、Reply/ReturnCode、wildcard、媒体 descriptor、UDP/TCP、MGCP alias、IPv4/IPv6、多会话/多流和 PCAP/NIC；明确三 alias 共用一个 planner；不修改 Go/MCP 实现。
