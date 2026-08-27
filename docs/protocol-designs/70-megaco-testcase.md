# Megaco/H.248（媒体网关控制协议）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/70-megaco-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/megaco.json`  
> 状态：`h248`、`mgcp`、`megaco` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前测试套件可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `megaco_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

基线为 ITU-T H.248.1/RFC 3525；`h248`、`mgcp`、`megaco` 三个名字必须归一到同一 planner（规划器）语义，JSON 占位的 `proto` 固定为 `megaco`。H.248 默认 UDP/TCP 2944，MGCP alias（别名）profile（档案）默认 UDP 2427。文本和 BER（基本编码规则）是两种不同编码，必须分别验证。

transaction ID（事务标识）、Context ID（上下文标识）、Termination ID（终结点标识）、invoke/会话关联标识、媒体地址/端口和时间均是动态值，不硬编码；使用 `presence`、`nonzero`、`same_as_packet`、`distinct`、类型/长度和同会话关联断言。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`h248_rfc3525_text_udp_ipv4`**：IPv4/UDP 双向流，目标端口 2944；断言 H.248.1/RFC 3525 版本、文本消息分隔、动态 transaction/context/termination ID、请求方向和 Reply 关联，`packet_count=8`。
2. **`h248_ber_udp_ipv4`**：合法 BER TLV；断言 tag、每级 length 覆盖实际子结构、事务请求/回复、ReturnCode 和 UDP 2944，禁止按文本命令解释 BER，`packet_count=8`。
3. **`h248_tcp_2944_ipv6`**：IPv6/TCP 2944 完成握手；设置 MSS 使消息跨 segment 并粘连多事务，先重组字节流再按 H.248 消息边界解析，`packet_count=12`。
4. **`h248_context_termination_commands`**：在同一动态 Context 中按合法状态执行 Add、Modify、Move、Subtract；断言 Termination 引用、前后 Context 关系、命令顺序和每项 ReturnCode，`packet_count=14`。
5. **`h248_audit_notify_servicechange`**：观察 Audit、Notify、ServiceChange 的请求/响应与方向；断言事件/原因、服务状态、终结点范围和动态事务关联，`packet_count=12`。
6. **`h248_reply_returncode`**：至少包含成功和错误 Reply；断言 Reply transaction ID 与请求 `same_as_packet`、每个命令 ReturnCode、错误结构和方向，不能以成功 ACK 替代失败返回，`packet_count=10`。
7. **`h248_wildcard_audit`**：分别审计 ROOT、wildcard 和具体 Termination；断言匹配范围、返回属性集合和动态 ID 关系，不能把 wildcard 静默替换成固定终结点，`packet_count=8`。
8. **`h248_media_descriptor`**：Add/Modify 中携带 local/remote media descriptor；断言 audio 媒体类型、IPv4/IPv6 地址族字段、动态地址/端口、编解码器/方向属性及长度，`packet_count=10`。
9. **`h248_multi_session_transactions`**：至少两个独立四元组会话，每会话多个事务；断言每流 transaction/context/termination 独立、响应同流匹配，允许全局交织，`packet_count=20`。
10. **`mgcp_alias_udp_2427`**：以 `mgcp` alias profile 使用 UDP 2427；断言 alias 归一后的事务/命令/Reply 语义与 H.248 相同，端口和方向独立观察，`packet_count=8`。
11. **`h248_ipv4_ipv6_media`**：独立 IPv4 与 IPv6 fixture，媒体 descriptor 分别声明对应地址族；断言 IP 版本、UDP/TCP next-header、端口和 descriptor 地址族不混用，`packet_count=10`。
12. **`h248_multi_flow`**：多个终结点/多个流并行执行 Add/Modify/Notify；断言流内状态、命令顺序、动态 ID 和媒体属性隔离，不依赖全局包序，`packet_count=18`。
13. **`h248_text_ber_alias_equivalence`**：使用 h248、mgcp、megaco 三入口的等价事务/命令 fixture，覆盖文本与 BER；断言三入口归一为一个 planner 语义，但各 profile 的载体端口按配置生效，`packet_count=12`。
14. **`h248_pcap_nic_consistency`**：同一 fixture 输出 PCAP 并执行 NIC 捕获；断言 IPv4/IPv6、UDP/TCP、2944/2427、消息边界、命令、ReturnCode、方向和动态关联一致，`packet_count=12`。

没有真实媒体网、控制器或 RTP 发送证据时，不添加“媒体已建立”“编解码协商成功”“网关已执行动作”等断言；没有专用 Megaco dissector（解析器）时使用 TCP/UDP、raw payload、文本 token 和 BER TLV 长度/偏移，不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 UDP/TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error","error_contains"}`，因此 packet_count 为 `—`，不添加 `notes`、`min_packets` 或其他键。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `megaco_neg_ber_text_encoding` | BER TLV 非法/截断，或文本字节却声明 BER、BER 字节却声明文本 | `encoding`、`ber` 或 `text` |
| `megaco_neg_transaction_response_mismatch` | Reply transaction ID、ReturnCode 所属事务或响应会话错配 | `transaction`、`reply` 或 `match` |
| `megaco_neg_invalid_termination_context` | 不存在/重复 Termination、Context 引用错误、ROOT/wildcard 作用域非法 | `termination`、`context` 或 `wildcard` |
| `megaco_neg_command_order` | 未 Add 先 Modify/Subtract、Move 目标不存在、ServiceChange/Notify 状态顺序错误 | `command`、`order` 或 `state` |
| `megaco_neg_length_truncation` | 文本/BER 长度越界、TCP 截断、UDP 数据报尾部缺失 | `length`、`truncation` 或 `message` |
| `megaco_neg_carrier_port_family` | UDP/TCP 与 profile 不符、2944/2427 端口错误、IPv4/IPv6 层链冲突 | `carrier`、`port` 或 `address` |

负例不能用“0 包”、空 PCAP 或任务成功替代错误传播；动态 ID 缺失/错配不能由 planner 自动补齐。

## 5. 三方一致性和静态检查

1. 设计 `70-megaco-design.md` §8、本文 §2、注册后的 `megaco.json` 和审计必须保持同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 只含 `megaco_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、载体、方向、编码、动态关联和可观察字段；6 个负例的 `expect` 键集合恰为 `{expect_error,error_contains}`，packet_count 为 `—`。
3. H.248.1/RFC 3525 版本、事务、Context/Termination、Add/Modify/Subtract/Move/Audit/Notify/ServiceChange、Reply/ReturnCode、wildcard 和 media descriptor 必须分别在表中有对应正例或明确关联断言。
4. 文本按语法边界验证；BER 按逐级 TLV 长度验证，父长度覆盖子字节；两种编码不能互相替代。
5. 动态 transaction/context/termination/媒体值只用 presence/nonzero/same_as_packet/distinct/类型长度，不枚举固定运行期 ID。
6. UDP/TCP 2944、MGCP 2427、IPv4/IPv6、多会话/多流、PCAP/NIC 各有正例；TCP 先重组，UDP 保留 datagram 边界。
7. 负例必须覆盖编码、response mismatch（响应错配）、非法 termination/context、命令顺序、长度/截断、载体/端口/地址族和错误传播；不得用正例透明观察掩盖错误。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/megaco.json` 应成功；当前数组只能含 `megaco_neg_unregistered`，且 `proto=megaco`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册统一 Megaco layer 后，先检查 alias 归一化、JSON ID 顺序、文本/BER 编码选择、动态 ID 关联、TCP 重组、UDP 边界和负例错误传播，再运行 1–14 的 PCAP/NIC 正例与 15–20 的负例。当前占位只证明层未注册，不得报告为 Megaco 测试套件通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Megaco/H.248 正例和 6 个严格负例，覆盖 H.248.1/RFC 3525、文本/BER、事务与命令状态、Context/Termination、Reply/ReturnCode、wildcard、媒体 descriptor、UDP/TCP、MGCP alias、IPv4/IPv6、多会话/多流和 PCAP/NIC；明确三 alias 共用一个 planner；不修改 Go/MCP 实现。
