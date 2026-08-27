# DCERPC（分布式计算环境远程过程调用，DCE/RPC）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/63-dcerpc-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/dcerpc.json`  
> 状态：`dcerpc` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§11 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `dcerpc_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

测试范围为 DCE/RPC version 5 over TCP：TCP/135 endpoint mapper（EPM，端点映射器）和 EPM 返回 dynamic endpoint（动态端点）的独立 TCP profile。验证器必须先按 TCP stream（字节流）重组，再按 common header 的 `frag_len` 切 PDU（协议数据单元）；TCP segment/record boundary 不是 DCE/RPC PDU boundary。认证 trailer（尾部）若为 NTLM/Kerberos，只断言 auth type/level、`auth_len`、边界、长度和 opaque（不透明）字节，不伪造密文、MIC、签名、sequence 或 session key。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier/stream/方向、common-header/raw frames（原始帧）和 dynamic values 的 presence/nonzero/same_as/distinct；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `dcerpc_epm_ipv4_bind_lookup` | 正 | TCP/135 EPM bind、endpoint lookup、IPv4 | 14 |
| 2 | `dcerpc_epm_ipv6_bind_lookup` | 正 | TCP/135 EPM bind、endpoint lookup、IPv6 独立 fixture | 14 |
| 3 | `dcerpc_dynamic_ipv4_profile` | 正 | EPM 返回 dynamic port 后独立 IPv4 session 调用 | 18 |
| 4 | `dcerpc_dynamic_ipv6_profile` | 正 | EPM 返回 dynamic port 后独立 IPv6 session 调用 | 18 |
| 5 | `dcerpc_common_header_fields` | 正 | version/type/flags/data rep/frag/auth/call ID | 12 |
| 6 | `dcerpc_bind_multi_context` | 正 | BIND/BIND ACK 多 context、abstract/transfer syntax UUID | 14 |
| 7 | `dcerpc_alter_context` | 正 | ALTER CONTEXT/RESP 新增 context 与结果 | 14 |
| 8 | `dcerpc_request_response_ndr` | 正 | REQUEST/RESPONSE、opnum、alloc hint 和 NDR scalar/struct | 14 |
| 9 | `dcerpc_fault_status` | 正 | REQUEST/FAULT status、context/call 关联及终态 | 12 |
| 10 | `dcerpc_ndr_pointer_array_union` | 正 | pointer、alignment、conformant array、union arm | 16 |
| 11 | `dcerpc_auth_trailer_opaque` | 正 | auth trailer boundary、opaque NTLM/Kerberos bytes | 14 |
| 12 | `dcerpc_multi_context_call_session` | 正 | 多 context、多 call、多 session 隔离 | 28 |
| 13 | `dcerpc_fragment_tcp_record_boundary` | 正 | PDU fragment/reassembly、PDU 与 TCP record 边界独立 | 20 |
| 14 | `dcerpc_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、PDU/common header 一致 | 16 |
| 15 | `dcerpc_neg_common_truncated` | 负 | common header/version/type/flags 非法 | — |
| 16 | `dcerpc_neg_frag_auth_length` | 负 | frag/auth length、overflow 或 fragment flags 非法 | — |
| 17 | `dcerpc_neg_context_syntax` | 负 | context/UUID/version/transfer syntax 非法 | — |
| 18 | `dcerpc_neg_ndr_bounds` | 负 | NDR alignment/pointer/array/union 越界或溢出 | — |
| 19 | `dcerpc_neg_auth_trailer` | 负 | auth trailer/verifier 边界和非法密文字段 | — |
| 20 | `dcerpc_neg_carrier_profile` | 负 | TCP/135/dynamic profile/session/IP family 错误 | — |

## 3. 正例逐项断言契约

1. **`dcerpc_epm_ipv4_bind_lookup`**：IPv4/TCP/135 完成握手，发送 BIND（EPM context），接收 BIND ACK，再发送 endpoint-map REQUEST 并接收 RESPONSE；断言 common header version=5/minor=0、packet type、PDU flags、`frag_len`/`auth_len`、call ID presence/same_as、EPM interface UUID 和 dynamic endpoint tower/port 边界，`packet_count=14`。
2. **`dcerpc_epm_ipv6_bind_lookup`**：独立 IPv6/TCP/135 session，断言 `ipv6.nxt=6`、地址族、EPM bind/lookup 顺序和 UUID/port 长度；不能复用 IPv4 的 TCP stream、call ID 或 endpoint bytes，`packet_count=14`。
3. **`dcerpc_dynamic_ipv4_profile`**：先由独立 EPM fixture 观察 dynamic port，再建立 IPv4/TCP 新四元组连接，完成目标 interface BIND/BIND ACK 和 REQUEST/RESPONSE；断言 destination port 非 135 且与 endpoint profile 一致、两个 session 的 call/context/association 隔离，`packet_count=18`。
4. **`dcerpc_dynamic_ipv6_profile`**：IPv6 dynamic endpoint 独立连接，断言 Next Header=6、端口、stream、abstract/transfer syntax UUID 和调用顺序；动态 endpoint 与 IPv4 fixture 不复用，`packet_count=18`。
5. **`dcerpc_common_header_fields`**：跨 BIND、REQUEST、RESPONSE、FAULT 观察 16-byte common header；断言 version/minor、packet type、FIRST/LAST flags、data representation、`frag_len` 包含整个 PDU、`auth_len` 边界及 call ID presence/nonzero。Call ID 在 request/response 使用 `same_as`，不同 call 使用 `distinct`，`packet_count=12`。
6. **`dcerpc_bind_multi_context`**：一条 BIND 含至少两个不同 context ID，各有 abstract syntax UUID/version 和一个或多个 transfer syntax UUID/version；BIND ACK 按 context 顺序返回 accepted/rejected result 与 negotiated syntax，断言 context 不重复、UUID bytes/长度、association group 和 secondary address 边界，`packet_count=14`。
7. **`dcerpc_alter_context`**：在已绑定 association 上发送 ALTER CONTEXT 新增 context，接收 ALTER_CONTEXT_RESP，再使用 accepted context 发起调用；断言不是新 TCP handshake，context ID/UUID/version 与结果对应，`packet_count=14`。
8. **`dcerpc_request_response_ndr`**：已 accepted context 上发送 REQUEST（alloc hint、context ID、opnum、stub）并接收 RESPONSE；断言 call ID/context ID same_as、opnum、stub length、NDR scalar/struct 的自然 alignment/padding 和 response alloc hint，`packet_count=14`。
9. **`dcerpc_fault_status`**：发送合法 REQUEST 后接收 FAULT；断言 packet type=FAULT、status、alloc hint/context/call 关联，FAULT 后该 call 终止且不发送伪造成功 RESPONSE，`packet_count=12`。
10. **`dcerpc_ndr_pointer_array_union`**：一个 stub 同时覆盖 4/8-byte alignment、pointer referent presence/nonzero、conformant/varying array 的 max/offset/actual counts 与 discriminated union 的单一 arm；断言 padding 和字段边界逐字节可复核、count 无溢出、selected arm 与 discriminant 一致，`packet_count=16`。
11. **`dcerpc_auth_trailer_opaque`**：选择声明 auth trailer 的 controlled fixture；断言 `auth_len>0`、pad/trailer 完整落在 `frag_len` 内、auth type/level/context/credential length 和跨 PDU 关联。NTLM/Kerberos credential/signature/MIC/session key 仅 presence/nonzero/length/opaque，不断言内部值，`packet_count=14`。
12. **`dcerpc_multi_context_call_session`**：至少两个 TCP sessions、每个至少两个 accepted contexts、并发多个 calls；断言四元组/stream/session、context ID、call ID、UUID、REQUEST→RESPONSE/FAULT 关联均隔离，动态 call ID 使用 distinct/same_as，不假设交织流全局顺序，`packet_count=28`。
13. **`dcerpc_fragment_tcp_record_boundary`**：将一个 REQUEST 和 RESPONSE 各拆成多个 DCE/RPC fragments，并把多个完整 PDU 合并到单个 TCP segment、另一个 PDU 跨多个 segments；断言每片 common header/`frag_len`、FIRST/LAST、同 call ID、重组后 NDR stub 完整，TCP record boundary 不替代 PDU boundary，`packet_count=20`。
14. **`dcerpc_pcap_nic_consistency`**：同一 EPM 或 dynamic fixture 分别输出 PCAP 并在指定 NIC 捕获；断言 TCP 端口/方向/stream、DCE/RPC version/type/flags/frag/auth length、call ID presence 和 PDU raw prefix 一致。过滤器为 `tcp port 135` 或 fixture dynamic port；记录 checksum/TSO offload 边界，`packet_count=16`。

正例不硬编码运行期 dynamic port、association group、UUID（若由 fixture 动态生成）或 call ID；跨包使用 presence/nonzero/same_as/distinct。没有授权密钥时，不添加 NTLM/Kerberos authenticator 内部字段、签名、MIC、序列号或 session key 断言。

## 4. 负例契约

每个负例必须在 planner/validator 处失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `dcerpc_neg_common_truncated` | common header 少于 16 bytes、未知 version/type 或 flags 非法 | `header`、`version` 或 `packet` |
| `dcerpc_neg_frag_auth_length` | frag_len/auth_len 不一致、越界、溢出或 fragment flags 不闭合 | `frag`、`auth`、`length` 或 `fragment` |
| `dcerpc_neg_context_syntax` | context ID 重复/未知、UUID/version 缺失或 transfer syntax 不匹配 | `context`、`syntax` 或 `uuid` |
| `dcerpc_neg_ndr_bounds` | alignment/padding、pointer、array、union/count 超界或溢出 | `ndr`、`alignment`、`pointer`、`array` 或 `union` |
| `dcerpc_neg_auth_trailer` | auth trailer 越界、auth_len 与 verifier 不符、伪造加密字段 | `auth`、`trailer` 或 `verifier` |
| `dcerpc_neg_carrier_profile` | 非 TCP、EPM/dynamic 端口错、跨 session 拼接或错误 IP family | `carrier`、`transport`、`endpoint` 或 `profile` |

合法的 empty stub、auth_len=0、FAULT、dynamic port、跨 TCP segmentation、多个 PDU/segment 和动态 UUID/call ID 由正例覆盖，不能误报为负例。错误传播须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §10、本文 §2、注册后的 JSON 和审计必须保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例，当前 JSON 另有一个 `dcerpc_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、profile、方向/stream 和稳定 common-header/raw fields；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. Common header 固定 16 bytes，version=5/minor=0；packet type、flags、data representation、frag_len、auth_len、call ID 的字节序和 PDU 语义必须按实际线格式断言。
4. `frag_len` 从 common header 起计并包含 pad/auth trailer；`auth_len` 不得越界；fragment flags、call ID 和 PDU 重组必须独立于 TCP segment boundary。
5. BIND/ACK/ALTER context ID 不重复，abstract/transfer syntax UUID+version 完整且 result 对应请求；EPM/动态 endpoint session 状态不串用。
6. REQUEST/RESPONSE/FAULT 以 call ID/context ID 关联；FAULT 后不得伪造同调用成功响应；多 call 使用 distinct，fragment 使用 same_as。
7. NDR 对齐、padding、pointer referent、array count/offset/actual count、union discriminant/arm 和 stub bounds 必须逐路径测试，不能只检查结构存在。
8. 认证 trailer 只能验证 auth type/level/length/boundary/opaque presence；不得伪造或硬编码 NTLM/Kerberos 密文、MIC、签名或 session key。
9. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/dcerpc.json` 应成功；当前数组只能含 `dcerpc_neg_unregistered`，且 `proto=dcerpc`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `dcerpc` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、EPM/dynamic ports、common-header offsets、PDU reassembly 和 tshark 字段注册，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 `dcerpc.*`/`epm.*` dissector，使用通用 `tcp`/`ip`/`ipv6`、端口、stream 和稳定 raw frames；不能自创解析字段。当前阶段不得将唯一 placeholder 运行结果报告为 DCERPC suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 DCE/RPC over TCP 正例和 6 个严格负例，覆盖 EPM/动态端点、common header、BIND/ACK/ALTER、REQUEST/RESPONSE/FAULT、context syntax、NDR、fragment/TCP record boundary、auth opaque、多 session/call、IPv4/IPv6、PCAP/NIC 和错误传播；不修改 Go 实现。
