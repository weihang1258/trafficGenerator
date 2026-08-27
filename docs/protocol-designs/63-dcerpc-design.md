# DCERPC（分布式计算环境远程过程调用，DCE/RPC）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`dcerpc` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/63-dcerpc-testcase.md`、`trafficgen/test/protocol_pcap/cases/dcerpc.json`  
> 规范基线：DCE 1.1 RPC、The Open Group C706、MS-RPCE、MS-DCOM、RFC 1050（ONC RPC 对照边界）、RFC 791/8200/793（IPv4/IPv6/TCP）。

## 1. 范围、profile（载体配置）和未注册边界

本设计定义 DCE/RPC version 5 over TCP 的连接型协议，覆盖 endpoint mapper（EPM，端点映射器）在 TCP/135 上的查询，以及绑定到 dynamic endpoint（动态端点）后的 RPC request/response。内容覆盖 common header（公共头）、BIND/BIND ACK、ALTER CONTEXT、REQUEST/RESPONSE/FAULT、context 与 abstract/transfer syntax UUID（通用/传输语法标识符）、NDR（网络数据表示）对齐与复合值、fragment（分片）重组和 TCP record boundary（记录边界）。

- **P-EPM**：TCP destination port 135，服务端先接受连接，再通过 EPM interface UUID（推荐 EPM v3）绑定并执行 endpoint-map request/response；135 是 mapper 端口，不把其当作被映射接口的动态端口。
- **P-DYNAMIC**：使用 EPM 返回的 endpoint profile（例如受控 fixture 的高端口），随后建立独立 TCP session 并执行目标 interface 的 BIND、REQUEST/RESPONSE。动态端口可为测试配置值，但不得从 135 静默推导。
- TCP payload 可能被分割为多个 segments；DCE/RPC `frag_len` 定义 PDU（协议数据单元）边界，不能将 TCP packet 边界当作 PDU 边界。一个 PDU 也可能跨多个 TCP segments。
- `auth_len` 非零时，认证 trailer（尾部）和 pad 只断言长度、边界、存在性与 opaque（不透明）字节；不伪造 NTLM/Kerberos 加密字段、签名、session key 或校验值。

当前仓库没有注册 `dcerpc` layer、planner（规划器）、validator（校验器）或生成器。`cases/dcerpc.json` 只保留一个 `dcerpc_neg_unregistered` 注册前置占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 DCERPC 行为通过。

## 2. 推荐配置和层链

推荐链为 `[ip, tcp, dcerpc]` 或 `[ipv6, tcp, dcerpc]`。HTTP、SMB、TLS 等其他 carrier 不在本契约内；EPM 与 dynamic profile 由 `dcerpc.profile` 显式选择。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"dcerpc": {}}],
  "src_ip": "192.0.2.63",
  "dst_ip": "198.51.100.63",
  "src_port": 40063,
  "dst_port": 135,
  "dcerpc": {
    "profile": "epm",
    "rpc_version": [5, 0],
    "events": ["bind", "bind_ack", "request", "response"],
    "contexts": [{"context_id": 0, "abstract_syntax": "dynamic", "transfer_syntax": "ndr"]},
    "ndr": {"pointer": "referent", "alignment": true},
    "auth": {"type": "none"}
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `epm`（TCP/135 endpoint mapper）或 `dynamic`（EPM 返回后另起动态端口）；不能由端口猜测。 |
| `rpc_version` | Common header 必须为 version 5、minor 0；未知版本拒绝。 |
| `contexts` | 每项有 context ID、abstract syntax UUID/version 和 transfer syntax UUID/version；同一 BIND 内 ID 不重复。 |
| `events` | 必须保持连接内的 bind/alter/request/response 状态顺序；EPM 查询与动态调用属于独立 session。 |
| `ndr` | 只描述可观察的 NDR scalar、alignment、pointer、array、union 布局；指针 referent ID 为运行期动态值。 |
| `fragment` | `frag_len` 驱动 PDU 分段/重组；fragment number、alloc hint 和 call ID 需按同一调用关联。 |
| `auth` | `none` 或明确 opaque trailer profile；NTLM/Kerberos trailer 不填入伪造的密文、MIC、签名或 session key。 |
| `wire_fault` | 仅负例注入口：`common_truncated`、`frag_auth_length`、`context_syntax`、`ndr_bounds`、`auth_trailer`、`carrier_profile`。不是合法线上字段。 |

## 3. Common Header（公共头）

每个 DCE/RPC PDU 从 common header 起点 `R` 开始；字段按 `DataRepresentation`（数据表示）声明的字节序编码，推荐 fixture 使用 little-endian。`frag_len` 和 `auth_len` 为 unsigned 16-bit，`call_id` 为 unsigned 32-bit，不应脱离 drep 固定假设网络大端。

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Version | 固定 `5`。 |
| 1 | 1 | VersionMinor | 固定 `0`。 |
| 2 | 1 | PacketType | `REQUEST=0`, `RESPONSE=2`, `FAULT=3`, `BIND=11`, `BIND_ACK=12`, `ALTER_CONTEXT=14`, `ALTER_CONTEXT_RESP=15` 等按规范枚举。 |
| 3 | 1 | PacketFlags | PFC_FIRST_FRAG、PFC_LAST_FRAG、PFC_PENDING_CANCEL、PFC_SUPPORT_HEADER_SIGN 等 bit 按 PDU 类型约束；分片时首/末状态必须闭合。 |
| 4 | 4 | DataRepresentation | 通常 `10 00 00 00`（little-endian integer、ASCII character、IEEE float）；fixture 必须显式声明，不能默改。 |
| 8 | 2 | FragLength | 16-bit per `DataRepresentation` (little-endian in the recommended fixture)；从 common header 起计，包含 auth trailer 和 pad。必须 `>=16`、不超出 TCP 重组记录和实现上限。 |
| 10 | 2 | AuthLength | 16-bit per `DataRepresentation` (little-endian in the recommended fixture)；认证凭据长度，不包括 common header；为零时不得伪造认证 trailer。 |
| 12 | 4 | CallId | 按 DataRepresentation 的整数表示编码；同一调用的 fragments、response、fault 使用 `same_as`，不同并发调用使用 `distinct`/presence。 |

`frag_len` 是 PDU 边界，必须覆盖 header、body、pad、auth verifier；`auth_len <= frag_len-16`。Header flags、packet type、length 与实际 payload 不一致时，validator 必须报错并传播 task error，而不是生成只含 TCP 的假成功。

## 4. PDU 固定字段和状态

### 4.1 BIND 与 BIND ACK

BIND body 紧随 common header：`max_xmit_frag(2)`、`max_recv_frag(2)`、`assoc_group_id(4)`、`num_context_items(1)`、`reserved(1)`、`reserved2(2)`，然后是 context list。每个 context element 为 `context_id(2)`、`num_transfer_syntaxes(1)`、`reserved(1)`、abstract syntax UUID(16)+version major/minor(2+2)，以及每个 transfer syntax UUID(16)+version major/minor(2+2)。

BIND ACK body 包含 negotiated max fragment sizes、association group、secondary address（含 TCP dynamic endpoint 的字符串长度/边界）和 result list；每项 result、reason、transfer syntax UUID/version 必须对应请求 context。ACK 的 accepted/rejected result 必须能观察到，不能把任意 UUID 作为成功证据。

同一 BIND 内 `context_id` 不可重复；abstract syntax 与 transfer syntax UUID/version 不能缺字段、越过 PDU 或被错误字节序重排。EPM context 与动态目标 context 必须在各自 session 隔离。

### 4.2 ALTER CONTEXT

`ALTER_CONTEXT` 使用与 BIND 相同的 context element 编码，但只声明新增或替换的 context。`ALTER_CONTEXT_RESP` 的结果列表按 context 顺序返回。正例要求在已有 association 上先完成 BIND，再对新 context 执行 ALTER；不得把 ALTER 当成新的 TCP handshake。Reject/unsupported result 必须停止该 context 的后续调用。

### 4.3 REQUEST、RESPONSE、FAULT

REQUEST body 的固定字段依次为 `alloc_hint(4)`、`context_id(2)`、`opnum(2)`，若 PFC_OBJECT_UUID 置位再有 object UUID(16)，随后是 stub（存根）NDR bytes。RESPONSE body 为 `alloc_hint(4)`、`context_id(2)`、`cancel_count(1)`、`reserved(1)`，随后 response stub。FAULT body 为 `alloc_hint(4)`、`context_id(2)`、`cancel_count(1)`、`reserved(1)`、`status(4)`、`reserved2(4)`，随后 fault stub。

同一 `call_id` 关联一个 REQUEST 与 RESPONSE 或 FAULT；并发 call 的 call ID 必须 distinct。`context_id` 必须来自已 accepted 的 BIND/ALTER context；未知 context、错 opnum、FAULT 后继续发送成功 RESPONSE 都属于错误状态。EPM request/response 的 operation 与 dynamic interface request 分开计数，不将 EPM mapper 地址查询伪装成目标接口业务。

## 5. NDR（网络数据表示）可观察契约

NDR stub 以 DataRepresentation 声明的字节序编码 scalar。每个复合值的起始位置必须满足自然对齐：2-byte 值对齐 2，4-byte 值对齐 4，8-byte 值对齐 8；padding bytes 计入 stub length，不能被跳过或挪到 trailer。

- **Pointer**：`unique`/`ref`/`full` pointer 的 referent ID 是 4-byte 动态值；断言 pointer presence、referent nonzero/zero 语义和 pointee 对齐，不硬编码随机 referent。
- **Conformant/varying array**：先有最大 count、offset、actual count，再按元素宽度编码；count/offset/actual count 不得乘法溢出，数组值不能超出 stub。
- **Struct**：字段按 NDR 对齐顺序排列，尾部 padding 与下一个字段的 offset 一致；不得按语言 struct 内存布局猜测。
- **Union**：discriminant 先按其宽度对齐并编码，选择 arm 后只出现对应 arm 的 NDR 表示；未知 discriminant、arm 越界或同时出现多个 arm 必须失败。
- **String/byte array**：长度字段计字节或元素必须由 fixture 声明，UTF-16 字符串按 2-byte code unit；NUL/长度一致性和承载边界必须可验证。

NDR 校验必须在 stub 边界内完成。`alloc_hint` 是调用提示，不得替代实际 stub/fragment length；多 fragment 重组后才比较完整数组、pointer、union。NDR alignment 的 padding 不得被当作 authentication trailer。

## 6. Fragment、TCP record boundary 和认证 trailer

当一个 PDU 超过单个输出 record，使用同一 call ID、context ID 和 `alloc_hint` 产生多个 fragments；首片有 PFC_FIRST_FRAG，末片有 PFC_LAST_FRAG，中间片不能伪造完整 request/response header。每个 fragment 自有 common header 和 `frag_len`；验证器按 TCP stream 先切出完整 PDU，再按 call ID/flags 重组 stub。多个 PDU 可以合并在一个 TCP segment，不能按 segment 一对一映射。

`auth_len=0` 时 PDU 结束于 stub/pad。`auth_len>0` 时，按规范先补齐 pad，再由 verifier trailer 的 auth type/level/context/credentials length 确定边界；只断言 `auth_len`、trailer 存在、长度闭合、PDU 内不越界以及跨 fragment 的关联。NTLM/Kerberos credentials、signature、MIC、sequence number 和 session key 皆为 opaque bytes，不能编造或硬编码加密内容。认证失败只能表现为明确 fault/reject 或 task error，不得静默降级为 unauthenticated success。

## 7. EPM 与 dynamic endpoint

P-EPM 固定 TCP/135，至少包含 BIND 到 EPM interface、一个 endpoint-map request、对应 response 和正常关闭；EPM response 中的 tower/annotation/endpoint bytes 只按长度、UUID、protocol/port 边界观察。EPM 返回的 dynamic port 是运行期或 fixture 声明值；P-DYNAMIC 必须新建 TCP session，使用该端口绑定目标 abstract syntax，再执行调用。不能把一个 session 的 EPM call ID、association group 或 context 状态复制到另一 session。

IPv4 和 IPv6 fixture 独立建立 outer address family；IPv6 断言 Next Header=6 和 TCP stream，不能因为使用相同 interface UUID 而复用 IPv4 packet bytes。EPM 135 与 dynamic port 的四元组、TCP stream、call ID 和 context ID 均按 session 隔离。

## 8. 边界、错误传播和安全限制

至少覆盖：common header 16-byte minimum、每种 packet type 的固定字段、`frag_len=16`/最大附近、`auth_len=0`/非零、CallId presence/distinct/same_as、BIND 多 context、ALTER 新 context、abstract/transfer syntax UUID/version、NDR 对齐/pointer/array/union、EPM 135、dynamic endpoint、IPv4/IPv6、多个 PDU 合并 segment、PDU 跨 segment、FAULT、截断和溢出。

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。每个负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `dcerpc_neg_common_truncated` | common header 少于 16 bytes、未知 version/type 或 flags 非法 | `header`、`version` 或 `packet` |
| `dcerpc_neg_frag_auth_length` | frag_len/auth_len 不一致、越界、溢出或 fragment flags 不闭合 | `frag`、`auth`、`length` 或 `fragment` |
| `dcerpc_neg_context_syntax` | context ID 重复/未知、UUID/version 缺失或 transfer syntax 不匹配 | `context`、`syntax` 或 `uuid` |
| `dcerpc_neg_ndr_bounds` | alignment/padding、pointer、array、union/count 超界或溢出 | `ndr`、`alignment`、`pointer`、`array` 或 `union` |
| `dcerpc_neg_auth_trailer` | auth trailer 越界、auth_len 与 verifier 不符、伪造加密字段 | `auth`、`trailer` 或 `verifier` |
| `dcerpc_neg_carrier_profile` | 非 TCP、EPM/dynamic 端口错、跨 session 拼接或错误 IP family | `carrier`、`transport`、`endpoint` 或 `profile` |

合法的 empty stub、auth_len=0、FAULT、dynamic port、跨 TCP segmentation、多个 PDU/segment 和动态 UUID/call ID 由正例覆盖，不能误报为负例。错误传播须保留原始原因，不能用通用“0 packets”替代验证错误。

## 9. PCAP/NIC 观察与完成定义

实现注册后先检查 `tshark -G fields | grep -E '\t(dcerpc|epm|tcp)\.'`。若环境没有 DCERPC dissector（解析器），使用通用 `tcp` 字段、端口、stream、稳定 raw frames 和本文 common-header 偏移断言，不自创 `dcerpc.*` 字段。正例断言：TCP/135 或 dynamic port、方向、stream、version/type/flags/data representation、frag/auth length、动态 call ID、PDU 重组、context/UUID 长度和 NDR stub boundary。认证 opaque 内容只用 presence/nonzero/same_as/length。

PCAP 与 NIC 模式需分别记录输出接口和过滤器 `tcp port 135` 或目标 dynamic port，并注明 checksum offload、TCP segmentation offload 与未解密 auth trailer 的观察边界。NIC 捕获不能把硬件分段视为 DCE/RPC fragment；验证器应先重组 TCP stream 和 DCE/RPC PDU。

完成定义：注册 `dcerpc` layer；EPM 与 dynamic profile 均能走 planner→worker→TCP output；common header、PDU 类型、BIND/ACK/ALTER、REQUEST/RESPONSE/FAULT、context syntax、NDR、fragment/reassembly、auth opaque boundary 和错误传播均可验证；-race 与集成测试覆盖多 session/context/call、IPv4/IPv6 及 TCP record boundary；未授权密钥下没有伪造 NTLM/Kerberos trailer 内容。

## 10. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 `63-dcerpc-testcase.md` §2 及未来注册后的 `dcerpc.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

## 11. 三方契约和实现后检查

1. 本文 §10、`63-dcerpc-testcase.md` §2、未来注册后的 `dcerpc.json` 和审计文档必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计数的 `dcerpc_neg_unregistered`。
2. 未来 14 个正例均需有 `packet_count`/`min_packets`、方向/stream、稳定 common-header/raw fields；6 个负例的 `expect` 键集合必须恰为 `expect_error`、`error_contains`。
3. Common header 固定 16 bytes，version=5/minor=0；packet type、flags、data representation、frag_len、auth_len 和 call_id 的字节序与 PDU 类型必须按实际线格式断言。
4. `frag_len` 从 common header 起计并包含 pad/auth trailer；`auth_len` 不得越界；fragment flags、call ID 和 PDU 重组必须独立于 TCP segment boundary。
5. BIND/ACK/ALTER context ID 不重复，abstract/transfer syntax UUID+version 完整且 result 对应请求；EPM/动态 endpoint 的 session 状态不串用。
6. REQUEST/RESPONSE/FAULT 以 call ID/context ID 关联；FAULT 后不得伪造同调用成功响应；多 call 使用 distinct，fragment 使用 same_as。
7. NDR 的自然对齐、padding、pointer referent、array count/offset/actual count、union discriminant/arm 和 stub bounds 必须逐路径测试；不能只检查对象结构。
8. 认证 trailer 只能验证 auth type/level/length/boundary/opaque presence；不得伪造或硬编码 NTLM/Kerberos 密文、MIC、签名或 session key。
9. IPv4/IPv6、TCP/135 与 dynamic port、PCAP/NIC 观察过滤器必须独立；未解密/未注册场景不能宣称 DCERPC suite 通过。
10. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/dcerpc.json` 应成功；当前数组只能含 `dcerpc_neg_unregistered`，且 `proto=dcerpc`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 12. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 DCE/RPC over TCP 正例和 6 个严格负例，覆盖 EPM/动态端点、common header、BIND/ACK/ALTER、REQUEST/RESPONSE/FAULT、context syntax、NDR、fragment/TCP record boundary、auth opaque、多 session/call、IPv4/IPv6、PCAP/NIC 和错误传播；不修改 Go 实现。
