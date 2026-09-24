# DCERPC（分布式计算环境远程过程调用，DCE/RPC）测试用例契约

> 版本：v2.0.1（行为面全枚举，ID 权威；P5 校准注记在 §1/状态行）
> 日期：2026-09-24
> 配套设计：`docs/protocol-designs/63-dcerpc-design.md` v2.0.0
> 机器契约：`trafficgen/test/protocol_pcap/cases/dcerpc.json`（80 例=48 正+32 负）
> 状态：P5 全绿（2026-09-24，80/80 ×2）；占位已移除；§4 补断言通道勘误——sec_trailer 字段（dcerpc.auth_type/level/pad_len）在 opaque 凭据下 tshark 不渲染（含 bind+auth 前导），auth 三例退化帧 hex 权威；EPM 深观察两例用真 epm_Lookup 线格式（请求 40B 全 NULL/零；应答 handle20+num_ents+ucarray(max,off,act)+entry+tower 后置+rc——wireshark epm 分解器源码实证）；多会话=按会话块序展开（同四元组会话合并单连接，跨端口会话块间按序）。

## 1. 测试原则

用例从设计 §2–§8 逐项派生；ID 权威=本文 §2（80 例），cases/dcerpc.json、T-DCERPC 与本文三方同序同集合。验证先 TCP stream 重组再按 frag_len 切 PDU；TCP record ≠ PDU 边界。auth trailer 只断言 type/level/长度/边界/opaque。正例断言 packet_count、方向、`dcerpc.*` fields（实现前先 `tshark -G fields` 实证 dissector 存在性；无则按契约 §9 退化 tcp+raw frames）+ frames offset 54（IPv4 TCP 载体 payload 起点 14+20+20）hex 钉；负例 expect 恰 {expect_error, error_contains} 单锚词。

## 2. 原子用例索引（ID 权威——80 = 48 正 + 32 负）

| # | ID | 型 | 覆盖 |
|---:|---|---|---|
| 1 | dcerpc_epm_ipv4_bind_lookup | 正 | TCP/135 EPM bind→lookup→response 基线（IPv4） |
| 2 | dcerpc_epm_ipv6_bind_lookup | 正 | IPv6 独立 EPM session（ipv6.nxt=6） |
| 3 | dcerpc_dynamic_ipv4_profile | 正 | EPM 查询→动态端口（显式）独立 session 调用 |
| 4 | dcerpc_dynamic_ipv6_profile | 正 | 同上 IPv6 |
| 5 | dcerpc_common_header_fields | 正 | 七型 PDU 混排：ver/type/flags/drep/frag/auth/call_id 逐字段 |
| 6 | dcerpc_bind_multi_context | 正 | 一 BIND 双 context+双 transfer syntax、result 逐项对应 |
| 7 | dcerpc_bind_single_context_min | 正 | 最小合法 BIND（单 ctx 单 syntax） |
| 8 | dcerpc_bind_ack_secondary_address | 正 | secondary address "1025" 长度前缀+对齐 |
| 9 | dcerpc_bind_ack_secondary_empty | 正 | secondary address 空串形态 |
| 10 | dcerpc_bind_ack_rejected_result | 正 | result=2 provider rejection 传播 |
| 11 | dcerpc_bind_ack_assoc_group | 正 | assoc_group_id 显式值回带 |
| 12 | dcerpc_alter_context | 正 | 已绑定 association 新增 context→ALTER_RESP |
| 13 | dcerpc_alter_context_resp_reject | 正 | ALTER_RESP rejected→该 context 后续拒（负例侧呼应） |
| 14 | dcerpc_request_response_ndr | 正 | REQUEST/RESPONSE call_id 同值、opnum、NDR scalar+struct |
| 15 | dcerpc_fault_status | 正 | REQUEST→FAULT status、call 终态 |
| 16 | dcerpc_ndr_pointer_array_union | 正 | pointer referent+conformant array 三计数+union 单 arm |
| 17 | dcerpc_ndr_scalars_hyper | 正 | 8B hyper 对齐/LE |
| 18 | dcerpc_ndr_utf16_string | 正 | UTF-16 max/offset/actual 2B code unit |
| 19 | dcerpc_ndr_conformant_array | 正 | max/offset/actual+元素 LE |
| 20 | dcerpc_ndr_unique_pointer_null | 正 | referent=0 NULL 语义 |
| 21 | dcerpc_ndr_struct_padding | 正 | 尾部 padding 计入 stub |
| 22 | dcerpc_auth_trailer_opaque | 正 | auth_len>0、pad/trailer 闭合、opaque credentials |
| 23 | dcerpc_auth_pad_2bytes | 正 | pad=2 与实际填充一致 |
| 24 | dcerpc_auth_type_level_variants | 正 | type/level 组合矩阵代表值 |
| 25 | dcerpc_multi_context_call_session | 正 | 2 session×2 ctx×并发 2 call 隔离 |
| 26 | dcerpc_fragment_first_last | 正 | REQUEST 拆 2 片 FIRST/LAST+重组 |
| 27 | dcerpc_fragment_three_pieces | 正 | 3 片（首/中/末）flags 矩阵 |
| 28 | dcerpc_multi_pdu_back_to_back | 正 | 多 PDU 背靠背（PDU≠TCP record 观察面） |
| 29 | dcerpc_frag_len_min | 正 | 最小合法 PDU（BIND frag_len 下限附近） |
| 30 | dcerpc_call_id_boundary | 正 | call_id 0 与 4294967295 |
| 31 | dcerpc_call_id_adjacent | 正 | 相邻值 1/2 应答配对 |
| 32 | dcerpc_opnum_boundary | 正 | opnum 0 与 65535 |
| 33 | dcerpc_context_id_zero | 正 | context_id=0 最小值 |
| 34 | dcerpc_alloc_hint_variants | 正 | alloc_hint 0 与≠实际 stub（合法提示） |
| 35 | dcerpc_request_object_uuid | 正 | PFC_OBJECT_UUID 置位+16B object UUID |
| 36 | dcerpc_response_cancel_count | 正 | cancel_count>0 |
| 37 | dcerpc_fault_status_boundary | 正 | status 边界值（rpc_s 域） |
| 38 | dcerpc_empty_stub | 正 | 合法 empty stub |
| 39 | dcerpc_prebound_profile | 正 | fixture 声明 prebound（跳 bind 直接调用合法面） |
| 40 | dcerpc_multi_session_sequential | 正 | 多会话按序整块展开 |
| 41 | dcerpc_concurrent_sessions | 正 | concurrent 交错（up 帧源 IP 交替） |
| 42 | dcerpc_max_xmit_recv_frag | 正 | max_xmit/max_recv 变体（5840/0xFFFF 边界） |
| 43 | dcerpc_epm_tower_variants | 正 | tower 长度/UUID/端口边界（EPM response 内观察） |
| 44 | dcerpc_epm_annotation | 正 | annotation 长度前缀字符串 |
| 45 | dcerpc_bind_ack_reject_then_altctx | 正 | reject 后 ALTER 换 syntax 成功 |
| 46 | dcerpc_large_stub | 正 | 1024B 级 stub（frag_len 扩展） |
| 47 | dcerpc_port_dynamic_declared | 正 | 动态端口显式声明（非 135，tshark DecodeAs 口径） |
| 48 | dcerpc_uuid_encoding_authority | 正 | MS/AD 混合端序 UUID 逐字节钉（编解码权威） |
| 49 | dcerpc_neg_version_not5 | 负 | version≠5 | header |
| 50 | dcerpc_neg_version_minor_not0 | 负 | minor≠0 | version |
| 51 | dcerpc_neg_packet_type_unknown | 负 | 未知 type | packet |
| 52 | dcerpc_neg_packet_type_reserved | 负 | 不产生型（如 SHUTDOWN=6） | packet |
| 53 | dcerpc_neg_flags_first_no_last | 负 | FIRST 置位无 LAST | fragment |
| 54 | dcerpc_neg_flags_last_no_first | 负 | LAST 置位无 FIRST | fragment |
| 55 | dcerpc_neg_drep_not_le | 负 | drep≠10000000 | drep |
| 56 | dcerpc_neg_frag_len_lt16 | 负 | frag_len<16 | frag |
| 57 | dcerpc_neg_frag_len_mismatch | 负 | frag_len≠实际 | length |
| 58 | dcerpc_neg_auth_len_over | 负 | auth_len 越 frag_len-24 | auth |
| 59 | dcerpc_neg_call_id_reuse | 负 | 并发 call_id 撞车 | call |
| 60 | dcerpc_neg_call_mismatch | 负 | 应答 call 与 open 集不符 | call |
| 61 | dcerpc_neg_state_ack_no_call | 负 | 应答无前置请求 | state |
| 62 | dcerpc_neg_state_request_unbound | 负 | bound 前 request | state |
| 63 | dcerpc_neg_context_duplicate | 负 | 同 BIND context_id 重复 | context |
| 64 | dcerpc_neg_context_unknown | 负 | 引用未 accepted context | context |
| 65 | dcerpc_neg_syntax_mismatch | 负 | rejected 后仍用该 context | syntax |
| 66 | dcerpc_neg_uuid_version_missing | 负 | abstract syntax version 缺字段 | uuid |
| 67 | dcerpc_neg_alloc_hint_negative | 负 | alloc_hint 越域 | hint |
| 68 | dcerpc_neg_ndr_alignment | 负 | NDR padding 缺失 | ndr |
| 69 | dcerpc_neg_ndr_array_count | 负 | count 越 stub | array |
| 70 | dcerpc_neg_ndr_union_unknown | 负 | 未知 discriminant | union |
| 71 | dcerpc_neg_ndr_stub_overflow | 负 | stub 越界 | ndr |
| 72 | dcerpc_neg_auth_pad_invalid | 负 | pad_length≠实际填充 | trailer |
| 73 | dcerpc_neg_auth_trailer_over | 负 | trailer 越 frag_len | trailer |
| 74 | dcerpc_neg_auth_verifier_len | 负 | auth_len 与 credentials 不符 | verifier |
| 75 | dcerpc_neg_carrier_layer_missing | 负 | 缺 tcp 载体 | carrier |
| 76 | dcerpc_neg_carrier_udp | 负 | udp 载体声明 | carrier |
| 77 | dcerpc_neg_port_undeclared | 负 | 非默认端口未声明 | port |
| 78 | dcerpc_neg_address_family_mismatch | 负 | IPv4/IPv6 混地址族 | family |
| 79 | dcerpc_neg_uuid_width | 负 | UUID 非 16B 渲染宽 | uuid |
| 80 | dcerpc_neg_assoc_group_width | 负 | assoc_group 超宽 | width |

（49-80 为 wire_fault 注入通道；自然面守卫值随 P4 落码据实勘误——处置表 17 自然+15 注入初版分类见设计 §7。）

## 3. 簇级断言要点

- **①双 profile×地址族（1-4）**：EPM 会话 BIND interface E1AF8308-...A0FA v3.0 + opnum=2 lookup；dynamic 会话端口显式且≠135；两 session call_id/assoc/ctx 不串用；IPv6 断言 ipv6.nxt=6。
- **②common header（5、29-32）**：16B 逐字段；frag_len 含全部；call_id 0/最大/相邻。
- **③④⑤BIND/ALTER/调用（6-15、35-38、42、45）**：context 编码/结果对应/FAULT 终态/empty stub 合法。
- **⑥NDR（16-21）**：对齐 padding 计入 stub、pointer NULL 语义、array 三计数、union 单 arm、UTF-16 code unit。
- **⑦auth（22-24）**：pad 0-3 与实际一致、credentials opaque presence/length。
- **⑧分片与多 PDU（26-28）**：FIRST/LAST 闭合、同 call_id、背靠背多 PDU。
- **⑨多会话多调用（25、40-41）**：会话整块展开/交错、并发 call distinct。
- **⑩UUID 权威（48）**：混合端序逐字节。
- **⑪负例（49-80）**：一行一注入单锚词；expect 恰两键。

## 4. 断言通道纪律

fields 优先 `dcerpc.*`（P4 前用 `tshark -G fields | grep dcerpc` 实证；不存在时退化 `tcp.*`+`tcp.payload` 偏移断言，帧 hex 权威=frames offset 54 逐字节钉）。多出现字段按帧逗号并集断言（bacnet P5 先例）；`frag_len` 断言走 fields 或帧字节（dissector 计算值口径先跑后钉）。has_payload（frame.len>80）不适用短 PDU 帧——不设。动态端口例用 decode_as（顶层键）。

## 5. 存量审计

占位 1 例 `dcerpc_neg_unregistered`（旧扁平形 spec）随注册移除（契约 §1）；无存量语义用例。
