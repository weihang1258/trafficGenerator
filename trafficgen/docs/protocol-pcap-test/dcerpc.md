# dcerpc Pcap Test Results

Cases: 80 — pass 80, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dcerpc_alloc_hint_variants | alloc_hint 0 与≠实际 stub（合法提示） | pass | 11 | [pcap](dcerpc/dcerpc_alloc_hint_variants.pcap) |
| dcerpc_alter_context | 已绑定 association 新增 context→ALTER_RESP | pass | 11 | [pcap](dcerpc/dcerpc_alter_context.pcap) |
| dcerpc_alter_context_resp_reject | ALTER_RESP rejected→该 context 后续拒（负例侧呼应） | pass | 11 | [pcap](dcerpc/dcerpc_alter_context_resp_reject.pcap) |
| dcerpc_auth_pad_2bytes | pad=2 与实际填充一致 | pass | 10 | [pcap](dcerpc/dcerpc_auth_pad_2bytes.pcap) |
| dcerpc_auth_trailer_opaque | auth_len>0、pad/trailer 闭合、opaque credentials | pass | 10 | [pcap](dcerpc/dcerpc_auth_trailer_opaque.pcap) |
| dcerpc_auth_type_level_variants | type/level 组合矩阵代表值 | pass | 11 | [pcap](dcerpc/dcerpc_auth_type_level_variants.pcap) |
| dcerpc_bind_ack_assoc_group | assoc_group_id 显式值回带（ack assoc 777=0x309） | pass | 9 | [pcap](dcerpc/dcerpc_bind_ack_assoc_group.pcap) |
| dcerpc_bind_ack_reject_then_altctx | reject 后 ALTER 换 syntax 成功 | pass | 11 | [pcap](dcerpc/dcerpc_bind_ack_reject_then_altctx.pcap) |
| dcerpc_bind_ack_rejected_result | result=2 provider rejection 传播 | pass | 9 | [pcap](dcerpc/dcerpc_bind_ack_rejected_result.pcap) |
| dcerpc_bind_ack_secondary_address | secondary address "1025" 长度前缀+对齐 | pass | 9 | [pcap](dcerpc/dcerpc_bind_ack_secondary_address.pcap) |
| dcerpc_bind_ack_secondary_empty | secondary address 空串形态 | pass | 9 | [pcap](dcerpc/dcerpc_bind_ack_secondary_empty.pcap) |
| dcerpc_bind_multi_context | 一 BIND 双 context+双 transfer syntax、result 逐项对应 | pass | 9 | [pcap](dcerpc/dcerpc_bind_multi_context.pcap) |
| dcerpc_bind_single_context_min | 最小合法 BIND（单 ctx 单 syntax） | pass | 8 | [pcap](dcerpc/dcerpc_bind_single_context_min.pcap) |
| dcerpc_call_id_adjacent | 相邻值 7/8 应答配对 | pass | 11 | [pcap](dcerpc/dcerpc_call_id_adjacent.pcap) |
| dcerpc_call_id_boundary | call_id 0 与 4294967295 | pass | 11 | [pcap](dcerpc/dcerpc_call_id_boundary.pcap) |
| dcerpc_common_header_fields | 七型 PDU 混排：ver/type/flags/drep/frag/call_id 逐字段 | pass | 15 | [pcap](dcerpc/dcerpc_common_header_fields.pcap) |
| dcerpc_concurrent_sessions | concurrent 交错（双会话按 event index 交替） | pass | 20 | [pcap](dcerpc/dcerpc_concurrent_sessions.pcap) |
| dcerpc_context_id_zero | context_id=0 最小值 | pass | 11 | [pcap](dcerpc/dcerpc_context_id_zero.pcap) |
| dcerpc_dynamic_ipv4_profile | EPM 查询→动态端口（4135 显式）独立 session 调用 | pass | 20 | [pcap](dcerpc/dcerpc_dynamic_ipv4_profile.pcap) |
| dcerpc_dynamic_ipv6_profile | 同上 IPv6 | pass | 20 | [pcap](dcerpc/dcerpc_dynamic_ipv6_profile.pcap) |
| dcerpc_empty_stub | 合法 empty stub（req/resp 双 24B） | pass | 9 | [pcap](dcerpc/dcerpc_empty_stub.pcap) |
| dcerpc_epm_annotation | annotation 长度前缀字符串 | pass | 11 | [pcap](dcerpc/dcerpc_epm_annotation.pcap) |
| dcerpc_epm_ipv4_bind_lookup | TCP/135 EPM bind→lookup→response 基线（IPv4） | pass | 11 | [pcap](dcerpc/dcerpc_epm_ipv4_bind_lookup.pcap) |
| dcerpc_epm_ipv6_bind_lookup | IPv6 独立 EPM session（ipv6.nxt=6） | pass | 11 | [pcap](dcerpc/dcerpc_epm_ipv6_bind_lookup.pcap) |
| dcerpc_epm_tower_variants | tower 长度/UUID/端口边界（EPM response 内观察） | pass | 11 | [pcap](dcerpc/dcerpc_epm_tower_variants.pcap) |
| dcerpc_fault_status | REQUEST→FAULT status、call 终态 | pass | 9 | [pcap](dcerpc/dcerpc_fault_status.pcap) |
| dcerpc_fault_status_boundary | status 边界值（nca 域 0x1C010003） | pass | 9 | [pcap](dcerpc/dcerpc_fault_status_boundary.pcap) |
| dcerpc_frag_len_min | 最小合法 PDU（empty REQUEST frag_len 24） | pass | 9 | [pcap](dcerpc/dcerpc_frag_len_min.pcap) |
| dcerpc_fragment_first_last | REQUEST 拆 2 片 FIRST/LAST+重组 | pass | 9 | [pcap](dcerpc/dcerpc_fragment_first_last.pcap) |
| dcerpc_fragment_three_pieces | 3 片（首/中/末）flags 矩阵 | pass | 10 | [pcap](dcerpc/dcerpc_fragment_three_pieces.pcap) |
| dcerpc_large_stub | 1024B 级 stub（frag_len 扩展） | pass | 9 | [pcap](dcerpc/dcerpc_large_stub.pcap) |
| dcerpc_max_xmit_recv_frag | max_xmit/max_recv 变体（0xFFFF 边界） | pass | 8 | [pcap](dcerpc/dcerpc_max_xmit_recv_frag.pcap) |
| dcerpc_multi_context_call_session | 2 session×2 ctx×并发 2 call 隔离 | pass | 26 | [pcap](dcerpc/dcerpc_multi_context_call_session.pcap) |
| dcerpc_multi_pdu_back_to_back | 多 PDU 背靠背（PDU≠TCP record 观察面） | pass | 11 | [pcap](dcerpc/dcerpc_multi_pdu_back_to_back.pcap) |
| dcerpc_multi_session_sequential | 多会话按序整块展开（单事件会话→块连续） | pass | 18 | [pcap](dcerpc/dcerpc_multi_session_sequential.pcap) |
| dcerpc_ndr_conformant_array | max/offset/actual+元素 LE | pass | 9 | [pcap](dcerpc/dcerpc_ndr_conformant_array.pcap) |
| dcerpc_ndr_pointer_array_union | pointer referent+conformant array 三计数+union 单 arm | pass | 9 | [pcap](dcerpc/dcerpc_ndr_pointer_array_union.pcap) |
| dcerpc_ndr_scalars_hyper | 8B hyper 对齐/LE | pass | 9 | [pcap](dcerpc/dcerpc_ndr_scalars_hyper.pcap) |
| dcerpc_ndr_struct_padding | 尾部 padding 计入 stub | pass | 9 | [pcap](dcerpc/dcerpc_ndr_struct_padding.pcap) |
| dcerpc_ndr_unique_pointer_null | referent=0 NULL 语义 | pass | 9 | [pcap](dcerpc/dcerpc_ndr_unique_pointer_null.pcap) |
| dcerpc_ndr_utf16_string | UTF-16 max/offset/actual 2B code unit | pass | 9 | [pcap](dcerpc/dcerpc_ndr_utf16_string.pcap) |
| dcerpc_neg_address_family_mismatch | IPv4/IPv6 混地址族 | pass | 0 | [pcap]() |
| dcerpc_neg_alloc_hint_negative | wire_fault 注入：alloc_hint_negative | pass | 0 | [pcap]() |
| dcerpc_neg_assoc_group_width | wire_fault 注入：assoc_group_width | pass | 0 | [pcap]() |
| dcerpc_neg_auth_len_over | wire_fault 注入：auth_len_over | pass | 0 | [pcap]() |
| dcerpc_neg_auth_pad_invalid | wire_fault 注入：auth_pad_invalid | pass | 0 | [pcap]() |
| dcerpc_neg_auth_trailer_over | wire_fault 注入：auth_trailer_over | pass | 0 | [pcap]() |
| dcerpc_neg_auth_verifier_len | wire_fault 注入：auth_verifier_len | pass | 0 | [pcap]() |
| dcerpc_neg_call_id_reuse | wire_fault 注入：call_id_reuse | pass | 0 | [pcap]() |
| dcerpc_neg_call_mismatch | wire_fault 注入：call_mismatch | pass | 0 | [pcap]() |
| dcerpc_neg_carrier_layer_missing | 缺 tcp 载体 | pass | 0 | [pcap]() |
| dcerpc_neg_carrier_udp | udp 载体声明 | pass | 0 | [pcap]() |
| dcerpc_neg_context_duplicate | wire_fault 注入：context_duplicate | pass | 0 | [pcap]() |
| dcerpc_neg_context_unknown | wire_fault 注入：context_unknown | pass | 0 | [pcap]() |
| dcerpc_neg_drep_not_le | wire_fault 注入：drep_not_le | pass | 0 | [pcap]() |
| dcerpc_neg_flags_first_no_last | wire_fault 注入：flags_first_no_last | pass | 0 | [pcap]() |
| dcerpc_neg_flags_last_no_first | wire_fault 注入：flags_last_no_first | pass | 0 | [pcap]() |
| dcerpc_neg_frag_len_lt16 | wire_fault 注入：frag_len_lt16 | pass | 0 | [pcap]() |
| dcerpc_neg_frag_len_mismatch | wire_fault 注入：frag_len_mismatch | pass | 0 | [pcap]() |
| dcerpc_neg_ndr_alignment | wire_fault 注入：ndr_alignment | pass | 0 | [pcap]() |
| dcerpc_neg_ndr_array_count | wire_fault 注入：ndr_array_count | pass | 0 | [pcap]() |
| dcerpc_neg_ndr_stub_overflow | wire_fault 注入：ndr_stub_overflow | pass | 0 | [pcap]() |
| dcerpc_neg_ndr_union_unknown | wire_fault 注入：ndr_union_unknown | pass | 0 | [pcap]() |
| dcerpc_neg_packet_type_reserved | wire_fault 注入：packet_type_reserved | pass | 0 | [pcap]() |
| dcerpc_neg_packet_type_unknown | wire_fault 注入：packet_type_unknown | pass | 0 | [pcap]() |
| dcerpc_neg_port_undeclared | wire_fault 注入：port_undeclared | pass | 0 | [pcap]() |
| dcerpc_neg_state_ack_no_call | wire_fault 注入：state_ack_no_call | pass | 0 | [pcap]() |
| dcerpc_neg_state_request_unbound | wire_fault 注入：state_request_unbound | pass | 0 | [pcap]() |
| dcerpc_neg_syntax_mismatch | wire_fault 注入：syntax_mismatch | pass | 0 | [pcap]() |
| dcerpc_neg_uuid_version_missing | wire_fault 注入：uuid_version_missing | pass | 0 | [pcap]() |
| dcerpc_neg_uuid_width | wire_fault 注入：uuid_width | pass | 0 | [pcap]() |
| dcerpc_neg_version_minor_not0 | wire_fault 注入：version_minor_not0 | pass | 0 | [pcap]() |
| dcerpc_neg_version_not5 | wire_fault 注入：version_not5 | pass | 0 | [pcap]() |
| dcerpc_opnum_boundary | opnum 0 与 65535 | pass | 11 | [pcap](dcerpc/dcerpc_opnum_boundary.pcap) |
| dcerpc_port_dynamic_declared | 动态端口显式声明（非 135，tshark DecodeAs 口径） | pass | 9 | [pcap](dcerpc/dcerpc_port_dynamic_declared.pcap) |
| dcerpc_prebound_profile | fixture 声明 prebound（跳 bind 直接调用合法面） | pass | 9 | [pcap](dcerpc/dcerpc_prebound_profile.pcap) |
| dcerpc_request_object_uuid | PFC_OBJECT_UUID 置位+16B object UUID | pass | 9 | [pcap](dcerpc/dcerpc_request_object_uuid.pcap) |
| dcerpc_request_response_ndr | REQUEST/RESPONSE call_id 同值、opnum、NDR scalar+struct | pass | 9 | [pcap](dcerpc/dcerpc_request_response_ndr.pcap) |
| dcerpc_response_cancel_count | cancel_count>0 | pass | 9 | [pcap](dcerpc/dcerpc_response_cancel_count.pcap) |
| dcerpc_uuid_encoding_authority | MS/AD 混合端序 UUID 逐字节钉（编解码权威） | pass | 9 | [pcap](dcerpc/dcerpc_uuid_encoding_authority.pcap) |
