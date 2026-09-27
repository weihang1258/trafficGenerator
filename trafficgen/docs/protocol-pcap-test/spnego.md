# spnego Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| spnego_der_canonical_boundaries | DER 边界：空可选字段 + 短/长 length（200B token 长形 0x82 档）+ 父长度覆盖子 TLV | pass | 9 | [pcap](spnego/spnego_der_canonical_boundaries.pcap) |
| spnego_downgrade_prevention | 降级防护：selectedMech ∈ 列表 + reject(2)→终止；supportedMech 由会话级覆盖钉死 | pass | 9 | [pcap](spnego/spnego_downgrade_prevention.pcap) |
| spnego_http_ipv4_init | HTTP Negotiate/IPv4：401→Authorization(init)→WWW-Authenticate(resp)→200 + InitialContextToken/negTokenInit | pass | 11 | [pcap](spnego/spnego_http_ipv4_init.pcap) |
| spnego_http_ipv6_init | HTTP Negotiate/IPv6 独立 fixture：ipv6.nxt=6 + 地址族 + HTTP Negotiate 方向与 DER 外层 | pass | 11 | [pcap](spnego/spnego_http_ipv6_init.pcap) |
| spnego_mech_oid_variants | 三机制 OID 变体：Kerberos/msKrb5/NTLM 逐字节 DER + supportedMech 列表绑定 | pass | 9 | [pcap](spnego/spnego_mech_oid_variants.pcap) |
| spnego_mech_token_opaque | 不透明 token：零长占位 + 非零负载 + OCTET STRING length/nonzero（内层不解析） | pass | 9 | [pcap](spnego/spnego_mech_token_opaque.pcap) |
| spnego_mechlist_mic | mechListMIC：request-mic(3)→补 MIC；验证输入=原始 DER mechTypes；线位 RFC [3] | pass | 10 | [pcap](spnego/spnego_mechlist_mic.pcap) |
| spnego_multi_session_stream | 多流多会话隔离：flows=2 两条独立 TCP stream（45061/45062→445，四元组隔离）+ 每流 s1(Kerberos+msKrb5→accept_completed)/s2(NTLM→reject 异常终止) 会话；候选列表/选定机制/状态不串用 | pass | 22 | [pcap](spnego/spnego_multi_session_stream.pcap) |
| spnego_neg_carrier_profile | HTTP/TCP profile/端口/stream 边界错误（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_der_length_overflow | 长形式溢出/父子长度不一致/非最短编码（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_der_truncated | DER tag/length/子 TLV 截断（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_invalid_token_choice | 未知 choice/错误 tag class/init-resp-targ 混用（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_mech_oid_selection | 非法 OID/选定机制绑定错误（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_mic_downgrade | MIC 缺失/不匹配/列表改写或降级选择（wire_fault 注入） | pass | 0 | [pcap]() |
| spnego_neg_token_init_hints | negTokenInit：有序 mechTypes + reqFlags + negHints([3] dissector 形) + mechToken；RFC 形 MIC 不共存 | pass | 11 | [pcap](spnego/spnego_neg_token_init_hints.pcap) |
| spnego_neg_token_resp_selection | negTokenResp：negResult + supportedMech(∈列表) + responseToken；accept_incomplete(1)→completed | pass | 11 | [pcap](spnego/spnego_neg_token_resp_selection.pcap) |
| spnego_neg_token_targ_legacy | 旧式 negTokenTarg：显式 init_targ 声明 + [0]negResult/[1]supportedMech/[2]responseToken 字段序 | pass | 9 | [pcap](spnego/spnego_neg_token_targ_legacy.pcap) |
| spnego_pcap_nic_consistency | PCAP/NIC 双路一致：TCP carrier/方向/端口/HTTP header/DER 外层/OID/token 长度一致 | pass | 11 | [pcap](spnego/spnego_pcap_nic_consistency.pcap) |
| spnego_tcp_ipv4_init | 裸 TCP/IPv4 stream 携带 InitialContextToken/negTokenInit：重组 stream + DER 父长度 + SPNEGO OID | pass | 9 | [pcap](spnego/spnego_tcp_ipv4_init.pcap) |
| spnego_tcp_ipv6_init | 裸 TCP/IPv6 stream 携带 token：ipv6.nxt=6 + IPv6 checksum + token 重组 | pass | 9 | [pcap](spnego/spnego_tcp_ipv6_init.pcap) |
