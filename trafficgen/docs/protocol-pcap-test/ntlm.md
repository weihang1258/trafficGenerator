# ntlm Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ntlm_authenticate_security_buffers | Type 3：LM/NT/domain/user/workstation/sessionkey 六类 Len/MaxLen/Offset（MaxLen>Len 档，MaxLen=Len+8） | pass | 11 | [pcap](ntlm/ntlm_authenticate_security_buffers.pcap) |
| ntlm_challenge_target_info | Type 2：8-byte ServerChallenge nonzero + TargetInfo AV 序列（已知 1/2/3/4/5/6/7/9 + 扩展 10，EOL 收尾） | pass | 11 | [pcap](ntlm/ntlm_challenge_target_info.pcap) |
| ntlm_http_negotiate_v2 | P-HTTP 明文 TCP/80：401 Negotiate → Type 1 → Type 2 → Type 3 → 2xx | pass | 11 | [pcap](ntlm/ntlm_http_negotiate_v2.pcap) |
| ntlm_mic_session_key_opaque | MIC（16B）/EncryptedRandomSessionKey（16B）长度与 opaque 边界（无密钥不比较值） | pass | 11 | [pcap](ntlm/ntlm_mic_session_key_opaque.pcap) |
| ntlm_multi_flow_streams | 多 TCP stream/方向 + segmentation：分段后按 stream 重组 token（offset 相对 NTLMSSP 起点） | pass | 15 | [pcap](ntlm/ntlm_multi_flow_streams.pcap) |
| ntlm_multi_session_isolation | 多会话：独立 ServerChallenge/client challenge/SecurityBuffer/结果（跨 session 无 same_as） | pass | 15 | [pcap](ntlm/ntlm_multi_session_isolation.pcap) |
| ntlm_neg_carrier_profile | SMB/HTTP 混用、非 TCP 载体、错误端口、SPNEGO 边界错误（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_neg_flags_target_info | flags 互不兼容、TargetInfo 缺失/越界、未知 reserved bits（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_neg_message_truncated | 通用头/三类消息固定字段截断（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_neg_offsets_overlap_overflow | Offset+Len 溢出、越界、固定头重叠或字段重叠（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_neg_security_buffer | Len/MaxLen 不一致、非偶数 Unicode、空字段伪造或 token 截断（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_neg_v2_blob_av_pairs | proof/blob 长度错误、AV_PAIR 越界/缺 EOL/重复非法（wire_fault 注入） | pass | 0 | [pcap]() |
| ntlm_negotiate_flags_version | flags 交集一致：会话 A 声明 NEGOTIATE_VERSION（8-byte Version，major=10）/ 会话 B 省略（Version 缺席） | pass | 15 | [pcap](ntlm/ntlm_negotiate_flags_version.pcap) |
| ntlm_ntlmv2_blob_av_pairs | NTLMv2 response：16-byte proof + blob（RV/HRV=1，TS fixture，CC fixture，AV+EOL） | pass | 11 | [pcap](ntlm/ntlm_ntlmv2_blob_av_pairs.pcap) |
| ntlm_pcap_nic_consistency | PCAP/NIC 一致：TCP profile 端口、方向、stream、NTLMSSP Type 与 token 长度一致（过滤器 tcp port 445） | pass | 11 | [pcap](ntlm/ntlm_pcap_nic_consistency.pcap) |
| ntlm_record_boundary_offsets | 最小/最大附近 token：600 字符用户名大包 + 全空身份会话（Offset+Len 不溢出且落在 token 内，UTF-16 偶数长度） | pass | 15 | [pcap](ntlm/ntlm_record_boundary_offsets.pcap) |
| ntlm_retry_auth_failure | challenge 重试（3 轮形态：Type 3 后仍 MORE）+ 最终 STATUS_LOGON_FAILURE（失败后无 authenticated data） | pass | 13 | [pcap](ntlm/ntlm_retry_auth_failure.pcap) |
| ntlm_smb_ipv4_v2_basic | P-SMB IPv4/TCP/445 Type 1→2→3 + STATUS_SUCCESS（NTLMv2） | pass | 11 | [pcap](ntlm/ntlm_smb_ipv4_v2_basic.pcap) |
| ntlm_smb_ipv6_v2_basic | P-SMB IPv6/TCP/445 独立地址族与会话（不复用 IPv4 challenge/stream） | pass | 11 | [pcap](ntlm/ntlm_smb_ipv6_v2_basic.pcap) |
| ntlm_spnego_outer_separation | SPNEGO 外层（GSS InitialContextToken/negTokenResp）与内层 NTLMSSP signature/Type 分界 | pass | 11 | [pcap](ntlm/ntlm_spnego_outer_separation.pcap) |
