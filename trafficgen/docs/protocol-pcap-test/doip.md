# doip Pcap Test Results

Cases: 80 — pass 80, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| doip_ack_code_0x01 | T052/T188: 0x8002 AckCode=0x01 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_alive_mid_messages | T115: AliveCheck 插入 Messages 中间 → 0x0007 在诊断包后 12 包 | pass | 14 | [pcap](doip/doip_alive_mid_messages.pcap) |
| doip_alive_response | T112/T120a: AliveCheck.Direction=up → 0x0008 心跳应答(SA=0x0E80, PL=2) 1 包 | pass | 10 | [pcap](doip/doip_alive_response.pcap) |
| doip_alive_sa_consistent | T113: 0x0008 SA 与 0x0005 SA 一致 (0x0E80) → 通过 9 包 | pass | 10 | [pcap](doip/doip_alive_sa_consistent.pcap) |
| doip_alive_sa_mismatch | T114: 0x0008 SA=0x1111 与 TesterAddress 不一致 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_at_0x01 | T022a: ActivationType=0x01 (WWH-OBD) → 0x0005+0x0006 成功激活 8 包 | pass | 9 | [pcap](doip/doip_at_0x01.pcap) |
| doip_at_0x02 | T022c: ActivationType=0x02 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_at_0xe0 | T022b: ActivationType=0xE0 (OEM) → 0x0005 AT=0xE0 成功激活 8 包 | pass | 9 | [pcap](doip/doip_at_0xe0.pcap) |
| doip_big_transfer_segmented | T184: 大文件 TransferData MSS 分段 → 0x36 多段 0x8001 (BlockSeq 递增) | pass | 11 | [pcap](doip/doip_big_transfer_segmented.pcap) |
| doip_generic_nack_0x00 | T121: 0x0000 NackCode=0x00 Incorrect Pattern → 通过 9 包 | pass | 10 | [pcap](doip/doip_generic_nack_0x00.pcap) |
| doip_generic_nack_0x02 | T123: 0x0000 NackCode=0x02 Message Too Large → 通过 9 包 | pass | 10 | [pcap](doip/doip_generic_nack_0x02.pcap) |
| doip_generic_nack_0x03 | T124: 0x0000 NackCode=0x03 Out of Memory → 通过 9 包 | pass | 10 | [pcap](doip/doip_generic_nack_0x03.pcap) |
| doip_generic_nack_0x04 | T125: 0x0000 NackCode=0x04 Invalid Payload Length → 通过 9 包 | pass | 10 | [pcap](doip/doip_generic_nack_0x04.pcap) |
| doip_generic_nack_0x05 | T126: 0x0000 NackCode=0x05 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_ipv6_activation | T132-T134: IPv6 路由激活流程 (src=fe80::1, dst=fe80::2) 8 包 | pass | 9 | [pcap](doip/doip_ipv6_activation.pcap) |
| doip_ipv6_alive | T135: IPv6 心跳 → 0x0007 over IPv6 9 包 | pass | 10 | [pcap](doip/doip_ipv6_alive.pcap) |
| doip_la_0x0000 | T158: LogicalAddress=0 边界 → 默认回退 0x0001 → 0x0006 CLA=0x0001 8 包 | pass | 9 | [pcap](doip/doip_la_0x0000.pcap) |
| doip_la_ffff | T159: LogicalAddress=0xFFFF 边界值 → 0x0006 CLA=0xFFFF 通过 8 包 | pass | 9 | [pcap](doip/doip_la_ffff.pcap) |
| doip_messages_without_activation | T163: 无 Activation 直接 Messages → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_mss_fallback | T148: MSS=0 fallback 1460 → 0x36 大传输单帧不分割 16 包 | pass | 11 | [pcap](doip/doip_mss_fallback.pcap) |
| doip_nack_0x00 | T060: 0x8003 NackCode=0x00 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_nack_0x01 | T061: 0x8003 NackCode=0x01 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_nack_0x03 | T057: 0x8003 NackCode=0x03 (Unknown TA) → 通过 10 包 | pass | 11 | [pcap](doip/doip_nack_0x03.pcap) |
| doip_nack_0x04 | T058: 0x8003 NackCode=0x04 (Too Large) → 通过 10 包 | pass | 11 | [pcap](doip/doip_nack_0x04.pcap) |
| doip_nack_0x06 | T059: 0x8003 NackCode=0x06 (Target Unreachable) → 通过 10 包 | pass | 11 | [pcap](doip/doip_nack_0x06.pcap) |
| doip_nack_0x09 | T062: 0x8003 NackCode=0x09 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_neg_activation_confirmation_missing | T-DOIP #18: RC=0x11 without confirmation_required -> chain rejects activation failed | pass | 0 | [pcap]() |
| doip_neg_presence | M5 presence: layers + top-level doip:{} coexist -> CheckProtoFlat kills | pass | 0 | [pcap]() |
| doip_neg_stray_count | M5 stray: top-level count with layers -> CheckProtoFlat kills | pass | 0 | [pcap]() |
| doip_neg_stray_src_ip | M5 stray: top-level src_ip with layers -> CheckProtoFlat kills | pass | 0 | [pcap]() |
| doip_neg_udp_carrier | T-DOIP #19: explicit udp carrier [ip,udp,doip] -> carrier reject | pass | 0 | [pcap]() |
| doip_neg_udp_phase_discovery | T-DOIP #20-22: layer discovery non-empty (UDP plane) -> chain precheck rejects | pass | 0 | [pcap]() |
| doip_neg_udp_phase_entity_status | T-DOIP #20-22: layer entity_status non-empty (UDP plane) -> chain precheck rejects | pass | 0 | [pcap]() |
| doip_neg_udp_phase_power_mode | T-DOIP #20-22: layer power_mode non-empty (UDP plane) -> chain precheck rejects | pass | 0 | [pcap]() |
| doip_no_discovery_direct_activation | T162: 无 Discovery 直接 Activation → TCP 握手+激活 8 包 | pass | 9 | [pcap](doip/doip_no_discovery_direct_activation.pcap) |
| doip_oem_255b | T154: OEM-specific=255B → 0x0005 PayloadLength=262 8 包 | pass | 9 | [pcap](doip/doip_oem_255b.pcap) |
| doip_pv_0x00 | T141: ProtocolVersion=0x00 → Validate 拒绝 (ExpectError) | pass | 9 | [pcap](doip/doip_pv_0x00.pcap) |
| doip_pv_0x03 | T142: ProtocolVersion=0x03 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_pv_0xff | T143: ProtocolVersion=0xFF → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_rc_0x01 | T021b: ResponseCode=0x01 (Unknown SA) → 激活失败 ECU FIN → 7 包 | pass | 0 | [pcap]() |
| doip_rc_0x04 | T021c: ResponseCode=0x04 (Missing Auth) → 0x0006 RC=0x04 激活失败 7 包 | pass | 0 | [pcap]() |
| doip_rc_0x05 | T021d: ResponseCode=0x05 (Rejected Confirmation) → 0x0006 RC=0x05 激活失败 7 包 | pass | 0 | [pcap]() |
| doip_rc_0x07 | T021e: ResponseCode=0x07 (TLS Required) → 0x0006 RC=0x07 激活失败 7 包 | pass | 0 | [pcap]() |
| doip_rc_0x11_confirm | T021f/T027: RC=0x11 + ConfirmationRequired=true 二次确认 0x0005×2+0x0006×2 → 10 包 | pass | 11 | [pcap](doip/doip_rc_0x11_confirm.pcap) |
| doip_rc_0x12 | T021g: ResponseCode=0x12 Reserved → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_s10_big_transfer | S10: 0x34 RequestDownload + 0x36 TransferData + 0x37 RequestTransferExit (首块不完整 → 0x36 段化); AddressAndLength/TransferData hex 解码 | pass | 19 | [pcap](doip/doip_s10_big_transfer.pcap) |
| doip_s11_activation_fail | S11/T026: RC=0x00 Unknown SA → 激活失败, 无诊断消息, ECU 主动 FIN 关闭 → 7 包 | pass | 0 | [pcap]() |
| doip_s2_routing_activation | S2/T008+T009: TCP 握手 + 0x0005(SA=0x0E80,AT=0x00,PL=7) + 0x0006(RC=0x10,PL=9) + 挥手中 FIN×3 → 8 包 | pass | 9 | [pcap](doip/doip_s2_routing_activation.pcap) |
| doip_s2_variant_oem4b | T-DOIP #4: OEM-specific 4B (array form) -> 0x0005 len=11 / 0x0006 len=13 | pass | 9 | [pcap](doip/doip_s2_variant_oem4b.pcap) |
| doip_s3_diag_uds10 | S3/T016+T017: 0x8001(SA=0x0E80,TA=0x0001,UDS 10 03) + 0x8002 Ack(PL=7,PrevDiag=10 03) | pass | 11 | [pcap](doip/doip_s3_diag_uds10.pcap) |
| doip_s4_diag_nack | S4/T018: 0x8001(UDS 22 F1 90) + 0x8003 Nack(NackCode=0x02,PL=10,PrevDiag=22 F1 90) | pass | 11 | [pcap](doip/doip_s4_diag_nack.pcap) |
| doip_s5_alive_check | S5/T010+T011: 0x0007 心跳请求(无载荷) 单发; direction=down 不发 0x0008 | pass | 10 | [pcap](doip/doip_s5_alive_check.pcap) |
| doip_s8_generic_nack | S8/T019: 0x0000 Generic NACK (NackCode=0x01 Unknown Payload Type, PL=1) 经 TCP | pass | 10 | [pcap](doip/doip_s8_generic_nack.pcap) |
| doip_sa_consistent | T028/T030: 0x8001 SA=TA=默认 与激活地址一致 → 通过 10 包 | pass | 11 | [pcap](doip/doip_sa_consistent.pcap) |
| doip_sa_mismatch | T029: 0x8001 SA=0x1111 与 TesterAddress 不一致 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_sa_zero_boundary | T189: 0x8001 SA=0x0000 (显式) → 通过 10 包 | pass | 11 | [pcap](doip/doip_sa_zero_boundary.pcap) |
| doip_ta_0x0000 | T160: TesterAddress=0x0000 边界 → 0x0005 SA=0x0E80 (默认回退) 8 包 | pass | 9 | [pcap](doip/doip_ta_0x0000.pcap) |
| doip_ta_ffff_boundary | T190: 0x8001 TA=0xFFFF 与 LogicalAddress 冲突 → 实现要求一致 (impl 差异) 8 包 | pass | 11 | [pcap](doip/doip_ta_ffff_boundary.pcap) |
| doip_tcp_diag_uds_read_write_did | T-DOIP #6: UDS 0x22 request / 0x62 positive response (SID\|0x40) / 0x2E write | pass | 15 | [pcap](doip/doip_tcp_diag_uds_read_write_did.pcap) |
| doip_tcp_full_flow | T-DOIP #13: end-to-end single session — activation, 4 UDS rounds, alive check, teardown | pass | 18 | [pcap](doip/doip_tcp_full_flow.pcap) |
| doip_tcp_multiflow_dynamic | T-DOIP #15: flows=2 sessions, tcp.src_port inc dynamic — distinct 4-tuples | pass | 18 | [pcap](doip/doip_tcp_multiflow_dynamic.pcap) |
| doip_tcp_options_nohandshake | T-DOIP #16: tcp.handshake=false -> no SYN/SYN-ACK/ACK, data starts immediately | pass | 6 | [pcap](doip/doip_tcp_options_nohandshake.pcap) |
| doip_termination_false | T195: Termination=false → 无 FIN 挥手 5 包 | pass | 5 | [pcap](doip/doip_termination_false.pcap) |
| doip_uds_10_nosubfunc_false | T193: 0x10 HasSubFunction=false 仍必须输出 sub-function=0x03 (§8.4 必需字段) → 生成 10 03, PayloadLength=0x06 | pass | 11 | [pcap](doip/doip_uds_10_nosubfunc_false.pcap) |
| doip_uds_22_response_sid | T050/负向修复: 0x22 响应 = RSID(0x62)+DID(2B)+dataRecord; data 十六进制解码为 01 02 | pass | 11 | [pcap](doip/doip_uds_22_response_sid.pcap) |
| doip_uds_22_subfunction | T192: UDS 0x22 + HasSubFunction=true → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_uds_27_even_response | T036: UDS 0x27 偶数响应无 key → UserData=67 02 10 包 | pass | 11 | [pcap](doip/doip_uds_27_even_response.pcap) |
| doip_uds_27_even_response_key | T037: UDS 0x27 偶数响应 + Key 非空 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_uds_27_odd_response | T035: UDS 0x27 奇数响应带 seed → UserData=67 01 11 22 33 44 10 包 | pass | 11 | [pcap](doip/doip_uds_27_odd_response.pcap) |
| doip_uds_27_seed_request | T033: UDS 0x27 0x01 请求 seed → 0x8001 UserData=27 01 10 包 | pass | 11 | [pcap](doip/doip_uds_27_seed_request.pcap) |
| doip_uds_27_send_key | T034: UDS 0x27 0x02 发送 key=55 66 77 88 → UserData=27 02 55 66 77 88 10 包 | pass | 11 | [pcap](doip/doip_uds_27_send_key.pcap) |
| doip_uds_3e_tester_present | T043: UDS 0x3E TesterPresent sub_function=0 → 0x8001+0x8002 Ack 10 包 | pass | 11 | [pcap](doip/doip_uds_3e_tester_present.pcap) |
| doip_uds_blockseq_wrap | T039/T040: 0x36 BlockSeq 回绕 n=256→0x00, n=257→0x01 → 4 包 | pass | 15 | [pcap](doip/doip_uds_blockseq_wrap.pcap) |
| doip_uds_nrc | T045/T046: UDS 0x22 NRC=0x11 → UserData=7F 22 11 (NRC 优先 IsResponse) 10 包 | pass | 11 | [pcap](doip/doip_uds_nrc.pcap) |
| doip_uds_nrc_0x00 | T047: UDS NRC=0x00 → Validate 拒绝 (ExpectError) | pass | 11 | [pcap](doip/doip_uds_nrc_0x00.pcap) |
| doip_uds_nrc_0x7f | T049: UDS NRC=0x7F 边界 → UserData=7F 22 7F 通过 10 包 | pass | 11 | [pcap](doip/doip_uds_nrc_0x7f.pcap) |
| doip_uds_nrc_0xff | T048: UDS NRC=0xFF → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_uds_unknown_sid | T191: UDS ServiceID=0xFF 未知 → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
| doip_userdata_empty | 负向: user_data=[] (空 0x8001, 无 UDS 服务) → Wireshark malformed(预期) | pass | 11 | [pcap](doip/doip_userdata_empty.pcap) |
| doip_v1_oem | T025: V1 + OEM-specific 非 nil → Validate 拒绝 (ExpectError) | pass | 0 | [pcap]() |
