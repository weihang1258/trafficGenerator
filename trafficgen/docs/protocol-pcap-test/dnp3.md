# dnp3 Pcap Test Results

Cases: 70 — pass 70, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dnp3_t10_multi_iplist_mismatch | T10 Validate: OutstationCount=2 但 IPList 长度=1 → 拒绝 (length mismatch) | pass | 0 | [pcap]() |
| dnp3_t14_block16_crc | T14 16B user-data 分块: CRC 分块写入链路帧 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t14_block16_crc.pcap) |
| dnp3_t15_block17_crc | T15 17B user-data: CRC 分两块写入 (16B+1B) 含独立 CRC | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t15_block17_crc.pcap) |
| dnp3_t17_read_class123 | T17: read_class123 → 3 个 Object 60.2/60.3/60.4 各 Qual=6; 请求 data=C2 01 3C 02 06 3C 03 06 3C 04 06 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t17_read_class123.pcap) |
| dnp3_t1_valid_minimal | T1 ValidMinimal: 默认 master/read_class0 最小配置, 期望成功生成 pcap | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t1_valid_minimal.pcap) |
| dnp3_t21_reset_link | T21: reset_link 场景（master, TCP）→ 握手3 + ResetLink(C0)+ACK(00) + 挥手4 = 9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t21_reset_link.pcap) |
| dnp3_t22_read_class0 | T22: read_class0 场景 → 握手3 + ResetLink/ACK + read请求(FC=1)+ACK + respond(FC=13)+ACK + 挥手4 = 13 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t22_read_class0.pcap) |
| dnp3_t23_select_operate | T23/T65: select_operate 场景 → select(FC=3) + operate(FC=4) 各带响应，SBO 共享 AppSeq=3 | pass | 15 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t23_select_operate.pcap) |
| dnp3_t24_direct_operate | T24/T69: direct_operate 场景 → FC=5 无 select，CON=0 (AC=0xC5)，响应回显 CROB | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t24_direct_operate.pcap) |
| dnp3_t25_unsolicited | T25/T77: unsolicited 外设主动上报（outstation, 链路FC=4）→ 上报(FC=14) + confirm(FC=15) | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t25_unsolicited.pcap) |
| dnp3_t26_cold_restart | T26: cold_restart 场景 → FC=129 请求(CA 81, 无对象) + 响应含 Obj=51.1 Time Delay Coarse | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t26_cold_restart.pcap) |
| dnp3_t27_udp_transport | T27: UDP transport → 无握手/挥手，每链路帧前置 2B 传输头(LTH+SEQ)，reset_link 场景 2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t27_udp_transport.pcap) |
| dnp3_t28_no_handshake | T28: handshake=false → 无 TCP 握手，直接从 Reset Link 开始（reset_link 场景 2+4=6 包） | pass | 6 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t28_no_handshake.pcap) |
| dnp3_t29_no_termination | T29: Termination=false → 无 TCP FIN，以最后 DNP3 ACK 结束（5 包） | pass | 5 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t29_no_termination.pcap) |
| dnp3_t30_appseq_wrap | T30: AppSeq=15 回绕 → multi-request 场景，AppSeq 15→0 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t30_appseq_wrap.pcap) |
| dnp3_t31_multi_outstation_3 | T31: MultiOutstation Count=3 → 3 个外设各不同 4-tuple，独立 ResetLink 流 | pass | 27 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t31_multi_outstation_3.pcap) |
| dnp3_t32_multi_outstation_3_groupid | T32: OutstationCount=3 → 3 个流 GroupID 各不同 (flowid 后缀 RTU-0/1/2), 4-tuple 唯一 | pass | 27 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t32_multi_outstation_3_groupid.pcap) |
| dnp3_t33_multi_outstation_3_wire_order | T33: OutstationCount=3 → 单外设内包序保持: ResetLink 先于 UserData, 每流 3握手+Reset+ACK+挥手 | pass | 39 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t33_multi_outstation_3_wire_order.pcap) |
| dnp3_t34_broadcast_no_ack | T34: DstAddr=0xFFFF + direct_operate_no_ack → 外设不响应，仅请求帧（无 ACK/Respond），广播地址 | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t34_broadcast_no_ack.pcap) |
| dnp3_t35_empty_objects_link_only | T35: Objects=[] + reset_link → 仅链路帧 (ResetLink up + ACK down), 无 App 层 | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t35_empty_objects_link_only.pcap) |
| dnp3_t36_malformed_crc | T36: MalformedCRC=true → CRC 字节被篡改，外设应检测 CRC 错误 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t36_malformed_crc.pcap) |
| dnp3_t37_iin_object_unknown | T37: IINObjectUnknown=true → 响应 IIN byte2=0x20 (ObjectUnknown bit) + Obj=255,Var=0,Qual=6 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t37_iin_object_unknown.pcap) |
| dnp3_t39_link_fc_status | T39 LinkFC=2 Status: 重置/ACK 帧 Control 字段 FC=2 而非默认 0 | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t39_link_fc_status.pcap) |
| dnp3_t3_valid_outstation | T3 ValidOutstation: link_type=outstation, scenario=respond, 期望成功生成 pcap | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t3_valid_outstation.pcap) |
| dnp3_t40_link_fc_overflow | T40 LinkFC=15 Validate 拒绝, MCP 报错 | pass | 0 | [pcap]() |
| dnp3_t41_fcb_zero_only | T41 LinkFCB=1 但 FCV=0: wire 上 FCB 强制为 0 | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t41_fcb_zero_only.pcap) |
| dnp3_t42_fcb_toggle | T42 LinkFCB=1+FCV=1: read_class0 请求帧 FCB=1, 响应帧 FCB=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t42_fcb_toggle.pcap) |
| dnp3_t43_malformed_length | T43: MalformedLength=255 → Length 字节被设为 0xFF（无效值） | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t43_malformed_length.pcap) |
| dnp3_t44_malformed_length_zero | T44 MalformedLength=0: 所有帧 Length 字节=0x00 (CRC 仍正确) | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t44_malformed_length_zero.pcap) |
| dnp3_t45_unknown_object_respond | T45: UnknownObject=true read_class0 → 响应 Object=255 Var=0 Q=0x06, IIN byte2=0x20 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t45_unknown_object_respond.pcap) |
| dnp3_t46_unknown_func | T46: UnknownFunc=true → 请求 FC=0xC8(200), 外设响应 FC=0xC9(201 FunctionUnknown) | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t46_unknown_func.pcap) |
| dnp3_t47_malformed_length_200 | T47 MalformedLength=200 合法范围: 帧 Length 字节=0xC8 | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t47_malformed_length_200.pcap) |
| dnp3_t48_iin_already_executing | T48: IINAlreadyExecuting=true → 响应 IIN byte2=0x04 (AlreadyExecuting bit) | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t48_iin_already_executing.pcap) |
| dnp3_t49_iin_event_buffer_overflow | T49: IINEventBufferOverflow=true → 响应 IIN byte2=0x08 (EventBufferOverflow bit) | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t49_iin_event_buffer_overflow.pcap) |
| dnp3_t4_invalid_link_type | T4 InvalidLinkType: link_type='slave' 应被 Validate 拒绝, MCP 报错 | pass | 0 | [pcap]() |
| dnp3_t50_iin_local_control | T50: IINLocalControl=true → 响应 IIN byte1=0x04 (LocalControl bit) | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t50_iin_local_control.pcap) |
| dnp3_t51_iin_broadcast | T51 IINBroadcast: iin_broadcast=true → 响应 IIN byte1=0x80 (BROADCAST bit7) | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t51_iin_broadcast.pcap) |
| dnp3_t52_iin_config_corrupt | T52: IINConfigCorrupt=true → 响应 IIN byte2=0x80 (ConfigCorrupt bit) | pass | 13 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t52_iin_config_corrupt.pcap) |
| dnp3_t53_iin_all_bits | T53 IINAllBits: 全 shorthand=true (除 ConfigCorrupt) → byte1=0x7A, byte2=0x7C | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t53_iin_all_bits.pcap) |
| dnp3_t54_iin_raw_and_shorthand | T54 IINRaw+Shorthand: iin=0x4000 (Class1) + iin_class2=true → byte1=0x60 OR | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t54_iin_raw_and_shorthand.pcap) |
| dnp3_t55_iin_out_of_range | T55: dnp3.iin=65536 超出 uint16 范围 → ValidateProtocolSubConfigs 拒绝 (iin out of uint16 range) | pass | 0 | [pcap]() |
| dnp3_t56_outstation_ip_start | T56: OutstationIPStart=10.0.0.10 Count=3 → RTU 0/1/2 = 10.0.0.10/11/12 连续递增 | pass | 27 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t56_outstation_ip_start.pcap) |
| dnp3_t57_multi_no_ip | T57 Validate: OutstationCount=2 无 IPStart 无 IPList → 拒绝 (outstation_ip required) | pass | 0 | [pcap]() |
| dnp3_t58_multi_port_zero | T58 Validate: OutstationCount=2 + IPList 但 SrcPortStart=0 → 拒绝 (src_port_start must be set) | pass | 0 | [pcap]() |
| dnp3_t59_multi_port_overflow | T59 Validate: OutstationCount=10 + SrcPortStart=65530 → 拒绝 (exceeds 65535) | pass | 0 | [pcap]() |
| dnp3_t5_invalid_transport | T5 InvalidTransport: transport='sctp' 应被 Validate 拒绝, MCP 报错 | pass | 0 | [pcap]() |
| dnp3_t60_iplist_overrides_start | T60: IPStart=10.0.0.10 + IPList=[10.0.0.20,10.0.0.30] → IPList 优先, RTU0=.20 RTU1=.30 | pass | 18 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t60_iplist_overrides_start.pcap) |
| dnp3_t64_freeze_clear_con0 | T64: scenario=freeze_clear + AppCON=0 → 请求帧 CON=0 (auto-set 0), AC 字节 C0 | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t64_freeze_clear_con0.pcap) |
| dnp3_t66_crob_request_status_rejected | T66: CROB (12.1) 请求携带 status 字段 → Validate 拒绝 (Status is response-only) | pass | 0 | [pcap]() |
| dnp3_t67_operate_crob_shared_appseq | T67: select_operate + CROB Code=3 → select/operate 共享 AppSeq=3, 请求帧 App 层字节 C3 03/04 0C 01 00 05 05 03 01 64 00 FF FF | pass | 15 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t67_operate_crob_shared_appseq.pcap) |
| dnp3_t68_respond_crob_status_echo | T68: outstation respond + CROB 回显 Status=0 → 响应帧 7B CROB: C3 81 00 00 0C 01 00 05 05 03 01 64 00 FF FF 00 | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t68_respond_crob_status_echo.pcap) |
| dnp3_t69_qualifier9_rejected | T69: qualifier=9 (非法) → Validate 拒绝 (invalid qualifier 0x09) | pass | 0 | [pcap]() |
| dnp3_t69b_qualifier0_index_overflow | T69(变体): qualifier=0 + index_range [300,300] 超出 8-bit → Validate 拒绝 (index exceeds 255) | pass | 0 | [pcap]() |
| dnp3_t69c_qualifier17_point_index_overflow | T69(变体): qualifier=0x17 + point index=300 超出 8-bit → Validate 拒绝 (index exceeds 255) | pass | 0 | [pcap]() |
| dnp3_t6_invalid_app_func | T6 InvalidAppFunc: app_func='foobar' (字符串而非 uint8) 应被解析拒绝, MCP 报错 | pass | 0 | [pcap]() |
| dnp3_t70_response_var0_rejected | T70 Validate: outstation+respond + Object{20,0,6} → 拒绝 (Variation=0 in response frame) | pass | 0 | [pcap]() |
| dnp3_t71_request_var0_accepted | T71: master+read + Object{20,0,6} → 通过 (请求帧 Variation=0 = 任意变体) | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t71_request_var0_accepted.pcap) |
| dnp3_t72_freeze_clear_var1 | T72: scenario=freeze_clear + Object{20,1,6} → 请求帧 data = C0 09 14 01 06 | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t72_freeze_clear_var1.pcap) |
| dnp3_t73_counter_var3_rejected | T73 Validate: Object{20,3,6} (Variation=3 不存在) → 拒绝 (must be 1 or 2) | pass | 0 | [pcap]() |
| dnp3_t74_fc31_reserved_rejected | T74 Validate: AppFuncCode=31 (Reserved) → 拒绝 (FC=31 is Reserved) | pass | 0 | [pcap]() |
| dnp3_t75_fc215_reserved_rejected | T75 Validate: AppFuncCode=215 (Configure deprecated) → 拒绝 (FC=215 is Reserved) | pass | 0 | [pcap]() |
| dnp3_t78_link_ctrl03_outstation_data | T78: scenario=respond 链路层 Control=0x03 (PRM=0,FC=3, User Data Confirm, outstation→master) | pass | 8 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t78_link_ctrl03_outstation_data.pcap) |
| dnp3_t7_appseq_overflow | T7 越界: app_seq=16 超出 [0..15] 范围, Validate 拒绝 | pass | 0 | [pcap]() |
| dnp3_t80_empty_data_10bytes | T80: scenario=reset_link 帧 Length=0 → 10B 帧 (05 64 00 ctrl dst src CRC16) | pass | 9 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t80_empty_data_10bytes.pcap) |
| dnp3_t81_strategy_convert_full_path | T81: strategy_convert 全链路 → link_type/src_addr/dst_addr/objects/points(status)/iin/multi_outstation 映射到 DNP3Config 再 Plan, wire 字节与直接构造一致 | pass | 16 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t81_strategy_convert_full_path.pcap) |
| dnp3_t84_multi_outstation_10 | T84: OutstationCount=10 + IPList (10 IP) → 10 个 4-tuple 各不同, 单流内顺序保持 | pass | 90 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t84_multi_outstation_10.pcap) |
| dnp3_t85_multi_outstation_20_stress | T85: OutstationCount=20 stress → 20 个流全产出, 每流 4-tuple 唯一, 总包数=20×9=180, 无冲突 | pass | 180 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_t85_multi_outstation_20_stress.pcap) |
| dnp3_t8_broadcast_confirm | T8 BroadcastConfirm: dst_addr=65535 + confirm_required=true 互斥, Validate 拒绝 | pass | 0 | [pcap]() |
| dnp3_t9_multi_zero_count | T9 Validate: OutstationCount=0 → 拒绝 (outstation_count must be > 0) | pass | 0 | [pcap]() |
| dnp3_write_single_80_1 | §6.4: write_single → FC=2 write Obj=80.1 Qual=0x00 Range=07 07 Data=01 | pass | 11 | [pcap](/tmp/mcp-pcaps/dnp3/dnp3_write_single_80_1.pcap) |
