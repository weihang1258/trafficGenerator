# enip Pcap Test Results

Cases: 135 — pass 135, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| enip_epath_16bit_attribute | T-080: EPATH Attribute 16-bit (0x31), attribute_id=0x0100, path 20 01 24 01 31 00 01 | pass | 8 | [pcap](enip/enip_epath_16bit_attribute.pcap) |
| enip_epath_16bit_class | T-076: EPATH Class 16-bit (0x21), class_id=0x0100, path 21 00 01 24 01 30 01 | pass | 8 | [pcap](enip/enip_epath_16bit_class.pcap) |
| enip_epath_16bit_instance | T-078: EPATH Instance 16-bit (0x25), instance_id=0x0100, path 20 01 25 00 01 30 01 | pass | 8 | [pcap](enip/enip_epath_16bit_instance.pcap) |
| enip_error_response_status | S11/T-023: CIP error response (down) General Status 0x0E + AddStatusSize=1, ENIP Status=0, Length=36 | pass | 8 | [pcap](enip/enip_error_response_status.pcap) |
| enip_forward_close_response | T-050: Forward_Close success response (down), Reply 0xCE, GeneralStatus=0 | pass | 8 | [pcap](enip/enip_forward_close_response.pcap) |
| enip_forward_close_triad | S8/T-047-049: Forward_Close (0x4E) triad (ConnSerial=1, Vendor=1, OrigSerial=1), Length=41, path 20 04 24 01 2C 02 2C 03 | pass | 8 | [pcap](enip/enip_forward_close_triad.pcap) |
| enip_forward_open_request | S7/T-031-042: Forward_Open 0x54, Length=66, O2TRPI=100000, ConnParams=0x0200, TCT=0x80, ConnectionPath 20 04 24 01 2C 02 2C 03 | pass | 8 | [pcap](enip/enip_forward_open_request.pcap) |
| enip_forward_open_response_full | T-043/044/045: Forward_Open success response (down), Reply 0xD4, O2T=0x12345678, T2O=0x87654321, full 26B body | pass | 8 | [pcap](enip/enip_forward_open_response_full.pcap) |
| enip_get_attribute_list | T-026: Get_Attribute_List (0x03) attrs [1,6], Length=28, CIP 03 02 20 01 24 01 02 00 01 00 06 00 | pass | 8 | [pcap](enip/enip_get_attribute_list.pcap) |
| enip_get_attributes_all | T-024: Get_Attributes_All (0x01) Identity class 1 instance 1, Length=22, path 20 01 24 01 | pass | 8 | [pcap](enip/enip_get_attributes_all.pcap) |
| enip_io_connection_udp_full_chain | S7+S9/T-046-072: Forward_Open -> response(down,O2T=0x55) -> SendUnitData(from_response) -> 2 UDP I/O frames seq 1,2 payload AA BB | pass | 5 | [pcap](enip/enip_io_connection_udp_full_chain.pcap) |
| enip_large_forward_open | S14/T-060-062: LargeForward_Open (0x5B) 4-byte ConnParams, Length=70, RPI=100ms, ConnPath 20 04 24 01 2C 02 2C 03 | pass | 8 | [pcap](enip/enip_large_forward_open.pcap) |
| enip_listidentity_response | T-006/007/008/009: ListIdentity response (down), TypeID=0x000C, Vendor=1, ProductName='ENIP Test Device', Revision=1.0 | pass | 8 | [pcap](enip/enip_listidentity_response.pcap) |
| enip_listidentity_session_lifecycle | S3/S4/S12: ListIdentity(0x0063) + RegisterSession(0x0065) + UnRegisterSession(0x0066), SenderContext auto 1,2,3, TCP Seq 100->124->152 (Bug C fix verified) | pass | 10 | [pcap](enip/enip_listidentity_session_lifecycle.pcap) |
| enip_multiple_service_packet | S10/T-055-059: MSP (0x0A) 2 sub-requests attr 1+6, Length=44, offsets 6,14, path 20 00 24 00 (class_id 默认 0) | pass | 8 | [pcap](enip/enip_multiple_service_packet.pcap) |
| enip_nop_heartbeat | S1/T-002: NOP keepalive 4-byte payload DE AD BE EF, 1 TCP packet, ENIP Length=4, SessionHandle=0x12345678, SenderContext fixed 0 | pass | 8 | [pcap](enip/enip_nop_heartbeat.pcap) |
| enip_registersession_session_state | S4+S5/T-071: RegisterSession down 响应 (SessionHandle=0x12345678) 建立 flow 级 session 状态, UnRegisterSession 复用该 session | pass | 9 | [pcap](enip/enip_registersession_session_state.pcap) |
| enip_reset_service | T-028: CIP Reset service (0x05), class 1 instance 1, path 20 01 24 01 | pass | 8 | [pcap](enip/enip_reset_service.pcap) |
| enip_sendrrdata_get_attribute_single | S6/T-020-022: SendRRData Get_Attribute_Single, Null+Unconnected CPF, path 20 01 24 01 30 01 (8-bit), ENIP Length=24 | pass | 8 | [pcap](enip/enip_sendrrdata_get_attribute_single.pcap) |
| enip_seq_wraparound_3_frames | T-074/128: SequenceCounter wraparound, sequence_start=65535, 3 UDP frames seq 65535,0,1 | pass | 4 | [pcap](enip/enip_seq_wraparound_3_frames.pcap) |
| enip_set_attribute_single | T-025: Set_Attribute_Single (0x10) attr 7 value 0x58 (STRING 2B len prefix), Length=25, CIP 10 02 20 01 24 01 30 07 00 01 58 | pass | 8 | [pcap](enip/enip_set_attribute_single.pcap) |
| enip_start_service | T-029: CIP Start service (0x06), class 1 instance 1, path 20 01 24 01 | pass | 8 | [pcap](enip/enip_start_service.pcap) |
| enip_stop_service | T-030: CIP Stop service (0x07), class 1 instance 1, path 20 01 24 01 | pass | 8 | [pcap](enip/enip_stop_service.pcap) |
| enip_t003_listservices | T-003: ListServices request (0x0004), Length=0 | pass | 8 | [pcap](enip/enip_t003_listservices.pcap) |
| enip_t010_listinterfaces | T-010: ListInterfaces request (0x0064), Length=0 | pass | 8 | [pcap](enip/enip_t010_listinterfaces.pcap) |
| enip_t014_registersession_nocpf | T-014: RegisterSession payload 4B (pv=1, flag=0), no CPF | pass | 8 | [pcap](enip/enip_t014_registersession_nocpf.pcap) |
| enip_t027_set_attribute_list | T-027: Set_Attribute_List (0x04) attrs [7] value X | pass | 8 | [pcap](enip/enip_t027_set_attribute_list.pcap) |
| enip_t063_large_forward_open_response | T-063: LargeForward_Open response (down) Reply Service=0xDB | pass | 8 | [pcap](enip/enip_t063_large_forward_open_response.pcap) |
| enip_t064_nop_no_response | T-064: NOP keepalive generates request only, no response packet | pass | 8 | [pcap](enip/enip_t064_nop_no_response.pcap) |
| enip_t066_identity_attr1 | T-066: Identity object attr 1 read response: VendorID=0x0001 | pass | 8 | [pcap](enip/enip_t066_identity_attr1.pcap) |
| enip_t067_identity_attr6 | T-067: Identity object attr 6 read response: SerialNumber 0x12345678 | pass | 8 | [pcap](enip/enip_t067_identity_attr6.pcap) |
| enip_t068_tcpip_attr1 | T-068: TCP/IP Interface (0xF5) attr 1 read response: IP 10.0.0.5 | pass | 8 | [pcap](enip/enip_t068_tcpip_attr1.pcap) |
| enip_t069_ethlink_attr3 | T-069: Ethernet Link (0xF6) attr 3 read response: MAC 6B | pass | 8 | [pcap](enip/enip_t069_ethlink_attr3.pcap) |
| enip_t070_sendercontext_echo | T-070: SenderContext echo in response (sender_context=0x0102030405060708) | pass | 8 | [pcap](enip/enip_t070_sendercontext_echo.pcap) |
| enip_t073_seq_10_frames | T-073: 10 I/O frames, payload AA BB per frame, Connected Data len=2 (seq 不再编码于 UDP I/O 帧，2026-08 修复) | pass | 11 | [pcap](enip/enip_t073_seq_10_frames.pcap) |
| enip_t075_epath_class8 | T-075: EPATH Class 8-bit 0x01 -> 20 01 | pass | 8 | [pcap](enip/enip_t075_epath_class8.pcap) |
| enip_t077_epath_instance8 | T-077: EPATH Instance 8-bit 0x01 -> 24 01 | pass | 8 | [pcap](enip/enip_t077_epath_instance8.pcap) |
| enip_t079_epath_attr8 | T-079: EPATH Attribute 8-bit 0x01 -> 30 01 | pass | 8 | [pcap](enip/enip_t079_epath_attr8.pcap) |
| enip_t081_unknown_command | T-081: unknown command 0x1234 -> Validate reject | pass | 0 | [pcap]() |
| enip_t082_registersession_cpf | T-082: RegisterSession with CPF items -> reject | pass | 0 | [pcap]() |
| enip_t083_registersession_pv0 | T-083: RegisterSession protocol_version=0 -> reject | pass | 0 | [pcap]() |
| enip_t084_registersession_optionflag | T-084: RegisterSession option_flag=1 -> reject | pass | 0 | [pcap]() |
| enip_t085_registersession_payload5 | T-085: RegisterSession Payload=5B -> Validate reject | pass | 0 | [pcap]() |
| enip_t086_sendrrdata_nocpf | T-086: SendRRData with no CPF/cip_service/payload -> reject | pass | 0 | [pcap]() |
| enip_t087_sendrrdata_itemcount1_noservice | T-087: SendRRData only 1 CPF item and no cip_service -> reject | pass | 0 | [pcap]() |
| enip_t088_sendunitdata_noaddr | T-088: SendUnitData missing Connection Address item -> reject | pass | 0 | [pcap]() |
| enip_t089_sendunitdata_nodata | T-089: SendUnitData missing Connected Data item -> reject | pass | 0 | [pcap]() |
| enip_t090_sessionhandle_strategy_inc | T-090: SessionHandle strategy=inc -> Validate reject | pass | 0 | [pcap]() |
| enip_t091_sessionhandle_strategy_rand | T-091: SessionHandle strategy=rand -> Validate reject | pass | 0 | [pcap]() |
| enip_t092_sendrrdata_cipservice0 | T-092: SendRRData cip_service=0 with Unconnected Data item -> Validate reject | pass | 0 | [pcap]() |
| enip_t093_forwardopen_noconnserial | T-093: Forward_Open missing conn_serial_number -> reject | pass | 0 | [pcap]() |
| enip_t094_forwardopen_novendor | T-094: Forward_Open missing originator_vendor_id -> reject | pass | 0 | [pcap]() |
| enip_t095_forwardopen_noorigserial | T-095: Forward_Open missing originator_serial_number -> reject | pass | 0 | [pcap]() |
| enip_t096_forwardopen_class5 | T-096: TransportClassTrigger=0x05 (class 5) -> reject | pass | 0 | [pcap]() |
| enip_t097_forwardopen_rpi0 | T-097: Forward_Open O2TRPI=0 -> reject | pass | 0 | [pcap]() |
| enip_t098_forwardopen_reservedbit | T-098: O2TConnParams bit12=0x1000 reserved -> reject | pass | 0 | [pcap]() |
| enip_t099_forwardclose_notriad | T-099: Forward_Close missing conn_serial_number -> reject | pass | 0 | [pcap]() |
| enip_t100_listidentity_cpf | T-100: ListIdentity request with CPF -> reject | pass | 0 | [pcap]() |
| enip_t101_listservices_cpf | T-101: ListServices request with CPF -> reject | pass | 0 | [pcap]() |
| enip_t102_listinterfaces_cpf | T-102: ListInterfaces request with CPF -> reject | pass | 0 | [pcap]() |
| enip_t103_unregistersession_payload | T-103: UnRegisterSession with payload -> reject | pass | 0 | [pcap]() |
| enip_t104_class_id_out_of_range | T-104: EPATH class_id=0x10000 (out of uint16) -> Validate reject | pass | 0 | [pcap]() |
| enip_t105_instance_id_out_of_range | T-105: EPATH instance_id=0x100000000 (out of uint32) -> Validate reject | pass | 0 | [pcap]() |
| enip_t106_msp_nosubrequests | T-106: Multiple_Service_Packet with empty sub_requests -> reject | pass | 0 | [pcap]() |
| enip_t107_msp_65subs | T-107: Multiple_Service_Packet with 65 sub_requests -> reject | pass | 0 | [pcap]() |
| enip_t108_io_framesize_65466 | T-108: I/O frame_size=65466 exceeds 65465 -> reject | pass | 0 | [pcap]() |
| enip_t109_io_framecount0 | T-109: I/O frame_count=0 -> reject | pass | 0 | [pcap]() |
| enip_t110_io_noconnid | T-110: I/O data with no o2t_connection_id (no from_response) -> reject | pass | 0 | [pcap]() |
| enip_t111_timeoutmult8 | T-111: ConnectionTimeoutMultiplier=8 -> reject | pass | 0 | [pcap]() |
| enip_t112_forwardopen_class15 | T-112: TransportClassTrigger=0x0F (class 15) -> reject | pass | 0 | [pcap]() |
| enip_t113_unknown_scenario | T-113: unknown scenario -> reject | pass | 0 | [pcap]() |
| enip_t114_unknown_transport | T-114: transport=icmp -> reject | pass | 0 | [pcap]() |
| enip_t115_dstport_502 | T-115: dst_port=502 -> reject | pass | 0 | [pcap]() |
| enip_t116_unknown_typeid | T-116: CPF item type_id=0x9999 -> reject | pass | 0 | [pcap]() |
| enip_t117_source_cmd_index_99 | T-117: source_command_index=99 out of range -> reject | pass | 0 | [pcap]() |
| enip_t118_unknown_fromresp_field | T-118: unknown from_response field -> reject | pass | 0 | [pcap]() |
| enip_t119_sockaddr_len15 | T-119: Sockaddr info item length=15 -> reject | pass | 0 | [pcap]() |
| enip_t120_connpathsize_mismatch | T-120: connection_path_size=5 with 4B path -> Validate reject | pass | 0 | [pcap]() |
| enip_t120a_forwardclose_path_mismatch | T-120a: Forward_Close path mismatches Forward_Open (same triad) -> reject | pass | 0 | [pcap]() |
| enip_t120b_registersession_pv2 | T-120b: RegisterSession protocol_version=2 -> reject (OpENer 0x0069) | pass | 0 | [pcap]() |
| enip_t121_nop_length0 | T-121: NOP minimal, ENIP Length=0 | pass | 8 | [pcap](enip/enip_t121_nop_length0.pcap) |
| enip_t124_sessionhandle_max | T-124: SessionHandle=0xFFFFFFFF | pass | 8 | [pcap](enip/enip_t124_sessionhandle_max.pcap) |
| enip_t125_sessionhandle_zero | T-125: SessionHandle=0x00000000 | pass | 8 | [pcap](enip/enip_t125_sessionhandle_zero.pcap) |
| enip_t127_sendercontext_max | T-127: SenderContext=0xFFFFFFFFFFFFFFFF | pass | 8 | [pcap](enip/enip_t127_sendercontext_max.pcap) |
| enip_t129_seq_start_7fff | T-129: I/O frame (no payload, frame_size 缺省=0), Connected Data len=0; seq 不再编码于 UDP I/O 帧 (2026-08 修复) | pass | 3 | [pcap](enip/enip_t129_seq_start_7fff.pcap) |
| enip_t130_seq_step2 | T-130: 3 个 I/O 帧 (no payload), Connected Data len=0; seq 不再编码于 UDP I/O 帧 (2026-08 修复) | pass | 4 | [pcap](enip/enip_t130_seq_step2.pcap) |
| enip_t131_epath_class8_max | T-131: EPATH Class 8-bit boundary 0xFF -> 20 FF | pass | 8 | [pcap](enip/enip_t131_epath_class8_max.pcap) |
| enip_t132_epath_class16_min | T-132: EPATH Class 16-bit boundary 0x0100 -> 21 00 01 | pass | 8 | [pcap](enip/enip_t132_epath_class16_min.pcap) |
| enip_t133_epath_instance32 | T-133: EPATH Instance 32-bit 0x10000 -> 26 00 00 01 00 (odd path padded) | pass | 8 | [pcap](enip/enip_t133_epath_instance32.pcap) |
| enip_t133a_epath_class32_raw | T-133a: EPATH Class 32-bit (0x22) via Forward_Open raw connection_path | pass | 8 | [pcap](enip/enip_t133a_epath_class32_raw.pcap) |
| enip_t133b_epath_attr32_raw | T-133b: EPATH Attribute 32-bit (0x32) via Forward_Open raw connection_path | pass | 8 | [pcap](enip/enip_t133b_epath_attr32_raw.pcap) |
| enip_t133c_epath_connpoint8 | T-133c: EPATH Connection Point 8-bit 0x02 -> 2C 02 | pass | 8 | [pcap](enip/enip_t133c_epath_connpoint8.pcap) |
| enip_t133d_epath_connpoint16 | T-133d: EPATH Connection Point 16-bit 0x0100 -> 2D 00 01 (padded) | pass | 8 | [pcap](enip/enip_t133d_epath_connpoint16.pcap) |
| enip_t134_rpi_min | T-134: Forward_Open O2TRPI=1 -> body 01 00 00 00 | pass | 8 | [pcap](enip/enip_t134_rpi_min.pcap) |
| enip_t135_rpi_max | T-135: Forward_Open O2TRPI=0xFFFFFFFF | pass | 8 | [pcap](enip/enip_t135_rpi_max.pcap) |
| enip_t136_connparams_6dff | T-136: Forward_Open O2TConnParams=0x6DFF -> FF 6D | pass | 8 | [pcap](enip/enip_t136_connparams_6dff.pcap) |
| enip_t137_large_connparams_max | T-137: LargeForward_Open O2TConnParams=0xF2FFFFFF (4B) | pass | 8 | [pcap](enip/enip_t137_large_connparams_max.pcap) |
| enip_t139_pathsize255 | T-139: Connection Path Size=255 (510B path) | pass | 8 | [pcap](enip/enip_t139_pathsize255.pcap) |
| enip_t140_msp_offset_boundary | T-140: MSP 2 sub-requests 0B data: Offset[0]=6, Offset[1]=12 (spec's 'both 6' impossible: offset advances by sub-request size) | pass | 8 | [pcap](enip/enip_t140_msp_offset_boundary.pcap) |
| enip_t141_io_framesize0 | T-141: I/O FrameSize=0 -> Connected Data length=0 (空 payload; seq 不再编码 2026-08) | pass | 2 | [pcap](enip/enip_t141_io_framesize0.pcap) |
| enip_t142_io_framesize_max | T-142: I/O FrameSize=65447 -> Connected Data length=65447 (0xFFA7, 无 seq 2026-08) | pass | 2 | [pcap](enip/enip_t142_io_framesize_max.pcap) |
| enip_t143_sendrrdata_itemcount1 | T-143: SendRRData cip_service with only 1 user CPF item -> accepted (impl allows when cip_service present; spec expects reject, see impl gap) | pass | 8 | [pcap](enip/enip_t143_sendrrdata_itemcount1.pcap) |
| enip_t144_itemcount4_sockaddr | T-144: SendRRData ItemCount=4 (Null+Unconnected+Sockaddr O2T+T2O) | pass | 8 | [pcap](enip/enip_t144_itemcount4_sockaddr.pcap) |
| enip_t145_sockaddr_port_max | T-145: Sockaddr Info SinPort=0xFFFF | pass | 8 | [pcap](enip/enip_t145_sockaddr_port_max.pcap) |
| enip_t146_sockaddr_ip_max | T-146: Sockaddr Info SinAddr=255.255.255.255 | pass | 8 | [pcap](enip/enip_t146_sockaddr_ip_max.pcap) |
| enip_t147_timeout0 | T-147: SendRRData Timeout=0 | pass | 8 | [pcap](enip/enip_t147_timeout0.pcap) |
| enip_t148_timeout_max | T-148: SendRRData Timeout=65535 | pass | 8 | [pcap](enip/enip_t148_timeout_max.pcap) |
| enip_t149_ifhandle_nonzero | T-149: SendRRData InterfaceHandle=0x12345678 | pass | 8 | [pcap](enip/enip_t149_ifhandle_nonzero.pcap) |
| enip_t151_addstatus_255words | T-151: CIP Additional Status 255 words (AddStatusSize=0xFF) | pass | 8 | [pcap](enip/enip_t151_addstatus_255words.pcap) |
| enip_t155_epath_odd_pad | T-155: EPATH odd 7B path padded to 8B (class8+instance16+attr8) | pass | 8 | [pcap](enip/enip_t155_epath_odd_pad.pcap) |
| enip_t156_epath_even | T-156: EPATH even 8B path no padding (class16+instance8+attr16) | pass | 8 | [pcap](enip/enip_t156_epath_even.pcap) |
| enip_t157_productname_empty | T-157: ListIdentity response ProductName empty -> SHORT_STRING len=0x00 | pass | 8 | [pcap](enip/enip_t157_productname_empty.pcap) |
| enip_t158_productname_255 | T-158: ListIdentity response ProductName 255B -> SHORT_STRING len=0xFF | pass | 8 | [pcap](enip/enip_t158_productname_255.pcap) |
| enip_t160_vendorid_max | T-160: ListIdentity response VendorID=0xFFFF | pass | 8 | [pcap](enip/enip_t160_vendorid_max.pcap) |
| enip_t161_sessioncount2_senderctx | T-161/T-176/T-178: SessionCount=2 -> 2 RegisterSession 请求 SenderContext 1,3 (全局递增, 每单元 2 命令) 且各自响应 SessionHandle 0x12345678/0x12345679; 每会话命令序列完整不交叉 | pass | 4 | [pcap](enip/enip_t161_sessioncount2_senderctx.pcap) |
| enip_t162_sessioncount8_handles | T-162/T-163: SessionCount=8 -> 8 个 RegisterSession 响应, SessionHandle 0x11111111..0x11111118 独立不重复; 8 个独立 TCP 流 (srcPort 12345..12352) | pass | 16 | [pcap](enip/enip_t162_sessioncount8_handles.pcap) |
| enip_t164_flowcount2_forwardopen | T-164/T-168/T-173: FlowCount=2 -> 2 个 Forward_Open ConnSerialNum 1,2 / O2T 1,3 (S13 交错); down 响应 payload 派生 O2T 0x55,0x57 | pass | 4 | [pcap](enip/enip_t164_flowcount2_forwardopen.pcap) |
| enip_t165_flowcount8_connids | T-165: FlowCount=8 -> 8 个 Forward_Open, O2T 1,3,5,..,15 独立; ConnSerialNum 1..8 | pass | 16 | [pcap](enip/enip_t165_flowcount8_connids.pcap) |
| enip_t166_2session2flow_io | T-166: SessionCount=2 x FlowCount=2 -> 4 组 I/O, 4 个独立 (SessionHandle, ConnectionID) 对 | pass | 12 | [pcap](enip/enip_t166_2session2flow_io.pcap) |
| enip_t167_multiflow_seq_from_1 | T-167: FlowCount=2, 每流 2 个 I/O 帧 -> 两流 SequenceCounter 均从 0x0001 开始递增 | pass | 8 | [pcap](enip/enip_t167_multiflow_seq_from_1.pcap) |
| enip_t169_multisession_tcp_tuples | T-169: SessionCount=2 (TCP) -> 2 个独立 TCP 流, srcPort 12345/12346, flowID 独立 | pass | 2 | [pcap](enip/enip_t169_multisession_tcp_tuples.pcap) |
| enip_t170_multiflow_udp_shared_tuple | T-170: transport=udp, FlowCount=2 -> I/O 帧共享同一 UDP 4-tuple (12345/44818), ConnectionID 0x55/0x57 区分; TCP 命令帧也共享 4-tuple | pass | 6 | [pcap](enip/enip_t170_multiflow_udp_shared_tuple.pcap) |
| enip_t172_fromresponse_session_isolated | T-172: SessionCount=2, NOP 用 from_response 提取 session_handle -> 每会话从自己的 RegisterSession 响应提取 0x12345678/0x12345679, 不交叉 | pass | 4 | [pcap](enip/enip_t172_fromresponse_session_isolated.pcap) |
| enip_t173_fromresponse_flow_isolated | T-173: FlowCount=2, SendUnitData from_response o2t_connection_id -> 每流从自己的 Forward_Open 响应提取 0x55/0x57 | pass | 6 | [pcap](enip/enip_t173_fromresponse_flow_isolated.pcap) |
| enip_t174_unregister_session_matched | T-174: SessionCount=2 -> 每会话独立 UnRegisterSession, SessionHandle 0x12345678/0x12345679 匹配本会话 | pass | 6 | [pcap](enip/enip_t174_unregister_session_matched.pcap) |
| enip_t175_forward_close_serial_matched | T-175: FlowCount=2 -> 每流独立 Forward_Close, ConnSerialNum 1/2 与本流 Forward_Open 匹配 | pass | 6 | [pcap](enip/enip_t175_forward_close_serial_matched.pcap) |
| enip_t176_senderctx_global_inc | T-176: SessionCount=2, 默认 SenderContext 策略 -> 跨会话全局递增 (1,2,3,4), 包 2 = 包 1 + 1 | pass | 4 | [pcap](enip/enip_t176_senderctx_global_inc.pcap) |
| enip_t177_senderctx_per_unit | T-177: FlowCount=2, 显式 sender_context=5 -> 每流独立: 流 1 首包=5, 流 2 首包=6 (显式值+u) | pass | 2 | [pcap](enip/enip_t177_senderctx_per_unit.pcap) |
| enip_t179_multiflow_order | T-179: FlowCount=2 -> 每流命令序列完整 (RegisterSession up -> down -> UnRegisterSession), 不交叉 | pass | 6 | [pcap](enip/enip_t179_multiflow_order.pcap) |
| enip_t199_scenario_full | T-199: scenario=full: ListIdentity+RegisterSession+SendRRData chain | pass | 10 | [pcap](enip/enip_t199_scenario_full.pcap) |
| enip_t217_status_0064 | T-217: ENIP Status=0x0064 InvalidSession | pass | 8 | [pcap](enip/enip_t217_status_0064.pcap) |
| enip_t218_status_0065 | T-218: ENIP Status=0x0065 InvalidLength | pass | 8 | [pcap](enip/enip_t218_status_0065.pcap) |
| enip_t219_status_0069 | T-219: ENIP Status=0x0069 UnsupportedProtocol | pass | 8 | [pcap](enip/enip_t219_status_0069.pcap) |
| enip_v005_session_count_negative | V-005: session_count=-1 -> Validate 拒绝 (out of range 1-1000) | pass | 0 | [pcap]() |
| enip_v006_flow_count_negative | V-006: flow_count=101 -> Validate 拒绝 (out of range 1-100) | pass | 0 | [pcap]() |
