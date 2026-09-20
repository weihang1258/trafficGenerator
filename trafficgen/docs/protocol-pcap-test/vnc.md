# vnc Pcap Test Results

Cases: 17 — pass 17, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| vnc_t10_colourmap | T-10 set_colour_map_entries：01 消息（first/num/6B 项） | pass | 35 | [pcap](vnc/vnc_t10_colourmap.pcap) |
| vnc_t11_client_msgs_off | T-11 client_set_pixel_format/encodings=false：客户端消息缺省面 | pass | 31 | [pcap](vnc/vnc_t11_client_msgs_off.pcap) |
| vnc_t12_rounds_linear | T-12 rounds=2 + fbu_update_interval=2：编排线性（Pointer→FBU×2 两轮） | pass | 37 | [pcap](vnc/vnc_t12_rounds_linear.pcap) |
| vnc_t13_pointer_default | T-13 pointer 坐标缺省 507/320 + button 0 帧字节钉 | pass | 33 | [pcap](vnc/vnc_t13_pointer_default.pcap) |
| vnc_t14_neg_sec_type | 负例：security_type=7（枚举外）planner 锚词 | pass | 0 | [pcap]() |
| vnc_t15_neg_auth_result | 负例：auth_result=3 超区间 V9 锚词 | pass | 0 | [pcap]() |
| vnc_t16_neg_rect_encoding | 负例：rect encoding 非法 planner 锚词 | pass | 0 | [pcap]() |
| vnc_t17_neg_width_zero | 负例：width=0 显式 0 planner 锚词 | pass | 0 | [pcap]() |
| vnc_t1_smoke_ref | T-1 smoke 改写（33 帧参考形）：Tight 握手 13 消息 + 客户端消息面 + FBU 循环 + 拆链，5900 端口 | pass | 33 | [pcap](vnc/vnc_t1_smoke_ref.pcap) |
| vnc_t2_handshake_bytes | T-2 握手字节钉：版本 12B / secTypes 02 02 10 / TunnelCaps 00000000 / AuthCaps 记录 / challenge+response 参考字节 | pass | 33 | [pcap](vnc/vnc_t2_handshake_bytes.pcap) |
| vnc_t3_sec_type_vncauth | T-3 security_type=2：VNC Auth 路径（无 Tunnel/AuthCaps/无 InteractionCaps，challenge/response 16B） | pass | 29 | [pcap](vnc/vnc_t3_sec_type_vncauth.pcap) |
| vnc_t4_sec_type_none | T-4 security_type=1：None 路径（secTypes 01 01，无 challenge，直通 init） | pass | 27 | [pcap](vnc/vnc_t4_sec_type_none.pcap) |
| vnc_t5_auth_fail | T-5 auth_result=1 失败分支：reason 透传 + 无 ServerInit + 提前拆链 | pass | 17 | [pcap](vnc/vnc_t5_auth_fail.pcap) |
| vnc_t6_share_false | T-6 share_desktop=false：ClientInit 0x00 | pass | 33 | [pcap](vnc/vnc_t6_share_false.pcap) |
| vnc_t7_raw_rect | T-7 raw 编码矩形：rawPixels 确定性 (n*13+1..4) 像素钉 | pass | 33 | [pcap](vnc/vnc_t7_raw_rect.pcap) |
| vnc_t8_key_down_explicit | T-8 key_events 显式：单 KeyEvent down 键 0xffe9 帧字节钉 | pass | 28 | [pcap](vnc/vnc_t8_key_down_explicit.pcap) |
| vnc_t9_extras_mix | T-9 extras 交织：Bell 02 + ServerCutText 03 + ClientCutText 06 | pass | 38 | [pcap](vnc/vnc_t9_extras_mix.pcap) |
