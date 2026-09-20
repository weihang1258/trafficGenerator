# pppoe Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pppoe_auth_chap | T-6 auth=chap：Challenge(down)/Response(up)/Success(down) 0xc223 三帧，value 16B（响应回显挑战值）。RFC 1994 §3 | pass | 11 | [pcap](pppoe/pppoe_auth_chap.pcap) |
| pppoe_auth_none_lcp_len | T-4 auth=none：LCP options=MRU+Magic 无 Auth-Protocol（type3）分支→LCP len 0x000e/payload_length 0x0010 钉 | pass | 8 | [pcap](pppoe/pppoe_auth_none_lcp_len.pcap) |
| pppoe_auth_pap | T-5 auth=pap：LCP 带 Auth-Protocol c023 选项+PAP Authenticate-Request(up)/Ack(down) 0xc023 两帧。RFC 1334 §2.1 | pass | 10 | [pcap](pppoe/pppoe_auth_pap.pcap) |
| pppoe_bras_three_tags | T-10 BRAS 三标签形：service_name=internet+ac_name=BRAS-1+cookie=deadbeef→PADO 3 标签+PADR echo AC-Cookie（现网 9.10） | pass | 8 | [pcap](pppoe/pppoe_bras_three_tags.pcap) |
| pppoe_composite_multi_session | T-14 复合大场景（9.50）：顶层 chap 模板共享+sessions[2] 交织——[0] 完整发现+data 1；[1] skip_discovery+down+data_frames 2。19 包 | pass | 19 | [pcap](pppoe/pppoe_composite_multi_session.pcap) |
| pppoe_data_direction_down | T-7 data_direction=down：数据帧 MAC/IP 全换向（server→client），ip.src=20.0.0.1；LCP/PADT 方向不变 | pass | 4 | [pcap](pppoe/pppoe_data_direction_down.pcap) |
| pppoe_data_frames_two | T-17 data_frames=2：LCP2+data2+PADT=5 帧（skip 形），多帧 IPID 递增 | pass | 5 | [pcap](pppoe/pppoe_data_frames_two.pcap) |
| pppoe_data_frames_zero_default | T-8 data_frames=0=缺省 1 数据帧（勘误：0 非'无数据帧'而是缺省 1，planner frames==0→1）；包数 8 与 T-1 同形 | pass | 8 | [pcap](pppoe/pppoe_data_frames_zero_default.pcap) |
| pppoe_data_payload_bytes | T-16 data_payload 显式字节：数据帧载荷原文字节钉（getByteSlice 字符串=原文字节语义） | pass | 4 | [pcap](pppoe/pppoe_data_payload_bytes.pcap) |
| pppoe_inner_tcp_explicit | T-15 inner_proto=6 显式 TCP：数据帧 ip.proto=6（内嵌 IPv4/TCP 合成面） | pass | 4 | [pcap](pppoe/pppoe_inner_tcp_explicit.pcap) |
| pppoe_inner_udp_explicit | T-18 inner_proto=17 显式 UDP：与 T-1 的缺省 UDP 对称（显式声明面） | pass | 4 | [pcap](pppoe/pppoe_inner_udp_explicit.pcap) |
| pppoe_lifecycle_full | T-1 全生命周期（smoke 改写，等价覆盖+PADT 重校准 7→8）：[ip,pppoe{}] 空业务面→PADI/PADO/PADR/PADS(缺省ID1)/LCP req/ack/1×IPv4 data/PADT(0xa7,ID回显,up)。RFC 2516 §5+§5.6 | pass | 8 | [pcap](pppoe/pppoe_lifecycle_full.pcap) |
| pppoe_mru_magic_explicit | T-11 mru=1480+magic_number=0x01020304 显式：LCP options 字节钉（01 04 05 c8+05 06 01 02 03 04） | pass | 4 | [pcap](pppoe/pppoe_mru_magic_explicit.pcap) |
| pppoe_neg_auth_invalid | T-19 负例：auth=radius 不在 {none,pap,chap}→Validate 拒（锚词 Auth） | pass | 0 | [pcap]() |
| pppoe_neg_data_frames_negative | T-21 负例：data_frames=-1→registry V9 范围门拒（链路径真实拦截点，Min 0） | pass | 0 | [pcap]() |
| pppoe_neg_duplicate_session_id | T-24 负例：两显式 session_id=100→判死（裁定5 锚词） | pass | 0 | [pcap]() |
| pppoe_neg_inner_proto_invalid | T-20 负例：inner_proto=5 不在 {0,6,17}→拒（锚词 InnerProto） | pass | 0 | [pcap]() |
| pppoe_neg_ipv6_inner | T-22 负例：ip 层同族 IPv6→PPPoE 只承载 IPv4（PPP 0x0021），pppoe validator 拒（锚词 must be IPv4） | pass | 0 | [pcap]() |
| pppoe_neg_sessions_mutex | T-23 负例：sessions[]与顶层行为键 data_frames 同给→互斥判死（裁定4 锚词） | pass | 0 | [pcap]() |
| pppoe_padt_suppressed | T-2 padt=false 抑制终止帧：7 帧（无 0xa7），帧序与 T-1 前 7 帧一致。RFC 2516 §5.6 拆断语义反向面 | pass | 7 | [pcap](pppoe/pppoe_padt_suppressed.pcap) |
| pppoe_service_name_any | T-9 空 Service-Name=零长标签 any-service（现网语义：客户端不挑服务）：PADI/PADO/PADR/PADS 四帧均 01 01 00 00 | pass | 8 | [pcap](pppoe/pppoe_service_name_any.pcap) |
| pppoe_sessions_derived_ids | T-12 sessions[3] 全空项：每项独立生命周期，派生 SessionID 1/2/3（DefaultSessionID+i 逐会话递增，9.40 非流序号共享），3 个 PADT | pass | 24 | [pcap](pppoe/pppoe_sessions_derived_ids.pcap) |
| pppoe_sessions_explicit_ids | T-13 sessions[2] 显式 session_id 100/200：PADS 回显显式值，每会话独立发现四步 | pass | 16 | [pcap](pppoe/pppoe_sessions_explicit_ids.pcap) |
| pppoe_skip_discovery | T-3 skip_discovery=true+显式 session_id=9：LCP req/ack+data+PADT 4 帧，全部回显 9，首帧即 0x8864 会话面 | pass | 4 | [pcap](pppoe/pppoe_skip_discovery.pcap) |
