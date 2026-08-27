# srv6 Pcap Test Results

Cases: 68 — pass 68, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| srv6_bnd01_127_segments | BND-01/V-P-09: 127 段最大（non-reduced），LastEntry=126，Hdr Ext Len=254，PL=2048 | pass | 1 | [pcap](srv6/srv6_bnd01_127_segments.pcap) |
| srv6_bnd02_126_segments_tlv | BND-02: 126 段 + 8 字节 TLV（Hdr Ext Len=254 恰好不溢出，validate 通过） | pass | 1 | [pcap](srv6/srv6_bnd02_126_segments_tlv.pcap) |
| srv6_bnd04_127_segments_reduced | BND-04/V-P-16: Reduced 127 段，LastEntry=125，Hdr Ext Len=252，DstIP=首段，PL=2032 | pass | 1 | [pcap](srv6/srv6_bnd04_127_segments_reduced.pcap) |
| srv6_bnd06_frames_1000 | BND-06: Frames=1000 Hop Limit wrap（64..1→255..1，永不出 0） | pass | 1000 | [pcap](srv6/srv6_bnd06_frames_1000.pcap) |
| srv6_bnd10_tlv_value_255 | BND-10: TLV value 255 字节边界通过（Length 字节=0xFF），SRH 281B 尾部 PadN 1B → 288 | pass | 1 | [pcap](srv6/srv6_bnd10_tlv_value_255.pcap) |
| srv6_e2e04_multi_flow_100 | E2E-04: 多流 100 包（strategy_flow_control flows=100，每包 5-tuple 唯一，SRH 相同） | pass | 100 | [pcap](srv6/srv6_e2e04_multi_flow_100.pcap) |
| srv6_exc01_hdr_ext_len_mismatch | EXC-01/NEW-16/V-N-23: builder 层异常（HdrExtLen mismatch / RoutingType≠4）——pcap 无法表达，归单测域 | pass | 1 | [pcap](srv6/srv6_exc01_hdr_ext_len_mismatch.pcap) |
| srv6_mf03_flowid_unique | MF-03: 10 流 5-tuple 全唯一（dst_port 各不同）→ FlowID 互异 | pass | 10 | [pcap](srv6/srv6_mf03_flowid_unique.pcap) |
| srv6_mf04_down_multi_flow | MF-04: 10 流 Direction=down（每流反转 + MAC/IP/Port swap，DstIP=原 List[0]） | pass | 10 | [pcap](srv6/srv6_mf04_down_multi_flow.pcap) |
| srv6_mf05_group_id | MF-05: group_id 固定值 → 同 worker 顺序发包（跨流时序保持） | pass | 10 | [pcap](srv6/srv6_mf05_group_id.pcap) |
| srv6_new01_dx4 | NEW-01: end.dx4 + IPv4 内层 40B（SRH NextHeader=4，RFC 8986 §4.5 解封装） | pass | 1 | [pcap](srv6/srv6_new01_dx4.pcap) |
| srv6_new01a_dt4 | NEW-01a: end.dt4 + IPv4 内层 40B（NextHeader=4，RFC 8986 §4.8） | pass | 1 | [pcap](srv6/srv6_new01a_dt4.pcap) |
| srv6_new01b_dt6 | NEW-01b: end.dt6 + IPv6 内层 48B（NextHeader=41，RFC 8986 §4.9） | pass | 1 | [pcap](srv6/srv6_new01b_dt6.pcap) |
| srv6_new03_inner_src_port_fallback | NEW-03: InnerSrcPort 未设置（0）→ 内层 SrcPort 回退 spec.SrcPort=12345 | pass | 1 | [pcap](srv6/srv6_new03_inner_src_port_fallback.pcap) |
| srv6_new04_inner_src_port_override | NEW-04: InnerSrcPort=54321 显式覆盖 spec.SrcPort=12345 | pass | 1 | [pcap](srv6/srv6_new04_inner_src_port_override.pcap) |
| srv6_new05_segments_left_default | NEW-05: 多段 + SegmentsLeftPtr=nil → SegmentsLeft 默认 = len-1 = 2 | pass | 1 | [pcap](srv6/srv6_new05_segments_left_default.pcap) |
| srv6_new06_segments_left_zero | NEW-06: 多段 + SegmentsLeftPtr=&0 → SegmentsLeft=0（终节点视角，不被默认覆盖） | pass | 1 | [pcap](srv6/srv6_new06_segments_left_zero.pcap) |
| srv6_new07_hdr_ext_len_byte | NEW-07: 单 segment 断言 Hdr Ext Len 字节 [41] = 0x02 | pass | 1 | [pcap](srv6/srv6_new07_hdr_ext_len_byte.pcap) |
| srv6_new08_dstip_byte_match | NEW-08: 3 段 DstIP 字节 == SRH List[n-1] 字节（反序存储第一段） | pass | 1 | [pcap](srv6/srv6_new08_dstip_byte_match.pcap) |
| srv6_new09_frames_negative | NEW-09: Frames=-1 → frames must be >= 0 拒绝 | pass | 0 | [pcap]() |
| srv6_new13_single_seg_sl_1 | NEW-13: 单段 + SegmentsLeftPtr=&1 → segments_left (1) > last_entry+1 (1) 拒绝 | pass | 0 | [pcap]() |
| srv6_new14_end_un | NEW-14: seg_type=end.un 合法字符串通过（v1 仅校验字符串合法性，不做 End* 语义校验） | pass | 1 | [pcap](srv6/srv6_new14_end_un.pcap) |
| srv6_p18_b6_encaps_red_default_reduced | V-P-18/P-18/NEW-17: end.b6.encaps.red 未设 reduced → 默认 true，2 段 reduced 编码（LE=0，wire=[S2]，DstIP=S1） | pass | 1 | [pcap](srv6/srv6_p18_b6_encaps_red_default_reduced.pcap) |
| srv6_tpos10_b6_encaps | S10: End.B6.Encaps 多层嵌套（外层 SRH NH=41 + 内层 IPv6+SRH+UDP 72B），外层 SL=0 | pass | 1 | [pcap](srv6/srv6_tpos10_b6_encaps.pcap) |
| srv6_tpos11_icmpv6 | S16: ICMPv6 内层（SRH NH=58，Echo Request Type=128 ID=1 Seq=1，数据 8B） | pass | 1 | [pcap](srv6/srv6_tpos11_icmpv6.pcap) |
| srv6_tpos13_direction_down | S12/Direction=down: SegmentList 反转 + IP/端口交换（源节点视角），DstIP=原 List[0] | pass | 1 | [pcap](srv6/srv6_tpos13_direction_down.pcap) |
| srv6_tpos14_payload_none | P-10: payload_protocol=none → SRH NextHeader=59（No Next Header），无内层载荷 | pass | 1 | [pcap](srv6/srv6_tpos14_payload_none.pcap) |
| srv6_tpos15_tag | Tag=0xABCD + 多段（3 段）: SRH 字节 6-7 = AB CD，SegmentList 反序完整 | pass | 1 | [pcap](srv6/srv6_tpos15_tag.pcap) |
| srv6_tpos16_pad1 | BYT-15/BND-12: Pad1单字节填充（1段+实验TLV value=5B → SRH 31B mod8=7 → 尾部00单字节，总长32） | pass | 1 | [pcap](srv6/srv6_tpos16_pad1.pcap) |
| srv6_tpos17_hbh_chain | V-P-14/P-12/BYT-19/E2E-06: SRv6 + HopByHop链（IPv6 NH=0 → HBH NH=43 → SRH） | pass | 1 | [pcap](srv6/srv6_tpos17_hbh_chain.pcap) |
| srv6_tpos18_tag_max | V-P-08/BND-08: Tag=0xFFFF边界 + 3段，SRH字节6-7 = FF FF | pass | 1 | [pcap](srv6/srv6_tpos18_tag_max.pcap) |
| srv6_tpos19_tag_zero | BND-07: Tag=0x0000下界 + 单段，SRH字节6-7 = 00 00 | pass | 1 | [pcap](srv6/srv6_tpos19_tag_zero.pcap) |
| srv6_tpos1_basic | S1: 单段 SRH(non-reduced) + 内层 UDP，payload=12345678，DstIP=SegmentList[0] | pass | 1 | [pcap](srv6/srv6_tpos1_basic.pcap) |
| srv6_tpos20_reduced_hmac | P-17: Reduced SRH + HMAC TLV（D bit=1，reduced DA verification disabled） | pass | 1 | [pcap](srv6/srv6_tpos20_reduced_hmac.pcap) |
| srv6_tpos21_multi_flow | MF-02: 多流并发（frames=5，5包SRH相同仅外层5-tuple不同，Hop Limit递减） | pass | 5 | [pcap](srv6/srv6_tpos21_multi_flow.pcap) |
| srv6_tpos2_multi3_reverse | S2: 3 段 SRH 反序存储核心断言（wire List[0]=最后段 B，List[2]=第一段 S1=DstIP）+ 内层 TCP | pass | 1 | [pcap](srv6/srv6_tpos2_multi3_reverse.pcap) |
| srv6_tpos3_reduced | S3: Reduced SRH（2 段，省略第一段 S1，SL=1 LE=0，wire 仅 1 项 S2，DstIP=S1） | pass | 1 | [pcap](srv6/srv6_tpos3_reduced.pcap) |
| srv6_tpos4_hmac_tlv | S4: HMAC TLV(Type=5, Len=0x26, 40B) + 单段，SRH 64B Hdr Ext Len=7，Flags=0 | pass | 1 | [pcap](srv6/srv6_tpos4_hmac_tlv.pcap) |
| srv6_tpos5_padn | S5: 自定义实验 TLV(Type=200, Len=2, AB CD) 触发 PadN(04 02 00 00) 尾部 8 对齐，SRH 32B | pass | 1 | [pcap](srv6/srv6_tpos5_padn.pcap) |
| srv6_tpos6_nested_ipv6 | S6: End.DX6 嵌套 IPv6（外层 SRH NH=41 + 内层 IPv6 40B + UDP 8B + payload 8B），终节点 SL=0 | pass | 1 | [pcap](srv6/srv6_tpos6_nested_ipv6.pcap) |
| srv6_tpos7_midpoint | S7: End 中间节点视角（3 段，SL=1 LE=2，DstIP=List[SL_new]=S2），伪头 DstIP=最终目的 List[0]=B | pass | 1 | [pcap](srv6/srv6_tpos7_midpoint.pcap) |
| srv6_tpos9_frames | Frames=5: 5 包 SRH 相同，Hop Limit 递减，每包 DstIP=SegmentList[0] | pass | 5 | [pcap](srv6/srv6_tpos9_frames.pcap) |
| srv6_vn01_no_srv6 | V-N-01: srv6 子配置缺失 → Validate 报错 srv6 config is required | pass | 0 | [pcap]() |
| srv6_vn02_empty_segment_list | V-N-02: segment_list 为空数组 → segment_list must not be empty | pass | 0 | [pcap]() |
| srv6_vn03_128_segments | V-N-03/NEW-10: 128 段超限 → segment_list too large for 8-bit hdr_ext_len | pass | 0 | [pcap]() |
| srv6_vn04_segments_left_gt_last_entry | V-N-04: segments_left=5 > last_entry+1=3 → 报错 segments_left (5) > last_entry+1 (3) | pass | 0 | [pcap]() |
| srv6_vn05_segment_not_ipv6 | V-N-05: segment_list 项为 IPv4 → segment_list[0] must be IPv6 | pass | 0 | [pcap]() |
| srv6_vn06_src_ipv6_invalid | V-N-06: srv6.src_ipv6 为 IPv4 → src_ipv6 must be IPv6 | pass | 0 | [pcap]() |
| srv6_vn07_src_ip_ipv4 | V-N-07: spec.SrcIP 为 IPv4 + srv6 非空 → srv6 requires IPv6 | pass | 0 | [pcap]() |
| srv6_vn08_unknown_seg_type | V-N-08: seg_type=end.zzz 未知 → unknown seg_type | pass | 0 | [pcap]() |
| srv6_vn09_flags_nonzero | V-N-09: flags=0x01 → flags must be 0 | pass | 0 | [pcap]() |
| srv6_vn10_tlv_value_256 | V-N-10/BND-11: tlv value 256 字节 → tlv[0] value length 256 exceeds 255 bytes | pass | 0 | [pcap]() |
| srv6_vn11_pad1_manual | V-N-11: 用户显式 TLV type=0 (Pad1) → pad1 must not be set manually | pass | 0 | [pcap]() |
| srv6_vn12_padn_manual | V-N-12: 用户显式 TLV type=4 (PadN) → padN must not be set manually | pass | 0 | [pcap]() |
| srv6_vn13_tlv_type1_reserved | V-N-13: TLV type=1 Reserved → reserved TLV type 1 must not be set | pass | 0 | [pcap]() |
| srv6_vn14_tlv_type2_reserved | V-N-14: TLV type=2 Reserved → reserved TLV type 2 must not be set | pass | 0 | [pcap]() |
| srv6_vn15_tlv_type6_reserved | V-N-15: TLV type=6 Reserved → reserved TLV type 6 must not be set | pass | 0 | [pcap]() |
| srv6_vn16_endx_no_dstmac | V-N-16: seg_type=end.x 未指定 dst_mac → end.x requires explicit dst_mac | pass | 1 | [pcap](srv6/srv6_vn16_endx_no_dstmac.pcap) |
| srv6_vn17_endb6_short_inner | V-N-17: end.b6 内层不足 40 字节 → end.b6 requires inner_payload >= 40 bytes | pass | 0 | [pcap]() |
| srv6_vn18_srv6_mpls | V-N-18/NEW-11: SRv6 + MPLS 互斥 → srv6 cannot combine with mpls | pass | 1 | [pcap](srv6/srv6_vn18_srv6_mpls.pcap) |
| srv6_vn19_srv6_gre | V-N-19/NEW-12: SRv6 + GRE 互斥 → srv6 cannot combine with gre | pass | 1 | [pcap](srv6/srv6_vn19_srv6_gre.pcap) |
| srv6_vn20_dx6_short_inner | V-N-20: end.dx6 内层不足 40 字节 → end.dx6 requires inner_payload >= 40 bytes | pass | 0 | [pcap]() |
| srv6_vn21_dx6_payload_none | V-N-21: end.dx6 + payload_protocol=none + 非空内层 → 报错 requires payload_protocol=ipv6, got none | pass | 0 | [pcap]() |
| srv6_vn22_hdr_ext_len_overflow | V-N-22/BND-03: 127 段 + 8 字节 TLV → hdr_ext_len overflow | pass | 0 | [pcap]() |
| srv6_vn24_down_with_segments_left | V-N-24: direction=down + segments_left 显式 → direction=down requires source-node view | pass | 0 | [pcap]() |
| srv6_vp03_full_explicit | V-P-03: 全字段显式（src/dst/SL/LE/Flags/Tag/SegType/PayloadProto/TLV）validate 通过 | pass | 1 | [pcap](srv6/srv6_vp03_full_explicit.pcap) |
| srv6_vp04_endx_dstmac | V-P-04: seg_type=end.x + 显式 dst_mac 通过（L2 邻居 MAC 由 DstMAC 承载） | pass | 1 | [pcap](srv6/srv6_vp04_endx_dstmac.pcap) |
| srv6_vp06_endb6 | V-P-06: seg_type=end.b6 + payload_protocol=ipv6 + 内层 48B 通过（外层 NH=41） | pass | 1 | [pcap](srv6/srv6_vp06_endb6.pcap) |
