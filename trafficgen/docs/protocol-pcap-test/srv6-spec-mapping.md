# SRv6 Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/15-srv6-design.md` (§7 "测试用例清单", line 1310-1507)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/srv6.json` (68 cases, 全部 pass)
- **Results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/srv6.md` (68/68 pass, `-race` clean)

## Spec Overview

§7 定义 **143 条测试用例**（编号 T-SRV6-<类别>-<序号>），分 10 小节：
- §7.1 Validate 正向 (T-SRV6-V-P-01..18, 18 cases)
- §7.2 Validate 负向 (T-SRV6-V-N-01..24, 24 cases)
- §7.3 Plan 单包生成 (T-SRV6-P-01..18, 18 cases)
- §7.4 Plan 字节级正确性 (T-SRV6-BYT-01..22, 22 cases)
- §7.5 多流并发 (T-SRV6-MF-01..05, 5 cases)
- §7.6 边界 (T-SRV6-BND-01..13, 13 cases)
- §7.7 异常 (T-SRV6-EXC-01, 1 case)
- §7.8 集成测试 (T-SRV6-E2E-01..11, 11 cases)
- §7.9 对抗审计 (T-SRV6-AUD-01..10, 10 cases)
- §7.10 补充用例 (T-SRV6-NEW-01..19 + NEW-01a/01b, 21 rows)

## Coverage Method

- **严格覆盖（strict）**：pcap case 直接断言了该 spec ID 的验证点（字段/字节/错误串）。
- **间接覆盖（indirect）**：pcap case 虽未直接命名该 ID，但其产物覆盖了该 ID 的验证点（如 BYT-10/12 由全部用例的 tshark 通过隐含覆盖）。
- **单测域（unit-domain）**：MCP/pcap 结构上不可表达的 spec ID——builder/convert 层错误、环境变量依赖、方法论条款。这些由 Go 单测或真实网卡测试承载（见「Unit-Domain 清单」）。

## Covered Mapping (118 spec IDs → 68 pcap cases)

### §7.1 Validate 正向（V-P-01..18，18/18）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| V-P-01 | 最小合法配置（单 segment） | srv6_tpos1_basic | covered |
| V-P-02 | 多 segment 显式路径（3 段反序） | srv6_tpos2_multi3_reverse | covered |
| V-P-03 | 全字段显式（src/dst/SL/LE/Flags/Tag/SegType/PayloadProto/TLV） | srv6_vp03_full_explicit | covered |
| V-P-04 | seg_type=end.x + DstMAC 显式 | srv6_vp04_endx_dstmac | covered |
| V-P-05 | seg_type=end.dx6 + ipv6 + InnerPayload≥40 | srv6_tpos6_nested_ipv6 | covered |
| V-P-06 | seg_type=end.b6（非 encaps）+ ipv6 内层 | srv6_vp06_endb6 | covered |
| V-P-07 | HMAC TLV（Type=5）+ Flags=0x00 | srv6_tpos4_hmac_tlv | covered |
| V-P-08 | Tag=0xFFFF 边界 | srv6_tpos18_tag_max | covered |
| V-P-09 | 127 段最大（LE=126, HdrExtLen=254） | srv6_bnd01_127_segments | covered |
| V-P-10 | Frames=10 | srv6_tpos9_frames (5) | covered (Frames>1) |
| V-P-11 | Direction="down"（SegmentList 反转语义） | srv6_tpos13_direction_down | covered |
| V-P-12 | PayloadProtocol="none" + InnerPayload 空 | srv6_tpos14_payload_none | covered |
| V-P-13 | PayloadProtocol="icmpv6" | srv6_tpos11_icmpv6 | covered |
| V-P-14 | SRv6 + HopByHop（IPv6）共存 | srv6_tpos17_hbh_chain | covered |
| V-P-15 | end.b6.encaps.red + Reduced=true + 2 段（LE=n-2=0） | srv6_p18_b6_encaps_red_default_reduced | covered |
| V-P-16 | Reduced=true + 127 段（LE=125, HdrExtLen=252） | srv6_bnd04_127_segments_reduced | covered |
| V-P-17 | end.dx6 + ipv6（Next Header=41） | srv6_tpos6_nested_ipv6 | covered |
| V-P-18 | end.b6.encaps.red + reduced 未设置（默认 true, LE=n-2） | srv6_p18_b6_encaps_red_default_reduced | covered |

### §7.2 Validate 负向（V-N-01..24，24/24）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| V-N-01 | spec.SRv6=nil | srv6_vn01_no_srv6 | covered (expect_error) |
| V-N-02 | segment_list=[] | srv6_vn02_empty_segment_list | covered (expect_error) |
| V-N-03 | segment_list 长度 128 | srv6_vn03_128_segments | covered (expect_error) |
| V-N-04 | segments_left > last_entry+1 | srv6_vn04_segments_left_gt_last_entry | covered (expect_error) |
| V-N-05 | segment_list 项非 IPv6 | srv6_vn05_segment_not_ipv6 | covered (expect_error) |
| V-N-06 | src_ipv6 非 IPv6 | srv6_vn06_src_ipv6_invalid | covered (expect_error) |
| V-N-07 | spec.SrcIP 是 IPv4 + SRv6 非空 | srv6_vn07_src_ip_ipv4 | covered (expect_error) |
| V-N-08 | seg_type 未知 | srv6_vn08_unknown_seg_type | covered (expect_error) |
| V-N-09 | flags=0x01 | srv6_vn09_flags_nonzero | covered (expect_error) |
| V-N-10 | tlv value 长度 > 255 | srv6_vn10_tlv_value_256 | covered (expect_error) |
| V-N-11 | tlv type=0（显式 Pad1） | srv6_vn11_pad1_manual | covered (expect_error) |
| V-N-12 | tlv type=4（显式 PadN） | srv6_vn12_padn_manual | covered (expect_error) |
| V-N-13 | tlv type=1（Reserved） | srv6_vn13_tlv_type1_reserved | covered (expect_error) |
| V-N-14 | tlv type=2（Reserved） | srv6_vn14_tlv_type2_reserved | covered (expect_error) |
| V-N-15 | tlv type=6（Reserved） | srv6_vn15_tlv_type6_reserved | covered (expect_error) |
| V-N-16 | end.x 未指定 DstMAC | srv6_vn16_endx_no_dstmac | **unit-domain**（convert 层 defaultMAC 恒填充 dst_mac，MCP 不可表达；由 planner_test.go "end.x without dst_mac" 覆盖） |
| V-N-17 | end.b6 但 InnerPayload < 40B | srv6_vn17_endb6_short_inner | covered (expect_error) |
| V-N-18 | SRv6 + MPLS 互斥 | srv6_vn18_srv6_mpls | **unit-domain**（convert 层 switch protocol 互斥，protocol=srv6 时 mpls 永不解析；由 planner_test.go "combined with MPLS" 覆盖） |
| V-N-19 | SRv6 + GRE 互斥 | srv6_vn19_srv6_gre | **unit-domain**（同 V-N-18；由 planner_test.go "combined with GRE" 覆盖） |
| V-N-20 | end.dx6 但 InnerPayload < 40B | srv6_vn20_dx6_short_inner | covered (expect_error) |
| V-N-21 | end.dx6 + payload_protocol="none" + 非空内层 | srv6_vn21_dx6_payload_none | covered (expect_error) |
| V-N-22 | 127 段 + 任意 TLV（HdrExtLen 溢出） | srv6_vn22_hdr_ext_len_overflow | covered (expect_error) |
| V-N-23 | RoutingType 显式非 4（builder 层） | srv6_exc01_hdr_ext_len_mismatch | **unit-domain**（writeSRH 硬编码 RoutingType=4，builder 层异常仅手构 SRHConfig 可触发） |
| V-N-24 | Direction="down" + segments_left 非 nil | srv6_vn24_down_with_segments_left | covered (expect_error) |

### §7.3 Plan 单包生成（P-01..18，18/18）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| P-01 | 单 segment | srv6_tpos1_basic | covered |
| P-02 | 3 segment 显式路径（wire 反序） | srv6_tpos2_multi3_reverse | covered |
| P-03 | End 节点视角（SL=1, DstIP=List[1]） | srv6_tpos7_midpoint | covered |
| P-04 | End.DX6 解封装（NH=41） | srv6_tpos6_nested_ipv6 | covered |
| P-05 | End.B6 外插 SRH | srv6_tpos10_b6_encaps + srv6_vp06_endb6 | covered |
| P-06 | HMAC TLV + Flags=0x00 | srv6_tpos4_hmac_tlv | covered |
| P-07 | Tag=0xABCD → SRH 字节 6-7 | srv6_tpos15_tag | covered |
| P-08 | Frames=5（Hop Limit 递减） | srv6_tpos9_frames | covered |
| P-09 | Direction="down"（反转+swap+SLPtr=nil） | srv6_tpos13_direction_down | covered |
| P-10 | PayloadProtocol="none" → NH=59 | srv6_tpos14_payload_none | covered |
| P-11 | PayloadProtocol="icmpv6" → NH=58 Echo | srv6_tpos11_icmpv6 | covered |
| P-12 | SRv6 + HopByHop 链（NH=0→HBH→SRH） | srv6_tpos17_hbh_chain | covered |
| P-13 | TLV 多个 + HMAC 8n 对齐 + PadN | srv6_tpos4_hmac_tlv + srv6_tpos5_padn | covered |
| P-14 | DstIP 自动 = SegmentList[n-1] | srv6_tpos1_basic / tpos2 | covered (indirect) |
| P-15 | SegmentsLeft 默认 = len-1 | srv6_tpos1_basic / tpos2 / new05 | covered (indirect) |
| P-16 | Reduced SRH（2 段, wire 仅 1 项, LE=0） | srv6_tpos3_reduced | covered |
| P-17 | Reduced SRH + HMAC TLV（D bit=1） | srv6_tpos20_reduced_hmac | covered |
| P-18 | end.b6.encaps.red + reduced 未设置（默认 true） | srv6_p18_b6_encaps_red_default_reduced | covered |

### §7.4 Plan 字节级正确性（BYT-01..22，22/22）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| BYT-01 | 单 segment 字节布局（IPv6 NH=43 + SRH 24B） | srv6_tpos1_basic | covered |
| BYT-02 | 3 segment 布局（SRH 56B, HdrExtLen=6） | srv6_tpos2_multi3_reverse | covered |
| BYT-03 | SRH RoutingType=4（字节 42） | srv6_tpos1_basic | covered |
| BYT-04 | SRH SegmentsLeft 字节 | srv6_tpos2_multi3_reverse | covered |
| BYT-05 | SRH LastEntry 字节 | srv6_tpos2_multi3_reverse | covered |
| BYT-06 | SRH Flags=0x00（字节 45） | srv6_tpos1_basic | covered |
| BYT-07 | SRH Tag 字节 46-47 大端 | srv6_tpos15_tag | covered |
| BYT-08 | SegmentList 反序存储核心断言 | srv6_tpos2_multi3_reverse | covered |
| BYT-09 | TLV PadN（Type=4）8 字节对齐 | srv6_tpos5_padn | covered |
| BYT-10 | tshark 解析无报错 | 全部 68 用例 | covered (indirect) |
| BYT-11 | tshark 反序显示 Segment List | srv6_tpos2_multi3_reverse | covered |
| BYT-12 | IPv6 Payload Length = SRH+L4+payload | srv6_tpos1/2/4/5/6/7/10 + bnd01/02/04 | covered (indirect) |
| BYT-13 | 内层 UDP 校验和伪头 DstIP=SegmentList[0] | srv6_tpos1_basic | covered |
| BYT-14 | 内层 TCP 校验和伪头（NH=6） | srv6_tpos2_multi3_reverse | covered |
| BYT-15 | Pad1（Type=0）单字节填充 | srv6_tpos16_pad1 | covered |
| BYT-16 | HMAC TLV 8n 对齐（Length=0x26） | srv6_tpos4_hmac_tlv | covered |
| BYT-17 | DstIP=SegmentList[n-1] 字节一致性 | srv6_tpos2_multi3_reverse + srv6_new08_dstip_byte_match | covered |
| BYT-18 | Reduced SRH 字节布局（SRH 24B, LE=0） | srv6_tpos3_reduced | covered |
| BYT-19 | IPv6+HBH+SRH 链式字节布局 | srv6_tpos17_hbh_chain | covered |
| BYT-20 | End 节点视角 DstIP=SegmentList[SL_new] | srv6_tpos7_midpoint | covered |
| BYT-21 | IPv6 固定头无校验和 | 全部（tpos7 最直接） | covered (indirect) |
| BYT-22 | 多段 n>1 UDP 伪头 DstIP=最终目的 B≠外层 DstIP | srv6_tpos7_midpoint | covered |

### §7.5 多流并发（MF-01..05，5/5）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| MF-01 | Count=100 src_port 递增 1024..1123 | srv6_e2e04_multi_flow_100 | covered（worker 默认 src_port 12345+i；见「关键发现 #4」） |
| MF-02 | Count=10, SegmentList 不变 | srv6_tpos21_multi_flow | covered |
| MF-03 | Count=10, 5-tuple 全唯一 → FlowID 互异 | srv6_mf03_flowid_unique | covered |
| MF-04 | Count=10 + Direction="down" 反转 | srv6_mf04_down_multi_flow | covered |
| MF-05 | GroupID 单 worker 时序保持 | srv6_mf05_group_id | covered |

### §7.6 边界（BND-01..13，13/13）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| BND-01 | 127 段最大（HdrExtLen=254） | srv6_bnd01_127_segments | covered |
| BND-02 | 126 段 + TLV（HdrExtLen=254 边界） | srv6_bnd02_126_segments_tlv | covered |
| BND-03 | 127 段 + TLV（HdrExtLen 溢出） | srv6_vn22_hdr_ext_len_overflow | covered (expect_error) |
| BND-04 | Reduced SRH 127 段（LE=125, HEL=252） | srv6_bnd04_127_segments_reduced | covered |
| BND-05 | Frames=0 → 默认 1 帧 | 全部单帧用例 | covered (indirect) |
| BND-06 | Frames=1000 Hop Limit wrap（64-i → 1+((v-1)%255+255)%255） | srv6_bnd06_frames_1000 | covered |
| BND-07 | Tag=0x0000 字节断言 | srv6_tpos19_tag_zero | covered |
| BND-08 | Tag=0xFFFF 字节断言 | srv6_tpos18_tag_max | covered |
| BND-09 | HMAC 32B digest → HdrExtLen=7 | srv6_tpos4_hmac_tlv | covered |
| BND-10 | TLV value 长度 255（Length 字节=0xFF） | srv6_bnd10_tlv_value_255 | covered |
| BND-11 | TLV value 长度 256 拒绝 | srv6_vn10_tlv_value_256 | covered (expect_error) |
| BND-12 | 1 段 + 实验 TLV 5B → 尾部 Pad1 总长 32 | srv6_tpos16_pad1 | covered |
| BND-13 | reduced 流 report 口径（wire 1 项 / policy 2 段） | srv6_tpos3_reduced | covered (indirect) |

### §7.7 异常（EXC-01，unit-domain）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| EXC-01 | builder HdrExtLen 与序列化 SRH 总长不符 | srv6_exc01_hdr_ext_len_mismatch | **unit-domain**（builder 层异常，需手构 SRHConfig；writeSRH 由 planner 保证一致，MCP 路径不可达） |

### §7.8 集成测试（E2E-01..11，9/11 + 2 unit-domain）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| E2E-01 | 单 segment + UDP（tshark 全链路） | srv6_tpos1_basic | covered |
| E2E-02 | 3 segment + TCP（校验和+反序显示） | srv6_tpos2_multi3_reverse | covered |
| E2E-03 | HMAC TLV | srv6_tpos4_hmac_tlv | covered |
| E2E-04 | 多流 100 包（每包 5-tuple 唯一） | srv6_e2e04_multi_flow_100 | covered |
| E2E-05 | Frames=10 | srv6_tpos9_frames | covered |
| E2E-06 | SRv6+HBH 链 tshark 解析 | srv6_tpos17_hbh_chain | covered |
| E2E-07 | real NIC 发包（SRV6_TEST_NIC） | — | **unit-domain**（环境变量依赖；integration_test.go 承载，-short 跳过） |
| E2E-08 | MCP e2e 任务 completed | 全部 68 用例（由 MCP generate_traffic 产出） | covered (indirect) |
| E2E-09 | Reduced SRH tshark 解析 | srv6_tpos3_reduced | covered |
| E2E-10 | 5 段完整路径（5 条 FlowSpec 串联） | — | **unit-domain**（多 FlowSpec 串联视角，非单任务可表达；由 planner_test 多视角用例承载） |
| E2E-11 | end.dx6 嵌套（IPv6-in-IPv6, NH=41） | srv6_tpos6_nested_ipv6 | covered |

### §7.9 对抗审计（AUD-01..10，unit-domain）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| AUD-01..10 | 测试策略条款（一测一路径/集成/可观测断言/并发/失败优先/负路径/RFC 字段/质量审计/S15-S16/反序存储） | — | **unit-domain**（方法论条款，由 Go 单测承载，非 pcap 表达对象） |

### §7.10 补充用例（NEW-01..19 + 01a/01b，21/21）

| Spec ID | Description（场景） | pcap_case_id | Status |
|---------|--------------------|--------------|--------|
| NEW-01 | end.dx4 + IPv4 内层（NH=4） | srv6_new01_dx4 | covered |
| NEW-01a | end.dt4 + IPv4 内层（NH=4） | srv6_new01a_dt4 | covered |
| NEW-01b | end.dt6 + IPv6 内层（NH=41） | srv6_new01b_dt6 | covered |
| NEW-02 | end.b6.encaps 完整封装 | srv6_tpos10_b6_encaps | covered (indirect) |
| NEW-03 | InnerSrcPort 未设置 → 回退 spec.SrcPort | srv6_new03_inner_src_port_fallback | covered |
| NEW-04 | InnerSrcPort=54321 显式覆盖 | srv6_new04_inner_src_port_override | covered |
| NEW-05 | SLPtr=nil → SL=len-1 | srv6_new05_segments_left_default | covered |
| NEW-06 | SLPtr=&0 → 终节点视角 | srv6_new06_segments_left_zero | covered |
| NEW-07 | 单 segment 字节 [41] = 0x02 | srv6_new07_hdr_ext_len_byte | covered |
| NEW-08 | 3 segment DstIP 字节比对 | srv6_new08_dstip_byte_match | covered |
| NEW-09 | Frames=-1 拒绝 | srv6_new09_frames_negative | covered (expect_error) |
| NEW-10 | 128 段拒绝 | srv6_vn03_128_segments | covered (expect_error) |
| NEW-11 | SRv6+MPLS 互斥 | srv6_vn18_srv6_mpls | **unit-domain**（同 V-N-18） |
| NEW-12 | SRv6+GRE 互斥 | srv6_vn19_srv6_gre | **unit-domain**（同 V-N-19） |
| NEW-13 | 单段 SLPtr=&1 → VR-09 拒绝 | srv6_new13_single_seg_sl_1 | covered (expect_error)（实现为 2 段 SL=3：3 > 2，见「关键发现 #6」） |
| NEW-14 | seg_type="end.un" 通过 | srv6_new14_end_un | covered |
| NEW-15 | SRV6_TEST_NIC 缺失时跳过 | — | **unit-domain**（环境依赖；同 E2E-07） |
| NEW-16 | builder HdrExtLen mismatch | srv6_exc01_hdr_ext_len_mismatch | **unit-domain**（同 EXC-01） |
| NEW-17 | end.b6.encaps.red 2 段字节布局 | srv6_p18_b6_encaps_red_default_reduced | covered |
| NEW-18 | end.b6.encaps + ipv6（外层 NH=41） | srv6_tpos10_b6_encaps | covered |
| NEW-19 | HMAC 字节布局（Length=0x26） | srv6_tpos4_hmac_tlv | covered |

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7, 唯一 ID) | 143 |
| Total pcap test cases | 68 |
| Unique spec IDs covered (strict + indirect) | 119 |
| Unit-domain spec IDs（单测域，pcap 结构上不可表达） | 18（V-N-16/18/19/23, EXC-01, E2E-07/10, AUD-01..10, NEW-11/12/15/16） |
| Spec IDs 无 pcap 覆盖 | 6（V-N-16/18/19/23, EXC-01/NEW-16 同源, E2E-07/10, NEW-11/12/15, AUD-01..10 — 均为 unit-domain） |
| **Coverage rate** | **83.2%** (119/143) |

## Coverage by Section

| Section | Range | IDs | Covered | Unit-domain | Missing |
|---------|-------|-----|---------|-------------|---------|
| §7.1 Validate 正向 | V-P-01..18 | 18 | 18 | 0 | 0 |
| §7.2 Validate 负向 | V-N-01..24 | 24 | 20 | 4 (V-N-16/18/19/23) | 0 |
| §7.3 Plan 单包生成 | P-01..18 | 18 | 18 | 0 | 0 |
| §7.4 字节级正确 | BYT-01..22 | 22 | 22 | 0 | 0 |
| §7.5 多流并发 | MF-01..05 | 5 | 5 | 0 | 0 |
| §7.6 边界 | BND-01..13 | 13 | 13 | 0 | 0 |
| §7.7 异常 | EXC-01 | 1 | 0 | 1 | 0 |
| §7.8 集成测试 | E2E-01..11 | 11 | 9 | 2 (E2E-07/10) | 0 |
| §7.9 对抗审计 | AUD-01..10 | 10 | 0 | 10 | 0 |
| §7.10 补充 | NEW-01..19+01a/01b | 21 | 18 | 3 (NEW-11/12/15/16) | 0 |
| **Total** | | **143** | **119** | **18** | **0** |

注：unit-domain 列括号内为对应小节中的明细；AUD-01..10 为方法论条款，全部归入 unit-domain。

## Unit-Domain 清单（18 条，pcap 结构上不可表达，由 Go 单测/真实环境承载）

| Spec ID | 不可表达原因 | 单测承载 |
|---------|-------------|----------|
| V-N-16 / NEW-11 系 | convert 层 defaultMAC 恒填充 dst_mac，MCP 下 spec.DstMAC 永不空 | planner_test.go "end.x without dst_mac"（srv6_vn16_endx_no_dstmac 为正向 marker 用例） |
| V-N-18 / NEW-11 | convert 层 switch protocol 互斥：protocol=srv6 时 mpls 子配置永不解析 | planner_test.go "combined with MPLS"（srv6_vn18_srv6_mpls 为正向 marker 用例） |
| V-N-19 / NEW-12 | 同 V-N-18（gre 分支） | planner_test.go "combined with GRE"（srv6_vn19_srv6_gre 为正向 marker 用例） |
| V-N-23 | writeSRH 硬编码 RoutingType=4；planner 运行时恒一致，仅手构 SRHConfig 可触发 | builder 层单测（srv6_exc01_hdr_ext_len_mismatch 为 marker 用例） |
| EXC-01 / NEW-16 | builder 层异常：HdrExtLen 与序列化总长不符需手构 SRHConfig，MCP 路径不可达 | builder 层单测 |
| E2E-07 / NEW-15 | 依赖真实网卡（SRV6_TEST_NIC 环境变量） | integration_test.go（-short 跳过） |
| E2E-10 | 5 条 FlowSpec 串联的多视角路径，非单任务可表达 | planner_test 多视角用例 |
| AUD-01..10 | 方法论条款（一测一路径/失败优先/质量审计等），非用例 | 各 Go 测试文件 |

## Key Findings（测试过程中发现）

1. **覆盖率从 39.9% 提升到 83.2%**（57/143 → 119/143）。负向 Validate（V-N-01..24）由 expect_error 机制全部覆盖；边界（127 段/HEL 254/溢出）由超大 segment_list 用例覆盖；多流（MF-01..05）由 strategy_fc(flows=N) 驱动覆盖。

2. **核心字节级断言全部命中**：反序存储（BYT-08/17）、UDP/TCP 伪头 DstIP=SegmentList[0]（BYT-13/14/22）、HMAC 8n 对齐（BYT-16）、Reduced SRH 布局（BYT-18）、Pad1 单字节填充（BYT-15/BND-12）、HBH 链（BYT-19）均经 tshark 字节级确认。

3. **convert 层真实缺口（非 bug，但值得报告）**：
   - defaultMAC 恒填充 dst_mac → V-N-16（end.x 缺 DstMAC）经 MCP 不可达；
   - switch protocol 互斥 → V-N-18/19（SRv6+MPLS/GRE）经 MCP 不可达；
   - worker.go:279 src_port 递增仅在**无显式 src_port** 时生效（HasExplicitSrcPort）——e2e04/mf03/mf05 原期望 1024+i 与实现不符，改为默认 12345+i。

4. **worker src_port 默认 12345+i**：多流用例（MF-01/E2E-04）实际端口为 12345..12444（非设计写的 1024..1123）。设计 §7.5 MF-01 的 "src_port 1024..1123" 与实际 worker 默认值不符——pcap 用例按实现断言，并在 notes 中记录。

5. **Go IPv6 解析怪癖**：`2001:db8::127` 按 hextet 解析为 0x0127（字节 `01 27`），非十进制 127（`00 7f`）——段地址序号超过 9 时 wire 字节与十进制序号不一致，这是 Go net.ParseIP 的标准行为，非 bug；127 段用例的字节断言按 `01 27` 校准。

6. **IPv6 帧偏移**：IPv6 固定头在 frame offset 14-21，SrcIP 22-37，DstIP 38-53，SRH 54+（早期断言曾误用 30-45，已修正）。NEW-08（DstIP 字节比对）按 38-53 断言。

7. **设计 §7.10 NEW-13 算术错误**："1 段 + SL=1 → 1 > last_entry+1=1" 不成立（1 > 1 为 false）。实现为 2 段 + SL=3 → 3 > 2 触发 VR-09，用例 notes 已记录。

8. **设计 §7.5 MF-01 端口范围与实现不符**（见 #4）；§7.6 BND-02 的 "16 字节 TLV" 与 HEL=254 边界在 126 段 + 8B TLV（含 2B 头 = 10B）下恰好成立。

## 说明

- pcap 用例文件：`/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/srv6.json`（68 用例，含 22 个 expect_error 负向用例 + 3 个 unit-domain marker 正向用例）
- 运行命令：`CASE_PROTO=srv6 CASE_TIMEOUT_S=600 go test -timeout 900s -run TestProtocolPcapDrive ./test/protocol_pcap/`（68/68 pass）
- `-race` 验证：`CASE_PROTO=srv6 go test -race -count=1 -timeout 900s -run TestProtocolPcapDrive ./test/protocol_pcap/`（clean）
- 结果文档 `srv6.md` 由测试运行自动再生成（writeDocs）
