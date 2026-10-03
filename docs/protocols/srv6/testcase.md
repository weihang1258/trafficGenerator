# #15 SRv6 测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocols/srv6/design.md` v2.0.3（历史 RFC 推导场景与当前 JSON 机器契约分开计数）
> 机器契约：`trafficgen/test/protocol_pcap/cases/srv6.json`（**74/74 ID 与本文 §2 顺序一致，已用 Python 机读**）
> 白话一句：**四十九条正例覆盖 SRH 反序、reduced、TLV、封装、逐包/多流与边界；二十五条负例覆盖校验器、框架门和 presence/静态复制拒绝；当前 JSON 仍登记四个顶层键形缺口/负例形状，不能把 as-built 写成纯层链。**

## 1. 形状基线（机读实测）

本版只登记机器契约现状，不宣称 pcap/NIC 复跑。`srv6.json` 是 JSON 数组，共 **74 例 = 49 正 + 25 负**；ID 无重复，顺序以 JSON 为权威。正例字段断言共 **142 条**。

| 项 | 机读结果 |
|---|---:|
| 例总数 | **74** |
| 正例 / 负例 | **49 / 25** |
| `spec_json` 顶层 `{layers}` | **70** |
| `spec_json` 顶层 `{group_id,layers}` | **3** |
| `spec_json` 顶层 `{layers,srv6}` | **1** |
| `{layers}` 之外的 P4 缺口 | **4**（G-SRV6-N-1…G-SRV6-N-4） |
| 正例字段断言 | **142** |
| 正例包数分布 | `packet_count=1` × 42；`packet_count=5` × 2；`packet_count=1000` × 1；`packet_count=100` × 1；`packet_count=10` × 3 |
| `strategy_fc` | **5**（4 正例多流 + 1 负例静态复制） |
| 负例 `expect` 严格为 `{expect_error,error_contains}` | **25/25** |

**层形基线**：`[ip,srv6]` × 73；`[eth,ip,srv6]` × 1（`srv6_vp04_endx_dstmac`）。这只是机器契约的现状形状，不替代顶层键迁移判定。

**P4 缺口逐类登记**：

- **G-SRV6-N-1…N-3：** `{group_id,layers}`（`srv6_e2e04_multi_flow_100`、`srv6_mf03_flowid_unique`、`srv6_mf05_group_id`）。`group_id` 仍游离在 `spec_json` 顶层；多流路由语义已在存量 JSON 中使用，待 P4 迁入统一层链承载。
- **G-SRV6-N-4：** `{layers,srv6}`（`srv6_t74_presence_reject`）。这是故意的顶层 `srv6` presence 负例形状，不能当作正例残留；负例保留原形以测试拒绝门。

## 2. 原子用例索引（74 条，JSON 顺序）

| # | ID | 类型 | `packet_count` | fields 条数 |
|---:|---|---|---:|---:|
| 1 | `srv6_tpos1_basic` | 正 | 1 | 9 |
| 2 | `srv6_tpos2_multi3_reverse` | 正 | 1 | 5 |
| 3 | `srv6_tpos3_reduced` | 正 | 1 | 4 |
| 4 | `srv6_tpos4_hmac_tlv` | 正 | 1 | 1 |
| 5 | `srv6_tpos5_padn` | 正 | 1 | 2 |
| 6 | `srv6_tpos6_nested_ipv6` | 正 | 1 | 3 |
| 7 | `srv6_tpos7_midpoint` | 正 | 1 | 4 |
| 8 | `srv6_tpos10_b6_encaps` | 正 | 1 | 1 |
| 9 | `srv6_tpos9_frames` | 正 | 5 | 3 |
| 10 | `srv6_tpos11_icmpv6` | 正 | 1 | 3 |
| 11 | `srv6_tpos13_direction_down` | 正 | 1 | 6 |
| 12 | `srv6_tpos14_payload_none` | 正 | 1 | 2 |
| 13 | `srv6_tpos15_tag` | 正 | 1 | 4 |
| 14 | `srv6_tpos16_pad1` | 正 | 1 | 2 |
| 15 | `srv6_tpos17_hbh_chain` | 正 | 1 | 3 |
| 16 | `srv6_tpos18_tag_max` | 正 | 1 | 3 |
| 17 | `srv6_tpos19_tag_zero` | 正 | 1 | 2 |
| 18 | `srv6_tpos20_reduced_hmac` | 正 | 1 | 4 |
| 19 | `srv6_vn02_empty_segment_list` | 负 | — | 0 |
| 20 | `srv6_vn03_128_segments` | 负 | — | 0 |
| 21 | `srv6_vn04_segments_left_gt_last_entry` | 负 | — | 0 |
| 22 | `srv6_vn05_segment_not_ipv6` | 负 | — | 0 |
| 23 | `srv6_vn06_src_ipv6_invalid` | 负 | — | 0 |
| 24 | `srv6_vn07_src_ip_ipv4` | 负 | — | 0 |
| 25 | `srv6_vn08_unknown_seg_type` | 负 | — | 0 |
| 26 | `srv6_vn09_flags_nonzero` | 负 | — | 0 |
| 27 | `srv6_vn10_tlv_value_256` | 负 | — | 0 |
| 28 | `srv6_vn11_pad1_manual` | 负 | — | 0 |
| 29 | `srv6_vn12_padn_manual` | 负 | — | 0 |
| 30 | `srv6_vn13_tlv_type1_reserved` | 负 | — | 0 |
| 31 | `srv6_vn14_tlv_type2_reserved` | 负 | — | 0 |
| 32 | `srv6_vn15_tlv_type6_reserved` | 负 | — | 0 |
| 33 | `srv6_vn16_endx_no_dstmac` | 正 | 1 | 1 |
| 34 | `srv6_vn17_endb6_short_inner` | 负 | — | 0 |
| 35 | `srv6_vn18_srv6_mpls` | 正 | 1 | 1 |
| 36 | `srv6_vn19_srv6_gre` | 正 | 1 | 1 |
| 37 | `srv6_vn20_dx6_short_inner` | 负 | — | 0 |
| 38 | `srv6_vn21_dx6_payload_none` | 负 | — | 0 |
| 39 | `srv6_vn22_hdr_ext_len_overflow` | 负 | — | 0 |
| 40 | `srv6_vn24_down_with_segments_left` | 负 | — | 0 |
| 41 | `srv6_bnd01_127_segments` | 正 | 1 | 4 |
| 42 | `srv6_bnd02_126_segments_tlv` | 正 | 1 | 2 |
| 43 | `srv6_bnd04_127_segments_reduced` | 正 | 1 | 4 |
| 44 | `srv6_bnd10_tlv_value_255` | 正 | 1 | 1 |
| 45 | `srv6_bnd06_frames_1000` | 正 | 1000 | 6 |
| 46 | `srv6_p18_b6_encaps_red_default_reduced` | 正 | 1 | 5 |
| 47 | `srv6_vp04_endx_dstmac` | 正 | 1 | 2 |
| 48 | `srv6_vp03_full_explicit` | 正 | 1 | 6 |
| 49 | `srv6_vp06_endb6` | 正 | 1 | 2 |
| 50 | `srv6_new01_dx4` | 正 | 1 | 2 |
| 51 | `srv6_new01a_dt4` | 正 | 1 | 2 |
| 52 | `srv6_new01b_dt6` | 正 | 1 | 3 |
| 53 | `srv6_new03_inner_src_port_fallback` | 正 | 1 | 2 |
| 54 | `srv6_new04_inner_src_port_override` | 正 | 1 | 1 |
| 55 | `srv6_new05_segments_left_default` | 正 | 1 | 2 |
| 56 | `srv6_new06_segments_left_zero` | 正 | 1 | 2 |
| 57 | `srv6_new07_hdr_ext_len_byte` | 正 | 1 | 0 |
| 58 | `srv6_new08_dstip_byte_match` | 正 | 1 | 0 |
| 59 | `srv6_new13_single_seg_sl_1` | 负 | — | 0 |
| 60 | `srv6_new14_end_un` | 正 | 1 | 2 |
| 61 | `srv6_new09_frames_negative` | 负 | — | 0 |
| 62 | `srv6_e2e04_multi_flow_100` | 正 | 100 | 4 |
| 63 | `srv6_mf03_flowid_unique` | 正 | 10 | 3 |
| 64 | `srv6_mf04_down_multi_flow` | 正 | 10 | 5 |
| 65 | `srv6_mf05_group_id` | 正 | 10 | 2 |
| 66 | `srv6_exc01_hdr_ext_len_mismatch` | 正 | 1 | 1 |
| 67 | `srv6_tpos21_multi_flow` | 正 | 5 | 3 |
| 68 | `srv6_t69_none_inner_payload_reject` | 负 | — | 0 |
| 69 | `srv6_t70_reduced_false` | 正 | 1 | 5 |
| 70 | `srv6_t71_tlv_type3_reject` | 负 | — | 0 |
| 71 | `srv6_t72_combo_hbh_tlv` | 正 | 1 | 3 |
| 72 | `srv6_t73_combo_down_hmac` | 正 | 1 | 4 |
| 73 | `srv6_t74_presence_reject` | 负 | — | 0 |
| 74 | `srv6_t75_static_copy_reject` | 负 | — | 0 |

`packet_count` 读取值逐条来自 JSON：1 包 × 42、5 包 × 2、10 包 × 3、100 包 × 1、1000 包 × 1；负例无包数。**以上仅为契约期望，不是本轮复跑结果。**

## 3. 正例断言契约（JSON 原子断言转录）

字段值和 frames hex 均按 JSON 原文登记；未写入的断言不补猜测。`frames` 的 offset 是契约给出的帧内偏移；SRH/IPv6/TLV 语义以配套设计 §2–§7 为准。

| # | ID | 包数 | fields（逐条） | frames（逐条） |
|---:|---|---:|---|---|
| 1 | `srv6_tpos1_basic` | 1 | ipv6.nxt=43；ipv6.routing.type=4；ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0；ipv6.routing.srh.flags=0x00；ipv6.routing.srh.tag=0000；ipv6.routing.srh.addr=2001:db8::2；ipv6.dst=2001:db8::2；udp.dstport=53 | 包1 offset 14 `62 00 00 00 00 28 2b 40`；包1 offset 54 `11 02 04 00 00 00 00 00`；包1 offset 78 `30 39 00 35 00 10`；包1 offset 86 `31 32 33 34 35 36 37 38` |
| 2 | `srv6_tpos2_multi3_reverse` | 1 | ipv6.routing.segleft=2；ipv6.routing.srh.last_entry=2；ipv6.routing.srh.addr=2001:db8:c::1,2001:db8:b::1,2001:db8:a::1；ipv6.dst=2001:db8:a::1；tcp.dstport=8080 | 包1 offset 14 `62 00 00 00 00 4c 2b 40`；包1 offset 54 `06 06 04 02 02 00 00 00`；包1 offset 62 `20 01 0d b8 00 0c 00 00 00 00 00 00 00 00 00 01`；包1 offset 78 `20 01 0d b8 00 0b 00 00 00 00 00 00 00 00 00 01`；包1 offset 94 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01`；包1 offset 110 `30 39 1f 90` |
| 3 | `srv6_tpos3_reduced` | 1 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=0；ipv6.routing.srh.addr=2001:db8:b::1；ipv6.dst=2001:db8:a::1 | 包1 offset 54 `11 02 04 01 00 00 00 00`；包1 offset 62 `20 01 0d b8 00 0b 00 00 00 00 00 00 00 00 00 01`；包1 offset 78 `30 39 00 50 00 08` |
| 4 | `srv6_tpos4_hmac_tlv` | 1 | ipv6.routing.srh.flags=0x00 | 包1 offset 14 `62 00 00 00 00 48 2b 40`；包1 offset 54 `11 07 04 00 00 00 00 00`；包1 offset 62 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01`；包1 offset 78 `05 26 00 00 00 00 00 01`；包1 offset 86 `00 00 00 00 00 00 00 00`；包1 offset 94 `00 00 00 00 00 00 00 00`；包1 offset 102 `00 00 00 00 00 00 00 00`；包1 offset 110 `00 00 00 00 00 00 00 00`；包1 offset 118 `30 39 00 50 00 08` |
| 5 | `srv6_tpos5_padn` | 1 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0 | 包1 offset 14 `62 00 00 00 00 28 2b 40`；包1 offset 54 `11 03 04 00 00 00 00 00`；包1 offset 62 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01`；包1 offset 78 `c8 04 61 62 63 64 04 00`；包1 offset 86 `30 39 00 50 00 08` |
| 6 | `srv6_tpos6_nested_ipv6` | 1 | ipv6.routing.segleft=0；ipv6.routing.type=4；ipv6.routing.srh.addr=2001:db8::2 | 包1 offset 14 `62 00 00 00 00 50 2b 40`；包1 offset 54 `29 02 04 00 00 00 00 00`；包1 offset 78 `60 00 00 00 00 10 11 40`；包1 offset 118 `30 39 00 35 00 10`；包1 offset 126 `31 32 33 34 35 36 37 38` |
| 7 | `srv6_tpos7_midpoint` | 1 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=2；ipv6.routing.srh.addr=2001:db8:c::1,2001:db8:b::1,2001:db8:a::1；ipv6.dst=2001:db8:b::1 | 包1 offset 14 `62 00 00 00 00 40 2b 40`；包1 offset 54 `11 06 04 01 02 00 00 00`；包1 offset 62 `20 01 0d b8 00 0c 00 00 00 00 00 00 00 00 00 01`；包1 offset 94 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01`；包1 offset 110 `30 39 00 50 00 08` |
| 8 | `srv6_tpos10_b6_encaps` | 1 | ipv6.routing.type=4,4 | 包1 offset 14 `62 00 00 00 00 60 2b 40`；包1 offset 54 `29 02 04 00 00 00 00 00`；包1 offset 78 `60 00 00 00 00 20 2b 40`；包1 offset 118 `11 02 04 00 00 00 00 00`；包1 offset 142 `00 00 00 00 00 08 a4 69` |
| 9 | `srv6_tpos9_frames` | 5 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=1；ipv6.dst=2001:db8:a::1 | 包1 offset 54 `11 04 04 01 01 00 00 00`；包5 offset 54 `11 04 04 01 01 00 00 00` |
| 10 | `srv6_tpos11_icmpv6` | 1 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0；ipv6.routing.type=4 | 包1 offset 14 `62 00 00 00 00 20 2b 40`；包1 offset 54 `3a 02 04 00 00 00 00 00`；包1 offset 62 `20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02`；包1 offset 78 `31 32 33 34 35 36 37 38` |
| 11 | `srv6_tpos13_direction_down` | 1 | ipv6.src=2001:db8:a::1；ipv6.dst=2001:db8:c::1；ipv6.routing.segleft=2；ipv6.routing.srh.addr=2001:db8:a::1,2001:db8:b::1,2001:db8:c::1；udp.srcport=4444；udp.dstport=3333 | 包1 offset 54 `11 06 04 02 02 00 00 00` |
| 12 | `srv6_tpos14_payload_none` | 1 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0 | 包1 offset 14 `62 00 00 00 00 18 2b 40`；包1 offset 54 `3b 02 04 00 00 00 00 00` |
| 13 | `srv6_tpos15_tag` | 1 | ipv6.routing.srh.tag=abcd；ipv6.routing.segleft=2；ipv6.routing.srh.last_entry=2；ipv6.routing.srh.addr=2001:db8:c::1,2001:db8:b::1,2001:db8:a::1 | 包1 offset 54 `06 06 04 02 02 00 ab cd`；包1 offset 62 `20 01 0d b8 00 0c 00 00 00 00 00 00 00 00 00 01`；包1 offset 94 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01` |
| 14 | `srv6_tpos16_pad1` | 1 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0 | — |
| 15 | `srv6_tpos17_hbh_chain` | 1 | ipv6.nxt=0；ipv6.hopopts.nxt=43；ipv6.routing.type=4 | 包1 offset 54 `2b 00 00 01 03 00 00 00`；包1 offset 62 `11 02 04 00 00 00 00 00` |
| 16 | `srv6_tpos18_tag_max` | 1 | ipv6.routing.srh.tag=ffff；ipv6.routing.segleft=2；ipv6.routing.srh.last_entry=2 | 包1 offset 54 `11 06 04 02 02 00 ff ff` |
| 17 | `srv6_tpos19_tag_zero` | 1 | ipv6.routing.srh.tag=0000；ipv6.routing.segleft=0 | 包1 offset 54 `11 02 04 00 00 00 00 00` |
| 18 | `srv6_tpos20_reduced_hmac` | 1 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=0；ipv6.routing.srh.addr=2001:db8:b::1；ipv6.dst=2001:db8:a::1 | — |
| 19 | `srv6_vn16_endx_no_dstmac` | 1 | ipv6.routing.segleft=0 | — |
| 20 | `srv6_vn18_srv6_mpls` | 1 | ipv6.routing.segleft=0 | — |
| 21 | `srv6_vn19_srv6_gre` | 1 | ipv6.routing.segleft=0 | — |
| 22 | `srv6_bnd01_127_segments` | 1 | ipv6.routing.segleft=126；ipv6.routing.srh.last_entry=126；ipv6.plen=2048；ipv6.dst=2001:db8::1 | 包1 offset 54 `11 fe 04 7e 7e 00 00 00`；包1 offset 62 `20 01 0d b8 00 00 00 00 00 00 00 00 00 00 01 27` |
| 23 | `srv6_bnd02_126_segments_tlv` | 1 | ipv6.routing.srh.last_entry=125；ipv6.plen=2048 | 包1 offset 54 `11 fe 04 7d 7d 00 00 00` |
| 24 | `srv6_bnd04_127_segments_reduced` | 1 | ipv6.routing.segleft=126；ipv6.routing.srh.last_entry=125；ipv6.plen=2032；ipv6.dst=2001:db8::1 | 包1 offset 54 `11 fc 04 7e 7d 00 00 00` |
| 25 | `srv6_bnd10_tlv_value_255` | 1 | ipv6.routing.segleft=0 | 包1 offset 54 `11 23 04 00 00 00 00 00`；包1 offset 78 `c8 ff 00 01 02 03 04 05` |
| 26 | `srv6_bnd06_frames_1000` | 1000 | ipv6.hlim=64；ipv6.hlim=255；ipv6.hlim=254；ipv6.hlim=255；ipv6.hlim=85；ipv6.routing.segleft=0 | — |
| 27 | `srv6_p18_b6_encaps_red_default_reduced` | 1 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=0；ipv6.routing.srh.addr=2001:db8:b::1；ipv6.dst=2001:db8:a::1,2001:db8::2；ipv6.routing.type=4 | 包1 offset 14 `62 00 00 00 00 48 2b 40`；包1 offset 54 `29 02 04 01 00 00 00 00`；包1 offset 62 `20 01 0d b8 00 0b 00 00 00 00 00 00 00 00 00 01`；包1 offset 78 `60 00 00 00 00 08 11 40`；包1 offset 118 `30 39 00 35 00 08` |
| 28 | `srv6_vp04_endx_dstmac` | 1 | ipv6.routing.segleft=0；eth.dst=02:00:00:00:00:99 | 包1 offset 54 `11 02 04 00 00 00 00 00` |
| 29 | `srv6_vp03_full_explicit` | 1 | ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=1；ipv6.routing.srh.flags=0x00；ipv6.routing.srh.tag=1234；udp.srcport=3333；udp.dstport=4444 | 包1 offset 54 `11 05 04 01 01 00 12 34`；包1 offset 94 `c8 04 61 62 63 64 04 00` |
| 30 | `srv6_vp06_endb6` | 1 | ipv6.routing.segleft=0；ipv6.routing.nxt=41 | 包1 offset 54 `29 02 04 00 00 00 00 00` |
| 31 | `srv6_new01_dx4` | 1 | ipv6.routing.segleft=0；ipv6.routing.nxt=4 | 包1 offset 54 `04 02 04 00 00 00 00 00`；包1 offset 78 `45 00 00 1c 00 01 00 00` |
| 32 | `srv6_new01a_dt4` | 1 | ipv6.routing.segleft=0；ipv6.routing.nxt=4 | 包1 offset 54 `04 02 04 00 00 00 00 00`；包1 offset 78 `45 00 00 1c 00 01 00 00` |
| 33 | `srv6_new01b_dt6` | 1 | ipv6.routing.segleft=0；ipv6.routing.nxt=41；ipv6.routing.type=4 | 包1 offset 54 `29 02 04 00 00 00 00 00` |
| 34 | `srv6_new03_inner_src_port_fallback` | 1 | udp.srcport=12345；udp.dstport=53 | — |
| 35 | `srv6_new04_inner_src_port_override` | 1 | udp.srcport=54321 | — |
| 36 | `srv6_new05_segments_left_default` | 1 | ipv6.routing.segleft=2；ipv6.routing.srh.last_entry=2 | — |
| 37 | `srv6_new06_segments_left_zero` | 1 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=1 | — |
| 38 | `srv6_new07_hdr_ext_len_byte` | 1 | （无 fields；以 frames/notes 为准） | 包1 offset 54 `11 02` |
| 39 | `srv6_new08_dstip_byte_match` | 1 | （无 fields；以 frames/notes 为准） | 包1 offset 38 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01`；包1 offset 94 `20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01` |
| 40 | `srv6_new14_end_un` | 1 | ipv6.routing.segleft=0；ipv6.routing.type=4 | — |
| 41 | `srv6_e2e04_multi_flow_100` | 100 | ipv6.routing.segleft=0；ipv6.routing.segleft=0；udp.srcport=12345；udp.srcport=12444 | 包1 offset 54 `11 02 04 00 00 00 00 00`；包100 offset 54 `11 02 04 00 00 00 00 00` |
| 42 | `srv6_mf03_flowid_unique` | 10 | udp.srcport=12345；udp.srcport=12354；ipv6.routing.segleft=0 | — |
| 43 | `srv6_mf04_down_multi_flow` | 10 | ipv6.src=2001:db8:a::1；ipv6.dst=2001:db8:c::1；udp.srcport=4444；udp.srcport=4444；ipv6.routing.segleft=2 | — |
| 44 | `srv6_mf05_group_id` | 10 | udp.srcport=12345；udp.srcport=12354 | — |
| 45 | `srv6_exc01_hdr_ext_len_mismatch` | 1 | ipv6.routing.type=4 | — |
| 46 | `srv6_tpos21_multi_flow` | 5 | ipv6.routing.segleft=0；ipv6.routing.srh.last_entry=0；ipv6.routing.segleft=0 | 包1 offset 54 `11 02 04 00 00 00 00 00`；包5 offset 54 `11 02 04 00 00 00 00 00` |
| 47 | `srv6_t70_reduced_false` | 1 | ipv6.nxt=43；ipv6.routing.type=4；ipv6.routing.segleft=1；ipv6.routing.srh.last_entry=1；ipv6.routing.srh.addr=2001:db8:b::1,2001:db8:a::1 | — |
| 48 | `srv6_t72_combo_hbh_tlv` | 1 | ipv6.nxt=0；ipv6.routing.type=4；ipv6.routing.segleft=2 | — |
| 49 | `srv6_t73_combo_down_hmac` | 1 | ipv6.src=2001:db8:a::1；ipv6.dst=2001:db8:c::1；udp.srcport=4444；udp.dstport=3333 | — |

**正例覆盖面归纳（不扩大断言）**：

- SRH 基础/反序/DstIP：`srv6_tpos1_basic`、`srv6_tpos2_multi3_reverse`、`srv6_tpos7_midpoint`、`srv6_new08_dstip_byte_match`、`srv6_t70_reduced_false`。
- reduced、默认值、Tag、SegmentsLeft：`srv6_tpos3_reduced`、`srv6_tpos20_reduced_hmac`、`srv6_p18_b6_encaps_red_default_reduced`、`srv6_new05_segments_left_default`、`srv6_new06_segments_left_zero`、`srv6_tpos15_tag`、`srv6_tpos18_tag_max`、`srv6_tpos19_tag_zero`。
- TLV/对齐/HMAC/组合链：`srv6_tpos4_hmac_tlv`、`srv6_tpos5_padn`、`srv6_tpos16_pad1`、`srv6_tpos17_hbh_chain`、`srv6_t72_combo_hbh_tlv`、`srv6_t73_combo_down_hmac`。
- 内层与 End*：`srv6_tpos6_nested_ipv6`、`srv6_tpos10_b6_encaps`、`srv6_vp06_endb6`、`srv6_new01_dx4`、`srv6_new01a_dt4`、`srv6_new01b_dt6`、`srv6_tpos11_icmpv6`、`srv6_tpos14_payload_none`、`srv6_new14_end_un`。
- 多流/帧/边界：`srv6_tpos9_frames`、`srv6_tpos21_multi_flow`、`srv6_e2e04_multi_flow_100`、`srv6_mf03_flowid_unique`、`srv6_mf04_down_multi_flow`、`srv6_mf05_group_id`、`srv6_bnd01_127_segments`、`srv6_bnd02_126_segments_tlv`、`srv6_bnd04_127_segments_reduced`、`srv6_bnd10_tlv_value_255`、`srv6_bnd06_frames_1000`。

**已知契约语义边界**：`srv6_exc01_hdr_ext_len_mismatch` 的 notes 明确说 builder 手写 `SRHConfig` 异常无法由 MCP 配置构造；其 JSON 只保留可观察的 `ipv6.routing.type=4`，不能宣称已覆盖 builder mismatch。`srv6_vn16_endx_no_dstmac`、`srv6_vn18_srv6_mpls`、`srv6_vn19_srv6_gre` 现为正例（各有 packet/field），notes 已明确 MCP default/switch 使设计负路径不可达；真正 planner 单测不在本 JSON 中。

## 4. 负例契约

负例 `expect` 严格为 `{expect_error,error_contains}`；25 例均带拒绝信号和真实锚词，不混入 `notes`、`packet_count`、`fields` 或其他成功断言。逐条 `error_contains` 如下。

| # | ID | `error_contains` | 现状备注 |
|---:|---|---|---|
| N-1 | `srv6_vn02_empty_segment_list` | `segment_list must not be empty` | design §7.2 T-SRV6-V-N-02; getStringSlice 过滤空串但保留空数组 → len=0 → VR-02 |
| N-2 | `srv6_vn03_128_segments` | `segment_list too large for 8-bit hdr_ext_len` | design §7.2 T-SRV6-V-N-03 / §7.10 NEW-10; 128 段 → VR-03 (max 127) |
| N-3 | `srv6_vn04_segments_left_gt_last_entry` | `segments_left (5) > last_entry+1 (3)` | design §7.2 T-SRV6-V-N-04; 3 段 → LE=2 → last_entry+1=3 → VR-09 |
| N-4 | `srv6_vn05_segment_not_ipv6` | `segment_list[0] must be IPv6` | design §7.2 T-SRV6-V-N-05; IPv4 字面量 → To4()!=nil → VR-04 |
| N-5 | `srv6_vn06_src_ipv6_invalid` | `src_ipv6 "10.0.0.1" is not IPv6` | design §7.2 T-SRV6-V-N-06; cfg.SrcIPv6 非 IPv6 → VR-05 |
| N-6 | `srv6_vn07_src_ip_ipv4` | `spec.SrcIP "10.0.0.1" is not IPv6 (srv6 requires IPv6)` | design §7.2 T-SRV6-V-N-07; 原 v4/v6 混族会被 validateSpecBase 家族门先拦（14.11 断言须对真实执法门），改双 v4 同族放行家族门 → validator VR-06 真触发；错误串含 srv6 requires IPv6 |
| N-7 | `srv6_vn08_unknown_seg_type` | `unknown seg_type` | design §7.2 T-SRV6-V-N-08; 不在 29 个合法名中 → VR-07 |
| N-8 | `srv6_vn09_flags_nonzero` | `flags must be 0` | design §7.2 T-SRV6-V-N-09; RFC 8754 §2.1 全位 Unused → VR-08 |
| N-9 | `srv6_vn10_tlv_value_256` | `tlv[0] value length 256 exceeds 255 bytes` | design §7.2 T-SRV6-V-N-10 / §7.6 BND-11; Length 字段 1 字节 → VR-10 |
| N-10 | `srv6_vn11_pad1_manual` | `pad1 must not be set manually` | design §7.2 T-SRV6-V-N-11; autoInsertedTLVTypes[0] → VR-11 |
| N-11 | `srv6_vn12_padn_manual` | `padN must not be set manually` | design §7.2 T-SRV6-V-N-12; autoInsertedTLVTypes[4] → VR-12 |
| N-12 | `srv6_vn13_tlv_type1_reserved` | `reserved TLV type 1 must not be set` | design §7.2 T-SRV6-V-N-13; RFC 8754 Reserved type 1 → VR-13 |
| N-13 | `srv6_vn14_tlv_type2_reserved` | `reserved TLV type 2 must not be set` | design §7.2 T-SRV6-V-N-14; RFC 8754 Reserved type 2 → VR-13 |
| N-14 | `srv6_vn15_tlv_type6_reserved` | `reserved TLV type 6 must not be set` | design §7.2 T-SRV6-V-N-15; RFC 8754 中 HMAC-Sig 不存在 → VR-13 |
| N-15 | `srv6_vn17_endb6_short_inner` | `end.b6 requires inner_payload >= 40 bytes` | design §7.2 T-SRV6-V-N-17; inner_payload=4B < 40B → VR-15 |
| N-16 | `srv6_vn20_dx6_short_inner` | `end.dx6 requires inner_payload >= 40 bytes` | design §7.2 T-SRV6-V-N-20; inner_payload=4B < 40B → VR-15 |
| N-17 | `srv6_vn21_dx6_payload_none` | `end.dx6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.4), got "none"` | design §7.2 T-SRV6-V-N-21; NH=59 包被 RFC 8200 §4.7 丢弃 → 解封装永不触发 |
| N-18 | `srv6_vn22_hdr_ext_len_overflow` | `hdr_ext_len overflow (max 255)` | design §7.2 T-SRV6-V-N-22 / §7.6 BND-03; 127 段 HEL=254 + 任何 TLV 超 255 → VR-18 |
| N-19 | `srv6_vn24_down_with_segments_left` | `direction=down requires source-node view` | design §7.2 T-SRV6-V-N-24; §5.4 反转列表不支持 End 中转视角 → VR-23 |
| N-20 | `srv6_new13_single_seg_sl_1` | `segments_left (3) > last_entry+1 (2)` | design §7.10 NEW-13; 2 段 LE=1 -> last_entry+1=2; SL=3 > 2 -> VR-09 |
| N-21 | `srv6_new09_frames_negative` | `not a numeric value in [0,1000000]` | design §7.10 NEW-09; registry frames Min0/Max1000000（V9）在 validator VR-21 之前执法，锚词对真实执法门（14.11）——VR-21 由 V9 覆盖，语义不变 |
| N-22 | `srv6_t69_none_inner_payload_reject` | `payload_protocol=none with non-empty inner_payload` | — |
| N-23 | `srv6_t71_tlv_type3_reject` | `reserved TLV type 3 must not be set` | — |
| N-24 | `srv6_t74_presence_reject` | `top-level srv6 sub-config` | — |
| N-25 | `srv6_t75_static_copy_reject` | `static four-tuple` | — |

**负例按拒绝来源分类**：

- **SRv6 validator/边界**：`srv6_vn02_empty_segment_list`、`srv6_vn03_128_segments`、`srv6_vn04_segments_left_gt_last_entry`、`srv6_vn05_segment_not_ipv6`、`srv6_vn06_src_ipv6_invalid`、`srv6_vn07_src_ip_ipv4`、`srv6_vn08_unknown_seg_type`、`srv6_vn09_flags_nonzero`、`srv6_vn10_tlv_value_256`、`srv6_vn11_pad1_manual`、`srv6_vn12_padn_manual`、`srv6_vn13_tlv_type1_reserved`、`srv6_vn14_tlv_type2_reserved`、`srv6_vn15_tlv_type6_reserved`、`srv6_vn17_endb6_short_inner`、`srv6_vn20_dx6_short_inner`、`srv6_vn21_dx6_payload_none`、`srv6_vn22_hdr_ext_len_overflow`、`srv6_vn24_down_with_segments_left`、`srv6_new13_single_seg_sl_1`、`srv6_t69_none_inner_payload_reject`、`srv6_t71_tlv_type3_reject`。
- **框架/层链 presence 门**：`srv6_t74_presence_reject`，`{layers,srv6}` 是故意负例形状，锚词为 `top-level srv6 sub-config`。
- **静态复制门**：`srv6_t75_static_copy_reject`，`strategy_fc={type:flows,value:2}`，锚词为 `static four-tuple`。
- `srv6_new09_frames_negative` 的实际锚词是 registry/V9 的 `not a numeric value in [0,1000000]`，文档不改写成设计文档中另一个 planner 锚词。

## 5. 覆盖对账

### 5.1 三源回指

标准语义来自 RFC 8754、RFC 8200、RFC 8986；设计约束来自 `15-srv6-design.md` v2.0.2；机器现状来自 `srv6.json`。本版只完成 JSON 机读对账，**没有新增 pcap、tshark、NIC 或端到端证据**。

### 5.2 设计要求面 → 现有 ID

| 要求面 | 现有 ID |
|---|---|
| RFC 8754 SRH 反序、DstIP、SegmentsLeft/LastEntry | `srv6_tpos1_basic`、`srv6_tpos2_multi3_reverse`、`srv6_tpos7_midpoint`、`srv6_new08_dstip_byte_match` |
| Reduced SRH 与默认规则 | `srv6_tpos3_reduced`、`srv6_tpos20_reduced_hmac`、`srv6_p18_b6_encaps_red_default_reduced`、`srv6_t70_reduced_false` |
| TLV Type 4/5、HMAC、Pad1、PadN、保留类型 | `srv6_tpos4_hmac_tlv`、`srv6_tpos5_padn`、`srv6_tpos16_pad1`、`srv6_tpos20_reduced_hmac`、`srv6_tpos72_combo_hbh_tlv`、`srv6_vn11`…`vn15`、`srv6_t71_tlv_type3_reject` |
| IPv6 HBH + SRH 链 | `srv6_tpos17_hbh_chain`、`srv6_t72_combo_hbh_tlv` |
| 内层 UDP/TCP/ICMPv6/IPv4/IPv6/none | `srv6_tpos1_basic`、`srv6_tpos2_multi3_reverse`、`srv6_tpos11_icmpv6`、`srv6_new01`/`01a`/`01b`、`srv6_tpos14_payload_none` |
| End/End.X/End.DX*/End.B6*/End.DT*/End.uN 字符串与形态 | `srv6_tpos7_midpoint`、`srv6_vp04_endx_dstmac`、`srv6_tpos6_nested_ipv6`、`srv6_tpos10_b6_encaps`、`srv6_vp06_endb6`、`srv6_new01`/`01a`/`01b`、`srv6_new14_end_un` |
| Direction down 与端口/地址/List 反转 | `srv6_tpos13_direction_down`、`srv6_mf04_down_multi_flow`、`srv6_t73_combo_down_hmac` |
| frames、flows、group_id、多流唯一性 | `srv6_tpos9_frames`、`srv6_tpos21_multi_flow`、`srv6_e2e04_multi_flow_100`、`srv6_mf03_flowid_unique`、`srv6_mf04_down_multi_flow`、`srv6_mf05_group_id` |
| Hdr Ext Len、127/126 段、TLV 长度边界 | `srv6_new07_hdr_ext_len_byte`、`srv6_bnd01_127_segments`、`srv6_bnd02_126_segments_tlv`、`srv6_bnd04_127_segments_reduced`、`srv6_bnd10_tlv_value_255`、`srv6_vn22_hdr_ext_len_overflow` |

### 5.3 对账结论

- 机器 ID 集合、顺序、正负分布、`expect` 键形、包数和字段数均已从 JSON 读取；文档没有虚构 ID。
- `{layers}` 之外的 4 个顶层键形是 **P4 层形迁移缺口**或故意负例形状，不能计入“纯层链已收敛”。
- 负例语义覆盖不等于本轮执行通过；所有执行/P5/NIC 结论均写为**待 P5 重跑**。

## 6. P3 固定动作

### 6.1 §3.15 三项

1. **同连接/同流内多轮操作：不适用。** SRv6 是逐包 IPv6 扩展头，不提供连接状态机；多流由 `strategy_fc`/`frames` 表达，不能冒充会话多轮。
2. **非正常结束：不适用。** SRH 本身无 FIN/RST/会话拆除；错误输入走 validator/框架拒绝。
3. **长保活：不适用。** 无 SRv6 保活语义；持续流量由 frames/flows 生成。

### 6.2 A′/B′ 两分类

| 分类 | 现状 | 去向 |
|---|---|---|
| A′ 协议/载体缺口 | 顶层 `group_id` 3 例迁移；builder `HdrExtLen mismatch` 仅 notes 占位；MCP 不可达的 End.X/MPLS/GRE 负路径 | **G-SRV6-N-1…N-4**；后续 P4 迁移/补单测，不把现有正例改写为负例 |
| B′ 框架缺口 | `{layers,srv6}` presence 负例与静态复制负例已存在；仍需保留框架拒绝门的反查 | `srv6_t74_presence_reject`、`srv6_t75_static_copy_reject` |

## 7. 执行建议（待 P5）

1. 先按 JSON 顺序跑 74 条；负例须在 planner/validator/框架门失败，不得变成 completed/0 packet 的假成功。
2. P4 先处理 G-SRV6-N-1…N-3 的 `group_id` 顶层迁移；G-SRV6-N-4 保留为 presence 负例，不应删除或改成正例。
3. 复跑后核对 49 正例的 packet_count、142 条 fields、frames hex；尤其是 `srv6_tpos2_multi3_reverse` 的反序与 DstIP、`srv6_tpos4_hmac_tlv` 的 `05 26`、`srv6_tpos16_pad1` 的自动对齐、`srv6_bnd01/02/04` 的边界。
4. 执行证据须另行记录 pcap/tshark/NIC；本文件当前没有这些证据，**均待 P5 重跑**。

## 8. 存量审计

机器契约无旧独立 `15-srv6-testcase.md` 可供逐条迁移；当前 74 条即存量 JSON。逐条去向：**49 正例保留为观察契约，25 负例保留为拒绝契约，4 个顶层键形按 G-SRV6-N 登记**。`srv6_vn16_endx_no_dstmac`、`srv6_vn18_srv6_mpls`、`srv6_vn19_srv6_gre` 的 notes 明示 MCP 配置面不可达设计负路径，不能从“存在正例”推导负例已验证；`srv6_exc01_hdr_ext_len_mismatch` 同理是 builder 单测域占位。

## 9. 反查门断言

主线程后续可从本文和 JSON 机读反查，但本轮不修改 gate/ledger：

1. `len(cases)==74`，ID 集合和顺序等于 §2。
2. 正/负 = 49/25；负例 `expect` 严格为 25/25 `{expect_error,error_contains}`，无 `packet_count`/`fields`/`notes`。
3. `spec_json` 顶层键形计数为 `{layers}:70`、`{group_id,layers}:3`、`{layers,srv6}:1`；其中 `{group_id,layers}` 三例登记为 G-SRV6-N-1…N-3，`{layers,srv6}` 的 `srv6_t74_presence_reject` 是故意 presence 负例 G-SRV6-N-4。
4. `{layers}` 之外仅登记 G-SRV6-N-1…N-4；不得宣称非负例顶层键全为 `{layers}`。
5. 正例 fields 总数 = 142；包数分布为 1×42、5×2、10×3、100×1、1000×1。
6. 层形为 `[ip,srv6]` ×73、`[eth,ip,srv6]` ×1。
7. 五例 `strategy_fc` 的 ID = `srv6_e2e04_multi_flow_100`、`srv6_mf03_flowid_unique`、`srv6_mf04_down_multi_flow`、`srv6_mf05_group_id`、`srv6_t75_static_copy_reject`。
8. 所有复跑、pcap、NIC、tshark 和 P5 结论均必须有外部证据；当前状态写“待 P5 重跑”。

## 11. 文档轨对齐（T1–T6）

### 11.1 T1/T2 三源回指与测试点清单

| 规范行 | 业务场景 | 设计条目 | 代码分支 | 用例/缺口 |
|---|---|---|---|---|
| RFC 8754 §2 | Segment List 反序、Last Entry | design §2.2/§3.2 | planner wire-order | `srv6_tpos2_multi3_reverse` |
| RFC 8754 §4.1 | 源节点 DstIP=第一段 | design §2.3/§5.3 | planner default DstIPv6 | `srv6_tpos1_basic`、`srv6_new08_dstip_byte_match` |
| RFC 8754 §4.1.1 | Reduced SRH | design §3.3/§5.3 | reduced list/LastEntry | `srv6_tpos3_reduced`、`srv6_t70_reduced_false` |
| RFC 8754 §2.1/§8.2 | TLV、Pad、HMAC、保留类型 | design §2.4/§7.2 | TLV validator/serializer | `srv6_tpos4/5/16/20`、`srv6_vn11`…`vn15`、`srv6_t72_combo_hbh_tlv`、`srv6_t71` |
| RFC 8200 §4.4 | HBH→SRH 链 | design §1.2 | extension Next Header | `srv6_tpos17_hbh_chain`、`srv6_t72_combo_hbh_tlv` |
| RFC 8986 §4.4/§4.5/§4.8/§4.9/§4.13/§4.14 | End.DX*/DT*/B6* 内层协议 | design §3.4 | payload protocol 41/4 | `srv6_new01`/`01a`/`01b`、`srv6_vp06_endb6` |
| RFC 8200 §8.1 | IPv6 UDP/TCP/ICMPv6 校验和 | design §5.2.1 | builder checksum | `srv6_tpos1_basic`、`srv6_tpos11_icmpv6` |
| CORE §1.11–1.13 | 顶层白名单/层链 | design §12.7 | presence/static-copy gates | 70 严格例；G-SRV6-N-1…N-4 |

未能由现有 JSON 证明的商业设备行为，标“待确认”；确认方式是抓取对应设备的 SRH pcap 并逐字段对账，不把 RFC 模型冒充现网证据。

### 11.2 T3 颗粒度、T4 §3.15 与 T6 失败路径

- **数据场景**：段数 1/2/3/126/127、TLV value 0/1/255/256、Pad1/PadN/HMAC、IPv4/IPv6/UDP/TCP/ICMPv6/none、HBH 组合，均拆为独立 ID；边界断言见 §3 与设计 §6。
- **业务场景**：source/midpoint/reduced/End*、up/down、single/multi-flow、frames 5/10/100/1000 各有独立 ID；动态端口与静态复制门分别有正/负例。
- **现网场景**：商业设备映射目前待确认；已列确认方式。
- **T4 同连接多轮操作**：不适用，SRv6 无连接/事务；`frames`/`flows` 不是多轮会话。**非正常结束**不适用，错误输入由 validator/层链门拒绝。**长保活**不适用，持续发包由 frames/flows 表达；三项均已明确裁定而非留空。
- T6：25 个负例均严格为 `{expect_error,error_contains}`，不带 `notes`、`packet_count`、`fields` 或其他成功断言；`error_contains` 与契约表逐条对应。真红仍待 P5 执行证据，不能以 JSON 静态契约宣称运行通过。

### 11.3 T5 存量逐条去向与 C6

74 条均为当前机器契约存量：49 正例合入观察契约，25 负例合入拒绝契约；无作废条目。`group_id` 三例为顶层结构键，非协议业务键；`srv6_t74_presence_reject` 的顶层 `srv6` 是故意 presence 负例，保留以验证拒绝门。`trafficgen/docs/protocol-pcap-test/srv6-spec-mapping.md` 存在时，字段映射仅作辅助对账；本次未宣称其替代 JSON 权威。

### 11.4 C4 负例契约修订

2026-10-01 已将 25 个负例的 `expect` 统一为严格两键 `{expect_error,error_contains}`；删除仅供说明、但会破坏 C4 机读契约的 `notes`。负例仍按拒绝来源分组，锚词未改写；设计文档中的场景说明仍保留为文档证据。

## 12. 修订记录

- v1.0.2（2026-10-01）：按 C4 将 25 个负例 `expect` 严格收敛为 `{expect_error,error_contains}`，删除 `notes`，同步形状基线、T6 与修订说明；自审 **2 轮，末轮干净（passed 2 rounds, last round clean）**。
- v1.0.3（2026-10-01）：与 design.md v2.0.3 对齐 74 例/49 正/25 负机读形状；补历史设计场景与 JSON 例数区分、§9 反查门与缺口编号对应；自审 **2 轮，末轮干净（passed 2 rounds, last round clean）**。
