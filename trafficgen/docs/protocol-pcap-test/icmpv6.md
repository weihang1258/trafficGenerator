# icmpv6 Pcap Test Results

Cases: 11 — pass 11, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| icmpv6_ip_dyn_multi | T-ICMPV6-11: ip.src 动态 inc + flows=2 → 4 包逐流源异（3.14 逃生口；dynamic 对象豁免 static copy 门） | pass | 4 | [pcap](icmpv6/icmpv6_ip_dyn_multi.pcap) |
| icmpv6_neg_code | T-ICMPV6-6: code=1 非 0（Echo 报文 code 恒 0，RFC 4443 §4.1/§4.2） | pass | 0 | [pcap]() |
| icmpv6_neg_pattern_step | T-ICMPV6-7: pattern step type=0 非法 | pass | 0 | [pcap]() |
| icmpv6_neg_type | T-ICMPV6-5: type=130 非法（Echo 语义仅 128/129） | pass | 0 | [pcap]() |
| icmpv6_neg_v4 | T-ICMPV6-4: v4 地址经 [ip,icmpv6] 链必须拒（legacy Validate v6 强制 icmpv6.go:60-79 复用） | pass | 0 | [pcap]() |
| icmpv6_pattern_data | T-ICMPV6-10: Pattern 多步多变 data（aa/bb）→ 4 包 seq 1/2 递增、data 逐字节断言 | pass | 4 | [pcap](icmpv6/icmpv6_pattern_data.pcap) |
| icmpv6_pattern_mixed | T-ICMPV6-9: Pattern 混型步（128 步+129 步）→ 3 包（req+reply 对 + 单 reply）；identifier 缺省 0 回退 Sequence | pass | 3 | [pcap](icmpv6/icmpv6_pattern_mixed.pcap) |
| icmpv6_smoke_01 | 冒烟：ICMPv6 Echo Request → 自动 Reply（IPv6 链路，地址住 ip 层）。type 128/129、code 0、id/seq 固定 1，共 2 包 | pass | 2 | [pcap](icmpv6/icmpv6_smoke_01.pcap) |
| icmpv6_type_129 | T-ICMPV6-8: type=129 单发（无 auto-reply，up 向 1 包）；identifier/sequence/data 显式（id=7≠seq=9 证非回退） | pass | 1 | [pcap](icmpv6/icmpv6_type_129.pcap) |
| icmpv6_vn_presence | T-ICMPV6-2: 顶层 icmpv6 presence 判死（空 map 也死，CheckProtoFlat sv 先例） | pass | 0 | [pcap]() |
| icmpv6_vn_static_copy | T-ICMPV6-3: ip 层显式标量 v6 地址 + flows=2 拒绝（static four-tuple 门） | pass | 0 | [pcap]() |
