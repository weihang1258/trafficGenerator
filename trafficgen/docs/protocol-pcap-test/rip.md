# rip Pcap Test Results

Cases: 71 — pass 71, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| rip_tedge10_51_entries | T-EDGE-10: 51 route entries split 25+25+1, 3 packets | pass | 3 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge10_51_entries.pcap) |
| rip_tedge11_default_route | T-EDGE-11: default route 0.0.0.0/0 with metric 1 passes through | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge11_default_route.pcap) |
| rip_tedge12_ip_bcast_err | T-EDGE-12: route IP 255.255.255.255 rejected by Validate | pass | 0 | [pcap]() |
| rip_tedge13_mask_zero | T-EDGE-13: SubnetMask=0.0.0.0 legal, mask bytes 00 00 00 00 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge13_mask_zero.pcap) |
| rip_tedge14_mask_ffff | T-EDGE-14: SubnetMask=255.255.255.255 host route legal, mask bytes FF FF FF FF | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge14_mask_ffff.pcap) |
| rip_tedge15_mask_noncontig | T-EDGE-15: non-contiguous mask 255.0.0.3 warning, planner passes through bytes FF 00 00 03 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge15_mask_noncontig.pcap) |
| rip_tedge16_ripng_len0 | T-EDGE-16: RIPng PrefixLen=0 default route legal (prefix 2001:db8::) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge16_ripng_len0.pcap) |
| rip_tedge17_ripng_len128 | T-EDGE-17: RIPng PrefixLen=128 host route legal, wire 0x80 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge17_ripng_len128.pcap) |
| rip_tedge18_ripng_len129_err | T-EDGE-18: RIPng PrefixLen=129 rejected by Validate | pass | 0 | [pcap]() |
| rip_tedge19_domain_ffff | T-EDGE-19: domain=0xFFFF transparent passthrough (header bytes 2-3 = FF FF) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge19_domain_ffff.pcap) |
| rip_tedge1_metric0_err | T-EDGE-1: metric=0 rejected by Validate | pass | 0 | [pcap]() |
| rip_tedge20_default_routes | T-EDGE-20: Routes=nil + Scenario omitted -> 5 default routes emitted (frame-level) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge20_default_routes.pcap) |
| rip_tedge21_routers_empty | T-EDGE-21: Routers=[] -> single router == FlowSpec itself, unicast sport 520 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge21_routers_empty.pcap) |
| rip_tedge22_routers_100_inc | T-EDGE-22: 100 routers + GroupIDStrategy=inc [1,100] -> 100 distinct group ids, 100 packets | pass | 100 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge22_routers_100_inc.pcap) |
| rip_tedge2_metric1 | T-EDGE-2: metric=1 minimum legal, RTE metric bytes 00 00 00 01 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge2_metric1.pcap) |
| rip_tedge3_metric16 | T-EDGE-3: metric=16 unreachable, RTE metric bytes 00 00 00 10 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge3_metric16.pcap) |
| rip_tedge4_metric17_err | T-EDGE-4: metric=17 rejected by Validate | pass | 0 | [pcap]() |
| rip_tedge5_metric255_err | T-EDGE-5: metric=255 rejected by Validate | pass | 0 | [pcap]() |
| rip_tedge6_zero_routes | T-EDGE-6: response with 0 routes (explicit empty routes slice) -> bare 4-byte header payload | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge6_zero_routes.pcap) |
| rip_tedge7_25_entries | T-EDGE-7: 25 route entries in a single packet (504B payload, no auth) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge7_25_entries.pcap) |
| rip_tedge8_26_entries | T-EDGE-8: 26 route entries split 25+1, 2 packets, second packet 1 entry (metric 2 variant) | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge8_26_entries.pcap) |
| rip_tedge9_50_entries | T-EDGE-9: 50 route entries split 25+25, 2 packets | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tedge9_50_entries.pcap) |
| rip_terr10_password_17b | T-ERR-10: simple auth password 17 bytes rejected by Validate | pass | 0 | [pcap]() |
| rip_terr11_ip_invalid | T-ERR-11: route IP 999.1.1.1 (unparseable) rejected by Validate | pass | 0 | [pcap]() |
| rip_terr12_mask_invalid | T-ERR-12: route SubnetMask not-a-mask rejected by Validate | pass | 0 | [pcap]() |
| rip_terr13_nh_v6 | T-ERR-13: v2 route next_hop IPv6 literal rejected by Validate | pass | 0 | [pcap]() |
| rip_terr14_multicast_overrides | T-ERR-14: multicast overrides user DstIP (packet still goes to 224.0.0.9) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_terr14_multicast_overrides.pcap) |
| rip_terr15_split_poison | T-ERR-15: split_horizon + poison_reverse warning; unicast keeps both, NH==dst poisoned to metric 16 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_terr15_split_poison.pcap) |
| rip_terr16_router_empty | T-ERR-16: Routers=[{}] empty element rejected by Validate | pass | 0 | [pcap]() |
| rip_terr17_authdatalen0 | T-ERR-17: MD5 auth_data_len explicitly 0 rejected by Validate | pass | 0 | [pcap]() |
| rip_terr18_multicast_split | T-ERR-18: split_horizon + multicast warning; multicast skips filtering, both entries kept metric 1 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_terr18_multicast_split.pcap) |
| rip_terr19_afi_ffff_explicit | T-ERR-19: route AFI=0xFFFF explicit rejected by Validate | pass | 0 | [pcap]() |
| rip_terr1_version_v3 | T-ERR-1: version=v3 rejected by Validate | pass | 0 | [pcap]() |
| rip_terr3_command_update | T-ERR-3: command=update rejected by Validate | pass | 0 | [pcap]() |
| rip_terr5_afi3 | T-ERR-5: route AFI=3 rejected by Validate | pass | 0 | [pcap]() |
| rip_terr6_afi_ffff | T-ERR-6: route AFI=0xFFFF + routes non-empty rejected by Validate | pass | 0 | [pcap]() |
| rip_terr7_auth_sha256 | T-ERR-7: auth type sha256 rejected by Validate | pass | 0 | [pcap]() |
| rip_terr8_auth_v1 | T-ERR-8: auth non-nil + version=v1 rejected by Validate | pass | 0 | [pcap]() |
| rip_terr9_auth_ng | T-ERR-9: auth non-nil + version=ng rejected by Validate | pass | 0 | [pcap]() |
| rip_tpos10_route_poison | T-POS-10: route poison metric=16 injected (0x10 in metric field), v2 multicast | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos10_route_poison.pcap) |
| rip_tpos10_split_horizon | T-POS-11: unicast split_horizon filters route with next_hop==dst_ip (only 172.16.0.0 survives) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos10_split_horizon.pcap) |
| rip_tpos12_poison_reverse | T-POS-12: unicast poison_reverse -> both entries kept, route with next_hop==dst_ip metric set to 16 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos12_poison_reverse.pcap) |
| rip_tpos13_triggered | T-POS-13: triggered update -> Response only (no Request preamble), rounds=1, metric 16 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos13_triggered.pcap) |
| rip_tpos14_ripng | T-POS-14: RIPng (version ng) multicast FF02::9, port 521/521, header 02 01 00 00, 1 route 2001:db8::/64 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos14_ripng.pcap) |
| rip_tpos15_ripng_default | T-POS-15: RIPng default route ::/0 metric 1 (PrefixLen=0x00) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos15_ripng_default.pcap) |
| rip_tpos16_3_routers | T-POS-16: 3 routers each with own SrcIP, src ports 52001-52003, same multicast dst 224.0.0.9 | pass | 3 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos16_3_routers.pcap) |
| rip_tpos17_100_routers | T-POS-17: 100-router stress, GroupIDStrategy=fixed (same worker), 100 packets, src ports 52001-52100 | pass | 100 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos17_100_routers.pcap) |
| rip_tpos18_default_routes | T-POS-18: Routes=nil + Scenario= omitted -> response_default emits 5 default routes (104B payload) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos18_default_routes.pcap) |
| rip_tpos1_request_full | T-POS-1: scenario request_full, v2 multicast -> 2 packets (Request 01 02 00 00 + auto Response 02 02 00 00 with 5 default routes), same 4-tuple | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos1_request_full.pcap) |
| rip_tpos1b_request_full_4tuple | T-POS-1b: request_full auto Response reuses the exact same 4-tuple (src/dst IP+port), 2 packets, Response carries 5 default routes | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos1b_request_full_4tuple.pcap) |
| rip_tpos1b_user_routes | T-POS-1 variant: request_full with 1 user route -> Response carries the user route (44B payload: 4B header + 20B Request RTE + 20B route) | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos1b_user_routes.pcap) |
| rip_tpos20_50_entries | T-POS-20: 50 route entries split into 2 packets of 25 each (512B / 512B) | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos20_50_entries.pcap) |
| rip_tpos21_51_entries | T-POS-21: 51 route entries split into 3 packets 25+25+1 | pass | 3 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos21_51_entries.pcap) |
| rip_tpos22_host_mask | T-POS-22: host route SubnetMask=255.255.255.255 legal, mask bytes FF FF FF FF | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos22_host_mask.pcap) |
| rip_tpos23_ripng_128 | T-POS-23: RIPng host route PrefixLen=128 legal (prefix 2001:db8:1::) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos23_ripng_128.pcap) |
| rip_tpos24_simple_auth_16b | T-POS-24: simple auth password exactly 16B (no zero padding), AFI FFFF type 2 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos24_simple_auth_16b.pcap) |
| rip_tpos25_md5_authdatalen20 | T-POS-25: MD5 AuthDataLen=20 passthrough, trailer 24B, digest placeholder 20B 0xAA, 68B payload | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos25_md5_authdatalen20.pcap) |
| rip_tpos27_auth_25_routes | T-POS-27: simple auth + 25 routes -> 524B payload (auth entry + 25 RTE) in a single packet | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos27_auth_25_routes.pcap) |
| rip_tpos27b_auth_26_routes | T-POS-27 variant: simple auth + 26 routes -> 2 packets (524B + 24B), auth only on first | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos27b_auth_26_routes.pcap) |
| rip_tpos28_8_routers | T-POS-28: 8 routers concurrent, total packets = 8 x 1 route x 1 round = 8, src ports 52001-52008 | pass | 8 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos28_8_routers.pcap) |
| rip_tpos29_version_default | T-POS-29: version="" defaults to v2 (RIP header version byte=0x02) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos29_version_default.pcap) |
| rip_tpos30_command_default | T-POS-30: Command omitted -> defaults to response, RIP header command byte 0x02 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos30_command_default.pcap) |
| rip_tpos32_v1_multicast_broadcast | T-POS-32: v1 + multicast=true -> broadcast 255.255.255.255, ttl 1, ignores user DstIP | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos32_v1_multicast_broadcast.pcap) |
| rip_tpos33_domain | T-POS-33: routing domain 1 in header (02 02 00 01) | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos33_domain.pcap) |
| rip_tpos3_26_entries | T-POS-3: v2 Response 26 entries split into 2 packets 25+1, same FlowID, no auth | pass | 2 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos3_26_entries.pcap) |
| rip_tpos4_v1_broadcast | T-POS-4: v1 multicast -> broadcast 255.255.255.255, 24B payload (4B header + 1 RTE), ttl 1 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos4_v1_broadcast.pcap) |
| rip_tpos5_unicast | T-POS-5: v2 unicast update to 192.168.1.2, ttl 64, dstport 520, 1 RTE metric 1 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos5_unicast.pcap) |
| rip_tpos6_multicast_ttl | T-POS-6: v2 multicast to 224.0.0.9, ttl 1, sport 520, 1 RTE metric 2 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos6_multicast_ttl.pcap) |
| rip_tpos7_rounds | T-POS-7: rounds=3 -> 3 response packets, one per round | pass | 3 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos7_rounds.pcap) |
| rip_tpos8_simple_auth | T-POS-8: v2 simple auth (RFC 4822), password secret123 zero-padded to 16B, AFI 0xFFFF type 2 | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos8_simple_auth.pcap) |
| rip_tpos9_md5_auth | T-POS-9: v2 MD5 auth (RFC 4822): auth entry PacketLength 44B + trailer FF FF 00 01 + 16B digest, 1 route, 64B payload | pass | 1 | [pcap](/tmp/mcp-pcaps/rip/rip_tpos9_md5_auth.pcap) |
