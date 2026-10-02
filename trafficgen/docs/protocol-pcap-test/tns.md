# tns Pcap Test Results

Cases: 24 — pass 23, fail 1, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tns_body_constants | CONNECT/ACCEPT/REFUSE/REDIRECT body 四态同链（双会话：CONNECT→REFUSE 终态 + CONNECT→ACCEPT→DATA）（pending-suite：suite 实测复钉） | pass | 19 | [pcap](tns/tns_body_constants.pcap) |
| tns_connect_accept | S1/T-TNS-S1: CONNECT→ACCEPT→TTC data; TCP 1521 (层链形 D-TNS-1) | pass | 11 | [pcap](tns/tns_connect_accept.pcap) |
| tns_data_flags_zero | DATA×2 flags=0：事件包 tns.data_flag=0x0000 + 包数 11（pending-suite：断言沿 testcase 设计值，suite 实测复钉） | pass | 11 | [pcap](tns/tns_data_flags_zero.pcap) |
| tns_dyn_srcport | tcp.src_port inc 动态（flows=2，每流独立）（pending-suite：断言/包数沿 testcase 设计值，suite 实测复钉） | fail | 18 | `tns/tns_dyn_srcport.pcap` |
| tns_header_fields | S7/T-TNS-S7: complete public header fields and DATA flags (层链形 D-TNS-1) | pass | 11 | [pcap](tns/tns_header_fields.pcap) |
| tns_ipv4_baseline | IPv4 CONNECT→ACCEPT 裸形（与 #6 地址族对称）（pending-suite：断言/包数沿 testcase 设计值，suite 实测复钉） | pass | 9 | [pcap](tns/tns_ipv4_baseline.pcap) |
| tns_ipv6_connect | S5/T-TNS-S5: IPv6 CONNECT→ACCEPT (层链形 D-TNS-1) | pass | 9 | [pcap](tns/tns_ipv6_connect.pcap) |
| tns_multi_session | S6/T-TNS-S6: two independent CONNECT→ACCEPT sessions (层链形 D-TNS-1) | pass | 18 | [pcap](tns/tns_multi_session.pcap) |
| tns_neg_bad_direction | N5/A'：非法 direction 枚举值拒绝（G-TNS-8 白名单） | pass | 0 | [pcap]() |
| tns_neg_checksum | N4: nonzero checksum conflicts with disabled mode | pass | 0 | [pcap]() |
| tns_neg_data_flags | N5: nonzero DATA flags rejected in v1 | pass | 0 | [pcap]() |
| tns_neg_length | N3: packet length below 8 rejected | pass | 0 | [pcap]() |
| tns_neg_packet_type | N2: unknown packet type rejected | pass | 0 | [pcap]() |
| tns_neg_presence_top_level_tns | M5①判死：层链 + 顶层空 tns 子映射并存（presence 负例形状） | pass | 0 | [pcap]() |
| tns_neg_server_type_in_c2s | P2判死: ACCEPT/REFUSE/REDIRECT 出现在 c2s 方向（设计 §4.2 行 3 状态机缺口收口） | pass | 0 | [pcap]() |
| tns_neg_state_skip | N4/A'：状态机跳步（ACCEPT 前 DATA）拒绝（G-TNS-8 守卫） | pass | 0 | [pcap]() |
| tns_neg_stray_src_mac | M5②判死：白名单外游离键（顶层 src_mac）与 layers 并存 | pass | 0 | [pcap]() |
| tns_neg_udp | N1: UDP carrier rejected (carrier) | pass | 0 | [pcap]() |
| tns_nonstd_port | 非标端口 9999（今日放行，钉行为）（pending-suite：断言/包数沿 testcase 设计值，suite 实测复钉） | pass | 9 | [pcap](tns/tns_nonstd_port.pcap) |
| tns_redirect | S3/T-TNS-S3: CONNECT→REDIRECT; no reconnect (层链形 D-TNS-1) | pass | 9 | [pcap](tns/tns_redirect.pcap) |
| tns_refuse | S2/T-TNS-S2: CONNECT→REFUSE; no DATA (层链形 D-TNS-1) | pass | 9 | [pcap](tns/tns_refuse.pcap) |
| tns_refuse_session | sessions 内 REFUSE（跨 sessions[1..n] 面，G-TNS-3 实测载体）（pending-suite：断言/包数沿 testcase 设计值，suite 实测复钉） | pass | 18 | [pcap](tns/tns_refuse_session.pcap) |
| tns_session_null_default | S11/T-TNS-S11: 空层配置默认化产一条 DATA（P0b-2，设计 §4.3 派生表） | pass | 8 | [pcap](tns/tns_session_null_default.pcap) |
| tns_ttc_sqlnet_session | S4/T-TNS-S4: TTC and SQL*Net data sequence, flags zero (层链形 D-TNS-1) | pass | 13 | [pcap](tns/tns_ttc_sqlnet_session.pcap) |

## Failures

### tns_dyn_srcport — tcp.src_port inc 动态（flows=2，每流独立）（pending-suite：断言/包数沿 testcase 设计值，suite 实测复钉）

verify: field tcp.srcport: distinct values mismatch (want [12345 12346]; missing []; unexpected [1521(x8)])

