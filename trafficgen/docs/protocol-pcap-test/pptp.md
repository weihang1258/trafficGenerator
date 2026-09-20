# pptp Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pptp_calls_two | T-7 calls=2 多 call 并发：OCRQ/OCRP 两轮+SLI 逐 call | pass | 31 | [pcap](pptp/pptp_calls_two.pcap) |
| pptp_composite_full_multi | T-13 复合大场景（9.50）：full+calls 2+echo+双数据+SLI 3 ≥3 类交织 | pass | 33 | [pcap](pptp/pptp_composite_full_multi.pcap) |
| pptp_control_header_magic | T-2 控制头钉：magic cookie 1a2b3c4d+Length+Type 字节（TCP 载荷首 8B） | pass | 26 | [pcap](pptp/pptp_control_header_magic.pcap) |
| pptp_data_both_directions | T-10 双数据方向：scenario=full+data_frames=2+down_data_frames=1 逐帧 GRE 头（数据面住 full 编排） | pass | 24 | [pcap](pptp/pptp_data_both_directions.pcap) |
| pptp_echo_keepalive | T-9 echo=true：ECRQ/ECRP 保活对（RFC 2637 §3.2.9-10） | pass | 23 | [pcap](pptp/pptp_echo_keepalive.pcap) |
| pptp_full_session_ref | T-1 full 会话（smoke 改写，参考 pcap 逐字节）：SCCRQ/SCCRP/OCRQ/OCRP/SLI×5/CCRQ+CCDN 合并/CCDN/StopRQ/StopRP | pass | 26 | [pcap](pptp/pptp_full_session_ref.pcap) |
| pptp_inner_ip_explicit | T-11 inner_ip 显式：src/dst/proto/payload 字节透传（PPP FF 03+0x0021+内嵌 IPv4） | pass | 16 | [pcap](pptp/pptp_inner_ip_explicit.pcap) |
| pptp_neg_calls_negative | T-16 负例：calls=-1→registry V9 范围门拒（链路径真实拦截点） | pass | 0 | [pcap]() |
| pptp_neg_host_name_long | 负例：exceed 64 bytes 锚词 | pass | 0 | [pcap]() |
| pptp_neg_inner_ip_invalid | 负例：invalid pptp inner src_ip 锚词 | pass | 0 | [pcap]() |
| pptp_neg_role_invalid | 负例：invalid pptp role 锚词 | pass | 0 | [pcap]() |
| pptp_neg_scenario_invalid | 负例：invalid pptp scenario 锚词 | pass | 0 | [pcap]() |
| pptp_neg_sli_count_negative | T-17 负例：sli_count=-1→registry V9 范围门拒（链路径真实拦截点） | pass | 0 | [pcap]() |
| pptp_neg_sub_address_hex | 负例：must be hex 锚词 | pass | 0 | [pcap]() |
| pptp_result_error_fields | T-12 失败分支字段：scrp_result=5+ocrp_result=2 非 0 透传（错误码面） | pass | 21 | [pcap](pptp/pptp_result_error_fields.pcap) |
| pptp_role_pac | T-6 role=pac：PAC 侧换向（方向/Call ID 语义反转） | pass | 21 | [pcap](pptp/pptp_role_pac.pcap) |
| pptp_scenario_control_only | T-3 scenario=control_only：控制面消息子集（无 GRE 数据面） | pass | 21 | [pcap](pptp/pptp_scenario_control_only.pcap) |
| pptp_scenario_data_only | T-5 scenario=data_only：纯 GRE 数据面 | pass | 4 | [pcap](pptp/pptp_scenario_data_only.pcap) |
| pptp_scenario_tunnel_only | T-4 scenario=tunnel_only：隧道建立+数据面（无控制拆除） | pass | 16 | [pcap](pptp/pptp_scenario_tunnel_only.pcap) |
| pptp_sli_count_three | T-8 sli_count=3：SLI 条数钉（缺省 5 由 T-1 承接） | pass | 24 | [pcap](pptp/pptp_sli_count_three.pcap) |
