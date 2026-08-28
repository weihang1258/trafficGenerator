# someip Pcap Test Results

Cases: 16 — pass 16, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| someip_error | T-SOMEIP-ERR-01/S4: REQUEST(0x00) -> ERROR(0x81) RC=0x01(E_NOT_OK), 同 SessionID 配对 | pass | 2 | [pcap](someip/someip_error.pcap) |
| someip_ipv6 | T-SOMEIP-IPV6-01/S9: IPv6 载体 UDP + SD Offer IPv6 Endpoint option (0x06) 2001:db8::1:30490 | pass | 2 | [pcap](someip/someip_ipv6.pcap) |
| someip_multi_method_event | T-SOMEIP-EVT-01/S7: 多方法 A/B(REQUEST->RESPONSE) + 事件 NOTIFICATION(0x02) method 0x8001 同流 | pass | 5 | [pcap](someip/someip_multi_method_event.pcap) |
| someip_multi_session | T-SOMEIP-SESS-01/S2: 两次方法调用 SessionID=1,2, 各自 RESPONSE 回用本会话号 (same_as_packet) | pass | 4 | [pcap](someip/someip_multi_session.pcap) |
| someip_neg_service_id | T-SOMEIP-NEG-01/V1: service_id=0 非法 -> Validate 拒绝 (任务必须失败) | pass | 0 | [pcap]() |
| someip_neg_session | T-SOMEIP-NEG-02/V2: session_start=1 且 session_inc=0（Session ID 不递增）-> Validate 拒绝 (任务必须失败) | pass | 0 | [pcap]() |
| someip_neg_tp | T-SOMEIP-NEG-04/V5: tp segment_size=0 越界 -> Validate 拒绝 | pass | 0 | [pcap]() |
| someip_neg_type | T-SOMEIP-NEG-03/V3: 非法 message_type=5 (非枚举) -> Validate 拒绝 | pass | 0 | [pcap]() |
| someip_no_return | T-SOMEIP-NORET-01/S3: REQUEST_NO_RETURN(0x01) 单包即结束, 无响应 (autoResponse 强制关闭) | pass | 1 | [pcap](someip/someip_no_return.pcap) |
| someip_req_empty | T-SOMEIP-REQ-02/S1v: 空载荷方法调用 REQUEST->RESPONSE, Length=8, 同 SessionID | pass | 2 | [pcap](someip/someip_req_empty.pcap) |
| someip_req_resp | T-SOMEIP-REQ-01/S1: 方法调用 REQUEST(0x00) -> autoResponse RESPONSE(0x80), payload de ad be ef, 同 SessionID/MessageID 配对, UDP 30490 | pass | 2 | [pcap](someip/someip_req_resp.pcap) |
| someip_sd_find_offer | T-SOMEIP-SD-01/S5: SD FindService(0x00) TTL=0xFFFFFF -> OfferService(0x01) TTL=3, Option IPv4 Endpoint 20.0.0.200:30490 | pass | 2 | [pcap](someip/someip_sd_find_offer.pcap) |
| someip_sd_ipv6 | T-SOMEIP-IPV6-SD-01: IPv6 载体上的 SD OfferService + IPv6 Endpoint Option(type=0x06) | pass | 1 | [pcap](someip/someip_sd_ipv6.pcap) |
| someip_sd_subscribe | T-SOMEIP-SD-02/S6: SubscribeEventgroup(0x06) EventgroupID=0x0001 -> SubscribeEventgroupAck(0x07) Counter=0 | pass | 2 | [pcap](someip/someip_sd_subscribe.pcap) |
| someip_tcp_swap | T-SOMEIP-TCP-01/S10: TCP 载体 30490, 握手后 REQUEST(0x00) -> RESPONSE(0x80) | pass | 9 | [pcap](someip/someip_tcp_swap.pcap) |
| someip_tp_segments | T-SOMEIP-TP-01/S8: TP 分段 2500B -> 2 段 (1400+1100), 首段 Type=0x20(TP_REQUEST) 段序 0,1, 末段 more=0, OfferedLength=2516 | pass | 2 | [pcap](someip/someip_tp_segments.pcap) |
