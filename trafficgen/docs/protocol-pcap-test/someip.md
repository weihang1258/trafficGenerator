# someip Pcap Test Results

Cases: 16 — pass 7, fail 9, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| someip_error | T-SOMEIP-ERR-01/S4: REQUEST(0x00) -> ERROR(0x81) RC=0x01(E_NOT_OK), 同 SessionID 配对 | fail | 1 | `someip/someip_error.pcap` |
| someip_ipv6 | T-SOMEIP-IPV6-01/S9: IPv6 载体 UDP + SD Offer IPv6 Endpoint option (0x06) 2001:db8::1:30490 | fail | 2 | `someip/someip_ipv6.pcap` |
| someip_multi_method_event | T-SOMEIP-EVT-01/S7: 多方法 A/B(REQUEST->RESPONSE) + 事件 NOTIFICATION(0x02) method 0x8001 同流 | fail | 3 | `someip/someip_multi_method_event.pcap` |
| someip_multi_session | T-SOMEIP-SESS-01/S2: 两次方法调用 SessionID=1,2, 各自 RESPONSE 回用本会话号 (same_as_packet) | fail | 2 | `someip/someip_multi_session.pcap` |
| someip_neg_service_id | T-SOMEIP-NEG-01/V1: service_id=0 非法 -> Validate 拒绝 (任务必须失败) | pass | 0 | [pcap]() |
| someip_neg_session | T-SOMEIP-NEG-02/V2: session_start=0 且 session_inc=0（非递增）-> Validate 拒绝 (任务必须失败) | fail | 0 | `` |
| someip_neg_tp | T-SOMEIP-NEG-04/V5: tp segment_size=0 越界 -> Validate 拒绝 | pass | 0 | [pcap]() |
| someip_neg_type | T-SOMEIP-NEG-03/V3: 非法 message_type=5 (非枚举) -> Validate 拒绝 | pass | 0 | [pcap]() |
| someip_no_return | T-SOMEIP-NORET-01/S3: REQUEST_NO_RETURN(0x01) 单包即结束, 无响应 (autoResponse 强制关闭) | pass | 1 | [pcap](someip/someip_no_return.pcap) |
| someip_req_empty | T-SOMEIP-REQ-02/S1v: 空载荷方法调用 REQUEST->RESPONSE, Length=8, 同 SessionID | pass | 2 | [pcap](someip/someip_req_empty.pcap) |
| someip_req_resp | T-SOMEIP-REQ-01/S1: 方法调用 REQUEST(0x00) -> autoResponse RESPONSE(0x80), payload de ad be ef, 同 SessionID/MessageID 配对, UDP 30490 | pass | 2 | [pcap](someip/someip_req_resp.pcap) |
| someip_sd_find_offer | T-SOMEIP-SD-01/S5: SD FindService(0x00) TTL=0xFFFFFF -> OfferService(0x01) TTL=3, Option IPv4 Endpoint 20.0.0.200:30490 | fail | 2 | `someip/someip_sd_find_offer.pcap` |
| someip_sd_ipv6 | T-SOMEIP-IPV6-SD-01: IPv6 载体上的 SD OfferService + IPv6 Endpoint Option(type=0x06) | fail | 1 | `someip/someip_sd_ipv6.pcap` |
| someip_sd_subscribe | T-SOMEIP-SD-02/S6: SubscribeEventgroup(0x06) EventgroupID=0x0001 -> SubscribeEventgroupAck(0x07) Counter=0 | fail | 2 | `someip/someip_sd_subscribe.pcap` |
| someip_tcp_swap | T-SOMEIP-TCP-01/S10: TCP 载体 30490, 握手后 REQUEST(0x00) -> RESPONSE(0x80) | pass | 9 | [pcap](someip/someip_tcp_swap.pcap) |
| someip_tp_segments | T-SOMEIP-TP-01/S8: TP 分段 2500B -> 2 段 (1400+1100), 首段 Type=0x20(TP_REQUEST) 段序 0,1, 末段 more=0, OfferedLength=2516 | fail | 2 | `someip/someip_tp_segments.pcap` |

## Failures

### someip_error — T-SOMEIP-ERR-01/S4: REQUEST(0x00) -> ERROR(0x81) RC=0x01(E_NOT_OK), 同 SessionID 配对

verify: count: got 1 packets, want 2; field someip.messagetype on packet 1: got "0x81", want "0x00"; field someip.messagetype: packet 2 out of range (file has 1 packets); field someip.returncode: packet 2 out of range (file has 1 packets); field someip.sessionid: packet 2 out of range (file has 1 packets); field udp.srcport: packet 2 out of range (file has 1 packets)

### someip_ipv6 — T-SOMEIP-IPV6-01/S9: IPv6 载体 UDP + SD Offer IPv6 Endpoint option (0x06) 2001:db8::1:30490

verify: field ipv6.src on packet 1: got "", want "2001:db8::1"; field ipv6.dst on packet 1: got "", want "2001:db8::2"

### someip_multi_method_event — T-SOMEIP-EVT-01/S7: 多方法 A/B(REQUEST->RESPONSE) + 事件 NOTIFICATION(0x02) method 0x8001 同流

verify: count: got 3 packets, want 5; field someip.methodid on packet 2: got "0x0002", want equal to packet 1 value "0x0001"; field someip.messagetype on packet 2: got "0x00", want "0x80"; field someip.methodid on packet 3: got "0x8001", want "0x0002"; field someip.messagetype on packet 3: got "0x02", want "0x00"; field someip.methodid: packet 4 out of range (file has 3 packets); field someip.messagetype: packet 4 out of range (file has 3 packets); field someip.methodid: packet 5 out of range (file has 3 packets); field someip.messagetype: packet 5 out of range (file has 3 packets)

### someip_multi_session — T-SOMEIP-SESS-01/S2: 两次方法调用 SessionID=1,2, 各自 RESPONSE 回用本会话号 (same_as_packet)

verify: count: got 2 packets, want 4; field someip.sessionid on packet 2: got "0x0002", want equal to packet 1 value "0x0001"; field someip.messagetype on packet 2: got "0x00", want "0x80"; field someip.sessionid: packet 3 out of range (file has 2 packets); field someip.messagetype: packet 3 out of range (file has 2 packets); field someip.sessionid: packet 4 out of range (file has 2 packets); field someip.messagetype: packet 4 out of range (file has 2 packets); frame: packet 3 out of range (file has 2 packets)

### someip_neg_session — T-SOMEIP-NEG-02/V2: session_start=0 且 session_inc=0（非递增）-> Validate 拒绝 (任务必须失败)

expected task to be rejected but it completed

### someip_sd_find_offer — T-SOMEIP-SD-01/S5: SD FindService(0x00) TTL=0xFFFFFF -> OfferService(0x01) TTL=3, Option IPv4 Endpoint 20.0.0.200:30490

verify: expert: frame 1 malformed: _ws.malformed,_ws.malformed; expert: frame 2 malformed: _ws.malformed,_ws.malformed; field someipsd.entry.serviceid on packet 1: got "0x3400", want "0x1234"; field someipsd.entry.instanceid on packet 1: got "0x0101", want "0x0001"; field someipsd.entry.ttl on packet 1: got "16776960", want "16777215"; field someipsd.entry.majorver on packet 2: got "0", want "1"; field someipsd.entry.ttl on packet 2: got "768", want "3"; field someipsd.option.type on packet 2: got "", want "1"; field someipsd.option.ipv4address on packet 2: got "", want "20.0.0.200"; field someipsd.option.port on packet 2: got "", want "30490"; frame packet 1 offset 42: bytes mismatch at offset 49 (got 2c, want 20); frame packet 2 offset 42: bytes mismatch at offset 53 (got 01, want 02)

### someip_sd_ipv6 — T-SOMEIP-IPV6-SD-01: IPv6 载体上的 SD OfferService + IPv6 Endpoint Option(type=0x06)

verify: expert: frame 1 malformed: _ws.malformed,_ws.malformed; field ipv6.src on packet 1: got "", want "2001:db8::10"; field ipv6.dst on packet 1: got "", want "2001:db8::20"; field someipsd.option.type on packet 1: got "", want "6"; field someipsd.option.ipv6address on packet 1: got "", want "2001:db8::1"; field someipsd.option.port on packet 1: got "", want "30490"

### someip_sd_subscribe — T-SOMEIP-SD-02/S6: SubscribeEventgroup(0x06) EventgroupID=0x0001 -> SubscribeEventgroupAck(0x07) Counter=0

verify: field someipsd.entry.serviceid on packet 1: got "0x3400", want "0x1234"; field someipsd.entry.instanceid on packet 1: got "0x0101", want "0x0001"; field someipsd.entry.eventgroupid on packet 1: got "0x0100", want "0x0001"; field someipsd.entry.counter on packet 2: got "0x00", want "0x0"

### someip_tp_segments — T-SOMEIP-TP-01/S8: TP 分段 2500B -> 2 段 (1400+1100), 首段 Type=0x20(TP_REQUEST) 段序 0,1, 末段 more=0, OfferedLength=2516

verify: expert: frame 2 malformed: _ws.malformed; field someip.tp.offset on packet 1: got "2512", want "2516"; field someip.tp.flags.more_segments on packet 1: got "0", want "1"; field someip.tp.flags.more_segments on packet 2: got "1", want "0"; field someip.tp.reassembled.length on packet 2: got "", want "2516"

