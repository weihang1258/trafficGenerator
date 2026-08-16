# sip Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sip_smoke_01 | SIP 注册+通话冒烟：INVITE→200→ACK→BYE→200 显式 dialog（types.go SIPConfig，RFC 3261 §8/§13/§15），头补全 completeDialogHeaders 补齐 Call-ID/From/To/CSeq | pass | 12 | [pcap](/tmp/mcp-pcaps/sip/sip_smoke_01.pcap) |
