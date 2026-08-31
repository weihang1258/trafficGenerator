# pop3 Pcap Test Results

Cases: 2 — pass 2, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pop3_over_tls | POP3S：TLS 载体上的 POP3 会话（[tcp,tls,pop3] 层链，995 POP3S 端口），tls 握手后 pop.request/response 命令交互 | pass | 21 | [pcap](pop3/pop3_over_tls.pcap) |
| pop3_smoke_01 | POP3 会话冒烟：显式 banner + USER/PASS/QUIT 命令（types.go POP3Config，RFC 1939 §3/§5），空配置只产握手+终止（设计行为），本 case 用显式消息配置驱动数据帧 | pass | 14 | [pcap](pop3/pop3_smoke_01.pcap) |
