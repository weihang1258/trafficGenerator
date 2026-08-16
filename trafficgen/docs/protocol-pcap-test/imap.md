# imap Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| imap_smoke_01 | IMAP 会话冒烟：显式 banner + LOGIN/LIST/LOGOUT 命令（types.go IMAPConfig，RFC 9051 §2.2），tag 自动生成 A001/A002/A003，空配置只产握手+终止（设计行为） | pass | 16 | [pcap](/tmp/mcp-pcaps/imap/imap_smoke_01.pcap) |
