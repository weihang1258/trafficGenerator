# socks5 Pcap Test Results

Cases: 2 — pass 2, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| socks5-connect-basic | SOCKS5 (端口 1080) 冒烟：完整 TCP 握手 + 方法协商 → CONNECT 请求/响应 + 终止 | pass | 10 | [pcap](socks5/socks5-connect-basic.pcap) |
| socks5_over_tls | SOCKS5-over-TLS：TLS 载体上的 SOCKS5 信令（[tcp,tls,socks5] 层链，1080 端口），tls 握手后 greeting/method/request/reply 信令字节 | pass | 20 | [pcap](socks5/socks5_over_tls.pcap) |
