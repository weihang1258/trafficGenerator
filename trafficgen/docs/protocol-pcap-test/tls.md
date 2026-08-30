# tls Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tls-handshake-basic | TLS (端口 443) 冒烟：完整 TCP 握手 + TLS 1.3 ClientHello → ServerHello → EncryptedExtensions → Certificate → Finished → 应用数据 + 终止 | pass | 17 | [pcap](tls/tls-handshake-basic.pcap) |
