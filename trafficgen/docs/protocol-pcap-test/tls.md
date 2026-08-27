# tls Pcap Test Results

Cases: 1 — pass 0, fail 1, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tls-handshake-basic | TLS (端口 443) 冒烟：完整 TCP 握手 + TLS 1.3 ClientHello → ServerHello → EncryptedExtensions → Certificate → Finished → 应用数据 + 终止 | fail | 17 | `tls/tls-handshake-basic.pcap` |

## Failures

### tls-handshake-basic — TLS (端口 443) 冒烟：完整 TCP 握手 + TLS 1.3 ClientHello → ServerHello → EncryptedExtensions → Certificate → Finished → 应用数据 + 终止

verify: expert: frame 7 malformed: _ws.malformed,_ws.malformed

