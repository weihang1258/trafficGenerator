# shadowsocks Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| shadowsocks_default_tcp | smoke: shadowsocks TCP mode (aes-256-gcm) over port 8388; salt (32B) then one AEAD chunk (34B); encrypted stream is random, only structural assertions | pass | 9 | [pcap](shadowsocks/shadowsocks_default_tcp.pcap) |
