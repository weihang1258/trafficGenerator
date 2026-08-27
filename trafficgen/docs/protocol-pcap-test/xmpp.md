# xmpp Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| xmpp-stream-basic | XMPP (端口 5222) 冒烟：完整 TCP 握手 + XML 流协商 + AUTH PLAIN → 会话建立 (bind/session) → presence → 流关闭 + 终止 | pass | 19 | [pcap](xmpp/xmpp-stream-basic.pcap) |
