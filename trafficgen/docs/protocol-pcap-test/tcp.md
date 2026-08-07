# tcp Pcap Test Results

Cases: 3 — pass 3, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tcp-data-segments | TCP 大载荷按 MSS 分片（6000 字节 body → 5 段 PSH-ACK） | pass | 9 | [pcap](/tmp/mcp-pcaps/tcp/tcp-data-segments.pcap) |
| tcp-handshake-basic | TCP 完整握手 + 数据 + 终止（默认配置，MSS 1460） | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-handshake-basic.pcap) |
| tcp-zero-window-custom-mss | TCP 自定义 MSS 536 与窗口 | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-zero-window-custom-mss.pcap) |
