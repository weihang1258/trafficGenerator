# tcp Pcap Test Results

Cases: 10 — pass 10, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tcp-data-segments | TCP 大载荷按 MSS 分片（6000 字节 body → 5 段 PSH-ACK） | pass | 9 | [pcap](/tmp/mcp-pcaps/tcp/tcp-data-segments.pcap) |
| tcp-handshake-basic | TCP 完整握手 + 数据 + 终止（默认配置，MSS 1460） | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-handshake-basic.pcap) |
| tcp-initial-seq-deterministic | TCP 显式 initial_seq=1000：SYN seq 1000、SYN-ACK ack 1001（确定性 ISN，无 payload） | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-initial-seq-deterministic.pcap) |
| tcp-no-handshake-direct-data | TCP 无握手直发数据：handshake=false 跳过 SYN 握手，数据段 PSH-ACK 直发 + 对端 ACK | pass | 2 | [pcap](/tmp/mcp-pcaps/tcp/tcp-no-handshake-direct-data.pcap) |
| tcp-rst-replaces-fin | TCP RST 替换 FIN 终止（rst:true 时无 FIN 挥手，RFC 9293 §3.5） | pass | 6 | [pcap](/tmp/mcp-pcaps/tcp/tcp-rst-replaces-fin.pcap) |
| tcp-validate-dst-port-out-of-range-reject | Validate-negative：dst_port=65536 超出 16 位范围必须被拒绝（否则 getUint16 截断回绕为 0） | pass | 0 | [pcap]() |
| tcp-validate-initial-seq-negative | Validate-negative：tcp.initial_seq=-1 必须被拒绝（否则 getUint32 截断回绕为 4294967295） | pass | 0 | [pcap]() |
| tcp-validate-mss-too-small | Validate-negative：MSS 500 < 536（RFC 879 下限）必须被拒绝 | pass | 0 | [pcap]() |
| tcp-window-size-applies | TCP 自定义窗口大小 4096 应用于握手双向（SYN 与 SYN-ACK 均填 winSize，非默认 65535） | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-window-size-applies.pcap) |
| tcp-zero-window-custom-mss | TCP 自定义 MSS 536 与窗口 | pass | 7 | [pcap](/tmp/mcp-pcaps/tcp/tcp-zero-window-custom-mss.pcap) |
