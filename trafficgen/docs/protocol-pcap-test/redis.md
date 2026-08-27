# redis Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| redis_ping_select_pong | smoke: RESP inline PING with auto_reply pong over TCP 6379; default SelectDB=0 emits SELECT 0 +OK first, then PING +PONG (handshake + 4 data frames + FIN) | pass | 11 | [pcap](redis/redis_ping_select_pong.pcap) |
