# sctp Pcap Test Results

Cases: 10 — pass 10, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sctp_t10_neg_frag_small | 负例：fragment_size=1 低于下界 | pass | 0 | [pcap]() |
| sctp_t1_baseline_assoc | T-1 基线关联：4 握手+3 关闭=7 帧，chunk_type 序 1/2/10/11/7/8/14 | pass | 7 | [pcap](sctp/sctp_t1_baseline_assoc.pcap) |
| sctp_t2_handshake_bytes | T-2 4 握手字节钉：INIT VTag=0/cookie 回显一致/COOKIE-ACK 4B | pass | 7 | [pcap](sctp/sctp_t2_handshake_bytes.pcap) |
| sctp_t3_data_bidir | T-3 DATA 双向：TSN 双空间自增+SID/SSN/PPID 钉 | pass | 9 | [pcap](sctp/sctp_t3_data_bidir.pcap) |
| sctp_t4_fragment_flags | T-4 分片三 flags：fragment_size=16，100B→7 段 B/middle×5/E+TSN 连续 | pass | 14 | [pcap](sctp/sctp_t4_fragment_flags.pcap) |
| sctp_t5_heartbeat_primary | T-5 HEARTBEAT 主路径：count=2→2 对插在 COOKIE-ACK 后 | pass | 11 | [pcap](sctp/sctp_t5_heartbeat_primary.pcap) |
| sctp_t6_altpath_multihoming | T-6 AltPath 多宿主：备用 4 元组子流+INIT 携带 IPv4 Address 参数 | pass | 9 | [pcap](sctp/sctp_t6_altpath_multihoming.pcap) |
| sctp_t7_abort | T-7 ABORT 突断：abort=true 替代 3 路 SHUTDOWN | pass | 5 | [pcap](sctp/sctp_t7_abort.pcap) |
| sctp_t8_explicit_tsn_sid | T-8 显式 TSN/SID/SSN/PPID 全钉（PPID 47 用户特征值） | pass | 8 | [pcap](sctp/sctp_t8_explicit_tsn_sid.pcap) |
| sctp_t9_neg_altpath_v6 | 负例：AltPath IPv6 拒（同地址族约束） | pass | 0 | [pcap]() |
