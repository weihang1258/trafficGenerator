# goose Pcap Test Results

Cases: 33 — pass 33, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| goose_combo_event | T-GOOSE-29 组合流 B: event_seq 事件 + 6 成员多类型 + numDatSetEntries 一致（9.11 ≥3） | pass | 5 | [pcap](goose/goose_combo_event.pcap) |
| goose_combo_flags | T-GOOSE-28 组合流 A: test=true+nds_com=true+VLAN 同帧三动作（9.11 ≥3） | pass | 2 | [pcap](goose/goose_combo_flags.pcap) |
| goose_dataset_change | T-GSE-S2-02 dataset change: heartbeat stNum=1 sqNum=1 then event frame stNum=2 sqNum=0 (RESET, not 1), retransmits sqNum 0..2 then heartbeat | pass | 5 | [pcap](goose/goose_dataset_change.pcap) |
| goose_goid | T-GOOSE-21: go_id 显式值（§3.4 可选键，0x83 段写显式串非 gocbRef 回填） | pass | 1 | [pcap](goose/goose_goid.pcap) |
| goose_heartbeat | T-GSE-S1-01/02 static heartbeat: 3 frames, stNum constant 1, sqNum 1/2/3 incrementing, appid 0x1000, confRev 1, TAL 500, numDatSetEntries 3, no IP (L2-direct 0x88b8) | pass | 3 | [pcap](goose/goose_heartbeat.pcap) |
| goose_int64 | T-GOOSE-24: int64 负值最小编码（85 01 ff，含符号位；9.21 int64 分支代表） | pass | 1 | [pcap](goose/goose_int64.pcap) |
| goose_multidataset | T-GSE-S7-01 multi-dataset: 6 members (bool/int32/uint32/float32/bit_string/visible_string), numDatSetEntries 6 == allData member count | pass | 2 | [pcap](goose/goose_multidataset.pcap) |
| goose_multitype | T-GSE-S5-01 multi-type data values: Boolean x2, Integer x2, Unsigned, FloatingPoint, BitString x2, VisibleString x2 (10 members) - all BER member tags byte-verified, numDatSetEntries 10 | pass | 2 | [pcap](goose/goose_multitype.pcap) |
| goose_ndscom_flag | T-GSE-S3-02 ndsCom flag set: all frames carry ndsCom=true encoded as BER 89 01 01 | pass | 2 | [pcap](goose/goose_ndscom_flag.pcap) |
| goose_neg_appid | negative: appid 0x4000 falls in the SV-reserved segment (0x4000-0x7FFF) and must fail; GOOSE segment is 0x0000-0x3FFF | pass | 0 | [pcap]() |
| goose_neg_confrev | T-GOOSE-15: conf_rev=0 拒（设计 §9.3，validator conf_rev must be non-zero） | pass | 0 | [pcap]() |
| goose_neg_gocbref | T-GOOSE-18: gocb_ref 空拒（validator gocb_ref and dat_set are required） | pass | 0 | [pcap]() |
| goose_neg_ip_carrier | T-GOOSE-32: [ip,goose] 载体拒（V7b must not have an ip/transport carrier） | pass | 0 | [pcap]() |
| goose_neg_no_data | T-GOOSE-16: 空 data 拒（validator at least one allData member） | pass | 0 | [pcap]() |
| goose_neg_sqnum | negative: non-contiguous sqNum - retransmit sequence jumps/duplicates sqNum (violates monotonically +1 within a burst) | pass | 0 | [pcap]() |
| goose_neg_sqnum_max | T-GOOSE-31: start_sqnum=0xFFFFFFFF 拒（sqNum must not overflow，validator :46） | pass | 0 | [pcap]() |
| goose_neg_stnum | negative: stNum wrap-around - stNum must never regress/wrap (0xFFFFFFFF -> 0), violating the change counter monotonicity | pass | 0 | [pcap]() |
| goose_neg_str255 | T-GOOSE-19: gocb_ref 256 字符拒（exceed 255 bytes，9.8 超长格） | pass | 0 | [pcap]() |
| goose_neg_tal | T-GOOSE-20: tal_ms=0 拒（tal_ms must be in 1..4294967295，9.8 空值/边界格） | pass | 0 | [pcap]() |
| goose_neg_type | T-GOOSE-17: 非法数据类型拒（§3.8 矩阵外，array/struct 规划中同拒） | pass | 0 | [pcap]() |
| goose_neg_vlan | T-GOOSE-33: vlan_id=4096 拒（V9 out of range [0,4095]） | pass | 0 | [pcap]() |
| goose_no_ip | T-GSE-S6-01 no-IP proof: frame carries ethernet 0x88b8 directly (no IPv4 0x0800 / IPv6 0x86dd), APDU 0x61 starts at byte 22 - GOOSE is L2-terminated | pass | 3 | [pcap](goose/goose_no_ip.pcap) |
| goose_octet_string | T-GOOSE-26: octet_string（0x89 tag，§3.8 取值补口） | pass | 1 | [pcap](goose/goose_octet_string.pcap) |
| goose_retransmit | T-GSE-S2-01 fast retransmit: 1 heartbeat(sqNum=1) + event + 5 fast retransmits (stNum=2 sqNum=0..5), then heartbeat resumes with sqNum=6; content byte-identical across retransmit frames | pass | 8 | [pcap](goose/goose_retransmit.pcap) |
| goose_start_sqnum | T-GOOSE-22: start_sqnum=5 非零起点（首帧 sqNum=5，5/6/7 连续） | pass | 3 | [pcap](goose/goose_start_sqnum.pcap) |
| goose_start_stnum | T-GOOSE-23: start_stnum=10 非零起点（stNum=10 恒，sqNum 1/2；§10.1 override 已实现） | pass | 2 | [pcap](goose/goose_start_stnum.pcap) |
| goose_test_flag | T-GSE-S3-01 test flag set: all frames carry test=true encoded as BER 87 01 01 | pass | 2 | [pcap](goose/goose_test_flag.pcap) |
| goose_uint64 | T-GOOSE-25: uint64 大值编码（2^32 → 86 05 01 00 00 00 00；uint64 分支代表） | pass | 1 | [pcap](goose/goose_uint64.pcap) |
| goose_utc_time | T-GOOSE-27: utc_time（0x91 8B CP 时间，tag+len 断言内容墙钟不定值） | pass | 1 | [pcap](goose/goose_utc_time.pcap) |
| goose_vlan | T-GSE-S4-01 VLAN: TPID 0x8100 + TCI 0x8064 (prio 4 / id 100), EtherType 0x88b8 shifted +4, APDU at offset 26 | pass | 2 | [pcap](goose/goose_vlan.pcap) |
| goose_vn_empty_layer | T-GOOSE-30: 空层 {goose:{}} 保底（零配置非 nil → gocb_ref 必填分支） | pass | 0 | [pcap]() |
| goose_vn_presence | T-GOOSE-2: 顶层 goose presence 判死（空 map 也死，CheckProtoFlat fins 先例） | pass | 0 | [pcap]() |
| goose_vn_static_copy | T-GOOSE-3: 显式标量 eth MAC + flows=2 拒绝（⑥ static-eth 门，sv/isis 同享） | pass | 0 | [pcap]() |
