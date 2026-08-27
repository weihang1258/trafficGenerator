# goose Pcap Test Results

Cases: 12 — pass 0, fail 3, error 9

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| goose_dataset_change | T-GSE-S2-02 dataset change: heartbeat stNum=1 sqNum=1 then event frame stNum=2 sqNum=0 (RESET, not 1), retransmits sqNum 0..2 then heartbeat | error | 0 | `` |
| goose_heartbeat | T-GSE-S1-01/02 static heartbeat: 3 frames, stNum constant 1, sqNum 1/2/3 incrementing, appid 0x1000, confRev 1, TAL 500, numDatSetEntries 3, no IP (L2-direct 0x88b8) | error | 0 | `` |
| goose_multidataset | T-GSE-S7-01 multi-dataset: 6 members (bool/int32/uint32/float32/bit_string/visible_string), numDatSetEntries 6 == allData member count | error | 0 | `` |
| goose_multitype | T-GSE-S5-01 multi-type data values: Boolean x2, Integer x2, Unsigned, FloatingPoint, BitString x2, VisibleString x2 (10 members) - all BER member tags byte-verified, numDatSetEntries 10 | error | 0 | `` |
| goose_ndscom_flag | T-GSE-S3-02 ndsCom flag set: all frames carry ndsCom=true encoded as BER 89 01 01 | error | 0 | `` |
| goose_neg_appid | negative: appid 0x4000 falls in the SV-reserved segment (0x4000-0x7FFF) and must fail; GOOSE segment is 0x0000-0x3FFF | fail | 0 | `` |
| goose_neg_sqnum | negative: non-contiguous sqNum - retransmit sequence jumps/duplicates sqNum (violates monotonically +1 within a burst) | fail | 0 | `` |
| goose_neg_stnum | negative: stNum wrap-around - stNum must never regress/wrap (0xFFFFFFFF -> 0), violating the change counter monotonicity | fail | 0 | `` |
| goose_no_ip | T-GSE-S6-01 no-IP proof: frame carries ethernet 0x88b8 directly (no IPv4 0x0800 / IPv6 0x86dd), APDU 0x61 starts at byte 22 - GOOSE is L2-terminated | error | 0 | `` |
| goose_retransmit | T-GSE-S2-01 fast retransmit: 1 heartbeat(sqNum=1) + event + 5 fast retransmits (stNum=2 sqNum=0..5), then heartbeat resumes with sqNum=6; content byte-identical across retransmit frames | error | 0 | `` |
| goose_test_flag | T-GSE-S3-01 test flag set: all frames carry test=true encoded as BER 87 01 01 | error | 0 | `` |
| goose_vlan | T-GSE-S4-01 VLAN: TPID 0x8100 + TCI 0x8064 (prio 4 / id 100), EtherType 0x88b8 shifted +4, APDU at offset 26 | error | 0 | `` |

## Failures

### goose_dataset_change — T-GSE-S2-02 dataset change: heartbeat stNum=1 sqNum=1 then event frame stNum=2 sqNum=0 (RESET, not 1), retransmits sqNum 0..2 then heartbeat

generate: invalid or missing protocol: goose

### goose_heartbeat — T-GSE-S1-01/02 static heartbeat: 3 frames, stNum constant 1, sqNum 1/2/3 incrementing, appid 0x1000, confRev 1, TAL 500, numDatSetEntries 3, no IP (L2-direct 0x88b8)

generate: invalid or missing protocol: goose

### goose_multidataset — T-GSE-S7-01 multi-dataset: 6 members (bool/int32/uint32/float32/bit_string/visible_string), numDatSetEntries 6 == allData member count

generate: invalid or missing protocol: goose

### goose_multitype — T-GSE-S5-01 multi-type data values: Boolean x2, Integer x2, Unsigned, FloatingPoint, BitString x2, VisibleString x2 (10 members) - all BER member tags byte-verified, numDatSetEntries 10

generate: invalid or missing protocol: goose

### goose_ndscom_flag — T-GSE-S3-02 ndsCom flag set: all frames carry ndsCom=true encoded as BER 89 01 01

generate: invalid or missing protocol: goose

### goose_neg_appid — negative: appid 0x4000 falls in the SV-reserved segment (0x4000-0x7FFF) and must fail; GOOSE segment is 0x0000-0x3FFF

rejected but error "invalid or missing protocol: goose" does not contain "appid"

### goose_neg_sqnum — negative: non-contiguous sqNum - retransmit sequence jumps/duplicates sqNum (violates monotonically +1 within a burst)

rejected but error "invalid or missing protocol: goose" does not contain "sqNum"

### goose_neg_stnum — negative: stNum wrap-around - stNum must never regress/wrap (0xFFFFFFFF -> 0), violating the change counter monotonicity

rejected but error "invalid or missing protocol: goose" does not contain "stNum"

### goose_no_ip — T-GSE-S6-01 no-IP proof: frame carries ethernet 0x88b8 directly (no IPv4 0x0800 / IPv6 0x86dd), APDU 0x61 starts at byte 22 - GOOSE is L2-terminated

generate: invalid or missing protocol: goose

### goose_retransmit — T-GSE-S2-01 fast retransmit: 1 heartbeat(sqNum=1) + event + 5 fast retransmits (stNum=2 sqNum=0..5), then heartbeat resumes with sqNum=6; content byte-identical across retransmit frames

generate: invalid or missing protocol: goose

### goose_test_flag — T-GSE-S3-01 test flag set: all frames carry test=true encoded as BER 87 01 01

generate: invalid or missing protocol: goose

### goose_vlan — T-GSE-S4-01 VLAN: TPID 0x8100 + TCI 0x8064 (prio 4 / id 100), EtherType 0x88b8 shifted +4, APDU at offset 26

generate: invalid or missing protocol: goose

