# thrift Pcap Test Results

Cases: 13 — pass 1, fail 12, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| thrift_call_reply | S1/T-THRIFT-S1-01：add CALL→REPLY，9 包，大端 i32 与 seqid=1 | fail | 8 | `thrift/thrift_call_reply.pcap` |
| thrift_containers | S4/T-THRIFT-S4-01：LIST/SET/MAP 容器，9 包 | fail | 8 | `thrift/thrift_containers.pcap` |
| thrift_exception_reply | S2/T-THRIFT-S2-01：divide CALL→EXCEPTION，9 包 | fail | 8 | `thrift/thrift_exception_reply.pcap` |
| thrift_ipv6_echo | S6/T-THRIFT-S6-01：IPv6 TCP 9090 echo CALL→REPLY，偏移74，9包 | fail | 8 | `thrift/thrift_ipv6_echo.pcap` |
| thrift_multi_sessions | S7/T-THRIFT-S7-01：策略级两条独立 TCP 会话，各9包，seqid各自从1 | fail | 16 | `thrift/thrift_multi_sessions.pcap` |
| thrift_neg_bad_message_type | N5/T-THRIFT-N5：message type=9 拒绝 | fail | 0 | `` |
| thrift_neg_bad_port | N6/T-THRIFT-N6：TCP 目标端口越界拒绝 | pass | 0 | [pcap]() |
| thrift_neg_negative_container_count | N4/T-THRIFT-N4：LIST 负 count 拒绝 | fail | 0 | `` |
| thrift_neg_negative_length | N3/T-THRIFT-N3：STRING 负长度拒绝 | fail | 0 | `` |
| thrift_neg_truncated | N1/T-THRIFT-N1：截断 payload 拒绝 | fail | 0 | `` |
| thrift_neg_unknown_type | N2/T-THRIFT-N2：非法 field type=99 拒绝 | fail | 0 | `` |
| thrift_oneway_call | S3/T-THRIFT-S3-01：ONEWAY notify 单向调用，无响应，8 包 | fail | 8 | `thrift/thrift_oneway_call.pcap` |
| thrift_scalar_types | S5/T-THRIFT-S5-01：BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY 全字段，9 包 | fail | 8 | `thrift/thrift_scalar_types.pcap` |

## Failures

### thrift_call_reply — S1/T-THRIFT-S1-01：add CALL→REPLY，9 包，大端 i32 与 seqid=1

verify: count: got 8 packets, want 9; field tcp.len on packet 4: got "17", want "30"; field tcp.len on packet 5: got "0", want "23"; frame packet 4 offset 54: bytes mismatch at offset 61 (got 04, want 03); frame packet 5 offset 54: bytes mismatch at offset 54 (got 00, want 80); has_payload: no packet with frame.len > 80

### thrift_containers — S4/T-THRIFT-S4-01：LIST/SET/MAP 容器，9 包

verify: count: got 8 packets, want 9; field tcp.len on packet 4: got "17", want "69"; frame packet 4 offset 54: bytes mismatch at offset 61 (got 04, want 08); has_payload: no packet with frame.len > 80

### thrift_exception_reply — S2/T-THRIFT-S2-01：divide CALL→EXCEPTION，9 包

verify: count: got 8 packets, want 9; field tcp.len on packet 4: got "17", want "33"; field tcp.len on packet 5: got "0", want "49"; frame packet 4 offset 54: bytes mismatch at offset 57 (got 01, want 03); frame packet 5 offset 54: bytes mismatch at offset 54 (got 00, want 80); has_payload: no packet with frame.len > 80

### thrift_ipv6_echo — S6/T-THRIFT-S6-01：IPv6 TCP 9090 echo CALL→REPLY，偏移74，9包

verify: count: got 8 packets, want 9; frame packet 4 offset 74: bytes mismatch at offset 82 (got 70, want 65)

### thrift_multi_sessions — S7/T-THRIFT-S7-01：策略级两条独立 TCP 会话，各9包，seqid各自从1

verify: count: got 16 packets, want 18; field tcp.srcport: distinct values mismatch (want [12345 12346]; missing [12346]; unexpected [9090(x6)]); field tcp.dstport: distinct values mismatch (want [9090]; missing []; unexpected [12345(x6)]); has_payload: no packet with frame.len > 80

### thrift_neg_bad_message_type — N5/T-THRIFT-N5：message type=9 拒绝

expected task to be rejected but it completed

### thrift_neg_negative_container_count — N4/T-THRIFT-N4：LIST 负 count 拒绝

expected task to be rejected but it completed

### thrift_neg_negative_length — N3/T-THRIFT-N3：STRING 负长度拒绝

expected task to be rejected but it completed

### thrift_neg_truncated — N1/T-THRIFT-N1：截断 payload 拒绝

expected task to be rejected but it completed

### thrift_neg_unknown_type — N2/T-THRIFT-N2：非法 field type=99 拒绝

expected task to be rejected but it completed

### thrift_oneway_call — S3/T-THRIFT-S3-01：ONEWAY notify 单向调用，无响应，8 包

verify: field tcp.len on packet 4: got "17", want "27"; frame packet 4 offset 54: bytes mismatch at offset 57 (got 01, want 04); has_payload: no packet with frame.len > 80

### thrift_scalar_types — S5/T-THRIFT-S5-01：BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY 全字段，9 包

verify: count: got 8 packets, want 9; field tcp.len on packet 4: got "17", want "79"; frame packet 4 offset 54: bytes mismatch at offset 61 (got 04, want 07); has_payload: no packet with frame.len > 80

