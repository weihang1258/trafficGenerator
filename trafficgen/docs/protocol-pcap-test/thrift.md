# thrift Pcap Test Results

Cases: 13 — pass 1, fail 5, error 7

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| thrift_call_reply | S1/T-THRIFT-S1-01：add CALL→REPLY，9 包，大端 i32 与 seqid=1 | error | 0 | `` |
| thrift_containers | S4/T-THRIFT-S4-01：LIST/SET/MAP 容器，9 包 | error | 0 | `` |
| thrift_exception_reply | S2/T-THRIFT-S2-01：divide CALL→EXCEPTION，9 包 | error | 0 | `` |
| thrift_ipv6_echo | S6/T-THRIFT-S6-01：IPv6 TCP 9090 echo CALL→REPLY，偏移74，9包 | error | 0 | `` |
| thrift_multi_sessions | S7/T-THRIFT-S7-01：策略级两条独立 TCP 会话，各9包，seqid各自从1 | error | 0 | `` |
| thrift_neg_bad_message_type | N5/T-THRIFT-N5：message type=9 拒绝 | fail | 0 | `` |
| thrift_neg_bad_port | N6/T-THRIFT-N6：TCP 目标端口越界拒绝 | pass | 0 | [pcap]() |
| thrift_neg_negative_container_count | N4/T-THRIFT-N4：LIST 负 count 拒绝 | fail | 0 | `` |
| thrift_neg_negative_length | N3/T-THRIFT-N3：STRING 负长度拒绝 | fail | 0 | `` |
| thrift_neg_truncated | N1/T-THRIFT-N1：截断 payload 拒绝 | fail | 0 | `` |
| thrift_neg_unknown_type | N2/T-THRIFT-N2：非法 field type=99 拒绝 | fail | 0 | `` |
| thrift_oneway_call | S3/T-THRIFT-S3-01：ONEWAY notify 单向调用，无响应，8 包 | error | 0 | `` |
| thrift_scalar_types | S5/T-THRIFT-S5-01：BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY 全字段，9 包 | error | 0 | `` |

## Failures

### thrift_call_reply — S1/T-THRIFT-S1-01：add CALL→REPLY，9 包，大端 i32 与 seqid=1

task ended failed: output error: [e29a1e7e-18ad-4bf6-b75d-aef3e6fa6401-1a3bd985-4982-41d8-9182-f837943ae5af: validation failed: thrift: config is required]

### thrift_containers — S4/T-THRIFT-S4-01：LIST/SET/MAP 容器，9 包

task ended failed: output error: [242b161f-f2df-4e65-accb-47a671a185f9-5898aa43-0761-4a14-8799-cfa5575209ea: validation failed: thrift: config is required]

### thrift_exception_reply — S2/T-THRIFT-S2-01：divide CALL→EXCEPTION，9 包

task ended failed: output error: [e7691d8c-d783-4f6c-8098-1f7f68a6c7dc-154b0616-701c-4d58-8b62-e504a01233ec: validation failed: thrift: config is required]

### thrift_ipv6_echo — S6/T-THRIFT-S6-01：IPv6 TCP 9090 echo CALL→REPLY，偏移74，9包

task ended failed: output error: [9fa5d3b6-5e40-4d5c-8cc1-47be3103b061-eaf5e568-e684-45e4-b22c-8c7971c2cc81: validation failed: thrift: config is required]

### thrift_multi_sessions — S7/T-THRIFT-S7-01：策略级两条独立 TCP 会话，各9包，seqid各自从1

task ended failed: output error: [3349cffb-d6c7-40ac-9fd0-58f748028690-0a533e18-1db9-44c4-b05e-c3b668d9f8f6: validation failed: thrift: config is required]

### thrift_neg_bad_message_type — N5/T-THRIFT-N5：message type=9 拒绝

rejected but error "output error: [4d22e9e4-f1fd-480d-a77f-912bed15fceb-41222b1e-c582-4785-82e4-10e56861a8f2: validation failed: thrift: config is required]" does not contain "invalid message type"

### thrift_neg_negative_container_count — N4/T-THRIFT-N4：LIST 负 count 拒绝

rejected but error "output error: [f3eb156f-5cb7-41ea-9cbe-ff01e478e9ff-0b476e52-d83a-44a6-a7f7-c8858cf3b101: validation failed: thrift: config is required]" does not contain "negative container count"

### thrift_neg_negative_length — N3/T-THRIFT-N3：STRING 负长度拒绝

rejected but error "output error: [1e62444b-5c00-4e19-bf14-06e99998dabf-5e6c2fd4-c643-4d09-8a82-0c35924369f3: validation failed: thrift: config is required]" does not contain "negative length"

### thrift_neg_truncated — N1/T-THRIFT-N1：截断 payload 拒绝

rejected but error "output error: [3d82c0eb-f9c1-42ab-8229-3de0590a756c-715c0af8-70ff-4dd9-908e-092812b02d55: validation failed: thrift: config is required]" does not contain "truncated"

### thrift_neg_unknown_type — N2/T-THRIFT-N2：非法 field type=99 拒绝

rejected but error "output error: [03a26051-651d-4ed4-b69d-8a9446519d0c-fe3e2764-9904-4807-82c0-6d0d3189fb69: validation failed: thrift: config is required]" does not contain "unknown field type"

### thrift_oneway_call — S3/T-THRIFT-S3-01：ONEWAY notify 单向调用，无响应，8 包

task ended failed: output error: [8c4b5992-612f-4b50-996c-b70e344e2d62-0989afc3-9018-4b82-9987-07daa6181a4c: validation failed: thrift: config is required]

### thrift_scalar_types — S5/T-THRIFT-S5-01：BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY 全字段，9 包

task ended failed: output error: [4dc8ce81-067a-4a9e-b40d-f3595617e5cb-20a28416-eaf8-466e-811b-5462d65ff914: validation failed: thrift: config is required]

