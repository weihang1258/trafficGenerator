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

task ended failed: output error: [b96f34af-bc80-4ede-bd90-297b03c5636a-b873dbcb-e300-4690-92f6-0ae889f8e09a: validation failed: thrift: config is required]

### thrift_containers — S4/T-THRIFT-S4-01：LIST/SET/MAP 容器，9 包

task ended failed: output error: [6d72518f-d9a7-4e63-b8c5-4009fd0c8b81-b347a3e1-651f-4406-8237-d56908e65757: validation failed: thrift: config is required]

### thrift_exception_reply — S2/T-THRIFT-S2-01：divide CALL→EXCEPTION，9 包

task ended failed: output error: [5ded1e3b-a10c-4b89-8385-ae9d6cbe2197-4613b5e3-ca7d-4c69-8dbc-eb2b42bfacff: validation failed: thrift: config is required]

### thrift_ipv6_echo — S6/T-THRIFT-S6-01：IPv6 TCP 9090 echo CALL→REPLY，偏移74，9包

task ended failed: output error: [3913c9d8-4dbc-4eac-9b19-82dc242e8cea-6fc8ad67-527f-4a6e-bfe6-7082ec189017: validation failed: thrift: config is required]

### thrift_multi_sessions — S7/T-THRIFT-S7-01：策略级两条独立 TCP 会话，各9包，seqid各自从1

task ended failed: output error: [60375c15-3f99-4aa5-90ac-c36e6203eea5-fae6edb0-40ff-4a17-9d57-84ccf41ac9d5: validation failed: thrift: config is required]

### thrift_neg_bad_message_type — N5/T-THRIFT-N5：message type=9 拒绝

rejected but error "output error: [0cbffe07-3dab-45c3-9318-c085719199ae-7dfd036a-055c-4e48-9e3c-dc00d22f3c99: validation failed: thrift: config is required]" does not contain "invalid message type"

### thrift_neg_negative_container_count — N4/T-THRIFT-N4：LIST 负 count 拒绝

rejected but error "output error: [cbacec92-9c92-4624-b1f5-f938951842e4-bd535cf4-cf22-4a76-887e-88cbda7f5c60: validation failed: thrift: config is required]" does not contain "negative container count"

### thrift_neg_negative_length — N3/T-THRIFT-N3：STRING 负长度拒绝

rejected but error "output error: [b77d119d-0a62-49b8-8808-7b748c3828b9-3b41fd94-dd3f-4e6d-8fc7-5d1570557dff: validation failed: thrift: config is required]" does not contain "negative length"

### thrift_neg_truncated — N1/T-THRIFT-N1：截断 payload 拒绝

rejected but error "output error: [073cc13b-d4ad-4330-a6dd-d935820181a3-190fc920-eb61-43ff-8f14-19505143d9f1: validation failed: thrift: config is required]" does not contain "truncated"

### thrift_neg_unknown_type — N2/T-THRIFT-N2：非法 field type=99 拒绝

rejected but error "output error: [c639f567-4c7b-4d29-a8ac-3c62cf008da3-0cea8284-e889-4982-99b4-f20dbf03765d: validation failed: thrift: config is required]" does not contain "unknown field type"

### thrift_oneway_call — S3/T-THRIFT-S3-01：ONEWAY notify 单向调用，无响应，8 包

task ended failed: output error: [022696b0-7ede-46f4-b7a5-6d5be043c7a2-1a5ece75-a3a5-4d59-8cca-60310095c6f4: validation failed: thrift: config is required]

### thrift_scalar_types — S5/T-THRIFT-S5-01：BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY 全字段，9 包

task ended failed: output error: [4769c90a-923f-44c6-bb99-d273059dd0fc-9206cdde-7207-45ae-826b-723c4c7a4ad2: validation failed: thrift: config is required]

