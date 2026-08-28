# drda Pcap Test Results

Cases: 10 — pass 1, fail 1, error 8

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| drda_database_connect | T-DRDA-003/S3：ACCRDB 关系数据库关联成功 | error | 0 | `` |
| drda_dss_length_mismatch | T-DRDA-009：DSS/DDM 显式长度与编码长度不一致时拒绝 | fail | 0 | `` |
| drda_dss_min_length | T-DRDA-006/S6：DDM length=10、length2=4 最小无参数边界 | error | 0 | `` |
| drda_excsat | T-DRDA-001/S1：TCP 446 与 EXCSAT→EXCSATRD 关联建立 | error | 0 | `` |
| drda_ipv6_excsat | T-DRDA-007/S7：IPv6 上 EXCSAT，DRDA 字节保持不变 | error | 0 | `` |
| drda_multi_session | T-DRDA-008/S8：两条独立 TCP 会话，各自 correlator 从 1 开始 | error | 0 | `` |
| drda_security_check | T-DRDA-002/S2：EXCSAT、ACCSEC、SECCHK 及响应顺序 | error | 0 | `` |
| drda_sql_error | T-DRDA-005/S5：SQLDTA→SQLCARD 负 SQLCODE 错误结果 | error | 0 | `` |
| drda_sql_success | T-DRDA-004/S4：SQLDTA→SQLCARD 成功 SQLCODE=0 | error | 0 | `` |
| drda_udp_rejected | T-DRDA-010：UDP 载体被 drda 层依赖校验拒绝 | pass | 0 | [pcap]() |

## Failures

### drda_database_connect — T-DRDA-003/S3：ACCRDB 关系数据库关联成功

task ended failed: output error: [585b0612-2e2b-4941-bb9d-3ff9bb26f0bb-8c077a1e-0e37-4291-a434-c182753600a8: validation failed: drda: config is required]

### drda_dss_length_mismatch — T-DRDA-009：DSS/DDM 显式长度与编码长度不一致时拒绝

rejected but error "output error: [a11b5f1f-ed55-4507-b269-75cbdb8a0cd3-8df5b910-38a4-4ae3-a91a-5e9f769a534e: validation failed: drda: config is required]" does not contain "dss_length"

### drda_dss_min_length — T-DRDA-006/S6：DDM length=10、length2=4 最小无参数边界

task ended failed: output error: [0b1f0a57-7d44-497e-95db-5880ab5a6275-a35bd2cb-94ad-4ab6-b353-d08528bdcd02: validation failed: drda: config is required]

### drda_excsat — T-DRDA-001/S1：TCP 446 与 EXCSAT→EXCSATRD 关联建立

task ended failed: output error: [2ac7fa40-472e-482e-8b9b-d729da5fffc3-5ed52a1a-c3e9-41aa-9e86-9edca00ee915: validation failed: drda: config is required]

### drda_ipv6_excsat — T-DRDA-007/S7：IPv6 上 EXCSAT，DRDA 字节保持不变

task ended failed: output error: [68b9086c-2206-4a35-8e39-582f9c8eac77-46861c12-3fd1-434f-b42a-98b40ceaf2e5: validation failed: drda: config is required]

### drda_multi_session — T-DRDA-008/S8：两条独立 TCP 会话，各自 correlator 从 1 开始

task ended failed: output error: [43da1708-6c67-4b98-b6e5-d6f61025757f-9dfaa45c-734d-42a1-8211-b3051ef4ff75: validation failed: drda: config is required]

### drda_security_check — T-DRDA-002/S2：EXCSAT、ACCSEC、SECCHK 及响应顺序

task ended failed: output error: [65d82db1-7341-4545-85b4-a845900df00b-500a6950-df0f-4f97-880f-7dd070fbe569: validation failed: drda: config is required]

### drda_sql_error — T-DRDA-005/S5：SQLDTA→SQLCARD 负 SQLCODE 错误结果

task ended failed: output error: [bfffd08c-6cf2-4cdb-8597-0a923d620391-6b7ac837-0f16-4c04-a088-71d62fc4454b: validation failed: drda: config is required]

### drda_sql_success — T-DRDA-004/S4：SQLDTA→SQLCARD 成功 SQLCODE=0

task ended failed: output error: [01c1c1c8-e1e2-4490-83c4-981713a4f77b-c621da06-8007-45d2-ac94-44b83c1945d4: validation failed: drda: config is required]

