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

task ended failed: output error: [88564c91-2455-456d-b683-ae2caf211b52-c83071fd-c5d5-4d6c-915a-dc1ffa0d0645: validation failed: drda: config is required]

### drda_dss_length_mismatch — T-DRDA-009：DSS/DDM 显式长度与编码长度不一致时拒绝

rejected but error "output error: [9678166c-79b5-427c-b28b-e86d4820c695-762e2ab4-c029-45db-9779-b3a5ee42adad: validation failed: drda: config is required]" does not contain "dss_length"

### drda_dss_min_length — T-DRDA-006/S6：DDM length=10、length2=4 最小无参数边界

task ended failed: output error: [c5eb72b4-3603-4967-a36d-4890ef3128c1-2bf75d8a-f388-4000-b5a8-14a2d9c7c453: validation failed: drda: config is required]

### drda_excsat — T-DRDA-001/S1：TCP 446 与 EXCSAT→EXCSATRD 关联建立

task ended failed: output error: [29b94117-42a0-41c5-8c61-a74c08a64052-9f5200b1-f1b9-46ef-a9db-e3d8ab081d17: validation failed: drda: config is required]

### drda_ipv6_excsat — T-DRDA-007/S7：IPv6 上 EXCSAT，DRDA 字节保持不变

task ended failed: output error: [468bb53a-de8b-41fb-aa33-5a7163089ad6-2a6720ef-860a-45d5-805e-a1139a3cd16f: validation failed: drda: config is required]

### drda_multi_session — T-DRDA-008/S8：两条独立 TCP 会话，各自 correlator 从 1 开始

task ended failed: output error: [2ae36b5e-0eaa-4b15-abc6-c8326dce6080-c75e7c83-9028-4f27-9fb2-800100fbbfc5: validation failed: drda: config is required]

### drda_security_check — T-DRDA-002/S2：EXCSAT、ACCSEC、SECCHK 及响应顺序

task ended failed: output error: [d305b0d8-25e7-469f-b01f-65a505fe6855-4ba9a200-c7f1-47df-bc78-3b96a412a096: validation failed: drda: config is required]

### drda_sql_error — T-DRDA-005/S5：SQLDTA→SQLCARD 负 SQLCODE 错误结果

task ended failed: output error: [fd7888db-e202-4fef-87d6-7a6a81e94c82-d916b040-6357-48ae-a486-2c178cd21b5c: validation failed: drda: config is required]

### drda_sql_success — T-DRDA-004/S4：SQLDTA→SQLCARD 成功 SQLCODE=0

task ended failed: output error: [7a7dd4b2-3539-44d1-812d-9a649c0717ac-5575f8ac-f27a-4b20-a331-708df078c187: validation failed: drda: config is required]

