# drda Pcap Test Results

Cases: 10 — pass 10, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| drda_database_connect | T-DRDA-003/S3：ACCRDB 关系数据库关联成功 | pass | 15 | [pcap](drda/drda_database_connect.pcap) |
| drda_dss_length_mismatch | T-DRDA-009：DSS/DDM 显式长度与编码长度不一致时拒绝 | pass | 0 | [pcap]() |
| drda_dss_min_length | T-DRDA-006/S6：DDM length=10、length2=4 最小无参数边界 | pass | 9 | [pcap](drda/drda_dss_min_length.pcap) |
| drda_excsat | T-DRDA-001/S1：TCP 446 与 EXCSAT→EXCSATRD 关联建立 | pass | 9 | [pcap](drda/drda_excsat.pcap) |
| drda_ipv6_excsat | T-DRDA-007/S7：IPv6 上 EXCSAT，DRDA 字节保持不变 | pass | 9 | [pcap](drda/drda_ipv6_excsat.pcap) |
| drda_multi_session | T-DRDA-008/S8：两条独立 TCP 会话，各自 correlator 从 1 开始 | pass | 18 | [pcap](drda/drda_multi_session.pcap) |
| drda_security_check | T-DRDA-002/S2：EXCSAT、ACCSEC、SECCHK 及响应顺序 | pass | 13 | [pcap](drda/drda_security_check.pcap) |
| drda_sql_error | T-DRDA-005/S5：SQLDTA→SQLCARD 负 SQLCODE 错误结果 | pass | 17 | [pcap](drda/drda_sql_error.pcap) |
| drda_sql_success | T-DRDA-004/S4：SQLDTA→SQLCARD 成功 SQLCODE=0 | pass | 17 | [pcap](drda/drda_sql_success.pcap) |
| drda_udp_rejected | T-DRDA-010：UDP 载体被 drda 层依赖校验拒绝 | pass | 0 | [pcap]() |
