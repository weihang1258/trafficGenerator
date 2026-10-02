# mms Pcap Test Results

Cases: 19 — pass 19, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mms_connect_establish | MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions | pass | 7 | [pcap](mms/mms_connect_establish.pcap) |
| mms_domain_overlong | A′ T-MMS-18（变体行 15）: domain 超 32B 拒（planner.go 域名门，此前零 cases） | pass | 0 | [pcap]() |
| mms_getnamelist | MMS GetNameList: request vmdSpecific scope, response listOfIdentifier | pass | 9 | [pcap](mms/mms_getnamelist.pcap) |
| mms_identify | MMS Identify: response vendor/model/revision | pass | 9 | [pcap](mms/mms_identify.pcap) |
| mms_information_report | MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame | pass | 8 | [pcap](mms/mms_information_report.pcap) |
| mms_ipv6 | MMS over IPv6: full association with payload offset 74 | pass | 7 | [pcap](mms/mms_ipv6.pcap) |
| mms_multi_session | MMS multi-session: two independent TCP associations each complete CR/CC | pass | 18 | [pcap](mms/mms_multi_session.pcap) |
| mms_multiflow | G-MMS-8 flow_control 补例（§12.12）：flows=2 双流并发，ip.src 层内动态逐流递增 + 框架逐流源端口 12345/12346，每流关联 7 包 | pass | 14 | [pcap](mms/mms_multiflow.pcap) |
| mms_neg_dead_sequence_key | G-MMS-2: sequence.loop 零消费（死配置）→ validator 判死 | pass | 0 | [pcap]() |
| mms_neg_multisession_override | 契约 §2.2: multiSession 子会话只覆盖 objects，写 enableWrite 等键读都不读（死配置）→ validator 判死 | pass | 0 | [pcap]() |
| mms_neg_object_members | §2.3 死配置: objects[].members 无编码路径读取（builder 零命中）→ validator 判死 | pass | 0 | [pcap]() |
| mms_neg_presence | 负例：层链+顶层 mms 子映射并存=判死（presence 负例形状） | pass | 0 | [pcap]() |
| mms_neg_stray_src_ip | 游离键: layers + 顶层 src_ip 并存判死 | pass | 0 | [pcap]() |
| mms_neg_unsupported_datatype | G-MMS-3: float 走 builder default 错字节 → validator 判死（编码与校验一致） | pass | 0 | [pcap]() |
| mms_no_associate | MMS negative: noAssociate=true skips four-way association, service frames only | pass | 5 | [pcap](mms/mms_no_associate.pcap) |
| mms_read_multi_type | MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime) | pass | 9 | [pcap](mms/mms_read_multi_type.pcap) |
| mms_service_error | MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent) | pass | 9 | [pcap](mms/mms_service_error.pcap) |
| mms_validate_reject | MMS negative: validator rejects an item-identifier whose UTF-8 encoding exceeds 32 bytes | pass | 0 | [pcap]() |
| mms_write_success | MMS Write: write full variable list, response success list (80 01 00 each) | pass | 9 | [pcap](mms/mms_write_success.pcap) |
