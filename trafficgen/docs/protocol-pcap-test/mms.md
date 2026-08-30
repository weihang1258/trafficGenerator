# mms Pcap Test Results

Cases: 11 — pass 11, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mms_connect_establish | MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions | pass | 7 | [pcap](mms/mms_connect_establish.pcap) |
| mms_getnamelist | MMS GetNameList: request vmdSpecific scope, response listOfIdentifier | pass | 9 | [pcap](mms/mms_getnamelist.pcap) |
| mms_identify | MMS Identify: response vendor/model/revision | pass | 9 | [pcap](mms/mms_identify.pcap) |
| mms_information_report | MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame | pass | 8 | [pcap](mms/mms_information_report.pcap) |
| mms_ipv6 | MMS over IPv6: full association with payload offset 74 | pass | 7 | [pcap](mms/mms_ipv6.pcap) |
| mms_multi_session | MMS multi-session: two independent TCP associations each complete CR/CC | pass | 18 | [pcap](mms/mms_multi_session.pcap) |
| mms_no_associate | MMS negative: noAssociate=true skips four-way association, service frames only | pass | 5 | [pcap](mms/mms_no_associate.pcap) |
| mms_read_multi_type | MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime) | pass | 9 | [pcap](mms/mms_read_multi_type.pcap) |
| mms_service_error | MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent) | pass | 9 | [pcap](mms/mms_service_error.pcap) |
| mms_validate_reject | MMS negative: validator rejects an item-identifier whose UTF-8 encoding exceeds 32 bytes | pass | 0 | [pcap]() |
| mms_write_success | MMS Write: write full variable list, response success list (80 01 00 each) | pass | 9 | [pcap](mms/mms_write_success.pcap) |
