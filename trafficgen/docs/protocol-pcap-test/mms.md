# mms Pcap Test Results

Cases: 11 — pass 0, fail 2, error 9

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mms_connect_establish | MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions | fail | 13 | `mms/mms_connect_establish.pcap` |
| mms_getnamelist | MMS GetNameList: request vmdSpecific scope, response listOfIdentifier | error | 0 | `` |
| mms_identify | MMS Identify: response vendor/model/revision | error | 0 | `` |
| mms_information_report | MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame | error | 0 | `` |
| mms_ipv6 | MMS over IPv6: full association with payload offset 74 | error | 0 | `` |
| mms_multi_session | MMS multi-session: two independent TCP associations each complete CR/CC | error | 0 | `` |
| mms_no_associate | MMS negative: noAssociate=true skips four-way association, service frames only | error | 0 | `` |
| mms_read_multi_type | MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime) | error | 0 | `` |
| mms_service_error | MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent) | error | 0 | `` |
| mms_validate_reject | MMS negative: validator rejects an item-identifier whose UTF-8 encoding exceeds 32 bytes | fail | 0 | `` |
| mms_write_success | MMS Write: write full variable list, response success list (80 01 00 each) | error | 0 | `` |

## Failures

### mms_connect_establish — MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions

verify: count: got 13 packets, want 7; field cotp.type on packet 7: got "", want "0x0f"; field cotp.eot on packet 7: got "", want "1"; frame packet 7: offset 105 beyond frame length 104

### mms_getnamelist — MMS GetNameList: request vmdSpecific scope, response listOfIdentifier

generate: layers: layer "mms": unknown field "enableGetNameList"

### mms_identify — MMS Identify: response vendor/model/revision

generate: layers: layer "mms": unknown field "enableIdentify"

### mms_information_report — MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame

generate: layers: layer "mms": unknown field "enableInformationReport"

### mms_ipv6 — MMS over IPv6: full association with payload offset 74

generate: layers[1]: each layer entry must contain exactly one layer name

### mms_multi_session — MMS multi-session: two independent TCP associations each complete CR/CC

generate: layers: layer "mms": unknown field "enableRead"

### mms_no_associate — MMS negative: noAssociate=true skips four-way association, service frames only

generate: layers: layer "mms": unknown field "association"

### mms_read_multi_type — MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime)

generate: layers: layer "mms": unknown field "enableRead"

### mms_service_error — MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent)

generate: layers: layer "mms": unknown field "enableRead"

### mms_validate_reject — MMS negative: validator rejects an item-identifier whose UTF-8 encoding exceeds 32 bytes

rejected but error "layers: layer \"mms\": unknown field \"enableRead\"" does not contain "name"

### mms_write_success — MMS Write: write full variable list, response success list (80 01 00 each)

generate: layers: layer "mms": unknown field "enableWrite"

