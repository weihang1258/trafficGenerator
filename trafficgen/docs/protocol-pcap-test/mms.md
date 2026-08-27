# mms Pcap Test Results

Cases: 11 — pass 0, fail 1, error 10

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mms_connect_establish | MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions | error | 0 | `` |
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

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_getnamelist — MMS GetNameList: request vmdSpecific scope, response listOfIdentifier

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_identify — MMS Identify: response vendor/model/revision

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_information_report — MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_ipv6 — MMS over IPv6: full association with payload offset 74

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_multi_session — MMS multi-session: two independent TCP associations each complete CR/CC

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_no_associate — MMS negative: noAssociate=true skips four-way association, service frames only

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_read_multi_type — MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime)

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_service_error — MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent)

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### mms_validate_reject — MMS negative: validator rejects an item-identifier whose UTF-8 encoding exceeds 32 bytes

rejected but error "invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag" does not contain "name"

### mms_write_success — MMS Write: write full variable list, response success list (80 01 00 each)

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

