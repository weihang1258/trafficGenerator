# opcua Pcap Test Results

Cases: 12 — pass 0, fail 2, error 10

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| opcua_bad_node | Read an unknown node and return BadNodeIdUnknown 0x80340000 | error | 0 | `` |
| opcua_bad_size_neg | Negative: malformed MessageSize and an overlong String length are rejected | fail | 0 | `` |
| opcua_browse | Browse the ObjectsFolder with forward references | error | 0 | `` |
| opcua_denied | Write an unauthorized node and return BadUserAccessDenied 0x801F0000 | error | 0 | `` |
| opcua_hello_ack | OPC UA transport handshake: HEL/ACK with an empty EndpointUrl | error | 0 | `` |
| opcua_ipv6 | OPC UA over IPv6: HEL/ACK, OPN, and Read | error | 0 | `` |
| opcua_multi_session | Three logical sessions interleave one Read each on one secure channel | error | 0 | `` |
| opcua_no_channel_neg | Negative: a Read before OpenSecureChannel is rejected | fail | 0 | `` |
| opcua_open_none | OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read | error | 0 | `` |
| opcua_open_sign | OpenSecureChannel with Basic256Sha256 Sign structure | error | 0 | `` |
| opcua_subscribe | Create a subscription, monitor one node, publish one notification, then one keep-alive | error | 0 | `` |
| opcua_write | Write one node Value attribute and return a service response | error | 0 | `` |

## Failures

### opcua_bad_node — Read an unknown node and return BadNodeIdUnknown 0x80340000

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_bad_size_neg — Negative: malformed MessageSize and an overlong String length are rejected

rejected but error "invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag" does not contain "MessageSize"

### opcua_browse — Browse the ObjectsFolder with forward references

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_denied — Write an unauthorized node and return BadUserAccessDenied 0x801F0000

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_hello_ack — OPC UA transport handshake: HEL/ACK with an empty EndpointUrl

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_ipv6 — OPC UA over IPv6: HEL/ACK, OPN, and Read

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_multi_session — Three logical sessions interleave one Read each on one secure channel

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_no_channel_neg — Negative: a Read before OpenSecureChannel is rejected

rejected but error "invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag" does not contain "secureChannel"

### opcua_open_none — OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_open_sign — OpenSecureChannel with Basic256Sha256 Sign structure

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_subscribe — Create a subscription, monitor one node, publish one notification, then one keep-alive

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

### opcua_write — Write one node Value attribute and return a service response

generate: invalid request: Key: 'CreateStrategyRequest.Config' Error:Field validation for 'Config' failed on the 'required' tag

