# opcua Pcap Test Results

Cases: 12 — pass 0, fail 5, error 7

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| opcua_bad_node | Read an unknown node and return BadNodeIdUnknown 0x80340000 | error | 0 | `` |
| opcua_bad_size_neg | Negative: malformed MessageSize and an overlong String length are rejected | fail | 0 | `` |
| opcua_browse | Browse the ObjectsFolder with forward references | error | 0 | `` |
| opcua_denied | Write an unauthorized node and return BadUserAccessDenied 0x801F0000 | error | 0 | `` |
| opcua_hello_ack | OPC UA transport handshake: HEL/ACK with an empty EndpointUrl | fail | 22 | `opcua/opcua_hello_ack.pcap` |
| opcua_ipv6 | OPC UA over IPv6: HEL/ACK, OPN, and Read | error | 0 | `` |
| opcua_multi_session | Three logical sessions interleave one Read each on one secure channel | error | 0 | `` |
| opcua_no_channel_neg | Negative: a Read before OpenSecureChannel is rejected | fail | 0 | `` |
| opcua_open_none | OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read | fail | 22 | `opcua/opcua_open_none.pcap` |
| opcua_open_sign | OpenSecureChannel with Basic256Sha256 Sign structure | fail | 22 | `opcua/opcua_open_sign.pcap` |
| opcua_subscribe | Create a subscription, monitor one node, publish one notification, then one keep-alive | error | 0 | `` |
| opcua_write | Write one node Value attribute and return a service response | error | 0 | `` |

## Failures

### opcua_bad_node — Read an unknown node and return BadNodeIdUnknown 0x80340000

generate: layers: layer "opcua": unknown field "error_inject"

### opcua_bad_size_neg — Negative: malformed MessageSize and an overlong String length are rejected

expected task to be rejected but it completed

### opcua_browse — Browse the ObjectsFolder with forward references

generate: layers: layer "opcua": unknown field "browse"

### opcua_denied — Write an unauthorized node and return BadUserAccessDenied 0x801F0000

generate: layers: layer "opcua": unknown field "error_inject"

### opcua_hello_ack — OPC UA transport handshake: HEL/ACK with an empty EndpointUrl

verify: expert: frame 9 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 10 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 13 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 14 malformed: [Malformed Packet: OpcUa],_ws.malformed; count: got 22 packets, want 11; frame packet 4 offset 54: bytes mismatch at offset 54 (got 00, want 48); frame packet 5 offset 54: bytes mismatch at offset 54 (got 00, want 41); frame packet 6 offset 54: bytes mismatch at offset 54 (got 00, want 4f); frame packet 8 offset 54: bytes mismatch at offset 54 (got 41, want 43)

### opcua_ipv6 — OPC UA over IPv6: HEL/ACK, OPN, and Read

generate: layers[0]: each layer entry must contain exactly one layer name

### opcua_multi_session — Three logical sessions interleave one Read each on one secure channel

generate: layers: layer "opcua": unknown field "sessions"

### opcua_no_channel_neg — Negative: a Read before OpenSecureChannel is rejected

expected task to be rejected but it completed

### opcua_open_none — OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read

verify: expert: frame 9 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 10 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 13 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 14 malformed: [Malformed Packet: OpcUa],_ws.malformed; count: got 22 packets, want 13; frame packet 6 offset 54: bytes mismatch at offset 54 (got 00, want 4f); frame packet 6: offset 62 beyond frame length 60; frame packet 7 offset 54: bytes mismatch at offset 54 (got 48, want 4f); frame packet 7 offset 62: bytes mismatch at offset 62 (got 00, want 01); frame packet 8 offset 54: bytes mismatch at offset 54 (got 41, want 4d); frame packet 8 offset 62: bytes mismatch at offset 62 (got 00, want 01); frame packet 8 offset 66: bytes mismatch at offset 66 (got 00, want e8); frame packet 10 offset 54: bytes mismatch at offset 54 (got 4f, want 43)

### opcua_open_sign — OpenSecureChannel with Basic256Sha256 Sign structure

verify: expert: frame 9 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 10 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 13 malformed: [Malformed Packet: OpcUa],_ws.malformed; expert: frame 14 malformed: [Malformed Packet: OpcUa],_ws.malformed; count: got 22 packets, want 11; frame packet 6 offset 54: bytes mismatch at offset 54 (got 00, want 4f); frame packet 6: offset 62 beyond frame length 60; frame packet 7 offset 54: bytes mismatch at offset 54 (got 48, want 4f); frame packet 7 offset 62: bytes mismatch at offset 62 (got 00, want 01); frame packet 8 offset 54: bytes mismatch at offset 54 (got 41, want 43)

### opcua_subscribe — Create a subscription, monitor one node, publish one notification, then one keep-alive

generate: layers: layer "opcua": unknown field "subscription"

### opcua_write — Write one node Value attribute and return a service response

generate: layers: layer "opcua": unknown field "write"

