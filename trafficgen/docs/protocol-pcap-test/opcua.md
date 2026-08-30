# opcua Pcap Test Results

Cases: 12 — pass 12, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| opcua_bad_node | Read an unknown node and return BadNodeIdUnknown 0x80340000 | pass | 15 | [pcap](opcua/opcua_bad_node.pcap) |
| opcua_bad_size_neg | Negative: malformed MessageSize and an overlong String length are rejected | pass | 0 | [pcap]() |
| opcua_browse | Browse the ObjectsFolder with forward references | pass | 15 | [pcap](opcua/opcua_browse.pcap) |
| opcua_denied | Write an unauthorized node and return BadUserAccessDenied 0x801F0000 | pass | 15 | [pcap](opcua/opcua_denied.pcap) |
| opcua_hello_ack | OPC UA transport handshake: HEL/ACK with an empty EndpointUrl | pass | 13 | [pcap](opcua/opcua_hello_ack.pcap) |
| opcua_ipv6 | OPC UA over IPv6: HEL/ACK, OPN, and Read | pass | 15 | [pcap](opcua/opcua_ipv6.pcap) |
| opcua_multi_session | Three logical sessions interleave one Read each on one secure channel | pass | 19 | [pcap](opcua/opcua_multi_session.pcap) |
| opcua_no_channel_neg | Negative: a Read before OpenSecureChannel is rejected | pass | 0 | [pcap]() |
| opcua_open_none | OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read | pass | 15 | [pcap](opcua/opcua_open_none.pcap) |
| opcua_open_sign | OpenSecureChannel with Basic256Sha256 Sign structure | pass | 13 | [pcap](opcua/opcua_open_sign.pcap) |
| opcua_subscribe | Create a subscription, monitor one node, publish one notification, then one keep-alive | pass | 23 | [pcap](opcua/opcua_subscribe.pcap) |
| opcua_write | Write one node Value attribute and return a service response | pass | 15 | [pcap](opcua/opcua_write.pcap) |
