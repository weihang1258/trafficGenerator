# 协议测试用例 ↔ pcap 对应关系

所有 pcap 位于 `/tmp/mcp-pcaps/`(子目录 `pcaps/` 或 `H/`)。
- 用例 ID 即 `run_<proto>.py` 中 `cases = [...]` 或 `run_test("ID", ...)` 的 ID。
- 断言逻辑见对应脚本 `case_<proto>_<N>` 函数体。
- "动态生成" 表示 pcap 路径由 `run_test` 统一命名(如 `b3-<id>.pcap`)。

---

## OpenVPN(`run_openvpn.py`,端口 1194,TCP/UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| OPENVPN.1.1 | P_CONTROL_HARD_RESET_CLIENT_V2 opcode=7 -> header byte 0x38 (key_id=0). | `openvpn_1_1.pcap` |
| OPENVPN.1.2 | P_DATA_V2 opcode=9 -> first byte 0x40 (high 3 bits = 100b). | `openvpn_1_2.pcap` |
| OPENVPN.1.3 | session_id=0xAABBCC appears as 8-byte BE after the opcode byte. | `openvpn_1_3.pcap` |
| OPENVPN.1.4 | tls_auth=true prepends 20 bytes of 0xAA HMAC after packet_id. | `openvpn_1_4.pcap` |
| OPENVPN.1.5 | tls_crypt=true emits wrapped_key (auth-tag 32B + IV 16B + cipher_key). | `openvpn_1_5.pcap` |
| OPENVPN.1.6 | TCP proto mode: TCP 3-way handshake + OpenVPN over TCP. | `openvpn_1_6.pcap` |
| OPENVPN.1.7 | Static-key P2P P_DATA_V1 opcode=7 -> first byte 0xE0 (key_id=0). | `openvpn_1_7.pcap` |
| OPENVPN.1.8 | Soft reset: P_CONTROL_SOFT_RESET_V1 opcode=3 -> first byte 0x60 (key_id=1). | `openvpn_1_8.pcap` |
| OPENVPN.2.1 | Full tunnel: handshake (HARD_RESET_V2) + P_DATA_V2 carrying inner | `openvpn_2_1.pcap` |
| OPENVPN.2.2 | Multiple inner IP packets: 3 distinct inner IPv4 business flows. | `openvpn_2_2.pcap` |
| OPENVPN.2.3 | Large inner packet: inner IPv4 with a large payload that triggers | `openvpn_2_3.pcap` |
| OPENVPN.2.4 | Inner IPv6: P_DATA_V2 carrying an inner IPv6 business packet. | `openvpn_2_4.pcap` |

## WireGuard(`run_wireguard.py`,端口 51820,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| WG.1.1 | Handshake Initiation (type=1, 0x01) first byte. | `wg_1_1.pcap` |
| WG.1.2 | Handshake Response (type=2, 0x02) first byte. | `wg_1_2.pcap` |
| WG.1.3 | Transport Data (type=4, 0x04) first byte after handshake. | `wg_1_3.pcap` |
| WG.1.4 | Initiation total length = 148 bytes (full UDP payload). | `wg_1_4.pcap` |
| WG.1.5 | sender_index=42 (0x2A 0x00 0x00 0x00 little-endian) at offset 4-8 of Initiation. | `wg_1_5.pcap` |
| WG.1.6 | Cookie Reply (type=3, 0x03) first byte (responder + CookieReplyThreshold). | `wg_1_6.pcap` |
| WG.1.7 | Full handshake + transport emits multiple UDP datagrams. | `wg_1_7.pcap` |
| WG.1.8 | Transport counter starts at 0 (bytes 8-16 = 0x00 x8). | `wg_1_8.pcap` |
| WG.2.1 | Complete tunnel: handshake + inner IPv4 transport + keepalive. | `wg_2_1.pcap` |
| WG.2.2 | Inner IPv6 tunnel: Transport Data carries inner IPv6 packet (0x60). | `wg_2_2.pcap` |
| WG.2.3 | Multi Transport Data frames (DataFrames=3): 3 inner IPv4 packets. | `wg_2_3.pcap` |
| WG.2.4 | Inner IPv4 UDP: inner UDP src/dst ports present at offset 36-40. | `wg_2_4.pcap` |
| WG.2.5 | Inner IPv4 header checksum correct (RFC 791). | `wg_2_5.pcap` |

## L2TP(`run_l2tp.py`,端口 1701,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| L2TP.1.1 | L2TP.1.1: SCCRQ control message (T=1, Ver=2 -> 0xC802 in first 2 bytes) | `l2tp_1_1.pcap` |
| L2TP.1.10 | L2TP.1.10: tunnel_with_data PPP data frame carries inner IPv4 (0x45) | `l2tp_1_10.pcap` |
| L2TP.1.11 | L2TP.1.11: tunnel_with_data StopCCN appears after PPP data (last packet) | `l2tp_1_11.pcap` |
| L2TP.1.12 | L2TP.1.12: tunnel_with_data with multiple data frames (3) emits 10 pkts | `l2tp_1_12.pcap` |
| L2TP.1.2 | L2TP.1.2: SCCRP control message (Message Type AVP=2) | `l2tp_1_2.pcap` |
| L2TP.1.3 | L2TP.1.3: SCCRQ+SCCRP+SCCCN handshake (3 packets) | `l2tp_1_3.pcap` |
| L2TP.1.4 | L2TP.1.4: L2TPv2 control header: T=1, L=1, S=1, Ver=2 (0xC802) | `l2tp_1_4.pcap` |
| L2TP.1.5 | L2TP.1.5: Tunnel ID field at offset 4-5 | `l2tp_1_5.pcap` |
| L2TP.1.6 | L2TP.1.6: L2TPv3 control header (T=1, Ver=3, 0xC803) | `l2tp_1_6.pcap` |
| L2TP.1.7 | L2TP.1.7: HELLO message (Message Type=6) | `l2tp_1_7.pcap` |
| L2TP.1.8 | L2TP.1.8: StopCCN message (Message Type=4) | `l2tp_1_8.pcap` |
| L2TP.1.9 | L2TP.1.9: tunnel_with_data scenario emits 8 packets (6 ctrl + 1 data + 1 StopCCN) | `l2tp_1_9.pcap` |

## IKE(`run_ike.py`,端口 500,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| IKE.1.1 | IKE.1.1: standard_v2 scenario emits >=2 messages | `ike_1_1.pcap` |
| IKE.1.2 | IKE.1.2: InitiatorSPI=0x0123456789ABCDEF in bytes[0:8] | `ike_1_2.pcap` |
| IKE.1.3 | IKE.1.3: ResponderSPI=0 in INIT request bytes[8:16] | `ike_1_3.pcap` |
| IKE.1.4 | IKE.1.4: Version=0x20 (IKEv2) in byte[17] | `ike_1_4.pcap` |
| IKE.1.5 | IKE.1.5: ExchangeType=34 (IKE_SA_INIT) in byte[18] | `ike_1_5.pcap` |
| IKE.1.6 | IKE.1.6: MessageID=0 in INIT request bytes[20:24] | `ike_1_6.pcap` |
| IKE.1.7 | IKE.1.7: Role=initiator scenario produces both up and down packets | `ike_1_7.pcap` |
| IKE.1.8 | IKE.1.8: DPD scenario emits INFORMATIONAL (ExchangeType=37) | `ike_1_8.pcap` |
| IKE.2.1 | IKE.2.1: IKE_SA_INIT handshake + ESP data flow emits >4 packets | `ike_2_1.pcap` |
| IKE.2.2 | IKE.2.2: ESP tunnel mode double-IP (SPI at bytes[0:4], inner IP at bytes[24:28]) | `ike_2_2.pcap` |
| IKE.2.3 | IKE.2.3: ESP transport mode (NextHeader=17 UDP, no inner IP header) | `ike_2_3.pcap` |
| IKE.2.4 | IKE.2.4: Multiple ESP packets in tunnel (business flow) with seq 1..N | `ike_2_4.pcap` |
| IKE.2.5 | IKE.2.5: CREATE_CHILD_SA rekey scenario emits CREATE_CHILD_SA (ExType=36) | `ike_2_5.pcap` |

## IKE-NAT-T(`run_ike_nat_t.py`,端口 4500,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| IKENATT.1.1 | IKENATT.1.1: default dialog emits >=2 messages | `ikenatt_1_1.pcap` |
| IKENATT.1.2 | IKENATT.1.2: Non-ESP Marker (4 bytes 0x00000000) on port 4500 | `ikenatt_1_2.pcap` |
| IKENATT.1.3 | IKENATT.1.3: IKE Header InitiatorSPI bytes[0:8] (after marker) | `ikenatt_1_3.pcap` |
| IKENATT.1.4 | IKENATT.1.4: ResponderSPI=0 in IKE_SA_INIT request bytes[8:16] | `ikenatt_1_4.pcap` |
| IKENATT.1.5 | IKENATT.1.5: Version=0x20 (IKEv2) byte[17] (offset 21 with marker) | `ikenatt_1_5.pcap` |
| IKENATT.1.6 | IKENATT.1.6: ExchangeType=34 (IKE_SA_INIT) byte[18] | `ikenatt_1_6.pcap` |
| IKENATT.1.7 | IKENATT.1.7: NAT-D Notify payloads present in INIT | `ikenatt_1_7.pcap` |
| IKENATT.1.8 | IKENATT.1.8: port 4500 (no port 500) | `ikenatt_1_8.pcap` |

## TLS(`run_tls.py`,端口 443,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| TLS.1.1 | ClientHello Record ContentType=0x16 (Handshake). | `tls_1_1.pcap` |
| TLS.1.2 | SNI extension host_name=api.example.com. | `tls_1_2.pcap` |
| TLS.1.3 | ALPN extension includes 'h2'. | `tls_1_3.pcap` |
| TLS.1.4 | Cipher suite TLS_AES_128_GCM_SHA256 (0x13 0x01) in ClientHello. | `tls_1_4.pcap` |
| TLS.1.5 | TLS 1.2 legacy_version=0x0303 in ClientHello. | `tls_1_5.pcap` |
| TLS.1.6 | Full handshake produces TCP FIN teardown. | `tls_1_6.pcap` |
| TLS.1.7 | TLS 1.0 legacy_version=0x0301 (compat mode). | `tls_1_7.pcap` |
| TLS.1.8 | Alert (close_notify) ContentType=0x15 at end of session. | `tls_1_8.pcap` |

## Shadowsocks(`run_shadowsocks.py`,端口 8388,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SS.1.1 | SOCKS5 greeting VER=0x05 first byte (when socks5_handshake=true). | `ss_1_1.pcap` |
| SS.1.2 | SOCKS5 password auth: greeting + username/password sub-negotiation. | `ss_1_2.pcap` |
| SS.1.3 | SOCKS5 CONNECT request with IPv4 ATYP=0x01. | `ss_1_3.pcap` |
| SS.1.4 | AEAD salt (32 bytes) emitted before chunks (cipher=aes-256-gcm). | `ss_1_4.pcap` |
| SS.1.5 | AEAD chunk: encrypted_len(2B) + payload(N) + tag(16B). | `ss_1_5.pcap` |
| SS.1.6 | HTTP obfuscation: CONNECT header before salt. | `ss_1_6.pcap` |
| SS.1.7 | TCP teardown: FIN-ACK 4-way after data exchange. | `ss_1_7.pcap` |
| SS.1.8 | Multiple AEAD chunks (chunks=3). | `ss_1_8.pcap` |

## VMess(`run_vmess.py`,端口 443,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| VMESS.1.1 | Request Version=0x01 (AEAD) first byte of first up PSH-ACK. | `vmess_1_1.pcap` |
| VMESS.1.2 | Request IV = 16 bytes following the Version byte. | `vmess_1_2.pcap` |
| VMESS.1.3 | Legacy mode: Request Version=0x00 (Legacy) first byte. | `vmess_1_3.pcap` |
| VMESS.1.4 | TCP mode: TCP 3-way handshake before VMess Request. | `vmess_1_4.pcap` |
| VMESS.1.5 | TCP teardown: FIN-ACK at end of session. | `vmess_1_5.pcap` |
| VMESS.1.6 | AddressType=0x02 (Domain) with domain 'example.com'. | `vmess_1_6.pcap` |
| VMESS.1.7 | Heartbeat mode: minimal request with HeaderPad=8. | `vmess_1_7.pcap` |
| VMESS.1.8 | Port=443 in request header (2 bytes big-endian 0x01 0xBB). | `vmess_1_8.pcap` |

## gRPC(`run_grpc.py`,端口 8604,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| GRPC.1.1 | GRPC.1.1: HTTP/2 connection preface magic (24 bytes) | `grpc_1_1.pcap` |
| GRPC.1.10 | GRPC.1.10: client-streaming (N request DATA, last ES=1) | `grpc_1_10.pcap` |
| GRPC.1.11 | GRPC.1.11: bidi-stream (interleaved client/server DATA) | `grpc_1_11.pcap` |
| GRPC.1.12 | GRPC.1.12: large response message (multi-chunk DATA segmentation) | `grpc_1_12.pcap` |
| GRPC.1.13 | GRPC.1.13: error trailers (grpc-status=14 UNAVAILABLE + grpc-message) | `grpc_1_13.pcap` |
| GRPC.1.14 | GRPC.1.14: flow control WINDOW_UPDATE frame (Type=0x08) | `grpc_1_14.pcap` |
| GRPC.1.2 | GRPC.1.2: SETTINGS frame (Type=0x04, byte[3]=0x04 after magic) | `grpc_1_2.pcap` |
| GRPC.1.3 | GRPC.1.3: HEADERS frame Type=0x01 appears somewhere | `grpc_1_3.pcap` |
| GRPC.1.4 | GRPC.1.4: DATA frame gRPC length-prefix (5-byte prefix) | `grpc_1_4.pcap` |
| GRPC.1.5 | GRPC.1.5: trailers grpc-status=0 | `grpc_1_5.pcap` |
| GRPC.1.6 | GRPC.1.6: GOAWAY frame at end (Type=0x07) | `grpc_1_6.pcap` |
| GRPC.1.7 | GRPC.1.7: PING frame (Type=0x06) | `grpc_1_7.pcap` |
| GRPC.1.8 | GRPC.1.8: Multi-call multiplexing (stream IDs 1, 3) | `grpc_1_8.pcap` |
| GRPC.1.9 | GRPC.1.9: server-streaming (1 request ES=1, N response DATA frames ES=0) | `grpc_1_9.pcap` |

## DNS(`run_dns.py`,端口 53,UDP/TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| DNS.1.1 | DNS.1.1: A query -- qtype=1, default TxID=0x1234, qr=0, arcount=0. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.10 | DNS.1.10: TypeAAAA response IPv6 rdata -- 16 bytes. | `b3-dns_1_11.pcap` |
| DNS.1.11 | DNS.1.11: TypeA + IPv6 response_ip rejected by Validate (negative). | `b3-dns_1_11.pcap` |
| DNS.1.12 | DNS.1.12: multi-RR response -- two A records in one Answer section. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.13 | DNS.1.13: CNAME chain -- CNAME RR followed by an A RR. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.14 | DNS.1.14: reverse PTR lookup -- in-addr.arpa query + PTR response. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.15 | DNS.1.15: SRV response -- priority+weight+port+target RDATA. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.16 | DNS.1.16: SOA response -- MName+RName+5x uint32. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.17 | DNS.1.17: NXDOMAIN + SOA in Authority (negative caching). | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.18 | DNS.1.18: DNS over TCP -- 2-byte length prefix + L4 tcp. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.19 | DNS.1.19: multiple questions in one query (QDCOUNT=2). | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.2 | DNS.1.2: AAAA query -- qtype=28. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.3 | DNS.1.3: CNAME response -- qtype=5, rdata=encoded target domain. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.4 | DNS.1.4: MX response -- qtype=15, rdata=2-byte pref + encoded domain. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.5 | DNS.1.5: TXT response -- qtype=16, rdata=length-prefix + text. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.6 | DNS.1.6: Custom TxID -- txid=0xABCD, bytes must be ab cd (NOT 0x1234). | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.7 | DNS.1.7: EDNS0 enabled -- ARCOUNT=1, OPT TYPE=41, CLASS=4096. | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.8 | DNS.1.8: EDNS0 + DO bit -- DO bit set (opt byte = 0x80). | (动态生成,见 `b3-<id>.pcap`) |
| DNS.1.9 | DNS.1.9: TypeA response IPv4 rdata + TxID echo. | `b3-dns_1_11.pcap` |

## mDNS(`run_mdns.py`,端口 5353,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| MDNS.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.6 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.7 |  | (动态生成,见 `b3-<id>.pcap`) |
| MDNS.1.8 |  | (动态生成,见 `b3-<id>.pcap`) |

## DHCP(`run_dhcp.py`,端口 67,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| DHCP.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.6 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.7 |  | (动态生成,见 `b3-<id>.pcap`) |
| DHCP.1.8 |  | (动态生成,见 `b3-<id>.pcap`) |
| — | *run_dhcp_scenarios.py 补充用例* | |
| DHCP.2.1 |  | (动态生成) |
| DHCP.2.2 |  | (动态生成) |
| DHCP.2.3 |  | (动态生成) |
| DHCP.2.4 |  | (动态生成) |
| DHCP.2.5 |  | (动态生成) |
| DHCP.2.6 | Two concurrent DORA flows with distinct xids (multi-client). | (动态生成) |
| DHCP.2.7 | Two concurrent DORA flows with distinct xids (multi-client). | (动态生成) |

## DHCPv6(`run_dhcpv6.py`,端口 547,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| DHCPV6.1.1 | DHCPv6.1.1: SOLICIT msg-type=1, byte[0]=0x01, direction up, dst port 547 | `dhcpv6_1_1.pcap` |
| DHCPV6.1.2 | DHCPv6.1.2: ADVERTISE msg-type=2, byte[0]=0x02 | `dhcpv6_1_2.pcap` |
| DHCPV6.1.3 | DHCPv6.1.3: REQUEST msg-type=3, ServerID auto-added | `dhcpv6_1_3.pcap` |
| DHCPV6.1.4 | DHCPv6.1.4: INFORMATION-REQUEST msg-type=11, byte[0]=0x0B | `dhcpv6_1_4.pcap` |
| DHCPV6.1.5 | DHCPv6.1.5: REPLY msg-type=7, byte[0]=0x07 | `dhcpv6_1_5.pcap` |
| DHCPV6.1.6 | DHCPv6.1.6: transaction-id=0x123456, byte[1:4]=0x123456 | `dhcpv6_1_6.pcap` |
| DHCPV6.1.7 | DHCPv6.1.7: DUID-LLT in ClientID (option 1, type=1) | `dhcpv6_1_7.pcap` |
| DHCPV6.1.8 | DHCPv6.1.8: RELAY-FORW msg-type=12, 34-byte header (hop-count 0 per RFC 8415) | `dhcpv6_1_8.pcap` |
| DHCPV6.2.1 | DHCPv6.2.1: SARR scenario - 4 packets Solicit/Advertise/Request/Reply | `dhcpv6_2_1.pcap` |
| DHCPV6.2.10 | DHCPv6.2.10: Reconfigure scenario - 3 pkts Reconfigure/Renew/Reply | `dhcpv6_2_10.pcap` |
| DHCPV6.2.11 | DHCPv6.2.11: Relay scenario - 4 pkts RELAY-FORW/REPL with inner SARR | `dhcpv6_2_11.pcap` |
| DHCPV6.2.12 | DHCPv6.2.12: SARR NoAddrsAvail - REPLY StatusCode=2 | `dhcpv6_2_12.pcap` |
| DHCPV6.2.2 | DHCPv6.2.2: SARR Rapid Commit - 2 packets Solicit/Reply both with opt14 | `dhcpv6_2_2.pcap` |
| DHCPV6.2.3 | DHCPv6.2.3: Information-Request scenario - 2 pkts, no IA_NA, REPLY has DNS | `dhcpv6_2_3.pcap` |
| DHCPV6.2.4 | DHCPv6.2.4: Renew scenario - 2 pkts Renew/Reply, Renew carries ServerID | `dhcpv6_2_4.pcap` |
| DHCPV6.2.5 | DHCPv6.2.5: Rebind scenario - 2 pkts, Rebind does NOT carry ServerID | `dhcpv6_2_5.pcap` |
| DHCPV6.2.6 | DHCPv6.2.6: Release scenario - 2 pkts, REPLY has StatusCode=0 (Success) | `dhcpv6_2_6.pcap` |
| DHCPV6.2.7 | DHCPv6.2.7: Decline scenario - 2 pkts Decline/Reply | `dhcpv6_2_7.pcap` |
| DHCPV6.2.8 | DHCPv6.2.8: Confirm scenario - 2 pkts, REPLY StatusCode=0 (Success) | `dhcpv6_2_8.pcap` |
| DHCPV6.2.9 | DHCPv6.2.9: Confirm NotOnLink - REPLY StatusCode=4 (NotOnLink) | `dhcpv6_2_9.pcap` |

## SIP(`run_sip.py`,端口 5060,UDP/TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SIP.1.1 | SIP.1.1: INVITE/100/180/200/ACK signaling dialog (5 messages). | `sip_1_1.pcap` |
| SIP.1.10 | SIP.1.10: RTP G.722 (PT=9) media sub-flow. | `sip_1_10.pcap` |
| SIP.1.11 | SIP.1.11: RTP between ACK and BYE (wire ordering). | `sip_1_11.pcap` |
| SIP.1.12 | SIP.1.12: FileSource RTP payload bytes. | `sip_1_12.pcap` |
| SIP.1.13 | SIP.1.13: SIP over IPv6 (EtherType 0x86DD). | `sip_1_13.pcap` |
| SIP.1.14 | SIP.1.14: SDP a=sendonly derives RTP direction 'up'. | `sip_1_14.pcap` |
| SIP.1.15 | SIP.1.15: SDP a=recvonly derives RTP direction 'down' (F1 fix). | `sip_1_15.pcap` |
| SIP.1.16 | SIP.1.16: SDP a=sendrecv defaults to 'up'. | `sip_1_16.pcap` |
| SIP.1.17 | SIP.1.17: Digest 401 challenge + re-REGISTER with Authorization. | `sip_1_17.pcap` |
| SIP.1.18 | SIP.1.18: SUBSCRIBE/NOTIFY event subscription (RFC 6665). | `sip_1_18.pcap` |
| SIP.1.19 | SIP.1.19: re-INVITE with SDP port change. | `sip_1_19.pcap` |
| SIP.1.2 | SIP.1.2: INVITE/100/200/ACK (no 180). | `sip_1_2.pcap` |
| SIP.1.20 | SIP.1.20: SDP with multiple m=audio lines (first wins). | `sip_1_20.pcap` |
| SIP.1.21 |  | `sip_1_21.pcap` |
| SIP.1.22 |  | `sip_1_22.pcap` |
| SIP.1.3 | SIP.1.3: BYE/200 teardown after ACK. | `sip_1_3.pcap` |
| SIP.1.4 | SIP.1.4: CANCEL/200 cancel pending INVITE. | `sip_1_4.pcap` |
| SIP.1.5 | SIP.1.5: REGISTER/200 registration. | `sip_1_5.pcap` |
| SIP.1.6 | SIP.1.6: OPTIONS/200 keepalive. | `sip_1_6.pcap` |
| SIP.1.7 | SIP.1.7: INFO/200 mid-dialog info then BYE/200. | `sip_1_7.pcap` |
| SIP.1.8 | SIP.1.8: re-INVITE session update (two INVITEs). | `sip_1_8.pcap` |
| SIP.1.9 | SIP.1.9: RTP G.711 PCMU (PT=0) media sub-flow between ACK and BYE. | `sip_1_9.pcap` |

## RTSP(`run_rtsp.py`,端口 554,TCP+UDP RTP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| RTSP.1.1 | 完整点播会话: DESCRIBE/200/SETUP×2/200/PLAY/200(emit RTP 20 帧)/TEARDOWN/200,CSeq 1-5 逐帧,RTP 全 down 方向. | `rtsp_1_1.pcap` |
| RTSP.1.2 | OPTIONS/200 能力探测(2 条消息). | `rtsp_1_2.pcap` |
| RTSP.1.3 | RTP-Info 一致性: url=trackID=5, seq/rtptime 匹配首帧, ssrc int32 表示(0x8D991AC7=-1919345977). | `rtsp_1_3.pcap` |
| RTSP.1.4 | Session 签发: SETUP 响应 15 位 hex, PLAY/TEARDOWN 回显. | `rtsp_1_4.pcap` |
| RTSP.1.5 | 用户 CSeq 重同步: cseq=[9,9,10,10] 计数器跳变. | `rtsp_1_5.pcap` |
| RTSP.1.6 | PAUSE/PLAY 续流: 第二次 PLAY RTP-Info seq=第一次+5, frame6 匹配. | `rtsp_1_6.pcap` |
| RTSP.1.7 | 状态码 Reason-Phrase 映射: 453 Not Enough Bandwidth. | `rtsp_1_7.pcap` |
| RTSP.1.8 | 12 方法枚举(24 条消息): DESCRIBE/SETUP/PLAY/TEARDOWN/OPTIONS/PAUSE/GET_PARAMETER/SET_PARAMETER/ANNOUNCE/RECORD/REDIRECT/PLAY_NOTIFY. | `rtsp_1_8.pcap` |
| RTSP.1.9 | IPv6: `DESCRIBE rtsp://[2001:db8::2]/media` 方括号 URI. | `rtsp_1_9.pcap` |
| RTSP.1.10 | 自动 Transport: 请求 client_port=DstPort-DstPort+1, 响应加 server_port=SrcPort-SrcPort+1. | `rtsp_1_10.pcap` |
| RTSP.1.11 | FileSource: RTP 载荷字节来自文件(FrameSize 切块). | `rtsp_1_11.pcap` |
| RTSP.1.12 | media 默认值: Frames=1, FrameSize=160, PT=0(不默认化,PCMU 合法), 端口 5004. | `rtsp_1_12.pcap` |
| RTSP.1.13 | EmitMedia 在 PLAY 请求: RTP 帧在请求后响应前(线上顺序), 响应无自动 RTP-Info. | `rtsp_1_13.pcap` |
| RTSP.1.14 | REDIRECT/PLAY_NOTIFY 服务器主动下发: 自动 down 方向. | `rtsp_1_14.pcap` |
| RTSP.1.15 | 空 dialog: 仅 7 个 TCP 包(3 握手+4 挥手), 无应用载荷. | `rtsp_1_15.pcap` |
| RTSP.1.16 | 响应 Body: 自动 Content-Length + Content-Type: application/sdp. | `rtsp_1_16.pcap` |

## SOCKS5(`run_socks5.py`,端口 1080,TCP + UDP 中继子流)

> 参考 pcap: llcj_pcap/llcj_mirror 系列 dport=1080 24 文件(10 SOCKS4 + 14 SOCKS5, 会话内字节全同构). 信令字节逐帧对照参考 pcap; SOCKS5 无认证会话 = 10 TCP 包(3 握手+4 信令+3 挥手).

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| S.4.1 | SOCKS5 无认证 CONNECT 域名: 10 TCP 包, greeting `05 01 00`/method `05 00`/request `05 01 00 03 0f www.example.com 00 50`/reply `05 00 00 01 00 00 00 00 00 00` 与参考 pcap 逐字节一致, 无数据面. | `socks_4_1.pcap` |
| S.4.2 | SOCKS4 CONNECT + 隧道 HTTP: request `04 01 00 50 5d b8 d8 77 00`/reply `00 5a 00 00 00 00 00 00` 与参考 pcap 一致, 隧道内 GET(up)/HTTP 200(down), Wireshark 启发式识别为 HTTP. | `socks_4_2.pcap` |
| S.4.3 | SOCKS5 用户名密码认证(RFC 1929): greeting `05 01 02`/method `05 02`/auth `01 05 alice 06 s3cret`/auth-resp `01 00`, 12 TCP 包. | `socks_4_3.pcap` |
| S.4.4 | SOCKS5 UDP ASSOCIATE: request CMD=3, reply 后 3 个 UDP 中继包, 每包 = RSV+FRAG+ATYP+ADDR+PORT 头 + 100B 载荷, 方向 down(20.0.0.1→10.0.0.1). | `socks_4_4.pcap` |
| S.4.5 | SOCKS4a 域名: DSTIP=0.0.0.1 + USERID 终止符后直接跟域名(无长度前缀, 0x00 终止). | `socks_4_5.pcap` |
| S.4.6 | 多会话: socks5+socks4 一个 batch 两条独立 flow, 信令互不干扰. | `socks_4_6.pcap` |
| S.8.3 | 转换默认: 未指定 dst_port 时默认 1080(标准代理端口). | `socks_8_3.pcap` |

## RADIUS(`run_radius.py`,端口 1812/1813,UDP)

> 参考 pcap: publicpcap/Radius/ 19 文件 + IPV6/ipv6_radius.pcap. 认证 1812/计费 1813(RFC 2865 §3/RFC 2866 §3). 单 flow = Rounds 次 request(up)/response(down) 交换, response 回显 request ID; 响应 0 = 自动映射(1→2, 4→5, 12→13), code 3/11 无自动映射须显式 response_code.

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| 7.1 | Access-Request/Accept: ID=0x53 + portion_Radius.pcap 的 13 个真实属性(含 Juniper(4874) VSA 55 的 82B 值/VSA 56 "f49f.f3dc.90dc "/VSA 57 IP, CUI `00`, NAS-Port 29364130) → 报文 239B `01 53 00 ef`, 响应 20B `02 53 00 14`, Wireshark 解码 User-Name "enet"/NAS-Port 29364130/Service-Type 2/NAS-Identifier "CUG-MX960-RE1". | `radius_7_1.pcap` |
| 7.2 | Accounting-Request/Response: ID=0 + radius_one.pcap 的 8 个真实属性(User-Name "C1000001@domain", Acct-Status-Type 1, 20942 厂商 VSA 120/121) → 报文 154B `04 00 00 9a`, 响应 20B `05 00 00 14`. | `radius_7_2.pcap` |
| 7.4 | IPv6 多轮: 3ffe::200:ff:fe00:71 ↔ 3ffe::200:ff:fe00:7, 3 轮 6 帧, EtherType 0x86DD, codes 1/2 交替, IDs 2/2/3/3/4/4(每轮递增+回显), 与 ipv6_radius.pcap 同构. | `radius_7_4.pcap` |
| 8.6 | 转换默认: 未指定 dst_port 时认证默认 1812. | `radius_8_6.pcap` |
| 8.7 | 转换默认(Code 感知): code=4 未指定 dst_port 时计费默认 1813. | `radius_8_7.pcap` |
| 8.8 | 转换拒绝: 非法协议名 type=radiusx → create_batch 报 invalid type(任务未创建). | — |

## LDAP(`run_ldap.py`,端口 389,TCP)

> 参考 pcap: llcj_mirror/ 24 文件 dport=389(AD RootDSE 会话: searchRequest 351B / searchResDone 23B / unbind 12B 逐字节复现; SASL GSS-API bind 密文不可复现, planner 输出 simple 认证普通 BER). BER 编码沿参考 pcap 的 AD 客户端习惯: 构造值恒 0x84+4B 长形式, 原始值短形式; equalityMatch [3] 是隐式标签直接承载 attributeDescription+assertionValue(无嵌套 SEQUENCE). 单 flow = 一个 TCP 会话: 握手 → 每轮 bind→search 交换(PSH-ACK 数据段) → 末轮后一次 unbind → 4-way 拆除; 每轮 messageID = Base+3r(bind)/+3r+1(search)/+3r+2(unbind).

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| 7.1 | RootDSE 查询逐字节: message_id_base=2422+time_limit=120 → searchRequest(messageID 2423) 351B 与参考 pcap 完全一致(15 属性), Wireshark 解出 bindRequest(2422) simple/bindResponse success/searchRequest "<ROOT>" baseObject/searchResEntry/searchResDone success/unbindRequest(2424). | `ldap_7_1.pcap` |
| 7.2 | bind simple 交换: bind_dn="cn=admin,dc=example,dc=com"+bind_password="secret" → bindRequest 含 `02 01 03 04 1a 636e3d... 80 06 736563726574`, bindResponse resultCode 0. | `ldap_7_2.pcap` |
| 7.3 | searchResEntry(op 0x64)+searchResDone(op 0x65) 回显同一 messageID, entry 每条 PartialAttribute type=name 且 SET 内含同名值. | `ldap_7_3.pcap` |
| 7.4 | 多轮信令面: Rounds=3 → 23 帧(7 TCP 头尾+16 应用), messageID 序列 [1,1,2,2,2,4,4,5,5,5,7,7,8,8,8,9], op 计数 0x60/0x61/0x63/0x64/0x65 ×3 + 0x42 ×1. | `ldap_7_4.pcap` |
| 7.5 | IPv6 + TCP: 3ffe::200:ff:fe00:71 ↔ 3ffe::200:ff:fe00:7, EtherType 0x86DD, LDAP payload 0x30 开头. | `ldap_7_5.pcap` |
| 7.6 | equality filter: filter_type=equality+cn=admin → searchRequest 含 `a3 84 00 00 00 0b 04 02 636e 04 05 61646d696e`, Wireshark 解出 Filter: (cn=admin) attributeDesc: cn assertionValue: admin. | `ldap_7_6.pcap` |
| 7.7 | 认证失败: result_code=49 → bindResponse/searchResDone 含 `0a 01 31`, Wireshark 显示 invalidCredentials. | `ldap_7_7.pcap` |
| 8.1 | 转换默认: 未指定 dst_port 时默认 389. | `ldap_8_1.pcap` |
| 8.2 | 转换接受: version=2. | `ldap_8_2.pcap` |
| 8.3 | 转换接受: search_scope=2. | `ldap_8_3.pcap` |
| 8.4 | 转换接受: filter_type=equality+filter_value. | `ldap_8_4.pcap` |
| 8.5 | 转换拒绝: filter_type=substring → 任务 failed(所有 flow failed validation/planning). | — |
| 8.6 | 转换拒绝: search_scope=5 → 任务 failed. | — |
| 8.7 | 转换拒绝: version=1 → 任务 failed. | — |
| 8.8 | 转换拒绝: 非法协议名 type=ldapx → create_batch 报 invalid type. | — |

## VNC(`run_vnc.py`,端口 5900,TCP)

> 参考 pcap: llcj_pcap/IP-TCP-10.3.1.143-20.3.1.143-1160-5901-1149-1631-69054-2262354.pcap(TightVNC server,RFC 6143). 默认配置逐字节复现参考: Tight 握手 13 条(版本/SecurityTypes `02 02 10`/tunnel/authCaps/选认证/挑战/响应/结果/share/ServerInit 38B/Interaction Caps 184B 11 条记录)、6×KeyEvent、SetPixelFormat、SetEncodings 64B(15 编码)、FBU request 10B、XCursor blob 82B + Hextile rect 头. 单 flow = 握手 → 客户端消息 → 首轮前 InitialFBU(2 rect: XCursor + 全屏 Hextile) → 每轮 PointerEvent + FBU → 末轮后增量 FBU request → 4-way 拆除. SecurityType 列表恒为 [count][types] 两字节形式(RFC 6143 §7.2.1);XCursor blob = 6B fg/bg + 38B 1bpp 位图 + 38B mask,缺 2B 位图行会导致 Wireshark 按段解析 FBU(1894×"Unknown server message type").

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| 7.1 | 默认 Tight 握手 13 条逐字节(版本/SecurityTypes `02 02 10`/tunnel/authCaps/选认证/挑战/响应/结果/share/ServerInit 38B/Caps 184B),Wireshark 全程 0 malformed、0 "Unknown server message type",2157 段全部重组为 FramebufferUpdate. | `vnc_7_1.pcap` |
| 7.2 | 客户端消息: 6×KeyEvent(04 00…pad 00 00)+ SetPixelFormat + SetEncodings 64B + FBU request 10B(逐字节). | `vnc_7_2.pcap` |
| 7.3 | InitialFBU: 00 00 00 02 + XCursor rect 头(00 00 00 01 00 0c 00 13 ff ff ff 10)+ 82B blob + Hextile rect 头(00 00 00 00 04 00 03 00 00 00 00 05);tshark 解出 Rectangle#1 XCursor/Rectangle#2 Hextile 1024×768. | `vnc_7_3.pcap` |
| 7.4 | Rounds=3: 3×PointerEvent(05 00 01 fb 01 40)+ 4×FBU(每 2 rect)+ 末轮增量 FBU request(03 01 …). | `vnc_7_4.pcap` |
| 7.5 | security_type=2(VNC Auth): 无 tunnel/caps,`01 02` 单类型列表 → 挑战-响应 → 结果 00 00 00 00 → share → ServerInit,数据面照常. | `vnc_7_5.pcap` |
| 7.6 | security_type=1(None): `01 01` → 无挑战,直接结果 → ServerInit. | `vnc_7_6.pcap` |
| 7.7 | auth_result=1: 结果 00 00 00 01 + reason "bad password"(`00 00 00 01 00 00 00 0b 62 61 64 …`),无 ServerInit. | `vnc_7_7.pcap` |
| 8.1 | 转换默认: 未指定 dst_port 时默认 5900. | `vnc_8_1.pcap` |
| 8.2 | 转换接受: security_type=2. | `vnc_8_2.pcap` |
| 8.3 | 转换接受: width=800/height=600/server_name="test" → ServerInit 含 03 20 02 58 + "test". | `vnc_8_3.pcap` |
| 8.4 | 转换接受: key_events=[{down:1,key:97}] → KeyEvent `04 01 00 00 00 00 00 61`(down 数字布尔 1 生效,修复 getBool). | `vnc_8_4.pcap` |
| 8.5 | 转换拒绝: security_type=3 → 任务 failed(error 含 "security type"). | — |
| 8.6 | 转换拒绝: auth_result=5 → 任务 failed. | — |
| 8.7 | 转换拒绝: encodings=["abc"] → 任务 failed(error 含 "encoding"). | — |
| 8.8 | 转换拒绝: 非法协议名 type=vncx → create_batch 报 invalid type. | — |

## PPTP(`run_pptp.py`,端口 1723,TCP 控制面 + GRE proto 47 数据面)

> 参考 pcap: llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-1260-980.pcap(PNS=客户端 49194,PAC=服务器 1723,RFC 2637). 默认配置逐字节复现参考: 控制面 14 条消息(SCCRQ 156B/SCCRP 156B/OCRQ 168B 含 subaddress 垃圾字节 `01 1f 42 3a 64 84 e9 4c af 72 89 2a 29 b1 d3 ab`/OCRP 32B/SLI 24B×5/CCRQ 16B/CCRQ+CCDN 合并单段 164B/CCDN 148B/StopRQ/StopRP),含参考实现怪癖(PAC 侧 SLI 的 peer call id = PNS 侧 TCP 源端口;合并段;CCDN 双向携带 PNS call id). 数据面 PPTP 增强 GRE 16B 头(flags 0x3081 = K|S|A+ver1,proto 0x880B,Key 高 16=payload 长度低 16=对端 Call ID,32 位 seq/ack)封装 PPP 帧(FF 03 + 0x0021 + 内层 IPv4+UDP),PNS 侧帧先发(seq 0..N-1,ack 0)再 PAC 侧帧(ack=N-1). CallID=0xa9c0 恒为 PNS 侧 ID、PeerCallID=0x35c9 恒为 PAC 侧 ID,role 只翻转方向. 场景模板: full(全部)/control_only(无 GRE)/tunnel_only(仅 OCRQ/OCRP)/data_only(仅 GRE);帧计数(data_frames/down_data_frames/sli_count)显式 0 = 合法 0 帧.

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| 7.1 | 默认 full: 14 条控制消息逐字节(上 7: SCCRQ/OCRQ/SLI×3/合并 164B/StopRQ;下 7: SCCRP/OCRP/SLI×2/CCRQ/CCDN/StopRP),tshark `-Y pptp` 识别 14 帧 0 malformed. | `pptp_7_1.pcap` |
| 7.2 | GRE 数据面: 3 up(Key 低 16=35c9,seq 0,1,2,ack 0)+ 2 down(Key 低 16=a9c0,seq 0,1,ack 2);flags 0x3081/Key 高 16=32=payload 长/PPP 头 ff 03 00 21/内层 10.10.10.1→10.10.10.2 UDP;Wireshark 解出 Enhanced GRE v1 + Payload Length 32 + Call ID. | `pptp_7_2.pcap` |
| 7.4 | Calls=2: 2 组 OCRQ(a9c0/a9c1)/OCRP(35c9/35ca)/SLI×5/CCRQ/CCDN;GRE Call ID 递增(up 35c9×3+35ca×3,down a9c0×2+a9c1×2). | `pptp_7_4.pcap` |
| 7.5a | control_only: 同 7.1 控制面 14 条,0 GRE 帧. | `pptp_7_5a.pcap` |
| 7.5b | tunnel_only: 仅 9 条(SCCRQ/SCCRP/OCRQ/OCRP/CCRQ/合并/CCDN/StopRQ/StopRP),无 SLI 无数据. | `pptp_7_5b.pcap` |
| 7.5c | data_only: 仅 5 GRE 帧,无 TCP 控制面. | `pptp_7_5c.pcap` |

## HTTP(`run_h.py`,端口 80,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| H1.1 | POST + Content-Encoding: gzip (request body=40B) | `H/H1_1.pcap` |
| H1.2 | gzip + ~11KB body | `H/H1_2.pcap` |
| H1.3 | 损坏 gzip (解压失败路径) | `H/H1_3.pcap` |
| H1.4 | response Content-Encoding: gzip | `H/H1_4.pcap` |
| H2.1 | MSS=536 (RFC 879 min) | `H/H2_1.pcap` |
| H2.2 | MSS=1460 (default) | `H/H2_2.pcap` |
| H2.3 | MSS=8960 (jumbo) | `H/H2_3.pcap` |
| H2.4 | MSS=65535 (uint16 max) | `H/H2_4.pcap` |
| H2.5 | MSS=0 -> default 1460 | `H/H2_5.pcap` |
| H2.6 | payload=10000, mss=1460 | `H/H2_6.pcap` |
| H2.7 | payload=1460, mss=1460 | `H/H2_7.pcap` |
| H2.8 | payload=100, mss=1460 | `H/H2_8.pcap` |
| H2.9 | MSS=100 -> 拒绝 (min 536) | `H/H2_9.pcap` |
| H2.10 | MSS=70000 -> 拒绝 (max 65535) | `H/H2_10.pcap` |
| H3.1 | chunked 响应 (Transfer-Encoding: chunked) | `H/H3_1.pcap` |
| H3.2 | chunked 请求 (request side) | `H/H3_2.pcap` |
| H3.3 | chunked multi-chunk (chunk_size=30, body=100B) | `H/H3_3.pcap` |
| H3.4 | pipelined 3 请求 (all reqs before resps) | `H/H3_4.pcap` |
| H3.5 (PUT) | method=PUT | `H/H3_5_PUT.pcap` |
| H3.5 (DELETE) | method=DELETE | `H/H3_5_DELETE.pcap` |
| H3.5 (HEAD) | method=HEAD | `H/H3_5_HEAD.pcap` |
| H3.5 (OPTIONS) | method=OPTIONS | `H/H3_5_OPTIONS.pcap` |
| H3.6 (301) | status=301 Moved Permanently | `H/H3_6_301.pcap` |
| H3.6 (404) | status=404 Not Found | `H/H3_6_404.pcap` |
| H3.6 (500) | status=500 Internal Server Error | `H/H3_6_500.pcap` |
| H3.7a | Content-Type JSON auto-sniff | `H/H3_7a.pcap` |
| H3.7b | Content-Type form-urlencoded (user) | `H/H3_7b.pcap` |
| H3.8 | Authorization + Cookie header | `H/H3_8.pcap` |

## SMTP(`run_smtp_v2.py`,端口 25,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SMTP.1.1 | HELO/EHLO greeting - client HELO + 250 server response. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.2 | MAIL FROM / RCPT TO - basic envelope commands. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.3 | QUIT command + 221 server response - minimal session. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.4 | QUIT command + 221 server response - minimal session. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.5 | AUTH PLAIN one-shot (RFC 4954) - AUTH PLAIN <b64> -> 235 success. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.6 | AUTH LOGIN 3-step (RFC 4954) - AUTH LOGIN -> 334 user prompt -> b64(user) -> 334 pass prom | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.7 | STARTTLS upgrade - EHLO advertises STARTTLS, then STARTTLS -> 220 Ready. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.1.8 | Multiple recipients - one MAIL FROM + three RCPT TO + DATA + QUIT. | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.2.1 | HTML body + single base64 attachment (multipart/mixed). | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.2.2 | HTML body + single base64 attachment (multipart/mixed). | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.2.3 | Multiple attachments (multipart/mixed, 3 parts). | (动态生成,见 `b3-<id>.pcap`) |
| SMTP.2.4 | Large attachment triggering TCP segmentation. | (动态生成,见 `b3-<id>.pcap`) |

## IMAP(`run_imap_v2.py`,端口 143,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| IMAP.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.6 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.7 |  | (动态生成,见 `b3-<id>.pcap`) |
| IMAP.1.8 |  | (动态生成,见 `b3-<id>.pcap`) |
| — | *run_imap_mime.py 补充用例* | |
| IMAP.2.1 |  | (动态生成) |
| IMAP.2.2 |  | (动态生成) |
| IMAP.2.3 |  | (动态生成) |
| IMAP.2.4 |  | (动态生成) |
| IMAP.2.5 |  | (动态生成) |
| imap_2_1 | FETCH simple text email via mime_body | (动态生成) |

## POP3(`run_pop3_v2.py`,端口 110,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| POP3.1.1 | USER/PASS authentication. | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.2 | STAT (message count). | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.3 | LIST (message sizes) - multi-line response. | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.4 | RETR (retrieve message) - via EmitMailDrop. | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.5 | DELE (delete message). | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.6 | QUIT. | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.7 | APOP authentication (RFC 1939 §6). | (动态生成,见 `b3-<id>.pcap`) |
| POP3.1.8 | TOP (preview headers) - multi-line response. | (动态生成,见 `b3-<id>.pcap`) |
| — | *run_pop3_mime.py 补充用例* | |
| POP3.1.10 | RETR multipart/mixed email with base64 attachment. | (动态生成) |
| POP3.1.11 | Multi-session: RETR 1 -> RETR 2 -> DELE 1 -> QUIT. | (动态生成) |
| POP3.1.12 | Large mail (body > MSS) triggers TCP segmentation. | (动态生成) |
| POP3.1.13 | TOP command via EmitTop (headers + first N body lines). | (动态生成) |
| POP3.1.9 | RETR plain-text email via EmitMailDrop. | (动态生成) |

## SSH(`run_ssh.py`,端口 22,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SSH.1.1 | 用例 1.1.1: ServerVersion=SSH-2.0-OpenSSH_8.9 | `ssh_1_1.pcap` |
| SSH.1.10 | 用例 1.10: shell 交互会话 (scenario=shell, pty-req + shell). | `ssh_1_10.pcap` |
| SSH.1.11 | 用例 1.11: 密码认证失败重试 (scenario=auth_fail_retry). | `ssh_1_11.pcap` |
| SSH.1.12 | 用例 1.12: 公钥认证 (scenario=publickey, probe+signed). | `ssh_1_12.pcap` |
| SSH.1.13 | 用例 1.13: 长输出多包 (scenario=long_output, multi CHANNEL_DATA + stderr). | `ssh_1_13.pcap` |
| SSH.1.14 | 用例 1.14: PTY + exec 会话 (scenario=pty-exec, pty-req + exec). | `ssh_1_14.pcap` |
| SSH.1.2 | 用例 1.1.4: ClientVersion=SSH-2.0-trafficgen_1.0 | `ssh_1_2.pcap` |
| SSH.1.3 | 用例 1.3.1: KEXINIT message_type=20 (0x14) | `ssh_1_3.pcap` |
| SSH.1.4 | 用例 1.4.1: NEWKEYS message_type=21 (0x15) | `ssh_1_4.pcap` |
| SSH.1.5 | 用例 1.9.1: USERAUTH_REQUEST method=none | `ssh_1_5.pcap` |
| SSH.1.6 | 用例 1.11.1: CHANNEL_OPEN type=session | `ssh_1_6.pcap` |
| SSH.1.7 | CHANNEL_DATA 完整会话 | `ssh_1_7.pcap` |
| SSH.1.8 | 用例 1.17.1: DISCONNECT + TCP FIN 拆除 | `ssh_1_8.pcap` |
| SSH.1.9 | 用例 1.9: 完整 exec 会话 (scenario=exec). | `ssh_1_9.pcap` |

## Telnet(`run_telnet.py`,端口 23,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| TELNET.1.1 | NVT CR LF line ending - alice data emits 0x0D 0x0A | `telnet_1_1.pcap` |
| TELNET.1.2 | IAC NOP (241) - bytes 0xFF 0xF1 | `telnet_1_2.pcap` |
| TELNET.1.3 | IAC WILL SGA (3) - bytes 0xFF 0xFB 0x03 | `telnet_1_3.pcap` |
| TELNET.1.4 | SB NAWS 80x24 - bytes 0xFF 0xFA 0x1F 0x00 0x50 0x00 0x18 0xFF 0xF0 | `telnet_1_4.pcap` |
| TELNET.1.5 | SB TTYPE IS xterm | `telnet_1_5.pcap` |
| TELNET.1.6 | Complete login sequence - login/password/exit appear in payload | `telnet_1_6.pcap` |
| TELNET.1.7 | Binary mode 0xFF escaping - 3 0xFF bytes emit 6 bytes. | `telnet_1_7.pcap` |
| TELNET.1.8 | Command exec 'ls -la' - verify payload contains 'ls' | `telnet_1_8.pcap` |
| TELNET.1.9 | NAWS negotiation - will option=31 + do option=31 + naws cols=80 rows=24 | `telnet_1_9.pcap` |
| TELNET.2.1 | Full negotiation + login + exec + logout session via Scenario field. | `telnet_2_1.pcap` |
| TELNET.2.2 | Authentication failure: wrong password -> 'Login incorrect' + re-prompt. | `telnet_2_2.pcap` |
| TELNET.2.3 | Multi-command exec: 3 commands each appear with CRLF. | `telnet_2_3.pcap` |
| TELNET.2.4 | Long output: server response > MSS -> multiple PSH-ACK segments. | `telnet_2_4.pcap` |
| TELNET.2.5 | Option rejection: DONT (FF FE) and WONT (FF FC) refusal bytes appear. | `telnet_2_5.pcap` |
| TELNET.2.6 | SYNCH signal: IAC IP (FF F4) + IAC DM (FF F2) appear in the stream. | `telnet_2_6.pcap` |

## RDP(`run_rdp.py`,端口 3389,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| RDP.1.1 | TPKT Version=0x03 - first byte of TCP application payload | `rdp_1_1.pcap` |
| RDP.1.2 | X.224 CR Code=0xE0 - Connection Request PDU | `rdp_1_2.pcap` |
| RDP.1.3 | Negotiation Request requestedProtocols=0x00000001 (PROTOCOL_RDP) | `rdp_1_3.pcap` |
| RDP.1.4 | Client Core Data version=0x00080007 (RDP 8.0) - LE 07 00 08 00 | `rdp_1_4.pcap` |
| RDP.1.5 | Client Core Data desktopWidth=1920 - LE 80 07 | `rdp_1_5.pcap` |
| RDP.1.6 | Client Core Data colorDepth=5 (32bpp) - LE 05 00 | `rdp_1_6.pcap` |
| RDP.1.7 | Client Info PDU userName=Administrator (UTF-16LE per MS-RDPBCGR §2.2.1.11) | `rdp_1_7.pcap` |
| RDP.1.8 | MCS Attach-User Confirm Initiator=1001 - PER encoded 0x03 0xE9 | `rdp_1_8.pcap` |
| RDP.2.1 | Full session scenario - MCS Connect-Initial ASN.1 tag (0x7F 0x65) present | `rdp_2_1.pcap` |
| RDP.2.10 | CLIPRDR scenario - cliprdr Channel-Join (ChannelId=1004) present | `rdp_2_10.pcap` |
| RDP.2.11 | RDPDR scenario - rdpdr Channel-Join (ChannelId=1004) + device list present | `rdp_2_11.pcap` |
| RDP.2.2 | Full session scenario - MCS Connect-Response ASN.1 tag (0x7F 0x66) present | `rdp_2_2.pcap` |
| RDP.2.3 | Full session scenario - Erect-Domain Request (0x04) present | `rdp_2_3.pcap` |
| RDP.2.4 | Multi-channel scenario - 5 Channel-Join Requests (MCS 0x38) present | `rdp_2_4.pcap` |
| RDP.2.5 | Bitmap update scenario - FastPath Output updateCode=0x01 (Bitmap) present | `rdp_2_5.pcap` |
| RDP.2.6 | Input events scenario - FastPath Input keyboard event present | `rdp_2_6.pcap` |
| RDP.2.7 | Channel-join failure scenario - one Channel-Join Confirm result=4 present | `rdp_2_7.pcap` |
| RDP.2.8 | Disconnect scenario - MCS Disconnect Provider Ultimatum (0xC0 0x80) present | `rdp_2_8.pcap` |
| RDP.2.9 | Full session scenario - X.224 CR + CC + MCS Connect-Initial sequence on wire | `rdp_2_9.pcap` |

## MySQL(`run_mysql.py`,端口 3306,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| MYSQL.1.1 | Login request (HandshakeResponse41): up packet body contains username 'root'. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.2 | Login request (HandshakeResponse41): up packet body contains username 'root'. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.3 | COM_QUERY (0x03) SELECT 1 -> up command body = 0x03 + 'SELECT 1', down OK reply. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.4 | COM_QUIT (0x01) -> up command body = 1 byte 0x01. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.5 | COM_PING (0x0e) -> up command body = 0x0e, down OK reply. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.6 | COM_INIT_DB (0x02) + database name 'test' -> body = 0x02 + 'test'. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.7 | Result set with rows: COM_QUERY returns column_count + col_defs + EOF + rows + EOF. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.1.8 | Error packet: COM_QUERY 'INVALID SQL' -> ERR(1064 #HY000 syntax error). | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.1 | Full business session: handshake + login + SET NAMES + SELECT + INSERT + COM_QUIT. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.2 | Prepared statement flow: COM_STMT_PREPARE + COM_STMT_EXECUTE + COM_STMT_CLOSE. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.3 | Transaction: BEGIN + INSERT + COMMIT with status flags. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.4 | Custom error: ERR(1062 duplicate key 23000). | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.5 | Custom error: ERR(1146 no table 42S02). | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.6 | Multi-type result set: int + string + datetime + tiny. | (动态生成,见 `b3-<id>.pcap`) |
| MYSQL.2.7 | Large result set: 20 rows with 2 columns. | (动态生成,见 `b3-<id>.pcap`) |

## PostgreSQL(`run_postgresql.py`,端口 5432,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| PG.1.1 | StartupMessage: 4-byte length + protocol_version + user=alice\0. | `pg_1_1.pcap` |
| PG.1.10 | Transaction full cycle: BEGIN -> SELECT -> COMMIT with status flips. | `pg_1_10.pcap` |
| PG.1.11 | ErrorResponse: standalone 'error' op emits E with SQLSTATE 42P01. | `pg_1_11.pcap` |
| PG.1.12 | Query with ErrorFields inside transaction: status flips to 'E'. | `pg_1_12.pcap` |
| PG.1.13 | COPY large data: 100 rows × 100 bytes, segmented by MSS. | `pg_1_13.pcap` |
| PG.1.14 | Multi-type RowDescription: SELECT with mixed column types. | `pg_1_14.pcap` |
| PG.1.15 | LISTEN/NOTIFY: listen ch + async notification push. | `pg_1_15.pcap` |
| PG.1.16 | Large result set: row_count=50 + multi-column SELECT. | `pg_1_16.pcap` |
| PG.1.2 | ReadyForQuery (Z) message: type byte 0x5A + length 0x00 0x00 0x00 0x05 + status 'I'. | `pg_1_2.pcap` |
| PG.1.3 | Terminate (X) message: 1 byte 0x58 + length 0x00 0x00 0x00 0x04. | `pg_1_3.pcap` |
| PG.1.4 | Terminate (X) message: 1 byte 0x58 + length 0x00 0x00 0x00 0x04. | `pg_1_4.pcap` |
| PG.1.5 | AuthenticationOk (R) message: type byte 0x52 + sub-type 0x00000000. | `pg_1_5.pcap` |
| PG.1.6 | MD5 auth challenge: server sends R + sub=5 + 4-byte salt. | `pg_1_6.pcap` |
| PG.1.7 | Extended Query: Parse + Bind + Describe + Execute + Sync. | `pg_1_7.pcap` |
| PG.1.8 | Full session: handshake + startup + auth + query + terminate produces many packets. | `pg_1_8.pcap` |
| PG.1.9 | Multi-statement query: SELECT 1; SELECT 2 produces 2 T+D+C + final Z. | `pg_1_9.pcap` |

## Redis(`run_redis.py`,端口 6379,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| REDIS.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.6 | REDIS.2.1 - Complete business session: AUTH->SELECT->SET->GET-> | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.7 | REDIS.2.1 - Complete business session: AUTH->SELECT->SET->GET-> | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.1.8 | REDIS.2.1 - Complete business session: AUTH->SELECT->SET->GET-> | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.1 | REDIS.2.1 - Complete business session: AUTH->SELECT->SET->GET-> | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.2 | REDIS.2.2 - Hash data structure: HSET/HGET/HGETALL/HDEL/HLEN. | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.3 | REDIS.2.3 - Set data structure: SADD/SMEMBERS/SCARD/SISMEMBER/SREM. | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.4 | REDIS.2.4 - Sorted Set: ZADD/ZRANGE WITHSCORES/ZSCORE/ZRANK/ZREM. | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.5 | REDIS.2.5 - Pub/Sub complete: SUBSCRIBE + server message push + | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.6 | REDIS.2.6 - Transaction MULTI/EXEC with +QUEUED replies. | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.7 | REDIS.2.7 - Error paths: WRONGPASS + unknown command + WRONGTYPE. | (动态生成,见 `b3-<id>.pcap`) |
| REDIS.2.8 | REDIS.2.8 - Large value: 100KB GET reply triggers MSS segmentation | (动态生成,见 `b3-<id>.pcap`) |

## SNMP(`run_snmp.py`,端口 161,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SNMP.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.6 | v3 GetRequest with HMAC-MD5 auth + engineID. | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.7 | v3 GetRequest with HMAC-MD5 auth + engineID. | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.1.8 | v3 GetRequest with HMAC-MD5 auth + engineID. | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.2.1 | v3 GetRequest with HMAC-MD5 auth + engineID. | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.2.2 | v3 GetRequest noAuth (discovery, empty userName). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.2.3 | v3 GetRequest auth+priv (SHA-1 + AES-128). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.3.1 | v1 GetRequest (version=0, community='private'). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.3.2 | v1 GetNextRequest (version=0). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.3.3 | v1 SetRequest (version=0). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.3.4 | v1 TrapV1 with configurable enterprise + agent_addr + generic + specific + timestamp. | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.1 | GetBulk with multiple varbinds (non-repeaters=2, max-repetitions=5). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.2 | Response with noSuchObject exception varbind (0x80). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.3 | Response with noSuchInstance exception varbind (0x81). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.4 | Response with endOfMibView exception varbind (0x82). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.5 | Response with tooBig error status (error-status=1). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.6 | Response with genErr error status + error-index (error-status=5). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.7 | Response with noAccess error status (error-status=6). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.8 | Multi-varbind GetRequest (3 OIDs). | (动态生成,见 `b3-<id>.pcap`) |
| SNMP.4.9 | Multi-varbind Response (mixed types: OCTET STRING + TimeTicks + INTEGER). | (动态生成,见 `b3-<id>.pcap`) |

## Syslog(`run_syslog.py`,端口 514,UDP/TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SYSLOG.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.4 | Fetch UDP payloads from the first flow and assert count + decode text. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.5 | Fetch UDP payloads from the first flow and assert count + decode text. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.6 | Fetch UDP payloads from the first flow and assert count + decode text. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.7 | Fetch UDP payloads from the first flow and assert count + decode text. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.1.8 | Fetch UDP payloads from the first flow and assert count + decode text. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.1 | Multi-payload: per-message StructuredData incrementing sequenceId. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.10 | Structured-data: PARAM-VALUE escaping (quote/backslash/bracket). | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.11 | Multi-payload BSD per-message | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.2 | Multi-payload: per-message StructuredData incrementing sequenceId. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.3 | Multi-payload: per-message MsgID variation. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.4 | Multi-payload: per-message MsgHasBOM variation (ASCII no BOM + UTF-8 with BOM). | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.5 | Multi-payload: per-message Timestamp variation. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.6 | Structured-data structured form: {id, parameters} map -> SD element. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.7 | Structured-data structured form: {id, parameters} map -> SD element. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.8 | Structured-data: SD-ID with PEN via structured form. | (动态生成,见 `b3-<id>.pcap`) |
| SYSLOG.2.9 | Structured-data: multi-param SD with deterministic (sorted) key order. | (动态生成,见 `b3-<id>.pcap`) |

## SSDP(`run_ssdp.py`,端口 1900,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| SSDP.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.6 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.7 |  | (动态生成,见 `b3-<id>.pcap`) |
| SSDP.1.8 |  | (动态生成,见 `b3-<id>.pcap`) |

## NTP(`run_ntp.py`,端口 123,UDP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| NTP.1.1 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.2 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.3 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.4 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.5 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.6 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.7 |  | (动态生成,见 `b3-<id>.pcap`) |
| NTP.1.8 |  | (动态生成,见 `b3-<id>.pcap`) |

## FTP(`run_c1.py`,端口 21,TCP)

| 用例 ID | 描述 | pcap 文件 |
|---------|------|-----------|
| C1.1 | Control plane only: USER/PASS/TYPE/QUIT, no data_channel. | `c1-1.pcap` |
| C1.10 | TYPE A ASCII command. | `c1-10.pcap` |
| C1.11 | Multi-command session: USER/PASS/TYPE I/CWD /,PASV,RETR,QUIT all generated. | `c1-11.pcap` |
| C1.12 | QUIT closes control plane: FIN-ACK teardown. | `c1-12.pcap` |
| C1.13 | PASV port parsing: 227 response yields port p1*256+p2 = 195*256+80 = 50000. | `c1-13.pcap` |
| C1.14 | PORT command port parsing: 78,17 -> 19985 (78*256+17). | `c1-14.pcap` |
| C1.15 | PORT case-insensitive (lowercase 'port'). | `c1-15.pcap` |
| C1.16 | FTP over IPv6: EtherType 0x86DD, IPv6 src/dst. | `c1-16.pcap` |
| C1.17 | Data packets land between 150 and 226 (order in wire). | `c1-17.pcap` |
| C1.18 | FileSource: data payload bytes come from PayloadCache via filesystem. | `c1-18.pcap` |
| C1.19 | ABOR: abort mid-transfer. abort_after_bytes truncates data channel to 200 bytes. | `c1-19.pcap` |
| C1.2 | Active mode RETR: server SYN from port 20. | `c1-2.pcap` |
| C1.20 | Multi-file: two RETR with separate PASV negotiations + distinct data ports. | `c1-20.pcap` |
| C1.21 | Auth failure: USER/PASS -> 530 (not logged in), no 230 success. | `c1-21.pcap` |
| C1.22 | NLST: name list via data channel (bare filenames, no attributes). | `c1-22.pcap` |
| C1.3 | Active mode STOR: client -> server data flow. | `c1-3.pcap` |
| C1.4 | Passive mode RETR: client SYN to server high port. | `c1-4.pcap` |
| C1.5 | Passive mode STOR. | `c1-5.pcap` |
| C1.6 | LIST active mode: data flow contains directory listing. | `c1-6.pcap` |
| C1.7 | LIST passive mode. | `c1-7.pcap` |
| C1.8 | Large file fragmentation: 10000 bytes split across MSS=1460 segments. | `c1-8.pcap` |
| C1.9 | TYPE I binary command. | `c1-9.pcap` |

---

**合计:约 426 个用例,覆盖 33 个协议(含 FTP/HTTP/TCP/UDP 基础)。**

## 说明
- **隧道内层 IP**:`openvpn_2_*`/`wg_2_*`/`l2tp_2_*`/`ike_2_*` 承载内层 IPv4/IPv6 双层封装。
- **多会话/认证全流程**:SSH/RDP/Telnet 的 `scenario` 用例、SIP Digest 401/407、邮件 AUTH。
- **邮件 MIME**:`smtp_2_*`/`imap_2_*`/`pop3_1_9+` 含 multipart 附件+base64。
- **DHCP/DHCPv6 交互**:`dhcp_2_*`(DORA)/`dhcpv6_2_*`(SARR/Renew/Relay)自动对话。
- **判定为非 bug(场景/缺 dissector)**:SOCKS5(8388 需 Decode-As)、VMess(无 dissector+加密随机字节)、NGAP(SCTP 38412 误触发,通用 SCTP 测试已改 12346)。