# #137 openvpn（OpenVPN）设计契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）
> 日期：2026-09-29
> 规范基线：OpenVPN `ssl_pkt.h`/`ssl_pkt.c`（opcode、key-id、控制/数据包布局）、Wireshark `packet-openvpn.c`（可观察字段）、RFC 768/791/8200（承载及内层 IP）。具体线形以仓库实现与现有 pcap 为准。
> 机器实现：`trafficgen/internal/protocol/openvpn/planner.go`、`layer_gen.go`；cases：`trafficgen/test/protocol_pcap/cases/openvpn.json`。

## 0. 范围与 as-built 边界

本契约描述 OpenVPN 终结层在 UDP 链上的声明式剧本回放：控制通道产生 HARD_RESET_CLIENT/SERVER，数据通道产生 P_DATA_V1/V2；可选 tls-auth、tls-crypt、Keepalive、soft reset、exit-notify、静态密钥及内层 IP。默认协议为 UDP、目的端口 1194。OpenVPN-over-TCP 的 legacy planner 可生成 2 字节大端长度前缀和 TLS 包裹，但 layer-chain 的 UDP 依赖层无法承载，validator 明确拒绝 `proto=tcp`（`layer_gen.go:118-123`）。

加密没有实现：IV、HMAC、AEAD tag、wrapped key 使用确定性填充（`planner.go:24-26`、`buildEncryptedPayloadRaw`）；生成结果是 DPI/结构测试字节，不可声称可被真实 OpenVPN 对端认证。session_id 默认每 flow 随机生成，显式非零值可固定；peer_id 为 session_id 低 24 位。

## 1. 协议栈、配置与目标形状

推荐层链为 `[ip, udp, openvpn]`，最小链 `[udp, openvpn]`；registry 中 `openvpn` 是 `CategoryTerminal`，依赖 `udp`，默认 `udp.dst_port=1194`（`layers/registry.go:516-519`）。ChainPlanner 将 `spec.OpenVPN` 直传终结层（`layers/chain_planner_translate.go:252-254`），默认目的端口在 `layers/chain_planner.go:1102-1106` 补齐。

目标形状（未来新增例应遵循）：
```json
{"layers":[{"udp":{"dst_port":1194}},{"openvpn":{"version":"2","data_packet_count":5}}]}
```
存量 `openvpn_udp1194_reset_data` 仍是 `{count:1,openvpn:{}}` 平面旧形，必须在 P4 迁移；不要把旧形当作最终层链契约。四元组住 `ip`/`udp`，协议业务键住 `openvpn` 层；`count` 迁入 `flow_control`。

## 2. 线格式

所有多字节整数均大端，除非下表另注。首字节为 `(opcode << 3) | (key_id & 0x07)`，opcode 占高 5 位、key_id 为低 3 位（`planner.go:817-822`）。控制包无 tls-auth 时：`header(1)+session_id(8)+ack_count(1)+ack_ids(4n)+remote_session_id(8 if n>0)+message_packet_id(4)+TLS payload`。当前生成器总是 `ack_count=0`，所以固定头为 14 字节加 TLS payload（`appendControlHeader`）。

| 形态 | 字段与长度 | 现状 |
|---|---|---|
| P_CONTROL_HARD_RESET_CLIENT_V1/V2/V3 | 1B header + 8B session + 1B ack count + 4B message id + TLS/包装体 | V1/V2/V3 opcode 1/7/10 |
| P_CONTROL_HARD_RESET_SERVER_V1/V2 | 同上 | V1/V2 opcode 2/8 |
| P_DATA_V1 | 1B header + opaque encrypted payload | opcode 6 |
| P_DATA_V2 | 1B header + 3B peer_id + opaque encrypted payload | opcode 9；peer_id=session low 24 bits |
| tls-auth control | header + session + HMAC(H) + replay id 4B + net time 4B + ack count + message id | H=MD5 16/SHA1 20/SHA256 32/SHA512 64 |
| tls-crypt | header + session + wrapped body | v2 prefix 2B length + 4B key id; filler body |

P_DATA CBC encrypted payload is `IV(16)+packet_id(4)+payload+HMAC(H)`; legacy DES uses 8B IV. AEAD is `nonce(12)+packet_id(4)+payload+tag(16)`; `NONE` is plaintext. These are structural fillers, not cryptography (`planner.go:1067-1179`).

## 3. State machine and event driving

States are `Start → ResetClient → ResetServer → Data → optional Keepalive → optional SoftReset/Data → optional ExitNotify → End`; static-key mode starts directly at Data. UDP emits one `PacketConfig` per event; TCP legacy emits handshake, length-prefixed segments, and teardown, but chain validator rejects it. Data uses `DataPacketCount` packets each direction (default 5), or exactly one pair per `InnerIPPackets` entry. `AuthUserPass` inserts TLS AppData after reset. `close` is not a field: UDP has no FIN/close event.

Each flow creates a session ID once (`planner.go:377-382`); all control packets reuse it; P_DATA_V2 uses its low 24-bit peer ID. No child flow is derived: inner IP packets are payload records in the same outer flow. There is no request/response transaction correlation beyond direction and shared session/peer identifiers.

## 4. Business scenarios and five-layer coverage

**功能**：V1/V2/V3 reset paths, P_DATA V1/V2, static key, tls-auth/tls-crypt, auth-user-pass, keepalive, soft reset, exit-notify, inner IPv4/IPv6 and TCP/UDP/ICMP are implemented branches; each needs an independent case. Invalid proto/version/key-id/cipher/auth/TLS combination, count, fragment, keepalive, exit-notify, MTU/MSS, static key and inner IP are validator negatives.

**性能**：data count 1, 1000, >1000; payload 0/1/16384/>16384; fragmentation 64, 1500 and adjacent values; TCP MSS segmentation; inner packet length and multiple inner packets. Count scales linearly; queues remain bounded by framework.

**数据**：opcode/key-id bit packing, session/peer widths, big-endian fields, cipher modes, HMAC sizes, TLS versions, auth credentials, wrapped-key layout, fragment header, and inner checksum/length fields. Invalid encodings and mixed address families are rejected.

**地址与流**：outer IPv4 and IPv6; UDP single flow baseline; TCP is an explicit layer-chain rejection. Inner IPv4/IPv6 is supported, but mixed inner families are rejected. No control/data child flow correlation applies.

**业务**：ordinary tunnel data, static-key P2P, authenticated tunnel, rekey, keepalive, explicit exit, and tunneled application packets. Multi-session is not implemented; multiple inner packets are same-session multi-record behavior.

## 5. Validator and errors

`Planner.Validate` checks outer IPs, required config, proto, version, key ID ≤7, cipher/auth/TLS enums, tls-crypt-v2 dependency, V1 incompatibilities, TCP dependency, data count ≤1000, mssfix [576,1500], payload ≤16384, static-key exclusivity/256-byte key, credentials 1..64 and controls, fragment [64,1500], keepalive restart ordering, exit-notify UDP-only and count ≤3, tun MTU [576,65535], MSS/TunMTU capacity, TCP MSS ≥536, and inner-IP validity. Error anchors are the exact strings in `planner.go:118-326`; layer-chain adds `openvpn: proto=tcp is not supported...` (`layer_gen.go:121-123`). Failed planning must propagate task error and emit no successful packet stream.

## 6. Performance and output contract

UDP event count in the default case is `2 + 2*DataPacketCount` (two reset packets plus bidirectional data), hence 12 for default count 5. Add one auth event, one keepalive, one soft-reset event plus its data count, and `2*ExitNotifyCount` only as configured by the actual event path; inner packets replace default data count. PCAP and NIC use the same case and assertions; NIC capture uses the configured test interface. No throughput claim is made here.

## 7. Dynamic fields

`ip.src`, `ip.dst`, `udp.src_port`, and `udp.dst_port` use the framework's fixed/inc/rand/list/pattern strategy machinery. `openvpn` has no entry in `layerDynAllowlist` (`layer_dyn.go:17-71`), so all business objects are rejected as dynamic; `session_id`, `key_id`, data payload/count, cipher, reset and inner packet lists are static per flow. Tuple fallback source ports are assigned by strategy conversion/worker. No dynamic business-field coverage is claimed.

## 8. Gate 1 §1–§14 table

| § | As-built satisfaction | Evidence |
|---|---|---|
| 1 | Layer chain is target shape; current case has legacy top-level keys | §1; `cases/openvpn.json` |
| 2 | strategy converts openvpn map; task combines flows and caps totals | `strategy_convert.go:1265`; framework |
| 3 | One outer session, reset→data timeline, no derived child flow; UDP terminal insertion | §3 |
| 4 | OpenVPN source + Wireshark dissector + RFC 768/791/8200 | §0/§2 |
| 5 | Depends on UDP; validator errors propagate | registry:516; planner:118-326 |
| 6 | Count/payload/fragment limits and bounded event stream | §6 |
| 7 | Design + testcase + cases (case currently legacy shape) | §1; testcase §2 |
| 8 | Design precedes implementation documentation | revision record |
| 9 | Source/code/case/pcap three-way checks required | testcase §5 |
| 10 | Review loop and explicit gaps recorded | §10 |
| 11 | Plain-language framing in §0 and §4 | §0 |
| 12 | Four-tuple dynamic list and business-field denial list | §7 |
| 13 | Registry schema already generated for openvpn; no new layer | registry:516 |
| 14 | Real pcap/NIC run must use same case contract | §6; testcase §7 |

### 8.1 §1 legacy key migration

`count` → `flow_control`; top-level `openvpn` → `layers[].openvpn`; `dst_port` → `layers[].udp.dst_port`; outer addresses → `layers[].ip`; source port → `layers[].udp.src_port`. Complete target: `{"layers":[{"ip":{"src":"192.0.2.1","dst":"192.0.2.2"}},{"udp":{"src_port":40000,"dst_port":1194}},{"openvpn":{"version":"2","data_packet_count":5}}],"flow_control":{"flows":1}}`.

### 8.2 §3 five-piece expansion

Session table: `s1` one UDP outer flow with one session ID. Transaction sequence: reset-client → reset-server → data pairs → optional modifiers. Correlation: shared session ID in control and peer ID in data; no parent/child flow. Insertion: terminal after UDP. Timeline: one datagram per event, up/down sequence as planner emits. Multi-session is not applicable; inner packets are records, not sessions.

### 8.3 §12 dynamic inventory

Outer four-tuple: `ip.src`, `ip.dst`, `udp.src_port`, `udp.dst_port`, all five strategies; sequence comes from shared tuple generator and worker fallback. Business fields: `proto`, `version`, `key_id`, `session_id`, TLS toggles/version/role, ciphers, payload/count, auth, fragmentation, keepalive, reset, exit, MTU, and `inner_ip_packets` are all closed to dynamic objects because no OpenVPN allowlist entry exists. The generator's session ID is selected once per Plan flow at `planner.go:377-382`, not per packet.

## 9. P3 implementation map

`OpenVPNGenerator.Generate` validates, rebuilds a FlowSpec, invokes legacy `Planner.Plan`, maps packet configs to message events, and sets `L4PortOverride=true` because legacy events already swap downlink ports (`layer_gen.go:40-80`). `Planner.Plan` owns defaults, IDs, event generation, outer headers and inner packet construction (`planner.go:329-812`). Registry/translation/strategy conversion are the five integration points listed in §1.

## 10. Gaps and stale artifacts

| Gap | Phenomenon / evidence | Stage |
|---|---|---|
| G-OPENVPN-1 | Existing case has `{count,openvpn}` instead of layer-only shape; `spec_json` has no pcap/NIC dual-path declaration | P4 migration |
| G-OPENVPN-2 | Only one smoke case; no cases for V1/V3, crypto wrappers, static key, inner IP, IPv6, limits, or validator negatives | P4 coverage |
| G-OPENVPN-3 | Business dynamic fields rejected because `layerDynAllowlist` has no `openvpn` entry | P4 decision/implementation |
| G-OPENVPN-4 | Synthetic cryptographic fillers are structurally valid only, not interoperable authentication | Explicit boundary; implementation scope |
| G-OPENVPN-5 | Layer-chain TCP is rejected although legacy planner has TCP path | Explicit boundary; add TCP transport layer first |
| G-OPENVPN-6 | Tracked `trafficgen/docs/protocol-pcap-test/openvpn.md` last commit `e7e7d1c` (2026-08-27), before 0417be5; its pcap directory is not present in this worktree | P5 rerun/regenerate |

## 11. Revision record

- v1.0.0（2026-09-29）：按实现、registry、strategy conversion、现有 case 逆向撰写；登记 legacy case 形状、单例覆盖、动态字段闭锁、TCP layer-chain 边界、合规加密边界及过期结果产物。自审 1 轮，末轮干净。
