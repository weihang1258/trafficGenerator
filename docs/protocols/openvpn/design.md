# #137 openvpn（OpenVPN）设计契约

> 版本：v2.0.0（P-PIPE 文档轨，P1–P4 as-built）
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
存量 `openvpn_udp1194_reset_data` 已采用严格层链；四元组住 `ip`/`udp`，协议业务键住 `openvpn` 层，流数住 `flow_control`。

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
| §1 | Layer chain is target shape; current case is strict layer-chain | §1; `cases/openvpn.json` |
| §2 | Strategy converts the OpenVPN map; task combines flows and caps totals | `strategy_convert.go:1265`; framework |
| §3 | One outer session, reset→data timeline, no derived child flow; UDP terminal insertion | §3 |
| §4 | OpenVPN source + Wireshark dissector + RFC 768/791/8200 | §0/§2 |
| §5 | Depends on UDP; validator errors propagate | `registry.go:516`; `planner.go:118-326` |
| §6 | Count/payload/fragment limits and bounded event stream | §6 |
| §7 | Design + testcase + cases (strict layer-chain) | §1; testcase §2 |
| §8 | Design precedes implementation documentation | revision record |
| §9 | Source/code/case/pcap three-way checks required | testcase §5 |
| §10 | Review loop and explicit gaps recorded | §10 |
| §11 | Plain-language framing in §0 and §4 | §0 |
| §12 | Four-tuple dynamic list and business-field denial list | §7 |
| §13 | Registry schema already generated for OpenVPN; no new layer | `registry.go:516` |
| §14 | Real pcap/NIC run must use same case contract | §6; testcase §7 |

### 8.1 Layer-chain shape (as-built)

The case uses `flow_control.flows` for flow count, top-level `openvpn` → `layers[].openvpn`, `dst_port` → `layers[].udp.dst_port`, outer addresses → `layers[].ip`, and source port → `layers[].udp.src_port`. The as-built shape is `{"layers":[{"ip":{"src":"192.0.2.1","dst":"192.0.2.2"}},{"udp":{"src_port":40000,"dst_port":1194}},{"openvpn":{"version":"2","data_packet_count":5}}],"flow_control":{"flows":1}}`.

### 8.2 §3 five-piece expansion

Session table: `s1` one UDP outer flow with one session ID. Transaction sequence: reset-client → reset-server → data pairs → optional modifiers. Correlation: shared session ID in control and peer ID in data; no parent/child flow. Insertion: terminal after UDP. Timeline: one datagram per event, up/down sequence as planner emits. Multi-session is not applicable; inner packets are records, not sessions.

### 8.3 §12 dynamic inventory

Outer four-tuple: `ip.src`, `ip.dst`, `udp.src_port`, `udp.dst_port`, all five strategies; sequence comes from shared tuple generator and worker fallback. Business fields: `proto`, `version`, `key_id`, `session_id`, TLS toggles/version/role, ciphers, payload/count, auth, fragmentation, keepalive, reset, exit, MTU, and `inner_ip_packets` are all closed to dynamic objects because no OpenVPN allowlist entry exists. The generator's session ID is selected once per Plan flow at `planner.go:377-382`, not per packet.

## 9. P3 implementation map

`OpenVPNGenerator.Generate` validates, rebuilds a FlowSpec, invokes legacy `Planner.Plan`, maps packet configs to message events, and sets `L4PortOverride=true` because legacy events already swap downlink ports (`layer_gen.go:40-80`). `Planner.Plan` owns defaults, IDs, event generation, outer headers and inner packet construction (`planner.go:329-812`). Registry/translation/strategy conversion are the five integration points listed in §1.

## 10. Gaps and stale artifacts

| Gap | Phenomenon / evidence | Stage |
|---|---|---|
| G-OPENVPN-1 | Layer-chain migration is complete; the case uses strict `layers` + `flow_control` shape | Closed in P4 |
| G-OPENVPN-2 | Only one smoke case; no cases for V1/V3, crypto wrappers, static key, inner IP, IPv6, limits, or validator negatives | P4 coverage |
| G-OPENVPN-3 | Business dynamic fields rejected because `layerDynAllowlist` has no `openvpn` entry | P4 decision/implementation |
| G-OPENVPN-4 | Synthetic cryptographic fillers are structurally valid only, not interoperable authentication | Explicit boundary; implementation scope |
| G-OPENVPN-5 | Layer-chain TCP is rejected although legacy planner has TCP path | Explicit boundary; add TCP transport layer first |
| G-OPENVPN-6 | Tracked `trafficgen/docs/protocol-pcap-test/openvpn.md` last commit `e7e7d1c` (2026-08-27), before 0417be5; its pcap directory is not present in this worktree | P5 rerun/regenerate |

## 11. Revision record

- v2.0.1（2026-10-01）：按当前严格层链 case 清理迁移完成后的 stale legacy 形状描述，关闭 G-OPENVPN-1；其余缺口与未运行边界保持不变。自审 2 轮，末轮干净。

## 12. P1 要求面矩阵（D1–D3）

### 12.1 规范要求→业务场景→代码现状→缺口

| 要求面 | 业务场景 | 代码现状/证据 | 用例或缺口 |
|---|---|---|---|
| UDP reset 与 data opcode | V2 客户端/服务端复位后双向数据 | `planner.go` 事件规划、`layer_gen.go` 终结层 | `openvpn_udp1194_reset_data` 已覆 |
| key-id/session/peer 关联 | 同一 flow 控制共享 session，V2 data 使用低 24 位 peer | `planner.go:377-382` | 已覆；V1/V3 待补 |
| 认证与包装 | tls-auth、tls-crypt、静态密钥 | `planner.go:1067-1179` filler 结构 | G-OPENVPN-2，需独立 cases |
| 约束拒绝 | 非法版本、key-id、计数、负载、MTU/MSS | `planner.go:118-326` | 负例缺口逐项列于 testcase §4 |
| 层链承载 | IP→UDP→OpenVPN，TCP 明确拒绝 | `registry.go:516-519`、`layer_gen.go:118-123` | TCP 缺口 G-OPENVPN-5 |

### 12.2 消息×响应/状态矩阵

| 消息/事件 | 成功后继 | 失败处理 | 状态 |
|---|---|---|---|
| HARD_RESET_CLIENT_V2 | SERVER_V2 | 规划失败，任务失败且无成功流 | 已覆/负例待补 |
| HARD_RESET_SERVER_V2 | P_DATA_V2 | 同上 | 已覆 |
| P_DATA_V1/V2 | 下一 data 或可选 modifier | 参数非法即拒绝 | V2 已覆，V1 待补 |
| keepalive/soft-reset/exit-notify | 继续 data 或结束 | UDP/TCP/计数约束拒绝 | 待补 |

### 12.3 数据形态变体表

| 维度 | 取值/边界 | 结论 |
|---|---|---|
| 外层地址族 | IPv4、IPv6 | 代码支持；IPv6 case 待补 |
| reset 版本 | V1/V2/V3 | 代码分支存在；V2 有例，V1/V3 待补 |
| data | V1/V2、NONE/CBC/AEAD | filler 结构已实现；独立断言待补 |
| key-id | 0、1、7、8 | 0 已覆；1/7 正例、8 负例待补 |
| payload/count | 0/1/16384/16384+、1/1000/1001 | validator 有界；边界例待补 |
| 内层数据 | IPv4/IPv6、TCP/UDP/ICMP | planner 支持；独立例待补 |

### 12.4 现网行为→用例映射

| 行为来源 | 观察 | 用例 |
|---|---|---|
| IANA UDP/1194 + Wireshark dissector | 1194、opcode、session/peer字段 | `openvpn_udp1194_reset_data` |
| OpenVPN `ssl_pkt.h`/`ssl_pkt.c` | V2 reset/data 线布局 | `openvpn_udp1194_reset_data` |
| 现有 `/tmp/probe-iana/openvpn.pcap` | offset 42 的 0x38/0x48 | 正例 frames |
| 开源实现/本仓库 planner | 事件顺序和 filler 边界 | 设计 §3、待补矩阵 |

## 13. 候选方案与 D4–D6 实施设计

| 方案 | 做法 | 取舍 | 结论 |
|---|---|---|---|
| A | 复用现有 legacy planner，再由层链包装 | 最小改动，保持已验证事件顺序；加密仍为 filler | 采用 |
| B | 新写纯层链 OpenVPN 状态机 | 可独立演进，但会重复校验和 ID/事件逻辑 | 不采用 |

**接口/数据/流程**：`OpenVPNGenerator.Generate` 接受层链转换后的 `FlowSpec`，调用 `Planner.Validate`/`Plan`，逐事件生成 `PacketConfig`；session ID 每 flow 一次，peer ID 取低 24 位，外层地址/端口只来自 `ip`/`udp` 层。错误返回 planner 原文并终止任务，不输出成功 PCAP。回滚只需恢复本三文件；不涉及代码或 schema。

**性能设计与验收（D6）**：事件流按包 `yield`，不聚合全量；单 flow 默认 12 个 UDP datagram，data 上限 1000，payload 上限 16384；队列/环形缓冲仍由框架上限控制。验收同时要求 PCAP 落盘逐字段 tshark 校对和 NIC 抓包复用同一 JSON 断言；本轮未宣称 NIC 实测吞吐。

## 14. D1–D8 静态迁移闭环

| ID | 结论 | 代码/机器证据与去向 |
|---|---|---|
| D1 | 层链是唯一配置真相：地址在 `ip`，端口在 `udp`，业务在 `openvpn`，流数在 `flow_control` | `cases/openvpn.json` 唯一正例顶层仅 `layers`、`flow_control`；`registry.go:516-519`、`chain_planner.go:1102-1106` |
| D2 | OpenVPN 是依赖 UDP 的终结层，标准序列为 `[ip,udp,openvpn]`；`[udp,openvpn]` 亦是最小链 | `registry.go:517` `DependsOn: [udp]`；层顺序由 registry/chain planner 校验；唯一例采用完整链 |
| D3 | UDP 承载与四元组由 carrier 层负责，OpenVPN 只产消息事件；每事件一个 datagram | `layer_gen.go:65-78` 将 planner packet 映射为 `MessageEvent`，`L4PortOverride=true`；`planner.go:560-812` 负责事件序列 |
| D4 | `version`、`key_id`、reset/data、加密包装、认证、保活、退出和 inner IP 等业务键只住 `layers[].openvpn` | `chain_planner_translate.go:252-254` 直传 `spec.OpenVPN`；`strategy_convert.go:4755-4792` 解析业务键 |
| D5 | 正例不得使用顶层 `openvpn`、顶层地址/端口或旧 `count`；故意的错误载体只能登记为负例，当前不伪造负例 | `openvpn.json` 无上述游离键；当前负例数为 0，缺口见 testcase §4 |
| D6 | 流控独立于协议业务；默认 data count 由 planner 补为 5，且单 flow 事件流保持有界 | `planner.go:402-406`、`chain_planner.go:1102-1106`；唯一例 `flow_control.flows=1`，预期 12 帧 |
| D7 | 动态只声称已有 allowlist 的外层字段；OpenVPN 业务动态对象当前拒绝，不把静态随机 session ID 冒充动态覆盖 | `layer_dyn.go:17-21` 仅列 `ip`/`udp` 等字段，无 `openvpn`；缺口 G-OPENVPN-3 |
| D8 | OpenVPN 特有观察面为 opcode/key-id、session/peer 关联、V2 data 帧偏移；V1/V3、包装、inner IP、失败边界均独立登记待补 | 唯一例 `expect.fields` 与 `frames` 覆盖 07/08/09、key-id、session/peer、offset 42；不扩写未有机器例的支持结论 |

D1–D8 只证明三文件的静态形状、代码锚点和边界登记，不证明 suite、Go 测试、PCAP 或 NIC 运行通过。回滚范围严格为本目录两文档与 `cases/openvpn.json`；不改 Go、schema、其他文档或 `LAYERCHAIN_INDEX`。

## 15. Revision record

- v2.0.1（2026-10-01）：补齐 D1–D8 逐项静态证据，校正 `flow_control`、动态 allowlist 与 planner 默认值的代码锚点；保持唯一正例、零负例和未运行边界。自审 2 轮，末轮干净。
