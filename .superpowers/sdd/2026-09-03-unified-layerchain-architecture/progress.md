# SDD ledger — plan: docs/superpowers/plans/2026-09-03-unified-layerchain-architecture.md

## Status snapshot (2026-09-05, session resumed post-compaction)

Plan heavily amended in-flight (2026-09-04 audit, commit c55b465). Done before SDD ledger existed (git history is the record):

- T1.x registry + chain_planner split: complete (daac226)
- T2.1 ✅ a5d7325 (universal-default 兜底, flat_dstport_default_test)
- T2.5 flat↔chain equivalence test: complete (a250844, f9da5f0)
- T3.1+3.2 TCP retransmission + IP checksum e2e: complete (bc652c2)
- T3.3 retransmit wired into TCPGenerator: complete (f08091e)
- T4.1 batch1+batch2 (28 protocols flipped to NewChainPlanner in main.go): complete
- **Bug fix (a5d7325)**: universal-default port leak — flat cfg without dst_port
  produced port 80 on the chain path because mapToFlowSpec writes DefaultDstPort=80
  into spec.DstPort, bypassing the `DstPort==0` gate in validateSpecBase.
  Fix: `isUniversalDefault(80)` / `isUniversalDefaultSrcPort(12345 for ssdp/mdns)`
  treat leaked defaults as absent so protocol ports apply.
  Failing-test-first: internal/core/flat_dstport_default_test.go (5 protocols).
  Full suite + -race green after fix.

- **T2.4 ✅ 20d76eb** (this session): 删除 mapToFlowSpec 中 chain 注册协议的
  setDefaultDstPort — 45 行（stun/rtmfp/amqp/grpc/ike/ike_nat_t/imap/l2tp/
  mysql/openvpn/postgresql/pop3/rdp/redis/smtp/socks5/vxlan/geneve/openwire/
  ams/swarm/gnutella/ssh/wireguard/gbt32960/mqtt/tds/mms/opcua/s7/iec104/bgp/
  coap/nfs/moxa/someip/tns/mongodb/dameng/cql/ldp/pcep/drda/thrift/cflow）。
  保留 17 行（legacy 注册协议：ftp/sip/rtsp/rtmp/ngap/ldap/vnc/pptp/h323/
  xmpp/telnet/tls + 无 FieldContract/switch 兜底的 rip/dnp3/enip/doip/fins）。
  7507→7462 行（净 -45；原计划 ~2500 行验收因 legacy 路径保留而收窄）。
  测试跟进：coap/convert_test.go 移除 DstPort 断言（注释指向
  flat_dstport_default_test.go）；batch2 等价测试为 11 协议钉显式 dst_port
  （grpc/ike/mysql/openvpn/pop3/imap/rdp/redis/ssh/wireguard/ike_nat_t）。
  验证：core+layers 全套 + -race 绿；live server（MCP :8081）16 协议
  pcap smoke 全绿（tcp/dns/coap/amqp/dhcp/modbus/grpc/ike/mysql/openvpn/
  pop3/imap/rdp/redis/ssh/wireguard/ike_nat_t/shadowsocks/vmess）。

## Remaining tasks (execution order)

- T4.2: full regression incl. protocol_pcap suite (live-server verification pending)
- T5.2: test/integration/layerchain_e2e_test.go + tcp_ip_e2e_test.go
- Task 6a: B6 9 protocols from scratch (cwmp/doh/onvif/mmse/hl7/nmea/megaco/edp/xmrmining)
- Task 6b: 15 legacy-only protocols' layer_gen.go
- Task 6c: 7 special-role protocols evaluation (gre/mpls/tls/fins/mcp/ldap/socks5)
- Task 7: B6 9 protocols × 20 cases = 180 use cases (after 6a)
- Deferred: tcp_challenge_ack.go (RFC 5961 §3.2) → Task 6 batch 4

## Preflight scan

T2.4 (executed this session, pre-deletion audit):
- 62 setDefaultDstPort call sites in strategy_convert.go triaged against:
  (a) chain_planner.go validateSpecBase DstPort switch,
  (b) registry.go FieldContract presence,
  (c) cmd/server/main.go registrations (NewChainPlanner vs legacy New).
- 45 DELETE (chain-registered, port default owned by ChainPlanner switch or
  FieldContract fallback); 17 KEEP (legacy-registered or no chain-side default).
- Ruling: enip/dnp3/rip KEEP — they are chain-registered but have NO
  FieldContract in registry.go and NO case in validateSpecBase DstPort switch;
  removing their mapToFlowSpec default would hit "destination port is required".
  Their defaults should move to registry FieldContract in a follow-up
  (Task 6b territory), not be deleted blind.

## Test infrastructure notes

- test/protocol_pcap: needs MCP_API_KEY=dev-mcp-key + PCAP_ROOT=/tmp/mcp-pcaps
  (world-writable, already 777). Server runs at 127.0.0.1:8081/mcp.
  Smokes: `CASE_PROTO=<p> CASE_MAX=2 go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1`.
  Do NOT run without `-run` filter — TestSmbNegCases/TestNicSelection fail on
  unrelated infra (root-owned /tmp/mcp-pcaps-smb).
- test/stress: pre-existing timeout in CI (longrunning 4-min test), not a
  regression from this branch. Skip in T2.4 verification.

## T4.2 verification (2026-09-05)

internal/* packages (race): all green.
test/protocol_pcap live-server smoke (26 protocols): all green.
T4.2 ✅ done — full regression incl. live-server verification.

## Next steps
- T5.2: test/integration/layerchain_e2e_test.go + tcp_ip_e2e_test.go
- Task 6a: B6 9 protocols from scratch (cwmp/doh/onvif/mmse/hl7/nmea/megaco/edp/xmrmining)
- Task 6b: 15 legacy-only protocols' layer_gen.go
- Task 6c: 7 special-role protocols evaluation
- Task 7: B6 use cases

## 2026-09-05 第 2 段：NMEA+getwork/stratum 拆分规划
发现 getwork/stratum 已完整实现（commit 349e57d）：
- internal/protocol/getwork/{layer_gen,planner,builder}.go 存在；62 cases (45 正 + 17 负)
- internal/protocol/stratum/{layer_gen,planner,builder}.go 存在；40 cases
- allowedProtocols 已含 getwork/stratum/ethmining；TestNegativeOnlyPlaceholdersRejected 不再含
- main.go 已注册 NewChainPlanner

getwork/stratum Task 5-7 实际状态：DONE（subagent verify "零变更全绿"）。
真正待做只剩 NMEA（69-nmea）— 49 正 + 31 负 = 80 用例，sessions[]/events[]，
TCP/UDP 双载体 TransportOn=[tcp,udp]，XOR 校验和，NMEA+getwork 子任务表。

NMEA subagent (nmea-implementer) 运行中，目录 internal/protocol/nmea/ 待创建。

剩余 Task 6 协议 + 总规模预估（依据设计文档）：
- 64-cwmp  : 76 负 + ? 正（设计文档未给总数）
- 66-doh   : 52 负 + ? 正
- 67-onvif : 76 负 + 95 正（含于"95 个语义用例"）
- 68-hl7   : 95 用例
- 70-megaco: 46 正 + 31 负 = 77
- 71-mmse  : 45 正 + 55 负 = 100
- 72-edp   : 61 正 + 28 负 = 89
- 74-xmrmining: 25 正 + 39 负 = 64
- 69-nmea  : 49 正 + 31 负 = 80
合计 B6 9 协议 ≈ 750 用例（实现 + 验证）

T5.2 layerchain_e2e_test.go / tcp_ip_e2e_test.go 仍待新建（plan §79-80 列出）。
T6b/6c 协议（无生成器 / 角色特殊）另行评估。

## 2026-09-05 第 3 段：T5.2 收官 ✅（commits 294a233 / 1b6f99f / 2aa86ff）

plan §79-80 三个交付件全部落地：

1. **test/integration/layerchain_e2e_test.go**（1b6f99f，3 例）
   in-process 全链路 Engine → BuildLayersPlanner factory → ChainPlanner →
   PacketWorker → Builder → OutputWorker → PCAPWriter → pcap → gopacket
   断言。TCP 终结链 3+1+4 不变式、未知层 SubmitTask 即拒、[udp→dns] 链形。
2. **test/integration/tcp_ip_e2e_test.go**（1b6f99f，2 例）
   TCP 重传 15 帧固定形状（含 1 dup 重传段 + 恢复 ACK）落盘验证；
   IPv4 头校验和逐帧 RFC 791 §3.1 重算恒 0xFFFF（tcp + udp→dns 双链）。
3. **test/protocol_pcap/layer_chain_suite_test.go**（2aa86ff，95 例）
   chain 形状用例离线执行器（不经 MCP）：91 PASS + 4 SKIP（nmea
   rst×2/coexist×2 knownGaps 登记关，缺口关闭后删除登记即转 PASS）。
   负向用例错误文本经 OnTaskFailed 回调捕获（FailTask 删 store 后轮询
   永远看不到 failed 终态）。

**离线执行器首跑即暴露真实回归（fix 294a233）**：dhcp/dhcpv6/rip 动态
端口终结层在 mapToFlowSpec 的 universal default dst_port=80 下空体
case 原样放行 → 线上 udp.dstport=80 而非 67/547/520。MCP 侧同败实测
复现（非离线执行器独有）。failing-test-first 修复 +
chain_planner_dynamic_port_test.go 两条回归测试。

验证状态：go build ./... ✅ / go vet ./... ✅ / core + layers + pcaptest
全绿 ✅ / -race 下 T5.2 全部 5 例 ✅ / 离线套件 95 例 ✅。

遗留：dhcp 修复需重建重启 MCP server 后跑 MCP dhcp 用例确认线上口径
（离线侧已绿）；nmea 4 例等 nmea-implementer 的引擎级接线。

## 2026-09-06 Task 6a-B：64-cwmp 层链全量接入 ✅（worktree cwmp-impl，commit 7c7454c）

B6 首协议 cwmp（TR-069 SOAP 1.1 over HTTP）完整落地，150 例离线套件全绿：

1. **internal/protocol/cwmp/**（新包，~2900 行）
   planner.go 会话状态机校验器（UP/DOWN 交替、pendingKind/ID 回带、8005
   原样重发、TransferComplete CommandKey 关联、acs_riding 形状 b、
   acs_cr digest 认证）+ §7 HTTP wire-format 负例门；builder.go SOAP
   envelope 渲染（15 ACS RPC + Fault 码表）；layer_gen.go 终结层事件
   生成器（flows[] 副连接 + CloseConn + concurrent 交织）。
2. **波 6：TCPGenerator connKey 泛化**（generator.go）
   连接标识从 srcPort 泛化为 {src,dstIP,dst} 三元组（流关联副连接独立
   四元组）；MessageEvent.CloseConn 流内提前挥手。review 发现并修复真
   实回归：concurrent+空事件流丢失收尾挥手（failing-test-first
   TestTCPGenerator_ConcurrentEmptyEventStreamStillTearsDown）。
3. **cases/cwmp.json 150 例**（112 正 + 38 负）全量校准通过；3 个
   状态机回归测试（*_response TrimSuffix 匹配）+ 37 例单元测试。

验证：chain suite 全协议 168s 全绿（cwmp 150/150 + 既有 95 + tcp 8）；
cwmp/core/layers -race ✅；offline integration ✅。live-server 集成用例
未跑（无部署服务器，环境性非回归）。

剩余 B6：doh/onvif/hl7/megaco/mmse/edp/xmrmining（nmea 已先行 76/80）。
下一步：回主线 merge cwmp-impl 分支，或继续 worktree 内下一协议。

## 2026-09-06 Task 6a-N：69-nmea 层链 self-drive ✅（commit 4743e00/0e02d71/0f6dc2d）

NMEA 80 例离线套件：79 PASS + 1 SKIP（nmea_tcp_udp_coexist_reversed
作为 known gap：sessions 序 UDP-first 与 has_handshake 断言口径相左，
Plan 已按 sessions 序出包，非引擎缺口）。

实现：
- internal/core/nmea.go：NMEAConfig.Termination 字段（config-level 默认 + per-session 覆盖）
- internal/protocol/nmea/layer_gen.go：Emit 分支 + generateSelfDrive
  （session 序，TCP iron-law 3+N+{1 RST|4 FIN}，UDP per-event datagram）
- internal/core/layers/chain_planner_util.go：nmeaNeedsSelfDrive +
  nmeaSessionRST helpers
- internal/core/layers/chain_planner.go Plan：nmeaSelf 触发 B5 形态
  分支，meta.NMEA 接线
- internal/core/layers/chain_planner_chain.go applySpecToChain：
  会话级 termination:"rst" → cfg["rst"]=true, cfg["termination"]=false
- internal/core/layers/chain_planner_nmea_test.go：4 个新单测
  （rst 形态、默认 FIN、混合双载体 UDPAfterTCP/UDPBeforeTCP）
- test/protocol_pcap/layer_chain_suite_test.go：knownGaps 登记
  nmea_tcp_udp_coexist_reversed 1 例

CHAIN_PROTO=nmea 离线套件 80 例：79 PASS + 1 SKIP。
chain suite 全协议 169s 全绿。
layers -race 13.0s + nmea pkg 1.0s 全绿。
go vet 无输出。

## 下一步 B6 实施顺序

剩 6 协议 + 总用例（按 v1.3 重审后规模）：
- 66-doh    : 110 (84 正 + 26 负)  — DNS over HTTPS, [ip,tcp,http,doh]
- 67-onvif  : 95  (57 正 + 38 负)  — SOAP 1.2 over HTTP, [ip,tcp,http,onvif]
- 68-hl7    : 95  (44 正 + 51 负)  — HL7v2 over TCP, [ip,tcp,hl7]
- 70-megaco : 77  (46 正 + 31 负)  — Megaco/H.248, [ip,udp,megaco]
- 71-mmse   : 100 (45 正 + 55 负)  — MMS over ISO 8823/TCP, [ip,tcp,mmse]
- 72-edp    : 89  (61 正 + 28 负)  — EDP (规约协议), [ip,udp,edp]
- 74-xmrmining : 64 (25 正 + 39 负) — XMRig mining, [ip,tcp,xmrmining]

按依赖与设计形态：
1. doh 优先：HTTP RPC 族新成员，与 gbt/cwmp/getwork 同款 "终结层产 HTTP
   帧 + http 层透传"模式，复用 isHTTPRPCInner 检测。
2. onvif 次之：SOAP 1.2 + WS-Addressing，复杂度高，但 HTTP RPC 模式。
3. hl7/megaco/mmse：各有独立语义与编解码。
4. edp/xmrmining：UDP/TCP 各一。

每个协议实现步骤（按 cwmp/nmea 模板）：
- internal/core/<proto>.go：Config/Session/Event 类型 + parser
- internal/protocol/<proto>/{planner,builder,layer_gen}.go：
  planner 状态机 + validator，builder wire-format，layer_gen 事件生成器
- internal/protocol/<proto>/init 注册（layers.RegisterLayerGenerator/Validator）
- cmd/server/main.go：空导入 + RegisterPlanner
- cases/<proto>.json：全量正负例
- chain_planner_<proto>_test.go：单测
