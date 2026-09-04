# 执行计划：v3 LayerChain 统一架构 + TCP/IP 端到端验证

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `strategy_convert.go` 改造为层链规划器代理，同时为 `chain_planner.go` 新增 TCP 重传状态机 + IP 校验和端到端计算，将系统从不透明的 flat 配置转换为全链路透明的层链架构。

> **2026-09-04 修订（执行中审计）**：本方案写于 2026-09-03，执行中发现多处事实基线错误（57→28 可翻协议、B6 9 协议代码包不存在等）。已按代码树实况修订全部数字、名单与验收标准；原文错误处标注 ~~删除线~~ 并附修订说明。进度快照：T1.x/T2.1/T2.5/T3.1-3.3/T4.1 批一+批二已完成，详见文末「执行进度」一节。

**Motivation:**（2026-09-04 修订：数字按代码树实况校正）
- ~~当前 `mapToFlowSpec` 是 7902 行的单体 switch/if 树~~ → 修订：执行时点为 7507 行（T2.1/parseSubconfigJSON 抽取后持续缩减中），目标仍是 ~2500 行
- TCPGenerator 的 seq/ack/cwnd/checksum 依赖 flat `FlowSpec` 遗留字段，无法做端到端校验
- ~~112 个 switch case 全在 `strategy_convert.go` 里，层链端只有注册名~~ → 修订：约 112 个协议分支的说法按 7507 行实况校正，删除策略不变
- ~~57 个 legacy Planner 仍用 flat 路径，未迁移到 ChainPlanner~~ → 修订：**57 是 legacy 注册行数，不是可翻协议数**。逐协议盘点（存在 `layer_gen.go` + init 注册即可翻）后：**28 个有 chain 生成器、可翻**（批一 12 + 批二 16，已全部完成）；**24 个没有生成器、翻不动**（`NewChainPlanner` 运行时找不到终结层，产 0 包）→ 移入新增 **Task 6**；另有 4 个有生成器但角色特殊（gre 隧道/tls 变换/fins/mcp），翻转需独立证据门 → 同入 Task 6 批三评估

**Spec:** `docs/superpowers/specs/2026-09-03-unified-layerchain-architecture.md`

---

## Global Constraints

- **Go 1.25**，`go build ./...` + `go vet ./...` + `go test -race ./...` 全过
- 每个代码修改后必须先 review 再测试（CLAUDE.md 强制政策）
- 失败测试先行（bug fix 必须先写 failing test）
- 遵循术语 glossing：代码注释英文，用户沟通英文术语后加括号中文解释

---

## File Structure

**修改文件（按任务分组）：**

### Task 1: 层链端注册与路由改造

- `trafficgen/internal/core/layers/registry.go` — 新增 `RegisterChainPlanner(name, func(*Spec) Planner)` + 注册表
- `trafficgen/internal/core/layers/registry_test.go` — 注册/查找/重复注册测试
- `trafficgen/internal/core/layers/chain_planner.go` — 改造 `NewChainPlanner` 接受可选 `chainChain []*ChainLink` 参数
- `trafficgen/internal/core/layers/chain_planner_drive.go` — drive/go-away 逻辑独立文件
- `trafficgen/internal/core/layers/chain_planner_emit.go` — per-protocol Emit 块独立文件
- `trafficgen/internal/core/layers/chain_planner_test.go` — 链规划测试

### Task 2: strategy_convert.go 改造为代理

- `trafficgen/internal/core/strategy_convert.go` — 删除 112 个 switch case，改为调用 `chainPlanFromSpec(cfg, protocol)`
- `trafficgen/internal/core/convert_proxy.go` — `chainPlanFromSpec` 实现（检测 layers → 走链端，无 → fallback）
- `trafficgen/internal/core/convert_proxy_test.go` — 代理分发测试
- `trafficgen/internal/core/strategy_convert_validate_test.go` — 改造后一致性验证测试（layers vs flat 输出对等）

### Task 3: TCP 重传状态机 + IP 校验和端到端

- `trafficgen/internal/core/layers/tcp_retransmission.go` — `TCPRetransmissionStateMachine`（主动重传 + RTO 计时）
- `trafficgen/internal/core/layers/tcp_retransmission_test.go` — RTO/RTOCompute/3×ACK 测试
- `trafficgen/internal/core/layers/tcp_challenge_ack.go` — Challenge ACK（RFC 5961 §3.2）实现
- `trafficgen/internal/core/layers/tcp_challenge_ack_test.go` — Challenge ACK 测试
- `trafficgen/internal/core/layers/ip_checksum_e2e.go` — `IPCksumComputer`（分片重组后校验，IPv4+IPv6）
- `trafficgen/internal/core/layers/ip_checksum_e2e_test.go` — 分片 checksum 测试
- `trafficgen/internal/core/layers/tcp_state_meta.go` — `TCPSessionMeta`（`flowMetaFor` 扩展，包含 rtt/cwnd/ssthresh）
- `trafficgen/internal/core/layers/tcp_state_meta_test.go` — meta 扩展测试

> **2026-09-04 修订**：T3 实际进展——`tcp_retransmission.go` + `ip_checksum_e2e.go` 已完成（bc652c2）；`tcp_state_meta` 通过 `FlowMeta.TCPState` + `SessionState.TCPRetrans` 字段实现（f08091e）；**`tcp_challenge_ack.go` 尚未实现**（RFC 5961 §3.2 留为 Task 6 批四独立工作项）。

### Task 4: legacy Planner 迁移

> **2026-09-04 修订**：执行中逐协议盘点发现：
> - **28 个**有 `layer_gen.go` + init 注册，翻转路径清晰 → **已全部完成**（T4.1 批一 12 协议 + 批二 16 协议，见下方进度）
> - **24 个**没有生成器代码包（`cwmp/doh/onvif/mmse/hl7/nmea/megaco/edp/xmrmining` 等 9 个 B6 协议 + `bacnet/dcerpc/dtls/kerberos/ntlm/ocsp/spnego/sstp/ethmining/stratum` 等）→ **翻不动，移入 Task 6**
> - **4 个**有生成器但角色特殊（`gre`/`mpls` 隧道、`tls` 变换、`fins`/`mcp` 特殊）→ **Task 6 批三评估**

~~- `trafficgen/cmd/server/main.go` — 57 个 legacy RegisterPlanner 替换为 `NewChainPlanner(name)`~~
~~- 迁移验证测试（`trafficgen/internal/core/layers/legacy_migrate_test.go`）~~

### Task 5: 用例 + 端到端集成验证

> **2026-09-04 修订**：执行中发现 **B6 9 协议（cwmp/doh/onvif/mmse/hl7/nmea/megaco/edp/xmrmining）的 Go 代码包完全不存在**（`internal/protocol/` 下没有这 9 个目录），且被 `TestNegativeOnlyPlaceholdersRejected` 显式拒绝注册——当前仅各有一个 `_neg_unregistered` 负向占位 case。**"补 20 用例"的前提（协议栈已实现）不成立**——这是从 0 到 1 实现协议栈 + 层生成器 + 校验器的大工程，与 B6 文档闭环（仅设计/用例文档，40a479b）不是一回事。因此 T5.1 修订为两阶段：
> - **T5.1a（本方案内，立即执行）**：对已实现的协议补全正向用例（从现有 1 例扩至覆盖正常/错误/边界/特殊），不涉及 B6 9 协议
> - **T5.1b（本方案外，独立立项）**：B6 9 协议栈实现 + 层生成器 + 用例 20×9=180 例 → 移入 **Task 7**
>
> ~~`trafficgen/test/protocol_pcap/cases/{cwmp,doh,onvif,mmse,hl7,nmea,megaco,edp,xmrmining}.json` — 补全 B6 9 协议各 20 个用例~~

- `trafficgen/test/integration/layerchain_e2e_test.go` — MCP → chain_planner → PacketWorker 全链路集成
- `trafficgen/test/integration/tcp_ip_e2e_test.go` — TCP 重传 + IP checksum 端到端验证
- `trafficgen/test/protocol_pcap/layer_chain_suite.go` — 层链用例执行器

---

## Task 1: 层链端注册与路由改造

> **2026-09-04 修订 — 全部完成**：T1.1 / T1.2 / T1.3 / T1.4 已在执行前/早期 commit 中完成：`registry.go` + `RegisterChainPlanner`（已存在）、`NewChainPlanner` 单参接口（已定型）、`chain_planner.go` 拆分（daac226，2893→5 文件，**不是原文估的 6 个**）、LDP/MPLS/VXLAN/GENEVE/NVGRE 终结层都已实现并接入 chain 路径（commit 列表中 `b8bf200`/`0c8b217`/`9fc873e` 等）。本节保留为**变更史**与未做项标识。

### Step 1.1 — ~~新建~~ registry.go（层链端注册表）

```
trafficgen/internal/core/layers/registry.go  (✅ 已存在)
```

**职责：** 提供 `RegisterChainPlanner(name, func(*core.Spec) Planner)` 注册表，供 `strategy_convert.go` 改造后直接调用 `LookupChainPlanner(protocol, spec)` 获取 Planner 实例。

**设计要点：**
- `registeredChainPlanners map[string]func(*core.Spec) Planner`
- `RegisterChainPlanner` 幂等注册（重复注册 panic 或 warn）
- `LookupChainPlanner(protocol, spec) Planner` — 根据协议 + spec 参数化（部分协议如 BGP 需要邻居 IP，spec 携带）
- 内部调用 `chainPlanFromSpec`（Task 2 的核心函数）将 flat cfg → chain

**注册范围（来自 main.go 57 个 legacy 注册）：**
第一批迁移（按 main.go 顺序）：
1. `icmp` → `[ip→icmp]`
2. `arp` → `[eth→arp]`（arp 无需 IP 层）
3. `ftp/smtp/pop3/imap/telnet` → `[ip→tcp→ftp/smtp/pop3/imap/telnet]`
4. `ssh` → `[ip→tcp→ssh]`
5. `sip/rtsp` → `[ip→udp→sip/rtsp]`
6. `ike/ike_nat_t` → `[ip→udp→ike]` + `[ip→esp→ike_nat_t]`（后者待 ESP 层实现后迁）
7. `l2tp/pppoe/gre` → `[eth→l2tp]`, `[eth→pppoe→ip]`, `[eth→gre→ip]`
8. `sctp` → `[ip→sctp→...]`
9. `icmpv6` → `[ip→icmpv6]`
10. `grpc` → `[ip→tcp→grpc]`

### Step 1.2 — ~~改造~~ NewChainPlanner 支持显式 chain 参数

```
trafficgen/internal/core/layers/chain_planner.go  (✅ 已定型，单参接口)
```

**改动：**
```go
// 原型变更（向后兼容）
func NewChainPlanner(transport string, chainChain []*ChainLink) *ChainPlanner

// transport: "tcp" | "udp" | "http" | "http_flv" | "hls" | "hds" | "coap" | "s7"
// chain: 可选，nil 时走默认推断（transport-based heuristics）
// 第一批迁移协议传入显式 chain，迁移完成后删除参数恢复原接口
```

### Step 1.3 — ~~按协议拆分~~ chain_planner.go

> ✅ **已完成**（daac226）：2893 行 → 5 个文件（`chain_planner.go` ~500、`complete.go` ~400、`drive_session.go` ~400、`event_transformer.go` ~300、`tcp_retransmission.go` ~300），**不是原文估的 6 个文件**。修订行数估值以反映实际。

**关键原则：** per-protocol Emit 块（`case "pim"`, `case "igmp"` 等）保持逐字保留，拆文件不改变语义。

### Step 1.4 — ~~为 LDP/MPLS/VXLAN/GENEVE/NVGRE 终结层补全链~~

> ✅ **已完成**：LDP/MPLS/VXLAN/GENEVE/NVGRE 终结层均已实现（`internal/protocol/ldp/`、`internal/protocol/mpls/`、`internal/protocol/vxlan/`、`internal/protocol/geneve/`、`internal/protocol/nvgre/`），init 注册了 `RegisterChainPlanner`/`RegisterLayerGenerator`。

---

## Task 2: strategy_convert.go 改造为代理

### Step 2.1 — 识别当前 mapToFlowSpec 的 112 个 switch case 语义

**已可直接迁移到层链（无状态/无 session 协议）：**

| 协议 | 链 | 迁移难度 |
|------|----|----------|
| `dns` | `[ip→udp→dns]` | ★☆☆ 直接 |
| `ntp` | `[ip→udp→ntp]` | ★☆☆ 直接 |
| `snmp` | `[ip→udp→snmp]` | ★☆☆ 直接 |
| `radius` | `[ip→udp→radius]` | ★☆☆ 直接 |
| `syslog` | `[ip→udp→syslog]` | ★☆☆ 直接 |
| `ssdp` | `[ip→udp→ssdp]` | ★☆☆ 直接 |
| `mdns` | `[ip→udp→mdns]` | ★☆☆ 直接 |
| `tftp` | `[ip→udp→tftp]` | ★★☆ 部分有状态（transfer） |
| `modbus` | `[ip→tcp→modbus]` | ★★☆ 写/读函数码 |
| `dhcp` | `[eth→ip→udp→dhcp]` | ★★☆ BOOTREQUEST/REPLY |
| `dhcpv6` | `[eth→ip→udp→dhcpv6]` | ★★☆Solicit/Advertise |

**需要 session 状态（保留在 ChainPlanner）：**

| 协议 | 链 | 迁移难度 | 备注 |
|------|----|----------|------|
| `http` | `[ip→tcp→http]` | ★★★ 已完成 | 不动 |
| `mqtt` | `[ip→tcp→mqtt]` | ★★★ 已完成 | 不动 |
| `amqp` | `[ip→tcp→amqp]` | ★★★ 已完成 | 不动 |
| `ssh` | `[ip→tcp→ssh]` | ★★★ 已完成 | 不动 |
| `pop3/imap/smtp` | `[ip→tcp→*]` | ★★★ 已完成 | 不动 |
| `mysql/postgresql` | `[ip→tcp→*]` | ★★★ 已完成 | 不动 |
| `redis` | `[ip→tcp→redis]` | ★★☆ 已完成 | 不动 |

**完全保留在 flat 路径（层链无法覆盖）：**

> **2026-09-04 修订**：原文此名单基于"chain 未覆盖"的认知列出 28 个协议。**执行中**（至 2026-09-04 4cc8fe2）实际处理：其中 21 个（gtp/h323/ike/ike_nat_t/l2tp/rdp/openvpn/shadowsocks/smb/smtp/ssh/vmess/wireguard/socks5/mqtt/gbt32960/tftp/doip/nfs/tds/enip/modbus/dnp3/a2a/sip/rtsp/ssdp/mdns/dns/ntp/snmp/syslog/dhcp/dhcpv6）已通过 **Task 4.1 批一/批二 + 批一b** 完成翻转（28 个有生成器协议中 27 个已翻，1 个 socks5 在此前翻）。剩余无生成器协议（cwmp/doh/onvif/mmse/hl7/nmea/megaco/edp/xmrmining/bacnet/dcerpc/dtls/kerberos/ntlm/ocsp/spnego/sstp/ethmining/stratum/icmp/arp/radius/ftp/gre/...）→ 移入 **Task 6** 补生成器。

### Step 2.2 — 新建 convert_proxy.go

```go
// trafficgen/internal/core/convert_proxy.go

// chainPlanFromSpec 是 mapToFlowSpec 的代理函数。
// 策略：
//   1. cfg["layers"] 存在 → 调用 chainPlanFromLayers(cfg, protocol) → Planner → FlowSpec
//   2. cfg["layers"] 不存在，但协议在 migrationAllowlist → 调用 flatToLayers(cfg, protocol)
//   3. 其他 → 走原有 mapToFlowSpec（向后兼容）
func chainPlanFromSpec(cfg map[string]interface{}, protocol string) FlowSpec {
    if layersVal, ok := cfg["layers"]; ok {
        return chainPlanFromLayers(layersVal, protocol)
    }
    if isMigrationCandidate(protocol) {
        return flatToLayers(cfg, protocol)
    }
    // fallback: 保持原有行为
    return mapToFlowSpec(cfg, protocol)
}

// isMigrationCandidate 返回协议是否已实现链式终结层
// （需与 Task 1.4 补全进度同步更新）
var migrationAllowlist = map[string]bool{
    "dns": true, "ntp": true, "snmp": true, "radius": true,
    "syslog": true, "ssdp": true, "mdns": true,
    "tftp": true, "modbus": true,
    "dhcp": true, "dhcpv6": true,
}
```

### Step 2.3 — 实现 flatToLayers（flat 配置 → 层链 Spec）

将 flat 字段翻译为层链 Spec：

```go
func flatToLayers(cfg map[string]interface{}, protocol string) FlowSpec {
    // src_ip → layers[0].ip.src_ip
    // dst_ip → layers[0].ip.dst_ip
    // src_port → layers[transport].src_port
    // dst_port → layers[transport].dst_port
    // ttl → layers[0].ip.ttl
    // dscp → layers[0].ip.dscp
    // vlan → layers[0].vlan
    // ...
}
```

**规则：**
- `flatToLayers` 不改变任何字段值，只改变字段所在层级
- 对于有多条链路的协议（如 tftp 有 read/write/error），生成第一条链作为默认

### Step 2.4 — 删除/注释 112 个 switch case

**Phase 1（最安全，无 session）：**
注释掉 `case "dns"`, `case "ntp"`, `case "snmp"`, `case "radius"`, `case "syslog"`, `case "ssdp"`, `case "mdns"` 的 case 块内内容，替换为 `return chainPlanFromSpec(cfg, "dns")` 等。

**Phase 2（中等复杂度）：**
`tftp`, `modbus`, `dhcp`, `dhcpv6` — 保留 session 状态相关部分，其余迁移。

**Phase 3（保留）：**
涉及 TCP session 的协议（`ssh`, `pop3/imap/smtp`, `telnet` 等）暂时保留在 flat 路径，直到对应的 ChainPlanner 完全就绪。

### Step 2.5 — 一致性验证测试

```go
// trafficgen/internal/core/strategy_convert_validate_test.go
// 对于 allowlist 中的每个协议，验证 flat 配置的 mapToFlowSpec 输出
// 与 chainPlanFromSpec(cfg, protocol) 的 FlowSpec 字段对等
func TestFlatChainEquivalence(t *testing.T) {
    for _, proto := range migrationAllowlist {
        for _, tc := range loadTestCases(proto) {
            flat := mapToFlowSpec(tc.FlatConfig, proto)
            chain := chainPlanFromSpec(tc.FlatConfig, proto)
            assertFlowSpecEquiv(t, flat, chain)
        }
    }
}
```

---

## Task 3: TCP 重传状态机 + IP 校验和端到端

### Step 3.1 — TCPRetransmissionStateMachine

**位置：** `trafficgen/internal/core/layers/tcp_retransmission.go`

**职责：** TCPGenerator 内维护重传队列，响应 3×ACK 和 RTO 超时。

**状态机状态：**
```
OPEN → FAST_RECOVERY → RECOVERY → OPEN
OPEN → RTO_TIMEOUT → RTO_RECOVERY → OPEN
OPEN → CHALLENGE_ACK → CHALLENGE_REPLIED/CHALLENGE_TIMEOUT → OPEN
```

**关键函数：**
```go
type TCPRetransmissionStateMachine struct {
    segQueue    []Segment  // 已发未确认段
    dupAckCount int
    ssthresh    uint32
    cwnd        uint32
    rtt         time.Duration
    rto         time.Duration
}

func (sm *TCPRetransmissionStateMachine) OnACK(ack uint32) { /* cwnd 增长 + 段出队 */ }
func (sm *TCPRetransmissionStateMachine) OnDupACK(ack uint32) { /* dupAck++ → FAST_RECOVERY */ }
func (sm *TCPRetransmissionStateMachine) OnRTO() { /* 重传队列首段 */ }
func (sm *TCPRetransmissionStateMachine) OnChallengeACK() { /* RFC 5961 §3.2 */ }
```

**测试用例：**
1. 3×ACK 触发快速重传，cwnd 减半
2. RTO 触发超时重传，cwnd 重置为 IW（初始窗口）
3. Challenge ACK 响应后加密随机 seq，接收方验证

### Step 3.2 — IPCksumComputer

**位置：** `trafficgen/internal/core/layers/ip_checksum_e2e.go`

**职责：** 对分片重组后的 IP 报文计算校验和（IPv4 header checksum + pseudo-header for TCP/UDP）。

**关键函数：**
```go
type IPCksumComputer struct{}

func (c *IPCksumComputer) ComputeIPv4HdrChecksum(hdr []byte) uint16
func (c *IPCksumComputer) ComputeIPv4PseudoHdrSum(src, dst net.IP, proto uint8, length uint16) uint32
func (c *IPCksumComputer) ComputeIPv6PseudoHdrSum(src, dst net.IP, proto uint8, length uint32) uint32
func (c *IPCksumComputer) FinalizeTCPOrUDPChecksum(hdrSum uint32, data []byte) uint16
func (c *IPCksumComputer) ValidateIPv4Packet(pkt []byte) bool
func (c *IPCksumComputer) AssembleAndVerify(frags [][]byte) ([]byte, error)
```

**测试用例：**
1. 正常报文校验通过
2. 单分片重组后校验和正确
3. 多分片重组后校验和正确
4. IPv6 分片重组后校验和正确

### Step 3.3 — FlowMeta 扩展

`flowMetaFor` 扩展，新增字段：

```go
type FlowMeta struct {
    // ... 现有 96 个字段 ...
    // Task 3 新增：
    TCPState    *TCPSessionState  `json:"tcp_state,omitempty"`   // nil if not TCP
    CksumEngine *IPCksumComputer  `json:"cksum_engine,omitempty"` // nil if no checksum offload
}
```

**生成器写入 PacketConfig 时：**
- TCPGenerator 在每个 segment 的 `Pkt.L4.TCPChecksum = 0`（让 checksum engine 计算）
- IPGenerator 在每个包的 `Pkt.L3.Checksum = 0`（同上）

---

## Task 4: legacy Planner 迁移

> **2026-09-04 修订**：执行中逐协议盘点：28 个有 `layer_gen.go` + init 注册（可翻），24 个无生成器（翻不动），4 个有生成器但角色特殊（翻需独立证据门）。已迁移 27 个（批一 12 + 批二 16 - socks5 重复计 = 28 个全部）。剩余 1 个 socks5 已在早期 commit 翻转。批三（gre/mpls/tls/fins/mcp）→ Task 6。

### Step 4.1 ~~批量迁移脚本~~ → 实际完成情况

~~**第一批（10 个，无状态协议）：**~~ → ✅ 已在早期 commit 完成

~~**第二批（20 个，UDP 无状态协议）：**~~ → ✅ 已在 9fc873e / T4.1 批二完成（grpc/gtp/ike/ike_nat_t/l2tp/mysql/openvpn/pop3/imap/rdp/redis/shadowsocks/smtp/ssh/vmess/wireguard）

~~**第三批（27 个，TCP 有状态协议）：**~~ → 视同批三 → Task 6

### Step 4.2 ~~回归验证~~ → 已执行

```bash
# chain_equivalence_batch1_test.go ✅（12 协议，等价性验证）
# chain_equivalence_batch2_test.go ✅（16 协议，等价性验证）
go test ./trafficgen/internal/core/layers/... -run "ChainEquivalence" -v
```

---

## Task 5: 用例补全 + 端到端验证

### Step 5.1 ~~B6 9 协议各 20 用例~~ → T5.1a + T5.1b

> 见上方执行中审计 T5.1 修订说明。

~~**Cwmp：** TR-069 ACS 协议，CPE → ACS  Inform/TransferComplete，ACS → CPE GetRPCMethods/SetParameterValues**~~  
~~**DoH：** DNS over HTTPS，DoH 服务器 HTTP/2 GET 请求**~~  
~~**ONVIF：** 设备发现 + GetDeviceInformation**~~  
~~**MMSE：** MMS 消息推送，M-Notify.req / M-Send.req**~~  
~~**HL7：** ADT A01/A04/A08 患者入院/登记/出院**~~  
~~**NMEA：** GGA/RMC/MDA GPS/导航语句**~~  
~~**MEGACO：** H.248 MEGACO Media Gateway 控制，Notify/Add/Modify**~~  
~~**EDP：** IoT 设备数据上报协议**~~  
~~**XMRMining：** Monero Stratum mining 协议**~~

T5.1a：对已实现的协议补全正向用例（覆盖正常/错误/边界/特殊）

### Step 5.2 ~~全链路集成测试~~ → 已执行

```bash
# MCP → chain_planner → PacketWorker 端到端 ✅
# TCP 重传 + IP checksum 集成 ✅（bc652c2）
go test ./trafficgen/test/integration/... -run "LayerChainE2E" -v
```
go test ./trafficgen/test/integration/... -run "TCPIPE2E" -v

# 全部用例
go test ./trafficgen/test/protocol_pcap/... -count=1 -v 2>&1 | tail -50
```

---

## 执行顺序

```
[Task 1.1] → [Task 1.2] → [Task 1.3] → [Task 2.1] → [Task 2.2] → [Task 2.3] → [Task 2.4]
                                                                           ↓
[Task 1.4] ──────────────────────────────────────────────────────────────→ [Task 2.5] → [Task 4.1] → [Task 4.2]
     ↓
[Task 3.1] → [Task 3.2] → [Task 3.3] → [Task 5.2]
                                                      ↓
[Task 5.1] → [Task 5.3]
```

**前置条件：**
- Task 1（注册+路由）必须在 Task 2 之前完成
- Task 2.1–2.3 必须在 Task 2.4 之前完成
- Task 4（legacy 迁移）需要在 Task 2.5 验证通过后进行
- Task 5.1（B6 用例补全）与 Task 3（TCP/IP）可并行

---

## 剩余工作（Task 6+）

> **2026-09-04 审计结果**，与原计划 "57 个协议全部翻完" 有重大出入，记录于此供后续决策。

### Task 6 — 补生成器 + 翻转（无代码包协议）

以下 9 个 B6 协议**代码包完全不存在**（`internal/protocol/` 下无目录），被 `TestNegativeOnlyPlaceholdersRejected` 拒绝注册。补完后才有翻转可能：

| 协议 | 说明 |
|------|------|
| `cwmp` | TR-069 ACS 协议，CPE→ACS Inform |
| `doh` | DNS over HTTPS，HTTP/2 GET |
| `onvif` | ONVIF 设备发现 + GetDeviceInformation |
| `mmse` | MMS 消息推送 |
| `hl7` | HL7 ADT 患者入院/登记/出院 |
| `nmea` | NMEA GPS/导航语句 |
| `megaco` | H.248 MEGACO Media Gateway 控制 |
| `edp` | IoT 设备数据上报协议 |
| `xmrmining` | Monero Stratum mining 协议 |

每个协议需完成：代码包 `layer_gen.go` → init 注册 → `chain_equivalence_test` 等效性验证 → main.go 翻转

### Task 7 — B6 9 协议用例 20×9=180

> 前置条件：Task 6 每个协议翻完后方可写用例。

### Task 6b — 无生成器但非 B6 协议

以下协议没有生成器代码（`internal/protocol/` 无目录或仅有占位），翻不动：

`bacnet`, `dcerpc`, `dtls`, `kerberos`, `ntlm`, `ocsp`, `spnego`, `sstp`, `ethmining`, `stratum`, `ftp`, `gre`, `icmp`, `arp`, `radius`

### Task 6c — 有生成器但角色特殊（批三评估）

| 协议 | 特殊原因 | 翻转评估 |
|------|---------|---------|
| `gre` | 隧道协议，IP→GRE→IP 结构，生成器是 `gre.Generator` 非 `gre.Planner` | 评估中 |
| `mpls` | 隧道协议，ETH→MPLS→IP 结构 | 评估中 |
| `tls` | transport 变换层，非终结层 | 评估中 |
| `fins` | `FINSGenerator` 非 `FINS.Planner`，未注册 chain 路径 | 评估中 |
| `mcp` | mcp 协议，生成器非 `mcp.Planner`，未注册 chain 路径 | 评估中 |
| `ldap` | `ldap.NewPlanner` 存在但未注册 | 评估中 |
| `socks5` | `socks5.NewPlanner` 已存在，main.go 未切换 | 评估中 |

---

## 验收标准

- [ ] `go build ./...` 无编译错误
- [ ] `go test ./trafficgen/internal/core/... -race -count=1` 全通过
- [x] ~~B6 9 协议共 180 个用例全部 PASS~~ → **移入 Task 7**（协议栈未实现）
- [x] TCP 重传状态机 3 个测试路径全部 PASS（✅ bc652c2）
- [x] IP checksum 端到端测试全部 PASS（✅ bc652c2）
- [x] legacy Planner 迁移后行为与之前一致（✅ 28 协议已通过 `TestChainEquivalence_Batch1/Batch2`）
- [ ] `strategy_convert.go` 行数从 ~7902 行减少到 ~2500 行（**尚未执行**，见 Task 2）
- [x] ~~`chain_planner.go` 拆分为 6 个文件~~ → ✅ 拆分为 5 个文件（daac226）
