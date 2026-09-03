# 执行计划：v3 LayerChain 统一架构

> 版本：**v1.0**（2026-09-03，基于 baseline 清查）
> 承接：`docs/superpowers/plans/2026-09-03-unified-layerchain-architecture.md`（总计划）
> 目标：完成层链端注册/路由改造 + 策略转换代理改造 + TCP 重传/IP 校验和端到端 + legacy 迁移，为后续 P2 铺底。

---

## 1. 基线快照（执行前实测）

### 代码结构

| 文件 | 行数 | 职责 |
|------|------|------|
| `internal/core/strategy_convert.go` | 7902 | flat 配置 → `FlowSpec`，含 112 个 switch case |
| `internal/core/layers/chain_planner.go` | 2877 | 链规划器（层链路径） |
| `internal/core/layers/registry.go` | 978 | 层链端注册表（已有部分实现） |
| `internal/core/layers/*.go` | 50 文件 | 层链端各层实现 |

### 用例现状

**纯 flat 风格（每协议仅 1 个用例，需全部迁移为 chain 风格）：**
`dns`(1), `ntp`(1), `snmp`(1), `syslog`(1), `ssdp`(1), `mdns`(1), `radius`(1), `dhcp`(1), `dhcpv6`(1) — 共 **9 协议 × 1 例 = 9 例**

**含大量 flat 风格（需批量迁移为 chain）：**
`tftp`(40 flat/186 chain), `modbus`(81 flat/132 chain) — 共 **2 协议，121 例 flat 需迁移**

**批次 2 高价值目标（6 协议，大用例量）：**
`doip`(69 flat), `enip`(66 flat), `dnp3`(29 flat), `nfs`(33 flat), `mqtt`(74 flat), `gbt32960`(42 flat) — 共 **6 协议 313 例 flat**

### 路由路径确认

- **REST → `coreTask.Layers = rawLayers`**（`internal/api/rest/task_handler.go:1047`）：`strategy.Config["layers"]` 直接透传给 `core.Task.Layers`
- **MCP → `StrategyModelToTask`**：走 `strategy.Config` 字段，`createStrategyAndTask` 内嵌 config 映射，layers key 由调用方传入
- **`engine.SubmitTask`**：读到 `task.Layers != nil` → 调用 `layerPlannerFactory(protocol, layers)` 构建 `ChainPlanner`
- **`PacketWorker.Dispatch`**：`taskID` → `layerPlanners[taskID]` → `ChainPlanner.Plan()` → `[]PacketConfig`

**关键：** `strategy_convert.go` 的 `mapToFlowSpec` 是给 legacy flat 路径用的；chain 路径走 `ChainPlanner`，两条路径完全独立。

---

## 2. 目标状态

1. `strategy_convert.go`：7902 行 → ~4200 行（删除/注释 112 个 switch case 中的 70 个，改为代理调用 `chainPlanFromSpec`）
2. `chain_planner.go`（2877 行）：拆为 6 个文件
3. 新增文件：TCP 重传状态机、IP 校验和端到端计算器
4. 批次 1 纯 flat 协议（9 协议 × 1 例）全部迁移为 chain 风格
5. `go build ./...` + `go test ./trafficgen/internal/core/... -race -count=1` 全过

---

## 3. 实施步骤

### Step 1 — 确认 registry.go 现有能力

**目标：** 确认 `RegisterChainPlanner`/`LookupChainPlanner` 是否已存在

```
Read: internal/core/layers/registry.go
```

- 如已存在且签名合理 → 直接使用
- 如不存在 → 补充实现

### Step 2 — 确认 Batch 1 协议层链终结层状态

**目标：** 确认 `dns`/`ntp`/`snmp`/`syslog`/`ssdp`/`mdns`/`radius`/`dhcp`/`dhcpv6` 在 `registry.go` 是否已注册

```
grep -n "dns\|ntp\|snmp\|syslog\|ssdp\|mdns\|radius\|dhcp" internal/core/layers/registry.go
```

- 已注册 → 确认 planner 能处理空层配置（`{dns:{}}`）
- 未注册 → 按注册顺序补充注册

### Step 3 — 改造 `strategy_convert.go` → `convert_proxy.go`

**新建文件：** `trafficgen/internal/core/convert_proxy.go`

核心函数：

```go
// chainPlanFromSpec: mapToFlowSpec 的代理。
// 策略：
//   1. cfg["layers"] 存在 → 调用 chainPlanFromLayers → Planner → FlowSpec
//   2. cfg["layers"] 不存在，但协议在 migrationAllowlist → flatToLayers
//   3. 其他 → 走原有 mapToFlowSpec（向后兼容）
func chainPlanFromSpec(cfg map[string]interface{}, protocol string) FlowSpec {
    if layersVal, ok := cfg["layers"]; ok {
        return chainPlanFromLayers(layersVal, protocol)
    }
    if isMigrationCandidate(protocol) {
        return flatToLayers(cfg, protocol)
    }
    return mapToFlowSpec(cfg, protocol)
}
```

- `migrationAllowlist`：dns, ntp, snmp, syslog, ssdp, mdns, radius, tftp, dhcp, dhcpv6, modbus（第一批）
- `flatToLayers`：将 flat 字段翻译为层链 Spec（src_ip → layers[0].ip.src_ip 等）
- **删除 `strategy_convert.go` 中 allowlist 协议的 case 块内容**，替换为 `return chainPlanFromSpec(cfg, protocol)`

### Step 4 — 拆分 `chain_planner.go`

**将 2877 行的 `chain_planner.go` 按职责拆为 6 个文件：**

| 新文件 | 行数(估) | 内容 |
|--------|----------|------|
| `chain_planner.go` | ~500 | `ChainPlanner` struct + `Plan()` + `driveChain()` |
| `chain_planner_drive.go` | ~400 | `driveSession()`, `tcpStateMachine()`, `retransmit()` |
| `chain_planner_emit.go` | ~600 | `finalizeEmit()` + 32 个 per-protocol Emit 块 |
| `chain_planner_gen.go` | ~300 | `genPackets()` + `newGenerator()` |
| `chain_planner_util.go` | ~300 | `l2For()`, `flowMetaFor()`, `flowID()`, `is*Chain()` helpers |
| `chain_planner_test.go` | ~800 | 链规划 + drive 状态机测试 |

**原则：** per-protocol Emit 块（`case "pim"`, `case "igmp"` 等）逐字保留，拆文件不改变语义。

### Step 5 — TCP 重传状态机 + IP 校验和端到端

**新建文件：**

```
trafficgen/internal/core/layers/tcp_retransmission.go
trafficgen/internal/core/layers/tcp_retransmission_test.go
trafficgen/internal/core/layers/ip_checksum_e2e.go
trafficgen/internal/core/layers/ip_checksum_e2e_test.go
```

**TCPRetransmissionStateMachine（`tcp_retransmission.go`）：**

```go
// 状态机状态：
// OPEN → FAST_RECOVERY → RECOVERY → OPEN
// OPEN → RTO_TIMEOUT → RTO_RECOVERY → OPEN
// OPEN → CHALLENGE_ACK → CHALLENGE_REPLIED/CHALLENGE_TIMEOUT → OPEN
type TCPRetransmissionStateMachine struct {
    segQueue    []Segment  // 已发未确认段
    dupAckCount int
    ssthresh    uint32
    cwnd        uint32
    rtt         time.Duration
    rto         time.Duration
}
func (sm *TCPRetransmissionStateMachine) OnACK(ack uint32)
func (sm *TCPRetransmissionStateMachine) OnDupACK(ack uint32)
func (sm *TCPRetransmissionStateMachine) OnRTO()
func (sm *TCPRetransmissionStateMachine) OnChallengeACK()
```

**IPCksumComputer（`ip_checksum_e2e.go`）：**

```go
type IPCksumComputer struct{}
func (c *IPCksumComputer) ComputeIPv4HdrChecksum(hdr []byte) uint16
func (c *IPCksumComputer) ComputeIPv4PseudoHdrSum(src, dst net.IP, proto uint8, length uint16) uint32
func (c *IPCksumComputer) ComputeIPv6PseudoHdrSum(src, dst net.IP, proto uint8, length uint32) uint32
func (c *IPCksumComputer) FinalizeTCPOrUDPChecksum(hdrSum uint32, data []byte) uint16
func (c *IPCksumComputer) AssembleAndVerify(frags [][]byte) ([]byte, error)
```

### Step 6 — Batch 1 用例迁移（9 协议 × 1 例 = 9 例）

**迁移协议：** dns, ntp, snmp, syslog, ssdp, mdns, radius, dhcp, dhcpv6

每个用例从 flat 风格：

```json
{"dns": {"domain": "example.com"}}
```

改为 chain 风格：

```json
{
  "layers": [{"udp": {}}, {"dns": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dns": {"domain": "example.com"}
}
```

**规则：**
- 保留原有的协议特定配置（dns query, snmp var_binds 等）在 flat key 中
- layers 数组由层链终结层自动推断，无需手动列全链
- 每个用例添加 `summary` 说明 chain 风格改写

### Step 7 — 一致性验证测试

**新建文件：** `trafficgen/internal/core/strategy_convert_validate_test.go`

```go
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

### Step 8 — 编译 + 测试验证

```bash
go build ./... && go vet ./...
go test ./trafficgen/internal/core/... -race -count=1
# 批次 1 用例验证（单协议跑）
flowb_run_protocol_suite --proto dns --case_dir test/protocol_pcap/cases/
```

---

## 4. 执行顺序

```
[Step 1] → [Step 2] → [Step 3] → [Step 4] → [Step 5] → [Step 6] → [Step 7] → [Step 8]
```

- Step 3（proxy）+ Step 4（拆分）+ Step 5（TCP/IP）可并行
- Step 6（用例迁移）依赖 Step 1–2 确认 registry 状态
- Step 7（一致性测试）依赖 Step 3
- Step 8 验证最后

---

## 5. 验收标准

- [ ] `go build ./...` 无编译错误
- [ ] `go vet ./...` 无警告
- [ ] `go test ./trafficgen/internal/core/... -race -count=1` 全通过
- [ ] `strategy_convert.go` 行数从 ~7902 行减少到 ~4200 行
- [ ] 批次 1 的 9 协议 × 1 例全部通过 chain 路径验证
- [ ] TCP 重传状态机 3 个测试路径全部 PASS（3×ACK/RTO/Challenge ACK）
- [ ] IP checksum 端到端测试全部 PASS
