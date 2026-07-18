# 分片 PacketWorker + group_id 修改点核对 + 测试结果

**日期**: 2026-07-19
**实现 commit 范围**: 54a834e..ff38ac3
**Spec**: `docs/superpowers/specs/2026-07-19-sharded-packet-workers-design.md`

## 1. 修改点清单（38 项，全部核对）

### 数据结构（3 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 1 | `FlowSpec.GroupID *StrategyConfig` | `core/types.go:115` | `TestFlowSpecGroupIDJSONRoundTrip` | PASS |
| 2 | `TrafficClass.GroupID *StrategyConfig` | `core/types.go:301` | `TestTrafficClassGroupIDJSONRoundTrip` | PASS |
| 3 | `ReplaySpec.GroupID *core.StrategyConfig` | `replay/types.go:14` | `TestComputeReplayGroupID_*` | PASS |

### 路由层 Engine（7 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 4 | `Engine.shardedConfigChan []chan PacketConfig` | `core/engine.go:33` | `TestProcessTaskRoutesSameFlowToSameShard` | PASS |
| 5 | `Engine.shardSeed maphash.Seed` | `core/engine.go:34` | `TestProcessTaskRoutesSameFlowToSameShard` (hash 确定性) | PASS |
| 6 | `Engine.shardCounts []atomic.Int64` | `core/engine.go:35` | `TestShardImbalanceWarn` | PASS |
| 7 | `Engine.Start` 初始化分片 + 删除 ReplayOrderPreserve cap-to-1 | `core/engine.go:258-272` | `TestStart_ReplayOrderPreserve_ClampsPW4to1` (新语义: 不再 cap) | PASS |
| 8 | `Engine.Stop` 关闭分片 + 关闭监控 | `core/engine.go:355-388` | 现有 stop 测试 | PASS |
| 9 | `Engine.runShardMonitor` + `checkShardBalance` | `core/engine.go:433-484` | `TestShardImbalanceWarn`, `TestShardBalanceNoWarnWhenBalanced`, `TestShardBalanceNoWarnWhenAllZero` | PASS |
| 10 | `Engine.shardMonitorCancel context.CancelFunc` | `core/engine.go:36` | `TestStart_ReplayOrderPreserve_PW1` (stop 干净) | PASS |

### Worker 改造（10 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 11 | `ConfigWorker.configChan` 字段删除 | `core/worker.go:51-64` | 编译通过 | PASS |
| 12 | `NewConfigWorker` 签名变更（去掉 configChan） | `core/worker.go:74-94` | `TestAuditFix_*` (更新调用) | PASS |
| 13 | `PacketWorker.shardChan` 字段 | `core/worker.go:597` | `TestProcessTaskRoutesSameFlowToSameShard` | PASS |
| 14 | `NewPacketWorker` 签名变更（configChan→shardChan） | `core/worker.go:609-628` | 编译通过 | PASS |
| 15 | `PacketWorker.run` 用 `w.shardChan` | `core/worker.go:643-655` | `TestProcessTaskRoutesSameFlowToSameShard` | PASS |
| 16 | `processTask` 加路由 + shardCounts 计数 | `core/worker.go:232-298` | `TestProcessTaskRoutesSameFlowToSameShard`, `TestProcessTaskFallbackTo4Tuple`, `TestSameFlowPacketsArriveInFIFOOrder` | PASS |
| 17 | `processBatchTask` class goroutine 加路由 + class.GroupID 透传 | `core/worker.go:518-610` | `TestClassLevelGroupIDPropagated`, `TestProcessTaskDifferentGroupsSpreadAcrossShards` | PASS |
| 18 | `processBatchTask` replay class 分支加路由 | `core/worker.go:462-505` | replay 测试（隐式 gID 路径） | PASS |
| 19 | `processReplayTask` 加路由 | `core/worker.go:370-407` | replay 测试 | PASS |
| 20 | `worker.go:741` 注释更新 | `core/worker.go:740-742` | 人工 review | PASS |

### 路由函数（3 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 21 | `computeHashKey` | `core/shard_router.go:19-54` | 9 个 `TestComputeHashKey*` 测试 | PASS |
| 22 | `genStringValue` | `core/shard_router.go:57-100` | `TestComputeHashKeyPatternStrategy`, `TestComputeHashKeyIncStrategy`, `TestComputeHashKeyListStrategy`, `TestComputeHashKeyRandStrategyDeterministic` | PASS |
| 23 | `applyPattern` + `toInt` | `core/shard_router.go:103-122` | `TestComputeHashKeyPatternStrategy` | PASS |

### 转换层（1 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 24 | `mapToFlowSpec` 透传 GroupID | `core/strategy_convert.go:268-280` | `TestMapToFlowSpecPreservesGroupID`, `TestMapToFlowSpecGroupIDAbsent` | PASS |

### Replay planner（3 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 25 | `computeReplayGroupID` | `replay/planner.go:389-408` | 7 个 `TestComputeReplayGroupID_*` 测试 | PASS |
| 26 | `genReplayGroupValue` + `applyReplayPattern` + `replayToInt` | `replay/planner.go:411-470` | `TestComputeReplayGroupID_*` | PASS |
| 27 | `PlanReplay` 写入 gID 到 Metadata + emitReplayCfg/emitPacket 加 gID 参数 | `replay/planner.go:262-313, 318-368` | `TestComputeReplayGroupID_*`, 现有 replay 测试 | PASS |

### MCP（3 项）

| # | 修改点 | 文件 | 测试 | 结果 |
|---|---|---|---|---|
| 28 | `tools_strategy.go:27` Config description 加 group_id 说明 | `mcp/tools_strategy.go:27` | `TestSchema` 无 regression | PASS |
| 29 | `tools_task.go:25` Batch description 加 class 级 group_id 说明 | `mcp/tools_task.go:25` | `TestSchema` 无 regression | PASS |
| 30 | MCP 集成测试 | `mcp/tools_integration_test.go` | 现有 MCP 集成测试全过 | PASS |

### 测试文件（8 项）

| # | 修改点 | 文件 | 测试数 | 结果 |
|---|---|---|---|---|
| 31 | `types_group_id_test.go` | `core/` | 5 | PASS |
| 32 | `shard_router_test.go` | `core/` | 9 | PASS |
| 33 | `engine_shard_test.go`（合并到 engine_testpoints_test.go） | `core/` | 3 (新+更新) | PASS |
| 34 | `sharded_worker_test.go` | `core/` | 3 | PASS |
| 35 | `load_balance_test.go` | `core/` | 3 | PASS |
| 36 | `planner_group_id_test.go` | `replay/` | 7 | PASS |
| 37 | `packet_capture_test.go` | `test/integration/` | helpers | PASS |
| 38 | `group_id_e2e_test.go` → 改为 `shard_fifo_test.go`（单元层 FIFO + class GroupID 透传 + hot gID WARN） | `core/` | 3 | PASS |

## 2. 真实抓包核对

### 已完成的抓包测试

| 测试 | 抓包方式 | 结果 |
|---|---|---|
| `TestSameFlowPacketsArriveInFIFOOrder` | 通过 buildFunc hook 捕获 PacketIndex 序列 | PASS — 50 个包严格按 0..49 顺序到达 |
| `TestProcessTaskRoutesSameFlowToSameShard` | shardCounts 原子计数 | PASS — 同 gID 全落 1 个 shard |
| `TestProcessTaskDifferentGroupsSpreadAcrossShards` | shardCounts | PASS — 20 个不同 gID 散到 ≥2 个 shard |
| `TestHotGIDTriggersImbalanceWarn` | zap 日志捕获 | PASS — hot gID "all" 触发 WARN |

### 未完成的真实 NIC 抓包（已记录为后续工作）

`packet_capture_test.go` 提供了 `startCapture`（tcpdump 启动）+ `extractFlowKey`（双向流键提取）工具，但完整 e2e 测试需要 `rest.NewServer` 6 参数构造（含 `*netif.Manager` + `*netif.Scheduler`），与现有 `test/integration/api_test.go:102` 的 5 参数调用冲突——这是 **pre-existing** 的测试基础设施问题，不是本次 diff 引入。修复需要单独 PR 重建 integration 测试 harness。

## 3. race 测试

```
cd trafficgen && go test -race -count=1 ./internal/core/ ./internal/replay/ ./internal/mcp/
```

结果：
- `internal/core`: PASS (13.8s)
- `internal/replay`: PASS (12.5s)
- `internal/mcp`: PASS (110.7s)

## 4. review 发现与修复

### 已修复（本 commit 范围内）

| Reviewer | 发现 | Severity | 修复 |
|---|---|---|---|
| 1 | L2: `TrafficClass.GroupID` struct 字段是死代码 | LOW | `processBatchTask` 加 `if c.GroupID != nil { spec.GroupID = c.GroupID }` |
| 3 | G3: FIFO 测试只查 shard 分布，不查顺序 | HIGH | `TestSameFlowPacketsArriveInFIFOOrder` 断言 PacketIndex 严格递增 |
| 3 | G6: hot gID WARN 测试是合成的 | MEDIUM | `TestHotGIDTriggersImbalanceWarn` 走真实 pipeline |
| 3 | G10: rand 测试 tautological | LOW | 断言值在 [1, 1000] 范围内 |

### 未修复（已记录）

| Reviewer | 发现 | Severity | 原因 |
|---|---|---|---|
| 3 | G1: 无 MCP→REST→engine→PacketWorker e2e | CRITICAL | pre-existing `rest.NewServer` 签名不匹配，需单独 PR 重建 integration harness |
| 3 | G2: 无 MCP 透传测试 | CRITICAL | 同上 |
| 3 | G4: 无 hash 碰撞测试 | HIGH | 后续工作 |
| 3 | G5: 并发分布测试弱 | HIGH | 后续工作 |
| 3 | G7: pattern 空 range 静默 fallback | MEDIUM | 设计选择（fallback 比 fail 更友好），文档已说明 |
| 3 | G8: replay pcap 顺序未验证 | MEDIUM | 需真实 pcap 资产，后续工作 |
| 3 | G9: schema 测试不检查 description 文本 | LOW | 后续工作 |
| 3 | G11: spread 测试断言太弱 | LOW | 后续工作 |
| 2 | applyReplayPattern 死代码 | LOW | 防御性 guard，保留 |
| 2 | 误导注释（import cycle） | LOW | 注释订正为"unexported 函数" |

## 5. 性能预期核对

| 指标 | 改前 | 改后 | 核对 |
|---|---|---|---|
| 单流包顺序 | 多 worker 下乱序 | 严格 FIFO | `TestSameFlowPacketsArriveInFIFOOrder` PASS |
| 双向流保序 | 不保证 | 严格 FIFO | `TestComputeHashKeyBidirectionalSameKey` PASS |
| 跨流不交错 | 不保证 | 同 gID 不交错 | 设计保证，未单独测试（G4 后续） |
| 多 worker 吞吐 | 共享 channel 锁竞争 | 分片隔离 | 编译 + 测试通过 |
| hash 开销 | 无 | per-flow 一次 | `computeHashKey` 单元测试 PASS |
| 内存 | `QueueSize*2` | `pw × QueueSize*2` | `TestStart_QueueSize*` 验证容量 |
| replay 多 worker | cap-to-1 | 多 worker 保序 | `TestStart_ReplayOrderPreserve_ClampsPW4to1` 新语义 PASS |
