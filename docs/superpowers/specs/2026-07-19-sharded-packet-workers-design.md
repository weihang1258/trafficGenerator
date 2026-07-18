# 分片 PacketWorker + group_id 跨流保序设计

**日期**: 2026-07-19
**状态**: 设计已确认，待写实现计划
**作者**: weihang + Claude

## 1. 背景与问题

### 1.1 当前 Pipeline（包处理流水线）结构

```
ConfigWorker ×N → 共享 configChan → PacketWorker ×N → 共享 packetChan → OutputWorker
```

- `ConfigWorker`（配置工作协程，把流规格展开成包配置）：N 个并发，push（推送）`PacketConfig`（包配置，单个以太网帧的完整描述）到共享 `configChan`（包配置队列）
- `PacketWorker`（包构建工作协程，把配置转二进制以太帧）：N 个并发，抢占式从共享 `configChan` 拉包
- `OutputWorker`（输出工作协程，写文件/网卡）：从共享 `packetChan`（包输出队列）拉包输出

### 1.2 问题：多 PacketWorker 下的流内乱序

N 个 PacketWorker 抢同一个共享 `configChan`，谁空闲谁拿下一个 `PacketConfig`。同一个 flow（流）的多个包可能被分到不同 worker 并发处理，而每个 worker 内部有 rate-limiter（限速器）`Wait`（令牌桶等待函数）、build（构建）耗时差异，**先拉的不一定先出**——`packetChan` 里同一个 flow 的包乱序。

代码证据：
- `worker.go:741` 注释："Resequencing is not currently used because a single PacketWorker guarantees ordering. If multiple PacketWorkers are configured in the future, resequencing will be needed."
- `engine.go:287` `ReplayOrderPreserve`（回放保序标志）：replay（pcap 回放）场景强行把 PacketWorker 数 cap（强制限制）到 1 保 pcap 顺序——反向证据，证明多 worker 无法保序。

### 1.3 问题：多流协议的跨流时序耦合

单流保序不够。多流协议（SIP 信令 + RTP 数据、RTSP + 媒体、FTP 控制 + 数据）要求：
- 信令流建立会话后数据流才能发
- 信令流拆除前数据流必须停
- 数据流的包周期必须在信令流生命周期内

按 4 元组（源/目的 IP + 源/目的端口）hash（哈希，把输入映射到固定整数的函数），信令流和数据流分到不同 worker，两个 worker 独立调度会让数据包跨过信令包先出，业务层时序错乱。

## 2. 设计目标

1. **流内保序**：同一条 flow 的所有包按生成顺序出
2. **跨流保序**：业务上绑定的多条流（如信令 + 数据）按业务时序交错出
3. **不牺牲并行吞吐**：不绑定的流仍然散到多 worker 并行
4. **扩展性**：支持一对一、一对多、多对多绑定场景
5. **replay 兼容**：replay 路径同样支持 `group_id`，且 pcap 顺序保住
6. **MCP 兼容**：MCP（Model Context Protocol，模型上下文协议）工具同步支持

## 3. 核心设计

### 3.1 分片 Channel（Sharded Channel）

把单个共享 `configChan` 改成 N 个分片 `shardedConfigChan[i]`（分片包配置队列数组，每 worker 对应一个）。

```
ConfigWorker ×N
    │
    │ push 前：算 shardIdx（分片编号）= hash(路由键) % N
    │         路由键优先级：group_id > 无序4元组 > replay隐式gID
    ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│shard[0]  │ │shard[1]  │ │shard[2]  │
│chan      │ │chan      │ │chan      │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│PacketW0  │ │PacketW1  │ │PacketW2  │
│单goroutine│ │单goroutine│ │单goroutine│
│串行 FIFO  │ │串行 FIFO  │ │串行 FIFO  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     └────────────┼────────────┘
                  ▼
            packetChan（合并输出队列）
                  ▼
            OutputWorker
```

**关键性质**：
- 每个 PacketWorker 只读自己的分片，单 goroutine 串行处理 → 出包 FIFO
- 同路由键的包永远落同一分片 → 流内 + 跨流保序
- 不同路由键的包散到不同分片 → 并行吞吐不退化
- 无锁：分片间完全隔离，无共享 channel 的 mutex（互斥锁）竞争

### 3.2 路由键算法

对每个 `PacketConfig`，ConfigWorker push 前按以下优先级算路由键：

1. **`group_id` 非空**：`hashKey = group_id`（分组标识字符串）
2. **`group_id` 空且 synth（合成流量）**：`hashKey = 无序4元组`（`{min(src,dst), max(src,dst), min(sport,dport), max(sport,dport)}`，把源/目的互换算同一个 hash，保证双向流落同 worker）
3. **`group_id` 空且 replay**：`hashKey = taskID + ":" + classID`（隐式 gID，整资产绑同一 worker，保 pcap 顺序）

`shardIdx = maphash(hashKey, seed) % N`，其中 seed（种子）是 engine 启动时随机生成的 `hash/maphash.Seed`（Go 标准库运行时 hash 的种子类型）。

### 3.3 `group_id` 作为策略字段

`group_id` 不是固定字符串，而是 `StrategyConfig`（值生成策略配置，支持 fixed/inc/rand/pattern/list 模式）。每条 flow（流）由 ConfigWorker 调 `ValuePattern`/`ValueInc`/`ValueRandom`/`ValueList`（值生成器组件）按 flowIdx（流序号）生成一个 gID（分组标识字符串）。

**配置示例**：

```yaml
batch:
  classes:
    - id: sip_call
      type: tcp
      flow_count: 100
      group_id:
        strategy: pattern              # 模式生成
        pattern: "call-{n}"
        n_range: [1, 100]
      tuples: { ... }

    - id: rtp_media
      type: udp
      flow_count: 100
      group_id:
        strategy: pattern              # 相同策略
        pattern: "call-{n}"
        n_range: [1, 100]
      tuples: { ... }
```

两个 class（流量类别）写**完全相同的策略**，第 k 条流两边生成同样的 gID（如 `call-7`），自然绑到同一 worker。

**多流协议覆盖能力**：

| 场景 | 配置方式 | 行为 |
|---|---|---|
| 一对一（1 控制 + 1 数据） | 两 class 同策略、同 `flow_count`、同 `n_range` | 第 k 条流同 gID，绑同 worker |
| 一对多（1 控制 + N 数据） | 数据 class 用更大 `flow_count`，`n_range` 会自动回绕（wrap，从头再来） | 多个数据流共享同一 gID |
| 多对多（M 控制 + N 数据） | 所有 class 同策略、同 `n_range` | 同 gID 跨多 class 绑同 worker |
| 不绑的流 | 不写 `group_id` | fallback 4 元组 hash，散开并行 |

### 3.4 关键不变量

1. **同 gID 的所有包 → 同 PacketWorker**（hash 函数确定 + worker 只读自己分片）
2. **同 worker 单 goroutine 串行** → 出包顺序 = ConfigWorker push 顺序
3. **ConfigWorker push 顺序 = 业务时序**（用户在 spec 里按时序声明，planner 按时序生成包）→ 跨流时序自动正确
4. **无 `group_id` 的流走 4 元组 hash** → 单流保序、跨流不绑 → 并行吞吐不退化
5. **replay 留空 `group_id`** → 整资产绑一个 worker → pcap 顺序保住

## 4. 数据结构变更

### 4.1 `FlowSpec`（流规格，`core/types.go`）

```go
type FlowSpec struct {
    // ...existing fields...
    GroupID StrategyConfig `json:"group_id,omitempty"`
}
```

### 4.2 `TrafficClass`（流量类别，`core/types.go`）

```go
type TrafficClass struct {
    // ...existing fields...
    GroupID StrategyConfig `json:"group_id,omitempty"`
}
```

### 4.3 `ReplaySpec`（回放规格，`replay/types.go`）

```go
type ReplaySpec struct {
    // ...existing fields...
    GroupID core.StrategyConfig `json:"group_id,omitempty"`
}
```

### 4.4 `PacketConfig`（包配置，`core/types.go`）

不改 struct 字段，通过 `Metadata`（元数据 map）传递：

- `Metadata["group_id"]`（string）：ConfigWorker 写入，路由层 + 调试用
- `Metadata["shard_idx"]`（int）：per-flow 算一次后写入，后续 push 直读，避免 per-packet 重算

**注**：`shard_idx` 实际上只在 ConfigWorker push 时用一次（决定 push 到哪个分片），PacketWorker 接收后不需要再读它。保留在 Metadata 是为调试和监控（可从包元数据看出它走了哪个分片）。

## 5. 路由层变更

### 5.1 `Engine` 结构体新增字段

```go
type Engine struct {
    // ...existing fields...
    shardedConfigChan []chan PacketConfig  // 分片数组，长度 = pw（实际 PacketWorker 数）
    shardSeed         maphash.Seed        // 随机种子，防 hash flooding
}
```

`Engine.Start`（引擎启动函数，`engine.go:240`）初始化（含删除 `ReplayOrderPreserve` cap-to-1 逻辑，见 §8.3）：

```go
// 改前
e.configChan = make(chan PacketConfig, e.config.QueueSize*2)
pw := e.config.PacketWorkers
if e.config.ReplayOrderPreserve && pw > 1 {
    pw = 1  // 旧逻辑：cap worker 数
}
e.packetWorkers = make([]*PacketWorker, pw)
for i := 0; i < pw; i++ {
    worker := NewPacketWorker(i, e.configChan, e.packetChan, buildFn, &e.wg, e)
    // ...
}

// 改后
e.shardSeed = maphash.MakeSeed()
pw := e.config.PacketWorkers
// 删除 ReplayOrderPreserve cap-to-1（见 §8.3：replay 留空 group_id 走隐式 gID 保 pcap 顺序，不需要 cap）
e.shardedConfigChan = make([]chan PacketConfig, pw)
for i := 0; i < pw; i++ {
    e.shardedConfigChan[i] = make(chan PacketConfig, e.config.QueueSize*2)  // 每分片容量 = 改前共享容量
}
e.packetWorkers = make([]*PacketWorker, pw)
for i := 0; i < pw; i++ {
    worker := NewPacketWorker(i, e.shardedConfigChan[i], e.packetChan, buildFn, &e.wg, e)
    // ...
}
```

每分片容量 = 改前共享 `configChan` 容量（`QueueSize*2`），总容量 = `pw × QueueSize×2`。内存增幅几 MB。理由见 §6.2。

### 5.2 `ConfigWorker`（配置工作协程）结构体

```go
type ConfigWorker struct {
    // ...existing fields...
    // shardedConfigChan 和 shardSeed 通过 engine 引用读，不复制到 ConfigWorker
    // （ConfigWorker 已有 engine *Engine 字段，见 worker.go:63）
}
```

无需新增字段——`ConfigWorker` 已持有 `engine *Engine`（`worker.go:63`），通过 `w.engine.shardedConfigChan` 和 `w.engine.shardSeed` 访问。

### 5.3 `PacketWorker`（包构建工作协程）结构体

```go
type PacketWorker struct {
    // ...existing fields...
    shardChan <-chan PacketConfig  // 新增：自己的分片
}
```

`NewPacketWorker`（构造函数，`worker.go:609`）签名改为接收 `shardChan <-chan PacketConfig` 而非共享 `configChan`。`Engine.Start` 在创建每个 PacketWorker 时传入 `e.shardedConfigChan[i]`。

### 5.4 `processTask` / `processBatchTask` / `processReplayTask`（任务处理函数）

在 push 前加路由逻辑。**per-flow（每流一次）**：在 `planner.Plan` 返回 `configChan` 之前，由 ConfigWorker 算一次 `shardIdx`，写入该流所有包的 `Metadata["shard_idx"]`。**注意**：由于 `planner.Plan` 返回的是 `<-chan PacketConfig`（只读 channel），ConfigWorker 无法在包进入 channel 前注入 `shardIdx`——需在**接收循环内**逐包写入（仍是一次 hash 计算 + N 次写 map，开销远小于 per-packet hash）：

```go
// 在 planner.Plan 返回 configChan 后，进入 for config := range configChan 循环前
// 算一次 shardIdx（per-flow，不是 per-packet）
hashKey := computeHashKey(spec, task)  // group_id > 4元组 > 隐式gID
shardIdx := int(maphash.String(hashKey, w.engine.shardSeed) % uint64(len(w.engine.shardedConfigChan)))

// 接收循环内逐包写入 Metadata（hash 只算了一次）
for config := range configChan {
    if config.Metadata == nil {
        config.Metadata = make(map[string]interface{})
    }
    config.Metadata["shard_idx"] = shardIdx
    config.Metadata["group_id"] = gID  // 可能为空字符串（fallback 路径）

    select {
    case <-taskCtx.Done():
        for range configChan {}  // drain（排空剩余包配置）
        // ...existing cancel handling...
        return
    case w.engine.shardedConfigChan[shardIdx] <- config:
        // ...
    }
}
```

`computeHashKey`（路由键计算函数）逻辑：
1. 若 `spec.GroupID.Strategy != ""`：调 `ValuePattern`/`ValueInc`/`ValueRandom`/`ValueList` 按 flowIdx 生成 gID，返回 gID
2. 若 synth 任务且 `spec.GroupID.Strategy == ""`：返回 `min(src,dst)+"-"+max(src,dst)+"-"+min(sport,dport)+"-"+max(sport,dport)`
3. 若 replay 任务且 `spec.GroupID.Strategy == ""`：返回 `task.ID + ":" + task.ClassID`（隐式 gID）

**per-flow 而非 per-packet 的关键**：`shardIdx` 在进入接收循环前算一次，循环内只写 map 不重算 hash。同一条流的所有包共享同一个 `shardIdx`。

### 5.5 `PacketWorker.run` 主循环

```go
// 改前
case config, ok := <-w.configChan:

// 改后
case config, ok := <-w.shardChan:
```

其余 build / rate-limit / push 逻辑不变。`shardChan` 在 `NewPacketWorker` 时由 `Engine.Start` 传入 `e.shardedConfigChan[i]`。

### 5.6 `Engine.Stop` 关闭分片 channel

`engine.go:334` 当前 `close(e.taskChan)` 让 ConfigWorker 退出。改后还需关闭所有分片 channel 让 PacketWorker 退出：

```go
// Engine.Stop 内
close(e.taskChan)
// ...等待 ConfigWorker 退出...
for i := range e.shardedConfigChan {
    close(e.shardedConfigChan[i])
}
// ...等待 PacketWorker 退出...
```

关闭顺序：先 `taskChan`（停止新任务进入）→ 等 ConfigWorker 退出（保证所有 push 已完成）→ 再 `close(shardedConfigChan[i])`（让 PacketWorker 的 `for config := range` 退出）→ 等 PacketWorker 退出。

## 6. hash 与路由策略

| 维度 | 选择 | 理由 |
|---|---|---|
| hash 函数 | `hash/maphash`（Go 标准库） | 零依赖、性能最优、带 seed 防碰撞 |
| 计算位置 | per-flow（每流一次） | 流数远小于包数，性能最优 |
| 路由 key 优先级 | `group_id` > 无序4元组 > replay隐式gID | 显式声明优先于隐式 |
| 分片容量 | 每分片 `QueueSize*2`（= 改前共享容量） | 总容量 ×N（几 MB），抗局部背压；与改前共享 channel 容量一致，避免改变背压行为 |
| push 阻塞 | `select` + `ctx.Done()` | 避免永久阻塞，支持优雅停止 |

### 6.1 为什么 per-flow 而非 per-packet

一条 TCP 流可能有几十上百个包。per-packet 每包算一次 hash，per-flow 只算一次。`shardIdx` 在进入 `planner.Plan` 返回的 `configChan` 接收循环前算一次，循环内只写 `Metadata["shard_idx"]`（map 写，无 hash 计算），开销从 O(packet_count) 降到 O(flow_count)。

### 6.2 为什么每分片 `QueueSize*2` 而非 `QueueSize*2 / N`

- **方案 A**（每分片 `QueueSize*2`，推荐）：每分片容量 = 改前共享 `configChan` 容量，总容量 = `N × QueueSize×2`（假设 `QueueSize=4096`、N=8，32768 个 `PacketConfig` 槽位，约几 MB），任一分片满不影响其他分片生产
- **方案 B**（每分片 `QueueSize*2 / N`）：总容量不变，但任一分片满会阻塞 ConfigWorker 串行 push 该 class 的所有包（包括其他分片的）

ConfigWorker 是串行 push 模型，方案 B 的"一分片满全卡"问题严重——某 worker 慢（rate limiter 卡住）会拖累所有 class。方案 A 让分片间真正隔离，且保持与改前相同的单分片背压行为（不会因为分片容量变小而更早触发背压）。

## 7. 负载均衡

### 7.1 不做动态 rebalance（重新平衡）

动态 rebalance 会破坏保序（保序前提是同 gID 永远同 worker）。改用**静态 hash + 监控告警**。

### 7.2 监控告警机制

每个分片维护 `atomic.Int64`（原子计数器）记录入队数。engine 启动一个后台 goroutine（Go 协程）周期采样（默认 10s），发现严重不均（某分片包数 > 平均值 × 3）打 WARN 日志：

```
zap.L().Warn("shard load imbalance detected",
    zap.Int("shard_idx", i),
    zap.Int64("packets", count),
    zap.Int64("avg", avg),
    zap.String("hint", "consider checking group_id strategy distribution"),
)
```

### 7.3 hot gID（热分组标识）问题

用户配置 `group_id: { strategy: fixed, value: "all" }`（所有流绑一个 gID）→ 全落一个 worker，吞吐退化到 1/N。这是用户配置问题，系统检测后打 WARN 提示，由用户负责修正。

## 8. replay 路径特殊处理

### 8.1 `group_id` 在 replay 的语义

`ReplaySpec.GroupID`（`core.StrategyConfig`）由 `ReplayPlanner.PlanReplay`（回放规划器实现，`replay/planner.go:63`）内部生成：

1. `PlanReplay` 解析 `ReplaySpec.GroupID`
2. 如果 `FlowScaling`（流放大配置）存在：每个 clone（克隆）用 `ValuePattern`/`ValueInc` 按 clone 索引推进生成 gID，**同一个 clone 的所有包共享该 clone 的 gID**
3. 如果 `FlowScaling` 不存在：整个资产视为单一 "clone 0"，按 `group_id` 策略生成一个 gID（或留空），所有包共享
4. 每个包的 `PacketConfig.Metadata["group_id"]` 写入该 gID

### 8.2 三种 replay 场景

| 场景 | 用户配置 | 路由行为 |
|---|---|---|
| 单资产单实例 replay | `group_id` 留空 | 整资产所有包用隐式 gID（`taskID+classID`），全落同 worker，保 pcap 顺序 |
| 单资产多实例 replay（flow_scaling 放大） | `group_id` 留空 | 每 clone 一个隐式 gID（`taskID+classID+cloneIdx`），clone 间散开并行；同 clone 内保 pcap 顺序 |
| 多资产 replay 绑定 | 两个 task/class 写相同 `group_id` 策略 | 同 gID 落同 worker，跨资产保跨流时序 |

### 8.3 `ReplayOrderPreserve` 向后兼容

`ReplayOrderPreserve` 字段语义变更：

| `ReplayOrderPreserve` 值 | 旧行为（改前） | 新行为（改后） |
|---|---|---|
| `true`（默认） | 强制 PacketWorker=1，cap worker 数 | **不再 cap worker 数**——保留字段但 cap 逻辑移除；replay 留空 `group_id` 时走隐式 gID（`taskID+classID`）保 pcap 顺序，多 worker 并行可用 |
| `false` | 多 worker 乱序 replay（用户接受乱序） | 行为不变——多 worker 乱序 replay（用户接受乱序） |

**关键决策**：删除 `engine.go:287` 的 `if e.config.ReplayOrderPreserve && pw > 1 { pw = 1 }` 强限制。replay 留空 `group_id` 时，所有包走隐式 gID（`taskID+classID`）→ `hash(taskID+classID) % pw` → 全部落同一 worker → 保 pcap 顺序，**不需要 cap worker 数**。`ReplayOrderPreserve=false` 时行为不变（用户显式接受乱序，可配 `group_id` 走分片或留空走隐式 gID）。

字段保留作向后兼容：旧配置 `ReplayOrderPreserve=true` 仍然保 pcap 顺序（通过隐式 gID 实现，而非 cap worker 数）。

## 9. MCP（模型上下文协议）同步

### 9.1 MCP 透传机制

MCP 工具的 input 类型对 `Config`/`Batch` 用 `map[string]interface{}`（Go 任意类型 map）透传给 REST handler（REST 请求处理函数），REST 反序列化成 `FlowSpec`/`core.BatchSpec`。加 `GroupID` 字段后，MCP 用户在 `Config`/`Batch` 里写 `group_id` 字段会**自动被 REST 反序列化捡起来**，无需改 MCP 代码。

### 9.2 文档更新（必做）

更新 `jsonschema`（JSON Schema，描述 JSON 结构的元数据）description（描述文本）：

- `tools_strategy.go:27` `Config` description 加一句："`group_id`（可选）：分组标识策略，相同 `group_id` 的流绑同一 worker 保跨流时序；不写则按 4 元组 hash 散开"
- `tools_task.go:25` `Batch` description 加一句："每个 class 可选 `group_id` 字段，标记需要跨流保序绑定的流组"
- replay 路径（`Mode="replay"` 时 `Config` 是 `ReplaySpec`）同理

### 9.3 测试验证（必做）

- `tools_schema_test.go`（MCP schema 测试）：跑测试确认 schema 无 regression（回归）
- `tools_integration_test.go`（MCP 集成测试）：加用例——通过 MCP 工具创建带 `group_id` 的策略/批量任务，验证包能正确生成并路由到同一 worker（MCP → REST → engine → PacketWorker 全链路）

### 9.4 不做的事

- 不在 MCP input 类型里把 `group_id` 提升为顶层字段——它属于 `Config`/`Batch` 内部业务字段，提升会破坏现有"strategy config 透传"的设计模式
- 不在 MCP 层做 `group_id` 校验——校验归 REST handler 和 `Validate`（协议规划器的校验方法），MCP 保持薄透传

## 10. 改动规模

### 10.1 新增

- 3 个字段：`FlowSpec.GroupID`、`TrafficClass.GroupID`、`ReplaySpec.GroupID`（均为 `StrategyConfig` 类型）
- 0 个新类型、0 个新组件（全复用现有 `StrategyConfig`/`ValuePattern`/`ValueInc`/`ValueRandom`/`ValueList`）

### 10.2 修改

- `Engine.Start`：单 channel 改分片数组，加 `shardSeed`
- `ConfigWorker`/`PacketWorker` 结构体：持有分片引用
- `processTask` / `processBatchTask` / `processReplayTask`：加路由逻辑（per-flow 算 `shardIdx`，写入 `Metadata`）
- `PlanReplay`：加 gID 生成
- MCP 2 个 description 文本 + 加集成测试

### 10.3 删除

- `engine.go:287` 的 `ReplayOrderPreserve` cap-to-1 强限制（字段保留作向后兼容）

## 11. 测试策略（遵循 CLAUDE.md 测试政策）

### 11.1 Spec-driven 测试派生

从本 spec 第 3、5、8 节派生测试：

- §3.1 分片 channel：测每个 worker 只读自己分片
- §3.2 路由键：测三种优先级（group_id > 4元组 > 隐式gID）
- §3.3 策略字段：测 pattern/inc/rand/list 四种模式生成 gID
- §3.4 不变量：5 条不变量每条至少一个测试
- §5 路由层：测 hash 函数确定性、per-flow 缓存、push 阻塞
- §8 replay：测三种场景 + `ReplayOrderPreserve` 向后兼容

### 11.2 失败路径测试

- `group_id` 策略配置错误（如 pattern 语法错）→ 任务失败
- 分片满了 + ctx 取消 → 优雅排空，无 goroutine 泄漏
- hot gID 检测 → WARN 日志正确触发

### 11.3 集成测试（MCP → REST → engine → PacketWorker）

- 通过 MCP 创建带 `group_id` 的策略 → 启动任务 → 验证同 gID 包落同 worker
- 通过 MCP 创建批量任务（多 class 同 `group_id` 策略）→ 验证跨流时序
- replay 任务带 `group_id` → 验证 pcap 顺序 + 跨资产绑定

### 11.4 并发测试（验证正确性，不只 race-safety）

- N 个 ConfigWorker 并发 push 不同 gID → 验证分片分布均匀
- 同 gID 的包并发生成 → 验证严格 FIFO（用 `PacketIndex` 检查出包顺序）
- `-race` 标志跑全部测试

### 11.5 Adversarial 测试审计

测试写完后按 CLAUDE.md 第 8 条做 adversarial review（对抗性审查）：
- 每个测试问：测的是不是 spec 要求的行为？
- 是否有 spec 行/字段没对应测试？
- 是否只测了 happy path？
- 并发测试是否验证了正确性（不只 race-safety）？

## 12. 代码审查政策（遵循 CLAUDE.md 代码修改政策）

每次代码修改后：

1. **先 review 改动**：读 diff 和实际文件，检查 race/deadlock/double-close/nil-deref/off-by-one、漏掉的 call site（调用点）、regression、resource leak（资源泄漏）
2. **再跑测试**：`go build ./...` + `go vet ./...` + `go test -race ./...`
3. **bug 修复也要 review**：每个 fix（修复）本身是代码修改，必须 review
4. **非平凡改动用并行 reviewer**：分片 channel 改动 + replay 改动 + MCP 改动可并行 review，每个 finding（发现）做 adversarial verification（对抗性验证，尝试反驳）

## 13. 性能预期

| 指标 | 改前 | 改后 |
|---|---|---|
| 单流包顺序 | 多 worker 下乱序 | 严格 FIFO |
| 跨流时序（多流协议） | 无法保证 | 业务时序保住 |
| 多 worker 吞吐 | 受限于共享 channel 锁竞争 | 分片隔离，锁竞争消除 |
| hash 开销 | 无 | per-flow 一次，可忽略 |
| 内存 | `QueueSize` | `N × QueueSize`（几 MB） |
| replay 多 worker | cap-to-1 限制 | 支持多 worker，保 pcap 顺序 |
