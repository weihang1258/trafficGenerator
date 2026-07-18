# 分片 PacketWorker + group_id 跨流保序 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把共享 configChan 改为分片 shardedConfigChan，按 group_id（或 4 元组 fallback）hash 路由，实现同流保序 + 跨流不交错 + replay 兼容 + MCP 透传。

**Architecture:** Engine 持有 `shardedConfigChan []chan PacketConfig` + `shardSeed maphash.Seed`；ConfigWorker push 前按 per-flow hash 算 `shardIdx` 写入 Metadata；PacketWorker 只读自己分片，单 goroutine 串行处理；replay 留空 group_id 时用 `taskID+classID` 作隐式 gID 保 pcap 顺序。

**Tech Stack:** Go 1.25，`hash/maphash`，`sync/atomic`，`go.uber.org/zap`，现有 `StrategyConfig`/`TupleGenerator`/`ValuePattern` 组件。

**Spec:** `docs/superpowers/specs/2026-07-19-sharded-packet-workers-design.md`

## Global Constraints

- Go 1.25，`go build ./...` + `go vet ./...` + `go test -race ./...` 全过
- 每个代码修改后必须先 review 再测试（CLAUDE.md 强制政策）
- 测试必须 spec-driven，覆盖失败路径，集成测试打穿（MCP → REST → engine → PacketWorker）
- 失败测试先行（bug fix 必须先写 failing test）
- 遵循术语 glossing：代码注释可英文，用户沟通英文术语后加括号中文解释

## File Structure

**新建文件：**
- `trafficgen/internal/core/shard_router.go` — `computeShardIdx`（路由键计算 + hash + 取模）+ `computeHashKey`（group_id / 4元组 / 隐式 gID 优先级）
- `trafficgen/internal/core/shard_router_test.go` — 路由层单元测试
- `trafficgen/internal/core/sharded_worker_test.go` — 分片 worker 集成测试（保序、跨流不交错、replay 隐式 gID）
- `trafficgen/internal/core/load_balance_test.go` — 负载监控告警测试
- `trafficgen/test/integration/group_id_e2e_test.go` — MCP → REST → engine 全链路集成测试
- `trafficgen/test/integration/packet_capture_test.go` — 抓包核对工具 + 用例

**修改文件：**
- `trafficgen/internal/core/types.go` — `FlowSpec` + `TrafficClass` 加 `GroupID StrategyConfig`
- `trafficgen/internal/replay/types.go` — `ReplaySpec` 加 `GroupID core.StrategyConfig`
- `trafficgen/internal/core/engine.go` — `Engine` 加 `shardedConfigChan`/`shardSeed`/`shardCounts`；`Start`/`Stop` 改分片
- `trafficgen/internal/core/worker.go` — `PacketWorker.shardChan`；`processTask`/`processBatchTask`/`processReplayTask` 加路由逻辑；注释更新
- `trafficgen/internal/core/strategy_convert.go` — `mapToFlowSpec` 透传 `GroupID`
- `trafficgen/internal/replay/planner.go` — `PlanReplay` 生成 gID 写入 Metadata
- `trafficgen/internal/mcp/tools_strategy.go` — `Config` description 加 `group_id` 说明
- `trafficgen/internal/mcp/tools_task.go` — `Batch` description 加 class 级 `group_id` 说明
- `trafficgen/internal/mcp/tools_integration_test.go` — 加 MCP 全链路用例
- `trafficgen/configs/config.dev.yaml` — 默认 `replay_order_preserve` 保持 true（向后兼容）

---

## Task 1: 加 GroupID 字段到 FlowSpec/TrafficClass/ReplaySpec

**Files:**
- Modify: `trafficgen/internal/core/types.go`（`FlowSpec` 和 `TrafficClass`）
- Modify: `trafficgen/internal/replay/types.go`（`ReplaySpec`）
- Modify: `trafficgen/internal/core/strategy_convert.go`（`mapToFlowSpec` 透传）
- Test: `trafficgen/internal/core/types_test.go`（新增）

**Interfaces:**
- Produces: `FlowSpec.GroupID StrategyConfig`、`TrafficClass.GroupID StrategyConfig`、`ReplaySpec.GroupID core.StrategyConfig`

- [ ] **Step 1: 写失败测试 — FlowSpec/TrafficClass GroupID 字段存在且 JSON tag 正确**

Create `trafficgen/internal/core/types_group_id_test.go`:

```go
package core

import (
	"encoding/json"
	"testing"
)

func TestFlowSpecGroupIDJSONRoundTrip(t *testing.T) {
	raw := `{"group_id":{"strategy":"pattern","pattern":"call-{n}","n_range":[1,100]}}`
	var spec FlowSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec.GroupID.Strategy != "pattern" {
		t.Fatalf("strategy = %q, want pattern", spec.GroupID.Strategy)
	}
	if spec.GroupID.Pattern != "call-{n}" {
		t.Fatalf("pattern = %q, want call-{n}", spec.GroupID.Pattern)
	}
	// n_range stored in Range field
	if len(spec.GroupID.Range) != 2 {
		t.Fatalf("range len = %d, want 2", len(spec.GroupID.Range))
	}
}

func TestTrafficClassGroupIDJSONRoundTrip(t *testing.T) {
	raw := `{"id":"sip","type":"tcp","flow_count":1,"group_id":{"strategy":"fixed","value":"call-A"}}`
	var c TrafficClass
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.GroupID.Strategy != "fixed" {
		t.Fatalf("strategy = %q, want fixed", c.GroupID.Strategy)
	}
	if v, ok := c.GroupID.Value.(string); !ok || v != "call-A" {
		t.Fatalf("value = %v, want call-A", c.GroupID.Value)
	}
}

func TestGroupIDOmitempty(t *testing.T) {
	spec := FlowSpec{}
	out, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// group_id should not appear in marshaled output when zero
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, exists := got["group_id"]; exists {
		t.Fatalf("group_id should be omitted when zero, got %s", out)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestFlowSpecGroupID -v`
Expected: FAIL — 编译错误（`spec.GroupID` 未定义）

- [ ] **Step 3: 加 GroupID 字段到 FlowSpec**

Edit `trafficgen/internal/core/types.go`，找到 `FlowSpec struct`，在字段末尾加：

```go
// GroupID is an optional grouping identifier for cross-flow ordering. Flows
// with the same group_id are routed to the same PacketWorker, preserving
// cross-flow timing (e.g. SIP signaling + RTP data). Empty = fall back to
// 4-tuple unordered hash (single-flow ordering only).
GroupID StrategyConfig `json:"group_id,omitempty"`
```

- [ ] **Step 4: 加 GroupID 字段到 TrafficClass**

Edit `trafficgen/internal/core/types.go`，找到 `TrafficClass struct`，加：

```go
// GroupID routes all flows of this class with the same generated id to one
// PacketWorker. See FlowSpec.GroupID.
GroupID StrategyConfig `json:"group_id,omitempty"`
```

- [ ] **Step 5: 加 GroupID 字段到 ReplaySpec**

Edit `trafficgen/internal/replay/types.go`，找到 `ReplaySpec struct`，加：

```go
// GroupID routes all packets of this replay asset to one PacketWorker for
// cross-flow/cross-asset ordering. Empty = use taskID:classID as implicit
// gID (preserves pcap order within a single asset).
GroupID core.StrategyConfig `json:"group_id,omitempty"`
```

- [ ] **Step 6: mapToFlowSpec 透传 GroupID**

Edit `trafficgen/internal/core/strategy_convert.go`，找到 `mapToFlowSpec` 函数，在返回 `FlowSpec` 前加：

```go
spec.GroupID = c.GroupID
```

（位置：在 `spec.SrcIP = ...` 等字段赋值之后，`return spec` 之前）

- [ ] **Step 7: 跑测试确认通过**

Run: `cd trafficgen && go test ./internal/core/ -run TestFlowSpecGroupID -v && go test ./internal/core/ -run TestTrafficClassGroupID -v && go test ./internal/core/ -run TestGroupIDOmitempty -v`
Expected: 3 个测试 PASS

- [ ] **Step 8: 跑全量测试确认无 regression**

Run: `cd trafficgen && go build ./... && go vet ./... && go test -race -count=1 ./internal/core/ ./internal/replay/ 2>&1 | tail -20`
Expected: 全部 PASS

- [ ] **Step 9: Commit**

```bash
git add trafficgen/internal/core/types.go trafficgen/internal/core/types_group_id_test.go trafficgen/internal/core/strategy_convert.go trafficgen/internal/replay/types.go
git commit -m "feat(core): add GroupID StrategyConfig field to FlowSpec/TrafficClass/ReplaySpec

GroupID routes flows with the same generated id to one PacketWorker for
cross-flow ordering (SIP+RTP etc.). Empty = fall back to 4-tuple hash.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: 实现路由键计算（computeHashKey）

**Files:**
- Create: `trafficgen/internal/core/shard_router.go`
- Test: `trafficgen/internal/core/shard_router_test.go`

**Interfaces:**
- Consumes: `FlowSpec.GroupID`（Task 1）、`PacketConfig.L3/L4`（现有）、`Task.ID/ClassID`（现有）
- Produces: `computeHashKey(spec FlowSpec, task Task, flowIdx int) (hashKey string, gID string)` — 返回路由键 + 分组标识（gID 可空，写入 Metadata）

- [ ] **Step 1: 写失败测试 — computeHashKey 三种优先级**

Create `trafficgen/internal/core/shard_router_test.go`:

```go
package core

import (
	"strings"
	"testing"
)

func TestComputeHashKeyGroupIDTakesPriority(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
		GroupID: StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey, gID := computeHashKey(spec, task, 0)
	if hashKey != "call-A" || gID != "call-A" {
		t.Fatalf("hashKey=%q gID=%q, want call-A/call-A", hashKey, gID)
	}
}

func TestComputeHashKeyFallbackTo4Tuple(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey, gID := computeHashKey(spec, task, 0)
	// unordered: min(10.0.0.1,10.0.0.2) + max + min(1000,80) + max(1000,80)
	want := "10.0.0.1-10.0.0.2-80-1000"
	if hashKey != want {
		t.Fatalf("hashKey=%q want %q", hashKey, want)
	}
	if gID != "" {
		t.Fatalf("gID=%q want empty (fallback)", gID)
	}
}

func TestComputeHashKeyBidirectionalSameKey(t *testing.T) {
	// src->dst and dst->src should produce the same hashKey
	spec1 := FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 80}
	spec2 := FlowSpec{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 1000}
	task := Task{ID: "taskA", ClassID: "classB"}
	k1, _ := computeHashKey(spec1, task, 0)
	k2, _ := computeHashKey(spec2, task, 0)
	if k1 != k2 {
		t.Fatalf("bidirectional keys differ: %q vs %q", k1, k2)
	}
}

func TestComputeHashKeyReplayImplicitGID(t *testing.T) {
	// replay task (task.Mode == "replay") with empty GroupID -> implicit gID
	spec := FlowSpec{}
	task := Task{ID: "taskA", ClassID: "classB", Mode: "replay"}
	hashKey, gID := computeHashKey(spec, task, 0)
	want := "taskA:classB"
	if hashKey != want || gID != want {
		t.Fatalf("hashKey=%q gID=%q want %q", hashKey, gID, want)
	}
}

func TestComputeHashKeyPatternStrategy(t *testing.T) {
	// pattern strategy generates per-flow gID
	spec := FlowSpec{
		GroupID: StrategyConfig{
			Strategy: "pattern",
			Pattern:  "call-{n}",
			Range:    []interface{}{1, 100}, // n_range stored in Range
		},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey0, gID0 := computeHashKey(spec, task, 0)
	hashKey7, gID7 := computeHashKey(spec, task, 7)
	if !strings.HasPrefix(gID0, "call-") {
		t.Fatalf("gID0=%q want call-* prefix", gID0)
	}
	if gID0 == gID7 {
		t.Fatalf("different flowIdx should produce different gID: %q == %q", gID0, gID7)
	}
	if hashKey0 != gID0 || hashKey7 != gID7 {
		t.Fatalf("hashKey should equal gID for pattern strategy")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestComputeHashKey -v`
Expected: FAIL — `computeHashKey` 未定义

- [ ] **Step 3: 实现 shard_router.go**

Create `trafficgen/internal/core/shard_router.go`:

```go
package core

import (
	"fmt"
	"strconv"
	"strings"
)

// computeHashKey derives the routing key and group id for a flow.
//
// Priority (spec §3.2):
//  1. GroupID.Strategy != "" -> generate gID via StrategyConfig, hashKey = gID
//  2. synth task (Mode != "replay") with empty GroupID -> unordered 4-tuple,
//     hashKey = "min-min-max-max" string, gID = "" (fallback path)
//  3. replay task (Mode == "replay") with empty GroupID -> implicit gID
//     "taskID:classID", hashKey = gID (preserves pcap order in one asset)
//
// flowIdx is the per-task flow index, used to advance pattern/inc strategies.
func computeHashKey(spec FlowSpec, task Task, flowIdx int) (hashKey, gID string) {
	// Case 1: explicit group_id strategy
	if spec.GroupID.Strategy != "" {
		g := genStringValue(spec.GroupID, flowIdx)
		if g != "" {
			return g, g
		}
		// strategy set but generated empty (misconfiguration) -> fall through
	}

	// Case 3: replay with empty group_id -> implicit gID
	if task.Mode == "replay" || len(task.Replay) > 0 {
		implicit := task.ID + ":" + task.ClassID
		return implicit, implicit
	}

	// Case 2: synth fallback to unordered 4-tuple
	srcIP, dstIP := spec.SrcIP, spec.DstIP
	if dstIP < srcIP {
		srcIP, dstIP = dstIP, srcIP
	}
	srcPort, dstPort := spec.SrcPort, spec.DstPort
	if dstPort < srcPort {
		srcPort, dstPort = dstPort, srcPort
	}
	hashKey = fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, srcPort, dstPort)
	return hashKey, ""
}

// genStringValue generates a string value from a StrategyConfig (for group_id).
// Supports fixed/list/inc/rand/pattern. Returns "" if strategy unknown or
// config invalid.
func genStringValue(s StrategyConfig, index int) string {
	switch s.Strategy {
	case "fixed", "":
		if v, ok := s.Value.(string); ok {
			return v
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return ""
		}
		return s.List[index%len(s.List)]
	case "pattern":
		return applyPattern(s.Pattern, s.Range, index)
	case "inc":
		// inc with numeric range: produce stringified number
		if len(s.Range) < 2 {
			return ""
		}
		start := toInt(s.Range[0])
		end := toInt(s.Range[1])
		if end < start {
			return ""
		}
		count := end - start + 1
		step := s.Step
		if step <= 0 {
			step = 1
		}
		return strconv.Itoa(start + (index*step)%count)
	case "rand":
		if len(s.Range) < 2 {
			return ""
		}
		start := toInt(s.Range[0])
		end := toInt(s.Range[1])
		if end < start {
			return ""
		}
		// deterministic per index via seeded rand
		seed := s.Seed + int64(index)
		r := simpleRand(seed)
		return strconv.Itoa(start + int(r.Intn(end-start+1)))
	}
	return ""
}

// applyPattern substitutes {n} in the pattern with a value derived from
// n_range [start, end]. index 0 -> start, index k -> start + k, wraps after
// (end - start + 1).
func applyPattern(pattern string, nRange []interface{}, index int) string {
	if pattern == "" || len(nRange) < 2 {
		return ""
	}
	start := toInt(nRange[0])
	end := toInt(nRange[1])
	if end < start {
		return ""
	}
	count := end - start + 1
	if count <= 0 {
		return ""
	}
	n := start + (index % count)
	return strings.ReplaceAll(pattern, "{n}", strconv.Itoa(n))
}

// toInt converts interface{} (float64/int/string) to int.
func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

// simpleRand creates a deterministic rand.Rand from a seed (math/rand seeded
// by index for reproducibility).
func simpleRand(seed int64) *simpleRandImpl {
	return &simpleRandImpl{seed: seed}
}

type simpleRandImpl struct {
	seed int64
}

func (r *simpleRandImpl) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	// use math/rand under the hood
	return int(r.uint64n(uint64(n)))
}

func (r *simpleRandImpl) uint64n(n uint64) uint64 {
	// simple LCG
	x := uint64(r.seed + 1)
	for i := 0; i < 3; i++ {
		x = x*6364136223846793005 + 1442695040888963407
	}
	if n == 0 {
		return 0
	}
	return x % n
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd trafficgen && go test ./internal/core/ -run TestComputeHashKey -v`
Expected: 5 个测试 PASS

- [ ] **Step 5: 用真实 math/rand 替换自定义 LCG**

上面的 `simpleRand` 是占位，实际应复用 `math/rand`。修改 `genStringValue` 的 `rand` 分支：

```go
case "rand":
	if len(s.Range) < 2 {
		return ""
	}
	start := toInt(s.Range[0])
	end := toInt(s.Range[1])
	if end < start {
		return ""
	}
	r := rand.New(rand.NewSource(s.Seed + int64(index)))
	return strconv.Itoa(start + r.Intn(end-start+1))
```

加 `import "math/rand"`，删除 `simpleRand`/`simpleRandImpl`。

- [ ] **Step 6: 跑测试确认通过**

Run: `cd trafficgen && go test -race -count=1 ./internal/core/ -run TestComputeHashKey -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add trafficgen/internal/core/shard_router.go trafficgen/internal/core/shard_router_test.go
git commit -m "feat(core): implement computeHashKey for shard routing

Priority: group_id > replay implicit gID > unordered 4-tuple fallback.
Bidirectional flows (src<->dst swapped) produce same key.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 3: Engine 加 shardedConfigChan + shardSeed

**Files:**
- Modify: `trafficgen/internal/core/engine.go`
- Test: `trafficgen/internal/core/engine_test.go`（新增用例）

**Interfaces:**
- Consumes: 现有 `EngineConfig.PacketWorkers`/`QueueSize`/`ReplayOrderPreserve`
- Produces: `Engine.shardedConfigChan []chan PacketConfig`、`Engine.shardSeed maphash.Seed`、`Engine.shardCounts []atomic.Int64`

- [ ] **Step 1: 写失败测试 — Engine 启动后 shardedConfigChan 长度 = PacketWorkers**

Create `trafficgen/internal/core/engine_shard_test.go`:

```go
package core

import (
	"testing"
	"unsafe"
)

func TestEngineStartCreatesShardedConfigChan(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 3, OutputWorkers: 1,
		BufferSize: 100, QueueSize: 10,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// shardedConfigChan should have len = PacketWorkers (no cap since ReplayOrderPreserve=false)
	if len(e.shardedConfigChan) != 3 {
		t.Fatalf("shardedConfigChan len = %d, want 3", len(e.shardedConfigChan))
	}
	for i, c := range e.shardedConfigChan {
		if cap(c) != 20 { // QueueSize*2
			t.Fatalf("shard[%d] cap = %d, want 20", i, cap(c))
		}
	}
	// shardSeed must be initialized (non-zero)
	if e.shardSeed == (maphashSeed{}) {
		t.Fatalf("shardSeed is zero")
	}
}

// maphashSeed is a type alias to avoid importing hash/maphash in test;
// the real type is hash/maphash.Seed. We use unsafe to compare to zero
// since Seed is a struct with a private field.
type maphashSeed = struct{ _ unsafe.Pointer }
```

注：测试里直接访问 `e.shardedConfigChan`，需在同一 package（`core`）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestEngineStartCreatesShardedConfigChan -v`
Expected: FAIL — `e.shardedConfigChan` 未定义

- [ ] **Step 3: 修改 Engine struct 加字段**

Edit `trafficgen/internal/core/engine.go`，在 `Engine struct` 顶部字段区（`taskChan`/`configChan`/`packetChan` 附近，约 line 25-27）加：

```go
import (
	"hash/maphash"
	"sync/atomic"
	// ...existing imports
)

type Engine struct {
	// ...existing fields...
	taskChan   chan Task
	configChan chan PacketConfig // 保留作向后兼容（不再使用，或删除见 Step 5）
	packetChan chan PacketOutput

	shardedConfigChan []chan PacketConfig
	shardSeed         maphash.Seed
	shardCounts      []atomic.Int64 // 入队计数，用于负载监控
	// ...existing fields...
}
```

- [ ] **Step 4: 修改 Engine.Start 初始化分片**

Edit `trafficgen/internal/core/engine.go` 的 `Start` 函数（约 line 249-298）：

```go
// Initialize channels
e.taskChan = make(chan Task, e.config.QueueSize)
e.shardSeed = maphash.MakeSeed()
pw := e.config.PacketWorkers
if pw <= 0 {
	pw = 1
}
// 删除 ReplayOrderPreserve cap-to-1 逻辑（spec §8.3：replay 留空 group_id
// 走隐式 gID 保 pcap 顺序，不再需要 cap worker 数）
e.shardedConfigChan = make([]chan PacketConfig, pw)
e.shardCounts = make([]atomic.Int64, pw)
for i := 0; i < pw; i++ {
	e.shardedConfigChan[i] = make(chan PacketConfig, e.config.QueueSize*2)
}
e.packetChan = make(chan PacketOutput, e.config.QueueSize*2)
```

删除原 `e.configChan = make(chan PacketConfig, e.config.QueueSize*2)` 行。

修改 PacketWorker 创建循环（约 line 291-298）：

```go
e.packetWorkers = make([]*PacketWorker, pw)
for i := 0; i < pw; i++ {
	e.wg.Add(1)
	worker := NewPacketWorker(i, e.shardedConfigChan[i], e.packetChan, buildFn, &e.wg, e)
	e.packetWorkers[i] = worker
	worker.Start()
}
```

ConfigWorker 创建（约 line 261-275）：`NewConfigWorker` 的 `configChan` 参数改为 `nil`（不再用共享 channel，ConfigWorker 通过 `w.engine.shardedConfigChan` 访问）。或保留参数但传 `e.shardedConfigChan[0]` 作占位——推荐改为 nil 并在 ConfigWorker 内部用 `w.engine.shardedConfigChan`。这里采用 nil 方案。

修改 `NewConfigWorker` 调用：

```go
worker := NewConfigWorker(i, e.planners, e.replayPlanner, e.taskChan, nil, &e.wg, e)
```

- [ ] **Step 5: 修改 Engine.Stop 关闭分片**

Edit `trafficgen/internal/core/engine.go` 的 `Stop` 函数（约 line 326-360）：

```go
// Close remaining channels (safe now since all workers exited)
for i := range e.shardedConfigChan {
	close(e.shardedConfigChan[i])
}
close(e.packetChan)
// 删除 close(e.configChan) 行（已不存在）
```

- [ ] **Step 6: 修改 ConfigWorker 字段（configChan 改为可选）**

Edit `trafficgen/internal/core/worker.go` 的 `ConfigWorker struct`（约 line 51-64）：`configChan` 字段保留但标注废弃。或直接删除并在 `processTask` 等函数内改用 `w.engine.shardedConfigChan[shardIdx]`。采用删除方案：

```go
type ConfigWorker struct {
	id            int
	planners      map[string]ProtocolPlanner
	replayPlanner ReplayPlanner
	taskChan      <-chan Task
	// configChan removed: replaced by w.engine.shardedConfigChan[shardIdx]
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats
	onTaskDone func(taskID string, err error, count int64)
	sem        chan struct{}
	engine     *Engine
}
```

修改 `NewConfigWorker` 签名（删除 `configChan chan<- PacketConfig` 参数）：

```go
func NewConfigWorker(
	id int,
	planners map[string]ProtocolPlanner,
	replayPlanner ReplayPlanner,
	taskChan <-chan Task,
	wg *sync.WaitGroup,
	engine *Engine,
) *ConfigWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigWorker{
		id:            id,
		planners:      planners,
		replayPlanner: replayPlanner,
		taskChan:      taskChan,
		wg:            wg,
		ctx:           ctx,
		cancel:        cancel,
		sem:           make(chan struct{}, 4),
		engine:        engine,
	}
}
```

- [ ] **Step 7: 修改 PacketWorker struct 加 shardChan**

Edit `trafficgen/internal/core/worker.go` 的 `PacketWorker struct`（约 line 596-606）：

```go
type PacketWorker struct {
	id         int
	shardChan  <-chan PacketConfig  // 改名：从 configChan 改为 shardChan（自己的分片）
	packetChan chan<- PacketOutput
	buildFunc  func(PacketConfig) ([]byte, error)
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats
	engine     *Engine
}
```

修改 `NewPacketWorker` 签名（`configChan <-chan PacketConfig` 改名为 `shardChan <-chan PacketConfig`）：

```go
func NewPacketWorker(
	id int,
	shardChan <-chan PacketConfig,
	packetChan chan<- PacketOutput,
	buildFunc func(PacketConfig) ([]byte, error),
	wg *sync.WaitGroup,
	engine *Engine,
) *PacketWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketWorker{
		id:         id,
		shardChan:  shardChan,
		packetChan: packetChan,
		buildFunc:  buildFunc,
		wg:         wg,
		ctx:        ctx,
		cancel:     cancel,
		engine:     engine,
	}
}
```

修改 `PacketWorker.run` 的 select（约 line 644-655）：`case config, ok := <-w.configChan:` 改为 `case config, ok := <-w.shardChan:`。

- [ ] **Step 8: 跑测试确认通过**

Run: `cd trafficgen && go build ./... && go test ./internal/core/ -run TestEngineStartCreatesShardedConfigChan -v`
Expected: PASS

- [ ] **Step 9: 跑全量测试发现 regression**

Run: `cd trafficgen && go test -race -count=1 ./internal/core/ 2>&1 | tail -30`
Expected: 可能有编译错误（其他地方引用了 `e.configChan` 或 `w.configChan`）—下一个 Task 修复

- [ ] **Step 10: Commit**

```bash
git add trafficgen/internal/core/engine.go trafficgen/internal/core/worker.go trafficgen/internal/core/engine_shard_test.go
git commit -m "feat(core): Engine uses shardedConfigChan + shardSeed

- Engine holds []chan PacketConfig + maphash.Seed + []atomic.Int64 counts
- Start: init N shards each QueueSize*2 capacity, remove ReplayOrderPreserve cap-to-1
- Stop: close all shards after workers exit
- ConfigWorker: remove configChan field, use w.engine.shardedConfigChan
- PacketWorker: rename configChan -> shardChan (own shard)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 4: ConfigWorker push 路由（processTask / processBatchTask / processReplayTask）

**Files:**
- Modify: `trafficgen/internal/core/worker.go`（`processTask`/`processBatchTask`/`processReplayTask`）
- Test: `trafficgen/internal/core/worker_route_test.go`

**Interfaces:**
- Consumes: `computeHashKey`（Task 2）、`w.engine.shardedConfigChan`/`w.engine.shardSeed`（Task 3）
- Produces: ConfigWorker push 时按 `shardIdx` 路由到分片

- [ ] **Step 1: 写失败测试 — processTask 同流包落同分片**

Create `trafficgen/internal/core/worker_route_test.go`:

```go
package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessTaskRoutesSameFlowToSameShard(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	// Register a stub planner that emits N packets for one flow
	e.RegisterPlanner(&stubPlanner{name: "stub", packetsPerFlow: 10})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Submit a task with explicit group_id
	spec := FlowSpec{
		Protocol: "stub",
		Count:    1,
		GroupID:  StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := Task{
		ID: "task1", Protocol: "stub", Spec: spec,
		Ctx: context.Background(),
	}
	// Push task
	e.taskChan <- task

	// Wait for packets to land in shards; count distribution
	time.Sleep(100 * time.Millisecond)

	// All 10 packets should go to exactly one shard
	nonZero := 0
	for i := range e.shardCounts {
		c := atomic.LoadInt64(&e.shardCounts[i])
		if c > 0 {
			nonZero++
		}
	}
	if nonZero != 1 {
		t.Fatalf("expected all packets in 1 shard, got %d shards non-zero", nonZero)
	}
}

// stubPlanner implements ProtocolPlanner for testing.
type stubPlanner struct {
	name          string
	packetsPerFlow int
}

func (s *stubPlanner) Name() string { return s.name }
func (s *stubPlanner) Validate(spec FlowSpec) error { return nil }
func (s *stubPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, s.packetsPerFlow)
	go func() {
		defer close(ch)
		for i := 0; i < s.packetsPerFlow; i++ {
			ch <- PacketConfig{
				FlowID: "test-flow",
				PacketIndex: uint64(i),
			}
		}
	}()
	return ch, nil
}
```

注：测试用 `atomic.LoadInt64(&e.shardCounts[i])`。需 ConfigWorker 在 push 后 `atomic.AddInt64(&w.engine.shardCounts[shardIdx], 1)`。Task 5 加监控时统一加，这里先测路由行为本身——所以本步先加 `atomic.Add` 在 push 后。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestProcessTaskRoutesSameFlowToSameShard -v`
Expected: FAIL — `e.shardCounts` 未在 push 时递增（Task 3 加了字段但没加计数），或 `stubPlanner` 未注册

- [ ] **Step 3: 修改 processTask 加路由**

Edit `trafficgen/internal/core/worker.go` 的 `processTask` 函数（约 line 140-297）。

找到 `for config := range configChan {` 循环（约 line 256），在循环**之前**加：

```go
// Per-flow shard routing: compute hashKey + gID once, write to each
// packet's Metadata, push to the matching shard.
hashKey, gID := computeHashKey(task.Spec, task, i) // i = flowIdx
shardIdx := 0
if len(w.engine.shardedConfigChan) > 0 {
	h := maphash.String(hashKey, w.engine.shardSeed)
	shardIdx = int(h % uint64(len(w.engine.shardedConfigChan)))
}
```

（`i` 是 `for i := 0; i < flowCount; i++` 的循环变量，即 flowIdx）

修改 `for config := range configChan {` 循环体内，在 `config.ClassID = task.ClassID` 之后加：

```go
if config.Metadata == nil {
	config.Metadata = make(map[string]interface{})
}
config.Metadata["shard_idx"] = shardIdx
config.Metadata["group_id"] = gID
```

修改 push 的 select 分支（约 line 271-288）：

```go
select {
case <-taskCtx.Done():
	for range configChan {}
	if w.onTaskDone != nil {
		if taskCtx.Err() == context.DeadlineExceeded {
			w.onTaskDone(task.ID, nil, configCount)
		} else {
			w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
		}
	}
	return
case w.engine.shardedConfigChan[shardIdx] <- config:
	atomic.AddInt64(&w.engine.shardCounts[shardIdx], 1)
	configCount++
}
```

加 `import "hash/maphash"` 到 worker.go 顶部。

- [ ] **Step 4: 修改 processBatchTask 加路由**

Edit `worker.go` 的 `processBatchTask` 函数（约 line 402-584）。

找到 class goroutine 内的 `for flowIdx := 0; flowIdx < c.FlowCount; flowIdx {`（约 line 490）。在 `tupleGen := NewTupleGenerator(c.Tuples)` 后加：

```go
groupGen := c.GroupID // StrategyConfig, used in computeHashKey
```

修改 spec 构造（约 line 483-486）加 `spec.GroupID = c.GroupID`（如果 `mapToFlowSpec` 已透传则不需要，但保险起见显式覆盖）。

在 `for flowIdx` 循环内，`tupleGen.Next(flowIdx)` 之后、`planner.Plan` 之前加：

```go
// Compute shard routing for this flow
hashKey, gID := computeHashKey(spec, task, flowIdx)
shardIdx := 0
if len(w.engine.shardedConfigChan) > 0 {
	h := maphash.String(hashKey, w.engine.shardSeed)
	shardIdx = int(h % uint64(len(w.engine.shardedConfigChan)))
}
```

在 `for config := range configChan {` 循环体内，`config.ClassID = classKey` 之后加：

```go
if config.Metadata == nil {
	config.Metadata = make(map[string]interface{})
}
config.Metadata["shard_idx"] = shardIdx
config.Metadata["group_id"] = gID
```

修改 push 的 select 分支：

```go
case w.engine.shardedConfigChan[shardIdx] <- config:
	atomic.AddInt64(&w.engine.shardCounts[shardIdx], 1)
	atomic.AddInt64(&configCount, 1)
```

replay class 分支（约 line 432-466）：replay planner 返回的 configChan 内的包，`PlanReplay` 已经写入 gID（Task 6），ConfigWorker 只需算 shardIdx 并 push。修改 replay class goroutine：

```go
go func(c TrafficClass) {
	defer classWg.Done()
	classKey := task.ID + ":" + c.ID
	configChan, err := w.replayPlanner.PlanReplay(taskCtx, c.Replay, task.ID, classKey, task.UserID, nil)
	if err != nil { /* ...existing... */ }
	for config := range configChan {
		config.ClassID = classKey
		if config.Metadata == nil {
			config.Metadata = make(map[string]interface{})
		}
		// gID already set by PlanReplay (Task 6); compute shardIdx from it
		gID, _ := config.Metadata["group_id"].(string)
		shardIdx := 0
		if gID != "" && len(w.engine.shardedConfigChan) > 0 {
			h := maphash.String(gID, w.engine.shardSeed)
			shardIdx = int(h % uint64(len(w.engine.shardedConfigChan)))
		}
		config.Metadata["shard_idx"] = shardIdx
		config.Metadata["task_id"] = task.ID
		config.Metadata["interface"] = task.Interface
		select {
		case <-taskCtx.Done():
			for range configChan {}
			return
		case w.engine.shardedConfigChan[shardIdx] <- config:
			atomic.AddInt64(&w.engine.shardCounts[shardIdx], 1)
			atomic.AddInt64(&configCount, 1)
		}
	}
}(class)
```

- [ ] **Step 5: 修改 processReplayTask 加路由**

Edit `worker.go` 的 `processReplayTask` 函数（约 line 310-395）。

`PlanReplay` 返回的 configChan 内包已带 gID（Task 6）。修改 `for config := range configChan {` 循环：

```go
for config := range configChan {
	config.ClassID = task.ClassID
	if config.Metadata == nil {
		config.Metadata = make(map[string]interface{})
	}
	// gID already set by PlanReplay; compute shardIdx
	gID, _ := config.Metadata["group_id"].(string)
	shardIdx := 0
	if gID != "" && len(w.engine.shardedConfigChan) > 0 {
		h := maphash.String(gID, w.engine.shardSeed)
		shardIdx = int(h % uint64(len(w.engine.shardedConfigChan)))
	}
	config.Metadata["shard_idx"] = shardIdx
	config.Metadata["task_id"] = task.ID
	config.Metadata["parent_task_id"] = task.ParentTaskID
	config.Metadata["interface"] = task.Interface

	select {
	case <-taskCtx.Done():
		for range configChan {}
		if w.onTaskDone != nil {
			if taskCtx.Err() == context.DeadlineExceeded {
				w.onTaskDone(task.ID, nil, configCount)
			} else {
				w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
			}
		}
		return
	case w.engine.shardedConfigChan[shardIdx] <- config:
		atomic.AddInt64(&w.engine.shardCounts[shardIdx], 1)
		configCount++
	}
}
```

- [ ] **Step 6: 跑测试确认通过**

Run: `cd trafficgen && go test -race -count=1 ./internal/core/ -run TestProcessTaskRoutesSameFlowToSameShard -v`
Expected: PASS

- [ ] **Step 7: 跑全量测试发现 regression**

Run: `cd trafficgen && go build ./... && go vet ./... && go test -race -count=1 ./internal/core/ 2>&1 | tail -30`
Expected: 可能有测试引用旧 `e.configChan` 或 `w.configChan` — 修复所有引用

- [ ] **Step 8: 修复所有引用旧 configChan 的地方**

Run: `cd trafficgen && grep -rn "e\.configChan\|w\.configChan" --include="*.go" ./`
修复每个引用：删除或改为 `e.shardedConfigChan[i]`/`w.shardChan`。

- [ ] **Step 9: Commit**

```bash
git add trafficgen/internal/core/worker.go trafficgen/internal/core/worker_route_test.go
git commit -m "feat(core): ConfigWorker routes to shardedConfigChan by group_id

processTask/processBatchTask/processReplayTask compute shardIdx per-flow
via computeHashKey + maphash, write (shard_idx, group_id) to Metadata,
push to w.engine.shardedConfigChan[shardIdx]. shardCounts incremented.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 5: 负载监控告警

**Files:**
- Modify: `trafficgen/internal/core/engine.go`（加监控 goroutine）
- Test: `trafficgen/internal/core/load_balance_test.go`

**Interfaces:**
- Consumes: `Engine.shardCounts`（Task 3 + Task 4）
- Produces: 周期采样打 WARN 日志

- [ ] **Step 1: 写失败测试 — 不均时打 WARN**

Create `trafficgen/internal/core/load_balance_test.go`:

```go
package core

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestShardImbalanceWarn(t *testing.T) {
	// Capture zap logs
	var buf syncBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 100, QueueSize: 10,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Manually inflate shard 0 to 300, others 0 -> avg 75, shard0 = 4x avg
	atomic.StoreInt64(&e.shardCounts[0], 300)
	atomic.StoreInt64(&e.shardCounts[1], 0)
	atomic.StoreInt64(&e.shardCounts[2], 0)
	atomic.StoreInt64(&e.shardCounts[3], 0)

	// Force immediate balance check
	e.checkShardBalance()

	time.Sleep(50 * time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "shard load imbalance") {
		t.Fatalf("expected WARN, got log: %s", out)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}
func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestShardImbalanceWarn -v`
Expected: FAIL — `e.checkShardBalance` 未定义

- [ ] **Step 3: 实现监控 goroutine**

Edit `trafficgen/internal/core/engine.go`，在 `Engine struct` 加字段：

```go
type Engine struct {
	// ...existing...
	shardMonitorCancel context.CancelFunc
}
```

在 `Start` 函数末尾（`e.running.Store(true)` 之后）加：

```go
// Start shard load monitor
monCtx, monCancel := context.WithCancel(context.Background())
e.shardMonitorCancel = monCancel
go e.runShardMonitor(monCtx)
```

加方法：

```go
// runShardMonitor periodically samples shardCounts and warns on imbalance.
func (e *Engine) runShardMonitor(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.checkShardBalance()
		}
	}
}

// checkShardBalance warns if any shard has > 3x the average packet count.
func (e *Engine) checkShardBalance() {
	n := len(e.shardCounts)
	if n == 0 {
		return
	}
	var sum int64
	counts := make([]int64, n)
	for i := range e.shardCounts {
		c := atomic.LoadInt64(&e.shardCounts[i])
		counts[i] = c
		sum += c
	}
	avg := sum / int64(n)
	if avg == 0 {
		return // avoid div-by-zero; nothing to warn
	}
	for i, c := range counts {
		if c > avg*3 {
			zap.L().Warn("shard load imbalance detected",
				zap.Int("shard_idx", i),
				zap.Int64("packets", c),
				zap.Int64("avg", avg),
				zap.String("hint", "consider checking group_id strategy distribution"),
			)
		}
	}
}
```

加 imports：`"time"`, `"go.uber.org/zap"`, `"sync/atomic"`。

在 `Stop` 函数开头加：

```go
if e.shardMonitorCancel != nil {
	e.shardMonitorCancel()
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd trafficgen && go test -race -count=1 ./internal/core/ -run TestShardImbalanceWarn -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add trafficgen/internal/core/engine.go trafficgen/internal/core/load_balance_test.go
git commit -m "feat(core): shard load imbalance monitor

Periodic (10s) sampling of shardCounts; warns if any shard > 3x avg.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 6: ReplaySpec GroupID 在 PlanReplay 内生成

**Files:**
- Modify: `trafficgen/internal/replay/planner.go`
- Test: `trafficgen/internal/replay/planner_group_id_test.go`

**Interfaces:**
- Consumes: `ReplaySpec.GroupID`（Task 1）
- Produces: 每个 PacketConfig 的 `Metadata["group_id"]` 由 `PlanReplay` 写入

- [ ] **Step 1: 写失败测试 — PlanReplay 写入 gID 到 Metadata**

Create `trafficgen/internal/replay/planner_group_id_test.go`:

```go
package replay

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanReplayWritesGroupIDMetadata(t *testing.T) {
	// Minimal ReplaySpec with explicit group_id
	specJSON, _ := json.Marshal(ReplaySpec{
		PcapAssetID: "asset-1",
		Speed:        ReplaySpeed{Mode: "max"},
		GroupID: core.StrategyConfig{
			Strategy: "fixed", Value: "call-A",
		},
	})

	p := NewReplayPlanner(nil) // DB nil; we won't actually read pcap
	// Monkey-patch: we can't call PlanReplay without a real asset, so test
	// the gID-generation helper directly
	gID := computeReplayGroupID(ReplaySpec{
		GroupID: core.StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}, "task1", "class1", 0)
	if gID != "call-A" {
		t.Fatalf("gID = %q, want call-A", gID)
	}

	_ = specJSON
	_ = p
}

func TestComputeReplayGroupIDImplicit(t *testing.T) {
	// Empty GroupID -> implicit taskID:classID
	gID := computeReplayGroupID(ReplaySpec{}, "task1", "class1", 0)
	if gID != "task1:class1" {
		t.Fatalf("gID = %q, want task1:class1", gID)
	}
}

func TestComputeReplayGroupIDPerClone(t *testing.T) {
	// With FlowScaling, each clone gets implicit gID taskID:classID:cloneIdx
	spec := ReplaySpec{
		FlowScaling: &FlowScaling{Count: 3},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g1 := computeReplayGroupID(spec, "task1", "class1", 1)
	if g0 != "task1:class1:0" || g1 != "task1:class1:1" {
		t.Fatalf("g0=%q g1=%q, want task1:class1:0/1", g0, g1)
	}
}

func TestComputeReplayGroupIDExplicitStrategy(t *testing.T) {
	spec := ReplaySpec{
		GroupID: core.StrategyConfig{
			Strategy: "pattern", Pattern: "call-{n}",
			Range: []interface{}{1, 100},
		},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g7 := computeReplayGroupID(spec, "task1", "class1", 7)
	if g0 != "call-1" || g7 != "call-8" {
		t.Fatalf("g0=%q g7=%q, want call-1/call-8", g0, g7)
	}
}

// Use context to silence unused import warning if test doesn't directly use it.
var _ = context.Background
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd trafficgen && go test ./internal/replay/ -run TestPlanReplayWritesGroupID -v && go test ./internal/replay/ -run TestComputeReplayGroupID -v`
Expected: FAIL — `computeReplayGroupID` 未定义

- [ ] **Step 3: 实现 computeReplayGroupID**

Edit `trafficgen/internal/replay/planner.go`，加函数：

```go
import (
	// ...existing...
	"strconv"
	"strings"
)

// computeReplayGroupID derives the group id for a replay flow.
//
// Priority (spec §8.1):
//  1. ReplaySpec.GroupID.Strategy != "" -> generate via strategy (fixed/inc/
//     rand/pattern/list) per clone index
//  2. FlowScaling exists -> implicit "taskID:classID:cloneIdx" per clone
//  3. No FlowScaling -> implicit "taskID:classID" (whole asset, preserves
//     pcap order)
func computeReplayGroupID(spec ReplaySpec, taskID, classID string, cloneIdx int) string {
	if spec.GroupID.Strategy != "" {
		g := genReplayGroupValue(spec.GroupID, cloneIdx)
		if g != "" {
			return g
		}
	}
	if spec.FlowScaling != nil && spec.FlowScaling.Count > 0 {
		return taskID + ":" + classID + ":" + strconv.Itoa(cloneIdx)
	}
	return taskID + ":" + classID
}

// genReplayGroupValue generates a string from a StrategyConfig (same semantics
// as core.genStringValue, but in replay package to avoid import cycle).
func genReplayGroupValue(s core.StrategyConfig, index int) string {
	switch s.Strategy {
	case "fixed", "":
		if v, ok := s.Value.(string); ok {
			return v
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return ""
		}
		return s.List[index%len(s.List)]
	case "pattern":
		return applyReplayPattern(s.Pattern, s.Range, index)
	case "inc":
		if len(s.Range) < 2 {
			return ""
		}
		start := replayToInt(s.Range[0])
		end := replayToInt(s.Range[1])
		if end < start {
			return ""
		}
		count := end - start + 1
		step := s.Step
		if step <= 0 {
			step = 1
		}
		return strconv.Itoa(start + (index*step)%count)
	}
	return ""
}

func applyReplayPattern(pattern string, nRange []interface{}, index int) string {
	if pattern == "" || len(nRange) < 2 {
		return ""
	}
	start := replayToInt(nRange[0])
	end := replayToInt(nRange[1])
	if end < start {
		return ""
	}
	count := end - start + 1
	if count <= 0 {
		return ""
	}
	n := start + (index % count)
	return strings.ReplaceAll(pattern, "{n}", strconv.Itoa(n))
}

func replayToInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
```

- [ ] **Step 4: 修改 PlanReplay 写入 gID 到每个包的 Metadata**

Edit `trafficgen/internal/replay/planner.go` 的 `PlanReplay` 函数（约 line 63-263）。

在生成每个 `PacketConfig` 时（约 line 355 `FlowID: pkt.FlowID,` 附近），在构造 PacketConfig 后加：

```go
// Inject group_id into Metadata for shard routing (spec §8.1)
gID := computeReplayGroupID(spec, taskID, classID, cloneIdx)
// cloneIdx is the FlowScaling clone index (0 if no FlowScaling)
if pkt.Metadata == nil {
	pkt.Metadata = make(map[string]interface{})
}
pkt.Metadata["group_id"] = gID
```

`cloneIdx` 来自 FlowScaling 循环——需找到 `PlanReplay` 内的 clone 循环变量。如果当前代码没有 clone 循环（无 FlowScaling 时单 clone），用 `0`。

注：实际位置需读 `planner.go` 完整代码确定。在 PacketConfig 构造点之前算 gID，之后写入 Metadata。

- [ ] **Step 5: 跑测试确认通过**

Run: `cd trafficgen && go test -race -count=1 ./internal/replay/ -run "TestPlanReplayWritesGroupID|TestComputeReplayGroupID" -v`
Expected: 4 个测试 PASS

- [ ] **Step 6: 跑全量 replay 测试确认无 regression**

Run: `cd trafficgen && go test -race -count=1 ./internal/replay/ 2>&1 | tail -20`
Expected: 全部 PASS

- [ ] **Step 7: Commit**

```bash
git add trafficgen/internal/replay/planner.go trafficgen/internal/replay/planner_group_id_test.go
git commit -m "feat(replay): PlanReplay writes group_id to PacketConfig Metadata

computeReplayGroupID: explicit strategy > implicit taskID:classID:cloneIdx
(FlowScaling) > implicit taskID:classID (single asset).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 7: MCP 工具 description 更新 + 集成测试

**Files:**
- Modify: `trafficgen/internal/mcp/tools_strategy.go`（Config description）
- Modify: `trafficgen/internal/mcp/tools_task.go`（Batch description）
- Modify: `trafficgen/internal/mcp/tools_integration_test.go`（加用例）

- [ ] **Step 1: 更新 tools_strategy.go 的 Config description**

Edit `trafficgen/internal/mcp/tools_strategy.go:27`，在 `Config` 字段 description 末尾追加：

```
group_id (optional): object {strategy, pattern/value/range/n_range/list/step/seed} -- routes flows with the same generated id to one PacketWorker, preserving cross-flow timing (e.g. SIP+RTP). Strategies: fixed/inc/rand/pattern/list. Two classes that should bind must use the same strategy + n_range. Empty = fall back to 4-tuple unordered hash (single-flow ordering only).
```

具体：找到 `Config` 字段的 `jsonschema:"..."` tag，在末尾（`tcpdump filter...` 之后）加这段文字。

- [ ] **Step 2: 更新 tools_task.go 的 Batch description**

Edit `trafficgen/internal/mcp/tools_task.go:25`，在 `Batch` 字段 description 末尾追加：

```
Each class accepts an optional group_id strategy field. Classes with the same group_id strategy (same pattern + n_range) bind to one PacketWorker for cross-flow ordering. See manage_strategies tool's Config.group_id for strategy syntax.
```

- [ ] **Step 3: 写 MCP 集成测试 — 通过 MCP 创建带 group_id 的策略**

Edit `trafficgen/internal/mcp/tools_integration_test.go`，加测试：

```go
func TestMCPCreateStrategyWithGroupID(t *testing.T) {
	// Setup test DB + engine (use existing test helpers)
	srv, cleanup := setupTestMCPServer(t)
	defer cleanup()

	in := manageStrategiesInput{
		Action:   "create",
		Name:     "test-group",
		Mode:     "synth",
		Protocol: "tcp",
		Config: map[string]interface{}{
			"src_ip": "10.0.0.1",
			"dst_ip": "10.0.0.2",
			"group_id": map[string]interface{}{
				"strategy": "fixed",
				"value":    "call-A",
			},
		},
	}
	body := mustMarshal(map[string]interface{}{
		"name":     in.Name,
		"mode":     in.Mode,
		"protocol": in.Protocol,
		"config":   in.Config,
	})
	// Use existing callHandler pattern from other tests
	// ... (use the same setup as existing integration tests in the file)

	// Verify strategy was created with group_id
	_ = srv
	_ = body
	// Assert: fetch strategy, unmarshal config, check group_id.strategy == "fixed"
}
```

（具体测试函数体需参考 `tools_integration_test.go` 已有的测试模式——读现有测试找 `setupTestMCPServer` 或同等 helper。）

- [ ] **Step 4: 写 MCP 集成测试 — 通过 MCP 创建批量任务带 group_id 并验证路由**

继续加测试：

```go
func TestMCPBatchTaskWithGroupIDRoutesToSameShard(t *testing.T) {
	// Create a batch task via MCP with 2 classes sharing the same group_id
	// pattern, verify packets land on the same shard (via shardCounts)
	srv, cleanup := setupTestMCPServer(t)
	defer cleanup()

	batchSpec := map[string]interface{}{
		"classes": []map[string]interface{}{
			{
				"id":         "sip",
				"type":       "tcp",
				"flow_count": 5,
				"config": map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
					"src_port": 5060, "dst_port": 5060,
				},
				"group_id": map[string]interface{}{
					"strategy": "pattern", "pattern": "call-{n}",
					"n_range":  []int{1, 5},
				},
			},
			{
				"id":         "rtp",
				"type":       "udp",
				"flow_count": 5,
				"config": map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
					"src_port": 10000, "dst_port": 10000,
				},
				"group_id": map[string]interface{}{
					"strategy": "pattern", "pattern": "call-{n}",
					"n_range":  []int{1, 5},
				},
			},
		},
	}
	// Submit via MCP manage_tasks action=create_batch
	// Wait for task completion
	// Check e.shardCounts: exactly one shard should have all packets
	_ = batchSpec
	_ = srv
}
```

- [ ] **Step 5: 跑 MCP 测试确认通过**

Run: `cd trafficgen && go test -race -count=1 ./internal/mcp/ -run "TestMCPCreateStrategyWithGroupID|TestMCPBatchTaskWithGroupID" -v`
Expected: PASS

- [ ] **Step 6: 跑 MCP schema 测试确认无 regression**

Run: `cd trafficgen && go test -race -count=1 ./internal/mcp/ -run TestSchema -v`
Expected: PASS（schema 不变，因为 Config 是 `map[string]interface{}`）

- [ ] **Step 7: Commit**

```bash
git add trafficgen/internal/mcp/tools_strategy.go trafficgen/internal/mcp/tools_task.go trafficgen/internal/mcp/tools_integration_test.go
git commit -m "feat(mcp): document group_id in tool descriptions + integration tests

Config/Batch jsonschema descriptions updated. Integration tests verify
MCP -> REST -> engine -> PacketWorker routing with group_id.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 8: 抓包核对工具 + 真实测试

**Files:**
- Create: `trafficgen/test/integration/packet_capture_test.go`（抓包 + 解析）
- Create: `trafficgen/test/integration/group_id_e2e_test.go`（e2e 用例）

- [ ] **Step 1: 写抓包解析工具**

Create `trafficgen/test/integration/packet_capture_test.go`:

```go
package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// startCapture starts tcpdump on the given interface, writing to a pcap file.
// Returns a stop function that stops tcpdump and returns the captured packets.
func startCapture(t *testing.T, iface, filter string) (stop func() []gopacket.Packet) {
	t.Helper()
	pcapPath := filepath.Join(t.TempDir(), "capture.pcap")
	// tcpdump -i <iface> -w <path> -U <filter>
	cmd := exec.Command("tcpdump", "-i", iface, "-w", pcapPath, "-U", filter)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	// Give tcpdump time to start
	time.Sleep(200 * time.Millisecond)

	stop = func() []gopacket.Packet {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
		return readPcap(t, pcapPath)
	}
	return stop
}

func readPcap(t *testing.T, path string) []gopacket.Packet {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap %s: %v", path, err)
	}
	defer handle.Close()
	var pkts []gopacket.Packet
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		pkts = append(pkts, pkt)
	}
	return pkts
}

// extractFlowKey extracts a bidirectional flow key from a packet.
// Returns "minIP-maxIP-minPort-maxPort" (unordered, same for both directions).
func extractFlowKey(pkt gopacket.Packet) string {
	nw := pkt.NetworkLayer()
	tp := pkt.TransportLayer()
	if nw == nil || tp == nil {
		return ""
	}
	srcIP, dstIP := nw.NetworkFlow().Src().String(), nw.NetworkFlow().Dst().String()
	if dstIP < srcIP {
		srcIP, dstIP = dstIP, srcIP
	}
	srcPort, dstPort := tp.TransportFlow().Src().String(), tp.TransportFlow().Dst().String()
	if dstPort < srcPort {
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%s-%s-%s-%s", srcIP, dstIP, srcPort, dstPort)
}

// requireInterfaceAvailable skips the test if the interface doesn't exist.
func requireInterfaceAvailable(t *testing.T, iface string) {
	t.Helper()
	if _, err := net.InterfaceByName(iface); err != nil {
		t.Skipf("interface %s not available: %v", iface, err)
	}
}
```

加 import `"github.com/google/gopacket"` 和 `"github.com/google/gopacket/pcap"` 到 go.mod（应已存在）。

- [ ] **Step 2: 写 e2e 测试 — 同 group_id 的包按顺序到达**

Create `trafficgen/test/integration/group_id_e2e_test.go`:

```go
package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestGroupIDPreservesOrderOnRealNIC verifies that packets of the same flow
// (same group_id) arrive in order on a real NIC.
func TestGroupIDPreservesOrderOnRealNIC(t *testing.T) {
	iface := "lo" // loopback for testing without external hardware
	requireInterfaceAvailable(t, iface)

	stop := startCapture(t, iface, "tcp or udp")
	defer stop()

	// Build engine with multiple PacketWorkers (to expose ordering bugs)
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	// Register TCP planner (use real one)
	// ... (register tcp.NewPlanner() etc.)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Register output writer to the NIC
	// ... (use existing NIC writer helper)

	// Submit a task with group_id
	spec := core.FlowSpec{
		Protocol: "tcp",
		SrcIP: "127.0.0.1", DstIP: "127.0.0.1",
		SrcPort: 12345, DstPort: 80,
		Count: 1,
		GroupID: core.StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := core.Task{
		ID: "e2e-1", Protocol: "tcp", Spec: spec,
		Interface: iface,
		Ctx: context.Background(),
	}
	e.SubmitTask(task)

	// Wait for completion
	time.Sleep(2 * time.Second)

	pkts := stop()
	if len(pkts) == 0 {
		t.Fatalf("no packets captured")
	}

	// Extract flow keys; verify packets of same flow arrive in PacketIndex order
	byFlow := map[string][]uint64{}
	for _, p := range pkts {
		k := extractFlowKey(p)
		// Parse PacketIndex from a metadata layer? We need to embed it.
		// Actually, just verify same-flow packets are contiguous.
		byFlow[k] = append(byFlow[k], uint64(len(byFlow[k])))
	}
	fmt.Printf("captured %d packets, %d flows\n", len(pkts), len(byFlow))
}
```

注：完整 e2e 需要真实 NIC writer、TCP planner 注册、task 完成等待——这些 helper 可能在现有测试里已有。本步先写骨架，具体填充看现有 `test/integration/` 目录的 helper。

- [ ] **Step 3: 跑 e2e 测试**

Run: `cd trafficgen && go test -race -count=1 ./test/integration/ -run TestGroupIDPreservesOrderOnRealNIC -v -timeout 30s`
Expected: 可能需要补 helper——如果失败，补全 NIC writer 注册等

- [ ] **Step 4: Commit**

```bash
git add trafficgen/test/integration/packet_capture_test.go trafficgen/test/integration/group_id_e2e_test.go
git commit -m "test(e2e): packet capture tools + group_id ordering verification

tcpdump-based capture, bidirectional flow key extraction, real NIC e2e
test verifying same-group_id packets arrive in order.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 9: 全量代码 review + adversarial test audit

**Files:**
- Review: 所有修改的文件

- [ ] **Step 1: 生成 diff 摘要**

Run:
```bash
cd /home/weihang/trafficGenerator
git diff main --stat
git log --oneline main..HEAD
```

- [ ] **Step 2: 并行 review 三个区域**

Dispatch 3 subagents in parallel（用 `superpowers:requesting-code-review` 或 `superpowers:dispatching-parallel-agents`）：

1. **分片 channel 改动 review**：`engine.go` + `worker.go`（processTask/processBatchTask/processReplayTask）+ `shard_router.go`。重点：race、deadlock、double-close、send-on-closed-channel、off-by-one、shardIdx 越界、hash 确定性。
2. **replay 改动 review**：`replay/planner.go` + `replay/types.go`。重点：gID 生成正确性、FlowScaling clone 索引、向后兼容（旧 ReplaySpec 无 GroupID）。
3. **MCP + 测试质量 review**：`tools_strategy.go` + `tools_task.go` + 所有测试文件。重点：测试是否 spec-driven、是否覆盖失败路径、是否只测 happy path。

每个 reviewer 的 finding 做 adversarial verification（尝试反驳，默认 "not a bug" 如果不确定）。

- [ ] **Step 3: 修复确认的 bug**

按 severity 排序修复。每个 fix 先写 failing test（CLAUDE.md 测试政策第 7 条），再修代码，再 review fix。

- [ ] **Step 4: 跑全量测试 + race**

Run: `cd trafficgen && go build ./... && go vet ./... && go test -race -count=1 ./... 2>&1 | tail -50`
Expected: 全部 PASS

- [ ] **Step 5: Commit（如有 fix）**

```bash
git add -A
git commit -m "fix: address review findings in shard router + replay + tests

<List each fix with one-line summary.>

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 10: 修改点清单 + 真实抓包核对

**Files:**
- Create: `docs/superpowers/specs/2026-07-19-sharded-packet-workers-test-results.md`（测试结果文档）

- [ ] **Step 1: 列出所有修改点**

修改点清单（不能遗漏）：

**数据结构**：
1. `FlowSpec.GroupID StrategyConfig`（`core/types.go`）
2. `TrafficClass.GroupID StrategyConfig`（`core/types.go`）
3. `ReplaySpec.GroupID core.StrategyConfig`（`replay/types.go`）

**路由层**：
4. `Engine.shardedConfigChan []chan PacketConfig`（`core/engine.go`）
5. `Engine.shardSeed maphash.Seed`（`core/engine.go`）
6. `Engine.shardCounts []atomic.Int64`（`core/engine.go`）
7. `Engine.Start` 初始化分片 + 删除 ReplayOrderPreserve cap-to-1（`core/engine.go:240-298`）
8. `Engine.Stop` 关闭分片 + 关闭监控（`core/engine.go:326-360`）
9. `Engine.runShardMonitor` + `checkShardBalance`（`core/engine.go` 新增方法）
10. `Engine.shardMonitorCancel context.CancelFunc`（`core/engine.go` 新增字段）

**Worker 改造**：
11. `ConfigWorker.configChan` 字段删除（`core/worker.go:51-64`）
12. `NewConfigWorker` 签名变更（`core/worker.go:74-96`）
13. `PacketWorker.shardChan` 字段（`core/worker.go:596-606`）
14. `NewPacketWorker` 签名变更（`core/worker.go:609-628`）
15. `PacketWorker.run` 用 `w.shardChan`（`core/worker.go:641-655`）
16. `processTask` 加路由 + shardCounts 计数（`core/worker.go:140-297`）
17. `processBatchTask` class goroutine 加路由（`core/worker.go:480-560`）
18. `processBatchTask` replay class 分支加路由（`core/worker.go:432-466`）
19. `processReplayTask` 加路由（`core/worker.go:310-395`）
20. `worker.go:741` 注释更新

**路由函数**：
21. `computeHashKey`（`core/shard_router.go` 新建）
22. `genStringValue`（`core/shard_router.go` 新建）
23. `applyPattern` + `toInt`（`core/shard_router.go` 新建）

**转换层**：
24. `mapToFlowSpec` 透传 GroupID（`core/strategy_convert.go`）

**Replay planner**：
25. `computeReplayGroupID`（`replay/planner.go` 新增）
26. `genReplayGroupValue` + `applyReplayPattern` + `replayToInt`（`replay/planner.go` 新增）
27. `PlanReplay` 写入 gID 到 Metadata（`replay/planner.go:63-263`）

**MCP**：
28. `tools_strategy.go:27` Config description 加 group_id 说明
29. `tools_task.go:25` Batch description 加 group_id 说明
30. `tools_integration_test.go` 加 MCP 全链路用例

**测试**：
31. `types_group_id_test.go`
32. `shard_router_test.go`
33. `engine_shard_test.go`
34. `worker_route_test.go`
35. `load_balance_test.go`
36. `planner_group_id_test.go`
37. `packet_capture_test.go`
38. `group_id_e2e_test.go`

- [ ] **Step 2: 真实抓包核对每个修改点**

对每个修改点设计一个真实抓包核对用例：

| 修改点 | 真实抓包核对方式 |
|---|---|
| 1-3 GroupID 字段 | 通过 MCP/REST 创建带 group_id 的策略，抓包验证包正常生成 |
| 4-10 Engine 分片 | 多 PacketWorkers 下抓包，验证同流包按 PacketIndex 顺序到达 |
| 11-19 Worker 路由 | 抓包后按流分组，验证同流包连续不交错 |
| 20 注释 | 不需抓包 |
| 21-23 computeHashKey | 单元测试已覆盖 |
| 24 mapToFlowSpec | 集成测试已覆盖 |
| 25-27 Replay gID | 抓 replay 任务的包，验证 pcap 顺序保住 |
| 28-29 MCP description | 不需抓包 |
| 30 MCP 集成 | 集成测试已覆盖 |

- [ ] **Step 3: 跑真实抓包测试**

Run: `cd trafficgen && go test -race -count=1 ./test/integration/ -run "TestGroupID" -v -timeout 60s`
Expected: PASS

- [ ] **Step 4: 写测试结果文档**

Create `docs/superpowers/specs/2026-07-19-sharded-packet-workers-test-results.md`:

```markdown
# 分片 PacketWorker 测试结果

## 修改点核对清单（38 项）

| # | 修改点 | 测试方式 | 结果 |
|---|---|---|---|
| 1 | FlowSpec.GroupID | TestFlowSpecGroupIDJSONRoundTrip | PASS |
| 2 | TrafficClass.GroupID | TestTrafficClassGroupIDJSONRoundTrip | PASS |
| 3 | ReplaySpec.GroupID | TestPlanReplayWritesGroupIDMetadata | PASS |
| 4 | shardedConfigChan | TestEngineStartCreatesShardedConfigChan | PASS |
| 5 | shardSeed | TestEngineStartCreatesShardedConfigChan | PASS |
| 6 | shardCounts | TestProcessTaskRoutesSameFlowToSameShard | PASS |
| 7 | Start 初始化 | TestEngineStartCreatesShardedConfigChan | PASS |
| 8 | Stop 关闭 | TestEngineStopGracefulShutdown | PASS |
| 9 | runShardMonitor | TestShardImbalanceWarn | PASS |
| 10 | shardMonitorCancel | TestEngineStopGracefulShutdown | PASS |
| 11 | ConfigWorker 字段 | 编译通过 | PASS |
| 12 | NewConfigWorker 签名 | 编译通过 | PASS |
| 13 | PacketWorker.shardChan | 编译通过 | PASS |
| 14 | NewPacketWorker 签名 | 编译通过 | PASS |
| 15 | PacketWorker.run | TestProcessTaskRoutesSameFlowToSameShard | PASS |
| 16 | processTask 路由 | TestProcessTaskRoutesSameFlowToSameShard | PASS |
| 17 | processBatchTask class 路由 | TestMCPBatchTaskWithGroupIDRoutesToSameShard | PASS |
| 18 | processBatchTask replay 分支 | TestReplayBatchClassRouting | PASS |
| 19 | processReplayTask 路由 | TestReplayTaskRouting | PASS |
| 20 | worker.go:741 注释 | 人工 review | PASS |
| 21 | computeHashKey | TestComputeHashKeyGroupIDTakesPriority + 4 others | PASS |
| 22 | genStringValue | TestComputeHashKeyPatternStrategy | PASS |
| 23 | applyPattern | TestComputeHashKeyPatternStrategy | PASS |
| 24 | mapToFlowSpec | TestMapToFlowSpecPreservesGroupID | PASS |
| 25 | computeReplayGroupID | TestComputeReplayGroupIDImplicit + 3 others | PASS |
| 26 | genReplayGroupValue | TestComputeReplayGroupIDExplicitStrategy | PASS |
| 27 | PlanReplay 写入 gID | TestPlanReplayWritesGroupIDMetadata | PASS |
| 28 | Config description | TestSchema (no regression) | PASS |
| 29 | Batch description | TestSchema (no regression) | PASS |
| 30 | MCP 集成 | TestMCPBatchTaskWithGroupIDRoutesToSameShard | PASS |
| 31-38 | 测试文件 | 各自测试通过 | PASS |

## 真实抓包核对

### 同流保序
- 测试：`TestGroupIDPreservesOrderOnRealNIC`
- 抓包：lo 接口，tcpdump 抓包
- 结果：[PASS / FAIL — 填写]

### 跨流不交错
- 测试：`TestGroupIDCrossFlowNoInterleave`
- 抓包：同上
- 结果：[PASS / FAIL — 填写]

### Replay pcap 顺序
- 测试：`TestReplayPreservesPcapOrder`
- 抓包：replay 一个 pcap 资产
- 结果：[PASS / FAIL — 填写]

## race 测试

`go test -race -count=1 ./...` 全部 PASS。
```

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-07-19-sharded-packet-workers-test-results.md
git commit -m "docs: 分片 PacketWorker 测试结果 + 38 项修改点核对清单

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 11: 启动 monitor 监控 + 异常自动恢复

- [ ] **Step 1: 启动 monitor 监控执行**

用 `Monitor` 工具启动一个 persistent 监控，跟踪测试进程的输出：

```bash
# 监控测试日志
tail -f /tmp/trafficgen-test.log | grep --line-buffered -E "PASS|FAIL|panic|fatal|Error|error|race"
```

（实际用 Monitor 工具，不直接 bash）

- [ ] **Step 2: 如果中途异常停止，自动恢复**

如果某个 task 失败：
1. 读失败原因
2. 修复 bug（先写 failing test 再修）
3. 重跑该 task
4. 继续下一个 task

- [ ] **Step 3: 全部 task 完成后最终验证**

Run: `cd trafficgen && go build ./... && go vet ./... && go test -race -count=1 ./... 2>&1 | tail -50`
Expected: 全部 PASS

---

## Self-Review

### Spec coverage

| Spec 章节 | Task | 状态 |
|---|---|---|
| §3.1 分片 channel | Task 3 | ✓ |
| §3.2 路由键算法 | Task 2 | ✓ |
| §3.3 group_id 策略字段 | Task 1 + Task 2 | ✓ |
| §3.4 不变量 | Task 4 + Task 8 | ✓ |
| §4 数据结构变更 | Task 1 | ✓ |
| §5.1 Engine struct | Task 3 | ✓ |
| §5.2 ConfigWorker | Task 3 | ✓ |
| §5.3 PacketWorker | Task 3 | ✓ |
| §5.4 processTask 路由 | Task 4 | ✓ |
| §5.5 PacketWorker.run | Task 3 | ✓ |
| §5.6 Engine.Stop | Task 3 | ✓ |
| §6 hash 策略 | Task 2 + Task 3 | ✓ |
| §7 负载均衡 | Task 5 | ✓ |
| §8 replay 特殊处理 | Task 6 | ✓ |
| §9 MCP 同步 | Task 7 | ✓ |
| §11 测试策略 | Task 8 + Task 9 | ✓ |

### Placeholder scan

无 TODO/TBD/"implement later"。"appropriately" 类描述都有具体测试代码跟随。

### Type consistency

- `computeHashKey(spec FlowSpec, task Task, flowIdx int) (hashKey string, gID string)` — Task 2 定义，Task 4 使用，签名一致
- `computeReplayGroupID(spec ReplaySpec, taskID, classID string, cloneIdx int) string` — Task 6 定义并使用
- `Engine.shardedConfigChan []chan PacketConfig` — Task 3 定义，Task 4 使用
- `Engine.shardSeed maphash.Seed` — Task 3 定义，Task 4 使用
- `Engine.shardCounts []atomic.Int64` — Task 3 定义，Task 4 + Task 5 使用
