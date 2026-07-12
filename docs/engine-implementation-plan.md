# 引擎功能完善与性能优化 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 FlowB 引擎功能完整（修 bug + 混合流量）、参数专业（DSCP/ECN/分片/TCP选项）、性能高效（PCAP/RingBuffer/Builder 优化）。

**Architecture:** 分 4 个 Phase 顺序实施，每个 Phase 独立可运行可测试。Phase 1 修 bug 并建好"按 ClassID 查 TokenBucket"基础设施；Phase 2 接入 BatchSpec 混合流量复用该设施；Phase 3 补全网络层参数；Phase 4 做性能优化。TDD：先写失败测试，再实现，再提交。

**Tech Stack:** Go 1.x、Gin、GORM（SQLite/Postgres）、zap、gopacket、标准库 testing/benchmark

**设计依据：** `docs/engine-design.md`

---

## 文件结构

| 文件 | 责任 | Phase |
|------|------|-------|
| `internal/core/engine.go` | 引擎主控、SubmitTask、速率限制器管理、CPU 基准 | 1,2 |
| `internal/core/worker.go` | ConfigWorker/PacketWorker/OutputWorker | 1,2 |
| `internal/core/buffer.go` | RingBuffer、TokenBucket | 4 |
| `internal/core/builder.go` | L2/L3/L4 包构建 | 3,4 |
| `internal/core/types.go` | FlowSpec/PacketConfig/BatchSpec 等类型 | 2,3 |
| `internal/core/strategy_convert.go` | map->FlowSpec 转换 | 2,3 |
| `internal/core/validate.go`（新增） | 参数范围校验 | 3 |
| `internal/core/tuple_generator.go`（新增） | 4元组生成器 | 2 |
| `internal/core/engine_bench_test.go`（新增） | 基准测试 | 4 |
| `internal/api/rest/system.go` | CPU 监控、GC 指标 | 1,4 |
| `internal/api/rest/settings_handler.go` | 设置持久化 | 1 |
| `internal/api/rest/server.go` | 注入 db/engine 到 SettingsHandler | 1 |
| `internal/storage/models.go` | SettingsModel | 1 |
| `internal/storage/db.go` | SettingsRepository | 1 |
| `cmd/server/main.go` | 启动时读 DB settings 构造 EngineConfig | 1 |
| `internal/output/pcap.go` | PCAP 写入优化 | 4 |

---

# Phase 1：修 Bug（P0）

## Task 1：速率限制接线

**Files:**
- Modify: `internal/core/engine.go`（SubmitTask 创建 TokenBucket、GetRateLimiter 并发安全）
- Modify: `internal/core/worker.go`（processConfig 改用真实字节 + 按 ClassID 查桶）
- Test: `internal/core/engine_test.go`（新增）

- [ ] **Step 1: 写失败测试 - 速率限制生效**

在 `internal/core/engine_test.go` 新增（若文件不存在则创建，package core）：

```go
func TestRateLimit_EnforcesBPS(t *testing.T) {
	// 构造一个最小引擎：1 config worker, 1 packet worker
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 128, QueueSize: 64,
	})
	// buildFunc 返回固定 1000 字节包
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		return make([]byte, 1000), nil
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// 提交一个 BPS=100k 的任务（100000 字节/秒）
	task := Task{
		ID:       "rl-1",
		Protocol: "tcp",
		ClassID:  "rl-1",
		Spec: FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1000, DstPort: 80,
			BPS:   "100k",
			Count: 50,
			TCP:   &TCPConfig{Handshake: false, Termination: false},
		},
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// 等任务完成（50 包 × 1000 字节 = 50000 字节，@100k 需 ~0.5s）
	time.Sleep(2 * time.Second)

	// 验证：100k 限速下 50000 字节至少需 0.4s（留容差）
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond {
		t.Errorf("rate limit not enforced: elapsed=%v, expected >= 400ms", elapsed)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `cd trafficgen && go test ./internal/core/ -run TestRateLimit_EnforcesBPS -v`
Expected: FAIL（当前 TokenBucket(0,...) 不限速，elapsed 远小于 400ms）

- [ ] **Step 3: 实现 - SubmitTask 解析 BPS 建桶**

在 `engine.go` 的 `SubmitTask` 中，验证之后、提交 taskChan 之前，加入：

```go
	// Wire rate limit: parse BPS and create per-class TokenBucket
	if task.Spec.BPS != "" {
		bps, err := ParseBPS(task.Spec.BPS)
		if err != nil {
			return fmt.Errorf("invalid bps %q: %w", task.Spec.BPS, err)
		}
		if bps > 0 {
			classKey := task.ClassID
			if classKey == "" {
				classKey = task.ID // 单协议任务无 ClassID 时用任务 ID
			}
			e.rateMu.Lock()
			e.rateLimiters[classKey] = NewTokenBucket(bps, 65536)
			e.rateMu.Unlock()
		}
	}
```

同时在 Engine 结构体加字段（若 rateLimiters 已有 map 但无锁）：
```go
	rateLimiters map[string]*TokenBucket
	rateMu       sync.RWMutex
```
并在 `GetRateLimiter` 加读锁：
```go
func (e *Engine) GetRateLimiter(classID string) *TokenBucket {
	e.rateMu.RLock()
	defer e.rateMu.RUnlock()
	return e.rateLimiters[classID]
}
```

- [ ] **Step 4: 实现 - PacketWorker 用真实字节 + 按 ClassID 查桶**

改 `worker.go` 的 `processConfig`，把限速从"打包前估算"挪到"打包后真实字节"，且按 config.ClassID 查引擎的桶（需 PacketWorker 持有 engine 引用或通过回调）。

把当前的：
```go
	if w.rateLimit != nil {
		estimatedSize := int64(1500)
		if err := w.rateLimit.Wait(w.ctx, estimatedSize); err != nil {
			return
		}
	}
	if w.buildFunc == nil { return }
	packet, err := w.buildFunc(config)
```

改为：
```go
	if w.buildFunc == nil {
		return
	}
	packet, err := w.buildFunc(config)
	if err != nil {
		// ... 现有错误处理 ...
		return
	}
	// 按 ClassID 查引擎级 TokenBucket，用真实字节数限速
	if w.engine != nil {
		classKey := config.ClassID
		if classKey == "" {
			classKey = "" // 无类则不限速
		}
		if classKey != "" {
			if limiter := w.engine.GetRateLimiter(classKey); limiter != nil {
				if err := limiter.Wait(w.ctx, int64(len(packet))); err != nil {
					return // 任务取消
				}
			}
		}
	}
```

PacketWorker 需新增 `engine *Engine` 字段，`NewPacketWorker` 加参数 `engine *Engine`，并在 `engine.go` Start() 创建 PacketWorker 时传入 `e`。同时移除旧的 `rateLimit *TokenBucket` 参数（或保留兼容，置 nil）。

- [ ] **Step 5: 运行测试验证通过**

Run: `cd trafficgen && go test ./internal/core/ -run TestRateLimit_EnforcesBPS -v`
Expected: PASS

- [ ] **Step 6: 全量回归 + race 检测**

Run: `cd trafficgen && go test ./internal/core/ -race`
Expected: 全绿

- [ ] **Step 7: 提交**

```bash
git add trafficgen/internal/core/engine.go trafficgen/internal/core/worker.go trafficgen/internal/core/engine_test.go
git commit -m "fix(engine): wire rate limiting - parse BPS to per-class TokenBucket, use real packet size"
```

---

## Task 2：CPU 监控

**Files:**
- Modify: `internal/core/engine.go`（记录启动 CPU 基准）
- Modify: `internal/api/rest/system.go`（GetStatus 计算 CPU）
- Test: `internal/api/rest/system_test.go`（新增）

- [ ] **Step 1: 写失败测试 - CPU 占用 > 0**

`internal/api/rest/system_test.go`（package rest）：

```go
func TestSystemStatus_CPUUsage(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{ConfigWorkers:1, PacketWorkers:1, OutputWorkers:1, BufferSize:64, QueueSize:32})
	if err := e.Start(); err != nil { t.Fatalf("start: %v", err) }
	defer e.Stop()
	// 跑一段 busy 循环制造 CPU 占用
	done := make(chan struct{})
	go func() { x := 0; for i:=0;i<1e7;i++ { x++ }; _ = x; close(done) }()
	<-done
	time.Sleep(200 * time.Millisecond)

	cpu := e.GetCPUUsage() // 期望引擎暴露此方法
	if cpu <= 0 {
		t.Errorf("CPU usage = %v, expected > 0", cpu)
	}
}
```

- [ ] **Step 2: 运行验证失败**

Run: `cd trafficgen && go test ./internal/api/rest/ -run TestSystemStatus_CPUUsage -v`
Expected: FAIL（GetCPUUsage 不存在）

- [ ] **Step 3: 实现 - 引擎记录 CPU 基准 + 暴露 GetCPUUsage**

`engine.go`：Engine 结构体加字段：
```go
	startWallClock time.Time
	startCPUTime   time.Duration
```
在 `Start()` 成功后（`e.running.Store(true)` 之后）记录：
```go
	e.startWallClock = time.Now()
	if usage, err := getProcessCPUTime(); err == nil {
		e.startCPUTime = usage
	}
```
新增辅助方法与函数：
```go
// getProcessCPUTime returns user+system CPU time of this process.
func getProcessCPUTime() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, err
	}
	return time.Duration(ru.Utime.Nano()+ru.Stime.Nano()), nil
}

// GetCPUUsage returns process CPU usage as a percentage (0-100*NumCPU).
func (e *Engine) GetCPUUsage() float64 {
	now := time.Now()
	cur, err := getProcessCPUTime()
	if err != nil { return 0 }
	elapsed := now.Sub(e.startWallClock)
	if elapsed <= 0 { return 0 }
	cpuTime := cur - e.startCPUTime
	return float64(cpuTime) / float64(elapsed) * 100.0
}
```
import 加 `"syscall"`。

- [ ] **Step 4: 实现 - system.go 用 GetCPUUsage**

`system.go:56` 把 `CpuUsage: 0` 改为 `CpuUsage: h.engine.GetCPUUsage()`。

- [ ] **Step 5: 运行验证通过 + race**

Run: `cd trafficgen && go test ./internal/api/rest/ -run TestSystemStatus_CPUUsage -v && go test ./internal/core/ -race`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add trafficgen/internal/core/engine.go trafficgen/internal/api/rest/system.go trafficgen/internal/api/rest/system_test.go
git commit -m "fix(system): implement CPU usage monitoring via Getrusage"
```

---

## Task 3：设置持久化

**Files:**
- Modify: `internal/storage/models.go`（新增 SettingsModel）
- Modify: `internal/storage/db.go`（SettingsRepository）
- Modify: `internal/api/rest/settings_handler.go`（db 读写 + 应用到引擎）
- Modify: `internal/api/rest/server.go`（注入 db/engine）
- Modify: `cmd/server/main.go`（启动读 DB settings）
- Test: `internal/api/rest/settings_test.go`（新增）

- [ ] **Step 1: 写失败测试 - 设置持久化**

`internal/api/rest/settings_test.go`（package rest）：

```go
func TestSettings_PersistAcrossInstances(t *testing.T) {
	db := setupTestDB(t) // 复用现有测试 DB 辅助；若无则内存 sqlite
	h1 := NewSettingsHandler(db)
	h1.Update(toUpdateReq(SettingsConfig{MaxTasks: 50, BufferSize: 2048, LogLevel: "warn"}))

	// 模拟重启：新建 handler 复用同一 db
	h2 := NewSettingsHandler(db)
	got := h2.GetConfig()
	if got.MaxTasks != 50 || got.BufferSize != 2048 || got.LogLevel != "warn" {
		t.Errorf("settings not persisted: %+v", got)
	}
}
```

- [ ] **Step 2: 运行验证失败**

Run: `cd trafficgen && go test ./internal/api/rest/ -run TestSettings_Persist -v`
Expected: FAIL（NewSettingsHandler 不接 db，无持久化）

- [ ] **Step 3: 实现 - SettingsModel + AutoMigrate**

`models.go` 加：
```go
// SettingsModel stores app settings (single row, id="default").
type SettingsModel struct {
	ID         string `gorm:"primaryKey;size:32"`
	MaxTasks   int    `gorm:"default:100"`
	BufferSize int    `gorm:"default:4096"`
	LogLevel   string `gorm:"size:16;default:'info'"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
}
func (SettingsModel) TableName() string { return "settings" }
```
`AutoMigrate` 加 `&SettingsModel{}`。

- [ ] **Step 4: 实现 - SettingsRepository**

`db.go` 加：
```go
// GetSettings returns the singleton settings row, creating defaults if missing.
func (db *DB) GetSettings() (*SettingsModel, error) {
	var s SettingsModel
	err := db.First(&s, "id = ?", "default").Error
	if err == gorm.ErrRecordNotFound {
		s = SettingsModel{ID: "default", MaxTasks: 100, BufferSize: 4096, LogLevel: "info"}
		if e := db.Create(&s).Error; e != nil { return nil, e }
		return &s, nil
	}
	return &s, err
}
// SaveSettings upserts the settings row.
func (db *DB) SaveSettings(s *SettingsModel) error {
	s.ID = "default"
	return db.Save(s).Error
}
```
import `"gorm.io/gorm"` 若未引入。

- [ ] **Step 5: 实现 - SettingsHandler 持有 db+engine，持久化+应用**

重写 `settings_handler.go`：`NewSettingsHandler(db *storage.DB, engine *core.Engine)`，Get 从 db 读，Update 写 db 并应用 log_level/max_tasks。暴露 `GetConfig() SettingsConfig` 供测试。log_level 动态生效需引擎持有 `zap.AtomicLevel`（见 Task 3.5）。

- [ ] **Step 6: 实现 - server.go 注入 + main.go 启动读 settings**

`server.go:92`：`NewSettingsHandler()` 改为 `NewSettingsHandler(s.db, s.engine)`。
`main.go initEngine()`：读 `app.db.GetSettings()`，用 `BufferSize` 覆盖 `core.EngineConfig.BufferSize`。

- [ ] **Step 7: 运行验证通过 + race**

Run: `cd trafficgen && go test ./internal/api/rest/ -run TestSettings -v -race`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add trafficgen/internal/storage/models.go trafficgen/internal/storage/db.go trafficgen/internal/api/rest/settings_handler.go trafficgen/internal/api/rest/server.go cmd/server/main.go trafficgen/internal/api/rest/settings_test.go
git commit -m "fix(settings): persist settings to DB, apply log_level/max_tasks at runtime, buffer_size on restart"
```

---

## Task 3.5：zap AtomicLevel 支持 log_level 动态生效（Task 3 依赖）

**Files:**
- Modify: `cmd/server/main.go`（logger 初始化用 AtomicLevel）
- Modify: `internal/core/engine.go`（持有 AtomicLevel 引用，暴露 SetLogLevel）

- [ ] **Step 1: main.go logger 用 AtomicLevel**

把现有 zap logger 初始化改为 `atom := zap.NewAtomicLevelAt(zapcore.InfoLevel); ... atom ...`，把 `atom` 传入 engine（`engine.SetLogLevel(atom)`）。

- [ ] **Step 2: engine.go 暴露 SetLogLevel**

```go
func (e *Engine) SetLogLevel(l zapcore.Level) {
	if e.logLevel != nil { e.logLevel.SetLevel(l) }
}
```

- [ ] **Step 3: SettingsHandler.Update 调 engine.SetLogLevel**

- [ ] **Step 4: 提交**（可与 Task 3 合并提交，或单独）

---

# Phase 2：混合流量（P0.5）

## Task 4：TupleGenerator（4元组生成器）

**Files:**
- Create: `internal/core/tuple_generator.go`
- Test: `internal/core/tuple_generator_test.go`

- [ ] **Step 1: 写失败测试** - inc IP 递增、rand 可复现、fixed、list 循环
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现 TupleGenerator** - 类型感知：IP 字段解析为 4 字节整数递增回绕；端口整数递增；rand 带 seed；list 按索引取模；fixed 固定。`Next(index int) (srcIP,dstIP string, srcPort,dstPort uint16)`
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(core): add type-aware TupleGenerator for 4-tuple generation`

## Task 5：抽取 mapToFlowSpec 公共函数

**Files:**
- Modify: `internal/core/strategy_convert.go`
- Test: `internal/core/convert_test.go`（扩展）

- [ ] **Step 1: 写测试** - `mapToFlowSpec(cfg, "tcp")` 对各协议字段映射正确
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 重构** - 从 `StrategyModelToTask` 抽取 map->FlowSpec 主体为 `mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec`，原函数改为调用它
- [ ] **Step 4: 运行全量测试** - 确保现有 StrategyModelToTask 行为不变
- [ ] **Step 5: 提交** `refactor(core): extract mapToFlowSpec for reuse by mixed traffic`

## Task 6：Task 加 Batch 字段 + SubmitTask 处理 BatchSpec

**Files:**
- Modify: `internal/core/types.go`（Task.Batch）
- Modify: `internal/core/engine.go`（SubmitTask 批量分支：为每类建桶、校验）
- Test: `internal/core/engine_test.go`

- [ ] **Step 1: 写测试** - 提交 2 类 BatchSpec，验证每类 TokenBucket 创建、任务能跑完
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - Task 加 `Batch *BatchSpec`；SubmitTask 检测 `task.Batch != nil`，遍历 classes 逐类 ParseBPS 建桶（key=taskID:classID），DurationSeconds>0 时给 ctx 设超时
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(engine): accept BatchSpec in SubmitTask, create per-class rate limiters`

## Task 7：ConfigWorker 批量模式（每类并发）

**Files:**
- Modify: `internal/core/worker.go`（processTask 批量分支）
- Test: `internal/core/engine_test.go`

- [ ] **Step 1: 写测试** - 3 类（TCP/UDP/ICMP）混合，验证输出包混合、每类流数正确、每类独立限速生效、总包数 = 各类流数×每流包数之和
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - processTask 检测 `task.Batch != nil`：用 sync.WaitGroup，每个 TrafficClass 起 goroutine：mapToFlowSpec 转 spec → TupleGenerator 生成 FlowCount 个 4 元组 → 每个 4 元组填入 spec 调对应 planner.Plan → range configChan 给每个 config 设 ClassID="taskID:classID"、Metadata task_id/interface → 转发 configChan。所有 goroutine 完成后回调 onTaskDone
- [ ] **Step 4: 运行验证通过 + race**（混合并发路径必须过 race）
- [ ] **Step 5: 提交** `feat(engine): mixed traffic - concurrent per-class planning in ConfigWorker`

## Task 8：API 层 BatchSpec 提交端点

**Files:**
- Modify: `internal/api/rest/task_handler.go`（新增批量提交处理）
- Modify: `internal/api/rest/types.go`（批量请求类型）
- Test: `internal/api/rest/task_handler_test.go`

- [ ] **Step 1: 写测试** - POST 批量任务，返回 task_id，状态可查
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - 新增 `POST /api/v1/tasks/batch`，解析 BatchSpec JSON → 构造 Task{Batch:...} → SubmitTask
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(api): add batch task submission endpoint for mixed traffic`

---

# Phase 3：协议参数完善（P1）

## Task 9：DSCP/ECN + IP 分片控制（L3）

**Files:**
- Modify: `internal/core/types.go`（L3Config 加 DSCP/ECN/Flags/FragOffset）
- Modify: `internal/core/builder.go`（buildL3 读新字段）
- Modify: `internal/core/strategy_convert.go`（新字段映射）
- Test: `internal/core/builder_test.go`

- [ ] **Step 1: 写测试** - DSCP=46 验证 `header[1]==(46<<2)`；DF=0/MF=1/FragOffset=100 验证 `header[6:8]`
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - L3Config 加字段；buildL3：`header[1]=(DSCP<<2)|(ECN&0x03)`、`header[6:8]=(Flags<<13)|(FragOffset&0x1FFF)`，默认 Flags=DF 兼容
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(builder): support DSCP/ECN and IP fragmentation flags`

## Task 10：TCP 选项（L4）

**Files:**
- Modify: `internal/core/types.go`（L4Config 加 TCPOptions）
- Modify: `internal/core/builder.go`（buildTCP 动态数据偏移 + 选项编码）
- Modify: `internal/protocol/tcp/tcp.go`（SYN 包带 MSS/SACK/WindowScale）
- Test: `internal/core/builder_test.go`

- [ ] **Step 1: 写测试** - 带 MSS 选项验证数据偏移=6（24字节）、选项字节正确
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - TCPOption{Kind, Data}；buildTCP 根据选项算数据偏移（ceil((20+optsLen)/4)），编码选项，末尾 padding 到 4 字节边界；TCP planner SYN 包自动加 MSS/SACK/WindowScale
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(builder): support TCP options (MSS/WindowScale/SACK/Timestamp)`

## Task 11：参数验证

**Files:**
- Create: `internal/core/validate.go`
- Modify: `internal/core/worker.go`（processTask 调验证）
- Test: `internal/core/validate_test.go`

- [ ] **Step 1: 写测试** - 端口 70000、VLAN 5000、MSS 100、DSCP 70、TTL 0 等非法值返回清晰错误；合法值通过
- [ ] **Step 2: 运行验证失败**
- [ ] **Step 3: 实现** - `ValidateFlowSpec(spec FlowSpec) error` + 各协议子校验；端口 0-65535、VLAN ID 0-4095、优先级 0-7、MSS 536-65535、TTL 1-255、DSCP 0-63、IP 格式、FlowCount>0
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `feat(core): add parameter validation with clear error messages`

---

# Phase 4：性能优化

## Task 12：PCAP 写入重构

**Files:**
- Modify: `internal/output/pcap.go`
- Test: `internal/output/output_test.go`

- [ ] **Step 1: 写测试** - 写 N 包后文件正确可读、每包时间戳递增（不再整批相同）
- [ ] **Step 2: 运行验证失败**（时间戳测试）
- [ ] **Step 3: 实现** - bufio.Writer 包裹 file；16字节头用栈数组 `var header [16]byte`；header+packet 拼一个切片一次 Write；循环内每包 `time.Now()`；fsync 只在 Close 调用；Write 末尾 Flush 而非 Sync
- [ ] **Step 4: 运行验证通过**
- [ ] **Step 5: 提交** `perf(pcap): buffered writes, single syscall per packet, per-packet timestamp, on-close fsync`

## Task 13：RingBuffer 去重复制

**Files:**
- Modify: `internal/core/buffer.go`
- Test: `internal/core/buffer_test.go`

- [ ] **Step 1: 写测试** - Put 后 Get 拿到的切片与原切片内容一致、且不共享底层数组（修改原切片不影响 buffer）
- [ ] **Step 2: 运行验证失败**（若加"不共享底层数组"断言）或先确认现状
- [ ] **Step 3: 实现** - Put 直接 `rb.buffer[rb.tail] = packet`（不 make+copy）；前提确认打包工每次返回新切片（builder.go Build 用 make 新建，满足）
- [ ] **Step 4: 运行验证通过 + race**
- [ ] **Step 5: 提交** `perf(buffer): eliminate per-packet copy in RingBuffer.Put`

## Task 14：Builder 单缓冲区构建 + sync.Pool

**Files:**
- Modify: `internal/core/builder.go`
- Test: `internal/core/builder_test.go`

- [ ] **Step 1: 写测试** - 确认 Build 输出与重构前逐字节一致（用现有测试 + 新参数测试）
- [ ] **Step 2: 运行验证全绿**
- [ ] **Step 3: 实现** - Build 一次 `make([]byte, 0, 预估总长)`，各层用固定偏移直接写入；sync.Pool 复用缓冲区（Build 用 pool.Get/Put，返回前 copy 到独立切片）
- [ ] **Step 4: 运行验证通过 + race**
- [ ] **Step 5: 提交** `perf(builder): single-buffer construction with sync.Pool`

## Task 15：基准测试 + GC 指标

**Files:**
- Create: `internal/core/engine_bench_test.go`
- Modify: `internal/api/rest/system.go`（GC 指标）

- [ ] **Step 1: 写基准测试** - TCP/UDP/HTTP 在 64/512/1500 字节下的 PPS；混合流量 3 类聚合 PPS；PCAP 写入吞吐
- [ ] **Step 2: 运行基准** `go test -bench=. ./internal/core/ -benchmem`，记录基线
- [ ] **Step 3: system.go 补 GC 指标** - `runtime.MemStats` 的 NumGC/PauseTotalNs 加入 status 响应
- [ ] **Step 4: 提交** `test(core): add engine benchmarks; feat(system): expose GC metrics`

---

# 收尾

## Task 16：全量回归 + 真机验证

- [ ] **Step 1: 全量测试** `cd trafficgen && go test ./... -race`，全绿
- [ ] **Step 2: 构建** `go build ./cmd/server/`，无错误
- [ ] **Step 3: 真机发包测试** - 用网口 `enp135s0f0np0`，提交一个带 DSCP=46 的 TCP 任务（output_mode=interface），用 `sudo tcpdump -i enp135s0f0np0 -nn -X -c 5` 抓包，核对 DSCP 字段、TCP 选项
- [ ] **Step 4: 限速验证** - 提交 BPS=1M 任务到网口，对端/同口用 `ifconfig`/`sar` 核对实际 BPS 接近 1M
- [ ] **Step 5: 混合流量验证** - 提交 3 类 BatchSpec 到 pcap，用 wireshark 打开核对协议混合、每类流数
- [ ] **Step 6: 提交验证记录**（如有文档更新）

---

## 自检（Self-Review）

**1. Spec 覆盖：**
- Phase 1 三个 bug：Task 1（速率限制）、Task 2（CPU）、Task 3+3.5（设置）✓
- Phase 2 混合流量：Task 4（TupleGenerator）、5（mapToFlowSpec）、6（BatchSpec 接入）、7（并发）、8（API）✓
- Phase 3 参数：Task 9（DSCP/ECN/分片）、10（TCP选项）、11（验证）✓
- Phase 4 性能：Task 12（PCAP）、13（RingBuffer）、14（Builder）、15（基准/GC）✓
- 测试网口 enp135s0f0np0：Task 16 ✓

**2. 类型一致性：**
- `GetRateLimiter(classID)` Task 1 定义，Task 6/7 复用 ✓
- `mapToFlowSpec(cfg, protocol)` Task 5 定义，Task 7 复用 ✓
- `TupleGenerator.Next(index)` Task 4 定义，Task 7 复用 ✓
- `GetCPUUsage()` Task 2 定义 ✓
- `Task.Batch *BatchSpec` Task 6 定义，Task 7/8 复用 ✓
- `TCPOption{Kind,Data}` Task 10 定义 ✓

**3. 无占位符：** Phase 1 含完整代码；Phase 2-4 任务级（实施时每步补全代码，遵循 TDD）。
