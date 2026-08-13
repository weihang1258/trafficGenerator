package core

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// Engine is the main traffic generation engine.
type Engine struct {
	config    EngineConfig
	planners  map[string]ProtocolPlanner
	buildFunc func(PacketConfig) ([]byte, error)
	// replayPlanner handles TrafficClass.Type=="replay" (§16.12). May be nil if
	// replay isn't wired (then replay classes are rejected).
	replayPlanner ReplayPlanner
	// layerPlannerFactory builds a per-task ChainPlanner from a "layers"
	// config JSON (P2c 层链驱动生成). Injected by the server via
	// SetLayerPlannerFactory (wired to layers.BuildLayersPlanner in
	// cmd/server/main.go); nil when layers aren't wired (unit tests).
	// layerPlanners holds the built planners per task ID; written during
	// SubmitTask (pre-Start or while running, guarded by taskMu) and read
	// by ConfigWorkers after Start, so all reads happen after the last
	// write for any running task (engine adds tasks before the workers
	// can observe them — SubmitTask and Start are synchronized by the
	// caller, and per-task ID writes happen-before the task's first
	// config reaches the worker via the task channel).
	layerPlannerFactory func(protocol string, layersJSON json.RawMessage) (ProtocolPlanner, error)
	layerPlanners       map[string]ProtocolPlanner

	// Channels
	taskChan chan Task
	// stopChan is a closed-during-stop guard. SubmitTask selects on it so a
	// concurrent submit racing Engine.Stop cannot send on a closed taskChan
	// (send-on-closed panic). Never closed in place; rebuilt as an open chan
	// at Start and swapped for a closed chan at Stop. channelMu guards the
	// taskChan + stopChan pointer pair so reads and writes of both fields
	// are atomic across Stop/Start cycles (avoids field-level data race
	// between SubmitTask reading them and Stop/Start swapping them).
	stopChan   chan struct{}
	channelMu  sync.Mutex
	// packetChan removed: replaced by shardedPacketChan (one per OutputWorker).

	// Sharded config channel: one per PacketWorker. ConfigWorker pushes to
	// shardedConfigChan[shardIdx] after computing shardIdx from group_id or
	// 4-tuple hash. Each PacketWorker reads only its own shard, guaranteeing
	// per-flow FIFO (spec §3.1).
	shardedConfigChan []chan PacketConfig
	// Sharded packet channel: one per OutputWorker. PacketWorker pushes to
	// shardedPacketChan[w.id] (same shardIdx as its config shard). Each
	// OutputWorker reads only its own shard. This closes the second ordering
	// gap: without sharding here, multiple OutputWorkers pulling from a shared
	// packetChan would reorder same-flow packets (large packet slow, small
	// packet fast -> small overtakes large on the wire).
	shardedPacketChan []chan PacketOutput
	shardSeed         maphash.Seed       // random seed for hash, anti-flooding
	shardCounts       []atomic.Int64     // per-shard enqueue count, for imbalance monitor
	shardMonitorCancel context.CancelFunc // stops runShardMonitor on Engine.Stop

	// Workers
	configWorkers []*ConfigWorker
	packetWorkers []*PacketWorker
	outputWorkers []*OutputWorker

	// Buffers
	buffer *PacketBuffer

	// Output writers indexed by task ID for per-task output routing
	outputWriters map[string]PacketWriter
	// dualWriters holds the two writers (c2s, s2c) for dual-port tasks (§16.11).
	// When present for a task, the OutputWorker routes by Direction instead of
	// using outputWriters[taskID].
	dualWriters map[string]*DualPortWriter
	outputMu    sync.RWMutex

	// Rate limiters
	rateLimiters map[string]*TokenBucket
	rateMu       sync.RWMutex

	// Flow counters for task-level flows ceiling. Keyed by parentTaskID.
	flowCounters map[string]*int64

	// State
	running   atomic.Bool
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	taskStore map[string]*taskEntry
	taskMu    sync.RWMutex

	// CPU monitoring baseline (recorded at Start)
	startWallClock time.Time
	startCPUTime   time.Duration

	// maxTasks caps the number of concurrently active tasks (0 = unlimited).
	// Set from persisted settings; enforced in SubmitTask.
	maxTasks atomic.Int64

	// Callbacks
	OnTaskComplete   func(taskID string)                // called when a task finishes (completed or failed)
	OnTaskFailed     func(taskID string, errMsg string) // called when a task fails with error message
	OnBufferOverflow func(taskID string, dropped int)   // called when buffer overflows
	OnOutputError    func(taskID string, err error)     // called when output writer fails
	OnProgress       func(taskID string, progress float64, stats TaskStats) // called when task progress changes

	// Error handling
	fatalError atomic.Value

	// payloadCache holds the engine-wide PayloadCache used to resolve
	// FileSource payloads for ftp/sip/sctp/http/icmp planners. The server
	// (cmd/server) constructs it from a filesystem.Filesystem and calls
	// SetPayloadCache once at startup; the worker reads it via
	// PayloadCache() and injects it into each task's ctx via
	// WithPayloadCache so planners can call PayloadCacheFrom(ctx).
	// May be nil when the engine runs without a filesystem (e.g. tests,
	// or a deployment that doesn't use FileSource); planners treat nil
	// as "skip FileSource resolution" rather than erroring.
	payloadCache *PayloadCache
}

// PacketWriter writes raw packets to an output (pcap file, network interface, etc.).
type PacketWriter interface {
	WritePackets(packets [][]byte) error
	Close() error
}

// TimedWriter is an optional interface a PacketWriter may implement to receive
// the scheduled send timestamp for each packet (§12: pcap output uses the
// scheduled send time, not time.Now()). The OutputWorker prefers
// WriteTimedPackets when the writer implements this interface; otherwise it
// falls back to WritePackets (which stamps time.Now() internally).
type TimedWriter interface {
	WriteTimedPackets(packets []PacketOutput) error
}

// writePacketsTo dispatches a single PacketOutput to a writer, preferring the
// timed path when available so pcap output preserves the scheduled send time.
func writePacketsTo(w PacketWriter, out PacketOutput) error {
	if tw, ok := w.(TimedWriter); ok {
		return tw.WriteTimedPackets([]PacketOutput{out})
	}
	return w.WritePackets([][]byte{out.Data})
}

// PacketOutput carries a built packet with its routing metadata.
type PacketOutput struct {
	Data        []byte
	Metadata    map[string]interface{}
	FlowID      string
	PacketIndex uint64
	Direction   string // c2s|s2c (or up|down for synth) -- drives dual-port routing
	Timestamp   time.Time // scheduled send time (§12: pcap output uses this, not time.Now())
}

type taskEntry struct {
	task   *Task
	status *TaskStatus
	cancel context.CancelFunc

	// Pipeline drain tracking: ConfigWorker sets totalConfigs when done,
	// OutputWorker increments writtenPackets per write, PacketWorker reports
	// build failures via OnPacketBuildError.
	// Completion fires when totalConfigs > 0 and every planned config is
	// accounted for (writtenPackets + errorPackets >= totalConfigs).
	totalConfigs   int64
	writtenPackets int64
	errorPackets   int64
	firstBuildErr  string
}

// EngineConfig for engine configuration.
type EngineConfig struct {
	ConfigWorkers  int
	PacketWorkers  int
	OutputWorkers  int
	BufferSize     int
	QueueSize      int
	MaxBufferBytes int64
	// ReplayOrderPreserve caps PacketWorkers to 1 when true, preserving pcap
	// file order for replay tasks (§13 hard guarantee). Multi-worker replay is
	// v2 (§17: "多 PacketWorker 并行 replay 保序需单工，暂缓"). Set this when
	// the engine will run replay tasks; synth-only engines can use N workers.
	ReplayOrderPreserve bool
	// MinMTU is the minimum NIC MTU enforced at task start. If an interface's
	// MTU is below this value, trafficgen runs `ip link set dev <iface> mtu
	// <min_mtu>` (requires CAP_NET_ADMIN / root) before submitting the task.
	// Original MTU is NOT restored after the task ends (logged at WARN).
	// 0 disables the check. Default 2000 (set by config defaults).
	MinMTU int
}

// NewEngine creates a new traffic engine.
func NewEngine(config EngineConfig) *Engine {
	return &Engine{
		config:        config,
		planners:      make(map[string]ProtocolPlanner),
		rateLimiters:  make(map[string]*TokenBucket),
		flowCounters:  make(map[string]*int64),
		taskStore:     make(map[string]*taskEntry),
		outputWriters: make(map[string]PacketWriter),
		dualWriters:   make(map[string]*DualPortWriter),
		layerPlanners: make(map[string]ProtocolPlanner),
	}
}

// RegisterPlanner registers a protocol planner.
func (e *Engine) RegisterPlanner(planner ProtocolPlanner) {
	e.planners[planner.Name()] = planner
}

// SetLayerPlannerFactory wires the injected layer-planner factory (P2c 层链
// 驱动生成). It builds a per-task ChainPlanner from a raw "layers" config
// JSON. The server wires it to layers.BuildLayersPlanner in main.go; core
// itself cannot import layers (layers imports core). Must be called before
// Start — the factory is read by SubmitTask but never mutated afterwards.
func (e *Engine) SetLayerPlannerFactory(fn func(protocol string, layersJSON json.RawMessage) (ProtocolPlanner, error)) {
	e.layerPlannerFactory = fn
}

// layerPlannerFor returns the per-task ChainPlanner for taskID, or nil when
// the task has no layers config (legacy protocol-name path). RLock guards the
// map read against concurrent deletes at task completion (FailTask /
// SetTaskTotalConfigs / StopTask all hold taskMu when removing entries).
func (e *Engine) layerPlannerFor(taskID string) ProtocolPlanner {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()
	return e.layerPlanners[taskID]
}

// ListProtocols returns all registered protocol names.
func (e *Engine) ListProtocols() []string {
	names := make([]string, 0, len(e.planners))
	for name := range e.planners {
		names = append(names, name)
	}
	return names
}

// SetBuildFunc sets the packet building function.
func (e *Engine) SetBuildFunc(fn func(PacketConfig) ([]byte, error)) {
	e.buildFunc = fn
}

// SetPayloadCache wires the engine-wide PayloadCache used to resolve
// FileSource payloads. The cache is constructed by the server (cmd/server)
// from a filesystem.Filesystem and set once at startup. The worker reads
// it via PayloadCache() and injects it into each task's ctx so the
// ftp/sip/sctp/http/icmp planners can call PayloadCacheFrom(ctx). May be
// left nil when FileSource isn't used.
func (e *Engine) SetPayloadCache(pc *PayloadCache) {
	e.payloadCache = pc
}

// PayloadCache returns the cache set by SetPayloadCache, or nil if none
// was set. The worker uses this to inject the cache into per-task ctx
// via WithPayloadCache.
func (e *Engine) PayloadCache() *PayloadCache {
	return e.payloadCache
}

// MinMTU returns the configured minimum NIC MTU enforced at task start.
// Returns 0 when the check is disabled. Callers (task handler) use this
// to decide whether to run `ip link set` before submitting a task.
func (e *Engine) MinMTU() int {
	return e.config.MinMTU
}

// DualPortWriter holds the two writers for a dual-port task: C2S (client->server,
// primary interface) and S2C (server->client, secondary interface).
type DualPortWriter struct {
	C2S PacketWriter
	S2C PacketWriter
}

// RegisterDualWriter registers a dual-port writer pair for a task (§16.11).
// When set, the OutputWorker routes packets by Direction to the matching writer.
func (e *Engine) RegisterDualWriter(taskID string, c2s, s2c PacketWriter) {
	e.outputMu.Lock()
	e.dualWriters[taskID] = &DualPortWriter{C2S: c2s, S2C: s2c}
	e.outputMu.Unlock()
}

// UnregisterDualWriter removes + closes a task's dual-port writers.
func (e *Engine) UnregisterDualWriter(taskID string) {
	e.outputMu.Lock()
	dw, ok := e.dualWriters[taskID]
	if ok {
		delete(e.dualWriters, taskID)
	}
	e.outputMu.Unlock()
	if ok && dw != nil {
		if dw.C2S != nil {
			dw.C2S.Close()
		}
		if dw.S2C != nil {
			dw.S2C.Close()
		}
	}
}

// GetDualWriter returns the dual-port writer pair for a task (or nil).
func (e *Engine) GetDualWriter(taskID string) *DualPortWriter {
	e.outputMu.RLock()
	defer e.outputMu.RUnlock()
	return e.dualWriters[taskID]
}

// SetReplayPlanner registers the replay planner (handles TrafficClass.Type=="replay").
func (e *Engine) SetReplayPlanner(p ReplayPlanner) {
	e.replayPlanner = p
}

// RegisterOutputWriter registers a packet writer for a task.
func (e *Engine) RegisterOutputWriter(taskID string, writer PacketWriter) {
	e.outputMu.Lock()
	e.outputWriters[taskID] = writer
	e.outputMu.Unlock()
}

// UnregisterOutputWriter removes and closes a task's output writer. Close runs
// outside the outputMu lock because PCAPWriter.Close fsyncs (can block); holding
// the write-lock during fsync would stall all packet output across all tasks.
func (e *Engine) UnregisterOutputWriter(taskID string) {
	e.outputMu.Lock()
	w, ok := e.outputWriters[taskID]
	if ok {
		delete(e.outputWriters, taskID)
	}
	e.outputMu.Unlock()
	if ok && w != nil {
		w.Close()
	}
}

// Start starts the engine.
func (e *Engine) Start() error {
	if e.running.Load() {
		return fmt.Errorf("engine already running")
	}

	// Initialize context
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Initialize channels
	e.channelMu.Lock()
	e.taskChan = make(chan Task, e.config.QueueSize)
	e.stopChan = make(chan struct{})
	e.channelMu.Unlock()
	e.shardSeed = maphash.MakeSeed()
	pw := e.config.PacketWorkers
	if pw <= 0 {
		pw = 1
	}
	// ReplayOrderPreserve no longer caps PacketWorkers to 1 (spec §8.3):
	// replay with empty group_id uses implicit gID "taskID:classID" so all
	// packets land on one shard via hash, preserving pcap order without
	// forcing single-worker.
	e.shardedConfigChan = make([]chan PacketConfig, pw)
	e.shardCounts = make([]atomic.Int64, pw)
	for i := 0; i < pw; i++ {
		e.shardedConfigChan[i] = make(chan PacketConfig, e.config.QueueSize*2)
	}
	// Sharded packet channel: OutputWorkers count forced to PacketWorkers
	// count so each OutputWorker[i] reads shardedPacketChan[i] (1:1 with
	// PacketWorker[i]). This closes the OutputWorker-layer ordering gap.
	ow := e.config.OutputWorkers
	if ow != pw {
		zap.L().Info("forcing OutputWorkers=PacketWorkers for shard 1:1 mapping",
			zap.Int("configured_output_workers", ow),
			zap.Int("actual_output_workers", pw))
		ow = pw
	}
	e.shardedPacketChan = make([]chan PacketOutput, ow)
	for i := 0; i < ow; i++ {
		e.shardedPacketChan[i] = make(chan PacketOutput, e.config.QueueSize*2)
	}

	// Initialize buffer
	e.buffer = NewPacketBuffer(PacketBufferConfig{
		Size:           e.config.BufferSize,
		MaxBytes:       e.config.MaxBufferBytes,
		EnableCombined: true,
	})

	// Start config workers
	e.configWorkers = make([]*ConfigWorker, e.config.ConfigWorkers)
	for i := 0; i < e.config.ConfigWorkers; i++ {
		e.wg.Add(1)
		// ConfigWorker accesses sharded channels via w.engine.shardedConfigChan
		worker := NewConfigWorker(i, e.planners, e.replayPlanner, e.taskChan, &e.wg, e)
		worker.SetOnTaskDone(func(taskID string, err error, count int64) {
			if err != nil {
				e.FailTask(taskID, err.Error())
			} else {
				e.SetTaskTotalConfigs(taskID, count)
			}
		})

		e.configWorkers[i] = worker
		worker.Start()
	}

	// Default buildFunc if none registered
	buildFn := e.buildFunc
	if buildFn == nil {
		buildFn = func(config PacketConfig) ([]byte, error) {
			return make([]byte, 64), nil
		}
	}

	// Start packet workers, one per shard.
	e.packetWorkers = make([]*PacketWorker, pw)
	for i := 0; i < pw; i++ {
		e.wg.Add(1)
		// Each PacketWorker reads only its own config shard channel and
		// writes to its own packet shard channel (same index i).
		worker := NewPacketWorker(i, e.shardedConfigChan[i], buildFn, &e.wg, e)
		e.packetWorkers[i] = worker
		worker.Start()
	}

	// Start output workers, one per shard (ow == pw enforced above).
	e.outputWorkers = make([]*OutputWorker, ow)
	for i := 0; i < ow; i++ {
		e.wg.Add(1)
		worker := NewOutputWorker(i, e.shardedPacketChan[i], e.buffer, e, &e.wg)
		e.outputWorkers[i] = worker
		worker.Start()
	}

	e.running.Store(true)

	// Start shard load imbalance monitor (spec §7.2)
	monCtx, monCancel := context.WithCancel(context.Background())
	e.shardMonitorCancel = monCancel
	go e.runShardMonitor(monCtx)

	// Record CPU monitoring baseline.
	e.startWallClock = time.Now()
	if usage, err := getProcessCPUTime(); err == nil {
		e.startCPUTime = usage
	}

	zap.L().Info("engine started",
		zap.Int("config_workers", e.config.ConfigWorkers),
		zap.Int("packet_workers", e.config.PacketWorkers),
		zap.Int("output_workers", e.config.OutputWorkers),
	)

	return nil
}

// Stop stops the engine.
func (e *Engine) Stop() {
	if !e.running.Load() {
		return
	}

	e.running.Store(false)

	// Stop shard load monitor first (no more warnings during shutdown)
	if e.shardMonitorCancel != nil {
		e.shardMonitorCancel()
		e.shardMonitorCancel = nil
	}

	// Swap taskChan for a stop guard so a concurrent SubmitTask racing this
	// Stop selects the stopChan branch instead of sending on a closed
	// taskChan (send-on-closed panic). The channel is never closed.
	stopChan := make(chan struct{})
	close(stopChan)
	e.channelMu.Lock()
	e.stopChan = stopChan
	e.channelMu.Unlock()

	// Cancel engine context (also cancels per-task contexts derived from it)
	e.cancel()

	// Cancel all worker contexts so they exit their select loops
	for _, w := range e.configWorkers {
		w.Stop()
	}
	for _, w := range e.packetWorkers {
		w.Stop()
	}
	for _, w := range e.outputWorkers {
		w.Stop()
	}

	// Wait for all workers to finish
	e.wg.Wait()

	// Close remaining channels (safe now since all workers exited)
	for i := range e.shardedConfigChan {
		close(e.shardedConfigChan[i])
	}
	e.shardedConfigChan = nil
	for i := range e.shardedPacketChan {
		close(e.shardedPacketChan[i])
	}
	e.shardedPacketChan = nil

	// Close buffer
	if e.buffer != nil {
		e.buffer.Close()
	}

	// Close all registered output writers. Without this, stopping the engine
	// mid-task leaks file handles and skips the PCAPWriter Close fsync (data
	// loss). Close outside the outputMu lock to avoid blocking output.
	e.outputMu.Lock()
	writers := make([]PacketWriter, 0, len(e.outputWriters))
	for id, w := range e.outputWriters {
		writers = append(writers, w)
		delete(e.outputWriters, id)
	}
	e.outputMu.Unlock()
	for _, w := range writers {
		if w != nil {
			w.Close()
		}
	}

	// Close dual-port writer pairs (same leak-prevention rationale).
	e.outputMu.Lock()
	duals := make([]*DualPortWriter, 0, len(e.dualWriters))
	for id, dw := range e.dualWriters {
		duals = append(duals, dw)
		delete(e.dualWriters, id)
	}
	e.outputMu.Unlock()
	for _, dw := range duals {
		if dw != nil {
			if dw.C2S != nil {
				dw.C2S.Close()
			}
			if dw.S2C != nil {
				dw.S2C.Close()
			}
		}
	}

	zap.L().Info("engine stopped")
}

// runShardMonitor periodically samples shardCounts and warns on severe
// imbalance (spec §7.2). Does NOT do dynamic rebalance — that would break
// per-flow ordering (shardIdx is sticky for a given gID).
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
// Avoids div-by-zero; no-op when all shards are zero.
func (e *Engine) checkShardBalance() {
	n := len(e.shardCounts)
	if n == 0 {
		return
	}
	var sum int64
	counts := make([]int64, n)
	for i := range e.shardCounts {
		c := e.shardCounts[i].Load()
		counts[i] = c
		sum += c
	}
	avg := sum / int64(n)
	if avg == 0 {
		return
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

// SubmitTask submits a task for execution.
func (e *Engine) SubmitTask(task Task) error {
	if !e.running.Load() {
		return fmt.Errorf("engine not running")
	}

	// Validate task
	if err := ValidateTask(task); err != nil {
		return fmt.Errorf("task validation failed: %w", err)
	}

	// Enforce max concurrent tasks (0 = unlimited).
	if max := e.maxTasks.Load(); max > 0 && int64(e.activeTaskCount()) >= max {
		return fmt.Errorf("max_tasks limit reached (%d active)", max)
	}

	// Wire rate limit: per-strategy child bucket + optional task-level parent
	// bucket (ceiling). Child bucket is keyed by ClassID (= engine task ID);
	// parent bucket is keyed by ParentTaskID.
	if task.Batch != nil {
		// Mixed traffic: create an independent bucket per class, keyed
		// "taskID:classID" so classes sharing the engine don't collide.
		for _, c := range task.Batch.Classes {
			if c.BPS == "" {
				continue
			}
			bps, err := ParseBPS(c.BPS)
			if err != nil {
				return fmt.Errorf("class %s invalid bps %q: %w", c.ID, c.BPS, err)
			}
			if bps > 0 {
				e.SetClassRateLimit(task.ID+":"+c.ID, bps)
			}
		}
	} else if task.Spec.BPS != "" {
		// Single-protocol / strategy-reference: child bucket keyed by ClassID.
		bps, err := ParseBPS(task.Spec.BPS)
		if err != nil {
			return fmt.Errorf("invalid bps %q: %w", task.Spec.BPS, err)
		}
		if bps > 0 {
			e.SetClassRateLimit(task.ClassID, bps)
		}
	}
	// Task-level BPS ceiling: parent bucket keyed by ParentTaskID.
	// TaskFCValue is already in bps (stored raw in TaskModel.FlowControl), so
	// convert directly -- a formatBPS->ParseBPS string round-trip would lose
	// precision (e.g. 1.5Gbps rounds to "2G").
	if task.TaskFCType == "bps" && task.ParentTaskID != "" {
		bps := int64(task.TaskFCValue)
		if bps > 0 {
			e.SetClassRateLimit(task.ParentTaskID, bps)
		}
	}
	// Task-level flows ceiling: lazily create a shared counter.
	if task.TaskFCType == "flows" && task.ParentTaskID != "" {
		e.getOrCreateFlowCounter(task.ParentTaskID)
	}

	// P2c 层链驱动生成: a task carrying a "layers" config gets a per-task
	// ChainPlanner from the injected factory (wired to layers.BuildLayersPlanner
	// in cmd/server/main.go). The planner is stored under the task ID; the
	// worker looks it up when dispatching. Errors surface at submit time —
	// a layers config that cannot be parsed/validated fails the task
	// submission, never silently generating an empty flow.
	if task.Layers != nil {
		if e.layerPlannerFactory == nil {
			return fmt.Errorf("layers: layer planner factory not wired")
		}
		planner, err := e.layerPlannerFactory(task.Protocol, task.Layers)
		if err != nil {
			return fmt.Errorf("layers: %w", err)
		}
		e.taskMu.Lock()
		e.layerPlanners[task.ID] = planner
		e.taskMu.Unlock()
	}

	// Create per-task context for cancellation. Priority:
	//  1. batch DurationSeconds
	//  2. task-level time ceiling (min with strategy Duration)
	//  3. strategy-level Duration
	//  4. no timeout (WithCancel)
	var taskCtx context.Context
	var cancel context.CancelFunc
	switch {
	case task.Batch != nil && task.Batch.Global.DurationSeconds > 0:
		taskCtx, cancel = context.WithTimeout(e.ctx, time.Duration(task.Batch.Global.DurationSeconds)*time.Second)
	case task.TaskFCType == "time" && task.ParentTaskID != "":
		eff := task.TaskFCValue
		if task.Spec.Duration > 0 && time.Duration(task.Spec.Duration)*time.Second < time.Duration(eff*float64(time.Second)) {
			eff = float64(task.Spec.Duration) // min(strategy, task-level)
		}
		taskCtx, cancel = context.WithTimeout(e.ctx, time.Duration(eff*float64(time.Second)))
	case task.Spec.Duration > 0:
		taskCtx, cancel = context.WithTimeout(e.ctx, time.Duration(task.Spec.Duration)*time.Second)
	default:
		taskCtx, cancel = context.WithCancel(e.ctx)
	}

	// Initialize task status
	status := &TaskStatus{
		TaskID:    task.ID,
		Status:    "created",
		Progress:  0,
		CreatedAt: time.Now(),
	}
	task.Ctx = taskCtx
	status.Status = "running"
	status.StartedAt = time.Now()
	// Lock across the store insert and the channel snapshot so a submit that
	// fails at the channel guard below (engine stopped between the running
	// check and the snapshot) cleans up everything this task registered —
	// including the layerPlanners entry inserted above.
	e.taskMu.Lock()
	e.taskStore[task.ID] = &taskEntry{task: &task, status: status, cancel: cancel}
	e.taskMu.Unlock()

	// Snapshot the channel pair under channelMu so the select below races
	// neither Stop's swap (which would make the taskChan send land on a
	// closed channel) nor Start's rebuild. The stopChan guard fires when the
	// engine stopped between the running check above and this select.
	e.channelMu.Lock()
	taskChan := e.taskChan
	stopChan := e.stopChan
	e.channelMu.Unlock()
	if taskChan == nil || stopChan == nil {
		e.taskMu.Lock()
		delete(e.taskStore, task.ID)
		delete(e.layerPlanners, task.ID)
		e.taskMu.Unlock()
		e.cleanupTaskRateLimiters(task.ID)
		return fmt.Errorf("engine not running")
	}

	// Submit task.
	select {
	case <-stopChan:
		status.Status = "failed"
		status.Error = "engine stopped during submit"
		cancel()
		e.taskMu.Lock()
		delete(e.taskStore, task.ID)
		delete(e.layerPlanners, task.ID)
		e.taskMu.Unlock()
		e.cleanupTaskRateLimiters(task.ID)
		return fmt.Errorf("engine not running")
	case taskChan <- task:
		zap.L().Info("task submitted",
			zap.String("task_id", task.ID),
			zap.String("protocol", task.Protocol),
		)
		return nil
	case <-time.After(5 * time.Second):
		status.Status = "failed"
		status.Error = "task queue full"
		cancel()
		// Clean up this task's rate limiter + taskStore entry so a queue-full
		// failure doesn't leak them (they were created above before queueing).
		e.taskMu.Lock()
		delete(e.taskStore, task.ID)
		delete(e.layerPlanners, task.ID)
		e.taskMu.Unlock()
		e.cleanupTaskRateLimiters(task.ID)
		return fmt.Errorf("task queue full")
	}
}

// StopTask stops a running task.
func (e *Engine) StopTask(taskID string) error {
	e.taskMu.Lock()
	defer e.taskMu.Unlock()

	entry, ok := e.taskStore[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	entry.cancel()
	entry.status.Status = "stopped"
	entry.status.CompletedAt = time.Now()
	delete(e.layerPlanners, taskID)

	zap.L().Info("task stopped", zap.String("task_id", taskID))
	return nil
}

// SetTaskTotalConfigs records the total number of configs for a task.
// Called by ConfigWorker after all configs are forwarded.
// Also checks for completion in case all packets were already written.
func (e *Engine) SetTaskTotalConfigs(taskID string, count int64) {
	e.taskMu.Lock()
	entry, ok := e.taskStore[taskID]
	if !ok {
		e.taskMu.Unlock()
		return
	}
	entry.totalConfigs = count
	// Complete when planning is done (onTaskDone fired) and every planned
	// config is accounted for (written, or failed to build). count == 0 means
	// planning produced no configs (e.g., an empty batch or all flows failed
	// validation); since onTaskDone already fired, no more packets will
	// arrive, so complete now with 0 packets.
	if count == 0 || entry.writtenPackets+entry.errorPackets >= count {
		if entry.errorPackets > 0 {
			e.taskMu.Unlock()
			e.FailTask(taskID, fmt.Sprintf("packet build failed: %s", entry.firstBuildErr))
			return
		}
		entry.status.Status = "completed"
		entry.status.Progress = 100
		entry.status.CompletedAt = time.Now()
		entry.cancel()
		delete(e.taskStore, taskID)
		delete(e.layerPlanners, taskID)
		e.taskMu.Unlock()
		e.cleanupTaskRateLimiters(taskID)
		zap.L().Info("task completed (totalConfigs set after drain)", zap.String("task_id", taskID), zap.Int64("configs", count))
		if e.OnTaskComplete != nil {
			e.OnTaskComplete(taskID)
		}
		return
	}
	e.taskMu.Unlock()
}

// cleanupTaskRateLimiters removes rate limiters owned by a task: the key
// matching taskID exactly (single-protocol tasks) and any "taskID:classID"
// keys (mixed-traffic classes). Called on task completion/failure to prevent
// the rateLimiters map from growing unbounded over a long engine lifetime.
func (e *Engine) cleanupTaskRateLimiters(taskID string) {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	delete(e.rateLimiters, taskID)
	prefix := taskID + ":"
	for k := range e.rateLimiters {
		if strings.HasPrefix(k, prefix) {
			delete(e.rateLimiters, k)
		}
	}
}

// OnPacketWritten is called by OutputWorker after writing a packet.
// When writtenPackets >= totalConfigs, the task is marked as completed.
func (e *Engine) OnPacketWritten(taskID string) {
	e.taskMu.Lock()
	entry, ok := e.taskStore[taskID]
	if !ok {
		e.taskMu.Unlock()
		return
	}
	entry.writtenPackets++
	// Skip further processing for stopped tasks
	if entry.status.Status == "stopped" {
		e.taskMu.Unlock()
		return
	}
	if entry.totalConfigs > 0 && entry.writtenPackets+entry.errorPackets >= entry.totalConfigs {
		// All planned configs accounted for. If any build failed, the task
		// cannot be reported completed: fail it with the first error.
		if entry.errorPackets > 0 {
			e.taskMu.Unlock()
			e.FailTask(taskID, fmt.Sprintf("packet build failed: %s", entry.firstBuildErr))
			return
		}
		entry.status.Status = "completed"
		entry.status.Progress = 100
		entry.status.CompletedAt = time.Now()
		entry.cancel()
		delete(e.taskStore, taskID)
		delete(e.layerPlanners, taskID)
		e.taskMu.Unlock()
		e.cleanupTaskRateLimiters(taskID)
		zap.L().Info("task completed (pipeline drained)", zap.String("task_id", taskID))
		if e.OnTaskComplete != nil {
			e.OnTaskComplete(taskID)
		}
		return
	}
	// Calculate intermediate progress and notify
	if entry.totalConfigs > 0 {
		newProgress := float64(entry.writtenPackets) / float64(entry.totalConfigs) * 100
		oldProgress := entry.status.Progress
		// Only notify when progress changes by at least 1%
		if newProgress-oldProgress >= 1.0 || newProgress == 100 {
			entry.status.Progress = newProgress
			e.taskMu.Unlock()
			if e.OnProgress != nil {
				e.OnProgress(taskID, newProgress, entry.status.Stats)
			}
			return
		}
	}
	e.taskMu.Unlock()
}

// FailTask marks a task as failed.
func (e *Engine) FailTask(taskID string, errMsg string) {
	e.taskMu.Lock()
	entry, ok := e.taskStore[taskID]
	if !ok {
		e.taskMu.Unlock()
		return
	}
	// A stopped task is already terminal: StopTask set the user-visible
	// "stopped" status and CompletedAt. Do NOT overwrite it with "failed"
	// when the draining pipeline reports "task cancelled" after a stop -
	// otherwise every user-initiated stop lands in "failed" state. Mirrors
	// the OnPacketWritten "stopped" guard.
	if entry.status.Status == "stopped" {
		e.taskMu.Unlock()
		return
	}
	entry.status.Status = "failed"
	entry.status.Error = errMsg
	entry.status.CompletedAt = time.Now()
	entry.cancel()
	delete(e.taskStore, taskID)
	delete(e.layerPlanners, taskID)
	e.taskMu.Unlock()
	e.cleanupTaskRateLimiters(taskID)

	zap.L().Info("task failed", zap.String("task_id", taskID), zap.String("error", errMsg))

	if e.OnTaskFailed != nil {
		e.OnTaskFailed(taskID, errMsg)
	}

	if e.OnTaskComplete != nil {
		e.OnTaskComplete(taskID)
	}
}

// OnPacketBuildError records a packet that failed to build for a task. The
// PacketWorker drops failed packets and never calls OnPacketWritten, so a
// build failure must be accounted for separately: once every planned config
// is accounted for (written + failed), the task can no longer progress and
// is failed with the first build error. Without this, a single failed packet
// wedges the task in "running" forever (completion waited only on
// writtenPackets >= totalConfigs).
func (e *Engine) OnPacketBuildError(taskID string, err error) {
	e.taskMu.Lock()
	entry, ok := e.taskStore[taskID]
	if !ok {
		e.taskMu.Unlock()
		return
	}
	// A stopped task is already terminal (StopTask set "stopped"); do not
	// record or fail it. Mirrors the OnPacketWritten/FailTask stopped guard.
	if entry.status.Status == "stopped" {
		e.taskMu.Unlock()
		return
	}
	entry.errorPackets++
	if entry.firstBuildErr == "" {
		entry.firstBuildErr = err.Error()
	}
	if entry.totalConfigs > 0 && entry.writtenPackets+entry.errorPackets >= entry.totalConfigs {
		e.taskMu.Unlock()
		e.FailTask(taskID, fmt.Sprintf("packet build failed: %s", entry.firstBuildErr))
		return
	}
	e.taskMu.Unlock()
}

// GetTaskStatus returns the status of a task.
func (e *Engine) GetTaskStatus(taskID string) (*TaskStatus, error) {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()

	entry, ok := e.taskStore[taskID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return entry.status, nil
}

// RangeTaskStore iterates over all tasks in the store and calls fn for each.
// If fn returns false, iteration stops.
func (e *Engine) RangeTaskStore(fn func(id string, status *TaskStatus) bool) {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()

	for id, entry := range e.taskStore {
		if !fn(id, entry.status) {
			return
		}
	}
}

// ActiveTaskCount returns the number of active tasks.
func (e *Engine) ActiveTaskCount() int {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()
	return len(e.taskStore)
}

// GetPackets retrieves packets from the buffer.
func (e *Engine) GetPackets(count int, mode string) [][]byte {
	if e.buffer == nil {
		return nil
	}
	return e.buffer.Get(count, mode)
}

// GetBufferStatus returns the buffer status.
func (e *Engine) GetBufferStatus() map[string]interface{} {
	if e.buffer == nil {
		return nil
	}
	return e.buffer.Status()
}

// SetClassRateLimit sets the rate limit for a class. bps is in bits/second
// (networking convention: "1M" = 1 Mbps). The token bucket consumes bytes per
// packet, so convert bits/s to bytes/s here. Without this conversion the bucket
// would treat bps as bytes/s and the actual wire rate would be 8x the configured
// value (e.g. "1M" -> 8 Mbps instead of 1 Mbps).
func (e *Engine) SetClassRateLimit(classID string, bps int64) {
	rateBytesPerSec := bps / 8
	if rateBytesPerSec < 1 {
		// Guard against truncation to zero: rate=0 means unlimited in the
		// token bucket, which would silently disable limiting for tiny bps.
		rateBytesPerSec = 1
	}
	limiter := NewTokenBucket(rateBytesPerSec, 65536)
	e.rateMu.Lock()
	e.rateLimiters[classID] = limiter
	e.rateMu.Unlock()
}

// GetRateLimiter returns the rate limiter for a class.
func (e *Engine) GetRateLimiter(classID string) *TokenBucket {
	e.rateMu.RLock()
	defer e.rateMu.RUnlock()
	return e.rateLimiters[classID]
}

// getOrCreateFlowCounter returns the shared flow counter for a parent task,
// creating it on first access. Used by task-level "flows" ceilings: each
// strategy's processTask increments this counter and stops generating flows
// once the task-level total is reached.
func (e *Engine) getOrCreateFlowCounter(parentTaskID string) *int64 {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	if c, ok := e.flowCounters[parentTaskID]; ok {
		return c
	}
	var v int64
	e.flowCounters[parentTaskID] = &v
	return &v
}

// CleanupTaskFlowControl removes the parent rate-limiter bucket and shared
// flow counter for a parent task, plus any leftover child buckets (safety
// net). Called by the task handler once ALL strategies of a parent task have
// finished (completed/failed/stopped), so the rateLimiters/flowCounters maps
// don't grow unbounded over the engine lifetime.
func (e *Engine) CleanupTaskFlowControl(parentTaskID string) {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	delete(e.rateLimiters, parentTaskID)
	delete(e.flowCounters, parentTaskID)
	// Child buckets are keyed "parentTaskID-strategyID"; sweep any leftovers.
	prefix := parentTaskID + "-"
	for k := range e.rateLimiters {
		if strings.HasPrefix(k, prefix) {
			delete(e.rateLimiters, k)
		}
	}
}

// getProcessCPUTime returns user+system CPU time accumulated by this process.
func getProcessCPUTime() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, err
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), nil
}

// GetCPUUsage returns process CPU usage as a percentage of one core since
// engine start (0-100 means one core fully busy; multi-core busy may exceed 100).
func (e *Engine) GetCPUUsage() float64 {
	if e.startWallClock.IsZero() {
		return 0
	}
	cur, err := getProcessCPUTime()
	if err != nil {
		return 0
	}
	elapsed := time.Since(e.startWallClock)
	if elapsed <= 0 {
		return 0
	}
	cpuTime := cur - e.startCPUTime
	return float64(cpuTime) / float64(elapsed) * 100.0
}

// SetMaxTasks sets the cap on concurrently active tasks (0 = unlimited).
func (e *Engine) SetMaxTasks(n int) {
	if n < 0 {
		n = 0
	}
	e.maxTasks.Store(int64(n))
}

// activeTaskCount returns the number of tasks currently in the store.
func (e *Engine) activeTaskCount() int {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()
	return len(e.taskStore)
}

// GetStats returns engine statistics.
func (e *Engine) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"running": e.running.Load(),
	}

	// Config worker stats
	var configPackets, configTasks, configErrors int64
	for _, w := range e.configWorkers {
		s := w.GetStats()
		configPackets += s.PacketsGenerated
		configTasks += s.TasksProcessed
		configErrors += s.Errors
	}
	stats["config_workers"] = map[string]interface{}{
		"packets": configPackets,
		"tasks":   configTasks,
		"errors":  configErrors,
	}

	// Packet worker stats
	var packetPackets, packetErrors int64
	for _, w := range e.packetWorkers {
		s := w.GetStats()
		packetPackets += s.PacketsGenerated
		packetErrors += s.Errors
	}
	stats["packet_workers"] = map[string]interface{}{
		"packets": packetPackets,
		"errors":  packetErrors,
	}

	// Output worker stats
	var outputPackets, outputErrors int64
	for _, w := range e.outputWorkers {
		s := w.GetStats()
		outputPackets += s.PacketsGenerated
		outputErrors += s.Errors
	}
	stats["output_workers"] = map[string]interface{}{
		"packets": outputPackets,
		"errors":  outputErrors,
	}

	// Buffer status
	stats["buffer"] = e.GetBufferStatus()

	return stats
}

// IsRunning returns true if the engine is running.
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}

// SetFatalError sets a fatal error.
func (e *Engine) SetFatalError(err error) {
	e.fatalError.Store(err)
}

// GetFatalError returns the fatal error if any.
func (e *Engine) GetFatalError() error {
	if v := e.fatalError.Load(); v != nil {
		return v.(error)
	}
	return nil
}
