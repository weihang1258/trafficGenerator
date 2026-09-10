package core

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// Helper function to get planner keys for logging
func getPlannerKeys(m map[string]ProtocolPlanner) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ProtocolPlanner defines the interface for protocol-specific planning.
type ProtocolPlanner interface {
	// Name returns the protocol name.
	Name() string

	// Plan generates packet configs from a flow spec.
	Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error)

	// Validate validates a flow spec.
	Validate(spec FlowSpec) error
}

// ReplayFC carries task-level flow-control state that the replay planner
// consults during plan execution. A nil FlowCounter means "no flows ceiling" --
// the planner counts but never caps. Ceiling is the max unique flows before
// new flows are skipped. SkippedAll is set by the planner when the ceiling
// skipped at least one flow; because the planner sets it before closing the
// output channel, the consumer's read after the channel closes is
// happens-after the write (channel-close memory ordering) — no atomic needed.
type ReplayFC struct {
	FlowCounter *int64 // nil = no flows ceiling
	Ceiling     int64
	SkippedAll  bool // set by planner: ceiling skipped >= 1 flow
}

// ReplayPlanner generates packet configs for a replay TrafficClass (§16.12).
// Defined in core (taking raw JSON) so core can dispatch to it without importing
// the replay package; the concrete replay.ReplayPlanner implements this.
type ReplayPlanner interface {
	PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string, fc *ReplayFC) (<-chan PacketConfig, error)
}

// ConfigWorker generates packet configurations.
type ConfigWorker struct {
	id            int
	planners      map[string]ProtocolPlanner
	replayPlanner ReplayPlanner
	taskChan      <-chan Task
	wg            *sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	stats         WorkerStats
	onTaskDone    func(taskID string, err error, count int64)
	sem           chan struct{} // limits concurrent task processing per worker
	engine        *Engine       // for sharded channels, shardSeed, rate limiters, task-level flow counter
}

// WorkerStats holds worker statistics.
type WorkerStats struct {
	PacketsGenerated int64
	TasksProcessed   int64
	Errors           int64
}

// NewConfigWorker creates a new config worker.
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
		sem:           make(chan struct{}, 4), // process up to 4 tasks concurrently per worker
		engine:        engine,
	}
}

// SetOnTaskDone sets the callback for task completion/failure.
func (w *ConfigWorker) SetOnTaskDone(fn func(taskID string, err error, count int64)) {
	w.onTaskDone = fn
}

// Start starts the config worker.
func (w *ConfigWorker) Start() {
	go w.run()
}

// Stop stops the config worker.
func (w *ConfigWorker) Stop() {
	w.cancel()
}

// run is the main worker loop.
func (w *ConfigWorker) run() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case task, ok := <-w.taskChan:
			if !ok {
				return
			}
			// Acquire semaphore slot (blocks if at capacity)
			w.sem <- struct{}{}
			// Track spawned goroutine in WaitGroup for proper shutdown
			w.wg.Add(1)
			go func(t Task) {
				defer func() {
					<-w.sem
					w.wg.Done()
				}()
				w.processTask(t)
			}(task)
		}
	}
}

// processTask processes a single task.
func (w *ConfigWorker) processTask(task Task) {
	// Mixed-traffic (batch) tasks fan out to per-class goroutines.
	if task.Batch != nil {
		w.processBatchTask(task)
		return
	}

	// Replay tasks (mode=replay) dispatch to the replay planner once -- no
	// per-flow loop, no protocol planner. The planner emits all of the asset's
	// packets in one channel, optionally paced by timestamps and capped by the
	// task-level flows ceiling.
	if task.Mode == "replay" || len(task.Replay) > 0 {
		w.processReplayTask(task)
		return
	}

	zap.L().Info("processing task",
		zap.String("task_id", task.ID),
		zap.String("protocol", task.Protocol),
		zap.Int("planners_count", len(w.planners)),
	)

	// P2c 层链驱动生成: a task carrying a "layers" config dispatches to its
	// per-task ChainPlanner (built by the engine's injected layer-planner
	// factory at SubmitTask) instead of the protocol-name planner. The
	// per-task planner is authoritative when present — for tunnel chains the
	// protocol name (e.g. "gre") may not even be a registered protocol
	// planner, so the per-task lookup runs before the protocol-name one and
	// cannot be gated on it.
	var planner ProtocolPlanner
	ok := false
	if lp := w.engine.layerPlannerFor(task.ID); lp != nil {
		planner = lp
		ok = true
	} else {
		planner, ok = w.planners[task.Protocol]
	}
	if !ok {
		zap.L().Error("unknown protocol",
			zap.String("task_id", task.ID),
			zap.String("protocol", task.Protocol),
			zap.Any("available_protocols", getPlannerKeys(w.planners)),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("unknown protocol: %s", task.Protocol), 0)
		}
		return
	}

	// Validate task. Two distinct sources of validation errors must BOTH
	// surface here, otherwise invalid input silently reaches Plan() and either
	// panics (make([]byte, -n)) or produces zero-byte packets that the
	// caller cannot distinguish from a real run:
	//
	//  1. spec.ValidationErrors — populated by strategy_convert.go lines
	//     478-512 from FileSource.Validate() (e.g. fill.bytes=-1, MinBytes>MaxBytes,
	//     negative MinBytes). These are user-facing input errors that bypass
	//     the protocol planner's Validate() method, which only inspects
	//     protocol-specific structure (ports, flags, etc.) — not FileSource
	//     fields. Without this check, B5.1-B5.10 (file_source.fill.bytes=-1
	//     and friends) silently report status=completed with error_message=null.
	//
	//  2. planner.Validate(spec) — protocol-specific structural checks
	//     (already wired here). Kept as a separate branch so each error
	//     source produces its own context in the failure log/metrics.
	if len(task.Spec.ValidationErrors) > 0 {
		joined := strings.Join(task.Spec.ValidationErrors, "; ")
		zap.L().Error("task spec validation failed (file_source/etc)",
			zap.String("task_id", task.ID),
			zap.Strings("validation_errors", task.Spec.ValidationErrors),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("validation failed: %s", joined), 0)
		}
		return
	}
	if err := planner.Validate(task.Spec); err != nil {
		zap.L().Error("task validation failed",
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("validation failed: %w", err), 0)
		}
		return
	}

	// Use per-task context if available, otherwise fall back to worker context
	taskCtx := task.Ctx
	if taskCtx == nil {
		taskCtx = w.ctx
	}
	// Inject the engine-wide cache when available. When w.engine is nil
	// (test-only ConfigWorker) or pc is nil (engine without a filesystem),
	// we skip injection — planners call PayloadCacheFrom(ctx), get nil, and
	// skip FileSource resolution. This is the intended degradation
	// (silently producing non-FileSource packets) rather than panicking on
	// a nil deref.
	if w.engine != nil {
		if pc := w.engine.PayloadCache(); pc != nil {
			taskCtx = WithPayloadCache(taskCtx, pc)
		}
	}

	// Number of flows to generate. spec.Count (from strategy flow_control
	// type="flows") controls flow count; <=0 defaults to 1 (e.g. bps-only or
	// time-only strategies that still produce at least one flow).
	flowCount := task.Spec.Count
	if flowCount <= 0 {
		flowCount = 1
	}

	// Task-level flows ceiling (shared counter across all strategies of the
	// parent task). Each flow increments the counter; once the ceiling is
	// exceeded, no more flows are generated.
	hasFlowCeiling := task.TaskFCType == "flows" && task.ParentTaskID != ""
	var flowCounter *int64
	// ceilingHit records whether THIS task's loop exited at the ceiling;
	// ranFlow records whether THIS task ever scheduled a flow (passed the
	// ceiling check and called the planner). The 0-config guard exempts the
	// case where both hold — the ceiling skipped the task before any flow
	// ran, so 0 configs is the ceiling doing its job, not a broken planner.
	// These are local facts, never inferred from the shared counter: another
	// strategy's later consumption could exhaust the counter and retroactively
	// mask a broken planner's 0 configs (adversarial review finding #1).
	var ceilingHit, ranFlow bool
	if hasFlowCeiling {
		flowCounter = w.engine.getOrCreateFlowCounter(task.ParentTaskID)
	}

	// Forward configs to packet workers
	var configCount int64
	for i := 0; i < flowCount; i++ {
		// Honour context cancellation between flows (time deadline / stop).
		select {
		case <-taskCtx.Done():
			if w.onTaskDone != nil {
				if taskCtx.Err() == context.DeadlineExceeded {
					w.onTaskDone(task.ID, nil, configCount) // time deadline = normal completion
				} else {
					w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
				}
			}
			return
		default:
		}
		// Task-level flows ceiling check.
		if hasFlowCeiling && atomic.AddInt64(flowCounter, 1) > int64(task.TaskFCValue) {
			ceilingHit = true
			break
		}
		ranFlow = true

		// Multi-flow src_port auto-increment: when flowCount > 1 and user didn't
		// explicitly provide src_port, increment src_port per flow to simulate
		// ephemeral ports. This prevents 4-tuple collisions that confuse Wireshark
		// (e.g. "TCP Port numbers reused", "Out-Of-Order"). Each flow gets a unique
		// 4-tuple, matching real TCP client behavior. User-provided src_port is
		// always honored (user > default rule).
		spec := task.Spec
		if flowCount > 1 && !spec.HasExplicitSrcPort {
			spec.SrcPort = DefaultSrcPort + uint16(i)
		}

		// Per-flow layer dynamics (D-FTP-3): resolve parsed layer-field
		// strategies at flow index i; non-zero resolutions override (same
		// "non-zero wins" order as the batch tuples loop). Placed after
		// auto-increment so layer dynamics override it; auto-increment
		// first is harmless when overridden (batch-parity order).
		resolveLayerTuple(&spec, i)

		// FlowIndex: zero-based flow sequence for per-flow dynamic fields in
		// planners that support them (FTP sessions/transactions, D-FTP-2).
		// Read-only for planners; 0 for direct callers.
		spec.FlowIndex = i

		// Per-flow shard routing: compute hashKey + gID once for this flow,
		// then write (shard_idx, group_id) to every packet's Metadata and push
		// to the matching shard. Same flow -> same shard -> single-goroutine
		// PacketWorker -> strict FIFO (spec §3.1, §5.4).
		hashKey, gID := computeHashKey(spec, task, i)
		shardIdx := 0
		if n := len(w.engine.shardedConfigChan); n > 0 {
			h := maphash.String(w.engine.shardSeed, hashKey)
			shardIdx = int(h % uint64(n))
		}

		// Plan packet configs for this flow. Use spec (the potentially modified
		// copy with auto-incremented src_port) instead of task.Spec.
		configChan, err := planner.Plan(taskCtx, spec)
		if err != nil {
			// Release the flows-ceiling slot this iteration reserved: a failed
			// flow produces no traffic, so it must not permanently consume a
			// slot that sibling strategies could use. (AddInt64 is atomic, so
			// this is safe under concurrent strategies; the brief over-count
			// window between reserve and release is bounded and rare.)
			if hasFlowCeiling {
				atomic.AddInt64(flowCounter, -1)
			}
			zap.L().Error("task planning failed",
				zap.String("task_id", task.ID),
				zap.Error(err),
			)
			atomic.AddInt64(&w.stats.Errors, 1)
			if w.onTaskDone != nil {
				w.onTaskDone(task.ID, fmt.Errorf("planning failed: %w", err), configCount)
			}
			return
		}

		for config := range configChan {
			config.ClassID = task.ClassID
			// Propagate flow-level VLAN to the packet's L2 config. Planners do not
			// copy spec.VLAN into L2Config, so without this the builder never sees
			// the VLAN and 802.1Q tags are never emitted.
			if config.L2.VLAN == nil && task.Spec.VLAN != nil {
				config.L2.VLAN = task.Spec.VLAN
			}
			// Propagate flow-level PadMinFrame to the packet's L2 config.
			// Planners leave L2.Pad nil; without this, the builder applies
			// its default (pad ON) and user false (don't pad) is lost.
			if config.L2.Pad == nil && task.Spec.PadMinFrame != nil {
				config.L2.Pad = task.Spec.PadMinFrame
			}
			if config.Metadata == nil {
				config.Metadata = make(map[string]interface{})
			}
			config.Metadata["task_id"] = task.ID
			config.Metadata["parent_task_id"] = task.ParentTaskID
			config.Metadata["interface"] = task.Interface
			config.Metadata["shard_idx"] = shardIdx
			config.Metadata["group_id"] = gID

			select {
			case <-taskCtx.Done():
				// Drain remaining configs so the planner goroutine is not blocked
				// on configChan <- (which would leak it permanently). Planners
				// generate a finite number of packets, so this drain is bounded.
				for range configChan {
				}
				if w.onTaskDone != nil {
					if taskCtx.Err() == context.DeadlineExceeded {
						w.onTaskDone(task.ID, nil, configCount) // time deadline = normal completion
					} else {
						w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
					}
				}
				return
			case w.engine.shardedConfigChan[shardIdx] <- config:
				w.engine.shardCounts[shardIdx].Add(1)
				configCount++
			}
		}
	}

	atomic.AddInt64(&w.stats.TasksProcessed, 1)
	atomic.AddInt64(&w.stats.PacketsGenerated, configCount)
	if w.onTaskDone != nil {
		// Zero configs means the planner produced no packets despite a
		// positive flow count — a broken or empty planner (the
		// jt808/jt809/jtt905 Plan() now fail explicitly). Reporting success
		// would mask the failure as "completed with 0 packets". Match the
		// batch path's all-flows-failed semantics: fail the task loudly.
		// A time-limited task whose deadline expired mid-planning is the
		// legitimate zero-config case — that path already reported its own
		// terminal state and returned (line ~272).
		// A task-level flows ceiling can legitimately skip a strategy task
		// BEFORE it runs any flow (shared parent counter exhausted by a
		// sibling — line ~290 breaks with a live context). That is the
		// ceiling doing its job, not a broken planner, so the 0-config
		// guard exempts the ceilingHit && !ranFlow case only. If the task
		// ran a flow (ranFlow) or never hit the ceiling, 0 configs still
		// mean a broken planner and must fail.
		if configCount == 0 && taskCtx.Err() == nil && !(ceilingHit && !ranFlow) {
			w.onTaskDone(task.ID, fmt.Errorf("planner produced 0 packet configs"), 0)
			return
		}
		w.onTaskDone(task.ID, nil, configCount)
	}
}

// processReplayTask runs a single-protocol replay task. Unlike synth tasks,
// there is no per-flow loop: the replay planner emits all of the asset's
// packets in one channel (handshake/data/termination come from the pcap). The
// task-level flows ceiling (if any) is enforced inside the planner via fc --
// each unique flow ID increments a shared counter, and flows beyond the
// ceiling are skipped at emit time.
//
// fc is always non-nil here so the planner takes the single-protocol path
// (bps/empty mode drops the in-packet pacer and routes through the engine's
// child rate-limiter bucket, mirroring synth). Only when FlowCounter != nil
// does the planner enforce a flows ceiling.
func (w *ConfigWorker) processReplayTask(task Task) {
	if w.replayPlanner == nil {
		zap.L().Error("replay task but no replay planner registered",
			zap.String("task_id", task.ID))
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("replay planner not registered"), 0)
		}
		return
	}

	zap.L().Info("processing replay task",
		zap.String("task_id", task.ID),
		zap.String("class_id", task.ClassID),
	)

	taskCtx := task.Ctx
	if taskCtx == nil {
		taskCtx = w.ctx
	}
	// Inject the engine-wide cache when available. When w.engine is nil
	// (test-only ConfigWorker) or pc is nil (engine without a filesystem),
	// we skip injection — planners call PayloadCacheFrom(ctx), get nil, and
	// skip FileSource resolution. This is the intended degradation
	// (silently producing non-FileSource packets) rather than panicking on
	// a nil deref.
	if w.engine != nil {
		if pc := w.engine.PayloadCache(); pc != nil {
			taskCtx = WithPayloadCache(taskCtx, pc)
		}
	}

	// Build fc. Always non-nil: signals single-protocol path to the planner
	// (drop pacer for bps/empty, route through engine child bucket). FlowCounter
	// is set only when the task-level ceiling is "flows" and a parent task
	// owns the shared counter.
	fc := &ReplayFC{}
	if task.TaskFCType == "flows" && task.ParentTaskID != "" {
		fc.FlowCounter = w.engine.getOrCreateFlowCounter(task.ParentTaskID)
		fc.Ceiling = int64(task.TaskFCValue)
	}

	configChan, err := w.replayPlanner.PlanReplay(taskCtx, task.Replay, task.ID, task.ClassID, task.UserID, fc)
	if err != nil {
		zap.L().Error("replay plan failed",
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("replay plan failed: %w", err), 0)
		}
		return
	}

	var configCount int64
	for config := range configChan {
		config.ClassID = task.ClassID
		if config.Metadata == nil {
			config.Metadata = make(map[string]interface{})
		}
		// gID already set by PlanReplay; compute shardIdx from it. If gID
		// empty (shouldn't happen — PlanReplay always sets it), fall back to
		// shard 0.
		gID, _ := config.Metadata["group_id"].(string)
		shardIdx := 0
		if gID != "" {
			n := len(w.engine.shardedConfigChan)
			if n > 0 {
				h := maphash.String(w.engine.shardSeed, gID)
				shardIdx = int(h % uint64(n))
			}
		}
		config.Metadata["task_id"] = task.ID
		config.Metadata["parent_task_id"] = task.ParentTaskID
		config.Metadata["interface"] = task.Interface
		config.Metadata["shard_idx"] = shardIdx

		select {
		case <-taskCtx.Done():
			// Drain remaining configs so the planner goroutine is not blocked
			// on configChan <- (leak). Bounded: planner emits a finite count.
			for range configChan {
			}
			if w.onTaskDone != nil {
				if taskCtx.Err() == context.DeadlineExceeded {
					w.onTaskDone(task.ID, nil, configCount) // time deadline = normal completion
				} else {
					w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
				}
			}
			return
		case w.engine.shardedConfigChan[shardIdx] <- config:
			w.engine.shardCounts[shardIdx].Add(1)
			configCount++
		}
	}

	atomic.AddInt64(&w.stats.TasksProcessed, 1)
	atomic.AddInt64(&w.stats.PacketsGenerated, configCount)
	if w.onTaskDone != nil {
		// A replay that emitted zero configs is a broken replay (e.g. an
		// asset that failed to load). Report it as a failure instead of
		// silent completion with 0 packets. The only benign zero-config
		// replay is a time-capped one whose context expired before any
		// packet was emitted; treat that as normal completion.
		// A task-level flows ceiling exhausted by a sibling strategy is
		// equally benign: the replay planner's countFlow skips flows past
		// the ceiling with a live context — the ceiling did its job, so do
		// not report a broken replay. fc.SkippedAll is the planner's exact
		// signal (set when countFlow actually returned false for some
		// flow); the counter alone would retroactively mask a genuinely
		// broken replay that happened to run after the ceiling was hit.
		if configCount == 0 && taskCtx.Err() == nil && !fc.SkippedAll {
			w.onTaskDone(task.ID, fmt.Errorf("replay planner produced 0 packet configs"), 0)
			return
		}
		// A time deadline during normal drain is normal completion; an
		// explicit cancel is an error. If ctx is still alive, the planner
		// simply exhausted its pcap -- also normal completion.
		if taskCtx.Err() == context.Canceled {
			w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
		} else {
			w.onTaskDone(task.ID, nil, configCount)
		}
	}
}

// processBatchTask runs a mixed-traffic task: each TrafficClass runs in its
// own goroutine, generating FlowCount flows through its protocol planner. All
// classes feed the shared configChan; each config is tagged with
// "taskID:classID" so PacketWorker can apply per-class rate limiting. Classes
// run concurrently so their packets interleave naturally in the output.
func (w *ConfigWorker) processBatchTask(task Task) {
	zap.L().Info("processing batch task",
		zap.String("task_id", task.ID),
		zap.Int("classes", len(task.Batch.Classes)),
	)

	taskCtx := task.Ctx
	if taskCtx == nil {
		taskCtx = w.ctx
	}
	// Inject the engine-wide cache when available. When w.engine is nil
	// (test-only ConfigWorker) or pc is nil (engine without a filesystem),
	// we skip injection — planners call PayloadCacheFrom(ctx), get nil, and
	// skip FileSource resolution. This is the intended degradation
	// (silently producing non-FileSource packets) rather than panicking on
	// a nil deref.
	if w.engine != nil {
		if pc := w.engine.PayloadCache(); pc != nil {
			taskCtx = WithPayloadCache(taskCtx, pc)
		}
	}

	var classWg sync.WaitGroup
	var configCount int64
	var flowFailures int64
	// validationErrs accumulates per-class ValidationErrors so the final task
	// status can surface them in the onTaskDone error message. Without this
	// the "all flows failed" branch below would report the generic
	// "all N flows failed validation/planning" and lose the actual input
	// error string the caller needs to distinguish user mistakes.
	var validationErrMu sync.Mutex
	var validationErrs []string
	totalFlows := 0
	for _, class := range task.Batch.Classes {
		// Replay classes contribute 1 "flow unit" to totalFlows; synth classes
		// contribute their FlowCount. Without this, a failed replay class would
		// not trigger the "all flows failed" guard (totalFlows would stay 0) and
		// the task would silently report "completed" with 0 packets.
		if class.Type == "replay" {
			totalFlows += 1
		} else {
			totalFlows += class.FlowCount
		}
	}

	for _, class := range task.Batch.Classes {
		// Replay class: dispatch to the replay planner (no protocol planner /
		// flow loop -- the planner emits all the asset's packets in one channel).
		if class.Type == "replay" {
			if w.replayPlanner == nil {
				zap.L().Error("batch replay class but no replay planner registered, skipping",
					zap.String("task_id", task.ID), zap.String("class_id", class.ID))
				atomic.AddInt64(&flowFailures, int64(1))
				continue
			}
			classWg.Add(1)
			go func(c TrafficClass) {
				defer classWg.Done()
				classKey := task.ID + ":" + c.ID
				// Per-class config tally (mirrors the synth-class guard below):
				// a replay class whose planner emitted zero configs counts as
				// failed, or an all-zero batch would silently complete.
				var classConfigs int64
				configChan, err := w.replayPlanner.PlanReplay(taskCtx, c.Replay, task.ID, classKey, task.UserID, nil)
				if err != nil {
					zap.L().Error("replay plan failed", zap.String("task_id", task.ID), zap.String("class_id", c.ID), zap.Error(err))
					atomic.AddInt64(&flowFailures, 1)
					return
				}
				for config := range configChan {
					config.ClassID = classKey
					if config.Metadata == nil {
						config.Metadata = make(map[string]interface{})
					}
					// gID already set by PlanReplay; compute shardIdx from it
					gID, _ := config.Metadata["group_id"].(string)
					shardIdx := 0
					if gID != "" {
						n := len(w.engine.shardedConfigChan)
						if n > 0 {
							h := maphash.String(w.engine.shardSeed, gID)
							shardIdx = int(h % uint64(n))
						}
					}
					config.Metadata["task_id"] = task.ID
					config.Metadata["interface"] = task.Interface
					config.Metadata["shard_idx"] = shardIdx
					select {
					case <-taskCtx.Done():
						for range configChan {
						}
						return
					case w.engine.shardedConfigChan[shardIdx] <- config:
						w.engine.shardCounts[shardIdx].Add(1)
						atomic.AddInt64(&configCount, 1)
						atomic.AddInt64(&classConfigs, 1)
					}
				}
				// Zero-emission replay class: count as failed unless the
				// context expired (time-capped batch = legitimate 0-packets).
				if atomic.LoadInt64(&classConfigs) == 0 && taskCtx.Err() == nil {
					zap.L().Error("batch replay class produced 0 packet configs, counting as failed",
						zap.String("task_id", task.ID),
						zap.String("class_id", c.ID),
					)
					atomic.AddInt64(&flowFailures, 1)
				}
			}(class)
			continue
		}
		planner, ok := w.planners[class.Type]
		if !ok {
			zap.L().Error("batch class unknown protocol, skipping",
				zap.String("task_id", task.ID),
				zap.String("class_id", class.ID),
				zap.String("type", class.Type),
			)
			atomic.AddInt64(&flowFailures, int64(class.FlowCount))
			continue
		}

		classWg.Add(1)
		go func(c TrafficClass, p ProtocolPlanner) {
			defer classWg.Done()
			// Per-class config tally. A class whose flows all produced zero
			// configs (the jt808/jt809/jtt905 Plan() now fail explicitly)
			// must count as failed, or an all-zero batch would silently
			// report "completed with 0 packets" — the engine's
			// all-flows-failed guard never fires because nothing increments
			// flowFailures.
			var classConfigs int64
			// classFailures counts THIS class's per-flow Validate/Plan failures
			// (mirror of flowFailures, scoped to the class). The zero-emission
			// guard below must not top up flowFailures with the full FlowCount
			// (double-counting already-counted failures) nor use the shared
			// flowFailures value as its baseline — a concurrent sibling class
			// could increment it between the Load and the Store, and its value
			// includes failures that belong to other classes (guard review
			// finding: a mixed batch that actually produced packets was pushed
			// past the all-flows-failed threshold).
			var classFailures int64

			spec := mapToFlowSpec(c.Config, c.Type)
			if c.BPS != "" {
				spec.BPS = c.BPS
			}
			// Class-level GroupID (TrafficClass.GroupID field) takes
			// precedence over config-map group_id: explicit struct field is
			// the canonical source. mapToFlowSpec may have set spec.GroupID
			// from c.Config["group_id"]; overwrite if c.GroupID is non-nil.
			if c.GroupID != nil {
				spec.GroupID = c.GroupID
			}
			// Reject the entire class BEFORE the per-flow loop if the spec
			// has user-facing input errors (e.g. file_source.fill.bytes=-1).
			// mapToFlowSpec populates these from strategy_convert.go lines
			// 478-512 for all 5 protocol-specific locations
			// (FTP.DataChannel, SIP.Media, HTTP, ICMP, SCTP.Chunks) plus
			// the bare FlowSpec.FileSource. Without this guard, B5.1-B5.10
			// silently flow through mapToFlowSpec into Plan(), where they
			// either panic on make([]byte, -n) or produce zero-byte
			// packets that callers cannot distinguish from real output.
			// Same per-flow-failure accounting as the planner.Validate()
			// branch below; "all N flows failed" at the bottom then fails
			// the task.
			if len(spec.ValidationErrors) > 0 {
				zap.L().Error("batch class spec validation failed (file_source/etc)",
					zap.String("task_id", task.ID),
					zap.String("class_id", c.ID),
					zap.Strings("validation_errors", spec.ValidationErrors),
				)
				validationErrMu.Lock()
				validationErrs = append(validationErrs, spec.ValidationErrors...)
				validationErrMu.Unlock()
				atomic.AddInt64(&flowFailures, int64(c.FlowCount))
				return
			}
			tupleGen := NewTupleGenerator(c.Tuples)
			classKey := task.ID + ":" + c.ID

			for flowIdx := 0; flowIdx < c.FlowCount; flowIdx++ {
				// tupleGen.Next returns ("", "", 0, 0) when the corresponding
				// TupleConfig strategy is empty. We must NOT clobber the
				// defaults that mapToFlowSpec just filled in (DefaultSrcIP,
				// DefaultDstIP, etc.) with those zero values -- only override
				// when the tuple generator actually produced a value.
				srcIP, dstIP, srcPort, dstPort := tupleGen.Next(flowIdx)
				if srcIP != "" {
					spec.SrcIP = srcIP
				}
				if dstIP != "" {
					spec.DstIP = dstIP
				}
				if srcPort != 0 {
					spec.SrcPort = srcPort
				}
				if dstPort != 0 {
					spec.DstPort = dstPort
				}

				// Layer dynamics (D-FTP-3): after the legacy tuples pool —
				// the layer declaration wins on conflict (layers are truth).
				resolveLayerTuple(&spec, flowIdx)

				// FlowIndex: per-flow dynamic field index for planners
				// (D-FTP-2) — same domain as the strategy loop.
				spec.FlowIndex = flowIdx

				// Per-flow shard routing for batch class. GroupID on the class
				// is propagated to spec via mapToFlowSpec; computeHashKey uses
				// it if set, else falls back to unordered 4-tuple.
				hashKey, gID := computeHashKey(spec, task, flowIdx)
				shardIdx := 0
				if n := len(w.engine.shardedConfigChan); n > 0 {
					h := maphash.String(w.engine.shardSeed, hashKey)
					shardIdx = int(h % uint64(n))
				}

				if err := p.Validate(spec); err != nil {
					zap.L().Warn("batch flow validation failed, skipping flow",
						zap.String("task_id", task.ID),
						zap.String("class_id", c.ID),
						zap.Error(err),
					)
					atomic.AddInt64(&flowFailures, 1)
					atomic.AddInt64(&classFailures, 1)
					continue
				}

				configChan, err := p.Plan(taskCtx, spec)
				if err != nil {
					// A single flow's planning error must not abort the entire
					// class: skip this flow and continue with the rest.
					zap.L().Error("batch flow planning failed, skipping flow",
						zap.String("task_id", task.ID),
						zap.String("class_id", c.ID),
						zap.Error(err),
					)
					atomic.AddInt64(&flowFailures, 1)
					atomic.AddInt64(&classFailures, 1)
					continue
				}
				for config := range configChan {
					config.ClassID = classKey
					// Propagate flow-level VLAN to the packet's L2 config.
					// Planners do not copy spec.VLAN into L2Config, so without
					// this the builder never sees the VLAN and 802.1Q tags are
					// never emitted.
					if config.L2.VLAN == nil && spec.VLAN != nil {
						config.L2.VLAN = spec.VLAN
					}
					// Propagate flow-level PadMinFrame to the packet's L2
					// config (same pattern as VLAN).
					if config.L2.Pad == nil && spec.PadMinFrame != nil {
						config.L2.Pad = spec.PadMinFrame
					}
					if config.Metadata == nil {
						config.Metadata = make(map[string]interface{})
					}
					config.Metadata["task_id"] = task.ID
					config.Metadata["interface"] = task.Interface
					config.Metadata["shard_idx"] = shardIdx
					config.Metadata["group_id"] = gID
					select {
					case <-taskCtx.Done():
						// Drain remaining configs so this class's planner goroutine
						// is not blocked on configChan <- (leak). Bounded: planners
						// generate a finite packet count per flow.
						for range configChan {
						}
						return
					case w.engine.shardedConfigChan[shardIdx] <- config:
						w.engine.shardCounts[shardIdx].Add(1)
						atomic.AddInt64(&configCount, 1)
						atomic.AddInt64(&classConfigs, 1)
					}
				}
			}
			// All flows ran without emitting a single config — a broken
			// planner (empty channel) or an unsatisfiable spec. Count the
			// class as fully failed so the task-level all-flows-failed guard
			// can report it; a mixed batch keeps the healthy classes' output.
			// Per-flow failures (Validate/Plan errors) already incremented
			// flowFailures once per flow, so only top up the difference using
			// THIS class's own failure count — the shared flowFailures value
			// includes other classes' failures and races with their
			// concurrent increments, so it is not a valid baseline (guard
			// review finding: a mixed batch that actually produced packets
			// was pushed past the all-failed threshold).
			if atomic.LoadInt64(&classConfigs) == 0 && taskCtx.Err() == nil {
				zap.L().Error("batch class produced 0 packet configs, counting as failed",
					zap.String("task_id", task.ID),
					zap.String("class_id", c.ID),
				)
				atomic.AddInt64(&flowFailures, int64(c.FlowCount)-atomic.LoadInt64(&classFailures))
			}
		}(class, planner)
	}

	classWg.Wait()

	atomic.AddInt64(&w.stats.TasksProcessed, 1)
	atomic.AddInt64(&w.stats.PacketsGenerated, configCount)
	// Report the appropriate terminal state. If every flow failed, report an
	// error. A duration deadline (context.DeadlineExceeded) is normal
	// completion - the task ran its configured lifetime - so report nil and
	// let SetTaskTotalConfigs complete it once in-flight packets drain. An
	// explicit cancel (context.Canceled: StopTask or engine shutdown) reports
	// "task cancelled"; FailTask respects the "stopped" status StopTask set.
	if w.onTaskDone != nil {
		switch {
		case totalFlows > 0 && atomic.LoadInt64(&flowFailures) >= int64(totalFlows):
			// User-input validation errors take priority over the generic
			// "all flows failed" message so the caller can see what was
			// wrong with the spec.
			validationErrMu.Lock()
			ve := validationErrs
			validationErrMu.Unlock()
			if len(ve) > 0 {
				w.onTaskDone(task.ID, fmt.Errorf("validation failed: %s", strings.Join(ve, "; ")), configCount)
			} else {
				w.onTaskDone(task.ID, fmt.Errorf("all %d flows failed validation/planning", totalFlows), configCount)
			}
		case taskCtx.Err() == context.DeadlineExceeded:
			w.onTaskDone(task.ID, nil, configCount)
		case taskCtx.Err() != nil:
			w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
		default:
			w.onTaskDone(task.ID, nil, configCount)
		}
	}
}

// GetStats returns worker statistics.
func (w *ConfigWorker) GetStats() WorkerStats {
	return WorkerStats{
		PacketsGenerated: atomic.LoadInt64(&w.stats.PacketsGenerated),
		TasksProcessed:   atomic.LoadInt64(&w.stats.TasksProcessed),
		Errors:           atomic.LoadInt64(&w.stats.Errors),
	}
}

// PacketWorker builds packets from configurations.
type PacketWorker struct {
	id        int
	shardChan <-chan PacketConfig // own shard of shardedConfigChan
	buildFunc func(PacketConfig) ([]byte, error)
	wg        *sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	stats     WorkerStats
	engine    *Engine // for per-class rate limiter lookup + shardedPacketChan
}

// NewPacketWorker creates a new packet worker. shardChan is this worker's
// own config shard; packet output goes to w.engine.shardedPacketChan[w.id].
func NewPacketWorker(
	id int,
	shardChan <-chan PacketConfig,
	buildFunc func(PacketConfig) ([]byte, error),
	wg *sync.WaitGroup,
	engine *Engine,
) *PacketWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketWorker{
		id:        id,
		shardChan: shardChan,
		buildFunc: buildFunc,
		wg:        wg,
		ctx:       ctx,
		cancel:    cancel,
		engine:    engine,
	}
}

// Start starts the packet worker.
func (w *PacketWorker) Start() {
	go w.run()
}

// Stop stops the packet worker.
func (w *PacketWorker) Stop() {
	w.cancel()
}

// run is the main worker loop.
func (w *PacketWorker) run() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case config, ok := <-w.shardChan:
			if !ok {
				return
			}
			w.processConfig(config)
		}
	}
}

// processConfig processes a single packet configuration.
func (w *PacketWorker) processConfig(config PacketConfig) {
	if w.buildFunc == nil {
		return
	}

	packet, err := w.buildFunc(config)
	if err != nil {
		zap.L().Error("packet build failed",
			zap.String("flow_id", config.FlowID),
			zap.Uint64("packet_index", config.PacketIndex),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		// Surface the failure to the engine so the task cannot wedge in
		// "running" waiting for a packet that will never be written.
		if w.engine != nil {
			if taskID, ok := config.Metadata["task_id"].(string); ok && taskID != "" {
				w.engine.OnPacketBuildError(taskID, err)
			}
		}
		return
	}

	// Rate limit AFTER build using the real packet size. Three layers, applied
	// top-down: (1) a per-packet Pacer in Metadata (replay timestamp/rate
	// pacing per §16.9) takes precedence; (2) the per-class child bucket
	// (strategy-level rate limit); (3) the task-level parent bucket (aggregate
	// ceiling). The parent bucket is ALWAYS applied when present -- even when a
	// pacer ran -- so the task-level bps ceiling cannot be bypassed by a
	// pacer-driven replay strategy. Pacer/child Wait errors (context cancel)
	// return immediately; the parent bucket then runs only if we did not return.
	if pacer, ok := config.Metadata["_pacer"]; ok {
		if rp, ok := pacer.(interface {
			Wait(context.Context, PacketConfig, int) error
		}); ok {
			if err := rp.Wait(w.ctx, config, len(packet)); err != nil {
				return // context cancelled while waiting
			}
		}
	} else if w.engine != nil && config.ClassID != "" {
		// Child bucket: per-strategy rate limit.
		if limiter := w.engine.GetRateLimiter(config.ClassID); limiter != nil {
			if err := limiter.Wait(w.ctx, int64(len(packet))); err != nil {
				return // context cancelled while waiting
			}
		}
	}
	// Parent bucket: task-level aggregate ceiling. Always applied when
	// parent_task_id is set, regardless of whether a pacer or child bucket
	// ran above. This is the invariant: replay strategies with original/
	// multiplier pacers are rejected at Create/Start if a task-level bps is
	// also set, so in well-formed tasks the parent bucket is either absent
	// or complementary. When misconfigured (e.g., a stale task loaded from
	// DB without re-validation), this still enforces the ceiling as
	// defense-in-depth.
	if w.engine != nil {
		if parentID, ok := config.Metadata["parent_task_id"].(string); ok && parentID != "" {
			if parentLimiter := w.engine.GetRateLimiter(parentID); parentLimiter != nil {
				if err := parentLimiter.Wait(w.ctx, int64(len(packet))); err != nil {
					return // context cancelled while waiting
				}
			}
		}
	}

	out := PacketOutput{
		Data:        packet,
		Metadata:    config.Metadata,
		FlowID:      config.FlowID,
		PacketIndex: config.PacketIndex,
		Direction:   config.Direction,
		Timestamp:   config.Timestamp, // scheduled send time (§12: pcap output uses this)
	}
	// Push to this worker's own shard in shardedPacketChan. PacketWorker.id
	// == shardIdx == OutputWorker.id, so the same shard's packets flow
	// ConfigWorker -> shardedConfigChan[i] -> PacketWorker[i] ->
	// shardedPacketChan[i] -> OutputWorker[i] -> NIC, all single-goroutine
	// serial, strict FIFO (spec §3.4 invariant 2-3).
	select {
	case <-w.ctx.Done():
		return
	case w.engine.shardedPacketChan[w.id] <- out:
		atomic.AddInt64(&w.stats.PacketsGenerated, 1)
	}
}

// GetStats returns worker statistics.
func (w *PacketWorker) GetStats() WorkerStats {
	return WorkerStats{
		PacketsGenerated: atomic.LoadInt64(&w.stats.PacketsGenerated),
		TasksProcessed:   atomic.LoadInt64(&w.stats.TasksProcessed),
		Errors:           atomic.LoadInt64(&w.stats.Errors),
	}
}

// NOTE: Per-flow sharded channel guarantees ordering — same flow always lands
// on the same PacketWorker (shard), so no resequencing is needed even with
// multiple PacketWorkers. See shardedConfigChan in Engine and computeHashKey
// in shard_router.go.

// OutputWorker handles packet output.
type OutputWorker struct {
	id        int
	shardChan <-chan PacketOutput // own shard of shardedPacketChan
	buffer    *PacketBuffer
	engine    *Engine // for accessing output writers
	wg        *sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	stats     WorkerStats

	// NOTE: Resequencing fields removed; sharded channel guarantees ordering.
}

// NewOutputWorker creates a new output worker.
func NewOutputWorker(
	id int,
	shardChan <-chan PacketOutput,
	buffer *PacketBuffer,
	engine *Engine,
	wg *sync.WaitGroup,
) *OutputWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &OutputWorker{
		id:        id,
		shardChan: shardChan,
		buffer:    buffer,
		engine:    engine,
		wg:        wg,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start starts the output worker.
func (w *OutputWorker) Start() {
	go w.run()
}

// Stop stops the output worker.
func (w *OutputWorker) Stop() {
	w.cancel()
}

// run is the main worker loop.
func (w *OutputWorker) run() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case out, ok := <-w.shardChan:
			if !ok {
				return
			}
			w.processPacket(out)
		}
	}
}

// processPacket processes a single packet output.
// Resequencing reorders packets by FlowID + PacketIndex to ensure
// correct ordering when multiple PacketWorkers are used.
func (w *OutputWorker) processPacket(out PacketOutput) {
	// Single PacketWorker guarantees ordering — pass through immediately
	w.writePacket(out)
}

// writePacket writes a single packet to output writer and buffer.
func (w *OutputWorker) writePacket(out PacketOutput) {
	packet := out.Data

	// 1. Route to registered output writer based on task_id metadata. For
	// dual-port tasks, route by Direction to the matching interface writer.
	if w.engine != nil && out.Metadata != nil {
		if taskID, ok := out.Metadata["task_id"].(string); ok && taskID != "" {
			if dw := w.engine.GetDualWriter(taskID); dw != nil {
				// Primary (C2S) side = "up"/"c2s"; secondary (S2C) = "down"/"s2c".
				pw := dw.C2S
				if out.Direction == "down" || out.Direction == "s2c" {
					pw = dw.S2C
				}
				if pw != nil {
					if err := writePacketsTo(pw, out); err != nil {
						zap.L().Error("dual-port writer error, failing task", zap.String("task_id", taskID), zap.Error(err))
						atomic.AddInt64(&w.stats.Errors, 1)
						if w.engine.OnOutputError != nil {
							w.engine.OnOutputError(taskID, err)
						} else {
							w.engine.FailTask(taskID, "output writer error: "+err.Error())
							w.engine.UnregisterDualWriter(taskID)
						}
						return
					}
					// Fall through to buffer + OnPacketWritten.
				}
			} else {
				w.engine.outputMu.RLock()
				writer, found := w.engine.outputWriters[taskID]
				w.engine.outputMu.RUnlock()
				if found && writer != nil {
					if err := writePacketsTo(writer, out); err != nil {
						zap.L().Error("output writer error, failing task",
							zap.String("task_id", taskID),
							zap.Error(err),
						)
						atomic.AddInt64(&w.stats.Errors, 1)
						if w.engine.OnOutputError != nil {
							w.engine.OnOutputError(taskID, err)
						} else {
							w.engine.FailTask(taskID, "output writer error: "+err.Error())
							w.engine.UnregisterOutputWriter(taskID)
						}
						return
					}
				}
			}
		}
	}

	// 2. Store in buffer for API retrieval (best-effort). Overflow does NOT
	// fail the task: the packet was already written to the output writer
	// above; the buffer is only a snapshot for get_packets. We log and count
	// the drop but still count the packet as written so task completion
	// accounting is not stalled (otherwise a task generating more than
	// BufferSize packets would never reach writtenPackets==totalConfigs and
	// leak forever).
	direction := "combined"
	if w.buffer != nil {
		if !w.buffer.Put(packet, direction) {
			zap.L().Warn("buffer overflow", zap.Int("worker_id", w.id))
			atomic.AddInt64(&w.stats.Errors, 1)
			if w.engine != nil && w.engine.OnBufferOverflow != nil {
				if taskID, ok := out.Metadata["task_id"].(string); ok {
					w.engine.OnBufferOverflow(taskID, 1)
				}
			}
		}
	}

	atomic.AddInt64(&w.stats.PacketsGenerated, 1)

	// 3. Notify engine that a packet was written. Always fires (even on buffer
	// overflow) so the task completes once all planned packets are processed.
	if w.engine != nil && out.Metadata != nil {
		if taskID, ok := out.Metadata["task_id"].(string); ok {
			w.engine.OnPacketWritten(taskID)
		}
	}
}

// GetStats returns worker statistics.
func (w *OutputWorker) GetStats() WorkerStats {
	return WorkerStats{
		PacketsGenerated: atomic.LoadInt64(&w.stats.PacketsGenerated),
		TasksProcessed:   atomic.LoadInt64(&w.stats.TasksProcessed),
		Errors:           atomic.LoadInt64(&w.stats.Errors),
	}
}
