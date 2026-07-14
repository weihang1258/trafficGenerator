package core

import (
	"context"
	"encoding/json"
	"fmt"
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

// ReplayPlanner generates packet configs for a replay TrafficClass (§16.12).
// Defined in core (taking raw JSON) so core can dispatch to it without importing
// the replay package; the concrete replay.ReplayPlanner implements this.
type ReplayPlanner interface {
	PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string) (<-chan PacketConfig, error)
}

// ConfigWorker generates packet configurations.
type ConfigWorker struct {
	id            int
	planners      map[string]ProtocolPlanner
	replayPlanner ReplayPlanner
	taskChan      <-chan Task
	configChan    chan<- PacketConfig
	wg            *sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	stats         WorkerStats
	onTaskDone    func(taskID string, err error, count int64)
	sem           chan struct{} // limits concurrent task processing per worker
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
	configChan chan<- PacketConfig,
	wg *sync.WaitGroup,
) *ConfigWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigWorker{
		id:            id,
		planners:      planners,
		replayPlanner: replayPlanner,
		taskChan:      taskChan,
		configChan:    configChan,
		wg:            wg,
		ctx:        ctx,
		cancel:     cancel,
		sem:        make(chan struct{}, 4), // process up to 4 tasks concurrently per worker
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

	zap.L().Info("processing task",
		zap.String("task_id", task.ID),
		zap.String("protocol", task.Protocol),
		zap.Int("planners_count", len(w.planners)),
	)

	planner, ok := w.planners[task.Protocol]
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

	// Validate task
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

	// Plan packet configs
	configChan, err := planner.Plan(taskCtx, task.Spec)
	if err != nil {
		zap.L().Error("task planning failed",
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		if w.onTaskDone != nil {
			w.onTaskDone(task.ID, fmt.Errorf("planning failed: %w", err), 0)
		}
		return
	}

	// Forward configs to packet workers
	var configCount int64
	for config := range configChan {
		config.ClassID = task.ClassID
		// Propagate flow-level VLAN to the packet's L2 config. Planners do not
		// copy spec.VLAN into L2Config, so without this the builder never sees
		// the VLAN and 802.1Q tags are never emitted.
		if config.L2.VLAN == nil && task.Spec.VLAN != nil {
			config.L2.VLAN = task.Spec.VLAN
		}
		if config.Metadata == nil {
			config.Metadata = make(map[string]interface{})
		}
		config.Metadata["task_id"] = task.ID
		config.Metadata["interface"] = task.Interface

		select {
		case <-taskCtx.Done():
			// Drain remaining configs so the planner goroutine is not blocked
			// on configChan <- (which would leak it permanently). Planners
			// generate a finite number of packets, so this drain is bounded.
			for range configChan {
			}
			if w.onTaskDone != nil {
				w.onTaskDone(task.ID, fmt.Errorf("task cancelled"), configCount)
			}
			return
		case w.configChan <- config:
			configCount++
		}
	}

	atomic.AddInt64(&w.stats.TasksProcessed, 1)
	atomic.AddInt64(&w.stats.PacketsGenerated, configCount)
	if w.onTaskDone != nil {
		w.onTaskDone(task.ID, nil, configCount)
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

	var classWg sync.WaitGroup
	var configCount int64
	var flowFailures int64
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
				configChan, err := w.replayPlanner.PlanReplay(taskCtx, c.Replay, task.ID, classKey, task.UserID)
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
					config.Metadata["task_id"] = task.ID
					config.Metadata["interface"] = task.Interface
					select {
					case <-taskCtx.Done():
						for range configChan {
						}
						return
					case w.configChan <- config:
						atomic.AddInt64(&configCount, 1)
					}
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

			spec := mapToFlowSpec(c.Config, c.Type)
			if c.BPS != "" {
				spec.BPS = c.BPS
			}
			tupleGen := NewTupleGenerator(c.Tuples)
			classKey := task.ID + ":" + c.ID

			for flowIdx := 0; flowIdx < c.FlowCount; flowIdx++ {
				srcIP, dstIP, srcPort, dstPort := tupleGen.Next(flowIdx)
				spec.SrcIP = srcIP
				spec.DstIP = dstIP
				spec.SrcPort = srcPort
				spec.DstPort = dstPort

				if err := p.Validate(spec); err != nil {
					zap.L().Warn("batch flow validation failed, skipping flow",
						zap.String("task_id", task.ID),
						zap.String("class_id", c.ID),
						zap.Error(err),
					)
					atomic.AddInt64(&flowFailures, 1)
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
					if config.Metadata == nil {
						config.Metadata = make(map[string]interface{})
					}
					config.Metadata["task_id"] = task.ID
					config.Metadata["interface"] = task.Interface
					select {
					case <-taskCtx.Done():
						// Drain remaining configs so this class's planner goroutine
						// is not blocked on configChan <- (leak). Bounded: planners
						// generate a finite packet count per flow.
						for range configChan {
						}
						return
					case w.configChan <- config:
						atomic.AddInt64(&configCount, 1)
					}
				}
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
			w.onTaskDone(task.ID, fmt.Errorf("all %d flows failed validation/planning", totalFlows), configCount)
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
	id         int
	configChan <-chan PacketConfig
	packetChan chan<- PacketOutput
	buildFunc  func(PacketConfig) ([]byte, error)
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats
	engine     *Engine // for per-class rate limiter lookup
}

// NewPacketWorker creates a new packet worker.
func NewPacketWorker(
	id int,
	configChan <-chan PacketConfig,
	packetChan chan<- PacketOutput,
	buildFunc func(PacketConfig) ([]byte, error),
	wg *sync.WaitGroup,
	engine *Engine,
) *PacketWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketWorker{
		id:         id,
		configChan: configChan,
		packetChan: packetChan,
		buildFunc:  buildFunc,
		wg:         wg,
		ctx:        ctx,
		cancel:     cancel,
		engine:     engine,
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
		case config, ok := <-w.configChan:
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
		return
	}

	// Rate limit AFTER build using the real packet size. For replay packets,
	// a Pacer in Metadata takes precedence (timestamp/rate pacing per §16.9);
	// otherwise fall back to the per-class TokenBucket.
	if pacer, ok := config.Metadata["_pacer"]; ok {
		if rp, ok := pacer.(interface {
			Wait(context.Context, PacketConfig, int) error
		}); ok {
			if err := rp.Wait(w.ctx, config, len(packet)); err != nil {
				return // context cancelled while waiting
			}
		}
	} else if w.engine != nil && config.ClassID != "" {
		if limiter := w.engine.GetRateLimiter(config.ClassID); limiter != nil {
			if err := limiter.Wait(w.ctx, int64(len(packet))); err != nil {
				return // context cancelled while waiting
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
	select {
	case <-w.ctx.Done():
		return
	case w.packetChan <- out:
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

// NOTE: Resequencing is not currently used because a single PacketWorker guarantees ordering.
// If multiple PacketWorkers are configured in the future, resequencing will be needed.

// OutputWorker handles packet output.
type OutputWorker struct {
	id         int
	packetChan <-chan PacketOutput
	buffer     *PacketBuffer
	engine     *Engine // for accessing output writers
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats

	// NOTE: Resequencing fields removed; single PacketWorker guarantees ordering.
}

// NewOutputWorker creates a new output worker.
func NewOutputWorker(
	id int,
	packetChan <-chan PacketOutput,
	buffer *PacketBuffer,
	engine *Engine,
	wg *sync.WaitGroup,
) *OutputWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &OutputWorker{
		id:           id,
		packetChan:   packetChan,
		buffer:       buffer,
		engine:       engine,
		wg:           wg,
		ctx:          ctx,
		cancel:       cancel,
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
		case out, ok := <-w.packetChan:
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
