package core

import (
	"context"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// ProtocolPlanner defines the interface for protocol-specific planning.
type ProtocolPlanner interface {
	// Name returns the protocol name.
	Name() string

	// Plan generates packet configs from a flow spec.
	Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error)

	// Validate validates a flow spec.
	Validate(spec FlowSpec) error
}

// ConfigWorker generates packet configurations.
type ConfigWorker struct {
	id          int
	planners    map[string]ProtocolPlanner
	taskChan    <-chan Task
	configChan  chan<- PacketConfig
	wg          *sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	stats       WorkerStats
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
	taskChan <-chan Task,
	configChan chan<- PacketConfig,
	wg *sync.WaitGroup,
) *ConfigWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigWorker{
		id:         id,
		planners:   planners,
		taskChan:   taskChan,
		configChan: configChan,
		wg:         wg,
		ctx:        ctx,
		cancel:     cancel,
	}
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

			w.processTask(task)
		}
	}
}

// processTask processes a single task.
func (w *ConfigWorker) processTask(task Task) {
	planner, ok := w.planners[task.Protocol]
	if !ok {
		zap.L().Error("unknown protocol",
			zap.String("task_id", task.ID),
			zap.String("protocol", task.Protocol),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		return
	}

	// Validate task
	if err := planner.Validate(task.Spec); err != nil {
		zap.L().Error("task validation failed",
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		return
	}

	// Plan packet configs
	configChan, err := planner.Plan(w.ctx, task.Spec)
	if err != nil {
		zap.L().Error("task planning failed",
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		atomic.AddInt64(&w.stats.Errors, 1)
		return
	}

	// Forward configs to packet workers
	for config := range configChan {
		config.ClassID = task.ClassID
		config.Metadata["task_id"] = task.ID
		config.Metadata["interface"] = task.Interface

		select {
		case <-w.ctx.Done():
			return
		case w.configChan <- config:
			atomic.AddInt64(&w.stats.PacketsGenerated, 1)
		}
	}

	atomic.AddInt64(&w.stats.TasksProcessed, 1)
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
	packetChan chan<- []byte
	buildFunc  func(PacketConfig) ([]byte, error)
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats
	rateLimit  *TokenBucket
}

// NewPacketWorker creates a new packet worker.
func NewPacketWorker(
	id int,
	configChan <-chan PacketConfig,
	packetChan chan<- []byte,
	buildFunc func(PacketConfig) ([]byte, error),
	wg *sync.WaitGroup,
	rateLimit *TokenBucket,
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
		rateLimit:  rateLimit,
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
	// Apply rate limiting
	if w.rateLimit != nil {
		// Estimate packet size (we don't know exact size yet)
		estimatedSize := int64(1500) // MTU
		if err := w.rateLimit.Wait(w.ctx, estimatedSize); err != nil {
			return
		}
	}

	// Build packet
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

	// Send to output worker
	select {
	case <-w.ctx.Done():
		return
	case w.packetChan <- packet:
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

// OutputWorker handles packet output.
type OutputWorker struct {
	id         int
	packetChan <-chan []byte
	buffer     *PacketBuffer
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	stats      WorkerStats
}

// NewOutputWorker creates a new output worker.
func NewOutputWorker(
	id int,
	packetChan <-chan []byte,
	buffer *PacketBuffer,
	wg *sync.WaitGroup,
) *OutputWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &OutputWorker{
		id:         id,
		packetChan: packetChan,
		buffer:     buffer,
		wg:         wg,
		ctx:        ctx,
		cancel:     cancel,
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
		case packet, ok := <-w.packetChan:
			if !ok {
				return
			}

			w.processPacket(packet)
		}
	}
}

// processPacket processes a single packet.
func (w *OutputWorker) processPacket(packet []byte) {
	// Store in buffer
	direction := "combined" // default
	if w.buffer != nil {
		if !w.buffer.Put(packet, direction) {
			zap.L().Warn("buffer overflow",
				zap.Int("worker_id", w.id),
			)
			atomic.AddInt64(&w.stats.Errors, 1)
			return
		}
	}

	atomic.AddInt64(&w.stats.PacketsGenerated, 1)
}

// GetStats returns worker statistics.
func (w *OutputWorker) GetStats() WorkerStats {
	return WorkerStats{
		PacketsGenerated: atomic.LoadInt64(&w.stats.PacketsGenerated),
		TasksProcessed:   atomic.LoadInt64(&w.stats.TasksProcessed),
		Errors:           atomic.LoadInt64(&w.stats.Errors),
	}
}
