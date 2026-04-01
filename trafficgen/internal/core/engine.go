package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Engine is the main traffic generation engine.
type Engine struct {
	config       EngineConfig
	planners     map[string]ProtocolPlanner
	buildFunc    func(PacketConfig) ([]byte, error)

	// Channels
	taskChan   chan Task
	configChan chan PacketConfig
	packetChan chan []byte

	// Workers
	configWorkers  []*ConfigWorker
	packetWorkers  []*PacketWorker
	outputWorkers  []*OutputWorker

	// Buffers
	buffer *PacketBuffer

	// Rate limiters
	rateLimiters map[string]*TokenBucket

	// State
	running   atomic.Bool
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	taskStore map[string]*TaskStatus

	// Error handling
	fatalError atomic.Value
}

// EngineConfig for engine configuration.
type EngineConfig struct {
	ConfigWorkers int
	PacketWorkers int
	OutputWorkers int
	BufferSize    int
	QueueSize     int
	MaxBufferBytes int64
}

// NewEngine creates a new traffic engine.
func NewEngine(config EngineConfig) *Engine {
	return &Engine{
		config:       config,
		planners:     make(map[string]ProtocolPlanner),
		rateLimiters: make(map[string]*TokenBucket),
		taskStore:    make(map[string]*TaskStatus),
	}
}

// RegisterPlanner registers a protocol planner.
func (e *Engine) RegisterPlanner(planner ProtocolPlanner) {
	e.planners[planner.Name()] = planner
}

// SetBuildFunc sets the packet building function.
func (e *Engine) SetBuildFunc(fn func(PacketConfig) ([]byte, error)) {
	e.buildFunc = fn
}

// Start starts the engine.
func (e *Engine) Start() error {
	if e.running.Load() {
		return fmt.Errorf("engine already running")
	}

	// Initialize context
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Initialize channels
	e.taskChan = make(chan Task, e.config.QueueSize)
	e.configChan = make(chan PacketConfig, e.config.QueueSize*2)
	e.packetChan = make(chan []byte, e.config.QueueSize*2)

	// Initialize buffer
	e.buffer = NewPacketBuffer(PacketBufferConfig{
		Size:           e.config.BufferSize,
		MaxBytes:       e.config.MaxBufferBytes,
		EnableCombined: true,
	})

	// Start config workers
	e.configWorkers = make([]*ConfigWorker, e.config.ConfigWorkers)
	for i := 0; i < e.config.ConfigWorkers; i++ {
		worker := NewConfigWorker(i, e.planners, e.taskChan, e.configChan, &e.wg)
		e.configWorkers[i] = worker
		worker.Start()
	}

	// Start packet workers
	e.packetWorkers = make([]*PacketWorker, e.config.PacketWorkers)
	for i := 0; i < e.config.PacketWorkers; i++ {
		rateLimiter := NewTokenBucket(0, 65536) // No rate limit by default
		worker := NewPacketWorker(i, e.configChan, e.packetChan, e.buildFunc, &e.wg, rateLimiter)
		e.packetWorkers[i] = worker
		worker.Start()
	}

	// Start output workers
	e.outputWorkers = make([]*OutputWorker, e.config.OutputWorkers)
	for i := 0; i < e.config.OutputWorkers; i++ {
		worker := NewOutputWorker(i, e.packetChan, e.buffer, &e.wg)
		e.outputWorkers[i] = worker
		worker.Start()
	}

	e.running.Store(true)
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

	// Close channels
	close(e.taskChan)

	// Cancel context
	e.cancel()

	// Wait for workers
	e.wg.Wait()

	// Close remaining channels
	close(e.configChan)
	close(e.packetChan)

	// Close buffer
	if e.buffer != nil {
		e.buffer.Close()
	}

	zap.L().Info("engine stopped")
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

	// Initialize task status
	status := &TaskStatus{
		TaskID:    task.ID,
		Status:    "created",
		Progress:  0,
		CreatedAt: time.Now(),
	}
	e.taskStore[task.ID] = status

	// Submit task
	select {
	case e.taskChan <- task:
		status.Status = "running"
		status.StartedAt = time.Now()
		zap.L().Info("task submitted",
			zap.String("task_id", task.ID),
			zap.String("protocol", task.Protocol),
		)
		return nil
	case <-time.After(5 * time.Second):
		status.Status = "failed"
		status.Error = "task queue full"
		return fmt.Errorf("task queue full")
	}
}

// GetTaskStatus returns the status of a task.
func (e *Engine) GetTaskStatus(taskID string) (*TaskStatus, error) {
	status, ok := e.taskStore[taskID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return status, nil
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

// SetClassRateLimit sets the rate limit for a class.
func (e *Engine) SetClassRateLimit(classID string, bps int64) {
	limiter := NewTokenBucket(bps, 65536)
	e.rateLimiters[classID] = limiter
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
