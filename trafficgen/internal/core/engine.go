package core

import (
	"context"
	"fmt"
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

	// Channels
	taskChan   chan Task
	configChan chan PacketConfig
	packetChan chan PacketOutput // carries packet bytes + metadata for routing

	// Workers
	configWorkers []*ConfigWorker
	packetWorkers []*PacketWorker
	outputWorkers []*OutputWorker

	// Buffers
	buffer *PacketBuffer

	// Output writers indexed by task ID for per-task output routing
	outputWriters map[string]PacketWriter
	outputMu      sync.RWMutex

	// Rate limiters
	rateLimiters map[string]*TokenBucket
	rateMu       sync.RWMutex

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

	// Callbacks
	OnTaskComplete   func(taskID string)                // called when a task finishes (completed or failed)
	OnTaskFailed     func(taskID string, errMsg string) // called when a task fails with error message
	OnBufferOverflow func(taskID string, dropped int)   // called when buffer overflows
	OnOutputError    func(taskID string, err error)     // called when output writer fails
	OnProgress       func(taskID string, progress float64, stats TaskStats) // called when task progress changes

	// Error handling
	fatalError atomic.Value
}

// PacketWriter writes raw packets to an output (pcap file, network interface, etc.).
type PacketWriter interface {
	WritePackets(packets [][]byte) error
	Close() error
}

// PacketOutput carries a built packet with its routing metadata.
type PacketOutput struct {
	Data        []byte
	Metadata    map[string]interface{}
	FlowID      string
	PacketIndex uint64
}

type taskEntry struct {
	task   *Task
	status *TaskStatus
	cancel context.CancelFunc

	// Pipeline drain tracking: ConfigWorker sets totalConfigs when done,
	// OutputWorker increments writtenPackets per write.
	// Completion fires when writtenPackets >= totalConfigs && totalConfigs > 0.
	totalConfigs   int64
	writtenPackets int64
}

// EngineConfig for engine configuration.
type EngineConfig struct {
	ConfigWorkers  int
	PacketWorkers  int
	OutputWorkers  int
	BufferSize     int
	QueueSize      int
	MaxBufferBytes int64
}

// NewEngine creates a new traffic engine.
func NewEngine(config EngineConfig) *Engine {
	return &Engine{
		config:        config,
		planners:      make(map[string]ProtocolPlanner),
		rateLimiters:  make(map[string]*TokenBucket),
		taskStore:     make(map[string]*taskEntry),
		outputWriters: make(map[string]PacketWriter),
	}
}

// RegisterPlanner registers a protocol planner.
func (e *Engine) RegisterPlanner(planner ProtocolPlanner) {
	e.planners[planner.Name()] = planner
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

// RegisterOutputWriter registers a packet writer for a task.
func (e *Engine) RegisterOutputWriter(taskID string, writer PacketWriter) {
	e.outputMu.Lock()
	e.outputWriters[taskID] = writer
	e.outputMu.Unlock()
}

// UnregisterOutputWriter removes and closes a task's output writer.
func (e *Engine) UnregisterOutputWriter(taskID string) {
	e.outputMu.Lock()
	w, ok := e.outputWriters[taskID]
	if ok {
		delete(e.outputWriters, taskID)
		w.Close()
	}
	e.outputMu.Unlock()
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
	e.packetChan = make(chan PacketOutput, e.config.QueueSize*2)

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
		worker := NewConfigWorker(i, e.planners, e.taskChan, e.configChan, &e.wg)
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

	// Start packet workers
	e.packetWorkers = make([]*PacketWorker, e.config.PacketWorkers)
	for i := 0; i < e.config.PacketWorkers; i++ {
		e.wg.Add(1)
		// Rate limiting is engine-level (per ClassID), looked up via engine ref.
		worker := NewPacketWorker(i, e.configChan, e.packetChan, buildFn, &e.wg, e)
		e.packetWorkers[i] = worker
		worker.Start()
	}

	// Start output workers
	e.outputWorkers = make([]*OutputWorker, e.config.OutputWorkers)
	for i := 0; i < e.config.OutputWorkers; i++ {
		e.wg.Add(1)
		worker := NewOutputWorker(i, e.packetChan, e.buffer, e, &e.wg)
		e.outputWorkers[i] = worker
		worker.Start()
	}

	e.running.Store(true)

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

	// Close taskChan so ConfigWorkers stop receiving new tasks
	close(e.taskChan)

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

	// Wire rate limit: parse BPS and create a per-class TokenBucket.
	// The bucket is keyed by ClassID (falls back to task ID for single-protocol
	// tasks without a ClassID). PacketWorker looks it up by config.ClassID.
	if task.Spec.BPS != "" {
		bps, err := ParseBPS(task.Spec.BPS)
		if err != nil {
			return fmt.Errorf("invalid bps %q: %w", task.Spec.BPS, err)
		}
		if bps > 0 {
			classKey := task.ClassID
			if classKey == "" {
				classKey = task.ID
			}
			e.SetClassRateLimit(classKey, bps)
		}
	}

	// Create per-task context for cancellation
	taskCtx, cancel := context.WithCancel(e.ctx)

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
	e.taskMu.Lock()
	e.taskStore[task.ID] = &taskEntry{task: &task, status: status, cancel: cancel}
	e.taskMu.Unlock()

	// Submit task
	select {
	case e.taskChan <- task:
		zap.L().Info("task submitted",
			zap.String("task_id", task.ID),
			zap.String("protocol", task.Protocol),
		)
		return nil
	case <-time.After(5 * time.Second):
		status.Status = "failed"
		status.Error = "task queue full"
		cancel()
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
	if count > 0 && entry.writtenPackets >= count {
		entry.status.Status = "completed"
		entry.status.Progress = 100
		entry.status.CompletedAt = time.Now()
		entry.cancel()
		delete(e.taskStore, taskID)
		e.taskMu.Unlock()
		zap.L().Info("task completed (totalConfigs set after drain)", zap.String("task_id", taskID))
		if e.OnTaskComplete != nil {
			e.OnTaskComplete(taskID)
		}
		return
	}
	e.taskMu.Unlock()
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
	if entry.totalConfigs > 0 && entry.writtenPackets >= entry.totalConfigs {
		entry.status.Status = "completed"
		entry.status.Progress = 100
		entry.status.CompletedAt = time.Now()
		entry.cancel()
		delete(e.taskStore, taskID)
		e.taskMu.Unlock()
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
	entry.status.Status = "failed"
	entry.status.Error = errMsg
	entry.status.CompletedAt = time.Now()
	entry.cancel()
	delete(e.taskStore, taskID)
	e.taskMu.Unlock()

	zap.L().Info("task failed", zap.String("task_id", taskID), zap.String("error", errMsg))

	if e.OnTaskFailed != nil {
		e.OnTaskFailed(taskID, errMsg)
	}

	if e.OnTaskComplete != nil {
		e.OnTaskComplete(taskID)
	}
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

// SetClassRateLimit sets the rate limit for a class.
func (e *Engine) SetClassRateLimit(classID string, bps int64) {
	limiter := NewTokenBucket(bps, 65536)
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
