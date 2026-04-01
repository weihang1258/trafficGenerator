// Package output provides packet output functionality.
package output

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// Writer defines the interface for packet output.
type Writer interface {
	// Write writes packets to the output.
	Write(packets [][]byte) error

	// Close closes the writer.
	Close() error
}

// MultiWriter writes to multiple outputs.
type MultiWriter struct {
	writers []Writer
	mu      sync.Mutex
}

// NewMultiWriter creates a new multi-writer.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
	}
}

// Write writes packets to all writers.
func (w *MultiWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var lastErr error
	for _, writer := range w.writers {
		if err := writer.Write(packets); err != nil {
			lastErr = err
			zap.L().Error("writer error", zap.Error(err))
		}
	}
	return lastErr
}

// Close closes all writers.
func (w *MultiWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var lastErr error
	for _, writer := range w.writers {
		if err := writer.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// AddWriter adds a writer.
func (w *MultiWriter) AddWriter(writer Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writers = append(w.writers, writer)
}

// Manager manages output writers.
type Manager struct {
	writers map[string]Writer
	mu      sync.RWMutex
}

// NewManager creates a new output manager.
func NewManager() *Manager {
	return &Manager{
		writers: make(map[string]Writer),
	}
}

// Register registers a writer with a name.
func (m *Manager) Register(name string, writer Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writers[name] = writer
}

// Get retrieves a writer by name.
func (m *Manager) Get(name string) (Writer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	writer, ok := m.writers[name]
	return writer, ok
}

// Write writes packets to a specific writer.
func (m *Manager) Write(name string, packets [][]byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	writer, ok := m.writers[name]
	if !ok {
		return fmt.Errorf("writer not found: %s", name)
	}
	return writer.Write(packets)
}

// WriteAll writes packets to all writers.
func (m *Manager) WriteAll(packets [][]byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for name, writer := range m.writers {
		if err := writer.Write(packets); err != nil {
			lastErr = err
			zap.L().Error("writer error",
				zap.String("writer", name),
				zap.Error(err),
			)
		}
	}
	return lastErr
}

// Close closes all writers.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for name, writer := range m.writers {
		if err := writer.Close(); err != nil {
			lastErr = err
			zap.L().Error("close writer error",
				zap.String("writer", name),
				zap.Error(err),
			)
		}
		delete(m.writers, name)
	}
	return lastErr
}

// List returns all writer names.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.writers))
	for name := range m.writers {
		names = append(names, name)
	}
	return names
}

// OutputWorker processes packets from a channel.
type OutputWorker struct {
	id        int
	packetChan <-chan [][]byte
	writer    Writer
	ctx       context.Context
	cancel    context.CancelFunc
	wg        *sync.WaitGroup
	stats     WorkerStats
}

// WorkerStats holds worker statistics.
type WorkerStats struct {
	PacketsWritten int64
	BytesWritten   int64
	Errors         int64
}

// NewOutputWorker creates a new output worker.
func NewOutputWorker(id int, packetChan <-chan [][]byte, writer Writer, wg *sync.WaitGroup) *OutputWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &OutputWorker{
		id:         id,
		packetChan: packetChan,
		writer:     writer,
		ctx:        ctx,
		cancel:     cancel,
		wg:         wg,
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
		case packets, ok := <-w.packetChan:
			if !ok {
				return
			}

			if err := w.writer.Write(packets); err != nil {
				w.stats.Errors++
				continue
			}

			for _, p := range packets {
				w.stats.PacketsWritten++
				w.stats.BytesWritten += int64(len(p))
			}
		}
	}
}

// GetStats returns worker statistics.
func (w *OutputWorker) GetStats() WorkerStats {
	return w.stats
}
