package output

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// packetHandle is the subset of *pcap.Handle this package uses (writing
// packets and closing). Declared as an interface so tests can inject a fake
// handle to exercise write-failure paths without a real network interface.
// *pcap.Handle satisfies this interface.
type packetHandle interface {
	WritePacketData([]byte) error
	Close()
}

// InterfaceWriter writes packets to a network interface.
type InterfaceWriter struct {
	handle    packetHandle
	iface     string
	mu        sync.Mutex
	sent      int64
	errors    int64
	startTime time.Time
}

// NewInterfaceWriter creates a new interface writer.
func NewInterfaceWriter(iface string) (*InterfaceWriter, error) {
	// Open live handle for packet injection
	handle, err := pcap.OpenLive(
		iface,
		65535, // snaplen
		true,  // promiscuous
		pcap.BlockForever,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}

	return &InterfaceWriter{
		handle:    handle,
		iface:     iface,
		startTime: time.Now(),
	}, nil
}

// Write writes packets to the interface. Returns the first write error
// encountered so a dead interface fails the task instead of silently
// reporting success with zero packets actually sent.
func (w *InterfaceWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.handle == nil {
		return fmt.Errorf("interface writer closed: %s", w.iface)
	}

	var firstErr error
	for _, packet := range packets {
		if err := w.handle.WritePacketData(packet); err != nil {
			w.errors++
			zap.L().Debug("write packet error",
				zap.String("interface", w.iface),
				zap.Error(err),
			)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		w.sent++
	}

	return firstErr
}

// Close closes the interface handle.
func (w *InterfaceWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.handle != nil {
		w.handle.Close()
		w.handle = nil
	}
	return nil
}

// Stats returns writer statistics.
func (w *InterfaceWriter) Stats() map[string]interface{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	duration := time.Since(w.startTime).Seconds()
	var pps float64
	if duration > 0 {
		pps = float64(w.sent) / duration
	}

	return map[string]interface{}{
		"interface":    w.iface,
		"packets_sent": w.sent,
		"errors":       w.errors,
		"duration_sec": duration,
		"pps":          pps,
	}
}

// BatchInterfaceWriter writes packets in batches for better performance.
type BatchInterfaceWriter struct {
	*InterfaceWriter
	batchSize     int
	batch         [][]byte
	flushInterval time.Duration
	timer         *time.Timer
	flushChan     chan struct{}
	done          chan struct{}
	once          sync.Once
}

// NewBatchInterfaceWriter creates a new batch interface writer.
func NewBatchInterfaceWriter(iface string, batchSize int, flushInterval time.Duration) (*BatchInterfaceWriter, error) {
	iw, err := NewInterfaceWriter(iface)
	if err != nil {
		return nil, err
	}

	bw := &BatchInterfaceWriter{
		InterfaceWriter: iw,
		batchSize:       batchSize,
		flushInterval:   flushInterval,
		batch:           make([][]byte, 0, batchSize),
		flushChan:       make(chan struct{}, 1),
		done:            make(chan struct{}),
	}

	// Start flush timer
	bw.timer = time.AfterFunc(flushInterval, func() {
		// Guard against sending after Close: select on done so we never send
		// on a flushed/closing path (flushChan is never closed, but we stop
		// signalling once done is closed).
		select {
		case <-bw.done:
		case bw.flushChan <- struct{}{}:
		default:
		}
	})

	go bw.flushLoop()

	return bw, nil
}

// Write adds packets to the batch.
func (w *BatchInterfaceWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, packet := range packets {
		w.batch = append(w.batch, packet)

		if len(w.batch) >= w.batchSize {
			if err := w.flushLocked(); err != nil {
				return err
			}
		}
	}

	return nil
}

// flushLoop periodically flushes the batch. Exits when done is closed.
// Logs flush errors (a transient timer-driven flush should not fail the task,
// but the error must not be silently swallowed). Re-arms the one-shot AfterFunc
// timer after each flush: without Reset the timer fires only once, so
// sub-batchSize writes would sit in w.batch until Close (delayed delivery /
// data held in memory for the task's whole lifetime).
func (w *BatchInterfaceWriter) flushLoop() {
	for {
		select {
		case <-w.done:
			return
		case <-w.flushChan:
			w.mu.Lock()
			if err := w.flushLocked(); err != nil {
				zap.L().Warn("batch interface flush error",
					zap.String("interface", w.iface),
					zap.Error(err),
				)
			}
			w.mu.Unlock()
			// Re-arm the periodic flush. Concurrent with Close's timer.Stop:
			// time.Timer Reset/Stop are mutex-protected internally (no panic,
			// no race-detector trip). If Stop already fired, this arms one more
			// tick whose callback harmlessly selects <-done and does not re-arm
			// again (this loop has exited), so there is no post-close spin.
			w.timer.Reset(w.flushInterval)
		}
	}
}

// flushLocked flushes the batch (must hold lock). Returns the first write error.
// Guards against a nil handle (e.g. Write-after-Close) to avoid a nil deref.
func (w *BatchInterfaceWriter) flushLocked() error {
	if len(w.batch) == 0 {
		return nil
	}
	if w.handle == nil {
		w.batch = w.batch[:0]
		return fmt.Errorf("interface writer closed: %s", w.iface)
	}

	var firstErr error
	for _, packet := range w.batch {
		if err := w.handle.WritePacketData(packet); err != nil {
			w.errors++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		w.sent++
	}

	w.batch = w.batch[:0]
	return firstErr
}

// Close closes the writer and flushes remaining packets. Signals flushLoop to
// exit via the done channel (closing done, never flushChan) to avoid a
// goroutine leak and a send-on-closed-channel panic. Returns the final flush
// error (if any) alongside the underlying close error.
func (w *BatchInterfaceWriter) Close() error {
	w.once.Do(func() { close(w.done) })
	if w.timer != nil {
		w.timer.Stop()
	}

	w.mu.Lock()
	flushErr := w.flushLocked()
	w.mu.Unlock()

	closeErr := w.InterfaceWriter.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// InjectPacket injects a single gopacket packet.
func (w *InterfaceWriter) InjectPacket(packet gopacket.Packet) error {
	return w.Write([][]byte{packet.Data()})
}
