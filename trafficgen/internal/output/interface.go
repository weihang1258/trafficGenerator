package output

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// InterfaceWriter writes packets to a network interface.
type InterfaceWriter struct {
	handle    *pcap.Handle
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

// Write writes packets to the interface.
func (w *InterfaceWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, packet := range packets {
		if err := w.handle.WritePacketData(packet); err != nil {
			w.errors++
			zap.L().Debug("write packet error",
				zap.String("interface", w.iface),
				zap.Error(err),
			)
			continue
		}
		w.sent++
	}

	return nil
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
	batchSize int
	batch     [][]byte
	timer     *time.Timer
	flushChan chan struct{}
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
		batch:           make([][]byte, 0, batchSize),
		flushChan:       make(chan struct{}, 1),
	}

	// Start flush timer
	bw.timer = time.AfterFunc(flushInterval, func() {
		select {
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

// flushLoop periodically flushes the batch.
func (w *BatchInterfaceWriter) flushLoop() {
	for range w.flushChan {
		w.mu.Lock()
		w.flushLocked()
		w.mu.Unlock()
	}
}

// flushLocked flushes the batch (must hold lock).
func (w *BatchInterfaceWriter) flushLocked() error {
	if len(w.batch) == 0 {
		return nil
	}

	for _, packet := range w.batch {
		if err := w.handle.WritePacketData(packet); err != nil {
			w.errors++
			continue
		}
		w.sent++
	}

	w.batch = w.batch[:0]
	return nil
}

// Close closes the writer and flushes remaining packets.
func (w *BatchInterfaceWriter) Close() error {
	w.mu.Lock()
	w.flushLocked()
	w.mu.Unlock()

	if w.timer != nil {
		w.timer.Stop()
	}

	return w.InterfaceWriter.Close()
}

// InjectPacket injects a single gopacket packet.
func (w *InterfaceWriter) InjectPacket(packet gopacket.Packet) error {
	return w.Write([][]byte{packet.Data()})
}
