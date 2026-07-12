// Package core provides the traffic generation engine.
package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RingBuffer is a thread-safe bounded ring buffer for packets.
type RingBuffer struct {
	mu       sync.RWMutex
	buffer   [][]byte
	size     int
	head     int
	tail     int
	count    int
	bytes    int64
	maxBytes int64
	closed   atomic.Bool
}

// NewRingBuffer creates a new ring buffer.
func NewRingBuffer(size int, maxBytes int64) *RingBuffer {
	return &RingBuffer{
		buffer:   make([][]byte, size),
		size:     size,
		maxBytes: maxBytes,
	}
}

// Put adds a packet to the buffer. Returns false if buffer is full.
func (rb *RingBuffer) Put(packet []byte) bool {
	if rb.closed.Load() {
		return false
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Check if full
	if rb.count >= rb.size {
		return false
	}

	// Check byte limit
	if rb.maxBytes > 0 && rb.bytes+int64(len(packet)) > rb.maxBytes {
		return false
	}

	// Hold the original slice reference directly. The builder returns a fresh
	// slice per packet (never reused), so copying here is wasted work. Callers
	// must not mutate the slice after Put.
	rb.buffer[rb.tail] = packet
	rb.tail = (rb.tail + 1) % rb.size
	rb.count++
	rb.bytes += int64(len(packet))

	return true
}

// Get retrieves a packet from the buffer.
func (rb *RingBuffer) Get() ([]byte, bool) {
	if rb.closed.Load() {
		return nil, false
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		return nil, false
	}

	packet := rb.buffer[rb.head]
	rb.buffer[rb.head] = nil
	rb.head = (rb.head + 1) % rb.size
	rb.count--
	rb.bytes -= int64(len(packet))

	return packet, true
}

// GetBatch retrieves multiple packets from the buffer.
func (rb *RingBuffer) GetBatch(max int) [][]byte {
	if rb.closed.Load() {
		return nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		return nil
	}

	n := max
	if n > rb.count {
		n = rb.count
	}

	packets := make([][]byte, n)
	for i := 0; i < n; i++ {
		packets[i] = rb.buffer[rb.head]
		rb.buffer[rb.head] = nil
		rb.head = (rb.head + 1) % rb.size
		rb.bytes -= int64(len(packets[i]))
	}
	rb.count -= n

	return packets
}

// Len returns the current number of packets in the buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// Bytes returns the current total bytes in the buffer.
func (rb *RingBuffer) Bytes() int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.bytes
}

// Close closes the buffer.
func (rb *RingBuffer) Close() {
	rb.closed.Store(true)
}

// IsFull returns true if the buffer is full.
func (rb *RingBuffer) IsFull() bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count >= rb.size
}

// Status returns the buffer status.
func (rb *RingBuffer) Status() map[string]interface{} {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return map[string]interface{}{
		"count":     rb.count,
		"size":      rb.size,
		"bytes":     rb.bytes,
		"max_bytes": rb.maxBytes,
		"full":      rb.count >= rb.size,
	}
}

// PacketBuffer is a multi-view buffer for up/down/combined directions.
type PacketBuffer struct {
	upBuffer      *RingBuffer
	downBuffer    *RingBuffer
	combinedBuffer *RingBuffer
	enableUp      bool
	enableDown    bool
	enableCombined bool
	mu            sync.RWMutex
}

// PacketBufferConfig for packet buffer configuration.
type PacketBufferConfig struct {
	Size           int
	MaxBytes       int64
	EnableUp       bool
	EnableDown     bool
	EnableCombined bool
}

// NewPacketBuffer creates a new packet buffer.
func NewPacketBuffer(cfg PacketBufferConfig) *PacketBuffer {
	pb := &PacketBuffer{
		enableUp:       cfg.EnableUp,
		enableDown:     cfg.EnableDown,
		enableCombined: cfg.EnableCombined,
	}

	if cfg.EnableUp {
		pb.upBuffer = NewRingBuffer(cfg.Size, cfg.MaxBytes)
	}
	if cfg.EnableDown {
		pb.downBuffer = NewRingBuffer(cfg.Size, cfg.MaxBytes)
	}
	if cfg.EnableCombined {
		pb.combinedBuffer = NewRingBuffer(cfg.Size, cfg.MaxBytes)
	}

	return pb
}

// Put adds a packet to the appropriate buffer based on direction.
func (pb *PacketBuffer) Put(packet []byte, direction string) bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	success := false

	switch direction {
	case "up":
		if pb.enableUp && pb.upBuffer != nil {
			success = pb.upBuffer.Put(packet)
		}
		if pb.enableCombined && pb.combinedBuffer != nil {
			pb.combinedBuffer.Put(packet)
		}
	case "down":
		if pb.enableDown && pb.downBuffer != nil {
			success = pb.downBuffer.Put(packet)
		}
		if pb.enableCombined && pb.combinedBuffer != nil {
			pb.combinedBuffer.Put(packet)
		}
	default:
		if pb.enableCombined && pb.combinedBuffer != nil {
			success = pb.combinedBuffer.Put(packet)
		}
	}

	return success
}

// Get retrieves packets from the specified buffer.
func (pb *PacketBuffer) Get(count int, mode string) [][]byte {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	var buffer *RingBuffer
	switch mode {
	case "up":
		if pb.enableUp {
			buffer = pb.upBuffer
		}
	case "down":
		if pb.enableDown {
			buffer = pb.downBuffer
		}
	case "combined":
		if pb.enableCombined {
			buffer = pb.combinedBuffer
		}
	}

	if buffer == nil {
		return nil
	}

	return buffer.GetBatch(count)
}

// Status returns the buffer status.
func (pb *PacketBuffer) Status() map[string]interface{} {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	status := make(map[string]interface{})

	if pb.enableUp && pb.upBuffer != nil {
		status["up"] = pb.upBuffer.Status()
	}
	if pb.enableDown && pb.downBuffer != nil {
		status["down"] = pb.downBuffer.Status()
	}
	if pb.enableCombined && pb.combinedBuffer != nil {
		status["combined"] = pb.combinedBuffer.Status()
	}

	return status
}

// Close closes all buffers.
func (pb *PacketBuffer) Close() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.upBuffer != nil {
		pb.upBuffer.Close()
	}
	if pb.downBuffer != nil {
		pb.downBuffer.Close()
	}
	if pb.combinedBuffer != nil {
		pb.combinedBuffer.Close()
	}
}

// TokenBucket for rate limiting.
type TokenBucket struct {
	rate      int64 // bytes per second
	burst     int64 // max burst in bytes
	tokens    int64
	lastTime  int64 // nanoseconds
	mu        sync.Mutex
}

// NewTokenBucket creates a new token bucket.
func NewTokenBucket(rate, burst int64) *TokenBucket {
	return &TokenBucket{
		rate:     rate,
		burst:    burst,
		tokens:   burst,
		lastTime: time.Now().UnixNano(),
	}
}

// Allow checks if n bytes can be sent and consumes tokens.
func (tb *TokenBucket) Allow(n int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// rate=0 means no rate limit — always allow
	if tb.rate == 0 {
		return true
	}

	now := time.Now().UnixNano()
	elapsed := now - tb.lastTime
	tb.lastTime = now

	// Add tokens based on elapsed time
	tb.tokens += (elapsed * tb.rate) / int64(time.Second)
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}

// Wait waits until n bytes can be sent.
func (tb *TokenBucket) Wait(ctx context.Context, n int64) error {
	for {
		if tb.Allow(n) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 10):
			// Continue waiting
		}
	}
}

// SetRate updates the rate limit.
func (tb *TokenBucket) SetRate(rate int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.rate = rate
}
