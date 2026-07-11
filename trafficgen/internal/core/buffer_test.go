package core

import (
	"testing"
)

func TestRingBuffer_PutAndGet(t *testing.T) {
	rb := NewRingBuffer(10, 0)

	// Test put
	packet := []byte("test packet")
	if !rb.Put(packet) {
		t.Error("Put should succeed")
	}

	// Test get
	got, ok := rb.Get()
	if !ok {
		t.Error("Get should succeed")
	}
	if string(got) != "test packet" {
		t.Errorf("Got %s, want test packet", string(got))
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	rb := NewRingBuffer(3, 0)

	// Fill buffer
	for i := 0; i < 3; i++ {
		if !rb.Put([]byte{byte(i)}) {
			t.Errorf("Put %d should succeed", i)
		}
	}

	// Next put should fail
	if rb.Put([]byte{4}) {
		t.Error("Put should fail when buffer is full")
	}

	// Check length
	if rb.Len() != 3 {
		t.Errorf("Len = %d, want 3", rb.Len())
	}
}

func TestRingBuffer_MaxBytes(t *testing.T) {
	rb := NewRingBuffer(10, 5)

	// Should succeed (3 bytes)
	if !rb.Put([]byte("abc")) {
		t.Error("Put should succeed")
	}

	// Should fail (would exceed max bytes)
	if rb.Put([]byte("xyz")) {
		t.Error("Put should fail when max bytes exceeded")
	}
}

func TestRingBuffer_GetBatch(t *testing.T) {
	rb := NewRingBuffer(10, 0)

	// Put multiple packets
	for i := 0; i < 5; i++ {
		rb.Put([]byte{byte(i)})
	}

	// Get batch
	packets := rb.GetBatch(3)
	if len(packets) != 3 {
		t.Errorf("Got %d packets, want 3", len(packets))
	}

	// Check remaining
	if rb.Len() != 2 {
		t.Errorf("Len = %d, want 2", rb.Len())
	}
}

func TestPacketBuffer(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{
		Size:           10,
		MaxBytes:       0,
		EnableUp:       true,
		EnableDown:     true,
		EnableCombined: true,
	})

	// Test up buffer
	if !pb.Put([]byte("up"), "up") {
		t.Error("Put to up buffer should succeed")
	}

	// Test down buffer
	if !pb.Put([]byte("down"), "down") {
		t.Error("Put to down buffer should succeed")
	}

	// Test combined buffer
	if !pb.Put([]byte("combined"), "combined") {
		t.Error("Put to combined buffer should succeed")
	}

	// Get from buffers
	upPackets := pb.Get(10, "up")
	if len(upPackets) != 1 {
		t.Errorf("Up buffer has %d packets, want 1", len(upPackets))
	}

	downPackets := pb.Get(10, "down")
	if len(downPackets) != 1 {
		t.Errorf("Down buffer has %d packets, want 1", len(downPackets))
	}

	combinedPackets := pb.Get(10, "combined")
	if len(combinedPackets) != 3 {
		t.Errorf("Combined buffer has %d packets, want 3", len(combinedPackets))
	}
}

func TestTokenBucket(t *testing.T) {
	tb := NewTokenBucket(1000, 100) // 1000 bytes/sec, burst 100

	// Should allow burst
	if !tb.Allow(100) {
		t.Error("Should allow burst")
	}

	// Should fail (burst exhausted)
	if tb.Allow(1) {
		t.Error("Should not allow after burst exhausted")
	}
}

func TestTokenBucket_RateLimit(t *testing.T) {
	tb := NewTokenBucket(1000, 10) // 1000 bytes/sec, burst 10

	// Use burst
	if !tb.Allow(10) {
		t.Error("Should allow burst")
	}

	// Set higher rate
	tb.SetRate(1000000)

	// Wait a bit for tokens to accumulate
	// In real test, we'd use time.Sleep or mocking
}

// TestRingBuffer_PutHoldsReference verifies Put stores the original slice
// reference (no per-packet make+copy). After the optimization, Get returns a
// slice sharing the same underlying array as the one passed to Put.
func TestRingBuffer_PutHoldsReference(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	packet := []byte("hello world packet data xyz")
	if !rb.Put(packet) {
		t.Fatal("Put failed")
	}
	got, ok := rb.Get()
	if !ok {
		t.Fatal("Get failed")
	}
	if string(got) != string(packet) {
		t.Errorf("content = %q, want %q", got, packet)
	}
	if len(got) == 0 || len(packet) == 0 || &got[0] != &packet[0] {
		t.Error("Put copied the slice; expected to hold the original reference (no copy)")
	}
}
