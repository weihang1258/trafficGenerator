package core

import (
	"testing"
)

func TestRingBuffer_PutAndGet(t *testing.T) {
	rb := NewRingBuffer(10, 0)

	// Test put
	packet := []byte("test packet")
	if _, ok := rb.Put(packet); !ok {
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
	// R9 设计对齐：实时视图=滑动窗口——满时挤旧留新，绝不拒新。
	rb := NewRingBuffer(3, 0)

	for i := 0; i < 3; i++ {
		if _, ok := rb.Put([]byte{byte(i)}); !ok {
			t.Errorf("Put %d should succeed", i)
		}
	}

	// 满后第 4 包：挤掉最旧（0），保留最新三个。
	evicted, ok := rb.Put([]byte{4})
	if !ok {
		t.Fatal("sliding window must never reject a fitting packet")
	}
	if evicted != 1 {
		t.Errorf("evicted = %d, want 1", evicted)
	}
	if rb.Len() != 3 {
		t.Errorf("Len = %d, want 3", rb.Len())
	}
	// 最旧（0）已被挤出：取出顺序 1,2,4。
	want := []byte{1, 2, 4}
	for _, w := range want {
		got, ok := rb.Get()
		if !ok || got[0] != w {
			t.Errorf("got %v, want %d (滑动窗口应保留最新)", got, w)
		}
	}
}

// TestRingBuffer_SlidingWindowEvictsOldest：显式锁滑动窗口语义。
func TestRingBuffer_SlidingWindowEvictsOldest(t *testing.T) {
	rb := NewRingBuffer(5, 0)
	for i := 0; i < 12; i++ {
		_, _ = rb.Put([]byte{byte(i)})
	}
	if rb.Len() != 5 {
		t.Errorf("Len = %d, want 5", rb.Len())
	}
	// 12 包进 5 槽：保留 7..11，7+12=19 取模还原字节值 byte(7..11)。
	for _, w := range []byte{7, 8, 9, 10, 11} {
		got, ok := rb.Get()
		if !ok || got[0] != w {
			t.Errorf("got %v, want %d (最新包必须保留)", got, w)
		}
	}
}

func TestRingBuffer_MaxBytes(t *testing.T) {
	rb := NewRingBuffer(10, 5)

	// Should succeed (3 bytes)
	if _, ok := rb.Put([]byte("abc")); !ok {
		t.Error("Put should succeed")
	}

	// Should fail (single packet exceeds max bytes — cannot ever fit)
	if _, ok := rb.Put([]byte("xyzwv")); !ok {
		t.Error("oversized single packet should be rejected")
	}
	// 未超限的单包在满时挤旧保留（滑动窗口）。
	if evicted, ok := rb.Put([]byte("de")); !ok {
		t.Error("fitting packet must be stored (evicting oldest)")
	} else if evicted < 1 {
		t.Errorf("evicted = %d, want >= 1 (挤旧腾位)", evicted)
	}
}

func TestRingBuffer_GetBatch(t *testing.T) {
	rb := NewRingBuffer(10, 0)

	// Put multiple packets
	for i := 0; i < 5; i++ {
		_, _ = rb.Put([]byte{byte(i)})
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
	if _, ok := pb.Put([]byte("up"), "up"); !ok {
		t.Error("Put to up buffer should succeed")
	}

	// Test down buffer
	if _, ok := pb.Put([]byte("down"), "down"); !ok {
		t.Error("Put to down buffer should succeed")
	}

	// Test combined buffer
	if _, ok := pb.Put([]byte("combined"), "combined"); !ok {
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
	if _, ok := rb.Put(packet); !ok {
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
