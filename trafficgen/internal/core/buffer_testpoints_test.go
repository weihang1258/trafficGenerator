package core

// Test points for buffer.go (RB1-RB34, PB1-PB28, TB1-TB18, CONC4, CONC5) from
// tools/test_points/engine_core.md. Adds uncovered branches. Same-package tests
// can access unexported fields (rb.buffer/head/tail, tb.tokens/lastTime, etc.)
// and can nil individual ring buffers to exercise nil-guard branches.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- RingBuffer: NewRingBuffer ---

func TestNewRingBuffer_Normal(t *testing.T) {
	rb := NewRingBuffer(1024, 0)
	if rb.size != 1024 {
		t.Errorf("size=%d want 1024", rb.size)
	}
	if rb.maxBytes != 0 {
		t.Errorf("maxBytes=%d want 0", rb.maxBytes)
	}
	if rb.Len() != 0 {
		t.Errorf("Len=%d want 0", rb.Len())
	}
}

func TestNewRingBuffer_SizeZero(t *testing.T) {
	rb := NewRingBuffer(0, 0)
	// count(0) >= size(0) -> Put always false.
	if rb.Put([]byte("x")) {
		t.Error("size=0 Put should return false (0>=0)")
	}
}

func TestNewRingBuffer_SizeNegative_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for size=-1 (make([][]byte,-1))")
		}
	}()
	NewRingBuffer(-1, 0)
}

// --- RingBuffer: Put ---

func TestPut_Closed(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Close()
	if rb.Put([]byte("x")) {
		t.Error("Put after Close should return false")
	}
}

func TestPut_MaxBytesZero_NoLimit(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	big := make([]byte, 1000)
	if !rb.Put(big) {
		t.Error("maxBytes=0 should impose no byte limit")
	}
}

func TestPut_ExactlyFills_WrapsTail(t *testing.T) {
	rb := NewRingBuffer(3, 0)
	for i := 0; i < 3; i++ {
		if !rb.Put([]byte{byte(i)}) {
			t.Errorf("Put %d should succeed", i)
		}
	}
	// tail wrapped to 0; 4th Put must fail (full).
	if rb.Put([]byte{4}) {
		t.Error("Put on full buffer should fail")
	}
	if rb.tail != 0 {
		t.Errorf("tail=%d want 0 (wrapped)", rb.tail)
	}
}

func TestPut_NilPacket(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	if !rb.Put(nil) {
		t.Error("Put(nil) should succeed (count increments)")
	}
	if rb.Len() != 1 {
		t.Errorf("Len=%d want 1", rb.Len())
	}
	if rb.Bytes() != 0 {
		t.Errorf("Bytes=%d want 0 (len(nil)==0)", rb.Bytes())
	}
}

func TestPut_ConcurrentSafe(t *testing.T) {
	const workers, perWorker = 100, 100
	rb := NewRingBuffer(workers, 0) // small buffer -> many drops
	var success int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < perWorker; j++ {
				if rb.Put([]byte{1}) {
					atomic.AddInt64(&success, 1)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	// Conservation: successful puts can never exceed buffer size (bounded buffer).
	if success > int64(workers) {
		t.Errorf("success=%d exceeds buffer size %d", success, workers)
	}
	if success < 0 {
		t.Errorf("success=%d negative", success)
	}
}

// --- RingBuffer: Get ---

func TestGet_Closed(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Put([]byte("x"))
	rb.Close()
	if _, ok := rb.Get(); ok {
		t.Error("Get after Close should return false")
	}
}

func TestGet_Empty(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	if _, ok := rb.Get(); ok {
		t.Error("Get on empty buffer should return false")
	}
}

func TestGet_WrapAround(t *testing.T) {
	rb := NewRingBuffer(3, 0)
	rb.Put([]byte("a"))
	rb.Put([]byte("b"))
	rb.Get()            // head -> 1
	rb.Put([]byte("c")) // tail wraps to 0
	rb.Put([]byte("d")) // tail -> 1? 3 slots: indices 0,1,2. After Put a,b: tail=2. Get: head=1. Put c: buffer[2]=c, tail=0. Put d: buffer[0]=d, tail=1. count=3.
	// Now head=1: b,c,d
	got, ok := rb.Get()
	if !ok || string(got) != "b" {
		t.Errorf("Get after wrap = %q ok=%v, want b", got, ok)
	}
}

func TestGet_SlotFreedForGC(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Put([]byte("x"))
	rb.Get()
	// Same-package: head slot should be nil after Get (frees reference for GC).
	if rb.buffer[rb.head] != nil {
		t.Error("slot at head not nil after Get (reference not released)")
	}
}

// --- RingBuffer: GetBatch ---

func TestGetBatch_Closed(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Put([]byte("x"))
	rb.Close()
	if pkts := rb.GetBatch(1); pkts != nil {
		t.Errorf("GetBatch after Close = %v, want nil", pkts)
	}
}

func TestGetBatch_Empty(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	if pkts := rb.GetBatch(3); pkts != nil {
		t.Errorf("GetBatch on empty = %v, want nil", pkts)
	}
}

func TestGetBatch_MaxGreaterThanCount(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Put([]byte("a"))
	rb.Put([]byte("b"))
	rb.Put([]byte("c"))
	if pkts := rb.GetBatch(10); len(pkts) != 3 {
		t.Errorf("GetBatch(10) with 3 items = %d, want 3 (capped)", len(pkts))
	}
}

func TestGetBatch_MaxEqualsCount(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	for i := 0; i < 3; i++ {
		rb.Put([]byte{byte(i)})
	}
	if pkts := rb.GetBatch(3); len(pkts) != 3 {
		t.Errorf("GetBatch(3) = %d, want 3", len(pkts))
	}
}

func TestGetBatch_MaxZero(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	for i := 0; i < 3; i++ {
		rb.Put([]byte{byte(i)})
	}
	if pkts := rb.GetBatch(0); len(pkts) != 0 {
		t.Errorf("GetBatch(0) = %d, want 0", len(pkts))
	}
	// Buffer still full (nothing consumed).
	if rb.Len() != 3 {
		t.Errorf("Len after GetBatch(0) = %d, want 3", rb.Len())
	}
}

func TestGetBatch_NegativeNonEmpty_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for GetBatch(-1) on non-empty buffer (make slice negative)")
		}
	}()
	rb := NewRingBuffer(10, 0)
	rb.Put([]byte("x"))
	rb.GetBatch(-1)
}

func TestGetBatch_NegativeEmpty_NoPanic(t *testing.T) {
	// Empty buffer returns nil early before make -> no panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetBatch(-1) on empty buffer panicked: %v", r)
		}
	}()
	rb := NewRingBuffer(10, 0)
	if pkts := rb.GetBatch(-1); pkts != nil {
		t.Errorf("GetBatch(-1) on empty = %v, want nil", pkts)
	}
}

func TestGetBatch_WrapAround(t *testing.T) {
	rb := NewRingBuffer(3, 0)
	rb.Put([]byte("a"))
	rb.Put([]byte("b"))
	rb.Get() // head -> 1
	rb.Put([]byte("c"))
	rb.Put([]byte("d")) // tail wrapped
	// head=1: b,c,d. GetBatch(3) crosses the wrap.
	pkts := rb.GetBatch(3)
	if len(pkts) != 3 {
		t.Fatalf("GetBatch(3) = %d items, want 3", len(pkts))
	}
	want := []string{"b", "c", "d"}
	for i, w := range want {
		if string(pkts[i]) != w {
			t.Errorf("pkts[%d] = %q, want %q", i, pkts[i], w)
		}
	}
}

func TestGetBatch_ConcurrentSafe(t *testing.T) {
	const producers, consumers, perProducer = 4, 4, 1000
	rb := NewRingBuffer(50, 0) // small -> forces drops
	var success, got int64
	var pwg sync.WaitGroup
	producersDone := make(chan struct{})
	for i := 0; i < producers; i++ {
		pwg.Add(1)
		go func(id int) {
			defer pwg.Done()
			for j := 0; j < perProducer; j++ {
				if rb.Put([]byte{byte(id), byte(j)}) {
					atomic.AddInt64(&success, 1)
				}
			}
		}(i)
	}
	go func() { pwg.Wait(); close(producersDone) }()

	var cwg sync.WaitGroup
	for i := 0; i < consumers; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			for {
				_, ok := rb.Get()
				if ok {
					atomic.AddInt64(&got, 1)
					continue
				}
				select {
				case <-producersDone:
					if rb.Len() == 0 {
						return
					}
				default:
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	cwg.Wait()
	// Conservation: every successful put is eventually consumed.
	if success != got {
		t.Errorf("conservation broken: successful puts=%d, consumed=%d", success, got)
	}
}

// --- RingBuffer: Len/Bytes/IsFull/Status/Close ---

func TestLen_Empty(t *testing.T) {
	if rb := NewRingBuffer(10, 0); rb.Len() != 0 {
		t.Errorf("Len=%d want 0", rb.Len())
	}
}

func TestLen_500(t *testing.T) {
	rb := NewRingBuffer(1000, 0)
	for i := 0; i < 500; i++ {
		rb.Put([]byte{byte(i)})
	}
	if rb.Len() != 500 {
		t.Errorf("Len=%d want 500", rb.Len())
	}
}

func TestBytes_Empty(t *testing.T) {
	if rb := NewRingBuffer(10, 0); rb.Bytes() != 0 {
		t.Errorf("Bytes=%d want 0", rb.Bytes())
	}
}

func TestBytes_1000(t *testing.T) {
	rb := NewRingBuffer(100, 0)
	rb.Put(make([]byte, 400))
	rb.Put(make([]byte, 600))
	if rb.Bytes() != 1000 {
		t.Errorf("Bytes=%d want 1000", rb.Bytes())
	}
}

func TestIsFull_Empty(t *testing.T) {
	if rb := NewRingBuffer(10, 0); rb.IsFull() {
		t.Error("empty buffer should not be full")
	}
}

func TestIsFull_Full(t *testing.T) {
	rb := NewRingBuffer(3, 0)
	for i := 0; i < 3; i++ {
		rb.Put([]byte{byte(i)})
	}
	if !rb.IsFull() {
		t.Error("full buffer should report full")
	}
}

func TestStatus_Normal(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	for i := 0; i < 5; i++ {
		rb.Put([]byte{byte(i)})
	}
	s := rb.Status()
	if s["count"].(int) != 5 {
		t.Errorf("count=%v want 5", s["count"])
	}
	if s["size"].(int) != 10 {
		t.Errorf("size=%v want 10", s["size"])
	}
	if s["full"].(bool) {
		t.Error("5/10 should not be full")
	}
}

func TestClose_Open(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Close()
	if !rb.closed.Load() {
		t.Error("closed flag not set after Close")
	}
	if rb.Put([]byte("x")) {
		t.Error("Put should fail after Close")
	}
}

func TestClose_AlreadyClosed(t *testing.T) {
	rb := NewRingBuffer(10, 0)
	rb.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("double Close panicked: %v", r)
		}
	}()
	rb.Close() // no-op
}

// --- PacketBuffer: NewPacketBuffer ---

func TestNewPacketBuffer_AllEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	if pb.upBuffer == nil || pb.downBuffer == nil || pb.combinedBuffer == nil {
		t.Errorf("all enabled: up=%v down=%v combined=%v, want all non-nil",
			pb.upBuffer, pb.downBuffer, pb.combinedBuffer)
	}
}

func TestNewPacketBuffer_UpDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableDown: true, EnableCombined: true})
	if pb.upBuffer != nil {
		t.Error("upBuffer should be nil when EnableUp=false")
	}
	if pb.downBuffer == nil || pb.combinedBuffer == nil {
		t.Error("down/combined should be non-nil")
	}
}

func TestNewPacketBuffer_DownDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	if pb.downBuffer != nil {
		t.Error("downBuffer should be nil when EnableDown=false")
	}
}

func TestNewPacketBuffer_CombinedDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true})
	if pb.combinedBuffer != nil {
		t.Error("combinedBuffer should be nil when EnableCombined=false")
	}
}

func TestNewPacketBuffer_AllDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10})
	if pb.upBuffer != nil || pb.downBuffer != nil || pb.combinedBuffer != nil {
		t.Errorf("all disabled: buffers should all be nil")
	}
}

// --- PacketBuffer: Put ---

func TestPut_UpAllEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	if !pb.Put([]byte("x"), "up") {
		t.Error("Put up should succeed (up enabled)")
	}
	if pb.upBuffer.Len() != 1 || pb.combinedBuffer.Len() != 1 {
		t.Errorf("up=%d combined=%d, want 1/1", pb.upBuffer.Len(), pb.combinedBuffer.Len())
	}
}

func TestPut_DownAllEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	if !pb.Put([]byte("x"), "down") {
		t.Error("Put down should succeed")
	}
	if pb.downBuffer.Len() != 1 || pb.combinedBuffer.Len() != 1 {
		t.Errorf("down=%d combined=%d, want 1/1", pb.downBuffer.Len(), pb.combinedBuffer.Len())
	}
}

func TestPut_DefaultDirection(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	if !pb.Put([]byte("x"), "default") {
		t.Error("Put default should succeed (combined)")
	}
	if pb.combinedBuffer.Len() != 1 {
		t.Errorf("combined=%d want 1", pb.combinedBuffer.Len())
	}
	if pb.upBuffer.Len() != 0 || pb.downBuffer.Len() != 0 {
		t.Error("up/down should not receive default direction")
	}
}

func TestPut_UpDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableDown: true, EnableCombined: true})
	// up disabled -> success tracks up (false), but combined still receives.
	if pb.Put([]byte("x"), "up") {
		t.Error("Put up with up disabled should return false (success tracks up)")
	}
	if pb.combinedBuffer.Len() != 1 {
		t.Errorf("combined should still receive: %d want 1", pb.combinedBuffer.Len())
	}
}

func TestPut_DownDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	if pb.Put([]byte("x"), "down") {
		t.Error("Put down with down disabled should return false")
	}
	if pb.combinedBuffer.Len() != 1 {
		t.Errorf("combined should still receive: %d want 1", pb.combinedBuffer.Len())
	}
}

func TestPut_UpCombinedDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true})
	if !pb.Put([]byte("x"), "up") {
		t.Error("Put up (combined disabled) should return true (up succeeded)")
	}
	if pb.upBuffer.Len() != 1 {
		t.Errorf("up=%d want 1", pb.upBuffer.Len())
	}
}

func TestPut_DefaultCombinedDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true})
	if pb.Put([]byte("x"), "default") {
		t.Error("Put default with combined disabled should return false (nothing to write)")
	}
}

func TestPut_UpNilBuffer(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	pb.upBuffer = nil // same-package: simulate nil up buffer despite enableUp
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Put up with nil upBuffer panicked: %v", r)
		}
	}()
	pb.Put([]byte("x"), "up") // nil check skips up; combined still receives
	if pb.combinedBuffer.Len() != 1 {
		t.Errorf("combined=%d want 1", pb.combinedBuffer.Len())
	}
}

func TestPut_UpBufferFull(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	pb.upBuffer = NewRingBuffer(1, 0) // up fills after 1
	pb.combinedBuffer = NewRingBuffer(10, 0)
	pb.Put([]byte("a"), "up") // fills up
	if pb.Put([]byte("b"), "up") {
		t.Error("Put up with up full should return false (tracks primary up)")
	}
	if pb.upBuffer.Len() != 1 {
		t.Errorf("up=%d want 1", pb.upBuffer.Len())
	}
	if pb.combinedBuffer.Len() != 2 {
		t.Errorf("combined=%d want 2 (both puts reach combined)", pb.combinedBuffer.Len())
	}
}

func TestPut_UpSucceedsCombinedFails(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	pb.upBuffer = NewRingBuffer(10, 0)
	pb.combinedBuffer = NewRingBuffer(1, 0) // combined fills after 1
	pb.Put([]byte("a"), "combined")         // fill combined via default
	// Now Put up: up succeeds, combined full -> combined.Put false (ignored).
	if !pb.Put([]byte("b"), "up") {
		t.Error("Put up should return true (success tracks primary up even if combined fails)")
	}
	if pb.upBuffer.Len() != 1 {
		t.Errorf("up=%d want 1", pb.upBuffer.Len())
	}
}

// --- PacketBuffer: Get ---

func TestGet_UpEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableCombined: true})
	pb.Put([]byte("x"), "up")
	if pkts := pb.Get(10, "up"); len(pkts) != 1 {
		t.Errorf("Get up = %d, want 1", len(pkts))
	}
}

func TestGet_DownEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableDown: true, EnableCombined: true})
	pb.Put([]byte("x"), "down")
	if pkts := pb.Get(10, "down"); len(pkts) != 1 {
		t.Errorf("Get down = %d, want 1", len(pkts))
	}
}

func TestGet_CombinedEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableCombined: true})
	pb.Put([]byte("x"), "combined")
	if pkts := pb.Get(10, "combined"); len(pkts) != 1 {
		t.Errorf("Get combined = %d, want 1", len(pkts))
	}
}

func TestGet_UpDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableCombined: true})
	if pkts := pb.Get(10, "up"); pkts != nil {
		t.Errorf("Get up with up disabled = %v, want nil", pkts)
	}
}

func TestGet_UnknownMode(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableCombined: true})
	pb.Put([]byte("x"), "combined")
	if pkts := pb.Get(10, "xyz"); pkts != nil {
		t.Errorf("Get unknown mode = %v, want nil", pkts)
	}
}

func TestGet_BufferEmpty(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true})
	if pkts := pb.Get(10, "up"); pkts != nil {
		t.Errorf("Get empty up = %v, want nil", pkts)
	}
}

// --- PacketBuffer: Status ---

func TestStatus_AllEnabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	s := pb.Status()
	if _, ok := s["up"]; !ok {
		t.Error("status missing up key")
	}
	if _, ok := s["down"]; !ok {
		t.Error("status missing down key")
	}
	if _, ok := s["combined"]; !ok {
		t.Error("status missing combined key")
	}
}

func TestStatus_UpDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableDown: true, EnableCombined: true})
	s := pb.Status()
	if _, ok := s["up"]; ok {
		t.Error("status should not contain up when disabled")
	}
	if _, ok := s["down"]; !ok {
		t.Error("status should contain down")
	}
}

func TestStatus_AllDisabled(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10})
	s := pb.Status()
	if len(s) != 0 {
		t.Errorf("all disabled status = %v, want empty map", s)
	}
}

// --- PacketBuffer: Close ---

func TestClose_AllExist(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true, EnableCombined: true})
	pb.Close()
	if pb.upBuffer.Put([]byte("x")) {
		t.Error("upBuffer should be closed")
	}
	if pb.downBuffer.Put([]byte("x")) {
		t.Error("downBuffer should be closed")
	}
	if pb.combinedBuffer.Put([]byte("x")) {
		t.Error("combinedBuffer should be closed")
	}
}

func TestClose_NilUp(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableDown: true, EnableCombined: true})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close with nil upBuffer panicked: %v", r)
		}
	}()
	pb.Close()
}

func TestClose_NilCombined(t *testing.T) {
	pb := NewPacketBuffer(PacketBufferConfig{Size: 10, EnableUp: true, EnableDown: true})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close with nil combinedBuffer panicked: %v", r)
		}
	}()
	pb.Close()
}

// --- TokenBucket ---

func TestNewTokenBucket_Normal(t *testing.T) {
	tb := NewTokenBucket(1000, 65536)
	if tb.tokens != 65536 {
		t.Errorf("tokens=%d want 65536 (initial burst)", tb.tokens)
	}
	if tb.lastTime == 0 {
		t.Error("lastTime=0, want non-zero (now)")
	}
	if tb.rate != 1000 || tb.burst != 65536 {
		t.Errorf("rate=%d burst=%d want 1000/65536", tb.rate, tb.burst)
	}
}

func TestNewTokenBucket_RateZero(t *testing.T) {
	tb := NewTokenBucket(0, 100)
	if tb.rate != 0 {
		t.Errorf("rate=%d want 0 (unlimited semantics)", tb.rate)
	}
}

func TestAllow_RateZero_AlwaysTrue(t *testing.T) {
	tb := NewTokenBucket(0, 100)
	for _, n := range []int64{0, 1, 50, 100, 1000000} {
		if !tb.Allow(n) {
			t.Errorf("rate=0 Allow(%d) = false, want true (unlimited)", n)
		}
	}
}

func TestAllow_TokensCappedToBurst(t *testing.T) {
	// rate=1 keeps elapsed*rate within int64 even when lastTime=1 (far past).
	tb := NewTokenBucket(1, 100)
	tb.mu.Lock()
	tb.lastTime = 1
	tb.mu.Unlock()
	tb.Allow(0) // refill, no consume
	if tb.tokens > tb.burst {
		t.Errorf("tokens=%d exceeds burst=%d (not capped)", tb.tokens, tb.burst)
	}
	if tb.tokens < 0 {
		t.Errorf("tokens=%d negative (overflow)", tb.tokens)
	}
}

func TestAllow_FirstCallAfterIdle_Capped(t *testing.T) {
	// rate=1 to avoid the TB12 known overflow.
	tb := NewTokenBucket(1, 100)
	tb.mu.Lock()
	tb.lastTime = 1
	tb.mu.Unlock()
	if !tb.Allow(10) {
		t.Error("Allow(10) after idle should succeed (capped to burst)")
	}
	if tb.tokens != 90 {
		t.Errorf("tokens=%d want 90 (burst 100 - 10 consumed)", tb.tokens)
	}
}

func TestAllow_NZero(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	if !tb.Allow(0) {
		t.Error("Allow(0) should return true (tokens>=0)")
	}
}

func TestAllow_NGreaterThanBurst_FromEmpty(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	tb.Allow(100) // drain to 0
	if tb.Allow(200) {
		t.Error("Allow(200) from empty with burst=100 should be false (n>burst never satisfiable)")
	}
}

func TestAllow_NGreaterThanBurst_Full(t *testing.T) {
	tb := NewTokenBucket(1000, 100) // tokens=100 (full)
	if tb.Allow(150) {
		t.Error("Allow(150) with burst=100 should be false even when full (100<150)")
	}
}

func TestAllow_NegativeElapsed(t *testing.T) {
	// Clock skew: lastTime in the future -> negative elapsed -> tokens decrease.
	// Use 60s skew so the negative refill dominates the small noise between
	// test-time and Allow-time (a few microseconds → ~0.06 bytes of refill).
	// Allow returned false (verified by the `if tb.Allow(1)` check) means
	// tokens went negative or near-zero, confirming the negative-elapsed
	// behaviour. We don't pin exact tokens value because it depends on the
	// precise nanosecond delta between the two time.Now() calls.
	tb := NewTokenBucket(1000, 1000)
	tb.mu.Lock()
	tb.lastTime = time.Now().UnixNano() + int64(60*time.Second) // 60s in the future
	tb.mu.Unlock()
	if tb.Allow(1) {
		t.Error("Allow(1) after clock skew should be false (tokens reduced well below 1)")
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens >= 1 {
		t.Errorf("tokens=%d >= 1 after negative-elapsed refill (Allow should fail)", tb.tokens)
	}
}

func TestAllow_LargeElapsedOverflow(t *testing.T) {
	// Known potential bug: elapsed*rate can overflow int64 for huge elapsed/rate.
	// Assert no panic (int64 wrap is defined, not a panic); value is undefined.
	tb := NewTokenBucket(1000, 1000)
	tb.mu.Lock()
	tb.lastTime = 1            // ~1970 -> elapsed ~now (huge ns)
	tb.rate = int64(1) << 62   // huge rate to force elapsed*rate overflow
	tb.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Allow panicked on large elapsed*rate overflow: %v", r)
		}
	}()
	_ = tb.Allow(1) // no panic; value undefined due to overflow (documented known issue)
	// Value assertion intentionally omitted: overflow makes the result non-meaningful.
}

func TestWait_Normal(t *testing.T) {
	tb := NewTokenBucket(1_000_000, 10) // fast refill
	tb.Allow(10)                        // drain
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tb.Wait(ctx, 5); err != nil {
		t.Errorf("Wait(5) = %v, want nil (refills quickly)", err)
	}
}

func TestWait_AllowImmediate(t *testing.T) {
	tb := NewTokenBucket(1000, 1000) // tokens=1000 (full)
	if err := tb.Wait(context.Background(), 10); err != nil {
		t.Errorf("Wait(10) with full tokens = %v, want nil (immediate)", err)
	}
}

func TestWait_CtxCancelled(t *testing.T) {
	tb := NewTokenBucket(1000, 10)
	tb.Allow(10) // drain
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Wait
	if err := tb.Wait(ctx, 5); err == nil {
		t.Error("Wait with cancelled ctx = nil, want ctx.Err()")
	}
}

func TestWait_PollingLoop(t *testing.T) {
	tb := NewTokenBucket(1000, 10) // 1000 B/s
	tb.Allow(10)                   // drain
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Wait(5): needs 5 bytes; at 1000 B/s that's ~5ms; polls every 10ms.
	if err := tb.Wait(ctx, 5); err != nil {
		t.Errorf("Wait(5) via polling = %v, want nil", err)
	}
}

func TestSetRate_Zero(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	tb.SetRate(0)
	if tb.rate != 0 {
		t.Errorf("rate=%d want 0 (disables limiting)", tb.rate)
	}
	// rate=0 -> Allow always true.
	if !tb.Allow(1000000) {
		t.Error("Allow after SetRate(0) should always be true")
	}
}

// --- Concurrent Close (CONC5) ---

func TestRingBuffer_ConcurrentClose(t *testing.T) {
	rb := NewRingBuffer(100, 0)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				rb.Put([]byte{1})
				rb.Get()
			}
		}()
	}
	close(start)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		time.Sleep(time.Millisecond)
		rb.Close()
	}()
	wg.Wait()
	// After Close, Put must return false.
	if rb.Put([]byte{1}) {
		t.Error("Put after concurrent Close should return false")
	}
}
