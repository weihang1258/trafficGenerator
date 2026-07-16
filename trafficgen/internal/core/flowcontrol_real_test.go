package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

// These are REAL behavior tests for flow control: they drive the actual
// builder (NewBuilder().Build, real Ethernet+IP+TCP frames) and measure
// observed throughput at the output writer. They are NOT mock/structural
// tests -- a regression that breaks rate enforcement fails these by producing
// the wrong measured bytes/sec, not by failing an internal assertion.

// countingWriter is a PacketWriter that counts bytes/packets written and
// records the first/last write wall-clock times so the test can compute the
// observed output rate.
type countingWriter struct {
	mu         sync.Mutex
	bytes      int64
	packets    int64
	firstWrite time.Time
	lastWrite  time.Time
}

func (w *countingWriter) WritePackets(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.firstWrite.IsZero() {
		w.firstWrite = now
	}
	w.lastWrite = now
	for _, p := range packets {
		w.bytes += int64(len(p))
		w.packets++
	}
	return nil
}

func (w *countingWriter) Close() error { return nil }

func (w *countingWriter) Bytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes
}

func (w *countingWriter) Packets() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packets
}

func (w *countingWriter) Span() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastWrite.IsZero() {
		return 0
	}
	return w.lastWrite.Sub(w.firstWrite)
}

// realFramePlanner yields perFlow packet configs with real L2/L3/L4 headers
// and a fixed payload, so NewBuilder().Build produces real frames of a known
// size. Used to drive measurable throughput through the rate limiter.
type realFramePlanner struct {
	name    string
	perFlow int
	payload int
}

func (p *realFramePlanner) Name() string                 { return p.name }
func (p *realFramePlanner) Validate(spec FlowSpec) error { return nil }
func (p *realFramePlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, 256)
	go func() {
		defer close(ch)
		for i := 0; i < p.perFlow; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- PacketConfig{
				FlowID: "f", PacketIndex: uint64(i),
				L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
				L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
				L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: uint32(i), Flags: 0x10},
				Payload: make([]byte, p.payload),
			}:
			}
		}
	}()
	return ch, nil
}

// R1: A per-strategy (child) bps bucket must actually limit the MEASURED
// output rate, not just exist in the rateLimiter map. Drives 2000 real frames
// (payload=500 -> ~554B each, ~1.1MB total) through an 8 Mbps bucket (~1 MB/s).
// Expected runtime ~1.1s; without rate limiting the mock-instant writer would
// finish in milliseconds.
func TestRateLimit_ChildBucketEnforcesMeasuredBPS(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 8192, QueueSize: 256,
	})
	e.RegisterPlanner(&realFramePlanner{name: "tcp", perFlow: 2000, payload: 500})
	e.SetBuildFunc(NewBuilder().Build)
	cw := &countingWriter{}
	e.RegisterOutputWriter("r1-task", cw)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	const configuredBPS = 8e6 // 8 Mbps = 1 MB/s
	task := Task{
		ID: "r1-task", Name: "rate", Protocol: "tcp", ClassID: "r1-task",
		Spec: FlowSpec{BPS: "8M", Count: 1},
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "r1-task", 15*time.Second)
	elapsed := time.Since(start)

	totalPackets := cw.Packets()
	if totalPackets != 2000 {
		t.Fatalf("packets written = %d, want 2000", totalPackets)
	}
	totalBytes := cw.Bytes()
	span := cw.Span()
	if span <= 0 {
		t.Fatalf("no write span recorded")
	}
	measuredBPS := float64(totalBytes) / span.Seconds() * 8
	t.Logf("R1: %d packets, %d bytes, span=%v, measured=%.0f bps, configured=%.0f bps",
		totalPackets, totalBytes, span, measuredBPS, configuredBPS)

	// The rate limiter must bound the output. Allow headroom for the 64KB
	// burst (flushes instantly) and scheduling jitter.
	if measuredBPS > configuredBPS*1.8 {
		t.Errorf("measured bps=%.0f exceeds configured %.0f (x1.8): rate limit NOT enforced", measuredBPS, configuredBPS)
	}
	// And it must have actually slowed the output (no-limit case finishes in
	// single-digit milliseconds for an instant writer).
	if elapsed < 400*time.Millisecond {
		t.Errorf("elapsed=%v too fast: rate limit did not slow output (measured=%.0f bps)", elapsed, measuredBPS)
	}
}

// R2: The task-level parent bucket must cap the AGGREGATE rate across multiple
// strategies (double-layer: child bucket applied first, then parent). Three
// strategies each with a permissive 100 Mbps child bucket but an 8 Mbps parent
// ceiling must together emit at ~8 Mbps, not ~300 Mbps. If the parent bucket
// were not applied in the double-layer path, the aggregate would be bounded
// only by the child buckets and finish in tens of milliseconds.
func TestRateLimit_ParentBucketCapsAggregateBPS(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 8192, QueueSize: 256,
	})
	e.RegisterPlanner(&realFramePlanner{name: "tcp", perFlow: 500, payload: 500})
	e.SetBuildFunc(NewBuilder().Build)
	cw := &countingWriter{}
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	const configuredParentBPS = 8e6 // 8 Mbps aggregate ceiling
	parentID := "r2-parent"
	// Three strategies sharing one parent. Each child bucket is permissive
	// (100 Mbps) so the parent is the binding constraint.
	for _, s := range []string{"A", "B", "C"} {
		tid := "r2-" + s
		e.RegisterOutputWriter(tid, cw) // shared writer -> aggregate byte count
		task := Task{
			ID: tid, Name: "strat-" + s, Protocol: "tcp", ClassID: tid,
			ParentTaskID: parentID,
			Spec:         FlowSpec{BPS: "100M", Count: 1},
			TaskFCType:   "bps",
			TaskFCValue:  configuredParentBPS,
		}
		if err := e.SubmitTask(task); err != nil {
			t.Fatalf("submit %s: %v", s, err)
		}
	}

	start := time.Now()
	for _, s := range []string{"A", "B", "C"} {
		waitTaskDone(t, e, "r2-"+s, 15*time.Second)
	}
	elapsed := time.Since(start)

	totalPackets := cw.Packets()
	if totalPackets != 1500 { // 3 * 500
		t.Fatalf("packets written = %d, want 1500", totalPackets)
	}
	totalBytes := cw.Bytes()
	span := cw.Span()
	measuredBPS := float64(totalBytes) / span.Seconds() * 8
	t.Logf("R2: %d packets, %d bytes, span=%v, measured=%.0f bps, parent ceiling=%.0f bps",
		totalPackets, totalBytes, span, measuredBPS, configuredParentBPS)

	if measuredBPS > configuredParentBPS*1.8 {
		t.Errorf("aggregate measured bps=%.0f exceeds parent ceiling %.0f (x1.8): parent bucket NOT enforced in double-layer path", measuredBPS, configuredParentBPS)
	}
	if elapsed < 400*time.Millisecond {
		t.Errorf("elapsed=%v too fast: parent ceiling did not cap aggregate (child-only would finish in tens of ms)", elapsed)
	}
	// Sanity: the shared writer saw all three strategies' packets.
	if got := cw.Packets(); got != 1500 {
		t.Errorf("shared writer packets = %d, want 1500", got)
	}
}
