package replay

import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestPacer_TimestampPacer verifies the timestamp pacer sleeps for the capture
// delta between packets, and absorbs drift on a late packet (no catch-up burst).
func TestPacer_TimestampPacer(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx := context.Background()

	// First packet: initializes the origin, no wait.
	pkt0 := core.PacketConfig{Timestamp: time.UnixMicro(0)}
	start := time.Now()
	p.Wait(ctx, pkt0, 0)
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Errorf("first packet waited %v, should be immediate", elapsed)
	}

	// Second packet 50ms later (capture ts): should wait ~50ms.
	pkt1 := core.PacketConfig{Timestamp: time.UnixMicro(50000)}
	start = time.Now()
	p.Wait(ctx, pkt1, 0)
	elapsed := time.Since(start)
	if elapsed < 30*time.Millisecond || elapsed > 80*time.Millisecond {
		t.Errorf("second packet waited %v, want ~50ms", elapsed)
	}
}

// TestPacer_TimestampPacer_DriftAbsorption verifies a late packet (scheduled in
// the past) is sent immediately and shifts the origin (no burst).
func TestPacer_TimestampPacer_DriftAbsorption(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx := context.Background()
	// Initialize with pkt0 at ts=0.
	p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(0)}, 0)
	// Simulate a long delay (so the next packet is "late"): advance the wall
	// clock past the scheduled time by sleeping.
	time.Sleep(50 * time.Millisecond)
	// pkt1 at ts=10us (scheduled ~10us after start, but we're now 50ms past).
	// Should send immediately (drift absorbed), not wait.
	start := time.Now()
	p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(10)}, 0)
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Errorf("late packet waited %v, should be immediate (drift absorbed)", elapsed)
	}
}

// TestPacer_MaxPacer verifies MaxPacer never waits.
func TestPacer_MaxPacer(t *testing.T) {
	p := MaxPacer{}
	start := time.Now()
	p.Wait(context.Background(), core.PacketConfig{}, 100)
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Errorf("MaxPacer waited %v", elapsed)
	}
}

// TestNewPacer_Selection verifies the factory selects the right pacer type.
func TestNewPacer_Selection(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"original", "*replay.TimestampPacer"},
		{"multiplier", "*replay.TimestampPacer"},
		{"bps", "*replay.TokenBucketPacer"},
		// pps removed: falls through to MaxPacer
		{"pps", "replay.MaxPacer"},
		{"max", "replay.MaxPacer"},
		{"", "replay.MaxPacer"},
	}
	for _, tc := range cases {
		p := NewPacer(ReplaySpeed{Mode: tc.mode, Multiplier: 2.0, BPS: "100k", PPS: 100})
		got := typeName(p)
		if got != tc.want {
			t.Errorf("mode %q: got %s, want %s", tc.mode, got, tc.want)
		}
	}
}

// typeName returns the concrete type name of a Pacer (test helper).
func typeName(p Pacer) string {
	switch p.(type) {
	case *TimestampPacer:
		return "*replay.TimestampPacer"
	case *TokenBucketPacer:
		return "*replay.TokenBucketPacer"
	case *PPSPacer:
		return "*replay.PPSPacer"
	case *MaxPacer:
		return "replay.MaxPacer"
	case MaxPacer:
		return "replay.MaxPacer"
	}
	return "unknown"
}
