package replay

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// This file covers pacing.go and flowscaling.go test points not already
// covered by pacing_test.go, pacer_race_test.go, audit_fixes_test.go, and
// flowscaling_test.go. It focuses on field-value assertions, failure paths,
// and the cross-worker aggregate-rate guarantee for PPSPacer (PA36).

// ---------------------------------------------------------------------------
// NewPacer factory: field-value assertions via type assertion (PA1-PA9).
// ---------------------------------------------------------------------------

func TestNewPacer_Original(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "original"})
	tp, ok := p.(*TimestampPacer)
	if !ok {
		t.Fatalf("got %T, want *TimestampPacer", p)
	}
	if tp.multiplier != 1.0 {
		t.Errorf("multiplier = %v, want 1.0", tp.multiplier)
	}
}

func TestNewPacer_Multiplier(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "multiplier", Multiplier: 1.5})
	tp, ok := p.(*TimestampPacer)
	if !ok {
		t.Fatalf("got %T, want *TimestampPacer", p)
	}
	if tp.multiplier != 1.5 {
		t.Errorf("multiplier = %v, want 1.5", tp.multiplier)
	}
}

func TestNewPacer_MultiplierZero(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "multiplier", Multiplier: 0})
	tp, ok := p.(*TimestampPacer)
	if !ok {
		t.Fatalf("got %T, want *TimestampPacer", p)
	}
	if tp.multiplier != 1.0 {
		t.Errorf("multiplier = %v, want 1.0 (zero clamps to 1.0)", tp.multiplier)
	}
}

func TestNewPacer_MultiplierNeg(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "multiplier", Multiplier: -1})
	tp, ok := p.(*TimestampPacer)
	if !ok {
		t.Fatalf("got %T, want *TimestampPacer", p)
	}
	if tp.multiplier != 1.0 {
		t.Errorf("multiplier = %v, want 1.0 (negative clamps to 1.0)", tp.multiplier)
	}
}

func TestNewPacer_BPS(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "bps", BPS: "200k"})
	tp, ok := p.(*TokenBucketPacer)
	if !ok {
		t.Fatalf("got %T, want *TokenBucketPacer", p)
	}
	if tp.bps != "200k" {
		t.Errorf("bps = %q, want %q", tp.bps, "200k")
	}
}

func TestNewPacer_PPS(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "pps", PPS: 1000})
	pp, ok := p.(*PPSPacer)
	if !ok {
		t.Fatalf("got %T, want *PPSPacer", p)
	}
	if pp.pps != 1000 {
		t.Errorf("pps = %v, want 1000", pp.pps)
	}
}

func TestNewPacer_Max(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "max"})
	if _, ok := p.(*MaxPacer); !ok {
		t.Errorf("got %T, want *MaxPacer", p)
	}
}

func TestNewPacer_Empty(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: ""})
	if _, ok := p.(*MaxPacer); !ok {
		t.Errorf("got %T, want *MaxPacer (empty mode -> max)", p)
	}
}

func TestNewPacer_Unknown(t *testing.T) {
	p := NewPacer(ReplaySpeed{Mode: "random"})
	if _, ok := p.(*MaxPacer); !ok {
		t.Errorf("got %T, want *MaxPacer (unknown mode -> max)", p)
	}
}

// ---------------------------------------------------------------------------
// TimestampPacer (PA10, PA12, PA13, PA15).
// ---------------------------------------------------------------------------

// PA10: the first Wait initializes the origin and returns immediately.
func TestTimestampPacer_FirstCallInit(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx := context.Background()
	pkt := core.PacketConfig{Timestamp: time.UnixMicro(1000)}
	start := time.Now()
	err := p.Wait(ctx, pkt, 0)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("first Wait err = %v, want nil", err)
	}
	if elapsed > 5*time.Millisecond {
		t.Errorf("first Wait waited %v, should be immediate", elapsed)
	}
	if !p.init {
		t.Error("p.init = false, want true after first Wait")
	}
	if p.firstTsUs != 1000 {
		t.Errorf("p.firstTsUs = %d, want 1000", p.firstTsUs)
	}
}

// PA12: a late packet (scheduled in the past) is sent immediately and shifts
// drift forward; assert drift > 0 after.
func TestTimestampPacer_LateAbsorbDrift(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx := context.Background()
	// Initialize origin at ts=0.
	if err := p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(0)}, 0); err != nil {
		t.Fatalf("init Wait: %v", err)
	}
	// Sleep past the scheduled time so pkt1 is "late".
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	// pkt1 ts=10us -> scheduled ~10us after start, but we are 50ms past.
	if err := p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(10)}, 0); err != nil {
		t.Fatalf("late Wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Errorf("late packet waited %v, should be immediate (drift absorbed)", elapsed)
	}
	if p.drift <= 0 {
		t.Errorf("p.drift = %v, want > 0 after absorbing lateness", p.drift)
	}
}

// PA13: a ctx cancelled during the future-sleep returns context.Canceled.
func TestTimestampPacer_CtxCancelDuringSleep(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Initialize origin at ts=0.
	if err := p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(0)}, 0); err != nil {
		t.Fatalf("init Wait: %v", err)
	}
	// pkt1 ts=1s future -> Wait sleeps ~1s; cancel after 10ms.
	pkt1 := core.PacketConfig{Timestamp: time.UnixMicro(1_000_000)}
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := p.Wait(ctx, pkt1, 0)
	elapsed := time.Since(start)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("Wait took %v, should return shortly after cancel", elapsed)
	}
}

// PA15: multiplier=2.0 compresses a 1000us capture delta to ~2ms wall sleep.
func TestTimestampPacer_Multiplier2x(t *testing.T) {
	p := &TimestampPacer{multiplier: 2.0}
	ctx := context.Background()
	if err := p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(0)}, 0); err != nil {
		t.Fatalf("init Wait: %v", err)
	}
	start := time.Now()
	// 1000us capture delta * 2.0 = 2000us = 2ms wall sleep.
	if err := p.Wait(ctx, core.PacketConfig{Timestamp: time.UnixMicro(1000)}, 0); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 1500*time.Microsecond || elapsed > 3500*time.Microsecond {
		t.Errorf("elapsed = %v, want ~2ms (multiplier 2x of 1000us)", elapsed)
	}
}

// ---------------------------------------------------------------------------
// MaxPacer (PA20).
// ---------------------------------------------------------------------------

func TestMaxPacer_AlwaysNil(t *testing.T) {
	p := MaxPacer{}
	ctx := context.Background()
	pkts := []core.PacketConfig{
		{Timestamp: time.UnixMicro(0)},
		{Timestamp: time.UnixMicro(1_000_000)},
		{},
	}
	sizes := []int{0, 1500, 65536}
	for i, pkt := range pkts {
		start := time.Now()
		err := p.Wait(ctx, pkt, sizes[i])
		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("pkt %d: err = %v, want nil", i, err)
		}
		if elapsed > 5*time.Millisecond {
			t.Errorf("pkt %d: waited %v, MaxPacer never waits", i, elapsed)
		}
	}
}

// ---------------------------------------------------------------------------
// TokenBucketPacer (PA22, PA23, PA26, PA28).
// PA29 skipped: covered by TestPacer_TokenBucketPacer_ConcurrentSafe.
// ---------------------------------------------------------------------------

// PA22: an unparseable bps leaves bucket nil; Wait is a no-op.
func TestTokenBucketPacer_BadBPS(t *testing.T) {
	p := &TokenBucketPacer{bps: "bad"}
	ctx := context.Background()
	start := time.Now()
	err := p.Wait(ctx, core.PacketConfig{}, 1500)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("err = %v, want nil (nil bucket = no limit)", err)
	}
	if p.bucket != nil {
		t.Error("bucket = non-nil, want nil (bad bps should not init bucket)")
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Wait took %v, should return immediately", elapsed)
	}
}

// PA23: bps parsing to <=0 leaves bucket nil; Wait is a no-op.
func TestTokenBucketPacer_BPSLEZero(t *testing.T) {
	p := &TokenBucketPacer{bps: "0"}
	ctx := context.Background()
	if err := p.Wait(ctx, core.PacketConfig{}, 1500); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if p.bucket != nil {
		t.Error("bucket = non-nil, want nil (bps<=0 should not init bucket)")
	}
}

// PA26: a nil bucket (from failed init) means no limit -- repeated Waits all
// return nil without blocking.
func TestTokenBucketPacer_NilBucketNoLimit(t *testing.T) {
	p := &TokenBucketPacer{bps: "bad"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		start := time.Now()
		err := p.Wait(ctx, core.PacketConfig{}, 1500)
		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("call %d: err = %v, want nil", i, err)
		}
		if elapsed > 5*time.Millisecond {
			t.Errorf("call %d: waited %v, nil bucket should not block", i, elapsed)
		}
	}
	if p.bucket != nil {
		t.Error("bucket = non-nil, want nil")
	}
}

// PA28: when the bucket actually blocks (drained burst, 1 byte/s rate), a ctx
// cancel propagates as context.Canceled. The burst is 65536 bytes, so the first
// Wait(65536) drains it; the subsequent Wait(1500) blocks until cancel.
func TestTokenBucketPacer_CtxCancel(t *testing.T) {
	p := &TokenBucketPacer{bps: "8"} // ParseBPS("8")=8 bits/s -> 1 byte/s
	ctx := context.Background()
	// Init bucket (rate=1 byte/s, burst=65536) and drain the entire burst.
	if err := p.Wait(ctx, core.PacketConfig{}, 65536); err != nil {
		t.Fatalf("drain Wait: %v", err)
	}
	if p.bucket == nil {
		t.Fatal("bucket = nil, want initialized after first Wait")
	}
	// Bucket is now empty; a 1500-byte Wait blocks (~1500s at 1 byte/s).
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := p.Wait(cctx, core.PacketConfig{}, 1500)
	elapsed := time.Since(start)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Wait took %v, should return shortly after cancel", elapsed)
	}
}

// ---------------------------------------------------------------------------
// PPSPacer (PA31, PA32, PA35, PA36, PA37).
// PA33 skipped: identical to PA31 (zero PPS -> no interval -> no-op).
// ---------------------------------------------------------------------------

// PA31: pps=0 leaves interval at 0; Wait is an immediate no-op.
func TestPPSPacer_ZeroPPS(t *testing.T) {
	p := &PPSPacer{pps: 0}
	ctx := context.Background()
	start := time.Now()
	err := p.Wait(ctx, core.PacketConfig{}, 0)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if elapsed > 5*time.Millisecond {
		t.Errorf("Wait took %v, should be immediate", elapsed)
	}
	if p.interval != 0 {
		t.Errorf("interval = %v, want 0", p.interval)
	}
}

// PA32: pps=1000 yields a 1ms interval. Trigger once.Do with a pre-cancelled
// ctx so Wait returns ctx.Err immediately after init; then assert interval.
func TestPPSPacer_Interval1000PPS(t *testing.T) {
	p := &PPSPacer{pps: 1000}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Wait(ctx, core.PacketConfig{}, 0)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled (pre-cancelled ctx)", err)
	}
	if p.interval != time.Millisecond {
		t.Errorf("interval = %v, want 1ms", p.interval)
	}
}

// PA35: a ctx cancelled during the inter-packet sleep returns context.Canceled.
// Use a very long interval (pps=10 -> interval=100ms) and cancel at 50ms to
// give the cancel goroutine plenty of margin over the interval timer.
func TestPPSPacer_CtxCancel(t *testing.T) {
	p := &PPSPacer{pps: 10}
	// Trigger once.Do with a pre-cancelled ctx (interval becomes 100ms).
	initCtx, initCancel := context.WithCancel(context.Background())
	initCancel()
	if err := p.Wait(initCtx, core.PacketConfig{}, 0); err != context.Canceled {
		t.Fatalf("init Wait: err = %v, want context.Canceled", err)
	}
	if p.interval != 100*time.Millisecond {
		t.Fatalf("interval = %v, want 100ms before cancel test", p.interval)
	}
	// Cancel at 50ms, well before the 100ms interval fires.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := p.Wait(ctx, core.PacketConfig{}, 0)
	elapsed := time.Since(start)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 90*time.Millisecond {
		t.Errorf("Wait took %v, should return shortly after cancel (~50ms)", elapsed)
	}
}

// PA36 (CORE): 8 workers x 100 calls = 800 calls on a shared PPSPacer at
// 1000 pps. Because the mutex serializes the inter-packet sleep, the aggregate
// rate ~= 1000 pps (800 calls in ~800ms). Without serialization each worker
// would sleep independently and the aggregate would be ~8000 pps (~100ms).
// Asserting actualPPS in [700,1300] proves the mutex serializes cross-worker.
func TestPPSPacer_ConcurrentAggregateRate(t *testing.T) {
	p := &PPSPacer{pps: 1000}
	ctx := context.Background()
	const workers, calls = 8, 100
	const totalCalls = workers * calls // 800
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				if err := p.Wait(ctx, core.PacketConfig{}, 0); err != nil {
					t.Errorf("Wait err = %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Serialized: 800 * 1ms = 800ms. Independent (8x): ~100ms.
	if elapsed < 600*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 600ms (serialized at 1000pps); mutex did not serialize", elapsed)
	}
	if elapsed > 1300*time.Millisecond {
		t.Errorf("elapsed = %v, want <= 1300ms", elapsed)
	}
	actualPPS := float64(totalCalls) / elapsed.Seconds()
	// 8x independent would be ~8000 pps; the upper bound of 1300 catches that.
	// The lower bound of 700 catches over-serialization / drift.
	if actualPPS < 700 || actualPPS > 1300 {
		t.Errorf("actualPPS = %f, want [700, 1300] (configured 1000; 8x bug would give ~8000)", actualPPS)
	}
}

// PA37: a fractional pps (0.5) yields a 2s interval.
func TestPPSPacer_FractionalPPS(t *testing.T) {
	p := &PPSPacer{pps: 0.5}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// once.Do sets interval = 1s/0.5 = 2s; the pre-cancelled ctx makes Wait
	// return ctx.Err immediately via the select, so the test does not wait 2s.
	err := p.Wait(ctx, core.PacketConfig{}, 0)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled (pre-cancelled ctx)", err)
	}
	if p.interval != 2*time.Second {
		t.Errorf("interval = %v, want 2s", p.interval)
	}
}

// ---------------------------------------------------------------------------
// generateClones (FS1, FS2, FS4, FS5, FS11, FS12, FS9).
// ---------------------------------------------------------------------------

func TestGenerateClones_Nil(t *testing.T) {
	clones, err := generateClones(nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if clones != nil {
		t.Errorf("clones = %v, want nil", clones)
	}
}

func TestGenerateClones_CountLEZero(t *testing.T) {
	fs := &FlowScaling{Count: 0}
	clones, err := generateClones(fs)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if clones != nil {
		t.Errorf("clones = %v, want nil for Count<=0", clones)
	}
}

func TestGenerateClones_Count5(t *testing.T) {
	fs := &FlowScaling{
		Count:   5,
		SrcIP:   core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:   core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SrcPort: core.StrategyConfig{Strategy: "fixed", Value: "100"},
		DstPort: core.StrategyConfig{Strategy: "fixed", Value: "200"},
	}
	clones, err := generateClones(fs)
	if err != nil {
		t.Fatalf("generateClones: %v", err)
	}
	if len(clones) != 5 {
		t.Fatalf("len(clones) = %d, want 5", len(clones))
	}
	for k, c := range clones {
		if c.Index != k {
			t.Errorf("clones[%d].Index = %d, want %d", k, c.Index, k)
		}
	}
}

func TestGenerateClones_SrcIPFail(t *testing.T) {
	fs := &FlowScaling{
		Count: 2,
		SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{}}, // no range -> error
	}
	_, err := generateClones(fs)
	if err == nil {
		t.Fatal("expected error for inc src_ip with empty range, got nil")
	}
	if !strings.Contains(err.Error(), "clone 0 src_ip") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "clone 0 src_ip")
	}
}

func TestGenerateClones_SeqOffsetFail(t *testing.T) {
	fs := &FlowScaling{
		Count:     2,
		SrcIP:     core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:     core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SeqOffset: core.StrategyConfig{Strategy: "inc", Range: []interface{}{}}, // no range -> error
	}
	_, err := generateClones(fs)
	if err == nil {
		t.Fatal("expected error for inc seq_offset with empty range, got nil")
	}
	if !strings.Contains(err.Error(), "seq_offset") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "seq_offset")
	}
}

func TestGenerateClones_AllResolved(t *testing.T) {
	fs := &FlowScaling{
		Count:     3,
		SrcIP:     core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:     core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SrcPort:   core.StrategyConfig{Strategy: "fixed", Value: "1000"},
		DstPort:   core.StrategyConfig{Strategy: "fixed", Value: "2000"},
		SrcMAC:    core.StrategyConfig{Strategy: "fixed", Value: "aa:bb:cc:dd:ee:ff"},
		DstMAC:    core.StrategyConfig{Strategy: "fixed", Value: "11:22:33:44:55:66"},
		SeqOffset: core.StrategyConfig{Strategy: "fixed", Value: "500"},
	}
	clones, err := generateClones(fs)
	if err != nil {
		t.Fatalf("generateClones: %v", err)
	}
	if len(clones) != 3 {
		t.Fatalf("len(clones) = %d, want 3", len(clones))
	}
	c := clones[0]
	if c.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want 10.0.0.1", c.SrcIP)
	}
	if c.DstIP != "10.0.0.2" {
		t.Errorf("DstIP = %q, want 10.0.0.2", c.DstIP)
	}
	if c.SrcPort != 1000 {
		t.Errorf("SrcPort = %d, want 1000", c.SrcPort)
	}
	if c.DstPort != 2000 {
		t.Errorf("DstPort = %d, want 2000", c.DstPort)
	}
	if c.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("SrcMAC = %q, want aa:bb:cc:dd:ee:ff", c.SrcMAC)
	}
	if c.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("DstMAC = %q, want 11:22:33:44:55:66", c.DstMAC)
	}
	if c.SeqOffset != 500 {
		t.Errorf("SeqOffset = %d, want 500", c.SeqOffset)
	}
}

// FS9: resolveCloneStr errors from SrcMAC are deliberately ignored (MAC is
// optional); srcMAC becomes "" and generateClones returns no error.
func TestGenerateClones_SrcMACErrorIgnored(t *testing.T) {
	fs := &FlowScaling{
		Count:  1,
		SrcIP:  core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:  core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SrcMAC: core.StrategyConfig{Strategy: "inc", Range: []interface{}{}}, // error ignored
	}
	clones, err := generateClones(fs)
	if err != nil {
		t.Errorf("err = %v, want nil (SrcMAC errors must be ignored)", err)
	}
	if len(clones) != 1 {
		t.Fatalf("len(clones) = %d, want 1", len(clones))
	}
	if clones[0].SrcMAC != "" {
		t.Errorf("SrcMAC = %q, want empty (error path returns empty)", clones[0].SrcMAC)
	}
}

// ---------------------------------------------------------------------------
// resolveCloneStr (FS14-FS29).
// ---------------------------------------------------------------------------

func TestResolveCloneStr_Fixed(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: "1.2.3.4"}
	got, err := resolveCloneStr(sc, 0, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestResolveCloneStr_FixedNil(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: nil}
	got, err := resolveCloneStr(sc, 0, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty for nil Value", got)
	}
}

func TestResolveCloneStr_IncNoRange(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "inc", Range: []interface{}{}}
	_, err := resolveCloneStr(sc, 0, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "inc strategy needs range") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "inc strategy needs range")
	}
}

func TestResolveCloneStr_IncIPStep0(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "inc",
		Range:    []interface{}{"10.0.0.1", "10.0.0.10"},
		Step:     0, // clamps to 1
	}
	got, err := resolveCloneStr(sc, 2, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "10.0.0.3" {
		t.Errorf("got %q, want 10.0.0.3 (start + k*1)", got)
	}
}

func TestResolveCloneStr_IncIPStep5(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "inc",
		Range:    []interface{}{"10.0.0.1", "10.0.0.100"},
		Step:     5,
	}
	got, err := resolveCloneStr(sc, 2, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "10.0.0.11" {
		t.Errorf("got %q, want 10.0.0.11 (start + 2*5)", got)
	}
}

func TestResolveCloneStr_IncIPInvalid(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "inc",
		Range:    []interface{}{"notanip", "x"},
		Step:     1,
	}
	_, err := resolveCloneStr(sc, 0, true)
	if err == nil {
		t.Fatal("expected error for invalid IP in inc range, got nil")
	}
}

func TestResolveCloneStr_IncNumeric(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "inc",
		Range:    []interface{}{"1000", "2000"},
		Step:     10,
	}
	got, err := resolveCloneStr(sc, 2, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "1020" {
		t.Errorf("got %q, want 1020 (1000 + 2*10)", got)
	}
}

func TestResolveCloneStr_IncNonNumeric(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "inc",
		Range:    []interface{}{"abc", "def"},
		Step:     1,
	}
	got, err := resolveCloneStr(sc, 2, false)
	if err != nil {
		t.Fatalf("err = %v, want nil (non-numeric inc returns start unchanged)", err)
	}
	if got != "abc" {
		t.Errorf("got %q, want abc (ParseInt fails -> start unchanged)", got)
	}
}

func TestResolveCloneStr_RandomNoRange(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "random", Range: []interface{}{}}
	_, err := resolveCloneStr(sc, 0, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "random strategy needs range") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "random strategy needs range")
	}
}

func TestResolveCloneStr_RandomIP(t *testing.T) {
	sc := core.StrategyConfig{
		Strategy: "random",
		Range:    []interface{}{"10.0.0.1", "10.0.0.10"},
		Seed:     42,
	}
	first, err := resolveCloneStr(sc, 0, true)
	if err != nil {
		t.Fatalf("first err = %v, want nil", err)
	}
	second, err := resolveCloneStr(sc, 0, true)
	if err != nil {
		t.Fatalf("second err = %v, want nil", err)
	}
	if first != second {
		t.Errorf("random not deterministic: %q vs %q", first, second)
	}
	// Result must be a valid IPv4 in range.
	ip := net.ParseIP(first)
	if ip == nil {
		t.Fatalf("result %q is not a valid IP", first)
	}
	v := binary.BigEndian.Uint32(ip.To4())
	lo := binary.BigEndian.Uint32(net.ParseIP("10.0.0.1").To4())
	hi := binary.BigEndian.Uint32(net.ParseIP("10.0.0.10").To4())
	if v < lo || v > hi {
		t.Errorf("result %s (=%d) out of range [%d,%d]", first, v, lo, hi)
	}
}

func TestResolveCloneStr_List(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "list", List: []string{"a", "b", "c"}}
	got, err := resolveCloneStr(sc, 5, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "c" {
		t.Errorf("got %q, want c (5%%3=2)", got)
	}
}

func TestResolveCloneStr_ListSingle(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "list", List: []string{"x"}}
	got, err := resolveCloneStr(sc, 99, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "x" {
		t.Errorf("got %q, want x (99%%1=0)", got)
	}
}

func TestResolveCloneStr_Unknown(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "unknown"}
	_, err := resolveCloneStr(sc, 0, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported strategy") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "unsupported strategy")
	}
}

// ---------------------------------------------------------------------------
// resolveClonePort (FS30-FS33).
// ---------------------------------------------------------------------------

func TestResolveClonePort_StrFail(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "inc", Range: []interface{}{}}
	v, err := resolveClonePort(sc, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if v != 0 {
		t.Errorf("port = %d, want 0 on error", v)
	}
}

func TestResolveClonePort_Empty(t *testing.T) {
	sc := core.StrategyConfig{Strategy: ""}
	v, err := resolveClonePort(sc, 0)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if v != 0 {
		t.Errorf("port = %d, want 0 for empty strategy", v)
	}
}

func TestResolveClonePort_Valid(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: "8080"}
	v, err := resolveClonePort(sc, 0)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if v != 8080 {
		t.Errorf("port = %d, want 8080", v)
	}
}

func TestResolveClonePort_Overflow(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: "99999"}
	_, err := resolveClonePort(sc, 0)
	if err == nil {
		t.Fatal("expected error for port > 65535, got nil")
	}
}

// ---------------------------------------------------------------------------
// resolveCloneSeq (FS35-FS37).
// ---------------------------------------------------------------------------

func TestResolveCloneSeq_Fixed(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: 1000}
	v, err := resolveCloneSeq(sc, 0)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if v != 1000 {
		t.Errorf("seq = %d, want 1000", v)
	}
}

func TestResolveCloneSeq_FixedNil(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: nil}
	v, err := resolveCloneSeq(sc, 0)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if v != 0 {
		t.Errorf("seq = %d, want 0 for nil Value", v)
	}
}

func TestResolveCloneSeq_FixedBad(t *testing.T) {
	sc := core.StrategyConfig{Strategy: "fixed", Value: "abc"}
	v, err := resolveCloneSeq(sc, 0)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if v != 0 {
		t.Errorf("seq = %d, want 0 on parse error", v)
	}
}

// ---------------------------------------------------------------------------
// incIP / randomInRange (FS41-FS48).
// ---------------------------------------------------------------------------

func TestIncIP_Invalid(t *testing.T) {
	_, err := incIP("notanip", 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestIncIP_IPv6(t *testing.T) {
	_, err := incIP("::1", 1)
	if err == nil {
		t.Fatal("expected error for IPv6, got nil")
	}
	if !strings.Contains(err.Error(), "not IPv4") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "not IPv4")
	}
}

func TestIncIP_Normal(t *testing.T) {
	got, err := incIP("10.0.0.1", 5)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "10.0.0.6" {
		t.Errorf("got %q, want 10.0.0.6", got)
	}
}

func TestIncIP_Wrap(t *testing.T) {
	got, err := incIP("255.255.255.255", 1)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "0.0.0.0" {
		t.Errorf("got %q, want 0.0.0.0 (32-bit wrap)", got)
	}
}

func TestRandomInRange_IPSwap(t *testing.T) {
	// lo > hi: implementation swaps, result stays in [10.0.0.1, 10.0.0.10].
	got, err := randomInRange("10.0.0.10", "10.0.0.1", 1, 0, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	ip := net.ParseIP(got)
	if ip == nil {
		t.Fatalf("got %q is not a valid IP", got)
	}
	v := binary.BigEndian.Uint32(ip.To4())
	lo := binary.BigEndian.Uint32(net.ParseIP("10.0.0.1").To4())
	hi := binary.BigEndian.Uint32(net.ParseIP("10.0.0.10").To4())
	if v < lo || v > hi {
		t.Errorf("result %s (=%d) out of swapped range [%d,%d]", got, v, lo, hi)
	}
}

func TestRandomInRange_NumericLoFail(t *testing.T) {
	_, err := randomInRange("abc", "10", 1, 0, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid range lo") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "invalid range lo")
	}
}

// ---------------------------------------------------------------------------
// clonePatches (FS55, FS56, FS58, FS62, FS64, FS68, FS-FULL).
// ---------------------------------------------------------------------------

func TestClonePatches_SrcIP(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, L4Protocol: "tcp"}
	c := Clone{SrcIP: "10.0.0.99"}
	patches := clonePatches(c, layout)
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	p := patches[0]
	if p.Field != "src_ip" {
		t.Errorf("Field = %q, want src_ip", p.Field)
	}
	if p.Offset != 26 {
		t.Errorf("Offset = %d, want 26", p.Offset)
	}
	if !net.IP(p.Bytes).Equal(net.ParseIP("10.0.0.99").To4()) {
		t.Errorf("Bytes = %v, want [10 0 0 99]", p.Bytes)
	}
	if p.Layer != "l3" {
		t.Errorf("Layer = %q, want l3", p.Layer)
	}
}

func TestClonePatches_SrcIPLayoutNeg(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: -1, L4Protocol: "tcp"}
	c := Clone{SrcIP: "10.0.0.99"}
	patches := clonePatches(c, layout)
	for _, p := range patches {
		if p.Field == "src_ip" {
			t.Error("found src_ip patch with layout.SrcIP=-1, want none")
		}
	}
}

func TestClonePatches_SrcIPEmpty(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, L4Protocol: "tcp"}
	c := Clone{SrcIP: ""}
	patches := clonePatches(c, layout)
	for _, p := range patches {
		if p.Field == "src_ip" {
			t.Error("found src_ip patch with empty clone.SrcIP, want none")
		}
	}
}

func TestClonePatches_SrcPort(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcPort: 34, L4Protocol: "tcp"}
	c := Clone{SrcPort: 5000}
	patches := clonePatches(c, layout)
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	p := patches[0]
	if p.Field != "src_port" {
		t.Errorf("Field = %q, want src_port", p.Field)
	}
	if binary.BigEndian.Uint16(p.Bytes) != 5000 {
		t.Errorf("Bytes = %v, want BE(5000)", p.Bytes)
	}
	if p.Layer != "l4" {
		t.Errorf("Layer = %q, want l4", p.Layer)
	}
}

func TestClonePatches_SrcPortZero(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcPort: 34, L4Protocol: "tcp"}
	c := Clone{SrcPort: 0}
	patches := clonePatches(c, layout)
	for _, p := range patches {
		if p.Field == "src_port" {
			t.Error("found src_port patch with SrcPort=0, want none")
		}
	}
}

func TestClonePatches_SrcMAC(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, L4Protocol: "tcp"}
	c := Clone{SrcMAC: "de:ad:be:ef:00:01"}
	patches := clonePatches(c, layout)
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	p := patches[0]
	if p.Field != "src_mac" {
		t.Errorf("Field = %q, want src_mac", p.Field)
	}
	if p.Layer != "l2" {
		t.Errorf("Layer = %q, want l2", p.Layer)
	}
	hw, err := net.ParseMAC("de:ad:be:ef:00:01")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	if string(p.Bytes) != string(hw) {
		t.Errorf("Bytes = %v, want %v", p.Bytes, hw)
	}
}

func TestClonePatches_AllFields(t *testing.T) {
	layout := testLayout(t)
	c := Clone{
		SrcIP:   "10.0.0.99",
		DstIP:   "10.0.0.88",
		SrcPort: 5000,
		DstPort: 6000,
		SrcMAC:  "de:ad:be:ef:00:01",
		DstMAC:  "ca:fe:ba:be:00:02",
	}
	patches := clonePatches(c, layout)
	if len(patches) != 6 {
		t.Fatalf("patches = %d, want 6 (all fields filled)", len(patches))
	}
	seen := map[string]bool{}
	for _, p := range patches {
		seen[p.Field] = true
	}
	for _, f := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "dst_mac"} {
		if !seen[f] {
			t.Errorf("missing patch for field %q", f)
		}
	}
}

// ---------------------------------------------------------------------------
// seqOffsetPatch (FS74-FS78).
// ---------------------------------------------------------------------------

func TestSeqOffsetPatch_Zero(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp"}
	raw := make([]byte, 54)
	_, ok := seqOffsetPatch(raw, Clone{SeqOffset: 0}, layout)
	if ok {
		t.Error("ok = true for SeqOffset=0, want false")
	}
}

func TestSeqOffsetPatch_LayoutNeg(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: -1, L4Protocol: "tcp"}
	raw := make([]byte, 54)
	_, ok := seqOffsetPatch(raw, Clone{SeqOffset: 1000}, layout)
	if ok {
		t.Error("ok = true for layout.Seq=-1, want false")
	}
}

func TestSeqOffsetPatch_OutOfBounds(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp"}
	raw := make([]byte, 40) // 38+4=42 > 40
	_, ok := seqOffsetPatch(raw, Clone{SeqOffset: 1000}, layout)
	if ok {
		t.Error("ok = true for out-of-bounds seq, want false")
	}
}

func TestSeqOffsetPatch_Valid(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp"}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 1000)
	p, ok := seqOffsetPatch(raw, Clone{SeqOffset: 1000}, layout)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if p.Field != "seq" {
		t.Errorf("Field = %q, want seq", p.Field)
	}
	if p.Layer != "l4" {
		t.Errorf("Layer = %q, want l4", p.Layer)
	}
	if binary.BigEndian.Uint32(p.Bytes) != 2000 {
		t.Errorf("Bytes = %v, want BE(2000) (origSeq 1000 + offset 1000)", p.Bytes)
	}
}

func TestSeqOffsetPatch_Wrap(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp"}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 0xFFFFFFFF)
	p, ok := seqOffsetPatch(raw, Clone{SeqOffset: 1}, layout)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if binary.BigEndian.Uint32(p.Bytes) != 0 {
		t.Errorf("Bytes = %v, want BE(0) (0xFFFFFFFF + 1 wraps to 0)", p.Bytes)
	}
}

// ---------------------------------------------------------------------------
// checkFlowScalingConflict (FS79, FS87-FS90, FS92).
// ---------------------------------------------------------------------------

func TestCheckFlowScalingConflict_Nil(t *testing.T) {
	err := checkFlowScalingConflict(nil, []RewriteRule{{Kind: "field", Target: "src_ip"}})
	if err != nil {
		t.Errorf("err = %v, want nil for nil fs", err)
	}
}

func TestCheckFlowScalingConflict_FieldVaried(t *testing.T) {
	fs := &FlowScaling{SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.10"}}}
	rules := []RewriteRule{{Kind: "field", Target: "src_ip"}}
	err := checkFlowScalingConflict(fs, rules)
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	if !strings.Contains(err.Error(), "FlowScaling varies src_ip") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "FlowScaling varies src_ip")
	}
}

func TestCheckFlowScalingConflict_FieldNotVaried(t *testing.T) {
	fs := &FlowScaling{SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.10"}}}
	rules := []RewriteRule{{Kind: "field", Target: "ttl"}}
	if err := checkFlowScalingConflict(fs, rules); err != nil {
		t.Errorf("err = %v, want nil (rule target ttl not varied by fs)", err)
	}
}

func TestCheckFlowScalingConflict_EndpointVaried(t *testing.T) {
	fs := &FlowScaling{SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.10"}}}
	rules := []RewriteRule{{Kind: "endpoint", Target: "client_ip"}}
	err := checkFlowScalingConflict(fs, rules)
	if err == nil {
		t.Fatal("expected conflict (endpoint client_ip -> src_ip, varied), got nil")
	}
	if !strings.Contains(err.Error(), "endpoint rule sets") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "endpoint rule sets")
	}
}

func TestCheckFlowScalingConflict_EndpointNotVaried(t *testing.T) {
	// fs varies dst_ip, but endpoint client_ip maps to src_ip (not varied) -> ok.
	fs := &FlowScaling{DstIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.10"}}}
	rules := []RewriteRule{{Kind: "endpoint", Target: "client_ip"}}
	if err := checkFlowScalingConflict(fs, rules); err != nil {
		t.Errorf("err = %v, want nil (client_ip->src_ip not varied by fs)", err)
	}
}

func TestCheckFlowScalingConflict_MappingAllowed(t *testing.T) {
	fs := &FlowScaling{SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.10"}}}
	rules := []RewriteRule{{Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1"}}}
	if err := checkFlowScalingConflict(fs, rules); err != nil {
		t.Errorf("err = %v, want nil (ipmap + flowscaling allowed)", err)
	}
}
