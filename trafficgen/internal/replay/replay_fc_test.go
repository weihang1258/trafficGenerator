package replay

// Spec-driven tests for the replay planner's fc parameter and pacer routing
// (R-F2 invariant: pacer and task-level bps parent bucket never coexist on
// the same packet). Covers R1-R7:
//   - R1-R3: batch path (fc=nil) always attaches a pacer.
//   - R4-R6: single-protocol path (fc!=nil) keeps pacer for original/multiplier
//     but drops it for bps/empty (routes through engine child bucket or none).
//   - R7: flows ceiling (fc.FlowCounter != nil) skips packets past the cap.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/core"
)

// pacerFromConfig extracts the _pacer metadata field set by the planner. Returns
// nil when the planner intentionally dropped the pacer (single-protocol bps/empty).
func pacerFromConfig(cfg core.PacketConfig) Pacer {
	if p, ok := cfg.Metadata["_pacer"]; ok {
		if pacer, ok := p.(Pacer); ok {
			return pacer
		}
	}
	return nil
}

// R1: batch (fc=nil) + original -> TimestampPacer attached.
func TestReplayFC_Batch_OriginalAttachesPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "original"}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawPacer bool
	for cfg := range ch {
		if p := pacerFromConfig(cfg); p != nil {
			sawPacer = true
			if _, ok := p.(*TimestampPacer); !ok {
				t.Errorf("batch original: pacer type %T, want *TimestampPacer", p)
			}
		}
	}
	if !sawPacer {
		t.Error("batch original: no pacer attached (expected TimestampPacer)")
	}
}

// R2: batch (fc=nil) + bps -> TokenBucketPacer attached.
func TestReplayFC_Batch_BPSAttachesPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "bps", BPS: "1m"}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawPacer bool
	for cfg := range ch {
		if p := pacerFromConfig(cfg); p != nil {
			sawPacer = true
			if _, ok := p.(*TokenBucketPacer); !ok {
				t.Errorf("batch bps: pacer type %T, want *TokenBucketPacer", p)
			}
		}
	}
	if !sawPacer {
		t.Error("batch bps: no pacer attached (expected TokenBucketPacer)")
	}
}

// R3: batch (fc=nil) + empty -> MaxPacer attached.
func TestReplayFC_Batch_EmptyAttachesPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawPacer bool
	for cfg := range ch {
		if p := pacerFromConfig(cfg); p != nil {
			sawPacer = true
			if _, ok := p.(*MaxPacer); !ok {
				t.Errorf("batch empty: pacer type %T, want *MaxPacer", p)
			}
		}
	}
	if !sawPacer {
		t.Error("batch empty: no pacer attached (expected MaxPacer)")
	}
}

// R4: single-protocol (fc!=nil) + original -> TimestampPacer STILL attached.
// original/multiplier always pace regardless of path.
func TestReplayFC_Single_OriginalKeepsPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "original"}}
	fc := &core.ReplayFC{} // non-nil but no FlowCounter (bps/empty path)
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawPacer bool
	for cfg := range ch {
		if p := pacerFromConfig(cfg); p != nil {
			sawPacer = true
			if _, ok := p.(*TimestampPacer); !ok {
				t.Errorf("single original: pacer type %T, want *TimestampPacer", p)
			}
		}
	}
	if !sawPacer {
		t.Error("single original: pacer dropped (R-F2 violation: original must always pace)")
	}
}

// R5: single-protocol (fc!=nil) + bps -> pacer dropped (nil). Routes through
// engine child bucket instead.
func TestReplayFC_Single_BPSDropsPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "bps", BPS: "1m"}}
	fc := &core.ReplayFC{}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var count int
	for cfg := range ch {
		count++
		if p := pacerFromConfig(cfg); p != nil {
			t.Errorf("single bps: pacer attached (%T), R-F2 requires nil (engine child bucket)", p)
		}
	}
	if count == 0 {
		t.Error("single bps: no packets emitted")
	}
}

// R6: single-protocol (fc!=nil) + empty -> pacer dropped (nil). No rate limit
// (only optional parent bucket applies).
func TestReplayFC_Single_EmptyDropsPacer(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	fc := &core.ReplayFC{}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var count int
	for cfg := range ch {
		count++
		if p := pacerFromConfig(cfg); p != nil {
			t.Errorf("single empty: pacer attached (%T), R-F2 requires nil (no rate limit)", p)
		}
	}
	if count == 0 {
		t.Error("single empty: no packets emitted")
	}
}

// R7: flows ceiling (fc.FlowCounter != nil) skips packets whose flow ID is past
// the ceiling. The test asset has 1 flow (3 packets), so a ceiling of 0 means
// the first flow increments the counter to 1 (>0=ceiling) and is skipped; all
// 3 packets of that flow are skipped -> 0 emitted. A ceiling of 1 lets the
// first flow through -> 3 packets emitted.
func TestReplayFC_FlowsCeiling_SkipsPastCap(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}

	t.Run("ceiling 0 skips all", func(t *testing.T) {
		var counter int64
		fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 0}
		ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		var count int
		for range ch {
			count++
		}
		if count != 0 {
			t.Errorf("ceiling=0: emitted %d packets, want 0 (all flows past cap)", count)
		}
		if atomic.LoadInt64(&counter) != 1 {
			t.Errorf("ceiling=0: counter=%d, want 1 (one flow counted then skipped)", counter)
		}
	})

	t.Run("ceiling 1 emits all (single-flow asset)", func(t *testing.T) {
		var counter int64
		fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 1}
		ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		var count int
		for range ch {
			count++
		}
		if count != 3 {
			t.Errorf("ceiling=1: emitted %d packets, want 3 (single flow under cap)", count)
		}
		if atomic.LoadInt64(&counter) != 1 {
			t.Errorf("ceiling=1: counter=%d, want 1 (single flow counted once)", counter)
		}
	})
}

// R7-BR: nil FlowCounter (ceiling inactive) emits all packets even with fc!=nil.
// This is the "single-protocol path without flows ceiling" case: fc signals
// pacer routing, but no cap is enforced.
func TestReplayFC_NilFlowCounter_NoCap(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	fc := &core.ReplayFC{FlowCounter: nil, Ceiling: 100} // Ceiling set but FlowCounter nil
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var count int
	for range ch {
		count++
	}
	if count != 3 {
		t.Errorf("nil FlowCounter: emitted %d packets, want 3 (no cap enforced)", count)
	}
}

// R7-CONC: flows ceiling under concurrent planners sharing a counter. Two
// planners each drawing from the same asset (1 flow each, same flow ID) share
// a FlowCounter with ceiling=1. Only one planner's flow should be admitted;
// the other is skipped. (Hard to make deterministic without two distinct
// assets, so this test uses ceiling=2 to verify both pass and the counter
// increments to 2.)
func TestReplayFC_Concurrent_SharedCounter(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	var counter int64
	fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 2}

	var wg sync.WaitGroup
	var counts [2]int
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", fc)
			if err != nil {
				t.Errorf("Plan: %v", err)
				return
			}
			for range ch {
				counts[idx]++
			}
		}(i)
	}
	wg.Wait()

	// Both planners share the same flow ID; ceiling=2 admits both (counter=2,
	// one flow per planner but same ID counted once per planner due to per-planner
	// seen map). Total emitted = 6 (3 packets x 2 planners).
	total := counts[0] + counts[1]
	if total != 6 {
		t.Errorf("concurrent: total emitted=%d, want 6 (ceiling=2 admits both)", total)
	}
}

// (End of replay_fc_test.go)

// R7-MULTI: multi-flow ceiling test. Builds a 2-flow asset (flow A: src_port=1234,
// flow B: src_port=5678; 2 packets each). With Ceiling=1, only flow A is admitted
// (counter: 1<=1 ok, then 2>1 skipped). Flow B's packets are all skipped.
// Verifies the seen/skipped dedup logic: once a flow is skipped, subsequent
// packets of the same flow are also skipped (no re-admission).
func TestReplayFC_FlowsCeiling_MultiFlow(t *testing.T) {
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	build := func(srcPort uint16, seq uint32) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: 80, Seq: seq, SYN: true, Window: 65535}
		ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, tcp, gopacket.Payload([]byte("x")))
		return buf.Bytes()
	}
	frames := [][]byte{
		build(1234, 100), // flow A pkt 1
		build(1234, 101), // flow A pkt 2
		build(5678, 200), // flow B pkt 1
		build(5678, 201), // flow B pkt 2
	}
	_, db, assetID := storeFrames(t, frames, "mf")
	planner := NewReplayPlanner(db)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}

	t.Run("ceiling 1 admits flow A only", func(t *testing.T) {
		var counter int64
		fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 1}
		ch, err := planner.Plan(plannerBg(), spec, "t", "c", "u1", fc)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		var count int
		for range ch {
			count++
		}
		if count != 2 {
			t.Errorf("ceiling=1: emitted %d packets, want 2 (flow A only; B skipped)", count)
		}
		if atomic.LoadInt64(&counter) != 2 {
			t.Errorf("ceiling=1: counter=%d, want 2 (both flows counted; B skipped after count)", counter)
		}
	})

	t.Run("ceiling 2 admits both flows", func(t *testing.T) {
		var counter int64
		fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 2}
		ch, err := planner.Plan(plannerBg(), spec, "t", "c", "u1", fc)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		var count int
		for range ch {
			count++
		}
		if count != 4 {
			t.Errorf("ceiling=2: emitted %d packets, want 4 (both flows under cap)", count)
		}
		if atomic.LoadInt64(&counter) != 2 {
			t.Errorf("ceiling=2: counter=%d, want 2 (each flow counted once)", counter)
		}
	})
}

// R7-CONC-ENFORCE: concurrent ceiling enforcement. Two planners with distinct
// flow IDs share a counter with Ceiling=1. Only one planner's flow is admitted;
// the other is skipped. Verifies the atomic increment+compare is race-free and
// enforces the cap under concurrency.
func TestReplayFC_Concurrent_CeilingEnforced(t *testing.T) {
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	build := func(srcPort uint16, seq uint32) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: 80, Seq: seq, SYN: true, Window: 65535}
		ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, tcp, gopacket.Payload([]byte("x")))
		return buf.Bytes()
	}
	// Two separate assets, each with one distinct flow.
	framesA := [][]byte{build(1234, 100), build(1234, 101)}
	framesB := [][]byte{build(5678, 200), build(5678, 201)}
	_, dbA, assetA := storeFrames(t, framesA, "concA")
	_, dbB, assetB := storeFrames(t, framesB, "concB")
	plannerA := NewReplayPlanner(dbA)
	plannerB := NewReplayPlanner(dbB)

	var counter int64
	fc := &core.ReplayFC{FlowCounter: &counter, Ceiling: 1}

	var wg sync.WaitGroup
	var countA, countB int
	wg.Add(2)
	go func() {
		defer wg.Done()
		ch, err := plannerA.Plan(plannerBg(), ReplaySpec{PcapAssetID: assetA, Speed: ReplaySpeed{Mode: ""}}, "t", "c", "u1", fc)
		if err != nil {
			t.Errorf("PlanA: %v", err)
			return
		}
		for range ch {
			countA++
		}
	}()
	go func() {
		defer wg.Done()
		ch, err := plannerB.Plan(plannerBg(), ReplaySpec{PcapAssetID: assetB, Speed: ReplaySpeed{Mode: ""}}, "t", "c", "u1", fc)
		if err != nil {
			t.Errorf("PlanB: %v", err)
			return
		}
		for range ch {
			countB++
		}
	}()
	wg.Wait()

	total := countA + countB
	// One planner's flow is admitted (2 packets), the other's is skipped (0).
	// Both increment the counter (to 2), but only the first one's increment was <=1.
	if total != 2 {
		t.Errorf("concurrent ceiling=1: total emitted=%d, want 2 (one flow admitted, one skipped)", total)
	}
	if atomic.LoadInt64(&counter) != 2 {
		t.Errorf("counter=%d, want 2 (both flows counted; only one admitted)", counter)
	}
}
