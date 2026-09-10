package ftp

import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestFTPLannerPerf measures planner throughput for 1000 FTP flows.
// The planner is called per-flow (worker loops over Count), so we call Plan
// 1000 times with Count=1 to measure real-world planner throughput.
func TestFTPLannerPerf(t *testing.T) {
	p := NewPlanner()
	spec := coreFlowSpec()
	spec.Count = 1 // planner generates 1 flow per call

	totalPkts := 0
	start := time.Now()
	for i := 0; i < 1000; i++ {
		ch, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan flow %d: %v", i, err)
		}
		for range ch {
			totalPkts++
		}
	}
	elapsed := time.Since(start)

	if totalPkts != 14000 {
		t.Errorf("expected 14000 packets (1000x14), got %d", totalPkts)
	}
	t.Logf("planner 1000 flows: %d packets in %v (%.0f pkts/s)", totalPkts, elapsed, float64(totalPkts)/elapsed.Seconds())
}

// TestFTPLannerPerfSessions measures planner throughput for 1000 flows
// with multi-session shape (1 session + data channel per flow).
func TestFTPLannerPerfSessions(t *testing.T) {
	p := NewPlanner()
	spec := coreFlowSpec()
	spec.Count = 1
	spec.FTP.Sessions = []core.FTPSession{
		{
			Transactions: []core.FTPTransaction{
				{
					Commands: []core.FTPCommand{
						{Cmd: "USER test", Response: "331"},
						{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
						{Cmd: "RETR /x.bin", Response: "150", EmitDataChannel: true},
						{Cmd: "", Response: "226"},
					},
					DataChannel: &core.FTPDataChannel{Payload: "S"},
				},
			},
		},
	}

	totalPkts := 0
	start := time.Now()
	for i := 0; i < 1000; i++ {
		ch, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan flow %d: %v", i, err)
		}
		for range ch {
			totalPkts++
		}
	}
	elapsed := time.Since(start)

	expected := 1000 * 23 // 3hs + 0banner(empty) + 5cmd(4x2+1x1) + 4teardown + 9data = 23/flow
	if totalPkts != expected {
		t.Errorf("expected %d packets, got %d", expected, totalPkts)
	}
	t.Logf("planner 1000 sessions+data: %d packets in %v (%.0f pkts/s)", totalPkts, elapsed, float64(totalPkts)/elapsed.Seconds())
}

// TestFTPMTFL6k measures planner throughput for 6000 FTP flows (target: >= 100k pkts/s).
func TestFTPMTFL6k(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping perf in short mode")
	}
	p := NewPlanner()
	spec := coreFlowSpec()
	spec.Count = 1

	totalPkts := 0
	start := time.Now()
	for i := 0; i < 6000; i++ {
		ch, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan flow %d: %v", i, err)
		}
		for range ch {
			totalPkts++
		}
	}
	elapsed := time.Since(start)
	rate := float64(totalPkts) / elapsed.Seconds()

	t.Logf("MTFL6k: %d packets in %v (%.0f pkts/s)", totalPkts, elapsed, rate)
	if rate < 100000 {
		t.Errorf("throughput %.0f pkts/s < 100000 target", rate)
	}
}

// coreFlowSpec returns a minimal single-flow FTP spec for reuse.
func coreFlowSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 21,
		Count:   1,
		FTP: &core.FTPConfig{
			Banner: "220 ready",
			Commands: []core.FTPCommand{
				{Cmd: "USER test", Response: "331"},
				{Cmd: "PASS pw", Response: "230"},
				{Cmd: "QUIT", Response: "221"},
			},
		},
	}
}
