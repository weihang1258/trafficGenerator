package grpc

// F3 regression tests: the gRPC planner must honor spec.TCP configuration
// (WindowSize, MSS) for the TCP handshake and teardown, like other TCP-based
// planners. Pre-fix: WindowSize was hardcoded to 65535, ignoring
// spec.TCP.WindowSize.

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestF3_TCPWindowSizeHonored verifies that spec.TCP.WindowSize is reflected
// in the emitted TCP packets (SYN, SYN-ACK, ACK, and data segments).
// Pre-fix: winSize was hardcoded to 65535 regardless of spec.TCP.WindowSize.
func TestF3_TCPWindowSizeHonored(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 8604,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{
			WindowSize: 32768,
			MSS:        1400,
		},
		GRPC: &core.GRPCConfig{
			Service: "test.Service",
			Method:  "Ping",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) == 0 {
		t.Fatalf("no packets emitted")
	}

	const wantWin = uint16(32768)
	for i, c := range cfgs {
		if c.L4.Protocol != "tcp" {
			continue
		}
		if c.L4.WindowSize != wantWin {
			t.Errorf("packet[%d] (%s) L4.WindowSize=%d, want %d (spec.TCP.WindowSize should be honored)",
				i, c.Direction, c.L4.WindowSize, wantWin)
		}
	}
}

// TestF3_TCPMSSHonored verifies that spec.TCP.MSS is reflected in the SYN
// packet's TCP options. This was already working but is tested here to
// prevent regression.
func TestF3_TCPMSSHonored(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 8604,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{
			MSS: 536,
		},
		GRPC: &core.GRPCConfig{
			Service: "test.Service",
			Method:  "Ping",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	// Find the SYN packet (first up-direction packet with flags 0x02).
	var synCfg *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Direction == "up" && cfgs[i].L4.Flags == 0x02 {
			synCfg = &cfgs[i]
			break
		}
	}
	if synCfg == nil {
		t.Fatalf("no SYN packet found")
	}

	// SYN must carry MSS option with value 536.
	const wantMSS = uint16(536)
	foundMSS := false
	for _, opt := range synCfg.L4.TCPOptions {
		if opt.Kind == core.TCPOptMSS && len(opt.Data) == 2 {
			got := uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
			if got == wantMSS {
				foundMSS = true
			}
		}
	}
	if !foundMSS {
		t.Errorf("SYN packet does not carry MSS option with value %d", wantMSS)
	}
}

// TestF3_TCPDefaultWindowSize verifies that when spec.TCP is nil or
// WindowSize is 0, the default 65535 is used (guard against the fix
// breaking the default path).
func TestF3_TCPDefaultWindowSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 8604,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		GRPC: &core.GRPCConfig{
			Service: "test.Service",
			Method:  "Ping",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	const wantDefault = uint16(65535)
	for i, c := range cfgs {
		if c.L4.Protocol != "tcp" {
			continue
		}
		if c.L4.WindowSize != wantDefault {
			t.Errorf("packet[%d] L4.WindowSize=%d, want default %d", i, c.L4.WindowSize, wantDefault)
		}
	}
}
