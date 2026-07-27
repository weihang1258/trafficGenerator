package l2tp

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "l2tp" {
		t.Errorf("Name() = %s, want l2tp", p.Name())
	}
}

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
		errSub  string
	}{
		{
			name: "valid v2 SCCRQ",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Role:      "lac",
					HostName:  "vpn1.example.net",
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: false,
		},
		{
			name: "missing L2TP config",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
			},
			wantErr: true,
			errSub:  "L2TP config is required",
		},
		{
			name: "invalid SrcIP",
			spec: core.FlowSpec{
				SrcIP: "not-an-ip", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "SrcIP",
		},
		{
			name: "invalid DstIP",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "bad",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "DstIP",
		},
		{
			name: "Version 4 rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   4,
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "Version 4 not in supported list",
		},
		{
			name: "Version 1 rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   1,
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "Version 1 not in supported list",
		},
		{
			name: "Role invalid rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Role:      "router",
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "Role",
		},
		{
			name: "v3 Cookie length 5 invalid",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv3,
					Cookie:    []byte{1, 2, 3, 4, 5},
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "Cookie length 5",
		},
		{
			name: "v3 Cookie length 4 valid",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv3,
					Cookie:    []byte{1, 2, 3, 4},
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: false,
		},
		{
			name: "CustomAVP exceeding 4095 rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version: VersionL2TPv2,
					CustomAVPs: []core.L2TPAVP{
						{AttrType: 99, Value: make([]byte, 4090)},
					},
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
				},
			},
			wantErr: true,
			errSub:  "exceeds max",
		},
		{
			name: "unknown step type rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Scenarios: []core.L2TPStep{{Type: "bogus"}},
				},
			},
			wantErr: true,
			errSub:  "not in supported list",
		},
		{
			name: "PPPFrames Protocol=0 rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 1701,
				L2TP: &core.L2TPConfig{
					Version:   VersionL2TPv2,
					Scenarios: []core.L2TPStep{{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN}, {Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN}},
					PPPFrames: []core.L2TPPPPFrame{
						{Protocol: 0, Data: []byte{1, 2, 3}},
					},
				},
			},
			wantErr: true,
			errSub:  "PPPFrames[0].Protocol 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("err=%v, want contains %q", err, tt.errSub)
				}
			}
		})
	}
}

func TestPlanner_Plan(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2,
			Role:    "lac",
			Scenarios: []core.L2TPStep{
				{Type: stepSCCRQ},
				{Type: stepSCCRP},
				{Type: stepSCCCN},
				{Type: stepOCRQ},
				{Type: stepOCRP},
				{Type: stepOCCN},
			},
		},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}

	if len(configs) != 6 {
		t.Fatalf("Expected 6 configs (3 tunnel + 3 session), got %d", len(configs))
	}

	// All packets should be UDP. DstPort=1701 for "up" (LAC->LNS), SrcPort=1701 for "down" (LNS->LAC).
	for i, cfg := range configs {
		if cfg.L4.Protocol != "udp" {
			t.Errorf("configs[%d].L4.Protocol = %s, want udp", i, cfg.L4.Protocol)
		}
		if len(cfg.Payload) == 0 {
			t.Errorf("configs[%d].Payload empty", i)
		}
	}

	// LAC side: SCCRQ/SCCCN/OCRQ/OCCN are LAC-originated => "up".
	// SCCRP/OCRP are LNS-originated replies => "down".
	wantDirs := []string{"up", "down", "up", "up", "down", "up"}
	for i, want := range wantDirs {
		if configs[i].Direction != want {
			t.Errorf("configs[%d].Direction = %s, want %s", i, configs[i].Direction, want)
		}
	}

	// For "up" packets, DstPort should be 1701 (LAC->LNS). For "down"
	// packets, SrcPort should be 1701 (LNS->LAC).
	for i, cfg := range configs {
		if cfg.Direction == "up" {
			if cfg.L4.DstPort != 1701 {
				t.Errorf("configs[%d] (up).DstPort = %d, want 1701", i, cfg.L4.DstPort)
			}
		} else {
			if cfg.L4.SrcPort != 1701 {
				t.Errorf("configs[%d] (down).SrcPort = %d, want 1701", i, cfg.L4.SrcPort)
			}
		}
	}
}

// TestPlanner_PlanContextCancel verifies that a cancelled context terminates
// the planner goroutine promptly.
func TestPlanner_PlanContextCancel(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2,
			Role:    "lac",
			Scenarios: []core.L2TPStep{
				{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
				{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}
	// At most 1 packet should be emitted before ctx-cancel is observed.
	if len(configs) > 1 {
		t.Errorf("Expected at most 1 packet after pre-cancelled ctx, got %d", len(configs))
	}
}

// TestPlanner_PlanV3ControlHeaderSize verifies L2TPv3 control messages have
// a 14-byte header (vs v2's 12) per RFC 3931 §3.2.
func TestPlanner_PlanV3ControlHeaderSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		L2TP: &core.L2TPConfig{
			Version:   VersionL2TPv3,
			Role:      "lac",
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
		},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}
	payload := configs[0].Payload
	if len(payload) < v3ControlHeaderSize {
		t.Fatalf("payload too short for v3 header: %d bytes", len(payload))
	}
	// Verify Length field matches total.
	lengthField := binary.BigEndian.Uint16(payload[2:4])
	if int(lengthField) != len(payload) {
		t.Errorf("v3 Length field = %d, want %d", lengthField, len(payload))
	}
}