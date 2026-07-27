package snmp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "snmp" {
		t.Errorf("Name() = %s, want snmp", p.Name())
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
			name: "valid v2c GetRequest",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing SNMP config",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
			},
			wantErr: true,
			errSub:  "SNMP config is required",
		},
		{
			name: "invalid SrcIP",
			spec: core.FlowSpec{
				SrcIP: "not-an-ip", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "SrcIP",
		},
		{
			name: "invalid DstIP",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "bad",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "DstIP",
		},
		{
			name: "invalid version 2",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   2,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "Version 2 is not a valid SNMP version",
		},
		{
			name: "invalid version 4",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   4,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "Version 4 is not a valid SNMP version",
		},
		{
			name: "v2c empty community rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "Community empty",
		},
		{
			name: "invalid PDUType 8",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   8,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "PDUType 8 not in supported list",
		},
		{
			name: "v3 priv without auth rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:       VersionSNMPv3,
					UserName:      "alice",
					AuthProtocol:  "none",
					PrivProtocol:  "aes128",
					PrivPassword:  "secret",
					PDUType:       PDUGetRequest,
					AuthoritativeEngineID: "80001F88",
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "auth before priv",
		},
		{
			name: "v3 invalid auth protocol",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:      VersionSNMPv3,
					UserName:     "alice",
					AuthProtocol: "rot13",
					AuthPassword: "pw",
					PDUType:      PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "AuthProtocol",
		},
		{
			name: "GetRequest with empty VarBinds rejected",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUGetRequest,
				},
			},
			wantErr: true,
			errSub:  "VarBinds empty",
		},
		{
			name: "TrapV2 with empty VarBinds accepted (planner synthesises)",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 162,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUSNMPv2Trap,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid OID format",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
				SrcPort: 12345, DstPort: 161,
				SNMP: &core.SNMPConfig{
					Version:   VersionSNMPv2c,
					Community: "public",
					PDUType:   PDUGetRequest,
					VarBinds: []core.SNMPVarBind{
						{Name: "1.3.x", Type: TagNull},
					},
				},
			},
			wantErr: true,
			errSub:  "VarBinds[0].Name",
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
		SrcPort: 12345, DstPort: 161,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SNMP: &core.SNMPConfig{
			Version:   VersionSNMPv2c,
			Community: "public",
			PDUType:   PDUGetRequest,
			RequestID: 1,
			VarBinds: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
			},
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for cfg := range configChan {
		configs = append(configs, cfg)
	}

	if len(configs) != 1 {
		t.Fatalf("Expected 1 config, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.L4.Protocol != "udp" {
		t.Errorf("Protocol = %s, want udp", cfg.L4.Protocol)
	}
	if cfg.L4.DstPort != 161 {
		t.Errorf("DstPort = %d, want 161", cfg.L4.DstPort)
	}
	if len(cfg.Payload) == 0 {
		t.Fatal("Payload empty")
	}
	if cfg.Payload[0] != TagSequence {
		t.Errorf("Payload[0] = 0x%02x, want 0x30 (SEQUENCE)", cfg.Payload[0])
	}
}

func TestPlanner_PlanWithResponse(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 161,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SNMP: &core.SNMPConfig{
			Version:   VersionSNMPv2c,
			Community: "public",
			PDUType:   PDUGetRequest,
			RequestID: 1,
			IsResponse: true,
			VarBinds: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
			},
			ResponseValues: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.1.0", Type: TagOctetString, StrValue: "Linux 5.10.0"},
			},
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for cfg := range configChan {
		configs = append(configs, cfg)
	}

	if len(configs) != 2 {
		t.Fatalf("Expected 2 configs (req + resp), got %d", len(configs))
	}

	if configs[0].Direction != "up" {
		t.Errorf("configs[0].Direction = %s, want up", configs[0].Direction)
	}
	if configs[1].Direction != "down" {
		t.Errorf("configs[1].Direction = %s, want down", configs[1].Direction)
	}
}

func TestPlanner_PlanTrapPort162(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.2", DstIP: "192.168.1.1",
		SrcPort: 12345,
		SrcMAC:  "11:22:33:44:55:66", DstMAC: "aa:bb:cc:dd:ee:ff",
		SNMP: &core.SNMPConfig{
			Version:   VersionSNMPv2c,
			Community: "public",
			PDUType:   PDUSNMPv2Trap,
			RequestID: 1,
			VarBinds: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.3.0", Type: TagTimeTicks, Value: []byte{0x00, 0x00, 0x00, 0x64}},
			},
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for cfg := range configChan {
		configs = append(configs, cfg)
	}

	if len(configs) != 1 {
		t.Fatalf("Expected 1 config, got %d", len(configs))
	}

	if configs[0].L4.DstPort != 162 {
		t.Errorf("Trap DstPort = %d, want 162 (default trap port)", configs[0].L4.DstPort)
	}
}

func TestPlanner_PlanContextCancel(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 161,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SNMP: &core.SNMPConfig{
			Version:     VersionSNMPv2c,
			Community:   "public",
			PDUType:     PDUGetRequest,
			RequestID:   1,
			RepeatCount: 1000,
			PollInterval: 10,
			VarBinds: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before drain

	configChan, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for cfg := range configChan {
		configs = append(configs, cfg)
	}

	// With pre-cancelled context, the goroutine should exit after the first
	// emit (which may already be in the buffer). At most 1 packet expected.
	if len(configs) > 1 {
		t.Errorf("Expected at most 1 packet after pre-cancelled ctx, got %d", len(configs))
	}
}
