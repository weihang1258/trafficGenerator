package tcp

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "tcp" {
		t.Errorf("Name() = %s, want tcp", p.Name())
	}
}

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid source IP",
			spec: core.FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "missing source port",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 0,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "missing destination port",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPlanner_Plan(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		TCP: &core.TCPConfig{
			Handshake:   true,
			Termination: true,
			MSS:         1460,
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Collect all configs
	var configs []core.PacketConfig
	for config := range configChan {
		configs = append(configs, config)
	}

	// Should have at least handshake (3) + termination (4) = 7 packets
	if len(configs) < 7 {
		t.Errorf("Expected at least 7 configs, got %d", len(configs))
	}

	// Check first packet is SYN
	if configs[0].L4.Flags != 0x02 {
		t.Errorf("First packet should be SYN, flags = %x", configs[0].L4.Flags)
	}

	// Check flow ID is set
	if configs[0].FlowID == "" {
		t.Error("FlowID should be set")
	}
}

// TestPlanner_SYNCarriesMSSOption verifies the SYN packet carries an MSS TCP
// option derived from TCPConfig.MSS, plus SACK-Permitted.
func TestPlanner_SYNCarriesMSSOption(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 80,
		TCP: &core.TCPConfig{Handshake: true, Termination: false, MSS: 1460},
	}
	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	syn := configs[0]
	if syn.L4.Flags != 0x02 {
		t.Fatalf("first packet not SYN: flags=%x", syn.L4.Flags)
	}
	// Expect MSS (Kind=2, 4 bytes incl len) + SACK-Permitted (Kind=4).
	var sawMSS, sawSACK bool
	for _, o := range syn.L4.TCPOptions {
		if o.Kind == core.TCPOptMSS {
			sawMSS = true
			if len(o.Data) != 2 || o.Data[0] != 0x05 || o.Data[1] != 0xB4 {
				t.Errorf("MSS data = %x, want 05b4 (1460)", o.Data)
			}
		}
		if o.Kind == core.TCPOptSACKPermit {
			sawSACK = true
		}
	}
	if !sawMSS {
		t.Error("SYN missing MSS option")
	}
	if !sawSACK {
		t.Error("SYN missing SACK-Permitted option")
	}
}

func TestPlanner_PlanWithPayload(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: []byte("test payload data"),
		TCP: &core.TCPConfig{
			Handshake:   true,
			Termination: true,
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for config := range configChan {
		configs = append(configs, config)
	}

	// Should have more packets with payload
	// handshake (3) + data + ack + termination (4)
	if len(configs) < 9 {
		t.Errorf("Expected at least 9 configs with payload, got %d", len(configs))
	}
}
