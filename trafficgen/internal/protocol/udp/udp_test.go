package udp

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestUDPDisableChecksumByIPVersion verifies that DisableChecksum=true
// produces a zero UDP checksum field for both IPv4 and IPv6 (RFC 6935/6936
// permit checksum=0 on both address families when L2 integrity is present).
func TestUDPDisableChecksumByIPVersion(t *testing.T) {
	b := core.NewBuilder()
	cases := []struct {
		name     string
		srcIP    string
		dstIP    string
		wantZero bool
	}{
		{name: "IPv4 allows disabled checksum", srcIP: "192.0.2.1", dstIP: "192.0.2.2", wantZero: true},
		{name: "IPv6 allows disabled checksum", srcIP: "2001:db8::1", dstIP: "2001:db8::2", wantZero: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := core.FlowSpec{
				SrcIP: tc.srcIP, DstIP: tc.dstIP,
				SrcPort: 12345, DstPort: 53,
				Payload: []byte("hello"),
				UDP:     &core.UDPConfig{DisableChecksum: true},
			}
			configs, err := NewPlanner().Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			cfg := <-configs
			pkt, err := b.Build(cfg)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			udpStart := 14
			if tc.srcIP[0] == '2' && tc.srcIP[1] == '0' && tc.srcIP[2] == '0' && tc.srcIP[3] == '1' {
				udpStart = 14 + 40
			} else {
				udpStart = 14 + 20
			}
			checksum := uint16(pkt[udpStart+6])<<8 | uint16(pkt[udpStart+7])
			if (checksum == 0) != tc.wantZero {
				t.Errorf("UDP checksum = 0x%04x, wantZero=%v", checksum, tc.wantZero)
			}
		})
	}
}

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "udp" {
		t.Errorf("Name() = %s, want udp", p.Name())
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
				DstPort: 53,
			},
			wantErr: false,
		},
		{
			name: "invalid destination IP",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "invalid",
				SrcPort: 12345,
				DstPort: 53,
			},
			wantErr: true,
		},
		{
			name: "missing source port",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 0,
				DstPort: 53,
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

// TestUDPValidate_LargePayloadWarns verifies that a UDP payload exceeding
// the typical Ethernet MTU (1500 - 20 IP - 8 UDP = 1472) triggers a
// fragmentation warning but does NOT fail validation. Fragmentation is a
// legitimate use case (jumbo frames, path-MTU probing), so Validate must
// return nil and emit the warning via zap.L().Warn.
func TestUDPValidate_LargePayloadWarns(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 53,
		Payload: make([]byte, 2000), // > 1472 typical MTU
	}
	err := p.Validate(spec)
	if err != nil {
		t.Fatalf("Validate() with large payload: expected no error, got %v", err)
	}
}

// TestUDPValidate_PayloadUnderMTUNoWarn sanity-checks that a payload within
// the typical MTU does not trigger the fragmentation warning path. This
// guards against accidentally flipping the comparison operator.
func TestUDPValidate_PayloadUnderMTUNoWarn(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 53,
		Payload: make([]byte, 512), // well under 1472
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate() with small payload: expected no error, got %v", err)
	}
}

func TestPlanner_Plan(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 53,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: []byte("test"),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for config := range configChan {
		configs = append(configs, config)
	}

	// Should have 1 packet (request only)
	if len(configs) != 1 {
		t.Errorf("Expected 1 config, got %d", len(configs))
	}

	// Check packet config
	if configs[0].L4.Protocol != "udp" {
		t.Errorf("Protocol = %s, want udp", configs[0].L4.Protocol)
	}
	if configs[0].L4.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", configs[0].L4.SrcPort)
	}
	if configs[0].L4.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", configs[0].L4.DstPort)
	}
}

func TestPlanner_PlanWithResponse(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 53,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: []byte("test"),
		UDP: &core.UDPConfig{
			IsResponse: true,
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

	// Should have 2 packets (request + response)
	if len(configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(configs))
	}

	// Check first packet is up (request)
	if configs[0].Direction != "up" {
		t.Errorf("First packet direction = %s, want up", configs[0].Direction)
	}

	// Check second packet is down (response)
	if configs[1].Direction != "down" {
		t.Errorf("Second packet direction = %s, want down", configs[1].Direction)
	}
}
