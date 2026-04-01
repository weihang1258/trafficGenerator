package dns

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "dns" {
		t.Errorf("Name() = %s, want dns", p.Name())
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
				DNS: &core.DNSConfig{
					Domain:    "example.com",
					QueryType: 1,
				},
			},
			wantErr: false,
		},
		{
			name: "missing DNS config",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 53,
			},
			wantErr: true,
		},
		{
			name: "missing domain",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 53,
				DNS: &core.DNSConfig{
					QueryType: 1,
				},
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
		DstPort: 53,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		DNS: &core.DNSConfig{
			Domain:    "example.com",
			QueryType: 1, // A record
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

	// Should have 1 packet (query only)
	if len(configs) != 1 {
		t.Errorf("Expected 1 config, got %d", len(configs))
	}

	// Check packet config
	if configs[0].L4.Protocol != "udp" {
		t.Errorf("Protocol = %s, want udp", configs[0].L4.Protocol)
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
		DNS: &core.DNSConfig{
			Domain:     "example.com",
			QueryType:  1,
			Response:   true,
			ResponseIP: "192.168.1.100",
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

	// Should have 2 packets (query + response)
	if len(configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(configs))
	}
}

func TestBuildDNSQuery(t *testing.T) {
	query := buildDNSQuery("example.com", 1)

	// Check minimum size (12 byte header + question)
	if len(query) < 20 {
		t.Errorf("Query too short: %d bytes", len(query))
	}

	// Check transaction ID
	if query[0] != 0x12 || query[1] != 0x34 {
		t.Errorf("Transaction ID should be 0x1234")
	}
}

func TestEncodeDomainName(t *testing.T) {
	tests := []struct {
		domain   string
		expected []byte
	}{
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"a.b.c", []byte{1, 'a', 1, 'b', 1, 'c', 0}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := encodeDomainName(tt.domain)
			if len(result) != len(tt.expected) {
				t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
			}
		})
	}
}
