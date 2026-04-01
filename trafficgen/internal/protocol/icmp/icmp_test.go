package icmp

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "icmp" {
		t.Errorf("Name() = %s, want icmp", p.Name())
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
			},
			wantErr: false,
		},
		{
			name: "invalid source IP",
			spec: core.FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
			},
			wantErr: true,
		},
		{
			name: "invalid destination IP",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "invalid",
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
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     TypeEchoRequest,
			Code:     0,
			Sequence: 1,
			Data:     []byte("test"),
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

	// Should have 2 packets (request + reply)
	if len(configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(configs))
	}

	// Check first packet is Echo Request
	if configs[0].L3.Protocol != 1 {
		t.Errorf("Protocol = %d, want 1 (ICMP)", configs[0].L3.Protocol)
	}

	// Check first packet direction
	if configs[0].Direction != "up" {
		t.Errorf("First packet direction = %s, want up", configs[0].Direction)
	}

	// Check second packet is Echo Reply
	if configs[1].Direction != "down" {
		t.Errorf("Second packet direction = %s, want down", configs[1].Direction)
	}
}

func TestPlanner_PlanEchoReply(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     TypeEchoReply,
			Code:     0,
			Sequence: 1,
			Data:     []byte("test"),
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

	// Should have 1 packet (reply only, no auto-response)
	if len(configs) != 1 {
		t.Errorf("Expected 1 config for reply, got %d", len(configs))
	}
}

func TestBuildICMPPayload(t *testing.T) {
	config := &core.ICMPConfig{
		Type:     TypeEchoRequest,
		Code:     0,
		Sequence: 123,
		Data:     []byte("test data"),
	}

	payload := buildICMPPayload(config)

	// Check minimum size (8 byte header + data)
	if len(payload) < 8+len(config.Data) {
		t.Errorf("Payload too short: %d bytes", len(payload))
	}

	// Check type
	if payload[0] != TypeEchoRequest {
		t.Errorf("Type = %d, want %d", payload[0], TypeEchoRequest)
	}

	// Check code
	if payload[1] != 0 {
		t.Errorf("Code = %d, want 0", payload[1])
	}

	// Check sequence (bytes 6-7)
	seq := uint16(payload[6])<<8 | uint16(payload[7])
	if seq != 123 {
		t.Errorf("Sequence = %d, want 123", seq)
	}
}

func TestCalculateChecksum(t *testing.T) {
	// Test with known data
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // Echo request with zero checksum

	checksum := calculateChecksum(data)

	// Checksum should not be zero
	if checksum == 0 {
		t.Error("Checksum should not be zero")
	}
}
