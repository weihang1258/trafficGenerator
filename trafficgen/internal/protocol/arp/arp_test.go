package arp

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "arp" {
		t.Errorf("Name() = %s, want arp", p.Name())
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
				SrcMAC:  "aa:bb:cc:dd:ee:ff",
				ARP: &core.ARPConfig{
					Operation: OperationRequest,
				},
			},
			wantErr: false,
		},
		{
			name: "missing ARP config",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
			},
			wantErr: true,
		},
		{
			name: "invalid source IP",
			spec: core.FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				ARP: &core.ARPConfig{
					Operation: OperationRequest,
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
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		ARP: &core.ARPConfig{
			Operation: OperationRequest,
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

	// Check first packet is request
	if configs[0].L2.EtherType != 0x0806 {
		t.Errorf("EtherType = %x, want 0x0806", configs[0].L2.EtherType)
	}

	// Check destination MAC is broadcast for request
	if configs[0].L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("DstMAC should be broadcast for ARP request")
	}

	// Check payload size (28 bytes for ARP)
	if len(configs[0].Payload) != 28 {
		t.Errorf("Payload size = %d, want 28", len(configs[0].Payload))
	}
}

func TestPlanner_PlanReply(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		ARP: &core.ARPConfig{
			Operation: OperationReply,
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

	// Should have 1 packet (reply only)
	if len(configs) != 1 {
		t.Errorf("Expected 1 config for reply, got %d", len(configs))
	}
}

func TestBuildARPPacket(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		ARP: &core.ARPConfig{
			Operation: OperationRequest,
		},
	}

	packet := buildARPPacket(spec)

	// Check size
	if len(packet) != 28 {
		t.Errorf("Packet size = %d, want 28", len(packet))
	}

	// Check hardware type (Ethernet = 1)
	if packet[0] != 0x00 || packet[1] != 0x01 {
		t.Errorf("Hardware type should be 1 (Ethernet)")
	}

	// Check protocol type (IPv4 = 0x0800)
	if packet[2] != 0x08 || packet[3] != 0x00 {
		t.Errorf("Protocol type should be 0x0800 (IPv4)")
	}

	// Check operation
	if packet[6] != 0x00 || packet[7] != 0x01 {
		t.Errorf("Operation should be 1 (Request)")
	}
}
