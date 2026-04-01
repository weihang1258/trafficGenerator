package core

import (
	"bytes"
	"testing"
)

func TestBuilder_BuildEthernet(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 6,
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Seq:      1000,
			Ack:      0,
			Flags:    0x02, // SYN
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check minimum size (Ethernet + IP + TCP = 14 + 20 + 20 = 54)
	if len(packet) < 54 {
		t.Errorf("Packet size = %d, want at least 54", len(packet))
	}

	// Check Ethernet header
	// Destination MAC
	if !bytes.Equal(packet[0:6], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) {
		t.Errorf("Wrong destination MAC")
	}
	// Source MAC
	if !bytes.Equal(packet[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("Wrong source MAC")
	}
	// EtherType (0x0800 = IPv4)
	if packet[12] != 0x08 || packet[13] != 0x00 {
		t.Errorf("Wrong EtherType")
	}
}

func TestBuilder_BuildUDP(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 17, // UDP
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: []byte("test payload"),
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check minimum size (Ethernet + IP + UDP = 14 + 20 + 8 = 42 + payload)
	if len(packet) < 42+len(config.Payload) {
		t.Errorf("Packet size = %d, want at least %d", len(packet), 42+len(config.Payload))
	}
}

func TestBuilder_BuildWithVLAN(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
			VLAN: &VLAN{
				ID:       100,
				Priority: 5,
			},
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 6,
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Flags:    0x02,
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// With VLAN, Ethernet header is 18 bytes instead of 14
	if len(packet) < 58 { // 18 + 20 + 20
		t.Errorf("Packet size = %d, want at least 58 (with VLAN)", len(packet))
	}

	// Check VLAN tag position (after 12 bytes of MACs)
	// VLAN TPID should be 0x8100
	if packet[12] != 0x81 || packet[13] != 0x00 {
		t.Errorf("Wrong VLAN TPID")
	}
}
