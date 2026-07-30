package ike

// esp_integration_test.go — Integration tests verifying the builder can
// assemble a complete ESP frame (Ethernet + outer IP + ESP payload) from
// the PacketConfigs emitted by the IKE planner.
//
// These tests cross the planner→builder boundary (CLAUDE.md testing policy
// §4: integration tests, not just unit tests). They verify:
//   1. The builder produces a byte buffer for an ESP PacketConfig without
//      error.
//   2. The ESP SPI/Seq appear at the correct offset (after the 20-byte
//      outer IPv4 header).
//   3. The outer IP Protocol field = 50 (ESP).
//   4. The full frame is at least 60 bytes (Ethernet minimum).

import (
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestESP_Integration_BuilderProducesESPFrame(t *testing.T) {
	spec := espSpec()
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)

	b := core.NewBuilder()
	frame, err := b.Build(espPkt)
	if err != nil {
		t.Fatalf("builder.Build failed: %v", err)
	}
	if len(frame) < 60 {
		t.Errorf("frame length = %d, want >= 60 (Ethernet minimum)", len(frame))
	}

	// Ethernet: dst MAC (6) + src MAC (6) + EtherType (2) = 14 bytes.
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != core.EtherTypeIPv4 {
		t.Errorf("EtherType = 0x%04X, want 0x%04X (IPv4)", etherType, core.EtherTypeIPv4)
	}

	// Outer IPv4 header starts at offset 14. Protocol at offset 14+9 = 23.
	if frame[14] != 0x45 {
		t.Errorf("outer IP Version/IHL = 0x%02X, want 0x45", frame[14])
	}
	proto := frame[23]
	if proto != 50 {
		t.Errorf("outer IP Protocol = %d, want 50 (ESP)", proto)
	}

	// ESP SPI at offset 14+20 = 34, Seq at 38.
	spi := binary.BigEndian.Uint32(frame[34:38])
	if spi != spec.IKE.ESPDataPlane.SPI {
		t.Errorf("ESP SPI = 0x%08X, want 0x%08X", spi, spec.IKE.ESPDataPlane.SPI)
	}
	seq := binary.BigEndian.Uint32(frame[38:42])
	if seq != 1 {
		t.Errorf("ESP Seq = %d, want 1", seq)
	}
}

func TestESP_Integration_TunnelModeFrameSize(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.InnerPayloadSize = 100
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)

	b := core.NewBuilder()
	frame, err := b.Build(espPkt)
	if err != nil {
		t.Fatalf("builder.Build failed: %v", err)
	}
	// Minimum expected: Eth(14) + outer IP(20) + SPI(4) + Seq(4) + IV(16)
	//   + inner IP(20) + inner UDP(8) + inner data(100) + trailer(2..4)
	//   + ICV(16) = 204+ bytes.
	if len(frame) < 200 {
		t.Errorf("frame length = %d, want >= 200 for tunnel mode with 100B payload", len(frame))
	}
}
