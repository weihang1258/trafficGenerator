// 外部测试包：ntp 链的字节级对比需要 legacy ntp.NewPlanner 与 chain
// （internal/protocol/ntp + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("ntp")）。
package layers_test

import (
	"bytes"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/ntp"
)

// ntpSpec builds a minimal NTP flow spec. Version and Mode must be explicit:
// legacy Validate rejects Version 0 (RFC 5905 §7.3) and reserved Mode 0, so
// the production path (strategy_convert.go defaults Version 4 / Mode 3) never
// reaches the planner with either — the chain keeps the same contract.
func ntpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 40000,
		DstPort: 123,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		NTP:     &core.NTPConfig{Mode: ntp.ModeClient, Version: 4},
	}
}

// maskNTPVolatile zeroes the volatile fields that differ between two
// independent runs: IPv4 ID (18-19), IP checksum (24-25), and — because a
// different payload makes the UDP checksum differ too — the UDP checksum
// (40-41). The four 8-byte NTP timestamps live at header offsets 16-47,
// which is packet offset 58-89 (14 Eth + 20 IP + 8 UDP). Everything else
// must be byte-identical.
func maskNTPVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 25 {
		out[18], out[19] = 0, 0 // IPID
		out[24], out[25] = 0, 0 // IP header checksum
	}
	if len(out) > 41 {
		out[40], out[41] = 0, 0 // UDP checksum (covers volatile payload)
	}
	for i := 58; i < 90 && i+8 <= len(out); i += 8 {
		for j := 0; j < 8; j++ {
			out[i+j] = 0
		}
	}
	return out
}

// assertNTPIdentical builds both packets and compares wire bytes after
// masking the volatile fields.
func assertNTPIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
	t.Helper()
	b := core.NewBuilder()
	cb, err := b.Build(chain)
	if err != nil {
		t.Fatalf("Build(chain[%d]): %v", idx, err)
	}
	lb, err := b.Build(legacy)
	if err != nil {
		t.Fatalf("Build(legacy[%d]): %v", idx, err)
	}
	if !bytes.Equal(maskNTPVolatile(cb), maskNTPVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// TestChainPlanner_NTP_Client verifies the [ip→udp→ntp] chain emits one up
// datagram carrying the NTP client request (Mode=3), byte-identical to the
// legacy ntp.NewPlanner (modulo IPID/timestamps).
func TestChainPlanner_NTP_Client(t *testing.T) {
	spec := ntpSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 40000 || chain[0].L4.DstPort != 123 {
		t.Errorf("L4 = %s %d/%d, want udp 40000/123", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("L3.Protocol = %d, want %d (UDP 17)", chain[0].L3.Protocol, core.ProtocolUDP)
	}
	if len(chain[0].Payload) != ntp.NTPHeaderLen {
		t.Errorf("payload len = %d, want %d (48-byte NTP header)", len(chain[0].Payload), ntp.NTPHeaderLen)
	}
	// LI(0)|VN(4)|Mode(3) → 0x23.
	if chain[0].Payload[0] != 0x23 {
		t.Errorf("NTP header byte 0 = 0x%02x, want 0x23 (VN=4 Mode=3)", chain[0].Payload[0])
	}
	assertNTPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_NTP_ClientResponse verifies IsResponse adds the down
// datagram (Mode=4, OriginTS echoes request TransmitTS), matching legacy.
func TestChainPlanner_NTP_ClientResponse(t *testing.T) {
	spec := ntpSpec()
	spec.NTP.IsResponse = true
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	if chain[0].Direction != "up" || chain[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down", chain[0].Direction, chain[1].Direction)
	}
	// Response: server ports (123→40000), Mode=4 (0x24 with VN=4).
	if chain[1].L4.SrcPort != 123 || chain[1].L4.DstPort != 40000 {
		t.Errorf("response ports = %d/%d, want 123/40000", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	if chain[1].L2.SrcMAC != "11:22:33:44:55:66" || chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("response MACs = %s→%s, want swapped", chain[1].L2.SrcMAC, chain[1].L2.DstMAC)
	}
	// Response is built from the same cfg (Mode stays 3 — legacy
	// buildServerResponse does not rewrite the mode byte; only the explicit
	// ModeServer mode emits 0x24). Assert the OriginTS echo instead.
	if chain[1].Payload[0] != 0x23 {
		t.Errorf("response header byte 0 = 0x%02x, want 0x23 (Mode=3 preserved)", chain[1].Payload[0])
	}
	if !bytes.Equal(chain[0].Payload[40:48], chain[1].Payload[24:32]) {
		t.Errorf("response OriginTS (24:32) does not echo request TransmitTS (40:48)")
	}
	for i := 0; i < 2; i++ {
		assertNTPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_NTP_Broadcast verifies broadcast mode (Mode=5): repeat
// loop with distinct TransmitTS per iteration, ports NOT swapped (legacy
// marks down but keeps endpoints), matching legacy bytes.
func TestChainPlanner_NTP_Broadcast(t *testing.T) {
	spec := ntpSpec()
	spec.NTP.Mode = ntp.ModeBroadcast
	spec.NTP.RepeatCount = 3
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3", len(chain))
	}
	for i := 0; i < 3; i++ {
		if chain[i].Direction != "up" {
			t.Errorf("broadcast %d direction = %s, want up (legacy down keeps endpoints)", i, chain[i].Direction)
		}
		// Broadcast keeps the spec endpoints (no swap).
		if chain[i].L4.SrcPort != 40000 || chain[i].L4.DstPort != 123 {
			t.Errorf("broadcast %d ports = %d/%d, want 40000/123", i, chain[i].L4.SrcPort, chain[i].L4.DstPort)
		}
		if chain[i].Payload[0] != 0x25 {
			t.Errorf("broadcast %d header byte 0 = 0x%02x, want 0x25 (VN=4 Mode=5)", i, chain[i].Payload[0])
		}
		assertNTPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_NTP_SymmetricActive verifies symmetric-active mode
// (Mode=1) with IsResponse: the peer reply (Mode=2) is a down event with
// swapped endpoints, matching legacy bytes.
func TestChainPlanner_NTP_SymmetricActive(t *testing.T) {
	spec := ntpSpec()
	spec.NTP.Mode = ntp.ModeSymmetricActive
	spec.NTP.IsResponse = true
	spec.NTP.RepeatCount = 2
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (2 iterations × request+reply)", len(chain))
	}
	if chain[0].Payload[0] != 0x21 || chain[1].Payload[0] != 0x22 {
		t.Errorf("active/passive header bytes = 0x%02x/0x%02x, want 0x21/0x22", chain[0].Payload[0], chain[1].Payload[0])
	}
	if chain[1].L4.SrcPort != 123 || chain[1].L4.DstPort != 40000 {
		t.Errorf("peer reply ports = %d/%d, want 123/40000", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	for i := 0; i < 4; i++ {
		assertNTPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_NTP_SymmetricPassive verifies symmetric-passive mode
// (Mode=2): legacy 把主报文标 "down" 但端点并不换向（planner.go:326-329
// emit 用 spec 源端点），链必须用 Up=true 保持相同线上字节；peer 回复
// 是 Up=false（真正换向）。
func TestChainPlanner_NTP_SymmetricPassive(t *testing.T) {
	spec := ntpSpec()
	spec.NTP.Mode = ntp.ModeSymmetricPassive
	spec.NTP.IsResponse = true
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2 (passive + peer reply)", len(chain))
	}
	if chain[0].Payload[0] != 0x22 || chain[1].Payload[0] != 0x21 {
		t.Errorf("passive/peer header bytes = 0x%02x/0x%02x, want 0x22/0x21", chain[0].Payload[0], chain[1].Payload[0])
	}
	// 主报文：legacy 标 down 但不换端点 → 线上 40000→123（与 up 相同）。
	if chain[0].L4.SrcPort != 40000 || chain[0].L4.DstPort != 123 {
		t.Errorf("passive main ports = %d/%d, want 40000/123 (未换向)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// peer 回复：真正换向 123→40000。
	if chain[1].L4.SrcPort != 123 || chain[1].L4.DstPort != 40000 {
		t.Errorf("peer reply ports = %d/%d, want 123/40000 (换向)", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	for i := 0; i < 2; i++ {
		assertNTPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_NTP_Control verifies control mode (Mode=6): 12-byte
// control header, sequence increments across repeats, matching legacy bytes.
func TestChainPlanner_NTP_Control(t *testing.T) {
	spec := ntpSpec()
	spec.NTP.Mode = ntp.ModeControl
	spec.NTP.Sequence = 7
	spec.NTP.RepeatCount = 2
	spec.NTP.RequestCode = 2
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)
	legacy := collectPlanner(t, ntp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// Control header: byte 1 = R(0)|E(0)|M(0)|OpCode(2) → 0x02; seq at 2-3.
	if chain[0].Payload[0]&0x07 != 6 {
		t.Errorf("control mode byte = 0x%02x, want Mode=6", chain[0].Payload[0])
	}
	seq0 := uint16(chain[0].Payload[2])<<8 | uint16(chain[0].Payload[3])
	seq1 := uint16(chain[1].Payload[2])<<8 | uint16(chain[1].Payload[3])
	if seq0 != 7 || seq1 != 8 {
		t.Errorf("control sequences = %d/%d, want 7/8", seq0, seq1)
	}
	for i := 0; i < 2; i++ {
		assertNTPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_NTP_DefaultPorts verifies the chain defaults dst port to
// 123 and src port to an ephemeral (30000-59999) when the spec omits them.
func TestChainPlanner_NTP_DefaultPorts(t *testing.T) {
	spec := ntpSpec()
	spec.SrcPort = 0
	spec.DstPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("ntp"), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L4.DstPort != 123 {
		t.Errorf("dst port = %d, want 123 (defaulted)", chain[0].L4.DstPort)
	}
	if chain[0].L4.SrcPort < 30000 || chain[0].L4.SrcPort > 59999 {
		t.Errorf("src port = %d, want ephemeral in [30000, 59999]", chain[0].L4.SrcPort)
	}
}

// TestChainPlanner_NTP_ValidateNegative mirrors the legacy Validate contract:
// nil NTP config now defaults (P0b-2), bad version, reserved mode 0, bad MAC
// length must fail.
func TestChainPlanner_NTP_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("ntp")

	spec := ntpSpec()
	spec.NTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(nil NTP config) = %v, want nil (default flow, P0b-2)", err)
	}

	spec = ntpSpec()
	spec.NTP.Version = 7
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Version 7) = nil, want error")
	}

	spec = ntpSpec()
	spec.NTP.Mode = ntp.ModeReserved
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Mode 0 reserved) = nil, want error")
	}

	spec = ntpSpec()
	spec.NTP.MAC = make([]byte, 8)
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(MAC len 8) = nil, want error (must be 0/16/20)")
	}
}
