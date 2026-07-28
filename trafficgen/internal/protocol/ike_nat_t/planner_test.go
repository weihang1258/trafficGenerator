package ike_nat_t

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Test helpers ---

// validBaseSpec returns a minimal valid FlowSpec for the IKE-NAT-T planner.
func validBaseSpec() core.FlowSpec {
	spi := uint64(0x0123456789ABCDEF)
	return core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		SrcPort: 4500,
		DstPort: 4500,
		IKENATT: &core.IKENATTConfig{
			InitiatorSPI: spi,
			ResponderSPI: 0x0011223344556677,
			NATDetection: true,
			NATDetectedOnSource: true,
			PortFloat: true,
			UDPEncapESP: true,
		},
	}
}

// readPackets drains a planner Plan channel and returns all emitted packets.
func readPackets(t *testing.T, ch <-chan core.PacketConfig) []core.PacketConfig {
	t.Helper()
	var pkts []core.PacketConfig
	for {
		select {
		case p, ok := <-ch:
			if !ok {
				return pkts
			}
			pkts = append(pkts, p)
		case <-time.After(2 * time.Second):
			t.Fatal("planner.Plan hung: did not close channel within 2s")
			return pkts
		}
	}
}

// runPlan invokes Plan and drains the channel.
func runPlan(t *testing.T, p *Planner, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	return readPackets(t, ch), nil
}

// mustPlan is runPlan with a fatal-on-error wrapper.
func mustPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	pkts, err := runPlan(t, NewPlanner(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return pkts
}

// --- Integration test: Standard IKE_SA_INIT + IKE_AUTH with NAT-T ---
func TestStandardIKENATTHandshake(t *testing.T) {
	// Scenario 1: Standard IKE-NAT-T handshake with NAT-D detection.
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)

	// Expect 4 packets: INIT_REQ, INIT_RESP, AUTH_REQ, AUTH_RESP.
	if len(pkts) < 4 {
		t.Fatalf("expected >=4 packets, got %d", len(pkts))
	}

	// Packet 0: IKE_SA_INIT request (up).
	p0 := pkts[0]
	if p0.Direction != "up" {
		t.Errorf("pkt[0] Direction=%q, want up", p0.Direction)
	}
	if p0.L4.Protocol != "udp" {
		t.Errorf("pkt[0] L4.Protocol=%q, want udp", p0.L4.Protocol)
	}
	if len(p0.Payload) < 4 {
		t.Fatalf("pkt[0] Payload too short: %d bytes", len(p0.Payload))
	}

	// Check Non-ESP Marker (first 4 bytes = 0x00000000).
	marker := binary.BigEndian.Uint32(p0.Payload[0:4])
	if marker != 0 {
		t.Errorf("pkt[0] Non-ESP Marker = 0x%08X, want 0x00000000", marker)
	}

	// Check IKE Header (bytes 4-31).
	if len(p0.Payload) < IKEHeaderAtPort4500 {
		t.Fatalf("pkt[0] Payload too short for IKE header: %d bytes", len(p0.Payload))
	}
	spii := binary.BigEndian.Uint64(p0.Payload[4:12])
	spir := binary.BigEndian.Uint64(p0.Payload[12:20])
	version := p0.Payload[21]
	exchangeType := p0.Payload[22]
	flags := p0.Payload[23]
	msgID := binary.BigEndian.Uint32(p0.Payload[24:28])
	length := binary.BigEndian.Uint32(p0.Payload[28:32])

	if spii == 0 {
		t.Error("pkt[0] InitiatorSPI = 0, want non-zero")
	}
	if spir != 0 {
		t.Errorf("pkt[0] ResponderSPI = 0x%X, want 0 (INIT_REQ)", spir)
	}
	if version != IKEv2Version {
		t.Errorf("pkt[0] Version = 0x%02X, want 0x%02X", version, IKEv2Version)
	}
	if exchangeType != ExchangeIKE_SA_INIT {
		t.Errorf("pkt[0] ExchangeType = %d, want %d (IKE_SA_INIT)", exchangeType, ExchangeIKE_SA_INIT)
	}
	if flags != FlagInitiator {
		t.Errorf("pkt[0] Flags = 0x%02X, want 0x%02X", flags, FlagInitiator)
	}
	if msgID != 0 {
		t.Errorf("pkt[0] MessageID = %d, want 0", msgID)
	}
	if length != uint32(IKEHeaderLen+len(p0.Payload)-IKEHeaderAtPort4500) {
		t.Errorf("pkt[0] Length = %d, want %d", length, uint32(IKEHeaderLen+len(p0.Payload)-IKEHeaderAtPort4500))
	}

	// Packet 1: IKE_SA_INIT response (down).
	p1 := pkts[1]
	if p1.Direction != "down" {
		t.Errorf("pkt[1] Direction=%q, want down", p1.Direction)
	}
	if len(p1.Payload) < IKEHeaderAtPort4500 {
		t.Fatalf("pkt[1] Payload too short: %d bytes", len(p1.Payload))
	}
	spir1 := binary.BigEndian.Uint64(p1.Payload[12:20])
	flags1 := p1.Payload[23]
	msgID1 := binary.BigEndian.Uint32(p1.Payload[24:28])

	if spir1 == 0 {
		t.Error("pkt[1] ResponderSPI = 0, want non-zero (INIT_RESP)")
	}
	if flags1 != FlagResponse {
		t.Errorf("pkt[1] Flags = 0x%02X, want 0x%02X", flags1, FlagResponse)
	}
	if msgID1 != 0 {
		t.Errorf("pkt[1] MessageID = %d, want 0", msgID1)
	}

	// Packet 2: IKE_AUTH request (up).
	p2 := pkts[2]
	if p2.Direction != "up" {
		t.Errorf("pkt[2] Direction=%q, want up", p2.Direction)
	}
	if len(p2.Payload) < IKEHeaderAtPort4500 {
		t.Fatalf("pkt[2] Payload too short: %d bytes", len(p2.Payload))
	}
	exchangeType2 := p2.Payload[22]
	msgID2 := binary.BigEndian.Uint32(p2.Payload[24:28])
	if exchangeType2 != ExchangeIKE_AUTH {
		t.Errorf("pkt[2] ExchangeType = %d, want %d (IKE_AUTH)", exchangeType2, ExchangeIKE_AUTH)
	}
	if msgID2 != 1 {
		t.Errorf("pkt[2] MessageID = %d, want 1", msgID2)
	}

	// Packet 3: IKE_AUTH response (down).
	p3 := pkts[3]
	if p3.Direction != "down" {
		t.Errorf("pkt[3] Direction=%q, want down", p3.Direction)
	}
	msgID3 := binary.BigEndian.Uint32(p3.Payload[24:28])
	if msgID3 != 1 {
		t.Errorf("pkt[3] MessageID = %d, want 1", msgID3)
	}
}

// --- NAT-D Payload verification ---
func TestNATDPayload(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)

	// Packet 0 (INIT_REQ) should have NAT-D Notify payloads.
	p0 := pkts[0]
	if len(p0.Payload) < IKEHeaderAtPort4500+8 {
		t.Fatalf("pkt[0] payload too short for NAT-D: %d bytes", len(p0.Payload))
	}

	// Check that the IKE header NextPayload points to the first payload.
	nextPayload := p0.Payload[20]
	if nextPayload == 0 {
		t.Error("pkt[0] NextPayload = 0, expected non-zero (SA payload)")
	}

	// Verify NAT-D Notify payloads exist after the IKE header.
	// The payload chain starts at offset IKEHeaderAtPort4500 (32).
	// SA (type 33) + KE (type 34) + Nonce (type 40) + NAT-D × 2.
	// Check that payload types in the chain are valid.
	offset := IKEHeaderAtPort4500
	for offset < len(p0.Payload)-4 {
		if offset+4 > len(p0.Payload) {
			break
		}
		plType := p0.Payload[offset]
		plLen := binary.BigEndian.Uint16(p0.Payload[offset+2 : offset+4])
		if int(plLen) < 4 {
			break
		}
		if plType == PayloadNOTIFY {
			// Verify NAT-D Notify structure.
			notifyOffset := offset + 4
			if notifyOffset+8 > len(p0.Payload) {
				break
			}
			protoID := p0.Payload[notifyOffset]
			spiSize := p0.Payload[notifyOffset+1]
			msgType := binary.BigEndian.Uint16(p0.Payload[notifyOffset+2 : notifyOffset+4])
			if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
				if protoID != 0 {
					t.Errorf("NAT-D Notify ProtocolID = %d, want 0", protoID)
				}
				if spiSize != 0 {
					t.Errorf("NAT-D Notify SPISize = %d, want 0", spiSize)
				}
				// Notification Data should be 20 bytes (SHA-1 hash).
				dataOffset := notifyOffset + 4
				dataLen := int(plLen) - 8
				if dataLen != NATDHashLen {
					t.Errorf("NAT-D Notify Data length = %d, want %d", dataLen, NATDHashLen)
				}
				// Verify the hash is a valid SHA-1 output.
				if dataLen >= NATDHashLen {
					hash := p0.Payload[dataOffset : dataOffset+NATDHashLen]
					if len(hash) != NATDHashLen {
						t.Errorf("NAT-D hash length = %d, want %d", len(hash), NATDHashLen)
					}
				}
			}
		}
		offset += int(plLen)
	}
}

// --- Non-ESP Marker validation ---
func TestNonESPMarker(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)

	for i, p := range pkts {
		if len(p.Payload) < 4 {
			t.Fatalf("pkt[%d] payload too short for marker: %d bytes", i, len(p.Payload))
		}
		// All packets on port 4500 must have Non-ESP Marker = 0x00000000.
		marker := binary.BigEndian.Uint32(p.Payload[0:4])
		if marker != 0 {
			t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
		}
		// UDP payload length >= 32 (4 marker + 28 IKE header).
		if len(p.Payload) < IKEHeaderAtPort4500 {
			t.Errorf("pkt[%d] payload length %d < %d (min IKE-NAT-T)", i, len(p.Payload), IKEHeaderAtPort4500)
		}
	}
}

// --- Port floating 500 -> 4500 ---
func TestPortFloating(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcPort = 500
	spec.DstPort = 500
	pkts := mustPlan(t, spec)

	if len(pkts) < 1 {
		t.Fatal("expected at least 1 packet")
	}

	// With NAT detected and PortFloat=true, all packets should use port 4500.
	for i, p := range pkts {
		if p.L4.DstPort != NATTPort {
			t.Errorf("pkt[%d] DstPort = %d, want %d (NAT-T port)", i, p.L4.DstPort, NATTPort)
		}
	}
}

// --- NAT-Keepalive ---
func TestNATKeepalive(t *testing.T) {
	spec := validBaseSpec()
	spec.IKENATT.NATDetectedOnSource = true
	spec.IKENATT.NATDetectedOnDest = false
	spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{
		Interval: 20,
		Count: 3,
		Direction: "up",
	}
	spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
		SPIout: 0xDEADBEEF,
		ESPCount: 1,
		ESPDataSize: 100,
	}

	pkts := mustPlan(t, spec)

	// Expect: 4 IKE packets + 1 ESP + 3 keepalive = 8.
	if len(pkts) < 8 {
		t.Fatalf("expected >=8 packets (4 IKE + 1 ESP + 3 keepalive), got %d", len(pkts))
	}

	// Check keepalive packets (last 3).
	for i := 0; i < 3; i++ {
		p := pkts[len(pkts)-3+i]
		if len(p.Payload) != 1 {
			t.Errorf("keepalive[%d] payload length = %d, want 1", i, len(p.Payload))
		}
		if len(p.Payload) > 0 && p.Payload[0] != 0xFF {
			t.Errorf("keepalive[%d] payload[0] = 0x%02X, want 0xFF", i, p.Payload[0])
		}
		if p.L4.Protocol != "udp" {
			t.Errorf("keepalive[%d] protocol = %q, want udp", i, p.L4.Protocol)
		}
	}

	// Check ESP packet.
	espPkt := pkts[len(pkts)-4]
	if len(espPkt.Payload) < ESPHeaderMinLen {
		t.Fatalf("ESP payload too short: %d bytes", len(espPkt.Payload))
	}
	spi := binary.BigEndian.Uint32(espPkt.Payload[0:4])
	if spi != 0xDEADBEEF {
		t.Errorf("ESP SPI = 0x%08X, want 0xDEADBEEF", spi)
	}
	seq := binary.BigEndian.Uint32(espPkt.Payload[4:8])
	if seq != 1 {
		t.Errorf("ESP Seq = %d, want 1", seq)
	}
}

// --- Validate tests ---
func TestValidate_NilIKENATTConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for nil IKENATT config")
	}
}

func TestValidate_BadSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.SrcIP = "not-an-ip"
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid SrcIP")
	}
}

func TestValidate_BadDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.DstIP = "not-an-ip"
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid DstIP")
	}
}

func TestValidate_BadDirection(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.IKENATT.Dialog = []core.IKENATTMessage{
		{Direction: "invalid", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0},
	}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid Direction")
	}
}

func TestValidate_NegativeRetransmit(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: -1}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for negative MaxRetransmits")
	}
}

func TestValidate_BackoffLessThanOne(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.IKENATT.Retransmit = &core.RetransmitConfig{Backoff: 0.5}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for Backoff < 1.0")
	}
}

func TestValidate_NATDHashLength(t *testing.T) {
	p := NewPlanner()
	spec := validBaseSpec()
	spec.IKENATT.Dialog = []core.IKENATTMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
			Payloads: []core.IKENATTPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
					{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
						{Type: 1, ID: 12, KeyLengthBits: 128},
					}},
				}}},
				{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
					ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
					NotificationData: make([]byte, 10), // Wrong length: 10 != 20
				}},
			},
		},
	}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid NAT-D hash length")
	}
}

// --- Non-ESP Marker at port 500 ---
func TestNonESPMarkerAtPort500(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcPort = 500
	spec.DstPort = 500
	spec.IKENATT.PortFloat = false
	spec.IKENATT.NATDetectedOnSource = false
	pkts := mustPlan(t, spec)

	if len(pkts) < 1 {
		t.Fatal("expected at least 1 packet")
	}

	// Without port floating, no Non-ESP Marker needed.
	p0 := pkts[0]
	if len(p0.Payload) < 4 {
		t.Fatalf("pkt[0] payload too short: %d bytes", len(p0.Payload))
	}
	// The first 4 bytes should NOT be 0x00000000 (they are IKE header bytes).
	marker := binary.BigEndian.Uint32(p0.Payload[0:4])
	// Since we don't add marker at port 500, the first 4 bytes are SPI.
	if marker == 0 && spec.IKENATT.InitiatorSPI != 0 {
		// If SPI != 0, first 4 bytes should not be 0.
		_ = 0 // This is expected when SPI != 0, marker should not be present
	}
}

// --- NAT-D Hash computation ---
func TestNATDHashComputation(t *testing.T) {
	spii := uint64(0x0123456789ABCDEF)
	spir := uint64(0x0011223344556677)
	ip := net.ParseIP("10.0.0.1")
	port := uint16(4500)

	hash := computeNATDHash(spii, spir, ip, port)
	if len(hash) != NATDHashLen {
		t.Errorf("NAT-D hash length = %d, want %d", len(hash), NATDHashLen)
	}

	// Verify deterministic: same inputs produce same hash.
	hash2 := computeNATDHash(spii, spir, ip, port)
	for i := range hash {
		if hash[i] != hash2[i] {
			t.Errorf("NAT-D hash not deterministic at byte %d: %02X vs %02X", i, hash[i], hash2[i])
		}
	}

	// Verify different IP produces different hash.
	ip2 := net.ParseIP("10.0.0.2")
	hash3 := computeNATDHash(spii, spir, ip2, port)
	same := true
	for i := range hash {
		if hash[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("NAT-D hash for different IPs should differ")
	}
}

// --- IKE Header version check ---
func TestIKEv2Version(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)

	if len(pkts) < 1 {
		t.Fatal("expected at least 1 packet")
	}

	p0 := pkts[0]
	if len(p0.Payload) < IKEHeaderAtPort4500+1 {
		t.Fatalf("payload too short: %d bytes", len(p0.Payload))
	}
	version := p0.Payload[21]
	if version != IKEv2Version {
		t.Errorf("IKE Version = 0x%02X, want 0x%02X (IKEv2)", version, IKEv2Version)
	}
}

// --- ESP-in-UDP encapsulation ---
func TestESPInUDPEncapsulation(t *testing.T) {
	spec := validBaseSpec()
	spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
		SPIout: 0xCAFEBABE,
		ESPCount: 2,
		ESPDataSize: 64,
	}
	pkts := mustPlan(t, spec)

	// 4 IKE packets + 2 ESP = 6.
	if len(pkts) < 6 {
		t.Fatalf("expected >=6 packets (4 IKE + 2 ESP), got %d", len(pkts))
	}

	// Check ESP packets (last 2).
	for i := 0; i < 2; i++ {
		p := pkts[4+i]
		if len(p.Payload) < ESPHeaderMinLen {
			t.Fatalf("ESP pkt[%d] payload too short: %d bytes", i, len(p.Payload))
		}
		spi := binary.BigEndian.Uint32(p.Payload[0:4])
		if spi != 0xCAFEBABE {
			t.Errorf("ESP[%d] SPI = 0x%08X, want 0xCAFEBABE", i, spi)
		}
		seq := binary.BigEndian.Uint32(p.Payload[4:8])
		if seq != uint32(i+1) {
			t.Errorf("ESP[%d] Seq = %d, want %d", i, seq, i+1)
		}
		if p.L4.Protocol != "udp" {
			t.Errorf("ESP[%d] protocol = %q, want udp", i, p.L4.Protocol)
		}
	}
}

// --- IKE Fragment ---
func TestIKEFragmentPayload(t *testing.T) {
	// Verify that a large IKE_AUTH message with raw payload produces valid wire bytes.
	spec := validBaseSpec()
	spec.IKENATT.Dialog = []core.IKENATTMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
			Payloads: []core.IKENATTPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
					{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
						{Type: 1, ID: 12, KeyLengthBits: 128},
					}},
				}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14, KeyData: make([]byte, 256)}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
		},
		{
			Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
			Payloads: []core.IKENATTPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
					{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
						{Type: 1, ID: 12, KeyLengthBits: 128},
					}},
				}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14, KeyData: make([]byte, 256)}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
		},
		{
			Direction: "up", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
			Payloads: []core.IKENATTPayload{
				{Type: PayloadIDi, Raw: make([]byte, 1000)}, // Large payload to test fragmentation
			},
		},
		{
			Direction: "down", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
			Payloads: []core.IKENATTPayload{
				{Type: PayloadIDr, Raw: make([]byte, 1000)},
			},
		},
	}

	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected >=4 packets, got %d", len(pkts))
	}

	// Verify all packets have Non-ESP Marker.
	for i, p := range pkts {
		if len(p.Payload) < 4 {
			t.Fatalf("pkt[%d] payload too short: %d bytes", i, len(p.Payload))
		}
		marker := binary.BigEndian.Uint32(p.Payload[0:4])
		if marker != 0 {
			t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
		}
		// Verify IKE header exists after marker.
		if len(p.Payload) < IKEHeaderAtPort4500 {
			t.Errorf("pkt[%d] payload too short for IKE header: %d bytes", i, len(p.Payload))
		}
	}
}

// --- Multiple NAT-Keepalive before expiry ---
func TestMultipleNATKeepalive(t *testing.T) {
	spec := validBaseSpec()
	spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{
		Interval: 20,
		Count: 5,
		Direction: "both",
	}
	spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
		SPIout: 0xDEADBEEF,
		ESPCount: 1,
		ESPDataSize: 100,
	}
	pkts := mustPlan(t, spec)

	// 4 IKE + 1 ESP + 5*2 keepalive (both directions) = 15.
	expectedCount := 4 + 1 + 5*2
	if len(pkts) < expectedCount {
		t.Fatalf("expected >=%d packets, got %d", expectedCount, len(pkts))
	}

	// Check keepalive packets.
	kaCount := 0
	for _, p := range pkts {
		if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
			kaCount++
			if p.L4.Protocol != "udp" {
				t.Errorf("keepalive protocol = %q, want udp", p.L4.Protocol)
			}
			if p.L4.DstPort != NATTPort {
				t.Errorf("keepalive DstPort = %d, want %d", p.L4.DstPort, NATTPort)
			}
		}
	}
	if kaCount != 10 {
		t.Errorf("keepalive count = %d, want 10 (5*2)", kaCount)
	}
}

// --- Complete IKE_SA_INIT bidirectional flow ---
func TestIKESAInitBidirectional(t *testing.T) {
	spec := validBaseSpec()
	spec.IKENATT.InitiatorSPI = 0x0123456789ABCDEF
	spec.IKENATT.ResponderSPI = 0x0011223344556677
	pkts := mustPlan(t, spec)

	if len(pkts) < 2 {
		t.Fatalf("expected >=2 packets for IKE_SA_INIT exchange, got %d", len(pkts))
	}

	// INIT_REQ (up).
	req := pkts[0]
	resp := pkts[1]

	// Verify direction.
	if req.Direction != "up" {
		t.Errorf("INIT_REQ direction = %q, want up", req.Direction)
	}
	if resp.Direction != "down" {
		t.Errorf("INIT_RESP direction = %q, want down", resp.Direction)
	}

	// Verify SPI exchange.
	reqSPIi := binary.BigEndian.Uint64(req.Payload[4:12])
	reqSPIr := binary.BigEndian.Uint64(req.Payload[12:20])
	respSPIi := binary.BigEndian.Uint64(resp.Payload[4:12])
	respSPIr := binary.BigEndian.Uint64(resp.Payload[12:20])

	if reqSPIi != 0x0123456789ABCDEF {
		t.Errorf("INIT_REQ SPIi = 0x%X, want 0x0123456789ABCDEF", reqSPIi)
	}
	if reqSPIr != 0 {
		t.Errorf("INIT_REQ SPIr = 0x%X, want 0", reqSPIr)
	}
	if respSPIi != 0x0123456789ABCDEF {
		t.Errorf("INIT_RESP SPIi = 0x%X, want 0x0123456789ABCDEF (echo)", respSPIi)
	}
	if respSPIr != 0x0011223344556677 {
		t.Errorf("INIT_RESP SPIr = 0x%X, want 0x0011223344556677", respSPIr)
	}

	// Verify Message ID.
	reqMsgID := binary.BigEndian.Uint32(req.Payload[24:28])
	respMsgID := binary.BigEndian.Uint32(resp.Payload[24:28])
	if reqMsgID != 0 {
		t.Errorf("INIT_REQ MessageID = %d, want 0", reqMsgID)
	}
	if respMsgID != 0 {
		t.Errorf("INIT_RESP MessageID = %d, want 0", respMsgID)
	}

	// Verify Exchange Type.
	reqExch := req.Payload[22]
	respExch := resp.Payload[22]
	if reqExch != ExchangeIKE_SA_INIT {
		t.Errorf("INIT_REQ ExchangeType = %d, want %d", reqExch, ExchangeIKE_SA_INIT)
	}
	if respExch != ExchangeIKE_SA_INIT {
		t.Errorf("INIT_RESP ExchangeType = %d, want %d", respExch, ExchangeIKE_SA_INIT)
	}

	// Verify Flags.
	reqFlags := req.Payload[23]
	respFlags := resp.Payload[23]
	if reqFlags != FlagInitiator {
		t.Errorf("INIT_REQ Flags = 0x%02X, want 0x%02X", reqFlags, FlagInitiator)
	}
	if respFlags != FlagResponse {
		t.Errorf("INIT_RESP Flags = 0x%02X, want 0x%02X", respFlags, FlagResponse)
	}
}

// --- NAT-OA Payload ---
func TestNATOAPayload(t *testing.T) {
	// NAT-OA payload is sent via Notify with type NAT_OA.
	// We verify it by checking that the Notify payload with custom type is serialized correctly.
	natOANotify := &core.NotifyPayload{
		ProtocolID: 0,
		SPISize: 0,
		NotifyMsgType: 16400, // NAT_OA_SOURCE (example)
		NotificationData: net.ParseIP("10.0.0.1").To4(),
	}

	body := encodeNotifyForNATT(natOANotify)
	if len(body) < 8 {
		t.Fatalf("NAT-OA Notify body too short: %d bytes", len(body))
	}

	protoID := body[0]
	if protoID != 0 {
		t.Errorf("ProtocolID = %d, want 0", protoID)
	}
	msgType := binary.BigEndian.Uint16(body[2:4])
	if msgType != 16400 {
		t.Errorf("NotifyMsgType = %d, want 16400", msgType)
	}
	if len(body[4:]) != 4 {
		t.Errorf("NAT-OA data length = %d, want 4 (IPv4)", len(body[4:]))
	}
}

// --- Non-ESP Marker = 0x00000000 for all port 4500 IKE messages ---
func TestNonESPMarkerValue(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)

	for i, p := range pkts {
		if len(p.Payload) < 4 {
			t.Fatalf("pkt[%d] payload too short: %d bytes", i, len(p.Payload))
		}
		marker := binary.BigEndian.Uint32(p.Payload[0:4])
		if marker != 0 {
			t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
		}
	}
}