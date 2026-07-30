package vmess

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// mustPlan calls Plan and fails the test on error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// validVmessSpec returns a minimal valid VMess spec with TCP handshake and
// teardown enabled. The UUID is a valid RFC 4122 v4 text form.
func validVmessSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1", DstIP: "192.0.2.2",
		SrcPort: 50000, DstPort: 443,
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		Vmess: &core.VmessConfig{
			UUID:       "12345678-1234-1234-1234-123456789abc",
			Address:    "example.com",
			Port:       80,
			Encryption: "aead_chacha20_poly1305",
			Command:    0x01,
		},
	}
}

// ===================================================================
// Integration tests: full Plan() output capture and end-to-end asserts.
// ===================================================================

// Integration 1: Standard vmess TCP handshake + request + response (scenario 1)
// Verifies the full packet sequence for a standard TCP proxy session.
// handshake(3) + request(1) + empty-chunk(1) + response(1) + empty-chunk(1) + teardown(4) = 11 packets.
func TestVmess_Integration_StandardTCPHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	cfgs := drain(mustPlan(t, p, spec))

	// 3 handshake + 1 req + 1 empty-chunk + 1 resp + 1 empty-chunk + 4 teardown = 11
	if len(cfgs) != 11 {
		t.Fatalf("packet count = %d, want 11", len(cfgs))
	}

	// Packet 0-2: handshake
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != flagSYN {
		t.Errorf("cfgs[0]: dir=%s flags=%02x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
	}
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != flagSYNACK {
		t.Errorf("cfgs[1]: dir=%s flags=%02x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
	}
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != flagACK {
		t.Errorf("cfgs[2]: dir=%s flags=%02x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}

	// Packet 3: VMess Request up — first byte should be Version=0x01 (AEAD)
	req := cfgs[3]
	if req.Direction != "up" {
		t.Errorf("cfgs[3].Direction=%s, want up", req.Direction)
	}
	if len(req.Payload) == 0 || req.Payload[0] != VersionAEAD {
		t.Errorf("Request first byte = %02x, want 0x01 (AEAD)", req.Payload[0])
	}
	// IV length = 16 bytes
	if len(req.Payload) < 1+IVLen {
		t.Fatalf("Request too short: %d bytes", len(req.Payload))
	}
	// Total request length = 1 (Version) + 16 (IV) + body + 16 (Tag)
	// body (AEAD, IPv4 case... but we use Domain here):
	// UUID(16) + Version(1) + Cmd(1) + AddrType(1) + Addr(1+N) + Port(2) + PadLen(1) + Pad + PayloadLen(2)
	// = 16+1+1+1+1+len("example.com")+2+1+padLen+2
	// = 16+1+1+1+1+11+2+1+padLen+2 = 36+padLen
	// Plus Version(1) + IV(16) + Tag(16) = 33 + body
	// So total = 33 + 36 + padLen = 69 + padLen
	// Just check minimum length
	if len(req.Payload) < 1+IVLen+UUIDLen+TagLen {
		t.Errorf("Request too short: got %d bytes", len(req.Payload))
	}

	// Packet 4: Empty AEAD chunk (2B len + 16B tag) up
	if cfgs[4].Direction != "up" {
		t.Errorf("cfgs[4].Direction=%s, want up (empty chunk)", cfgs[4].Direction)
	}

	// Packet 5: VMess Response down — first byte should be Version=0x01 (AEAD)
	resp := cfgs[5]
	if resp.Direction != "down" {
		t.Errorf("cfgs[5].Direction=%s, want down", resp.Direction)
	}
	if len(resp.Payload) == 0 || resp.Payload[0] != VersionAEAD {
		t.Errorf("Response first byte = %02x, want 0x01 (AEAD)", resp.Payload[0])
	}

	// Packet 6: Empty AEAD response chunk down
	if cfgs[6].Direction != "down" {
		t.Errorf("cfgs[6].Direction=%s, want down (empty chunk)", cfgs[6].Direction)
	}

	// Packets 7-10: teardown
	teardown := cfgs[7:11]
	if teardown[0].Direction != "up" || teardown[0].L4.Flags != flagFINACK {
		t.Errorf("teardown[0]: dir=%s flags=%02x", teardown[0].Direction, teardown[0].L4.Flags)
	}
	if teardown[1].Direction != "down" || teardown[1].L4.Flags != flagACK {
		t.Errorf("teardown[1]: dir=%s flags=%02x", teardown[1].Direction, teardown[1].L4.Flags)
	}
	if teardown[2].Direction != "down" || teardown[2].L4.Flags != flagFINACK {
		t.Errorf("teardown[2]: dir=%s flags=%02x", teardown[2].Direction, teardown[2].L4.Flags)
	}
	if teardown[3].Direction != "up" || teardown[3].L4.Flags != flagACK {
		t.Errorf("teardown[3]: dir=%s flags=%02x", teardown[3].Direction, teardown[3].L4.Flags)
	}

	// Verify all packet indices are strictly ascending.
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex <= cfgs[i-1].PacketIndex {
			t.Errorf("PacketIndex[%d]=%d not > prev=%d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex)
		}
	}

	// Verify all packets share the same FlowID.
	for i, c := range cfgs {
		if c.FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID=%q, want %q", i, c.FlowID, cfgs[0].FlowID)
		}
	}
}

// Integration 2: vmess over UDP (scenario 2). Command=0x02 triggers UDP
// mode, emitting only the VMess Request and Response as UDP datagrams.
func TestVmess_Integration_UDPMode(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Command = 0x02 // UDP
	cfgs := drain(mustPlan(t, p, spec))

	// UDP mode: 1 request up + 1 response down = 2 packets
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2 (UDP mode)", len(cfgs))
	}
	if cfgs[0].Direction != "up" || cfgs[0].L4.Protocol != "udp" {
		t.Errorf("cfgs[0]: dir=%s proto=%s, want up/udp", cfgs[0].Direction, cfgs[0].L4.Protocol)
	}
	if cfgs[1].Direction != "down" || cfgs[1].L4.Protocol != "udp" {
		t.Errorf("cfgs[1]: dir=%s proto=%s, want down/udp", cfgs[1].Direction, cfgs[1].L4.Protocol)
	}
	// Verify request first byte = 0x01 (AEAD version)
	if cfgs[0].Payload[0] != VersionAEAD {
		t.Errorf("UDP request first byte = %02x, want 0x01", cfgs[0].Payload[0])
	}
}

// Integration 3: AEAD chunked payload (scenario 3) — when Payload is set,
// the planner emits the encrypted payload bytes after the request header.
func TestVmess_Integration_AEADChunkedPayload(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Payload = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	cfgs := drain(mustPlan(t, p, spec))

	// handshake(3) + request(1) + payload(>=1 segments) + response(1) + empty-chunk(1) + teardown(4)
	// = at least 10 packets
	if len(cfgs) < 10 {
		t.Fatalf("packet count = %d, want at least 10", len(cfgs))
	}

	// Find the request packet (first up-direction payload after handshake)
	reqIdx := -1
	for i := 3; i < len(cfgs); i++ {
		if cfgs[i].Direction == "up" && len(cfgs[i].Payload) > 0 {
			reqIdx = i
			break
		}
	}
	if reqIdx < 0 {
		t.Fatal("no VMess Request payload found")
	}
	// Request first byte = 0x01 (AEAD)
	if cfgs[reqIdx].Payload[0] != VersionAEAD {
		t.Errorf("Request first byte = %02x, want 0x01", cfgs[reqIdx].Payload[0])
	}
}

// Integration 4: Domain address type (scenario 4) — verify that a domain
// address is encoded as 0x02 + 1B length + N bytes.
func TestVmess_Integration_DomainAddressType(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Address = "example.com"
	cfgs := drain(mustPlan(t, p, spec))

	// Find first up-direction non-handshake payload
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			// The Payload[0] is Version (0x01). Bytes 1-16 are IV.
			// Bytes 17+ are EncryptedBody (random). We can't decrypt the
			// body, but we CAN check the request has the expected length
			// for a domain address.
			// Body (AEAD) = UUID(16) + Version(1) + Cmd(1) + AddrType(1) + Addr(1+11) + Port(2) + PadLen(1) + Pad + PayloadLen(2)
			// = 16+1+1+1+12+2+1+padLen+2 = 36+padLen
			// Total = 1 (Version) + 16 (IV) + 36+padLen (body) + 16 (Tag) = 69+padLen
			// padLen is random 0-16, so 69-85
			if len(c.Payload) < 69 {
				t.Errorf("Request too short for domain address: %d bytes", len(c.Payload))
			}
			return
		}
	}
	t.Fatal("no up-direction payload found")
}

// Integration 5: IPv6 address type (scenario 5) — verify that IPv6 is
// encoded as 0x03 + 16 bytes.
func TestVmess_Integration_IPv6AddressType(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Address = "2001:db8::1"
	cfgs := drain(mustPlan(t, p, spec))

	// Find first up-direction non-handshake payload
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			// Body (AEAD) for IPv6 = UUID(16) + Version(1) + Cmd(1) + AddrType(1) + Addr(16) + Port(2) + PadLen(1) + Pad + PayloadLen(2)
			// = 16+1+1+1+16+2+1+padLen+2 = 40+padLen
			// Total = 1 + 16 + 40+padLen + 16 = 73+padLen (73-89)
			if len(c.Payload) < 73 {
				t.Errorf("Request too short for IPv6 address: %d bytes", len(c.Payload))
			}
			return
		}
	}
	t.Fatal("no up-direction payload found")
}

// Integration 6: Legacy mode (scenario 6) — verify that legacy_aes_128_cfb
// produces a request starting with Version=0x00.
func TestVmess_Integration_LegacyMode(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Encryption = "legacy_aes_128_cfb"
	spec.Vmess.AlterID = 16
	cfgs := drain(mustPlan(t, p, spec))

	// Find first up-direction non-handshake payload
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			if c.Payload[0] != VersionLegacy {
				t.Errorf("Legacy request first byte = %02x, want 0x00", c.Payload[0])
			}
			return
		}
	}
	t.Fatal("no up-direction payload found")
}

// Integration 7: mTLS wrapped vmess (scenario 7) — verify that the vmess
// planner still emits the correct wire format when wrapped under a TLS
// outer flow. This is a basic test: the planner doesn't know about TLS
// wrapping, so we just verify the inner vmess bytes are correct.
func TestVmess_Integration_mTLSPayload(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	// Simulate mTLS by adding a payload that mimics wrapped vmess
	spec.Vmess.Payload = []byte("wrapped vmess data")
	cfgs := drain(mustPlan(t, p, spec))

	// Verify request and response are both emitted
	var hasUp, hasDown bool
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			if c.Payload[0] == VersionAEAD {
				hasUp = true
			}
		}
		if c.Direction == "down" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			if c.Payload[0] == VersionAEAD {
				hasDown = true
			}
		}
	}
	if !hasUp {
		t.Error("no VMess Request found")
	}
	if !hasDown {
		t.Error("no VMess Response found")
	}
}

// Integration 8: Heartbeat mode — verify that Heartbeat=true emits a
// minimal request/response cycle.
func TestVmess_Integration_HeartbeatMode(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Heartbeat = true
	spec.Vmess.HeartbeatCount = 2
	cfgs := drain(mustPlan(t, p, spec))

	// handshake(3) + 2 heartbeat cycles (req+resp each = 2) + teardown(4) = 3 + 4 + 4 = 11
	if len(cfgs) != 11 {
		t.Fatalf("packet count = %d, want 11 (heartbeat mode)", len(cfgs))
	}
}

// Integration 9: MUX mode — verify that Command=0x03 with MuxStreams
// emits the MUX frames after the request/response handshake.
func TestVmess_Integration_MUXMode(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Command = 0x03 // MUX
	spec.Vmess.MuxStreams = []core.VmessMuxStream{
		{
			SessionID:  1,
			TargetAddr: "example.com",
			TargetPort: 80,
			Frames: []core.VmessMuxFrame{
				{Status: MuxStatusNEW},
				{Status: MuxStatusKEEP, Payload: []byte("hello")},
				{Status: MuxStatusEND},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))

	// handshake(3) + request(1) + empty-chunk(1) + response(1) + empty-chunk(1) + 3 MUX frames + teardown(4)
	// = 3 + 1 + 1 + 1 + 1 + 3 + 4 = 14
	if len(cfgs) != 14 {
		t.Fatalf("packet count = %d, want 14 (MUX mode)", len(cfgs))
	}
}

// Integration 10: Validate failure path — verify that an invalid UUID
// causes Plan to return an error.
func TestVmess_Integration_InvalidUUID(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.UUID = "invalid-uuid"
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should return error for invalid UUID")
	}
	if !strings.Contains(err.Error(), "uuid") {
		t.Errorf("Error should mention uuid, got: %v", err)
	}
}

// Integration 11: Validate failure path — verify that port=0 causes Plan
// to return an error.
func TestVmess_Integration_PortZero(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Port = 0
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should return error for port=0")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("Error should mention port, got: %v", err)
	}
}

// Integration 12: Validate failure path — verify that a missing VmessConfig
// causes Plan to return an error.
func TestVmess_Integration_MissingConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1", DstIP: "192.0.2.2",
		SrcPort: 50000, DstPort: 443,
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
	}
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should return error for missing VmessConfig")
	}
}

// Integration 13: Context cancellation — verify that the planner goroutine
// exits promptly when ctx is cancelled.
func TestVmess_Integration_ContextCancellation(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	// Cancel immediately and drain
	cancel()
	// Drain should not block indefinitely
	drained := 0
	for range ch {
		drained++
		if drained > 1000 {
			t.Fatal("drain did not terminate after ctx cancel")
		}
	}
}

// Integration 14: IPv4 address type — verify that an IPv4 address is
// encoded as 0x01 + 4 bytes.
func TestVmess_Integration_IPv4AddressType(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Address = "192.168.1.1"
	cfgs := drain(mustPlan(t, p, spec))

	// Body (AEAD) for IPv4 = UUID(16) + Version(1) + Cmd(1) + AddrType(1) + Addr(4) + Port(2) + PadLen(1) + Pad + PayloadLen(2)
	// = 16+1+1+1+4+2+1+padLen+2 = 28+padLen
	// Total = 1 + 16 + 28+padLen + 16 = 61+padLen (61-77)
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.L4.Flags == flagPSHACK {
			if len(c.Payload) < 61 {
				t.Errorf("Request too short for IPv4 address: %d bytes", len(c.Payload))
			}
			return
		}
	}
	t.Fatal("no up-direction payload found")
}

// Integration 15: Sequence number advancement — verify that sequence numbers
// advance correctly based on payload bytes sent.
func TestVmess_Integration_SequenceNumberAdvancement(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	cfgs := drain(mustPlan(t, p, spec))

	// After SYN (ISN), clientSeq = ISN+1
	// The SYN-ACK's ACK should ack ISN+1
	if cfgs[1].L4.Ack != cfgs[0].L4.Seq+1 {
		t.Errorf("SYN-ACK Ack=%d, want SYN Seq+1=%d", cfgs[1].L4.Ack, cfgs[0].L4.Seq+1)
	}
	// The final ACK of handshake (cfgs[2]) acks serverSeq+1
	if cfgs[2].L4.Ack != cfgs[1].L4.Seq+1 {
		t.Errorf("Handshake ACK Ack=%d, want SYN-ACK Seq+1=%d", cfgs[2].L4.Ack, cfgs[1].L4.Seq+1)
	}
}

// Integration 16: RST termination — verify that TCP.RST=true replaces 4-way
// teardown with a single RST packet.
func TestVmess_Integration_RSTTermination(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.TCP.RST = true
	cfgs := drain(mustPlan(t, p, spec))

	// Last packet should be RST
	last := cfgs[len(cfgs)-1]
	if last.L4.Flags != flagRSTACK {
		t.Errorf("Last packet flags = %02x, want RST/RSTACK %02x", last.L4.Flags, flagRSTACK)
	}
}

// Integration 17: AEAD payload chunking - verify that a non-empty payload
// is emitted as VMess AEAD length-prefixed chunks:
//   [2B big-endian length][payload][16B tag] per chunk
//   + terminating [0x00 0x00][16B tag]
// A payload longer than MaxChunkPayload produces multiple chunks.
func TestVmess_Integration_AEADPayloadChunkStructure(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	// Use a large MSS to avoid TCP-level segmentation obscuring the chunk structure.
	spec.TCP.MSS = 65535
	// Use a payload larger than MaxChunkPayload to force multi-chunk splitting.
	spec.Vmess.Payload = make([]byte, MaxChunkPayload+5000) // 21383 bytes -> 2 chunks
	cfgs := drain(mustPlan(t, p, spec))

	// Collect all up PSH-ACKs after the request header (the 1st up PSH-ACK).
	// The chunked payload follows the request header as subsequent up PSH-ACKs.
	upPSHACKs := make([][]byte, 0)
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == flagPSHACK {
			upPSHACKs = append(upPSHACKs, c.Payload)
		}
	}
	if len(upPSHACKs) < 2 {
		t.Fatalf("expected at least 2 up PSH-ACKs (request + payload), got %d", len(upPSHACKs))
	}

	// Concatenate all PSH-ACKs after the request header (index 0 = request header).
	var chunkedPayload []byte
	for i := 1; i < len(upPSHACKs); i++ {
		chunkedPayload = append(chunkedPayload, upPSHACKs[i]...)
	}

	// Expected structure:
	// Chunk 1: [2B len=16383][16383B payload][16B tag] = 16401 bytes
	// Chunk 2: [2B len=5000][5000B payload][16B tag] = 5018 bytes
	// Terminating: [2B len=0][16B tag] = 18 bytes
	// Total = 16401 + 5018 + 18 = 21437 bytes

	// Parse chunk 1
	offset := 0
	chunk1Len := int(binary.BigEndian.Uint16(chunkedPayload[offset : offset+2]))
	if chunk1Len != MaxChunkPayload {
		t.Errorf("chunk1 length field=%d, want %d (MaxChunkPayload)", chunk1Len, MaxChunkPayload)
	}
	offset += 2 + chunk1Len + TagLen // skip [2B len][payload][16B tag]

	// Parse chunk 2
	chunk2Len := int(binary.BigEndian.Uint16(chunkedPayload[offset : offset+2]))
	if chunk2Len != 5000 {
		t.Errorf("chunk2 length field=%d, want 5000", chunk2Len)
	}
	offset += 2 + chunk2Len + TagLen

	// Parse terminating empty chunk
	termLen := int(binary.BigEndian.Uint16(chunkedPayload[offset : offset+2]))
	if termLen != 0 {
		t.Errorf("terminating chunk length=%d, want 0", termLen)
	}
	offset += 2 + TagLen

	// Verify total length
	if offset != len(chunkedPayload) {
		t.Errorf("total consumed=%d, payload length=%d (should match)", offset, len(chunkedPayload))
	}
}

// Integration 18: AEAD small payload chunking - verify a small payload
// produces 1 chunk + terminating empty chunk.
func TestVmess_Integration_AEADSmallPayloadChunkStructure(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Payload = []byte("hello") // 5 bytes
	cfgs := drain(mustPlan(t, p, spec))

	// Find the chunked payload packet (2nd up-direction PSH-ACK).
	upCount := 0
	var chunkedPayload []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == flagPSHACK {
			upCount++
			if upCount == 2 {
				chunkedPayload = c.Payload
				break
			}
		}
	}
	if chunkedPayload == nil {
		t.Fatal("no chunked payload found")
	}

	// Expected: [2B len=5][5B payload][16B tag] + [2B len=0][16B tag]
	// Total = 23 + 18 = 41 bytes
	expectedTotal := 2 + 5 + TagLen + 2 + TagLen
	if len(chunkedPayload) != expectedTotal {
		t.Errorf("chunked payload length=%d, want %d", len(chunkedPayload), expectedTotal)
	}

	// Verify first chunk length = 5
	chunk1Len := int(binary.BigEndian.Uint16(chunkedPayload[0:2]))
	if chunk1Len != 5 {
		t.Errorf("chunk1 length=%d, want 5", chunk1Len)
	}

	// Verify terminating chunk at offset 2+5+16 = 23
	termOffset := 2 + 5 + TagLen
	termLen := int(binary.BigEndian.Uint16(chunkedPayload[termOffset : termOffset+2]))
	if termLen != 0 {
		t.Errorf("terminating chunk length=%d, want 0", termLen)
	}
}

// Integration 19: AlterID > 255 in Legacy mode is rejected by Validate,
// not silently truncated. Per design §2.1.0, the alterId field on the wire
// is 1 byte (0-255). Values > 255 must be rejected with a clear error.
func TestVmess_Integration_AlterIDOver255Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Encryption = "legacy_aes_128_cfb"
	spec.Vmess.AlterID = 300 // > 255, would be silently truncated to 44
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject AlterID=300 (>255) for Legacy mode")
	}
	if !strings.Contains(err.Error(), "alter_id") {
		t.Errorf("Error should mention alter_id, got: %v", err)
	}
}

// Integration 20: AlterID = 255 (max valid) is accepted in Legacy mode.
func TestVmess_Integration_AlterIDMax255(t *testing.T) {
	p := NewPlanner()
	spec := validVmessSpec()
	spec.Vmess.Encryption = "legacy_aes_128_cfb"
	spec.Vmess.AlterID = 255 // max valid 1-byte alterId
	_, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan should accept AlterID=255, got error: %v", err)
	}
}
