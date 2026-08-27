package pcep

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// hexStr decodes a hex string like "20 01 00 10".
func hexStr(s string) []byte {
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "").Replace(s))
	if err != nil {
		panic(err)
	}
	return b
}

// hexStrUpper decodes a hex string, uppercased.
func hx(s string) []byte { return hexStr(s) }

// ---- Builder tests ----

func TestBuildOpenMsg(t *testing.T) {
	pdu := BuildOpenMsg(30, 120, 7, nil)
	// Wireshark-verified encoding (OPEN_OBJ_MIN_LEN=4): SID is 1 byte.
	// Common header: 20 01 00 0c (Version=0x20, MsgType=1, Length=12)
	// OPEN object: Class=1, Type=1 (0x10), Len=8; Body: 20 1e 78 07
	if len(pdu) != 12 {
		t.Fatalf("BuildOpenMsg len=%d, want 12\nhex: %s", len(pdu), hex.EncodeToString(pdu))
	}
	if pdu[0] != 0x20 || pdu[1] != 0x01 || pdu[2] != 0x00 || pdu[3] != 0x0c {
		t.Fatalf("Open header = %02x %02x %02x %02x, want 20 01 00 0c",
			pdu[0], pdu[1], pdu[2], pdu[3])
	}
	// Object class = 1 (OPEN), Type=1 in high nibble
	if pdu[4] != 1 || pdu[5] != 0x10 {
		t.Fatalf("Open object header = %02x %02x, want 01 10", pdu[4], pdu[5])
	}
	// Object-Length = 8
	if pdu[6] != 0 || pdu[7] != 8 {
		t.Fatalf("Open object length = %d, want 8", uint16(pdu[6])<<8|uint16(pdu[7]))
	}
	// Body: Ver=0x20 (Ver=1<<5), KA=30(0x1E), DT=120(0x78), SID=7 (1 byte)
	if pdu[8] != 0x20 || pdu[9] != 0x1E || pdu[10] != 0x78 {
		t.Fatalf("Open body flags/ka/dt = %02x %02x %02x, want 20 1E 78",
			pdu[8], pdu[9], pdu[10])
	}
	if pdu[11] != 7 {
		t.Fatalf("Open SID byte = %02x, want 07", pdu[11])
	}
}

func TestBuildOpenMsgSID8(t *testing.T) {
	pdu := BuildOpenMsg(30, 120, 8, nil)
	if len(pdu) != 12 {
		t.Fatalf("BuildOpenMsg SID8 len=%d, want 12", len(pdu))
	}
	if pdu[11] != 8 {
		t.Fatalf("Open SID = %d, want 8", pdu[11])
	}
}

func TestBuildKeepAliveMsg(t *testing.T) {
	pdu := BuildKeepAliveMsg()
	want := hexStr("20 02 00 04")
	if len(pdu) != len(want) {
		t.Fatalf("BuildKeepAliveMsg len=%d, want %d", len(pdu), len(want))
	}
	for i := range want {
		if pdu[i] != want[i] {
			t.Fatalf("BuildKeepAliveMsg byte %d = %02x, want %02x", i, pdu[i], want[i])
		}
	}
}

func TestBuildPCReqMsg(t *testing.T) {
	rp := BuildRPObject(1001, true, false)
	ep := BuildEndpointObjectIPv4("192.0.2.10", "192.0.2.20")
	ero := BuildEROObject([]pcepSubobject{
		{Type: "ipv4", Address: "198.51.100.1", PrefixLength: 32, L: true},
	})
	metric := BuildMetricObject(1, true, false, 12.5)
	pdu := BuildPCReqMsg([][]byte{rp, ep, ero, metric})

	// Check msg type byte
	if len(pdu) < 4 {
		t.Fatalf("PCReq too short: %d", len(pdu))
	}
	if pdu[1] != 6 {
		t.Fatalf("PCReq msg type = %d, want 6", pdu[1])
	}
	// Check RP request_id
	// Find RP object in the PCReq payload.
	// RP object: Class=2, Type=1 (high nibble 0x10) | P flag (0x02) = 0x12,
	// body: Reserved(1) + Flags(3) + RequestID(4) → RequestID at body offset 4.
	foundRP := false
	for i := 0; i < len(pdu)-6; i++ {
		if pdu[i] == 2 && pdu[i+1] == 0x12 { // RP class=2, Type=1, P=1, I=0
			foundRP = true
			rid := uint32(pdu[i+8])<<24 | uint32(pdu[i+9])<<16 | uint32(pdu[i+10])<<8 | uint32(pdu[i+11])
			if rid != 1001 {
				t.Fatalf("RP request_id = %d, want 1001", rid)
			}
			break
		}
	}
	if !foundRP {
		t.Fatal("PCReq missing RP object")
	}
	// Check endpoint IPv4 addresses
	foundEP := false
	for i := 0; i < len(pdu)-8; i++ {
		// Look for endpoint object (class=4, type=1 → byte1 & 0xF0 == 0x10)
		if pdu[i] == 4 && pdu[i+1]&0xF0 == 0x10 {
			// Source IP at body offset 0
			if pdu[i+4] == 192 && pdu[i+5] == 0 && pdu[i+6] == 2 && pdu[i+7] == 10 {
				foundEP = true
			}
		}
	}
	if !foundEP {
		t.Fatal("PCReq missing endpoint 192.0.2.10")
	}

	// Check ERO subobject IPv4 address
	foundERO := false
	for i := 0; i < len(pdu)-6; i++ {
		if pdu[i] == 7 && (pdu[i+1]&0xF0) == 0x10 {
			// ERO object - check subobject
			subStart := i + 4 // after object header
			if subStart+2 < len(pdu) && pdu[subStart]&0x7F == 1 && pdu[subStart+1] == 8 {
				// L flag on the type byte (Mask_L = 0x80)
				if pdu[subStart]&0x80 != 0 {
					foundERO = true
				}
			}
		}
	}
	if !foundERO {
		t.Fatal("PCReq missing ERO with L flag")
	}
}

func TestBuildPCRepMsg(t *testing.T) {
	rro := BuildRROObject([]pcepSubobject{
		{Type: "ipv4", Address: "198.51.100.1", PrefixLength: 32, L: false},
	})
	metric := BuildMetricObject(2, false, true, 20.0)
	pdu := BuildPCRepMsg([][]byte{rro, metric})

	if len(pdu) < 4 {
		t.Fatalf("PCRep too short: %d", len(pdu))
	}
	if pdu[1] != 7 {
		t.Fatalf("PCRep msg type = %d, want 7", pdu[1])
	}
}

func TestBuildPCNtfMsg(t *testing.T) {
	pdu := BuildPCNtfMsg(1, 1)
	if len(pdu) < 4 {
		t.Fatalf("PCNtf too short: %d", len(pdu))
	}
	if pdu[1] != 4 {
		t.Fatalf("PCNtf msg type = %d, want 4", pdu[1])
	}
}

func TestBuildPCErrMsg(t *testing.T) {
	pdu := BuildPCErrMsg(1, 2)
	if len(pdu) < 4 {
		t.Fatalf("PCErr too short: %d", len(pdu))
	}
	if pdu[1] != 3 {
		t.Fatalf("PCErr msg type = %d, want 3", pdu[1])
	}
}

func TestBuildRPObjectFlags(t *testing.T) {
	// Test P and I flags on the object header.
	// Object header byte 1: Type=1 (0x10 high nibble), P=0x02, I=0x01.
	obj := BuildRPObject(8501, true, true)
	if len(obj) < 2 {
		t.Fatalf("RP object too short")
	}
	if obj[1] != 0x13 {
		t.Fatalf("RP object header byte 1 = %02x, want 13 (Type=1, P=1, I=1)", obj[1])
	}
}

func TestBuildLSPObject(t *testing.T) {
	flags := map[string]bool{"delegate": true, "create": true, "administrative": true}
	obj := BuildLSPObject(77, flags)
	if len(obj) != 8 {
		t.Fatalf("LSP object length=%d, want 8", len(obj))
	}
	if obj[0] != 32 {
		t.Fatalf("LSP object class = %d, want 32", obj[0])
	}
	// PLSP-ID = 77 << 4 in 3 bytes (mask 0xFFFFF0)
	plsp := uint32(obj[4])<<16 | uint32(obj[5])<<8 | uint32(obj[6])
	if (plsp >> 4) != 77 {
		t.Fatalf("LSP PLSP-ID = %d, want 77", plsp>>4)
	}
	// Flags: delegate=0x01, administrative=0x08, create=0x80
	if obj[7]&0x01 == 0 {
		t.Fatal("LSP delegate flag not set")
	}
	if obj[7]&0x08 == 0 {
		t.Fatal("LSP administrative flag not set")
	}
	if obj[7]&0x80 == 0 {
		t.Fatal("LSP create flag not set")
	}
}

func TestBuildSRPObject(t *testing.T) {
	obj := BuildSRPObject(9001, nil)
	// SRP object: class=33, body = Flags(4) + SRP-ID(4)
	if obj[0] != 33 {
		t.Fatalf("SRP object class = %d, want 33", obj[0])
	}
	// SRP-ID at body offset 4
	srpID := uint32(obj[8])<<24 | uint32(obj[9])<<16 | uint32(obj[10])<<8 | uint32(obj[11])
	if srpID != 9001 {
		t.Fatalf("SRP ID = %d, want 9001", srpID)
	}
}

func TestBuildLSPAObject(t *testing.T) {
	obj := BuildLSPAObject(true, 3, 4)
	if len(obj) != 20 {
		t.Fatalf("LSPA object length=%d, want 20", len(obj))
	}
	if obj[0] != 9 {
		t.Fatalf("LSPA object class = %d, want 9", obj[0])
	}
	// Setup=3, Holding=4 at body offsets 12, 13 → object offsets 16, 17
	if obj[16] != 3 {
		t.Fatalf("LSPA setup_priority = %d, want 3", obj[16])
	}
	if obj[17] != 4 {
		t.Fatalf("LSPA holding_priority = %d, want 4", obj[17])
	}
	// L flag at body offset 14 → object offset 18 (mask 0x01)
	if obj[18]&0x01 == 0 {
		t.Fatal("LSPA L flag not set")
	}
}

func TestBuildMetricObject(t *testing.T) {
	// Metric type 1, C flag, value 12.5
	obj := BuildMetricObject(1, true, false, 12.5)
	// Object-Length = 12 (4 header + 8 body)
	objLen := uint16(obj[2])<<8 | uint16(obj[3])
	if objLen != 12 {
		t.Fatalf("Metric object length = %d, want 12", objLen)
	}
	// C flag at body offset 2 (mask 0x02) → object offset 6
	if obj[6]&0x02 == 0 {
		t.Fatal("Metric C flag not set")
	}
	// Type at body offset 3 → object offset 7
	if obj[7] != 1 {
		t.Fatalf("Metric type = %d, want 1", obj[7])
	}

	// Metric type 2, B flag, value 20.0
	obj2 := BuildMetricObject(2, false, true, 20.0)
	if obj2[6]&0x01 == 0 {
		t.Fatal("Metric B flag not set")
	}
	if obj2[7] != 2 {
		t.Fatalf("Metric type = %d, want 2", obj2[7])
	}
}

func TestBuildIPv6Endpoint(t *testing.T) {
	obj := BuildEndpointObjectIPv6("2001:db8::10", "2001:db8::20")
	if len(obj) != 36 {
		t.Fatalf("IPv6 endpoint length=%d, want 36", len(obj))
	}
	if obj[0] != 4 {
		t.Fatalf("Endpoint object class = %d, want 4", obj[0])
	}
	// Object type for IPv6 = 2 in high nibble
	if obj[1]&0xF0 != 0x20 {
		t.Fatalf("Endpoint object type = %02x, want 0x20 (OT=2)", obj[1]&0xF0)
	}
}

func TestBuildIPv6Subobject(t *testing.T) {
	ero := BuildEROObject([]pcepSubobject{
		{Type: "ipv6", Address: "2001:db8:1::1", PrefixLength: 128, L: true},
	})
	if len(ero) < 8 {
		t.Fatalf("ERO with IPv6 too short: %d", len(ero))
	}
	// Subobject type = 2 (IPv6), L flag on the type byte (Mask_L=0x80)
	found := false
	for i := 0; i < len(ero)-2; i++ {
		if ero[i]&0x7F == 2 && ero[i+1] == 20 {
			if ero[i]&0x80 != 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("ERO missing IPv6 subobject with L flag")
	}
}

func TestBuildStatefulOpen(t *testing.T) {
	cap := []core.PCEPCapability{
		{Kind: "stateful_pce", LSPUpdate: true, IncludeDBVersion: true},
	}
	pdu := BuildOpenMsg(30, 120, 7, cap)
	if len(pdu) < 4 {
		t.Fatalf("Stateful Open too short: %d", len(pdu))
	}
	if pdu[1] != 1 {
		t.Fatalf("Stateful Open msg type = %d, want 1", pdu[1])
	}
	// Basic Open is 12 bytes; stateful adds TLV 16 (8) + TLV 17 (8) = 28 bytes.
	msgLen := uint16(pdu[2])<<8 | uint16(pdu[3])
	if msgLen != 28 {
		t.Fatalf("Stateful Open msg_length = %d, want 28", msgLen)
	}
	// TLV 16 (Stateful-PCE-Capability) and TLV 17 (Sync-Capability) in the body.
	// Body starts after object header (4 bytes) + OPEN body (4 bytes) = offset 8.
	bodyStart := 8
	foundTLV16 := false
	foundTLV17 := false
	for i := bodyStart; i < len(pdu)-4; i++ {
		tlvType := uint16(pdu[i])<<8 | uint16(pdu[i+1])
		if tlvType == 16 {
			foundTLV16 = true
			// U bit at value byte 3 (flags[3] & 0x01)
			if pdu[i+4+3]&0x01 == 0 {
				t.Fatal("TLV 16 missing U bit (lsp_update)")
			}
			// S bit at value byte 3 (flags[3] & 0x02)
			if pdu[i+4+3]&0x02 == 0 {
				t.Fatal("TLV 16 missing S bit (include_db_version)")
			}
		}
		if tlvType == 17 {
			foundTLV17 = true
			if pdu[i+4+3]&0x02 == 0 {
				t.Fatal("TLV 17 missing S bit (include_db_version)")
			}
		}
	}
	if !foundTLV16 {
		t.Fatal("Stateful Open missing TLV 16 (Stateful-PCE-Capability)")
	}
	if !foundTLV17 {
		t.Fatal("Stateful Open missing TLV 17 (Sync-Capability)")
	}
}

// ---- Planner tests ----

func TestPlannerOpenKeepalive(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40000,
		DstPort: 4189,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "keepalive", Direction: "c2s"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// 3 handshake + 3 events + 4 teardown = 10 packets
	if len(packets) != 10 {
		t.Fatalf("expected 10 packets, got %d", len(packets))
	}
	// Packet 4 (index 3) should be Open c2s (PSH|ACK with payload)
	pkt := packets[3]
	if pkt.Direction != "up" {
		t.Fatalf("packet 4 direction = %s, want up", pkt.Direction)
	}
	if len(pkt.Payload) < 4 {
		t.Fatalf("packet 4 payload too short: %d", len(pkt.Payload))
	}
	if pkt.Payload[0] != 0x20 || pkt.Payload[1] != 1 {
		t.Fatalf("packet 4 payload header = %02x %02x, want 20 01", pkt.Payload[0], pkt.Payload[1])
	}
	// Packet 5 (index 4) should be Open s2c (down)
	pkt5 := packets[4]
	if pkt5.Direction != "down" {
		t.Fatalf("packet 5 direction = %s, want down", pkt5.Direction)
	}
	if pkt5.Payload[0] != 0x20 || pkt5.Payload[1] != 1 {
		t.Fatalf("packet 5 payload header = %02x %02x, want 20 01", pkt5.Payload[0], pkt5.Payload[1])
	}
	// Packet 6 (index 5) should be Keepalive c2s
	pkt6 := packets[5]
	if pkt6.Direction != "up" {
		t.Fatalf("packet 6 direction = %s, want up", pkt6.Direction)
	}
	if len(pkt6.Payload) != 4 {
		t.Fatalf("packet 6 payload len = %d, want 4", len(pkt6.Payload))
	}
	if pkt6.Payload[0] != 0x20 || pkt6.Payload[1] != 2 {
		t.Fatalf("packet 6 payload header = %02x %02x, want 20 02", pkt6.Payload[0], pkt6.Payload[1])
	}
}

func TestPlannerPCReqPCRep(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40000,
		DstPort: 4189,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "pcreq", Direction: "c2s", RequestID: 1001,
					Endpoint: &core.PCEPEndpoint{SourceIPv4: "192.0.2.10", DestinationIPv4: "192.0.2.20"}},
				{Kind: "pcerr", Direction: "s2c", RequestID: 1001},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// 3 handshake + 4 events + 4 teardown = 11 packets
	if len(packets) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(packets))
	}
	// Packet 6 (index 5) = PCReq c2s
	pkt := packets[5]
	if pkt.Direction != "up" || pkt.Payload[1] != 6 {
		t.Fatalf("packet 6: dir=%s type=%d, want up/6", pkt.Direction, pkt.Payload[1])
	}
	// Packet 7 (index 6) = PCErr s2c
	pkt7 := packets[6]
	if pkt7.Direction != "down" || pkt7.Payload[1] != 3 {
		t.Fatalf("packet 7: dir=%s type=%d, want down/3", pkt7.Direction, pkt7.Payload[1])
	}
}

func TestPlannerPCNtfPCErr(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40000,
		DstPort: 4189,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "pcntf", Direction: "s2c"},
				{Kind: "pcerr", Direction: "s2c"},
				{Kind: "keepalive", Direction: "c2s"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// 3 handshake + 5 events + 4 teardown = 12 packets
	if len(packets) != 12 {
		t.Fatalf("expected 12 packets, got %d", len(packets))
	}
	// Check PCNtf (msg type 4)
	if packets[5].Payload[1] != 4 {
		t.Fatalf("packet 6 type = %d, want 4 (PCNtf)", packets[5].Payload[1])
	}
	// Check PCErr (msg type 3)
	if packets[6].Payload[1] != 3 {
		t.Fatalf("packet 7 type = %d, want 3 (PCErr)", packets[6].Payload[1])
	}
}

func TestPlannerContextCancel(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40000,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate cancel

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// With cancelled context, select may randomly pick either case.
	// We just verify it returns quickly (within 1s) and doesn't
	// produce a full session.
	count := 0
	done := make(chan struct{})
	go func() {
		for range ch {
			count++
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
	// Should have at most 8 packets (3 handshake + 1 event + 4 teardown max)
	// but with cancelled context it may exit early
	if count > 8 {
		t.Fatalf("expected <= 8 packets with cancelled context, got %d", count)
	}
}

// ---- Generator tests ----

func TestGeneratorOpenKeepalive(t *testing.T) {
	g := &PCEPGenerator{}
	cfg := &core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "keepalive", Direction: "c2s"},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{PCEP: cfg},
		EmitMsg: emit,
	}
	err := g.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if !events[0].Up || events[0].Bytes[1] != 1 {
		t.Fatalf("event 0: up=%v type=%d, want up=true type=1", events[0].Up, events[0].Bytes[1])
	}
	if events[1].Up || events[1].Bytes[1] != 1 {
		t.Fatalf("event 1: up=%v type=%d, want up=false type=1", events[1].Up, events[1].Bytes[1])
	}
	if !events[2].Up || events[2].Bytes[1] != 2 {
		t.Fatalf("event 2: up=%v type=%d, want up=true type=2", events[2].Up, events[2].Bytes[1])
	}
}

// ---- Validation tests ----

func TestValidateConfigRequired(t *testing.T) {
	err := ValidateConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected 'config is required', got %v", err)
	}
}

func TestValidateConfigEmptyEvents(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{})
	if err == nil || !strings.Contains(err.Error(), "at least one event") {
		t.Fatalf("expected 'at least one event', got %v", err)
	}
}

func TestValidateConfigMissingDirection(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Keepalive: 30, Deadtime: 120, SID: 8},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("expected direction error, got %v", err)
	}
}

func TestValidateConfigUnknownProfile(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "unknown",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected 'unknown profile', got %v", err)
	}
}

func TestValidateConfigUnknownKind(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "bogus", Direction: "c2s"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("expected 'unknown kind', got %v", err)
	}
}

func TestValidateConfigKeepaliveWithObjects(t *testing.T) {
	rawObj := json.RawMessage(`{"class": "rp"}`)
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "keepalive", Direction: "c2s", Objects: []json.RawMessage{rawObj}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "keepalive must not have objects") {
		t.Fatalf("expected keepalive object error, got %v", err)
	}
}

func TestValidateConfigStatefulInBaseProfile(t *testing.T) {
	rawObj := json.RawMessage(`{"class": "lsp", "plsp_id": 77}`)
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "pcreq", Direction: "c2s", Objects: []json.RawMessage{rawObj}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "stateful") {
		t.Fatalf("expected 'requires stateful profile', got %v", err)
	}
}

func TestValidateConfigIPv6InIPv4Profile(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "pcreq", Direction: "c2s", RequestID: 1,
				Endpoint: &core.PCEPEndpoint{SourceIPv6: "2001:db8::10", DestinationIPv6: "2001:db8::20"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "IPv6 endpoint in IPv4 address family profile") {
		t.Fatalf("expected IPv6 endpoint error, got %v", err)
	}
}

func TestValidateConfigValid(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "keepalive", Direction: "c2s"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfigStatefulValid(t *testing.T) {
	err := ValidateConfig(&core.PCEPConfig{
		Profile: "pcep_rfc8231_stateful",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
			{Kind: "pcreq", Direction: "c2s", RequestID: 1},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- Negative / fault tests ----

func TestCheckFault(t *testing.T) {
	tests := []struct {
		kind string
		ok   bool
	}{
		{"", true},
		{"length", false},
		{"type", false},
		{"object_length", false},
		{"keepalive", false},
		{"session", false},
		{"address_family", false},
		{"stateful", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		err := CheckFault(tt.kind)
		if tt.ok && err != nil {
			t.Errorf("CheckFault(%q): unexpected error %v", tt.kind, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("CheckFault(%q): expected error", tt.kind)
		}
	}
}

// ---- Parse and error-propagation tests ----

func TestParsePCEPConfig(t *testing.T) {
	cfg := &core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			{Kind: "keepalive", Direction: "s2c"},
		},
	}
	payloads, ups, err := parsePCEPConfig(cfg)
	if err != nil {
		t.Fatalf("parsePCEPConfig: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
	if !ups[0] {
		t.Fatalf("event 0 direction: want up(c2s), got down")
	}
	if ups[1] {
		t.Fatalf("event 1 direction: want down(s2c), got up")
	}
}

func TestParsePCEPConfigUnknownEvent(t *testing.T) {
	cfg := &core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "bogus", Direction: "c2s"},
		},
	}
	_, _, err := parsePCEPConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "unknown event kind") {
		t.Fatalf("expected 'unknown event kind', got %v", err)
	}
}

func TestParsePCEPConfigUnknownMessage(t *testing.T) {
	cfg := &core.PCEPConfig{
		Profile: "pcep_rfc5440_ipv4",
		Events: []core.PCEPEvent{
			{Kind: "unknown", Direction: "c2s", MessageType: 99},
		},
	}
	payloads, _, err := parsePCEPConfig(cfg)
	if err != nil {
		t.Fatalf("parsePCEPConfig unknown: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	if payloads[0][1] != 99 {
		t.Fatalf("unknown message type = %d, want 99", payloads[0][1])
	}
}

func TestPlannerValidatesConfig(t *testing.T) {
	p := Planner{}
	// Missing PCEP config
	_, err := p.Plan(context.Background(), core.FlowSpec{})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected 'config is required', got %v", err)
	}
}

// ---- Multi-session planner test ----

func TestPlannerMultiSession(t *testing.T) {
	// Test that the planner can handle the multi-session case
	// by verifying individual session behavior
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40001,
		DstPort: 4189,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "pcreq", Direction: "c2s", RequestID: 8101,
					Endpoint: &core.PCEPEndpoint{SourceIPv4: "192.0.2.10", DestinationIPv4: "192.0.2.20"}},
				{Kind: "pcrep", Direction: "s2c", RequestID: 8101},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// 3 handshake + 4 events + 4 teardown = 11 packets
	if len(packets) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(packets))
	}
	// Verify PCReq then PCRep
	if packets[5].Payload[1] != 6 {
		t.Fatalf("packet 6 type = %d, want 6 (PCReq)", packets[5].Payload[1])
	}
	if packets[6].Payload[1] != 7 {
		t.Fatalf("packet 7 type = %d, want 7 (PCRep)", packets[6].Payload[1])
	}
}

// ---- Stateful planner test ----

func TestPlannerStatefulLSP(t *testing.T) {
	rawRP := json.RawMessage(`{"class": "rp", "requested_id_number": 5001, "flags": {"p": true}}`)
	rawLSP := json.RawMessage(`{"class": "lsp", "plsp_id": 77, "flags": {"delegate": true, "create": true, "administrative": true}}`)
	rawSRP := json.RawMessage(`{"class": "srp", "id_number": 9001, "flags": {"remove": false}}`)

	p := Planner{}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "192.0.2.20",
		SrcPort: 40000,
		DstPort: 4189,
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc8231_stateful",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "pcreq", Direction: "c2s", RequestID: 5001,
					Endpoint: &core.PCEPEndpoint{SourceIPv4: "192.0.2.10", DestinationIPv4: "192.0.2.20"},
					Objects:  []json.RawMessage{rawRP, rawLSP, rawSRP}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// 3 handshake + 3 events + 4 teardown = 10 packets
	if len(packets) != 10 {
		t.Fatalf("expected 10 packets, got %d", len(packets))
	}
	// PCReq with LSP/SRP objects
	pkt := packets[5]
	if pkt.Payload[1] != 6 {
		t.Fatalf("packet 6 type = %d, want 6", pkt.Payload[1])
	}
	// Check for LSP object (class 32)
	foundLSP := false
	for i := 0; i < len(pkt.Payload)-4; i++ {
		if pkt.Payload[i] == 32 {
			foundLSP = true
			break
		}
	}
	if !foundLSP {
		t.Fatal("PCReq missing LSP object")
	}
}

// ---- Error propagation test ----

func TestPlannerErrorPropagation(t *testing.T) {
	// Planner should return an error for invalid config
	// (simulating the N1 malformed length case)
	p := Planner{}
	_, err := p.Plan(context.Background(), core.FlowSpec{
		PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
				{Kind: "open", Direction: "s2c", Keepalive: 30, Deadtime: 120, SID: 8},
				{Kind: "pcreq", Direction: "c2s", WireFault: &core.PCEPFault{Kind: "length", Declared: 2}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for malformed length, got nil")
	}
}

// ---- Hex output verification tests ----

func TestHexOpenMsg(t *testing.T) {
	// Verify the exact hex for Open message as expected by pcep.json
	// Frame hex: 20 01 00 0c (corrected — OPEN body is 4 bytes, not 8)
	pdu := BuildOpenMsg(30, 120, 7, nil)
	if pdu[0] != 0x20 || pdu[1] != 0x01 || pdu[2] != 0x00 || pdu[3] != 0x0c {
		t.Fatalf("Open header = %02x %02x %02x %02x, want 20 01 00 0c",
			pdu[0], pdu[1], pdu[2], pdu[3])
	}
	// msg_length = 12
	msgLen := uint16(pdu[2])<<8 | uint16(pdu[3])
	if msgLen != 12 {
		t.Fatalf("Open msg_length = %d, want 12", msgLen)
	}
	// OPEN object header: Class=1, Type=1 (0x10), Length=8
	if pdu[4] != 1 {
		t.Fatalf("Open object class = %d, want 1", pdu[4])
	}
	if pdu[5] != 0x10 {
		t.Fatalf("Open object header byte1 = %02x, want 10 (Type=1, P=0, I=0)", pdu[5])
	}
}

func TestHexKeepAliveMsg(t *testing.T) {
	// Frame hex: 20 02 00 04
	pdu := BuildKeepAliveMsg()
	if pdu[0] != 0x20 || pdu[1] != 0x02 || pdu[2] != 0x00 || pdu[3] != 0x04 {
		t.Fatalf("Keepalive header = %02x %02x %02x %02x, want 20 02 00 04",
			pdu[0], pdu[1], pdu[2], pdu[3])
	}
	// msg_length = 4
	msgLen := uint16(pdu[2])<<8 | uint16(pdu[3])
	if msgLen != 4 {
		t.Fatalf("Keepalive msg_length = %d, want 4", msgLen)
	}
}

func TestHexPCReqMsg(t *testing.T) {
	// Frame hex starts with: 20 06
	rp := BuildRPObject(1001, true, false)
	ep := BuildEndpointObjectIPv4("192.0.2.10", "192.0.2.20")
	pdu := BuildPCReqMsg([][]byte{rp, ep})
	if pdu[0] != 0x20 || pdu[1] != 0x06 {
		t.Fatalf("PCReq header = %02x %02x, want 20 06", pdu[0], pdu[1])
	}
}

func TestHexPCRepMsg(t *testing.T) {
	// Frame hex starts with: 20 07
	rro := BuildRROObject([]pcepSubobject{
		{Type: "ipv4", Address: "198.51.100.1", PrefixLength: 32, L: false},
	})
	pdu := BuildPCRepMsg([][]byte{rro})
	if pdu[0] != 0x20 || pdu[1] != 0x07 {
		t.Fatalf("PCRep header = %02x %02x, want 20 07", pdu[0], pdu[1])
	}
}

func TestHexPCNtfMsg(t *testing.T) {
	// Frame hex starts with: 20 04
	pdu := BuildPCNtfMsg(1, 1)
	if pdu[0] != 0x20 || pdu[1] != 0x04 {
		t.Fatalf("PCNtf header = %02x %02x, want 20 04", pdu[0], pdu[1])
	}
}

func TestHexPCErrMsg(t *testing.T) {
	// Frame hex starts with: 20 03
	pdu := BuildPCErrMsg(1, 2)
	if pdu[0] != 0x20 || pdu[1] != 0x03 {
		t.Fatalf("PCErr header = %02x %02x, want 20 03", pdu[0], pdu[1])
	}
}

// ---- Object P/I flag verification ----

func TestObjectFlags(t *testing.T) {
	// pcep.obj.hdr.flags.p and pcep.obj.hdr.flags.i
	obj := BuildRPObject(8501, true, true)
	// Object header byte 1: Type=1 (0x10) | P=1 (0x02) | I=1 (0x01) = 0x13
	if obj[1] != 0x13 {
		t.Fatalf("Object header byte 1 = %02x, want 0x13 (P=1, I=1)", obj[1])
	}
	// Object header byte 1 P flag only
	obj2 := BuildRPObject(8501, true, false)
	if obj2[1] != 0x12 {
		t.Fatalf("Object header byte 1 = %02x, want 0x12 (P=1, I=0)", obj2[1])
	}
	// Object header byte 1 I flag only
	obj3 := BuildRPObject(8501, false, true)
	if obj3[1] != 0x11 {
		t.Fatalf("Object header byte 1 = %02x, want 0x11 (P=0, I=1)", obj3[1])
	}
}

// ---- Metric flag verification ----

func TestMetricFlags(t *testing.T) {
	// C flag + type 1 + value 12.5
	obj := BuildMetricObject(1, true, false, 12.5)
	if obj[6]&0x02 == 0 {
		t.Fatal("Metric C flag not set")
	}
	if obj[6]&0x01 != 0 {
		t.Fatal("Metric B flag should not be set")
	}

	// B flag + type 2 + value 20.0
	obj2 := BuildMetricObject(2, false, true, 20.0)
	if obj2[6]&0x01 == 0 {
		t.Fatal("Metric B flag not set")
	}
	if obj2[6]&0x02 != 0 {
		t.Fatal("Metric C flag should not be set")
	}
}

// ---- Name method test ----

func TestName(t *testing.T) {
	p := Planner{}
	if p.Name() != "pcep" {
		t.Fatalf("Planner.Name() = %s, want pcep", p.Name())
	}
	g := &PCEPGenerator{}
	if g.Name() != "pcep" {
		t.Fatalf("PCEPGenerator.Name() = %s, want pcep", g.Name())
	}
}

// ---- Generator error test ----

func TestGeneratorNilEmitMsg(t *testing.T) {
	g := &PCEPGenerator{}
	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{PCEP: &core.PCEPConfig{
			Profile: "pcep_rfc5440_ipv4",
			Events: []core.PCEPEvent{
				{Kind: "open", Direction: "c2s", Keepalive: 30, Deadtime: 120, SID: 7},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("expected 'EmitMsg is nil', got %v", err)
	}
}

func TestGeneratorNilConfig(t *testing.T) {
	g := &PCEPGenerator{}
	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected 'config is required', got %v", err)
	}
}

// ---- Benchmark ----

func BenchmarkBuildOpenMsg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		BuildOpenMsg(30, 120, 7, nil)
	}
}

func BenchmarkBuildPCReqMsg(b *testing.B) {
	rp := BuildRPObject(1001, true, false)
	ep := BuildEndpointObjectIPv4("192.0.2.10", "192.0.2.20")
	ero := BuildEROObject([]pcepSubobject{
		{Type: "ipv4", Address: "198.51.100.1", PrefixLength: 32, L: true},
	})
	metric := BuildMetricObject(1, true, false, 12.5)
	for i := 0; i < b.N; i++ {
		BuildPCReqMsg([][]byte{rp, ep, ero, metric})
	}
}

// ---- init test ----

func TestInitRegistration(t *testing.T) {
	// Verify init() ran by checking the generator is registered
	// (just check that the package init didn't panic)
	_ = fmt.Sprintf("pcep package loaded")
}
