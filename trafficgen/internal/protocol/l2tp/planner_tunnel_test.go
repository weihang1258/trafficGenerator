package l2tp

// Failing-first, spec-driven tests for the L2TP "tunnel_with_data" scenario
// and ZLB (Zero Length Body) acknowledgment support.
//
// Spec sources:
//   - RFC 2661 §3.1 (control/data message headers), §4 (control messages),
//     §5 (AVPs), §7 (LAC/LNS roles)
//   - RFC 3931 §3.1 (L2TPv3 data messages: no Tunnel ID, 32-bit Session ID)
//   - RFC 1661 §6 (PPP frame: Protocol field + Information)
//   - RFC 791 §3.1 (IPv4 header: version/IHL/TTL/protocol/checksum)
//
// Coverage:
//   1. Complete tunnel scenario: control establish + PPP inner-IPv4 data +
//      teardown, in order.
//   2. Inner IPv4 packet correctness (version=4, IHL=5, checksum, proto,
//      src/dst IP).
//   3. Inner L4 (UDP) header with ports.
//   4. Multiple PPP data frames (tunnel traffic).
//   5. L2TPv3 data message variant.
//   6. ZLB acknowledgment (control message with no AVPs).
//   7. Mutual exclusion + validation failure paths.

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ipv4HeaderChecksum recomputes the IPv4 header checksum (RFC 791 §3.1) for
// verification in tests. The checksum field itself must be zero during
// computation.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// findPPPDataFrame locates the first PPP data frame in configs (a packet
// whose L2TP data message carries PPP). Returns the PPP bytes (after the
// L2TP data header) and the packet index, or nil/-1 if not found.
func findPPPDataPayload(configs []core.PacketConfig, version uint8) ([]byte, int) {
	for i, c := range configs {
		p := c.Payload
		if version == VersionL2TPv3 {
			// v3 data: Flags(1)+Ver(1)+SesID(4) = 6 bytes; T=0 (data).
			if len(p) < 6 {
				continue
			}
			// Data message: bit 7 of byte 0 (T flag) is 0 for v3 data
			// (v3 data flags byte has no T bit; control uses 0xC8xx).
			// Distinguish from control: control starts 0xC8 0x03.
			if p[0] == 0xC8 {
				continue // control message
			}
			return p[6:], i
		}
		// v2 data: TunID(2)+SesID(2) = 4 bytes; control starts 0xC8.
		if len(p) < 4 {
			continue
		}
		if p[0] == 0xC8 {
			continue // control message
		}
		return p[4:], i
	}
	return nil, -1
}

// ============================================================================
// §1 Complete tunnel scenario (RFC 2661 §4 + §7 + RFC 1661 §6)
// ============================================================================

// 1.1: Scenario="tunnel_with_data" emits the full control establishment
// (SCCRQ->SCCRP->SCCCN->ICRQ->ICRP->ICCN) + PPP data + StopCCN, in order.
func TestL2TP_TunnelWithData_FullSequence(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
		},
	}
	configs := mustPlan(t, p, spec)

	// 6 control + 1 PPP data + 1 StopCCN = 8 packets.
	if len(configs) != 8 {
		t.Fatalf("expected 8 packets (6 control + 1 data + 1 stopccn), got %d", len(configs))
	}

	// Verify control message types in order via the Message Type AVP.
	wantMsgTypes := []uint16{1, 2, 3, 9, 10, 11} // SCCRQ, SCCRP, SCCCN, ICRQ, ICRP, ICCN
	for i, want := range wantMsgTypes {
		_, _, _, val, ok := findAVP(configs[i].Payload, v2ControlHeaderSize, attrMessageType)
		if !ok {
			t.Fatalf("configs[%d]: Message Type AVP not found", i)
		}
		if len(val) < 2 {
			t.Fatalf("configs[%d]: Message Type AVP value too short", i)
		}
		got := binary.BigEndian.Uint16(val)
		if got != want {
			t.Errorf("configs[%d] msg type = %d, want %d", i, got, want)
		}
	}

	// Packet 7 (index 6) is PPP data: T=0 (not control).
	dataPkt := configs[6].Payload
	if len(dataPkt) < 4 {
		t.Fatal("PPP data packet too short")
	}
	if dataPkt[0] == 0xC8 {
		t.Errorf("configs[6] is a control message (0xC8), expected data message")
	}

	// Packet 8 (index 7) is StopCCN (msg type 4).
	_, _, _, val, ok := findAVP(configs[7].Payload, v2ControlHeaderSize, attrMessageType)
	if !ok {
		t.Fatal("StopCCN: Message Type AVP not found")
	}
	if len(val) < 2 || binary.BigEndian.Uint16(val) != 4 {
		t.Errorf("configs[7] msg type = %x, want 4 (StopCCN)", val)
	}
}

// 1.2: Direction auto-resolution for LAC role: SCCRQ/SCCCN/ICRQ/ICCN up,
// SCCRP/ICRP down, PPP data up, StopCCN up.
func TestL2TP_TunnelWithData_Directions(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
		},
	}
	configs := mustPlan(t, p, spec)
	wantDirs := []string{"up", "down", "up", "up", "down", "up", "up", "up"}
	for i, want := range wantDirs {
		if configs[i].Direction != want {
			t.Errorf("configs[%d].Direction = %s, want %s", i, configs[i].Direction, want)
		}
	}
}

// 1.3: LNS role flips directions.
func TestL2TP_TunnelWithData_LNSDirections(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lns",
			Scenario: "tunnel_with_data",
		},
	}
	configs := mustPlan(t, p, spec)
	// LNS: SCCRQ down, SCCRP up, SCCCN down, ICRQ down, ICRP up, ICCN down, data down, StopCCN down.
	wantDirs := []string{"down", "up", "down", "down", "up", "down", "down", "down"}
	for i, want := range wantDirs {
		if configs[i].Direction != want {
			t.Errorf("configs[%d].Direction = %s, want %s", i, configs[i].Direction, want)
		}
	}
}

// ============================================================================
// §2 Inner IPv4 packet correctness (RFC 791 §3.1 + RFC 1661 §6)
// ============================================================================

// 2.1: PPP Protocol field = 0x0021 (IPv4) and inner IPv4 header is valid.
func TestL2TP_TunnelWithData_InnerIPv4Header(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP: "10.10.10.1",
				DstIP: "10.10.10.2",
				Proto: 17, // UDP
			},
		},
	}
	configs := mustPlan(t, p, spec)

	ppp, idx := findPPPDataPayload(configs, VersionL2TPv2)
	if ppp == nil {
		t.Fatal("PPP data frame not found")
	}
	// PPP frame: optional 0xFF 0x03 HDLC + Protocol(2) + IPv4.
	// The planner emits L2PPPHeader=true for scenario data, so expect 0xFF 0x03.
	var proto uint16
	var ipStart int
	if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		proto = binary.BigEndian.Uint16(ppp[2:4])
		ipStart = 4
	} else {
		proto = binary.BigEndian.Uint16(ppp[0:2])
		ipStart = 2
	}
	if proto != 0x0021 {
		t.Errorf("PPP Protocol = 0x%04x, want 0x0021 (IPv4)", proto)
	}
	if ipStart+20 > len(ppp) {
		t.Fatalf("inner IPv4 header truncated at offset %d (len=%d)", ipStart, len(ppp))
	}
	ipHdr := ppp[ipStart : ipStart+20]
	// Version=4, IHL=5 -> 0x45.
	if ipHdr[0] != 0x45 {
		t.Errorf("inner IPv4 ver/ihl = 0x%02x, want 0x45", ipHdr[0])
	}
	// TTL.
	if ipHdr[8] != 64 {
		t.Errorf("inner IPv4 TTL = %d, want 64", ipHdr[8])
	}
	// Protocol = 17 (UDP).
	if ipHdr[9] != 17 {
		t.Errorf("inner IPv4 proto = %d, want 17 (UDP)", ipHdr[9])
	}
	// SrcIP.
	srcIP := net.IP(ipHdr[12:16]).String()
	if srcIP != "10.10.10.1" {
		t.Errorf("inner src IP = %s, want 10.10.10.1", srcIP)
	}
	dstIP := net.IP(ipHdr[16:20]).String()
	if dstIP != "10.10.10.2" {
		t.Errorf("inner dst IP = %s, want 10.10.10.2", dstIP)
	}
	_ = idx
}

// 2.2: Inner IPv4 header checksum is correct (recompute and compare).
func TestL2TP_TunnelWithData_InnerIPv4Checksum(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP: "172.16.0.1",
				DstIP: "172.16.0.2",
				Proto: 6, // TCP
			},
		},
	}
	configs := mustPlan(t, p, spec)
	ppp, _ := findPPPDataPayload(configs, VersionL2TPv2)
	if ppp == nil {
		t.Fatal("PPP data frame not found")
	}
	var ipStart int
	if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		ipStart = 4
	} else {
		ipStart = 2
	}
	ipHdr := make([]byte, 20)
	copy(ipHdr, ppp[ipStart:ipStart+20])
	stored := binary.BigEndian.Uint16(ipHdr[10:12])
	// Zero the checksum field for recomputation.
	ipHdr[10] = 0
	ipHdr[11] = 0
	computed := ipv4HeaderChecksum(ipHdr)
	if stored != computed {
		t.Errorf("inner IPv4 checksum = 0x%04x, want 0x%04x", stored, computed)
	}
}

// 2.3: Inner L4 (UDP) header present with configured ports.
func TestL2TP_TunnelWithData_InnerUDPL4(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP:    "10.10.10.1",
				DstIP:    "10.10.10.2",
				Proto:    17,
				SrcPort:  5000,
				DstPort:  8080,
				Payload:  []byte("hello-inner"),
			},
		},
	}
	configs := mustPlan(t, p, spec)
	ppp, _ := findPPPDataPayload(configs, VersionL2TPv2)
	if ppp == nil {
		t.Fatal("PPP data frame not found")
	}
	var ipStart int
	if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		ipStart = 4
	} else {
		ipStart = 2
	}
	// IPv4 header IHL=5 -> 20 bytes. UDP header starts at ipStart+20.
	udpStart := ipStart + 20
	if udpStart+8 > len(ppp) {
		t.Fatalf("inner UDP header truncated: need %d, have %d", udpStart+8, len(ppp))
	}
	srcPort := binary.BigEndian.Uint16(ppp[udpStart : udpStart+2])
	dstPort := binary.BigEndian.Uint16(ppp[udpStart+2 : udpStart+4])
	udpLen := binary.BigEndian.Uint16(ppp[udpStart+4 : udpStart+6])
	if srcPort != 5000 {
		t.Errorf("inner UDP src port = %d, want 5000", srcPort)
	}
	if dstPort != 8080 {
		t.Errorf("inner UDP dst port = %d, want 8080", dstPort)
	}
	// UDP length = 8 (header) + len(payload).
	wantLen := uint16(8 + len("hello-inner"))
	if udpLen != wantLen {
		t.Errorf("inner UDP length = %d, want %d", udpLen, wantLen)
	}
}

// 2.4: Inner TCP header present with configured ports and data offset.
func TestL2TP_TunnelWithData_InnerTCPL4(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP:   "10.10.10.1",
				DstIP:   "10.10.10.2",
				Proto:   6,
				SrcPort: 4000,
				DstPort: 22,
			},
		},
	}
	configs := mustPlan(t, p, spec)
	ppp, _ := findPPPDataPayload(configs, VersionL2TPv2)
	if ppp == nil {
		t.Fatal("PPP data frame not found")
	}
	var ipStart int
	if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		ipStart = 4
	} else {
		ipStart = 2
	}
	tcpStart := ipStart + 20
	if tcpStart+20 > len(ppp) {
		t.Fatalf("inner TCP header truncated: need %d, have %d", tcpStart+20, len(ppp))
	}
	srcPort := binary.BigEndian.Uint16(ppp[tcpStart : tcpStart+2])
	dstPort := binary.BigEndian.Uint16(ppp[tcpStart+2 : tcpStart+4])
	if srcPort != 4000 {
		t.Errorf("inner TCP src port = %d, want 4000", srcPort)
	}
	if dstPort != 22 {
		t.Errorf("inner TCP dst port = %d, want 22", dstPort)
	}
	// Data offset (high nibble of byte 12) should be >= 5.
	dataOff := ppp[tcpStart+12] >> 4
	if dataOff < 5 {
		t.Errorf("inner TCP data offset = %d, want >= 5", dataOff)
	}
}

// ============================================================================
// §3 Multiple PPP data frames (tunnel traffic) - RFC 1661 §6
// ============================================================================

// 3.1: DataFrames=3 emits 3 PPP data frames with distinct inner IPIDs.
func TestL2TP_TunnelWithData_MultipleDataFrames(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP:     "10.10.10.1",
				DstIP:     "10.10.10.2",
				Proto:     17,
				DataFrames: 3,
			},
		},
	}
	configs := mustPlan(t, p, spec)
	// 6 control + 3 data + 1 StopCCN = 10.
	if len(configs) != 10 {
		t.Fatalf("expected 10 packets (6 control + 3 data + 1 stopccn), got %d", len(configs))
	}

	// Collect inner IPIDs from the 3 data frames (indices 6,7,8).
	ipids := make(map[uint16]bool)
	for i := 6; i <= 8; i++ {
		ppp := configs[i].Payload[4:] // skip v2 data header
		var ipStart int
		if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
			ipStart = 4
		} else {
			ipStart = 2
		}
		ipid := binary.BigEndian.Uint16(ppp[ipStart+4 : ipStart+6])
		if ipids[ipid] {
			t.Errorf("duplicate inner IPID %d at data frame %d", ipid, i)
		}
		ipids[ipid] = true
	}
	if len(ipids) != 3 {
		t.Errorf("expected 3 distinct IPIDs, got %d", len(ipids))
	}
}

// ============================================================================
// §4 L2TPv3 data message variant (RFC 3931 §3.1)
// ============================================================================

// 4.1: Scenario="tunnel_with_data" with Version=3 emits v3 data messages
// (no Tunnel ID, 32-bit Session ID, Flags byte + Ver=3).
func TestL2TP_TunnelWithData_V3DataMessage(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:         VersionL2TPv3,
			Role:            "lac",
			Scenario:        "tunnel_with_data",
			LocalSessionID32: 0x12345678,
		},
	}
	configs := mustPlan(t, p, spec)
	// Find the PPP data frame (index 6).
	dataPkt := configs[6].Payload
	if len(dataPkt) < 6 {
		t.Fatal("v3 data packet too short")
	}
	// v3 data: byte 0 = flags (not 0xC8), byte 1 = 0x03 (Ver=3).
	if dataPkt[0] == 0xC8 {
		t.Errorf("data packet is control (0xC8), expected v3 data message")
	}
	if dataPkt[1] != 0x03 {
		t.Errorf("v3 data Ver byte = 0x%02x, want 0x03", dataPkt[1])
	}
	// 32-bit Session ID at offset 2-5.
	sesID := binary.BigEndian.Uint32(dataPkt[2:6])
	if sesID != 0x12345678 {
		t.Errorf("v3 data Session ID = 0x%08x, want 0x12345678", sesID)
	}
	// PPP payload starts at offset 6 (no Tunnel ID in v3 data).
	ppp := dataPkt[6:]
	var proto uint16
	if len(ppp) >= 4 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		proto = binary.BigEndian.Uint16(ppp[2:4])
	} else if len(ppp) >= 2 {
		proto = binary.BigEndian.Uint16(ppp[0:2])
	}
	if proto != 0x0021 {
		t.Errorf("PPP Protocol = 0x%04x, want 0x0021 (IPv4)", proto)
	}
}

// ============================================================================
// §5 ZLB acknowledgment (RFC 2661 §3.1.1 - Zero Length Body)
// ============================================================================

// 5.1: ZLB step emits a control message with NO AVPs (just the 12-byte v2
// header). Length field = 12 (header only).
func TestL2TP_ZLB_NoAVPs(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:   VersionL2TPv2,
			Role:      "lac",
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}, {Type: stepZLB}},
		},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(configs))
	}
	zlb := configs[1].Payload
	// v2 control header is 12 bytes; ZLB has no AVPs so Length = 12.
	flags, length, _, _, _, _, ok := readControlHeader(zlb)
	if !ok {
		t.Fatal("ZLB payload too short for v2 header")
	}
	// T=1, L=1, S=1, Ver=2 -> 0xC802.
	if flags != 0xC802 {
		t.Errorf("ZLB flags = 0x%04x, want 0xC802", flags)
	}
	if int(length) != v2ControlHeaderSize {
		t.Errorf("ZLB Length = %d, want %d (header only, no AVPs)", length, v2ControlHeaderSize)
	}
	if len(zlb) != v2ControlHeaderSize {
		t.Errorf("ZLB payload len = %d, want %d (no AVP bytes)", len(zlb), v2ControlHeaderSize)
	}
}

// 5.2: ZLB is tunnel-level (Session ID = 0 in header).
func TestL2TP_ZLB_TunnelLevelSessionIDZero(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:        VersionL2TPv2,
			Role:           "lac",
			LocalSessionID: 99,
			Scenarios:      []core.L2TPStep{{Type: stepZLB}},
		},
	}
	configs := mustPlan(t, p, spec)
	_, _, _, sesID, _, _, ok := readControlHeader(configs[0].Payload)
	if !ok {
		t.Fatal("ZLB payload too short")
	}
	if sesID != 0 {
		t.Errorf("ZLB Session ID = %d, want 0 (tunnel-level, RFC 2661 §5.1)", sesID)
	}
}

// 5.3: ZLB carries Ns/Nr sequence numbers (S=1).
func TestL2TP_ZLB_SequenceNumbers(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:   VersionL2TPv2,
			Role:      "lac",
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}, {Type: stepZLB}},
		},
	}
	configs := mustPlan(t, p, spec)
	// SCCRQ is up (Ns=0), then ZLB is up (Ns=1, Nr=0).
	_, _, _, _, ns, nr, ok := readControlHeader(configs[1].Payload)
	if !ok {
		t.Fatal("ZLB payload too short")
	}
	if ns != 1 {
		t.Errorf("ZLB Ns = %d, want 1 (after SCCRQ Ns=0)", ns)
	}
	if nr != 0 {
		t.Errorf("ZLB Nr = %d, want 0", nr)
	}
}

// ============================================================================
// §6 Validation failure paths
// ============================================================================

// 6.1: Scenario + Scenarios both set -> mutual exclusion error.
func TestL2TP_TunnelWithData_MutualExclusion(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:   VersionL2TPv2,
			Scenario:  "tunnel_with_data",
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted Scenario + Scenarios; want mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "Scenario") || !strings.Contains(err.Error(), "Scenarios") {
		t.Errorf("err = %v, want contains 'Scenario' and 'Scenarios'", err)
	}
}

// 6.2: Scenario + PPPFrames both set -> mutual exclusion error.
func TestL2TP_TunnelWithData_MutualExclusionPPPFrames(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:   VersionL2TPv2,
			Scenario:  "tunnel_with_data",
			PPPFrames: []core.L2TPPPPFrame{{Protocol: 0x0021, Data: []byte("x")}},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted Scenario + PPPFrames; want mutual-exclusion error")
	}
}

// 6.3: Unknown Scenario value -> error.
func TestL2TP_TunnelWithData_UnknownScenario(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Scenario: "bogus_scenario",
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted unknown scenario; want error")
	}
	if !strings.Contains(err.Error(), "Scenario") {
		t.Errorf("err = %v, want contains 'Scenario'", err)
	}
}

// 6.4: InnerIP invalid SrcIP -> error.
func TestL2TP_TunnelWithData_InvalidInnerSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP: "not-an-ip",
				DstIP: "10.10.10.2",
			},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted invalid InnerIP.SrcIP; want error")
	}
}

// 6.5: InnerIP invalid Proto -> error (only 1/6/17 supported).
func TestL2TP_TunnelWithData_InvalidInnerProto(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP: "10.10.10.1",
				DstIP: "10.10.10.2",
				Proto: 99,
			},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted Proto=99; want error")
	}
}

// 6.6: Scenario + InnerIP SrcIP/DstIP version mismatch -> error.
func TestL2TP_TunnelWithData_InnerIPVersionMismatch(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				SrcIP: "::1", // IPv6
				DstIP: "10.10.10.2",
			},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate accepted IPv6 inner SrcIP; want error (inner must be IPv4)")
	}
}

// 6.7: Context cancellation terminates the scenario. A pre-cancelled
// context should let at most 1 packet through (matching the existing
// TestL2TP_PlanContextCancel behavior).
func TestL2TP_TunnelWithData_ContextCancel(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Scenario: "tunnel_with_data",
			InnerIP: &core.L2TPInnerIP{
				DataFrames: 3,
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var configs []core.PacketConfig
	for c := range ch {
		configs = append(configs, c)
	}
	// Pre-cancelled ctx => at most 1 packet emitted before ctx.Done observed.
	if len(configs) > 1 {
		t.Errorf("expected at most 1 packet after pre-cancelled ctx, got %d", len(configs))
	}
}
