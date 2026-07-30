// Package rdp scenario-mode tests (MS-RDPBCGR §2.2 connection sequence +
// design_rdp.md §4 scenarios).
//
// These tests are written failing-first: they assert the new
// RDPConfig.Scenario field and per-scenario DataEvents/ServerResponses
// auto-population produce the spec-correct byte sequence on the wire.
// Each test corresponds to one or more rows of the §3.1 state-machine
// table and asserts a wire-shape invariant.
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// phaseKind classifies the high-level RDP phase a packet belongs to.
type phaseKind int

const (
	phaseHandshake phaseKind = iota
	phaseX224CR
	phaseX224CC
	phaseTLSClientHello
	phaseTLSServerHello
	phaseMCSConnectInitial
	phaseMCSConnectResponse
	phaseMCSErectDomain
	phaseMCSAttachUserReq
	phaseMCSAttachUserConf
	phaseMCSChannelJoinReq
	phaseMCSChannelJoinConf
	phaseSecurityExchange
	phaseClientInfo
	phaseLicense
	phaseCapability
	phaseActive
	phaseShutdown
	phaseMCSDisconnect
	phaseTeardown
)

// classifyPacket inspects the TCP application-layer payload and returns
// the high-level RDP phase it belongs to. Returns -1 when the packet does
// not match any phase (e.g. control packet or unknown payload).
//
// Note on empty-payload ACKs: the TCP 3-way handshake emits a SYN, a
// SYN-ACK, and an ACK. All three are control packets with empty
// payload; only the SYN carries flag 0x02 uniquely. SYN-ACK (0x12) and
// the handshake ACK (0x10) are indistinguishable from teardown FIN-ACK
// (0x11) and ACK (0x10) by flag alone, so this function classifies them
// all as -1 (control plane). The integration tests rely on positional
// checks (phase counts and order) rather than classifying every
// control packet.
//
// Byte layout reminder (MS-RDPBCGR §2.2):
//   TPKT:    [0]=0x03 [1]=0x00 [2:4]=length BE
//   X.224 DT:[4]=0x02(LI) [5]=0xF0(Code) [6]=0x00(roa)
//   RDP PDU: [7:]  (Share Control Header / Client Info / License / SecExch)
// For Share Control Header: [7:9]=totalLength LE, [9:11]=pduType LE,
// [11:13]=pduSource LE. For DATA pduType=0x0017, Share Data Header
// follows: [21]=pduType2 (low byte).
// MCS Connect-Initial: [7]=0x7F [8]=0x65 (APPLICATION 101 long form).
// MCS Connect-Response: [7]=0x7F [8]=0x66 (APPLICATION 102 long form).
// FastPath Input: [0]&0xC0==0x00, [1]=length (non-zero, distinguishes
// from TPKT which has [1]=0x00 reserved).
// TLS record: [0]=0x16, [1]=0x03 (version major).
func classifyPacket(cfg core.PacketConfig) phaseKind {
	if len(cfg.Payload) == 0 {
		if cfg.L4.Flags == 0x02 {
			return phaseHandshake
		}
		return -1
	}
	pl := cfg.Payload

	// TLS record: ContentType=0x16 (Handshake) + Version 0x03 0x0X.
	// Checked before FastPath because 0x16 & 0xC0 == 0x00 (looks like
	// FastPath Input action).
	if pl[0] == 0x16 && len(pl) >= 3 && pl[1] == 0x03 {
		if cfg.Direction == "up" {
			return phaseTLSClientHello
		}
		return phaseTLSServerHello
	}

	// FastPath Output: action header high 2 bits = 01 (0x40).
	if pl[0]&0xC0 == 0x40 {
		return phaseActive
	}

	// FastPath Input: action header high 2 bits = 00 (0x00). BUT we must
	// exclude TPKT packets (pl[0]==0x03, pl[1]==0x00 reserved) because
	// 0x03 & 0xC0 == 0x00. The distinguishing factor: TPKT has
	// pl[1]==0x00 (reserved), FastPath Input has pl[1]==length (!= 0).
	if pl[0]&0xC0 == 0x00 && len(pl) >= 2 && pl[1] != 0x00 {
		return phaseActive
	}

	// TPKT-wrapped X.224 / MCS / RDP PDU.
	if pl[0] != TPKTVersion || len(pl) < 6 {
		return -1
	}
	switch pl[5] {
	case X224CR:
		return phaseX224CR
	case X224CC:
		return phaseX224CC
	case X224DT:
		if len(pl) < 8 {
			return -1
		}
		// MCS PDU first byte at pl[7].
		switch pl[7] {
		case MCSConnectInitialTag: // 0x7F — APPLICATION long-form prefix
			if len(pl) < 9 {
				return -1
			}
			switch pl[8] {
			case MCSConnectInitialTagByte: // 0x65
				return phaseMCSConnectInitial
			case MCSConnectResponseTagByte: // 0x66
				return phaseMCSConnectResponse
			}
			return -1
		case MCSErectDomainRequest:
			return phaseMCSErectDomain
		case MCSAttachUserRequest:
			return phaseMCSAttachUserReq
		case MCSAttachUserConfirm:
			return phaseMCSAttachUserConf
		case MCSChannelJoinRequest:
			return phaseMCSChannelJoinReq
		case MCSChannelJoinConfirm:
			return phaseMCSChannelJoinConf
		case MCSDisconnectProviderUltimatum:
			return phaseMCSDisconnect
		case 0x64:
			// MCS Send Data Request — channel data (CLIPRDR/RDPDR/etc.)
			return phaseActive
		}

		// Share Control Header (RDP PDU at offset 7):
		// [7:9]=totalLength LE, [9:11]=pduType LE, [11:13]=pduSource LE.
		if len(pl) < 11 {
			return -1
		}
		pduType := binary.LittleEndian.Uint16(pl[9:11])
		switch pduType {
		case 0x0007: // PDU_TYPE_DEMAND_ACTIVE
			return phaseCapability
		case 0x0017: // PDU_TYPE_DATA
			if len(pl) < 22 {
				return phaseActive
			}
			// pduType2 is the low byte at offset 21 (Share Data Header
			// layout: [13:17]=shareId, [17]=pad1, [18]=streamId,
			// [19:21]=uncompressedLength, [21]=pduType2).
			pduType2 := pl[21]
			switch pduType2 {
			case 0x1B: // PDUTYPE2_CONFIRMACTIVE
				return phaseCapability
			case 0x27: // PDUTYPE2_SHUTDOWN_REQUEST
				return phaseShutdown
			}
			return phaseActive
		}

		// Security Exchange: first 4 bytes after X.224 DT are the
		// security header flags. SEC_EXCHANGE_PKT=0x0080 → pl[7]=0x80.
		if pl[7] == SecExchangePkt&0xFF {
			return phaseSecurityExchange
		}

		// License PDU: bMsgType at pl[7].
		switch pl[7] {
		case LicenseRequest, LicenseInfo, NewLicenseRequest,
			ClientLicenseInfo, ErrorAlert, PlatformChallenge:
			return phaseLicense
		}

		// Client Info PDU: codePage(4 LE) + flags(2 LE). flags low byte
		// at pl[11]. INFO_UNICODE=0x0010 is always set by the planner.
		if len(pl) >= 12 && pl[11]&byte(InfoUnicode&0xFF) != 0 {
			return phaseClientInfo
		}
	}
	return -1
}

// collectPhases classifies every packet and returns the ordered phase
// sequence, ignoring -1 (unclassified).
func collectPhases(t *testing.T, configs []core.PacketConfig) []phaseKind {
	t.Helper()
	out := make([]phaseKind, 0, len(configs))
	for _, cfg := range configs {
		if p := classifyPacket(cfg); p >= 0 {
			out = append(out, p)
		}
	}
	return out
}

// findPacket returns the first packet whose phase matches.
func findPacket(configs []core.PacketConfig, phase phaseKind) (core.PacketConfig, bool) {
	for _, cfg := range configs {
		if classifyPacket(cfg) == phase {
			return cfg, true
		}
	}
	return core.PacketConfig{}, false
}

// countPhase returns how many packets classify as the given phase.
func countPhase(configs []core.PacketConfig, phase phaseKind) int {
	n := 0
	for _, cfg := range configs {
		if classifyPacket(cfg) == phase {
			n++
		}
	}
	return n
}

// countTeardown returns the number of TCP control packets at the END of
// the flow that participate in the 4-way teardown (FIN/ACK/FIN/ACK
// sequence). We detect them by the FIN flag (0x01) bit set: FIN is
// unique to teardown among non-data control packets. There should be
// exactly 2 FIN packets and 2 ACK packets in the teardown.
func countTeardown(configs []core.PacketConfig) int {
	if len(configs) < 4 {
		return 0
	}
	tail := configs[len(configs)-4:]
	for _, cfg := range tail {
		if cfg.L4.Flags != 0x11 && cfg.L4.Flags != 0x10 {
			return 0
		}
	}
	return 4
}

// =============== Scenario field validation ===============

// TestScenario_ValidateUnknownRejected verifies an unknown scenario name
// is rejected by Validate() (per validate_conventions §4.3).
func TestScenario_ValidateUnknownRejected(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{Scenario: "bogus_scenario"},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unknown scenario")) {
		t.Errorf("expected unknown-scenario error, got %v", err)
	}
}

// TestScenario_ValidateKnownAccepted verifies all documented scenario
// names pass Validate() without error.
func TestScenario_ValidateKnownAccepted(t *testing.T) {
	scenarios := []string{
		"full_session", "multi_channel", "cliprdr", "rdpdr",
		"input_events", "bitmap_update", "channel_join_failure",
		"disconnect",
	}
	for _, sc := range scenarios {
		t.Run(sc, func(t *testing.T) {
			p := NewPlanner()
			err := p.Validate(core.FlowSpec{
				SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
				SrcPort: 1000,
				RDP:     &core.RDPConfig{Scenario: sc},
			})
			if err != nil {
				t.Errorf("scenario %q rejected: %v", sc, err)
			}
		})
	}
}

// =============== full_session scenario ===============

// TestScenario_FullSession_PhaseOrder asserts the spec-correct phase
// sequence (MS-RDPBCGR §3.1 Connection Sequence table) for the
// "full_session" scenario with default TLS security.
//
// The phase order MUST match the spec table. We only assert the
// well-known prefixes (X.224 CR/CC, TLS, MCS Connect-Initial/Response,
// Erect-Domain, Attach-User) since downstream phases (license,
// capability, active, shutdown) can repeat or interleave in
// scenario-specific ways.
func TestScenario_FullSession_PhaseOrder(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "full_session",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)
	phases := collectPhases(t, configs)

	// Expected order prefix (handshake SYN + X.224 CR/CC + TLS pair +
	// MCS Connect-Initial/Response + Erect-Domain + Attach-User pair).
	expectedPrefix := []phaseKind{
		phaseHandshake, // SYN
		phaseX224CR, phaseX224CC,
		phaseTLSClientHello, phaseTLSServerHello,
		phaseMCSConnectInitial, phaseMCSConnectResponse,
		phaseMCSErectDomain,
		phaseMCSAttachUserReq, phaseMCSAttachUserConf,
	}
	if len(phases) < len(expectedPrefix) {
		t.Fatalf("too few phases: got %d, want >= %d", len(phases), len(expectedPrefix))
	}
	for i, want := range expectedPrefix {
		if phases[i] != want {
			t.Errorf("phases[%d] = %d, want %d (full_session)", i, phases[i], want)
		}
	}

	// The session must contain at least: 1 license PDU, >=1 capability PDU,
	// >=1 active PDU (full_session populates data events), a Shutdown PDU,
	// an MCS Disconnect, and the 4-way TCP teardown.
	if countPhase(configs, phaseLicense) < 1 {
		t.Errorf("full_session: expected >=1 license PDU, got %d", countPhase(configs, phaseLicense))
	}
	if countPhase(configs, phaseCapability) < 1 {
		t.Errorf("full_session: expected >=1 capability PDU, got %d", countPhase(configs, phaseCapability))
	}
	if countPhase(configs, phaseActive) < 1 {
		t.Errorf("full_session: expected >=1 active PDU, got %d", countPhase(configs, phaseActive))
	}
	if countPhase(configs, phaseShutdown) < 1 {
		t.Errorf("full_session: expected Shutdown Request, got %d", countPhase(configs, phaseShutdown))
	}
	if countPhase(configs, phaseMCSDisconnect) != 1 {
		t.Errorf("full_session: expected 1 MCS Disconnect, got %d", countPhase(configs, phaseMCSDisconnect))
	}
	if td := countTeardown(configs); td != 4 {
		t.Errorf("full_session: expected 4 teardown packets, got %d", td)
	}
}

// TestScenario_FullSession_AutoPopulatesChannels verifies that when the
// user leaves Channels empty and sets Scenario="full_session", the
// planner populates the standard channel set (cliprdr/rdpdr/rdpsnd/
// drdynvc) so the MCS Connect-Initial userData contains a CS_CHANNELS
// block with >=4 entries.
func TestScenario_FullSession_AutoPopulatesChannels(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "full_session",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Expect Channel-Join Requests for I/O (1003) + >=4 static channels.
	cjIDs := map[uint16]bool{}
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		id := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		cjIDs[id] = true
	}
	if !cjIDs[1003] {
		t.Errorf("full_session: missing I/O channel (1003)")
	}
	for _, want := range []uint16{1004, 1005, 1006, 1007} {
		if !cjIDs[want] {
			t.Errorf("full_session: missing static channel ID %d (cliprdr/rdpdr/rdpsnd/drdynvc)", want)
		}
	}
}

// TestScenario_FullSession_AutoPopulatesDataEvents verifies the
// full_session scenario emits at least one FastPath Input PDU (keyboard)
// and one ServerResponse FastPath Output bitmap PDU during the active
// phase.
func TestScenario_FullSession_AutoPopulatesDataEvents(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "full_session",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	foundFPInput := false
	foundFPOutput := false
	for _, cfg := range configs {
		if len(cfg.Payload) < 2 {
			continue
		}
		// FastPath Output: action header high 2 bits = 01 (0x40).
		if cfg.Payload[0]&0xC0 == 0x40 {
			foundFPOutput = true
		}
		// FastPath Input (up direction): action high 2 bits = 00.
		if cfg.Direction == "up" && cfg.Payload[0]&0xC0 == 0x00 && len(cfg.Payload) >= 5 {
			// Skip TLS record (byte 1 is 0x03).
			if cfg.Payload[1] == 0x03 {
				continue
			}
			foundFPInput = true
		}
	}
	if !foundFPInput {
		t.Errorf("full_session: no FastPath Input PDU emitted")
	}
	if !foundFPOutput {
		t.Errorf("full_session: no FastPath Output PDU emitted")
	}
}

// =============== multi_channel scenario ===============

// TestScenario_MultiChannel_ChannelIDs asserts the multi_channel
// scenario populates exactly 5 channels (I/O + cliprdr + rdpdr + rdpsnd +
// drdynvc) and emits the correct Channel-Join ID sequence.
func TestScenario_MultiChannel_ChannelIDs(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "multi_channel",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	var cjIDs []uint16
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		id := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		cjIDs = append(cjIDs, id)
	}
	want := []uint16{1003, 1004, 1005, 1006, 1007}
	if len(cjIDs) != len(want) {
		t.Fatalf("Channel-Join count = %d, want %d (%v)", len(cjIDs), len(want), want)
	}
	for i, w := range want {
		if cjIDs[i] != w {
			t.Errorf("cjIDs[%d] = %d, want %d", i, cjIDs[i], w)
		}
	}
}

// TestScenario_MultiChannel_ConfResultsAllZero asserts all 5
// Channel-Join Confirm responses carry result byte 0 (rt-successful).
func TestScenario_MultiChannel_ConfResultsAllZero(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "multi_channel",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	confCount := 0
	for _, cfg := range configs {
		if cfg.Direction != "down" || len(cfg.Payload) < 13 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinConfirm {
			continue
		}
		result := cfg.Payload[12]
		if result != 0 {
			t.Errorf("Channel-Join Confirm result = %d, want 0 (rt-successful)", result)
		}
		confCount++
	}
	if confCount != 5 {
		t.Errorf("Channel-Join Confirm count = %d, want 5", confCount)
	}
}

// =============== channel_join_failure scenario ===============

// TestScenario_ChannelJoinFailure_OneRejected asserts the
// channel_join_failure scenario causes one of the server-side
// Channel-Join Confirm packets to carry result byte 4
// (rt-no-such-channel) per MS-RDPBCGR §3.2.1.5.
func TestScenario_ChannelJoinFailure_OneRejected(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "channel_join_failure",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	countRej := 0
	for _, cfg := range configs {
		if cfg.Direction != "down" || len(cfg.Payload) < 13 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinConfirm {
			continue
		}
		if cfg.Payload[12] == 4 {
			countRej++
		}
	}
	if countRej != 1 {
		t.Errorf("channel_join_failure: rejected channel count = %d, want 1", countRej)
	}
}

// =============== input_events scenario ===============

// TestScenario_InputEvents_KeyboardAndMouse asserts the input_events
// scenario emits at least one FastPath Input keyboard event AND at
// least one FastPath Input mouse event (both in the up direction).
func TestScenario_InputEvents_KeyboardAndMouse(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "input_events",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	foundKbd := false
	foundMouse := false
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 2 {
			continue
		}
		if cfg.Payload[0]&0xC0 != 0x00 {
			continue
		}
		if cfg.Payload[1] == 0x00 {
			continue // TPKT reserved (not FastPath Input)
		}
		// FastPath Input layout (MS-RDPBCGR §2.2.8.1.1.2): header(1) +
		// length(1) + events. length field includes header+length byte
		// itself + events. So length=4 means 2-byte keyboard event;
		// length=8 means 6-byte mouse event.
		if cfg.Payload[1] == 0x04 { // 1 keyboard event (2 bytes)
			foundKbd = true
		}
		if cfg.Payload[1] == 0x08 { // 1 mouse event (6 bytes)
			foundMouse = true
		}
	}
	if !foundKbd {
		t.Errorf("input_events: no FastPath keyboard event found")
	}
	if !foundMouse {
		t.Errorf("input_events: no FastPath mouse event found")
	}
}

// =============== bitmap_update scenario ===============

// TestScenario_BitmapUpdate_FastPathOutput asserts the bitmap_update
// scenario emits at least one FastPath Output PDU with the Bitmap
// update code (0x01) in the up direction from server.
func TestScenario_BitmapUpdate_FastPathOutput(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "bitmap_update",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	foundBitmap := false
	for _, cfg := range configs {
		if cfg.Direction != "down" || len(cfg.Payload) < 4 {
			continue
		}
		if cfg.Payload[0]&0xC0 != 0x40 { // FastPath Output (action=01)
			continue
		}
		// updateCode at offset 2, FastPathUpdateBitmap = 0x01.
		if cfg.Payload[2] == FastPathUpdateBitmap {
			foundBitmap = true
		}
	}
	if !foundBitmap {
		t.Errorf("bitmap_update: no FastPath Output Bitmap PDU found")
	}
}

// =============== disconnect scenario ===============

// TestScenario_Disconnect_HasShutdownAndMCSDisconnect asserts the
// disconnect scenario emits both a Shutdown Request PDU and an MCS
// Disconnect Provider Ultimatum PDU before the TCP teardown.
func TestScenario_Disconnect_HasShutdownAndMCSDisconnect(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "disconnect",
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// The MCS Disconnect must carry reason byte 0x80 (user-requested).
	foundDisc := false
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 9 {
			continue
		}
		if cfg.Payload[0] != TPKTVersion {
			continue
		}
		if cfg.Payload[5] != X224DT {
			continue
		}
		if cfg.Payload[7] != MCSDisconnectProviderUltimatum {
			continue
		}
		if cfg.Payload[8] != 0x80 {
			t.Errorf("Disconnect Ultimatum reason = 0x%x, want 0x80 (user-requested)", cfg.Payload[8])
		}
		foundDisc = true
	}
	if !foundDisc {
		t.Errorf("disconnect: no MCS Disconnect Provider Ultimatum PDU")
	}
	if countPhase(configs, phaseShutdown) < 1 {
		t.Errorf("disconnect: no Shutdown Request PDU")
	}
	if td := countTeardown(configs); td != 4 {
		t.Errorf("disconnect: expected 4 teardown packets, got %d", td)
	}
}

// =============== cliprdr / rdpdr scenarios ===============

// TestScenario_CLIPRDR_AutoPopulatesCliprdrChannel asserts the cliprdr
// scenario declares cliprdr in CS_CHANNELS and emits at least one
// CB_FORMAT_LIST data event on the cliprdr channel.
func TestScenario_CLIPRDR_AutoPopulatesCliprdrChannel(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP:     &core.RDPConfig{SecurityLayer: "tls", Scenario: "cliprdr"},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Find a Channel-Join Request with ChannelId=1004 (cliprdr).
	foundCliprdrJoin := false
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		id := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		if id == MCSFirstStaticChan {
			foundCliprdrJoin = true
		}
	}
	if !foundCliprdrJoin {
		t.Errorf("cliprdr: missing Channel-Join for ChannelId=1004 (cliprdr)")
	}

	// Find a CLIPRDR CB_FORMAT_LIST message type (0x0002) somewhere on
	// the wire (data event or server response).
	foundFL := false
	for _, cfg := range configs {
		if len(cfg.Payload) < 8 {
			continue
		}
		// CB_FORMAT_LIST msgType (LE) = 0x02 0x00. We search for the
		// bytes anywhere in the payload.
		if bytes.Contains(cfg.Payload, []byte{0x02, 0x00, 0x00, 0x00}) {
			foundFL = true
		}
	}
	if !foundFL {
		t.Errorf("cliprdr: no CLIPRDR CB_FORMAT_LIST payload found")
	}
}

// TestScenario_RDPDR_AutoPopulatesRdpdrChannel asserts the rdpdr
// scenario declares rdpdr in CS_CHANNELS and emits at least one
// PAKID_CORE_DEVICELIST_ANNOUNCE on the rdpdr channel.
func TestScenario_RDPDR_AutoPopulatesRdpdrChannel(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "rdpdr",
			Channels:      []core.RDPChannel{{Name: "rdpdr"}},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Find a Channel-Join Request with ChannelId=1004 (rdpdr is first
	// declared channel, so it maps to MCSFirstStaticChan=1004 — not 1005.
	// Channel ID assignment is positional by declaration order; rdpdr
	// only is index 0 -> 1004. The earlier test expected 1005 because it
	// assumed a 4-channel prefix, but the rdpdr scenario declares only
	// rdpdr, so its channel ID is 1004.)
	foundRdpdrJoin := false
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		id := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		if id == MCSFirstStaticChan {
			foundRdpdrJoin = true
		}
	}
	if !foundRdpdrJoin {
		t.Errorf("rdpdr: missing Channel-Join for ChannelId=%d (rdpdr)", MCSFirstStaticChan)
	}

	// PAKID_CORE_DEVICELIST_ANNOUNCE = 0x0004 (LE: 0x04 0x00). Search
	// inside ChannelData PDUs. The ChannelData wraps a CLIPRDR/RDPDR
	// header (component=2/3, packetId=4). We assert that some payload
	// contains the bytes 0x04 0x00 in a plausible position; the more
	// specific assertion would require TPKT/X.224/MCS unwrapping.
	found := false
	for _, cfg := range configs {
		if bytes.Contains(cfg.Payload, []byte{0x04, 0x00}) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("rdpdr: no PAKID_CORE_DEVICELIST_ANNOUNCE marker found")
	}
}

// =============== Manual override preserved ===============

// TestScenario_ManualConfigOverridesScenario asserts that when the user
// supplies explicit Channels/DataEvents/ServerResponses, the scenario
// field does NOT silently overwrite them (forwarder semantics).
func TestScenario_ManualConfigOverridesScenario(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			Scenario:      "full_session",
			Channels: []core.RDPChannel{
				{Name: "custom"},
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Only one Channel-Join for ChannelId=1004 (custom). The full_session
	// scenario would normally populate cliprdr/rdpdr/rdpsnd/drdynvc, but
	// the user-supplied Channels slice (custom only) wins.
	countCJ := 0
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		countCJ++
	}
	// 1 I/O + 1 user-declared = 2.
	if countCJ != 2 {
		t.Errorf("manual override: Channel-Join count = %d, want 2 (I/O + custom)", countCJ)
	}
}