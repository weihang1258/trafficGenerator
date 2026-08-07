package pppoe

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// planAll runs the planner to completion and returns every emitted config.
func planAll(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// TestPlanner_FullSession_WireSequence verifies the complete Discovery
// state machine (RFC 2516 §5.1-5.4) followed by the LCP session phase and
// the IPv4 data plane:
//
//	PADI (client, broadcast) -> PADO (server, AC-Name + AC-Cookie) ->
//	PADR (client, echoes AC-Cookie) -> PADS (server, assigns Session ID) ->
//	LCP Configure-Request/Ack -> N IPv4 data frames
//
// and the Session-ID binding: Discovery frames carry 0x0000, every Session
// Data frame carries the PADS-assigned ID.
func TestPlanner_FullSession_WireSequence(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 1000,
		DstPort: 2000,
		SrcMAC:  "00:01:00:02:00:03",
		DstMAC:  "00:03:a0:12:30:cc",
		Payload: []byte("data"),
		TCP:     &core.TCPConfig{},
		PPPoE: &core.PPPoEConfig{
			SessionID:  0x000f,
			Cookie:     []byte{0xde, 0xad, 0xbe, 0xef},
			DataFrames: 2,
		},
	}

	cfgs := planAll(t, spec)
	// PADI, PADO, PADR, PADS, LCP req, LCP ack, 2 data frames.
	if len(cfgs) != 8 {
		t.Fatalf("emitted %d packets, want 8 (4 discovery + 2 LCP + 2 data)", len(cfgs))
	}

	// ----- Discovery: PADI -----
	padi := cfgs[0]
	if padi.Direction != "up" {
		t.Errorf("PADI direction = %q, want up", padi.Direction)
	}
	if padi.L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("PADI dst MAC = %q, want broadcast ff:ff:ff:ff:ff:ff (RFC 2516 §5.2)", padi.L2.DstMAC)
	}
	if padi.L2.EtherType != core.EtherTypePPPoEDiscovery {
		t.Errorf("PADI EtherType = 0x%04x, want 0x8863", padi.L2.EtherType)
	}
	if padi.L2.PPPoE.Code != core.PPPoECodePADI {
		t.Errorf("PADI code = 0x%02x, want 0x09", padi.L2.PPPoE.Code)
	}
	if padi.L2.PPPoE.SessionID != 0 {
		t.Errorf("PADI SessionID = %d, want 0 (discovery, RFC 2516 §5.2)", padi.L2.PPPoE.SessionID)
	}
	if padi.L3.SrcIP != "" || padi.L4.Protocol != "" {
		t.Errorf("PADI must carry no L3/L4, got L3=%+v L4=%+v", padi.L3, padi.L4)
	}
	tags := padi.L2.PPPoE.DiscoveryTags
	if len(tags) != 1 || tags[0].Type != core.PPPoETagServiceName {
		t.Errorf("PADI tags = %+v, want single zero-length Service-Name tag", tags)
	}

	// ----- Discovery: PADO -----
	pado := cfgs[1]
	if pado.Direction != "down" || pado.L2.PPPoE.Code != core.PPPoECodePADO {
		t.Errorf("PADO = dir %q code 0x%02x, want down/0x07", pado.Direction, pado.L2.PPPoE.Code)
	}
	if pado.L2.PPPoE.SessionID != 0 {
		t.Errorf("PADO SessionID = %d, want 0", pado.L2.PPPoE.SessionID)
	}
	gotTypes := map[uint16][]byte{}
	for _, tag := range pado.L2.PPPoE.DiscoveryTags {
		gotTypes[tag.Type] = tag.Value
	}
	if !bytes.Equal(gotTypes[core.PPPoETagACName], []byte("trafficgen")) {
		t.Errorf("PADO AC-Name = %q, want default trafficgen", gotTypes[core.PPPoETagACName])
	}
	if !bytes.Equal(gotTypes[core.PPPoETagACCookie], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("PADO AC-Cookie = % x, want de ad be ef", gotTypes[core.PPPoETagACCookie])
	}

	// ----- Discovery: PADR echoes the AC-Cookie (RFC 2516 §5.4) -----
	padr := cfgs[2]
	if padr.Direction != "up" || padr.L2.PPPoE.Code != core.PPPoECodePADR || padr.L2.PPPoE.SessionID != 0 {
		t.Errorf("PADR = dir %q code 0x%02x session %d, want up/0x19/0", padr.Direction, padr.L2.PPPoE.Code, padr.L2.PPPoE.SessionID)
	}
	var padrCookie []byte
	for _, tag := range padr.L2.PPPoE.DiscoveryTags {
		if tag.Type == core.PPPoETagACCookie {
			padrCookie = tag.Value
		}
	}
	if !bytes.Equal(padrCookie, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("PADR AC-Cookie = % x, want de ad be ef (echo from PADO)", padrCookie)
	}

	// ----- Discovery: PADS assigns the Session ID (RFC 2516 §5.4) -----
	pads := cfgs[3]
	if pads.Direction != "down" || pads.L2.PPPoE.Code != core.PPPoECodePADS {
		t.Errorf("PADS = dir %q code 0x%02x, want down/0x65", pads.Direction, pads.L2.PPPoE.Code)
	}
	if pads.L2.PPPoE.SessionID != 0x000f {
		t.Errorf("PADS SessionID = %d, want 0x000f (assigned)", pads.L2.PPPoE.SessionID)
	}

	// ----- Session: LCP Configure-Request (up) + Configure-Ack (down) -----
	lcpReq := cfgs[4]
	if lcpReq.Direction != "up" || lcpReq.L2.PPPoE.Code != core.PPPoECodeSessionData ||
		lcpReq.L2.PPPoE.SessionID != 0x000f || lcpReq.L2.PPPoE.PPPProtocol != core.PPPProtocolLCP {
		t.Errorf("LCP req = dir %q code 0x%02x session %d proto 0x%04x, want up/0x00/0x000f/0xc021",
			lcpReq.Direction, lcpReq.L2.PPPoE.Code, lcpReq.L2.PPPoE.SessionID, lcpReq.L2.PPPoE.PPPProtocol)
	}
	if lcpReq.L3.SrcIP != "" || lcpReq.L4.Protocol != "" {
		t.Errorf("LCP frame must carry no L3/L4")
	}
	if lcpReq.Payload[0] != lcpConfigureRequest {
		t.Errorf("LCP req code = 0x%02x, want 1 (Configure-Request)", lcpReq.Payload[0])
	}
	lcpAck := cfgs[5]
	if lcpAck.Direction != "down" || lcpAck.Payload[0] != lcpConfigureAck {
		t.Errorf("LCP ack = dir %q code 0x%02x, want down/2 (Configure-Ack)", lcpAck.Direction, lcpAck.Payload[0])
	}
	if !bytes.Equal(lcpAck.Payload[4:], lcpReq.Payload[4:]) {
		t.Errorf("LCP Configure-Ack must echo the Configure-Request options exactly (RFC 1661 §6.1)")
	}

	// ----- IPv4 data plane (RFC 1661 §6) -----
	for i := 0; i < 2; i++ {
		data := cfgs[6+i]
		if data.Direction != "up" {
			t.Errorf("data[%d] direction = %q, want up", i, data.Direction)
		}
		if data.L2.PPPoE.SessionID != 0x000f || data.L2.PPPoE.PPPProtocol != core.PPPProtocolIPv4 {
			t.Errorf("data[%d] session %d proto 0x%04x, want 0x000f/0x0021", i, data.L2.PPPoE.SessionID, data.L2.PPPoE.PPPProtocol)
		}
		if data.L3.SrcIP != "10.0.0.1" || data.L3.DstIP != "10.0.0.2" {
			t.Errorf("data[%d] inner IPs = %s->%s, want 10.0.0.1->10.0.0.2", i, data.L3.SrcIP, data.L3.DstIP)
		}
		if data.L4.Protocol != "tcp" || data.L4.SrcPort != 1000 || data.L4.DstPort != 2000 {
			t.Errorf("data[%d] L4 = %+v, want tcp 1000->2000 (spec.TCP selects TCP)", i, data.L4)
		}
		if !bytes.Equal(data.Payload, []byte("data")) {
			t.Errorf("data[%d] payload = %q, want spec.Payload", i, data.Payload)
		}
	}
}

// TestPlanner_LCPFrameBytes_Pcap reproduces pcap 4.pppoe_sample.pcap frame
// 1 byte-for-byte THROUGH THE FULL CHAIN (planner -> builder): SkipDiscovery
// starts at the LCP session phase, and the builder emits the PPPoE header.
// The test feeds MRU/MagicNumber/SessionID/MACs from the capture and
// asserts the final 60-byte Ethernet frame matches the pcap exactly.
func TestPlanner_LCPFrameBytes_Pcap(t *testing.T) {
	spec := core.FlowSpec{
		SrcMAC: "00:01:00:02:00:03",
		DstMAC: "00:03:a0:12:30:cc",
		PPPoE: &core.PPPoEConfig{
			SkipDiscovery: true,
			SessionID:     0x000f,
			MRU:           0x05d4,     // 1492
			MagicNumber:   0x09e5f145, // RFC 1661 §6.13
		},
	}

	cfgs := planAll(t, spec)
	// SkipDiscovery: LCP req, LCP ack, 1 data frame.
	if len(cfgs) != 3 {
		t.Fatalf("emitted %d packets, want 3", len(cfgs))
	}

	builder := core.NewBuilder()
	packet, err := builder.Build(cfgs[0])
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []byte{
		0x00, 0x03, 0xa0, 0x12, 0x30, 0xcc,
		0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
		0x88, 0x64,
		0x11, 0x00,
		0x00, 0x0f,
		0x00, 0x10, // 16 = 2 (PPP proto) + 14 (LCP)
		0xc0, 0x21,
		0x01, 0x01, 0x00, 0x0e,
		0x01, 0x04, 0x05, 0xd4,
		0x05, 0x06, 0x09, 0xe5, 0xf1, 0x45,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("planner->builder frame mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestPlanner_PAP verifies the PAP authentication phase (RFC 1334): the LCP
// Configure-Request carries the Auth-Protocol option (0xc023), followed by
// Authenticate-Request (client) and Authenticate-Ack (server).
func TestPlanner_PAP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "00:01:00:02:00:03", DstMAC: "00:03:a0:12:30:cc",
		PPPoE: &core.PPPoEConfig{
			SkipDiscovery: true,
			SessionID:     1,
			Auth:          "pap",
			Username:      "alice",
			Password:      "s3cret",
			DataFrames:    0,
		},
	}

	cfgs := planAll(t, spec)
	// LCP req, LCP ack, PAP req, PAP ack, 1 default data frame.
	if len(cfgs) != 5 {
		t.Fatalf("emitted %d packets, want 5", len(cfgs))
	}

	// LCP Configure-Request options include Auth-Protocol = PAP (0xc023):
	// option type 3, len 4, value c0 23 (RFC 1334 §2.2).
	lcpReq := cfgs[0].Payload
	if !bytes.Contains(lcpReq, []byte{0x03, 0x04, 0xc0, 0x23}) {
		t.Errorf("LCP options = % x, want Auth-Protocol PAP (03 04 c0 23)", lcpReq)
	}

	// Authenticate-Request (RFC 1334 §2.1): code 1, id 1, length,
	// peer-id-length, peer-id, password-length, password.
	papReq := cfgs[2]
	if papReq.Direction != "up" || papReq.L2.PPPoE.PPPProtocol != core.PPPProtocolPAP {
		t.Errorf("PAP req = dir %q proto 0x%04x, want up/0xc023", papReq.Direction, papReq.L2.PPPoE.PPPProtocol)
	}
	wantReq := []byte{
		0x01, 0x01, 0x00, 0x11, // code 1 (Authenticate-Request), id 1, len 17
		0x05, 'a', 'l', 'i', 'c', 'e', // peer-id "alice"
		0x06, 's', '3', 'c', 'r', 'e', 't', // password "s3cret"
	}
	if !bytes.Equal(papReq.Payload, wantReq) {
		t.Errorf("PAP Authenticate-Request = % x, want % x", papReq.Payload, wantReq)
	}

	// Authenticate-Ack (RFC 1334 §2.1): code 2, id 1, message "welcome".
	papAck := cfgs[3]
	if papAck.Direction != "down" || papAck.Payload[0] != papAuthAck {
		t.Errorf("PAP ack = dir %q code 0x%02x, want down/2", papAck.Direction, papAck.Payload[0])
	}
	if !bytes.Equal(papAck.Payload[4:], []byte{0x07, 'w', 'e', 'l', 'c', 'o', 'm', 'e'}) {
		t.Errorf("PAP Ack message = % x, want 07 welcome", papAck.Payload[4:])
	}
}

// TestPlanner_CHAP verifies the CHAP authentication phase (RFC 1994): the
// LCP Configure-Request carries the Auth-Protocol option (0xc223), then
// Challenge (server) -> Response (client, echoes the challenge value) ->
// Success (server).
func TestPlanner_CHAP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "00:01:00:02:00:03", DstMAC: "00:03:a0:12:30:cc",
		PPPoE: &core.PPPoEConfig{
			SkipDiscovery: true,
			Auth:          "chap",
			Username:      "bob",
			DataFrames:    0,
		},
	}

	cfgs := planAll(t, spec)
	// LCP req, LCP ack, CHAP challenge, CHAP response, CHAP success, 1 data.
	if len(cfgs) != 6 {
		t.Fatalf("emitted %d packets, want 6", len(cfgs))
	}

	lcpReq := cfgs[0].Payload
	if !bytes.Contains(lcpReq, []byte{0x03, 0x04, 0xc2, 0x23}) {
		t.Errorf("LCP options = % x, want Auth-Protocol CHAP (03 04 c2 23)", lcpReq)
	}

	// Challenge (RFC 1994 §3): code 1, id 1, value-size 16, value, name.
	chal := cfgs[2]
	if chal.Direction != "down" || chal.L2.PPPoE.PPPProtocol != core.PPPProtocolCHAP {
		t.Errorf("CHAP challenge = dir %q proto 0x%04x, want down/0xc223", chal.Direction, chal.L2.PPPoE.PPPProtocol)
	}
	if chal.Payload[0] != chapChallenge || chal.Payload[4] != chapValueLen {
		t.Errorf("CHAP challenge header = % x, want code 1, value-size 16", chal.Payload[:5])
	}
	chalValue := chal.Payload[5 : 5+chapValueLen]

	// Response (RFC 1994 §3): code 2, echoes the challenge value, name.
	resp := cfgs[3]
	if resp.Direction != "up" || resp.Payload[0] != chapResponse {
		t.Errorf("CHAP response = dir %q code 0x%02x, want up/2", resp.Direction, resp.Payload[0])
	}
	if !bytes.Equal(resp.Payload[5:5+chapValueLen], chalValue) {
		t.Errorf("CHAP response value = % x, want echo of challenge % x", resp.Payload[5:5+chapValueLen], chalValue)
	}

	// Success (RFC 1994 §3): code 3, length 4, no message.
	succ := cfgs[4]
	if succ.Direction != "down" || succ.Payload[0] != chapSuccess {
		t.Errorf("CHAP success = dir %q code 0x%02x, want down/3", succ.Direction, succ.Payload[0])
	}
	if len(succ.Payload) != 4 {
		t.Errorf("CHAP success length = %d, want 4", len(succ.Payload))
	}
}

// TestPlanner_DefaultSessionID verifies SessionID=0 is assigned the
// deterministic default (1) by PADS and echoed by the session phase
// (RFC 2516 §5.4: the Session ID is bound to the PPP connection).
func TestPlanner_DefaultSessionID(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "00:01:00:02:00:03", DstMAC: "00:03:a0:12:30:cc",
		PPPoE: &core.PPPoEConfig{},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 7 {
		t.Fatalf("emitted %d packets, want 7", len(cfgs))
	}
	// PADS assigns 1.
	if cfgs[3].L2.PPPoE.SessionID != DefaultSessionID {
		t.Errorf("PADS SessionID = %d, want default %d", cfgs[3].L2.PPPoE.SessionID, DefaultSessionID)
	}
	// LCP + data echo it.
	for i := 4; i < len(cfgs); i++ {
		if cfgs[i].L2.PPPoE.SessionID != DefaultSessionID {
			t.Errorf("packet[%d] SessionID = %d, want default %d", i, cfgs[i].L2.PPPoE.SessionID, DefaultSessionID)
		}
	}
	// PADI/PADO/PADR carry 0; PADS carries the assigned ID (RFC 2516 §5.4).
	for i := 0; i < 3; i++ {
		if cfgs[i].L2.PPPoE.SessionID != 0 {
			t.Errorf("discovery packet[%d] SessionID = %d, want 0", i, cfgs[i].L2.PPPoE.SessionID)
		}
	}
}

// TestPlanner_DataPlane_Down verifies the down-direction IPv4 data plane:
// MACs and inner IPs are swapped, the inner protocol is TCP with the
// spec.TCP L4 fields, the payload comes from DataPayload, and each of the
// DataFrames packets gets a distinct inner IPID.
func TestPlanner_DataPlane_Down(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5000, DstPort: 8080,
		SrcMAC: "00:01:00:02:00:03", DstMAC: "00:03:a0:12:30:cc",
		TCP: &core.TCPConfig{Seq: 100, Ack: 200, Flags: 0x18, WindowSize: 4096},
		PPPoE: &core.PPPoEConfig{
			SkipDiscovery: true,
			SessionID:     1,
			InnerProto:    6, // TCP
			DataFrames:    3,
			DataPayload:   []byte("payload-bytes"),
			DataDirection: "down",
		},
	}

	cfgs := planAll(t, spec)
	// LCP req, LCP ack, 3 data frames.
	if len(cfgs) != 5 {
		t.Fatalf("emitted %d packets, want 5", len(cfgs))
	}

	seenIPIDs := map[uint16]bool{}
	for i := 0; i < 3; i++ {
		data := cfgs[2+i]
		if data.Direction != "down" {
			t.Errorf("data[%d] direction = %q, want down", i, data.Direction)
		}
		if data.L2.SrcMAC != "00:03:a0:12:30:cc" || data.L2.DstMAC != "00:01:00:02:00:03" {
			t.Errorf("data[%d] MACs = %s->%s, want swapped", i, data.L2.SrcMAC, data.L2.DstMAC)
		}
		if data.L3.SrcIP != "10.0.0.2" || data.L3.DstIP != "10.0.0.1" {
			t.Errorf("data[%d] inner IPs = %s->%s, want swapped (down)", i, data.L3.SrcIP, data.L3.DstIP)
		}
		if data.L3.Protocol != 6 {
			t.Errorf("data[%d] inner proto = %d, want 6 (TCP)", i, data.L3.Protocol)
		}
		if data.L4.Seq != 100 || data.L4.Ack != 200 || data.L4.Flags != 0x18 || data.L4.WindowSize != 4096 {
			t.Errorf("data[%d] L4 = %+v, want spec.TCP fields", i, data.L4)
		}
		if !bytes.Equal(data.Payload, []byte("payload-bytes")) {
			t.Errorf("data[%d] payload = %q, want DataPayload", i, data.Payload)
		}
		seenIPIDs[data.L3.IPID] = true
	}
	if len(seenIPIDs) != 3 {
		t.Errorf("inner IPIDs = %v, want 3 distinct values", seenIPIDs)
	}
}

// TestPlanner_Validate covers the Validate spec table: missing config, bad
// IPs (including IPv6 — PPPoE carries IPv4 only, RFC 1661 §6), bad auth,
// bad inner proto, negative DataFrames, bad DataDirection.
func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
		errSub  string
	}{
		{
			name:    "valid default",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{}},
			wantErr: false,
		},
		{
			name:    "missing PPPoE config",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
			wantErr: true,
			errSub:  "PPPoE config is required",
		},
		{
			name:    "invalid SrcIP",
			spec:    core.FlowSpec{SrcIP: "not-an-ip", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{}},
			wantErr: true,
			errSub:  "SrcIP",
		},
		{
			name:    "IPv6 inner IP rejected",
			spec:    core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{}},
			wantErr: true,
			errSub:  "must be IPv4",
		},
		{
			name:    "bad auth",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{Auth: "radius"}},
			wantErr: true,
			errSub:  "Auth",
		},
		{
			name:    "bad inner proto",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{InnerProto: 5}},
			wantErr: true,
			errSub:  "InnerProto",
		},
		{
			name:    "negative DataFrames",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{DataFrames: -1}},
			wantErr: true,
			errSub:  "DataFrames",
		},
		{
			name:    "bad DataDirection",
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PPPoE: &core.PPPoEConfig{DataDirection: "sideways"}},
			wantErr: true,
			errSub:  "DataDirection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate succeeded, want error")
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSub)
				}
			} else if err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
		})
	}
}

// TestPlanner_EndToEnd_WireBytes drives the full chain — mapToFlowSpec-style
// config -> planner -> builder — and asserts final wire bytes for the PADI,
// PADR (cookie echo), LCP and IPv4 data frames.
func TestPlanner_EndToEnd_WireBytes(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 1000,
		DstPort: 2000,
		SrcMAC:  "00:01:00:02:00:03",
		DstMAC:  "00:03:a0:12:30:cc",
		Payload: []byte("hello"),
		PPPoE: &core.PPPoEConfig{
			SessionID: 0x000f,
			MRU:       1492,
			Cookie:    []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}

	cfgs := planAll(t, spec)
	if len(cfgs) != 7 {
		t.Fatalf("emitted %d packets, want 7", len(cfgs))
	}

	builder := core.NewBuilder()
	frames := make([][]byte, 0, len(cfgs))
	for i, cfg := range cfgs {
		frame, err := builder.Build(cfg)
		if err != nil {
			t.Fatalf("Build packet[%d]: %v", i, err)
		}
		frames = append(frames, frame)
	}

	// PADI frame: 88 63 | 11 09 | 00 00 | 00 04 | 01 01 00 00, broadcast dst.
	padi := frames[0]
	if !bytes.Equal(padi[0:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Errorf("PADI dst MAC = % x, want broadcast", padi[0:6])
	}
	if !bytes.Equal(padi[12:24], []byte{0x88, 0x63, 0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00}) {
		t.Errorf("PADI frame = % x, want 88 63 11 09 00 00 00 04 01 01 00 00 at [12:24]", padi[12:24])
	}

	// PADR frame: cookie tag echoed after the Service-Name tag:
	// [PPPoE hdr 6][01 01 00 00 (Service-Name)][01 04 00 04 de ad be ef].
	padr := frames[2]
	if !bytes.Equal(padr[20:32], []byte{0x01, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("PADR tags = % x, want Service-Name + AC-Cookie echo", padr[20:32])
	}

	// LCP Configure-Request frame: session 0x000f, PPP proto 0xc021,
	// Payload_Length = 2 + 14 = 16.
	lcp := frames[4]
	if !bytes.Equal(lcp[12:22], []byte{0x88, 0x64, 0x11, 0x00, 0x00, 0x0f, 0x00, 0x10, 0xc0, 0x21}) {
		t.Errorf("LCP frame = % x, want 88 64 11 00 00 0f 00 10 c0 21 at [12:22]", lcp[12:22])
	}

	// IPv4 data frame: session 0x000f, PPP proto 0x0021, inner IP at 22,
	// Payload_Length = 2 + 20 + 8 + 5 = 35 = 0x0023.
	data := frames[6]
	if !bytes.Equal(data[12:22], []byte{0x88, 0x64, 0x11, 0x00, 0x00, 0x0f, 0x00, 0x23, 0x00, 0x21}) {
		t.Errorf("data frame = % x, want 88 64 11 00 00 0f 00 23 00 21 at [12:22]", data[12:22])
	}
	if data[22] != 0x45 || data[31] != 0x11 { // IPv4 header, protocol 17 (UDP)
		t.Errorf("inner IP = % x, want 45 ... 11 (UDP)", data[22:32])
	}
	if !bytes.Equal(data[50:55], []byte("hello")) {
		t.Errorf("data payload = % x, want hello", data[50:55])
	}
}
