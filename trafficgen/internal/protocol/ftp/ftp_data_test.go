package ftp

// Data-channel test points for the FTP planner. These verify that the
// FTPDataChannel sub-flow is emitted at the right position in the control-
// channel dialog, with the right 4-tuple, direction, and wire-format
// fields. Derived from the FTPDataChannel struct spec in types.go and
// the emit-FTP-data-channel algorithm in ftp.go.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// dataChannelSpec builds a spec with a PASV-mode RETR download of a small
// file body. The control channel has a PASV negotiation command and a RETR
// command flagged with EmitDataChannel=true so the data sub-flow lands
// between RETR's "150" response and the final "226" response.
func dataChannelSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anonymous", Response: "331 Password required"},
				{Cmd: "PASS guest", Response: "230 Login OK"},
				{Cmd: "TYPE I", Response: "200 Type set"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
				{
					Cmd:             "RETR /file.bin",
					Response:        "150 Opening data connection",
					EmitDataChannel: true,
				},
				{Cmd: "", Response: "226 Transfer complete"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   "FILE-BODY-12345",
			},
		},
	}
}

// findSubFlowPackets returns the configs whose FlowID has the ":sub-0"
// suffix — these are the data-channel packets emitted by EmitSubFlow.
func findSubFlowPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":sub-0") {
			out = append(out, c)
		}
	}
	return out
}

// findControlPackets returns the configs whose FlowID does NOT have the
// ":sub-" suffix — these are the control-channel packets.
func findControlPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if !strings.Contains(c.FlowID, ":sub-") {
			out = append(out, c)
		}
	}
	return out
}

// findPacketWithPayload returns the first config whose payload contains
// the given substring. Useful for locating where in the wire order a
// specific FTP command landed.
func findPacketWithPayload(cfgs []core.PacketConfig, substr string) (int, *core.PacketConfig) {
	for i, c := range cfgs {
		if strings.Contains(string(c.Payload), substr) {
			return i, &c
		}
	}
	return -1, nil
}

// TestFTPDataChannel_PassiveRetrSubFlowEmitted verifies that a PASV-mode
// RETR with EmitDataChannel=true produces a data-channel sub-flow with
// the expected packet count: 3 handshake + 2*segments + 4 teardown.
// For a 14-byte payload under MSS=1460, that's 1 segment, so 3+2+4=9
// sub-flow packets.
func TestFTPDataChannel_PassiveRetrSubFlowEmitted(t *testing.T) {
	spec := dataChannelSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets emitted; want 9 (3+2+4)")
	}
	if got, want := len(sub), 9; got != want {
		t.Errorf("len(sub-flow)=%d, want %d (3 handshake + 2 data/ack + 4 teardown)", got, want)
	}

	// All sub-flow packets share the parent's FlowID + ":sub-0".
	parentFlowID := "10.0.0.1-20.0.0.1-20000-21"
	for i, c := range sub {
		if c.FlowID != parentFlowID+":sub-0" {
			t.Errorf("sub[%d].FlowID=%q, want %q", i, c.FlowID, parentFlowID+":sub-0")
		}
	}
}

// TestFTPDataChannel_SubFlowPositionBetween150And226 verifies the
// sub-flow's packets land BETWEEN the "150 Opening data connection"
// response and the "226 Transfer complete" response in wire order.
// This is the key FTP data-channel semantics: data packets are
// interleaved into the control channel, not appended.
func TestFTPDataChannel_SubFlowPositionBetween150And226(t *testing.T) {
	spec := dataChannelSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	idx150, _ := findPacketWithPayload(cfgs, "150 Opening")
	if idx150 < 0 {
		t.Fatalf("could not find 150 response in wire order")
	}
	idx226, _ := findPacketWithPayload(cfgs, "226 Transfer")
	if idx226 < 0 {
		t.Fatalf("could not find 226 response in wire order")
	}
	if idx150 >= idx226 {
		t.Fatalf("150 at %d should precede 226 at %d", idx150, idx226)
	}

	// Every sub-flow packet must be between idx150+1 and idx226-1.
	for i, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":sub-0") {
			if i <= idx150 || i >= idx226 {
				t.Errorf("sub-flow packet at index %d not between 150 (%d) and 226 (%d)",
					i, idx150, idx226)
			}
		}
	}

	// Count sub-flow packets between 150 and 226.
	between := 0
	for i := idx150 + 1; i < idx226; i++ {
		if strings.HasSuffix(cfgs[i].FlowID, ":sub-0") {
			between++
		}
	}
	if between == 0 {
		t.Errorf("no sub-flow packets between 150 and 226; want 9")
	}
}

// TestFTPDataChannel_PassiveModePorts verifies passive-mode port
// derivation: SrcPort = control_src_port + 1 (ephemeral), DstPort = 50000
// (default when no PASV response is parsed).
func TestFTPDataChannel_PassiveModePorts(t *testing.T) {
	spec := dataChannelSpec()
	// Control src_port=20000 -> passive sub-flow SrcPort=20001
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}

	// SYN packet (first sub-flow packet) carries the client's src/dst ports.
	syn := sub[0]
	if syn.L4.SrcPort != 20001 {
		t.Errorf("passive SrcPort=%d, want 20001 (control 20000 + 1)", syn.L4.SrcPort)
	}
	if syn.L4.DstPort != 50000 {
		t.Errorf("passive DstPort=%d, want 50000 (default PASV high port)", syn.L4.DstPort)
	}
}

// TestFTPDataChannel_ActiveModePorts verifies active-mode (PORT) port
// derivation: SrcPort = 20 (server's data port), DstPort = control_src_port
// + 1 (client's data port that the server connects to).
//
// In SubFlowSpec, SrcPort is always the CLIENT's port and DstPort is the
// SERVER's port. So for active mode where the server connects from port 20
// to the client's port 20001:
//   - sub.SrcPort (client's port) = 20001
//   - sub.DstPort (server's port) = 20
//
// The first sub-flow packet (SYN) goes server→client (Direction: "down")
// because the server opens the connection.
func TestFTPDataChannel_ActiveModePorts(t *testing.T) {
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Mode = "active"
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}

	// SYN packet (first sub-flow packet) is server→client in active mode.
	syn := sub[0]
	if syn.Direction != "down" {
		t.Errorf("active SYN Direction=%q, want \"down\" (server opens)", syn.Direction)
	}
	// Server→client SYN: SrcPort=server's port (20), DstPort=client's port (20001).
	if syn.L4.SrcPort != 20 {
		t.Errorf("active SYN SrcPort=%d, want 20 (server data port)", syn.L4.SrcPort)
	}
	if syn.L4.DstPort != 20001 {
		t.Errorf("active SYN DstPort=%d, want 20001 (control 20000 + 1)", syn.L4.DstPort)
	}
	// SYN comes from server IP (20.0.0.1) going to client IP (10.0.0.1).
	if syn.L3.SrcIP != "20.0.0.1" {
		t.Errorf("active SYN L3.SrcIP=%q, want server IP", syn.L3.SrcIP)
	}
	if syn.L3.DstIP != "10.0.0.1" {
		t.Errorf("active SYN L3.DstIP=%q, want client IP", syn.L3.DstIP)
	}
}

// TestFTPDataChannel_PassiveModeSYNDirection verifies that in passive mode
// the client opens the data connection: SYN goes client→server with
// SrcPort=client's ephemeral, DstPort=server's PASV port.
func TestFTPDataChannel_PassiveModeSYNDirection(t *testing.T) {
	spec := dataChannelSpec()
	// spec already has Mode: "passive" from dataChannelSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}

	syn := sub[0]
	if syn.Direction != "up" {
		t.Errorf("passive SYN Direction=%q, want \"up\" (client opens)", syn.Direction)
	}
	// Client→server SYN: SrcPort=client's ephemeral (20001), DstPort=server's PASV port (50000).
	if syn.L4.SrcPort != 20001 {
		t.Errorf("passive SYN SrcPort=%d, want 20001 (client ephemeral)", syn.L4.SrcPort)
	}
	if syn.L4.DstPort != 50000 {
		t.Errorf("passive SYN DstPort=%d, want 50000 (server PASV port)", syn.L4.DstPort)
	}
	if syn.L3.SrcIP != "10.0.0.1" {
		t.Errorf("passive SYN L3.SrcIP=%q, want client IP", syn.L3.SrcIP)
	}
	if syn.L3.DstIP != "20.0.0.1" {
		t.Errorf("passive SYN L3.DstIP=%q, want server IP", syn.L3.DstIP)
	}
}

// TestFTPDataChannel_DirectionDown verifies Direction="down" (RETR) has
// the data PSH-ACK packet going from server to client — server pushes
// file bytes to client.
func TestFTPDataChannel_DirectionDown(t *testing.T) {
	spec := dataChannelSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) < 4 {
		t.Fatalf("len(sub)=%d, want >= 4", len(sub))
	}

	// Data PSH-ACK is at index 3 (after SYN, SYN-ACK, ACK).
	dataPkt := sub[3]
	if dataPkt.Direction != "down" {
		t.Errorf("data Direction=%q, want \"down\" (RETR: server→client)", dataPkt.Direction)
	}
	if dataPkt.L3.SrcIP != "20.0.0.1" {
		t.Errorf("data L3.SrcIP=%q, want server IP", dataPkt.L3.SrcIP)
	}
	if string(dataPkt.Payload) != "FILE-BODY-12345" {
		t.Errorf("data Payload=%q, want \"FILE-BODY-12345\"", string(dataPkt.Payload))
	}
}

// TestFTPDataChannel_DirectionUp verifies Direction="up" (STOR upload)
// has the data PSH-ACK going from client to server.
func TestFTPDataChannel_DirectionUp(t *testing.T) {
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Direction = "up"
	// Adjust the commands to look like STOR.
	spec.FTP.Commands = []core.FTPCommand{
		{Cmd: "USER anonymous", Response: "331"},
		{Cmd: "PASS guest", Response: "230"},
		{Cmd: "TYPE I", Response: "200"},
		{Cmd: "PORT 10,0,0,1,78,17", Response: "200 PORT OK"},
		{
			Cmd:             "STOR /upload.bin",
			Response:        "150 Opening data connection",
			EmitDataChannel: true,
		},
		{Cmd: "", Response: "226 Transfer complete"},
		{Cmd: "QUIT", Response: "221 Bye"},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) < 4 {
		t.Fatalf("len(sub)=%d, want >= 4", len(sub))
	}
	dataPkt := sub[3]
	if dataPkt.Direction != "up" {
		t.Errorf("data Direction=%q, want \"up\" (STOR: client→server)", dataPkt.Direction)
	}
	if dataPkt.L3.SrcIP != "10.0.0.1" {
		t.Errorf("data L3.SrcIP=%q, want client IP", dataPkt.L3.SrcIP)
	}
}

// TestFTPDataChannel_NoDataChannel verifies that DataChannel=nil produces
// no sub-flow packets (backward compat with pre-data-channel specs).
func TestFTPDataChannel_NoDataChannel(t *testing.T) {
	spec := validFTPSpec() // no DataChannel
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) != 0 {
		t.Errorf("DataChannel=nil but got %d sub-flow packets, want 0", len(sub))
	}
}

// TestFTPDataChannel_EmitFlagFalse verifies that EmitDataChannel=false on
// all commands suppresses the sub-flow, even when DataChannel is set.
func TestFTPDataChannel_EmitFlagFalse(t *testing.T) {
	spec := dataChannelSpec()
	// Clear all EmitDataChannel flags.
	for i := range spec.FTP.Commands {
		spec.FTP.Commands[i].EmitDataChannel = false
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) != 0 {
		t.Errorf("EmitDataChannel=false but got %d sub-flow packets, want 0", len(sub))
	}
}

// TestFTPDataChannel_PayloadB64 verifies that PayloadB64 carries binary
// file body bytes (e.g. a PNG signature) through the sub-flow.
func TestFTPDataChannel_PayloadB64(t *testing.T) {
	pngSig := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	encoded := base64.StdEncoding.EncodeToString(pngSig)
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Payload = ""
	spec.FTP.DataChannel.PayloadB64 = encoded
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) < 4 {
		t.Fatalf("len(sub)=%d, want >= 4", len(sub))
	}
	dataPkt := sub[3]
	if string(dataPkt.Payload) != string(pngSig) {
		t.Errorf("data Payload=%v, want %v (PNG signature from PayloadB64)", dataPkt.Payload, pngSig)
	}
}

// TestFTPDataChannel_MSSInheritsFromParent verifies that when DataChannel
// has no MSS set, it inherits the parent TCPConfig.MSS. A 3000-byte
// payload under MSS=1400 should split into 3 segments.
func TestFTPDataChannel_MSSInheritsFromParent(t *testing.T) {
	spec := dataChannelSpec()
	// Make payload 3000 bytes; set parent MSS=1400.
	payload := strings.Repeat("A", 3000)
	spec.FTP.DataChannel.Payload = payload
	spec.TCP = &core.TCPConfig{MSS: 1400}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	// 3 handshake + 2*3 (data+ack per segment) + 4 teardown = 3+6+4 = 13
	if got, want := len(sub), 13; got != want {
		t.Errorf("len(sub)=%d, want %d (3 segments under MSS=1400)", got, want)
	}
}

// TestFTPDataChannel_MSSOverrideOnDataChannel verifies that MSS set on
// DataChannel overrides the parent TCP MSS for the sub-flow.
func TestFTPDataChannel_MSSOverrideOnDataChannel(t *testing.T) {
	spec := dataChannelSpec()
	payload := strings.Repeat("A", 3000)
	spec.FTP.DataChannel.Payload = payload
	spec.FTP.DataChannel.MSS = 1000 // override
	spec.TCP = &core.TCPConfig{MSS: 1400}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	// MSS=1000, 3000 bytes -> 3 segments (1000+1000+1000), so 3+2*3+4 = 13
	if got, want := len(sub), 13; got != want {
		t.Errorf("len(sub)=%d, want %d (MSS=1000 -> 3 segments)", got, want)
	}
	// Each data segment should be 1000 bytes.
	for i, c := range sub {
		// Data packets are PSH|ACK (0x18). The 3 data segments are at
		// positions 3, 5, 7 in the sub slice.
		if c.L4.Flags == 0x18 {
			if len(c.Payload) != 1000 {
				t.Errorf("data segment %d (idx %d) len=%d, want 1000", i, i, len(c.Payload))
			}
		}
	}
}

// TestFTPDataChannel_ControlChannelUnchanged verifies that the control
// channel's packet count and structure are unchanged when DataChannel
// is added — the sub-flow is purely additive. The control channel
// should have the same handshake + banner + command/response + teardown
// sequence as without DataChannel.
func TestFTPDataChannel_ControlChannelUnchanged(t *testing.T) {
	withDC := dataChannelSpec()
	withoutDC := dataChannelSpec()
	withoutDC.FTP.DataChannel = nil
	for i := range withoutDC.FTP.Commands {
		withoutDC.FTP.Commands[i].EmitDataChannel = false
	}

	ch1, _ := NewPlanner().Plan(context.Background(), withDC)
	ch2, _ := NewPlanner().Plan(context.Background(), withoutDC)
	cfgsWith := drain(ch1)
	cfgsWithout := drain(ch2)

	ctrlWith := findControlPackets(cfgsWith)
	ctrlWithout := findControlPackets(cfgsWithout)

	if len(ctrlWith) != len(ctrlWithout) {
		t.Errorf("control packet count: with DC=%d, without DC=%d (should match)", len(ctrlWith), len(ctrlWithout))
	}
}

// TestFTPDataChannel_UserPortOverride verifies that explicit SrcPort/DstPort
// on the DataChannel override the derived defaults.
func TestFTPDataChannel_UserPortOverride(t *testing.T) {
	spec := dataChannelSpec()
	spec.FTP.DataChannel.SrcPort = 43210
	spec.FTP.DataChannel.DstPort = 12345
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	if syn.L4.SrcPort != 43210 {
		t.Errorf("SrcPort=%d, want 43210 (user override)", syn.L4.SrcPort)
	}
	if syn.L4.DstPort != 12345 {
		t.Errorf("DstPort=%d, want 12345 (user override)", syn.L4.DstPort)
	}
}

// TestFTPDataChannel_MultipleEmitFlags verifies that EmitDataChannel=true
// on multiple commands emits the sub-flow multiple times. This is rare
// (a real FTP session usually has one data transfer) but supported.
func TestFTPDataChannel_MultipleEmitFlags(t *testing.T) {
	spec := dataChannelSpec()
	// Flag two commands — the RETR (already flagged) and the QUIT.
	// (QUIT-with-data-channel is unrealistic, but it tests the loop.)
	spec.FTP.Commands[6].EmitDataChannel = true // QUIT
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	// Two sub-flow emits, each 9 packets = 18.
	if got, want := len(sub), 18; got != want {
		t.Errorf("len(sub)=%d, want %d (2 data channels * 9 packets)", got, want)
	}
}

// TestFTPDataChannel_PortOverflowGuard verifies that when the control
// channel's SrcPort is 65535, the data channel's derived port does NOT
// wrap to 0 (which would be interpreted as "derive" and produce a weird
// default). Instead the planner picks a safe ephemeral port.
func TestFTPDataChannel_PortOverflowGuard(t *testing.T) {
	spec := dataChannelSpec()
	spec.SrcPort = 65535 // would wrap to 0 if not guarded
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	// In passive mode, SrcPort (client's port) is the derived one. With
	// overflow guard it should be 1024, not 0.
	if syn.L4.SrcPort == 0 {
		t.Errorf("passive SrcPort wrapped to 0; overflow guard failed")
	}
	if syn.L4.SrcPort != 1024 {
		t.Errorf("passive SrcPort=%d, want 1024 (overflow fallback)", syn.L4.SrcPort)
	}
}

// TestFTPDataChannel_PortOverflowGuardActive verifies the overflow guard
// fires on active mode too (server's DstPort = client's derived port).
func TestFTPDataChannel_PortOverflowGuardActive(t *testing.T) {
	spec := dataChannelSpec()
	spec.SrcPort = 65535
	spec.FTP.DataChannel.Mode = "active"
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	// Active mode: SYN goes server→client. DstPort=client's derived port
	// = 1024 (overflow fallback).
	if syn.L4.DstPort == 0 {
		t.Errorf("active DstPort wrapped to 0; overflow guard failed")
	}
	if syn.L4.DstPort != 1024 {
		t.Errorf("active DstPort=%d, want 1024 (overflow fallback)", syn.L4.DstPort)
	}
}

// TestFTPDataChannel_ModeCaseInsensitive verifies Mode comparison is
// case-insensitive (real-world configs may use any casing).
func TestFTPDataChannel_ModeCaseInsensitive(t *testing.T) {
	cases := []string{"Active", "ACTIVE", "active"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			spec := dataChannelSpec()
			spec.FTP.DataChannel.Mode = mode
			ch, err := NewPlanner().Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			cfgs := drain(ch)
			sub := findSubFlowPackets(cfgs)
			if len(sub) == 0 {
				t.Fatalf("no sub-flow packets for Mode=%q", mode)
			}
			// All these casings should be recognized as active mode:
			// SYN goes server→client (Direction: "down") with SrcPort=20.
			syn := sub[0]
			if syn.Direction != "down" {
				t.Errorf("Mode=%q: SYN Direction=%q, want \"down\"", mode, syn.Direction)
			}
			if syn.L4.SrcPort != 20 {
				t.Errorf("Mode=%q: SYN SrcPort=%d, want 20 (server data port)", mode, syn.L4.SrcPort)
			}
		})
	}
}

// TestFTPDataChannel_ModeEmptyDefaultsPassive verifies that an empty Mode
// defaults to passive (the modern default; active is rare outside legacy).
func TestFTPDataChannel_ModeEmptyDefaultsPassive(t *testing.T) {
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Mode = ""
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	// Passive mode: SYN goes client→server (Direction: "up").
	if syn.Direction != "up" {
		t.Errorf("empty Mode: SYN Direction=%q, want \"up\" (passive default)", syn.Direction)
	}
}

// TestParsePASVPort verifies the 227 PASV response parser. Per RFC 959 §5.2
// the data-port is p1*256+p2 from the 6-tuple "(h1,h2,h3,h4,p1,p2)".
func TestParsePASVPort(t *testing.T) {
	cases := []struct {
		name     string
		response string
		want     uint16
	}{
		{"standard", "227 Entering Passive Mode (20,0,0,1,195,80)", 50000},   // 195*256+80
		{"high_port", "227 Entering Passive Mode (20,0,0,1,255,255)", 65535}, // 255*256+255
		{"low_port", "227 Entering Passive Mode (20,0,0,1,0,1)", 1},          // 0*256+1
		{"no_match", "227 Entering Passive Mode", 0},
		{"malformed", "227 Entering Passive Mode (20,0,0,1)", 0},
		{"empty", "", 0},
		// Regex must anchor on "227" so a non-PASV response containing a
		// 6-tuple (multi-line banner, MLSD/STAT listing) is NOT misinterpreted
		// as a PASV advertisement.
		{"non_227_banner_with_6tuple", "230-Welcome (1,2,3,4,5,6)", 0},
		{"non_227_listing_with_6tuple", "150 Here follows a list (10,20,30,40,50,60)", 0},
		// strconv.Atoi error must be checked, not swallowed - huge numbers
		// that overflow int must NOT silently wrap into [0,65535].
		{"overflow_p1", "227 Entering Passive Mode (20,0,0,1,99999999999999999999,80)", 0},
		{"overflow_p2", "227 Entering Passive Mode (20,0,0,1,195,99999999999999999999)", 0},
		// Multi-line 227 response per RFC 959 §4.2 continuation format:
		// "227-Welcome\r\n227 Entering Passive Mode (...)". The regex must
		// match the SECOND line (the final 227 line), not fail because the
		// first line has no 6-tuple. Pre-fix the `^227` anchor without
		// `(?m)` rejected this multi-line format.
		{"multiline_227_continuation", "227-Welcome to FTP\r\n227 Entering Passive Mode (20,0,0,1,195,80)", 50000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePASVPort(tc.response)
			if got != tc.want {
				t.Errorf("parsePASVPort(%q)=%d, want %d", tc.response, got, tc.want)
			}
		})
	}
}

// TestParsePORTPort verifies the PORT command parser. Per RFC 959 §5.2 the
// data-port is p1*256+p2 from "PORT h1,h2,h3,h4,p1,p2".
func TestParsePORTPort(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want uint16
	}{
		{"standard", "PORT 10,0,0,1,78,17", 19985},   // 78*256+17
		{"high_port", "PORT 10,0,0,1,255,255", 65535}, // 255*256+255
		{"low_port", "PORT 10,0,0,1,0,200", 200},      // 0*256+200
		// Per RFC 959 §5.3.1 FTP commands are case-insensitive. The regex
		// uses (?i) so "port", "Port", "PORT" all parse the same.
		{"lowercase", "port 10,0,0,1,78,17", 19985},
		{"mixed_case", "Port 10,0,0,1,78,17", 19985},
		{"no_match", "USER anonymous", 0},
		{"pasv_response", "227 Entering Passive Mode (20,0,0,1,195,80)", 0},
		{"empty", "", 0},
		// strconv.Atoi error must be checked, not swallowed - huge numbers
		// that overflow int must NOT silently wrap into [0,65535].
		{"overflow_p1", "PORT 10,0,0,1,99999999999999999999,17", 0},
		{"overflow_p2", "PORT 10,0,0,1,78,99999999999999999999", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePORTPort(tc.cmd)
			if got != tc.want {
				t.Errorf("parsePORTPort(%q)=%d, want %d", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestFTPDataChannel_PassivePortFromPASVResponse verifies that the data-channel
// DstPort (server's PASV port) is parsed from the 227 PASV response in the
// control-channel dialog rather than falling back to 50000.
//
// The default dataChannelSpec has "227 Entering Passive Mode (20,0,0,1,195,80)"
// → port 50000, which happens to match the old hardcoded default. To prove
// the parser is actually running, we use a different PASV port (50001 = 195*256+81)
// and check the data-channel SYN's DstPort equals 50001.
func TestFTPDataChannel_PassivePortFromPASVResponse(t *testing.T) {
	spec := dataChannelSpec()
	// Change the PASV response to advertise port 50001 (195*256+81) instead
	// of the default 50000.
	spec.FTP.Commands[3].Response = "227 Entering Passive Mode (20,0,0,1,195,81)"
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	if syn.L4.DstPort != 50001 {
		t.Errorf("passive DstPort=%d, want 50001 (parsed from 227 response 195,81)", syn.L4.DstPort)
	}
	// The SrcPort is still the client's ephemeral derived from control port +1.
	if syn.L4.SrcPort != 20001 {
		t.Errorf("passive SrcPort=%d, want 20001 (control 20000 + 1)", syn.L4.SrcPort)
	}
}

// TestFTPDataChannel_ActivePortFromPORTCommand verifies that the data-channel
// client-side port is parsed from the PORT command in the control-channel
// dialog rather than falling back to control_src_port+1.
//
// We inject "PORT 10,0,0,1,78,33" → port 20001 (78*256+33=20001) and check
// the data-channel SYN's DstPort (client's port the server connects to)
// equals 20001.
func TestFTPDataChannel_ActivePortFromPORTCommand(t *testing.T) {
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Mode = "active"
	// Replace the PASV command/response pair with a PORT command.
	// 78*256+33 = 20001 (matches the conventional ctrl_port+1 by coincidence,
	// but proves the parser works — if it ignored PORT and fell back to
	// ctrl+1 the answer would still be 20001). Use a non-+1 port to make the
	// test meaningful: 100*256+1 = 25601.
	spec.FTP.Commands[3] = core.FTPCommand{
		Cmd:      "PORT 10,0,0,1,100,1",
		Response: "200 PORT command successful",
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	// Active mode: SYN goes server→client. DstPort=client's advertised PORT port.
	// 100*256+1 = 25601
	if syn.L4.DstPort != 25601 {
		t.Errorf("active DstPort=%d, want 25601 (parsed from PORT 100,1)", syn.L4.DstPort)
	}
	// Server's port is still 20.
	if syn.L4.SrcPort != 20 {
		t.Errorf("active SrcPort=%d, want 20 (server data port)", syn.L4.SrcPort)
	}
}

// TestFTPDataChannel_UserOverrideBeatsSignaling verifies that explicit user
// override on DataChannel.SrcPort/DstPort wins over both signaling-derived
// and hardcoded defaults.
func TestFTPDataChannel_UserOverrideBeatsSignaling(t *testing.T) {
	spec := dataChannelSpec()
	// Signaling says 50001; user says 43210.
	spec.FTP.Commands[3].Response = "227 Entering Passive Mode (20,0,0,1,195,81)"
	spec.FTP.DataChannel.DstPort = 43210
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("no sub-flow packets")
	}
	syn := sub[0]
	if syn.L4.DstPort != 43210 {
		t.Errorf("DstPort=%d, want 43210 (user override beats signaling 50001)", syn.L4.DstPort)
	}
}

// TestFTPDataChannel_MultiTransferDistinctPorts verifies that a dialog with
// two PASV negotiations (advertising ports 50000 and 50001) and two
// EmitDataChannel flags produces two data channels with DISTINCT DstPorts -
// each data channel must associate with its own preceding PASV, not the
// first one in the dialog. Pre-fix the function returned the first PASV
// match for all data channels, producing 4-tuple collisions.
//
// This test asserts port-to-CHANNEL ordering (first data channel uses 50000,
// second uses 50001), not just that both ports appear somewhere - a
// hypothetical swap regression would pass the weaker assertion.
func TestFTPDataChannel_MultiTransferDistinctPorts(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anonymous", Response: "331 Password required"},
				{Cmd: "PASS guest", Response: "230 Login OK"},
				{Cmd: "TYPE I", Response: "200 Type set"},
				// First transfer: PASV advertises port 50000.
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"}, // 50000
				{
					Cmd:             "RETR /file1.bin",
					Response:        "150 Opening data connection",
					EmitDataChannel: true,
				},
				{Cmd: "", Response: "226 Transfer complete"},
				// Second transfer: PASV advertises port 50001.
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,81)"}, // 50001
				{
					Cmd:             "RETR /file2.bin",
					Response:        "150 Opening data connection",
					EmitDataChannel: true,
				},
				{Cmd: "", Response: "226 Transfer complete"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   "FILE-BODY",
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	// Collect SYN packets (passive mode: client->server, carries TCP options)
	// in wire order. Each data channel starts with one SYN; two data channels
	// -> two SYNs, ordered by emit time (first data channel's SYN before
	// second's).
	var syns []core.PacketConfig
	for _, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":sub-0") &&
			c.Direction == "up" &&
			len(c.L4.TCPOptions) > 0 &&
			c.L4.Flags == 0x02 { // SYN flag only (SYN-ACK has 0x12)
			syns = append(syns, c)
		}
	}
	if len(syns) != 2 {
		t.Fatalf("found %d SYN packets in sub-flow, want 2 (two data channels)", len(syns))
	}
	// First data channel's SYN must use the FIRST PASV port (50000).
	if syns[0].L4.DstPort != 50000 {
		t.Errorf("first data channel SYN DstPort=%d, want 50000 (first PASV)",
			syns[0].L4.DstPort)
	}
	// Second data channel's SYN must use the SECOND PASV port (50001).
	if syns[1].L4.DstPort != 50001 {
		t.Errorf("second data channel SYN DstPort=%d, want 50001 (second PASV)",
			syns[1].L4.DstPort)
	}
}
