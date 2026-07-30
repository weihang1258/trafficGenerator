package ftp

// Spec-driven coverage tests for the FTP planner, derived from RFC 959.
// These fill three gaps identified in the coverage audit:
//   1. §4.1.1/§5.4 authentication failure path (530 reply) - CLAUDE.md
//      mandates failure-path coverage; only the success path (230) was tested.
//   2. §4.1.4 ABOR (abort transfer) - the planner always sent the FULL data
//      payload; there was no way to model a transfer interrupted mid-stream.
//      AbortAfterBytes truncates the data-channel payload so the sub-flow
//      tears down after N bytes, modeling an aborted transfer.
//   3. §4.1.4 NLST (name list) - a LIST variant with no test.
//
// Plus a full-session integration test (§3.2 data connection + §4.1 commands)
// asserting the complete control+data dual-channel wire order.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// controlPayloads extracts the application-layer text (CRLF-stripped) from
// control-channel packets (those WITHOUT the ":sub-" FlowID suffix), in wire
// order. Used to assert the FTP command/response dialog sequence.
func controlPayloads(cfgs []core.PacketConfig) []string {
	var out []string
	for _, c := range cfgs {
		if strings.Contains(c.FlowID, ":sub-") {
			continue
		}
		if len(c.Payload) == 0 {
			continue
		}
		out = append(out, strings.TrimRight(string(c.Payload), "\r\n"))
	}
	return out
}

// subFlowDataBytes returns the concatenated payload bytes of all PSH-ACK
// (0x18) data segments in the data-channel sub-flow. This is the reassembled
// file body that the data channel carried. Used to assert that ABOR truncation
// produced exactly AbortAfterBytes bytes (not the full payload).
func subFlowDataBytes(cfgs []core.PacketConfig) []byte {
	var out []byte
	for _, c := range cfgs {
		if !strings.HasSuffix(c.FlowID, ":sub-0") {
			continue
		}
		// PSH-ACK (0x18) carries data; pure ACK (0x10), SYN (0x02), FIN (0x11)
		// do not. Only accumulate PSH-ACK segments.
		if c.L4.Flags == 0x18 {
			out = append(out, c.Payload...)
		}
	}
	return out
}

// TestFTP_AuthFailure_530 verifies the authentication FAILURE path per RFC
// 959 §4.1.1 (USER) / §5.4 (reply codes). When credentials are rejected the
// server replies 530 "Not logged in" instead of 230 "User logged in". The
// planner must emit the 530 response verbatim and must NOT emit a 230. This
// is the failure-path counterpart to the existing 331->230 success tests
// (CLAUDE.md §2: cover failure paths, not just the happy path).
func TestFTP_AuthFailure_530(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER baduser", Response: "331 Password required"},
				{Cmd: "PASS wrongpass", Response: "530 Login incorrect"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	dialog := controlPayloads(cfgs)

	// Assert the 530 failure response is present in the wire stream.
	found530 := false
	found230 := false
	for _, line := range dialog {
		if strings.HasPrefix(line, "530 ") {
			found530 = true
		}
		if strings.HasPrefix(line, "230 ") {
			found230 = true
		}
	}
	if !found530 {
		t.Errorf("expected 530 auth-failure response in dialog, not found; dialog=%v", dialog)
	}
	if found230 {
		t.Errorf("auth failure path must NOT emit 230 success; dialog=%v", dialog)
	}

	// Assert the USER/PASS commands and the 331 intermediate response are present.
	assertDialogContains := func(substr string) {
		for _, line := range dialog {
			if strings.Contains(line, substr) {
				return
			}
		}
		t.Errorf("expected %q in dialog, not found; dialog=%v", substr, dialog)
	}
	assertDialogContains("USER baduser")
	assertDialogContains("PASS wrongpass")
	assertDialogContains("331 Password required")
}

// TestFTP_AnonymousAccess verifies the anonymous FTP login pattern per RFC
// 959 §4.1.1: USER anonymous -> 331 -> PASS guest@ -> 230. This is the most
// common real-world FTP auth flow and was only implicitly covered (C1.1 NIC
// case) without a Go-level assertion on the 331->230 transition.
func TestFTP_AnonymousAccess(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 FTP server ready",
			Commands: []core.FTPCommand{
				{Cmd: "USER anonymous", Response: "331 Anonymous login ok, send email as password"},
				{Cmd: "PASS anonymous@", Response: "230 Login OK"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	dialog := controlPayloads(drain(ch))

	// RFC 959 §5.4: 331 = "User name okay, need password" (intermediate),
	// 230 = "User logged in, proceed" (final success). Both must appear, in order.
	idx331, idx230 := -1, -1
	for i, line := range dialog {
		if strings.HasPrefix(line, "331 ") && idx331 < 0 {
			idx331 = i
		}
		if strings.HasPrefix(line, "230 ") && idx230 < 0 {
			idx230 = i
		}
	}
	if idx331 < 0 {
		t.Fatalf("expected 331 response (need password), not found; dialog=%v", dialog)
	}
	if idx230 < 0 {
		t.Fatalf("expected 230 response (logged in), not found; dialog=%v", dialog)
	}
	if idx331 >= idx230 {
		t.Errorf("331 (idx %d) must precede 230 (idx %d); dialog=%v", idx331, idx230, dialog)
	}
	// Assert the anonymous user and the email-as-password convention.
	if !contains(dialog, "USER anonymous") {
		t.Errorf("expected 'USER anonymous' command; dialog=%v", dialog)
	}
	if !contains(dialog, "PASS anonymous@") {
		t.Errorf("expected 'PASS anonymous@' (email as password); dialog=%v", dialog)
	}
}

func contains(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// TestFTP_NLST verifies the NLST (Name List) command per RFC 959 §4.1.4.
// NLST returns a bare list of file names (no attributes, unlike LIST). The
// planner plays it back as a command/response pair; this test asserts the
// command string and a data channel carrying the bare name list.
func TestFTP_NLST(t *testing.T) {
	nlstBody := "file1.txt\nfile2.txt\nfile3.txt\n"
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 FTP",
			Commands: []core.FTPCommand{
				{Cmd: "USER a", Response: "331 OK"},
				{Cmd: "PASS a", Response: "230 OK"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
				{Cmd: "NLST", Response: "150 Here comes the name listing", EmitDataChannel: true},
				{Cmd: "", Response: "226 Directory send OK"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   nlstBody,
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	dialog := controlPayloads(cfgs)

	if !contains(dialog, "NLST") {
		t.Errorf("expected NLST command in dialog; dialog=%v", dialog)
	}
	// The data channel should carry the bare name list (no file attributes).
	dataBytes := subFlowDataBytes(cfgs)
	if !strings.Contains(string(dataBytes), "file1.txt") {
		t.Errorf("expected 'file1.txt' in data channel payload; got %q", dataBytes)
	}
	if !strings.Contains(string(dataBytes), "file3.txt") {
		t.Errorf("expected 'file3.txt' in data channel payload; got %q", dataBytes)
	}
}

// TestFTPDataChannel_AbortAfterBytes verifies ABOR (abort transfer) per RFC
// 959 §4.1.4. When AbortAfterBytes is set, the data channel sends only the
// first N bytes of the payload then tears down - modeling a transfer
// interrupted mid-stream. Without this field the planner always sends the
// FULL payload, so there was no way to model an aborted transfer.
//
// The control-channel dialog models: RETR -> 150 -> [partial data channel]
// -> ABOR -> 426 (transfer aborted) -> 226 (abort OK).
func TestFTPDataChannel_AbortAfterBytes(t *testing.T) {
	fullPayload := strings.Repeat("ABCDEFGH", 100) // 800 bytes, well over one MSS
	abortAfter := 200
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 FTP",
			Commands: []core.FTPCommand{
				{Cmd: "USER a", Response: "331 OK"},
				{Cmd: "PASS a", Response: "230 OK"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
				{Cmd: "RETR /big.bin", Response: "150 Opening data connection", EmitDataChannel: true},
				{Cmd: "ABOR", Response: "426 Connection closed; transfer aborted"},
				{Cmd: "", Response: "226 Abort OK"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:            "passive",
				Direction:       "down",
				Payload:         fullPayload,
				AbortAfterBytes: abortAfter,
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	// Assert 1: the data channel carries EXACTLY abortAfter bytes, not the
	// full 800-byte payload. This is the core ABOR semantic.
	dataBytes := subFlowDataBytes(cfgs)
	if got := len(dataBytes); got != abortAfter {
		t.Errorf("data channel sent %d bytes, want %d (AbortAfterBytes); full payload is %d",
			got, abortAfter, len(fullPayload))
	}
	// Assert the truncated bytes are the PREFIX of the full payload (not a
	// suffix or middle slice - ABOR stops sending, it doesn't skip ahead).
	if string(dataBytes) != fullPayload[:abortAfter] {
		t.Errorf("data channel bytes are not the prefix of the full payload")
	}

	// Assert 2: the control channel has the ABOR command and 426/226 responses
	// per RFC 959 §5.4 (426 = "Connection closed; transfer aborted",
	// 226 = "Closing data connection" / abort successful).
	dialog := controlPayloads(cfgs)
	if !contains(dialog, "ABOR") {
		t.Errorf("expected ABOR command in dialog; dialog=%v", dialog)
	}
	assertReplyCode := func(code string) {
		for _, line := range dialog {
			if strings.HasPrefix(line, code+" ") {
				return
			}
		}
		t.Errorf("expected %s reply in dialog; dialog=%v", code, dialog)
	}
	assertReplyCode("426")
	assertReplyCode("226")

	// Assert 3: the ABOR command and 426 response land AFTER the 150 response
	// (the transfer was in progress when aborted) and the 226 lands after 426.
	idx150, idxABOR, idx426, idx226 := -1, -1, -1, -1
	for i, line := range dialog {
		if strings.HasPrefix(line, "150 ") && idx150 < 0 {
			idx150 = i
		}
		if line == "ABOR" && idxABOR < 0 {
			idxABOR = i
		}
		if strings.HasPrefix(line, "426 ") && idx426 < 0 {
			idx426 = i
		}
		if strings.HasPrefix(line, "226 ") && idx226 < 0 {
			idx226 = i
		}
	}
	if idx150 < 0 || idxABOR < 0 || idx426 < 0 || idx226 < 0 {
		t.Fatalf("missing one of 150/ABOR/426/226; idx150=%d idxABOR=%d idx426=%d idx226=%d",
			idx150, idxABOR, idx426, idx226)
	}
	if !(idx150 < idxABOR) {
		t.Errorf("150 (idx %d) must precede ABOR (idx %d)", idx150, idxABOR)
	}
	if !(idxABOR < idx426) {
		t.Errorf("ABOR (idx %d) must precede 426 (idx %d)", idxABOR, idx426)
	}
	if !(idx426 < idx226) {
		t.Errorf("426 (idx %d) must precede 226 (idx %d)", idx426, idx226)
	}
}

// TestFTPDataChannel_AbortAfterBytesZero verifies that AbortAfterBytes=0 (the
// default/zero value) means NO truncation - the full payload is sent. This
// guards against a regression where 0 is treated as "send zero bytes".
func TestFTPDataChannel_AbortAfterBytesZero(t *testing.T) {
	fullPayload := "FILE-BODY-12345"
	spec := dataChannelSpec() // PASV RETR, no AbortAfterBytes
	spec.FTP.DataChannel.Payload = fullPayload
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	dataBytes := subFlowDataBytes(cfgs)
	if string(dataBytes) != fullPayload {
		t.Errorf("AbortAfterBytes=0 should send full payload %q, got %q", fullPayload, dataBytes)
	}
}

// TestFTPDataChannel_AbortAfterBytesExceedsPayload verifies that when
// AbortAfterBytes > len(payload), the full payload is sent (no truncation
// past the end). This is the boundary case.
func TestFTPDataChannel_AbortAfterBytesExceedsPayload(t *testing.T) {
	fullPayload := "SHORT-BODY"
	spec := dataChannelSpec()
	spec.FTP.DataChannel.Payload = fullPayload
	spec.FTP.DataChannel.AbortAfterBytes = 9999 // exceeds len("SHORT-BODY")=10
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	dataBytes := subFlowDataBytes(cfgs)
	if string(dataBytes) != fullPayload {
		t.Errorf("AbortAfterBytes > len(payload) should send full payload %q, got %q", fullPayload, dataBytes)
	}
}

// TestFTP_FullSession_ControlAndData is the integration test for a complete
// control+data dual-channel FTP session per RFC 959 §3.2 (data connection) +
// §4.1 (commands). It asserts the full wire-order dialog:
//
//	handshake -> 220 banner -> USER -> 331 -> PASS -> 230 ->
//	TYPE I -> 200 -> PASV -> 227 -> RETR -> 150 ->
//	[data channel sub-flow: handshake + file body + teardown] ->
//	226 -> QUIT -> 221 -> teardown
//
// This is the "full_session" scenario: one control channel (port 21) carrying
// the command dialog, one data channel (PASV-negotiated port) carrying the
// file body, with the data packets interleaved between 150 and 226.
func TestFTP_FullSession_ControlAndData(t *testing.T) {
	fileBody := "COMPLETE-SESSION-FILE-BODY"
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 FTP server ready",
			Commands: []core.FTPCommand{
				{Cmd: "USER anonymous", Response: "331 Password required"},
				{Cmd: "PASS guest@", Response: "230 Login OK"},
				{Cmd: "TYPE I", Response: "200 Type set to I"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
				{Cmd: "RETR /pub/file.bin", Response: "150 Opening data connection", EmitDataChannel: true},
				{Cmd: "", Response: "226 Transfer complete"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   fileBody,
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	// Assert 1: control-channel dialog has the complete command/response
	// sequence in order (RFC 959 §4.1 command set + §5.4 reply codes).
	dialog := controlPayloads(cfgs)
	expectedSequence := []string{
		"220 FTP server ready",
		"USER anonymous",
		"331 Password required",
		"PASS guest@",
		"230 Login OK",
		"TYPE I",
		"200 Type set to I",
		"PASV",
		"227 Entering Passive Mode (20,0,0,1,195,80)",
		"RETR /pub/file.bin",
		"150 Opening data connection",
		"226 Transfer complete",
		"QUIT",
		"221 Bye",
	}
	// Walk the dialog in order, matching each expected line as a subsequence.
	// (Handshake/banner/teardown packets with empty payloads are skipped by
	// controlPayloads, so the dialog is exactly the FTP text lines.)
	ei := 0
	for _, line := range dialog {
		if ei < len(expectedSequence) && line == expectedSequence[ei] {
			ei++
		}
	}
	if ei != len(expectedSequence) {
		t.Errorf("dialog did not contain the expected command/response sequence in order; "+
			"matched %d/%d; dialog=%v", ei, len(expectedSequence), dialog)
	}

	// Assert 2: a data-channel sub-flow exists and carries the file body.
	sub := findSubFlowPackets(cfgs)
	if len(sub) == 0 {
		t.Fatalf("expected data-channel sub-flow packets, found none")
	}
	dataBytes := subFlowDataBytes(cfgs)
	if string(dataBytes) != fileBody {
		t.Errorf("data channel body = %q, want %q", dataBytes, fileBody)
	}

	// Assert 3: the data-channel sub-flow packets land between the 150 and 226
	// responses in wire order (RFC 959 §3.2: data connection is established
	// after 150 and torn down before 226).
	idx150, _ := findPacketWithPayload(cfgs, "150 Opening")
	idx226, _ := findPacketWithPayload(cfgs, "226 Transfer")
	if idx150 < 0 || idx226 < 0 {
		t.Fatalf("could not locate 150 (idx %d) or 226 (idx %d) in wire stream", idx150, idx226)
	}
	for i, c := range cfgs {
		if !strings.HasSuffix(c.FlowID, ":sub-0") {
			continue
		}
		if i <= idx150 || i >= idx226 {
			t.Errorf("sub-flow packet at wire idx %d not between 150 (idx %d) and 226 (idx %d)",
				i, idx150, idx226)
		}
	}

	// Assert 4: the data channel uses the PASV-negotiated port (50000 =
	// 195*256+80) as the server's data port, proving the control-channel
	// PASV negotiation drove the data-channel 4-tuple (RFC 959 §4.1.2).
	subSYN := filterSubFlowSYNs(cfgs)
	if len(subSYN) == 0 {
		t.Fatalf("expected at least one data-channel SYN")
	}
	if subSYN[0].L4.DstPort != 50000 {
		t.Errorf("data channel SYN DstPort=%d, want 50000 (PASV-negotiated)", subSYN[0].L4.DstPort)
	}

	// Assert 5: control channel has TCP teardown (FIN-ACK) after QUIT (RFC 959
	// §4.1.1 QUIT closes the control connection).
	finCount := 0
	for _, c := range cfgs {
		if strings.Contains(c.FlowID, ":sub-") {
			continue
		}
		if c.L4.Flags == 0x11 { // FIN-ACK
			finCount++
		}
	}
	if finCount < 2 {
		t.Errorf("control channel FIN-ACK count=%d, want >= 2 (4-way teardown)", finCount)
	}
}

// TestFTP_MultiRetrSequence verifies a multi-file download session: two RETR
// commands, each with its own PASV negotiation and data channel. Per RFC 959
// §3.2 each data transfer uses a separate data connection, so two RETR
// commands produce two data-channel sub-flows with distinct PASV-negotiated
// ports. This extends the existing MultiTransferDistinctPorts test by also
// asserting the file bodies are carried correctly on each channel.
func TestFTP_MultiRetrSequence(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		FTP: &core.FTPConfig{
			Banner: "220 FTP",
			Commands: []core.FTPCommand{
				{Cmd: "USER a", Response: "331 OK"},
				{Cmd: "PASS a", Response: "230 OK"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)", }, // 50000
				{Cmd: "RETR /file1.bin", Response: "150 Opening data connection", EmitDataChannel: true},
				{Cmd: "", Response: "226 Transfer complete"},
				{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,81)"}, // 50001
				{Cmd: "RETR /file2.bin", Response: "150 Opening data connection", EmitDataChannel: true},
				{Cmd: "", Response: "226 Transfer complete"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   "FILE1-BODY",
			},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	// Two data channels -> two SYNs, each using its own PASV port.
	syns := filterSubFlowSYNs(cfgs)
	if len(syns) != 2 {
		t.Fatalf("expected 2 data-channel SYNs, got %d", len(syns))
	}
	if syns[0].L4.DstPort != 50000 {
		t.Errorf("first data channel SYN DstPort=%d, want 50000", syns[0].L4.DstPort)
	}
	if syns[1].L4.DstPort != 50001 {
		t.Errorf("second data channel SYN DstPort=%d, want 50001", syns[1].L4.DstPort)
	}

	// Both RETR commands present in the control dialog.
	dialog := controlPayloads(cfgs)
	if !contains(dialog, "RETR /file1.bin") {
		t.Errorf("expected 'RETR /file1.bin' in dialog; dialog=%v", dialog)
	}
	if !contains(dialog, "RETR /file2.bin") {
		t.Errorf("expected 'RETR /file2.bin' in dialog; dialog=%v", dialog)
	}

	// Assert both data channels carry the file body. Both sub-flows share the
	// same DataChannel.Payload ("FILE1-BODY") since FTPConfig has one
	// DataChannel; the key assertion is that TWO distinct sub-flows are emitted.
	totalSubDataBytes := subFlowDataBytes(cfgs)
	if len(totalSubDataBytes) != 2*len("FILE1-BODY") {
		t.Errorf("total data-channel bytes=%d, want %d (two transfers of FILE1-BODY)",
			len(totalSubDataBytes), 2*len("FILE1-BODY"))
	}
}
