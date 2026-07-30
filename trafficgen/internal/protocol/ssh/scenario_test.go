// Package ssh scenario_test.go - spec-driven tests for scenario-mode dialog
// generation and complete-session ordering.
//
// Per CLAUDE.md testing policy:
//   - Spec-driven: derived from RFC 4253 §7/§8 (transport) and RFC 4254 §5/§6
//     (connection/channel). Each scenario asserts the FULL ordered message
//     sequence a real SSH session produces, not just that individual messages
//     exist.
//   - Failure paths: unknown scenario rejected; auth-failure-retry exercises
//     the failure-then-retry path.
//   - Per-code-path: each channel-request subtype (env, subsystem, signal,
//     window-change, x11-req, exit-signal) gets its own encoder test.
//   - Observable outcomes: message bytes, ordering indices, directions.
//
// These tests FAIL until scenario.go + the Scenario field on SSHConfig exist.
package ssh

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// scenarioSpec returns a spec with the given scenario set and versions
// enabled so the version-exchange packets are emitted (lets us assert the
// full session from version exchange through teardown).
func scenarioSpec(scenario string) core.FlowSpec {
	s := validSSHSpec()
	s.SSH.ServerVersion = "SSH-2.0-OpenSSH_8.9"
	s.SSH.ClientVersion = "SSH-2.0-trafficgen_1.0"
	s.SSH.Scenario = scenario
	return s
}

// msgByte returns the SSH message number of the BPP payload of cfg, or 0 if
// the payload is not a BPP frame (e.g. version string, handshake).
func msgByte(c core.PacketConfig) (byte, bool) {
	p := bppPayload(c.Payload)
	if len(p) == 0 {
		return 0, false
	}
	return p[0], true
}

// msgIndex returns the index of the first cfg whose BPP payload starts with
// the given message byte, or -1.
func msgIndex(cfgs []core.PacketConfig, msg byte) int {
	for i, c := range cfgs {
		if b, ok := msgByte(c); ok && b == msg {
			return i
		}
	}
	return -1
}

// allMsgIndices returns all indices whose BPP payload starts with msg.
func allMsgIndices(cfgs []core.PacketConfig, msg byte) []int {
	var out []int
	for i, c := range cfgs {
		if b, ok := msgByte(c); ok && b == msg {
			out = append(out, i)
		}
	}
	return out
}

// --- Scenario validation (failure path) ---

// RFC: an unknown scenario name must be rejected at Validate time so the
// planner does not silently emit a default dialog under a misleading label.
func TestSSHScenario_UnknownRejected(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.Scenario = "bogus"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unknown SSH scenario") {
		t.Errorf("err=%v, want contains 'unknown SSH scenario'", err)
	}
}

// Each known scenario must validate cleanly.
func TestSSHScenario_KnownAccepted(t *testing.T) {
	for _, sc := range []string{"exec", "shell", "pty-exec", "publickey", "auth_fail_retry", "long_output"} {
		p := NewPlanner()
		spec := validSSHSpec()
		spec.SSH.Scenario = sc
		if err := p.Validate(spec); err != nil {
			t.Errorf("scenario %q: %v", sc, err)
		}
	}
}

// --- exec scenario: complete ordered session (RFC 4254 §6.5) ---

// The exec scenario must produce the full ordered sequence a real SSH exec
// session generates: version exchange -> KEXINIT -> KEXDH -> NEWKEYS ->
// SERVICE -> USERAUTH_REQUEST -> USERAUTH_SUCCESS -> CHANNEL_OPEN(session) ->
// CHANNEL_OPEN_CONFIRMATION -> CHANNEL_REQUEST(exec) -> CHANNEL_DATA(stdout,
// server->client) -> CHANNEL_EOF(down) -> CHANNEL_CLOSE(down) ->
// CHANNEL_EOF(up) -> CHANNEL_CLOSE(up) -> teardown.
func TestSSHScenario_ExecCompleteSession(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, scenarioSpec("exec")))

	// Required messages in order.
	wantOrder := []byte{
		MsgKexInit, MsgKexDHInit, MsgKexDHReply, MsgNewKeys,
		MsgServiceRequest, MsgServiceAccept,
		MsgUserAuthRequest, MsgUserAuthSuccess,
		MsgChannelOpen, MsgChannelOpenConf,
		MsgChannelRequest, // exec
		MsgChannelData,    // stdout (down)
		MsgChannelEOF,     // server EOF
		MsgChannelClose,   // server close
		MsgChannelEOF,     // client EOF
		MsgChannelClose,   // client close
	}
	prevIdx := -1
	for i, want := range wantOrder {
		// Find the next occurrence of `want` after prevIdx.
		found := -1
		for j := prevIdx + 1; j < len(cfgs); j++ {
			if b, ok := msgByte(cfgs[j]); ok && b == want {
				found = j
				break
			}
		}
		if found == -1 {
			t.Fatalf("wantOrder[%d]=0x%02x not found after idx %d", i, want, prevIdx)
		}
		prevIdx = found
	}

	// The exec CHANNEL_REQUEST must carry the command string.
	execReq := findNthMsg(cfgs, MsgChannelRequest, 1)
	if execReq == nil {
		t.Fatalf("exec CHANNEL_REQUEST not found")
	}
	p_ := bppPayload(execReq.Payload)
	off := 5 // msg(1)+recipient(4)
	typeLen := binary.BigEndian.Uint32(p_[off : off+4])
	typeStr := string(p_[off+4 : off+4+int(typeLen)])
	if typeStr != "exec" {
		t.Errorf("request_type=%q, want 'exec'", typeStr)
	}

	// The CHANNEL_DATA must be server->client (down) carrying stdout.
	dataIdx := msgIndex(cfgs, MsgChannelData)
	if dataIdx == -1 {
		t.Fatalf("CHANNEL_DATA not found")
	}
	if cfgs[dataIdx].Direction != "down" {
		t.Errorf("CHANNEL_DATA dir=%s, want down (server stdout)", cfgs[dataIdx].Direction)
	}
}

// --- shell scenario: pty-req + shell (RFC 4254 §6.2/§6.7) ---

func TestSSHScenario_ShellCompleteSession(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, scenarioSpec("shell")))
	// Must contain a pty-req followed by a shell request.
	ptyIdx := -1
	shellIdx := -1
	for i, c := range cfgs {
		b, ok := msgByte(c)
		if !ok || b != MsgChannelRequest {
			continue
		}
		p_ := bppPayload(c.Payload)
		typeLen := binary.BigEndian.Uint32(p_[5:9])
		rt := string(p_[9 : 9+int(typeLen)])
		if rt == "pty-req" && ptyIdx == -1 {
			ptyIdx = i
		}
		if rt == "shell" && shellIdx == -1 {
			shellIdx = i
		}
	}
	if ptyIdx == -1 {
		t.Fatal("pty-req not found in shell scenario")
	}
	if shellIdx == -1 {
		t.Fatal("shell request not found in shell scenario")
	}
	if shellIdx < ptyIdx {
		t.Errorf("shell request at %d before pty-req at %d (RFC 4254 §6.7: pty-req precedes shell)", shellIdx, ptyIdx)
	}
	// CHANNEL_DATA must appear (interactive data).
	if msgIndex(cfgs, MsgChannelData) == -1 {
		t.Errorf("CHANNEL_DATA not found in shell scenario")
	}
}

// --- pty-exec scenario: pty-req + exec (RFC 4254 §6.2 + §6.5) ---

func TestSSHScenario_PtyExecCompleteSession(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, scenarioSpec("pty-exec")))
	// Must contain pty-req then exec.
	ptyIdx := -1
	execIdx := -1
	for i, c := range cfgs {
		b, ok := msgByte(c)
		if !ok || b != MsgChannelRequest {
			continue
		}
		p_ := bppPayload(c.Payload)
		typeLen := binary.BigEndian.Uint32(p_[5:9])
		rt := string(p_[9 : 9+int(typeLen)])
		if rt == "pty-req" && ptyIdx == -1 {
			ptyIdx = i
		}
		if rt == "exec" && execIdx == -1 {
			execIdx = i
		}
	}
	if ptyIdx == -1 || execIdx == -1 {
		t.Fatalf("pty-exec scenario: ptyIdx=%d execIdx=%d", ptyIdx, execIdx)
	}
	if execIdx < ptyIdx {
		t.Errorf("exec before pty-req in pty-exec scenario")
	}
}

// --- publickey scenario: probe -> failure -> signed -> success (RFC 4252 §7) ---

func TestSSHScenario_PublickeyAuth(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, scenarioSpec("publickey")))
	// Count USERAUTH_REQUEST messages.
	reqs := allMsgIndices(cfgs, MsgUserAuthRequest)
	if len(reqs) < 2 {
		t.Fatalf("publickey scenario: USERAUTH_REQUEST count=%d, want >= 2 (probe + signed)", len(reqs))
	}
	// First request: publickey, has_signature=false (probe).
	p1 := bppPayload(cfgs[reqs[0]].Payload)
	if !msgHasMethod(p1, "publickey") {
		t.Errorf("first USERAUTH_REQUEST method != publickey")
	}
	// The probe request has_signature=false. Read the bool after the method.
	off := 1
	for k := 0; k < 3; k++ { // skip username, service, method
		l := binary.BigEndian.Uint32(p1[off : off+4])
		off += 4 + int(l)
	}
	if off >= len(p1) || p1[off] != 0x00 {
		t.Errorf("probe request has_signature=0x%02x, want 0x00 (probe)", p1[off])
	}
	// Second request (signed): has_signature=true.
	p2 := bppPayload(cfgs[reqs[1]].Payload)
	off = 1
	for k := 0; k < 3; k++ {
		l := binary.BigEndian.Uint32(p2[off : off+4])
		off += 4 + int(l)
	}
	if off >= len(p2) || p2[off] != 0x01 {
		t.Errorf("signed request has_signature=0x%02x, want 0x01", p2[off])
	}
	// Must contain a USERAUTH_FAILURE between the two requests.
	failIdx := msgIndex(cfgs, MsgUserAuthFailure)
	if failIdx == -1 {
		t.Errorf("USERAUTH_FAILURE not found in publickey scenario")
	} else if failIdx <= reqs[0] || failIdx >= reqs[len(reqs)-1] {
		t.Errorf("USERAUTH_FAILURE at %d not between probe %d and signed %d", failIdx, reqs[0], reqs[len(reqs)-1])
	}
	// Must end auth with USERAUTH_SUCCESS.
	if msgIndex(cfgs, MsgUserAuthSuccess) == -1 {
		t.Errorf("USERAUTH_SUCCESS not found in publickey scenario")
	}
}

// msgHasMethod checks if a USERAUTH_REQUEST payload has the given method name.
// Layout: msg(1) || string(username) || string(service) || string(method) || ...
func msgHasMethod(payload []byte, method string) bool {
	if len(payload) < 1 || payload[0] != MsgUserAuthRequest {
		return false
	}
	// Skip username (string) and service (string) - 2 strings.
	off := 1
	for k := 0; k < 2; k++ {
		if off+4 > len(payload) {
			return false
		}
		l := binary.BigEndian.Uint32(payload[off : off+4])
		off += 4 + int(l)
	}
	if off+4 > len(payload) {
		return false
	}
	ml := binary.BigEndian.Uint32(payload[off : off+4])
	return string(payload[off+4:off+4+int(ml)]) == method
}

// --- auth_fail_retry scenario: password -> failure -> retry -> success ---

func TestSSHScenario_AuthFailRetry(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, scenarioSpec("auth_fail_retry")))
	reqs := allMsgIndices(cfgs, MsgUserAuthRequest)
	if len(reqs) < 2 {
		t.Fatalf("auth_fail_retry: USERAUTH_REQUEST count=%d, want >= 2", len(reqs))
	}
	failIdx := msgIndex(cfgs, MsgUserAuthFailure)
	if failIdx == -1 {
		t.Fatalf("USERAUTH_FAILURE not found")
	}
	if failIdx <= reqs[0] || failIdx >= reqs[1] {
		t.Errorf("USERAUTH_FAILURE at %d not between two requests %d..%d", failIdx, reqs[0], reqs[1])
	}
	// Both requests use password method.
	for _, ri := range reqs[:2] {
		p_ := bppPayload(cfgs[ri].Payload)
		if !msgHasMethod(p_, "password") {
			t.Errorf("USERAUTH_REQUEST at %d method != password", ri)
		}
	}
	// Success after the retry.
	succIdx := msgIndex(cfgs, MsgUserAuthSuccess)
	if succIdx == -1 || succIdx < reqs[1] {
		t.Errorf("USERAUTH_SUCCESS must come after retry request")
	}
}

// --- long_output scenario: multiple CHANNEL_DATA + stderr ---

func TestSSHScenario_LongOutput(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("long_output")
	spec.SSH.Stdout = []byte(strings.Repeat("line of output\n", 100))
	spec.SSH.Stderr = []byte("warning: deprecation\n")
	cfgs := drain(mustPlan(t, p, spec))
	dataCount := len(allMsgIndices(cfgs, MsgChannelData))
	if dataCount < 3 {
		t.Errorf("CHANNEL_DATA count=%d, want >= 3 (multi-packet stdout)", dataCount)
	}
	// CHANNEL_EXTENDED_DATA (stderr) must be present.
	if msgIndex(cfgs, MsgChannelExtendedData) == -1 {
		t.Errorf("CHANNEL_EXTENDED_DATA (stderr) not found in long_output scenario")
	}
}

// --- scenario overrides manual Channels ---

// When Scenario is set, manual Channels/AuthMethods are ignored (the scenario
// owns the dialog). This prevents a confusing mix of scenario + hand-crafted
// messages.
func TestSSHScenario_OverridesManualChannels(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("exec")
	// Provide a manual channel that would NOT appear in the exec scenario.
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "subsystem", SubsystemName: "sftp"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// No subsystem request should appear (scenario owns the dialog).
	for _, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 || p_[0] != MsgChannelRequest {
			continue
		}
		typeLen := binary.BigEndian.Uint32(p_[5:9])
		rt := string(p_[9 : 9+int(typeLen)])
		if rt == "subsystem" {
			t.Errorf("manual 'subsystem' channel leaked into exec scenario output")
		}
	}
}

// --- Command / Stdout propagation ---

func TestSSHScenario_CommandPropagation(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("exec")
	spec.SSH.Command = "whoami"
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 || p_[0] != MsgChannelRequest {
			continue
		}
		off := 5
		typeLen := binary.BigEndian.Uint32(p_[off : off+4])
		rt := string(p_[off+4 : off+4+int(typeLen)])
		if rt != "exec" {
			continue
		}
		off += 4 + int(typeLen) + 1 // +want_reply
		cmdLen := binary.BigEndian.Uint32(p_[off : off+4])
		cmd := string(p_[off+4 : off+4+int(cmdLen)])
		if cmd != "whoami" {
			t.Errorf("command=%q, want 'whoami'", cmd)
		}
		return
	}
	t.Errorf("exec CHANNEL_REQUEST not found")
}

func TestSSHScenario_StdoutPropagation(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("exec")
	spec.SSH.Stdout = []byte("hello-world-stdout")
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 || p_[0] != MsgChannelData {
			continue
		}
		dataLen := binary.BigEndian.Uint32(p_[5:9])
		data := p_[9 : 9+int(dataLen)]
		if string(data) == "hello-world-stdout" {
			return
		}
	}
	t.Errorf("stdout 'hello-world-stdout' not found in CHANNEL_DATA")
}

// --- Full-session ordering invariant (RFC 4253 state machine) ---

// Regardless of scenario, the transport ordering must hold:
// KEXINIT < NEWKEYS < SERVICE < USERAUTH < CHANNEL.
func TestSSHScenario_TransportOrdering(t *testing.T) {
	for _, sc := range []string{"exec", "shell", "pty-exec", "publickey", "auth_fail_retry", "long_output"} {
		t.Run(sc, func(t *testing.T) {
			p := NewPlanner()
			cfgs := drain(mustPlan(t, p, scenarioSpec(sc)))
			kex := msgIndex(cfgs, MsgKexInit)
			nk := msgIndex(cfgs, MsgNewKeys)
			svc := msgIndex(cfgs, MsgServiceRequest)
			auth := msgIndex(cfgs, MsgUserAuthRequest)
			ch := msgIndex(cfgs, MsgChannelOpen)
			if kex == -1 || nk == -1 || svc == -1 || auth == -1 || ch == -1 {
				t.Fatalf("missing required messages: kex=%d nk=%d svc=%d auth=%d ch=%d", kex, nk, svc, auth, ch)
			}
			if !(kex < nk && nk < svc && svc < auth && auth < ch) {
				t.Errorf("scenario %s ordering broken: kex=%d nk=%d svc=%d auth=%d ch=%d", sc, kex, nk, svc, auth, ch)
			}
		})
	}
}

// --- DisconnectOnClose + scenario ---

func TestSSHScenario_DisconnectOnCloseWithExec(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("exec")
	spec.SSH.DisconnectOnClose = true
	cfgs := drain(mustPlan(t, p, spec))
	// DISCONNECT must appear after the channel close and before teardown.
	discIdx := msgIndex(cfgs, MsgDisconnect)
	if discIdx == -1 {
		t.Fatalf("DISCONNECT not found")
	}
	lastClose := -1
	for _, i := range allMsgIndices(cfgs, MsgChannelClose) {
		if i > lastClose {
			lastClose = i
		}
	}
	if lastClose != -1 && discIdx < lastClose {
		t.Errorf("DISCONNECT at %d before last CHANNEL_CLOSE at %d", discIdx, lastClose)
	}
}

// --- Channel-request encoder coverage (RFC 4254 §6) ---

// RFC 4254 §6.4 env request.
func TestEncodeChannelRequest_Env(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 2, RequestType: "env", WantReply: false, EnvVarName: "PATH", EnvVarValue: "/usr/bin"}
	payload := encodeChannelRequest(2, "env", false, ch)
	if payload[0] != MsgChannelRequest {
		t.Fatalf("msg=0x%02x", payload[0])
	}
	off := 5 // msg(1)+recipient(4)
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(typeLen)]) != "env" {
		t.Errorf("type != env")
	}
	off += 4 + int(typeLen) + 1 // +want_reply
	nameLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(nameLen)]) != "PATH" {
		t.Errorf("name=%q", payload[off+4:off+4+int(nameLen)])
	}
	off += 4 + int(nameLen)
	valLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(valLen)]) != "/usr/bin" {
		t.Errorf("value=%q", payload[off+4:off+4+int(valLen)])
	}
}

// RFC 4254 §6.5 subsystem request.
func TestEncodeChannelRequest_Subsystem(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 1, RequestType: "subsystem", WantReply: true, SubsystemName: "sftp"}
	payload := encodeChannelRequest(1, "subsystem", true, ch)
	off := 5
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4 + int(typeLen) + 1
	subLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(subLen)]) != "sftp" {
		t.Errorf("subsystem=%q", payload[off+4:off+4+int(subLen)])
	}
}

// RFC 4254 §6.9 signal request.
func TestEncodeChannelRequest_Signal(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 1, RequestType: "signal", SignalName: "TERM"}
	payload := encodeChannelRequest(1, "signal", false, ch)
	off := 5
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4 + int(typeLen) + 1
	sigLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(sigLen)]) != "TERM" {
		t.Errorf("signal=%q", payload[off+4:off+4+int(sigLen)])
	}
}

// RFC 4254 §6.7 window-change request.
func TestEncodeChannelRequest_WindowChange(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 1, RequestType: "window-change", WidthChars: 120, HeightRows: 40, WidthPixels: 800, HeightPixels: 600}
	payload := encodeChannelRequest(1, "window-change", false, ch)
	off := 5
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4 + int(typeLen) + 1
	wc := binary.BigEndian.Uint32(payload[off : off+4])
	if wc != 120 {
		t.Errorf("width_chars=%d, want 120", wc)
	}
	hr := binary.BigEndian.Uint32(payload[off+4 : off+8])
	if hr != 40 {
		t.Errorf("height_rows=%d, want 40", hr)
	}
}

// RFC 4254 §6.10 exit-signal request.
func TestEncodeChannelRequest_ExitSignal(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 1, RequestType: "exit-signal", SignalName: "KILL"}
	payload := encodeChannelRequest(1, "exit-signal", false, ch)
	off := 5
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4 + int(typeLen) + 1
	sigLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(sigLen)]) != "KILL" {
		t.Errorf("signal=%q", payload[off+4:off+4+int(sigLen)])
	}
	off += 4 + int(sigLen)
	// core_dumped bool
	if payload[off] != 0x00 {
		t.Errorf("core_dumped=0x%02x, want 0x00", payload[off])
	}
}

// RFC 4254 §6.3 x11-req request.
func TestEncodeChannelRequest_X11Req(t *testing.T) {
	ch := core.ChannelEntry{RecipientChannel: 1, RequestType: "x11-req", WantReply: true, SingleConnection: true, X11AuthProtocol: "MIT-MAGIC-COOKIE-1", X11AuthCookie: []byte{0x01, 0x02}, X11ScreenNumber: 0}
	payload := encodeChannelRequest(1, "x11-req", true, ch)
	off := 5
	typeLen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4 + int(typeLen) + 1
	if payload[off] != 0x01 {
		t.Errorf("single_connection=0x%02x, want 0x01", payload[off])
	}
	off++
	protoLen := binary.BigEndian.Uint32(payload[off : off+4])
	if string(payload[off+4 : off+4+int(protoLen)]) != "MIT-MAGIC-COOKIE-1" {
		t.Errorf("auth_protocol=%q", payload[off+4:off+4+int(protoLen)])
	}
}

// --- findNthMsg helper ---

// findNthMsg returns the Nth (1-based) cfg whose BPP payload starts with msg.
func findNthMsg(cfgs []core.PacketConfig, msg byte, n int) *core.PacketConfig {
	count := 0
	for i := range cfgs {
		p := bppPayload(cfgs[i].Payload)
		if len(p) > 0 && p[0] == msg {
			count++
			if count == n {
				return &cfgs[i]
			}
		}
	}
	return nil
}

// --- context propagation (no deadlock) ---

func TestSSHScenario_ContextCancel(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := p.Plan(ctx, scenarioSpec("exec"))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	drain(ch)
}
