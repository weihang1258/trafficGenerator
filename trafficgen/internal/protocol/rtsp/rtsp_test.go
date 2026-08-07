package rtsp

// RTSP planner tests, derived from /tmp/l7_planner_design/testcases_rtsp.md
// and the reference pcap /home/pcap_auto/mypcap/publicpcap/IPv4/rtsp/proto_rtsp.pcap
// (QuickTime Streaming Server session: DESCRIBE → 200 → SETUP(track5) →
// 200 → SETUP(track6) → 200 → PLAY → 200 → TEARDOWN → 200, CSeq 1-5,
// Session 8d9dea6f8d9deaa8f, RTP-Info ssrc printed as signed int32).
//
// Every test asserts observable wire output (payload text / bytes /
// PacketConfig fields), not just "no error".

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// tcpData returns the PSH-ACK payloads in wire order.
func tcpData(cfgs []core.PacketConfig) []string {
	var out []string
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 {
			out = append(out, string(c.Payload))
		}
	}
	return out
}

// rtspUDP returns the UDP (RTP) packet configs in wire order.
func rtspUDP(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "udp" {
			out = append(out, c)
		}
	}
	return out
}

// headerValueOf extracts the value of the first header with the given
// name (case-insensitive per RFC 2326 §12) from a rendered payload.
func headerValueOf(payload, name string) (string, bool) {
	for _, line := range strings.Split(payload, "\r\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
			return strings.TrimSpace(line[idx+1:]), true
		}
	}
	return "", false
}

// findPayload returns the first PSH-ACK payload containing substr.
func findPayload(payloads []string, substr string) string {
	for _, p := range payloads {
		if strings.Contains(p, substr) {
			return p
		}
	}
	return ""
}

// sessionIDRe matches the reference pcap's Session format: 15 lowercase
// hex digits ("8d9dea6f8d9deaa8f").
var sessionIDRe = regexp.MustCompile(`^[0-9a-f]{15}$`)

// pointPlaybackSpec models the reference QuickTime session: 5 requests,
// 2 tracks, RTP media on 1024/1026. EmitMedia sits on the PLAY response
// so the auto RTP-Info describes the frames that follow.
func pointPlaybackSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "192.168.45.2", DstIP: "192.168.1.27",
		SrcPort: 62020, DstPort: 554,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		RTSP: &core.RTSPConfig{
			Dialog: []core.RTSPMessage{
				{Method: "DESCRIBE"},
				{StatusCode: 200, StatusText: "OK",
					Body: "v=0\r\no=qtss 3695163805 1 IN IP4 192.168.1.27\r\ns=35k_3sec.mov\r\nc=IN IP4 192.168.1.27\r\nt=0 0\r\na=control:*\r\nm=audio 0 RTP/AVP 96\r\na=control:trackID=5\r\nm=video 0 RTP/AVP 97\r\na=control:trackID=6\r\n"},
				{Method: "SETUP", URI: "rtsp://192.168.1.27/35k_3sec.mov/trackID=5"},
				{StatusCode: 200, StatusText: "OK"},
				{Method: "SETUP", URI: "rtsp://192.168.1.27/35k_3sec.mov/trackID=6"},
				{StatusCode: 200, StatusText: "OK"},
				{Method: "PLAY", Headers: []string{"Range: npt=0.000000-3.296670"}},
				{StatusCode: 200, StatusText: "OK", EmitMedia: true},
				{Method: "TEARDOWN"},
				{StatusCode: 200, StatusText: "OK"},
			},
			Media: &core.RTSPMedia{
				SrcPort: 1024, DstPort: 1024,
				Frames: 20, PayloadType: 96,
			},
		},
	}
}

// --- Validate ---

func TestRTSPValidate_Valid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(pointPlaybackSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestRTSPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := pointPlaybackSpec()
	spec.SrcIP = "999.1.1.1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestRTSPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := pointPlaybackSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestRTSPValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := pointPlaybackSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536 (RFC 879)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want MSS error", err)
	}
}

func TestRTSPValidate_EmptyDialog(t *testing.T) {
	p := NewPlanner()
	spec := pointPlaybackSpec()
	spec.RTSP = &core.RTSPConfig{Dialog: nil}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "dialog is required") {
		t.Errorf("err=%v, want 'dialog is required'", err)
	}
}

func TestRTSPValidate_NilRTSPConfig(t *testing.T) {
	p := NewPlanner()
	spec := pointPlaybackSpec()
	spec.RTSP = nil
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "dialog is required") {
		t.Errorf("err=%v, want 'dialog is required' (nil RTSP config means no dialog)", err)
	}
}

// --- CSeq state machine (§12.17, testcases 1.3) ---

func TestRTSPPlan_CSeq_FullSessionSequence(t *testing.T) {
	// testcase 1.3.9: DESCRIBE/200/SETUP/200/SETUP/200/PLAY/200/TEARDOWN/200
	// → CSeq 1,1,2,2,3,3,4,4,5,5 (reference pcap exact values).
	cfgs := mustPlan(t, NewPlanner(), pointPlaybackSpec())
	payloads := tcpData(cfgs)

	expect := []struct{ request, cseq string }{
		{"DESCRIBE", "1"},
		{"SETUP", "2"},
		{"SETUP", "3"},
		{"PLAY", "4"},
		{"TEARDOWN", "5"},
	}
	if len(payloads) != 10 {
		t.Fatalf("got %d signaling messages, want 10", len(payloads))
	}
	for i, e := range expect {
		req := payloads[i*2]
		if !strings.HasPrefix(req, e.request+" ") {
			t.Errorf("message %d: %q, want request line starting %q", i, req, e.request)
		}
		if v, ok := headerValueOf(req, "CSeq"); !ok || v != e.cseq {
			t.Errorf("request %d CSeq=%q (ok=%v), want %q", i, v, ok, e.cseq)
		}
		resp := payloads[i*2+1]
		if v, ok := headerValueOf(resp, "CSeq"); !ok || v != e.cseq {
			t.Errorf("response %d CSeq=%q (ok=%v), want echo %q", i, v, ok, e.cseq)
		}
	}
}

func TestRTSPPlan_CSeq_UserOverrideResyncs(t *testing.T) {
	// testcases 1.3.5-1.3.7: user CSeq:10 → response echoes 10 → next
	// request auto-assigns 11.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE", Headers: []string{"CSeq: 10"}},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "TEARDOWN"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))

	if v, ok := headerValueOf(payloads[0], "CSeq"); !ok || v != "10" {
		t.Errorf("request CSeq=%q, want user value 10", v)
	}
	if v, ok := headerValueOf(payloads[1], "CSeq"); !ok || v != "10" {
		t.Errorf("response CSeq=%q, want echo 10", v)
	}
	if v, ok := headerValueOf(payloads[2], "CSeq"); !ok || v != "11" {
		t.Errorf("second request CSeq=%q, want 11 (counter resumes from user value)", v)
	}
}

func TestRTSPPlan_CSeq_NonNumericUserValue(t *testing.T) {
	// A non-numeric CSeq (e.g. "abc") is echoed verbatim but does not
	// re-sync the counter: the next request keeps incrementing from the
	// untouched counter (0 → 1).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE", Headers: []string{"CSeq: abc"}},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "TEARDOWN"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, _ := headerValueOf(payloads[2], "CSeq"); v != "1" {
		t.Errorf("second request CSeq=%q, want 1 (non-numeric user value ignored for counting)", v)
	}
}

func TestRTSPPlan_CSeq_DialogOpensWithResponse(t *testing.T) {
	// testcase 1.3.8: a dialog whose first message is a response gets the
	// next auto number (1) — no request to echo.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[0], "CSeq"); !ok || v != "1" {
		t.Errorf("opening response CSeq=%q, want 1", v)
	}
}

// --- Session state machine (§12.37, testcases 1.4/3.3) ---

func TestRTSPPlan_Session_IssuedAndEchoed(t *testing.T) {
	// testcases 1.4.1-1.4.4, 3.3.1-3.3.4: Session first appears in the
	// first SETUP response (15 hex digits), then every later request and
	// response carries the same value. DESCRIBE (before any SETUP) has
	// none (1.4.8).
	cfgs := mustPlan(t, NewPlanner(), pointPlaybackSpec())
	payloads := tcpData(cfgs)

	describe := payloads[0]
	if _, ok := headerValueOf(describe, "Session"); ok {
		t.Error("DESCRIBE request must NOT carry Session (session not established yet)")
	}

	setup1Resp := payloads[3]
	sess, ok := headerValueOf(setup1Resp, "Session")
	if !ok {
		t.Fatal("first SETUP response missing Session")
	}
	if !sessionIDRe.MatchString(sess) {
		t.Errorf("Session=%q, want 15 hex digits (reference format)", sess)
	}

	// SETUP#2 request (index 4) and response (5), PLAY (6) and response
	// (7), TEARDOWN (8) and response (9) all echo the same value.
	for _, idx := range []int{4, 5, 6, 7, 8, 9} {
		v, ok := headerValueOf(payloads[idx], "Session")
		if !ok {
			t.Errorf("message %d missing Session", idx)
			continue
		}
		if v != sess {
			t.Errorf("message %d Session=%q, want %q (one session per dialog, §3.3.4)", idx, v, sess)
		}
	}
}

func TestRTSPPlan_Session_UserSuppliedInResponse(t *testing.T) {
	// testcase 1.4.5: a user Session on the response is kept verbatim and
	// becomes the echoed value.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK", Headers: []string{"Session: abc123"}},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[1], "Session"); !ok || v != "abc123" {
		t.Errorf("SETUP response Session=%q, want user value abc123", v)
	}
	if v, ok := headerValueOf(payloads[2], "Session"); !ok || v != "abc123" {
		t.Errorf("PLAY request Session=%q, want echo abc123", v)
	}
}

func TestRTSPPlan_Session_UserSuppliedOnRequestNotGenerated(t *testing.T) {
	// testcase 1.4.6: a user Session on the request is output verbatim
	// (no generation needed).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5", Headers: []string{"Session: xyz"}},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[0], "Session"); !ok || v != "xyz" {
		t.Errorf("SETUP request Session=%q, want user value xyz", v)
	}
}

// --- Transport (§12.39, testcases 1.5) ---

func TestRTSPPlan_Transport_AutoGenerated(t *testing.T) {
	// testcases 1.5.1-1.5.2: SETUP request gets
	// client_port=<DstPort>-<DstPort+1>; the SETUP response adds
	// server_port=<SrcPort>-<SrcPort+1> (reference pcap format).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://192.168.1.27/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[0], "Transport"); !ok || v != "RTP/AVP;unicast;client_port=1024-1025" {
		t.Errorf("SETUP request Transport=%q, want %q", v, "RTP/AVP;unicast;client_port=1024-1025")
	}
	wantResp := "RTP/AVP;unicast;client_port=1024-1025;server_port=1024-1025"
	if v, ok := headerValueOf(payloads[1], "Transport"); !ok || v != wantResp {
		t.Errorf("SETUP response Transport=%q, want %q", v, wantResp)
	}
}

func TestRTSPPlan_Transport_UserOverride(t *testing.T) {
	// testcase 1.5.3: user Transport wins verbatim.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5",
			Headers: []string{"Transport: RTP/AVP/TCP;unicast;interleaved=0-1"}},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[0], "Transport"); !ok || v != "RTP/AVP/TCP;unicast;interleaved=0-1" {
		t.Errorf("SETUP request Transport=%q, want user value", v)
	}
}

func TestRTSPPlan_Transport_NotGeneratedWithoutMedia(t *testing.T) {
	// testcases 1.5.4-1.5.5: Media=nil → no Transport anywhere; non-SETUP
	// requests → no Transport.
	spec := pointPlaybackSpec()
	spec.RTSP.Media = nil
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	for i, p := range payloads {
		if _, ok := headerValueOf(p, "Transport"); ok {
			t.Errorf("message %d has Transport but Media=nil", i)
		}
	}
}

// --- Content-Length / Content-Type (§12.14/§12.19, testcases 1.6) ---

func TestRTSPPlan_ContentLength_AutoAppended(t *testing.T) {
	// testcase 1.6.1: response with SDP body gets Content-Length = len(body)
	// and Content-Type: application/sdp (1.6.5, reference pcap).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: "v=0\r\no=qtss 1 1 IN IP4 1.2.3.4\r\ns=x\r\n"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	body := "v=0\r\no=qtss 1 1 IN IP4 1.2.3.4\r\ns=x\r\n"
	resp := payloads[1]
	if v, ok := headerValueOf(resp, "Content-Length"); !ok || v != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length=%q, want %d", v, len(body))
	}
	if v, ok := headerValueOf(resp, "Content-Type"); !ok || v != "application/sdp" {
		t.Errorf("Content-Type=%q, want application/sdp", v)
	}
}

func TestRTSPPlan_ContentLength_UserSuppliedNotDuplicated(t *testing.T) {
	// testcases 1.6.2-1.6.3: user Content-Length (any case) wins; no
	// second header is appended.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK",
			Headers: []string{"content-length: 362"},
			Body:    "v=0\r\ns=x\r\n"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	resp := payloads[1]
	count := strings.Count(resp, "Content-Length") + strings.Count(resp, "content-length")
	if count != 1 {
		t.Errorf("Content-Length appears %d times, want 1", count)
	}
	if v, ok := headerValueOf(resp, "Content-Length"); !ok || v != "362" {
		t.Errorf("Content-Length=%q, want user value 362", v)
	}
}

func TestRTSPPlan_ContentLength_NoBodyNoHeader(t *testing.T) {
	// testcase 1.6.4: no body → no Content-Length.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "OPTIONS"},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if _, ok := headerValueOf(payloads[1], "Content-Length"); ok {
		t.Error("response without body must not carry Content-Length")
	}
}

func TestRTSPPlan_ContentType_UserOverride(t *testing.T) {
	// testcase 1.6.6: user Content-Type wins (reference kuanguang
	// SET_PARAMETER).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SET_PARAMETER", Body: "test",
			Headers: []string{"Content-Type: application/x-rtsp-udp-packetpair"}},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[0], "Content-Type"); !ok || v != "application/x-rtsp-udp-packetpair" {
		t.Errorf("Content-Type=%q, want user value", v)
	}
}

// --- Request/Status line and URI (testcases 1.1/1.2) ---

func TestRTSPPlan_Methods_AllSupported(t *testing.T) {
	// testcase 1.1.1-1.1.12: every RFC 2326/7826 method renders its own
	// request line. REDIRECT/PLAY_NOTIFY are server-initiated → down
	// (testcases 6.12/6.13).
	methods := []string{"DESCRIBE", "SETUP", "PLAY", "TEARDOWN", "OPTIONS",
		"PAUSE", "GET_PARAMETER", "SET_PARAMETER", "ANNOUNCE", "RECORD"}
	for _, m := range methods {
		spec := pointPlaybackSpec()
		spec.RTSP.Dialog = []core.RTSPMessage{{Method: m}}
		cfgs := mustPlan(t, NewPlanner(), spec)
		payloads := tcpData(cfgs)
		if !strings.HasPrefix(payloads[0], m+" ") {
			t.Errorf("method %s: request line %q", m, payloads[0])
		}
		for _, c := range cfgs {
			if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 && c.Direction != "up" {
				t.Errorf("method %s: direction=%s, want up", m, c.Direction)
			}
		}
	}
	// Server-initiated requests go down.
	for _, m := range []string{"REDIRECT", "PLAY_NOTIFY"} {
		spec := pointPlaybackSpec()
		spec.RTSP.Dialog = []core.RTSPMessage{{Method: m}}
		cfgs := mustPlan(t, NewPlanner(), spec)
		payloads := tcpData(cfgs)
		if !strings.HasPrefix(payloads[0], m+" ") {
			t.Errorf("method %s: request line %q", m, payloads[0])
		}
		found := false
		for _, c := range cfgs {
			if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 && c.Direction == "down" {
				found = true
			}
		}
		if !found {
			t.Errorf("method %s: no down-direction message emitted", m)
		}
	}
}

func TestRTSPPlan_StatusCode_AllSupported(t *testing.T) {
	// testcase 1.2.1-1.2.22: status codes render their status line
	// verbatim; user StatusText wins (1.2.24).
	cases := []struct {
		code int
		want string
	}{
		{200, "RTSP/1.0 200 OK\r\n"},
		{400, "RTSP/1.0 400 Bad Request\r\n"},
		{401, "RTSP/1.0 401 Unauthorized\r\n"},
		{404, "RTSP/1.0 404 Not Found\r\n"},
		{405, "RTSP/1.0 405 Method Not Allowed\r\n"},
		{453, "RTSP/1.0 453 Not Enough Bandwidth\r\n"},
		{454, "RTSP/1.0 454 Session Not Found\r\n"},
		{455, "RTSP/1.0 455 Method Not Valid in This State\r\n"},
		{456, "RTSP/1.0 456 Header Field Not Valid for Resource\r\n"},
		{457, "RTSP/1.0 457 Invalid Range\r\n"},
		{458, "RTSP/1.0 458 Parameter Is Read-Only\r\n"},
		{459, "RTSP/1.0 459 Aggregate Operation Not Allowed\r\n"},
		{460, "RTSP/1.0 460 Only Aggregate Operation Allowed\r\n"},
		{461, "RTSP/1.0 461 Unsupported Transport\r\n"},
		{462, "RTSP/1.0 462 Destination Unreachable\r\n"},
		{463, "RTSP/1.0 463 Key Management Failure\r\n"},
		{500, "RTSP/1.0 500 Internal Server Error\r\n"},
		{501, "RTSP/1.0 501 Not Implemented\r\n"},
		{503, "RTSP/1.0 503 Service Unavailable\r\n"},
		{505, "RTSP/1.0 505 RTSP Version Not Supported\r\n"},
		{551, "RTSP/1.0 551 Option not supported\r\n"},
		{552, "RTSP/1.0 552 Session Parameter Not Supported\r\n"},
	}
	for _, c := range cases {
		spec := pointPlaybackSpec()
		spec.RTSP.Dialog = []core.RTSPMessage{{StatusCode: c.code}}
		payloads := tcpData(mustPlan(t, NewPlanner(), spec))
		if !strings.HasPrefix(payloads[0], c.want) {
			t.Errorf("code %d: got %q, want prefix %q", c.code, payloads[0], c.want)
		}
	}
	// User StatusText wins (testcase 1.2.24).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{StatusCode: 200, StatusText: "Success"}}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[0], "RTSP/1.0 200 Success\r\n") {
		t.Errorf("user status text: got %q", payloads[0])
	}
}

func TestRTSPPlan_URI_AutoGenerated(t *testing.T) {
	// testcases 1.1.13-1.1.17: empty URI → rtsp://<dstIP>/media; IPv6
	// hosts bracketed; user URI verbatim.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{Method: "DESCRIBE"}}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[0], "DESCRIBE rtsp://192.168.1.27/media RTSP/1.0\r\n") {
		t.Errorf("empty URI: got %q, want prefix %q", payloads[0], "DESCRIBE rtsp://192.168.1.27/media RTSP/1.0\r\n")
	}

	spec6 := pointPlaybackSpec()
	spec6.DstIP = "3ffe::4"
	spec6.RTSP.Dialog = []core.RTSPMessage{{Method: "DESCRIBE"}}
	payloads6 := tcpData(mustPlan(t, NewPlanner(), spec6))
	if !strings.HasPrefix(payloads6[0], "DESCRIBE rtsp://[3ffe::4]/media ") {
		t.Errorf("IPv6 empty URI: got %q, want bracketed host", payloads6[0])
	}

	specU := pointPlaybackSpec()
	specU.RTSP.Dialog = []core.RTSPMessage{{Method: "SETUP", URI: "rtsp://host/path/trackID=5"}}
	payloadsU := tcpData(mustPlan(t, NewPlanner(), specU))
	if !strings.HasPrefix(payloadsU[0], "SETUP rtsp://host/path/trackID=5 ") {
		t.Errorf("user URI: got %q, want verbatim", payloadsU[0])
	}
}

// --- Header rendering (testcases 1.7/2.1) ---

func TestRTSPPlan_UserHeaders_OrderAndColonInValue(t *testing.T) {
	// testcases 1.7.1-1.7.5: user headers keep their order, appended after
	// auto headers; a colon in the value is not truncated.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE", Headers: []string{
			"User-Agent: -- None --",
			"Accept: application/sdp",
			"Accept-Language: en-US",
		}},
		{Method: "PLAY", Headers: []string{"Range: npt=0.000000-3.296670"}},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	describe := payloads[0]
	if !strings.Contains(describe, "User-Agent: -- None --\r\nAccept: application/sdp\r\nAccept-Language: en-US\r\n") {
		t.Errorf("user header order not preserved: %q", describe)
	}
	// Auto headers (CSeq) precede the user headers, which keep their
	// order after them (testcase 1.7.5; reference pcap CSeq is first).
	if strings.Index(describe, "CSeq: 1") > strings.Index(describe, "User-Agent") {
		t.Errorf("auto CSeq must precede user headers: %q", describe)
	}
	// Colon in Range value survives (testcase 1.7.4).
	play := payloads[1]
	if !strings.Contains(play, "Range: npt=0.000000-3.296670\r\n") {
		t.Errorf("Range header value truncated: %q", play)
	}
}

func TestRTSPPlan_CRLF_Only(t *testing.T) {
	// testcase 2.1.2: no bare LF in any signaling payload.
	cfgs := mustPlan(t, NewPlanner(), pointPlaybackSpec())
	for i, p := range tcpData(cfgs) {
		if strings.Contains(p, "\n") && !strings.Contains(p, "\r\n") {
			t.Errorf("payload %d contains bare LF", i)
		}
		if strings.Contains(strings.ReplaceAll(p, "\r\n", ""), "\n") {
			t.Errorf("payload %d contains bare LF", i)
		}
	}
}

func TestRTSPPlan_Body_VerbatimWithCRLF(t *testing.T) {
	// testcases 1.8.1/2.2.1-2.2.2: body bytes output verbatim after the
	// blank line; SDP lines CRLF-terminated.
	body := "v=0\r\no=qtss 3695163805 1 IN IP4 192.168.1.27\r\ns=35k_3sec.mov\r\n"
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: body},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasSuffix(payloads[1], "\r\n"+body) {
		t.Errorf("body not verbatim after blank line: %q", payloads[1])
	}
}

// --- Business scenarios (testcases 4.x) ---

func TestRTSPPlan_PointPlayback_MessageCountAndOrder(t *testing.T) {
	// testcase 4.1.1: 10 signaling messages in reference order; TCP
	// handshake before, teardown after.
	cfgs := mustPlan(t, NewPlanner(), pointPlaybackSpec())
	payloads := tcpData(cfgs)
	if len(payloads) != 10 {
		t.Fatalf("got %d signaling messages, want 10", len(payloads))
	}
	wantOrder := []string{"DESCRIBE", "200", "SETUP", "200", "SETUP", "200", "PLAY", "200", "TEARDOWN", "200"}
	for i, w := range wantOrder {
		if w == "200" {
			if !strings.HasPrefix(payloads[i], "RTSP/1.0 200 ") {
				t.Errorf("message %d: %q, want status line", i, payloads[i])
			}
		} else if !strings.HasPrefix(payloads[i], w+" ") {
			t.Errorf("message %d: %q, want %q request", i, payloads[i], w)
		}
	}
	// Wire order: handshake packets come before all data, teardown after.
	var flags []uint8
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			flags = append(flags, c.L4.Flags)
		}
	}
	// 3 handshake + 10 data + 4 teardown = 17 TCP packets.
	if len(flags) != 17 {
		t.Fatalf("got %d TCP packets, want 17", len(flags))
	}
	if flags[0] != 0x02 || flags[1] != 0x12 || flags[2] != 0x10 {
		t.Errorf("handshake flags=%v, want SYN/SYN-ACK/ACK (3.1.1)", flags[:3])
	}
	if flags[13] != 0x11 || flags[14] != 0x10 || flags[15] != 0x11 || flags[16] != 0x10 {
		t.Errorf("teardown flags=%v, want FIN/ACK/FIN/ACK (3.1.5)", flags[13:])
	}
}

func TestRTSPPlan_LiveSession_OPTIONS(t *testing.T) {
	// testcases 4.3.1-4.3.2: live session opens with OPTIONS; its 200 has
	// no Session and no Content-Length.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "OPTIONS"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: "v=0\r\ns=x\r\n"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[0], "OPTIONS ") {
		t.Errorf("first message: %q", payloads[0])
	}
	if _, ok := headerValueOf(payloads[1], "Session"); ok {
		t.Error("OPTIONS 200 must not carry Session")
	}
	if _, ok := headerValueOf(payloads[1], "Content-Length"); ok {
		t.Error("OPTIONS 200 (no body) must not carry Content-Length")
	}
}

func TestRTSPPlan_PauseResume_SecondEmit(t *testing.T) {
	// testcase 4.4.1: PAUSE carries Session; a second PLAY response with
	// EmitMedia emits a second RTP burst.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
		{Method: "PAUSE"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
	}
	spec.RTSP.Media = &core.RTSPMedia{SrcPort: 1024, DstPort: 1024, Frames: 3, PayloadType: 96}
	cfgs := mustPlan(t, NewPlanner(), spec)
	payloads := tcpData(cfgs)
	if v, ok := headerValueOf(payloads[4], "Session"); !ok || v == "" {
		t.Errorf("PAUSE request must carry Session, got %q", v)
	}
	udp := rtspUDP(cfgs)
	if len(udp) != 6 {
		t.Errorf("got %d RTP frames, want 6 (two bursts of 3)", len(udp))
	}
	// RTP-Info of the second PLAY response describes the continued stream:
	// its seq continues from the first burst.
	info1, _ := headerValueOf(payloads[3], "RTP-Info")
	info2, _ := headerValueOf(payloads[7], "RTP-Info")
	if info1 == "" || info2 == "" {
		t.Fatalf("both PLAY responses must carry RTP-Info, got %q / %q", info1, info2)
	}
	seq1 := rtpInfoParam(info1, "seq")
	seq2 := rtpInfoParam(info2, "seq")
	if seq2 != seq1+3 {
		t.Errorf("second RTP-Info seq=%d, want first seq %d + 3 frames", seq2, seq1)
	}
}

func TestRTSPPlan_GetParameter_Session(t *testing.T) {
	// testcase 4.5.1: GET_PARAMETER mid-session carries the Session.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "GET_PARAMETER"},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[2], "Session"); !ok || v == "" {
		t.Errorf("GET_PARAMETER request must carry Session, got %q", v)
	}
}

func TestRTSPPlan_WMS_SetParameterContentType(t *testing.T) {
	// testcase 4.6.1: SET_PARAMETER carries the user's packetpair
	// Content-Type (kuanguang reference).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "SETUP", URI: "rtsp://host/wmv/rtx"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "SET_PARAMETER", Headers: []string{"Content-Type: application/x-rtsp-udp-packetpair"}},
		{StatusCode: 200, StatusText: "OK"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[2], "SETUP rtsp://host/wmv/rtx ") {
		t.Errorf("SETUP rtx URI: %q", payloads[2])
	}
	if v, ok := headerValueOf(payloads[4], "Content-Type"); !ok || v != "application/x-rtsp-udp-packetpair" {
		t.Errorf("SET_PARAMETER Content-Type=%q", v)
	}
}

func TestRTSPPlan_IPv6_Session(t *testing.T) {
	// testcases 4.7.1-4.7.2: IPv6 signaling with bracketed URI host; RTP
	// sub-flow over IPv6 (EtherType 0x86DD).
	spec := pointPlaybackSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "3ffe::4"
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "SETUP", URI: "rtsp://[3ffe::4]/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
	}
	spec.RTSP.Media = &core.RTSPMedia{SrcPort: 1024, DstPort: 1024, Frames: 2, PayloadType: 96}
	cfgs := mustPlan(t, NewPlanner(), spec)
	payloads := tcpData(cfgs)
	if !strings.HasPrefix(payloads[0], "DESCRIBE rtsp://[3ffe::4]/media ") {
		t.Errorf("IPv6 DESCRIBE URI: %q", payloads[0])
	}
	if !strings.HasPrefix(payloads[2], "SETUP rtsp://[3ffe::4]/media/trackID=5 ") {
		t.Errorf("IPv6 SETUP URI: %q", payloads[2])
	}
	udp := rtspUDP(cfgs)
	if len(udp) == 0 {
		t.Fatal("no RTP frames emitted")
	}
	if udp[0].L2.EtherType != 0x86DD {
		t.Errorf("RTP EtherType=%04x, want 0x86DD", udp[0].L2.EtherType)
	}
	if udp[0].L3.SrcIP != "3ffe::4" || udp[0].L3.DstIP != "2001:db8::1" {
		t.Errorf("RTP tuple %s→%s, want server 3ffe::4 → client 2001:db8::1", udp[0].L3.SrcIP, udp[0].L3.DstIP)
	}
}

// --- Edge / boundary cases (testcases 6.x) ---

func TestRTSPPlan_EmptyDialog(t *testing.T) {
	// testcase 6.1: no dialog → Validate rejects with a clear error.
	// Previously this produced a 7-frame TCP-only pcap (handshake+teardown)
	// which looked "successful" but had zero RTSP content — a silent failure
	// that masked misconfigured strategies (see mcp_rtsp.pcap incident).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = nil
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "dialog is required") {
		t.Fatalf("Plan with empty dialog: err=%v, want 'dialog is required'", err)
	}
}

func TestRTSPPlan_AllEmptyMessage(t *testing.T) {
	// testcase 6.2: [{}] → no message emitted, handshake+teardown fine.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(tcpData(cfgs)) != 0 {
		t.Error("empty message must emit no payload")
	}
	if len(cfgs) != 7 {
		t.Errorf("got %d packets, want 7", len(cfgs))
	}
}

func TestRTSPPlan_FirstMessageIsResponse(t *testing.T) {
	// testcase 6.3: dialog opens with a response → status line + CSeq 1.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{StatusCode: 200, StatusText: "OK"}}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if payloads[0] != "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" {
		t.Errorf("opening response: %q", payloads[0])
	}
}

func TestRTSPPlan_InvalidDirection_Skipped(t *testing.T) {
	// testcase 6.4: "sideways" → message skipped (SIP semantics).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE", Direction: "sideways"},
		{Method: "TEARDOWN"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if len(payloads) != 1 || !strings.HasPrefix(payloads[0], "TEARDOWN ") {
		t.Errorf("payloads=%v, want only TEARDOWN", payloads)
	}
}

func TestRTSPPlan_MethodAndStatusCode_MethodWins(t *testing.T) {
	// testcase 6.5: Method + StatusCode both set → request (SIP semantics).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{Method: "PLAY", StatusCode: 200}}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[0], "PLAY ") {
		t.Errorf("got %q, want request line", payloads[0])
	}
}

func TestRTSPPlan_MSS_Minimum536(t *testing.T) {
	// testcase 6.7: MSS=536 segments by 536, valid output.
	spec := pointPlaybackSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: strings.Repeat("a", 1200)},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	segments := 0
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if len(c.Payload) > 536 {
				t.Errorf("segment of %d bytes exceeds MSS 536", len(c.Payload))
			}
			segments++
		}
	}
	if segments < 3 {
		t.Errorf("got %d segments, want >= 3 for 1200-byte body", segments)
	}
}

func TestRTSPPlan_LongBody_SegmentedContiguousSeq(t *testing.T) {
	// testcases 3.1.2/6.6: a long SDP body is split into PSH-ACK
	// segments with contiguous seq numbers.
	spec := pointPlaybackSpec()
	body := "v=0\r\n" + strings.Repeat("a=foo:bar\r\n", 200)
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: body},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	var segs []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 && c.Direction == "down" {
			segs = append(segs, c)
		}
	}
	if len(segs) < 2 {
		t.Fatalf("got %d down segments, want >= 2", len(segs))
	}
	for i := 1; i < len(segs); i++ {
		if segs[i].L4.Seq != segs[i-1].L4.Seq+uint32(len(segs[i-1].Payload)) {
			t.Errorf("segment %d seq=%d, want previous seq %d + %d bytes",
				i, segs[i].L4.Seq, segs[i-1].L4.Seq, len(segs[i-1].Payload))
		}
	}
}

func TestRTSPPlan_EmitMediaWithoutMediaConfig(t *testing.T) {
	// testcase 6.11: EmitMedia=true but Media=nil → no RTP, no panic.
	spec := pointPlaybackSpec()
	spec.RTSP.Media = nil
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "PLAY", EmitMedia: true},
		{StatusCode: 200, StatusText: "OK"},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(rtspUDP(cfgs)) != 0 {
		t.Error("EmitMedia with Media=nil must not emit RTP")
	}
}

func TestRTSPPlan_UserSessionInResponse_EchoedByLaterRequests(t *testing.T) {
	// testcase 6.10: user Session on a response is echoed by later
	// requests even when that response is not the first SETUP response.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK", Headers: []string{"Session: abc"}},
		{Method: "TEARDOWN"},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[2], "Session"); !ok || v != "abc" {
		t.Errorf("TEARDOWN Session=%q, want echo abc", v)
	}
}

func TestRTSPPlan_REDIRECT_ServerInitiated(t *testing.T) {
	// testcase 6.12: REDIRECT without Direction → down (server→client).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{Method: "REDIRECT", URI: "rtsp://new-host/media"}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	found := false
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 {
			if c.Direction != "down" {
				t.Errorf("REDIRECT direction=%s, want down", c.Direction)
			}
			found = true
		}
	}
	if !found {
		t.Error("REDIRECT message not emitted")
	}
}

func TestRTSPPlan_Headers_EmptyString(t *testing.T) {
	// testcase 6.14: a header that is an empty string must not crash;
	// renderer treats it as a blank line (harmless) — assert no panic and
	// the request line still present.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE", Headers: []string{""}},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if !strings.HasPrefix(payloads[0], "DESCRIBE ") {
		t.Errorf("got %q", payloads[0])
	}
}

func TestRTSPPlan_Body_UTF8ContentLength(t *testing.T) {
	// testcase 6.16: Content-Length counts UTF-8 bytes, not runes.
	body := "会话描述" // 12 UTF-8 bytes
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "DESCRIBE"},
		{StatusCode: 200, StatusText: "OK", Body: body},
	}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if v, ok := headerValueOf(payloads[1], "Content-Length"); !ok || v != "12" {
		t.Errorf("Content-Length=%q, want 12 (UTF-8 byte count)", v)
	}
}

// rtpInfoParam extracts a "key=value" parameter from an RTP-Info header
// value, as a float64 (values may be large).
func rtpInfoParam(info, key string) int64 {
	for _, part := range strings.Split(info, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] == key {
			n, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}
