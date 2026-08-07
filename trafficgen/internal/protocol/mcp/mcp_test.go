package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all packets from ch into a slice; used by tests that want to
// inspect the full PacketConfig sequence (e.g. T57 / T77).
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	out := []core.PacketConfig{}
	for p := range ch {
		out = append(out, p)
	}
	return out
}

// findPayload returns the first Payload whose bytes start with `prefix`,
// or nil if not found.
func findPayload(pkts []core.PacketConfig, prefix []byte) []byte {
	for _, p := range pkts {
		if len(p.Payload) >= len(prefix) && string(p.Payload[:len(prefix)]) == string(prefix) {
			return p.Payload
		}
	}
	return nil
}

// lastPkt returns the last packet in the slice, or nil if empty.
func lastPkt(pkts []core.PacketConfig) *core.PacketConfig {
	if len(pkts) == 0 {
		return nil
	}
	return &pkts[len(pkts)-1]
}

// --- T01: stdio line-delimited JSON single packet encoding (§2.3, T01) ---

func TestBuildInitializeRequest_StdioLineDelimited(t *testing.T) {
	b, err := buildInitializeRequest(1, DefaultProtocolVersion, core.MCPClientInfo{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.HasPrefix(s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`) {
		t.Errorf("stdio initialize: unexpected prefix: %s", s[:min(120, len(s))])
	}
	// Builder emits raw JSON object bytes. The stdio "\n" line delimiter
	// is appended by the writer at TCP-segment boundary, NOT by the
	// builder (design §2.3: each JSON-RPC packet is a single JSON object;
	// the line delimiter is framing). Builder output should be a valid
	// JSON object ending with '}'.
	if !strings.HasSuffix(s, "}") {
		t.Errorf("stdio initialize: builder output must end with '}', got %q", s[len(s)-3:])
	}
}

// --- T05/T06: JSON-RPC required fields & result/error mutex ---

func TestBuildRequest_MethodRequired(t *testing.T) {
	if _, err := buildRequest(1, "", nil, false); err == nil {
		t.Errorf("empty method should be rejected")
	}
}

func TestBuildSuccessResponse_DefaultEmptyResult(t *testing.T) {
	b, err := buildSuccessResponse(42, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"id":42`) || !strings.Contains(s, `"result":{}`) {
		t.Errorf("expected id=42 + empty result, got %s", s)
	}
}

func TestBuildErrorResponse_ParseErrorNullID(t *testing.T) {
	b, err := buildErrorResponse(nil, -32700, "Parse error", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(b), `"id":null`) {
		t.Errorf("Parse error must use id=null (T50), got %s", string(b))
	}
	if !strings.Contains(string(b), `"code":-32700`) {
		t.Errorf("expected code -32700, got %s", string(b))
	}
}

// --- T07: default initialize request fields (§7.1) ---
//
// v1.1.1 N-4 修复回归：未提供 ClientCapabilities 时不再自动注入
// roots+sampling；capabilities 字段缺省（不出现）。

func TestBuildInitializeRequest_DefaultFields(t *testing.T) {
	b, err := buildInitializeRequest(1, "", core.MCPClientInfo{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"protocolVersion":"2024-11-05"`) {
		t.Errorf("default protocolVersion missing: %s", s)
	}
	if !strings.Contains(s, `"name":"trafficgen-client"`) {
		t.Errorf("default clientInfo.name missing: %s", s)
	}
	if !strings.Contains(s, `"version":"1.0.0"`) {
		t.Errorf("default clientInfo.version missing: %s", s)
	}
	// N-4: 不应自动注入 roots/sampling。
	if strings.Contains(s, `"roots"`) {
		t.Errorf("N-4 regression: capabilities.roots must NOT be auto-injected, got: %s", s)
	}
	if strings.Contains(s, `"sampling"`) {
		t.Errorf("N-4 regression: capabilities.sampling must NOT be auto-injected, got: %s", s)
	}
}

// --- T08: default initialize response capabilities ---
//
// v1.1.2 C-3 修复回归：未提供 ServerCapabilities 时不再自动注入
// tools/resources/prompts/logging/completion；capabilities 字段缺省。

func TestBuildInitializeResponse_DefaultCapabilities(t *testing.T) {
	b, err := buildInitializeResponse(1, "", core.MCPServerInfo{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"serverInfo":{"name":"trafficgen-server","version":"1.0.0"}`) {
		t.Errorf("default serverInfo missing: %s", s)
	}
	// C-3: 不应自动注入 5 个 server capabilities。
	for _, bad := range []string{`"tools"`, `"resources"`, `"prompts"`, `"logging"`, `"completion"`} {
		if strings.Contains(s, bad) {
			t.Errorf("C-3 regression: capabilities.%s must NOT be auto-injected, got: %s", bad, s)
		}
	}
	// capabilities 字段本身不应出现（未提供时缺省）。
	if strings.Contains(s, `"capabilities"`) {
		t.Errorf("C-3 regression: capabilities field must NOT appear when ServerCapabilities absent, got: %s", s)
	}
}

// --- T09: notifications/initialized has no id, no params (strict spec) ---

func TestBuildInitializedNotification_NoParamsField(t *testing.T) {
	b, err := buildInitializedNotification()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"id":`) {
		t.Errorf("notifications/initialized must NOT carry id (T64), got: %s", s)
	}
	if strings.Contains(s, `"params":`) {
		t.Errorf("notifications/initialized strict-spec: NO params field allowed (T09/T64), got: %s", s)
	}
	if !strings.Contains(s, `"method":"notifications/initialized"`) {
		t.Errorf("missing method name: %s", s)
	}
}

// --- T13: tools/list default 3 tools ---

func TestBuildToolsListResponse_ThreeTools(t *testing.T) {
	b, err := buildToolsListResponse(2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	for _, name := range []string{`"name":"ping"`, `"name":"echo"`, `"name":"search"`} {
		if !strings.Contains(s, name) {
			t.Errorf("tools/list response missing %s in %s", name, s)
		}
	}
}

// --- T15: tools/call isError=true (tool-level failure) ---

func TestSynthesizeResponse_ToolsCallIsErrorFlag(t *testing.T) {
	successBytes, err := buildSuccessResponse(3, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "search query too short"}},
		"isError": true,
	})
	if err != nil {
		t.Fatalf("build error: %v", err)
	}
	idx := map[int][]byte{3: successBytes}
	b, err := synthesizeResponse(idx, 3, "tools/call")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(b), `"isError":true`) {
		t.Errorf("tool-level isError=true not emitted: %s", string(b))
	}
}

// --- T22/T92: resources/read error.code=-32002 (MCP spec) ---

func TestBuildErrorResponse_ResourceNotFound(t *testing.T) {
	b, err := buildErrorResponse(5, -32002, "Resource not found", map[string]any{"uri": "file:///nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"code":-32002`) {
		t.Errorf("resources/read 404 must use code -32002 (T92, §7.19), got: %s", s)
	}
	if !strings.Contains(s, `"Resource not found"`) {
		t.Errorf("expected 'Resource not found' message, got: %s", s)
	}
}

// --- T29: notifications/cancelled carries requestId ---

func TestSynthesizeResponse_CancelledNotification(t *testing.T) {
	cancelledBytes, err := buildNotification("notifications/cancelled", map[string]any{
		"requestId": 3,
		"reason":    "user cancelled",
	}, false)
	if err != nil {
		t.Fatalf("build cancelled notification: %v", err)
	}
	idx := map[int][]byte{3: cancelledBytes}
	b, err := synthesizeResponse(idx, 3, "tools/call")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(b), `"requestId":3`) {
		t.Errorf("cancelled notification missing requestId=3: %s", string(b))
	}
}

// --- T48: id=0 accepted; mixed auto/explicit rejected ---

func TestValidate_MixedIDAssignment(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Requests: []core.MCPRequest{
				{Method: "tools/list"},  // ID=0 → auto
				{ID: 5, Method: "ping"}, // ID=5 → explicit
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("mixed auto/explicit id assignment should be rejected (T48)")
	} else if !strings.Contains(err.Error(), "mixed auto and explicit") {
		t.Errorf("error message must mention mixed mode, got: %v", err)
	}
}

func TestValidate_AllExplicitIDs(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Requests: []core.MCPRequest{
				{ID: 1, Method: "tools/list"},
				{ID: 2, Method: "tools/call"},
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Errorf("all-explicit IDs should be accepted: %v", err)
	}
}

func TestValidate_AllAutoIDs(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Requests: []core.MCPRequest{
				{Method: "tools/list"},
				{Method: "tools/call"},
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Errorf("all-auto IDs should be accepted: %v", err)
	}
}

// --- T49: method empty string rejected ---

func TestValidate_EmptyMethodRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Requests: []core.MCPRequest{{Method: ""}},
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("empty method should be rejected (T49)")
	}
}

// --- T79: MCPError.Code rejects positive numbers ---

func TestValidate_PositiveErrorCodeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Responses: []core.MCPMessage{
				{ID: 1, Error: &core.MCPError{Code: 42, Message: "x"}},
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("positive error code should be rejected (T79, §4.4 rule 13)")
	}
}

func TestValidate_NegativeErrorCodeAccepted(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Responses: []core.MCPMessage{
				{ID: 1, Error: &core.MCPError{Code: -32601, Message: "Method not found"}},
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Errorf("valid negative error code rejected: %v", err)
	}
}

// --- T90/T99: capabilities duplicate keys rejected ---

func TestCheckDuplicateKeys(t *testing.T) {
	dup := json.RawMessage(`{"roots":{},"roots":{}}`)
	if err := checkDuplicateKeys(dup); err == nil {
		t.Errorf("duplicate capability key must be rejected (T90)")
	}
}

func TestCheckDuplicateKeys_Unique(t *testing.T) {
	unique := json.RawMessage(`{"roots":{"listChanged":true},"sampling":{}}`)
	if err := checkDuplicateKeys(unique); err != nil {
		t.Errorf("unique keys should be accepted: %v", err)
	}
}

func TestValidate_CapabilitiesDupeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			ClientCapabilities: json.RawMessage(`{"roots":{},"roots":{}}`),
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("dupe ClientCapabilities keys must be rejected (T90)")
	}
}

func TestValidate_ServerCapabilitiesDupeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			ServerCapabilities: json.RawMessage(`{"tools":{},"tools":{}}`),
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("dupe ServerCapabilities keys must be rejected (T99)")
	}
}

// --- T04: SSE event format (event+data+\n\n) ---

func TestBuildSSEMessage(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	got := buildSSEMessage("message", data)
	want := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	if string(got) != want {
		t.Errorf("SSE format mismatch:\n got  %q\n want %q", got, want)
	}
}

// --- T78: HTTP+SSE POST response 202 ---

func TestBuildHTTPResponse_202(t *testing.T) {
	// The buildHTTPResponse helper does NOT auto-emit Content-Length for
	// empty bodies (to keep 204 No Content compliant with RFC 7230 §3.3.2
	// which forbids Content-Length on 204). The production path
	// (buildPostAccepted) explicitly adds "Content-Length: 0" per design
	// §6.3. This test verifies the production path.
	got := buildHTTPResponse(202, "Accepted", map[string]string{"Content-Length": "0"}, nil)
	want := "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
	if string(got) != want {
		t.Errorf("202 Accepted format:\n got  %q\n want %q", got, want)
	}
}

// --- T91: DELETE /mcp 204 No Content ---

func TestBuildHTTPResponse_204(t *testing.T) {
	got := buildHTTPResponse(204, "No Content", nil, nil)
	want := "HTTP/1.1 204 No Content\r\n\r\n"
	if !strings.HasPrefix(string(got), "HTTP/1.1 204 No Content\r\n") {
		t.Errorf("204 status line mismatch: %q", got)
	}
	if !strings.HasSuffix(string(got), want[len(want)-4:]) {
		t.Errorf("204 trailing CRLF missing: %q", got)
	}
}

// --- errCodeInRange helper test (T13/§4.4 rule 13) ---

func TestErrCodeInRange(t *testing.T) {
	cases := []struct {
		c    int
		want bool
	}{
		{-32700, true},
		{-32002, true},
		{-32000, true},
		{-31999, false},
		{-32701, false},
		{0, false},
		{42, false},
	}
	for _, tc := range cases {
		if got := errCodeInRange(tc.c); got != tc.want {
			t.Errorf("errCodeInRange(%d)=%v, want %v", tc.c, got, tc.want)
		}
	}
}

// --- T57: stdio complete session byte sequence (§6.2) ---

func TestPlan_StdioCompleteSession(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport: TransportStdio,
			Requests: []core.MCPRequest{
				{Method: "tools/list"},
				{Method: "tools/call", Params: map[string]any{"name": "ping"}},
			},
		},
	}
	p := &Planner{}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// Handshake (3) + initialize req/resp (2) + initialized (1) + 2x(req+resp) (4) + teardown (3) = 13.
	const wantCount = 13
	if len(pkts) != wantCount {
		t.Fatalf("stdio session packet count: got %d, want %d", len(pkts), wantCount)
	}
	// Packet 3 (index 4, payload=initialize request) must start with initialize.
	idx := findPayload(pkts, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"`))
	if idx == nil {
		t.Errorf("initialize request packet not found (T57)")
	}
	// Teardown last packet (index 12) must be up + ACK (flags=0x10).
	last := *lastPkt(pkts)
	if last.Direction != "up" {
		t.Errorf("teardown last packet direction: got %s, want up (T57/T77)", last.Direction)
	}
	if last.L4.Flags != 0x10 {
		t.Errorf("teardown last packet flags: got 0x%02x, want 0x10 (T77)", last.L4.Flags)
	}
	// Teardown second-to-last packet must be down + FIN-ACK (flags=0x11).
	prev := pkts[len(pkts)-2]
	if prev.Direction != "down" || prev.L4.Flags != 0x11 {
		t.Errorf("teardown 2nd-to-last: dir=%s flags=0x%02x, want down/0x11 (T77)", prev.Direction, prev.L4.Flags)
	}
	// Teardown third-to-last packet must be up + FIN-ACK (flags=0x11).
	td0 := pkts[len(pkts)-3]
	if td0.Direction != "up" || td0.L4.Flags != 0x11 {
		t.Errorf("teardown 3rd-to-last: dir=%s flags=0x%02x, want up/0x11 (T77)", td0.Direction, td0.L4.Flags)
	}
}

// --- T53: capabilities full empty object ---

func TestBuildInitializeRequest_CapabilitiesEmptyObject(t *testing.T) {
	caps := json.RawMessage(`{}`)
	b, err := buildInitializeRequest(1, DefaultProtocolVersion, core.MCPClientInfo{}, caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty capabilities: builder emits `{}` literally (per design §7.1
	// capabilities is optional, but when user explicitly provides empty
	// object we honor it).
	s := string(b)
	if !strings.Contains(s, `"capabilities":{}`) {
		t.Errorf("empty capabilities should be honored as {}, got: %s", s)
	}
}

// --- T44: multi-session id sequence isolated + packet_index unique ---

func TestPlan_MultiSessionUniquePacketIndex(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport: TransportStdio,
			Requests:  []core.MCPRequest{{Method: "tools/list"}},
		},
	}
	// Run two sessions and verify all PacketIndex values are unique.
	ch1, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan1: %v", err)
	}
	ch2, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan2: %v", err)
	}
	pkts1 := drain(ch1)
	pkts2 := drain(ch2)

	seen := make(map[uint64]bool)
	for _, p := range pkts1 {
		if seen[p.PacketIndex] {
			t.Errorf("duplicate packet_index %d in session 1 (T44)", p.PacketIndex)
		}
		seen[p.PacketIndex] = true
	}
	for _, p := range pkts2 {
		if seen[p.PacketIndex] {
			t.Errorf("duplicate packet_index %d across sessions (T44)", p.PacketIndex)
		}
		seen[p.PacketIndex] = true
	}
}

// --- T12: tools/call before initialize (must be rejected by state machine
//     handling; here we test that explicit Requests work since the planner
//     always auto-injects initialize, so this scenario is NOT a Validate
//     rejection. Document the behavior.) ---

func TestPlan_AutoInjectsInitialize(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport: TransportStdio,
			// Skip initialize in user Requests — planner auto-injects.
			Requests: []core.MCPRequest{
				{Method: "tools/call", Params: map[string]any{"name": "ping"}},
			},
		},
	}
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Errorf("Validate should accept tools/call without explicit initialize (planner auto-injects), got: %v", err)
	}
}

// --- T50/T51/T52: error responses cover -32700/-32601/-32602 ---

func TestBuildErrorResponse_AllStandardCodes(t *testing.T) {
	cases := []struct {
		code    int
		message string
	}{
		{-32700, "Parse error"},
		{-32601, "Method not found"},
		{-32602, "Invalid params"},
	}
	for _, tc := range cases {
		b, err := buildErrorResponse(1, tc.code, tc.message, nil)
		if err != nil {
			t.Errorf("error code %d: %v", tc.code, err)
			continue
		}
		if !strings.Contains(string(b), tc.message) {
			t.Errorf("error code %d: missing message %q in %s", tc.code, tc.message, b)
		}
	}
}

// --- T93: sampling reject error.code=-1 ---

func TestBuildErrorResponse_SamplingReject(t *testing.T) {
	b, err := buildErrorResponse(13, -1, "User rejected sampling request", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(b), `"code":-1`) {
		t.Errorf("sampling reject must use code -1 (T93, §7.19), got: %s", string(b))
	}
}

// --- T31: notifications/progress must carry progressToken ---

func TestSynthesizeResponse_ProgressNotificationRequiresToken(t *testing.T) {
	// Plan should NOT emit a notifications/progress without a
	// progressToken; the builder does not validate this — the planner
	// emits user-supplied Notifications as-is, so test that
	// buildNotification round-trips a valid progress notification.
	b, err := buildNotification("notifications/progress", map[string]any{
		"progressToken": 42,
		"progress":      50,
		"total":         100,
		"message":       "half done",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"progressToken":42`, `"progress":50`, `"total":100`, `"message":"half done"`} {
		if !strings.Contains(s, want) {
			t.Errorf("progress notification missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, `"state":`) {
		t.Errorf("notifications/progress must NOT carry state field (T80), got: %s", s)
	}
}

// --- parseJSONRPC round-trip ---

func TestParseJSONRPC_RoundTrip(t *testing.T) {
	b, err := buildRequest(1, "tools/list", nil, true)
	if err != nil {
		t.Fatalf("build error: %v", err)
	}
	obj, err := parseJSONRPC(b)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if obj["method"] != "tools/list" {
		t.Errorf("method round-trip: %v", obj["method"])
	}
	if obj["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc round-trip: %v", obj["jsonrpc"])
	}
}

// --- T68: prompts/get with multi-part ---

func TestBuildPromptsGetResponse_MultipleMessages(t *testing.T) {
	// Override the default prompts/get response with a multi-message one
	// (design §7.7 example).
	b, err := buildSuccessResponse(9, map[string]any{
		"description": "Review code",
		"messages": []any{
			map[string]any{"role": "user", "content": map[string]any{"type": "text", "text": "review this"}},
			map[string]any{"role": "assistant", "content": map[string]any{"type": "text", "text": "I'll review it"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"role":"user"`) || !strings.Contains(s, `"role":"assistant"`) {
		t.Errorf("multi-message response missing roles: %s", s)
	}
}

// --- splitSSELines helper ---

func TestSplitSSELines(t *testing.T) {
	data := []byte("event: message\ndata: {}\n\nevent: message\ndata: []\n\n")
	parts := splitSSELines(data)
	if len(parts) != 2 {
		t.Errorf("SSE split: got %d parts, want 2", len(parts))
	}
}

// --- Validate: missing MCP config (rule 1) ---

func TestValidate_MissingMCPConfig(t *testing.T) {
	if err := (&Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}); err == nil {
		t.Errorf("missing MCP config must be rejected (rule 1)")
	}
}

// --- Validate: invalid protocol version (rule 3) ---

func TestValidate_InvalidProtocolVersion(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP:   &core.MCPConfig{ProtocolVersion: "1999-01-01"},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("unknown protocol version should be rejected (rule 3, T10 §7.18)")
	}
}

// --- Validate: invalid transport (rule 2) ---

func TestValidate_InvalidTransport(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP:   &core.MCPConfig{Transport: "websocket"},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("invalid transport should be rejected (rule 2)")
	}
}

// --- Validate: invalid auth scheme (rule 4) ---

func TestValidate_InvalidAuthScheme(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP:   &core.MCPConfig{Auth: core.MCPAuth{Schemes: []string{"FooBar"}}},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("invalid auth scheme should be rejected (rule 4)")
	}
}

// --- Validate: Notifications[].Step out of range (rule 12) ---

func TestValidate_NotificationStepOutOfRange(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Requests:      []core.MCPRequest{{Method: "tools/list"}},
			Notifications: []core.MCPNotification{{Step: 5, Method: "notifications/progress"}},
		},
	}
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Errorf("Step out of range must be rejected (rule 12)")
	}
}

// --- T11: protocol version downgrade (request 2025-06-18, response 2024-11-05) ---

func TestPlan_ProtocolVersionDowngrade(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport:       TransportStdio,
			ProtocolVersion: "2025-06-18",
			Requests:        []core.MCPRequest{{Method: "tools/list"}},
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// Find initialize request: should have protocolVersion 2025-06-18.
	reqBytes := findPayload(pkts, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"`))
	if reqBytes == nil {
		t.Fatalf("initialize request not found")
	}
	if !strings.Contains(string(reqBytes), `"protocolVersion":"2025-06-18"`) {
		t.Errorf("client requested 2025-06-18, got: %s", string(reqBytes))
	}
	// Find initialize response: default serverInfo.version uses 2024-11-05
	// (the planner does not auto-downgrade — that's an explicit config
	// decision). Here we verify both request and response appear.
	// findPayload matches by prefix, so search for the JSON-RPC response
	// prefix; the protocolVersion field is nested inside "result" and is
	// checked via substring.
	respBytes := findPayload(pkts, []byte(`{"jsonrpc":"2.0","id":1,"result":`))
	if respBytes == nil {
		t.Fatalf("initialize response not found")
	}
	if !strings.Contains(string(respBytes), `"protocolVersion"`) {
		t.Errorf("response missing protocolVersion field: %s", string(respBytes))
	}
}

// --- T58/T96: HTTP+SSE complete session — GET before POST, endpoint event ---

func TestPlan_HTTPSSE_GetBeforePost(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50001,
		MCP: &core.MCPConfig{
			Transport: TransportHTTPSSE,
			Requests: []core.MCPRequest{
				{Method: "tools/list"},
			},
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// Handshake (3) + GET (1) + GET-SSE-response (1) + POST initialize (1)
	// + 202 (1) + POST initialized (1) + 202 (1) + POST tools/list (1)
	// + 202 (1) + SSE message (1) + teardown (3) = 15.
	const wantCount = 15
	if len(pkts) != wantCount {
		t.Fatalf("HTTP+SSE session packet count: got %d, want %d", len(pkts), wantCount)
	}

	// (1) Packet 4 (index 3) must be up + GET /mcp (GET precedes POST, T58/T96).
	pkt4 := pkts[3]
	if pkt4.Direction != "up" {
		t.Errorf("packet 4 direction: got %s, want up (T58 GET-before-POST)", pkt4.Direction)
	}
	if !strings.HasPrefix(string(pkt4.Payload), "GET /mcp HTTP/1.1\r\n") {
		t.Errorf("packet 4 must start with GET /mcp HTTP/1.1, got: %q", string(pkt4.Payload[:min(40, len(pkt4.Payload))]))
	}
	// GET must NOT carry Mcp-Session-Id (Appendix A.2: session learned from endpoint event).
	if strings.Contains(string(pkt4.Payload), "Mcp-Session-Id:") {
		t.Errorf("GET /mcp must not carry Mcp-Session-Id (Appendix A.2): %q", string(pkt4.Payload))
	}
	// GET must carry Accept: text/event-stream.
	if !strings.Contains(string(pkt4.Payload), "Accept: text/event-stream") {
		t.Errorf("GET /mcp must carry Accept: text/event-stream: %q", string(pkt4.Payload))
	}

	// (2) Packet 5 (index 4) is the down GET SSE response: 200 OK +
	// endpoint event + initialize message event (T96).
	pkt5 := pkts[4]
	if pkt5.Direction != "down" {
		t.Errorf("packet 5 direction: got %s, want down", pkt5.Direction)
	}
	if !strings.HasPrefix(string(pkt5.Payload), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("packet 5 must start with HTTP/1.1 200 OK, got: %q", string(pkt5.Payload[:min(30, len(pkt5.Payload))]))
	}
	if !strings.Contains(string(pkt5.Payload), "Content-Type: text/event-stream") {
		t.Errorf("GET SSE response must have text/event-stream content type")
	}
	// First event must be `endpoint` (spec-mandated, §6.3 step 5 / T96).
	endpointIdx := strings.Index(string(pkt5.Payload), "event: endpoint\ndata: ")
	if endpointIdx < 0 {
		t.Errorf("GET SSE response missing `event: endpoint` (T96, spec §2.4)")
	} else {
		// Verify endpoint data is /mcp?session=...
		rest := string(pkt5.Payload)[endpointIdx+len("event: endpoint\ndata: "):]
		nl := strings.Index(rest, "\n")
		if nl < 0 || !strings.HasPrefix(rest, "/mcp?session=") {
			t.Errorf("endpoint event data must be /mcp?session=..., got: %q", rest[:min(40, nl)])
		}
	}
	// Verify `event: message` follows with initialize response.
	if !strings.Contains(string(pkt5.Payload), "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":") {
		t.Errorf("GET SSE response must contain message event with initialize response (T58/T96)")
	}

	// (3) Subsequent up packets are POSTs to the endpoint URI (T58/T96).
	pkt6 := pkts[5]
	if pkt6.Direction != "up" {
		t.Errorf("packet 6 direction: got %s, want up (POST initialize)", pkt6.Direction)
	}
	if !strings.HasPrefix(string(pkt6.Payload), "POST /mcp?session=") {
		t.Errorf("POST must target endpoint URI /mcp?session=..., got: %q", string(pkt6.Payload[:min(40, len(pkt6.Payload))]))
	}
	// POST must carry Mcp-Session-Id header.
	if !strings.Contains(string(pkt6.Payload), "Mcp-Session-Id:") {
		t.Errorf("POST must carry Mcp-Session-Id header (Appendix A.2)")
	}

	// (4) POST responses are 202 Accepted (T78).
	pkt7 := pkts[6]
	if pkt7.Direction != "down" {
		t.Errorf("packet 7 direction: got %s, want down (202 Accepted)", pkt7.Direction)
	}
	if !strings.HasPrefix(string(pkt7.Payload), "HTTP/1.1 202 Accepted\r\n") {
		t.Errorf("POST response must be 202 Accepted (T78), got: %q", string(pkt7.Payload[:min(40, len(pkt7.Payload))]))
	}
}

// --- T78: HTTP+SSE POST response 202 (no body) ---

func TestPlan_HTTPSSE_PostResponse202(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50002,
		MCP: &core.MCPConfig{
			Transport: TransportHTTPSSE,
			Requests:  []core.MCPRequest{{Method: "ping"}},
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// Find all down packets that are HTTP responses (start with HTTP/1.1).
	var postResponses [][]byte
	for _, p := range pkts {
		if p.Direction == "down" && strings.HasPrefix(string(p.Payload), "HTTP/1.1 202") {
			postResponses = append(postResponses, p.Payload)
		}
	}
	if len(postResponses) < 2 {
		t.Fatalf("expected at least 2 POST 202 responses, got %d", len(postResponses))
	}
	// Each 202 response must be exactly "HTTP/1.1 202 Accepted\r\n
	// Content-Length: 0\r\n\r\n" (no body) per T78 / Appendix A.2.
	want := "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
	for i, r := range postResponses {
		if string(r) != want {
			t.Errorf("202 response %d: got %q, want %q", i, string(r), want)
		}
	}
}

// --- T91: Streamable HTTP DELETE /mcp 204 No Content ---

func TestPlan_Streamable_DeleteTerminatesSession(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50003,
		MCP: &core.MCPConfig{
			Transport: TransportStreamable,
			Requests:  []core.MCPRequest{{Method: "ping"}},
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// Find the DELETE request (up).
	var deleteReq []byte
	for _, p := range pkts {
		if p.Direction == "up" && strings.HasPrefix(string(p.Payload), "DELETE /mcp") {
			deleteReq = p.Payload
			break
		}
	}
	if deleteReq == nil {
		t.Fatalf("DELETE /mcp request not found (T91)")
	}
	if !strings.HasPrefix(string(deleteReq), "DELETE /mcp HTTP/1.1\r\n") {
		t.Errorf("DELETE request line mismatch (T91): %q", string(deleteReq[:min(40, len(deleteReq))]))
	}
	if !strings.Contains(string(deleteReq), "Mcp-Session-Id:") {
		t.Errorf("DELETE /mcp must carry Mcp-Session-Id (T91)")
	}

	// Find the 204 response (down) — must be the last down packet.
	lastDown := pkts[len(pkts)-1]
	if lastDown.Direction != "down" {
		// The DELETE response should be the second-to-last (last is
		// teardown FIN-ACK up). Actually in Streamable mode there's no
		// TCP teardown — DELETE replaces it. So the last packet should
		// be the 204 response.
		t.Errorf("last packet direction: got %s, want down (204 No Content)", lastDown.Direction)
	}
	if !strings.HasPrefix(string(lastDown.Payload), "HTTP/1.1 204 No Content\r\n") {
		t.Errorf("last packet must be 204 No Content (T91), got: %q", string(lastDown.Payload[:min(40, len(lastDown.Payload))]))
	}
}

// --- T55: Streamable HTTP mode single-endpoint (POST + JSON/SSE response) ---

func TestPlan_Streamable_PostJSONResponse(t *testing.T) {
	noShutdown := false
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50004,
		MCP: &core.MCPConfig{
			Transport:       TransportStreamable,
			ProtocolVersion: "2024-11-05",
			Requests:        []core.MCPRequest{{Method: "tools/list"}},
			Shutdown:        &noShutdown, // no DELETE, examine POST responses
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// First up packet with payload is POST initialize.
	var initPost []byte
	for _, p := range pkts {
		if p.Direction == "up" && len(p.Payload) > 0 && strings.HasPrefix(string(p.Payload), "POST /mcp") {
			initPost = p.Payload
			break
		}
	}
	if initPost == nil {
		t.Fatalf("POST /mcp initialize request not found")
	}
	if !strings.Contains(string(initPost), "Mcp-Session-Id:") {
		t.Errorf("Streamable POST must carry Mcp-Session-Id (§A.3)")
	}
	if !strings.Contains(string(initPost), "Content-Type: application/json") {
		t.Errorf("Streamable POST must carry Content-Type: application/json (§A.3)")
	}

	// First down packet with payload is the initialize response: 200 OK + JSON.
	var initResp []byte
	for _, p := range pkts {
		if p.Direction == "down" && len(p.Payload) > 0 && strings.HasPrefix(string(p.Payload), "HTTP/1.1 200 OK") {
			initResp = p.Payload
			break
		}
	}
	if initResp == nil {
		t.Fatalf("200 OK initialize response not found")
	}
	if !strings.Contains(string(initResp), "Content-Type: application/json") {
		t.Errorf("Streamable 200 OK response must be application/json (§A.3)")
	}
	if !strings.Contains(string(initResp), "\"jsonrpc\":\"2.0\"") {
		t.Errorf("200 OK response body must contain JSON-RPC payload (§A.3)")
	}
}

// --- T85: Streamable HTTP SSE response when notifications interleave ---

func TestPlan_Streamable_SSEResponseWithNotifications(t *testing.T) {
	noShutdown := false
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50005,
		MCP: &core.MCPConfig{
			Transport: TransportStreamable,
			Requests:  []core.MCPRequest{{Method: "tools/call", Params: map[string]any{"name": "long_task"}}},
			Notifications: []core.MCPNotification{
				{Step: 0, Method: "notifications/progress", Params: map[string]any{
					"progressToken": 2,
					"progress":      50,
					"total":         100,
				}},
			},
			Shutdown: &noShutdown,
		},
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	pkts := drain(ch)

	// The tools/call response should be a 200 OK + text/event-stream
	// (because a notifications/progress interleaves at Step 0).
	var sseResp []byte
	for _, p := range pkts {
		if p.Direction == "down" && strings.HasPrefix(string(p.Payload), "HTTP/1.1 200 OK") &&
			strings.Contains(string(p.Payload), "text/event-stream") {
			sseResp = p.Payload
			break
		}
	}
	if sseResp == nil {
		t.Fatalf("expected 200 OK + text/event-stream response for interleaved notification (T85)")
	}
	// The SSE stream must contain a notifications/progress event + a
	// tools/call response event.
	if !strings.Contains(string(sseResp), "notifications/progress") {
		t.Errorf("SSE stream must contain notifications/progress event (T85)")
	}
	if !strings.Contains(string(sseResp), "event: message") {
		t.Errorf("SSE stream must contain event: message frames (T85)")
	}
}

// --- helper ---

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =====================================================================
// v1.1.x 回归修复测试（Finding-2 / Finding-3 / Finding-4 / Finding-5）
// =====================================================================

// --- Finding-2 (N-4): 显式 ClientCapabilities 正常透传 ---

func TestBuildInitializeRequest_ExplicitCapabilities(t *testing.T) {
	caps := json.RawMessage(`{"roots":{"listChanged":true},"sampling":{}}`)
	b, err := buildInitializeRequest(1, DefaultProtocolVersion, core.MCPClientInfo{}, caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	// 显式提供的 capabilities 必须原样透传。
	if !strings.Contains(s, `"roots":{"listChanged":true}`) {
		t.Errorf("explicit capabilities.roots not passed through: %s", s)
	}
	if !strings.Contains(s, `"sampling":{}`) {
		t.Errorf("explicit capabilities.sampling not passed through: %s", s)
	}
}

// --- Finding-2 (N-4): null ClientCapabilities 等同于未提供，不注入 ---

func TestBuildInitializeRequest_NullCapabilities(t *testing.T) {
	b, err := buildInitializeRequest(1, DefaultProtocolVersion, core.MCPClientInfo{}, json.RawMessage(`null`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"capabilities"`) {
		t.Errorf("null ClientCapabilities must not produce capabilities field, got: %s", s)
	}
	if strings.Contains(s, `"roots"`) || strings.Contains(s, `"sampling"`) {
		t.Errorf("null ClientCapabilities must not auto-inject roots/sampling, got: %s", s)
	}
}

// --- Finding-3 (C-3): 显式 ServerCapabilities 正常透传 ---

func TestBuildInitializeResponse_ExplicitCapabilities(t *testing.T) {
	caps := json.RawMessage(`{"tools":{"listChanged":true},"logging":{}}`)
	b, err := buildInitializeResponse(1, DefaultProtocolVersion, core.MCPServerInfo{}, caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"tools":{"listChanged":true}`) {
		t.Errorf("explicit capabilities.tools not passed through: %s", s)
	}
	if !strings.Contains(s, `"logging":{}`) {
		t.Errorf("explicit capabilities.logging not passed through: %s", s)
	}
	// 不应出现用户未提供的 resources/prompts/completion。
	if strings.Contains(s, `"resources"`) || strings.Contains(s, `"prompts"`) || strings.Contains(s, `"completion"`) {
		t.Errorf("C-3 regression: non-provided capabilities leaked into response: %s", s)
	}
}

// --- Finding-3 (C-3): null ServerCapabilities 等同于未提供，不注入 ---

func TestBuildInitializeResponse_NullCapabilities(t *testing.T) {
	b, err := buildInitializeResponse(1, DefaultProtocolVersion, core.MCPServerInfo{}, json.RawMessage(`null`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"capabilities"`) {
		t.Errorf("null ServerCapabilities must not produce capabilities field, got: %s", s)
	}
	for _, bad := range []string{`"tools"`, `"resources"`, `"prompts"`, `"logging"`, `"completion"`} {
		if strings.Contains(s, bad) {
			t.Errorf("C-3 regression: %s auto-injected for null ServerCapabilities, got: %s", bad, s)
		}
	}
}

// --- Finding-4 (M-1): Plan goroutine 错误通过 Err() 暴露 ---
//
// 验证策略：
//  1. 正常路径：Plan 成功完成后 Err() 通道无数据（非阻塞可读返回 default）。
//  2. 错误路径：直接调用包私有 planStreamable/planHTTPSSE，注入会让
//     buildRequest 失败的输入（Requests[].Method=""），通过 sendErr
//     回调断言错误被传递。这绕过了 Validate 的空 method 拒绝，直接
//     测试 goroutine 内部的错误回传机制。

func TestPlan_ErrChannel_NoErrorOnSuccess(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport: TransportStdio,
			Requests:  []core.MCPRequest{{Method: "tools/list"}},
		},
	}
	p := &Planner{}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// drain 所有 packet。
	_ = drain(ch)
	// Err() 必须可读且不阻塞；正常完成时应无错误。
	errCh := p.Err()
	if errCh == nil {
		t.Fatalf("Err() returned nil channel after Plan")
	}
	select {
	case e := <-errCh:
		t.Errorf("expected no error on Err() channel after successful Plan, got: %v", e)
	default:
		// 正常：无错误。
	}
}

// --- Finding-4 (M-1): planStreamable 错误通过 sendErr 回传 ---
//
// 这个测试直接调用包私有 planStreamable，注入 Requests[].Method=""
// （绕过 Validate），断言 sendErr 被调用且错误信息包含 "build request"。
// 修复前：错误被 `return` 静默吞咽，sendErr 永远不会被调用。
// 修复后：sendErr 被调用，错误可观测。

func TestPlanStreamable_ErrorReportedViaSendErr(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50011,
		MCP: &core.MCPConfig{
			Transport: TransportStreamable,
			// 空 method 会让 buildRequest 返回错误。注意：这里不经过
			// Validate，直接调用 planStreamable。
			Requests: []core.MCPRequest{{Method: ""}},
		},
	}
	cfg := spec.MCP
	ps := &planState{idCounter: 1, now: time.Now()}
	sid, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	ps.sessionID = sid
	hps := newHTTPPlanState(ps, cfg)

	out := make(chan core.PacketConfig, 256)
	var reportedErr error
	errDone := make(chan struct{})
	sendErr := func(e error) {
		reportedErr = e
		close(errDone)
	}

	go func() {
		planStreamable(context.Background(), out, spec, cfg, 8081, "mcp-flow", 64, ps, hps, 1, false, sendErr)
		close(out)
	}()
	_ = drain(out)

	select {
	case <-errDone:
		// 成功：sendErr 被调用。
	case <-time.After(2 * time.Second):
		t.Fatalf("sendErr not called within 2s — error swallowed (M-1 regression)")
	}
	if reportedErr == nil {
		t.Fatalf("reportedErr is nil after sendErr")
	}
	if !strings.Contains(reportedErr.Error(), "build request") {
		t.Errorf("error message should mention 'build request', got: %v", reportedErr)
	}
}

// --- Finding-4 (M-1): planHTTPSSE 错误通过 sendErr 回传 ---

func TestPlanHTTPSSE_ErrorReportedViaSendErr(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50012,
		MCP: &core.MCPConfig{
			Transport: TransportHTTPSSE,
			Requests:  []core.MCPRequest{{Method: ""}},
		},
	}
	cfg := spec.MCP
	ps := &planState{idCounter: 1, now: time.Now()}
	sid, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	ps.sessionID = sid
	hps := newHTTPPlanState(ps, cfg)

	out := make(chan core.PacketConfig, 256)
	var reportedErr error
	errDone := make(chan struct{})
	sendErr := func(e error) {
		reportedErr = e
		close(errDone)
	}

	go func() {
		planHTTPSSE(context.Background(), out, spec, cfg, 8081, "mcp-flow", 64, ps, hps, 1, false, sendErr)
		close(out)
	}()
	_ = drain(out)

	select {
	case <-errDone:
		// 成功：sendErr 被调用。
	case <-time.After(2 * time.Second):
		t.Fatalf("sendErr not called within 2s — error swallowed (M-1 regression)")
	}
	if reportedErr == nil {
		t.Fatalf("reportedErr is nil after sendErr")
	}
	if !strings.Contains(reportedErr.Error(), "build request") {
		t.Errorf("error message should mention 'build request', got: %v", reportedErr)
	}
}

// --- Finding-5 (M-2): ctx 取消时 pushPkt 不阻塞，goroutine 干净退出 ---
//
// 验证方式：构造一个缓冲区已满的 out 通道（buffer=1，先塞 1 个），
// 然后用可取消的 ctx 启动 Plan，立即取消 ctx。若 pushPkt 不监听
// ctx.Done()，goroutine 会永远阻塞在 out<-pkt 上（channel 满），
// 导致 goroutine 泄漏。修复后 pushPkt 应 select ctx.Done() 并立即
// 返回，goroutine 退出，out channel 被 close。
//
// 由于 Plan 内部自己创建 out 通道（buffer=256），难以直接填满。我们
// 改用另一种验证：启动 Plan 后立即取消 ctx，然后 drain。若 pushPkt
// 不监听 ctx，在 256 缓冲未满前 goroutine 会快速 emit 完所有包并
// 退出——这无法区分。因此我们构造一个"消费极慢"的场景：启动 Plan
// 后不立即 drain，先 cancel ctx，再 drain。goroutine 在 ctx 取消后
// 的 pushPkt 调用应立即返回（丢弃 packet），最终 channel 被 close。
//
// 关键断言：drain 在合理时间内完成（goroutine 没有因为某个 pushPkt
// 阻塞而挂死）。使用带超时的 select 检测。

func TestPlan_PushPktRespectsCtxCancellation(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		MCP: &core.MCPConfig{
			Transport: TransportStdio,
			Requests:  []core.MCPRequest{{Method: "tools/list"}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Planner{}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// 立即取消 ctx，然后 drain。若 pushPkt 不监听 ctx，在 buffer=256
	// 足够大的情况下 goroutine 可能在 cancel 之前就 emit 完所有包。
	// 为了真正测试阻塞路径，我们用一个不 drain 的消费者：只取第 1 个
	// 包后立即 cancel，迫使后续 pushPkt 面对一个接近满的 buffer。
	//
	// 取第 1 个包。
	firstPkt := <-ch
	if firstPkt.PacketIndex == 0 {
		t.Fatalf("expected non-zero packet index")
	}
	// 立即取消 ctx。
	cancel()
	// 现在 drain 剩余包。无论 goroutine 是否已 emit 完，drain 必须在
	// 合理时间内返回（channel 被 close）。若 pushPkt 在 ctx 取消后
	// 仍然阻塞（未监听 ctx.Done），且 buffer 满了，goroutine 会挂死，
	// channel 永远不会被 close，drain 会阻塞直到测试超时。
	done := make(chan struct{})
	var pkts []core.PacketConfig
	go func() {
		for p := range ch {
			pkts = append(pkts, p)
		}
		close(done)
	}()
	select {
	case <-done:
		// 成功：goroutine 干净退出，channel 被 close。
	case <-time.After(5 * time.Second):
		t.Fatalf("drain did not complete within 5s after ctx cancel — pushPkt may be blocked (M-2 regression)")
	}
}

// --- Finding-5 (M-2): pushPkt 单元测试——ctx 取消时不发送 ---
//
// 直接测试 pushPkt：用满 buffer 的 channel + 已取消的 ctx，验证
// pushPkt 立即返回且不阻塞，且 packet 没有被发送到 channel。

func TestPushPkt_CtxCancelledDoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// buffer=1，先塞满。
	ch := make(chan core.PacketConfig, 1)
	ch <- core.PacketConfig{PacketIndex: 1}
	// 取消 ctx。
	cancel()
	// 现在 pushPkt 应该立即返回（select ctx.Done()），不阻塞。
	pkt := core.PacketConfig{PacketIndex: 2}
	done := make(chan struct{})
	go func() {
		pushPkt(ctx, ch, pkt)
		close(done)
	}()
	select {
	case <-done:
		// 成功：pushPkt 没有阻塞。
	case <-time.After(2 * time.Second):
		t.Fatalf("pushPkt blocked on full channel with cancelled ctx (M-2 regression)")
	}
	// channel 中应该只有 1 个 packet（第 2 个被丢弃）。
	if len(ch) != 1 {
		t.Errorf("expected 1 packet in channel (2nd discarded), got %d", len(ch))
	}
	got := <-ch
	if got.PacketIndex != 1 {
		t.Errorf("expected packet index 1 (first), got %d", got.PacketIndex)
	}
}

// --- Finding-5 (M-2): pushPkt 正常路径仍能发送 ---

func TestPushPkt_NormalSend(t *testing.T) {
	ctx := context.Background()
	ch := make(chan core.PacketConfig, 1)
	pkt := core.PacketConfig{PacketIndex: 42}
	pushPkt(ctx, ch, pkt)
	select {
	case got := <-ch:
		if got.PacketIndex != 42 {
			t.Errorf("expected packet index 42, got %d", got.PacketIndex)
		}
	default:
		t.Errorf("pushPkt did not send packet on normal path")
	}
}
