package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/replay"
)

// helpers -------------------------------------------------------------------

// newHTTPTestServer builds a fully wired MCP HTTP test server with the same
// middleware stack as NewHTTPServer (CORS outermost, API key inside).
// Returns the server (close it via .Close()) and a ready-to-use mcp Client
// session already connected with the API key.
func newHTTPTestServer(t *testing.T, env *testMCPEnv, apiKey string, corsOrigins []string) (*httptest.Server, *mcp.ClientSession) {
	t.Helper()
	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware(corsOrigins, apiKeyMiddleware(apiKey, streamHandler)))
	ts := httptest.NewServer(mux)

	httpClient := &http.Client{
		Transport: &apiKeyTransport{base: http.DefaultTransport, apiKey: apiKey},
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		ts.Close()
		t.Fatalf("connect: %v", err)
	}
	return ts, session
}

// ---------------------------------------------------------------------------
// Test 1: All 15 tools are advertised via tools/list over HTTP
// ---------------------------------------------------------------------------

// TestHTTPServer_AllToolsListed verifies all 15 MCP tools appear in the
// tools/list response over a real HTTP transport. This is the LLM's
// discovery surface -- if a tool is missing, the LLM can't invoke it.
func TestHTTPServer_AllToolsListed(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	wantTools := map[string]bool{
		// 10 domain tools
		"flowb_query_system":       false,
		"flowb_manage_strategies":  false,
		"flowb_manage_users":       false,
		"flowb_manage_auth":        false,
		"flowb_manage_profile":     false,
		"flowb_manage_pcaps":       false,
		"flowb_manage_port_groups": false,
		"flowb_manage_settings":    false,
		"flowb_manage_tasks":       false,
		"flowb_query_layers":       false,
		// 5 workflow tools
		"flowb_generate_traffic":  false,
		"flowb_get_task_progress": false,
		"flowb_stop_all_tasks":    false,
		"flowb_wait_for_task":     false,
		"flowb_replay_pcap":       false,
	}
	for _, tool := range resp.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, found := range wantTools {
		if !found {
			t.Errorf("expected tool %q in tools/list response, not found", name)
		}
	}
	if len(resp.Tools) < len(wantTools) {
		t.Errorf("tools/list returned %d tools, want >= %d", len(resp.Tools), len(wantTools))
	}
}

// ---------------------------------------------------------------------------
// Test 2: End-to-end workflow over HTTP
// ---------------------------------------------------------------------------

// TestHTTPServer_EndToEndWorkflow exercises the canonical user workflow over
// the real HTTP transport:
//   1. Query system status (verify backend ready)
//   2. Generate traffic (create strategy + task + start)
//   3. Get task progress (poll)
//   4. Wait for task completion
//   5. Verify task in task list/history
//
// This is the LLM-equivalent of "generate 5 TCP packets and tell me when done".
func TestHTTPServer_EndToEndWorkflow(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: query_system(action=status)
	statusResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_query_system",
		Arguments: map[string]interface{}{"action": "status"},
	})
	if err != nil {
		t.Fatalf("query_system status: %v", err)
	}
	if statusResult.IsError {
		t.Fatalf("query_system status returned error: %s", statusResult.Content)
	}

	// Step 2: generate_traffic (TCP, 5 packets, output to pcap)
	pcapPath := env.tmp + "/e2e.pcap"
	genResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_generate_traffic",
		Arguments: map[string]interface{}{
			"task_name":   "e2e-test",
			"protocol":    "tcp",
			"config":      map[string]interface{}{"dst_port": 80, "count": 5},
			"output_type": "pcap",
			"output_config": map[string]interface{}{
				"pcap_path": pcapPath,
			},
		},
	})
	if err != nil {
		t.Fatalf("generate_traffic: %v", err)
	}
	if genResult.IsError {
		t.Fatalf("generate_traffic returned error: %s", genResult.Content)
	}
	// Extract task_id from the structured output.
	var genOut struct {
		TaskID     string `json:"task_id"`
		StrategyID string `json:"strategy_id"`
		Status     string `json:"status"`
	}
	if err := parseToolResult(genResult, &genOut); err != nil {
		t.Fatalf("parse generate output: %v", err)
	}
	if genOut.TaskID == "" {
		t.Fatal("generate_traffic did not return task_id")
	}
	if genOut.Status != "running" && genOut.Status != "created" {
		t.Errorf("generate status: got %q, want running or created", genOut.Status)
	}

	// Step 3: get_task_progress
	progResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_get_task_progress",
		Arguments: map[string]interface{}{"task_id": genOut.TaskID},
	})
	if err != nil {
		t.Fatalf("get_task_progress: %v", err)
	}
	if progResult.IsError {
		t.Fatalf("get_task_progress error: %s", progResult.Content)
	}

	// Step 4: wait_for_task (short timeout since the task is trivial)
	// We may need to manually flip the DB status since the test engine
	// callback doesn't update DB status (only signals env.done).
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete via env.done")
	}
	env.db.Exec("UPDATE tasks SET status = ?, progress = 100 WHERE id = ?",
		"completed", genOut.TaskID)

	waitResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_wait_for_task",
		Arguments: map[string]interface{}{
			"task_id":              genOut.TaskID,
			"timeout_seconds":      5,
			"poll_interval_seconds": 1,
		},
	})
	if err != nil {
		t.Fatalf("wait_for_task: %v", err)
	}
	if waitResult.IsError {
		t.Fatalf("wait_for_task error: %s", waitResult.Content)
	}
	var waitEnvelope struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := parseToolResult(waitResult, &waitEnvelope); err != nil {
		t.Fatalf("parse wait output: %v", err)
	}
	if waitEnvelope.Data == nil {
		t.Fatalf("wait_for_task returned nil data envelope: %+v", waitResult)
	}
	if status, _ := waitEnvelope.Data["status"].(string); status != "completed" {
		t.Errorf("wait_for_task status: got %q, want completed", status)
	}

	// Step 5: list tasks -- should include our task
	listResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_manage_tasks",
		Arguments: map[string]interface{}{
			"action": "list",
			"size":   10,
		},
	})
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if listResult.IsError {
		t.Fatalf("list tasks error: %s", listResult.Content)
	}
}

// ---------------------------------------------------------------------------
// Test 3: All 9 domain tools respond to a simple action over HTTP
// ---------------------------------------------------------------------------

// TestHTTPServer_AllDomainToolsCallable verifies every domain tool can be
// invoked over HTTP with a minimal action and returns a non-error response.
// This catches registration/wiring bugs where a tool is listed but its
// handler is broken.
func TestHTTPServer_AllDomainToolsCallable(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cases := []struct {
		tool      string
		arguments map[string]interface{}
		allowErr  bool // tool may return an error result (e.g., 403 for admin-only)
	}{
		{"flowb_query_system", map[string]interface{}{"action": "status"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "protocols"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "stats"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "health"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "ready"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "interfaces"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "ports"}, false},
		{"flowb_query_system", map[string]interface{}{"action": "refresh_interfaces"}, false},
		{"flowb_manage_strategies", map[string]interface{}{"action": "list"}, false},
		{"flowb_manage_users", map[string]interface{}{"action": "list"}, true}, // 403 in service mode (expected)
		{"flowb_manage_auth", map[string]interface{}{"action": "register", "username": "validuser", "password": "validpass123", "email": "valid@example.com"}, false},
		{"flowb_manage_profile", map[string]interface{}{"action": "get"}, false},
		{"flowb_manage_pcaps", map[string]interface{}{"action": "list"}, false},
		{"flowb_manage_port_groups", map[string]interface{}{"action": "list"}, false},
		{"flowb_manage_settings", map[string]interface{}{"action": "get"}, false},
		{"flowb_manage_tasks", map[string]interface{}{"action": "list"}, false},
	}

	for _, c := range cases {
		actionStr, _ := c.arguments["action"].(string)
		t.Run(c.tool+"/"+actionStr, func(t *testing.T) {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      c.tool,
				Arguments: c.arguments,
			})
			if err != nil {
				if c.allowErr {
					t.Logf("%s returned expected error: %v", c.tool, err)
					return
				}
				t.Fatalf("CallTool %s: %v", c.tool, err)
			}
			if result.IsError && !c.allowErr {
				t.Errorf("%s returned error result: %s", c.tool, result.Content)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 4: All 5 workflow tools callable
// ---------------------------------------------------------------------------

// TestHTTPServer_AllWorkflowToolsCallable verifies every workflow tool can be
// invoked over HTTP. The one-shot tools (generate, replay) use a trivial
// config; the polling tools (progress, wait, stop_all) target the generated
// task.
func TestHTTPServer_AllWorkflowToolsCallable(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. generate_traffic
	pcapPath := env.tmp + "/wf.pcap"
	genResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_generate_traffic",
		Arguments: map[string]interface{}{
			"task_name":   "wf-test",
			"protocol":    "tcp",
			"config":      map[string]interface{}{"dst_port": 80, "count": 2},
			"output_type": "pcap",
			"output_config": map[string]interface{}{
				"pcap_path": pcapPath,
			},
		},
	})
	if err != nil || genResult.IsError {
		t.Fatalf("generate_traffic: err=%v result=%s", err, genResult.Content)
	}
	var genOut struct {
		TaskID string `json:"task_id"`
	}
	if err := parseToolResult(genResult, &genOut); err != nil {
		t.Fatalf("parse gen output: %v", err)
	}

	// 2. get_task_progress
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_get_task_progress",
		Arguments: map[string]interface{}{"task_id": genOut.TaskID},
	})
	if err != nil {
		t.Errorf("get_task_progress: %v", err)
	}

	// 3. stop_all_tasks (may or may not stop our task depending on timing)
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_stop_all_tasks",
		Arguments: map[string]interface{}{},
	})
	if err != nil {
		t.Errorf("stop_all_tasks: %v", err)
	}

	// 4. wait_for_task with short timeout (the task should complete naturally
	// for 2 packets; if not, timeout is acceptable)
	// Drain env.done first since stop_all_tasks may have stopped the task.
	go func() {
		for range env.done {
		}
	}()
	env.db.Exec("UPDATE tasks SET status = ? WHERE id = ?", "completed", genOut.TaskID)
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_wait_for_task",
		Arguments: map[string]interface{}{
			"task_id":               genOut.TaskID,
			"timeout_seconds":       3,
			"poll_interval_seconds": 1,
		},
	})
	if err != nil {
		t.Errorf("wait_for_task: %v", err)
	}

	// 5. replay_pcap -- need to import a pcap first
	// Use the shared importTestPcap helper which writes a valid pcap and
	// extracts the asset ID (PcapAssetModel has no JSON tags so the ID
	// field is "ID", not "id" -- the helper handles this).
	env.eng.SetReplayPlanner(replay.NewReplayPlanner(env.db))
	assetID := importTestPcap(t, env)

	replayPcap := env.tmp + "/replay.pcap"
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name: "flowb_replay_pcap",
		Arguments: map[string]interface{}{
			"task_name":     "wf-replay",
			"pcap_asset_id": assetID,
			"speed":         map[string]interface{}{"mode": "original"},
			"loop":          1,
			"output_type":   "pcap",
			"output_config": map[string]interface{}{
				"pcap_path": replayPcap,
			},
		},
	})
	if err != nil {
		t.Errorf("replay_pcap: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Concurrent sessions
// ---------------------------------------------------------------------------

// TestHTTPServer_ConcurrentSessions verifies multiple LLM clients can connect
// and call tools simultaneously without interfering with each other. Each
// session should see its own service-account data (and the same global state
// since they share the service account).
func TestHTTPServer_ConcurrentSessions(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numSessions = 3
	done := make(chan error, numSessions)
	for i := 0; i < numSessions; i++ {
		i := i
		go func() {
			// Each goroutine creates its own session.
			httpClient := &http.Client{
				Transport: &apiKeyTransport{base: http.DefaultTransport, apiKey: "test-secret"},
			}
			transport := &mcp.StreamableClientTransport{
				Endpoint:             ts.URL + "/mcp",
				HTTPClient:           httpClient,
				DisableStandaloneSSE: true,
			}
			client := mcp.NewClient(&mcp.Implementation{
				Name: "concurrent-client", Version: "v1.0.0",
			}, nil)
			sess, err := client.Connect(ctx, transport, nil)
			if err != nil {
				done <- err
				return
			}
			defer sess.Close()

			_, err = sess.CallTool(ctx, &mcp.CallToolParams{
				Name:      "flowb_query_system",
				Arguments: map[string]interface{}{"action": "status"},
			})
			if err != nil {
				done <- err
				return
			}
			t.Logf("session %d: status OK", i)
			done <- nil
		}()
	}
	for i := 0; i < numSessions; i++ {
		if err := <-done; err != nil {
			t.Errorf("session %d failed: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 6: Session isolation (invalid session-id rejected)
// ---------------------------------------------------------------------------

// TestHTTPServer_InvalidSessionID verifies the server rejects requests with
// a bogus Mcp-Session-Id. This catches SDK session-id validation regressions.
func TestHTTPServer_InvalidSessionID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// POST tools/call with a bogus session id -- should be rejected.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flowb_query_system","arguments":{"action":"status"}}}`
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")
	req.Header.Set("Mcp-Session-Id", "bogus-session-id-not-real")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	// The SDK should reject the bogus session id with 4xx (typically 400 or 404).
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("bogus session id: status %d, want 4xx", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Handshake order regression (raw HTTP)
// ---------------------------------------------------------------------------

// rawMCPRequest sends a single JSON-RPC request over raw HTTP (not the SDK
// client) and returns the HTTP status code + body. Used to verify the SDK's
// handshake constraints from the server's perspective, since the SDK client
// always does the right thing and would hide regressions.
func rawMCPRequest(t *testing.T, ts *httptest.Server, headers map[string]string, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestHTTPServer_HandshakeRejectsToolsListBeforeInitialize verifies the SDK
// rejects tools/list sent before initialize. The StreamableHTTP spec requires
// a stateful session: initialize → notifications/initialized → tools/list.
// Calling tools/list first must fail with the SDK's
// "method %q is invalid during session initialization" error, NOT succeed.
//
// Regression value: catches anyone reordering middleware, enabling stateless
// mode by accident, or SDK upgrades that loosen the handshake rule.
func TestHTTPServer_HandshakeRejectsToolsListBeforeInitialize(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	headers := map[string]string{
		"X-MCP-Key": "test-secret",
		"Accept":    "application/json, text/event-stream",
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	status, respBody := rawMCPRequest(t, ts, headers, body)

	// The server may return 200 with an error response in the body (SSE
	// stream), or 400/404 for a session violation. Either is acceptable; what
	// is NOT acceptable is a 200 with a valid tools list.
	containsError := strings.Contains(respBody, "invalid during session initialization") ||
		strings.Contains(respBody, "session not found") ||
		status == 400 || status == 404
	if !containsError {
		t.Errorf("expected handshake violation, got status=%d body=%s", status, respBody)
	}
	if strings.Contains(respBody, `"tools":[`) && !strings.Contains(respBody, "invalid during") {
		t.Errorf("server leaked tools/list before initialize: %s", respBody)
	}
}

// TestHTTPServer_HandshakeRejectsMissingAccept verifies the SDK rejects POST
// requests whose Accept header is missing one of the required media types.
// The StreamableHTTP spec requires clients to accept BOTH application/json
// (for single responses) and text/event-stream (for SSE streams), because the
// server may respond in either format.
//
// Regression value: catches anyone who tries to use plain `Accept: application/json`
// or omits Accept entirely. The SDK enforces this before any handler runs.
func TestHTTPServer_HandshakeRejectsMissingAccept(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Case 1: only application/json (missing text/event-stream)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	status, respBody := rawMCPRequest(t, ts, map[string]string{
		"X-MCP-Key": "test-secret",
		"Accept":    "application/json",
	}, body)
	if status != 400 {
		t.Errorf("Accept=application/json only: status=%d, want 400 (Accept must contain both)", status)
	}
	if !strings.Contains(respBody, "Accept must contain both") {
		t.Errorf("expected 'Accept must contain both' error, got: %s", respBody)
	}

	// Case 2: no Accept header at all
	status, _ = rawMCPRequest(t, ts, map[string]string{
		"X-MCP-Key": "test-secret",
	}, body)
	if status != 400 {
		t.Errorf("no Accept header: status=%d, want 400", status)
	}
}

// TestHTTPServer_HandshakeRejectsToolsListWithoutSessionID verifies that
// after a correct initialize, calling tools/list WITHOUT the Mcp-Session-Id
// header is rejected. The session id returned in the initialize response
// header is the only way to address the session; omitting it starts a new
// (uninitialized) session, which rejects tools/list.
//
// Regression value: the previous bug was that the SDK client always supplied
// the session id, so this constraint was invisible. A raw client that
// forgets to copy the header must be caught.
func TestHTTPServer_HandshakeRejectsToolsListWithoutSessionID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Step 1: correct initialize (returns session id in response header).
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	resp.Body.Close()
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize did not return Mcp-Session-Id")
	}

	// Step 2: notifications/initialized (carrying session id)
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, _ = http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(notifBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialized: %v", err)
	}
	resp.Body.Close()

	// Step 3: tools/list WITHOUT Mcp-Session-Id -- must be rejected.
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	status, respBody := rawMCPRequest(t, ts, map[string]string{
		"X-MCP-Key": "test-secret",
		"Accept":    "application/json, text/event-stream",
	}, listBody)
	// Without a session id, the server creates a fresh uninitialized session
	// which rejects tools/list with "invalid during session initialization".
	containsError := strings.Contains(respBody, "invalid during session initialization") ||
		status == 400 || status == 404
	if !containsError {
		t.Errorf("tools/list without session id should be rejected, got status=%d body=%s", status, respBody)
	}
	if strings.Contains(respBody, `"tools":[`) && !strings.Contains(respBody, "invalid during") {
		t.Errorf("server leaked tools/list without session id: %s", respBody)
	}
}

// TestHTTPServer_HandshakeFullSequence verifies the canonical 3-step
// handshake works end-to-end with raw HTTP (no SDK client), producing a
// valid tools list. This is the positive counterpart to the rejection tests
// above: it confirms our server actually accepts the handshake when done
// correctly, so a regression in any rejection test is a real regression,
// not a "server is broken in general" false alarm.
//
// Regression value: if someone breaks middleware ordering (e.g. wrapping
// CORS inside API key, breaking preflight) or removes the session id
// passthrough, this test fails alongside the rejection tests, localizing
// the bug to "handshake broken" rather than "all tools broken".
func TestHTTPServer_HandshakeFullSequence(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1) initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	resp.Body.Close()
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize did not return Mcp-Session-Id")
	}

	// 2) notifications/initialized
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, _ = http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(notifBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialized: %v", err)
	}
	resp.Body.Close()

	// 3) tools/list
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	status, respBody := rawMCPRequest(t, ts, map[string]string{
		"X-MCP-Key":       "test-secret",
		"Accept":          "application/json, text/event-stream",
		"Mcp-Session-Id":  sid,
	}, listBody)
	if status != 200 {
		t.Errorf("tools/list: status=%d, want 200; body=%s", status, respBody)
	}
	if !strings.Contains(respBody, `"tools":[`) {
		t.Errorf("tools/list did not return a tools array: %s", respBody)
	}
	// Sanity check: at least one flowb tool must appear.
	if !strings.Contains(respBody, "flowb_") {
		t.Errorf("tools/list response missing flowb_ tools: %s", respBody)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseToolResult unmarshals the structured output of a CallToolResult into
// the target struct. The MCP SDK returns the tool's output struct serialized
// as JSON inside result.Content (or as structured content).
func parseToolResult(result *mcp.CallToolResult, target interface{}) error {
	// The SDK serializes the tool's output struct as JSON in Content[0].
	for _, c := range result.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			return json.Unmarshal([]byte(text.Text), target)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test 8: OutputSchema compatibility with Claude Code's zod validator
// ---------------------------------------------------------------------------

// TestHTTPServer_OutputSchema_NoBooleanSchemas verifies that no tool's
// outputSchema contains a boolean schema (e.g. `"data": true`). Claude Code's
// zod validator rejects boolean JSON Schemas at tools/list time with
// "Invalid input", which breaks ALL tool discovery even though the server is
// functional.
//
// Root cause this guards against: a field of type `interface{}` (Go's "any")
// produces `"data": true` under the JSON Schema spec's boolean-schema form
// (which means "accept anything"). That's a valid schema in spec, but zod's
// MCP validator only accepts object schemas with explicit properties.
//
// Fix: every tool whose output struct has a `Data interface{}` field must
// also set an explicit OutputSchema on the Tool, replacing `true` with `{}`
// (empty schema = accept anything, but in object form).
//
// Regression value: if someone adds a new tool with `Data interface{}` and
// forgets the explicit OutputSchema, or if the SDK's schema inference changes
// to produce boolean schemas for other types, this test catches it before the
// LLM client sees a broken tools/list.
func TestHTTPServer_OutputSchema_NoBooleanSchemas(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Paginate through all tools -- the SDK may split tools/list into pages.
	allTools := []*mcp.Tool{}
	var cursor string
	for {
		resp, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			t.Fatalf("list tools (cursor=%q): %v", cursor, err)
		}
		allTools = append(allTools, resp.Tools...)
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}

	for _, tool := range allTools {
		// Tools without outputSchema are fine (SDK omits it for `any` output).
		if tool.OutputSchema == nil {
			continue
		}
		// Marshal the outputSchema to JSON so we can scan for boolean values.
		// The SDK accepts OutputSchema as any; under the hood it's typically a
		// *jsonschema.Schema or a map[string]any. Marshal normalizes both.
		b, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("tool %q: marshal outputSchema: %v", tool.Name, err)
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(b, &schema); err != nil {
			t.Fatalf("tool %q: parse outputSchema: %v", tool.Name, err)
		}
		// The fix ensures every "data" property is an object (even if empty).
		// If we see a boolean true, the regression is back.
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		dataProp, ok := props["data"]
		if !ok {
			continue
		}
		if _, isBool := dataProp.(bool); isBool {
			t.Errorf("tool %q has outputSchema.properties.data = true (boolean schema); "+
				"Claude Code zod will reject this. Add OutputSchema: manageOutputSchema() "+
				"or dataOnlyOutputSchema() to the Tool registration.", tool.Name)
		}
	}
}

// TestHTTPServer_OutputSchema_AcceptsAnyDataValue verifies that the explicit
// OutputSchema on tools with `Data interface{}` accepts any JSON value for
// the data property -- objects, arrays, strings, numbers, booleans, and null.
// The schema must not constrain the data type, or it will reject valid
// backend responses.
//
// Regression value: if someone "fixes" the boolean-schema issue by giving
// data a concrete type (e.g. `{"type": "object"}`), every list action that
// returns an array would fail validation at tools/call time. This test
// catches that overcorrection.
func TestHTTPServer_OutputSchema_AcceptsAnyDataValue(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Paginate through all tools.
	allTools := []*mcp.Tool{}
	var cursor string
	for {
		resp, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			t.Fatalf("list tools (cursor=%q): %v", cursor, err)
		}
		allTools = append(allTools, resp.Tools...)
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}

	// Tools that must accept any data type (have `Data interface{}` output).
	wantAnyData := map[string]bool{
		"flowb_manage_strategies":  false,
		"flowb_manage_tasks":       false,
		"flowb_manage_users":       false,
		"flowb_manage_auth":        false,
		"flowb_manage_profile":     false,
		"flowb_manage_pcaps":       false,
		"flowb_manage_port_groups": false,
		"flowb_manage_settings":    false,
		"flowb_query_system":       false,
		"flowb_get_task_progress":  false,
		"flowb_wait_for_task":      false,
	}
	for _, tool := range allTools {
		_, want := wantAnyData[tool.Name]
		if !want {
			continue
		}
		wantAnyData[tool.Name] = true

		if tool.OutputSchema == nil {
			t.Errorf("tool %q: missing OutputSchema (needed to override interface{} boolean schema)", tool.Name)
			continue
		}
		b, _ := json.Marshal(tool.OutputSchema)
		var schema map[string]interface{}
		if err := json.Unmarshal(b, &schema); err != nil {
			t.Errorf("tool %q: parse outputSchema: %v", tool.Name, err)
			continue
		}
		props, _ := schema["properties"].(map[string]interface{})
		dataProp, _ := props["data"].(map[string]interface{})
		// "data" must NOT have a "type" constraint -- any type is valid.
		if _, hasType := dataProp["type"]; hasType {
			t.Errorf("tool %q: outputSchema.properties.data has 'type' constraint; "+
				"this will reject valid backend responses of other types (arrays, strings, etc.)",
				tool.Name)
		}
	}
	for name, found := range wantAnyData {
		if !found {
			t.Errorf("expected tool %q in tools/list, not found", name)
		}
	}
}
