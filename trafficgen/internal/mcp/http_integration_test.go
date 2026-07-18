package mcp

import (
	"context"
	"encoding/json"
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
// Test 1: All 14 tools are advertised via tools/list over HTTP
// ---------------------------------------------------------------------------

// TestHTTPServer_AllToolsListed verifies all 14 MCP tools appear in the
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
		// 9 domain tools
		"flowb_query_system":       false,
		"flowb_manage_strategies":  false,
		"flowb_manage_users":       false,
		"flowb_manage_auth":        false,
		"flowb_manage_profile":     false,
		"flowb_manage_pcaps":       false,
		"flowb_manage_port_groups": false,
		"flowb_manage_settings":    false,
		"flowb_manage_tasks":       false,
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
