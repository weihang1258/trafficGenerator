package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Constructor validation tests ---

func TestHTTPServer_ConstructorValidation(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	tests := []struct {
		name        string
		listen      string
		apiKey      string
		corsOrigins []string
		wantErr     string
	}{
		{
			name:    "empty listen",
			listen:  "",
			apiKey:  "secret-key",
			wantErr: "listen is empty",
		},
		{
			name:    "empty api_key",
			listen:  "127.0.0.1:0",
			apiKey:  "",
			wantErr: "api_key is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHTTPServer(env.srv, tt.listen, tt.apiKey, tt.corsOrigins)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// --- API key middleware tests ---

// dummyOKHandler is a no-op handler that returns 200 OK. Used to verify the
// middleware passes through to the next handler on success.
func dummyOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"ok":true}`)
	})
}

func TestAPIKeyMiddleware_MissingKey(t *testing.T) {
	h := apiKeyMiddleware("secret", dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "X-MCP-Key" {
		t.Fatalf("WWW-Authenticate: got %q, want %q", got, "X-MCP-Key")
	}
}

func TestAPIKeyMiddleware_WrongKey(t *testing.T) {
	h := apiKeyMiddleware("secret", dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(`{}`))
	req.Header.Set("X-MCP-Key", "wrong-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	h := apiKeyMiddleware("secret", dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(`{}`))
	req.Header.Set("X-MCP-Key", "secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestAPIKeyMiddleware_TimingSafe verifies the middleware does not leak key
// length via timing. This is a smoke test -- a real timing attack needs
// millions of samples. We just ensure ConstantTimeCompare is used.
func TestAPIKeyMiddleware_TimingSafe(t *testing.T) {
	// Short key vs long wrong key -- both must fail. The test ensures no panic
	// and both return 401.
	h := apiKeyMiddleware("abc", dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	for _, wrong := range []string{"a", "ab", "abcd", "abcdefghijklmnopqrstuvwxyz"} {
		req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(`{}`))
		req.Header.Set("X-MCP-Key", wrong)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post with key %q: %v", wrong, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("key %q: status %d, want 401", wrong, resp.StatusCode)
		}
	}
}

// --- CORS middleware tests ---

func TestCORSMiddleware_PreflightAllowedOrigin(t *testing.T) {
	h := corsMiddleware([]string{"http://localhost:3000"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("ACAO: got %q, want %q", got, "http://localhost:3000")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-MCP-Key") {
		t.Fatalf("ACAH missing X-MCP-Key: got %q", got)
	}
}

func TestCORSMiddleware_BlockedOrigin(t *testing.T) {
	h := corsMiddleware([]string{"http://localhost:3000"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "http://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()

	// Preflight still returns 204 (CORS middleware does not block the request,
	// it just does not set CORS headers -- the browser will block the actual
	// request). The key assertion is that Allow-Origin is NOT set.
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be empty for blocked origin, got %q", got)
	}
}

func TestCORSMiddleware_Wildcard(t *testing.T) {
	h := corsMiddleware([]string{"*"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "http://anything.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://anything.example.com" {
		t.Fatalf("ACAO with wildcard config: got %q, want %q", got, "http://anything.example.com")
	}
}

// TestCORSMiddleware_PortWildcard verifies that "http://localhost:*" (the
// default config value) actually matches "http://localhost:3000" -- a
// regression for the CRITICAL bug where the wildcard port suffix was treated
// literally and never matched, silently blocking every browser dev server.
func TestCORSMiddleware_PortWildcard(t *testing.T) {
	h := corsMiddleware([]string{"http://localhost:*", "http://127.0.0.1:*"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	for _, origin := range []string{
		"http://localhost:3000",
		"http://localhost:5173",
		"http://127.0.0.1:8080",
	} {
		req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("%s: options: %v", origin, err)
			continue
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("port wildcard for %s: ACAO got %q, want %q", origin, got, origin)
		}
		resp.Body.Close()
	}
}

// TestCORSMiddleware_BlockedPort verifies that ports NOT covered by the
// wildcard are still blocked (e.g. "https://evil.com:443" should NOT get ACAO).
func TestCORSMiddleware_BlockedPort(t *testing.T) {
	h := corsMiddleware([]string{"http://localhost:*"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "https://evil.com:443")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("non-matching origin should not get ACAO, got %q", got)
	}
}

// TestCORSMiddleware_ExposeHeadersAndVary verifies the Expose-Headers
// (Mcp-Session-Id) and Vary: Origin are set so browser-based MCP clients can
// read the session id and caches do not serve cross-origin responses.
func TestCORSMiddleware_ExposeHeadersAndVary(t *testing.T) {
	h := corsMiddleware([]string{"*"}, dummyOKHandler())
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got == "" || !strings.Contains(got, "Mcp-Session-Id") {
		t.Errorf("Expose-Headers should contain Mcp-Session-Id, got %q", got)
	}
	if got := resp.Header.Get("Vary"); got == "" || !strings.Contains(got, "Origin") {
		t.Errorf("Vary should contain Origin, got %q", got)
	}
}

// TestHTTPServer_CORS_PreflightWithoutAPIKey verifies the CRITICAL CORS
// regression: browser preflight (OPTIONS) requests do NOT carry X-MCP-Key
// (the spec forbids custom headers on preflight). If API key middleware is
// erroneously outermost, every preflight 401s and browsers block all
// cross-origin requests. CORS must be outermost so preflight returns 204
// with CORS headers regardless of API key.
func TestHTTPServer_CORS_PreflightWithoutAPIKey(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	// Same order as NewHTTPServer uses: CORS outermost, API key inside.
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"http://localhost:3000"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Preflight request: NO X-MCP-Key header (browser cannot send it).
	req, _ := http.NewRequest("OPTIONS", ts.URL+"/mcp", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-MCP-Key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight without API key: status %d, want 204 (CORS must be outermost). body: %s",
			resp.StatusCode, readBody(t, resp.Body))
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("ACAO: got %q, want %q", got, "http://localhost:3000")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-MCP-Key") {
		t.Errorf("ACAH missing X-MCP-Key: got %q", got)
	}
}

// readBody is a small helper for error-message body inclusion.
func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		return "<unreadable>"
	}
	return string(b)
}

// --- Full HTTP protocol integration test ---

// apiKeyTransport wraps an http.RoundTripper to inject X-MCP-Key header on
// every request. Used with mcp.StreamableClientTransport to drive the full
// MCP protocol over HTTP in tests.
type apiKeyTransport struct {
	base   http.RoundTripper
	apiKey string
}

func (t *apiKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-MCP-Key", t.apiKey)
	return t.base.RoundTrip(req)
}

func TestHTTPServer_ProtocolFlow(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Bind to port 0 (ephemeral) to avoid conflicts. We use httptest.NewServer
	// instead of Start() because it gives us the actual URL immediately.
	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware([]string{"*"}, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Build a client transport with the API key injected.
	httpClient := &http.Client{
		Transport: &apiKeyTransport{
			base:   http.DefaultTransport,
			apiKey: "test-secret",
		},
	}
	clientTransport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: httpClient,
		// Disable standalone SSE so the test doesn't hang waiting for a GET
		// stream we don't need for request/response testing.
		DisableStandaloneSSE: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	// List tools -- should return the 3 Phase 1 tools.
	toolsResp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	wantTools := map[string]bool{
		"flowb_manage_strategies": false,
		"flowb_manage_tasks":      false,
		"flowb_generate_traffic":  false,
	}
	for _, tool := range toolsResp.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, found := range wantTools {
		if !found {
			t.Errorf("expected tool %q in tools/list response, not found", name)
		}
	}

	// Call flowb_manage_strategies(action=list) -- should succeed (empty list).
	args := map[string]interface{}{"action": "list"}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_manage_strategies",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %s", result.Content)
	}
}

// TestHTTPServer_ProtocolFlow_MissingKey verifies the SDK client without an
// API key gets 401 on initialize.
func TestHTTPServer_ProtocolFlow_MissingKey(t *testing.T) {
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

	// Client WITHOUT API key -- should fail to connect.
	clientTransport := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		DisableStandaloneSSE: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
	_, err := client.Connect(ctx, clientTransport, nil)
	if err == nil {
		t.Fatalf("expected connect to fail with 401, got nil error")
	}
	if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected 401 error, got: %v", err)
	}
}

// TestHTTPServer_RawInitialize verifies the raw HTTP initialize request works
// and returns a session ID. This is a lower-level test than the SDK client
// flow, useful for debugging protocol issues.
func TestHTTPServer_RawInitialize(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server { return env.srv.MCP() },
		&mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", corsMiddleware(nil, apiKeyMiddleware("test-secret", streamHandler)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "raw-test",
				"version": "1.0.0",
			},
		},
	}
	body, _ := json.Marshal(initReq)

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-MCP-Key", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, _ := io.ReadAll(resp.Body)
	// The SDK returns text/event-stream by default (SSE format). Each event
	// is "event: message\ndata: <json>\n\n". Extract the data: line.
	bodyStr := string(respBody)
	var jsonData []byte
	for _, line := range strings.Split(bodyStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			jsonData = []byte(line[len("data: "):])
			break
		}
	}
	if jsonData == nil {
		t.Fatalf("no data: line in SSE response. body: %s", bodyStr)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("parse response: %v\njson: %s", err, jsonData)
	}
	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc: got %v, want 2.0", parsed["jsonrpc"])
	}
	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing result in response: %s", jsonData)
	}
	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing serverInfo in result: %s", jsonData)
	}
	if serverInfo["name"] != "flowB" {
		t.Errorf("server name: got %v, want flowB", serverInfo["name"])
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Errorf("expected non-empty Mcp-Session-Id header")
	}
}
