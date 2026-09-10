// Negative-parity sweep: the same bad configs must be rejected with the same
// message via REST and via MCP. MCP forwards through callHandler into the
// same REST handlers (no re-validation), so any divergence is a wiring bug
// (e.g. MCP pruning/rewriting the config before forwarding, or prettyfying
// the error). Table-driven: each case gives the REST body plus the
// equivalent MCP input; the test asserts both fail and the messages match.
package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

type parityCase struct {
	name     string
	restBody string
	mcpIn    manageStrategiesInput
}

func restStrategyMessage(t *testing.T, env *testMCPEnv, body string) string {
	t.Helper()
	h := rest.NewStrategyHandler(env.db)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "svc-user-1")
		c.Set("username", "mcp-test-svc")
		c.Set("roles", []string{"user"})
		c.Next()
	})
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == 201 {
		t.Fatalf("REST unexpectedly accepted %s", body)
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode REST error body: %v (raw %s)", err, w.Body.String())
	}
	return resp.Message
}

func mcpStrategyMessage(t *testing.T, env *testMCPEnv, in manageStrategiesInput) string {
	t.Helper()
	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, in)
	if err == nil {
		raw, _ := json.Marshal(in)
		t.Fatalf("MCP unexpectedly accepted %s", string(raw))
	}
	return err.Error()
}

func TestNegativeParity_StrategyCreate(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	cfg := func(s string) map[string]interface{} {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("bad case config: %v", err)
		}
		return m
	}
	cases := []parityCase{
		{
			name:     "bad ip format",
			restBody: `{"name":"p1","mode":"synth","protocol":"tcp","config":{"src_ip":"999.1.1.1"}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p1", Mode: "synth", Protocol: "tcp", Config: cfg(`{"src_ip":"999.1.1.1"}`)},
		},
		{
			name:     "bad mac format",
			restBody: `{"name":"p2","mode":"synth","protocol":"tcp","config":{"src_mac":"zz"}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p2", Mode: "synth", Protocol: "tcp", Config: cfg(`{"src_mac":"zz"}`)},
		},
		{
			name:     "range violation",
			restBody: `{"name":"p3","mode":"synth","protocol":"tcp","config":{"dscp":64}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p3", Mode: "synth", Protocol: "tcp", Config: cfg(`{"dscp":64}`)},
		},
		{
			name:     "unknown protocol",
			restBody: `{"name":"p4","mode":"synth","protocol":"nope","config":{}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p4", Mode: "synth", Protocol: "nope", Config: cfg(`{}`)},
		},
		{
			name:     "bad flow_control type",
			restBody: `{"name":"p5","mode":"synth","protocol":"tcp","config":{},"flow_control":{"type":"cps","value":1}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p5", Mode: "synth", Protocol: "tcp", Config: cfg(`{}`), FlowControl: &flowControlInput{Type: "cps", Value: 1}},
		},
		{
			name:     "replay layers rejected",
			restBody: `{"name":"p6","mode":"replay","config":{"pcap_asset_id":"x","layers":[{"tcp":{}}]}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p6", Mode: "replay", Config: cfg(`{"pcap_asset_id":"x","layers":[{"tcp":{}}]}`)},
		},
		{
			name:     "replay bad speed",
			restBody: `{"name":"p7","mode":"replay","config":{"pcap_asset_id":"x","speed":{"mode":"nope"}}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p7", Mode: "replay", Config: cfg(`{"pcap_asset_id":"x","speed":{"mode":"nope"}}`)},
		},
		{
			name:     "replay null direction",
			restBody: `{"name":"p8","mode":"replay","config":{"pcap_asset_id":"x","direction":null}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p8", Mode: "replay", Config: map[string]interface{}{"pcap_asset_id": "x", "direction": nil}},
		},
		{
			name:     "unknown layer",
			restBody: `{"name":"p9","mode":"synth","protocol":"","config":{"layers":[{"nope":{}}]}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p9", Mode: "synth", Config: cfg(`{"layers":[{"nope":{}}]}`)},
		},
		{
			name:     "layer unknown field",
			restBody: `{"name":"p10","mode":"synth","protocol":"","config":{"layers":[{"ip":{}},{"tcp":{"mss_nope":1}},{"http":{}}]}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p10", Mode: "synth", Config: cfg(`{"layers":[{"ip":{}},{"tcp":{"mss_nope":1}},{"http":{}}]}`)},
		},
		{
			name:     "layers empty chain",
			restBody: `{"name":"p11","mode":"synth","protocol":"","config":{"layers":[]}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p11", Mode: "synth", Config: cfg(`{"layers":[]}`)},
		},
		{
			name:     "replay bad checksum",
			restBody: `{"name":"p12","mode":"replay","config":{"pcap_asset_id":"x","checksum_mode":"mangle"}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p12", Mode: "replay", Config: cfg(`{"pcap_asset_id":"x","checksum_mode":"mangle"}`)},
		},
		{
			name:     "layers flat four-tuple mixed use",
			restBody: `{"name":"p13","mode":"synth","protocol":"","config":{"layers":[{"tcp":{}}],"src_port":12345}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p13", Mode: "synth", Config: cfg(`{"layers":[{"tcp":{}}],"src_port":12345}`)},
		},
		{
			name:     "layer dynamic malformed range",
			restBody: `{"name":"p15","mode":"synth","protocol":"","config":{"layers":[{"ip":{"src":{"strategy":"inc"}}}]}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p15", Mode: "synth", Config: cfg(`{"layers":[{"ip":{"src":{"strategy":"inc"}}}]}`)},
		},
		{
			name:     "static copy pinned port",
			restBody: `{"name":"p14","mode":"synth","protocol":"tcp","config":{"src_port":12345},"flow_control":{"type":"flows","value":2}}`,
			mcpIn:    manageStrategiesInput{Action: "create", Name: "p14", Mode: "synth", Protocol: "tcp", Config: cfg(`{"src_port":12345}`), FlowControl: &flowControlInput{Type: "flows", Value: 2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restMsg := restStrategyMessage(t, env, tc.restBody)
			mcpMsg := mcpStrategyMessage(t, env, tc.mcpIn)
			if restMsg != mcpMsg {
				t.Errorf("message divergence:\nREST: %q\nMCP:  %q", restMsg, mcpMsg)
			}
		})
	}
}

type taskParityCase struct {
	name     string
	restBody string
	mcpIn    manageTasksInput
}

func restTaskMessage(t *testing.T, env *testMCPEnv, body string) string {
	t.Helper()
	h := rest.NewTaskHandlerWithCallbacks(env.db, env.eng, nil, false)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "svc-user-1")
		c.Set("username", "mcp-test-svc")
		c.Set("roles", []string{"user"})
		c.Next()
	})
	r.POST("/tasks", h.Create)
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == 201 {
		t.Fatalf("REST unexpectedly accepted %s", body)
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode REST error body: %v (raw %s)", err, w.Body.String())
	}
	return resp.Message
}

func mcpTaskMessage(t *testing.T, env *testMCPEnv, in manageTasksInput) string {
	t.Helper()
	_, _, err := env.srv.handleManageTasks(context.Background(), nil, in)
	if err == nil {
		raw, _ := json.Marshal(in)
		t.Fatalf("MCP unexpectedly accepted %s", string(raw))
	}
	return err.Error()
}

func TestNegativeParity_TaskCreate(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	cases := []taskParityCase{
		{
			name:     "no ids nor batch",
			restBody: `{"name":"t","output_type":"pcap","output_config":{"pcap_path":"x"}}`,
			mcpIn:    manageTasksInput{Action: "create", Name: "t", OutputType: "pcap", OutputConfig: &outputConfigInput{PcapPath: "x.pcap"}},
		},
		{
			name:     "unknown strategy",
			restBody: `{"name":"t","strategy_ids":["nope"],"output_type":"pcap","output_config":{"pcap_path":"x"}}`,
			mcpIn:    manageTasksInput{Action: "create", Name: "t", StrategyIDs: []string{"nope"}, OutputType: "pcap", OutputConfig: &outputConfigInput{PcapPath: "x.pcap"}},
		},
		{
			name:     "bad task fc type",
			restBody: `{"name":"t","strategy_ids":["s"],"output_type":"pcap","output_config":{"pcap_path":"x"},"flow_control":{"type":"cps","value":1}}`,
			mcpIn:    manageTasksInput{Action: "create", Name: "t", StrategyIDs: []string{"s"}, OutputType: "pcap", OutputConfig: &outputConfigInput{PcapPath: "x.pcap"}, FlowControl: &flowControlInput{Type: "cps", Value: 1}},
		},
		{
			name:     "pg missing id",
			restBody: `{"name":"t","strategy_ids":["s"],"output_type":"port_group","output_config":{}}`,
			mcpIn:    manageTasksInput{Action: "create", Name: "t", StrategyIDs: []string{"s"}, OutputType: "port_group", OutputConfig: &outputConfigInput{}},
		},
		{
			name:     "batch null direction",
			restBody: `{"name":"t","output_type":"pcap","output_config":{"pcap_path":"x"},"batch":{"classes":[{"id":"c","type":"replay","replay":{"pcap_asset_id":"x","direction":null}}]}}`,
			mcpIn:    manageTasksInput{Action: "create", Name: "t", OutputType: "pcap", OutputConfig: &outputConfigInput{PcapPath: "x.pcap"}, Batch: map[string]interface{}{"classes": []interface{}{map[string]interface{}{"id": "c", "type": "replay", "replay": map[string]interface{}{"pcap_asset_id": "x", "direction": nil}}}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restMsg := restTaskMessage(t, env, tc.restBody)
			mcpMsg := mcpTaskMessage(t, env, tc.mcpIn)
			if restMsg != mcpMsg {
				t.Errorf("message divergence:\nREST: %q\nMCP:  %q", restMsg, mcpMsg)
			}
		})
	}
}
