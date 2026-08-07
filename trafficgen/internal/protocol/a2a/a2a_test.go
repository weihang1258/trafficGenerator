package a2a

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Planner.Name ---

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "a2a" {
		t.Errorf("Name() = %q, want %q", got, "a2a")
	}
}

// --- Planner.Validate ---

func TestPlanner_Validate_Basic(t *testing.T) {
	p := NewPlanner()

	// Valid minimal config
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestPlanner_Validate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "invalid",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(&A2AConfig{}),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("expected invalid source IP error, got: %v", err)
	}
}

func TestPlanner_Validate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "invalid",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(&A2AConfig{}),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("expected invalid destination IP error, got: %v", err)
	}
}

func TestPlanner_Validate_MissingConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Errorf("expected config required error, got: %v", err)
	}
}

func TestPlanner_Validate_InvalidMethod(t *testing.T) {
	p := NewPlanner()
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{Method: "tasks/send", RequestID: json.RawMessage(`"req-001"`)}, // Invalid method
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V2") {
		t.Errorf("expected V2 method validation error, got: %v", err)
	}
}

func TestPlanner_Validate_StreamingConsistency(t *testing.T) {
	p := NewPlanner()

	// Streaming=true but sync method
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageSend,
				Streaming: true, // Wrong - message/send is not streaming
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V8") {
		t.Errorf("expected V8 streaming consistency error, got: %v", err)
	}
}

func TestPlanner_Validate_PartKind(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "data-stream", Text: "test"}}, // Invalid kind
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V4") {
		t.Errorf("expected V4 Part kind error, got: %v", err)
	}
}

func TestPlanner_Validate_TaskIDRequired(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodTasksGet,
				TaskID:    "", // Missing required TaskID
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V8") {
		t.Errorf("expected V8 TaskID required error, got: %v", err)
	}
}

func TestPlanner_Validate_ResultErrorMutualExclusion(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"req-001"`),
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task"}`),
					Error:  &A2AError{Code: JSONRPCTaskNotFound, Message: "not found"},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V16") {
		t.Errorf("expected V16 result/error mutual exclusion error, got: %v", err)
	}
}

// --- Planner.Plan ---

func TestPlanner_Plan_Basic(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task","id":"task-001","contextId":"ctx-001","status":{"state":"completed"}}`),
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Should have: SYN, SYN-ACK, ACK, HTTP Request, HTTP Response, FIN, ACK, FIN, ACK
	if len(configs) < 9 {
		t.Errorf("Expected at least 9 configs, got %d", len(configs))
	}

	// Check first packet is SYN
	if configs[0].L4.Flags != 0x02 {
		t.Errorf("First packet should be SYN, flags = %x", configs[0].L4.Flags)
	}
}

func TestPlanner_Plan_WithAgentCardDiscovery(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL:       "https://agent.example.com/a2a",
		AgentCardPath: "/.well-known/agent.json",
		Discover:      true,
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Should have more packets due to Agent Card discovery
	if len(configs) < 12 {
		t.Errorf("Expected at least 12 configs with discovery, got %d", len(configs))
	}
}

func TestPlanner_Plan_Streaming(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageStream,
				Streaming: true,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "stream this"}},
					MessageID: "m-002",
				},
				RequestID: json.RawMessage(`"req-002"`),
				SSEEvents: []A2ASSEEvent{
					{
						Kind: "task",
						Task: &A2ATaskObject{
							ID:        "task-002",
							ContextID: "ctx-002",
							Status:    A2ATaskStatus{State: TaskStateSubmitted},
							Kind:      DefaultTaskKind,
						},
					},
					{
						Kind: "status-update",
						StatusUpdate: &A2ATaskStatusUpdateEvent{
							TaskID:    "task-002",
							ContextID: "ctx-002",
							Kind:      DefaultStatusUpdateKind,
							Status:    A2ATaskStatus{State: TaskStateWorking},
							Final:     false,
						},
					},
					{
						Kind: "status-update",
						StatusUpdate: &A2ATaskStatusUpdateEvent{
							TaskID:    "task-002",
							ContextID: "ctx-002",
							Kind:      DefaultStatusUpdateKind,
							Status:    A2ATaskStatus{State: TaskStateCompleted},
							Final:     true,
						},
					},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Find SSE response packet
	foundSSE := false
	for _, cfg := range configs {
		if cfg.Direction == "down" && len(cfg.Payload) > 0 {
			if strings.Contains(string(cfg.Payload), "data: {") {
				foundSSE = true
				payload := string(cfg.Payload)
				// Design doc §6.2 S3: the SSE response must be a full HTTP
				// response — status line, Content-Type: text/event-stream,
				// and chunked framing — followed by unnamed data: events.
				if !strings.HasPrefix(payload, "HTTP/1.1 200 OK") {
					t.Errorf("SSE response should start with HTTP status line, got %q", payload[:min(len(payload), 40)])
				}
				if !strings.Contains(payload, "Content-Type: text/event-stream") {
					t.Errorf("SSE response should contain Content-Type: text/event-stream")
				}
				if !strings.Contains(payload, "Transfer-Encoding: chunked") {
					t.Errorf("SSE response should contain Transfer-Encoding: chunked")
				}
				if strings.Contains(payload, "event:") {
					t.Errorf("SSE events must be unnamed (no event: field)")
				}
			}
		}
	}

	if !foundSSE {
		t.Errorf("Expected to find SSE response in stream")
	}
}

// --- Builder functions ---

func TestBuildJSONRPCRequest(t *testing.T) {
	params := map[string]any{
		"message": map[string]any{
			"role": "user",
			"parts": []map[string]any{
				{"kind": "text", "text": "hello"},
			},
		},
	}
	b := BuildJSONRPCRequest(MethodMessageSend, params, "req-001")

	var req map[string]any
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	if req["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", req["jsonrpc"])
	}
	if req["method"] != MethodMessageSend {
		t.Errorf("method = %v, want %s", req["method"], MethodMessageSend)
	}
	if req["id"] != "req-001" {
		t.Errorf("id = %v, want req-001", req["id"])
	}
}

func TestBuildJSONRPCError(t *testing.T) {
	b := BuildJSONRPCError(JSONRPCTaskNotFound, "Task not found", nil, "req-001")

	var resp map[string]any
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", resp["jsonrpc"])
	}

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("error object not found")
	}
	// N7 修复：json.Unmarshal 把 JSON 数字解码为 float64，直接用
	// errObj["code"] != JSONRPCTaskNotFound（int）做类型不匹配比较恒为
	// true，该断言永远不会真正校验 code 值。改为先断言 float64 再比 int。
	code, ok := errObj["code"].(float64)
	if !ok {
		t.Fatalf("error.code not a number, got %T", errObj["code"])
	}
	if int(code) != JSONRPCTaskNotFound {
		t.Errorf("code = %v, want %d", code, JSONRPCTaskNotFound)
	}
	if errObj["message"] != "Task not found" {
		t.Errorf("message = %v, want 'Task not found'", errObj["message"])
	}
}

func TestBuildSSEEvent(t *testing.T) {
	resp := []byte(`{"jsonrpc":"2.0","id":"req-001","result":{"kind":"task"}}`)
	event := BuildSSEEvent(resp)

	expected := "data: {\"jsonrpc\":\"2.0\",\"id\":\"req-001\",\"result\":{\"kind\":\"task\"}}\n\n"
	if string(event) != expected {
		t.Errorf("SSE event = %q, want %q", string(event), expected)
	}
}

func TestBuildTaskObject(t *testing.T) {
	task := BuildTaskObject("task-001", "ctx-001", TaskStateCompleted, nil, nil, nil)

	if task["id"] != "task-001" {
		t.Errorf("id = %v, want task-001", task["id"])
	}
	if task["contextId"] != "ctx-001" {
		t.Errorf("contextId = %v, want ctx-001", task["contextId"])
	}
	if task["kind"] != "task" {
		t.Errorf("kind = %v, want task", task["kind"])
	}

	status, ok := task["status"].(map[string]any)
	if !ok {
		t.Fatalf("status not found")
	}
	if status["state"] != TaskStateCompleted {
		t.Errorf("state = %v, want %s", status["state"], TaskStateCompleted)
	}
}

func TestBuildMessage(t *testing.T) {
	parts := []A2APart{{Kind: "text", Text: "hello"}}
	msg := BuildMessage("user", parts, "m-001", "task-001", "ctx-001", nil)

	if msg["role"] != "user" {
		t.Errorf("role = %v, want user", msg["role"])
	}
	if msg["messageId"] != "m-001" {
		t.Errorf("messageId = %v, want m-001", msg["messageId"])
	}
	if msg["taskId"] != "task-001" {
		t.Errorf("taskId = %v, want task-001", msg["taskId"])
	}
	if msg["contextId"] != "ctx-001" {
		t.Errorf("contextId = %v, want ctx-001", msg["contextId"])
	}
}

func TestBuildStatusUpdateEvent(t *testing.T) {
	ev := BuildStatusUpdateEvent("task-001", "ctx-001", TaskStateWorking, false, nil)

	if ev["taskId"] != "task-001" {
		t.Errorf("taskId = %v, want task-001", ev["taskId"])
	}
	if ev["kind"] != "status-update" {
		t.Errorf("kind = %v, want status-update", ev["kind"])
	}
	if ev["final"] != false {
		t.Errorf("final = %v, want false", ev["final"])
	}
}

func TestBuildHTTPRequest(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"message/send"}`)
	req := BuildHTTPRequest("POST", "/a2a", "agent.example.com", "application/json", "application/json", "keep-alive", "trafficgen-a2a/2.0", body, nil)

	if !strings.Contains(req, "POST /a2a HTTP/1.1") {
		t.Errorf("Request should contain method and path")
	}
	if !strings.Contains(req, "Host: agent.example.com") {
		t.Errorf("Request should contain Host header")
	}
	if !strings.Contains(req, "Content-Type: application/json") {
		t.Errorf("Request should contain Content-Type header")
	}
	if !strings.Contains(req, `{"jsonrpc":"2.0","method":"message/send"}`) {
		t.Errorf("Request should contain body")
	}
}

func TestBuildHTTPResponse(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","result":{}}`)
	resp := BuildHTTPResponse(200, "OK", "application/json", body, nil)

	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Errorf("Response should start with status line")
	}
	if !strings.Contains(resp, "Content-Type: application/json") {
		t.Errorf("Response should contain Content-Type header")
	}
	if !strings.Contains(resp, `{"jsonrpc":"2.0","result":{}}`) {
		t.Errorf("Response should contain body")
	}
}

// --- Parser functions ---

func TestParseJSONRPCRequest(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"message/send","params":{"message":{"role":"user"}},"id":"req-001"}`)
	req, err := ParseJSONRPCRequest(data)
	if err != nil {
		t.Fatalf("ParseJSONRPCRequest error: %v", err)
	}

	if req.Method != "message/send" {
		t.Errorf("method = %q, want message/send", req.Method)
	}
	if req.ID != "req-001" {
		t.Errorf("id = %v, want req-001", req.ID)
	}
}

func TestParseJSONRPCResponse(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","result":{"kind":"task"},"id":"req-001"}`)
	resp, err := ParseJSONRPCResponse(data)
	if err != nil {
		t.Fatalf("ParseJSONRPCResponse error: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("error should be nil for success response")
	}
}

func TestParseJSONRPCResponse_Error(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Task not found"},"id":"req-001"}`)
	resp, err := ParseJSONRPCResponse(data)
	if err != nil {
		t.Fatalf("ParseJSONRPCResponse error: %v", err)
	}

	if resp.Error == nil {
		t.Fatalf("error should be present")
	}
	if resp.Error.Code != JSONRPCTaskNotFound {
		t.Errorf("code = %d, want %d", resp.Error.Code, JSONRPCTaskNotFound)
	}
}

func TestParseSSEStream(t *testing.T) {
	data := []byte(`data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"task"}}

data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"status-update","final":true}}

`)
	events, err := ParseSSEStream(data)
	if err != nil {
		t.Fatalf("ParseSSEStream error: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	if events[0].JSONRPC != "2.0" {
		t.Errorf("first event jsonrpc = %q, want 2.0", events[0].JSONRPC)
	}
}

func TestIsValidMethod(t *testing.T) {
	if !IsValidMethod(MethodMessageSend) {
		t.Errorf("message/send should be valid")
	}
	if !IsValidMethod(MethodMessageStream) {
		t.Errorf("message/stream should be valid")
	}
	if IsValidMethod("invalid/method") {
		t.Errorf("invalid/method should not be valid")
	}
}

func TestIsValidTaskState(t *testing.T) {
	if !IsValidTaskState(TaskStateCompleted) {
		t.Errorf("completed should be valid")
	}
	if !IsValidTaskState(TaskStateWorking) {
		t.Errorf("working should be valid")
	}
	if IsValidTaskState("invalid") {
		t.Errorf("invalid should not be valid")
	}
}

func TestIsTerminalState(t *testing.T) {
	if !IsTerminalState(TaskStateCompleted) {
		t.Errorf("completed is terminal")
	}
	if !IsTerminalState(TaskStateFailed) {
		t.Errorf("failed is terminal")
	}
	if IsTerminalState(TaskStateWorking) {
		t.Errorf("working is not terminal")
	}
}

func TestIsStreamingMethod(t *testing.T) {
	if !IsStreamingMethod(MethodMessageStream) {
		t.Errorf("message/stream is streaming")
	}
	if !IsStreamingMethod(MethodTasksResubscribe) {
		t.Errorf("tasks/resubscribe is streaming")
	}
	if IsStreamingMethod(MethodMessageSend) {
		t.Errorf("message/send is not streaming")
	}
}

// --- V10 state transitions (design doc §4.2) ---

func TestPlanner_Validate_IllegalStateTransition(t *testing.T) {
	p := NewPlanner()
	// submitted -> completed is not listed in §4.2; Validate must reject.
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageStream,
				Streaming: true,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "stream"}},
					MessageID: "m-002",
				},
				RequestID: json.RawMessage(`"req-002"`),
				SSEEvents: []A2ASSEEvent{
					{Kind: "task", Task: &A2ATaskObject{ID: "task-002", ContextID: "ctx-002", Status: A2ATaskStatus{State: TaskStateSubmitted}, Kind: DefaultTaskKind}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateCompleted}, Final: true}},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V10") {
		t.Errorf("expected V10 illegal state transition error (submitted->completed), got: %v", err)
	}
}

func TestPlanner_Validate_TerminalStateTransition(t *testing.T) {
	p := NewPlanner()
	// completed -> working: terminal states are immutable (§4.2).
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageStream,
				Streaming: true,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "stream"}},
					MessageID: "m-002",
				},
				RequestID: json.RawMessage(`"req-002"`),
				SSEEvents: []A2ASSEEvent{
					{Kind: "task", Task: &A2ATaskObject{ID: "task-002", ContextID: "ctx-002", Status: A2ATaskStatus{State: TaskStateCompleted}, Kind: DefaultTaskKind}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateWorking}, Final: false}},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V10") {
		t.Errorf("expected V10 error for terminal->working transition, got: %v", err)
	}
}

func TestPlanner_Validate_InputRequiredToCompletedRejected(t *testing.T) {
	p := NewPlanner()
	// input-required -> completed is not defined by spec (§4.2, T120).
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageStream,
				Streaming: true,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "stream"}},
					MessageID: "m-002",
				},
				RequestID: json.RawMessage(`"req-002"`),
				SSEEvents: []A2ASSEEvent{
					{Kind: "task", Task: &A2ATaskObject{ID: "task-002", ContextID: "ctx-002", Status: A2ATaskStatus{State: TaskStateWorking}, Kind: DefaultTaskKind}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateInputRequired}, Final: false}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateCompleted}, Final: true}},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V10") {
		t.Errorf("expected V10 error for input-required->completed, got: %v", err)
	}
}

// --- RequestID required (V8) ---

func TestPlanner_Validate_MissingRequestID(t *testing.T) {
	p := NewPlanner()
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
				// RequestID intentionally absent
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V8") {
		t.Errorf("expected V8 RequestID required error, got: %v", err)
	}
}

// --- V12 length constraints ---

func TestPlanner_Validate_OversizedRequestID(t *testing.T) {
	p := NewPlanner()
	// 129-byte string id must be rejected (§2.10).
	longID := strings.Repeat("a", 129)
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"` + longID + `"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V12") {
		t.Errorf("expected V12 oversized id error, got: %v", err)
	}
}

func TestPlanner_Validate_OversizedPartText(t *testing.T) {
	p := NewPlanner()
	// Part.text > 1MB must be rejected (§2.10).
	bigText := strings.Repeat("a", maxPartTextLen+1)
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: bigText}},
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V12") {
		t.Errorf("expected V12 oversized Part.text error, got: %v", err)
	}
}

// --- A2AConfig.TCP.MSS takes effect (was ignored) ---

func TestPlanner_Plan_CfgMSSUsed(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		TCP: A2ATCP{MSS: 600},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: strings.Repeat("x", 3000)}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task","id":"task-001","contextId":"ctx-001","status":{"state":"completed"}}`),
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// The 3000-byte message body must be split into segments of at most 600
	// bytes each. Find the up-direction data packets (PSH-ACK, 0x18) that
	// carry the JSON-RPC request (method=message/send) and assert the max
	// payload length <= 600.
	maxSeg := 0
	for _, c := range configs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), "message/send") {
				if len(c.Payload) > maxSeg {
					maxSeg = len(c.Payload)
				}
			}
		}
	}
	if maxSeg == 0 {
		t.Fatalf("no request data segment found")
	}
	if maxSeg > 600 {
		t.Errorf("max segment %d exceeds configured MSS 600", maxSeg)
	}
}

// --- 3-packet teardown (design doc §6.1 #4) ---

func TestPlanner_Plan_TeardownThreePackets(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Sequence: ... FIN(up), FIN-ACK(down), ACK(up) — exactly 3 teardown
	// packets, with the intermediate ACK merged into the server FIN.
	finCount := 0
	lastThree := configs[len(configs)-3:]
	if len(lastThree) != 3 {
		t.Fatalf("expected 3 teardown packets, got %d", len(lastThree))
	}
	for _, c := range lastThree {
		if c.L4.Flags&0x01 != 0 {
			finCount++
		}
	}
	if finCount != 2 {
		t.Errorf("expected 2 FIN packets in teardown (up + down FIN-ACK), got %d", finCount)
	}
	if lastThree[1].L4.Flags != 0x11 || lastThree[1].Direction != "down" {
		t.Errorf("teardown packet 2 should be down FIN-ACK (0x11), got flags=%x dir=%s",
			lastThree[1].L4.Flags, lastThree[1].Direction)
	}
	if lastThree[2].L4.Flags != 0x10 || lastThree[2].Direction != "up" {
		t.Errorf("teardown packet 3 should be up ACK (0x10), got flags=%x dir=%s",
			lastThree[2].L4.Flags, lastThree[2].Direction)
	}
}

// --- API key in query (design doc T096) ---

func TestPlanner_Plan_APIKeyQuery(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Auth: A2AAuth{Scheme: "apikey", APIKey: "k-123", APIKeyName: "api_key", APIKeyIn: "query"},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	found := false
	for _, c := range configs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), "message/send") {
				found = true
				if !strings.Contains(string(c.Payload), "POST /a2a?api_key=k-123") {
					t.Errorf("request line should carry API key in query, got %q",
						string(c.Payload)[:min(len(c.Payload), 60)])
				}
			}
		}
	}
	if !found {
		t.Errorf("request segment not found")
	}
}

// --- BaseURL path extraction ---

func TestPlanner_Plan_BaseURLPath(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/api/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/api/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	found := false
	for _, c := range configs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), "message/send") {
				found = true
				if !strings.Contains(string(c.Payload), "POST /api/a2a HTTP/1.1") {
					t.Errorf("request line should use BaseURL path /api/a2a, got %q",
						string(c.Payload)[:min(len(c.Payload), 60)])
				}
			}
		}
	}
	if !found {
		t.Errorf("request segment not found")
	}
}

// --- V6: Security references must exist in SecuritySchemes ---

func TestPlanner_Validate_SecuritySchemeMissing(t *testing.T) {
	p := NewPlanner()
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
			Security:           []map[string][]string{{"noSuchScheme": {}}},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V6") {
		t.Errorf("expected V6 security scheme reference error, got: %v", err)
	}
}

// --- BUG-1 + BUG-2: explicit JSON null id preserved (JSON-RPC 2.0 §6.11.2) ---

// TestUnmarshalID_ExplicitNull verifies that a json.RawMessage carrying the
// literal JSON null is returned as json.RawMessage("null") — NOT as Go nil —
// so the caller can distinguish "explicit null" from "absent id".
func TestUnmarshalID_ExplicitNull(t *testing.T) {
	got := unmarshalID(json.RawMessage(`null`))
	if string(got) != "null" {
		t.Errorf("unmarshalID(null) = %q, want %q (explicit null must not become Go nil)", string(got), "null")
	}
}

// TestUnmarshalID_Empty verifies the empty RawMessage path: unmarshalID
// returns an empty RawMessage so callers can substitute their default.
func TestUnmarshalID_Empty(t *testing.T) {
	got := unmarshalID(json.RawMessage{})
	if len(got) != 0 {
		t.Errorf("unmarshalID(empty) = %q, want empty RawMessage", string(got))
	}
}

// TestUnmarshalID_StringAndNumber verifies valid JSON id values pass through
// unchanged for downstream embedding.
func TestUnmarshalID_StringAndNumber(t *testing.T) {
	if got := unmarshalID(json.RawMessage(`"req-001"`)); string(got) != `"req-001"` {
		t.Errorf("unmarshalID(string) = %q, want preserved", string(got))
	}
	if got := unmarshalID(json.RawMessage(`42`)); string(got) != `42` {
		t.Errorf("unmarshalID(number) = %q, want preserved", string(got))
	}
}

// TestResolveIDForOutput_ExplicitNullPreserved verifies that an explicit
// null id is NOT substituted with "req-001" — it serializes as JSON null.
func TestResolveIDForOutput_ExplicitNullPreserved(t *testing.T) {
	got := resolveIDForOutput(json.RawMessage("null"))
	if string(got) != "null" {
		t.Errorf("resolveIDForOutput(null) = %q, want %q (must not substitute default for explicit null)",
			string(got), "null")
	}
}

// TestResolveIDForOutput_EmptySubstitutesDefault verifies the fallback
// when RequestID was truly absent (not just explicit null).
func TestResolveIDForOutput_EmptySubstitutesDefault(t *testing.T) {
	got := resolveIDForOutput(json.RawMessage{})
	if string(got) != `"req-001"` {
		t.Errorf("resolveIDForOutput(empty) = %q, want %q", string(got), `"req-001"`)
	}
}

// TestBuildJSONRPCRequest_NullID emits a JSON-RPC request body whose id is
// the literal JSON null (BUG-1: was previously rewritten to "req-001").
func TestBuildJSONRPCRequest_NullID(t *testing.T) {
	task := A2ATask{
		Method:    MethodMessageSend,
		RequestID: json.RawMessage("null"),
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "hello"}},
			MessageID: "m-001",
		},
	}
	b := buildJSONRPCRequest(&A2AConfig{}, task, MethodMessageSend)

	var req map[string]any
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	// JSON null decodes into map[string]any as Go nil.
	if req["id"] != nil {
		t.Errorf("id = %v, want JSON null (Go nil after round-trip), got %T", req["id"], req["id"])
	}
	// Also assert the raw body contains the literal "null" — this catches
	// the pre-fix bug where json.Marshal would have omitted the key entirely.
	if !strings.Contains(string(b), `"id":null`) {
		t.Errorf("raw request body must carry literal \"id\":null, got %q", string(b))
	}
}

// TestPlan_NullID_ResponsePreservesNull drives the full Plan pipeline with a
// task whose RequestID is literal JSON null and asserts that BOTH the
// request body (up) and response body (down) carry "id":null (BUG-1 + BUG-2).
func TestPlan_NullID_ResponsePreservesNull(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageSend,
				RequestID: json.RawMessage("null"), // BUG-1/BUG-2 trigger
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task","id":"task-001","contextId":"ctx-001","status":{"state":"completed"}}`),
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	sawRequestWithNullID := false
	sawResponseWithNullID := false
	for _, c := range configs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), `"method":"message/send"`) {
				if !strings.Contains(string(c.Payload), `"id":null`) {
					t.Errorf("up request must carry literal \"id\":null, got: %q",
						string(c.Payload))
				} else {
					sawRequestWithNullID = true
				}
			}
		}
		if c.Direction == "down" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), `"result":`) {
				if !strings.Contains(string(c.Payload), `"id":null`) {
					t.Errorf("down response must carry literal \"id\":null, got: %q",
						string(c.Payload))
				} else {
					sawResponseWithNullID = true
				}
			}
		}
	}
	if !sawRequestWithNullID {
		t.Errorf("did not observe any up request with explicit null id (BUG-1 not fixed)")
	}
	if !sawResponseWithNullID {
		t.Errorf("did not observe any down response with explicit null id (BUG-2 not fixed)")
	}
}

// TestPlan_NullID_ErrorResponsePreservesNull is the error-branch counterpart:
// when Response.Error is set, the id field on the JSON-RPC error envelope
// must still be literal null per §6.11.2.
func TestPlan_NullID_ErrorResponsePreservesNull(t *testing.T) {
	p := NewPlanner()

	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageSend,
				RequestID: json.RawMessage("null"),
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				Response: A2ATaskResponse{
					StatusCode: 400,
					Error: &A2AError{
						Code:    JSONRPCParseError,
						Message: "parse error",
					},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	sawErrorWithNullID := false
	for _, c := range configs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			if strings.Contains(string(c.Payload), `"error":`) {
				if !strings.Contains(string(c.Payload), `"id":null`) {
					t.Errorf("down error response must carry literal \"id\":null, got: %q",
						string(c.Payload))
				} else {
					sawErrorWithNullID = true
				}
			}
		}
	}
	if !sawErrorWithNullID {
		t.Errorf("did not observe error response with explicit null id (BUG-2 not fixed on error path)")
	}
}

// TestPlanner_Validate_NullIDAccepted confirms that V8 validation treats
// an explicit JSON null as a valid RequestID (§6.11.2 allows it).
func TestPlanner_Validate_NullIDAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method:    MethodMessageSend,
				RequestID: json.RawMessage("null"),
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() with null id must NOT return error per §6.11.2, got: %v", err)
	}
}

// --- SSE response stream also uses resolveIDForOutput ---
func TestBuildSSEResponse_NullID(t *testing.T) {
	task := A2ATask{
		Method:    MethodMessageStream,
		Streaming: true,
		RequestID: json.RawMessage("null"),
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "stream"}},
			MessageID: "m-002",
		},
		SSEEvents: []A2ASSEEvent{
			{
				Kind: "task",
				Task: &A2ATaskObject{
					ID:        "task-002",
					ContextID: "ctx-002",
					Status:    A2ATaskStatus{State: TaskStateSubmitted},
					Kind:      DefaultTaskKind,
				},
			},
		},
	}
	b := buildSSEResponse(&A2AConfig{}, task)
	if !strings.Contains(string(b), `"id":null`) {
		t.Errorf("SSE event must carry literal \"id\":null, got %q", string(b))
	}
}

// --- Bug #1: TCP Handshake/Termination 显式 false 必须被尊重 ---

// boolPtr 是 A2ATCP.Handshake/Termination 字段的辅助构造器。
func boolPtr(v bool) *bool { return &v }

// minimalA2AConfig 构造一个最小可用 A2AConfig，供 Bug 测试复用。
func minimalA2AConfig() *A2AConfig {
	return &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
			},
		},
	}
}

// TestPlanner_Plan_HandshakeExplicitFalseDisabled 断言当 TCP.Handshake
// 被显式设为 false 时，Plan 输出不含 SYN/SYN-ACK/ACK 握手包。
// 此前实现因 bool 零值与显式 false 不可区分，将显式 false 强制覆盖为 true。
func TestPlanner_Plan_HandshakeExplicitFalseDisabled(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.TCP.Handshake = boolPtr(false) // 显式禁用握手

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}
	if len(configs) == 0 {
		t.Fatalf("no packets emitted")
	}
	// 第一个包不应是 SYN（0x02）。握手被禁用时第一个包应是数据/挥手。
	if configs[0].L4.Flags == 0x02 {
		t.Errorf("Handshake=false 但仍输出 SYN，说明显式 false 被强制覆盖为 true")
	}
	// 全程不应出现 SYN。
	for i, c := range configs {
		if c.L4.Flags == 0x02 {
			t.Errorf("packet[%d] 是 SYN，Handshake=false 应完全跳过握手", i)
		}
	}
}

// TestPlanner_Plan_TerminationExplicitFalseDisabled 断言当
// TCP.Termination 被显式设为 false 时，Plan 输出不含 FIN 挥手包。
func TestPlanner_Plan_TerminationExplicitFalseDisabled(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.TCP.Termination = boolPtr(false) // 显式禁用挥手

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}
	for i, c := range configs {
		if c.L4.Flags&0x01 != 0 {
			t.Errorf("packet[%d] 含 FIN 标志，Termination=false 应完全跳过挥手", i)
		}
	}
}

// TestPlanner_Plan_HandshakeNilDefaultsTrue 断言当 TCP.Handshake 为 nil
// （未设置）时，Plan 输出包含握手包，确认默认 true 行为保留。
func TestPlanner_Plan_HandshakeNilDefaultsTrue(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	// Handshake/Termination 不设置（nil）

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}
	if len(configs) == 0 || configs[0].L4.Flags != 0x02 {
		t.Errorf("Handshake=nil 应默认 true，第一个包应是 SYN")
	}
}

// --- Bug #2: SSE chunked 编码必须对 body 分帧 ---

// TestPlanner_Plan_SSEChunkedBodyEncoded 断言 SSE 响应的 body 按 HTTP/1.1
// chunked 传输编码分帧（RFC 7230 §4.1）：hex 长度行 + body + CRLF + 0 结束。
// 此前实现只写 Transfer-Encoding 头但 body 原样输出。
func TestPlanner_Plan_SSEChunkedBodyEncoded(t *testing.T) {
	p := NewPlanner()
	cfg := &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{Streaming: true},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageStream, Streaming: true,
				Message: A2AMessage{
					Role: "user", Parts: []A2APart{{Kind: "text", Text: "stream"}},
					MessageID: "m-002",
				},
				RequestID: json.RawMessage(`"req-002"`),
				SSEEvents: []A2ASSEEvent{
					{Kind: "task", Task: &A2ATaskObject{ID: "task-002", ContextID: "ctx-002", Status: A2ATaskStatus{State: TaskStateSubmitted}, Kind: DefaultTaskKind}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateWorking}, Final: false}},
					{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{TaskID: "task-002", ContextID: "ctx-002", Kind: DefaultStatusUpdateKind, Status: A2ATaskStatus{State: TaskStateCompleted}, Final: true}},
				},
			},
		},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	for _, c := range configs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		s := string(c.Payload)
		if !strings.Contains(s, "Transfer-Encoding: chunked") {
			continue
		}
		// 定位 header/body 边界
		idx := strings.Index(s, "\r\n\r\n")
		if idx < 0 {
			t.Fatalf("chunked 响应缺少 header/body 分隔符")
		}
		body := s[idx+4:]
		// body 必须以 hex 长度行开头，后接 CRLF
		eol := strings.Index(body, "\r\n")
		if eol < 0 {
			t.Fatalf("chunked body 缺少第一个 chunk 的长度行 CRLF")
		}
		lenLine := body[:eol]
		chunkLen, convErr := strconv.ParseInt(lenLine, 16, 64)
		if convErr != nil {
			t.Errorf("chunk 长度行 %q 不是合法十六进制：chunked body 未编码", lenLine)
			continue
		}
		// 校验 chunk 数据长度与声明一致
		dataStart := eol + 2
		if int64(len(body)-dataStart) < chunkLen+2 {
			t.Errorf("chunk 数据长度不足：声明 %d 字节但剩余 %d 字节", chunkLen, len(body)-dataStart)
			continue
		}
		chunkData := body[dataStart : dataStart+int(chunkLen)]
		if !strings.Contains(chunkData, "data: {") {
			t.Errorf("chunk 数据应包含 SSE data: 行，got %q", chunkData[:min(len(chunkData), 60)])
		}
		// body 必须以结束 chunk 0\r\n\r\n 收尾
		if !strings.HasSuffix(body, "0\r\n\r\n") {
			t.Errorf("chunked body 必须以 0\\r\\n\\r\\n 结束，got tail %q", body[max(0, len(body)-12):])
		}
		return // 找到 chunked 响应并校验通过
	}
	t.Errorf("未找到 chunked SSE 响应")
}

// --- Bug #3: Plan goroutine 必须响应 ctx 取消 ---

// TestPlanner_Plan_ContextCancelExitsGoroutine 断言当 ctx 被取消且消费者
// 停止读取 channel 后，Plan goroutine 不会泄漏（能在合理时间内退出）。
// 此前实现完全忽略 ctx，取消后 goroutine 永久阻塞于 configChan <- cfg。
func TestPlanner_Plan_ContextCancelExitsGoroutine(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	ctx, cancel := context.WithCancel(context.Background())
	configChan, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// 读取第一个包（SYN）后立即取消 ctx 并停止读取 channel。
	// goroutine 仍会尝试发送剩余的 ~9 个包到 buffered channel（cap=256），
	// 由于 buffer 足够大，发送不会阻塞；但取消后 goroutine 应尽快退出。
	select {
	case <-configChan:
	case <-time.After(2 * time.Second):
		t.Fatalf("Plan 未在超时前发出第一个包")
	}
	cancel()

	// channel 必须最终被关闭（goroutine 退出），不会永远挂起。
	select {
	case _, ok := <-configChan:
		// 持续读取直到关闭
		for ok {
			_, ok = <-configChan
		}
	case <-time.After(5 * time.Second):
		t.Errorf("ctx 取消后 5 秒 channel 仍未关闭，goroutine 泄漏")
	}
}

// TestPlanner_Plan_PreCancelledContextExitsImmediately 断言 ctx 在 Plan
// 返回前已被取消时，goroutine 立即退出且不发送任何包。
func TestPlanner_Plan_PreCancelledContextExitsImmediately(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: a2aConfigToPayload(cfg),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 提前取消

	configChan, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	count := 0
	for range configChan {
		count++
		if count > 100 {
			t.Fatalf("提前取消的 ctx 仍持续发包，goroutine 未响应取消")
		}
	}
}

// --- Bug #4: ParamsMetadata 必须嵌套到 params.metadata ---

// TestBuildJSONRPCRequest_ParamsMetadataNested 断言 ParamsMetadata 的
// 内容出现在 params.metadata 子对象中，而不是展开到 params 顶层。
// 此前实现把每个 key 直接写入 params 顶层，污染标准字段。
func TestBuildJSONRPCRequest_ParamsMetadataNested(t *testing.T) {
	task := A2ATask{
		Method:    MethodMessageSend,
		RequestID: json.RawMessage(`"req-001"`),
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "hello"}},
			MessageID: "m-001",
		},
		ParamsMetadata: map[string]any{
			"traceId": "trace-xyz",
			"region":  "cn-north-1",
		},
	}
	b := buildJSONRPCRequest(&A2AConfig{}, task, MethodMessageSend)

	var req struct {
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	md, ok := req.Params["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("params.metadata 缺失或类型错误，params 顶层 keys: %v", mapKeys(req.Params))
	}
	if md["traceId"] != "trace-xyz" {
		t.Errorf("params.metadata.traceId = %v, want trace-xyz", md["traceId"])
	}
	if md["region"] != "cn-north-1" {
		t.Errorf("params.metadata.region = %v, want cn-north-1", md["region"])
	}
	// 顶层不得出现 traceId/region（此前 bug 行为）。
	if _, topLevel := req.Params["traceId"]; topLevel {
		t.Errorf("traceId 不应出现在 params 顶层（应嵌套在 params.metadata 下）")
	}
	if _, topLevel := req.Params["region"]; topLevel {
		t.Errorf("region 不应出现在 params 顶层（应嵌套在 params.metadata 下）")
	}
	// 标准字段 message 必须保留。
	if _, ok := req.Params["message"]; !ok {
		t.Errorf("params.message 缺失，ParamsMetadata 不应覆盖标准字段")
	}
}

// TestBuildJSONRPCRequest_ParamsMetadataEmptyOmitted 断言 ParamsMetadata
// 为空时，params 中不出现 metadata 键。
func TestBuildJSONRPCRequest_ParamsMetadataEmptyOmitted(t *testing.T) {
	task := A2ATask{
		Method:    MethodMessageSend,
		RequestID: json.RawMessage(`"req-001"`),
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "hello"}},
			MessageID: "m-001",
		},
	}
	b := buildJSONRPCRequest(&A2AConfig{}, task, MethodMessageSend)
	if strings.Contains(string(b), `"metadata"`) {
		t.Errorf("ParamsMetadata 为空时不应输出 metadata 键，got %q", string(b))
	}
}

// mapKeys 返回 map 的所有 key，用于测试诊断信息。
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// --- Bug #5: V4 校验 Kind=file 时 File 必须非 nil ---

// TestPlanner_Validate_FilePartRequiresFile 断言 Kind=file 但 File 为 nil
// 的 Part 被 Validate 拒绝。此前实现只检查互斥字段，漏掉 File 本身缺失。
func TestPlanner_Validate_FilePartRequiresFile(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Message.Parts = []A2APart{{Kind: "file"}} // File 为 nil

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("Kind=file 且 File=nil 必须被 V4 拒绝，但 Validate 通过")
	}
	if !strings.Contains(err.Error(), "V4") {
		t.Errorf("错误应标注 V4，got: %v", err)
	}
}

// TestPlanner_Validate_FilePartWithFileAccepted 断言 Kind=file 且 File 非
// nil 时校验通过（FileWithBytes 与 FileWithUri 两种形式）。
func TestPlanner_Validate_FilePartWithFileAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Message.Parts = []A2APart{
		{Kind: "file", File: &A2AFile{Name: "a.txt", MimeType: "text/plain", Bytes: "aGVsbG8="}},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("FileWithBytes 的 file Part 应通过校验，got: %v", err)
	}

	cfg2 := minimalA2AConfig()
	cfg2.Tasks[0].Message.Parts = []A2APart{
		{Kind: "file", File: &A2AFile{Name: "b.bin", MimeType: "application/octet-stream", URI: "https://agent.example.com/files/b.bin"}},
	}
	spec2 := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg2),
	}
	if err := p.Validate(spec2); err != nil {
		t.Errorf("FileWithUri 的 file Part 应通过校验，got: %v", err)
	}
}

// --- Bug #6: V12 校验 id 类型白名单 ---

// TestPlanner_Validate_RequestIDTypeObjectRejected 断言 JSON object 作为
// JSON-RPC id 被 V12 拒绝（spec §2.10 仅允许 string/integer/null）。
// 此前实现 string 与 json.Number 解析都失败时静默放行。
func TestPlanner_Validate_RequestIDTypeObjectRejected(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].RequestID = json.RawMessage(`{"x":1}`) // object 类型

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("object 类型 id 必须被 V12 拒绝，但 Validate 通过")
	}
	if !strings.Contains(err.Error(), "V12") {
		t.Errorf("错误应标注 V12，got: %v", err)
	}
}

// TestPlanner_Validate_RequestIDTypeArrayRejected 断言 array 类型 id 被拒绝。
func TestPlanner_Validate_RequestIDTypeArrayRejected(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].RequestID = json.RawMessage(`[1,2,3]`) // array 类型

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V12") {
		t.Errorf("array 类型 id 应被 V12 拒绝，got: %v", err)
	}
}

// TestPlanner_Validate_RequestIDTypeFloatRejected 断言浮点 id（如 1.5）
// 被拒绝（spec 限定 integer，1.5 不是合法 id）。
func TestPlanner_Validate_RequestIDTypeFloatRejected(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].RequestID = json.RawMessage(`1.5`) // 浮点

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}

	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V12") {
		t.Errorf("浮点 id 应被 V12 拒绝，got: %v", err)
	}
}

// TestPlanner_Validate_RequestIDNullStillAccepted 断言显式 null id 仍被
// 接受（§6.11.2 允许），V12 白名单不能误伤 null。
func TestPlanner_Validate_RequestIDNullStillAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].RequestID = json.RawMessage(`null`)

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("显式 null id 应通过校验（§6.11.2），got: %v", err)
	}
}

// TestPlanner_Validate_RequestIDIntegerAccepted 断言合法 integer id 通过。
func TestPlanner_Validate_RequestIDIntegerAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].RequestID = json.RawMessage(`42`)

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("integer id 应通过校验，got: %v", err)
	}
}

// --- N1: V16 视 null Result 为未设置，不与 Error 互斥 ---

// TestPlanner_Validate_V16_NullResultWithErrorAccepted 断言当
// A2ATaskResponse.Result 为字面 JSON null 时，即使 Error 非空，V16 也不应
// 报"result 与 error 互斥"。N1 修复前：omitempty 让 null 不再被输出，
// 但 V16 仍按 len(Result)>0 判定，对 `null`（4 字节）误报互斥。
func TestPlanner_Validate_V16_NullResultWithErrorAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Response = A2ATaskResponse{
		Result: json.RawMessage(`null`), // 显式 null：视为未设置
		Error:  &A2AError{Code: JSONRPCTaskNotFound, Message: "not found"},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("null Result + Error 应通过 V16（null 视为未设置），got: %v", err)
	}
}

// TestPlanner_Validate_V16_RealResultWithErrorStillRejected 断言携带实际
// JSON 值（非 null/空白）的 Result 仍与 Error 互斥。N1 修复后此路径必须
// 保留——只有 null/空/空白被豁免，真实对象仍触发 V16。
func TestPlanner_Validate_V16_RealResultWithErrorStillRejected(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Response = A2ATaskResponse{
		Result: json.RawMessage(`{"kind":"task","id":"t1"}`),
		Error:  &A2AError{Code: JSONRPCTaskNotFound, Message: "not found"},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "V16") {
		t.Errorf("真实 Result + Error 必须仍被 V16 拒绝，got: %v", err)
	}
}

// TestPlanner_Validate_V16_EmptyResultWithErrorAccepted 断言当
// A2ATaskResponse.Result 为空（nil RawMessage）且 Error 非空时，V16 不应
// 报"result 与 error 互斥"。N1 修复前：omitempty 让空 Result 不再被输出，
// 但 V16 仍按 len(Result)>0 判定——空 Result 已 len==0 不触发，确认该路径
// 在 N1 修复后无回归。
//
// 注：纯空白 Result（"   "）会破坏 json.Marshal（invalid JSON），无法通过
// a2aConfigToPayload 序列化路径触发 Validate，故该形态仅在 TestIsResultSet
// 中直接驱动 isResultSet 单元测试覆盖。
func TestPlanner_Validate_V16_EmptyResultWithErrorAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Response = A2ATaskResponse{
		Result: json.RawMessage(nil), // 空：视为未设置
		Error:  &A2AError{Code: JSONRPCTaskNotFound, Message: "not found"},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("空 Result + Error 应通过 V16（视为未设置），got: %v", err)
	}
}

// TestIsResultSet 边界用例：直接驱动 isResultSet 覆盖空/null/空白/真实值
// 四种形态，确保 N1 修复的判定函数行为稳定。
func TestIsResultSet(t *testing.T) {
	cases := []struct {
		name string
		in   json.RawMessage
		want bool
	}{
		{"empty", json.RawMessage(nil), false},
		{"null", json.RawMessage(`null`), false},
		{"null_with_spaces", json.RawMessage(`  null  `), false},
		{"whitespace_only", json.RawMessage(`   `), false},
		{"real_object", json.RawMessage(`{"kind":"task"}`), true},
		{"real_array", json.RawMessage(`[1,2,3]`), true},
		{"string_value", json.RawMessage(`"hello"`), true},
	}
	for _, c := range cases {
		if got := isResultSet(c.in); got != c.want {
			t.Errorf("isResultSet[%s] = %v, want %v", c.name, got, c.want)
		}
	}
}

// --- N2: A2ATask.RequestID 加 omitempty ---

// TestA2ATask_RequestID_OmitemptyWhenAbsent 断言当 RequestID 未设置（nil
// RawMessage）时，A2ATask 序列化后的 JSON 不包含 "requestId" 键。N2 修复
// 前：无 omitempty 标签，nil RawMessage 输出为 `"requestId":null`，污染
// 请求/响应载荷并可能误导对端 Agent。
func TestA2ATask_RequestID_OmitemptyWhenAbsent(t *testing.T) {
	task := A2ATask{
		Method: MethodMessageSend,
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "hi"}},
			MessageID: "m-1",
		},
		// RequestID 故意不设置
	}
	b, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"requestId"`) {
		t.Errorf("未设置的 RequestID 应被 omitempty 省略，got: %s", string(b))
	}
}

// TestA2ATask_RequestID_SerializedWhenPresent 断言当 RequestID 设置后，
// 序列化输出包含 "requestId" 键且值正确。N2 修复后必须保留正向路径，避免
// omitempty 误伤显式赋值的场景。
func TestA2ATask_RequestID_SerializedWhenPresent(t *testing.T) {
	task := A2ATask{
		Method:    MethodMessageSend,
		RequestID: json.RawMessage(`"req-xyz"`),
		Message: A2AMessage{
			Role:      "user",
			Parts:     []A2APart{{Kind: "text", Text: "hi"}},
			MessageID: "m-1",
		},
	}
	b, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"requestId":"req-xyz"`) {
		t.Errorf("显式 RequestID 必须序列化输出，got: %s", string(b))
	}
}

// --- N3: V4 校验 file Part 必须携带 Bytes 或 URI ---

// TestPlanner_Validate_V4_FilePartEmptyBytesAndURIRejected 断言 Kind=file
// 且 File 非 nil 但 Bytes 与 URI 均为空时，V4 必须拒绝。N3 修复前：仅校验
// File 非 nil，放过 {"file":{}} 这种违反 spec anyOf 的退化报文。
func TestPlanner_Validate_V4_FilePartEmptyBytesAndURIRejected(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Message.Parts = []A2APart{
		{Kind: "file", File: &A2AFile{Name: "empty.txt", MimeType: "text/plain"}}, // Bytes 与 URI 均空
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("Bytes 与 URI 均空的 file Part 必须被 V4 拒绝")
	}
	if !strings.Contains(err.Error(), "V4") {
		t.Errorf("错误应标注 V4，got: %v", err)
	}
	if !strings.Contains(err.Error(), "Bytes or URI") {
		t.Errorf("错误消息应提及 Bytes 或 URI，got: %v", err)
	}
}

// TestPlanner_Validate_V4_FilePartWithURIOnlyAccepted 断言 Kind=file 且
// File 只携带 URI（不含 Bytes）时仍通过校验。N3 修复不得误伤合法的
// FileWithUri 形态。
func TestPlanner_Validate_V4_FilePartWithURIOnlyAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Message.Parts = []A2APart{
		{Kind: "file", File: &A2AFile{URI: "https://agent.example.com/f.bin"}},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("仅含 URI 的 file Part 应通过校验，got: %v", err)
	}
}

// --- N5: V9 拆为两段（Streaming 先行，SSEEvents 非空再进子规则） ---

// TestPlanner_Validate_V9_StreamingWithNoSSEEventsStillAccepted 断言当
// task.Streaming=true 但 SSEEvents 为空时，V9 不报错（仅跳过子规则）。
// N5 修复拆分后此路径必须保留——空 SSEEvents 不违法，仅意味着由 Plan
// 生成默认事件序列。
func TestPlanner_Validate_V9_StreamingWithNoSSEEventsStillAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Method = MethodMessageStream
	cfg.Tasks[0].Streaming = true
	// SSEEvents 故意留空

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Streaming=true + 空 SSEEvents 应通过 V9，got: %v", err)
	}
}

// TestPlanner_Validate_V9_NonStreamingWithSSEEventsSkipsSubrules 断言当
// task.Streaming=false 但配置了 SSEEvents 时，V9 子规则不触发（不报"首个
// 事件 kind 必须是 task/message"）。N5 修复拆分后，子规则只在
// Streaming=true 时进入；此用例确保非流式方法携带 SSEEvents 不会误触发
// V9 的"first event kind"检查（该方法本就属于 V8 Streaming 一致性范畴）。
func TestPlanner_Validate_V9_NonStreamingWithSSEEventsSkipsSubrules(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	// Streaming=false（默认）+ SSEEvents：V9 子规则不应触发。Method=
	// message/send 属 SyncMethods，V8 通过；V9 因 Streaming=false 整体跳过。
	cfg.Tasks[0].SSEEvents = []A2ASSEEvent{
		{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{
			TaskID: "t1", ContextID: "c1", Kind: DefaultStatusUpdateKind,
			Status: A2ATaskStatus{State: TaskStateWorking}, Final: true,
		}},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	err := p.Validate(spec)
	// 非流式方法携带 SSEEvents：V9 不应报"first event kind must be task
	// or message"——确认 N5 拆分后外层 Streaming 守卫仍生效。
	if err != nil && strings.Contains(err.Error(), "first SSE event kind") {
		t.Errorf("非流式方法不应触发 V9 first-event-kind 检查（N5 拆分未生效），got: %v", err)
	}
}

// TestPlanner_Validate_V9_StreamingWithValidSSEEventsAccepted 断言 N5 拆分
// 后，合法的流式配置（Streaming=true + 首事件 task + 末事件 final=true 的
// status-update）仍通过校验。这是回归保护：拆分不能破坏合法路径。
func TestPlanner_Validate_V9_StreamingWithValidSSEEventsAccepted(t *testing.T) {
	p := NewPlanner()
	cfg := minimalA2AConfig()
	cfg.Tasks[0].Method = MethodMessageStream
	cfg.Tasks[0].Streaming = true
	cfg.Tasks[0].SSEEvents = []A2ASSEEvent{
		{Kind: "task", Task: &A2ATaskObject{
			ID: "t1", ContextID: "c1", Status: A2ATaskStatus{State: TaskStateSubmitted},
			Kind: DefaultTaskKind,
		}},
		{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{
			TaskID: "t1", ContextID: "c1", Kind: DefaultStatusUpdateKind,
			Status: A2ATaskStatus{State: TaskStateWorking}, Final: false,
		}},
		{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{
			TaskID: "t1", ContextID: "c1", Kind: DefaultStatusUpdateKind,
			Status: A2ATaskStatus{State: TaskStateCompleted}, Final: true,
		}},
	}

	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		Payload: a2aConfigToPayload(cfg),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("合法流式配置应通过 V9（N5 拆分未破坏合法路径），got: %v", err)
	}
}

// Helper to wrap A2AConfig in FlowSpec
func a2aConfigToPayload(cfg *A2AConfig) []byte {
	b, _ := json.Marshal(cfg)
	return b
}
