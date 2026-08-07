package a2a

// parser.go provides packet parsing helpers for A2A protocol.
// These functions extract JSON-RPC requests/responses from captured payloads.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParsedJSONRPCRequest represents a parsed JSON-RPC request.
type ParsedJSONRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      any            `json:"id"`
}

// ParsedJSONRPCResponse represents a parsed JSON-RPC response.
type ParsedJSONRPCResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	Result  map[string]any `json:"result,omitempty"`
	Error   *A2AError      `json:"error,omitempty"`
	ID      any            `json:"id"`
}

// ParsedSSEEvent represents a parsed SSE event.
type ParsedSSEEvent struct {
	JSONRPC string         `json:"jsonrpc"`
	Result  map[string]any `json:"result,omitempty"`
	Error   *A2AError      `json:"error,omitempty"`
	ID      any            `json:"id"`
}

// ParseJSONRPCRequest parses a JSON-RPC request from a byte slice.
func ParseJSONRPCRequest(data []byte) (*ParsedJSONRPCRequest, error) {
	var req ParsedJSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC request: %w", err)
	}
	if req.JSONRPC != "2.0" {
		return nil, fmt.Errorf("invalid jsonrpc version: %q", req.JSONRPC)
	}
	if req.Method == "" {
		return nil, fmt.Errorf("missing method field")
	}
	return &req, nil
}

// ParseJSONRPCResponse parses a JSON-RPC response from a byte slice.
func ParseJSONRPCResponse(data []byte) (*ParsedJSONRPCResponse, error) {
	var resp ParsedJSONRPCResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}
	if resp.JSONRPC != "2.0" {
		return nil, fmt.Errorf("invalid jsonrpc version: %q", resp.JSONRPC)
	}
	if resp.Result != nil && resp.Error != nil {
		return nil, fmt.Errorf("result and error are mutually exclusive")
	}
	return &resp, nil
}

// ParseSSEStream parses an SSE stream into individual events.
// SSE events are separated by double newline ("\n\n").
// Each event starts with "data: " prefix.
func ParseSSEStream(data []byte) ([]ParsedSSEEvent, error) {
	var events []ParsedSSEEvent
	body := string(data)

	// Extract SSE data lines
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		payload = strings.TrimSpace(payload)
		if payload == "" {
			continue
		}

		var event ParsedSSEEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, fmt.Errorf("parse SSE event: %w", err)
		}
		if event.JSONRPC != "2.0" {
			return nil, fmt.Errorf("invalid jsonrpc version in SSE event: %q", event.JSONRPC)
		}
		events = append(events, event)
	}

	return events, nil
}

// ExtractHTTPBody extracts the HTTP body from a raw HTTP message.
// Returns the body and the Content-Type header value.
func ExtractHTTPBody(data []byte) (body []byte, contentType string, err error) {
	s := string(data)
	// Find the double CRLF that separates headers from body
	idx := strings.Index(s, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(s, "\n\n")
		if idx < 0 {
			return nil, "", fmt.Errorf("no body separator found")
		}
		idx += 2
	} else {
		idx += 4
	}

	// Extract Content-Type
	lines := strings.Split(s[:idx], "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(s[:idx], "\n")
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "content-type: ") {
			contentType = strings.TrimPrefix(strings.ToLower(line), "content-type: ")
			break
		}
	}

	return data[idx:], contentType, nil
}

// IsJSONRPCRequest checks if the data is a JSON-RPC request.
func IsJSONRPCRequest(data []byte) bool {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, hasMethod := m["method"]
	return hasMethod
}

// IsJSONRPCResponse checks if the data is a JSON-RPC response.
func IsJSONRPCResponse(data []byte) bool {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, hasResult := m["result"]
	_, hasError := m["error"]
	return hasResult || hasError
}

// IsSSEStream checks if the data is an SSE stream.
func IsSSEStream(data []byte) bool {
	s := string(data)
	return strings.Contains(s, "data: ") && strings.Contains(s, "\n\n")
}

// GetJSONRPCMethod extracts the method name from a JSON-RPC request.
func GetJSONRPCMethod(data []byte) (string, error) {
	var req ParsedJSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return "", err
	}
	return req.Method, nil
}

// GetJSONRPCErrorCode extracts the error code from a JSON-RPC error response.
func GetJSONRPCErrorCode(data []byte) (int, error) {
	var resp struct {
		Error *A2AError `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, err
	}
	if resp.Error == nil {
		return 0, fmt.Errorf("no error in response")
	}
	return resp.Error.Code, nil
}

// IsValidMethod checks if a method name is a valid A2A method.
func IsValidMethod(method string) bool {
	return ValidMethods[method]
}

// IsValidTaskState checks if a state is a valid A2A task state.
func IsValidTaskState(state string) bool {
	return ValidTaskStates[state]
}

// IsTerminalState checks if a task state is a terminal state.
func IsTerminalState(state string) bool {
	switch state {
	case TaskStateCompleted, TaskStateCanceled, TaskStateFailed, TaskStateRejected, TaskStateUnknown:
		return true
	}
	return false
}

// IsStreamingMethod checks if a method uses SSE streaming.
func IsStreamingMethod(method string) bool {
	return StreamingMethods[method]
}
