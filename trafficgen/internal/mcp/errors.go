// Package mcp implements the MCP (Model Context Protocol) server for flowB,
// exposing trafficgen's backend capabilities to LLM clients.
package mcp

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// backendResponse mirrors rest.Response for parsing gin handler outputs.
// The REST layer writes {code, message, data} JSON; we parse it here to
// translate backend status codes into MCP errors.
type backendResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// parseBackendResponse reads the gin handler's JSON response from the recorder.
func parseBackendResponse(w *httptest.ResponseRecorder) (*backendResponse, error) {
	var resp backendResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse backend response (body=%q): %w", w.Body.String(), err)
	}
	return &resp, nil
}

// backendError maps a backend Response.Code to a jsonrpc.Error.
// See docs/mcp-design.md §8.1.
//
// code=0 (success) and code=409 (idempotent hit, treated as success) are
// handled by the caller; this function is only invoked for actual error codes.
func backendError(code int, message string) *jsonrpc.Error {
	switch code {
	case 400:
		return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: message}
	case 401:
		// service account config error (should not happen in normal flow;
		// MCP injects userID internally so auth middleware is bypassed)
		return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "service account config error: " + message}
	case 403, 404:
		return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: message}
	case 500:
		return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: message}
	default:
		return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: fmt.Sprintf("backend code %d: %s", code, message)}
	}
}

// rawData unmarshals a JSON RawMessage into interface{} for use in MCP output
// structs. The MCP SDK v1.6.1 generates an overly-restrictive JSON schema for
// json.RawMessage (it sees []byte = []uint8, emits {"type":["null","array"],
// "items":{"type":"integer"}}) which then fails validation when the actual
// payload is a JSON object or array of objects. Using interface{} produces an
// unconstrained schema, and unmarshalling first ensures the value serializes
// as the original JSON rather than base64-encoded bytes.
func rawData(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

// asRaw marshals an interface{} (typically an MCP output Data field) back to
// json.RawMessage. Used by tests that need to inspect structured content via
// json.Unmarshal or string conversion.
func asRaw(v interface{}) json.RawMessage {
	if v == nil {
		return nil
	}
	if raw, ok := v.(json.RawMessage); ok {
		return raw
	}
	b, _ := json.Marshal(v)
	return b
}
