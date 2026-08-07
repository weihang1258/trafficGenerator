package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// parseJSONRPC parses a single JSON-RPC 2.0 object into a generic map.
// Returns an error if the bytes are not a valid JSON object. Used by tests
// to round-trip emitted bytes (design §8 T01, T57, T60).
func parseJSONRPC(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("mcp: json decode failed: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mcp: top-level is not a JSON object (got %T)", v)
	}
	if obj["jsonrpc"] != "2.0" {
		return nil, fmt.Errorf("mcp: missing or wrong jsonrpc field (got %v)", obj["jsonrpc"])
	}
	return obj, nil
}

// checkDuplicateKeys scans a raw JSON object for duplicate keys at the
// TOP LEVEL only (nested objects are NOT recursively scanned; only the
// first-level key set is checked). Returns an error describing the
// duplicate key, or nil if unique.
//
// Per design §5.4 rule 5: JSON encoders differ on duplicate-key handling
// (Go last-wins, Python last-wins, JS first-wins), so the planner MUST
// reject duplicates to avoid semantic ambiguity.
func checkDuplicateKeys(raw json.RawMessage) error {
	// Walk the token stream to detect duplicate top-level keys. We do NOT
	// use json.Unmarshal into a map because that silently collapses
	// duplicates (Go's last-wins semantics).
	ts := json.NewDecoder(bytes.NewReader(raw))
	ts.UseNumber()
	t, err := ts.Token()
	if err != nil {
		return fmt.Errorf("mcp: capabilities not valid JSON: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("mcp: capabilities must be a JSON object")
	}
	seen := map[string]bool{}
	for ts.More() {
		keyTok, err := ts.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("mcp: non-string key in capabilities object")
		}
		if seen[key] {
			return fmt.Errorf("duplicate capability key %q", key)
		}
		seen[key] = true
		// Skip the value (object/array/scalar) by raw decode.
		var rawVal json.RawMessage
		if err := ts.Decode(&rawVal); err != nil {
			return err
		}
	}
	return nil
}

// splitSSELines splits a byte slice into SSE event payloads (one per
// event:message / event:endpoint pair). Each event is the bytes between
// `\n\n` delimiters (design §2.4 SSE format).
//
// Used by tests to validate T04 / T55 / T85 SSE event byte sequences.
func splitSSELines(data []byte) [][]byte {
	// Each event ends with "\n\n"; split and strip trailing blank lines.
	parts := bytes.Split(data, []byte("\n\n"))
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseSSEEvent extracts the `event:` type and `data:` payload from one
// SSE event block. Multiple `data:` lines are joined with "\n" per the SSE
// spec (design §2.4: "多行 data: 用 \n 连接后再解析"). Returns ("", nil,
// error) on parse failure.
func parseSSEEvent(block []byte) (eventType string, data []byte, err error) {
	lines := strings.Split(string(block), "\n")
	var dataParts []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			dataParts = append(dataParts, strings.TrimPrefix(line, "data: "))
		}
	}
	if eventType == "" {
		return "", nil, fmt.Errorf("mcp: SSE event missing `event:` field")
	}
	if len(dataParts) == 0 {
		return "", nil, fmt.Errorf("mcp: SSE event missing `data:` field")
	}
	return eventType, []byte(strings.Join(dataParts, "\n")), nil
}

// extractStatusLine returns the first line of an HTTP/1.x response (e.g.
// "HTTP/1.1 202 Accepted"). Used by tests T58 / T78 / T91.
func extractStatusLine(resp []byte) string {
	idx := bytes.Index(resp, []byte("\r\n"))
	if idx < 0 {
		return string(resp)
	}
	return string(resp[:idx])
}

// extractHeader returns the value of an HTTP header (case-insensitive name)
// from a request or response block. Used by tests.
func extractHeader(block []byte, name string) string {
	lines := strings.Split(string(block), "\r\n")
	needle := strings.ToLower(name) + ": "
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), needle) {
			return strings.TrimPrefix(line[len(needle)-2:], " ")
		}
	}
	return ""
}

// parseHTTPBody returns the body portion of an HTTP/1.x request/response
// (everything after the blank line \r\n\r\n).
func parseHTTPBody(block []byte) []byte {
	idx := bytes.Index(block, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return block[idx+4:]
}

// errCodeInRange returns true if c is within the JSON-RPC 2.0 spec
// reserved range [-32700, -32000] (design §4.4 rule 13).
func errCodeInRange(c int) bool {
	return c >= errCodeMin && c <= errCodeMax
}