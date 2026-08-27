package jsonrpc

import (
	"testing"
)

func TestVersion(t *testing.T) {
	if Version != "2.0" {
		t.Errorf("Version = %q, want %q", Version, "2.0")
	}
}

// TestMarshalAlphabetical verifies Marshal uses encoding/json's canonical
// (alphabetical) ordering, which is a2a's wire-format style.
func TestMarshalAlphabetical(t *testing.T) {
	b, err := Marshal(map[string]any{
		"params":  map[string]any{},
		"method":  "message/send",
		"id":      "req-001",
		"jsonrpc": Version,
	})
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	want := `{"id":"req-001","jsonrpc":"2.0","method":"message/send","params":{}}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}

// TestMarshalOrdered_Request verifies the ordered style used by mcp's
// buildRequest: "jsonrpc","id","method","params" first, remainder sorted.
func TestMarshalOrdered_Request(t *testing.T) {
	b, err := MarshalOrdered(map[string]any{
		"jsonrpc": Version,
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{},
	}, "jsonrpc", "id", "method", "params", "result", "error")
	if err != nil {
		t.Fatalf("MarshalOrdered error: %v", err)
	}
	want := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	if string(b) != want {
		t.Errorf("MarshalOrdered = %s, want %s", string(b), want)
	}
}

// TestMarshalOrdered_ErrorResponse verifies the error envelope ordering with
// a nil id (JSON-RPC 2.0 §6.11.2: parse-error responses use id:null) and a
// nested error object emitted with its keys alphabetized.
func TestMarshalOrdered_ErrorResponse(t *testing.T) {
	b, err := MarshalOrdered(map[string]any{
		"jsonrpc": Version,
		"id":      nil,
		"error": map[string]any{
			"code":    -32700,
			"message": "Parse error",
		},
	}, "jsonrpc", "id", "error", "result")
	if err != nil {
		t.Fatalf("MarshalOrdered error: %v", err)
	}
	want := `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`
	if string(b) != want {
		t.Errorf("MarshalOrdered = %s, want %s", string(b), want)
	}
}

// TestMarshalOrdered_RemainderSorted verifies keys not in `order` are emitted
// afterwards in sorted order (extra keys sorted alphabetically).
func TestMarshalOrdered_RemainderSorted(t *testing.T) {
	b, err := MarshalOrdered(map[string]any{
		"z_last":  true,
		"a_first": 2,
		"mid":     "x",
	}, "mid")
	if err != nil {
		t.Fatalf("MarshalOrdered error: %v", err)
	}
	want := `{"mid":"x","a_first":2,"z_last":true}`
	if string(b) != want {
		t.Errorf("MarshalOrdered = %s, want %s", string(b), want)
	}
}

// TestMarshalValue verifies integer encoding (id:1 not id:1.0), bool, nil,
// nested map, and array handling.
func TestMarshalValue(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"int", 1, "1"},
		{"int64", int64(-3), "-3"},
		{"uint16", uint16(42), "42"},
		{"string", "hi", `"hi"`},
		{"true", true, "true"},
		{"false", false, "false"},
		{"array", []any{1, "a", true}, `[1,"a",true]`},
		{"object", map[string]any{"b": 2, "a": 1}, `{"a":1,"b":2}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := marshalValue(tc.in)
			if err != nil {
				t.Fatalf("marshalValue error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("marshalValue(%v) = %s, want %s", tc.in, string(got), tc.want)
			}
		})
	}
}
