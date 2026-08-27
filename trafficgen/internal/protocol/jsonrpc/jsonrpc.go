// Package jsonrpc provides reusable JSON-RPC 2.0 wire-format serialization
// shared by the a2a and mcp protocol planners.
//
// Both a2a and mcp build JSON-RPC 2.0 envelopes over HTTP: a request is
// {"jsonrpc":"2.0","method":...,"params":...,"id":...} and a response is
// {"jsonrpc":"2.0","result":...|"error":...,"id":...}. Historically each
// package reimplemented its own JSON emission. This package centralizes the
// two serialization styles the family needs:
//
//   - Marshal emits the map with keys in encoding/json's canonical
//     (alphabetical) order. a2a's wire format relies on this ordering.
//   - MarshalOrdered emits keys in an explicit order first, then the
//     remainder sorted. mcp's deterministic output (design appendix A) relies
//     on this ordering.
//
// The Version constant is the JSON-RPC 2.0 protocol literal, so both packages
// source the version from a single definition instead of a raw "2.0".
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Version is the JSON-RPC 2.0 protocol version literal.
const Version = "2.0"

// Marshal serializes m to JSON using the standard library, which emits map
// keys in sorted (alphabetical) order. This is the a2a wire-format style.
func Marshal(m map[string]any) ([]byte, error) {
	return json.Marshal(m)
}

// MarshalOrdered serializes m to JSON with keys emitted in `order` first (in
// the given order), then any remaining keys in sorted order. This yields
// deterministic output matching the mcp design appendix A examples (e.g.
// "jsonrpc","id","method","params"). A key equal to "" is skipped.
func MarshalOrdered(m map[string]any, order ...string) ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte('{')
	first := true
	seen := make(map[string]bool, len(m))
	// Emit ordered keys first.
	for _, k := range order {
		v, ok := m[k]
		if !ok {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		seen[k] = true
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalValue(v)
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	// Emit remaining keys in sorted order.
	extra := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sortStrings(extra)
	for _, k := range extra {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalValue(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalValue marshals a single JSON value, using integer encoding for int
// types (matches spec examples like "id":1 not "id":1.0).
func marshalValue(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return []byte("null"), nil
	case int:
		return []byte(strconv.FormatInt(int64(t), 10)), nil
	case int64:
		return []byte(strconv.FormatInt(t, 10)), nil
	case uint16:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case uint32:
		return []byte(strconv.FormatUint(uint64(t), 10)), nil
	case string:
		return json.Marshal(t)
	case bool:
		if t {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case map[string]any:
		return MarshalOrdered(t)
	case []any:
		buf := &bytes.Buffer{}
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			eb, err := marshalValue(e)
			if err != nil {
				return nil, err
			}
			buf.Write(eb)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	default:
		return json.Marshal(t)
	}
}

// sortStrings sorts a string slice in ascending order (small helper to
// avoid pulling in "sort" for one call site).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
