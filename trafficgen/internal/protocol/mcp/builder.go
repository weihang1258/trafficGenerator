package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/trafficgen/trafficgen/internal/core"
)

// buildRequest builds a JSON-RPC 2.0 request object as a single JSON object
// (NOT batch). The result is the canonical JSON-RPC request per design
// §2.1.1.
//
// Per design §2.1.1, the id can be number/string/null. We emit number for
// integer ids and string for negative (or any non-int canonical id).
//
// params handling (design §7.2 / §7.3 / §7.12): if params is nil and the
// caller signals omitParams (e.g. notifications/initialized, ping, roots/
// list), the "params" key is NOT emitted. Otherwise, params is emitted
// as the value (possibly an empty object {} when emitEmptyParams is true).
func buildRequest(id int, method string, params map[string]any, emitEmptyParams bool) ([]byte, error) {
	if method == "" {
		return nil, fmt.Errorf("mcp: method is required")
	}
	obj := map[string]any{
		"jsonrpc": DefaultJSONRPCVersion,
		"method":  method,
	}
	// id: emit number for non-negative ints (most common case).
	obj["id"] = id
	if params != nil {
		obj["params"] = params
	} else if emitEmptyParams {
		obj["params"] = map[string]any{}
	}
	return marshalJSONOrdered(obj, "jsonrpc", "id", "method", "params", "result", "error")
}

// buildNotification builds a JSON-RPC 2.0 notification object (no id).
// Per design §2.1.3, notifications carry no id field; per §7.2 the
// notifications/initialized notification must NOT carry a params field
// when emitted in strict-spec mode.
func buildNotification(method string, params map[string]any, emitEmptyParams bool) ([]byte, error) {
	if method == "" {
		return nil, fmt.Errorf("mcp: notification method is required")
	}
	obj := map[string]any{
		"jsonrpc": DefaultJSONRPCVersion,
		"method":  method,
	}
	if params != nil {
		obj["params"] = params
	} else if emitEmptyParams {
		obj["params"] = map[string]any{}
	}
	return marshalJSONOrdered(obj, "jsonrpc", "method", "params")
}

// buildSuccessResponse builds a JSON-RPC 2.0 success response with a result.
// Per design §2.1.2, id is required and matches the request id.
func buildSuccessResponse(id int, result map[string]any) ([]byte, error) {
	if result == nil {
		result = map[string]any{}
	}
	obj := map[string]any{
		"jsonrpc": DefaultJSONRPCVersion,
		"id":      id,
		"result":  result,
	}
	return marshalJSONOrdered(obj, "jsonrpc", "id", "result", "error")
}

// buildErrorResponse builds a JSON-RPC 2.0 error response. id is required;
// per §2.1.2, when the request id is unparseable it is set to nil.
func buildErrorResponse(id any, code int, message string, data any) ([]byte, error) {
	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}
	obj := map[string]any{
		"jsonrpc": DefaultJSONRPCVersion,
		"id":      id,
		"error":   errObj,
	}
	return marshalJSONOrdered(obj, "jsonrpc", "id", "error", "result")
}

// marshalJSONOrdered marshals m as JSON with keys ordered by `order` first
// (in the given order), then any remaining keys in sorted order. This
// gives deterministic output that matches the design appendix A examples
// (e.g. "jsonrpc","id","method","params"). Empty string in order = skip.
func marshalJSONOrdered(m map[string]any, order ...string) ([]byte, error) {
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

// marshalValue marshals a JSON value, using integer encoding for int types
// (matches spec examples like "id":1 not "id":1.0).
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
		return marshalJSONOrdered(t)
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

// buildInitializeRequest builds the default initialize request body
// (design §7.1 / Appendix A.1). protocolVersion defaults to "2024-11-05".
// Per v1.1.1 N-4 修复回归：未提供 ClientCapabilities（nil/null/empty）时
// params 中不出现 capabilities 字段（不再自动注入 roots+sampling）；
// 调用方需显式设置 ClientCapabilities 才会输出 capabilities。
// 显式 {} 会被原样透传。
//
// id is the JSON-RPC request id (design §4.1: IDCounter=0→1, non-zero→use
// that value as the first request id).
func buildInitializeRequest(id int, protocolVersion string, clientInfo core.MCPClientInfo, clientCaps json.RawMessage) ([]byte, error) {
	if protocolVersion == "" {
		protocolVersion = DefaultProtocolVersion
	}
	if clientInfo.Name == "" {
		clientInfo.Name = "trafficgen-client"
	}
	if clientInfo.Version == "" {
		clientInfo.Version = "1.0.0"
	}
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"clientInfo": map[string]any{
			"name":    clientInfo.Name,
			"version": clientInfo.Version,
		},
	}
	// v1.1.1 N-4: 不再自动注入 roots+sampling。仅当调用方显式提供
	// ClientCapabilities（非 nil/null）时透传；否则 capabilities 字段缺省。
	if len(clientCaps) > 0 && !bytes.Equal(clientCaps, []byte("null")) {
		var caps map[string]any
		if err := json.Unmarshal(clientCaps, &caps); err == nil {
			params["capabilities"] = caps
		}
	}
	return buildRequest(id, "initialize", params, true)
}

// buildInitializeResponse builds the default initialize response body
// (design §7.1 / Appendix A.1). serverCapabilities defaults to absent
// (no capabilities field) when serverCaps is nil / null / empty — per
// v1.1.2 C-3 the planner does NOT auto-inject tools/resources/prompts/
// logging/completion; the caller MUST explicitly set ServerCapabilities
// if capabilities are desired. This mirrors buildInitializeRequest's
// behavior for the client side (both omit capabilities when absent).
//
// protocolVersion is the SERVER's version: per design §7.1 / T11 the
// response must reflect the server's supported protocol version (the
// planner passes the server version, which is at most 2024-11-05), never
// echo a newer client-requested version.
func buildInitializeResponse(id int, protocolVersion string, serverInfo core.MCPServerInfo, serverCaps json.RawMessage) ([]byte, error) {
	if protocolVersion == "" {
		protocolVersion = DefaultProtocolVersion
	}
	// Capability clamp: the server implementation supports only the baseline
	// 2024-11-05 protocol. A caller-requested newer version (2025-03-26 /
	// 2025-06-18) is downgraded to the server maximum rather than echoed.
	// Kept as a defensive invariant independent of the planner call site.
	for _, v := range []string{DefaultProtocolVersion, "2025-03-26", "2025-06-18"} {
		if protocolVersion == v {
			break
		}
		if protocolVersion == "2025-03-26" || protocolVersion == "2025-06-18" {
			protocolVersion = DefaultProtocolVersion
			break
		}
	}
	if serverInfo.Name == "" {
		serverInfo.Name = "trafficgen-server"
	}
	if serverInfo.Version == "" {
		serverInfo.Version = "1.0.0"
	}
	result := map[string]any{
		"protocolVersion": protocolVersion,
		"serverInfo": map[string]any{
			"name":    serverInfo.Name,
			"version": serverInfo.Version,
		},
	}
	// v1.1.2 C-3: 不再自动注入 tools/resources/prompts/logging/completion。
	// 未提供 capabilities 时 result 中不出现 capabilities 字段（与请求侧行为
	// 一致：capabilities 是可选字段，缺省即"无任何 capability"）。
	if len(serverCaps) > 0 && !bytes.Equal(serverCaps, []byte("null")) {
		var caps map[string]any
		if err := json.Unmarshal(serverCaps, &caps); err == nil {
			result["capabilities"] = caps
		}
	}
	return buildSuccessResponse(id, result)
}

// buildInitializedNotification builds the notifications/initialized
// notification (design §7.2 / §A.1). Per spec, the notification MUST NOT
// carry a params field (strict spec mode); emitEmptyParams=false.
func buildInitializedNotification() ([]byte, error) {
	return buildNotification("notifications/initialized", nil, false)
}

// buildSSEMessage, buildHTTPRequest, buildHTTPResponse, buildEndpointEvent,
// buildSessionIDHeader are defined in http_builder.go.
