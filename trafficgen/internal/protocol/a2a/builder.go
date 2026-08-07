package a2a

// builder.go provides standalone builders for A2A protocol messages.
// These are used by the planner and can be used independently for testing.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BuildJSONRPCRequest builds a JSON-RPC 2.0 request.
func BuildJSONRPCRequest(method string, params map[string]any, id any) []byte {
	if id == nil {
		id = "req-001"
	}
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      id,
	}
	b, _ := json.Marshal(req)
	return b
}

// BuildJSONRPCResponse builds a JSON-RPC 2.0 success response.
func BuildJSONRPCResponse(result map[string]any, id any) []byte {
	if id == nil {
		id = "req-001"
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"result":  result,
		"id":      id,
	}
	b, _ := json.Marshal(resp)
	return b
}

// BuildJSONRPCError builds a JSON-RPC 2.0 error response.
func BuildJSONRPCError(code int, message string, data any, id any) []byte {
	if id == nil {
		id = "req-001"
	}
	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"error":   errObj,
		"id":      id,
	}
	b, _ := json.Marshal(resp)
	return b
}

// BuildSSEEvent builds a single SSE event with the given JSON-RPC response.
func BuildSSEEvent(resp []byte) []byte {
	return []byte(fmt.Sprintf("data: %s\n\n", resp))
}

// BuildSSEStream builds an SSE stream from multiple events.
func BuildSSEStream(events [][]byte) []byte {
	var sb strings.Builder
	for _, ev := range events {
		sb.WriteString(fmt.Sprintf("data: %s\n\n", ev))
	}
	return []byte(sb.String())
}

// BuildTaskObject builds a Task object map.
func BuildTaskObject(id, contextID, state string, artifacts []A2AArtifact, history []A2AMessage, metadata map[string]any) map[string]any {
	m := map[string]any{
		"id":        id,
		"contextId": contextID,
		"status": map[string]any{
			"state": state,
		},
		"kind": DefaultTaskKind,
	}
	if len(artifacts) > 0 {
		arts := make([]map[string]any, len(artifacts))
		for i, a := range artifacts {
			arts[i] = artifactToMap(a)
		}
		m["artifacts"] = arts
	}
	if len(history) > 0 {
		hist := make([]map[string]any, len(history))
		for i, h := range history {
			hist[i] = messageToMap(h)
		}
		m["history"] = hist
	}
	if len(metadata) > 0 {
		m["metadata"] = metadata
	}
	return m
}

// BuildMessage builds a Message object map.
func BuildMessage(role string, parts []A2APart, messageID, taskID, contextID string, metadata map[string]any) map[string]any {
	m := map[string]any{
		"role":      role,
		"parts":     partsToMaps(parts),
		"messageId": messageID,
		"kind":      DefaultMessageKind,
	}
	if taskID != "" {
		m["taskId"] = taskID
	}
	if contextID != "" {
		m["contextId"] = contextID
	}
	if len(metadata) > 0 {
		m["metadata"] = metadata
	}
	return m
}

// BuildStatusUpdateEvent builds a TaskStatusUpdateEvent map.
func BuildStatusUpdateEvent(taskID, contextID, state string, final bool, metadata map[string]any) map[string]any {
	m := map[string]any{
		"taskId":    taskID,
		"contextId": contextID,
		"kind":      DefaultStatusUpdateKind,
		"status": map[string]any{
			"state": state,
		},
		"final": final,
	}
	if len(metadata) > 0 {
		m["metadata"] = metadata
	}
	return m
}

// BuildArtifactUpdateEvent builds a TaskArtifactUpdateEvent map.
func BuildArtifactUpdateEvent(taskID, contextID string, artifact A2AArtifact, append, lastChunk bool, metadata map[string]any) map[string]any {
	m := map[string]any{
		"taskId":    taskID,
		"contextId": contextID,
		"kind":      DefaultArtifactUpdateKind,
		"artifact":  artifactToMap(artifact),
		"append":    append,
		"lastChunk": lastChunk,
	}
	if len(metadata) > 0 {
		m["metadata"] = metadata
	}
	return m
}

// BuildPushNotificationConfig builds a PushNotificationConfig map.
func BuildPushNotificationConfig(url, id, token string, schemes []string, credentials string) map[string]any {
	m := map[string]any{
		"url": url,
	}
	if id != "" {
		m["id"] = id
	}
	if token != "" {
		m["token"] = token
	}
	if len(schemes) > 0 {
		auth := map[string]any{
			"schemes": schemes,
		}
		if credentials != "" {
			auth["credentials"] = credentials
		}
		m["authentication"] = auth
	}
	return m
}

// BuildAgentCard builds an AgentCard map.
func BuildAgentCard(name, description, url, version, protocolVersion string, capabilities *A2AAgentCapabilities, skills []A2AAgentSkill, inputModes, outputModes []string) map[string]any {
	m := map[string]any{
		"name":               name,
		"description":        description,
		"url":                url,
		"version":            version,
		"protocolVersion":    protocolVersion,
		"capabilities":       capabilities,
		"skills":             skills,
		"defaultInputModes":  inputModes,
		"defaultOutputModes": outputModes,
	}
	return m
}

// BuildHTTPRequest builds a raw HTTP request string.
func BuildHTTPRequest(method, path, host, contentType, accept, connection, userAgent string, body []byte, extraHeaders map[string]string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))
	if contentType != "" && !hasHeader(extraHeaders, "Content-Type") {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if accept != "" && !hasHeader(extraHeaders, "Accept") {
		sb.WriteString(fmt.Sprintf("Accept: %s\r\n", accept))
	}
	if len(body) > 0 && !hasHeader(extraHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	if userAgent != "" && !hasHeader(extraHeaders, "User-Agent") {
		sb.WriteString(fmt.Sprintf("User-Agent: %s\r\n", userAgent))
	}
	if connection != "" && !hasHeader(extraHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", connection))
	}
	for k, v := range extraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// BuildHTTPResponse builds a raw HTTP response string.
func BuildHTTPResponse(statusCode int, statusText, contentType string, body []byte, extraHeaders map[string]string) string {
	var sb strings.Builder
	if statusText == "" {
		statusText = statusTextFor(statusCode)
	}
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
	if contentType != "" && !hasHeader(extraHeaders, "Content-Type") {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if len(body) > 0 && !hasHeader(extraHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	for k, v := range extraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// BuildTextPart builds a text Part map.
func BuildTextPart(text string) map[string]any {
	return map[string]any{
		"kind": "text",
		"text": text,
	}
}

// BuildDataPart builds a data Part map.
func BuildDataPart(data map[string]any) map[string]any {
	return map[string]any{
		"kind": "data",
		"data": data,
	}
}

// BuildFilePartBytes builds a file Part map with bytes.
func BuildFilePartBytes(name, mimeType, bytes string) map[string]any {
	m := map[string]any{
		"kind": "file",
		"file": map[string]any{
			"name":     name,
			"mimeType": mimeType,
			"bytes":    bytes,
		},
	}
	return m
}

// BuildFilePartURI builds a file Part map with URI.
func BuildFilePartURI(name, mimeType, uri string) map[string]any {
	m := map[string]any{
		"kind": "file",
		"file": map[string]any{
			"name":     name,
			"mimeType": mimeType,
			"uri":      uri,
		},
	}
	return m
}

// BuildTaskPushNotificationConfig builds a TaskPushNotificationConfig response map.
func BuildTaskPushNotificationConfig(taskID string, pnc A2APushNotificationConfig) map[string]any {
	return map[string]any{
		"taskId":                 taskID,
		"pushNotificationConfig": pushNotificationConfigToMap(pnc),
	}
}
