package mcp

import (
	"sort"
	"strconv"
	"strings"
)

// buildSSEMessage formats one SSE event: "event: <name>\ndata: <data>\n\n"
// (design §2.4 / Appendix A.2). data is emitted as-is (already JSON).
func buildSSEMessage(event string, data []byte) []byte {
	var buf strings.Builder
	buf.WriteString("event: ")
	buf.WriteString(event)
	buf.WriteByte('\n')
	buf.WriteString("data: ")
	buf.Write(data)
	buf.WriteString("\n\n")
	return []byte(buf.String())
}

// buildHTTPRequest builds an HTTP/1.1 request for HTTP+SSE / Streamable
// HTTP mode (design §2.4-§2.5 / Appendix A.2-§A.3).
//
// Per §A.2 the GET /mcp (SSE establishment) does NOT carry Mcp-Session-Id
// (the session id is learned from the `endpoint` event response).
func buildHTTPRequest(method, path, host string, headers map[string]string, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(host)
	sb.WriteString("\r\n")
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(headers[k])
		sb.WriteString("\r\n")
	}
	if len(body) > 0 {
		sb.WriteString("Content-Length: ")
		sb.WriteString(strconv.Itoa(len(body)))
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return []byte(sb.String())
}

// buildHTTPResponse builds a minimal HTTP/1.1 response (design §6.3:
// "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"; §A.3 200 OK;
// T91: 204 No Content). body may be nil.
func buildHTTPResponse(statusCode int, statusText string, headers map[string]string, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(strconv.Itoa(statusCode))
	sb.WriteByte(' ')
	sb.WriteString(statusText)
	sb.WriteString("\r\n")
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(headers[k])
		sb.WriteString("\r\n")
	}
	if len(body) > 0 {
		sb.WriteString("Content-Length: ")
		sb.WriteString(strconv.Itoa(len(body)))
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return []byte(sb.String())
}

// buildEndpointEvent formats the GET /mcp SSE response's first event:
// "event: endpoint\ndata: <post_uri>\n\n" (design §2.4 / §6.3 / §A.2).
// This is the spec-mandated first event that tells the client which URI
// to POST subsequent messages to.
func buildEndpointEvent(postURI string) []byte {
	return buildSSEMessage("endpoint", []byte(postURI))
}

// buildSessionIDHeader returns the value for the Mcp-Session-Id header
// (design §1.2 / §A.2). The header itself is added by the caller.
func buildSessionIDHeader(sessionID string) string {
	return "Mcp-Session-Id: " + sessionID
}