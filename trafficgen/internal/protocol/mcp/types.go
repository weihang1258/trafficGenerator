// Package mcp implements the MCP (Model Context Protocol) planner. MCP is a
// JSON-RPC 2.0 application-layer protocol over stdio (line-delimited JSON)
// or HTTP+SSE / Streamable HTTP. The planner generates wire-format bytes
// only; it does NOT use the modelcontextprotocol/go-sdk (the SDK drives
// real sessions). This package is isolated from internal/mcp/ (which is a
// real MCP server) and imports only internal/core.
package mcp

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Transport modes for MCP (design §2.3-§2.5).
const (
	TransportStdio      = "stdio"
	TransportHTTPSSE    = "http_sse"
	TransportStreamable = "streamable"
)

// Default ports (design §1.4 / §10.7).
const (
	// DefaultPortHTTP is the default port for HTTP+SSE / Streamable HTTP
	// mode. Matches the MCP server convention in internal/mcp/.
	DefaultPortHTTP uint16 = 8081

	// DefaultPortStdio is the default port for stdio mode (SSH tunnel
	// scenario); users may set spec.DstPort=8081 to simulate local stdio
	// forwarding to the MCP server.
	DefaultPortStdio uint16 = 22
)

// Supported protocol versions (design §4.4 rule 3).
var validProtocolVersions = map[string]bool{
	"":             true, // empty = use default
	"2024-11-05":   true,
	"2025-03-26":   true,
	"2025-06-18":   true,
}

// Supported auth schemes (design §4.4 rule 4).
var validAuthSchemes = map[string]bool{
	"":          true,
	"Bearer":    true,
	"Basic":     true,
	"OAuth2":    true,
	"Negotiate": true,
}

// State values for the long-task tools/call state machine (design §5.3).
var validStateValues = map[string]bool{
	"":                true,
	"submitted":       true,
	"working":         true,
	"input_required":  true,
	"completed":       true,
	"failed":          true,
	"canceled":        true,
}

// Content type values (design §4.4 rule 11; spec 2024-11-05 text/image/
// resource; spec 2025-06-18 adds audio/resource_link).
var validContentTypes = map[string]bool{
	"":              true,
	"text":          true,
	"image":         true,
	"audio":         true,
	"resource":      true,
	"resource_link": true,
}

// Role values (design §4.4 rule 10).
var validRoles = map[string]bool{
	"":          true,
	"user":      true,
	"assistant": true,
}

// JSON-RPC 2.0 standard error codes (design §2.2 / Appendix B).
const (
	ErrCodeParseError      = -32700
	ErrCodeInvalidRequest  = -32600
	ErrCodeMethodNotFound  = -32601
	ErrCodeInvalidParams   = -32602
	ErrCodeInternalError   = -32603
	ErrCodeResourceNotFound = -32002 // MCP spec 2024-11-05 §server/resources
)

// JSON-RPC 2.0 spec reserved range: [-32700, -32000]. error.code must be
// in this range (design §4.4 rule 13).
const (
	errCodeMin = -32700
	errCodeMax = -32000
)

// DefaultRequestSequence is the default Requests when user supplies none
// (design §4.3 table).
var DefaultRequestSequence = []core.MCPRequest{
	{Method: "tools/list"},
	{Method: "tools/call", Params: map[string]any{"name": "ping"}},
}

// DefaultProtocolVersion is the default protocol version when user supplies
// none (design §4.3 / Appendix A).
const DefaultProtocolVersion = "2024-11-05"

// DefaultJSONRPCVersion is the JSON-RPC 2.0 protocol version literal.
const DefaultJSONRPCVersion = "2.0"

// DefaultSessionIDLength is the hex character length for auto-generated
// session IDs (design §4.3 / §6.5; 32 hex chars = 16 bytes / 128 bits).
const DefaultSessionIDLength = 32