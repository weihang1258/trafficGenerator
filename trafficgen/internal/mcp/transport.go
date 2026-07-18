package mcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewStdioTransport returns a stdio transport for use with Server.Run.
// stdio is the default transport for local LLM clients (Claude Desktop,
// Cursor) that start the MCP server as a subprocess and communicate over
// stdin/stdout. No authentication is required for stdio (local trust).
//
// HTTP/SSE transport (remote MCP primary use case) is implemented in
// http_server.go via mcp.NewStreamableHTTPHandler, with X-MCP-Key
// authentication and CORS. See NewHTTPServer.
func NewStdioTransport() mcp.Transport {
	return &mcp.StdioTransport{}
}
