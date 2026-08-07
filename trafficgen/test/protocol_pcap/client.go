// Package protocolpcap drives the trafficgen MCP server over HTTP/SSE
// (Streamable HTTP) to generate per-protocol pcap files, then verifies
// each pcap against the design-doc test cases with tshark.
package protocolpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultEndpoint is the MCP Streamable HTTP endpoint of the dev server.
const DefaultEndpoint = "http://127.0.0.1:8081/mcp"

// DefaultAPIKey matches configs/config.dev.yaml mcp.api_key.
const DefaultAPIKey = "dev-mcp-key"

// headerInjectingRoundTripper adds the X-MCP-Key header to every request.
type headerInjectingRoundTripper struct {
	base   http.RoundTripper
	apiKey string
}

func (rt *headerInjectingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("X-MCP-Key", rt.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return rt.base.RoundTrip(req)
}

// Client is a thin wrapper around the go-sdk MCP client session.
// A client owns a single MCP session and must be closed when done.
type Client struct {
	sess *mcp.ClientSession
	cc   *http.Client
	mu   sync.Mutex // serializes tool calls; MCP session is request/response paired
}

// NewClient connects to the MCP endpoint and performs the initialize
// handshake. The caller must call Close when finished.
func NewClient(ctx context.Context, endpoint, apiKey string) (*Client, error) {
	cc := &http.Client{
		Transport: &headerInjectingRoundTripper{
			base:   http.DefaultTransport,
			apiKey: apiKey,
		},
		Timeout: 2 * time.Minute,
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: cc,
	}
	cli := mcp.NewClient(&mcp.Implementation{Name: "protocol-pcap-test", Version: "0.1.0"}, nil)
	sess, err := cli.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp connect: %w", err)
	}
	return &Client{sess: sess, cc: cc}, nil
}

// Close terminates the MCP session.
func (c *Client) Close() {
	if c.sess == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sess.Close()
	c.sess = nil
}

// CallTool invokes an MCP tool with the given JSON arguments and returns
// the JSON payload of the first text content block.
func (c *Client) CallTool(ctx context.Context, name string, args any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, err := c.sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("call tool %s: %w", name, err)
	}
	if res.IsError {
		return nil, fmt.Errorf("tool %s error: %s", name, contentText(res))
	}
	// The server serializes the handler's output struct as JSON into
	// Content[0].Text (see http_integration_test.go parseToolResult).
	for _, blk := range res.Content {
		if text, ok := blk.(*mcp.TextContent); ok && text.Text != "" {
			var out json.RawMessage
			if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
				return json.RawMessage(text.Text), nil
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("tool %s: no text content in result", name)
}

func contentText(res *mcp.CallToolResult) string {
	for _, blk := range res.Content {
		if text, ok := blk.(*mcp.TextContent); ok {
			return text.Text
		}
	}
	return fmt.Sprintf("%+v", res.Content)
}
