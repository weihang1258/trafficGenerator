package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// httpTransportKey marks tool-call contexts served over the Streamable HTTP
// transport. The HTTP server injects it via middleware; stdio never does, so
// absence means the client runs on this host.
type httpTransportKey struct{}

// taskDataForTransport adapts a REST task payload to the calling transport.
//
// stdio clients run on this host: output_config.pcap_path is the direct
// artifact reference, while the relative download_url cannot be resolved
// without a server host:port — it is stripped (pre-direct-link behavior).
// HTTP clients are remote: download_url (the unauthenticated capability
// link set by rest.convertTaskToResponse for pcap tasks) is the useful
// handle and is kept. Handles both a single task object and a list of tasks.
func taskDataForTransport(ctx context.Context, raw json.RawMessage) interface{} {
	v := rawData(raw)
	if ctx.Value(httpTransportKey{}) != nil {
		return v
	}
	switch t := v.(type) {
	case map[string]interface{}:
		delete(t, "download_url")
		// List responses are {items:[task...], total, ...}: strip per item.
		if items, ok := t["items"].([]interface{}); ok {
			for _, e := range items {
				if m, ok := e.(map[string]interface{}); ok {
					delete(m, "download_url")
				}
			}
		}
	}
	return v
}

// callHandler invokes a gin handler with service account context and returns
// the parsed backend response. The caller inspects resp.Code (0 == success,
// 409 == idempotent hit per §8.1) or treats the returned error as an MCP error.
//
// body:  JSON request body (nil for GET-like handlers that read only URL/query params).
// id:    URL :id param (empty for handlers that don't use :id).
// query: URL query params (nil for handlers that don't use query params).
// handler: the gin handler method to invoke.
//
// ctx is propagated into c.Request so handlers doing ctx-aware I/O (DB queries,
// engine submission) see client cancellation/deadline.
func (s *Server) callHandler(ctx context.Context, body []byte, id string, query url.Values, handler func(*gin.Context)) (resp *backendResponse, err error) {
	var params gin.Params
	if id != "" {
		params = gin.Params{{Key: "id", Value: id}}
	}
	return s.callHandlerWithParams(ctx, body, params, query, handler)
}

// callHandlerWithParams is the generic variant of callHandler that accepts a
// full gin.Params slice. Used by handlers that need multiple path params
// (e.g., /pcaps/:id/flows/:fid uses both :id and :fid).
func (s *Server) callHandlerWithParams(ctx context.Context, body []byte, params gin.Params, query url.Values, handler func(*gin.Context)) (resp *backendResponse, err error) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("userID", s.serviceUserID)
	c.Set("username", s.serviceUsername)
	c.Set("roles", []string{s.serviceUserRole})

	method := "GET"
	// Declare as io.Reader so a nil body yields a nil interface (not a nil
	// *bytes.Reader wrapped in a non-nil interface, which would make
	// http.NewRequest call .Len() on a nil pointer and panic).
	var bodyReader io.Reader
	if body != nil {
		method = "POST"
		bodyReader = bytes.NewReader(body)
	}

	// Propagate ctx so handler ctx-aware I/O is cancellable. Fall back to
	// Background if ctx is nil (defensive; callers always pass non-nil).
	reqCtx := ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	c.Request, _ = http.NewRequestWithContext(reqCtx, method, "/", bodyReader)
	if body != nil {
		c.Request.Header.Set("Content-Type", "application/json")
	}
	if query != nil {
		c.Request.URL.RawQuery = query.Encode()
	}

	if len(params) > 0 {
		c.Params = params
	}

	// Recover from handler panics. The REST path runs through gin's Recovery()
	// middleware which converts panics to 500 responses; callHandler bypasses
	// the middleware chain (gin.CreateTestContext uses gin.New()), so without
	// this guard a nil-deref or OOB in any handler would crash the entire
	// trafficgen process (taking REST down with MCP).
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			err = &jsonrpc.Error{
				Code:    jsonrpc.CodeInternalError,
				Message: fmt.Sprintf("handler panic: %v", r),
			}
			// Surface the stack in the error Data field for debugging; the
			// MCP SDK includes Data in the error response to the LLM.
			resp = &backendResponse{Code: 500, Message: fmt.Sprintf("handler panic: %v\n%s", r, stack)}
		}
	}()

	handler(c)

	resp, err = parseBackendResponse(w)
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: err.Error()}
	}

	// code=0 (success) and code=409 (idempotent hit -> success per §8.1).
	// The backend's idempotent path returns code=0 with message "already exists";
	// 409 mapping is kept as defense-in-depth for any future conflict responses.
	if resp.Code == 0 || resp.Code == 409 {
		return resp, nil
	}

	return resp, backendError(resp.Code, resp.Message)
}

// callRawHandler invokes a gin handler that writes its response directly via
// c.JSON (without the rest.Success {code,message,data} envelope), capturing
// the raw body as Data. Used by health/ready endpoints which predate the
// envelope convention and are asserted on by REST tests in raw form.
//
// Returns a backendResponse with Code=0 and Data=raw body. HTTP-level errors
// (panic, non-2xx status) are surfaced as errors.
func (s *Server) callRawHandler(ctx context.Context, handler func(*gin.Context)) (resp *backendResponse, err error) {
	return s.callRawHandlerWithParams(ctx, nil, nil, handler)
}

// callRawHandlerWithParams is the generic variant of callRawHandler that
// accepts path params and query params. Used by binary-returning pcap
// handlers (get_stream/get_body/get_packet_payload) which need :id + :fid/:pid.
func (s *Server) callRawHandlerWithParams(ctx context.Context, params gin.Params, query url.Values, handler func(*gin.Context)) (resp *backendResponse, err error) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("userID", s.serviceUserID)
	c.Set("username", s.serviceUsername)
	c.Set("roles", []string{s.serviceUserRole})

	method := "GET"
	reqCtx := ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	c.Request, _ = http.NewRequestWithContext(reqCtx, method, "/", nil)
	if query != nil {
		c.Request.URL.RawQuery = query.Encode()
	}
	if len(params) > 0 {
		c.Params = params
	}

	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			err = &jsonrpc.Error{
				Code:    jsonrpc.CodeInternalError,
				Message: fmt.Sprintf("handler panic: %v", r),
			}
			resp = &backendResponse{Code: 500, Message: fmt.Sprintf("handler panic: %v\n%s", r, stack)}
		}
	}()

	handler(c)

	// If the handler wrote a non-2xx status, surface it as an error so the
	// tool caller can react (e.g., 503 from ready-check when engine is down).
	if w.Code >= 400 {
		return nil, backendError(w.Code, string(w.Body.Bytes()))
	}

	return &backendResponse{Code: 0, Data: w.Body.Bytes()}, nil
}
