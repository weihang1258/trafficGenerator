package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// httpPlanState holds per-flow mutable state for HTTP+SSE / Streamable
// HTTP transport modes (design §6.3 / §6.4 / Appendix A.2-§A.3). It wraps
// planState with HTTP-specific session URI tracking.
type httpPlanState struct {
	sessionID string
	postURI   string // URI learned from `endpoint` event (HTTP+SSE only)
	host      string // Host header value (default "mcp.example.com:8081")
	basePath  string // base path; default "/mcp"
	auth      string // Authorization header value ("" = none, design §7.14)
}

// newHTTPPlanState creates an httpPlanState from a planState + cfg.
func newHTTPPlanState(ps *planState, cfg *core.MCPConfig) *httpPlanState {
	hps := &httpPlanState{
		sessionID: ps.sessionID,
		host:      defaultHTTPHost,
		basePath:  defaultBasePath,
		auth:      authHeader(cfg),
	}
	if cfg.BaseURL != "" {
		hps.basePath = ensureLeadingSlash(cfg.BaseURL)
	}
	// POST URI for HTTP+SSE is learned from the `endpoint` event; we set
	// it to basePath?session=<sid> per Appendix A.2 (the server tells the
	// client which URI to POST to via the endpoint event).
	hps.postURI = fmt.Sprintf("%s?session=%s", hps.basePath, ps.sessionID)
	return hps
}

// defaultHTTPHost is the default Host header value when spec does not
// supply one (design Appendix A.2 / A.3 examples use "mcp.example.com:8081").
const defaultHTTPHost = "mcp.example.com:8081"

// defaultBasePath is the default HTTP path for MCP endpoints (design §1.4).
const defaultBasePath = "/mcp"

// buildGetSSERequest builds the GET /mcp HTTP request that establishes
// the SSE stream in HTTP+SSE mode (design §6.3 step 4 / Appendix A.2).
// Per Appendix A.2: GET does NOT carry Mcp-Session-Id (session id is
// learned from the `endpoint` event response).
func (hps *httpPlanState) buildGetSSERequest() []byte {
	headers := map[string]string{
		"Accept": "text/event-stream",
	}
	if hps.auth != "" {
		headers["Authorization"] = hps.auth
	}
	return buildHTTPRequest("GET", hps.basePath, hps.host, headers, nil)
}

// buildGetSSEResponse builds the HTTP 200 OK response that carries the
// initial SSE stream: `endpoint` event followed by the first `message`
// event containing the initialize response (design §6.3 step 5 /
// Appendix A.2). Per spec 2024-11-05 §basic/transports, the server MUST
// send an `endpoint` event as the first event.
//
// The `endpoint` event's data field is the POST URI the client should
// use for subsequent POST messages (design Appendix A.2:
// "/mcp?session=a1b2c3...").
func (hps *httpPlanState) buildGetSSEResponse(initResp []byte) []byte {
	// Endpoint event: tells client where to POST.
	endpointEvt := buildEndpointEvent(hps.postURI)
	// First message event: the initialize response.
	msgEvt := buildSSEMessage("message", initResp)
	body := make([]byte, 0, len(endpointEvt)+len(msgEvt))
	body = append(body, endpointEvt...)
	body = append(body, msgEvt...)
	headers := map[string]string{
		"Content-Type":  "text/event-stream",
		"Cache-Control": "no-cache",
		"Connection":    "keep-alive",
	}
	return buildHTTPResponse(200, "OK", headers, body)
}

// buildPostRequest builds an HTTP POST request carrying a JSON-RPC
// payload to the endpoint URI learned from the `endpoint` event
// (design §6.3 step 6 / Appendix A.2). Per Appendix A.2 the POST
// carries Mcp-Session-Id + Content-Type: application/json + Accept.
func (hps *httpPlanState) buildPostRequest(jsonBody []byte) []byte {
	headers := map[string]string{
		"Content-Type":   "application/json",
		"Accept":         "application/json, text/event-stream",
		"Mcp-Session-Id": hps.sessionID,
	}
	if hps.auth != "" {
		headers["Authorization"] = hps.auth
	}
	return buildHTTPRequest("POST", hps.postURI, hps.host, headers, jsonBody)
}

// buildPostAccepted builds the HTTP 202 Accepted response (no body) for
// HTTP+SSE POST requests (design §6.3 step 7 / Appendix A.2: "HTTP/1.1
// 202 Accepted\r\nContent-Length: 0\r\n\r\n"). The actual JSON-RPC
// response is pushed via the GET SSE stream, not in the POST response.
// We explicitly emit Content-Length: 0 (design T78) since the helper
// buildHTTPResponse only auto-emits Content-Length for non-empty bodies.
func (hps *httpPlanState) buildPostAccepted() []byte {
	return buildHTTPResponse(202, "Accepted", map[string]string{"Content-Length": "0"}, nil)
}

// buildSSEMessageEvent builds an `event: message\ndata: {...}\n\n` SSE
// event for pushing responses/notifications over the GET SSE stream
// (design §6.3 step 10 / §2.4).
func (hps *httpPlanState) buildSSEMessageEvent(jsonPayload []byte) []byte {
	return buildSSEMessage("message", jsonPayload)
}

// buildStreamableJSONResponse builds a 200 OK + Content-Type:
// application/json response carrying a JSON-RPC body for Streamable HTTP
// mode (design §6.4 / Appendix A.3: simple request/response scenario).
// Per Appendix A.3 the response carries Mcp-Session-Id header.
func (hps *httpPlanState) buildStreamableJSONResponse(jsonBody []byte) []byte {
	headers := map[string]string{
		"Content-Type":   "application/json",
		"Mcp-Session-Id": hps.sessionID,
	}
	return buildHTTPResponse(200, "OK", headers, jsonBody)
}

// buildStreamableSSEResponse builds a 200 OK + Content-Type:
// text/event-stream response carrying one or more SSE events for
// Streamable HTTP mode (design §6.4 / Appendix A.3: streaming result
// or mid-operation notification scenario). Per Appendix A.3 the
// response carries Mcp-Session-Id header.
func (hps *httpPlanState) buildStreamableSSEResponse(sseBody []byte) []byte {
	headers := map[string]string{
		"Content-Type":   "text/event-stream",
		"Mcp-Session-Id": hps.sessionID,
	}
	return buildHTTPResponse(200, "OK", headers, sseBody)
}

// buildDeleteRequest builds the DELETE /mcp HTTP request for Streamable
// HTTP session termination (design §2.5 / T91). Per T91 the DELETE
// carries Mcp-Session-Id header.
func (hps *httpPlanState) buildDeleteRequest() []byte {
	headers := map[string]string{
		"Mcp-Session-Id": hps.sessionID,
	}
	if hps.auth != "" {
		headers["Authorization"] = hps.auth
	}
	return buildHTTPRequest("DELETE", hps.basePath, hps.host, headers, nil)
}

// buildDeleteResponse builds the HTTP 204 No Content response for the
// DELETE /mcp request (design T91: "HTTP/1.1 204 No Content\r\n\r\n").
func (hps *httpPlanState) buildDeleteResponse() []byte {
	return buildHTTPResponse(204, "No Content", nil, nil)
}

// authHeader returns the Authorization header value for the configured
// auth scheme (design §7.14), or empty string when no auth is configured.
func authHeader(cfg *core.MCPConfig) string {
	if len(cfg.Auth.Schemes) == 0 {
		return ""
	}
	scheme := cfg.Auth.Schemes[0]
	switch scheme {
	case "Bearer":
		if cfg.Auth.Credentials == "" {
			return ""
		}
		return "Bearer " + cfg.Auth.Credentials
	case "Basic":
		if cfg.Auth.Credentials == "" {
			return ""
		}
		return "Basic " + cfg.Auth.Credentials
	case "OAuth2":
		// OAuth2 uses Bearer token format on the wire (design §7.14);
		// the token may live in either field.
		token := cfg.Auth.OAuth2Token
		if token == "" {
			token = cfg.Auth.Credentials
		}
		if token == "" {
			return ""
		}
		return "Bearer " + token
	case "Negotiate":
		if cfg.Auth.Credentials == "" {
			return ""
		}
		return "Negotiate " + cfg.Auth.Credentials
	}
	return ""
}

// ensureLeadingSlash ensures path begins with "/" (Host header is
// separate; the request line path should be absolute per RFC 7230 §5.3.1).
func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// planHTTP emits the application-layer packets for HTTP+SSE and Streamable
// HTTP transports (design §6.3 / §6.4 / Appendix A.2-§A.3). It is invoked
// by Plan() after the transport dispatch; the TCP handshake and teardown
// are emitted here (per §6.1 step 3/5g, handshake precedes HTTP framing
// and teardown follows it).
//
// HTTP+SSE (design §6.3, spec 2024-11-05 §basic/transports) enforces the
// GET-before-POST ordering:
//
//	up:   GET /mcp (establish SSE stream)
//	down: HTTP/1.1 200 OK + SSE headers + `endpoint` event + initialize
//	      response `message` event
//	up:   POST <endpoint-uri> + notifications/initialized
//	down: HTTP/1.1 202 Accepted (no body)
//	up:   POST <endpoint-uri> + request
//	down: HTTP/1.1 202 Accepted
//	down: event: message <response> (pushed over the GET SSE stream)
//	...   (repeat per request/round)
//
// Streamable HTTP (design §6.4, spec 2025-03-26) uses a single endpoint:
//
//	up:   POST /mcp + request (Mcp-Session-Id header)
//	down: HTTP/1.1 200 OK + JSON body (or SSE stream)
//	...   (repeat per request/round)
//	up:   DELETE /mcp (session termination, T91) when Shutdown=true
//	down: HTTP/1.1 204 No Content
//
// authHeader (design §7.14) is added to POST/GET/DELETE requests when
// cfg.Auth is non-empty.
//
// v1.1.x M-1 修复：sendErr 用于将 goroutine 内部构造错误回传给调用方。
// v1.1.x M-2 修复：ctx 透传到所有 emit 函数，支持 ctx 取消时立即退出。
func planHTTP(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, cfg *core.MCPConfig, dstPort uint16, ps *planState, rounds int, shutdown bool, sendErr func(error)) {
	flowID := fmt.Sprintf("mcp-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, dstPort)
	ttl := uint8(64)
	hps := newHTTPPlanState(ps, cfg)

	// 1. TCP handshake.
	emitHandshake(ctx, out, spec, dstPort, flowID, ttl, ps)

	if cfg.Transport == TransportHTTPSSE {
		planHTTPSSE(ctx, out, spec, cfg, dstPort, flowID, ttl, ps, hps, rounds, shutdown, sendErr)
		return
	}
	planStreamable(ctx, out, spec, cfg, dstPort, flowID, ttl, ps, hps, rounds, shutdown, sendErr)
}

// planHTTPSSE emits the HTTP+SSE (legacy, 2024-11-05 spec) application
// layer: GET SSE stream first, `endpoint` event, then POSTs to the
// endpoint URI with 202 Accepted responses and SSE message pushes.
func planHTTPSSE(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, cfg *core.MCPConfig, dstPort uint16, flowID string, ttl uint8, ps *planState, hps *httpPlanState, rounds int, shutdown bool, sendErr func(error)) {
	// Step 2: GET /mcp establishes the SSE stream (GET precedes POST,
	// spec §2.4/§6.3 step 4). GET does not carry Mcp-Session-Id (session
	// id is learned from the `endpoint` event response).
	getReq := hps.buildGetSSERequest()
	emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, getReq)

	// Step 3: the server's 200 OK response carries the `endpoint` event
	// first (spec-mandated), then the initialize response as a `message`
	// event (design §6.3 step 5 / Appendix A.2). The initialize request
	// itself is POSTed to the endpoint URI (design §6.3: "POST 到
	// endpoint 事件指定的 URI").
	initID := ps.idCounter
	ps.idCounter++
	// Server-side version: the server speaks only 2024-11-05 (design
	// §7.1 / T11 downgrade); the REQUEST carries the client version.
	initResp, err := buildInitializeResponse(initID, DefaultProtocolVersion, cfg.ServerInfo, cfg.ServerCapabilities)
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialize response: %w", err))
		return
	}
	getSSEBody := hps.buildGetSSEResponse(initResp)
	emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, getSSEBody)

	// Step 4: initialize request via POST to the endpoint URI (carrying
	// Mcp-Session-Id, design §6.3 step 6).
	initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialize request: %w", err))
		return
	}
	postInit := hps.buildPostRequest(initReq)
	emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postInit)
	// POST response: 202 Accepted, no body (T78).
	emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())

	// Step 5: notifications/initialized via POST to the endpoint URI.
	initdN, err := buildInitializedNotification()
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialized notification: %w", err))
		return
	}
	postInitdN := hps.buildPostRequest(initdN)
	emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postInitdN)
	// POST response: 202 Accepted, no body.
	emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())

	// Step 6: Requests loop — each request is a POST to the endpoint URI;
	// the 202 Accepted confirms receipt; the response is pushed as an
	// `event: message` over the GET SSE stream.
	respIdx := buildResponseIndex(cfg.Responses)
	anyExplicitID := len(cfg.Requests) > 0 && cfg.Requests[0].ID != 0

	for round := 0; round < rounds; round++ {
		for i, req := range cfg.Requests {
			reqID := req.ID
			if !anyExplicitID {
				reqID = ps.nextID()
			}
			emitEmpty := req.Params == nil && shouldEmitEmptyParams(req.Method)
			emitReq, err := buildRequest(reqID, req.Method, req.Params, emitEmpty)
			if err != nil {
				sendErr(fmt.Errorf("mcp: build request %q: %w", req.Method, err))
				return
			}
			postReq := hps.buildPostRequest(emitReq)
			emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postReq)
			// POST accepted (202, no body).
			emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())

			// Server response is pushed over the GET SSE stream.
			respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
			if err != nil {
				sendErr(fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err))
				return
			}
			emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildSSEMessageEvent(respBytes))

			// Standalone notifications at this step (Step == i).
			for _, n := range cfg.Notifications {
				if n.Step != i {
					continue
				}
				dir := "down"
				if isClientNotification(n.Method) {
					dir = "up"
					nb, err := buildNotification(n.Method, n.Params, false)
					if err != nil {
						sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
						return
					}
					postN := hps.buildPostRequest(nb)
					emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, postN)
					emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, hps.buildSSEMessageEvent(nb))
			}
		}

		// Notifications whose Step == len(Requests) fire after the last
		// request of each round.
		for _, n := range cfg.Notifications {
			if n.Step != len(cfg.Requests) {
				continue
			}
			dir := "down"
			if isClientNotification(n.Method) {
				dir = "up"
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				postN := hps.buildPostRequest(nb)
				emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, postN)
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())
				continue
			}
			nb, err := buildNotification(n.Method, n.Params, false)
			if err != nil {
				sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
				return
			}
			emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, hps.buildSSEMessageEvent(nb))
		}
	}

	// Teardown (3 packets per socks5 template §6.2).
	if shutdown {
		emitTeardown(ctx, out, spec, dstPort, flowID, ttl, ps)
	}
}

// planStreamable emits the Streamable HTTP (2025-03-26 spec) application
// layer: single POST endpoint, responses as JSON body or SSE stream, and
// DELETE /mcp session termination (T91).
func planStreamable(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, cfg *core.MCPConfig, dstPort uint16, flowID string, ttl uint8, ps *planState, hps *httpPlanState, rounds int, shutdown bool, sendErr func(error)) {
	// initialize request via POST /mcp (Mcp-Session-Id header, §A.3).
	initID := ps.idCounter
	ps.idCounter++
	initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialize request: %w", err))
		return
	}
	postInit := hps.buildPostRequest(initReq)
	emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postInit)

	// initialize response: 200 OK + application/json body (simple
	// request/response scenario, §A.3). Server version per §7.1 / T11.
	initResp, err := buildInitializeResponse(initID, DefaultProtocolVersion, cfg.ServerInfo, cfg.ServerCapabilities)
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialize response: %w", err))
		return
	}
	emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildStreamableJSONResponse(initResp))

	// notifications/initialized via POST. Per Streamable HTTP spec
	// (2025-03-26 §transports), a POST carrying only notifications is
	// acknowledged with 202 Accepted (no body).
	initdN, err := buildInitializedNotification()
	if err != nil {
		sendErr(fmt.Errorf("mcp: build initialized notification: %w", err))
		return
	}
	postN := hps.buildPostRequest(initdN)
	emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postN)
	emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())

	// Requests loop: each request POSTed; response is a JSON body
	// (default) or an SSE stream (when Notifications interleave).
	respIdx := buildResponseIndex(cfg.Responses)
	anyExplicitID := len(cfg.Requests) > 0 && cfg.Requests[0].ID != 0

	for round := 0; round < rounds; round++ {
		for i, req := range cfg.Requests {
			reqID := req.ID
			if !anyExplicitID {
				reqID = ps.nextID()
			}
			emitEmpty := req.Params == nil && shouldEmitEmptyParams(req.Method)
			emitReq, err := buildRequest(reqID, req.Method, req.Params, emitEmpty)
			if err != nil {
				sendErr(fmt.Errorf("mcp: build request %q: %w", req.Method, err))
				return
			}
			postReq := hps.buildPostRequest(emitReq)
			emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postReq)

			respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
			if err != nil {
				sendErr(fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err))
				return
			}

			// Collect interleaved server→client notifications (Step == i).
			// When present, the response is a 200 OK + SSE stream with the
			// notifications followed by the response event (design §6.4).
			var sseParts [][]byte
			for _, n := range cfg.Notifications {
				if n.Step != i || isClientNotification(n.Method) {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				sseParts = append(sseParts, hps.buildSSEMessageEvent(nb))
			}
			if len(sseParts) > 0 {
				var stream []byte
				for _, part := range sseParts {
					stream = append(stream, part...)
				}
				stream = append(stream, hps.buildSSEMessageEvent(respBytes)...)
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildStreamableSSEResponse(stream))
			} else {
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildStreamableJSONResponse(respBytes))
			}

			// Client→server notifications at this step are POSTed; the
			// server acknowledges with 202 Accepted (no body).
			for _, n := range cfg.Notifications {
				if n.Step != i || !isClientNotification(n.Method) {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				postN := hps.buildPostRequest(nb)
				emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postN)
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())
			}
		}

		// Notifications whose Step == len(Requests) fire after the last
		// request of each round.
		for _, n := range cfg.Notifications {
			if n.Step != len(cfg.Requests) {
				continue
			}
			if isClientNotification(n.Method) {
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				postN := hps.buildPostRequest(nb)
				emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, postN)
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildPostAccepted())
				continue
			}
			nb, err := buildNotification(n.Method, n.Params, false)
			if err != nil {
				sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
				return
			}
			emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildSSEMessageEvent(nb))
		}
	}

	// DELETE /mcp terminates the session (design §2.5 / T91). The
	// planner emits this when Shutdown=true (the HTTP equivalent of the
	// TCP FIN teardown in stdio mode).
	if shutdown {
		emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, hps.buildDeleteRequest())
		emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, hps.buildDeleteResponse())
	}
}
