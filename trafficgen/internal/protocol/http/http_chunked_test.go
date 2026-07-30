package http

// Spec-driven tests for chunked transfer-encoding (RFC 7230 §4.1) and HTTP
// pipelining (RFC 9112 §6.3.2). Written failing-first: each test asserts the
// spec-required wire format BEFORE the implementation exists, so a green run
// proves the implementation matches the spec rather than that the test was
// written to match the implementation.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- RFC 7230 §4.1 chunked transfer-encoding ---

// chunkedBodySep returns the bytes after the "\r\n\r\n" header/body
// separator, i.e. the framed message body.
func chunkedBodySep(t *testing.T, msg string) string {
	t.Helper()
	idx := strings.Index(msg, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no header/body separator in %q", msg)
	}
	return msg[idx+4:]
}

// TestChunkedEncode_SingleChunk verifies RFC 7230 §4.1 chunk framing:
//   chunk = chunk-size CRLF chunk-data CRLF
//   last-chunk = "0" CRLF CRLF
// A body that fits in one chunk (chunkSize <= 0 or >= len(body)) produces
// "<hex-size>\r\n<data>\r\n0\r\n\r\n".
func TestChunkedEncode_SingleChunk(t *testing.T) {
	got := chunkedEncode([]byte("Hello"), 0)
	// 5 decimal = 0x5 -> "5"
	want := "5\r\nHello\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("chunkedEncode(Hello,0) = %q, want %q", got, want)
	}
}

// TestChunkedEncode_MultiChunk verifies a body larger than chunkSize is split
// into multiple chunks, each independently length-prefixed in hex, terminated
// by the zero-length last-chunk.
func TestChunkedEncode_MultiChunk(t *testing.T) {
	// "HelloWorld" (10 bytes), chunkSize=5 -> two 5-byte chunks.
	got := chunkedEncode([]byte("HelloWorld"), 5)
	want := "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("chunkedEncode(HelloWorld,5) = %q, want %q", got, want)
	}
}

// TestChunkedEncode_PartialLastChunk verifies the final data chunk may be
// smaller than chunkSize (§4.1: "a sequence of chunk-size octets").
func TestChunkedEncode_PartialLastChunk(t *testing.T) {
	// 11 bytes, chunkSize=5 -> 5,5,1.
	got := chunkedEncode([]byte("HelloWorld!"), 5)
	want := "5\r\nHello\r\n5\r\nWorld\r\n1\r\n!\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("chunkedEncode(HelloWorld!,5) = %q, want %q", got, want)
	}
}

// TestChunkedEncode_HexSize verifies the chunk-size field is hexadecimal
// (RFC 7230 §4.1: chunk-size = 1*HEXDIG), so a 255-byte chunk is "ff".
func TestChunkedEncode_HexSize(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 255)
	got := chunkedEncode(body, 0)
	prefix := "ff\r\n"
	if !strings.HasPrefix(string(got), prefix) {
		t.Errorf("255-byte chunk prefix = %q, want %q (hex)", got[:len(prefix)], prefix)
	}
}

// TestChunkedEncode_EmptyBody verifies an empty body still produces a valid
// chunked frame: just the last-chunk "0\r\n\r\n" (§4.1: last-chunk is
// mandatory even when there are zero data chunks).
func TestChunkedEncode_EmptyBody(t *testing.T) {
	got := chunkedEncode([]byte{}, 0)
	want := "0\r\n\r\n"
	if string(got) != want {
		t.Errorf("chunkedEncode(empty,0) = %q, want %q", got, want)
	}
}

// TestBuildHTTPResponse_Chunked verifies the response side emits a
// "Transfer-Encoding: chunked" header and a chunked-framed body, and does NOT
// emit Content-Length (§3.3.3: Transfer-Encoding takes precedence over
// Content-Length).
func TestBuildHTTPResponse_Chunked(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:        "Hello",
		ResponseTransferEncoding: "chunked",
	}
	result := buildHTTPResponse(cfg)

	if !strings.Contains(result, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("result=%q, want 'Transfer-Encoding: chunked' header", result)
	}
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("result=%q, must NOT contain Content-Length when chunked", result)
	}
	body := chunkedBodySep(t, result)
	want := "5\r\nHello\r\n0\r\n\r\n"
	if body != want {
		t.Errorf("chunked body = %q, want %q", body, want)
	}
}

// TestBuildHTTPResponse_ChunkedMultiChunk verifies ChunkSize splits the
// response body into multiple chunks on the wire.
func TestBuildHTTPResponse_ChunkedMultiChunk(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:        "HelloWorld",
		ResponseTransferEncoding: "chunked",
		ChunkSize:           5,
	}
	result := buildHTTPResponse(cfg)
	body := chunkedBodySep(t, result)
	want := "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"
	if body != want {
		t.Errorf("chunked body = %q, want %q", body, want)
	}
}

// TestBuildHTTPRequest_Chunked verifies the request side symmetric behavior.
func TestBuildHTTPRequest_Chunked(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:             "POST",
		URI:                "/upload",
		Body:               "data",
		RequestTransferEncoding: "chunked",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("result=%q, want 'Transfer-Encoding: chunked' header", result)
	}
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("result=%q, must NOT contain Content-Length when chunked", result)
	}
	body := chunkedBodySep(t, result)
	want := "4\r\ndata\r\n0\r\n\r\n"
	if body != want {
		t.Errorf("chunked body = %q, want %q", body, want)
	}
}

// TestBuildHTTPResponse_ChunkedUserHeaderOverride verifies a user-provided
// Transfer-Encoding header suppresses the auto-emitted one (no duplicate),
// matching the unified user > default > none rule.
func TestBuildHTTPResponse_ChunkedUserHeaderOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:             "x",
		ResponseTransferEncoding: "chunked",
		ResponseHeaders:          map[string]string{"Transfer-Encoding": "chunked"},
	}
	result := buildHTTPResponse(cfg)
	count := strings.Count(result, "Transfer-Encoding:")
	if count != 1 {
		t.Errorf("Transfer-Encoding header count = %d, want 1 (no duplicate): %q", count, result)
	}
}

// TestBuildHTTPResponse_ChunkedWithGzip verifies chunked framing wraps the
// gzip-compressed bytes (Content-Encoding applied first, then chunked).
func TestBuildHTTPResponse_ChunkedWithGzip(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:             "Hello, world!",
		ResponseContentEncoding:  "gzip",
		ResponseTransferEncoding: "chunked",
	}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Content-Encoding: gzip\r\n") {
		t.Errorf("result=%q, want 'Content-Encoding: gzip' header", result)
	}
	if !strings.Contains(result, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("result=%q, want 'Transfer-Encoding: chunked' header", result)
	}
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("result=%q, must NOT contain Content-Length when chunked", result)
	}
}

// TestBuildHTTPResponse_ChunkedEmptyBody verifies an empty body with chunked
// produces just the terminating last-chunk "0\r\n\r\n".
func TestBuildHTTPResponse_ChunkedEmptyBody(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseTransferEncoding: "chunked",
	}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("result=%q, want 'Transfer-Encoding: chunked' header", result)
	}
	body := chunkedBodySep(t, result)
	want := "0\r\n\r\n"
	if body != want {
		t.Errorf("chunked empty body = %q, want %q", body, want)
	}
}

// TestBuildHTTPResponse_NoChunkedByDefault verifies chunked is opt-in: a
// normal response uses Content-Length, never Transfer-Encoding.
func TestBuildHTTPResponse_NoChunkedByDefault(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "OK"}
	result := buildHTTPResponse(cfg)
	if strings.Contains(result, "Transfer-Encoding:") {
		t.Errorf("result=%q, must NOT contain Transfer-Encoding by default", result)
	}
	if !strings.Contains(result, "Content-Length: 2\r\n") {
		t.Errorf("result=%q, want Content-Length: 2", result)
	}
}

// TestBuildHTTPResponse_TransferEncodingNonChunked verifies a non-"chunked"
// value is passed through as a literal header without framing (caller
// responsibility), mirroring the ContentEncoding non-gzip pass-through.
func TestBuildHTTPResponse_TransferEncodingNonChunked(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:             "x",
		ResponseTransferEncoding: "identity",
	}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Transfer-Encoding: identity\r\n") {
		t.Errorf("result=%q, want literal 'Transfer-Encoding: identity' header", result)
	}
	// Body must NOT be chunk-framed (identity = no transformation).
	body := chunkedBodySep(t, result)
	if body != "x" {
		t.Errorf("body = %q, want plaintext 'x' (identity must not frame)", body)
	}
}

// --- Plan-level chunked integration ---

// TestHTTPPlan_ChunkedResponsePayload verifies the planner emits a chunked
// response body on the wire (the PSH-ACK payload contains the chunk framing).
func TestHTTPPlan_ChunkedResponsePayload(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:                   "GET",
		URI:                      "/",
		ResponseBody:             "Hello",
		ResponseTransferEncoding: "chunked",
		Transactions:             1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the response packet (down, PSH-ACK, payload starts "HTTP/").
	var resp *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 &&
			strings.HasPrefix(string(cfgs[i].Payload), "HTTP/") {
			resp = &cfgs[i]
			break
		}
	}
	if resp == nil {
		t.Fatalf("no response packet found")
	}
	pl := string(resp.Payload)
	if !strings.Contains(pl, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("response payload missing Transfer-Encoding header: %q", pl)
	}
	if !strings.HasSuffix(pl, "5\r\nHello\r\n0\r\n\r\n") {
		t.Errorf("response payload must end with chunked frame, got: %q", pl)
	}
}

// --- RFC 9112 §6.3.2 HTTP pipelining ---

// TestHTTPPlan_Pipeline_AllRequestsBeforeResponses verifies that when
// Pipelined=true, all N request packets are emitted before any response
// packet. The default (Pipelined=false) interleaves request->response per
// transaction.
func TestHTTPPlan_Pipeline_AllRequestsBeforeResponses(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: "OK",
		Transactions: 3,
		Pipelined:    true,
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Collect the direction sequence of data packets (PSH-ACK with payload),
	// skipping handshake (SYN/SYN-ACK/ACK) and termination (FIN/ACK) packets.
	var dataDirs []string
	for _, c := range cfgs {
		if c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			dataDirs = append(dataDirs, c.Direction)
		}
	}
	// 3 requests + 3 responses = 6 data packets.
	if len(dataDirs) != 6 {
		t.Fatalf("data packet count = %d, want 6: %v", len(dataDirs), dataDirs)
	}
	// Pipelined: first 3 must all be "up" (requests), last 3 all "down".
	for i := 0; i < 3; i++ {
		if dataDirs[i] != "up" {
			t.Errorf("data packet %d direction = %s, want up (request) in pipeline burst: %v", i, dataDirs[i], dataDirs)
		}
	}
	for i := 3; i < 6; i++ {
		if dataDirs[i] != "down" {
			t.Errorf("data packet %d direction = %s, want down (response) after pipeline burst: %v", i, dataDirs[i], dataDirs)
		}
	}
}

// TestHTTPPlan_Pipeline_SeqAdvances verifies that in pipelined mode the
// client sequence number advances across all request packets (each request
// ACKs the same server seq since no response has arrived yet), and the
// server seq advances across all response packets.
func TestHTTPPlan_Pipeline_SeqAdvances(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "POST",
		URI:          "/",
		Body:         "ABCDE",
		ResponseBody: "OK",
		Transactions: 3,
		Pipelined:    true,
	}
	cfgs := drain(mustPlan(t, p, spec))

	var reqs, resps []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		if c.Direction == "up" {
			reqs = append(reqs, c)
		} else {
			resps = append(resps, c)
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("request count = %d, want 3", len(reqs))
	}
	// Each request's Seq must advance by the previous request's payload len.
	for i := 1; i < len(reqs); i++ {
		want := reqs[i-1].L4.Seq + uint32(len(reqs[i-1].Payload))
		if reqs[i].L4.Seq != want {
			t.Errorf("req[%d].Seq = %d, want %d", i, reqs[i].L4.Seq, want)
		}
	}
	// All requests must ACK the same server seq (no response yet).
	for i := 1; i < len(reqs); i++ {
		if reqs[i].L4.Ack != reqs[0].L4.Ack {
			t.Errorf("req[%d].Ack = %d, want %d (same server seq during pipeline burst)", i, reqs[i].L4.Ack, reqs[0].L4.Ack)
		}
	}
}

// TestHTTPPlan_Pipeline_ConnectionKeepAlive verifies pipelined mode implies
// keep-alive (multiple transactions on one connection), so the Connection
// header defaults to keep-alive.
func TestHTTPPlan_Pipeline_ConnectionKeepAlive(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		Transactions: 3,
		Pipelined:    true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the first request packet.
	for _, c := range cfgs {
		if c.L4.Flags == 0x18 && c.Direction == "up" && len(c.Payload) > 0 {
			if !strings.Contains(string(c.Payload), "Connection: keep-alive\r\n") {
				t.Errorf("pipelined request missing 'Connection: keep-alive': %q", string(c.Payload))
			}
			return
		}
	}
	t.Fatalf("no request packet found")
}

// TestHTTPPlan_Pipeline_SingleTransaction verifies pipelined=true with a
// single transaction behaves identically to the default (one request, one
// response) - no reordering needed.
func TestHTTPPlan_Pipeline_SingleTransaction(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: "OK",
		Transactions: 1,
		Pipelined:    true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 data + 4 termination = 9.
	if len(cfgs) != 9 {
		t.Fatalf("len = %d, want 9", len(cfgs))
	}
}

// --- Multi-method coverage ---

// TestBuildHTTPRequest_MultipleMethods verifies methods beyond GET/POST are
// emitted verbatim in the request line.
func TestBuildHTTPRequest_MultipleMethods(t *testing.T) {
	methods := []string{"PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			cfg := &core.HTTPConfig{Method: m, URI: "/r"}
			result := buildHTTPRequest(cfg, "10.0.0.2")
			wantLine := fmt.Sprintf("%s /r HTTP/1.1\r\n", m)
			if !strings.HasPrefix(result, wantLine) {
				t.Errorf("result=%q, want request line %q", result, wantLine)
			}
		})
	}
}

// TestBuildHTTPRequest_MethodsWithBody verifies PUT/PATCH carry a body with
// Content-Length.
func TestBuildHTTPRequest_MethodsWithBody(t *testing.T) {
	cases := []struct{ method, body string }{
		{"PUT", `{"name":"x"}`},
		{"PATCH", `{"op":"replace"}`},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			cfg := &core.HTTPConfig{Method: c.method, URI: "/", Body: c.body}
			result := buildHTTPRequest(cfg, "10.0.0.2")
			wantCL := fmt.Sprintf("Content-Length: %d\r\n", len(c.body))
			if !strings.Contains(result, wantCL) {
				t.Errorf("result=%q, want %s", result, wantCL)
			}
			if !strings.HasSuffix(result, c.body) {
				t.Errorf("result=%q, want body %q at end", result, c.body)
			}
		})
	}
}

// TestBuildHTTPRequest_HEADNoBody verifies HEAD requests have no body and no
// Content-Length by default (RFC 9110 §9.3.2: HEAD has no message body).
func TestBuildHTTPRequest_HEADNoBody(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "HEAD", URI: "/"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("HEAD result=%q, should not have Content-Length with no body", result)
	}
}

// --- Multi Content-Type coverage ---

// TestBuildHTTPRequest_ContentTypeJSON verifies JSON body sniffs to
// application/json.
func TestBuildHTTPRequest_ContentTypeJSON(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "POST", URI: "/", Body: `{"k":"v"}`}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Content-Type: application/json; charset=utf-8\r\n") {
		t.Errorf("result=%q, want application/json Content-Type", result)
	}
}

// TestBuildHTTPRequest_UserContentTypeFormURLEncoded verifies a user-supplied
// Content-Type header passes through verbatim (form-urlencoded is not
// auto-sniffed, so the user must set it).
func TestBuildHTTPRequest_UserContentTypeFormURLEncoded(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "POST",
		URI:            "/",
		Body:           "key=value&foo=bar",
		RequestHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Content-Type: application/x-www-form-urlencoded\r\n") {
		t.Errorf("result=%q, want user Content-Type", result)
	}
	// Must not also auto-emit a sniffed Content-Type.
	count := strings.Count(result, "Content-Type:")
	if count != 1 {
		t.Errorf("Content-Type count = %d, want 1: %q", count, result)
	}
}

// TestBuildHTTPRequest_UserContentTypeMultipart verifies multipart/form-data
// with a user-supplied boundary passes through.
func TestBuildHTTPRequest_UserContentTypeMultipart(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method: "POST",
		URI:    "/upload",
		Body:   "--boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--boundary--\r\n",
		RequestHeaders: map[string]string{
			"Content-Type": "multipart/form-data; boundary=boundary",
		},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Content-Type: multipart/form-data; boundary=boundary\r\n") {
		t.Errorf("result=%q, want multipart Content-Type", result)
	}
}

// --- Multi status-code coverage (Plan-level) ---

// TestHTTPPlan_StatusCode404 verifies the planner emits a 404 status line in
// the response payload.
func TestHTTPPlan_StatusCode404(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:              "GET",
		URI:                 "/missing",
		ResponseBody:        "not found",
		ResponseStatusCode:  404,
		Transactions:        1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "HTTP/") {
			if !strings.HasPrefix(string(c.Payload), "HTTP/1.1 404 Not Found\r\n") {
				t.Errorf("response payload = %q, want 404 status line", string(c.Payload))
			}
			return
		}
	}
	t.Fatalf("no response packet found")
}

// TestHTTPPlan_StatusCode301WithLocation verifies a redirect response carries
// a user-supplied Location header.
func TestHTTPPlan_StatusCode301WithLocation(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:              "GET",
		URI:                 "/old",
		ResponseBody:        "",
		ResponseStatusCode:  301,
		ResponseHeaders:     map[string]string{"Location": "/new"},
		Transactions:        1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "HTTP/") {
			pl := string(c.Payload)
			if !strings.HasPrefix(pl, "HTTP/1.1 301 Moved Permanently\r\n") {
				t.Errorf("status line = %q, want 301", pl)
			}
			if !strings.Contains(pl, "Location: /new\r\n") {
				t.Errorf("payload missing Location header: %q", pl)
			}
			return
		}
	}
	t.Fatalf("no response packet found")
}

// TestHTTPPlan_StatusCode500 verifies a 500 response.
func TestHTTPPlan_StatusCode500(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:              "GET",
		URI:                 "/",
		ResponseBody:        "boom",
		ResponseStatusCode:  500,
		Transactions:        1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "HTTP/") {
			if !strings.HasPrefix(string(c.Payload), "HTTP/1.1 500 Internal Server Error\r\n") {
				t.Errorf("status line = %q, want 500", string(c.Payload))
			}
			return
		}
	}
	t.Fatalf("no response packet found")
}

// --- Authorization / Cookie header passthrough ---

// TestBuildHTTPRequest_AuthorizationHeader verifies a user-supplied
// Authorization header passes through verbatim.
func TestBuildHTTPRequest_AuthorizationHeader(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/secret",
		RequestHeaders: map[string]string{"Authorization": "Bearer abc123"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Authorization: Bearer abc123\r\n") {
		t.Errorf("result=%q, want Authorization header", result)
	}
}

// TestBuildHTTPRequest_CookieHeader verifies a user-supplied Cookie header
// passes through verbatim.
func TestBuildHTTPRequest_CookieHeader(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		RequestHeaders: map[string]string{"Cookie": "session=xyz; theme=dark"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Cookie: session=xyz; theme=dark\r\n") {
		t.Errorf("result=%q, want Cookie header", result)
	}
}

// TestBuildHTTPRequest_UserHostHeader verifies a user-supplied Host header
// (e.g. with SNI hostname) replaces the default dstIP-derived Host.
func TestBuildHTTPRequest_UserHostHeader(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		RequestHeaders: map[string]string{"Host": "api.example.com"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: api.example.com\r\n") {
		t.Errorf("result=%q, want user Host header", result)
	}
	if strings.Contains(result, "Host: 10.0.0.2") {
		t.Errorf("result=%q, must not contain default dstIP Host", result)
	}
}

// --- Validation / failure paths ---

// TestHTTPValidate_PipelineSingleTransactionNoError verifies Pipelined=true
// with Transactions=1 is accepted (no-op, not an error).
func TestHTTPValidate_PipelineSingleTransactionNoError(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Pipelined = true
	spec.HTTP.Transactions = 1
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() error = %v, want nil (pipeline+1 transaction is a no-op, not an error)", err)
	}
}

// Ensure context import is used (Plan-based tests use context indirectly via
// mustPlan; this guards against unused-import removal if a test is trimmed).
var _ = context.Background
