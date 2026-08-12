package http

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// ---- 波 2 失败测试：http 层生成器产报文事件流 ----

// newHTTPGenForTest builds the registered http layer generator (注册表反向
// 注册的工厂），失败则 t.Fatal。
func newHTTPGenForTest(t *testing.T) layers.LayerGenerator {
	t.Helper()
	g, err := layers.NewHTTPGenerator()
	if err != nil {
		t.Fatalf("NewHTTPGenerator: %v", err)
	}
	return g
}

// TestHTTPLayerGen_EmitsRequestResponseEvents verifies HTTPGenerator
// emits one up event (request bytes) then one down event (response
// bytes) per transaction, carrying the full built request/response.
func TestHTTPLayerGen_EmitsRequestResponseEvents(t *testing.T) {
	g := newHTTPGenForTest(t)
	spec := core.FlowSpec{
		DstIP: "10.0.0.2",
		HTTP: &core.HTTPConfig{
			Method: "GET",
			URI:    "/api/test",
		},
	}
	req, err := layers.NewGenRequestForHTTP(spec)
	if err != nil {
		t.Fatalf("NewGenRequestForHTTP: %v", err)
	}
	var events []layers.MessageEvent
	req.EmitMsg = func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (req+resp)", len(events))
	}
	if !events[0].Up || !strings.Contains(string(events[0].Bytes), "GET /api/test HTTP/1.1") {
		t.Errorf("event 0 = up=%v bytes=%q, want up GET request", events[0].Up, string(events[0].Bytes))
	}
	if events[1].Up || !strings.Contains(string(events[1].Bytes), "HTTP/1.1 200") {
		t.Errorf("event 1 = up=%v bytes=%q, want down 200 response", events[1].Up, string(events[1].Bytes))
	}
}

// TestHTTPLayerGen_PipelinedAllRequestsFirst verifies the pipelined
// ordering: N requests before N responses.
func TestHTTPLayerGen_PipelinedAllRequestsFirst(t *testing.T) {
	g := newHTTPGenForTest(t)
	spec := core.FlowSpec{
		DstIP: "10.0.0.2",
		HTTP: &core.HTTPConfig{
			Method:       "GET",
			URI:          "/",
			Transactions: 3,
			Pipelined:    true,
		},
	}
	req, err := layers.NewGenRequestForHTTP(spec)
	if err != nil {
		t.Fatalf("NewGenRequestForHTTP: %v", err)
	}
	var events []layers.MessageEvent
	req.EmitMsg = func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6 (3 req + 3 resp)", len(events))
	}
	for i := 0; i < 3; i++ {
		if !events[i].Up {
			t.Errorf("event %d = down, want up (all requests first)", i)
		}
	}
	for i := 3; i < 6; i++ {
		if events[i].Up {
			t.Errorf("event %d = up, want down (all responses last)", i)
		}
	}
}

// TestHTTPLayerGen_FileSourceResolvesRequest verifies FileSource bytes
// are resolved into the request event (Task 12 semantics preserved:
// PayloadCache.GetOrLoad + text/b64 derivation, byte-compatible with the
// legacy planner).
func TestHTTPLayerGen_FileSourceResolvesRequest(t *testing.T) {
	g := newHTTPGenForTest(t)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	spec := core.FlowSpec{
		DstIP: "10.0.0.2",
		HTTP: &core.HTTPConfig{
			Method:     "POST",
			URI:        "/upload",
			FileSource: &filesystem.FileSource{Literal: "HTTP-FILE-BYTES"},
		},
	}
	req, err := layers.NewGenRequestForHTTP(spec)
	if err != nil {
		t.Fatalf("NewGenRequestForHTTP: %v", err)
	}
	ctx := core.WithPayloadCache(context.Background(), pc)
	var events []layers.MessageEvent
	req.EmitMsg = func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(events[0].Bytes), "HTTP-FILE-BYTES") {
		t.Errorf("request event does not contain FileSource bytes: %q", string(events[0].Bytes))
	}
	// Content-Length must reflect the resolved byte count (15), proving the
	// event bytes were built AFTER FileSource resolution.
	if !strings.Contains(string(events[0].Bytes), "Content-Length: 15") {
		t.Errorf("request event Content-Length missing or wrong: %q", string(events[0].Bytes))
	}
	// 跨 flow 串扰防护：FileSource 解析不得污染调用方的 *HTTPConfig。
	if spec.HTTP.Body != "" {
		t.Errorf("caller HTTPConfig.Body mutated by FileSource resolution: %q", spec.HTTP.Body)
	}
}
