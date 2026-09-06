// Package onvif implements the ONVIF terminal layer ([ip→tcp→http→onvif] chain,
// ONVIF Core Spec Ver. 26.06, four services: device/media/ptz/events).
//
// Wire-format authority: docs/protocol-designs/67-onvif-design.md v2.1.1 — the
// four SOAP 1.2 service namespaces (tds/trt/tptz20/tev), WS-Addressing 1.0
// Action derivation (§2.3.2), WSS UsernameToken Profile 1.0 digest computation
// (§2.3.3), 11 WSDL operations, SOAP Fault structure with nested Subcode
// (§2.4), HTTP POST/2xx/4xx/5xx frame shapes, and 38-row wire fault dispatch
// table (§7) with pinned anchor words.
//
// The generator emits complete HTTP frames as MessageEvents; the http layer
// forwards them verbatim (identity transformer, isHTTPRPCInner) and the tcp layer
// owns segmentation, handshake, and teardown.
package onvif

import (
	"context"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ONVIFGenerator is the onvif terminal-layer generator.
type ONVIFGenerator struct{}

// Name returns "onvif".
func (g *ONVIFGenerator) Name() string { return "onvif" }

// Generate walks sessions (concurrent = round-robin per event index;
// sequential = session by session) and emits request/response frame pairs per
// event.
func (g *ONVIFGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("onvif generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.ONVIF
	if cfg == nil {
		cfg = &core.ONVIFConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线单事务——GetSystemDateAndTime 请求 →
		// 200 OK + UTC 日期时间。9 包（3 握手 + 2 帧 + 4 挥手）。
		sessions = []core.ONVIFSession{{
			Events: []core.ONVIFEvent{{
				Kind:      "request",
				Service:   "device",
				Operation: "GetSystemDateAndTime",
				Auth: &core.ONVIFAuth{
					Username: "admin",
					Password: "password",
				},
			}},
		}}
	}

	host := req.Meta.DstIP
	if host == "" {
		host = "192.0.2.200"
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		runs[i] = &sessionRun{sess: s, cfg: cfg, host: host}
	}

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for j := 0; j < maxLen; j++ {
			for _, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := r.buildEvents(j, emit, j == len(r.sess.Events)-1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, r := range runs {
		for i, ev := range r.sess.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			_ = ev
			if err := r.buildEvents(i, emit, i == len(r.sess.Events)-1); err != nil {
				return err
			}
		}
	}
	return nil
}

// sessionRun holds per-session generation state.
type sessionRun struct {
	sess core.ONVIFSession
	cfg  *core.ONVIFConfig
	host string
}

// setEventEndpoint stamps a per-session SrcPort / DstPort override onto an
// event (doh family pattern): 0 values fall back to the connection defaults
// inside the tcp/udp event loop.
func (run *sessionRun) setEventEndpoint(out *layers.MessageEvent) {
	if p := run.sess.SrcPort; p != 0 {
		out.SrcPort = p
	}
	if p := run.sess.DstPort; p != 0 {
		out.DstPort = p
	}
}

// buildEvents emits the request frame (up) and the auto-answer response frame
// (down). isLast controls the HTTP Connection header (close on last).
func (run *sessionRun) buildEvents(selfIdx int, emit func(layers.MessageEvent) error, isLast bool) error {
	ev := run.sess.Events[selfIdx]

	// Resolve same_as_response references before rendering.
	resolved, err := ResolveEvent(ev, run.sess.Events, selfIdx)
	if err != nil {
		return err
	}

	// Render the SOAP envelope + WSS UsernameToken.
	reqBody := BuildRequestEnvelope("s", resolved)
	respBody := BuildResponseEnvelope("s", resolved, ev.Response)

	// Wire fault: skip auto-2xx, render the error frame instead.
	if resolved.WireFault != "" {
		// Default to HTTP 500 server error for wire_fault (design §7
		// dispatch: when the request envelope is malformed the device
		// must reject with a server error).
		contentType := DefaultContentType
		if run.cfg.ContentType != "" {
			contentType = run.cfg.ContentType
		}
		overrides := map[string]string{}
		if ev.HTTP != nil && ev.HTTP.RequestHeaders != nil {
			for k, v := range ev.HTTP.RequestHeaders {
				overrides[k] = v
			}
		}
		conn := "close"
		if !isLast {
			conn = "keep-alive"
		}
		reqFrame := BuildPOSTFrame(resolved.Method, resolved.URI, run.host,
			contentType, reqBody, conn, overrides)
		out := layers.MessageEvent{Up: true, Bytes: reqFrame}
		run.setEventEndpoint(&out)
		if err := emit(out); err != nil {
			return err
		}
		respFrame := BuildErrorFrame(500, "", nil)
		out = layers.MessageEvent{Up: false, Bytes: respFrame}
		run.setEventEndpoint(&out)
		return emit(out)
	}

	// Normal case: POST + 200 with envelope body.
	reqContentType := DefaultContentType
	if run.cfg.ContentType != "" {
		reqContentType = run.cfg.ContentType
	}
	overrides := map[string]string{}
	if ev.HTTP != nil && ev.HTTP.RequestHeaders != nil {
		for k, v := range ev.HTTP.RequestHeaders {
			overrides[k] = v
		}
	}
	conn := "close"
	if !isLast {
		conn = "keep-alive"
	}
	reqFrame := BuildPOSTFrame(resolved.Method, resolved.URI, run.host,
		reqContentType, reqBody, conn, overrides)
	out := layers.MessageEvent{Up: true, Bytes: reqFrame}
	run.setEventEndpoint(&out)
	if err := emit(out); err != nil {
		return err
	}

	// Response shape depends on the explicit ev.Response override.
	status := 200
	var respFrame []byte
	if ev.Response != nil && ev.Response.HTTPStatus != 0 {
		status = ev.Response.HTTPStatus
	}
	respContentType := DefaultContentType
	if run.cfg.ContentType != "" {
		respContentType = run.cfg.ContentType
	}
	switch {
	case ev.Response != nil && ev.Response.Fault != nil:
		faultStatus := status
		if faultStatus == 200 {
			faultStatus = 500
		}
		respFrame = Build2xxFrame(faultStatus, respContentType, respBody, nil)
	case status == 401:
		respFrame = BuildErrorFrame(401, ev.Response.WWWAuthenticate, nil)
	case status < 200 || status >= 300:
		respFrame = BuildErrorFrame(status, "", nil)
	default:
		respFrame = Build2xxFrame(status, respContentType, respBody, nil)
	}
	out = layers.MessageEvent{Up: false, Bytes: respFrame}
	run.setEventEndpoint(&out)
	return emit(out)
}

// GenEvents marks this generator as a message event producer.
func (g *ONVIFGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy the
// producer marker. Events flow through GenRequest.EmitMsg only.
func (g *ONVIFGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("onvif generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("onvif", func() (layers.LayerGenerator, error) {
		return &ONVIFGenerator{}, nil
	})
	layers.RegisterLayerValidator("onvif", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}

// hostHeader is currently unused (kept for symmetry with the doh
// generator's hostHeader helper). 留作 §3.1 Host 显式用例扩展。
//
//nolint:unused
func hostHeader(dstIP string, overrides map[string]string) string {
	for k, v := range overrides {
		if strings.EqualFold(k, "Host") && v != "" {
			return v
		}
	}
	return dstIP
}
