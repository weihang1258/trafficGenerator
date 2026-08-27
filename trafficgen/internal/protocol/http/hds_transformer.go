package http

import (
	"context"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// generateHDSTransformer implements the http layer's transformer mode for the
// hds chain [ip→tcp→http→hds].
//
// The hds terminal generator produces one body event per session (F4M manifest
// XML, bootstrap box bytes, or F4F fragment bytes). The http transformer wraps
// each body event in HTTP GET/200 framing:
//
//   - manifest body → GET <manifest uri> → 200 with Content-Type application/f4m+xml
//   - bootstrap body → GET <bootstrap uri> → 200 with application/octet-stream
//   - fragment body → GET <fragment uri> → 200 with video/f4f
//
// Connection stays keep-alive so one TCP session can carry manifest →
// bootstrap → fragment GETs in order. The Generate() dispatcher in
// layer_gen.go routes to this when req.Meta.HDS != nil.
func (g *HTTPGenerator) generateHDSTransformer(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("http generator: EmitMsg is nil (hds transformer mode)")
	}
	version := "HTTP/1.1"
	if v := layerConfigString(req.Layer.Config, "version"); v != "" {
		if strings.HasPrefix(v, "HTTP/") {
			version = v
		} else {
			version = "HTTP/" + v
		}
	}

	hcfg := req.Meta.HDS
	if hcfg == nil {
		return fmt.Errorf("http generator: hds transformer mode requires Meta.HDS config")
	}

	// 每个 session 恰好一个 body 事件（行序 = JSON 数组序；会话间不交错）。
	for i := range hcfg.Sessions {
		s := &hcfg.Sessions[i]
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev, ok := g.readInnerBody(ctx, req.Meta.Events)
		if !ok {
			return fmt.Errorf("http generator: inner hds stream closed before body event %d/%d", i+1, len(hcfg.Sessions))
		}

		uri := s.URI
		if uri == "" && s.Kind == "manifest" && hcfg.Manifest != nil {
			uri = hcfg.Manifest.URI
		}
		if uri == "" {
			uri = "/live/channel.f4m"
		}

		contentType, err := hdsContentType(s.Kind)
		if err != nil {
			drainEvents(ctx, req.Meta.Events)
			return err
		}

		reqBytes := buildHTTPHlsGetRequest(version, uri, req.Meta.DstIP, true)
		if err := req.EmitMsg(layers.MessageEvent{Up: true, Bytes: []byte(reqBytes)}); err != nil {
			drainEvents(ctx, req.Meta.Events)
			return err
		}
		respBytes := buildHTTPHlsResponse(version, 200, contentType, ev.Bytes, true)
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: []byte(respBytes)}); err != nil {
			drainEvents(ctx, req.Meta.Events)
			return err
		}
	}
	return drainEvents(ctx, req.Meta.Events)
}

// hdsContentType returns the default Content-Type for one HDS resource kind.
func hdsContentType(kind string) (string, error) {
	switch kind {
	case "manifest":
		return "application/f4m+xml", nil
	case "bootstrap":
		return "application/octet-stream", nil
	case "fragment":
		return "video/f4f", nil
	default:
		return "", fmt.Errorf("http generator: unknown HDS session kind %q", kind)
	}
}