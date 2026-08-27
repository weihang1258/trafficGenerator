package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// generateHLSTransformer implements the http layer's transformer mode for the
// hls chain [ip→tcp→http→hls].
//
// The hls terminal generator produces one body event per session (playlist
// text or segment/key bytes). The http transformer wraps body events in
// HTTP framing:
//
//   - playlist body (master/media/refresh) → GET <session uri> → 200
//     with Content-Type application/vnd.apple.mpegurl
//   - segment body → GET resource uri → 200/206 with resource Content-Type
//   - key body → GET key uri → 200 with application/octet-stream
//
// Response status/content-type/body come from the session config (explicit
// 404/410/429/5xx, response_content_type, response_body/b64). Rounds defaults
// to 1.
// generateHLSTransformer is defined in this file; the Generate() dispatcher in
// layer_gen.go routes to it when req.Meta.HLS != nil.

// hlsResponse describes one wrapped HTTP response for a body event.
type hlsResponse struct {
	statusCode  int
	contentType string
	body        []byte
	keepAlive   bool
}

// generateHLSTransformer is the HLS transformer entry.
func (g *HTTPGenerator) generateHLSTransformer(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("http generator: EmitMsg is nil (hls transformer mode)")
	}
	drainFunc := drainEvents
	version := "HTTP/1.1"
	if v := layerConfigString(req.Layer.Config, "version"); v != "" {
		if strings.HasPrefix(v, "HTTP/") {
			version = v
		} else {
			version = "HTTP/" + v
		}
	}

	hcfg := req.Meta.HLS
	if hcfg == nil {
		return fmt.Errorf("http generator: hls transformer mode requires Meta.HLS config")
	}
	if hcfg.Profile == "" {
		hcfg.Profile = "rfc8216_v7"
	}

	// sessions 事件流：planner 依次产出，transformer 依次包装（行序 =
	// JSON 数组序；会话间事件不交错）。
	for i := range hcfg.Sessions {
		s := &hcfg.Sessions[i]
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 读内层 body 事件（每个 session 恰好一个）。
		ev, ok := g.readInnerBody(ctx, req.Meta.Events)
		if !ok {
			return fmt.Errorf("http generator: inner hls stream closed before body event %d/%d", i+1, len(hcfg.Sessions))
		}

		resp, err := g.hlsWrappedResponse(s, ev.Bytes, hcfg)
		if err != nil {
			drainFunc(ctx, req.Meta.Events)
			return err
		}
		// GET 请求（up）→ 响应（down）。
		reqBytes := buildHTTPHlsGetRequest(version, s.URI, req.Meta.DstIP, resp.keepAlive)
		if err := req.EmitMsg(layers.MessageEvent{Up: true, Bytes: []byte(reqBytes)}); err != nil {
			drainFunc(ctx, req.Meta.Events)
			return err
		}
		if resp.body == nil && s.ResponseBodyB64 == "" && s.ResponseBody == "" {
			// 无显式 body：用内层 body 事件（playlist/segment/key bytes）
			resp.body = ev.Bytes
		}
		respBytes := buildHTTPHlsResponse(version, resp.statusCode, resp.contentType, resp.body, resp.keepAlive)
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: []byte(respBytes)}); err != nil {
			drainFunc(ctx, req.Meta.Events)
			return err
		}
	}
	return drainFunc(ctx, req.Meta.Events)
}

// drainEvents 排空内层事件流（结构性错误退出前）。
func drainEvents(ctx context.Context, events <-chan layers.MessageEvent) error {
	for events != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		select {
		case _, ok := <-events:
			if !ok {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// hlsWrappedResponse computes the wrapped HTTP response for one body event.
func (g *HTTPGenerator) hlsWrappedResponse(s *core.HLSSession, innerBody []byte, hcfg *core.HLSConfig) (hlsResponse, error) {
	keepAlive := true
	resp := hlsResponse{statusCode: 200, keepAlive: keepAlive}

	switch s.Kind {
	case "master":
		resp.contentType = "application/vnd.apple.mpegurl"
		resp.body = innerBody
	case "media", "refresh":
		resp.contentType = "application/vnd.apple.mpegurl"
		resp.body = innerBody
	case "segment":
		resp.contentType = "video/mp2t"
		if s.ResponseContentType != "" {
			resp.contentType = s.ResponseContentType
		}
		resp.body = innerBody
	case "key":
		resp.contentType = "application/octet-stream"
		resp.body = innerBody
	default:
		return resp, fmt.Errorf("http generator: unknown HLS session kind %q", s.Kind)
	}

	// 显式业务错误（404/410/429/5xx）不置 body。
	if s.ResponseStatusCode > 0 {
		resp.statusCode = s.ResponseStatusCode
		// 4xx/5xx 视为错误响应：保留空 body（无 Content-Length body）
		resp.body = nil
	}
	return resp, nil
}

// buildHTTPHlsGetRequest builds the HTTP GET request for one HLS resource.
// request-target 使用 session 的 uri（相对/绝对原样；path-absolute 由
// validator 保证）。Connection: keep-alive 恒置（同一连接多 GET）。
func buildHTTPHlsGetRequest(version, uri, dstIP string, keepAlive bool) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("GET %s %s\r\n", uri, version))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP)))
	if keepAlive {
		sb.WriteString("Connection: keep-alive\r\n")
	} else {
		sb.WriteString("Connection: close\r\n")
	}
	sb.WriteString("\r\n")
	return sb.String()
}

// buildHTTPHlsResponse builds one HTTP response carrying an HLS body.
// 206 时带 Content-Range（response_status_code=206 + 显式 byte_range）。
func buildHTTPHlsResponse(version string, statusCode int, contentType string, body []byte, keepAlive bool) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", version, statusCode, statusTextFor(statusCode)))
	if contentType != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if statusCode != 204 && statusCode != 304 && statusCode >= 200 && statusCode < 300 {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	if statusCode >= 400 {
		// 4xx/5xx：无 body
	} else {
		if keepAlive {
			sb.WriteString("Connection: keep-alive\r\n")
		} else {
			sb.WriteString("Connection: close\r\n")
		}
	}
	sb.WriteString("\r\n")
	if statusCode < 400 {
		sb.Write(body)
	}
	return sb.String()
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}