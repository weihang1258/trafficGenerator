package hls

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HLSGenerator is the hls terminal-layer generator ([ip→tcp→http→hls] chain).
// It produces HLS body events (playlist text, segment bytes, key bytes); the
// http layer above it wraps each event in an HTTP GET/response pair.
// The http layer is the EventTransformer; hls is the plain terminal producer.
type HLSGenerator struct{}

// Name returns "hls".
func (g *HLSGenerator) Name() string { return "hls" }

// Generate produces one MessageEvent per HLS session (down direction).
// Each event carries the body bytes (playlist text, segment bytes, or key bytes).
// The http transformer reads these events and wraps each in HTTP framing.
func (g *HLSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("hls generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	hcfg := req.Meta.HLS
	if hcfg == nil {
		hcfg = &core.HLSConfig{Profile: "rfc8216_v7"}
	}

	for _, s := range hcfg.Sessions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		body, err := buildSessionBody(&s, hcfg)
		if err != nil {
			return fmt.Errorf("hls: build body for %s (%s): %w", s.URI, s.Kind, err)
		}
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: body}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *HLSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent satisfies the EventGenerator interface; events flow through GenRequest.EmitMsg.
func (g *HLSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("hls generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// buildSessionBody builds the body bytes for one HLS session.
func buildSessionBody(s *core.HLSSession, hcfg *core.HLSConfig) ([]byte, error) {
	switch s.Kind {
	case "master":
		playlist, err := buildPlaylistBody(s, hcfg)
		if err != nil {
			return nil, err
		}
		return []byte(playlist), nil

	case "media", "refresh":
		playlist, err := buildPlaylistBody(s, hcfg)
		if err != nil {
			return nil, err
		}
		return []byte(playlist), nil

	case "segment":
		body := resolveBody(s.ResponseBody, s.ResponseBodyB64)
		if len(body) == 0 {
			body = []byte("dummy segment content")
		}
		return body, nil

	case "key":
		// AES-128 key: 16 bytes from response_body_b64, or default key
		body := resolveBody(s.ResponseBody, s.ResponseBodyB64)
		if len(body) == 0 {
			body = buildKeyBody()
		}
		return body, nil

	default:
		return nil, fmt.Errorf("hls: unknown session kind %q", s.Kind)
	}
}

// resolveBody resolves body bytes from text or base64 fields.
func resolveBody(text, b64 string) []byte {
	if b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return decoded
		}
	}
	return []byte(text)
}

func init() {
	layers.RegisterLayerGenerator("hls", func() (layers.LayerGenerator, error) {
		return &HLSGenerator{}, nil
	})
	layers.RegisterLayerValidator("hls", func(spec *core.FlowSpec) error {
		if spec.HLS == nil {
			return nil
		}
		// wire_fault flags handled at config level
		return nil
	})
}