package http_flv

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HTTPFLVGenerator is the http_flv terminal-layer generator (http_flv 终结层
// 生成器, [ip→tcp→http→http_flv] 链)。It produces FLV body events (just the
// FLV bytes, no HTTP framing); the http layer above it wraps each FLV body in
// an HTTP GET/200 pair. The http layer is the EventTransformer; http_flv is
// the plain terminal producer.
type HTTPFLVGenerator struct{}

// Name returns "http_flv".
func (g *HTTPFLVGenerator) Name() string { return "http_flv" }

// Generate produces one MessageEvent per FLV body (down direction) from the
// configured tags. Each event carries the complete FLV byte content: 9-byte
// FLV header + 4-byte PreviousTagSize0 + tag sequence. The http transformer
// reads these events and wraps each in HTTP 200 response framing.
//
// Rounds > 1 produces multiple FLV body events, one per round, so the http
// transformer can emit multiple GET/200 transactions over the same connection.
func (g *HTTPFLVGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("http_flv generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	hcfg := req.Meta.HTTPFLV
	if hcfg == nil {
		hcfg = &core.HTTPFLVConfig{Flags: 0x05, Rounds: 1}
	}

	rounds := hcfg.Rounds
	if rounds <= 0 {
		rounds = 1
	}

	// 每轮产一个 FLV body 事件（down 方向）
	for i := 0; i < rounds; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		body, err := buildFLVBody(hcfg)
		if err != nil {
			return fmt.Errorf("http_flv: build FLV body (round %d): %w", i, err)
		}
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: body}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer (终结层报文事件
// 生成器, ChainPlanner 经此接线事件流到 http 变换器)。
func (g *HTTPFLVGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *HTTPFLVGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("http_flv generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("http_flv", func() (layers.LayerGenerator, error) {
		return &HTTPFLVGenerator{}, nil
	})
	layers.RegisterLayerValidator("http_flv", func(spec *core.FlowSpec) error {
		if spec.HTTPFLV == nil {
			return nil
		}
		if spec.HTTPFLV.Flags&0x05 != spec.HTTPFLV.Flags {
			return fmt.Errorf("http_flv: flags 0x%02x has reserved bits set (only bit0=video, bit2=audio allowed)", spec.HTTPFLV.Flags)
		}
		if spec.HTTPFLV.Rounds < 0 {
			return fmt.Errorf("http_flv: rounds %d must be >= 0", spec.HTTPFLV.Rounds)
		}
		// 验证 tag 类型
		for i, t := range spec.HTTPFLV.Tags {
			switch t.Type {
			case "script", "audio", "video":
				// valid
			default:
				return fmt.Errorf("http_flv: tag[%d] unknown type %q", i, t.Type)
			}
		}
		return nil
	})
}