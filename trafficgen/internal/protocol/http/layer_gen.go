package http

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HTTPGenerator is the http terminal-layer generator (http 终结层层生成器,
// 波 2 方案 A)。It produces HTTP message events (方向 + 完整报文字节) into
// the transport layer's event stream; the tcp layer owns MSS segmentation,
// seq/ack progression, handshake, and teardown. The event ordering follows
// the legacy http.go transaction loop (interleaved default / pipelined),
// byte-compatible with the legacy planner's data segment sequence.
type HTTPGenerator struct{}

// Name returns "http".
func (g *HTTPGenerator) Name() string { return "http" }

// Generate produces one message event per HTTP message (request or
// response) in transaction order. The events carry direction and the
// fully-built bytes; the transport layer segments them.
//
// 复刻 legacy http.go 事务循环（http.go:266-357）：interleaved = 每事务
// 请求紧跟响应；pipelined = 全部请求后全部响应。文件源（FileSource）在
// 循环前解析一次（http.go:249-262 语义），请求/响应字节复用 buildHTTPRequest
// /buildHTTPResponse（纯函数，无副作用，逐字节一致）。
func (g *HTTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	// 复制配置，保证 FileSource 解析不污染调用方（legacy http.go:91-107
	// 的跨 flow 数据串扰防护语义）。
	hcfg := req.Meta.HTTP
	if hcfg == nil {
		hcfg = &core.HTTPConfig{
			Method:       "GET",
			URI:          "/",
			ResponseBody: "OK",
		}
	} else {
		copied := *hcfg
		hcfg = &copied
	}

	transactions := hcfg.Transactions
	if transactions <= 0 {
		transactions = 1
	}

	// FileSource 解析（一次，循环前）：text → Body，binary → BodyB64。
	// 与 legacy http.go:249-262 一致，需 PayloadCache 注入 ctx。
	if hcfg.FileSource != nil {
		pc := core.PayloadCacheFrom(ctx)
		if pc != nil {
			if bytes, err := pc.GetOrLoad(ctx, *hcfg.FileSource); err == nil {
				if core.IsText(bytes) {
					hcfg.Body = string(bytes)
					hcfg.BodyB64 = "" // text wins over b64 when FileSource resolves
				} else {
					hcfg.BodyB64 = base64.StdEncoding.EncodeToString(bytes)
					hcfg.Body = "" // b64 wins over text for binary bytes
				}
			}
		}
	}
	requestBody := resolveRequestBody(hcfg)
	responseBody := resolveResponseBody(hcfg)

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			// 未接线即报错：绝不能静默丢事件（review LOW-4 同款纪律）。
			return fmt.Errorf("http generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	if hcfg.Pipelined {
		// HTTP pipelining (RFC 9112 §6.3.2): all requests first, then all
		// responses. Byte sequence mirrors legacy http.go:340-345.
		for i := 0; i < transactions; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			request := buildHTTPRequestBody(hcfg, req.Meta.DstIP, requestBody)
			if err := emit(layers.MessageEvent{Up: true, Bytes: []byte(request)}); err != nil {
				return err
			}
		}
		for i := 0; i < transactions; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			response := buildHTTPResponseBody(hcfg, responseBody)
			if err := emit(layers.MessageEvent{Up: false, Bytes: []byte(response)}); err != nil {
				return err
			}
		}
		return nil
	}

	// interleaved (default): request immediately followed by its response.
	for i := 0; i < transactions; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		request := buildHTTPRequestBody(hcfg, req.Meta.DstIP, requestBody)
		if err := emit(layers.MessageEvent{Up: true, Bytes: []byte(request)}); err != nil {
			return err
		}
		response := buildHTTPResponseBody(hcfg, responseBody)
		if err := emit(layers.MessageEvent{Up: false, Bytes: []byte(response)}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer (终结层报文事件
// 生成器，ChainPlanner 经此接线事件流)。
func (g *HTTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to
// satisfy the producer marker. The ChainPlanner wires events through
// EmitMsg (the synchronous callback on GenRequest); calling EmitEvent
// directly is a wiring error — fail loudly instead of silently dropping
// the event (review LOW-4 fix).
func (g *HTTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("http generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 http 层生成器工厂（layers 包不依赖 http 包）。
	layers.RegisterHTTPGenerator(func() (layers.LayerGenerator, error) {
		return &HTTPGenerator{}, nil
	})
}
