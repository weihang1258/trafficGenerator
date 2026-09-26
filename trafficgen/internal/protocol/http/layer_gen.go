package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HTTPGenerator is the http terminal-layer generator (http 终结层层生成器,
// 波 2 方案 A)。It produces HTTP message events (方向 + 完整报文字节) into
// the transport layer's event stream; the tcp layer owns MSS segmentation,
// seq/ack progression, handshake, and teardown. The event ordering follows
// the legacy http.go transaction loop (interleaved default / pipelined),
// byte-compatible with the legacy planner's data segment sequence.
//
// It is also an EventTransformer (http_flv 链 [ip→tcp→http→http_flv]): when
// an inner terminal stream exists (Meta.Events != nil), the http layer wraps
// each inner FLV body event in an HTTP GET request + 200 response pair —
// identical to how tls transforms the inner event stream. In terminal mode
// (Meta.Events == nil) the behavior is unchanged.
type HTTPGenerator struct{}

// Name returns "http".
func (g *HTTPGenerator) Name() string { return "http" }

// TransformEvents marks this generator as an event transformer (http_flv 链路
// 上 http 位于终结层 http_flv 与 transport tcp 之间：FLV body 事件由
// http_flv 产出，http 变换后（GET/200 帧）转发给 tcp。终端模式同样满足
// 标记——assertEventWiring 只在结构上要求该位置的层实现标记，终结层本身
// 的 GenEvents 分支不检查 TransformEvents)。
func (g *HTTPGenerator) TransformEvents() bool { return true }

// Generate produces one message event per HTTP message (request or
// response) in transaction order. The events carry direction and the
// fully-built bytes; the transport layer segments them.
//
// 复刻 legacy http.go 事务循环（http.go:266-357）：interleaved = 每事务
// 请求紧跟响应；pipelined = 全部请求后全部响应。文件源（FileSource）在
// 循环前解析一次（http.go:249-262 语义），请求/响应字节复用 buildHTTPRequest
// /buildHTTPResponse（纯函数，无副作用，逐字节一致）。
func (g *HTTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	// 变换器模式（http_flv 链 [ip→tcp→http→http_flv]）：http 不是终结层，
	// 而是把内层 http_flv 的 FLV body 事件包成 HTTP GET/200 帧的事件变换器。
	// 检测入口：req.Meta.HTTPFLV 非 nil 即 http_flv 终结层配置存在（终结层
	// 模式该字段恒 nil——纯 http 链不设 HTTPFLV 配置）。注意不能以
	// req.Meta.Events 做判别：驱动接线把 transport 事件流写入 meta.Events
	// （transformCh[n]），终结层 http 的 Meta.Events 也非 nil，用它判别会
	// 误入变换器模式并阻塞在空事件流上。
	if req.Meta.HTTPFLV != nil {
		return g.generateHTTPFLVTransformer(ctx, req)
	}
	if req.Meta.HLS != nil {
		return g.generateHLSTransformer(ctx, req)
	}
	if req.Meta.HDS != nil {
		return g.generateHDSTransformer(ctx, req)
	}
	// 透传变换器模式（B6 HTTP-RPC 族 [ip→tcp→http→gbt/…]）：gbt 等 HTTP
	// JSON-RPC 终结层的事件字节已是完整 HTTP 帧（请求行/状态行/头/体按各自
	// 契约钉死），http 层不重包装，原样转发到 tcp——与 http_flv/hls/hds 的
	// "内层产 body、http 包帧"分工不同（那些内层只有 body 语义）。检测入口
	// 同款：Meta 里存在该族的终结层配置即进入透传。
	if isHTTPRPCInner(req.Meta) {
		return g.generateForwardTransformer(ctx, req)
	}
	// 终结层模式（既有行为分派到老逻辑）
	return g.generateTerminal(ctx, req)
}

// isHTTPRPCInner reports whether the inner terminal layer emits pre-framed
// HTTP messages that must be forwarded verbatim (identity transformer).
func isHTTPRPCInner(meta layers.FlowMeta) bool {
	return meta.GBT != nil || meta.GetWork != nil || meta.CWMP != nil || meta.DOH != nil ||
		meta.ONVIF != nil || meta.MMSE != nil || // D-MMSE-1：http 族第 5 协议（WAP-209 PDU 是完整 HTTP 帧）
		meta.NTLM != nil || // D-NTLM-1：http 族第 6 协议（http-negotiate profile 的 401/Negotiate 帧由 ntlm 层自封，http 层透传）
		meta.OCSP != nil || // D-OCSP-1：http 族第 7 协议（OCSP 请求/响应是完整 HTTP 帧，裸 TCP 整 DER 直发）
		meta.SPNEGO != nil // D-SPNEGO-1：http 族第 8 协议（http profile 的 401/Negotiate 帧由 spnego 层自封，http 层透传）
}

// generateForwardTransformer forwards the inner terminal stream's events
// verbatim (透传变换器)：每事件经 EmitMsg 原样转发，流关闭即结束。事件字节
// 是内层已构造好的完整 HTTP 帧方向与字节，tcp 层照常分段/握手/挥手。
func (g *HTTPGenerator) generateForwardTransformer(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("http generator: EmitMsg is nil (forward transformer mode)")
	}
	events := req.Meta.Events
	for events != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if err := req.EmitMsg(ev); err != nil {
				return err
			}
		}
	}
	return nil
}

// generateTerminal is the original terminal-layer Generate body (见上文注释
// 与 legacy http.go 事务循环)，行为与引入变换器模式前逐字一致。
func (g *HTTPGenerator) generateTerminal(ctx context.Context, req *layers.GenRequest) error {
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
	return g.terminalLoop(ctx, req, hcfg)
}

// generatorTransformerState 无状态：本生成器无字段。FLV body 事件来自
// Meta.Events（http_flv 终结层 → transformCh[0]），http 变换后经 EmitMsg
// 转发到 transformCh[1] → tcp。GET/200 的 method/uri 由 http 层 config
// 驱动；rounds 由 spec.HTTPFLV.Rounds 决定（http_flv 每轮产一个 FLV body）。
func (g *HTTPGenerator) generateHTTPFLVTransformer(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("http generator: EmitMsg is nil (http transformer mode)")
	}
	// drain：结构性错误在退出前排空输入（review transform-wiring F1 同款纪律
	// ——本生成器是 transformCh[0] 的唯一消费者，满缓冲时同步写者阻塞）。
	drain := func() error {
		events := req.Meta.Events
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

	// GET 请求配置：method/uri 从 http 层 config 读（要求层链含显式 http 层）。
	cfg := req.Layer.Config
	method := layerConfigString(cfg, "method")
	if method == "" {
		method = "GET"
	}
	uri := layerConfigString(cfg, "uri")
	if uri == "" {
		uri = "/live/stream.flv" // http_flv 链专用默认（区别于 http 终结层的 /）
	}
	version := layerConfigString(cfg, "version")
	if version == "" {
		version = "HTTP/1.1"
	} else if !strings.HasPrefix(version, "HTTP/") {
		// 裸版本号归一（HLS/HDS 变换器同款，D-HTTP-1 §4）：层 schema 默认
		// "1.1"，线上必须完整 "HTTP/1.1"。
		version = "HTTP/" + version
	}

	// 轮数：http_flv Rounds 决定 GET/200 事务数（http_flv 每轮产一个 FLV body）。
	rounds := 1
	if hf := req.Meta.HTTPFLV; hf != nil && hf.Rounds > 0 {
		rounds = hf.Rounds
	}

	// 每轮：GET（up）→ 读内层 FLV body 事件（down FLV body）→ 包 200（down）。
	for i := 0; i < rounds; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		keepAlive := i < rounds-1
		reqMsg := buildHTTPFlvGetRequest(method, uri, version, req.Meta.DstIP, keepAlive)
		if err := req.EmitMsg(layers.MessageEvent{Up: true, Bytes: []byte(reqMsg)}); err != nil {
			drain()
			return err
		}
		// 读内层 body 事件（每轮恰好一个：http_flv 每轮产一个 body 事件）。
		ev, ok := g.readInnerBody(ctx, req.Meta.Events)
		if !ok {
			// 内层流关闭但还差 body：变换报文到一半，结构性失败。
			return fmt.Errorf("http generator: inner %s stream closed before body event %d/%d", "http_flv", i+1, rounds)
		}
		respMsg := buildHTTPFlvResponse(version, ev.Bytes, keepAlive)
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: []byte(respMsg)}); err != nil {
			drain()
			return err
		}
	}
	// 已消费到最后一轮；除非 http_flv 多产了事件（配置错误），正常退出。
	// 残余事件按协议丢弃（变换器关闭自己的输出，tcp 消费到关闭进入挥手）。
	// 为防御配置不一致（rounds 与 FLV body 事件数不符），仍排空残余流。
	return drain()
}

// readFLVBody reads exactly one FLV body event from the inner stream.
// Returns ok=false when the stream closes before an event arrives.
func (g *HTTPGenerator) readInnerBody(ctx context.Context, events <-chan layers.MessageEvent) (layers.MessageEvent, bool) {
	for events != nil {
		select {
		case <-ctx.Done():
			return layers.MessageEvent{}, false
		case ev, ok := <-events:
			if !ok {
				return layers.MessageEvent{}, false
			}
			return ev, true
		}
	}
	return layers.MessageEvent{}, false
}

// buildHTTPFlvGetRequest builds the HTTP GET request for an http_flv
// transaction (GET/1.1 method + uri + Host + Connection)。帧字节与 http 终结
// 层请求一致（buildHTTPRequestBody 同款），仅默认 Connection 按 keepAlive
// 显式控制。
func buildHTTPFlvGetRequest(method, uri, version, dstIP string, keepAlive bool) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s %s\r\n", method, uri, version))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP)))
	if keepAlive {
		sb.WriteString("Connection: keep-alive\r\n")
	} else {
		sb.WriteString("Connection: close\r\n")
	}
	sb.WriteString("\r\n")
	return sb.String()
}

// buildHTTPFlvResponse builds the HTTP 200 response carrying one FLV body
// (Content-Type: video/x-flv + Content-Length: len(body) + FLV bytes)。
func buildHTTPFlvResponse(version string, flvBody []byte, keepAlive bool) string {
	var sb strings.Builder
	statusCode := 200
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", version, statusCode, statusTextFor(statusCode)))
	sb.WriteString("Content-Type: video/x-flv\r\n")
	sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(flvBody)))
	if keepAlive {
		sb.WriteString("Connection: keep-alive\r\n")
	} else {
		sb.WriteString("Connection: close\r\n")
	}
	sb.WriteString("\r\n")
	sb.Write(flvBody)
	return sb.String()
}

// layerConfigString reads a string layer config field（层 config 经 schema
// 校验，类型保证为 string；nil/缺失 → ""）。
func layerConfigString(cfg map[string]interface{}, key string) string {
	s, _ := cfg[key].(string)
	return s
}

// terminalLoop is the original Generate loop body（interleaved / pipelined），
// 抽取出来供 generateTerminal 复用。
func (g *HTTPGenerator) terminalLoop(ctx context.Context, req *layers.GenRequest, hcfg *core.HTTPConfig) error {
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
	layers.RegisterLayerValidator("http", validateHTTPSpec)
}

// validateHTTPSpec is the http terminal-layer spec validator (D-HTTP-1 §5,
// mqtt layer_gen.go:236 范式)：复用 legacy Planner.Validate（IP 格式 +
// MSS 下界），再把 spec.TCP 握手/挥手 pin true——legacy http.go 恒产握手/
// 挥手（无开关），spec.TCP 零值 false 会让 tcp 层生成器跳过握手/挥手。
func validateHTTPSpec(spec *core.FlowSpec) error {
	if err := (&Planner{}).Validate(*spec); err != nil {
		return err
	}
	if spec.TCP == nil {
		spec.TCP = &core.TCPConfig{}
	}
	spec.TCP.Handshake = true
	spec.TCP.Termination = true
	return nil
}
