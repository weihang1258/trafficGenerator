package coap

import (
	"encoding/base64"
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type CoAPGenerator struct{}

func (g *CoAPGenerator) Name() string { return "coap" }
func (g *CoAPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("coap generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("coap generator: EmitMsg is nil")
	}
	cfg, err := configFromValue(req.Meta.CoAP)
	if err != nil {
		return err
	}
	if err := (&Planner{}).Validate(core.FlowSpec{SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP, SrcPort: effectivePort(req.Meta.SrcPort), DstPort: req.Meta.DstPort, CoAP: cfg}); err != nil {
		return err
	}
	baseMid := cfg.MessageID
	baseToken := cfg.Token

	switch {
	// --- CON 超时重传（RFC 7252 §4.2）：初始 CON + MaxRetransmit 次同包 ---
	case cfg.Retransmit != nil:
		total := 1 + int(cfg.Retransmit.MaxRetransmit)
		for i := 0; i < total; i++ {
			msg, err := BuildMessage(cfg, false)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: msg}); err != nil {
				return err
			}
		}
		return nil

	// --- 业务错误响应序列（设计 §6.11）：每 error 一次 GET → err ACK ---
	case len(cfg.ErrorResponses) > 0:
		for i, er := range cfg.ErrorResponses {
			mid := baseMid + uint16(i)
			tok := er.Token
			if len(tok) == 0 {
				tok = baseToken
			}
			reqCfg := *cfg
			reqCfg.MessageID = mid
			reqCfg.Token = tok
			if len(er.Path) > 0 {
				reqCfg.Path = er.Path
			}
			reqMsg, err := BuildMessage(&reqCfg, false)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqMsg}); err != nil {
				return err
			}
			respCfg := *cfg
			respCfg.MessageID = mid
			respCfg.Token = tok
			respCfg.ResponseCode = er.Code
			respCfg.ResponsePayload = er.Payload
			respMsg, err := BuildMessage(&respCfg, true)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: respMsg}); err != nil {
				return err
			}
		}
		return nil

	// --- Block2 两块响应（设计 §6.7）：GET Block2(n,M=0) → ACK block(n) ---
	case cfg.Block2 != nil:
		for i, rb := range cfg.ResponseBlocks {
			mid := baseMid + uint16(i)
			reqCfg := *cfg
			reqCfg.MessageID = mid
			reqCfg.Block2 = &core.BlockConfig{Number: rb.Number, More: false, SizeExp: rb.SizeExp}
			reqMsg, err := BuildMessage(&reqCfg, false)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqMsg}); err != nil {
				return err
			}
			respCfg := *cfg
			respCfg.MessageID = mid
			respCfg.ResponseCode = "2.05"
			respCfg.ResponsePayload = rb.Payload
			respCfg.ResponseBlock2 = &core.BlockConfig{Number: rb.Number, More: rb.More, SizeExp: rb.SizeExp}
			respMsg, err := BuildMessage(&respCfg, true)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: respMsg}); err != nil {
				return err
			}
		}
		return nil

	// --- Observe（RFC 7641，设计 §6.13）：GET Observe=0 → ACK → N 通知 → 空ACK ---
	case cfg.Observe != nil:
		regCfg := *cfg
		regCfg.MessageID = baseMid
		regCfg.Token = baseToken
		regCfg.Observe = &core.ObserveConfig{StartSequence: 0}
		regMsg, err := BuildMessage(&regCfg, false)
		if err != nil {
			return err
		}
		if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: regMsg}); err != nil {
			return err
		}
		ackCfg := *cfg
		ackCfg.MessageID = baseMid
		ackCfg.Token = baseToken
		ackCfg.ResponseCode = "2.05"
		ackCfg.ResponsePayload = cfg.ResponsePayload
		ackCfg.Observe = &core.ObserveConfig{StartSequence: cfg.Observe.StartSequence}
		ackMsg, err := BuildMessage(&ackCfg, true)
		if err != nil {
			return err
		}
		if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: ackMsg}); err != nil {
			return err
		}
		for i := 0; i < int(cfg.Observe.NotifyCount); i++ {
			seq := cfg.Observe.StartSequence + 1 + uint32(i)
			notifyType := notificationType(cfg.Observe, i)
			notifyMid := baseMid + 1 + uint16(i)
			notifyCfg := *cfg
			notifyCfg.MessageID = notifyMid
			notifyCfg.Token = baseToken
			notifyCfg.ResponseCode = "2.05"
			notifyCfg.ResponsePayload = cfg.ResponsePayload
			notifyCfg.Observe = &core.ObserveConfig{StartSequence: seq}
			notifyMsg, err := buildMessageTyped(&notifyCfg, true, &notifyType)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: notifyMsg}); err != nil {
				return err
			}
			if notifyType == 0 { // CON 通知需空 ACK（客户端→服务端）
				emptyType := uint8(2)
				emptyCfg := *cfg
				emptyCfg.MessageID = notifyMid
				emptyCfg.Token = nil
				emptyCfg.TokenLength = 0
				emptyCfg.Method = "" // 空消息 code=0（设计 §3.3）
				emptyCfg.Code = 0
				emptyMsg, err := buildMessageTyped(&emptyCfg, false, &emptyType)
				if err != nil {
					return err
				}
				if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: emptyMsg}); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// --- 多会话（P0a 模式的 UDP 形态）：每会话一组 token/mid/源IP/源端口，
	// 事件携带 SrcPort/SrcIP 逐事件覆盖（udp 层支持），无握手无挥旧 —--
	if len(cfg.SessionSrcPorts) > 0 {
		for i := range cfg.SessionSrcPorts {
			var tok []byte
			if i < len(cfg.Tokens) {
				tok = decodeToken(cfg.Tokens[i])
			}
			var mid uint16
			if i < len(cfg.MessageIDs) {
				mid = cfg.MessageIDs[i]
			} else {
				mid = baseMid + uint16(i)
			}
			var srcIP string
			if i < len(cfg.SessionSrcIPs) {
				srcIP = cfg.SessionSrcIPs[i]
			}
			srcPort := cfg.SessionSrcPorts[i]

			reqCfg := *cfg
			reqCfg.MessageID = mid
			reqCfg.Token = tok
			reqMsg, err := BuildMessage(&reqCfg, false)
			if err != nil {
				return err
			}
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqMsg, SrcPort: srcPort, SrcIP: srcIP}); err != nil {
				return err
			}
			respCfg := *cfg
			respCfg.MessageID = mid
			respCfg.Token = tok
			respMsg, err := BuildMessage(&respCfg, true)
			if err != nil {
				return err
			}
			// 响应帧源端口 = 服务端口（5683），目的端口 = 会话客户端口：
			// down 帧同样携带 SrcPort——udp 层把覆盖值参与 up/down 端口交换，
			// down 包 L4.DstPort 落会话客户端口（up 包 L4.SrcPort 同值）。
			if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: respMsg, SrcPort: srcPort, SrcIP: srcIP}); err != nil {
				return err
			}
		}
		return nil
	}

	// --- 默认单请求 + 单响应（现有行为） ---
	request, err := BuildMessage(cfg, false)
	if err != nil {
		return err
	}
	if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: request}); err != nil {
		return err
	}
	if !shouldRespond(cfg) {
		return nil
	}
	response, err := BuildMessage(cfg, true)
	if err != nil {
		return err
	}
	return emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response})
}

// notificationType returns the CoAP message-type byte (0=CON, 1=NON) for the
// i-th observe notification, per NotificationTypes[i] or the config default.
func notificationType(cfg *core.ObserveConfig, i int) uint8 {
	typ := "CON"
	if len(cfg.NotificationTypes) > 0 {
		typ = cfg.NotificationTypes[i%len(cfg.NotificationTypes)]
	} else if !cfg.Confirmable {
		typ = "NON"
	}
	if typ == "NON" {
		return 1
	}
	return 0
}
func (g *CoAPGenerator) GenEvents() layers.EventGenerator { return g }
func (g *CoAPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("coap generator: EmitEvent is not wired")
}
func emit(ctx context.Context, fn func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fn(ev)
	}
}
func configFromValue(v interface{}) (*CoAPConfig, error) {
	switch x := v.(type) {
	case *core.CoAPConfig:
		if x == nil {
			// P0b-2：空配置默认化（GET 请求，不自动响应——空 ResponseCode
			// 无法编码合法响应）。
			falseVal := false
			return &CoAPConfig{Method: "GET", Response: &falseVal}, nil
		}
		return x, nil
	case map[string]interface{}:
		b, e := json.Marshal(x)
		if e != nil {
			return nil, e
		}
		var c CoAPConfig
		e = json.Unmarshal(b, &c)
		return &c, e
	case json.RawMessage:
		var c CoAPConfig
		e := json.Unmarshal(x, &c)
		return &c, e
	default:
		return nil, fmt.Errorf("coap generator: unsupported config type %T", v)
	}
}
func effectivePort(port uint16) uint16 {
	if port != 0 {
		return port
	}
	return 1
}

// decodeToken decodes a base64 (std encoding) token string from the session
// token list; nil on decode failure (the message builder treats nil token
// with TokenLength 0 as "no token").
func decodeToken(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func init() {
	layers.RegisterLayerGenerator("coap", func() (layers.LayerGenerator, error) { return &CoAPGenerator{}, nil })
	layers.RegisterLayerValidator("coap", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
