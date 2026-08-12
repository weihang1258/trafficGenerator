package ntp

import (
	"context"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NTPGenerator is the ntp terminal-layer generator (ntp 终结层层生成器,
// 波 4)。It produces one MessageEvent per NTP packet into the transport
// layer's event stream; the udp layer emits one datagram per event with
// direction from the event (up → src:spec 端口, down → swapped). Event bytes
// reuse the legacy builders (buildClientRequest / buildServerResponse /
// buildBroadcast / buildSymmetric / buildControlRequest / buildControlResponse
// / buildBasicHeader), so the wire output is byte-identical to the legacy
// ntp.NewPlanner (planner.go Plan) — modulo the IPID/checksum masking already
// handled by the tests.
//
// 方向语义与 legacy 的差异（已接受，见 09-tds-design.md 波 4 节）：
// legacy 把 broadcast/symmetric-passive 标记为 "down" 但端口/MAC 并不换向
// （emit 用 spec 源端点 + effectiveDstPort，planner.go:305-306 同款）；链
// 上用 Up=true 事件表达同样的线上字节（udp 层换向逻辑会真正换端口，
// 若标 down 会产生错误端口）。请求方向的客户端/控制包是 Up；响应方向的
// 服务器/对端包是 Down（udp 层换向，端口/MAC 与 legacy 响应一致）。
type NTPGenerator struct{}

// Name returns "ntp".
func (g *NTPGenerator) Name() string { return "ntp" }

// Generate produces NTP message events in mode order (mirrors planner.go
// Plan 的 mode switch + repeat 循环)。
func (g *NTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.NTP
	if cfg == nil {
		cfg = &core.NTPConfig{Mode: ModeClient}
	} else {
		copied := *cfg
		cfg = &copied
	}
	// 默认值（legacy planner.go:203-225 同款）：Version 4, Poll 6,
	// Precision -6。Mode=0 是保留值（Validate 拒绝），但 nil-config 降级
	// 路径用 ModeClient。
	if cfg.Version == 0 {
		cfg.Version = DefaultVersion
	}
	if cfg.Poll == 0 {
		cfg.Poll = DefaultPoll
	}
	if cfg.Precision == 0 {
		cfg.Precision = DefaultPrecision
	}

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("ntp generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	now := time.Now()
	repeat := cfg.RepeatCount
	if repeat <= 0 {
		repeat = 1
	}

	switch cfg.Mode {
	case ModeClient:
		// Client mode: request (Mode=3); if IsResponse, response (Mode=4)
		// echoes the request TransmitTS as OriginTS (planner.go:287-298 同款)。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			payload, txTS := buildClientRequest(cfg, now)
			if err := emit(layers.MessageEvent{Up: true, Bytes: payload}); err != nil {
				return err
			}
			if cfg.IsResponse {
				respPayload := buildServerResponse(cfg, now, txTS)
				if err := emit(layers.MessageEvent{Up: false, Bytes: respPayload}); err != nil {
					return err
				}
			}
		}

	case ModeServer:
		// Server mode: standalone response (Mode=4), OriginTS = user value
		// (planner.go:302-306 同款)。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			payload := buildServerResponse(cfg, now, cfg.OriginTS)
			if err := emit(layers.MessageEvent{Up: false, Bytes: payload}); err != nil {
				return err
			}
		}

	case ModeBroadcast:
		// Broadcast mode: Mode=5 with distinct TransmitTS per iteration
		// (planner.go:310-318 同款)。legacy 标 down 但端口不换向 → Up=true。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			txTS := now.Add(time.Duration(i) * time.Duration(max(cfg.PollInterval, 1)) * time.Second)
			payload := buildBroadcast(cfg, txTS)
			if err := emit(layers.MessageEvent{Up: true, Bytes: payload}); err != nil {
				return err
			}
		}

	case ModeSymmetricActive, ModeSymmetricPassive:
		// Symmetric modes: Mode=1/2; if IsResponse, the peer reply with
		// swapped mode (planner.go:320-356 同款)。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			txTS := now.Add(time.Duration(i) * time.Duration(max(cfg.PollInterval, 1)) * time.Second)
			payload := buildSymmetric(cfg, txTS)
			// 方向语义：legacy 对 passive 主报文标 "down" 但端点不换向
			// （planner.go:326-329 emit 用 spec 源端点）；链必须用 Up=true
			// 保持相同线上字节（udp 层标 down 会真正换端口）。
			up := true
			if err := emit(layers.MessageEvent{Up: up, Bytes: payload}); err != nil {
				return err
			}
			if cfg.IsResponse {
				peerCfg := *cfg
				peerCfg.Mode = ModeSymmetricPassive
				if cfg.Mode == ModeSymmetricPassive {
					peerCfg.Mode = ModeSymmetricActive
				}
				peerPayload := buildSymmetric(&peerCfg, txTS)
				// peer 回复真正换向（legacy peerDir 换端点）→ Up=false。
				if err := emit(layers.MessageEvent{Up: !up, Bytes: peerPayload}); err != nil {
					return err
				}
			}
		}

	case ModeControl:
		// Control mode (RFC 1305 App. B): 12-byte control header + Data;
		// if IsResponse, matching-Sequence response with R bit
		// (planner.go:358-378 同款)。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			seq := cfg.Sequence
			if repeat > 1 {
				seq = cfg.Sequence + uint16(i)
			}
			payload := buildControlRequest(cfg, seq)
			if err := emit(layers.MessageEvent{Up: true, Bytes: payload}); err != nil {
				return err
			}
			if cfg.IsResponse {
				respPayload := buildControlResponse(cfg, seq)
				if err := emit(layers.MessageEvent{Up: false, Bytes: respPayload}); err != nil {
					return err
				}
			}
		}

	case ModePrivate:
		// Private mode (Mode=7): 48-byte basic header (planner.go:380-388
		// 同款)。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			payload := buildBasicHeader(cfg, now)
			if err := emit(layers.MessageEvent{Up: true, Bytes: payload}); err != nil {
				return err
			}
		}

	default:
		// legacy 的兜底（planner.go:390-398 同款）：basic header。
		for i := 0; i < repeat; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			payload := buildBasicHeader(cfg, now)
			if err := emit(layers.MessageEvent{Up: true, Bytes: payload}); err != nil {
				return err
			}
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *NTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *NTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ntp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 ntp 层生成器工厂 + 协议校验器（layers 包不依赖 ntp 包）。
	layers.RegisterLayerGenerator("ntp", func() (layers.LayerGenerator, error) {
		return &NTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("ntp", func(spec *core.FlowSpec) error {
		return validateNTPConfig(*spec)
	})
}
