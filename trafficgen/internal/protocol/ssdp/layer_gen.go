package ssdp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SSDPGenerator is the ssdp terminal-layer generator (ssdp 终结层层生成器,
// 波 5b)。It produces one MessageEvent per SSDP datagram into the transport
// layer's event stream; the udp layer emits one datagram per event. Event
// bytes reuse the legacy builders (buildSSDPNotify / buildSSDPMSearch /
// buildSSDPResponse), so the wire output is byte-identical to the legacy
// ssdp.NewPlanner (planner.go Plan) — modulo the IPID/checksum masking
// handled by the tests.
//
// 多播目标（波 5 基础设施）：NOTIFY/M-SEARCH 携带 OverrideDstIP + DstIP=
// 多播组（239.255.255.250 / ff02::c，默认按源 IP 版本选择，legacy
// planner.go:214-221 同款）。DstMAC 不显式覆盖——链层按多播 IP 推导
// 01:00:5e/33:33 MAC（multicastDstMAC，legacy resolveMulticastMAC 同款）。
// TTL 恒 4（RFC draft-cai-ssdp-v1-03 §6.2，legacy DefaultTTL=4）：所有事件
// （多播与单播回程）携带 TTL=4，udp 层覆盖分支（ev.TTL != 0）写入包并置
// 覆盖标记，ip 层/finalEmit 的 TTL 覆盖（spec.TTL / ipTTL 默认 64）被标记
// 跳过——legacy ssdp 无条件强制 4，spec.TTL 无效（planner.go:207-213 同款）。
//
// 单播回程（M-SEARCH 的 200 OK / 独立 response）：legacy 以 spec.SrcIP/
// srcPort 为目标（响应回给控制点）。响应事件携带 OverrideDstIP + DstIP=
// 回程目标——链上 spec.DstIP 是搜索方向的多播组，响应包必须覆盖为单播
// 目标。DstMAC 空 → 链层 multicastDstMAC 返回 ""（单播不推导）→ 回退
// spec.DstMAC（legacy resolveMulticastMAC 同款：非多播返回空）。up 方向
// 不变（legacy 全部 up，无 down 交换，覆盖标记保证不交换）。
type SSDPGenerator struct{}

// Name returns "ssdp".
func (g *SSDPGenerator) Name() string { return "ssdp" }

// Generate produces the SSDP message events (mirrors planner.go Plan 的
// MessageType switch + repeat/response-delay 循环)。
func (g *SSDPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.SSDP
	if cfg == nil {
		return fmt.Errorf("ssdp generator: SSDP config is nil (spec.ssdp required)")
	}
	copied := *cfg
	cfg = &copied

	// Effective TTL（legacy planner.go:282-285 同款）：spec.TTL 非零被
	// honor，零值回退 DefaultTTL=4（RFC draft-cai-ssdp-v1-03 §6.2）。
	effectiveTTL := req.Meta.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}
	// 多播组默认按源 IP 版本（legacy planner.go:214-221 同款）。
	multicastGroup := cfg.MulticastGroup
	if multicastGroup == "" {
		if req.Meta.SrcIP != "" && net.ParseIP(req.Meta.SrcIP).To4() == nil {
			multicastGroup = IPv6MulticastGroup
		} else {
			multicastGroup = IPv4MulticastGroup
		}
	}
	// 有效目的 IP（legacy planner.go:224-228：spec.DstIP 空 → 多播组）。
	dstIP := req.Meta.DstIP
	if dstIP == "" {
		dstIP = multicastGroup
	}
	dstPort := req.Meta.DstPort
	if dstPort == 0 {
		dstPort = DefaultPort
	}
	srcPort := req.Meta.SrcPort
	if srcPort == 0 {
		srcPort = DefaultPort
	}
	hostHeader := buildHostHeader(multicastGroup, dstPort)

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("ssdp generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	switch cfg.MessageType {
	case "alive", "byebye", "update":
		repeat := cfg.RepeatCount
		if repeat < 1 {
			repeat = 1
		}
		repeatDelay := time.Duration(0)
		if repeat > 1 {
			if cfg.RepeatIntervalMs > 0 {
				repeatDelay = time.Duration(cfg.RepeatIntervalMs) * time.Millisecond
			} else {
				maxAge := cfg.MaxAge
				if maxAge <= 0 {
					maxAge = DefaultMaxAge
				}
				repeatDelay = time.Duration(maxAge/3) * time.Second
			}
		}
		for i := 0; i < repeat; i++ {
			if err := g.emitNotify(ctx, emit, cfg, hostHeader, multicastGroup, dstIP, dstPort, effectiveTTL); err != nil {
				return err
			}
			if i < repeat-1 && repeatDelay > 0 {
				timer := time.NewTimer(repeatDelay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
				timer.Stop()
			}
		}

	case "msearch":
		payload := buildSSDPMSearch(cfg, hostHeader)
		if err := g.emitSearch(ctx, emit, payload, dstIP, dstPort, effectiveTTL); err != nil {
			return err
		}

		// 响应回程（legacy planner.go:366-422）：单播回 spec.SrcIP/srcPort。
		responseCount := cfg.ResponseCount
		if responseCount < 1 {
			responseCount = DefaultResponseCount
		}
		if responseCount > 1 {
			minDelay := cfg.ResponseDelayMinMs
			if minDelay <= 0 {
				minDelay = DefaultResponseDelayMinMs
			}
			maxDelay := cfg.ResponseDelayMaxMs
			if maxDelay <= 0 {
				if cfg.MX > 0 {
					maxDelay = cfg.MX * 1000
				} else {
					maxDelay = DefaultResponseDelayMaxMs
				}
			}
			for k := 0; k < responseCount; k++ {
				delay := time.Duration(minDelay+rand.Intn(maxDelay-minDelay+1)) * time.Millisecond
				mxMs := DefaultMX * 1000
				if cfg.MX > 0 {
					mxMs = cfg.MX * 1000
				}
				if delay > time.Duration(mxMs)*time.Millisecond {
					delay = time.Duration(mxMs) * time.Millisecond
				}
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
				timer.Stop()
				if err := g.emitResponse(ctx, emit, cfg, hostHeader, req.Meta.SrcIP, srcPort, effectiveTTL); err != nil {
					return err
				}
			}
		} else if responseCount == 1 {
			mxMs := DefaultMX * 1000
			if cfg.MX > 0 {
				mxMs = cfg.MX * 1000
			}
			delay := time.Duration(rand.Intn(mxMs)) * time.Millisecond
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			timer.Stop()
			if err := g.emitResponse(ctx, emit, cfg, hostHeader, req.Meta.SrcIP, srcPort, effectiveTTL); err != nil {
				return err
			}
		}

	case "response":
		if err := g.emitResponse(ctx, emit, cfg, hostHeader, dstIP, dstPort, effectiveTTL); err != nil {
			return err
		}
	}
	return nil
}

// emitNotify emits a multicast NOTIFY event (up, override dst = multicast).
func (g *SSDPGenerator) emitNotify(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.SSDPConfig, hostHeader, multicastGroup, dstIP string, dstPort uint16, ttl uint8) error {
	return g.emitCtx(ctx, emit, layers.MessageEvent{
		Up:            true,
		Bytes:         buildSSDPNotify(cfg, core.FlowSpec{}, hostHeader, multicastGroup),
		OverrideDstIP: true,
		DstIP:         dstIP,
		TTL:           ttl,
	})
}

// emitSearch emits a multicast M-SEARCH event (up, override dst = multicast).
func (g *SSDPGenerator) emitSearch(ctx context.Context, emit func(layers.MessageEvent) error, payload []byte, dstIP string, dstPort uint16, ttl uint8) error {
	return g.emitCtx(ctx, emit, layers.MessageEvent{
		Up:            true,
		Bytes:         payload,
		OverrideDstIP: true,
		DstIP:         dstIP,
		TTL:           ttl,
	})
}

// emitResponse emits a 200 OK event. M-SEARCH 响应回给控制点（spec.SrcIP，
// 单播），独立 response 去 spec.DstIP/多播组——两者都是显式目标，携带
// OverrideDstIP=true（链层不覆盖、不交换；udp 层按标记跳过 dst 覆盖）。
// DstMAC 空 → 链层 multicastDstMAC 对单播返回 "" → 回退 spec.DstMAC
// （legacy resolveMulticastMAC 同款）。TTL 恒 4 强制（legacy 同款）。
func (g *SSDPGenerator) emitResponse(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.SSDPConfig, hostHeader, dstIP string, dstPort uint16, ttl uint8) error {
	return g.emitCtx(ctx, emit, layers.MessageEvent{
		Up:            true,
		Bytes:         buildSSDPResponse(cfg, hostHeader, dstIP, dstPort),
		OverrideDstIP: true,
		DstIP:         dstIP,
		TTL:           ttl,
	})
}

func (g *SSDPGenerator) emitCtx(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *SSDPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SSDPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ssdp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ssdp", func() (layers.LayerGenerator, error) {
		return &SSDPGenerator{}, nil
	})
	layers.RegisterLayerValidator("ssdp", func(spec *core.FlowSpec) error {
		if spec.SSDP == nil {
			return fmt.Errorf("ssdp: SSDP config is required (set spec.ssdp)")
		}
		if err := validateSSDPConfig(*spec.SSDP); err != nil {
			return err
		}
		// Port validation（legacy planner.go:254-261 同款）：validateSpecBase
		// 已把端口 0 默认化为 1900，此处校验"非 1900"拒绝。
		if spec.DstPort != 0 && spec.DstPort != DefaultPort {
			return fmt.Errorf("ssdp destination port must be 1900")
		}
		if spec.SrcPort != 0 && spec.SrcPort != DefaultPort {
			return fmt.Errorf("ssdp source port must be 1900 or ephemeral (0)")
		}
		return nil
	})
}
