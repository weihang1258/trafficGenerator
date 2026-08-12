package mdns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MDNSGenerator is the mdns terminal-layer generator (mdns 终结层层生成器,
// 波 5)。It produces one MessageEvent per mDNS datagram into the transport
// layer's event stream; the udp layer emits one datagram per event. Event
// bytes reuse the legacy builders (buildMDNSMessage / encodeResourceRecord),
// so the wire output is byte-identical to the legacy mdns.NewPlanner
// (planner.go Plan) — modulo the IPID/checksum masking handled by the tests.
//
// 多播目标（波 5 基础设施）：每个事件携带 OverrideDstIP + DstIP=多播组
// （224.0.0.251 / ff02::fb，默认按源 IP 版本选择，legacy planner.go:400-405
// 同款）。DstMAC 不显式覆盖——链层按多播 IP 推导 01:00:5e/33:33 MAC
// （multicastDstMAC），与 legacy planner.go:405 的 dstMAC 推导一致。mDNS
// 恒单向：所有包 Direction="up"（legacy 同款）。
//
// 模式时序（重复 + 间隔）复刻 legacy planner.go:439-520 的
// repeatCount/intervalMs/jitterMax 组合：query/goodbye 单包无间隔，
// response 单包 + ResponseDelay 睡眠，probe/announce 多包 + 间隔睡眠 +
// 可选定种子抖动（种子 0 = 非确定性随机，legacy 同款）。
type MDNSGenerator struct{}

// Name returns "mdns".
func (g *MDNSGenerator) Name() string { return "mdns" }

// Generate produces the mDNS message events in mode order (mirrors planner.go
// Plan 的 mode switch + repeat/interval 循环)。
func (g *MDNSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.MDNS
	if cfg == nil {
		cfg = &core.MDNSConfig{}
	} else {
		copied := *cfg
		cfg = &copied
	}

	// Effective defaults（legacy planner.go:388-436 同款）。
	mode := cfg.Mode
	if mode == "" {
		mode = "query"
	}
	defaultTTL := cfg.DefaultTTL
	if defaultTTL == 0 {
		defaultTTL = DefaultTTL
	}
	// 多播组默认按源 IP 版本（legacy planner.go:396-405 同款）。
	dstIP := cfg.MulticastGroup
	if dstIP == "" {
		if req.Meta.SrcIP != "" && net.ParseIP(req.Meta.SrcIP).To4() == nil {
			dstIP = MulticastIPv6
		} else {
			dstIP = MulticastIPv4
		}
	}

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("mdns generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	// 模式时序参数（legacy planner.go:439-487 同款）。
	var repeatCount int
	var intervalMs int
	var jitterMax int
	var jitterSeed int64
	var forceTTL0 bool
	switch mode {
	case "query":
		repeatCount = 1
	case "response":
		repeatCount = 1
		intervalMs = cfg.ResponseDelay
	case "probe":
		repeatCount = cfg.ProbingRepeat
		if repeatCount == 0 {
			repeatCount = DefaultProbingRepeat
		}
		intervalMs = cfg.ProbingInterval
		if intervalMs == 0 {
			intervalMs = DefaultProbingInterval
		}
		jitterMax = cfg.ProbingJitterMax
		jitterSeed = cfg.ProbingJitterSeed
	case "announce":
		repeatCount = cfg.AnnouncingRepeat
		if repeatCount == 0 {
			repeatCount = DefaultAnnouncingRepeat
		}
		intervalMs = cfg.AnnouncingInterval
		if intervalMs == 0 {
			intervalMs = DefaultAnnouncingInterval
		}
	case "goodbye":
		repeatCount = 1
		forceTTL0 = true
	default:
		// legacy 不校验模式（Validate 拒绝未知模式，Plan 兜底 query 语义）。
		repeatCount = 1
	}

	var rng *rand.Rand
	if jitterSeed != 0 {
		rng = rand.New(rand.NewSource(jitterSeed))
	}

	for i := 0; i < repeatCount; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// 间隔（legacy planner.go:523-557 同款：i>0 且 intervalMs>0 睡眠，
		// 响应模式单包前睡 ResponseDelay）。
		if intervalMs > 0 && (i > 0 || mode == "response") {
			delay := time.Duration(intervalMs) * time.Millisecond
			if i > 0 && jitterMax > 0 {
				if rng != nil {
					delay += time.Duration(rng.Intn(jitterMax+1)) * time.Millisecond
				} else {
					delay += time.Duration(rand.Intn(jitterMax+1)) * time.Millisecond
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			timer.Stop()
		}

		payload := buildMDNSMessage(cfg, mode, forceTTL0, defaultTTL)
		if err := emit(layers.MessageEvent{
			Up:            true,
			Bytes:         payload,
			OverrideDstIP: true,
			DstIP:         dstIP,
		}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *MDNSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *MDNSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("mdns generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 mdns 层生成器工厂 + 协议校验器（layers 包不依赖 mdns 包）。
	layers.RegisterLayerGenerator("mdns", func() (layers.LayerGenerator, error) {
		return &MDNSGenerator{}, nil
	})
	layers.RegisterLayerValidator("mdns", func(spec *core.FlowSpec) error {
		return validateMDNSConfig(*spec)
	})
}
