package rip

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// RIPGenerator is the rip terminal-layer generator (rip 终结层层生成器，
// 波 5c)。It produces one MessageEvent per RIP packet into the transport
// layer's event stream; the udp layer emits one datagram per event. Event
// bytes reuse the legacy builder (BuildRIPPacket), so the wire output is
// byte-identical to the legacy rip.NewPlanner (rip.go Plan) — modulo the
// volatile IPID/checksum masked by the tests.
//
// 事件流复刻 legacy Plan 的完整语义（rip.go:389-567）：
//   - scenario 推导（request/response_default/request_full）与 routes 默认
//     （nil → response_default 的 5 条示例路由）；
//   - 每 router 独立 4-tuple（SrcPort 经 resolveSrcPort：单 router Response=
//     520 well-known、multi-router=52001+idx、request_full=52001）与独立
//     FlowID/PacketIndex/IPID 起点；
//   - request_full = Request + auto-Response 双包同 4-tuple；
//   - rounds 循环（每 round 独立 RIP Response 消息，首包携带 auth entry）；
//   - split horizon / poison reverse 仅 unicast（filterRoutes 复用）；
//   - 25 RTE/包拆分（auth 首包 24，RFC 4822 §2.1）；
//   - TTL：multicast→1、unicast→spec.TTL 或 DefaultTTL=64；
//   - DSCP：spec.DSCP 透传（legacy 的 CS6 默认是死参数，见下）；
//   - DstIP：getDstIP 推导（v1 广播 / v2 224.0.0.9 / ng FF02::9）。
//
// 目标覆盖（波 5 基础设施）：所有事件携带 OverrideDstIP=true + DstIP=
// 推导目标——RIP 的 DstIP 可能偏离 spec.DstIP（v1 即使 multicast=false 也
// 广播、v2 无 DstIP 回退 224.0.0.9、ng 默认 FF02::9），事件目标绝对化，
// 链层不覆盖、不交换。DstMAC 空 → 链层 multicastDstMAC 按 DstIP 推导
// （224.0.0.9→01:00:5e:00:00:09、255.255.255.255→ff:ff:ff:ff:ff:ff、
// FF02::9→33:33:00:00:00:09），legacy resolveMulticastMAC 同款。
// SrcMAC 经 FlowMeta 注入（legacy emitRIPPacket L2Base 的 spec.SrcMAC）。
// 每事件携带 SrcPort（resolveSrcPort 结果）——事件级端口覆盖（波 5c 扩展）。
type RIPGenerator struct{}

// Name returns "rip".
func (g *RIPGenerator) Name() string { return "rip" }

// Generate produces the RIP packet events (mirrors planner.go Plan 的
// router/rounds/scenario/auth/split 事件流)。
func (g *RIPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.RIP
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（v2 response_default）。与
		// Planner.Plan 的默认化一致。
		cfg = &core.RIPConfig{Version: "v2"}
	}
	copied := *cfg
	cfg = &copied

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("rip generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	version := versionFromString(cfg.Version)

	cmd := uint8(CommandResponse)
	if cfg.Command != "" {
		cmd, _ = commandFromString(cfg.Command)
	}

	// request_full 是固定 request+response 序列；TriggeredUpdate 只影响普通
	// 场景且不能取消它（legacy rip.go:415-421 同款）。
	triggered := cfg.TriggeredUpdate && cfg.Scenario != "request_full"
	if triggered {
		cmd = CommandResponse
	}

	// Scenario 推导（legacy rip.go:423-431 同款）：仅当 Routes 为空时。
	scenario := cfg.Scenario
	if scenario == "" && len(cfg.Routes) == 0 {
		if cmd == CommandRequest {
			scenario = "request_full"
		} else {
			scenario = "response_default"
		}
	}

	// Effective routes。nil（字段缺省）= 用场景默认；显式空 slice = 零路由
	// （裸 4 字节头，legacy rip.go:433-444 同款）。
	routes := cfg.Routes
	if routes == nil {
		if scenario == "response_default" {
			routes = defaultRoutes
		}
		// request_full：Request 包用 builder 生成的特殊 entry（routes 保持
		// nil）；auto-Response 在其分支回退 defaultRoutes。
	}

	// 空 Routers = 单 router 用 FlowSpec 自身 4-tuple（legacy rip.go:446-451
	// 同款）。
	routers := cfg.Routers
	if len(routers) == 0 {
		routers = []RIPRouter{{}}
	}

	rounds := cfg.Rounds
	if rounds <= 0 {
		rounds = 1
	}

	// 每 router：独立 4-tuple、FlowID（带 router 索引）、packet index / IPID。
	for routerIdx, router := range routers {
		srcIP := router.SrcIP
		if srcIP == "" {
			srcIP = req.Meta.SrcIP
		}
		dstIP := router.DstIP
		if dstIP == "" {
			dstIP = req.Meta.DstIP
		}
		srcPort := router.SrcPort
		if srcPort == 0 {
			srcPort = req.Meta.SrcPort
		}
		dstPort := router.DstPort
		if dstPort == 0 {
			dstPort = req.Meta.DstPort
		}

		// 多播目标（legacy rip.go:478-484 同款）：multicast 覆盖 DstIP；
		// 否则用用户 DstIP 或版本默认。
		multicast := cfg.Multicast
		effectiveDstIP := getDstIP(version, multicast, dstIP)
		if effectiveDstIP == "" {
			effectiveDstIP = dstIP
		}

		// TTL：multicast/broadcast = 1，unicast = spec.TTL 或默认 64
		// （legacy rip.go:486-492 同款）。
		ttl := req.Meta.TTL
		if multicast {
			ttl = 1
		} else if ttl == 0 {
			ttl = DefaultTTL
		}

		// DSCP：**不加默认**（关键：legacy rip.go:494-498 计算的 dscp 是死参数，
		// 从未传给 L3Base——emitRIPPacket 用 L3Base(..., spec)，DSCP 恒等于
		// spec.DSCP，DefaultDSCP=0xC0 常量无实际效果）。事件 DSCP 直接透传
		// spec.DSCP（0 时 ip 层 schema 默认 0 落盘），与 legacy 字节一致。
		dscp := req.Meta.DSCP

		// Split Horizon / Poison Reverse 仅 unicast（legacy rip.go:500-505 同款）。
		filteredRoutes := routes
		if !multicast {
			filteredRoutes = filterRoutes(routes, effectiveDstIP, cfg.SplitHorizon, cfg.PoisonReverse)
		}

		// request_full：router 是请求主机，响应同 4-tuple（legacy rip.go:507-515
		// 同款）。
		isRequestingRouter := scenario == "request_full" && cmd == CommandRequest
		if srcPort == 0 {
			srcPort = resolveSrcPort(version, srcPort, !isRequestingRouter, len(routers) > 1, routerIdx)
		}
		if dstPort == 0 {
			dstPort = getDstPort(version)
		}

		// 多播事件（多播组/广播）：链层推导多播 MAC（multicastDstMAC），
		// 广播 ff:ff:ff:ff:ff:ff 亦由 multicastDstMAC(255.255.255.255) 推导。
		// multicastDstMAC 是波 5 共享设施（mdns/ssdp 已验证）；legacy rip 无
		// 该推导——恒落 spec.DstMAC（rip.go:657-659），分歧见
		// chain_planner_rip_test.go 的 MulticastMACDerivation 测试。

		// 每 router 独立 FlowID（legacy rip.go:517-520 同款）：含已解析端口
		// （resolveSrcPort/getDstPort 之后）与有效目标（multicast 推导值）。
		// 经事件携带到链层回填（MessageEvent.FlowID/PacketIndex，波 5c）——
		// 链层默认回填的是 spec 级 flowID（未解析端口 0/520 + spec.DstIP），
		// 无法表达 per-router 分割。
		flowID := fmt.Sprintf("%s-%s-%d-%d", srcIP, effectiveDstIP, srcPort, dstPort)
		if len(routers) > 1 {
			flowID = fmt.Sprintf("router%d-%s", routerIdx, flowID)
		}

		// request_full：Request + auto-Response 双包同 4-tuple、共享 FlowID、
		// PacketIndex 0/1...（legacy rip.go:530-552 同款）。
		if scenario == "request_full" && cmd == CommandRequest {
			if err := g.emitPacket(ctx, emit, version, CommandRequest, cfg.Domain,
				srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
				nil, flowID, 0, req, true, true); err != nil {
				return err
			}

			// Auto Response：用户路由存在时用，否则默认 5 条。
			responseRoutes := filteredRoutes
			if len(responseRoutes) == 0 {
				responseRoutes = defaultRoutes
			}
			packetIndex := uint64(1)
			if err := g.emitRoutes(ctx, emit, version, CommandResponse, cfg.Domain,
				srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
				responseRoutes, cfg.Auth, flowID, &packetIndex, req, true); err != nil {
				return err
			}
			continue
		}

		// 普通场景：每 round 独立 RIP Response 消息，首包携带自身 auth entry
		// （legacy rip.go:554-562 同款）。
		packetIndex := uint64(0)
		for r := 0; r < rounds; r++ {
			if err := g.emitRoutes(ctx, emit, version, cmd, cfg.Domain,
				srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
				filteredRoutes, cfg.Auth, flowID, &packetIndex, req, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitRoutes emits RIP packet events with the given routes, handling
// multi-packet splitting (max 25 route entries per packet; 24 when the first
// packet carries an auth entry, legacy rip.go:596-633 同款)。
func (g *RIPGenerator) emitRoutes(ctx context.Context, emit func(layers.MessageEvent) error,
	version string, command uint8, domain uint16,
	srcIP, dstIP string, srcPort, dstPort uint16, ttl uint8, dscp uint8,
	routes []RIPRoute, auth *RIPAuth, flowID string, packetIndex *uint64,
	req *layers.GenRequest, authFirst bool) error {

	if len(routes) == 0 {
		if err := g.emitPacket(ctx, emit, version, command, domain,
			srcIP, dstIP, srcPort, dstPort, ttl, dscp, nil, flowID,
			*packetIndex, req, false, authFirst); err != nil {
			return err
		}
		(*packetIndex)++
		return nil
	}

	for start := 0; start < len(routes); {
		// Auth entry（及 MD5 trailer）只在多包消息的首包（RFC 4822 §2.1）。
		isFirstPacket := authFirst && start == 0
		pktMaxRTE := MaxRTEPerPacket
		if isFirstPacket && auth != nil {
			pktMaxRTE = MaxRTEPerPacket - 1
		}
		end := start + pktMaxRTE
		if end > len(routes) {
			end = len(routes)
		}
		if err := g.emitPacket(ctx, emit, version, command, domain,
			srcIP, dstIP, srcPort, dstPort, ttl, dscp, routes[start:end], flowID,
			*packetIndex, req, false, isFirstPacket); err != nil {
			return err
		}
		(*packetIndex)++
		start = end
	}
	return nil
}

// emitPacket emits a single RIP packet event. Event 携带：OverrideDstIP=true
//（DstIP 绝对目标，链层不覆盖/不交换）、TTL（multicast=1 / unicast=spec 或
// 64）、SrcPort/DstPort（resolveSrcPort/getDstPort 结果，事件级端口覆盖——
// validateSpecBase 对 rip 链不默认化端口，全部经事件传递）、SrcIP（router
// 级覆盖，多 router 时各包源 IP 不同，ip 层注入的 spec.SrcIP 不适用）、
// DSCP（透传 spec.DSCP——legacy 的 dscp 参数是死参数，恒用 spec 直配）、
// SrcMAC（经 Meta 注入，legacy emitRIPPacket L2Base 的 spec.SrcMAC）。
func (g *RIPGenerator) emitPacket(ctx context.Context, emit func(layers.MessageEvent) error,
	version string, command uint8, domain uint16,
	srcIP, dstIP string, srcPort, dstPort uint16, ttl uint8, dscp uint8,
	routes []RIPRoute, flowID string, packetIndex uint64,
	req *layers.GenRequest, isRequestFull bool, isFirstPacket bool) error {

	payload := BuildRIPPacket(version, command, domain, routes, req.Meta.RIP.Auth, isRequestFull, isFirstPacket)
	return emit(layers.MessageEvent{
		Up:            true,
		Bytes:         payload,
		OverrideDstIP: true,
		DstIP:         dstIP,
		SrcIP:         srcIP,
		TTL:           ttl,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		DSCP:          dscp,
		// 事件级 flow 标识（波 5c）：链层回填尊重之（FlowID 非空即事件覆盖，
		// 不写回 spec 级 flowID / 全局索引）。
		FlowID: flowID,
		// 每 router 从 0 起的 per-flow index（request_full 双包共享 0/1）。
		PacketIndex: &packetIndex,
	})
}

// GenEvents marks this generator as a message event producer.
func (g *RIPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *RIPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("rip generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Validate wraps the legacy rip.Planner.Validate (单一校验实现，178-green
// 教训)：链层与 legacy 共用同一份校验，杜绝漂移。
func (g *RIPGenerator) Validate(spec *core.FlowSpec) error {
	return (&Planner{}).Validate(*spec)
}

func init() {
	layers.RegisterLayerGenerator("rip", func() (layers.LayerGenerator, error) {
		return &RIPGenerator{}, nil
	})
	layers.RegisterLayerValidator("rip", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
