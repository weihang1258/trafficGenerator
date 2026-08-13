package dhcpv6

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DHCPv6Generator is the dhcpv6 terminal-layer generator（dhcpv6 终结层层
// 生成器，波 5e）。It produces one MessageEvent per DHCPv6 datagram into the
// transport layer's event stream; the udp layer emits one datagram per event.
// Event bytes reuse the legacy builders (buildClientServerMessage /
// buildRelayMessage / serializeDUID / appendOption), so the wire output is
// byte-identical to the legacy dhcpv6.NewPlanner (planner.go Plan).
//
// 事件流复刻 legacy Plan 的完整语义（planner.go:296-411）：
//   - DUID 解析：cfg.ClientDUID/ServerDUID 显式值优先，nil 时
//     autoClientDUID（DUID-LLT，含 time.Now() 非确定性——字节对比测试
//     必须显式设 ClientDUID）/autoServerDUID（DUID-EN trafficgen）；
//   - scenario 推导（buildScenarioMessages，内部 randomXID()——场景测试
//     只能做结构断言，字节对比须走 manual 模式显式 XID）；
//   - XID：零值 → down 且非 RECONFIGURE 复制 lastXID，否则 randomXID()；
//     relay 消息（12/13）跳过 XID 逻辑（planner.go:365-378 同款）；
//   - 每消息 resolveAddrs（planner.go:433-480）：ports 缺省 546/547，
//     down 交换 MAC/IP/端口，relay 消息端点取 RelayConfig.RelayMAC/IP、
//     端口恒 547/547；
//   - EtherType：core.EtherTypeFor(srcIP) → IPv6 链恒 0x86DD。
//
// 目标覆盖（波 5 基础设施）：所有事件携带 OverrideDstIP=true +
// DstIP=resolveAddrs 结果（up = spec.DstIP；down = spec.SrcIP——legacy
// resolveAddrs 已交换，事件值即最终 L3 目标，finalEmit 覆盖分支不再交换）、
// OverrideDstMAC=true + DstMAC=解析结果（阻止链层 multicastDstMAC 对
// IPv6 多播目标推导 33:33——legacy 从不推导 MAC，TestMulticast_DstMAC 语义，
// finalEmit 仅当事件 DstMAC 为空才推导）、SrcMAC/SrcIP（resolveAddrs 结果）。
// 端口事件级覆盖 + L4PortOverride=true：resolveAddrs 已按方向交换端口
// （up 546/547、down 547/546、relay 547/547），事件携带每方向最终端口；
// udp 层对 down 事件还会交换一次（generator.go 事件循环
// `if !ev.L4PortOverride { srcPort, dstPort = dstPort, srcPort }`），
// 不覆盖会把已交换的 547/546 二次交换成 546/547（与 dhcp 同机制，但
// dhcp 是方向无关端口，dhcpv6 是事件端口已按方向解析）。TTL=effectiveTTL
// （spec.TTL 或 legacy DefaultTTL=
// 64）经覆盖标记落 L3。FlowID 不携带（legacy flowID 用 spec 值拼接，
// 与链层默认回填格式相同，chain_planner.go flowID 同款）；PacketIndex
// 每消息携带 uint64(i)。
type DHCPv6Generator struct{}

// Name returns "dhcpv6".
func (g *DHCPv6Generator) Name() string { return "dhcpv6" }

// Generate produces the DHCPv6 message events (mirrors planner.go Plan 的
// DUID/scenario/XID/方向/mac-ip-端口交换事件流)。
func (g *DHCPv6Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.DHCPv6
	if cfg == nil {
		return fmt.Errorf("dhcpv6 generator: DHCPv6 config is nil (spec.dhcpv6 required)")
	}
	copied := *cfg
	cfg = &copied

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("dhcpv6 generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	// DUID 解析（planner.go:308-316 同款：显式优先，nil 走自动）。
	clientDUID := cfg.ClientDUID
	if clientDUID == nil {
		clientDUID = autoClientDUID(req.Meta.SrcMAC)
	}
	serverDUID := cfg.ServerDUID
	if serverDUID == nil {
		serverDUID = autoServerDUID()
	}

	// 消息序列（planner.go:322-325 同款：scenario 推导，manual 用原列表）。
	messages := cfg.Messages
	if cfg.Scenario != "" {
		messages = buildScenarioMessages(cfg, clientDUID, serverDUID)
	}

	effectiveTTL := req.Meta.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	var lastXID [3]byte
	for i, msg := range messages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 方向（planner.go:357-361 同款：显式优先，否则类型推断）。
		direction := msg.Direction
		if direction == "" {
			direction = inferDirection(msg.MsgType)
		}

		// XID（planner.go:363-378 同款：relay 跳过；零值 → down 非
		// RECONFIGURE 复制 lastXID，否则 randomXID；显式值直落并记录）。
		xid := msg.TransactionID
		isRelay := msg.MsgType == MsgTypeRelayForw || msg.MsgType == MsgTypeRelayRepl
		if !isRelay {
			if xid == [3]byte{} {
				if direction == "down" && msg.MsgType != MsgTypeReconfigure {
					xid = lastXID
				} else {
					xid = randomXID()
				}
			}
			lastXID = xid
		}

		// 载荷（planner.go:380-385 同款：序列化失败即停）。
		payload, err := buildMessage(msg, cfg, clientDUID, serverDUID, xid)
		if err != nil {
			return err
		}

		// 每消息 L2/L3/L4（planner.go:388 同款）。
		srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort := resolveAddrs(specFromMeta(req), cfg, direction, msg)

		packetIndex := uint64(i)
		if err := emit(layers.MessageEvent{
			Up:             direction != "down",
			Bytes:          payload,
			OverrideDstIP:  true,
			DstIP:          dstIP,
			SrcIP:          srcIP,
			OverrideDstMAC: true,
			DstMAC:         dstMAC,
			SrcMAC:         srcMAC,
			TTL:            effectiveTTL,
			SrcPort:        srcPort,
			DstPort:        dstPort,
			L4PortOverride: true,
			PacketIndex:    &packetIndex,
		}); err != nil {
			return err
		}
	}
	return nil
}

// specFromMeta rebuilds a minimal FlowSpec view of the flow-level values the
// legacy resolveAddrs reads (spec.SrcPort/DstPort/SrcIP/DstIP/SrcMAC/DstMAC)。
// DHCPv6 链 validateSpecBase 不默认化端口（生成器按方向解析 546/547），
// spec 空值经 resolveAddrs 缺省回退——与 legacy Plan 对 spec 空值的处理一致。
func specFromMeta(req *layers.GenRequest) core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
	}
}

// GenEvents marks this generator as a message event producer.
func (g *DHCPv6Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *DHCPv6Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("dhcpv6 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Validate wraps the legacy dhcpv6.Planner.Validate（单一校验实现，178-green
// 教训）：链层与 legacy 共用同一份校验，杜绝漂移。
func (g *DHCPv6Generator) Validate(spec *core.FlowSpec) error {
	if spec.DHCPv6 == nil {
		return fmt.Errorf("dhcpv6 config is required")
	}
	return (&Planner{}).Validate(*spec)
}

func init() {
	layers.RegisterLayerGenerator("dhcpv6", func() (layers.LayerGenerator, error) {
		return &DHCPv6Generator{}, nil
	})
	layers.RegisterLayerValidator("dhcpv6", func(spec *core.FlowSpec) error {
		if spec.DHCPv6 == nil {
			return fmt.Errorf("dhcpv6 config is required")
		}
		return (&Planner{}).Validate(*spec)
	})
}
