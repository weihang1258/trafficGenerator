package dhcp

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DHCPGenerator is the dhcp terminal-layer generator (dhcp 终结层层生成器，
// 波 5d)。It produces one MessageEvent per DHCP datagram into the transport
// layer's event stream; the udp layer emits one datagram per event. Event
// bytes reuse the legacy builders (buildDHCPMessage / encodeBootpHeader /
// encodeOptions), so the wire output is byte-identical to the legacy
// dhcp.NewPlanner (planner.go Plan) — modulo the volatile IPID/checksum
// masked by the tests.
//
// 事件流复刻 legacy Plan 的完整语义（planner.go:390-640）：
//   - scenario 推导（buildScenarioMessages + scenarioConfig 清除默认选项）；
//   - xid：0 = 随机（与 legacy 同种子语义：随机数不确定，字节对比由测试
//     固定 xid）；
//   - 角色解析：resolvePorts（client 68→67 / server 67→68 / relay 67→67）、
//     resolveIPs（缺省 src=0.0.0.0、dst=255.255.255.255）、resolveMACs
//     （缺省 dst=BroadcastMAC）；
//   - 每条消息：op/direction 推断、per-message broadcast、ciaddr/yiaddr/
//     siaddr/giaddr 合并、up/down 方向下的 MAC/IP 交换与 DefaultServerMAC
//     回退、广播时 DstMAC=ff:ff:ff:ff:ff:ff、DstIP=255.255.255.255。
//
// 目标覆盖（波 5 基础设施）：所有事件携带 OverrideDstIP=true +
// DstIP=广播/单播目标（broadcast 时 255.255.255.255，否则 legacy 的
// msgDstIP）、OverrideDstMAC=true + DstMAC=广播 ff:ff:ff:ff:ff:ff（或单播
// 显式值）——DHCP 目标绝对化，链层不覆盖、不交换。SrcMAC 经 FlowMeta 注入
// （legacy L2 装配的 msgSrcMAC）。每事件携带 SrcPort/DstPort（resolvePorts
// 结果，事件级端口覆盖，波 5c 扩展）与 TTL（spec.TTL 或 legacy DefaultTTL=
// 64——legacy 对 up 包用有效 TTL 直配 L3Base，零值即默认）。
type DHCPGenerator struct{}

// Name returns "dhcp".
func (g *DHCPGenerator) Name() string { return "dhcp" }

// Generate produces the DHCP message events (mirrors planner.go Plan 的
// scenario/role/方向/mac-ip 交换事件流)。
func (g *DHCPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.DHCP
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（client 角色单 DISCOVER）。与
		// Planner.Plan 的默认化一致。
		cfg = &core.DHCPConfig{Role: "client", Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}}}
	}
	copied := *cfg
	cfg = &copied

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("dhcp generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	// 与 legacy Plan 相同的解析顺序（planner.go:400-473 同款）。
	role := cfg.Role
	if role == "" {
		role = "client"
	}

	var messages []core.DHCPMessage
	var effectiveDHCP *core.DHCPConfig
	if cfg.Scenario != "" {
		messages = buildScenarioMessages(cfg)
		effectiveDHCP = scenarioConfig(cfg)
	} else {
		messages = cfg.Messages
		effectiveDHCP = cfg
	}

	xid := cfg.Xid
	if xid == 0 {
		xid = rand.Uint32()
	}

	htype := cfg.HType
	if htype == 0 {
		htype = HTypeEthernet
	}
	hlen := cfg.HLen
	if hlen == 0 {
		hlen = 6
	}

	clientMAC := cfg.ClientMAC
	if clientMAC == "" {
		if role == "client" {
			clientMAC = req.Meta.SrcMAC
		} else {
			clientMAC = req.Meta.DstMAC
		}
	}

	// 角色解析（resolvePorts/resolveIPs/resolveMACs 同款，缺省值语义一致）。
	srcPort, dstPort := resolvePorts(role, specFromMeta(req))
	srcIP, dstIP := resolveIPs(role, specFromMeta(req), cfg)
	srcMAC, dstMAC := resolveMACs(role, specFromMeta(req), dstIP)

	flowID := fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, srcPort, dstPort)
	effectiveTTL := req.Meta.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	for i, msg := range messages {
		op := inferOpFromType(msg.Type)
		direction := msg.Direction
		if direction == "" {
			direction = inferDirectionFromType(msg.Type)
		}

		msgBroadcast := cfg.BroadcastFlag
		if msg.Broadcast != nil {
			msgBroadcast = *msg.Broadcast
		}

		flags := uint16(0)
		if msgBroadcast {
			flags = BroadcastFlag
		}

		hops := msg.Hops

		ciaddr := resolveStr(msg.ClientIP, effectiveDHCP.DefaultClientIP, "0.0.0.0")
		yiaddr := resolveStr(msg.YourIP, effectiveDHCP.DefaultYourIP, "0.0.0.0")
		siaddr := resolveStr(msg.ServerIP, effectiveDHCP.DefaultServerIP, "0.0.0.0")
		giaddr := resolveStr(msg.RelayAgentIP, effectiveDHCP.DefaultRelayAgentIP, "0.0.0.0")

		payload, err := buildDHCPMessage(
			msg, effectiveDHCP, op, htype, hlen, hops, xid, cfg.Secs, flags,
			ciaddr, yiaddr, siaddr, giaddr,
			clientMAC, cfg.Sname, cfg.File,
		)
		if err != nil {
			// legacy 序列化失败即停（planner.go:527-530 同款：跳过整个流）。
			return err
		}

		// L2 MAC 交换（planner.go:552-578 同款）。
		msgSrcMAC := srcMAC
		msgDstMAC := dstMAC
		if direction == "down" {
			if role == "server" {
				if msgSrcMAC == "" {
					msgSrcMAC = DefaultServerMAC
				}
			} else {
				msgSrcMAC = dstMAC
				msgDstMAC = srcMAC
				if msgSrcMAC == "" || msgSrcMAC == BroadcastMAC {
					msgSrcMAC = DefaultServerMAC
				}
			}
		}
		if msgBroadcast {
			msgDstMAC = BroadcastMAC
		}

		// L3 IP 交换（planner.go:580-616 同款）。
		msgSrcIP := srcIP
		msgDstIP := dstIP
		if direction == "up" && (msg.Type == MsgTypeDiscover || msg.Type == MsgTypeRequest || msg.Type == MsgTypeDecline) {
			if ciaddr == "0.0.0.0" || ciaddr == "" {
				msgSrcIP = "0.0.0.0"
			}
		}
		if direction == "down" {
			msgSrcIP = req.Meta.DstIP
			msgDstIP = req.Meta.SrcIP
			if msgSrcIP == "" {
				msgSrcIP = "0.0.0.0"
			}
			if msgDstIP == "" {
				msgDstIP = "0.0.0.0"
			}
		}
		if direction == "up" && msgBroadcast {
			msgDstIP = BroadcastIP
			if msgSrcIP == "" || msgSrcIP == "0.0.0.0" {
				msgSrcIP = "0.0.0.0"
			}
		}
		if direction == "up" && (msg.Type == MsgTypeRelease || msg.Type == MsgTypeInform) {
			if ciaddr != "0.0.0.0" && ciaddr != "" {
				msgSrcIP = ciaddr
			}
		}

		packetIndex := uint64(i)
		if err := emit(layers.MessageEvent{
			Up:             direction != "down",
			Bytes:          payload,
			OverrideDstIP:  true,
			DstIP:          msgDstIP,
			SrcIP:          msgSrcIP,
			OverrideDstMAC: true,
			DstMAC:         msgDstMAC,
			SrcMAC:         msgSrcMAC,
			TTL:            effectiveTTL,
			SrcPort:        srcPort,
			DstPort:        dstPort,
			L4PortOverride: true, // dhcp 端口方向无关（legacy 每条消息恒写角色端口）
			FlowID:         flowID,
			PacketIndex:    &packetIndex,
		}); err != nil {
			return err
		}
	}
	return nil
}

// specFromMeta rebuilds a minimal FlowSpec view of the flow-level values the
// legacy role resolvers read (resolvePorts/resolveIPs/resolveMACs only touch
// spec.SrcPort/DstPort/SrcIP/DstIP/SrcMAC/DstMAC)。DHCP 链 validateSpecBase
// 不默认化端口（生成器按角色解析），spec 空值经角色缺省回退——与 legacy
// Plan 对 spec 空值的处理一致。
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
func (g *DHCPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *DHCPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("dhcp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Validate wraps the legacy dhcp.Planner.Validate (单一校验实现，178-green
// 教训)：链层与 legacy 共用同一份校验，杜绝漂移。
func (g *DHCPGenerator) Validate(spec *core.FlowSpec) error {
	return (&Planner{}).Validate(*spec)
}

func init() {
	layers.RegisterLayerGenerator("dhcp", func() (layers.LayerGenerator, error) {
		return &DHCPGenerator{}, nil
	})
	layers.RegisterLayerValidator("dhcp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
