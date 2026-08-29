package ldp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// LDPGenerator implements the layers.LayerGenerator interface.
type LDPGenerator struct{}

// Name returns the protocol name.
func (g *LDPGenerator) Name() string { return "ldp" }

// GenEvents returns the event generator.
func (g *LDPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired (events flow through the chain planner).
func (g *LDPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("ldp generator: EmitEvent is not wired")
}

// Generate generates LDP protocol messages from the config.
func (g *LDPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || (req.EmitMsg == nil && req.Emit == nil) {
		return fmt.Errorf("ldp generator: EmitMsg is nil")
	}
	cfg := req.Meta.LDP
	if cfg == nil {
		return fmt.Errorf("ldp: config is required")
	}
	// dual_adjacency：混合载体（UDP Hello + TCP 会话）。[ip, ldp] 链无
	// 传输层，链驱动走 req.Emit 完整包路径（chain_planner isCarrierMixedChain
	// 分支）；此时 EmitMsg 为 nil 而非错误。
	if len(cfg.Adjacencies) > 0 {
		if req.Emit == nil {
			return fmt.Errorf("ldp generator: Emit is nil (dual_adjacency requires full-packet emission)")
		}
		return emitAdjacencies(ctx, req, cfg)
	}
	// 多会话展开（P0a 模式）：每条 session 一条独立 TCP 连接，事件携带
	// SrcPort 触发 tcp 层会话边界（挥旧握新）；每会话事件列表独立解析
	// （src_lsr_id 作为 PDU LSR 标识）。
	if len(cfg.Sessions) > 0 {
		for _, sess := range cfg.Sessions {
			events := sess.Events
			if sess.SrcLSRID != "" || sess.DstLSRID != "" {
				// 会话级 LSR 标识无条件覆盖事件级值（case 权威：多会话的
				// 事件列表常从单会话复制，旧值必须被会话身份替换）。
				events = make([]core.LDPEvent, len(sess.Events))
				copy(events, sess.Events)
				for j := range events {
					if sess.SrcLSRID != "" {
						events[j].LSRID = sess.SrcLSRID
					}
					if sess.DstLSRID != "" {
						events[j].ReceiverLSRID = sess.DstLSRID
					}
				}
			}
			payloads, ups, err := parseLDPEvents(cfg, events, sess.SrcLSRID)
			if err != nil {
				return err
			}
			for i, pdu := range payloads {
				if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: ups[i], Bytes: pdu, SrcPort: sess.SrcPort}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	payloads, ups, err := parseLDPConfig(cfg)
	if err != nil {
		return err
	}
	for i, pdu := range payloads {
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: ups[i], Bytes: pdu}); err != nil {
			return err
		}
	}
	return nil
}

// emitSel sends an event respecting context cancellation.
// emitAdjacencies assembles and emits complete packets for a dual-adjacency
// config: each UDP discovery adjacency is one Hello PDU datagram; each
// tcp_session adjacency is a full connection (handshake, events, teardown).
func emitAdjacencies(ctx context.Context, req *layers.GenRequest, cfg *core.LDPConfig) error {
	sip := req.Meta.SrcIP
	dip := req.Meta.DstIP
	if sip == "" {
		sip = "192.0.2.1"
	}
	if dip == "" {
		dip = "192.0.2.2"
	}
	idx := uint64(0)
	emitPkt := func(up bool, payload []byte, proto string, sport, dport uint16, flags uint8) error {
		s, d, sp, dp := sip, dip, sport, dport
		dir := "up"
		if !up {
			s, d, sp, dp = dip, sip, dport, sport
			dir = "down"
		}
		protoNum := uint8(6) // TCP
		if proto == "udp" {
			protoNum = 17
		}
		pkt := core.PacketConfig{
			FlowID:      "ldp",
			PacketIndex: idx,
			Direction:   dir,
			L2:          core.L2Config{EtherType: core.EtherTypeFor(s)},
			L3:          core.L3Base(s, d, protoNum, 64, uint16(idx), core.FlowSpec{SrcIP: s, DstIP: d}),
			L4:          core.L4Config{Protocol: proto, SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
			Payload:     payload,
		}
		idx++
		return req.Emit(pkt)
	}

	for _, adj := range cfg.Adjacencies {
		switch adj.Carrier {
		case "udp_discovery":
			targeted := adj.Targeted || adj.Kind == "targeted"
			holdTime := cfg.HoldTime
			if holdTime == 0 {
				holdTime = 14
			}
			mid := adj.MessageID
			if mid == 0 {
				mid = 1
			}
			// 发送方身份：c2s 由 src 端发起（lsr = spec 源/默认 192.0.2.1），
			// s2c 由 dst 端发起（lsr = 192.0.2.2）。期望帧：down Hello 的
			// LDPID 与 transport address 都是接收侧身份。
			up := adj.Direction != "s2c"
			sender := sip
			if !up {
				sender = dip
			}
			lsrID := cfg.LSRID
			if lsrID == "" {
				lsrID = sender
			}
			pdu := BuildHelloPDU(parseLSRID(lsrID), cfg.LabelSpace, mid, holdTime, targeted, sender)
			if err := emitPkt(up, pdu, "udp", 646, 646, 0); err != nil {
				return err
			}
		case "tcp_session":
			srcPort := adj.SrcPort
			if srcPort == 0 {
				srcPort = 50000
			}
			dstPort := adj.DstPort
			if dstPort == 0 {
				dstPort = 646
			}
			// handshake
			if err := emitPkt(true, nil, "tcp", srcPort, dstPort, 0x02); err != nil {
				return err
			}
			if err := emitPkt(false, nil, "tcp", srcPort, dstPort, 0x12); err != nil {
				return err
			}
			if err := emitPkt(true, nil, "tcp", srcPort, dstPort, 0x10); err != nil {
				return err
			}
			payloads, ups, err := parseLDPEvents(cfg, adj.Events, cfg.LSRID)
			if err != nil {
				return err
			}
			for i, pdu := range payloads {
				if err := emitPkt(ups[i], pdu, "tcp", srcPort, dstPort, 0x18); err != nil {
					return err
				}
			}
			// teardown
			if err := emitPkt(true, nil, "tcp", srcPort, dstPort, 0x11); err != nil {
				return err
			}
			if err := emitPkt(false, nil, "tcp", srcPort, dstPort, 0x10); err != nil {
				return err
			}
			if err := emitPkt(false, nil, "tcp", srcPort, dstPort, 0x11); err != nil {
				return err
			}
			if err := emitPkt(true, nil, "tcp", srcPort, dstPort, 0x10); err != nil {
				return err
			}
		default:
			return fmt.Errorf("ldp: adjacency unknown carrier %q", adj.Carrier)
		}
	}
	return nil
}

func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

func init() {
	layers.RegisterLayerGenerator("ldp", func() (layers.LayerGenerator, error) { return &LDPGenerator{}, nil })
	layers.RegisterLayerValidator("ldp", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
