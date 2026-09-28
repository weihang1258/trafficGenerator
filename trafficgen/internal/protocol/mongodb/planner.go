package mongodb

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner plans MongoDB (TCP 27017) traffic.
type Planner struct{}

func (Planner) Name() string { return "mongodb" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.MongoDB
	if cfg == nil {
		// P0b-2: 空配置不再报错——Plan 会默认化并产默认流 (layers 数组路径
		// 下 layer config 为空/缺省时)。
		return nil
	}
	if len(cfg.Messages) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("mongodb: at least one message or session required")
	}
	if len(cfg.Messages) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("mongodb: messages and sessions are mutually exclusive")
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	msgs := cfg.Messages
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Messages) == 0 {
				return fmt.Errorf("mongodb: session %d: empty messages", i)
			}
			if err := checkMessages(s.Messages, fmt.Sprintf("session %d message", i)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := checkMessages(msgs, "message"); err != nil {
		return err
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("mongodb: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("mongodb: invalid destination IP")
	}
	return nil
}

// checkMessages runs the per-message validation chain for one connection
// (single session or one entry of sessions[]): opcode resolution, the
// request/response pairing guard, and a buildMessage preflight. `where` names
// the container so errors read "mongodb: message 3: …" / "mongodb: session 0
// message 3: …".
func checkMessages(msgs []core.MongoDBMessage, where string) error {
	seen := make(map[int32]bool, len(msgs))
	for i, m := range msgs {
		op, err := resolveOpcode(m.Opcode)
		if err != nil {
			return fmt.Errorf("mongodb: %s %d: %w", where, i, err)
		}
		// D-MONGODB-1 G-MONGO-3：responseTo 配对守卫（设计 §4.2/§10.4）。
		// OP_REPLY 是响应——responseTo 必须非 0 且指向同连接内**更早出现**
		// 的 requestID（[^2] "responseTo is set"）；其余 opcode 是请求——
		// responseTo 必须为 0。锚词 "responseTo"。
		if op == OpReply {
			if m.ResponseTo == 0 {
				return fmt.Errorf("mongodb: %s %d: OP_REPLY responseTo must reference the request it answers (responseTo)", where, i)
			}
			if !seen[m.ResponseTo] {
				return fmt.Errorf("mongodb: %s %d: responseTo %d has no matching earlier request (responseTo)", where, i, m.ResponseTo)
			}
		} else if m.ResponseTo != 0 {
			return fmt.Errorf("mongodb: %s %d: request opcode %s must not set responseTo (responseTo)", where, i, opcodeString(op))
		}
		seen[m.RequestID] = true
		// D-MONGODB-1 G-MONGO-3/§7：生成期错误不许变成空流假成功。链路径下
		// buildMessage 的错误发生在 Generate 期，被 drive 吞成**空流**（包流
		// 为空但任务"完成"）。故在此用同一 builder 预演一遍——任何构建期拒绝
		// （MaxMessagePayload 超限；opcode 已被上方白名单挡住）同步变 task
		// error。逐消息构建、立即丢弃，不聚合、不缓存（设计 §6.8）。
		if _, err := buildMessage(m); err != nil {
			// buildMessage 的错误自带 "mongodb: " 前缀，此处不重复叠加。
			return fmt.Errorf("mongodb: %s %d: %s", where, i, strings.TrimPrefix(err.Error(), "mongodb: "))
		}
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 27017
	}
	cfg := spec.MongoDB
	if cfg == nil {
		cfg = &core.MongoDBConfig{Messages: []core.MongoDBMessage{{Opcode: "OP_QUERY"}}}
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8, srcPort uint16) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, srcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "mongodb",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 6, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// runSession emits a full TCP connection: handshake, messages, teardown.
		runSession := func(srcPort uint16, msgs []core.MongoDBMessage) bool {
			// TCP handshake
			if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
				return false
			}
			// Messages
			for _, m := range msgs {
				payload, err := buildMessage(m)
				if err != nil {
					return false
				}
				op, _ := resolveOpcode(m.Opcode)
				up := opcodeDirection(op) != "s2c"
				if !emit(up, payload, 0x18, srcPort) {
					return false
				}
			}
			// TCP teardown
			emit(true, nil, 0x11, srcPort)
			emit(false, nil, 0x10, srcPort)
			emit(false, nil, 0x11, srcPort)
			emit(true, nil, 0x10, srcPort)
			return true
		}

		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				sp := s.SrcPort
				if sp == 0 {
					sp = spec.SrcPort
				}
				if !runSession(sp, s.Messages) {
					return
				}
			}
		} else {
			runSession(spec.SrcPort, cfg.Messages)
		}
	}()
	return out, nil
}

// resolveOpcode resolves an opcode from string or numeric value.
//
// D-MONGODB-1（#87）G-MONGO-3：数字路径白名单化——只接受 §3.2 的 7 个
// legacy opcode 值 {1,2001,2002,2004,2005,2006,2007}，其余（含 0、
// RESERVED 2003、OP_MSG 2013、OP_COMPRESSED 2012、INT_MAX）一律
// "unknown opcode"（与字符串路径同文案）。修前数字路径只拒 0：越界值经
// Validate 放行、在 buildMessage default 拒，而链路径下 Generate 期错误被
// drive 吞成**空流**（假成功，违反 CORE_MEMORY §14.11/§14.12）。
func resolveOpcode(op interface{}) (int32, error) {
	switch o := op.(type) {
	case string:
		c, ok := opcodeForOp(o)
		if !ok {
			return 0, fmt.Errorf("unknown opcode %q", o)
		}
		return c, nil
	case int32:
		if !knownOpcode(o) {
			return 0, fmt.Errorf("unknown opcode %d", o)
		}
		return o, nil
	case float64:
		v := int32(o)
		if !knownOpcode(v) {
			return 0, fmt.Errorf("unknown opcode %v", o)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("invalid opcode type %T", op)
	}
}

