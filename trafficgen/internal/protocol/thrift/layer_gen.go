package thrift

import (
	"context"
	"fmt"
	"encoding/binary"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type ThriftGenerator struct{}

func (g *ThriftGenerator) Name() string                     { return "thrift" }
func (g *ThriftGenerator) GenEvents() layers.EventGenerator { return g }
func (g *ThriftGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("thrift generator: EmitEvent is not wired")
}

func (g *ThriftGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("thrift generator: EmitMsg is nil")
	}
	cfg := req.Meta.Thrift
	if cfg == nil {
		cfg = &core.ThriftConfig{}
	}
	if len(cfg.Messages) == 0 {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）。无现成默认消息分支，给出最能体现 Thrift 协议的最小 CALL 消息。
		c := *cfg
		c.Messages = []core.ThriftMessage{{Type: "CALL", Method: "ping", SeqID: 1}}
		cfg = &c
	}
	for i, m := range cfg.Messages {
		mt, _ := msgType(m.Type)
		body, err := buildMessageBody(mt, m.Args, m.Result, m.Exception)
		if err != nil {
			return err
		}
		payload := buildMessage(mt, m.Method, m.SeqID, body)
		up := mt == MCall || mt == MOneway
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload}); err != nil {
			return err
		}
		// RPC 响应语义（case thrift_containers/scalar_types 期望 9 包）：
		// CALL 无显式 REPLY/EXCEPTION 响应时自动补空 REPLY（同 method/
		// seqid，body 仅 STOP）；ONEWAY 单向不补，EXCEPTION 本身是响应。
		if mt == MCall && !hasMatchingResponse(cfg.Messages, i, m) {
			reply := buildMessage(MReply, m.Method, m.SeqID, []byte{TStop})
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: reply}); err != nil {
				return err
			}
		}
	}
	return nil
}

// hasMatchingResponse reports whether a later message responds to the CALL at
// index i (REPLY or EXCEPTION with the same method and seqid).
func hasMatchingResponse(msgs []core.ThriftMessage, i int, call core.ThriftMessage) bool {
	for j := i + 1; j < len(msgs); j++ {
		m := msgs[j]
		mt, _ := msgType(m.Type)
		if (mt == MReply || mt == MException) && m.Method == call.Method && m.SeqID == call.SeqID {
			return true
		}
	}
	return false
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
	layers.RegisterLayerGenerator("thrift", func() (layers.LayerGenerator, error) { return &ThriftGenerator{}, nil })
	layers.RegisterLayerValidator("thrift", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}

// Make binary.BigEndian available for the package
var _ = binary.BigEndian