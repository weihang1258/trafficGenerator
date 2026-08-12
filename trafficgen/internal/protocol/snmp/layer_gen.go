package snmp

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SNMPGenerator is the snmp terminal-layer generator (snmp 终结层层生成器,
// 波 4)。It produces one MessageEvent per SNMP datagram into the transport
// layer's event stream; the udp layer emits one datagram per event with
// direction from the event (up → src:spec 端口, down → swapped). Event bytes
// reuse the legacy builder buildSNMPMessage, so the wire output is
// byte-identical to the legacy snmp.NewPlanner (planner.go Plan) — modulo
// IPID/checksum and the random request-id start already handled by the tests.
type SNMPGenerator struct{}

// Name returns "snmp".
func (g *SNMPGenerator) Name() string { return "snmp" }

// Generate produces SNMP message events: one request/trap (up) per iteration,
// plus one response (down) when IsResponse — mirrors planner.go Plan 的
// repeat 循环 + request-id 递增。
func (g *SNMPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.SNMP
	if cfg == nil {
		cfg = &core.SNMPConfig{}
	} else {
		copied := *cfg
		cfg = &copied
	}

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("snmp generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	repeat := cfg.RepeatCount
	if repeat <= 0 {
		repeat = 1
	}
	// request-id handling (planner.go:337-341 同款): 0 = incrementing from a
	// random start.
	baseRequestID := cfg.RequestID
	if baseRequestID == 0 {
		baseRequestID = rand.Uint32()
	}
	// PollInterval 节流（planner.go:405-411 同款）：毫秒级间隔，
	// 除最后一次迭代外每次迭代间等待。
	interval := time.Duration(cfg.PollInterval) * time.Millisecond

	buildRequest := func(reqID uint32) []byte {
		return buildSNMPMessage(cfg, reqID, false)
	}
	buildResponse := func(reqID uint32) []byte {
		return buildSNMPMessage(cfg, reqID, true)
	}

	for i := 0; i < repeat; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		reqID := baseRequestID + uint32(i)
		if err := emit(layers.MessageEvent{Up: true, Bytes: buildRequest(reqID)}); err != nil {
			return err
		}
		if cfg.IsResponse {
			if err := emit(layers.MessageEvent{Up: false, Bytes: buildResponse(reqID)}); err != nil {
				return err
			}
		}
		if i < repeat-1 && interval > 0 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *SNMPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SNMPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("snmp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 snmp 层生成器工厂 + 协议校验器（layers 包不依赖 snmp 包）。
	layers.RegisterLayerGenerator("snmp", func() (layers.LayerGenerator, error) {
		return &SNMPGenerator{}, nil
	})
	layers.RegisterLayerValidator("snmp", func(spec *core.FlowSpec) error {
		return validateSNMPConfig(*spec)
	})
}
