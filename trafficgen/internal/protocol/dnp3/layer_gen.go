package dnp3

// DNP3Generator is the dnp3 terminal-layer generator (dnp3 终结层层生成器,
// P4a)。DNP3 over TCP——每个 scenario 展开为一串链路层帧（reset/request/
// respond/ack 交换，scenarioFrames 产出），帧字节由 BuildLinkFrame/
// BuildAppFrame 纯函数构造。事件模式（http 波 2 方案 A 同款）：生成器
// 只产"报文事件"（方向 + 完整帧字节），TCP 语义（握手/seq-ack/挥手/MSS
// 分段）交给 tcp 层生成器。
//
// 与 legacy planFlow（dnp3.go:92-143）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）+ 挥手（4 包，dnp3.go:134/141）——
//     事件模式不产：tcp 层生成器负责（防双握手）。legacy Handshake/
//     Termination 开关经 LayerValidator 校准进 spec.TCP，tcp 层按 legacy
//     值执行（Handshake/Termination 默认 true，指针区分显式 false）。
//   - legacy UDP transport 模式（dnp3.go:138-139 前导 2 字节 + seq 计数）
//     不支持：链上无 UDP 混合流，生成器显式拒绝（enip IOData 同款先例）。
//   - MultiOutstation 展开（dnp3.go:74-79 多 RTU 独立流）不支持：每条
//     outstation 是独立 flow，事件模式单流；显式拒绝（enip session_count
//     同款先例）。
//   - ThinkTime 延时（dnp3.go:104-107/131 帧间 sleep）不产：事件模式同步
//     产全部帧；帧 Timestamp 由 ChainPlanner 逐包回填（ThinkTime 只影响
//     legacy 的时间戳与节奏，不影响字节）。
//
// 生成器内部顺序与 legacy 循环（dnp3.go:135-140）逐帧一致：
// scenarioFrames(c) → 每帧一个事件（方向 + 帧字节）。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DNP3Generator is the dnp3 terminal-layer generator.
type DNP3Generator struct{}

// Name returns "dnp3".
func (g *DNP3Generator) Name() string { return "dnp3" }

// Generate produces one message event per DNP3 link-layer frame in
// scenario order。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *DNP3Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("dnp3 generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.DNP3
	if c == nil {
		return fmt.Errorf("dnp3 generator: no config (spec.dnp3 required)")
	}
	if c.Transport == "udp" {
		return fmt.Errorf("dnp3 generator: transport=udp is not supported on the layer chain (tcp only)")
	}
	if c.MultiOutstation != nil {
		return fmt.Errorf("dnp3 generator: multi_outstation is not supported on the layer chain (one flow per outstation)")
	}
	frames, err := scenarioFrames(c)
	if err != nil {
		return err
	}
	for _, f := range frames {
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: f.direction == "up", Bytes: f.data}); err != nil {
			return err
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *DNP3Generator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *DNP3Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *DNP3Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("dnp3 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("dnp3", func() (layers.LayerGenerator, error) {
		return &DNP3Generator{}, nil
	})
	layers.RegisterLayerValidator("dnp3", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 设计 95-dnp3 §7 N-21/N-22：能力拒绝必须在 validator 期报锚词——
		// 只放生成器期会被 0-packet 错误掩蔽（suite 实证）。置于 shape
		// 校验之后：形状负例（t9/t10/t57-t59）锚词保持语义分层。
		if c := spec.DNP3; c != nil {
			if c.Transport == "udp" {
				return fmt.Errorf("dnp3 generator: transport=udp is not supported on the layer chain (tcp only)")
			}
			if c.MultiOutstation != nil {
				return fmt.Errorf("dnp3 generator: multi_outstation is not supported on the layer chain (one flow per outstation)")
			}
			// user_data_size 上界在 validator 期报（评审 MEDIUM）：
			// blocksLen = size + 2*ceil(size/16) ≤ 255 → size ≤ 225；越界的
			// BuildLinkFrame 错误只会在 Generate 期出现并被 0-packet 掩蔽。
			if c.UserDataSize != nil && *c.UserDataSize > 225 {
				return fmt.Errorf("dnp3: user_data_size must be 1-225 (link frame length limit 255), got %d", *c.UserDataSize)
			}
		}
		// cfg.Handshake/Termination 校准进 spec.TCP（legacy dnp3.go:120 同款：
		// nil→true，显式 false→false；spec.TCP 零值 false 必须写默认值，否则
		// tcp 层生成器跳过握手/挥手）。legacy MSS 常量未用，不校准。
		c := spec.DNP3
		if c == nil {
			return nil
		}
		hs, term := true, true
		if c.Handshake != nil {
			hs = *c.Handshake
		}
		if c.Termination != nil {
			term = *c.Termination
		}
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = hs
		spec.TCP.Termination = term
		return nil
	})
}
