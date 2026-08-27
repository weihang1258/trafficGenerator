package s7

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type S7Generator struct{}

func (g *S7Generator) Name() string { return "s7" }

func (g *S7Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("s7 generator: EmitMsg is nil")
	}
	cfg := req.Meta.S7
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）。与 Planner.Plan 的默认化一致——默认 read DB1 在下方补。
		cfg = &S7Config{Transport: "tcp"}
	}
	if len(cfg.Commands) == 0 {
		copyCfg := *cfg
		copyCfg.Commands = []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}
		cfg = &copyCfg
	}
	cr, err := BuildConnectionRequest(cfg)
	if err != nil {
		return err
	}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: cr}); err != nil {
		return err
	}
	cc := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x01, 0x00}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: cc}); err != nil {
		return err
	}
	setup, err := BuildSetup(cfg, false)
	if err != nil {
		return err
	}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: setup}); err != nil {
		return err
	}
	setupResponse, err := BuildSetup(cfg, true)
	if err != nil {
		return err
	}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: setupResponse}); err != nil {
		return err
	}
	for _, cmd := range cfg.Commands {
		var b []byte
		if cmd.Kind == "write" {
			b, err = BuildWrite(cfg, cmd)
		} else {
			b, err = BuildRead(cfg, cmd)
		}
		if err != nil {
			return err
		}
		if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: b}); err != nil {
			return err
		}
		if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: b}); err != nil {
			return err
		}
	}
	return nil
}

func emitS7Event(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}
func (g *S7Generator) GenEvents() layers.EventGenerator { return g }
func (g *S7Generator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("s7 generator: EmitEvent is not wired")
}

func init() {
	layers.RegisterLayerGenerator("s7", func() (layers.LayerGenerator, error) { return &S7Generator{}, nil })
	layers.RegisterLayerValidator("s7", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
