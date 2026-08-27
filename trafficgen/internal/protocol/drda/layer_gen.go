package drda

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type DRDAGenerator struct{}

func (g *DRDAGenerator) Name() string                     { return "drda" }
func (g *DRDAGenerator) GenEvents() layers.EventGenerator { return g }
func (g *DRDAGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("drda generator: EmitEvent is not wired")
}

func (g *DRDAGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("drda generator: EmitMsg is nil")
	}
	cfg := req.Meta.DRDA
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）。下方 len(cfg.DSSSegments)==0 已有 buildDefaultSegments 分支。
		cfg = &DRDAConfig{}
	}

	correlator := cfg.CorrelatorStart
	if correlator == 0 {
		correlator = 1
	}
	corrInc := cfg.CorrelatorInc
	if corrInc == 0 {
		corrInc = 1
	}

	var segs []DRDASegment
	if len(cfg.DSSSegments) > 0 {
		segs = cfg.DSSSegments
	} else {
		segs = buildDefaultSegments(cfg, correlator, corrInc)
	}

	for _, s := range segs {
		params := make([][]byte, len(s.Parameters))
		for i, p := range s.Parameters {
			pp, err := param(p.CodePoint, p.Data)
			if err != nil {
				return err
			}
			params[i] = pp
		}
		ddm, err := ddmBuild(byte(s.Format), s.Correlator, s.CodePoint, params, false)
		if err != nil {
			return err
		}
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: ddm}); err != nil {
			return err
		}
		// response (down)
		respCP := respCodePoint(s.CodePoint)
		if respCP != 0 {
			var respParams [][]byte
			// SQLCARD: SQLCODE + SQLSTATE
			if s.CodePoint == CPSQLDTA && cfg.SQL != nil {
				state := cfg.SQL.SQLState
				if state == "" {
					state = "00000"
				}
				p1, err := param(0x1252, u32enc(cfg.SQL.SQLCode))
				if err != nil {
					return err
				}
				p2, err := param(0x1495, []byte(state))
				if err != nil {
					return err
				}
				respParams = [][]byte{p1, p2}
			}
			resp, err := ddmBuild(0x01, s.Correlator, respCP, respParams, false)
			if err != nil {
				return err
			}
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: resp}); err != nil {
				return err
			}
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
	layers.RegisterLayerGenerator("drda", func() (layers.LayerGenerator, error) { return &DRDAGenerator{}, nil })
	layers.RegisterLayerValidator("drda", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}