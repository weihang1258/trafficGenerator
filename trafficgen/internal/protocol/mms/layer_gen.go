package mms

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type MMSGenerator struct{}

func (*MMSGenerator) Name() string                     { return "mms" }
func (*MMSGenerator) GenEvents() layers.EventGenerator { return &MMSGenerator{} }
func (*MMSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("mms generator: EmitEvent is not wired")
}
func (g *MMSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("mms generator: EmitMsg is nil")
	}
	if req.Meta.MMS == nil {
		// P0b-2：空配置默认化并产默认流（association + read）。与
		// Planner.Plan 的默认化一致——默认 EnableRead=true。
		req.Meta.MMS = &core.MMSConfig{EnableRead: true}
	}
	cfg := req.Meta.MMS
	var err error
	no := cfg.Association != nil && cfg.Association.NoAssociate
	if !no {
		cr, err := BuildCR()
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: cr}); err != nil {
			return err
		}
		cc, err := BuildCC()
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: cc}); err != nil {
			return err
		}
		b, err := BuildAssociate(cfg, false)
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: b}); err != nil {
			return err
		}
		b, err = BuildAssociate(cfg, true)
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: b}); err != nil {
			return err
		}
	}
	steps := []string{"read"}
	if cfg.Sequence != nil && len(cfg.Sequence.Steps) > 0 {
		steps = cfg.Sequence.Steps
	}
	invoke := byte(1)
	for _, step := range steps {
		if !serviceEnabled(cfg, step) {
			continue
		}
		var request, response []byte
		switch step {
		case "read":
			request, err = BuildReadRequest(cfg, invoke)
			if err == nil {
				if cfg.ErrorClassName != "" {
					response, err = BuildServiceError(cfg, invoke)
				} else {
					response, err = BuildReadResponse(cfg, invoke)
				}
			}
		case "write":
			request, err = BuildWriteRequest(cfg, invoke)
			if err == nil {
				if cfg.ErrorClassName != "" {
					response, err = BuildServiceError(cfg, invoke)
				} else {
					response, err = BuildWriteResponse(cfg, invoke)
				}
			}
		case "getnmlist":
			request, err = BuildGetNameListRequest(invoke)
			if err == nil {
				response, err = BuildGetNameListResponse(cfg, invoke)
			}
		case "identify":
			request, err = BuildIdentifyRequest(invoke)
			if err == nil {
				response, err = BuildIdentifyResponse(cfg, invoke)
			}
		case "report":
			request, err = BuildInformationReport(cfg)
		}
		if err != nil {
			return err
		}
		if step == "report" {
			wrapped, err := cotpDT(request)
			if err != nil {
				return err
			}
			if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: wrapped}); err != nil {
				return err
			}
			continue
		}
		wrappedReq, err := cotpDT(request)
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: wrappedReq}); err != nil {
			return err
		}
		wrappedResp, err := cotpDT(response)
		if err != nil {
			return err
		}
		if err = emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: wrappedResp}); err != nil {
			return err
		}
		invoke++
	}
	return nil
}

func serviceEnabled(cfg *core.MMSConfig, step string) bool {
	switch step {
	case "read":
		return cfg.EnableRead
	case "write":
		return cfg.EnableWrite
	case "getnmlist":
		return cfg.EnableGetNameList
	case "identify":
		return cfg.EnableIdentify
	case "report":
		return cfg.EnableInformationReport
	default:
		return false
	}
}
func emit(ctx context.Context, fn func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fn(ev)
	}
}
func init() {
	layers.RegisterLayerGenerator("mms", func() (layers.LayerGenerator, error) { return &MMSGenerator{}, nil })
	layers.RegisterLayerValidator("mms", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
