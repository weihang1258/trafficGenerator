package coap

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type CoAPGenerator struct{}

func (g *CoAPGenerator) Name() string { return "coap" }
func (g *CoAPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("coap generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("coap generator: EmitMsg is nil")
	}
	cfg, err := configFromValue(req.Meta.CoAP)
	if err != nil {
		return err
	}
	if err := (&Planner{}).Validate(core.FlowSpec{SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP, SrcPort: effectivePort(req.Meta.SrcPort), DstPort: req.Meta.DstPort, CoAP: cfg}); err != nil {
		return err
	}
	request, err := BuildMessage(cfg, false)
	if err != nil {
		return err
	}
	if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: request}); err != nil {
		return err
	}
	if !shouldRespond(cfg) {
		return nil
	}
	response, err := BuildMessage(cfg, true)
	if err != nil {
		return err
	}
	return emit(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response})
}
func (g *CoAPGenerator) GenEvents() layers.EventGenerator { return g }
func (g *CoAPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("coap generator: EmitEvent is not wired")
}
func emit(ctx context.Context, fn func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fn(ev)
	}
}
func configFromValue(v interface{}) (*CoAPConfig, error) {
	switch x := v.(type) {
	case *core.CoAPConfig:
		if x == nil {
			// P0b-2：空配置默认化（GET 请求，不自动响应——空 ResponseCode
			// 无法编码合法响应）。
			falseVal := false
			return &CoAPConfig{Method: "GET", Response: &falseVal}, nil
		}
		return x, nil
	case map[string]interface{}:
		b, e := json.Marshal(x)
		if e != nil {
			return nil, e
		}
		var c CoAPConfig
		e = json.Unmarshal(b, &c)
		return &c, e
	case json.RawMessage:
		var c CoAPConfig
		e := json.Unmarshal(x, &c)
		return &c, e
	default:
		return nil, fmt.Errorf("coap generator: unsupported config type %T", v)
	}
}
func effectivePort(port uint16) uint16 {
	if port != 0 {
		return port
	}
	return 1
}

func init() {
	layers.RegisterLayerGenerator("coap", func() (layers.LayerGenerator, error) { return &CoAPGenerator{}, nil })
	layers.RegisterLayerValidator("coap", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
