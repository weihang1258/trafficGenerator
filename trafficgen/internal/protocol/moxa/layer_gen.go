package moxa

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type MOXAGenerator struct{}

func (*MOXAGenerator) Name() string                     { return "moxa" }
func (*MOXAGenerator) GenEvents() layers.EventGenerator { return &MOXAGenerator{} }
func (*MOXAGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("moxa generator: EmitEvent is not wired")
}
func (g *MOXAGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("moxa generator: EmitMsg is nil")
	}
	if req.Meta.MOXA == nil {
		// P0b-2：空配置默认化并产默认流（stream "hello"）。与 Planner.Plan
		// 的默认化一致。
		req.Meta.MOXA = &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}}
	}
	cfg := req.Meta.MOXA
	stream := cfg.Stream
	if len(stream) == 0 {
		stream = []MOXAStreamBlock{{Payload: "hello"}}
	}
	for _, blk := range stream {
		if blk.Direction != "" && blk.Direction != "up" && blk.Direction != "down" {
			return fmt.Errorf("moxa: invalid direction %q, want up|down", blk.Direction)
		}
		var data []byte
		if blk.PayloadB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(blk.PayloadB64)
			if err != nil {
				return fmt.Errorf("moxa: invalid payload_b64: %v", err)
			}
			data = decoded
		} else if blk.Payload != "" {
			data = []byte(blk.Payload)
		} else {
			return fmt.Errorf("moxa: empty stream block or payload required")
		}
		if len(data) == 0 {
			return fmt.Errorf("moxa: empty stream block or payload required")
		}
		if len(data) > MaxBlockBytes {
			return fmt.Errorf("moxa: payload exceeds max %d", MaxBlockBytes)
		}
		if len(data) >= 3 && data[0] == 0x5a && data[1] == 0x5a && data[2] == 0x5a {
			return fmt.Errorf("moxa: config-packet bytes in stream are not supported (see §3.2)")
		}
		if cfg.Sessions > 1 {
			return fmt.Errorf("moxa: sessions=%d>1 not supported (multi-sessions: use strategy flow_control flows)", cfg.Sessions)
		}
		up := blk.Direction == "" || blk.Direction == "up"
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: data}); err != nil {
			return err
		}
	}
	_ = core.FlowSpec{}
	return nil
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
	layers.RegisterLayerGenerator("moxa", func() (layers.LayerGenerator, error) { return &MOXAGenerator{}, nil })
	layers.RegisterLayerValidator("moxa", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
