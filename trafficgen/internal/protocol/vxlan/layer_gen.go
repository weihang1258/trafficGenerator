package vxlan

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// VXLANGenerator is the vxlan terminal-layer generator placeholder (B4 封装
// 类脚手架)：真实实现随 B4 交付覆盖本文件。
type VXLANGenerator struct{}

func (g *VXLANGenerator) Name() string { return "vxlan" }

func (g *VXLANGenerator) GenEvents() layers.EventGenerator { return nil }

func (g *VXLANGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	return fmt.Errorf("vxlan generator: not implemented in this build")
}

func init() {
	layers.RegisterLayerGenerator("vxlan", func() (layers.LayerGenerator, error) {
		return &VXLANGenerator{}, nil
	})
	layers.RegisterLayerValidator("vxlan", func(spec *core.FlowSpec) error {
		return fmt.Errorf("vxlan: generator not implemented in this build")
	})
}
