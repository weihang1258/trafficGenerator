package nvgre

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NVGREGenerator is the nvgre terminal-layer generator placeholder (B4 封装
// 类脚手架)：真实实现随 B4 交付覆盖本文件。
type NVGREGenerator struct{}

func (g *NVGREGenerator) Name() string { return "nvgre" }

func (g *NVGREGenerator) GenEvents() layers.EventGenerator { return nil }

func (g *NVGREGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	return fmt.Errorf("nvgre generator: not implemented in this build")
}

func init() {
	layers.RegisterLayerGenerator("nvgre", func() (layers.LayerGenerator, error) {
		return &NVGREGenerator{}, nil
	})
	layers.RegisterLayerValidator("nvgre", func(spec *core.FlowSpec) error {
		return fmt.Errorf("nvgre: generator not implemented in this build")
	})
}
