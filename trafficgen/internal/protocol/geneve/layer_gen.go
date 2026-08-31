package geneve

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GeneveGenerator is the geneve terminal-layer generator placeholder (B4 封装
// 类脚手架)：真实实现随 B4 交付覆盖本文件。
type GeneveGenerator struct{}

func (g *GeneveGenerator) Name() string { return "geneve" }

func (g *GeneveGenerator) GenEvents() layers.EventGenerator { return nil }

func (g *GeneveGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	return fmt.Errorf("geneve generator: not implemented in this build")
}

func init() {
	layers.RegisterLayerGenerator("geneve", func() (layers.LayerGenerator, error) {
		return &GeneveGenerator{}, nil
	})
	layers.RegisterLayerValidator("geneve", func(spec *core.FlowSpec) error {
		return fmt.Errorf("geneve: generator not implemented in this build")
	})
}
