package rtmp

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// D-FILE-2 复审 CRITICAL 守卫：无 data[] 的 rtmp 链必须正常出包（默认形），
// 不得因 file_source 解析守卫的下标访问 panic（曾留调试打印 cfg.Data[0] 越界）。
func TestChainRTMPEmptyDataNoPanic(t *testing.T) {
	g, err := layers.NewLayerGenerator("rtmp")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			RTMP: &core.RTMPConfig{App: "live", Command: "play", StreamName: "s1"},
		},
	}
	req.Emit = func(p core.PacketConfig) error {
		n++
		return nil
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if n == 0 {
		t.Fatal("空 data 链应产出默认形包序列")
	}
}
