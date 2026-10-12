package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-1e 兜底面补全（复审 H1）：udp 终结层 file_source 直迁 →
// ChainPlanner.Plan 单点解析 → 数据报载荷=文件字节。
func TestFileIDUDPTerminalChain(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("UDPWIRE", 10)
	r, err := fsys.UploadInfo(context.Background(), "u.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	planner := layers.NewChainPlannerFromChain("udp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "udp", Config: map[string]interface{}{
			"src_port":    50001,
			"dst_port":    9001,
			"file_source": map[string]interface{}{"file_id": r.FileID},
		}},
	})
	packets, err := planner.Plan(ctx, core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50001, DstPort: 9001})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var data []byte
	for pk := range packets {
		if pk.Direction == "up" && len(pk.Payload) > 0 {
			data = append(data, pk.Payload...)
		}
	}
	if string(data) != content {
		t.Fatalf("udp payload = %d bytes, want %d", len(data), len(content))
	}
}
