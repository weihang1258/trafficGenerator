package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-1e 兜底面（D-FILE-1 裁定 6）：tcp 终结层 file_source → spec.FileSource
// → 裸流 payload=文件字节（FileSource 赢过 inline payload）。
func TestFileIDTCPTerminalChain(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("TCPPAYLOAD", 20)
	r, err := fsys.UploadInfo(context.Background(), "t.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	planner := layers.NewChainPlannerFromChain("tcp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{
			"src_port":    50000,
			"dst_port":    9000,
			"payload":     "inline-not-used",
			"file_source": map[string]interface{}{"file_id": r.FileID},
		}},
	})
	packets, err := planner.Plan(ctx, core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 9000})
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
		t.Fatalf("tcp payload = %d bytes, want %d (file bytes on wire)", len(data), len(content))
	}
	if strings.Contains(string(data), "inline-not-used") {
		t.Fatal("inline payload leaked (FileSource should win)")
	}
}
