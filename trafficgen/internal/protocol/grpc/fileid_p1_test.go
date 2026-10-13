package grpc

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（grpc）：FileSource 覆盖 RequestMessages（既有接线——本红例
// 锁链路径可达性，防回归）。
func TestChainFileSourceP1RequestMessages(t *testing.T) {
	content := "GRPCP1-" + strings.Repeat("g", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("grpc")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			GRPC: &core.GRPCConfig{
				Service:    "pkg.Svc",
				Method:     "Put",
				CallType:   "unary",
				FileSource: &filesystem.FileSource{FileID: r.FileID},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		got = append(got, ev.Bytes...)
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(got), content) {
		t.Fatalf("请求消息缺文件原文 (got %d bytes)", len(got))
	}
}
