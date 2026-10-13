package pppoe

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P2（pppoe）：内层 IPv4 数据包载荷来自 file_source
func TestChainFileSourceP2PPPoE(t *testing.T) {
	content := "PPPOEP2-" + strings.Repeat("p", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p2.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("pppoe")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			PPPoE: &core.PPPoEConfig{FileSource: &filesystem.FileSource{FileID: r.FileID}},
		},
	}
	req.Emit = func(p core.PacketConfig) error {
		got = append(got, p.Payload...)
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(got), content) {
		t.Fatalf("线上缺文件原文 (got %d bytes)", len(got))
	}
}
