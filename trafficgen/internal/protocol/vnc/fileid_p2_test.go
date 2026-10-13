package vnc

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P2（vnc）：客户端剪贴板文本来自 file_source
func TestChainFileSourceP2VNCCutText(t *testing.T) {
	content := "VNCP2-" + strings.Repeat("v", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p2.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("vnc")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			VNC: &core.VNCConfig{SecurityType: 1, Width: 1024, Height: 768, Rounds: 1, FBUUpdateInterval: 1, InitialFBU: []core.VNCRectConfig{{Width: 100, Height: 100}}, UpdateRects: []core.VNCRectConfig{{Width: 100, Height: 100}}, FileSource: &filesystem.FileSource{FileID: r.FileID}},
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
