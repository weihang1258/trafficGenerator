package icmp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（icmp）：echo data 来自 file_source（legacy 消费通路，translate 反转 ③C 已映射）
func TestChainFileSourceP1IcmpData(t *testing.T) {
	content := "ICMPP1-" + strings.Repeat("i", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("icmp")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			ICMP: &core.ICMPConfig{Type: 8, Code: 0, Sequence: 1, FileSource: &filesystem.FileSource{FileID: r.FileID}},
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
