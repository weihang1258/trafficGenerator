package icmpv6

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（icmpv6）：echo data 来自 file_source（icmp 对称）
func TestChainFileSourceP1Icmpv6Data(t *testing.T) {
	content := "ICMP6P1-" + strings.Repeat("6", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("icmpv6")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			ICMPv6: &core.ICMPv6Config{Type: 128, Code: 0, Sequence: 1, FileSource: &filesystem.FileSource{FileID: r.FileID}},
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
