package srv6

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P2（srv6）：内层载荷来自 file_source
func TestChainFileSourceP2SRv6(t *testing.T) {
	content := "SRV6P2-" + strings.Repeat("v", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p2.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("srv6")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SRv6: &core.SRv6Config{SrcIPv6: "2001:db8::1", DstIPv6: "2001:db8::2", SegmentList: []string{"2001:db8::1"}, FileSource: &filesystem.FileSource{FileID: r.FileID}},
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
