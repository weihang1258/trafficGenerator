package xmpp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（xmpp）：<body> 来自 item 级 file_source（XML 文本语义）。
func TestChainFileSourceP1XmppBody(t *testing.T) {
	content := "XMPPP1-" + strings.Repeat("x", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("xmpp")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			Xmpp: &core.XmppConfig{
				Messages: []core.XmppMessage{{
					Direction:  "up",
					Body:       "inline-should-lose",
					FileSource: &filesystem.FileSource{FileID: r.FileID},
				}},
			},
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
	if strings.Contains(string(got), "inline-should-lose") {
		t.Fatal("低优先级 Body 泄漏上线")
	}
}
