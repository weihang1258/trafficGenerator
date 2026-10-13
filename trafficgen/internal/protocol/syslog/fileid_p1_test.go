package syslog

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（syslog）：Msg 来自 file_source（config 级，UTF-8 文本语义）
func TestChainFileSourceP1SyslogMsg(t *testing.T) {
	content := "SYSP1-" + strings.Repeat("s", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("syslog")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			Syslog: &core.SyslogConfig{FileSource: &filesystem.FileSource{FileID: r.FileID}},
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
		t.Fatalf("线上缺文件原文 (got %d bytes)", len(got))
	}
}
