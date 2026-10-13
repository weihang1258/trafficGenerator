package imap

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2 P1（imap）：APPEND literal 体来自 item 级 file_source——
// 生成器曾以假前提（"链路径不可用"）降级，本红例锁定恢复后的通路。
// 优先级 MIMEBody > FileSource > LiteralBodyB64 > LiteralBody。
func TestChainFileSourceP1AppendLiteral(t *testing.T) {
	content := "IMAPP1-" + strings.Repeat("a", 90)
	fs, err := filesystem.New(t.TempDir())
	if err != nil { t.Fatal(err) }
	r, err := fs.UploadInfo(context.Background(), "p1.bin", filesystem.FileSource{Literal: content})
	if err != nil { t.Fatal(err) }
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("imap")
	if err != nil { t.Fatal(err) }
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			IMAP: &core.IMAPConfig{
				Banner: "* OK ready\r\n",
				Commands: []core.IMAPCommand{{
					Cmd:        "APPEND INBOX (\\Seen) {100}",
					FileSource: &filesystem.FileSource{FileID: r.FileID},
				}},
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
		t.Fatalf("literal 体缺文件原文 (got %d bytes)", len(got))
	}
}
