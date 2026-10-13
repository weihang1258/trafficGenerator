package rdp

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2e（D-FILE-2 裁定6）：rdp data_events[].file_source → 该事件载荷
// ==文件原文；优先级 FileSource > Payload > PayloadB64（家族契约）。
func TestChainDataEventFileSource(t *testing.T) {
	content := "RDPFILE-" + strings.Repeat("d", 100)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fs.UploadInfo(context.Background(), "d.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("rdp")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			RDP: &core.RDPConfig{
				DataEvents: []core.RDPDataEvent{
					{Type: "cliprdr_format_list", Channel: "cliprdr", FileSource: &filesystem.FileSource{FileID: r.FileID}},
				},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if strings.Contains(string(ev.Bytes), content) {
			found = true
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !found {
		t.Fatal("data event 载荷缺文件原文")
	}
}

// L4 复审：三级优先级双填断言——FileSource > Payload > PayloadB64 必须真被遵守。
func TestDataEventTripleFillPriority(t *testing.T) {
	content := "RDPPRI-" + strings.Repeat("p", 60)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fs.UploadInfo(context.Background(), "p.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	g, err := layers.NewLayerGenerator("rdp")
	if err != nil {
		t.Fatal(err)
	}
	var up [][]byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			RDP: &core.RDPConfig{
				DataEvents: []core.RDPDataEvent{{
					Type:       "cliprdr_format_list",
					Channel:    "cliprdr",
					Payload:    []byte("INLINE-SHOULD-LOSE"),
					PayloadB64: "SU5MSU5FLUI2NC1TSE9VTEQtTE9TRQ==",
					FileSource: &filesystem.FileSource{FileID: r.FileID},
				}},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if ev.Up {
			up = append(up, ev.Bytes)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := string(bytes.Join(up, nil))
	if !strings.Contains(joined, content) {
		t.Fatal("FileSource 未赢")
	}
	if strings.Contains(joined, "INLINE-SHOULD-LOSE") || strings.Contains(joined, "INLINE-B64-SHOULD-LOSE") {
		t.Fatal("低优先级载荷泄漏上线")
	}
}
