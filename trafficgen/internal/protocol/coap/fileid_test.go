package coap

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2c（D-FILE-2 裁定4）：file_source → 请求 payload；response_file_source
// → 响应 payload。显式双字段防双填歧义（三.7 教训）。
func TestChainFileSourceRequestAndResponse(t *testing.T) {
	reqContent := "COAPREQ-" + strings.Repeat("c", 80)
	rspContent := "COAPRSP-" + strings.Repeat("r", 80)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rid, err := fs.UploadInfo(context.Background(), "req.bin", filesystem.FileSource{Literal: reqContent})
	if err != nil {
		t.Fatal(err)
	}
	sid, err := fs.UploadInfo(context.Background(), "rsp.bin", filesystem.FileSource{Literal: rspContent})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("coap")
	if err != nil {
		t.Fatal(err)
	}
	var up, down []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			CoAP: &core.CoAPConfig{
				Method:             "POST",
				Path:               []string{"upload"},
				FileSource:         &filesystem.FileSource{FileID: rid.FileID},
				Response:           boolPtr(true),
				ResponseCode:       "2.01",
				ResponseFileSource: &filesystem.FileSource{FileID: sid.FileID},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if ev.Up {
			up = append(up, ev.Bytes...)
		} else {
			down = append(down, ev.Bytes...)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(up), reqContent) {
		t.Fatalf("请求 payload 缺文件原文 (up=%d bytes)", len(up))
	}
	if !strings.Contains(string(down), rspContent) {
		t.Fatalf("响应 payload 缺文件原文 (down=%d bytes)", len(down))
	}
}

func boolPtr(b bool) *bool { return &b }

// L4 复审：悬空 file_id → warn 静默跳过（家族契约），不报错不发包内容。
func TestChainFileSourceDanglingSilentSkip(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	g, err := layers.NewLayerGenerator("coap")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			CoAP: &core.CoAPConfig{
				Method:       "GET",
				Path:         []string{"f"},
				ResponseCode: "2.05",
				FileSource:   &filesystem.FileSource{FileID: strings.Repeat("cd", 32)},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		n++
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("悬空引用不得报错: %v", err)
	}
	if n == 0 {
		t.Fatal("悬空时信令事件应照常发射（仅载荷缺席）")
	}
}
