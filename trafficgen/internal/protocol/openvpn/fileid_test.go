package openvpn

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2d（D-FILE-2 裁定5）：openvpn 层 file_source → P_DATA 明文载荷
// ==文件原文（加密外层不校内容——载荷在加密前注入 DataPayload 通路）。
func TestChainFileSourceDataPayload(t *testing.T) {
	content := "OVPNFILE-" + strings.Repeat("o", 120)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fs.UploadInfo(context.Background(), "o.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("openvpn")
	if err != nil {
		t.Fatal(err)
	}
	// P_DATA 外层加密——明文不上线（设计如此）。断言解析面：Generate 后
	// cfg.DataPayload 必须等于文件原文（planner.go:406 通路注入），且
	// P_DATA 事件长度 >= 原文长度（密文含原文全文）。
	cfg := &core.OpenVPNConfig{FileSource: &filesystem.FileSource{FileID: r.FileID}}
	n := 0
	maxLen := 0
	req := &layers.GenRequest{Meta: layers.FlowMeta{OpenVPN: cfg}}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		n++
		if len(ev.Bytes) > maxLen {
			maxLen = len(ev.Bytes)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if string(cfg.DataPayload) != content {
		t.Fatalf("DataPayload=%d 字节, want 文件原文 %d", len(cfg.DataPayload), len(content))
	}
	if n == 0 || maxLen < len(content) {
		t.Fatalf("P_DATA 事件 n=%d maxLen=%d, want >= %d", n, maxLen, len(content))
	}
}

// L4 复审：悬空 file_id → 解析失败静默跳过，DataPayload 不被污染。
func TestChainFileSourceDanglingSilentSkip(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	g, err := layers.NewLayerGenerator("openvpn")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &core.OpenVPNConfig{FileSource: &filesystem.FileSource{FileID: strings.Repeat("ab", 32)}}
	req := &layers.GenRequest{Meta: layers.FlowMeta{OpenVPN: cfg}}
	req.EmitMsg = func(layers.MessageEvent) error { return nil }
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("悬空引用不得报错: %v", err)
	}
	if len(cfg.DataPayload) != 0 {
		t.Fatalf("悬空时 DataPayload 应保持缺席, got %d 字节", len(cfg.DataPayload))
	}
}
