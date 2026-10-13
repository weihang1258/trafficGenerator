package socks5

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// T-FILE-2a（D-FILE-2 裁定2）：socks5 data[].file_source 曾被生成器+validator
// 以"FlowMeta 不承载 payload cache"为由双拒——该前提已被 8 个链生成器实跑
// 证伪（PayloadCacheFrom(ctx) 在生成器 ctx 恒可用）。撤拒后：隧道数据载荷
// == 文件原文（[]byte 直上，绕过 Payload string 二进制安全）。
func TestChainDataFileSourceCarriesContent(t *testing.T) {
	content := "SOCKSFILE-" + strings.Repeat("s", 100)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fs.UploadInfo(context.Background(), "s.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("socks5")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			Socks: &core.SocksConfig{
				Data: []core.SocksDataMessage{
					{Direction: "up", FileSource: &filesystem.FileSource{FileID: r.FileID}},
				},
			},
		},
	}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if ev.Up {
			got = append(got, ev.Bytes...)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v（撤拒后不得报错）", err)
	}
	if !strings.Contains(string(got), content) {
		t.Fatalf("隧道数据缺文件原文 (len=%d)", len(got))
	}
}

// T-FILE-2a 负例：悬空 file_id → 解析失败静默跳过（家族契约），不报错。
func TestChainDataFileSourceDanglingSilentSkip(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	g, err := layers.NewLayerGenerator("socks5")
	if err != nil {
		t.Fatal(err)
	}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			Socks: &core.SocksConfig{
				Data: []core.SocksDataMessage{
					{Direction: "up", FileSource: &filesystem.FileSource{FileID: strings.Repeat("ab", 32)}},
					{Direction: "up", Payload: "INLINE-OK"},
				},
			},
		},
	}
	var got []byte
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if ev.Up {
			got = append(got, ev.Bytes...)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("悬空引用不得报错: %v", err)
	}
	if !strings.Contains(string(got), "INLINE-OK") || strings.Contains(string(got), "\x00\x00") {
		t.Fatalf("内联消息应照发, 悬空消息应缺席: got=%d bytes", len(got))
	}
}
