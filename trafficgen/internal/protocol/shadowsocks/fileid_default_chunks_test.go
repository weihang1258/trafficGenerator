package shadowsocks

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// 客户端第9轮复核 三.3：cipher=none + file_source（不显式 chunks）曾静默丢
// 内容 —— layer_gen 先按空 Meta.Payload 算 chunkSizes（落到 [ChunkPayloadSize]
// = 0），再解析 FileSource，分块循环拿到的 sz=0 → 只发 2 字节空块 "0000"。
// 修复口径：FileSource 解析必须在 chunkSizes 计算之前，file 内容按缺省分块
// 规则（Chunks=0 且 Payload 非空 → 按 MaxChunkPayload 拆）进线。
func TestChainFileSourceWithoutChunksCarriesContent(t *testing.T) {
	content := strings.Repeat("SSFILE-", 40) // 280B > MaxChunkPayload？否——280 < 1400，单块全量
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fsys.UploadInfo(context.Background(), "ss.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("shadowsocks")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			Shadowsocks: &core.ShadowsocksConfig{Cipher: "none"},
			// FileSource 不经 Meta.Payload 直传 —— 由生成器解析
		},
	}
	// 手工构造带 FileSource 的 spec 形态：直接设 ss.FileSource（生成器读
	// req.Meta.Shadowsocks.FileSource）。
	req.Meta.Shadowsocks.FileSource = &filesystem.FileSource{FileID: r.FileID}
	req.EmitMsg = func(ev layers.MessageEvent) error {
		got = append(got, ev.Bytes...)
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), content) {
		t.Fatalf("wire missing file content (len=%d)", len(got))
	}
}
