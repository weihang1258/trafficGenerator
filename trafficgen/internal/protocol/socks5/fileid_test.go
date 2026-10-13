package socks5

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
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
	// L4 复审强化：逐事件断言——悬空消息须整条缺席（非空载荷段冒充），
	// 内联消息照发。只看拼接字节区分不了"跳过"与"发空段"。
	var ups [][]byte
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if ev.Up {
			ups = append(ups, ev.Bytes)
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("悬空引用不得报错: %v", err)
	}
	// up 事件 = 2 信令（greeting/request）+ 数据面。悬空消息整条缺席 →
	// 数据面恰 1 条（INLINE-OK）；若实现退化成"发空载荷段"则出现 4 条
	// 且其中一条为空——两种实现在此口径下可区分。
	if len(ups) != 3 {
		t.Fatalf("up 事件数=%d, want 3（2 信令+1 数据面；悬空缺席）", len(ups))
	}
	if string(ups[2]) != "INLINE-OK" {
		t.Fatalf("数据面 up=%q, want INLINE-OK", ups[2])
	}
	for i, b := range ups {
		if len(b) == 0 {
			t.Fatalf("up[%d] 为空载荷段（家族契约=整条跳过）", i)
		}
	}
}
