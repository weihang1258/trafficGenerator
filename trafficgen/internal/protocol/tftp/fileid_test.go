package tftp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2b（D-FILE-2 裁定3）：tftp 层 file_source → 文件模式——块数=
// ceil(size/blksize)，块内容拼接==文件原文（逐块切片，末块=余量）。
// 此前 file_source 仅算块数，内容恒走 DataPayloadPattern 循环填充=假传输。
func TestChainFileSourceFileModeBlocksConcatToContent(t *testing.T) {
	content := "TFTPFILE-" + strings.Repeat("t", 600) + "-END" // 618B > 512 → 2 块
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.UploadInfo(context.Background(), "t.bin", filesystem.FileSource{Literal: content}); err != nil {
		t.Fatal(err)
	}
	_ = filesystem.FileSource{FileID: "probe"} // import 保底：链路径由单点解析承接
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	g, err := layers.NewLayerGenerator("tftp")
	if err != nil {
		t.Fatal(err)
	}
	// 模拟链路径：单点解析已把 spec.FileSource 字节放进 Meta.Payload
	// （ChainPlanner.Plan 单点契约）。
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			TFTP:    &core.TFTPConfig{Filename: "f.bin", Mode: "read"},
			Payload: []byte(content),
		},
	}
	var dataBlocks [][]byte
	req.EmitMsg = func(ev layers.MessageEvent) error {
		if len(ev.Bytes) >= 4 && ev.Bytes[0] == 0 && ev.Bytes[1] == 3 { // DATA
			dataBlocks = append(dataBlocks, ev.Bytes[4:])
		}
		return nil
	}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(dataBlocks) == 0 {
		t.Fatal("无 DATA 块")
	}
	var concat []byte
	for _, b := range dataBlocks {
		concat = append(concat, b...)
	}
	if string(concat) != content {
		t.Fatalf("块拼接=%d 字节, want %d（文件原文）", len(concat), len(content))
	}
	// 末块=余量（618-512=106），不得填零或循环填充
	if last := dataBlocks[len(dataBlocks)-1]; len(last) != len(content)-512 {
		t.Fatalf("末块=%d 字节, want 余量 %d", len(last), len(content)-512)
	}
}
