package core_test

import (
	"context"
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// 客户端第9轮复核 三.2：file+file_id 双填时胜出内容必须确定 —— 契约
// File > FileID（pkg/filesystem resolveBytes 同序）。此前 PayloadCache 的
// file_id 早查（M1 零 IO 优化）不看 src.File 是否非空：file_id 内容一旦
// 入过缓存，双填时早查直接返回 file_id 内容，压过 File —— 胜者随"哪个
// 内容先入过缓存"漂移（客户端实测 13 组无规则）。
func TestGetOrLoadFileBeatsFileID(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fsys.UploadInfo(context.Background(), "fid.bin", filesystem.FileSource{Literal: "FID-CONTENT"})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	// 先单独解析 file_id 让其内容入缓存（复现前置：早查命中的条件）。
	if b, err := pc.GetOrLoad(ctx, filesystem.FileSource{FileID: r.FileID}); err != nil || string(b) != "FID-CONTENT" {
		t.Fatalf("warm file_id: %q err=%v", b, err)
	}

	// 双填：file 指向磁盘文件（内容 FILE-CONTENT）+ file_id。file 必须恒赢。
	disk := t.TempDir() + "/a.bin"
	if err := writeFile(disk, "FILE-CONTENT"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		b, err := pc.GetOrLoad(ctx, filesystem.FileSource{File: disk, FileID: r.FileID})
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "FILE-CONTENT" {
			t.Fatalf("round %d: file+file_id resolved %q, want FILE-CONTENT (contract File > FileID)", i, b)
		}
	}
}

// 客户端第9轮复核 三.1：file_id 引用的 blob 被 delete 后，缓存里残留的
// 内容不得再被注入 —— 早查命中必须先确认 blob 仍存在（O(1) stat 面），
// 已删则丢弃陈旧条目、走 resolve 失败路径（与"从未存在"同口径降级）。
func TestGetOrLoadDeletedFileIDDoesNotServeStaleCache(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := fsys.UploadInfo(context.Background(), "gone.bin", filesystem.FileSource{Literal: "STALE-BYTES"})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)
	src := filesystem.FileSource{FileID: r.FileID}

	if b, err := pc.GetOrLoad(ctx, src); err != nil || string(b) != "STALE-BYTES" {
		t.Fatalf("warm: %q err=%v", b, err)
	}
	if err := fsys.Delete(context.Background(), "gone.bin"); err != nil {
		t.Fatal(err)
	}
	b, err := pc.GetOrLoad(ctx, src)
	if err == nil {
		t.Fatalf("after delete GetOrLoad returned %q (stale cache served), want error", b)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
