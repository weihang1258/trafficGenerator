package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// T-FILE-1a/1b/1d（D-FILE-1）：上传去重回执 / 按哈希反查 / 错误面。
func TestUploadInfoDedupReceipt(t *testing.T) {
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	content := "file-id-dedup-content"

	r1, err := fs.UploadInfo(ctx, "a/first.bin", FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	want := hex.EncodeToString(sum[:])
	if r1.FileID != want || r1.SHA256 != want || r1.Existed || r1.Bytes != len(content) {
		t.Fatalf("r1 = %+v, want file_id=%s existed=false", r1, want)
	}

	// 同内容不同路径 → 同 file_id + existed=true（上传即查询）
	r2, err := fs.UploadInfo(ctx, "b/second.bin", FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	if r2.FileID != want || !r2.Existed {
		t.Fatalf("r2 = %+v, want same id + existed", r2)
	}

	// 路径来源同内容 → 同样 existed
	r3, err := fs.UploadInfo(ctx, "c/third.bin", FileSource{File: "a/first.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if r3.FileID != want || !r3.Existed {
		t.Fatalf("r3 = %+v", r3)
	}

	// file_id 反查：命中
	info, err := fs.QueryByHash(ctx, want)
	if err != nil || info.SHA256 != want || info.Size != int64(len(content)) {
		t.Fatalf("QueryByHash = %+v err=%v", info, err)
	}
	// file_id 反查：未知哈希（合法形状）→ ErrNotFound + 人话文案
	ghost := strings.Repeat("ab", 32)
	_, err = fs.QueryByHash(ctx, ghost)
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("ghost query err = %v", err)
	}
	// ReadByHash 字节等值 + 缺失文案
	b, err := fs.ReadByHash(ctx, want)
	if err != nil || string(b) != content {
		t.Fatalf("ReadByHash = %q err=%v", b, err)
	}
	if _, err := fs.ReadByHash(ctx, ghost); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("ghost read err = %v", err)
	}
	// file_id 悬空（删除后）→ 不再解析
	if err := fs.Delete(ctx, "a/first.bin"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(ctx, "b/second.bin"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(ctx, "c/third.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadByHash(ctx, want); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("deleted blob should not resolve, err=%v", err)
	}
}

// T-FILE-1d：file_id 形状校验 fail-loud + 多源静默优先级 File>FileID>Literal>Fill>Random。
func TestFileIDValidationAndPrecedence(t *testing.T) {
	fs, _ := New(t.TempDir())
	ctx := context.Background()
	// 形状：短/非 hex
	if _, err := fs.UploadInfo(ctx, "x.bin", FileSource{Literal: "x", FileID: "abc"}); err == nil {
		t.Fatal("short file_id accepted")
	}
	// 注意：Literal+FileID 同填走静默优先级 FileID>Literal → resolve 用 file_id；
	// 形状错在 Validate 拒，UploadInfo 不调 Validate（既有分工），resolveBytes 直接走分支——
	// 形状错由 resolve 分支的 ReadByHash→validFileID 拒。
	if _, err := fs.UploadInfo(ctx, "y.bin", FileSource{FileID: "abc", Literal: "y"}); err == nil {
		t.Fatal("invalid file_id shape should fail in resolve")
	}
	// 优先级：FileID > Literal（合法 file_id 时 Literal 被忽略）
	content := "precedence-content"
	r, _ := fs.UploadInfo(ctx, "p.bin", FileSource{Literal: content})
	b, err := fs.Read(ctx, "p.bin")
	if err != nil || string(b) != content {
		t.Fatalf("setup read = %q err=%v", b, err)
	}
	// file_id 指向 p.bin 的内容 + File 同填 → File 赢（File > FileID）
	r2, err := fs.UploadInfo(ctx, "q.bin", FileSource{File: "p.bin", FileID: r.FileID})
	if err != nil {
		t.Fatal(err)
	}
	qb, _ := fs.Read(ctx, "q.bin")
	if string(qb) != content {
		t.Fatalf("File>FileID precedence broken: %q", qb)
	}
	_ = r2
	// Validate 面：非法 file_id 拒
	if err := (&FileSource{FileID: "zz"}).Validate(); err == nil {
		t.Fatal("Validate accepted bad file_id")
	}
	if err := (&FileSource{FileID: r.FileID}).Validate(); err != nil {
		t.Fatalf("Validate rejected good file_id: %v", err)
	}
}

// file_id 作为上传源：给已有内容再挂一个路径名（re-materialize）。
func TestUploadByFileIDRematerializes(t *testing.T) {
	fs, _ := New(t.TempDir())
	ctx := context.Background()
	r, err := fs.UploadInfo(ctx, "orig.bin", FileSource{Literal: "remat"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := fs.UploadInfo(ctx, "alias.bin", FileSource{FileID: r.FileID})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Existed || r2.FileID != r.FileID {
		t.Fatalf("r2 = %+v", r2)
	}
	b, err := fs.Read(ctx, "alias.bin")
	if err != nil || string(b) != "remat" {
		t.Fatalf("alias read = %q err=%v", b, err)
	}
}
