package filesystem_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestUpload_FromRandom_Unseeded_VariesAcrossCalls verifies that two
// consecutive Upload calls with an unseeded Random source produce different
// bytes (crypto-random freshness), not just length-in-range. This is a
// stronger assertion than TestUpload_Random_Unseeded_LengthInRange, which
// only checks length.
func TestUpload_FromRandom_Unseeded_VariesAcrossCalls(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Random: &filesystem.Random{MinBytes: 64, MaxBytes: 64}}
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload 1 err=%v", err)
	}
	got1, err := fs.Read(ctx, "a.bin")
	if err != nil {
		t.Fatalf("Read 1 err=%v", err)
	}
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload 2 err=%v", err)
	}
	got2, err := fs.Read(ctx, "a.bin")
	if err != nil {
		t.Fatalf("Read 2 err=%v", err)
	}
	if len(got1) != 64 || len(got2) != 64 {
		t.Fatalf("lens got1=%d got2=%d, want 64", len(got1), len(got2))
	}
	if bytes.Equal(got1, got2) {
		t.Fatalf("unseeded Random should differ on each call (got1==got2=%x)", got1[:8])
	}
}

// TestUpload_FromFile_SourcePath verifies that a FileSource{File: ...} that
// references another file *within the same filesystem* is resolved via
// fs.Read and the bytes match the source file.
//
// (TestUpload_SourceFile_NoDeadlock in filesystem_branches_test.go already
// asserts no deadlock + bytes match for a top-level path. This test adds a
// subdirectory path to ensure cleanRelPath-then-Read composes correctly for
// nested sources.)
func TestUpload_FromFile_SourcePath(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "docs/source.txt", filesystem.FileSource{Literal: "from-file source"}); err != nil {
		t.Fatalf("Upload source.txt err=%v", err)
	}
	if err := fs.Upload(ctx, "docs/copy.txt", filesystem.FileSource{File: "docs/source.txt"}); err != nil {
		t.Fatalf("Upload copy.txt err=%v", err)
	}
	got, err := fs.Read(ctx, "docs/copy.txt")
	if err != nil {
		t.Fatalf("Read copy.txt err=%v", err)
	}
	if string(got) != "from-file source" {
		t.Fatalf("Read copy.txt got %q, want %q", string(got), "from-file source")
	}
}

// TestUpload_FromDiskFile verifies that src.File may be an absolute disk
// path (outside the filesystem's own root). resolveBytes must detect the
// absolute path and read directly from disk via os.ReadFile, instead of
// routing through fs.Read (which would reject the absolute path).
func TestUpload_FromDiskFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "real.txt")
	if err := os.WriteFile(tmpFile, []byte("from-disk content"), 0644); err != nil {
		t.Fatalf("WriteFile err=%v", err)
	}
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "disk.txt", filesystem.FileSource{File: tmpFile}); err != nil {
		t.Fatalf("Upload disk.txt err=%v", err)
	}
	got, err := fs.Read(ctx, "disk.txt")
	if err != nil {
		t.Fatalf("Read disk.txt err=%v", err)
	}
	if string(got) != "from-disk content" {
		t.Fatalf("Read disk.txt got %q, want %q", string(got), "from-disk content")
	}
}

// TestUpload_FromDiskFile_MissingFile verifies the failure path for the
// absolute disk path branch: pointing src.File at a non-existent disk file
// surfaces the os.ReadFile error instead of silently producing empty bytes
// or a generic "not found".
func TestUpload_FromDiskFile_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.txt")
	fs := newFS(t)
	ctx := context.Background()
	err := fs.Upload(ctx, "disk.txt", filesystem.FileSource{File: missing})
	if err == nil {
		t.Fatal("Upload with missing disk file should return error")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("err=%v, want os.IsNotExist", err)
	}
}
