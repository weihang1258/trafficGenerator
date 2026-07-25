package filesystem_test

import (
	"context"
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestUpload_ThenRead_RoundTrip(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "hello world"}
	if err := fs.Upload(ctx, "docs/greeting.txt", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, err := fs.Read(ctx, "docs/greeting.txt")
	if err != nil {
		t.Fatalf("Read err=%v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("Read got %q, want %q", string(got), "hello world")
	}
}

func TestUpload_SameContentSameHash_DoesNotRewriteBlob(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "same content"}
	if err := fs.Upload(ctx, "a.txt", src); err != nil {
		t.Fatalf("Upload a.txt err=%v", err)
	}
	blobPath, err := fs.BlobPathForContent(ctx, []byte("same content"))
	if err != nil {
		t.Fatalf("BlobPathForContent err=%v", err)
	}
	info1, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("first blob stat err=%v", err)
	}
	if err := fs.Upload(ctx, "b.txt", src); err != nil {
		t.Fatalf("Upload b.txt err=%v", err)
	}
	info2, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("second blob stat err=%v", err)
	}
	// Same ModTime: blob was not rewritten.
	if info1.ModTime() != info2.ModTime() {
		t.Fatalf("blob was rewritten on second Upload (mtime changed)")
	}
}

func TestUpload_OverwriteExistingPath_DedupOldBlobIfLastRef(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	// Upload path a.txt with content X
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "content X"}); err != nil {
		t.Fatalf("Upload a.txt X err=%v", err)
	}
	// Verify blob X exists
	blobX, _ := fs.BlobPathForContent(ctx, []byte("content X"))
	if _, err := os.Stat(blobX); err != nil {
		t.Fatalf("blob X should exist: %v", err)
	}
	// Overwrite a.txt with content Y
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "content Y"}); err != nil {
		t.Fatalf("Upload a.txt Y err=%v", err)
	}
	// Blob X should now be deleted (no remaining refs)
	if _, err := os.Stat(blobX); !os.IsNotExist(err) {
		t.Fatalf("blob X should be deleted after overwrite, got err=%v", err)
	}
}

// newFS returns a fresh Filesystem rooted at a temp dir.
func newFS(t *testing.T) *filesystem.Filesystem {
	t.Helper()
	dir := t.TempDir()
	fs, err := filesystem.New(dir)
	if err != nil {
		t.Fatalf("New err=%v", err)
	}
	return fs
}
