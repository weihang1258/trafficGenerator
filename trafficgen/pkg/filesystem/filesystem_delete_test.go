package filesystem_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestDelete_RemovesNameOnly_WhenOtherRefsExist(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "shared content"}
	if err := fs.Upload(ctx, "a.txt", src); err != nil {
		t.Fatalf("Upload a.txt err=%v", err)
	}
	if err := fs.Upload(ctx, "b.txt", src); err != nil {
		t.Fatalf("Upload b.txt err=%v", err)
	}
	blobPath, _ := fs.BlobPathForContent(ctx, []byte("shared content"))

	// Delete a.txt — blob should still exist because b.txt references it.
	if err := fs.Delete(ctx, "a.txt"); err != nil {
		t.Fatalf("Delete a.txt err=%v", err)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob should still exist after deleting one of two refs: %v", err)
	}
	// a.txt no longer readable.
	if _, err := fs.Read(ctx, "a.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Read a.txt after delete: got err=%v, want ErrNotFound", err)
	}
	// b.txt still readable.
	if got, err := fs.Read(ctx, "b.txt"); err != nil || string(got) != "shared content" {
		t.Fatalf("Read b.txt after delete: got %q, err=%v", string(got), err)
	}
}

func TestDelete_RemovesBlob_WhenLastRef(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "only.txt", filesystem.FileSource{Literal: "unique content"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	blobPath, _ := fs.BlobPathForContent(ctx, []byte("unique content"))

	if err := fs.Delete(ctx, "only.txt"); err != nil {
		t.Fatalf("Delete err=%v", err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob should be deleted, got err=%v", err)
	}
}

func TestDelete_NotFound(t *testing.T) {
	fs := newFS(t)
	if err := fs.Delete(context.Background(), "nope.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Delete nope.txt: got err=%v, want ErrNotFound", err)
	}
}

// TestDelete_CleanRelPath_Rejections mirrors TestUpload_CleanRelPath_Rejections:
// empty path, absolute path, ".." escape, and "." (cleaned to "" -> rejected).
// Guards against a future refactor that skips cleanRelPath on Delete and
// silently allows path-escape on delete.
func TestDelete_CleanRelPath_Rejections(t *testing.T) {
	fs := newFS(t)
	for _, path := range []string{"", "/etc/foo", "../foo", "."} {
		if err := fs.Delete(context.Background(), path); err == nil {
			t.Fatalf("Delete(%q) should return error", path)
		}
	}
}
