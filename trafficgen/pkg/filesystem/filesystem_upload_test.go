package filesystem_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
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
	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat blob err=%v", err)
	}
	// Capture inode + mtime; dedup should not rewrite the blob.
	firstIno := inodeOf(t, blobInfo)
	firstMod := blobInfo.ModTime()
	if err := fs.Upload(ctx, "b.txt", src); err != nil {
		t.Fatalf("Upload b.txt err=%v", err)
	}
	// Content-based assertion: blob bytes are exactly "same content", proving
	// dedup did not overwrite with different bytes (and is present at all).
	got, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob err=%v", err)
	}
	if string(got) != "same content" {
		t.Fatalf("blob content after dedup = %q, want %q", string(got), "same content")
	}
	// Structural assertion: blob was not rewritten (same inode, mtime unchanged).
	secondInfo, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat blob after dedup err=%v", err)
	}
	if inodeOf(t, secondInfo) != firstIno {
		t.Fatalf("blob inode changed: got %d, want %d (dedup should not rewrite)", inodeOf(t, secondInfo), firstIno)
	}
	if !secondInfo.ModTime().Equal(firstMod) {
		t.Fatalf("blob mtime changed: got %v, want %v", secondInfo.ModTime(), firstMod)
	}
}

// TestUpload_MaterializesFile_OnDisk verifies that after Upload, the file
// is visible at relPath on disk (hardlink to the blob). Guards against a
// refactor that drops the materialization step and makes List/Query silently
// miss files.
func TestUpload_MaterializesFile_OnDisk(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "visible.txt", filesystem.FileSource{Literal: "V"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	abs := filepath.Join(fs.Root(), "visible.txt")
	st, err := os.Stat(abs)
	if err != nil {
		t.Fatalf("visible.txt should be materialized on disk: %v", err)
	}
	if st.Size() != 1 {
		t.Fatalf("visible.txt size got %d, want 1", st.Size())
	}
	// Query must agree: same Name, Size, non-empty SHA256.
	info, err := fs.Query(ctx, "visible.txt")
	if err != nil {
		t.Fatalf("Query err=%v", err)
	}
	if info.Name != "visible.txt" || info.Size != 1 || info.SHA256 == "" {
		t.Fatalf("Query mismatch: %+v", info)
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
	// Verify a.txt is visible on disk (materialized hardlink).
	aPath := filepath.Join(fs.Root(), "a.txt")
	if _, err := os.Stat(aPath); err != nil {
		t.Fatalf("a.txt should be materialized on disk: %v", err)
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

// inodeOf returns the file's inode number (Unix only; fine for tests).
func inodeOf(t *testing.T, fi os.FileInfo) uint64 {
	t.Helper()
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}
