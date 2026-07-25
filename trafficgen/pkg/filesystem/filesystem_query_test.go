package filesystem_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestQuery_ReturnsFileInfo(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "hello"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	info, err := fs.Query(ctx, "a.txt")
	if err != nil {
		t.Fatalf("Query err=%v", err)
	}
	if info.Name != "a.txt" {
		t.Fatalf("Name got %q, want %q", info.Name, "a.txt")
	}
	if info.IsDir {
		t.Fatalf("IsDir should be false")
	}
	if info.Size != 5 {
		t.Fatalf("Size got %d, want 5", info.Size)
	}
	if info.SHA256 == "" {
		t.Fatalf("SHA256 should be set")
	}
}

func TestQuery_NotFound(t *testing.T) {
	fs := newFS(t)
	_, err := fs.Query(context.Background(), "nope.txt")
	if !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Query nope.txt: got err=%v, want ErrNotFound", err)
	}
}

func TestList_RootListsFilesAndDirs(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "A"})
	fs.Upload(ctx, "docs/b.txt", filesystem.FileSource{Literal: "B"})
	fs.Mkdir(ctx, "empty-dir")

	entries, err := fs.List(ctx, ".")
	if err != nil {
		t.Fatalf("List . err=%v", err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	if !names["a.txt"] || !names["docs"] || !names["empty-dir"] {
		t.Fatalf("List missing entries: got %v", names)
	}
}

func TestList_EmptyDir(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Mkdir(ctx, "empty")
	entries, err := fs.List(ctx, "empty")
	if err != nil {
		t.Fatalf("List empty err=%v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("List empty got %d entries, want 0", len(entries))
	}
}

// TestList_NonexistentDir_IsErrNotFound covers the Important fix: a
// non-existent dir must come back as ErrNotFound, while other os.ReadDir
// errors (e.g., permission denied) must NOT be masked as ErrNotFound.
func TestList_NonexistentDir_IsErrNotFound(t *testing.T) {
	fs := newFS(t)
	_, err := fs.List(context.Background(), "does-not-exist")
	if !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("List on nonexistent dir: got err=%v, want ErrNotFound", err)
	}
}

// TestList_PermissionDenied_IsNotErrNotFound covers the Important fix:
// a permission-denied directory exists on disk but is unreadable. It
// must NOT be reported as ErrNotFound (which would mislead callers into
// thinking the path is simply missing). Instead, the underlying error
// should surface so the caller can distinguish.
func TestList_PermissionDenied_IsNotErrNotFound(t *testing.T) {
	// Drop privileges to a non-root user so chmod 000 actually blocks
	// the read. When running as root, chmod 000 is a no-op (root bypasses
	// DAC), so skip the test in that case — it would assert nothing.
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 would not block root, test would not exercise the intended path")
	}
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "locked"); err != nil {
		t.Fatalf("Mkdir locked err=%v", err)
	}
	lockedDir := filepath.Join(fs.Root(), "locked")
	if err := os.Chmod(lockedDir, 0o000); err != nil {
		t.Fatalf("chmod 000 err=%v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockedDir, 0o755) })

	_, err := fs.List(ctx, "locked")
	if err == nil {
		t.Fatal("List on permission-denied dir should return error")
	}
	if errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("List on permission-denied dir returned ErrNotFound — should surface the underlying error, got err=%v", err)
	}
}
