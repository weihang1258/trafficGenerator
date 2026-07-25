package filesystem_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestMkdir_OnExistingFile_ReturnsErrExists covers the Mkdir branch where
// relPath already exists as a file (not a directory). Mkdir must return
// ErrExists rather than silently masking the file with a directory.
func TestMkdir_OnExistingFile_ReturnsErrExists(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "file.txt", filesystem.FileSource{Literal: "A"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	err := fs.Mkdir(ctx, "file.txt")
	if !errors.Is(err, filesystem.ErrExists) {
		t.Fatalf("Mkdir on existing file: got err=%v, want ErrExists", err)
	}
	// Original file must still be readable and unchanged.
	got, err := fs.Read(ctx, "file.txt")
	if err != nil {
		t.Fatalf("Read after Mkdir err=%v", err)
	}
	if string(got) != "A" {
		t.Fatalf("Read got %q, want %q", string(got), "A")
	}
}

// TestRmdir_OnFile_Fails covers the Rmdir branch where relPath exists but
// is not a directory. Rmdir must return an error (specifically
// ErrNotADirectory) and must not delete the file.
func TestRmdir_OnFile_Fails(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "file.txt", filesystem.FileSource{Literal: "A"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	err := fs.Rmdir(ctx, "file.txt", filesystem.RmdirOptions{Recursive: false})
	if err == nil {
		t.Fatal("Rmdir on file: got nil error, want non-nil")
	}
	if !errors.Is(err, filesystem.ErrNotADirectory) {
		t.Fatalf("Rmdir on file: got err=%v, want ErrNotADirectory", err)
	}
	// Ensure error is not masquerading as ErrNotFound or ErrNotEmpty.
	if errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Rmdir on file: err should not be ErrNotFound: %v", err)
	}
	if errors.Is(err, filesystem.ErrNotEmpty) {
		t.Fatalf("Rmdir on file: err should not be ErrNotEmpty: %v", err)
	}
	// File must still be present.
	got, err := fs.Read(ctx, "file.txt")
	if err != nil {
		t.Fatalf("Read after Rmdir err=%v", err)
	}
	if string(got) != "A" {
		t.Fatalf("Read got %q, want %q", string(got), "A")
	}
}

// TestRmdir_Recursive_ForeignFile_NoMeta covers the recursive branch's
// ErrNotFound guard for foreign files (files on disk without a meta entry).
// A foreign file is dropped into a directory via os.WriteFile (bypassing
// Upload so no meta is created). Rmdir(dir, {Recursive: true}) must remove
// both the directory and the foreign file without error.
func TestRmdir_Recursive_ForeignFile_NoMeta(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "dir"); err != nil {
		t.Fatalf("Mkdir err=%v", err)
	}
	// Drop a foreign file directly on disk (no Upload => no meta entry).
	foreignPath := filepath.Join(fs.Root(), "dir", "foreign.txt")
	if err := os.WriteFile(foreignPath, []byte("foreign"), 0644); err != nil {
		t.Fatalf("os.WriteFile err=%v", err)
	}
	// Sanity: no meta entry should exist for the foreign file.
	if _, err := fs.Query(ctx, "dir/foreign.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Query foreign pre-Rmdir: got err=%v, want ErrNotFound", err)
	}

	if err := fs.Rmdir(ctx, "dir", filesystem.RmdirOptions{Recursive: true}); err != nil {
		t.Fatalf("Rmdir recursive with foreign file: err=%v", err)
	}
	// Directory and foreign file should both be gone.
	if _, err := os.Stat(filepath.Join(fs.Root(), "dir")); !os.IsNotExist(err) {
		t.Fatalf("dir should be removed: %v", err)
	}
	if _, err := os.Stat(foreignPath); !os.IsNotExist(err) {
		t.Fatalf("foreign file should be removed: %v", err)
	}
}
