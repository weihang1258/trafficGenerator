package filesystem_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestFileSource_ZeroValue(t *testing.T) {
	var fs filesystem.FileSource
	if fs.File != "" || fs.Literal != "" || fs.Fill != nil || fs.Random != nil {
		t.Fatalf("zero FileSource should have all zero values: %+v", fs)
	}
}

func TestNew_EmptyRoot(t *testing.T) {
	_, err := filesystem.New("")
	if err == nil {
		t.Fatal("New(\"\") should return error on empty root")
	}
}

func TestNew_CreatesDir(t *testing.T) {
	// Use a non-existent nested root so MkdirAll creation path is exercised
	// rather than relying on t.TempDir() which already exists.
	dir := filepath.Join(t.TempDir(), "nested", "root")
	fs, err := filesystem.New(dir)
	if err != nil {
		t.Fatalf("New(%q) err=%v", dir, err)
	}
	if fs == nil {
		t.Fatal("New returned nil Filesystem")
	}
	// Verify both required subdirectories were actually created on disk.
	for _, sub := range []string{".meta/files", "blobs"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Errorf("expected %q to exist after New: %v", sub, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("expected %q to be a directory, got mode=%v", sub, info.Mode())
		}
	}
	// Root() accessor returns the configured root.
	if got := fs.Root(); got != dir {
		t.Errorf("Root()=%q, want %q", got, dir)
	}
}

func TestNew_Idempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "root")
	if _, err := filesystem.New(dir); err != nil {
		t.Fatalf("first New(%q) err=%v", dir, err)
	}
	// Calling New on the same root again should succeed without error.
	// initDirs uses MkdirAll which is idempotent.
	if _, err := filesystem.New(dir); err != nil {
		t.Fatalf("second New(%q) err=%v", dir, err)
	}
}
