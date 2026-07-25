package filesystem_test

import (
	"context"
	"errors"
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
