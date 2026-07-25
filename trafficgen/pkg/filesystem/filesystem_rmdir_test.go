package filesystem_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestMkdir_CreatesNested(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "a/b/c"); err != nil {
		t.Fatalf("Mkdir a/b/c err=%v", err)
	}
	if info, err := fs.Query(ctx, "a/b/c"); err != nil || !info.IsDir {
		t.Fatalf("Query a/b/c: info=%+v err=%v", info, err)
	}
}

func TestRmdir_EmptyDir_NonRecursive_Succeeds(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Mkdir(ctx, "empty")
	if err := fs.Rmdir(ctx, "empty", filesystem.RmdirOptions{Recursive: false}); err != nil {
		t.Fatalf("Rmdir empty non-recursive err=%v", err)
	}
}

func TestRmdir_NonEmptyDir_NonRecursive_Fails(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Mkdir(ctx, "dir")
	fs.Upload(ctx, "dir/a.txt", filesystem.FileSource{Literal: "A"})
	err := fs.Rmdir(ctx, "dir", filesystem.RmdirOptions{Recursive: false})
	if !errors.Is(err, filesystem.ErrNotEmpty) {
		t.Fatalf("Rmdir non-empty non-recursive: got err=%v, want ErrNotEmpty", err)
	}
}

func TestRmdir_Recursive_DeletesAllFilesAndDirs(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Mkdir(ctx, "root")
	fs.Mkdir(ctx, "root/sub")
	fs.Upload(ctx, "root/a.txt", filesystem.FileSource{Literal: "A"})
	fs.Upload(ctx, "root/sub/b.txt", filesystem.FileSource{Literal: "B"})

	blobA, _ := fs.BlobPathForContent(ctx, []byte("A"))
	blobB, _ := fs.BlobPathForContent(ctx, []byte("B"))

	if err := fs.Rmdir(ctx, "root", filesystem.RmdirOptions{Recursive: true}); err != nil {
		t.Fatalf("Rmdir root recursive err=%v", err)
	}
	// Both blobs should be deleted (each had one ref).
	if _, err := os.Stat(blobA); !os.IsNotExist(err) {
		t.Fatalf("blobA should be deleted: %v", err)
	}
	if _, err := os.Stat(blobB); !os.IsNotExist(err) {
		t.Fatalf("blobB should be deleted: %v", err)
	}
}

func TestRmdir_Recursive_DedupedBlobSurvivesWhenOtherRefsExist(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	fs.Mkdir(ctx, "dir1")
	fs.Mkdir(ctx, "dir2")
	src := filesystem.FileSource{Literal: "shared"}
	fs.Upload(ctx, "dir1/a.txt", src)
	fs.Upload(ctx, "dir2/b.txt", src) // same blob, two refs
	blobShared, _ := fs.BlobPathForContent(ctx, []byte("shared"))

	// Delete dir1 recursively — blob should survive (dir2/b.txt still references it).
	if err := fs.Rmdir(ctx, "dir1", filesystem.RmdirOptions{Recursive: true}); err != nil {
		t.Fatalf("Rmdir dir1 err=%v", err)
	}
	if _, err := os.Stat(blobShared); err != nil {
		t.Fatalf("shared blob should survive: %v", err)
	}
}

func TestRmdir_NotFound(t *testing.T) {
	fs := newFS(t)
	if err := fs.Rmdir(context.Background(), "nope", filesystem.RmdirOptions{}); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Rmdir nope: got err=%v, want ErrNotFound", err)
	}
}
