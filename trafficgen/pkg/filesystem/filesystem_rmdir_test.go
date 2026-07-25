package filesystem_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// TestRmdir_EmptySubdir_NonRecursive_Succeeds is a regression test for I4:
// a newly-created empty subdir (with no user entries) must be removable
// non-recursive. The fix skips both ".meta" and "blobs" in the userEntries
// count. Without the fix, Rmdir on a subdir would work (subdirs don't have
// .meta or blobs), but a future Rmdir on the ROOT (if cleanRelPath ever
// allowed it) would count "blobs" as a user entry. We test the empty-subdir
// path here because it's the closest user-accessible analog.
func TestRmdir_EmptySubdir_NonRecursive_Succeeds(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "empty"); err != nil {
		t.Fatalf("Mkdir empty: %v", err)
	}
	if err := fs.Rmdir(ctx, "empty", filesystem.RmdirOptions{Recursive: false}); err != nil {
		t.Fatalf("Rmdir empty non-recursive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fs.Root(), "empty")); !os.IsNotExist(err) {
		t.Fatalf("empty should be removed: %v", err)
	}
}

// TestRmdir_Recursive_SkipsBlobsDir is a regression test for I3: the
// recursive walk must NOT descend into the "blobs/" directory at the
// ROOT level. We can't call Rmdir("/") directly (cleanRelPath rejects
// "."), so we test indirectly: when a subdir's blobs are deleted via
// Rmdir recursive, the root blobs/ directory itself must survive (the
// walk must not recurse into it and delete the blob files of OTHER
// refs).
//
// Setup: two subdirs each referencing the SAME blob (dedup). Rmdir
// recursive on subdir1 removes the blob's ref for "subdir1/a.txt" but
// the blob itself must survive (subdir2/a.txt still references it). We
// then verify the blob is intact (both content and on-disk presence)
// AND the root blobs/ directory is intact (still contains the blob
// file). Without the I3 fix, a recursive walk that descended into root
// blobs/ could delete the blob file even though subdir2 still
// references it.
func TestRmdir_Recursive_SkipsBlobsDir(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()

	// Upload the SAME content to two different subdirs (dedup: one blob,
	// two refs).
	if err := fs.Mkdir(ctx, "subdir1"); err != nil {
		t.Fatalf("Mkdir subdir1: %v", err)
	}
	if err := fs.Mkdir(ctx, "subdir2"); err != nil {
		t.Fatalf("Mkdir subdir2: %v", err)
	}
	src := filesystem.FileSource{Literal: "shared-content"}
	if err := fs.Upload(ctx, "subdir1/a.txt", src); err != nil {
		t.Fatalf("Upload subdir1/a.txt: %v", err)
	}
	if err := fs.Upload(ctx, "subdir2/a.txt", src); err != nil {
		t.Fatalf("Upload subdir2/a.txt: %v", err)
	}
	blobShared, _ := fs.BlobPathForContent(ctx, []byte("shared-content"))

	// Rmdir recursive on subdir1 must succeed.
	if err := fs.Rmdir(ctx, "subdir1", filesystem.RmdirOptions{Recursive: true}); err != nil {
		t.Fatalf("Rmdir subdir1 recursive: %v", err)
	}

	// The shared blob must STILL EXIST on disk because subdir2/a.txt
	// still references it (removeRefLocked only deletes the blob when
	// refs become empty). Without the I3 fix, a recursive walk that
	// descended into root blobs/ might delete the blob file directly,
	// breaking subdir2/a.txt.
	if _, err := os.Stat(blobShared); err != nil {
		t.Fatalf("shared blob should still exist (subdir2 still references it): %v", err)
	}

	// subdir2/a.txt must still be readable (blob intact).
	got, err := fs.Read(ctx, "subdir2/a.txt")
	if err != nil {
		t.Fatalf("Read subdir2/a.txt after Rmdir subdir1: %v", err)
	}
	if string(got) != "shared-content" {
		t.Fatalf("subdir2/a.txt content = %q, want %q", string(got), "shared-content")
	}

	// The root blobs/ directory must still contain the blob file.
	blobsDir := filepath.Join(fs.Root(), "blobs")
	blobEntries, err := os.ReadDir(blobsDir)
	if err != nil {
		t.Fatalf("ReadDir root blobs/: %v", err)
	}
	if len(blobEntries) != 1 {
		t.Fatalf("root blobs/ should have 1 entry (the shared blob), got %d", len(blobEntries))
	}
}

// TestRmdirRecursive_CorruptedMeta_ContinuesWalk is a regression test for
// I8: when removeRefLocked returns a non-ErrNotFound error during a
// recursive walk, the walk must log and continue rather than aborting.
// The trailing os.Remove still cleans up the on-disk file.
//
// To trigger a non-ErrNotFound error from removeRefLocked, we replace a
// blob file with a non-empty directory. removeRefLocked calls
// os.Remove(blobPath), which fails with ENOTEMPTY when the path is a
// non-empty directory. Without the I8 fix, this aborts the entire walk
// (the second file in dir/ is never cleaned up and dir/ itself is not
// removed). With the fix, the walk logs and continues, cleaning up the
// rest of the directory.
func TestRmdirRecursive_CorruptedMeta_ContinuesWalk(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()

	// Upload two files in a subdir.
	if err := fs.Mkdir(ctx, "dir"); err != nil {
		t.Fatalf("Mkdir dir: %v", err)
	}
	if err := fs.Upload(ctx, "dir/a.txt", filesystem.FileSource{Literal: "A"}); err != nil {
		t.Fatalf("Upload a.txt: %v", err)
	}
	if err := fs.Upload(ctx, "dir/b.txt", filesystem.FileSource{Literal: "B"}); err != nil {
		t.Fatalf("Upload b.txt: %v", err)
	}

	// Sabotage one blob: replace the blob file for "dir/a.txt" with a
	// non-empty directory. os.Remove on a non-empty directory fails with
	// ENOTEMPTY, which is NOT IsNotExist — so removeRefLocked returns it,
	// and the I8 fix must catch it (log + continue) instead of aborting.
	blobA, _ := fs.BlobPathForContent(ctx, []byte("A"))
	if err := os.Remove(blobA); err != nil {
		t.Fatalf("remove blob A to sabotage: %v", err)
	}
	// Create a directory at the blob path with a file inside (non-empty).
	if err := os.MkdirAll(blobA, 0755); err != nil {
		t.Fatalf("MkdirAll sabotage blob A: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobA, "blocker"), []byte("x"), 0644); err != nil {
		t.Fatalf("WriteFile blocker inside sabotaged blob: %v", err)
	}

	// Rmdir recursive on "dir" must NOT return an error. The walk hits
	// "dir/a.txt", removeRefLocked fails (ENOTEMPTY on blob removal), but
	// the I8 fix logs and continues. "dir/b.txt" is cleaned up normally,
	// and "dir" itself is removed.
	err := fs.Rmdir(ctx, "dir", filesystem.RmdirOptions{Recursive: true})
	if err != nil {
		t.Fatalf("Rmdir recursive with sabotaged blob should not error (I8 fix: log+continue), got: %v", err)
	}

	// The dir itself must be gone (walk completed).
	if _, err := os.Stat(filepath.Join(fs.Root(), "dir")); !os.IsNotExist(err) {
		t.Fatalf("dir should be removed after recursive Rmdir: %v", err)
	}

	// The sabotaged blob-directory still exists (we couldn't remove it),
	// but that's expected — the fix is about not aborting the walk, not
	// about forcefully removing blobs. A future operator can clean it up.
}
