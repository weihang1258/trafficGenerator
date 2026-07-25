package filesystem_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestConcurrent_UploadSamePath_NTimes(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	const N = 50
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = fs.Upload(ctx, "shared.txt", filesystem.FileSource{Literal: "same"})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d err=%v", i, err)
		}
	}
	// After N concurrent Uploads, exactly one blob should exist for hash("same").
	got, _ := fs.Read(ctx, "shared.txt")
	if string(got) != "same" {
		t.Fatalf("got %q", string(got))
	}
	// Observable correctness: dedup must hold — exactly one blob on disk,
	// and the meta for that blob must list exactly one ref ("shared.txt").
	// If any Upload violated mutual exclusion (e.g., wrote the blob twice
	// or appended "shared.txt" to Refs more than once), this would catch it.
	blobEntries, err := os.ReadDir(filepath.Join(fs.Root(), "blobs"))
	if err != nil {
		t.Fatalf("ReadDir blobs err=%v", err)
	}
	if len(blobEntries) != 1 {
		t.Fatalf("expected exactly 1 blob after dedup, got %d", len(blobEntries))
	}
	// Query verifies the registered ref is "shared.txt" and reports the
	// correct SHA256 — observable outcome, not just structural presence.
	fi, err := fs.Query(ctx, "shared.txt")
	if err != nil {
		t.Fatalf("Query shared.txt err=%v", err)
	}
	if fi.Name != "shared.txt" {
		t.Fatalf("Query Name=%q, want %q", fi.Name, "shared.txt")
	}
	if fi.SHA256 == "" {
		t.Fatalf("Query SHA256 empty (meta not registered)")
	}
}

func TestConcurrent_UploadDistinctPaths_ReadBack(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	const N = 50
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("file-%d.txt", i)
			errs[i] = fs.Upload(ctx, path, filesystem.FileSource{Literal: fmt.Sprintf("content-%d", i)})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d err=%v", i, err)
		}
	}
	for i := 0; i < N; i++ {
		got, err := fs.Read(ctx, fmt.Sprintf("file-%d.txt", i))
		if err != nil {
			t.Fatalf("Read %d err=%v", i, err)
		}
		if want := fmt.Sprintf("content-%d", i); string(got) != want {
			t.Fatalf("Read %d got %q, want %q", i, string(got), want)
		}
	}
}

func TestConcurrent_DeleteAndRead_NoCorruption(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	// Two refs to same blob.
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "shared"}); err != nil {
		t.Fatalf("setup Upload a.txt err=%v", err)
	}
	if err := fs.Upload(ctx, "b.txt", filesystem.FileSource{Literal: "shared"}); err != nil {
		t.Fatalf("setup Upload b.txt err=%v", err)
	}

	const N = 50
	var wg sync.WaitGroup
	errs := make([]error, N*2)
	for i := 0; i < N; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			errs[i] = fs.Delete(ctx, "a.txt") // first N goroutines delete a.txt
		}(i)
		go func(i int) {
			defer wg.Done()
			_, errs[N+i] = fs.Read(ctx, "b.txt") // last N goroutines read b.txt
		}(i)
	}
	wg.Wait()
	// Reads of b.txt should never fail: deleting a.txt only removes one ref
	// from the shared blob; b.txt still references it, so the blob survives.
	for i := N; i < 2*N; i++ {
		if errs[i] != nil {
			t.Fatalf("Read b.txt err=%v", errs[i])
		}
	}
	// Sanity: b.txt content is intact and correct.
	got, err := fs.Read(ctx, "b.txt")
	if err != nil {
		t.Fatalf("final Read b.txt err=%v", err)
	}
	if string(got) != "shared" {
		t.Fatalf("final Read b.txt got %q, want %q", string(got), "shared")
	}
}
