package core_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func newCache(t *testing.T) (*core.PayloadCache, *filesystem.Filesystem) {
	t.Helper()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New err=%v", err)
	}
	return core.NewPayloadCache(fs), fs
}

func TestPayloadCache_Literal_HitAndMiss(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "hello"}

	b1, err := pc.GetOrLoad(ctx, src)
	if err != nil {
		t.Fatalf("GetOrLoad 1 err=%v", err)
	}
	b2, err := pc.GetOrLoad(ctx, src)
	if err != nil {
		t.Fatalf("GetOrLoad 2 err=%v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("b1 != b2: %q vs %q", string(b1), string(b2))
	}
	// Same backing memory — truly cached, not re-computed.
	if len(b1) == 0 {
		t.Fatalf("b1 is empty")
	}
	if &b1[0] != &b2[0] {
		t.Fatalf("b1 and b2 have different backing arrays — not cached")
	}
	entries, _ := pc.Stats()
	if entries != 1 {
		t.Fatalf("entries got %d, want 1", entries)
	}
}

func TestPayloadCache_File_HitsFilesystemRead(t *testing.T) {
	pc, fs := newCache(t)
	ctx := context.Background()
	fs.Upload(ctx, "shared.txt", filesystem.FileSource{Literal: "from fs"})

	b, err := pc.GetOrLoad(ctx, filesystem.FileSource{File: "shared.txt"})
	if err != nil {
		t.Fatalf("GetOrLoad err=%v", err)
	}
	if string(b) != "from fs" {
		t.Fatalf("got %q", string(b))
	}
}

func TestPayloadCache_Fill_Hit(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Fill: &filesystem.Fill{Byte: 0xCC, Bytes: 100}}
	b1, _ := pc.GetOrLoad(ctx, src)
	b2, _ := pc.GetOrLoad(ctx, src)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("fill should be cached identically")
	}
	entries, _ := pc.Stats()
	if entries != 1 {
		t.Fatalf("entries got %d, want 1", entries)
	}
}

func TestPayloadCache_RandomSeeded_Cached(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Random: &filesystem.Random{MinBytes: 64, MaxBytes: 64, Seed: 42}}
	b1, _ := pc.GetOrLoad(ctx, src)
	b2, _ := pc.GetOrLoad(ctx, src)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("seeded random should be cached identically")
	}
	entries, _ := pc.Stats()
	if entries != 1 {
		t.Fatalf("entries got %d, want 1 (seeded random is cached)", entries)
	}
}

func TestPayloadCache_RandomUnseeded_NotCached(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Random: &filesystem.Random{MinBytes: 64, MaxBytes: 64}}
	b1, _ := pc.GetOrLoad(ctx, src)
	b2, _ := pc.GetOrLoad(ctx, src)
	if bytes.Equal(b1, b2) {
		t.Fatalf("unseeded random should differ each call")
	}
	entries, _ := pc.Stats()
	if entries != 0 {
		t.Fatalf("entries got %d, want 0 (unseeded random is NOT cached)", entries)
	}
}

func TestPayloadCache_Fill_NegativeBytes_Errors(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Fill: &filesystem.Fill{Byte: 0xAA, Bytes: -1}}
	_, err := pc.GetOrLoad(ctx, src)
	if err == nil {
		t.Fatalf("expected error for negative Fill.Bytes, got nil")
	}
}

func TestPayloadCache_Concurrent_10kFlows_SameContent_OneEntry(t *testing.T) {
	pc, _ := newCache(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "shared"}

	const N = 1000 // smaller for -race CI
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = pc.GetOrLoad(ctx, src)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d err=%v", i, err)
		}
	}
	entries, _ := pc.Stats()
	if entries != 1 {
		t.Fatalf("entries got %d, want 1 (deduplication across goroutines)", entries)
	}
}
