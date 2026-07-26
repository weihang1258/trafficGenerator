package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestPayloadCache_GetOrLoad_RespectsCanceledCtx verifies the cache honors
// ctx.Err() at entry. Before the fix, GetOrLoad ignored ctx and would
// proceed to resolve bytes + populate cache even after the task was
// canceled — wasting CPU/IO during graceful shutdown. The fix adds an
// early select { case <-ctx.Done(): ... } at function entry so a canceled
// ctx short-circuits before any work.
//
// Test strategy: pre-cancel the ctx before calling GetOrLoad, then
// assert the call returns (nil, context.Canceled) AND the cache stays
// empty (no entry added). Without the entry check, a fix that returned
// early but still cached would pass — Stats() guards against that.
func TestPayloadCache_GetOrLoad_RespectsCanceledCtx(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel before any work

	// Use Literal so we don't depend on filesystem blocking behavior —
	// the entry-point ctx check must fire before resolveBytes is called.
	b, err := pc.GetOrLoad(ctx, filesystem.FileSource{Literal: "hello"})
	if err != context.Canceled {
		t.Fatalf("GetOrLoad on canceled ctx: err got %v, want context.Canceled", err)
	}
	if b != nil {
		t.Fatalf("GetOrLoad on canceled ctx: got bytes %v, want nil", b)
	}
	// The cache MUST stay empty — a fix that returns early but still
	// caches would silently keep growing memory during shutdown.
	entries, totalBytes := pc.Stats()
	if entries != 0 || totalBytes != 0 {
		t.Fatalf("cache polluted after canceled ctx: entries=%d totalBytes=%d, want 0/0",
			entries, totalBytes)
	}
}

// TestPayloadCache_GetOrLoad_RespectsCanceledCtx_AfterEntryVerifyHeader
// verifies the fix doesn't break the happy path: a non-canceled ctx still
// resolves and caches as before. This guards against a regression that
// flips the ctx check to always-return-err.
func TestPayloadCache_GetOrLoad_NormalCtx_StillWorks(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := context.Background()

	b, err := pc.GetOrLoad(ctx, filesystem.FileSource{Literal: "hello"})
	if err != nil {
		t.Fatalf("GetOrLoad on normal ctx: err %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("GetOrLoad got %q, want %q", string(b), "hello")
	}
	entries, _ := pc.Stats()
	if entries != 1 {
		t.Fatalf("cache entries got %d, want 1", entries)
	}
}
