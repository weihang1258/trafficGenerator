package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestEngine_SetPayloadCache verifies the engine wiring for PayloadCache.
// The cache is injected at the engine level by the server (Task 13), and
// the worker reads it via Engine.PayloadCache() to inject into each
// task's ctx so planners can resolve FileSource payloads.
func TestEngine_SetPayloadCache(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{})
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	e.SetPayloadCache(pc)
	got := e.PayloadCache()
	if got != pc {
		t.Fatalf("PayloadCache got %p, want %p", got, pc)
	}
}

// TestWithPayloadCache_RoundTrip verifies the ctx-injection helper used
// by the worker (core.WithPayloadCache) and the planner-side reader
// (core.PayloadCacheFrom) agree on the key type. The 5 protocol planners
// (ftp, sip, sctp, http, icmp) call core.PayloadCacheFrom(ctx) — the
// engine worker must call core.WithPayloadCache(ctx, pc) for them to
// find the cache.
func TestWithPayloadCache_RoundTrip(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	got := core.PayloadCacheFrom(ctx)
	if got != pc {
		t.Fatalf("PayloadCacheFrom got %p, want %p", got, pc)
	}
}

// TestPayloadCacheFrom_NoCache verifies the reader returns nil (not a
// panic) when no cache was injected. Planners rely on this nil-check to
// skip FileSource resolution gracefully when running outside the engine
// (e.g. unit tests that forgot to inject).
func TestPayloadCacheFrom_NoCache(t *testing.T) {
	if got := core.PayloadCacheFrom(context.Background()); got != nil {
		t.Fatalf("PayloadCacheFrom on bare ctx got %p, want nil", got)
	}
}
