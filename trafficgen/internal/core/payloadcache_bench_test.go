package core_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// BenchmarkPayloadCache_10kFlows_SameContent proves memory dedup: 1000
// concurrent goroutines all asking for the same 64KB literal must collapse
// to exactly one cache entry (65536 total bytes). The post-bench assertion
// turns a pure metric report into a regression guard — if dedup breaks
// (e.g. each goroutine stores its own copy), the benchmark FAILS, not just
// reports a high entry count.
func BenchmarkPayloadCache_10kFlows_SameContent(b *testing.B) {
	fs, err := filesystem.New(b.TempDir())
	if err != nil {
		b.Fatalf("filesystem.New err=%v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}

	const N = 1000 // smaller for -race CI

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j := 0; j < N; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = pc.GetOrLoad(ctx, src)
			}()
		}
		wg.Wait()
	}
	b.StopTimer()

	entries, totalBytes := pc.Stats()
	b.ReportMetric(float64(entries), "entries")
	b.ReportMetric(float64(totalBytes), "bytes")
	if entries != 1 {
		b.Errorf("entries=%d, want 1 (dedup broken)", entries)
	}
	if totalBytes != 65536 {
		b.Errorf("totalBytes=%d, want 65536", totalBytes)
	}
}

// BenchmarkPayloadCache_10kFlows_CacheHit proves the hit path is fast:
// the cache is pre-loaded with one GetOrLoad call before the timed loop,
// so every b.N iteration's 1000 concurrent calls is a pure cache hit
// (no filesystem.Read / no os.ReadFile / no bytes.Copy on the hot path).
// Stats should still show entries=1 and bytes=65536.
func BenchmarkPayloadCache_10kFlows_CacheHit(b *testing.B) {
	fs, err := filesystem.New(b.TempDir())
	if err != nil {
		b.Fatalf("filesystem.New err=%v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}

	// Pre-load the cache so every timed call is a hit.
	if _, err := pc.GetOrLoad(ctx, src); err != nil {
		b.Fatalf("preload GetOrLoad err=%v", err)
	}

	const N = 1000 // smaller for -race CI

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j := 0; j < N; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = pc.GetOrLoad(ctx, src)
			}()
		}
		wg.Wait()
	}
	b.StopTimer()

	entries, totalBytes := pc.Stats()
	b.ReportMetric(float64(entries), "entries")
	b.ReportMetric(float64(totalBytes), "bytes")
	if entries != 1 {
		b.Errorf("entries=%d, want 1 (dedup broken on hit path)", entries)
	}
	if totalBytes != 65536 {
		b.Errorf("totalBytes=%d, want 65536", totalBytes)
	}
}
