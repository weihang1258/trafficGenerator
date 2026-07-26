package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// PayloadCache is the traffic-generator's in-process dedup cache for
// payload bytes. It is the only consumer of filesystem in the traffic
// generation path — it calls filesystem.Read when src.File is a relative
// path, or os.ReadFile when src.File is an absolute disk path. Cached
// []byte values are immutable; multiple PacketConfigs share the same
// slice without race.
//
// Cache rule (the user's explicit constraint):
//   - file, literal, fill, seeded-random: CACHE — same hash → one entry
//   - unseeded random: BYPASS — generate fresh bytes on every call,
//     never write to cache (would always miss and only pollute memory)
type PayloadCache struct {
	fs         *filesystem.Filesystem
	entries    sync.Map // hash(string) -> []byte (immutable after publish)
	totalBytes atomic.Int64
}

// payloadCacheKey is the context-key type used by the engine to inject
// a *PayloadCache into per-task ctx. The worker calls core.WithPayloadCache
// before invoking ProtocolPlanner.Plan; the 5 protocol planners that
// support FileSource (ftp, sip, sctp, http, icmp) call core.PayloadCacheFrom
// to read it back. Keeping the key type unexported is fine because both
// the writer (engine/worker) and the reader (planners) live outside the
// core package — they go through the exported WithPayloadCache /
// PayloadCacheFrom helpers, which is the canonical Go pattern for
// context-key encapsulation.
type payloadCacheKey struct{}

// WithPayloadCache returns a context carrying pc. The engine worker calls
// this once per task to inject the engine-level cache so planners can
// resolve FileSource payloads via PayloadCache.GetOrLoad.
func WithPayloadCache(ctx context.Context, pc *PayloadCache) context.Context {
	return context.WithValue(ctx, payloadCacheKey{}, pc)
}

// PayloadCacheFrom returns the cache injected by WithPayloadCache, or nil
// if none was set. Planners call this (NOT ctx.Value(payloadCacheKey{})
// directly) so the key type stays an opaque implementation detail of
// this package. A nil return means the engine didn't wire the cache —
// planners treat that as "FileSource cannot be resolved, skip emitting
// the affected chunk/message" rather than panicking.
func PayloadCacheFrom(ctx context.Context) *PayloadCache {
	pc, _ := ctx.Value(payloadCacheKey{}).(*PayloadCache)
	return pc
}

// NewPayloadCache returns a cache that uses fs for src.File resolution.
// fs may be nil — then src.File is treated as an absolute disk path
// (returns error if relative).
func NewPayloadCache(fs *filesystem.Filesystem) *PayloadCache {
	return &PayloadCache{fs: fs}
}

// GetOrLoad returns the bytes for src. For unseeded random, returns fresh
// bytes on every call without touching the cache. Returns ctx.Err() early
// when ctx is already canceled — saves CPU/IO during graceful shutdown.
func (c *PayloadCache) GetOrLoad(ctx context.Context, src filesystem.FileSource) ([]byte, error) {
	// Honor ctx cancellation before any work. The traffic-gen worker
	// calls GetOrLoad per-task; during graceful shutdown the ctx is
	// canceled, and proceeding would still resolve bytes + populate the
	// cache — wasting IO and memory after the operator asked to stop.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	// Rule: unseeded random bypasses the cache entirely.
	if src.Random != nil && src.Random.Seed == 0 {
		return filesystem.GenerateRandomBytes(src.Random)
	}

	b, err := c.resolveBytes(ctx, src)
	if err != nil {
		return nil, err
	}
	hash := hashHex(b)
	// LoadOrStore so totalBytes is incremented exactly once per unique hash.
	// Concurrent callers that race on the same hash will both compute b, but
	// only the first Store wins (stored=false for losers); the loser returns
	// the winner's []byte. Bytes are immutable after publish, so sharing is
	// race-free.
	actual, stored := c.entries.LoadOrStore(hash, b)
	if !stored {
		// We added a new entry — account for the bytes.
		c.totalBytes.Add(int64(len(b)))
	}
	return actual.([]byte), nil
}

// resolveBytes fetches/constructs the bytes for src (after the unseeded
// random bypass). File > Literal > Fill > Seeded Random.
func (c *PayloadCache) resolveBytes(ctx context.Context, src filesystem.FileSource) ([]byte, error) {
	switch {
	case src.File != "":
		if filepath.IsAbs(src.File) {
			// Absolute disk path — read directly.
			return os.ReadFile(src.File)
		}
		if c.fs == nil {
			return nil, errors.New("payloadcache: relative src.File but no filesystem configured")
		}
		return c.fs.Read(ctx, src.File)
	case src.Literal != "":
		return []byte(src.Literal), nil
	case src.Fill != nil:
		if src.Fill.Bytes < 0 {
			return nil, errors.New("payloadcache: Fill.Bytes must not be negative")
		}
		buf := make([]byte, src.Fill.Bytes)
		for i := range buf {
			buf[i] = src.Fill.Byte
		}
		return buf, nil
	case src.Random != nil && src.Random.Seed != 0:
		return filesystem.GenerateRandomBytes(src.Random)
	default:
		return nil, errors.New("payloadcache: FileSource has no source set")
	}
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Stats returns current cache size (entries, total bytes).
func (c *PayloadCache) Stats() (entries int, totalBytes int64) {
	c.entries.Range(func(_, _ interface{}) bool {
		entries++
		return true
	})
	return entries, c.totalBytes.Load()
}
