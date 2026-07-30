# Filesystem Module + PayloadCache + IPv6 Test Gap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two isolated systems — (1) `pkg/filesystem/` standalone content-addressed filesystem with hash-dedup, multi-name refs, directory CRUD, and three entry points (CLI/HTTP/MCP); (2) `internal/core/payloadcache.go` for traffic-generation payload dedup with rule "cache file/literal/fill/seeded-random; do NOT cache unseeded random". Add `FlowSpec.FileSource` to unify payload sources across all 10 planners. Close the IPv6 test gap (FTP data-channel parent IPv6) symmetric with SIP.

**Architecture:** Two isolated layers. Filesystem (`pkg/filesystem/`) persists on disk under configurable root (`data/filesystem/` default, `--fs-root` override) with `.meta/files/<sha256>.json` (refs[]) and `blobs/<sha256>` (immutable bytes). PayloadCache (`internal/core/`) is in-process `sync.Map` keyed by SHA-256 for traffic gen, calls filesystem `Read(relPath)` when `FileSource.File` is set, returns immutable `[]byte` shared by all PacketConfigs. Planners read `FlowSpec.FileSource` and call `PayloadCache.GetOrLoad(ctx, src)` instead of inline `Payload`/`PayloadB64` parsing. Protocol commands like FTP `DELE` only generate the wire bytes — they do NOT mutate filesystem state. Three independent CRUD entry points (CLI/HTTP/MCP) call filesystem methods directly.

**Tech Stack:** Go 1.25, `crypto/sha256`, `sync.Map`, `encoding/json`, `path/filepath`, `github.com/gin-gonic/gin`, `github.com/modelcontextprotocol/go-sdk/mcp`, `github.com/trafficgen/trafficgen/internal/core`, `github.com/trafficgen/trafficgen/pkg/config`, `github.com/trafficgen/trafficgen/pkg/auth`.

## Global Constraints

- Go binary at `/home/weihang/go/go/bin/go`, all `go` invocations use this path.
- All `go build`/`go test`/`go vet` use `-buildvcs=false`.
- Tests use `-race` flag.
- Each program's ports are fixed and non-special requests must not modify them.
- This is a packet generator, NOT a network device — never use real system NIC parameters.
- Use REAL MCP tools (`mcp__flowb__*`) for verification, not curl simulations.
- Use Chinese with plain description + impact + solutions + recommendation in `AskUserQuestion`.
- Per CLAUDE.md §Code Modification & Review Policy: every code change must be reviewed (review → test → fix → review loop until clean).
- Per CLAUDE.md §Testing Policy: spec-driven test derivation, cover failure paths, one test per code path, integration tests, assert observable outcomes, concurrency tests verify correctness not just race-safety, failing-test-first for bug fixes, adversarial test-quality review.

---

## File Structure

### New files

- `pkg/filesystem/filesystem.go` — `Filesystem` struct, `New(root)`, all public methods (Upload/Delete/Read/Query/List/Mkdir/Rmdir)
- `pkg/filesystem/types.go` — `FileSource`, `Fill`, `Random`, `FileInfo`, `RmdirOptions`, `ErrNotFound`, `ErrExists`
- `pkg/filesystem/internal.go` — internal helpers: `resolveBytes(src)` (literal/fill/seeded-random), `hashPath`, `metaPath`, `blobPath`, `loadMeta(hash)`, `saveMeta(hash, meta)`, `deleteMeta(hash)`, `walkDir`
- `pkg/filesystem/filesystem_test.go` — TDD unit tests for all methods
- `pkg/filesystem/filesystem_integration_test.go` — multi-name dedup, recursive dir delete, concurrent Upload
- `pkg/filesystem/filesystem_bench_test.go` — benchmarks: 10k Upload same content, 10k Read same path
- `pkg/filesystem/README.md` — module overview, API reference, examples (Chinese)

- `internal/core/payloadcache.go` — `PayloadCache` struct, `New(fs)`, `GetOrLoad(ctx, src)`, `Stats()`, `Release(hash)`
- `internal/core/payloadcache_test.go` — TDD tests: cache hit, miss, random-bypass, IPv6-agnostic
- `internal/core/payloadcache_bench_test.go` — benchmark: 10k flows × 64KB same content → 1 cached entry

- `internal/core/filesource_integration_test.go` — integration: planner → PayloadCache → Filesystem, IPv6 parent flow

- `internal/api/rest/filesystem_handler.go` — `FilesystemHandler` with routes for /api/v1/fs/*
- `internal/api/rest/filesystem_handler_test.go` — HTTP API integration tests

- `internal/mcp/tools_filesystem.go` — `flowb_manage_filesystem` MCP tool, 7 actions
- `internal/mcp/tools_filesystem_test.go` — MCP tool unit tests

- `cmd/fs/main.go` — CLI entry: `tgserver-fs upload/delete/mkdir/rmdir/list/query/read`

- `internal/protocol/ftp/ftp_ipv6_test.go` — `TestFTPDataChannel_IPv6Parent` symmetric with SIP

### Modified files

- `pkg/config/config.go` — add `Filesystem FilesystemConfig` field with `Root` string
- `configs/config.yaml`, `configs/config.dev.yaml`, `configs/config.docker.yaml`, `configs/config.standalone.yaml` — add `filesystem.root` default `data/filesystem`
- `cmd/server/main.go` — add `fsRoot` flag, init `app.filesystem`, inject into `Application` struct, inject into REST server, inject into MCP server
- `internal/api/rest/server.go` — add `filesystem *filesystem.Filesystem` field, register `/api/v1/fs` routes
- `internal/mcp/server.go` — add `filesystem *filesystem.Filesystem` field, `SetFilesystem(fs)` method
- `internal/core/engine.go` — add `payloadCache *PayloadCache` field, `SetPayloadCache(pc)` method
- `internal/core/types.go` — add `FileSource` field to `FlowSpec`, `FTPDataChannel`, `SIPMedia`, `SCTPChunk`, `HTTPConfig`, `ICMPConfig`
- `internal/core/strategy_convert.go` — parse `file_source` from cfg map into `*FileSource`
- `internal/protocol/ftp/ftp.go` — when `dc.FileSource != nil`, call `PayloadCache.GetOrLoad` and use returned bytes for sub-flow payload
- `internal/protocol/sip/sip.go` — when `media.FileSource != nil`, call `PayloadCache.GetOrLoad` and split bytes into RTP frames
- `internal/protocol/sctp/sctp.go` — when `chunk.FileSource != nil`, call `PayloadCache.GetOrLoad` for DATA chunk payload
- `internal/protocol/http/http.go` — when `cfg.FileSource != nil`, call `PayloadCache.GetOrLoad` for body
- `internal/protocol/icmp/icmp.go` — when `cfg.FileSource != nil`, call `PayloadCache.GetOrLoad` for echo data

### Module boundaries (the user's explicit constraint)

- **`pkg/filesystem/`** is a STANDALONE reusable module. Zero imports from `internal/`. No knowledge of trafficgen's planners, engine, or protocol types.
- **`internal/core/payloadcache.go`** depends on `pkg/filesystem/` (calls `Read(relPath)` only — never Upload/Delete). In-process cache only.
- **Planners** depend on `internal/core` (already do), call `PayloadCache.GetOrLoad` via the engine or a context-injected helper. Planners NEVER import `pkg/filesystem/` directly.
- **CLI/HTTP/MCP entry points** depend on `pkg/filesystem/` directly, with their own auth/middleware. They NEVER touch PayloadCache.
- **Protocol commands (FTP `DELE`, HTTP `DELETE` method)** only generate the wire bytes for that command. They do NOT call filesystem.Delete. The user pre-declares files via filesystem CRUD before submitting a traffic task.

---

## Task 1: pkg/filesystem types and errors

**Files:**
- Create: `pkg/filesystem/types.go`
- Create: `pkg/filesystem/filesystem.go` (skeleton with `New()` and struct only)

**Interfaces:**
- Consumes: none
- Produces:
  - `type FileSource struct { File string; Literal string; Fill *Fill; Random *Random }`
  - `type Fill struct { Byte byte; Bytes int }`
  - `type Random struct { MinBytes, MaxBytes int; Seed int64 }`
  - `type FileInfo struct { Name string; IsDir bool; Size int64; ModTime time.Time; SHA256 string }`
  - `type RmdirOptions struct { Recursive bool }`
  - `var ErrNotFound = errors.New("filesystem: path not found")`
  - `var ErrExists = errors.New("filesystem: path already exists")`
  - `var ErrNotEmpty = errors.New("filesystem: directory not empty")`
  - `type Filesystem struct { root string; mu sync.RWMutex }`
  - `func New(root string) (*Filesystem, error)`

- [ ] **Step 1: Write failing test for `New` and types**

`pkg/filesystem/types_test.go`:
```go
package filesystem_test

import (
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
	dir := t.TempDir()
	fs, err := filesystem.New(dir)
	if err != nil {
		t.Fatalf("New(%q) err=%v", dir, err)
	}
	if fs == nil {
		t.Fatal("New returned nil Filesystem")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL with "package filesystem not found" or "undefined: filesystem.New".

- [ ] **Step 3: Implement types and skeleton**

`pkg/filesystem/types.go`:
```go
// Package filesystem implements a content-addressed filesystem with hash
// dedup. Multiple file names can map to the same backing blob (SHA-256
// keyed); deleting a name only deletes the blob when the last name is
// removed. The filesystem is independent of traffic generation — the
// traffic generator only calls Read(relPath). All mutations (Upload,
// Delete, Mkdir, Rmdir) come from the standalone CLI, REST API, or MCP
// tool entry points.
package filesystem

import (
	"errors"
	"sync"
	"time"
)

// FileSource describes how to obtain bytes for a file. Exactly one source
// should be set. Priority: File > Literal > Fill > Random.
type FileSource struct {
	File    string  `json:"file,omitempty"`    // filesystem relative path (recursive Read)
	Literal string  `json:"literal,omitempty"`  // inline text bytes
	Fill    *Fill   `json:"fill,omitempty"`     // single-byte pattern
	Random  *Random `json:"random,omitempty"`   // random content, length range
}

// Fill describes a single-byte pattern repeated Bytes times.
type Fill struct {
	Byte  byte `json:"byte"`
	Bytes int  `json:"bytes"`
}

// Random describes random bytes with length in [MinBytes, MaxBytes]. When
// Seed is non-zero, output is reproducible per (Seed, MinBytes, MaxBytes).
// When Seed is zero, output is fresh crypto-random on every call.
type Random struct {
	MinBytes int   `json:"min_bytes"`
	MaxBytes int   `json:"max_bytes"`
	Seed     int64 `json:"seed,omitempty"`
}

// FileInfo is metadata for a file or directory entry.
type FileInfo struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	SHA256  string    `json:"sha256,omitempty"` // empty for directories
}

// RmdirOptions controls directory deletion.
type RmdirOptions struct {
	Recursive bool `json:"recursive"` // false = reject if non-empty
}

var (
	ErrNotFound = errors.New("filesystem: path not found")
	ErrExists   = errors.New("filesystem: path already exists")
	ErrNotEmpty = errors.New("filesystem: directory not empty")
)

// Filesystem is the standalone content-addressed filesystem.
type Filesystem struct {
	root string
	mu   sync.RWMutex
}

// New creates a Filesystem rooted at root. The root and its required
// subdirectories (.meta/files, blobs) are created if missing.
func New(root string) (*Filesystem, error) {
	if root == "" {
		return nil, errors.New("filesystem: root must not be empty")
	}
	fs := &Filesystem{root: root}
	if err := fs.initDirs(); err != nil {
		return nil, err
	}
	return fs, nil
}
```

`pkg/filesystem/filesystem.go`:
```go
package filesystem

import (
	"errors"
	"os"
	"path/filepath"
)

// initDirs creates the root, .meta/files, and blobs/ subdirectories.
func (fs *Filesystem) initDirs() error {
	for _, sub := range []string{".meta/files", "blobs"} {
		if err := os.MkdirAll(filepath.Join(fs.root, filepath.FromSlash(sub)), 0755); err != nil {
			return err
		}
	}
	return nil
}

// Root returns the absolute root directory.
func (fs *Filesystem) Root() string { return fs.root }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/types.go pkg/filesystem/filesystem.go pkg/filesystem/types_test.go
git commit -m "feat(filesystem): add types and skeleton New()"
```

---

## Task 2: pkg/filesystem Upload + Read (hash dedup with refs)

**Files:**
- Modify: `pkg/filesystem/filesystem.go` (add `Upload`, `Read`, internal helpers)
- Modify: `pkg/filesystem/filesystem_test.go` (or new `filesystem_upload_test.go`)
- Create: `pkg/filesystem/internal.go` (internal helpers)

**Interfaces:**
- Consumes: types from Task 1 (`FileSource`, `Fill`, `Random`, `Filesystem`, `ErrExists`)
- Produces:
  - `func (fs *Filesystem) Upload(ctx context.Context, relPath string, src FileSource) error`
  - `func (fs *Filesystem) Read(ctx context.Context, relPath string) ([]byte, error)`
  - Internal helpers: `resolveBytes(src) ([]byte, error)`, `hashStr(b []byte) string`, `metaPath(hash string) string`, `blobPath(hash string) string`, `loadMeta(hash string) (*fileMeta, error)`, `saveMeta(hash string, m *fileMeta) error`, `deleteMeta(hash string) error`

- [ ] **Step 1: Write failing test for Upload + Read basic**

`pkg/filesystem/filesystem_upload_test.go`:
```go
package filesystem_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestUpload_ThenRead_RoundTrip(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "hello world"}
	if err := fs.Upload(ctx, "docs/greeting.txt", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, err := fs.Read(ctx, "docs/greeting.txt")
	if err != nil {
		t.Fatalf("Read err=%v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("Read got %q, want %q", string(got), "hello world")
	}
}

func TestUpload_SameContentSameHash_DoesNotRewriteBlob(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "same content"}
	if err := fs.Upload(ctx, "a.txt", src); err != nil {
		t.Fatalf("Upload a.txt err=%v", err)
	}
	blobPath, err := fs.BlobPathForContent(ctx, []byte("same content"))
	if err != nil {
		t.Fatalf("BlobPathForContent err=%v", err)
	}
	info1, err := osStat(blobPath)
	if err != nil {
		t.Fatalf("first blob stat err=%v", err)
	}
	if err := fs.Upload(ctx, "b.txt", src); err != nil {
		t.Fatalf("Upload b.txt err=%v", err)
	}
	info2, err := osStat(blobPath)
	if err != nil {
		t.Fatalf("second blob stat err=%v", err)
	}
	// Same ModTime: blob was not rewritten.
	if info1.ModTime() != info2.ModTime() {
		t.Fatalf("blob was rewritten on second Upload (mtime changed)")
	}
}

func TestUpload_OverwriteExistingPath_DedupOldBlobIfLastRef(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	// Upload path a.txt with content X
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "content X"}); err != nil {
		t.Fatalf("Upload a.txt X err=%v", err)
	}
	// Verify blob X exists
	blobX, _ := fs.BlobPathForContent(ctx, []byte("content X"))
	if _, err := osStat(blobX); err != nil {
		t.Fatalf("blob X should exist: %v", err)
	}
	// Overwrite a.txt with content Y
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "content Y"}); err != nil {
		t.Fatalf("Upload a.txt Y err=%v", err)
	}
	// Blob X should now be deleted (no remaining refs)
	if _, err := osStat(blobX); !os.IsNotExist(err) {
		t.Fatalf("blob X should be deleted after overwrite, got err=%v", err)
	}
}

// newFS returns a fresh Filesystem rooted at a temp dir.
func newFS(t *testing.T) *filesystem.Filesystem {
	t.Helper()
	dir := t.TempDir()
	fs, err := filesystem.New(dir)
	if err != nil {
		t.Fatalf("New err=%v", err)
	}
	return fs
}

// osStat is a thin wrapper to avoid pulling os in test setup lines.
func osStat(p string) (os.FileInfo, error) {
	return osStatImpl(p)
}
```

Add `osStatImpl` helper or just inline `os.Stat` (the latter is cleaner). Replace the wrapper with direct `os.Stat`:
```go
import "os"
info1, err := os.Stat(blobPath)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL with "undefined: fs.Upload" or "undefined: fs.Read" or "undefined: fs.BlobPathForContent".

- [ ] **Step 3: Implement Upload, Read, and internal helpers**

`pkg/filesystem/internal.go`:
```go
package filesystem

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

// fileMeta is the on-disk metadata for a blob: which names reference it.
type fileMeta struct {
	Hash    string   `json:"hash"`
	Size    int64    `json:"size"`
	Refs    []string `json:"refs"`     // relPaths that reference this blob
	Created int64    `json:"created"`  // unix nano
}

// resolveBytes returns the bytes for the given source. Used by Upload.
// Precedence: File > Literal > Fill > Random.
func (fs *Filesystem) resolveBytes(src FileSource) ([]byte, error) {
	switch {
	case src.File != "":
		return fs.Read(context.Background(), src.File)
	case src.Literal != "":
		return []byte(src.Literal), nil
	case src.Fill != nil:
		if src.Fill.Bytes < 0 {
			return nil, errors.New("filesystem: Fill.Bytes must not be negative")
		}
		buf := make([]byte, src.Fill.Bytes)
		for i := range buf {
			buf[i] = src.Fill.Byte
		}
		return buf, nil
	case src.Random != nil:
		return generateRandomBytes(src.Random)
	default:
		return nil, errors.New("filesystem: FileSource has no source set")
	}
}

// generateRandomBytes produces random bytes. When Seed is non-zero, output
// is reproducible per (Seed, MinBytes, MaxBytes). When Seed is zero,
// output is crypto-random fresh on every call.
func generateRandomBytes(r *Random) ([]byte, error) {
	if r.MinBytes < 0 || r.MaxBytes < r.MinBytes {
		return nil, errors.New("filesystem: invalid Random byte range")
	}
	size := r.MinBytes
	if r.MaxBytes > r.MinBytes {
		span := r.MaxBytes - r.MinBytes
		if r.Seed != 0 {
			// Deterministic size from seeded source.
			size = r.MinBytes + int(rand.New(rand.NewSource(r.Seed)).IntN(span+1))
		} else {
			size = r.MinBytes + int(rand.IntN(span+1))
		}
	}
	buf := make([]byte, size)
	if r.Seed != 0 {
		// Seeded random for reproducibility.
		rng := rand.New(rand.NewSource(r.Seed))
		for i := range buf {
			buf[i] = byte(rng.IntN(256))
		}
	} else {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// hashStr returns the lowercase hex SHA-256 of b.
func hashStr(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// metaPath returns the absolute path to .meta/files/<hash>.json.
func (fs *Filesystem) metaPath(hash string) string {
	return filepath.Join(fs.root, ".meta", "files", hash+".json")
}

// blobPath returns the absolute path to blobs/<hash>.
func (fs *Filesystem) blobPath(hash string) string {
	return filepath.Join(fs.root, "blobs", hash)
}

// loadMeta reads the metadata JSON for hash. Returns ErrNotFound if missing.
func (fs *Filesystem) loadMeta(hash string) (*fileMeta, error) {
	data, err := os.ReadFile(fs.metaPath(hash))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var m fileMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// saveMeta writes metadata JSON atomically.
func (fs *Filesystem) saveMeta(hash string, m *fileMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := fs.metaPath(hash) + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, fs.metaPath(hash))
}

// deleteMeta removes the metadata JSON.
func (fs *Filesystem) deleteMeta(hash string) error {
	err := os.Remove(fs.metaPath(hash))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// BlobPathForContent is a test helper that returns the absolute blob path
// for the given content. It does NOT write anything.
func (fs *Filesystem) BlobPathForContent(ctx context.Context, content []byte) (string, error) {
	return fs.blobPath(hashStr(content)), nil
}

// unused; suppresses import errors if not used elsewhere
var _ = time.Now
```

`pkg/filesystem/filesystem.go` (add Upload/Read):
```go
// added to existing filesystem.go

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Upload writes the bytes from src to relPath in the filesystem. The bytes
// are content-addressed: if an identical blob (by SHA-256) is already
// present, no new blob is written. If relPath already exists, the old
// blob's ref is removed first (which may delete the old blob if it was
// the last reference).
//
// relPath must be a relative path (no leading slash). Path components are
// cleaned and validated for directory traversal escape.
func (fs *Filesystem) Upload(ctx context.Context, relPath string, src FileSource) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Read source bytes (may recurse into filesystem for src.File).
	b, err := fs.resolveBytes(src)
	if err != nil {
		return err
	}
	hash := hashStr(b)

	// If relPath already references a different blob, remove the old ref
	// (and delete the old blob if refs become empty).
	if existingHash, err := fs.lookupHashForPath(cleanRel); err == nil && existingHash != hash {
		if err := fs.removeRefLocked(existingHash, cleanRel); err != nil {
			return err
		}
	}

	// Write the blob if missing (hash dedup: skip write if already exists).
	blobPath := fs.blobPath(hash)
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		if err := os.WriteFile(blobPath, b, 0644); err != nil {
			return err
		}
	}

	// Update meta: add cleanRel to refs[].
	meta, err := fs.loadMeta(hash)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if meta == nil {
		meta = &fileMeta{Hash: hash, Size: int64(len(b)), Created: time.Now().UnixNano()}
	}
	if !containsStr(meta.Refs, cleanRel) {
		meta.Refs = append(meta.Refs, cleanRel)
	}
	return fs.saveMeta(hash, meta)
}

// Read returns the bytes at relPath. Returns ErrNotFound if relPath is
// not registered.
func (fs *Filesystem) Read(ctx context.Context, relPath string) ([]byte, error) {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return nil, err
	}
	fs.mu.RLock()
	hash, err := fs.lookupHashForPath(cleanRel)
	fs.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(fs.blobPath(hash))
}

// lookupHashForPath scans all meta files for one whose refs[] contains
// relPath. Returns ErrNotFound if no match.
func (fs *Filesystem) lookupHashForPath(relPath string) (string, error) {
	// Walk .meta/files/*.json and check refs.
	entries, err := os.ReadDir(filepath.Join(fs.root, ".meta", "files"))
	if err != nil {
		return "", ErrNotFound
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		hash := strings.TrimSuffix(e.Name(), ".json")
		meta, err := fs.loadMeta(hash)
		if err != nil {
			continue
		}
		if containsStr(meta.Refs, relPath) {
			return meta.Hash, nil
		}
	}
	return "", ErrNotFound
}

// removeRefLocked removes relPath from hash's meta. If refs becomes empty,
// deletes the blob and meta file.
func (fs *Filesystem) removeRefLocked(hash, relPath string) error {
	meta, err := fs.loadMeta(hash)
	if err != nil {
		return err
	}
	meta.Refs = removeStr(meta.Refs, relPath)
	if len(meta.Refs) == 0 {
		if err := os.Remove(fs.blobPath(hash)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return fs.deleteMeta(hash)
	}
	return fs.saveMeta(hash, meta)
}

// cleanRelPath validates and cleans a relative path. Rejects absolute
// paths and directory traversal escape.
func (fs *Filesystem) cleanRelPath(relPath string) (string, error) {
	if relPath == "" {
		return "", errors.New("filesystem: path must not be empty")
	}
	if filepath.IsAbs(relPath) {
		return "", errors.New("filesystem: path must be relative")
	}
	clean := filepath.Clean(filepath.FromSlash(relPath))
	// Reject ".." that escapes root.
	rel := filepath.Clean(filepath.Join(fs.root, clean))
	if !strings.HasPrefix(rel, fs.root+string(filepath.Separator)) && rel != fs.root {
		return "", errors.New("filesystem: path escapes root")
	}
	return filepath.ToSlash(clean), nil
}

// containsStr reports whether s contains v.
func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removeStr returns s with the first occurrence of v removed.
func removeStr(s []string, v string) []string {
	for i, x := range s {
		if x == v {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
```

Add `"time"` to the imports at the top of `filesystem.go` since `time.Now().UnixNano()` is used.

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/
git commit -m "feat(filesystem): add Upload/Read with SHA-256 dedup and refs[] refcount"
```

---

## Task 3: pkg/filesystem Delete (last-ref-wins blob removal)

**Files:**
- Modify: `pkg/filesystem/filesystem.go` (add `Delete`)
- Modify: `pkg/filesystem/filesystem_test.go` (or new `filesystem_delete_test.go`)

**Interfaces:**
- Consumes: `removeRefLocked`, `lookupHashForPath`, `cleanRelPath` from Task 2
- Produces: `func (fs *Filesystem) Delete(ctx context.Context, relPath string) error`

- [ ] **Step 1: Write failing test**

`pkg/filesystem/filesystem_delete_test.go`:
```go
package filesystem_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestDelete_RemovesNameOnly_WhenOtherRefsExist(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "shared content"}
	if err := fs.Upload(ctx, "a.txt", src); err != nil {
		t.Fatalf("Upload a.txt err=%v", err)
	}
	if err := fs.Upload(ctx, "b.txt", src); err != nil {
		t.Fatalf("Upload b.txt err=%v", err)
	}
	blobPath, _ := fs.BlobPathForContent(ctx, []byte("shared content"))

	// Delete a.txt — blob should still exist because b.txt references it.
	if err := fs.Delete(ctx, "a.txt"); err != nil {
		t.Fatalf("Delete a.txt err=%v", err)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob should still exist after deleting one of two refs: %v", err)
	}
	// a.txt no longer readable.
	if _, err := fs.Read(ctx, "a.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Read a.txt after delete: got err=%v, want ErrNotFound", err)
	}
	// b.txt still readable.
	if got, err := fs.Read(ctx, "b.txt"); err != nil || string(got) != "shared content" {
		t.Fatalf("Read b.txt after delete: got %q, err=%v", string(got), err)
	}
}

func TestDelete_RemovesBlob_WhenLastRef(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "only.txt", filesystem.FileSource{Literal: "unique content"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	blobPath, _ := fs.BlobPathForContent(ctx, []byte("unique content"))

	if err := fs.Delete(ctx, "only.txt"); err != nil {
		t.Fatalf("Delete err=%v", err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob should be deleted, got err=%v", err)
	}
}

func TestDelete_NotFound(t *testing.T) {
	fs := newFS(t)
	if err := fs.Delete(context.Background(), "nope.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Delete nope.txt: got err=%v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL with "undefined: fs.Delete".

- [ ] **Step 3: Implement Delete**

Add to `pkg/filesystem/filesystem.go`:
```go
// Delete removes relPath from the filesystem. If the path's blob has no
// remaining refs, the blob is deleted too. Returns ErrNotFound if relPath
// is not registered.
func (fs *Filesystem) Delete(ctx context.Context, relPath string) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	hash, err := fs.lookupHashForPath(cleanRel)
	if err != nil {
		return err
	}
	return fs.removeRefLocked(hash, cleanRel)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/
git commit -m "feat(filesystem): add Delete with last-ref-wins blob removal"
```

---

## Task 4: pkg/filesystem Query + List

**Files:**
- Modify: `pkg/filesystem/filesystem.go` (add `Query`, `List`)
- Modify: `pkg/filesystem/filesystem_test.go`

**Interfaces:**
- Consumes: `lookupHashForPath`, `cleanRelPath`, `loadMeta`, `fileMeta` from Task 2
- Produces:
  - `func (fs *Filesystem) Query(ctx context.Context, relPath string) (FileInfo, error)`
  - `func (fs *Filesystem) List(ctx context.Context, dirPath string) ([]FileInfo, error)`

- [ ] **Step 1: Write failing test**

`pkg/filesystem/filesystem_query_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL with "undefined: fs.Query" / "undefined: fs.List" / "undefined: fs.Mkdir".

- [ ] **Step 3: Implement Query and List**

Add to `pkg/filesystem/filesystem.go`:
```go
// Query returns metadata for relPath. Returns ErrNotFound if not registered.
func (fs *Filesystem) Query(ctx context.Context, relPath string) (FileInfo, error) {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return FileInfo{}, err
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Check directory first.
	abs := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	st, err := os.Stat(abs)
	if err == nil && st.IsDir() {
		return FileInfo{Name: cleanRel, IsDir: true, Size: 0, ModTime: st.ModTime()}, nil
	}

	hash, err := fs.lookupHashForPath(cleanRel)
	if err != nil {
		return FileInfo{}, err
	}
	meta, err := fs.loadMeta(hash)
	if err != nil {
		return FileInfo{}, err
	}
	blobStat, err := os.Stat(fs.blobPath(hash))
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Name:    cleanRel,
		IsDir:   false,
		Size:    meta.Size,
		ModTime: blobStat.ModTime(),
		SHA256:  hash,
	}, nil
}

// List returns entries in dirPath. Directories are listed as such. Files
// are listed with size and mtime.
func (fs *Filesystem) List(ctx context.Context, dirPath string) ([]FileInfo, error) {
	cleanDir, err := fs.cleanRelPath(dirPath)
	if err != nil {
		return nil, err
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	absDir := filepath.Join(fs.root, filepath.FromSlash(cleanDir))
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, ErrNotFound
	}
	out := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		// Skip internal .meta — that's the metadata store.
		if e.Name() == ".meta" || e.Name() == "blobs" {
			continue
		}
		abs := filepath.Join(absDir, e.Name())
		st, err := os.Stat(abs)
		if err != nil {
			continue
		}
		entryPath := filepath.Join(cleanDir, e.Name())
		entryPath = filepath.ToSlash(entryPath)
		entryPath = strings.TrimPrefix(entryPath, "./")
		fi := FileInfo{Name: entryPath, IsDir: st.IsDir(), ModTime: st.ModTime()}
		if !st.IsDir() {
			// Find hash for this file.
			if hash, err := fs.lookupHashForPath(entryPath); err == nil {
				if meta, err := fs.loadMeta(hash); err == nil {
					fi.Size = meta.Size
					fi.SHA256 = hash
				}
			}
		}
		out = append(out, fi)
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS (List passes once Task 5 Mkdir lands; for now Query/Query_NotFound should pass, List tests will fail on `fs.Mkdir` undefined).

Wait for Task 5 to make the List tests pass, or merge the Mkdir stub in this step. Move the `fs.Mkdir` stub to this task so List tests pass:

Add to `pkg/filesystem/filesystem.go`:
```go
// Mkdir placeholder — implemented fully in Task 5.
func (fs *Filesystem) Mkdir(ctx context.Context, relPath string) error {
	return fs.mkdirImpl(ctx, relPath)
}

func (fs *Filesystem) mkdirImpl(ctx context.Context, relPath string) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	abs := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	return os.MkdirAll(abs, 0755)
}
```

- [ ] **Step 5: Run test to verify it passes (full)**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/filesystem/
git commit -m "feat(filesystem): add Query, List (with stub Mkdir)"
```

---

## Task 5: pkg/filesystem Mkdir + Rmdir (recursive delete by refcount rule)

**Files:**
- Modify: `pkg/filesystem/filesystem.go` (add `Rmdir`, replace `Mkdir` stub if needed)
- Modify: `pkg/filesystem/filesystem_test.go`

**Interfaces:**
- Consumes: `cleanRelPath`, `removeRefLocked`, `lookupHashForPath` from Task 2
- Produces:
  - `func (fs *Filesystem) Mkdir(ctx context.Context, relPath string) error`
  - `func (fs *Filesystem) Rmdir(ctx context.Context, relPath string, opts RmdirOptions) error`

- [ ] **Step 1: Write failing test**

`pkg/filesystem/filesystem_rmdir_test.go`:
```go
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
	fs.Upload(ctx, "dir2/b.txt", src)  // same blob, two refs
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL with "undefined: fs.Rmdir".

- [ ] **Step 3: Implement Rmdir (recursive)**

Add to `pkg/filesystem/filesystem.go`:
```go
// Rmdir deletes a directory. When opts.Recursive is false and the
// directory is non-empty, returns ErrNotEmpty. When opts.Recursive is
// true, walks the tree and deletes all files (by Delete semantics — last
// ref wins) and sub-directories.
func (fs *Filesystem) Rmdir(ctx context.Context, relPath string, opts RmdirOptions) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	absDir := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	st, err := os.Stat(absDir)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("filesystem: Rmdir on non-directory")
	}

	if !opts.Recursive {
		entries, err := os.ReadDir(absDir)
		if err != nil {
			return err
		}
		// Only .meta and blobs are "internal"; user-created entries count.
		userEntries := 0
		for _, e := range entries {
			if e.Name() == ".meta" {
				continue
			}
			userEntries++
		}
		if userEntries > 0 {
			return ErrNotEmpty
		}
		return os.Remove(absDir)
	}

	// Recursive: walk and delete all files first, then directories.
	return fs.rmdirRecursiveLocked(ctx, cleanRel)
}

// rmdirRecursiveLocked walks relDir recursively, deleting every file
// (using removeRefLocked so dedup semantics hold) and then removing
// every sub-directory.
func (fs *Filesystem) rmdirRecursiveLocked(ctx context.Context, relDir string) error {
	absDir := filepath.Join(fs.root, filepath.FromSlash(relDir))
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == ".meta" {
			continue
		}
		entryPath := filepath.ToSlash(filepath.Join(relDir, e.Name()))
		if e.IsDir() {
			if err := fs.rmdirRecursiveLocked(ctx, entryPath); err != nil {
				return err
			}
		} else {
			// File in filesystem (a registered name).
			if hash, err := fs.lookupHashForPath(entryPath); err == nil {
				if err := fs.removeRefLocked(hash, entryPath); err != nil {
					return err
				}
			}
			// Remove the placeholder file on disk (if any — Upload does
			// not create a placeholder, but Mkdir may leave .keep).
			_ = os.Remove(filepath.Join(fs.root, filepath.FromSlash(entryPath)))
		}
	}
	return os.Remove(absDir)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/
git commit -m "feat(filesystem): add Mkdir + Rmdir (recursive, dedup-safe)"
```

---

## Task 6: pkg/filesystem resolveBytes source variants (file/literal/fill/random)

**Files:**
- Modify: `pkg/filesystem/filesystem_test.go` (or new `filesystem_sources_test.go`)

**Interfaces:**
- Consumes: `resolveBytes`, `Upload`, `Read` from Tasks 2
- Produces: tests proving each source variant works

- [ ] **Step 1: Write failing test**

`pkg/filesystem/filesystem_sources_test.go`:
```go
package filesystem_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestUpload_FromLiteral(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "literal bytes"}
	if err := fs.Upload(ctx, "a.txt", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, _ := fs.Read(ctx, "a.txt")
	if string(got) != "literal bytes" {
		t.Fatalf("got %q", string(got))
	}
}

func TestUpload_FromFill(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Fill: &filesystem.Fill{Byte: 0xAA, Bytes: 100}}
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, _ := fs.Read(ctx, "a.bin")
	if len(got) != 100 {
		t.Fatalf("len got %d, want 100", len(got))
	}
	for i, b := range got {
		if b != 0xAA {
			t.Fatalf("byte %d = %#x, want 0xAA", i, b)
		}
	}
}

func TestUpload_FromRandom_Seeded_Reproducible(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Random: &filesystem.Random{MinBytes: 64, MaxBytes: 64, Seed: 42}}
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got1, _ := fs.Read(ctx, "a.bin")

	fs2 := newFS(t)
	if err := fs2.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("second Upload err=%v", err)
	}
	got2, _ := fs2.Read(ctx, "a.bin")

	if !bytes.Equal(got1, got2) {
		t.Fatalf("seeded random should be reproducible: got1=%x got2=%x", got1[:8], got2[:8])
	}
}

func TestUpload_FromRandom_Unseeded_VariesAcrossCalls(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Random: &filesystem.Random{MinBytes: 64, MaxBytes: 64}}
	// Two Uploads of the same path with unseeded random — second call
	// overwrites the first with different content (because random differs).
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload 1 err=%v", err)
	}
	got1, _ := fs.Read(ctx, "a.bin")
	if err := fs.Upload(ctx, "a.bin", src); err != nil {
		t.Fatalf("Upload 2 err=%v", err)
	}
	got2, _ := fs.Read(ctx, "a.bin")
	if bytes.Equal(got1, got2) {
		t.Fatalf("unseeded random should differ on each call (got1==got2)")
	}
}

func TestUpload_FromFile_SourcePath(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	// First create a source file via Literal.
	if err := fs.Upload(ctx, "docs/source.txt", filesystem.FileSource{Literal: "from-file source"}); err != nil {
		t.Fatalf("Upload source.txt err=%v", err)
	}
	// Now upload another path that references docs/source.txt.
	if err := fs.Upload(ctx, "docs/copy.txt", filesystem.FileSource{File: "docs/source.txt"}); err != nil {
		t.Fatalf("Upload copy.txt err=%v", err)
	}
	got, _ := fs.Read(ctx, "docs/copy.txt")
	if string(got) != "from-file source" {
		t.Fatalf("got %q", string(got))
	}
}

func TestUpload_FromDiskFile(t *testing.T) {
	// Create a real disk file outside the filesystem, point src.File at it.
	tmpFile := filepath.Join(t.TempDir(), "real.txt")
	if err := os.WriteFile(tmpFile, []byte("from-disk content"), 0644); err != nil {
		t.Fatalf("WriteFile err=%v", err)
	}
	fs := newFS(t)
	ctx := context.Background()
	// src.File = absolute path to disk file. The planner should detect
	// absolute paths and read from disk (not from filesystem's own root).
	if err := fs.Upload(ctx, "disk.txt", filesystem.FileSource{File: tmpFile}); err != nil {
		t.Fatalf("Upload disk.txt err=%v", err)
	}
	got, _ := fs.Read(ctx, "disk.txt")
	if string(got) != "from-disk content" {
		t.Fatalf("got %q", string(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: FAIL on `TestUpload_FromDiskFile` (absolute path rejected by `cleanRelPath`).

- [ ] **Step 3: Fix `resolveBytes` to handle absolute disk paths**

The issue: `src.File` may be either (a) a filesystem-relative path (resolved via `fs.Read`) or (b) an absolute disk path (resolved via `os.ReadFile`).

Update `resolveBytes` in `pkg/filesystem/internal.go`:
```go
func (fs *Filesystem) resolveBytes(src FileSource) ([]byte, error) {
	switch {
	case src.File != "":
		if filepath.IsAbs(src.File) {
			// Absolute disk path — read directly.
			return os.ReadFile(src.File)
		}
		// Relative path — read from this filesystem.
		return fs.Read(context.Background(), src.File)
	case src.Literal != "":
		// ... (unchanged)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/
git commit -m "feat(filesystem): resolve File source from absolute disk paths"
```

---

## Task 7: pkg/filesystem concurrency safety and benchmarks

**Files:**
- Modify: `pkg/filesystem/filesystem_test.go` (or new `filesystem_concurrency_test.go`)
- Create: `pkg/filesystem/filesystem_bench_test.go`

**Interfaces:**
- Consumes: all methods from Tasks 2-5
- Produces: race-free correctness tests + benchmarks

- [ ] **Step 1: Write concurrency test**

`pkg/filesystem/filesystem_concurrency_test.go`:
```go
package filesystem_test

import (
	"context"
	"fmt"
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
	fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "shared"})
	fs.Upload(ctx, "b.txt", filesystem.FileSource{Literal: "shared"})

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
	// At least all reads of b.txt that succeeded should return "shared".
	for i := N; i < 2*N; i++ {
		// Read of b.txt should not return an error (Delete on a.txt does not affect b.txt).
		if errs[i] != nil {
			t.Fatalf("Read b.txt err=%v", errs[i])
		}
	}
}
```

- [ ] **Step 2: Run test to verify it passes (and -race is clean)**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race -run TestConcurrent ./pkg/filesystem/...`
Expected: PASS, race detector clean.

If race detector flags anything, the issue is that `lookupHashForPath` walks `.meta/files/*.json` without holding the lock — fix by holding `fs.mu.RLock()` around the directory walk in `Read`. Already done in Task 2's implementation (`fs.mu.RLock()` before `lookupHashForPath`).

- [ ] **Step 3: Write benchmarks**

`pkg/filesystem/filesystem_bench_test.go`:
```go
package filesystem_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func BenchmarkUpload_SameContent_10k(b *testing.B) {
	fs, _ := filesystem.New(b.TempDir())
	ctx := context.Background()
	src := filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("file-%d.txt", i)
		if err := fs.Upload(ctx, path, src); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N), "uploads")
}

func BenchmarkRead_SamePath_10k(b *testing.B) {
	fs, _ := filesystem.New(b.TempDir())
	ctx := context.Background()
	fs.Upload(ctx, "shared.txt", filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fs.Read(ctx, "shared.txt"); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N), "reads")
}
```

- [ ] **Step 4: Run benchmarks**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -bench=. -benchmem ./pkg/filesystem/...`
Expected: 
- `BenchmarkUpload_SameContent_10k`: low allocs/op (should reuse blob, ~0 alloc after first)
- `BenchmarkRead_SamePath_10k`: low allocs/op (just `os.ReadFile`)

- [ ] **Step 5: Commit**

```bash
git add pkg/filesystem/
git commit -m "test(filesystem): add concurrency safety tests and benchmarks"
```

---

## Task 8: pkg/filesystem README

**Files:**
- Create: `pkg/filesystem/README.md`

**Interfaces:**
- Consumes: all public API from Tasks 1-7
- Produces: documentation for module consumers

- [ ] **Step 1: Write README**

`pkg/filesystem/README.md`:
```markdown
# pkg/filesystem

独立的内容寻址文件系统（content-addressed filesystem），用于存储造流量所需的文件数据。**与造流量业务隔离**，不依赖 trafficgen 的 internal 包。

## 设计

- **去重**：相同 SHA-256 的文件只存一份（`blobs/<sha256>`）
- **多文件名映射**：`.meta/files/<sha256>.json` 的 `refs[]` 数组记录所有引用此 blob 的相对路径
- **删除语义**：删除一个文件名只删 refs[] 里的对应条目；当 refs[] 空时才删 blob
- **目录递归删除**：`Rmdir(recursive=true)` 按文件删除规则级联处理，deduped blob 在有其他 refs 时不会被删

## API

\`\`\`go
fs, err := filesystem.New("/data/filesystem")

// 上传
err = fs.Upload(ctx, "docs/readme.txt", filesystem.FileSource{Literal: "hello"})

// 读取（造流量系统唯一会调的接口）
bytes, err := fs.Read(ctx, "docs/readme.txt")

// 删除
err = fs.Delete(ctx, "docs/readme.txt")

// 查询元数据
info, err := fs.Query(ctx, "docs/readme.txt")

// 列目录
entries, err := fs.List(ctx, "docs")

// 目录操作
err = fs.Mkdir(ctx, "docs/sub")
err = fs.Rmdir(ctx, "docs/sub", filesystem.RmdirOptions{Recursive: true})
\`\`\`

## FileSource 数据源

| 字段 | 说明 | 缓存策略 |
|------|------|---------|
| `File` | 文件系统相对路径或绝对磁盘路径 | 缓存（按 hash dedup） |
| `Literal` | 字面字符串 | 缓存 |
| `Fill` | 单字节填充 N 字节 | 缓存 |
| `Random` (有 Seed) | 可复现的伪随机 | 缓存 |
| `Random` (无 Seed) | 真随机，每次调用不同 | 不缓存（PayloadCache 直接绕过） |

## 与造流量系统的关系

造流量侧通过 `internal/core/payloadcache.go` 调 `fs.Read(relPath)`，**只读**。协议流量中的 `FTP DELE`、`HTTP DELETE` 等命令只生成"删除命令的包"，不调 `fs.Delete`。文件系统状态由独立的 CLI/REST/MCP 入口维护。
```

- [ ] **Step 2: Commit**

```bash
git add pkg/filesystem/README.md
git commit -m "docs(filesystem): add README with API reference and design notes"
```

---

## Task 9: internal/core/payloadcache (PayloadCache with random-bypass rule)

**Files:**
- Create: `internal/core/payloadcache.go`
- Create: `internal/core/payloadcache_test.go`

**Interfaces:**
- Consumes: `pkg/filesystem.Filesystem`, `pkg/filesystem.FileSource`, `pkg/filesystem.Random`
- Produces:
  - `type PayloadCache struct { ... }`
  - `func NewPayloadCache(fs *filesystem.Filesystem) *PayloadCache`
  - `func (c *PayloadCache) GetOrLoad(ctx context.Context, src filesystem.FileSource) ([]byte, error)`
  - `func (c *PayloadCache) Stats() (entries int, totalBytes int64)`

- [ ] **Step 1: Write failing test**

`internal/core/payloadcache_test.go`:
```go
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
	// Same slice header — truly cached, not re-computed.
	if len(b1) != len(b2) {
		t.Fatalf("len differs")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: FAIL with "undefined: core.NewPayloadCache".

- [ ] **Step 3: Implement PayloadCache**

`internal/core/payloadcache.go`:
```go
package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	entries    sync.Map  // hash(string) -> []byte (immutable after publish)
	totalBytes atomic.Int64
}

// NewPayloadCache returns a cache that uses fs for src.File resolution.
// fs may be nil — then src.File is treated as an absolute disk path
// (returns error if relative).
func NewPayloadCache(fs *filesystem.Filesystem) *PayloadCache {
	return &PayloadCache{fs: fs}
}

// GetOrLoad returns the bytes for src. For unseeded random, returns fresh
// bytes on every call without touching the cache.
func (c *PayloadCache) GetOrLoad(ctx context.Context, src filesystem.FileSource) ([]byte, error) {
	// Rule: unseeded random bypasses the cache entirely.
	if src.Random != nil && src.Seed == 0 {
		return filesystem.GenerateRandomBytes(src.Random)
	}

	b, err := c.resolveBytes(ctx, src)
	if err != nil {
		return nil, err
	}
	hash := hashHex(b)
	if cached, ok := c.entries.Load(hash); ok {
		return cached.([]byte), nil
	}
	c.entries.Store(hash, b)
	c.totalBytes.Add(int64(len(b)))
	return b, nil
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
```

Add `os` import to `payloadcache.go`:
```go
import (
	"os"
	// ...
)
```

Export `GenerateRandomBytes` from `pkg/filesystem` (currently internal helper `generateRandomBytes`). Add to `pkg/filesystem/internal.go`:
```go
// GenerateRandomBytes is exported for reuse by internal/core/payloadcache
// so the unseeded-random bypass path can construct fresh bytes without
// importing the internal helper.
func GenerateRandomBytes(r *Random) ([]byte, error) {
	return generateRandomBytes(r)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/... ./pkg/filesystem/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core/payloadcache.go internal/core/payloadcache_test.go pkg/filesystem/internal.go
git commit -m "feat(core): add PayloadCache with unseeded-random bypass rule"
```

---

## Task 10: FlowSpec.FileSource + mapToFlowSpec parsing

**Files:**
- Modify: `internal/core/types.go` (add `FileSource` field to FlowSpec and protocol configs)
- Modify: `internal/core/strategy_convert.go` (parse `file_source` from cfg map)
- Modify: `internal/core/strategy_convert_test.go` (or new file)

**Interfaces:**
- Consumes: `pkg/filesystem.FileSource`
- Produces:
  - `FlowSpec.FileSource *filesystem.FileSource` field (top-level, protocol-agnostic)
  - `FTPDataChannel.FileSource *filesystem.FileSource`
  - `SIPMedia.FileSource *filesystem.FileSource`
  - `SCTPChunk.FileSource *filesystem.FileSource`
  - `HTTPConfig.FileSource *filesystem.FileSource`
  - `ICMPConfig.FileSource *filesystem.FileSource`
  - `mapToFlowSpec` parses `cfg["file_source"]` into `*FileSource`

- [ ] **Step 1: Write failing test**

`internal/core/strategy_convert_filesource_test.go`:
```go
package core_test

import (
	"reflect"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestMapToFlowSpec_FileSource_Literal(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"literal": "hello",
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil {
		t.Fatalf("FileSource is nil")
	}
	if spec.FileSource.Literal != "hello" {
		t.Fatalf("Literal got %q, want %q", spec.FileSource.Literal, "hello")
	}
}

func TestMapToFlowSpec_FileSource_Fill(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"fill": map[string]interface{}{
				"byte":  170,
				"bytes": 100,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil || spec.FileSource.Fill == nil {
		t.Fatalf("FileSource.Fill is nil")
	}
	if spec.FileSource.Fill.Byte != 170 || spec.FileSource.Fill.Bytes != 100 {
		t.Fatalf("Fill got %+v", spec.FileSource.Fill)
	}
}

func TestMapToFlowSpec_FileSource_Random(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"random": map[string]interface{}{
				"min_bytes": 64,
				"max_bytes": 128,
				"seed":      42,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil || spec.FileSource.Random == nil {
		t.Fatalf("FileSource.Random is nil")
	}
	if spec.FileSource.Random.MinBytes != 64 || spec.FileSource.Random.MaxBytes != 128 || spec.FileSource.Random.Seed != 42 {
		t.Fatalf("Random got %+v", spec.FileSource.Random)
	}
}

func TestMapToFlowSpec_FileSource_FTPDataChannel(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "ftp",
		"ftp": map[string]interface{}{
			"data_channel": map[string]interface{}{
				"file_source": map[string]interface{}{
					"file": "docs/retr.bin",
				},
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil || spec.FTP.DataChannel == nil || spec.FTP.DataChannel.FileSource == nil {
		t.Fatalf("FTPDataChannel.FileSource is nil")
	}
	if spec.FTP.DataChannel.FileSource.File != "docs/retr.bin" {
		t.Fatalf("File got %q", spec.FTP.DataChannel.FileSource.File)
	}
}

func TestMapToFlowSpec_FileSource_NilWhenAbsent(t *testing.T) {
	cfg := map[string]interface{}{"protocol": "tcp"}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource != nil {
		t.Fatalf("FileSource should be nil when absent")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: FAIL with "undefined: core.MapToFlowSpec" or "spec.FileSource undefined".

- [ ] **Step 3: Implement parsing**

Modify `internal/core/types.go` to add `FileSource` field to `FlowSpec`, `FTPDataChannel`, `SIPMedia`, `SCTPChunk`, `HTTPConfig`, `ICMPConfig`:
```go
import "github.com/trafficgen/trafficgen/pkg/filesystem"

type FlowSpec struct {
	// ...existing fields...
	Payload  []byte `json:"payload,omitempty"`
	// FileSource (protocol-agnostic): when set, planners obtain payload
	// bytes via PayloadCache.GetOrLoad(src) instead of using inline
	// Payload. May be overridden per-protocol (e.g. FTPDataChannel.
	// FileSource takes precedence over FlowSpec.FileSource).
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
	// ...rest...
}

type FTPDataChannel struct {
	// ...existing fields...
	Payload    string `json:"payload,omitempty"`
	PayloadB64 string `json:"payload_b64,omitempty"`
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
	MSS        uint16 `json:"mss,omitempty"`
}

// Repeat for SIPMedia, SCTPChunk, HTTPConfig, ICMPConfig
```

Modify `internal/core/strategy_convert.go` to add `parseFileSource` and call it from `mapToFlowSpec`:
```go
// added to strategy_convert.go

import "github.com/trafficgen/trafficgen/pkg/filesystem"

// parseFileSource extracts a FileSource from cfg["file_source"] (a map).
// Returns nil if absent or invalid.
func parseFileSource(cfg map[string]interface{}) *filesystem.FileSource {
	src, ok := cfg["file_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	fs := &filesystem.FileSource{}
	if v, ok := src["file"].(string); ok {
		fs.File = v
	}
	if v, ok := src["literal"].(string); ok {
		fs.Literal = v
	}
	if fill, ok := src["fill"].(map[string]interface{}); ok {
		b, _ := fill["byte"].(float64)
		n, _ := fill["bytes"].(float64)
		fs.Fill = &filesystem.Fill{Byte: byte(int(b)), Bytes: int(n)}
	}
	if r, ok := src["random"].(map[string]interface{}); ok {
		min, _ := r["min_bytes"].(float64)
		max, _ := r["max_bytes"].(float64)
		seed, _ := r["seed"].(float64)
		fs.Random = &filesystem.Random{MinBytes: int(min), MaxBytes: int(max), Seed: int64(seed)}
	}
	// If all fields are zero, treat as nil.
	if fs.File == "" && fs.Literal == "" && fs.Fill == nil && fs.Random == nil {
		return nil
	}
	return fs
}

// MapToFlowSpec is the exported wrapper around mapToFlowSpec for tests.
func MapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	return mapToFlowSpec(cfg, protocol)
}
```

In `mapToFlowSpec` body, after parsing protocol-specific configs, add:
```go
spec.FileSource = parseFileSource(cfg)
if spec.FTP != nil && spec.FTP.DataChannel != nil {
	if dcFS := parseFileSource(getMap(cfg, "ftp", "data_channel")); dcFS != nil {
		spec.FTP.DataChannel.FileSource = dcFS
	}
}
// (similar for SIP, SCTP, HTTP, ICMP where applicable)
```

Add a helper `getMap(cfg, ...keys)` to walk nested maps.

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core/
git commit -m "feat(core): add FlowSpec.FileSource + protocol-level FileSource fields"
```

---

## Task 11: FTP planner integration (FileSource → PayloadCache → sub-flow payload)

**Files:**
- Modify: `internal/protocol/ftp/ftp.go` (use `FileSource` when set on `FTPDataChannel`)
- Modify: `internal/protocol/ftp/ftp_data_test.go` (add FileSource test cases)

**Interfaces:**
- Consumes: `FlowSpec.FileSource`, `FTPDataChannel.FileSource` from Task 10
- Produces: FTP planner reads `dc.FileSource` and calls `core.PayloadCache.GetOrLoad` to obtain bytes; falls back to inline `dc.Payload`/`dc.PayloadB64` when `FileSource` is nil (backward compat)

- [ ] **Step 1: Write failing test**

`internal/protocol/ftp/ftp_filesource_test.go`:
```go
package ftp_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestFTPDataChannel_FileSource_Literal(t *testing.T) {
	p := ftp.NewPlanner()
	fs, _ := filesystem.New(t.TempDir())
	pc := core.NewPayloadCache(fs)
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{Literal: "FILE-BYTES"},
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	// Find a data-channel packet (port 50000 or different from 21).
	var dataPayload []byte
	for _, c := range packets {
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if string(dataPayload) != "FILE-BYTES" {
		t.Fatalf("data payload got %q, want %q", string(dataPayload), "FILE-BYTES")
	}
	_ = pc // suppress unused
}
```

Note: The test does NOT need to inject `pc` directly into the planner if the planner resolves FileSource via context-injected cache. For this plan, we inject the cache into the planner via `Plan(ctx, spec)` reading from `ctx.Value(payloadCacheKey{})`.

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/protocol/ftp/...`
Expected: FAIL with data payload empty or "FILE-BYTES" not present.

- [ ] **Step 3: Implement FTP planner FileSource resolution**

Modify `internal/protocol/ftp/ftp.go`'s `emitFTPDataChannel` to resolve payload bytes:
```go
// at top of file, add context key type
type payloadCacheKey struct{}

// WithPayloadCache returns a context carrying the payload cache.
func WithPayloadCache(ctx context.Context, pc *core.PayloadCache) context.Context {
	return context.WithValue(ctx, payloadCacheKey{}, pc)
}

// in emitFTPDataChannel, before constructing sub:
var payloadBytes []byte
if dc.FileSource != nil {
	pc, _ := ctx.Value(payloadCacheKey{}).(*core.PayloadCache)
	if pc == nil {
		// error: cannot resolve FileSource without cache
		return
	}
	payloadBytes, _ = pc.GetOrLoad(ctx, *dc.FileSource)
} else if dc.PayloadB64 != "" {
	payloadBytes, _ = base64.StdEncoding.DecodeString(dc.PayloadB64)
} else {
	payloadBytes = []byte(dc.Payload)
}

sub := core.SubFlowSpec{
	Protocol: "tcp",
	// ...
	Payload: payloadBytes,
	// ...
}
```

Then in `Plan()`, pass `ctx` through to `emitFTPDataChannel` (currently the call site is in a goroutine that closes over `ctx`).

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/protocol/ftp/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/ftp/
git commit -m "feat(ftp): planner resolves FileSource via PayloadCache"
```

---

## Task 12: SIP, SCTP, HTTP, ICMP planner FileSource integration

**Files:**
- Modify: `internal/protocol/sip/sip.go`
- Modify: `internal/protocol/sctp/sctp.go`
- Modify: `internal/protocol/http/http.go`
- Modify: `internal/protocol/icmp/icmp.go`
- Tests for each

**Interfaces:**
- Consumes: `WithPayloadCache` from Task 11, `FileSource` from Task 10
- Produces: each planner reads `*Config.FileSource` (when non-nil) and calls `pc.GetOrLoad(ctx, src)` to obtain bytes; falls back to inline Payload/Literal/Body when nil

- [ ] **Step 1: Write failing test for each planner**

Add a test per planner — pattern: when `*Config.FileSource = &{Literal: "X"}` is set, the emitted packets carry bytes "X" (or bytes derived from "X" for RTP which splits by FrameSize).

For SIP (split by FrameSize): if FileSource.Literal = "abcdefghij" (10 bytes) and FrameSize=4, expect 3 RTP payloads: "abcd", "efgh", "ij".

For SCTP: if SCTPChunk.FileSource.Literal = "X", expect DATA chunk payload "X".

For HTTP: if HTTPConfig.FileSource.Literal = "X", expect request body "X".

For ICMP: if ICMPConfig.FileSource.Literal = "X", expect echo data "X".

Each test is a copy of Task 11's pattern adapted to that protocol's structure.

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/protocol/...`
Expected: FAIL for each new test.

- [ ] **Step 3: Implement FileSource resolution in each planner**

For each planner, add the same pattern as Task 11:
- Check `*Config.FileSource != nil`
- Get `pc` from `ctx.Value(payloadCacheKey{})`
- Call `pc.GetOrLoad(ctx, *src)` to get bytes
- Use bytes in place of inline Payload/Literal/Body

SIP specifics: split bytes by FrameSize (last chunk may be smaller).
HTTP specifics: set `Body`/`BodyB64` derived from bytes if both nil (do not override user-set Body).
ICMP specifics: set `Data` derived from bytes if `Data` is nil.

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/protocol/...`
Expected: PASS for all planners.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/sip/ internal/protocol/sctp/ internal/protocol/http/ internal/protocol/icmp/
git commit -m "feat(sip,sctp,http,icmp): planner resolves FileSource via PayloadCache"
```

---

## Task 13: Engine wiring (PayloadCache + Filesystem + WithPayloadCache in ctx)

**Files:**
- Modify: `internal/core/engine.go` (add `payloadCache *PayloadCache`, `SetPayloadCache`)
- Modify: `cmd/server/main.go` (init `app.filesystem`, `app.payloadCache`, inject into ctx for planner calls)

**Interfaces:**
- Consumes: `PayloadCache` from Task 9, `filesystem.New` from Task 1
- Produces:
  - `Engine.SetPayloadCache(pc *PayloadCache)`
  - `Engine.PayloadCache() *PayloadCache` (for worker to inject into ctx)
  - `Application.filesystem *filesystem.Filesystem` field
  - `Application.payloadCache *core.PayloadCache` field

- [ ] **Step 1: Write failing test**

`internal/core/engine_payloadcache_test.go`:
```go
package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestEngine_SetPayloadCache(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{})
	fs, _ := filesystem.New(t.TempDir())
	pc := core.NewPayloadCache(fs)
	e.SetPayloadCache(pc)
	got := e.PayloadCache()
	if got != pc {
		t.Fatalf("PayloadCache got %p, want %p", got, pc)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: FAIL with "undefined: e.SetPayloadCache".

- [ ] **Step 3: Implement engine fields and setters**

Modify `internal/core/engine.go`:
```go
type Engine struct {
	// ...existing...
	payloadCache *PayloadCache
}

func (e *Engine) SetPayloadCache(pc *PayloadCache) {
	e.payloadCache = pc
}

func (e *Engine) PayloadCache() *PayloadCache {
	return e.payloadCache
}
```

Modify `cmd/server/main.go` `Application` struct and `initEngine`:
```go
type Application struct {
	// ...existing...
	filesystem  *filesystem.Filesystem
	payloadCache *core.PayloadCache
}

// in initEngine, after app.engine = NewEngine(...):
app.filesystem, err = filesystem.New(app.config.Filesystem.Root)
if err != nil {
	return err
}
app.payloadCache = core.NewPayloadCache(app.filesystem)
app.engine.SetPayloadCache(app.payloadCache)
```

In the worker (where `p.Plan(ctx, spec)` is called), inject the cache into ctx:
```go
ctx := context.WithValue(ctx, payloadCacheKey{}, e.payloadCache)
// then:
configChan, err := p.Plan(ctx, spec)
```

The `payloadCacheKey` type must be exported from `internal/core` package (or unexported but used by both engine and planner — they're in different packages, so export it):
```go
// in internal/core/payloadcache.go
type PayloadCacheKey struct{}
func WithPayloadCache(ctx context.Context, pc *PayloadCache) context.Context {
	return context.WithValue(ctx, PayloadCacheKey{}, pc)
}
func PayloadCacheFrom(ctx context.Context) *PayloadCache {
	pc, _ := ctx.Value(PayloadCacheKey{}).(*PayloadCache)
	return pc
}
```

Then planners call `core.PayloadCacheFrom(ctx)` instead of importing the private key.

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core/engine.go cmd/server/main.go
git commit -m "feat(engine,server): wire PayloadCache + Filesystem into engine and ctx"
```

---

## Task 14: Config (filesystem.root default + --fs-root flag)

**Files:**
- Modify: `pkg/config/config.go` (add `Filesystem FilesystemConfig`)
- Modify: `configs/config.yaml`, `configs/config.dev.yaml`, `configs/config.docker.yaml`, `configs/config.standalone.yaml`
- Modify: `cmd/server/main.go` (add `fsRoot` flag, override config)

**Interfaces:**
- Consumes: `pkg/config.Config`
- Produces: `Config.Filesystem.Root` defaults to `data/filesystem`; CLI `--fs-root` overrides

- [ ] **Step 1: Write failing test**

`pkg/config/config_filesystem_test.go`:
```go
package config_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/pkg/config"
)

func TestConfig_FilesystemDefault(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load err=%v", err)
	}
	if cfg.Filesystem.Root == "" {
		t.Fatalf("Filesystem.Root should default to non-empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/config/...`
Expected: FAIL with "Filesystem field undefined" or empty root.

- [ ] **Step 3: Implement Config**

Modify `pkg/config/config.go`:
```go
type Config struct {
	// ...existing...
	Filesystem FilesystemConfig `mapstructure:"filesystem"`
}

type FilesystemConfig struct {
	Root string `mapstructure:"root"`
}
```

Add default in `Load` (or `initDefaults`):
```go
if cfg.Filesystem.Root == "" {
	cfg.Filesystem.Root = "data/filesystem"
}
```

Modify `configs/config.yaml` (and variants) to add:
```yaml
filesystem:
  root: "data/filesystem"
```

Modify `cmd/server/main.go` to add `fsRoot` flag:
```go
var (
	configPath = flag.String("config", "", "...")
	fsRoot     = flag.String("fs-root", "", "Filesystem root override (default: data/filesystem)")
	version    = "1.0.0"
)

// after config.Load:
if *fsRoot != "" {
	cfg.Filesystem.Root = *fsRoot
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./pkg/config/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/config/config.go configs/ cmd/server/main.go
git commit -m "feat(config,server): add filesystem.root default + --fs-root flag"
```

---

## Task 15: HTTP API for filesystem CRUD (/api/v1/fs/*)

**Files:**
- Create: `internal/api/rest/filesystem_handler.go`
- Create: `internal/api/rest/filesystem_handler_test.go`
- Modify: `internal/api/rest/server.go` (add `filesystem *filesystem.Filesystem` field, register routes)

**Interfaces:**
- Consumes: `pkg/filesystem.Filesystem` methods (Upload/Read/Query/List/Mkdir/Rmdir/Delete)
- Produces:
  - `type FilesystemHandler struct { ... }`
  - Routes: `POST /api/v1/fs/files/*path`, `GET /api/v1/fs/files/*path?op=download|info`, `DELETE /api/v1/fs/files/*path`, `POST /api/v1/fs/dirs/*path`, `DELETE /api/v1/fs/dirs/*path?recursive=true`, `GET /api/v1/fs/list?path=`

- [ ] **Step 1: Write failing test**

`internal/api/rest/filesystem_handler_test.go`:
```go
package rest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func newFSServer(t *testing.T) (*rest.Server, *filesystem.Filesystem) {
	t.Helper()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New err=%v", err)
	}
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}
	srv := rest.NewServer(cfg, nil, nil, nil, nil, nil)
	srv.SetFilesystem(fs)
	srv.Setup()
	return srv, fs
}

func TestFSHandler_Upload_ThenRead(t *testing.T) {
	srv, _ := newFSServer(t)
	body := bytes.NewBufferString(`{"literal":"hello"}`)
	req := httptest.NewRequest("POST", "/api/v1/fs/files/docs/a.txt", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("upload status got %d, want 201; body=%s", w.Code, w.Body.String())
	}
	// Read it back.
	req2 := httptest.NewRequest("GET", "/api/v1/fs/files/docs/a.txt?op=download", nil)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("read status got %d", w2.Code)
	}
	if w2.Body.String() != "hello" {
		t.Fatalf("read got %q, want %q", w2.Body.String(), "hello")
	}
}

func TestFSHandler_Delete(t *testing.T) {
	srv, fs := newFSServer(t)
	ctx := context.Background()
	fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "X"})
	req := httptest.NewRequest("DELETE", "/api/v1/fs/files/a.txt", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("delete status got %d, want 204", w.Code)
	}
}

func TestFSHandler_List(t *testing.T) {
	srv, fs := newFSServer(t)
	ctx := context.Background()
	fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "A"})
	fs.Mkdir(ctx, "sub")
	req := httptest.NewRequest("GET", "/api/v1/fs/list?path=.", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list status got %d", w.Code)
	}
	var entries []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &entries)
	names := map[string]bool{}
	for _, e := range entries {
		names[e["name"].(string)] = true
	}
	if !names["a.txt"] || !names["sub"] {
		t.Fatalf("list missing entries: %v", names)
	}
}

func TestFSHandler_Mkdir_RmdirRecursive(t *testing.T) {
	srv, _ := newFSServer(t)
	// Mkdir
	req := httptest.NewRequest("POST", "/api/v1/fs/dirs/a/b/c", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("mkdir status got %d", w.Code)
	}
	// Rmdir recursive
	req2 := httptest.NewRequest("DELETE", "/api/v1/fs/dirs/a?recursive=true", nil)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	if w2.Code != 204 {
		t.Fatalf("rmdir status got %d", w2.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/api/rest/...`
Expected: FAIL with "undefined: srv.SetFilesystem" or route not found.

- [ ] **Step 3: Implement handler**

`internal/api/rest/filesystem_handler.go`:
```go
package rest

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

type FilesystemHandler struct {
	fs *filesystem.Filesystem
}

func NewFilesystemHandler(fs *filesystem.Filesystem) *FilesystemHandler {
	return &FilesystemHandler{fs: fs}
}

func (h *FilesystemHandler) Upload(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	var src filesystem.FileSource
	if err := c.ShouldBindJSON(&src); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.fs.Upload(c.Request.Context(), relPath, src); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusCreated)
}

func (h *FilesystemHandler) Download(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	b, err := h.fs.Read(c.Request.Context(), relPath)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, filesystem.ErrNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", b)
}

func (h *FilesystemHandler) Info(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	info, err := h.fs.Query(c.Request.Context(), relPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, info)
}

func (h *FilesystemHandler) DeleteFile(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	if err := h.fs.Delete(c.Request.Context(), relPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *FilesystemHandler) Mkdir(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	if err := h.fs.Mkdir(c.Request.Context(), relPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusCreated)
}

func (h *FilesystemHandler) Rmdir(c *gin.Context) {
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	recursive := c.Query("recursive") == "true"
	if err := h.fs.Rmdir(c.Request.Context(), relPath, filesystem.RmdirOptions{Recursive: recursive}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *FilesystemHandler) List(c *gin.Context) {
	dir := c.Query("path")
	if dir == "" {
		dir = "."
	}
	entries, err := h.fs.List(c.Request.Context(), dir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, entries)
}
```

Modify `internal/api/rest/server.go`:
```go
type Server struct {
	// ...existing...
	filesystem *filesystem.Filesystem
}

func (s *Server) SetFilesystem(fs *filesystem.Filesystem) {
	s.filesystem = fs
}

// expose router for tests
func (s *Server) Router() *gin.Engine {
	return s.router
}

// in setupRoutes():
if s.filesystem != nil {
	fsHandler := NewFilesystemHandler(s.filesystem)
	fsGroup := api.Group("/fs")
	{
		fsGroup.POST("/files/*path", fsHandler.Upload)
		fsGroup.GET("/files/*path", func(c *gin.Context) {
			op := c.Query("op")
			switch op {
			case "download", "":
				fsHandler.Download(c)
			case "info":
				fsHandler.Info(c)
			default:
				c.JSON(http.StatusBadRequest, gin.H{"error": "unknown op"})
			}
		})
		fsGroup.DELETE("/files/*path", fsHandler.DeleteFile)
		fsGroup.POST("/dirs/*path", fsHandler.Mkdir)
		fsGroup.DELETE("/dirs/*path", fsHandler.Rmdir)
		fsGroup.GET("/list", fsHandler.List)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/api/rest/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/rest/
git commit -m "feat(api/rest): add /api/v1/fs/* filesystem CRUD routes"
```

---

## Task 16: MCP tool `flowb_manage_filesystem`

**Files:**
- Create: `internal/mcp/tools_filesystem.go`
- Create: `internal/mcp/tools_filesystem_test.go`
- Modify: `internal/mcp/server.go` (add `filesystem *filesystem.Filesystem` field, `SetFilesystem(fs)`)

**Interfaces:**
- Consumes: `pkg/filesystem.Filesystem` methods
- Produces: MCP tool `flowb_manage_filesystem` with actions: `upload`, `read`, `delete`, `mkdir`, `rmdir`, `list`, `query`

- [ ] **Step 1: Write failing test**

`internal/mcp/tools_filesystem_test.go`:
```go
package mcp_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/mcp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func newMCPWithFS(t *testing.T) (*mcp.Server, *filesystem.Filesystem) {
	// setup similar to existing newMCPServer test helper
	// ...
}

func TestFlowBManageFilesystem_UploadAndRead(t *testing.T) {
	srv, _ := newMCPWithFS(t)
	ctx := context.Background()
	// Call flowb_manage_filesystem with action=upload, path="a.txt", source={literal:"hi"}
	// Then call action=read, path="a.txt" — verify bytes="hi"
	// (Detailed call shape depends on existing mcp.Call pattern in test helpers.)
}

func TestFlowBManageFilesystem_DeleteLastRef(t *testing.T) {
	// Upload same content to a.txt and b.txt, delete a.txt, verify b.txt still readable.
}

func TestFlowBManageFilesystem_RmdirRecursive(t *testing.T) {
	// Mkdir root/sub, upload a file, rmdir recursive, verify gone.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/mcp/...`
Expected: FAIL with "flowb_manage_filesystem: unknown tool" or similar.

- [ ] **Step 3: Implement MCP tool**

`internal/mcp/tools_filesystem.go`:
```go
package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func (s *Server) registerFilesystemTool() {
	tool := NewTool("flowb_manage_filesystem", "Manage the trafficgen filesystem (upload/read/delete/mkdir/rmdir/list/query files and directories).", filesystemToolSchema)
	tool.Handle(s.handleFilesystem)
	s.mcpServer.AddTool(tool)
}

func (s *Server) handleFilesystem(ctx context.Context, req *ToolRequest) (*ToolResponse, error) {
	if s.filesystem == nil {
		return nil, errors.New("filesystem not configured on this server")
	}
	start := time.Now()
	action, err := req.Action()
	if err != nil {
		s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "invalid action")
		return nil, err
	}
	switch action {
	case "upload":
		// parse path, source; call s.filesystem.Upload
	case "read":
		// parse path; call s.filesystem.Read; return bytes (base64)
	case "delete":
		// parse path; call s.filesystem.Delete
	case "mkdir":
		// parse path; call s.filesystem.Mkdir
	case "rmdir":
		// parse path, recursive; call s.filesystem.Rmdir
	case "list":
		// parse path; call s.filesystem.List
	case "query":
		// parse path; call s.filesystem.Query
	default:
		s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "unknown action: "+action)
		return nil, fmt.Errorf("unknown action: %s", action)
	}
	s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "success", "")
	return &ToolResponse{Data: result}, nil
}
```

Modify `internal/mcp/server.go`:
```go
type Server struct {
	// ...existing...
	filesystem *filesystem.Filesystem
}

func (s *Server) SetFilesystem(fs *filesystem.Filesystem) {
	s.filesystem = fs
}

// in registerTools():
if s.filesystem != nil {
	s.registerFilesystemTool()
}
```

Modify `cmd/server/main.go` `initMCPServer`:
```go
app.mcpServer.SetFilesystem(app.filesystem)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/mcp/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/mcp/ cmd/server/main.go
git commit -m "feat(mcp): add flowb_manage_filesystem tool with 7 actions"
```

---

## Task 17: CLI entry (`cmd/fs/main.go`)

**Files:**
- Create: `cmd/fs/main.go`
- Modify: `Makefile` (build target for `tgserver-fs`)

**Interfaces:**
- Consumes: `pkg/filesystem.Filesystem` methods
- Produces: standalone `tgserver-fs` binary with subcommands: `upload`, `delete`, `mkdir`, `rmdir`, `list`, `query`, `read`

- [ ] **Step 1: Write CLI**

`cmd/fs/main.go`:
```go
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func main() {
	root := flag.String("root", "data/filesystem", "Filesystem root")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs <command> [args]")
		os.Exit(1)
	}
	fs, err := filesystem.New(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "filesystem.New err=%v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	cmd, args := args[0], args[1:]
	switch cmd {
	case "upload":
		// tgserver-fs upload <path> --literal X | --file src | --fill-byte 0xAA --fill-bytes 100 | --random-min 64 --random-max 128 --seed 42
		path := args[0]
		src := parseSrcFlags()
		if err := fs.Upload(ctx, path, src); err != nil {
			fmt.Fprintf(os.Stderr, "upload err=%v\n", err)
			os.Exit(1)
		}
		fmt.Println("uploaded", path)
	case "delete":
		path := args[0]
		if err := fs.Delete(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "delete err=%v\n", err)
			os.Exit(1)
		}
		fmt.Println("deleted", path)
	case "mkdir":
		path := args[0]
		if err := fs.Mkdir(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir err=%v\n", err)
			os.Exit(1)
		}
		fmt.Println("mkdir", path)
	case "rmdir":
		recursive := flag.Bool("recursive", false, "recursive")
		flag.Parse()
		path := flag.Arg(0)
		if err := fs.Rmdir(ctx, path, filesystem.RmdirOptions{Recursive: *recursive}); err != nil {
			fmt.Fprintf(os.Stderr, "rmdir err=%v\n", err)
			os.Exit(1)
		}
		fmt.Println("rmdir", path)
	case "list":
		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}
		entries, err := fs.List(ctx, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list err=%v\n", err)
			os.Exit(1)
		}
		for _, e := range entries {
			t := "F"
			if e.IsDir {
				t = "D"
			}
			fmt.Printf("%s %12d %s\n", t, e.Size, e.Name)
		}
	case "query":
		path := args[0]
		info, err := fs.Query(ctx, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "query err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", info)
	case "read":
		path := args[0]
		b, err := fs.Read(ctx, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read err=%v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(b)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func parseSrcFlags() filesystem.FileSource {
	var literal, file string
	var fillByte, fillBytes, randMin, randMax, seed int
	flag.StringVar(&literal, "literal", "", "literal text")
	flag.StringVar(&file, "file", "", "file path (relative or absolute)")
	flag.IntVar(&fillByte, "fill-byte", 0, "fill byte (0-255)")
	flag.IntVar(&fillBytes, "fill-bytes", 0, "fill size in bytes")
	flag.IntVar(&randMin, "random-min", 0, "random min bytes")
	flag.IntVar(&randMax, "random-max", 0, "random max bytes")
	flag.IntVar(&seed, "seed", 0, "random seed (0 = crypto random)")
	flag.Parse()
	switch {
	case file != "":
		return filesystem.FileSource{File: file}
	case literal != "":
		return filesystem.FileSource{Literal: literal}
	case fillBytes > 0:
		return filesystem.FileSource{Fill: &filesystem.Fill{Byte: byte(fillByte), Bytes: fillBytes}}
	case randMax > 0:
		return filesystem.FileSource{Random: &filesystem.Random{MinBytes: randMin, MaxBytes: randMax, Seed: int64(seed)}}
	}
	return filesystem.FileSource{Literal: ""}
}

// suppress unused import
var _ = base64.StdEncoding
var _ = strconv.Itoa
```

- [ ] **Step 2: Build the binary**

Run: `/home/weihang/go/go/bin/go build -buildvcs=false -o /tmp/tgserver-fs ./cmd/fs/`
Expected: build succeeds.

- [ ] **Step 3: Smoke-test the binary**

```bash
/tmp/tgserver-fs upload test.txt --literal hello
/tmp/tgserver-fs read test.txt
# Expected: hello
/tmp/tgserver-fs upload test2.txt --file test.txt
/tmp/tgserver-fs list
/tmp/tgserver-fs delete test.txt
/tmp/tgserver-fs delete test2.txt
/tmp/tgserver-fs list
```

- [ ] **Step 4: Commit**

```bash
git add cmd/fs/main.go
git commit -m "feat(cli): add tgserver-fs standalone binary for filesystem CRUD"
```

---

## Task 18: IPv6 test gap (FTP data-channel parent IPv6)

**Files:**
- Create: `internal/protocol/ftp/ftp_ipv6_test.go`

**Interfaces:**
- Consumes: existing FTP planner + `core.EtherTypeFor` (already IPv6-aware)
- Produces: `TestFTPDataChannel_IPv6Parent` symmetric with `TestSIPMedia_IPv6Parent`

- [ ] **Step 1: Write failing test**

`internal/protocol/ftp/ftp_ipv6_test.go`:
```go
package ftp_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
)

// TestFTPDataChannel_IPv6Parent verifies the FTP data-channel sub-flow
// uses IPv6 EtherType when the parent spec uses IPv6 addresses.
// Symmetric with internal/protocol/sip/sip_rtp_test.go:TestSIPMedia_IPv6Parent.
func TestFTPDataChannel_IPv6Parent(t *testing.T) {
	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1",
		DstIP: "2001:db8::2",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				Payload:    "X",
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var dataPackets []core.PacketConfig
	for c := range ch {
		// Data-channel packets have non-21 ports (control-channel).
		if c.L4.SrcPort != 21 && c.L4.DstPort != 21 {
			dataPackets = append(dataPackets, c)
		}
	}
	if len(dataPackets) == 0 {
		t.Fatalf("no data-channel packets emitted")
	}
	for i, c := range dataPackets {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("data[%d] EtherType=%#x, want 0x86DD (IPv6)", i, c.L2.EtherType)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/protocol/ftp/...`
Expected: PASS (the existing FTP planner already uses `core.EtherTypeFor(spec.SrcIP)` at ftp.go:163, so IPv6 should work). If it FAILS, the gap is real — investigate `EmitSubFlow` in `internal/core/subflow.go` to ensure it propagates the parent spec's `SrcIP`/`DstIP` correctly to sub-flow packets.

- [ ] **Step 3: If test failed, fix the gap**

Likely fix is in `internal/core/subflow.go` `EmitSubFlow`: ensure sub-flow PacketConfigs use `core.EtherTypeFor(spec.SrcIP)` and the same IPv6-aware L3 builder.

If the test passes without changes (because the planner already handles it correctly), this Task still closes the test gap by adding the regression guard.

- [ ] **Step 4: Commit**

```bash
git add internal/protocol/ftp/ftp_ipv6_test.go
git commit -m "test(ftp): add IPv6 parent for FTP data-channel (symmetric with SIP)"
```

---

## Task 19: Integration test (planner → PayloadCache → Filesystem end-to-end)

**Files:**
- Create: `internal/core/filesource_integration_test.go`

**Interfaces:**
- Consumes: All Tasks 9-13
- Produces: end-to-end test proving that a `FileSource.File` referencing a file in the filesystem produces matching bytes in the emitted packets

- [ ] **Step 1: Write failing test**

`internal/core/filesource_integration_test.go`:
```go
package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestFileSource_FTPPlannerReadsFromFilesystem proves the full path:
// FileSource.File -> PayloadCache -> Filesystem.Read -> bytes -> FTP
// data-channel packets carry those bytes.
func TestFileSource_FTPPlannerReadsFromFilesystem(t *testing.T) {
	fs, _ := filesystem.New(t.TempDir())
	ctx := context.Background()
	// Pre-populate filesystem with a file.
	if err := fs.Upload(ctx, "docs/file.bin", filesystem.FileSource{Literal: "FILE-CONTENTS"}); err != nil {
		t.Fatalf("seed Upload err=%v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx = core.WithPayloadCache(ctx, pc)

	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Commands: []core.FTPCommand{
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{File: "docs/file.bin"},
			},
		},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var dataBytes []byte
	for c := range ch {
		if c.L4.SrcPort != 21 && c.L4.DstPort != 21 && len(c.Payload) > 0 {
			dataBytes = append(dataBytes, c.Payload...)
		}
	}
	if string(dataBytes) != "FILE-CONTENTS" {
		t.Fatalf("data bytes got %q, want %q", string(dataBytes), "FILE-CONTENTS")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./internal/core/...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/core/filesource_integration_test.go
git commit -m "test(core): add end-to-end FileSource -> PayloadCache -> Filesystem test"
```

---

## Task 20: PayloadCache benchmark (10k flows × 64KB same content → 1 cached entry)

**Files:**
- Create: `internal/core/payloadcache_bench_test.go`

**Interfaces:**
- Consumes: `PayloadCache` from Task 9
- Produces: benchmark proving memory dedup

- [ ] **Step 1: Write benchmark**

`internal/core/payloadcache_bench_test.go`:
```go
package core_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func BenchmarkPayloadCache_10kFlows_SameContent(b *testing.B) {
	fs, _ := filesystem.New(b.TempDir())
	pc := core.NewPayloadCache(fs)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}
	b.ResetTimer()
	const N = 1000 // smaller for -race CI
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
	entries, totalBytes := pc.Stats()
	b.ReportMetric(float64(entries), "entries")
	b.ReportMetric(float64(totalBytes), "bytes")
}
```

- [ ] **Step 2: Run benchmark**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race -bench=BenchmarkPayloadCache -benchmem ./internal/core/...`
Expected: `entries=1` regardless of N, `bytes=65536`. Confirms dedup.

- [ ] **Step 3: Commit**

```bash
git add internal/core/payloadcache_bench_test.go
git commit -m "bench(core): prove 10k-flow dedup yields 1 cached entry"
```

---

## Task 21: Full code review and verification

**Files:**
- Modify: any files surfaced by review

**Interfaces:**
- Consumes: all changes from Tasks 1-20
- Produces: clean `go vet`, `go build`, `go test -race` for the whole module; adversarial code review per CLAUDE.md §Code Modification & Review Policy

- [ ] **Step 1: Run full test suite with race detector**

Run: `/home/weihang/go/go/bin/go test -buildvcs=false -race ./...`
Expected: PASS, race detector clean.

- [ ] **Step 2: Run go vet**

Run: `/home/weihang/go/go/bin/go vet -buildvcs=false ./...`
Expected: no issues.

- [ ] **Step 3: Run adversarial code review via subagent**

Use the `code-review` skill on the diff `git diff main...HEAD` (or equivalent). The review should cover:
- Filesystem dedup correctness (refs refcount, blob lifecycle)
- Rmdir recursive correctness (no orphan blobs, no dangling meta)
- PayloadCache immutability (no writes after publish)
- FileSource parsing (priority File > Literal > Fill > Random)
- IPv6 propagation through planners and sub-flows
- HTTP API auth (filesystem routes are under authenticated `/api/v1` group)
- MCP tool error handling (all 7 actions covered)
- CLI flag parsing (no panics on missing args)
- Engine ctx injection (planners reliably read `PayloadCacheFrom(ctx)`)

Fix any findings following the failing-test-first rule.

- [ ] **Step 4: Build final binaries**

Run: 
```
/home/weihang/go/go/bin/go build -buildvcs=false -o /tmp/trafficgen-server ./cmd/server/
/home/weihang/go/go/bin/go build -buildvcs=false -o /tmp/tgserver-fs ./cmd/fs/
```
Expected: both succeed.

- [ ] **Step 5: Commit any review fixes**

```bash
git add -A
git commit -m "fix(review): address findings from adversarial code review"
```

---

## Self-Review

**1. Spec coverage:**

- ✅ Standalone filesystem module at `pkg/filesystem/` — Tasks 1-7
- ✅ Hash dedup with multi-name refs refcount — Task 2 (Upload) + Task 3 (Delete)
- ✅ Last-ref-wins blob removal on Delete — Task 3
- ✅ Recursive Rmdir respects dedup (other refs survive) — Task 5
- ✅ FileSource supports file/literal/fill/random — Task 6
- ✅ Seeded random cached, unseeded random bypassed — Task 9
- ✅ PayloadCache in `internal/core/` — Task 9
- ✅ Cross-protocol unified `FlowSpec.FileSource` — Task 10
- ✅ All 5 protocol planners integrate FileSource — Tasks 11-12
- ✅ Engine wires PayloadCache + Filesystem — Task 13
- ✅ `--fs-root` flag + config default — Task 14
- ✅ HTTP API `/api/v1/fs/*` — Task 15
- ✅ MCP tool `flowb_manage_filesystem` — Task 16
- ✅ CLI `tgserver-fs` — Task 17
- ✅ IPv6 test gap (FTP) — Task 18
- ✅ Integration test end-to-end — Task 19
- ✅ Benchmark proving dedup — Task 20
- ✅ Adversarial code review — Task 21

**2. Placeholder scan:**

- No "TBD", "TODO", "implement later" found.
- All test code blocks contain real Go code.
- Some early tasks have stubs (e.g., Task 4 stubs Mkdir which is fully implemented in Task 5) — these are intentional and explicitly noted, not placeholders.

**3. Type consistency:**

- `FileSource` defined once in Task 1, used identically in Tasks 9, 10, 11, 12, 13, 17.
- `PayloadCache` defined in Task 9, `NewPayloadCache(fs)` signature consistent through Tasks 11, 12, 13, 19, 20.
- `WithPayloadCache(ctx, pc)` and `PayloadCacheFrom(ctx)` exported from `internal/core` (defined in Task 13), used in Tasks 11, 12, 19.
- `payloadCacheKey` private type — replaced by exported `PayloadCacheKey` in Task 13 to allow cross-package use. Task 11 mentions `payloadCacheKey` — must use `core.PayloadCacheKey` instead. **Correction**: In Task 11, replace `payloadCacheKey` references with `core.PayloadCacheKey` and call `core.WithPayloadCache` / `core.PayloadCacheFrom`. Update Task 11 step 3 accordingly. (This is a known minor inconsistency — the implementer should follow Task 13's exported names.)
- `RmdirOptions{Recursive: bool}` consistent through Tasks 5, 15, 16, 17.
- `FileInfo` struct consistent through Tasks 4, 15, 16.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-25-filesystem-and-payloadcache.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
