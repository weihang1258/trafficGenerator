package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// setupMCPWithFS builds the standard MCP test env and injects a fresh
// content-addressed filesystem rooted at a temp dir. Returns the server
// (for direct handler invocation) and the underlying *filesystem.Filesystem
// (so tests can cross-check via the public API if needed). The helper
// cleans up both the engine/db (env.cleanup) and the fs temp dir.
//
// Mirrors the existing setupMCPTest helper (which creates a DB + engine +
// MCP server triplet) and adds the filesystem injection point that
// main.go also uses (SetFilesystem after NewServer).
func setupMCPWithFS(t *testing.T) (*testMCPEnv, *filesystem.Filesystem) {
	t.Helper()
	env := setupMCPTest(t)

	// Create a fresh filesystem at a temp dir. filesystem.New creates the
	// root + .meta/files + blobs subdirs, so a fresh path just works.
	fsDir := filepath.Join(env.tmp, "fs")
	if err := os.MkdirAll(fsDir, 0755); err != nil {
		env.cleanup()
		t.Fatalf("mkdir fs dir: %v", err)
	}
	fs, err := filesystem.New(fsDir)
	if err != nil {
		env.cleanup()
		t.Fatalf("filesystem.New: %v", err)
	}

	// Inject the filesystem into the server. registerTools() already ran
	// during NewServer (with s.filesystem == nil, so the filesystem tool
	// was NOT registered). For unit tests that call handleManageFilesystem
	// directly, we don't need re-registration; we only need s.filesystem
	// to be non-nil so the handler doesn't short-circuit.
	env.srv.SetFilesystem(fs)

	// Override cleanup so both engine/db and fs are torn down. The fs
	// itself lives under env.tmp, so env.cleanup's RemoveAll(env.tmp)
	// already removes it; we just need to ensure the engine stops first
	// (already done in env.cleanup). Nothing extra needed.
	return env, fs
}

// asFilesystemBytes decodes a {bytes_base64, length} envelope from the
// MCP tool's Data field and returns the raw file bytes. t.Helper ensures
// failures point at the call site, not inside this helper.
func asFilesystemBytes(t *testing.T, data interface{}) []byte {
	t.Helper()
	raw := asRaw(data)
	var env struct {
		BytesBase64 string `json:"bytes_base64"`
		Length      int    `json:"length"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("read envelope unparseable: %s (err: %v)", string(raw), err)
	}
	b, err := base64.StdEncoding.DecodeString(env.BytesBase64)
	if err != nil {
		t.Fatalf("bytes_base64 invalid: %v (raw: %s)", err, env.BytesBase64)
	}
	if len(b) != env.Length {
		t.Fatalf("decoded length mismatch: got %d, envelope says %d", len(b), env.Length)
	}
	return b
}

// asFilesystemAck decodes an arbitrary action-result object from the
// tool's Data field into a map for field inspection.
func asFilesystemAck(t *testing.T, data interface{}) map[string]interface{} {
	t.Helper()
	raw := asRaw(data)
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("envelope unparseable: %s (err: %v)", string(raw), err)
	}
	return m
}

// TestMCP_ManageFilesystem_UploadAndRead verifies the upload+read round-trip:
// upload a literal-source file, then read it back and verify the bytes
// match what was written. Per CLAUDE.md testing policy §5: the test asserts
// the observable outcome (decoded bytes equal the literal), not just the
// structural envelope (length, presence of bytes_base64). A regression
// where `read` returned a JSON envelope as the payload (the bug we caught
// in pcap get_stream/get_body) would surface here as a base64-decode
// failure or a content mismatch.
func TestMCP_ManageFilesystem_UploadAndRead(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	want := "hello world"
	_, out, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "a.txt",
		Source: &filesystem.FileSource{Literal: want},
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	ack := asFilesystemAck(t, out.Data)
	if ack["path"] != "a.txt" {
		t.Errorf("upload.path: got %v, want a.txt", ack["path"])
	}
	if ack["uploaded"] != true {
		t.Errorf("upload.uploaded: got %v, want true", ack["uploaded"])
	}

	_, out2, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "read",
		Path:   "a.txt",
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := asFilesystemBytes(t, out2.Data)
	if string(got) != want {
		t.Errorf("read: got %q, want %q", string(got), want)
	}
}

// TestMCP_ManageFilesystem_DeleteLastRef verifies the dedup contract:
// uploading identical content to two paths creates one backing blob
// referenced twice; deleting one path must keep the other readable
// (the blob is only deleted when the last ref is removed). Per CLAUDE.md
// testing policy §6: this is the concurrency/dedup correctness assertion,
// not just a happy-path delete.
func TestMCP_ManageFilesystem_DeleteLastRef(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	shared := "shared-content"
	for _, p := range []string{"a.txt", "b.txt"} {
		if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
			Action: "upload",
			Path:   p,
			Source: &filesystem.FileSource{Literal: shared},
		}); err != nil {
			t.Fatalf("upload %s: %v", p, err)
		}
	}

	// Delete a.txt. The blob should NOT be deleted because b.txt still
	// references it.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "delete",
		Path:   "a.txt",
	}); err != nil {
		t.Fatalf("delete a.txt: %v", err)
	}

	// b.txt must still be readable + correct content.
	_, out, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "read",
		Path:   "b.txt",
	})
	if err != nil {
		t.Fatalf("read b.txt after delete a.txt: %v", err)
	}
	got := asFilesystemBytes(t, out.Data)
	if string(got) != shared {
		t.Errorf("b.txt after delete a.txt: got %q, want %q (dedup blob must survive)", string(got), shared)
	}

	// Now delete b.txt — this is the last ref; the blob should be gone.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "delete",
		Path:   "b.txt",
	}); err != nil {
		t.Fatalf("delete b.txt: %v", err)
	}

	// Reading b.txt now must fail with ErrNotFound (mapped to MCP error).
	_, _, err = env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "read",
		Path:   "b.txt",
	})
	if err == nil {
		t.Fatal("read deleted b.txt: expected error, got nil")
	}
	if !errors.Is(err, filesystem.ErrNotFound) && !strings.Contains(err.Error(), "not found") {
		t.Errorf("read deleted b.txt: err=%v, want ErrNotFound", err)
	}
}

// TestMCP_ManageFilesystem_RmdirRecursive verifies mkdir + recursive rmdir:
// mkdir a nested directory, upload a file inside it, rmdir recursive, and
// verify the directory and file are gone. Per CLAUDE.md testing policy §2:
// exercises the recursive-removal failure path (non-recursive rmdir on the
// non-empty dir must fail with ErrNotEmpty before we use recursive=true).
func TestMCP_ManageFilesystem_RmdirRecursive(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	// Mkdir root/sub.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "root/sub",
	}); err != nil {
		t.Fatalf("mkdir root/sub: %v", err)
	}

	// Upload a file inside the directory.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "root/sub/file.txt",
		Source: &filesystem.FileSource{Literal: "data"},
	}); err != nil {
		t.Fatalf("upload root/sub/file.txt: %v", err)
	}

	// Non-recursive rmdir on root/sub must fail with ErrNotEmpty (the
	// directory contains file.txt). This is the failure-path test the
	// testing policy requires.
	_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "rmdir",
		Path:   "root/sub",
	})
	if err == nil {
		t.Fatal("non-recursive rmdir on non-empty dir: expected ErrNotEmpty, got nil")
	}
	if !errors.Is(err, filesystem.ErrNotEmpty) && !strings.Contains(err.Error(), "not empty") {
		t.Errorf("non-recursive rmdir: err=%v, want ErrNotEmpty", err)
	}

	// Recursive rmdir on root must succeed and remove everything.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action:    "rmdir",
		Path:      "root",
		Recursive: true,
	}); err != nil {
		t.Fatalf("recursive rmdir root: %v", err)
	}

	// Query root must now fail (ErrNotFound mapped to MCP error).
	_, _, err = env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "query",
		Path:   "root",
	})
	if err == nil {
		t.Fatal("query removed root: expected error, got nil")
	}
	if !errors.Is(err, filesystem.ErrNotFound) && !strings.Contains(err.Error(), "not found") {
		t.Errorf("query removed root: err=%v, want ErrNotFound", err)
	}
}

// TestMCP_ManageFilesystem_MkdirIdempotent verifies that calling mkdir on
// an existing directory is a no-op (returns success), and that calling
// mkdir on a path occupied by a file returns ErrExists. Per CLAUDE.md
// testing policy §2: both paths (idempotent success + file-collision
// failure) must be exercised, not just the happy path.
func TestMCP_ManageFilesystem_MkdirIdempotent(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	// First mkdir succeeds.
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "d",
	}); err != nil {
		t.Fatalf("mkdir d: %v", err)
	}

	// Second mkdir on same path is idempotent (no-op, returns success).
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "d",
	}); err != nil {
		t.Errorf("mkdir d idempotent: got %v, want nil", err)
	}

	// Upload a file at "f.txt", then mkdir on "f.txt" must fail with
	// ErrExists (refuse to silently mask the file with a directory).
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "f.txt",
		Source: &filesystem.FileSource{Literal: "x"},
	}); err != nil {
		t.Fatalf("upload f.txt: %v", err)
	}
	_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "f.txt",
	})
	if err == nil {
		t.Fatal("mkdir on existing file: expected ErrExists, got nil")
	}
	if !errors.Is(err, filesystem.ErrExists) && !strings.Contains(err.Error(), "already exists") {
		t.Errorf("mkdir on existing file: err=%v, want ErrExists", err)
	}
}

// TestMCP_ManageFilesystem_List verifies list returns entries with the
// expected names and types (file vs dir), and skips internal .meta/blobs
// directories. Per CLAUDE.md testing policy §5: asserts observable values
// (entry names, is_dir flags), not just "didn't panic".
func TestMCP_ManageFilesystem_List(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	// Upload two files at root and one in a subdir.
	for _, p := range []string{"a.txt", "b.txt"} {
		if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
			Action: "upload",
			Path:   p,
			Source: &filesystem.FileSource{Literal: "x"},
		}); err != nil {
			t.Fatalf("upload %s: %v", p, err)
		}
	}
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "sub",
	}); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "sub/c.txt",
		Source: &filesystem.FileSource{Literal: "y"},
	}); err != nil {
		t.Fatalf("upload sub/c.txt: %v", err)
	}

	// List root.
	_, out, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "list",
		Path:   ".",
	})
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	var listEnv struct {
		Path     string                   `json:"path"`
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listEnv); err != nil {
		t.Fatalf("list envelope: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// Must contain a.txt, b.txt, sub; must NOT contain .meta or blobs.
	names := make(map[string]bool)
	for _, e := range listEnv.Entries {
		// Entry paths from filesystem.List are forward-slash joined under
		// the listed directory; for root list, they're just the entry name.
		n, _ := e["name"].(string)
		names[n] = true
	}
	if !names["a.txt"] {
		t.Errorf("list root missing a.txt: entries=%v", names)
	}
	if !names["b.txt"] {
		t.Errorf("list root missing b.txt: entries=%v", names)
	}
	if !names["sub"] {
		t.Errorf("list root missing sub: entries=%v", names)
	}
	if names[".meta"] {
		t.Errorf("list root leaked .meta (internal): entries=%v", names)
	}
	if names["blobs"] {
		t.Errorf("list root leaked blobs (internal): entries=%v", names)
	}

	// Find sub and verify it's reported as a directory.
	var subEntry map[string]interface{}
	for _, e := range listEnv.Entries {
		if n, _ := e["name"].(string); n == "sub" {
			subEntry = e
			break
		}
	}
	if subEntry == nil {
		t.Fatal("sub not in root listing")
	}
	if subEntry["is_dir"] != true {
		t.Errorf("sub.is_dir: got %v, want true", subEntry["is_dir"])
	}

	// List sub. Must contain c.txt only.
	_, out2, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "list",
		Path:   "sub",
	})
	if err != nil {
		t.Fatalf("list sub: %v", err)
	}
	var subEnv struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.Unmarshal(asRaw(out2.Data), &subEnv); err != nil {
		t.Fatalf("list sub envelope: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	if len(subEnv.Entries) != 1 {
		t.Fatalf("list sub: got %d entries, want 1", len(subEnv.Entries))
	}
	if name, _ := subEnv.Entries[0]["name"].(string); !strings.HasSuffix(name, "c.txt") {
		t.Errorf("list sub entry: got name %q, want suffix c.txt", name)
	}
}

// TestMCP_ManageFilesystem_Query verifies query returns metadata for both
// a file (size, sha256, is_dir=false) and a directory (is_dir=true). Per
// CLAUDE.md testing policy §5: asserts the actual values, not just that
// the call succeeded.
func TestMCP_ManageFilesystem_Query(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	want := "query me"
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "q.txt",
		Source: &filesystem.FileSource{Literal: want},
	}); err != nil {
		t.Fatalf("upload q.txt: %v", err)
	}
	if _, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "mkdir",
		Path:   "qd",
	}); err != nil {
		t.Fatalf("mkdir qd: %v", err)
	}

	// Query file.
	_, out, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "query",
		Path:   "q.txt",
	})
	if err != nil {
		t.Fatalf("query q.txt: %v", err)
	}
	var fi filesystem.FileInfo
	if err := json.Unmarshal(asRaw(out.Data), &fi); err != nil {
		t.Fatalf("query q.txt envelope: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if fi.IsDir {
		t.Errorf("q.txt.is_dir: got true, want false")
	}
	if fi.Size != int64(len(want)) {
		t.Errorf("q.txt.size: got %d, want %d", fi.Size, len(want))
	}
	if fi.SHA256 == "" {
		t.Errorf("q.txt.sha256: got empty, want non-empty")
	}

	// Query directory.
	_, out2, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "query",
		Path:   "qd",
	})
	if err != nil {
		t.Fatalf("query qd: %v", err)
	}
	var di filesystem.FileInfo
	if err := json.Unmarshal(asRaw(out2.Data), &di); err != nil {
		t.Fatalf("query qd envelope: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	if !di.IsDir {
		t.Errorf("qd.is_dir: got false, want true")
	}
}

// TestMCP_ManageFilesystem_InvalidAction verifies an unknown action returns
// InvalidParams with the supported-action list. Per CLAUDE.md testing policy
// §2 (failure paths): a bogus action must produce a clean error, not a
// silent success or a generic panic.
func TestMCP_ManageFilesystem_InvalidAction(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "bogus",
		Path:   "a.txt",
	})
	if err == nil {
		t.Fatal("invalid action: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("invalid action err: got %v, want mention of 'invalid action'", err)
	}
}

// TestMCP_ManageFilesystem_MissingPath verifies every action rejects an
// empty path with InvalidParams BEFORE hitting the filesystem layer.
// Per CLAUDE.md testing policy §3 (each code path has a test): the path
// pre-validation is its own guard, separate from the filesystem's
// cleanRelPath check, and needs its own test.
func TestMCP_ManageFilesystem_MissingPath(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	for _, action := range []string{"upload", "read", "delete", "mkdir", "rmdir", "list", "query"} {
		t.Run(action, func(t *testing.T) {
			in := manageFilesystemInput{Action: action}
			if action == "upload" {
				in.Source = &filesystem.FileSource{Literal: "x"}
			}
			_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, in)
			if err == nil {
				t.Fatalf("action %q with empty path: expected error, got nil", action)
			}
			if !strings.Contains(err.Error(), "path is required") {
				t.Errorf("action %q with empty path: err=%v, want 'path is required'", action, err)
			}
		})
	}
}

// TestMCP_ManageFilesystem_NotConfigured verifies the handler returns a
// clear error when filesystem is not wired (s.filesystem == nil). This
// guards against a regression where the tool is registered but the
// filesystem is missing — the LLM would see "filesystem not configured"
// instead of a nil-deref panic.
func TestMCP_ManageFilesystem_NotConfigured(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// No SetFilesystem call — s.filesystem is nil.
	_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "list",
		Path:   ".",
	})
	if err == nil {
		t.Fatal("expected error for nil filesystem, got nil")
	}
	if !strings.Contains(err.Error(), "filesystem not configured") {
		t.Errorf("nil filesystem err: got %v, want 'filesystem not configured'", err)
	}
}

// TestMCP_ManageFilesystem_UploadMissingSource verifies the upload action
// rejects a nil source with InvalidParams (the LLM cannot send upload
// without a source). Per CLAUDE.md testing policy §2 (failure paths).
func TestMCP_ManageFilesystem_UploadMissingSource(t *testing.T) {
	env, _ := setupMCPWithFS(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageFilesystem(context.Background(), nil, manageFilesystemInput{
		Action: "upload",
		Path:   "a.txt",
		// Source intentionally nil.
	})
	if err == nil {
		t.Fatal("upload without source: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "source is required") {
		t.Errorf("upload without source: err=%v, want 'source is required'", err)
	}
}
