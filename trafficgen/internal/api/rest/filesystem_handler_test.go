package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	"gorm.io/gorm"
)

// newFSServer creates a REST Server wired with a real filesystem and an
// in-memory SQLite DB (the auth middleware dereferences s.db.DB during
// setupRoutes, so we cannot pass nil). A minimal engine is created so
// NewTaskHandler does not dereference a nil *core.Engine when it
// installs engine callbacks. The filesystem routes are mounted under
// /api/v1/fs/* without auth (filesystem has its own root-scoped path
// validation; auth isolation is layered on later).
func newFSServer(t *testing.T) (*Server, *filesystem.Filesystem) {
	t.Helper()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New err=%v", err)
	}
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/fs_test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	if err := engine.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { engine.Stop() })
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "test"},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}
	srv := NewServer(cfg, engine, nil, db, nil, nil)
	srv.SetFilesystem(fs)
	if err := srv.Setup(); err != nil {
		t.Fatalf("Setup err=%v", err)
	}
	return srv, fs
}

// fsEnvelope is the Response{Code,Message,Data} envelope shared by all
// /api/v1/fs/* JSON endpoints. Raw-bytes endpoints (Download) and
// no-body endpoints (Upload/Mkdir/Delete/Rmdir) do not use it.
type fsEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
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
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "X"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
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
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "A"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	if err := fs.Mkdir(ctx, "sub"); err != nil {
		t.Fatalf("Mkdir err=%v", err)
	}
	req := httptest.NewRequest("GET", "/api/v1/fs/list?path=.", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list status got %d", w.Code)
	}
	var resp struct {
		Code    int                       `json:"code"`
		Message string                   `json:"message"`
		Data    []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("envelope code got %d, want 0", resp.Code)
	}
	if resp.Message != "success" {
		t.Fatalf("envelope message got %q, want %q", resp.Message, "success")
	}
	if resp.Data == nil {
		t.Fatalf("envelope data missing: body=%s", w.Body.String())
	}
	names := map[string]bool{}
	for _, e := range resp.Data {
		name, ok := e["name"].(string)
		if !ok {
			t.Fatalf("entry has no string name: %+v", e)
		}
		names[name] = true
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
		t.Fatalf("mkdir status got %d, want 201; body=%s", w.Code, w.Body.String())
	}
	// Rmdir recursive
	req2 := httptest.NewRequest("DELETE", "/api/v1/fs/dirs/a?recursive=true", nil)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	if w2.Code != 204 {
		t.Fatalf("rmdir status got %d, want 204; body=%s", w2.Code, w2.Body.String())
	}
}

// TestFSHandler_Download_NotFound_404 verifies the error envelope is
// returned with a 404 status when the path does not exist.
func TestFSHandler_Download_NotFound_404(t *testing.T) {
	srv, _ := newFSServer(t)
	req := httptest.NewRequest("GET", "/api/v1/fs/files/missing.txt?op=download", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp fsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 404 {
		t.Fatalf("envelope code got %d, want 404", resp.Code)
	}
	if resp.Message == "" {
		t.Fatalf("envelope message empty: body=%s", w.Body.String())
	}
}

// TestFSHandler_Info_NotFound_404 verifies the same status mapping on
// the Info path (the prior implementation returned 404 for all errors;
// now ErrNotFound -> 404 and other fs errors take their proper status).
func TestFSHandler_Info_NotFound_404(t *testing.T) {
	srv, _ := newFSServer(t)
	req := httptest.NewRequest("GET", "/api/v1/fs/files/missing.txt?op=info", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp fsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 404 {
		t.Fatalf("envelope code got %d, want 404", resp.Code)
	}
}

// TestFSHandler_Mkdir_ExistingFile_409 verifies that Mkdir on a path
// already occupied by a file returns ErrExists -> 409 Conflict (not
// 500, and not silently masking the file).
func TestFSHandler_Mkdir_ExistingFile_409(t *testing.T) {
	srv, fs := newFSServer(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "X"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	req := httptest.NewRequest("POST", "/api/v1/fs/dirs/a.txt", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp fsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 409 {
		t.Fatalf("envelope code got %d, want 409", resp.Code)
	}
}

// TestFSHandler_Rmdir_NonEmptyNonRecursive_409 verifies that Rmdir
// without ?recursive=true on a non-empty directory returns
// ErrNotEmpty -> 409 Conflict.
func TestFSHandler_Rmdir_NonEmptyNonRecursive_409(t *testing.T) {
	srv, fs := newFSServer(t)
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "sub"); err != nil {
		t.Fatalf("Mkdir err=%v", err)
	}
	if err := fs.Upload(ctx, "sub/inner.txt", filesystem.FileSource{Literal: "Y"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	req := httptest.NewRequest("DELETE", "/api/v1/fs/dirs/sub", nil) // no recursive=true
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp fsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 409 {
		t.Fatalf("envelope code got %d, want 409", resp.Code)
	}
}

// TestFSHandler_UnknownOp_400 verifies the ?op= dispatch returns a
// 400 BadRequest envelope for unknown op values (not via respondFsError
// since this is not a filesystem error).
func TestFSHandler_UnknownOp_400(t *testing.T) {
	srv, fs := newFSServer(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "a.txt", filesystem.FileSource{Literal: "X"}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	req := httptest.NewRequest("GET", "/api/v1/fs/files/a.txt?op=delete", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp fsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	if resp.Code != 400 {
		t.Fatalf("envelope code got %d, want 400", resp.Code)
	}
	if resp.Message == "" || !contains(resp.Message, "unknown op") {
		t.Fatalf("envelope message unexpected: %q", resp.Message)
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
