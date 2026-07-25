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
	var entries []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal err=%v; body=%s", err, w.Body.String())
	}
	names := map[string]bool{}
	for _, e := range entries {
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
