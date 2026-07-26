package main

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestInitServer_FilesystemRoutesReachable verifies the production wiring
// path: app.initServer() calls rest.NewServer → SetFilesystem → Setup in
// the right order. If SetFilesystem is called AFTER Setup (or skipped
// entirely due to a nil-guard regression), the /api/v1/fs/* routes are
// reachable but the handler returns "filesystem not configured" -- the
// existing TestFSHandler_* tests bypass this path by constructing
// rest.NewServer directly, so they would stay green even if initServer
// broke. This test drives the real path: it builds a minimal Application
// with a wired filesystem, calls initServer, and probes /api/v1/fs/list
// to assert the routes are mounted and the filesystem is reachable.
func TestInitServer_FilesystemRoutesReachable(t *testing.T) {
	fsRoot := t.TempDir()
	fs, err := filesystem.New(fsRoot)
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	// Pre-populate so List has something to return.
	if err := fs.Upload(t.Context(), "hello.txt", filesystem.FileSource{Literal: "hi"}); err != nil {
		t.Fatalf("seed Upload: %v", err)
	}

	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/initserver_test.db"), &gorm.Config{})
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
		Filesystem: config.FilesystemConfig{Root: fsRoot},
	}

	app := &Application{
		config:     cfg,
		engine:     engine,
		db:         db,
		filesystem: fs,
	}
	if err := app.initServer(); err != nil {
		t.Fatalf("initServer: %v", err)
	}
	if app.server == nil {
		t.Fatal("initServer did not set app.server")
	}

	// Path "." is rejected by cleanRelPath; List accepts a non-empty
	// relative path that does not resolve to root itself. We uploaded
	// hello.txt at the root, so we can't List "/" — instead List the
	// file directly via Query, which is also wired by initServer.
	req := httptest.NewRequest("GET", "/api/v1/fs/files/hello.txt?op=info", nil)
	w := httptest.NewRecorder()
	app.server.Router().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/v1/fs/files/hello.txt?op=info status got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Sanity-check the Response envelope shape. If SetFilesystem was
	// skipped (e.g. nil-guard regression), the handler returns a 500
	// "filesystem not configured" envelope and this body assertion fails.
	if !bytes.Contains(w.Body.Bytes(), []byte(`"code":0`)) {
		t.Fatalf("response body does not look like a success envelope: %s", w.Body.String())
	}
}
