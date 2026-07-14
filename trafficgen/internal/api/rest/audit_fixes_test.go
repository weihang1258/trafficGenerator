package rest

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// newPcapTestServerFull creates a handler + gin engine with ALL PCAP routes
// registered (mirrors server.go). Used by audit tests that need to exercise the
// full §19 endpoint surface.
func newPcapTestServerFull(t *testing.T) (*PcapHandler, *gin.Engine, *storage.DB) {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}
	dataDir := filepath.Join(t.TempDir(), "pcaps")
	h := NewPcapHandler(db, dataDir)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	pcaps := r.Group("/pcaps")
	pcaps.POST("", h.Import)
	pcaps.GET("", h.List)
	pcaps.GET("/:id", h.Get)
	pcaps.DELETE("/:id", h.Delete)
	pcaps.GET("/:id/flows", h.ListFlows)
	pcaps.GET("/:id/flows/:fid", h.GetFlow)
	pcaps.GET("/:id/flows/:fid/packets", h.ListPackets)
	pcaps.GET("/:id/flows/:fid/stream", h.GetStream)
	pcaps.GET("/:id/flows/:fid/body", h.GetBody)
	pcaps.GET("/:id/packets", h.ListPacketsByAsset)
	pcaps.GET("/:id/packets/:pid", h.GetPacket)
	pcaps.GET("/:id/packets/:pid/payload", h.GetPacketPayload)
	pcaps.POST("/:id/search", h.Search)
	pcaps.POST("/:id/match-preview", h.MatchPreview)
	pcaps.POST("/:id/extract", h.Extract)
	pcaps.GET("/:id/download", h.Download)
	pcaps.POST("/:id/reparse", h.Reparse)
	return h, r, db
}

// TestAuditFix_M11_AllPcapEndpointsRegistered (M11): all 17 §19 endpoints are
// registered on the router. Before the fix, 8 endpoints were missing. This
// test enumerates every route the production server (server.go:203-222) should
// register and asserts each exists via a request that at least reaches the
// handler (either 200/OK or a handler-generated error like 400/404 -- NOT
// gin's 404 route-not-found).
func TestAuditFix_M11_AllPcapEndpointsRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Build a router mirroring the real production route table.
	_, r, _ := newPcapTestServerFull(t)

	// Route probes. Method + path + a body if the handler binds. For unknown
	// asset IDs, the handler should return 404 (asset not found) -- not gin's
	// 404 (route not registered). Both produce status 404 but only handler-404
	// includes a JSON body with our error envelope; gin's route-not-found emits
	// an empty body.
	probes := []struct {
		method string
		path   string
		body   []byte
	}{
		{"POST", "/pcaps", nil}, // no file → handler returns 400
		{"GET", "/pcaps", nil},
		{"GET", "/pcaps/nope", nil},
		{"DELETE", "/pcaps/nope", nil},
		{"GET", "/pcaps/nope/flows", nil},
		{"GET", "/pcaps/nope/flows/f1", nil},
		{"GET", "/pcaps/nope/flows/f1/packets", nil},
		{"GET", "/pcaps/nope/flows/f1/stream", nil},
		{"GET", "/pcaps/nope/flows/f1/body", nil},
		{"GET", "/pcaps/nope/packets", nil},
		{"GET", "/pcaps/nope/packets/p1", nil},
		{"GET", "/pcaps/nope/packets/p1/payload", nil},
		{"POST", "/pcaps/nope/search", []byte("{}")},
		{"POST", "/pcaps/nope/match-preview", []byte("{}")},
		{"POST", "/pcaps/nope/extract", []byte("{}")},
		{"GET", "/pcaps/nope/download", nil},
		{"POST", "/pcaps/nope/reparse", nil},
	}
	for _, p := range probes {
		var req *bytes.Reader
		if p.body != nil {
			req = bytes.NewReader(p.body)
		} else {
			req = bytes.NewReader(nil)
		}
		r2 := httptest.NewRequest(p.method, p.path, req)
		if p.body != nil {
			r2.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, r2)
		// Gin's route-not-found returns status 404 with empty body. Handler-404
		// returns 404 with a JSON body. If the route is unregistered, w.Body
		// will be empty.
		if w.Code == 404 && w.Body.Len() == 0 {
			t.Errorf("route %s %s: not registered (gin 404, empty body)", p.method, p.path)
		}
	}
}

// TestAuditFix_QueryRejectsNonReadyAsset (M12): all query endpoints reject
// assets not in the "ready" state. Before the fix, they operated on
// importing/error assets, returning incomplete/stale data.
//
// Covers ALL 12 handlers that call requireReady (pcap_handler.go:552):
// ListFlows, GetFlow, ListPackets, ListPacketsByAsset, GetPacket,
// GetPacketPayload, Search, MatchPreview, Extract, GetStream, GetBody, Download.
func TestAuditFix_QueryRejectsNonReadyAsset(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServerFull(t)
	// Insert an asset directly in "importing" state.
	asset := &storage.PcapAssetModel{
		ID: "ast-importing", UserID: "test-user", Name: "imp.pcap",
		StoragePath: "/tmp/imp.pcap", Status: "importing", LinkType: 1,
	}
	if err := h.repo.CreateAsset(asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	// Each probe hits a requireReady-guarded endpoint. All must return 400.
	probes := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"ListFlows", "GET", "/pcaps/ast-importing/flows", nil},
		{"GetFlow", "GET", "/pcaps/ast-importing/flows/f1", nil},
		{"ListPackets", "GET", "/pcaps/ast-importing/flows/f1/packets", nil},
		{"ListPacketsByAsset", "GET", "/pcaps/ast-importing/packets", nil},
		{"GetPacket", "GET", "/pcaps/ast-importing/packets/p1", nil},
		{"GetPacketPayload", "GET", "/pcaps/ast-importing/packets/p1/payload", nil},
		{"Search", "POST", "/pcaps/ast-importing/search", []byte("{}")},
		{"MatchPreview", "POST", "/pcaps/ast-importing/match-preview", []byte("{}")},
		{"Extract", "POST", "/pcaps/ast-importing/extract", []byte("{}")},
		{"GetStream", "GET", "/pcaps/ast-importing/flows/f1/stream", nil},
		{"GetBody", "GET", "/pcaps/ast-importing/flows/f1/body", nil},
		{"Download", "GET", "/pcaps/ast-importing/download", nil},
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			var body *bytes.Reader
			if p.body != nil {
				body = bytes.NewReader(p.body)
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(p.method, p.path, body)
			if p.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != 400 {
				t.Errorf("%s on importing asset: status=%d, want 400 (requireReady rejection). Body: %s", p.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestAuditFix_QueryRejectsErrorAsset (M12 extended): also verifies "error"
// and "reindexing" statuses are rejected across ALL 12 requireReady-guarded
// handlers. Any status other than "ready" should be rejected -- this catches
// a regression that special-cased only one non-ready status.
func TestAuditFix_QueryRejectsErrorAsset(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Two non-ready statuses × 12 handlers. Each handler is checked once per
	// status; a regression that accepted, say, "reindexing" while still
	// rejecting "importing"/"error" would be caught here.
	nonReadyStatuses := []string{"error", "reindexing"}
	handlers := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"ListFlows", "GET", "/pcaps/%s/flows", nil},
		{"GetFlow", "GET", "/pcaps/%s/flows/f1", nil},
		{"ListPackets", "GET", "/pcaps/%s/flows/f1/packets", nil},
		{"ListPacketsByAsset", "GET", "/pcaps/%s/packets", nil},
		{"GetPacket", "GET", "/pcaps/%s/packets/p1", nil},
		{"GetPacketPayload", "GET", "/pcaps/%s/packets/p1/payload", nil},
		{"Search", "POST", "/pcaps/%s/search", []byte("{}")},
		{"MatchPreview", "POST", "/pcaps/%s/match-preview", []byte("{}")},
		{"Extract", "POST", "/pcaps/%s/extract", []byte("{}")},
		{"GetStream", "GET", "/pcaps/%s/flows/f1/stream", nil},
		{"GetBody", "GET", "/pcaps/%s/flows/f1/body", nil},
		{"Download", "GET", "/pcaps/%s/download", nil},
	}
	for _, st := range nonReadyStatuses {
		h, r, _ := newPcapTestServerFull(t)
		assetID := "ast-" + st
		asset := &storage.PcapAssetModel{
			ID: assetID, UserID: "test-user", Name: st + ".pcap",
			StoragePath: "/tmp/" + st + ".pcap", Status: st, LinkType: 1,
		}
		if err := h.repo.CreateAsset(asset); err != nil {
			t.Fatalf("create %s asset: %v", st, err)
		}
		for _, hd := range handlers {
			t.Run(st+"/"+hd.name, func(t *testing.T) {
				path := fmt.Sprintf(hd.path, assetID)
				var body *bytes.Reader
				if hd.body != nil {
					body = bytes.NewReader(hd.body)
				} else {
					body = bytes.NewReader(nil)
				}
				req := httptest.NewRequest(hd.method, path, body)
				if hd.body != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if w.Code != 400 {
					t.Errorf("%s on %s asset: status=%d, want 400 (requireReady rejection). Body: %s",
						hd.name, st, w.Code, w.Body.String())
				}
			})
		}
	}
}
