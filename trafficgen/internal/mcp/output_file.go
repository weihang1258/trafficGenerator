package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// Data-fetch tools accept output_path: the model decides per call whether a
// result is returned inline or written to a server-side file (huge extracts,
// stream bodies and long lists would otherwise flood the model context).
// The receipt is tiny — {written_to, bytes, export_id, download_url?}. The
// export registry lets HTTP clients fetch the written file back through
// GET /downloads/exports/<uuid> (uuid = capability token, same model as the
// other /downloads/* links); only registered files resolve, so arbitrary
// server paths stay unreadable. stdio clients read written_to directly and
// get no URL (transport rule).

const maxExportEntries = 256

var exportRegistry = struct {
	mu    sync.Mutex
	paths map[string]string
	order []string
}{paths: map[string]string{}}

func registerExport(path string) string {
	id := uuid.New().String()
	exportRegistry.mu.Lock()
	defer exportRegistry.mu.Unlock()
	exportRegistry.paths[id] = path
	exportRegistry.order = append(exportRegistry.order, id)
	if len(exportRegistry.order) > maxExportEntries {
		for _, old := range exportRegistry.order[:len(exportRegistry.order)-maxExportEntries] {
			delete(exportRegistry.paths, old)
		}
		exportRegistry.order = exportRegistry.order[len(exportRegistry.order)-maxExportEntries:]
	}
	return id
}

// applyOutputPath writes data to outPath (model-specified absolute server
// path, parents auto-created) and returns the small receipt payload. The
// receipt carries download_url so the transport adapter (taskDataForTransport)
// rewrites it to an absolute URL over HTTP and strips it for stdio — same
// rule as every other artifact reference.
func (s *Server) applyOutputPath(ctx context.Context, outPath string, data json.RawMessage) (json.RawMessage, error) {
	if outPath == "" {
		return data, nil
	}
	if !filepath.IsAbs(outPath) {
		return nil, fmt.Errorf("output_path must be an absolute server-side path (got %q)", outPath)
	}
	clean := filepath.Clean(outPath)
	if clean != outPath {
		return nil, fmt.Errorf("output_path must be a clean absolute path without '..' (got %q)", outPath)
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	if err := os.WriteFile(clean, data, 0o644); err != nil {
		return nil, fmt.Errorf("write output file: %w", err)
	}
	id := registerExport(clean)
	receipt, _ := json.Marshal(map[string]interface{}{
		"written_to":   clean,
		"bytes":        len(data),
		"export_id":    id,
		"download_url": "/downloads/exports/" + id,
		"note":         "full result written to the file; fetch via download_url (HTTP) or read written_to directly (local)",
	})
	return receipt, nil
}

// ServeExportPublic serves GET /downloads/exports/<uuid> for files registered
// by applyOutputPath. Unregistered or malformed ids are a uniform 404.
func ServeExportPublic(w http.ResponseWriter, r *http.Request) {
	const prefix = "/downloads/exports/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if id == "" || id != filepath.Base(id) {
		http.NotFound(w, r)
		return
	}
	exportRegistry.mu.Lock()
	path, ok := exportRegistry.paths[id]
	exportRegistry.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="export-`+id[:8]+`.json"`)
	http.ServeFile(w, r, path)
}
