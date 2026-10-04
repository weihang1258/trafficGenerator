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

var maxExportEntries = 256 // var：测试缩小驱逐窗口

// exportsRoot is the server-managed directory for remote/auto exports,
// resolved absolute at startup (stdio receipts hand written_to to a
// same-host client, which cannot know the server process cwd). Tests
// repoint it at a temp dir.
var exportsRoot = func() string {
	abs, err := filepath.Abs(filepath.Join("data", "exports"))
	if err != nil {
		return filepath.Join("data", "exports")
	}
	return abs
}()

// maxInlineResponseBytes is the auto-export threshold (user ruling
// 2026-10-03): data-fetch responses above it become server-managed
// exports answered with a receipt instead of flooding the model context
// (~64 KB JSON ≈ 15-20K tokens; client tool-output truncation sits well
// below the sizes that hurt). Var, not const: tests swap it.
var maxInlineResponseBytes = 64 << 10

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
			p := exportRegistry.paths[old]
			delete(exportRegistry.paths, old)
			// The link is gone either way — remove the backing file too so
			// auto-export cannot grow data/exports without bound. Only
			// server-managed paths are ours to delete; stdio receipts that
			// name a model-chosen absolute path outside exportsRoot stay.
			if strings.HasPrefix(p, exportsRoot+string(filepath.Separator)) {
				os.Remove(p)
			}
		}
		exportRegistry.order = exportRegistry.order[len(exportRegistry.order)-maxExportEntries:]
	}
	return id
}

// sanitizeExportName reduces an arbitrary model-supplied output_path to a
// bare file name. Remote models cannot know server paths (user ruling
// 2026-10-03), so over HTTP the value is only a naming hint; traversal
// strings reduce to their basename and pathological names are rejected.
func sanitizeExportName(name string) (string, error) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return "", fmt.Errorf("output_path needs a usable file name (got %q)", name)
	}
	return base, nil
}

func exportReceipt(target string, data json.RawMessage) json.RawMessage {
	id := registerExport(target)
	m := map[string]interface{}{
		"written_to":   target,
		"bytes":        len(data),
		"export_id":    id,
		"download_url": "/downloads/exports/" + id,
		"note":         "full result written to the file; fetch via download_url (HTTP) or read written_to directly (local)",
	}
	// List-shaped payloads carry their row count in "total" — surface it in
	// the receipt so the caller knows the file's size without fetching it
	// (client audit 2026-10-05: receipt vs items shape confusion).
	var probe struct {
		Total int64 `json:"total"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Total > 0 {
		m["total"] = probe.Total
	}
	receipt, _ := json.Marshal(m)
	return receipt
}

// writeExportFile stores data under exportsRoot as name and returns the
// receipt. Callers keep names unique (uuid prefix) so a later same-name
// export can never clobber an earlier receipt's download link.
func writeExportFile(name string, data json.RawMessage) (json.RawMessage, error) {
	target := filepath.Join(exportsRoot, name)
	if err := os.MkdirAll(exportsRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create exports dir: %w", err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return nil, fmt.Errorf("write export file: %w", err)
	}
	return exportReceipt(target, data), nil
}

// applyOutputPath writes data to a file per the transport: HTTP clients are
// remote — ANY outPath is a file-name hint resolved into exportsRoot (short
// uuid prefix keeps same-name exports distinct); stdio clients share this
// host and must name an absolute, clean path. The receipt carries
// download_url so the transport adapter (taskDataForTransport) rewrites it
// to an absolute URL over HTTP and strips it for stdio — same rule as every
// other artifact reference.
func (s *Server) applyOutputPath(ctx context.Context, outPath string, data json.RawMessage) (json.RawMessage, error) {
	if outPath == "" {
		return data, nil
	}
	if _, isHTTP := ctx.Value(httpTransportKey{}).(string); isHTTP {
		name, err := sanitizeExportName(outPath)
		if err != nil {
			return nil, err
		}
		return writeExportFile(uuid.NewString()[:8]+"-"+name, data)
	}
	if !filepath.IsAbs(outPath) {
		return nil, fmt.Errorf("output_path must be an absolute path — stdio shares this host's filesystem (got %q)", outPath)
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
	return exportReceipt(clean, data), nil
}

// maybeExport applies the auto-export threshold to an inline response:
// above maxInlineResponseBytes the payload moves into a server-managed
// export (label names the tool_action for the file), below it the payload
// passes through untouched. A write failure degrades to inline — the fetch
// itself is healthy; the export is a courtesy, not a reason to fail.
func (s *Server) maybeExport(label string, data json.RawMessage) json.RawMessage {
	if len(data) <= maxInlineResponseBytes {
		return data
	}
	receipt, err := writeExportFile(label+"-"+uuid.NewString()[:8]+".json", data)
	if err != nil {
		return data
	}
	return receipt
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

// autoExportNote is appended to tool descriptions whose payloads can be
// bulk (CORE_MEMORY §13.27: descriptions change with the behavior).
const autoExportNote = " Responses above 64 KB are auto-exported: the reply becomes a small receipt {written_to, bytes, export_id, download_url} — fetch with curl and read the file locally."
