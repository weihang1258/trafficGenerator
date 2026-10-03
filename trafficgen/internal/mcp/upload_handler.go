package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// uploadPcapHandler serves POST /uploads/pcaps (multipart field "file") on
// the MCP HTTP port — remote MCP clients (e.g. Claude Code on another host)
// register a pcap in one curl: the file is saved and run through the same
// import pipeline as flowb_manage_pcaps action=import (hash dedup, parse,
// flows/packets), returning the ready asset. X-MCP-Key auth applies (this
// is a write path — unlike the read-only /downloads/* links, it must not
// be unauthenticated).
func (s *Server) uploadPcapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed (POST only)", http.StatusMethodNotAllowed)
		return
	}
	// Hard cap mirrors the REST upload (§15.6: 2GB). Multipart parsing
	// spills to disk above 32MB, so memory stays bounded for small files.
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "multipart field 'file' is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Land the upload under its original (sanitized) name so ImportFromPath
	// derives the asset name from it, not from a random temp name.
	name := filepath.Base(hdr.Filename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "upload.pcap"
	}
	tmpDir, err := os.MkdirTemp("", "tg-upload-*")
	if err != nil {
		http.Error(w, "create temp dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpName := filepath.Join(tmpDir, name)
	dst, err := os.Create(tmpName)
	if err != nil {
		http.Error(w, "create temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		http.Error(w, "save upload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := dst.Close(); err != nil {
		http.Error(w, "save upload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Same import pipeline as the manage_pcaps import action: hash dedup,
	// parse, flows/packets. Asset belongs to the MCP service account —
	// the same owner the tool actions use.
	asset, err := rest.NewPcapHandler(s.db, "").ImportFromPath(s.serviceUserID, tmpName)
	if err != nil {
		http.Error(w, "import failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+hdr.Filename+`"`)
	json.NewEncoder(w).Encode(asset)
}
