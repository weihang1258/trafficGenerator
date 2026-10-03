package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// uploadRequest builds a multipart POST request for the upload endpoint.
func uploadRequest(t *testing.T, method, url, pcapPath string, withFile bool) *http.Request {
	t.Helper()
	var body io.Reader
	ct := "application/json"
	if withFile {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", "up.pcap")
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(pcapPath)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(b)
		mw.Close()
		body = &buf
		ct = mw.FormDataContentType()
	}
	req, _ := http.NewRequest(method, url, body)
	req.Header.Set("Content-Type", ct)
	return req
}

// POST /uploads/pcaps：multipart "file" → 上传+解析+注册一步完成，返回
// ready 资产；缺 file → 400；非 POST → 405；注册后可经公开直链取回。
func TestUploadPcapHandler(t *testing.T) {
	srv := newTransportTestServer(t)
	pcapPath := filepath.Join(t.TempDir(), "up.pcap")
	writeTestPcap(t, pcapPath)

	post := func(method string, withFile bool) *http.Response {
		req := uploadRequest(t, method, "http://h/uploads/pcaps", pcapPath, withFile)
		w := httptest.NewRecorder()
		srv.uploadPcapHandler(w, req)
		return w.Result()
	}

	resp := post(http.MethodPost, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload status = %d, want 200: %s", resp.StatusCode, b)
	}
	var asset map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&asset); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id, _ := asset["ID"].(string)
	if id == "" {
		t.Fatalf("asset ID missing: %v", asset)
	}
	if asset["Status"] != "ready" {
		t.Errorf("asset status = %v, want ready", asset["Status"])
	}

	if resp := post(http.MethodPost, false); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing file: status = %d, want 400", resp.StatusCode)
	}
	if resp := post(http.MethodGet, false); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", resp.StatusCode)
	}

	// 注册后的资产可经公开直链取回（读方向免鉴权，与下载语义一致）。
	pub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest.ServePcapPublic(srv.db, w, r)
	}))
	defer pub.Close()
	got, err := http.Get(pub.URL + "/downloads/pcaps/" + id + "/download")
	if err != nil {
		t.Fatalf("public download: %v", err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Errorf("public download status = %d, want 200", got.StatusCode)
	}
	if cd := got.Header.Get("Content-Disposition"); !strings.Contains(cd, "up.pcap") {
		t.Errorf("Content-Disposition = %q", cd)
	}
}
