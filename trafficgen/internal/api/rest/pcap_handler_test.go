package rest

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gorm.io/gorm"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// writePcapForREST builds a small pcap file for handler tests.
func writePcapForREST(t *testing.T, path string) {
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, SYN: true, Window: 65535}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp, gopacket.Payload([]byte("hello")))
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	w.WritePacket(ci, buf.Bytes())
	f.Close()
}

// newPcapTestServer creates a handler + gin engine with a test DB and data dir.
func newPcapTestServer(t *testing.T) (*PcapHandler, *gin.Engine, *storage.DB) {
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
	r.POST("/pcaps", h.Import)
	r.GET("/pcaps", h.List)
	r.GET("/pcaps/:id", h.Get)
	r.DELETE("/pcaps/:id", h.Delete)
	r.GET("/pcaps/:id/flows", h.ListFlows)
	r.GET("/pcaps/:id/flows/:fid/packets", h.ListPackets)
	r.GET("/pcaps/:id/packets/:pid", h.GetPacket)
	r.POST("/pcaps/:id/search", h.Search)
	return h, r, db
}

// TestPcapHandler_ImportListGetDelete exercises the asset lifecycle.
func TestPcapHandler_ImportListGetDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, r, _ := newPcapTestServer(t)

	// Build a pcap to upload.
	pcapPath := filepath.Join(t.TempDir(), "upload.pcap")
	writePcapForREST(t, pcapPath)

	// Import via multipart upload.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "upload.pcap")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	data, _ := os.ReadFile(pcapPath)
	part.Write(data)
	writer.Close()
	req := httptest.NewRequest("POST", "/pcaps", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("import status = %d, body = %s", w.Code, w.Body.String())
	}
	var importResp struct {
		Data storage.PcapAssetModel `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &importResp); err != nil {
		t.Fatalf("unmarshal import: %v, body=%s", err, w.Body.String())
	}
	asset := importResp.Data
	if asset.Status != "ready" {
		t.Errorf("status = %q, want ready", asset.Status)
	}
	if asset.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1", asset.FlowCount)
	}
	assetID := asset.ID

	// List.
	req = httptest.NewRequest("GET", "/pcaps", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), assetID) {
		t.Errorf("list body missing asset id: %s", w.Body.String())
	}

	// Get.
	req = httptest.NewRequest("GET", "/pcaps/"+assetID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get status = %d", w.Code)
	}

	// List flows.
	req = httptest.NewRequest("GET", "/pcaps/"+assetID+"/flows", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list flows status = %d, body=%s", w.Code, w.Body.String())
	}
	var flowsResp struct {
		Data struct {
			Items []storage.FlowModel `json:"items"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &flowsResp)
	if len(flowsResp.Data.Items) != 1 {
		t.Fatalf("flows = %d, want 1", len(flowsResp.Data.Items))
	}
	flowID := flowsResp.Data.Items[0].ID

	// List packets for the flow.
	req = httptest.NewRequest("GET", "/pcaps/"+assetID+"/flows/"+flowID+"/packets", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list packets status = %d, body=%s", w.Code, w.Body.String())
	}
	var pktsResp struct {
		Data struct {
			Items []storage.PacketModel `json:"items"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &pktsResp)
	if len(pktsResp.Data.Items) != 1 {
		t.Fatalf("packets = %d, want 1", len(pktsResp.Data.Items))
	}
	pid := pktsResp.Data.Items[0].ID

	// Get packet (dynamic re-parse -> layers).
	req = httptest.NewRequest("GET", "/pcaps/"+assetID+"/packets/"+pid, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get packet status = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ipv4") || !strings.Contains(w.Body.String(), "tcp") {
		t.Errorf("get packet missing layers: %s", w.Body.String())
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/pcaps/"+assetID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("delete status = %d, body=%s", w.Code, w.Body.String())
	}
	// Verify gone.
	req = httptest.NewRequest("GET", "/pcaps/"+assetID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("get-after-delete status = %d, want 404", w.Code)
	}
}

// TestPcapHandler_Dedup verifies importing the same file twice returns the same asset.
func TestPcapHandler_Dedup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, r, _ := newPcapTestServer(t)
	pcapPath := filepath.Join(t.TempDir(), "dup.pcap")
	writePcapForREST(t, pcapPath)
	data, _ := os.ReadFile(pcapPath)

	importOnce := func() string {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "dup.pcap")
		part.Write(data)
		writer.Close()
		req := httptest.NewRequest("POST", "/pcaps", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp struct {
			Data storage.PcapAssetModel `json:"data"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		return resp.Data.ID
	}
	id1 := importOnce()
	id2 := importOnce()
	if id1 != id2 {
		t.Errorf("dedup failed: %s vs %s", id1, id2)
	}
}
