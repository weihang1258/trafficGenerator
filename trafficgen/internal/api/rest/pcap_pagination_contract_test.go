package rest

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// pcap 四个列表端点的分页口径（客户端 2026-11-23 报告问题 3 的同型缺陷，
// 当时只修了 task 的 List/History）。
//
// 契约：size=0 是"全量"哨兵（不加 LIMIT），响应里的 size 必须回**实际
// 返回条数**，而不是原样回 0——否则 {"items":[N 条],"size":0} 自相矛盾，
// 按 size 判断分页的调用方会误判为没有数据。MCP 侧 tools_pcap.go 在 size
// 省略时**强制发送 "0"**，所以这是每个 pcap list 调用的默认路径。

// pcapPageBody 是分页响应的公共形状。
type pcapPageBody struct {
	Items []json.RawMessage `json:"items"`
	Page  int               `json:"page"`
	Size  int               `json:"size"`
	Total int64             `json:"total"`
}

func parsePcapPage(t *testing.T, body []byte) pcapPageBody {
	t.Helper()
	code, msg, data := parseResponse(t, body)
	if code != 0 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
	var p pcapPageBody
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v data=%s", err, string(data))
	}
	return p
}

// assertSizeMatchesItems 校验 size 回显与实际条数一致（size>0 的普通分页
// 也适用：size 应等于本页实际条数，除非恰好满页）。
func assertSizeMatchesItems(t *testing.T, p pcapPageBody, label string) {
	t.Helper()
	if p.Size != len(p.Items) {
		t.Errorf("%s: size = %d while returning %d items — size must reflect the "+
			"actual page size (0 means all; report the count, not the sentinel)",
			label, p.Size, len(p.Items))
	}
}

// TestPcapList_SizeZeroReportsActualCount 覆盖资产列表。
func TestPcapList_SizeZeroReportsActualCount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	// file_hash 有 (user_id, file_hash) 唯一索引，逐条写不同的哈希值；
	// 插入错误必须检查，否则唯一约束失败会静默少行（本测试最初就踩了）。
	for i := 0; i < 3; i++ {
		if err := h.repo.CreateAsset(&storage.PcapAssetModel{
			ID: "ast-z" + string(rune('a'+i)), UserID: "test-user",
			Name: "z.pcap", Status: "ready", LinkType: 1,
			FileHash: fmt.Sprintf("hash-%d", i),
		}); err != nil {
			t.Fatalf("create asset %d: %v", i, err)
		}
	}

	req := httptest.NewRequest("GET", "/pcaps?size=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	p := parsePcapPage(t, w.Body.Bytes())
	if len(p.Items) != 3 {
		t.Fatalf("precondition: got %d items, want 3", len(p.Items))
	}
	assertSizeMatchesItems(t, p, "GET /pcaps?size=0")
}

// TestPcapListFlows_SizeZeroReportsActualCount 覆盖 flow 列表。
func TestPcapListFlows_SizeZeroReportsActualCount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	if err := h.repo.CreateAsset(&storage.PcapAssetModel{
		ID: "ast-f", UserID: "test-user", Name: "f.pcap",
		Status: "ready", LinkType: 1,
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	for i := 0; i < 3; i++ {
		h.db.Create(&storage.FlowModel{
			ID: "flow-z" + string(rune('a'+i)), PcapAssetID: "ast-f",
			UserID: "test-user", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: uint16(1000 + i), DstPort: 80, L4Protocol: "tcp",
		})
	}

	req := httptest.NewRequest("GET", "/pcaps/ast-f/flows?size=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	p := parsePcapPage(t, w.Body.Bytes())
	if len(p.Items) != 3 {
		t.Fatalf("precondition: got %d flows, want 3 (body=%.200s)", len(p.Items), w.Body.String())
	}
	assertSizeMatchesItems(t, p, "GET /pcaps/:id/flows?size=0")
}

// seedAssetWithFlowsAndPackets 造一个资产 + 1 条流 + n 个包，返回资产 id 与流 id。
func seedAssetWithFlowsAndPackets(t *testing.T, h *PcapHandler, assetID, flowID string, n int) {
	t.Helper()
	if err := h.repo.CreateAsset(&storage.PcapAssetModel{
		ID: assetID, UserID: "test-user", Name: assetID + ".pcap",
		Status: "ready", LinkType: 1, FileHash: "hash-" + assetID,
	}); err != nil {
		t.Fatalf("create asset %s: %v", assetID, err)
	}
	if err := h.db.Create(&storage.FlowModel{
		ID: flowID, PcapAssetID: assetID, UserID: "test-user",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 80,
		L4Protocol: "tcp",
	}).Error; err != nil {
		t.Fatalf("create flow %s: %v", flowID, err)
	}
	for i := 0; i < n; i++ {
		if err := h.db.Create(&storage.PacketModel{
			ID: fmt.Sprintf("%s-p%02d", flowID, i), PcapAssetID: assetID,
			FlowID: flowID, UserID: "test-user", L4Protocol: "tcp",
			Length: 64, TimestampUs: int64(1000 + i), IndexInFlow: i,
		}).Error; err != nil {
			t.Fatalf("create packet %d: %v", i, err)
		}
	}
}

// TestPcapListPackets_SizeZeroReportsActualCount 覆盖按流查包。
func TestPcapListPackets_SizeZeroReportsActualCount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-p", "flow-p", 3)

	req := httptest.NewRequest("GET", "/pcaps/ast-p/flows/flow-p/packets?size=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	p := parsePcapPage(t, w.Body.Bytes())
	if len(p.Items) != 3 {
		t.Fatalf("precondition: got %d packets, want 3 (body=%.200s)", len(p.Items), w.Body.String())
	}
	assertSizeMatchesItems(t, p, "GET /pcaps/:id/flows/:fid/packets?size=0")
}

// TestPcapListPacketsByAsset_SizeZeroReportsActualCount 覆盖按资产查包
// （newPcapTestServer 没有注册该路由，这里自建路由器，保持与生产
// server.go 同形）。
func TestPcapListPacketsByAsset_SizeZeroReportsActualCount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-a", "flow-a", 3)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/pcaps/:id/packets", h.ListPacketsByAsset)

	req := httptest.NewRequest("GET", "/pcaps/ast-a/packets?size=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	p := parsePcapPage(t, w.Body.Bytes())
	if len(p.Items) != 3 {
		t.Fatalf("precondition: got %d packets, want 3 (body=%.200s)", len(p.Items), w.Body.String())
	}
	assertSizeMatchesItems(t, p, "GET /pcaps/:id/packets?size=0")
}

// TestPcapGetStream_OffsetOutOfRangeIsEmpty 覆盖流式读取的 offset 越界：
// 越界必须回空体（调用方明确要"第 N 字节之后"），不得静默忽略 offset 后
// 回整条流——那会让"读尾巴"的调用方拿到头部数据还以为读对了。
func TestPcapGetStream_OffsetOutOfRangeIsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	payloads := filepath.Join(tmp, "ast-s.payloads")
	if err := os.WriteFile(payloads, []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("write payloads: %v", err)
	}
	h, r, _ := newPcapTestServer(t)
	r.GET("/pcaps/:id/flows/:fid/stream", h.GetStream)
	if err := h.repo.CreateAsset(&storage.PcapAssetModel{
		ID: "ast-s", UserID: "test-user", Name: "s.pcap", Status: "ready",
		LinkType: 1, FileHash: "hash-s", PayloadsPath: payloads,
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := h.db.Create(&storage.FlowModel{
		ID: "flow-s", PcapAssetID: "ast-s", UserID: "test-user",
		L4Protocol: "tcp", C2SOffset: 0, C2SLength: 10,
	}).Error; err != nil {
		t.Fatalf("create flow: %v", err)
	}

	cases := []struct {
		query string
		want  string
	}{
		{"", "0123456789"},           // 无 range = 整条流
		{"?offset=4", "456789"},      // 中段
		{"?offset=10", ""},           // 恰好等于长度 → 空
		{"?offset=99", ""},           // 越界 → 空，不是整条流
		{"?offset=4&limit=3", "456"}, // 中段带限长
		{"?limit=999", "0123456789"}, // limit 超长 → 整条流
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/pcaps/ast-s/flows/flow-s/stream"+tc.query, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("%q: status=%d body=%s", tc.query, w.Code, w.Body.String())
			continue
		}
		if got := w.Body.String(); got != tc.want {
			t.Errorf("%q: body = %q, want %q", tc.query, got, tc.want)
		}
	}
}

// TestPcapGetStream_BadRangeIs400 覆盖非法 offset/limit：语法错误必须报错，
// 不能被当成"没给"而回整条流。
func TestPcapGetStream_BadRangeIs400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	payloads := filepath.Join(tmp, "ast-b.payloads")
	if err := os.WriteFile(payloads, []byte("abcdefghij"), 0o644); err != nil {
		t.Fatalf("write payloads: %v", err)
	}
	h, r, _ := newPcapTestServer(t)
	r.GET("/pcaps/:id/flows/:fid/stream", h.GetStream)
	if err := h.repo.CreateAsset(&storage.PcapAssetModel{
		ID: "ast-b", UserID: "test-user", Name: "b.pcap", Status: "ready",
		LinkType: 1, FileHash: "hash-b", PayloadsPath: payloads,
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := h.db.Create(&storage.FlowModel{
		ID: "flow-b", PcapAssetID: "ast-b", UserID: "test-user",
		L4Protocol: "tcp", C2SOffset: 0, C2SLength: 10,
	}).Error; err != nil {
		t.Fatalf("create flow: %v", err)
	}

	for _, q := range []string{"?offset=abc", "?offset=-1", "?limit=0", "?limit=xyz"} {
		req := httptest.NewRequest("GET", "/pcaps/ast-b/flows/flow-b/stream"+q, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("%q: status=%d, want 400 (body=%q)", q, w.Code, w.Body.String())
		}
	}
}
// 回端点默认值，不得当成"全量"（否则一个手滑的 `size=abc` 就把全库拉出来）。
// 三条同形端点一起校验。
func TestPcapList_GarbageSizeFallsBackToDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-g", "flow-g", 3)

	cases := []struct{ path, label string }{
		{"/pcaps?size=abc", "GET /pcaps?size=abc"},
		{"/pcaps/ast-g/flows?size=abc", "GET /pcaps/:id/flows?size=abc"},
		{"/pcaps/ast-g/flows/flow-g/packets?size=abc", "GET .../packets?size=abc"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", tc.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data struct {
				Size int `json:"size"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.label, err)
		}
		if body.Data.Size == 0 {
			t.Errorf("%s: size=0 (treated as ALL) — a non-numeric size must fall "+
				"back to the endpoint default, not pull the whole library", tc.label)
		}
	}
}

// TestPcapList_SizeOverCapClamps 覆盖超上限 size 收敛（不是回默认）。
func TestPcapList_SizeOverCapClamps(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-c", "flow-c", 1)

	req := httptest.NewRequest("GET", "/pcaps?size=99999", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var body struct {
		Data struct {
			Size int `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Data.Size != 200 {
		t.Errorf("size = %d, want 200 (clamped to the assets cap)", body.Data.Size)
	}
}
