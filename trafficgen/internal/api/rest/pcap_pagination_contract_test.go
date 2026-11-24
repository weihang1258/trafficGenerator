package rest

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// assertSizeMatchesItems 只适用于 size=0（全量）的响应：那时 size 必须回实际
// 条数，否则 {"items":[3 条],"size":0} 自相矛盾。
//
// 不适用于 size>0 的普通分页——那时 size 回显请求的页大小是对的，本页只
// 有 1 条也要回 20，因为 total/page/size 三者要能算出页数。
func assertSizeMatchesItems(t *testing.T, p pcapPageBody, label string) {
	t.Helper()
	if p.Size != len(p.Items) {
		t.Errorf("%s: size = %d while returning %d items — with size=0 (ALL) the "+
			"response must report the actual count, not the 0 sentinel",
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
//
// 断言必须是**具体的默认值**，不能只判 `size != 0`：垃圾输入被当成全量时
// size 会回实际条数（3），同样 != 0，只判非零的写法两种行为都放行。
// 这里按端点各自的默认值（assets 20 / flows 50 / packets 50）钉死。
func TestPcapList_GarbageSizeFallsBackToDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-g", "flow-g", 3)

	cases := []struct {
		path      string
		label     string
		wantSize  int // 该端点的默认页大小
		wantItems int // seedAssetWithFlowsAndPackets 造 1 资产 / 1 流 / n 包
	}{
		{"/pcaps?size=abc", "GET /pcaps?size=abc", 20, 1},
		{"/pcaps/ast-g/flows?size=abc", "GET /pcaps/:id/flows?size=abc", 50, 1},
		{"/pcaps/ast-g/flows/flow-g/packets?size=abc", "GET .../packets?size=abc", 50, 3},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", tc.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data struct {
				Size  int               `json:"size"`
				Items []json.RawMessage `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.label, err)
		}
		if body.Data.Size != tc.wantSize {
			t.Errorf("%s: size = %d, want the endpoint default %d — a non-numeric "+
				"size must fall back to the default, not be treated as ALL (%d means "+
				"no LIMIT and would dump the whole library)",
				tc.label, body.Data.Size, tc.wantSize, 0)
		}
		if len(body.Data.Items) != tc.wantItems {
			t.Errorf("%s: items = %d, want %d (fixture rows)", tc.label, len(body.Data.Items), tc.wantItems)
		}
	}
}

// TestPcapList_NegativeSizeFallsBackToDefault 覆盖 size 负数。负数不是
// "全量"的另一种写法：不拦住的话 repo 的 `size > 0` 守卫会跳过 LIMIT，
// 整库被拉出，而响应还回显 size:-1。
func TestPcapList_NegativeSizeFallsBackToDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	seedAssetWithFlowsAndPackets(t, h, "ast-neg", "flow-neg", 3)

	cases := []struct {
		path     string
		label    string
		wantSize int
	}{
		{"/pcaps?size=-1", "GET /pcaps?size=-1", 20},
		{"/pcaps/ast-neg/flows?size=-1", "GET /pcaps/:id/flows?size=-1", 50},
		{"/pcaps/ast-neg/flows/flow-neg/packets?size=-1", "GET .../packets?size=-1", 50},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", tc.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data struct {
				Size  int               `json:"size"`
				Items []json.RawMessage `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.label, err)
		}
		if body.Data.Size != tc.wantSize {
			t.Errorf("%s: size = %d, want %d — a negative size must fall back to the "+
				"endpoint default", tc.label, body.Data.Size, tc.wantSize)
		}
		wantItems := 1
		if tc.label == "GET .../packets?size=-1" {
			wantItems = 3
		}
		if len(body.Data.Items) != wantItems {
			t.Errorf("%s: items = %d, want %d (fixture rows)", tc.label, len(body.Data.Items), wantItems)
		}
	}
}

// TestListEndpoints_NonPositivePageFallsBackToOne 覆盖 page 的非正数/非数字
// 输入：必须归一成第 1 页，不能把 page 原样透传（page=0 时 offset 变负）。
func TestListEndpoints_NonPositivePageFallsBackToOne(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	for i := 0; i < 3; i++ {
		if err := db.Create(&storage.TaskModel{
			ID: fmt.Sprintf("pg-%d", i), UserID: "test-user", Name: "x", Status: "completed",
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	for _, q := range []string{"?page=0", "?page=-5", "?page=abc"} {
		req := httptest.NewRequest("GET", "/tasks"+q, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data struct {
				Page  int               `json:"page"`
				Size  int               `json:"size"`
				Items []json.RawMessage `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: unmarshal: %v", q, err)
		}
		if body.Data.Page != 1 {
			t.Errorf("%s: page = %d, want 1 (non-positive/garbage page normalizes "+
				"to the first page)", q, body.Data.Page)
		}
		if len(body.Data.Items) == 0 {
			t.Errorf("%s: items = 0, want the first page's rows", q)
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

// TestPcapSearch_L7FiltersReachTheWire 覆盖分层集成：flow_filter 的
// L7Method/L7Host/L7QueryName 必须真的筛掉不匹配的流。这三个字段在
// FlowFilter 里声明了、REST 也透传了，但匹配侧从来没读过——传进去等于
// 静默通配（客户端 2026-11-23 报告问题 2 的同型缺陷）。单测只覆盖
// pcapparser.matchFlow，这里补 REST → 存储投影 → 匹配 的整条链路。
func TestPcapSearch_L7FiltersReachTheWire(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	if err := h.repo.CreateAsset(&storage.PcapAssetModel{
		ID: "ast-search", UserID: "test-user", Name: "s.pcap", Status: "ready",
		LinkType: 1, FileHash: "hash-search",
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	seed := []storage.FlowModel{
		{ID: "s-get", L4Protocol: "tcp", L7Protocol: "http", L7Method: "GET", L7Host: "a.example.com"},
		{ID: "s-post", L4Protocol: "tcp", L7Protocol: "http", L7Method: "POST", L7Host: "b.example.com"},
		{ID: "s-dns", L4Protocol: "udp", L7Protocol: "dns", L7QueryName: "c.example.com"},
	}
	for _, f := range seed {
		f.PcapAssetID = "ast-search"
		f.UserID = "test-user"
		f.SrcIP, f.DstIP = "10.0.0.1", "10.0.0.2"
		if err := h.db.Create(&f).Error; err != nil {
			t.Fatalf("create flow %s: %v", f.ID, err)
		}
	}

	search := func(filterJSON string) []string {
		t.Helper()
		req := httptest.NewRequest("POST", "/pcaps/ast-search/search",
			strings.NewReader(`{"flow_filter":`+filterJSON+`}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("search %s: status=%d body=%s", filterJSON, w.Code, w.Body.String())
		}
		var body struct {
			Data []struct {
				Flow struct {
					ID string `json:"ID"`
				} `json:"Flow"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("search %s: unmarshal: %v (body=%.200s)", filterJSON, err, w.Body.String())
		}
		ids := make([]string, len(body.Data))
		for i, d := range body.Data {
			ids[i] = d.Flow.ID
		}
		return ids
	}

	if got := search(`{"L7Method":"POST"}`); len(got) != 1 || got[0] != "s-post" {
		t.Errorf("L7Method=POST -> %v, want [s-post]", got)
	}
	if got := search(`{"L7Host":"a.example.com"}`); len(got) != 1 || got[0] != "s-get" {
		t.Errorf("L7Host -> %v, want [s-get]", got)
	}
	if got := search(`{"L7QueryName":"c.example.com"}`); len(got) != 1 || got[0] != "s-dns" {
		t.Errorf("L7QueryName -> %v, want [s-dns]", got)
	}
}

// TestPcapLists_PageTwoReturnsSecondSlice 覆盖"分页偏移真的对"——现有 pcap
// 测试只断言回显字段和 total，不校验返回的是不是第 2 页的行。把
// PageOffset 的 (page-1)*size 写成 page*size，这些测试依然绿。
//
// 三个 pcap 列表端点各造 5 行，取 size=2 的第 2 页，断言拿到的正是第 3、4 行。
func TestPcapLists_PageTwoReturnsSecondSlice(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPcapTestServer(t)
	r.GET("/pcaps/:id/packets", h.ListPacketsByAsset)

	// 5 个资产，file_hash 唯一（有 (user_id, file_hash) 唯一索引）。
	for i := 0; i < 5; i++ {
		if cerr := h.repo.CreateAsset(&storage.PcapAssetModel{
			ID: fmt.Sprintf("pg-asset-%d", i), UserID: "test-user",
			Name: "p.pcap", Status: "ready", LinkType: 1,
			FileHash: fmt.Sprintf("hash-pg-%d", i),
		}); cerr != nil {
			t.Fatalf("create asset %d: %v", i, cerr)
		}
	}
	// 一条流 + 5 个包，按 index_in_flow 升序。
	if err := h.db.Create(&storage.FlowModel{
		ID: "pg-flow", PcapAssetID: "pg-asset-0", UserID: "test-user",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, L4Protocol: "tcp",
	}).Error; err != nil {
		t.Fatalf("create flow: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := h.db.Create(&storage.PacketModel{
			ID: fmt.Sprintf("pg-pkt-%d", i), PcapAssetID: "pg-asset-0",
			FlowID: "pg-flow", UserID: "test-user", L4Protocol: "tcp",
			Length: 64, TimestampUs: int64(1000 + i), IndexInFlow: i,
		}).Error; err != nil {
			t.Fatalf("create packet %d: %v", i, err)
		}
	}

	type page struct {
		Items []json.RawMessage `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
		Size  int               `json:"size"`
	}
	get := func(path string) page {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: status=%d body=%s", path, w.Code, w.Body.String())
		}
		var body struct {
			Data page `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: unmarshal: %v", path, err)
		}
		return body.Data
	}

	// 资产列表按 created_at DESC, id DESC：第 2 页（size=2）应是第 3、4 行。
	assets := get("/pcaps?page=2&size=2")
	if len(assets.Items) != 2 {
		t.Fatalf("assets page 2: %d items, want 2", len(assets.Items))
	}
	if assets.Total != 5 {
		t.Errorf("assets total = %d, want 5", assets.Total)
	}
	// 内容正确性：第 1 页与第 2 页的 id 不能重叠，合起来应当是全部 5 个。
	first := get("/pcaps?page=1&size=2")
	seen := map[string]bool{}
	for _, it := range append(first.Items, assets.Items...) {
		var a storage.PcapAssetModel
		if err := json.Unmarshal(it, &a); err != nil {
			t.Fatalf("unmarshal asset: %v", err)
		}
		if seen[a.ID] {
			t.Errorf("asset %s appears on both page 1 and page 2 — the offset is wrong", a.ID)
		}
		seen[a.ID] = true
	}
	if len(seen) != 4 {
		t.Errorf("pages 1+2 covered %d distinct rows, want 4", len(seen))
	}

	// 包列表按 index_in_flow ASC：第 2 页应是 index 2、3。
	pkts := get("/pcaps/pg-asset-0/flows/pg-flow/packets?page=2&size=2")
	if len(pkts.Items) != 2 {
		t.Fatalf("packets page 2: %d items, want 2", len(pkts.Items))
	}
	for i, it := range pkts.Items {
		var p storage.PacketModel
		if err := json.Unmarshal(it, &p); err != nil {
			t.Fatalf("unmarshal packet: %v", err)
		}
		if want := 2 + i; p.IndexInFlow != want {
			t.Errorf("packets page 2 item %d: index_in_flow = %d, want %d — page 2 "+
				"must start at the (page-1)*size-th row", i, p.IndexInFlow, want)
		}
	}
}
