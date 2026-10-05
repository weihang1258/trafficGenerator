package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// P0-1（2026-10-05 客户端复测）：config 内嵌 flow_control 必须生效——层链
// config 是唯一配置真相。此前内嵌键全仓库无消费者，一律静默走 flows:1 缺省，
// 客户端 flows=2000/bps=50000 的声明全部失效（P0-2 的"静默 coerce"同源于此）。
// 语义：顶层参数显式给定时覆盖内嵌；内嵌非法值走与顶层同一 schemaGate 拒绝。

const embeddedFCChain = `{"layers":[{"ip":{"src":"10.9.0.1","dst":"10.9.0.2"}},{"udp":{"dst_port":53}},{"dns":{"name":"embfc.example"}}]}`

// flows>1 的用例用动态 src（静态四元组 + flows>1 被 static-copy 门拒，是既有语义）。
const embeddedFCDynChain = `{"layers":[{"ip":{"src":{"strategy":"rand","range":["10.9.0.1","10.9.0.254"]},"dst":"10.9.0.2"}},{"udp":{"dst_port":53}},{"dns":{"name":"embfc.example"}}]}`

// postStrategyBody POSTs a raw strategy body and returns (status, body string).
func postStrategyBody(t *testing.T, r *gin.Engine, body string) (int, string) {
	t.Helper()
	w := postStrategy(t, r, body)
	return w.Code, w.Body.String()
}

func strategyIDFromBody(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil || parsed.Data.ID == "" {
		t.Fatalf("parse strategy id from %s: %v", body, err)
	}
	return parsed.Data.ID
}

func storedFlowControl(t *testing.T, db *storage.DB, id string) string {
	t.Helper()
	var s storage.StrategyModel
	if err := db.Where("id = ?", id).First(&s).Error; err != nil {
		t.Fatalf("load strategy %s: %v", id, err)
	}
	return s.FlowControl
}

// 内嵌 flows=3 → 策略行落 {"type":"flows","value":3}，执行层 spec.Count=3。
func TestEmbeddedFlowControl_FlowsStored(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-flows","protocol":"dns","config":{"flow_control":{"type":"flows","value":3},%s}}`, embeddedFCDynChain[1:]))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, resp)
	}
	stored := storedFlowControl(t, db, strategyIDFromBody(t, resp))
	var fc struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	}
	if err := json.Unmarshal([]byte(stored), &fc); err != nil {
		t.Fatalf("stored flow_control not JSON: %q", stored)
	}
	if fc.Type != "flows" || fc.Value != 3 {
		t.Errorf("embedded flows=3 must be stored, got %q", stored)
	}
}

// 内嵌 bps=50000 → 落 bps（客户端 D-01 的 bps 声明）。
func TestEmbeddedFlowControl_BPSStored(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-bps","protocol":"dns","config":{"flow_control":{"type":"bps","value":50000},%s}}`, embeddedFCChain[1:]))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, resp)
	}
	stored := storedFlowControl(t, db, strategyIDFromBody(t, resp))
	if !strings.Contains(stored, "bps") || !strings.Contains(stored, "50000") {
		t.Errorf("embedded bps=50000 must be stored, got %q", stored)
	}
}

// 顶层参数显式给定时覆盖内嵌（顶层优先）。
func TestTopLevelFlowControlOverridesEmbedded(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-override","protocol":"dns","flow_control":{"type":"flows","value":5},"config":{"flow_control":{"type":"flows","value":3},%s}}`, embeddedFCDynChain[1:]))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, resp)
	}
	stored := storedFlowControl(t, db, strategyIDFromBody(t, resp))
	if !strings.Contains(stored, "5") || strings.Contains(stored, "3") {
		t.Errorf("top-level flows=5 must override embedded flows=3, got %q", stored)
	}
}

// 内嵌非法 type → 与顶层同文案拒绝（不再静默）。
func TestEmbeddedFlowControlInvalidTypeRejected(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-fps","protocol":"dns","config":{"flow_control":{"type":"fps","value":10},%s}}`, embeddedFCDynChain[1:]))
	if code != http.StatusBadRequest {
		t.Errorf("embedded type=fps must be rejected with 400, got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "must be flows, bps, or time") {
		t.Errorf("rejection must carry the canonical gate text, got: %s", resp)
	}
}

// 内嵌 value<=0 → 拒绝（顶层 binding 的 required 语义对内嵌由 gate 承接）。
func TestEmbeddedFlowControlNonPositiveRejected(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-zero","protocol":"dns","config":{"flow_control":{"type":"flows","value":0},%s}}`, embeddedFCDynChain[1:]))
	if code != http.StatusBadRequest {
		t.Errorf("embedded value=0 must be rejected with 400, got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "positive") {
		t.Errorf("rejection must mention positivity, got: %s", resp)
	}
}

// 两处都没有 → 保持缺省 flows:1（既有行为不变）。
func TestNoFlowControlAnywhereKeepsDefault(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(`{"name":"emb-none","protocol":"dns","config":%s}`, embeddedFCChain))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, resp)
	}
	stored := storedFlowControl(t, db, strategyIDFromBody(t, resp))
	if !strings.Contains(stored, `"flows"`) || !strings.Contains(stored, "1") {
		t.Errorf("default flows:1 must be kept, got %q", stored)
	}
}

// update（全量替换）带内嵌 fc、顶层省略 → 内嵌生效（与 create 同一规则）。
func TestEmbeddedFlowControlOnUpdate(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	sid := createStrategy(t, r, "dns", embeddedFCDynChain, "")
	body := fmt.Sprintf(`{"name":"emb-update","protocol":"dns","config":{"flow_control":{"type":"flows","value":7},%s}}`, embeddedFCDynChain[1:])
	req := httptest.NewRequest("PUT", "/strategies/"+sid, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	stored := storedFlowControl(t, db, sid)
	if !strings.Contains(stored, "7") {
		t.Errorf("update must store embedded flows=7, got %q", stored)
	}
}

// 语料兼容简写 {"flows":N}（protocol-pcap cases 惯例，116 例）等价规范形。
func TestEmbeddedFlowControlShorthand(t *testing.T) {
	r, db, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	code, resp := postStrategyBody(t, r, fmt.Sprintf(
		`{"name":"emb-short","protocol":"dns","config":{"flow_control":{"flows":2},%s}}`, embeddedFCDynChain[1:]))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, resp)
	}
	stored := storedFlowControl(t, db, strategyIDFromBody(t, resp))
	if !strings.Contains(stored, `"flows"`) || !strings.Contains(stored, "2") {
		t.Errorf("shorthand {\"flows\":2} must normalize to flows:2, got %q", stored)
	}
}
