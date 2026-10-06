package rest

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// OBS-1（2026-10-06 客户端反馈）：query_system action=protocols 与
// query_layers action=examples 两处协议清单不一致——前者 = planner 注册面
//（含纯传输层 udp、无 cwmp），后者 = case 语料面（含 cwmp、无 udp）。
// 对齐口径（用户裁定）：两边同为"可生成的应用协议"——注册面补 cwmp 别名
// planner（main.go），清单面剔除纯传输层 udp（tcp 有语料用例，保留）。
func TestGetProtocolsExcludesTransportOnlyUDP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	eng := core.NewEngine(core.EngineConfig{})
	eng.RegisterPlanner(layers.NewChainPlanner("tcp"))
	eng.RegisterPlanner(layers.NewChainPlanner("udp"))
	eng.RegisterPlanner(layers.NewChainPlanner("cwmp"))
	eng.RegisterPlanner(layers.NewChainPlanner("http"))
	h := NewSystemHandler(eng)
	r := gin.New()
	r.GET("/system/protocols", h.GetProtocols)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/system/protocols", nil))
	var resp struct {
		Code int      `json:"code"`
		Data []string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	got := map[string]bool{}
	for _, p := range resp.Data {
		got[p] = true
	}
	if got["udp"] {
		t.Errorf("udp must not be listed (transport-only layer, has no corpus examples; it remains a valid chain layer)")
	}
	if !got["cwmp"] {
		t.Errorf("cwmp must be listed (corpus-facing alias planner)")
	}
	if !got["tcp"] || !got["http"] {
		t.Errorf("tcp/http must stay listed, got %v", resp.Data)
	}
}
