package rest

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// P2-6（2026-10-05 客户端复测）：显式 protocol 非法时必须单因报错——此前
// 层链 mismatch 校验与 IsAllowedProtocol 两条分支同时触发，错误拼接成
// "does not match outermost ...; invalid or missing protocol ..."，调用方
// 不知道改哪一处。未知协议（连同指引）单独报，层链校验随后不再叠加。
func TestStrategyCreateUnknownProtocolSingleCause(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	stratUser(r, "u1", "alice")
	r.POST("/strategies", h.Create)

	body := `{"name":"p2-6","protocol":"no_such_proto","config":{"layers":[{"ip":{"src":"10.9.0.1","dst":"10.9.0.2"}},{"udp":{"dst_port":53}},{"dns":{"name":"single.example"}}]}}`
	w := postStrategy(t, r, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown protocol must 400, got %d: %s", w.Code, w.Body.String())
	}
	msg := w.Body.String()
	if !strings.Contains(msg, "invalid or missing protocol: no_such_proto") {
		t.Errorf("error must name the unknown protocol, got: %s", msg)
	}
	if strings.Contains(msg, "does not match outermost") {
		t.Errorf("unknown protocol must be a single-cause error, got dual-cause: %s", msg)
	}
	if !strings.Contains(msg, "flowb_query_layers") {
		t.Errorf("error should point at the discovery action, got: %s", msg)
	}
}
