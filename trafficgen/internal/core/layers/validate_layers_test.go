package layers

import (
	"encoding/json"
	"strings"
	"testing"
)

// P3 creation-time validation tests. Derived from design §10.2 V1-V10 and
// §14.1 T9-T10/T16-T22: each rule gets a negative case (rejected) plus a
// positive case (accepted), and V9 additionally covers the explicit-0-vs-
// missing semantics of §6.4. Layer entries use the design §3.1 format —
// `[{ "tcp": { "mss": 1460 } }]`, layer name as the key — and JSON payloads
// use float64 (encoding/json) for numeric config values, mirroring the
// production strategy-config shape.

func mustRaw(t *testing.T, s string) json.RawMessage {
	t.Helper()
	return json.RawMessage(s)
}

// T16: empty layers → error; empty layersJSON (absent) → nil (legacy path).
func TestValidateLayers_EmptyChain(t *testing.T) {
	if _, err := ValidateLayers(mustRaw(t, `[]`), ""); err == nil {
		t.Error("empty layers array: expected error, got nil")
	}
	if _, err := ValidateLayers(nil, "tcp"); err != nil {
		t.Errorf("absent layers field (legacy path): expected nil, got %v", err)
	}
}

// T17 (V1): unknown layer name → error.
func TestValidateLayers_UnknownLayer(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"foo":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "unknown layer") {
		t.Errorf("unknown layer: want error mentioning unknown layer, got %v", err)
	}
	// 一条多键（一条里塞两层）→ 拒绝。
	_, err = ValidateLayers(mustRaw(t, `[{"tcp":{},"http":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "exactly one layer") {
		t.Errorf("multi-key entry: want error, got %v", err)
	}
}

// T18 (V2): duplicated terminal layer → error.
func TestValidateLayers_DuplicateTerminal(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"http":{}},{"ip":{}},{"http":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Errorf("duplicate http: want error mentioning duplicated, got %v", err)
	}
}

// T19 (V5): transport as last layer in a multi-layer chain → error.
// 实现把 V4/V5/V6 合并为一条 "must end with a terminal layer" 消息
// （complete.go validateChain，P1 定稿口径），按语义断言 V5 被触发。
func TestValidateLayers_TransportAsLast(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"ip":{}},{"tcp":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "must end with a terminal layer") {
		t.Errorf("[ip,tcp]: want V5 error, got %v", err)
	}
}

// T20 (V6): tunnel as last layer → error.
func TestValidateLayers_TunnelAsLast(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"tls":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "must end with a terminal layer") {
		t.Errorf("[tls]: want V6 error, got %v", err)
	}
	// gre 单层同样被拒（补全后 [ip, gre, ip]，末层是网络层）。
	if _, err := ValidateLayers(mustRaw(t, `[{"gre":{}}]`), ""); err == nil {
		t.Error("[gre]: want V6 error, got nil")
	}
}

// T21 (V9): field out of range → error; explicit 0 accepted (§6.4).
func TestValidateLayers_FieldRange(t *testing.T) {
	// mss 500 < min 536 → rejected.
	_, err := ValidateLayers(mustRaw(t, `[{"tcp":{"mss":500}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "mss") {
		t.Errorf("mss 500: want range error, got %v", err)
	}
	// explicit 0 is a valid request (§6.4: 显式 0 ≠ 缺失; 0 = 用 schema 默认).
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{"mss":0}}]`), ""); err != nil {
		t.Errorf("explicit mss 0: expected nil, got %v", err)
	}
	// absent config keys are not range-checked (schema default fills at R2).
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{}}]`), ""); err != nil {
		t.Errorf("no config: expected nil, got %v", err)
	}
	// unknown field → rejected (防拼写错误).
	_, err = ValidateLayers(mustRaw(t, `[{"tcp":{"mas":500}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field mas: want error, got %v", err)
	}
}

// T22 (V10): protocol mismatching outermost layer → error; matching → nil.
func TestValidateLayers_ProtocolOutermost(t *testing.T) {
	// protocol "gre" vs [tcp,http] chain → mismatch error.
	_, err := ValidateLayers(mustRaw(t, `[{"tcp":{}},{"http":{}}]`), "gre")
	if err == nil || !strings.Contains(err.Error(), "does not match outermost layer") {
		t.Errorf("protocol gre vs http chain: want V10 error, got %v", err)
	}
	// protocol matching outermost → nil.
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{}},{"http":{}}]`), "http"); err != nil {
		t.Errorf("protocol http matching: expected nil, got %v", err)
	}
	// empty protocol → inferred from outermost layer.
	inferred, err := ValidateLayers(mustRaw(t, `[{"http":{}}]`), "")
	if err != nil {
		t.Fatalf("inference: expected nil error, got %v", err)
	}
	if inferred != "http" {
		t.Errorf("inferred protocol = %q, want %q", inferred, "http")
	}
	// legacy flat path (no layers) returns empty inference.
	if inferred, err := ValidateLayers(nil, ""); err != nil || inferred != "" {
		t.Errorf("absent layers: want ('', nil), got (%q, %v)", inferred, err)
	}
}

// V8: hard-dependency completion — a bare [tcp] chain completes to
// [ip, tcp]; a [http] chain completes to [ip, tcp, http].
func TestValidateLayers_DependencyCompletion(t *testing.T) {
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{}}]`), ""); err != nil {
		t.Errorf("bare [tcp]: expected nil (completed [ip,tcp]), got %v", err)
	}
	if _, err := ValidateLayers(mustRaw(t, `[{"http":{}}]`), ""); err != nil {
		t.Errorf("bare [http]: expected nil (completed [ip,tcp,http]), got %v", err)
	}
	// tunnel completion: [tls] is V6-rejected (no inner), but
	// [tls,http] completes to [ip,tcp,tls,http] with tls wrapping http.
	if _, err := ValidateLayers(mustRaw(t, `[{"tls":{}},{"http":{}}]`), ""); err != nil {
		t.Errorf("[tls,http]: expected nil (tls wrapping http), got %v", err)
	}
}

// §6.1 完整示例：gre 链补全后 [ip, gre, ip, tcp, http]，protocol "gre"
// 合法（最外层用户协议层是 gre，外层 ip 是补全插入的脚手架）。
func TestValidateLayers_GreChainOutermost(t *testing.T) {
	// 完整示例链 + protocol "gre" → nil。
	if _, err := ValidateLayers(mustRaw(t, `[{"ip":{"src":"10.0.0.1"}},{"gre":{"key":100}},{"ip":{}},{"tcp":{}},{"http":{}}]`), "gre"); err != nil {
		t.Errorf("[ip,gre,ip,tcp,http] + protocol gre: want nil, got %v", err)
	}
	// 写非最外层用户协议层（http）→ V10 报错。
	if _, err := ValidateLayers(mustRaw(t, `[{"ip":{}},{"gre":{}},{"ip":{}},{"tcp":{}},{"http":{}}]`), "http"); err == nil {
		t.Error("[ip,gre,ip,tcp,http] + protocol http: want V10 error, got nil")
	}
	// protocol 空 → 推断 "gre"（最外层用户协议层）。
	inferred, err := ValidateLayers(mustRaw(t, `[{"ip":{}},{"gre":{}},{"ip":{}},{"tcp":{}},{"http":{}}]`), "")
	if err != nil {
		t.Fatalf("gre chain inference: want nil error, got %v", err)
	}
	if inferred != "gre" {
		t.Errorf("inferred protocol = %q, want %q", inferred, "gre")
	}
}

// 独立传输 flow：[tcp] 单层豁免 V4，推断 "tcp"（全链都是脚手架 → 末层）。
func TestValidateLayers_TransportFlowInference(t *testing.T) {
	inferred, err := ValidateLayers(mustRaw(t, `[{"tcp":{}}]`), "")
	if err != nil {
		t.Fatalf("bare [tcp]: want nil, got %v", err)
	}
	if inferred != "tcp" {
		t.Errorf("inferred protocol = %q, want %q", inferred, "tcp")
	}
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{}}]`), "tcp"); err != nil {
		t.Errorf("[tcp] + protocol tcp: want nil, got %v", err)
	}
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":{}}]`), "udp"); err == nil {
		t.Error("[tcp] + protocol udp: want V10 error, got nil")
	}
}

// V3: duplicated transport layer → error.
func TestValidateLayers_DuplicateTransport(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"tcp":{}},{"tcp":{}},{"http":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Errorf("duplicate tcp: want error, got %v", err)
	}
}

// V8 反序负向用例：http 写在 tcp 外层（反序）。补全给 http 外层再插一个 tcp
// （依赖在外层）→ 用户显式 tcp 落到末层 → V5 拒绝（传输层不能当末层）。
// 反序链无法表达"用户想要的顺序"，拒绝是正确行为。
func TestValidateLayers_ReversedOrder(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"http":{}},{"tcp":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "must end with a terminal layer") {
		t.Errorf("[http,tcp] reversed: want terminal-layer error, got %v", err)
	}
	// http 只支持 tcp，写 udp 反序同样拒绝。
	if _, err := ValidateLayers(mustRaw(t, `[{"http":{}},{"udp":{}}]`), ""); err == nil {
		t.Error("[http,udp]: want error, got nil")
	}
}

// V7: L2 layer inside a tunnel → error; L2 in the outermost run → ok.
func TestValidateLayers_L2Placement(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"ip":{}},{"vlan":{}},{"http":{}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "must be in the outermost run") {
		t.Errorf("[ip,vlan,http]: want V7 error, got %v", err)
	}
	// vlan outermost before ip is fine: [vlan,ip,tcp,http].
	if _, err := ValidateLayers(mustRaw(t, `[{"vlan":{}},{"http":{}}]`), ""); err != nil {
		t.Errorf("[vlan,http] completed: expected nil, got %v", err)
	}
}

// V9 through float64 JSON numbers (production shape): mss 70000 (uint16
// wrap) must be rejected, matching the flat-config truncation guard.
func TestValidateLayers_FieldRangeFloat64(t *testing.T) {
	_, err := ValidateLayers(mustRaw(t, `[{"tcp":{"mss":70000}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "mss") {
		t.Errorf("mss 70000: want range error, got %v", err)
	}
	// non-integer value (1.5) rejected — no silent truncation to pass V9.
	_, err = ValidateLayers(mustRaw(t, `[{"tcp":{"mss":1460.5}}]`), "")
	if err == nil || !strings.Contains(err.Error(), "mss") {
		t.Errorf("mss 1460.5: want range error, got %v", err)
	}
}

// Malformed layers JSON → error.
func TestValidateLayers_MalformedJSON(t *testing.T) {
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp":`), ""); err == nil {
		t.Error("malformed JSON: expected error, got nil")
	}
	if _, err := ValidateLayers(mustRaw(t, `{"not":"an array"}`), ""); err == nil {
		t.Error("non-array JSON: expected error, got nil")
	}
	// 层配置值不是对象 → 拒绝。
	if _, err := ValidateLayers(mustRaw(t, `[{"tcp": 5}]`), ""); err == nil {
		t.Error("non-object layer config: expected error, got nil")
	}
}
