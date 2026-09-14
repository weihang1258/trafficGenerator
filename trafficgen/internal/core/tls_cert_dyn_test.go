package core

import (
	"encoding/json"
	"testing"
)

// D-TLS-2 步骤 0 locking⑥：cert subject/san 动态解析与关字段拒绝。
func TestDTLS2_CertDynShapes(t *testing.T) {
	// 开字段：subject list 解析
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"tls": map[string]any{
			"cert": map[string]any{
				"subject": map[string]any{"strategy": "list", "list": []string{"CN=a.test,O=Lab,C=CN", "CN=b.test,O=Lab,C=CN"}},
			},
		}},
	}}, "tls")
	if spec.LayerDyn == nil || spec.LayerDyn.TLS.CertSubject == nil {
		t.Fatalf("want LayerDyn.TLS.CertSubject parsed, got %+v (errs=%v)", spec.LayerDyn, spec.ValidationErrors)
	}
	if got := ResolveStringValue(spec.LayerDyn.TLS.CertSubject, 1); got != "CN=b.test,O=Lab,C=CN" {
		t.Fatalf("index1 subject = %q", got)
	}
	resolveLayerTuple(&spec, 1)
	if spec.TLS == nil || spec.TLS.ServerCertificate == nil || spec.TLS.ServerCertificate.Subject != "CN=b.test,O=Lab,C=CN" {
		t.Fatalf("resolveLayerTuple subject = %+v", spec.TLS)
	}
	mk := func(m map[string]interface{}) *StrategyConfig {
		raw, _ := json.Marshal(m)
		var sc StrategyConfig
		if err := json.Unmarshal(raw, &sc); err != nil {
			t.Fatal(err)
		}
		return &sc
	}
	// 关字段：key_type 对象形状拒绝
	m := map[string]interface{}{"strategy": "list", "list": []interface{}{"ecdsa-p256"}}
	if msg := checkTLSCertDynShape("tls.cert.key_type", "key_type", mk(m)); msg == "" || !containsSub(msg, "does not support dynamic") {
		t.Fatalf("key_type object: want does-not-support-dynamic, got %q", msg)
	}
	// 开字段 string 面：rand 拒绝
	m2 := map[string]interface{}{"strategy": "rand", "range": []interface{}{"a", "b"}}
	if msg := checkTLSCertDynShape("tls.cert.subject", "subject", mk(m2)); msg == "" || !containsSub(msg, "not supported for string field") {
		t.Fatalf("subject/rand: want string-surface rejection, got %q", msg)
	}
}
