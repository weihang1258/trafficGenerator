package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// D-TLS-2 步骤 0 locking⑤：结构性校验拒绝非法 cert。
func TestDTLS2_TLSCertStructRejects(t *testing.T) {
	cases := []struct {
		name string
		cert string
		want string
	}{
		{"bad key_type", `{"key_type":"rsa-2048"}`, `not supported yet`},
		{"bad date", `{"not_before":"yesterday"}`, `invalid RFC3339 timestamp`},
		{"unknown subkey", `{"bogus":1}`, `unknown field`},
		{"non-object cert", `"oops"`, `must be an object`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lj := `[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":40000,"dst_port":443}},{"tls":{"cert":` + c.cert + `}},{"http":{}}]`
			p, err := layers.BuildLayersPlanner("tls", json.RawMessage(lj))
			if err != nil {
				if !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Build err=%q, want %q", err, c.want)
				}
				return
			}
			_, err = p.Plan(context.Background(), tlsChainSpec())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Plan err=%v, want %q", err, c.want)
			}
		})
	}
}
