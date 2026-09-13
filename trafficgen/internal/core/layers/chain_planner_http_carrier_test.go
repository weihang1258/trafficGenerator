package layers_test

// D-HTTP-1 §5 载体检查 5 家补齐：gbt/getwork/hls/hds/http_flv 缺 http 载体
// 在 BuildLayersPlanner 即拒绝（doh TestDOHChainCarrierRejected 同款），
// 锚词 requires the http carrier layer（T-HTTP-3）。
import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doh"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gbt"
	_ "github.com/trafficgen/trafficgen/internal/protocol/getwork"
	_ "github.com/trafficgen/trafficgen/internal/protocol/hds"
	_ "github.com/trafficgen/trafficgen/internal/protocol/hls"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http_flv"
	_ "github.com/trafficgen/trafficgen/internal/protocol/onvif"
)

func TestHTTPCarrierRequired_FiveFamilies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layers []map[string]map[string]interface{}
	}{
		{"gbt", []map[string]map[string]interface{}{{"ip": {}}, {"tcp": {}}, {"gbt": {}}}},
		{"getwork", []map[string]map[string]interface{}{{"ip": {}}, {"tcp": {}}, {"getwork": {}}}},
		{"hls", []map[string]map[string]interface{}{{"tcp": {}}, {"hls": {}}}},
		{"hds", []map[string]map[string]interface{}{{"tcp": {}}, {"hds": {}}}},
		{"http_flv", []map[string]map[string]interface{}{{"ip": {}}, {"tcp": {}}, {"http_flv": {}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.layers)
			if err != nil {
				t.Fatalf("marshal layers: %v", err)
			}
			_, err = layers.BuildLayersPlanner("", raw)
			if err == nil {
				t.Fatalf("%v: missing http carrier must be rejected", tc.layers)
			}
			if !strings.Contains(err.Error(), "requires the http carrier layer") {
				t.Errorf("want carrier anchor, got: %v", err)
			}
		})
	}
}
