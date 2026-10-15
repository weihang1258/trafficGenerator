package schema

// D-ROBUST-2 N3：批量语境的动态对象拒绝必须带批量指引（否则指向策略入口
// 的通用文案让批量用户迷路——客户端复测回执实测的迷路点）。
import (
	"strings"
	"testing"
)

func TestValidateBatchClassLayerFields_DynObjectGetsBatchHint(t *testing.T) {
	msg := ValidateBatchClassLayerFields(map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]any{"udp": map[string]any{"dst_port": 53, "src_port": map[string]any{"strategy": "inc", "range": []any{41010, 41012}}}},
		},
	})
	if msg == "" {
		t.Fatal("dyn object in batch class: no rejection")
	}
	if !strings.Contains(msg, "batch classes replicate a single flow") {
		t.Fatalf("msg = %q, want batch-context guidance anchor", msg)
	}
}
