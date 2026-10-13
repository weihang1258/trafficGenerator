package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol"
)

// 第10轮反馈 B（键名零校验）：file_source 内未知键/缺已知键必须在配置校验
// 即报错——此前 {"file_path":...} 静默通过、任务 completed 但内容为空。
func TestFileSourceUnknownKeyRejectedAtConfigValidation(t *testing.T) {
	run := func(chain string) error {
		t.Helper()
		planner, err := layers.BuildLayersPlanner("http", json.RawMessage(chain))
		if err != nil {
			return err
		}
		_, err = planner.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.2", SrcPort: 32000, DstPort: 80})
		return err
	}
	err := run(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"dst_port":80}},{"http":{"method":"POST","uri":"/u","file_source":{"file_path":"a.bin"}}}]`)
	if err == nil || !strings.Contains(err.Error(), "file_path") {
		t.Fatalf("未知键 file_path 应在配置校验报错并点名, got %v", err)
	}
	err = run(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"dst_port":80}},{"http":{"method":"POST","uri":"/u","file_source":{"zzz":1}}}]`)
	if err == nil || !strings.Contains(err.Error(), "zzz") {
		t.Fatalf("纯未知键应报错, got %v", err)
	}
}
