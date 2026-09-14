package gre

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// D-GRE-1 步骤 0①（failing 先行，直调 validator 口径——tls
// layer_validate_test.go 同款）：flat spec.GRE 非法 ProtocolType 进
// validateGRESpec 必须拒绝（legacy planner.Validate 枚举：0x0800/0x0806/
// 0x86DD/0 之外全拒）。当前无 validator：本测试在实现前红（validateGRESpec
// 未定义 → 编译红）。
func TestGRESpecValidator_FlatRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 80,
		GRE: &core.GREConfig{ProtocolType: 0x9999},
	}
	if err := validateGRESpec(&spec); err == nil {
		t.Error("validateGRESpec accepted ProtocolType 0x9999, want rejection")
	}
}

// D-GRE-1 步骤 0②（nil 容忍契约钉死，2026-09-14 探针修订）：纯层链路径
// spec.GRE 恒 nil（mapToFlowSpec 只在顶层 gre 子映射时填充，链上生成器读
// gre 层 config 不读 flat spec）——validator 必须放行 nil，否则翻转后所有
// 纯层链 gre 策略全被误杀（vxlan/geneve/nvgre ValidateConfig nil→nil 同款
// 先例）。若实现成 nil 拒绝，本例红。
func TestGRESpecValidator_NilTolerant(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 80,
	}
	if err := validateGRESpec(&spec); err != nil {
		t.Fatalf("validateGRESpec rejected nil GRE (pure-chain legal state): %v", err)
	}
}

// D-GRE-1 步骤 0③（既有 allowlist 门的回归锁，当日绿非红例）：
// layerDynAllowlist 无 gre 行——gre 层 key 写动态对象在 checkLayerDynObjects
// 即拒（D-GRE-1 §12：业务 3 键全关）。链形必须结构合法（内层以终结层 dns
// 收尾，裸 [ip,gre,ip,udp] 过不了 V4 到不了动态检查）。
func TestGRELayer_KeyDynamicRejected(t *testing.T) {
	chain := []map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"gre": map[string]interface{}{"key": map[string]interface{}{"strategy": "list", "list": []interface{}{100}}}},
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 80}},
		{"dns": map[string]interface{}{}},
	}
	raw, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	_, err = layers.ValidateLayers(raw, "gre")
	if err == nil || !strings.Contains(err.Error(), "does not support dynamic") {
		t.Fatalf("ValidateLayers err = %v, want does not support dynamic", err)
	}
}
