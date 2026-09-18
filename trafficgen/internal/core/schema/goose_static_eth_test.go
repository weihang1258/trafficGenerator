package schema

import (
	"strings"
	"testing"
)

// D-GOOSE-1 §4 红例④（failing 先行，P-PIPE #12 P4，⑥ static-eth 门）。
// eth-only 链显式标量 MAC + flows=2 → static four-tuple 拒绝。
// 现状：checkLayerChainStaticCopy 只查 ip/tcp/udp 层 → 静默放行
// （sqNum 撞号 N 条重复流，12.9 未满足）。
func TestGOOSEChainStaticEthRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "goose", map[string]any{
		"layers": []any{
			map[string]any{"eth": map[string]any{"src_mac": "aa:bb:cc:dd:ee:01"}},
			map[string]any{"goose": map[string]any{}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want eth static-copy rejection, got %v", errs)
	}
}

// 红例⑤【D-GOOSE-1 §4/12.9】：sv 同享 static-eth 门——sv 链显式标量 eth
// MAC + flows=2 同门拒绝（同法则适用；sv 用例零 strategy_fc 保持）。
// 现状：checkLayerChainStaticCopy 只查 ip/tcp/udp → 静默放行。
func TestSVChainStaticEthRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sv", map[string]any{
		"layers": []any{
			map[string]any{"eth": map[string]any{"src_mac": "aa:bb:cc:dd:ee:01"}},
			map[string]any{"sv": map[string]any{}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want sv eth static-copy rejection (same gate as goose), got %v", errs)
	}
}
