package core

import "testing"

// T-FTP-7 前置 failing test（D-FTP-2 §7 步骤2）：strategy config "tuples"
// 解析进 spec.Tuples；缺席 = nil。
func TestMapToFlowSpec_Tuples(t *testing.T) {
	cfg := map[string]interface{}{
		"tuples": map[string]interface{}{
			"src_ip":   map[string]interface{}{"strategy": "inc", "range": []interface{}{"10.0.1.1", "10.0.1.5"}},
			"src_port": map[string]interface{}{"strategy": "inc", "range": []interface{}{20000, 20009}},
			"dst_ip":   "20.0.0.9",
			"dst_port": map[string]interface{}{"strategy": "fixed", "value": 51000},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.Tuples == nil {
		t.Fatal("spec.Tuples nil (tuples shape not parsed yet)")
	}
	if spec.Tuples.SrcIP.Strategy != "inc" {
		t.Errorf("SrcIP.Strategy = %q", spec.Tuples.SrcIP.Strategy)
	}
	if v := genPort(spec.Tuples.SrcPort, 3); v != 20003 {
		t.Errorf("resolved src_port(3) = %d, want 20003", v)
	}
	if v := genIP(spec.Tuples.SrcIP, 2); v != "10.0.1.3" {
		t.Errorf("resolved src_ip(2) = %q, want 10.0.1.3", v)
	}
	// fixed endpoint round-trips as a StrategyConfig
	if spec.Tuples.DstPort.Strategy != "fixed" {
		t.Errorf("DstPort.Strategy = %q, want fixed", spec.Tuples.DstPort.Strategy)
	}

	// Absent tuples → nil
	spec2 := mapToFlowSpec(map[string]interface{}{"src_port": float64(12345)}, "tcp")
	if spec2.Tuples != nil {
		t.Errorf("absent tuples must stay nil, got %+v", spec2.Tuples)
	}
}
