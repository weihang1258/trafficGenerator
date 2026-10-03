package core

import (
	"strings"
	"testing"
)

// 未知 flat 键一次性全报（LLM 反馈"挤牙膏"：首错即返回迫使多轮往返）。
// 单键报错文案逐字不变（sstp_chain_test 等钉死 substring），仅多键时聚合。
func TestCheckProtoFlat_ReportsAllOffendingKeys(t *testing.T) {
	msg := CheckProtoFlat("dns", map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "20.0.0.1",
		"src_port": 12345,
		"dst_port": 53,
		"count":    3,
	})
	if msg == "" {
		t.Fatal("want flat rejection, got empty")
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		if !strings.Contains(msg, k) {
			t.Errorf("aggregated error missing %q: %s", k, msg)
		}
	}
	if strings.Count(msg, "no longer accepts flat config field") != 1 {
		t.Errorf("want single sentence listing all keys, got: %s", msg)
	}

	// 单键场景：文案逐字不漂移（既有钉死测试依赖）。
	single := CheckProtoFlat("dns", map[string]interface{}{"dst_ip": "20.0.0.1"})
	want := "protocol dns no longer accepts flat config field dst_ip" +
		" (use a layers chain: ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports, flow_control for the flow count)"
	if single != want {
		t.Errorf("single-key message drifted:\n got  %s\n want %s", single, want)
	}
}
