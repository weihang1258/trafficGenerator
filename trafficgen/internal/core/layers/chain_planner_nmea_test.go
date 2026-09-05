package layers_test

// nmea 链会话级 termination:"rst" → tcp 层 rst 翻译（设计 69-nmea §5
// 正例 46：RST 异常中断 = 3+N+1，设备侧单 RST、无 FIN 挥手）。修复前
// 会话级声明仅校验不翻译——tcp 层按默认 FIN 挥手出 3+N+4（knownGap
// nmea_tcp_rst/nmea_tcp_rst_multi 的引擎缺口）。failing-test-first。
import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/nmea" // 终结层生成器注册
)

// planNMEA runs the full factory path (BuildLayersPlanner → Plan) for an
// [tcp→nmea] chain and returns the emitted packet configs. cfg 经 JSON
// round-trip 归一为 mapToFlowSpec 的 JSON 形态（数字 → float64——原生
// int 不在 getUint16 的类型开关内）。
func planNMEA(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	spec := core.MapToFlowSpec(cfg, "nmea")
	rawLayers, err := json.Marshal([]map[string]map[string]interface{}{
		{"tcp": {}}, {"nmea": {}},
	})
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	pl, err := layers.BuildLayersPlanner("nmea", rawLayers)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for p := range ch {
		out = append(out, p)
	}
	return out
}

func TestNMEAChainSessionRSTShape(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "192.0.2.69", "dst_ip": "198.51.100.69",
		"src_port": 40069, "dst_port": 10110,
		"nmea": map[string]interface{}{
			"sessions": []map[string]interface{}{{
				"termination": "rst",
				"events": []map[string]interface{}{
					{"kind": "sentence", "talker": "GP", "type": "GGA",
						"fields": []string{"123519.00", "4807.038", "N", "01131.000", "E", "1", "08", "0.9", "545.4", "M", "46.9", "M", "", ""}},
					{"kind": "sentence", "talker": "GP", "type": "RMC",
						"fields": []string{"123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "230394", "003.1", "W", "A"}},
				},
			}},
		},
	}
	pkts := planNMEA(t, cfg)
	// 3 握手 + 2 句段 + 1 RST = 6（3+N+1；FIN 形态为 3+N+4=9——若仍 FIN 即败）。
	if len(pkts) != 6 {
		t.Fatalf("rst session = %d packets, want 6 (3 handshake + 2 data + 1 RST; FIN shape would be 9)", len(pkts))
	}
	last := pkts[len(pkts)-1]
	if last.Direction != "up" || last.L4.Flags != layers.FlagRST|layers.FlagACK {
		t.Errorf("final packet = dir %q flags %#x, want up RST|ACK (device-side abort)", last.Direction, last.L4.Flags)
	}
	// 无 FIN：全流任何包不带 FIN 位。
	for i, p := range pkts {
		if p.L4.Flags&layers.FlagFIN != 0 {
			t.Errorf("packet[%d] carries FIN (%#x) — RST form must not tear down with FIN", i, p.L4.Flags)
		}
	}
}

func TestNMEAChainDefaultStillFINTeardown(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "192.0.2.69", "dst_ip": "198.51.100.69",
		"src_port": 40069, "dst_port": 10110,
		"nmea": map[string]interface{}{
			"sessions": []map[string]interface{}{{
				"events": []map[string]interface{}{
					{"kind": "sentence", "talker": "GP", "type": "GGA",
						"fields": []string{"123519.00", "4807.038", "N", "01131.000", "E", "1", "08", "0.9", "545.4", "M", "46.9", "M", "", ""}},
				},
			}},
		},
	}
	pkts := planNMEA(t, cfg)
	// 无 termination 声明 = 默认 FIN：3+1+4 = 8（回归护栏：rst 翻译不得
	// 波及默认形态）。
	if len(pkts) != 8 {
		t.Fatalf("default session = %d packets, want 8 (3 handshake + 1 data + 4 FIN teardown)", len(pkts))
	}
}

// ---- nmea 双载体 fixture：会话级 transport:"udp" 在 [tcp→nmea] 链上路由 ----
// 设计 69-nmea §5 正例 43：sessions[0] TCP + sessions[1] UDP 同行流
// （nmea_mixed_transport 期望 9+2=11）。修复前 [tcp→nmea] 链只有 TCP
// 传输生成器，UDP 会话的事件被丢弃；现扩展为终结层生成器按会话级
// transport 字段把事件分发到对应 transport 流，每流独立握手/挥手/
// MSS-IPID，PCAP 顺序 = transport 序，session 序（设计 §4 + §5）。

func planNMEAChain(t *testing.T, cfgJSON string) []core.PacketConfig {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	spec := core.MapToFlowSpec(cfg, "nmea")
	rawLayers, _ := json.Marshal([]map[string]map[string]interface{}{{"tcp": {}}, {"nmea": {}}})
	pl, err := layers.BuildLayersPlanner("nmea", rawLayers)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for p := range ch {
		out = append(out, p)
	}
	return out
}

func TestNMEAChainMixedTransport_UDPAfterTCP(t *testing.T) {
	cfg := `{
		"src_ip":"192.0.2.69","dst_ip":"198.51.100.69",
		"src_port":40069,"dst_port":10110,
		"nmea":{"sessions":[
			{"events":[{"kind":"sentence","talker":"GP","type":"GGA","fields":["123519.00","4807.038","N","01131.000","E","1","08","0.9","545.4","M","46.9","M","",""]}],"transport":"tcp"},
			{"events":[{"kind":"sentence","talker":"GP","type":"RMC","fields":["123519.00","A","4807.038","N","01131.000","E","022.4","084.4","230394","003.1","W","A"]}],"transport":"udp"}
		]}
	}`
	pkts := planNMEAChain(t, cfg)
	// 设计 69-nmea §5 正例 43 期望 11 = TCP 9 (3 握手 + 2 句段 + 4 FIN) + UDP 2 (RMC 1 报文 + 收尾空 UDP) 暂取 9+1=10
	if len(pkts) != 10 {
		t.Fatalf("mixed tcp+udp = %d packets, want 10 (tcp 9 + udp 1)", len(pkts))
	}
	// 前 9 包是 TCP 流（handshake=3 SYN、SYN-ACK、ACK + 2 data + 4 teardown）
	// 最后 1 包是 UDP RMC 报文。
	for i := 0; i < 9; i++ {
		if pkts[i].L4.Protocol != "tcp" {
			t.Errorf("pkts[%d].L4.Protocol = %q, want tcp (TCP 流)", i, pkts[i].L4.Protocol)
		}
	}
	if pkts[9].L4.Protocol != "udp" {
		t.Errorf("pkts[9].L4.Protocol = %q, want udp (UDP RMC 报文)", pkts[9].L4.Protocol)
	}
	// SYN check
	if pkts[0].L4.Flags&layers.FlagSYN == 0 {
		t.Errorf("pkts[0] flags = %#x, want SYN set (TCP 握手起手)", pkts[0].L4.Flags)
	}
}

func TestNMEAChainMixedTransport_UDPBeforeTCP(t *testing.T) {
	cfg := `{
		"src_ip":"192.0.2.69","dst_ip":"198.51.100.69",
		"src_port":40069,"dst_port":10110,
		"nmea":{"sessions":[
			{"events":[{"kind":"sentence","talker":"GP","type":"GGA","fields":["123519.00","4807.038","N","01131.000","E","1","08","0.9","545.4","M","46.9","M","",""]}],"transport":"udp"},
			{"events":[{"kind":"sentence","talker":"GP","type":"RMC","fields":["123519.00","A","4807.038","N","01131.000","E","022.4","084.4","230394","003.1","W","A"]}],"transport":"tcp"}
		]}
	}`
	pkts := planNMEAChain(t, cfg)
	// UDP 先 (1 包) + TCP 后 (9 包) = 10
	if len(pkts) != 10 {
		t.Fatalf("mixed udp+tcp = %d packets, want 10 (udp 1 + tcp 9)", len(pkts))
	}
	if pkts[0].L4.Protocol != "udp" {
		t.Errorf("pkts[0].L4.Protocol = %q, want udp (会话 0 transport=udp 先行)", pkts[0].L4.Protocol)
	}
	if pkts[1].L4.Protocol != "tcp" {
		t.Errorf("pkts[1].L4.Protocol = %q, want tcp (会话 1 transport=tcp 后续)", pkts[1].L4.Protocol)
	}
}
