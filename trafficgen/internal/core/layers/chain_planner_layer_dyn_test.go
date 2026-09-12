package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ftp"
)

// D-FTP-3 层字段动态 tcp 对象回归（同键二态）：tcp.src_port/dst_port 写动态
// 对象时，worker resolveLayerTuple 的逐流解析值经 spec 进入 drive，Plan 不得
// 把原始链上的对象报 "cannot convert to uint16"。
//
// Failing-first：precheck 曾读原始链 config 做 resolveCfg，对象直达生成器
// 判死；drive 的 applySpecToChain 剥离也曾只删不注，逐流值上不了线。
// 测试按 worker 语义逐流设 spec 端口（模拟 resolveLayerTuple 解析结果），
// 再 Plan，断言线上客户端口就是该流解析值。
func TestChainPlanner_TCPLayerDynObject(t *testing.T) {
	mkPlanner := func(t *testing.T, tcpCfg string) (core.ProtocolPlanner, core.FlowSpec) {
		t.Helper()
		raw := `{"layers":[{"ip":{}},{"tcp":{` + tcpCfg + `}},{"ftp":{"commands":[{"cmd":"QUIT","response":"221"}]}}]}`
		var cfg map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatal(err)
		}
		spec := core.MapToFlowSpec(cfg, "ftp")
		if spec.LayerDyn == nil {
			t.Fatal("LayerDyn nil: parseLayerDyn 未解析出 tcp 层动态对象")
		}
		lv, _ := json.Marshal(cfg["layers"])
		pl, err := layers.BuildLayersPlanner("ftp", lv)
		if err != nil {
			t.Fatalf("build planner: %v", err)
		}
		return pl, spec
	}
	// 断言该流每个包的客户端口（up 包 SrcPort / down 包 DstPort）均为 want。
	assertFlowPorts := func(t *testing.T, pl core.ProtocolPlanner, spec core.FlowSpec, want uint16, wantDst uint16) {
		t.Helper()
		ch, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan err: %v", err)
		}
		n := 0
		for pkt := range ch {
			n++
			var client, server uint16
			if pkt.Direction == "up" {
				client, server = pkt.L4.SrcPort, pkt.L4.DstPort
			} else {
				client, server = pkt.L4.DstPort, pkt.L4.SrcPort
			}
			if client != want {
				t.Fatalf("packet %d dir=%s client port = %d, want %d (server %d, wantDst %d)",
					n, pkt.Direction, client, want, server, wantDst)
			}
			if server != wantDst {
				t.Fatalf("packet %d dir=%s server port = %d, want %d", n, pkt.Direction, server, wantDst)
			}
		}
		if n == 0 {
			t.Fatal("Plan 产出空流")
		}
	}

	t.Run("src_port_inc", func(t *testing.T) {
		pl, spec := mkPlanner(t, `"src_port":{"strategy":"inc","range":[15200,15202]}`)
		for i := 0; i < 3; i++ {
			s := spec
			s.FlowIndex = i
			s.SrcPort = 15200 + uint16(i) // 模拟 worker resolveLayerTuple(i)
			assertFlowPorts(t, pl, s, 15200+uint16(i), 21)
		}
	})
	t.Run("dst_port_inc", func(t *testing.T) {
		pl, spec := mkPlanner(t, `"dst_port":{"strategy":"inc","range":[212,214]}`)
		for i := 0; i < 3; i++ {
			s := spec
			s.FlowIndex = i
			s.DstPort = 212 + uint16(i) // 模拟 worker resolveLayerTuple(i)
			assertFlowPorts(t, pl, s, s.SrcPort, 212+uint16(i))
		}
	})
}
