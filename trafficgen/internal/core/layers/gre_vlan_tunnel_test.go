package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns" // init 注册 dns 终结层生成器
	_ "github.com/trafficgen/trafficgen/internal/protocol/gre" // init 注册 gre 隧道层生成器
)

// D-GRE-3 步骤 0 红例族（failing 先行，2026-09-15）。
// 实现前全红：vlan 层无生成器（BuildLayersPlanner 预检拒）/ 通用隧道块未建。
// 红例走 BuildLayersPlanner 全链口径（P2c 真实入口），不是直调内部函数。

func vlanGreChain(t *testing.T, vlan map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []map[string]map[string]interface{}{
		{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"gre": {}},
		{"ip": {"src": "192.168.1.1", "dst": "192.168.1.2"}},
		{"udp": {"src_port": float64(12345), "dst_port": float64(80)}},
		{"dns": {}},
	}
	// vlan 只能打头（V7：L2 必须在最外连续段）。
	raw := []map[string]map[string]interface{}{{}}
	_ = raw
	full := []interface{}{map[string]interface{}{"vlan": vlan}}
	for _, l := range chain {
		m := map[string]interface{}{}
		for k, v := range l {
			m[k] = v
		}
		full = append(full, m)
	}
	out, _ := json.Marshal(full)
	return out
}

func greSpecV4() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80}
}

// 红例1【D-GRE-3 §5】：vlan 层链 BuildLayersPlanner 通过（现状：
// `generator not implemented for layer "vlan"`——newGenerator 无分支）。
func TestVLANChain_BuildPasses(t *testing.T) {
	raw := vlanGreChain(t, map[string]interface{}{"id": float64(100), "priority": float64(4)})
	p, err := layers.BuildLayersPlanner("gre", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v (vlan 层应由框架 passthrough 生成器承载，不在驱动预检拒绝)", err)
	}
	if err := p.Validate(greSpecV4()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// 红例2【D-GRE-3 §4】：vlan tag 落 wire——首帧 offset 12:14=81 00（TPID），
// 14:16=80 64（TCI=4<<13|100=0x8064），且全帧（up+down）带 tag。
func TestVLANChain_TagOnWire(t *testing.T) {
	raw := vlanGreChain(t, map[string]interface{}{"id": float64(100), "priority": float64(4)})
	p, err := layers.BuildLayersPlanner("gre", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(greSpecV4()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), greSpecV4())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) == 0 {
		t.Fatal("vlan chain produced 0 packets (passthrough strand 即静默空流)")
	}
	b := core.NewBuilder()
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v", i, err)
		}
		if len(f) < 18 {
			t.Fatalf("packet %d frame too short: %d bytes (< eth14+vlan4)", i, len(f))
		}
		if f[12] != 0x81 || f[13] != 0x00 {
			t.Errorf("packet %d TPID = %02x %02x, want 81 00 (802.1Q tag 缺失)", i, f[12], f[13])
		}
		if f[14] != 0x80 || f[15] != 0x64 {
			t.Errorf("packet %d TCI = %02x %02x, want 80 64 (priority 4<<13 | id 100)", i, f[14], f[15])
		}
	}
}

// 红例3【D-GRE-3 §5】：隧道结构性错误前缀是 `tunnel chain:`（通用块——
// 下一条隧道零新增复用；子串锚词不变，用例 error_contains 不漂移）。
func TestTunnelChain_GenericPrefix(t *testing.T) {
	raw := vlanGreChain(t, map[string]interface{}{})
	_ = raw
	// 内层混族链：前缀断言对象。
	mixed := []map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"gre": map[string]interface{}{}},
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "fd00::2"}},
		{"udp": map[string]interface{}{"src_port": float64(12345), "dst_port": float64(80)}},
		{"dns": map[string]interface{}{}},
	}
	mraw, _ := json.Marshal(mixed)
	p, err := layers.BuildLayersPlanner("gre", mraw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(greSpecV4())
	if err == nil || !strings.Contains(err.Error(), "tunnel chain:") {
		t.Fatalf("Validate err = %v, want generic `tunnel chain:` prefix (gre 专属前缀随泛化退役)", err)
	}
	if !strings.Contains(err.Error(), "must be the same IP version") {
		t.Errorf("Validate err = %v, want sub-anchor `must be the same IP version` preserved", err)
	}
}
