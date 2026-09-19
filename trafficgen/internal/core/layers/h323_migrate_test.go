package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/h323" // init 注册 h323 层生成器 + 校验器
)

// D-H323-1 §4 红例①②③④（failing 先行，P-PIPE #15 P4）。
// 实现前预期：①红（CheckProtoFlat 无 h323 presence 分支，放行）；②红
// （registry h323 无行，层内业务键 V9 全拒 unknown field）；③红
// （translate case "h323" 为 no-op → spec.H323 恒 nil → legacy Validate
// "H323Config is required"；且 raw-IP 驱动名单无 h323=生成器缺位）；
// ④红（translate 不镜像 setDefaultDstPort → spec.DstPort=0 上包）。

func h323Chain(t *testing.T, h323Cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"h323": h323Cfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-H323-1 §2】：顶层 h323 子映射 presence 判死——空 map 也死。
func TestH323Chain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"h323": map[string]interface{}{}},
		},
		"h323": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("h323", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(h323, {layers, h323:{}}) = \"\", want top-level h323 presence rejection")
	} else if !strings.Contains(msg, "top-level h323 sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-H323-1 §1】：h323 层 10 业务键 V9 放行（一律无 Default；缺省
// 语义在 translate 镜像 parse——决策 F）。
func TestH323Chain_LayerFieldsAccepted(t *testing.T) {
	raw := h323Chain(t, map[string]interface{}{
		"role":         "caller",
		"scenario":     "full",
		"crv":          0x2584,
		"display_name": "Administrator",
		"calls":        1,
		"rewrite_addr": false,
		"src_port":     12345,
		"dst_port":     1720,
		"media":        map[string]interface{}{"enabled": true, "frames": 2},
		"ras":          map[string]interface{}{"enabled": true},
	})
	if _, err := layers.ValidateLayers(raw, "h323"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-H323-1 §3】：translate 上线——[ip,h323] 链整包 relay，full
// 场景 15 包/呼叫（3 握手+9 Q.931+3 挥手，代码精算实证）；握手 SYN
// flags 0x02/1720，首条 Q.931 payload TPKT 0x03 + msg_type 0x05(SETUP)。
func TestH323Chain_LayerTranslateCallCycle(t *testing.T) {
	p := layers.NewChainPlannerFromChain("h323", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "h323", Config: map[string]interface{}{"src_port": 12345, "dst_port": 1720}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	// full=16/呼叫（3 握手+10 Q.931+3 挥手）：Q.931 序列 SETUP/CP/F↓/
	// ALERTING↓/F↑/F↓/F↑/CONNECT↓/RELCOMP↑/RELCOMP↓=10 条（h323.go:322-341
	// 逐行计数；存量例 min_packets=15 掩盖了精确值——红例先行的价值）。
	if len(pkts) != 16 {
		t.Fatalf("packets=%d want 16 (full=3 handshake+10 Q.931+3 teardown)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("pkt1 flags=0x%x want 0x02 (SYN)", pkts[0].L4.Flags)
	}
	if pkts[0].L4.DstPort != 1720 {
		t.Fatalf("pkt1 dstPort=%d want 1720", pkts[0].L4.DstPort)
	}
	q := pkts[3].Payload // 首条 Q.931（SETUP）
	if len(q) < 9 || q[0] != 0x03 {
		t.Fatalf("pkt4 payload head=%v want TPKT version 0x03", q[:min(4, len(q))])
	}
	// Q.931 头布局（h323.go:14-15）：TPKT(4)+PD 0x08(4)+CRVlen 0x02(5)+
	// CRV(6-7)+msg_type(8)。
	if q[4] != 0x08 {
		t.Fatalf("pkt4 PD=0x%x want 0x08", q[4])
	}
	if q[6] != 0x25 || q[7] != 0x84 {
		t.Fatalf("pkt4 CRV=% 02x % 02x want 0x25 0x84 (DefaultCRV)", q[6], q[7])
	}
	if q[8] != 0x05 {
		t.Fatalf("pkt4 msg_type=0x%x want 0x05 (SETUP)", q[8])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 红例④【D-H323-1 决策 B/C】：空 h323 层 → dst_port 缺省 1720
// （translate 镜像 parse 的 setDefaultDstPort(spec, cfg, 1720)，
// strategy_convert.go:933）。实现前 spec.DstPort=0 上包。
func TestH323Chain_DstPortDefault1720(t *testing.T) {
	p := layers.NewChainPlannerFromChain("h323", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "h323", Config: map[string]interface{}{}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	pkt, ok := <-ch
	if !ok {
		t.Fatal("no packets")
	}
	if pkt.L4.DstPort != 1720 {
		t.Fatalf("empty-layer dstPort=%d want 1720 (translate must mirror parse default)", pkt.L4.DstPort)
	}
}
