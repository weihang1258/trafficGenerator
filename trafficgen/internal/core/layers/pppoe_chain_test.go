package layers_test

// D-PPPOE-1 P4 链级红例（failing 先行）：[ip→pppoe] raw 自驱链（裁定1，
// 帧无外层 IP 头，ip 层值=内层 IPv4 语义）。生成器 wrap legacy
// Planner.Plan（srv6 先例：Direction 统一 "up" 防 raw-IP drive 二次换向）。
// 裁定3：padt 缺省 true → 全生命周期 8 帧。

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 pppoe 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/pppoe"
)

func TestChainPlanner_PPPOERawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("pppoe", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "pppoe", Config: mustJSONMap(t, `{
			"session_id": 77, "auth": "none",
			"magic_number": 16909060, "data_frames": 1
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.PPPoE == nil {
		t.Fatalf("translate must populate spec.PPPoE from the pppoe layer config")
	}
	if validated.PPPoE.SessionID != 77 {
		t.Fatalf("spec.PPPoE.SessionID=%d want 77 (layer value wins)", validated.PPPoE.SessionID)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var codes []uint8
	var sessIDs []uint16
	for pkt := range ch {
		if pkt.L2.PPPoE == nil {
			t.Fatalf("every frame must carry L2.PPPoE, got %+v", pkt.L2)
		}
		codes = append(codes, pkt.L2.PPPoE.Code)
		sessIDs = append(sessIDs, pkt.L2.PPPoE.SessionID)
		// 裁定1：帧无外层 IP 头——Discovery/Auth 帧不得带 L3。
		if pkt.L2.PPPoE.PPPProtocol != core.PPPProtocolIPv4 && pkt.L3.SrcIP != "" {
			t.Fatalf("non-data frame carries L3: code=%#x srcIP=%q", pkt.L2.PPPoE.Code, pkt.L3.SrcIP)
		}
	}
	want := []uint8{core.PPPoECodePADI, core.PPPoECodePADO, core.PPPoECodePADR, core.PPPoECodePADS,
		core.PPPoECodeSessionData, core.PPPoECodeSessionData, core.PPPoECodeSessionData, core.PPPoECodePADT}
	if len(codes) != len(want) {
		t.Fatalf("frames=%d (%v) want 8 (PADI/PADO/PADR/PADS + LCP req/ack + data + PADT)", len(codes), codes)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("frame[%d] code=%#x want %#x (full=%v)", i, codes[i], want[i], codes)
		}
	}
	if sessIDs[3] != 77 || sessIDs[7] != 77 {
		t.Fatalf("PADS/PADT session ids=%v want 77 echoed", sessIDs)
	}
}

// 9.49 sessions[] 链路径：每项一完整生命周期，FlowID 带 session 后缀
// （裁定5 flow identity）。
func TestChainPlanner_PPPOESessionsChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("pppoe", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// sessions 数值面经 JSON 往返构造（getUint16/getInt 只认
		// float64/json.Number，与生产 JSON 解码面一致——Go 字面量 int
		// 是测试专用形状，sip_sessions_test 同口径）。
		{Name: "pppoe", Config: mustJSONMap(t, `{
			"ac_name": "BRAS-1",
			"sessions": [{"session_id": 100, "data_frames": 1}, {"data_frames": 1}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	flowIDs := map[string]bool{}
	padsSeen := map[uint16]bool{}
	padtCount := 0
	for pkt := range ch {
		if pkt.L2.PPPoE == nil {
			continue
		}
		switch pkt.L2.PPPoE.Code {
		case core.PPPoECodePADS:
			padsSeen[pkt.L2.PPPoE.SessionID] = true
		case core.PPPoECodePADT:
			padtCount++
			if !flowIDs[pkt.FlowID] {
				flowIDs[pkt.FlowID] = true
			}
		}
	}
	if !padsSeen[100] || !padsSeen[2] {
		t.Fatalf("PADS ids=%v want {100, derived 2}", padsSeen)
	}
	if padtCount != 2 {
		t.Fatalf("PADT count=%d want 2 (one per session)", padtCount)
	}
	if len(flowIDs) != 2 {
		t.Fatalf("FlowIDs=%v want 2 distinct (session-suffixed, 裁定5)", flowIDs)
	}
}

// mustJSONMap builds a layer-config map through a JSON round-trip so the
// numeric leaves are float64 (the shape every parse helper consumes).
func mustJSONMap(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	return m
}
