package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ngap" // init 注册 ngap 层生成器 + 校验器
)

// D-NGAP-1 §4 红例①②③④（failing 先行，P-PIPE #17 P4）。
// 实现前预期：①红（CheckProtoFlat 无 ngap presence 分支）；②红
// （registry 无 ngap 行——连占位都无，V9 全拒 unknown layer）；③红
// （translate 无 case + 生成器未注册 → Plan 报 generator not implemented）；
// ④红（translate 不落 spec.NGAP → 恒 nil）。

func ngapChain(t *testing.T, ngapCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"ngap": ngapCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-NGAP-1 §2】：顶层 ngap 子映射 presence 判死——空 map 也死。
func TestNGAPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"ngap": map[string]interface{}{}},
		},
		"ngap": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("ngap", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(ngap, {layers, ngap:{}}) = \"\", want top-level ngap presence rejection")
	} else if !strings.Contains(msg, "top-level ngap sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-NGAP-1 §1】：ngap 层 14 键 V9 放行（registry 无行 → 实现前
// 整层 unknown）。业务 12 键 + 端口 2 键（h323/mpls 已批同款，端口住层）。
func TestNGAPChain_LayerFieldsAccepted(t *testing.T) {
	raw := ngapChain(t, map[string]interface{}{
		"src_port": 12345,
		"dst_port": 38412,
		"global_ran_node_id": map[string]interface{}{
			"plmn_mcc": 460, "plmn_mnc": 1, "gnb_id": 4097,
		},
		"supported_ta_list": []interface{}{
			map[string]interface{}{"plmn_mcc": 460, "plmn_mnc": 1, "tacs": []interface{}{100, 200}},
		},
		"default_paging_drx": 2,
		"amf_name":           "AMF-TEST-01",
		"ran_ue_ngap_id":     1,
		"amf_ue_ngap_id":     16777216,
		"initial_ue_message": true,
		"initial_nas":        "abc",
		"downlink_nas":       "de",
		"uplink_nas":         "ad",
		"pdu_session_setup": map[string]interface{}{
			"pdu_session_id": 1, "sst": 1, "sd": 1,
		},
		"ue_context_release": true,
	})
	if _, err := layers.ValidateLayers(raw, "ngap"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-NGAP-1 §3】：translate + 生成器上线——[ip,ngap] 链最小 9 包
// SCTP 联结（INIT 1/INIT_ACK 2/COOKIE_ECHO 10/COOKIE_ACK 11 + NGSetup DATA
// 对 + SHUTDOWN 7/SHUTDOWN_ACK 8/SHUTDOWN_COMPLETE 14）。legacy 输出
// L4.Protocol="sctp"、chunk 裸序列在 Payload（ngap.go:282-309 emitSCTP
// 合同），chunk 类型字节 = Payload[0]。
func TestNGAPChain_LayerTranslateMinimalSession(t *testing.T) {
	p := layers.NewChainPlannerFromChain("ngap", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "ngap", Config: map[string]interface{}{
			"src_port": 12345, "dst_port": 38412,
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	wantTypes := []byte{1, 2, 10, 11, 0, 0, 7, 8, 14}
	// 方向面：up 包 dst=38412（AMF 端口），down 包 dst=12345（gNB 端口，
	// legacy 逐 emit 自换——emitSCTP 调用序 ngap.go:322-418 实钉）。
	wantDst := []uint16{38412, 12345, 38412, 12345, 38412, 12345, 38412, 12345, 38412}
	n := 0
	for pkt := range ch {
		if n >= len(wantTypes) {
			t.Fatalf("packet overflow: got >%d packets", len(wantTypes))
		}
		if pkt.L4.Protocol != "sctp" {
			t.Fatalf("packet %d: L4.Protocol=%q want sctp", n+1, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != wantDst[n] {
			t.Fatalf("packet %d: dstPort=%d want %d (direction-aware association)", n+1, pkt.L4.DstPort, wantDst[n])
		}
		if len(pkt.Payload) == 0 || pkt.Payload[0] != wantTypes[n] {
			t.Fatalf("packet %d: chunk type=%d want %d (SCTP association order)", n+1, pkt.Payload[0], wantTypes[n])
		}
		n++
	}
	if n != len(wantTypes) {
		t.Fatalf("packets=%d want %d (minimal NGAP association)", n, len(wantTypes))
	}
}

// 红例④【D-NGAP-1 决策 C】：translate 把层 config 填进 spec.NGAP——经
// ValidateSpec 后 spec.NGAP 非 nil 且业务键逐槽映射（实现前恒 nil =
// legacy "SCTP handshake only" 静默）。嵌套三件（object/list）下钻证通路。
func TestNGAPChain_PresenceFilled(t *testing.T) {
	p := layers.NewChainPlannerFromChain("ngap", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "ngap", Config: map[string]interface{}{
			"amf_name":           "AMF-EDGE-07",
			"default_paging_drx": 2,
			"initial_ue_message": true,
			"initial_nas":        "aabb",
			"downlink_nas":       "cc",
			"uplink_nas":         "dd",
			"ue_context_release": true,
			"global_ran_node_id": map[string]interface{}{
				"plmn_mcc": 460, "plmn_mnc": 1, "gnb_id": 4097,
			},
			"supported_ta_list": []interface{}{
				map[string]interface{}{"plmn_mcc": 460, "plmn_mnc": 1, "tacs": []interface{}{100}},
			},
			"pdu_session_setup": map[string]interface{}{
				"pdu_session_id": 7, "sst": 2, "sd": 1,
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.NGAP == nil {
		t.Fatal("spec.NGAP must be translated from the layer config")
	}
	g := out.NGAP
	if g.AMFName != "AMF-EDGE-07" || g.DefaultPagingDRX != 2 || !g.InitialUEMessage || !g.UEContextRelease {
		t.Fatalf("business keys not mapped: %+v", g)
	}
	if g.GlobalRANNodeID == nil || g.GlobalRANNodeID.PLMNMCC != 460 || g.GlobalRANNodeID.GNBID != 4097 {
		t.Fatalf("global_ran_node_id not drilled: %+v", g.GlobalRANNodeID)
	}
	if len(g.SupportedTAList) != 1 || len(g.SupportedTAList[0].TACs) != 1 || g.SupportedTAList[0].TACs[0] != 100 {
		t.Fatalf("supported_ta_list not drilled: %+v", g.SupportedTAList)
	}
	if g.PDUSessionSetup == nil || g.PDUSessionSetup.PDUSessionID != 7 || g.PDUSessionSetup.SST != 2 || g.PDUSessionSetup.SD != 1 {
		t.Fatalf("pdu_session_setup not drilled: %+v", g.PDUSessionSetup)
	}
}
