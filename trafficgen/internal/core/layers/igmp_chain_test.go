package layers_test

// D-IGMP-1 P4 链级红例：[ip→igmp] raw-IP 链（ip-layer raw 第 13 连协议）。
// 红例面（契约 §14-P2）：①顶层 igmp 子映射 presence 判死；②白名单外游离键
// V9 拒；③链夹 tcp/udp 拒（carrier 锚）；④缺 ip 拒（carrier 锚）。
// 附 translate 上线正例：v2 report 层配置进 spec.IGMP，payload=1600+cksum+group。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 igmp 包 init 注册层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/igmp"
)

func igmpChainRaw(t *testing.T, igmpCfg map[string]interface{}, ipCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	if ipCfg == nil {
		ipCfg = map[string]interface{}{"src": "10.0.0.1"}
	}
	b, err := json.Marshal([]map[string]interface{}{
		{"ip": ipCfg},
		{"igmp": igmpCfg},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// 红①【D-IGMP-1 G-IGMP-1】：顶层 igmp 子映射 presence 判死（层链+顶层并存，
// 空映射同判死）。
func TestIGMPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1"}},
			map[string]interface{}{"igmp": map[string]interface{}{}},
		},
		"igmp": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("igmp", cfg); msg == "" {
		t.Fatal(`CheckProtoFlat(igmp, {layers, igmp:{}}) = "", want top-level igmp presence rejection`)
	} else if !strings.Contains(msg, "top-level igmp sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红②【D-IGMP-1 G-IGMP-2】：白名单（registry Fields）外游离键 V9 拒。
func TestIGMPChain_StrayLayerKeyRejected(t *testing.T) {
	raw := igmpChainRaw(t, map[string]interface{}{
		"profile": "v2",
		"kind":    "report",
		"group":   "239.1.1.1",
		"port":    1234, // registry Fields 白名单外
	}, nil)
	_, err := layers.BuildLayersPlanner("igmp", raw)
	if err == nil {
		t.Fatal("BuildLayersPlanner accepted stray layer key `port`, want unknown-field rejection")
	}
	if !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "port") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// 红③【D-IGMP-1 G-IGMP-3】：链夹 tcp/udp 拒——IGMP 裸 IP（protocol 2）无传输层。
func TestIGMPChain_TCPCarrierRejected(t *testing.T) {
	b, err := json.Marshal([]map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1"}},
		{"tcp": map[string]interface{}{"dst_port": 80}},
		{"igmp": map[string]interface{}{}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := layers.BuildLayersPlanner("igmp", b); err == nil {
		t.Fatal("BuildLayersPlanner accepted [ip,tcp,igmp], want carrier rejection")
	} else if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("anchor mismatch: %v", err)
	}

	b, err = json.Marshal([]map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1"}},
		{"udp": map[string]interface{}{"dst_port": 5353}},
		{"igmp": map[string]interface{}{}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := layers.BuildLayersPlanner("igmp", b); err == nil {
		t.Fatal("BuildLayersPlanner accepted [ip,udp,igmp], want carrier rejection")
	} else if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// 红④【D-IGMP-1 G-IGMP-3】：缺 ip 载体拒。
func TestIGMPChain_MissingIPCarrierRejected(t *testing.T) {
	b, err := json.Marshal([]map[string]interface{}{
		{"igmp": map[string]interface{}{"profile": "v2", "kind": "report"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := layers.BuildLayersPlanner("igmp", b); err == nil {
		t.Fatal("BuildLayersPlanner accepted bare [igmp], want missing-ip carrier rejection")
	} else if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), "ip") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// 正例【D-IGMP-1 裁定：translate 上线】：v2 report 层配置进 spec.IGMP，
// 生成器按 dstFor 仲裁（RFC 2236：Report 发往组地址）——L3.DstIP=group，
// payload 首字节 type=0x16。
func TestIGMPChain_LayerTranslateV2Report(t *testing.T) {
	p, err := layers.BuildLayersPlanner("igmp", igmpChainRaw(t, map[string]interface{}{
		"profile": "v2",
		"kind":    "report",
		"group":   "239.1.1.1",
	}, map[string]interface{}{"src": "10.0.0.1", "ttl": 1}))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", TTL: 1}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	pkt := <-ch
	if len(pkt.Payload) < 8 || pkt.Payload[0] != 0x16 {
		t.Fatalf("payload[0] = %#x, want 0x16 (v2 report)", pkt.Payload[0])
	}
	if got := pkt.L3.DstIP; got != "239.1.1.1" {
		t.Fatalf("L3.DstIP = %q, want 239.1.1.1 (dstFor: report -> group)", got)
	}
}
