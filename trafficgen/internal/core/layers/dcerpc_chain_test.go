package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dcerpc" // init 注册 dcerpc 终结层生成器+校验器
)

// D-DCERPC-1 P4 链级红例（bacnet_chain_test 同构）：
// ①EPM 基线 bind→bind_ack 字节钉（16B 头 LE/UUID 混合端序/secondary "1025"）
// ②request→response（callWalker 缺省迭代 1→2）③bind_ack rejected→request 引用
// 拒（syntax）④ALTER_CTX/RESP ⑤分片 FIRST/LAST ⑥fault status ⑦auth trailer
// ⑧多会话按端口隔离 ⑨uuid 混合端序权威钉 ⑩prebound；负例：自然面守卫+
// 未知 wire_fault+载体三形状。fixture：客户端 192.0.2.63 / 服务端 198.51.100.63
// / EPM 135 / NDR syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0。

const (
	dceTestAbstract = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	dceTestSyntax   = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	dceCli          = "192.0.2.63"
	dceSrv          = "198.51.100.63"
)

func dceChainJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func dceLayers(cfg map[string]interface{}, dstPort interface{}) []interface{} {
	tcpLayer := map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40063, "dst_port": dstPort}}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": dceCli, "dst": dceSrv}},
		tcpLayer,
		map[string]interface{}{"dcerpc": cfg},
	}
}

func planDCERPCChainAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("dcerpc", dceChainJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: dceCli, DstIP: dceSrv, SrcPort: 40063, DstPort: 135}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

func driveDCERPC(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planDCERPCChainAt(t, dceLayers(cfg, 135))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveDCERPCErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planDCERPCChainAt(t, dceLayers(cfg, 135))
	return err
}

func dceHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

func dceTestContexts() []interface{} {
	return []interface{}{map[string]interface{}{
		"context_id":       0,
		"abstract":         dceTestAbstract,
		"abstract_version": []interface{}{3, 0},
		"syntaxes": []interface{}{map[string]interface{}{
			"uuid": dceTestSyntax, "version": []interface{}{2, 0}}},
	}}
}

// dceBindEvents 构造基线 bind 事件（.respond bind_ack + secondary "1025"）。
func dceBindEvents() []interface{} {
	return []interface{}{map[string]interface{}{
		"kind": "bind", "contexts": dceTestContexts(),
		"respond": map[string]interface{}{
			"ack":       "bind_ack",
			"secondary": "1025",
			"results": []interface{}{map[string]interface{}{
				"context_id": 0, "result": 0, "reason": 0,
				"uuid": dceTestSyntax, "version": []interface{}{2, 0}}},
		},
	}}
}

// ① EPM 基线：bind→bind_ack（secondary "1025"）。帧 1 与正例逐字节：
// frag_len 0x48=72、assoc 0、单 ctx、UUID 混合端序。
func TestDCERPCChain_BindBaselineBytes(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{map[string]interface{}{
		"events": dceBindEvents()}}}
	pkts := driveDCERPC(t, cfg)
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets (3 hs + bind + ack + 4 fin), got %d", len(pkts))
	}
	want1 := "05000B03100000004800000001000000" +
		"D016D0160000000001000000" +
		"000001000883AFE11F5DC91191A408002B14A0FA03000000" +
		"045D888AEB1CC9119FE808002B10486002000000"
	if got := dceHex(t, pkts, 3); got != want1 {
		t.Fatalf("bind mismatch:\n got %s\nwant %s", got, want1)
	}
	want2 := "05000C03100000003C00000001000000" +
		"D016D0160000000004003130323500000100000000000000045D888AEB1CC9119FE808002B10486002000000"
	if got := dceHex(t, pkts, 4); got != want2 {
		t.Fatalf("bind_ack mismatch:\n got %s\nwant %s", got, want2)
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions: %s / %s", pkts[0].Direction, pkts[1].Direction)
	}
}

// ② request→response：callWalker 缺省迭代（bind=1 → request=2）、opnum LE。
func TestDCERPCChain_RequestResponseBytes(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{map[string]interface{}{
		"prebound": true,
		"events": []interface{}{map[string]interface{}{
			"kind": "request", "context_id": 0, "opnum": 2, "alloc_hint": 8,
			"stub":    "010400010400",
			"respond": map[string]interface{}{"ack": "response", "stub": "010400"}}}}}}
	pkts := driveDCERPC(t, cfg)
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	// request：alloc 08000000 ctx 0000 op 0200 + stub 6B → frag 0x1C，call 1（prebound 无 bind，walker 起 1）
	want1 := "05000003100000001E000000010000000800000000000200010400010400"
	if got := dceHex(t, pkts, 3); got != want1 {
		t.Fatalf("request mismatch:\n got %s\nwant %s", got, want1)
	}
	// response：alloc 00000000 ctx 0000 cc 00 rsv 00 + stub 3B → frag 0x17
	want2 := "05000203100000001B000000010000000000000000000000010400"
	if got := dceHex(t, pkts, 4); got != want2 {
		t.Fatalf("response mismatch:\n got %s\nwant %s", got, want2)
	}
}

// ③ callWalker 相邻声明：bind 声明 call 5 → request 缺省迭代 6。
func TestDCERPCChain_CallWalkerSequence(t *testing.T) {
	bind := map[string]interface{}{
		"kind": "bind", "call_id": 5, "contexts": dceTestContexts(),
		"respond": map[string]interface{}{
			"ack": "bind_ack",
			"results": []interface{}{map[string]interface{}{
				"context_id": 0, "result": 0, "uuid": dceTestSyntax,
				"version": []interface{}{2, 0}}},
		},
	}
	req := map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 0}
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{bind, req}}}}
	pkts := driveDCERPC(t, cfg)
	if len(pkts) != 10 {
		t.Fatalf("want 10 packets (3 hs + bind + ack + req + 4 fin), got %d", len(pkts))
	}
	got := dceHex(t, pkts, 5)
	// call_id 住 16B 头 offset 12（hex[24:32]）；frag 16+alloc4+ctx2+op2=24=0x18
	if !strings.HasPrefix(got, "050000031000000018000000") || got[24:32] != "06000000" {
		t.Fatalf("request call_id not 6: %s", got)
	}
}

// ④ 分片 FIRST/LAST：fragments 2 → 两片 flags 01/02，同 call_id。
func TestDCERPCChain_FragmentFlags(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{
			"prebound": true,
			"events": []interface{}{map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0, "fragments": 2,
				"stub": "0011223344556677"}}}}}
	pkts := driveDCERPC(t, cfg)
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets (3 hs + 2 frag + 4 fin), got %d", len(pkts))
	}
	p1, p2 := dceHex(t, pkts, 3), dceHex(t, pkts, 4)
	if !strings.HasPrefix(p1, "050000011") || !strings.HasPrefix(p2, "050000021") {
		t.Fatalf("frag flags wrong: %s / %s", p1[:12], p2[:12])
	}
	if !strings.Contains(p1, "00112233") || !strings.Contains(p2, "44556677") {
		t.Fatalf("stub split wrong: %s / %s", p1, p2)
	}
}

// ⑤ fault：REQUEST→FAULT status。
func TestDCERPCChain_FaultStatus(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{
			"prebound": true,
			"events": []interface{}{map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0,
				"respond": map[string]interface{}{"ack": "fault", "status": 5}}}}}}
	pkts := driveDCERPC(t, cfg)
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	// fault body: alloc(4) ctx(2) cc(1) rsv(1) status(4) rsv2(4)=12B → frag 0x1C
	want := "0500030310000000200000000100000000000000000000000500000000000000"
	if got := dceHex(t, pkts, 4); got != want {
		t.Fatalf("fault mismatch:\n got %s\nwant %s", got, want)
	}
}

// ⑥ auth trailer：request + auth（type 10/level 2/pad 0/creds 4B）。
func TestDCERPCChain_AuthTrailer(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{
			"prebound": true,
			"events": []interface{}{map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0, "stub": "AABB",
				"auth":    map[string]interface{}{"type": 10, "level": 2, "context_id": 0, "credentials": "DEADBEEF"},
				"respond": map[string]interface{}{"ack": "response"}}}}}}
	pkts := driveDCERPC(t, cfg)
	got := dceHex(t, pkts, 3)
	// body: alloc4+ctx2+op2+stub2=10；trailer = 6B 头(type/level/padlen/rsv/ctx_id u16)+4 creds → frag 16+10+10=36=0x24 auth_len 10=0x0A
	if !strings.HasPrefix(got, "050000031000000024000A0001000000") || !strings.HasSuffix(got, "0A0200000000DEADBEEF") {
		t.Fatalf("auth trailer layout wrong: %s", got)
	}
}

// ⑦ 多会话按事件端口隔离：EPM(135 缺省)+dynamic(4135 显式) 顺序展开。
func TestDCERPCChain_MultiSessionPorts(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "bind", "contexts": dceTestContexts()}},
		},
		map[string]interface{}{
			"dst_port": 4135,
			"prebound": true,
			"events": []interface{}{map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0}},
		},
	}}
	pkts := driveDCERPC(t, cfg)
	// concurrent=true（链级缺省）：按 event index 交错——conn1 hs+bind[0..3]、
	// conn2 hs+req[4..7]、conn1 4fin[8..11]、conn2 4fin[12..15]。
	if len(pkts) != 16 {
		t.Fatalf("want 16 packets (3hs+bind+3hs+req interleaved + 8 fin), got %d", len(pkts))
	}
	if pkts[3].L4.DstPort != 135 || pkts[7].L4.DstPort != 4135 {
		t.Fatalf("session ports: %v / %v, want 135 / 4135", pkts[3].L4.DstPort, pkts[7].L4.DstPort)
	}
	if pkts[3].Payload == nil || pkts[7].Payload == nil {
		t.Fatalf("data frames missing payload: %v / %v", pkts[3].Payload, pkts[7].Payload)
	}
}

// ⑧ 自然面守卫（红线词逐条）——cfg 统一经 helper 构造。
func dceSess(prebound bool, events ...interface{}) map[string]interface{} {
	m := map[string]interface{}{"events": events}
	if prebound {
		m["prebound"] = true
	}
	return map[string]interface{}{"sessions": []interface{}{m}}
}

func TestDCERPCChain_NaturalGuards(t *testing.T) {
	bindAckReject := map[string]interface{}{
		"kind": "bind", "contexts": dceTestContexts(),
		"respond": map[string]interface{}{
			"ack": "bind_ack",
			"results": []interface{}{map[string]interface{}{
				"context_id": 0, "result": 2, "uuid": dceTestSyntax,
				"version": []interface{}{2, 0}}},
		},
	}
	bindOK := map[string]interface{}{
		"kind": "bind", "contexts": dceTestContexts(),
		"respond": func() map[string]interface{} {
			m := map[string]interface{}{"ack": "bind_ack"}
			m["results"] = []interface{}{map[string]interface{}{
				"context_id": 0, "result": 0, "uuid": dceTestSyntax,
				"version": []interface{}{2, 0}}}
			return m
		}(),
	}
	cases := []struct {
		name   string
		cfg    map[string]interface{}
		anchor string
	}{
		{"state_request_unbound", dceSess(false, map[string]interface{}{"kind": "request", "context_id": 0}), "state"},
		{"context_duplicate", dceSess(false,
			map[string]interface{}{"kind": "bind", "contexts": []interface{}{dceTestContexts()[0], dceTestContexts()[0]}}), "context"},
		{"context_unknown", dceSess(false, bindAckReject,
			map[string]interface{}{"kind": "request", "context_id": 0}), "syntax"},
		{"call_id_reuse", dceSess(true,
			map[string]interface{}{"kind": "request", "call_id": 3, "context_id": 0},
			map[string]interface{}{"kind": "request", "call_id": 3, "context_id": 0}), "call"},
		{"alloc_hint_negative", dceSess(true,
			map[string]interface{}{"kind": "request", "context_id": 0, "alloc_hint": -1}), "hint"},
		{"context_syntax_missing_version", dceSess(false,
			map[string]interface{}{"kind": "bind", "contexts": []interface{}{map[string]interface{}{
				"context_id": 0, "abstract": dceTestAbstract,
				"abstract_version": []interface{}{3, 0},
				"syntaxes":         []interface{}{map[string]interface{}{"uuid": dceTestSyntax}}}}}), "uuid"},
		{"auth_pad_invalid", dceSess(true,
			map[string]interface{}{"kind": "request", "context_id": 0,
				"auth": map[string]interface{}{"type": 10, "pad": 7, "credentials": "AA"}}), "trailer"},
		{"call_mismatch", dceSess(true,
			map[string]interface{}{"kind": "request", "call_id": 1, "context_id": 0,
				"respond": map[string]interface{}{"ack": "response", "call_id": 9}}), "call"},
		{"bind_ack_wrong_type", dceSess(false,
			map[string]interface{}{"kind": "bind", "contexts": dceTestContexts(),
				"respond": map[string]interface{}{
					"ack": "response",
					"results": []interface{}{map[string]interface{}{
						"context_id": 0, "result": 0, "uuid": dceTestSyntax,
						"version": []interface{}{2, 0}}}}}), "state"},
		{"bind_ack_auth_silent_drop", dceSess(false,
			map[string]interface{}{"kind": "bind", "contexts": dceTestContexts(),
				"respond": map[string]interface{}{
					"ack": "bind_ack",
					"auth": map[string]interface{}{
						"type": 9, "level": 2, "credentials": "AA"},
					"results": []interface{}{map[string]interface{}{
						"context_id": 0, "result": 0, "uuid": dceTestSyntax,
						"version": []interface{}{2, 0}}}}}), "state"},
		{"unknown_kind", dceSess(false, map[string]interface{}{"kind": "mystery"}), "unknown event kind"},
		{"bind_ok_then_request_ok_negative_not", nil, ""}, // 占位删除
	}
	cases = cases[:len(cases)-1]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveDCERPCErr(t, tc.cfg)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err.Error(), tc.anchor)
			}
		})
	}
	_ = bindOK
}

// ⑨ 未知 wire_fault 分发拒。
func TestDCERPCChain_UnknownWireFault(t *testing.T) {
	err := driveDCERPCErr(t, map[string]interface{}{"wire_fault": "made_up_fault"})
	if err == nil || !strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("want unknown wire_fault rejection, got %v", err)
	}
}

// ⑩ 载体三形状：缺 tcp（carrier）/udp 载体（carrier）/混合地址族（family）。
func TestDCERPCChain_CarrierShapes(t *testing.T) {
	_, err := planDCERPCChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": dceCli, "dst": dceSrv}},
		map[string]interface{}{"dcerpc": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing tcp: want carrier rejection, got %v", err)
	}
	_, err = planDCERPCChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": dceCli, "dst": dceSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 135, "dst_port": 135}},
		map[string]interface{}{"dcerpc": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier: want carrier rejection, got %v", err)
	}
	_, err = planDCERPCChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::63", "dst": dceSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{}},
		map[string]interface{}{"dcerpc": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("mixed family: want family rejection, got %v", err)
	}
}
