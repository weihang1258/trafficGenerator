package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/kerberos" // init 注册 kerberos 终结层生成器+校验器
)

// D-KERBEROS-1 P4 链级红例（dtls_chain_test 同构）：①空配置基线（1 条
// 最小 AS-REQ datagram，76B 全 fixture 缺省——bacnet/dtls 空配置缺省家族）
// /②TCP 4B BE record 长度前缀（不含自身，RFC 4120 §6——裁定7）/③AS
// 请求-应答对（应答长形 0x81f0 双字节长度）/④七 kind 顶层 tag
// （6a/6b/6c/6d/6e/6f/7e——P2 tag 权威表）/⑤tag↔msg-type 一致性守卫
// （裁定6）/⑥⑦krb_error 必带 error_code/未知 kind/body 转义口/会话
// dst_port 冲突守卫/⑧6 wire_fault 注入锚词 + 未知 fault/⑨carrier 三形状
// （缺载体/udp+tcp 并存/混合地址族）/⑩严格解码（config 未知键拒）/
// ⑪多会话隔离（src_port/src_ip 覆盖 + down 显式路由回会话客户端）。
// 契约 fixture：客户端 192.0.2.59 / 服务端 198.51.100.59 / KDC 端口 88。

// kASReqDefault 是缺省 fixture AS-REQ 的完整 DER（76B；P4 实测钉，
// P5 tshark kerberos dissector 复核）：[10] AS-REQ { pvno[1]=5,
// msg-type[2]=10, req-body[4]{ kdc-options[0] BIT STRING(4B 全零),
// realm[2] "EXAMPLE.TEST", till[7] 20370913024805Z, nonce[9]=778001,
// etype[10]{18} } }。
const kASReqDefault = "6A4A3048A103020105A20302010AA43C303AA00703050000000000A20E040C4558414D504C452E54455354A711180F32303337303931333032343830355AA90502030BDF11AA053003020112"

func kerberosJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func kLayers(carrier string, cfg map[string]interface{}) []interface{} {
	tr := map[string]interface{}{"src_port": 40159, "dst_port": 88}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.59", "dst": "198.51.100.59"}},
		map[string]interface{}{carrier: tr},
		map[string]interface{}{"kerberos": cfg},
	}
}

func k6Layers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::59", "dst": "2001:db8:ffff::59"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 40159, "dst_port": 88}},
		map[string]interface{}{"kerberos": cfg},
	}
}

func planKerberosAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("kerberos", kerberosJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.59", DstIP: "198.51.100.59", SrcPort: 40159, DstPort: 88}
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

func driveK(t *testing.T, carrier string, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planKerberosAt(t, kLayers(carrier, cfg))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveKErr(t *testing.T, carrier string, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planKerberosAt(t, kLayers(carrier, cfg))
	return err
}

func kHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

func kSess(events ...map[string]interface{}) map[string]interface{} {
	evs := make([]interface{}, len(events))
	for i, e := range events {
		evs[i] = e
	}
	return map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": evs}}}
}

// ① 空配置基线：1 条最小 AS-REQ datagram（up/76B/端口 88），字节逐位钉。
func TestKerberosChain_UDPBaselineDefault(t *testing.T) {
	pkts := driveK(t, "udp", map[string]interface{}{})
	if len(pkts) != 1 {
		t.Fatalf("want 1 baseline datagram, got %d", len(pkts))
	}
	if pkts[0].Direction != "up" {
		t.Fatalf("baseline direction %q", pkts[0].Direction)
	}
	if pkts[0].L4.DstPort != 88 || pkts[0].L4.SrcPort != 40159 {
		t.Fatalf("ports: %d->%d", pkts[0].L4.SrcPort, pkts[0].L4.DstPort)
	}
	if got := kHex(t, pkts, 0); got != kASReqDefault {
		t.Fatalf("baseline bytes:\n got %s\nwant %s", got, kASReqDefault)
	}
}

// ② TCP 载体：3 握手 + 1 数据段 + 4 挥手 = 8 包；数据段前置 4B BE record
// 长度（不含自身——0x4C=76）+ 与 UDP 面逐字节相同的 DER（裁定7）。
func TestKerberosChain_TCPCarrierFraming(t *testing.T) {
	pkts := driveK(t, "tcp", map[string]interface{}{})
	if len(pkts) != 8 {
		t.Fatalf("tcp baseline: want 8 packets (3 hs + 1 data + 4 fin), got %d", len(pkts))
	}
	data := kHex(t, pkts, 3)
	if !strings.HasPrefix(data, "0000004C") {
		t.Fatalf("tcp record prefix: %s", data[:16])
	}
	if got := data[8:]; got != kASReqDefault {
		t.Fatalf("tcp DER body differs from UDP face:\n got %s", got)
	}
	if pkts[3].L4.Flags&0x18 != 0x18 { // PSH|ACK
		t.Fatalf("data segment flags %d", pkts[3].L4.Flags)
	}
}

// ③ AS 请求-应答对：up AS-REQ 76B 短形 / down AS-REP 243B 长形（0x81F0），
// down 方向端口交换（88→40159）。
func TestKerberosChain_ASReqRepPair(t *testing.T) {
	pkts := driveK(t, "udp", kSess(
		map[string]interface{}{"kind": "as_req", "up": true},
		map[string]interface{}{"kind": "as_rep", "up": false},
	))
	if len(pkts) != 2 {
		t.Fatalf("want 2, got %d", len(pkts))
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions: %s / %s", pkts[0].Direction, pkts[1].Direction)
	}
	if got := kHex(t, pkts, 0); got != kASReqDefault {
		t.Fatalf("as_req bytes:\n got %s", got)
	}
	rep := kHex(t, pkts, 1)
	if !strings.HasPrefix(rep, "6B81F0") {
		t.Fatalf("as_rep header (app tag 0x6b + long-form len 0x81f0): %s", rep[:16])
	}
	if len(rep)/2 != 243 {
		t.Fatalf("as_rep len %d, want 243", len(rep)/2)
	}
	if pkts[1].L4.SrcPort != 88 || pkts[1].L4.DstPort != 40159 {
		t.Fatalf("down ports: %d->%d", pkts[1].L4.SrcPort, pkts[1].L4.DstPort)
	}
}

// ④ 七 kind 顶层 application tag 一一对应（P2 tag 权威表逐行）：
// as_req 6a / as_rep 6b / tgs_req 6c / tgs_rep 6d / ap_req 6e / ap_rep 6f /
// krb_error 7e；msg-type 同值（报文 [1]/[2] 槽位）。
func TestKerberosChain_KindTagTable(t *testing.T) {
	table := []struct {
		kind string
		up   bool
		tag  string // 首字节 + SEQUENCE 长度形后的 msg-type 可见性由 tag 钉
		mt   string // msg-type INTEGER hex（后随 02 01 xx 或 02 xx）
	}{
		{"as_req", true, "6A", "0A"},
		{"as_rep", false, "6B", "0B"},
		{"tgs_req", true, "6C", "0C"},
		{"tgs_rep", false, "6D", "0D"},
		{"ap_req", true, "6E", "0E"},
		{"ap_rep", false, "6F", "0F"},
		{"krb_error", false, "7E", "1E"},
	}
	var events []map[string]interface{}
	for _, row := range table {
		ev := map[string]interface{}{"kind": row.kind, "up": row.up}
		if row.kind == "krb_error" {
			ev["error_code"] = 7
		}
		events = append(events, ev)
	}
	pkts := driveK(t, "udp", kSess(events...))
	if len(pkts) != len(table) {
		t.Fatalf("want %d datagrams, got %d", len(table), len(pkts))
	}
	for i, row := range table {
		got := kHex(t, pkts, i)
		if !strings.HasPrefix(got, row.tag) {
			t.Fatalf("%s: first byte %s, want %s", row.kind, got[:2], row.tag)
		}
		// msg-type 出现在 msg-type[2]（REQ）或 [1]（REP/ERROR）INTEGER 槽：
		// 序列 30 xx 后必见 02 01 <msg-type> 或 A1/A2 03 02 01 <mt>。
		if !strings.Contains(got[8:], "0201"+row.mt) {
			t.Fatalf("%s: msg-type %s not found in body %s", row.kind, row.mt, got[:48])
		}
	}
}

// ⑤ tag↔msg-type 一致性守卫（裁定6——自然配置通道）：as_req 声明
// msg_type=11 ≠ kind 派生 10 → 拒（锚 tag）。
func TestKerberosChain_MsgTypeGuard(t *testing.T) {
	err := driveKErr(t, "udp", kSess(map[string]interface{}{"kind": "as_req", "up": true, "msg_type": 11}))
	if err == nil || !strings.Contains(err.Error(), "(tag)") {
		t.Fatalf("msg-type guard: %v", err)
	}
}

// ⑥⑦ 结构守卫：krb_error 必带 error_code；未知 kind；body 转义口（奇长/
// 非 hex）；会话 dst_port 冲突。
func TestKerberosChain_StructureGuards(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		cont string
	}{
		{"krb_error_no_code", kSess(map[string]interface{}{"kind": "krb_error", "up": false}), "error_code"},
		{"unknown_kind", kSess(map[string]interface{}{"kind": "magic", "up": true}), "unknown event kind"},
		{"body_odd_hex", kSess(map[string]interface{}{"kind": "as_req", "up": true, "body": "ABC"}), "odd length"},
		{"body_non_hex", kSess(map[string]interface{}{"kind": "as_req", "up": true, "body": "ZZ"}), "non-hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveKErr(t, "udp", tc.cfg)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.cont)
			}
			if !strings.Contains(err.Error(), tc.cont) {
				t.Fatalf("error %q missing %q", err, tc.cont)
			}
		})
	}
	// 会话间 dst_port 冲突。
	err := driveKErr(t, "udp", map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"dst_port": 88, "events": []interface{}{map[string]interface{}{"kind": "as_req", "up": true}}},
		map[string]interface{}{"dst_port": 89, "events": []interface{}{map[string]interface{}{"kind": "as_req", "up": true}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "(port)") {
		t.Fatalf("dst_port conflict: %v", err)
	}
}

// ⑧ 6 wire_fault 注入锚词 + 未知 fault 拒（值面=设计 §2 配置键表逐字）。
func TestKerberosChain_WireFaults(t *testing.T) {
	for fault, anchor := range map[string]string{
		"record_truncated":   "anchor record",
		"record_length":      "anchor tcp",
		"tag":                "anchor tag",
		"encrypted_boundary": "anchor encrypted",
		"replay":             "anchor replay",
		"carrier":            "anchor udp",
	} {
		err := driveKErr(t, "udp", map[string]interface{}{"wire_fault": fault})
		if err == nil {
			t.Fatalf("%s: want error, got nil", fault)
		}
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: error %q missing anchor %q", fault, err, anchor)
		}
	}
	if err := driveKErr(t, "udp", map[string]interface{}{"wire_fault": "no_such_fault"}); err == nil ||
		!strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown fault: %v", err)
	}
}

// ⑨ carrier 三形状（预检锚词）：缺载体 / udp+tcp 并存 / 混合地址族。
func TestKerberosChain_CarrierShapes(t *testing.T) {
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.59", "dst": "198.51.100.59"}},
			map[string]interface{}{"kerberos": map[string]interface{}{}},
		}, "(carrier)"},
		{"dual_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.59", "dst": "198.51.100.59"}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": 40159, "dst_port": 88}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40159, "dst_port": 88}},
			map[string]interface{}{"kerberos": map[string]interface{}{}},
		}, "(carrier)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.59", "dst": "2001:db8:ffff::59"}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": 40159, "dst_port": 88}},
			map[string]interface{}{"kerberos": map[string]interface{}{}},
		}, "(family)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := func() error {
				_, err := planKerberosAt(t, tc.layers)
				return err
			}()
			if err == nil {
				t.Fatalf("want error with anchor %s, got nil", tc.anchor)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %s", err, tc.anchor)
			}
		})
	}
}

// ⑨b TCP 载体 + 会话 src_ip 覆盖 = 守卫拒（连接身份四元组，datagram 端点
// 覆盖面不适用——自然配置通道，锚词 carrier）。
func TestKerberosChain_TCPSrcIPGuard(t *testing.T) {
	err := driveKErr(t, "tcp", map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_ip": "192.0.2.60", "events": []interface{}{
			map[string]interface{}{"kind": "as_req", "up": true},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "(carrier)") {
		t.Fatalf("tcp src_ip guard: %v", err)
	}
}

// ⑩ 严格解码：kerberos 层 config 未知键拒（DisallowUnknownFields）。
func TestKerberosChain_StrictDecode(t *testing.T) {
	err := driveKErr(t, "udp", map[string]interface{}{"no_such_key": 1})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict decode: %v", err)
	}
}

// ⑪ 多会话隔离：逐会话 src_port/src_ip 覆盖；down 事件显式路由回会话
// 客户端（OverrideDstIP——服务端→双客户端各回各端）。
func TestKerberosChain_MultiSessionIsolation(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_port": 5001, "events": []interface{}{
			map[string]interface{}{"kind": "ap_req", "up": true},
		}},
		map[string]interface{}{"src_ip": "192.0.2.60", "src_port": 5002, "events": []interface{}{
			map[string]interface{}{"kind": "ap_req", "up": true},
			map[string]interface{}{"kind": "ap_rep", "up": false},
		}},
	}}
	pkts := driveK(t, "udp", cfg)
	if len(pkts) != 3 {
		t.Fatalf("want 3, got %d", len(pkts))
	}
	if pkts[0].L4.SrcPort != 5001 || pkts[1].L4.SrcPort != 5002 {
		t.Fatalf("src ports: %d / %d", pkts[0].L4.SrcPort, pkts[1].L4.SrcPort)
	}
	// 会话 2 的 AP-REQ/REP 字节独立于会话 1（ap_req 同 fixture，方向/会话隔离）。
	for i, tag := range []string{"6E", "6F"} {
		if got := kHex(t, pkts, i+1); !strings.HasPrefix(got, tag) {
			t.Fatalf("pkt %d first byte %s, want %s", i+1, got[:2], tag)
		}
	}
	// down 应答路由回会话 2 客户端 192.0.2.60（非流缺省 dst）。
	if pkts[2].Direction != "down" {
		t.Fatalf("pkt3 direction %q", pkts[2].Direction)
	}
	if pkts[2].L3.DstIP != "192.0.2.60" {
		t.Fatalf("down dst ip %q, want session client 192.0.2.60", pkts[2].L3.DstIP)
	}
}

// ⑫ IPv6 载体：同 fixture 独立地址族（设计 §9——外层地址族不改变 DER）。
func TestKerberosChain_IPv6Carrier(t *testing.T) {
	raw, _ := json.Marshal(k6Layers(map[string]interface{}{}))
	p, err := layers.BuildLayersPlanner("kerberos", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "2001:db8::59", DstIP: "2001:db8:ffff::59", SrcPort: 40159, DstPort: 88}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) != 1 {
		t.Fatalf("want 1, got %d", len(pkts))
	}
	if got := strings.ToUpper(hex.EncodeToString(pkts[0].Payload)); got != kASReqDefault {
		t.Fatalf("ipv6 DER differs:\n got %s", got)
	}
}
