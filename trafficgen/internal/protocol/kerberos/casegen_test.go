package kerberos

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 用例生成器（一次性，D-KERBEROS-1 P5）：按用例文档 §2 权威序产出 20 例
// （14 正 + 6 负）。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，
// 与套件同路径——单权威，无重复编码）。帧内 Kerberos 起点：IPv4/UDP=42、
// IPv6/UDP=62、IPv4/TCP=54（无 TCP options）；TCP 每消息前置 4B BE record
// 长度（不含自身——RFC 4120 §6）。
//
// packet_count 与契约 §2 约定值的偏离（裁定4 P5 实测重钉，落 TEST_CASES
// v1.0.1）：③tcp_record_framing 原约定 8（一条 record 跨 TCP segments 需
// cipher_len 撑长 + mss 536，实测 10=3 握手+3 段+4 挥手）；④as_req_as_rep
// 原约定 4（单对 AS-REQ/AS-REP 语义完备，实测 2）。其余 12 例实测与约定
// 一致。

type kfld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Distinct []string
	Exclude  []string
}

func (f kfld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	return m
}

type kfr struct {
	Packet int
	Offset int
	Hex    string
}

func (f kfr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type kposCase struct {
	id      string
	summary string
	layers  []interface{}
	count   int
	base    int
	fields  []kfld
	frames  []kfr
}

type knegCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
}

const (
	kCli   = "192.0.2.59"
	kSrv   = "198.51.100.59"
	kCli6  = "2001:db8::59"
	kSrv6  = "2001:db8:ffff::59"
	kSport = 40159
	kPort  = 88
)

// 字面量钉（内容权威）：链级单测 TestKerberosChain_* 已逐位钉死的缺省
// fixture 字节；本文件用它们锚定"链回放 = builder 渲染 + 双载体分帧"。
// 其余帧钉由 kPin 从同一 buildMessage 派生（与 dtls casegen 的 recHex/hsHex
// 同判：DER 内容权威在链级单测，本文件权威在分帧/序/方向/会话路由）。
const (
	hexASReqDefault = "6A4A3048A103020105A20302010AA43C303AA00703050000000000A20E1B0C4558414D504C452E54455354A511180F32303337303931333032343830355AA70502030BDF11A8053003020112"
	hexKrbErrPre    = "7E393037A003020105A10302011EA411180F32303236303932343132303030305AA503020100A603020107A90E1B0C4558414D504C452E54455354"
)

// kPin 渲染一事件的完整 DER 并大写 hex（builder 单权威；与套件走同一
// buildMessage）。
func kPin(t *testing.T, ev core.KerberosEvent) string {
	t.Helper()
	b, err := buildMessage(&ev)
	if err != nil {
		t.Fatalf("buildMessage(%s): %v", ev.Kind, err)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// kPinPrefix 取前 n 字节（n 为字节数）——长形长度前缀随字段长度变化时只钉
// 稳定头。
func kPinPrefix(t *testing.T, ev core.KerberosEvent, n int) string {
	t.Helper()
	h := kPin(t, ev)
	return h[:2*n]
}

func kInt(i int) *int { return &i }

// ip(n)/udp(n)/tcpLayer(n)/kLayer 快捷构造。
func ipL(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func udpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"udp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func tcpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func kL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"kerberos": cfg}
}
func kEv(kind string, up bool, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"kind": kind, "up": up}
	for k, v := range extra {
		m[k] = v
	}
	return m
}
func kSess(events ...map[string]interface{}) map[string]interface{} {
	evs := make([]interface{}, len(events))
	for i, e := range events {
		evs[i] = e
	}
	return map[string]interface{}{"events": evs}
}
func kSessAt(srcIP string, srcPort int, events ...map[string]interface{}) map[string]interface{} {
	m := kSess(events...)
	if srcIP != "" {
		m["src_ip"] = srcIP
	}
	if srcPort != 0 {
		m["src_port"] = srcPort
	}
	return m
}
func kChain(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipL(kCli, kSrv), udpL(kSport, kPort), kL(cfg)}
}
func kChain6(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipL(kCli6, kSrv6), udpL(kSport, kPort), kL(cfg)}
}
func kChainTCP(cfg map[string]interface{}, mss int) []interface{} {
	tc := map[string]interface{}{"src_port": kSport, "dst_port": kPort}
	if mss != 0 {
		tc["mss"] = mss
	}
	return []interface{}{ipL(kCli, kSrv), map[string]interface{}{"tcp": tc}, kL(cfg)}
}

func planKChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("kerberos", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: kCli, DstIP: kSrv, SrcPort: kSport, DstPort: kPort}
	if len(layersArr) > 0 {
		if ip, ok := layersArr[0].(map[string]interface{})["ip"].(map[string]interface{}); ok {
			spec.SrcIP, spec.DstIP = ip["src"].(string), ip["dst"].(string)
		}
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// frameAsserts 校验 wire 帧与 pin 一致（单权威构造，不手拼字节）。
func kFrameAsserts(t *testing.T, pkts []core.PacketConfig, specs []kfr) []kfr {
	t.Helper()
	out := make([]kfr, 0, len(specs))
	for _, sp := range specs {
		if sp.Packet > len(pkts) {
			t.Fatalf("frame %d out of range (%d packets)", sp.Packet, len(pkts))
		}
		// 载体起点：IPv4/TCP 无 options=54（14+20+20）、IPv6/UDP=62（14+40+8）、
		// 其余（IPv4/UDP）=42（14+20+8）——契约 §3 偏移表。
		base := 42
		if pkts[sp.Packet-1].L4.Protocol == "tcp" {
			base = 54
		} else if sp.Offset >= 62 {
			base = 62
		}
		payload := pkts[sp.Packet-1].Payload
		idx := 0
		if sp.Offset > base {
			idx = sp.Offset - base
		}
		ln := len(sp.Hex) / 2
		if idx+ln > len(payload) {
			t.Fatalf("frame %d: pin at %d+%d exceeds payload %d", sp.Packet, idx, ln, len(payload))
		}
		h := strings.ToUpper(hex.EncodeToString(payload[idx : idx+ln]))
		if h != sp.Hex {
			t.Fatalf("frame %d@%d: wire %s does not match pin %s", sp.Packet, sp.Offset, h, sp.Hex)
		}
		out = append(out, kfr{Packet: sp.Packet, Offset: sp.Offset, Hex: sp.Hex})
	}
	return out
}

// ============================================================
//  正例（14 例，按用例文档 §2 权威序）
// ============================================================

func TestGenerateKerberosCases(t *testing.T) {
	var positives []kposCase

	// builder 派生钉（分帧/序权威；DER 内容权威=链级单测字面量）。
	asRepDef := core.KerberosEvent{Kind: "as_rep"}
	apReqDef := core.KerberosEvent{Kind: "ap_req", Up: true}
	apRepDef := core.KerberosEvent{Kind: "ap_rep"}
	asRep700 := kPin(t, core.KerberosEvent{Kind: "as_rep", CipherLen: 700})
	// record 长度前缀（4B BE，不含自身——RFC 4120 §6）。
	asRepRecPrefix := fmt.Sprintf("%08X", len(asRep700)/2)

	add := func(id, summary string, layersArr []interface{}, count int, fields []kfld, framePins []kfr) {
		pkts := planKChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, contract pins %d", id, len(pkts), count)
		}
		base := 42
		if len(framePins) > 0 && framePins[0].Offset >= 62 {
			base = 62
		}
		frames := kFrameAsserts(t, pkts, framePins)
		positives = append(positives, kposCase{id: id, summary: summary, layers: layersArr, count: count, base: base, fields: fields, frames: frames})
	}

	// ① kerberos_ipv4_udp_as_basic（4）：kinit 标准形态——无 preauth AS-REQ →
	// KRB-ERROR(PREAUTH_REQUIRED) → 带 PA-ENC-TIMESTAMP 的 AS-REQ' → AS-REP。
	add("kerberos_ipv4_udp_as_basic", "IPv4/UDP 88 AS 交换（preauth 轮回 kinit 形态）",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
			kEv("as_req", true, map[string]interface{}{"padata": []interface{}{
				map[string]interface{}{"type": 2, "value_len": 4},
			}}),
			kEv("as_rep", false, nil),
		)}}), 4,
		[]kfld{
			{1, "ip.proto", "17", 0, nil, nil},
			{1, "udp.dstport", "88", 0, nil, nil},
			{1, "kerberos.msg_type", "10", 0, nil, nil},
			{1, "kerberos.pvno", "5", 0, nil, nil},
			{1, "kerberos.nonce", "778001", 0, nil, nil},
			{2, "kerberos.msg_type", "30", 0, nil, nil},
			{2, "kerberos.error_code", "7", 0, nil, nil},
			{3, "kerberos.msg_type", "10", 0, nil, nil},
			{4, "kerberos.msg_type", "11", 0, nil, nil},
			{4, "kerberos.CNameString", "user", 0, nil, nil},
		},
		[]kfr{
			{1, 42, hexASReqDefault},
			{2, 42, hexKrbErrPre},
			{4, 42, kPinPrefix(t, asRepDef, 32)},
		})

	// ② kerberos_ipv6_udp_as_basic（4）：同 fixture 独立地址族，起点 62。
	add("kerberos_ipv6_udp_as_basic", "IPv6/UDP 88 独立 AS fixture（外层地址族不改变 DER）",
		kChain6(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
			kEv("as_req", true, map[string]interface{}{"padata": []interface{}{
				map[string]interface{}{"type": 2, "value_len": 4},
			}}),
			kEv("as_rep", false, nil),
		)}}), 4,
		[]kfld{
			{1, "ipv6.nxt", "17", 0, nil, nil},
			{1, "udp.dstport", "88", 0, nil, nil},
			{1, "kerberos.msg_type", "10", 0, nil, nil},
		},
		[]kfr{
			{1, 62, hexASReqDefault},
			{2, 62, hexKrbErrPre},
		})

	// ③ kerberos_tcp_record_framing（11，原约定 8——裁定4 P5 实测重钉）：
	// TCP/88 握手 3 + AS-REQ 整 record 1 段（80B）+ AS-REP record（cipher_len
	// 700 双 enc-part 同扩 + 长度形升级 → 1559B，前缀 0x0000061B）跨 3
	// segments（mss 536：536/536/491）+ 挥手 4 = 11。record 长度不含自身
	//（RFC 4120 §6——裁定7）。
	add("kerberos_tcp_record_framing", "TCP 4-byte record framing：整 record + record 跨 segments 按 length 重组",
		kChainTCP(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("as_rep", false, map[string]interface{}{"cipher_len": 700}),
		)}}, 536), 11,
		[]kfld{
			{1, "tcp.dstport", "88", 0, nil, nil},
			{1, "tcp.flags.syn", "1", 0, nil, nil},
			{4, "tcp.len", "80", 0, nil, nil},
			{5, "tcp.len", "536", 0, nil, nil},
			{6, "tcp.len", "536", 0, nil, nil},
			{7, "tcp.len", "495", 0, nil, nil},
		},
		[]kfr{
			{4, 54, "0000004C" + hexASReqDefault},
			{5, 54, asRepRecPrefix + asRep700[:64]},
		})

	// ④ kerberos_as_req_as_rep（2，原约定 4——裁定4 重钉）：裸 AS 对，显式
	// principal/realm/nonce 外壳逐字段断言。
	add("kerberos_as_req_as_rep", "AS-REQ/AS-REP 单对：nonce/realm/principal 外壳",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, map[string]interface{}{
				"cname": []interface{}{"alice"}, "sname": []interface{}{"krbtgt", "EXAMPLE.TEST"},
				"nonce": 778101, "name_type": 1, "realm": "EXAMPLE.TEST",
			}),
			kEv("as_rep", false, map[string]interface{}{
				"cname": []interface{}{"alice"}, "crealm": "EXAMPLE.TEST",
				"realm": "EXAMPLE.TEST", "nonce": 778101,
			}),
		)}}), 2,
		[]kfld{
			{1, "kerberos.msg_type", "10", 0, nil, nil},
			{1, "kerberos.CNameString", "alice", 0, nil, nil},
			{1, "kerberos.nonce", "778101", 0, nil, nil},
			{2, "kerberos.msg_type", "11", 0, nil, nil},
			{2, "kerberos.crealm", "EXAMPLE.TEST", 0, nil, nil},
			{2, "kerberos.CNameString", "alice", 0, nil, nil},
		},
		[]kfr{
			{1, 42, kPinPrefix(t, core.KerberosEvent{Kind: "as_req", Up: true,
				CName: []string{"alice"}, SName: []string{"krbtgt", "EXAMPLE.TEST"},
				Nonce: kInt(778101), NameType: kInt(1), Realm: "EXAMPLE.TEST"}, 24)},
		})

	// ⑤ kerberos_tgs_req_tgs_rep（6）：完整域登录链 AS→TGS→AP，TGS-REQ 携带
	// PA-TGS-REQ（padata-type 1，RFC 4120 §7.5.1）+ service principal 边界。
	add("kerberos_tgs_req_tgs_rep", "AS→TGS→AP 全链：krbtgt 与 service ticket 边界",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("as_rep", false, nil),
			kEv("tgs_req", true, map[string]interface{}{
				"padata": []interface{}{map[string]interface{}{"type": 1, "value_len": 8}},
				"sname":  []interface{}{"host", "app.example.test"},
				"nonce":  778201,
			}),
			kEv("tgs_rep", false, map[string]interface{}{"sname": []interface{}{"host", "app.example.test"}}),
			kEv("ap_req", true, nil),
			kEv("ap_rep", false, nil),
		)}}), 6,
		[]kfld{
			{3, "kerberos.msg_type", "12,14", 0, nil, nil},
			{3, "kerberos.SNameString", "krbtgt,EXAMPLE.TEST,host,app.example.test", 0, nil, nil},
			{4, "kerberos.msg_type", "13", 0, nil, nil},
			{5, "kerberos.msg_type", "14", 0, nil, nil},
			{6, "kerberos.msg_type", "15", 0, nil, nil},
		},
		[]kfr{
			{3, 42, kPinPrefix(t, core.KerberosEvent{Kind: "tgs_req", Up: true,
				PAData: []core.KerberosPAData{{Type: 1, ValueLen: 8}},
				SName:  []string{"host", "app.example.test"}, Nonce: kInt(778201)}, 15)},
			{4, 42, kPinPrefix(t, core.KerberosEvent{Kind: "tgs_rep",
				SName: []string{"host", "app.example.test"}}, 16)},
			{5, 42, kPinPrefix(t, apReqDef, 16)},
			{6, 42, kPin(t, apRepDef)},
		})

	// ⑥ kerberos_ap_req_ap_rep（6）：三服务 AP 交换（mutual auth），ticket/
	// authenticator 只断言 etype/长度外壳。
	add("kerberos_ap_req_ap_rep", "AP-REQ/AP-REP 三服务交换：ticket/authenticator opaque",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("ap_req", true, map[string]interface{}{"etype": 18, "kvno": 2, "cipher_len": 52}),
			kEv("ap_rep", false, map[string]interface{}{"etype": 18, "cipher_len": 52}),
			kEv("ap_req", true, map[string]interface{}{"etype": 17, "kvno": 1, "cipher_len": 64, "sname": []interface{}{"cifs", "fs.example.test"}}),
			kEv("ap_rep", false, map[string]interface{}{"etype": 17, "cipher_len": 64}),
			kEv("ap_req", true, map[string]interface{}{"etype": 23, "cipher_len": 36, "sname": []interface{}{"ldap", "dc.example.test"}}),
			kEv("ap_rep", false, map[string]interface{}{"etype": 23, "cipher_len": 36}),
		)}}), 6,
		[]kfld{
			{1, "kerberos.etype", "18,18", 0, nil, nil},
			{3, "kerberos.etype", "17,17", 0, nil, nil},
			{5, "kerberos.etype", "23,23", 0, nil, nil},
			{1, "kerberos.kvno", "2,2", 0, nil, nil},
		},
		[]kfr{
			{1, 42, kPinPrefix(t, core.KerberosEvent{Kind: "ap_req", Up: true,
				EType: kInt(18), KVNO: kInt(2), CipherLen: 52}, 16)},
			{2, 42, kPin(t, apRepDef)},
		})

	// ⑦ kerberos_krb_error_preauth_required（4）：KRB-ERROR 字段全可断言
	//（error_code/ctime/stime/susec/realm）+ 重试轮回。
	add("kerberos_krb_error_preauth_required", "KRB-ERROR PREAUTH_REQUIRED 字段面 + 重试",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("krb_error", false, map[string]interface{}{
				"error_code": 7, "e_text": "NEEDS-PA", "crealm": "EXAMPLE.TEST",
				"cname": []interface{}{"user"}, "sname": []interface{}{"krbtgt", "EXAMPLE.TEST"},
				"ctime": "20260924115959Z", "cusec": 111, "stime": "20260924120000Z", "susec": 222,
			}),
			kEv("as_req", true, map[string]interface{}{"padata": []interface{}{
				map[string]interface{}{"type": 2, "value_len": 4},
			}}),
			kEv("as_rep", false, nil),
		)}}), 4,
		[]kfld{
			{2, "kerberos.error_code", "7", 0, nil, nil},
			{2, "kerberos.ctime", "2026-09-24 11:59:59 (UTC)", 0, nil, nil},
			{2, "kerberos.cusec", "111", 0, nil, nil},
			{2, "kerberos.stime", "2026-09-24 12:00:00 (UTC)", 0, nil, nil},
			{2, "kerberos.susec", "222", 0, nil, nil},
			{2, "kerberos.CNameString", "user", 0, nil, nil},
		},
		[]kfr{
			{2, 42, kPin(t, core.KerberosEvent{Kind: "krb_error",
				ErrorCode: kInt(7), EText: "NEEDS-PA", CRealm: "EXAMPLE.TEST",
				CName: []string{"user"}, SName: []string{"krbtgt", "EXAMPLE.TEST"},
				CTime: "20260924115959Z", CUsec: kInt(111),
				Stime: "20260924120000Z", SUsec: kInt(222)})},
		})

	// ⑧ kerberos_preauth_rfc6113（6）：METHOD-DATA 保序（PA-ENC-TS 2 → 未知
	// 类型 150）+ PA-TGS-REQ（1）与 AS 预认证不可混淆。
	add("kerberos_preauth_rfc6113", "RFC 6113 METHOD-DATA 保序 + PA-TGS-REQ 载体区分",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
			kEv("as_req", true, map[string]interface{}{"padata": []interface{}{
				map[string]interface{}{"type": 2, "value_len": 4},
				map[string]interface{}{"type": 150, "value_len": 0},
			}}),
			kEv("as_rep", false, nil),
			kEv("tgs_req", true, map[string]interface{}{
				"padata": []interface{}{map[string]interface{}{"type": 1, "value_len": 8}},
			}),
			kEv("tgs_rep", false, nil),
		)}}), 6,
		[]kfld{
			{3, "kerberos.msg_type", "10", 0, nil, nil},
			{5, "kerberos.msg_type", "12,14", 0, nil, nil},
		},
		[]kfr{
			{3, 42, kPinPrefix(t, core.KerberosEvent{Kind: "as_req", Up: true,
				PAData: []core.KerberosPAData{{Type: 2, ValueLen: 4}, {Type: 150, ValueLen: 0}}}, 40)},
		})

	// ⑨ kerberos_ticket_principal_realm（6）：Ticket tkt-vno=5、realm、
	// sname name-type/name-string 组件精确。
	add("kerberos_ticket_principal_realm", "Ticket/principal/realm 组件与关联",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, map[string]interface{}{"cname": []interface{}{"bob"}}),
			kEv("as_rep", false, map[string]interface{}{"cname": []interface{}{"bob"}}),
			kEv("tgs_req", true, map[string]interface{}{
				"sname": []interface{}{"host", "web.example.test"}, "name_type": 2, "nonce": 778301,
			}),
			kEv("tgs_rep", false, map[string]interface{}{"cname": []interface{}{"bob"}}),
			kEv("ap_req", true, map[string]interface{}{"sname": []interface{}{"host", "web.example.test"}}),
			kEv("ap_rep", false, nil),
		)}}), 6,
		[]kfld{
			{1, "kerberos.CNameString", "bob", 0, nil, nil},
			{3, "kerberos.SNameString", "host,web.example.test", 0, nil, nil},
			{4, "kerberos.msg_type", "13", 0, nil, nil},
			{5, "kerberos.msg_type", "14", 0, nil, nil},
		},
		[]kfr{
			{4, 42, kPinPrefix(t, core.KerberosEvent{Kind: "tgs_rep",
				CName: []string{"bob"}}, 16)},
		})

	// ⑩ kerberos_encrypteddata_opaque（6）：etype/cipher_len 外壳可见、
	// 密文确定性填充 opaque。
	add("kerberos_encrypteddata_opaque", "EncryptedData etype/长度可见、内层 opaque",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_rep", false, map[string]interface{}{"etype": 18, "cipher_len": 52}),
			kEv("tgs_rep", false, map[string]interface{}{"etype": 17, "cipher_len": 64}),
			kEv("ap_req", true, map[string]interface{}{"etype": 23, "cipher_len": 16}),
			kEv("ap_rep", false, map[string]interface{}{"etype": 23, "cipher_len": 16}),
			kEv("as_rep", false, map[string]interface{}{"etype": 18, "kvno": 3, "cipher_len": 52}),
			kEv("ap_req", true, map[string]interface{}{"etype": 17, "cipher_len": 64}),
		)}}), 6,
		[]kfld{
			{1, "kerberos.etype", "18,18", 0, nil, nil},
			{2, "kerberos.etype", "17,17", 0, nil, nil},
			{3, "kerberos.etype", "23,23", 0, nil, nil},
			{5, "kerberos.kvno", "3,3", 0, nil, nil},
		},
		[]kfr{
			{3, 42, kPinPrefix(t, core.KerberosEvent{Kind: "ap_req", Up: true,
				EType: kInt(23), CipherLen: 16}, 16)},
			{4, 42, kPin(t, core.KerberosEvent{Kind: "ap_rep", EType: kInt(23), CipherLen: 16})},
		})

	// ⑪ kerberos_nonce_time_skew（6）：nonce 关联 + KRB_AP_ERR_SKEW(25)
	// skew 错误可见。
	add("kerberos_nonce_time_skew", "nonce 关联、时间窗口、KRB_AP_ERR_SKEW 边界",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, map[string]interface{}{"nonce": 778401, "till": "20380101120000Z"}),
			kEv("as_rep", false, nil),
			kEv("tgs_req", true, map[string]interface{}{"nonce": 778402}),
			kEv("tgs_rep", false, nil),
			kEv("ap_req", true, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 25, "stime": "20260924120130Z", "susec": 900}),
		)}}), 6,
		[]kfld{
			{1, "kerberos.nonce", "778401", 0, nil, nil},
			{3, "kerberos.nonce", "778402", 0, nil, nil},
			{1, "kerberos.till", "2038-01-01 12:00:00 (UTC)", 0, nil, nil},
			{6, "kerberos.error_code", "25", 0, nil, nil},
			{6, "kerberos.stime", "2026-09-24 12:01:30 (UTC)", 0, nil, nil},
			{6, "kerberos.susec", "900", 0, nil, nil},
		},
		[]kfr{
			{6, 42, kPin(t, core.KerberosEvent{Kind: "krb_error",
				ErrorCode: kInt(25), Stime: "20260924120130Z", SUsec: kInt(900)})},
		})

	// ⑫ kerberos_replay_retransmission（8）：合法重传复用相同 request
	// bytes/nonce；重复 AP-REQ 触发 replay 错误（错误面可见，非静默）。
	add("kerberos_replay_retransmission", "请求重传复用 bytes + 重复 AP-REQ replay 错误",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("as_req", true, nil), // 合法重传：同 bytes 同 nonce
			kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
			kEv("as_req", true, map[string]interface{}{"padata": []interface{}{map[string]interface{}{"type": 2, "value_len": 4}}}),
			kEv("as_rep", false, nil),
			kEv("ap_req", true, nil),
			kEv("ap_req", true, nil), // 重复 authenticator → replay
			kEv("krb_error", false, map[string]interface{}{"error_code": 41}), // KRB_AP_ERR_REPEAT
		)}}), 8,
		[]kfld{
			{1, "kerberos.msg_type", "10", 0, nil, nil},
			{2, "kerberos.msg_type", "10", 0, nil, nil},
			{6, "kerberos.msg_type", "14", 0, nil, nil},
			{8, "kerberos.error_code", "41", 0, nil, nil},
			{1, "ip.src", kCli, 0, []string{kCli}, []string{kSrv}},
		},
		[]kfr{
			{1, 42, hexASReqDefault},
			{2, 42, hexASReqDefault},
		})

	// ⑬ kerberos_multi_session_flow（12）：三客户端三会话（IPv4/UDP 88 同
	// 目的），会话端点独立、状态不串用。
	add("kerberos_multi_session_flow", "多会话/多流：三客户端独立 nonce/ticket/framing 状态",
		kChain(map[string]interface{}{"sessions": []interface{}{
			kSessAt("192.0.2.61", 5001,
				kEv("as_req", true, nil),
				kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
				kEv("as_req", true, map[string]interface{}{"padata": []interface{}{map[string]interface{}{"type": 2, "value_len": 4}}}),
				kEv("as_rep", false, nil),
			),
			kSessAt("192.0.2.62", 5002,
				kEv("tgs_req", true, nil),
				kEv("tgs_rep", false, nil),
				kEv("ap_req", true, nil),
				kEv("ap_rep", false, nil),
			),
			kSessAt("192.0.2.63", 5003,
				kEv("as_req", true, nil),
				kEv("as_rep", false, nil),
				kEv("ap_req", true, nil),
				kEv("ap_rep", false, nil),
			),
		}}), 12,
		[]kfld{
			{1, "udp.srcport", "5001", 0, nil, nil},
			{5, "udp.srcport", "5002", 0, nil, nil},
			{9, "udp.srcport", "5003", 0, nil, nil},
			{5, "kerberos.msg_type", "12", 0, nil, nil},
			{9, "kerberos.msg_type", "10", 0, nil, nil},
		},
		[]kfr{
			{9, 42, hexASReqDefault},
		})

	// ⑭ kerberos_pcap_nic_consistency（8）：稳定前缀双钉 + 方向/端口/顶层
	// tag 一致（PCAP/NIC 同 fixture 口径——裁定4）。
	add("kerberos_pcap_nic_consistency", "PCAP/NIC 一致：方向/端口/88/record 外壳稳定",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, nil),
			kEv("as_rep", false, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 7}),
			kEv("ap_req", true, nil),
			kEv("ap_rep", false, nil),
			kEv("tgs_req", true, nil),
			kEv("tgs_rep", false, nil),
			kEv("krb_error", false, map[string]interface{}{"error_code": 25}),
		)}}), 8,
		[]kfld{
			{1, "udp.dstport", "88", 0, nil, nil},
			{2, "udp.srcport", "88", 0, nil, nil},
			{1, "kerberos.msg_type", "10", 0, nil, nil},
			{2, "kerberos.msg_type", "11", 0, nil, nil},
			{4, "kerberos.msg_type", "14", 0, nil, nil},
			{6, "kerberos.msg_type", "12", 0, nil, nil},
		},
		[]kfr{
			{1, 42, hexASReqDefault},
			{2, 42, kPinPrefix(t, asRepDef, 32)},
			{3, 42, hexKrbErrPre},
			{5, 42, kPin(t, apRepDef)},
		})

	// ============================================================
	//  负例（6 例）
	// ============================================================
	var negatives []knegCase

	addNeg := func(id, summary string, layersArr []interface{}, anchor string) {
		negatives = append(negatives, knegCase{id: id, summary: summary, layers: layersArr, anchor: anchor})
	}

	// ⑮ record_truncated
	addNeg("kerberos_neg_truncated_record", "消息/DER 头截断（wire_fault 注入）",
		kChain(map[string]interface{}{"wire_fault": "record_truncated"}),
		"record")

	// ⑯ record_length（TCP 4B 前缀错）
	addNeg("kerberos_neg_tcp_length", "TCP 4-byte record 长度前缀错（wire_fault 注入）",
		kChainTCP(map[string]interface{}{"wire_fault": "record_length"}, 0),
		"tcp")

	// ⑰ message_tag（自然配置：声明 msg_type≠kind 派生——裁定6 守卫）
	addNeg("kerberos_neg_message_tag", "顶层 tag/msg-type 不一致（声明 msg_type=11 于 as_req）",
		kChain(map[string]interface{}{"sessions": []interface{}{kSess(
			kEv("as_req", true, map[string]interface{}{"msg_type": 11}),
		)}}),
		"tag")

	// ⑱ encrypted_boundary
	addNeg("kerberos_neg_encrypted_boundary", "EncryptedData 外壳越界（wire_fault 注入）",
		kChain(map[string]interface{}{"wire_fault": "encrypted_boundary"}),
		"encrypted")

	// ⑲ replay
	addNeg("kerberos_neg_time_nonce_replay", "skew/nonce/replay 状态错（wire_fault 注入）",
		kChain(map[string]interface{}{"wire_fault": "replay"}),
		"replay")

	// ⑳ udp_carrier（udp+tcp 双载体并存——预检拒）
	addNeg("kerberos_neg_udp_carrier", "双载体并存拒（一条 kerberos 流只骑单载体）",
		[]interface{}{
			ipL(kCli, kSrv),
			udpL(kSport, kPort),
			tcpL(kSport, kPort),
			kL(map[string]interface{}{}),
		},
		"udp")

	// ---- 写入（套件同构扁平数组：spec_json/expect/decode_as）----
	type outCase struct {
		ID       string                 `json:"id"`
		Proto    string                 `json:"proto"`
		Summary  string                 `json:"summary"`
		Spec     map[string]interface{} `json:"spec_json"`
		Expect   map[string]interface{} `json:"expect"`
		DecodeAs []string               `json:"decode_as,omitempty"`
	}
	var out []outCase
	for _, pc := range positives {
		fields := make([]interface{}, 0, len(pc.fields))
		for _, f := range pc.fields {
			fields = append(fields, f.m())
		}
		frames := make([]interface{}, 0, len(pc.frames))
		for _, f := range pc.frames {
			frames = append(frames, f.m())
		}
		expect := map[string]interface{}{
			"packet_count": pc.count,
			"fields":       fields,
			"frames":       frames,
		}
		out = append(out, outCase{ID: pc.id, Proto: "kerberos", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect})
	}
	for _, nc := range negatives {
		out = append(out, outCase{ID: nc.id, Proto: "kerberos", Summary: nc.summary,
			Spec:   map[string]interface{}{"layers": nc.layers},
			Expect: map[string]interface{}{"expect_error": true, "error_contains": nc.anchor}})
	}
	if len(out) != 20 {
		t.Fatalf("want 20 cases, built %d", len(out))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := "../../../test/protocol_pcap/cases/kerberos.json"
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases (%d pos + %d neg)", len(out), len(positives), len(negatives))
}
