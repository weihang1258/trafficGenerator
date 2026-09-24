package dtls

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

// 用例生成器（一次性，D-DTLS-1 P5）：按用例文档 §2 权威序产出 20 例
// （14 正 + 6 负）。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，
// 与套件同路径——单权威，无重复编码）。UDP/IPv4 帧内 record 起点 42、
// IPv6 62。
//
// v3 校准：①真实握手体取代空 body（CH SH Cert CKE HVR 均具 tshark 可
// 识别体，消除 Malformed）；②msg_seq 每方向独立计数器 + 续片复用旧值 +
// 声明推进（< 计数器 = 重传合法不推进）；③pin 索引校准（③⑦⑨⑫帧索引）。

type fld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Distinct []string
	Exclude  []string
}

func (f fld) m() map[string]interface{} {
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

type fr struct {
	Packet int
	Offset int
	Hex    string
}

func (f fr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type posCase struct {
	id      string
	summary string
	layers  []interface{}
	count   int
	base    int
	fields  []fld
	frames  []fr
}

type negCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
}

const (
	dtlsCli   = "192.0.2.63"
	dtlsSrv   = "198.51.100.63"
	dtlsCli6  = "2001:db8::63"
	dtlsSrv6  = "2001:db8:ffff::63"
	dtlsCli2  = "192.0.2.64"
	defaultSP = 44330
)

// --- 真实握手体（tshark DTLS 1.2 dissector 可识别）---

// rnd32 32B random 占位（全零确定性）；chBody0 ClientHello 无 cookie 体
// （ver2+rand32+sid0+cookie0+cs_len2+suite2+comp_len1+comp1 = 42B）。
var (
	rnd32    = strings.Repeat("00", 32)                                                                               // 64 hex
	chBody0  = "FEFD" + rnd32 + "00000002002F0100"                                                                    // 84 hex = 42B
	shBody   = "FEFD" + rnd32 + "00" + "002F" + "00"                                                                  // ServerHello 38B
	certBody = "000000"                                                                                               // 空 Certificate list
	ckeBody  = "0030414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141" // RSA CKE 50B（2B len 0x0030 + 48B blob——tshark DTLS CKE 前置 2B 长度）
)

// chBodyWithCookie: ver2+rand32+sid0+cookie_len(1)+cookie+cs+comp（CH' 带
// cookie 重发——RFC 6347 §4.2.1）。
func chBodyWithCookie(cookieHex string) string {
	b, _ := hex.DecodeString(cookieHex)
	return "FEFD" + rnd32 + "00" + fmt.Sprintf("%02x", len(b)) + cookieHex + "0002002F0100"
}

// --- 层/会话便捷构造 ---

func ipLayer(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func udpLayer(sport, dport int) map[string]interface{} {
	return map[string]interface{}{"udp": map[string]interface{}{"src_port": sport, "dst_port": dport}}
}
func dtlsLayer(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"dtls": cfg}
}

func hsE(up bool, typ int, extra map[string]interface{}) map[string]interface{} {
	h := map[string]interface{}{"type": typ}
	for k, v := range extra {
		h[k] = v
	}
	return map[string]interface{}{"kind": "handshake", "up": up, "handshake": h}
}
func ev(kind string, up bool, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"kind": kind, "up": up}
	for k, v := range extra {
		m[k] = v
	}
	return m
}
func ccs(up bool) map[string]interface{} { return ev("ccs", up, nil) }
func app(up bool, n int) map[string]interface{} {
	return ev("appdata", up, map[string]interface{}{"ciphertext_len": n})
}
func appE(up bool, n, e int) map[string]interface{} {
	return ev("appdata", up, map[string]interface{}{"epoch": e, "ciphertext_len": n})
}
func alertEnc(up bool, e int) map[string]interface{} {
	return ev("alert", up, map[string]interface{}{"epoch": e, "ciphertext_len": 2})
}
func dSess(events ...interface{}) map[string]interface{} {
	return map[string]interface{}{"events": events}
}
func dSessAt(srcIP string, srcPort int, version string, events ...interface{}) map[string]interface{} {
	m := map[string]interface{}{"events": events}
	if srcIP != "" {
		m["src_ip"] = srcIP
	}
	if srcPort != 0 {
		m["src_port"] = srcPort
	}
	if version != "" {
		m["version"] = version
	}
	return m
}

func chain(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer(dtlsCli, dtlsSrv), udpLayer(defaultSP, 4433), dtlsLayer(cfg)}
}
func chain6(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer(dtlsCli6, dtlsSrv6), udpLayer(defaultSP, 4433), dtlsLayer(cfg)}
}

func planChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("dtls", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: dtlsCli, DstIP: dtlsSrv, SrcPort: defaultSP, DstPort: 4433}
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

// recHex/hsHex 生成 record/握手 16 进制 pin（单权威构造，不手拼字节——
// 与 builder 同一套字段序：record 13B 全大端，握手头 type+len24+seq16+
// off24+fraglen24）。
func recHex(ct int, epoch, seq int, hs string) string {
	return fmt.Sprintf("%02XFEFD%04X%012X%04X", ct, epoch, seq, len(hs)/2) + hs
}
func hsHex(typ, length, msgSeq, off, fragLen int, bodyHex string) string {
	return fmt.Sprintf("%02X%06X%04X%06X%06X", typ, length, msgSeq, off, fragLen) + bodyHex
}

func frameAsserts(t *testing.T, pkts []core.PacketConfig, specs []fr) []fr {
	t.Helper()
	out := make([]fr, 0, len(specs))
	for _, sp := range specs {
		if sp.Packet > len(pkts) {
			t.Fatalf("frame %d out of range (%d packets)", sp.Packet, len(pkts))
		}
		base := 42
		if sp.Offset >= 62 {
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
		out = append(out, fr{Packet: sp.Packet, Offset: sp.Offset, Hex: sp.Hex})
	}
	return out
}

// ============================================================
//  正例（14 例，按用例文档 §2 权威序）
// ============================================================

func TestGenerateDTLSCases(t *testing.T) {
	var positives []posCase

	add := func(id, summary string, layersArr []interface{}, count int, fields []fld, framePins []fr) {
		pkts := planChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, contract pins %d", id, len(pkts), count)
		}
		base := 42
		if len(framePins) > 0 && framePins[0].Offset >= 62 {
			base = 62
		}
		frames := frameAsserts(t, pkts, framePins)
		positives = append(positives, posCase{id: id, summary: summary, layers: layersArr, count: count, base: base, fields: fields, frames: frames})
	}

	// ① dtls_ipv4_v12_basic（12）：CH→SH→Cert→CKE→CCS×2→appdata×4→加密 alert×2。
	add("dtls_ipv4_v12_basic", "IPv4/UDP 4433 DTLS 1.2 握手+应用+关闭基线",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 12,
		[]fld{
			{1, "ip.proto", "17", 0, nil, nil},
			{1, "udp.dstport", "4433", 0, nil, nil},
			{1, "dtls.record.version", "0xfefd", 0, nil, nil},
			{1, "dtls.record.epoch", "0", 0, nil, nil},
			{1, "dtls.record.sequence_number", "0", 0, nil, nil},
			{1, "dtls.record.length", "54", 0, nil, nil},
			{1, "dtls.record.content_type", "22", 0, nil, nil},
			{2, "dtls.record.sequence_number", "0", 0, nil, nil},
			{8, "dtls.record.content_type", "23", 0, nil, nil},
			{8, "dtls.record.epoch", "1", 0, nil, nil},
		},
		[]fr{
			{1, 42, recHex(0x16, 0, 0, hsHex(1, 42, 0, 0, 42, chBody0))},
		})

	// ② dtls_ipv6_v12_basic（12）：IPv6 同序，帧内起点 62。
	add("dtls_ipv6_v12_basic", "IPv6/UDP 4433 DTLS 1.2 握手+应用+关闭基线",
		chain6(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 12,
		[]fld{
			{1, "ipv6.nxt", "17", 0, nil, nil},
			{1, "dtls.record.version", "0xfefd", 0, nil, nil},
		},
		[]fr{
			{1, 62, recHex(0x16, 0, 0, hsHex(1, 42, 0, 0, 42, chBody0))},
		})

	// ③ dtls_v10_legacy_record（12）：会话缺省 1.0 → feff。
	add("dtls_v10_legacy_record", "DTLS 1.0 legacy record version feff",
		chain(map[string]interface{}{"sessions": []interface{}{dSessAt("", 0, "1.0",
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 12,
		[]fld{
			{1, "dtls.record.version", "0xfeff", 0, nil, nil},
		},
		nil)

	// ④ dtls_v12_cookie_exchange（16）：CH→HVR(cookie)→CH'(cookie)→SH→Cert→CKE→CCS×2→app×4。
	add("dtls_v12_cookie_exchange", "DTLS 1.2 完整 cookie 交换 + 握手",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 3, map[string]interface{}{"cookie": "AABBCC"}),
			hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("AABBCC")}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 16,
		[]fld{
			{1, "dtls.handshake.type", "1", 0, nil, nil},
			{2, "dtls.handshake.type", "3", 0, nil, nil},
			{2, "dtls.handshake.cookie_length", "3", 0, nil, nil},
			{3, "dtls.handshake.type", "1", 0, nil, nil},
		},
		nil)

	// ⑤ dtls_handshake_fragmentation（3）：CKE 分片（type 16 不触发 malformed）。
	// p1 off0/fraglen8, p2 off8/cont, p3 off16/fin。
	add("dtls_handshake_fragmentation", "一个 handshake 消息跨 3 records 分片",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 16, map[string]interface{}{"body": "0102030405060708", "length": 20, "fragment_length": 8}),
			hsE(true, 16, map[string]interface{}{"fragment_offset": 8, "body": "1112131415161718", "length": 20, "fragment_length": 8}),
			hsE(true, 16, map[string]interface{}{"fragment_offset": 16, "body": "21222324", "length": 20, "fragment_length": 4}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1),
		)}}), 10,
		[]fld{
			{1, "dtls.handshake.fragment_offset", "0", 0, nil, nil},
			{1, "dtls.handshake.fragment_length", "8", 0, nil, nil},
			{1, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{2, "dtls.handshake.fragment_offset", "8", 0, nil, nil},
			{3, "dtls.handshake.fragment_offset", "16", 0, nil, nil},
			{4, "dtls.record.sequence_number", "0", 0, nil, nil},
		},
		nil)

	// ⑥ dtls_handshake_reassembly（10）：乱序续片共用 message_seq=0。
	add("dtls_handshake_reassembly", "乱序分片按 message_seq/offset 重组（续片共用 msg_seq）",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 16, map[string]interface{}{"length": 20, "fragment_offset": 8, "body": "1112131415161718", "message_seq": 0}),
			hsE(true, 16, map[string]interface{}{"length": 20, "fragment_offset": 0, "body": "0102030405060708", "message_seq": 0}),
			hsE(true, 16, map[string]interface{}{"length": 20, "fragment_offset": 16, "body": "21222324", "message_seq": 0}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 10,
		[]fld{
			{1, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{2, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{3, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{2, "dtls.handshake.fragment_offset", "0", 0, nil, nil},
			{1, "dtls.handshake.fragment_offset", "8", 0, nil, nil},
			{3, "dtls.handshake.fragment_offset", "16", 0, nil, nil},
			{4, "dtls.record.content_type", "20", 0, nil, nil},
			{6, "dtls.record.epoch", "1", 0, nil, nil},
		},
		nil)

	// ⑦ dtls_epoch_sequence_transition（14）：epoch 切换后 seq 回 0（双向独立）。
	add("dtls_epoch_sequence_transition", "epoch 0→1 切换、每方向 48-bit sequence 独立递增",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1),
			appE(true, 16, 1), appE(false, 16, 1),
			appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 14,
		[]fld{
			{1, "dtls.record.epoch", "0", 0, nil, nil},
			{1, "dtls.record.sequence_number", "0", 0, nil, nil},
			{2, "dtls.record.sequence_number", "0", 0, nil, nil},
			{7, "dtls.record.epoch", "1", 0, nil, nil},
			{7, "dtls.record.sequence_number", "0", 0, nil, nil},
			{8, "dtls.record.sequence_number", "0", 0, nil, nil},
			{9, "dtls.record.sequence_number", "1", 0, nil, nil},
			{12, "dtls.record.sequence_number", "2", 0, nil, nil},
		},
		nil)

	// ⑧ dtls_ccs_alert_application（16）：明文 CCS/alert + 加密 appdata/alert。
	add("dtls_ccs_alert_application", "CCS→alert→加密 epoch appdata/关闭（外层类型混排）",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			ccs(true),
			ev("alert", true, map[string]interface{}{"alert_level": 2, "alert_desc": 10}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1), appE(true, 8, 1), appE(false, 8, 1),
			appE(true, 32, 1), appE(false, 32, 1), appE(true, 16, 1), appE(false, 16, 1),
			alertEnc(true, 1), alertEnc(false, 1),
			appE(true, 8, 1), alertEnc(false, 1),
		)}}), 16,
		[]fld{
			{1, "dtls.record.content_type", "20", 0, nil, nil},
			{2, "dtls.record.content_type", "21", 0, nil, nil},
			{2, "dtls.alert_message.level", "2", 0, nil, nil},
			{2, "dtls.alert_message.desc", "10", 0, nil, nil},
			{5, "dtls.record.content_type", "23", 0, nil, nil},
			{5, "dtls.record.epoch", "1", 0, nil, nil},
			{13, "dtls.record.content_type", "21", 0, nil, nil},
			{13, "dtls.record.epoch", "1", 0, nil, nil},
			{13, "dtls.record.length", "2", 0, nil, nil},
		},
		nil)

	// ⑨ dtls_retransmission_timeout（18）：声明 message_seq 重传复用；多方向混合。
	add("dtls_retransmission_timeout", "flight 重传（同 msg_seq / 新 record seq）+ 超时关闭",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			// CH(0) → retx
			hsE(true, 1, map[string]interface{}{"body": chBody0, "message_seq": 0}),
			hsE(true, 1, map[string]interface{}{"body": chBody0, "message_seq": 0}),
			// HVR(0) down → retx
			hsE(false, 3, map[string]interface{}{"cookie": "DD", "message_seq": 0}),
			hsE(false, 3, map[string]interface{}{"cookie": "DD", "message_seq": 0}),
			// CH'(1) → retx
			hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("DD"), "message_seq": 1}),
			hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("DD"), "message_seq": 1}),
			// SH(1) down
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			// Cert(2) down
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			// CKE(2)
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			// retx CKE(2)
			hsE(true, 16, map[string]interface{}{"body": ckeBody, "message_seq": 2}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(true, 16, 1),
			alertEnc(true, 1),
			alertEnc(false, 1),
			alertEnc(true, 1),
			alertEnc(false, 1),
		)}}), 18,
		[]fld{
			{1, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{2, "dtls.handshake.message_seq", "0", 0, nil, nil},
			{3, "dtls.handshake.cookie_length", "1", 0, nil, nil},
			{5, "dtls.record.sequence_number", "2", 0, nil, nil},
			{6, "dtls.record.sequence_number", "3", 0, nil, nil},
			{9, "dtls.handshake.message_seq", "2", 0, nil, nil},
			{10, "dtls.handshake.message_seq", "2", 0, nil, nil},
			{15, "dtls.record.content_type", "21", 0, nil, nil},
		},
		nil)

	// ⑩ dtls_multi_session_isolation（24）：双会话各 12（cookie/epoch/seq 全隔离）。
	add("dtls_multi_session_isolation", "双独立 session 各自 cookie/epoch/seq/关闭（不串用）",
		chain(map[string]interface{}{"sessions": []interface{}{
			dSessAt("", 5001, "",
				hsE(true, 1, map[string]interface{}{"body": chBody0}),
				hsE(false, 3, map[string]interface{}{"cookie": "AABBCC"}),
				hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("AABBCC")}),
				hsE(false, 2, map[string]interface{}{"body": shBody}),
				hsE(false, 11, map[string]interface{}{"body": certBody}),
				hsE(true, 16, map[string]interface{}{"body": ckeBody}),
				ccs(true), ccs(false),
				appE(true, 16, 1), appE(false, 16, 1),
				alertEnc(true, 1), alertEnc(false, 1),
			),
			dSessAt(dtlsCli2, 5002, "",
				hsE(true, 1, map[string]interface{}{"body": chBody0}),
				hsE(false, 3, map[string]interface{}{"cookie": "DD"}),
				hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("DD")}),
				hsE(false, 2, map[string]interface{}{"body": shBody}),
				hsE(false, 11, map[string]interface{}{"body": certBody}),
				hsE(true, 16, map[string]interface{}{"body": ckeBody}),
				ccs(true), ccs(false),
				appE(true, 16, 1), appE(false, 16, 1),
				alertEnc(true, 1), alertEnc(false, 1),
			),
		}}), 24,
		[]fld{
			{1, "udp.srcport", "5001", 0, nil, nil},
			{2, "dtls.handshake.cookie_length", "3", 0, nil, nil},
			{13, "udp.srcport", "5002", 0, nil, nil},
			{13, "dtls.record.epoch", "0", 0, nil, nil},
			{13, "dtls.record.sequence_number", "0", 0, nil, nil},
			{14, "dtls.handshake.cookie_length", "1", 0, nil, nil},
			{1, "udp.srcport", "5001", 0, []string{"5001", "5002"}, []string{"4433"}},
		},
		nil)

	// ⑪ dtls_multi_flow（12）：多四元组（不同 src_ip + src_port）双向流。
	add("dtls_multi_flow", "多四元组多流（src_ip/src_port 独立，状态不跨流拼接）",
		chain(map[string]interface{}{"sessions": []interface{}{
			dSessAt(dtlsCli2, 5001, "",
				hsE(true, 1, map[string]interface{}{"body": chBody0}),
				hsE(false, 2, map[string]interface{}{"body": shBody}),
				ccs(true), ccs(false),
				appE(true, 16, 1), alertEnc(false, 1),
			),
			dSessAt("", 5002, "",
				hsE(true, 1, map[string]interface{}{"body": chBody0}),
				hsE(false, 2, map[string]interface{}{"body": shBody}),
				ccs(true), ccs(false),
				appE(true, 16, 1), alertEnc(false, 1),
			),
		}}), 12,
		[]fld{
			{1, "ip.src", dtlsCli2, 0, nil, nil},
			{7, "ip.src", dtlsCli, 0, nil, nil},
			{8, "ip.src", dtlsSrv, 0, nil, nil},
			{7, "udp.srcport", "5002", 0, nil, nil},
			{1, "udp.srcport", "5001", 0, nil, nil},
		},
		nil)

	// ⑫ dtls_record_boundary_lengths（6）：1/62(CKE 50B 体)/1/2/1400/1。
	add("dtls_record_boundary_lengths", "record 长度边界（1/62/1/2/1400/1）",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			app(true, 1), // 1B opaque（tshark 对 0 长记录标 malformed——零长由 TestDTLSChain_ZeroLengthRecord 链级单测钉）
			hsE(true, 16, map[string]interface{}{"body": ckeBody}), // RSA CKE 50B
			ccs(true),
			ev("alert", true, nil),
			app(true, 1400),
			app(true, 1),
		)}}), 6,
		[]fld{
			{1, "dtls.record.length", "1", 0, nil, nil},
			{2, "dtls.record.length", "62", 0, nil, nil},
			{2, "dtls.handshake.length", "50", 0, nil, nil},
			{3, "dtls.record.length", "1", 0, nil, nil},
			{4, "dtls.record.length", "2", 0, nil, nil},
			{5, "dtls.record.length", "1400", 0, nil, nil},
			{6, "dtls.record.length", "1", 0, nil, nil},
		},
		[]fr{
			{1, 42, recHex(0x17, 0, 0, "A5")},
			{2, 42, recHex(0x16, 0, 1, hsHex(16, 50, 0, 0, 50, ckeBody))},
		})

	// ⑬ dtls_pcap_nic_consistency（16）：稳定前缀双钉 + 方向/端口。
	add("dtls_pcap_nic_consistency", "PCAP/NIC 同 fixture：方向/4433/record 头一致",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0}),
			hsE(false, 3, map[string]interface{}{"cookie": "AABBCC"}),
			hsE(true, 1, map[string]interface{}{"body": chBodyWithCookie("AABBCC")}),
			hsE(false, 2, map[string]interface{}{"body": shBody}),
			hsE(false, 11, map[string]interface{}{"body": certBody}),
			hsE(true, 16, map[string]interface{}{"body": ckeBody}),
			ccs(true), ccs(false),
			appE(true, 16, 1), appE(false, 16, 1),
			alertEnc(true, 1), alertEnc(false, 1),
			appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
		)}}), 16,
		[]fld{
			{1, "udp.dstport", "4433", 0, nil, nil},
			{2, "udp.srcport", "4433", 0, nil, nil},
			{1, "dtls.record.content_type", "22", 0, nil, nil},
			{2, "dtls.record.content_type", "22", 0, nil, nil},
			{2, "dtls.record.epoch", "0", 0, nil, nil},
			{2, "dtls.record.sequence_number", "0", 0, nil, nil},
		},
		[]fr{
			{1, 42, recHex(0x16, 0, 0, hsHex(1, 42, 0, 0, 42, chBody0))},
			{2, 42, recHex(0x16, 0, 0, hsHex(3, 6, 0, 0, 6, "FEFD03AABBCC"))},
		})

	// ⑭ dtls_encrypted_opaque_boundary（10）：加密后只断言外层。
	add("dtls_encrypted_opaque_boundary", "加密 epoch 外层可见/明文不可声称（opaque 边界）",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			ccs(true), ccs(false),
			appE(true, 8, 1), appE(false, 8, 1),
			alertEnc(true, 1), alertEnc(false, 1),
			appE(true, 16, 1), appE(false, 16, 1),
			alertEnc(true, 1), appE(false, 32, 1),
		)}}), 10,
		[]fld{
			{3, "dtls.record.content_type", "23", 0, nil, nil},
			{3, "dtls.record.epoch", "1", 0, nil, nil},
			{3, "dtls.record.length", "8", 0, nil, nil},
			{5, "dtls.record.content_type", "21", 0, nil, nil},
			{5, "dtls.record.length", "2", 0, nil, nil},
		},
		[]fr{
			{3, 42, recHex(0x17, 1, 0, strings.Repeat("A5", 8))},
		})

	// ============================================================
	//  负例（6 例）
	// ============================================================
	var negatives []negCase

	addNeg := func(id, summary string, layersArr []interface{}, anchor string) {
		negatives = append(negatives, negCase{id: id, summary: summary, layers: layersArr, anchor: anchor})
	}

	// ⑮ record_truncated
	addNeg("dtls_neg_record_truncated", "record Length 与实际 datagram 字节不符（wire_fault 注入）",
		chain(map[string]interface{}{"wire_fault": "record_length"}),
		"record")

	// ⑯ version_epoch
	addNeg("dtls_neg_version_epoch", "非法版本/epoch（wire_fault 注入）",
		chain(map[string]interface{}{"wire_fault": "version_epoch"}),
		"version")

	// ⑰ sequence_overflow
	addNeg("dtls_neg_sequence_overflow", "seq 超 48-bit 范围（wire_fault 注入）",
		chain(map[string]interface{}{"wire_fault": "sequence_overflow"}),
		"sequence")

	// ⑱ fragment_bounds
	addNeg("dtls_neg_fragment_bounds", "分片超出 handshake length（fragment_offset+fraglen > length）",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": "0102", "length": 2, "fragment_offset": 2, "fragment_length": 4}),
		)}}),
		"fragment")

	// ⑲ cookie_state
	addNeg("dtls_neg_cookie_state", "cookie 只能出现在 type 3 HVR 上",
		chain(map[string]interface{}{"sessions": []interface{}{dSess(
			hsE(true, 1, map[string]interface{}{"body": chBody0, "cookie": "AABBCC"}),
		)}}),
		"cookie")

	// ⑳ carrier_udp
	addNeg("dtls_neg_udp_carrier", "DTLS 需要 UDP 载体，tcp 载体拒绝",
		[]interface{}{
			ipLayer(dtlsCli, dtlsSrv),
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40063, "dst_port": 4433}},
			dtlsLayer(map[string]interface{}{"sessions": []interface{}{dSess(ccs(true))}}),
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
		out = append(out, outCase{ID: pc.id, Proto: "dtls", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect})
	}
	for _, nc := range negatives {
		out = append(out, outCase{ID: nc.id, Proto: "dtls", Summary: nc.summary,
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
	path := "../../../test/protocol_pcap/cases/dtls.json"
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases (%d pos + %d neg)", len(out), len(positives), len(negatives))
}
