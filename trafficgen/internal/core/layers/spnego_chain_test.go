package layers_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/spnego" // init 注册 spnego 终结层生成器+校验器
)

// D-SPNEGO-1 P4 链级红例（ntlm_chain_test / kerberos_chain_test 同构）：
// ①空配置基线（tcp 缺省档一条最小 init）/②DER 线形钉字节（InitialContext
// Token 0x60 + SPNEGO OID + NegTokenInit [0]{30{…}}；mechTypes/reqFlags/
// mechToken 三槽的 [n] 显式包装 = 裁定2 §10.7 M-shape-1 锚）/③negTokenResp/
// negTokenTarg 三形 choice（0xA1 枝 + ENUMERATED 值域）/④negHints dissector
// 形与 RFC 形 MIC 的 [3] 槽互斥/⑤HTTP profile 成帧（401↔Authorization
// base64；DER 字节不变）/⑥结构守卫负例（profile/negotiation/oid/selection/
// req_flags/neg_result/layout/端点覆盖/顺序）/⑦6 wire_fault 注入锚词/
// ⑧载体形状（缺 tcp/夹 udp/混合地址族/profile↔http 层有无）/⑨严格解码/
// ⑩多会话隔离/⑪IPv6/⑫presence 与顶层游离键判死（1.11–1.13）/⑬用例文件
// 收官自查。
// 契约 fixture：客户端 192.0.2.61 / 服务端 198.51.100.61 / 裸 TCP 445 /
// HTTP 80（契约 §11.1）。

const (
	sCli   = "192.0.2.61"
	sSrv   = "198.51.100.61"
	sCli6  = "2001:db8::61"
	sSrv6  = "2001:db8:ffff::61"
	sSport = 45061
	sPortH = 45062
)

// sOID{Kerberos,MsKrb5,NTLM,SPNEGO} = 契约 §4 四值 DER（含 tag/len，逐字节钉）。
const (
	sOIDKrb   = "06092a864886f712010202"
	sOIDMsKrb = "06092a864882f712010202"
	sOIDNTLM  = "060a2b06010401823702020a"
	sOIDSpn   = "06062b0601050502"
)

func sJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func sIP(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 445}},
		map[string]interface{}{"spnego": cfg},
	}
}

func sIP6(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": sCli6, "dst": sSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 445}},
		map[string]interface{}{"spnego": cfg},
	}
}

func sHTTP(cfg map[string]interface{}, withHTTPLayer bool) []interface{} {
	out := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": sPortH, "dst_port": 80}},
	}
	if withHTTPLayer {
		out = append(out, map[string]interface{}{"http": map[string]interface{}{}})
	}
	return append(out, map[string]interface{}{"spnego": cfg})
}

func sPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("spnego", sJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	// 四元组回填：从 layers[0].ip 与 layers[1].tcp 的显式声明派生（ntlm/
	// kerberos casegen 同款——src/dst/src_port/dst_port 以链声明为准）。
	spec := core.FlowSpec{SrcIP: sCli, DstIP: sSrv, SrcPort: sSport, DstPort: 445}
	for _, item := range layersArr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if ipc, ok := m["ip"].(map[string]interface{}); ok {
			if v, ok := ipc["src"].(string); ok && v != "" {
				spec.SrcIP = v
			}
			if v, ok := ipc["dst"].(string); ok && v != "" {
				spec.DstIP = v
			}
		}
		if tcpc, ok := m["tcp"].(map[string]interface{}); ok {
			switch v := tcpc["src_port"].(type) {
			case float64:
				spec.SrcPort = uint16(v)
			case int:
				spec.SrcPort = uint16(v)
			}
			switch v := tcpc["dst_port"].(type) {
			case float64:
				spec.DstPort = uint16(v)
			case int:
				spec.DstPort = uint16(v)
			}
		}
	}
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

func sDrive(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := sPlan(t, layersArr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func sDriveErr(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := sPlan(t, layersArr)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	return err
}

// sSess 构造单会话配置（events 为 kind 列表）。
func sSess(events ...string) map[string]interface{} {
	evs := make([]interface{}, len(events))
	for i, k := range events {
		evs[i] = map[string]interface{}{"kind": k}
	}
	return map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": evs}}}
}

// sData 返回 payload 非空的数据包（去掉握手/挥手空包）。
func sData(pkts []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, p := range pkts {
		if len(p.Payload) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// ---- DER 解析辅助（断言用，非生成侧第二套实现）----

// sTLV 读一处 TLV（返回 tag、内容、总长）。
func sTLV(t *testing.T, b []byte, at int) (byte, []byte, int) {
	t.Helper()
	if at+2 > len(b) {
		t.Fatalf("TLV at %d truncated (len %d)", at, len(b))
	}
	tag := b[at]
	l := int(b[at+1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7F
		if n < 1 || n > 2 {
			t.Fatalf("unsupported DER length form %#x at %d", b[at+1], at)
		}
		if at+2+n > len(b) {
			t.Fatalf("DER long length truncated at %d", at)
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[at+2+i])
		}
		hdr = 2 + n
	}
	if at+hdr+l > len(b) {
		t.Fatalf("TLV tag %#x at %d: content %d exceeds buffer %d", tag, at, l, len(b))
	}
	return tag, b[at+hdr : at+hdr+l], hdr + l
}

// sCheckTLV 断言 tag 与内容长度（父长度覆盖子项面）。
func sCheckTLV(t *testing.T, b []byte, at int, wantTag byte, what string) []byte {
	t.Helper()
	tag, content, _ := sTLV(t, b, at)
	if tag != wantTag {
		t.Fatalf("%s: tag %#x, want %#x", what, tag, wantTag)
	}
	return content
}

// ---- ① 空配置基线（tcp 缺省档）----

func TestSPNEGOChain_TCPBaselineDefault(t *testing.T) {
	pkts := sDrive(t, sIP(map[string]interface{}{}))
	if len(pkts) != 8 {
		t.Fatalf("want 8 packets (3 hs + 1 data + 4 fin), got %d", len(pkts))
	}
	if pkts[3].Direction != "up" {
		t.Fatalf("baseline direction %q", pkts[3].Direction)
	}
	if pkts[3].L4.DstPort != 445 || pkts[3].L4.SrcPort != sSport {
		t.Fatalf("ports %d->%d", pkts[3].L4.SrcPort, pkts[3].L4.DstPort)
	}
	der := pkts[3].Payload
	// 外层 InitialContextToken [APPLICATION 0] = 0x60；内层 = SPNEGO OID +
	// [0] EXPLICIT negotiationToken（0xA0）。
	wantPrefix := "60" + "3f" + sOIDSpn + "a0"
	if got := hex.EncodeToString(der[:len(wantPrefix)/2]); got != wantPrefix {
		t.Fatalf("baseline DER prefix %s, want %s (full %s)", got, wantPrefix, hex.EncodeToString(der))
	}
	inner := sCheckTLV(t, der, 0, 0x60, "InitialContextToken")
	oid := sCheckTLV(t, inner, 0, 0x06, "thisMech OID")
	if got := hex.EncodeToString(oid); got != sOIDSpn[4:] {
		t.Fatalf("thisMech OID %s, want %s", got, sOIDSpn[4:])
	}
	neg := sCheckTLV(t, inner, len(oid)+2, 0xA0, "innerContextToken [0]")
	seq := sCheckTLV(t, neg, 0, 0x30, "NegTokenInit SEQUENCE")
	mt := sCheckTLV(t, seq, 0, 0xA0, "mechTypes [0]")
	list := sCheckTLV(t, mt, 0, 0x30, "MechTypeList SEQUENCE OF")
	first := sCheckTLV(t, list, 0, 0x06, "mechType[0] OID")
	if got := hex.EncodeToString(first); got != sOIDKrb[4:] {
		t.Fatalf("default mech type %s, want Kerberos V5 %s", got, sOIDKrb[4:])
	}
	// mechToken [2] 缺省 fixture（32B opaque）。
	mtOff := 2 + len(mt) // mechTypes [0] 的 TLV 全长为 2+len(mt)
	tok := sCheckTLV(t, seq, mtOff, 0xA2, "mechToken [2]")
	os := sCheckTLV(t, tok, 0, 0x04, "mechToken OCTET STRING")
	if len(os) != 32 {
		t.Fatalf("default mechToken %d bytes, want 32", len(os))
	}
}

// ---- ② DER 线形钉字节（§10.7 M-shape-1 锚 + 三 OID 变体 + reqFlags）----

func TestSPNEGOChain_DERWireShape(t *testing.T) {
	// reqFlags=c0 + 单 OID + 显式零长 mechToken：与 §10.7 M-shape-1 单 OID
	// 实测锚（`602906062b0601050502a01f301da00d300b06092a864886f712010202
	// a104030200c0a2060404deadbeef`）同形（仅 token 长度/值不同）。
	cfg := map[string]interface{}{
		"mech_types": []interface{}{"1.2.840.113554.1.2.2"},
		"req_flags":  0xC0,
		"mech_token": map[string]interface{}{"opaque": true, "len": 4},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}
	pkts := sDrive(t, sIP(cfg))
	data := sData(pkts)
	if len(data) != 1 {
		t.Fatalf("want 1 data segment, got %d", len(data))
	}
	der := data[0].Payload
	// 长度前缀：单 OID(11B) + token TLV(6B) + reqFlags TLV(4B) = 场景内钉死
	// 的整串（含父长度 0x29/0x1f/0x0d/0x0b 逐字节——父长度覆盖子 TLV）。
	want := "6029" + "06062b0601050502" + "a01f" + "301d" +
		"a00d" + "300b" + sOIDKrb +
		"a104" + "030200c0" +
		"a206" + "0404" + "a5a5a5a5"
	if got := hex.EncodeToString(der); got != want {
		t.Fatalf("DER wire shape:\n got %s\nwant %s", got, want)
	}
	// [3] 槽缺席（无 MIC/negHints）：seq 内容长度 = 11+2+A1 段。
	inner := sCheckTLV(t, der, 0, 0x60, "InitialContextToken")
	neg := sCheckTLV(t, inner, len(sOIDSpn)/2, 0xA0, "innerContextToken [0]")
	seq := sCheckTLV(t, neg, 0, 0x30, "NegTokenInit")
	_ = seq
}

func TestSPNEGOChain_MechOIDVariants(t *testing.T) {
	// 三 OID 全枚举（列表序=线上序，禁排序）：msKrb5 的 arc 48018 展开
	// `82 F7 12`、NTLM 的 `82 37` 双字节 arc——逐字节钉（契约 §4）。
	pkts := sDrive(t, sIP(map[string]interface{}{
		"mech_types": []interface{}{
			"1.2.840.113554.1.2.2",
			"1.2.840.48018.1.2.2",
			"1.3.6.1.4.1.311.2.2.10",
		},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}))
	der := sData(pkts)[0].Payload
	h := hex.EncodeToString(der)
	// 乱序存在性 + 顺序：Kerberos 先于 msKrb5 先于 NTLM。
	iKrb := strings.Index(h, sOIDKrb)
	iMs := strings.Index(h, sOIDMsKrb)
	iNt := strings.Index(h, sOIDNTLM)
	if iKrb < 0 || iMs < 0 || iNt < 0 {
		t.Fatalf("三 OID 未全部在线上序内出现: %s", h)
	}
	if !(iKrb < iMs && iMs < iNt) {
		t.Fatalf("OID 列表序被改写: krb@%d ms@%d ntlm@%d", iKrb, iMs, iNt)
	}
	// 别名等价（契约 §2 oid_alias）：别名不改变线上 OID 字节。
	pktsAlias := sDrive(t, sIP(map[string]interface{}{
		"mech_types": []interface{}{"Kerberos", "mskrb5", "NTLM"},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}))
	if got, want := hex.EncodeToString(sData(pktsAlias)[0].Payload), hex.EncodeToString(der); got != want {
		t.Fatalf("别名改写了线上 OID 字节:\n got %s\nwant %s", got, want)
	}
}

// ---- ③ 三形 choice（resp/targ 0xA1 枝 + ENUMERATED 值域）----

func TestSPNEGOChain_NegTokenRespAndTarg(t *testing.T) {
	// init_resp：init → resp（negState=accept-incomplete(1)）+ supportedMech
	// =列表次项（降级守卫合规）→ mic 续（§5 事务 t1/t2/t3）。
	pkts := sDrive(t, sIP(map[string]interface{}{
		"negotiation":    "init_resp",
		"mech_types":     []interface{}{"1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2"},
		"supported_mech": "1.2.840.48018.1.2.2",
		"neg_result":     1,
		"mech_list_mic":  map[string]interface{}{"layout": "rfc4178", "opaque": true, "len": 16},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "resp"},
				map[string]interface{}{"kind": "mic"},
			},
		}},
	}))
	data := sData(pkts)
	if len(data) != 3 {
		t.Fatalf("want 3 data segments, got %d", len(data))
	}
	if data[0].Direction != "up" || data[1].Direction != "down" || data[2].Direction != "up" {
		t.Fatalf("directions %s/%s/%s, want up/down/up", data[0].Direction, data[1].Direction, data[2].Direction)
	}
	// resp：choice [1]（0xA1）> SEQUENCE > negState [0] ENUMERATED(1) +
	// supportedMech [1] OID(msKrb5) + responseToken [2] OCTET STRING。
	resp := data[1].Payload
	if resp[0] != 0xA1 {
		t.Fatalf("resp choice %#x, want 0xA1 (negTokenResp)", resp[0])
	}
	body := sCheckTLV(t, resp, 0, 0xA1, "negTokenResp [1]")
	seq := sCheckTLV(t, body, 0, 0x30, "NegTokenResp SEQUENCE")
	st := sCheckTLV(t, seq, 0, 0xA0, "negState [0]")
	enum := sCheckTLV(t, st, 0, 0x0A, "negState ENUMERATED")
	if len(enum) != 1 || enum[0] != 1 {
		t.Fatalf("negState % x, want 01 (accept-incomplete)", enum)
	}
	sm := sCheckTLV(t, seq, 2+len(st), 0xA1, "supportedMech [1]")
	smOID := sCheckTLV(t, sm, 0, 0x06, "supportedMech OID")
	if got := hex.EncodeToString(smOID); got != sOIDMsKrb[4:] {
		t.Fatalf("supportedMech %s, want msKrb5 %s", got, sOIDMsKrb[4:])
	}
	// mic 续：negTokenInit（0x60 外层）+ [3] 槽 = RFC 形 MIC（A3{04 …}）。
	micDer := data[2].Payload
	if micDer[0] != 0x60 {
		t.Fatalf("mic message outer %#x, want 0x60 (InitialContextToken)", micDer[0])
	}
	if !strings.Contains(hex.EncodeToString(micDer), "a312"+"0410") {
		t.Fatalf("RFC 形 mechListMIC [3] 槽缺失（want a3 12 04 10）: %s", hex.EncodeToString(micDer))
	}
	// 旧式 targ：profile 显式声明 init_targ，negResult 三值档（reject=2）。
	pktsT := sDrive(t, sIP(map[string]interface{}{
		"negotiation": "init_targ",
		"neg_result":  2,
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "targ"},
			},
		}},
	}))
	targ := sData(pktsT)[1].Payload
	bodyT := sCheckTLV(t, targ, 0, 0xA1, "negTokenTarg [1]")
	seqT := sCheckTLV(t, bodyT, 0, 0x30, "NegTokenTarg SEQUENCE")
	stT := sCheckTLV(t, seqT, 0, 0xA0, "negResult [0]")
	enumT := sCheckTLV(t, stT, 0, 0x0A, "negResult ENUMERATED")
	if len(enumT) != 1 || enumT[0] != 2 {
		t.Fatalf("negResult % x, want 02 (reject)", enumT)
	}
}

// ---- ④ negHints dissector 形（[3] 槽）与 RFC 形 MIC 互斥 ----

func TestSPNEGOChain_NegHintsSlot(t *testing.T) {
	pkts := sDrive(t, sIP(map[string]interface{}{
		"neg_hints": map[string]interface{}{
			"carry":        "dissector",
			"hint_name":    "hint.example",
			"hint_address": "C0000201",
		},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}))
	der := sData(pkts)[0].Payload
	h := hex.EncodeToString(der)
	// M-shape-3 线形：A3 { 30 { A0{1B hintName}, A1{04 hintAddress} } }。
	wantHint := "a3" + "1a" + "30" + "18" +
		"a0" + "0e" + "1b" + "0c" + hex.EncodeToString([]byte("hint.example")) +
		"a1" + "06" + "04" + "04" + "c0000201"
	if !strings.Contains(h, wantHint) {
		t.Fatalf("negHints [3] 槽线形缺失:\n got %s\nwant 内含 %s", h, wantHint)
	}
	// 同消息同时声明 dissector 形 negHints 与 RFC 形 MIC → planner 拒
	// （裁定2 ②：`[3]` 槽二义）。
	err := sDriveErr(t, sIP(map[string]interface{}{
		"neg_hints": map[string]interface{}{"carry": "dissector", "hint_name": "hint.example"},
		"mech_list_mic": map[string]interface{}{
			"layout": "rfc4178", "opaque": true,
		},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}))
	if !strings.Contains(err.Error(), "(mic)") {
		t.Fatalf("负例锚词缺 (mic): %v", err)
	}
	// carry=none（缺省）不占 [3] 槽。
	pktsNone := sDrive(t, sIP(map[string]interface{}{
		"neg_hints": map[string]interface{}{"carry": "none"},
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}},
	}))
	if strings.Contains(hex.EncodeToString(sData(pktsNone)[0].Payload), "a31b") {
		t.Fatal("carry=none 不得占用 [3] 槽")
	}
}

// ---- ⑤ HTTP profile 成帧（401 ↔ Authorization；DER 不变）----

func TestSPNEGOChain_HTTPProfile(t *testing.T) {
	cfg := map[string]interface{}{
		"profile": "http",
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "challenge"},
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "resp"},
				map[string]interface{}{"kind": "http_success"},
			},
		}},
	}
	// 显式 http 底座（可选底座透传）：DER/header 字节与裸 tcp 链（同事件序、
	// 无 http 层）逐字节一致——http 层在变换器位置原样转发内层帧。
	pktsA := sDrive(t, sHTTP(cfg, true))
	if len(pktsA) != 11 {
		t.Fatalf("packet count %d, want 11", len(pktsA))
	}
	// 上行包（init）端口：DstPort=80（http profile 缺省契约端口，taint 面见
	// 门1 §13——fixture 显式写 80 时不生效）。
	var upPkt *core.PacketConfig
	for i := range pktsA {
		if len(pktsA[i].Payload) > 0 && pktsA[i].Direction == "up" {
			upPkt = &pktsA[i]
			break
		}
	}
	if upPkt == nil {
		t.Fatal("no up data packet")
	}
	if upPkt.L4.DstPort != 80 || upPkt.L4.SrcPort != sPortH {
		t.Fatalf("http profile up ports %d->%d, want %d->80", upPkt.L4.SrcPort, upPkt.L4.DstPort, sPortH)
	}
	dataA := sData(pktsA)
	// challenge：401 + 裸 WWW-Authenticate: Negotiate（探测轮）。
	if !strings.HasPrefix(string(dataA[0].Payload), "HTTP/1.1 401 Unauthorized\r\n") ||
		!strings.Contains(string(dataA[0].Payload), "WWW-Authenticate: Negotiate\r\n") {
		t.Fatalf("challenge response: %q", dataA[0].Payload[:40])
	}
	// init（up）：GET + Authorization: Negotiate <b64>，base64 解码后是完整
	// InitialContextToken（DER 字节不变——HTTP base64 只是传输包装）。
	if !strings.HasPrefix(string(dataA[1].Payload), "GET / HTTP/1.1\r\n") ||
		!strings.Contains(string(dataA[1].Payload), "Authorization: Negotiate ") {
		t.Fatalf("init request: %q", dataA[1].Payload[:40])
	}
	raw := sB64Header(t, dataA[1].Payload, "Authorization: Negotiate ")
	rawInner := sCheckTLV(t, raw, 0, 0x60, "base64 InitialContextToken")
	rawOID := sCheckTLV(t, rawInner, 0, 0x06, "base64 thisMech")
	if got := hex.EncodeToString(rawOID); got != sOIDSpn[4:] {
		t.Fatalf("base64 token thisMech %s, want %s", got, sOIDSpn[4:])
	}
	// resp（down）：401 + WWW-Authenticate: Negotiate <b64>（abnf: 挑战值可带 token）。
	if !strings.HasPrefix(string(dataA[2].Payload), "HTTP/1.1 401 Unauthorized\r\n") ||
		!strings.Contains(string(dataA[2].Payload), "WWW-Authenticate: Negotiate ") {
		t.Fatalf("resp response: %q", dataA[2].Payload[:40])
	}
	respRaw := sB64Header(t, dataA[2].Payload, "WWW-Authenticate: Negotiate ")
	if respRaw[0] != 0xA1 {
		t.Fatalf("resp base64 token choice %#x, want 0xA1", respRaw[0])
	}
	// http_success：200 OK（RFC 4559 §4.2 结果显式配置面）。
	if !strings.HasPrefix(string(dataA[3].Payload), "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("final response: %q", dataA[3].Payload[:20])
	}
}

// sB64Header 取 HTTP header 的 base64 值并解码（传输包装面断言）。
func sB64Header(t *testing.T, msg []byte, prefix string) []byte {
	t.Helper()
	idx := strings.Index(string(msg), prefix)
	if idx < 0 {
		t.Fatalf("header %q missing in %q", prefix, msg)
	}
	v := string(msg[idx+len(prefix):])
	v = v[:strings.Index(v, "\r\n")]
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("token base64: %v", err)
	}
	return raw
}

// ---- ⑥ 结构守卫负例 ----

func TestSPNEGOChain_StructureGuards(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"mech_types":     []interface{}{"1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2"},
			"supported_mech": "1.2.840.113554.1.2.2",
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{
					map[string]interface{}{"kind": "init"},
					map[string]interface{}{"kind": "resp"},
				},
			}},
		}
	}
	with := func(k string, v interface{}) map[string]interface{} {
		c := base()
		c[k] = v
		return c
	}
	cases := []struct {
		name   string
		cfg    map[string]interface{}
		anchor string
	}{
		{"unknown_profile", with("profile", "udp"), "(profile)"},
		{"unknown_negotiation", with("negotiation", "init_bogus"), "(sequence)"},
		{"unknown_oid", with("mech_types", []interface{}{"1.2.3.4.5.6.7"}), "(oid)"},
		{"empty_oid", with("mech_types", []interface{}{""}), "(oid)"},
		{"supported_not_offered", with("supported_mech", "1.3.6.1.4.1.311.2.2.10"), "(selection)"},
		{"supported_oid_invalid", with("supported_mech", "9.9.9"), "(oid)"},
		{"neg_result_overflow", with("neg_result", 4), "(neg_result)"},
		{"neg_hints_bad_carry", with("neg_hints", map[string]interface{}{"carry": "rfc"}), "(neg_hints)"},
		{"mic_bad_layout", with("mech_list_mic", map[string]interface{}{"layout": "dissector"}), "(layout)"},
		{"mic_negative_len", with("mech_list_mic", map[string]interface{}{"len": -1}), "(length)"},
		{"token_negative_len", with("mech_token", map[string]interface{}{"len": -3}), "(length)"},
		{"bad_hint_address_hex", with("neg_hints", map[string]interface{}{
			"carry": "dissector", "hint_address": "zz",
		}), "(length)"},
		{"unknown_kind", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "magic"}},
		}}), `kind "magic"`},
		{"tcp_kind_in_http", map[string]interface{}{
			"profile": "http",
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{map[string]interface{}{"kind": "init"}, map[string]interface{}{"kind": "resp"}, map[string]interface{}{"kind": "mic"}},
			}},
		}, "(profile)"},
		{"targ_without_init_targ", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "targ"},
			},
		}}), "(sequence)"},
		{"resp_in_targ_negotiation", map[string]interface{}{
			"negotiation": "init_targ",
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{
					map[string]interface{}{"kind": "init"},
					map[string]interface{}{"kind": "resp"},
				},
			}},
		}, "(sequence)"},
		{"resp_before_init", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "resp"}},
		}}), "(sequence)"},
		{"mic_before_resp", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "mic"},
			},
		}}), "(sequence)"},
		{"targ_result_overflow", map[string]interface{}{
			"negotiation": "init_targ",
			"neg_result":  3,
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{
					map[string]interface{}{"kind": "init"},
					map[string]interface{}{"kind": "targ"},
				},
			}},
		}, "(neg_result)"},
		{"session_supported_not_offered", with("sessions", []interface{}{map[string]interface{}{
			"mech_types":     []interface{}{"1.2.840.113554.1.2.2"},
			"supported_mech": "1.2.840.48018.1.2.2",
			"events": []interface{}{
				map[string]interface{}{"kind": "init"},
				map[string]interface{}{"kind": "resp"},
			},
		}}), "(selection)"},
		{"session_dst_port_conflict", with("sessions", []interface{}{map[string]interface{}{
			"dst_port": 8080,
			"events":   []interface{}{map[string]interface{}{"kind": "init"}},
		}}), "(port)"},
		{"session_src_ip_override", with("sessions", []interface{}{map[string]interface{}{
			"src_ip": "192.0.2.99",
			"events": []interface{}{map[string]interface{}{"kind": "init"}},
		}}), "(carrier)"},
		{"unknown_config_key", with("no_such_key", 1), "unknown field"},
		{"unknown_session_key", with("sessions", []interface{}{map[string]interface{}{
			"whoknows": 1,
			"events":   []interface{}{map[string]interface{}{"kind": "init"}},
		}}), "unknown field"},
		{"unknown_event_key", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "init", "nope": 1}},
		}}), "unknown field"},
		{"unknown_hints_key", with("neg_hints", map[string]interface{}{
			"carry": "dissector", "hint_nam": "typo",
		}), "unknown field"},
		{"unknown_token_key", with("mech_token", map[string]interface{}{"lenn": 4}), "unknown field"},
		{"unknown_mic_key", with("mech_list_mic", map[string]interface{}{"layuot": "rfc4178"}), "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sDriveErr(t, sIP(tc.cfg))
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err, tc.anchor)
			}
		})
	}
}

// ---- ⑦ 6 wire_fault 注入锚词 ----

func TestSPNEGOChain_WireFaults(t *testing.T) {
	for fault, anchor := range map[string]string{
		"der_truncated": "anchor der",
		"der_length":    "anchor length",
		"choice":        "anchor choice",
		"mech_oid":      "anchor oid",
		"mic":           "anchor mic",
		"carrier":       "anchor carrier",
	} {
		err := sDriveErr(t, sIP(map[string]interface{}{"wire_fault": fault}))
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: error %q missing anchor %q", fault, err, anchor)
		}
	}
	if err := sDriveErr(t, sIP(map[string]interface{}{"wire_fault": "no_such_fault"})); err == nil ||
		!strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown fault: %v", err)
	}
}

// ---- ⑧ 载体形状与 profile↔http 底座一致性 ----

func TestSPNEGOChain_CarrierShapes(t *testing.T) {
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_tcp", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"spnego": map[string]interface{}{}},
		}, "(carrier)"},
		{"udp_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": sSport, "dst_port": 445}},
			map[string]interface{}{"spnego": map[string]interface{}{}},
		}, "(transport)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv6}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 445}},
			map[string]interface{}{"spnego": map[string]interface{}{}},
		}, "(family)"},
		{"tcp_profile_with_http_base", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 80}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"spnego": map[string]interface{}{"profile": "tcp"}},
		}, "(profile)"},
		{"tcp_default_with_http_base", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 80}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"spnego": map[string]interface{}{}},
		}, "(profile)"},
		{"http_profile_without_http_base", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 80}},
			map[string]interface{}{"spnego": map[string]interface{}{"profile": "http"}},
		}, "(profile)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sDriveErr(t, tc.layers)
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err, tc.anchor)
			}
		})
	}
}

// ---- ⑨ 多会话隔离（候选列表/选定 OID/协商结果逐会话独立）----

func TestSPNEGOChain_MultiSessionIsolation(t *testing.T) {
	pkts := sDrive(t, sIP(map[string]interface{}{
		"mech_types": []interface{}{"1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2"},
		"sessions": []interface{}{
			map[string]interface{}{
				"id":         "s1",
				"mech_types": []interface{}{"1.2.840.113554.1.2.2"},
				"events": []interface{}{
					map[string]interface{}{"kind": "init"},
					map[string]interface{}{"kind": "resp"},
				},
			},
			map[string]interface{}{
				"id":             "s2",
				"mech_types":     []interface{}{"1.3.6.1.4.1.311.2.2.10"},
				"supported_mech": "1.3.6.1.4.1.311.2.2.10",
				"neg_result":     2,
				"events": []interface{}{
					map[string]interface{}{"kind": "init"},
					map[string]interface{}{"kind": "resp"},
				},
			},
		},
	}))
	data := sData(pkts)
	if len(data) != 4 {
		t.Fatalf("want 4 data segments (2 sessions x 2), got %d", len(data))
	}
	// s1 init 只携带 Kerberos；s2 init 只携带 NTLM（候选列表不串用）。
	h0, h2 := hex.EncodeToString(data[0].Payload), hex.EncodeToString(data[2].Payload)
	if !strings.Contains(h0, sOIDKrb) || strings.Contains(h0, sOIDNTLM) {
		t.Fatalf("s1 候选列表泄漏: %s", h0)
	}
	if !strings.Contains(h2, sOIDNTLM) || strings.Contains(h2, sOIDKrb) {
		t.Fatalf("s2 候选列表泄漏: %s", h2)
	}
	// s2 resp 的 negState=reject(2)、supportedMech=NTLM（会话级覆盖生效）。
	resp := data[3].Payload
	body := sCheckTLV(t, resp, 0, 0xA1, "s2 negTokenResp")
	seq := sCheckTLV(t, body, 0, 0x30, "s2 SEQUENCE")
	st := sCheckTLV(t, seq, 0, 0xA0, "s2 negState")
	enum := sCheckTLV(t, st, 0, 0x0A, "s2 ENUMERATED")
	if len(enum) != 1 || enum[0] != 2 {
		t.Fatalf("s2 negState % x, want 02 (reject)", enum)
	}
	if !strings.Contains(hex.EncodeToString(resp), sOIDNTLM) {
		t.Fatalf("s2 supportedMech 缺 NTLM: %s", hex.EncodeToString(resp))
	}
}

// ---- ⑩ IPv6 载体 ----

func TestSPNEGOChain_IPv6Carrier(t *testing.T) {
	pkts := sDrive(t, sIP6(map[string]interface{}{}))
	if len(pkts) != 8 {
		t.Fatalf("ipv6 baseline packets %d, want 8", len(pkts))
	}
	if pkts[0].L3.SrcIP != sCli6 || pkts[0].L3.DstIP != sSrv6 {
		t.Fatalf("ipv6 addrs %s -> %s", pkts[0].L3.SrcIP, pkts[0].L3.DstIP)
	}
	// IPv6 外层不改 DER（地址族与 token 无关——契约 §3 明示不得把 IPv6
	// outer 地址当机制字段）。
	if got := hex.EncodeToString(pkts[3].Payload); got[:2] != "60" {
		t.Fatalf("ipv6 token outer %s", got[:8])
	}
	// 与 IPv4 基线同 DER 前缀（同 fixtures）。
	v4 := sDrive(t, sIP(map[string]interface{}{}))
	if hex.EncodeToString(pkts[3].Payload) != hex.EncodeToString(v4[3].Payload) {
		t.Fatal("ipv6 DER differs from ipv4 fixture")
	}
}

// ---- ⑪ presence 与顶层游离键判死（1.11–1.13）----

func TestSPNEGOChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	// ①presence 负例形状（§11-P2 清单①）：层链 + 顶层空子映射并存 = 判死。
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": sCli, "dst": sSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": sSport, "dst_port": 445}},
			map[string]interface{}{"spnego": map[string]interface{}{}},
		},
		"spnego": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("spnego", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(spnego, {layers, spnego:{}}) = \"\", want top-level spnego presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level spnego sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	// ②白名单外游离键（1.11–1.13）：四元组类经 CheckProtoFlat 判死。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("spnego", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(spnego, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// MAC/TTL 类经 schema 语义门（checkLayerFlatConflict）判死。
	_, errs := schema.ValidateStrategy("synth", "spnego", map[string]any{
		"layers":  cfg["layers"],
		"src_mac": "aa:bb:cc:dd:ee:01",
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "src_mac") {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema must reject top-level src_mac alongside layers, errs=%v", errs)
	}
}

// ---- ⑫ 用例文件收官自查（非负例顶层键=0 + 三方一致）----

func TestSPNEGOChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/spnego.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 20 {
		t.Fatalf("want 20 cases, got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", id)
		}
		_, isNeg := exp["expect_error"]
		if isNeg {
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys must be exactly expect_error/error_contains, got %v", id, exp)
			}
			continue
		}
		// 非负例顶层键=0：只允许白名单结构性键。
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: stray top-level key %q (1.11–1.13)", id, k)
			}
		}
		if exp["packet_count"] == nil {
			t.Fatalf("%s: positive case must carry packet_count", id)
		}
	}
	if cases[0]["id"] != "spnego_http_ipv4_init" || cases[19]["id"] != "spnego_neg_carrier_profile" {
		t.Fatalf("case order/ID mismatch: first=%v last=%v", cases[0]["id"], cases[19]["id"])
	}
	if cases[14]["id"] != "spnego_neg_der_truncated" {
		t.Fatalf("negatives must start at index 14 (14 positives first), got %v", cases[14]["id"])
	}
}
