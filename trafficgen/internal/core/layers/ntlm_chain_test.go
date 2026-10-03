package layers_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ntlm" // init 注册 ntlm 终结层生成器+校验器
)

// D-NTLM-1 P4 链级红例（kerberos/dtls_chain_test 同构）：①空配置基线（smb2
// 缺省档一条最小 NEGOTIATE）/②NTLMSSP 三消息固定布局（little-endian
// SecurityBuffer 三元组、offset 相对 NTLMSSP 起点）/③SMB2 成帧（NBSS+SMB2
// header 64B+SESSION_SETUP body，status trio + msgID/sessionID 语义）/④HTTP
// 成帧（401 Negotiate ↔ Authorization: Negotiate base64）/⑤SPNEGO 外层隔离
// （ASN.1 tag/length 与 NTLM SecurityBuffer 分离）/⑥结构守卫负例（profile/
// version/outer/sequence/flags/unicode/av/length）/⑦6 wire_fault 注入锚词/
// ⑧载体形状（缺 tcp/udp/混合地址族/profile↔http 底座）/⑨严格解码/⑩多会话
// 隔离/⑪IPv6/⑫presence 与顶层游离键判死（1.11–1.13）/⑬用例文件收官自查。
// 契约 fixture：客户端 192.0.2.60 / 服务端 198.51.100.60 / SMB 445 / HTTP 80。

const (
	nCli    = "192.0.2.60"
	nSrv    = "198.51.100.60"
	nCli6   = "2001:db8::60"
	nSrv6   = "2001:db8:ffff::60"
	nSport  = 45600
	nSport6 = 45601
)

// nType1Default 是缺省档 Type 1 的完整 NTLMSSP 字节（P4 实测钉）：
// Signature | Type=1 | flags=0xA0898205 | DomainFields(Len=14/MaxLen=14/Off=32)
// | WorkstationFields(Len=22/MaxLen=22/Off=46) | payload "EXAMPLE"+
// "WORKSTATION"（UTF-16LE，偶数长度）。
const nType1Default = "4e544c4d5353500001000000058289a00e000e0020000000160016002e0000004500580041004d0050004c00450057004f0052004b00530054004100540049004f004e00"

func nJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func nIP(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
		map[string]interface{}{"ntlm": cfg},
	}
}

func nIP6(cfg map[string]interface{}) []interface{} {
	// IPv6 = 同一个 ip 层承载 v6 地址（无独立 ipv6 层——kerberos 先例实测；
	// 契约 §2 "IPv6 将 ip 替换为 ipv6" 为文档口径差异，P5 校准注记）。
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": nCli6, "dst": nSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport6, "dst_port": 445}},
		map[string]interface{}{"ntlm": cfg},
	}
}

func nHTTP(cfg map[string]interface{}, withHTTPLayer bool) []interface{} {
	out := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 80}},
	}
	if withHTTPLayer {
		out = append(out, map[string]interface{}{"http": map[string]interface{}{}})
	}
	return append(out, map[string]interface{}{"ntlm": cfg})
}

func nPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("ntlm", nJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	// 四元组回填：从 layers[0].ip 与 layers[1].tcp 的显式声明派生（kerberos
	// casegen 同款——src/dst/src_port/dst_port 以链声明为准）。
	spec := core.FlowSpec{SrcIP: nCli, DstIP: nSrv, SrcPort: nSport, DstPort: 445}
	for _, item := range layersArr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if ipc, ok := m["ip"].(map[string]interface{}); ok {
			if s, ok := ipc["src"].(string); ok && s != "" {
				spec.SrcIP = s
			}
			if s, ok := ipc["dst"].(string); ok && s != "" {
				spec.DstIP = s
			}
		}
		if tcpc, ok := m["tcp"].(map[string]interface{}); ok {
			if f, ok := tcpc["src_port"].(float64); ok {
				spec.SrcPort = uint16(f)
			}
			if f, ok := tcpc["dst_port"].(float64); ok {
				spec.DstPort = uint16(f)
			}
			if i, ok := tcpc["src_port"].(int); ok {
				spec.SrcPort = uint16(i)
			}
			if i, ok := tcpc["dst_port"].(int); ok {
				spec.DstPort = uint16(i)
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

func nDrive(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := nPlan(t, layersArr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func nDriveErr(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := nPlan(t, layersArr)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	return err
}

// nSess 构造单会话配置（events 为 kind 列表）。
func nSess(events ...string) map[string]interface{} {
	evs := make([]interface{}, len(events))
	for i, k := range events {
		evs[i] = map[string]interface{}{"kind": k}
	}
	return map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": evs}}}
}

// nData 返回 payload 非空的数据包（去掉握手/挥手空包）。
func nData(pkts []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, p := range pkts {
		if len(p.Payload) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// ---- NTLMSSP / SMB2 解析辅助（断言用，非生成侧第二套实现）----

// nSMB2Token 从 SMB2 PDU 里按 SecurityBufferOffset/Length 取 NTLMSSP token。
func nSMB2Token(t *testing.T, pdu []byte) []byte {
	t.Helper()
	if len(pdu) < 4+64 {
		t.Fatalf("pdu too short: %d", len(pdu))
	}
	if pdu[0] != 0x00 {
		t.Fatalf("NBSS type %#x, want 0x00", pdu[0])
	}
	nbssLen := int(pdu[1])<<16 | int(pdu[2])<<8 | int(pdu[3])
	if nbssLen != len(pdu)-4 {
		t.Fatalf("NBSS length %d != payload %d", nbssLen, len(pdu)-4)
	}
	msg := pdu[4:]
	if string(msg[0:4]) != "\xfeSMB" {
		t.Fatalf("SMB2 protocol id % x", msg[0:4])
	}
	if binary.LittleEndian.Uint16(msg[4:6]) != 64 {
		t.Fatalf("SMB2 StructureSize %d, want 64", binary.LittleEndian.Uint16(msg[4:6]))
	}
	if binary.LittleEndian.Uint16(msg[12:14]) != 0x0001 {
		t.Fatalf("SMB2 command %#x, want SESSION_SETUP", binary.LittleEndian.Uint16(msg[12:14]))
	}
	bodySize := binary.LittleEndian.Uint16(msg[64 : 64+2])
	var off, ln int
	switch bodySize {
	case 25: // request: SecurityBufferOffset at body+12
		off = int(binary.LittleEndian.Uint16(msg[64+12 : 64+14]))
		ln = int(binary.LittleEndian.Uint16(msg[64+14 : 64+16]))
	case 9: // response: SecurityBufferOffset at body+4
		off = int(binary.LittleEndian.Uint16(msg[64+4 : 64+6]))
		ln = int(binary.LittleEndian.Uint16(msg[64+6 : 64+8]))
	default:
		t.Fatalf("SESSION_SETUP StructureSize %d, want 25 or 9", bodySize)
	}
	if ln == 0 {
		return nil
	}
	if off+ln > len(msg) {
		t.Fatalf("security buffer %d+%d exceeds SMB2 message %d", off, ln, len(msg))
	}
	return msg[off : off+ln]
}

// nSB 是一项 security buffer 的三元组（断言侧解码）。
type nSB struct {
	len, maxLen uint16
	off         uint32
}

func nSecBuf(t *testing.T, tok []byte, at int) nSB {
	t.Helper()
	if at+8 > len(tok) {
		t.Fatalf("security buffer at %d exceeds token %d", at, len(tok))
	}
	return nSB{
		len:    binary.LittleEndian.Uint16(tok[at : at+2]),
		maxLen: binary.LittleEndian.Uint16(tok[at+2 : at+4]),
		off:    binary.LittleEndian.Uint32(tok[at+4 : at+8]),
	}
}

// nCheckSB 校验三元组自洽（Len<=MaxLen、Offset+Len 落在 token 内、非空字段
// 可读——契约 §5 规则 1/3/4 的断言面）。
func nCheckSB(t *testing.T, tok []byte, at int, what string) nSB {
	t.Helper()
	sb := nSecBuf(t, tok, at)
	if sb.len > sb.maxLen {
		t.Fatalf("%s: Len %d > MaxLen %d", what, sb.len, sb.maxLen)
	}
	if int(sb.off)+int(sb.len) > len(tok) {
		t.Fatalf("%s: Offset %d + Len %d exceeds token %d (overflow/out-of-token)", what, sb.off, sb.len, len(tok))
	}
	if sb.len > 0 {
		if sb.off < 8 {
			t.Fatalf("%s: Offset %d lands inside the fixed header", what, sb.off)
		}
		_ = tok[sb.off : int(sb.off)+int(sb.len)]
	}
	if sb.len%2 != 0 {
		t.Fatalf("%s: Len %d is odd (UTF-16LE must be even)", what, sb.len)
	}
	return sb
}

func nMsgType(t *testing.T, tok []byte) uint32 {
	t.Helper()
	if len(tok) < 12 {
		t.Fatalf("token %d bytes < 12 (message)", len(tok))
	}
	if string(tok[0:8]) != "NTLMSSP\x00" {
		t.Fatalf("signature % x, want NTLMSSP\\0 (signature)", tok[0:8])
	}
	return binary.LittleEndian.Uint32(tok[8:12])
}

// ---- ① 空配置基线（smb2 缺省档）----

func TestNTLMChain_SMB2BaselineDefault(t *testing.T) {
	pkts := nDrive(t, nIP(map[string]interface{}{}))
	if len(pkts) != 8 {
		t.Fatalf("want 8 packets (3 hs + 1 data + 4 fin), got %d", len(pkts))
	}
	if pkts[3].Direction != "up" {
		t.Fatalf("baseline direction %q", pkts[3].Direction)
	}
	if pkts[3].L4.DstPort != 445 || pkts[3].L4.SrcPort != nSport {
		t.Fatalf("ports %d->%d", pkts[3].L4.SrcPort, pkts[3].L4.DstPort)
	}
	tok := nSMB2Token(t, pkts[3].Payload)
	if mt := nMsgType(t, tok); mt != 1 {
		t.Fatalf("baseline message type %d, want NEGOTIATE(1)", mt)
	}
	if got := strings.ToUpper(hex.EncodeToString(tok)); got != strings.ToUpper(nType1Default) {
		t.Fatalf("baseline token:\n got %s\nwant %s", got, nType1Default)
	}
	// SMB2 header 语义：MessageId=0、SessionId=0（首个 SESSION_SETUP）、
	// CreditCharge=1、Credits=31、Command=1、Status=0。
	msg := pkts[3].Payload[4:]
	if binary.LittleEndian.Uint64(msg[24:32]) != 0 || binary.LittleEndian.Uint64(msg[40:48]) != 0 {
		t.Fatalf("first request msgID/sessionID: %d/%d", binary.LittleEndian.Uint64(msg[24:32]), binary.LittleEndian.Uint64(msg[40:48]))
	}
	if binary.LittleEndian.Uint16(msg[6:8]) != 1 || binary.LittleEndian.Uint16(msg[14:16]) != 31 {
		t.Fatalf("credit charge/credits: %d/%d", binary.LittleEndian.Uint16(msg[6:8]), binary.LittleEndian.Uint16(msg[14:16]))
	}
	// SESSION_SETUP 固定体：StructureSize=25、SecurityBufferOffset=88、
	// SecurityBufferLength=token 长度、SecurityMode=signing enabled。
	if body := msg[64:]; body[0] != 0x19 || body[3] != 0x01 {
		t.Fatalf("SESSION_SETUP body head % x", body[0:4])
	}
	if off := binary.LittleEndian.Uint16(msg[64+12 : 64+14]); off != 88 {
		t.Fatalf("SecurityBufferOffset %d, want 88 (64+24)", off)
	}
	if ln := binary.LittleEndian.Uint16(msg[64+14 : 64+16]); int(ln) != len(tok) {
		t.Fatalf("SecurityBufferLength %d != token %d", ln, len(tok))
	}
}

// ---- ② NTLMSSP 三消息布局（SMB2 会话全链）----

func TestNTLMChain_ThreeMessageLayout(t *testing.T) {
	cfg := map[string]interface{}{
		"profile": "smb2",
		"version": "ntlmv2",
		"outer":   "none",
		"sessions": []interface{}{map[string]interface{}{
			"id": "s1", "domain": "EXAMPLE", "user": "alice", "workstation": "WS01",
			"target_name": "EXAMPLE",
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "challenge"},
				map[string]interface{}{"kind": "authenticate"},
				map[string]interface{}{"kind": "session_setup_success"},
			},
		}},
	}
	pkts := nDrive(t, nIP(cfg))
	if len(pkts) != 11 {
		t.Fatalf("want 11 packets (3+4+4), got %d", len(pkts))
	}
	data := nData(pkts)
	if len(data) != 4 {
		t.Fatalf("want 4 data segments, got %d", len(data))
	}
	// 状态码 trio：request 0 / MORE_PROCESSING_REQUIRED / request 0 / SUCCESS。
	statuses := make([]uint32, 0, 4)
	for i, p := range data {
		msg := p.Payload[4:]
		statuses = append(statuses, binary.LittleEndian.Uint32(msg[8:12]))
		if want := uint64(i / 2); binary.LittleEndian.Uint64(msg[24:32]) != want {
			t.Fatalf("pkt%d MessageId %d, want %d", i+1, binary.LittleEndian.Uint64(msg[24:32]), want)
		}
	}
	want := []uint32{0, 0xC0000016, 0, 0}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("data[%d] status %#x, want %#x", i, statuses[i], want[i])
		}
	}
	// 会话 ID：首个 request=0，其余三包 = 服务端分配值（一致且非零）。
	sid := binary.LittleEndian.Uint64(data[1].Payload[4:][40:48])
	if sid == 0 {
		t.Fatal("assigned session id must be nonzero")
	}
	if binary.LittleEndian.Uint64(data[0].Payload[4:][40:48]) != 0 {
		t.Fatal("first SESSION_SETUP request must carry SessionId=0")
	}
	for i := 1; i < 4; i++ {
		if got := binary.LittleEndian.Uint64(data[i].Payload[4:][40:48]); got != sid {
			t.Fatalf("data[%d] session id %#x, want %#x", i, got, sid)
		}
	}

	// Type 1：固定头 32 + domain/workstation 负载。
	t1 := nSMB2Token(t, data[0].Payload)
	if mt := nMsgType(t, t1); mt != 1 {
		t.Fatalf("msg type %d", mt)
	}
	sbD := nCheckSB(t, t1, 16, "Type1.DomainNameFields")
	sbW := nCheckSB(t, t1, 24, "Type1.WorkstationFields")
	if sbD.len != 14 || sbD.off != 32 || sbD.maxLen != 14 {
		t.Fatalf("Type1 domain fields %+v", sbD)
	}
	if sbW.len != 8 || sbW.off != 32+14 {
		t.Fatalf("Type1 workstation fields %+v", sbW)
	}
	if got := string(t1[sbD.off : sbD.off+uint32(sbD.len)]); got != "E\x00X\x00A\x00M\x00P\x00L\x00E\x00" {
		t.Fatalf("Type1 domain payload %q", got)
	}

	// Type 2：TargetName(14)+TargetInfo(120) 负载、ServerChallenge 非零、
	// Reserved 全零、AV 序列以 MsvAvEOL 收尾。
	t2 := nSMB2Token(t, data[1].Payload)
	if mt := nMsgType(t, t2); mt != 2 {
		t.Fatalf("msg type %d", mt)
	}
	if len(t2) < 48 {
		t.Fatalf("Type2 token %d < 48 (message)", len(t2))
	}
	sbTN := nCheckSB(t, t2, 12, "Type2.TargetNameFields")
	sbTI := nCheckSB(t, t2, 40, "Type2.TargetInfoFields")
	if string(t2[sbTN.off:sbTN.off+uint32(sbTN.len)]) != "E\x00X\x00A\x00M\x00P\x00L\x00E\x00" {
		t.Fatalf("Type2 target name payload mismatch")
	}
	if off := sbTI.off; off != sbTN.off+uint32(sbTN.len) {
		t.Fatalf("Type2 target info offset %d, want %d", off, sbTN.off+uint32(sbTN.len))
	}
	chal := t2[24:32]
	if binary.LittleEndian.Uint64(chal) == 0 {
		t.Fatal("ServerChallenge must be nonzero (契约 §6)")
	}
	for i, b := range t2[32:40] {
		if b != 0 {
			t.Fatalf("Type2 Reserved byte %d = %#x, want 0", i, b)
		}
	}
	// AV 序列解析：每项 AvId(2)|AvLen(2)|Value(AvLen)，最后一项 EOL(0,0)。
	avs := t2[sbTI.off : sbTI.off+uint32(sbTI.len)]
	ids := []uint16{}
	for pos := 0; pos < len(avs); {
		if pos+4 > len(avs) {
			t.Fatalf("AV_PAIR header truncated at %d", pos)
		}
		id := binary.LittleEndian.Uint16(avs[pos : pos+2])
		l := int(binary.LittleEndian.Uint16(avs[pos+2 : pos+4]))
		if pos+4+l > len(avs) {
			t.Fatalf("AV_PAIR id %d len %d exceeds sequence %d (av)", id, l, len(avs))
		}
		ids = append(ids, id)
		pos += 4 + l
	}
	if ids[len(ids)-1] != 0 {
		t.Fatalf("AV sequence must end with MsvAvEOL, ids=%v", ids)
	}
	if len(ids) < 4 {
		t.Fatalf("want multiple AV pairs, got %v", ids)
	}

	// Type 3：六类 security buffer + flags + NTLMv2 blob（proof 16B + 结构）。
	t3 := nSMB2Token(t, data[2].Payload)
	if mt := nMsgType(t, t3); mt != 3 {
		t.Fatalf("msg type %d", mt)
	}
	if len(t3) < 64 {
		t.Fatalf("Type3 token %d < 64 (message)", len(t3))
	}
	sbLM := nCheckSB(t, t3, 12, "Type3.LmChallengeResponse")
	sbNT := nCheckSB(t, t3, 20, "Type3.NtChallengeResponse")
	sbDom := nCheckSB(t, t3, 28, "Type3.DomainName")
	sbUser := nCheckSB(t, t3, 36, "Type3.UserName")
	sbWS := nCheckSB(t, t3, 44, "Type3.Workstation")
	sbKey := nCheckSB(t, t3, 52, "Type3.SessionKey")
	if sbLM.len != 0 || sbLM.maxLen != 0 {
		t.Fatalf("NTLMv2 profile LM response must be empty, got %+v", sbLM)
	}
	if sbNT.len < 16+28 {
		t.Fatalf("NT response %d must cover 16B proof + blob", sbNT.len)
	}
	if sbKey.len != 0 {
		t.Fatalf("session key must be empty (no key), got %+v", sbKey)
	}
	// 字段不重叠：按声明顺序严格递增。
	order := []nSB{sbLM, sbNT, sbDom, sbUser, sbWS, sbKey}
	last := uint32(0)
	for _, sb := range order {
		if sb.len == 0 {
			continue
		}
		if sb.off < last {
			t.Fatalf("security buffers overlap: %+v (last end %d)", sb, last)
		}
		last = sb.off + uint32(sb.len)
	}
	if got := string(t3[sbUser.off : sbUser.off+uint32(sbUser.len)]); got != "a\x00l\x00i\x00c\x00e\x00" {
		t.Fatalf("Type3 user payload %q", got)
	}
	// blob：proof(16, 非全零 opaque) | RespType=1 | HiRespType=1 | TS/CC ...
	blob := t3[sbNT.off : sbNT.off+uint32(sbNT.len)]
	if binary.LittleEndian.Uint32(t3[8:12]) != 3 {
		t.Fatal("blob container must be NTLMSSP type 3")
	}
	allZero := true
	for _, b := range blob[0:16] {
		if b != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Fatal("proof placeholder must be nonzero opaque (fixture fill)")
	}
	if blob[16] != 1 || blob[17] != 1 {
		t.Fatalf("blob RespType/HiRespType = %d/%d, want 1/1", blob[16], blob[17])
	}
	// blob 尾部 MsvAvEOL（最后 4 字节全零）。
	if got := binary.LittleEndian.Uint32(blob[len(blob)-4:]); got != 0 {
		t.Fatalf("blob must end with MsvAvEOL, got %#x", got)
	}

	// SUCCESS 响应：Status=0、SecurityBufferOffset=72、Length=0。
	msg := data[3].Payload[4:]
	if binary.LittleEndian.Uint32(msg[8:12]) != 0 {
		t.Fatal("final status must be SUCCESS")
	}
	if off := binary.LittleEndian.Uint16(msg[64+4 : 64+6]); off != 72 {
		t.Fatalf("SUCCESS SecurityBufferOffset %d, want 72", off)
	}
	if ln := binary.LittleEndian.Uint16(msg[64+6 : 64+8]); ln != 0 {
		t.Fatalf("SUCCESS SecurityBufferLength %d, want 0", ln)
	}
}

// ---- ③ HTTP profile（401 Negotiate ↔ Authorization）----

func TestNTLMChain_HTTPProfile(t *testing.T) {
	cfg := map[string]interface{}{
		"profile": "http-negotiate",
		"outer":   "none",
		"sessions": []interface{}{map[string]interface{}{
			"user": "alice",
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "challenge"},
				map[string]interface{}{"kind": "authenticate"},
				map[string]interface{}{"kind": "http_success"},
			},
		}},
	}
	// 显式 http 底座（可选底座透传）与无 http 底座两形字节一致。
	pktsA := nDrive(t, nHTTP(cfg, true))
	pktsB := nDrive(t, nHTTP(cfg, false))
	if len(pktsA) != 11 || len(pktsB) != 11 {
		t.Fatalf("packet counts %d/%d, want 11/11", len(pktsA), len(pktsB))
	}
	if pktsA[3].L4.DstPort != 80 {
		t.Fatalf("http profile dst port %d, want 80", pktsA[3].L4.DstPort)
	}
	dataA, dataB := nData(pktsA), nData(pktsB)
	for i := range dataA {
		if string(dataA[i].Payload) != string(dataB[i].Payload) {
			t.Fatalf("data[%d]: http layer passthrough changed bytes", i)
		}
	}
	// 请求行/状态行 + header scheme。
	if !strings.HasPrefix(string(dataA[0].Payload), "POST / HTTP/1.1\r\n") {
		t.Fatalf("request line: %q", dataA[0].Payload[:20])
	}
	if !strings.Contains(string(dataA[0].Payload), "Authorization: Negotiate ") {
		t.Fatal("request must carry Authorization: Negotiate")
	}
	if !strings.HasPrefix(string(dataA[1].Payload), "HTTP/1.1 401 Unauthorized\r\n") ||
		!strings.Contains(string(dataA[1].Payload), "WWW-Authenticate: Negotiate ") {
		t.Fatalf("challenge response: %q", dataA[1].Payload[:40])
	}
	if !strings.HasPrefix(string(dataA[3].Payload), "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("final response: %q", dataA[3].Payload[:20])
	}
	// base64 token 解码后必须是完整 NTLMSSP（header scheme/token 边界）。
	line := string(dataA[2].Payload)
	idx := strings.Index(line, "Authorization: Negotiate ")
	if idx < 0 {
		t.Fatal("Type 3 request missing Authorization header")
	}
	b64 := line[idx+len("Authorization: Negotiate "):]
	b64 = b64[:strings.Index(b64, "\r\n")]
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("token base64: %v", err)
	}
	if mt := nMsgType(t, raw); mt != 3 {
		t.Fatalf("Authorization token type %d, want 3", mt)
	}
	nCheckSB(t, raw, 20, "HTTP.Type3.NtChallengeResponse")
}

// ---- ④ SPNEGO 外层隔离（契约 §8）----

func TestNTLMChain_SPNEGOOuter(t *testing.T) {
	pkts := nDrive(t, nIP(map[string]interface{}{
		"outer": "spnego",
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "challenge"},
			},
		}},
	}))
	data := nData(pkts)
	// Type 1：GSS-API InitialContextToken [APPLICATION 0] + SPNEGO OID +
	// negTokenInit[0] + mechTypes[0](NTLM OID 1.3.6.1.4.1.311.2.2.10) +
	// mechToken[2]。ASN.1 tag/length 与 NTLM SecurityBuffer 分离。
	tok := nSMB2Token(t, data[0].Payload)
	wantPrefix := "606206062b060105050230" // 60 62 | OID SPNEGO | NegTokenInit SEQUENCE(30)
	if !strings.HasPrefix(strings.ToLower(hex.EncodeToString(tok)), wantPrefix) {
		t.Fatalf("spnego type1 prefix: %s", hex.EncodeToString(tok[:16]))
	}
	ntlmOIDHex := "060a2b06010401823702020a"
	if !strings.Contains(strings.ToLower(hex.EncodeToString(tok)), ntlmOIDHex) {
		t.Fatalf("NTLM mech OID missing in spnego wrapper: %s", hex.EncodeToString(tok))
	}
	innerIdx := strings.Index(strings.ToLower(hex.EncodeToString(tok)), "4e544c4d53535000")
	if innerIdx < 0 {
		t.Fatal("inner NTLMSSP signature missing inside mechToken")
	}
	inner := tok[innerIdx/2:]
	if mt := nMsgType(t, inner); mt != 1 {
		t.Fatalf("inner type %d, want 1", mt)
	}
	// Type 2：negTokenResp [1]（a1 ...）包裹。
	tok2 := nSMB2Token(t, data[1].Payload)
	if !strings.HasPrefix(strings.ToLower(hex.EncodeToString(tok2)), "a1") {
		t.Fatalf("spnego type2 must be negTokenResp [1]: %s", hex.EncodeToString(tok2[:8]))
	}
	// 不能把 ASN.1 tag/length 当 MessageType：token 起点不是 NTLMSSP signature，
	// 内层 signature 只在 responseToken 内出现一次。
	if strings.Count(strings.ToLower(hex.EncodeToString(tok2)), "4e544c4d53535000") != 1 {
		t.Fatalf("inner NTLMSSP signature must appear exactly once: %s", hex.EncodeToString(tok2))
	}
}

// ---- ⑤ 结构/状态守卫负例 ----

func TestNTLMChain_StructureGuards(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{
					map[string]interface{}{"kind": "negotiate"},
					map[string]interface{}{"kind": "challenge"},
					map[string]interface{}{"kind": "authenticate"},
					map[string]interface{}{"kind": "session_setup_success"},
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
		{"unknown_profile", with("profile", "smb3"), "(profile)"},
		{"unsupported_version", with("version", "ntlmv1"), "(version)"},
		{"unknown_outer", with("outer", "gssapi"), "(spnego)"},
		{"unknown_kind", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "magic"}},
		}}), `kind "magic"`},
		{"http_kind_in_smb2", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "http_success"},
			},
		}}), "not a smb2 carrier event (profile)"},
		{"smb2_kind_in_http", map[string]interface{}{
			"profile": "http-negotiate",
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{
					map[string]interface{}{"kind": "negotiate"},
					map[string]interface{}{"kind": "session_setup_success"},
				},
			}},
		}, "(profile)"},
		{"challenge_before_negotiate", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "challenge"}},
		}}), "(sequence)"},
		{"authenticate_before_challenge", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "authenticate"},
			},
		}}), "(sequence)"},
		{"status_before_authenticate", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "negotiate"},
				map[string]interface{}{"kind": "challenge"},
				map[string]interface{}{"kind": "session_setup_success"},
			},
		}}), "(sequence)"},
		{"flags_target_info_mismatch", func() map[string]interface{} {
			c := base()
			c["flags"] = map[string]interface{}{"target_info": false}
			c["target_info"] = map[string]interface{}{"nb_domain_name": "EXAMPLE"}
			return c
		}(), "(flags)"},
		{"oem_non_latin1", func() map[string]interface{} {
			c := base()
			c["flags"] = map[string]interface{}{"unicode": false}
			c["sessions"] = []interface{}{map[string]interface{}{
				"user": "пользователь",
				"events": []interface{}{
					map[string]interface{}{"kind": "negotiate"},
				},
			}}
			return c
		}(), "(unicode)"},
		{"target_info_no_eol", with("target_info", map[string]interface{}{"no_eol": true}), "(av)"},
		{"blob_no_eol", with("ntlmv2_response", map[string]interface{}{"no_eol": true}), "(av)"},
		{"lm_response_over_bound", with("ntlmv2_response", map[string]interface{}{"lm_response_len": 300}), "(length)"},
		{"session_key_negative", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "negotiate", "session_key_len": -1,
			}},
		}}), "(length)"},
		{"server_challenge_bad_hex", with("sessions", []interface{}{map[string]interface{}{
			"server_challenge": "zz",
			"events":           []interface{}{map[string]interface{}{"kind": "negotiate"}},
		}}), "non-hex"},
		{"server_challenge_short", with("sessions", []interface{}{map[string]interface{}{
			"server_challenge": "00112233",
			"events":           []interface{}{map[string]interface{}{"kind": "negotiate"}},
		}}), "want 8"},
		{"unknown_config_key", with("no_such_key", 1), "unknown field"},
		{"unknown_session_key", with("sessions", []interface{}{map[string]interface{}{
			"whoknows": 1,
			"events":   []interface{}{map[string]interface{}{"kind": "negotiate"}},
		}}), "unknown field"},
		{"unknown_event_key", with("sessions", []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "negotiate", "nope": 1}},
		}}), "unknown field"},
		{"unknown_flags_key", func() map[string]interface{} {
			c := base()
			c["flags"] = map[string]interface{}{"unicode_typo": true}
			return c
		}(), "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := nDriveErr(t, nIP(tc.cfg))
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err, tc.anchor)
			}
		})
	}
}

// ---- ⑥ 6 wire_fault 注入锚词 ----

func TestNTLMChain_WireFaults(t *testing.T) {
	for fault, anchor := range map[string]string{
		"message_length":    "anchor message",
		"security_buffer":   "anchor buffer",
		"offset_overflow":   "anchor offset",
		"flags_target_info": "anchor flags",
		"blob_av_pairs":     "anchor blob",
		"carrier_profile":   "anchor carrier",
	} {
		err := nDriveErr(t, nIP(map[string]interface{}{"wire_fault": fault}))
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: error %q missing anchor %q", fault, err, anchor)
		}
	}
	if err := nDriveErr(t, nIP(map[string]interface{}{"wire_fault": "no_such_fault"})); err == nil ||
		!strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown fault: %v", err)
	}
}

// ---- ⑦ 载体形状与 profile↔底座一致性 ----

func TestNTLMChain_CarrierShapes(t *testing.T) {
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_tcp", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
			map[string]interface{}{"ntlm": map[string]interface{}{}},
		}, "(carrier)"},
		{"udp_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
			map[string]interface{}{"ntlm": map[string]interface{}{}},
		}, "(transport)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv6}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
			map[string]interface{}{"ntlm": map[string]interface{}{}},
		}, "(family)"},
		{"smb2_with_http_base", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"ntlm": map[string]interface{}{"profile": "smb2"}},
		}, "(profile)"},
		{"smb2_default_with_http_base", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"ntlm": map[string]interface{}{}},
		}, "(profile)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := nDriveErr(t, tc.layers)
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err, tc.anchor)
			}
		})
	}
}

// ---- ⑧ 多会话隔离（同目的端口，独立 SessionId/ServerChallenge/端点）----

func TestNTLMChain_MultiSessionIsolation(t *testing.T) {
	// 同一 TCP 连接上的两个认证会话（SMB2 多会话共享连接 = 流内四元组；
	// 会话间 SessionId/ServerChallenge/user 全隔离。跨四元组的多流由
	// flows>1/多策略路径提供——单流内不做 per-session 端点覆盖（tcp 连接
	// 身份=四元组，kerberos tcp+src_ip 同判）。
	mk := func(user string, evs ...string) map[string]interface{} {
		ev := make([]interface{}, len(evs))
		for i, k := range evs {
			ev[i] = map[string]interface{}{"kind": k}
		}
		return map[string]interface{}{"id": user, "user": user, "events": ev}
	}
	cfg := map[string]interface{}{
		"profile": "smb2",
		"sessions": []interface{}{
			mk("alice", "negotiate", "challenge", "authenticate", "session_setup_success"),
			mk("bob", "negotiate", "challenge", "authenticate", "session_setup_success"),
		},
	}
	pkts := nDrive(t, nIP(cfg))
	data := nData(pkts)
	if len(data) != 8 {
		t.Fatalf("want 8 data segments (2 sessions x 4), got %d", len(data))
	}
	// 每个会话内 Type 1→2→3 顺序 + 会话间 SessionChallenge/SessionId 独立。
	// 每会话前 3 个数据包 = Type 1→2→3（第 4 包是 SUCCESS 载体终态，无 token）。
	for _, base := range []int{0, 4} {
		got := []uint32{
			nMsgType(t, nSMB2Token(t, data[base].Payload)),
			nMsgType(t, nSMB2Token(t, data[base+1].Payload)),
			nMsgType(t, nSMB2Token(t, data[base+2].Payload)),
		}
		if got[0] != 1 || got[1] != 2 || got[2] != 3 {
			t.Fatalf("session base %d type order %v", base, got)
		}
		if tok := nSMB2Token(t, data[base+3].Payload); tok != nil {
			t.Fatalf("session base %d: SUCCESS response must carry no token", base)
		}
	}
	chalA := nSMB2Token(t, data[1].Payload)[24:32]
	chalB := nSMB2Token(t, data[5].Payload)[24:32]
	if string(chalA) == string(chalB) {
		t.Fatalf("server challenges must differ across sessions: %x", chalA)
	}
	sidA := binary.LittleEndian.Uint64(data[1].Payload[4:][40:48])
	sidB := binary.LittleEndian.Uint64(data[5].Payload[4:][40:48])
	if sidA == sidB || sidA == 0 || sidB == 0 {
		t.Fatalf("session ids must be independent and nonzero: %#x / %#x", sidA, sidB)
	}
	users := map[string]bool{}
	for _, i := range []int{2, 6} {
		tok := nSMB2Token(t, data[i].Payload)
		sb := nSecBuf(t, tok, 36)
		users[string(tok[sb.off:sb.off+uint32(sb.len)])] = true
	}
	if !users["a\x00l\x00i\x00c\x00e\x00"] || !users["b\x00o\x00b\x00"] {
		t.Fatalf("per-session usernames wrong: %v", users)
	}
}

// ---- ⑨ IPv6 载体 ----

func TestNTLMChain_IPv6Carrier(t *testing.T) {
	pkts := nDrive(t, nIP6(map[string]interface{}{}))
	if len(pkts) != 8 {
		t.Fatalf("ipv6 baseline packets %d, want 8", len(pkts))
	}
	if pkts[0].L3.SrcIP != nCli6 || pkts[0].L3.DstIP != nSrv6 {
		t.Fatalf("ipv6 addrs %s -> %s", pkts[0].L3.SrcIP, pkts[0].L3.DstIP)
	}
	tok := nSMB2Token(t, pkts[3].Payload)
	if got := strings.ToUpper(hex.EncodeToString(tok)); got != strings.ToUpper(nType1Default) {
		t.Fatalf("ipv6 token differs from ipv4 fixture:\n got %s", got)
	}
}

// ---- ⑩ presence 与顶层游离键判死（1.11–1.13）----

func TestNTLMChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	// ①presence 负例形状（M5 清单①）：层链 + 顶层空子映射并存 = 判死。
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": nSport, "dst_port": 445}},
			map[string]interface{}{"ntlm": map[string]interface{}{}},
		},
		"ntlm": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("ntlm", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(ntlm, {layers, ntlm:{}}) = \"\", want top-level ntlm presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level ntlm sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	// ②白名单外游离键（1.11–1.13）：四元组类经 CheckProtoFlat/门2-1 判死。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("ntlm", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(ntlm, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// MAC 类经 schema 语义门（checkLayerFlatConflict）判死。
	_, errs := schema.ValidateStrategy("synth", "ntlm", map[string]any{
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

// ---- ⑪ 用例文件收官自查（M5 清单④：非负例顶层键=0 + 三方一致）----

func TestNTLMChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/ntlm.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 21 {
		t.Fatalf("want 21 cases (20 ID + T-21 A′ 补例), got %d", len(cases))
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
		// 非负例顶层键=0（M5 清单④）：只允许白名单结构性键。
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: stray top-level key %q (1.11–1.13)", id, k)
			}
		}
		if exp["packet_count"] == nil {
			t.Fatalf("%s: positive case must carry packet_count", id)
		}
	}
	// 21 例 = 20 ID（14 正 + 6 负）+ T-21（A′ 补例，插在 #14 正例之后、负例之前）。
	if cases[0]["id"] != "ntlm_smb_ipv4_v2_basic" || cases[20]["id"] != "ntlm_neg_carrier_profile" {
		t.Fatalf("case order/ID mismatch: first=%v last=%v", cases[0]["id"], cases[20]["id"])
	}
	if cases[15]["id"] != "ntlm_neg_message_truncated" {
		t.Fatalf("negatives must start at index 15 (15 positives first), got %v", cases[15]["id"])
	}
	if cases[14]["id"] != "ntlm_http_negotiate_v6" {
		t.Fatalf("T-21 must sit at index 14 (after #14), got %v", cases[14]["id"])
	}
}
