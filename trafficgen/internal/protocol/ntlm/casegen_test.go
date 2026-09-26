// Package ntlm — casegen 一次性用例生成器（D-NTLM-1 P5）。
//
// 20 例（14 正 + 6 负），按用例文档 §2 权威序。正例帧断言取自全链真实回放
// （BuildLayersPlanner→Plan，与套件同路径——单权威，无重复编码）：帧内
// NTLMSSP token = builder 渲染（builder 单权威），载体 = SMB2 SESSION_SETUP
// 自封帧 / HTTP Negotiate 自封帧。
//
// 先跑后钉口径（P5 实测计数 vs 设计 §11 约定计数）：
//
//	TCP 算术 = 3 握手 + 每事件一数据段（无 MSS 超出、无多事件合并时）+
//	4 挥手。事件数 E 的会话 → 3+E+4。
//	① #1 设计 14 / 实测 11（4 事件：3+4+4）
//	② #2 设计 14 / 实测 11（同 #1，IPv6 外层不改变 TCP 算术）
//	③ #3 设计 14 / 实测 11（4 事件，http-negotiate）
//	④ #4 设计 12 / 实测 15（两会话各 4 事件，上链为一条流：3+8+4）
//	⑤ #5 设计 10 / 实测 11（4 事件）
//	⑥ #6 设计 12 / 实测 11（4 事件）
//	⑦ #7 设计 10 / 实测 11（4 事件）
//	⑧ #8 设计 12 / 实测 11（4 事件）
//	⑨ #9 设计 14 / 实测 11（4 事件，SPNEGO 外层）
//	⑩ #10 设计 28 / 实测 15（两会话各 4 事件，一条流：3+8+4）
//	⑪ #11 设计 18 / 实测 17（两会话各 4 事件 + 长用户名 Type-3 真分段：3+10+4，mss 536，max payload 536；终审 M1 修轮）
//	⑫ #12 设计 18 / 实测 13（6 事件重试链：3+6+4）
//	⑬ #13 设计 8 / 实测 15（两会话各 4 事件：3+8+4；长用户名大包）
//	⑭ #14 设计 16 / 实测 11（4 事件稳定 fixture）
//	（差异根因：设计计数按旧包公式手算，实测按引擎链回放；以先跑后钉实测为准。）
package ntlm

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

type nfld struct {
	Packet   int
	Field    string
	Value    string
	Nonzero  bool
	Same     int
	Distinct []string
	Exclude  []string
}

func (f nfld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Nonzero {
		m["nonzero"] = true
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

type nfr struct {
	Packet int
	Offset int
	Hex    string
}

func (f nfr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type nposCase struct {
	id      string
	summary string
	layers  []interface{}
	count   int
	fields  []nfld
	frames  []nfr
}

type nnegCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
}

const (
	nCli   = "192.0.2.60"
	nSrv   = "198.51.100.60"
	nCli6  = "2001:db8::60"
	nSrv6  = "2001:db8:ffff::60"
	nSport = 45600
	nPort  = 445
	nHTTPP = 80
)

func nInt(i int) *int    { return &i }
func nBool(b bool) *bool { return &b }

func nIP() map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": nCli, "dst": nSrv}}
}
func nIP6() map[string]interface{} {
	// IPv6 uses the plain ip layer with v6 addresses (there is no ipv6 layer).
	return map[string]interface{}{"ip": map[string]interface{}{"src": nCli6, "dst": nSrv6}}
}
func nTCP(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func nTCPMSS(sp, dp, mss int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp, "mss": mss}}
}
func nHTTP() map[string]interface{} { return map[string]interface{}{"http": map[string]interface{}{}} }
func nL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"ntlm": cfg}
}

func nEv(kind string, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"kind": kind}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// nSess 生成一会话（身份 knobs + 有序事件）。
func nSess(id string, knobs map[string]interface{}, kinds ...string) map[string]interface{} {
	m := map[string]interface{}{}
	if id != "" {
		m["id"] = id
	}
	for k, v := range knobs {
		m[k] = v
	}
	var evs []interface{}
	for _, k := range kinds {
		evs = append(evs, map[string]interface{}{"kind": k})
	}
	m["events"] = evs
	return m
}

func nChainSMB(cfg map[string]interface{}) []interface{} {
	return []interface{}{nIP(), nTCP(nSport, nPort), nL(cfg)}
}

// nWirePin 经全链回放取某事件消息（transport payload）的完整帧 hex：
// NTLMSSP token 与载体成帧 = builder 单权威（内容权威=链级单测），本文件
// 权威只在包号/字段/方向/会话路由。
func nWirePin(t *testing.T, pkts []core.PacketConfig, pkt int) string {
	t.Helper()
	if pkt < 1 || pkt > len(pkts) {
		t.Fatalf("pin packet %d out of range (%d)", pkt, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[pkt-1].Payload))
}

func nPlanChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("ntlm", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: nCli, DstIP: nSrv, SrcPort: nSport, DstPort: nPort}
	if len(layersArr) > 0 {
		if first, ok := layersArr[0].(map[string]interface{}); ok {
			if ip, ok := first["ip"].(map[string]interface{}); ok {
				spec.SrcIP = ip["src"].(string)
				spec.DstIP = ip["dst"].(string)
			}
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

func nPlanErr(layersArr []interface{}) error {
	raw, err := json.Marshal(layersArr)
	if err != nil {
		return err
	}
	p, err := layers.BuildLayersPlanner("ntlm", raw)
	if err != nil {
		return err
	}
	spec := core.FlowSpec{SrcIP: nCli, DstIP: nSrv, SrcPort: nSport, DstPort: nPort}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return err
	}
	for range ch {
	}
	return nil
}

func TestGenerateNTLMCases(t *testing.T) {
	var positives []nposCase

	std4 := func(profile string) map[string]interface{} {
		c := map[string]interface{}{}
		if profile != "" {
			c["profile"] = profile
		}
		c["sessions"] = []interface{}{
			nSess("s1", nil, "negotiate", "challenge", "authenticate", "session_setup_success"),
		}
		return c
	}

	add := func(id, summary string, layersArr []interface{}, count int, fields []nfld, framePins []nfr) {
		pkts := nPlanChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, pinned %d", id, len(pkts), count)
		}
		positives = append(positives, nposCase{id: id, summary: summary, layers: layersArr, count: count, fields: fields, frames: framePins})
	}

	// ① ntlm_smb_ipv4_v2_basic（11）:P-SMB TCP/445 Type 1→2→3 + SUCCESS。
	add("ntlm_smb_ipv4_v2_basic", "P-SMB IPv4/TCP/445 Type 1→2→3 + STATUS_SUCCESS（NTLMv2）",
		nChainSMB(std4("smb2")), 11,
		[]nfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
			{4, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
			{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
			{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
			{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
			{7, "smb2.nt_status", "0x00000000", false, 0, nil, nil},
			{5, "smb2.nt_status", "0xc0000016", false, 0, nil, nil},
			{4, "ntlmssp.negotiateflags", "", true, 0, nil, nil},
			{6, "ntlmssp.auth.username", "user", false, 0, nil, nil},
		},
		func() []nfr {
			pkts := nPlanChain(t, nChainSMB(std4("smb2")))
			return []nfr{
				{4, 54, nWirePin(t, pkts, 4)},
				{5, 54, nWirePin(t, pkts, 5)[:128]},
				{6, 54, nWirePin(t, pkts, 6)[:128]},
				{7, 54, nWirePin(t, pkts, 7)[:64]},
			}
		}())

	// ② ntlm_smb_ipv6_v2_basic（11）:独立 IPv6 fixture（地址族/会话隔离，TCP 算术不变）。
	{
		layersArr := []interface{}{nIP6(), nTCP(nSport, nPort), nL(std4("smb2"))}
		pkts := nPlanChain(t, layersArr)
		add("ntlm_smb_ipv6_v2_basic", "P-SMB IPv6/TCP/445 独立地址族与会话（不复用 IPv4 challenge/stream）",
			layersArr, len(pkts),
			[]nfld{
				{1, "ipv6.nxt", "6", false, 0, nil, nil},
				{1, "tcp.dstport", "445", false, 0, nil, nil},
				{4, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
				{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
				{7, "smb2.nt_status", "0x00000000", false, 0, nil, nil},
			},
			[]nfr{{4, 74, nWirePin(t, pkts, 4)}, {6, 74, nWirePin(t, pkts, 6)[:128]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_smb_ipv6_v2_basic: %d packets, want 11 (TCP 3+4+4)", len(pkts))
		}
	}

	// ③ ntlm_http_negotiate_v2（11）:P-HTTP 明文 TCP/80 401→Type 3→2xx。
	add("ntlm_http_negotiate_v2", "P-HTTP 明文 TCP/80：401 Negotiate → Type 1 → Type 2 → Type 3 → 2xx",
		[]interface{}{nIP(), nTCP(nSport, nHTTPP), nL(map[string]interface{}{
			"profile": "http-negotiate",
			"sessions": []interface{}{
				nSess("s1", nil, "negotiate", "challenge", "authenticate", "http_success"),
			},
		})}, 11,
		[]nfld{
			{1, "tcp.dstport", "80", false, 0, nil, nil},
			{5, "http.response.code", "401", false, 0, nil, nil},
			{7, "http.response.code", "200", false, 0, nil, nil},
			{4, "http.request.method", "POST", false, 0, nil, nil},
			{6, "http.request.method", "POST", false, 0, nil, nil},
			{5, "http.www_authenticate", "", true, 0, nil, nil},
			{6, "http.authorization", "", true, 0, nil, nil},
		},
		// frames 钉 4-7 全钉（终审 n2 回补）：hex.go 解析器已按通用标签形跳过
		// "NTLMSSP / GSSAPI Data (N bytes):" 提取块（commit 7cb82de），
		// 包 5+ 的帧索引不再漂移。
		func() []nfr {
			arr := []interface{}{nIP(), nTCP(nSport, nHTTPP), nL(map[string]interface{}{
				"profile":  "http-negotiate",
				"sessions": []interface{}{nSess("s1", nil, "negotiate", "challenge", "authenticate", "http_success")},
			})}
			pkts := nPlanChain(t, arr)
			return []nfr{
				{4, 54, nWirePin(t, pkts, 4)},
				{5, 54, nWirePin(t, pkts, 5)[:128]},
				{6, 54, nWirePin(t, pkts, 6)[:128]},
				{7, 54, nWirePin(t, pkts, 7)[:64]},
			}
		}())

	// ④ ntlm_negotiate_flags_version（15）:会话 A version=true（8-byte Version 出现，
	// version.major=10）；会话 B 不声明（Version 缺席）。
	{
		cfgA := map[string]interface{}{
			"flags":    map[string]interface{}{"version": true},
			"sessions": []interface{}{nSess("sA", nil, "negotiate", "challenge", "authenticate", "session_setup_success")},
		}
		cfgB := map[string]interface{}{
			"sessions": []interface{}{nSess("sB", map[string]interface{}{"user": "bob"}, "negotiate", "challenge", "authenticate", "session_setup_success")},
		}
		merged := map[string]interface{}{
			"flags":    cfgA["flags"],
			"sessions": []interface{}{cfgA["sessions"].([]interface{})[0], cfgB["sessions"].([]interface{})[0]},
		}
		layersArr := nChainSMB(merged)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_negotiate_flags_version", "flags 交集一致：会话 A 声明 NEGOTIATE_VERSION（8-byte Version，major=10）/ 会话 B 省略（Version 缺席）",
			layersArr, len(pkts),
			[]nfld{
				{4, "ntlmssp.negotiateversion", "1", false, 0, nil, nil},
				{4, "ntlmssp.version.major", "10", false, 0, nil, nil},
				{4, "ntlmssp.negotiateflags", "", true, 0, nil, nil},
				{8, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
				{9, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{9, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{4, "ntlmssp.negotiateflags", "", false, 8, nil, nil}, // Type 1 A/B flags 一致
			},
			[]nfr{{4, 54, nWirePin(t, pkts, 4)}, {8, 54, nWirePin(t, pkts, 8)[:128]}})
		if len(pkts) != 15 {
			t.Fatalf("ntlm_negotiate_flags_version: %d packets, want 15 (TCP 3+8+4)", len(pkts))
		}
	}

	// ⑤ ntlm_challenge_target_info（11）:Type 2 TargetInfo AV 集（已知+未知扩展项）。
	{
		cfg := map[string]interface{}{
			"target_info": map[string]interface{}{
				"nb_computer_name":  "DC01",
				"nb_domain_name":    "EXAMPLE",
				"dns_computer_name": "dc01.example.test",
				"dns_domain_name":   "example.test",
				"dns_tree_name":     "example.test",
				"target_name":       "cifs/dc01.example.test",
				"av_flags":          2,
				"extra": []interface{}{
					map[string]interface{}{"id": 10, "value_hex": "DEADBEEF"},
				},
			},
			"sessions": []interface{}{
				nSess("s1", map[string]interface{}{"target_name": "EXAMPLE"}, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_challenge_target_info", "Type 2：8-byte ServerChallenge nonzero + TargetInfo AV 序列（已知 1/2/3/4/5/6/7/9 + 扩展 10，EOL 收尾）",
			layersArr, len(pkts),
			[]nfld{
				{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{5, "ntlmssp.challenge.target_name", "EXAMPLE", false, 0, nil, nil},
				{5, "ntlmssp.challenge.target_info.nb_domain_name", "EXAMPLE", false, 0, nil, nil},
				{5, "ntlmssp.challenge.target_info.timestamp", "", true, 0, nil, nil},
				{5, "ntlmssp.challenge.target_info.item.type", "0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0009,0x0007,0x000a,0x0000", false, 0, nil, nil},
			},
			[]nfr{{5, 54, nWirePin(t, pkts, 5)[:256]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_challenge_target_info: %d packets, want 11", len(pkts))
		}
	}

	// ⑥ ntlm_authenticate_security_buffers（11）:Type 3 六类 security buffer +
	// 非空 LM（len=24）+ MaxLen>Len 档。
	{
		cfg := map[string]interface{}{
			"ntlmv2_response": map[string]interface{}{"lm_response_len": 24, "max_len_pad": 8},
			"sessions": []interface{}{
				nSess("s1", map[string]interface{}{"domain": "EXAMPLE", "user": "alice-long-name", "workstation": "WS01"},
					"negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_authenticate_security_buffers", "Type 3：LM/NT/domain/user/workstation/sessionkey 六类 Len/MaxLen/Offset（MaxLen>Len 档，MaxLen=Len+8）",
			layersArr, len(pkts),
			[]nfld{
				{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
				{6, "ntlmssp.auth.username", "alice-long-name", false, 0, nil, nil},
				{6, "ntlmssp.auth.domain", "EXAMPLE", false, 0, nil, nil},
				{6, "ntlmssp.auth.hostname", "WS01", false, 0, nil, nil},
				{6, "ntlmssp.auth.lmresponse", "", true, 0, nil, nil},
				{6, "ntlmssp.auth.ntresponse", "", true, 0, nil, nil},
				{6, "ntlmssp.string.length", "14,30,8", false, 0, nil, nil}, // username UTF-16 15x2
			},
			[]nfr{{6, 54, nWirePin(t, pkts, 6)[:256]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_authenticate_security_buffers: %d packets, want 11", len(pkts))
		}
	}

	// ⑦ ntlm_ntlmv2_blob_av_pairs（11）:blob 结构全可断言面（RV/HRV/TS/CC/AV/EOL）。
	{
		cfg := map[string]interface{}{
			"ntlmv2_response": map[string]interface{}{
				"response_version":    1,
				"hi_response_version": 1,
				"timestamp":           "0100000000000000",
				"client_challenge":    "0203040506070809",
				"av_pairs": []interface{}{
					map[string]interface{}{"id": 7, "value_hex": "0100000000000000"},
					map[string]interface{}{"id": 2, "text": "EXAMPLE"},
				},
			},
			"sessions": []interface{}{
				nSess("s1", nil, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_ntlmv2_blob_av_pairs", "NTLMv2 response：16-byte proof + blob（RV/HRV=1，TS fixture，CC fixture，AV+EOL）",
			layersArr, len(pkts),
			[]nfld{
				{6, "ntlmssp.ntlmv2_response.rversion", "1", false, 0, nil, nil},
				{6, "ntlmssp.ntlmv2_response.hirversion", "1", false, 0, nil, nil},
				{6, "ntlmssp.ntlmv2_response.time", "", true, 0, nil, nil},
				{6, "ntlmssp.ntlmv2_response.chal", "", true, 0, nil, nil},
				{6, "ntlmssp.ntlmv2_response.ntproofstr", "", true, 0, nil, nil},
				{6, "ntlmssp.ntlmv2_response.chal", "", true, 0, nil, nil},
			},
			[]nfr{{6, 54, nWirePin(t, pkts, 6)[:256]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_ntlmv2_blob_av_pairs: %d packets, want 11", len(pkts))
		}
	}

	// ⑧ ntlm_mic_session_key_opaque（11）:MIC 16B + session key 16B 长度/边界面。
	{
		cfg := map[string]interface{}{
			"mic":                          true,
			"encrypted_random_session_key": 16,
			"sessions": []interface{}{
				nSess("s1", nil, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_mic_session_key_opaque", "MIC（16B）/EncryptedRandomSessionKey（16B）长度与 opaque 边界（无密钥不比较值）",
			layersArr, len(pkts),
			[]nfld{
				{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
				{6, "ntlmssp.authenticate.mic", "", true, 0, nil, nil},
				{6, "ntlmssp.auth.sesskey", "", true, 0, nil, nil},
			},
			[]nfr{{6, 54, nWirePin(t, pkts, 6)[:128]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_mic_session_key_opaque: %d packets, want 11", len(pkts))
		}
	}

	// ⑨ ntlm_spnego_outer_separation（11）:outer=spnego，ASN.1 外层/内层分界。
	{
		cfg := map[string]interface{}{
			"outer":    "spnego",
			"sessions": []interface{}{nSess("s1", nil, "negotiate", "challenge", "authenticate", "session_setup_success")},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_spnego_outer_separation", "SPNEGO 外层（GSS InitialContextToken/negTokenResp）与内层 NTLMSSP signature/Type 分界",
			layersArr, len(pkts),
			[]nfld{
				{5, "spnego.supportedMech", "1.3.6.1.4.1.311.2.2.10", false, 0, nil, nil},
				{5, "spnego.negResult", "1", false, 0, nil, nil},
				{6, "spnego.negResult", "0", false, 0, nil, nil},
				{5, "spnego.responseToken", "", true, 0, nil, nil},
				{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
			},
			[]nfr{{4, 54, nWirePin(t, pkts, 4)[:160]}, {5, 54, nWirePin(t, pkts, 5)[:160]}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_spnego_outer_separation: %d packets, want 11", len(pkts))
		}
	}

	// ⑩ ntlm_multi_session_isolation（15）:两会话并行（不同 user/challenge，结果独立）。
	{
		cfg := map[string]interface{}{
			"sessions": []interface{}{
				nSess("s1", map[string]interface{}{"user": "alice"}, "negotiate", "challenge", "authenticate", "session_setup_success"),
				nSess("s2", map[string]interface{}{"user": "bob"}, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_multi_session_isolation", "多会话：独立 ServerChallenge/client challenge/SecurityBuffer/结果（跨 session 无 same_as）",
			layersArr, len(pkts),
			[]nfld{
				{1, "tcp.dstport", "445", false, 0, nil, nil},
				{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{9, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
				{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{9, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{6, "ntlmssp.auth.username", "alice", false, 0, nil, nil},
				{10, "ntlmssp.auth.username", "bob", false, 0, nil, nil},
			},
			[]nfr{{4, 54, nWirePin(t, pkts, 4)}, {8, 54, nWirePin(t, pkts, 8)[:128]}})
		if len(pkts) != 15 {
			t.Fatalf("ntlm_multi_session_isolation: %d packets, want 15 (TCP 3+8+4)", len(pkts))
		}
	}

	// ⑪ ntlm_multi_flow_streams（28）:两会话 + mss 536 多流分段（重组后消息顺序）。
	{
		longUser := strings.Repeat("u", 600) // #13 同款：Type-3 ≈1.4KB > mss 536 → 真分段
		cfg := map[string]interface{}{
			"sessions": []interface{}{
				nSess("s1", map[string]interface{}{"user": longUser}, "negotiate", "challenge", "authenticate", "session_setup_success"),
				nSess("s2", map[string]interface{}{"user": "bob"}, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := []interface{}{nIP(), nTCPMSS(nSport, nPort, 536), nL(cfg)}
		pkts := nPlanChain(t, layersArr)
		add("ntlm_multi_flow_streams", "多 TCP stream/方向 + segmentation：分段后按 stream 重组 token（offset 相对 NTLMSSP 起点）",
			layersArr, len(pkts),
			[]nfld{
				{1, "tcp.dstport", "445", false, 0, nil, nil},
				{4, "tcp.len", "", true, 0, nil, nil},
				// Type-3（alice）跨包 6-8（536+536+380）；dissector 在重组末包 8
				// 才解出字段——先跑后钉，断言钉包 8，包 6 只钉原始分段字节。
				{8, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
				{8, "ntlmssp.auth.username", longUser, false, 0, nil, nil},
			},
			[]nfr{{4, 54, nWirePin(t, pkts, 4)[:64]}, {6, 54, nWirePin(t, pkts, 6)[:256]}})
		if len(pkts) != 17 {
			t.Fatalf("ntlm_multi_flow_streams: %d packets, want 17 (TCP 3+10+4，真分段)", len(pkts))
		}
	}

	// ⑫ ntlm_retry_auth_failure（13）:challenge 重试 + 最终 LOGON_FAILURE。
	{
		cfg := map[string]interface{}{
			"sessions": []interface{}{
				nSess("s1", nil, "negotiate", "challenge", "authenticate", "challenge", "authenticate", "session_setup_failure"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_retry_auth_failure", "challenge 重试（3 轮形态：Type 3 后仍 MORE）+ 最终 STATUS_LOGON_FAILURE（失败后无 authenticated data）",
			layersArr, len(pkts),
			[]nfld{
				{5, "smb2.nt_status", "0xc0000016", false, 0, nil, nil},
				{7, "smb2.nt_status", "0xc0000016", false, 0, nil, nil},
				{9, "smb2.nt_status", "0xc000006d", false, 0, nil, nil},
				{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{7, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
				{4, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
				{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
				{8, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
			},
			[]nfr{{4, 54, nWirePin(t, pkts, 4)}, {9, 54, nWirePin(t, pkts, 9)[:64]}})
		if len(pkts) != 13 {
			t.Fatalf("ntlm_retry_auth_failure: %d packets, want 13 (TCP 3+6+4)", len(pkts))
		}
	}

	// ⑬ ntlm_record_boundary_offsets（15）:长用户名大包 + 空身份会话（Offset+Len
	// 不溢出、完全落在 token 内）。
	{
		longUser := strings.Repeat("u", 600)
		cfg := map[string]interface{}{
			"sessions": []interface{}{
				nSess("s1", map[string]interface{}{"user": longUser}, "negotiate", "challenge", "authenticate", "session_setup_success"),
				nSess("s2", map[string]interface{}{"user": "", "domain": "", "workstation": ""}, "negotiate", "challenge", "authenticate", "session_setup_success"),
			},
		}
		layersArr := nChainSMB(cfg)
		pkts := nPlanChain(t, layersArr)
		add("ntlm_record_boundary_offsets", "最小/最大附近 token：600 字符用户名大包 + 全空身份会话（Offset+Len 不溢出且落在 token 内，UTF-16 偶数长度）",
			layersArr, len(pkts),
			[]nfld{
				{6, "ntlmssp.auth.username", longUser, false, 0, nil, nil},
				{6, "tcp.len", "", true, 0, nil, nil},
				{4, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
				{8, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
			},
			[]nfr{{6, 54, nWirePin(t, pkts, 6)[:256]}})
		if len(pkts) != 15 {
			t.Fatalf("ntlm_record_boundary_offsets: %d packets, want 15 (TCP 3+8+4)", len(pkts))
		}
	}

	// ⑭ ntlm_pcap_nic_consistency（11）:稳定 fixture 双路一致（carrier/方向/端口/
	// token 长度）。
	add("ntlm_pcap_nic_consistency", "PCAP/NIC 一致：TCP profile 端口、方向、stream、NTLMSSP Type 与 token 长度一致（过滤器 tcp port 445）",
		nChainSMB(std4("smb2")), 11,
		[]nfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
			{1, "tcp.flags.syn", "1", false, 0, nil, nil},
			{4, "ntlmssp.messagetype", "0x00000001", false, 0, nil, nil},
			{5, "ntlmssp.messagetype", "0x00000002", false, 0, nil, nil},
			{6, "ntlmssp.messagetype", "0x00000003", false, 0, nil, nil},
			{5, "ntlmssp.ntlmserverchallenge", "", true, 0, nil, nil},
			{4, "tcp.len", "160", false, 0, nil, nil},
		},
		func() []nfr {
			pkts := nPlanChain(t, nChainSMB(std4("smb2")))
			return []nfr{
				{4, 54, nWirePin(t, pkts, 4)},
				{5, 54, nWirePin(t, pkts, 5)[:128]},
				{7, 54, nWirePin(t, pkts, 7)[:64]},
			}
		}())

	// ㉑ ntlm_http_negotiate_v6（T-21，A′ 补例：IPv6×HTTP 格——终审 M2 修轮。
	// #3 的 IPv6 对称形：P-HTTP 明文 TCP/80，401→Type 3→2xx）。
	{
		arr := []interface{}{nIP6(), nTCP(nSport, nHTTPP), nL(map[string]interface{}{
			"profile": "http-negotiate",
			"sessions": []interface{}{
				nSess("s1", nil, "negotiate", "challenge", "authenticate", "http_success"),
			},
		})}
		pkts := nPlanChain(t, arr)
		add("ntlm_http_negotiate_v6", "P-HTTP IPv6 对称：TCP/80 401 Negotiate → Type 1 → Type 2 → Type 3 → 2xx（T-21，地址族×profile 第 4 格）",
			arr, len(pkts),
			[]nfld{
				{1, "tcp.dstport", "80", false, 0, nil, nil},
				{1, "ipv6.nxt", "6", false, 0, nil, nil},
				{5, "http.response.code", "401", false, 0, nil, nil},
				{7, "http.response.code", "200", false, 0, nil, nil},
				{4, "http.request.method", "POST", false, 0, nil, nil},
				{6, "http.request.method", "POST", false, 0, nil, nil},
				{5, "http.www_authenticate", "", true, 0, nil, nil},
				{6, "http.authorization", "", true, 0, nil, nil},
			},
			[]nfr{{4, 74, nWirePin(t, pkts, 4)}})
		if len(pkts) != 11 {
			t.Fatalf("ntlm_http_negotiate_v6: %d packets, want 11 (TCP 3+4+4, #3 IPv6 对称)", len(pkts))
		}
	}

	// ============================================================
	//  负例（6 例）——锚词逐例实测通过才落盘（t.Fatalf 守）
	// ============================================================
	var negatives []nnegCase

	addNeg := func(id, summary string, layersArr []interface{}, anchor string) {
		err := nPlanErr(layersArr)
		if err == nil {
			t.Fatalf("%s: want error containing %q, got nil", id, anchor)
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(anchor)) {
			t.Fatalf("%s: error %q missing anchor %q", id, err, anchor)
		}
		negatives = append(negatives, nnegCase{id: id, summary: summary, layers: layersArr, anchor: anchor})
	}

	addNeg("ntlm_neg_message_truncated", "通用头/三类消息固定字段截断（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "message_length"}), "message")

	addNeg("ntlm_neg_security_buffer", "Len/MaxLen 不一致、非偶数 Unicode、空字段伪造或 token 截断（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "security_buffer"}), "buffer")

	addNeg("ntlm_neg_offsets_overlap_overflow", "Offset+Len 溢出、越界、固定头重叠或字段重叠（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "offset_overflow"}), "offset")

	addNeg("ntlm_neg_flags_target_info", "flags 互不兼容、TargetInfo 缺失/越界、未知 reserved bits（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "flags_target_info"}), "flags")

	addNeg("ntlm_neg_v2_blob_av_pairs", "proof/blob 长度错误、AV_PAIR 越界/缺 EOL/重复非法（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "blob_av_pairs"}), "blob")

	addNeg("ntlm_neg_carrier_profile", "SMB/HTTP 混用、非 TCP 载体、错误端口、SPNEGO 边界错误（wire_fault 注入）",
		nChainSMB(map[string]interface{}{"wire_fault": "carrier_profile"}), "carrier")

	// 自然配置通道补检（同断言、不另落盘）：
	// ① blob 自然负例（no_eol → av）
	if err := nPlanErr(nChainSMB(map[string]interface{}{"ntlmv2_response": map[string]interface{}{"no_eol": true}})); err == nil ||
		!strings.Contains(err.Error(), "av") {
		t.Fatalf("natural no_eol: %v", err)
	}
	// ② udp 载体（transport）
	if err := nPlanErr([]interface{}{nIP(),
		map[string]interface{}{"udp": map[string]interface{}{"src_port": nSport, "dst_port": nPort}},
		nL(map[string]interface{}{})}); err == nil ||
		!strings.Contains(err.Error(), "transport") {
		t.Fatalf("natural udp carrier: %v", err)
	}
	// ③ smb2 档带 http 底座（profile）
	if err := nPlanErr([]interface{}{nIP(), nTCP(nSport, nPort), nHTTP(),
		nL(map[string]interface{}{"profile": "smb2"})}); err == nil ||
		!strings.Contains(err.Error(), "profile") {
		t.Fatalf("natural smb2+http: %v", err)
	}

	// ---- 写入（套件同构扁平数组：spec_json/expect）----
	type outCase struct {
		ID      string                 `json:"id"`
		Proto   string                 `json:"proto"`
		Summary string                 `json:"summary"`
		Spec    map[string]interface{} `json:"spec_json"`
		Expect  map[string]interface{} `json:"expect"`
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
		out = append(out, outCase{ID: pc.id, Proto: "ntlm", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect})
	}
	for _, nc := range negatives {
		out = append(out, outCase{ID: nc.id, Proto: "ntlm", Summary: nc.summary,
			Spec:   map[string]interface{}{"layers": nc.layers},
			Expect: map[string]interface{}{"expect_error": true, "error_contains": nc.anchor}})
	}
	if len(out) != 21 {
		t.Fatalf("want 21 cases (20 ID + T-21 A′ 补例), built %d", len(out))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := "../../../test/protocol_pcap/cases/ntlm.json"
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases (%d pos + %d neg)", len(out), len(positives), len(negatives))
	_ = fmt.Sprint
	_ = nInt
	_ = nBool
}
