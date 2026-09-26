package ocsp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http" // http 层生成器（http profile 链）
)

// 用例生成器（一次性，D-OCSP-1 P5）：按用例文档 §2 权威序产出 20 例
// （14 正 + 6 负）。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，
// 与套件走同一路径——单权威，无重复编码）；DER 内容权威在链级单测的
// 字面量钉（ocsp_chain_test.go），本文件权威在分帧/序/方向/双 profile。
//
// packet_count 与契约 §2 约定值的偏离（先跑后钉，落 case notes）：
// 约定表按"3 握手 + M 消息 + 3 挥手"估算，实测 tcp 层挥手恒 4 帧（FIN/
// ACK + FIN + ACK + 末 ACK）、HTTP 单事务 = 3+2+4 = 9。mmse 范本同判
// （契约"约定 packet_count（正例）…… 实现期以实际输出校准"）。
//
// 帧内起点（无 TCP options）：IPv4/TCP = 54（14+20+20）、IPv6/TCP = 74。

type ofld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Nonzero  bool
	Distinct []string
	Exclude  []string
}

func (f ofld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if f.Nonzero {
		m["nonzero"] = true
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	return m
}

type ofr struct {
	Packet int
	Offset int
	Hex    string
}

func (f ofr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type oposCase struct {
	id      string
	summary string
	layers  []interface{}
	count   int
	base    int
	fields  []ofld
	frames  []ofr
	notes   []string
}

type onegCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
	notes   []string
}

const (
	oCli   = "192.0.2.62"
	oSrv   = "198.51.100.62"
	oCli6  = "2001:db8::62"
	oSrv6  = "2001:db8:ffff::62"
	oSprt  = 42062
	oSprt2 = 42063
	oPort  = 80
	oTCPPt = 8080
)

// ---- 链构造（与链级红例同形；本文件独立副本以保持 casegen 自洽）----

func ipL(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func tcpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func httpL() map[string]interface{} { return map[string]interface{}{"http": map[string]interface{}{}} }
func ocspL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"ocsp": cfg}
}

// oHTTP 返回 HTTP profile 链 [ip,tcp,http,ocsp]（IPv4）。
func oHTTP(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipL(oCli, oSrv), tcpL(oSprt, oPort), httpL(), ocspL(cfg)}
}

// oHTTP6 返回 IPv6 HTTP profile 链。
func oHTTP6(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipL(oCli6, oSrv6), tcpL(oSprt, oPort), httpL(), ocspL(cfg)}
}

// oRaw 返回裸 TCP profile 链 [ip,tcp,ocsp]（8080）。
func oRaw(cfg map[string]interface{}, mss int) []interface{} {
	tc := map[string]interface{}{"src_port": oSprt, "dst_port": oTCPPt}
	if mss != 0 {
		tc["mss"] = mss
	}
	return []interface{}{ipL(oCli, oSrv), map[string]interface{}{"tcp": tc}, ocspL(cfg)}
}

// ---- 会话/事务构造 ----

func sess(id string, extra map[string]interface{}, txs ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, len(txs))
	for i, tx := range txs {
		arr[i] = tx
	}
	m := map[string]interface{}{"id": id, "transactions": arr}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func tx(id string, extra map[string]interface{}, certs ...map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"id": id}
	if len(certs) > 0 {
		ce := make([]interface{}, len(certs))
		for i, c := range certs {
			ce[i] = c
		}
		m["request"] = map[string]interface{}{"certs": ce}
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func cert(serial string, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"serial": serial}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func oneSession(id string, txs ...map[string]interface{}) map[string]interface{} {
	return sess(id, map[string]interface{}{}, txs...)
}

func cfgWith(sessions ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, len(sessions))
	for i, s := range sessions {
		arr[i] = s
	}
	return map[string]interface{}{"sessions": arr}
}

// planOChain 全链回放（与套件同路径）。
func planOChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("ocsp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: oCli, DstIP: oSrv, SrcPort: oSprt, DstPort: oPort}
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

// wholeFrame 钉某包整段 payload（offset 起）。
func wholeFrame(t *testing.T, pkts []core.PacketConfig, idx, base int) ofr {
	t.Helper()
	if idx > len(pkts) {
		t.Fatalf("frame %d out of range (%d packets)", idx, len(pkts))
	}
	payload := pkts[idx-1].Payload
	if len(payload) == 0 {
		t.Fatalf("frame %d has empty payload", idx)
	}
	return ofr{Packet: idx, Offset: base, Hex: strings.ToUpper(hex.EncodeToString(payload))}
}

// headFrame 钉某包 payload 前 n 字节（长消息只钉稳定头）。
func headFrame(t *testing.T, pkts []core.PacketConfig, idx, base, n int) ofr {
	t.Helper()
	if idx > len(pkts) {
		t.Fatalf("frame %d out of range (%d packets)", idx, len(pkts))
	}
	payload := pkts[idx-1].Payload
	if len(payload) < n {
		n = len(payload)
	}
	return ofr{Packet: idx, Offset: base, Hex: strings.ToUpper(hex.EncodeToString(payload[:n]))}
}

// nonceFor 复算派生 nonce（与 builder 同算法——多会话 distinct 断言用）。
func nonceFor(si, ti int) string {
	b, err := resolveNonce(&core.OCSPNonce{Enabled: true}, si, ti)
	if err != nil {
		panic(err)
	}
	// 小写：tshark 3.6 提取 ocsp.ReOcspNonce 输出小写 hex，distinct 断言
	// 逐字比较不归一化大小写（P5 实测）。
	return hex.EncodeToString(b)
}

// ============================================================
//  20 例生成（14 正 + 6 负）
// ============================================================

func TestGenerateOCSPCases(t *testing.T) {
	var positives []oposCase
	var negatives []onegCase

	add := func(id, summary string, layersArr []interface{}, count int, base int, fields []ofld, frames []ofr, notes ...string) {
		pkts := planOChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, pinned %d", id, len(pkts), count)
		}
		positives = append(positives, oposCase{id: id, summary: summary, layers: layersArr,
			count: count, base: base, fields: fields, frames: frames, notes: notes})
	}

	// ① ocsp_http_ipv4_request_response（约定 8 → 实测 9）：HTTP POST/IPv4、
	// 单 CertID 请求 + successful 响应、Content-Type 双向、DER 外层。
	{
		cfg := cfgWith(oneSession("s1", tx("t1", nil, cert("auto", nil))))
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_http_ipv4_request_response",
			"HTTP POST/IPv4 单查询：DER OCSPRequest/OCSPResponse + content type",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{1, "ip.proto", "6", 0, false, nil, nil},
				{1, "tcp.dstport", "80", 0, false, nil, nil},
				{4, "http.request.method", "POST", 0, false, nil, nil},
				{4, "http.request.uri", "/", 0, false, nil, nil},
				{4, "http.content_type", "application/ocsp-request", 0, false, nil, nil},
				{4, "http.content_length", "", 0, true, nil, nil},
				{4, "ocsp.serialNumber", "10000000", 0, false, nil, nil},
				{5, "http.response.code", "200", 0, false, nil, nil},
				{5, "http.content_type", "application/ocsp-response", 0, false, nil, nil},
				{5, "ocsp.responseStatus", "0", 0, false, nil, nil},
				{5, "ocsp.responseType.id", "1.3.6.1.5.5.7.48.1.1", 0, false, nil, nil},
				{5, "ocsp.responses", "1", 0, false, nil, nil},
				{5, "ocsp.certStatus", "0", 0, false, nil, nil},
			},
			[]ofr{wholeFrame(t, pkts, 4, 54), wholeFrame(t, pkts, 5, 54)},
			"契约 §8 约定 8；实测 9（tcp 层挥手恒 4 帧：3 握手 + 2 消息 + 4 挥手）；requestList 是 dissector 树节点不可过滤，请求面断言走 serialNumber")
	}

	// ② ocsp_http_ipv6_request_response（约定 8 → 实测 9）：独立 IPv6
	// fixture，地址族不继承，起点 74。
	{
		cfg := cfgWith(oneSession("s1", tx("t1", nil, cert("auto", nil))))
		pkts := planOChain(t, oHTTP6(cfg))
		add("ocsp_http_ipv6_request_response",
			"HTTP POST/IPv6 独立 fixture：地址族/外层 DER 与响应",
			oHTTP6(cfg), 9, 74,
			[]ofld{
				{1, "ipv6.nxt", "6", 0, false, nil, nil},
				{1, "tcp.dstport", "80", 0, false, nil, nil},
				{4, "http.request.method", "POST", 0, false, nil, nil},
				{5, "http.response.code", "200", 0, false, nil, nil},
				{5, "ocsp.responseStatus", "0", 0, false, nil, nil},
				{5, "ocsp.responseType.id", "1.3.6.1.5.5.7.48.1.1", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 74, 32), headFrame(t, pkts, 5, 74, 32)},
			"契约 §8 约定 8；实测 9（挥手 4 帧）")
	}

	// ③ ocsp_tcp_record_framing（约定 8 → 实测 10）：裸 TCP 整 DER 直发，
	// 无私有长度前缀；批量 6 项使响应 DER 跨 2 个 TCP segment（mss 536），
	// 父长度重组、TCP 段边界不当 OCSP 字段。
	{
		cfg := map[string]interface{}{
			"profile":       "tcp",
			"request_count": 6,
			"sessions": []interface{}{
				sess("s1", map[string]interface{}{}, tx("t1", nil)),
			},
		}
		pkts := planOChain(t, oRaw(cfg, 536))
		add("ocsp_tcp_record_framing",
			"裸 TCP 整 DER：无私有长度前缀，响应 DER 跨 segment 按父长度重组",
			oRaw(cfg, 536), 10, 54,
			[]ofld{
				{1, "tcp.dstport", "8080", 0, false, nil, nil},
				{1, "tcp.flags.syn", "1", 0, false, nil, nil},
				{4, "tcp.len", fmt.Sprintf("%d", len(pkts[3].Payload)), 0, false, nil, nil},
				{5, "tcp.len", "536", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 16), headFrame(t, pkts, 5, 54, 32), headFrame(t, pkts, 6, 54, 16)},
			"契约 §8 约定 8；实测 10（响应 DER 跨 2 segment）——TCP 段边界不当作 OCSP 字段")
	}

	// ④ ocsp_request_certid_sha1（约定 6 → 实测 9）：SHA-1 AlgorithmIdentifier
	// OID 与双 20B hash、serial 最短 INTEGER。
	{
		cfg := cfgWith(oneSession("s1", tx("t1", nil, cert("auto", nil))))
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_request_certid_sha1",
			"SHA-1 CertID：OID 1.3.14.3.2.26 + 20B issuer hashes + 最短 INTEGER serial",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "x509af.algorithm.id", "1.3.14.3.2.26", 0, false, nil, nil},
				{4, "ocsp.issuerNameHash", strings.Repeat("11", 20), 0, false, nil, nil},
				{4, "ocsp.issuerKeyHash", strings.Repeat("22", 20), 0, false, nil, nil},
				{4, "ocsp.serialNumber", "10000000", 0, false, nil, nil},
				{4, "ocsp.requestList", "1", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 48)},
			"契约 §8 约定 6；实测 9（HTTP 单事务 = 3+2+4）")
	}

	// ⑤ ocsp_request_certid_sha256_rfc8954（约定 6 → 实测 9）：SHA-256 OID
	// 2.16.840.1.101.3.4.2.1 + 双 32B hash（算法↔长度绑定，不误判 SHA-1）。
	{
		cfg := map[string]interface{}{
			"hash_algorithm": "sha256",
			"sessions":       []interface{}{oneSession("s1", tx("t1", nil, cert("auto", nil)))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_request_certid_sha256_rfc8954",
			"RFC 8954 SHA-256 CertID：OID + 32B 双 hash（算法↔长度绑定）",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "x509af.algorithm.id", "2.16.840.1.101.3.4.2.1", 0, false, nil, nil},
				{4, "ocsp.issuerNameHash", strings.Repeat("11", 32), 0, false, nil, nil},
				{4, "ocsp.issuerKeyHash", strings.Repeat("22", 32), 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 48)},
			"契约 §8 约定 6；实测 9")
	}

	// ⑥ ocsp_batch_multi_request（约定 8 → 实测 9）：requestList ≥2 保序、
	// 逐项 response matching（serial 序 = 请求序）。
	{
		cfg := map[string]interface{}{
			"request_count": 3,
			"sessions":      []interface{}{oneSession("s1", tx("t1", nil))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_batch_multi_request",
			"批量 requestList 3 项：线上顺序保留 + 逐项响应匹配",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "ocsp.requestList", "3", 0, false, nil, nil},
				{4, "ocsp.serialNumber", "10000000,10000001,10000002", 0, false, nil, nil},
				{5, "ocsp.responses", "3", 0, false, nil, nil},
				{5, "ocsp.serialNumber", "10000000,10000001,10000002", 0, false, nil, nil},
				{5, "ocsp.certStatus", "0,0,0", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 48), headFrame(t, pkts, 5, 54, 32)},
			"契约 §8 约定 8；实测 9；serial 列表顺序 = 请求序（不去重/不重排）")
	}

	// ⑦ ocsp_nonce_extension（约定 6 → 实测 9）：nonce OID 1.3.6.1.5.5.7.48.1.2、
	// 双层 OCTET STRING、请求/响应 same_as、非零。
	{
		cfg := map[string]interface{}{
			"nonce":               map[string]interface{}{"enabled": true, "opaque": true},
			"response_extensions": true,
			"sessions":            []interface{}{oneSession("s1", tx("t1", nil, cert("auto", nil)))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_nonce_extension",
			"nonce 扩展双层 OCTET STRING：请求/响应同值（same_as）",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "ocsp.requestExtensions", "1", 0, false, nil, nil},
				{4, "ocsp.ReOcspNonce", "", 0, true, nil, nil},
				{5, "ocsp.responseExtensions", "1", 0, false, nil, nil},
				{5, "ocsp.ReOcspNonce", "", 4, true, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 32), headFrame(t, pkts, 5, 54, 32)},
			"契约 §8 约定 6；实测 9；响应 nonce 与请求 same_as_packet（双层长度逐层计算）")
	}

	// ⑧ ocsp_signed_request（约定 8 → 实测 9）：requestorName [1] +
	// optionalSignature [0] + signatureAlgorithm + BIT STRING + certs [0]；
	// version 显式（非规范默认值形）。
	{
		cfg := map[string]interface{}{
			"signed_request": true,
			"certs":          true,
			"version":        2,
			"sessions":       []interface{}{oneSession("s1", tx("t1", nil, cert("auto", nil)))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_signed_request",
			"签名请求：requestorName/optionalSignature/signatureAlgorithm/certs 结构面",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "ocsp.version", "2", 0, false, nil, nil},
				{4, "ocsp.requestorName", "1", 0, false, nil, nil},
				{4, "ocsp.optionalSignature_element", "1", 0, false, nil, nil},
				{4, "ocsp.certs", "1", 0, false, nil, nil},
				{4, "ocsp.signature", strings.Repeat("77", 64), 0, false, nil, nil},
				{5, "ocsp.responseStatus", "0", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 48), headFrame(t, pkts, 5, 54, 32)},
			"契约 §8 约定 8；实测 9；v1 DEFAULT 按 DER §11.5 恒省略，version=2 为显式非默认形；无 key 不宣称验证成功")
	}

	// ⑨ ocsp_basic_response_status（约定 8 → 实测 9）：responseStatus +
	// ResponseBytes + Basic OID + ResponderID byName [1] 形。
	{
		cfg := map[string]interface{}{
			"responder_id": "byname",
			"sessions":     []interface{}{oneSession("s1", tx("t1", nil, cert("auto", nil)))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_basic_response_status",
			"responseStatus successful + ResponseBytes + BasicOCSPResponse（ResponderID byName）",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{5, "ocsp.responseStatus", "0", 0, false, nil, nil},
				{5, "ocsp.responseBytes_element", "1", 0, false, nil, nil},
				{5, "ocsp.responseType.id", "1.3.6.1.5.5.7.48.1.1", 0, false, nil, nil},
				{5, "ocsp.responderID", "1", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 5, 54, 48)},
			"契约 §8 约定 8；实测 9；ResponderID 取 byName [1]（与 byKey [2] 不可互换）")
	}

	// ⑩ ocsp_single_response_statuses（约定 8 → 实测 9）：good[0] /
	// revoked[1]+RevokedInfo / unknown[2] 三态 tag；nextUpdate 可选形。
	{
		cfg := cfgWith(oneSession("s1", tx("t1", nil,
			cert("1", map[string]interface{}{"status": "good"}),
			cert("2", map[string]interface{}{"status": "revoked"}),
			cert("3", map[string]interface{}{"status": "unknown"}),
		)))
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_single_response_statuses",
			"SingleResponse 三态：good[0]/revoked[1]+RevokedInfo/unknown[2] tag 面",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{5, "ocsp.responses", "3", 0, false, nil, nil},
				{5, "ocsp.certStatus", "0,1,2", 0, false, nil, nil},
				{5, "ocsp.revocationTime", "2026-09-20 10:00:00 (UTC)", 0, false, nil, nil},
				{5, "ocsp.revocationReason", "1", 0, false, nil, nil},
				{5, "ocsp.thisUpdate", "2026-09-26 12:00:00 (UTC),2026-09-26 12:00:00 (UTC),2026-09-26 12:00:00 (UTC)", 0, false, nil, nil},
				{5, "ocsp.nextUpdate", "2026-09-27 12:00:00 (UTC),2026-09-27 12:00:00 (UTC),2026-09-27 12:00:00 (UTC)", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 5, 54, 48)},
			"契约 §8 约定 8；实测 9；certStatus 为 IMPLICIT choice tag（非字符串）")
	}

	// ⑪ ocsp_response_signature_extensions（约定 8 → 实测 9）：Basic
	// signatureAlgorithm/signature/certs + ResponseData [1] 与 SingleResponse
	// [1] 扩展槽。
	{
		cfg := map[string]interface{}{
			"nonce":               map[string]interface{}{"enabled": true},
			"certs":               true,
			"response_extensions": true,
			"single_extensions":   true,
			"sessions":            []interface{}{oneSession("s1", tx("t1", nil, cert("auto", nil)))},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_response_signature_extensions",
			"Basic signature/certs + ResponseData[1]/SingleResponse[1] 扩展槽",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{4, "x509af.algorithm.id", "1.3.14.3.2.26", 0, false, nil, nil},
				{5, "ocsp.signature", strings.Repeat("77", 64), 0, false, nil, nil},
				{5, "ocsp.certs", "1", 0, false, nil, nil},
				{5, "ocsp.responseExtensions", "1", 0, false, nil, nil},
				{5, "ocsp.singleExtensions", "1", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 5, 54, 48)},
			"契约 §8 约定 8；实测 9；signature/cert 值 opaque（确定性 fixture），只断言结构/长度")
	}

	// ⑫ ocsp_time_validity_windows（约定 6 → 实测 9）：producedAt/thisUpdate
	// 必需、nextUpdate 可选 [0] EXPLICIT；缺 nextUpdate 形（第二项省略）。
	{
		cfg := cfgWith(oneSession("s1", tx("t1", nil,
			cert("1", nil),
			cert("2", map[string]interface{}{"next_update": "none"}),
		)))
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_time_validity_windows",
			"时间窗：producedAt/thisUpdate 必需 + nextUpdate 可选 [0] EXPLICIT（缺省形）",
			oHTTP(cfg), 9, 54,
			[]ofld{
				{5, "ocsp.producedAt", "2026-09-26 12:00:00 (UTC)", 0, false, nil, nil},
				{5, "ocsp.thisUpdate", "2026-09-26 12:00:00 (UTC),2026-09-26 12:00:00 (UTC)", 0, false, nil, nil},
				{5, "ocsp.nextUpdate", "2026-09-27 12:00:00 (UTC)", 0, false, nil, nil},
				{5, "ocsp.responses", "2", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 5, 54, 48)},
			"契约 §8 约定 6；实测 9；nextUpdate 单值 = 第二项省略该 Optional 字段；nextUpdate 不早于 thisUpdate")
	}

	// ⑬ ocsp_multi_session_stream（约定 16 → 实测 21）：两个 HTTP keep-alive
	// 会话（独立四元组）并行；会话内多事务含 tryLater(3) → HTTP 503 重试
	// 分支；nonce/CertID/响应状态逐会话隔离。
	{
		cfg := map[string]interface{}{
			"nonce": map[string]interface{}{"enabled": true},
			"sessions": []interface{}{
				sess("s1", map[string]interface{}{},
					tx("t1", nil, cert("auto", nil)),
					tx("t2", nil, cert("auto", nil), cert("auto", nil)),
					tx("t3", map[string]interface{}{"expect_status": "try_later"}),
				),
				sess("s2", map[string]interface{}{"src_port": oSprt2},
					tx("t1", nil, cert("auto", nil)),
				),
			},
		}
		pkts := planOChain(t, oHTTP(cfg))
		add("ocsp_multi_session_stream",
			"多会话/keep-alive：两 HTTP 会话交错回放 + tryLater(3)/503 重试分支 + nonce 隔离",
			oHTTP(cfg), 22, 54,
			[]ofld{
				{1, "tcp.srcport", "", 0, false, []string{"42062", "42063"}, []string{"80"}},
				{4, "http.request.method", "POST", 0, false, nil, nil},
				{9, "ocsp.ReOcspNonce", "", 0, false, []string{nonceFor(0, 0), nonceFor(0, 1), nonceFor(0, 2), nonceFor(1, 0)}, nil},
				{9, "http.response.code", "503", 0, false, nil, nil},
				{9, "ocsp.responseStatus", "3", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 24), headFrame(t, pkts, 9, 54, 32)},
			"契约 §8 约定 16；实测 22（s1 = 3+6+4、s2 = 3+2+4；会话数据先于挥手：s1 数据 4-9、s2 会话 10-14、双会话挥手殿后）；会话间 nonce distinct（4 值派生，tshark 小写 hex）；tryLater → HTTP 503 + Retry-After，不静默成功")
	}

	// ⑭ ocsp_pcap_nic_consistency（约定 12 → 实测 18）：明文 HTTP fixture
	// 双会话（POST + RFC 5019 GET base64url）；PCAP 与 NIC 共用同一断言集
	// （方向/端口/HTTP method/DER 外层/Basic OID/status）。
	{
		cfg := cfgWith(
			sess("s1", map[string]interface{}{}, tx("t1", nil, cert("auto", nil))),
			sess("s2", map[string]interface{}{"src_port": oSprt2, "profile": "http-get"},
				tx("t1", nil, cert("auto", nil))),
		)
		pkts := planOChain(t, oHTTP(cfg))
		// GET URI = "/" + base64url(DER)（RFC 5019 无 padding）——由 builder
		// 单权威渲染后取真值（不做第二套编码）。
		getURI := "/" + base64.RawURLEncoding.EncodeToString(renderRequest(mustPlan(t, cfg, 1, 0)))
		add("ocsp_pcap_nic_consistency",
			"PCAP/NIC 一致：POST + RFC 5019 GET base64url（无 padding）双会话 carrier 断言",
			oHTTP(cfg), 18, 54,
			[]ofld{
				{1, "ip.proto", "6", 0, false, nil, nil},
				{1, "tcp.dstport", "80", 0, false, nil, nil},
				{4, "http.request.method", "POST", 0, false, nil, nil},
				{5, "ocsp.responseStatus", "0", 0, false, nil, nil},
				{5, "ocsp.responseType.id", "1.3.6.1.5.5.7.48.1.1", 0, false, nil, nil},
				{9, "http.request.method", "GET", 0, false, nil, nil},
				{9, "http.request.uri", getURI, 0, false, nil, nil},
				{10, "http.response.code", "200", 0, false, nil, nil},
				{10, "ocsp.responseStatus", "0", 0, false, nil, nil},
			},
			[]ofr{headFrame(t, pkts, 4, 54, 32), headFrame(t, pkts, 9, 54, 32), headFrame(t, pkts, 10, 54, 32)},
			"契约 §8 约定 12；实测 18（双会话：s1 数据 4-5、s2 会话 6-10、双会话挥手殿后；GET 会话独立四元组）；GET path 为 base64url 无 padding，URL 字符数不等于 DER 长度；NIC 路径复用同一断言集")
	}

	// ============================================================
	//  负例（6 例）
	// ============================================================

	addNeg := func(id, summary string, layersArr []interface{}, anchor string, notes ...string) {
		negatives = append(negatives, onegCase{id: id, summary: summary, layers: layersArr, anchor: anchor, notes: notes})
	}

	// ⑮ der_truncated：注入通道（生成路径结构上恒自洽，注入是唯一通道）。
	addNeg("ocsp_neg_der_truncated",
		"DER 父/子 TLV 截断（wire_fault 注入）",
		oHTTP(map[string]interface{}{"wire_fault": "der_truncated"}), "der",
		"契约 §7 目标词 der/response/length；主锚词 der")

	// ⑯ certid_hash：自然面——算法↔hash 长度绑定（sha256 需 32B，声明 20B）。
	addNeg("ocsp_neg_certid_hash_length",
		"算法 OID 与 hash 长度不匹配（sha256 + 20B fixture）",
		oHTTP(map[string]interface{}{
			"hash_algorithm": "sha256",
			"sessions": []interface{}{sess("s1", map[string]interface{}{},
				tx("t1", nil, cert("auto", map[string]interface{}{
					"issuer_name_hash": strings.Repeat("11", 20),
				})))},
		}), "hash",
		"契约 §7 目标词 certid/hash/algorithm；自然面守卫（算法↔长度绑定）")

	// ⑰ request_response：自然面——request_count 与 request.certs 批量项数冲突。
	addNeg("ocsp_neg_request_response_mismatch",
		"批量项不匹配（request_count 3 vs request.certs 2 项）",
		oHTTP(map[string]interface{}{
			"request_count": 3,
			"sessions": []interface{}{sess("s1", map[string]interface{}{},
				tx("t1", nil, cert("auto", nil), cert("auto", nil)))},
		}), "match",
		"契约 §7 目标词 match/certid/nonce；自然面守卫（批量项一致性）")

	// ⑱ nonce_extension：自然面——nonce 长度越界（40B > RFC 8954 §4 上限 32B）。
	addNeg("ocsp_neg_nonce_extension",
		"nonce 双层 OCTET STRING 长度越界（40B > 32B 上限）",
		oHTTP(map[string]interface{}{
			"nonce": map[string]interface{}{"enabled": true, "value": strings.Repeat("aa", 40)},
		}), "nonce",
		"契约 §7 目标词 nonce/extension/length；自然面守卫（nonce 长度域）")

	// ⑲ signature：自然面——未知签名算法名（signatureAlgorithm 结构面）。
	addNeg("ocsp_neg_signature",
		"签名算法名未知（signature_algorithm 结构错误）",
		oHTTP(map[string]interface{}{
			"signed_request":      true,
			"signature_algorithm": "md5-with-nonexistent",
		}), "algorithm",
		"契约 §7 目标词 signature/algorithm/responder；自然面守卫（签名算法名域）")

	// ⑳ carrier_profile：validate_layers 预检——http profile 但链上无 http 层。
	addNeg("ocsp_neg_carrier_profile",
		"HTTP profile 与链载体不一致（http-post 但链无 http 层）",
		oRaw(map[string]interface{}{
			"profile":  "http-post",
			"sessions": []interface{}{sess("s1", map[string]interface{}{}, tx("t1", nil))},
		}, 0), "carrier",
		"契约 §7 目标词 carrier/http/tcp/profile；预检通道（profile↔http 层有无一致性）")

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
		if len(pc.notes) > 0 {
			expect["notes"] = pc.notes
		}
		out = append(out, outCase{ID: pc.id, Proto: "ocsp", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect})
	}
	for _, nc := range negatives {
		expect := map[string]interface{}{
			"expect_error":   true,
			"error_contains": nc.anchor,
		}
		if len(nc.notes) > 0 {
			expect["notes"] = nc.notes
		}
		out = append(out, outCase{ID: nc.id, Proto: "ocsp", Summary: nc.summary,
			Spec:   map[string]interface{}{"layers": nc.layers},
			Expect: expect})
	}
	if len(out) != 20 {
		t.Fatalf("want 20 cases, built %d", len(out))
	}
	if len(positives) != 14 || len(negatives) != 6 {
		t.Fatalf("want 14 positive + 6 negative, got %d + %d", len(positives), len(negatives))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := "../../../test/protocol_pcap/cases/ocsp.json"
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases (%d pos + %d neg)", len(out), len(positives), len(negatives))
}

// mustPlan 解析单事务计划（GET URI 复算用——同一 builder 单权威）。
func mustPlan(t *testing.T, cfg map[string]interface{}, si, ti int) *txPlan {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c core.OCSPConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	p, err := resolvePlan(&c, true, &c.Sessions[si], si, ti)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
