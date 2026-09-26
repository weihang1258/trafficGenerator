package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http" // http profile 链的 http 层生成器
	_ "github.com/trafficgen/trafficgen/internal/protocol/ocsp" // init 注册 ocsp 终结层生成器+校验器
)

// D-OCSP-1 P4 链级红例（kerberos_chain_test 同构）：
// ①http-post 基线（POST 1 CertID + successful 响应，9 包）
// ②tcp profile 基线（整 DER 直发，无私有长度前缀）
// ③SHA-1/SHA-256 CertID 算法↔hash 长度绑定（natural certid_hash 负例）
// ④nonce 双层 OCTET STRING（请求/响应 same_as）+ nonce 长度越界负例
// ⑤signed request（requestorName/optionalSignature/certs 结构面）
// ⑥SingleResponse 三态 tag（good[0]/revoked[1]/unknown[2]）+ 时间窗
// ⑦wire_fault 6 值注入锚词 + 未知 fault
// ⑧request_count↔request.certs 批量项冲突（request_response 自然面）
// ⑨profile↔http 层有无不一致（carrier 预检双形）+ 缺 tcp 载体 + 混合地址族
// ⑩严格解码（config 未知键拒）
// ⑪会话 dst_port 冲突守卫
// ⑫node：顶层 ocsp 空子映射 presence 判死（B3 必含①——CheckProtoFlat）
// ⑬白名单外游离键判死负例（1.11-1.13，必含②）。
// ⑭收官自查行：非负例顶层键=0（必含④）。
// 契约 fixture：客户端 192.0.2.62 / 服务端 198.51.100.62 / HTTP 端口 80。

const (
	oCli  = "192.0.2.62"
	oSrv  = "198.51.100.62"
	oCli6 = "2001:db8::62"
	oSrv6 = "2001:db8:ffff::62"
	oPort = 80
	oTCPP = 8080
	oSprt = 42062
)

func ocspJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func ipO(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func tcpO(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func httpO() map[string]interface{} { return map[string]interface{}{"http": map[string]interface{}{}} }
func ocspO(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"ocsp": cfg}
}

// oLayers 构造 HTTP profile 链 [ip,tcp,http,ocsp]（IPv4 默认 80）。
func oLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipO(oCli, oSrv), tcpO(oSprt, oPort), httpO(), ocspO(cfg)}
}

// oLayersTCP 构造裸 TCP 链 [ip,tcp,ocsp]。
func oLayersTCP(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipO(oCli, oSrv), tcpO(oSprt, oTCPP), ocspO(cfg)}
}

func planOCSPAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("ocsp", ocspJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: oCli, DstIP: oSrv, SrcPort: oSprt, DstPort: oPort}
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

func driveO(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planOCSPAt(t, layersArr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveOErr(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := planOCSPAt(t, layersArr)
	return err
}

func oHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

func oSess(transactions ...map[string]interface{}) map[string]interface{} {
	txs := make([]interface{}, len(transactions))
	for i, tx := range transactions {
		txs[i] = tx
	}
	return map[string]interface{}{"id": "s1", "transactions": txs}
}

func oTx(certs ...map[string]interface{}) map[string]interface{} {
	ce := make([]interface{}, len(certs))
	for i, c := range certs {
		ce[i] = c
	}
	m := map[string]interface{}{"id": "t1"}
	if len(ce) > 0 {
		m["request"] = map[string]interface{}{"certs": ce}
	}
	return m
}

func oCert(serial string) map[string]interface{} {
	m := map[string]interface{}{}
	if serial != "" {
		m["serial"] = serial
	}
	return m
}

// 字面量钉（内容权威）：缺省 fixture OCSPRequest / OCSPRequest(SHA-256) 的
// 完整 DER——链级单测逐字节冻结 builder 输出（casegen 的帧钉由同一 builder
// 派生，此处是独立写死的第二通道）。REQ = OCSPRequest{ tbsRequest{
// requestList{ Request{ CertID{ AlgorithmIdentifier{SHA-1,NULL},
// issuerNameHash 20B 0x11*, issuerKeyHash 20B 0x22*, serial 0x10000000 } } } } }
const (
	hexOCSPReqDefault = "304530433041303F303D300906052B0E03021A05000414111111111111111111111111111111111111111104142222222222222222222222222222222222222222020410000000"
	// SHA-256 形：AlgorithmIdentifier 无参数（RFC 8954 §2）+ 32B 双 hash。
	hexOCSPReqSHA256 = "305F305D305B30593057300B06096086480165030402010420111111111111111111111111111111111111111111111111111111111111111104202222222222222222222222222222222222222222222222222222222222222222020410000000"
	// 响应头：OCSPResponse SEQUENCE + responseStatus ENUMERATED successful(0)
	// + responseBytes [0] EXPLICIT + ResponseBytes{ id-pkix-ocsp-basic ，
	// OCTET STRING(BasicOCSPResponse) } + tbsResponseData 头 + responderID
	// byKey [2]——RFC 6960 模块 EXPLICIT TAGS，[2] 显式包 OCTET STRING
	// （a2 16 04 14…；P5 实证 primitive 82 14 会令 tshark 中止解析）。
	hexOCSPRespPrefix = "3081FF0A0100A081F93081F606092B06010505073001010481E83081E5308192A21604143333333333333333333333333333333333333333"
)

// ① http-post 基线：POST 1 CertID + successful。包序 = 3 握手 + POST
// （pkg 4）+ 200 response（pkg 5）+ 4 挥手 = 9。
func TestOCSPChain_HTTPPostBaseline(t *testing.T) {
	pkts := driveO(t, oLayers(map[string]interface{}{
		"sessions": []interface{}{oSess(oTx(oCert("")))},
	}))
	if len(pkts) != 9 {
		t.Fatalf("http-post baseline: got %d packets, want 9", len(pkts))
	}
	req := oHex(t, pkts, 3)
	if !strings.Contains(req, "504F5354") { // "POST"
		t.Fatalf("packet 4 must be HTTP POST, payload=%s...", req[:64])
	}
	if !strings.Contains(req, hexOCSPReqDefault) {
		t.Fatalf("packet 4 must carry the literal default OCSPRequest DER")
	}
	if !strings.Contains(req, "6F6373702D72657175657374") { // "ocsp-request"
		t.Fatalf("packet 4 must carry Content-Type application/ocsp-request")
	}
	resp := oHex(t, pkts, 4)
	if !strings.Contains(resp, hexOCSPRespPrefix) {
		t.Fatalf("packet 5 must carry the literal OCSPResponse prefix (successful + Basic OID)")
	}
	if !strings.Contains(resp, "323030") || !strings.Contains(resp, "6F6373702D726573706F6E7365") { // 200 + "ocsp-response"
		t.Fatalf("packet 5 must be HTTP 200 ocsp-response, payload=%s...", resp[:64])
	}
}

// ② tcp profile 基线：整 DER 直发在 TCP payload，无 HTTP 帧头（0x30 开头），
// 无私有长度前缀（payload 首字节就是 DER SEQUENCE tag）。
func TestOCSPChain_TCPBaseline(t *testing.T) {
	pkts := driveO(t, oLayersTCP(map[string]interface{}{
		"profile":  "tcp",
		"sessions": []interface{}{oSess(oTx(oCert("")))},
	}))
	if len(pkts) != 9 {
		t.Fatalf("tcp baseline: got %d packets, want 9", len(pkts))
	}
	req := oHex(t, pkts, 3)
	if !strings.HasPrefix(req, "30") {
		t.Fatalf("tcp profile request must start with DER SEQUENCE (0x30), got %s", req[:8])
	}
}

// ③ SHA-1 vs SHA-256：算法↔hash 长度绑定（SHA-256 OID + 32B 双 hash）；
// 自然面：sha256 算法 + 20B fixture hash = certid_hash 锚词拒。
func TestOCSPChain_SHA256Binding(t *testing.T) {
	pkts := driveO(t, oLayers(map[string]interface{}{
		"hash_algorithm": "sha256",
		"sessions":       []interface{}{oSess(oTx(oCert("")))},
	}))
	if len(pkts) != 9 {
		t.Fatalf("sha256: got %d packets, want 9", len(pkts))
	}
	req := oHex(t, pkts, 3)
	if !strings.Contains(req, hexOCSPReqSHA256) {
		t.Fatalf("sha256 request must match the literal SHA-256 OCSPRequest DER, payload=%s", req[:128])
	}
	err := driveOErr(t, oLayers(map[string]interface{}{
		"hash_algorithm": "sha256",
		"sessions": []interface{}{oSess(map[string]interface{}{
			"id": "t1",
			"request": map[string]interface{}{"certs": []interface{}{
				map[string]interface{}{
					"serial":           "auto",
					"issuer_name_hash": strings.Repeat("11", 20), // 20B ≠ 32B
				},
			}},
		})},
	}))
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("sha256 + 20B hash must be rejected with hash anchor, got %v", err)
	}
}

// ④ nonce：请求/响应同值（双层 OCTET STRING 逐层长度——req 与 resp payload
// 共享同一 nonce hex）；nonce 长度超界（33B）= nonce 锚词拒。
func TestOCSPChain_Nonce(t *testing.T) {
	pkts := driveO(t, oLayers(map[string]interface{}{
		"nonce":               map[string]interface{}{"enabled": true, "value": strings.Repeat("aa", 16)},
		"response_extensions": true, // 响应侧 responseExtensions [1] 也带 nonce（same_as 面）
		"sessions":            []interface{}{oSess(oTx(oCert("")))},
	}))
	if len(pkts) != 9 {
		t.Fatalf("nonce: got %d packets, want 9", len(pkts))
	}
	req, resp := oHex(t, pkts, 3), oHex(t, pkts, 4)
	if !strings.Contains(req, "2B0601050507300102") { // nonce OID
		t.Fatalf("request must carry nonce OID")
	}
	nonceHex := strings.ToUpper(strings.Repeat("aa", 16))
	if !strings.Contains(req, nonceHex) || !strings.Contains(resp, nonceHex) {
		t.Fatalf("request/response nonce must be same_as (same bytes)")
	}
	err := driveOErr(t, oLayers(map[string]interface{}{
		"nonce":    map[string]interface{}{"enabled": true, "value": strings.Repeat("aa", 33)},
		"sessions": []interface{}{oSess(oTx(oCert("")))},
	}))
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("33B nonce must be rejected with nonce anchor, got %v", err)
	}
}

// ⑤ signed request：requestorName + optionalSignature [0] + signature
// AlgorithmIdentifier；certs=true 内嵌证书 [0]。
func TestOCSPChain_SignedRequest(t *testing.T) {
	pkts := driveO(t, oLayers(map[string]interface{}{
		"signed_request": true,
		"certs":          true,
		"sessions":       []interface{}{oSess(oTx(oCert("")))},
	}))
	if len(pkts) != 9 {
		t.Fatalf("signed: got %d packets, want 9", len(pkts))
	}
	req := oHex(t, pkts, 3)
	// optionalSignature = A0 wrapper 出现在 request DER 内
	if !strings.Contains(req, "A0") {
		t.Fatalf("signed request must carry optionalSignature [0] (A0)")
	}
	err := driveOErr(t, oLayers(map[string]interface{}{
		"signed_request":      true,
		"signature_algorithm": "bogus-alg",
		"sessions":            []interface{}{oSess(oTx(oCert("")))},
	}))
	if err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("bogus signature_algorithm must be rejected with algorithm anchor, got %v", err)
	}
}

// ⑥ 三态 CertStatus tag：good [0]=8000 / revoked [1] IMPLICIT / unknown [2]。
// 同一 requestList 三项批量验证逐项 CertID + 状态 tag 面。
func TestOCSPChain_CertStatusTags(t *testing.T) {
	pkts := driveO(t, oLayers(map[string]interface{}{
		"sessions": []interface{}{oSess(map[string]interface{}{
			"id": "t1",
			"request": map[string]interface{}{"certs": []interface{}{
				map[string]interface{}{"serial": "1", "status": "good"},
				map[string]interface{}{"serial": "2", "status": "revoked"},
				map[string]interface{}{"serial": "3", "status": "unknown"},
			}},
		})},
	}))
	if len(pkts) != 9 {
		t.Fatalf("tristate: got %d packets, want 9", len(pkts))
	}
	resp := oHex(t, pkts, 4)
	if !strings.Contains(resp, "8000") { // good [0] IMPLICIT NULL
		t.Fatalf("response must carry good[0] (8000)")
	}
	if !strings.Contains(resp, "8200") { // unknown [2] IMPLICIT NULL
		t.Fatalf("response must carry unknown[2] (8200)")
	}
	if !strings.Contains(resp, "A1") { // revoked [1] 构造型
		t.Fatalf("response must carry revoked[1] (A1)")
	}
}

// ⑦ 6 wire_fault 注入锚词 + 未知 fault 拒。
func TestOCSPChain_WireFaultAnchors(t *testing.T) {
	anchors := map[string]string{
		"der_truncated":    "der",
		"certid_hash":      "hash",
		"request_response": "match",
		"nonce":            "nonce",
		"signature":        "algorithm",
		"carrier":          "carrier",
	}
	for fault, anchor := range anchors {
		err := driveOErr(t, oLayers(map[string]interface{}{"wire_fault": fault}))
		if err == nil || !strings.Contains(err.Error(), anchor) {
			t.Fatalf("wire_fault=%s must be rejected with anchor %q, got %v", fault, anchor, err)
		}
	}
	if err := driveOErr(t, oLayers(map[string]interface{}{"wire_fault": "bogus"})); err == nil {
		t.Fatal("unknown wire_fault must be rejected")
	}
}

// ⑧ request_count↔request.certs 批量项冲突（自然 request_response 面）。
func TestOCSPChain_RequestCountMismatch(t *testing.T) {
	err := driveOErr(t, oLayers(map[string]interface{}{
		"request_count": 2,
		"sessions": []interface{}{oSess(map[string]interface{}{
			"id": "t1",
			"request": map[string]interface{}{"certs": []interface{}{
				map[string]interface{}{"serial": "1"},
			}},
		})},
	}))
	if err == nil || !strings.Contains(err.Error(), "match") {
		t.Fatalf("request_count 2 vs 1 cert must be rejected with match anchor, got %v", err)
	}
}

// ⑨ profile↔http 层有无不一致：
//   - http profile（http-post）但链无 http 层 → carrier 拒；
//   - tcp profile 但链有 http 层 → carrier 拒；
//   - 裸 ocsp 无 tcp 载体 → carrier 拒；混合地址族 → family 拒。
func TestOCSPChain_CarrierPrecheck(t *testing.T) {
	httpProf := map[string]interface{}{
		"profile":  "http-post",
		"sessions": []interface{}{oSess(oTx(oCert("")))},
	}
	if err := driveOErr(t, oLayersTCP(httpProf)); err == nil ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("http-post without http layer must be rejected (carrier), got %v", driveOErr(t, oLayersTCP(httpProf)))
	}
	tcpProf := map[string]interface{}{
		"profile":  "tcp",
		"sessions": []interface{}{oSess(oTx(oCert("")))},
	}
	if err := driveOErr(t, oLayers(tcpProf)); err == nil ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("tcp profile with http layer must be rejected (carrier), got %v", driveOErr(t, oLayers(tcpProf)))
	}
	if err := driveOErr(t, []interface{}{
		ipO(oCli, oSrv), httpO(), ocspO(map[string]interface{}{
			"sessions": []interface{}{oSess(oTx(oCert("")))},
		}),
	}); err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing tcp carrier must be rejected (carrier), got %v", err)
	}
	if err := driveOErr(t, []interface{}{
		ipO(oCli, oSrv6), tcpO(oSprt, oPort), httpO(), ocspO(map[string]interface{}{
			"sessions": []interface{}{oSess(oTx(oCert("")))},
		}),
	}); err == nil {
		t.Fatal("mixed address family must be rejected")
	}
}

// ⑩ 严格解码：ocsp 层未知键拒（translate 严格往返——未知键在 config 层即拒）。
func TestOCSPChain_StrictDecode(t *testing.T) {
	if err := driveOErr(t, oLayers(map[string]interface{}{
		"bogus_key": 1,
		"sessions":  []interface{}{oSess(oTx(oCert("")))},
	})); err == nil {
		t.Fatal("unknown ocsp layer key must be rejected")
	}
}

// ⑪ 会话 dst_port 冲突守卫（kerberos 同款）。
func TestOCSPChain_SessionPortConflict(t *testing.T) {
	err := driveOErr(t, oLayers(map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"id": "s1", "dst_port": 80,
				"transactions": []interface{}{oTx(oCert(""))},
			},
			map[string]interface{}{
				"id": "s2", "dst_port": 8080,
				"transactions": []interface{}{oTx(oCert(""))},
			},
		},
	}))
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("conflicting session dst_port must be rejected (port), got %v", err)
	}
}

// ⑫ 顶层 ocsp 空子映射与层链并存 = presence 判死（B3 必含①，非残留）：
// CheckProtoFlat 是 schema 层与 mapToFlowSpec 的单一真相（新建/更新 400、
// 存量行 spec.ValidationErrors）。
func TestOCSPChain_PresenceKill(t *testing.T) {
	msg := core.CheckProtoFlat("ocsp", map[string]interface{}{
		"layers": oLayers(map[string]interface{}{}),
		"ocsp":   map[string]interface{}{}, // 空 map 也死（presence 语义）
	})
	if msg == "" {
		t.Fatal("top-level ocsp sub-config alongside layers must be rejected (presence kill)")
	}
	if !strings.Contains(msg, "top-level ocsp sub-config") {
		t.Fatalf("presence kill message must name the top-level key, got %q", msg)
	}
	if core.CheckProtoFlat("ocsp", map[string]interface{}{"layers": oLayers(map[string]interface{}{})}) != "" {
		t.Fatal("layers-only shape must not trigger the presence kill")
	}
}

// ⑬ 白名单外游离顶层键判死（1.11-1.13，B3 必含②）：layers + 顶层 src_mac
// 并存 = 混用配置拒（checkLayerFlatConflict 家族）。
func TestOCSPChain_TopLevelFreeKeyKilled(t *testing.T) {
	_, errs := schema.ValidateStrategy("synth", "ocsp", map[string]any{
		"src_mac": "aa:bb:cc:dd:ee:62",
		"layers": []any{
			map[string]any{"ip": map[string]any{"src": oCli, "dst": oSrv}},
			map[string]any{"tcp": map[string]any{"src_port": oSprt, "dst_port": oPort}},
			map[string]any{"http": map[string]any{}},
			map[string]any{"ocsp": map[string]any{
				"sessions": []any{map[string]any{"id": "s1", "transactions": []any{
					map[string]any{"id": "t1"},
				}}},
			}},
		},
	}, &schema.FlowControl{Type: "flows", Value: 1})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "config mixes layers") {
			found = true
		}
	}
	if !found {
		t.Fatalf("top-level src_mac + layers must be rejected as mixed config (1.11 whitelist), got %v", errs)
	}
}

// 非负例顶层键=0 收官自查行（B3 必含④）：此文件所有正例 spec_json 顶层键
// 仅 layers/flow_control/output 家族——casegen 落盘前由本函数的同款口径复核。
func TestOCSPChain_PositiveTopLevelKeys(t *testing.T) {
	// 直接扫落盘用例（真契约面，而非单例形状）：非负例 spec_json 顶层键
	// 只许 layers/flow_control/output 家族；负例 expect 键集合恰
	// {expect_error, error_contains}（契约 §4 执法口径）。
	allowed := map[string]bool{
		"layers": true, "flow_control": true, "output": true,
		"output_config": true, "strategy_fc": true, "ttl": true,
	}
	b, err := os.ReadFile("../../../test/protocol_pcap/cases/ocsp.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID     string                 `json:"id"`
		Expect map[string]interface{} `json:"expect"`
		Spec   map[string]interface{} `json:"spec_json"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 20 {
		t.Fatalf("ocsp.json must carry 20 semantic cases, got %d", len(cases))
	}
	for _, c := range cases {
		expectError, _ := c.Expect["expect_error"].(bool)
		if expectError {
			for k := range c.Expect {
				if k != "expect_error" && k != "error_contains" && k != "notes" {
					t.Fatalf("%s: negative expect key %q not allowed (only expect_error/error_contains)", c.ID, k)
				}
			}
			if c.Expect["error_contains"] == nil || c.Expect["error_contains"] == "" {
				t.Fatalf("%s: negative case must carry error_contains anchor", c.ID)
			}
			continue
		}
		for k := range c.Spec {
			if !allowed[k] {
				t.Fatalf("%s: positive spec_json top-level key %q not allowed (non-negative top-level keys must be 0)", c.ID, k)
			}
		}
	}
}
