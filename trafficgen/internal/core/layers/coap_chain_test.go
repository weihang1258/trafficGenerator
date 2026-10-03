package layers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/coap" // init 注册 coap 终结层生成器+校验器
)

// D-COAP-1 P4 链级红例（bgp_chain_test 同构）。覆盖：
//  ① G-COAP-1①：层内业务键翻译生效（translate case 之前层 config 到不了
//    spec.CoAP → 生成器回退默认 GET/不响应，只发 1 包 4 字节头）；
//  ② presence 负例形状（M5 清单①）：层链 + 顶层空 coap 子映射并存判死；
//  ③ 白名单外游离键判死（M5 清单②，1.11–1.13：五键 + schema 语义门 src_mac）；
//  ④ 载体拒绝：coap 只坐 udp（无 TransportOn → 补全插入 udp 后 transport 重复）；
//  ⑤ 单层 [coap] 链补全补 ip/udp（契约 §13-P2「缺 ip」面：补全供给非报错）；
//  ⑥ 用例文件收官自查（非负例顶层键=0；19 例 = 12 正 + 7 负）。

const (
	cCli   = "10.0.0.1"
	cSrv   = "20.0.0.1"
	cSport = 56565
	cDport = 5683
)

func coapLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": cCli, "dst": cSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": cSport, "dst_port": cDport}},
		map[string]interface{}{"coap": cfg},
	}
}

// coapGetCfg 是契约样例请求（design §13.1 目标形状）：CON GET /sensors/temp，
// Token 01020304（base64 AQIDBA==）、MID 4097、ACK 2.05 带 JSON 负载。
func coapGetCfg() map[string]interface{} {
	return map[string]interface{}{
		"method": "GET", "path": []interface{}{"sensors", "temp"},
		"confirmable": true, "token": "AQIDBA==", "message_id": 4097,
		"response_code": "2.05", "response_payload": "eyJ2YWx1ZSI6MjMuNX0=",
		"response_content_format": 50,
	}
}

func planCoAP(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("coap", raw)
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: cCli, DstIP: cSrv, SrcPort: cSport}
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

// ① 层内业务键翻译端到端：请求 + 默认响应两事件。缺 translate case 时
// spec.CoAP 恒 nil → 生成器默认化（GET + Response:false）→ 只 1 包且固定
// 头为 50 01 00 00（NON / MID 0）——断言 MID/Token/响应三面即钉死翻译。
func TestCoAPChain_LayerConfigTranslated(t *testing.T) {
	pkts, err := planCoAP(t, coapLayers(coapGetCfg()))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2 (request + ACK response)", len(pkts))
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions = %q, %q; want up, down", pkts[0].Direction, pkts[1].Direction)
	}
	// 请求固定头 44 01 10 01（Ver=1 CON TKL=4 / Code=1 GET / MID=0x1001）+ Token。
	wantReq := []byte{0x44, 0x01, 0x10, 0x01, 0x01, 0x02, 0x03, 0x04}
	if !bytes.HasPrefix(pkts[0].Payload, wantReq) {
		t.Fatalf("request payload = % x, want prefix % x", pkts[0].Payload, wantReq)
	}
	// 路径选项逐字节（builder 单测同款期望）：固定头+Token 之后恰为选项。
	wantOpts := append([]byte{0xB7}, append([]byte("sensors"), append([]byte{0x04}, []byte("temp")...)...)...)
	if !bytes.Equal(pkts[0].Payload[8:], wantOpts) {
		t.Fatalf("request options = % x, want % x", pkts[0].Payload[8:], wantOpts)
	}
	// 响应固定头 64 45 10 01（ACK / 2.05 / MID 回显）+ Token 回显。
	wantResp := []byte{0x64, 0x45, 0x10, 0x01, 0x01, 0x02, 0x03, 0x04}
	if !bytes.HasPrefix(pkts[1].Payload, wantResp) {
		t.Fatalf("response payload = % x, want prefix % x", pkts[1].Payload, wantResp)
	}
	if pkts[0].L4.DstPort != cDport || pkts[1].L4.DstPort != cSport {
		t.Fatalf("ports up=%d down=%d, want %d/%d", pkts[0].L4.DstPort, pkts[1].L4.DstPort, cDport, cSport)
	}
}

// ①b response 三态：显式 response:false 抑制响应（1 包），缺键保默认响应
// （2 包）——completedConfig 的 schema 默认 false 经 JSON 往返会变非 nil
// 指针而吞掉默认响应，本断言钉死该陷阱（Accept=0 同族，见翻译块注释）。
func TestCoAPChain_ResponseTriState(t *testing.T) {
	cfg := coapGetCfg()
	cfg["response"] = false
	pkts, err := planCoAP(t, coapLayers(cfg))
	if err != nil {
		t.Fatalf("Plan(response:false): %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("response:false got %d packets, want 1", len(pkts))
	}
	cfg = coapGetCfg()
	delete(cfg, "response")
	pkts, err = planCoAP(t, coapLayers(cfg))
	if err != nil {
		t.Fatalf("Plan(response absent): %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("response absent got %d packets, want 2 (default response)", len(pkts))
	}
}

// ② presence 与顶层游离键判死。
func TestCoAPChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": coapLayers(coapGetCfg()),
		"coap":   map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("coap", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(coap, {layers, coap:{}}) = \"\", want top-level coap presence rejection")
	}
	if !strings.Contains(msg, "rejects a top-level coap sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		m := core.CheckProtoFlat("coap", bad)
		if m == "" {
			t.Fatalf("CheckProtoFlat(coap, {layers, %s}) = \"\", want flat-field rejection", k)
		}
		if !strings.Contains(m, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, m)
		}
	}
	// MAC 类走 schema 语义门（checkLayerFlatConflict 六键）。
	_, errs := schema.ValidateStrategy("synth", "coap", map[string]any{
		"layers":  coapLayers(coapGetCfg()),
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

// ③ 载体拒：coap 仅 udp（registry 无 TransportOn）。实测文案
// `layers: transport layer duplicated (2 transport layers: tcp, udp)`
// （补全为 [ip,tcp,udp,coap]）——用例锚词 "tcp" 两面同命中。
func TestCoAPChain_TCPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": cCli, "dst": cSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": cSport, "dst_port": cDport}},
		map[string]interface{}{"coap": coapGetCfg()},
	}
	raw, _ := json.Marshal(arr)
	_, err := layers.BuildLayersPlanner("coap", raw)
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,tcp,coap]) = nil, want carrier/transport rejection")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("carrier error = %q, want anchor \"tcp\"", err.Error())
	}
}

// ④ 单层 [coap] 链：DependsOn 补全供给 ip/udp（契约 §13-P2「缺 ip」面），
// 层 config 经 completeChainPreservingConfig 保留 → 翻译仍生效。
func TestCoAPChain_SingleLayerCompletedWithIPTail(t *testing.T) {
	pkts, err := planCoAP(t, []interface{}{map[string]interface{}{"coap": coapGetCfg()}})
	if err != nil {
		t.Fatalf("Plan(single layer): %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2", len(pkts))
	}
	if !bytes.HasPrefix(pkts[0].Payload, []byte{0x44, 0x01, 0x10, 0x01}) {
		t.Fatalf("payload = % x, want MID 0x1001 header", pkts[0].Payload)
	}
	if pkts[0].L4.DstPort != cDport {
		t.Fatalf("dst port %d, want %d (validateSpecBase 5683 缺省)", pkts[0].L4.DstPort, cDport)
	}
}

// ④b 空层 {} 走 P0b-2 缺省流（GET + 不响应 = 1 包）。本断言钉死"只搬用户
// 显式键"的必要性：若经 completedConfig，schema 零值 method:"" 会落 config
// 压掉生成器默认（BuildMessage code=0 → "code is invalid" 任务失败），
// response:false 会变非 nil 指针压掉默认自动响应（探测实证）。
func TestCoAPChain_EmptyLayerDefaultFlow(t *testing.T) {
	pkts, err := planCoAP(t, coapLayers(map[string]interface{}{}))
	if err != nil {
		t.Fatalf("Plan(empty layer): %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("empty layer got %d packets, want 1 (GET, no auto-response)", len(pkts))
	}
	// 默认化 = GET + Response:false → NON(1) / Code=1 / MID=0 → 50 01 00 00。
	if !bytes.HasPrefix(pkts[0].Payload, []byte{0x50, 0x01, 0x00, 0x00}) {
		t.Fatalf("payload = % x, want 50 01 00 00 (NON GET default)", pkts[0].Payload)
	}
}

// ⑤ 用例文件收官自查：19 例（12 正 + 7 负）；非负例顶层键 ⊆ {layers,
// flow_control, group_id}；非负例链形恒 [ip,udp,coap]；presence/游离键/
// 载体三红例在案；负例 expect 恰两键且带锚词。
func TestCoAPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/coap.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 19 {
		t.Fatalf("want 19 cases (12 pos + 7 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "group_id": true}
	presence, neg := false, 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		isNeg := exp != nil && exp["expect_error"] == true
		if isNeg {
			neg++
			if set := sortedKeys(exp); len(set) != 2 || set[0] != "error_contains" || set[1] != "expect_error" {
				t.Fatalf("%s: negative expect keys = %v, want {expect_error, error_contains}", id, set)
			}
			if s, _ := exp["error_contains"].(string); s == "" {
				t.Fatalf("%s: negative case without error_contains", id)
			}
		} else {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/group_id)", id, k)
				}
			}
			lays, _ := sj["layers"].([]interface{})
			if len(lays) != 3 {
				t.Fatalf("%s: want 3 layers [ip,udp,coap], got %d", id, len(lays))
			}
			for i, want := range []string{"ip", "udp", "coap"} {
				m, _ := lays[i].(map[string]interface{})
				if m == nil || len(m) != 1 {
					t.Fatalf("%s: layer %d shape", id, i)
				}
				for k := range m {
					if k != want {
						t.Fatalf("%s: layer %d = %q, want %q", id, i, k, want)
					}
				}
			}
		}
		if _, hasTop := sj["coap"]; hasTop {
			if !isNeg {
				t.Fatalf("%s: top-level coap on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level coap), found none")
	}
	if neg != 7 {
		t.Fatalf("want 7 negatives (4 validate + presence/stray/carrier), got %d", neg)
	}
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
