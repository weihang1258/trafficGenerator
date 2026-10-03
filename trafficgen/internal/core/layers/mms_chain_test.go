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
	_ "github.com/trafficgen/trafficgen/internal/protocol/mms" // init 注册 mms 终结层生成器+校验器
)

// D-MMS-2 P4 链级红例（smb_chain_test.go 同构）：
// ①空配置基线（关联 7 包：3 握手 + CR/CC + DT1/DT2）/②read 服务对（+2 包 =
// 9）/③CR canonical 字节钉 /④validator 三拒（超长名/非法 datatype/非法
// 步名）/⑤层内未知键同步拒（V9）/⑥carrier 形状（混 udp 拒；缺 tcp 由
// DependsOn 自动补全——smb 同款"缺 tcp 拒"不适用，见注释）/⑦presence 双形状
// （M5 必含①②：顶层空 mms 子映射 + 游离键）/⑧IPv6（同包数 + EtherType
// 0x86DD）/⑨用例文件收官自查（非负例顶层键=0 + 链形 [ip,tcp,mms]）。

const (
	mmsCli   = "192.0.2.88"
	mmsSrv   = "198.51.100.88"
	mmsCli6  = "2001:db8::1"
	mmsSrv6  = "2001:db8::2"
	mmsSport = 40001
)

func mmsLayers(mmsCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mmsCli, "dst": mmsSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mmsSport, "dst_port": 102}},
		map[string]interface{}{"mms": mmsCfg},
	}
}

func mmsJSON(t *testing.T, layersArr []interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func mmsPlan(t *testing.T, layersArr []interface{}, src, dst string, sport, dport uint16) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("mms", mmsJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport}
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

func mmsDrive(t *testing.T, mmsCfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := mmsPlan(t, mmsLayers(mmsCfg), mmsCli, mmsSrv, mmsSport, 102)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func mmsDriveErr(t *testing.T, mmsCfg map[string]interface{}) error {
	t.Helper()
	_, err := mmsPlan(t, mmsLayers(mmsCfg), mmsCli, mmsSrv, mmsSport, 102)
	return err
}

// ① 空配置基线：3 握手 + CR + CC + DT1 + DT2 = 7 包。
func TestMMSChain_BaselineDefault(t *testing.T) {
	pkts := mmsDrive(t, map[string]interface{}{})
	if len(pkts) != 7 {
		t.Fatalf("want 7 packets, got %d", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
}

// ② read 服务对：基线 7 + req/resp 2 = 9 包。
func TestMMSChain_ReadServicePair(t *testing.T) {
	pkts := mmsDrive(t, map[string]interface{}{
		"objects":    []interface{}{map[string]interface{}{"domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": true}},
		"enableRead": true,
		"sequence":   map[string]interface{}{"steps": []interface{}{"read"}},
	})
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
}

// ③ CR canonical：帧 4（包序 3）载荷 = TPKT(20B) CR（cases 帧 4 同值）。
func TestMMSChain_CRCanonical(t *testing.T) {
	pkts := mmsDrive(t, map[string]interface{}{})
	if len(pkts[3].Payload) != 20 {
		t.Fatalf("CR payload len %d, want 20", len(pkts[3].Payload))
	}
	got := strings.ToLower(hex.EncodeToString(pkts[3].Payload))
	want := "030000140fe00000000100c0010cc20101c10102"
	if got != want {
		t.Fatalf("CR = %s, want %s", got, want)
	}
}

// ④ validator 三拒（同步拒，非 ValidationErrors 吞没）。
func TestMMSChain_InvalidValuesReject(t *testing.T) {
	if err := mmsDriveErr(t, map[string]interface{}{
		"objects":    []interface{}{map[string]interface{}{"domain": "IED1", "name": strings.Repeat("x", 33), "datatype": "boolean"}},
		"enableRead": true,
	}); err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
		t.Fatalf("overlong name err = %v", err)
	}
	if err := mmsDriveErr(t, map[string]interface{}{
		"objects":    []interface{}{map[string]interface{}{"domain": "IED1", "name": "x", "datatype": "bogus"}},
		"enableRead": true,
	}); err == nil || !strings.Contains(err.Error(), "datatype") {
		t.Fatalf("bad datatype err = %v", err)
	}
	if err := mmsDriveErr(t, map[string]interface{}{
		"sequence": map[string]interface{}{"steps": []interface{}{"bogus"}},
	}); err == nil || !strings.Contains(err.Error(), "sequence step") {
		t.Fatalf("bad step err = %v", err)
	}
}

// ⑤ 层内未知键同步拒（V9 未知字段面）。
func TestMMSChain_UnknownLayerKeyReject(t *testing.T) {
	_, err := mmsPlan(t, mmsLayers(map[string]interface{}{"bogus_key": 1}), mmsCli, mmsSrv, mmsSport, 102)
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus_key"`) {
		t.Fatalf("bogus_key err = %v", err)
	}
}

// ⑥ carrier 形状：混 udp 拒（complete.go 通用 tcpOnly 门，锚词 carrier）。
// 缺 tcp 不拒——mms DependsOn ["tcp"] 无 TransportOn，[ip,mms] 链经 CompleteChain
// 自动补 tcp（smb"缺 tcp 拒"依赖其预检块；mms 无专属预检块，补全即合法链）。
func TestMMSChain_CarrierShapes(t *testing.T) {
	_, err := layers.BuildLayersPlanner("mms", mmsJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mmsCli, "dst": mmsSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mmsSport, "dst_port": 102}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": mmsSport, "dst_port": 102}},
		map[string]interface{}{"mms": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "udp carrier is not supported") {
		t.Fatalf("udp mix err = %v", err)
	}
}

// ⑦ presence 双形状（M5 清单①②）。
func TestMMSChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": mmsLayers(map[string]interface{}{}),
		"mms":    map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("mms", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(mms, {layers, mms:{}}) = \"\", want presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level mms sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	spec := core.MapToFlowSpec(map[string]interface{}{"mms": map[string]interface{}{}}, "mms")
	joined := strings.Join(spec.ValidationErrors, "; ")
	if !strings.Contains(joined, "rejects a top-level mms") {
		t.Fatalf("presence wired: %q", joined)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("mms", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(mms, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ⑧ IPv6：同包数 + 首包 EtherType 0x86DD + L3 地址。
func TestMMSChain_IPv6Carrier(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mmsCli6, "dst": mmsSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mmsSport, "dst_port": 102}},
		map[string]interface{}{"mms": map[string]interface{}{}},
	}
	pkts, err := mmsPlan(t, arr, mmsCli6, mmsSrv6, mmsSport, 102)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 7 {
		t.Fatalf("want 7 packets, got %d", len(pkts))
	}
	if pkts[0].L2.EtherType != 0x86DD {
		t.Fatalf("ethertype 0x%04x, want 0x86DD", pkts[0].L2.EtherType)
	}
	if pkts[0].L3.SrcIP != mmsCli6 || pkts[0].L3.DstIP != mmsSrv6 {
		t.Fatalf("addrs %s -> %s", pkts[0].L3.SrcIP, pkts[0].L3.DstIP)
	}
}

// ⑨ 用例文件收官自查：19 例（11 正 + 8 负）；非负例顶层键 ⊆ 白名单；
// 非负例链形 = [ip,tcp,mms]；presence 负例在案。
func TestMMSChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/mms.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 19 {
		t.Fatalf("want 19 cases (11 pos + 8 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence := false
	nNeg := 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if neg {
			nNeg++
		} else {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
				}
			}
			lays, _ := sj["layers"].([]interface{})
			if len(lays) != 3 {
				t.Fatalf("%s: want 3 layers [ip,tcp,mms], got %d", id, len(lays))
			}
			for i, want := range []string{"ip", "tcp", "mms"} {
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
		if _, hasMMS := sj["mms"]; hasMMS {
			if !neg {
				t.Fatalf("%s: top-level mms on non-negative case", id)
			}
			presence = true
		}
	}
	if nNeg != 8 {
		t.Fatalf("want 8 negatives, got %d", nNeg)
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level mms), found none")
	}
}
