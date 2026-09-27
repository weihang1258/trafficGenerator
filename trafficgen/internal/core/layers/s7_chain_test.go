package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/s7" // init 注册 s7 终结层生成器+校验器
)

// D-S7-85 P4 链级测试（tds_chain_test 同构）：①层条目→Payload 翻译端到端
// （[ip,tcp,s7] 出包，握手 3 + CR/CC 2 + setup 2 + 命令对 2 + 挥手 4 = 13）
// /②presence 并存与顶层游离键判死（CheckProtoFlat s7 分支 + mapToFlowSpec
// ValidationErrors 双面）/③udp 载体拒（tcp-only 形态，complete.go carrier
// 锚词）/④s7 层严格解码（顶层未知键 DisallowUnknownFields）/⑤用例文件收官
// 自查（非负例顶层键=0，presence/游离键负例在案）。

func s7JSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func s7Layers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 102}},
		map[string]interface{}{"s7": cfg},
	}
}

func s7ReadItems() []interface{} {
	return []interface{}{
		map[string]interface{}{"area": 132, "db_number": 1, "address": 0, "transport_size": 4, "length": 1},
	}
}

func s7MinRead() map[string]interface{} {
	return map[string]interface{}{
		"transport": "tcp",
		"commands":  []interface{}{map[string]interface{}{"kind": "read", "items": s7ReadItems()}},
	}
}

func s7Plan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("s7", s7JSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102}
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

// ①层条目→Payload 翻译端到端：最小 read 会话 13 包，首包 SYN。
func TestS7Chain_LayerToPayloadPlan(t *testing.T) {
	pkts, err := s7Plan(t, s7Layers(s7MinRead()))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + CR/CC 2 + setup 2 + read pair 2 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	// CR payload 走 s7 层配置（层链是唯一真相）：payload[5] = COTP CR 0xe0。
	if len(pkts[3].Payload) == 0 || pkts[3].Payload[0] != 0x03 || pkts[3].Payload[5] != 0xe0 {
		t.Fatalf("CR payload = %x", pkts[3].Payload)
	}
	// 缺省 setup-only（显式 commands: []）11 包——presence 语义（nil=注入
	// 默认 read DB1，[]=无业务命令）。
	pkts2, err := s7Plan(t, s7Layers(map[string]interface{}{"transport": "tcp", "commands": []interface{}{}}))
	if err != nil {
		t.Fatalf("setup-only plan: %v", err)
	}
	if len(pkts2) != 11 {
		t.Fatalf("setup-only packets = %d, want 11", len(pkts2))
	}
	// 空层 {} 走缺省 read DB1（P0b-2 缺省流）。
	pkts3, err := s7Plan(t, s7Layers(map[string]interface{}{}))
	if err != nil {
		t.Fatalf("empty-layer plan: %v", err)
	}
	if len(pkts3) != 13 {
		t.Fatalf("empty s7 layer packets = %d, want 13 (default read DB1)", len(pkts3))
	}
}

// ②presence 并存判死 + 顶层游离键判死（CheckProtoFlat 单一真相 = create 400
// 面；mapToFlowSpec 记 ValidationErrors = 存量行启动 error 面）。
func TestS7Chain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	t.Run("top_level_empty_s7_map", func(t *testing.T) {
		if got := core.CheckProtoFlat("s7", map[string]interface{}{"s7": map[string]interface{}{}}); !strings.Contains(got, "no longer accepts a top-level s7") {
			t.Fatalf("presence: %q", got)
		}
		spec := core.MapToFlowSpec(map[string]interface{}{"s7": map[string]interface{}{}}, "s7")
		joined := strings.Join(spec.ValidationErrors, "; ")
		if !strings.Contains(joined, "no longer accepts a top-level s7") {
			t.Fatalf("presence wired: %q", joined)
		}
	})
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"src_ip", "no longer accepts flat config field src_ip"},
		{"dst_ip", "no longer accepts flat config field dst_ip"},
		{"src_port", "no longer accepts flat config field src_port"},
		{"dst_port", "no longer accepts flat config field dst_port"},
		{"count", "no longer accepts flat config field count"},
	} {
		t.Run("flat_"+tc.key, func(t *testing.T) {
			if got := core.CheckProtoFlat("s7", map[string]interface{}{tc.key: "x"}); !strings.Contains(got, tc.want) {
				t.Fatalf("presence %s: %q", tc.key, got)
			}
			// 游离扁平键的 wired 面走 schema create/update 400 与 batch
			// ValidateBatchSpec（同一 CheckProtoFlat 单一真相，sstp 同款
			// 注记）——mapToFlowSpec 只对顶层 s7 子映射记 ValidationErrors。
		})
	}
}

// ③udp 载体拒（s7 DependsOn tcp、零 TransportOn = tcp-only 形态；
// complete.go 专用锚词 "carrier"）。
func TestS7Chain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 102}},
		map[string]interface{}{"s7": s7MinRead()},
	}
	_, err := layers.BuildLayersPlanner("s7", s7JSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,s7]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④s7 层严格解码：顶层未知键（DisallowUnknownFields）与嵌套 commands 未知键
// 都在 Validate 同步拒（此前静默丢弃，配置拼错产出缺省流）。
func TestS7Chain_StrictLayerDecode(t *testing.T) {
	for _, lj := range []string{
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":102}},{"s7":{"transport":"tcp","commands":[{"kind":"read","bogus":1}]}}]`,
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":102}},{"s7":{"transport":"tcp","commands":[{"kind":"read","items":[{"area":132,"length":1,"bogus":1}]}]}}]`,
	} {
		p, err := layers.BuildLayersPlanner("s7", json.RawMessage(lj))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102})
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("strict decode: %v", err)
		}
	}
	// 层 schema 未知字段（V9）走另一条锚词。
	_, err := layers.BuildLayersPlanner("s7", json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":102}},{"s7":{"bogus":1}}]`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("layer schema unknown field: %v", err)
	}
}

// ⑤校验收紧三支（G-S7-2/3/4）：未知 kind / transport_size 越界 / sessions
// 越界——此前三者在生成器里静默放行（假成功）。
func TestS7Chain_TightenedDomains(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{"unknown_kind", map[string]interface{}{"transport": "tcp", "commands": []interface{}{map[string]interface{}{"kind": "reed"}}}, `unknown kind "reed"`},
		{"transport_size", map[string]interface{}{"transport": "tcp", "commands": []interface{}{map[string]interface{}{"kind": "read", "items": []interface{}{map[string]interface{}{"area": 132, "transport_size": 10, "length": 1}}}}}, "invalid transport_size 0x0a"},
		{"sessions_over", map[string]interface{}{"transport": "tcp", "sessions": 17, "commands": []interface{}{}}, "invalid sessions 17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := layers.BuildLayersPlanner("s7", s7JSON(t, s7Layers(tc.cfg)))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			err = p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want anchor %q, got %v", tc.want, err)
			}
		})
	}
}

// ⑥用例文件收官自查：28 例（16 正 + 12 负）；非负例顶层键=0；presence 与
// 游离键负例在案；负例全部带 error_contains 锚词（G-S7-8 闭环）。
func TestS7Chain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/s7.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 28 {
		t.Fatalf("want 28 cases (16 pos + 12 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence, stray, anchors := false, false, 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if !neg {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
				}
			}
			continue
		}
		// 一切负例 expect_error 带错误锚词（D-条目 §13-P2 ③）。
		ec, _ := exp["error_contains"].(string)
		if ec == "" {
			t.Fatalf("%s: negative without error_contains anchor", id)
		}
		anchors++
		if _, hasS7 := sj["s7"]; hasS7 {
			presence = true
		}
		if _, hasFlat := sj["src_ip"]; hasFlat {
			stray = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level s7), found none")
	}
	if !stray {
		t.Fatal("want 1 stray-key negative (layers + top-level src_ip), found none")
	}
	if anchors != 12 {
		t.Fatalf("want 12 anchored negatives, got %d", anchors)
	}
}
