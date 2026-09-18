package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/goose" // init 注册 goose 层生成器 + 校验器
	_ "github.com/trafficgen/trafficgen/internal/protocol/sv"    // sv 同享门回归
)

// D-GOOSE-1 §4 红例①②③（failing 先行，P-PIPE #12 P4）+ ⑤ V9 正交锁。
// 实现前预期：①红（CheckProtoFlat 无 goose presence 分支，放行）；②红
// （registry goose 零 Fields，层内业务键 V9 全拒 unknown field）；③红
// （translate case "goose" 为 no-op → spec.GOOSE 恒 nil → validator
// "goose config is required"）。
//
// ⑥ static-eth 门（④）走 schema.ValidateStrategy（协议推断 goose），
// 不经 layers 包——见 schema 包红例 TestGOOSEChainStaticEthRejected；
// ⑤ 在此包只锁 V9 对显式 eth MAC 放行（与 static 门正交，恒绿）。

func gooseChain(t *testing.T, gooseCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"eth": map[string]interface{}{}},
		map[string]interface{}{"goose": gooseCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-GOOSE-1 §2】：顶层 goose 子映射 presence 判死——空 map 也死
// （srv6/fins 先例）。现状：CheckProtoFlat("goose", ...) 返回空。
func TestGOOSEChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"eth": map[string]interface{}{}},
			map[string]interface{}{"goose": map[string]interface{}{}},
		},
		"goose": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("goose", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(goose, {layers, goose:{}}) = \"\", want top-level goose presence rejection")
	} else if !strings.Contains(msg, "top-level goose sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-GOOSE-1 §1】：goose 层 18 业务键 V9 放行（一律无 Default）。
// 现状：registry goose 零 Fields → 任意键 unknown field。
func TestGOOSEChain_LayerFieldsAccepted(t *testing.T) {
	raw := gooseChain(t, map[string]interface{}{
		"appid":         4096,
		"gocb_ref":      "gcb",
		"dat_set":       "set",
		"go_id":         "gid",
		"tal_ms":        500,
		"conf_rev":      1,
		"start_stnum":   10,
		"start_sqnum":   5,
		"test":          false,
		"nds_com":       false,
		"data":          []interface{}{map[string]interface{}{"name": "pos", "type": "int32", "value": 1234}},
		"event_seq":     []interface{}{map[string]interface{}{"data_idx": 0, "delay_ms": 5, "retransmits": 2}},
		"count":         3,
		"dst_mac":       "01:0c:cd:01:02:03",
		"vlan_enabled":  false,
		"vlan_id":       100,
		"vlan_priority": 4,
	})
	if _, err := layers.ValidateLayers(raw, "goose"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-GOOSE-1 §3】：translate 上线——层 config 进 spec.GOOSE。
// 现状：translateTerminalConfig case "goose" 为 no-op → spec.GOOSE 恒 nil
// → validator "goose config is required"； heartbeat 3 帧不出。
func TestGOOSEChain_LayerTranslateHeartbeat(t *testing.T) {
	p := layers.NewChainPlannerFromChain("goose", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{}},
		{Name: "goose", Config: map[string]interface{}{
			"appid":    4096,
			"gocb_ref": "simpleIOGenericIO/LLN0$GO$gcbAnalogValues",
			"dat_set":  "simpleIOGenericIO/LLN0$AnalogValues",
			"tal_ms":   500,
			"conf_rev": 1,
			"data":     []interface{}{map[string]interface{}{"name": "pos", "type": "int32", "value": 1234}},
			"count":    3,
		}},
	})
	spec := core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	stOK, sqOK := true, true
	wantSQ := uint32(1)
	for pkt := range ch {
		n++
		// stNum 恒 1（heartbeat 无 event_seq）、sqNum 1/2/3 连续。
		st, sq := gooseStSq(t, pkt.Payload)
		if st != 1 {
			stOK = false
		}
		if sq != wantSQ {
			sqOK = false
		}
		wantSQ++
	}
	if n != 3 {
		t.Fatalf("packets=%d want 3 (translate missing? spec.GOOSE nil → validate fail)", n)
	}
	if !stOK {
		t.Fatal("stNum not constant 1 across heartbeat frames")
	}
	if !sqOK {
		t.Fatal("sqNum not 1/2/3 contiguous across heartbeat frames")
	}
}

// gooseStSq 从 GOOSE 帧 payload 解析 stNum/sqNum（APDU 0x85/0x86 最小编码
// 单字节值；heartbeat 小值恒走此形，大值不断——红例只钉小值序列）。
func gooseStSq(t *testing.T, payload []byte) (uint32, uint32) {
	t.Helper()
	var st, sq uint32
	var stOK, sqOK bool
	for i := 0; i+2 < len(payload); i++ {
		if payload[i] == 0x85 && payload[i+1] == 0x01 {
			st, stOK = uint32(payload[i+2]), true
		}
		if payload[i] == 0x86 && payload[i+1] == 0x01 {
			sq, sqOK = uint32(payload[i+2]), true
		}
	}
	if !stOK || !sqOK {
		t.Fatalf("stNum/sqNum tags not found in payload (%d bytes)", len(payload))
	}
	return st, sq
}

// 红例⑤【D-GOOSE-1 §4/12.9】：sv 同享 static-eth 门不回归——sv 空 eth 层
// + 显式标量 MAC 在 V9 不被误杀（static 门本身在 schema.ValidateStrategy，
// 见 schema 包红例 TestGOOSEChainStaticEthRejected；此处只锁 V9 放行，
// 通过即 V9 未误杀 eth 显式标量——与 static 门正交）。
func TestSVChain_StaticEthRejected(t *testing.T) {
	raw, _ := json.Marshal([]interface{}{
		map[string]interface{}{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01"}},
		map[string]interface{}{"sv": map[string]interface{}{}},
	})
	if _, err := layers.ValidateLayers(raw, "sv"); err != nil {
		t.Fatalf("V9 must accept explicit eth MAC (static gate is schema-level): %v", err)
	}
}
