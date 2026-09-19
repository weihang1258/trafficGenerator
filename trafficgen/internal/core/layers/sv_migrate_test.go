package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/sv" // init 注册 sv 层生成器 + 校验器
)

// D-SV-1 §4 红例①②③④⑤（failing 先行，P-PIPE #13 P4）。
// 实现前预期：①红（CheckProtoFlat 无 sv presence 分支，放行）；②红
// （registry sv 零 Fields，层内业务键 V9 全拒 unknown field）；③红
// （translate case "sv" 为 no-op → spec.SV 恒 nil → validator "sv config
// is required"）；④红（V9 appid 无下界，16383 放行或 unknown field 锚不
// 对）；⑤红（实现前 translate no-op → 锚词不对；转绿后=appid 0 经 V9
// u==0 放行→validator 双界拒的回归锁——P3"只查上界"系假发现，P4 实读
// sv.go:26 纠正）。
//
// static-eth 门（12.9）在 schema.ValidateStrategy，不经 layers 包——
// TestSVChainStaticEthRejected（goose_static_eth_test.go）已绿；V9 对显式
// eth MAC 放行的正交锁已在 goose_migrate_test.go TestSVChain_StaticEthRejected。

func svChain(t *testing.T, svCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"eth": map[string]interface{}{}},
		map[string]interface{}{"sv": svCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-SV-1 §2】：顶层 sv 子映射 presence 判死——空 map 也死
// （goose/srv6/fins 先例）。现状：CheckProtoFlat("sv", ...) 返回空。
func TestSVChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"eth": map[string]interface{}{}},
			map[string]interface{}{"sv": map[string]interface{}{}},
		},
		"sv": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("sv", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(sv, {layers, sv:{}}) = \"\", want top-level sv presence rejection")
	} else if !strings.Contains(msg, "top-level sv sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-SV-1 §1】：sv 层 15 业务键 V9 放行（一律无 Default；appid 取
// 下边界 16384=0x4000 顺带钉 V9 Min 语义）。
// 现状：registry sv 零 Fields → 任意键 unknown field。
func TestSVChain_LayerFieldsAccepted(t *testing.T) {
	raw := svChain(t, map[string]interface{}{
		"sv_id":             "xxxxMUnn01",
		"dat_set":           "xxxxMUnn01/dataset",
		"appid":             16384,
		"conf_rev":          1,
		"samples_per_cycle": 4000,
		"smp_synch":         2,
		"smp_rate":          4000,
		"period_us":         250,
		"data":              []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100, "quality": 0}},
		"count":             3,
		"dst_mac":           "01:0c:cd:04:00:01",
		"double_send":       false,
		"vlan_enabled":      false,
		"vlan_id":           100,
		"vlan_priority":     4,
	})
	if _, err := layers.ValidateLayers(raw, "sv"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-SV-1 §3】：translate 上线——层 config 进 spec.SV，smpCnt
// 0/1/2 序列出包。现状：translateTerminalConfig case "sv" 为 no-op →
// spec.SV 恒 nil → validator "sv config is required"。
func TestSVChain_LayerTranslateSmpSeq(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sv", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{}},
		{Name: "sv", Config: map[string]interface{}{
			"sv_id":             "xxxxMUnn01",
			"appid":             16384,
			"conf_rev":          1,
			"samples_per_cycle": 80,
			"data":              []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100}},
			"count":             3,
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
	want := uint16(0)
	smpOK := true
	for pkt := range ch {
		n++
		if got := svSmpCnt(t, pkt.Payload); got != want {
			smpOK = false
		}
		want++
	}
	if n != 3 {
		t.Fatalf("packets=%d want 3 (translate missing? spec.SV nil → validate fail)", n)
	}
	if !smpOK {
		t.Fatal("smpCnt not 0/1/2 sequential across frames")
	}
}

// svSmpCnt 从 SV 帧 payload 解析 smpCnt（APDU tag 0x82 两字节 BE；红例
// 小值恒最小编码，svID ASCII 无 0x82 前缀碰撞——扫描口径同 gooseStSq）。
func svSmpCnt(t *testing.T, payload []byte) uint16 {
	t.Helper()
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == 0x82 && payload[i+1] == 0x02 {
			return uint16(payload[i+2])<<8 | uint16(payload[i+3])
		}
	}
	t.Fatalf("smpCnt tag 0x82 not found in payload (%d bytes)", len(payload))
	return 0
}

// 红例④【D-SV-1 ② 终审】：appid 下界 V9 create-time 执法——16383
// (0x3fff) 拒，锚词 V9 真实门。现状：registry 无 Fields → unknown field
// （锚不对=红）。
func TestSVChain_AppidBelowRangeRejected(t *testing.T) {
	raw := svChain(t, map[string]interface{}{
		"sv_id":             "xxxxMUnn01",
		"appid":             16383,
		"conf_rev":          1,
		"samples_per_cycle": 80,
		"data":              []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100}},
	})
	_, err := layers.ValidateLayers(raw, "sv")
	if err == nil {
		t.Fatal("appid 16383 (0x3fff) below SV range 0x4000-0x7fff must be rejected at V9")
	}
	if !strings.Contains(err.Error(), "out of range [16384,32767]") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// 红例⑤【D-SV-1 依赖链 ⑤】：appid 显式 0 经 V9 u==0 放行（complete.go
// :315）→ validator 双界拒（sv.go:26 `< 0x4000 || > 0x7fff` 既有）。
// 现状（实现前）：translate no-op → "sv config is required"≠锚词=红；
// 转绿后此例恒绿=双界执法回归锁（P3"只查上界"系假发现，P4 实读纠正）。
func TestSVChain_AppidZeroRejected(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sv", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{}},
		{Name: "sv", Config: map[string]interface{}{
			"sv_id":             "xxxxMUnn01",
			"appid":             0,
			"conf_rev":          1,
			"samples_per_cycle": 80,
			"data":              []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100}},
		}},
	})
	spec := core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01"}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("explicit appid 0 must be rejected (V9 u==0 pass-through reaches validator dual-bound check sv.go:26)")
	}
	if !strings.Contains(err.Error(), "sv appid 0x0000 outside SV range 0x4000-0x7fff") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}
