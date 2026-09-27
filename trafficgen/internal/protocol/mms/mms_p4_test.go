package mms

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-MMS-2 P4：G-MMS-2 死字段判死 + G-MMS-3 错编码 datatype 判死。
// 两条都是失败测试先行（契约 §7 纪律）：改 validator 前此文件必红。

// G-MMS-2：sequence.loop/stepGap/injectOn 配上不生效（layer_gen.go 零消费）
// ——按契约 §2.3「不许留死配置」判死，锚词点名键名。
func TestValidateRejectsDeadSequenceKeys(t *testing.T) {
	p := Planner{}
	for _, tc := range []struct {
		name string
		seq  *core.MMSSequence
		key  string
	}{
		{"loop", &core.MMSSequence{Steps: []string{"read"}, Loop: 3}, "loop"},
		{"stepGap", &core.MMSSequence{Steps: []string{"read"}, StepGap: 5}, "stepGap"},
		{"injectOn", &core.MMSSequence{Steps: []string{"read"}, InjectOn: 1}, "injectOn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{EnableRead: true, Sequence: tc.seq}})
			if err == nil {
				t.Fatalf("sequence.%s configured but not consumed — want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("err = %v, want anchor %q", err, tc.key)
			}
		})
	}
}

// G-MMS-3：float/binaryTime/structure 走 builder default 分支落 ber(0x80,nil)
// （空数组字节），与声明类型不符——validator 与 builder 必须一致（契约
// §10.5「编码与校验一致，不许一放一错」）。拒收侧锚词 datatype。
func TestValidateRejectsUnsupportedDatatypes(t *testing.T) {
	p := Planner{}
	for _, dt := range []string{"float", "binaryTime", "structure"} {
		t.Run(dt, func(t *testing.T) {
			err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
				EnableRead: true,
				Objects:    []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: dt, Value: 1.5}},
			}})
			if err == nil {
				t.Fatalf("datatype %q is silently mis-encoded by builder — want rejection", dt)
			}
			if !strings.Contains(err.Error(), "datatype") {
				t.Fatalf("err = %v, want anchor \"datatype\"", err)
			}
		})
	}
	// 空 datatype 继续放行（语义未定——契约 §3.5 已声明；本批只关错编码面，
	// 不扩大拒收面）。
	if err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
		EnableRead: true,
		Objects:    []core.MMSObjectConfig{{Domain: "IED1", Name: "x"}},
	}}); err != nil {
		t.Fatalf("empty datatype must stay accepted (empty array encoding), got %v", err)
	}
	// 五个已覆类型仍放行。
	for _, dt := range []string{"boolean", "integer", "unsigned", "octetString", "utcTime", "visibleString"} {
		if err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
			EnableRead: true,
			Objects:    []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: dt}},
		}}); err != nil {
			t.Fatalf("datatype %q must stay accepted: %v", dt, err)
		}
	}
}

// G-MMS-3 根因面（同一 bug 类的第二入口）：multiSession[i] 子会话配置经
// BuildReadRequest(sessions[i]) 走**同一条编码路径**，却从不进 Validate——
// 主配置拒掉的错编码 datatype / 超长名，配在子会话里照旧落线。「编码与校验
// 一致」必须覆盖全部入口，否则修的是症状不是根因。
//
// 契约 §2.2 对 multiSession 的语义是「每项覆盖 objects，继承主配置其余」
// （layer_gen.go:40-45 实证：仅 len(over.Objects)>0 时覆盖，其余键读都不读）
// ——objects 之外任何键都是死配置，按 §2.3 判死并点名。
func TestValidateCoversMultiSessionSubConfigs(t *testing.T) {
	p := Planner{}
	sub := func(o []core.MMSObjectConfig) core.FlowSpec {
		return core.FlowSpec{MMS: &core.MMSConfig{
			EnableRead:   true,
			MultiSession: []core.MMSConfig{{Objects: o}},
		}}
	}
	for _, tc := range []struct {
		name string
		spec core.FlowSpec
		want string
	}{
		{"overlong name", sub([]core.MMSObjectConfig{
			{Domain: "IED2", Name: strings.Repeat("x", 33), Datatype: "boolean"}}), "exceeds 32 bytes"},
		{"mis-encoded datatype", sub([]core.MMSObjectConfig{
			{Domain: "IED2", Name: "x", Datatype: "float", Value: 1.5}}), "datatype"},
		{"overlong domain", sub([]core.MMSObjectConfig{
			{Domain: strings.Repeat("d", 33), Name: "x", Datatype: "boolean"}}), "domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(tc.spec)
			if err == nil {
				t.Fatalf("multiSession[0].objects.%s bypasses validation — want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want anchor %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "multiSession[0]") {
				t.Fatalf("err = %v, want the offending sub-session named", err)
			}
		})
	}
	// 死配置：objects 之外的键（契约 §2.2 语义 = 继承主配置，子会话写它们
	// 读都不读）——逐键判死并点名键名。
	for _, tc := range []struct {
		name string
		sub  core.MMSConfig
		key  string
	}{
		{"sequence", core.MMSConfig{Sequence: &core.MMSSequence{Steps: []string{"read"}}}, "sequence"},
		{"errorClassName", core.MMSConfig{ErrorClassName: "access"}, "errorClassName"},
		{"transport", core.MMSConfig{Transport: "tcp"}, "transport"},
		{"enableRead", core.MMSConfig{EnableRead: true}, "enableRead"},
		{"iedName", core.MMSConfig{IEDName: "X"}, "iedName"},
		{"errorValue", core.MMSConfig{ErrorValue: 3}, "errorValue"},
		{"association", core.MMSConfig{Association: &core.MMSAssociationConfig{NoAssociate: true}}, "association"},
		{"nested multiSession", core.MMSConfig{MultiSession: []core.MMSConfig{{}}}, "multiSession"},
	} {
		t.Run("dead_"+tc.name, func(t *testing.T) {
			err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
				EnableRead:   true,
				MultiSession: []core.MMSConfig{tc.sub},
			}})
			if err == nil {
				t.Fatalf("multiSession[0].%s is never read by the generator — want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("err = %v, want the offending key %q named", err, tc.key)
			}
		})
	}
	// 合法子会话（仅 objects）继续放行；子会话索引在锚词里逐项可辨。
	if err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
		EnableRead:   true,
		MultiSession: []core.MMSConfig{{Objects: []core.MMSObjectConfig{{Domain: "IED2", Name: "MMXU1.TotW.mag.f", Datatype: "integer", Value: 5}}}},
	}}); err != nil {
		t.Fatalf("valid multiSession must stay accepted: %v", err)
	}
	err := p.Validate(core.FlowSpec{MMS: &core.MMSConfig{
		EnableRead:   true,
		MultiSession: []core.MMSConfig{{}, {Objects: []core.MMSObjectConfig{{Domain: "IED3", Name: strings.Repeat("y", 33)}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "multiSession[1]") {
		t.Fatalf("err = %v, want multiSession[1] named (index must be the real one)", err)
	}
}
