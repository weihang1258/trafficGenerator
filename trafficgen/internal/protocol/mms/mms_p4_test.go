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
