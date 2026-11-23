package mcp

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestMCPSurfaceProtocolCountAgreement（客户端审查 2026-10-13 问题3 后续）：
// instructions 曾写 125、工具描述写 123，三处硬编码 + 一个测试钉死数字，
// 加协议时必须记得同步改四处——必然漂移。
//
// 现在 instructions 的数字来自 engine 注册表（运行期计算），工具描述不再
// 声称任何数字。本测试守住这两条不变量，而不是某个具体数字：
//  1. instructions 里的 N 必须等于 ListProtocols() − udp（与 rest
//     GetProtocols 的暴露口径一致）；
//  2. 工具描述里不得再出现 "<digits> protocols supported" 这类硬编码声称
//     （否则又会和注册表分叉）。
func TestMCPSurfaceProtocolCountAgreement(t *testing.T) {
	// 一个装了 3 个协议的引擎：tcp/http 计入，udp 按口径剔除 → 2。
	e := newEngineWithProtocols(t, "tcp", "http", "udp")

	got := serverInstructions(e)
	re := regexp.MustCompile(`for (\d+) protocols\.`)
	m := re.FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("instructions missing protocol count: %.80s", got)
	}
	if m[1] != "2" {
		t.Errorf("instructions says %s protocols, want 2 (ListProtocols − udp)", m[1])
	}

	// 加一个协议后数字必须自己跟上去——这是本测试的核心价值。
	e.RegisterPlanner(&stubNamedPlanner{name: "dns"})
	got2 := serverInstructions(e)
	m2 := re.FindStringSubmatch(got2)
	if m2 == nil {
		t.Fatalf("instructions missing protocol count after adding dns: %.80s", got2)
	}
	if m2[1] != "3" {
		t.Errorf("after registering dns instructions says %s protocols, want 3 "+
			"(count is not derived from the live registry)", m2[1])
	}

	// 工具描述不得再硬编码数字。
	hardcoded := regexp.MustCompile(`\d+ protocols supported`)
	for _, typ := range []reflect.Type{
		reflect.TypeOf(generateTrafficInput{}),
		reflect.TypeOf(manageStrategiesInput{}),
	} {
		f, ok := typ.FieldByName("Protocol")
		if !ok {
			t.Fatalf("%s has no Protocol field", typ.Name())
		}
		if tag := f.Tag.Get("jsonschema"); hardcoded.MatchString(tag) {
			t.Errorf("%s.Protocol tag hardcodes a protocol count (%q) — it will drift from the registry; "+
				"point at flowb_query_layers instead", typ.Name(), tag)
		}
	}
}

// stubNamedPlanner is a no-op planner that only contributes a Name (enough for
// engine.ListProtocols).
type stubNamedPlanner struct{ name string }

func (p *stubNamedPlanner) Name() string                 { return p.name }
func (p *stubNamedPlanner) Validate(core.FlowSpec) error { return nil }
func (p *stubNamedPlanner) Plan(context.Context, core.FlowSpec) (<-chan core.PacketConfig, error) {
	ch := make(chan core.PacketConfig)
	close(ch)
	return ch, nil
}

// newEngineWithProtocols builds a bare engine (not started — ListProtocols
// only reads the registration map) with the given planner names registered.
func newEngineWithProtocols(t *testing.T, names ...string) *core.Engine {
	t.Helper()
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	for _, n := range names {
		e.RegisterPlanner(&stubNamedPlanner{name: n})
	}
	return e
}
