package fins

// 字节级等价证据（T6c 评估结论：fins 翻转前补 EventsMatchLegacyPlan）：
// legacy Planner.Plan 的数据帧（非握手/挥手）与 FINSGenerator 产出的
// MessageEvent 在方向/字节上一致。两侧共享 BuildFrameWithConfig + wrapTCP
// 同一字节源；本测试锁定该不变量，防止任一侧分叉。
//
// 已知文档化分歧（不在本测试断言范围）：
//   - TCP 握手/挥手：legacy 自己 emit 空 payload 包（flags 2/0x12/0x10 +
//     挥手 4 包），chain 路径由 tcp 层生成器拥有——比对仅覆盖数据帧。
//   - 多会话 srcPort=0 默认：legacy 40000+session，generator Meta.SrcPort
//     0→1245 基准——两侧分支不同；测试用显式 SrcPort 规避（翻转后该场景
//     走 generator 1245 基准，与 legacy 40000 不同，需在翻转时知晓）。
import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// collectLegacyData runs the legacy planner and returns the data-frame
// (non-nil payload) sequence as (up, bytes) pairs — handshake/teardown
// packets (nil payload, flags-only) are excluded.
func collectLegacyData(t *testing.T, spec core.FlowSpec, cfg *FINSConfig) [][2]interface{} {
	t.Helper()
	spec = AttachSpec(spec, cfg)
	pcs, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out [][2]interface{}
	for pc := range pcs {
		if pc.Payload == nil {
			continue
		}
		out = append(out, [2]interface{}{pc.Direction == "up", pc.Payload})
	}
	return out
}

// collectGeneratorEvents drives FINSGenerator and returns (up, bytes) pairs.
func collectGeneratorEvents(t *testing.T, cfg *FINSConfig, srcPort uint16) [][2]interface{} {
	t.Helper()
	var events []layers.MessageEvent
	gen := &FINSGenerator{}
	meta := layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: srcPort, DstPort: DefaultPort}
	c2 := *cfg
	meta.FINS = &c2
	req := &layers.GenRequest{
		Meta: meta,
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := make([][2]interface{}, 0, len(events))
	for _, ev := range events {
		out = append(out, [2]interface{}{ev.Up, ev.Bytes})
	}
	return out
}

func assertFINSFramesEqual(t *testing.T, legacy, chain [][2]interface{}, label string) {
	t.Helper()
	if len(legacy) == 0 {
		t.Fatalf("%s: legacy produced no data frames", label)
	}
	if len(legacy) != len(chain) {
		t.Fatalf("%s: frame count legacy=%d chain=%d", label, len(legacy), len(chain))
	}
	for i := range legacy {
		upL, bytesL := legacy[i][0].(bool), legacy[i][1].([]byte)
		upC, ok := chain[i][0].(bool)
		if !ok {
			t.Fatalf("%s: chain[%d] not bool", label, i)
		}
		var bytesC []byte
		switch b := chain[i][1].(type) {
		case []byte:
			bytesC = b
		default:
			t.Fatalf("%s: chain[%d] unexpected type %T", label, i, chain[i][1])
		}
		if upL != upC {
			t.Errorf("%s: frame %d direction legacy(up=%v) chain(up=%v)", label, i, upL, upC)
		}
		if string(bytesL) != string(bytesC) {
			t.Errorf("%s: frame %d bytes differ\n legacy: %x\n chain:  %x", label, i, bytesL, bytesC)
		}
	}
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：udp/tcp 载体、显式 SID、
// SIDAuto 递增、down-only 事件、ExpectResponse=false、多会话（显式 SrcPort
// 规避 0 基准分歧）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	expectTrue := true
	expectFalse := false
	baseSpec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	cases := []struct {
		name string
		cfg  *FINSConfig
	}{
		{"udp default dm read", &FINSConfig{}},
		{"udp explicit sid 7", &FINSConfig{SID: 7}},
		{"udp two commands sid auto", &FINSConfig{
			SIDAuto: true, SIDAutoSet: true,
			Commands: []FINSCommand{
				{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2},
				{Command: CommandMemoryAreaWrite, MemoryArea: "dm", Address: 200, Items: 1, Data: []byte{0x00, 0x2A}},
			},
		}},
		{"udp down-only command", &FINSConfig{
			Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2, Direction: "down"}},
		}},
		{"udp expect_response false", &FINSConfig{
			Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2, ExpectResponse: &expectFalse}},
		}},
		{"tcp two commands", &FINSConfig{
			Transport: "tcp", SID: 3,
			Commands: []FINSCommand{
				{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2},
				{Command: CommandMemoryAreaWrite, MemoryArea: "dm", Address: 200, Items: 1, Data: []byte{0x00, 0x7F}},
			},
		}},
		{"sessions 2", &FINSConfig{
			Sessions: 2, SID: 1, SIDAuto: true, SIDAutoSet: true,
			Commands: []FINSCommand{
				{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2},
				{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 300, Items: 4},
			},
		}},
		{"handshake termination tcp", &FINSConfig{
			Transport: "tcp", Handshake: &expectTrue, Termination: &expectTrue,
			Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 多会话/0 默认分歧规避：legacy spec 显式 SrcPort，generator
			// Meta.SrcPort 同值（sessions>1 时两侧各自 +i 递增，基准一致）。
			legacy := collectLegacyData(t, baseSpec, tc.cfg)
			srcPort := baseSpec.SrcPort
			if srcPort == 0 {
				srcPort = 41000
			}
			// AttachSpec only defaults DstPort; legacy Plan session srcPort
			// derives from spec.SrcPort — feed the same value into the spec.
			spec := AttachSpec(core.FlowSpec{SrcIP: baseSpec.SrcIP, DstIP: baseSpec.DstIP, SrcPort: srcPort}, tc.cfg)
			legacy = collectLegacyData(t, spec, tc.cfg)
			chain := collectGeneratorEvents(t, tc.cfg, srcPort)
			assertFINSFramesEqual(t, legacy, chain, tc.name)
		})
	}
}
