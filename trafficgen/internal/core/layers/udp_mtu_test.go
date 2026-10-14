package layers

// D-UDP-MTU：udp 层数据报大小控制（mtu 参数 + 族感知拆包）。
// 设计条目 docs/CODE_DESIGN.md D-UDP-MTU；测试登记 docs/TEST_CASES.md T-UDP-MTU。
// 红例先行（9.7）：T-4/T-5/T-8 在实现前必然失败（当前恒 1 包整载荷直传）。

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// mtuReq 构造独立模式（无事件流）的 GenRequest。
func mtuReq(cfg map[string]interface{}, srcIP string, payload []byte, hbh []core.IPv6Option) *GenRequest {
	return &GenRequest{
		Layer: Layer{Name: "udp", Config: cfg},
		Sess:  &SessionState{},
		Meta:  FlowMeta{FlowID: "f-mtu", SrcIP: srcIP, Payload: payload, HopByHop: hbh},
	}
}

func sizes(packets []core.PacketConfig) []int {
	out := make([]int, len(packets))
	for i := range packets {
		out[i] = len(packets[i].Payload)
	}
	return out
}

func sizesEq(t *testing.T, got []int, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("packet sizes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packet sizes = %v, want %v", got, want)
		}
	}
}

// T-UDP-MTU-2 恰等单包不拆：载荷=chunk（默认 1472）→ 恰 1 包（存量回归守卫）。
func TestUDPMTU_EqualBudgetSinglePacket(t *testing.T) {
	var out []core.PacketConfig
	req := mtuReq(nil, "10.0.0.1", bytes.Repeat([]byte{7}, 1472), nil)
	req.Emit = emitCollector(&out)
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 1 || len(out[0].Payload) != 1472 {
		t.Fatalf("1472B payload = %d packets (first %dB), want 1 packet 1472B", len(out), len(out[0].Payload))
	}
}

// T-UDP-MTU-3 分界 ±1。
func TestUDPMTU_BoundaryPlusMinusOne(t *testing.T) {
	for _, tc := range []struct {
		size int
		want []int
	}{
		{1473, []int{1472, 1}},
		{2944, []int{1472, 1472}},
		{2945, []int{1472, 1472, 1}},
	} {
		var out []core.PacketConfig
		req := mtuReq(nil, "10.0.0.1", bytes.Repeat([]byte{7}, tc.size), nil)
		req.Emit = emitCollector(&out)
		if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
			t.Fatalf("Generate(%dB) error = %v", tc.size, err)
		}
		sizesEq(t, sizes(out), tc.want...)
	}
}

// T-UDP-MTU-4 拆包内容【红例】：3000B → 3 包（1472/1472/56），拼接==原文，
// 全部 up 同端口对（当前实现 1 包 3000B 直传，必红）。
func TestUDPMTU_Split3000(t *testing.T) {
	orig := bytes.Repeat([]byte{0x41}, 3000)
	var out []core.PacketConfig
	req := mtuReq(map[string]interface{}{"src_port": uint16(5000), "dst_port": uint16(9001)}, "10.0.0.1", orig, nil)
	req.Emit = emitCollector(&out)
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	sizesEq(t, sizes(out), 1472, 1472, 56)
	var joined bytes.Buffer
	for i := range out {
		if out[i].Direction != "up" {
			t.Fatalf("packet %d direction = %q, want up", i, out[i].Direction)
		}
		if out[i].L4.SrcPort != 5000 || out[i].L4.DstPort != 9001 {
			t.Fatalf("packet %d ports = %d/%d, want 5000/9001", i, out[i].L4.SrcPort, out[i].L4.DstPort)
		}
		joined.Write(out[i].Payload)
	}
	if !bytes.Equal(joined.Bytes(), orig) {
		t.Fatal("concatenated datagrams != original payload")
	}
}

// T-UDP-MTU-5 response 双向拆 + 换向。
func TestUDPMTU_ResponseSplitsSwapped(t *testing.T) {
	orig := bytes.Repeat([]byte{0x42}, 3000)
	var out []core.PacketConfig
	req := mtuReq(map[string]interface{}{"src_port": uint16(5000), "dst_port": uint16(9001)}, "10.0.0.1", orig, nil)
	req.Emit = emitCollector(&out)
	req.Meta.UDP = &core.UDPConfig{IsResponse: true}
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 6 {
		t.Fatalf("IsResponse 3000B = %d packets, want 6 (3 up + 3 down)", len(out))
	}
	var up, down bytes.Buffer
	for i := range out {
		if i < 3 {
			if out[i].Direction != "up" {
				t.Fatalf("packet %d direction = %q, want up", i, out[i].Direction)
			}
			up.Write(out[i].Payload)
		} else {
			if out[i].Direction != "down" {
				t.Fatalf("packet %d direction = %q, want down", i, out[i].Direction)
			}
			if out[i].L4.SrcPort != 9001 || out[i].L4.DstPort != 5000 {
				t.Fatalf("down packet %d ports = %d/%d, want swapped 9001/5000", i, out[i].L4.SrcPort, out[i].L4.DstPort)
			}
			down.Write(out[i].Payload)
		}
	}
	if !bytes.Equal(up.Bytes(), orig) || !bytes.Equal(down.Bytes(), orig) {
		t.Fatal("up/down concatenation != original payload")
	}
}

// T-UDP-MTU-5 补格：v6×response（9.24 族对称）与显式 mtu=9000×response。
func TestUDPMTU_ResponseMatrixFill(t *testing.T) {
	orig := bytes.Repeat([]byte{0x45}, 3000)
	// v6 载体 response：6 包（3 up + 3 down，chunk=1452），down 换向拼接==原文。
	var out []core.PacketConfig
	req := mtuReq(map[string]interface{}{"src_port": uint16(5000), "dst_port": uint16(9001)}, "2001:db8::1", orig, nil)
	req.Emit = emitCollector(&out)
	req.Meta.UDP = &core.UDPConfig{IsResponse: true}
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("v6 response: Generate() error = %v", err)
	}
	if len(out) != 6 {
		t.Fatalf("v6 response 3000B = %d packets, want 6", len(out))
	}
	sizesEq(t, sizes(out[:3]), 1452, 1452, 96)
	for i := 3; i < 6; i++ {
		if out[i].L4.SrcPort != 9001 || out[i].L4.DstPort != 5000 {
			t.Fatalf("v6 down packet %d ports = %d/%d, want swapped", i, out[i].L4.SrcPort, out[i].L4.DstPort)
		}
	}
	// 显式 mtu=9000×response：2 包（单文件不拆的反面——超 9000 预算仍拆）。
	out = nil
	req = mtuReq(map[string]interface{}{"mtu": uint16(9000), "src_port": uint16(5000), "dst_port": uint16(9001)}, "10.0.0.1", orig, nil)
	req.Emit = emitCollector(&out)
	req.Meta.UDP = &core.UDPConfig{IsResponse: true}
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("9000 response: Generate() error = %v", err)
	}
	// 3000 ≤ 9000−28：request 1 包 + response 1 包 = 2 包。
	if len(out) != 2 || len(out[0].Payload) != 3000 || len(out[1].Payload) != 3000 {
		t.Fatalf("9000x response = %d packets, want 2x3000B", len(out))
	}
}

// T-UDP-MTU-6 空载荷恒 1 包（既有语义回归守卫，off==0 边界）。
func TestUDPMTU_EmptyPayloadSingleDatagram(t *testing.T) {
	var out []core.PacketConfig
	req := mtuReq(nil, "10.0.0.1", nil, nil)
	req.Emit = emitCollector(&out)
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("empty payload = %d packets, want exactly 1", len(out))
	}
}

// T-UDP-MTU-7 显式 mtu（jumbo / 上限 / 下界 / 越上界拆包 / mtu=0 默认）。
func TestUDPMTU_ExplicitMTU(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mtu     interface{}
		size    int
		want    []int
		wantErr string
	}{
		{"jumbo 单包不拆", uint16(9000), 3000, []int{3000}, ""},
		{"上限恰好单包", uint16(65535), 65507, []int{65507}, ""},
		{"越上界拆 2 片（不设总上限）", uint16(65535), 65508, []int{65507, 1}, ""},
		{"下界 chunk=40", uint16(68), 100, []int{40, 40, 20}, ""},
		{"0=默认 1500（u==0 放行惯例）", uint16(0), 3000, []int{1472, 1472, 56}, ""},
		{"低于下界拒绝", uint16(67), 10, nil, "68"},
		{"非标量拒绝", "abc", 10, nil, "mtu"},
	} {
		var out []core.PacketConfig
		cfg := map[string]interface{}{}
		if tc.mtu != nil {
			cfg["mtu"] = tc.mtu
		}
		req := mtuReq(cfg, "10.0.0.1", bytes.Repeat([]byte{7}, tc.size), nil)
		req.Emit = emitCollector(&out)
		err := (&UDPGenerator{}).Generate(context.Background(), req)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: err = %v, want contains %q", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: Generate() error = %v", tc.name, err)
		}
		sizesEq(t, sizes(out), tc.want...)
	}
}

// T-UDP-MTU-8 IPv6 族感知【红例】：v6 载体 chunk=mtu−48（硬编码 28 则每片大 20B 必红）。
func TestUDPMTU_FamilyAwareV6(t *testing.T) {
	orig := bytes.Repeat([]byte{0x43}, 3000)
	var out []core.PacketConfig
	req := mtuReq(nil, "2001:db8::1", orig, nil)
	req.Emit = emitCollector(&out)
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// chunk = 1500 − 40 − 8 = 1452 → 1452/1452/96。
	sizesEq(t, sizes(out), 1452, 1452, 96)
}

// T-UDP-MTU-8b chunk≤0 负例：mtu=68 + v6 + 大 hop-by-hop → 报错（扩展头预算分叉）。
func TestUDPMTU_ChunkBudgetNonPositive(t *testing.T) {
	// 8 字节基本 + 选项 ≥20B → 扩展头 >20 → 68−40−ext−8 < 0。
	bigOpt := core.IPv6Option{Type: 0x1E, Value: bytes.Repeat([]byte{9}, 20)}
	var out []core.PacketConfig
	req := mtuReq(map[string]interface{}{"mtu": uint16(68)}, "2001:db8::1", bytes.Repeat([]byte{7}, 100), []core.IPv6Option{bigOpt})
	req.Emit = emitCollector(&out)
	err := (&UDPGenerator{}).Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "chunk budget") {
		t.Fatalf("chunk budget 68-40-ext-8 <= 0: err = %v, want 'chunk budget' anchor", err)
	}
}

// T-UDP-MTU-15④ 零拷贝：各分片共享原载荷底层数组（SliceData 相等）。
func TestUDPMTU_SlicesShareBackingArray(t *testing.T) {
	orig := bytes.Repeat([]byte{7}, 3000)
	var out []core.PacketConfig
	req := mtuReq(nil, "10.0.0.1", orig, nil)
	req.Emit = emitCollector(&out)
	if err := (&UDPGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for i := range out {
		if &out[i].Payload[0] != &orig[i*1472] {
			t.Fatalf("slice %d does not share backing array at offset %d", i, i*1472)
		}
	}
}

// T-UDP-MTU-1 V9 建策略面：mtu=67 → out of range [68,65535]（complete.go 范围检查）。
func TestUDPMTU_V9RangeReject(t *testing.T) {
	l := Layer{Name: "udp", Config: map[string]interface{}{"mtu": uint16(67)}}
	if err := DefaultRegistry().ValidateLayerConfig(l); err == nil || !strings.Contains(err.Error(), "[68,65535]") {
		t.Fatalf("mtu=67: err = %v, want out-of-range [68,65535]", err)
	}
	// JSON 数值进 V9 是 float64——上界拒绝（T-7 越上界格的 V9 面）以
	// 65536 float64 字面量验证（uint16 字面量装不下 65536，编译期即拒）。
	if err := DefaultRegistry().ValidateLayerConfig(Layer{Name: "udp", Config: map[string]interface{}{"mtu": float64(65536)}}); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("mtu=65536: err = %v, want out-of-range", err)
	}
	l0 := Layer{Name: "udp", Config: map[string]interface{}{"mtu": uint16(0)}}
	if err := DefaultRegistry().ValidateLayerConfig(l0); err != nil {
		t.Fatalf("mtu=0 (use-default convention): err = %v, want nil", err)
	}
}

// 链级接线：ChainPlanner 独立 [ip→udp] 流 3000B → 3 包、PacketIndex 连续。
func TestUDPMTU_ChainPlannerWiring(t *testing.T) {
	p := NewChainPlanner("udp")
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5000, DstPort: 9001,
		Payload: bytes.Repeat([]byte{0x44}, 3000),
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var out []core.PacketConfig
	for pkt := range ch {
		out = append(out, pkt)
	}
	if len(out) != 3 {
		t.Fatalf("chain flow = %d packets, want 3", len(out))
	}
	sizesEq(t, sizes(out), 1472, 1472, 56)
	for i := range out {
		if out[i].PacketIndex != uint64(i) {
			t.Fatalf("PacketIndex = %d at %d", out[i].PacketIndex, i)
		}
	}
}

// T-UDP-MTU-8b MCP 面：Plan 期同步预检——mtu 预算错误带真实锚词，
// 不落 drive 的 0 包掩蔽（14.11 负例锚词）。链必须带用户层配置
// （NewChainPlannerFromChain——mtu/hop_by_hop 住层，spec 直填不算）。
func TestUDPMTU_PlanSyncBudgetError(t *testing.T) {
	chain := []Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2", "hop_by_hop": []interface{}{map[string]interface{}{"type": float64(30), "value": strings.Repeat("09", 100)}}}},
		{Name: "udp", Config: map[string]interface{}{"src_port": uint16(5000), "dst_port": uint16(9001), "mtu": uint16(68)}},
	}
	p := NewChainPlannerFromChain("udp", chain)
	// 生产路径上地址由策略转换提升进 spec（1.1 地址住 ip 层）；此处直填
	// 等价形态，族判定读 spec.SrcIP/DstIP。
	spec := core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 5000, DstPort: 9001}
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan() = nil error, want sync chunk-budget anchor (not 0-packet masking)")
	}
	if !strings.Contains(err.Error(), "chunk budget") {
		t.Fatalf("err = %v, want 'chunk budget' anchor", err)
	}
	if ch != nil {
		t.Fatal("Plan() channel must be nil on sync error")
	}
}
