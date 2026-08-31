package geneve

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GENEVE 终结层生成器测试（B4 封装类）——事件模式（vxlan 同款）：
// 每数据报 1 事件，Bytes = 8-byte 基础头 + options + 内层 Ethernet 帧；
// 方向与事件级端口覆盖由事件携带，UDP 语义交给 udp 层生成器。

// collectEvents drives the generator and collects emitted events.
func collectEvents(t *testing.T, cfg *core.GeneveConfig) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Geneve: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := (&GeneveGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return events
}

// fixture returns a valid inner Ethernet fixture for generator tests.
func fixture() *core.EncapEthernetFixture {
	return &core.EncapEthernetFixture{
		SrcMAC:    "02:aa:00:00:12:01",
		DstMAC:    "02:bb:00:00:12:01",
		EtherType: "ipv4",
		SrcIP:     "10.20.1.1",
		DstIP:     "10.20.1.2",
		Payload:   []byte("geneve-inner-01"),
	}
}

// TestHeaderBytes pins the 8-byte GENEVE base header layout (RFC 8926 §3):
// byte0 = Ver<<6 | OptLen, byte1 = OAM(0x80)/Critical(0x40)/reserved-zero,
// Protocol Type 0x6558 BE, 24-bit BE VNI, trailing reserved zero. Version
// encoding is pinned directly (version!=0 is rejected by the validator before
// generation, but the shift semantics must stay correct).
func TestHeaderBytes(t *testing.T) {
	cases := []struct {
		name     string
		vni      uint32
		version  uint8
		oam      bool
		critical bool
		optLen   int
		want     []byte
	}{
		{"vni5000_noopts", 5000, 0, false, false, 0, []byte{0x00, 0x00, 0x65, 0x58, 0x00, 0x13, 0x88, 0x00}},
		{"vni0", 0, 0, false, false, 0, []byte{0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 0x00, 0x00}},
		{"vnimax", 0xffffff, 0, false, false, 0, []byte{0x00, 0x00, 0x65, 0x58, 0xff, 0xff, 0xff, 0x00}},
		{"optlen3", 1, 0, false, false, 3, []byte{0x03, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01, 0x00}},
		{"oam", 1, 0, true, false, 0, []byte{0x00, 0x80, 0x65, 0x58, 0x00, 0x00, 0x01, 0x00}},
		{"critical", 1, 0, false, true, 0, []byte{0x00, 0x40, 0x65, 0x58, 0x00, 0x00, 0x01, 0x00}},
		{"oam_critical", 2, 0, true, true, 0, []byte{0x00, 0xc0, 0x65, 0x58, 0x00, 0x00, 0x02, 0x00}},
		{"version1_shift", 2, 1, false, false, 0, []byte{0x40, 0x00, 0x65, 0x58, 0x00, 0x00, 0x02, 0x00}},
	}
	for _, c := range cases {
		got := buildGeneveHeader(c.vni, c.version, c.oam, c.critical, c.optLen)
		if len(got) != 8 {
			t.Errorf("%s: header len %d, want 8", c.name, len(got))
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("%s: byte %d = %#02x, want %#02x (full: % x)", c.name, i, got[i], c.want[i], got)
				break
			}
		}
	}
}

// TestOptionsBytes pins the option chain encoding (RFC 8926 §3.4): 4-byte
// header = Class(2, BE) + Type(1) + Rsvd(3)<<5 | Length(5, 4-byte units),
// data in config order, zero-length option legal (Length=0).
func TestOptionsBytes(t *testing.T) {
	// 空 options → 零字节。
	b, err := buildOptions(nil)
	if err != nil || len(b) != 0 {
		t.Fatalf("nil options: %v len=%d", err, len(b))
	}

	// 单 option：class 0x0101 type 0x02 data 4B → header 01 01 02 01。
	b, err = buildOptions([]core.GeneveOption{
		{Class: 0x0101, Type: 0x02, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
	})
	if err != nil {
		t.Fatalf("single option: %v", err)
	}
	want := []byte{0x01, 0x01, 0x02, 0x01, 0xde, 0xad, 0xbe, 0xef}
	if len(b) != len(want) {
		t.Fatalf("single option len %d, want %d (% x)", len(b), len(want), b)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Errorf("single option byte %d = %#02x, want %#02x", i, b[i], want[i])
		}
	}

	// 零长 option：Length=0 合法边界。
	b, err = buildOptions([]core.GeneveOption{{Class: 0x0102, Type: 0x03}})
	if err != nil {
		t.Fatalf("zero-length option: %v", err)
	}
	if len(b) != 4 || b[0] != 0x01 || b[1] != 0x02 || b[2] != 0x03 || b[3] != 0x00 {
		t.Errorf("zero-length option encoding = % x, want 01 02 03 00", b)
	}

	// 多 option 顺序保持：A(4B data) + B(8B data)，输出 A 头 + A data + B 头 + B data。
	b, err = buildOptions([]core.GeneveOption{
		{Class: 0x0102, Type: 0x05, Data: []byte{1, 2, 3, 4}},
		{Class: 0x0103, Type: 0x06, Data: []byte{5, 6, 7, 8, 9, 10, 11, 12}},
	})
	if err != nil {
		t.Fatalf("multiple options: %v", err)
	}
	want = []byte{
		0x01, 0x02, 0x05, 0x01, 1, 2, 3, 4,
		0x01, 0x03, 0x06, 0x02, 5, 6, 7, 8, 9, 10, 11, 12,
	}
	if len(b) != len(want) {
		t.Fatalf("multiple options len %d, want %d", len(b), len(want))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Errorf("multiple options byte %d = %#02x, want %#02x", i, b[i], want[i])
		}
	}

	// 非 4 对齐 data → 报错。
	if _, err := buildOptions([]core.GeneveOption{{Class: 1, Type: 1, Data: []byte{1, 2, 3}}}); err == nil {
		t.Errorf("misaligned option data: want error")
	}
}

// TestGenerateEventFolding pins the folding contract: empty Datagrams → one
// event from top-level fields; N entries → N events with per-entry
// VNI/ports/direction/options/flags; entry Options/Inner nil falls back to
// top-level; down events carry absolute ports + L4PortOverride.
func TestGenerateEventFolding(t *testing.T) {
	// 空 Datagrams → 单事件，VNI 5000 无 options。
	events := collectEvents(t, &core.GeneveConfig{VNI: 5000, Inner: fixture()})
	if len(events) != 1 {
		t.Fatalf("empty datagrams: got %d events, want 1", len(events))
	}
	if !events[0].Up {
		t.Errorf("default event must be up")
	}
	if !bytesPrefix(events[0].Bytes, []byte{0x00, 0x00, 0x65, 0x58, 0x00, 0x13, 0x88, 0x00}) {
		t.Errorf("event 1 header prefix = % x", events[0].Bytes[:8])
	}
	if len(events[0].Bytes) != 8+14+20+len(fixture().Payload) {
		t.Errorf("event 1 total len %d, want header+inner", len(events[0].Bytes))
	}
	if !bytesContains(events[0].Bytes, []byte("geneve-inner-01")) {
		t.Errorf("event 1 payload not from inner fixture")
	}

	// N entries → N events；entry 字段逐项覆盖 + 顶层回退。
	down := false
	up := true
	innerB := &core.EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:12:02", DstMAC: "02:bb:00:00:12:02",
		EtherType: "ipv4", SrcIP: "10.20.2.1", DstIP: "10.20.2.2",
		Payload: []byte("geneve-b"),
	}
	opts := []core.GeneveOption{{Class: 0x0101, Type: 0x02, Data: []byte{0, 0, 0, 0}}}
	cfg := &core.GeneveConfig{
		VNI:     700,
		Inner:   innerB, // entry 无 Inner 时回退
		Options: opts,   // entry 无 Options 时回退
		Datagrams: []core.GeneveDatagram{
			{VNI: 100, SrcPort: 40001},
			{VNI: 200, SrcPort: 40002, Options: []core.GeneveOption{{Class: 0x0200, Type: 0x01}}, Inner: innerB},
			{VNI: 300, SrcPort: 40003, Up: &down, OAM: boolPtr(true)},
			{VNI: 400, SrcPort: 40004, Up: &up, Critical: boolPtr(true), Version: uint8Ptr(0)},
		},
	}
	events = collectEvents(t, cfg)
	if len(events) != 4 {
		t.Fatalf("4 datagrams: got %d events, want 4", len(events))
	}
	// VNI 与 flags/optlen 前两字节：顶层 options = 4B 头+4B data → OptLen 2
	// 单位（0x02）；事件 2 被 entry 的零长 option 覆盖 → OptLen 1（0x01）。
	wantByte0 := []byte{0x02, 0x01, 0x02, 0x02}
	wantByte1 := []byte{0x00, 0x00, 0x80, 0x40}
	wantVNI := []uint32{100, 200, 300, 400}
	for i := range events {
		hdr := events[i].Bytes[:8]
		if hdr[0] != wantByte0[i] {
			t.Errorf("event %d byte0 = %#02x, want %#02x", i+1, hdr[0], wantByte0[i])
		}
		if hdr[1] != wantByte1[i] {
			t.Errorf("event %d byte1 = %#02x, want %#02x", i+1, hdr[1], wantByte1[i])
		}
		if got := uint32(hdr[4])<<16 | uint32(hdr[5])<<8 | uint32(hdr[6]); got != wantVNI[i] {
			t.Errorf("event %d vni %d, want %d", i+1, got, wantVNI[i])
		}
	}
	// 事件 1 options 来自顶层回退（class 0x0101 出现在字节 8-11）。
	if events[0].Bytes[8] != 0x01 || events[0].Bytes[9] != 0x01 {
		t.Errorf("event 1 options class = % x, want 01 01", events[0].Bytes[8:10])
	}
	// 事件 2 options 被 entry 覆盖（class 0x0200）。
	if events[1].Bytes[8] != 0x02 || events[1].Bytes[9] != 0x00 {
		t.Errorf("event 2 options class = % x, want 02 00", events[1].Bytes[8:10])
	}
	// 内层回退：event 1 用顶层 fixture（geneve-b）。
	if !bytesContains(events[0].Bytes, []byte("geneve-b")) {
		t.Errorf("event 1 payload not from top-level inner fallback")
	}
	// 方向与端口：3 down 绝对端口（Src=6081/Dst=40003, L4PortOverride）。
	if events[2].Up {
		t.Errorf("event 3 must be down")
	}
	if events[2].SrcPort != udpPort || events[2].DstPort != 40003 || !events[2].L4PortOverride {
		t.Errorf("down event ports wrong: src=%d dst=%d override=%v", events[2].SrcPort, events[2].DstPort, events[2].L4PortOverride)
	}
}

// TestGenerateEmptyConfigDefaultFlow (P0b contract): nil config produces one
// parseable datagram（默认 VNI=0、version=0、无 flags/options、内建 fixture）。
func TestGenerateEmptyConfigDefaultFlow(t *testing.T) {
	events := collectEvents(t, nil)
	if len(events) != 1 {
		t.Fatalf("nil config: got %d events, want 1", len(events))
	}
	if !bytesPrefix(events[0].Bytes, []byte{0x00, 0x00, 0x65, 0x58, 0, 0, 0, 0}) {
		t.Errorf("default header = % x", events[0].Bytes[:8])
	}
}

// TestGenerateNilEmitMsg / TestGenerateCtxCancel: wiring errors and ctx
// cancellation are hard errors, never panics or hangs.
func TestGenerateNilEmitMsg(t *testing.T) {
	if err := (&GeneveGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Errorf("nil request: want error")
	}
	if err := (&GeneveGenerator{}).Generate(context.Background(), &layers.GenRequest{}); err == nil {
		t.Errorf("nil EmitMsg: want error")
	}
}

func TestGenerateCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &core.GeneveConfig{VNI: 1, Inner: fixture()}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{Geneve: cfg},
		EmitMsg: func(layers.MessageEvent) error { return nil },
	}
	if err := (&GeneveGenerator{}).Generate(ctx, req); err == nil {
		t.Errorf("cancelled ctx: want error")
	}
}

// TestValidatorAnchors covers every rejection rule and its testcase-contract
// anchor word (strings.Contains, case-sensitive; design §4).
func TestValidatorAnchors(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *core.GeneveConfig
		anchor string
	}{
		{"fault_header_truncated", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "header_truncated"}}, "header"},
		{"fault_reserved_flags", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "reserved_flags"}}, "reserved"},
		{"fault_option_length", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "option_length"}}, "option"},
		{"fault_vni_overflow", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "vni_overflow"}}, "vni"},
		{"fault_wrong_udp_port", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "wrong_udp_port"}}, "port"},
		{"fault_inner_truncated", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "inner_truncated"}}, "inner"},
		{"fault_checksum", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "checksum"}}, "checksum"},
		{"unknown_fault_kind", &core.GeneveConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "bogus"}}, "unknown wire_fault"},
		{"real vni overflow top", &core.GeneveConfig{VNI: 16777216, Inner: fixture()}, "vni"},
		{"real vni overflow datagram", &core.GeneveConfig{Inner: fixture(), Datagrams: []core.GeneveDatagram{{VNI: 16777216}}}, "vni"},
		{"real version nonzero", &core.GeneveConfig{Version: 1, VNI: 1, Inner: fixture()}, "version"},
		{"real version nonzero datagram", &core.GeneveConfig{VNI: 1, Inner: fixture(), Datagrams: []core.GeneveDatagram{{Version: uint8Ptr(3)}}}, "version"},
		{"real option misaligned", &core.GeneveConfig{VNI: 1, Inner: fixture(), Options: []core.GeneveOption{{Class: 1, Type: 1, Data: []byte{1, 2, 3}}}}, "option"},
		{"real option misaligned datagram", &core.GeneveConfig{VNI: 1, Inner: fixture(), Datagrams: []core.GeneveDatagram{{Options: []core.GeneveOption{{Data: make([]byte, 6)}}}}}, "option"},
		{"real option rsvd", &core.GeneveConfig{VNI: 1, Inner: fixture(), Options: []core.GeneveOption{{Class: 1, Type: 1, Rsvd: 1}}}, "option"},
		{"real option total overflow", &core.GeneveConfig{VNI: 1, Inner: fixture(), Options: []core.GeneveOption{{Class: 1, Type: 1, Data: make([]byte, 256)}}}, "length"},
		// 5-bit option Length 字段上限 31 单位：128B data 总长 132 ≤ 252 能过
		// OptLen 总校验，但线上 Length 字段回绕——必须单独拒绝（回归）。
		{"real option 5-bit length overflow", &core.GeneveConfig{VNI: 1, Inner: fixture(), Options: []core.GeneveOption{{Class: 1, Type: 1, Data: make([]byte, 128)}}}, "option"},
		{"real proto mismatch", &core.GeneveConfig{VNI: 1, ProtocolType: 0x0800, Inner: fixture()}, "protocol"},
		// 非 TEB + 无 inner：生成器只产 Ethernet 内层，协议类型声明 0x0800 却
		// 补默认 Ethernet 帧是自相矛盾的线上字节——必须拒绝（回归）。
		{"real proto mismatch no inner", &core.GeneveConfig{VNI: 1, ProtocolType: 0x0800}, "protocol"},
		{"real proto mismatch datagram", &core.GeneveConfig{VNI: 1, ProtocolType: 0x0800, Datagrams: []core.GeneveDatagram{{Inner: fixture()}}}, "protocol"},
		{"bad inner mac", &core.GeneveConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "nope", DstMAC: "02:bb:00:00:12:01", EtherType: "ipv4", SrcIP: "10.20.1.1", DstIP: "10.20.1.2"}}, "inner"},
		{"bad inner ether_type", &core.GeneveConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:12:01", DstMAC: "02:bb:00:00:12:01", EtherType: "gre", SrcIP: "10.20.1.1", DstIP: "10.20.1.2"}}, "inner"},
		{"family mismatch", &core.GeneveConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:12:01", DstMAC: "02:bb:00:00:12:01", EtherType: "ipv6", SrcIP: "10.20.1.1", DstIP: "fc00::2"}}, "family"},
	}
	for _, c := range cases {
		err := ValidateConfig(c.cfg)
		if err == nil {
			t.Errorf("%s: want error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.anchor) {
			t.Errorf("%s: error %q missing anchor %q", c.name, err.Error(), c.anchor)
		}
	}
}

// TestValidatorBoundariesLegal: VNI=0/0xffffff, empty payload, zero-length
// option, OAM/Critical set, ProtocolType 0/0x6558, nil WireFault must NOT be
// rejected (design §4 note).
func TestValidatorBoundariesLegal(t *testing.T) {
	cfgs := []*core.GeneveConfig{
		{VNI: 0, Inner: fixture()},
		{VNI: 0xffffff, Inner: fixture()},
		{VNI: 1, ProtocolType: 0x6558, Inner: fixture()},
		{VNI: 1, OAM: true, Critical: true, Inner: fixture()},
		{VNI: 1, Inner: fixture(), Options: []core.GeneveOption{{Class: 0x0100, Type: 0x01}}},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:12:01", DstMAC: "02:bb:00:00:12:01", EtherType: "ipv4", SrcIP: "10.20.1.1", DstIP: "10.20.1.2", Payload: nil}},
		{VNI: 1, Inner: fixture(), WireFault: nil},
	}
	for i, cfg := range cfgs {
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("boundary %d: unexpected error %v", i, err)
		}
	}
}

// TestLayerValidatorPortCheck: the registered layer validator rejects an
// explicit non-6081 destination port (udp_carrier 锚词 "port") and passes
// 0/6081.
func TestLayerValidatorPortCheck(t *testing.T) {
	validate := func(spec core.FlowSpec) error {
		p, err := layers.BuildLayersPlanner("geneve", []byte(`[{"ip":{}},{"udp":{}},{"geneve":{}}]`))
		if err != nil {
			return err
		}
		return p.Validate(spec)
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Geneve: &core.GeneveConfig{VNI: 1, Inner: fixture()}}
	if err := validate(spec); err != nil {
		t.Errorf("default (no dst_port): unexpected error %v", err)
	}
	spec.DstPort = 6081
	if err := validate(spec); err != nil {
		t.Errorf("dst_port 6081: unexpected error %v", err)
	}
	spec.DstPort = 6082
	err := validate(spec)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("dst_port 6082: want error containing %q, got %v", "port", err)
	}
}

// TestGeneratorInterface pins the layer contract: event producer registered
// under "geneve".
func TestGeneratorInterface(t *testing.T) {
	g := &GeneveGenerator{}
	if g.Name() != "geneve" {
		t.Errorf("Name %q", g.Name())
	}
	if g.GenEvents() == nil {
		t.Errorf("GenEvents must return the event producer")
	}
	factory, err := layers.NewLayerGenerator("geneve")
	if err != nil {
		t.Fatalf("NewLayerGenerator: %v", err)
	}
	if factory.Name() != "geneve" {
		t.Errorf("registered generator name %q", factory.Name())
	}
}

func boolPtr(v bool) *bool    { return &v }
func uint8Ptr(v uint8) *uint8 { return &v }

func bytesPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

func bytesContains(b, sub []byte) bool {
	return strings.Contains(string(b), string(sub))
}
