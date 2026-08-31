package vxlan

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// VXLAN 终结层生成器测试（B4 封装类）——事件模式（socks5/gtp 同款）：
// 每数据报 1 事件，Bytes = 8-byte VXLAN 头 + 内层 Ethernet 帧；方向与
// 事件级端口覆盖由事件携带，UDP 语义交给 udp 层生成器。

// collectEvents drives the generator and collects emitted events.
func collectEvents(t *testing.T, cfg *core.VXLANConfig) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{VXLAN: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := (&VXLANGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return events
}

// fixture returns a valid inner Ethernet fixture for generator tests.
func fixture() *core.EncapEthernetFixture {
	return &core.EncapEthernetFixture{
		SrcMAC:    "02:aa:00:00:10:01",
		DstMAC:    "02:bb:00:00:10:01",
		EtherType: "ipv4",
		SrcIP:     "10.10.1.1",
		DstIP:     "10.10.1.2",
		Payload:   []byte("vxlan-inner-01"),
	}
}

// TestHeaderBytes pins the 8-byte VXLAN header layout (RFC 7348 §4):
// flags byte (I=bit3→0x08), three reserved zero bytes, 24-bit BE VNI,
// trailing reserved zero.
func TestHeaderBytes(t *testing.T) {
	cases := []struct {
		name  string
		vni   uint32
		iFlag bool
		want  []byte
	}{
		{"vni5000_iflag", 5000, true, []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x00}},
		{"vni0", 0, true, []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"vnimax", 0xffffff, true, []byte{0x08, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00}},
		{"no_iflag", 1, false, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}},
	}
	for _, c := range cases {
		got := buildVXLANHeader(c.vni, c.iFlag)
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

// TestGenerateEventFolding pins the folding contract: empty Datagrams → one
// event from top-level VNI/IFlag/Inner; N entries → N events with per-entry
// VNI/ports/direction; entry Inner nil falls back to top-level Inner; down
// events carry absolute ports + L4PortOverride (udp 层跳过交换).
func TestGenerateEventFolding(t *testing.T) {
	// 空 Datagrams → 单事件，默认 VNI=0、I 置位。
	events := collectEvents(t, &core.VXLANConfig{VNI: 5000, Inner: fixture()})
	if len(events) != 1 {
		t.Fatalf("empty datagrams: got %d events, want 1", len(events))
	}
	if !events[0].Up {
		t.Errorf("default event must be up")
	}
	if !bytesPrefix(events[0].Bytes, []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x00}) {
		t.Errorf("event 1 header prefix = % x", events[0].Bytes[:8])
	}
	if len(events[0].Bytes) != 8+14+20+len(fixture().Payload) {
		t.Errorf("event 1 total len %d, want header+inner", len(events[0].Bytes))
	}

	// N entries → N events。
	up := true
	down := false
	innerA := fixture()
	innerB := &core.EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:10:02", DstMAC: "02:bb:00:00:10:02",
		EtherType: "ipv4", SrcIP: "10.10.2.1", DstIP: "10.10.2.2",
		Payload: []byte("vxlan-b"),
	}
	cfg := &core.VXLANConfig{
		Inner: innerA, // entry 无 Inner 时回退
		Datagrams: []core.VXLANDatagram{
			{VNI: 100, SrcPort: 40001},
			{VNI: 200, SrcPort: 40002, Inner: innerB},
			{VNI: 300, SrcPort: 40003, Up: &down},
			{VNI: 400, SrcPort: 40004, Up: &up},
		},
	}
	// 注：i_flag=false 不进生成器路径——ValidateConfig 先行拒绝（负例）；
	// flags 字节的 I=0 编码由 TestHeaderBytes 的 no_iflag 用例锁定。
	events = collectEvents(t, cfg)
	if len(events) != 4 {
		t.Fatalf("4 datagrams: got %d events, want 4", len(events))
	}
	wantVNI := []uint32{100, 200, 300, 400}
	for i, vni := range wantVNI {
		hdr := events[i].Bytes[:8]
		if got := uint32(hdr[4])<<16 | uint32(hdr[5])<<8 | uint32(hdr[6]); got != vni {
			t.Errorf("event %d vni %d, want %d", i+1, got, vni)
		}
	}
	// 内层回退：event 1 用顶层 fixture，event 2 用 entry fixture。
	if !bytesContains(events[0].Bytes, []byte("vxlan-inner-01")) {
		t.Errorf("event 1 payload not from top-level inner")
	}
	if !bytesContains(events[1].Bytes, []byte("vxlan-b")) {
		t.Errorf("event 2 payload not from entry inner")
	}
	// 方向与端口：1/2 up（SrcPort 覆盖，DstPort 留链层默认 0）、3 down
	// 绝对端口（Src=4789/Dst=40003, L4PortOverride）。
	if !events[0].Up || !events[1].Up {
		t.Errorf("events 1/2 must be up")
	}
	if events[0].SrcPort != 40001 || events[1].SrcPort != 40002 {
		t.Errorf("up SrcPort overrides wrong: %d/%d", events[0].SrcPort, events[1].SrcPort)
	}
	if events[2].Up {
		t.Errorf("event 3 must be down")
	}
	if events[2].SrcPort != udpPort || events[2].DstPort != 40003 || !events[2].L4PortOverride {
		t.Errorf("down event ports wrong: src=%d dst=%d override=%v", events[2].SrcPort, events[2].DstPort, events[2].L4PortOverride)
	}
}

// TestGenerateZeroChecksum pins the checksum-profile event metadata: a
// UDPSumZero datagram carries udp_disable_checksum=true（builder 据此写
// IPv4 UDP checksum 0x0000，RFC 768 合法档位），其余数据报不带键。
func TestGenerateZeroChecksum(t *testing.T) {
	cfg := &core.VXLANConfig{
		VNI: 7, Inner: fixture(),
		Datagrams: []core.VXLANDatagram{
			{VNI: 7, Inner: fixture()},
			{VNI: 7, Inner: fixture(), UDPSumZero: true},
		},
	}
	events := collectEvents(t, cfg)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Metadata != nil {
		t.Errorf("event 1 must not carry metadata, got %v", events[0].Metadata)
	}
	if v, ok := events[1].Metadata["udp_disable_checksum"]; !ok || v != true {
		t.Errorf("event 2 metadata = %v, want udp_disable_checksum=true", events[1].Metadata)
	}
}

// TestGenerateEmptyConfigDefaultFlow (P0b contract): nil config produces one
// parseable datagram（默认 VNI=0、I 置位、内建 fixture）。
func TestGenerateEmptyConfigDefaultFlow(t *testing.T) {
	events := collectEvents(t, nil)
	if len(events) != 1 {
		t.Fatalf("nil config: got %d events, want 1", len(events))
	}
	if !bytesPrefix(events[0].Bytes, []byte{0x08, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("default header = % x", events[0].Bytes[:8])
	}
}

// TestGenerateNilEmitMsg / TestGenerateCtxCancel: wiring errors and ctx
// cancellation are hard errors, never panics or hangs.
func TestGenerateNilEmitMsg(t *testing.T) {
	if err := (&VXLANGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Errorf("nil request: want error")
	}
	if err := (&VXLANGenerator{}).Generate(context.Background(), &layers.GenRequest{}); err == nil {
		t.Errorf("nil EmitMsg: want error")
	}
}

func TestGenerateCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &core.VXLANConfig{VNI: 1, Inner: fixture()}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{VXLAN: cfg},
		EmitMsg: func(layers.MessageEvent) error { return nil },
	}
	if err := (&VXLANGenerator{}).Generate(ctx, req); err == nil {
		t.Errorf("cancelled ctx: want error")
	}
}

// TestValidatorAnchors covers every rejection rule and its testcase-contract
// anchor word (strings.Contains, case-sensitive; design §10).
func TestValidatorAnchors(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *core.VXLANConfig
		anchor string
	}{
		{"fault_header_truncated", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "header_truncated"}}, "header"},
		{"fault_reserved_flags", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "reserved_flags"}}, "reserved"},
		{"fault_vni_overflow", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "vni_overflow"}}, "vni"},
		{"fault_wrong_udp_port", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "wrong_udp_port"}}, "port"},
		{"fault_inner_truncated", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "inner_truncated"}}, "inner"},
		{"fault_checksum", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "checksum"}}, "checksum"},
		{"unknown_fault_kind", &core.VXLANConfig{VNI: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "bogus"}}, "unknown wire_fault"},
		{"real vni overflow top", &core.VXLANConfig{VNI: 16777216, Inner: fixture()}, "vni"},
		{"real vni overflow datagram", &core.VXLANConfig{Inner: fixture(), Datagrams: []core.VXLANDatagram{{VNI: 16777216}}}, "vni"},
		{"real i_flag false", &core.VXLANConfig{VNI: 1, IFlag: boolPtr(false), Inner: fixture()}, "flag"},
		{"real i_flag false datagram", &core.VXLANConfig{Inner: fixture(), Datagrams: []core.VXLANDatagram{{VNI: 1, IFlag: boolPtr(false)}}}, "flag"},
		{"bad inner mac", &core.VXLANConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "nope", DstMAC: "02:bb:00:00:10:01", EtherType: "ipv4", SrcIP: "10.10.1.1", DstIP: "10.10.1.2"}}, "inner"},
		{"bad inner ether_type", &core.VXLANConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:10:01", DstMAC: "02:bb:00:00:10:01", EtherType: "gre", SrcIP: "10.10.1.1", DstIP: "10.10.1.2"}}, "inner"},
		{"vid overflow", &core.VXLANConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:10:01", DstMAC: "02:bb:00:00:10:01", EtherType: "vlan_ipv4", VLANID: 4096, SrcIP: "10.10.1.1", DstIP: "10.10.1.2"}}, "vlan"},
		{"family mismatch", &core.VXLANConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:10:01", DstMAC: "02:bb:00:00:10:01", EtherType: "ipv6", SrcIP: "10.10.1.1", DstIP: "fc00::2"}}, "family"},
		{"payload overflow", &core.VXLANConfig{VNI: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:10:01", DstMAC: "02:bb:00:00:10:01", EtherType: "ipv4", SrcIP: "10.10.1.1", DstIP: "10.10.1.2", Payload: make([]byte, 0xffff)}}, "length"},
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

// TestValidatorBoundariesLegal: VNI=0/0xffffff, empty payload, VID=0/4095,
// nil WireFault must NOT be rejected (design §10 note).
func TestValidatorBoundariesLegal(t *testing.T) {
	cfgs := []*core.VXLANConfig{
		{VNI: 0, Inner: fixture()},
		{VNI: 0xffffff, Inner: fixture()},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:10:01", DstMAC: "02:bb:00:00:10:01", EtherType: "ipv4", SrcIP: "10.10.1.1", DstIP: "10.10.1.2", Payload: nil}},
		{VNI: 1, Inner: fixture(), WireFault: nil},
	}
	for i, cfg := range cfgs {
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("boundary %d: unexpected error %v", i, err)
		}
	}
}

// TestLayerValidatorPortCheck: the registered layer validator rejects an
// explicit non-4789 destination port (udp_carrier 锚词 "port") and passes
// 0/4789.
func TestLayerValidatorPortCheck(t *testing.T) {
	validate := func(spec core.FlowSpec) error {
		p, err := layers.BuildLayersPlanner("vxlan", []byte(`[{"ip":{}},{"udp":{}},{"vxlan":{}}]`))
		if err != nil {
			return err
		}
		return p.Validate(spec)
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", VXLAN: &core.VXLANConfig{VNI: 1, Inner: fixture()}}
	if err := validate(spec); err != nil {
		t.Errorf("default (no dst_port): unexpected error %v", err)
	}
	spec.DstPort = 4789
	if err := validate(spec); err != nil {
		t.Errorf("dst_port 4789: unexpected error %v", err)
	}
	spec.DstPort = 4788
	err := validate(spec)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("dst_port 4788: want error containing %q, got %v", "port", err)
	}
}

// TestGeneratorInterface pins the layer contract: event producer registered
// under "vxlan".
func TestGeneratorInterface(t *testing.T) {
	g := &VXLANGenerator{}
	if g.Name() != "vxlan" {
		t.Errorf("Name %q", g.Name())
	}
	if g.GenEvents() == nil {
		t.Errorf("GenEvents must return the event producer")
	}
	factory, err := layers.NewLayerGenerator("vxlan")
	if err != nil {
		t.Fatalf("NewLayerGenerator: %v", err)
	}
	if factory.Name() != "vxlan" {
		t.Errorf("registered generator name %q", factory.Name())
	}
}

func boolPtr(v bool) *bool { return &v }

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

// 防呆：binary 引用保留（header 编码函数在包内使用）。
var _ = binary.BigEndian
