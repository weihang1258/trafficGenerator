package bgp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func testConfig() *BGPConfig {
	return &BGPConfig{Version: 4, ASN: 64512, HoldTime: 90, Identifier: "192.0.2.1", WireProfile: "bgp_rfc4271_ipv4_unicast"}
}

func TestBuildOpenExactRFC4271Bytes(t *testing.T) {
	got, err := BuildOpen(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100"
	if hex.EncodeToString(got) != want {
		t.Fatalf("OPEN=%x want %s", got, want)
	}
	if len(got) != int(got[16])<<8|int(got[17]) {
		t.Fatalf("length field mismatch: %d", len(got))
	}
}

func TestBuildKeepaliveMinimumLegalMessage(t *testing.T) {
	got, err := BuildKeepalive()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("KEEPALIVE=%x", got)
	}
	if len(got) != 19 {
		t.Fatalf("length=%d", len(got))
	}
}

func TestBuildOpenRejectsMalformedConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*BGPConfig)
		want   string
	}{
		{"marker", func(c *BGPConfig) { c.Marker = []byte("bad") }, "marker"},
		{"length", func(c *BGPConfig) { c.Length = 18 }, "length"},
		{"version", func(c *BGPConfig) { c.Version = 3 }, "version"},
		{"asn", func(c *BGPConfig) { c.ASN = 65536 }, "as"},
		{"identifier", func(c *BGPConfig) { c.Identifier = "2001:db8::1" }, "identifier"},
		{"capability", func(c *BGPConfig) { c.Capabilities = []byte{1} }, "capabilit"},
		{"update", func(c *BGPConfig) { c.Update = []byte{1} }, "update"},
		{"notification", func(c *BGPConfig) { c.Notification = []byte{1} }, "notification"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.mutate(c)
			if _, err := BuildOpen(c); err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerAcceptsIPv6TransportWithIPv4Identifier(t *testing.T) {
	cfg := testConfig()
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 40000, DstPort: 179, BGP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) < 10 {
		t.Fatalf("packets=%d", len(packets))
	}
	if packets[3].Direction != "up" || packets[4].Direction != "down" {
		t.Fatalf("directions=%q,%q", packets[3].Direction, packets[4].Direction)
	}
	if hex.EncodeToString(packets[3].Payload) != "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100" {
		t.Fatalf("open=%x", packets[3].Payload)
	}
	if hex.EncodeToString(packets[5].Payload) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("keepalive=%x", packets[5].Payload)
	}
}

func TestPlannerRejectsUnsupportedCarrierAndIPv6Profile(t *testing.T) {
	cases := []struct {
		name string
		spec core.FlowSpec
		want string
	}{
		{"udp", core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 179, BGP: testConfig(), Metadata: map[string]interface{}{"transport": "udp"}}, "tcp"},
		{"profile", core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 179, BGP: &BGPConfig{Version: 4, ASN: 64512, Identifier: "192.0.2.1", WireProfile: "bgp_ipv6_mp_reach"}}, "profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (Planner{}).Plan(context.Background(), tc.spec); err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestGeneratorEmitsBidirectionalApplicationEvents(t *testing.T) {
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: testConfig()}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("events=%d want 6", len(events))
	}
	for i, ev := range events {
		wantUp := i%2 == 0
		if ev.Up != wantUp {
			t.Fatalf("event %d direction=%v", i, ev.Up)
		}
	}
	for _, ev := range events {
		if len(ev.Bytes) < 19 || ev.Bytes[0] != 0xff {
			t.Fatalf("invalid message=%x", ev.Bytes)
		}
	}
}

func TestGeneratorRejectsNilAndUnsupportedConfig(t *testing.T) {
	if err := (&BGPGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	bad := testConfig()
	bad.Update = []byte{1}
	if err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: bad}, EmitMsg: func(layers.MessageEvent) error { return nil }}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "update") {
		t.Fatalf("err=%v", err)
	}
}

func TestPlannerEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（BGP nil）→ Plan 默认化并产默认流。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 6 {
		t.Fatalf("packets=%d want >=6", count)
	}
}

func TestGeneratorEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（BGP nil）→ Generate 默认化并产默认流。
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("events=%d want 6", len(events))
	}
	// 默认 OPEN：version 4, ASN 64512, holdtime 0(零值保持显式), identifier 192.0.2.1。
	if hex.EncodeToString(events[0].Bytes) != "ffffffffffffffffffffffffffffffff001d0104fc000000c000020100" {
		t.Fatalf("open=%x", events[0].Bytes)
	}
	if hex.EncodeToString(events[2].Bytes) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("keepalive=%x", events[2].Bytes)
	}
}

// ---- 设计 §2/§3/§4：events 驱动生成，而非写死序列 ----

// u8/u16/u32/str helpers for building expectations concisely.
func u8(v byte) *uint8     { return &v }
func u16(v uint16) *uint16 { return &v }

func TestPlannerEmitsConfiguredEvents(t *testing.T) {
	// 设计 §2 推荐最小 OPEN/KEEPALIVE 会话：open c2s, open s2c, ka c2s, ka s2c。
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{
		{Kind: "open", Direction: "c2s", Version: 4, MyAS: 64512, HoldTime: 90, Identifier: "192.0.2.1"},
		{Kind: "open", Direction: "s2c", Version: 4, MyAS: 64513, HoldTime: 90, Identifier: "192.0.2.2"},
		{Kind: "keepalive", Direction: "c2s"},
		{Kind: "keepalive", Direction: "s2c"},
	}}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179, BGP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 注：此测试走 legacy Plan 路径，其 FIN 为 2 包（0x11 上行 + 0x11 下行），
	// 故 count = 3(握手) + 4(事件) + 2(FIN) = 9。pcap 驱动走 layer-chain 路径
	// (generator.go TCP 封套)，其 FIN 挥手为 4 包，故设计 §6 的 packet_count=11。
	if len(packets) != 9 {
		t.Fatalf("packets=%d want 9 (legacy Plan)", len(packets))
	}
	// 事件帧从 index 3 起（握手占 3）。open c2s 为上行、open s2c 为下行。
	if packets[3].Direction != "up" || packets[4].Direction != "down" {
		t.Fatalf("dir[3],dir[4]=%q,%q", packets[3].Direction, packets[4].Direction)
	}
	// c2s open: version4/my_as 64512(0xfc00)/hold 90(0x5a)/id 192.0.2.1。
	if hex.EncodeToString(packets[3].Payload) != "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100" {
		t.Fatalf("open c2s=%x", packets[3].Payload)
	}
	// s2c open: my_as 64513(0xfc01)/id 192.0.2.2。
	if hex.EncodeToString(packets[4].Payload) != "ffffffffffffffffffffffffffffffff001d0104fc01005ac000020200" {
		t.Fatalf("open s2c=%x", packets[4].Payload)
	}
	// 两个 keepalive。
	if hex.EncodeToString(packets[5].Payload) != "ffffffffffffffffffffffffffffffff001304" ||
		hex.EncodeToString(packets[6].Payload) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("keepalive=%x,%x", packets[5].Payload, packets[6].Payload)
	}
}

func TestGeneratorEmitsConfiguredEvents(t *testing.T) {
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{
		{Kind: "open", Direction: "c2s", Version: 4, MyAS: 64512, HoldTime: 90, Identifier: "192.0.2.1"},
		{Kind: "open", Direction: "s2c", Version: 4, MyAS: 64513, HoldTime: 90, Identifier: "192.0.2.2"},
		{Kind: "keepalive", Direction: "c2s"},
		{Kind: "keepalive", Direction: "s2c"},
	}}
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want 4", len(events))
	}
	if !events[0].Up || events[1].Up {
		t.Fatalf("up[0]=%v up[1]=%v, want true,false", events[0].Up, events[1].Up)
	}
	if !events[2].Up || events[3].Up {
		t.Fatalf("ka directions wrong")
	}
}

// ---- 设计 §3.4：UPDATE 属性与 IPv4 NLRI 逐字节；§3.5：NOTIFICATION ----

func TestBuildUpdateFullAttributesExactBytes(t *testing.T) {
	zero := uint8(0)
	ev := &core.BGPEvent{
		Kind: "update",
		NLRI: []string{"203.0.113.0/24"},
		Attributes: &core.BGPUpdateAttributes{
			Origin: &zero, ASPath: []uint16{64512}, NextHop: "192.0.2.1",
			MultiExitDisc: 100, LocalPref: 100, Communities: []string{"NO_EXPORT"},
		},
	}
	got, err := BuildUpdate(ev)
	if err != nil {
		t.Fatal(err)
	}
	// 设计 §3.4 全属性 UPDATE：bgp_update_attributes 帧，length 0x42=66。
	want := "ffffffffffffffffffffffffffffffff00420200000027400101004002040201fc00400304c00002018004040000006440050400000064c00804ffffff0118cb0071"
	if hex.EncodeToString(got) != want {
		t.Fatalf("UPDATE=%x want %s", got, want)
	}
	// Total Path Attribute Length 字段：正文从 got[19] 起（withdrawn_len 2 字节
	// 在 [19:21]，withdrawn 为空，path_attr_len 在 [21:23]）= 39。
	if binary.BigEndian.Uint16(got[21:23]) != 39 {
		t.Fatalf("path_attr_len=%d want 39", binary.BigEndian.Uint16(got[21:23]))
	}
}

func TestBuildUpdateWithdrawOnlyExactBytes(t *testing.T) {
	ev := &core.BGPEvent{Kind: "update", WithdrawnPrefixes: []string{"203.0.113.0/24"}}
	got, err := BuildUpdate(ev)
	if err != nil {
		t.Fatal(err)
	}
	// 设计 §3.4 withdraw-only：bgp_update_withdraw 帧，length 0x1b=27。
	want := "ffffffffffffffffffffffffffffffff001b02000418cb00710000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("UPDATE=%x want %s", got, want)
	}
	// Withdrawn Routes Length = 4。
	if binary.BigEndian.Uint16(got[19:21]) != 4 {
		t.Fatalf("withdrawn_len=%d want 4", binary.BigEndian.Uint16(got[19:21]))
	}
}

func TestBuildUpdateNlri32ExactBytes(t *testing.T) {
	zero := uint8(0)
	ev := &core.BGPEvent{
		Kind: "update", NLRI: []string{"192.0.2.1/32"},
		Attributes: &core.BGPUpdateAttributes{
			Origin: &zero, ASPath: []uint16{64512}, NextHop: "192.0.2.1",
			MultiExitDisc: 100, LocalPref: 100, Communities: []string{"NO_EXPORT"},
		},
	}
	got, err := BuildUpdate(ev)
	if err != nil {
		t.Fatal(err)
	}
	// 设计 §3.4 /32：bgp_ipv4_nlri_32 帧，length 0x43=67。
	want := "ffffffffffffffffffffffffffffffff00430200000027400101004002040201fc00400304c00002018004040000006440050400000064c00804ffffff0120c0000201"
	if hex.EncodeToString(got) != want {
		t.Fatalf("UPDATE/32=%x want %s", got, want)
	}
}

func TestBuildNotificationExactBytes(t *testing.T) {
	ev := &core.BGPEvent{Kind: "notification", ErrorCode: 4, ErrorSubcode: 0, Direction: "s2c"}
	got, err := BuildNotification(ev)
	if err != nil {
		t.Fatal(err)
	}
	// 设计 §3.5：bgp_notification_hold_expired 帧，length 0x15=21。
	want := "ffffffffffffffffffffffffffffffff0015030400"
	if hex.EncodeToString(got) != want {
		t.Fatalf("NOTIFICATION=%x want %s", got, want)
	}
	if binary.BigEndian.Uint16(got[16:18]) != 21 {
		t.Fatalf("length=%d want 21", binary.BigEndian.Uint16(got[16:18]))
	}
}

// ---- 设计 §7 错误处理表：每个负例一测，验证错误在 planner/validator 被拒 ----

func TestPlannerRejectsWireFaultCases(t *testing.T) {
	cases := []struct {
		name string
		evs  []core.BGPEvent
		want string
	}{
		{"marker", []core.BGPEvent{{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"}, {Kind: "wire_fault", Direction: "c2s", FaultKind: "marker"}}, "marker"},
		{"length", []core.BGPEvent{{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"}, {Kind: "wire_fault", Direction: "c2s", FaultKind: "length", Value: u16(18)}}, "length"},
		{"type", []core.BGPEvent{{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"}, {Kind: "wire_fault", Direction: "c2s", FaultKind: "type", Value: u16(9)}}, "type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: tc.evs}
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179, BGP: cfg})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerRejectsVersionAndAsAndAddressAndState(t *testing.T) {
	cases := []struct {
		name string
		evs  []core.BGPEvent
		want string
	}{
		// N6: OPEN version 3。
		{"version", []core.BGPEvent{{Kind: "open", Direction: "c2s", Version: 3}}, "version"},
		// N7: My AS 70000 超 2 字节。
		{"as", []core.BGPEvent{{Kind: "open", Direction: "c2s", MyAS: 70000}}, "as"},
		// N9: IPv6 NLRI 在 IPv4 profile。
		{"address", []core.BGPEvent{
			{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"},
			{Kind: "keepalive", Direction: "c2s"}, {Kind: "keepalive", Direction: "s2c"},
			{Kind: "update", Direction: "c2s", NLRI: []string{"2001:db8::/32"}},
		}, "address"},
		// N8: UPDATE 在 OPEN 前。
		{"state", []core.BGPEvent{{Kind: "update", Direction: "c2s", NLRI: []string{"203.0.113.0/24"}}}, "state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: tc.evs}
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179, BGP: cfg})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerRejectsNotificationBeforeOpen(t *testing.T) {
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{{Kind: "notification", Direction: "s2c", ErrorCode: 4}}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179, BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "state") {
		t.Fatalf("err=%v want state", err)
	}
}

func TestPlannerRejectsNotificationNotLast(t *testing.T) {
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{
		{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"},
		{Kind: "notification", Direction: "s2c", ErrorCode: 4}, {Kind: "keepalive", Direction: "c2s"},
	}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "last") {
		t.Fatalf("err=%v want last", err)
	}
}

func TestPlannerRejectsSingleOpen(t *testing.T) {
	// 设计 §4：open 必须成对出现（两方向各一条）。
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{
		{Kind: "open", Direction: "c2s"},
	}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "exactly two") {
		t.Fatalf("err=%v want exactly two", err)
	}
}

func TestPlannerRejectsOpenAfterEstablished(t *testing.T) {
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Events: []core.BGPEvent{
		{Kind: "open", Direction: "c2s"}, {Kind: "open", Direction: "s2c"},
		{Kind: "keepalive", Direction: "c2s"}, {Kind: "keepalive", Direction: "s2c"},
		{Kind: "open", Direction: "c2s"},
	}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "state") {
		t.Fatalf("err=%v want state", err)
	}
}

func TestPlannerRejectsMultiSession(t *testing.T) {
	// 设计 §2：sessions>1 多流展开是框架 SubFlow 课题（T3）；显式拒绝。
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Sessions: []core.BGPSession{
		{SrcPort: 12345, Events: []core.BGPEvent{{Kind: "open", Direction: "c2s"}}},
		{SrcPort: 12346, Events: []core.BGPEvent{{Kind: "open", Direction: "c2s"}}},
	}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "multi-stream") {
		t.Fatalf("err=%v want multi-stream", err)
	}
}

func TestGeneratorRejectsMultiSession(t *testing.T) {
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Sessions: []core.BGPSession{
		{SrcPort: 12345, Events: []core.BGPEvent{{Kind: "open", Direction: "c2s"}}},
		{SrcPort: 12346, Events: []core.BGPEvent{{Kind: "open", Direction: "c2s"}}},
	}}
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: cfg}, EmitMsg: func(layers.MessageEvent) error { return nil }})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "multi-stream") {
		t.Fatalf("err=%v want multi-stream", err)
	}
}

func TestGeneratorPromotesSingleSessionEvents(t *testing.T) {
	// 设计 §2 多会话边界：len(Sessions)==1 时提升该 session 的 events 为事件源
	// （镜像 mongodb layer_gen），而非静默回退默认流（否则单 session 自定义事件
	// 产错包）。3 事件（open/open/keepalive）应产 3 条 MessageEvent。
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Sessions: []core.BGPSession{
		{SrcPort: 12345, Events: []core.BGPEvent{
			{Kind: "open", Direction: "c2s", Version: 4, MyAS: 64512, HoldTime: 90, Identifier: "192.0.2.1"},
			{Kind: "open", Direction: "s2c", Version: 4, MyAS: 64513, HoldTime: 90, Identifier: "192.0.2.2"},
			{Kind: "keepalive", Direction: "c2s"},
		}},
	}}
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 179}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d want 3 (session events), got default stream", len(events))
	}
	// 首条是 c2s open（my_as 64512），非默认流。
	if hex.EncodeToString(events[0].Bytes) != "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100" {
		t.Fatalf("open=%x", events[0].Bytes)
	}
}

func TestPlannerRejectsIllegalSessionSequence(t *testing.T) {
	// len(Sessions)==1 时 session 内非法序列（update 于 open 前）也应被状态机拒绝。
	cfg := &BGPConfig{WireProfile: "bgp_rfc4271_ipv4_unicast", Sessions: []core.BGPSession{
		{SrcPort: 12345, Events: []core.BGPEvent{{Kind: "update", Direction: "c2s", NLRI: []string{"203.0.113.0/24"}}}},
	}}
	err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", BGP: cfg})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "state") {
		t.Fatalf("err=%v want state", err)
	}
}

// ---- 用例校准：tshark 字段名（bgp_update_withdraw 的 withdraw 前缀尾 0x00 是 PathAttr Length）----

func TestBuildUpdateRejectsOverlongAttribute(t *testing.T) {
	// §3.4/§7：属性值长度 >= 256 必须拒绝（extended-length 超出本版范围），
	// 而非用 byte(len) 静默截断。128 个 ASN → AS_PATH 值长 2+128*2=258。
	asns := make([]uint16, 128)
	for i := range asns {
		asns[i] = uint16(64512 + i) // 恒 <= 65535
	}
	ev := &core.BGPEvent{Kind: "update", Attributes: &core.BGPUpdateAttributes{ASPath: asns}}
	_, err := BuildUpdate(ev)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "extended-length") {
		t.Fatalf("err=%v want extended-length reject", err)
	}
}

func TestBuildUpdateRejectsMessageOverflow(t *testing.T) {
	// §3.1/§7：BGP 报文总长超过 4096 必须拒绝。833 个 /32 NLRI（每个 5 字节）
	// → NLRI 4165 字节，正文超过 4096。
	var nlri []string
	for i := 0; i < 850; i++ {
		nlri = append(nlri, "192.0.2.1/32")
	}
	ev := &core.BGPEvent{Kind: "update", Attributes: &core.BGPUpdateAttributes{ASPath: []uint16{64512}}, NLRI: nlri}
	_, err := BuildUpdate(ev)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "4096") {
		t.Fatalf("err=%v want 4096 reject", err)
	}
}

func TestBuildUpdateWithdrawUsesTrailingZeroAsPathAttrLen(t *testing.T) {
	// 设计 §3.4 withdraw：withdrawn_len=4=18 cb 00 71，其后 00 00 是
	// path_attr_len=0（非前缀 padding / 下一片）。tshark 已字节级验证。
	ev := &core.BGPEvent{Kind: "update", WithdrawnPrefixes: []string{"203.0.113.0/24"}}
	got, err := BuildUpdate(ev)
	if err != nil {
		t.Fatal(err)
	}
	// offset 54 起（Ethernet14+IPv4 20+TCP20）→ BGP body 从 got[0] 起。
	// withdrawn_len 在 got[19:21]，withdrawn 路由 4 字节在 [21:25]，
	// path_attr_len 在 [25:27]=0x0000。
	if binary.BigEndian.Uint16(got[25:27]) != 0 {
		t.Fatalf("path_attr_len=%d want 0", binary.BigEndian.Uint16(got[25:27]))
	}
	// NLRI 区为空（无 NLRI 字节）。
	if len(got) != 27 {
		t.Fatalf("len=%d want 27", len(got))
	}
}
