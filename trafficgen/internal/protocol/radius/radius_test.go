package radius

// RADIUS planner tests, derived from /tmp/l7_planner_design/testcases_radius.md
// (§1 RFC 字段 / §2 字节布局 / §3 状态机 / §4 业务场景 / §5 数据面 / §6 边界 /
// §8 Validate) and the reference pcaps under
// /home/pcap_auto/mypcap/publicpcap/Radius (portion_Radius.pcap,
// radius_one.pcap, ipv6_radius.pcap, ...).
//
// Model: one UDP flow = Rounds request/response exchanges on the same
// 4-tuple. Request (up) uses Code/Identifier/Authenticator/Attributes;
// response (down) echoes the Identifier, uses ResponseCode (0 = auto),
// and carries ResponseAttributes.

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func mustPlanCtx(t *testing.T, ctx context.Context, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// radiusSpec returns a base spec with a RADIUS config.
func radiusSpec(cfg *core.RadiusConfig) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 36165, DstPort: 1812,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	spec.Radius = cfg
	return spec
}

// udpPayloads returns the UDP payload bytes in wire order.
func udpPayloads(cfgs []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.L4.Protocol == "udp" {
			out = append(out, append([]byte(nil), c.Payload...))
		}
	}
	return out
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// assertPayloads checks the UDP payload bytes in order.
func assertPayloads(t *testing.T, cfgs []core.PacketConfig, want ...string) {
	t.Helper()
	got := udpPayloads(cfgs)
	if len(got) != len(want) {
		t.Fatalf("got %d UDP payloads %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if hexStr(got[i]) != want[i] {
			t.Errorf("payload[%d] = %s, want %s", i, hexStr(got[i]), want[i])
		}
	}
}

// --- §1 RFC 字段 ---

// TestHeader_AccessRequest (1.1.1/1.1.4): request header Code/ID/Length/
// Authenticator with a fixed authenticator and the default attribute set
// (User-Name "user" → 6 bytes), so Length = 20+6 = 26 = 0x001A.
func TestHeader_AccessRequest(t *testing.T) {
	cfg := &core.RadiusConfig{
		Code:          1,
		Identifier:    0x53,
		Authenticator: "eeb59c08743d33c5269cdcd8a5ab77a3",
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if hexStr(got[0]) != "0153001aeeb59c08743d33c5269cdcd8a5ab77a3010675736572" {
		t.Errorf("request = %s, want 0153001a...010675736572", hexStr(got[0]))
	}
}

// TestLength_WithAttributes (1.1.2): Length = 20 + Σ(attr len) —
// User-Name "enet" (6) + NAS-Port 29364130 (6) → 32 = 0x0020.
func TestLength_WithAttributes(t *testing.T) {
	cfg := &core.RadiusConfig{
		Identifier: 0x53,
		Attributes: []core.RadiusAttribute{
			{Type: 1, Value: "enet"},
			{Type: 5, Format: "uint32", Value: "29364130"},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if got[0][2] != 0x00 || got[0][3] != 0x20 {
		t.Errorf("Length bytes = %02x %02x, want 00 20 (32)", got[0][2], got[0][3])
	}
	if !bytes.Equal(got[0][20:26], []byte{0x01, 0x06, 'e', 'n', 'e', 't'}) {
		t.Errorf("attr 1 bytes = %s, want 0106656e6574", hexStr(got[0][20:26]))
	}
	if !bytes.Equal(got[0][26:32], []byte{0x05, 0x06, 0x01, 0xc0, 0x0f, 0xa2}) {
		t.Errorf("attr 2 bytes = %s, want 050601c00fa2", hexStr(got[0][26:32]))
	}
}

// TestLength_Min (1.1.3): a response with no attributes is exactly 20 bytes.
func TestLength_Min(t *testing.T) {
	cfg := &core.RadiusConfig{}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if len(got[1]) != 20 {
		t.Errorf("response length = %d, want 20", len(got[1]))
	}
	if got[1][2] != 0x00 || got[1][3] != 0x14 {
		t.Errorf("response Length bytes = %02x %02x, want 00 14", got[1][2], got[1][3])
	}
}

// TestAuthenticator_Random (1.1.5): empty authenticator → fresh random
// 16 bytes per round; two rounds differ.
func TestAuthenticator_Random(t *testing.T) {
	cfg := &core.RadiusConfig{Rounds: 2}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 4 {
		t.Fatalf("got %d packets, want 4", len(got))
	}
	for i := 0; i < 4; i++ {
		auth := got[i][4:20]
		if len(auth) != 16 {
			t.Errorf("packet %d authenticator length = %d, want 16", i, len(auth))
		}
	}
	if bytes.Equal(got[0][4:20], got[2][4:20]) {
		t.Errorf("round 1 and round 2 request authenticators are identical (want fresh random per round)")
	}
}

// TestCodes (1.2.1): request Code byte for the five allowed request codes.
// Codes 3/11 have no auto response mapping (design §5 S3), so they need an
// explicit ResponseCode to pass Validate.
func TestCodes(t *testing.T) {
	cases := []struct {
		code int
		resp uint8
		want byte
	}{
		{1, 0, 0x01},
		{3, 2, 0x03},
		{4, 0, 0x04},
		{11, 2, 0x0B},
		{12, 0, 0x0C},
	}
	for _, c := range cases {
		cfg := &core.RadiusConfig{Code: c.code, ResponseCode: c.resp}
		cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
		got := udpPayloads(cfgs)
		if len(got) == 0 || got[0][0] != c.want {
			t.Errorf("code %d: first byte = %02x, want %02x", c.code, got[0][0], c.want)
		}
	}
}

// TestIdentifier_Echo (1.3.1): response echoes the request ID — 0x53
// (portion_Radius.pcap reference).
func TestIdentifier_Echo(t *testing.T) {
	cfg := &core.RadiusConfig{Identifier: 83}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if got[0][1] != 0x53 {
		t.Errorf("request ID = %02x, want 53", got[0][1])
	}
	if got[1][1] != 0x53 {
		t.Errorf("response ID = %02x, want 53 (echo)", got[1][1])
	}
}

// TestIdentifier_Default (1.3.2): empty Identifier → 0 (radius_one.pcap).
func TestIdentifier_Default(t *testing.T) {
	cfg := &core.RadiusConfig{}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if got[0][1] != 0x00 || got[1][1] != 0x00 {
		t.Errorf("IDs = %02x/%02x, want 00/00", got[0][1], got[1][1])
	}
}

// TestIdentifier_MultiRound (1.3.3): round n uses (Identifier+n-1)&0xFF —
// 0xFE, 0xFF, 0x00 with wrap; each response echoes its own round's ID.
func TestIdentifier_MultiRound(t *testing.T) {
	cfg := &core.RadiusConfig{Identifier: 0xFE, Rounds: 3}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 6 {
		t.Fatalf("got %d packets, want 6", len(got))
	}
	wantIDs := []byte{0xFE, 0xFE, 0xFF, 0xFF, 0x00, 0x00}
	for i, w := range wantIDs {
		if got[i][1] != w {
			t.Errorf("packet %d ID = %02x, want %02x", i, got[i][1], w)
		}
	}
}

// TestAttr_String (1.4.1): User-Name "enet" → `01 06 65 6e 65 74`
// (portion_Radius.pcap reference). Header Length = 26 = 0x001A.
func TestAttr_String(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{{Type: 1, Value: "enet"}},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if hexStr(got[0][:4]) != "0100001a" {
		t.Errorf("head = %s, want 0100001a", hexStr(got[0][:4]))
	}
	if hexStr(got[0][20:26]) != "0106656e6574" {
		t.Errorf("attr bytes = %s, want 0106656e6574", hexStr(got[0][20:26]))
	}
}

// TestAttr_Uint32 (1.4.2): NAS-Port 29364130 → `05 06 01 c0 0f a2`
// (portion_Radius.pcap reference: 29364130 = 0x01C00FA2).
func TestAttr_Uint32(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{{Type: 5, Format: "uint32", Value: "29364130"}},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if !bytes.Equal(got[0][20:26], []byte{0x05, 0x06, 0x01, 0xc0, 0x0f, 0xa2}) {
		t.Errorf("attr bytes = %s, want 050601c00fa2", hexStr(got[0][20:26]))
	}
}

// TestAttr_IPv4 (1.4.3): NAS-IP-Address 10.80.1.29 → `04 06 0a 50 01 1d`.
func TestAttr_IPv4(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{{Type: 4, Format: "ipv4", Value: "10.80.1.29"}},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if !bytes.Equal(got[0][20:26], []byte{0x04, 0x06, 0x0a, 0x50, 0x01, 0x1d}) {
		t.Errorf("attr bytes = %s, want 04060a50011d", hexStr(got[0][20:26]))
	}
}

// TestAttr_Hex (1.4.4): User-Password 16 ciphertext bytes → Len=18=0x12.
func TestAttr_Hex(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 2, Format: "hex", Value: "71f047ccc775fff88bbcbc0289367752"},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if hexStr(got[0][:4]) != "01000026" {
		t.Errorf("head = %s, want 01000026", hexStr(got[0][:4]))
	}
	if hexStr(got[0][20:38]) != "021271f047ccc775fff88bbcbc0289367752" {
		t.Errorf("attr bytes = %s, want 021271f047ccc775fff88bbcbc0289367752", hexStr(got[0][20:38]))
	}
}

// TestAttr_Order (1.4.5): attributes concatenate in list order; header
// Length = 20 + Σ(len).
func TestAttr_Order(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 1, Value: "enet"},
			{Type: 6, Format: "uint32", Value: "2"},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if got[0][2] != 0x00 || got[0][3] != 0x20 {
		t.Errorf("Length = %02x %02x, want 00 20 (32)", got[0][2], got[0][3])
	}
	if hexStr(got[0][20:32]) != "0106656e6574060600000002" {
		t.Errorf("attr bytes = %s, want 0106656e6574060600000002", hexStr(got[0][20:32]))
	}
}

// TestAttr_EmptyString (6.5): empty string value → Len=2 (no value bytes).
func TestAttr_EmptyString(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{{Type: 89}},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if !bytes.Equal(got[0][20:22], []byte{0x59, 0x02}) {
		t.Errorf("attr bytes = %s, want 5902", hexStr(got[0][20:22]))
	}
}

// TestVSA_IPv4 (1.5.1): Vendor-Specific 4874, inner type 57, value
// 59.71.191.254 → `1a 0c 00 00 13 0a 39 06 3b 47 bf fe`
// (portion_Radius.pcap reference).
func TestVSA_IPv4(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 57, Format: "ipv4", Value: "59.71.191.254", VendorID: 4874},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if !bytes.Equal(got[0][20:32], []byte{0x1a, 0x0c, 0x00, 0x00, 0x13, 0x0a, 0x39, 0x06, 0x3b, 0x47, 0xbf, 0xfe}) {
		t.Errorf("attr bytes = %s, want 1a0c0000130a39063b47bffe", hexStr(got[0][20:32]))
	}
	// outer Length = 20 + 12 = 32 = 0x0020
	if got[0][2] != 0x00 || got[0][3] != 0x20 {
		t.Errorf("Length = %02x %02x, want 00 20", got[0][2], got[0][3])
	}
}

// TestVSA_String (1.5.2): Vendor-Specific 2011 with string value
// "27.19.114.65" (12 bytes) → outer Len 8+12=20=0x14, inner Len 2+12=14=0x0E.
func TestVSA_String(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 60, Value: "27.19.114.65", VendorID: 2011},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	want := "1a14000007db3c0e" + hexStr([]byte("27.19.114.65"))
	if hexStr(got[0][20:]) != want {
		t.Errorf("attr bytes = %s, want %s", hexStr(got[0][20:]), want)
	}
}

// TestVSA_Zero (1.5.3): VendorID=0 → plain attribute, no VSA wrapping.
func TestVSA_Zero(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 1, Value: "enet", VendorID: 0},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if !bytes.Equal(got[0][20:26], []byte{0x01, 0x06, 'e', 'n', 'e', 't'}) {
		t.Errorf("attr bytes = %s, want 0106656e6574", hexStr(got[0][20:26]))
	}
}

// TestResponseCode_Auto (1.6.1/1.6.2): request→response auto mapping —
// 1→2 (Access-Accept), 4→5 (Accounting-Response).
func TestResponseCode_Auto(t *testing.T) {
	for _, c := range []struct {
		reqCode int
		resp    byte
	}{{1, 0x02}, {4, 0x05}} {
		cfg := &core.RadiusConfig{Code: c.reqCode}
		cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
		got := udpPayloads(cfgs)
		if got[1][0] != c.resp {
			t.Errorf("code %d: response byte = %02x, want %02x", c.reqCode, got[1][0], c.resp)
		}
	}
}

// TestResponseCode_Explicit (1.6.3): ResponseCode=3 overrides the auto
// mapping (ipv6_radius.pcap round 3 uses Access-Reject).
func TestResponseCode_Explicit(t *testing.T) {
	cfg := &core.RadiusConfig{Code: 1, ResponseCode: 3}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if got[1][0] != 0x03 {
		t.Errorf("response byte = %02x, want 03", got[1][0])
	}
}

// TestResponse_Attrs (1.6.4): response attributes appear after the header;
// response Length reflects them.
func TestResponse_Attrs(t *testing.T) {
	cfg := &core.RadiusConfig{
		ResponseAttributes: []core.RadiusAttribute{{Type: 1, Value: "alice"}},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got[1]) != 27 {
		t.Errorf("response length = %d, want 27", len(got[1]))
	}
	if !bytes.Equal(got[1][20:27], []byte{0x01, 0x07, 'a', 'l', 'i', 'c', 'e'}) {
		t.Errorf("response attr bytes = %s, want 0107616c696365", hexStr(got[1][20:27]))
	}
}

// --- §2 字节布局 ---

// TestWire_portion (2.1.1/2.1.2): request/response exchange mirroring
// portion_Radius.pcap: ID 0x53, the 13 real attributes (extracted from the
// pcap: 219 attr bytes → Length 239), response Length 20.
func TestWire_portion(t *testing.T) {
	attrs := []core.RadiusAttribute{
		{Type: 1, Value: "enet"},
		{Type: 2, Format: "hex", Value: "71f047ccc775fff88bbcbc0289367752"},
		{Type: 6, Format: "uint32", Value: "2"},
		{Type: 89, Format: "hex", Value: "00"},
		{Type: 44, Value: "1533275"},
		{Type: 55, Format: "hex", Value: "010332043b47b883390205783c0c6468637063642d352e352e360c18616e64726f69642d32323763343463323732633636306635370a012103060f1a1c333a3b520f010d67652d302f312f373a34303032", VendorID: 4874},
		{Type: 57, Format: "ipv4", Value: "59.71.191.254", VendorID: 4874},
		{Type: 56, Value: "f49f.f3dc.90dc ", VendorID: 4874},
		{Type: 32, Value: "CUG-MX960-RE1"},
		{Type: 5, Format: "uint32", Value: "29364130"},
		{Type: 87, Value: "ge-0/1/7.4002:4002"},
		{Type: 61, Format: "uint32", Value: "15"},
		{Type: 4, Format: "ipv4", Value: "10.80.1.29"},
	}
	cfg := &core.RadiusConfig{
		Identifier: 83,
		Attributes: attrs,
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if len(got[0]) != 239 {
		t.Errorf("request length = %d, want 239 (portion_Radius)", len(got[0]))
	}
	if len(got[1]) != 20 {
		t.Errorf("response length = %d, want 20", len(got[1]))
	}
	if got[1][0] != 0x02 || got[1][1] != 0x53 {
		t.Errorf("response head = %02x %02x, want 02 53", got[1][0], got[1][1])
	}
}

// TestWire_accounting (2.1.3): radius_one.pcap — code 4, ID 0, response
// `05 00 00 14`.
func TestWire_accounting(t *testing.T) {
	cfg := &core.RadiusConfig{
		Code:       4,
		Identifier: 0,
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if got[1][0] != 0x05 || got[1][1] != 0x00 || got[1][2] != 0x00 || got[1][3] != 0x14 {
		t.Errorf("response head = %s, want 05000014", hexStr(got[1][:4]))
	}
}

// TestDirection (2.2.1): request src=Spec.SrcIP (up), response src=Spec.DstIP
// (down), same 4-tuple.
func TestDirection(t *testing.T) {
	cfg := &core.RadiusConfig{}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
	if cfgs[0].Direction != "up" || cfgs[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down", cfgs[0].Direction, cfgs[1].Direction)
	}
	if cfgs[0].L3.SrcIP != "10.0.0.1" || cfgs[0].L3.DstIP != "20.0.0.1" {
		t.Errorf("request IPs = %s→%s", cfgs[0].L3.SrcIP, cfgs[0].L3.DstIP)
	}
	if cfgs[1].L3.SrcIP != "20.0.0.1" || cfgs[1].L3.DstIP != "10.0.0.1" {
		t.Errorf("response IPs = %s→%s", cfgs[1].L3.SrcIP, cfgs[1].L3.DstIP)
	}
	if cfgs[0].L4.SrcPort != 36165 || cfgs[0].L4.DstPort != 1812 {
		t.Errorf("request ports = %d→%d", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	if cfgs[1].L4.SrcPort != 1812 || cfgs[1].L4.DstPort != 36165 {
		t.Errorf("response ports = %d→%d", cfgs[1].L4.SrcPort, cfgs[1].L4.DstPort)
	}
}

// TestIPv6 (2.2.3): IPv6 hosts → EtherType 0x86DD (ipv6_radius.pcap
// reference), IPv4 → 0x0800.
func TestIPv6(t *testing.T) {
	cfg := &core.RadiusConfig{}
	spec := radiusSpec(cfg)
	spec.SrcIP = "3ffe::200:ff:fe00:71"
	spec.DstIP = "3ffe::200:ff:fe00:7"
	cfgs := mustPlan(t, NewPlanner(), spec)
	for i, c := range cfgs {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("packet %d EtherType = %#x, want 0x86DD", i, c.L2.EtherType)
		}
	}
	if l3 := cfgs[0].L3; l3.SrcIP != "3ffe::200:ff:fe00:71" || l3.DstIP != "3ffe::200:ff:fe00:7" {
		t.Errorf("L3 IPs = %s→%s", cfgs[0].L3.SrcIP, cfgs[0].L3.DstIP)
	}
}

// --- §3 状态机 ---

// TestStateMachine_SingleRound (3.1): default config → 2 packets,
// request code 1, response code 2.
func TestStateMachine_SingleRound(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(&core.RadiusConfig{}))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
	got := udpPayloads(cfgs)
	if got[0][0] != 0x01 || got[1][0] != 0x02 {
		t.Errorf("codes = %02x/%02x, want 01/02", got[0][0], got[1][0])
	}
}

// TestStateMachine_MultiRound (3.2): Rounds=3 → 6 packets, up/down
// alternating, per-round ID increment + echo.
func TestStateMachine_MultiRound(t *testing.T) {
	cfg := &core.RadiusConfig{Rounds: 3}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	if len(cfgs) != 6 {
		t.Fatalf("got %d packets, want 6", len(cfgs))
	}
	wantDirs := []string{"up", "down", "up", "down", "up", "down"}
	wantIDs := []byte{0x00, 0x00, 0x01, 0x01, 0x02, 0x02}
	got := udpPayloads(cfgs)
	for i := 0; i < 6; i++ {
		if cfgs[i].Direction != wantDirs[i] {
			t.Errorf("packet %d direction = %s, want %s", i, cfgs[i].Direction, wantDirs[i])
		}
		if got[i][1] != wantIDs[i] {
			t.Errorf("packet %d ID = %02x, want %02x", i, got[i][1], wantIDs[i])
		}
	}
}

// TestStateMachine_Accounting (3.4): code 4 → default Acct-* attributes,
// response code 5.
func TestStateMachine_Accounting(t *testing.T) {
	cfg := &core.RadiusConfig{Code: 4}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if got[0][0] != 0x04 || got[1][0] != 0x05 {
		t.Errorf("codes = %02x/%02x, want 04/05", got[0][0], got[1][0])
	}
	// default attrs: Acct-Status-Type(40)=1 (uint32) + Acct-Session-Id(44)="session-0001"
	wantAttrs := "2806000000012c0e73657373696f6e2d30303031"
	if hexStr(got[0][20:]) != wantAttrs {
		t.Errorf("default attrs = %s, want %s", hexStr(got[0][20:]), wantAttrs)
	}
}

// TestStateMachine_Reject (3.5): code 1 with explicit response 3.
func TestStateMachine_Reject(t *testing.T) {
	cfg := &core.RadiusConfig{ResponseCode: 3}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if got[1][0] != 0x03 {
		t.Errorf("response code = %02x, want 03", got[1][0])
	}
}

// --- §4 业务场景 ---

// TestScenario_DefaultAttrs (5.1): empty Attributes → User-Name "user"
// `01 06 75 73 65 72` for code 1.
func TestScenario_DefaultAttrs(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(&core.RadiusConfig{}))
	got := udpPayloads(cfgs)
	if hexStr(got[0][20:]) != "010675736572" {
		t.Errorf("default attrs = %s, want 010675736572", hexStr(got[0][20:]))
	}
}

// TestScenario_CHAP (4.5): CHAP-Password(3) hex 17 bytes + CHAP-Challenge(60)
// hex 16 bytes (ipv6_radius.pcap frame 1 attributes).
func TestScenario_CHAP(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 3, Format: "hex", Value: "016397e30fb44f6bd3a1aa01698cf0800d"},
			{Type: 60, Format: "hex", Value: "3786f5aa172cbffe19a443ce15dafba8"},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if hexStr(got[0][20:39]) != "0313016397e30fb44f6bd3a1aa01698cf0800d" {
		t.Errorf("CHAP-Password bytes = %s", hexStr(got[0][20:39]))
	}
	if hexStr(got[0][39:57]) != "3c123786f5aa172cbffe19a443ce15dafba8" {
		t.Errorf("CHAP-Challenge bytes = %s", hexStr(got[0][39:57]))
	}
}

// TestScenario_MultiRoundIPv6 (4.4): IPv6 hosts, 3 rounds — 6 IPv6 packets
// (ipv6_radius.pcap shape).
func TestScenario_MultiRoundIPv6(t *testing.T) {
	cfg := &core.RadiusConfig{Identifier: 2, Rounds: 3}
	spec := radiusSpec(cfg)
	spec.SrcIP = "3ffe::200:ff:fe00:71"
	spec.DstIP = "3ffe::200:ff:fe00:7"
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 6 {
		t.Fatalf("got %d packets, want 6", len(cfgs))
	}
	for i, c := range cfgs {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("packet %d EtherType = %#x, want 0x86DD", i, c.L2.EtherType)
		}
	}
}

// --- §6 边界 / 异常 ---

// TestDefaults_AllEmpty (6.1): RadiusConfig{} → code 1, ID 0, random
// auth, default attrs, response code 2, echoed ID.
func TestDefaults_AllEmpty(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(&core.RadiusConfig{}))
	got := udpPayloads(cfgs)
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if got[0][0] != 0x01 || got[1][0] != 0x02 {
		t.Errorf("codes = %02x/%02x, want 01/02", got[0][0], got[1][0])
	}
	if got[0][1] != 0x00 || got[1][1] != 0x00 {
		t.Errorf("IDs = %02x/%02x, want 00/00", got[0][1], got[1][1])
	}
	if len(got[0]) != 26 || len(got[1]) != 20 {
		t.Errorf("lengths = %d/%d, want 26/20", len(got[0]), len(got[1]))
	}
}

// TestRounds_Zero (6.8): Rounds=0 → treated as 1 round.
func TestRounds_Zero(t *testing.T) {
	cfg := &core.RadiusConfig{Rounds: 0}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
}

// TestID_Wrap (6.9): Identifier=255, Rounds=2 → IDs 0xFF/0x00.
func TestID_Wrap(t *testing.T) {
	cfg := &core.RadiusConfig{Identifier: 255, Rounds: 2}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	want := []byte{0xFF, 0xFF, 0x00, 0x00}
	for i, w := range want {
		if got[i][1] != w {
			t.Errorf("packet %d ID = %02x, want %02x", i, got[i][1], w)
		}
	}
}

// TestVendorID_Max (6.11): VendorID=0xFFFFFFFF → 4-byte big-endian.
func TestVendorID_Max(t *testing.T) {
	cfg := &core.RadiusConfig{
		Attributes: []core.RadiusAttribute{
			{Type: 1, Value: "x", VendorID: 0xFFFFFFFF},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), radiusSpec(cfg))
	got := udpPayloads(cfgs)
	if hexStr(got[0][20:29]) != "1a09ffffffff010378" {
		t.Errorf("VSA bytes = %s, want 1a09ffffffff010378", hexStr(got[0][20:29]))
	}
}

// TestEncodeAttr_Overflow (6.12): encodeRadiusAttribute called directly
// with an oversized value returns an error instead of truncating the
// 1-byte Length field.
func TestEncodeAttr_Overflow(t *testing.T) {
	over := string(make([]byte, 254))
	if _, err := encodeRadiusAttribute(core.RadiusAttribute{Type: 1, Value: over}); err == nil {
		t.Error("plain attr 254 bytes: encode returned nil, want error")
	}
	overVSA := string(make([]byte, 248))
	if _, err := encodeRadiusAttribute(core.RadiusAttribute{Type: 1, Value: overVSA, VendorID: 2011}); err == nil {
		t.Error("VSA attr 248 bytes: encode returned nil, want error")
	}
	// boundary: 253 plain / 247 VSA still encode
	if b, err := encodeRadiusAttribute(core.RadiusAttribute{Type: 1, Value: string(make([]byte, 253))}); err != nil || len(b) != 255 {
		t.Errorf("plain 253 bytes: err=%v len=%d, want 255", err, len(b))
	}
	if b, err := encodeRadiusAttribute(core.RadiusAttribute{Type: 1, Value: string(make([]byte, 247)), VendorID: 2011}); err != nil || len(b) != 255 {
		t.Errorf("VSA 247 bytes: err=%v len=%d, want 255", err, len(b))
	}
}

// TestPortDefault (S1): DstPort=0 → 1812 (code 1) / 1813 (code 4).
func TestPortDefault(t *testing.T) {
	for _, c := range []struct {
		code int
		port uint16
	}{{1, 1812}, {4, 1813}} {
		cfg := &core.RadiusConfig{Code: c.code}
		spec := radiusSpec(cfg)
		spec.DstPort = 0
		cfgs := mustPlan(t, NewPlanner(), spec)
		if cfgs[0].L4.DstPort != c.port {
			t.Errorf("code %d: DstPort = %d, want %d", c.code, cfgs[0].L4.DstPort, c.port)
		}
	}
}

// --- §8 Validate ---

func TestValidate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.RadiusConfig
	}{
		{"response code as request", &core.RadiusConfig{Code: 2}},
		{"response code as request 5", &core.RadiusConfig{Code: 5}},
		{"response code as request 13", &core.RadiusConfig{Code: 13}},
		{"invalid code", &core.RadiusConfig{Code: 7}},
		{"invalid response code", &core.RadiusConfig{ResponseCode: 1}},
		{"invalid response code 4", &core.RadiusConfig{ResponseCode: 4}},
		{"no auto response for code 3", &core.RadiusConfig{Code: 3}},
		{"no auto response for code 11", &core.RadiusConfig{Code: 11}},
		{"attr value too long", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 1, Value: string(make([]byte, 254))}}}},
		{"vsa value too long", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 1, Value: string(make([]byte, 248)), VendorID: 2011}}}},
		{"hex decodes past plain limit", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 2, Format: "hex", Value: hex.EncodeToString(make([]byte, 254))}}}},
		{"hex decodes past vsa limit", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 55, Format: "hex", Value: hex.EncodeToString(make([]byte, 248)), VendorID: 4874}}}},
		{"bad ipv4", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 4, Format: "ipv4", Value: "999.1.1.1"}}}},
		{"ipv6 in ipv4 format", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 4, Format: "ipv4", Value: "2001:db8::1"}}}},
		{"bad hex", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 2, Format: "hex", Value: "zz"}}}},
		{"unknown format", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 1, Format: "octet", Value: "x"}}}},
		{"bad source IP", &core.RadiusConfig{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := radiusSpec(c.cfg)
			if c.name == "bad source IP" {
				spec.SrcIP = "999.1.1.1"
			}
			if err := NewPlanner().Validate(spec); err == nil {
				t.Errorf("Validate(%s) returned nil, want error", c.name)
			}
		})
	}
}

func TestValidate_Acceptance(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.RadiusConfig
	}{
		{"all empty", &core.RadiusConfig{}},
		{"code 3 with explicit response", &core.RadiusConfig{Code: 3, ResponseCode: 2}},
		{"code 11 with explicit response", &core.RadiusConfig{Code: 11, ResponseCode: 2}},
		{"code 12 auto response", &core.RadiusConfig{Code: 12}},
		{"code 4", &core.RadiusConfig{Code: 4}},
		{"explicit response 13", &core.RadiusConfig{Code: 12, ResponseCode: 13}},
		{"response attrs", &core.RadiusConfig{ResponseAttributes: []core.RadiusAttribute{{Type: 1, Value: "alice"}}}},
		{"multi-round", &core.RadiusConfig{Rounds: 3}},
		{"string 253 bytes", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 1, Value: string(make([]byte, 253))}}}},
		{"vsa max value", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 1, Value: string(make([]byte, 246)), VendorID: 2011}}}},
		{"hex decodes to 253 bytes", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 2, Format: "hex", Value: hex.EncodeToString(make([]byte, 253))}}}},
		{"hex decodes to 247 bytes vsa", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 55, Format: "hex", Value: hex.EncodeToString(make([]byte, 247)), VendorID: 4874}}}},
		{"vsa value empty", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 55, VendorID: 4874}}}},
		{"ipv4 format", &core.RadiusConfig{Attributes: []core.RadiusAttribute{{Type: 4, Format: "ipv4", Value: "10.0.0.1"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := NewPlanner().Validate(radiusSpec(c.cfg)); err != nil {
				t.Errorf("Validate(%s) returned error: %v", c.name, err)
			}
		})
	}
}

// TestValidate_Code3NeedsExplicitResponse: covered in TestValidate_Errors.
// TestPlan_ContextCancel: Plan must drain cleanly on cancelled context.
func TestPlan_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := NewPlanner().Plan(ctx, radiusSpec(&core.RadiusConfig{}))
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	if n := len(drain(ch)); n != 0 {
		t.Errorf("cancelled plan emitted %d packets, want 0", n)
	}
}
