package rip

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
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

func ripSpec(cfg *core.RIPConfig) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 52001,
		DstPort: 520,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
	}
	spec.RIP = cfg
	return spec
}

// T-POS-1: RIP v2 Request 全量路由 (request_full scenario)
// Payload: 01 02 00 00 (RIP头: Command=1 Request, Version=2, Domain=0)
// Entry: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
//   - AFI=0x0000 (RFC 2453 §3.9.1)
//   - RouteTag/IP/Mask/NextHop all zero, Metric=16 (infinity)
//
// DstIP=224.0.0.9 (multicast), TTL=1 (design T-POS-1 / R-5.05).
func TestTPOS1_RequestFull(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v2",
		Command:   "request",
		Scenario:  "request_full",
		Multicast: true,
		Routes:    []core.RIPRoute{},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	// request_full generates 2 packets: Request + Response
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}

	// Check first packet is Request
	payload := cfgs[0].Payload
	if len(payload) < 24 {
		t.Fatalf("payload too short: %d bytes", len(payload))
	}

	// RIP header: Command=1, Version=2, Domain=0
	if payload[0] != 0x01 {
		t.Errorf("Command = %02x, want 01", payload[0])
	}
	if payload[1] != 0x02 {
		t.Errorf("Version = %02x, want 02", payload[1])
	}
	if payload[2] != 0x00 || payload[3] != 0x00 {
		t.Errorf("Domain = %02x%02x, want 0000", payload[2], payload[3])
	}

	// Entry: AFI=0x0000 (RFC 2453 §3.9.1 full-route request)
	if afi := binary.BigEndian.Uint16(payload[4:6]); afi != 0x0000 {
		t.Errorf("AFI = %04x, want 0000", afi)
	}

	// RouteTag=0, IP=0.0.0.0, Mask=0, NextHop=0 (offset 6-20)
	if !bytes.Equal(payload[6:20], make([]byte, 14)) {
		t.Errorf("request entry fields = %x, want all zeros", payload[6:20])
	}

	// Metric = 16 (infinity), offset 20-23
	if metric := binary.BigEndian.Uint32(payload[20:24]); metric != 16 {
		t.Errorf("Metric = %d, want 16", metric)
	}

	// DstIP = 224.0.0.9, TTL = 1, DstPort = 520
	if cfgs[0].L3.DstIP != "224.0.0.9" {
		t.Errorf("DstIP = %s, want 224.0.0.9", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL = %d, want 1", cfgs[0].L3.TTL)
	}
	if cfgs[0].L4.DstPort != 520 {
		t.Errorf("DstPort = %d, want 520", cfgs[0].L4.DstPort)
	}

	// Response packet (packet 2): Command=2, same FlowID, PacketIndex=1,
	// default 5 routes (design T-POS-1b).
	if cfgs[1].Payload[0] != 0x02 {
		t.Errorf("Response Command = %02x, want 02", cfgs[1].Payload[0])
	}
	if cfgs[1].FlowID != cfgs[0].FlowID {
		t.Errorf("Response FlowID %s != Request FlowID %s", cfgs[1].FlowID, cfgs[0].FlowID)
	}
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}
	// Response carries the 5 default routes: 4 + 5*20 = 104 bytes
	if len(cfgs[1].Payload) != 104 {
		t.Errorf("Response payload len = %d, want 104 (5 default routes)", len(cfgs[1].Payload))
	}
	// Same-direction 4-tuple (design §6.1 / R-4.04)
	if cfgs[1].L3.SrcIP != cfgs[0].L3.SrcIP || cfgs[1].L3.DstIP != cfgs[0].L3.DstIP ||
		cfgs[1].L4.SrcPort != cfgs[0].L4.SrcPort || cfgs[1].L4.DstPort != cfgs[0].L4.DstPort {
		t.Errorf("Response 4-tuple differs from Request: %v vs %v",
			cfgs[1], cfgs[0])
	}
}

// T-POS-4: RIP v1 Response 无掩码
// Version=1, Entry 偏移 8-11=0, 偏移 12-15=0, Metric=1 (payload offset 20-23),
// v1 multicast=true -> DstIP=255.255.255.255 (T-POS-32 配套).
func TestTPOS4_RIPv1NoMask(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v1",
		Command:   "response",
		Multicast: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", Metric: 1},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}

	payload := cfgs[0].Payload
	if len(payload) != 24 {
		t.Fatalf("payload length = %d, want 24", len(payload))
	}

	// RIP header: Command=2, Version=1
	if !bytes.Equal(payload[0:2], []byte{0x02, 0x01}) {
		t.Errorf("RIP header = %02x%02x, want 02 01", payload[0], payload[1])
	}

	// AFI=2
	if afi := binary.BigEndian.Uint16(payload[4:6]); afi != 2 {
		t.Errorf("AFI = %04x, want 0002", afi)
	}
	// MustBeZero (offset 6-7)
	if !bytes.Equal(payload[6:8], make([]byte, 2)) {
		t.Errorf("MustBeZero = %x, want zeros", payload[6:8])
	}
	// IP=10.0.0.0
	if !bytes.Equal(payload[8:12], net.ParseIP("10.0.0.0").To4()) {
		t.Errorf("IP = %v, want 10.0.0.0", payload[8:12])
	}
	// v1: mask=0 (offset 12-15) and next-hop=0 (offset 16-19)
	if !bytes.Equal(payload[12:20], make([]byte, 8)) {
		t.Errorf("v1 zero fields = %x, want 8 zero bytes", payload[12:20])
	}
	// Metric = 1 at payload offset 20-23
	if metric := binary.BigEndian.Uint32(payload[20:24]); metric != 1 {
		t.Errorf("Metric = %d, want 1", metric)
	}

	// v1 multicast -> broadcast DstIP 255.255.255.255, TTL=1
	if cfgs[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("DstIP = %s, want 255.255.255.255", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL = %d, want 1", cfgs[0].L3.TTL)
	}
}

// T-POS-6: RIP v2 组播更新 TTL=1
// DstIP=224.0.0.9, TTL=1, SrcPort=520 (RFC 2453 §3.6: Response from port 520).
func TestTPOS6_MulticastUpdate(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v2",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0 // no explicit src port: Response must use 520
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}

	// Check TTL=1
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL = %d, want 1", cfgs[0].L3.TTL)
	}

	// Check DstIP is multicast
	if cfgs[0].L3.DstIP != "224.0.0.9" {
		t.Errorf("DstIP = %s, want 224.0.0.9", cfgs[0].L3.DstIP)
	}

	// Check SrcPort=520 (Response from the well-known port)
	if cfgs[0].L4.SrcPort != 520 {
		t.Errorf("SrcPort = %d, want 520", cfgs[0].L4.SrcPort)
	}
	if cfgs[0].L4.DstPort != 520 {
		t.Errorf("DstPort = %d, want 520", cfgs[0].L4.DstPort)
	}
}

// T-POS-8: RIP v2 明文认证
// 第 1 entry AFI=0xFFFF, AuthType=0x0002, 16B 密码
func TestTPOS8_SimpleAuth(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:     "simple",
			Password: "secret123",
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}

	payload := cfgs[0].Payload
	if len(payload) < 44 { // 4 (header) + 20 (auth) + 20 (route)
		t.Fatalf("payload too short: %d bytes", len(payload))
	}

	// First entry is auth: AFI=0xFFFF
	afi := binary.BigEndian.Uint16(payload[4:6])
	if afi != 0xFFFF {
		t.Errorf("Auth AFI = %04x, want FFFF", afi)
	}

	// AuthType = 0x0002 (simple)
	authType := binary.BigEndian.Uint16(payload[6:8])
	if authType != 0x0002 {
		t.Errorf("Auth Type = %04x, want 0002", authType)
	}

	// Password starts at offset 8, up to 16 bytes
	pwdBytes := payload[8:24]
	if !bytes.HasPrefix(pwdBytes, []byte("secret123")) {
		t.Errorf("Password bytes = %s, want secret123...", hex.EncodeToString(pwdBytes))
	}
	// Zero padding for the remaining 7 bytes (9-byte password)
	if !bytes.Equal(pwdBytes[9:], make([]byte, 7)) {
		t.Errorf("Password padding = %x, want 7 zero bytes", pwdBytes[9:])
	}
	// Route entry follows at offset 24: AFI=2, IP=10.0.0.0
	if afi := binary.BigEndian.Uint16(payload[24:26]); afi != 2 {
		t.Errorf("route AFI = %04x, want 0002", afi)
	}
	if !bytes.Equal(payload[28:32], net.ParseIP("10.0.0.0").To4()) {
		t.Errorf("route IP = %v, want 10.0.0.0", payload[28:32])
	}
}

// T-POS-9: RIP v2 MD5 认证
// Payload[6:8]=00 03, PacketLength=44, KeyID=1, AuthDataLen=16,
// SeqNum=12345, MustBeZero=0, trailer FF FF 00 01, digest 16B 0xAA,
// 完整 Payload 长度 = 64B (design §6.8, T-POS-9).
func TestTPOS9_MD5Auth(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:           "md5",
			KeyID:          1,
			AuthDataLen:    ptr(uint8(16)),
			SequenceNumber: 12345,
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}

	payload := cfgs[0].Payload
	if len(payload) != 64 { // 4 header + 20 auth + 20 route + 4 trailer + 16 digest
		t.Fatalf("payload length = %d, want 64", len(payload))
	}

	// Auth entry AFI = 0xFFFF
	if afi := binary.BigEndian.Uint16(payload[4:6]); afi != 0xFFFF {
		t.Errorf("Auth AFI = %04x, want FFFF", afi)
	}

	// Auth entry AuthType = 0x0003 (MD5)
	if authType := binary.BigEndian.Uint16(payload[6:8]); authType != 0x0003 {
		t.Errorf("Auth Type = %04x, want 0003", authType)
	}

	// RIPv2 Packet Length = 4 + 20*(1+1) = 44
	if packetLen := binary.BigEndian.Uint16(payload[8:10]); packetLen != 44 {
		t.Errorf("Packet Length = %d, want 44", packetLen)
	}

	// KeyID = 1 (offset 10)
	if payload[10] != 1 {
		t.Errorf("KeyID = %d, want 1", payload[10])
	}

	// AuthDataLen = 16 (offset 11)
	if payload[11] != 16 {
		t.Errorf("AuthDataLen = %d, want 16", payload[11])
	}

	// SeqNum = 12345 (offset 12-15)
	if seq := binary.BigEndian.Uint32(payload[12:16]); seq != 12345 {
		t.Errorf("SeqNum = %d, want 12345", seq)
	}

	// MustBeZero = 0 (offset 16-23)
	if !bytes.Equal(payload[16:24], make([]byte, 8)) {
		t.Errorf("MustBeZero = %v, want 8 zero bytes", payload[16:24])
	}

	// Route entry follows: AFI=2, IP=10.0.0.0, mask=255.0.0.0, metric=1
	if afi := binary.BigEndian.Uint16(payload[24:26]); afi != 2 {
		t.Errorf("route AFI = %04x, want 0002", afi)
	}
	if !bytes.Equal(payload[28:32], net.ParseIP("10.0.0.0").To4()) {
		t.Errorf("route IP = %v, want 10.0.0.0", payload[28:32])
	}
	if !bytes.Equal(payload[32:36], net.ParseIP("255.0.0.0").To4()) {
		t.Errorf("route mask = %v, want 255.0.0.0", payload[32:36])
	}
	if m := binary.BigEndian.Uint32(payload[40:44]); m != 1 {
		t.Errorf("route metric = %d, want 1", m)
	}

	// Trailer header at offset 44: FF FF 00 01 (Auth Marker + Type=0x0001)
	if !bytes.Equal(payload[44:48], []byte{0xFF, 0xFF, 0x00, 0x01}) {
		t.Errorf("Trailer header = %s, want ffff0001", hex.EncodeToString(payload[44:48]))
	}

	// Digest placeholder: 16 bytes of 0xAA (offset 48-63)
	for i := 48; i < 64; i++ {
		if payload[i] != 0xAA {
			t.Errorf("digest[%d] = %02x, want aa", i, payload[i])
		}
	}
}

// T-POS-14: RIPng IPv6 组播
// DstIP=FF02::9, DstPort=521, Version=1, EtherType=0x86DD, TTL=1
// Entry: 16B prefix + 2B RouteTag + 1B PrefixLen + 1B Metric (design T-POS-14).
func TestTPOS14_RIPngIPv6(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "ng",
		Command:   "response",
		Multicast: true,
		Routes: []core.RIPRoute{
			{IPAddr: "2001:db8::", PrefixLen: 64, Metric: 1},
		},
	}
	spec := ripSpec(cfg)
	spec.SrcIP = "2001:db8::1"
	spec.DstPort = 0 // planner derives 521 for RIPng
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}

	payload := cfgs[0].Payload
	if len(payload) != 24 { // 4 header + 20 entry
		t.Fatalf("payload length = %d, want 24", len(payload))
	}

	// Full RIP header: Command=2, Version=1, Domain=0 (R-4.05)
	if !bytes.Equal(payload[0:4], []byte{0x02, 0x01, 0x00, 0x00}) {
		t.Errorf("RIP header = %x, want 02 01 00 00", payload[0:4])
	}

	// IPv6 prefix 2001:db8:: (offset 4-19)
	if !bytes.Equal(payload[4:20], net.ParseIP("2001:db8::")) {
		t.Errorf("prefix = %v, want 2001:db8::", payload[4:20])
	}
	// RouteTag = 0 (offset 20-21), PrefixLen = 64 (offset 22), Metric = 1 (offset 23)
	if rt := binary.BigEndian.Uint16(payload[20:22]); rt != 0 {
		t.Errorf("RouteTag = %d, want 0", rt)
	}
	if payload[22] != 64 {
		t.Errorf("PrefixLen = %d, want 64", payload[22])
	}
	if payload[23] != 1 {
		t.Errorf("Metric = %d, want 1", payload[23])
	}

	// Check DstPort=521 (RIPng), DstIP=FF02::9, TTL=1, EtherType=0x86DD
	if cfgs[0].L4.DstPort != 521 {
		t.Errorf("DstPort = %d, want 521", cfgs[0].L4.DstPort)
	}
	if cfgs[0].L3.DstIP != "FF02::9" {
		t.Errorf("DstIP = %s, want FF02::9", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL = %d, want 1", cfgs[0].L3.TTL)
	}
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType = %04x, want 86DD", cfgs[0].L2.EtherType)
	}
}

// T-POS-16: 多路由器 3 路由器并发
func TestTPOS16_MultiRouter(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routers: []core.RIPRouter{
			{SrcIP: "192.168.1.1", SrcPort: 52001},
			{SrcIP: "192.168.1.2", SrcPort: 52002},
			{SrcIP: "192.168.2.1", SrcPort: 52003},
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	// 3 routers, each sends 1 packet
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(cfgs))
	}

	// Check each router has its own FlowID
	for i, c := range cfgs {
		if c.FlowID == "" {
			t.Errorf("packet %d has empty FlowID", i)
		}
	}
}

// T-EDGE-1: Metric=0 报错
func TestTEdge1_MetricZero(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 0}},
	}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for metric=0, got nil")
	}
}

// T-EDGE-4: Metric=17 报错
func TestTEdge4_Metric17(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 17}},
	}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for metric=17, got nil")
	}
}

// T-EDGE-8: Route entry 数=26 拆 2 包
func TestTEdge8_Split26Entries(t *testing.T) {
	// Generate 26 routes
	routes := make([]core.RIPRoute, 26)
	for i := 0; i < 26; i++ {
		routes[i] = core.RIPRoute{
			IPAddr:     "10.0.0.0",
			SubnetMask: "255.0.0.0",
			Metric:     1,
		}
	}
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  routes,
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	// 26 entries = 25 + 1, so 2 packets
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}

	// Check FlowID is same for both packets
	if cfgs[0].FlowID != cfgs[1].FlowID {
		t.Errorf("FlowID mismatch: %s vs %s", cfgs[0].FlowID, cfgs[1].FlowID)
	}

	// Check PacketIndex increments
	if cfgs[0].PacketIndex != 0 {
		t.Errorf("PacketIndex[0] = %d, want 0", cfgs[0].PacketIndex)
	}
	if cfgs[1].PacketIndex != 1 {
		t.Errorf("PacketIndex[1] = %d, want 1", cfgs[1].PacketIndex)
	}
}

// T-ERR-1: Version="v3" 报错
func TestTErr1_InvalidVersion(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v3",
	}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for version=v3, got nil")
	}
}

// T-ERR-8: Auth 非 nil + Version="v1" 报错
func TestTErr8_AuthOnV1(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v1",
		Auth:    &core.RIPAuth{Type: "simple", Password: "secret"},
	}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for auth on v1, got nil")
	}
}

// T-ERR-10: Auth.Password > 16 字节 报错
func TestTErr10_PasswordTooLong(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Auth:    &core.RIPAuth{Type: "simple", Password: "this_is_17_bytes!"},
	}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for password > 16 bytes, got nil")
	}
}

// Helper to create uint8 pointer
func ptr(u uint8) *uint8 {
	return &u
}

// makeRoutes builds n route entries for split tests.
func makeRoutes(n int) []core.RIPRoute {
	routes := make([]core.RIPRoute, n)
	for i := 0; i < n; i++ {
		routes[i] = core.RIPRoute{
			IPAddr:     "10.0.0.0",
			SubnetMask: "255.0.0.0",
			Metric:     1,
		}
	}
	return routes
}

// T-POS-3: RIP v2 Response 26 entry 拆 2 包 (25+1, 同 FlowID)
func TestTPOS3_Split26(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: makeRoutes(26)}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	if len(cfgs[0].Payload) != 4+25*20 {
		t.Errorf("packet0 payload = %d, want %d", len(cfgs[0].Payload), 4+25*20)
	}
	if len(cfgs[1].Payload) != 4+1*20 {
		t.Errorf("packet1 payload = %d, want %d", len(cfgs[1].Payload), 4+1*20)
	}
	if cfgs[0].FlowID != cfgs[1].FlowID {
		t.Errorf("FlowID mismatch: %s vs %s", cfgs[0].FlowID, cfgs[1].FlowID)
	}
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}
	// Both packets are independent complete RIP messages with own headers
	if cfgs[0].Payload[0] != 0x02 || cfgs[1].Payload[0] != 0x02 {
		t.Errorf("command bytes = %02x/%02x, want 02/02", cfgs[0].Payload[0], cfgs[1].Payload[0])
	}
}

// T-POS-7: RIP v2 组播 Rounds=3 -> 3 个 PacketConfig, 同 FlowID, Index 0/1/2
func TestTPOS7_Rounds(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v2",
		Command:   "response",
		Multicast: true,
		Rounds:    3,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(cfgs))
	}
	for i, c := range cfgs {
		if c.FlowID != cfgs[0].FlowID {
			t.Errorf("packet %d FlowID %s != %s", i, c.FlowID, cfgs[0].FlowID)
		}
		if c.PacketIndex != uint64(i) {
			t.Errorf("packet %d PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
		if c.L3.TTL != 1 {
			t.Errorf("packet %d TTL = %d, want 1", i, c.L3.TTL)
		}
		if c.L4.SrcPort != 520 {
			t.Errorf("packet %d SrcPort = %d, want 520", i, c.L4.SrcPort)
		}
	}
}

// T-POS-10: 路由毒化 metric=16
func TestTPOS10_RoutePoison(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 16},
			{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", Metric: 1},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	// First entry metric=16
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[20:24]); m != 16 {
		t.Errorf("metric[0] = %d, want 16", m)
	}
	// Second entry metric=1
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[40:44]); m != 1 {
		t.Errorf("metric[1] = %d, want 1", m)
	}
}

// T-POS-11: 水平分割 - NextHop==DstIP 的路由被过滤
func TestTPOS11_SplitHorizon(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:      "v2",
		Command:      "response",
		SplitHorizon: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", NextHop: "192.168.1.2", Metric: 1},
			{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", NextHop: "192.168.1.1", Metric: 1},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	// Only 1 entry remains (the 10.0.0.0/8 route with NextHop==DstIP is filtered)
	if len(cfgs[0].Payload) != 4+20 {
		t.Errorf("payload len = %d, want 24 (1 entry)", len(cfgs[0].Payload))
	}
	if !bytes.Equal(cfgs[0].Payload[8:12], net.ParseIP("172.16.0.0").To4()) {
		t.Errorf("remaining route IP = %v, want 172.16.0.0", cfgs[0].Payload[8:12])
	}
}

// T-POS-12: 毒化反转 - NextHop==DstIP 的路由 metric 改 16 仍发出
func TestTPOS12_PoisonReverse(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:       "v2",
		Command:       "response",
		PoisonReverse: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", NextHop: "192.168.1.2", Metric: 1},
			{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", NextHop: "192.168.1.1", Metric: 1},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	// Both entries kept, first with metric 16
	if len(cfgs[0].Payload) != 4+40 {
		t.Errorf("payload len = %d, want 44 (2 entries)", len(cfgs[0].Payload))
	}
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[20:24]); m != 16 {
		t.Errorf("poisoned metric = %d, want 16", m)
	}
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[40:44]); m != 1 {
		t.Errorf("second metric = %d, want 1", m)
	}
}

// T-POS-13: 触发更新 - 仅 Response, 无 Request 前导, Rounds=1
func TestTPOS13_TriggeredUpdate(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:         "v2",
		Command:         "request", // ignored: TriggeredUpdate forces Response
		TriggeredUpdate: true,
		Routes:          []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 16}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != 0x02 {
		t.Errorf("Command = %02x, want 02 (Response)", cfgs[0].Payload[0])
	}
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[20:24]); m != 16 {
		t.Errorf("metric = %d, want 16", m)
	}
}

// T-POS-18 / T-EDGE-20: Routes=nil + Scenario="" -> response_default (5 routes)
func TestTPOS18_DefaultScenario(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response"}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	// 4 header + 5*20 = 104
	if len(cfgs[0].Payload) != 104 {
		t.Errorf("payload len = %d, want 104 (5 default routes)", len(cfgs[0].Payload))
	}
	if cfgs[0].Payload[0] != 0x02 {
		t.Errorf("Command = %02x, want 02", cfgs[0].Payload[0])
	}
	// First default route 10.0.0.0/8
	if !bytes.Equal(cfgs[0].Payload[8:12], net.ParseIP("10.0.0.0").To4()) {
		t.Errorf("first default route = %v, want 10.0.0.0", cfgs[0].Payload[8:12])
	}
}

// T-POS-27 / T-POS-31: Auth + 25 routes -> 首包 1 认证 + 24 路由 (524B MD5),
// 第 2 包 1 路由且无认证 trailer (RFC 4822 §2.1).
func TestTPOS27_AuthMultiPacket(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:           "md5",
			KeyID:          1,
			AuthDataLen:    ptr(uint8(16)),
			SequenceNumber: 12345,
		},
		Routes: makeRoutes(25),
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	// First packet: 4 + 20*1(auth) + 24*20 + 4(trailer) + 16(digest) = 524
	if len(cfgs[0].Payload) != 524 {
		t.Errorf("packet0 payload = %d, want 524", len(cfgs[0].Payload))
	}
	// Auth entry present
	if afi := binary.BigEndian.Uint16(cfgs[0].Payload[4:6]); afi != 0xFFFF {
		t.Errorf("packet0 AFI = %04x, want FFFF", afi)
	}
	// PacketLength = 4 + 20*(1+24) = 504
	if pl := binary.BigEndian.Uint16(cfgs[0].Payload[8:10]); pl != 504 {
		t.Errorf("packet0 PacketLength = %d, want 504", pl)
	}
	// Trailer + digest at the end
	if !bytes.Equal(cfgs[0].Payload[504:508], []byte{0xFF, 0xFF, 0x00, 0x01}) {
		t.Errorf("packet0 trailer = %x, want ffff0001", cfgs[0].Payload[504:508])
	}
	// Second packet: 4 + 20*1 = 24, no auth, no trailer
	if len(cfgs[1].Payload) != 24 {
		t.Errorf("packet1 payload = %d, want 24", len(cfgs[1].Payload))
	}
	if afi := binary.BigEndian.Uint16(cfgs[1].Payload[4:6]); afi == 0xFFFF {
		t.Errorf("packet1 must not carry an auth entry")
	}
	if len(cfgs[1].Payload) > 24 {
		t.Errorf("packet1 has unexpected trailer bytes")
	}
	// Same FlowID, PacketIndex 0/1
	if cfgs[0].FlowID != cfgs[1].FlowID {
		t.Errorf("FlowID mismatch")
	}
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}
}

// T-POS-27b: B-17 回归 — 26 routes + MD5 auth → 2 包 (24+2).
// 修复前：maxRTE 在循环外一次性计算为 24，导致后续包也被限制为 24，
// 26 条路由被拆成 24+1+1（3 包）。修复后：maxRTE 按包独立计算，
// 首包 24 条（受 auth 限制），后续包恢复 25 条上限，26 条路由拆成 24+2（2 包）。
func TestTPOS27b_AuthSplitB17Fix(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:           "md5",
			KeyID:          1,
			AuthDataLen:    ptr(uint8(16)),
			SequenceNumber: 12345,
		},
		Routes: makeRoutes(26),
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	// First packet: 4 + 20*(1+24) + 4 + 16 = 524 B (1 auth + 24 routes + MD5 trailer)
	if len(cfgs[0].Payload) != 524 {
		t.Errorf("packet0 payload = %d, want 524", len(cfgs[0].Payload))
	}
	// Auth entry present in first packet
	if afi := binary.BigEndian.Uint16(cfgs[0].Payload[4:6]); afi != 0xFFFF {
		t.Errorf("packet0 AFI = %04x, want FFFF", afi)
	}
	// PacketLength = 4 + 20*(1+24) = 504
	if pl := binary.BigEndian.Uint16(cfgs[0].Payload[8:10]); pl != 504 {
		t.Errorf("packet0 PacketLength = %d, want 504", pl)
	}
	// MD5 trailer at end of first packet
	if !bytes.Equal(cfgs[0].Payload[504:508], []byte{0xFF, 0xFF, 0x00, 0x01}) {
		t.Errorf("packet0 trailer = %x, want ffff0001", cfgs[0].Payload[504:508])
	}
	// Second packet: 4 + 20*2 = 44 B (2 routes, no auth, no trailer)
	if len(cfgs[1].Payload) != 44 {
		t.Errorf("packet1 payload = %d, want 44", len(cfgs[1].Payload))
	}
	if afi := binary.BigEndian.Uint16(cfgs[1].Payload[4:6]); afi == 0xFFFF {
		t.Errorf("packet1 must not carry an auth entry")
	}
	if len(cfgs[1].Payload) > 44 {
		t.Errorf("packet1 has unexpected trailer bytes")
	}
	// Same FlowID, PacketIndex 0/1
	if cfgs[0].FlowID != cfgs[1].FlowID {
		t.Errorf("FlowID mismatch")
	}
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}
}

// T-POS-32: v1 + multicast=true -> DstIP=255.255.255.255, TTL=1, 忽略用户 DstIP
func TestTPOS32_V1Broadcast(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v1",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.DstIP = "192.168.1.99" // ignored under multicast
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if cfgs[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("DstIP = %s, want 255.255.255.255", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL = %d, want 1", cfgs[0].L3.TTL)
	}
}

// T-POS-33: Domain=0x0001 -> RIP 头第 3-4 字节 = 00 01
func TestTPOS33_Domain(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Domain:  1,
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if !bytes.Equal(cfgs[0].Payload[2:4], []byte{0x00, 0x01}) {
		t.Errorf("Domain = %02x%02x, want 00 01", cfgs[0].Payload[2], cfgs[0].Payload[3])
	}
}

// T-POS-29: Version="" -> 默认 v2 (RIP 头 Version 字节 = 0x02)
func TestTPOS29_DefaultVersion(t *testing.T) {
	cfg := &core.RIPConfig{Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if cfgs[0].Payload[1] != 0x02 {
		t.Errorf("Version = %02x, want 02", cfgs[0].Payload[1])
	}
}

// T-POS-30: Command="" -> 默认 response
func TestTPOS30_DefaultCommand(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != 0x02 {
		t.Errorf("Command = %02x, want 02", cfgs[0].Payload[0])
	}
}

// T-POS-25: MD5 AuthDataLen=20 (trafficgen 私有扩展) -> 528B 完整 Payload
func TestTPOS25_MD5AuthDataLen20(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:           "md5",
			KeyID:          1,
			AuthDataLen:    ptr(uint8(20)),
			SequenceNumber: 12345,
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	p := cfgs[0].Payload
	// RIP header 4B + auth entry 20B (RIPv2 MD5: type=3, keyid, len, seq,
	// reserved, keyid+digest 16B) + route 20B + trailer 4B + 20-byte
	// digest block = 68 bytes total.
	if len(p) != 68 { // 4 + 20 + 20 + 4 + 20 = 68
		t.Errorf("payload len = %d, want 68", len(p))
	}
	if p[11] != 20 {
		t.Errorf("AuthDataLen = %d, want 20", p[11])
	}
	if !bytes.Equal(p[44:48], []byte{0xFF, 0xFF, 0x00, 0x01}) {
		t.Errorf("trailer = %x, want ffff0001", p[44:48])
	}
	for i := 48; i < 68; i++ {
		if p[i] != 0xAA {
			t.Errorf("digest[%d] = %02x, want aa", i, p[i])
		}
	}
}

// T-POS-24: 明文密码 16 字节恰好填满, 无补零
func TestTPOS24_Password16(t *testing.T) {
	pwd := "0123456789abcdef" // exactly 16 bytes
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth:    &core.RIPAuth{Type: "simple", Password: pwd},
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if !bytes.Equal(cfgs[0].Payload[8:24], []byte(pwd)) {
		t.Errorf("AuthData = %q, want %q", cfgs[0].Payload[8:24], pwd)
	}
}

// T-POS-16 补强: 多路由器未显式设 src_port 时按 router 索引分配 52001+
func TestTPOS16b_MultiRouterDefaultPorts(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routers: []core.RIPRouter{
			{SrcIP: "192.168.1.1"},
			{SrcIP: "192.168.1.2"},
			{SrcIP: "192.168.2.1"},
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(cfgs))
	}
	// Each router gets a unique port 52001/52002/52003 (design §6.13)
	ports := map[uint16]bool{}
	for i, c := range cfgs {
		if c.L4.SrcPort != uint16(52001+i) {
			t.Errorf("router %d SrcPort = %d, want %d", i, c.L4.SrcPort, 52001+i)
		}
		ports[c.L4.SrcPort] = true
		if c.FlowID == "" {
			t.Errorf("router %d has empty FlowID", i)
		}
	}
	if len(ports) != 3 {
		t.Errorf("src ports not unique: %v", ports)
	}
}

// T-EDGE-2: Metric=1 合法
func TestTEdge2_MetricOne(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[20:24]); m != 1 {
		t.Errorf("metric = %d, want 1", m)
	}
}

// T-EDGE-3: Metric=16 不可达, 合法
func TestTEdge3_Metric16(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 16}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if m := binary.BigEndian.Uint32(cfgs[0].Payload[20:24]); m != 16 {
		t.Errorf("metric = %d, want 16", m)
	}
}

// T-EDGE-5: Metric=255 报错
func TestTEdge5_Metric255(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 255}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for metric=255, got nil")
	}
}

// T-EDGE-6 / T-POS-19: Route entry 数=0 -> 仅 4B RIP 头
func TestTEdge6_ZeroRoutes(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if len(cfgs[0].Payload) != 4 {
		t.Errorf("payload len = %d, want 4", len(cfgs[0].Payload))
	}
}

// T-EDGE-7: Route entry 数=25 单包
func TestTEdge7_25Entries(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: makeRoutes(25)}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if len(cfgs[0].Payload) != 504 {
		t.Errorf("payload len = %d, want 504", len(cfgs[0].Payload))
	}
}

// T-EDGE-9: 50 entry -> 2 包各 25
func TestTEdge9_50Entries(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: makeRoutes(50)}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	if len(cfgs[0].Payload) != 504 || len(cfgs[1].Payload) != 504 {
		t.Errorf("payload lens = %d/%d, want 504/504", len(cfgs[0].Payload), len(cfgs[1].Payload))
	}
}

// T-EDGE-10: 51 entry -> 3 包 25/25/1
func TestTEdge10_51Entries(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: makeRoutes(51)}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(cfgs))
	}
	if len(cfgs[0].Payload) != 504 || len(cfgs[1].Payload) != 504 || len(cfgs[2].Payload) != 24 {
		t.Errorf("payload lens = %d/%d/%d, want 504/504/24",
			len(cfgs[0].Payload), len(cfgs[1].Payload), len(cfgs[2].Payload))
	}
}

// T-EDGE-11: IP=0.0.0.0 缺省路由合法
func TestTEdge11_DefaultRoute(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "0.0.0.0", SubnetMask: "0.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if !bytes.Equal(cfgs[0].Payload[8:12], []byte{0, 0, 0, 0}) {
		t.Errorf("IP = %v, want 0.0.0.0", cfgs[0].Payload[8:12])
	}
}

// T-EDGE-12: IP=255.255.255.255 报错
func TestTEdge12_BroadcastRoute(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "255.255.255.255", SubnetMask: "255.255.255.255", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for broadcast route, got nil")
	}
}

// T-EDGE-13: SubnetMask=0.0.0.0 缺省合法
func TestTEdge13_ZeroMask(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "0.0.0.0", SubnetMask: "0.0.0.0", Metric: 1}}}
	if _, err := NewPlanner().Plan(context.Background(), ripSpec(cfg)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// T-EDGE-14: SubnetMask=255.255.255.255 主机路由合法
func TestTEdge14_HostMask(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.1", SubnetMask: "255.255.255.255", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if !bytes.Equal(cfgs[0].Payload[12:16], []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("mask = %v, want ff ff ff ff", cfgs[0].Payload[12:16])
	}
}

// T-EDGE-16/17: PrefixLen=0/128 合法
func TestTEdge16_17_PrefixLen(t *testing.T) {
	for _, tc := range []struct {
		plen uint8
		want byte
	}{
		{0, 0x00}, // T-EDGE-16 default route
		{128, 0x80},
	} {
		cfg := &core.RIPConfig{Version: "ng", Command: "response", Routes: []core.RIPRoute{{IPAddr: "::", PrefixLen: tc.plen, Metric: 1}}}
		spec := ripSpec(cfg)
		spec.SrcIP = "2001:db8::1"
		spec.DstIP = "2001:db8::2" // IPv6 DstIP required for RIPng unicast
		spec.DstPort = 0
		cfgs := mustPlan(t, NewPlanner(), spec)
		if len(cfgs) != 1 {
			t.Fatalf("prefix_len=%d: expected 1 packet, got %d", tc.plen, len(cfgs))
		}
		if cfgs[0].Payload[22] != tc.want {
			t.Errorf("prefix_len=%d: field = %02x, want %02x", tc.plen, cfgs[0].Payload[22], tc.want)
		}
	}
}

// T-EDGE-18: PrefixLen=129 报错
func TestTEdge18_PrefixLen129(t *testing.T) {
	cfg := &core.RIPConfig{Version: "ng", Command: "response", Routes: []core.RIPRoute{{IPAddr: "::", PrefixLen: 129, Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for prefix_len=129, got nil")
	}
}

// T-EDGE-19: Domain=0xFFFF 透传
func TestTEdge19_DomainFFFF(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Domain: 0xFFFF, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if !bytes.Equal(cfgs[0].Payload[2:4], []byte{0xFF, 0xFF}) {
		t.Errorf("Domain = %02x%02x, want ff ff", cfgs[0].Payload[2], cfgs[0].Payload[3])
	}
}

// T-EDGE-21: Routers=[] 单路由器
func TestTEdge21_EmptyRouters(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routers: []core.RIPRouter{}, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}}}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(cfgs))
	}
	if cfgs[0].FlowID != "192.168.1.1-192.168.1.2-52001-520" {
		t.Errorf("FlowID = %s, want single-router FlowID", cfgs[0].FlowID)
	}
}

// T-ERR-3: Command="update" 报错
func TestTErr3_InvalidCommand(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "update"}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for command=update, got nil")
	}
}

// T-ERR-5: AFI=3 报错
func TestTErr5_InvalidAFI(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{AFI: 3, IPAddr: "10.0.0.0", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for AFI=3, got nil")
	}
}

// T-ERR-19: AFI=0xFFFF 用户显式设 报错
func TestTErr19_AFIFFFF(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{AFI: 0xFFFF, IPAddr: "10.0.0.0", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for AFI=0xFFFF, got nil")
	}
}

// T-ERR-7: Auth.Type="sha256" 报错
func TestTErr7_InvalidAuthType(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Auth: &core.RIPAuth{Type: "sha256"}, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for auth type sha256, got nil")
	}
}

// T-ERR-9: Auth 非 nil + Version="ng" 报错
func TestTErr9_AuthOnNG(t *testing.T) {
	cfg := &core.RIPConfig{Version: "ng", Auth: &core.RIPAuth{Type: "simple", Password: "secret"}, Routes: []core.RIPRoute{{IPAddr: "::", PrefixLen: 0, Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for auth on ng, got nil")
	}
}

// T-ERR-11: RIPRoute.IPAddr 非法 IP 报错
func TestTErr11_InvalidRouteIP(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "999.1.1.1", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for invalid route IP, got nil")
	}
}

// T-ERR-11b: ng + IPv4 路由地址报错 (协议族不匹配, 避免 IPv4-mapped 错乱)
func TestTErr11b_NGRouteIPv4(t *testing.T) {
	cfg := &core.RIPConfig{Version: "ng", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", PrefixLen: 8, Metric: 1}}}
	spec := ripSpec(cfg)
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error for ng + IPv4 route address, got nil")
	}
}

// T-ERR-12: SubnetMask 非法 IPv4 报错
func TestTErr12_InvalidMask(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "not-a-mask", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for invalid mask, got nil")
	}
}

// T-ERR-13: NextHop 协议族不匹配 报错 (v2 + IPv6 next hop)
func TestTErr13_NextHopFamilyMismatch(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", NextHop: "2001:db8::1", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for v6 next hop on v2, got nil")
	}
}

// T-ERR-16: Routers=[{}] 空元素 报错
func TestTErr16_EmptyRouter(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routers: []core.RIPRouter{{}}, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for empty router element, got nil")
	}
}

// T-ERR-17: MD5 AuthDataLen 显式为 0 报错
func TestTErr17_AuthDataLenZero(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Auth: &core.RIPAuth{Type: "md5", AuthDataLen: ptr(0)}, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}}}
	_, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err == nil {
		t.Fatal("expected error for auth_data_len=0, got nil")
	}
}

// T-ERR-14: Multicast=true + DstIP 用户给 -> 不报错, Plan 用组播 IP (警告语义)
func TestTErr14_MulticastOverridesDstIP(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Multicast: true, Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}}}
	spec := ripSpec(cfg)
	spec.DstIP = "192.168.1.99"
	cfgs, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := drain(cfgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	if out[0].L3.DstIP != "224.0.0.9" {
		t.Errorf("DstIP = %s, want 224.0.0.9 (multicast wins)", out[0].L3.DstIP)
	}
}

// T-ERR-15: SplitHorizon + PoisonReverse 共存 -> 不报错, PoisonReverse 生效
func TestTErr15_SplitHorizonAndPoisonReverse(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:       "v2",
		Command:       "response",
		SplitHorizon:  true,
		PoisonReverse: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", NextHop: "192.168.1.2", Metric: 1},
			{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", NextHop: "192.168.1.1", Metric: 1},
		},
	}
	cfgs, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := drain(cfgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	// PoisonReverse wins: both routes kept, first metric=16
	if len(out[0].Payload) != 44 {
		t.Errorf("payload len = %d, want 44", len(out[0].Payload))
	}
	if m := binary.BigEndian.Uint32(out[0].Payload[20:24]); m != 16 {
		t.Errorf("metric = %d, want 16", m)
	}
}

// T-ERR-18: SplitHorizon=true + Multicast=true -> 不报错, 组播下过滤被跳过
func TestTErr18_SplitHorizonMulticast(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:      "v2",
		Command:      "response",
		Multicast:    true,
		SplitHorizon: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", NextHop: "224.0.0.9", Metric: 1},
			{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", NextHop: "192.168.1.1", Metric: 1},
		},
	}
	cfgs, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := drain(cfgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	// No filtering under multicast: both routes present
	if len(out[0].Payload) != 44 {
		t.Errorf("payload len = %d, want 44 (no filtering under multicast)", len(out[0].Payload))
	}
}

// T-ERR-18 扩展: PoisonReverse=true + Multicast=true -> 不报错, 不生效
func TestTErr18b_PoisonReverseMulticast(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:       "v2",
		Command:       "response",
		Multicast:     true,
		PoisonReverse: true,
		Routes: []core.RIPRoute{
			{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", NextHop: "224.0.0.9", Metric: 1},
		},
	}
	cfgs, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := drain(cfgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	// No poisoning under multicast: metric stays 1
	if m := binary.BigEndian.Uint32(out[0].Payload[20:24]); m != 1 {
		t.Errorf("metric = %d, want 1 (no poisoning under multicast)", m)
	}
}

// T-POS-1b-variant: request_full 用户 Routes 优先 (自动 Response 用用户 Routes)
func TestTPOS1bVariant_UserRoutesPreferred(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:  "v2",
		Command:  "request",
		Scenario: "request_full",
		Routes: []core.RIPRoute{
			{IPAddr: "10.1.0.0", SubnetMask: "255.255.0.0", Metric: 3},
			{IPAddr: "172.20.0.0", SubnetMask: "255.255.0.0", Metric: 2},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), ripSpec(cfg))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	// Auto Response uses user routes: 4 + 2*20 = 44
	if len(cfgs[1].Payload) != 44 {
		t.Errorf("Response payload = %d, want 44 (2 user routes)", len(cfgs[1].Payload))
	}
	// First user route 10.1.0.0 with metric 3
	if !bytes.Equal(cfgs[1].Payload[8:12], net.ParseIP("10.1.0.0").To4()) {
		t.Errorf("Response route = %v, want 10.1.0.0", cfgs[1].Payload[8:12])
	}
	if m := binary.BigEndian.Uint32(cfgs[1].Payload[20:24]); m != 3 {
		t.Errorf("Response metric = %d, want 3", m)
	}
	// Same 4-tuple as Request
	if cfgs[1].L3.SrcIP != cfgs[0].L3.SrcIP || cfgs[1].L3.DstIP != cfgs[0].L3.DstIP ||
		cfgs[1].L4.SrcPort != cfgs[0].L4.SrcPort || cfgs[1].L4.DstPort != cfgs[0].L4.DstPort {
		t.Errorf("Response 4-tuple differs from Request")
	}
}

// T-EDGE-15: SubnetMask 非连续掩码 -> 不报错 (planner 透传)
func TestTEdge15_NonContiguousMask(t *testing.T) {
	cfg := &core.RIPConfig{Version: "v2", Command: "response", Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.3", Metric: 1}}}
	cfgs, err := NewPlanner().Plan(context.Background(), ripSpec(cfg))
	if err != nil {
		t.Fatalf("unexpected error for non-contiguous mask: %v", err)
	}
	out := drain(cfgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	if !bytes.Equal(out[0].Payload[12:16], []byte{0xFF, 0x00, 0x00, 0x03}) {
		t.Errorf("mask = %v, want ff 00 00 03 (passthrough)", out[0].Payload[12:16])
	}
}

// T-EDGE-22: 多路由器 src_port 分配唯一性（并发路由到不同 worker 的 4-tuple 基础）
func TestTEdge22_ManyRouters(t *testing.T) {
	// Each router needs at least one non-empty field (T-ERR-16), so give each
	// a distinct SrcIP.
	routers := make([]core.RIPRouter, 100)
	for i := range routers {
		routers[i].SrcIP = fmt.Sprintf("192.168.%d.%d", i/250, 1+i%250)
	}
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routers: routers,
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) != 100 {
		t.Fatalf("expected 100 packets, got %d", len(cfgs))
	}
	flowIDs := map[string]bool{}
	for _, c := range cfgs {
		if flowIDs[c.FlowID] {
			t.Errorf("duplicate FlowID: %s", c.FlowID)
		}
		flowIDs[c.FlowID] = true
	}
	// router 99 gets src port 52001+99 (dynamic allocation per router index)
	if cfgs[99].L4.SrcPort != 52001+99 {
		t.Errorf("router 99 SrcPort = %d, want %d", cfgs[99].L4.SrcPort, 52001+99)
	}
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil RIP）默认化（v2 response_default 5 路由），
	// Validate/Plan 产默认流。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "224.0.0.9", SrcPort: 520, DstPort: 520}
	p := Planner{}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}
}
