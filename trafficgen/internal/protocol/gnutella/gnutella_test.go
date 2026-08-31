package gnutella

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func cfg() *core.GnutellaConfig { return &core.GnutellaConfig{} }

func guid(n byte) []byte {
	g := make([]byte, 16)
	for i := range g {
		g[i] = byte(int(n) + i)
	}
	return g
}

// §3.1 握手：首行 + 能力头 + CRLF；键序稳定。
func TestHandshakeFrames(t *testing.T) {
	c := BuildHandshake("connect", nil)
	if !strings.HasPrefix(string(c), "GNUTELLA CONNECT/0.6\r\n") {
		t.Fatalf("connect first line wrong: %q", string(c[:30]))
	}
	if !strings.HasSuffix(string(c), "\r\n\r\n") {
		t.Fatalf("connect must end with empty CRLF line")
	}
	if !strings.Contains(string(c), "User-Agent: trafficgen/1.0\r\n") ||
		!strings.Contains(string(c), "X-Query-Routing: 0.1\r\n") ||
		!strings.Contains(string(c), "X-Node: "+defaultNodeHex+"\r\n") {
		t.Fatalf("capability headers missing: %q", string(c))
	}
	uaIdx := strings.Index(string(c), "User-Agent")
	xqIdx := strings.Index(string(c), "X-Query-Routing")
	if uaIdx > xqIdx {
		t.Fatalf("headers must be sorted for deterministic bytes")
	}
	ok := BuildHandshake("ok", nil)
	if !strings.HasPrefix(string(ok), "GNUTELLA/0.6 200 OK\r\n") {
		t.Fatalf("200 OK first line wrong")
	}
	ref := BuildHandshake("refuse", nil)
	if !strings.HasPrefix(string(ref), "GNUTELLA/0.6 503 Busy\r\n") {
		t.Fatalf("503 first line wrong")
	}
}

// §3.2 消息头：23B、GUID/Descriptor/TTL/Hops、PayloadLength 小端只计 payload。
func TestMessageHeaderLayout(t *testing.T) {
	g := guid(1)
	f, err := BuildMessage(&core.GnutellaEvent{Kind: "ping", MessageID: g, TTL: 5, Hops: 2}, "")
	if err != nil {
		t.Fatalf("BuildMessage: %v", err)
	}
	if len(f) != headerLen {
		t.Fatalf("min ping frame = %d bytes, want 23", len(f))
	}
	if hex.EncodeToString(f[:16]) != hex.EncodeToString(g) {
		t.Fatalf("GUID mismatch")
	}
	if f[16] != descPing || f[17] != 5 || f[18] != 2 {
		t.Fatalf("desc/ttl/hops = %x", f[16:19])
	}
	// PayloadLength 小端 0。
	if f[19] != 0 || f[20] != 0 || f[21] != 0 || f[22] != 0 {
		t.Fatalf("payload length LE = %x", f[19:23])
	}
}

// §4 PONG：Port|Address|Files|KB；地址宽度随 profile（v6→16B）。
func TestPongFrame(t *testing.T) {
	g := guid(2)
	f, err := BuildMessage(&core.GnutellaEvent{Kind: "pong", MessageID: g, TTL: 5,
		PongPort: 6346, Files: 3, KB: 128}, "")
	if err != nil {
		t.Fatalf("pong: %v", err)
	}
	// payload = 2+4+4+4 = 14 → LE(0x0e,0,0,0)
	if f[19] != 0x0e || f[20] != 0 || f[21] != 0 || f[22] != 0 {
		t.Fatalf("pong payload len = %x", f[19:23])
	}
	// 端口小端（Gnutella 0.6 规范：payload 多字节一律 Intel 序）。
	if f[23] != 0xca || f[24] != 0x18 { // 6346 = 0x18ca LE
		t.Fatalf("pong port = %x", f[23:25])
	}
	if f[29] != 3 || f[33] != 128 { // files/kb 首字节（LE 低字节在前）
		t.Fatalf("pong files/kb = %x %x", f[29], f[33])
	}
	if string(f[25:29]) != string([]byte{10, 0, 0, 9}) {
		t.Fatalf("pong address = %x", f[25:29])
	}
	// v6 profile → 地址 16B。
	f6, err := BuildMessage(&core.GnutellaEvent{Kind: "pong", MessageID: g}, profileV6)
	if err != nil {
		t.Fatalf("pong v6: %v", err)
	}
	if f6[19] != 0x1a { // 2+16+4+4 = 26
		t.Fatalf("v6 pong payload len = %d", f6[19])
	}
	// 显式地址与 profile 宽度不符拒绝。
	if _, err := BuildMessage(&core.GnutellaEvent{Kind: "pong", MessageID: g,
		PongAddress: make([]byte, 16)}, ""); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("address width mismatch must be rejected: %v", err)
	}
}

// §4 QUERY：MinSpeed + NUL 终止 criteria；QUERY_HIT：Hits/Port/Address/Speed/
// Result*/ServentID，Hits 必须等于 result 数。
func TestQueryFrames(t *testing.T) {
	q, err := BuildMessage(&core.GnutellaEvent{Kind: "query", MessageID: guid(3),
		Criteria: "mp3", MinSpeed: 10}, "")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	// payload = 2 + 3 + 1 = 6；min_speed 小端（10 = 0a 00）。
	if q[19] != 6 || q[23] != 0x0a || q[24] != 0 || string(q[25:28]) != "mp3" || q[28] != 0 {
		t.Fatalf("query payload wrong: %x", q[19:])
	}
	if q[16] != descQuery {
		t.Fatalf("query descriptor = %x", q[16])
	}
	hit, err := BuildMessage(&core.GnutellaEvent{Kind: "query_hit", MessageID: guid(4),
		QueryID: guid(3), Hits: 1, HitPort: 6348, Speed: 100,
		Results:   []core.GnutellaResult{{FileIndex: 7, FileSize: 4096, Name: "a.txt"}},
		ServentID: guid(9)}, "")
	if err != nil {
		t.Fatalf("query_hit: %v", err)
	}
	if hit[16] != descQueryHit || hit[23] != 1 {
		t.Fatalf("query_hit header/hits wrong")
	}
	// hit 头部端口/速度小端：6348=0x18cc→cc 18、100→64 00 00 00。
	if hit[24] != 0xcc || hit[25] != 0x18 {
		t.Fatalf("query_hit port = %x", hit[24:26])
	}
	if hit[30] != 100 || hit[31] != 0 || hit[32] != 0 || hit[33] != 0 {
		t.Fatalf("query_hit speed = %x", hit[30:34])
	}
	if hit[34] != 7 || hit[38] != 0x00 || hit[39] != 0x10 { // index 7 LE / size 4096=0x1000 LE
		t.Fatalf("query_hit result index/size = %x %x", hit[34:38], hit[38:42])
	}
	if !strings.Contains(hex.EncodeToString(hit), hex.EncodeToString(guid(9))) {
		t.Fatalf("servent id missing")
	}
	// Hits 与 result 数不一致拒绝（validator 与 builder 双层）。
	if _, err := BuildMessage(&core.GnutellaEvent{Kind: "query_hit", MessageID: guid(4),
		QueryID: guid(3), Hits: 2, Results: []core.GnutellaResult{{FileIndex: 1}}}, ""); err == nil ||
		!strings.Contains(err.Error(), "payload") {
		t.Fatalf("hits mismatch must be rejected: %v", err)
	}
}

// §4 PUSH + VENDOR。
func TestPushVendorFrames(t *testing.T) {
	p, err := BuildMessage(&core.GnutellaEvent{Kind: "push", MessageID: guid(5),
		ServentID: guid(9), FileIndex: 7, PushPort: 6349}, "")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	// payload = 16 + 4 + 4 + 2 = 26；file_index/port 小端。
	if p[19] != 26 || p[16] != descPush {
		t.Fatalf("push layout wrong")
	}
	if p[39] != 7 || p[47] != 0xcd || p[48] != 0x18 { // index@39 LE、port@47 6349=0x18cd LE
		t.Fatalf("push index/port = %x %x", p[39:43], p[47:49])
	}
	v, err := BuildMessage(&core.GnutellaEvent{Kind: "vendor", MessageID: guid(6),
		VendorID: "GTKG", Selector: 3, Version: 1, Payload: []byte{0xde, 0xad}}, "")
	if err != nil {
		t.Fatalf("vendor: %v", err)
	}
	if v[16] != descVendor || v[19] != 10 || string(v[23:27]) != "GTKG" {
		t.Fatalf("vendor layout wrong")
	}
	// selector/version 小端：3→03 00、1→01 00。
	if v[27] != 3 || v[28] != 0 || v[29] != 1 || v[30] != 0 {
		t.Fatalf("vendor selector/version = %x", v[27:31])
	}
	// vendor_id 长度非法拒绝。
	if _, err := BuildMessage(&core.GnutellaEvent{Kind: "vendor", MessageID: guid(6),
		VendorID: "TOOLONG"}, ""); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("vendor_id length must be rejected: %v", err)
	}
}

// §7 边界：GUID 缺省非零、frame_max 守卫、TTL/Hops uint8。
func TestBoundaries(t *testing.T) {
	f, err := BuildMessage(&core.GnutellaEvent{Kind: "ping"}, "")
	if err != nil {
		t.Fatalf("default GUID ping: %v", err)
	}
	if bytesAllZero(f[:16]) {
		t.Fatalf("default GUID must be non-zero")
	}
	frame, err := BuildMessage(&core.GnutellaEvent{Kind: "vendor", MessageID: guid(1),
		Payload: make([]byte, 4000)}, "")
	if err != nil {
		t.Fatalf("big vendor: %v", err)
	}
	if err := CheckFrameMax(frame, 100); err == nil {
		t.Fatalf("big frame must exceed frame_max 100")
	}
	if err := CheckFrameMax(frame, 0); err != nil {
		t.Fatalf("default frame_max must accept: %v", err)
	}
}

func bytesAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func anchorErr(t *testing.T, c *core.GnutellaConfig, anchors ...string) error {
	t.Helper()
	err := ValidateConfig(c)
	if err == nil {
		t.Fatalf("expected rejection containing %v, got nil", anchors)
	}
	for _, a := range anchors {
		if !strings.Contains(err.Error(), a) {
			t.Fatalf("error %q missing anchor %q", err.Error(), a)
		}
	}
	return err
}

// §5 状态机正例。
func TestValidateHappyPath(t *testing.T) {
	c := &core.GnutellaConfig{Connections: []core.GnutellaConn{{
		Events: []core.GnutellaEvent{
			{Kind: "connect"}, {Kind: "ok"},
			{Kind: "ping", MessageID: guid(1), TTL: 5, Hops: 0},
			{Kind: "pong", MessageID: guid(1), TTL: 5, Hops: 1, PongPort: 6346, Files: 1, KB: 2},
			{Kind: "query", MessageID: guid(3), TTL: 5, Criteria: "mp3"},
			{Kind: "query_hit", MessageID: guid(4), QueryID: guid(3), TTL: 5, Hits: 1,
				Results: []core.GnutellaResult{{FileIndex: 7, Name: "a"}}, ServentID: guid(9)},
			{Kind: "push", MessageID: guid(5), ServentID: guid(9), FileIndex: 7},
			{Kind: "ping", MessageID: guid(1), TTL: 4, Hops: 1}, // 转发副本
		}}}}
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
}

// §5/§8 负例矩阵。
func TestValidateNegatives(t *testing.T) {
	hs := func(ev ...core.GnutellaEvent) []core.GnutellaEvent {
		return append([]core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}}, ev...)
	}
	conn := func(ev ...core.GnutellaEvent) *core.GnutellaConfig {
		return &core.GnutellaConfig{Connections: []core.GnutellaConn{{Events: ev}}}
	}
	// 首帧非 CONNECT。
	anchorErr(t, conn(core.GnutellaEvent{Kind: "ping", MessageID: guid(1)}), "handshake")
	// 200 前发业务。
	anchorErr(t, conn(core.GnutellaEvent{Kind: "connect"}, core.GnutellaEvent{Kind: "ping", MessageID: guid(1)}), "handshake", "state")
	// TTL/Hops 回绕。
	anchorErr(t, conn(hs(core.GnutellaEvent{Kind: "ping", MessageID: guid(1), TTL: 200, Hops: 100})...), "ttl", "hops")
	// 转发不递减 TTL。
	anchorErr(t, conn(hs(
		core.GnutellaEvent{Kind: "ping", MessageID: guid(1), TTL: 5, Hops: 0},
		core.GnutellaEvent{Kind: "ping", MessageID: guid(1), TTL: 5, Hops: 1})...), "ttl", "hops")
	// pong 无对应 ping。
	anchorErr(t, conn(hs(core.GnutellaEvent{Kind: "pong", MessageID: guid(2)})...), "correlation")
	// query_hit 引用未知 query。
	anchorErr(t, conn(hs(core.GnutellaEvent{Kind: "query_hit", MessageID: guid(4),
		QueryID: guid(3), Hits: 0, ServentID: guid(9)})...), "query", "correlation")
	// hits 与 result 数不符。
	anchorErr(t, conn(hs(
		core.GnutellaEvent{Kind: "query", MessageID: guid(3), Criteria: "x"},
		core.GnutellaEvent{Kind: "query_hit", MessageID: guid(4), QueryID: guid(3), Hits: 2,
			Results:   []core.GnutellaResult{{FileIndex: 1}}, ServentID: guid(9)})...), "payload", "hits")
	// push 无 query_hit 来源。
	anchorErr(t, conn(hs(core.GnutellaEvent{Kind: "push", MessageID: guid(5), ServentID: guid(9)})...), "servent", "correlation")
	// 地址宽度不符。
	anchorErr(t, conn(hs(
		core.GnutellaEvent{Kind: "ping", MessageID: guid(1)},
		core.GnutellaEvent{Kind: "pong", MessageID: guid(1), PongAddress: make([]byte, 16)})...), "address", "payload")
	// GUID 长度非法。
	anchorErr(t, conn(hs(core.GnutellaEvent{Kind: "ping", MessageID: []byte{1, 2}})...), "message")
	// 未知 kind。
	anchorErr(t, conn(core.GnutellaEvent{Kind: "bogus"}), "descriptor")
	// 未知 profile。
	anchorErr(t, &core.GnutellaConfig{Profile: "bogus"}, "profile")
	// 空事件连接。
	anchorErr(t, &core.GnutellaConfig{Connections: []core.GnutellaConn{{}}}, "handshake")
}

// §8 wire_fault 与端口校验。
func TestValidateWireFaultAndPort(t *testing.T) {
	for kind, anchor := range map[string]string{
		"bad_handshake_line": "handshake",
		"header_truncation":  "message",
		"bad_descriptor":     "descriptor",
		"length_overrun":     "length",
	} {
		c := &core.GnutellaConfig{WireFault: kind, Connections: []core.GnutellaConn{{
			Events: []core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}}}}}
		anchorErr(t, c, anchor)
	}
	if err := ValidateConfig(&core.GnutellaConfig{WireFault: "nope", Connections: []core.GnutellaConn{{
		Events: []core.GnutellaEvent{{Kind: "connect"}}}}}); err == nil {
		t.Fatalf("unknown wire_fault must be rejected")
	}
	if err := ValidateSpec(&core.FlowSpec{Gnutella: &core.GnutellaConfig{}, DstPort: 6347}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("port validation = %v", err)
	}
	if err := ValidateSpec(&core.FlowSpec{Gnutella: &core.GnutellaConfig{
		Connections: []core.GnutellaConn{{Events: []core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}}}}}}); err != nil {
		t.Fatalf("valid config must pass: %v", err)
	}
}

// 生成器冒烟：握手/消息方向与 SrcPort 会话边界。
func TestGenerateEvents(t *testing.T) {
	g := &GnutellaGenerator{}
	var evs []layers.MessageEvent
	c := &core.GnutellaConfig{Connections: []core.GnutellaConn{{SrcPort: 42058,
		Events: []core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}}}}}
	if err := g.generateEvents(t.Context(), func(e layers.MessageEvent) error {
		evs = append(evs, e)
		return nil
	}, c); err != nil {
		t.Fatalf("generateEvents: %v", err)
	}
	if len(evs) != 2 || !evs[0].Up || evs[1].Up || evs[0].SrcPort != 42058 {
		t.Fatalf("events = %+v", evs)
	}
}
