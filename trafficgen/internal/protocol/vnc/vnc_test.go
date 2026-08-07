package vnc

// VNC/RFB planner tests, derived from /tmp/l7_planner_design/testcases_vnc.md
// (§2 握手消息 / §3 客户端消息 / §4 服务器消息 / §5 数据面 / §6 Validate) and the
// reference pcap
// /home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.143-20.3.1.143-1160-5901-1149-1631-69054-2262354.pcap
// (TightVNC session: 13 handshake messages byte-exact, ServerInit 38B,
// Interaction Caps 184B, XCursor blob 80B).
//
// Model: one TCP flow = handshake (server speaks first) → client messages →
// initial FBU → Rounds × (PointerEvent → FBU) → incremental FBU request →
// teardown. Reference-pcap garbage padding (0x417e, 0x4300, 0x1b01fd) is not
// reproduced (RFC padding is zero).

import (
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

func vncSpec(cfg *core.VNCConfig) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1160, DstPort: 5901,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	spec.VNC = cfg
	return spec
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// tcpData returns (flags, direction, payload) of TCP frames carrying
// payload, in order.
type tcpDataMsg struct {
	flags   uint8
	dir     string
	payload []byte
}

func tcpData(cfgs []core.PacketConfig) []tcpDataMsg {
	var out []tcpDataMsg
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && len(c.Payload) > 0 {
			out = append(out, tcpDataMsg{c.L4.Flags, c.Direction, append([]byte(nil), c.Payload...)})
		}
	}
	return out
}

func tcpFlags(cfgs []core.PacketConfig) []uint8 {
	var out []uint8
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c.L4.Flags)
		}
	}
	return out
}

// msgs returns the payloads of data packets in the given direction.
func msgs(cfgs []core.PacketConfig, dir string) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && len(c.Payload) > 0 && c.Direction == dir {
			out = append(out, append([]byte(nil), c.Payload...))
		}
	}
	return out
}

// smallCfg returns a minimal default config: Tight security, reference
// ServerInit values, no key events and empty rects so each message fits one
// segment and the drained flow stays small.
func smallCfg() *core.VNCConfig {
	return &core.VNCConfig{
		SecurityType:      16,
		Width:             1024,
		Height:            768,
		ServerName:        "QTMS:1 (ykaul)",
		Rounds:            1,
		FBUUpdateInterval: 1,
		PointerX:          507,
		PointerY:          320,
		KeyEvents:         []core.VNCKeyEventConfig{},
		InitialFBU:        []core.VNCRectConfig{},
		UpdateRects:       []core.VNCRectConfig{},
	}
}

func assertHex(t *testing.T, got []byte, wantHex string, what string) {
	t.Helper()
	if h := hexStr(got); h != wantHex {
		t.Fatalf("%s: got %s want %s", what, h, wantHex)
	}
}

// --- §2 握手消息 (1.1-1.6) ---

// 1.1 版本字符串 "RFB 003.008\n" 12B.
func TestVersionString(t *testing.T) {
	cfg := smallCfg()
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")
	if len(down) < 1 || len(up) < 1 {
		t.Fatalf("no handshake messages: down=%d up=%d", len(down), len(up))
	}
	assertHex(t, down[0], "524642203030332e3030380a", "server version")
	assertHex(t, up[0], "524642203030332e3030380a", "client version echo")
}

// 1.2 安全类型列表(1/2/16 三路径).
func TestSecTypesBytes(t *testing.T) {
	assertHex(t, secTypesBytes(16), "020210", "Tight list")
	assertHex(t, secTypesBytes(2), "0102", "VNC Auth single type (count=1 + type)")
	assertHex(t, secTypesBytes(1), "0101", "None single type (count=1 + type)")
}

// 1.3 Tight 握手完整字节(参考 pcap 逐字节,13 条消息).
func TestTightHandshakeBytes(t *testing.T) {
	cfg := smallCfg()
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")

	// 13 handshake messages: 7 down + 6 up, then the data plane (SetPixelFormat,
	// SetEncodings, FBU req, PointerEvent, FBUs) adds more; assert the handshake
	// prefix and exact per-message bytes.
	if len(down) < 7 || len(up) < 5 {
		t.Fatalf("handshake message counts: down=%d up=%d", len(down), len(up))
	}
	assertHex(t, down[0], "524642203030332e3030380a", "down version")
	assertHex(t, up[0], "524642203030332e3030380a", "up version")
	assertHex(t, down[1], "020210", "security types [2,16]")
	assertHex(t, up[1], "10", "client selects Tight (16)")
	assertHex(t, down[2], "00000000", "tunnel caps (none)")
	assertHex(t, down[3], "000000010000000253544456564e43415554485f", "auth caps (VNCAUTH)")
	assertHex(t, up[2], "00000002", "client selects VNC Auth (2)")
	assertHex(t, down[4], "46708ddc13a8b313c5991e6decfaf280", "challenge")
	assertHex(t, up[3], "df1324a50b30903a38c8f9b833262c6e", "response")
	assertHex(t, down[5], "00000000", "security result OK")
	assertHex(t, up[4], "01", "share desktop flag")
	assertHex(t, down[6], "040003002018000100ff00ff00ff1008000000000000000e51544d533a312028796b61756c29",
		"ServerInit 38B")
}

// 1.4 ServerInit 38B 逐字节(参考 pcap) — covered by 1.3 down[6]; assert the
// custom server_name path here.
func TestServerInitCustomName(t *testing.T) {
	cfg := smallCfg()
	cfg.Width, cfg.Height = 800, 600
	cfg.ServerName = "test"
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down := msgs(cfgs, "down")
	assertHex(t, down[6], "032002582018000100ff00ff00ff1008000000000000000474657374", "ServerInit 800x600 \"test\"")
}

// 1.5 Interaction Caps 184B 逐字节(参考 pcap).
func TestInteractionCapsBytes(t *testing.T) {
	got := buildInteractionCaps(nil)
	want := "0000000b00000000" +
		"00000002535444565252455f5f5f5f5f" +
		"000000055354445648455854494c455f" +
		"000000075447485454494748545f5f5f" +
		"00000010535444565a524c455f5f5f5f" +
		"0000000153544456434f505952454354" +
		"ffffff0054474854434f4d50524c564c" +
		"ffffffe0544748544a504547514c564c" +
		"ffffff10544748545831314355525352" +
		"ffffff11544748545243484355525352" +
		"ffffff20544748544c41535452454354" +
		"ffffff21535444564e4557464253495a"
	if len(got) != 184 {
		t.Fatalf("caps length: got %d want 184", len(got))
	}
	assertHex(t, got, want, "Interaction Caps 184B")
}

// 1.6 像素格式 16B 编码.
func TestPixelFormatBytes(t *testing.T) {
	assertHex(t, pixelFormatBytes(nil),
		"2018000100ff00ff00ff100800000000", "default 32bpp/24bit")

	custom := &core.VNCPixelFormatConfig{
		BitsPerPixel: 16, Depth: 16, TrueColor: true,
		RedMax: 31, GreenMax: 63, BlueMax: 31,
		RedShift: 11, GreenShift: 5,
	}
	assertHex(t, pixelFormatBytes(custom),
		"10100001001f003f001f0b0500000000", "16bpp 5-6-5")
}

// --- §3 客户端消息 (1.7) ---

// 1.7 客户端消息字节: KeyEvent / SetPixelFormat / SetEncodings / FBU req /
// PointerEvent / ClientCutText.
func TestClientMessagesBytes(t *testing.T) {
	// Direct builder assertions.
	assertHex(t, buildKeyEvent(false, 0xffe9), "040000000000ffe9", "KeyEvent release")
	assertHex(t, buildKeyEvent(true, 0xffe1), "040100000000ffe1", "KeyEvent press")
	assertHex(t, buildSetPixelFormat(nil), "000000002018000100ff00ff00ff100800000000", "SetPixelFormat")
	assertHex(t, buildSetEncodings(nil), "0200000f"+
		"0000000500000008000000070000000600000004000000020000000100000000"+
		"ffffff06ffffff10ffffff11ffffff18ffffffe6ffffff20ffffff21", "SetEncodings 15")
	assertHex(t, buildFBURequest(false, 1024, 768), "03000000000004000300", "FBU request non-incremental")
	assertHex(t, buildFBURequest(true, 1024, 768), "03010000000004000300", "FBU request incremental")
	assertHex(t, buildPointerEvent(0, 507, 320), "050001fb0140", "PointerEvent")
	assertHex(t, buildClientCutText("hello"), "060000000000000568656c6c6f", "ClientCutText")

	// Plan-level: configured key event + client cut text flow through.
	cfg := smallCfg()
	cfg.KeyEvents = []core.VNCKeyEventConfig{{Down: true, Key: 97}}
	cfg.ClientCutText = "hello"
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	up := msgs(cfgs, "up")
	// up: version, select, selectAuth, response, share, SetPixelFormat,
	// SetEncodings, 1×KeyEvent, FBU req, ClientCutText
	assertHex(t, up[5], "000000002018000100ff00ff00ff100800000000", "plan SetPixelFormat")
	assertHex(t, up[7], "0401000000000061", "plan KeyEvent down key=97")
	assertHex(t, up[9], "060000000000000568656c6c6f", "plan ClientCutText")
}

// --- §4 服务器消息 (1.8-1.11) ---

// 1.8 服务器消息结构.
func TestServerMessagesBytes(t *testing.T) {
	assertHex(t, buildFramebufferUpdate(nil), "00000000", "FBU nRects=0")
	assertHex(t, buildSetColourMapEntries(0, []string{"0000ff00ff00"}),
		"0100000000010000ff00ff00", "SetColourMapEntries")
	assertHex(t, buildServerCutText("hi"), "03000000000000026869", "ServerCutText")
	// Bell is a bare 0x02 emitted by the planner's extras path (3.6 covers it).

	// Plan-level extras: Bell + colour map + cut text before each FBU.
	cfg := smallCfg()
	cfg.Bell = true
	cfg.SetColourMapEntries = &core.VNCColourMapConfig{First: 0, Colors: []string{"0000ff00ff00"}}
	cfg.ServerCutText = "hi"
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down := msgs(cfgs, "down")
	// down: version, secTypes, tunnel, authCaps, challenge, result,
	// ServerInit, caps, [Bell, ColourMap, CutText, FBU], [Bell, ColourMap,
	// CutText, FBU]
	last := down[len(down)-4:]
	assertHex(t, last[0], "02", "Bell")
	assertHex(t, last[1], "0100000000010000ff00ff00", "SetColourMapEntries")
	assertHex(t, last[2], "03000000000000026869", "ServerCutText")
	assertHex(t, last[3], "00000000", "FBU after extras")
}

// 1.9 Hextile raw tile(参考 pcap FBU#2 模式): rect(16,16,16,16) →
// ctrl 01 + 1024B 确定性像素.
func TestHextileRawTile(t *testing.T) {
	rect := core.VNCRectConfig{X: 16, Y: 16, Width: 16, Height: 16, Encoding: "hextile"}
	fbu := buildFramebufferUpdate([]core.VNCRectConfig{rect})
	assertHex(t, fbu[:16], "00000001001000100010001000000005", "FBU header + rect header")
	data := fbu[16:]
	if len(data) != 1025 {
		t.Fatalf("tile length: got %d want 1025", len(data))
	}
	if data[0] != 0x01 {
		t.Fatalf("tile ctrl: got %02x want 01", data[0])
	}
	for n := 0; n < 256; n++ {
		want := [4]byte{byte((n*13 + 1) & 0xFF), byte((n*13 + 2) & 0xFF), byte((n*13 + 3) & 0xFF), byte((n*13 + 4) & 0xFF)}
		got := data[1+4*n : 1+4*n+4]
		if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
			t.Fatalf("pixel %d: got %v want %v", n, got, want)
		}
	}
}

// 1.10 XCursor blob 82B(参考 pcap 逐字节): rect(0,1,12,19) → FBU 98B.
// 82B = 6B fg/bg + 38B 1bpp 位图(19 行 × 2B)+ 38B mask(19 行 × 2B).
// 参考位图有 3 个前导全零行;此前实现只有 2 行(80B),导致 Wireshark
// 按段解析 FBU(见 e2e 7.3 调查)。
func TestXCursorBlob(t *testing.T) {
	rect := core.VNCRectConfig{X: 0, Y: 1, Width: 12, Height: 19, Encoding: "xcursor"}
	fbu := buildFramebufferUpdate([]core.VNCRectConfig{rect})
	if len(fbu) != 98 {
		t.Fatalf("FBU length: got %d want 98", len(fbu))
	}
	assertHex(t, fbu[:16], "0000000100000001000c0013ffffff10", "FBU header + rect header")
	assertHex(t, fbu[16:], "000000ffffff"+
		"00000000000040006000700078005c007e005f007f807c006e00460006000300038001000000"+
		"8000c000e000f000f800fc00fe00ff00ff80ffc0ffe0fff0ff00ff00cf00cf80078007c00300",
		"XCursor blob 82B")
}

// 1.11 Raw rect: rect(0,0,2,2) → 12B 头 + 16B 像素.
func TestRawRect(t *testing.T) {
	rect := core.VNCRectConfig{X: 0, Y: 0, Width: 2, Height: 2, Encoding: "raw"}
	fbu := buildFramebufferUpdate([]core.VNCRectConfig{rect})
	assertHex(t, fbu[:16], "00000001000000000002000200000000", "FBU header + rect header")
	px := fbu[16:]
	if len(px) != 16 {
		t.Fatalf("pixel data length: got %d want 16", len(px))
	}
	for n := 0; n < 4; n++ {
		want := [4]byte{byte((n*13 + 1) & 0xFF), byte((n*13 + 2) & 0xFF), byte((n*13 + 3) & 0xFF), byte((n*13 + 4) & 0xFF)}
		got := px[4*n : 4*n+4]
		if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
			t.Fatalf("pixel %d: got %v want %v", n, got, want)
		}
	}
}

// 1.12 TCP 发射: SYN / SYN-ACK / ACK → PSH-ACK 数据 → FIN-ACK 4 帧.
func TestTCPEmission(t *testing.T) {
	cfg := smallCfg()
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	flags := tcpFlags(cfgs)
	if len(flags) < 7 {
		t.Fatalf("too few packets: %d", len(flags))
	}
	want := append([]uint8{tcpSYN, tcpSYNACK, tcpACK}, make([]uint8, len(flags)-3)...)
	for i := 3; i < len(flags)-4; i++ {
		want[i] = tcpPSHACK
	}
	want[len(flags)-4] = tcpFINACK
	want[len(flags)-3] = tcpACK
	want[len(flags)-2] = tcpFINACK
	want[len(flags)-1] = tcpACK
	for i := range flags {
		if flags[i] != want[i] {
			t.Fatalf("packet %d flags: got %02x want %02x", i, flags[i], want[i])
		}
	}
}

// --- §6 Validate (2.1-2.6) ---

// 2.1-2.6 Validate 校验表.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*core.VNCConfig)
		wantErr string
	}{
		{"security_type=3", func(c *core.VNCConfig) { c.SecurityType = 3 }, "security type"},
		{"auth_result=5", func(c *core.VNCConfig) { c.AuthResult = 5 }, "auth result"},
		{"width=0", func(c *core.VNCConfig) { c.Width = 0 }, "width"},
		{"height=70000", func(c *core.VNCConfig) { c.Height = 70000 }, "height"},
		{"rounds=0", func(c *core.VNCConfig) { c.Rounds = 0 }, "rounds"},
		{"pointer_x=70000", func(c *core.VNCConfig) { c.PointerX = 70000 }, "pointer"},
		{"pointer_button=256", func(c *core.VNCConfig) { c.PointerButton = 256 }, "pointer button"},
		{"rect.width=0", func(c *core.VNCConfig) {
			c.InitialFBU = []core.VNCRectConfig{{X: 0, Y: 0, Width: 0, Height: 1, Encoding: "raw"}}
		}, "rect"},
		{"rect encoding bogus", func(c *core.VNCConfig) {
			c.UpdateRects = []core.VNCRectConfig{{X: 0, Y: 0, Width: 1, Height: 1, Encoding: "tight"}}
		}, "rect encoding"},
		{"xcursor_blob=zz", func(c *core.VNCConfig) {
			c.InitialFBU = []core.VNCRectConfig{{X: 0, Y: 0, Width: 1, Height: 1, Encoding: "xcursor", XCursorBlob: "zz"}}
		}, "xcursor"},
		{"hextile_data=xyz", func(c *core.VNCConfig) {
			c.UpdateRects = []core.VNCRectConfig{{X: 0, Y: 0, Width: 16, Height: 16, Encoding: "hextile", HextileTileData: "xyz"}}
		}, "hextile"},
		{"encoding=-300", func(c *core.VNCConfig) { c.Encodings = []int{-300} }, "encoding"},
		{"key=-1", func(c *core.VNCConfig) { c.KeyEvents = []core.VNCKeyEventConfig{{Key: -1}} }, "key"},
		{"bpp=4", func(c *core.VNCConfig) {
			c.PixelFormat = &core.VNCPixelFormatConfig{BitsPerPixel: 4, Depth: 4}
		}, "bpp"},
		{"depth> bpp", func(c *core.VNCConfig) {
			c.PixelFormat = &core.VNCPixelFormatConfig{BitsPerPixel: 8, Depth: 16}
		}, "depth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := smallCfg()
			tc.mutate(cfg)
			if err := NewPlanner().Validate(vncSpec(cfg)); err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			} else if !contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}

	// 2.x accepted values: encodings=[3] (non-standard but RFC-legal),
	// pointer at (0,0), custom bpp.
	ok := smallCfg()
	ok.Encodings = []int{3}
	ok.PointerX, ok.PointerY = 0, 0
	ok.PixelFormat = &core.VNCPixelFormatConfig{BitsPerPixel: 16, Depth: 16}
	if err := NewPlanner().Validate(vncSpec(ok)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// 2.6 VNC 配置缺失 / IP 非法.
func TestValidateMissingConfigAndIP(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(vncSpec(nil)); err == nil || !contains(err.Error(), "vnc config is required") {
		t.Fatalf("missing vnc config: %v", err)
	}
	spec := vncSpec(smallCfg())
	spec.SrcIP = "bad"
	if err := p.Validate(spec); err == nil || !contains(err.Error(), "source IP") {
		t.Fatalf("bad src IP: %v", err)
	}
	spec = vncSpec(smallCfg())
	spec.DstIP = "bad"
	if err := p.Validate(spec); err == nil || !contains(err.Error(), "destination IP") {
		t.Fatalf("bad dst IP: %v", err)
	}
}

// --- §5 数据面序列 (3.1-3.7) ---

// 3.1 Rounds=3 默认序列: 客户端 6×KeyEvent + SetPixelFormat + SetEncodings +
// FBU req(非增量)→ InitialFBU → 3×[PointerEvent → FBU] → FBU req(增量).
func TestRounds3Sequence(t *testing.T) {
	cfg := smallCfg()
	cfg.Rounds = 3
	cfg.KeyEvents = defaultKeyEvents
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")

	// down: 8 handshake + InitialFBU + 3 round FBUs.
	if len(down) != 12 {
		t.Fatalf("down message count: got %d want 12", len(down))
	}
	// up: 5 handshake + post (SetPixelFormat, SetEncodings, 6×KeyEvent,
	// FBU req, 3×PointerEvent, FBU req).
	if len(up) != 5+13 {
		t.Fatalf("up message count: got %d want %d", len(up), 5+13)
	}

	// Up messages after the handshake (index 5 = share):
	// SetPixelFormat(00), SetEncodings(02), 6×KeyEvent(04), FBU req(03),
	// 3×PointerEvent(05), FBU req(03).
	post := up[5:]
	if post[0][0] != 0x00 || post[1][0] != 0x02 {
		t.Fatalf("expected SetPixelFormat+SetEncodings first, got %02x %02x", post[0][0], post[1][0])
	}
	for i := 2; i < 8; i++ {
		if post[i][0] != 0x04 || len(post[i]) != 8 {
			t.Fatalf("key event %d: type %02x len %d", i-2, post[i][0], len(post[i]))
		}
	}
	assertHex(t, post[8], "03000000000004000300", "initial FBU request")
	for i := 9; i < 12; i++ {
		assertHex(t, post[i], "050001fb0140", "PointerEvent")
	}
	assertHex(t, post[12], "03010000000004000300", "incremental FBU request")

	// Down: 8 handshake + FBU#1 (initial, 0 rects) + 3 round FBUs.
	if len(down) != 12 {
		t.Fatalf("down count: got %d", len(down))
	}
	assertHex(t, down[8], "00000000", "initial FBU")
	for i := 9; i < 12; i++ {
		assertHex(t, down[i], "00000000", "round FBU")
	}
}

// 3.2 认证失败路径: AuthResult=1 + reason, 无 ServerInit, 直接 FIN.
func TestAuthFailure(t *testing.T) {
	cfg := smallCfg()
	cfg.AuthResult = 1
	cfg.AuthReason = "bad password"
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")

	// down: version, secTypes, tunnel, authCaps, challenge, result(fail) = 6.
	if len(down) != 6 {
		t.Fatalf("down count: got %d want 6", len(down))
	}
	assertHex(t, down[5], "000000010000000c6261642070617373776f7264", "failure result + reason")
	if len(up) != 4 { // version, select, selectAuth, response
		t.Fatalf("up count: got %d want 4", len(up))
	}
	// No ServerInit: nothing after the failure result.
	// Teardown happens immediately: last 4 flags are FIN/ACK.
	flags := tcpFlags(cfgs)
	n := len(flags)
	if flags[n-4] != tcpFINACK || flags[n-3] != tcpACK || flags[n-2] != tcpFINACK || flags[n-1] != tcpACK {
		t.Fatalf("teardown flags: %02x %02x %02x %02x", flags[n-4], flags[n-3], flags[n-2], flags[n-1])
	}
}

// 3.3 security_type=2 纯 VNC 路径(无 caps,挑战-响应 + 结果 + ServerInit).
func TestSecurityType2(t *testing.T) {
	cfg := smallCfg()
	cfg.SecurityType = 2
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")
	// down: version, 02, challenge, result, ServerInit handshake (no caps),
	// then data plane (InitialFBU + round FBU).
	if len(down) < 5 {
		t.Fatalf("down count: got %d", len(down))
	}
	assertHex(t, down[1], "0102", "security types count=1 + type 2")
	assertHex(t, down[2], "46708ddc13a8b313c5991e6decfaf280", "challenge")
	assertHex(t, down[3], "00000000", "result")
	assertHex(t, down[4][:4], "04000300", "ServerInit starts with 1024x768")
	// up: version, 02, response, share handshake, then data plane.
	if len(up) < 4 {
		t.Fatalf("up count: got %d", len(up))
	}
	assertHex(t, up[1], "02", "client selects 2")
	assertHex(t, up[2], "df1324a50b30903a38c8f9b833262c6e", "response")
	assertHex(t, up[3], "01", "share")
}

// 3.4 security_type=1 None 路径(无挑战).
func TestSecurityType1(t *testing.T) {
	cfg := smallCfg()
	cfg.SecurityType = 1
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")
	// down: version, 01, result, ServerInit handshake (no challenge), then
	// data plane.
	if len(down) < 4 {
		t.Fatalf("down count: got %d", len(down))
	}
	assertHex(t, down[1], "0101", "security types count=1 + type 1")
	assertHex(t, down[2], "00000000", "result")
	assertHex(t, down[3][:4], "04000300", "ServerInit")
	// up: version, 01, share handshake, then data plane.
	if len(up) < 3 {
		t.Fatalf("up count: got %d", len(up))
	}
	assertHex(t, up[1], "01", "client selects 1")
	assertHex(t, up[2], "01", "share")
}

// 3.5 客户端消息开关: 关闭 SetPixelFormat/SetEncodings/KeyEvents → 握手后直接
// FBU req.
func TestClientMessagesDisabled(t *testing.T) {
	f := false
	cfg := smallCfg()
	cfg.ClientSetPixelFormat = &f
	cfg.ClientSetEncodings = &f
	cfg.KeyEvents = []core.VNCKeyEventConfig{}
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	up := msgs(cfgs, "up")
	// up: version, select, selectAuth, response, share, FBU req, [rounds
	// pointer, FBU req inc]
	post := up[5:]
	if len(post) != 3 {
		t.Fatalf("post-handshake up count: got %d want 3", len(post))
	}
	assertHex(t, post[0], "03000000000004000300", "first client message is FBU request")
	assertHex(t, post[1], "050001fb0140", "PointerEvent")
	assertHex(t, post[2], "03010000000004000300", "incremental FBU request")
}

// 3.6 附加服务器消息: Bell + SetColourMapEntries + ServerCutText 每轮 FBU 前.
func TestServerExtras(t *testing.T) {
	cfg := smallCfg()
	cfg.Bell = true
	cfg.SetColourMapEntries = &core.VNCColourMapConfig{First: 0, Colors: []string{"0000ff00ff00"}}
	cfg.ServerCutText = "hi"
	cfg.Rounds = 2
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down := msgs(cfgs, "down")
	// 8 handshake + 3×(Bell, ColourMap, CutText, FBU) with rounds=2.
	if len(down) != 8+3*4 {
		t.Fatalf("down count: got %d want %d", len(down), 8+3*4)
	}
	for i := 8; i < len(down); i += 4 {
		assertHex(t, down[i], "02", "Bell")
		assertHex(t, down[i+1], "0100000000010000ff00ff00", "SetColourMapEntries")
		assertHex(t, down[i+2], "03000000000000026869", "ServerCutText")
		assertHex(t, down[i+3], "00000000", "FBU")
	}
}

// 3.7 IPv6 主机: EtherType 0x86DD,端口与 payload 不变.
func TestIPv6Hosts(t *testing.T) {
	cfg := smallCfg()
	spec := vncSpec(cfg)
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	cfgs := mustPlan(t, NewPlanner(), spec)
	for _, c := range cfgs {
		if c.L2.EtherType != 0x86DD {
			t.Fatalf("packet EtherType: got %04x want 86dd", c.L2.EtherType)
		}
		// Ports swap with direction: the server side is the spec DstPort.
		if c.Direction == "up" && (c.L4.SrcPort != 1160 || c.L4.DstPort != 5901) {
			t.Fatalf("up ports changed: %d %d", c.L4.SrcPort, c.L4.DstPort)
		}
		if c.Direction == "down" && (c.L4.SrcPort != 5901 || c.L4.DstPort != 1160) {
			t.Fatalf("down ports changed: %d %d", c.L4.SrcPort, c.L4.DstPort)
		}
	}
	down := msgs(cfgs, "down")
	assertHex(t, down[0], "524642203030332e3030380a", "version over IPv6")
}

// --- 4.1 默认端口 ---

// 4.1 DstPort=0 → 默认 5900.
func TestDefaultPort(t *testing.T) {
	spec := vncSpec(smallCfg())
	spec.DstPort = 0
	cfgs := mustPlan(t, NewPlanner(), spec)
	for _, c := range cfgs {
		// DstPort=0 → 5900; the server side of the flow carries it.
		if c.Direction == "up" && c.L4.DstPort != 5900 {
			t.Fatalf("dst port: got %d want 5900", c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 5900 {
			t.Fatalf("server port: got %d want 5900", c.L4.SrcPort)
		}
	}
}

// --- 4.2 FBU 多矩形 + 大 Hextile 分段 ---

// 4.2a FBU nRects=2 多矩形.
func TestFBUMultiRect(t *testing.T) {
	cfg := smallCfg()
	cfg.InitialFBU = []core.VNCRectConfig{
		{X: 16, Y: 16, Width: 16, Height: 16, Encoding: "hextile"},
		{X: 0, Y: 0, Width: 2, Height: 2, Encoding: "raw"},
	}
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down := msgs(cfgs, "down")
	init := down[8]
	assertHex(t, init[:4], "00000002", "nRects=2")
	assertHex(t, init[4:16], "001000100010001000000005", "rect1 header hextile")
	assertHex(t, init[len(init)-28:len(init)-16], "000000000002000200000000", "rect2 header raw")
}

// 4.2b 大 Hextile rect(64×16 = 4 tiles × 1025B)超过 MSS → 3 段 PSH-ACK.
func TestHextileSegmentation(t *testing.T) {
	rect := core.VNCRectConfig{X: 0, Y: 0, Width: 64, Height: 16, Encoding: "hextile"}
	msg := buildFramebufferUpdate([]core.VNCRectConfig{rect})
	if len(msg) != 4+12+4*1025 {
		t.Fatalf("message length: got %d want %d", len(msg), 4+12+4*1025)
	}
	segments := segmentByMSS(msg, DefaultMSS)
	if len(segments) != 3 {
		t.Fatalf("segment count: got %d want 3", len(segments))
	}
	if len(segments[0]) != DefaultMSS || len(segments[1]) != DefaultMSS {
		t.Fatalf("segment sizes: %d %d", len(segments[0]), len(segments[1]))
	}
	var joined []byte
	for _, s := range segments {
		joined = append(joined, s...)
	}
	if hexStr(joined) != hexStr(msg) {
		t.Fatal("reassembled payload mismatch")
	}
	// Plan-level: the 4100B tile data message emits 3 consecutive PSH-ACK
	// data packets in the down direction.
	cfg := smallCfg()
	cfg.UpdateRects = []core.VNCRectConfig{rect}
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down := msgs(cfgs, "down")
	if len(down) != 8+1+3 {
		t.Fatalf("down count: got %d want 12", len(down))
	}
}

// --- 种子化挑战/响应 ---

func TestSeededChallengeResponse(t *testing.T) {
	cfg := smallCfg()
	cfg.ChallengeSeed = 42
	cfg.ResponseSeed = 7
	cfgs := mustPlan(t, NewPlanner(), vncSpec(cfg))
	down, up := msgs(cfgs, "down"), msgs(cfgs, "up")
	// Challenge is down[4] for Tight (version, secTypes, tunnel, authCaps, challenge).
	if len(down[4]) != 16 || len(up[3]) != 16 {
		t.Fatalf("challenge/response lengths: %d %d", len(down[4]), len(up[3]))
	}
	if hexStr(down[4]) == hexStr(referenceChallenge) {
		t.Fatal("seeded challenge must differ from the reference bytes")
	}
	if hexStr(up[3]) == hexStr(referenceResponse) {
		t.Fatal("seeded response must differ from the reference bytes")
	}
	// Deterministic: same seed twice → same bytes.
	got1 := seededBytes(42, 16)
	got2 := seededBytes(42, 16)
	if hexStr(got1) != hexStr(got2) {
		t.Fatal("seeded bytes not deterministic")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
