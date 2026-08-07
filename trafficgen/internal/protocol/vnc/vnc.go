// Package vnc implements the VNC/RFB (RFC 6143) protocol planner.
//
// The reference pcap is a complete TightVNC session
// (/home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.143-20.3.1.143-1160-5901-1149-1631-69054-2262354.pcap,
// server "QTMS:1 (ykaul)", 1024×768, 32bpp): its 13 handshake messages are
// reproduced byte-for-byte by default (security type 16 = Tight, reference
// challenge/response bytes). The data plane emits Raw (0), Hextile (5) and
// XCursor (-240) encodings only - Tight zlib data is not modeled (design
// decision §7.4); reference-pcap garbage padding bytes are not reproduced
// (RFC padding is zero).
package vnc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the VNC TCP port (RFC 6143 §1.1; range 5900-5909).
	DefaultPort = 5900

	// security types (RFC 6143 §7.2.1).
	secTypeNone   = 1
	secTypeVNC    = 2
	secTypeTight  = 16
	secTypeVNCAuthCode = 2 // auth-caps record code: VNC Authentication

	// rect encodings (RFC 6143 appendix / TightVNC pseudo-encodings).
	encRaw      = 0
	encHextile  = 5
	encXCursor  = -240

	// TCP flags (mirror internal/protocol/rtsp).
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11

	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536
)

// versionString is the protocol version (RFC 6143 §7.1), 12 bytes including
// the trailing LF: "RFB 003.008\n".
var versionString = []byte("RFB 003.008\n")

// defaultKeyEvents mirrors the reference pcap's 6 key releases
// (RFC 6143 §8.4.4): 0xffe9 Page_Up, 0xffe3 Super_L, 0xffe1 Shift_L,
// 0xffea Page_Down, 0xffe4 Control_L, 0xffe2 Shift_R.
var defaultKeyEvents = []core.VNCKeyEventConfig{
	{Down: false, Key: 0xffe9},
	{Down: false, Key: 0xffe3},
	{Down: false, Key: 0xffe1},
	{Down: false, Key: 0xffea},
	{Down: false, Key: 0xffe4},
	{Down: false, Key: 0xffe2},
}

// defaultEncodings mirrors the reference pcap SetEncodings (15 entries):
// Hextile, 8, Tight, ZLIB, CoRRE, RRE, CopyRect, Raw, CompressLevel6 (-250),
// XCursor (-240), RichCursor (-239), PointerPos (-232), QualityLevel6 (-26),
// LastRect (-224), NewFBSize (-223).
var defaultEncodings = []int{5, 8, 7, 6, 4, 2, 1, 0, -250, -240, -239, -232, -26, -224, -223}

// referenceChallenge / referenceResponse are the reference pcap's fixed
// 16-byte challenge and DES-ciphertext response (byte-exact reproduction by
// default; seedable via ChallengeSeed/ResponseSeed).
var referenceChallenge = []byte{0x46, 0x70, 0x8d, 0xdc, 0x13, 0xa8, 0xb3, 0x13, 0xc5, 0x99, 0x1e, 0x6d, 0xec, 0xfa, 0xf2, 0x80}
var referenceResponse = []byte{0xdf, 0x13, 0x24, 0xa5, 0x0b, 0x30, 0x90, 0x3a, 0x38, 0xc8, 0xf9, 0xb8, 0x33, 0x26, 0x2c, 0x6e}

// defaultXCursorBlob is the reference pcap's 82-byte XCursor blob
// (6B fg/bg colors + 38B 1bpp bitmap (19 rows x 2B) + 38B mask (19 rows x 2B)),
// reproduced verbatim by default. The reference bitmap has 3 leading all-zero
// rows; an 80B blob (2 leading rows) misaligns Wireshark's FBU length math and
// makes it dissect the framebuffer segment by segment.
var defaultXCursorBlob, _ = hex.DecodeString(
	"000000ffffff" +
		"00000000000040006000700078005c007e005f007f807c006e00460006000300038001000000" +
		"8000c000e000f000f800fc00fe00ff00ff80ffc0ffe0fff0ff00ff00cf00cf80078007c00300")

// defaultCaps mirrors the reference pcap Interaction Caps records (11).
var defaultCaps = []core.VNCCapabilityConfig{
	{Code: 0x00000002, Vendor: "STDV", Name: "RRE_____"},
	{Code: 0x00000005, Vendor: "STDV", Name: "HEXTILE_"},
	{Code: 0x00000007, Vendor: "TGHT", Name: "TIGHT___"},
	{Code: 0x00000010, Vendor: "STDV", Name: "ZRLE____"},
	{Code: 0x00000001, Vendor: "STDV", Name: "COPYRECT"},
	{Code: 0xffffff00, Vendor: "TGHT", Name: "COMPRLVL"},
	{Code: 0xffffffe0, Vendor: "TGHT", Name: "JPEGQLVL"},
	{Code: 0xffffff10, Vendor: "TGHT", Name: "X11CURSR"},
	{Code: 0xffffff11, Vendor: "TGHT", Name: "RCHCURSR"},
	{Code: 0xffffff20, Vendor: "TGHT", Name: "LASTRECT"},
	{Code: 0xffffff21, Vendor: "STDV", Name: "NEWFBSIZ"},
}

// Planner implements the VNC protocol planner.
type Planner struct{}

// NewPlanner creates a new VNC planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "vnc"
}

// Validate validates a VNC flow spec (design_vnc.md §6).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.VNC == nil {
		return fmt.Errorf("vnc config is required")
	}
	cfg := spec.VNC

	if st := cfg.SecurityType; st != secTypeNone && st != secTypeVNC && st != secTypeTight {
		return fmt.Errorf("invalid vnc security type %d (allowed: 1, 2, 16)", st)
	}
	if ar := cfg.AuthResult; ar < 0 || ar > 2 {
		return fmt.Errorf("invalid vnc auth result %d (allowed: 0, 1, 2)", ar)
	}
	if cfg.Width < 1 || cfg.Width > 65535 {
		return fmt.Errorf("invalid vnc width %d (allowed: 1-65535)", cfg.Width)
	}
	if cfg.Height < 1 || cfg.Height > 65535 {
		return fmt.Errorf("invalid vnc height %d (allowed: 1-65535)", cfg.Height)
	}
	if cfg.Rounds < 1 {
		return fmt.Errorf("invalid vnc rounds %d", cfg.Rounds)
	}
	if cfg.PointerX < 0 || cfg.PointerX > 65535 {
		return fmt.Errorf("invalid vnc pointer x %d (allowed: 0-65535)", cfg.PointerX)
	}
	if cfg.PointerY < 0 || cfg.PointerY > 65535 {
		return fmt.Errorf("invalid vnc pointer y %d (allowed: 0-65535)", cfg.PointerY)
	}
	if cfg.PointerButton < 0 || cfg.PointerButton > 255 {
		return fmt.Errorf("invalid vnc pointer button %d (allowed: 0-255)", cfg.PointerButton)
	}
	if cfg.FBUUpdateInterval < 1 {
		return fmt.Errorf("invalid vnc fbu update interval %d", cfg.FBUUpdateInterval)
	}
	if pf := cfg.PixelFormat; pf != nil {
		if pf.BitsPerPixel != 8 && pf.BitsPerPixel != 16 && pf.BitsPerPixel != 32 {
			return fmt.Errorf("invalid vnc pixel format bpp %d (allowed: 8, 16, 32)", pf.BitsPerPixel)
		}
		if pf.Depth < 1 || pf.Depth > pf.BitsPerPixel {
			return fmt.Errorf("invalid vnc pixel format depth %d (allowed: 1-%d)", pf.Depth, pf.BitsPerPixel)
		}
	}
	for _, ke := range cfg.KeyEvents {
		if ke.Key < 0 || ke.Key > 0xFFFFFFFF {
			return fmt.Errorf("invalid vnc key %d", ke.Key)
		}
	}
	for _, e := range cfg.Encodings {
		if e < -256 || e > 0x7FFFFFFF {
			return fmt.Errorf("invalid vnc encoding %d", e)
		}
	}
	for _, r := range cfg.InitialFBU {
		if err := validateRect(r); err != nil {
			return err
		}
	}
	for _, r := range cfg.UpdateRects {
		if err := validateRect(r); err != nil {
			return err
		}
	}
	if cm := cfg.SetColourMapEntries; cm != nil {
		for _, c := range cm.Colors {
			if _, err := hex.DecodeString(c); err != nil {
				return fmt.Errorf("invalid vnc colour %q", c)
			}
		}
	}
	return nil
}

func validateRect(r core.VNCRectConfig) error {
	if r.X < 0 || r.X > 65535 || r.Y < 0 || r.Y > 65535 ||
		r.Width < 1 || r.Width > 65535 || r.Height < 1 || r.Height > 65535 {
		return fmt.Errorf("invalid vnc rect %d %d %d %d", r.X, r.Y, r.Width, r.Height)
	}
	if r.Encoding != "" && r.Encoding != "raw" && r.Encoding != "hextile" && r.Encoding != "xcursor" {
		return fmt.Errorf("invalid vnc rect encoding %q (allowed: raw, hextile, xcursor)", r.Encoding)
	}
	if r.XCursorBlob != "" {
		b, err := hex.DecodeString(r.XCursorBlob)
		if err != nil || len(b) < 6 {
			return fmt.Errorf("invalid vnc xcursor blob %q", r.XCursorBlob)
		}
	}
	if r.HextileTileData != "" {
		if _, err := hex.DecodeString(r.HextileTileData); err != nil {
			return fmt.Errorf("invalid vnc hextile data %q", r.HextileTileData)
		}
	}
	return nil
}

// --- message builders (design_vnc.md §3-§4) ---

// secTypesBytes encodes the security-type list (RFC 6143 §7.2.1): the
// message is always [u8 count][count × u8 type], even for a single type.
// Tight (16) offers [2, 16] with a count byte (reference pcap); a server
// offering only VNC Auth (2) or None (1) sends count=1 + the type byte.
func secTypesBytes(secType int) []byte {
	switch secType {
	case secTypeTight:
		return []byte{0x02, 0x02, 0x10}
	case secTypeVNC:
		return []byte{0x01, 0x02}
	default:
		return []byte{0x01, 0x01}
	}
}

// buildServerInit encodes ServerInit (RFC 6143 §7.3.2): framebuffer-width
// u16 + framebuffer-height u16 + pixel format 16B + nameLen u32 + name.
func buildServerInit(width, height int, name string, pf *core.VNCPixelFormatConfig) []byte {
	p := pixelFormatBytes(pf)
	out := make([]byte, 0, 4+16+4+len(name))
	out = append(out, byte(width>>8), byte(width))
	out = append(out, byte(height>>8), byte(height))
	out = append(out, p...)
	out = append(out, byte(len(name)>>24), byte(len(name)>>16), byte(len(name)>>8), byte(len(name)))
	out = append(out, name...)
	return out
}

// pixelFormatBytes encodes the RFC 6143 §7.3.3 pixel format (16 bytes). A nil
// config uses the reference pcap default (32bpp/24bit/little-endian
// true-color/255/16/8/0).
func pixelFormatBytes(pf *core.VNCPixelFormatConfig) []byte {
	bpp, depth := 32, 24
	bigEndian, trueColor := false, true
	redMax, greenMax, blueMax := 255, 255, 255
	redShift, greenShift, blueShift := 16, 8, 0
	if pf != nil {
		if pf.BitsPerPixel != 0 {
			bpp = pf.BitsPerPixel
		}
		if pf.Depth != 0 {
			depth = pf.Depth
		}
		bigEndian = pf.BigEndian
		trueColor = pf.TrueColor
		if pf.RedMax != 0 {
			redMax = pf.RedMax
		}
		if pf.GreenMax != 0 {
			greenMax = pf.GreenMax
		}
		if pf.BlueMax != 0 {
			blueMax = pf.BlueMax
		}
		if pf.RedShift != 0 {
			redShift = pf.RedShift
		}
		if pf.GreenShift != 0 {
			greenShift = pf.GreenShift
		}
		if pf.BlueShift != 0 {
			blueShift = pf.BlueShift
		}
	}
	out := make([]byte, 0, 16)
	out = append(out, byte(bpp), byte(depth))
	if bigEndian {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	if trueColor {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, byte(redMax>>8), byte(redMax))
	out = append(out, byte(greenMax>>8), byte(greenMax))
	out = append(out, byte(blueMax>>8), byte(blueMax))
	out = append(out, byte(redShift), byte(greenShift), byte(blueShift), 0, 0, 0)
	return out
}

// buildAuthCaps encodes the Tight auth capabilities (design_vnc.md §3.1):
// count u32 + one record (code u32 + vendor 4B + name 8B) for VNC
// Authentication. The reference pcap advertises exactly one record.
func buildAuthCaps() []byte {
	out := make([]byte, 0, 4+16)
	out = append(out, 0, 0, 0, 1)
	out = append(out, 0, 0, 0, byte(secTypeVNCAuthCode))
	out = append(out, []byte("STDV")...)
	out = append(out, []byte("VNCAUTH_")...)
	return out
}

// buildSecurityResult encodes SecurityResult (RFC 6143 §7.2.2): u32 result
// (0 = OK), and on failure a reasonLen u32 + reason string.
func buildSecurityResult(authResult int, reason string) []byte {
	out := make([]byte, 0, 4)
	out = append(out, byte(uint32(authResult)>>24), byte(uint32(authResult)>>16), byte(uint32(authResult)>>8), byte(authResult))
	if authResult != 0 {
		out = append(out, byte(len(reason)>>24), byte(len(reason)>>16), byte(len(reason)>>8), byte(len(reason)))
		out = append(out, reason...)
	}
	return out
}

// buildInteractionCaps encodes the TightVNC Interaction Caps message: 4×u16
// header (nServerMessageTypes, nClientMessageTypes, nEncodingTypes, pad) +
// 16-byte capability records. A nil config uses the reference pcap default
// (0/11/0 + the 11 records).
func buildInteractionCaps(ic *core.VNCInteractionCapsConfig) []byte {
	nServer, nClient, nEnc := 0, 11, 0
	caps := defaultCaps
	if ic != nil {
		nServer, nClient, nEnc = ic.ServerMsgTypes, ic.ClientMsgTypes, ic.EncodingTypes
		if ic.Caps != nil {
			caps = ic.Caps
		}
	}
	out := make([]byte, 0, 8+16*len(caps))
	out = append(out, byte(nServer>>8), byte(nServer))
	out = append(out, byte(nClient>>8), byte(nClient))
	out = append(out, byte(nEnc>>8), byte(nEnc))
	out = append(out, 0, 0)
	for _, c := range caps {
		out = append(out, byte(uint32(c.Code)>>24), byte(uint32(c.Code)>>16), byte(uint32(c.Code)>>8), byte(c.Code))
		v := []byte(c.Vendor)
		for len(v) < 4 {
			v = append(v, '_')
		}
		out = append(out, v[:4]...)
		n := []byte(c.Name)
		for len(n) < 8 {
			n = append(n, '_')
		}
		out = append(out, n[:8]...)
	}
	return out
}

// buildKeyEvent encodes a KeyEvent (RFC 6143 §8.4.4): type 04 + down u8 +
// pad 2B + key u32.
func buildKeyEvent(down bool, key int) []byte {
	out := make([]byte, 0, 8)
	out = append(out, 0x04)
	if down {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, 0, 0)
	out = append(out, byte(uint32(key)>>24), byte(uint32(key)>>16), byte(uint32(key)>>8), byte(key))
	return out
}

// buildSetPixelFormat encodes SetPixelFormat (RFC 6143 §8.1): type 00 + pad
// 3B + pixel format 16B.
func buildSetPixelFormat(pf *core.VNCPixelFormatConfig) []byte {
	out := make([]byte, 0, 20)
	out = append(out, 0x00, 0x00, 0x00, 0x00)
	return append(out, pixelFormatBytes(pf)...)
}

// buildSetEncodings encodes SetEncodings (RFC 6143 §8.2): type 02 + pad 1B +
// nEncodings u16 + 4B×n. A nil list uses the reference pcap's 15 encodings.
func buildSetEncodings(enc []int) []byte {
	list := enc
	if list == nil {
		list = defaultEncodings
	}
	out := make([]byte, 0, 4+4*len(list))
	out = append(out, 0x02, 0x00)
	out = append(out, byte(len(list)>>8), byte(len(list)))
	for _, e := range list {
		out = append(out, byte(uint32(e)>>24), byte(uint32(e)>>16), byte(uint32(e)>>8), byte(e))
	}
	return out
}

// buildFBURequest encodes FramebufferUpdateRequest (RFC 6143 §8.3): type 03 +
// incremental u8 + x u16 + y u16 + w u16 + h u16.
func buildFBURequest(incremental bool, width, height int) []byte {
	out := make([]byte, 0, 10)
	out = append(out, 0x03)
	if incremental {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, 0, 0, 0, 0)
	out = append(out, byte(width>>8), byte(width))
	out = append(out, byte(height>>8), byte(height))
	return out
}

// buildPointerEvent encodes PointerEvent (RFC 6143 §8.4.3): type 05 +
// buttonMask u8 + x u16 + y u16.
func buildPointerEvent(button, x, y int) []byte {
	out := make([]byte, 0, 6)
	out = append(out, 0x05, byte(button))
	out = append(out, byte(x>>8), byte(x))
	out = append(out, byte(y>>8), byte(y))
	return out
}

// buildClientCutText encodes ClientCutText (RFC 6143 §8.5): type 06 + pad 3B
// + length u32 + text.
func buildClientCutText(text string) []byte {
	out := make([]byte, 0, 8+len(text))
	out = append(out, 0x06, 0, 0, 0)
	out = append(out, byte(len(text)>>24), byte(len(text)>>16), byte(len(text)>>8), byte(len(text)))
	return append(out, text...)
}

// buildServerCutText encodes ServerCutText (RFC 6143 §9.4): type 03 + pad 3B
// + length u32 + text.
func buildServerCutText(text string) []byte {
	out := make([]byte, 0, 8+len(text))
	out = append(out, 0x03, 0, 0, 0)
	out = append(out, byte(len(text)>>24), byte(len(text)>>16), byte(len(text)>>8), byte(len(text)))
	return append(out, text...)
}

// buildSetColourMapEntries encodes SetColourMapEntries (RFC 6143 §9.2):
// type 01 + pad 1B + first u16 + num u16 + 6B×num (2B red + 2B green + 2B
// blue per entry).
func buildSetColourMapEntries(first int, colors []string) []byte {
	out := make([]byte, 0, 8+6*len(colors))
	out = append(out, 0x01, 0x00)
	out = append(out, byte(first>>8), byte(first))
	out = append(out, byte(len(colors)>>8), byte(len(colors)))
	for _, c := range colors {
		b, _ := hex.DecodeString(c)
		if len(b) != 6 {
			b = make([]byte, 6)
		}
		out = append(out, b...)
	}
	return out
}

// buildFramebufferUpdate encodes FramebufferUpdate (RFC 6143 §9.1): type 00 +
// pad 1B + nRects u16 + rects.
func buildFramebufferUpdate(rects []core.VNCRectConfig) []byte {
	out := make([]byte, 0, 4)
	out = append(out, 0x00, 0x00)
	out = append(out, byte(len(rects)>>8), byte(len(rects)))
	for _, r := range rects {
		out = append(out, buildRect(r)...)
	}
	return out
}

// buildRect encodes one FBU rectangle: x u16 + y u16 + w u16 + h u16 +
// encoding i32 + encoding data.
func buildRect(r core.VNCRectConfig) []byte {
	out := make([]byte, 0, 12)
	out = append(out, byte(r.X>>8), byte(r.X))
	out = append(out, byte(r.Y>>8), byte(r.Y))
	out = append(out, byte(r.Width>>8), byte(r.Width))
	out = append(out, byte(r.Height>>8), byte(r.Height))
	switch r.Encoding {
	case "raw":
		out = append(out, 0, 0, 0, 0)
		out = append(out, rawPixels(r.Width, r.Height)...)
	case "xcursor":
		xc := int32(encXCursor)
		out = append(out, byte(uint32(xc)>>24), byte(uint32(xc)>>16), byte(uint32(xc)>>8), byte(xc))
		blob := defaultXCursorBlob
		if r.XCursorBlob != "" {
			blob, _ = hex.DecodeString(r.XCursorBlob)
		}
		out = append(out, blob...)
	default: // "hextile" and empty (default encoding)
		out = append(out, 0, 0, 0, byte(encHextile))
		out = append(out, hextileData(r)...)
	}
	return out
}

// rawPixels generates w×h pixels of 4B BGRX each. Pixel n (row-major) is
// [(n*13+1)&0xFF, (n*13+2)&0xFF, (n*13+3)&0xFF, (n*13+4)&0xFF] — a
// deterministic fill assertable byte-by-byte in tests.
func rawPixels(w, h int) []byte {
	out := make([]byte, 0, w*h*4)
	for n := 0; n < w*h; n++ {
		out = append(out, byte((n*13+1)&0xFF), byte((n*13+2)&0xFF), byte((n*13+3)&0xFF), byte((n*13+4)&0xFF))
	}
	return out
}

// hextileData encodes a rect as 16×16 tiles (RFC 6143 appendix), each tile =
// ctrl u8 + payload. Default tile = ctrl 0x01 + raw w×h×4 pixels (reference
// pcap FBU#2 pattern); HextileTileData (hex of one tile's ctrl+payload) is
// repeated for every tile when set.
func hextileData(r core.VNCRectConfig) []byte {
	out := make([]byte, 0, (r.Width*r.Height*4)/16)
	if r.HextileTileData != "" {
		tile, _ := hex.DecodeString(r.HextileTileData)
		for ty := 0; ty < r.Height; ty += 16 {
			for tx := 0; tx < r.Width; tx += 16 {
				out = append(out, tile...)
			}
		}
		return out
	}
	for ty := 0; ty < r.Height; ty += 16 {
		tileH := 16
		if r.Height-ty < 16 {
			tileH = r.Height - ty
		}
		for tx := 0; tx < r.Width; tx += 16 {
			tileW := 16
			if r.Width-tx < 16 {
				tileW = r.Width - tx
			}
			out = append(out, 0x01)
			out = append(out, rawPixels(tileW, tileH)...)
		}
	}
	return out
}

// --- Plan ---

// Plan generates packet configs for one VNC TCP session: handshake
// (version → security → auth → ServerInit) then client messages and server
// framebuffer updates per Rounds, then TCP teardown (design_vnc.md §4).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.VNC

	// Apply defaults here too: Validate sees a value copy, so defaults
	// applied there are lost for Plan.
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	secType := cfg.SecurityType
	if secType == 0 {
		secType = secTypeTight
	}
	width, height := cfg.Width, cfg.Height
	if width < 1 {
		width = 1024
	}
	if height < 1 {
		height = 768
	}
	name := cfg.ServerName
	if name == "" {
		name = "QTMS:1 (ykaul)"
	}
	rounds := cfg.Rounds
	if rounds < 1 {
		rounds = 1
	}
	fbuInterval := cfg.FBUUpdateInterval
	if fbuInterval < 1 {
		fbuInterval = 1
	}
	share := true
	if cfg.ShareDesktop != nil {
		share = *cfg.ShareDesktop
	}
	sendPixelFormat := true
	if cfg.ClientSetPixelFormat != nil {
		sendPixelFormat = *cfg.ClientSetPixelFormat
	}
	sendEncodings := true
	if cfg.ClientSetEncodings != nil {
		sendEncodings = *cfg.ClientSetEncodings
	}
	keyEvents := cfg.KeyEvents
	if keyEvents == nil {
		keyEvents = defaultKeyEvents
	}
	initialFBU := cfg.InitialFBU
	if initialFBU == nil {
		initialFBU = []core.VNCRectConfig{
			{X: 0, Y: 1, Width: 12, Height: 19, Encoding: "xcursor"},
			{X: 0, Y: 0, Width: width, Height: height, Encoding: "hextile"},
		}
	}
	updateRects := cfg.UpdateRects
	if updateRects == nil {
		updateRects = []core.VNCRectConfig{
			{X: 16, Y: 16, Width: 16, Height: 16, Encoding: "hextile"},
			{X: 32, Y: 32, Width: 16, Height: 16, Encoding: "hextile"},
		}
	}
	challenge := referenceChallenge
	if cfg.ChallengeSeed != 0 {
		challenge = seededBytes(cfg.ChallengeSeed, 16)
	}
	response := referenceResponse
	if cfg.ResponseSeed != 0 {
		response = seededBytes(cfg.ResponseSeed, 16)
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		select {
		case <-ctx.Done():
			return
		default:
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()
		ipID := randomIPID()
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}
		ttl := spec.TTL
		if ttl == 0 {
			ttl = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randomUint32()
		}
		serverSeq := randomUint32()

		packetIndex := uint64(0)

		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, ttl, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: 65535,
			}
			if flags == tcpSYN || flags == tcpSYNACK {
				l4.TCPOptions = synOpts
			}
			cfgOut := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:      l3,
				L4:      l4,
				Payload: payload,
			}
			select {
			case configChan <- cfgOut:
			case <-ctx.Done():
			}
			packetIndex++
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, tcpPSHACK, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		up := func(seq, peer uint32, payload []byte) uint32 {
			return emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, seq, peer, payload)
		}
		down := func(seq, peer uint32, payload []byte) uint32 {
			return emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, seq, peer, payload)
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, tcpSYN, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpSYNACK, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)

		// --- handshake messages (design_vnc.md §3.1; server speaks first) ---
		serverSeq = down(serverSeq, clientSeq, versionString)
		clientSeq = up(clientSeq, serverSeq, versionString) // client echoes version
		serverSeq = down(serverSeq, clientSeq, secTypesBytes(secType))
		clientSeq = up(clientSeq, serverSeq, []byte{byte(secType)})
		if secType == secTypeTight {
			serverSeq = down(serverSeq, clientSeq, []byte{0, 0, 0, 0}) // tunnel caps: none
			serverSeq = down(serverSeq, clientSeq, buildAuthCaps())
			clientSeq = up(clientSeq, serverSeq, []byte{0, 0, 0, 2}) // select VNC Auth
		}
		if secType == secTypeTight || secType == secTypeVNC {
			serverSeq = down(serverSeq, clientSeq, challenge)
			clientSeq = up(clientSeq, serverSeq, response)
		}
		serverSeq = down(serverSeq, clientSeq, buildSecurityResult(cfg.AuthResult, cfg.AuthReason))

		if cfg.AuthResult != 0 {
			// authentication failed: no ClientInit/ServerInit, teardown.
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpFINACK, nil)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpACK, nil)
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpFINACK, nil)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)
			return
		}

		// --- ClientInit (shared-flag) + ServerInit ---
		if share {
			clientSeq = up(clientSeq, serverSeq, []byte{0x01})
		} else {
			clientSeq = up(clientSeq, serverSeq, []byte{0x00})
		}
		serverSeq = down(serverSeq, clientSeq, buildServerInit(width, height, name, cfg.PixelFormat))
		if secType == secTypeTight {
			serverSeq = down(serverSeq, clientSeq, buildInteractionCaps(cfg.InteractionCaps))
		}

		// --- client messages after the handshake ---
		if sendPixelFormat {
			clientSeq = up(clientSeq, serverSeq, buildSetPixelFormat(cfg.PixelFormat))
		}
		if sendEncodings {
			clientSeq = up(clientSeq, serverSeq, buildSetEncodings(cfg.Encodings))
		}
		for _, ke := range keyEvents {
			clientSeq = up(clientSeq, serverSeq, buildKeyEvent(ke.Down, ke.Key))
		}
		// full-screen non-incremental FBU request
		clientSeq = up(clientSeq, serverSeq, buildFBURequest(false, width, height))
		if cfg.ClientCutText != "" {
			clientSeq = up(clientSeq, serverSeq, buildClientCutText(cfg.ClientCutText))
		}

		// server extras before each FramebufferUpdate (Bell / colour map /
		// cut text)
		extras := func(seq, peer uint32) uint32 {
			if cfg.Bell {
				seq = down(seq, peer, []byte{0x02})
			}
			if cm := cfg.SetColourMapEntries; cm != nil {
				seq = down(seq, peer, buildSetColourMapEntries(cm.First, cm.Colors))
			}
			if cfg.ServerCutText != "" {
				seq = down(seq, peer, buildServerCutText(cfg.ServerCutText))
			}
			return seq
		}

		// --- initial framebuffer update ---
		serverSeq = extras(serverSeq, clientSeq)
		serverSeq = down(serverSeq, clientSeq, buildFramebufferUpdate(initialFBU))

		// --- data plane rounds: PointerEvent (up) → FBU(s) (down) ---
		for r := 0; r < rounds; r++ {
			clientSeq = up(clientSeq, serverSeq, buildPointerEvent(cfg.PointerButton, cfg.PointerX, cfg.PointerY))
			for i := 0; i < fbuInterval; i++ {
				serverSeq = extras(serverSeq, clientSeq)
				serverSeq = down(serverSeq, clientSeq, buildFramebufferUpdate(updateRects))
			}
		}

		// --- incremental full-screen FBU request after the last round ---
		clientSeq = up(clientSeq, serverSeq, buildFBURequest(true, width, height))

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpFINACK, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpACK, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpFINACK, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)
	}()

	return configChan, nil
}

// seededBytes derives n deterministic bytes from a seed (xorshift64*), used
// for the challenge/response when ChallengeSeed/ResponseSeed != 0.
func seededBytes(seed uint64, n int) []byte {
	out := make([]byte, n)
	state := seed
	for i := 0; i < n; i++ {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		out[i] = byte(state * 2685821657736338717 >> 56)
	}
	return out
}

// segmentByMSS splits a payload into MSS-sized chunks (RFC 879). An empty
// payload yields a single empty chunk. Mirrors internal/protocol/rtsp.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted. Mirrors internal/protocol/rtsp.synOptions.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// randomIPID returns a random 16-bit IP identification seed.
func randomIPID() uint16 {
	b, err := randomBytes(2)
	if err != nil {
		return 0x1234
	}
	return binary.BigEndian.Uint16(b)
}

// randomUint32 returns a random uint32 (crypto/rand; deterministic fallback
// on the practically impossible failure path).
func randomUint32() uint32 {
	b, err := randomBytes(4)
	if err != nil {
		return 0x12345678
	}
	return binary.BigEndian.Uint32(b)
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
