package protocolpcap

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseTsharkHex(t *testing.T) {
	out := "Frame 1: 66 bytes on wire (528 bits), 66 bytes captured\n" +
		"    Ethernet II, Src: 02:00:00:00:00:01\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 34 23 03 40 00 40 06 f9 9f 0a 00 00 01 14 00   .4#.@.@.........\n" +
		"0020  00 01 30 39 00 50 45 c8 f3 21 00 00 00 00 80 02   ..09.PE..!......\n" +
		"0030  ff ff e3 a0 00 00 02 04 05 b4 03 03 07 04 02 01   ................\n" +
		"0040  01 01                                             ..\n" +
		"\n" +
		"Frame 2: 66 bytes on wire (528 bits), 66 bytes captured\n" +
		"0000  02 00 00 00 00 01 02 00 00 00 00 02 08 00 45 20   ..............E \n" +
		"0010  00 34 23 04 40 00 40 06 f9 9e 14 00 00 01 0a 00   .4#.@.@.........\n"
	frames := parseTsharkHex(out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].frameNo != 1 || frames[1].frameNo != 2 {
		t.Fatalf("frame numbers = %d, %d, want 1, 2", frames[0].frameNo, frames[1].frameNo)
	}
	want := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x20,
		0x00, 0x34, 0x23, 0x03, 0x40, 0x00, 0x40, 0x06, 0xf9, 0x9f, 0x0a, 0x00, 0x00, 0x01, 0x14, 0x00,
		0x00, 0x01, 0x30, 0x39, 0x00, 0x50, 0x45, 0xc8, 0xf3, 0x21, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
		0xff, 0xff, 0xe3, 0xa0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0x01,
		0x01, 0x01}
	if !bytes.Equal(frames[0].bytes, want) {
		t.Fatalf("frame1 bytes mismatch: got %d bytes, want %d", len(frames[0].bytes), len(want))
	}
}

func TestParseTsharkHex_NoSeparatorsInAsciiGutter(t *testing.T) {
	// ASCII gutter with no spaces between characters (short trailing line).
	out := "0000  00 01 63 6f 6e 66 69 67 2e 74 78 74 00 6f 63 74   .config.txt.oct\n" +
		"0010  65 74 00                                          et.\n"
	frames := parseTsharkHex(out)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	want := []byte{0x00, 0x01, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00}
	if !bytes.Equal(frames[0].bytes, want) {
		t.Fatalf("bytes mismatch: %x vs %x", frames[0].bytes, want)
	}
}

func TestParseHexBytes(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
		err  bool
	}{
		{"00 01 63 6f", []byte{0x00, 0x01, 0x63, 0x6f}, false},
		{"0001636f", []byte{0x00, 0x01, 0x63, 0x6f}, false},
		{"00\n01", []byte{0x00, 0x01}, false},
		{"0", nil, true},
		{"0g", nil, true},
	}
	for _, c := range cases {
		got, err := parseHexBytes(c.in)
		if c.err {
			if err == nil {
				t.Errorf("%q: want error, got %x", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%q: got %x, want %x", c.in, got, c.want)
		}
	}
}

func TestMatchHexOffset(t *testing.T) {
	fb := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45}
	cases := []struct {
		offset int
		want   string
		ok     bool
	}{
		{0, "02 00 00 00 00 01", true},
		{0, "02", true},
		{6, "08 00", true},        // ethertype
		{6, "08 00 45 20", false}, // frame too short after offset
		{8, "45", true},           // exact tail byte
		{9, "45", false},          // offset == frame length: nothing to match
		{10, "02 03", false},      // mismatch
		{-1, "02", false},         // negative offset
		{99, "02", false},         // beyond frame
		{0, "", true},             // empty want matches at start
		{3, "", true},             // empty want matches anywhere
	}
	for _, c := range cases {
		ok, _ := matchHexOffset(fb, c.offset, mustHex(t, c.want))
		if ok != c.ok {
			t.Errorf("matchHexOffset(offset=%d, want=%q): got %v, want %v", c.offset, c.want, ok, c.ok)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := parseHexBytes(s)
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b
}

// TestVerifyPcap_FrameAssert exercises the FrameAssert path against a real
// pcap produced by the smoke case (tcp-handshake-basic).
func TestVerifyPcap_FrameAssert(t *testing.T) {
	// Requires tshark; skip when unavailable.
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skipf("tshark not available: %v", err)
	}
	if _, err := os.Stat("/tmp/mcp-pcaps/tcp/tcp-handshake-basic.pcap"); err != nil {
		t.Skip("smoke pcap not present; run the driver test first")
	}
	c := Case{ID: "frame-test", Proto: "tcp"}
	c.Expect.Frames = []FrameAssert{
		{Packet: 1, Hex: "02 00 00 00 00 02 02 00 00 00 00 01 08 00"}, // eth dst/src + ethertype
		{Packet: 1, Offset: 14, Hex: "45"},                            // IPv4 version/IHL
		{Packet: 1, Offset: 14, Hex: "45 20 00 34"},                   // version/IHL + total length (52)
		{Packet: 1, Offset: 22, Hex: "40 06"},                         // protocol (TCP)
		{Packet: 1, Offset: 34, Hex: "30 39 00 50"},                   // src port 12345, dst port 80
		{Packet: 1, Offset: 46, Hex: "80 02 ff ff"},                   // flags (SYN|NS) + window
	}
	probs := VerifyPcap("/tmp/mcp-pcaps/tcp/tcp-handshake-basic.pcap", c)
	if len(probs) > 0 {
		t.Fatalf("FrameAssert failed: %s", strings.Join(probs, "; "))
	}

	// Negative: wrong byte should fail.
	c2 := Case{ID: "frame-test-neg", Proto: "tcp"}
	c2.Expect.Frames = []FrameAssert{{Packet: 1, Hex: "02 00 00 00 00 99"}}
	probs = VerifyPcap("/tmp/mcp-pcaps/tcp/tcp-handshake-basic.pcap", c2)
	if len(probs) == 0 {
		t.Fatal("negative FrameAssert: expected failure, got pass")
	}
}
