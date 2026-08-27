package protocolpcap

import (
	"bytes"
	"fmt"
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
	if frames[0].FrameNo != 1 || frames[1].FrameNo != 2 {
		t.Fatalf("frame numbers = %d, %d, want 1, 2", frames[0].FrameNo, frames[1].FrameNo)
	}
	want := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x20,
		0x00, 0x34, 0x23, 0x03, 0x40, 0x00, 0x40, 0x06, 0xf9, 0x9f, 0x0a, 0x00, 0x00, 0x01, 0x14, 0x00,
		0x00, 0x01, 0x30, 0x39, 0x00, 0x50, 0x45, 0xc8, 0xf3, 0x21, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
		0xff, 0xff, 0xe3, 0xa0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0x01,
		0x01, 0x01}
	if !bytes.Equal(frames[0].Bytes, want) {
		t.Fatalf("frame1 bytes mismatch: got %d bytes, want %d", len(frames[0].Bytes), len(want))
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
	if !bytes.Equal(frames[0].Bytes, want) {
		t.Fatalf("bytes mismatch: %x vs %x", frames[0].Bytes, want)
	}
}

func TestParseTsharkHex_AsciiGutterHexLookalikes(t *testing.T) {
	// Regression: the ASCII gutter can contain tokens that look like 2-char
	// hex bytes ("00" in "00 OK", "30 30" digits, "2e"/"30" in ".0.0"). The
	// parser must count the 16 byte columns, never swallow gutter tokens.
	out := "0000  48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d   HTTP/1.1 200 OK.\n" +
		"0010  0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a   .Content-Length:\n" +
		"0020  20 32 31 38 0d 0a 0d 0a 65 76 65 6e 74 3a 20 65   218....event: e\n" +
		"0030  6e 64 70 6f 69 6e 74 0a 64 61 74 61 3a 20 2f 6d   ndpoint.data: /m\n" +
		"0040  63 70 0a 0a 65 76 65 6e 74 3a 20 65 6e 64 70 6f   cp..event: endpo\n"
	frames := parseTsharkHex(out)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	// 80 wanted bytes: five 16-byte lines. The final line's hex columns end
	// with "20" (not "65"), so its two trailing columns "65 76" are in the
	// ASCII gutter and must NOT leak into the frame bytes.
	if len(frames[0].Bytes) != 80 {
		t.Fatalf("got %d bytes, want 80 (gutter lookalikes must not leak in)", len(frames[0].Bytes))
	}
	want := []byte("HTTP/1.1 200 OK\r\nContent-Length: 218\r\n\r\nevent: endpoint\ndata: /mcp\n\n" +
		"event: endpo")
	if !bytes.Equal(frames[0].Bytes, want) {
		t.Fatalf("bytes mismatch: %q vs %q", frames[0].Bytes, want)
	}
}

func TestParseTsharkHex_FiveDigitOffsets(t *testing.T) {
	// Regression: tshark -x emits 5-digit hex offsets (00000, 00010, ...)
	// once a frame's byte offset reaches 0x10000. Frames >= 65536 bytes
	// therefore have hex-dump lines whose offset column is 5 chars, not 4.
	// The parser previously rejected those lines (isHexDumpLine required
	// exactly 4 chars) AND overflowed on the 16-bit ParseUint for offsets
	// >= 0x10000, so the entire big frame was silently dropped, shifting
	// every subsequent FrameAssert packet index by one.
	//
	// This mirrors a real 65610-byte gbt32960 frame (gbt_t118_dataunit_65531)
	// whose dump lines run 00000 -> 10010.
	frameSmall := "0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 2a 00 01 40 00 40 06 00 00 0a 00 00 01 0a 00   .*..@.@.........\n" +
		"0020  00 02 30 39 27 10 00 00 00 00 00 00 50 02 ff ff   ..09'.........P.\n" +
		"002c  00 00 00 00                                       ....\n"
	// Build a realistic 65552-byte frame dump: 4097 contiguous lines from
	// 00000 to 10010, 16 bytes each (tshark never leaves gaps between lines).
	want := make([]byte, 65552)
	for i := range want {
		want[i] = byte(i % 251)
	}
	want[0], want[1], want[2], want[3] = 0x23, 0x23, 0x02, 0xfe // gbt32960 start flag + cmd
	want[0x1000F] = 0x5a                                        // tail spot marker (last byte)
	var big strings.Builder
	for off := 0; off < len(want); off += 16 {
		fmt.Fprintf(&big, "%05x  ", off)
		for j := 0; j < 16; j++ {
			fmt.Fprintf(&big, "%02x ", want[off+j])
		}
		big.WriteString("  ................\n")
	}
	out := "Frame 1: 52 bytes on wire\n" + frameSmall + "\n" +
		"Frame 2: 65552 bytes on wire\n" + big.String() + "\n" +
		"Frame 3: 52 bytes on wire\n" + frameSmall
	frames := parseTsharkHex(out)
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3 (5-digit-offset frame must not be dropped)", len(frames))
	}
	if !bytes.Equal(frames[1].Bytes, want) {
		t.Fatalf("frame2: got %d bytes, want %d (5-digit lines must merge into the frame)", len(frames[1].Bytes), len(want))
	}
	if len(frames[2].Bytes) != 52 {
		t.Fatalf("frame3: got %d bytes, want 52 (index shift after big frame)", len(frames[2].Bytes))
	}
}

func TestParseTsharkHex_ReassembledTCPPhantom(t *testing.T) {
	// Regression: tshark -x appends "Reassembled TCP (N bytes)" hex blocks to
	// frames carrying partial TCP segments. These blocks start with "0000" and
	// were being parsed as new frames, shifting every subsequent FrameAssert
	// packet index. The fix is twofold: (1) hexDumpAll disables TCP
	// desegmentation so each segment appears as its own frame; (2) the parser
	// recognizes "Reassembled TCP" preamble lines and stops the current frame.
	out := "Frame (64 bytes):\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 32 3a 77 40 00 40 06 eb ca 0a 00 00 64 0a 00   .2:w@.@......d..\n" +
		"0020  00 01 30 39 4e 20 1b 71 15 27 2f bd e2 bd 50 18   ..09N .q.'/...P.\n" +
		"0030  ff ff ee c9 00 00 05 64 00 80 00 04 01 00 e4 3f   .......d.......?\n" +
		"Reassembled TCP (13 bytes):\n" +
		"0000  ff 92 9c 05 64 00 80 00 04 01 00 e4 3f            ....d.......?\n" +
		"\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 41 3a 78 40 00 40 06 eb ba 0a 00 00 64 0a 00   .A:x@.@......d..\n" +
		"0020  00 01 30 39 4e 20 1b 71 15 31 2f bd e2 bd 50 18   ..09N .q.1/...P.\n" +
		"0030  ff ff 28 d4 00 00 05 64 0f d3 00 04 01 00 24 84   ..(....d......$.\n"
	frames := parseTsharkHex(out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2 (Reassembled TCP phantom must not create a 3rd)", len(frames))
	}
	wantLen := 64
	if len(frames[0].Bytes) != wantLen {
		t.Fatalf("frame1: got %d bytes, want %d (phantom must not be appended)", len(frames[0].Bytes), wantLen)
	}
	// Frame 2 must start with the new segment's Ethernet header, not the
	// phantom's first byte (0xff).
	if frames[1].Bytes[0] != 0x02 {
		t.Fatalf("frame2: first byte = %02x, want 0x02 (phantom bytes leaked into next frame)", frames[1].Bytes[0])
	}
}

func TestParseTsharkHex_DecompressedHeaderPhantom(t *testing.T) {
	// Regression (grpc case): tshark -x appends "Decompressed Header (N bytes):"
	// hex blocks to frames carrying HPACK-compressed HTTP/2 HEADERS. These
	// blocks start with "0000" and were being parsed as new frames, shifting
	// every subsequent FrameAssert packet index.
	out := "Frame (199 bytes):\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 b9 68 65 40 00 40 06 b3 b8 0a 00 00 01 14 00   ..he@.@.........\n" +
		"Decompressed Header (248 bytes):\n" +
		"0000  00 00 00 07 3a 6d 65 74 68 6f 64 00 00 00 04 50   ....:method....P\n" +
		"0010  4f 53 54 00 00 00 07 3a 73 63 68 65 6d 65 00 00   OST....:scheme..\n" +
		"\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 36 68 66 40 00 40 06 b4 3a 0a 00 00 01 14 00   .6hf@.@..:......\n" +
		"0020  00 01 30 39 00 50 e8 e4 32 72 28 69 9f 8a 50 18   ..09.P..2r(i..P.\n"
	frames := parseTsharkHex(out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2 (Decompressed Header phantom must not create a 3rd)", len(frames))
	}
	// Frame 1 ends at the original 2 dump lines (32 bytes); the decompressed
	// header block (len 0x100 > frame len) must not be appended to it.
	if len(frames[0].Bytes) != 32 {
		t.Fatalf("frame1: got %d bytes, want 32 (phantom must not be appended)", len(frames[0].Bytes))
	}
	// Frame 2 must start with the new segment's Ethernet header, not the
	// decompressed header's first byte (0x00).
	if frames[1].Bytes[0] != 0x02 {
		t.Fatalf("frame2: first byte = %02x, want 0x02 (phantom bytes leaked into next frame)", frames[1].Bytes[0])
	}
}

func TestParseTsharkHex_UnchunkedRTMPPhantom(t *testing.T) {
	// Regression (rtmp case): tshark -x appends "Unchunked RTMP (N bytes):"
	// hex blocks to frames carrying RTMP chunks (message re-assembly across
	// segments). These blocks start with "0000" and were being parsed as new
	// frames, shifting every subsequent FrameAssert packet index.
	out := "Frame (131 bytes):\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 75 00 04 40 00 40 06 1c 5e 0a 00 00 01 14 00   .u..@.@..^......\n" +
		"Unchunked RTMP (1537 bytes):\n" +
		"0000  03 a1 83 1a c3 00 00 00 00 ae 95 fe b0 53 7f 70   .............S.p\n" +
		"0010  d0 20 6d 25 e9 ef 9c f4 5d 77 f1 f0 ec 43 cc e0   . m%....]w...C..\n" +
		"\n" +
		"0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E \n" +
		"0010  00 3a 00 05 40 00 40 06 1c 93 0a 00 00 01 14 00   .:..@.@.........\n"
	frames := parseTsharkHex(out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2 (Unchunked RTMP phantom must not create a 3rd)", len(frames))
	}
	// Frame 1 ends at the original 2 dump lines (32 bytes); the unchunked
	// block must not be appended to it.
	if len(frames[0].Bytes) != 32 {
		t.Fatalf("frame1: got %d bytes, want 32 (phantom must not be appended)", len(frames[0].Bytes))
	}
	// Frame 2 must start with the new segment's Ethernet header, not the
	// unchunked payload's first byte (0x03).
	if frames[1].Bytes[0] != 0x02 {
		t.Fatalf("frame2: first byte = %02x, want 0x02 (phantom bytes leaked into next frame)", frames[1].Bytes[0])
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
