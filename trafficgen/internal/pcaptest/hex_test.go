package pcaptest

import (
	"strings"
	"testing"
)

// tshark -x output shape as emitted by tshark 3.6 for a frame carrying an
// NTLMSSP token in HTTP: the packet boundary label is "Frame (N bytes):"
// (after a blank line), and after the packet's hex dump the dissector appends
// an extraction block "NTLMSSP / GSSAPI Data (M bytes):" with its own
// 0000-prefixed hex dump — that block must NOT count as a frame.
const ntlmExtractOutput = `Frame (60 bytes):
0000  aa aa aa aa aa aa bb bb bb bb bb bb 08 00 45 00   ................
0010  00 28 00 01 00 00 40 06 f3 7a c0 00 02 0a c0 00   .(.......@...z..
0020  02 0b a1 5c 00 50 00 00 00 01 00 00 00 02 50 10   .\.P..........P.
0030  ff ff 8d ad 00 00                                 ......

Frame (285 bytes):
0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 20   ..............E
0010  01 0f 84 26 40 00 40 06 c8 f6 c0 00 02 3c c6 33   ...&.@..@....<.3
0020  64 3c b2 20 00 50 b7 99 b5 52 ed 14 09 09 50 18   d<. ...R......P.
0030  ff ff a0 fa 00 00 50 4f 53 54 20 2f 20 48 54 54   ......POST / HTT
NTLMSSP / GSSAPI Data (68 bytes):
0000  4e 54 4c 4d 53 53 50 00 01 00 00 00 05 82 89 a0   NTLMSSP.........
0010  0e 00 0e 00 20 00 00 00 16 00 16 00 2e 00 00 00   .... ...........
0020  45 00 58 00 41 00 4d 00 50 00 4c 00 45 00 57 00   E.X.A.M.P.L.E.W.
0030  00 41 00 57 00 00 00 44 00 00 00 2a f1 4c 6b 7b   .A.W...D...*.Lk{
0040  00 00 00 00                                       ....
`

func TestParseTsharkHexSkipsExtractionBlocks(t *testing.T) {
	frames := ParseTsharkHex(ntlmExtractOutput)
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2 (extraction block must not count as a frame)", len(frames))
	}
	// The second frame's bytes must be the packet dump only, not the
	// extraction block's 0000-prefixed dump (which starts with NTLMSSP sig).
	last := frames[len(frames)-1]
	if len(last.Bytes) < 0x40 {
		t.Fatalf("frame 2 bytes = %d, want the full packet dump", len(last.Bytes))
	}
	for i, b := range []byte{0x50, 0x4f, 0x53, 0x54} { // "POST" near end of dump
		if last.Bytes[0x36+i] != b {
			t.Fatalf("frame 2 byte 0x%02x = %#x, want %#x (POST marker)", 0x36+i, last.Bytes[0x36+i], b)
		}
	}
	if strings.Contains(string(last.Bytes), "NTLMSSP") {
		t.Fatal("frame 2 swallowed the extraction block's NTLMSSP hex dump")
	}
}

func TestMatchHexPrefixRejectsTruncatedFrame(t *testing.T) {
	matched, at := MatchHexPrefix([]byte{0x01, 0x02}, []byte{0x01, 0x02, 0x03})
	if matched {
		t.Fatal("MatchHexPrefix accepted a wanted prefix longer than the frame")
	}
	if at != 2 {
		t.Fatalf("mismatch index = %d, want 2", at)
	}
}

func TestMatchHexPrefixMatchesEmptyPrefix(t *testing.T) {
	matched, at := MatchHexPrefix([]byte{0x01}, nil)
	if !matched || at != 0 {
		t.Fatalf("empty prefix result = (%v, %d), want (true, 0)", matched, at)
	}
}
