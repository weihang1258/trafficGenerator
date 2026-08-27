package pcaptest

import "testing"

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
