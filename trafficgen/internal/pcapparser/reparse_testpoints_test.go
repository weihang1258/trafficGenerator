package pcapparser

// Test points for reparse.go, derived from tools/test_points/pcapparser.md
// (components RE1-RE2). REAL tests.

import (
	"testing"
	"time"
)

// --- RE1: Reparse delegates to Parse ---

func TestReparse_DelegatesToParse(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("dns")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	a1, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	a2, err := Reparse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Reparse: %v", err)
	}
	if a1.PacketCount != a2.PacketCount || a1.FlowCount != a2.FlowCount {
		t.Errorf("Reparse diverged: packets %d vs %d, flows %d vs %d", a1.PacketCount, a2.PacketCount, a1.FlowCount, a2.FlowCount)
	}
	if len(a2.Flows) > 0 && a2.Flows[0].ParserVersion != ParserVersion {
		t.Errorf("ParserVersion = %q, want %q", a2.Flows[0].ParserVersion, ParserVersion)
	}
}

// --- RE2: NeedsReparse ---

func TestNeedsReparse_VersionMatch(t *testing.T) {
	if NeedsReparse(ParserVersion) {
		t.Errorf("NeedsReparse(current) = true, want false")
	}
}

func TestNeedsReparse_VersionMismatch(t *testing.T) {
	if !NeedsReparse("0.9.0") {
		t.Errorf("NeedsReparse('0.9.0') = false, want true (version mismatch)")
	}
}