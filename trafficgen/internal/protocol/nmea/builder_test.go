package nmea

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestXorHex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,", "69"},
		{"$GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A", "29"},
		{"$GPGSA,A,3,04,05,06,09,12,17,19,24,25,29,31,32,2.5,1.3,2.0", "3F"},
		{"$PGRME,15.0,M,20.0,M,25.0,M", "1F"},
	}
	for _, c := range cases {
		if got := xorHex(c.in); got != c.want {
			t.Errorf("xorHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildSentence_ProprietaryAddress(t *testing.T) {
	// $P + MfrID = $PGRME (NOT $GPGRME — old bug).
	ev := core.NMEAEvent{
		Kind:   "sentence",
		Talker: "P",
		Type:   "E",
		MfrID:  "GRM",
		Fields: []string{"15.0", "M", "20.0", "M", "25.0", "M"},
	}
	b, err := BuildSentence(nil, ev)
	if err != nil {
		t.Fatalf("BuildSentence: %v", err)
	}
	got := string(b)
	want := "$PGRME,15.0,M,20.0,M,25.0,M*1F\r\n"
	if got != want {
		t.Errorf("BuildSentence($P) =\n  got %q\n want %q", got, want)
	}
}

func TestBuildSentence_StandardGGA(t *testing.T) {
	ev := core.NMEAEvent{
		Kind:   "sentence",
		Talker: "GP",
		Type:   "GGA",
		Fields: FixtureGGABaseline(),
	}
	b, err := BuildSentence(nil, ev)
	if err != nil {
		t.Fatalf("BuildSentence: %v", err)
	}
	want := "$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*69\r\n"
	if string(b) != want {
		t.Errorf("GGA baseline bytes mismatch:\n got %q\nwant %q", b, want)
	}
}

func TestBuildSentence_OmittedChecksum(t *testing.T) {
	no := false
	ev := core.NMEAEvent{
		Kind:     "sentence",
		Talker:   "GP",
		Type:     "GGA",
		Checksum: &no,
		Fields:   FixtureGGABaseline(),
	}
	b, err := BuildSentence(nil, ev)
	if err != nil {
		t.Fatalf("BuildSentence: %v", err)
	}
	if strings.Contains(string(b), "*") {
		t.Errorf("checksum=false must omit *hh, got %q", b)
	}
	if !strings.HasSuffix(string(b), "\r\n") {
		t.Errorf("must end CRLF, got %q", b)
	}
	if len(b) != 67 {
		t.Errorf("GGA no-checksum length = %d, want 67", len(b))
	}
}

func TestBuildSentence_PinnedChecksum(t *testing.T) {
	ev := core.NMEAEvent{
		Kind:          "sentence",
		Talker:        "GP",
		Type:          "GGA",
		ChecksumValue: "6A", // bad-checksum observation mode (positive case 48)
		Fields:        FixtureGGABaseline(),
	}
	b, err := BuildSentence(nil, ev)
	if err != nil {
		t.Fatalf("BuildSentence: %v", err)
	}
	if !strings.HasSuffix(string(b), "*6A\r\n") {
		t.Errorf("pinned checksum not honored: got %q", b)
	}
}

func TestFixtureGGABytes_MatchesTestcase(t *testing.T) {
	b := FixtureGGABytes()
	want := "2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A36390D0A"
	if strings.ToUpper(hex.EncodeToString(b)) != want {
		t.Errorf("FixtureGGABytes hex:\n  got %s\n want %s", hex.EncodeToString(b), want)
	}
	if len(b) != 70 {
		t.Errorf("GGA baseline len = %d, want 70", len(b))
	}
}

func TestFixtureRMCBytes_MatchesTestcase(t *testing.T) {
	b := FixtureRMCBytes()
	want := "244750524D432C3132333531392E30302C412C343830372E3033382C4E2C30313133312E3030302C452C3032322E342C3038342E342C3233303339342C3030332E312C572C412A32390D0A"
	if strings.ToUpper(hex.EncodeToString(b)) != want {
		t.Errorf("FixtureRMCBytes hex:\n  got %s\n want %s", hex.EncodeToString(b), want)
	}
	if len(b) != 75 {
		t.Errorf("RMC baseline len = %d, want 75", len(b))
	}
}
