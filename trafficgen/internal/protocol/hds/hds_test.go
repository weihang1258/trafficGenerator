package hds

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- F4M manifest builder tests ----

func TestBuildF4MManifest(t *testing.T) {
	m := &core.HDSManifest{
		ID:         "channel-1",
		StreamType: "live",
		URI:        "/live/channel.f4m",
		Media: []core.HDSMedia{
			{StreamID: "main", Href: "channel", Bitrate: 800, BootstrapInfoID: "b0"},
		},
		BootstrapInfos: []core.HDSBootstrapInfo{
			{ID: "b0", Profile: "named", Base64: "AAAA"},
		},
	}
	xml, err := buildF4MManifest(m, "hds_http1")
	if err != nil {
		t.Fatalf("buildF4MManifest: %v", err)
	}
	if !contains(xml, `<id>channel-1</id>`) {
		t.Error("missing id in manifest")
	}
	if !contains(xml, `<streamType>live</streamType>`) {
		t.Error("missing streamType")
	}
	if !contains(xml, `bitrate="800"`) {
		t.Error("missing bitrate")
	}
	if !contains(xml, `bootstrapInfoId="b0"`) {
		t.Error("missing bootstrapInfoId")
	}
	if !contains(xml, `<bootstrapInfo id="b0" profile="named">AAAA</bootstrapInfo>`) {
		t.Error("missing bootstrapInfo")
	}
}

// ---- F4M manifest builder failure paths ----

func TestBuildF4MManifest_Nil(t *testing.T) {
	_, err := buildF4MManifest(nil, "hds_http1")
	if err == nil || !contains(err.Error(), "manifest config is nil") {
		t.Fatalf("expected nil manifest error, got: %v", err)
	}
}

func TestBuildF4MManifest_EmptyID(t *testing.T) {
	_, err := buildF4MManifest(&core.HDSManifest{ID: "", StreamType: "live", Media: []core.HDSMedia{{}}}, "hds_http1")
	if err == nil || !contains(err.Error(), "manifest id is required") {
		t.Fatalf("expected id error, got: %v", err)
	}
}

func TestBuildF4MManifest_EmptyStreamType(t *testing.T) {
	_, err := buildF4MManifest(&core.HDSManifest{ID: "x", StreamType: "", Media: []core.HDSMedia{{}}}, "hds_http1")
	if err == nil || !contains(err.Error(), "manifest stream_type is required") {
		t.Fatalf("expected stream_type error, got: %v", err)
	}
}

func TestBuildF4MManifest_NoMedia(t *testing.T) {
	_, err := buildF4MManifest(&core.HDSManifest{ID: "x", StreamType: "live", Media: nil}, "hds_http1")
	if err == nil || !contains(err.Error(), "at least one media entry") {
		t.Fatalf("expected media error, got: %v", err)
	}
}

// ---- Bootstrap box builder tests ----

func TestBuildBootstrapBox(t *testing.T) {
	media := &core.HDSMedia{
		StreamID: "main", Href: "channel", Bitrate: 800, BootstrapInfoID: "b0",
		Fragments: []core.HDSFragment{
			{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000, Body: "AAAA"},
		},
	}
	box, err := buildBootstrapBox(media, "hds_http1")
	if err != nil {
		t.Fatalf("buildBootstrapBox: %v", err)
	}
	if len(box) < 16 {
		t.Fatalf("bootstrap box too short: %d", len(box))
	}
	// Check abst box header
	if string(box[4:8]) != "abst" {
		t.Errorf("expected abst box, got %q", string(box[4:8]))
	}
	// Check nested asrt box
	asrtOff := findBox(box, "asrt")
	if asrtOff < 0 {
		t.Error("missing asrt box")
	}
	// Check nested afrt box
	afrtOff := findBox(box, "afrt")
	if afrtOff < 0 {
		t.Error("missing afrt box")
	}
	// asrt should come before afrt
	if asrtOff > afrtOff {
		t.Error("asrt should precede afrt")
	}

	// Verify asrt content: 1 segment run, segment=1, count=1
	// asrt box: 8-byte header, then payload:
	//   version(1) + flags(3) + qualityEntryCount(1) + segCount(4)
	//   then segment(4)+fragmentsPerSegment(4)
	// segCount at box offset 13 (8 header + 5 preamble)
	asrtData := box[asrtOff:]
	segCount := readU32BE(asrtData[13:17])
	if segCount != 1 {
		t.Errorf("asrt segment count: want 1, got %d", segCount)
	}
	// First segment entry at box offset 17
	seg := readU32BE(asrtData[17:21])
	if seg != 1 {
		t.Errorf("asrt first segment: want 1, got %d", seg)
	}

	// Verify afrt content: 1 fragment run, fragment=1, timestamp=0, duration=2000
	// afrt box: 8-byte header, then payload:
	//   version(1) + flags(3) + timescale(4) + qualityEntryCount(1) + fragCount(4)
	// fragCount at box offset 17 (8 header + 9 preamble)
	afrtData := box[afrtOff:]
	fragCount := readU32BE(afrtData[17:21])
	if fragCount != 1 {
		t.Errorf("afrt fragment count: want 1, got %d", fragCount)
	}
}

func TestBuildBootstrapBox_NilMedia(t *testing.T) {
	_, err := buildBootstrapBox(nil, "hds_http1")
	if err == nil || !contains(err.Error(), "media config is nil") {
		t.Fatalf("expected nil media error, got: %v", err)
	}
}

// ---- F4F fragment builder tests ----

func TestBuildF4FFragment(t *testing.T) {
	body := []byte("hello world")
	frag := buildF4FFragment(body)
	if string(frag[4:8]) != "mdat" {
		t.Errorf("expected mdat box, got %q", string(frag[4:8]))
	}
	// Size = 8 (header) + len(body)
	wantSize := uint32(8 + len(body))
	gotSize := uint32(frag[0])<<24 | uint32(frag[1])<<16 | uint32(frag[2])<<8 | uint32(frag[3])
	if gotSize != wantSize {
		t.Errorf("mdat size: want %d, got %d", wantSize, gotSize)
	}
	if string(frag[8:]) != "hello world" {
		t.Errorf("mdat body mismatch: got %q", string(frag[8:]))
	}
}

// ---- buildSessionBody tests ----

func TestBuildSessionBody_Manifest(t *testing.T) {
	hcfg := &core.HDSConfig{
		Profile: "hds_http1",
		Manifest: &core.HDSManifest{
			ID: "c", StreamType: "live", URI: "/live/c.f4m",
			Media: []core.HDSMedia{{StreamID: "m", Href: "c", Bitrate: 500}},
		},
	}
	body, err := buildSessionBody(&core.HDSSession{Kind: "manifest", URI: "/live/c.f4m"}, hcfg)
	if err != nil {
		t.Fatalf("buildSessionBody manifest: %v", err)
	}
	if !contains(string(body), `<id>c</id>`) {
		t.Error("manifest body missing id")
	}
}

func TestBuildSessionBody_Bootstrap_Base64(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00, 0x0c, 0x61, 0x62, 0x73, 0x74}
	b64 := base64.StdEncoding.EncodeToString(raw)
	hcfg := &core.HDSConfig{
		Profile: "hds_http1",
		Manifest: &core.HDSManifest{
			ID: "c", StreamType: "live", URI: "/live/c.f4m",
			Media: []core.HDSMedia{{StreamID: "m", Href: "c", Bitrate: 500, BootstrapInfoID: "b0"}},
			BootstrapInfos: []core.HDSBootstrapInfo{
				{ID: "b0", Profile: "named", Base64: b64},
			},
		},
	}
	body, err := buildSessionBody(&core.HDSSession{Kind: "bootstrap", URI: "/live/c.abst"}, hcfg)
	if err != nil {
		t.Fatalf("buildSessionBody bootstrap base64: %v", err)
	}
	if string(body[4:8]) != "abst" {
		t.Errorf("expected abst box, got %q", string(body[4:8]))
	}
}

func TestBuildSessionBody_Bootstrap_Generated(t *testing.T) {
	hcfg := &core.HDSConfig{
		Profile: "hds_http1",
		Manifest: &core.HDSManifest{
			ID: "c", StreamType: "live", URI: "/live/c.f4m",
			Media: []core.HDSMedia{{
				StreamID: "m", Href: "c", Bitrate: 500, BootstrapInfoID: "b0",
				Fragments: []core.HDSFragment{
					{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000, Body: "data"},
				},
			}},
		},
	}
	body, err := buildSessionBody(&core.HDSSession{Kind: "bootstrap", URI: "/live/c.abst"}, hcfg)
	if err != nil {
		t.Fatalf("buildSessionBody bootstrap generated: %v", err)
	}
	if len(body) < 16 {
		t.Fatalf("bootstrap box too short: %d", len(body))
	}
	if string(body[4:8]) != "abst" {
		t.Errorf("expected abst box, got %q", string(body[4:8]))
	}
}

func TestBuildSessionBody_Fragment(t *testing.T) {
	hcfg := &core.HDSConfig{
		Profile: "hds_http1",
		Manifest: &core.HDSManifest{
			ID: "c", StreamType: "live", URI: "/live/c.f4m",
			Media: []core.HDSMedia{{
				StreamID: "m", Href: "c", Bitrate: 500, BootstrapInfoID: "b0",
				Fragments: []core.HDSFragment{
					{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000, Body: "testdata"},
				},
			}},
		},
	}
	body, err := buildSessionBody(&core.HDSSession{Kind: "fragment", URI: "/live/c/Seg1-Frag1"}, hcfg)
	if err != nil {
		t.Fatalf("buildSessionBody fragment: %v", err)
	}
	if string(body[4:8]) != "mdat" {
		t.Errorf("expected mdat box, got %q", string(body[4:8]))
	}
	if string(body[8:]) != "testdata" {
		t.Errorf("fragment body mismatch: got %q", string(body[8:]))
	}
}

func TestBuildSessionBody_UnknownKind(t *testing.T) {
	_, err := buildSessionBody(&core.HDSSession{Kind: "invalid"}, &core.HDSConfig{})
	if err == nil || !contains(err.Error(), "unknown session kind") {
		t.Fatalf("expected unknown kind error, got: %v", err)
	}
}

func TestBuildSessionBody_ManifestNil(t *testing.T) {
	_, err := buildSessionBody(&core.HDSSession{Kind: "manifest", URI: "/live/c.f4m"}, &core.HDSConfig{})
	if err == nil || !contains(err.Error(), "manifest config is nil") {
		t.Fatalf("expected nil manifest error, got: %v", err)
	}
}

func TestBuildSessionBody_BootstrapNoMedia(t *testing.T) {
	_, err := buildSessionBody(&core.HDSSession{Kind: "bootstrap"}, &core.HDSConfig{Manifest: &core.HDSManifest{ID: "c", StreamType: "live"}})
	if err == nil || !contains(err.Error(), "manifest/media required") {
		t.Fatalf("expected media required error, got: %v", err)
	}
}

func TestBuildSessionBody_FragmentNoMedia(t *testing.T) {
	_, err := buildSessionBody(&core.HDSSession{Kind: "fragment"}, &core.HDSConfig{Manifest: &core.HDSManifest{ID: "c", StreamType: "live"}})
	if err == nil || !contains(err.Error(), "manifest/media required") {
		t.Fatalf("expected media required error, got: %v", err)
	}
}

func TestBuildSessionBody_FragmentNoFragments(t *testing.T) {
	_, err := buildSessionBody(&core.HDSSession{Kind: "fragment"}, &core.HDSConfig{
		Manifest: &core.HDSManifest{
			ID: "c", StreamType: "live",
			Media: []core.HDSMedia{{StreamID: "m", Href: "c", Bitrate: 500}},
		},
	})
	if err == nil || !contains(err.Error(), "no fragments configured") {
		t.Fatalf("expected no fragments error, got: %v", err)
	}
}

// ---- Validate tests ----

func TestValidateHDSConfig_EmptySessions(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{}})
	if err == nil || !contains(err.Error(), "sessions is required") {
		t.Fatalf("expected sessions required error, got: %v", err)
	}
}

func TestValidateHDSConfig_ManifestInvalid(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{
		Sessions: []core.HDSSession{{Kind: "manifest"}},
		Manifest: &core.HDSManifest{ID: "", StreamType: "", Media: nil},
	}})
	if err == nil || !contains(err.Error(), "manifest id is required") {
		t.Fatalf("expected manifest id error, got: %v", err)
	}
}

func TestValidateHDSConfig_BootstrapNoMedia(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{
		Sessions: []core.HDSSession{{Kind: "bootstrap"}},
	}})
	if err == nil || !contains(err.Error(), "manifest/media required") {
		t.Fatalf("expected media required error, got: %v", err)
	}
}

func TestValidateHDSConfig_FragmentNoFragments(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{
		Sessions: []core.HDSSession{{Kind: "fragment"}},
		Manifest: &core.HDSManifest{ID: "c", StreamType: "live", Media: []core.HDSMedia{{StreamID: "m"}}},
	}})
	if err == nil || !contains(err.Error(), "no fragments configured") {
		t.Fatalf("expected no fragments error, got: %v", err)
	}
}

func TestValidateHDSConfig_UnknownKind(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{
		Sessions: []core.HDSSession{{Kind: "bogus"}},
		Manifest: &core.HDSManifest{ID: "c", StreamType: "live", Media: []core.HDSMedia{{StreamID: "m"}}},
	}})
	if err == nil || !contains(err.Error(), "unknown session kind") {
		t.Fatalf("expected unknown kind error, got: %v", err)
	}
}

func TestValidateHDSConfig_Nil(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: nil})
	if err != nil {
		t.Fatalf("expected nil error for nil HDS config, got: %v", err)
	}
}

func TestValidateHDSConfig_Valid(t *testing.T) {
	err := validateHDSConfig(&core.FlowSpec{HDS: &core.HDSConfig{
		Sessions: []core.HDSSession{{Kind: "manifest"}},
		Manifest: &core.HDSManifest{ID: "c", StreamType: "live", Media: []core.HDSMedia{{StreamID: "m"}}},
	}})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---- Generate test ----

func TestHDSGenerator_Generate(t *testing.T) {
	gen := &HDSGenerator{}
	if gen.Name() != "hds" {
		t.Errorf("Name: want hds, got %s", gen.Name())
	}

	// Verify GenEvents returns non-nil
	if gen.GenEvents() == nil {
		t.Error("GenEvents() should not return nil")
	}

	// Verify EmitEvent returns error (not wired)
	err := gen.EmitEvent(layers.MessageEvent{})
	if err == nil || !contains(err.Error(), "EmitEvent is not wired") {
		t.Fatalf("expected not wired error, got: %v", err)
	}

	// Generate with valid config
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			HDS: &core.HDSConfig{
				Profile: "hds_http1",
				Manifest: &core.HDSManifest{
					ID: "c", StreamType: "live", URI: "/live/c.f4m",
					Media: []core.HDSMedia{{
						StreamID: "m", Href: "c", Bitrate: 500, BootstrapInfoID: "b0",
						Fragments: []core.HDSFragment{
							{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000, Body: "frag"},
						},
					}},
				},
				Sessions: []core.HDSSession{
					{Kind: "manifest", URI: "/live/c.f4m"},
					{Kind: "fragment", URI: "/live/c/Seg1-Frag1"},
				},
			},
		},
	}

	err = gen.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// Event 0: manifest body (XML)
	if !contains(string(events[0].Bytes), `<id>c</id>`) {
		t.Error("event 0 missing manifest XML")
	}
	// Event 1: fragment body (mdat box)
	if string(events[1].Bytes[4:8]) != "mdat" {
		t.Errorf("event 1 expected mdat, got %q", string(events[1].Bytes[4:8]))
	}
}

func TestHDSGenerator_Generate_EmitMsgNil(t *testing.T) {
	gen := &HDSGenerator{}
	err := gen.Generate(context.Background(), &layers.GenRequest{})
	if err == nil || !contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("expected EmitMsg nil error, got: %v", err)
	}
}

// ---- Box helpers ----

func TestBuildASRTBox_Sorted(t *testing.T) {
	media := &core.HDSMedia{
		Fragments: []core.HDSFragment{
			{Segment: 3, Fragment: 1, Timestamp: 0, Duration: 2000},
			{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000},
			{Segment: 2, Fragment: 1, Timestamp: 0, Duration: 2000},
		},
	}
	box := buildASRTBox(media)
	// box header 8 bytes + version(1)+flags(3)+qualityEntryCount(1)
	segCount := readU32BE(box[13:17])
	if segCount != 3 {
		t.Fatalf("segCount: want 3, got %d", segCount)
	}
	seg1 := readU32BE(box[17:21])
	seg2 := readU32BE(box[25:29])
	seg3 := readU32BE(box[33:37])
	if seg1 != 1 || seg2 != 2 || seg3 != 3 {
		t.Errorf("segments not sorted: seg1=%d seg2=%d seg3=%d", seg1, seg2, seg3)
	}
}

func TestBuildABSTBox_Structure(t *testing.T) {
	media := &core.HDSMedia{
		Fragments: []core.HDSFragment{
			{Segment: 1, Fragment: 1, Timestamp: 0, Duration: 2000},
		},
	}
	asrtBytes := buildASRTBox(media)
	afrtBytes := buildAFRTBox(media)
	box := buildABSTBox(media, asrtBytes, afrtBytes, "hds_http1")

	if string(box[4:8]) != "abst" {
		t.Errorf("expected abst, got %q", string(box[4:8]))
	}
	// Find asrt inside abst
	off := findBox(box, "asrt")
	if off < 0 {
		t.Error("missing asrt inside abst")
	}
	off = findBox(box, "afrt")
	if off < 0 {
		t.Error("missing afrt inside abst")
	}
}

// ---- xmlEscape test ----

func TestXMLEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a&b", "a&amp;b"},
		{"<tag>", "&lt;tag&gt;"},
		{`"quote"`, "&quot;quote&quot;"},
		{"'apos'", "&apos;apos&apos;"},
	}
	for _, tc := range cases {
		got := xmlEscape(tc.in)
		if got != tc.want {
			t.Errorf("xmlEscape(%q): want %q, got %q", tc.in, tc.want, got)
		}
	}
}

// ---- resolveBody test ----

func TestResolveBody(t *testing.T) {
	// text-only
	got := resolveBody("hello", "")
	if string(got) != "hello" {
		t.Errorf("resolveBody text: want hello, got %q", string(got))
	}
	// base64 takes precedence
	got = resolveBody("hello", "d29ybGQ=")
	if string(got) != "world" {
		t.Errorf("resolveBody b64: want world, got %q", string(got))
	}
	// invalid base64 falls back to text
	got = resolveBody("fallback", "!!!invalid!!!")
	if string(got) != "fallback" {
		t.Errorf("resolveBody invalid b64: want fallback, got %q", string(got))
	}
}

// ---- helpers ----

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsString(s, substr)
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func readU32BE(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func findBox(data []byte, name string) int {
	return indexOf(data, []byte(name))
}

func indexOf(data, needle []byte) int {
	for i := 0; i <= len(data)-len(needle); i++ {
		if string(data[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func init() {
	// Suppress unused import warning for hex
	_ = hex.EncodeToString
}