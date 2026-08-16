package protocolpcap

import (
	"os"
	"strings"
	"testing"
)

// Deep-audit gate tests: the Expert Info / checksum scan added to
// VerifyPcap must (a) flag real malformed frames, (b) pass known
// dissector-artifact whitelist cases, (c) report ILLEGAL checksums,
// and (d) not run for validate-negative (ExpectError) cases.
// The end-to-end gate runs inside TestProtocolPcapDrive on freshly
// generated pcaps; these unit tests pin the whitelist logic and reuse
// pcaps from /tmp/mcp-pcaps (the CASE_FORCE=1 full run) when present.

const (
	// a real malformed frame from a NON-whitelisted case would be ideal,
	// but every pcap currently on disk is either clean or whitelisted.
	// Instead the whitelist tests assert the whitelist logic directly,
	// and checkExpertInfo is exercised against whitelisted pcaps to prove
	// it returns no problems for them.
	pcapRoot = "/tmp/mcp-pcaps"
)

// requirePcap skips the test when the referenced pcap is missing (the
// /tmp/mcp-pcaps tree is ephemeral and cleaned between runs); the real
// gate runs inside TestProtocolPcapDrive on fresh pcaps.
func requirePcap(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("pcap not present (ephemeral tree cleaned): %s", path)
	}
}

func TestExpertCheck_WhitelistedCasesPass(t *testing.T) {
	// Every case currently flagged malformed on disk is whitelisted; assert
	// checkExpertInfo + VerifyPcap return no expert problems for them, and
	// that the whitelist is actually consulted (flag present + allowed).
	for _, tc := range []struct {
		proto, caseID string
	}{
		{"nfs", "nfs_t001_v3_null_mount"}, // MOUNT dup-XID artifact
		{"smb", "smb_tpos41_custom_securityblob"},
		{"tds", "tds_rpc_param_xml_json_udt"},
		{"doip", "doip_userdata_empty"},
		{"modbus", "modbus-fc99-exemption"},
		{"srv6", "srv6_tpos1_basic"}, // DNS short-payload artifact
		{"enip", "enip_seq_wraparound_3_frames"},
	} {
		pcap := pcapRoot + "/" + tc.proto + "/" + tc.caseID + ".pcap"
		requirePcap(t, pcap)
		if probs := checkExpertInfo(pcap, tc.caseID, nil); len(probs) != 0 {
			t.Errorf("case %s: unexpected expert problems: %v", tc.caseID, probs)
		}
	}
}

func TestExpertCheck_RealMalformedFlagged(t *testing.T) {
	// A malformed flag on a case that is NOT whitelisted must be reported.
	// Craft the assertion through the whitelist classifier directly:
	// the nfs_t111..t128 cases are explicitly excluded from the MOUNT
	// artifact whitelist, so a MOUNT flag there must NOT be whitelisted.
	for _, cid := range []string{"nfs_t111_v4_lock_new_owner_false", "nfs_t128_v4_secinfo"} {
		if isMalformedWhitelisted(cid, "[Malformed Packet: MOUNT],_ws.malformed") {
			t.Errorf("case %s: MOUNT flag wrongly whitelisted", cid)
		}
	}
	// An unrelated protocol's malformed flag must not be whitelisted.
	if isMalformedWhitelisted("modbus_t001_basic", "[Malformed Packet: Modbus/TCP],_ws.malformed") {
		t.Error("modbus malformed flag wrongly whitelisted")
	}
	// Null-caseID probe must not whitelist a plain flag.
	if isMalformedWhitelisted("nfs_other_case", "_ws.malformed") {
		t.Error("bare _ws.malformed without MOUNT wrongly whitelisted for nfs")
	}
}

func TestVerifyPcap_SkipsExpectError(t *testing.T) {
	// Validate-negative cases (ExpectError) short-circuit: no expert scan,
	// no field checks — and they return zero problems.
	c := Case{
		Expect: struct {
			PacketCount   int           `json:"packet_count,omitempty"`
			MinPackets    int           `json:"min_packets,omitempty"`
			Fields        []FieldAssert `json:"fields,omitempty"`
			Frames        []FrameAssert `json:"frames,omitempty"`
			HasHandshake  bool          `json:"has_handshake,omitempty"`
			HasPayload    bool          `json:"has_payload,omitempty"`
			Negotiated    bool          `json:"negotiated,omitempty"`
			Terminates    bool          `json:"terminates,omitempty"`
			Directional   bool          `json:"directional,omitempty"`
			Notes         []string      `json:"notes,omitempty"`
			ExpectError   bool          `json:"expect_error,omitempty"`
			ErrorContains string        `json:"error_contains,omitempty"`
		}{ExpectError: true, PacketCount: 5},
	}
	if probs := VerifyPcap("/nonexistent.pcap", c); len(probs) != 0 {
		t.Errorf("ExpectError case must not verify pcap, got problems: %v", probs)
	}
}

func TestVerifyPcap_RealCleanPcapPasses(t *testing.T) {
	// A clean pcap (no malformed, no ILLEGAL checksum) must pass with zero
	// problems under the new gate. Use a known-clean tftp pcap.
	pcap := pcapRoot + "/tftp/tftp-rrq-short-aa100.pcap"
	requirePcap(t, pcap)
	if probs := VerifyPcap(pcap, Case{ID: "tftp-rrq-short-aa100"}); len(probs) != 0 {
		t.Errorf("clean pcap flagged: %v", probs)
	}
}

func TestVerifyPcap_DistinctValues_Assertion(t *testing.T) {
	// The DistinctValues aggregation assertion (schedule-independent multi-flow
	// check) must flag mismatches. Use a real pcap whose srcport values are
	// known. This fails before the aggregation branch existed (the assertion
	// was silently ignored).
	pcap := pcapRoot + "/mcp/mcp_t043_stdio_multiflow_3_sessions.pcap"
	requirePcap(t, pcap)

	// Correct expectation: the 3 flows' srcports appear, nothing else.
	ok := VerifyPcap(pcap, Case{ID: "mcp_t043_stdio_multiflow_3_sessions", Expect: struct {
		PacketCount   int           `json:"packet_count,omitempty"`
		MinPackets    int           `json:"min_packets,omitempty"`
		Fields        []FieldAssert `json:"fields,omitempty"`
		Frames        []FrameAssert `json:"frames,omitempty"`
		HasHandshake  bool          `json:"has_handshake,omitempty"`
		HasPayload    bool          `json:"has_payload,omitempty"`
		Negotiated    bool          `json:"negotiated,omitempty"`
		Terminates    bool          `json:"terminates,omitempty"`
		Directional   bool          `json:"directional,omitempty"`
		Notes         []string      `json:"notes,omitempty"`
		ExpectError   bool          `json:"expect_error,omitempty"`
		ErrorContains string        `json:"error_contains,omitempty"`
	}{
		Fields: []FieldAssert{{Field: "tcp.srcport", DistinctValues: []string{"12345", "12346", "12347"}, DistinctExclude: []string{"8081"}}},
	}})
	if len(ok) != 0 {
		t.Errorf("correct distinct values flagged: %v", ok)
	}

	// Missing value must be flagged.
	miss := VerifyPcap(pcap, Case{ID: "mcp_t043_stdio_multiflow_3_sessions", Expect: struct {
		PacketCount   int           `json:"packet_count,omitempty"`
		MinPackets    int           `json:"min_packets,omitempty"`
		Fields        []FieldAssert `json:"fields,omitempty"`
		Frames        []FrameAssert `json:"frames,omitempty"`
		HasHandshake  bool          `json:"has_handshake,omitempty"`
		HasPayload    bool          `json:"has_payload,omitempty"`
		Negotiated    bool          `json:"negotiated,omitempty"`
		Terminates    bool          `json:"terminates,omitempty"`
		Directional   bool          `json:"directional,omitempty"`
		Notes         []string      `json:"notes,omitempty"`
		ExpectError   bool          `json:"expect_error,omitempty"`
		ErrorContains string        `json:"error_contains,omitempty"`
	}{
		Fields: []FieldAssert{{Field: "tcp.srcport", DistinctValues: []string{"12345", "12346"}, DistinctExclude: []string{"8081"}}},
	}})
	found := false
	for _, p := range miss {
		if strings.Contains(p, "missing") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing-value mismatch not flagged: %v", miss)
	}

	// Unexpected extra value must be flagged.
	extra := VerifyPcap(pcap, Case{ID: "mcp_t043_stdio_multiflow_3_sessions", Expect: struct {
		PacketCount   int           `json:"packet_count,omitempty"`
		MinPackets    int           `json:"min_packets,omitempty"`
		Fields        []FieldAssert `json:"fields,omitempty"`
		Frames        []FrameAssert `json:"frames,omitempty"`
		HasHandshake  bool          `json:"has_handshake,omitempty"`
		HasPayload    bool          `json:"has_payload,omitempty"`
		Negotiated    bool          `json:"negotiated,omitempty"`
		Terminates    bool          `json:"terminates,omitempty"`
		Directional   bool          `json:"directional,omitempty"`
		Notes         []string      `json:"notes,omitempty"`
		ExpectError   bool          `json:"expect_error,omitempty"`
		ErrorContains string        `json:"error_contains,omitempty"`
	}{
		Fields: []FieldAssert{{Field: "tcp.srcport", DistinctValues: []string{"12345", "12346", "12347", "99999"}, DistinctExclude: []string{"8081"}}},
	}})
	found = false
	for _, p := range extra {
		if strings.Contains(p, "unexpected") {
			found = true
		}
	}
	if !found {
		t.Errorf("unexpected-value mismatch not flagged: %v", extra)
	}
}

func TestVerifyPcap_MalformedReportedWithoutWhitelist(t *testing.T) {
	// checkExpertInfo must report a malformed flag for a case that exists
	// on disk with malformed frames but is NOT whitelisted. Use the old
	// T303 residue name which no longer has a whitelist entry... it was
	// deleted; instead simulate by scanning a whitelisted pcap under a
	// different (non-whitelisted) case id.
	pcap := pcapRoot + "/nfs/nfs_t001_v3_null_mount.pcap"
	requirePcap(t, pcap)
	probs := checkExpertInfo(pcap, "some_other_nfs_case", nil)
	found := false
	for _, p := range probs {
		if strings.Contains(p, "malformed") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected malformed report for non-whitelisted id, got %v", probs)
	}
}

func TestDecodeAs_PropagatesToFieldExtraction(t *testing.T) {
	// DecodeAs must reach the field-extraction path (tsharkFieldValues /
	// runTshark), not just expert/hex paths: a heuristic dissector that
	// claims the flow's port would otherwise shadow the field and make
	// extraction return nothing. Smoke: tsharkFieldValues with decodeAs
	// appends the -d flags and still returns the wanted field.
	pcap := pcapRoot + "/tftp/tftp-rrq-short-aa100.pcap"
	requirePcap(t, pcap)
	vals, err := tsharkFieldValues(pcap, "udp.srcport", []string{"udp.port==69,tftp"})
	if err != nil {
		t.Fatalf("tsharkFieldValues with decodeAs: %v", err)
	}
	if len(vals) == 0 {
		t.Fatal("no values extracted with decodeAs present")
	}
}
