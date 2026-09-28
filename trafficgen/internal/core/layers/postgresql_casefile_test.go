package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// pgsqlTypeFirstByte maps a tshark pgsql.type label to the payload's first
// byte. Bytes with two meanings (D/C/S/E) are direction-dependent; the caller
// resolves them by matching the nearest candidate index.
var pgsqlTypeFirstByte = map[string]byte{
	"Startup message":             0x00,
	"SSL request":                 0x00,
	"GSS encrypt request":         0x00,
	"Cancel request":              0x00,
	"Authentication request":      0x52,
	"Parameter status":            0x53,
	"Backend key data":            0x4b,
	"Ready for query":             0x5a,
	"Simple query":                0x51,
	"Row description":             0x54,
	"Data row":                    0x44,
	"Command completion":          0x43,
	"Error":                       0x45,
	"Notice response":             0x4e,
	"Notification response":       0x41,
	"Empty query response":        0x49,
	"Termination":                 0x58,
	"Password message":            0x70,
	"GSSResponse message":         0x70,
	"SASLInitialResponse message": 0x70,
	"SASLResponse message":        0x70,
	"Parse":                       0x50,
	"Parse completion":            0x31,
	"Bind":                        0x42,
	"Bind completion":             0x32,
	"Describe":                    0x44,
	"Execute":                     0x45,
	"Parameter description":       0x74,
	"No data":                     0x6e,
	"Portal suspended":            0x73,
	"Sync":                        0x53,
	"Flush":                       0x48,
	"Close":                       0x43,
	"Close completion":            0x33,
	"Function call":               0x46,
	"Function call response":      0x56,
}

// planCaseFile drives one case's layers config through the chain planner and
// returns every emitted packet. It is the single driver shared by the
// case-file audit tests below (negative cases are skipped by the callers).
func planCaseFile(t *testing.T, specJSON map[string]interface{}) []core.PacketConfig {
	t.Helper()
	lj, err := json.Marshal(specJSON["layers"])
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	p, err := layers.BuildLayersPlanner("postgresql", lj)
	if err != nil {
		t.Fatalf("build planner: %v", err)
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("planner is %T, want *layers.ChainPlanner", p)
	}
	fin, err := cp.ValidateSpec(core.FlowSpec{SrcIP: pgCli, DstIP: pgSrv, SrcPort: pgSport})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, err := cp.Plan(ctx, fin)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var pkts []core.PacketConfig
	for x := range ch {
		pkts = append(pkts, x)
	}
	return pkts
}

// loadPGCases parses cases/postgresql.json into raw maps (the audit tests need
// the full expect sub-map, including keys caseFile does not model).
func loadPGCases(t *testing.T) []map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile("../../../test/protocol_pcap/cases/postgresql.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	return cases
}

// TestPostgresqlCaseFile_FramesAndFieldIndices pins every frames[] hex and
// every pgsql.type packet index to the payload the engine actually emits.
//
// This is the §14.20 "先跑后钉" guard: the declared bytes are compared against
// the generated payload, so a hand-written length field or an off-by-N packet
// index (both of which shipped in the first draft of this file) fails here
// instead of passing silently until the suite runs.
func TestPostgresqlCaseFile_FramesAndFieldIndices(t *testing.T) {
	for _, c := range loadPGCases(t) {
		expect, _ := c["expect"].(map[string]interface{})
		if expect == nil || expect["expect_error"] == true {
			continue
		}
		id, _ := c["id"].(string)
		specJSON, _ := c["spec_json"].(map[string]interface{})
		if specJSON == nil {
			continue
		}
		frames, _ := expect["frames"].([]interface{})
		fields, _ := expect["fields"].([]interface{})
		if len(frames) == 0 && len(fields) == 0 {
			continue
		}
		pkts := planCaseFile(t, specJSON)

		for _, f := range frames {
			fm, _ := f.(map[string]interface{})
			if fm == nil {
				continue
			}
			pn, _ := fm["packet"].(float64)
			want, _ := fm["hex"].(string)
			if int(pn) < 1 || int(pn) > len(pkts) {
				t.Errorf("%s: frames packet %d out of range (%d packets)", id, int(pn), len(pkts))
				continue
			}
			if got := hex.EncodeToString(pkts[int(pn)-1].Payload); got != want {
				t.Errorf("%s: frames pkt%d\n  want %s\n  got  %s", id, int(pn), want, got)
			}
		}

		for _, f := range fields {
			fm, _ := f.(map[string]interface{})
			if fm == nil || fm["field"] != "pgsql.type" {
				continue
			}
			pn, _ := fm["packet"].(float64)
			label, _ := fm["value"].(string)
			first, known := pgsqlTypeFirstByte[label]
			if !known {
				continue
			}
			if int(pn) < 1 || int(pn) > len(pkts) {
				t.Errorf("%s: field pkt%d out of range (%d packets) want %q", id, int(pn), len(pkts), label)
				continue
			}
			got := pkts[int(pn)-1].Payload
			if len(got) == 0 || got[0] != first {
				t.Errorf("%s: field pkt%d want %q (first byte %02x) got %s",
					id, int(pn), label, first, hex.EncodeToString(got))
			}
		}
	}
}

// TestPostgresqlCaseFile_PacketCounts pins every positive case's declared
// packet_count to the measured emission (N + 7 for a single session; the
// per-session sum for sessions[]).
func TestPostgresqlCaseFile_PacketCounts(t *testing.T) {
	for _, c := range loadPGCases(t) {
		expect, _ := c["expect"].(map[string]interface{})
		if expect == nil || expect["expect_error"] == true {
			continue
		}
		want, ok := expect["packet_count"].(float64)
		if !ok {
			continue
		}
		id, _ := c["id"].(string)
		specJSON, _ := c["spec_json"].(map[string]interface{})
		if specJSON == nil {
			continue
		}
		got := len(planCaseFile(t, specJSON))
		if got != int(want) {
			t.Errorf("%s: packet_count=%d, measured %d", id, int(want), got)
		}
	}
}
