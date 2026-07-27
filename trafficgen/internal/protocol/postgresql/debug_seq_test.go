package postgresql

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestPG_DebugSeqNumbers checks that down packets in a SELECT query have
// incrementing sequence numbers (catches closure capture bug in runSimpleQuery).
func TestPG_DebugSeqNumbers(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "SELECT 1"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var sawQ bool
	var downSeqs []uint32
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			sawQ = true
			continue
		}
		if sawQ && c.Direction == "down" && c.L4.Flags == 0x18 {
			downSeqs = append(downSeqs, c.L4.Seq)
		}
	}
	if len(downSeqs) < 4 {
		t.Fatalf("expected >= 4 down packets after Q, got %d", len(downSeqs))
	}
	for i := 1; i < len(downSeqs); i++ {
		if downSeqs[i] == downSeqs[i-1] {
			t.Errorf("down packet[%d].Seq=%d same as prev (closure capture bug)", i, downSeqs[i])
		}
	}
	t.Logf("down seqs: %v", downSeqs)
}
