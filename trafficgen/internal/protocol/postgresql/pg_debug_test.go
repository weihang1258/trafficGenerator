package postgresql

import (
	"fmt"
	"testing"
	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPGDebugMultiStmt(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "SELECT 1; SELECT 2"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if len(c.Payload) > 0 {
			fmt.Printf("[%d] dir=%s type=%c\n", i, c.Direction, c.Payload[0])
		} else {
			fmt.Printf("[%d] dir=%s (no payload)\n", i, c.Direction)
		}
	}
}
