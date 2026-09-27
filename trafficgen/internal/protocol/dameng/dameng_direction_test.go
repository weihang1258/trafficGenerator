package dameng

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-DAMENG-1 G-DM-5：显式 direction 与 kind 自然方向不一致必须拒。
func TestValidateDamengDirectionMismatch(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "s2c"},
			},
		},
	})
	if err == nil {
		t.Fatal("want direction-mismatch rejection, got nil")
	}
	if !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("want anchor %q, got %q", "inconsistent", err.Error())
	}
}
