package layers

// D-PERF-2 侦查（临时）：每流成本分解——Plan 固定开销 vs 管线排空。
import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestProbeFlowCostBreakdown(t *testing.T) {
	n := 1000
	p := NewChainPlannerFromChain("udp", []Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "udp", Config: map[string]interface{}{"dst_port": uint16(9000)}},
	})
	total := time.Now()
	var planSum, drainSum time.Duration
	for i := 0; i < n; i++ {
		spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.2", SrcPort: uint16(5000 + i%1000), DstPort: 9000}
		start := time.Now()
		ch, err := p.Plan(context.Background(), spec)
		planSum += time.Since(start)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		start = time.Now()
		for range ch {
		}
		drainSum += time.Since(start)
	}
	el := time.Since(total)
	t.Logf("n=%d 串行全链路=%v (流均%v) | Plan-setup 累计=%v (流均%v) | 排空累计=%v (流均%v)",
		n, el.Round(time.Millisecond),
		(el / time.Duration(n)).Round(time.Microsecond),
		planSum.Round(time.Millisecond), (planSum / time.Duration(n)).Round(time.Microsecond),
		drainSum.Round(time.Millisecond), (drainSum / time.Duration(n)).Round(time.Microsecond))
}
