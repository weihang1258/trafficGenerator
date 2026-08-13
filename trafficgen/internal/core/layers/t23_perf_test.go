// T23 性能测试（P2e）：层链生成性能与扁平配置同量级（18 号文档 §13.5）。
// 对比 legacy planner（protocol/tcp + protocol/http，main.go 切层链前的
// 生产路径）与 ChainPlanner（同一 tcp/http 流）的 Plan 吞吐。
// 判据非硬阈值（机器相关）：legacy/chain 比率 < 10x 即"同量级"——防止
// 层链驱动引入数量级退化（如每包线性扫链、意外全量收集）。-benchmem 附带
// 分配对比。
package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

const t23Flows = 200

// t23Spec is the shared flow spec for both paths (字节断言无关，只比吞吐)。
func t23Spec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 8080,
		Count: 10,
	}
}

// drain drains a Plan channel (Plan 的产包路径全量走完，与生产一致)。
func drain(ch <-chan core.PacketConfig) (int, error) {
	n := 0
	for range ch {
		n++
	}
	return n, nil
}

// benchLegacyTCP plans t23Flows standalone tcp flows through the legacy tcp
// planner (层链接入前的生产路径)。drain 返回包数必须 > 0——若路径回归成
// 0 包（静默空流），bench 测的是空 Plan 开销，比率失真且假 PASS。
// ReportMetric 的 pkts/iter 供 ratio() 断言两侧包数一致（review MEDIUM-1：
// 包数偏斜会被计入吞吐 → "链更快"假 PASS，判据必须比较同样的流）。
func benchLegacyTCP(b *testing.B) {
	p := tcp.NewPlanner()
	spec := t23Spec()
	var total int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < t23Flows; j++ {
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				b.Fatalf("legacy tcp Plan: %v", err)
			}
			n, err := drain(ch)
			if err != nil {
				b.Fatalf("legacy tcp drain: %v", err)
			}
			total += int64(n)
		}
	}
	if total == 0 {
		b.Fatal("legacy tcp Plan produced 0 packets")
	}
	b.ReportMetric(float64(total)/float64(b.N), "pkts/iter")
}

// benchChainTCP plans t23Flows standalone tcp flows through the layer chain
// (单层豁免 [{"tcp":{}}] 补全 [ip, tcp] 后驱动)。
func benchChainTCP(b *testing.B) {
	p, err := layers.BuildLayersPlanner("tcp", json.RawMessage(`[{"tcp":{}}]`))
	if err != nil {
		b.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := t23Spec()
	var total int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < t23Flows; j++ {
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				b.Fatalf("chain tcp Plan: %v", err)
			}
			n, err := drain(ch)
			if err != nil {
				b.Fatalf("chain tcp drain: %v", err)
			}
			total += int64(n)
		}
	}
	if total == 0 {
		b.Fatal("chain tcp Plan produced 0 packets")
	}
	b.ReportMetric(float64(total)/float64(b.N), "pkts/iter")
}

// benchLegacyHTTP plans t23Flows http flows through the legacy http planner
// (层链接入前的生产路径)。
func benchLegacyHTTP(b *testing.B) {
	p := http.NewPlanner()
	spec := t23Spec()
	var total int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < t23Flows; j++ {
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				b.Fatalf("legacy http Plan: %v", err)
			}
			n, err := drain(ch)
			if err != nil {
				b.Fatalf("legacy http drain: %v", err)
			}
			total += int64(n)
		}
	}
	if total == 0 {
		b.Fatal("legacy http Plan produced 0 packets")
	}
	b.ReportMetric(float64(total)/float64(b.N), "pkts/iter")
}

// benchChainHTTP plans t23Flows http flows through the layer chain
// ({"http":{}} 补全 [ip, tcp, http] 后驱动)。
func benchChainHTTP(b *testing.B) {
	p, err := layers.BuildLayersPlanner("http", json.RawMessage(`[{"http":{}}]`))
	if err != nil {
		b.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := t23Spec()
	var total int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < t23Flows; j++ {
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				b.Fatalf("chain http Plan: %v", err)
			}
			n, err := drain(ch)
			if err != nil {
				b.Fatalf("chain http drain: %v", err)
			}
			total += int64(n)
		}
	}
	if total == 0 {
		b.Fatal("chain http Plan produced 0 packets")
	}
	b.ReportMetric(float64(total)/float64(b.N), "pkts/iter")
}

// TestT23_LayerChainSameOrderAsLegacy: 层链吞吐与 legacy 同量级（<10x），
// 防数量级退化（§13.5 T23）。
func TestT23_LayerChainSameOrderAsLegacy(t *testing.T) {
	legacyTCP := testing.Benchmark(benchLegacyTCP)
	chainTCP := testing.Benchmark(benchChainTCP)
	legacyHTTP := testing.Benchmark(benchLegacyHTTP)
	chainHTTP := testing.Benchmark(benchChainHTTP)

	nsPerFlow := func(r testing.BenchmarkResult) float64 {
		return float64(r.NsPerOp()) / t23Flows
	}
	// ratio 断言两侧包数一致（review MEDIUM-1）：判据必须比较同样的流——
	// 若链侧少产包（补全回退、termination 静默关闭），少掉的包不计吞吐，
	// 链看起来更快 → 假 PASS。ReportMetric 的 pkts/iter = 每次外层迭代
	// （200 flows）的总包数，两侧必须相等。
	samePackets := func(name string, legacy, chain testing.BenchmarkResult) {
		l, c := legacy.Extra["pkts/iter"], chain.Extra["pkts/iter"]
		if l != c {
			t.Errorf("%s: packet counts differ (legacy %.0f vs chain %.0f pkts/iter) — ratio compares different flows",
				name, l, c)
		}
	}
	ratio := func(name string, legacy, chain testing.BenchmarkResult) {
		l, c := nsPerFlow(legacy), nsPerFlow(chain)
		// 零计时防御（review MEDIUM-2）：极快路径测得 0 ns/op 时比率会变
		// +Inf/NaN，c > l*10 恒 false → 静默 PASS。这是 bench 方法学故障，
		// 直接 FAIL 而不是假装通过。
		if l == 0 || c == 0 {
			t.Fatalf("%s: zero timing measured (legacy %.2f ns/flow, chain %.2f) — benchmark resolution too coarse", name, l, c)
		}
		t.Logf("%s: legacy %.2f ns/flow, chain %.2f ns/flow (ratio %.1fx, chain %.1f MB/iter vs legacy %.1f, %.0f pkts/iter)",
			name, l, c, c/l,
			float64(chain.AllocedBytesPerOp())/1e6, float64(legacy.AllocedBytesPerOp())/1e6,
			chain.Extra["pkts/iter"])
		if c > l*10 {
			t.Errorf("%s: layer chain %.1fx slower than legacy (%.2f ns/flow vs %.2f) — order-of-magnitude regression",
				name, c/l, c, l)
		}
	}
	samePackets("tcp", legacyTCP, chainTCP)
	samePackets("http", legacyHTTP, chainHTTP)
	ratio("tcp", legacyTCP, chainTCP)
	ratio("http", legacyHTTP, chainHTTP)
}
