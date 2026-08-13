// 外部测试包：BuildLayersPlanner 是 main.go 注入引擎的层链工厂（P2c 层链
// 驱动生成），这里用真实 factory 验证"单层链 → 补全 → 产包 → config 保留"。
// 引 protocol/tcp 触发注册（layer_gen.go 的 tcp→layers 依赖使内层包无法测试）。
package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// TestBuildLayersPlanner_SingleLayerChainGeneratesPackets: P2c 的 CRITICAL-1
// 回归——单层豁免链 [{"tcp":{}}] 经 BuildLayersPlanner 必须补全成
// [ip, tcp] 并实际产包。旧实现把未补全的用户链直传 ChainPlanner，Plan 的
// drive 找不到 ip 层报 "no ip layer"，错误被驱动 goroutine 吞掉 → 任务
// 报 completed 且 0 包（静默空流）。补全必须发生在 factory 内（链要驱动
// 生成），不能留到 Plan 再补（单层豁免链的补全被 V4 拒绝，Plan 无法识别
// 豁免条件）。
func TestBuildLayersPlanner_SingleLayerChainGeneratesPackets(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tcp", json.RawMessage(`[{"tcp":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 80,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("single-layer [tcp] chain produced 0 packets (CRITICAL-1: silent empty flow)")
	}
}

// TestBuildLayersPlanner_PreservesLayerConfig: 补全必须保留用户链的层
// config——单层链 [{"tcp":{"window_size":8192}}] 的窗口必须出现在所有
// 包的 L4 上。旧豁免路径（completeSynthesized）从裸协议名重建链，config
// 全丢 → 静默生成 schema 默认（65535）的包。
func TestBuildLayersPlanner_PreservesLayerConfig(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tcp", json.RawMessage(`[{"tcp":{"window_size":8192}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 80,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("single-layer [tcp] chain produced 0 packets")
	}
	for i := range pkts {
		if pkts[i].L4.WindowSize != 8192 {
			t.Errorf("packet %d window = %d, want 8192 (layer config lost in completion)", i, pkts[i].L4.WindowSize)
		}
	}
}
