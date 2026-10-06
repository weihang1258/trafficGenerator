package rest

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// P2-⑤（2026-10-06 提示词实测）：任务完成返回里没有任何实发统计——
// 描述承诺 packets_sent/bytes_sent，客户端"实发 2000 条"无法闭环验证。
// 根因：TaskModel 有统计列但 convertTaskToResponse 从不填 Stats。
// 契约：有实发记录 → stats 非 nil 且数值正确；零值任务（未运行）→ stats 为 nil。

func TestConvertTaskToResponse_Stats(t *testing.T) {
	base := storage.TaskModel{ID: "t1", Name: "n", Status: "completed", OutputType: "port_group"}

	if resp := convertTaskToResponse(&base); resp.Stats != nil {
		t.Fatalf("zero-value task must not fabricate stats, got %+v", resp.Stats)
	}

	sent := base
	sent.PacketsSent = 2000
	sent.BytesSent = 123456
	sent.FlowsCount = 2000
	resp := convertTaskToResponse(&sent)
	if resp.Stats == nil {
		t.Fatal("task with sent counters must expose stats")
	}
	if resp.Stats.PacketsSent != 2000 || resp.Stats.BytesSent != 123456 || resp.Stats.FlowsCount != 2000 {
		t.Fatalf("stats mismatch: %+v", resp.Stats)
	}
}
