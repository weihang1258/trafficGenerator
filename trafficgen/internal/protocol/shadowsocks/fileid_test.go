package shadowsocks

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-1e（D-FILE-1 口径修复）：file_id → spec.Payload → 分块原文。
// cipher="none" 明文面断言：chunk 内容=文件字节（原桩行为是落随机数，
// 该用例对修复前恒红——随机字节不等于原文）。
func TestPlanFileIDNoneCipherChunkContent(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("SSFILEID", 10) // 80B
	r, err := fsys.UploadInfo(context.Background(), "s.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.FileSource = &filesystem.FileSource{FileID: r.FileID}
	cfgs := drain(mustPlanCtx(t, p, ctx, spec))

	// none cipher 无 salt：首个 up PSH-ACK 即 chunk，内容=原文前缀。
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no PSH-ACK up payload")
	}
	// chunk = 2B len + payload（MaxChunkPayload 截断，SIP004 none 面）。
	chunkPayload := first[2:]
	if !strings.Contains(string(chunkPayload), "SSFILEID") {
		t.Fatalf("chunk content = %q (random stub leaked — file bytes must reach the wire)", chunkPayload[:40])
	}
}

func mustPlanCtx(t *testing.T, p *Planner, ctx context.Context, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}
