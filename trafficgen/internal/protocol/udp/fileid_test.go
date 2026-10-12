package udp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-1e 兜底面（D-FILE-1 裁定 6）：spec.FileSource → spec.Payload →
// 单 datagram 载荷=文件字节。
func TestPlanFileIDDatagram(t *testing.T) {
	fsys, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("UDPFILE", 10)
	r, err := fsys.UploadInfo(context.Background(), "u.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)

	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40030, DstPort: 9001,
		FileSource: &filesystem.FileSource{FileID: r.FileID},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for pk := range ch {
		if pk.Direction == "up" && len(pk.Payload) > 0 {
			data = append(data, pk.Payload...)
		}
	}
	if string(data) != content {
		t.Fatalf("udp payload = %d bytes, want %d", len(data), len(content))
	}
}
