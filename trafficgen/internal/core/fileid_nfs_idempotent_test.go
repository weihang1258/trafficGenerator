package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/nfs"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-1e 补充：nfs 追加面幂等（Plan 可重入不重复追加 write op）。
func TestFileIDNFSAppendIdempotent(t *testing.T) {
	fsys, _ := filesystem.New(t.TempDir())
	r, err := fsys.UploadInfo(context.Background(), "x.bin", filesystem.FileSource{Literal: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fsys)
	ctx := core.WithPayloadCache(context.Background(), pc)
	cfg := &nfs.NFSConfig{Version: 3, FileSource: &filesystem.FileSource{FileID: r.FileID}}
	spec := nfs.AttachSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40010, DstPort: 2049}, cfg)
	p := nfs.NewPlanner()
	for i := 0; i < 3; i++ {
		ch, err := p.Plan(ctx, spec)
		if err != nil {
			t.Fatal(err)
		}
		for range ch {
		}
	}
	writes := 0
	for _, op := range cfg.Ops {
		if op.Procedure == 7 {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("write ops after 3 plans = %d, want 1 (ops=%+v)", writes, cfg.Ops)
	}
}
