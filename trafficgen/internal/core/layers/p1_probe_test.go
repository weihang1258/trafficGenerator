package layers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// P1 残留定位探针（临时）：四例 MISS/ERR 的 parse→spec→线 三段检查。
func TestP1ResidualProbe(t *testing.T) {
	fs, _ := filesystem.New(t.TempDir())
	content := "P1PROBE-" + strings.Repeat("z", 90)
	r, _ := fs.UploadInfo(context.Background(), "z.bin", filesystem.FileSource{Literal: content})
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	fid := r.FileID

	run := func(name, proto, chain string) {
		t.Helper()
		planner, err := layers.BuildLayersPlanner(proto, json.RawMessage(chain))
		if err != nil { fmt.Println(name, "BUILD-ERR:", err); return }
		ch, err := planner.Plan(ctx, core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.2", SrcPort: 31000, DstPort: 41000})
		if err != nil { fmt.Println(name, "PLAN-ERR:", err); return }
		found, n := false, 0
		for p := range ch { n++; if strings.Contains(string(p.Payload), content) { found = true } }
		fmt.Println(name, "| pkts:", n, "| 内容在线:", found)
	}
	// spec 面检查：parse 是否携带 FileSource
	specChk := func(name, proto, chain string) {
		t.Helper()
		_, err := layers.BuildLayersPlanner(proto, json.RawMessage(chain))
		_ = err
		// 直接走 ValidateLayers 无法读 spec——用 BuildLayersPlanner 内部翻译
		// 面已有（BuildLayersPlanner 返回 planner 不暴露 spec）。改为检查
		// 线面（run）即反推。
		_ = name
	}
	_ = specChk

	run("icmpv6", "icmpv6",
		`[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"icmpv6":{"file_source":{"file_id":"`+fid+`"}}}]`)
	run("rtmp", "rtmp",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"src_port":31001,"dst_port":1935}},{"rtmp":{"data":[{"direction":"up","file_source":{"file_id":"`+fid+`"}}]}}]`)
	run("xmpp", "xmpp",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"src_port":31002,"dst_port":5222}},{"xmpp":{"messages":[{"direction":"up","file_source":{"file_id":"`+fid+`"}}]}}]`)
	run("someip", "someip",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"udp":{"dst_port":30490}},{"someip":{"file_source":{"file_id":"`+fid+`"}}}]`)
}
