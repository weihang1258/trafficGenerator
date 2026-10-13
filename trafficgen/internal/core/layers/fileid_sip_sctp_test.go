package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// T-FILE-2f（D-FILE-2 裁定1）：sip/sctp file_source 链路径可达性回归——
// 第9轮曾误判"申报未达"，Go 级红例证伪：sctp chunks[].file_source 直接可达；
// sip media.file_source 须 dialog 消息 emit_media:true + media.enabled:true
// （D-SIP-2 媒体锚点设计）。本测试锁住两条通路防回归。
func TestFileIDSipSctpChainReachability(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := "WIREPROOF-" + strings.Repeat("w", 80)
	r, err := fs.UploadInfo(context.Background(), "w.bin", filesystem.FileSource{Literal: content})
	if err != nil {
		t.Fatal(err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	run := func(t *testing.T, name, proto, chain string, want bool) {
		t.Helper()
		planner, err := layers.BuildLayersPlanner(proto, json.RawMessage(chain))
		if err != nil {
			t.Fatalf("%s BUILD-ERR: %v", name, err)
		}
		ch, err := planner.Plan(ctx, core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.2", SrcPort: 30000, DstPort: 40000})
		if err != nil {
			t.Fatalf("%s PLAN-ERR: %v", name, err)
		}
		found := false
		for p := range ch {
			if strings.Contains(string(p.Payload), content) {
				found = true
			}
		}
		if found != want {
			t.Errorf("%s 内容在线=%v, want %v", name, found, want)
		}
	}

	t.Run("sctp_chunk_file_id", func(t *testing.T) {
		run(t, "sctp", "sctp",
			`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"sctp":{"chunks":[{"tsn":1,"sid":0,"ssn":0,"ppid":1,"direction":"up","file_source":{"file_id":"`+r.FileID+`"}}]}}]`, true)
	})
	t.Run("sip_media_emit_media_gate", func(t *testing.T) {
		run(t, "sip", "sip",
			`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"udp":{"dst_port":5060}},{"sip":{"dialog":[{"method":"INVITE","direction":"up","emit_media":true}],"media":{"enabled":true,"frames":2,"file_source":{"file_id":"`+r.FileID+`"}}}}]`, true)
		run(t, "sip 未开 emit_media 门→媒体不发射", "sip",
			`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"udp":{"dst_port":5060}},{"sip":{"dialog":[{"method":"INVITE","direction":"up"}],"media":{"enabled":true,"frames":2,"file_source":{"file_id":"`+r.FileID+`"}}}}]`, false)
	})
}
