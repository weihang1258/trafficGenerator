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

// P1 残留探针（临时）：xmpp/rtmp/icmpv6/someip 全链三态区分。
func TestP1ChainProbe(t *testing.T) {
	fs, _ := filesystem.New(t.TempDir())
	content := "P1PROBE-" + strings.Repeat("z", 90)
	r, _ := fs.UploadInfo(context.Background(), "z.bin", filesystem.FileSource{Literal: content})
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	runIP := func(name, proto, chain, srcIP, dstIP string) {
		planner, err := layers.BuildLayersPlanner(proto, json.RawMessage(chain))
		if err != nil {
			fmt.Println(name, "BUILD-ERR:", err)
			return
		}
		ch, err := planner.Plan(ctx, core.FlowSpec{SrcIP: srcIP, DstIP: dstIP, SrcPort: 31000, DstPort: 41000})
		if err != nil {
			fmt.Println(name, "PLAN-ERR:", err)
			return
		}
		found, inline, n := false, false, 0
		for p := range ch {
			n++
			if strings.Contains(string(p.Payload), content) {
				found = true
			}
			if strings.Contains(string(p.Payload), "INLINE-X") {
				inline = true
			}
		}
		fmt.Println(name, "| pkts:", n, "| 原文:", found, "| 内联标记:", inline)
	}
	run := func(name, proto, chain string) {
		runIP(name, proto, chain, "10.0.0.1", "20.0.0.2")
	}

	run("xmpp(body=INLINE-X+file)", "xmpp",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"src_port":31002,"dst_port":5222}},{"xmpp":{"messages":[{"direction":"up","body":"INLINE-X","file_source":{"file_id":"`+r.FileID+`"}}]}}]`)
	run("rtmp(file)", "rtmp",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"tcp":{"src_port":31003,"dst_port":1935}},{"rtmp":{"data":[{"direction":"up","file_source":{"file_id":"`+r.FileID+`"}}]}}]`)
	runIP("icmpv6(v6对)", "icmpv6",
		`[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"icmpv6":{"file_source":{"file_id":"`+r.FileID+`"}}}]`, "2001:db8::1", "2001:db8::2")
	run("someip", "someip",
		`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.2"}},{"udp":{"dst_port":30490}},{"someip":{"file_source":{"file_id":"`+r.FileID+`"}}}]`)
}
