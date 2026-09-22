package megaco

// D-MEGACO-1 复评2 F2：validator 长度天花板（sessionRenderSizes）与生成器
// 实发字节的逐字节一致性守卫——两侧任何渲染漂移在此变红，而非静默复活
// "1472B 空流"。UDP：sizes[ei] == len(event.Bytes)；TCP：sizes[ei]+4 ==
// len(event.Bytes)（TPKT 4B 头由生成器侧附加）。配置经 JSON 反序列化构造
//（与 translate 面同一 json 标签路径）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func parityCfg(t *testing.T, js string) *core.MegacoConfig {
	t.Helper()
	var cfg core.MegacoConfig
	if err := json.Unmarshal([]byte(js), &cfg); err != nil {
		t.Fatalf("parity cfg unmarshal: %v", err)
	}
	return &cfg
}

func parityCfgs(t *testing.T) map[string]*core.MegacoConfig {
	big := strings.Repeat("1", 1200)
	return map[string]*core.MegacoConfig{
		"baseline": parityCfg(t, `{"encoding":"text","version":1,"token_form":"long","sessions":[
			{"role":"mg","events":[
				{"kind":"message","direction":"c2s","transactions":[{"type":"request","actions":[{"context":"-","commands":[{"name":"ServiceChange","termination":"ROOT","descriptor":{"services":{"method":"Restart","reason":"901 Cold Boot"}}}]}]}]},
				{"kind":"message","direction":"s2c","transactions":[{"type":"reply","actions":[{"context":"-","commands":[{"name":"ServiceChange","termination":"ROOT"}]}]}]}
			]}]}`),
		"big-digitmap-near-mtu": parityCfg(t, `{"encoding":"text","version":1,"sessions":[
			{"role":"mg","mid":"[192.0.2.70]","events":[
				{"kind":"message","direction":"c2s","transactions":[{"type":"request","id":"auto","actions":[{"context":"-","commands":[{"name":"Modify","termination":"A4444","descriptor":{"digit_map":{"name":"D1","value":"`+big+`"}}}]}]}]}
			]}]}`),
		"abbrev-whitespace-comment": parityCfg(t, `{"encoding":"text","version":1,"token_form":"abbrev","whitespace":"comment","sessions":[
			{"role":"mg","mid":"[192.0.2.70]","events":[
				{"kind":"message","direction":"c2s","transactions":[{"type":"request","id":"auto","actions":[{"context":"-","commands":[{"name":"AuditValue","termination":"ROOT"}]}]}]}
			]}]}`),
		"sdp-media": parityCfg(t, `{"encoding":"text","version":1,"sessions":[
			{"role":"mgc","mid":"[192.0.2.70]","peer_mid":"[198.51.100.70]","events":[
				{"kind":"message","direction":"c2s","transactions":[{"type":"request","id":"1","actions":[{"context":"1","commands":[{"name":"Modify","termination":"A4444","descriptor":{"media":{"streams":[{"id":1,"local_sdp":"v=0} o=junk","remote_sdp":"v=0"}]}}}]}]}]}
			]}]}`),
	}
}

func TestRenderParityWithGenerator(t *testing.T) {
	for name, cfg := range parityCfgs(t) {
		for _, carrier := range []string{"udp", "tcp"} {
			var events []layers.MessageEvent
			g := &MegacoGenerator{}
			req := &layers.GenRequest{
				Chain: []layers.Layer{{Name: "ip"}, {Name: carrier}, {Name: "megaco"}},
				Meta:  layers.FlowMeta{Megaco: cfg, SrcIP: "192.0.2.70", DstIP: "198.51.100.70"},
				EmitMsg: func(ev layers.MessageEvent) error {
					events = append(events, ev)
					return nil
				},
			}
			if err := g.Generate(context.Background(), req); err != nil {
				t.Fatalf("%s/%s: Generate: %v", name, carrier, err)
			}
			ei := 0
			for _, sess := range cfg.Sessions {
				sizes, err := sessionRenderSizes(cfg, sess, "192.0.2.70", "198.51.100.70")
				if err != nil {
					t.Fatalf("%s/%s: sessionRenderSizes: %v", name, carrier, err)
				}
				if len(sizes) != len(sess.Events) {
					t.Fatalf("%s/%s: sizes=%d events=%d", name, carrier, len(sizes), len(sess.Events))
				}
				for k, want := range sizes {
					if ei >= len(events) {
						t.Fatalf("%s/%s: generator emitted %d events, want >= %d", name, carrier, len(events), ei+1)
					}
					got := len(events[ei].Bytes)
					if carrier == "udp" && got != want {
						t.Fatalf("%s/udp event %d: generator %d bytes vs validator render %d (parity broken)", name, k, got, want)
					}
					if carrier == "tcp" && got != want+4 {
						t.Fatalf("%s/tcp event %d: generator %d bytes vs validator render %d+4 (parity broken)", name, k, got, want)
					}
					ei++
				}
			}
			if ei != len(events) {
				t.Fatalf("%s/%s: counted %d events, generator emitted %d", name, carrier, ei, len(events))
			}
		}
	}
}
