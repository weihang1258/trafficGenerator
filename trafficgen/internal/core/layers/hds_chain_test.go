package layers_test

// D-HDS-1（G-HDS-1）P4 链级红例（cwmp_chain_test.go / smb_chain_test.go 同构）：
//  ①层 config 翻译进 spec.HDS（现状：translate 只置零值结构体，层内
//    profile/manifest/sessions 静默丢弃 → "sessions is required"）；
//  ②顶层 hds 子映射 presence 判死（M5①；现状放行）；
//  ③白名单外游离键判死（M5②；现状顶层 src_ip 走 CheckProtoFlat、src_mac
//    走 layers+flat 混用门）；
//  ④缺 http 载体拒绝（M5③，存量预检在案，本例为其链级红例）；
//  ⑤registry 五键 V9 allowlist（现状：层内业务键全拒 unknown field）；
//  ⑥空层 {"hds":{}} = sessions 必写（validator 同步拒，零假成功）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/hds" // init 注册 hds 终结层生成器 + 校验器
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
)

const (
	hdsCli = "192.0.2.47"
	hdsSrv = "198.51.100.47"
	hdsSP  = 41000
)

// hdsManifestCfg 是 17 例共用的 F4M fixture 最小形（id/stream_type/media 三
// 检查齐；bootstrap_infos 缺席 = 生成式 bootstrap 路径）。
func hdsManifestCfg() map[string]interface{} {
	return map[string]interface{}{
		"id":          "channel-1",
		"stream_type": "live",
		"uri":         "/live/channel.f4m",
		"media": []interface{}{
			map[string]interface{}{
				"stream_id": "main", "href": "channel", "bitrate": 800,
				"bootstrap_info_id": "b0",
				"fragments": []interface{}{
					map[string]interface{}{
						"segment": 1, "fragment": 1, "timestamp": 0,
						"duration": 2000, "body": "AAAA",
					},
				},
			},
		},
	}
}

func hdsMigrateChain(t *testing.T, hdsCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": hdsCli, "dst": hdsSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": hdsSP, "dst_port": 80}},
		map[string]interface{}{"http": map[string]interface{}{}},
		map[string]interface{}{"hds": hdsCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func hdsMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: hdsCli, DstIP: hdsSrv, SrcPort: hdsSP, DstPort: 80}
}

// 红先绿后证据（审查 M1 补）：本文件 6 例与接线同批提交（1047e00）；
// 红态复现法——`git stash` 掉 chain_planner_translate.go / strategy_convert.go /
// registry.go 三处接线改动后 `go test ./internal/core/layers/ -run TestHDSChain`
// 即 3 红（unknown field "keep_alive" / presence 无拒 / V9 拒），接线回填即全绿
// （2026-09-28 车道实测）。
// 红例①【http+hds 叠翻译】：层 config（profile/manifest/sessions）必须上线
// ——GET 请求行 + F4M body 均须出现（现状：层值被丢弃，Plan 报 sessions）。
func TestHDSChain_LayerConfigTranslates(t *testing.T) {
	raw := hdsMigrateChain(t, map[string]interface{}{
		"profile":    "hds_http1",
		"keep_alive": true,
		"manifest":   hdsManifestCfg(),
		"sessions": []interface{}{
			map[string]interface{}{"kind": "manifest", "uri": "/live/channel.f4m"},
		},
	})
	p, err := layers.BuildLayersPlanner("hds", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), hdsMigrateSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawRequest, sawF4M bool
	var firstLine string
	n := 0
	for pkt := range ch {
		n++
		s := string(pkt.Payload)
		if pkt.Direction == "up" && firstLine == "" {
			firstLine = s
		}
		if strings.Contains(s, "GET /live/channel.f4m") {
			sawRequest = true
		}
		// F4M 主体经 http 层包帧后落在同一 TCP 载荷（body 变换器分工：
		// hds 只产 body，http 包 GET/200 帧）。
		if strings.Contains(s, "<manifest xmlns=\"http://ns.adobe.com/f4m/1.0\">") &&
			strings.Contains(s, "<id>channel-1</id>") {
			sawF4M = true
		}
	}
	if n != 9 {
		t.Fatalf("packets=%d, want 9 (3 handshake + GET/200 + 4 teardown)", n)
	}
	if !sawRequest {
		t.Fatalf("layer hds config not translated: no GET /live/channel.f4m on the wire (first up payload: %q)", firstLine)
	}
	if !sawF4M {
		t.Fatal("layer hds manifest not translated: F4M body never emitted (translate case missing?)")
	}
}

// 红例②【D-HDS-1 M5①】：顶层 hds 子映射 presence 判死（空 map 也死）。
func TestHDSChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"hds": map[string]interface{}{}},
		},
		"hds": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("hds", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(hds, {layers, hds:{}}) = "", want top-level hds presence rejection`)
	}
	if !strings.Contains(msg, "rejects a top-level hds sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `rejects a top-level hds sub-config`", msg)
	}
	// 层链形状（无顶层 hds）不触发。
	if msg := core.CheckProtoFlat("hds", map[string]interface{}{
		"layers": []interface{}{map[string]interface{}{"hds": map[string]interface{}{}}},
	}); msg != "" {
		t.Fatalf("layers-only shape must not trigger, got %q", msg)
	}
}

// 红例③【D-HDS-1 M5② / CORE_MEMORY 1.11–1.13】：白名单外游离键判死——
// 顶层四元组/扁平 count 走 CheckProtoFlat，src_mac 走 layers+flat 混用门。
func TestHDSChain_StrayKeyRejected(t *testing.T) {
	if msg := core.CheckProtoFlat("hds", map[string]interface{}{
		"layers": []interface{}{map[string]interface{}{"hds": map[string]interface{}{}}},
		"src_ip": hdsCli,
	}); !strings.Contains(msg, "rejects flat config field src_ip") {
		t.Fatalf("flat anchor msg = %q", msg)
	}
	if _, errs := schema.ValidateStrategy("synth", "hds", map[string]any{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"hds": map[string]interface{}{}},
		},
		"src_mac": "02:00:00:00:00:47",
	}, nil); len(errs) == 0 {
		t.Fatal("layers + top-level src_mac must be rejected (1.11 whitelist)")
	} else {
		found := false
		for _, e := range errs {
			if strings.Contains(e.Message, "mixes layers with flat four-tuple field src_mac") {
				found = true
			}
		}
		if !found {
			t.Fatalf("stray-key anchor errs = %v", errs)
		}
	}
}

// 红例④【D-HDS-1 M5③】：缺 http 载体拒绝（[tcp,hds] 直连）。
func TestHDSChain_CarrierRejected(t *testing.T) {
	raw, _ := json.Marshal([]interface{}{
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": hdsSP, "dst_port": 80}},
		map[string]interface{}{"hds": map[string]interface{}{}},
	})
	_, err := layers.BuildLayersPlanner("hds", raw)
	if err == nil {
		t.Fatal("[tcp,hds] must be rejected (missing http carrier)")
	}
	if !strings.Contains(err.Error(), "requires the http carrier layer") {
		t.Fatalf("want carrier anchor, got: %v", err)
	}
}

// 红例⑤【D-HDS-1 裁定】：registry 五键 V9 allowlist——未知键拒，五键放行。
func TestHDSChain_V9Allowlist(t *testing.T) {
	bad := hdsMigrateChain(t, map[string]interface{}{"nope": 1})
	if _, err := layers.ValidateLayers(bad, "hds"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown layer field must be rejected, got %v", err)
	}
	ok := hdsMigrateChain(t, map[string]interface{}{
		"profile":    "hds_http1",
		"keep_alive": true,
		"manifest":   hdsManifestCfg(),
		"sessions":   []interface{}{},
		"wire_fault": "",
	})
	if _, err := layers.ValidateLayers(ok, "hds"); err != nil {
		t.Fatalf("five contract keys must pass V9: %v", err)
	}
}

// 红例⑥【设计 §7】：空层 {"hds":{}} = 零 session → "sessions is required"
// （翻译出非 nil 零值，validator 同步拒；零假成功，不产生成功 PCAP）。
func TestHDSChain_EmptyLayerSessionsRequired(t *testing.T) {
	raw := hdsMigrateChain(t, map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("hds", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(hdsMigrateSpec())
	if err == nil {
		t.Fatal(`empty {"hds":{}} layer must fail Validate (sessions required)`)
	}
	if !strings.Contains(err.Error(), "sessions is required") {
		t.Fatalf("want sessions anchor, got: %v", err)
	}
}
