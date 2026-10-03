package isis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 用例整形器（一次性，D-ISIS-1 P4；design §12.1 去向表 + testcase §5 逐条去向）。
//
// 产出 test/protocol_pcap/cases/isis.json：28 例（13 正 + 15 负）纯 L2 链形
// ——`layers` 恒 `[{"eth":{...}},{"isis":{...}}]`（#19 载体负例保留
// `[{"ip":{}},{"isis":{...}}]` 作拒绝触发源），顶层键归零。
//
// 三条铁律（P4 实测，不是照抄文档）：
//  1. **expect 块原样搬运**：存量 25 例的 fields/frames 是旧 suite 经真实
//     tshark 落盘的已验值，本整形器只改 spec_json 形状，绝不重算/手打
//     （design §12.1「不搬运旧期望值」指的是不照抄旧**顶层扁平**配置值，
//     wire 断言仍是唯一实测来源；P5 先跑后钉复核）。
//  2. **数量键不落**：design §12.1 去向表把数量映射为兄弟键 `flow_control`
//     （`{"flows": packet_count}`）。实测框架语义：isis 包数由层内 `events`
//     事件数决定（单流内逐事件 Emit），`flows` 是流数（worker 每流调一次
//     Plan）——`flows=4` 会产 16 包而非 4 包；且 `spec_json` 内的
//     `flow_control` 不被任何代码读取（死配置），用例级唯一被 runner 消费的
//     流控键是 `strategy_fc`（nfs/enip/tftp/smb/igmp 先例）。故一律不写，
//     包数由事件数决定（#12=4、#13=2、其余单 PDU=1），与 design §2 的
//     packet_count 序列逐值一致。
//  3. **M5 红例三面**：presence（顶层空 isis 子映射）/ 游离键（顶层 src_ip）/
//     载体（ip 载体 #19 已存 + 本轮补 tcp 载体，覆盖 V7b 的 Transport 分支
//     ——CORE_MEMORY 测试规则 3「每条分支都要有例」）。design §12-P2 原列
//     4 例含「裸 `[isis]` 拒」，P4 实测**证伪**：裸链由 CompleteChain 的
//     DependsOn eth 自动补全成 `[eth,isis]`（与全族协议同款语法糖），
//     BuildLayersPlanner 返回 nil error——该例不建（见 P4 报告缺口项）。

const isisCaseSrcMAC = "02:00:00:00:10:01"

type caseFile struct {
	ID       string                 `json:"id"`
	Proto    string                 `json:"proto"`
	Summary  string                 `json:"summary"`
	SpecJSON map[string]interface{} `json:"spec_json"`
	Expect   map[string]interface{} `json:"expect"`
}

func (c caseFile) m() map[string]interface{} {
	out := map[string]interface{}{
		"id": c.ID, "proto": c.Proto, "summary": c.Summary,
		"spec_json": c.SpecJSON, "expect": c.Expect,
	}
	return out
}

// reshape 把一例的旧混合形 spec_json（顶层 src_mac + 空层 + 顶层 isis 子映射）
// 整形为纯 layers 形：eth 条目填 src_mac、isis 条目填顶层 isis 子映射全部业务键、
// 顶层两键删除。链形（含 #19 的 [ip,isis]）原样保留——它是拒绝触发源。
// **幂等**：已整形（spec_json 只有 layers）的例原样返回，重复运行不再改写。
func reshape(t *testing.T, c caseFile) caseFile {
	t.Helper()
	sj := c.SpecJSON
	if _, hasTopISIS := sj["isis"]; !hasTopISIS {
		if _, hasTopMAC := sj["src_mac"]; !hasTopMAC {
			return c // already reshaped
		}
	}
	layersArr, ok := sj["layers"].([]interface{})
	if !ok || len(layersArr) != 2 {
		t.Fatalf("%s: layers must have exactly 2 entries, got %v", c.ID, sj["layers"])
	}
	ethEntry, _ := layersArr[0].(map[string]interface{})
	isisEntry, _ := layersArr[1].(map[string]interface{})
	if ethEntry == nil || isisEntry == nil {
		t.Fatalf("%s: malformed layer entries %v", c.ID, layersArr)
	}
	if _, ok := isisEntry["isis"]; !ok {
		t.Fatalf("%s: layers[1] is not the isis entry: %v", c.ID, isisEntry)
	}
	// eth 条目填 src_mac（顶层 src_mac 迁移）；#19 无 src_mac（顶层键仅
	// isis/layers），eth 位置实际是 ip 层，原样保留。
	if src, ok := sj["src_mac"].(string); ok && src != "" {
		ethCfg, _ := ethEntry["eth"].(map[string]interface{})
		if ethCfg == nil {
			t.Fatalf("%s: layers[0] is not the eth entry but top-level src_mac present: %v", c.ID, ethEntry)
		}
		ethCfg["src_mac"] = src
	}
	// isis 条目填业务键（顶层 isis 子映射全量迁入）。
	if sub, ok := sj["isis"].(map[string]interface{}); ok {
		dst, _ := isisEntry["isis"].(map[string]interface{})
		if dst == nil {
			t.Fatalf("%s: layers[1].isis is not an object: %v", c.ID, isisEntry["isis"])
		}
		for k, v := range sub {
			dst[k] = v
		}
	}
	c.SpecJSON = map[string]interface{}{"layers": layersArr}
	return c
}

// redCase builds one of the M5 negatives (expect 严格两键).
func redCase(id, summary, chainJSON, anchor string) map[string]interface{} {
	var layersArr []interface{}
	if err := json.Unmarshal([]byte(chainJSON), &layersArr); err != nil {
		panic("bad chain JSON for " + id + ": " + err.Error())
	}
	return map[string]interface{}{
		"id": id, "proto": "isis", "summary": summary,
		"spec_json": map[string]interface{}{"layers": layersArr},
		"expect":    map[string]interface{}{"expect_error": true, "error_contains": anchor},
	}
}

// isisRedIDs is the M5 red-case ID set. The generator rebuilds these from
// scratch every run, so it drops them from the input before reshaping (that
// keeps the whole generator idempotent — a second run sees 28 cases in the
// file, drops the 3 reds, reshapes the 25 stock ones, re-appends the 3).
var isisRedIDs = map[string]bool{
	"isis_neg_presence_top_level_isis": true,
	"isis_neg_stray_src_ip":            true,
	"isis_neg_tcp_carrier":             true,
}

func TestGenerateISISCases(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases", "isis.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var all []map[string]interface{}
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	existing := make([]map[string]interface{}, 0, len(all))
	for _, em := range all {
		if id, _ := em["id"].(string); isisRedIDs[id] {
			continue
		}
		existing = append(existing, em)
	}
	if len(existing) != 25 {
		t.Fatalf("want 25 stock cases after dropping the 3 reds, got %d", len(existing))
	}

	out := make([]map[string]interface{}, 0, 28)
	for i, em := range existing {
		b, _ := json.Marshal(em)
		var c caseFile
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		out = append(out, reshape(t, c).m())
	}

	// M5 红例三面（①②③）：presence / 游离键 / 载体（V7b Transport 分支）。
	// #19 已覆 Network 分支（[ip,isis]），本轮补 Transport（[eth,tcp,isis]）。
	reds := []map[string]interface{}{
		redCase(
			"isis_neg_presence_top_level_isis",
			"presence 判死：层链 + 顶层空 isis 子映射并存（M5①）",
			`[{"eth":{"src_mac":"`+isisCaseSrcMAC+`"}},{"isis":{}}]`,
			"rejects a top-level isis sub-config",
		),
		redCase(
			"isis_neg_stray_src_ip",
			"白名单外游离键判死：layers + 顶层 src_ip（M5②，1.11–1.13）",
			`[{"eth":{"src_mac":"`+isisCaseSrcMAC+`"}},{"isis":{}}]`,
			"rejects flat config field src_ip",
		),
		redCase(
			"isis_neg_tcp_carrier",
			"载体判死（V7b Transport 分支）：[eth,tcp,isis] 夹传输层（M5③；#19 覆 Network 分支）",
			`[{"eth":{"src_mac":"`+isisCaseSrcMAC+`"}},{"tcp":{}},{"isis":{}}]`,
			"must not have an ip/transport carrier",
		),
	}
	// presence 例保留顶层空 isis 子映射（判死形状本体）。
	reds[0]["spec_json"].(map[string]interface{})["isis"] = map[string]interface{}{}
	// 游离键例保留顶层 src_ip（判死形状本体）。
	reds[1]["spec_json"].(map[string]interface{})["src_ip"] = "192.0.2.99"
	out = append(out, reds...)

	if len(out) != 28 {
		t.Fatalf("want 28 cases (13 pos + 15 neg), got %d", len(out))
	}
	nPos, nNeg := 0, 0
	for _, c := range out {
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", c["id"])
		}
		if exp["expect_error"] == true {
			nNeg++
			if len(exp) != 2 {
				t.Fatalf("%s: negative expect must be exactly {expect_error, error_contains}, got %v", c["id"], exp)
			}
		} else {
			nPos++
			for _, k := range []string{"packet_count", "fields", "frames", "has_payload", "directional"} {
				if _, ok := exp[k]; !ok {
					t.Fatalf("%s: positive expect missing %q", c["id"], k)
				}
			}
			// 非负例顶层键=0（只留 layers）。
			sj, _ := c["spec_json"].(map[string]interface{})
			for k := range sj {
				if k != "layers" {
					t.Fatalf("%s: non-negative top-level key %q (want only layers)", c["id"], k)
				}
			}
		}
	}
	if nPos != 13 || nNeg != 15 {
		t.Fatalf("pos/neg = %d/%d, want 13/15", nPos, nNeg)
	}

	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	if err := os.WriteFile(path, append(buf, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d cases: %d pos + %d neg)\n", path, len(out), nPos, nNeg)
}
