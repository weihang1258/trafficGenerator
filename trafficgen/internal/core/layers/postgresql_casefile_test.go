package layers_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// pgsqlTypeFirstByte maps a tshark pgsql.type label to the payload's first
// byte. Bytes with two meanings (D/C/S/E) are direction-dependent; the caller
// resolves them by matching the nearest candidate index.
var pgsqlTypeFirstByte = map[string]byte{
	"Startup message":             0x00,
	"SSL request":                 0x00,
	"GSS encrypt request":         0x00,
	"Cancel request":              0x00,
	"Authentication request":      0x52,
	"Parameter status":            0x53,
	"Backend key data":            0x4b,
	"Ready for query":             0x5a,
	"Simple query":                0x51,
	"Row description":             0x54,
	"Data row":                    0x44,
	"Command completion":          0x43,
	"Error":                       0x45,
	"Notice":                      0x4e,
	"Notification":                0x41,
	"Empty query":                 0x49,
	"Termination":                 0x58,
	"Password message":            0x70,
	"GSSResponse message":         0x70,
	"SASLInitialResponse message": 0x70,
	"SASLResponse message":        0x70,
	"Parse":                       0x50,
	"Parse completion":            0x31,
	"Bind":                        0x42,
	"Bind completion":             0x32,
	"Describe":                    0x44,
	"Execute":                     0x45,
	"Parameter description":       0x74,
	"No data":                     0x6e,
	"Portal suspended":            0x73,
	"Sync":                        0x53,
	"Flush":                       0x48,
	"Close":                       0x43,
	"Close completion":            0x33,
	"Function call":               0x46,
	"Function call response":      0x56,
}

// planCaseFile drives one case's layers config through the chain planner and
// returns every emitted packet. It is the single driver shared by the
// case-file audit tests below (negative cases are skipped by the callers).
func planCaseFile(t *testing.T, specJSON map[string]interface{}, flows int) []core.PacketConfig {
	t.Helper()
	lj, err := json.Marshal(specJSON["layers"])
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	p, err := layers.BuildLayersPlanner("postgresql", lj)
	if err != nil {
		t.Fatalf("build planner: %v", err)
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("planner is %T, want *layers.ChainPlanner", p)
	}
	fin, err := cp.ValidateSpec(core.FlowSpec{SrcIP: pgCli, DstIP: pgSrv, SrcPort: pgSport, Count: flows})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, err := cp.Plan(ctx, fin)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var pkts []core.PacketConfig
	for x := range ch {
		pkts = append(pkts, x)
	}
	return pkts
}

// loadPGCases parses cases/postgresql.json into raw maps (the audit tests need
// the full expect sub-map, including keys caseFile does not model).
func loadPGCases(t *testing.T) []map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile("../../../test/protocol_pcap/cases/postgresql.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	return cases
}

// caseFlows 从用例的 strategy_fc 取 flows（离线套件/生产同口径）。
func caseFlows(c map[string]interface{}) int {
	if fc, ok := c["strategy_fc"].(map[string]interface{}); ok {
		if t, _ := fc["type"].(string); t == "flows" {
			if v, ok := fc["value"].(float64); ok {
				return int(v)
			}
		}
	}
	return 1
}

// TestPostgresqlCaseFile_FramesAndFieldIndices pins every frames[] hex and
// every pgsql.type packet index to the payload the engine actually emits.
//
// This is the §14.20 "先跑后钉" guard: the declared bytes are compared against
// the generated payload, so a hand-written length field or an off-by-N packet
// index (both of which shipped in the first draft of this file) fails here
// instead of passing silently until the suite runs.
func TestPostgresqlCaseFile_FramesAndFieldIndices(t *testing.T) {
	for _, c := range loadPGCases(t) {
		expect, _ := c["expect"].(map[string]interface{})
		if expect == nil || expect["expect_error"] == true {
			continue
		}
		id, _ := c["id"].(string)
		specJSON, _ := c["spec_json"].(map[string]interface{})
		if specJSON == nil {
			continue
		}
		frames, _ := expect["frames"].([]interface{})
		fields, _ := expect["fields"].([]interface{})
		if len(frames) == 0 && len(fields) == 0 {
			continue
		}
		pkts := planCaseFile(t, specJSON, caseFlows(c))

		for _, f := range frames {
			fm, _ := f.(map[string]interface{})
			if fm == nil {
				continue
			}
			pn, _ := fm["packet"].(float64)
			want, _ := fm["hex"].(string)
			if int(pn) < 1 || int(pn) > len(pkts) {
				t.Errorf("%s: frames packet %d out of range (%d packets)", id, int(pn), len(pkts))
				continue
			}
			if got := hex.EncodeToString(pkts[int(pn)-1].Payload); got != want {
				t.Errorf("%s: frames pkt%d\n  want %s\n  got  %s", id, int(pn), want, got)
			}
		}

		// gen-review C1：原实现只认 `pgsql.type` 且只比**首字节**——于是
		// `pgsql.status`/`pgsql.severity`/`pgsql.val.length` 这类**值**断言
		// 与任何非 type 字段的**包号**全都不受检，14 个正例带着错值/错包号
		// 一路全绿。下面把覆盖面扩到**全部 fields 的包号与值**（值按字段语义
		// 从 payload 字节推导，与用例文件断言面一一对应）。
		for _, f := range fields {
			fm, _ := f.(map[string]interface{})
			if fm == nil {
				continue
			}
			if dv, _ := fm["distinct_values"].([]interface{}); len(dv) > 0 ||
				fm["nonzero"] == true || fm["same_as_packet"] != nil {
				// 聚合/持久性断言：无单包索引语义，由 pcap 级验证器覆盖。
				continue
			}
			fname, _ := fm["field"].(string)
			if fname == "" || !strings.HasPrefix(fname, "pgsql.") {
				// 载体层字段（tcp.*/ipv6.*）不住应用层 payload 内，
				// 由 pcap 级验证器（VerifyPcap）负责；本自查只管 pgsql.*。
				continue
			}
			pn, _ := fm["packet"].(float64)
			if int(pn) < 1 || int(pn) > len(pkts) {
				t.Errorf("%s: field %s pkt%d out of range (%d packets)", id, fname, int(pn), len(pkts))
				continue
			}
			payload := pkts[int(pn)-1].Payload
			switch fname {
			case "pgsql.type":
				label, _ := fm["value"].(string)
				first, known := pgsqlTypeFirstByte[label]
				if !known {
					t.Errorf("%s: field pgsql.type pkt%d unknown label %q", id, int(pn), label)
					continue
				}
				if len(payload) == 0 || payload[0] != first {
					t.Errorf("%s: pgsql.type pkt%d want %q (first byte %02x) got %s",
						id, int(pn), label, first, hex.EncodeToString(payload))
				}
			case "pgsql.status":
				// ReadyForQuery 体 = 4 头 + 1 字节 status（'I'/'T'/'E'）。
				want, _ := fm["value"].(string)
				if len(payload) < 6 {
					t.Errorf("%s: pgsql.status pkt%d payload too short: %s", id, int(pn), hex.EncodeToString(payload))
					continue
				}
				got := strconv.Itoa(int(payload[5]))
				if got != want {
					t.Errorf("%s: pgsql.status pkt%d got %s want %s", id, int(pn), got, want)
				}
			case "pgsql.length":
				// 体长字段 = 头 4 字节的大端 uint32（含头自身）。
				want, _ := fm["value"].(string)
				if len(payload) < 4 {
					t.Errorf("%s: pgsql.length pkt%d payload too short", id, int(pn))
					continue
				}
				got := strconv.Itoa(int(binary.BigEndian.Uint32(payload[0:4])))
				if got == strconv.Itoa(len(payload)) {
					// 消息起点：头 length 自洽，可与声明值比对。
					if got != want {
						t.Errorf("%s: pgsql.length pkt%d got %s want %s", id, int(pn), got, want)
					}
				} else {
					// 跨 MSS 续段（非消息起点）：tshark 该包读不到完整
					// length，声明值来自重组后的消息——由 frames/包数面
					// 覆盖，此处不判。
					t.Logf("%s: pgsql.length pkt%d is a mid-message segment (payload %d B), skipped", id, int(pn), len(payload))
				}
			default:
				// 其余字段（severity/code/condition/text/pid/val.*/authtype/
				// statement/…）无通用字节推导式——按**存在性 + 包号**断言：
				// 该包必须携带非空 payload（包号错位在此暴露），并记录
				// 需要 tshark 级复核的字段清单由 C1 回归测试覆盖。
				if len(payload) == 0 {
					t.Errorf("%s: field %s pkt%d has empty payload (packet index wrong?)", id, fname, int(pn))
				}
			}
		}
	}
}

// TestPostgresqlCaseFile_PacketCounts pins every positive case's declared
// packet_count to the measured emission (N + 7 for a single session; the
// per-session sum for sessions[]).
func TestPostgresqlCaseFile_PacketCounts(t *testing.T) {
	for _, c := range loadPGCases(t) {
		expect, _ := c["expect"].(map[string]interface{})
		if expect == nil || expect["expect_error"] == true {
			continue
		}
		want, ok := expect["packet_count"].(float64)
		if !ok {
			continue
		}
		id, _ := c["id"].(string)
		specJSON, _ := c["spec_json"].(map[string]interface{})
		if specJSON == nil {
			continue
		}
		// planner 只产单流；flows=N 由 worker 复制 N 条（worker.go:279）→
		// 端到端包数 = 单流包数 × N（与离线执行器 spec.Count 口径一致）。
		got := len(planCaseFile(t, specJSON, 1)) * caseFlows(c)
		if got != int(want) {
			t.Errorf("%s: packet_count=%d, measured %d", id, int(want), got)
		}
	}
}
