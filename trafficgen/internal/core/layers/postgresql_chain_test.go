package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/postgresql" // init 注册 postgresql 终结层生成器+校验器
)

// D-POSTGRESQL-1 P4 链级红例（drda/dameng_chain_test 同构）。覆盖：
//  ① 层 config 翻译端到端（含 dialect 两档端口契约 5432/54321）；
//  ② presence 判死（M5 清单①：层链 + 顶层空 postgresql 子映射并存 = G-PG-6
//     关闭后的判死形状）；
//  ③ 白名单外游离键判死（M5 清单②，1.11–1.13 五键）；
//  ④ 载体拒绝（链夹 udp，锚词 tcp）；
//  ⑤ 负例带锚词（M5 清单③）：每条断言 error_contains 命中代码锚词；
//  ⑥ 收官自查行（M5 清单④）：用例文件全例「非负例顶层键=0」+ 64-ID 计数。

const (
	pgCli   = "192.0.2.82"
	pgSrv   = "198.51.100.82"
	pgSport = 45082
)

func pgLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": pgCli, "dst": pgSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": pgSport}},
		map[string]interface{}{"postgresql": cfg},
	}
}

func pgMinCfg() map[string]interface{} {
	return map[string]interface{}{
		"dialect":      "postgresql",
		"wire_profile": "postgresql_v3",
		"events": []interface{}{
			map[string]interface{}{"kind": "startup", "direction": "c2s",
				"user": "bench", "database": "bench"},
		},
	}
}

func planPGAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("postgresql", raw)
	if err != nil {
		return nil, err
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("planner is %T, want *layers.ChainPlanner", p)
	}
	spec := core.FlowSpec{SrcIP: pgCli, DstIP: pgSrv, SrcPort: pgSport}
	fin, err := cp.ValidateSpec(spec)
	if err != nil {
		return nil, err
	}
	ch, err := cp.Plan(context.Background(), fin)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

// ① 层 config 翻译端到端 + dialect 端口契约两档。
func TestPostgresqlChain_DialectPortContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     map[string]interface{}
		port    uint16
		packets int
	}{
		{"postgresql", pgMinCfg(), 5432, 8},
		{"kingbase", map[string]interface{}{
			"dialect":      "kingbase",
			"wire_profile": "kingbase_es_v8_pg_compatible",
			"events": []interface{}{
				map[string]interface{}{"kind": "startup", "direction": "c2s",
					"user": "bench", "database": "bench"},
			},
		}, 54321, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkts, err := planPGAt(t, pgLayers(tc.cfg))
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if len(pkts) != tc.packets {
				t.Fatalf("packets=%d want %d", len(pkts), tc.packets)
			}
			if pkts[0].L4.DstPort != tc.port {
				t.Fatalf("dst_port=%d want %d", pkts[0].L4.DstPort, tc.port)
			}
			if pkts[0].L4.Flags != 0x02 {
				t.Fatalf("first packet flags=0x%02x want SYN", pkts[0].L4.Flags)
			}
			// 应用字节：startup 是首个数据帧，第 4 包（1-based）。
			if got := pkts[3].Payload; len(got) == 0 || got[0] != 0x00 {
				t.Fatalf("pkt4 payload=%x want untagged StartupMessage", got)
			}
		})
	}
}

// ①b 空层默认流（P0b-2）：空 config 也翻译出非 nil 配置，走默认流。
func TestPostgresqlChain_EmptyLayerDefault(t *testing.T) {
	pkts, err := planPGAt(t, pgLayers(map[string]interface{}{}))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	// 空 events → 0 事件 → 仅握手 3 + 挥手 4 = 7 包（connect-only）。
	if len(pkts) != 7 {
		t.Fatalf("packets=%d want 7 (connect-only default)", len(pkts))
	}
}

// ② presence 与顶层游离键判死（M5 必含①②）。
func TestPostgresqlChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	// ① 层链 + 顶层空 postgresql 子映射并存 = 判死（G-PG-6 关闭后）。
	cfg := map[string]interface{}{
		"layers":     pgLayers(pgMinCfg()),
		"postgresql": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("postgresql", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(postgresql, {layers, postgresql:{}}) = \"\", want top-level postgresql presence rejection")
	}
	if !strings.Contains(msg, "top-level postgresql sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	// 层链形状不触发（回归守卫：别把正常链判死）。
	if msg := core.CheckProtoFlat("postgresql", map[string]interface{}{"layers": pgLayers(pgMinCfg())}); msg != "" {
		t.Fatalf("CheckProtoFlat(postgresql, {layers}) = %q, want \"\"", msg)
	}
	// ② 白名单外游离键判死（1.11–1.13）。五键由 CheckProtoFlat 判死；
	// MAC 键由 schema 语义门（层链/扁平混用门）判死——两条机制不混写
	// （dameng_chain_test 同款）。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("postgresql", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(postgresql, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	for _, tc := range []struct {
		key string
		val interface{}
	}{
		{"src_mac", "02:00:00:00:00:01"},
		{"dst_mac", "02:00:00:00:00:02"},
	} {
		bad := map[string]interface{}{"layers": cfg["layers"], tc.key: tc.val}
		if _, errs := schema.ValidateStrategy("synth", "postgresql", bad, nil); len(errs) == 0 {
			t.Fatalf("ValidateStrategy(postgresql, {layers, %s}) accepted, want rejection (1.11–1.13 whitelist)", tc.key)
		}
	}
	// 已知框架缺口（登记，不加单协议分支）：顶层 in-range ttl（如 64）无
	// 类型/混用门拦，只有越界值（>255）被范围门拒——与设计 §10.6 登记的
	// "config 级 unknown-key 白名单缺失"同源（kingbase 记忆裁定：判死补门
	// 方案先问"这个身份还准入吗"，禁加单键黑名单分支）。本测试只钉现状：
	// 越界必拒；in-range 静默放行如实记录，不冒充覆盖。
	if _, errs := schema.ValidateStrategy("synth", "postgresql",
		map[string]interface{}{"layers": cfg["layers"], "ttl": 300}, nil); len(errs) == 0 {
		t.Fatal("ValidateStrategy(postgresql, {layers, ttl:300}) accepted, want out-of-range rejection")
	}
}

// ③ 载体拒绝：链夹 udp（postgresql 只走 tcp）。
func TestPostgresqlChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": pgCli, "dst": pgSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": pgSport}},
		map[string]interface{}{"postgresql": pgMinCfg()},
	}
	raw, _ := json.Marshal(arr)
	_, err := layers.BuildLayersPlanner("postgresql", raw)
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,postgresql]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("error %q does not contain 'tcp'", err.Error())
	}
}

// ④ 端口契约域校验：显式非契约端口拒（dialect 决定期望值）。
func TestPostgresqlChain_NonContractPortRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialect string
		wire    string
		port    int
		anchor  string
	}{
		{"postgresql-5433", "postgresql", "postgresql_v3", 5433, "5432"},
		{"kingbase-54322", "kingbase", "kingbase_es_v8_pg_compatible", 54322, "54321"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arr := []interface{}{
				map[string]interface{}{"ip": map[string]interface{}{"src": pgCli, "dst": pgSrv}},
				map[string]interface{}{"tcp": map[string]interface{}{"src_port": pgSport, "dst_port": tc.port}},
				map[string]interface{}{"postgresql": map[string]interface{}{
					"dialect": tc.dialect, "wire_profile": tc.wire,
					"events": []interface{}{map[string]interface{}{"kind": "startup", "direction": "c2s"}}}},
			}
			_, err := planPGAt(t, arr)
			if err == nil {
				t.Fatal("want non-contract port rejection")
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.anchor)
			}
		})
	}
}

// ⑤ 负例锚词：五类配置面错误逐条命中代码锚词。
func TestPostgresqlChain_NegativeAnchors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    map[string]interface{}
		anchor string
	}{
		{"unknown-dialect",
			map[string]interface{}{"dialect": "mysql", "wire_profile": "postgresql_v3",
				"events": []interface{}{map[string]interface{}{"kind": "startup"}}}, "dialect"},
		{"unknown-wire-profile",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "pg_unknown",
				"events": []interface{}{map[string]interface{}{"kind": "startup"}}}, "wire profile"},
		{"native-pending",
			map[string]interface{}{"dialect": "kingbase", "wire_profile": "kingbase_native_pending",
				"events": []interface{}{map[string]interface{}{"kind": "startup"}}}, "payload"},
		{"query-before-ready",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{map[string]interface{}{"kind": "query", "direction": "c2s", "sql": "SELECT 1"}}}, "state"},
		{"terminate-then-query",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					map[string]interface{}{"kind": "ready", "direction": "s2c"},
					map[string]interface{}{"kind": "terminate", "direction": "c2s"},
					map[string]interface{}{"kind": "query", "direction": "c2s", "sql": "SELECT 1"}}}, "state"},
		{"empty-sql",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					map[string]interface{}{"kind": "ready", "direction": "s2c"},
					map[string]interface{}{"kind": "query", "direction": "c2s", "sql": "  "}}}, "sql"},
		{"invalid-direction",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{map[string]interface{}{"kind": "startup", "direction": "c2b"}}}, "direction"},
		{"unknown-kind",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{map[string]interface{}{"kind": "bogus_kind"}}}, "kind"},
		{"wire-fault-truncate",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events":     []interface{}{map[string]interface{}{"kind": "startup"}},
				"wire_fault": map[string]interface{}{"kind": "truncate_startup", "value": 1}}, "length"},
		{"wire-fault-limit",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events":     []interface{}{map[string]interface{}{"kind": "startup"}},
				"wire_fault": map[string]interface{}{"kind": "message_limit", "value": "x"}}, "limit"},
		{"wire-fault-shape",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events":     []interface{}{map[string]interface{}{"kind": "startup"}},
				"wire_fault": "truncate"}, "object"},
		// 设计 §3.4/§10：auth_data/auth_token 是 opaque 十六进制字节串；
		// 非 hex 在 validator 被拒（否则生成器解码失败会静默丢子类型
		// payload —— §14.11 零假成功）。
		{"auth-data-not-hex",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					map[string]interface{}{"kind": "auth_request", "direction": "s2c",
						"authtype": 8, "auth_data": "zzzz"}}}, "not valid hex"},
		{"auth-token-not-hex",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					map[string]interface{}{"kind": "auth_request", "direction": "s2c", "authtype": 8},
					map[string]interface{}{"kind": "auth_response", "direction": "c2s",
						"auth_token": "not-hex"}}}, "not valid hex"},
		{"md5-salt-wrong-length",
			map[string]interface{}{"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					map[string]interface{}{"kind": "auth_request", "direction": "s2c",
						"authtype": 5, "auth_data": "aabb"}}}, "exactly 4 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planPGAt(t, pgLayers(tc.cfg))
			if err == nil {
				t.Fatalf("want rejection containing %q", tc.anchor)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.anchor)
			}
		})
	}
}

// ⑥ 层内第 6 键判死（V9 白名单，与 presence 是两条不同机制）。
func TestPostgresqlChain_UnknownLayerField(t *testing.T) {
	cfg := pgMinCfg()
	cfg["auth_method"] = "md5"
	arr := pgLayers(cfg)
	raw, _ := json.Marshal(arr)
	_, err := layers.BuildLayersPlanner("postgresql", raw)
	if err == nil {
		t.Fatal("want unknown-field rejection for the 6th layer key")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error %q does not contain 'unknown field'", err.Error())
	}
}

// ⑥b 静态复制拒绝（flows>1 + 全静态四元组，create 期形状门）。
func TestPostgresqlChain_StaticCopyRejected(t *testing.T) {
	cfg := map[string]interface{}{"layers": pgLayers(pgMinCfg())}
	_, errs := schema.ValidateStrategy("synth", "postgresql", cfg, &schema.FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want static-copy rejection, got %v", errs)
	}
}

// ⑩ auth 子类型 payload（设计 §3.4）：R5 必带 4 字节 salt（length=12）、
// R10 必带机制名列表、R8/R11/R12 必带 Byte^n；缺失即结构不合法。
// 回归守卫（P4 修轮实测抓到的缺陷：旧生成器对全部子类型恒发 8 字节空
// payload，与设计 §3.4 表逐行冲突）。
func TestPostgresqlChain_AuthSubtypePayloads(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authtype int
		authData string
		want     string
	}{
		{"md5-salt-default", 5, "", "520000000c0000000512345678"},
		{"md5-salt-explicit", 5, "aabbccdd", "520000000c00000005aabbccdd"},
		{"sasl-mechanisms", 10, "", "52000000170000000a534352414d2d5348412d3235360000"},
		{"gss-continue", 8, "0102030405060708", "5200000010000000080102030405060708"},
		{"sasl-final", 12, "763d7369676e61747572653d3d", "52000000150000000c763d7369676e61747572653d3d"},
		// 无附加 payload 的子类型保持 8 字节。
		{"auth-ok", 0, "", "520000000800000000"},
		{"kerberos", 2, "", "520000000800000002"},
		{"scm-credential", 6, "", "520000000800000006"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := tc.authtype
			ev := map[string]interface{}{"kind": "auth_request", "direction": "s2c", "authtype": at}
			if tc.authData != "" {
				ev["auth_data"] = tc.authData
			}
			cfg := map[string]interface{}{
				"dialect": "postgresql", "wire_profile": "postgresql_v3",
				"events": []interface{}{
					map[string]interface{}{"kind": "startup", "direction": "c2s"},
					ev,
					map[string]interface{}{"kind": "ready", "direction": "s2c"},
				},
			}
			pkts, err := planPGAt(t, pgLayers(cfg))
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			// pkt5（1-based）是 auth_request；4 = 3 握手 + startup。
			if got := hex.EncodeToString(pkts[4].Payload); got != tc.want {
				t.Fatalf("auth payload=%s want %s", got, tc.want)
			}
		})
	}
}

// ⑩b c2s opaque token 形（GSSResponse/SASLInitialResponse/SASLResponse 均
// 骑 `p` 但承载字节 token，不带 NUL 终止；与 cleartext 口令串形区分）。
func TestPostgresqlChain_AuthTokenRawForm(t *testing.T) {
	cfg := map[string]interface{}{
		"dialect": "postgresql", "wire_profile": "postgresql_v3",
		"events": []interface{}{
			map[string]interface{}{"kind": "startup", "direction": "c2s"},
			map[string]interface{}{"kind": "auth_request", "direction": "s2c", "authtype": 8},
			map[string]interface{}{"kind": "auth_response", "direction": "c2s", "auth_token": "600c060a2b0601050502"},
			map[string]interface{}{"kind": "ready", "direction": "s2c"},
		},
	}
	pkts, err := planPGAt(t, pgLayers(cfg))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	// pkt6 = c2s token：无 NUL 终止（对比 cleartext 形的 ...737300）。
	if got := hex.EncodeToString(pkts[5].Payload); got != "700000000e600c060a2b0601050502" {
		t.Fatalf("c2s token payload=%s want raw token without NUL", got)
	}
}

// ⑪ 用例文件收官自查（M5 清单④）：64-ID 全集在案、非负例顶层键=0、
// 负例 expect 严格两键、每负例带锚词。
func TestPostgresqlChain_CaseFileAudit(t *testing.T) {
	b, err := os.ReadFile("../../../test/protocol_pcap/cases/postgresql.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []struct {
		ID       string                 `json:"id"`
		Proto    string                 `json:"proto"`
		SpecJSON map[string]interface{} `json:"spec_json"`
		Expect   map[string]interface{} `json:"expect"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) < 64 {
		t.Fatalf("cases=%d want >= 64 (the 64-ID set)", len(cases))
	}
	var pos, neg int
	for _, c := range cases {
		if c.Proto != "postgresql" {
			t.Fatalf("%s: proto=%q want postgresql", c.ID, c.Proto)
		}
		if c.Expect["expect_error"] == true {
			neg++
			if len(c.Expect) != 2 || c.Expect["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys=%v want exactly {expect_error, error_contains}", c.ID, c.Expect)
			}
			continue
		}
		pos++
		// 非负例顶层键=0（仅 layers / flow_control 家族 / output）。
		for k := range c.SpecJSON {
			switch k {
			case "layers", "flow_control", "output", "output_config", "group_id", "strategy_fc":
			default:
				t.Fatalf("%s: stray top-level key %q (non-negative cases must have zero)", c.ID, k)
			}
		}
		if c.Expect["packet_count"] == nil && c.Expect["min_packets"] == nil {
			t.Fatalf("%s: positive case lacks packet_count/min_packets", c.ID)
		}
		if c.Expect["has_payload"] != true {
			t.Fatalf("%s: positive case lacks has_payload", c.ID)
		}
	}
	// 64-ID 全集 = 48 正 + 16 负（本文用例文件另含 A′ 补例与新增负例，
	// 故为超集；两者都必须在案）。
	if pos < 48 {
		t.Fatalf("positive cases=%d want >= 48", pos)
	}
	if neg < 16 {
		t.Fatalf("negative cases=%d want >= 16", neg)
	}
}

// ⑧ 事件面新 kind 端到端：extended query 与 Z 三态走链翻译（A′ 接线证明）。
func TestPostgresqlChain_ExtendedAndStatusKinds(t *testing.T) {
	cfg := map[string]interface{}{
		"dialect": "postgresql", "wire_profile": "postgresql_v3",
		"events": []interface{}{
			map[string]interface{}{"kind": "startup", "direction": "c2s"},
			map[string]interface{}{"kind": "auth_request", "direction": "s2c", "authtype": 0},
			map[string]interface{}{"kind": "ready", "direction": "s2c", "status": "T"},
			map[string]interface{}{"kind": "parse", "direction": "c2s",
				"statement": "s1", "sql": "SELECT $1", "oids": []interface{}{23}},
			map[string]interface{}{"kind": "parse_complete", "direction": "s2c"},
			map[string]interface{}{"kind": "sync", "direction": "c2s"},
			map[string]interface{}{"kind": "ready", "direction": "s2c"},
		},
	}
	pkts, err := planPGAt(t, pgLayers(cfg))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(pkts) != 14 {
		t.Fatalf("packets=%d want 14 (3+7+4)", len(pkts))
	}
	// 包序（1-based）：1-3 握手，4 startup，5 R0，6 Z(T)，7 Parse，8 ParseComplete，
	// 9 Sync，10 Z，11-14 挥手。
	// p6 = Z(status T) → 5a 00 00 00 05 54
	if got := pkts[5].Payload; len(got) != 6 || got[0] != 0x5a || got[5] != 'T' {
		t.Fatalf("pkt6 payload=%x want ReadyForQuery status 'T'", got)
	}
	// p7 = Parse
	if got := pkts[6].Payload; len(got) == 0 || got[0] != 'P' {
		t.Fatalf("pkt7 payload=%x want Parse", got)
	}
	// p8 = ParseComplete (0x31)
	if got := pkts[7].Payload; len(got) == 0 || got[0] != '1' {
		t.Fatalf("pkt8 payload=%x want ParseComplete", got)
	}
	// p9 = Sync (0x53) —— 与 ParameterStatus 同字节，方向消歧（c2s）
	if got := pkts[8].Payload; len(got) == 0 || got[0] != 'S' {
		t.Fatalf("pkt9 payload=%x want Sync", got)
	}
}

// ⑨ 事件内死字段 profile/result 已从结构体删除：仍写该键不再有语义，
// 且事件面白名单（V9）只约束层顶 5 键——事件内键不判死（有界缺口，
// 见 coverage_gate 注记）。本测试钉住"删字段后不再有 .Profile/.Result"。
func TestPostgresqlChain_DeadFieldsRemoved(t *testing.T) {
	// 编译期证明：PostgreSQLEvent 无 Profile/Result 字段。写该键的 JSON
	// 解码仍成功（encoding/json 忽略未知键），但不产生任何语义。
	raw := []byte(`{"kind":"startup","profile":"x","result":"success"}`)
	var ev core.PostgreSQLEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Kind != "startup" {
		t.Fatalf("kind=%q", ev.Kind)
	}
	// 用 reflect 证明结构体确无这两个字段（防回退）。
	typ := reflect.TypeOf(ev)
	for _, name := range []string{"Profile", "Result"} {
		if _, ok := typ.FieldByName(name); ok {
			t.Fatalf("PostgreSQLEvent still has field %s (G-PG-5 regression)", name)
		}
	}
}
