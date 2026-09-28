package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/postgresql" // init 注册 postgresql 层生成器 + 校验器
)

// caseFile is one entry from the postgresql.json / kingbase.json case suites.
type caseFile struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	SpecJSON json.RawMessage `json:"spec_json"`
	// StrategyFC 是策略级流控（flows=N）；create 期形状门（静态复制拒绝面）
	// 需要它才能复现（MCP 的 stratFC(c.StrategyFC) 同款）。
	StrategyFC *struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	} `json:"strategy_fc"`
	Expect struct {
		PacketCount   int    `json:"packet_count"`
		HasHandshake  bool   `json:"has_handshake"`
		Terminates    bool   `json:"terminates"`
		HasPayload    bool   `json:"has_payload"`
		ExpectError   bool   `json:"expect_error"`
		ErrorContains string `json:"error_contains"`
	} `json:"expect"`
}

// loadPGAbsolute loads a case file by absolute path (resolved from repo root
// via the test's working-dir-relative path, robust to cwd).
func loadCaseFile(t *testing.T, rel string) []caseFile {
	t.Helper()
	// Try a few candidate roots: the test runs with cwd = the package dir.
	candidates := []string{
		rel,
		filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases"), // not used; see below
	}
	_ = candidates
	// Resolve against the repo's test/protocol_pcap/cases dir.
	base, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// From internal/core/layers, the cases dir is ../../../test/protocol_pcap/cases.
	dir := filepath.Join(base, "..", "..", "..", "test", "protocol_pcap", "cases")
	b, err := os.ReadFile(filepath.Join(dir, filepath.Base(rel)))
	if err != nil {
		t.Fatalf("read case file %s (dir=%s): %v", rel, dir, err)
	}
	var cs []caseFile
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return cs
}

// driveCase builds the layer planner from the case's layers config and drives
// Plan. Returns the planner error (if any) and emitted packet count.
func driveCase(t *testing.T, c caseFile) (error, int) {
	t.Helper()
	pkts, err := driveCasePackets(t, c)
	if err != nil {
		return err, 0
	}
	// C1 回归：ChainPlanner.Plan 只产**单流**（flows 的复制语义住
	// worker.go:279，不在 planner）——故端到端包数 = 单流包数 × flows。
	// 原实现直接返回 len(pkts)，multi_flow_dynamic 的 packet_count=33
	// 因此恒报 11。
	flows := 1
	if c.StrategyFC != nil && c.StrategyFC.Type == "flows" && c.StrategyFC.Value > 0 {
		flows = int(c.StrategyFC.Value)
	}
	return nil, len(pkts) * flows
}

// driveCasePackets drives the case config and returns the collected packets.
func driveCasePackets(t *testing.T, c caseFile) ([]core.PacketConfig, error) {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(c.SpecJSON, &cfg); err != nil {
		t.Fatalf("parse spec_json: %v", err)
	}
	proto := c.Proto
	if proto == "" {
		proto = "postgresql"
	}
	layersJSON, _ := json.Marshal(cfg["layers"])
	planner, err := layers.BuildLayersPlanner(proto, layersJSON)
	if err != nil {
		return nil, err
	}
	spec := core.MapToFlowSpec(cfg, proto)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, err := planner.Plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	return pkts, nil
}

func TestPostgreSQLCaseConfigs(t *testing.T) {
	for _, rel := range []string{"postgresql.json", "kingbase.json"} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			for _, c := range loadCaseFile(t, rel) {
				c := c
				t.Run(c.ID, func(t *testing.T) {
					// 负例：create 期形状门（ValidateStrategy，与 MCP 建策略同路）
					// 与 task 期链边界两路任一命中锚词即通过——MCP 的
					// runOneCasePcap 正是"生成或任务被拒即 pass"，本 helper 对齐
					// 该口径（否则 create 期判死类负例在此假红）。
					if c.Expect.ExpectError {
						msg := createTimeRejection(t, c)
						if msg == "" {
							msg = planTimeRejection(t, c)
						}
						if msg == "" {
							t.Fatalf("expected error containing %q, but neither create nor plan rejected", c.Expect.ErrorContains)
						}
						if c.Expect.ErrorContains != "" && !strings.Contains(msg, c.Expect.ErrorContains) {
							t.Fatalf("error %q does not contain %q", msg, c.Expect.ErrorContains)
						}
						return
					}
					err, count := driveCase(t, c)
					if err != nil {
						t.Fatalf("planner error: %v", err)
					}
					if c.Expect.PacketCount > 0 && count != c.Expect.PacketCount {
						t.Fatalf("packet_count=%d, want %d", count, c.Expect.PacketCount)
					}
				})
			}
		})
	}
}

// createTimeRejection runs the create-time shape gate (schema.ValidateStrategy)
// and returns the first error message, or "" when the config is accepted.
func createTimeRejection(t *testing.T, c caseFile) string {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(c.SpecJSON, &cfg); err != nil {
		t.Fatalf("parse spec_json: %v", err)
	}
	fc := &schema.FlowControl{Type: "flows", Value: 1}
	if c.StrategyFC != nil {
		fc.Type = c.StrategyFC.Type
		fc.Value = c.StrategyFC.Value
	}
	proto := c.Proto
	if proto == "" {
		proto = "postgresql"
	}
	_, errs := schema.ValidateStrategy("synth", proto, cfg, fc)
	if len(errs) == 0 {
		return ""
	}
	return errs[0].Error()
}

// planTimeRejection drives the chain planner and returns its error message, or
// "" when the plan succeeded (a negative case that produced packets is a fail).
func planTimeRejection(t *testing.T, c caseFile) string {
	t.Helper()
	err, count := driveCase(t, c)
	if err != nil {
		return err.Error()
	}
	if count > 0 {
		return ""
	}
	return ""
}

// TestPostgresqlLayerSchemaAndFieldContract asserts the postgresql layer is
// registered with the shared FieldContract (→tcp.dst_port=5432) and dialect
// field default "postgresql".
func TestPostgresqlLayerSchemaAndFieldContract(t *testing.T) {
	r := layers.DefaultRegistry()
	s, ok := r.Get("postgresql")
	if !ok {
		t.Fatal("postgresql layer not registered")
	}
	if s.Category != layers.CategoryTerminal {
		t.Fatalf("category=%v want terminal", s.Category)
	}
	if len(s.DependsOn) != 1 || s.DependsOn[0] != "tcp" {
		t.Fatalf("DependsOn=%v want [tcp]", s.DependsOn)
	}
	if s.FieldContract["tcp.dst_port"] != "5432" {
		t.Fatalf("FieldContract[tcp.dst_port]=%q want 5432", s.FieldContract["tcp.dst_port"])
	}
	// dialect field default.
	f, ok := s.Fields["dialect"]
	if !ok {
		t.Fatal("dialect field missing")
	}
	if f.Default != "postgresql" {
		t.Fatalf("dialect default=%v want postgresql", f.Default)
	}
	if wf, ok := s.Fields["wire_profile"]; !ok || wf.Default != "postgresql_v3" {
		t.Fatalf("wire_profile field default=%v want postgresql_v3", wf.Default)
	}
}

// TestPostgresqlEffectiveFieldContractDialect drives the dialect→port contract
// override: postgresql→5432, kingbase→54321 (design §1.3/§3.3 F4).
func TestPostgresqlEffectiveFieldContractDialect(t *testing.T) {
	r := layers.DefaultRegistry()
	pg := r.EffectiveFieldContract(layers.Layer{Name: "postgresql"})
	if pg["tcp.dst_port"] != "5432" {
		t.Fatalf("postgresql contract=%q want 5432", pg["tcp.dst_port"])
	}
	kb := r.EffectiveFieldContract(layers.Layer{Name: "postgresql", Config: map[string]interface{}{"dialect": "kingbase"}})
	if kb["tcp.dst_port"] != "54321" {
		t.Fatalf("kingbase contract=%q want 54321", kb["tcp.dst_port"])
	}
	// dialect default (absent) stays 5432.
	absent := r.EffectiveFieldContract(layers.Layer{Name: "postgresql", Config: map[string]interface{}{}})
	if absent["tcp.dst_port"] != "5432" {
		t.Fatalf("absent-dialect contract=%q want 5432", absent["tcp.dst_port"])
	}
}

// TestPostgresqlDialectPortDrivesTcpLayer asserts the chain planner writes the
// FieldContract-port into the tcp carrier's dst_port (5432/54321), NOT a
// hardcoded case: dialect=postgresql → 5432, dialect=kingbase → 54321.
func TestPostgresqlDialectPortDrivesTcpLayer(t *testing.T) {
	for _, tc := range []struct {
		dialect string
		port    uint16
	}{
		{"postgresql", 5432},
		{"kingbase", 54321},
	} {
		t.Run(tc.dialect, func(t *testing.T) {
			layersJSON := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345}},{"postgresql":{"dialect":"` + tc.dialect + `","wire_profile":"postgresql_v3","events":[{"kind":"startup","direction":"c2s"}]}}]`)
			planner, err := layers.BuildLayersPlanner("postgresql", layersJSON)
			if err != nil {
				t.Fatalf("build planner: %v", err)
			}
			spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, Count: 1}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ch, err := planner.Plan(ctx, spec)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			var got []core.PacketConfig
			for p := range ch {
				got = append(got, p)
			}
			if len(got) != 8 { // 3 handshake + 1 startup event + 4 teardown
				t.Fatalf("packets=%d want 8", len(got))
			}
			// SYN packet dst_port must equal the dialect port.
			if got[0].L4.DstPort != tc.port {
				t.Fatalf("dst_port=%d want %d (dialect=%s)", got[0].L4.DstPort, tc.port, tc.dialect)
			}
		})
	}
}

// TestPostgresqlNegUDPCarrier asserts a UDP carrier is rejected (error contains
// "tcp"). This exercises the postgresql carrier check + V3 duplicate-transport
// message change.
func TestPostgresqlNegUDPCarrier(t *testing.T) {
	layersJSON := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":12345}},{"postgresql":{"dialect":"kingbase","wire_profile":"kingbase_es_v8_pg_compatible","events":[{"kind":"startup","direction":"c2s"}]}}]`)
	_, err := layers.BuildLayersPlanner("postgresql", layersJSON)
	if err == nil {
		t.Fatal("expected udp-carrier rejection, got nil")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("error %q does not contain 'tcp'", err.Error())
	}
}

// TestPostgresqlNegPort asserts a nonstandard tcp.dst_port is rejected for
// dialect=kingbase (error contains "54321").
func TestPostgresqlNegPort(t *testing.T) {
	layersJSON := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":54322}},{"postgresql":{"dialect":"kingbase","wire_profile":"kingbase_es_v8_pg_compatible","events":[{"kind":"startup","direction":"c2s"}]}}]`)
	planner, err := layers.BuildLayersPlanner("postgresql", layersJSON)
	if err != nil {
		t.Fatalf("build planner (config validates at creation; port rule fires at Plan): %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, Count: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = planner.Plan(ctx, spec)
	if err == nil {
		t.Fatal("expected port rejection, got nil")
	}
	if !strings.Contains(err.Error(), "54321") {
		t.Fatalf("error %q does not contain '54321'", err.Error())
	}
}

// TestPostgresqlNegWireFault asserts the wire_fault (truncate_startup) is
// rejected at validation (error contains "length").
func TestPostgresqlNegWireFault(t *testing.T) {
	layersJSON := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345}},{"postgresql":{"dialect":"kingbase","wire_profile":"kingbase_es_v8_pg_compatible","events":[{"kind":"startup","direction":"c2s","user":"test","database":"test"}],"wire_fault":{"kind":"truncate_startup","value":1}}}]`)
	planner, err := layers.BuildLayersPlanner("postgresql", layersJSON)
	if err != nil {
		t.Fatalf("build planner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, Count: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = planner.Plan(ctx, spec)
	if err == nil {
		t.Fatal("expected wire_fault rejection, got nil")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Fatalf("error %q does not contain 'length'", err.Error())
	}
}

// caseBytes is a helper that loads a case by id from the kingbase.json suite.
func loadKingbaseCase(t *testing.T, id string) caseFile {
	t.Helper()
	for _, c := range loadCaseFile(t, "kingbase.json") {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("case %s not found in kingbase.json", id)
	return caseFile{}
}

// TestPostgresqlAuthSuccessBytes asserts the S3 auth flow bytes: packet 5
// (1-indexed) = auth_request hex 'R' (0x52), packet 6 = auth_response hex 'p'
// (0x70), packet 7 = ready hex 'Z' (0x5a). 11 packets total (3 handshake +
// 4 events + 4 teardown).
func TestPostgresqlAuthSuccessBytes(t *testing.T) {
	pkts, err := driveCasePackets(t, loadKingbaseCase(t, "kingbase_auth_success"))
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if len(pkts) != 11 {
		t.Fatalf("packets=%d want 11", len(pkts))
	}
	// 0-indexed: [3]=startup, [4]=auth_request, [5]=auth_response, [6]=ready.
	if len(pkts[4].Payload) == 0 || pkts[4].Payload[0] != 0x52 {
		t.Fatalf("pkt[4] first byte=0x%x want 0x52 (R=AuthRequest)", byte0(pkts[4]))
	}
	if len(pkts[5].Payload) == 0 || pkts[5].Payload[0] != 0x70 {
		t.Fatalf("pkt[5] first byte=0x%x want 0x70 (p=PasswordMessage)", byte0(pkts[5]))
	}
	if len(pkts[6].Payload) == 0 || pkts[6].Payload[0] != 0x5a {
		t.Fatalf("pkt[6] first byte=0x%x want 0x5a (Z=ReadyForQuery)", byte0(pkts[6]))
	}
}

// TestPostgresqlQueryErrorBytes asserts the S5 query-error flow bytes: packet 8
// (1-indexed) = query hex 'Q' (0x51) with the case SQL, packet 9 = error hex
// 'E' (0x45), packet 10 = ready hex 'Z' (0x5a). 14 packets total.
func TestPostgresqlQueryErrorBytes(t *testing.T) {
	pkts, err := driveCasePackets(t, loadKingbaseCase(t, "kingbase_query_error"))
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if len(pkts) != 14 {
		t.Fatalf("packets=%d want 14", len(pkts))
	}
	// 0-indexed: [7]=query, [8]=query_error, [9]=ready.
	if len(pkts[7].Payload) == 0 || pkts[7].Payload[0] != 0x51 {
		t.Fatalf("pkt[7] first byte=0x%x want 0x51 (Q=Query)", byte0(pkts[7]))
	}
	if !strings.Contains(string(pkts[7].Payload), "SELECT missing_column FROM missing_table") {
		t.Fatalf("pkt[7] query SQL not found in %x", pkts[7].Payload)
	}
	if len(pkts[8].Payload) == 0 || pkts[8].Payload[0] != 0x45 {
		t.Fatalf("pkt[8] first byte=0x%x want 0x45 (E=ErrorResponse)", byte0(pkts[8]))
	}
	if len(pkts[9].Payload) == 0 || pkts[9].Payload[0] != 0x5a {
		t.Fatalf("pkt[9] first byte=0x%x want 0x5a (Z=ReadyForQuery)", byte0(pkts[9]))
	}
}

// TestPostgresqlMultiSessionConnections asserts the S8 two-independent-sessions
// case: 22 packets (2 connections x 11), two distinct data srcports [12345,
// 12346], and every data/dstport on 54321.
func TestPostgresqlMultiSessionConnections(t *testing.T) {
	pkts, err := driveCasePackets(t, loadKingbaseCase(t, "kingbase_multi_session"))
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if len(pkts) != 22 {
		t.Fatalf("packets=%d want 22", len(pkts))
	}
	srcs := map[uint16]bool{}
	for _, p := range pkts {
		if p.L4.Protocol != "tcp" {
			continue
		}
		// Data packets (PSH-ACK) carry the client source port; collect them.
		if p.L4.Flags&layers.FlagPSH != 0 && p.L4.SrcPort != 54321 {
			srcs[p.L4.SrcPort] = true
			// A client→server data packet must carry the server port 54321.
			if p.L4.DstPort != 54321 {
				t.Fatalf("client data packet dst_port=%d want 54321 (src=%d)", p.L4.DstPort, p.L4.SrcPort)
			}
		}
	}
	if len(srcs) != 2 || !srcs[12345] || !srcs[12346] {
		t.Fatalf("data srcports=%v want {12345,12346}", srcs)
	}
}

// byte0 returns the first payload byte, or 0 if empty, for error messages.
func byte0(p core.PacketConfig) int {
	if len(p.Payload) == 0 {
		return 0
	}
	return int(p.Payload[0])
}
