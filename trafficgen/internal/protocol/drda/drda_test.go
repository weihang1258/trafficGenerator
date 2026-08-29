package drda

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestDDMBuildEXCSAT(t *testing.T) {
	// S1: EXCSAT (0x1041) min DDM, length=10, length2=4
	ddm, err := ddmBuild(0x01, 1, CPEXCSAT, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ddm) != 10 {
		t.Fatalf("len=%d want 10", len(ddm))
	}
	// length=10
	if got := binary.BigEndian.Uint16(ddm[0:2]); got != 10 {
		t.Fatalf("length=%d want 10", got)
	}
	if ddm[2] != DDMMagic {
		t.Fatalf("magic=%02x want %02x", ddm[2], DDMMagic)
	}
	if ddm[3] != 0x01 {
		t.Fatalf("format=%02x", ddm[3])
	}
	if binary.BigEndian.Uint16(ddm[4:6]) != 1 {
		t.Fatalf("correlator=%d", binary.BigEndian.Uint16(ddm[4:6]))
	}
	if got := binary.BigEndian.Uint16(ddm[6:8]); got != 4 {
		t.Fatalf("length2=%d want 4", got)
	}
	if binary.BigEndian.Uint16(ddm[8:10]) != CPEXCSAT {
		t.Fatalf("code_point=%04x", binary.BigEndian.Uint16(ddm[8:10]))
	}
	// canonical hex: 00 0a d0 01 00 01 00 04 10 41
	want := "000ad001000100041041"
	if hex(ddm) != want {
		t.Fatalf("hex=%s want %s", hex(ddm), want)
	}
}

func TestDDMBuildEXCSATRD(t *testing.T) {
	// EXCSATRD response (0x1443), same correlator
	ddm, err := ddmBuild(0x01, 1, CPEXCSATRD, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(ddm[8:10]) != CPEXCSATRD {
		t.Fatalf("code_point=%04x", binary.BigEndian.Uint16(ddm[8:10]))
	}
	want := "000ad001000100041443"
	if hex(ddm) != want {
		t.Fatalf("hex=%s want %s", hex(ddm), want)
	}
}

func TestParamBuildsCorrectly(t *testing.T) {
	// CCSID parameter: code_point 0x2113, data = 1208 big-endian
	p, err := param(0x2113, u16enc(1208))
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 6 {
		t.Fatalf("param len=%d want 6 (len2+cp2+data2)", len(p))
	}
	if binary.BigEndian.Uint16(p[0:2]) != 6 {
		t.Fatalf("param length=%d want 6", binary.BigEndian.Uint16(p[0:2]))
	}
	if binary.BigEndian.Uint16(p[2:4]) != 0x2113 {
		t.Fatalf("param cp=%04x", binary.BigEndian.Uint16(p[2:4]))
	}
	if binary.BigEndian.Uint16(p[4:6]) != 1208 {
		t.Fatalf("param data=%d want 1208", binary.BigEndian.Uint16(p[4:6]))
	}
}

func TestDDMBuildWithParams(t *testing.T) {
	// ACCSEC with CCSID parameter
	p, _ := param(0x2113, u16enc(1208))
	ddm, err := ddmBuild(0x01, 2, CPACCSEC, [][]byte{p}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ddm) != 16 {
		t.Fatalf("len=%d want 16 (10 head + 6 param)", len(ddm))
	}
	if got := binary.BigEndian.Uint16(ddm[0:2]); got != 16 {
		t.Fatalf("length=%d want 16", got)
	}
	if got := binary.BigEndian.Uint16(ddm[6:8]); got != 10 {
		t.Fatalf("length2=%d want 10 (4+6)", got)
	}
	if binary.BigEndian.Uint16(ddm[8:10]) != CPACCSEC {
		t.Fatalf("code_point=%04x", binary.BigEndian.Uint16(ddm[8:10]))
	}
}

func TestValidateAcceptsEmptyConfig(t *testing.T) {
	// P0b-2：空配置（DRDA nil）不再被 validator 拒绝——Generate/Plan 会默认化并产默认流。
	if err := (Planner{}).Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("empty config should pass validation, got err=%v", err)
	}
}

func TestValidateAcceptsDefaultConfig(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{DRDA: &core.DRDAConfig{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlannerEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（DRDA nil）→ Plan 默认化并产默认流。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 6 {
		t.Fatalf("packets=%d want >=6", count)
	}
}

func TestGeneratorEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（DRDA nil）→ Generate 默认化并产默认流。
	var events []layers.MessageEvent
	err := (&DRDAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 6 {
		t.Fatalf("events=%d want >=6", len(events))
	}
}

func TestPlanEXCSAT(t *testing.T) {
	// S1: EXCSAT/EXCSATRD, 9 packets
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 446,
		DRDA: &core.DRDAConfig{Transport: "excsat", CorrelatorStart: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 9 {
		t.Fatalf("packets=%d want 9 (3 handshake + 2 DDM + 4 teardown)", len(pkts))
	}
	// packet 4: EXCSAT DDM
	if pkts[3].Direction != "up" {
		t.Fatalf("pkt4 direction=%q want up", pkts[3].Direction)
	}
	if binary.BigEndian.Uint16(pkts[3].Payload[8:10]) != CPEXCSAT {
		t.Fatalf("pkt4 code_point=%04x", binary.BigEndian.Uint16(pkts[3].Payload[8:10]))
	}
	// packet 5: EXCSATRD response (down)
	if pkts[4].Direction != "down" {
		t.Fatalf("pkt5 direction=%q want down", pkts[4].Direction)
	}
	if binary.BigEndian.Uint16(pkts[4].Payload[8:10]) != CPEXCSATRD {
		t.Fatalf("pkt5 code_point=%04x", binary.BigEndian.Uint16(pkts[4].Payload[8:10]))
	}
	// correlator same
	if binary.BigEndian.Uint16(pkts[3].Payload[4:6]) != binary.BigEndian.Uint16(pkts[4].Payload[4:6]) {
		t.Fatalf("correlator mismatch")
	}
	// canonical hex: 00 0a d0 01 00 01 00 04 10 41
	want := "000ad001000100041041"
	if hex(pkts[3].Payload) != want {
		t.Fatalf("pkt4 hex=%s want %s", hex(pkts[3].Payload), want)
	}
}

func TestPlanFullSecurity(t *testing.T) {
	// S2: EXCSAT + ACCSEC + SECCHK, 13 packets (3 h + 5 req/resp + 4 t)
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 446,
		DRDA: &core.DRDAConfig{
			Transport: "security", CorrelatorStart: 1,
			SecurityUser: "TESTUSR", SecurityToken: []byte{1, 2, 3, 4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 13 {
		t.Fatalf("packets=%d want 13", len(pkts))
	}
	// packet 4: EXCSAT, 6: ACCSEC, 8: SECCHK
	if binary.BigEndian.Uint16(pkts[5].Payload[8:10]) != CPACCSEC {
		t.Fatalf("pkt6 cp=%04x want ACCSEC", binary.BigEndian.Uint16(pkts[5].Payload[8:10]))
	}
	if binary.BigEndian.Uint16(pkts[7].Payload[8:10]) != CPSECCHK {
		t.Fatalf("pkt8 cp=%04x want SECCHK", binary.BigEndian.Uint16(pkts[7].Payload[8:10]))
	}
}

func TestPlanFullDatabase(t *testing.T) {
	// S3: EXCSAT + ACCSEC + SECCHK + ACCRDB, 15 packets
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 446,
		DRDA: &core.DRDAConfig{
			Transport: "database", CorrelatorStart: 1,
			SecurityUser: "TESTUSR", RDBName: "SAMPLE",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 15 {
		t.Fatalf("packets=%d want 15", len(pkts))
	}
	// ACCRDB at index 9 (10th packet, 0-indexed): 3 handshake + 3*2 = 6 DDM req/resp
	if binary.BigEndian.Uint16(pkts[9].Payload[8:10]) != CPACCRDB {
		t.Fatalf("pkt12 cp=%04x want ACCRDB", binary.BigEndian.Uint16(pkts[11].Payload[8:10]))
	}
}

func TestPlanSQLSuccess(t *testing.T) {
	// S4: full + SQLDTA, 17 packets
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 446,
		DRDA: &core.DRDAConfig{
			Transport: "sql", CorrelatorStart: 1,
			RDBName:        "SAMPLE",
			SecurityUser:   "TESTUSR",
			SecurityToken:  []byte{1, 2, 3, 4},
			SQL: &core.DRDASQLConfig{
				Data: []byte{1, 2, 3, 4}, SQLCode: 0, SQLState: "00000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 17 {
		t.Fatalf("packets=%d want 17", len(pkts))
	}









}

func TestPlanIPV6(t *testing.T) {
	// S7: IPv6 EXCSAT
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 12345, DstPort: 446,
		DRDA: &core.DRDAConfig{Transport: "excsat", CorrelatorStart: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 9 {
		t.Fatalf("packets=%d want 9", len(pkts))
	}
	if pkts[3].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("src=%s", pkts[3].L3.SrcIP)
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("drda")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "drda" {
		t.Fatalf("name=%q", g.Name())
	}
}

func TestLayerGeneratorEXCSAT(t *testing.T) {
	var events []layers.MessageEvent
	err := (&DRDAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{DRDA: &core.DRDAConfig{
			Transport: "excsat", CorrelatorStart: 1,
		}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2 (EXCSAT + EXCSATRD)", len(events))
	}
	if !events[0].Up {
		t.Fatal("event0 not up")
	}
	if events[1].Up {
		t.Fatal("event1 not down")
	}
	if binary.BigEndian.Uint16(events[0].Bytes[8:10]) != CPEXCSAT {
		t.Fatalf("event0 cp=%04x", binary.BigEndian.Uint16(events[0].Bytes[8:10]))
	}
	if binary.BigEndian.Uint16(events[1].Bytes[8:10]) != CPEXCSATRD {
		t.Fatalf("event1 cp=%04x", binary.BigEndian.Uint16(events[1].Bytes[8:10]))
	}
}

func TestLayerGeneratorSQLSuccess(t *testing.T) {
	var events []layers.MessageEvent
	err := (&DRDAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{DRDA: &core.DRDAConfig{
			Transport: "sql", CorrelatorStart: 1, RDBName: "SAMPLE",
			SecurityUser: "TESTUSR",
			SQL: &core.DRDASQLConfig{
				Data: []byte{1, 2, 3, 4}, SQLCode: 0, SQLState: "00000",
			},
		}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 10 events: EXCSAT/EXCSATRD, ACCSEC/ACCSECRD, SECCHK/SECCHKRM, ACCRDB/ACCRDBRM, SQLDTA/SQLCARD
	if len(events) != 10 {
		t.Fatalf("events=%d want 10", len(events))
	}
	// SQLCARD at event index 9 (last)
	last := events[9]
	if last.Up {
		t.Fatal("SQLCARD should be down")
	}
	if binary.BigEndian.Uint16(last.Bytes[8:10]) != CPSQLCARD {
		t.Fatalf("SQLCARD cp=%04x", binary.BigEndian.Uint16(last.Bytes[8:10]))
	}
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}
func TestValidateDSSLengthConsistency(t *testing.T) {
	seg := core.DRDASegment{Format: 1, Correlator: 1, Length: 10, Length2: 4, CodePoint: 4161}

	// 声明 dss_length 与段 length 一致 → 放行
	ok := core.FlowSpec{DRDA: &core.DRDAConfig{DSSLength: 10, DSSSegments: []core.DRDASegment{seg}}}
	if err := (Planner{}).Validate(ok); err != nil {
		t.Fatalf("matching dss_length should pass, got %v", err)
	}

	// 声明 dss_length 与段 length 不一致 → 拒绝（锚点 dss_length）
	bad := core.FlowSpec{DRDA: &core.DRDAConfig{DSSLength: 11, DSSSegments: []core.DRDASegment{seg}}}
	err := (Planner{}).Validate(bad)
	if err == nil || !strings.Contains(err.Error(), "dss_length") {
		t.Fatalf("mismatched dss_length should be rejected with dss_length anchor, got %v", err)
	}

	// dss_length < 6 → 拒绝
	small := core.FlowSpec{DRDA: &core.DRDAConfig{DSSLength: 5}}
	err = (Planner{}).Validate(small)
	if err == nil || !strings.Contains(err.Error(), "dss_length") {
		t.Fatalf("dss_length < 6 should be rejected, got %v", err)
	}
}
