package mms

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestTPKTRejectsOversizeBody(t *testing.T) {
	body := make([]byte, 65532)
	if got, err := tpkt(body); err == nil || got != nil {
		t.Fatalf("oversize TPKT returned %d bytes, err=%v", len(got), err)
	}
}

func TestBuildCRCanonical(t *testing.T) {
	got, err := BuildCR()
	if err != nil {
		t.Fatal(err)
	}
	want := "030000140fe00000000100c0010cc20101c10102"
	if fmtHex(got) != want {
		t.Fatalf("CR=%s want %s", fmtHex(got), want)
	}
	if binary.BigEndian.Uint16(got[2:4]) != uint16(len(got)) {
		t.Fatalf("TPKT length mismatch")
	}
}

func TestBuildCCCanonical(t *testing.T) {
	got, err := BuildCC()
	if err != nil {
		t.Fatal(err)
	}
	want := "030000140fd00001000200c0010cc10101c20102"
	if fmtHex(got) != want {
		t.Fatalf("CC=%s want %s", fmtHex(got), want)
	}
}

func TestPlannerAssociationAndRead(t *testing.T) {
	cfg := &core.MMSConfig{Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "GGIO1.stVal", Datatype: "boolean", Value: true}}, EnableRead: true, Sequence: &core.MMSSequence{Steps: []string{"read"}}}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102, MMS: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var got []core.PacketConfig
	for p := range ch {
		got = append(got, p)
	}
	if len(got) < 11 {
		t.Fatalf("packets=%d want association plus read", len(got))
	}
	if !strings.Contains(fmtHex(got[3].Payload), "0300") {
		t.Fatalf("CR payload missing")
	}
	var app int
	for _, p := range got {
		if len(p.Payload) > 0 {
			app++
		}
	}
	if app < 6 {
		t.Fatalf("application packets=%d", app)
	}
}

func TestBuildAssociateMatchesCanonicalFrame(t *testing.T) {
	got, err := BuildAssociate(&core.MMSConfig{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("030000a502f0800d920506130100160102140200023305000102030434020001c1810081317fa003800101a278810412345678820487654321a425301002020101060452010001300406025101301102020103060528ca22020130040602510161433041020101a03c603aa1060628ca220203be30282e020103a029a82780040000fa0081010582010583010aa416800101810305f100820c05ee1c00000408000079ef18")
	if err != nil {
		t.Fatal(err)
	}
	if fmtHex(got) != fmtHex(want) {
		t.Fatalf("associate=%x want %x", got, want)
	}
}
func TestBuildAssociateMatchesCanonicalAcknowledge(t *testing.T) {
	got, err := BuildAssociate(&core.MMSConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("030000a102f0800e900506130100160102140200023305000102030434020001c17f317da003800101a276830400000001a51e300d02020101300780010081025101300d02020103300780010081025101614e304c020101a0476145a1060628ca220203a203020100a305a103020100be2f282d020103a028a92680040000fa0081010582010583010aa415800101810205f1820c0b0000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if fmtHex(got) != fmtHex(want) {
		t.Fatalf("associate ack=%x want %x", got, want)
	}
}

func TestBuildAssociateAppliesNonDefaultParameters(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{
		LocalDetail:           0x12345678,
		MaxOutstandingCalling: 7,
		MaxOutstandingCalled:  8,
		NestingLevel:          9,
	}}
	for _, response := range []bool{false, true} {
		got, err := BuildAssociate(cfg, response)
		if err != nil {
			t.Fatal(err)
		}
		if !containsSubslice(got, []byte{0x80, 0x04, 0x12, 0x34, 0x56, 0x78}) {
			t.Fatalf("response=%v missing local-detail: %x", response, got)
		}
		for _, value := range []byte{7, 8, 9} {
			if !containsSubslice(got, []byte{0x01, value}) {
				t.Fatalf("response=%v missing association value %d: %x", response, value, got)
			}
		}
		if binary.BigEndian.Uint16(got[2:4]) != uint16(len(got)) {
			t.Fatalf("response=%v TPKT length mismatch", response)
		}
		if len(got) < 8 || got[4] != 2 || got[5] != 0xf0 || got[6] != 0x80 {
			t.Fatalf("response=%v invalid COTP DT header: %x", response, got[:8])
		}
	}
}

func TestBuildAssociateAppliesServicesSupported(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: "0102030404"}}
	got, err := BuildAssociate(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubslice(got, []byte{0x82, 0x05, 0x01, 0x02, 0x03, 0x04, 0x04}) {
		t.Fatalf("missing configured services-supported bit string: %x", got)
	}
}

func TestBuildAssociateUsesLongFormLengths(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: strings.Repeat("00", 256)}}
	got, err := BuildAssociate(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubslice(got, []byte{0xa8, 0x82}) || !containsSubslice(got, []byte{0x28, 0x82}) {
		t.Fatalf("association does not encode long-form nested lengths: %x", got)
	}
	if got[2] != byte(len(got)>>8) || got[3] != byte(len(got)) {
		t.Fatalf("TPKT length mismatch: header=%x actual=%d", got[2:4], len(got))
	}
}

func TestBuildAssociateRejectsInvalidServicesSupported(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: "0xz"}}
	if _, err := BuildAssociate(cfg, false); err == nil || !strings.Contains(err.Error(), "servicesSupported") {
		t.Fatalf("err=%v want invalid servicesSupported", err)
	}
}

func TestBuildAssociateUsesCanonicalForEmptyAssociation(t *testing.T) {
	got, err := BuildAssociate(&core.MMSConfig{Association: &core.MMSAssociationConfig{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fmtHex(got), "030000a502f0800d92") {
		t.Fatalf("empty association did not use canonical SPDU: %x", got)
	}
}

func TestBuildAssociateRejectsOversizeTPKT(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: strings.Repeat("00", 130890)}}
	if _, err := BuildAssociate(cfg, false); err == nil || !strings.Contains(err.Error(), "TPKT") {
		t.Fatalf("err=%v want TPKT size error", err)
	}
}

func TestBuildAssociateHasSingleExternalWrapper(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: "0102030404"}}
	got, err := BuildAssociate(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	beCount := 0
	for _, b := range got {
		if b == 0xbe {
			beCount++
		}
	}
	if beCount != 1 || !containsSubslice(got, []byte{0x28, 0x27, 0x02, 0x01, 0x03}) {
		t.Fatalf("invalid EXTERNAL wrapper (beCount=%d): %x", beCount, got)
	}
}

func TestBuildAssociateHasSessionAndPresentationWrappers(t *testing.T) {
	cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: "0102030404"}}
	got, err := BuildAssociate(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	// Request envelope: c1 + marker 0x81 + 2-byte length + CP (reference
	// capture form; the 2-byte length = bytes remaining after it, i.e. the
	// whole CP element starting at offset 36).
	want := []byte{0xc1, 0x81, byte((len(got) - 36) >> 8), byte(len(got) - 36), 0x31}
	if !containsSubslice(got, want) {
		t.Fatalf("missing SPDU/session user-data wrapper (want %x): %x", want, got)
	}
}

func TestBuildAssociateRejectsInvalidServicesSupportedBits(t *testing.T) {
	for _, value := range []string{"08", "01ff"} {
		cfg := &core.MMSConfig{Association: &core.MMSAssociationConfig{ServicesSupported: value}}
		if _, err := BuildAssociate(cfg, false); err == nil || !strings.Contains(err.Error(), "servicesSupported") {
			t.Fatalf("value=%q err=%v want semantic servicesSupported error", value, err)
		}
	}
}

func TestBuildMMSServicePayloads(t *testing.T) {
	cfg := &core.MMSConfig{
		IEDName: "FAKE8150",
		Objects: []core.MMSObjectConfig{
			{Domain: "IED1", Name: "GGIO1.stVal", Datatype: "boolean", Value: true},
			{Domain: "IED1", Name: "MMXU1.TotW.mag.f", Datatype: "integer", Value: 42},
			{Domain: "IED1", Name: "LLN0.Mod.stVal", Datatype: "octetString", Value: "0102"},
		},
	}
	checks := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"read request", mustService(BuildReadRequest(cfg, 1)), []byte{0xa0, 0xa4, 0x1a}},
		{"read response", mustService(BuildReadResponse(cfg, 1)), []byte{0xa1, 0xa4, 0x83, 0x85, 0x89}},
		{"write request", mustService(BuildWriteRequest(cfg, 1)), []byte{0xa0, 0xa5, 0x83, 0x85}},
		{"write response", mustService(BuildWriteResponse(cfg, 1)), []byte{0xa1, 0xa5, 0x81}},
		{"name list request", mustService(BuildGetNameListRequest(1)), []byte{0xa0, 0xa1, 0x80, 0x00}},
		{"name list response", mustService(BuildGetNameListResponse(cfg, 1)), []byte{0xa1, 0xa1, 0x1a}},
		{"identify request", mustService(BuildIdentifyRequest(1)), []byte{0xa0, 0xa2, 0x00}},
		{"identify response", mustService(BuildIdentifyResponse(cfg, 1)), []byte{0xa1, 0xa2, 0x80, 0x81, 0x82}},
		{"information report", mustService(BuildInformationReport(cfg)), []byte{0xa3, 0xa0, 0x83}},
		{"service error", mustService(BuildServiceError(cfg, 1)), []byte{0xa2, 0xa0, 0x87, 0x02}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			for _, needle := range tc.want {
				if !containsByte(tc.got, needle) {
					t.Fatalf("payload=%x missing 0x%02x", tc.got, needle)
				}
			}
		})
	}
}

func mustService(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func containsByte(b []byte, want byte) bool {
	for _, got := range b {
		if got == want {
			return true
		}
	}
	return false
}

func wrapCOTP(b []byte) []byte {
	got, err := cotpDT(b)
	if err != nil {
		panic(err)
	}
	return got
}

func TestPlannerUsesServiceBuilders(t *testing.T) {
	tests := []struct {
		name string
		cfg  core.MMSConfig
		want func(*core.MMSConfig, byte) []byte
	}{
		{"read", core.MMSConfig{EnableRead: true, Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}}, Sequence: &core.MMSSequence{Steps: []string{"read"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildReadRequest(c, invoke); return wrapCOTP(b) }},
		{"write", core.MMSConfig{EnableWrite: true, Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}}, Sequence: &core.MMSSequence{Steps: []string{"write"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildWriteRequest(c, invoke); return wrapCOTP(b) }},
		{"getnmlist", core.MMSConfig{EnableGetNameList: true, Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean"}}, Sequence: &core.MMSSequence{Steps: []string{"getnmlist"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildGetNameListRequest(invoke); return wrapCOTP(b) }},
		{"identify", core.MMSConfig{EnableIdentify: true, Sequence: &core.MMSSequence{Steps: []string{"identify"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildIdentifyRequest(invoke); return wrapCOTP(b) }},
		{"report", core.MMSConfig{EnableInformationReport: true, Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}}, Sequence: &core.MMSSequence{Steps: []string{"report"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildInformationReport(c); return wrapCOTP(b) }},
		{"error", core.MMSConfig{EnableRead: true, ErrorClassName: "access", ErrorValue: 2, Objects: []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean"}}, Sequence: &core.MMSSequence{Steps: []string{"read"}}}, func(c *core.MMSConfig, invoke byte) []byte { b, _ := BuildServiceError(c, invoke); return wrapCOTP(b) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102, MMS: &tc.cfg})
			if err != nil {
				t.Fatal(err)
			}
			var payloads [][]byte
			for p := range ch {
				if len(p.Payload) != 0 {
					payloads = append(payloads, p.Payload)
				}
			}
			want := tc.want(&tc.cfg, 1)
			found := false
			for _, payload := range payloads {
				if string(payload) == string(want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("planner did not emit builder payload %x; payloads=%x", want, payloads)
			}
		})
	}
}

func TestLayerGeneratorEmitsConfiguredServices(t *testing.T) {
	cfg := &core.MMSConfig{
		Objects:    []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}},
		EnableRead: true,
		Sequence:   &core.MMSSequence{Steps: []string{"read"}},
	}
	var events []layers.MessageEvent
	err := (&MMSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MMS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("events=%d want CR/CC/associate/read req+resp", len(events))
	}
	if !containsSubslice(events[4].Bytes, []byte{0xa4}) || !containsSubslice(events[5].Bytes, []byte{0xa4}) {
		t.Fatalf("read service missing: req=%x resp=%x", events[4].Bytes, events[5].Bytes)
	}
}

func containsSubslice(b, want []byte) bool {
	for i := 0; i+len(want) <= len(b); i++ {
		match := true
		for j := range want {
			if b[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
func TestPlannerIncrementsInvokeIDAcrossSteps(t *testing.T) {
	cfg := &core.MMSConfig{
		Objects:        []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}},
		EnableRead:     true,
		EnableIdentify: true,
		Sequence:       &core.MMSSequence{Steps: []string{"read", "identify"}},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102, MMS: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var servicePayloads [][]byte
	for p := range ch {
		if len(p.Payload) > 10 && (p.Payload[7] == 0xa0 || p.Payload[7] == 0xa1) {
			servicePayloads = append(servicePayloads, p.Payload)
		}
	}
	if len(servicePayloads) != 4 {
		t.Fatalf("service payloads=%d want 4", len(servicePayloads))
	}
	if servicePayloads[0][11] != 1 || servicePayloads[1][11] != 1 {
		t.Fatalf("read invoke IDs=%d/%d want 1", servicePayloads[0][11], servicePayloads[1][11])
	}
	if servicePayloads[2][11] != 2 || servicePayloads[3][11] != 2 {
		t.Fatalf("identify invoke IDs=%d/%d want 2", servicePayloads[2][11], servicePayloads[3][11])
	}
}

func TestPlannerInformationReportIsDownstream(t *testing.T) {
	cfg := &core.MMSConfig{
		Objects:                 []core.MMSObjectConfig{{Domain: "IED1", Name: "x", Datatype: "boolean", Value: true}},
		EnableInformationReport: true,
		Sequence:                &core.MMSSequence{Steps: []string{"report"}},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102, MMS: cfg})
	if err != nil {
		t.Fatal(err)
	}
	for p := range ch {
		if len(p.Payload) > 7 && p.Payload[7] == 0xa3 && p.Direction != "down" {
			t.Fatalf("information report direction=%q", p.Direction)
		}
	}
}
func TestValidateRejectsMMSConfig(t *testing.T) {
	p := Planner{}
	tests := []struct {
		name string
		spec core.FlowSpec
		want string
	}{
		{"transport", core.FlowSpec{MMS: &core.MMSConfig{Transport: "udp"}}, "transport"},
		{"name", core.FlowSpec{MMS: &core.MMSConfig{Objects: []core.MMSObjectConfig{{Name: strings.Repeat("x", 33), Datatype: "boolean"}}}}, "name"},
		{"datatype", core.FlowSpec{MMS: &core.MMSConfig{Objects: []core.MMSObjectConfig{{Name: "x", Datatype: "bad"}}}}, "datatype"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Validate(tc.spec); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("mms")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "mms" {
		t.Fatalf("name=%q", g.Name())
	}
}

func fmtHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2], out[i*2+1] = hexdigits[v>>4], hexdigits[v&15]
	}
	return string(out)
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config 默认化（association + read），Validate/Plan/Generate
	// 均产默认流。
	p := Planner{}
	if err := p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102}); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102})
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}

	var events []layers.MessageEvent
	err = (&MMSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 102},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}

func TestGeneratorMultiSessionExpansion(t *testing.T) {
	// case mms_multi_session: 2 concurrent associations on separate TCP
	// connections — session A carries SrcPort 40000, session B 40001;
	// interleaved phases: CR/CC ×2, associate pair ×2, services ×2 (mms
	// concurrent-session semantics; tcp layer keeps independent connections
	// per SrcPort, no teardown between phases).
	var events []layers.MessageEvent
	err := (&MMSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MMS: &core.MMSConfig{
			Objects:       []core.MMSObjectConfig{{Domain: "IED1", Name: "GGIO1.SPCSO1.stVal", Datatype: "boolean"}},
			EnableRead:    true,
			MultiSession:  []core.MMSConfig{{Objects: []core.MMSObjectConfig{{Domain: "IED2", Name: "MMXU1.TotW.mag.f", Datatype: "integer", Value: 5}}}},
			Sequence:      &core.MMSSequence{Steps: []string{"read"}},
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 12 { // 2 sessions × 6 events (CR,CC,Assoc,AssocResp,readReq,readResp)
		t.Fatalf("events=%d want 12", len(events))
	}
	// 交错序（tcp 层握手延迟到首事件，CR_B 触发 hsB 插在 CR_A 后）：
	// CR_A CR_B CC_A CC_B DT1_A DT1_B DT2_A DT2_B svcA req resp svcB req resp
	// （case 侧把 hsB 的 3 个握手包插在 4 与 8 之间，事件序即此）。会话 0
	// 不带 SrcPort 覆盖（默认流端口），会话 1 = 40001。
	wantSrc := []uint16{0, 40001, 0, 40001, 0, 40001, 0, 40001, 0, 0, 40001, 40001}
	wantDir := []bool{true, true, false, false, true, true, false, false, true, false, true, false}
	for i, ev := range events {
		if ev.SrcPort != wantSrc[i] {
			t.Fatalf("event %d SrcPort=%d want %d", i, ev.SrcPort, wantSrc[i])
		}
		if ev.Up != wantDir[i] {
			t.Fatalf("event %d Up=%v want %v", i, ev.Up, wantDir[i])
		}
	}
}
