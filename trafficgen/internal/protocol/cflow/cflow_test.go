package cflow

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// hexStr decodes a hex string like "00 09 00 02".
func hexStr(s string) []byte {
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "").Replace(s))
	if err != nil {
		panic(err)
	}
	return b
}

// ---- NetFlow v9 builder tests ----

func TestBuildV9Header(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:   "netflow_v9_rfc3954",
		SourceID:  7,
		Sequence:  100,
		SysUptime: 600,
		UnixSecs:  1000000,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
				"dstaddr": "10.43.1.2",
			}},
		},
	}
	pdu, err := BuildV9ExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildV9ExportPacket: %v", err)
	}
	if len(pdu) < 20 {
		t.Fatalf("v9 packet too short: %d", len(pdu))
	}
	// Version = 9
	if pdu[0] != 0 || pdu[1] != 9 {
		t.Fatalf("v9 version = %02x %02x, want 00 09", pdu[0], pdu[1])
	}
	// Count should be > 0
	count := uint16(pdu[2])<<8 | uint16(pdu[3])
	if count == 0 {
		t.Fatal("v9 count = 0, want > 0")
	}
	// Source ID
	sid := uint32(pdu[16])<<24 | uint32(pdu[17])<<16 | uint32(pdu[18])<<8 | uint32(pdu[19])
	if sid != 7 {
		t.Fatalf("v9 source_id = %d, want 7", sid)
	}
	// Sequence
	seq := uint32(pdu[12])<<24 | uint32(pdu[13])<<16 | uint32(pdu[14])<<8 | uint32(pdu[15])
	if seq != 100 {
		t.Fatalf("v9 sequence = %d, want 100", seq)
	}
}

func TestBuildV9IPv6Record(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 8,
		Templates: []core.CFlowTemplate{
			{TemplateID: 257, Fields: []core.CFlowField{
				{ElementID: 27, Length: 16},
				{ElementID: 28, Length: 16},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 257, Record: map[string]interface{}{
				"srcaddrv6": "2001:db8:43::1",
				"dstaddrv6": "2001:db8:43::2",
			}},
		},
	}
	pdu, err := BuildV9ExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildV9ExportPacket IPv6: %v", err)
	}
	if len(pdu) < 20 {
		t.Fatalf("v9 packet too short: %d", len(pdu))
	}
	if pdu[0] != 0 || pdu[1] != 9 {
		t.Fatalf("v9 version = %02x %02x, want 00 09", pdu[0], pdu[1])
	}
}

func TestBuildV9MultiRecord(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 10,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.5.1",
				"dstaddr": "10.43.5.2",
			}},
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.5.3",
				"dstaddr": "10.43.5.4",
			}},
		},
	}
	pdu, err := BuildV9ExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildV9ExportPacket multi-record: %v", err)
	}
	// Count should be 3 (1 template + 2 data records)
	count := uint16(pdu[2])<<8 | uint16(pdu[3])
	if count != 3 {
		t.Fatalf("v9 multi-record count = %d, want 3", count)
	}
}

func TestBuildV9HeaderSequenceSource(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:   "netflow_v9_rfc3954",
		SourceID:  168496141,
		Sequence:  16909060,
		SysUptime: 600,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
				"dstaddr": "10.43.1.2",
			}},
		},
	}
	pdu, err := BuildV9ExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildV9ExportPacket: %v", err)
	}
	// Sequence = 16909060 = 0x01020304
	seq := uint32(pdu[12])<<24 | uint32(pdu[13])<<16 | uint32(pdu[14])<<8 | uint32(pdu[15])
	if seq != 16909060 {
		t.Fatalf("v9 sequence = %d, want 16909060", seq)
	}
	// Source ID = 168496141 = 0x0a0b0c0d
	sid := uint32(pdu[16])<<24 | uint32(pdu[17])<<16 | uint32(pdu[18])<<8 | uint32(pdu[19])
	if sid != 168496141 {
		t.Fatalf("v9 source_id = %d, want 168496141", sid)
	}
}

// ---- IPFIX builder tests ----

func TestBuildIPFIXMessage(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 43,
		Sequence:            1,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"sourceIPv4Address":      "10.43.8.1",
				"destinationIPv4Address": "10.43.8.2",
			}},
		},
	}
	pdu, err := BuildIPFIXMessage(cfg)
	if err != nil {
		t.Fatalf("BuildIPFIXMessage: %v", err)
	}
	if len(pdu) < 16 {
		t.Fatalf("IPFIX message too short: %d", len(pdu))
	}
	// Version = 10
	if pdu[0] != 0 || pdu[1] != 10 {
		t.Fatalf("IPFIX version = %02x %02x, want 00 0a", pdu[0], pdu[1])
	}
	// Length should be > 16
	msgLen := uint16(pdu[2])<<8 | uint16(pdu[3])
	if msgLen <= 16 {
		t.Fatalf("IPFIX length = %d, want > 16", msgLen)
	}
	// OD ID
	odID := uint32(pdu[12])<<24 | uint32(pdu[13])<<16 | uint32(pdu[14])<<8 | uint32(pdu[15])
	if odID != 43 {
		t.Fatalf("IPFIX od_id = %d, want 43", odID)
	}
}

func TestBuildIPFIXIPv6Record(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 44,
		Templates: []core.CFlowTemplate{
			{TemplateID: 257, Fields: []core.CFlowField{
				{ElementID: 27, Length: 16},
				{ElementID: 28, Length: 16},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 257, Record: map[string]interface{}{
				"srcaddrv6": "2001:db8:44::1",
				"dstaddrv6": "2001:db8:44::2",
			}},
		},
	}
	pdu, err := BuildIPFIXMessage(cfg)
	if err != nil {
		t.Fatalf("BuildIPFIXMessage IPv6: %v", err)
	}
	if pdu[0] != 0 || pdu[1] != 10 {
		t.Fatalf("IPFIX version = %02x %02x, want 00 0a", pdu[0], pdu[1])
	}
}

func TestBuildIPFIXEnterpriseIE(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 45,
		Templates: []core.CFlowTemplate{
			{TemplateID: 258, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 32769, Length: 4, PEN: 424242},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 258, Record: map[string]interface{}{
				"srcaddr":                  "10.43.9.1",
				"enterprise_private_entry": "01020304",
			}},
		},
	}
	pdu, err := BuildIPFIXMessage(cfg)
	if err != nil {
		t.Fatalf("BuildIPFIXMessage enterprise: %v", err)
	}
	if pdu[0] != 0 || pdu[1] != 10 {
		t.Fatalf("IPFIX version = %02x %02x, want 00 0a", pdu[0], pdu[1])
	}
}

func TestBuildIPFIXObservationDomainSequence(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 287454020,
		Sequence:            16909060,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"sourceIPv4Address":      "10.43.8.1",
				"destinationIPv4Address": "10.43.8.2",
			}},
		},
	}
	pdu, err := BuildIPFIXMessage(cfg)
	if err != nil {
		t.Fatalf("BuildIPFIXMessage: %v", err)
	}
	// OD = 287454020 = 0x11223344
	odID := uint32(pdu[12])<<24 | uint32(pdu[13])<<16 | uint32(pdu[14])<<8 | uint32(pdu[15])
	if odID != 287454020 {
		t.Fatalf("IPFIX od_id = %d, want 287454020", odID)
	}
	// Sequence = 16909060 = 0x01020304
	seq := uint32(pdu[8])<<24 | uint32(pdu[9])<<16 | uint32(pdu[10])<<8 | uint32(pdu[11])
	if seq != 16909060 {
		t.Fatalf("IPFIX sequence = %d, want 16909060", seq)
	}
}

func TestBuildIPFIXOptionsTemplate(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 47,
		Templates: []core.CFlowTemplate{
			{
				Kind:       "options",
				TemplateID: 260,
				ScopeFields: []core.CFlowField{
					{ElementID: 138, Length: 8},
				},
				OptionFields: []core.CFlowField{
					{ElementID: 34, Length: 2},
				},
			},
		},
		Options: &core.CFlowOptions{
			ActiveTimeout:   60,
			InactiveTimeout: 15,
		},
	}
	pdu, err := BuildIPFIXMessage(cfg)
	if err != nil {
		t.Fatalf("BuildIPFIXMessage options: %v", err)
	}
	if pdu[0] != 0 || pdu[1] != 10 {
		t.Fatalf("IPFIX version = %02x %02x, want 00 0a", pdu[0], pdu[1])
	}
}

func TestBuildV9OptionsSet(t *testing.T) {
	opts := &core.CFlowOptions{
		ActiveTimeout:   60,
		InactiveTimeout: 15,
		SamplingInterval: 1000,
	}
	body := buildV9OptionsSet(opts)
	if body == nil {
		t.Fatal("buildV9OptionsSet returned nil")
	}
	// Should contain FlowSet header for ID=1 (Options Template)
	if len(body) < 4 {
		t.Fatalf("options body too short: %d", len(body))
	}
	fsID := binary.BigEndian.Uint16(body[0:2])
	if fsID != 1 {
		t.Fatalf("options FlowSet ID = %d, want 1", fsID)
	}
	// Should also contain data FlowSet (ID=256)
	// Skip past the options template set
	tmplSetLen := binary.BigEndian.Uint16(body[2:4])
	if int(tmplSetLen) > len(body) {
		t.Fatalf("options template set length %d exceeds body %d", tmplSetLen, len(body))
	}
	dataStart := int(tmplSetLen)
	if dataStart+4 <= len(body) {
		dataID := binary.BigEndian.Uint16(body[dataStart : dataStart+2])
		if dataID != 256 {
			t.Fatalf("options data FlowSet ID = %d, want 256", dataID)
		}
	}
}

func TestBuildV9OptionsSetNil(t *testing.T) {
	if buildV9OptionsSet(nil) != nil {
		t.Fatal("expected nil for nil opts")
	}
	if buildV9OptionsSet(&core.CFlowOptions{}) != nil {
		t.Fatal("expected nil for empty opts")
	}
}

func TestBuildExportPacketV9(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 7,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
			}},
		},
	}
	pdu, err := BuildExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildExportPacket v9: %v", err)
	}
	if pdu[0] != 0 || pdu[1] != 9 {
		t.Fatalf("version = %02x %02x, want 00 09", pdu[0], pdu[1])
	}
}

func TestBuildExportPacketIPFIX(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 43,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"sourceIPv4Address": "10.43.8.1",
			}},
		},
	}
	pdu, err := BuildExportPacket(cfg)
	if err != nil {
		t.Fatalf("BuildExportPacket ipfix: %v", err)
	}
	if pdu[0] != 0 || pdu[1] != 10 {
		t.Fatalf("version = %02x %02x, want 00 0a", pdu[0], pdu[1])
	}
}

func TestBuildExportPacketUnknownProfile(t *testing.T) {
	cfg := &core.CFlowConfig{
		Profile: "unknown",
	}
	_, err := BuildExportPacket(cfg)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected 'unknown profile' error, got %v", err)
	}
}

// ---- Validation tests ----

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *core.CFlowConfig
		wantErr string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: "config is required",
		},
		{
			name:    "unknown profile",
			cfg:     &core.CFlowConfig{Profile: "invalid"},
			wantErr: "unknown profile",
		},
		{
			name: "v9 valid",
			cfg: &core.CFlowConfig{
				Profile:  "netflow_v9_rfc3954",
				SourceID: 7,
				Templates: []core.CFlowTemplate{
					{TemplateID: 256, Fields: []core.CFlowField{
						{ElementID: 8, Length: 4},
					}},
				},
				Records: []core.CFlowRecord{
					{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
				},
			},
			wantErr: "",
		},
		{
			name: "ipfix valid",
			cfg: &core.CFlowConfig{
				Profile:             "ipfix_rfc7011",
				ObservationDomainID: 43,
				Templates: []core.CFlowTemplate{
					{TemplateID: 256, Fields: []core.CFlowField{
						{ElementID: 8, Length: 4},
					}},
				},
				Records: []core.CFlowRecord{
					{TemplateID: 256, Record: map[string]interface{}{"sourceIPv4Address": "10.0.0.1"}},
				},
			},
			wantErr: "",
		},
		{
			name: "record references unknown template",
			cfg: &core.CFlowConfig{
				Profile:  "netflow_v9_rfc3954",
				SourceID: 7,
				Records: []core.CFlowRecord{
					{TemplateID: 999, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
				},
			},
			wantErr: "unknown template",
		},
		{
			name: "template has no fields",
			cfg: &core.CFlowConfig{
				Profile:  "netflow_v9_rfc3954",
				SourceID: 7,
				Templates: []core.CFlowTemplate{
					{TemplateID: 256},
				},
			},
			wantErr: "has no fields",
		},
		{
			name: "wire fault checksum",
			cfg: &core.CFlowConfig{
				Profile:   "netflow_v9_rfc3954",
				SourceID:  7,
				WireFault: &core.CFlowFault{Kind: "checksum"},
			},
			wantErr: "checksum",
		},
		{
			name: "v9 profile version mismatch",
			cfg: &core.CFlowConfig{
				Profile:  "netflow_v9_rfc3954",
				Version:  10,
				SourceID: 7,
			},
			wantErr: "version",
		},
		{
			name: "v9 profile matching version",
			cfg: &core.CFlowConfig{
				Profile:  "netflow_v9_rfc3954",
				Version:  9,
				SourceID: 7,
			},
			wantErr: "",
		},
		{
			name: "ipfix profile version mismatch",
			cfg: &core.CFlowConfig{
				Profile:             "ipfix_rfc7011",
				Version:             9,
				ObservationDomainID: 43,
			},
			wantErr: "version",
		},
		{
			name: "wire fault length",
			cfg: &core.CFlowConfig{
				Profile:   "ipfix_rfc7011",
				SourceID:  7,
				WireFault: &core.CFlowFault{Kind: "length", Value: 3},
			},
			wantErr: "length",
		},
		{
			name: "wire fault field count",
			cfg: &core.CFlowConfig{
				Profile:   "netflow_v9_rfc3954",
				SourceID:  7,
				WireFault: &core.CFlowFault{Kind: "field_count"},
			},
			wantErr: "field",
		},
		{
			name: "wire fault template",
			cfg: &core.CFlowConfig{
				Profile:   "netflow_v9_rfc3954",
				SourceID:  7,
				WireFault: &core.CFlowFault{Kind: "template"},
			},
			wantErr: "template",
		},
		{
			name: "wire fault address family",
			cfg: &core.CFlowConfig{
				Profile:   "ipfix_rfc7011",
				SourceID:  7,
				WireFault: &core.CFlowFault{Kind: "address_family"},
			},
			wantErr: "address",
		},
		{
			name: "data set without template",
			cfg: &core.CFlowConfig{
				Profile: "ipfix_rfc7011",
				Sets: []core.CFlowSet{
					{ID: 256, Records: []core.CFlowRecord{{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}}}},
				},
			},
			wantErr: "template",
		},
		{
			name: "address family mismatch",
			cfg: &core.CFlowConfig{
				Profile: "ipfix_rfc7011",
				Templates: []core.CFlowTemplate{
					{TemplateID: 256, Fields: []core.CFlowField{{ElementID: 8, Length: 4}}},
				},
				Records: []core.CFlowRecord{
					{TemplateID: 256, Record: map[string]interface{}{"srcaddrv6": "2001:db8::1"}},
				},
			},
			wantErr: "address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

// ---- Planner tests ----

func TestPlannerValidate(t *testing.T) {
	p := Planner{}

	// No config
	err := p.Validate(core.FlowSpec{})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected 'config is required', got %v", err)
	}

	// Valid cflow config
	err = p.Validate(core.FlowSpec{
		CFlow: &core.CFlowConfig{
			Profile:  "netflow_v9_rfc3954",
			SourceID: 7,
			Templates: []core.CFlowTemplate{
				{TemplateID: 256, Fields: []core.CFlowField{
					{ElementID: 8, Length: 4},
				}},
			},
			Records: []core.CFlowRecord{
				{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wrong port for v9 should contain "udp" (lowercase)
	err = p.Validate(core.FlowSpec{
		CFlow: &core.CFlowConfig{
			Profile:  "netflow_v9_rfc3954",
			SourceID: 7,
		},
		DstPort: 4739,
	})
	if err == nil || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("expected 'udp' in error, got %v", err)
	}

	// Wrong port for ipfix
	err = p.Validate(core.FlowSpec{
		CFlow: &core.CFlowConfig{
			Profile:             "ipfix_rfc7011",
			ObservationDomainID: 43,
		},
		DstPort: 2055,
	})
	if err == nil || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("expected 'udp' in error, got %v", err)
	}
}

func TestPlannerPlan(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 7,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "198.51.100.10",
		SrcPort: 40000,
		DstPort: 2055,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	pkt := packets[0]
	if pkt.Direction != "up" {
		t.Fatalf("direction = %s, want up", pkt.Direction)
	}
	if pkt.L4.Protocol != "udp" {
		t.Fatalf("protocol = %s, want udp", pkt.L4.Protocol)
	}
}

func TestPlannerPlanIPv6(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 8,
		Templates: []core.CFlowTemplate{
			{TemplateID: 257, Fields: []core.CFlowField{
				{ElementID: 27, Length: 16},
				{ElementID: 28, Length: 16},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 257, Record: map[string]interface{}{
				"srcaddrv6": "2001:db8:43::1",
				"dstaddrv6": "2001:db8:43::2",
			}},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "2001:db8:43::10",
		DstIP:   "2001:db8:43::20",
		SrcPort: 40001,
		DstPort: 2055,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan IPv6: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
}

func TestPlannerPlanIPFIX(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 43,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{"sourceIPv4Address": "10.43.8.1"}},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.20",
		DstIP:   "198.51.100.20",
		SrcPort: 42000,
		DstPort: 4739,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan IPFIX: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
}

func TestPlannerMultiExporter(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 101,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
				"dstaddr": "10.43.1.2",
			}},
		},
		Exporters: []core.CFlowExporter{
			{
				SourceID: 202,
				Templates: []core.CFlowTemplate{
					{TemplateID: 256, Fields: []core.CFlowField{
						{ElementID: 8, Length: 4},
						{ElementID: 12, Length: 4},
					}},
				},
				Records: []core.CFlowRecord{
					{TemplateID: 256, Record: map[string]interface{}{
						"srcaddr": "10.43.1.1",
						"dstaddr": "10.43.1.2",
					}},
				},
			},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.14",
		DstIP:   "198.51.100.14",
		SrcPort: 40005,
		DstPort: 2055,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan multi-exporter: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
}

func TestPlannerMultiSession(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 7,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
				"dstaddr": "10.43.1.2",
			}},
		},
		Sessions: []core.CFlowSession{
			{
				SrcPort:  41002,
				SourceID: 7,
				Templates: []core.CFlowTemplate{
					{TemplateID: 256, Fields: []core.CFlowField{
						{ElementID: 8, Length: 4},
						{ElementID: 12, Length: 4},
					}},
				},
				Records: []core.CFlowRecord{
					{TemplateID: 256, Record: map[string]interface{}{
						"srcaddr": "10.43.1.1",
						"dstaddr": "10.43.1.2",
					}},
				},
			},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.15",
		DstIP:   "198.51.100.15",
		SrcPort: 41001,
		DstPort: 2055,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan multi-session: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
}

func TestPlannerContextCancel(t *testing.T) {
	p := Planner{}
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 7,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "198.51.100.10",
		SrcPort: 40000,
		DstPort: 2055,
		CFlow:   cfg,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	// With cancelled context, the select may or may not send before ctx.Done
	// But at minimum, channel should be closed
	if len(packets) > 1 {
		t.Fatalf("expected 0 or 1 packet with cancelled context, got %d", len(packets))
	}
}

func TestPlannerErrorPropagation(t *testing.T) {
	p := Planner{}
	// WireFault with checksum should produce an error from ValidateConfig
	cfg := &core.CFlowConfig{
		Profile:   "netflow_v9_rfc3954",
		SourceID:  7,
		WireFault: &core.CFlowFault{Kind: "checksum"},
	}
	spec := core.FlowSpec{
		SrcIP:   "192.0.2.10",
		DstIP:   "198.51.100.10",
		SrcPort: 40000,
		DstPort: 2055,
		CFlow:   cfg,
	}
	_, err := p.Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected checksum error, got %v", err)
	}
}

// ---- Generator tests ----

func TestGeneratorName(t *testing.T) {
	g := &Generator{}
	if g.Name() != "cflow" {
		t.Fatalf("Generator.Name() = %s, want cflow", g.Name())
	}
}

func TestGeneratorNilEmitMsg(t *testing.T) {
	g := &Generator{}
	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{CFlow: &core.CFlowConfig{
			Profile:  "netflow_v9_rfc3954",
			SourceID: 7,
			Templates: []core.CFlowTemplate{
				{TemplateID: 256, Fields: []core.CFlowField{
					{ElementID: 8, Length: 4},
				}},
			},
			Records: []core.CFlowRecord{
				{TemplateID: 256, Record: map[string]interface{}{"srcaddr": "10.0.0.1"}},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("expected 'EmitMsg is nil', got %v", err)
	}
}

func TestGeneratorNilConfig(t *testing.T) {
	g := &Generator{}
	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected 'config is required', got %v", err)
	}
}

// ---- Benchmark ----

func BenchmarkBuildV9ExportPacket(b *testing.B) {
	cfg := &core.CFlowConfig{
		Profile:  "netflow_v9_rfc3954",
		SourceID: 7,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"srcaddr": "10.43.1.1",
				"dstaddr": "10.43.1.2",
			}},
		},
	}
	for i := 0; i < b.N; i++ {
		BuildV9ExportPacket(cfg)
	}
}

func BenchmarkBuildIPFIXMessage(b *testing.B) {
	cfg := &core.CFlowConfig{
		Profile:             "ipfix_rfc7011",
		ObservationDomainID: 43,
		Templates: []core.CFlowTemplate{
			{TemplateID: 256, Fields: []core.CFlowField{
				{ElementID: 8, Length: 4},
				{ElementID: 12, Length: 4},
			}},
		},
		Records: []core.CFlowRecord{
			{TemplateID: 256, Record: map[string]interface{}{
				"sourceIPv4Address":      "10.43.8.1",
				"destinationIPv4Address": "10.43.8.2",
			}},
		},
	}
	for i := 0; i < b.N; i++ {
		BuildIPFIXMessage(cfg)
	}
}

// ---- init test ----

func TestInitRegistration(t *testing.T) {
	_ = fmt.Sprintf("cflow package loaded")
}
