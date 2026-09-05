package nmea

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func baseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "192.0.2.69", DstIP: "198.51.100.69",
		SrcPort: 40069, DstPort: 10110,
		NMEA: &core.NMEAConfig{
			Sessions: []core.NMEASession{{
				Events: []core.NMEAEvent{{
					Kind: "sentence", Talker: "GP", Type: "GGA",
					Fields: FixtureGGABaseline(),
				}},
			}},
		},
	}
}

func TestValidate_PositiveBaseline(t *testing.T) {
	if err := Validate(baseSpec()); err != nil {
		t.Fatalf("baseline spec must pass: %v", err)
	}
}

func TestValidate_BareNilConfig(t *testing.T) {
	if err := Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("bare nil NMEA config must pass: %v", err)
	}
}

func TestValidate_ProprietaryRequiresChecksum(t *testing.T) {
	no := false
	s := baseSpec()
	s.NMEA.Sessions[0].Events[0] = core.NMEAEvent{
		Kind: "sentence", Talker: "P", Type: "E", MfrID: "GRM",
		Checksum: &no,
		Fields:   []string{"15.0", "M", "20.0", "M", "25.0", "M"},
	}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("proprietary checksum=false must be rejected with 'checksum', got %v", err)
	}
	s.NMEA.Sessions[0].Events[0].Checksum = nil
	if err := Validate(s); err != nil {
		t.Errorf("proprietary with default checksum must pass: %v", err)
	}
}

func TestValidate_AllWireFaultsRejected(t *testing.T) {
	faults := []struct{ fault, anchor string }{
		{"missing_dollar", "dollar"}, {"missing_crlf", "crlf"},
		{"lf_only", "crlf"}, {"truncated_tcp", "truncat"},
		{"udp_truncated", "datagram"}, {"udp_cross_datagram", "datagram"},
		{"start_bang", "start"}, {"unknown_talker", "talker"},
		{"unknown_type", "type"}, {"talker_p_standard", "talker"},
		{"field_count_short", "field"}, {"field_count_extra", "field"},
		{"lat_over", "latitude"}, {"lon_over", "longitude"},
		{"minutes_over", "minute"}, {"direction_char", "direction"},
		{"time_out_of_range", "time"}, {"date_out_of_range", "date"},
		{"status_char", "status"}, {"gsa_mode_char", "mode"},
		{"gsa_fix_type", "fix"}, {"sentence_length", "length"},
		{"checksum_mismatch", "checksum"}, {"checksum_hex_width", "checksum"},
		{"proprietary_no_checksum", "checksum"},
		{"gsv_seq_correlation", "sequence"},
		{"carrier_layer_missing", "carrier"}, {"carrier_conflict", "carrier"},
		{"port_undeclared", "port"},
		{"address_family_mismatch", "family"}, {"propagation", "propagat"},
	}
	if len(faults) != 31 {
		t.Fatalf("must cover all 31 wire faults, got %d", len(faults))
	}
	for _, f := range faults {
		s := baseSpec()
		s.NMEA.WireFault = f.fault
		err := Validate(s)
		if err == nil {
			t.Errorf("wire_fault %q must be rejected", f.fault)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), f.anchor) {
			t.Errorf("wire_fault %q error %q missing anchor %q", f.fault, err.Error(), f.anchor)
		}
	}
}

func TestValidate_GSVSequence(t *testing.T) {
	mk := func(ev ...core.NMEAEvent) core.FlowSpec {
		s := baseSpec()
		s.NMEA.Sessions[0].Events = ev
		return s
	}
	gsv := func(total, msg string) core.NMEAEvent {
		return core.NMEAEvent{
			Kind: "sentence", Talker: "GP", Type: "GSV",
			Fields: []string{total, msg, "11", "04", "45", "190", "47"},
		}
	}
	// In-order sequence passes.
	if err := Validate(mk(gsv("3", "1"), gsv("3", "2"), gsv("3", "3"))); err != nil {
		t.Errorf("in-order GSV sequence must pass: %v", err)
	}
	// Jumped sequence fails.
	if err := Validate(mk(gsv("3", "1"), gsv("3", "3"))); err == nil ||
		!strings.Contains(err.Error(), "sequence") {
		t.Errorf("jumped GSV sequence must fail with 'sequence', got %v", err)
	}
	// Mixed total fails.
	if err := Validate(mk(gsv("3", "1"), gsv("2", "2"))); err == nil {
		t.Errorf("mixed-total GSV sequence must fail, got nil")
	}
}

func TestValidate_ValueDomains(t *testing.T) {
	s := baseSpec()
	// Invalid talker.
	s.NMEA.Sessions[0].Events[0].Talker = "ZZ"
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "talker") {
		t.Errorf("talker ZZ must fail with 'talker', got %v", err)
	}
	// Invalid type.
	s = baseSpec()
	s.NMEA.Sessions[0].Events[0].Type = "XYZ"
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "type") {
		t.Errorf("type XYZ must fail with 'type', got %v", err)
	}
	// Bad hemisphere.
	s = baseSpec()
	s.NMEA.Sessions[0].Events[0].Fields[2] = "X"
	if err := Validate(s); err == nil {
		t.Errorf("hemisphere X must fail, got nil")
	}
	// Latitude over range (90°30' > 90).
	s = baseSpec()
	s.NMEA.Sessions[0].Events[0].Fields[1] = "9030.0000"
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "latitude") {
		t.Errorf("lat 9030 must fail with 'latitude', got %v", err)
	}
	// Time out of range.
	s = baseSpec()
	s.NMEA.Sessions[0].Events[0].Fields[0] = "253519.00"
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "time") {
		t.Errorf("time 253519 must fail with 'time', got %v", err)
	}
	// Field count short (GGA needs 14).
	s = baseSpec()
	s.NMEA.Sessions[0].Events[0].Fields = FixtureGGABaseline()[:12]
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "field") {
		t.Errorf("short field count must fail with 'field', got %v", err)
	}
}
