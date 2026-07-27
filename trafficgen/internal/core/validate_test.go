package core

import (
	"strings"
	"testing"
)

// TestValidateProtocolSubConfigs_MSS_AllProtocols verifies the H2.10 fix:
// MSS range validation (0 or 536-65535) must apply to ALL TCP-based
// protocols, not just protocol="tcp". Previously the http/ftp/sip cases
// in ValidateProtocolSubConfigs had only comments saying MSS was "governed
// by tcp.mss", but the http/ftp/sip branches never executed the check, so
// protocol=http + tcp.mss=70000 silently wrapped to 4464 (uint16 cast) and
// passed validation. This is the failing-test-first regression guard.
func TestValidateProtocolSubConfigs_MSS_AllProtocols(t *testing.T) {
	// Note: cfg["tcp"].mss uses float64 because production cfg comes from
	// JSON unmarshal (encoding/json always emits float64 for numbers).
	// getInt() handles float64 and json.Number; passing int directly would
	// hit the default branch and silently return 0 (an unrelated quirk
	// already documented in strategy_convert.go:903).
	cases := []struct {
		name     string
		protocol string
		cfg      map[string]interface{}
		wantErr  bool
		wantMsg  string
	}{
		{
			name:     "http/mss=70000 out of range",
			protocol: "http",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(70000)}},
			wantErr:  true,
			wantMsg:  "tcp.mss",
		},
		{
			name:     "http/mss=-1 out of range",
			protocol: "http",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(-1)}},
			wantErr:  true,
			wantMsg:  "tcp.mss",
		},
		{
			name:     "http/mss=1460 valid",
			protocol: "http",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(1460)}},
			wantErr:  false,
		},
		{
			name:     "http/mss=0 ok (default)",
			protocol: "http",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(0)}},
			wantErr:  false,
		},
		{
			name:     "ftp/mss=70000 out of range",
			protocol: "ftp",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(70000)}},
			wantErr:  true,
			wantMsg:  "tcp.mss",
		},
		{
			name:     "ftp/mss=1460 valid",
			protocol: "ftp",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(1460)}},
			wantErr:  false,
		},
		{
			name:     "sip/mss=70000 out of range",
			protocol: "sip",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(70000)}},
			wantErr:  true,
			wantMsg:  "tcp.mss",
		},
		{
			name:     "sip/mss=536 min valid",
			protocol: "sip",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(536)}},
			wantErr:  false,
		},
		{
			name:     "tcp/mss=70000 still rejected (regression guard for tcp case)",
			protocol: "tcp",
			cfg:      map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(70000)}},
			wantErr:  true,
			wantMsg:  "tcp.mss",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(tt.cfg, tt.protocol)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateProtocolSubConfigs(%s) expected error, got nil", tt.protocol)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateProtocolSubConfigs(%s) unexpected error: %v", tt.protocol, err)
			}
			if tt.wantMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

// TestValidateFlowSpec_Ranges
func TestValidateFlowSpec_Ranges(t *testing.T) {
	tests := []struct {
		name    string
		spec    FlowSpec
		wantErr bool
	}{
		{
			name:    "empty spec ok (defaults)",
			spec:    FlowSpec{},
			wantErr: false,
		},
		{
			name:    "vlan id too large",
			spec:    FlowSpec{VLAN: &VLAN{ID: 5000}},
			wantErr: true,
		},
		{
			name:    "vlan id max valid (4095)",
			spec:    FlowSpec{VLAN: &VLAN{ID: 4095}},
			wantErr: false,
		},
		{
			name:    "vlan priority too large",
			spec:    FlowSpec{VLAN: &VLAN{ID: 100, Priority: 9}},
			wantErr: true,
		},
		{
			name:    "vlan priority max valid (7)",
			spec:    FlowSpec{VLAN: &VLAN{ID: 100, Priority: 7}},
			wantErr: false,
		},
		{
			name:    "dscp too large",
			spec:    FlowSpec{DSCP: 70},
			wantErr: true,
		},
		{
			name:    "dscp max valid (63)",
			spec:    FlowSpec{DSCP: 63},
			wantErr: false,
		},
		{
			name:    "ecn too large",
			spec:    FlowSpec{ECN: 4},
			wantErr: true,
		},
		{
			name:    "mss too small",
			spec:    FlowSpec{TCP: &TCPConfig{MSS: 100}},
			wantErr: true,
		},
		{
			name:    "mss zero ok (default)",
			spec:    FlowSpec{TCP: &TCPConfig{MSS: 0}},
			wantErr: false,
		},
		{
			name:    "mss min valid (536)",
			spec:    FlowSpec{TCP: &TCPConfig{MSS: 536}},
			wantErr: false,
		},
		{
			name: "valid full spec",
			spec: FlowSpec{
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				VLAN: &VLAN{ID: 100, Priority: 3},
				DSCP: 46, ECN: 1, TTL: 64,
				TCP: &TCPConfig{MSS: 1460},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlowSpec(tt.spec)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateFlowSpec() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateFlowSpec() unexpected error: %v", err)
			}
		})
	}
}
