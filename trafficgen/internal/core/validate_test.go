package core

import (
	"testing"
)

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
