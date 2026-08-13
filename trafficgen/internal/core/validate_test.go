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

// TestValidateProtocolSubConfigs_DNP3_IINRange covers design §7.6.2 T55:
// IIN is a uint16 field; parseDNP3Config's getUint16 silently truncates
// out-of-range values (0x10000 -> 0), so a config carrying dnp3.iin=65536
// would previously pass validation and complete the task with IIN=0x0000 on
// the wire. ValidateProtocolSubConfigs must reject before conversion.
func TestValidateProtocolSubConfigs_DNP3_IINRange(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		wantErr bool
		wantMsg string
	}{
		{
			name:    "iin=65536 out of uint16 range",
			cfg:     map[string]interface{}{"dnp3": map[string]interface{}{"iin": float64(65536)}},
			wantErr: true,
			wantMsg: "iin",
		},
		{
			name:    "iin=0x10000 (65536) negative-free boundary",
			cfg:     map[string]interface{}{"dnp3": map[string]interface{}{"iin": float64(0x10000)}},
			wantErr: true,
			wantMsg: "iin",
		},
		{
			name:    "iin=65535 max valid",
			cfg:     map[string]interface{}{"dnp3": map[string]interface{}{"iin": float64(65535)}},
			wantErr: false,
		},
		{
			name:    "iin=0 default valid",
			cfg:     map[string]interface{}{"dnp3": map[string]interface{}{"iin": float64(0)}},
			wantErr: false,
		},
		{
			name:    "negative iin invalid",
			cfg:     map[string]interface{}{"dnp3": map[string]interface{}{"iin": float64(-1)}},
			wantErr: true,
			wantMsg: "iin",
		},
		{
			name:    "no dnp3 sub-config ok",
			cfg:     map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(1460)}},
			wantErr: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(tt.cfg, "dnp3")
			if tt.wantErr && err == nil {
				t.Errorf("ValidateProtocolSubConfigs(dnp3) expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateProtocolSubConfigs(dnp3) unexpected error: %v", err)
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

// TestValidateProtocolSubConfigs_TFTP_Ranges covers the pre-conversion
// range checks added to ValidateProtocolSubConfigs for the tftp case.
// These checks exist because parseTFTPConfig's getUint16 silently truncates
// out-of-range values (e.g. blksize=70000 -> 0x1170? no: 70000&0xFFFF), so
// an out-of-range config would pass validation and produce wrong options on
// the wire (RFC 2348 blksize 8-65464, RFC 2349 timeout 1-255).
func TestValidateProtocolSubConfigs_TFTP_Ranges(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		wantErr bool
		wantMsg string
	}{
		{
			name:    "mode bogus invalid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"mode": "fetch"}},
			wantErr: true,
			wantMsg: "tftp.mode",
		},
		{
			name:    "mode read valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"mode": "READ"}},
			wantErr: false,
		},
		{
			name:    "mode empty ok (default read)",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"mode": ""}},
			wantErr: false,
		},
		{
			name:    "transfer_mode mail deprecated",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"transfer_mode": "mail"}},
			wantErr: true,
			wantMsg: "deprecated",
		},
		{
			name:    "transfer_mode octet valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"transfer_mode": "octet"}},
			wantErr: false,
		},
		{
			name:    "error_side bogus invalid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"error_side": "peer"}},
			wantErr: true,
			wantMsg: "tftp.error_side",
		},
		{
			name:    "blksize 70000 out of range (RFC 2348 max 65464)",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"blksize": float64(70000)}},
			wantErr: true,
			wantMsg: "blksize",
		},
		{
			name:    "blksize 7 below RFC 2348 min 8",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"blksize": float64(7)}},
			wantErr: true,
			wantMsg: "blksize",
		},
		{
			name:    "blksize 65464 max valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"blksize": float64(65464)}},
			wantErr: false,
		},
		{
			name:    "blksize 0 ok (do not send)",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"blksize": float64(0)}},
			wantErr: false,
		},
		{
			name:    "timeout 300 out of range (RFC 2349 max 255)",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"timeout": float64(300)}},
			wantErr: true,
			wantMsg: "timeout",
		},
		{
			name:    "timeout 255 max valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"timeout": float64(255)}},
			wantErr: false,
		},
		{
			name:    "windowsize 70000 out of range",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"windowsize": float64(70000)}},
			wantErr: true,
			wantMsg: "windowsize",
		},
		{
			name:    "error_code 9 invalid (0-8)",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"error_code": float64(9)}},
			wantErr: true,
			wantMsg: "error_code",
		},
		{
			name:    "error_code 8 max valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"error_code": float64(8)}},
			wantErr: false,
		},
		{
			name:    "server_tid 512 in well-known range",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"server_tid": float64(512)}},
			wantErr: true,
			wantMsg: "well-known",
		},
		{
			name:    "server_tid 1024 valid",
			cfg:     map[string]interface{}{"tftp": map[string]interface{}{"server_tid": float64(1024)}},
			wantErr: false,
		},
		{
			name:    "no tftp sub-config ok",
			cfg:     map[string]interface{}{"udp": map[string]interface{}{"src_port": float64(69)}},
			wantErr: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(tt.cfg, "tftp")
			if tt.wantErr && err == nil {
				t.Errorf("ValidateProtocolSubConfigs(tftp) expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateProtocolSubConfigs(tftp) unexpected error: %v", err)
			}
			if tt.wantMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

// TestValidateProtocolSubConfigs_ENIP_EPATHRanges covers the pre-conversion
// range checks for enip class_id (uint16) and instance_id (uint32) inside
// the commands array. parseENIPCommands uses getUint16/getUint32 which
// silently truncate out-of-range values (0x10000 -> 0), so the ENIP EPATH
// would encode the wrong class/instance on the wire (design §7.3 T-104/105).
func TestValidateProtocolSubConfigs_ENIP_EPATHRanges(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		wantErr bool
		wantMsg string
	}{
		{
			name: "class_id 65536 out of uint16 range",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"commands": []interface{}{
					map[string]interface{}{"class_id": float64(65536)},
				},
			}},
			wantErr: true,
			wantMsg: "class_id",
		},
		{
			name: "instance_id 4294967296 out of uint32 range",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"commands": []interface{}{
					map[string]interface{}{"instance_id": float64(4294967296)},
				},
			}},
			wantErr: true,
			wantMsg: "instance_id",
		},
		{
			name: "class_id 65535 + instance_id 4294967295 max valid",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"commands": []interface{}{
					map[string]interface{}{
						"class_id":    float64(65535),
						"instance_id": float64(4294967295),
					},
				},
			}},
			wantErr: false,
		},
		{
			name: "empty commands ok",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"commands": []interface{}{},
			}},
			wantErr: false,
		},
		{
			name:    "no enip sub-config ok",
			cfg:     map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(1460)}},
			wantErr: false,
		},
		{
			name: "negative class_id invalid",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"commands": []interface{}{
					map[string]interface{}{"class_id": float64(-1)},
				},
			}},
			wantErr: true,
			wantMsg: "class_id",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(tt.cfg, "enip")
			if tt.wantErr && err == nil {
				t.Errorf("ValidateProtocolSubConfigs(enip) expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateProtocolSubConfigs(enip) unexpected error: %v", err)
			}
			if tt.wantMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

// TestValidateProtocolSubConfigs_TFTP_NegativeErrorCode covers the negative
// bound of tftp.error_code (0-8). A negative value would be wrapped by the
// uint8 cast in parseTFTPConfig (e.g. -1 -> 255), which then triggers the
// planner's range check at plan time — but the pre-conversion layer must
// reject it directly, consistent with the other out-of-range fields.
func TestValidateProtocolSubConfigs_TFTP_NegativeErrorCode(t *testing.T) {
	err := ValidateProtocolSubConfigs(map[string]interface{}{
		"tftp": map[string]interface{}{"error_code": float64(-1)},
	}, "tftp")
	if err == nil {
		t.Fatalf("ValidateProtocolSubConfigs(tftp) error_code=-1: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "error_code") {
		t.Errorf("error %q does not mention error_code", err.Error())
	}
}

// TestValidateProtocolSubConfigs_ENIP_SubRequestEPATH covers the class_id /
// instance_id range checks inside the sub_requests array (the
// Multiple_Service_Packet path). parseENIPSubRequests truncates out-of-range
// values just like parseENIPCommands, so the validator must reject them
// before conversion (design §7.3 T-104/105).
func TestValidateProtocolSubConfigs_ENIP_SubRequestEPATH(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		wantErr bool
		wantMsg string
	}{
		{
			name: "sub_request class_id 65536 out of uint16 range",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"sub_requests": []interface{}{
					map[string]interface{}{"class_id": float64(65536)},
				},
			}},
			wantErr: true,
			wantMsg: "sub_requests[0].class_id",
		},
		{
			name: "sub_request instance_id 4294967296 out of uint32 range",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"sub_requests": []interface{}{
					map[string]interface{}{"instance_id": float64(4294967296)},
				},
			}},
			wantErr: true,
			wantMsg: "sub_requests[0].instance_id",
		},
		{
			name: "sub_request max valid values",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"sub_requests": []interface{}{
					map[string]interface{}{
						"class_id":    float64(65535),
						"instance_id": float64(4294967295),
					},
				},
			}},
			wantErr: false,
		},
		{
			name: "empty sub_requests ok",
			cfg: map[string]interface{}{"enip": map[string]interface{}{
				"sub_requests": []interface{}{},
			}},
			wantErr: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(tt.cfg, "enip")
			if tt.wantErr && err == nil {
				t.Errorf("ValidateProtocolSubConfigs(enip) expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateProtocolSubConfigs(enip) unexpected error: %v", err)
			}
			if tt.wantMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}
