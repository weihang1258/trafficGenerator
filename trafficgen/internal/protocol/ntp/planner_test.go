package ntp

// Unit tests for NTP planner. Focused on Validate behavior and basic Plan
// happy path. Atomic test points derived from testcases_ntp.md live in
// planner_testpoints_test.go per CLAUDE.md testing policy.

import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "ntp" {
		t.Errorf("Name() = %q, want %q", got, "ntp")
	}
}

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name: "valid client spec",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP: &core.NTPConfig{
					Mode:    ModeClient,
					Version: 4,
				},
			},
			wantErr: false,
		},
		{
			name: "valid server spec",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 123,
				DstPort: 12345,
				NTP: &core.NTPConfig{
					Mode:    ModeServer,
					Version: 4,
					Stratum: 2,
				},
			},
			wantErr: false,
		},
		{
			name: "missing NTP config",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
			},
			wantErr: true,
		},
		{
			name: "invalid source IP",
			spec: core.FlowSpec{
				SrcIP:   "not-an-ip",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeClient},
			},
			wantErr: true,
		},
		{
			name: "invalid destination IP",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "999.999.999.999",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeServer},
			},
			wantErr: true,
		},
		{
			name: "invalid mode (8 > 7)",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: 8},
			},
			wantErr: true,
		},
		{
			name: "reserved mode 0",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeReserved},
			},
			wantErr: true,
		},
		{
			name: "invalid version 5",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeClient, Version: 5},
			},
			wantErr: true,
		},
		{
			name: "invalid version 0",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeServer, Version: 0},
			},
			wantErr: true,
		},
		{
			name: "invalid stratum 17",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeServer, Stratum: 17},
			},
			wantErr: true,
		},
		{
			name: "invalid LI 4",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeClient, LeapIndicator: 4},
			},
			wantErr: true,
		},
		{
			name: "MAC length 15 invalid",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP: &core.NTPConfig{
					Mode: ModeClient,
					MAC:  make([]byte, 15),
				},
			},
			wantErr: true,
		},
		{
			name: "MAC length 16 valid",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP: &core.NTPConfig{
					Mode:    ModeClient,
					Version: 4,
					MAC:     make([]byte, 16),
				},
			},
			wantErr: false,
		},
		{
			name: "control data too large",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 123,
				NTP: &core.NTPConfig{
					Mode:        ModeControl,
					Sequence:    1,
					RequestCode: 1,
					ControlData: make([]byte, 469),
				},
			},
			wantErr: true,
		},
		{
			name: "IPv6 addresses accepted",
			spec: core.FlowSpec{
				SrcIP:   "2001:db8::1",
				DstIP:   "2001:db8::2",
				SrcPort: 12345,
				DstPort: 123,
				NTP:     &core.NTPConfig{Mode: ModeClient, Version: 4},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNTPValidate_Idempotent checks that Validate is read-only (pass-by-value
// preserves caller spec per CLAUDE.md testing policy §1.1).
func TestNTPValidate_Idempotent(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 123,
		NTP: &core.NTPConfig{Mode: ModeClient, Version: 4},
	}
	originalPort := spec.DstPort

	err1 := p.Validate(spec)
	err2 := p.Validate(spec)

	if err1 != nil || err2 != nil {
		t.Fatalf("expected nil errors, got %v / %v", err1, err2)
	}
	if spec.DstPort != originalPort {
		t.Errorf("DstPort mutated: %d -> %d", originalPort, spec.DstPort)
	}
}

func TestPlanner_Plan(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 123,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		NTP: &core.NTPConfig{
			Mode:    ModeClient,
			Version: 4,
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Default client mode without IsResponse emits exactly 1 request packet.
	if len(configs) != 1 {
		t.Fatalf("Expected 1 config, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol = %q, want %q", cfg.L4.Protocol, "udp")
	}
	if cfg.L4.DstPort != 123 {
		t.Errorf("L4.DstPort = %d, want 123", cfg.L4.DstPort)
	}
	if cfg.L2.EtherType != 0x0800 {
		t.Errorf("EtherType = 0x%04x, want 0x0800", cfg.L2.EtherType)
	}
	if cfg.Direction != "up" {
		t.Errorf("Direction = %q, want %q", cfg.Direction, "up")
	}
	// Payload must be the 48-byte NTP basic header.
	if len(cfg.Payload) != NTPHeaderLen {
		t.Errorf("Payload len = %d, want %d (NTPHeaderLen)", len(cfg.Payload), NTPHeaderLen)
	}
}

func TestPlanner_PlanWithResponse(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 123,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		NTP: &core.NTPConfig{
			Mode:       ModeClient,
			Version:    4,
			IsResponse: true,
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Mode=3 + IsResponse=true: emit 1 request (up) + 1 response (down).
	if len(configs) != 2 {
		t.Fatalf("Expected 2 configs (request+response), got %d", len(configs))
	}
	if configs[0].Direction != "up" {
		t.Errorf("first packet direction = %q, want %q", configs[0].Direction, "up")
	}
	if configs[1].Direction != "down" {
		t.Errorf("second packet direction = %q, want %q", configs[1].Direction, "down")
	}
	// Response must echo the request's Transmit as the Origin timestamp.
	requestTx := configs[0].Payload[40:48]
	responseOrigin := configs[1].Payload[24:32]
	if string(requestTx) != string(responseOrigin) {
		t.Errorf("response OriginTS (byte[24:32]) does not match request TransmitTS (byte[40:48])")
	}
}

func TestPlanner_PlanServer(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 123,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		NTP: &core.NTPConfig{
			Mode:    ModeServer,
			Version: 4,
			Stratum: 2,
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	if len(configs) != 1 {
		t.Fatalf("Expected 1 server response, got %d", len(configs))
	}
	// Server mode: byte 0 has Mode=4 in the bottom 3 bits (0x04).
	if configs[0].Payload[0]&0x07 != ModeServer {
		t.Errorf("Payload[0] mode bits = %d, want %d (ModeServer)", configs[0].Payload[0]&0x07, ModeServer)
	}
}

// TestBuildNTPPacket_Version3VN3Bitness checks that Version=3, Mode=3
// produces byte[0] = (LI<<6)|(3<<3)|3 = 0x1B for LI=0.
func TestBuildNTPPacket_Version3VN3Bitness(t *testing.T) {
	cfg := &core.NTPConfig{
		LeapIndicator: 0,
		Version:       3,
		Mode:          ModeClient,
	}
	buf := buildClientRequestForTest(cfg)
	want := byte(0)<<6 | 3<<3 | ModeClient
	if buf[0] != want {
		t.Errorf("byte[0] = 0x%02x, want 0x%02x", buf[0], want)
	}
}

// buildClientRequestForTest is a tiny helper for test-time header building
// without timing dependency (transmitTS=zero).
func buildClientRequestForTest(cfg *core.NTPConfig) []byte {
	return buildNTPPacket(cfg, cfg.RefTimestamp, cfg.OriginTS, cfg.ReceiveTS, cfg.TransmitTS)
}

func TestSecondsToFixed16_16(t *testing.T) {
	tests := []struct {
		name   string
		sec    float64
		want   uint32
	}{
		{"zero", 0.0, 0x00000000},
		{"1.0 sec", 1.0, 0x00010000},
		{"0.5 sec", 0.5, 0x00008000},
		{"2.0 sec", 2.0, 0x00020000},
		{"negative clamped", -1.0, 0x00000000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secondsToFixed16_16(tt.sec)
			// Allow small rounding differences in the fraction.
			high := got & 0xFFFF0000
			if high != tt.want&0xFFFF0000 {
				t.Errorf("secondsToFixed16_16(%v) high16 = 0x%04x, want 0x%04x",
					tt.sec, high>>16, tt.want>>16)
			}
		})
	}
}

func TestTimeToNTPTimestamp(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
		want uint64
	}{
		{"zero time", time.Time{}, 0},
	}
	_ = tests
	// NTP epoch: 1900-01-01 00:00:00 UTC -> 0
	epoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := timeToNTPTimestamp(epoch); got != 0 {
		t.Errorf("1900-01-01 epoch -> 0x%016x, want 0", got)
	}
	// 1970-01-01 UTC -> NTPEpochOffset seconds (0x83AA7E80)
	unixEpoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	got := timeToNTPTimestamp(unixEpoch)
	wantSecs := uint64(NTPEpochOffset)
	if got>>32 != wantSecs {
		t.Errorf("1970 epoch seconds field = %d, want %d", got>>32, wantSecs)
	}
}
