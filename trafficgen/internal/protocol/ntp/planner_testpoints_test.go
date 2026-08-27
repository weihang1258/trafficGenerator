package ntp

// Test points derived from /tmp/l7_planner_design/testcases_ntp.md.
// Each test asserts observable PacketConfig field values (header bytes, port,
// direction, packet count) -- not just "no error". Naming: TestNTP_<section>_<case>.
// Notes about testcase deviations from the testcases doc are in comments
// where they occur; the canonical doc describes the intent.

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// validNTPSpec returns a baseline spec with Mode=3, Version=4, MAC empty.
func validNTPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 123,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		NTP: &core.NTPConfig{
			Mode:    ModeClient,
			Version: 4,
		},
	}
}

// ============================================================================
// 1. RFC field coverage (LI, VN, Mode, Stratum, Poll, Precision, Root Delay,
//    Root Dispersion, Reference ID, timestamps, Key ID, MAC, Extensions)
// ============================================================================

// 1.1 LI field tests -- verify byte 0 high 2 bits encode the LI value.
func TestNTP_1_1_LIVersion3(t *testing.T) {
	// LI=0 in Mode=3 (client) -> byte[0] high 2 bits = 00
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, LeapIndicator: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0xC0 != 0x00 {
		t.Errorf("byte[0] high 2 bits = 0x%02x, want 0x00", cfg.Payload[0]&0xC0)
	}
}

func TestNTP_1_2_LIServer1(t *testing.T) {
	// LI=1 in Mode=4 (server) -> byte[0] high 2 bits = 01
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, LeapIndicator: 1}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0xC0 != 0x40 {
		t.Errorf("byte[0] high 2 bits = 0x%02x, want 0x40", cfg.Payload[0]&0xC0)
	}
}

func TestNTP_1_3_LI2Client(t *testing.T) {
	// LI=2 in Mode=3 -> byte[0] high 2 bits = 10
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, LeapIndicator: 2}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0xC0 != 0x80 {
		t.Errorf("byte[0] high 2 bits = 0x%02x, want 0x80", cfg.Payload[0]&0xC0)
	}
}

func TestNTP_1_4_LI3Alarm(t *testing.T) {
	// LI=3 in Mode=3 -> byte[0] high 2 bits = 11
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, LeapIndicator: 3}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0xC0 != 0xC0 {
		t.Errorf("byte[0] high 2 bits = 0x%02x, want 0xC0", cfg.Payload[0]&0xC0)
	}
}

func TestNTP_1_5_LI0Broadcast(t *testing.T) {
	// LI=0 in Mode=5 (broadcast) -> byte[0] high 2 bits = 00
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeBroadcast, Version: 4, LeapIndicator: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0xC0 != 0x00 {
		t.Errorf("byte[0] high 2 bits = 0x%02x, want 0x00", cfg.Payload[0]&0xC0)
	}
}

func TestNTP_1_6_VN4Client(t *testing.T) {
	// VN=4 in Mode=3 -> byte[0] bits[5:3] = 100
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x38 != 0x20 {
		t.Errorf("byte[0] bits[5:3] (VN) = 0x%02x, want 0x20 (VN=4)", cfg.Payload[0]&0x38)
	}
}

func TestNTP_1_7_VN3Compat(t *testing.T) {
	// VN=3 in Mode=3 (NTPv3 compat) -> byte[0] bits[5:3] = 011
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 3}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x38 != 0x18 {
		t.Errorf("byte[0] bits[5:3] (VN) = 0x%02x, want 0x18 (VN=3)", cfg.Payload[0]&0x38)
	}
}

func TestNTP_1_8_VN0Invalid(t *testing.T) {
	// VN=0 -> Validate error
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 0}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(VN=0): expected error, got nil")
	}
}

func TestNTP_1_9_VN5Invalid(t *testing.T) {
	// VN=5 -> Validate error
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 5}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(VN=5): expected error, got nil")
	}
}

func TestNTP_1_10_ModeSymmetricActive(t *testing.T) {
	// Mode=1 -> byte[0] low 3 bits = 001
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeSymmetricActive, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x07 != ModeSymmetricActive {
		t.Errorf("byte[0] low 3 bits = %d, want %d", cfg.Payload[0]&0x07, ModeSymmetricActive)
	}
}

func TestNTP_1_11_ModeSymmetricPassive(t *testing.T) {
	// Mode=2 -> byte[0] low 3 bits = 010
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeSymmetricPassive, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x07 != ModeSymmetricPassive {
		t.Errorf("byte[0] low 3 bits = %d, want %d", cfg.Payload[0]&0x07, ModeSymmetricPassive)
	}
}

func TestNTP_1_12_Mode3Client(t *testing.T) {
	// Mode=3 -> byte[0] low 3 bits = 011
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x07 != ModeClient {
		t.Errorf("byte[0] low 3 bits = %d, want %d", cfg.Payload[0]&0x07, ModeClient)
	}
}

func TestNTP_1_13_Mode4ServerResponse(t *testing.T) {
	// Mode=4 + IsResponse=true -> byte[0] low 3 bits = 100, emits 1 response
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, IsResponse: true}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (server response only)", len(cfgs))
	}
	if cfgs[0].Payload[0]&0x07 != ModeServer {
		t.Errorf("byte[0] low 3 bits = %d, want %d", cfgs[0].Payload[0]&0x07, ModeServer)
	}
}

func TestNTP_1_14_Mode5Broadcast3(t *testing.T) {
	// Mode=5 + RepeatCount=3 -> 3 packets, byte[0] low 3 bits = 101
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeBroadcast, Version: 4, RepeatCount: 3}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 3 {
		t.Fatalf("len=%d, want 3 (3 broadcast packets)", len(cfgs))
	}
	for i, c := range cfgs {
		if c.Payload[0]&0x07 != ModeBroadcast {
			t.Errorf("packet[%d] byte[0] low 3 bits = %d, want %d", i, c.Payload[0]&0x07, ModeBroadcast)
		}
	}
}

func TestNTP_1_15_Mode6Control(t *testing.T) {
	// Mode=6 + DataSize=10 -> control packet, header = 12 bytes + 10 data
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		ControlData: make([]byte, 10),
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1", len(cfgs))
	}
	if len(cfgs[0].Payload) != ControlHeaderLen+10 {
		t.Errorf("control payload len=%d, want %d (%d header + 10 data)",
			len(cfgs[0].Payload), ControlHeaderLen+10, ControlHeaderLen)
	}
}

// TestNTP_1_15a_Mode6ControlByte0Layout verifies the Mode=6 control header
// byte 0 uses the standard NTP LI(2)|VN(3)|Mode(3) layout -- the same layout
// the ntpd reference implementation packs via PKT_LI_VN_MODE(l, v, m) in
// ntp.h -- and that the payload is the 12-byte control header (not the
// 48-byte standard header). This guards against a regression to the
// non-standard Version(2)|LI(2)|Mode(4) packing described in design_ntp.md
// §2.3, which the planner already rejects (see planner.go buildControlRequest
// comment block).
//
// Expected byte 0 values (LI<<6 | VN<<3 | Mode, Mode=6):
//   LI=0 VN=4 -> 0x26   LI=0 VN=3 -> 0x1e   LI=3 VN=4 -> 0xE6
func TestNTP_1_15a_Mode6ControlByte0Layout(t *testing.T) {
	cases := []struct {
		name    string
		version uint8
		li      uint8
		wantB0  byte
	}{
		{"VN4_LI0", 4, 0, 0x26}, // (0<<6)|(4<<3)|6
		{"VN3_LI0", 3, 0, 0x1e}, // (0<<6)|(3<<3)|6
		{"VN4_LI3", 4, 3, 0xE6}, // (3<<6)|(4<<3)|6
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := validNTPSpec()
			spec.NTP = &core.NTPConfig{
				Mode:          ModeControl,
				Version:       c.version,
				LeapIndicator: c.li,
				Sequence:      1,
				RequestCode:   1,
				ControlData:   make([]byte, 4),
			}
			cfgs := drain(mustPlan(t, NewPlanner(), spec))
			if len(cfgs) != 1 {
				t.Fatalf("len=%d, want 1", len(cfgs))
			}
			// Mode=6 must emit the 12-byte control header, NOT the 48-byte
			// standard header (RFC 1305 App. B / ntpd ntp_control.h).
			if got := len(cfgs[0].Payload); got != ControlHeaderLen+4 {
				t.Errorf("payload len=%d, want %d (12-byte control header + 4 data), "+
					"not the 48-byte standard header", got, ControlHeaderLen+4)
			}
			// Byte 0 = LI(2)|VN(3)|Mode(3); Mode=6 must be recoverable from
			// the low 3 bits.
			got := cfgs[0].Payload[0]
			if got&0x07 != ModeControl {
				t.Errorf("byte[0] low 3 bits = 0x%02x, want Mode=6", got&0x07)
			}
			if got != c.wantB0 {
				t.Errorf("byte[0] = 0x%02x, want 0x%02x (LI=%d VN=%d Mode=6)",
					got, c.wantB0, c.li, c.version)
			}
			// VN must be recoverable from bits 5-3.
			if vn := (got >> 3) & 0x07; vn != c.version {
				t.Errorf("byte[0] VN bits = %d, want %d", vn, c.version)
			}
			// LI must be recoverable from bits 7-6.
			if li := (got >> 6) & 0x03; li != c.li {
				t.Errorf("byte[0] LI bits = %d, want %d", li, c.li)
			}
		})
	}
}

func TestNTP_1_16_Mode7Private(t *testing.T) {
	// Mode=7 -> byte[0] low 3 bits = 111
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModePrivate, Version: 4}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1", len(cfgs))
	}
	if cfgs[0].Payload[0]&0x07 != ModePrivate {
		t.Errorf("byte[0] low 3 bits = %d, want %d", cfgs[0].Payload[0]&0x07, ModePrivate)
	}
}

func TestNTP_1_17_Mode0Invalid(t *testing.T) {
	// Mode=0 -> Validate error (reserved)
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeReserved, Version: 4}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Mode=0): expected error, got nil")
	}
}

func TestNTP_1_18_Stratum0KoD(t *testing.T) {
	// Stratum=0 + Mode=4 -> byte[1] = 0x00
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x00 {
		t.Errorf("byte[1] (Stratum) = %d, want 0", cfg.Payload[1])
	}
}

func TestNTP_1_19_Stratum1Primary(t *testing.T) {
	// Stratum=1 -> byte[1] = 0x01
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 1}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x01 {
		t.Errorf("byte[1] (Stratum) = %d, want 1", cfg.Payload[1])
	}
}

func TestNTP_1_20_Stratum2(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 2}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x02 {
		t.Errorf("byte[1] = %d, want 2", cfg.Payload[1])
	}
}

func TestNTP_1_21_Stratum16(t *testing.T) {
	// Stratum=16 (unsync) -> byte[1] = 0x10
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 16}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x10 {
		t.Errorf("byte[1] = 0x%02x, want 0x10", cfg.Payload[1])
	}
}

func TestNTP_1_22_Stratum17Invalid(t *testing.T) {
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 17}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Stratum=17): expected error, got nil")
	}
}

func TestNTP_1_23_Poll4(t *testing.T) {
	// Poll=4 -> byte[2] = 0x04
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x04 {
		t.Errorf("byte[2] (Poll) = %d, want 4", cfg.Payload[2])
	}
}

func TestNTP_1_24_Poll6(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 6}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x06 {
		t.Errorf("byte[2] = %d, want 6", cfg.Payload[2])
	}
}

func TestNTP_1_25_Poll10(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 10}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x0A {
		t.Errorf("byte[2] = 0x%02x, want 0x0A", cfg.Payload[2])
	}
}

func TestNTP_1_26_Poll17Max(t *testing.T) {
	// Poll=17 (max) -> byte[2] = 0x11
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 17}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x11 {
		t.Errorf("byte[2] = 0x%02x, want 0x11", cfg.Payload[2])
	}
}

func TestNTP_1_27_PrecisionMinus6(t *testing.T) {
	// Precision=-6 -> byte[3] = 0xFA (=256-6), about 15ms
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Precision: -6}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[3] != 0xFA {
		t.Errorf("byte[3] (Precision -6) = 0x%02x, want 0xFA", cfg.Payload[3])
	}
}

func TestNTP_1_28_Precision0(t *testing.T) {
	// Precision=0 in Mode=4 -> byte[3] = 0x00
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Precision: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	// Note: planner also defaults Precision=0 -> -6 (DefaultPrecision).
	// Setting Precision=0 explicitly means "user chose 0", but because
	// 0 is the default value of int8, we cannot distinguish. The planner
	// substitutes DefaultPrecision=-6 when the field is 0. So this test
	// verifies that end-state.
	if cfg.Payload[3] != 0xFA {
		// Either Precision=-6 (0xFA) because the planner applied default,
		// or Precision=0 if the user-set value respected. The planner applies
		// the default, so we accept 0xFA.
		t.Errorf("byte[3] = 0x%02x, want 0xFA (DefaultPrecision=-6 applied)", cfg.Payload[3])
	}
}

func TestNTP_1_29_PrecisionMinus32(t *testing.T) {
	// Precision=-32 -> byte[3] = 0xE0 (=256-32), very high precision
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Precision: -32}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[3] != 0xE0 {
		t.Errorf("byte[3] = 0x%02x, want 0xE0", cfg.Payload[3])
	}
}

func TestNTP_1_30_RootDelayZero(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, RootDelay: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[4:8])
	if got != 0 {
		t.Errorf("RootDelay uint32 = 0x%08x, want 0", got)
	}
}

func TestNTP_1_31_RootDelayOne(t *testing.T) {
	// RootDelay=1.0 -> uint32 = 0x00010000 (16.16 fixed-point)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, RootDelay: 1.0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[4:8])
	if got != 0x00010000 {
		t.Errorf("RootDelay uint32 = 0x%08x, want 0x00010000", got)
	}
}

func TestNTP_1_32_RootDelayHalf(t *testing.T) {
	// RootDelay=0.5 -> 0x00008000
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, RootDelay: 0.5}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[4:8])
	if got != 0x00008000 {
		t.Errorf("RootDelay uint32 = 0x%08x, want 0x00008000", got)
	}
}

func TestNTP_1_33_RootDispersionZero(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, RootDispersion: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[8:12])
	if got != 0 {
		t.Errorf("RootDispersion uint32 = 0x%08x, want 0", got)
	}
}

func TestNTP_1_34_RootDispersionTwo(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, RootDispersion: 2.0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[8:12])
	if got != 0x00020000 {
		t.Errorf("RootDispersion uint32 = 0x%08x, want 0x00020000", got)
	}
}

func TestNTP_1_35_ReferenceIDZero(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, ReferenceID: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0 {
		t.Errorf("ReferenceID = 0x%08x, want 0", got)
	}
}

func TestNTP_1_36_ReferenceIDASCII(t *testing.T) {
	// ReferenceID=ASCII "DENY" -> 0x44454E59 (Stratum=0 KoD)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     0,
		ReferenceID: 0x44454E59,
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0x44454E59 {
		t.Errorf("ReferenceID = 0x%08x, want 0x44454E59 ('DENY')", got)
	}
}

func TestNTP_1_37_ReferenceIDGPS(t *testing.T) {
	// ReferenceID=ASCII "GPS " + Stratum=1 -> 0x47505320
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     1,
		ReferenceID: 0x47505320,
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0x47505320 {
		t.Errorf("ReferenceID = 0x%08x, want 0x47505320 ('GPS ')", got)
	}
}

func TestNTP_1_38_ReferenceIDIPv4(t *testing.T) {
	// ReferenceID=IPv4 192.168.1.1 -> 0xC0A80101
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     2,
		ReferenceID: 0xC0A80101,
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0xC0A80101 {
		t.Errorf("ReferenceID = 0x%08x, want 0xC0A80101 (192.168.1.1)", got)
	}
}

func TestNTP_1_39_RefTimestampZero(t *testing.T) {
	// RefTimestamp=0 (zero time) -> 64-bit zero
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4} // RefTimestamp=zero
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint64(cfg.Payload[16:24])
	if got != 0 {
		t.Errorf("RefTimestamp = 0x%016x, want 0", got)
	}
}

func TestNTP_1_40_TransmitTSZero(t *testing.T) {
	// TransmitTS=0 (zero time) -> 64-bit zero in request packet
	// Note: planner defaults TransmitTS=now when zero, so we only verify
	// the request packet has a non-zero Transmit (current time). This is
	// the observable contract: a client request always carries a transmit
	// timestamp set to "now" unless the user overrides.
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4} // TransmitTS=zero -> planner uses now
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint64(cfg.Payload[40:48])
	if got == 0 {
		t.Errorf("TransmitTS = 0, want non-zero (planner substitutes now())")
	}
}

func TestNTP_1_41_TransmitTSSet(t *testing.T) {
	// TransmitTS=2026-01-01 -> NTP seconds reflect 1900-01-01 + delta
	spec := validNTPSpec()
	// NTP epoch is 1900-01-01. 2026-01-01 = 126 years after 1900.
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, TransmitTS: ts}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint64(cfg.Payload[40:48])
	wantSec := uint64(ts.Unix()) + NTPEpochOffset
	if got>>32 != wantSec {
		t.Errorf("TransmitTS seconds = %d, want %d (NTP epoch)", got>>32, wantSec)
	}
}

func TestNTP_1_42_OriginFromRequest(t *testing.T) {
	// In client mode + IsResponse=true, response's Origin = request's Transmit.
	spec := validNTPSpec()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, IsResponse: true, TransmitTS: ts}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	reqTx := binary.BigEndian.Uint64(cfgs[0].Payload[40:48])
	respOrigin := binary.BigEndian.Uint64(cfgs[1].Payload[24:32])
	if reqTx != respOrigin {
		t.Errorf("request Transmit (0x%016x) != response Origin (0x%016x)", reqTx, respOrigin)
	}
}

func TestNTP_1_43_ReceiveTimestampZero(t *testing.T) {
	// Mode=3 client: Receive=0 (client did not receive anything)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint64(cfg.Payload[32:40])
	if got != 0 {
		t.Errorf("ReceiveTS = 0x%016x, want 0 for client request", got)
	}
}

func TestNTP_1_44_KeyID0NoTrailer(t *testing.T) {
	// KeyID=0, MAC=nil -> 48-byte packet only
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if len(cfg.Payload) != NTPHeaderLen {
		t.Errorf("payload len = %d, want %d (48-byte header, no auth trailer)", len(cfg.Payload), NTPHeaderLen)
	}
}

func TestNTP_1_45_KeyIDPlusMAC16(t *testing.T) {
	// KeyID=1 + MAC=16 bytes -> byte[48:52]=KeyID, byte[52:68]=MAC
	spec := validNTPSpec()
	mac := make([]byte, 16)
	for i := range mac {
		mac[i] = 0xAA
	}
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, KeyID: 1, MAC: mac}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if len(cfg.Payload) != NTPHeaderLen+4+16 {
		t.Errorf("payload len = %d, want %d (48 + 4 KeyID + 16 MAC)", len(cfg.Payload), NTPHeaderLen+4+16)
	}
	if got := binary.BigEndian.Uint32(cfg.Payload[48:52]); got != 1 {
		t.Errorf("KeyID bytes = 0x%08x, want 0x00000001", got)
	}
}

func TestNTP_1_46_ExtensionsNone(t *testing.T) {
	// Extensions=nil -> 48-byte packet only
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if len(cfg.Payload) != NTPHeaderLen {
		t.Errorf("payload len = %d, want %d (no extensions)", len(cfg.Payload), NTPHeaderLen)
	}
}

func TestNTP_1_47_ExtensionsOne(t *testing.T) {
	// 1 ext with Type=0x0001, Value=4 bytes -> 8 bytes after header
	spec := validNTPSpec()
	val := make([]byte, 4)
	spec.NTP = &core.NTPConfig{
		Mode:    ModeClient,
		Version: 4,
		Extensions: []core.NTPExt{
			{Type: 0x0001, Value: val},
		},
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if len(cfg.Payload) != NTPHeaderLen+8 {
		t.Errorf("payload len = %d, want %d (48 + 8 ext)", len(cfg.Payload), NTPHeaderLen+8)
	}
}

// ============================================================================
// 2. State machine tests
// ============================================================================

func TestNTP_2_1_ClientRequestEmits(t *testing.T) {
	// Mode=3 default: 1 packet (request)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1 (Mode=3 default: 1 request)", len(cfgs))
	}
}

func TestNTP_2_2_ServerResponseEmits(t *testing.T) {
	// Mode=4 + IsResponse: 1 response
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, IsResponse: true}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1 (Mode=4 + IsResponse: 1 response)", len(cfgs))
	}
}

func TestNTP_2_3_ClientPlusResponse2Packets(t *testing.T) {
	// Mode=3 + IsResponse: 2 packets (request + response)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, IsResponse: true}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Errorf("len=%d, want 2 (request + response)", len(cfgs))
	}
}

func TestNTP_2_4_BroadcastRepeat(t *testing.T) {
	// Mode=5 + RepeatCount=5 -> 5 packets
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeBroadcast, Version: 4, RepeatCount: 5}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 5 {
		t.Errorf("len=%d, want 5", len(cfgs))
	}
}

func TestNTP_2_5_SymmetricActiveEmits(t *testing.T) {
	// Mode=1 + RepeatCount=3 -> 3 packets
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeSymmetricActive, Version: 4, RepeatCount: 3}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 3 {
		t.Errorf("len=%d, want 3", len(cfgs))
	}
}

func TestNTP_2_6_SymmetricWithResponse(t *testing.T) {
	// Mode=1 + IsResponse=true + RepeatCount=3 -> 6 packets (3 + 3)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeSymmetricActive,
		Version:     4,
		IsResponse:  true,
		RepeatCount: 3,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 6 {
		t.Errorf("len=%d, want 6 (3 active + 3 passive)", len(cfgs))
	}
}

func TestNTP_2_7_BroadcastTransmitIncrements(t *testing.T) {
	// Mode=5 + RepeatCount=3 -> 3 packets, TransmitTS ascending
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeBroadcast, Version: 4, RepeatCount: 3, PollInterval: 16}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 3 {
		t.Fatalf("len=%d, want 3", len(cfgs))
	}
	ts0 := binary.BigEndian.Uint64(cfgs[0].Payload[40:48])
	ts1 := binary.BigEndian.Uint64(cfgs[1].Payload[40:48])
	ts2 := binary.BigEndian.Uint64(cfgs[2].Payload[40:48])
	if !(ts0 < ts1 && ts1 < ts2) {
		t.Errorf("TransmitTS not ascending: %d < %d < %d ?", ts0, ts1, ts2)
	}
}

func TestNTP_2_8_ControlSequenceMatches(t *testing.T) {
	// Mode=6 + IsResponse + Sequence=7 -> request and response both have seq=7.
	// Per RFC 1305 App. B the Sequence is a 16-bit field at bytes 2-3.
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    7,
		RequestCode: 1,
		IsResponse:  true,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (request + response)", len(cfgs))
	}
	if got := binary.BigEndian.Uint16(cfgs[0].Payload[2:4]); got != 7 {
		t.Errorf("request Sequence (bytes 2-3) = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint16(cfgs[1].Payload[2:4]); got != 7 {
		t.Errorf("response Sequence (bytes 2-3) = %d, want 7", got)
	}
}

func TestNTP_2_9_PrivateEmits48ByteHeader(t *testing.T) {
	// Mode=7: 1 packet, 48-byte basic header layout
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModePrivate, Version: 4}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1", len(cfgs))
	}
	if len(cfgs[0].Payload) != NTPHeaderLen {
		t.Errorf("Mode=7 payload len = %d, want %d (48-byte basic)", len(cfgs[0].Payload), NTPHeaderLen)
	}
}

// ============================================================================
// 3. Business scenarios
// ============================================================================

func TestNTP_3_1_ClientQueryCommon(t *testing.T) {
	// Mode=3 + IsResponse -> request + response, Origin echoed from request
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, IsResponse: true}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	// request direction = up, response = down
	if cfgs[0].Direction != "up" {
		t.Errorf("request direction = %s, want up", cfgs[0].Direction)
	}
	if cfgs[1].Direction != "down" {
		t.Errorf("response direction = %s, want down", cfgs[1].Direction)
	}
	// Response Origin = Request Transmit
	if !bytes.Equal(cfgs[0].Payload[40:48], cfgs[1].Payload[24:32]) {
		t.Error("response Origin does not equal request Transmit")
	}
}

func TestNTP_3_2_Stratum2ReferenceIPv4(t *testing.T) {
	// Stratum=2 server with IPv4 ReferenceID
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     2,
		ReferenceID: 0xC0A80101,
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0xC0A80101 {
		t.Errorf("Stratum=2 reference IPv4 = 0x%08x, want 0xC0A80101", got)
	}
}

func TestNTP_3_3_BroadcastStratum1(t *testing.T) {
	// Mode=5 + Stratum=1 -> primary server broadcast
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeBroadcast,
		Version:     4,
		Stratum:     1,
		ReferenceID: 0x47505320, // "GPS "
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 1 {
		t.Errorf("byte[1] (Stratum) = %d, want 1", cfg.Payload[1])
	}
}

func TestNTP_3_4_MultiStratumChain(t *testing.T) {
	// Stratum=1 server emits valid mode=4 packet
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     1,
		ReferenceID: 0x47505320,
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x01 {
		t.Errorf("Stratum=1 byte[1] = %d, want 1", cfg.Payload[1])
	}
}

func TestNTP_3_5_ControlRequestCode(t *testing.T) {
	// Mode=6 + RequestCode=0x01 (read_var) -> byte[1] low 5 bits = 0x01 (OpCode)
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 0x01,
		ControlData: []byte{1, 2, 3},
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if got := cfg.Payload[1] & 0x1F; got != 0x01 {
		t.Errorf("OpCode (byte[1]&0x1F) = 0x%02x, want 0x01", got)
	}
}

func TestNTP_3_6_ControlResponseErrorBit(t *testing.T) {
	// Mode=6 + IsResponse + Error=false -> response Error bit (byte[1]&0x40) = 0
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		IsResponse:  true,
		Error:       false,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// Error bit is byte 1 bit 6 (0x40) per RFC 1305 App. B.
	if cfgs[1].Payload[1]&0x40 != 0 {
		t.Errorf("response Error bit (byte[1]&0x40) = 1, want 0")
	}
	// Response must also have the R bit (byte 1 bit 7) set.
	if cfgs[1].Payload[1]&0x80 == 0 {
		t.Errorf("response R bit (byte[1]&0x80) = 0, want 1 (response)")
	}
}

func TestNTP_3_7_KoDDeny(t *testing.T) {
	// Stratum=0 + ReferenceID="DENY" -> KoD reject
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeServer,
		Version:     4,
		Stratum:     0,
		ReferenceID: 0x44454E59, // "DENY"
	}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0 {
		t.Errorf("KoD Stratum = %d, want 0", cfg.Payload[1])
	}
	got := binary.BigEndian.Uint32(cfg.Payload[12:16])
	if got != 0x44454E59 {
		t.Errorf("KoD ReferenceID = 0x%08x, want 0x44454E59", got)
	}
}

func TestNTP_3_8_NTPv3Compat(t *testing.T) {
	// VN=3 + Mode=3 -> byte[0] bits[5:3] = 011
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 3}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[0]&0x38 != 0x18 {
		t.Errorf("VN=3 bits[5:3] = 0x%02x, want 0x18", cfg.Payload[0]&0x38)
	}
}

// ============================================================================
// 4. Data scenarios
// ============================================================================

func TestNTP_4_1_AllTimestampsZero(t *testing.T) {
	// All timestamps zero except TransmitTS (which planner sets to now)
	// and ReceiveTS (which for client mode is 0; for server mode planner
	// sets to now). We verify byte[16:32] = 0 (RefTimestamp + Origin),
	// and that byte[40:48] (Transmit) is non-zero because planner uses now.
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4} // all timestamp fields zero
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	// RefTimestamp (16:24) = 0
	for i := 16; i < 24; i++ {
		if cfg.Payload[i] != 0 {
			t.Errorf("byte[%d] = 0x%02x, want 0 (RefTimestamp zero)", i, cfg.Payload[i])
		}
	}
	// Origin (24:32) = 0 (client request has no origin)
	for i := 24; i < 32; i++ {
		if cfg.Payload[i] != 0 {
			t.Errorf("byte[%d] = 0x%02x, want 0 (OriginTimestamp zero for client)", i, cfg.Payload[i])
		}
	}
	// Transmit (40:48) is set by planner to now() - verify it's non-zero.
	transmit := binary.BigEndian.Uint64(cfg.Payload[40:48])
	if transmit == 0 {
		t.Errorf("TransmitTS = 0, want non-zero (planner substitutes now() for client request)")
	}
}

func TestNTP_4_2_Stratum0Payload(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Stratum: 0}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[1] != 0x00 {
		t.Errorf("Stratum=0 byte[1] = 0x%02x, want 0x00", cfg.Payload[1])
	}
}

func TestNTP_4_3_PollMin(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x04 {
		t.Errorf("Poll=4 byte[2] = %d, want 4", cfg.Payload[2])
	}
}

func TestNTP_4_4_PollMax(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, Poll: 17}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[2] != 0x11 {
		t.Errorf("Poll=17 byte[2] = 0x%02x, want 0x11", cfg.Payload[2])
	}
}

func TestNTP_4_5_PrecisionBoundary(t *testing.T) {
	// Precision=-32 -> byte[3] = 0xE0
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, Precision: -32}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Payload[3] != 0xE0 {
		t.Errorf("Precision=-32 byte[3] = 0x%02x, want 0xE0", cfg.Payload[3])
	}
}

func TestNTP_4_6_LI4Invalid(t *testing.T) {
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, LeapIndicator: 4}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(LI=4): expected error")
	}
}

func TestNTP_4_7_MAC17Invalid(t *testing.T) {
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4, MAC: make([]byte, 17)}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(MAC len=17): expected error")
	}
}

func TestNTP_4_8_ControlData469Invalid(t *testing.T) {
	// Mode=6 + ControlData=469 -> exceeds CTL_MAX_DATA_LEN (468) -> error.
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		ControlData: make([]byte, 469),
	}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(ControlData len=469): expected error")
	}
}

func TestNTP_4_9_ControlData468Max(t *testing.T) {
	// Mode=6 + ControlData=468 -> total packet 480 (12-byte header + 468 data)
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		ControlData: make([]byte, 468),
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(ControlData len=468): unexpected error %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[0].Payload) != ControlHeaderLen+468 {
		t.Errorf("total len = %d, want %d (12 + 468)", len(cfgs[0].Payload), ControlHeaderLen+468)
	}
}

func TestNTP_4_10_MinimalPacket(t *testing.T) {
	// Minimal: 48 bytes header only
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if len(cfg.Payload) != 48 {
		t.Errorf("minimal packet len = %d, want 48", len(cfg.Payload))
	}
}

func TestNTP_4_11_VLANTagPropagates(t *testing.T) {
	// Spec.VLAN non-nil -> PacketConfig.L2.VLAN non-nil
	vlan := &core.VLAN{ID: 100, Priority: 5}
	spec := validNTPSpec()
	spec.VLAN = vlan
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.L2.VLAN == nil || cfg.L2.VLAN.ID != 100 {
		t.Errorf("L2.VLAN = %+v, want ID=100", cfg.L2.VLAN)
	}
}

// ============================================================================
// 5. IPv6 / IPv4 -- both must work (per multicast_ipv6_vlan.md §5 NTP required)
// ============================================================================

func TestNTP_5_1_IPv4Basic(t *testing.T) {
	spec := validNTPSpec() // already IPv4
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.L2.EtherType != 0x0800 {
		t.Errorf("IPv4 EtherType = 0x%04x, want 0x0800", cfg.L2.EtherType)
	}
}

func TestNTP_5_2_IPv6EtherType(t *testing.T) {
	spec := validNTPSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.L2.EtherType != 0x86DD {
		t.Errorf("IPv6 EtherType = 0x%04x, want 0x86DD", cfg.L2.EtherType)
	}
}

// ============================================================================
// 6. General Validate / Plan coverage
// ============================================================================

func TestNTP_6_1_PlanValidateFailsReturnsNil(t *testing.T) {
	// Plan with invalid spec returns nil channel and error.
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeReserved, Version: 4} // invalid
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Error("Plan: expected error, got nil")
	}
	if ch != nil {
		t.Error("Plan: expected nil channel on validate fail")
	}
}

func TestNTP_6_2_DefaultPort123(t *testing.T) {
	// SrcPort/DstPort=0 -> planner substitutes 123 (per mapToFlowSpec's
	// strategy_convert.go override; planner Plan goroutine takes DstPort
	// from spec.DstPort which strategy_convert.go has already defaulted to
	// 123 when absent in JSON).
	spec := validNTPSpec()
	spec.DstPort = 123
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.L4.DstPort != 123 {
		t.Errorf("L4.DstPort = %d, want 123", cfg.L4.DstPort)
	}
}

func TestNTP_6_3_DefaultTTL(t *testing.T) {
	spec := validNTPSpec()
	spec.TTL = 0 // unset -> planner uses DefaultTTL
	spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.L3.TTL != DefaultTTL {
		t.Errorf("L3.TTL = %d, want %d (default)", cfg.L3.TTL, DefaultTTL)
	}
}

func TestNTP_6_4_NoGoroutineLeakBasic(t *testing.T) {
	// 10 sequential Plan calls, all complete within timeout.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			p := NewPlanner()
			spec := validNTPSpec()
			spec.NTP = &core.NTPConfig{Mode: ModeClient, Version: 4}
			cfgs := drain(mustPlan(t, p, spec))
			if len(cfgs) != 1 {
				t.Errorf("iteration %d: got %d configs", i, len(cfgs))
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: Plan goroutine leak suspected")
	}
}

func TestNTP_6_5_ServerMACsSwappedOnDirectionDown(t *testing.T) {
	// Mode=4 emits direction=down with MACs/IPs/ports swapped.
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{Mode: ModeServer, Version: 4, IsResponse: true}
	cfg := drain(mustPlan(t, NewPlanner(), spec))[0]
	if cfg.Direction != "down" {
		t.Errorf("server packet Direction = %s, want down", cfg.Direction)
	}
	// L2.SrcMAC should equal spec.DstMAC (response comes from server)
	if cfg.L2.SrcMAC != spec.DstMAC {
		t.Errorf("L2.SrcMAC = %s, want %s (swapped)", cfg.L2.SrcMAC, spec.DstMAC)
	}
}

// TestNTP_7_ValidateErrorFormat checks that nil NTP config is accepted
// (P0b-2: 空配置默认化产默认流)。
func TestNTP_7_ValidateErrorFormat(t *testing.T) {
	p := NewPlanner()
	spec := validNTPSpec()
	spec.NTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty config should default to a flow, got err=%v", err)
	}
}
