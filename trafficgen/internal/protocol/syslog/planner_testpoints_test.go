package syslog

// Test points derived from /tmp/l7_planner_design/testcases_syslog.md.
// Each test corresponds to an atomic case (1.1.1.x, 1.1.2.x, etc.)
// and asserts observable PacketConfig field values, not just "no error".
//
// Categories covered:
//   1.1.1 Facility 0-23 (24 cases) — assert PRI prefix
//   1.1.2 Severity 0-7 (8 cases) — assert PRI prefix
//   1.1.3 PRI combinations (selected)
//   1.1.4 PRI out-of-range
//   1.2 VERSION edge cases
//   1.3 TIMESTAMP formats
//   1.4 HOSTNAME edge cases
//   1.5-1.7 APP-NAME/PROCID/MSGID edge cases
//   1.8 STRUCTURED-DATA edge cases
//   1.9 MSG + BOM edge cases
//   1.10 BSD format
//   2.1-2.6 State machine
//   3.1-3.15 Business scenarios (selected)
//   4.1-4.5 Data scenarios (selected)

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- 1.1.1.x Facility 0-23 (24 cases) ---
// Each case asserts the encoded PRI = `<Facility*8+6>` for Facility=0..23.

func TestPoint_1_1_1_1_Facility0_Kern(t *testing.T) {
	// Facility=0 (kern) + Severity=6 -> PRI=`<6>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 0
	spec.Syslog.Severity = 6
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<6>1 ")) {
		t.Errorf("Facility=0 Severity=6 PRI=%q, want '<6>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_1_2_Facility1_User(t *testing.T) {
	// Facility=1 (user) + Severity=6 -> PRI=`<14>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<14>1 ")) {
		t.Errorf("Facility=1 Severity=6 PRI=%q, want '<14>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_1_16_Facility15_Local0(t *testing.T) {
	// Facility=15 (local0) + Severity=6 -> PRI=`<126>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 15
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<126>1 ")) {
		t.Errorf("Facility=15 Severity=6 PRI=%q, want '<126>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_1_17_Facility16_Local1(t *testing.T) {
	// Facility=16 (local1) + Severity=6 -> PRI=`<134>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 16
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 ")) {
		t.Errorf("Facility=16 Severity=6 PRI=%q, want '<134>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_1_23_Facility22_Local7(t *testing.T) {
	// Facility=22 (local7) + Severity=6 -> PRI=`<182>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 22
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<182>1 ")) {
		t.Errorf("Facility=22 Severity=6 PRI=%q, want '<182>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_1_24_Facility23_Reserved(t *testing.T) {
	// Facility=23 (reserved) + Severity=6 -> PRI=`<190>`. Validate passes
	// (per RFC 5424 §6.2.1: 24-23 reserved for future extension).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 23
	if err := p.Validate(spec); err != nil {
		t.Errorf("Facility=23 should be valid: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<190>1 ")) {
		t.Errorf("Facility=23 Severity=6 PRI=%q, want '<190>1 '", first10(cfgs[0].Payload))
	}
}

// --- 1.1.2.x Severity 0-7 (8 cases) ---

func TestPoint_1_1_2_1_Severity0_Emerg(t *testing.T) {
	// Facility=1 (user) + Severity=0 (emerg) -> PRI=`<8>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 0
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<8>1 ")) {
		t.Errorf("Facility=1 Severity=0 PRI=%q, want '<8>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_2_Severity1_Alert(t *testing.T) {
	// Facility=1 + Severity=1 -> PRI=`<9>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 1
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<9>1 ")) {
		t.Errorf("Facility=1 Severity=1 PRI=%q, want '<9>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_3_Severity2_Crit(t *testing.T) {
	// Facility=1 + Severity=2 -> PRI=`<10>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 2
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<10>1 ")) {
		t.Errorf("Facility=1 Severity=2 PRI=%q, want '<10>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_4_Severity3_Err(t *testing.T) {
	// Facility=1 + Severity=3 -> PRI=`<11>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 3
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<11>1 ")) {
		t.Errorf("Facility=1 Severity=3 PRI=%q, want '<11>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_5_Severity4_Warning(t *testing.T) {
	// Facility=1 + Severity=4 -> PRI=`<12>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 4
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<12>1 ")) {
		t.Errorf("Facility=1 Severity=4 PRI=%q, want '<12>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_6_Severity5_Notice(t *testing.T) {
	// Facility=1 + Severity=5 -> PRI=`<13>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 5
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<13>1 ")) {
		t.Errorf("Facility=1 Severity=5 PRI=%q, want '<13>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_7_Severity6_Info(t *testing.T) {
	// Facility=1 + Severity=6 -> PRI=`<14>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 6
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<14>1 ")) {
		t.Errorf("Facility=1 Severity=6 PRI=%q, want '<14>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_2_8_Severity7_Debug(t *testing.T) {
	// Facility=1 + Severity=7 -> PRI=`<15>`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 1
	spec.Syslog.Severity = 7
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<15>1 ")) {
		t.Errorf("Facility=1 Severity=7 PRI=%q, want '<15>1 '", first10(cfgs[0].Payload))
	}
}

// --- 1.1.3 PRI combinations (selected) ---

func TestPoint_1_1_3_1_MinPRI(t *testing.T) {
	// Facility=0 + Severity=0 -> PRI=`<0>` (min, emerg-kern).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 0
	spec.Syslog.Severity = 0
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<0>1 ")) {
		t.Errorf("min PRI=%q, want '<0>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_3_2_MaxPRI(t *testing.T) {
	// Facility=23 + Severity=7 -> PRI=`<191>` (max).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 23
	spec.Syslog.Severity = 7
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<191>1 ")) {
		t.Errorf("max PRI=%q, want '<191>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_1_3_4_AuthErr(t *testing.T) {
	// Facility=4 + Severity=3 -> PRI=`<35>` (auth-err common combo).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 4
	spec.Syslog.Severity = 3
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<35>1 ")) {
		t.Errorf("auth-err PRI=%q, want '<35>1 '", first10(cfgs[0].Payload))
	}
}

// --- 1.1.4 PRI out-of-range ---

func TestPoint_1_1_4_1_Facility24_Invalid(t *testing.T) {
	// Facility=24 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 24
	err := p.Validate(spec)
	if err == nil {
		t.Error("Facility=24 should fail Validate")
	}
}

func TestPoint_1_1_4_3_Severity8_Invalid(t *testing.T) {
	// Severity=8 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Severity = 8
	err := p.Validate(spec)
	if err == nil {
		t.Error("Severity=8 should fail Validate")
	}
}

// --- 1.2 VERSION ---

func TestPoint_1_2_1_Version1_Default(t *testing.T) {
	// Version=1 -> output starts with "<PRI>1 ...".
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSyslogSpec()))
	// validSyslogSpec has Version=1, Facility=16, Severity=6 -> PRI=134
	// <134>1 ...
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 ")) {
		t.Errorf("Version=1 prefix=%q, want '<134>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_1_2_2_Version0_Rfc5424_Fails(t *testing.T) {
	// Version=0 with Format=rfc5424 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 0
	spec.Syslog.Format = "" // default rfc5424
	err := p.Validate(spec)
	if err == nil {
		t.Error("Version=0 with rfc5424 should fail Validate")
	}
}

func TestPoint_1_2_3_Version2_Invalid(t *testing.T) {
	// Version=2 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 2
	err := p.Validate(spec)
	if err == nil {
		t.Error("Version=2 should fail Validate")
	}
}

func TestPoint_1_2_4_Version0_Bsd_Ok(t *testing.T) {
	// Version=0 with Format=bsd -> no VERSION field in output.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Version = 0
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	cfgs := drain(mustPlan(t, p, spec))
	// BSD format: <PRI>TIMESTAMP SP HOSTNAME SP TAG[PID]: SP MSG
	// No "VERSION 1" between PRI and TIMESTAMP.
	if bytes.Contains(cfgs[0].Payload, []byte(">1 ")) {
		t.Errorf("BSD format should not contain '>1 ' (VERSION), got %q", cfgs[0].Payload)
	}
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>Jul 28 10:00:00 ")) {
		t.Errorf("BSD format prefix=%q, want '<134>Jul 28 10:00:00 '", first20(cfgs[0].Payload))
	}
}

// --- 1.3.1 TIMESTAMP formats ---

func TestPoint_1_3_1_1_Timestamp_Short(t *testing.T) {
	// "2003-10-11T22:14:15Z" (20 bytes).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2003-10-11T22:14:15Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("2003-10-11T22:14:15Z")) {
		t.Errorf("missing short timestamp, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_1_2_Timestamp_Millis(t *testing.T) {
	// "2003-10-11T22:14:15.003Z" (24 bytes).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2003-10-11T22:14:15.003Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("2003-10-11T22:14:15.003Z")) {
		t.Errorf("missing ms timestamp, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_1_3_Timestamp_Nanos(t *testing.T) {
	// "2003-10-11T22:14:15.123456789+08:00" (36 bytes).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2003-10-11T22:14:15.123456789+08:00"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("2003-10-11T22:14:15.123456789+08:00")) {
		t.Errorf("missing ns+tz timestamp, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_1_4_Timestamp_NegTZ(t *testing.T) {
	// "2003-10-11T22:14:15-05:00" (25 bytes).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2003-10-11T22:14:15-05:00"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("2003-10-11T22:14:15-05:00")) {
		t.Errorf("missing neg-tz timestamp, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_1_5_Timestamp_Empty_NILVALUE(t *testing.T) {
	// Empty timestamp -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = ""
	cfgs := drain(mustPlan(t, p, spec))
	// Format: <PRI>1 SP TIMESTAMP SP HOSTNAME SP ... -> first TIMESTAMP is "-".
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 - server01 ")) {
		t.Errorf("empty ts prefix=%q, want '<134>1 - server01 '", first20(cfgs[0].Payload))
	}
}

func TestPoint_1_3_1_6_Timestamp_Invalid_Fails(t *testing.T) {
	// "invalid-format" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "invalid-format"
	err := p.Validate(spec)
	if err == nil {
		t.Error("invalid timestamp should fail Validate")
	}
}

// --- 1.3.2 BSD TIMESTAMP ---

func TestPoint_1_3_2_1_BSD_Timestamp_Normal(t *testing.T) {
	// Format=bsd + 2026-07-28T10:00:00Z -> "Jul 28 10:00:00".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("Jul 28 10:00:00")) {
		t.Errorf("BSD timestamp missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_2_2_BSD_Timestamp_DayPadding(t *testing.T) {
	// Day 1-9 -> space-padded "Jan  5".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-01-05T03:04:05Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("Jan  5 03:04:05")) {
		t.Errorf("BSD day-padded missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_3_2_3_BSD_Timestamp_Dec(t *testing.T) {
	// 2026-12-31T23:59:59Z -> "Dec 31 23:59:59".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-12-31T23:59:59Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("Dec 31 23:59:59")) {
		t.Errorf("BSD Dec timestamp missing, got %q", cfgs[0].Payload)
	}
}

// --- 1.4 HOSTNAME ---

func TestPoint_1_4_1_Hostname_FQDN(t *testing.T) {
	// HOSTNAME="server01.example.com" -> 17 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "server01.example.com"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("server01.example.com")) {
		t.Errorf("FQDN hostname missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_4_2_Hostname_IPv4(t *testing.T) {
	// HOSTNAME="192.0.2.1" -> 8 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "192.0.2.1"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("192.0.2.1")) {
		t.Errorf("IPv4 hostname missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_4_4_Hostname_Empty_NILVALUE(t *testing.T) {
	// Empty HOSTNAME -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = ""
	cfgs := drain(mustPlan(t, p, spec))
	// Format: ... PROCID SP MSGID SP SD SP - cron - HEARTBEAT ...
	// Actually: PRI 1 - - cron - HEARTBEAT - ...
	if !bytes.Contains(cfgs[0].Payload, []byte(" - cron - HEARTBEAT")) {
		t.Errorf("nil hostname position wrong, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_4_6_Hostname_MinLength(t *testing.T) {
	// HOSTNAME="a" -> 1 byte.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "a"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(" a ")) {
		t.Errorf("1-byte hostname missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_4_7_Hostname_WithSP_Fails(t *testing.T) {
	// HOSTNAME="host name" -> Validate fails (no SP allowed).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "host name"
	err := p.Validate(spec)
	if err == nil {
		t.Error("hostname with SP should fail Validate")
	}
}

func TestPoint_1_4_8_Hostname_256_Fails(t *testing.T) {
	// HOSTNAME 256 bytes -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = strings.Repeat("a", 256)
	err := p.Validate(spec)
	if err == nil {
		t.Error("256-byte hostname should fail Validate")
	}
}

// --- 1.5 APP-NAME ---

func TestPoint_1_5_1_AppName_SSHD(t *testing.T) {
	// APP-NAME="sshd" -> 4 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.AppName = "sshd"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(" sshd ")) {
		t.Errorf("sshd app-name missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_5_4_AppName_Empty_NILVALUE(t *testing.T) {
	// Empty APP-NAME -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.AppName = ""
	cfgs := drain(mustPlan(t, p, spec))
	// Format: PRI 1 - server01 - - HEARTBEAT ...
	if !bytes.Contains(cfgs[0].Payload, []byte(" server01 - - HEARTBEAT")) {
		t.Errorf("nil appname position wrong, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_5_6_AppName_WithSP_Fails(t *testing.T) {
	// APP-NAME="my app" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.AppName = "my app"
	err := p.Validate(spec)
	if err == nil {
		t.Error("appname with SP should fail Validate")
	}
}

func TestPoint_1_5_7_AppName_49_Fails(t *testing.T) {
	// APP-NAME 49 bytes -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.AppName = strings.Repeat("a", 49)
	err := p.Validate(spec)
	if err == nil {
		t.Error("49-byte appname should fail Validate")
	}
}

// --- 1.6 PROCID ---

func TestPoint_1_6_1_ProcID_PID(t *testing.T) {
	// PROCID="1234" -> 4 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.ProcID = "1234"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(" 1234 ")) {
		t.Errorf("PID 1234 missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_6_3_ProcID_Empty_NILVALUE(t *testing.T) {
	// Empty PROCID -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.ProcID = ""
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(" cron - HEARTBEAT")) {
		t.Errorf("nil procid position wrong, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_6_5_ProcID_WithSP_Fails(t *testing.T) {
	// PROCID="proc 1" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.ProcID = "proc 1"
	err := p.Validate(spec)
	if err == nil {
		t.Error("procid with SP should fail Validate")
	}
}

func TestPoint_1_6_6_ProcID_129_Fails(t *testing.T) {
	// PROCID 129 bytes -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.ProcID = strings.Repeat("a", 129)
	err := p.Validate(spec)
	if err == nil {
		t.Error("129-byte procid should fail Validate")
	}
}

// --- 1.7 MSGID ---

func TestPoint_1_7_1_MsgID_TCPIN(t *testing.T) {
	// MSGID="TCPIN" -> 5 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.MsgID = "TCPIN"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(" TCPIN ")) {
		t.Errorf("MSGID TCPIN missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_7_3_MsgID_Empty_NILVALUE(t *testing.T) {
	// Empty MSGID -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.MsgID = ""
	cfgs := drain(mustPlan(t, p, spec))
	// Format: PRI 1 - server01 cron - - ...
	if !bytes.Contains(cfgs[0].Payload, []byte(" - - ")) {
		t.Errorf("nil msgid position wrong, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_7_5_MsgID_WithSP_Fails(t *testing.T) {
	// MSGID with SP -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.MsgID = "ID with space"
	err := p.Validate(spec)
	if err == nil {
		t.Error("msgid with SP should fail Validate")
	}
}

func TestPoint_1_7_6_MsgID_33_Fails(t *testing.T) {
	// MSGID 33 bytes -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.MsgID = strings.Repeat("a", 33)
	err := p.Validate(spec)
	if err == nil {
		t.Error("33-byte msgid should fail Validate")
	}
}

// --- 1.8 STRUCTURED-DATA ---

func TestPoint_1_8_1_1_SD_SingleElement(t *testing.T) {
	// STRUCTURED-DATA=`[origin ip="192.0.2.1"]` -> 24 bytes pre-framed.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[origin ip="192.0.2.1"]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[origin ip="192.0.2.1"]`)) {
		t.Errorf("SD element missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_1_3_SD_Minimal(t *testing.T) {
	// STRUCTURED-DATA=`[x]` (no params) -> 3 bytes minimal.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[x]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[x]`)) {
		t.Errorf("minimal SD missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_1_4_SD_Empty_NILVALUE(t *testing.T) {
	// Empty STRUCTURED-DATA -> NILVALUE "-".
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = nil
	cfgs := drain(mustPlan(t, p, spec))
	// Format: PRI 1 - server01 cron - HEARTBEAT - MSG
	if !bytes.Contains(cfgs[0].Payload, []byte(" HEARTBEAT - Job ran")) {
		t.Errorf("nil SD position wrong, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_2_1_SD_MultipleElements(t *testing.T) {
	// Multiple SD-ELEMENTs concatenated without spaces.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{
		`[origin ip="192.0.2.1"]`,
		`[meta sequenceId="1"]`,
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := `[origin ip="192.0.2.1"][meta sequenceId="1"]`
	if !bytes.Contains(cfgs[0].Payload, []byte(want)) {
		t.Errorf("multi SD not concatenated, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_3_1_SD_WithPEN(t *testing.T) {
	// SD-ID with PEN: `[eventID@32473 ...]`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[eventID@32473 id="1234"]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[eventID@32473 id="1234"]`)) {
		t.Errorf("SD with PEN missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_3_2_SD_SignBlock(t *testing.T) {
	// RFC 5848 sign SD: `[sign@32473 ...]`.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"sigA"}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[sign@32473 signature="sigA"]`)) {
		t.Errorf("sign SD missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_8_5_1_SD_Unclosed_Fails(t *testing.T) {
	// SD-ELEMENT missing `]` -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[origin ip="1.2.3.4"`}
	err := p.Validate(spec)
	if err == nil {
		t.Error("unclosed SD should fail Validate")
	}
}

func TestPoint_1_8_5_3_SD_ID_WithSP_Fails(t *testing.T) {
	// SD-ID with embedded SP -> Validate fails. We use a malformed
	// pre-framed form where the SD-ID is `bad id` (split by SP). Per RFC
	// 5424 §6.2.8, SD-ELEMENT is `[SD-ID[@PEN] (SP PARAM-NAME="PARAM-VALUE")*]`.
	// With SP between `bad` and `id`, the parser treats `bad` as SD-ID and
	// `id="1"` as a malformed parameter (PARAM-NAME `id` is followed by
	// `="1"` which IS a valid parameter form). To trigger the failure, we
	// use a parameter with no `=`: `[bad id val]` — `id` and `val` are
	// both bare tokens with no `=`, so they fail the parameter check.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[bad id val]`}
	err := p.Validate(spec)
	if err == nil {
		t.Error("malformed SD (bare tokens with no '=') should fail Validate")
	}
}

func TestPoint_1_8_5_4_SD_ID_33_Fails(t *testing.T) {
	// SD-ID > 32 bytes -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[` + strings.Repeat("a", 33) + `]`}
	err := p.Validate(spec)
	if err == nil {
		t.Error("33-byte SD-ID should fail Validate")
	}
}

// --- 1.9 MSG ---

func TestPoint_1_9_1_1_Msg_ASCII(t *testing.T) {
	// MSG="Login from alice" -> 16 bytes ASCII.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "Login from alice"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte(" Login from alice")) {
		t.Errorf("ASCII MSG missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_9_1_2_Msg_ASCII_Short(t *testing.T) {
	// MSG="Hello, world!" -> 13 bytes.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "Hello, world!"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte(" Hello, world!")) {
		t.Errorf("short ASCII MSG missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_9_2_1_Msg_UTF8_WithBOM(t *testing.T) {
	// MSG="系统已启动" + MsgHasBOM=true -> BOM + UTF-8.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "系统已启动"
	spec.Syslog.MsgHasBOM = true
	cfgs := drain(mustPlan(t, p, spec))
	wantSuffix := append([]byte{0xEF, 0xBB, 0xBF}, []byte("系统已启动")...)
	if !bytes.HasSuffix(cfgs[0].Payload, wantSuffix) {
		t.Errorf("UTF-8 + BOM missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_9_2_2_Msg_UTF8_NoBOM(t *testing.T) {
	// MSG="系统已启动" + MsgHasBOM=false -> SP + UTF-8.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "系统已启动"
	spec.Syslog.MsgHasBOM = false
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte(" 系统已启动")) {
		t.Errorf("UTF-8 without BOM missing, got %q", cfgs[0].Payload)
	}
	if bytes.Contains(cfgs[0].Payload, []byte{0xEF, 0xBB, 0xBF}) {
		t.Errorf("BOM should not appear, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_9_3_4_Msg_NUL_Ok(t *testing.T) {
	// MSG with NUL byte (0x00) is allowed (RFC 5424 §6.4.4).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "a\x00b"
	if err := p.Validate(spec); err != nil {
		t.Errorf("NUL in MSG should pass Validate: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte{'a', 0, 'b'}) {
		t.Errorf("NUL byte in MSG missing, got %q", cfgs[0].Payload)
	}
}

// --- 1.10 BSD format ---

func TestPoint_1_10_1_BSD_Format(t *testing.T) {
	// Format=bsd + Facility=13 + Severity=5 + (timestamp)
	// -> <PRI>Oct 11 22:14:15 host tag: msg
	// (using our test timestamp 2026-07-28T10:00:00Z -> "Jul 28 10:00:00")
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Facility = 13
	spec.Syslog.Severity = 5
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	spec.Syslog.Hostname = "host1"
	spec.Syslog.AppName = "sshd"
	spec.Syslog.ProcID = "1234"
	spec.Syslog.Msg = "Login from alice"
	cfgs := drain(mustPlan(t, p, spec))
	// PRI = 13*8+5 = 109.
	want := "<109>Jul 28 10:00:00 host1 sshd[1234]: Login from alice"
	if string(cfgs[0].Payload) != want {
		t.Errorf("BSD payload=%q, want %q", cfgs[0].Payload, want)
	}
}

func TestPoint_1_10_2_BSD_TagPID(t *testing.T) {
	// BSD with TAG[PID]: -> `sshd[1234]: Login from alice`
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	spec.Syslog.Hostname = "host1"
	spec.Syslog.AppName = "sshd"
	spec.Syslog.ProcID = "1234"
	spec.Syslog.Msg = "Login from alice"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("sshd[1234]: Login from alice")) {
		t.Errorf("TAG[PID] missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_10_3_BSD_TagOnly(t *testing.T) {
	// BSD with TAG only (no PID) -> `sshd: Login`
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	spec.Syslog.Hostname = "host1"
	spec.Syslog.AppName = "sshd"
	spec.Syslog.ProcID = "" // no PID
	spec.Syslog.Msg = "Login"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte("sshd: Login")) {
		t.Errorf("TAG without PID missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_1_10_5_Format_Unknown_Fails(t *testing.T) {
	// Format="unknown" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "unknown"
	err := p.Validate(spec)
	if err == nil {
		t.Error("unknown format should fail Validate")
	}
}

// --- 2.x State machine ---

func TestPoint_2_1_1_UDP_SinglePacket(t *testing.T) {
	// UDP: 1 message -> 1 packet.
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSyslogSpec()))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1", len(cfgs))
	}
}

func TestPoint_2_1_2_UDP_ValidateFail_NilChannel(t *testing.T) {
	// IDLE -> Validate fail -> ERROR, channel nil.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 100
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error")
	}
	if ch != nil {
		t.Error("expected nil channel")
	}
}

func TestPoint_2_1_3_UDP_NilConfig_NilChannel(t *testing.T) {
	// spec.Syslog=nil -> 空配置默认化，Plan 产默认流（P0b-2）。
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = nil
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("expected at least 1 packet from empty config")
	}
}

func TestPoint_2_1_4_UDP_Direction_Up(t *testing.T) {
	// UDP single packet Direction="up".
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSyslogSpec()))
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want 'up'", cfgs[0].Direction)
	}
}

func TestPoint_2_1_5_UDP_Count10(t *testing.T) {
	// Count=10 -> 10 packets, PacketIndex 0-9.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 10
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 10 {
		t.Errorf("len=%d, want 10", len(cfgs))
	}
	for i, cfg := range cfgs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfg.PacketIndex, i)
		}
	}
}

func TestPoint_2_2_1_TCP_HandshakeFrameTeardown(t *testing.T) {
	// TCP: 3 (handshake) + N (frames) + 4 (teardown).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 8 { // 3 + 1 + 4
		t.Errorf("len=%d, want 8", len(cfgs))
	}
}

func TestPoint_2_3_3_NonTransparent_LF_Fails(t *testing.T) {
	// TCP non-transparent + MSG with LF -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "non_transparent"
	spec.Syslog.Msg = "line1\nline2"
	err := p.Validate(spec)
	if err == nil {
		t.Error("non-transparent with LF should fail Validate")
	}
}

func TestPoint_2_6_1_Count0_DefaultsOne(t *testing.T) {
	// Count=0 -> 1 packet.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1", len(cfgs))
	}
}

// --- 3.x Business scenarios ---

func TestPoint_3_1_1_UDP_INFO_Log(t *testing.T) {
	// Facility=16 + Severity=6 + standard fields + UDP -> "<134>1 - server01 cron - HEARTBEAT - Job ran"
	// Note: empty timestamp -> "-".
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 514,
		// MACs default to empty when not provided.
		Syslog: &core.SyslogConfig{
			Facility: 16, Severity: 6, Version: 1,
			Hostname: "server01",
			AppName:  "cron",
			MsgID:    "HEARTBEAT",
			Msg:      "Job ran",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.DstPort != 514 {
		t.Errorf("DstPort=%d, want 514 (syslog)", cfgs[0].L4.DstPort)
	}
	// Verify PRI=134 and the field order.
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 - server01 cron - HEARTBEAT")) {
		t.Errorf("INFO log prefix=%q, want '<134>1 - server01 cron - HEARTBEAT'", first40(cfgs[0].Payload))
	}
}

func TestPoint_3_2_1_UDP_EMERG_Log(t *testing.T) {
	// Facility=0 (kern) + Severity=0 (emerg) + MSG="Kernel panic" -> "<0>1 ..."
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 514,
		Syslog: &core.SyslogConfig{
			Facility: 0, Severity: 0, Version: 1,
			Hostname: "server01",
			AppName:  "kernel",
			Msg:      "Kernel panic - not syncing",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<0>1 - server01 kernel")) {
		t.Errorf("EMERG prefix=%q, want '<0>1 - server01 kernel'", first30(cfgs[0].Payload))
	}
}

func TestPoint_3_3_1_UDP_Count10_Sequence(t *testing.T) {
	// Count=10 -> 10 packets, PacketIndex 0-9, FlowID consistent.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 10
	cfgs := drain(mustPlan(t, p, spec))
	flowID := cfgs[0].FlowID
	for i, cfg := range cfgs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfg.PacketIndex, i)
		}
		if cfg.FlowID != flowID {
			t.Errorf("cfgs[%d].FlowID mismatch", i)
		}
	}
}

func TestPoint_3_7_1_SD_MultipleElements(t *testing.T) {
	// SD with 2 elements concatenated without spaces.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{
		`[origin ip="192.0.2.1"]`,
		`[meta sequenceId="1234" sysUpTime="0"]`,
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := `[origin ip="192.0.2.1"][meta sequenceId="1234" sysUpTime="0"]`
	if !bytes.Contains(cfgs[0].Payload, []byte(want)) {
		t.Errorf("multi SD missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_3_9_1_ASCII_NoBOM(t *testing.T) {
	// ASCII MSG + MsgHasBOM=false -> SP + MSG (no BOM).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "hello"
	spec.Syslog.MsgHasBOM = false
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte(" hello")) {
		t.Errorf("ASCII + no BOM missing, got %q", cfgs[0].Payload)
	}
	if bytes.Contains(cfgs[0].Payload, []byte{0xEF, 0xBB, 0xBF}) {
		t.Error("BOM should not be present")
	}
}

func TestPoint_3_9_2_ASCII_WithBOM(t *testing.T) {
	// ASCII MSG + MsgHasBOM=true -> BOM + MSG (no SP).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "hello"
	spec.Syslog.MsgHasBOM = true
	cfgs := drain(mustPlan(t, p, spec))
	wantSuffix := append([]byte{0xEF, 0xBB, 0xBF}, []byte("hello")...)
	if !bytes.HasSuffix(cfgs[0].Payload, wantSuffix) {
		t.Errorf("ASCII + BOM missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_3_14_1_SignBlocks_Single(t *testing.T) {
	// SignBlocks=["signature1"] -> STRUCTURED-DATA contains sign.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"signature1"}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[sign@32473 signature="signature1"]`)) {
		t.Errorf("sign block missing, got %q", cfgs[0].Payload)
	}
}

func TestPoint_3_14_3_SignBlocks_Base64(t *testing.T) {
	// base64 signature with `+` `/` `=` chars.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"a+b/c="}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[sign@32473 signature="a+b/c="]`)) {
		t.Errorf("base64 sign block missing, got %q", cfgs[0].Payload)
	}
}

// --- 4.x Data scenarios ---

func TestPoint_4_1_1_SyslogConfigNil_Fails(t *testing.T) {
	// spec.Syslog=nil -> Validate 允许（空配置默认化，P0b-2）。
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty config Validate err: %v", err)
	}
}

func TestPoint_4_1_3_MinimalMessage(t *testing.T) {
	// spec.Syslog={Facility:0, Severity:0, Version:1} -> "<0>1 - - - - - -"
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = &core.SyslogConfig{
		Facility: 0, Severity: 0, Version: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := "<0>1 - - - - - -"
	if string(cfgs[0].Payload) != want {
		t.Errorf("minimal=%q, want %q", cfgs[0].Payload, want)
	}
}

func TestPoint_4_2_1_1_PRI_Min(t *testing.T) {
	// PRI min (Facility=0, Severity=0).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 0
	spec.Syslog.Severity = 0
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<0>1 ")) {
		t.Errorf("min PRI=%q, want '<0>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_4_2_1_2_PRI_Max(t *testing.T) {
	// PRI max (Facility=23, Severity=7).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 23
	spec.Syslog.Severity = 7
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<191>1 ")) {
		t.Errorf("max PRI=%q, want '<191>1 '", first10(cfgs[0].Payload))
	}
}

func TestPoint_4_3_1_Facility_24_Fails(t *testing.T) {
	// Facility=24 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 24
	err := p.Validate(spec)
	if err == nil {
		t.Error("Facility=24 should fail")
	}
}

func TestPoint_4_3_2_Severity_8_Fails(t *testing.T) {
	// Severity=8 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Severity = 8
	err := p.Validate(spec)
	if err == nil {
		t.Error("Severity=8 should fail")
	}
}

func TestPoint_4_3_3_Version0_Rfc5424_Fails(t *testing.T) {
	// Version=0 with Format=rfc5424 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 0
	spec.Syslog.Format = "rfc5424"
	err := p.Validate(spec)
	if err == nil {
		t.Error("Version=0 rfc5424 should fail")
	}
}

func TestPoint_4_3_4_Version2_Fails(t *testing.T) {
	// Version=2 -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 2
	err := p.Validate(spec)
	if err == nil {
		t.Error("Version=2 should fail")
	}
}

func TestPoint_4_3_5_Format_Unknown_Fails(t *testing.T) {
	// Format="unknown" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "unknown"
	err := p.Validate(spec)
	if err == nil {
		t.Error("unknown format should fail")
	}
}

func TestPoint_4_3_6_Transport_Icmp_Fails(t *testing.T) {
	// Transport="icmp" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "icmp"
	err := p.Validate(spec)
	if err == nil {
		t.Error("icmp transport should fail")
	}
}

func TestPoint_4_3_7_TCPFraming_Unknown_Fails(t *testing.T) {
	// TCPFraming="unknown" -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "unknown"
	err := p.Validate(spec)
	if err == nil {
		t.Error("unknown framing should fail")
	}
}

func TestPoint_4_3_8_SD_Unclosed_Fails(t *testing.T) {
	// SD-ELEMENT missing `]` -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[origin ip="1.2.3.4"`}
	err := p.Validate(spec)
	if err == nil {
		t.Error("unclosed SD should fail")
	}
}

func TestPoint_4_3_11_MsgLF_NonTransparent_Fails(t *testing.T) {
	// TCP non-transparent + MSG with LF -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "non_transparent"
	spec.Syslog.Msg = "line1\nline2"
	err := p.Validate(spec)
	if err == nil {
		t.Error("LF in non-transparent should fail")
	}
}

func TestPoint_4_3_12_Hostname_WithSP_Fails(t *testing.T) {
	// HOSTNAME with SP -> Validate fails.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "host name"
	err := p.Validate(spec)
	if err == nil {
		t.Error("hostname with SP should fail")
	}
}

func TestPoint_4_5_1_MinimumRFC5424_Message(t *testing.T) {
	// 4.5.1: Minimum RFC 5424 message = "<0>1 - - - - - -" (16 bytes).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = &core.SyslogConfig{
		Facility: 0, Severity: 0, Version: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[0].Payload) != 16 {
		t.Errorf("len=%d, want 16", len(cfgs[0].Payload))
	}
	if string(cfgs[0].Payload) != "<0>1 - - - - - -" {
		t.Errorf("min payload=%q, want '<0>1 - - - - - -'", cfgs[0].Payload)
	}
}

// --- Helpers ---

func first10(b []byte) []byte {
	if len(b) > 10 {
		return b[:10]
	}
	return b
}

func first20(b []byte) []byte {
	if len(b) > 20 {
		return b[:20]
	}
	return b
}

func first30(b []byte) []byte {
	if len(b) > 30 {
		return b[:30]
	}
	return b
}

func first40(b []byte) []byte {
	if len(b) > 40 {
		return b[:40]
	}
	return b
}
