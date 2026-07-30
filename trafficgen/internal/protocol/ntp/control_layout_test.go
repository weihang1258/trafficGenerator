package ntp

// Spec-driven tests for the Mode=6 control message wire layout per
// RFC 1305 Appendix B (NTP Control Message Header, Figure 5) and the ntpd
// reference implementation (ntp_control.h, struct ntp_control). Wireshark's
// dissect_ntp_ctrl reads exactly this 12-byte layout; the old 8-byte header
// produced [Malformed Packet: NTP].
//
// Canonical layout (RFC 1305 App. B / ntpd ntp_control.h):
//
//	byte 0:     LI(2) | VN(3) | Mode(3)         -- Mode=6
//	byte 1:     R(1) | E(1) | M(1) | OpCode(5)   -- R=response, E=error, M=more
//	bytes 2-3:  Sequence (16-bit, big-endian)
//	bytes 4-5:  Status (16-bit)
//	bytes 6-7:  Association ID (16-bit)
//	bytes 8-9:  Offset (16-bit)
//	bytes 10-11: Count (16-bit) = data length
//	bytes 12+:  Data (max 468 = CTL_MAX_DATA_LEN)

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestNTP_Control_RFC1305_HeaderLayout asserts the full 12-byte control header
// layout against RFC 1305 App. B. This FAILS against the old 8-byte layout
// (Sequence at byte 1, no AssocID/Offset, Count at bytes 6-7).
func TestNTP_Control_RFC1305_HeaderLayout(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:           ModeControl,
		Version:        4,
		Sequence:       7,
		RequestCode:    1, // CTL_OP_READVAR
		StatusWord:     0x1234,
		AssociationID:  42,
		Offset:         0,
		ControlData:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1", len(cfgs))
	}
	p := cfgs[0].Payload
	// Header must be 12 bytes + 4 data = 16 bytes (NOT the old 8+4=12).
	if want := ControlHeaderLen + 4; len(p) != want {
		t.Fatalf("payload len=%d, want %d (12-byte control header + 4 data)", len(p), want)
	}
	// Byte 0: LI(0)|VN(4)|Mode(6) = 0x26
	if p[0] != 0x26 {
		t.Errorf("byte[0]=0x%02x, want 0x26 (LI=0 VN=4 Mode=6)", p[0])
	}
	// Byte 1: R(0)|E(0)|M(0)|OpCode(1) = 0x01
	if p[1] != 0x01 {
		t.Errorf("byte[1]=0x%02x, want 0x01 (OpCode=1, R/E/M=0 for request)", p[1])
	}
	// Bytes 2-3: Sequence = 7 (big-endian)
	if got := binary.BigEndian.Uint16(p[2:4]); got != 7 {
		t.Errorf("Sequence=0x%04x, want 7", got)
	}
	// Bytes 4-5: Status = 0x1234
	if got := binary.BigEndian.Uint16(p[4:6]); got != 0x1234 {
		t.Errorf("Status=0x%04x, want 0x1234", got)
	}
	// Bytes 6-7: Association ID = 42
	if got := binary.BigEndian.Uint16(p[6:8]); got != 42 {
		t.Errorf("AssociationID=%d, want 42", got)
	}
	// Bytes 8-9: Offset = 0
	if got := binary.BigEndian.Uint16(p[8:10]); got != 0 {
		t.Errorf("Offset=%d, want 0", got)
	}
	// Bytes 10-11: Count = 4 (data length)
	if got := binary.BigEndian.Uint16(p[10:12]); got != 4 {
		t.Errorf("Count=%d, want 4 (data length)", got)
	}
	// Bytes 12+: Data
	if !bytes.Equal(p[12:], []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("Data=%v, want DEADBEEF", p[12:])
	}
}

// TestNTP_Control_HeaderLenIs12 verifies the control header constant is 12
// (not 8). The old non-standard layout used 8.
func TestNTP_Control_HeaderLenIs12(t *testing.T) {
	if ControlHeaderLen != 12 {
		t.Errorf("ControlHeaderLen=%d, want 12 per RFC 1305 App. B", ControlHeaderLen)
	}
}

// TestNTP_Control_MaxDataIs468 verifies the max Data region matches ntpd
// CTL_MAX_DATA_LEN (468) and Wireshark's "Data (468 octets max)".
func TestNTP_Control_MaxDataIs468(t *testing.T) {
	if MaxControlData != 468 {
		t.Errorf("MaxControlData=%d, want 468 (ntpd CTL_MAX_DATA_LEN)", MaxControlData)
	}
}

// TestNTP_Control_ResponseSetsRBit verifies the Response bit (byte 1 bit 7) is
// set on responses and clear on requests, per RFC 1305 App. B.
func TestNTP_Control_ResponseSetsRBit(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		IsResponse:  true,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (request+response)", len(cfgs))
	}
	if cfgs[0].Payload[1]&0x80 != 0 {
		t.Errorf("request R bit set, want 0 (request)")
	}
	if cfgs[1].Payload[1]&0x80 == 0 {
		t.Errorf("response R bit not set, want 0x80 (response)")
	}
}

// TestNTP_Control_ErrorBitPosition verifies the Error bit lives in byte 1
// bit 6 (0x40), NOT in the Status word (the old layout put it at Status bit 15).
func TestNTP_Control_ErrorBitPosition(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		IsResponse:  true,
		Error:       true,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[1].Payload[1]&0x40 == 0 {
		t.Errorf("response Error bit (byte[1]&0x40) not set, want set")
	}
}

// TestNTP_Control_MoreBitPosition verifies the More bit lives in byte 1 bit 5.
func TestNTP_Control_MoreBitPosition(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		More:        true,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[0].Payload[1]&0x20 == 0 {
		t.Errorf("More bit (byte[1]&0x20) not set, want set")
	}
}

// TestNTP_Control_OpCode5Bits verifies OpCode is masked to 5 bits and that
// Validate rejects values > 31 (cannot encode in 5 bits without truncation).
func TestNTP_Control_OpCode5Bits(t *testing.T) {
	t.Run("valid opcode 31", func(t *testing.T) {
		spec := validNTPSpec()
		spec.NTP = &core.NTPConfig{
			Mode:        ModeControl,
			Version:     4,
			Sequence:    1,
			RequestCode: 31,
		}
		cfgs := drain(mustPlan(t, NewPlanner(), spec))
		if got := cfgs[0].Payload[1] & 0x1F; got != 31 {
			t.Errorf("OpCode=0x%02x, want 0x1F", got)
		}
	})
	t.Run("opcode 32 rejected by Validate", func(t *testing.T) {
		p := NewPlanner()
		spec := validNTPSpec()
		spec.NTP = &core.NTPConfig{
			Mode:        ModeControl,
			Version:     4,
			Sequence:    1,
			RequestCode: 32,
		}
		if err := p.Validate(spec); err == nil {
			t.Error("Validate(RequestCode=32): expected error (OpCode is 5 bits, max 31)")
		}
	})
}

// TestNTP_Control_Sequence16Bit verifies a Sequence > 255 is encoded correctly
// in the 16-bit field (the old layout used an 8-bit field and could not hold it).
func TestNTP_Control_Sequence16Bit(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    300,
		RequestCode: 1,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if got := binary.BigEndian.Uint16(cfgs[0].Payload[2:4]); got != 300 {
		t.Errorf("Sequence=%d, want 300 (16-bit field)", got)
	}
}

// TestNTP_Control_AssocIDAndOffsetPropagate verifies AssociationID and Offset
// fields are emitted at bytes 6-7 and 8-9 respectively.
func TestNTP_Control_AssocIDAndOffsetPropagate(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:          ModeControl,
		Version:       4,
		Sequence:      1,
		RequestCode:   1,
		AssociationID: 0x0100,
		Offset:        0x0200,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	p := cfgs[0].Payload
	if got := binary.BigEndian.Uint16(p[6:8]); got != 0x0100 {
		t.Errorf("AssociationID=0x%04x, want 0x0100", got)
	}
	if got := binary.BigEndian.Uint16(p[8:10]); got != 0x0200 {
		t.Errorf("Offset=0x%04x, want 0x0200", got)
	}
}

// TestNTP_Control_EmptyData verifies a control message with no Data still has
// a 12-byte header and Count=0.
func TestNTP_Control_EmptyData(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	p := cfgs[0].Payload
	if len(p) != ControlHeaderLen {
		t.Errorf("payload len=%d, want %d (12-byte header, no data)", len(p), ControlHeaderLen)
	}
	if got := binary.BigEndian.Uint16(p[10:12]); got != 0 {
		t.Errorf("Count=%d, want 0 (no data)", got)
	}
}
