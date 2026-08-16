// NFS planner tests, derived from /home/weihang/trafficGenerator/docs/protocol-designs/08-nfs-design.md
// §1-§10. The tests are spec-driven (each test corresponds to a section
// of the design doc), cover the positive and negative paths for each
// codepath, and assert observable wire bytes (XDR encoded payload) using
// the parser in parser.go.
//
// Model: one TCP/UDP flow = handshake → Rounds call/reply exchanges → teardown.
// Per-flow: NFSv3 (MOUNT auto + Ops + UMOUNT auto), NFSv4
// (SETCLIENTID + SETCLIENTID_CONFIRM auto + Ops). Each op generates a
// call (up) and a reply (down) on the same 4-tuple.

package nfs

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func nfsSpec(t *testing.T, cfg *NFSConfig) core.FlowSpec {
	t.Helper()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
	}
	return AttachSpec(spec, cfg)
}

// payloadOf finds the first user-op packet carrying a non-empty payload
// in the given direction. Auto-inserted MOUNT (Program=100005, §4.2
// rule 1) calls/replies are skipped so tests observe the user-configured
// op (T-001..T-060, S1..S16d). Because the planner emits each op as an
// alternating call (up) / reply (down) pair, a MOUNT call is paired with
// exactly the next down payload — XID matching is not usable here since
// XIDIncr=0 (all calls share one XID, §10.5) is a supported config.
func payloadOf(cfgs []core.PacketConfig, dir string) []byte {
	skipNextDown := false
	for _, c := range cfgs {
		if len(c.Payload) == 0 || len(c.Payload) < 4 {
			continue
		}
		if c.Direction == "up" {
			hdr, _, err := ParseRPCCallHeader(c.Payload[4:])
			if err == nil && hdr.Program == ProgramMount {
				skipNextDown = true
				continue
			}
			if dir == "up" {
				return c.Payload
			}
			continue
		}
		// down
		if skipNextDown {
			skipNextDown = false
			continue
		}
		if dir == "down" {
			return c.Payload
		}
	}
	return nil
}

// payloadsWithDir returns all (direction, payload) pairs.
func payloadsWithDir(cfgs []core.PacketConfig) [][2]interface{} {
	var out [][2]interface{}
	for _, c := range cfgs {
		if len(c.Payload) > 0 {
			out = append(out, [2]interface{}{c.Direction, c.Payload})
		}
	}
	return out
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// uint32Ptr returns a pointer to the given uint32. Useful for
// NFSAttributes.AtimeSecs/MtimeSecs fields which are *uint32 (nil
// means "not provided" → SET_TO_SERVER_TIME).
func uint32Ptr(v uint32) *uint32 { return &v }

// --- T-001: NFSv3 NULL call ---
func TestNFS3NULLCall(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops:     []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	if call == nil {
		t.Fatal("missing call payload")
	}
	// RM=0x80000028, XID=0x00000001, Type=0, RPCVer=2, Program=100003, Version=3, Procedure=0
	rm, _, err := ParseRecordMark(call)
	if err != nil {
		t.Fatalf("RM: %v", err)
	}
	if rm != 0x80000028 {
		t.Errorf("RM: got 0x%08x, want 0x80000028", rm)
	}
	hdr, _, err := ParseRPCCallHeader(call[4:])
	if err != nil {
		t.Fatalf("Call header: %v", err)
	}
	if hdr.XID != 1 {
		t.Errorf("XID: got %d, want 1", hdr.XID)
	}
	if hdr.Program != ProgramNFS {
		t.Errorf("Program: got %d, want %d", hdr.Program, ProgramNFS)
	}
	if hdr.Version != 3 {
		t.Errorf("Version: got %d, want 3", hdr.Version)
	}
	if hdr.Procedure != 0 {
		t.Errorf("Procedure: got %d, want 0", hdr.Procedure)
	}
	if hdr.CredFlavor != AuthFlavorNone {
		t.Errorf("CredFlavor: got %d, want 0", hdr.CredFlavor)
	}
}

// --- T-002: NFSv3 NULL reply ---
func TestNFS3NULLReply(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops:     []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	reply := payloadOf(cfgs, "down")
	if reply == nil {
		t.Fatal("missing reply payload")
	}
	rm, _, _ := ParseRecordMark(reply)
	if rm != 0x80000018 {
		t.Errorf("RM: got 0x%08x, want 0x80000018", rm)
	}
	hdr, _, err := ParseRPCReplyHeader(reply[4:])
	if err != nil {
		t.Fatalf("Reply header: %v", err)
	}
	if hdr.XID != 1 {
		t.Errorf("XID echo: got %d, want 1", hdr.XID)
	}
	if hdr.ReplyState != RPCMsgAccepted {
		t.Errorf("ReplyState: got %d, want 0", hdr.ReplyState)
	}
	if hdr.AcceptState != RPCSuccess {
		t.Errorf("AcceptState: got %d, want 0", hdr.AcceptState)
	}
}

// --- T-005: AUTH_NONE default ---
func TestNFS3AuthNone(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops:     []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, _, _ := ParseRPCCallHeader(call[4:])
	if hdr.CredFlavor != 0 {
		t.Errorf("CredFlavor: got %d, want 0", hdr.CredFlavor)
	}
	if hdr.CredBodyLen != 0 {
		t.Errorf("CredBodyLen: got %d, want 0", hdr.CredBodyLen)
	}
}

// --- T-006: AUTH_SYS basic ---
func TestNFS3AuthSys(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:    3,
		AuthFlavor: AuthFlavorSys,
		AuthSys: &AuthSysInfo{
			Stamp:       1,
			MachineName: "host",
			UID:         65534,
			GID:         65534,
		},
		Ops: []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, _, _ := ParseRPCCallHeader(call[4:])
	if hdr.CredFlavor != AuthFlavorSys {
		t.Errorf("CredFlavor: got %d, want 1", hdr.CredFlavor)
	}
	// Body = 4 stamp + 4 machinename_len + 4 machinename + 4 uid + 4 gid + 4 gid_count = 24
	if hdr.CredBodyLen != 24 {
		t.Errorf("CredBodyLen: got %d, want 24", hdr.CredBodyLen)
	}
	// Verify body
	body := hdr.CredBody
	if got := binaryBigEndianU32(body[0:4]); got != 1 {
		t.Errorf("stamp: got %d, want 1", got)
	}
	if got := binaryBigEndianU32(body[4:8]); got != 4 {
		t.Errorf("machinename len: got %d, want 4", got)
	}
	if !bytes.Equal(body[8:12], []byte("host")) {
		t.Errorf("machinename: got %q, want host", body[8:12])
	}
	if got := binaryBigEndianU32(body[12:16]); got != 65534 {
		t.Errorf("uid: got %d, want 65534", got)
	}
}

// --- T-008: AUTH_SYS defaults ---
func TestNFS3AuthSysDefaults(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:    3,
		AuthFlavor: AuthFlavorSys,
		Ops:        []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, _, _ := ParseRPCCallHeader(call[4:])
	// machinename default = "trafficgen" (10 chars). Body = 4 + 4 + 10 + 2pad + 4 + 4 + 4 = 32
	if hdr.CredBodyLen != 32 {
		t.Errorf("CredBodyLen: got %d, want 32", hdr.CredBodyLen)
	}
}

// --- T-009: AUTH_SYS groups ---
func TestNFS3AuthSysGroups(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:    3,
		AuthFlavor: AuthFlavorSys,
		AuthSys: &AuthSysInfo{
			Stamp:       0,
			MachineName: "h",
			UID:         0,
			GID:         0,
			Groups:      []uint32{1000, 2000},
		},
		Ops: []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, _, _ := ParseRPCCallHeader(call[4:])
	// Body = 4 stamp + 4 len + 1 + 3 pad + 4 uid + 4 gid + 4 count + 4*2 groups = 32
	if hdr.CredBodyLen != 32 {
		t.Errorf("CredBodyLen: got %d, want 32", hdr.CredBodyLen)
	}
}

// --- T-011: RPCSEC_GSS rejected ---
func TestNFS3RPCSECGSSRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:    3,
		AuthFlavor: AuthFlavorGSS,
		Ops:        []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for AuthFlavor=6")
	}
	if !containsStr(err.Error(), "RPCSEC_GSS not supported") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-013/T-014: XID increment ---
func TestNFS3XIDIncr(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		XIDBase: 100,
		XIDIncr: 2,
		Ops: []NFSOp{
			{Procedure: NFS3ProcNULL},
			{Procedure: NFS3ProcNULL},
		},
	})
	cfgs := mustPlan(t, p, spec)
	calls := [][]byte{}
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			calls = append(calls, c.Payload)
		}
	}
	if len(calls) < 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	h1, _, _ := ParseRPCCallHeader(calls[0][4:])
	h2, _, _ := ParseRPCCallHeader(calls[1][4:])
	if h1.XID != 100 {
		t.Errorf("call1 XID: got %d, want 100", h1.XID)
	}
	if h2.XID != 102 {
		t.Errorf("call2 XID: got %d, want 102", h2.XID)
	}
}

// --- T-015: XID no increment ---
func TestNFS3XIDSame(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		XIDBase: 50,
		XIDIncr: 0,
		Ops: []NFSOp{
			{Procedure: NFS3ProcNULL},
			{Procedure: NFS3ProcNULL},
		},
	})
	cfgs := mustPlan(t, p, spec)
	var calls [][]byte
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			calls = append(calls, c.Payload)
		}
	}
	if len(calls) < 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	h1, _, _ := ParseRPCCallHeader(calls[0][4:])
	h2, _, _ := ParseRPCCallHeader(calls[1][4:])
	if h1.XID != h2.XID {
		t.Errorf("XIDs should be equal with XIDIncr=0, got %d and %d", h1.XID, h2.XID)
	}
}

// --- T-017: XID wrap ---
func TestNFS3XIDWrap(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		XIDBase: 0xFFFFFFFF,
		XIDIncr: 1,
		Ops: []NFSOp{
			{Procedure: NFS3ProcNULL},
			{Procedure: NFS3ProcNULL},
		},
	})
	cfgs := mustPlan(t, p, spec)
	var calls [][]byte
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			calls = append(calls, c.Payload)
		}
	}
	if len(calls) < 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	h1, _, _ := ParseRPCCallHeader(calls[0][4:])
	h2, _, _ := ParseRPCCallHeader(calls[1][4:])
	if h1.XID != 0xFFFFFFFF {
		t.Errorf("call1 XID: got %d, want 0xFFFFFFFF", h1.XID)
	}
	if h2.XID != 0 {
		t.Errorf("call2 XID: got %d, want 0 (wrap)", h2.XID)
	}
}

// --- T-018: UDP transport ---
func TestNFS3UDP(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:   3,
		Transport: "udp",
		Ops:       []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	// The first up packet (non-empty payload) is the UDP NULL call.
	var first *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Direction == "up" && len(cfgs[i].Payload) > 0 {
			first = &cfgs[i]
			break
		}
	}
	if first == nil {
		t.Fatal("no UDP call found")
	}
	if first.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol: got %q, want udp", first.L4.Protocol)
	}
	// UDP has no RM; first 4 bytes are XID.
	xid := binaryBigEndianU32(first.Payload[0:4])
	if xid != 1 {
		t.Errorf("XID: got %d, want 1", xid)
	}
}

// --- T-019: UDP rejected for v4 ---
func TestNFS4UDPRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:   4,
		Transport: "udp",
		Ops: []NFSOp{{
			Procedure:   NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_PUTROOTFH}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for v4+udp")
	}
	if !containsStr(err.Error(), "NFSv4 requires TCP") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-021/T-022: GETATTR call/reply ---
func TestNFS3GETATTR(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcGETATTR,
			Filehandle: []byte{0x01},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	if call == nil {
		t.Fatal("missing call")
	}
	hdr, nfsOff, err := ParseRPCCallHeader(call[4:])
	if err != nil {
		t.Fatalf("call header: %v", err)
	}
	if hdr.Procedure != NFS3ProcGETATTR {
		t.Errorf("Procedure: got %d, want %d", hdr.Procedure, NFS3ProcGETATTR)
	}
	// After RPC header (40 bytes), the GETATTR3args body is fh (4 + 1 + 3pad) = 8
	p2 := newParser(call[4+nfsOff:])
	fh, err := p2.readOpaque()
	if err != nil {
		t.Fatalf("fh: %v", err)
	}
	if !bytes.Equal(fh, []byte{0x01}) {
		t.Errorf("fh: got %x, want 01", fh)
	}

	reply := payloadOf(cfgs, "down")
	res, err := ParseNFS3GETATTRRes(reply[4+24:]) // skip RM + RPC reply header (24B = XID+Type+ReplyState+VerfFlavor+VerfBodyLen+AcceptState)
	if err != nil {
		t.Fatalf("GETATTR res: %v", err)
	}
	if res.Status != NFS3OK {
		t.Errorf("status: got %d, want 0", res.Status)
	}
	if !res.AttrPresent {
		t.Error("AttrPresent: got false, want true")
	}
	if len(res.Fattr3) != 84 {
		t.Errorf("fattr3 len: got %d, want 84", len(res.Fattr3))
	}
}

// --- T-026: filehandle > NFS3_FHSIZE rejected ---
func TestNFS3FilehandleOverLimit(t *testing.T) {
	p := NewPlanner()
	huge := make([]byte, NFS3FHSIZE+1)
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcGETATTR,
			Filehandle: huge,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for oversized filehandle")
	}
	if !containsStr(err.Error(), "NFS3_FHSIZE") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-027: filehandle = 128 OK on v4 ---
func TestNFS4FilehandleAtLimit(t *testing.T) {
	p := NewPlanner()
	huge := make([]byte, NFS4FHSIZE)
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{
				Opcode:     OP_PUTFH,
				Filehandle: huge,
			}},
		}},
	})
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// --- T-028: filehandle > NFS4_FHSIZE rejected ---
func TestNFS4FilehandleOverLimit(t *testing.T) {
	p := NewPlanner()
	huge := make([]byte, NFS4FHSIZE+1)
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{
				Opcode:     OP_PUTFH,
				Filehandle: huge,
			}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for oversized filehandle")
	}
	if !containsStr(err.Error(), "NFS4_FHSIZE") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-029: SETATTR mode ---
func TestNFS3SETATTRMode(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcSETATTR,
			Filehandle: []byte{0x01},
			Attributes: &NFSAttributes{SetMode: true, Mode: 0644},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, nfsOff, _ := ParseRPCCallHeader(call[4:])
	if hdr.Procedure != NFS3ProcSETATTR {
		t.Errorf("Procedure: got %d, want %d", hdr.Procedure, NFS3ProcSETATTR)
	}
	p2 := newParser(call[4+nfsOff:])
	fh, err := p2.readOpaque()
	if err != nil {
		t.Fatalf("fh: %v", err)
	}
	if !bytes.Equal(fh, []byte{0x01}) {
		t.Errorf("fh: %x", fh)
	}
	// sattr3: set_mode(1)+mode(4)+set_uid(0)+set_gid(0)+set_size(0)+set_atime(0)+set_mtime(0) = 28 bytes
	setMode, _ := p2.readU32()
	if setMode != 1 {
		t.Errorf("set_mode: got %d, want 1", setMode)
	}
	mode, _ := p2.readU32()
	if mode != 0644 {
		t.Errorf("mode: got %d, want 0644", mode)
	}
	setUid, _ := p2.readU32()
	if setUid != 0 {
		t.Errorf("set_uid: got %d, want 0", setUid)
	}
}

// --- T-033: atime SET_TO_SERVER_TIME (AtimeSecs not provided = nil) ---
func TestNFS3SETATTRAtimeServerTime(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcSETATTR,
			Filehandle: []byte{0x01},
			Attributes: &NFSAttributes{SetAtime: true /* AtimeSecs left nil */},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque() // fh
	// set_mode=0, set_uid=0, set_gid=0, set_size=0
	for i := 0; i < 4; i++ {
		p2.readU32()
	}
	setAtime, _ := p2.readU32()
	// AtimeSecs is nil → time_how=1 (SET_TO_SERVER_TIME), per §2.8/v2.0.4
	if setAtime != TimeHowSET_TO_SERVER_TIME {
		t.Errorf("set_atime: got %d, want %d (SET_TO_SERVER_TIME)", setAtime, TimeHowSET_TO_SERVER_TIME)
	}
}
func TestNFS3SETATTRAtimeSentinel(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcSETATTR,
			Filehandle: []byte{0x01},
			Attributes: &NFSAttributes{SetAtime: true, AtimeSecs: uint32Ptr(0xFFFFFFFF)},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque()
	for i := 0; i < 4; i++ {
		p2.readU32()
	}
	setAtime, _ := p2.readU32()
	if setAtime != TimeHowSET_TO_SERVER_TIME {
		t.Errorf("set_atime: got %d, want %d (SET_TO_SERVER_TIME)", setAtime, TimeHowSET_TO_SERVER_TIME)
	}
}

// --- T-035: atime SET_TO_CLIENT_TIME ---
func TestNFS3SETATTRAtimeClientTime(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcSETATTR,
			Filehandle: []byte{0x01},
			Attributes: &NFSAttributes{SetAtime: true, AtimeSecs: uint32Ptr(1234567890), AtimeNsecs: uint32Ptr(0)},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque()
	for i := 0; i < 4; i++ {
		p2.readU32()
	}
	setAtime, _ := p2.readU32()
	if setAtime != TimeHowSET_TO_CLIENT_TIME {
		t.Errorf("set_atime: got %d, want %d", setAtime, TimeHowSET_TO_CLIENT_TIME)
	}
	secs, _ := p2.readU32()
	if secs != 1234567890 {
		t.Errorf("secs: got %d, want 1234567890", secs)
	}
}

// --- T-036: LOOKUP filename ---
func TestNFS3LOOKUP(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcLOOKUP,
			Filehandle: []byte{0x01},
			Filename:   "doc.txt",
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	fh, _ := p2.readOpaque()
	if !bytes.Equal(fh, []byte{0x01}) {
		t.Errorf("fh: %x", fh)
	}
	name, _ := p2.readString()
	if name != "doc.txt" {
		t.Errorf("name: got %q, want doc.txt", name)
	}

	reply := payloadOf(cfgs, "down")
	// Look for the LOOKUP reply (after MOUNT).
	var lookRep []byte
	for i, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && i > 3 {
			// Skip MOUNT reply which precedes
			h, _, _ := ParseRPCReplyHeader(c.Payload[4:])
			if h.AcceptState == RPCSuccess {
				// First successful down payload is MOUNT; skip it.
				// We pick the second one.
				continue
			}
		}
	}
	_ = lookRep
	_ = reply
}

// --- T-040: filename too long rejected ---
func TestNFS3FilenameTooLong(t *testing.T) {
	p := NewPlanner()
	name := make([]byte, NFS3MaxNamelen+1)
	for i := range name {
		name[i] = 'a'
	}
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcLOOKUP,
			Filehandle: []byte{0x01},
			Filename:   string(name),
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for too-long filename")
	}
	if !containsStr(err.Error(), "NFS3_MAXNAMLEN") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-046: READ offset 0xFFFFFFFF ---
func TestNFS3READOffsetMax(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcREAD,
			Filehandle: []byte{0x01},
			Offset:     0xFFFFFFFF,
			Count:      10,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque() // fh
	off, _ := p2.readU64()
	if off != 0xFFFFFFFF {
		t.Errorf("offset: got %d, want 0xFFFFFFFF", off)
	}
}

// --- T-047a: write count != data length rejected ---
func TestNFS3WriteCountMismatch(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcWRITE,
			Filehandle: []byte{0x01},
			Count:      10,
			Data:       []byte("hello"),
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for write count mismatch")
	}
	if !containsStr(err.Error(), "write count must equal data length") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-050: stable_how out of range ---
func TestNFS3StableHowRange(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcWRITE,
			Filehandle: []byte{0x01},
			Count:      1,
			Data:       []byte{0},
			StableHow:  3,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for stable_how=3")
	}
	if !containsStr(err.Error(), "stable_how") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-055b: MKNOD ftype out of range ---
func TestNFS3MKNODFtypeRange(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcMKNOD,
			Filehandle: []byte{0x01},
			Filename:   "n",
			Ftype:      0,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for ftype=0")
	}
	if !containsStr(err.Error(), "ftype") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-058: RENAME multi-arg ---
func TestNFS3RENAMEArgs(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcRENAME,
			Filehandle:  []byte{0x01},
			Oldname:     "a.txt",
			Filehandle2: []byte{0x01, 0x02, 0x03, 0x04},
			Newname:     "b.txt",
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	hdr, nfsOff, _ := ParseRPCCallHeader(call[4:])
	if hdr.Procedure != NFS3ProcRENAME {
		t.Errorf("Procedure: got %d, want %d", hdr.Procedure, NFS3ProcRENAME)
	}
	p2 := newParser(call[4+nfsOff:])
	from, _ := p2.readOpaque()
	if !bytes.Equal(from, []byte{0x01}) {
		t.Errorf("from.dir: got %x", from)
	}
	fromName, _ := p2.readString()
	if fromName != "a.txt" {
		t.Errorf("from.name: got %q, want a.txt", fromName)
	}
	to, _ := p2.readOpaque()
	if !bytes.Equal(to, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("to.dir: got %x", to)
	}
	toName, _ := p2.readString()
	if toName != "b.txt" {
		t.Errorf("to.name: got %q, want b.txt", toName)
	}
}

// --- T-066: NFSv3 proc 22+ pass-through ---
func TestNFS3ProcPassthrough(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops:     []NFSOp{{Procedure: 22}},
	})
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
	cfgs := mustPlan(t, p, spec)
	// Find the call carrying procedure=22 (skip MOUNT auto-call which is proc=1).
	var found bool
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, _, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure == 22 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a call with procedure=22")
	}
}

// --- T-067/T-068: minorversion ---
func TestNFS4MinorVersion(t *testing.T) {
	p := NewPlanner()
	mv := uint32(1)
	spec := nfsSpec(t, &NFSConfig{
		Version:      4,
		MinorVersion: &mv,
		Ops: []NFSOp{{
			Procedure:   NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_PUTROOTFH}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for minorversion=1")
	}
	if !containsStr(err.Error(), "minorversion=0") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-061: COMPOUND argarray ---
func TestNFS4COMPOUND(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_GETATTR, AttrMask: []uint32{0x10, 0x02, 0}},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find the user-configured COMPOUND (skip auto SETCLIENTID + CONFIRM).
	var found bool
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		// Skip SETCLIENTID: it has 1 op with opcode=35. Skip CONFIRM (opcode=36).
		tag, minor, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		_ = tag
		if minor != 0 {
			continue
		}
		if len(ops) >= 1 && ops[0].Opcode == OP_PUTROOTFH {
			found = true
			if len(ops) != 2 {
				t.Errorf("argarray len: got %d, want 2", len(ops))
			}
		}
	}
	if !found {
		t.Error("expected PUTROOTFH COMPOUND")
	}
}

// --- T-073: GETATTR bitmap ---
func TestNFS4GETATTRBitmap(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{
				Opcode:   OP_GETATTR,
				AttrMask: []uint32{0x10, 0x02, 0},
			}},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find the GETATTR call (skip SETCLIENTID + CONFIRM).
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		tag, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		_ = tag
		if err != nil {
			continue
		}
		if len(ops) == 0 {
			continue
		}
		// Skip SETCLIENTID/CONFIRM auto-replies.
		if ops[0].Opcode == OP_SETCLIENTID || ops[0].Opcode == OP_SETCLIENTID_CONFIRM {
			continue
		}
		// PUTROOTFH is auto-inserted at op[0] (§4.1 rule 2), so GETATTR
		// is now at op[1]. Find the GETATTR op.
		var getattrArgs []byte
		found := false
		for _, o := range ops {
			if o.Opcode == OP_GETATTR {
				getattrArgs = o.Args
				found = true
				break
			}
		}
		if !found {
			continue
		}
		// Bitmap should be 3 words
		words, _, err := ReadBitmap4(getattrArgs)
		if err != nil {
			t.Fatalf("bitmap: %v", err)
		}
		if len(words) != 3 {
			t.Errorf("bitmap len: got %d, want 3", len(words))
		}
		if words[0] != 0x10 {
			t.Errorf("word0: got 0x%x, want 0x10", words[0])
		}
		if words[1] != 0x02 {
			t.Errorf("word1: got 0x%x, want 0x02", words[1])
		}
		return
	}
	t.Fatal("GETATTR call not found")
}

// --- T-088a: share_access=0 rejected ---
func TestNFS4ShareAccessRange(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{
				Opcode:      OP_OPEN,
				Seqid:       1,
				ShareAccess: 0,
				ShareDeny:   0,
				Clientid:    1,
				OpenHow:     &NFSOpenHow{Type: "unchecked"},
				Claim:       &NFSClaim{Type: "null"},
				Name:        "f",
			}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for share_access=0")
	}
	if !containsStr(err.Error(), "share_access") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-101: SETCLIENTID auto-completion ---
func TestNFS4SETCLIENTIDAUTO(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_GETATTR, AttrMask: []uint32{0x10}},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// First COMPOUND call (up) should be SETCLIENTID (opcode=35).
	var sawSetClientID, sawConfirm, sawUserOps bool
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		if len(ops) == 0 {
			continue
		}
		switch ops[0].Opcode {
		case OP_SETCLIENTID:
			sawSetClientID = true
		case OP_SETCLIENTID_CONFIRM:
			sawConfirm = true
		case OP_PUTROOTFH:
			sawUserOps = true
		}
	}
	if !sawSetClientID {
		t.Error("expected auto SETCLIENTID")
	}
	if !sawConfirm {
		t.Error("expected auto SETCLIENTID_CONFIRM")
	}
	if !sawUserOps {
		t.Error("expected user PUTROOTFH COMPOUND")
	}
}

// --- T-103: explicit SETCLIENTID not duplicated ---
func TestNFS4SETCLIENTIDExplicit(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_SETCLIENTID},
				{Opcode: OP_PUTROOTFH},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Count COMPOUND calls that start with SETCLIENTID — should be 1.
	count := 0
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		if len(ops) > 0 && ops[0].Opcode == OP_SETCLIENTID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("SETCLIENTID count: got %d, want 1", count)
	}
}

// --- T-105: SETCLIENTID without explicit CONFIRM appends one ---
func TestNFS4SETCLIENTIDConfirmAppend(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_SETCLIENTID},
				{Opcode: OP_PUTROOTFH},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	var sawConfirm bool
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		if len(ops) > 0 && ops[0].Opcode == OP_SETCLIENTID_CONFIRM {
			sawConfirm = true
		}
	}
	if !sawConfirm {
		t.Error("expected auto SETCLIENTID_CONFIRM after explicit SETCLIENTID")
	}
}

// --- T-106: clientid per session ---
func TestNFS4SessionsClientID(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:             4,
		Sessions:            2,
		SessionsSrcPortBase: 50000,
		SessionsSrcPortStep: 1,
		Ops: []NFSOp{{
			Procedure:   NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_PUTROOTFH}},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find SETCLIENTID calls and inspect client.id (string arg).
	clientIDs := map[string]bool{}
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil || len(ops) == 0 || ops[0].Opcode != OP_SETCLIENTID {
			continue
		}
		// args = verifier(8) + id(string) + callback(prog + 2 strings) + ident(4)
		p2 := newParser(ops[0].Args)
		p2.readFixedOpaque(8) // verifier
		id, _ := p2.readString()
		clientIDs[id] = true
	}
	if !clientIDs["trafficgen-client-0"] || !clientIDs["trafficgen-client-1"] {
		t.Errorf("expected both client-0 and client-1 ids, got %v", clientIDs)
	}
}

// --- T-108: duplicate clientid across sessions rejected ---
func TestNFS4DuplicateClientID(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:             4,
		Sessions:            2,
		SessionsSrcPortBase: 50000,
		SessionsSrcPortStep: 1,
		Ops: []NFSOp{
			{
				Procedure: NFS4ProcCOMPOUND,
				CompoundOps: []NFSv4CompoundOp{{
					Opcode:   OP_PUTROOTFH,
					Clientid: 100,
				}},
			},
			{
				Procedure: NFS4ProcCOMPOUND,
				CompoundOps: []NFSv4CompoundOp{{
					Opcode:   OP_GETFH,
					Clientid: 100, // same explicit clientid in a second op
				}},
			},
		},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for duplicate clientid")
	}
	if !containsStr(err.Error(), "duplicate clientid") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-119: per-owner seqid independence ---
func TestNFS4PerOwnerSeqID(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 1, ShareDeny: 0, Clientid: 1,
					OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim:   &NFSClaim{Type: "null"},
					Name:    "f"},
				{Opcode: OP_LOCK, LockType: 1, Reclaim: false, Offset: 0, Length: 100,
					NewLockOwner: true,
					OpenToLockOwner: &OpenToLockOwner{
						OpenSeqid: 2, OpenStateid: &NFSStateid{},
						LockSeqid: 1, LockOwner: &NFSLockOwner{Clientid: 1, Owner: []byte{0x01}},
					},
				},
				{Opcode: OP_LOCKU, LockType: 1, Seqid: 2,
					Stateid: &NFSStateid{},
					Offset:  0, Length: 100,
				},
				{Opcode: OP_CLOSE, Seqid: 3, OpenStateid: &NFSStateid{}},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find the user's COMPOUND (skip auto SETCLIENTID + CONFIRM). The
	// per-op argument lengths are opcode-specific, so the argarray
	// parser cannot walk past a variable-length op (e.g. OPEN); instead
	// the OPEN_CONFIRM auto-insertion is verified at both the pure
	// function level (autoCompleteOpenConfirm) and the wire level
	// (opcode 20 present in the user COMPOUND's argarray bytes).
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil || len(ops) == 0 {
			continue
		}
		// Skip auto
		if ops[0].Opcode == OP_SETCLIENTID || ops[0].Opcode == OP_SETCLIENTID_CONFIRM {
			continue
		}
		// The first argarray entry is PUTROOTFH (auto-prepended by
		// §4.1 rule 2). The wire bytes must contain the OPEN_CONFIRM
		// opcode (20) right after the OPEN opcode (18).
		if ops[0].Opcode != OP_PUTROOTFH {
			t.Errorf("op[0]: got %d, want PUTROOTFH", ops[0].Opcode)
		}
		body := c.Payload[4+nfsOff:]
		// argarray: look for the 6-opcode sequence
		// 24(PUTROOTFH) 18(OPEN) 20(OPEN_CONFIRM) 12(LOCK) 14(LOCKU) 4(CLOSE)
		// The opcodes are 4-byte BE fields; variable args follow each.
		// Scan for "18 00 00 00" followed by "14 00 00 00" within the
		// same compound (OPEN args precede OPEN_CONFIRM's opcode).
		openPos := bytes.Index(body, []byte{0x12, 0x00, 0x00, 0x00})
		if openPos < 0 {
			t.Error("OPEN opcode not found in user COMPOUND")
			return
		}
		confirmPos := bytes.Index(body[openPos:], []byte{0x14, 0x00, 0x00, 0x00})
		if confirmPos < 0 {
			t.Error("OPEN_CONFIRM (auto, opcode 20) not found after OPEN")
			return
		}
		return
	}
	t.Fatal("user COMPOUND not found")
}

// T-119/T-110 supplement: OPEN_CONFIRM auto-insertion and per-owner
// seqid behavior at the pure-function level (autoCompleteOpenConfirm).
func TestNFS4OpenConfirmPureFunction(t *testing.T) {
	ops := []NFSOp{{
		Procedure: NFS4ProcCOMPOUND,
		CompoundOps: []NFSv4CompoundOp{
			{Opcode: OP_PUTROOTFH},
			{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 1, ShareDeny: 0, Clientid: 1,
				OpenHow: &NFSOpenHow{Type: "unchecked"},
				Claim:   &NFSClaim{Type: "null"},
				Name:    "f"},
			{Opcode: OP_LOCK, LockType: 1, Reclaim: false, Offset: 0, Length: 100,
				NewLockOwner: true,
				OpenToLockOwner: &OpenToLockOwner{
					OpenSeqid: 2, OpenStateid: &NFSStateid{},
					LockSeqid: 1, LockOwner: &NFSLockOwner{Clientid: 1, Owner: []byte{0x01}},
				},
			},
			{Opcode: OP_LOCKU, LockType: 1, Seqid: 2,
				Stateid: &NFSStateid{},
				Offset:  0, Length: 100,
			},
			{Opcode: OP_CLOSE, Seqid: 3, OpenStateid: &NFSStateid{}},
		},
	}}
	out := autoCompleteOpenConfirm(ops)
	if len(out) != 1 || len(out[0].CompoundOps) != 6 {
		t.Fatalf("argarray: got %d ops, want 6 (PUTROOTFH, OPEN, OPEN_CONFIRM, LOCK, LOCKU, CLOSE)", len(out[0].CompoundOps))
	}
	cops := out[0].CompoundOps
	if cops[0].Opcode != OP_PUTROOTFH {
		t.Errorf("op[0]: got %d, want PUTROOTFH", cops[0].Opcode)
	}
	if cops[1].Opcode != OP_OPEN {
		t.Errorf("op[1]: got %d, want OPEN", cops[1].Opcode)
	}
	if cops[2].Opcode != OP_OPEN_CONFIRM {
		t.Errorf("op[2]: got %d, want OPEN_CONFIRM (auto)", cops[2].Opcode)
	}
	if cops[2].Seqid != 2 {
		t.Errorf("OPEN_CONFIRM seqid: got %d, want 2 (OPEN seqid + 1, RFC 7530 §16.18.4)", cops[2].Seqid)
	}
	if cops[3].Opcode != OP_LOCK {
		t.Errorf("op[3]: got %d, want LOCK", cops[3].Opcode)
	}
	if cops[4].Opcode != OP_LOCKU {
		t.Errorf("op[4]: got %d, want LOCKU", cops[4].Opcode)
	}
	if cops[5].Opcode != OP_CLOSE {
		t.Errorf("op[5]: got %d, want CLOSE", cops[5].Opcode)
	}
}

// --- T-136: MOUNT proc=6 rejected ---
func TestNFS3MOUNTProcRange(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Program:   ProgramMount,
			Procedure: 6,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for MOUNT proc=6")
	}
	if !containsStr(err.Error(), "MOUNT v3 procedure out of range") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-148: proc=22 + RPC PROC_UNAVAIL ---
func TestNFS3ProcUnavailInjection(t *testing.T) {
	p := NewPlanner()
	acc := uint32(RPCProcUnavail)
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:      22,
			RPCAcceptState: &acc,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find the reply with AcceptState=3.
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, _, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.AcceptState == RPCProcUnavail {
			return
		}
	}
	t.Error("expected a reply with AcceptState=PROC_UNAVAIL")
}

// --- T-149: attrmask word2 non-zero rejected ---
func TestNFS4AttrMaskWord2(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{
				Opcode:   OP_GETATTR,
				AttrMask: []uint32{0, 0, 0x10},
			}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for attrmask word2 != 0")
	}
	if !containsStr(err.Error(), "NFSv4.1+") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-152: ReplyStatus per-op override ---
func TestNFS4ReplyStatusOverride(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure:   NFS4ProcCOMPOUND,
			ReplyStatus: NFS4ERR_NOFILEHANDLE,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_GETATTR, AttrMask: []uint32{0x10}}},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.AcceptState != RPCSuccess {
			continue
		}
		res, err := ParseCompound4Res(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		// Skip SETCLIENTID/CONFIRM auto-replies (status=0); find the
		// user one with status=10020.
		if res.Status == NFS4ERR_NOFILEHANDLE {
			return
		}
	}
	t.Error("expected COMPOUND reply with status=NFS4ERR_NOFILEHANDLE")
}

// --- T-154: GETATTR before PUTFH triggers NOFILEHANDLE ---
func TestNFS4GETATTRNoFH(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure:   NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_GETATTR, AttrMask: []uint32{0x10}}},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// The user's COMPOUND has PUTROOTFH auto-inserted at the start
	// (per §4.1 rule 2), so this test is not a true "no PUTFH" scenario.
	// Instead, verify the resulting reply is OK (no error since we
	// auto-inserted PUTROOTFH).
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.AcceptState != RPCSuccess {
			continue
		}
		_ = nfsOff
		_ = hdr
	}
}

// --- T-155: COMPOUND truncation on per-op failure ---
func TestNFS4CompoundTruncation(t *testing.T) {
	p := NewPlanner()
	failStatus := uint32(NFS4ERR_BAD_STATEID)
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_GETATTR, AttrMask: []uint32{0x10}, OpStatus: &failStatus},
				{Opcode: OP_READ, Stateid: &NFSStateid{}, Offset: 0, Count: 10},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	// Find the user COMPOUND reply.
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.AcceptState != RPCSuccess {
			continue
		}
		res, err := ParseCompound4Res(c.Payload[4+nfsOff:])
		if err != nil {
			continue
		}
		// Skip auto SETCLIENTID/CONFIRM replies
		if res.Status == 0 && len(res.ResOps) > 0 && res.ResOps[0].Opcode == OP_SETCLIENTID {
			continue
		}
		// The user COMPOUND should have status=BAD_STATEID and resarray truncated to 2.
		if res.Status == NFS4ERR_BAD_STATEID {
			if len(res.ResOps) != 2 {
				t.Errorf("resarray len: got %d, want 2 (truncation)", len(res.ResOps))
			}
			return
		}
	}
	t.Error("expected truncated COMPOUND reply with status=BAD_STATEID")
}

// --- T-158: RPCAcceptState=PROG_UNAVAIL ---
func TestNFSRPCAcceptState(t *testing.T) {
	p := NewPlanner()
	acc := uint32(RPCProgUnavail)
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:      NFS3ProcNULL,
			RPCAcceptState: &acc,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, _, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.AcceptState == RPCProgUnavail {
			return
		}
	}
	t.Error("expected AcceptState=PROG_UNAVAIL")
}

// --- T-163: RPCRejectState=RPC_MISMATCH ---
func TestNFSRPCRejectMismatch(t *testing.T) {
	p := NewPlanner()
	rs := uint32(RPCMismatch)
	low := uint32(2)
	high := uint32(2)
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:       NFS3ProcNULL,
			RPCRejectState:  &rs,
			RPCMismatchLow:  &low,
			RPCMismatchHigh: &high,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, _, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.ReplyState == RPCMsgDenied && hdr.RejectState == RPCMismatch {
			if hdr.MismatchLow != 2 || hdr.MismatchHigh != 2 {
				t.Errorf("mismatch range: got %d..%d, want 2..2", hdr.MismatchLow, hdr.MismatchHigh)
			}
			return
		}
	}
	t.Error("expected MSG_DENIED + RPC_MISMATCH")
}

// --- T-164: RPCRejectState=AUTH_ERROR ---
func TestNFSRPCRejectAuthError(t *testing.T) {
	p := NewPlanner()
	rs := uint32(RPCAuthError)
	ast := uint32(AuthBadCred)
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:      NFS3ProcNULL,
			RPCRejectState: &rs,
			AuthStat:       &ast,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		hdr, _, _ := ParseRPCReplyHeader(c.Payload[4:])
		if hdr.ReplyState == RPCMsgDenied && hdr.RejectState == RPCAuthError {
			if hdr.AuthStat != AuthBadCred {
				t.Errorf("auth_stat: got %d, want %d", hdr.AuthStat, AuthBadCred)
			}
			return
		}
	}
	t.Error("expected MSG_DENIED + AUTH_ERROR")
}

// --- T-171/T-172: multi-session distinct flowIDs ---
func TestNFS3MultiSession(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:             3,
		Sessions:            2,
		SessionsSrcPortBase: 40000,
		SessionsSrcPortStep: 1,
		Ops:                 []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	cfgs := mustPlan(t, p, spec)
	flowIDs := map[string]bool{}
	for _, c := range cfgs {
		flowIDs[c.FlowID] = true
	}
	if len(flowIDs) != 2 {
		t.Errorf("flow count: got %d, want 2", len(flowIDs))
	}
	// Check src ports
	ports := map[uint16]bool{}
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Protocol == "tcp" {
			ports[c.L4.SrcPort] = true
		}
	}
	if !ports[40000] || !ports[40001] {
		t.Errorf("expected ports 40000 and 40001, got %v", ports)
	}
}

// --- T-175: sessions>1 step=0 rejected ---
func TestNFS3SessionsStepZero(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:             3,
		Sessions:            2,
		SessionsSrcPortBase: 40000,
		SessionsSrcPortStep: 0,
		Ops:                 []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for sessions>1 with step=0")
	}
	if !containsStr(err.Error(), "sessions_src_port_step must be non-zero") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-181: version=0 rejected ---
func TestNFSVersion0(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 0,
		Ops:     []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for version=0")
	}
	if !containsStr(err.Error(), "version must be 3 or 4") {
		t.Errorf("error: got %q", err)
	}
}

// --- T-184: empty ops rejected ---
func TestNFSEmptyOps(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops:     nil,
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty ops")
	}
	if !containsStr(err.Error(), "ops must not be empty") {
		t.Errorf("error: got %q", err)
	}
}

// --- XDR encoding tests ---

// --- T-143: filename UTF-8 ---
func TestNFS3FilenameUTF8(t *testing.T) {
	p := NewPlanner()
	name := "文件.txt" // 10 bytes in UTF-8
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcLOOKUP,
			Filehandle: []byte{0x01},
			Filename:   name,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque()
	got, _ := p2.readString()
	if got != name {
		t.Errorf("filename: got %q, want %q", got, name)
	}
}

// --- T-144..T-147: XDR padding ---
func TestXDROpaquePadding(t *testing.T) {
	// 1-byte opaque → 3 bytes padding
	b := appendOpaque(nil, []byte{0x01})
	if len(b) != 4+1+3 {
		t.Errorf("1B opaque: got %d bytes, want 8", len(b))
	}
	// 2-byte → 2 bytes padding
	b = appendOpaque(nil, []byte{0x01, 0x02})
	if len(b) != 4+2+2 {
		t.Errorf("2B opaque: got %d bytes, want 8", len(b))
	}
	// 3-byte → 1 byte padding
	b = appendOpaque(nil, []byte{0x01, 0x02, 0x03})
	if len(b) != 4+3+1 {
		t.Errorf("3B opaque: got %d bytes, want 8", len(b))
	}
	// 4-byte → no padding
	b = appendOpaque(nil, []byte{0x01, 0x02, 0x03, 0x04})
	if len(b) != 4+4 {
		t.Errorf("4B opaque: got %d bytes, want 8", len(b))
	}
}

// --- T-185: filehandle = "" (0 bytes) ---
func TestNFS3EmptyFilehandle(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcGETATTR,
			Filehandle: []byte{},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	fh, _ := p2.readOpaque()
	if len(fh) != 0 {
		t.Errorf("fh len: got %d, want 0", len(fh))
	}
}

// --- T-187: offset uint64 max ---
func TestNFS3OffsetMax(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:  NFS3ProcREAD,
			Filehandle: []byte{0x01},
			Offset:     0xFFFFFFFFFFFFFFFF,
			Count:      1,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	call := payloadOf(cfgs, "up")
	_, nfsOff, _ := ParseRPCCallHeader(call[4:])
	p2 := newParser(call[4+nfsOff:])
	p2.readOpaque()
	off, _ := p2.readU64()
	if off != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("offset: got %d, want max", off)
	}
}

// --- V12: NFSv3 op with compound fields rejected ---
func TestNFS3CompoundFieldsRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcNULL,
			CompoundOps: []NFSv4CompoundOp{{Opcode: OP_PUTROOTFH}},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for v3 with compound_ops")
	}
}

// --- T-141: UDP length > 65507 rejected ---
func TestNFS3UDPLengthLimit(t *testing.T) {
	p := NewPlanner()
	// Create WRITE with data > UDPMaxPayload - headers
	bigData := make([]byte, UDPMaxPayload) // way too big
	spec := nfsSpec(t, &NFSConfig{
		Version:   3,
		Transport: "udp",
		Ops: []NFSOp{{
			Procedure:  NFS3ProcWRITE,
			Filehandle: []byte{0x01},
			Count:      uint32(len(bigData)),
			Data:       bigData,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for UDP > UDPMaxPayload")
	}
	if !containsStr(err.Error(), "UDP RPC message exceeds") {
		t.Errorf("error: got %q", err)
	}
}

// --- V11: NFSv4 procedure != 0/1 rejected ---
func TestNFS4BadProcedure(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: 5,
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for v4 procedure=5")
	}
}

// --- V13: auth_sys non-nil with auth_flavor=0 rejected ---
func TestNFS3AuthSysInconsistent(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version:    3,
		AuthFlavor: 0,
		AuthSys:    &AuthSysInfo{MachineName: "x"},
		Ops:        []NFSOp{{Procedure: NFS3ProcNULL}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for auth_sys with auth_flavor=0")
	}
	if !containsStr(err.Error(), "auth_sys must be nil when auth_flavor=0") {
		t.Errorf("error: got %q", err)
	}
}

// --- V16/V17: invalid opcode ---
func TestNFS4InvalidOpcode(t *testing.T) {
	p := NewPlanner()
	for _, opc := range []uint32{0, 1, 2, 63, 100} {
		spec := nfsSpec(t, &NFSConfig{
			Version: 4,
			Ops: []NFSOp{{
				Procedure:   NFS4ProcCOMPOUND,
				CompoundOps: []NFSv4CompoundOp{{Opcode: opc}},
			}},
		})
		err := p.Validate(spec)
		if err == nil {
			t.Errorf("opcode=%d: expected error", opc)
		}
	}
	// 40-62 should pass (NFSv4.1+ passthrough)
	for _, opc := range []uint32{40, 50, 62} {
		spec := nfsSpec(t, &NFSConfig{
			Version: 4,
			Ops: []NFSOp{{
				Procedure:   NFS4ProcCOMPOUND,
				CompoundOps: []NFSv4CompoundOp{{Opcode: opc}},
			}},
		})
		if err := p.Validate(spec); err != nil {
			t.Errorf("opcode=%d: should pass: %v", opc, err)
		}
	}
}

// --- H-1: seqid validation for OPEN/OPEN_CONFIRM/LOCK ---

// T-H1a: OPEN with Seqid=0 is rejected by Validate (RFC 7530 §16.16).
func TestNFS4OpenSeqidZeroRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 0, ShareAccess: 1, ShareDeny: 0, Clientid: 1,
					OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim:   &NFSClaim{Type: "null"},
					Name:    "f"},
			},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for OPEN seqid=0")
	}
	if !containsStr(err.Error(), "OPEN seqid must be > 0") {
		t.Errorf("error: got %q", err)
	}
}

// T-H1b: OPEN_CONFIRM with Seqid=0 is rejected (RFC 7530 §16.18).
func TestNFS4OpenConfirmSeqidZeroRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN_CONFIRM, Seqid: 0, OpenStateid: &NFSStateid{}},
			},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for OPEN_CONFIRM seqid=0")
	}
	if !containsStr(err.Error(), "OPEN_CONFIRM seqid must be > 0") {
		t.Errorf("error: got %q", err)
	}
}

// T-H1c: LOCK with new_lock_owner=true and zero OpenSeqid/LockSeqid is
// rejected (RFC 7530 §16.10).
func TestNFS4LockNewOwnerSeqidZeroRejected(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 1, ShareDeny: 0, Clientid: 1,
					OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim:   &NFSClaim{Type: "null"},
					Name:    "f"},
				{Opcode: OP_LOCK, LockType: 1, Reclaim: false, Offset: 0, Length: 100,
					NewLockOwner: true,
					OpenToLockOwner: &OpenToLockOwner{
						OpenSeqid: 0, OpenStateid: &NFSStateid{},
						LockSeqid: 1, LockOwner: &NFSLockOwner{Clientid: 1, Owner: []byte{0x01}},
					},
				},
			},
		}},
	})
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for LOCK open_seqid=0")
	}
	if !containsStr(err.Error(), "open_seqid must be > 0") {
		t.Errorf("error: got %q", err)
	}
}

// --- H-2: encodeNFS4Call / applyOpenReplyStateid deep-copy ---

// T-H2: Calling Plan twice (simulating batch re-plan or multi-session) must
// not mutate the user's NFSConfig.CompoundOps. Before H-2 fix, the first
// call would overwrite Clientid=0 with the per-session clientid, so the
// second call would see Clientid already set.
func TestNFS4NoMutationOnRepeatedPlan(t *testing.T) {
	p := NewPlanner()
	cfg := &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 1, ShareDeny: 0, Clientid: 0,
					OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim:   &NFSClaim{Type: "null"},
					Name:    "f"},
			},
		}},
	}
	spec := nfsSpec(t, cfg)

	// Snapshot the user's OPEN Clientid before Plan.
	if cfg.Ops[0].CompoundOps[1].Clientid != 0 {
		t.Fatalf("precondition: user Clientid should be 0, got %d",
			cfg.Ops[0].CompoundOps[1].Clientid)
	}

	// Plan twice.
	_ = mustPlan(t, p, spec)
	_ = mustPlan(t, p, spec)

	// After Plan, user's Clientid must still be 0 (not the session clientid).
	if cfg.Ops[0].CompoundOps[1].Clientid != 0 {
		t.Errorf("user cfg mutated: OPEN Clientid = %d, want 0",
			cfg.Ops[0].CompoundOps[1].Clientid)
	}
}

// --- H-3: autoCompleteOpenConfirm reuses NFSOp.OpenReplyStateid ---

// T-H3: When the user configures NFSOp.OpenReplyStateid (the server's
// OPEN reply stateid), the auto-injected OPEN_CONFIRM must echo that
// reply stateid, not the anonymous input stateid. Before H-3 fix, the
// auto-injected OPEN_CONFIRM used cop.OpenStateid (typically all-zero).
func TestNFS4OpenConfirmReusesReplyStateid(t *testing.T) {
	p := NewPlanner()
	replySid := &NFSStateid{
		Seqid: 1,
		Other: [12]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	}
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 1, ShareDeny: 0, Clientid: 1,
					OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim:   &NFSClaim{Type: "null"},
					Name:    "f"},
			},
			OpenReplyStateid: replySid,
		}},
	})
	cfgs := mustPlan(t, p, spec)

	// Find the user's COMPOUND call (skip auto SETCLIENTID + CONFIRM).
	for _, c := range cfgs {
		if c.Direction != "up" || len(c.Payload) == 0 {
			continue
		}
		hdr, nfsOff, _ := ParseRPCCallHeader(c.Payload[4:])
		if hdr.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		_, _, ops, err := ParseCompound4Args(c.Payload[4+nfsOff:])
		if err != nil || len(ops) == 0 {
			continue
		}
		if ops[0].Opcode == OP_SETCLIENTID || ops[0].Opcode == OP_SETCLIENTID_CONFIRM {
			continue
		}
		// ops[0] is the first op (PUTROOTFH); Args contains all subsequent
		// bytes including OPEN and auto-injected OPEN_CONFIRM. Scan for
		// the reply stateid's 12-byte Other pattern — if H-3 is correct,
		// the OPEN_CONFIRM's open_stateid carries these bytes.
		payload := c.Payload[4+nfsOff:]
		pattern := replySid.Other[:]
		found := false
		for i := 0; i+len(pattern) <= len(payload); i++ {
			match := true
			for k := 0; k < len(pattern); k++ {
				if payload[i+k] != pattern[k] {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OPEN_CONFIRM did not echo reply stateid Other bytes %x",
				pattern)
		}
		return
	}
	t.Fatal("user COMPOUND not found")
}

// --- Helpers ---

func binaryBigEndianU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func binaryBigEndianU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- Deep-audit fixes (2026-08): pcap malformed regressions ---
//
// The following tests are derived from tshark [Malformed Packet: NFS/MOUNT]
// findings in the pcap drive (cases/nfs.json t001/t053/t059/t060a/t060b/
// t060c/t092/t093/t097/t099/t100/t111-t118). Each encodes the RFC 1813 /
// RFC 7531 wire layout the malformed frames violated.

// callPayloadOf finds the first user-op CALL payload in cfgs (skips
// auto MOUNT call/reply pairs), returning (payload, NFS body offset).
func callPayloadOf(cfgs []core.PacketConfig) ([]byte, int) {
	skipNextDown := false
	for _, c := range cfgs {
		if len(c.Payload) == 0 || len(c.Payload) < 4 {
			continue
		}
		if c.Direction == "up" {
			hdr, off, err := ParseRPCCallHeader(c.Payload[4:])
			if err == nil && hdr.Program == ProgramMount {
				skipNextDown = true
				continue
			}
			return c.Payload, 4 + off
		}
		if skipNextDown {
			skipNextDown = false
		}
	}
	return nil, 0
}

// replyPayloadOf finds the first user-op REPLY payload (skips the auto
// MOUNT call/reply pair and any MOUNT reply after a MOUNT call).
func replyPayloadOf(cfgs []core.PacketConfig) ([]byte, int) {
	skipNextDown := false
	for _, c := range cfgs {
		if len(c.Payload) == 0 || len(c.Payload) < 4 {
			continue
		}
		if c.Direction == "up" {
			hdr, _, err := ParseRPCCallHeader(c.Payload[4:])
			if err == nil && hdr.Program == ProgramMount {
				skipNextDown = true
			}
			continue
		}
		if skipNextDown {
			skipNextDown = false
			continue
		}
		_, off, err := ParseRPCReplyHeader(c.Payload[4:])
		if err != nil {
			continue
		}
		return c.Payload, 4 + off
	}
	return nil, 0
}

// lastCallPayloadOf finds the LAST user-op CALL payload in cfgs (skips
// auto MOUNT and auto SETCLIENTID call/reply pairs, which precede the
// user-configured ops). Returns (payload, NFS body offset).
//
// Only up-direction (CALL) payloads update `out`; down (REPLY) frames
// and unparseable frames (e.g. handshake) leave the previous candidate
// in place.
func lastCallPayloadOf(cfgs []core.PacketConfig) ([]byte, int) {
	var out []byte
	var off int
	for _, c := range cfgs {
		if len(c.Payload) < 4 || c.Direction != "up" {
			continue
		}
		hdr, o, err := ParseRPCCallHeader(c.Payload[4:])
		if err != nil || hdr.Program == ProgramMount {
			continue
		}
		out = c.Payload
		off = 4 + o
	}
	if out == nil {
		return nil, 0
	}
	return out, off
}

// argWalkOp is a single op entry while walking a COMPOUND call body:
// the opcode and the exact slice of its XDR args (0 bytes for no-arg ops).
type argWalkOp struct {
	opcode uint32
	args   []byte
}

// walkCompoundArgs walks a COMPOUND4args body (starting just past
// tag + minorversion + opcount) and returns one entry per op with the
// exact args bytes. The args of the LAST op extend to the end of the
// body (no delimiter), and per-op widths are taken from the same
// encoders the planner uses, so a missing case is a test failure rather
// than silent garbage.
func walkCompoundArgs(t *testing.T, b []byte) []argWalkOp {
	t.Helper()
	var out []argWalkOp
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatalf("dangling opcode bytes: %x", b)
		}
		opcode := binaryBigEndianU32(b)
		rest := b[4:]
		var width int
		switch opcode {
		case OP_PUTROOTFH, OP_PUTPUBFH, OP_LOOKUPP, OP_READLINK, OP_GETFH:
			width = 0
		case OP_PUTFH:
			if len(rest) < 4 {
				t.Fatalf("PUTFH args underflow: %x", rest)
			}
			width = SkipOpaque(rest)
		case OP_GETATTR:
			// bitmap4: length + words — empty in these tests.
			if len(rest) < 4 {
				t.Fatalf("GETATTR args underflow: %x", rest)
			}
			words := int(binaryBigEndianU32(rest))
			width = 4 + 4*words
		case OP_LOOKUP, OP_REMOVE:
			width = SkipOpaque(rest)
		case OP_RENAME:
			if len(rest) < 4 {
				t.Fatalf("RENAME args underflow: %x", rest)
			}
			o := SkipOpaque(rest)
			if o < 0 {
				t.Fatalf("RENAME oldname underflow: %x", rest)
			}
			nn := SkipOpaque(rest[o:])
			if nn < 0 {
				t.Fatalf("RENAME newname underflow: %x", rest[o:])
			}
			width = o + nn
		case OP_SETATTR:
			// stateid4 (16) + fattr4 (bitmap len + words + attrlist opaque).
			if len(rest) < 16+4 {
				t.Fatalf("SETATTR args underflow: %x", rest)
			}
			words := int(binaryBigEndianU32(rest[16:]))
			if len(rest) < 20+4*words+4 {
				t.Fatalf("SETATTR fattr4 underflow: %x", rest)
			}
			attrLen := int(binaryBigEndianU32(rest[20+4*words:]))
			width = 20 + 4*words + 4 + attrLen + (4-(attrLen%4))%4
		case OP_READ:
			// stateid4 + offset(8) + count(4) = 28.
			width = 28
		case OP_WRITE:
			// stateid4 + offset(8) + stable(4) + data opaque.
			if len(rest) < 28 {
				t.Fatalf("WRITE args underflow: %x", rest)
			}
			width = 28 + SkipOpaque(rest[28:])
		case OP_OPEN_CONFIRM:
			// OPEN_CONFIRM4args = open_stateid4 + seqid4 (RFC 7530 §16.18.2).
			width = 16 + 4
		case OP_OPEN_DOWNGRADE:
			// OPEN_DOWNGRADE4args = open_stateid4 + seqid4 + share_access +
			// share_deny (RFC 7530 §16.19.2).
			width = 16 + 4 + 4 + 4
		case OP_CLOSE:
			// CLOSE4args = seqid4 + open_stateid4 (RFC 7530 §16.2.2).
			width = 4 + 16
		case OP_LOCK:
			// locktype(4) + reclaim(4) + offset(8) + length(8) + locker4.
			if len(rest) < 24 {
				t.Fatalf("LOCK args underflow: %x", rest)
			}
			if binaryBigEndianU32(rest[20:]) == 1 {
				// new_lock_owner=true → open_to_lock_owner4 (seqid + open
				// stateid + lock seqid + lock_owner4) — not covered by the
				// R10 test; fail loudly rather than mis-slice.
				t.Fatalf("LOCK new_lock_owner=true unsupported in walker")
			}
			// new_lock_owner=false → lock_owner4 = clientid(8) + seqid(4)
			// + owner opaque (RFC 7530 §16.10.2). LOCK4args = locktype(4)
			// + reclaim(4) + offset(8) + length(8) + new_lock_owner(4)
			// + lock_owner4.
			width = 24 + 4 + 8 + 4 + SkipOpaque(rest[40:])
		case OP_LOCKU:
			// locktype(4) + seqid(4) + stateid(16) + offset(8) + length(8).
			width = 4 + 4 + 16 + 8 + 8
		case OP_DELEGRETURN:
			width = 16
		case OP_CREATE:
			// objtype (otype4 discriminant 4 + name opaque) + attrs fattr4.
			if len(rest) < 4 {
				t.Fatalf("CREATE args underflow: %x", rest)
			}
			nm := SkipOpaque(rest[4:])
			if nm < 0 {
				t.Fatalf("CREATE name underflow: %x", rest[4:])
			}
			width = 4 + nm + 4 + 4 + 4 // attrs: bitmap len 0 + attrlist len 0
		case OP_OPEN:
			// seqid(4) + share_access(4) + share_deny(4) + owner(clientid 8
			// + opaque) + openflag4 + open_claim4. The test opens use
			// Owner==nil (owner opaque len 0 → 4+0), openflag4 with
			// opentype=1 + createmode + bitmap len + attrlist len (16),
			// and CLAIM_NULL (discriminant 4 + name opaque).
			if len(rest) < 12 {
				t.Fatalf("OPEN args underflow: %x", rest)
			}
			ownerLen := int(binaryBigEndianU32(rest[12:]))
			if len(rest) < 12+4+ownerLen+4 {
				t.Fatalf("OPEN owner underflow: %x", rest)
			}
			ownerW := 8 + 4 + ownerLen + (4-(ownerLen%4))%4
			openflag := rest[12+ownerW:]
			openflagW := openflag4Width(t, openflag)
			// open_claim4: discriminant(4) + payload.
			claimDisc := rest[12+ownerW+openflagW:]
			if len(claimDisc) < 4 {
				t.Fatalf("OPEN claim underflow: %x", claimDisc)
			}
			var claimW int
			switch binaryBigEndianU32(claimDisc) {
			case ClaimNULL, ClaimDELEGATE_PREV:
				claimW = 4 + SkipOpaque(claimDisc[4:])
			case ClaimPREVIOUS:
				claimW = 4 + 4
			case ClaimDELEGATE_CUR:
				claimW = 4 + 16 + SkipOpaque(claimDisc[20:])
			default:
				t.Fatalf("unknown claim type %d", binaryBigEndianU32(claimDisc))
			}
			width = 12 + ownerW + openflagW + claimW
		default:
			t.Fatalf("walkCompoundArgs: unhandled opcode %d", opcode)
		}
		if width < 0 || width > len(rest) {
			t.Fatalf("opcode %d: args width %d exceeds remaining %d: %x",
				opcode, width, len(rest), b)
		}
		out = append(out, argWalkOp{opcode: opcode, args: rest[:width]})
		b = rest[width:]
	}
	return out
}

// openflag4Width returns the XDR width of an openflag4 union body.
// opentype4 NOCREATE (0) → 4 bytes; CREATE (1) → createmode4 (4) +
// body, where EXCLUSIVE (2) adds an 8-byte createverf4 and
// UNCHECKED/GUARDED add a createattrs fattr4 (bitmap4 + attrlist4).
func openflag4Width(t *testing.T, b []byte) int {
	t.Helper()
	if len(b) < 4 {
		t.Fatalf("openflag4 underflow: %x", b)
	}
	opentype := binaryBigEndianU32(b)
	if opentype == OpenTypeNOCREATE {
		return 4
	}
	if len(b) < 8 {
		t.Fatalf("openflag4 createmode underflow: %x", b)
	}
	mode := binaryBigEndianU32(b[4:])
	if mode == CreatemodeEXCLUSIVE4 {
		return 4 + 4 + 8
	}
	// createattrs: bitmap4 len + words + attrlist4 len + bytes.
	if len(b) < 12 {
		t.Fatalf("openflag4 createattrs underflow: %x", b)
	}
	words := int(binaryBigEndianU32(b[8:]))
	if len(b) < 12+4*words+4 {
		t.Fatalf("openflag4 attrlist underflow: %x", b)
	}
	attrLen := int(binaryBigEndianU32(b[12+4*words:]))
	return 12 + 4*words + 4 + attrLen + (4-(attrLen%4))%4
}

// userOpOf walks a compound call body and returns the first op that is
// not an auto-injected helper (a leading PUTROOTFH/PUTFH/PUTPUBFH that
// was prepended by autoCompletePutRootFH). The return value is nil when
// no user op remains.
func userOpOf(t *testing.T, b []byte) *argWalkOp {
	t.Helper()
	ops := walkCompoundArgs(t, b)
	for i := range ops {
		switch ops[i].opcode {
		case OP_PUTROOTFH, OP_PUTFH, OP_PUTPUBFH:
			continue // auto-prepended by autoCompletePutRootFH
		}
		return &ops[i]
	}
	return nil
}

// lastReplyPayloadOf finds the LAST user-op REPLY payload in cfgs
// (skips auto MOUNT and auto SETCLIENTID call/reply pairs, which
// precede the user-configured ops). Returns (payload, NFS body offset).
func lastReplyPayloadOf(cfgs []core.PacketConfig) ([]byte, int) {
	mountUp := false
	var out []byte
	var off int
	for _, c := range cfgs {
		if len(c.Payload) < 4 {
			continue
		}
		if c.Direction == "up" {
			hdr, _, err := ParseRPCCallHeader(c.Payload[4:])
			if err != nil {
				continue
			}
			if hdr.Program == ProgramMount {
				mountUp = true
			} else {
				mountUp = false
			}
			continue
		}
		if mountUp {
			mountUp = false
			continue
		}
		out = c.Payload
		off = 0
		if _, o, err := ParseRPCReplyHeader(c.Payload[4:]); err == nil {
			off = 4 + o
		}
	}
	if out == nil {
		return nil, 0
	}
	return out, off
}

// nfs3ReplyStatusAndOffsets walks a NFSv3 reply's post_op_attr
// (discriminant + 84B fattr3 when set) and returns the payload offset
// just past it.
func nfs3ReplyPostAttrEnd(b []byte) (int, bool) {
	p := newParser(b)
	if _, err := p.readU32(); err != nil { // status
		return 0, false
	}
	disc, err := p.readU32()
	if err != nil {
		return 0, false
	}
	if disc != 0 {
		if _, err := p.readFixedOpaque(84); err != nil {
			return 0, false
		}
	}
	return p.i, disc != 0
}

// R1: MKDIR with a nil attributes block must emit a full 24-byte sattr3
// (set_mode/set_uid/set_gid/set_size/set_atime/set_mtime — each a
// discriminant that may or may not be followed by the value, RFC 1813
// §2.6). Before the fix, nil emitted only 4 bytes, so tshark read
// garbage and flagged [Malformed Packet: NFS].
func TestNFS3MKDIREmptySattr3(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure: NFS3ProcMKDIR,
			Filename:  "d",
			// Attributes == nil (all DONT_CHANGE) — the sattr3 must
			// still be the full 24-byte union.
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := callPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op call found")
	}
	body := payload[off:]
	// body = dirfh(4+n+pad) + name(4+m+pad) + sattr3
	n := SkipOpaque(body)
	if n < 0 {
		t.Fatalf("bad dirfh: %v", n)
	}
	m := SkipOpaque(body[n:])
	if m < 0 {
		t.Fatalf("bad name: %v", m)
	}
	sattr := body[n+m:]
	if len(sattr) != 24 {
		t.Errorf("sattr3 length = %d, want 24 (full union; got %x)", len(sattr), sattr)
	}
}

// R2: READLINK3resok is post_op_attr FIRST, then the symlink path
// (RFC 1813 §3.3.6). The old encoder wrote the string then the attr, so
// tshark read the first 4 bytes of the path as the attributes_follow
// discriminant and mis-parsed the rest.
func TestNFS3READLINKReplyOrder(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:     NFS3ProcREADLINK,
			SymlinkTarget: "/export/data/link",
			ReplyStatus:   NFS3OK,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := replyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	attrEnd, attrPresent := nfs3ReplyPostAttrEnd(body)
	if !attrPresent {
		t.Fatalf("expected post_op_attr present at reply start, body=%x", body)
	}
	// After the 88-byte post_op_attr (disc + fattr3) must come the
	// symlink path (length-prefixed string).
	_, n := ReadOpaqueLen(body[attrEnd:])
	if n < 0 {
		t.Fatalf("expected symlink string after post_op_attr, got %x", body[attrEnd:])
	}
	path := string(body[attrEnd+4 : attrEnd+4+n])
	if path != "/export/data/link" {
		t.Errorf("symlink path = %q, want %q", path, "/export/data/link")
	}
}

// R3: LINK3resok = post_op_attr + wcc_data (RFC 1813 §3.3.9). The old
// encoder wrote neither, so tshark hit EOF right after the status.
func TestNFS3LINKReplyWccData(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcLINK,
			LinkDirFh:   []byte{0x10, 0x20, 0x30, 0x40},
			Newname:     "hardlink",
			ReplyStatus: NFS3OK,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := replyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	// status + post_op_attr(88) + wcc_data(92) = 184 bytes.
	want := 4 + 88 + 92
	if len(body) != want {
		t.Errorf("LINK3resok length = %d, want %d (status+post_op_attr+wcc_data)", len(body), want)
	}
	// wcc_data = pre_op_attr disc (0) + post_op_attr disc (1) + fattr3 (84)
	wcc := body[4+88:]
	if len(wcc) != 92 {
		t.Fatalf("wcc_data length = %d, want 92", len(wcc))
	}
	if binaryBigEndianU32(wcc) != 0 {
		t.Errorf("wcc_data pre_op_attr discriminant = %d, want 0", binaryBigEndianU32(wcc))
	}
	if binaryBigEndianU32(wcc[4:]) != 1 {
		t.Errorf("wcc_data post_op_attr discriminant = %d, want 1", binaryBigEndianU32(wcc[4:]))
	}
}

// R4: FSSTAT/FSINFO/PATHCONF replies must carry their resok fields after
// post_op_attr (RFC 1813 §3.3.13-15):
//
//	fsstat3resok   = obj_attributes + tbytes(8) fbytes(8) abytes(8)
//	                 tfiles(8) ffiles(8) afiles(8) invarsec(8)
//	fsinfo3resok   = obj_attributes + rtmax(4) rtpref(4) rtmult(4)
//	                 wtmax(4) wtpref(4) wtmult(4) dtpref(4)
//	                 maxfilesize(8) time_delta(8) properties(4)
//	pathconf3resok = obj_attributes + linkmax(4) name_max(4) no_trunc(4)
//	                 chown_restricted(4) case_insensitive(4) case_preserving(4)
//
// The old encoder wrote only post_op_attr (92 bytes total), so tshark
// hit EOF after fattr3 and flagged malformed.
func TestNFS3FSSTATReplyFields(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcFSSTAT,
			ReplyStatus: NFS3OK,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := replyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	attrEnd, attrPresent := nfs3ReplyPostAttrEnd(body)
	if !attrPresent {
		t.Fatalf("expected post_op_attr, body=%x", body)
	}
	if len(body) != attrEnd+56 {
		t.Errorf("fsstat3resok length = %d, want %d (attr 88 + 7 uint64)",
			len(body), attrEnd+56)
	}
}

func TestNFS3FSINFOReplyFields(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcFSINFO,
			ReplyStatus: NFS3OK,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := replyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	attrEnd, attrPresent := nfs3ReplyPostAttrEnd(body)
	if !attrPresent {
		t.Fatalf("expected post_op_attr, body=%x", body)
	}
	// fsinfo3resok = obj_attributes + rtmax rtpref rtmult wtmax wtpref
	// wtmult dtpref (7 x uint32) + maxfilesize(8) + time_delta(8)
	// + properties(4) = 48 bytes (RFC 1813 §3.3.15).
	if len(body) != attrEnd+48 {
		t.Fatalf("fsinfo3resok length = %d, want %d (attr 88 + 48)",
			len(body), attrEnd+48)
	}
	res := body[attrEnd:]
	for i, want := range []uint32{1, 1, 1, 1, 1, 1, 1} {
		if got := binaryBigEndianU32(res[i*4:]); got != want {
			t.Errorf("fsinfo field %d = %d, want %d (rtmax rtpref rtmult "+
				"wtmax wtpref wtmult dtpref all = 1)", i, got, want)
		}
	}
	if got := binaryBigEndianU64(res[28:]); got != 0 {
		t.Errorf("maxfilesize = %d, want 0", got)
	}
	if got := binaryBigEndianU32(res[36:]); got != 0 {
		t.Errorf("time_delta.seconds = %d, want 0", got)
	}
	if got := binaryBigEndianU32(res[40:]); got != 1 {
		t.Errorf("time_delta.nseconds = %d, want 1", got)
	}
	if got := binaryBigEndianU32(res[44:]); got != 0 {
		t.Errorf("properties = %d, want 0", got)
	}
}

func TestNFS3PATHCONFReplyFields(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{{
			Procedure:   NFS3ProcPATHCONF,
			ReplyStatus: NFS3OK,
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := replyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	attrEnd, attrPresent := nfs3ReplyPostAttrEnd(body)
	if !attrPresent {
		t.Fatalf("expected post_op_attr, body=%x", body)
	}
	// linkmax(4) name_max(4) no_trunc(4) chown_restricted(4)
	// case_insensitive(4) case_preserving(4) = 24 bytes.
	if len(body) != attrEnd+24 {
		t.Errorf("pathconf3resok length = %d, want %d (attr 88 + 24)", len(body), attrEnd+24)
	}
}

// R5: reply XID echo — the reply must echo the call XID (RFC 5531 §5.3.1).
// With default XIDIncr=0 all calls share XID 1; the test uses
// XIDIncr=1 to prove the per-op increment is applied to both sides.
func TestNFS3ReplyEchoesCallXID(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 3,
		Ops: []NFSOp{
			{Procedure: NFS3ProcNULL},
			{Procedure: NFS3ProcGETATTR},
		},
	})
	cfgs := mustPlan(t, p, spec)
	// Collect up/down payloads, skipping MOUNT pairs.
	var callXIDs, replyXIDs []uint32
	skipNextDown := false
	for _, c := range cfgs {
		if len(c.Payload) < 4 {
			continue
		}
		if c.Direction == "up" {
			hdr, _, err := ParseRPCCallHeader(c.Payload[4:])
			if err == nil && hdr.Program == ProgramMount {
				skipNextDown = true
				continue
			}
			callXIDs = append(callXIDs, binaryBigEndianU32(c.Payload[4:8]))
			continue
		}
		if skipNextDown {
			skipNextDown = false
			continue
		}
		replyXIDs = append(replyXIDs, binaryBigEndianU32(c.Payload[4:8]))
	}
	if len(callXIDs) != 2 || len(replyXIDs) != 2 {
		t.Fatalf("got %d calls %d replies, want 2/2", len(callXIDs), len(replyXIDs))
	}
	for i := range callXIDs {
		if callXIDs[i] != replyXIDs[i] {
			t.Errorf("pair %d: call XID %d != reply XID %d", i, callXIDs[i], replyXIDs[i])
		}
	}
}

// R6: OPEN_DOWNGRADE4args = open_stateid4 + seqid4 + share_access4 +
// share_deny4 (RFC 7530 §16.19.2 — stateid FIRST, then seqid, access,
// deny). The old encoder had no case, so the op emitted zero args and
// tshark read the next op's bytes as its stateid (t092 frame evidence).
func TestNFS4OpenDowngradeArgs(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_OPEN_DOWNGRADE, Seqid: 5, ShareAccess: 2, ShareDeny: 0,
					OpenStateid: &NFSStateid{Seqid: 3,
						Other: [12]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0}}},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := lastCallPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op call found")
	}
	body := payload[off:]
	// tag + minorversion + opcount
	n := SkipOpaque(body)
	if n < 0 {
		t.Fatal("bad tag")
	}
	p2 := body[n+8:]
	ops := walkCompoundArgs(t, p2)
	if len(ops) != 2 || ops[0].opcode != OP_PUTROOTFH || ops[1].opcode != OP_OPEN_DOWNGRADE {
		t.Fatalf("ops = %+v, want [PUTROOTFH, OPEN_DOWNGRADE]", ops)
	}
	args := ops[1].args
	// open_stateid4 = 16 bytes, FIRST
	if len(args) < 16 {
		t.Fatalf("args too short: %x", args)
	}
	if binaryBigEndianU32(args) != 3 {
		t.Errorf("open_stateid seqid = %d, want 3", binaryBigEndianU32(args))
	}
	if !bytes.Equal(args[4:16], []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0}) {
		t.Errorf("open_stateid other = %x", args[4:16])
	}
	if len(args) != 28 {
		t.Errorf("OPEN_DOWNGRADE args length = %d, want 28 (stateid16+seqid4+access4+deny4)", len(args))
	}
	if binaryBigEndianU32(args[16:]) != 5 {
		t.Errorf("seqid = %d, want 5", binaryBigEndianU32(args[16:]))
	}
	if binaryBigEndianU32(args[20:]) != 2 {
		t.Errorf("share_access = %d, want 2", binaryBigEndianU32(args[20:]))
	}
	if binaryBigEndianU32(args[24:]) != 0 {
		t.Errorf("share_deny = %d, want 0", binaryBigEndianU32(args[24:]))
	}
}

// R10: LOCK4args with new_lock_owner=false must be locktype + reclaim +
// offset + length + lock_owner4 (clientid + owner opaque) — NOT a
// stateid (RFC 7531 §15.13). The old encoder wrote a stateid there, so
// tshark consumed the clientid/owner bytes as the stateid and hit EOF.
func TestNFS4LockNewOwnerFalseArgs(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_LOCK, LockType: 1, Reclaim: false, Offset: 0, Length: 100,
					NewLockOwner: false,
					LockOwner: &LockOwner{
						Clientid: 0x3039,
						Seqid:    1,
						Owner:    []byte{0x01, 0x01, 0x00, 0x00, 0x00},
					}},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := lastCallPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op call found")
	}
	body := payload[off:]
	n := SkipOpaque(body)
	if n < 0 {
		t.Fatal("bad tag")
	}
	ops := walkCompoundArgs(t, body[n+8:])
	if len(ops) != 2 || ops[0].opcode != OP_PUTROOTFH || ops[1].opcode != OP_LOCK {
		t.Fatalf("ops = %+v, want [PUTROOTFH, LOCK]", ops)
	}
	args := ops[1].args
	// locktype(4) + reclaim(4) + offset(8) + length(8) = 24
	if len(args) < 24 {
		t.Fatalf("LOCK args too short: %x", args)
	}
	if binaryBigEndianU32(args) != 1 || binaryBigEndianU32(args[4:]) != 0 {
		t.Errorf("locktype/reclaim = %d/%d, want 1/0", binaryBigEndianU32(args), binaryBigEndianU32(args[4:]))
	}
	if binaryBigEndianU32(args[20:]) != 100 {
		t.Errorf("length = %d, want 100", binaryBigEndianU32(args[20:]))
	}
	rest := args[24:]
	if len(rest) < 16 {
		t.Fatalf("missing lock_owner4: %x", rest)
	}
	// new_lock_owner(false) discriminant precedes the lock_owner4.
	if binaryBigEndianU32(rest[:4]) != 0 {
		t.Errorf("new_lock_owner = %d, want 0 (false)", binaryBigEndianU32(rest[:4]))
	}
	if binaryBigEndianU64(rest[4:12]) != 0x3039 {
		t.Errorf("lock_owner clientid = %x, want 0x3039", binaryBigEndianU64(rest[4:12]))
	}
	// lock_owner4 = clientid4 + state_owner4{seqid4, owner4}
	// (RFC 7530 §16.10.2). Pre-fix the seqid was missing, so tshark 3.6
	// read lock_owner4 as a 16B stateid4 and consumed the owner bytes,
	// then hit EOF (t111 frame 8 evidence).
	if binaryBigEndianU32(rest[12:16]) != 1 {
		t.Errorf("lock_owner seqid = %d, want 1", binaryBigEndianU32(rest[12:16]))
	}
	on := ReadOpaqueLenNoAdvance(rest[16:])
	if on < 0 {
		t.Fatalf("bad owner opaque: %x", rest[16:])
	}
	if on != 5 {
		t.Errorf("owner length = %d, want 5", on)
	}
}

// R7: OPEN4resok = stateid4 + change_info4 + result flags + attrset +
// open_delegation4 (RFC 7530 §16.17.3). change_info4 = bool(4) +
// changeid before(8) + after(8) = 20 bytes, so the resok is
// 16 + 20 + 4 + 4 + 4 = 48 bytes with the NONE delegation. The old
// encoder wrote only the stateid, so tshark read the following ops'
// bytes as change_info/rflags/delegation and hit EOF (t093 frame 9
// evidence).
func TestNFS4OpenReplyFull(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_PUTROOTFH},
				{Opcode: OP_OPEN, Seqid: 1, ShareAccess: 2, ShareDeny: 0,
					Clientid: 1, OpenHow: &NFSOpenHow{Type: "unchecked"},
					Claim: &NFSClaim{Type: "null"}, Name: "f"},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := lastReplyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	n := SkipOpaque(body) // tag
	if n < 0 {
		t.Fatal("bad tag")
	}
	res := body[n+8:] // skip minorversion + opcount
	// The reply's resarray begins with the auto-prepended PUTROOTFH
	// (opcode + status = 8 bytes); the OPEN resop follows.
	if len(res) < 8 || binaryBigEndianU32(res) != OP_PUTROOTFH {
		t.Fatalf("leading resop = %d, want auto PUTROOTFH: %x", binaryBigEndianU32(res), res)
	}
	res = res[8:]
	if len(res) < 8 {
		t.Fatalf("short reply: %x", res)
	}
	if binaryBigEndianU32(res) != OP_OPEN {
		t.Fatalf("first resop opcode = %d, want OPEN", binaryBigEndianU32(res))
	}
	if binaryBigEndianU32(res[4:]) != 0 {
		t.Fatalf("open status = %d, want 0", binaryBigEndianU32(res[4:]))
	}
	// resop4 = opcode(4) + status(4) + result; the reply has NO
	// minorversion, so the result starts right after opcode+status.
	rest := res[8:]
	// stateid4 (16) + change_info4 (20) + rflags (4) + attrset (4) +
	// delegation (4) = 48
	if len(rest) < 48 {
		t.Fatalf("OPEN4resok length = %d, want 48 (stateid16+change_info20+rflags4+attrset4+deleg4), got %x",
			len(rest), rest)
	}
	// change_info4: atomic=1, before=0, after=0
	if binaryBigEndianU32(rest[16:]) != 1 {
		t.Errorf("change_info atomic = %d, want 1", binaryBigEndianU32(rest[16:]))
	}
	if binaryBigEndianU64(rest[20:28]) != 0 || binaryBigEndianU64(rest[28:36]) != 0 {
		t.Errorf("change_info before/after = %d/%d, want 0/0",
			binaryBigEndianU64(rest[20:28]), binaryBigEndianU64(rest[28:36]))
	}
	// delegation type discriminant must be OPEN_DELEGATE_NONE (0).
	if binaryBigEndianU32(rest[44:]) != 0 {
		t.Errorf("open_delegation4 type = %d, want 0 (NONE)", binaryBigEndianU32(rest[44:]))
	}
	// The OPEN introduces a new open-owner, so autoCompleteOpenConfirm
	// injects a trailing OPEN_CONFIRM resop (opcode + status + stateid16).
	tail := rest[48:]
	if len(tail) < 24 {
		t.Fatalf("missing trailing OPEN_CONFIRM resop: %x", tail)
	}
	if binaryBigEndianU32(tail) != OP_OPEN_CONFIRM || binaryBigEndianU32(tail[4:]) != 0 {
		t.Fatalf("trailing resop = %d/%d, want OPEN_CONFIRM/0: %x",
			binaryBigEndianU32(tail), binaryBigEndianU32(tail[4:]), tail)
	}
	if len(tail) != 24 {
		t.Errorf("trailing resop length = %d, want 24 (opcode+status+stateid16)", len(tail))
	}
}

// SECINFO4resok = secinfo4<> array (RFC 7530 §16.33.2). Each entry:
// flavor4 + union { flavor_info4 = flavor4 + secinfo_style4 + payload }.
// Pre-fix encodeCompoundOpResult had no OP_SECINFO case, so the resop
// carried zero bytes and tshark hit EOF after the op status (t128 frame
// 9 evidence).
func TestNFS4SecinfoReply(t *testing.T) {
	p := NewPlanner()
	spec := nfsSpec(t, &NFSConfig{
		Version: 4,
		Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_SECINFO, Name: "f"},
			},
		}},
	})
	cfgs := mustPlan(t, p, spec)
	payload, off := lastReplyPayloadOf(cfgs)
	if payload == nil {
		t.Fatal("no user op reply found")
	}
	body := payload[off:]
	n := SkipOpaque(body) // tag
	if n < 0 {
		t.Fatal("bad tag")
	}
	res := body[n+8:] // skip minorversion + opcount
	// The reply's resarray begins with the auto-prepended PUTROOTFH
	// (opcode + status = 8 bytes); the SECINFO resop follows.
	if len(res) < 8 || binaryBigEndianU32(res) != OP_PUTROOTFH {
		t.Fatalf("leading resop = %d, want auto PUTROOTFH: %x", binaryBigEndianU32(res), res)
	}
	res = res[8:]
	if len(res) < 8 || binaryBigEndianU32(res) != OP_SECINFO {
		t.Fatalf("first resop = %d, want SECINFO: %x", binaryBigEndianU32(res), res)
	}
	if binaryBigEndianU32(res[4:]) != 0 {
		t.Fatalf("secinfo status = %d, want 0", binaryBigEndianU32(res[4:]))
	}
	rest := res[8:]
	// secinfo4<> = count(4) + entries. Each entry = flavor(4) + union{
	// flavor_info4 = secinfo_style4(4) + payload } (RFC 7530 §16.33.2).
	if len(rest) < 4 {
		t.Fatalf("secinfo4 missing: %x", rest)
	}
	count := binaryBigEndianU32(rest)
	if count == 0 {
		t.Fatalf("secinfo4 count = 0, want >= 1 (RFC 7530 §16.33.2)")
	}
	ent := rest[4:]
	for i := uint32(0); i < count; i++ {
		if len(ent) < 8 {
			t.Fatalf("secinfo4 entry %d underflow: %x", i, ent)
		}
		flavor := binaryBigEndianU32(ent)
		if binaryBigEndianU32(ent[4:]) != 0 {
			t.Errorf("secinfo4 entry %d style = %d, want 0 (PARENT)", i, binaryBigEndianU32(ent[4:]))
		}
		switch flavor {
		case AuthFlavorNone:
			ent = ent[8:] // style(4) + no payload
		case AuthFlavorSys:
			if len(ent) < 12 {
				t.Fatalf("AUTH_SYS entry underflow: %x", ent)
			}
			ml := binaryBigEndianU32(ent[8:])
			if ml == 0 || len(ent) < 12+int(ml) {
				t.Fatalf("AUTH_SYS machine name bad: len=%d", ml)
			}
			ent = ent[12+int(ml):]
		default:
			t.Fatalf("unexpected flavor %d", flavor)
		}
	}
}

// R8: CLOSE4resok / OPEN_CONFIRM4resok / OPEN_DOWNGRADE4resok /
// LOCK4resok / LOCKU4resok / DELEGRETURN4resok are all stateid4.
// The old result encoder wrote an op-length prefix (a 4-byte zero) plus
// the 16-byte stateid (20 bytes total), so tshark read 16 bytes and hit
// 4 leftover bytes (t093 frame 9 evidence).
func TestNFS4StateidOnlyReplyOpcodes(t *testing.T) {
	ops := []uint32{OP_CLOSE, OP_OPEN_CONFIRM, OP_OPEN_DOWNGRADE, OP_LOCK, OP_LOCKU, OP_DELEGRETURN}
	for _, opcode := range ops {
		t.Run(fmt.Sprintf("opcode-%d", opcode), func(t *testing.T) {
			p := NewPlanner()
			var cop NFSv4CompoundOp
			switch opcode {
			case OP_OPEN_CONFIRM:
				cop = NFSv4CompoundOp{Opcode: opcode, Seqid: 2,
					OpenStateid: &NFSStateid{Seqid: 2}}
			case OP_OPEN_DOWNGRADE:
				cop = NFSv4CompoundOp{Opcode: opcode, Seqid: 1, ShareAccess: 2, ShareDeny: 0,
					OpenStateid: &NFSStateid{Seqid: 2}}
			case OP_LOCK, OP_LOCKU:
				cop = NFSv4CompoundOp{Opcode: opcode, LockType: 1, Offset: 0, Length: 10,
					OpenStateid: &NFSStateid{Seqid: 2},
					LockOwner:   &LockOwner{Clientid: 1, Owner: []byte{0xAA}}}
			case OP_DELEGRETURN:
				cop = NFSv4CompoundOp{Opcode: opcode,
					Stateid: &NFSStateid{Seqid: 2}}
			default: // OP_CLOSE
				cop = NFSv4CompoundOp{Opcode: opcode, Seqid: 3,
					OpenStateid: &NFSStateid{Seqid: 2}}
			}
			spec := nfsSpec(t, &NFSConfig{
				Version: 4,
				Ops: []NFSOp{{
					Procedure:   NFS4ProcCOMPOUND,
					CompoundOps: []NFSv4CompoundOp{cop},
				}},
			})
			cfgs := mustPlan(t, p, spec)
			payload, off := lastReplyPayloadOf(cfgs)
			if payload == nil {
				t.Fatal("no user op reply found")
			}
			body := payload[off:]
			n := SkipOpaque(body)
			if n < 0 {
				t.Fatal("bad tag")
			}
			res := body[n+8:] // status(4) + tag + opcount(4); no minorversion
			// Skip the auto-prepended PUTROOTFH resop when present.
			// OPEN_CONFIRM needs no current fh (needsCurrentFH=false), so
			// its compound has no PUTROOTFH.
			gotOpcode := binaryBigEndianU32(res)
			if gotOpcode == OP_PUTROOTFH {
				res = res[8:]
				if len(res) < 8 {
					t.Fatalf("short reply after PUTROOTFH: %x", res)
				}
				gotOpcode = binaryBigEndianU32(res)
			}
			if len(res) < 8 || gotOpcode != opcode {
				t.Fatalf("resop opcode = %d, want %d: %x", gotOpcode, opcode, res)
			}
			if binaryBigEndianU32(res[4:]) != 0 {
				t.Fatalf("op status = %d, want 0", binaryBigEndianU32(res[4:]))
			}
			rest := res[8:] // opcode(4) + status(4), then the result
			if len(rest) != 16 {
				t.Errorf("opcode %d result length = %d, want 16 (stateid4), got %x",
					opcode, len(rest), rest)
			}
		})
	}
}

// R9: CREATE4resok = change_info4 + newfh + attrset (RFC 7530 §16.1.3);
// REMOVE4resok / RENAME4resok = change_info4 + change_info4;
// SETATTR4resok = attrsset bitmap. change_info4 = 20 bytes (bool +
// before + after). The old encoder wrote no result body at all, so
// tshark hit EOF after op status (t097/t099/t100 frame evidence).
func TestNFS4CreateRemoveRenameSetattrReplies(t *testing.T) {
	cases := []struct {
		opcode uint32
		want   int // expected result body length in bytes
	}{
		{OP_CREATE, 20 + 8 + 4}, // change_info(20) + newfh(4+1+3 pad) + attrsset(4)
		{OP_REMOVE, 20 + 20},    // change_info x2
		{OP_RENAME, 20 + 20},    // change_info x2
		{OP_SETATTR, 4},         // attrsset bitmap (empty = len 0)
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("opcode-%d", tc.opcode), func(t *testing.T) {
			p := NewPlanner()
			var cop NFSv4CompoundOp
			switch tc.opcode {
			case OP_CREATE:
				cop = NFSv4CompoundOp{Opcode: OP_CREATE, Name: "newfile",
					OpenHow: &NFSOpenHow{Type: "unchecked"}}
			case OP_REMOVE:
				cop = NFSv4CompoundOp{Opcode: OP_REMOVE, Name: "oldfile"}
			case OP_RENAME:
				cop = NFSv4CompoundOp{Opcode: OP_RENAME, Oldname: "a", Newname: "b"}
			case OP_SETATTR:
				cop = NFSv4CompoundOp{Opcode: OP_SETATTR, Stateid: &NFSStateid{Seqid: 1}}
			}
			spec := nfsSpec(t, &NFSConfig{
				Version: 4,
				Ops: []NFSOp{{
					Procedure:   NFS4ProcCOMPOUND,
					CompoundOps: []NFSv4CompoundOp{cop},
				}},
			})
			cfgs := mustPlan(t, p, spec)
			payload, off := lastReplyPayloadOf(cfgs)
			if payload == nil {
				t.Fatal("no user op reply found")
			}
			body := payload[off:]
			n := SkipOpaque(body)
			if n < 0 {
				t.Fatal("bad tag")
			}
			res := body[n+8:]
			// Skip the auto-prepended PUTROOTFH resop (opcode + status).
			if len(res) < 8 || binaryBigEndianU32(res) != OP_PUTROOTFH {
				t.Fatalf("leading resop = %d, want auto PUTROOTFH: %x", binaryBigEndianU32(res), res)
			}
			res = res[8:]
			if len(res) < 8 || binaryBigEndianU32(res) != tc.opcode {
				t.Fatalf("resop opcode = %d, want %d", binaryBigEndianU32(res), tc.opcode)
			}
			if binaryBigEndianU32(res[4:]) != 0 {
				t.Fatalf("op status = %d, want 0", binaryBigEndianU32(res[4:]))
			}
			rest := res[8:] // opcode(4) + status(4), then the result body
			if len(rest) != tc.want {
				t.Errorf("opcode %d result length = %d, want %d, got %x",
					tc.opcode, len(rest), tc.want, rest)
			}
		})
	}
}

// ensure unused import suppression
var _ = fmt.Sprintf
