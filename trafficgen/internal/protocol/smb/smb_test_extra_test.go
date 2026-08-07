// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb_test_extra.go: Additional integration tests for SMB2/SMB3 planner.
package smb

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// findPSHPackets returns all PSH-ACK packets from the plan output.
func findPSHPackets(packets []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, p := range packets {
		if p.L4.Flags == 0x18 && len(p.Payload) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// parsePDUFromPayload extracts an SMB2 PDU from a PacketConfig payload (with NBSS).
func parsePDUFromPayload(t *testing.T, payload []byte) *ParsedPDU {
	t.Helper()
	if len(payload) < 4 {
		t.Fatal("payload too short")
	}
	if payload[0] != 0x00 {
		t.Fatalf("expected NBSS type 0x00, got %X", payload[0])
	}
	parsed, err := ParsePDU(payload, true)
	if err != nil {
		t.Fatalf("ParsePDU failed: %v", err)
	}
	return parsed
}

// TestPlan_NegotiateRequest verifies NEGOTIATE request PDU structure.
func TestPlan_NegotiateRequest(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	if len(psh) == 0 {
		t.Fatal("no PSH-ACK packets")
	}
	p := psh[0]
	if p.Direction != "up" {
		t.Errorf("first PSH-ACK direction = %q, want up", p.Direction)
	}
	parsed := parsePDUFromPayload(t, p.Payload)
	if parsed.Command != CmdNegotiate {
		t.Errorf("Command = %X, want NEGOTIATE (%X)", parsed.Command, CmdNegotiate)
	}
	if parsed.MessageID != 0 {
		t.Errorf("NEGOTIATE req MessageId = %d, want 0", parsed.MessageID)
	}
	if parsed.Flags != 0 {
		t.Errorf("NEGOTIATE req Flags = %X, want 0", parsed.Flags)
	}
}

// TestPlan_NegotiateResponse verifies NEGOTIATE response has SERVER_TO_REDIR flag.
func TestPlan_NegotiateResponse(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	if len(psh) < 2 {
		t.Fatal("expected at least 2 PSH-ACK packets")
	}
	var negotiateResp *core.PacketConfig
	for i := range psh {
		if psh[i].Direction == "down" {
			negotiateResp = &psh[i]
			break
		}
	}
	if negotiateResp == nil {
		t.Fatal("no down PSH-ACK found")
	}
	parsed := parsePDUFromPayload(t, negotiateResp.Payload)
	if parsed.Command != CmdNegotiate {
		t.Errorf("Command = %X, want NEGOTIATE", parsed.Command)
	}
	if parsed.Flags&FlagServerToRedir == 0 {
		t.Errorf("NEGOTIATE resp must have SERVER_TO_REDIR flag, got %X", parsed.Flags)
	}
}

// TestPlan_SessionSetup_AuthenticatedRounds verifies NTLM uses 3 rounds.
func TestPlan_SessionSetup_AuthenticatedRounds(t *testing.T) {
	spec := testSpec() // default: ntlm, 3 rounds
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	if len(psh) < 8 {
		t.Fatalf("expected >= 8 PSH-ACK packets with NTLM 3 rounds, got %d", len(psh))
	}

	sessionCount := 0
	for _, p := range psh {
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdSessionSetup {
			sessionCount++
		}
	}
	if sessionCount != 6 {
		t.Errorf("SESSION_SETUP count = %d, want 6 (3 rounds × 2 directions)", sessionCount)
	}
}

// TestPlan_NBSSLengthField verifies NBSS length encoding (big-endian 3 bytes).
func TestPlan_NBSSLengthField(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	if len(psh) == 0 {
		t.Fatal("no PSH-ACK packets")
	}
	p := psh[0]
	nbssLen := uint32(p.Payload[1])<<16 | uint32(p.Payload[2])<<8 | uint32(p.Payload[3])
	wantLen := uint32(len(p.Payload) - 4)
	if nbssLen != wantLen {
		t.Errorf("NBSS length = %d, want %d", nbssLen, wantLen)
	}
}

// TestPlan_TransportNetBIOS verifies netbios transport is accepted.
func TestPlan_TransportNetBIOS(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.Transport = "netbios"
	})
	if err := NewPlanner().Validate(spec); err != nil {
		t.Errorf("validate netbios: %v", err)
	}
	cfg, _ := LookupSMBConfig(spec)
	if cfg.Transport != "netbios" {
		t.Errorf("Transport = %q", cfg.Transport)
	}
}

// TestPlan_KerberosAuth verifies kerberos uses 2 rounds.
func TestPlan_KerberosAuth(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.AuthMechanism = "kerberos"
	})
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	sessionCount := 0
	for _, p := range psh {
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdSessionSetup {
			sessionCount++
		}
	}
	if sessionCount != 4 {
		t.Errorf("kerberos SESSION_SETUP count = %d, want 4", sessionCount)
	}
}

// TestPlan_AnonymousAuth verifies anonymous uses 1 round.
func TestPlan_AnonymousAuth(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.AuthMechanism = "anonymous"
	})
	packets := collectPlan(t, spec)

	psh := findPSHPackets(packets)
	sessionCount := 0
	for _, p := range psh {
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdSessionSetup {
			sessionCount++
		}
	}
	if sessionCount != 2 {
		t.Errorf("anonymous SESSION_SETUP count = %d, want 2", sessionCount)
	}
}

// TestPlan_TreeConnectPath verifies TREE_CONNECT path encoding.
func TestPlan_TreeConnectPath(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	for _, p := range packets {
		if p.L4.Flags != 0x18 || p.Direction != "up" || p.L4.Protocol != "tcp" {
			continue
		}
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdTreeConnect {
			_, _, path, err := ParseTreeConnectRequest(parsed.Body)
			if err != nil {
				t.Fatalf("ParseTreeConnectRequest: %v", err)
			}
			if path != "\\\\server\\share" {
				t.Errorf("path = %q, want \\\\server\\share", path)
			}
			return
		}
	}
	t.Fatal("TREE_CONNECT request not found")
}

// TestPlan_CreateFileName verifies CREATE file name encoding.
func TestPlan_CreateFileName(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	for _, p := range packets {
		if p.L4.Flags != 0x18 || p.Direction != "up" {
			continue
		}
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdCreate {
			_, _, _, _, _, _, _, _, name, err := ParseCreateRequest(parsed.Body)
			if err != nil {
				t.Fatalf("ParseCreateRequest: %v", err)
			}
			if name != "file.txt" {
				t.Errorf("CREATE name = %q, want file.txt", name)
			}
			return
		}
	}
	t.Fatal("CREATE request not found")
}

// TestPlan_ReadLength verifies READ Length field.
func TestPlan_ReadLength(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	for _, p := range packets {
		if p.L4.Flags != 0x18 || p.Direction != "up" {
			continue
		}
		if len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdRead {
			length, _, _, err := ParseReadRequest(parsed.Body)
			if err != nil {
				t.Fatalf("ParseReadRequest: %v", err)
			}
			if length != 4096 {
				t.Errorf("READ length = %d, want 4096", length)
			}
			return
		}
	}
	t.Fatal("READ request not found")
}
