// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb_test.go: Core test cases for the SMB2/SMB3 planner.
package smb

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// testSpec creates a basic SMB FlowSpec with sensible defaults.
func testSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 49152,
		DstPort: 445,
		SrcMAC:  "00:11:22:33:44:55",
		DstMAC:  "66:77:88:99:aa:bb",
		TTL:     64,
		SMB:     &SMBConfig{},
	}
}

// testSpecWith creates an SMB FlowSpec with a custom config.
func testSpecWith(mutate func(*SMBConfig)) core.FlowSpec {
	cfg := &SMBConfig{}
	if mutate != nil {
		mutate(cfg)
	}
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 49152,
		DstPort: 445,
		SrcMAC:  "00:11:22:33:44:55",
		DstMAC:  "66:77:88:99:aa:bb",
		TTL:     64,
		SMB:     cfg,
	}
}

// collectPlan runs the planner and gathers all emitted packets.
func collectPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// TestPlanner_Name verifies the protocol name.
func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "smb" {
		t.Errorf("Name() = %q, want %q", got, "smb")
	}
}

// TestValidate_Default verifies that default config validates OK.
func TestValidate_Default(t *testing.T) {
	spec := testSpec()
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("default Validate failed: %v", err)
	}
}

// TestValidate_MissingConfig verifies error when no SMB config is present.
func TestValidate_MissingConfig(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 49152,
		DstPort: 445,
		SMB:     nil,
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for missing smb config")
	}
	if _, err := LookupSMBConfig(spec); err == nil {
		t.Errorf("expected error from LookupSMBConfig for spec.SMB=nil")
	}
}

// TestValidate_BadDialect verifies V1 enforcement.
func TestValidate_BadDialect(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.Dialects = []string{"0x9999"}
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for invalid dialect")
	}
}

// TestValidate_SMB1 verifies V2 enforcement (no SMB1 strings).
func TestValidate_SMB1(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.Dialects = []string{"NT LM 0.12"}
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for SMB1 dialect string")
	}
}

// TestValidate_AuthRounds verifies V12-V16 enforcement.
func TestValidate_AuthRounds(t *testing.T) {
	// V16: ntlm + AuthRounds=1 invalid
	spec := testSpecWith(func(c *SMBConfig) {
		c.AuthMechanism = "ntlm"
		c.AuthRounds = 1
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for ntlm + AuthRounds=1")
	}

	// V13: anonymous + AuthRounds=3 invalid
	spec = testSpecWith(func(c *SMBConfig) {
		c.AuthMechanism = "anonymous"
		c.AuthRounds = 3
	})
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for anonymous + AuthRounds=3")
	}

	// V12: AuthRounds=10 invalid
	spec = testSpecWith(func(c *SMBConfig) {
		c.AuthRounds = 10
	})
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for AuthRounds=10")
	}
}

// TestValidate_ErrorConsistency verifies V29-V31.
func TestValidate_ErrorConsistency(t *testing.T) {
	// ErrorResponseStatus set without ErrorOnCommand
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = StatusObjectNameNotFound
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for status without command")
	}

	// ErrorOnCommand set without ErrorResponseStatus
	spec = testSpecWith(func(c *SMBConfig) {
		c.ErrorOnCommand = "create"
	})
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for command without status")
	}

	// Unknown status code
	spec = testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = 0xDEADBEEF
		c.ErrorOnCommand = "create"
	})
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for unknown status code")
	}
}

// TestValidate_SizeLimits verifies V32-V34.
func TestValidate_SizeLimits(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.MaxTransactSize = 0xFFFFFFFF
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for MaxTransactSize > 16777215")
	}
}

// TestValidate_ShareType verifies V19.
func TestValidate_ShareType(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ShareType = 9
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for ShareType=9")
	}
}

// TestValidate_BadUNC verifies V18.
func TestValidate_BadUNC(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.TreeConnectShare = "share"
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for non-UNC share path")
	}
}

// TestValidate_BadOperations verifies V23.
func TestValidate_BadOperations(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.Operations = []SMBOperation{{OpType: "delete"}}
	})
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for invalid OpType")
	}
}

// TestApplyDefaults verifies default values are populated.
func TestApplyDefaults(t *testing.T) {
	cfg := applyDefaults(&SMBConfig{})

	if len(cfg.Dialects) == 0 {
		t.Error("Dialects should default to 5")
	}
	if cfg.SelectedDialect == "" {
		t.Error("SelectedDialect should default")
	}
	if cfg.AuthMechanism != "ntlm" {
		t.Errorf("AuthMechanism default = %q, want ntlm", cfg.AuthMechanism)
	}
	if cfg.AuthRounds != 3 {
		t.Errorf("AuthRounds default for ntlm = %d, want 3", cfg.AuthRounds)
	}
	if cfg.TreeConnectShare != "\\\\server\\share" {
		t.Errorf("TreeConnectShare default = %q", cfg.TreeConnectShare)
	}
	if cfg.FilePath != "file.txt" {
		t.Errorf("FilePath default = %q", cfg.FilePath)
	}
	if cfg.CreateDisposition != 1 {
		t.Errorf("CreateDisposition default = %d", cfg.CreateDisposition)
	}
	if cfg.AccessMask != 0x00120089 {
		t.Errorf("AccessMask default = %X", cfg.AccessMask)
	}
	if cfg.FileAttributes != 0x80 {
		t.Errorf("FileAttributes default = %X", cfg.FileAttributes)
	}
	if cfg.ShareAccess != 0x07 {
		t.Errorf("ShareAccess default = %X", cfg.ShareAccess)
	}
	if cfg.MaxTransactSize != 65536 {
		t.Errorf("MaxTransactSize default = %d", cfg.MaxTransactSize)
	}
	if cfg.MaxReadSize != 1048576 {
		t.Errorf("MaxReadSize default = %d", cfg.MaxReadSize)
	}
	if cfg.MaxWriteSize != 1048576 {
		t.Errorf("MaxWriteSize default = %d", cfg.MaxWriteSize)
	}
}

// TestApplyDefaults_CapabilityDowngrade verifies M-7 (dialect-based bit clearing).
func TestApplyDefaults_CapabilityDowngrade(t *testing.T) {
	// dialect 0x0202: Encryption bit should be cleared
	cfg := applyDefaults(&SMBConfig{Dialects: []string{"0x0202"}})
	if cfg.ClientCapabilities&GlobalCapEncryption != 0 {
		t.Errorf("0x0202 should not have Encryption bit set, got %X", cfg.ClientCapabilities)
	}

	// dialect 0x0311: Encryption bit should remain
	cfg = applyDefaults(&SMBConfig{Dialects: []string{"0x0311"}})
	if cfg.ClientCapabilities&GlobalCapEncryption == 0 {
		t.Errorf("0x0311 should have Encryption bit set, got %X", cfg.ClientCapabilities)
	}
}

// TestApplyDefaults_IPCShareType verifies V20 (auto ShareType=1 for IPC$).
func TestApplyDefaults_IPCShareType(t *testing.T) {
	cfg := applyDefaults(&SMBConfig{TreeConnectShare: "\\\\server\\IPC$"})
	if cfg.ShareType != 1 {
		t.Errorf("IPC$ should auto-set ShareType=1, got %d", cfg.ShareType)
	}
}

// TestApplyDefaults_OperationsDefault verifies V24.
func TestApplyDefaults_OperationsDefault(t *testing.T) {
	cfg := applyDefaults(&SMBConfig{})
	if len(cfg.Operations) != 1 || cfg.Operations[0].OpType != "read" {
		t.Errorf("Operations default = %+v", cfg.Operations)
	}
	if cfg.Operations[0].Length != 4096 {
		t.Errorf("READ default Length = %d", cfg.Operations[0].Length)
	}
}

// TestPlan_Basic runs a full default session and verifies the packet count.
func TestPlan_Basic(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	// 3 TCP SYN/SYN-ACK/ACK + 2*NEGOTIATE + 6*SESSION_SETUP(NTLM3) + 2*TREE_CONNECT +
	// 2*CREATE + 2*READ + 2*CLOSE + 2*TREE_DISCONNECT + 2*LOGOFF + 3 TCP FIN = ?
	// Default: 3 + 20 (10 SMB pairs) + 4 TCP teardown = 27 packets total
	// Total SMB PDU = 20 (10 pairs)
	// Non-SMB = 7 (TCP handshake/teardown)
	if len(packets) < 20 {
		t.Errorf("expected at least 20 packets, got %d", len(packets))
	}
}

// TestPlan_PacketStructure verifies packets have correct L3/L4 layout.
func TestPlan_PacketStructure(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)
	if len(packets) == 0 {
		t.Fatal("no packets emitted")
	}

	// First packet should be TCP SYN
	p0 := packets[0]
	if p0.Direction != "up" {
		t.Errorf("packet 0 direction = %q", p0.Direction)
	}
	if p0.L4.Protocol != "tcp" {
		t.Errorf("packet 0 protocol = %q", p0.L4.Protocol)
	}
	if p0.L4.Flags != 0x02 {
		t.Errorf("packet 0 TCP flags = %X, want 0x02 (SYN)", p0.L4.Flags)
	}
}

// TestPlan_PayloadContainsSMB verifies PSH-ACK packets carry SMB2 PDUs.
func TestPlan_PayloadContainsSMB(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	// Find first PSH-ACK with payload starting with NBSS (0x00).
	var firstPSH *core.PacketConfig
	for i := range packets {
		p := &packets[i]
		if p.L4.Flags == 0x18 && len(p.Payload) > 4 {
			if p.Payload[0] == 0x00 {
				firstPSH = p
				break
			}
		}
	}
	if firstPSH == nil {
		t.Fatal("no PSH-ACK with NBSS prefix found")
	}

	// NBSS length (BE 3 bytes at offset 1-3) + ProtocolId (LE 4 bytes)
	// After NBSS: 0xFE 0x53 0x4D 0x42 (ProtocolId)
	if len(firstPSH.Payload) < 8 {
		t.Fatal("payload too short for NBSS+SMB2 header")
	}
	if firstPSH.Payload[4] != 0xFE || firstPSH.Payload[5] != 0x53 ||
		firstPSH.Payload[6] != 0x4D || firstPSH.Payload[7] != 0x42 {
		t.Errorf("SMB2 ProtocolId not found, got % X", firstPSH.Payload[4:8])
	}
}

// TestParser_ParsePDU verifies the parser round-trip on a real PDU.
func TestParser_ParsePDU(t *testing.T) {
	// Build a minimal SMB2 header
	hdr := buildSMB2Header(CmdNegotiate, 1, 0, 0, 0, 0, 0)
	body := buildNegotiateRequestBody([]uint16{0x0311}, 0x01, 0x03,
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		[]uint16{0x0001}, []uint16{0x0001, 0x0002})
	pdu := append(hdr, body...)
	nbssPDU := append(buildNBSSHeader(len(pdu)), pdu...)

	parsed, err := ParsePDU(nbssPDU, true)
	if err != nil {
		t.Fatalf("ParsePDU failed: %v", err)
	}
	if parsed.Command != CmdNegotiate {
		t.Errorf("Command = %X, want %X", parsed.Command, CmdNegotiate)
	}
	if parsed.MessageID != 0 {
		t.Errorf("MessageID = %d, want 0", parsed.MessageID)
	}
	if parsed.NBSSLength != uint32(len(pdu)) {
		t.Errorf("NBSSLength = %d, want %d", parsed.NBSSLength, len(pdu))
	}
}

// TestBuilder_NegotiateRequest verifies field-by-field correctness.
func TestBuilder_NegotiateRequest(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	body := buildNegotiateRequestBody([]uint16{0x0202, 0x0311}, 0x01, 0x03, guid,
		nil, nil)
	if len(body) < 36 {
		t.Fatal("body too short")
	}
	// StructureSize = 36
	if body[0] != 0x24 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 24 00", body[0], body[1])
	}
	// DialectCount = 2
	if body[2] != 0x02 || body[3] != 0x00 {
		t.Errorf("DialectCount = %X %X, want 02 00", body[2], body[3])
	}
	// SecurityMode = 0x01
	if body[4] != 0x01 {
		t.Errorf("SecurityMode = %X", body[4])
	}
	// Capabilities = 0x03
	if body[8] != 0x03 || body[11] != 0x00 {
		t.Errorf("Capabilities = %X %X %X %X", body[8], body[9], body[10], body[11])
	}
	// ClientGuid bytes
	for i := 0; i < 16; i++ {
		if body[12+i] != byte(i+1) {
			t.Errorf("ClientGuid[%d] = %X, want %X", i, body[12+i], i+1)
		}
	}
	// Dialects array: 02 02 11 03
	if body[36] != 0x02 || body[37] != 0x02 {
		t.Errorf("Dialect[0] = %X %X", body[36], body[37])
	}
	if body[38] != 0x11 || body[39] != 0x03 {
		t.Errorf("Dialect[1] = %X %X", body[38], body[39])
	}
}

// TestBuilder_SessionSetupRequest verifies SESSION_SETUP request layout.
func TestBuilder_SessionSetupRequest(t *testing.T) {
	body := buildSessionSetupRequestBody(0, 0x01, 0x01, 0, []byte{1, 2, 3}, 0)
	if len(body) < 24 {
		t.Fatal("body too short")
	}
	// StructureSize = 25
	if body[0] != 0x19 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 19 00", body[0], body[1])
	}
	// SecurityMode = 0x01
	if body[3] != 0x01 {
		t.Errorf("SecurityMode = %X", body[3])
	}
	// SecurityBufferOffset = 88
	if body[12] != 0x58 || body[13] != 0x00 {
		t.Errorf("SecurityBufferOffset = %X %X, want 58 00", body[12], body[13])
	}
	// SecurityBufferLength = 3
	if body[14] != 0x03 || body[15] != 0x00 {
		t.Errorf("SecurityBufferLength = %X %X", body[14], body[15])
	}
	// PreviousSessionId = 0
	if body[16] != 0x00 || body[23] != 0x00 {
		t.Errorf("PreviousSessionId not zero")
	}
}

// TestBuilder_TreeConnectRequest verifies TREE_CONNECT path encoding.
func TestBuilder_TreeConnectRequest(t *testing.T) {
	body := buildTreeConnectRequestBody("\\\\server\\share")
	if len(body) < 8 {
		t.Fatal("body too short")
	}
	// StructureSize = 9
	if body[0] != 0x09 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X", body[0], body[1])
	}
	// PathOffset = 72 (64+8)
	if body[4] != 0x48 || body[5] != 0x00 {
		t.Errorf("PathOffset = %X %X, want 48 00", body[4], body[5])
	}
	// PathLength = 28 (14 chars × 2: "\\server\share" is 14 UTF-16 units)
	if body[6] != 0x1C || body[7] != 0x00 {
		t.Errorf("PathLength = %X %X, want 1C 00", body[6], body[7])
	}
	// First 4 bytes of UTF-16LE: 5C 00 5C 00
	if body[8] != 0x5C || body[9] != 0x00 ||
		body[10] != 0x5C || body[11] != 0x00 {
		t.Errorf("UTF-16LE start = % X", body[8:12])
	}
}

// TestBuilder_CreateRequest verifies CREATE request NameOffset.
func TestBuilder_CreateRequest(t *testing.T) {
	body := buildCreateRequestBody(2, 0x00120089, 0x80, 0x07, 1, 0, "file.txt")
	if len(body) < 56 {
		t.Fatal("body too short")
	}
	// StructureSize = 57
	if body[0] != 0x39 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 39 00", body[0], body[1])
	}
	// ImpersonationLevel = 2
	if body[4] != 0x02 || body[7] != 0x00 {
		t.Errorf("ImpersonationLevel = %X", body[4:8])
	}
	// NameOffset = 120
	if body[44] != 0x78 || body[45] != 0x00 {
		t.Errorf("NameOffset = %X %X, want 78 00", body[44], body[45])
	}
	// NameLength = 16
	if body[46] != 0x10 || body[47] != 0x00 {
		t.Errorf("NameLength = %X %X, want 10 00", body[46], body[47])
	}
}

// TestBuilder_WriteRequest verifies WRITE DataOffset.
func TestBuilder_WriteRequest(t *testing.T) {
	body := buildWriteRequestBody(100, 0, [16]byte{}, []byte{1, 2, 3}, 0)
	if len(body) < 48 {
		t.Fatal("body too short")
	}
	// DataOffset = 112
	if body[2] != 0x70 || body[3] != 0x00 {
		t.Errorf("DataOffset = %X %X, want 70 00", body[2], body[3])
	}
}

// TestBuilder_ReadResponse verifies READ response DataOffset = 80.
// BUG #16 修复后响应体由 16 字节头 + dataLength 字节 data 组成。
func TestBuilder_ReadResponse(t *testing.T) {
	const dataLen = uint32(4096)
	body := buildReadResponseBody(dataLen, makeReadData(dataLen))
	if body[2] != 0x50 {
		t.Errorf("DataOffset = %X, want 50 (80)", body[2])
	}
	if uint32(len(body)-16) != dataLen {
		t.Errorf("response body data part = %d bytes, want %d", len(body)-16, dataLen)
	}
}

// TestBuilder_QueryDirectoryRequest verifies FileNameOffset = 96.
func TestBuilder_QueryDirectoryRequest(t *testing.T) {
	body := buildQueryDirectoryRequestBody([16]byte{}, 37, "*", 4096)
	if body[24] != 0x60 || body[25] != 0x00 {
		t.Errorf("FileNameOffset = %X %X, want 60 00", body[24], body[25])
	}
}

// TestCreditChargeFor verifies dialect-based CreditCharge.
func TestCreditChargeFor(t *testing.T) {
	if creditChargeFor(DialectSMB2_002) != 0 {
		t.Errorf("SMB2.002 CreditCharge should be 0")
	}
	if creditChargeFor(DialectSMB2_1) != 1 {
		t.Errorf("SMB2.1 CreditCharge should be 1")
	}
	if creditChargeFor(DialectSMB3_0) != 1 {
		t.Errorf("SMB3.0 CreditCharge should be 1")
	}
	if creditChargeFor(DialectSMB3_11) != 1 {
		t.Errorf("SMB3.1.1 CreditCharge should be 1")
	}
}

// TestSMBFlags verifies Flags field generation.
func TestSMBFlags(t *testing.T) {
	if smbFlags(false, false) != 0 {
		t.Errorf("request unsigned = %X", smbFlags(false, false))
	}
	if smbFlags(true, false) != FlagServerToRedir {
		t.Errorf("response unsigned = %X, want %X", smbFlags(true, false), FlagServerToRedir)
	}
	if smbFlags(false, true) != FlagSigned {
		t.Errorf("request signed = %X, want %X", smbFlags(false, true), FlagSigned)
	}
	if smbFlags(true, true) != (FlagServerToRedir | FlagSigned) {
		t.Errorf("response signed = %X", smbFlags(true, true))
	}
}

// TestNextSessionID verifies atomic SessionId allocation.
func TestNextSessionID(t *testing.T) {
	var wg sync.WaitGroup
	ids := make(map[uint64]bool)
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := nextSessionID()
			mu.Lock()
			ids[id] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}

// TestParseDialect verifies dialect string parsing.
func TestParseDialect(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
	}{
		{"0x0202", DialectSMB2_002},
		{"0x0210", DialectSMB2_1},
		{"0x0300", DialectSMB3_0},
		{"0x0302", DialectSMB3_02},
		{"0x0311", DialectSMB3_11},
		{"0x9999", 0},
	}
	for _, tt := range tests {
		got, err := parseDialect(tt.in)
		if tt.want == 0 {
			if err == nil {
				t.Errorf("parseDialect(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDialect(%q) error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("parseDialect(%q) = %X, want %X", tt.in, got, tt.want)
		}
	}
}

// TestKnownStatusCodes verifies the §3.26 status code whitelist.
func TestKnownStatusCodes(t *testing.T) {
	known := []uint32{
		StatusSuccess,
		StatusMoreProcessingRequired,
		StatusAccessDenied,
		StatusObjectNameNotFound,
		StatusObjectNameCollision,
		StatusInvalidParameter,
		StatusCancelled,
		StatusInvalidImageFormat,
		StatusBadNetworkName,
		StatusLogonFailure,
		StatusEndOfFile,
		StatusFileLockConflict,
		StatusUserSessionDeleted,
		StatusInvalidHandle,
	}
	if len(known) != 14 {
		t.Errorf("expected 14 known status codes, got %d", len(known))
	}
	for _, s := range known {
		if !IsKnownStatusCode(s) {
			t.Errorf("status %X should be known", s)
		}
	}
	if IsKnownStatusCode(0xDEADBEEF) {
		t.Errorf("0xDEADBEEF should not be a known status code")
	}
}

// TestDefaultAuthRounds verifies mechanism-based default rounds.
func TestDefaultAuthRounds(t *testing.T) {
	if defaultAuthRounds("ntlm") != 3 {
		t.Errorf("ntlm default rounds = %d, want 3", defaultAuthRounds("ntlm"))
	}
	if defaultAuthRounds("kerberos") != 2 {
		t.Errorf("kerberos default rounds = %d, want 2", defaultAuthRounds("kerberos"))
	}
	if defaultAuthRounds("anonymous") != 1 {
		t.Errorf("anonymous default rounds = %d, want 1", defaultAuthRounds("anonymous"))
	}
	if defaultAuthRounds("guest") != 1 {
		t.Errorf("guest default rounds = %d, want 1", defaultAuthRounds("guest"))
	}
}

// TestUtf16LE verifies UTF-8 to UTF-16LE encoding.
func TestUtf16LE(t *testing.T) {
	out := utf16LE("a")
	if len(out) != 2 || out[0] != 0x61 || out[1] != 0x00 {
		t.Errorf("utf16LE(\"a\") = % X, want 61 00", out)
	}
	out = utf16LE("file.txt")
	if len(out) != 16 {
		t.Errorf("utf16LE(\"file.txt\") len = %d, want 16", len(out))
	}
}

// TestAlign8 verifies 8-byte alignment.
func TestAlign8(t *testing.T) {
	b := []byte{1, 2, 3}
	out := align8(b)
	if len(out) != 8 {
		t.Errorf("align8 len = %d, want 8", len(out))
	}
	out = align8([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if len(out) != 8 {
		t.Errorf("align8 already-aligned len = %d, want 8", len(out))
	}
}

// TestBuildNBSSHeader verifies NBSS length encoding.
func TestBuildNBSSHeader(t *testing.T) {
	h := buildNBSSHeader(200)
	if h[0] != 0x00 {
		t.Errorf("NBSS type = %X", h[0])
	}
	// 200 = 0xC8
	if h[1] != 0x00 || h[2] != 0x00 || h[3] != 0xC8 {
		t.Errorf("NBSS length = %X %X %X, want 00 00 C8", h[1], h[2], h[3])
	}

	h = buildNBSSHeader(316)
	// 316 = 0x13C
	if h[1] != 0x00 || h[2] != 0x01 || h[3] != 0x3C {
		t.Errorf("NBSS length 316 = %X %X %X, want 00 01 3C", h[1], h[2], h[3])
	}
}

// TestPlan_AuthVariations verifies different AuthRounds produce different
// packet counts.
func TestPlan_AuthVariations(t *testing.T) {
	// NTLM 3 rounds (default)
	spec := testSpec()
	pkts3 := collectPlan(t, spec)

	// NTLM 2 rounds
	spec2 := testSpecWith(func(c *SMBConfig) {
		c.AuthMechanism = "ntlm"
		c.AuthRounds = 2
	})
	pkts2 := collectPlan(t, spec2)

	if len(pkts2) >= len(pkts3) {
		t.Errorf("2-round should produce fewer packets than 3-round")
	}
}

// TestPlan_DefaultAuthRounds verifies V12 (AuthRounds=0 → mechanism default).
func TestPlan_DefaultAuthRounds(t *testing.T) {
	for _, mech := range []string{"ntlm", "kerberos", "anonymous", "guest"} {
		spec := testSpecWith(func(c *SMBConfig) {
			c.AuthMechanism = mech
			c.AuthRounds = 0
		})
		if err := NewPlanner().Validate(spec); err != nil {
			t.Errorf("Validate(%s, 0) failed: %v", mech, err)
		}
	}
}

// TestPlan_TransportDirectDefault verifies Transport default.
func TestPlan_TransportDirectDefault(t *testing.T) {
	spec := testSpec()
	if err := NewPlanner().Validate(spec); err != nil {
		t.Errorf("default validate failed: %v", err)
	}
	cfg, _ := LookupSMBConfig(spec)
	if cfg.Transport != "" {
		t.Errorf("default Transport = %q, want empty (default direct)", cfg.Transport)
	}
}

// TestPlan_ErrorOnNegotiate verifies S15-style error injection.
func TestPlan_ErrorOnNegotiate(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = StatusInvalidParameter
		c.ErrorOnCommand = "negotiate"
	})
	packets := collectPlan(t, spec)
	// Should emit: TCP handshake + NEGOTIATE req + NEGOTIATE resp (error) +
	// TCP teardown. No LOGOFF because negotiate error short-circuits.
	if len(packets) == 0 {
		t.Fatal("expected some packets")
	}
}

// TestPlan_ErrorOnCreate verifies S15-style create error with teardown.
func TestPlan_ErrorOnCreate(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = StatusObjectNameNotFound
		c.ErrorOnCommand = "create"
	})
	packets := collectPlan(t, spec)
	// Should include TREE_DISCONNECT + LOGOFF after CREATE error.
	if len(packets) < 15 {
		t.Errorf("expected at least 15 packets, got %d", len(packets))
	}
}

// TestPlan_IncludeFlags verifies the Include* flags control stage skipping.
func TestPlan_IncludeFlags(t *testing.T) {
	f := false
	spec := testSpecWith(func(c *SMBConfig) {
		c.IncludeNegotiate = &f
	})
	if err := NewPlanner().Validate(spec); err != nil {
		t.Fatalf("validate: %v", err)
	}
	packets := collectPlan(t, spec)
	if len(packets) == 0 {
		t.Fatal("expected some packets")
	}

	// Find first PSH-ACK and check its Command
	for _, p := range packets {
		if p.L4.Flags == 0x18 && len(p.Payload) > 8 {
			// NBSS (4B) + SMB2 header (64B), Command at NBSS+12 (offset 12 within SMB2 hdr)
			if p.Payload[0] == 0x00 {
				cmdOffset := 4 + 12
				cmd := uint16(p.Payload[cmdOffset]) | uint16(p.Payload[cmdOffset+1])<<8
				if cmd != CmdSessionSetup {
					t.Errorf("first SMB command = %X, want SESSION_SETUP (%X)", cmd, CmdSessionSetup)
				}
				return
			}
		}
	}
}

// TestSessionID_Allocated verifies SESSION_SETUP response allocates a non-zero SessionId.
func TestSessionID_Allocated(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	// Find SESSION_SETUP response (direction="down", CmdSessionSetup)
	for _, p := range packets {
		if p.L4.Flags == 0x18 && p.Direction == "down" && len(p.Payload) > 8 {
			if p.Payload[0] == 0x00 {
				parsed, err := ParsePDU(p.Payload, true)
				if err != nil || parsed.Command != CmdSessionSetup {
					continue
				}
				if parsed.SessionID == 0 {
					t.Error("SESSION_SETUP resp SessionId should be non-zero")
				}
				return
			}
		}
	}
}

// TestPlan_MultipleSessions verifies SessionId uniqueness across concurrent sessions.
func TestPlan_MultipleSessions(t *testing.T) {
	const N = 5
	var wg sync.WaitGroup
	sids := make(map[uint64]bool)
	var mu sync.Mutex

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec := testSpec()
			packets := collectPlan(t, spec)
			// Extract SessionId from first SESSION_SETUP response
			for _, p := range packets {
				if p.L4.Flags == 0x18 && p.Direction == "down" && len(p.Payload) > 8 {
					if p.Payload[0] == 0x00 {
						parsed, err := ParsePDU(p.Payload, true)
						if err != nil || parsed.Command != CmdSessionSetup {
							continue
						}
						sid := parsed.SessionID
						mu.Lock()
						sids[sid] = true
						mu.Unlock()
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	if len(sids) < N {
		t.Errorf("expected at least %d unique SessionIds, got %d", N, len(sids))
	}
}

// TestBuildPreauthContext verifies the SMB3.1.1 Preauth Integrity context.
func TestBuildPreauthContext(t *testing.T) {
	ctx := buildPreauthContext([]uint16{HashSHA512})
	if len(ctx) < 8 {
		t.Fatal("context too short")
	}
	if ctx[0] != 0x01 || ctx[1] != 0x00 {
		t.Errorf("ContextType = %X %X, want 01 00", ctx[0], ctx[1])
	}
	// HashAlgorithms: 01 00
	if ctx[8] != 0x01 || ctx[9] != 0x00 {
		t.Errorf("HashAlgorithmCount = %X %X, want 01 00", ctx[8], ctx[9])
	}
	// SaltLength: 32 = 0x20
	if ctx[10] != 0x20 || ctx[11] != 0x00 {
		t.Errorf("SaltLength = %X %X, want 20 00", ctx[10], ctx[11])
	}
	// HashAlgorithms[0] = 0x0001
	if ctx[12] != 0x01 || ctx[13] != 0x00 {
		t.Errorf("HashAlgorithms[0] = %X %X", ctx[12], ctx[13])
	}
}

// TestBuildEncryptionContext verifies the SMB3.1.1 Encryption context.
func TestBuildEncryptionContext(t *testing.T) {
	ctx := buildEncryptionContext([]uint16{EncryptAESCCM, EncryptAESGCM})
	if ctx[0] != 0x02 || ctx[1] != 0x00 {
		t.Errorf("ContextType = %X %X, want 02 00", ctx[0], ctx[1])
	}
	// CipherCount = 2
	if ctx[8] != 0x02 || ctx[9] != 0x00 {
		t.Errorf("CipherCount = %X %X", ctx[8], ctx[9])
	}
	// Ciphers: 01 00 02 00
	if ctx[10] != 0x01 || ctx[12] != 0x02 {
		t.Errorf("Ciphers = %X %X", ctx[10], ctx[12])
	}
}

// TestPlan_MessageID_NotInflated verifies BUG #5 修复.
// 原 bug: 每个 request/response 对各递增一次 messageID, 导致 MessageId 翻倍.
// 修复后预期: NTLM 3轮默认 session 输出的 request MessageId 序列为
// 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 7 (NEGOTIATE req=0, NEGOTIATE resp=0,
// SESSION_SETUP r1 req=1, resp=1, r2 req=2, resp=2, r3 req=3, resp=3,
// TREE_CONNECT req=4, CREATE req=5, READ req=6, CLOSE req=7).
// 关键检查: 相邻两个 request 的 MessageId 差值为 1 (不是 2), 而且
// SESSION_SETUP req 和 resp 共用同一 MessageId.
func TestPlan_MessageID_NotInflated(t *testing.T) {
	spec := testSpec() // NTLM 3 rounds
	packets := collectPlan(t, spec)

	type pduPair struct {
		cmd   uint16
		dir   string
		msgID uint64
	}
	var seq []pduPair
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdNegotiate ||
			parsed.Command == CmdSessionSetup ||
			parsed.Command == CmdTreeConnect ||
			parsed.Command == CmdCreate ||
			parsed.Command == CmdRead ||
			parsed.Command == CmdWrite ||
			parsed.Command == CmdClose ||
			parsed.Command == CmdTreeDisconnect ||
			parsed.Command == CmdLogoff {
			seq = append(seq, pduPair{cmd: parsed.Command, dir: p.Direction, msgID: parsed.MessageID})
		}
	}
	if len(seq) < 4 {
		t.Fatalf("not enough PDUs collected, got %d", len(seq))
	}

	// 检查 1: 第一个 (NEGOTIATE request) MessageId 必须为 0。
	if seq[0].cmd != CmdNegotiate || seq[0].dir != "up" || seq[0].msgID != 0 {
		t.Errorf("first PDU should be NEGOTIATE req msgID=0, got cmd=%X dir=%q msgID=%d",
			seq[0].cmd, seq[0].dir, seq[0].msgID)
	}

	// 检查 2: NEGOTIATE req/resp 共用同一 MessageId (=0)。
	if seq[1].cmd != CmdNegotiate || seq[1].dir != "down" || seq[1].msgID != 0 {
		t.Errorf("NEGOTIATE resp should share msgID=0, got cmd=%X dir=%q msgID=%d",
			seq[1].cmd, seq[1].dir, seq[1].msgID)
	}

	// 检查 3: SESSION_SETUP 三对 request/response, 每个 req 和 对应 resp
	// MessageId 相等 (即 NTLM round1=1, round2=2, round3=3).
	for i := 2; i+1 < len(seq) && seq[i].cmd == CmdSessionSetup; i += 2 {
		if i+1 >= len(seq) || seq[i+1].cmd != CmdSessionSetup ||
			seq[i+1].dir != "down" {
			t.Errorf("SESSION_SETUP pair broken at index %d", i)
			continue
		}
		if seq[i].msgID != seq[i+1].msgID {
			t.Errorf("BUG #5: SESSION_SETUP req/resp msgID mismatch: req=%d resp=%d",
				seq[i].msgID, seq[i+1].msgID)
		}
	}

	// 检查 4: 任意两个相邻 request 的 MessageId 差值必须 <= 1.
	// BUG #5 触发时差值为 2; 修复后差值为 0 (共用于 resp) 或 1 (下一个 req).
	for i := 0; i+1 < len(seq); i++ {
		curr, next := seq[i], seq[i+1]
		if curr.dir != "up" || next.dir != "up" {
			continue // 只比较相邻两个 request
		}
		// 跳过 SESSION_SETUP 第一轮的 resp → 下一轮 req 之间的特例
		diff := int64(next.msgID) - int64(curr.msgID)
		if diff > 1 {
			t.Errorf("BUG #5 复现: adjacent request MessageIds inflated. "+
				"cmd=%X→%X msgID %d→%d (diff=%d, want <=1)",
				curr.cmd, next.cmd, curr.msgID, next.msgID, diff)
		}
	}
}

// TestPlan_ReadResponseCarriesData verifies BUG #16 修复.
// 原 bug: READ 响应体仅含 16 字节头部 (DataLength 声明了长度但无 data).
// 修复后: 响应体尾部追加 op.Length 字节的数据, 供 Wireshark 解析为完整 PDU.
func TestPlan_ReadResponseCarriesData(t *testing.T) {
	const wantLen = uint32(4096)
	spec := testSpecWith(func(c *SMBConfig) {
		c.Operations = []SMBOperation{{OpType: "read", Offset: 0, Length: wantLen}}
	})
	packets := collectPlan(t, spec)

	// 找到第一个 READ response (direction=down, command=CmdRead)。
	var found bool
	for _, p := range packets {
		if p.L4.Flags != 0x18 || p.Direction != "down" {
			continue
		}
		if len(p.Payload) < 72 {
			continue
		}
		// 跳过 NBSS 头 (4 字节) 找到 SMB2 头起始。
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command != CmdRead {
			continue
		}
		// 验证响应 body: 16 字节响应头 + DataLength 字节数据。
		if uint32(len(parsed.Body)) < 16 {
			t.Fatalf("READ response body too short: %d bytes", len(parsed.Body))
		}
		dataOffset, dataLength, err := ParseReadResponse(parsed.Body)
		if err != nil {
			t.Fatalf("ParseReadResponse: %v", err)
		}
		if dataOffset != 0x50 {
			t.Errorf("DataOffset = %X, want 0x50 (80)", dataOffset)
		}
		if dataLength != wantLen {
			t.Errorf("DataLength = %d, want %d", dataLength, wantLen)
		}
		// BUG #16 修复关键断言: 响应体除 16 字节头外, 尾部必须携带
		// 与 DataLength 等长的数据负载. 数据经 MSS 分段 (DefaultMSS=1460,
		// 每段 4B NBSS + 64B SMB2 头 + 1392B body), 后续段是裸数据续传
		// (无 SMB2 头). 只统计到补足 dataLength 为止, 之后是其他命令
		// (CLOSE/TREE_DISCONNECT/LOGOFF) 的响应段, 不计入.
		totalData := uint32(len(parsed.Body) - 16)
		foundFirst := false
		for _, seg := range packets {
			if totalData >= dataLength {
				break
			}
			if seg.L4.Flags != 0x18 || seg.Direction != "down" {
				continue
			}
			if !foundFirst {
				// 跳过首段自身 (即当前 parsed 所在段)。
				if len(seg.Payload) == len(p.Payload) {
					foundFirst = true
				}
				continue
			}
			// 后续段: 裸 TCP 续传数据, 全部计入数据负载.
			totalData += uint32(len(seg.Payload))
		}
		if totalData != dataLength {
			t.Errorf("BUG #16 复现: READ response missing data. "+
				"aggregated trailing bytes = %d, want %d (DataLength)",
				totalData, dataLength)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("READ response PDU not found")
	}
}
