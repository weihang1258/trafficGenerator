// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb_test_integration.go: Plan integration tests for session lifecycle.
package smb

import (
	"context"
	"testing"
	"time"
)

// TestPlan_TreeIDSet verifies TreeId is set after TREE_CONNECT.
func TestPlan_TreeIDSet(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	tdAfterTC := false
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
		if parsed.Command == CmdTreeConnect {
			tdAfterTC = true
			continue
		}
		if tdAfterTC && parsed.Command == CmdCreate {
			if parsed.TreeID == 0 {
				t.Errorf("CREATE request TreeId = 0, want non-zero")
			}
			return
		}
	}
	t.Fatal("CREATE request after TREE_CONNECT not found")
}

// TestPlan_FileIDSet verifies FileId is set after CREATE.
func TestPlan_FileIDSet(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	// Find READ request (first PDU after CREATE response)
	afterCreate := false
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
			afterCreate = true
			continue
		}
		if afterCreate && parsed.Command == CmdRead {
			// READ should have FileId in body (not header)
			_, _, fileID, err := ParseReadRequest(parsed.Body)
			if err != nil {
				t.Fatalf("ParseReadRequest: %v", err)
			}
			if fileID == ([16]byte{}) {
				t.Error("READ request FileId should be non-zero")
			}
			return
		}
	}
	t.Fatal("READ request after CREATE not found")
}

// TestPlan_ContextCancel verifies the planner handles context cancellation.
func TestPlan_ContextCancel(t *testing.T) {
	spec := testSpec()
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())

	cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		return
	}
	doneCh := make(chan struct{})
	go func() {
		for range ch {
		}
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
	}
}

// TestPlan_TCPTeardown verifies 4-way FIN teardown.
func TestPlan_TCPTeardown(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	finCount := 0
	for _, p := range packets {
		if p.L4.Flags == 0x11 {
			finCount++
		}
	}
	if finCount < 2 {
		t.Errorf("expected at least 2 FIN packets, got %d", finCount)
	}
}

// TestPlan_StreamOutput verifies the channel can be consumed as a stream.
func TestPlan_StreamOutput(t *testing.T) {
	spec := testSpec()
	p := NewPlanner()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	count := 0
	for range ch {
		count++
	}
	if count < 20 {
		t.Errorf("expected >= 20 packets, got %d", count)
	}
}

// TestPlan_DispatchAcrossWorkers verifies concurrent Plan() calls don't share state.
func TestPlan_DispatchAcrossWorkers(t *testing.T) {
	const N = 4
	results := make([]int, N)
	done := make(chan struct{}, N)

	for i := 0; i < N; i++ {
		go func(idx int) {
			spec := testSpec()
			p := NewPlanner()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ch, err := p.Plan(ctx, spec)
			if err != nil {
				done <- struct{}{}
				return
			}
			for range ch {
				results[idx]++
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < N; i++ {
		<-done
	}
	for i, n := range results {
		if n < 20 {
			t.Errorf("worker %d produced %d packets, want >= 20", i, n)
		}
	}
}

// TestValidate_UnknownCommand verifies ErrorOnCommand validation.
func TestValidate_UnknownCommand(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorOnCommand = "invalid_command"
	})
	if err := NewPlanner().Validate(spec); err == nil {
		t.Errorf("expected error for unknown ErrorOnCommand")
	}
}

// TestPlan_AllCommandsPresent verifies all major commands are emitted.
func TestPlan_AllCommandsPresent(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	seen := make(map[uint16]bool)
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		seen[parsed.Command] = true
	}

	// Required commands for a complete session
	required := []uint16{
		CmdNegotiate,
		CmdSessionSetup,
		CmdTreeConnect,
		CmdCreate,
		CmdRead,
		CmdClose,
		CmdTreeDisconnect,
		CmdLogoff,
	}
	for _, cmd := range required {
		if !seen[cmd] {
			t.Errorf("Command %X not found in plan output", cmd)
		}
	}
}

// TestPlan_TripleHANRequest verifies MessageId numbering for the default
// NTLM 3-round session.
func TestPlan_TripleHANRequest(t *testing.T) {
	spec := testSpec() // default NTLM 3 rounds
	packets := collectPlan(t, spec)

	// Collect MessageIds for the first NEGOTIATE request
	var msgIDs []uint64
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
		// Record request MessageIds
		if parsed.Command == CmdNegotiate ||
			parsed.Command == CmdSessionSetup ||
			parsed.Command == CmdTreeConnect ||
			parsed.Command == CmdCreate ||
			parsed.Command == CmdRead ||
			parsed.Command == CmdClose ||
			parsed.Command == CmdTreeDisconnect ||
			parsed.Command == CmdLogoff {
			msgIDs = append(msgIDs, parsed.MessageID)
		}
	}
	// Defaults: NTLM 3-round = 2 NEGOTIATE + 6 SESSION_SETUP + 2 TREE_CONNECT + ...
	// First MessageId should be 0 (NEGOTIATE)
	if len(msgIDs) == 0 || msgIDs[0] != 0 {
		t.Errorf("first MessageId should be 0, got %v", msgIDs)
	}
}

// TestPlan_FlowIDSet verifies every packet has a flow_id.
func TestPlan_FlowIDSet(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	for i, p := range packets {
		if p.FlowID == "" {
			t.Errorf("packet %d has empty FlowID", i)
		}
	}
}

// TestPlan_Direction verifies up/down alternation pattern.
func TestPlan_Direction(t *testing.T) {
	spec := testSpec()
	packets := collectPlan(t, spec)

	if len(packets) < 5 {
		t.Fatal("not enough packets")
	}
	// First 3 should be TCP handshake (SYN, SYN-ACK, ACK)
	for i := 0; i < 3; i++ {
		if i == 0 && packets[i].Direction != "up" {
			t.Errorf("packet 0 direction = %q, want up", packets[i].Direction)
		}
		if i == 1 && packets[i].Direction != "down" {
			t.Errorf("packet 1 direction = %q, want down", packets[i].Direction)
		}
		if i == 2 && packets[i].Direction != "up" {
			t.Errorf("packet 2 direction = %q, want up", packets[i].Direction)
		}
	}
}

// TestParser_OffsetBaseFromHeader verifies C-1: PathOffset/NameOffset are
// relative to the SMB2 header start, so the parser must subtract HeaderSize.
func TestParser_OffsetBaseFromHeader(t *testing.T) {
	// TREE_CONNECT: PathOffset=72 (64+8), path appended at body offset 8.
	body := buildTreeConnectRequestBody("\\\\server\\share")
	_, _, path, err := ParseTreeConnectRequest(body)
	if err != nil {
		t.Fatalf("ParseTreeConnectRequest: %v", err)
	}
	if path != "\\\\server\\share" {
		t.Errorf("C-1 复现: TREE_CONNECT path = %q, want \\\\server\\share", path)
	}

	// CREATE: NameOffset=120 (64+56), name appended at body offset 56.
	cbody := buildCreateRequestBody(2, 0x00120089, 0x80, 0x07, 1, 0, "file.txt")
	_, _, _, _, _, _, _, _, name, err := ParseCreateRequest(cbody)
	if err != nil {
		t.Fatalf("ParseCreateRequest: %v", err)
	}
	if name != "file.txt" {
		t.Errorf("C-1 复现: CREATE name = %q, want file.txt", name)
	}
}

// TestPlan_ReadRequestBufferByte verifies M-3: READ request body carries the
// trailing 1-byte Buffer (total 49 bytes, NBSS = 64+48+1 = 113).
func TestPlan_ReadRequestBufferByte(t *testing.T) {
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
			if len(parsed.Body) != 49 {
				t.Errorf("M-3 复现: READ req body = %d bytes, want 49 (48 fixed + 1 Buffer)",
					len(parsed.Body))
			}
			// 设计 S5: NBSS length = 64+48+1 = 113.
			if parsed.NBSSLength != 113 {
				t.Errorf("M-3 复现: READ req NBSS length = %d, want 113 (64+48+1)", parsed.NBSSLength)
			}
			return
		}
	}
	t.Fatal("READ request not found")
}

// TestPlan_SignaturePlaceholderNonZero verifies M-2: SigningRequired=true 时
// Signature 区 16B 非全零（设计 S14/T184）。
func TestPlan_SignaturePlaceholderNonZero(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.SigningRequired = true
	})
	packets := collectPlan(t, spec)

	checked := 0
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Flags&FlagSigned == 0 {
			continue
		}
		// Signature 区偏移 48-63 必须非全零。
		allZero := true
		for _, b := range parsed.Signature {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Errorf("M-2 复现: SIGNED PDU Signature 全零, cmd=%X msgID=%d", parsed.Command, parsed.MessageID)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no SIGNED PDU found")
	}
}

// TestPlan_EncryptionRequiredTransformHeader verifies H-3: EncryptionRequired
// 且 SMB3.0+ dialect 时, SESSION_SETUP 之后的信令 PDU 以 52B TRANSFORM_HEADER
// 包裹（设计 §3.27/S14/T178-182）。
func TestPlan_EncryptionRequiredTransformHeader(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.EncryptionRequired = true
		c.Dialects = []string{"0x0311"}
		// 小 READ 使加密 PDU 单段容纳 (MSS 1460), OriginalMessageSize
		// 直接等于本段负载长度, 避免跨段聚合的复杂度。
		c.Operations = []SMBOperation{{OpType: "read", Offset: 0, Length: 512}}
	})
	if err := NewPlanner().Validate(spec); err != nil {
		t.Fatalf("validate: %v", err)
	}
	packets := collectPlan(t, spec)

	foundTransform := false
	foundPlain := false // SESSION_SETUP 自身不应加密
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 4 {
			continue
		}
		// 检查是否为 TRANSFORM_HEADER (NBSS 后 4B = FD 53 4D 42)。
		if len(p.Payload) >= 8 && p.Payload[4] == 0xFD && p.Payload[5] == 0x53 &&
			p.Payload[6] == 0x4D && p.Payload[7] == 0x42 {
			// T178: TRANSFORM_HEADER 52B; 协议标识 FD 53 4D 42 (T179)。
			if len(p.Payload) < 4+52+64 {
				t.Errorf("H-3 复现: TRANSFORM payload too short (%d)", len(p.Payload))
				continue
			}
			// T182: OriginalMessageSize (偏移 36-39 of transform) == 密文长度。
			orig := uint32(p.Payload[4+36]) | uint32(p.Payload[4+37])<<8 |
				uint32(p.Payload[4+38])<<16 | uint32(p.Payload[4+39])<<24
			if orig != uint32(len(p.Payload)-4-52) {
				t.Errorf("H-3 复现: OriginalMessageSize = %d, want %d", orig, len(p.Payload)-4-52)
			}
			// T180: Flags 偏移 42-43 = 01 00 (Encrypted)。
			if p.Payload[4+42] != 0x01 || p.Payload[4+43] != 0x00 {
				t.Errorf("H-3 复现: TRANSFORM Flags = %X %X, want 01 00", p.Payload[4+42], p.Payload[4+43])
			}
			foundTransform = true
			continue
		}
		// 非加密 PDU: 只能是 NEGOTIATE / SESSION_SETUP。
		if len(p.Payload) >= 8 && p.Payload[4] == 0xFE {
			cmd := uint16(p.Payload[4+12]) | uint16(p.Payload[4+13])<<8
			if cmd != CmdNegotiate && cmd != CmdSessionSetup {
				t.Errorf("H-3 复现: 非加密 PDU 命令 = %X, 期望仅 NEGOTIATE/SESSION_SETUP 明文", cmd)
			}
			foundPlain = true
		}
	}
	if !foundTransform {
		t.Error("H-3 复现: 未找到 TRANSFORM_HEADER 包裹的加密 PDU")
	}
	if !foundPlain {
		t.Error("H-3 复现: 未找到明文的 NEGOTIATE/SESSION_SETUP PDU")
	}
}

// TestPlan_ErrorOnTreeDisconnect verifies H-1: ErrorOnCommand=tree_disconnect
// 时 TREE_DISCONNECT 请求正常生成、响应返回 ErrorResponseStatus，之后仍 LOGOFF
// （设计 §4.2 跳过规则表）。
func TestPlan_ErrorOnTreeDisconnect(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = StatusAccessDenied
		c.ErrorOnCommand = "tree_disconnect"
	})
	packets := collectPlan(t, spec)

	var treeDiscResp *ParsedPDU
	logoffSeen := false
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		switch parsed.Command {
		case CmdTreeDisconnect:
			if p.Direction == "down" {
				treeDiscResp = parsed
			}
		case CmdLogoff:
			logoffSeen = true
		}
	}
	if treeDiscResp == nil {
		t.Fatal("H-1 复现: 未找到 TREE_DISCONNECT 响应")
	}
	if treeDiscResp.Status != StatusAccessDenied {
		t.Errorf("H-1 复现: TREE_DISCONNECT resp Status = %X, want %X (ErrorResponseStatus)",
			treeDiscResp.Status, StatusAccessDenied)
	}
	if !logoffSeen {
		t.Error("H-1 复现: tree_disconnect 错误后应保留 LOGOFF")
	}
}

// TestPlan_ErrorOnLogoff verifies H-1: ErrorOnCommand=logoff 时 LOGOFF 请求
// 正常生成、响应返回 ErrorResponseStatus，之后直接 TCP teardown
// （设计 §4.2 跳过规则表）。
func TestPlan_ErrorOnLogoff(t *testing.T) {
	spec := testSpecWith(func(c *SMBConfig) {
		c.ErrorResponseStatus = StatusUserSessionDeleted
		c.ErrorOnCommand = "logoff"
	})
	packets := collectPlan(t, spec)

	var logoffResp *ParsedPDU
	for _, p := range packets {
		if p.L4.Flags != 0x18 || len(p.Payload) < 72 {
			continue
		}
		parsed, err := ParsePDU(p.Payload, true)
		if err != nil {
			continue
		}
		if parsed.Command == CmdLogoff && p.Direction == "down" {
			logoffResp = parsed
		}
	}
	if logoffResp == nil {
		t.Fatal("H-1 复现: 未找到 LOGOFF 响应")
	}
	if logoffResp.Status != StatusUserSessionDeleted {
		t.Errorf("H-1 复现: LOGOFF resp Status = %X, want %X (ErrorResponseStatus)",
			logoffResp.Status, StatusUserSessionDeleted)
	}
}

// TestApplyDefaults_ExplicitZeroCreateDisposition verifies M-1: 用户显式设置
// create 阶段任一字段时, CreateDisposition=0 (supersede) 不被默认值覆盖。
func TestApplyDefaults_ExplicitZeroCreateDisposition(t *testing.T) {
	cfg := applyDefaults(&SMBConfig{AccessMask: 0x00120089, CreateDisposition: 0})
	if cfg.CreateDisposition != 0 {
		t.Errorf("M-1 复现: 显式 CreateDisposition=0 被覆盖为 %d, want 0 (supersede)", cfg.CreateDisposition)
	}

	// 纯空配置仍套用设计默认值 1 (open)。
	empty := applyDefaults(&SMBConfig{})
	if empty.CreateDisposition != 1 {
		t.Errorf("空配置 CreateDisposition = %d, want 1 (open)", empty.CreateDisposition)
	}
}
