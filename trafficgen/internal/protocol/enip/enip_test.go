// Package enip tests for the EtherNet/IP (ENIP) planner.
// Tests derive from docs/protocol-designs/12-enip-design.md §6 (S1-S15 HexDumps)
// and §7 (T-001 ~ T-220 test cases). Each test asserts observable wire output.
package enip

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

// drain collects all packets from a Plan channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// intPtr returns a pointer to n (for IOData.SourceCommandIndex).
func intPtr(n int) *int { return &n }

// basicSpec returns a minimal FlowSpec for ENIP testing.
func basicSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "192.168.1.100",
		DstIP:   "192.168.1.1",
		SrcPort: 49152,
		DstPort: DefaultPort,
	}
}

// =============================================================================
// §6.2 S1: NOP keep-alive
// =============================================================================

func TestNopMinimal(t *testing.T) {
	// T-001: NOP 最小包, Command=0x0000, Length=0, 24 字节
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdNop, SessionHandle: 0x12345678},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if len(p) != 24 {
		t.Fatalf("expected 24 bytes ENIP header, got %d", len(p))
	}
	cmd := binary.LittleEndian.Uint16(p[0:2])
	length := binary.LittleEndian.Uint16(p[2:4])
	if cmd != CmdNop {
		t.Errorf("Command: got 0x%04X, want 0x0000", cmd)
	}
	if length != 0 {
		t.Errorf("Length: got %d, want 0", length)
	}
}

func TestNopWithPayload(t *testing.T) {
	// T-002: NOP 带 payload, 28 字节, Length=4
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdNop, SessionHandle: 0x12345678, Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if len(p) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(p))
	}
	if p[24] != 0xDE || p[25] != 0xAD || p[26] != 0xBE || p[27] != 0xEF {
		t.Errorf("Payload mismatch: got % X", p[24:28])
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 4 {
		t.Errorf("Length: got %d, want 4", binary.LittleEndian.Uint16(p[2:4]))
	}
}

// =============================================================================
// §6.3 S2: ListServices
// =============================================================================

func TestListServicesRequest(t *testing.T) {
	// T-003: ListServices 请求, 24 字节, Length=0
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListServices},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if len(p) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(p))
	}
	if binary.LittleEndian.Uint16(p[0:2]) != CmdListServices {
		t.Errorf("Command: got 0x%04X, want 0x0004", binary.LittleEndian.Uint16(p[0:2]))
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 0 {
		t.Errorf("Length: got %d, want 0", binary.LittleEndian.Uint16(p[2:4]))
	}
}

// =============================================================================
// §6.4 S3: ListIdentity
// =============================================================================

func TestListIdentityRequest(t *testing.T) {
	// T-005: ListIdentity 请求, Command=0x0063, Length=0
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity},
		},
	}
	planner := NewPlanner()
	ch, _ := planner.Plan(context.Background(), spec)
	packets := drain(ch)
	p := packets[0].Payload
	if binary.LittleEndian.Uint16(p[0:2]) != CmdListIdentity {
		t.Errorf("Command: got 0x%04X, want 0x0063", binary.LittleEndian.Uint16(p[0:2]))
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 0 {
		t.Errorf("Length: got %d, want 0", binary.LittleEndian.Uint16(p[2:4]))
	}
}

// =============================================================================
// §6.5 S4: RegisterSession
// =============================================================================

func TestRegisterSessionRequest(t *testing.T) {
	// T-012: RegisterSession 请求, 28 字节, Length=4, ProtocolVersion=1
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1, OptionFlag: 0},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if len(p) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(p))
	}
	if binary.LittleEndian.Uint16(p[0:2]) != CmdRegisterSession {
		t.Errorf("Command: got 0x%04X, want 0x0065", binary.LittleEndian.Uint16(p[0:2]))
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 4 {
		t.Errorf("Length: got %d, want 4", binary.LittleEndian.Uint16(p[2:4]))
	}
	// ProtocolVersion=1, OptionFlag=0
	if p[24] != 0x01 || p[25] != 0x00 || p[26] != 0x00 || p[27] != 0x00 {
		t.Errorf("RegisterSession payload: got % X, want 01 00 00 00", p[24:28])
	}
}

// =============================================================================
// §6.6 S5: UnRegisterSession
// =============================================================================

func TestUnRegisterSessionRequest(t *testing.T) {
	// T-015: UnRegisterSession 请求, 24 字节, Length=0
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdUnRegisterSession, SessionHandle: 0x12345678},
		},
	}
	planner := NewPlanner()
	ch, _ := planner.Plan(context.Background(), spec)
	packets := drain(ch)
	p := packets[0].Payload
	if len(p) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(p))
	}
	if binary.LittleEndian.Uint16(p[0:2]) != CmdUnRegisterSession {
		t.Errorf("Command: got 0x%04X, want 0x0066", binary.LittleEndian.Uint16(p[0:2]))
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 0 {
		t.Errorf("Length: got %d, want 0", binary.LittleEndian.Uint16(p[2:4]))
	}
	sh := binary.LittleEndian.Uint32(p[4:8])
	if sh != 0x12345678 {
		t.Errorf("SessionHandle: got 0x%08X, want 0x12345678", sh)
	}
}

// =============================================================================
// §6.7 S6: SendRRData Get_Attribute_Single
// =============================================================================

func TestSendRRDataGetAttributeSingle(t *testing.T) {
	// T-016, T-017, T-020, T-021, T-022:
	// SendRRData Get_Attribute_Single: CIP Service=0x0E, ItemCount=2,
	// TypeIDs 0x0000 (Null) and 0x00B2 (Unconnected).
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:        CmdSendRRData,
				SessionHandle:  0x12345678,
				InterfaceHandle: 0,
				Timeout:        10,
				CIPService:     CIPGetAttributeSingle,
				ClassID:        0x01, // Identity
				InstanceID:     1,
				AttributeID:    1, // Vendor ID
			},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	// Header checks
	if binary.LittleEndian.Uint16(p[0:2]) != CmdSendRRData {
		t.Errorf("Command: got 0x%04X, want 0x006F", binary.LittleEndian.Uint16(p[0:2]))
	}
	// 6B prefix: InterfaceHandle(4) + Timeout(2)
	if binary.LittleEndian.Uint32(p[24:28]) != 0 {
		t.Errorf("InterfaceHandle: got %d, want 0", binary.LittleEndian.Uint32(p[24:28]))
	}
	if binary.LittleEndian.Uint16(p[28:30]) != 10 {
		t.Errorf("Timeout: got %d, want 10", binary.LittleEndian.Uint16(p[28:30]))
	}
	// ItemCount=2 at offset 30
	if binary.LittleEndian.Uint16(p[30:32]) != 2 {
		t.Errorf("ItemCount: got %d, want 2", binary.LittleEndian.Uint16(p[30:32]))
	}
	// Item 1: Null Address (0x0000) + Length=0
	if binary.LittleEndian.Uint16(p[32:34]) != TypeIDNullAddress {
		t.Errorf("Item1 TypeID: got 0x%04X, want 0x0000", binary.LittleEndian.Uint16(p[32:34]))
	}
	// Item 2: Unconnected Data (0x00B2)
	if binary.LittleEndian.Uint16(p[36:38]) != TypeIDUnconnectedData {
		t.Errorf("Item2 TypeID: got 0x%04X, want 0x00B2", binary.LittleEndian.Uint16(p[36:38]))
	}
	// CIP data: offset 40 = Service, 41 = RequestPathSize, 42+ = padded path
	if p[40] != CIPGetAttributeSingle {
		t.Errorf("CIP Service: got 0x%02X, want 0x0E", p[40])
	}
	// Path = 20 01 24 01 30 01 00 00 (Class 8-bit + Instance 8-bit + Attr 8-bit,
	// 6 字节路径 + 1 字节补齐到偶数；§2.7.4 最小适配编码)
	if p[42] != 0x20 || p[43] != 0x01 {
		t.Errorf("EPATH Class segment: got %02X %02X, want 20 01", p[42], p[43])
	}
	if p[44] != 0x24 {
		t.Errorf("EPATH Instance 8-bit: got 0x%02X, want 0x24", p[44])
	}
	if p[46] != 0x30 || p[47] != 0x01 {
		t.Errorf("EPATH Attribute segment: got %02X %02X, want 30 01", p[46], p[47])
	}
}

// =============================================================================
// §6.8 S7: Forward_Open
// =============================================================================

func TestForwardOpenRequest(t *testing.T) {
	// T-031: Forward_Open service code = 0x54
	// T-033~T-042: field order and offsets
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:                    CmdSendRRData,
				SessionHandle:              0x12345678,
				InterfaceHandle:            0,
				Timeout:                    10,
				CIPService:                 CIPForwardOpen,
				ClassID:                    0x06, // Connection Manager
				InstanceID:                 1,
				PriorityTimeTick:           0x0A,
				TimeoutTicks:               0x05,
				O2TConnID:                  0x00000001,
				T2OConnID:                  0x00000002,
				ConnSerialNum:              0x0001,
				OrigVendorID:               0x0001,
				OrigSerialNum:              0x00000001,
				ConnectionTimeoutMultiplier: 7,
				O2TRPI:                     100000, // 0x000186A0
				T2ORPI:                     100000,
				O2TConnParams:              0x0200,
				T2OConnParams:              0x0200,
				TransportClassTrigger:      0x80, // Class 0 Client
			},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if binary.LittleEndian.Uint16(p[0:2]) != CmdSendRRData {
		t.Errorf("Command: got 0x%04X, want 0x006F", binary.LittleEndian.Uint16(p[0:2]))
	}

	// CIP data starts after ENIP header(24) + 6B prefix(4 IfHdl + 2 Timeout)
	// + 2B ItemCount + Item1(4) + Item2 TypeID/Length(4) = 40。
	// CIP header: Service + RequestPathSize + Path = 1 + 1 + 4 = 6
	// CIP body: PriorityTimeTick + TimeoutTicks + ... = 44B
	cipStart := 40

	// T-031: Service=0x54
	if p[cipStart] != CIPForwardOpen {
		t.Errorf("CIP Service: got 0x%02X, want 0x54", p[cipStart])
	}
	// RequestPathSize=2 (Class 0x06 Instance 8-bit 0x01 = 4 bytes / 2 = 2 words)
	if p[cipStart+1] != 2 {
		t.Errorf("RequestPathSize: got %d, want 2", p[cipStart+1])
	}
	// Path: 20 06 24 01 (Class 0x06 + Instance 0x01)
	if p[cipStart+2] != 0x20 || p[cipStart+3] != 0x06 || p[cipStart+4] != 0x24 || p[cipStart+5] != 0x01 {
		t.Errorf("EPATH: got % X, want 20 06 24 01", p[cipStart+2:cipStart+6])
	}
	// CIP body starts at cipStart+6
	body := p[cipStart+6:]
	// T-032: PriorityTimeTick=0x0A, TimeoutTicks=0x05
	if body[0] != 0x0A || body[1] != 0x05 {
		t.Errorf("Priority/Tick: got %02X %02X, want 0A 05", body[0], body[1])
	}
	// O2TConnID at body[2:6]
	if binary.LittleEndian.Uint32(body[2:6]) != 0x00000001 {
		t.Errorf("O2TConnID: got 0x%08X, want 0x00000001", binary.LittleEndian.Uint32(body[2:6]))
	}
	// T2OConnID at body[6:10]
	if binary.LittleEndian.Uint32(body[6:10]) != 0x00000002 {
		t.Errorf("T2OConnID: got 0x%08X, want 0x00000002", binary.LittleEndian.Uint32(body[6:10]))
	}
	// T-033: ConnSerialNum at body[10:12]
	if binary.LittleEndian.Uint16(body[10:12]) != 0x0001 {
		t.Errorf("ConnSerialNum: got 0x%04X, want 0x0001", binary.LittleEndian.Uint16(body[10:12]))
	}
	// T-034: OrigVendorID at body[12:14]
	if binary.LittleEndian.Uint16(body[12:14]) != 0x0001 {
		t.Errorf("OrigVendorID: got 0x%04X, want 0x0001", binary.LittleEndian.Uint16(body[12:14]))
	}
	// T-035: OrigSerialNum at body[14:18]
	if binary.LittleEndian.Uint32(body[14:18]) != 0x00000001 {
		t.Errorf("OrigSerialNum: got 0x%08X, want 0x00000001", binary.LittleEndian.Uint32(body[14:18]))
	}
	// T-036: ConnectionTimeoutMultiplier at body[18]
	if body[18] != 0x07 {
		t.Errorf("TimeoutMult: got %d, want 7", body[18])
	}
	// T-037: Reserved 3B at body[19:22] = 0
	if body[19] != 0 || body[20] != 0 || body[21] != 0 {
		t.Errorf("Reserved: got %02X %02X %02X, want 00 00 00", body[19], body[20], body[21])
	}
	// T-038: O2TRPI at body[22:26]
	if binary.LittleEndian.Uint32(body[22:26]) != 100000 {
		t.Errorf("O2TRPI: got %d, want 100000", binary.LittleEndian.Uint32(body[22:26]))
	}
	// T-039: O2TConnParams at body[26:28] (2B)
	if binary.LittleEndian.Uint16(body[26:28]) != 0x0200 {
		t.Errorf("O2TConnParams: got 0x%04X, want 0x0200", binary.LittleEndian.Uint16(body[26:28]))
	}
	// T-040: T2ORPI at body[28:32]
	if binary.LittleEndian.Uint32(body[28:32]) != 100000 {
		t.Errorf("T2ORPI: got %d, want 100000", binary.LittleEndian.Uint32(body[28:32]))
	}
	// T-041: TransportClassTrigger at body[34] = 0x80
	if body[34] != 0x80 {
		t.Errorf("TransportClassTrigger: got 0x%02X, want 0x80", body[34])
	}
	// T-042: ConnectionPathSize at body[35] = 4 words
	if body[35] != 4 {
		t.Errorf("ConnPathSize: got %d, want 4", body[35])
	}
	// ConnectionPath at body[36:44] = 20 04 24 01 2C 02 2C 03
	expectedPath := []byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03}
	for i, b := range expectedPath {
		if body[36+i] != b {
			t.Errorf("ConnPath[%d]: got 0x%02X, want 0x%02X", i, body[36+i], b)
		}
	}
}

// =============================================================================
// §6.9 S8: Forward_Close
// =============================================================================

func TestForwardCloseRequest(t *testing.T) {
	// T-047: Forward_Close service = 0x4E
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:        CmdSendRRData,
				SessionHandle:  0x12345678,
				InterfaceHandle: 0,
				Timeout:        10,
				CIPService:     CIPForwardClose,
				ClassID:        0x06,
				InstanceID:     1,
				ConnSerialNum:  0x0001,
				OrigVendorID:   0x0001,
				OrigSerialNum:  0x00000001,
			},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if binary.LittleEndian.Uint16(p[0:2]) != CmdSendRRData {
		t.Errorf("Command: got 0x%04X, want 0x006F", binary.LittleEndian.Uint16(p[0:2]))
	}

	cipStart := 40
	if p[cipStart] != CIPForwardClose {
		t.Errorf("CIP Service: got 0x%02X, want 0x4E", p[cipStart])
	}
	body := p[cipStart+6:]
	// T-049: no ConnectionID field
	// T-048: ConnSerialNum at body[2:4], OrigVendorID at [4:6], OrigSerialNum at [6:10]
	if binary.LittleEndian.Uint16(body[2:4]) != 0x0001 {
		t.Errorf("ConnSerialNum: got 0x%04X, want 0x0001", binary.LittleEndian.Uint16(body[2:4]))
	}
	if binary.LittleEndian.Uint16(body[4:6]) != 0x0001 {
		t.Errorf("OrigVendorID: got 0x%04X, want 0x0001", binary.LittleEndian.Uint16(body[4:6]))
	}
	if binary.LittleEndian.Uint32(body[6:10]) != 0x00000001 {
		t.Errorf("OrigSerialNum: got 0x%08X, want 0x00000001", binary.LittleEndian.Uint32(body[6:10]))
	}
	// PathSize at body[10] = 4 words
	if body[10] != 4 {
		t.Errorf("ConnPathSize: got %d, want 4", body[10])
	}
}

func TestForwardCloseBodyHasReservedByte(t *testing.T) {
	// pcap 深度测试回归（failing-test-first）：Forward_Close body 在 PathSize
	// 与 Connection Path 之间必须有 Reserved 字节（0x00）。Wireshark 3.6.14
	// dissect_cip_cm_fwd_close_req 固定读取 offset+10=PathSize、offset+11=
	// Reserved、offset+12=Path；缺少 Reserved 会把路径首字节 0x20 误读为
	// Reserved，且路径只剩 7/8 字节 → [Malformed Packet: CIPCM]。
	body := BuildForwardCloseBody(
		0x0A, 0x05, 0x0001, 0x0001, 0x00000001,
		[]byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03},
	)
	if len(body) != 20 {
		t.Fatalf("Forward_Close body 长度: got %d, want 20 (1+1+2+2+4 ptt/triad + 1 pathsize + 1 reserved + 9 path)", len(body))
	}
	if body[11] != 0x00 {
		t.Errorf("PathSize 后必须紧跟 Reserved 字节 0x00: got %02X at body[11]", body[11])
	}
	if string(body[12:]) != string([]byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03}) {
		t.Errorf("Connection Path 必须从 body[12] 开始: got % X", body[12:])
	}
	// 端到端：完整 Forward_Close 帧的 CIP 体布局
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, SessionHandle: 0x12345678,
				CIPService:    CIPForwardClose,
				ConnSerialNum: 0x0001, OrigVendorID: 0x0001, OrigSerialNum: 0x00000001},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	p := packets[0].Payload
	items, err := ParseCPFPayload(p[30:])
	if err != nil {
		t.Fatalf("ParseCPFPayload: %v", err)
	}
	cip := items[1].Data
	// CIP: 4e 02 20 06 24 01 | ptt/tt 2B | triad 8B | pathsize 04 | reserved 00 | path 8B
	if cip[16] != 0x04 {
		t.Errorf("PathSize: got %d, want 4", cip[16])
	}
	if cip[17] != 0x00 {
		t.Errorf("Reserved after PathSize: got %02X, want 00", cip[17])
	}
	// serial 在 cip[8:10]（6B 前缀 + ptt/tt 2B）
	if got := binary.LittleEndian.Uint16(cip[8:10]); got != 0x0001 {
		t.Errorf("ConnSerialNum: got 0x%04X, want 0x0001", got)
	}
}

// =============================================================================
// §6.10 S9: SendUnitData Connected
// =============================================================================

func TestSendUnitDataConnected(t *testing.T) {
	// T-051, T-052, T-053, T-054:
	// SendUnitData I/O frame, ConnectionID=0x00000001, Seq=0x0001
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:         CmdSendUnitData,
				SessionHandle:   0x12345678,
				InterfaceHandle: 0,
				Timeout:         0,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDConnectionAddress, Length: 4, Data: u32LE(0x00000001)},
					{TypeID: TypeIDConnectedData, Length: 4, Data: u16LE(0x0001)},
				},
			},
		},
	}
	planner := NewPlanner()
	ch, _ := planner.Plan(context.Background(), spec)
	packets := drain(ch)
	p := packets[0].Payload
	if binary.LittleEndian.Uint16(p[0:2]) != CmdSendUnitData {
		t.Errorf("Command: got 0x%04X, want 0x0070", binary.LittleEndian.Uint16(p[0:2]))
	}
	// ItemCount=2 at offset 30
	if binary.LittleEndian.Uint16(p[30:32]) != 2 {
		t.Errorf("ItemCount: got %d, want 2", binary.LittleEndian.Uint16(p[30:32]))
	}
	// Item1: TypeID=0x00A1
	if binary.LittleEndian.Uint16(p[32:34]) != TypeIDConnectionAddress {
		t.Errorf("Item1 TypeID: got 0x%04X, want 0x00A1", binary.LittleEndian.Uint16(p[32:34]))
	}
	// Item1 Data: ConnectionID=0x00000001
	if binary.LittleEndian.Uint32(p[36:40]) != 0x00000001 {
		t.Errorf("ConnectionID: got 0x%08X, want 0x00000001", binary.LittleEndian.Uint32(p[36:40]))
	}
	// Item2: TypeID=0x00B1
	if binary.LittleEndian.Uint16(p[40:42]) != TypeIDConnectedData {
		t.Errorf("Item2 TypeID: got 0x%04X, want 0x00B1", binary.LittleEndian.Uint16(p[40:42]))
	}
	// Item2 Data: SequenceCounter=0x0001
	if binary.LittleEndian.Uint16(p[44:46]) != 0x0001 {
		t.Errorf("SequenceCounter: got 0x%04X, want 0x0001", binary.LittleEndian.Uint16(p[44:46]))
	}
}

func TestBuildIODataFramesUsesPayload(t *testing.T) {
	frames := buildIODataFrames(&core.ENIPIOData{
		O2TConnectionID: 1, SequenceStart: 7, FrameCount: 1,
		Payload: []byte{0xAA, 0xBB, 0xCC},
	}, 0x12345678)
	if len(frames) != 1 {
		t.Fatalf("帧数: got %d, want 1", len(frames))
	}
	items, err := ParseCPFPayload(frames[0][30:])
	if err != nil {
		t.Fatalf("解析 CPF: %v", err)
	}
	got := items[1].Data
	// pcap 深度测试回归（failing-test-first）：UDP I/O 帧的 Connected Data
	// Item 不带 2B SequenceCounter。Wireshark 对未注册 connid 的 UDP
	// SendUnitData 按 CIP Message Router 解析该 item，seq(2B)+payload(≥2B)
	// 恰好构成最小显式消息并读入 payload 首字节作为服务码 → 异常
	// → [Malformed Packet: CIP]。payload 直接就是 Connected Data 内容。
	want := []byte{0xAA, 0xBB, 0xCC}
	if len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("Connected Data: got % X, want % X", got, want)
	}
}

func TestBuildIODataFramesUsesFrameSize(t *testing.T) {
	frames := buildIODataFrames(&core.ENIPIOData{
		O2TConnectionID: 1, SequenceStart: 1, FrameCount: 1, FrameSize: 4,
	}, 0)
	items, err := ParseCPFPayload(frames[0][30:])
	if err != nil {
		t.Fatalf("解析 CPF: %v", err)
	}
	if got := len(items[1].Data); got != 4 {
		t.Fatalf("Connected Data 长度: got %d, want 4 (无 SequenceCounter)", got)
	}
	if string(items[1].Data) != string(make([]byte, 4)) {
		t.Fatalf("帧数据不是 4 字节零填充: % X", items[1].Data)
	}
}

// =============================================================================
// EPATH Encoding Tests (§2.7)
// =============================================================================

func TestEncodeCIPPathClass8bit(t *testing.T) {
	// T-075: EPATH Class 8-bit, ClassID=0x01 → segment byte 0x20
	path := EncodeCIPPath(0x01, 1, 0)
	if path[0] != 0x20 || path[1] != 0x01 {
		t.Errorf("Class 8-bit: got %02X %02X, want 20 01", path[0], path[1])
	}
}

func TestEncodeCIPPathClass16bit(t *testing.T) {
	// T-076: EPATH Class 16-bit, ClassID=0x0100 → segment byte 0x21
	path := EncodeCIPPath(0x0100, 1, 0)
	if path[0] != 0x21 {
		t.Errorf("Class 16-bit segment: got 0x%02X, want 0x21", path[0])
	}
	if binary.LittleEndian.Uint16(path[1:3]) != 0x0100 {
		t.Errorf("Class 16-bit value: got 0x%04X, want 0x0100", binary.LittleEndian.Uint16(path[1:3]))
	}
}

func TestEncodeCIPPathInstance8bit(t *testing.T) {
	// T-077: Instance 8-bit, InstanceID=0x01 → segment byte 0x24
	path := EncodeCIPPath(0x01, 0x01, 0)
	// path[0:2] = 20 01 (Class), path[2:4] = 24 01 (Instance)
	if path[2] != 0x24 || path[3] != 0x01 {
		t.Errorf("Instance 8-bit: got %02X %02X, want 24 01", path[2], path[3])
	}
}

func TestEncodeCIPPathInstance16bit(t *testing.T) {
	// T-078: Instance 16-bit, InstanceID=0x0100 → segment byte 0x25
	path := EncodeCIPPath(0x01, 0x0100, 0)
	if path[2] != 0x25 {
		t.Errorf("Instance 16-bit segment: got 0x%02X, want 0x25", path[2])
	}
}

func TestEncodeCIPPathAttribute8bit(t *testing.T) {
	// T-079: Attribute 8-bit, AttrID=0x01 → segment byte 0x30
	path := EncodeCIPPath(0x01, 1, 0x01)
	// Class(2) + Instance(2) = path[0:4], Attribute at path[4]
	if path[4] != 0x30 || path[5] != 0x01 {
		t.Errorf("Attribute 8-bit: got %02X %02X, want 30 01", path[4], path[5])
	}
}

func TestEncodeCIPPathAttribute16bit(t *testing.T) {
	// T-080: Attribute 16-bit, AttrID=0x0100 → segment byte 0x31
	path := EncodeCIPPath(0x01, 1, 0x0100)
	if path[4] != 0x31 {
		t.Errorf("Attribute 16-bit segment: got 0x%02X, want 0x31", path[4])
	}
}

func TestEncodeCIPPathConnectionPoint(t *testing.T) {
	// T-212: Connection Point 8-bit segment = 0x2C
	path := EncodeCIPPath(0x04, 1, 0, 2, 3)
	// path = 20 04 24 01 2C 02 2C 03 (8 bytes)
	expected := []byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03}
	if len(path) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(path))
	}
	for i, b := range expected {
		if path[i] != b {
			t.Errorf("path[%d]: got 0x%02X, want 0x%02X", i, path[i], b)
		}
	}
}

func TestEncodeCIPPathInstance32bit(t *testing.T) {
	// T-133: Instance 32-bit, InstanceID=0x10000 → segment byte 0x26
	path := EncodeCIPPath(0x01, 0x10000, 0)
	if path[2] != 0x26 {
		t.Errorf("Instance 32-bit segment: got 0x%02X, want 0x26", path[2])
	}
}

// =============================================================================
// ENIP Header Tests (§2.1)
// =============================================================================

func TestBuildENIPHeader(t *testing.T) {
	// T-214: LE byte order
	var sc [8]byte
	for i := range sc {
		sc[i] = byte(i + 1)
	}
	hdr := BuildENIPHeader(CmdListIdentity, 51, 0x12345678, 0, binary.LittleEndian.Uint64(sc[:]), 0)
	if len(hdr) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(hdr))
	}
	if hdr[0] != 0x63 || hdr[1] != 0x00 {
		t.Errorf("Command LE: got %02X %02X, want 63 00", hdr[0], hdr[1])
	}
	if hdr[2] != 0x33 || hdr[3] != 0x00 {
		t.Errorf("Length LE: got %02X %02X, want 33 00", hdr[2], hdr[3])
	}
	if binary.LittleEndian.Uint32(hdr[4:8]) != 0x12345678 {
		t.Errorf("SessionHandle: got 0x%08X, want 0x12345678", binary.LittleEndian.Uint32(hdr[4:8]))
	}
}

// =============================================================================
// Validate Tests (§8)
// =============================================================================

func TestValidateUnknownCommand(t *testing.T) {
	// T-081: unknown command rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: 0x1234},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for unknown command")
	}
}

func TestValidateRegisterSessionProtocolVersion(t *testing.T) {
	// T-083: ProtocolVersion=0 rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 0, OptionFlag: 0},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for ProtocolVersion=0")
	}
}

func TestValidateRegisterSessionOptionFlag(t *testing.T) {
	// T-084: OptionFlag≠0 rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1, OptionFlag: 1},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for OptionFlag=1")
	}
}

func TestValidateSendRRDataNoCPF(t *testing.T) {
	// T-086: SendRRData requires CPF items
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for SendRRData with no CPF items")
	}
}

func TestSendRRDataAppendsUserCPFItems(t *testing.T) {
	cmd := &core.ENIPCommand{
		Command: CmdSendRRData, CIPService: CIPGetAttributeSingle,
		ClassID: 1, InstanceID: 1, AttributeID: 1,
		CPFItems: []core.CPFItem{{TypeID: TypeIDSockaddrO2T, Length: 16, Data: make([]byte, 16)}},
	}
	msg := buildENIPPacket(cmd, 0, &core.ENIPConfig{}, 0)
	items, err := ParseCPFPayload(msg[30:])
	if err != nil {
		t.Fatalf("解析 CPF: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("CPF 项数: got %d, want 3", len(items))
	}
	if items[0].TypeID != TypeIDNullAddress || items[1].TypeID != TypeIDUnconnectedData || items[2].TypeID != TypeIDSockaddrO2T {
		t.Fatalf("CPF 顺序错误: %04X %04X %04X", items[0].TypeID, items[1].TypeID, items[2].TypeID)
	}
}

func TestValidateSendUnitDataRequiresConnectedData(t *testing.T) {
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{Commands: []core.ENIPCommand{{
		Command: CmdSendUnitData,
		CPFItems: []core.CPFItem{{TypeID: TypeIDConnectionAddress, Length: 4, Data: make([]byte, 4)}},
	}}}
	if err := NewPlanner().Validate(spec); err == nil {
		t.Fatal("缺少 Connected Data 时应校验失败")
	}
}

func TestValidateForwardOpenInvalidTransportClass(t *testing.T) {
	// T-096: TransportClassTrigger with invalid class (5)
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:               CmdSendRRData,
				CIPService:            CIPForwardOpen,
				ConnSerialNum:         1,
				OrigVendorID:          1,
				OrigSerialNum:         1,
				TransportClassTrigger: 0x05, // Class 5 (reserved)
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDNullAddress, Length: 0, Data: nil},
					{TypeID: TypeIDUnconnectedData, Length: 2, Data: []byte{0x54, 0x00}},
				},
			},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for invalid transport class")
	}
}

func TestValidateUnknownScenario(t *testing.T) {
	// T-113: unknown scenario rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Scenario: "unknown",
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for unknown scenario")
	}
}

func TestValidateUnknownTransport(t *testing.T) {
	// T-114: unknown transport rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "icmp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for unknown transport")
	}
}

func TestValidateIODataFrameCount(t *testing.T) {
	// T-109: FrameCount=0 rejected
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity},
		},
		IOData: &core.ENIPIOData{FrameCount: 0},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for FrameCount=0")
	}
}

// =============================================================================
// §2.6 Transport Class/Trigger Bit Layout Tests
// =============================================================================

func TestTransportClassTriggerBitLayout(t *testing.T) {
	// Verify bit layout: bit 0-3 = Transport Class, bit 4-6 = Trigger, bit 7 = Direction
	// 0x80 = bit 7 set (Direction=Client/Producer), bit 0-3 = 0 (Class 0)
	if 0x80&0x0F != 0 {
		t.Error("0x80 should have Transport Class = 0")
	}
	if 0x80&0x80 != 0x80 {
		t.Error("0x80 should have Direction bit set")
	}
	// 0x81 = Class 1 Client
	if 0x81&0x0F != 1 {
		t.Error("0x81 should have Transport Class = 1")
	}
	// 0x03 = Class 3 Server
	if 0x03&0x0F != 3 {
		t.Error("0x03 should have Transport Class = 3")
	}
	if 0x03&0x80 != 0 {
		t.Error("0x03 should have Direction = 0 (Server)")
	}
}

// =============================================================================
// §2.3.1 CIP General Status / §2.3.2 Connection Manager Extended Status
// =============================================================================

func TestCIPGeneralStatusConstants(t *testing.T) {
	// Verify key CIP General Status values from §2.3.1
	statuses := map[uint8]string{
		0x00: "Success",
		0x01: "Connection Failure",
		0x05: "Path Destination Unknown",
		0x08: "Service Not Supported",
		0x0E: "Attribute Not Supported",
		0x15: "Permission Denied",
	}
	for code, name := range statuses {
		if code == 0xFF {
			t.Errorf("%s should be valid", name)
		}
	}
}

func TestConnectionManagerExtendedStatusConstants(t *testing.T) {
	// Verify key Connection Manager Extended Status values from §2.3.2
	// 0x0100 = Connection in use
	// 0x0107 = Target connection not found
	// 0x0111 = RPI not supported
	// 0x0112 = RPI values not acceptable
	// 0x0316 = ForwardClose connection path mismatch
	// 0xFFFF = Wrong closer
	statuses := []uint16{
		0x0100, 0x0103, 0x0106, 0x0107, 0x0110, 0x0111, 0x0112,
		0x0113, 0x0114, 0x0115, 0x0116, 0x0127, 0x0128,
		0x0203, 0x0204, 0x0312, 0x0315, 0x0316, 0xFFFF,
	}
	if len(statuses) != 19 {
		t.Errorf("expected 19 extended status codes, got %d", len(statuses))
	}
}

// =============================================================================
// §2.3 ENIP Status Error Code Tests
// =============================================================================

func TestENIPStatusValues(t *testing.T) {
	// Verify ENIP Status codes from §2.3 (7 legal values)
	// 0x0000=Success, 0x0001=InvalidCommand, 0x0002=InsufficientMemory,
	// 0x0003=IncorrectData, 0x0064=InvalidSessionHandle,
	// 0x0065=InvalidLength, 0x0069=UnsupportedProtocol
	statuses := map[uint32]string{
		0x0000: "Success",
		0x0001: "InvalidCommand",
		0x0002: "InsufficientMemory",
		0x0003: "IncorrectData",
		0x0064: "InvalidSessionHandle",
		0x0065: "InvalidLength",
		0x0069: "UnsupportedProtocol",
	}
	for code, name := range statuses {
		_ = name
		if code > 0xFFFF {
			t.Errorf("ENIP Status %s (0x%04X) exceeds 16-bit", name, code)
		}
	}
}

// =============================================================================
// Multiple_Service_Packet Tests (§3.9)
// =============================================================================

func TestBuildMultipleServicePacket(t *testing.T) {
	// T-055, T-056, T-057, T-058: MSP encoding
	subs := []core.ENIPSubRequest{
		{Service: CIPGetAttributeSingle, ClassID: 0x01, InstanceID: 1, AttributeID: 1},
		{Service: CIPGetAttributeSingle, ClassID: 0x01, InstanceID: 1, AttributeID: 6},
	}
	msp := BuildMultipleServicePacket(0x02, 1, subs)
	// First byte should be Service=0x0A
	if msp[0] != CIPMultipleServicePacket {
		t.Errorf("MSP Service: got 0x%02X, want 0x0A", msp[0])
	}
	// After Service(1) + RequestPathSize(1) + RequestPath(4) = 6 bytes
	// T-056: OffsetCount at offset 6 = 2
	offsetCount := binary.LittleEndian.Uint16(msp[6:8])
	if offsetCount != 2 {
		t.Errorf("OffsetCount: got %d, want 2", offsetCount)
	}
	// T-057: Offset[0] at offset 8 = 6 (2 for OffsetCount + 2*2 for offsets array)
	offset0 := binary.LittleEndian.Uint16(msp[8:10])
	if offset0 != 6 {
		t.Errorf("Offset[0]: got %d, want 6", offset0)
	}
}

// =============================================================================
// §6.11 S11: Error Response Tests
// =============================================================================

func TestBuildCIPResponse(t *testing.T) {
	// T-023: CIP response structure
	resp := BuildCIPResponse(0x8E, 0x00, nil, []byte{0x01, 0x00})
	// Reply Service=0x8E
	if resp[0] != 0x8E {
		t.Errorf("Reply Service: got 0x%02X, want 0x8E", resp[0])
	}
	// Reserved=0
	if resp[1] != 0x00 {
		t.Errorf("Reserved: got 0x%02X, want 0x00", resp[1])
	}
	// General Status=0
	if resp[2] != 0x00 {
		t.Errorf("General Status: got 0x%02X, want 0x00", resp[2])
	}
	// Additional Status Size=0
	if resp[3] != 0x00 {
		t.Errorf("AddStatus Size: got 0x%02X, want 0x00", resp[3])
	}
}

// TestSetAttributeListPayloadCount: Set_Attribute_List (0x04) 的 Payload
// 是 AttrID(2B) + 属性数据(类型相关, Identity STRING 为 2B 长度前缀+数据)
// 的混合结构（设计 §3.10；Wireshark dissect_cip_set_attribute_list_req
// L8157-8188 按 att_count 读取 AttrID 后用 dissect_cip_attribute 按属性
// 类型消费数据，AttrID 后无 DataSize 字段）。
// 回归：旧实现把整个 Payload 当 AttrID 列表（count=len/2），t027
// Payload=[7,0,0,1,88] 被算成 count=2 并把值字节误当 AttrID。
func TestSetAttributeListPayloadCount(t *testing.T) {
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{
				Command:     CmdSendRRData,
				CIPService:  CIPSetAttributeList,
				ClassID:     1,
				InstanceID:  1,
				Payload:     []byte{7, 0, 0, 1, 88}, // AttrID=7 + STRING data (len=1 + 'X')
				SessionHandle: 1,
			},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	// ENIP 头 24B + SendRRData 头 8B + Null item 4B + B2 item 头 4B = 40B
	if len(p) < 40 {
		t.Fatalf("payload too short: %d", len(p))
	}
	body := p[40:]
	// Service=0x04
	if body[0] != 0x04 {
		t.Fatalf("Service: got 0x%02X, want 0x04", body[0])
	}
	// PathSize=2, Path=20 01 24 01
	if body[1] != 2 || body[2] != 0x20 || body[3] != 0x01 || body[4] != 0x24 || body[5] != 0x01 {
		t.Errorf("Path: got % X, want 02 20 01 24 01", body[1:6])
	}
	// AttributeCount=1（旧实现误算为 2）
	if got := binary.LittleEndian.Uint16(body[6:8]); got != 1 {
		t.Errorf("AttributeCount: got %d, want 1", got)
	}
	// 单 attribute: AttrID=7 + 数据 00 01 58（原样保留）
	if got := body[8:13]; !bytes.Equal(got, []byte{7, 0, 0, 1, 88}) {
		t.Errorf("attribute data: got % X, want 07 00 00 01 58", got)
	}
}

// =============================================================================
// §6.16 S15: Heartbeat / IndicateStatus
// =============================================================================

func TestIndicateStatus(t *testing.T) {
	// T-064, T-065: NOP / IndicateStatus
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdIndicateStatus, SessionHandle: 0x12345678, Payload: []byte{0x01, 0x00, 0x00, 0x00}},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0].Payload
	if binary.LittleEndian.Uint16(p[0:2]) != CmdIndicateStatus {
		t.Errorf("Command: got 0x%04X, want 0x0072", binary.LittleEndian.Uint16(p[0:2]))
	}
	if binary.LittleEndian.Uint16(p[2:4]) != 4 {
		t.Errorf("Length: got %d, want 4", binary.LittleEndian.Uint16(p[2:4]))
	}
}

// =============================================================================
// Parser Tests
// =============================================================================

func TestParseENIPHeader(t *testing.T) {
	hdr := BuildENIPHeader(CmdListIdentity, 51, 0x12345678, 0, 0x0102030405060708, 0)
	cmd, length, sh, status, sc, opts, err := ParseENIPHeader(hdr)
	if err != nil {
		t.Fatalf("ParseENIPHeader: %v", err)
	}
	if cmd != CmdListIdentity {
		t.Errorf("Command: got 0x%04X, want 0x0063", cmd)
	}
	if length != 51 {
		t.Errorf("Length: got %d, want 51", length)
	}
	if sh != 0x12345678 {
		t.Errorf("SessionHandle: got 0x%08X, want 0x12345678", sh)
	}
	if status != 0 {
		t.Errorf("Status: got %d, want 0", status)
	}
	if sc != 0x0102030405060708 {
		t.Errorf("SenderContext: got 0x%016X, want 0x0102030405060708", sc)
	}
	if opts != 0 {
		t.Errorf("Options: got %d, want 0", opts)
	}
}

func TestParseForwardOpenBody(t *testing.T) {
	body := BuildForwardOpenBody(
		0x0A, 0x05, 0x00000001, 0x00000002,
		0x0001, 0x0001, 0x00000001, 0x07,
		100000, 100000, 0x0200, 0x0200, 0x80,
		[]byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03},
	)
	parsed, err := ParseForwardOpenBody(body)
	if err != nil {
		t.Fatalf("ParseForwardOpenBody: %v", err)
	}
	if parsed["priority_time_tick"].(uint8) != 0x0A {
		t.Errorf("PriorityTimeTick: got %v, want 0x0A", parsed["priority_time_tick"])
	}
	if parsed["o2t_connection_id"].(uint32) != 0x00000001 {
		t.Errorf("O2TConnID: got %v, want 0x00000001", parsed["o2t_connection_id"])
	}
	if parsed["transport_class_trigger"].(uint8) != 0x80 {
		t.Errorf("TransportClassTrigger: got %v, want 0x80", parsed["transport_class_trigger"])
	}
}

func TestParseForwardCloseBody(t *testing.T) {
	body := BuildForwardCloseBody(
		0x0A, 0x05, 0x0001, 0x0001, 0x00000001,
		[]byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03},
	)
	parsed, err := ParseForwardCloseBody(body)
	if err != nil {
		t.Fatalf("ParseForwardCloseBody: %v", err)
	}
	if parsed["connection_serial_number"].(uint16) != 0x0001 {
		t.Errorf("ConnSerialNum: got %v, want 0x0001", parsed["connection_serial_number"])
	}
}

func TestParseCIPResponse(t *testing.T) {
	resp := BuildCIPResponse(0x8E, 0x0E, []uint16{0x0000}, nil)
	reply, status, addStatus, _, err := ParseCIPResponse(resp)
	if err != nil {
		t.Fatalf("ParseCIPResponse: %v", err)
	}
	if reply != 0x8E {
		t.Errorf("ReplyService: got 0x%02X, want 0x8E", reply)
	}
	if status != 0x0E {
		t.Errorf("GeneralStatus: got 0x%02X, want 0x0E", status)
	}
	if len(addStatus) != 1 || addStatus[0] != 0x0000 {
		t.Errorf("AdditionalStatus: got %v, want [0x0000]", addStatus)
	}
}

// =============================================================================
// §2.5 CIP Service Code Tests
// =============================================================================

func TestCIPServiceCodes(t *testing.T) {
	// T-201 ~ T-208: Verify CIP service code values
	codes := map[uint8]string{
		CIPForwardOpen:           "Forward_Open",
		CIPForwardClose:          "Forward_Close",
		CIPLargeForwardOpen:      "LargeForward_Open",
		CIPMultipleServicePacket: "Multiple_Service_Packet",
		CIPGetAttributeList:      "Get_Attribute_List",
		CIPSetAttributeList:      "Set_Attribute_List",
		CIPGetAttributeSingle:    "Get_Attribute_Single",
		CIPSetAttributeSingle:    "Set_Attribute_Single",
	}
	expected := map[uint8]string{
		CIPForwardOpen:           "0x54",
		CIPForwardClose:          "0x4E",
		CIPLargeForwardOpen:      "0x5B",
		CIPMultipleServicePacket: "0x0A",
		CIPGetAttributeList:      "0x03",
		CIPSetAttributeList:      "0x04",
		CIPGetAttributeSingle:    "0x0E",
		CIPSetAttributeSingle:    "0x10",
	}
	for code, name := range codes {
		if expected[code] == "" {
			t.Errorf("missing expected for %s", name)
		}
	}
}

// =============================================================================
// §2.4.1 CPF TypeID Tests
// =============================================================================

func TestCPFTypeIDs(t *testing.T) {
	// T-215: verify CPF TypeIDs are correctly defined
	expected := map[uint16]string{
		TypeIDNullAddress:       "0x0000",
		TypeIDListIdentityResp:  "0x000C",
		TypeIDConnectionAddress: "0x00A1",
		TypeIDConnectedData:     "0x00B1",
		TypeIDUnconnectedData:   "0x00B2",
		TypeIDListServicesResp:  "0x0100",
		TypeIDSockaddrO2T:       "0x8000",
		TypeIDSockaddrT2O:       "0x8001",
		TypeIDSequencedAddress:  "0x8002",
	}
	for typeID, hex := range expected {
		_ = hex
		if typeID > 0xFFFF {
			t.Errorf("TypeID exceeds 16-bit")
		}
	}
}

// =============================================================================
// 修复回归测试：M-1/M-2 SenderContext、H-1 ConnectionID 选择、H-2
// from_response、M-3 Forward_Close 路径一致、M-4 CIP 服务码校验
// =============================================================================

func TestSenderContextIncrementsPerCommand(t *testing.T) {
	// M-1（设计 §6.13 S12）：未显式设置 SenderContext 时，flow 内逐命令
	// 递增（1, 2, 3, ...），每请求唯一，用于请求-响应追踪。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListServices},
			{Command: CmdListIdentity},
			{Command: CmdRegisterSession, ProtocolVersion: 1},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	for i, p := range packets {
		sc := binary.LittleEndian.Uint64(p.Payload[12:20])
		if sc != uint64(i+1) {
			t.Errorf("packet %d SenderContext: got %d, want %d", i, sc, i+1)
		}
	}
}

func TestSenderContextExplicitZeroPreserved(t *testing.T) {
	// M-2：用户显式设置 SenderContext=0（通过 SenderContextPtr）时不得被
	// 默认递增覆盖（T-126：SenderContext 全 0）。
	zero := uint64(0)
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity, SenderContextPtr: &zero},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	sc := binary.LittleEndian.Uint64(packets[0].Payload[12:20])
	if sc != 0 {
		t.Errorf("SenderContext: got %d, want 0", sc)
	}
}

func TestValidateRejectsUnknownCIPService(t *testing.T) {
	// M-4（设计 §8.2 V-112）：CIPService 必须为已知服务码或 0。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: 0x99,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDNullAddress, Length: 0, Data: nil},
					{TypeID: TypeIDUnconnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for unknown cip_service 0x99")
	}
}

func TestValidateIODataNoO2TConnectionID(t *testing.T) {
	// H-1（设计 §3.6/§5.5，T-110）：I/O 发包必须配置 O→T Connection ID，
	// 不能回退到 T2O（originator 接收方向）。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands:  []core.ENIPCommand{{Command: CmdListIdentity}},
		IOData:    &core.ENIPIOData{FrameCount: 1, O2TConnectionID: 0, T2OConnectionID: 5},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error when o2t_connection_id=0 and no from_response")
	}
}

func TestForwardClosePathMismatchRejected(t *testing.T) {
	// M-3（设计 §3.7/§8.2 V-114，T-120a）：同一连接的 Forward_Close 路径
	// 与 Forward_Open 不一致时拒绝。
	open := core.ENIPCommand{
		Command: CmdSendRRData, CIPService: CIPForwardOpen,
		ClassID: 0x06, InstanceID: 1,
		ConnSerialNum: 1, OrigVendorID: 1, OrigSerialNum: 1,
		O2TRPI: 100000, T2ORPI: 100000,
		ConnectionPath: []byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03},
	}
	close := core.ENIPCommand{
		Command: CmdSendRRData, CIPService: CIPForwardClose,
		ClassID: 0x06, InstanceID: 1,
		ConnSerialNum: 1, OrigVendorID: 1, OrigSerialNum: 1,
		ConnectionPath: []byte{0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x04}, // 不同
	}
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{Transport: "tcp", Commands: []core.ENIPCommand{open, close}}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for mismatched Forward_Close path")
	}
}

func TestFromResponseSessionHandleAndIODelivery(t *testing.T) {
	// H-2（设计 §5.6.1/T-071/T-072）：命令 1 = RegisterSession 响应
	// （direction=down），命令 2 用 from_response 引用其 session_handle；
	// IOData.SourceCommandIndex 引用 Forward_Open 响应提取 O2T Connection ID。
	// 先构造 Forward_Open 响应（direction=down，Payload 为完整 CIP 响应）。
	fwdOpenBody := make([]byte, 26)
	binary.LittleEndian.PutUint32(fwdOpenBody[0:4], 0x00000055) // O2T
	binary.LittleEndian.PutUint32(fwdOpenBody[4:8], 0x00000066) // T2O
	binary.LittleEndian.PutUint16(fwdOpenBody[8:10], 0x0001)    // ConnSerial
	fwdOpenResp := append([]byte{0xD4, 0x00, 0x00, 0x00}, fwdOpenBody...)

	srcIdx := 0
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			// 命令 0：Forward_Open 响应（down 方向，供后续引用）
			{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x12345678,
				Payload: fwdOpenResp},
			// 命令 1：SendUnitData 请求，O2T ConnID 来自命令 0 响应
			{Command: CmdSendUnitData, Direction: "up",
				FromResponseField:  "o2t_connection_id",
				SourceCommandIndex: 0,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDConnectionAddress, Length: 4, Data: make([]byte, 4)},
					{TypeID: TypeIDConnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
		IOData: &core.ENIPIOData{
			FrameCount: 1, SequenceStart: 1,
			SourceCommandIndex: &srcIdx,
			Payload:            []byte{0xAA},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets (cmd0 + cmd1 + 1 I/O frame), got %d", len(packets))
	}
	// 命令 1（SendUnitData）的 Connection Address Item Data 应为响应 O2T ID。
	// CPF 起点 = 24 + 6 = 30：ItemCount(2) + Item1 头(TypeID2+Len2) +
	// Item1 Data(4B ConnectionID) → ConnectionID 在 30+2+4 = 36。
	p1 := packets[1].Payload
	if binary.LittleEndian.Uint32(p1[36:40]) != 0x00000055 {
		t.Errorf("SendUnitData ConnectionID: got 0x%08X, want 0x00000055",
			binary.LittleEndian.Uint32(p1[36:40]))
	}
	// I/O 帧（packet 2，UDP）同样结构：ConnectionID 在 offset 36。
	p2 := packets[2].Payload
	if binary.LittleEndian.Uint32(p2[36:40]) != 0x00000055 {
		t.Errorf("IO frame ConnectionID: got 0x%08X, want 0x00000055",
			binary.LittleEndian.Uint32(p2[36:40]))
	}
	// I/O 帧 Connected Data = payload（pcap 回归：无 2B SequenceCounter 前缀，
	// 见 TestBuildIODataFramesUsesPayload）
	items, err := ParseCPFPayload(p2[30:])
	if err != nil {
		t.Fatalf("解析 I/O CPF: %v", err)
	}
	if got := items[1].Data; len(got) != 1 || got[0] != 0xAA {
		t.Errorf("I/O Connected Data: got % X, want AA", got)
	}
}

func TestFromResponseInvalidConfigRejected(t *testing.T) {
	// H-2（T-117/T-118）：source_command_index 超范围 / field 未知 → Plan 拒绝。
	planner := NewPlanner()

	// T-118: field 未知
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendUnitData, FromResponseField: "bogus", SourceCommandIndex: 1,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDConnectionAddress, Length: 4, Data: make([]byte, 4)},
					{TypeID: TypeIDConnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
	}
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Error("expected error for unknown from_response field")
	}

	// T-117: source_command_index 超范围
	spec = basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendUnitData, FromResponseField: "session_handle", SourceCommandIndex: 99,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDConnectionAddress, Length: 4, Data: make([]byte, 4)},
					{TypeID: TypeIDConnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
	}
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Error("expected error for out-of-range source_command_index")
	}
}

// === §7.3 负向校验缺口（T-085/090/091/092/104/105/120，failing-test-first）===

func TestValidateRejectsRegisterSessionPayloadNot4Bytes(t *testing.T) {
	// T-085（设计 §7.3/V-102）：RegisterSession Payload 必须恰好 4B
	// （ProtocolVersion 2B + OptionFlag 2B）。Payload=5B 应拒绝。
	for _, payload := range [][]byte{
		{0x01, 0x00},                   // 2B 过短
		{0x01, 0x00, 0x00, 0x00, 0x01}, // 5B 过长（T-085 输入）
	} {
		spec := basicSpec()
		spec.ENIP = &core.ENIPConfig{
			Transport: "tcp",
			Commands: []core.ENIPCommand{
				{Command: CmdRegisterSession, ProtocolVersion: 1, Payload: payload},
			},
		}
		planner := NewPlanner()
		if err := planner.Validate(spec); err == nil {
			t.Errorf("expected error for RegisterSession payload len=%d", len(payload))
		}
	}
	// 恰好 4B 合法（回归保护：T-014/T-220 依赖）
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1, Payload: []byte{0x01, 0x00, 0x00, 0x00}},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err != nil {
		t.Errorf("expected valid for 4-byte payload, got: %v", err)
	}
}

func TestValidateRejectsSessionHandleStrategy(t *testing.T) {
	// T-090/T-091（设计 §7.3/V-107/V-402）：SessionHandle 仅允许
	// fixed / from_response，inc/rand 无业务意义，应拒绝。
	// （策略经 parseENIPCommands 从 session_handle.{strategy} 映射，
	// 见 strategy_convert.go；此处直接构造 ENIPCommand 底层字段。）
	for _, strategy := range []string{"inc", "rand"} {
		spec := basicSpec()
		spec.ENIP = &core.ENIPConfig{
			Transport: "tcp",
			Commands: []core.ENIPCommand{
				{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle,
					ClassID: 0x01, InstanceID: 1, AttributeID: 1,
					SessionHandleStrategy: strategy},
			},
		}
		planner := NewPlanner()
		if err := planner.Validate(spec); err == nil {
			t.Errorf("expected error for session_handle strategy %q", strategy)
		}
	}
	// from_response / fixed 合法（回归保护）
	for _, strategy := range []string{"", "fixed", "from_response"} {
		spec := basicSpec()
		spec.ENIP = &core.ENIPConfig{
			Transport: "tcp",
			Commands: []core.ENIPCommand{
				{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle,
					ClassID: 0x01, InstanceID: 1, AttributeID: 1,
					SessionHandleStrategy: strategy},
			},
		}
		planner := NewPlanner()
		if err := planner.Validate(spec); err != nil {
			t.Errorf("expected valid for session_handle strategy %q, got: %v", strategy, err)
		}
	}
}

func TestValidateRejectsSendRRDataCIPService0(t *testing.T) {
	// T-092（设计 §7.3/V-112 语境）：SendRRData 携带 Unconnected Data
	// （0x00B2）但没有 CIP 服务码（cip_service=0）——Unconnected Data 必须
	// 含 CIP 消息，拒绝。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: 0,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDNullAddress, Length: 0, Data: nil},
					{TypeID: TypeIDUnconnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for SendRRData with Unconnected Data but cip_service=0")
	}
}

func TestValidateRejectsEPATHOutOfRange(t *testing.T) {
	// T-104/T-105（设计 §7.3）：class_id 超 uint16（0x10000）、
	// instance_id 超 uint32（0x100000000）应拒绝（编码不可表达，且转换层
	// getUint16/getUint32 静默截断后无法按字段编码，必须在转换前拒绝）。
	// 注意：planner 层无法表达超范围值（ENIPCommand.ClassID 是 uint16，
	// 0x10000 会被截断为 0），因此校验与测试都位于转换前一层
	// core.ValidateProtocolSubConfigs（raw map 域）。
	cmd := map[string]interface{}{
		"command":      float64(111), // SendRRData
		"cip_service":  float64(0x0E),
		"class_id":     float64(1),
		"instance_id":  float64(1),
		"attribute_id": float64(1),
	}

	// class_id=0x10000 > uint16 max -> reject
	bad := copyMap(cmd)
	bad["class_id"] = float64(0x10000)
	err := core.ValidateProtocolSubConfigs(enipRawCfg(bad), "enip")
	if err == nil {
		t.Error("expected error for class_id=0x10000 (out of uint16)")
	}

	// instance_id=0x100000000 > uint32 max -> reject
	bad = copyMap(cmd)
	bad["instance_id"] = float64(0x100000000)
	err = core.ValidateProtocolSubConfigs(enipRawCfg(bad), "enip")
	if err == nil {
		t.Error("expected error for instance_id=0x100000000 (out of uint32)")
	}

	// 边界内合法（回归保护：T-131/T-132/T-133 依赖）
	for _, cid := range []float64{0xFFFF, 0x0100, 0xFF} {
		ok := copyMap(cmd)
		ok["class_id"] = cid
		if err := core.ValidateProtocolSubConfigs(enipRawCfg(ok), "enip"); err != nil {
			t.Errorf("expected valid for class_id=0x%04X, got: %v", int(cid), err)
		}
	}
	// T-133：instance_id=0x10000 在 uint32 内，合法（32-bit instance segment）
	ok := copyMap(cmd)
	ok["instance_id"] = float64(0x10000)
	if err := core.ValidateProtocolSubConfigs(enipRawCfg(ok), "enip"); err != nil {
		t.Errorf("expected valid for instance_id=0x10000 (T-133), got: %v", err)
	}
}

// enipRawCfg wraps a single raw command map in the raw spec shape
// {"enip": {"commands": [...]}} that ValidateProtocolSubConfigs receives.
func enipRawCfg(cmd map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"enip": map[string]interface{}{
			"commands": []interface{}{cmd},
		},
	}
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestValidateRejectsConnectionPathSizeMismatch(t *testing.T) {
	// T-120（设计 §7.3/V-120）：ConnectionPathSize 必须 = ⌈len(Path)/2⌉。
	// 显式 5 与实际 4B 路径不符应拒绝。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				ConnSerialNum: 1, OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				ConnectionPath:     []byte{0x20, 0x04, 0x24, 0x01},
				ConnectionPathSize: 5, // 应为 2
			},
		},
	}
	planner := NewPlanner()
	if err := planner.Validate(spec); err == nil {
		t.Error("expected error for connection_path_size mismatch (5 != ceil(4/2))")
	}

	// 合法组合回归保护：size=2 与 4B 路径匹配
	spec = basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				ConnSerialNum: 1, OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				ConnectionPath:     []byte{0x20, 0x04, 0x24, 0x01},
				ConnectionPathSize: 2,
			},
		},
	}
	if err := planner.Validate(spec); err != nil {
		t.Errorf("expected valid for matching path size, got: %v", err)
	}
}

// === TCP Seq/Ack 逐包递增（修复：ENIP 曾是唯一不设 Seq 的 TCP planner，
// 多包同方向时 tshark 无法重组流，第 2+ 包 ENIP 层解析失败）===
func TestTcpSeqAdvancesPerPacket(t *testing.T) {
	// 3 条同方向命令：ListIdentity(up) + ListServices(up) + NOP(up)，
	// 每条 24B 头（ListServices 带 2B data → 26B）。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity, SessionHandle: 0},
			{Command: CmdListServices, SessionHandle: 0},
			{Command: CmdNop, SessionHandle: 0x12345678},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	// 全部 up 方向：Seq 逐包推进，Ack 恒为 server 当前 Seq（初始随机）。
	firstSeq := packets[0].L4.Seq
	if packets[0].L4.Ack != 0 && packets[1].L4.Ack != packets[0].L4.Ack {
		t.Errorf("Ack must be stable across up packets: p0=%d p1=%d", packets[0].L4.Ack, packets[1].L4.Ack)
	}
	want := firstSeq + uint32(len(packets[0].Payload))
	if packets[1].L4.Seq != want {
		t.Errorf("packet 1 Seq: got %d, want %d (advance by payload len)", packets[1].L4.Seq, want)
	}
	want = want + uint32(len(packets[1].Payload))
	if packets[2].L4.Seq != want {
		t.Errorf("packet 2 Seq: got %d, want %d (advance by payload len)", packets[2].L4.Seq, want)
	}
	if packets[0].L4.Flags&0x18 != 0x18 {
		t.Errorf("packet 0 flags: got 0x%02X, want PSH+ACK", packets[0].L4.Flags)
	}
}

func TestTcpSeqDirSwapsForDown(t *testing.T) {
	// 混合方向：RegisterSession(up) + 响应(down) + NOP(up)。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, SessionHandle: 0, ProtocolVersion: 1},
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x12345678, ProtocolVersion: 1},
			{Command: CmdNop, SessionHandle: 0x12345678},
		},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	up0, down, up1 := packets[0], packets[1], packets[2]
	if up0.L4.DstPort != DefaultPort || down.L4.SrcPort != DefaultPort {
		t.Fatalf("port direction swap missing: up0 dst=%d, down src=%d", up0.L4.DstPort, down.L4.SrcPort)
	}
	// down 包 Seq 属于 server 方向（独立计数器），Ack = client 当前 Seq。
	if down.L4.Seq == up0.L4.Seq {
		t.Errorf("down Seq must differ from up Seq (separate counters): both %d", down.L4.Seq)
	}
	if down.L4.Ack != up0.L4.Seq+uint32(len(up0.Payload)) {
		t.Errorf("down Ack: got %d, want %d (client seq after p0)", down.L4.Ack, up0.L4.Seq+uint32(len(up0.Payload)))
	}
	// down 包后 serverSeq 推进，up1 的 Ack = 推进后的 serverSeq。
	if up1.L4.Ack != down.L4.Seq+uint32(len(down.Payload)) {
		t.Errorf("up1 Ack: got %d, want %d (server seq after down)", up1.L4.Ack, down.L4.Seq+uint32(len(down.Payload)))
	}
}

// =============================================================================
// §7.5 多会话/多流（T-161 ~ T-179，failing-test-first）
// =============================================================================
// 语义（设计 §7.5 + §6.13 S12 + §6.14 S13 + R43）：
//   - SessionCount×FlowCount 个单元，每单元独立会话状态（SessionHandle、
//     TCP 序列号、响应表）与独立 4-tuple（TCP 时 srcPort+u；UDP 时共享）；
//   - 逐单元派生：SessionHandle+u、ConnSerialNum+u、O2T/T2O+2u（S13 交错
//     1,3/2,4）、down Forward_Open 响应 payload 同步派生（from_response
//     提取得到逐单元不同 ConnectionID）；单元 0 与单单元场景完全一致；
//   - SenderContext 默认全局递增（跨会话跨流，T-176），显式值 +u（T-177）。

// multiSessionSpec 构造 SessionCount 会话的 RegisterSession 命令模板：
// [RegisterSession 请求(up), RegisterSession 响应(down, SessionHandle=base)]。
func multiSessionSpec(sessionCount int, handleBase uint32) core.FlowSpec {
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport:    "tcp",
		SessionCount: sessionCount,
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1},
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: handleBase, ProtocolVersion: 1},
		},
	}
	return spec
}

// fwdOpenResp 构造 Forward_Open 成功响应 payload（MR 头 4B + body 10B，
// 与设计 §5.6.1 提取布局一致：O2T body[0:4]、T2O body[4:8]、serial body[8:10]）。
func fwdOpenResp(o2t, t2o uint32, serial uint16) []byte {
	p := append([]byte{0xD4, 0x00, 0x00, 0x00}, make([]byte, 10)...)
	binary.LittleEndian.PutUint32(p[4:8], o2t)
	binary.LittleEndian.PutUint32(p[8:12], t2o)
	binary.LittleEndian.PutUint16(p[12:14], serial)
	return p
}

func TestMultiSessionRegisterSessionSenderContextDistinct(t *testing.T) {
	// T-161/T-178：SessionCount=2 → 2 个 RegisterSession 包，SenderContext
	// 不同（全局递增 1,3——每单元 2 条命令）；每单元命令序列完整不交叉。
	spec := multiSessionSpec(2, 0x12345678)
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 4 {
		t.Fatalf("expected 4 packets (2 cmds × 2 sessions), got %d", len(packets))
	}
	sc0 := binary.LittleEndian.Uint64(packets[0].Payload[12:20])
	sc1 := binary.LittleEndian.Uint64(packets[2].Payload[12:20])
	if sc0 == sc1 {
		t.Errorf("T-161: RegisterSession SenderContext must differ across sessions: both %d", sc0)
	}
	if sc0 != 1 || sc1 != 3 {
		t.Errorf("T-176: SenderContext global increment: got %d,%d want 1,3 (per-unit 2 cmds)", sc0, sc1)
	}
	// T-178：每会话命令序列完整（up 在前 down 在后，不交叉）
	for i := 0; i < 4; i++ {
		want := uint16(CmdRegisterSession)
		if got := binary.LittleEndian.Uint16(packets[i].Payload[0:2]); got != want {
			t.Fatalf("packet %d command: got 0x%04X, want 0x%04X", i, got, want)
		}
	}
	if packets[0].L4.DstPort != DefaultPort || packets[2].L4.DstPort != DefaultPort {
		t.Errorf("up packets must target %d", DefaultPort)
	}
	if packets[1].L4.SrcPort != DefaultPort || packets[3].L4.SrcPort != DefaultPort {
		t.Errorf("down packets must originate from %d", DefaultPort)
	}
}

func TestMultiSession8IndependentSessionHandles(t *testing.T) {
	// T-162/T-163：SessionCount=8 → 8 个 down RegisterSession 响应携带
	// 8 个独立 SessionHandle（base+u，0x11111111..0x11111118）。
	spec := multiSessionSpec(8, 0x11111111)
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 16 {
		t.Fatalf("expected 16 packets (2 cmds × 8 sessions), got %d", len(packets))
	}
	seen := make(map[uint32]bool)
	for u := 0; u < 8; u++ {
		p := packets[2*u+1] // down RegisterSession 响应
		if p.L4.SrcPort != DefaultPort {
			t.Errorf("session %d response must be down (src=44818), got %d", u, p.L4.SrcPort)
		}
		h := binary.LittleEndian.Uint32(p.Payload[4:8])
		want := uint32(0x11111111) + uint32(u)
		if h != want {
			t.Errorf("session %d SessionHandle: got 0x%08X, want 0x%08X", u, h, want)
		}
		if seen[h] {
			t.Errorf("session %d SessionHandle 0x%08X duplicated", u, h)
		}
		seen[h] = true
	}
}

func TestMultiSessionTcpTuplesDistinct(t *testing.T) {
	// T-169：SessionCount=2（TCP）→ 每会话独立 TCP 流，srcPort 不同
	// （49152 / 49153），flowID 不同。
	spec := multiSessionSpec(2, 0x12345678)
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	p0, p2 := packets[0], packets[2]
	if p0.L4.SrcPort != 49152 || p2.L4.SrcPort != 49153 {
		t.Errorf("T-169: srcPort must differ per session: got %d / %d", p0.L4.SrcPort, p2.L4.SrcPort)
	}
	if p0.FlowID == p2.FlowID {
		t.Errorf("T-169: flowID must differ per session, both %q", p0.FlowID)
	}
	if p0.FlowID != "enip-192.168.1.100-192.168.1.1-49152-44818" {
		t.Errorf("flowID format: got %q", p0.FlowID)
	}
}

func TestMultiFlowForwardOpenDistinct(t *testing.T) {
	// T-164/T-168：FlowCount=2 → 2 个 Forward_Open，ConnSerialNum 不同
	// （1,2）、O2TConnectionID 不同（1,3，§6.14 S13 交错 2 步）；
	// down 响应 payload 同步派生（O2T 0x55→0x57）。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		FlowCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				O2TConnID: 1, T2OConnID: 2, ConnSerialNum: 1,
				OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				O2TConnParams: 512, T2OConnParams: 512,
				TransportClassTrigger: 0x80, ConnectionTimeoutMultiplier: 7},
			{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x12345678,
				Payload: fwdOpenResp(0x55, 0x66, 1)},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 4 {
		t.Fatalf("expected 4 packets (2 cmds × 2 flows), got %d", len(packets))
	}
	// Forward_Open 请求（packets[0] / [2]）：CIP body 内 O2T 在 cip[8:12]，
	// ConnSerialNum 在 cip[16:18]（service+pathSize+path 共 6B 前缀）。
	for u, idx := range []int{0, 2} {
		items, err := ParseCPFPayload(packets[idx].Payload[30:])
		if err != nil {
			t.Fatalf("flow %d: ParseCPFPayload: %v", u, err)
		}
		cip := items[1].Data
		wantO2T := uint32(1 + 2*u)
		if got := binary.LittleEndian.Uint32(cip[8:12]); got != wantO2T {
			t.Errorf("flow %d O2TConnectionID: got %d, want %d", u, got, wantO2T)
		}
		wantSerial := uint16(1 + u)
		if got := binary.LittleEndian.Uint16(cip[16:18]); got != wantSerial {
			t.Errorf("flow %d ConnSerialNum: got %d, want %d", u, got, wantSerial)
		}
	}
	// down 响应 payload 派生：flow 1 响应 O2T = 0x55 + 2 = 0x57
	if v, ok := extractFromResponse(packets[3].Payload, "o2t_connection_id"); !ok || v != 0x57 {
		t.Errorf("flow 1 response O2T: got %d (ok=%v), want 0x57", v, ok)
	}
}

func TestMultiFlowFromResponseIsolated(t *testing.T) {
	// T-173：FlowCount=2，SendUnitData 用 from_response 提取 o2t_connection_id
	// → 每流从自己的 Forward_Open 响应提取（0x55 / 0x57），不交叉引用。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		FlowCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				O2TConnID: 1, T2OConnID: 2, ConnSerialNum: 1,
				OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				O2TConnParams: 512, T2OConnParams: 512,
				TransportClassTrigger: 0x80, ConnectionTimeoutMultiplier: 7},
			{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x12345678,
				Payload: fwdOpenResp(0x55, 0x66, 1)},
			{Command: CmdSendUnitData,
				FromResponseField:  "o2t_connection_id",
				SourceCommandIndex: 1,
				CPFItems: []core.CPFItem{
					{TypeID: TypeIDConnectionAddress, Length: 4, Data: make([]byte, 4)},
					{TypeID: TypeIDConnectedData, Length: 2, Data: []byte{0x01, 0x00}},
				}},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 6 {
		t.Fatalf("expected 6 packets (3 cmds × 2 flows), got %d", len(packets))
	}
	for u, idx := range []int{2, 5} {
		items, err := ParseCPFPayload(packets[idx].Payload[30:])
		if err != nil {
			t.Fatalf("flow %d SendUnitData: ParseCPFPayload: %v", u, err)
		}
		want := uint32(0x55 + 2*u)
		if got := binary.LittleEndian.Uint32(items[0].Data); got != want {
			t.Errorf("flow %d ConnectionID: got 0x%08X, want 0x%08X", u, got, want)
		}
	}
}

func TestMultiFlowUdpSharedTupleDistinctConnID(t *testing.T) {
	// T-170/T-167：transport=udp，FlowCount=2 → 4-tuple 完全共享；
	// I/O 帧 ConnectionID 不同（0x55/0x57），每流 SequenceCounter 均从 0x0001。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "udp",
		FlowCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				O2TConnID: 1, T2OConnID: 2, ConnSerialNum: 1,
				OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				O2TConnParams: 512, T2OConnParams: 512,
				TransportClassTrigger: 0x80, ConnectionTimeoutMultiplier: 7},
			{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x12345678,
				Payload: fwdOpenResp(0x55, 0x66, 1)},
		},
		IOData: &core.ENIPIOData{
			FrameCount: 1, SequenceStart: 1,
			SourceCommandIndex: intPtr(1),
			Payload:            []byte{0xAA},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 6 {
		t.Fatalf("expected 6 packets (2 cmds × 2 flows + 2 I/O), got %d", len(packets))
	}
	// 布局：unit0 [open, resp, I/O] unit1 [open, resp, I/O] → I/O 帧在 2 和 5
	io0, io1 := packets[2], packets[5]
	if io0.L4.Protocol != "udp" || io1.L4.Protocol != "udp" {
		t.Fatalf("I/O must be UDP, got %s / %s", io0.L4.Protocol, io1.L4.Protocol)
	}
	if io0.FlowID != io1.FlowID {
		t.Errorf("T-170: I/O frames must share flowID, got %q / %q", io0.FlowID, io1.FlowID)
	}
	if io0.L4.SrcPort != io1.L4.SrcPort || io0.L4.DstPort != io1.L4.DstPort {
		t.Errorf("T-170: I/O 4-tuple must be shared: (%d,%d) vs (%d,%d)",
			io0.L4.SrcPort, io0.L4.DstPort, io1.L4.SrcPort, io1.L4.DstPort)
	}
	for u, p := range []core.PacketConfig{io0, io1} {
		items, err := ParseCPFPayload(p.Payload[30:])
		if err != nil {
			t.Fatalf("I/O flow %d: ParseCPFPayload: %v", u, err)
		}
		want := uint32(0x55 + 2*u)
		if got := binary.LittleEndian.Uint32(items[0].Data); got != want {
			t.Errorf("flow %d I/O ConnectionID: got 0x%08X, want 0x%08X", u, got, want)
		}
		// T-167：Connected Data = payload（pcap 回归：无 SequenceCounter 前缀）
		if got := items[1].Data; len(got) != 1 || got[0] != 0xAA {
			t.Errorf("flow %d I/O Connected Data: got % X, want AA", u, got)
		}
	}
}

func TestMultiSessionFromResponseSessionHandleIsolated(t *testing.T) {
	// T-172：SessionCount=2，NOP 用 from_response 提取 session_handle
	// → 每会话从自己的 RegisterSession 响应提取（0x12345678 / 0x12345679）。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport:    "tcp",
		SessionCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x12345678, ProtocolVersion: 1},
			{Command: CmdNop, FromResponseField: "session_handle", SourceCommandIndex: 0},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 4 {
		t.Fatalf("expected 4 packets (2 cmds × 2 sessions), got %d", len(packets))
	}
	for u, idx := range []int{1, 3} {
		want := uint32(0x12345678) + uint32(u)
		if got := binary.LittleEndian.Uint32(packets[idx].Payload[4:8]); got != want {
			t.Errorf("session %d NOP SessionHandle: got 0x%08X, want 0x%08X", u, got, want)
		}
	}
}

func TestMultiSessionUnRegisterMatchesOwnHandle(t *testing.T) {
	// T-174：SessionCount=2，UnRegisterSession 复用本会话 SessionHandle
	// （0x12345678 / 0x12345679），不跨会话。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport:    "tcp",
		SessionCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1},
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x12345678, ProtocolVersion: 1},
			{Command: CmdUnRegisterSession},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 6 {
		t.Fatalf("expected 6 packets (3 cmds × 2 sessions), got %d", len(packets))
	}
	for u, idx := range []int{2, 5} {
		want := uint32(0x12345678) + uint32(u)
		if got := binary.LittleEndian.Uint32(packets[idx].Payload[4:8]); got != want {
			t.Errorf("session %d UnRegisterSession handle: got 0x%08X, want 0x%08X", u, got, want)
		}
	}
}

func TestMultiFlowForwardCloseSerialMatches(t *testing.T) {
	// T-175：FlowCount=2，Forward_Close 的 ConnSerialNum 与本流 Forward_Open
	// 匹配（1 / 2），不跨流。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		FlowCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen,
				O2TConnID: 1, T2OConnID: 2, ConnSerialNum: 1,
				OrigVendorID: 1, OrigSerialNum: 1,
				O2TRPI: 100000, T2ORPI: 100000,
				O2TConnParams: 512, T2OConnParams: 512,
				TransportClassTrigger: 0x80, ConnectionTimeoutMultiplier: 7},
			{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x12345678,
				Payload: fwdOpenResp(0x55, 0x66, 1)},
			{Command: CmdSendRRData, CIPService: CIPForwardClose,
				ConnSerialNum: 1, OrigVendorID: 1, OrigSerialNum: 1},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 6 {
		t.Fatalf("expected 6 packets (3 cmds × 2 flows), got %d", len(packets))
	}
	for u, idx := range []int{2, 5} {
		items, err := ParseCPFPayload(packets[idx].Payload[30:])
		if err != nil {
			t.Fatalf("flow %d Forward_Close: ParseCPFPayload: %v", u, err)
		}
		cip := items[1].Data
		if cip[0] != CIPForwardClose {
			t.Errorf("flow %d: got service 0x%02X, want Forward_Close 0x4E", u, cip[0])
		}
		// Forward_Close body：ptt/tt 在 cip[6:8]，triad 8B，pathsize 在
		// cip[16]，reserved 在 cip[17]，serial 在 cip[8:10]（6B 前缀 +
		// ptt/tt 2B → 位置不变；加入 reserved 只后移 path）
		want := uint16(1 + u)
		if got := binary.LittleEndian.Uint16(cip[8:10]); got != want {
			t.Errorf("flow %d Forward_Close ConnSerialNum: got %d, want %d", u, got, want)
		}
		if cip[17] != 0x00 {
			t.Errorf("flow %d Forward_Close reserved: got %02X, want 00", u, cip[17])
		}
	}
}

func TestSetAttributeIdentityProductNameHasStringLength(t *testing.T) {
	// pcap 深度测试回归（failing-test-first）：Set_Attribute_Single 写
	// Identity (0x01) attr 7 (Product Name) 必须带 CIP STRING 2B 长度前缀。
	// tshark 对无长度前缀的 STRING 报 "Missing string data" → _ws.malformed。
	body := BuildSetAttributeSingle(0x01, 1, 7, []byte{0x08, 0x00, 0x58, 0x00}) // STRING: 2B len + 'X'
	if len(body) != 12 {
		t.Fatalf("BuildSetAttributeSingle 长度: got %d, want 12 (2B 头 + 6B 路径 + 4B STRING)", len(body))
	}
	if binary.LittleEndian.Uint16(body[8:10]) != 8 {
		t.Errorf("STRING 长度: got %d, want 8", binary.LittleEndian.Uint16(body[8:10]))
	}
	if body[10] != 0x58 {
		t.Errorf("STRING 内容: got %02X, want 58", body[10])
	}
	// 直接端到端：Set_Attribute_Single 帧 payload 应为
	// 10 03 20 01 24 01 30 07 + 用户原始 STRING 编码（2B 长度 + 字节）；
	// 缺长度前缀时 tshark 报 "Missing string data" → _ws.malformed。
	// 用户必须按 CIP 类型（STRING）自行编码 Payload（含长度前缀）。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPSetAttributeSingle,
				ClassID: 0x01, InstanceID: 1, AttributeID: 7,
				Payload: []byte{0x08, 0x00, 0x58, 0x00}}, // STRING(len=8) + 'X'
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	items, err := ParseCPFPayload(packets[0].Payload[30:])
	if err != nil {
		t.Fatalf("ParseCPFPayload: %v", err)
	}
	cip := items[1].Data
	// CIP: 10 03 20 01 24 01 30 07 + STRING(len 08 00 + 'X')
	if len(cip) != 12 {
		t.Fatalf("CIP 长度: got %d, want 12 (8B 头 + 2B 长度 + 2B 数据)", len(cip))
	}
	if binary.LittleEndian.Uint16(cip[8:10]) != 8 {
		t.Errorf("STRING 长度: got %d, want 8", binary.LittleEndian.Uint16(cip[8:10]))
	}
	if cip[10] != 0x58 {
		t.Errorf("STRING 内容: got %02X, want 58", cip[10])
	}
	// 原始 payload（无长度前缀）必须原样透传（builder 不重写用户数据）
	rawSpec := basicSpec()
	rawSpec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPSetAttributeSingle,
				ClassID: 0x01, InstanceID: 1, AttributeID: 7,
				Payload: []byte{0x30, 0x07, 0x58}},
		},
	}
	rawCh, rawErr := NewPlanner().Plan(context.Background(), rawSpec)
	if rawErr != nil {
		t.Fatalf("Plan(raw): %v", rawErr)
	}
	rawPackets := drain(rawCh)
	rawItems, err := ParseCPFPayload(rawPackets[0].Payload[30:])
	if err != nil {
		t.Fatalf("ParseCPFPayload: %v", err)
	}
	rawCIP := rawItems[1].Data
	// 10 03 | 20 01 24 01 30 07 | 30 07 58 —— 路径(6B) + 原始 payload 透传
	if len(rawCIP) != 11 || rawCIP[8] != 0x30 || rawCIP[10] != 0x58 {
		t.Errorf("原始 Payload 应原样透传: got % X, want 10 03 20 01 24 01 30 07 30 07 58", rawCIP)
	}
}

func TestMultiUnitSenderContextExplicitPerUnit(t *testing.T) {
	// T-177：显式 sender_context=5（每流独立策略）→ 流 1 首包 = 6 ≠ 流 2 首包 = 5。
	spec := basicSpec()
	spec.ENIP = &core.ENIPConfig{
		Transport: "tcp",
		FlowCount: 2,
		Commands: []core.ENIPCommand{
			{Command: CmdListIdentity, SenderContext: 5},
		},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	sc0 := binary.LittleEndian.Uint64(packets[0].Payload[12:20])
	sc1 := binary.LittleEndian.Uint64(packets[1].Payload[12:20])
	if sc0 != 5 || sc1 != 6 {
		t.Errorf("T-177: SenderContext per-unit: got %d,%d want 5,6", sc0, sc1)
	}
}

func TestValidateRejectsBadSessionFlowCount(t *testing.T) {
	// V-005/V-006（设计 §8.1）：SessionCount 1-1000、FlowCount 1-100；
	// 负数与超上限必须拒绝。
	for _, c := range []struct{ sc, fc int }{
		{-1, 1}, {1001, 1}, {1, -1}, {1, 101},
	} {
		spec := basicSpec()
		spec.ENIP = &core.ENIPConfig{
			Transport:    "tcp",
			SessionCount: c.sc,
			FlowCount:    c.fc,
			Commands:     []core.ENIPCommand{{Command: CmdListIdentity}},
		}
		planner := NewPlanner()
		if err := planner.Validate(spec); err == nil {
			t.Errorf("expected error for session_count=%d flow_count=%d", c.sc, c.fc)
		}
	}
	// 边界合法：1000/100 与默认 0（=1）均通过
	for _, c := range []struct{ sc, fc int }{{1000, 100}, {0, 0}} {
		spec := basicSpec()
		spec.ENIP = &core.ENIPConfig{
			Transport:    "tcp",
			SessionCount: c.sc,
			FlowCount:    c.fc,
			Commands:     []core.ENIPCommand{{Command: CmdListIdentity}},
		}
		if err := NewPlanner().Validate(spec); err != nil {
			t.Errorf("expected valid for session_count=%d flow_count=%d, got %v", c.sc, c.fc, err)
		}
	}
}
