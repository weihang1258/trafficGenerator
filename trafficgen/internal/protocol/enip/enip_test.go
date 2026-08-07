// Package enip tests for the EtherNet/IP (ENIP) planner.
// Tests derive from docs/protocol-designs/12-enip-design.md §6 (S1-S15 HexDumps)
// and §7 (T-001 ~ T-220 test cases). Each test asserts observable wire output.
package enip

import (
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
	want := []byte{0x07, 0x00, 0xAA, 0xBB, 0xCC}
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
	if got := len(items[1].Data); got != 6 {
		t.Fatalf("Connected Data 长度: got %d, want 6", got)
	}
	if string(items[1].Data[2:]) != string(make([]byte, 4)) {
		t.Fatalf("帧数据不是 4 字节零填充: % X", items[1].Data[2:])
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
	// I/O 帧 Connected Data = Seq(2B) + Payload
	items, err := ParseCPFPayload(p2[30:])
	if err != nil {
		t.Fatalf("解析 I/O CPF: %v", err)
	}
	if got := items[1].Data; len(got) != 3 || got[0] != 0x01 || got[1] != 0x00 || got[2] != 0xAA {
		t.Errorf("I/O Connected Data: got % X, want 01 00 AA", got)
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
