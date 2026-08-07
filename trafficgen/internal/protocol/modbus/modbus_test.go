// Package modbus implements the Modbus TCP protocol planner.
// This file contains tests for the Modbus TCP implementation.
package modbus

import (
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// helper: uint8 pointer
func u8ptr(v uint8) *uint8 { return &v }

// helper: bytes to hex string for error messages
func toHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0xf]
	}
	return string(out)
}

// assertBytes checks if two byte slices are equal.
func assertBytes(t *testing.T, name string, expected, actual []byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("%s: length mismatch: expected %d (%s), got %d (%s)",
			name, len(expected), toHex(expected), len(actual), toHex(actual))
		return
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("%s: byte %d mismatch: expected 0x%02X, got 0x%02X (expected=%s, got=%s)",
				name, i, expected[i], actual[i], toHex(expected), toHex(actual))
			return
		}
	}
}

// === T-001: FC=0x01 Read Coils basic ===
func TestT001_ReadCoilsBasic(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x01,
		StartingAddress: 0x0000,
		Quantity:        10,
		// §8.4: ResponseValues = FC 之后的字节 = Byte Count(1) + 位数据(⌈10/8⌉=2).
		ResponseValues: []byte{0x02, 0x03, 0x01}, // BC=2, data=03 01
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x01, 0x00, 0x00, 0x00, 0x0A}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x01, 0x02, 0x03, 0x01}, respPDU)
}

// === T-002: FC=0x01 bit packing qty=8 ===
func TestT002_ReadCoilsBitPacking8(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x01,
		StartingAddress: 0x0000,
		Quantity:        8,
		ResponseValues:  []byte{0x01, 0xFF},
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x01, 0x01, 0xFF}, respPDU)
}

// === T-003: FC=0x01 qty=2000 upper limit ===
func TestT003_ReadCoilsQty2000(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x01,
		StartingAddress: 0x0000,
		Quantity:        2000,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 250 {
		t.Errorf("Byte Count: expected 0xFA=250, got %d", respPDU[1])
	}
}

// === T-004: FC=0x02 Read Discrete Inputs ===
func TestT004_ReadDiscreteInputs(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x02,
		StartingAddress: 0x0000,
		Quantity:        1,
		ResponseValues:  []byte{0x01, 0x01},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x02, 0x00, 0x00, 0x00, 0x01}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x02, 0x01, 0x01}, respPDU)
}

// === T-005: FC=0x03 Read Holding Registers basic ===
func TestT005_ReadHoldingRegistersBasic(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x03,
		StartingAddress: 0x0000,
		Quantity:        3,
		ResponseValues:  []byte{0x06, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x03, 0x00, 0x00, 0x00, 0x03}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x03, 0x06, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, respPDU)
}

// === T-006: FC=0x03 default all-zero response ===
func TestT006_ReadHoldingRegistersDefault(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x03,
		StartingAddress: 0x0000,
		Quantity:        2,
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x03, 0x04, 0x00, 0x00, 0x00, 0x00}, respPDU)
}

// === T-007: FC=0x03 qty=125 upper limit (Length boundary) ===
func TestT007_ReadHoldingRegistersQty125(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x03,
		StartingAddress: 0x0000,
		Quantity:        125,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 250 {
		t.Errorf("Byte Count: expected 0xFA=250, got %d", respPDU[1])
	}
	// PDU length = 2 + 250 = 252, MBAP Length = 1 + 252 = 253
	pduLen := len(respPDU)
	mbapLen := 1 + pduLen
	if mbapLen != 253 {
		t.Errorf("MBAP Length: expected 253=0x00FD, got %d", mbapLen)
	}
}

// === T-008: FC=0x04 Read Input Registers ===
func TestT008_ReadInputRegisters(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x04,
		StartingAddress: 0x0000,
		Quantity:        1,
		ResponseValues:  []byte{0x02, 0xAB, 0xCD},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x04, 0x00, 0x00, 0x00, 0x01}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x04, 0x02, 0xAB, 0xCD}, respPDU)
}

// === T-009: FC=0x05 Write Single Coil ON ===
func TestT009_WriteSingleCoilON(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x05,
		StartingAddress: 0x0064,
		WriteValue:      0xFF00,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x05, 0x00, 0x64, 0xFF, 0x00}, reqPDU)
}

// === T-010: FC=0x05 Write Single Coil OFF ===
func TestT010_WriteSingleCoilOFF(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x05,
		StartingAddress: 0x0064,
		WriteValue:      0x0000,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x05, 0x00, 0x64, 0x00, 0x00}, reqPDU)
}

// === T-011: FC=0x05 WriteValue=1 boolean mapping ===
func TestT011_WriteSingleCoilBool1(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x05,
		StartingAddress: 0x0064,
		WriteValue:      1,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x05, 0x00, 0x64, 0xFF, 0x00}, reqPDU)
}

// === T-012: FC=0x05 WriteValue=0 boolean mapping ===
func TestT012_WriteSingleCoilBool0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x05,
		StartingAddress: 0x0064,
		WriteValue:      0,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x05, 0x00, 0x64, 0x00, 0x00}, reqPDU)
}

// === T-013: FC=0x05 echo response ===
func TestT013_WriteSingleCoilEcho(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x05,
		StartingAddress: 0x0064,
		WriteValue:      0xFF00,
	}
	reqPDU := buildRequestPDU(op)
	respPDU := buildResponsePDU(op)
	assertBytes(t, "echo response", reqPDU, respPDU)
}

// === T-014: FC=0x06 Write Single Register ===
func TestT014_WriteSingleRegister(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x06,
		StartingAddress: 0x0014,
		WriteValue:      0x1234,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x06, 0x00, 0x14, 0x12, 0x34}, reqPDU)
}

// === T-015: FC=0x06 echo response ===
func TestT015_WriteSingleRegisterEcho(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x06,
		StartingAddress: 0x0014,
		WriteValue:      0x1234,
	}
	reqPDU := buildRequestPDU(op)
	respPDU := buildResponsePDU(op)
	assertBytes(t, "echo response", reqPDU, respPDU)
}

// === T-016: FC=0x07 Read Exception Status ===
func TestT016_ReadExceptionStatus(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x07,
		ResponseValues: []byte{0xFF},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x07}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x07, 0xFF}, respPDU)
}

// === T-017: FC=0x07 exception status all zero ===
func TestT017_ReadExceptionStatusZero(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x07,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x00 {
		t.Errorf("expected 0x00, got 0x%02X", respPDU[1])
	}
}

// === T-018: FC=0x08 Diagnostic Return Query Data ===
func TestT018_DiagnosticReturnQueryData(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0000,
		Values:       []byte{0xAA, 0xBB},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x08, 0x00, 0x00, 0xAA, 0xBB}, reqPDU)

	respPDU := buildResponsePDU(op)
	// §3.3.6: sub-function 0x0000 Return Query Data echoes the request PDU.
	assertBytes(t, "response PDU", reqPDU, respPDU)
}

// === T-019: FC=0x11 Report Server ID (no Byte Count field, R4-H2) ===
func TestT019_ReportServerID(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x11,
		ResponseValues: []byte{0x01, 0xFF, 0xAA, 0xBB},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x11}, reqPDU)

	respPDU := buildResponsePDU(op)
	// No Byte Count field; first byte after FC is Slave ID
	assertBytes(t, "response PDU", []byte{0x11, 0x01, 0xFF, 0xAA, 0xBB}, respPDU)
}

// === T-020: FC=0x14 Read File Records (R3-C1: File Response Length semantics) ===
func TestT020_ReadFileRecords(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x14,
		Values: []byte{ // 1 item: RefType(0x06) + File(0001) + Record(0000) + RecLen(0002)
			0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
		},
		ResponseValues: []byte{ // BC=6, then item: FileRespLen=0x05 + RefType=0x06 + RecordData(4B)
			0x06, 0x05, 0x06, 0x12, 0x34, 0x56, 0x78,
		},
	}
	reqPDU := buildRequestPDU(op)
	// Values = 7 bytes (RefType+File+Record+RecLen), so BC = 0x07
	expectedReq := []byte{0x14, 0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}
	assertBytes(t, "request PDU", expectedReq, reqPDU)

	respPDU := buildResponsePDU(op)
	expectedResp := []byte{0x14, 0x06, 0x05, 0x06, 0x12, 0x34, 0x56, 0x78}
	assertBytes(t, "response PDU", expectedResp, respPDU)
}

// === T-021: FC=0x15 Write File Records (R4-C1: item starts with RefType, no inner BC) ===
func TestT021_WriteFileRecords(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x15,
		Values: []byte{
			// outer BC=0x0B=11, then item: RefType(0x06) + File(0001) + Record(0000) + RecLen(0002) + Data(1234 5678)
			0x0B, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78,
		},
	}
	reqPDU := buildRequestPDU(op)
	expectedReq := []byte{0x15, 0x0B, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78}
	assertBytes(t, "request PDU", expectedReq, reqPDU)

	// Response is echo
	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU (echo)", expectedReq, respPDU)
}

// === T-022: FC=0x15 multiple items ===
func TestT022_WriteFileRecordsMultipleItems(t *testing.T) {
	// 2 items, RecLen=1+1, each item total = 7+2*1=9 bytes
	op := &core.MODBUSOperation{
		FunctionCode: 0x15,
		Values: []byte{
			// outer BC=18=0x12, item1: 06 0001 0000 0001 1234 (9 bytes)
			// item2: 06 0002 0001 0001 5678 (9 bytes)
			0x12,
			0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34,
			0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x56, 0x78,
		},
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

// === T-023: FC=0x16 Mask Write Register ===
func TestT023_MaskWriteRegister(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x16,
		StartingAddress: 0x0000,
		MaskAnd:         0xFFFF,
		MaskOr:          0x0000,
	}
	reqPDU := buildRequestPDU(op)
	expectedReq := []byte{0x16, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}
	assertBytes(t, "request PDU", expectedReq, reqPDU)
}

// === T-025: FC=0x2B Read Device Identification complete response (R4-H1: MEI 0x0E) ===
func TestT025_ReadDeviceIdentification(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x000E, // MEI Type 0x0E
		Values:       []byte{0x01, 0x00}, // Read Device ID Code=0x01, Object ID=0x00
		ResponseValues: []byte{
			0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, // MEI + Code + Conformity + More + Next + Count
			0x00, 0x04, 0x41, 0x42, 0x43, 0x44, // Object: ID=0, Len=4, "ABCD"
		},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x2B, 0x0E, 0x01, 0x00}, reqPDU)

	respPDU := buildResponsePDU(op)
	expectedResp := []byte{
		0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x04, 0x41, 0x42, 0x43, 0x44,
	}
	assertBytes(t, "response PDU", expectedResp, respPDU)
}

// === T-027: FC=0x17 Read/Write Multiple Registers ===
func TestT027_ReadWriteMultipleRegisters(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		ReadAddress:   0x0000,
		ReadQuantity:  10,
		WriteAddress:  0x0014,
		WriteQuantity: 3,
		Values:        []byte{0x11, 0x11, 0x22, 0x22, 0x33, 0x33},
	}
	reqPDU := buildRequestPDU(op)
	expectedReq := []byte{
		0x17, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x14, 0x00, 0x03, 0x06,
		0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
	}
	assertBytes(t, "request PDU", expectedReq, reqPDU)
}

// === T-028: FC=0x17 response Byte Count=ReadQty*2 ===
func TestT028_ReadWriteMultipleResponseBC(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		ReadAddress:   0x0000,
		ReadQuantity:  10,
		WriteAddress:  0x0014,
		WriteQuantity: 3,
		Values:        []byte{0x11, 0x11, 0x22, 0x22, 0x33, 0x33},
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x14 {
		t.Errorf("Byte Count: expected 0x14=20, got 0x%02X", respPDU[1])
	}
}

// === T-029: FC=0x18 Read FIFO Queue ===
func TestT029_ReadFIFOQueue(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x18,
		StartingAddress: 0x0000,
		ResponseValues: []byte{
			0x00, 0x06, // Byte Count (2 bytes) = 6 = 2 + 2*2
			0x00, 0x02, // FIFO Count = 2
			0x00, 0x01, // Value 1
			0x00, 0x02, // Value 2
		},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x18, 0x00, 0x00}, reqPDU)

	respPDU := buildResponsePDU(op)
	expectedResp := []byte{0x18, 0x00, 0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02}
	assertBytes(t, "response PDU", expectedResp, respPDU)
}

// === T-030: FC=0x18 FIFO Count=31 upper limit ===
func TestT030_ReadFIFOCount31(t *testing.T) {
	rv := make([]byte, 4+31*2)
	rv[0] = 0x00
	rv[1] = 0x40 // Byte Count = 2 + 62 = 64
	rv[2] = 0x00
	rv[3] = 0x1F // FIFO Count = 31
	op := &core.MODBUSOperation{
		FunctionCode:   0x18,
		StartingAddress: 0x0000,
		ResponseValues: rv,
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

// === T-031: FC=0x01 exception response 0x01 ===
func TestT031_ExceptionResponse01(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x01,
		ExceptionCode: 0x01,
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "exception PDU", []byte{0x81, 0x01}, respPDU)
}

// === T-032: FC=0x03 exception response 0x02 (R3-L1: request PDU still built normally) ===
func TestT032_ExceptionResponse02(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x03,
		StartingAddress: 0x0000,
		Quantity:       1,
		ExceptionCode:  0x02,
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU (normal)", []byte{0x03, 0x00, 0x00, 0x00, 0x01}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "exception PDU", []byte{0x83, 0x02}, respPDU)
}

// === T-033: FC=0x05 exception response 0x03 ===
func TestT033_ExceptionResponse03(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x05,
		ExceptionCode: 0x03,
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "exception PDU", []byte{0x85, 0x03}, respPDU)
}

// === T-034: FC=0x10 exception response 0x04 ===
func TestT034_ExceptionResponse04(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x10,
		ExceptionCode: 0x04,
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "exception PDU", []byte{0x90, 0x04}, respPDU)
}

// === T-035: Exception code 0x05 Acknowledge ===
func TestT035_ExceptionCode05(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x05,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x05 {
		t.Errorf("expected exc_code 0x05, got 0x%02X", respPDU[1])
	}
}

// === T-036: Exception code 0x06 Slave Busy ===
func TestT036_ExceptionCode06(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x06,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x06 {
		t.Errorf("expected exc_code 0x06, got 0x%02X", respPDU[1])
	}
}

// === T-037: Exception code 0x07 Negative Acknowledge ===
func TestT037_ExceptionCode07(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x07,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x07 {
		t.Errorf("expected exc_code 0x07, got 0x%02X", respPDU[1])
	}
}

// === T-038: Exception code 0x08 Memory Parity ===
func TestT038_ExceptionCode08(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x08,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x08 {
		t.Errorf("expected exc_code 0x08, got 0x%02X", respPDU[1])
	}
}

// === T-039: Exception code 0x0A Gateway Path ===
func TestT039_ExceptionCode0A(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x0A,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x0A {
		t.Errorf("expected exc_code 0x0A, got 0x%02X", respPDU[1])
	}
}

// === T-040: Exception code 0x0B Gateway Target ===
func TestT040_ExceptionCode0B(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x0B,
	}
	respPDU := buildResponsePDU(op)
	if respPDU[1] != 0x0B {
		t.Errorf("expected exc_code 0x0B, got 0x%02X", respPDU[1])
	}
}

// === T-052: FC=0x10 Write Multiple Registers basic ===
func TestT052_WriteMultipleRegisters(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x10,
		StartingAddress: 0x0000,
		Quantity:        2,
		Values:          []byte{0x11, 0x11, 0x22, 0x22},
	}
	reqPDU := buildRequestPDU(op)
	expectedReq := []byte{0x10, 0x00, 0x00, 0x00, 0x02, 0x04, 0x11, 0x11, 0x22, 0x22}
	assertBytes(t, "request PDU", expectedReq, reqPDU)
}

// === T-053: FC=0x0F Write Multiple Coils basic ===
func TestT053_WriteMultipleCoils(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x0F,
		StartingAddress: 0x0000,
		Quantity:        10,
		Values:          []byte{0x03, 0x01},
	}
	reqPDU := buildRequestPDU(op)
	expectedReq := []byte{0x0F, 0x00, 0x00, 0x00, 0x0A, 0x02, 0x03, 0x01}
	assertBytes(t, "request PDU", expectedReq, reqPDU)
}

// === T-054: FC=0x0B Get Comm Event Counter ===
func TestT054_CommEventCounter(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x0B,
		ResponseValues: []byte{0xFF, 0xFF, 0x00, 0x64},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x0B}, reqPDU)

	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x0B, 0xFF, 0xFF, 0x00, 0x64}, respPDU)
}

// === T-055: FC=0x0C Get Comm Event Log (R3-H2: field order) ===
func TestT055_CommEventLog(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x0C,
		ResponseValues: []byte{
			0x0A, // BC=10
			0xFF, 0xFF, // Status=0xFFFF
			0x00, 0x64, // EventCount=100=0x0064
			0x00, 0x0A, // MessageCount=10=0x000A
			0x01, 0x02, 0x03, 0x04, // Events (4 bytes)
		},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x0C}, reqPDU)

	respPDU := buildResponsePDU(op)
	expectedResp := []byte{
		0x0C, 0x0A, 0xFF, 0xFF, 0x00, 0x64, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04,
	}
	assertBytes(t, "response PDU", expectedResp, respPDU)
}

// === T-062: FC=0x18 FIFO Count=0 (R4-H4: self-consistent) ===
func TestT062_FIFOCount0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x18,
		StartingAddress: 0x0000,
		ResponseValues: []byte{
			0x00, 0x02, // Byte Count = 2
			0x00, 0x00, // FIFO Count = 0
		},
	}
	respPDU := buildResponsePDU(op)
	expectedResp := []byte{0x18, 0x00, 0x02, 0x00, 0x00}
	assertBytes(t, "response PDU", expectedResp, respPDU)
}

// === T-063: FC=0x08 sub-function 0x0001 Restart Communications ===
func TestT063_DiagRestartCommunications(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0001,
		Values:       []byte{0xFF, 0x00},
	}
	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x08, 0x00, 0x01, 0xFF, 0x00}, reqPDU)
}

// === T-064: FC=0x08 sub-function 0x0013 legal (R3-H1) ===
func TestT064_DiagSubFunc0x0013(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0013,
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("sub_function 0x0013 should be valid: %v", err)
	}
}

// === T-074: Transactions=nil default 1 transaction ===
func TestT074_TransactionsNilDefault(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		MODBUS: &core.MODBUSConfig{},
	}
	// Validate should pass with nil transactions
	if err := p.Validate(spec); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

// === T-080: FC=0x11 Additional Data can be empty (R4-H2) ===
func TestT080_ReportServerIDNoAdditional(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x11,
		ResponseValues: []byte{0x01, 0xFF},
	}
	respPDU := buildResponsePDU(op)
	assertBytes(t, "response PDU", []byte{0x11, 0x01, 0xFF}, respPDU)
}

// === T-081: FC not in support set + ExcCode=0 → reject ===
func TestT081_UnsupportedFCNoExc(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x99,
		ExceptionCode: 0,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for unsupported FC 0x99")
	}
}

// === T-082: FC high bit set → reject ===
func TestT082_FCHighBitSet(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x83,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for FC with high bit set")
	}
}

// === T-089: Exception code 0x00 treated as unset (R4-L3) ===
func TestT089_ExceptionCode0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x00,
		Quantity:      1,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err != nil {
		t.Errorf("exception code 0x00 should not error: %v", err)
	}
}

// === T-090: Exception code 0x09 invalid ===
func TestT090_ExceptionCode09(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0x09,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for exception code 0x09")
	}
}

// === T-092: Exception code 0xFF invalid ===
func TestT092_ExceptionCodeFF(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		ExceptionCode: 0xFF,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for exception code 0xFF")
	}
}

// === T-093: ExcCode and ResponseValues mutually exclusive ===
func TestT093_ExcCodeAndResponseValuesMutex(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x03,
		ExceptionCode:  0x01,
		ResponseValues: []byte{0x00},
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for mutually exclusive ExcCode and ResponseValues")
	}
}

// === T-094: Broadcast + read FC → reject ===
func TestT094_BroadcastReadFC(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x01,
	}
	cfg := &core.MODBUSConfig{
		UnitID: u8ptr(0),
	}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + read FC")
	}
}

// === T-095: Broadcast + FC=0x17 → reject ===
func TestT095_BroadcastFC17(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		ReadQuantity:  1,
		WriteQuantity: 1,
		Values:        []byte{0x00, 0x00},
	}
	cfg := &core.MODBUSConfig{
		UnitID: u8ptr(0),
	}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x17")
	}
}

// === T-095b: Broadcast + FC=0x02 → reject ===
func TestT095b_BroadcastFC02(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x02, Quantity: 1, ResponseValues: []byte{0x01, 0x01}}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x02")
	}
}

// === T-095c: Broadcast + FC=0x03 → reject ===
func TestT095c_BroadcastFC03(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x03, Quantity: 1, ResponseValues: []byte{0x02, 0x00, 0x01}}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x03")
	}
}

// === T-095d: Broadcast + FC=0x04 → reject ===
func TestT095d_BroadcastFC04(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x04, Quantity: 1, ResponseValues: []byte{0x02, 0x00, 0x01}}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x04")
	}
}

// === T-095e: Broadcast + FC=0x07 → reject ===
func TestT095e_BroadcastFC07(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x07}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x07")
	}
}

// === T-095f: Broadcast + FC=0x08 → reject ===
func TestT095f_BroadcastFC08(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x08, SubFunction: 0x0000}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x08")
	}
}

// === T-095g: Broadcast + FC=0x0B → reject ===
func TestT095g_BroadcastFC0B(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x0B}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x0B")
	}
}

// === T-095h: Broadcast + FC=0x0C → reject ===
func TestT095h_BroadcastFC0C(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x0C}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x0C")
	}
}

// === T-095i: Broadcast + FC=0x11 → reject ===
func TestT095i_BroadcastFC11(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x11}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x11")
	}
}

// === T-095j: Broadcast + FC=0x14 → reject ===
func TestT095j_BroadcastFC14(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x14, Values: []byte{}}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x14")
	}
}

// === T-095k: Broadcast + FC=0x18 → reject ===
func TestT095k_BroadcastFC18(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x18, StartingAddress: 0}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x18")
	}
}

// === T-095l: Broadcast + FC=0x2B → reject ===
func TestT095l_BroadcastFC2B(t *testing.T) {
	op := &core.MODBUSOperation{FunctionCode: 0x2B, SubFunction: 0x000E}
	cfg := &core.MODBUSConfig{UnitID: u8ptr(0)}
	p := NewPlanner()
	err := p.validateOperation(op, cfg)
	if err == nil {
		t.Error("expected error for broadcast + FC 0x2B")
	}
}

// === T-096: UnitID=248 reserved ===
func TestT096_UnitID248(t *testing.T) {
	cfg := &core.MODBUSConfig{UnitID: u8ptr(248)}
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{MODBUS: cfg})
	if err == nil {
		t.Error("expected error for UnitID=248 reserved (V-001)")
	}
}

// === T-097: UnitID=255 reserved ===
func TestT097_UnitID255(t *testing.T) {
	cfg := &core.MODBUSConfig{UnitID: u8ptr(255)}
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{MODBUS: cfg})
	if err == nil {
		t.Error("expected error for UnitID=255 reserved (V-001)")
	}
}

// === T-098: FC=0x01 qty=0 → reject ===
func TestT098_ReadCoilsQty0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x01,
		Quantity:     0,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=0")
	}
}

// === T-098b: FC=0x01 qty=0 + ExceptionCode=0x01 → backed, allowed (§8.3) ===
func TestT098b_QuantityBackedByException(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x01,
		StartingAddress: 0,
		Quantity:        0, // semantically illegal, but exception backs it
		ExceptionCode:   0x01,
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("quantity=0 backed by exception must be accepted, got %v", err)
	}
}

// === T-099: FC=0x01 qty=2001 → reject ===
func TestT099_ReadCoilsQty2001(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x01,
		Quantity:     2001,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=2001")
	}
}

// === T-100: FC=0x03 qty=0 → reject ===
func TestT100_ReadRegistersQty0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x03,
		Quantity:     0,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=0")
	}
}

// === T-100b: FC=0x03 qty=0 + ExceptionCode → backed, allowed (§8.3) ===
func TestT100b_RegistersQty0BackedByException(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x03,
		StartingAddress: 0,
		Quantity:        0,
		ExceptionCode:   0x03,
		ResponseValues:  nil, // mutually exclusive
	}
	// First, RV must be empty because ExceptionCode+RV is mutually exclusive.
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("quantity=0 backed by exception must be accepted, got %v", err)
	}
}

// === T-101: FC=0x03 qty=126 → reject ===
func TestT101_ReadRegistersQty126(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x03,
		Quantity:     126,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=126")
	}
}

// === T-102: FC=0x0F qty=1969 → reject ===
func TestT102_WriteCoilsQty1969(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x0F,
		Quantity:     1969,
		Values:       make([]byte, 247),
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=1969")
	}
}

// === T-103: FC=0x10 qty=124 → reject ===
func TestT103_WriteRegsQty124(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x10,
		Quantity:     124,
		Values:       make([]byte, 248),
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for quantity=124")
	}
}

// === T-104: FC=0x17 ReadQty=0 → reject ===
func TestT104_FC17ReadQty0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		ReadQuantity:  0,
		WriteQuantity: 1,
		Values:        []byte{0x00, 0x00},
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for ReadQty=0")
	}
}

// === T-105: FC=0x17 WriteQty=0 → reject ===
func TestT105_FC17WriteQty0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		ReadQuantity:  1,
		WriteQuantity: 0,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for WriteQty=0")
	}
}

// === T-111: FC=0x05 WriteValue semantic invalid ===
func TestT111_WriteValueInvalid(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x05,
		WriteValue:   0x1234,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for invalid WriteValue 0x1234")
	}
}

// === T-112: FC=0x18 FIFO Count=32 → reject ===
func TestT112_FIFOCount32(t *testing.T) {
	rv := make([]byte, 4+32*2)
	rv[0] = 0x00
	rv[1] = 0x42 // Byte Count = 2 + 64 = 66
	rv[2] = 0x00
	rv[3] = 0x20 // FIFO Count = 32
	op := &core.MODBUSOperation{
		FunctionCode:   0x18,
		StartingAddress: 0,
		ResponseValues: rv,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for FIFO Count=32")
	}
}

// === T-113: FC=0x08 SubFunction=0x0016 → reject (R3-H1) ===
func TestT113_DiagSubFunc0x0016(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0016,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for sub_function 0x0016")
	}
}

// === T-114: FC=0x08 SubFunction=0x0005 reserved → reject ===
func TestT114_DiagSubFunc0x0005(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0005,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for reserved sub_function 0x0005")
	}
}

// === T-115: FC=0x2B SubFunction high byte non-zero → reject ===
func TestT115_MEIHighByteNonZero(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x010E,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for high byte non-zero")
	}
}

// === T-116: FC=0x2B SubFunction=0x0000 → reject ===
func TestT116_MEISubFunc0(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x0000,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for sub_function 0x0000")
	}
}

// === T-117: FC=0x2B SubFunction=0x000D (CANopen) → reject (R4-H1) ===
func TestT117_MEISubFunc0D(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x000D,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for sub_function 0x000D (CANopen)")
	}
}

// === T-117b: FC=0x2B SubFunction=0x000F → reject ===
func TestT117b_MEISubFunc0F(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x000F,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for sub_function 0x000F")
	}
}

// === T-119b: FC=0x18 FIFO Count mismatch → reject (R4-H4) ===
func TestT119b_FIFOLengthMismatch(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x18,
		StartingAddress: 0,
		ResponseValues: []byte{
			0x00, 0x04, // Byte Count = 4
			0x00, 0x02, // FIFO Count = 2 (needs 4 value bytes, but only 2 provided)
			0x00, 0x01, // only 1 value (2 bytes), should be 2 values (4 bytes)
		},
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err == nil {
		t.Error("expected error for FIFO count mismatch")
	}
}

// === T-119c: FC=0x18 RV too short for BC+FIFO → reject, no panic (slice guard) ===
func TestT119c_FIFOResponseTooShortNoPanic(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		op := &core.MODBUSOperation{
			FunctionCode:    0x18,
			StartingAddress: 0,
			ResponseValues:  make([]byte, n),
		}
		p := NewPlanner()
		if err := p.validateOperation(op, &core.MODBUSConfig{}); err == nil {
			t.Errorf("RV length %d: expected length-match error, got nil", n)
		}
	}
}

// === T-029b: FC=0x18 ResponseValues Byte Count is recomputed (R4-H4) ===
func TestT029b_ReadFIFOBCRecomputed(t *testing.T) {
	// RV with stale Byte Count 0xFFFF that should be replaced by 2+2*2=6.
	op := &core.MODBUSOperation{
		FunctionCode:    0x18,
		StartingAddress: 0,
		ResponseValues: []byte{
			0xFF, 0xFF, // stale Byte Count (should be recomputed to 0x0006)
			0x00, 0x02, // FIFO Count = 2
			0x00, 0x01, 0x00, 0x02,
		},
	}
	respPDU := buildResponsePDU(op)
	if len(respPDU) < 4 {
		t.Fatalf("response too short: %d bytes", len(respPDU))
	}
	if got := int(respPDU[1])<<8 | int(respPDU[2]); got != 6 {
		t.Errorf("recomputed Byte Count: expected 6=0x0006, got %d", got)
	}
}

// === T-150: FC=0x08 SubFunction=0x0015 max legal (R3-H1) ===
func TestT150_DiagSubFunc0x0015(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0015,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err != nil {
		t.Errorf("sub_function 0x0015 should be valid: %v", err)
	}
}

// === T-201: FC=0x99 exemption path response bytes (R2-C1) ===
func TestT201_ExemptionPath0x99(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x99,
		ExceptionCode: 0x01,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err != nil {
		t.Errorf("exemption path should be valid: %v", err)
	}

	reqPDU := buildRequestPDU(op)
	assertBytes(t, "request PDU", []byte{0x99}, reqPDU)

	respPDU := buildResponsePDU(op)
	// 0x99 | 0x80 = 0x99 (idempotent, bit7 already set)
	assertBytes(t, "response PDU", []byte{0x99, 0x01}, respPDU)
}

// === T-202: FC=0x2B response complete structure (R2-C2/R4-H1) ===
func TestT202_FC2BCompleteResponse(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x000E,
		ResponseValues: []byte{
			0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x04, 0x41, 0x42, 0x43, 0x44,
		},
	}
	respPDU := buildResponsePDU(op)
	expected := []byte{
		0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x04, 0x41, 0x42, 0x43, 0x44,
	}
	assertBytes(t, "response PDU", expected, respPDU)
}

// === T-203: FC=0x08 SubFunction=0x0013 legal (R3-H1) ===
func TestT203_DiagSubFunc0x0013Legal(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0013,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err != nil {
		t.Errorf("sub_function 0x0013 should be valid: %v", err)
	}
}

// === T-204: FC=0x08 SubFunction=0x0014 legal (R3-H1) ===
func TestT204_DiagSubFunc0x0014Legal(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0014,
	}
	p := NewPlanner()
	err := p.validateOperation(op, &core.MODBUSConfig{})
	if err != nil {
		t.Errorf("sub_function 0x0014 should be valid: %v", err)
	}
}

// === T-205: ResponseValues and Values independence (R2-H2) ===
func TestT205_ValuesAndResponseValuesIndependent(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x03,
		StartingAddress: 0,
		Quantity:       1,
		Values:         []byte{0xFF}, // request data (not used by FC 0x03 but stored)
		ResponseValues: []byte{0x02, 0xAB, 0xCD},
	}
	reqPDU := buildRequestPDU(op)
	respPDU := buildResponsePDU(op)
	// Request and response are independent
	if string(reqPDU) == string(respPDU) {
		t.Error("request and response should be independent")
	}
}

// === MBAP frame tests ===

// === S1: Read Coils (FC=0x01, qty=10) ===
func TestS1_ReadCoils(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x01,
		StartingAddress: 0x0000,
		Quantity:       10,
		ResponseValues: []byte{0x02, 0x03, 0x01},
	}
	reqPDU := buildRequestPDU(op)
	reqFrame := BuildMBAPFrame(0, 1, reqPDU)
	expectedReq := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01,
		0x01, 0x00, 0x00, 0x00, 0x0A,
	}
	assertBytes(t, "request frame", expectedReq, reqFrame)

	respPDU := buildResponsePDU(op)
	respFrame := BuildMBAPFrame(0, 1, respPDU)
	expectedResp := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01,
		0x01, 0x02, 0x03, 0x01,
	}
	assertBytes(t, "response frame", expectedResp, respFrame)
}

// === S3: Write Single Coil (FC=0x05) ===
func TestS3_WriteSingleCoil(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x05,
		StartingAddress: 0x0064,
		WriteValue:     1, // maps to 0xFF00
	}
	reqPDU := buildRequestPDU(op)
	reqFrame := BuildMBAPFrame(0, 1, reqPDU)
	expectedReq := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01,
		0x05, 0x00, 0x64, 0xFF, 0x00,
	}
	assertBytes(t, "request frame", expectedReq, reqFrame)
}

// === S8: Report Server ID (FC=0x11, no Byte Count, R4-H2) ===
func TestS8_ReportServerID(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x11,
		ResponseValues: []byte{0x01, 0xFF, 0xAA, 0xBB},
	}
	reqPDU := buildRequestPDU(op)
	reqFrame := BuildMBAPFrame(5, 1, reqPDU)
	expectedReq := []byte{
		0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x01,
		0x11,
	}
	assertBytes(t, "request frame", expectedReq, reqFrame)

	respPDU := buildResponsePDU(op)
	respFrame := BuildMBAPFrame(5, 1, respPDU)
	expectedResp := []byte{
		0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01,
		0x11, 0x01, 0xFF, 0xAA, 0xBB,
	}
	assertBytes(t, "response frame", expectedResp, respFrame)
}

// === S14: Exemption path (FC=0x99 + ExceptionCode=0x01, R2-C1) ===
func TestS14_ExemptionPath(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x99,
		ExceptionCode: 0x01,
	}
	reqPDU := buildRequestPDU(op)
	reqFrame := BuildMBAPFrame(9, 1, reqPDU)
	expectedReq := []byte{
		0x00, 0x09, 0x00, 0x00, 0x00, 0x02, 0x01,
		0x99,
	}
	assertBytes(t, "request frame", expectedReq, reqFrame)

	respPDU := buildResponsePDU(op)
	respFrame := BuildMBAPFrame(9, 1, respPDU)
	expectedResp := []byte{
		0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x01,
		0x99, 0x01, // 0x99|0x80=0x99 (idempotent)
	}
	assertBytes(t, "response frame", expectedResp, respFrame)
}

// === Parser tests ===

func TestParseMBAPHeader(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01}
	h, err := ParseMBAPHeader(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if h.TransactionID != 1 {
		t.Errorf("TransactionID: expected 1, got %d", h.TransactionID)
	}
	if h.ProtocolID != 0 {
		t.Errorf("ProtocolID: expected 0, got %d", h.ProtocolID)
	}
	if h.Length != 6 {
		t.Errorf("Length: expected 6, got %d", h.Length)
	}
	if h.UnitID != 1 {
		t.Errorf("UnitID: expected 1, got %d", h.UnitID)
	}
}

func TestParseMBAPHeaderInvalidProtocolID(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01}
	_, err := ParseMBAPHeader(data)
	if err == nil {
		t.Error("expected error for non-zero Protocol ID")
	}
}

func TestParseReadBitsRequest(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x0A}
	req, err := ParseReadBitsRequest(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if req.StartingAddress != 0 {
		t.Errorf("StartingAddress: expected 0, got %d", req.StartingAddress)
	}
	if req.Quantity != 10 {
		t.Errorf("Quantity: expected 10, got %d", req.Quantity)
	}
}

func TestParseExceptionResponse(t *testing.T) {
	pdu := []byte{0x83, 0x02}
	resp, err := ParseExceptionResponse(pdu)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if resp.FunctionCode != 0x03 {
		t.Errorf("FunctionCode: expected 0x03, got 0x%02X", resp.FunctionCode)
	}
	if resp.ExceptionCode != 0x02 {
		t.Errorf("ExceptionCode: expected 0x02, got 0x%02X", resp.ExceptionCode)
	}
}

func TestParseReadFileRecordsRequest(t *testing.T) {
	// BC=7, 1 item: RefType=0x06, File=0001, Record=0000, RecLen=0002
	data := []byte{0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}
	items, err := ParseReadFileRecordsRequest(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].FileNumber != 1 {
		t.Errorf("FileNumber: expected 1, got %d", items[0].FileNumber)
	}
	if items[0].RecordLength != 2 {
		t.Errorf("RecordLength: expected 2, got %d", items[0].RecordLength)
	}
}

func TestParseWriteFileRecordsRequest(t *testing.T) {
	// BC=11, 1 item: RefType=0x06, File=0001, Record=0000, RecLen=0002, Data=1234 5678
	data := []byte{
		0x0B,
		0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78,
	}
	items, err := ParseWriteFileRecordsRequest(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].RecordLength != 2 {
		t.Errorf("RecordLength: expected 2, got %d", items[0].RecordLength)
	}
	if len(items[0].RecordData) != 4 {
		t.Errorf("RecordData len: expected 4, got %d", len(items[0].RecordData))
	}
}

func TestPackBits(t *testing.T) {
	bits := make([]bool, 10)
	bits[0] = true
	bits[1] = true
	bits[8] = true
	packed := PackBits(bits)
	if len(packed) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(packed))
	}
	if packed[0] != 0x03 {
		t.Errorf("byte 0: expected 0x03, got 0x%02X", packed[0])
	}
	if packed[1] != 0x01 {
		t.Errorf("byte 1: expected 0x01, got 0x%02X", packed[1])
	}
}

func TestUnpackBits(t *testing.T) {
	data := []byte{0x03, 0x01}
	bits := UnpackBits(data, 10)
	if !bits[0] || !bits[1] || !bits[8] {
		t.Errorf("expected bits 0,1,8 to be true")
	}
	if bits[2] || bits[9] {
		t.Errorf("expected bits 2,9 to be false")
	}
}

func TestExceptionResponseFC(t *testing.T) {
	// 0x01 | 0x80 = 0x81
	if ExceptionResponseFC(0x01) != 0x81 {
		t.Errorf("0x01|0x80: expected 0x81, got 0x%02X", ExceptionResponseFC(0x01))
	}
	// 0x99 | 0x80 = 0x99 (idempotent, bit7 already set)
	if ExceptionResponseFC(0x99) != 0x99 {
		t.Errorf("0x99|0x80: expected 0x99, got 0x%02X", ExceptionResponseFC(0x99))
	}
}

func TestBuildFileRecordResponseItem(t *testing.T) {
	recordData := []byte{0x12, 0x34, 0x56, 0x78}
	item := BuildFileRecordResponseItem(2, recordData)
	// File Response Length = 1 + 2*2 = 5
	// RefType = 0x06
	// RecordData = 4 bytes
	expected := []byte{0x05, 0x06, 0x12, 0x34, 0x56, 0x78}
	assertBytes(t, "file record response item", expected, item)
}

func TestBuildWriteFileRecordRequestItem(t *testing.T) {
	recordData := []byte{0x12, 0x34, 0x56, 0x78}
	item := BuildWriteFileRecordRequestItem(1, 0, 2, recordData)
	// RefType=0x06, File=0001, Record=0000, RecLen=0002, Data=1234 5678
	expected := []byte{0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78}
	assertBytes(t, "write file record request item", expected, item)
}

func TestParseReadFIFOResponse(t *testing.T) {
	// FC=0x18, Byte Count=6, FIFO Count=2, Values=0001 0002
	data := []byte{0x00, 0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02}
	resp, err := ParseReadFIFOResponse(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if resp.FIFOCount != 2 {
		t.Errorf("FIFOCount: expected 2, got %d", resp.FIFOCount)
	}
	if len(resp.FIFOValues) != 2 {
		t.Fatalf("expected 2 values, got %d", len(resp.FIFOValues))
	}
	if resp.FIFOValues[0] != 1 {
		t.Errorf("value 0: expected 1, got %d", resp.FIFOValues[0])
	}
	if resp.FIFOValues[1] != 2 {
		t.Errorf("value 1: expected 2, got %d", resp.FIFOValues[1])
	}
}

// === Parser: ParseCommEventLogResponse with Byte Count beyond available data → error, no panic ===
func TestParseCommEventLogBCOverflowNoPanic(t *testing.T) {
	// Byte Count = 20 but only 8 bytes available; old code panicked at slice [7:21].
	data := []byte{
		0x14,             // BC = 20 (claims 14 events bytes)
		0xFF, 0xFF,       // Status
		0x00, 0x64,       // EventCount
		0x00, 0x0A,       // MessageCount
		0x01,             // one event byte only
	}
	if _, err := ParseCommEventLogResponse(data); err == nil {
		t.Error("expected error for byte count overflow, got nil")
	}
}

// === Parser: ParseCommEventLogResponse with Byte Count < 6 → error ===
func TestParseCommEventLogBCTooSmall(t *testing.T) {
	data := []byte{0x04, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00} // BC=4, missing events
	if _, err := ParseCommEventLogResponse(data); err == nil {
		t.Error("expected error for byte count < 6")
	}
}

// === T-118a: FC=0x14 item Record Length=0 → reject (V-114) ===
func TestT118a_FC14ItemRecordLengthZero(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x14,
		Values: []byte{
			// 1 item: RefType=0x06, File=0x0001, Record=0x0000, RecLen=0x0000
			0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		},
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err == nil {
		t.Error("expected error for record length=0 (V-114)")
	}
}

// === T-118b: FC=0x14 item Record Length>0 → accept ===
func TestT118b_FC14ItemRecordLengthPositive(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x14,
		Values: []byte{
			// 1 item: RefType=0x06, File=0x0001, Record=0x0000, RecLen=0x0002
			0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
		},
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err != nil {
		t.Errorf("record length=2 must be accepted, got %v", err)
	}
}

func TestParseReadDeviceIDResponse(t *testing.T) {
	data := []byte{
		0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x04, 0x41, 0x42, 0x43, 0x44,
	}
	resp, err := ParseReadDeviceIDResponse(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if resp.MEIType != 0x0E {
		t.Errorf("MEIType: expected 0x0E, got 0x%02X", resp.MEIType)
	}
	if resp.ConformityLevel != 0x01 {
		t.Errorf("ConformityLevel: expected 0x01, got 0x%02X", resp.ConformityLevel)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].ID != 0 {
		t.Errorf("object ID: expected 0, got %d", resp.Objects[0].ID)
	}
	if string(resp.Objects[0].Value) != "ABCD" {
		t.Errorf("object value: expected ABCD, got %s", string(resp.Objects[0].Value))
	}
}

func TestBuildMEIReadDeviceIDResponse(t *testing.T) {
	objects := []MEIObject{
		{ID: 0x00, Value: []byte("ABCD")},
	}
	result := BuildMEIReadDeviceIDResponse(0x01, 0x01, 0x00, 0x00, objects)
	expected := []byte{
		0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x04, 0x41, 0x42, 0x43, 0x44,
	}
	assertBytes(t, "MEI response", expected, result)
}

// === T-156: FC=0x17 WriteAddress fallback ===
func TestT156_WriteAddressFallback(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		StartingAddress: 0,
		ReadAddress:   0,
		ReadQuantity:  10,
		WriteAddress:  0, // fallback to StartingAddress + WriteQuantity
		WriteQuantity: 3,
		Values:        []byte{0x11, 0x11, 0x22, 0x22, 0x33, 0x33},
	}
	reqPDU := buildRequestPDU(op)
	// WriteAddress should be 0 + 3 = 3
	writeAddr := binary.BigEndian.Uint16(reqPDU[5:7])
	if writeAddr != 3 {
		t.Errorf("WriteAddress: expected 3, got %d", writeAddr)
	}
}

// === T-157: FC=0x17 WriteAddress fallback uint16 wrap ===
func TestT157_WriteAddressFallbackWrap(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x17,
		StartingAddress: 0xFFFF,
		ReadAddress:   0,
		ReadQuantity:  10,
		WriteAddress:  0, // fallback to 0xFFFF + 3 = 2 (uint16 wrap)
		WriteQuantity: 3,
		Values:        []byte{0x11, 0x11, 0x22, 0x22, 0x33, 0x33},
	}
	reqPDU := buildRequestPDU(op)
	writeAddr := binary.BigEndian.Uint16(reqPDU[5:7])
	if writeAddr != 2 {
		t.Errorf("WriteAddress: expected 2 (wrap), got %d", writeAddr)
	}
}

// === T-049: Broadcast + SuppressBroadcast=true suppresses response ===
func TestT049_BroadcastSuppress(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x05,
		StartingAddress: 0x0064,
		WriteValue:     0xFF00,
	}
	cfg := &core.MODBUSConfig{
		UnitID:            u8ptr(0),
		SuppressBroadcast: true,
	}
	if shouldGenerateResponse(op, cfg) {
		t.Error("expected response to be suppressed")
	}
}

// === T-050: Broadcast + ExceptionCode + SuppressBroadcast suppresses exception response ===
func TestT050_BroadcastExceptionSuppress(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:   0x05,
		ExceptionCode:  0x04,
	}
	cfg := &core.MODBUSConfig{
		UnitID:            u8ptr(0),
		SuppressBroadcast: true,
	}
	if shouldGenerateResponse(op, cfg) {
		t.Error("expected exception response to be suppressed")
	}
}

// === T-078: ResponseMode=no_response suppresses response ===
func TestT078_ResponseModeNoResponse(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:  0x03,
		Quantity:      1,
		ResponseMode:  "no_response",
	}
	cfg := &core.MODBUSConfig{}
	if shouldGenerateResponse(op, cfg) {
		t.Error("expected response to be suppressed")
	}
}

// === T-078b: FC=0x08 sub-function 0x0004 Force Listen Only Mode: no response (§3.3.6/§4.1) ===
func TestT078b_DiagSubFunc0004NoResponse(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0004,
	}
	cfg := &core.MODBUSConfig{}
	if shouldGenerateResponse(op, cfg) {
		t.Error("Force Listen Only (0x0004) must not produce a response")
	}
}

// === T-078c: FC=0x08 sub-function 0x0001 does produce a response ===
func TestT078c_DiagSubFuncNon0004HasResponse(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0001,
	}
	cfg := &core.MODBUSConfig{}
	if !shouldGenerateResponse(op, cfg) {
		t.Error("sub-function 0x0001 must produce a response")
	}
}

// === T-118: FC=0x14 item Record Length=0 → reject (R2-M5) ===
func TestT118_FC14ItemRecordLengthZero(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x14,
		Values: []byte{
			// 1 item: RefType=0x06, File=0x0001, Record=0x0000, RecLen=0x0000
			0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		},
	}
	p := NewPlanner()
	if err := p.validateOperation(op, &core.MODBUSConfig{}); err == nil {
		t.Error("expected error for record length=0 (V-114)")
	}
}
