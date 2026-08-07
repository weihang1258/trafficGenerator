// Package modbus implements the Modbus TCP protocol planner.
// This file contains MBAP frame and PDU construction utilities.
package modbus

import (
	"encoding/binary"
	"fmt"
)

// BuildMBAPFrame builds the complete Modbus TCP frame (MBAP header + PDU).
// MBAP header: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1) = 7 bytes.
// Length field = 1(Unit ID) + len(PDU) — NOT the PDU length itself (§1.5 #2).
func BuildMBAPFrame(transactionID uint16, unitID uint8, pdu []byte) []byte {
	frame := make([]byte, MBAPHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(frame[MBAPTxnIDOffset:], transactionID)
	binary.BigEndian.PutUint16(frame[MBAPProtoIDOffset:], ProtocolID)
	binary.BigEndian.PutUint16(frame[MBAPLengthOffset:], uint16(1+len(pdu)))
	frame[MBAPUnitIDOffset] = unitID
	copy(frame[MBAPHeaderLen:], pdu)
	return frame
}

// BuildMBAPHeader builds only the 7-byte MBAP header.
func BuildMBAPHeader(transactionID uint16, unitID uint8, pduLen int) []byte {
	header := make([]byte, MBAPHeaderLen)
	binary.BigEndian.PutUint16(header[MBAPTxnIDOffset:], transactionID)
	binary.BigEndian.PutUint16(header[MBAPProtoIDOffset:], ProtocolID)
	binary.BigEndian.PutUint16(header[MBAPLengthOffset:], uint16(1+pduLen))
	header[MBAPUnitIDOffset] = unitID
	return header
}

// BuildExceptionPDU builds an exception response PDU: FC|0x80 + ExceptionCode.
// For FCs with bit7 already set (exemption path), the OR is idempotent.
func BuildExceptionPDU(fc, excCode uint8) []byte {
	return []byte{fc | ExceptionMask, excCode}
}

// BuildReadBitsRequestPDU builds FC 0x01/0x02 request PDU.
func BuildReadBitsRequestPDU(fc uint8, addr, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = fc
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], qty)
	return pdu
}

// BuildReadRegistersRequestPDU builds FC 0x03/0x04 request PDU.
func BuildReadRegistersRequestPDU(fc uint8, addr, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = fc
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], qty)
	return pdu
}

// BuildWriteSingleCoilRequestPDU builds FC 0x05 request PDU.
// writeValue: 0/1/0xFF00/0x0000 (1 maps to 0xFF00; §2.3).
func BuildWriteSingleCoilRequestPDU(addr uint16, writeValue uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = FCWriteSingleCoil
	binary.BigEndian.PutUint16(pdu[1:], addr)
	val := writeValue
	if val == 1 {
		val = 0xFF00
	}
	binary.BigEndian.PutUint16(pdu[3:], val)
	return pdu
}

// BuildWriteSingleRegisterRequestPDU builds FC 0x06 request PDU.
func BuildWriteSingleRegisterRequestPDU(addr, value uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = FCWriteSingleRegister
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], value)
	return pdu
}

// BuildDiagnosticRequestPDU builds FC 0x08 request PDU.
func BuildDiagnosticRequestPDU(subFunc uint16, data []byte) []byte {
	pdu := make([]byte, 3+len(data))
	pdu[0] = FCDiagnostic
	binary.BigEndian.PutUint16(pdu[1:], subFunc)
	copy(pdu[3:], data)
	return pdu
}

// BuildWriteMultipleCoilsRequestPDU builds FC 0x0F request PDU.
func BuildWriteMultipleCoilsRequestPDU(addr, qty uint16, values []byte) []byte {
	pdu := make([]byte, 6+len(values))
	pdu[0] = FCWriteMultipleCoils
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], qty)
	pdu[5] = uint8(len(values))
	copy(pdu[6:], values)
	return pdu
}

// BuildWriteMultipleRegistersRequestPDU builds FC 0x10 request PDU.
func BuildWriteMultipleRegistersRequestPDU(addr, qty uint16, values []byte) []byte {
	pdu := make([]byte, 6+len(values))
	pdu[0] = FCWriteMultipleRegisters
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], qty)
	pdu[5] = uint8(len(values))
	copy(pdu[6:], values)
	return pdu
}

// BuildReadFileRecordsRequestPDU builds FC 0x14 request PDU.
// Each item is 7 bytes: RefType(1) + File(2) + Record(2) + RecLen(2).
func BuildReadFileRecordsRequestPDU(items []byte) []byte {
	pdu := make([]byte, 2+len(items))
	pdu[0] = FCReadFileRecords
	pdu[1] = uint8(len(items)) // Byte Count
	copy(pdu[2:], items)
	return pdu
}

// BuildWriteFileRecordsRequestPDU builds FC 0x15 request PDU.
// Values already contains the outer Byte Count as its first byte, so the
// PDU is FC + Values verbatim (R4-C1: no inner item Byte Count).
func BuildWriteFileRecordsRequestPDU(values []byte) []byte {
	pdu := make([]byte, 1+len(values))
	pdu[0] = FCWriteFileRecords
	copy(pdu[1:], values)
	return pdu
}

// BuildMaskWriteRegisterRequestPDU builds FC 0x16 request PDU.
func BuildMaskWriteRegisterRequestPDU(addr, maskAnd, maskOr uint16) []byte {
	pdu := make([]byte, 7)
	pdu[0] = FCMaskWriteRegister
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], maskAnd)
	binary.BigEndian.PutUint16(pdu[5:], maskOr)
	return pdu
}

// BuildReadWriteMultipleRegistersRequestPDU builds FC 0x17 request PDU.
func BuildReadWriteMultipleRegistersRequestPDU(readAddr, readQty, writeAddr, writeQty uint16, values []byte) []byte {
	pdu := make([]byte, 10+len(values))
	pdu[0] = FCReadWriteMultipleRegs
	binary.BigEndian.PutUint16(pdu[1:], readAddr)
	binary.BigEndian.PutUint16(pdu[3:], readQty)
	binary.BigEndian.PutUint16(pdu[5:], writeAddr)
	binary.BigEndian.PutUint16(pdu[7:], writeQty)
	pdu[9] = uint8(len(values))
	copy(pdu[10:], values)
	return pdu
}

// BuildReadFIFORequestPDU builds FC 0x18 request PDU.
func BuildReadFIFORequestPDU(addr uint16) []byte {
	pdu := make([]byte, 3)
	pdu[0] = FCReadFIFOQueue
	binary.BigEndian.PutUint16(pdu[1:], addr)
	return pdu
}

// BuildMEIRequestPDU builds FC 0x2B request PDU.
func BuildMEIRequestPDU(meiType uint8, data []byte) []byte {
	pdu := make([]byte, 2+len(data))
	pdu[0] = FCEncapsulatedInterface
	pdu[1] = meiType
	copy(pdu[2:], data)
	return pdu
}

// BuildReadBitsResponsePDU builds FC 0x01/0x02 response PDU.
func BuildReadBitsResponsePDU(fc uint8, qty uint16, responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = fc
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.1: default bit data is all zeros (length-correct zeros).
	byteCount := (int(qty) + 7) / 8
	pdu := make([]byte, 2+byteCount)
	pdu[0] = fc
	pdu[1] = uint8(byteCount)
	return pdu
}

// BuildReadRegistersResponsePDU builds FC 0x03/0x04 response PDU.
func BuildReadRegistersResponsePDU(fc uint8, qty uint16, responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = fc
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.2: default register values are all zeros.
	byteCount := int(qty) * 2
	pdu := make([]byte, 2+byteCount)
	pdu[0] = fc
	pdu[1] = uint8(byteCount)
	return pdu
}

// BuildReadExceptionStatusResponsePDU builds FC 0x07 response PDU.
func BuildReadExceptionStatusResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCReadExceptionStatus
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.5 default: Exception Status=0x00.
	return []byte{FCReadExceptionStatus, 0x00}
}

// BuildCommEventCounterResponsePDU builds FC 0x0B response PDU.
func BuildCommEventCounterResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCGetCommEventCounter
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.7 default: Status=0xFFFF (ready), EventCount=0.
	return []byte{FCGetCommEventCounter, 0xFF, 0xFF, 0x00, 0x00}
}

// BuildCommEventLogResponsePDU builds FC 0x0C response PDU.
func BuildCommEventLogResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCGetCommEventLog
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.8 default: Byte Count=6, Status=0xFFFF, EventCount=0,
	// MessageCount=0, Events empty (Byte Count = 6 + 0).
	return []byte{FCGetCommEventLog, 0x06, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
}

// BuildWriteMultipleResponsePDU builds FC 0x0F/0x10 response PDU.
func BuildWriteMultipleResponsePDU(fc uint8, addr, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = fc
	binary.BigEndian.PutUint16(pdu[1:], addr)
	binary.BigEndian.PutUint16(pdu[3:], qty)
	return pdu
}

// BuildReportServerIDResponsePDU builds FC 0x11 response PDU.
// No Byte Count field; first byte is Slave ID (R4-H2).
func BuildReportServerIDResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCReportServerID
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.11 default: Slave ID=0x01, Run Indicator=0xFF.
	return []byte{FCReportServerID, 0x01, 0xFF}
}

// BuildReadFileRecordsResponsePDU builds FC 0x14 response PDU.
// Each item: FileResponseLength(1)=1+2*RL + RefType(1)=0x06 + RecordData(2*RL) (R3-C1).
func BuildReadFileRecordsResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCReadFileRecords
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.12: no auto-derivable default → empty Byte Count=0.
	return []byte{FCReadFileRecords, 0x00}
}

// BuildWriteFileRecordsResponsePDU builds FC 0x15 response PDU (echo).
func BuildWriteFileRecordsResponsePDU(requestPDU []byte) []byte {
	resp := make([]byte, len(requestPDU))
	copy(resp, requestPDU)
	return resp
}

// BuildReadWriteMultipleRegistersResponsePDU builds FC 0x17 response PDU.
func BuildReadWriteMultipleRegistersResponsePDU(readQty uint16, responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCReadWriteMultipleRegs
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.15: default read register values are all zeros.
	byteCount := int(readQty) * 2
	pdu := make([]byte, 2+byteCount)
	pdu[0] = FCReadWriteMultipleRegs
	pdu[1] = uint8(byteCount)
	return pdu
}

// BuildReadFIFOResponsePDU builds FC 0x18 response PDU.
// Byte Count is 2 bytes (unlike other FCs).
// FIFO Count must be <= 31, and value bytes must = 2 * FIFO Count.
func BuildReadFIFOResponsePDU(responseValues []byte) ([]byte, error) {
	if len(responseValues) >= 4 {
		fifoCount := binary.BigEndian.Uint16(responseValues[2:4])
		if fifoCount > MaxFIFOCount {
			return nil, fmt.Errorf("FIFO count exceeds 31")
		}
		valueBytes := len(responseValues) - 4
		if valueBytes != int(fifoCount)*2 {
			return nil, fmt.Errorf("response_values length must match FIFO count")
		}
		// Recompute Byte Count = 2 + 2*FIFOCount (R4-H4: the planner owns
		// the Byte Count, not the user).
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCReadFIFOQueue
		binary.BigEndian.PutUint16(pdu[1:3], uint16(2+2*int(fifoCount)))
		copy(pdu[3:], responseValues[2:])
		return pdu, nil
	}
	if len(responseValues) > 0 && len(responseValues) < 4 {
		return nil, fmt.Errorf("response_values length must match FIFO count")
	}
	// §3.3.16 default: Byte Count=2, FIFO Count=0.
	return []byte{FCReadFIFOQueue, 0x00, 0x02, 0x00, 0x00}, nil
}

// BuildMEIResponsePDU builds FC 0x2B response PDU.
func BuildMEIResponsePDU(responseValues []byte) []byte {
	if len(responseValues) > 0 {
		pdu := make([]byte, 1+len(responseValues))
		pdu[0] = FCEncapsulatedInterface
		copy(pdu[1:], responseValues)
		return pdu
	}
	// §3.3.17 default: MEI Type=0x0E, Read Device ID Code=0x01,
	// Conformity=0x01, More Follows=0x00, Next Object ID=0x00,
	// Object Count=1, Object {ID=0x00, Len=0x00, Value=empty}.
	return []byte{FCEncapsulatedInterface, MEITypeReadDeviceIdentification, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}
}

// PackBits packs coil/input bit data per §2.2.
// LSB of first byte = starting_address+0, bits flow toward high order.
// Last byte's high bits are zero-padded if quantity is not a multiple of 8.
func PackBits(bits []bool) []byte {
	byteCount := (len(bits) + 7) / 8
	result := make([]byte, byteCount)
	for i, b := range bits {
		if b {
			result[i/8] |= 1 << (i % 8)
		}
	}
	return result
}

// UnpackBits unpacks coil/input bit data per §2.2.
func UnpackBits(data []byte, count int) []bool {
	bits := make([]bool, count)
	for i := 0; i < count; i++ {
		if i/8 < len(data) {
			bits[i] = (data[i/8] >> (i % 8)) & 1 == 1
		}
	}
	return bits
}

// BuildMEIReadDeviceIDResponse builds a complete FC 0x2B Read Device
// Identification response. Returns the PDU bytes after the FC byte:
// MEI Type(1)=0x0E + Code(1) + Conformity(1) + More(1) + Next(1) +
// Object Count(1) + Object(s) (§3.3.17).
func BuildMEIReadDeviceIDResponse(readDeviceIDCode, conformityLevel, moreFollows, nextObjectID uint8, objects []MEIObject) []byte {
	// MEI Type(1) + Code(1) + Conformity(1) + More(1) + Next(1) + Count(1) + objects
	objBytes := 0
	for _, obj := range objects {
		objBytes += 2 + len(obj.Value)
	}
	result := make([]byte, 6+objBytes)
	result[0] = MEITypeReadDeviceIdentification
	result[1] = readDeviceIDCode
	result[2] = conformityLevel
	result[3] = moreFollows
	result[4] = nextObjectID
	result[5] = uint8(len(objects))
	idx := 6
	for _, obj := range objects {
		result[idx] = obj.ID
		result[idx+1] = uint8(len(obj.Value))
		copy(result[idx+2:], obj.Value)
		idx += 2 + len(obj.Value)
	}
	return result
}

// MEIObject represents one object in a Read Device Identification response.
type MEIObject struct {
	ID    uint8
	Value []byte
}

// BuildFileRecordRequestItem builds one FC 0x14 request item (7 bytes).
// Item = RefType(1)=0x06 + File(2) + Record(2) + RecLen(2).
func BuildFileRecordRequestItem(fileNum, recordNum, recordLen uint16) []byte {
	item := make([]byte, 7)
	item[0] = 0x06 // Reference Type
	binary.BigEndian.PutUint16(item[1:], fileNum)
	binary.BigEndian.PutUint16(item[3:], recordNum)
	binary.BigEndian.PutUint16(item[5:], recordLen)
	return item
}

// BuildFileRecordResponseItem builds one FC 0x14 response item.
// Item = FileResponseLength(1)=1+2*RL + RefType(1)=0x06 + RecordData(2*RL) (R3-C1).
func BuildFileRecordResponseItem(recordLen uint16, recordData []byte) []byte {
	itemLen := 2 + int(recordLen)*2
	item := make([]byte, itemLen)
	item[0] = uint8(1 + 2*int(recordLen)) // File Response Length = 1 + 2*RL
	item[1] = 0x06                        // Reference Type
	copy(item[2:], recordData)
	return item
}

// BuildWriteFileRecordRequestItem builds one FC 0x15 request item.
// Item = RefType(1)=0x06 + File(2) + Record(2) + RecLen(2) + Data(2*RL);
// no inner Byte Count (R4-C1).
func BuildWriteFileRecordRequestItem(fileNum, recordNum, recordLen uint16, recordData []byte) []byte {
	itemLen := 7 + int(recordLen)*2
	item := make([]byte, itemLen)
	item[0] = 0x06 // Reference Type
	binary.BigEndian.PutUint16(item[1:], fileNum)
	binary.BigEndian.PutUint16(item[3:], recordNum)
	binary.BigEndian.PutUint16(item[5:], recordLen)
	copy(item[7:], recordData)
	return item
}
