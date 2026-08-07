// Package modbus implements the Modbus TCP protocol planner.
// This file contains MBAP frame and PDU parsing utilities.
package modbus

import (
	"encoding/binary"
	"fmt"
)

// MBAPHeader represents the 7-byte MBAP header.
type MBAPHeader struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
}

// ParseMBAPHeader parses the 7-byte MBAP header.
func ParseMBAPHeader(data []byte) (*MBAPHeader, error) {
	if len(data) < MBAPHeaderLen {
		return nil, fmt.Errorf("MBAP header too short: %d bytes", len(data))
	}
	h := &MBAPHeader{
		TransactionID: binary.BigEndian.Uint16(data[MBAPTxnIDOffset:]),
		ProtocolID:    binary.BigEndian.Uint16(data[MBAPProtoIDOffset:]),
		Length:        binary.BigEndian.Uint16(data[MBAPLengthOffset:]),
		UnitID:        data[MBAPUnitIDOffset],
	}
	if h.ProtocolID != ProtocolID {
		return nil, fmt.Errorf("protocol_id must be 0x0000, got 0x%04X", h.ProtocolID)
	}
	return h, nil
}

// ParseFrame parses a complete Modbus TCP frame (MBAP header + PDU).
// Returns the MBAP header and the PDU bytes.
func ParseFrame(data []byte) (*MBAPHeader, []byte, error) {
	h, err := ParseMBAPHeader(data)
	if err != nil {
		return nil, nil, err
	}
	pdu := data[MBAPHeaderLen:]
	expectedLen := int(h.Length) - 1 // Length = 1(UnitID) + PDU len
	if len(pdu) != expectedLen {
		return nil, nil, fmt.Errorf("PDU length mismatch: expected %d, got %d", expectedLen, len(pdu))
	}
	return h, pdu, nil
}

// PDUInfo contains parsed PDU information.
type PDUInfo struct {
	FunctionCode uint8
	IsException  bool
	Data         []byte
}

// ParsePDU parses a PDU and returns function code and data.
func ParsePDU(pdu []byte) (*PDUInfo, error) {
	if len(pdu) < 1 {
		return nil, fmt.Errorf("PDU too short")
	}
	fc := pdu[0]
	isException := fc&ExceptionMask != 0
	data := pdu[1:]
	return &PDUInfo{
		FunctionCode: fc,
		IsException:  isException,
		Data:         data,
	}, nil
}

// ReadBitsRequest represents a parsed FC 0x01/0x02 request.
type ReadBitsRequest struct {
	StartingAddress uint16
	Quantity        uint16
}

// ParseReadBitsRequest parses FC 0x01/0x02 request data.
func ParseReadBitsRequest(data []byte) (*ReadBitsRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("read bits request too short: %d bytes", len(data))
	}
	return &ReadBitsRequest{
		StartingAddress: binary.BigEndian.Uint16(data[0:2]),
		Quantity:        binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// ReadRegistersRequest represents a parsed FC 0x03/0x04 request.
type ReadRegistersRequest struct {
	StartingAddress uint16
	Quantity        uint16
}

// ParseReadRegistersRequest parses FC 0x03/0x04 request data.
func ParseReadRegistersRequest(data []byte) (*ReadRegistersRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("read registers request too short: %d bytes", len(data))
	}
	return &ReadRegistersRequest{
		StartingAddress: binary.BigEndian.Uint16(data[0:2]),
		Quantity:        binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// WriteSingleCoilRequest represents a parsed FC 0x05 request.
type WriteSingleCoilRequest struct {
	OutputAddress uint16
	OutputValue   uint16
}

// ParseWriteSingleCoilRequest parses FC 0x05 request data.
func ParseWriteSingleCoilRequest(data []byte) (*WriteSingleCoilRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("write single coil request too short: %d bytes", len(data))
	}
	return &WriteSingleCoilRequest{
		OutputAddress: binary.BigEndian.Uint16(data[0:2]),
		OutputValue:   binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// WriteSingleRegisterRequest represents a parsed FC 0x06 request.
type WriteSingleRegisterRequest struct {
	RegisterAddress uint16
	RegisterValue   uint16
}

// ParseWriteSingleRegisterRequest parses FC 0x06 request data.
func ParseWriteSingleRegisterRequest(data []byte) (*WriteSingleRegisterRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("write single register request too short: %d bytes", len(data))
	}
	return &WriteSingleRegisterRequest{
		RegisterAddress: binary.BigEndian.Uint16(data[0:2]),
		RegisterValue:   binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// DiagnosticRequest represents a parsed FC 0x08 request.
type DiagnosticRequest struct {
	SubFunction uint16
	Data        []byte
}

// ParseDiagnosticRequest parses FC 0x08 request data.
func ParseDiagnosticRequest(data []byte) (*DiagnosticRequest, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("diagnostic request too short: %d bytes", len(data))
	}
	return &DiagnosticRequest{
		SubFunction: binary.BigEndian.Uint16(data[0:2]),
		Data:        data[2:],
	}, nil
}

// WriteMultipleCoilsRequest represents a parsed FC 0x0F request.
type WriteMultipleCoilsRequest struct {
	StartingAddress uint16
	Quantity        uint16
	ByteCount       uint8
	Values          []byte
}

// ParseWriteMultipleCoilsRequest parses FC 0x0F request data.
func ParseWriteMultipleCoilsRequest(data []byte) (*WriteMultipleCoilsRequest, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("write multiple coils request too short: %d bytes", len(data))
	}
	req := &WriteMultipleCoilsRequest{
		StartingAddress: binary.BigEndian.Uint16(data[0:2]),
		Quantity:        binary.BigEndian.Uint16(data[2:4]),
		ByteCount:       data[4],
	}
	if int(req.ByteCount) > len(data)-5 {
		return nil, fmt.Errorf("byte count exceeds available data")
	}
	req.Values = data[5 : 5+int(req.ByteCount)]
	return req, nil
}

// WriteMultipleRegistersRequest represents a parsed FC 0x10 request.
type WriteMultipleRegistersRequest struct {
	StartingAddress uint16
	Quantity        uint16
	ByteCount       uint8
	Values          []byte
}

// ParseWriteMultipleRegistersRequest parses FC 0x10 request data.
func ParseWriteMultipleRegistersRequest(data []byte) (*WriteMultipleRegistersRequest, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("write multiple registers request too short: %d bytes", len(data))
	}
	req := &WriteMultipleRegistersRequest{
		StartingAddress: binary.BigEndian.Uint16(data[0:2]),
		Quantity:        binary.BigEndian.Uint16(data[2:4]),
		ByteCount:       data[4],
	}
	if int(req.ByteCount) > len(data)-5 {
		return nil, fmt.Errorf("byte count exceeds available data")
	}
	req.Values = data[5 : 5+int(req.ByteCount)]
	return req, nil
}

// MaskWriteRegisterRequest represents a parsed FC 0x16 request.
type MaskWriteRegisterRequest struct {
	ReferenceAddress uint16
	ANDMask          uint16
	ORMask           uint16
}

// ParseMaskWriteRegisterRequest parses FC 0x16 request data.
func ParseMaskWriteRegisterRequest(data []byte) (*MaskWriteRegisterRequest, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("mask write register request too short: %d bytes", len(data))
	}
	return &MaskWriteRegisterRequest{
		ReferenceAddress: binary.BigEndian.Uint16(data[0:2]),
		ANDMask:          binary.BigEndian.Uint16(data[2:4]),
		ORMask:           binary.BigEndian.Uint16(data[4:6]),
	}, nil
}

// ReadWriteMultipleRegistersRequest represents a parsed FC 0x17 request.
type ReadWriteMultipleRegistersRequest struct {
	ReadStartingAddress  uint16
	QuantityToRead       uint16
	WriteStartingAddress uint16
	QuantityToWrite      uint16
	WriteByteCount       uint8
	WriteValues          []byte
}

// ParseReadWriteMultipleRegistersRequest parses FC 0x17 request data.
func ParseReadWriteMultipleRegistersRequest(data []byte) (*ReadWriteMultipleRegistersRequest, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("read/write multiple registers request too short: %d bytes", len(data))
	}
	req := &ReadWriteMultipleRegistersRequest{
		ReadStartingAddress:  binary.BigEndian.Uint16(data[0:2]),
		QuantityToRead:       binary.BigEndian.Uint16(data[2:4]),
		WriteStartingAddress: binary.BigEndian.Uint16(data[4:6]),
		QuantityToWrite:      binary.BigEndian.Uint16(data[6:8]),
		WriteByteCount:       data[8],
	}
	if int(req.WriteByteCount) > len(data)-9 {
		return nil, fmt.Errorf("write byte count exceeds available data")
	}
	req.WriteValues = data[9 : 9+int(req.WriteByteCount)]
	return req, nil
}

// ReadFIFORequest represents a parsed FC 0x18 request.
type ReadFIFORequest struct {
	FIFOPointerAddress uint16
}

// ParseReadFIFORequest parses FC 0x18 request data.
func ParseReadFIFORequest(data []byte) (*ReadFIFORequest, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("read FIFO request too short: %d bytes", len(data))
	}
	return &ReadFIFORequest{
		FIFOPointerAddress: binary.BigEndian.Uint16(data[0:2]),
	}, nil
}

// ReadFIFOResponse represents a parsed FC 0x18 response.
type ReadFIFOResponse struct {
	ByteCount   uint16
	FIFOCount   uint16
	FIFOValues  []uint16
}

// ParseReadFIFOResponse parses FC 0x18 response data (after FC byte).
func ParseReadFIFOResponse(data []byte) (*ReadFIFOResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("read FIFO response too short: %d bytes", len(data))
	}
	resp := &ReadFIFOResponse{
		ByteCount: binary.BigEndian.Uint16(data[0:2]),
		FIFOCount: binary.BigEndian.Uint16(data[2:4]),
	}
	if resp.FIFOCount > MaxFIFOCount {
		return nil, fmt.Errorf("FIFO count exceeds 31")
	}
	expectedValues := int(resp.FIFOCount)
	if len(data)-4 < expectedValues*2 {
		return nil, fmt.Errorf("FIFO values incomplete")
	}
	resp.FIFOValues = make([]uint16, expectedValues)
	for i := 0; i < expectedValues; i++ {
		resp.FIFOValues[i] = binary.BigEndian.Uint16(data[4+i*2 : 6+i*2])
	}
	return resp, nil
}

// MEIRequest represents a parsed FC 0x2B request.
type MEIRequest struct {
	MEIType uint8
	Data    []byte
}

// ParseMEIRequest parses FC 0x2B request data.
func ParseMEIRequest(data []byte) (*MEIRequest, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("MEI request too short: %d bytes", len(data))
	}
	return &MEIRequest{
		MEIType: data[0],
		Data:    data[1:],
	}, nil
}

// ExceptionResponse represents a parsed exception response.
type ExceptionResponse struct {
	FunctionCode  uint8 // original FC (with 0x80 mask removed)
	ExceptionCode uint8
}

// ParseExceptionResponse parses an exception response PDU.
func ParseExceptionResponse(pdu []byte) (*ExceptionResponse, error) {
	if len(pdu) < 2 {
		return nil, fmt.Errorf("exception response too short: %d bytes", len(pdu))
	}
	fc := pdu[0]
	if fc&ExceptionMask == 0 {
		return nil, fmt.Errorf("not an exception response: FC=0x%02X", fc)
	}
	return &ExceptionResponse{
		FunctionCode:  fc &^ ExceptionMask,
		ExceptionCode: pdu[1],
	}, nil
}

// FileRecordRequestItem represents one item in a FC 0x14 request.
type FileRecordRequestItem struct {
	ReferenceType uint8
	FileNumber    uint16
	RecordNumber  uint16
	RecordLength  uint16
}

// ParseReadFileRecordsRequest parses FC 0x14 request items.
func ParseReadFileRecordsRequest(data []byte) ([]FileRecordRequestItem, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("read file records request too short")
	}
	byteCount := int(data[0])
	if byteCount+1 > len(data) {
		return nil, fmt.Errorf("byte count exceeds available data")
	}
	if byteCount%7 != 0 {
		return nil, fmt.Errorf("byte count must be a multiple of 7")
	}
	itemCount := byteCount / 7
	items := make([]FileRecordRequestItem, itemCount)
	for i := 0; i < itemCount; i++ {
		offset := 1 + i*7
		items[i] = FileRecordRequestItem{
			ReferenceType: data[offset],
			FileNumber:    binary.BigEndian.Uint16(data[offset+1 : offset+3]),
			RecordNumber:  binary.BigEndian.Uint16(data[offset+3 : offset+5]),
			RecordLength:  binary.BigEndian.Uint16(data[offset+5 : offset+7]),
		}
	}
	return items, nil
}

// WriteFileRecordItem represents one item in a FC 0x15 request.
type WriteFileRecordItem struct {
	ReferenceType uint8
	FileNumber    uint16
	RecordNumber  uint16
	RecordLength  uint16
	RecordData    []byte
}

// ParseWriteFileRecordsRequest parses FC 0x15 request items.
// Each item: RefType(1)=0x06 + File(2) + Record(2) + RecLen(2) + Data(2*RL).
func ParseWriteFileRecordsRequest(data []byte) ([]WriteFileRecordItem, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("write file records request too short")
	}
	byteCount := int(data[0])
	if byteCount+1 > len(data) {
		return nil, fmt.Errorf("byte count exceeds available data")
	}
	items := []WriteFileRecordItem{}
	idx := 1
	for idx < 1+byteCount {
		if idx+7 > 1+byteCount {
			return nil, fmt.Errorf("item length mismatch")
		}
		item := WriteFileRecordItem{
			ReferenceType: data[idx],
			FileNumber:    binary.BigEndian.Uint16(data[idx+1 : idx+3]),
			RecordNumber:  binary.BigEndian.Uint16(data[idx+3 : idx+5]),
			RecordLength:  binary.BigEndian.Uint16(data[idx+5 : idx+7]),
		}
		dataLen := int(item.RecordLength) * 2
		if idx+7+dataLen > 1+byteCount {
			return nil, fmt.Errorf("item length mismatch")
		}
		item.RecordData = data[idx+7 : idx+7+dataLen]
		items = append(items, item)
		idx += 7 + dataLen
	}
	return items, nil
}

// FileRecordResponseItem represents one item in a FC 0x14 response.
type FileRecordResponseItem struct {
	FileResponseLength uint8
	ReferenceType      uint8
	RecordData         []byte
}

// ParseReadFileRecordsResponse parses FC 0x14 response items.
func ParseReadFileRecordsResponse(data []byte) ([]FileRecordResponseItem, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("read file records response too short")
	}
	byteCount := int(data[0])
	if byteCount+1 > len(data) {
		return nil, fmt.Errorf("byte count exceeds available data")
	}
	items := []FileRecordResponseItem{}
	idx := 1
	for idx < 1+byteCount {
		if idx+2 > 1+byteCount {
			return nil, fmt.Errorf("item incomplete")
		}
		item := FileRecordResponseItem{
			FileResponseLength: data[idx],
			ReferenceType:      data[idx+1],
		}
		recordDataLen := int(item.FileResponseLength) - 1
		if recordDataLen < 0 {
			return nil, fmt.Errorf("invalid file response length")
		}
		if idx+2+recordDataLen > 1+byteCount {
			return nil, fmt.Errorf("record data incomplete")
		}
		item.RecordData = data[idx+2 : idx+2+recordDataLen]
		items = append(items, item)
		idx += 2 + recordDataLen
	}
	return items, nil
}

// ReadDeviceIDResponse represents a parsed FC 0x2B Read Device ID response.
type ReadDeviceIDResponse struct {
	MEIType          uint8
	ReadDeviceIDCode uint8
	ConformityLevel  uint8
	MoreFollows      uint8
	NextObjectID     uint8
	NumberOfObjects  uint8
	Objects          []MEIObject
}

// ParseReadDeviceIDResponse parses FC 0x2B Read Device ID response data.
func ParseReadDeviceIDResponse(data []byte) (*ReadDeviceIDResponse, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("read device ID response too short: %d bytes", len(data))
	}
	resp := &ReadDeviceIDResponse{
		MEIType:          data[0],
		ReadDeviceIDCode: data[1],
		ConformityLevel:  data[2],
		MoreFollows:      data[3],
		NextObjectID:     data[4],
		NumberOfObjects:  data[5],
	}
	idx := 6
	for i := 0; i < int(resp.NumberOfObjects); i++ {
		if idx+2 > len(data) {
			return nil, fmt.Errorf("object %d incomplete", i)
		}
		obj := MEIObject{
			ID: data[idx],
		}
		objLen := int(data[idx+1])
		if idx+2+objLen > len(data) {
			return nil, fmt.Errorf("object %d value incomplete", i)
		}
		obj.Value = data[idx+2 : idx+2+objLen]
		resp.Objects = append(resp.Objects, obj)
		idx += 2 + objLen
	}
	return resp, nil
}

// CommEventCounterResponse represents a parsed FC 0x0B response.
type CommEventCounterResponse struct {
	Status    uint16
	EventCount uint16
}

// ParseCommEventCounterResponse parses FC 0x0B response data.
func ParseCommEventCounterResponse(data []byte) (*CommEventCounterResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("comm event counter response too short: %d bytes", len(data))
	}
	return &CommEventCounterResponse{
		Status:    binary.BigEndian.Uint16(data[0:2]),
		EventCount: binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// CommEventLogResponse represents a parsed FC 0x0C response.
type CommEventLogResponse struct {
	ByteCount    uint8
	Status       uint16
	EventCount   uint16
	MessageCount uint16
	Events       []byte
}

// ParseCommEventLogResponse parses FC 0x0C response data.
func ParseCommEventLogResponse(data []byte) (*CommEventLogResponse, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("comm event log response too short: %d bytes", len(data))
	}
	resp := &CommEventLogResponse{
		ByteCount:    data[0],
		Status:       binary.BigEndian.Uint16(data[1:3]),
		EventCount:   binary.BigEndian.Uint16(data[3:5]),
		MessageCount: binary.BigEndian.Uint16(data[5:7]),
	}
	// §3.3.8: Byte Count = 6 + N (Status + EventCount + MessageCount + Events).
	if resp.ByteCount < 6 {
		return nil, fmt.Errorf("comm event log byte count %d too small (min 6)", resp.ByteCount)
	}
	eventsLen := int(resp.ByteCount) - 6
	if 7+eventsLen > len(data) {
		return nil, fmt.Errorf("comm event log events truncated: byte count %d needs %d bytes, have %d",
			resp.ByteCount, 7+eventsLen, len(data))
	}
	if eventsLen > 0 {
		resp.Events = data[7 : 7+eventsLen]
	}
	return resp, nil
}
