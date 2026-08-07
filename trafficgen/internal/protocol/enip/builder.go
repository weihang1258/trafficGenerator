package enip

import (
	"encoding/binary"
	"fmt"
)

// EncodeCIPPath encodes an EPATH for CIP messages. classID/instanceID/attrID
// are encoded with the smallest segment format that fits.
// Optional connPointIDs are appended as Connection Point segments.
func EncodeCIPPath(classID uint16, instanceID uint32, attrID uint16, connPointIDs ...uint16) []byte {
	var path []byte
	// Class segment
	if classID <= 0xFF {
		path = append(path, epathSegClass8bit, byte(classID))
	} else {
		path = append(path, epathSegClass16bit)
		path = append(path, u16LE(classID)...)
	}
	// Instance segment
	if instanceID <= 0xFF {
		path = append(path, epathSegInstance8bit, byte(instanceID))
	} else if instanceID <= 0xFFFF {
		path = append(path, epathSegInstance16bit)
		path = append(path, u16LE(uint16(instanceID))...)
	} else {
		path = append(path, epathSegInstance32bit)
		path = append(path, u32LE(instanceID)...)
	}
	// Attribute segment (skip if attrID == 0)
	if attrID > 0 {
		if attrID <= 0xFF {
			path = append(path, epathSegAttribute8bit, byte(attrID))
		} else {
			path = append(path, epathSegAttribute16bit)
			path = append(path, u16LE(attrID)...)
		}
	}
	// Connection Point segments
	for _, cp := range connPointIDs {
		if cp <= 0xFF {
			path = append(path, epathSegConnectionPoint8bit, byte(cp))
		} else {
			path = append(path, epathSegConnectionPoint16bit)
			path = append(path, u16LE(cp)...)
		}
	}
	return path
}

// EncodePaddedCIPPath encodes an EPATH and pads to even byte count.
// Returns the padded path and the RequestPathSize in words.
func EncodePaddedCIPPath(classID uint16, instanceID uint32, attrID uint16, connPointIDs ...uint16) (path []byte, pathSize uint8) {
	path = EncodeCIPPath(classID, instanceID, attrID, connPointIDs...)
	// Pad to even byte count if necessary
	if len(path)%2 != 0 {
		path = append(path, 0x00)
	}
	pathSize = uint8(len(path) / 2)
	return
}

// BuildENIPHeader builds the 24-byte ENIP encapsulation header.
func BuildENIPHeader(command, length uint16, sessionHandle, status uint32,
	senderContext uint64, options uint32) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint16(buf[0:2], command)
	binary.LittleEndian.PutUint16(buf[2:4], length)
	binary.LittleEndian.PutUint32(buf[4:8], sessionHandle)
	binary.LittleEndian.PutUint32(buf[8:12], status)
	binary.LittleEndian.PutUint64(buf[12:20], senderContext)
	binary.LittleEndian.PutUint32(buf[20:24], options)
	return buf
}

// BuildRegisterSessionPayload builds the 4-byte RegisterSession payload.
func BuildRegisterSessionPayload(protocolVersion, optionFlag uint16) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint16(buf[0:2], protocolVersion)
	binary.LittleEndian.PutUint16(buf[2:4], optionFlag)
	return buf
}

// BuildCPFItem builds a CPF item with TypeID, Length, and Data.
func BuildCPFItem(typeID uint16, data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint16(buf[0:2], typeID)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(data)))
	copy(buf[4:], data)
	return buf
}

// BuildCPFPayload builds the CPF payload (ItemCount + items).
func BuildCPFPayload(items []Item) []byte {
	var body []byte
	itemCount := uint16(len(items))
	body = append(body, u16LE(itemCount)...)
	for _, item := range items {
		body = append(body, BuildCPFItem(item.TypeID, item.Data)...)
	}
	return body
}

// BuildSendRRDataPayload builds SendRRData/SendUnitData payload:
// InterfaceHandle(4) + Timeout(2) + CPF.
func BuildSendRRDataPayload(interfaceHandle uint32, timeout uint16, items []Item) []byte {
	var body []byte
	body = append(body, u32LE(interfaceHandle)...)
	body = append(body, u16LE(timeout)...)
	body = append(body, BuildCPFPayload(items)...)
	return body
}

// BuildCIPRequest builds a CIP request: Service + RequestPathSize + PaddedPath + Data.
func BuildCIPRequest(service uint8, classID uint16, instanceID uint32, attrID uint16, data []byte, connPointIDs ...uint16) []byte {
	path, pathSize := EncodePaddedCIPPath(classID, instanceID, attrID, connPointIDs...)
	buf := make([]byte, 0, 2+len(path)+len(data))
	buf = append(buf, service)
	buf = append(buf, pathSize)
	buf = append(buf, path...)
	buf = append(buf, data...)
	return buf
}

// BuildForwardOpenBody builds the Forward_Open (0x54) request body.
func BuildForwardOpenBody(priorityTimeTick, timeoutTicks uint8,
	o2tConnID, t2oConnID uint32,
	connSerialNum, origVendorID uint16, origSerialNum uint32,
	connTimeoutMult uint8,
	o2tRPI, t2oRPI uint32,
	o2tConnParams, t2oConnParams uint16,
	transportClassTrigger uint8,
	connPath []byte) []byte {
	buf := make([]byte, 0, 35+len(connPath))
	buf = append(buf, priorityTimeTick)
	buf = append(buf, timeoutTicks)
	buf = append(buf, u32LE(o2tConnID)...)
	buf = append(buf, u32LE(t2oConnID)...)
	buf = append(buf, u16LE(connSerialNum)...)
	buf = append(buf, u16LE(origVendorID)...)
	buf = append(buf, u32LE(origSerialNum)...)
	buf = append(buf, connTimeoutMult)
	buf = append(buf, 0x00, 0x00, 0x00) // 3-byte reserved
	buf = append(buf, u32LE(o2tRPI)...)
	buf = append(buf, u16LE(o2tConnParams)...)
	buf = append(buf, u32LE(t2oRPI)...)
	buf = append(buf, u16LE(t2oConnParams)...)
	buf = append(buf, transportClassTrigger)
	// Connection Path
	pathSize := uint8(len(connPath) / 2)
	buf = append(buf, pathSize)
	buf = append(buf, connPath...)
	return buf
}

// BuildLargeForwardOpenBody builds the LargeForward_Open (0x5B) request body.
func BuildLargeForwardOpenBody(priorityTimeTick, timeoutTicks uint8,
	o2tConnID, t2oConnID uint32,
	connSerialNum, origVendorID uint16, origSerialNum uint32,
	connTimeoutMult uint8,
	o2tRPI, t2oRPI uint32,
	o2tConnParams, t2oConnParams uint32,
	transportClassTrigger uint8,
	connPath []byte) []byte {
	buf := make([]byte, 0, 39+len(connPath))
	buf = append(buf, priorityTimeTick)
	buf = append(buf, timeoutTicks)
	buf = append(buf, u32LE(o2tConnID)...)
	buf = append(buf, u32LE(t2oConnID)...)
	buf = append(buf, u16LE(connSerialNum)...)
	buf = append(buf, u16LE(origVendorID)...)
	buf = append(buf, u32LE(origSerialNum)...)
	buf = append(buf, connTimeoutMult)
	buf = append(buf, 0x00, 0x00, 0x00) // 3-byte reserved
	buf = append(buf, u32LE(o2tRPI)...)
	buf = append(buf, u32LE(o2tConnParams)...)
	buf = append(buf, u32LE(t2oRPI)...)
	buf = append(buf, u32LE(t2oConnParams)...)
	buf = append(buf, transportClassTrigger)
	pathSize := uint8(len(connPath) / 2)
	buf = append(buf, pathSize)
	buf = append(buf, connPath...)
	return buf
}

// BuildForwardCloseBody builds the Forward_Close (0x4E) request body.
func BuildForwardCloseBody(priorityTimeTick, timeoutTicks uint8,
	connSerialNum, origVendorID uint16, origSerialNum uint32,
	connPath []byte) []byte {
	buf := make([]byte, 0, 10+len(connPath))
	buf = append(buf, priorityTimeTick)
	buf = append(buf, timeoutTicks)
	buf = append(buf, u16LE(connSerialNum)...)
	buf = append(buf, u16LE(origVendorID)...)
	buf = append(buf, u32LE(origSerialNum)...)
	pathSize := uint8(len(connPath) / 2)
	buf = append(buf, pathSize)
	buf = append(buf, connPath...)
	return buf
}

// BuildMultipleServicePacket builds the Multiple_Service_Packet (0x0A) body.
// Per spec §3.9, offset values are relative to the OffsetCount field start.
// Offset[i] = 2 (OffsetCount itself) + 2*N (offsets array) + sum(len(Sub-requests[0..i-1]))
func BuildMultipleServicePacket(classID uint16, instanceID uint32, subRequests []SubRequest) []byte {
	// Encode the RequestPath (points to Message Router or other object)
	path, pathSize := EncodePaddedCIPPath(classID, instanceID, 0)

	offsetCount := uint16(len(subRequests))
	buf := make([]byte, 0, 2+len(path)+2+int(offsetCount)*2)
	buf = append(buf, CIPMultipleServicePacket) // Service
	buf = append(buf, pathSize)
	buf = append(buf, path...)
	buf = append(buf, u16LE(offsetCount)...)

	// Write offsets (relative to OffsetCount field start)
	offset := uint16(2 + int(offsetCount)*2) // After OffsetCount(2) + offsets array
	for _, sr := range subRequests {
		buf = append(buf, u16LE(offset)...)
		subPath, _ := EncodePaddedCIPPath(sr.ClassID, sr.InstanceID, sr.AttributeID)
		offset += uint16(2 + len(subPath) + len(sr.Data))
	}

	// Append sub-request data
	for _, sr := range subRequests {
		subPath, _ := EncodePaddedCIPPath(sr.ClassID, sr.InstanceID, sr.AttributeID)
		buf = append(buf, sr.Service)
		buf = append(buf, uint8(len(subPath)/2))
		buf = append(buf, subPath...)
		buf = append(buf, sr.Data...)
	}

	return buf
}

// BuildGetAttributeSingle builds a Get_Attribute_Single (0x0E) request.
func BuildGetAttributeSingle(classID uint16, instanceID uint32, attrID uint16) []byte {
	return BuildCIPRequest(CIPGetAttributeSingle, classID, instanceID, attrID, nil)
}

// BuildSetAttributeSingle builds a Set_Attribute_Single (0x10) request with data.
func BuildSetAttributeSingle(classID uint16, instanceID uint32, attrID uint16, data []byte) []byte {
	return BuildCIPRequest(CIPSetAttributeSingle, classID, instanceID, attrID, data)
}

// BuildListIdentityResponseItem builds a ListIdentity response item payload.
// Per spec §3.11, the full item data is:
//   EncapsulationProtocolVersion(2) + ProtocolVersion(2) + SocketAddress(16) +
//   Vendor ID(2) + Device Type(2) + Product Code(2) + Revision(2) +
//   Status(2) + Serial Number(4) + Product Name(SHORT_STRING) + State(1)
func BuildListIdentityResponseItem(vendorID, deviceType, productCode uint16,
	majorRev, minorRev uint8, productName string,
	serialNumber uint32, deviceStatus uint16, deviceState uint8) []byte {
	// Encode product name as SHORT_STRING (1-byte length + ASCII)
	nameBytes := []byte(productName)
	if len(nameBytes) > 255 {
		nameBytes = nameBytes[:255]
	}

	var buf []byte
	// EncapProtoVer=1 (2B LE), ProtocolVersion=1 (2B LE)
	buf = append(buf, u16LE(1)...)
	buf = append(buf, u16LE(1)...)
	// SocketAddress: SinFamily(2) + SinPort(2) + SinAddr(4) + SinZero(8) = 16B
	// AF_INET=2, port=44818 (LE), IP=0.0.0.0 (placeholder), SinZero=0
	buf = append(buf, u16LE(2)...)               // SinFamily
	buf = append(buf, u16LE(44818)...)           // SinPort (44818 default)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)    // SinAddr
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)    // SinZero (8B)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// Identity fields
	buf = append(buf, u16LE(vendorID)...)
	buf = append(buf, u16LE(deviceType)...)
	buf = append(buf, u16LE(productCode)...)
	buf = append(buf, majorRev, minorRev) // Revision: 2 bytes total
	buf = append(buf, u16LE(deviceStatus)...)
	buf = append(buf, u32LE(serialNumber)...)
	// ProductName as SHORT_STRING
	buf = append(buf, byte(len(nameBytes)))
	buf = append(buf, nameBytes...)
	// Device state (1 byte, per ListIdentity spec)
	buf = append(buf, deviceState)
	return buf
}

// BuildCIPResponse builds a CIP Message Router Response.
func BuildCIPResponse(replyService, generalStatus uint8, additionalStatus []uint16, data []byte) []byte {
	addStatusSize := uint8(len(additionalStatus))
	buf := make([]byte, 0, 4+len(additionalStatus)*2+len(data))
	buf = append(buf, replyService)
	buf = append(buf, 0x00) // Reserved
	buf = append(buf, generalStatus)
	buf = append(buf, addStatusSize)
	for _, as := range additionalStatus {
		buf = append(buf, u16LE(as)...)
	}
	buf = append(buf, data...)
	return buf
}

// u16LE returns a 2-byte little-endian representation.
func u16LE(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// u32LE returns a 4-byte little-endian representation.
func u32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// ParseENIPHeader parses a 24-byte ENIP header.
func ParseENIPHeader(data []byte) (command, length uint16, sessionHandle, status uint32, senderContext uint64, options uint32, err error) {
	if len(data) < 24 {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("enip header requires 24 bytes, got %d", len(data))
	}
	command = binary.LittleEndian.Uint16(data[0:2])
	length = binary.LittleEndian.Uint16(data[2:4])
	sessionHandle = binary.LittleEndian.Uint32(data[4:8])
	status = binary.LittleEndian.Uint32(data[8:12])
	senderContext = binary.LittleEndian.Uint64(data[12:20])
	options = binary.LittleEndian.Uint32(data[20:24])
	return
}

// BuildSockaddrInfoItem builds a Sockaddr Info item (16 bytes).
func BuildSockaddrInfoItem(port uint16, ip []byte) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 2) // AF_INET
	binary.LittleEndian.PutUint16(buf[2:4], port)
	if len(ip) >= 4 {
		copy(buf[4:8], ip[:4])
	}
	// SinZero (8 bytes) already zero-initialized
	return buf
}

// BuildConnectedDataItem builds a Connected Data item with sequence counter + data.
// Per spec §2.4.1, the Connected Data Item (0x00B1) carries SequenceCounter(2B LE)
// followed by payload data. The ConnectionID belongs in the Connection Address Item (0x00A1).
func BuildConnectedDataItem(seqCounter uint16, data []byte) []byte {
	itemData := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(itemData[0:2], seqCounter)
	copy(itemData[2:], data)
	return itemData
}
