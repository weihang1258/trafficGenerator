package enip

import (
	"encoding/binary"
	"fmt"
)

// ParseCPFPayload parses a CPF payload starting at the given offset.
// Returns the items and the total bytes consumed.
func ParseCPFPayload(data []byte) ([]Item, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("CPF payload too short for ItemCount")
	}
	itemCount := binary.LittleEndian.Uint16(data[0:2])
	offset := 2

	items := make([]Item, 0, itemCount)
	for i := uint16(0); i < itemCount; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("CPF item %d: not enough data for header", i)
		}
		typeID := binary.LittleEndian.Uint16(data[offset : offset+2])
		length := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("CPF item %d: data length %d exceeds payload", i, length)
		}
		itemData := make([]byte, length)
		copy(itemData, data[offset:offset+int(length)])
		offset += int(length)
		items = append(items, Item{
			TypeID: typeID,
			Length: length,
			Data:   itemData,
		})
	}
	return items, nil
}

// ParseCIPRequest parses a CIP request from data.
// Returns service, pathSize, path, and remaining data.
func ParseCIPRequest(data []byte) (service uint8, pathSize uint8, path []byte, body []byte, err error) {
	if len(data) < 2 {
		return 0, 0, nil, nil, fmt.Errorf("CIP request too short")
	}
	service = data[0]
	pathSize = data[1]
	pathLen := int(pathSize) * 2
	if len(data) < 2+pathLen {
		return 0, 0, nil, nil, fmt.Errorf("CIP request path exceeds data")
	}
	path = make([]byte, pathLen)
	copy(path, data[2:2+pathLen])
	body = make([]byte, len(data)-2-pathLen)
	copy(body, data[2+pathLen:])
	return
}

// ParseForwardOpenBody parses a Forward_Open request body.
func ParseForwardOpenBody(data []byte) (map[string]interface{}, error) {
	if len(data) < 35 {
		return nil, fmt.Errorf("Forward_Open body requires at least 35 bytes, got %d", len(data))
	}
	result := make(map[string]interface{})
	result["priority_time_tick"] = data[0]
	result["timeout_ticks"] = data[1]
	result["o2t_connection_id"] = binary.LittleEndian.Uint32(data[2:6])
	result["t2o_connection_id"] = binary.LittleEndian.Uint32(data[6:10])
	result["connection_serial_number"] = binary.LittleEndian.Uint16(data[10:12])
	result["originator_vendor_id"] = binary.LittleEndian.Uint16(data[12:14])
	result["originator_serial_number"] = binary.LittleEndian.Uint32(data[14:18])
	result["connection_timeout_multiplier"] = data[18]
	result["reserved"] = data[19:22]
	result["o2t_rpi"] = binary.LittleEndian.Uint32(data[22:26])
	result["o2t_connection_parameters"] = binary.LittleEndian.Uint16(data[26:28])
	result["t2o_rpi"] = binary.LittleEndian.Uint32(data[28:32])
	result["t2o_connection_parameters"] = binary.LittleEndian.Uint16(data[32:34])
	result["transport_class_trigger"] = data[34]
	if len(data) > 35 {
		connPathSize := int(data[35])
		result["connection_path_size"] = connPathSize
		if len(data) >= 36+connPathSize*2 {
			result["connection_path"] = data[36 : 36+connPathSize*2]
		}
	}
	return result, nil
}

// ParseForwardCloseBody parses a Forward_Close request body.
func ParseForwardCloseBody(data []byte) (map[string]interface{}, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("Forward_Close body requires at least 10 bytes, got %d", len(data))
	}
	result := make(map[string]interface{})
	result["priority_time_tick"] = data[0]
	result["timeout_ticks"] = data[1]
	result["connection_serial_number"] = binary.LittleEndian.Uint16(data[2:4])
	result["originator_vendor_id"] = binary.LittleEndian.Uint16(data[4:6])
	result["originator_serial_number"] = binary.LittleEndian.Uint32(data[6:10])
	if len(data) > 10 {
		connPathSize := int(data[10])
		result["connection_path_size"] = connPathSize
		if len(data) >= 11+connPathSize*2 {
			result["connection_path"] = data[11 : 11+connPathSize*2]
		}
	}
	return result, nil
}

// ParseCIPResponse parses a CIP Message Router Response.
func ParseCIPResponse(data []byte) (replyService, generalStatus uint8, additionalStatus []uint16, responseData []byte, err error) {
	if len(data) < 4 {
		return 0, 0, nil, nil, fmt.Errorf("CIP response requires at least 4 bytes")
	}
	replyService = data[0]
	// data[1] = reserved
	generalStatus = data[2]
	addStatusSize := data[3]
	if len(data) < 4+int(addStatusSize)*2 {
		return 0, 0, nil, nil, fmt.Errorf("CIP response additional status exceeds data")
	}
	additionalStatus = make([]uint16, addStatusSize)
	for i := uint8(0); i < addStatusSize; i++ {
		additionalStatus[i] = binary.LittleEndian.Uint16(data[4+i*2 : 6+i*2])
	}
	responseData = make([]byte, len(data)-4-int(addStatusSize)*2)
	copy(responseData, data[4+int(addStatusSize)*2:])
	return
}

// ParseListIdentityResponseItem parses a ListIdentity response item.
// Per spec §3.11, the item data starts with EncapProtoVer(2) + ProtocolVersion(2)
// + SocketAddress(16), followed by Vendor ID(2) + Device Type(2) + Product Code(2)
// + Revision(2) + Status(2) + SerialNumber(4) + ProductName(SHORT_STRING) + State(1).
func ParseListIdentityResponseItem(data []byte) (map[string]interface{}, error) {
	// Minimum size: 2+2+16 + 2+2+2+2+2+4+1+0+1 = 34 bytes (empty product name)
	if len(data) < 34 {
		return nil, fmt.Errorf("ListIdentity response item too short, got %d bytes, need >= 34", len(data))
	}
	result := make(map[string]interface{})
	// Header: EncapProtoVer(2) + ProtocolVersion(2) + SocketAddress(16) = 20 bytes
	result["encap_protocol_version"] = binary.LittleEndian.Uint16(data[0:2])
	result["protocol_version"] = binary.LittleEndian.Uint16(data[2:4])
	// SocketAddress at offset 4: SinFamily(2) + SinPort(2) + SinAddr(4) + SinZero(8)
	result["sin_family"] = binary.LittleEndian.Uint16(data[4:6])
	result["sin_port"] = binary.LittleEndian.Uint16(data[6:8])
	sinAddr := make([]byte, 4)
	copy(sinAddr, data[8:12])
	result["sin_addr"] = sinAddr
	// Identity fields starting at offset 20
	const identityOffset = 20
	result["vendor_id"] = binary.LittleEndian.Uint16(data[identityOffset+0 : identityOffset+2])
	result["device_type"] = binary.LittleEndian.Uint16(data[identityOffset+2 : identityOffset+4])
	result["product_code"] = binary.LittleEndian.Uint16(data[identityOffset+4 : identityOffset+6])
	result["revision_major"] = data[identityOffset+6]
	result["revision_minor"] = data[identityOffset+7]
	result["device_status"] = binary.LittleEndian.Uint16(data[identityOffset+8 : identityOffset+10])
	result["serial_number"] = binary.LittleEndian.Uint32(data[identityOffset+10 : identityOffset+14])
	nameLen := int(data[identityOffset+14])
	if len(data) < identityOffset+15+nameLen+1 {
		return nil, fmt.Errorf("ListIdentity response item product name truncated")
	}
	result["product_name"] = string(data[identityOffset+15 : identityOffset+15+nameLen])
	result["device_state"] = data[identityOffset+15+nameLen]
	return result, nil
}
