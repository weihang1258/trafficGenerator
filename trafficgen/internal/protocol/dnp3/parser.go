package dnp3

import (
	"encoding/binary"
	"fmt"
)

// ParseLinkFrame validates frame boundaries and all CRCs, then removes block CRCs.
func ParseLinkFrame(frame []byte) (*LinkFrame, error) {
	if len(frame) < LinkHeaderLen { return nil, fmt.Errorf("dnp3: frame too short: %d", len(frame)) }
	if frame[0] != Start1 || frame[1] != Start2 { return nil, fmt.Errorf("dnp3: invalid start bytes") }
	if got, want := binary.LittleEndian.Uint16(frame[8:10]), CRC16(frame[:8]); got != want {
		return nil, fmt.Errorf("dnp3: header CRC mismatch: got 0x%04X want 0x%04X", got, want)
	}
	length := int(frame[2])
	if len(frame) != LinkHeaderLen+length { return nil, fmt.Errorf("dnp3: length mismatch: field %d actual %d", length, len(frame)-LinkHeaderLen) }
	wire := frame[10:]
	data := make([]byte, 0, length)
	for len(wire) > 0 {
		chunkLen := 16
		if len(wire) < 18 { chunkLen = len(wire)-2 }
		if chunkLen < 0 { return nil, fmt.Errorf("dnp3: truncated data CRC") }
		chunk := wire[:chunkLen]
		got := binary.LittleEndian.Uint16(wire[chunkLen:chunkLen+2])
		if want := CRC16(chunk); got != want { return nil, fmt.Errorf("dnp3: data CRC mismatch: got 0x%04X want 0x%04X", got, want) }
		data = append(data, chunk...)
		wire = wire[chunkLen+2:]
	}
	return &LinkFrame{Length: frame[2], Control: frame[3], DstAddr: binary.LittleEndian.Uint16(frame[4:6]), SrcAddr: binary.LittleEndian.Uint16(frame[6:8]), Data: data}, nil
}

// ParseAppFrame parses the application header and object header boundaries.
func ParseAppFrame(data []byte) (*AppFrame, error) {
	if len(data) < 2 { return nil, fmt.Errorf("dnp3: application frame too short") }
	a := &AppFrame{Control: data[0], FunctionCode: data[1]}
	off := 2
	if a.FunctionCode == AppRespond || a.FunctionCode == AppUnsolicitedRespond {
		if len(data) < 4 { return nil, fmt.Errorf("dnp3: response missing IIN") }
		a.HasIIN = true; a.IIN = binary.BigEndian.Uint16(data[2:4]); off = 4
	}
	for off < len(data) {
		obj, used, err := parseObject(data[off:])
		if err != nil { return nil, err }
		a.Objects = append(a.Objects, obj)
		off += used
		// Point widths depend on function and variation. Preserve the rest on
		// the final object rather than guessing object boundaries incorrectly.
		if off < len(data) { a.Objects[len(a.Objects)-1].Data = append([]byte(nil), data[off:]...); break }
	}
	return a, nil
}

func parseObject(data []byte) (ParsedObject, int, error) {
	if len(data) < 3 { return ParsedObject{}, 0, fmt.Errorf("dnp3: truncated object header") }
	o := ParsedObject{ObjectType: data[0], Variation: data[1], Qualifier: data[2]}
	off := 3
	switch o.Qualifier {
	case 0x00:
		if len(data) < off+2 { return o, 0, fmt.Errorf("dnp3: truncated 8-bit range") }
		o.Start, o.Stop, off = uint16(data[off]), uint16(data[off+1]), off+2
	case 0x01:
		if len(data) < off+4 { return o, 0, fmt.Errorf("dnp3: truncated 16-bit range") }
		o.Start, o.Stop = binary.LittleEndian.Uint16(data[off:]), binary.LittleEndian.Uint16(data[off+2:]); off += 4
	case 0x06:
	case 0x07, 0x17:
		if len(data) < off+1 { return o, 0, fmt.Errorf("dnp3: truncated 8-bit count") }
		o.Count, off = uint16(data[off]), off+1
	case 0x08, 0x28:
		if len(data) < off+2 { return o, 0, fmt.Errorf("dnp3: truncated 16-bit count") }
		o.Count, off = binary.LittleEndian.Uint16(data[off:]), off+2
	default:
		return o, 0, fmt.Errorf("dnp3: unsupported qualifier 0x%02X", o.Qualifier)
	}
	return o, off, nil
}
