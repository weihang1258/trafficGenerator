package someip

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Message Type values (AUTOSAR SOME/IP, design §2.3/§2.4).
const (
	MTRequest        = 0x00
	MTRequestNoRet   = 0x01
	MTNotification   = 0x02
	MTResponse       = 0x80
	MTError          = 0x81
	MTTPRequest      = 0x20
	MTTPRequestNoRet = 0x21
	MTTPNotification = 0x22
	MTTPResponse     = 0xA0
	MTTPError        = 0xA1
)

// SD entry types (§3.4.1).
const (
	SDEntryFind      = 0x00
	SDEntryOffer     = 0x01
	SDEntrySubscribe = 0x06
	SDEntrySubAck    = 0x07
)

// SD option types (§3.4.2).
const (
	SDOptionIPv4Endpoint  = 0x01
	SDOptionIPv4Multicast = 0x02
	SDOptionIPv6Endpoint  = 0x06
)

// SD fixed outer Message ID.
const (
	SDServiceID = 0xFFFF
	SDMethodID  = 0x8100
)

// msgTypeFromString maps a config message_type string/number to wire byte.
func msgTypeFromString(v interface{}) (byte, bool) {
	switch s := v.(type) {
	case string:
		switch s {
		case "", "request":
			return MTRequest, true
		case "request_no_return":
			return MTRequestNoRet, true
		case "event", "notification":
			return MTNotification, true
		case "response":
			return MTResponse, true
		case "error":
			return MTError, true
		}
	case float64:
		b := byte(int(s))
		switch b {
		case MTRequest, MTRequestNoRet, MTNotification, MTResponse, MTError,
			MTTPRequest, MTTPRequestNoRet, MTTPNotification, MTTPResponse, MTTPError:
			return b, true
		}
	}
	return 0, false
}

// msgTypeForTP returns the TP variant of a base message type.
func msgTypeForTP(base byte) byte {
	switch base {
	case MTRequest:
		return MTTPRequest
	case MTRequestNoRet:
		return MTTPRequestNoRet
	case MTNotification:
		return MTTPNotification
	case MTResponse:
		return MTTPResponse
	case MTError:
		return MTTPError
	}
	return base
}

// sdTypeFromString maps a config sd.type string to entry type byte.
func sdTypeFromString(s string) (byte, bool) {
	switch s {
	case "find":
		return SDEntryFind, true
	case "offer":
		return SDEntryOffer, true
	case "subscribe":
		return SDEntrySubscribe, true
	case "subscribe_ack":
		return SDEntrySubAck, true
	}
	return 0, false
}

// buildHeader builds the 16-byte SOME/IP message header (big endian, §3.1).
func buildHeader(serviceID, methodID, clientID, sessionID uint16, protocolVer, interfaceVer, msgType, retCode byte, payloadLen int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b[0:2], serviceID)
	binary.BigEndian.PutUint16(b[2:4], methodID)
	binary.BigEndian.PutUint32(b[4:8], uint32(8+payloadLen))
	binary.BigEndian.PutUint16(b[8:10], clientID)
	binary.BigEndian.PutUint16(b[10:12], sessionID)
	b[12] = protocolVer
	b[13] = interfaceVer
	b[14] = msgType
	b[15] = retCode
	return b
}

// buildMessage assembles a complete SOME/IP message: 16B header + payload.
func buildMessage(serviceID, methodID, clientID, sessionID uint16, protocolVer, interfaceVer, msgType, retCode byte, payload []byte) []byte {
	h := buildHeader(serviceID, methodID, clientID, sessionID, protocolVer, interfaceVer, msgType, retCode, len(payload))
	return append(h, payload...)
}

// SDOption carries a single SD Option entry for building.
type SDOption struct {
	Type  uint8
	IP    string
	Port  uint16
	Proto string
}

// buildSDMessage builds a complete SD datagram: 16B SOME/IP header (SD outer
// ID) + 8B SD header + 16B entry + options. sdType is the entry type byte.
// options are the optional Option entries.
func buildSDMessage(sdType byte, serviceID, instanceID uint16, majorVer uint8, minorVer uint32, ttl uint32, flags byte, eventgroupID uint16, counter uint8, options []SDOption, clientID, sessionID uint16) ([]byte, error) {
	// SD header: Flags(1) + Reserved(3) + Entries Length(4)
	sdHdr := make([]byte, 8)
	sdHdr[0] = flags

	// Entry (16 bytes, §3.4.1)
	entry := make([]byte, 16)
	entry[0] = sdType
	binary.BigEndian.PutUint16(entry[3:5], serviceID)
	binary.BigEndian.PutUint16(entry[5:7], instanceID)
	entry[7] = majorVer
	entry[8] = byte(ttl >> 16)
	entry[9] = byte(ttl >> 8)
	entry[10] = byte(ttl)
	binary.BigEndian.PutUint32(entry[11:15], minorVer)

	// Subscribe/SubscribeAck variants: EventgroupID at offset 13-14, Counter at 15
	if sdType == SDEntrySubscribe || sdType == SDEntrySubAck {
		binary.BigEndian.PutUint16(entry[13:15], eventgroupID)
		entry[15] = counter & 0x0F
	}

	entriesLen := 16
	binary.BigEndian.PutUint32(sdHdr[4:8], uint32(entriesLen))

	// Options
	var optBytes []byte
	for _, o := range options {
		ob, err := buildOptionBytes(o)
		if err != nil {
			return nil, err
		}
		optBytes = append(optBytes, ob...)
	}
	// Set NumOpts1 for the entry
	if len(options) > 0 {
		if len(options) > 15 {
			return nil, fmt.Errorf("someip: too many sd options (%d > 15)", len(options))
		}
		entry[1] = byte(len(options) & 0x0F)
	}

	payload := append(sdHdr, entry...)
	payload = append(payload, optBytes...)
	msg := buildHeader(SDServiceID, SDMethodID, clientID, sessionID, 1, 1, MTNotification, 0, len(payload))
	return append(msg, payload...), nil
}

func buildOptionBytes(o SDOption) ([]byte, error) {
	switch o.Type {
	case SDOptionIPv4Endpoint, SDOptionIPv4Multicast:
		ip := net.ParseIP(o.IP).To4()
		if ip == nil {
			return nil, fmt.Errorf("someip: invalid IPv4 option address %q", o.IP)
		}
		// Type(1) + Length(2) + Reserved(1) + addr(4) + Reserved(1) + proto(1) + port(2) = 12B
		b := make([]byte, 12)
		b[0] = o.Type
		binary.BigEndian.PutUint16(b[1:3], 9)
		copy(b[4:8], ip)
		b[9] = protoToByte(o.Proto)
		binary.BigEndian.PutUint16(b[10:12], o.Port)
		return b, nil
	case SDOptionIPv6Endpoint:
		ip := net.ParseIP(o.IP)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("someip: invalid IPv6 option address %q", o.IP)
		}
		// Type(1)+Length(2)+Reserved(1)+addr(16)+Reserved(1)+proto(1)+port(2)=24B
		b := make([]byte, 24)
		b[0] = o.Type
		binary.BigEndian.PutUint16(b[1:3], 21)
		copy(b[4:20], ip)
		b[21] = protoToByte(o.Proto)
		binary.BigEndian.PutUint16(b[22:24], o.Port)
		return b, nil
	default:
		return nil, fmt.Errorf("someip: unsupported sd option type %d", o.Type)
	}
}

func protoToByte(p string) byte {
	if p == "tcp" {
		return 0x06
	}
	return 0x11
}

// buildTPHeader builds the 8-byte TP header: OfferedLength(4) + SegmentID(1) + more(1) + reserved(2).
func buildTPHeader(offeredLen uint32, segmentID byte, more bool) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], offeredLen)
	b[4] = segmentID
	if more {
		b[5] = 0x01
	}
	return b
}