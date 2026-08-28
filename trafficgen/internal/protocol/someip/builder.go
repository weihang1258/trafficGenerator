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

// SD option types (§3.4.2). These are the LOGICAL config enums (design §3.4.2)
// used by sd.options[].type: 1=IPv4 Endpoint, 2=IPv4 Multicast, 6=IPv6 Endpoint.
// On the wire the AUTOSAR SD option-type byte differs from these enums (see
// configToWireOptionType), because tshark's sd_option_type enum renumbers them.
const (
	SDOptionIPv4Endpoint  = 0x01 // logical enum: IPv4 Endpoint
	SDOptionIPv4Multicast = 0x02 // logical enum: IPv4 Multicast
	SDOptionIPv6Endpoint  = 0x06 // logical enum: IPv6 Endpoint
)

// Wire SD option type bytes (AUTOSAR / tshark sd_option_type enum).
const (
	sdWireOptionIPv4Endpoint  = 0x04
	sdWireOptionIPv4Multicast = 0x14
	sdWireOptionIPv6Endpoint  = 0x06
)

// configToWireOptionType maps a logical config enum (design §3.4.2) to the wire
// option-type byte tshark switches on. Returns sdWireOptionIPv4Endpoint (0x04)
// for the default IPv4 Endpoint.
func configToWireOptionType(t uint8) uint8 {
	switch t {
	case SDOptionIPv4Multicast:
		return sdWireOptionIPv4Multicast
	case SDOptionIPv6Endpoint:
		return sdWireOptionIPv6Endpoint
	default: // SDOptionIPv4Endpoint and any unknown -> IPv4 Endpoint wire
		return sdWireOptionIPv4Endpoint
	}
}

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
// ID) + 8B SD header + entries + 4B options length + options. options are the
// optional Option entries.
//
// Wire layout (byte-verified against tshark 3.6.14 packet-someip-sd.c):
//
//	SOME/IP header: service=0xffff method=0x8100 length=8+plen client sess ver=1 ifv=1 type=0x02 rc=0
//	SD header:      flags(1) reserved(3) entries_len(4)
//	Entries:        16 bytes each (see buildServiceEntry / buildEventgroupEntry)
//	Options length: 4 bytes
//	Options:        each Length(2)+Type(1)+Reserved(1)+data … (see buildOptionBytes)
//
// sdType selects service (0-3) vs eventgroup (4-7) entry layout.
func buildSDMessage(sdType byte, serviceID, instanceID uint16, majorVer uint8, minorVer uint32, ttl uint32, flags byte, eventgroupID uint16, counter uint8, options []SDOption, clientID, sessionID uint16) ([]byte, error) {
	// SD header: Flags(1) + Reserved(3) + Entries Length(4)
	sdHdr := make([]byte, 8)
	sdHdr[0] = flags

	var entry []byte
	if sdType >= 4 {
		// Eventgroup entry (Subscribe 0x06 / SubscribeAck 0x07 / NACK).
		entry = buildEventgroupEntry(sdType, serviceID, instanceID, majorVer, ttl, eventgroupID, counter, len(options))
	} else {
		// Service entry (Find 0x00 / Offer 0x01 / StopOffer).
		entry = buildServiceEntry(sdType, serviceID, instanceID, majorVer, ttl, minorVer, len(options))
	}

	entriesLen := len(entry)
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

	// 4B Options length (missing before this fix — tshark read the option's
	// first 4 bytes as options length and flagged truncated/malformed).
	optLenField := make([]byte, 4)
	binary.BigEndian.PutUint32(optLenField, uint32(len(optBytes)))

	payload := append(sdHdr, entry...)
	payload = append(payload, optLenField...)
	payload = append(payload, optBytes...)
	msg := buildHeader(SDServiceID, SDMethodID, clientID, sessionID, 1, 1, MTNotification, 0, len(payload))
	return append(msg, payload...), nil
}

// buildServiceEntry builds a 16-byte service entry (Type 0-3: Find/Offer/Stop).
// Layout: type(1) index1(1) index2(1) numopts(1) | serviceid(2) instanceid(2)
// majorver(1) ttl(3) minorver(4). numopts byte = (numopt1<<4)|(numopt2&0x0f).
// Offsets are index0-relative; tshark reads serviceid at [4:6], ttl at [9:12].
func buildServiceEntry(sdType byte, serviceID, instanceID uint16, majorVer uint8, ttl uint32, minorVer uint32, numOpts int) []byte {
	entry := make([]byte, 16)
	entry[0] = sdType
	setOpts(entry, numOpts)
	binary.BigEndian.PutUint16(entry[4:6], serviceID)
	binary.BigEndian.PutUint16(entry[6:8], instanceID)
	entry[8] = majorVer
	putU24(entry[9:12], ttl&0xFFFFFF)
	binary.BigEndian.PutUint32(entry[12:16], minorVer)
	return entry
}

// buildEventgroupEntry builds a 16-byte eventgroup entry (Type 4-7:
// Subscribe/SubscribeAck). Layout: type(1) index1(1) index2(1) numopts(1) |
// serviceid(2) instanceid(2) majorver(1) ttl(3) | reserved(1) init_event(1)
// reserved(1) counter(1) eventgroupid(2). tshark reads the counter from entry[13]
// low nibble and eventgroupid at [14:16]. NOTE: the eventgroupid sits at [14:16],
// NOT at [12:14] (design v1 put it at [12:14] — corrected against tshark).
func buildEventgroupEntry(sdType byte, serviceID, instanceID uint16, majorVer uint8, ttl uint32, eventgroupID uint16, counter uint8, numOpts int) []byte {
	entry := make([]byte, 16)
	entry[0] = sdType
	setOpts(entry, numOpts)
	binary.BigEndian.PutUint16(entry[4:6], serviceID)
	binary.BigEndian.PutUint16(entry[6:8], instanceID)
	entry[8] = majorVer
	putU24(entry[9:12], ttl&0xFFFFFF)
	// entry[12] = reserved, entry[14] = reserved2 (0). Counter low nibble, initial
	// event req is bit7 of entry[13] (0x80).
	entry[13] = counter & 0x0F
	binary.BigEndian.PutUint16(entry[14:16], eventgroupID)
	return entry
}

// setOpts writes the numopts byte (high nibble = numopts1 count, low nibble = 0).
func setOpts(entry []byte, numOpts int) {
	if numOpts > 0 {
		if numOpts > 15 {
			numOpts = 15
		}
		entry[3] = byte(numOpts&0x0F) << 4
	}
}

// putU24 writes a 24-bit big-endian value into dst (len 3).
func putU24(dst []byte, v uint32) {
	dst[0] = byte(v >> 16)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v)
}

func buildOptionBytes(o SDOption) ([]byte, error) {
	switch o.Type {
	case SDOptionIPv4Endpoint, SDOptionIPv4Multicast:
		ip := net.ParseIP(o.IP).To4()
		if ip == nil {
			return nil, fmt.Errorf("someip: invalid IPv4 option address %q", o.IP)
		}
		// Length(2)+Type(1)+Reserved(1)+addr(4)+Reserved(1)+proto(1)+port(2) = 12B.
		// Wire order is Length FIRST (tshark reads real_length = ntohs(length)+3),
		// then Type. Length=9 -> real_length=12 (SD_OPTION_IPV4_LENGTH).
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:2], 9)
		b[2] = configToWireOptionType(o.Type)
		copy(b[4:8], ip)
		b[9] = protoToByte(o.Proto)
		binary.BigEndian.PutUint16(b[10:12], o.Port)
		return b, nil
	case SDOptionIPv6Endpoint:
		ip := net.ParseIP(o.IP)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("someip: invalid IPv6 option address %q", o.IP)
		}
		// Length(2)+Type(1)+Reserved(1)+addr(16)+Reserved(1)+proto(1)+port(2)=24B.
		// Length=21 -> real_length=24 (SD_OPTION_IPV6_LENGTH).
		b := make([]byte, 24)
		binary.BigEndian.PutUint16(b[0:2], 21)
		b[2] = configToWireOptionType(o.Type)
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

// buildTPHeader builds the 4-byte SOME/IP-TP header used by tshark's dissector:
// the raw field value is the byte offset (lower 28 bits, MUST be 16-aligned per
// AUTOSAR; tshark masks it with 0xfffffff0), a 3-bit reserved field, and the
// more-segments bit (bit0). SOMEIP_TP_HDR_LEN=4. offset is the byte offset of
// this segment within the reassembled message (0 for the first segment).
func buildTPHeader(offset uint32, more bool) []byte {
	b := make([]byte, 4)
	v := offset & 0xfffffff0
	if more {
		v |= 0x01
	}
	binary.BigEndian.PutUint32(b, v)
	return b
}