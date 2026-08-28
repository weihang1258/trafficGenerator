package ldp

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// LDP wire format constants.
const (
	ldpVersion    = 1
	pduHdrLen     = 10
	msgHdrLen     = 8 // U+Type(2) + Length(2) + MessageID(4)
	tlvHdrLen     = 4 // U/F+Type(2) + Length(2)
	defaultLSRID  = "192.0.2.1"
	defaultHold   = 15
	defaultKA     = 30
	defaultMaxPDU = 4096
)

// Message types.
const (
	msgNotification   uint16 = 0x0001
	msgHello          uint16 = 0x0100
	msgInitialization uint16 = 0x0200
	msgKeepAlive      uint16 = 0x0201
	msgAddress        uint16 = 0x0300
	msgLabelMapping   uint16 = 0x0400
	msgLabelRequest   uint16 = 0x0401
	msgLabelWithdraw  uint16 = 0x0402
	msgLabelRelease   uint16 = 0x0403
)

// TLV types.
const (
	tlvFEC              uint16 = 0x0100
	tlvAddressList      uint16 = 0x0101
	tlvGenericLabel     uint16 = 0x0200
	tlvStatus           uint16 = 0x0300
	tlvHelloParams      uint16 = 0x0400
	tlvSessionParams    uint16 = 0x0500
	tlvTransportAddress uint16 = 0x0401
)

// FEC element types.
const (
	fecPrefix = 2
)

// ad field values.
const (
	adDownstreamUnsolicited = 0
	adDownstreamOnDemand    = 1
)

// BuildPDU builds a complete LDP PDU (common header + one message).
func BuildPDU(lsrID string, labelSpace uint16, msgType uint16, msgID uint32, msgBody []byte) []byte {
	msgLen := msgHdrLen + len(msgBody)
	pduLen := 4 + msgLen // PDU Length = Version(2) + PDU Length(2) excluded, so msg(+4) minus those 4
	// Actually: PDU Length is the length of the PDU excluding Version and PDU Length fields.
	// So: PDU Length = LSR ID(4) + Label Space ID(2) + Message = 6 + msgLen
	pduLen = 6 + msgLen

	hdr := make([]byte, pduHdrLen)
	binary.BigEndian.PutUint16(hdr[0:2], ldpVersion)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(pduLen))
	lsr := net.ParseIP(lsrID).To4()
	if lsr == nil {
		lsr = net.ParseIP(defaultLSRID).To4()
	}
	copy(hdr[4:8], lsr)
	binary.BigEndian.PutUint16(hdr[8:10], labelSpace)

	msg := buildMessage(msgType, msgID, msgBody)
	return append(hdr, msg...)
}

// buildMessage builds a message header + body.
func buildMessage(msgType uint16, msgID uint32, body []byte) []byte {
	// Message Length = Message ID (4) + parameters
	msgLen := 4 + len(body)
	buf := make([]byte, msgHdrLen+len(body))
	binary.BigEndian.PutUint16(buf[0:2], msgType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(buf[4:8], msgID)
	copy(buf[8:], body)
	return buf
}

// buildTLV builds a TLV.
func buildTLV(tlvType uint16, value []byte) []byte {
	buf := make([]byte, tlvHdrLen+len(value))
	binary.BigEndian.PutUint16(buf[0:2], tlvType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[4:], value)
	return buf
}

// BuildHello builds a Hello message body.
func BuildHello(holdTime uint16, targeted bool, transportAddr string) []byte {
	// Hello Common Parameters TLV: Hold Time(2) + Flags(2)
	flags := uint16(0)
	if targeted {
		flags |= 0x8000 // Targeted bit
	}
	helloParams := make([]byte, 4)
	binary.BigEndian.PutUint16(helloParams[0:2], holdTime)
	binary.BigEndian.PutUint16(helloParams[2:4], flags)
	body := buildTLV(tlvHelloParams, helloParams)

	if transportAddr != "" {
		addr := net.ParseIP(transportAddr).To4()
		if addr != nil {
			body = append(body, buildTLV(tlvTransportAddress, addr)...)
		}
	}
	return body
}

// BuildInitialization builds an Initialization message body.
func BuildInitialization(keepaliveTime uint16, labelAdvert string, lsrID, receiverLSRID string, labelSpace uint16) []byte {
	// Common Session Parameters TLV (0x0500), 14-byte Value:
	// Protocol Version(2) | KeepAlive Time(2) | Flags(1) | Path Vector Limit(1)
	// | Max PDU Length(2) | Receiver LSR ID(4) | Receiver Label Space ID(2)
	ad := adDownstreamUnsolicited
	if labelAdvert == "downstream_on_demand" {
		ad = adDownstreamOnDemand
	}

	params := make([]byte, 14)
	binary.BigEndian.PutUint16(params[0:2], ldpVersion)
	binary.BigEndian.PutUint16(params[2:4], keepaliveTime)
	params[4] = byte(ad << 6) // Label Advertisement Discipline in the 2 high bits
	params[5] = 0             // Path Vector Limit = 0
	binary.BigEndian.PutUint16(params[6:8], defaultMaxPDU)
	if r := net.ParseIP(receiverLSRID).To4(); r != nil {
		copy(params[8:12], r)
	}
	binary.BigEndian.PutUint16(params[12:14], labelSpace)

	return buildTLV(tlvSessionParams, params)
}

// BuildKeepAlive returns an empty KeepAlive message body.
func BuildKeepAlive() []byte {
	return nil
}

// BuildAddress builds an Address message body.
func BuildAddress(addresses []string) []byte {
	// Address List TLV: Address Family(2) + addresses (4 each)
	addrs := make([]byte, 0, 2+len(addresses)*4)
	af := make([]byte, 2)
	binary.BigEndian.PutUint16(af, 1) // IPv4
	addrs = append(addrs, af...)
	for _, a := range addresses {
		ip := net.ParseIP(a).To4()
		if ip != nil {
			addrs = append(addrs, ip...)
		}
	}
	return buildTLV(tlvAddressList, addrs)
}

// BuildFECTLV builds an IPv4 Prefix FEC TLV.
func BuildFECTLV(prefix string, prefixLen uint8) []byte {
	// FEC Element Type(1) + Address Family(2) + Prefix Length(1) + Prefix(ceil(prefixLen/8))
	body := make([]byte, 0, 4+4)
	body = append(body, fecPrefix) // FEC Element Type = Prefix
	af := make([]byte, 2)
	binary.BigEndian.PutUint16(af, 1) // Address Family = IPv4
	body = append(body, af...)
	body = append(body, prefixLen)
	octets := (prefixLen + 7) / 8
	ip := net.ParseIP(prefix).To4()
	if ip != nil {
		body = append(body, ip[:octets]...)
	}
	return buildTLV(tlvFEC, body)
}

// BuildGenericLabelTLV builds a Generic Label TLV with 4-byte value.
func BuildGenericLabelTLV(label uint32) []byte {
	// RFC 5036 §3.4.3: Generic Label TLV value is 4 bytes (hex F0-F3).
	// PutUint32 emits 4 bytes big-endian. The 20-bit label occupies the
	// high-order bits of a 32-bit label word by construction of the input.
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, label)
	return buildTLV(tlvGenericLabel, val)
}

// BuildLabelMapping builds a Label Mapping message body.
func BuildLabelMapping(prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildFECTLV(prefix, prefixLen)
	body = append(body, BuildGenericLabelTLV(label)...)
	return body
}

// BuildLabelRequest builds a Label Request message body.
func BuildLabelRequest(prefix string, prefixLen uint8) []byte {
	return BuildFECTLV(prefix, prefixLen)
}

// BuildLabelWithdraw builds a Label Withdraw message body.
func BuildLabelWithdraw(prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildFECTLV(prefix, prefixLen)
	if label > 0 {
		body = append(body, BuildGenericLabelTLV(label)...)
	}
	return body
}

// BuildLabelRelease builds a Label Release message body.
func BuildLabelRelease(prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildFECTLV(prefix, prefixLen)
	if label > 0 {
		body = append(body, BuildGenericLabelTLV(label)...)
	}
	return body
}

// BuildNotification builds a Notification message body.
//
// Per RFC 5036 §3.5.3.1 the Status TLV value is 10 bytes:
//
//	Status Code (4) | Message ID (4) | Message Type (2)
//
// The Message ID / Message Type identify the message being reported on; a
// standalone Notification (e.g. Shutdown) has no triggering message, so both
// are 0. tshark's LDP dissector rejects a Status TLV that is not exactly 10
// bytes ("length is %d, should be 10"), so we must always emit the full form.
func BuildNotification(statusCode, msgID uint32, msgType uint16) []byte {
	val := make([]byte, 10)
	binary.BigEndian.PutUint32(val[0:4], statusCode)
	binary.BigEndian.PutUint32(val[4:8], msgID)
	binary.BigEndian.PutUint16(val[8:10], msgType)
	return buildTLV(tlvStatus, val)
}

// BuildHelloPDU builds a complete PDU for Hello (UDP).
func BuildHelloPDU(lsrID string, labelSpace uint16, msgID uint32, holdTime uint16, targeted bool, transportAddr string) []byte {
	body := BuildHello(holdTime, targeted, transportAddr)
	return BuildPDU(lsrID, labelSpace, msgHello, msgID, body)
}

// BuildInitPDU builds a complete PDU for Initialization (TCP).
func BuildInitPDU(lsrID string, labelSpace uint16, msgID uint32, kaTime uint16, labelAdvert, receiverLSRID string) []byte {
	body := BuildInitialization(kaTime, labelAdvert, lsrID, receiverLSRID, labelSpace)
	return BuildPDU(lsrID, labelSpace, msgInitialization, msgID, body)
}

// BuildKeepAlivePDU builds a complete PDU for KeepAlive.
func BuildKeepAlivePDU(lsrID string, labelSpace uint16, msgID uint32) []byte {
	body := BuildKeepAlive()
	return BuildPDU(lsrID, labelSpace, msgKeepAlive, msgID, body)
}

// BuildAddressPDU builds a complete PDU for Address.
func BuildAddressPDU(lsrID string, labelSpace uint16, msgID uint32, addresses []string) []byte {
	body := BuildAddress(addresses)
	return BuildPDU(lsrID, labelSpace, msgAddress, msgID, body)
}

// BuildLabelMappingPDU builds a complete PDU for Label Mapping.
func BuildLabelMappingPDU(lsrID string, labelSpace uint16, msgID uint32, prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildLabelMapping(prefix, prefixLen, label)
	return BuildPDU(lsrID, labelSpace, msgLabelMapping, msgID, body)
}

// BuildLabelRequestPDU builds a complete PDU for Label Request.
func BuildLabelRequestPDU(lsrID string, labelSpace uint16, msgID uint32, prefix string, prefixLen uint8) []byte {
	body := BuildLabelRequest(prefix, prefixLen)
	return BuildPDU(lsrID, labelSpace, msgLabelRequest, msgID, body)
}

// BuildLabelWithdrawPDU builds a complete PDU for Label Withdraw.
func BuildLabelWithdrawPDU(lsrID string, labelSpace uint16, msgID uint32, prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildLabelWithdraw(prefix, prefixLen, label)
	return BuildPDU(lsrID, labelSpace, msgLabelWithdraw, msgID, body)
}

// BuildLabelReleasePDU builds a complete PDU for Label Release.
func BuildLabelReleasePDU(lsrID string, labelSpace uint16, msgID uint32, prefix string, prefixLen uint8, label uint32) []byte {
	body := BuildLabelRelease(prefix, prefixLen, label)
	return BuildPDU(lsrID, labelSpace, msgLabelRelease, msgID, body)
}

// BuildNotificationPDU builds a complete PDU for Notification.
func BuildNotificationPDU(lsrID string, labelSpace uint16, msgID uint32, statusCode uint32) []byte {
	// The Status TLV carries the *reported* message ID + type. A standalone
	// Shutdown notification has no triggering message, so both are 0.
	body := BuildNotification(statusCode, 0, 0)
	return BuildPDU(lsrID, labelSpace, msgNotification, msgID, body)
}

// resolveFEC parses a FEC string like "203.0.113.0/24" into prefix and length.
func resolveFEC(fec string) (string, uint8, error) {
	// net.ParseCIDR rejects prefix lengths > 32 with a generic "invalid CIDR
	// address" error, which makes prefix-bounds validation messages opaque.
	// Inspect the /len suffix first so out-of-range prefixes surface a clear
	// "prefix length out of range" error instead.
	if slash := strings.LastIndexByte(fec, '/'); slash >= 0 {
		var plen int
		if _, err := fmt.Sscanf(fec[slash+1:], "%d", &plen); err == nil && plen > 32 {
			return "", 0, fmt.Errorf("ldp: FEC prefix length %d out of range (max 32)", plen)
		}
	}
	ip, ipnet, err := net.ParseCIDR(fec)
	if err != nil {
		return "", 0, fmt.Errorf("ldp: invalid FEC %q: %w", fec, err)
	}
	ones, _ := ipnet.Mask.Size()
	return ip.String(), uint8(ones), nil
}

// CheckFault returns an error for fault injection, or nil.
func CheckFault(faultKind string) error {
	switch faultKind {
	case "":
		return nil
	case "pdu_length", "message_length", "tlv_length", "label_bounds", "unknown_message", "checksum":
		return fmt.Errorf("ldp: fault injection %q", faultKind)
	default:
		return fmt.Errorf("ldp: unknown fault kind %q", faultKind)
	}
}

// parseLSRID parses an LSR ID string or returns the default.
func parseLSRID(lsrID string) string {
	if lsrID == "" {
		return defaultLSRID
	}
	return lsrID
}

// parseLDPConfig parses LDP events from the config and returns PDU bytes.
// Used by both the planner and the generator.
func parseLDPConfig(cfg *core.LDPConfig) ([][]byte, []bool, error) {
	var payloads [][]byte
	var ups []bool

	lsrID := parseLSRID(cfg.LSRID)
	labelSpace := cfg.LabelSpace

	for _, ev := range cfg.Events {
		up := ev.Direction == "c2s"
		mid := ev.MessageID
		var pdu []byte

		switch ev.Kind {
		case "hello":
			targeted := ev.Targeted || cfg.Targeted
			taddr := ev.LSRID
			if taddr == "" {
				taddr = lsrID
			}
			pdu = BuildHelloPDU(lsrID, labelSpace, mid, ev.HoldTime, targeted, taddr)
		case "initialization":
			ka := ev.KeepaliveTime
			if ka == 0 {
				ka = cfg.KeepaliveTime
			}
			if ka == 0 {
				ka = defaultKA
			}
			receiver := ev.ReceiverLSRID
			if receiver == "" {
				receiver = ev.LSRID
			}
			pdu = BuildInitPDU(lsrID, labelSpace, mid, ka, cfg.LabelAdvertisement, receiver)
		case "keepalive":
			pdu = BuildKeepAlivePDU(lsrID, labelSpace, mid)
		case "address":
			addrs := ev.Addresses
			if len(addrs) == 0 {
				addrs = []string{lsrID}
			}
			pdu = BuildAddressPDU(lsrID, labelSpace, mid, addrs)
		case "label_mapping":
			prefix, pl, err := resolveFEC(ev.FEC)
			if err != nil {
				return nil, nil, err
			}
			pdu = BuildLabelMappingPDU(lsrID, labelSpace, mid, prefix, pl, ev.Label)
		case "label_request":
			prefix, pl, err := resolveFEC(ev.FEC)
			if err != nil {
				return nil, nil, err
			}
			pdu = BuildLabelRequestPDU(lsrID, labelSpace, mid, prefix, pl)
		case "label_withdraw":
			prefix, pl, err := resolveFEC(ev.FEC)
			if err != nil {
				return nil, nil, err
			}
			pdu = BuildLabelWithdrawPDU(lsrID, labelSpace, mid, prefix, pl, ev.Label)
		case "label_release":
			prefix, pl, err := resolveFEC(ev.FEC)
			if err != nil {
				return nil, nil, err
			}
			pdu = BuildLabelReleasePDU(lsrID, labelSpace, mid, prefix, pl, ev.Label)
		case "notification":
			sc := ev.StatusCode
			if sc == 0 {
				sc = 1 // Shutdown
			}
			pdu = BuildNotificationPDU(lsrID, labelSpace, mid, sc)
		default:
			return nil, nil, fmt.Errorf("ldp: unknown event kind %q", ev.Kind)
		}

		payloads = append(payloads, pdu)
		ups = append(ups, up)
	}
	return payloads, ups, nil
}

// ValidateConfig validates the LDP config.
func ValidateConfig(cfg *core.LDPConfig) error {
	if cfg == nil {
		return fmt.Errorf("ldp: config is required")
	}
	if len(cfg.Events) == 0 {
		return fmt.Errorf("ldp: at least one event required")
	}
	if cfg.Carrier != "udp_discovery" && cfg.Carrier != "tcp_session" && cfg.Carrier != "" {
		return fmt.Errorf("ldp: unknown carrier %q", cfg.Carrier)
	}
	if cfg.LabelAdvertisement != "" && cfg.LabelAdvertisement != "downstream_unsolicited" && cfg.LabelAdvertisement != "downstream_on_demand" {
		return fmt.Errorf("ldp: unknown label advertisement %q", cfg.LabelAdvertisement)
	}
	if cfg.FaultKind != "" {
		if err := CheckFault(cfg.FaultKind); err != nil {
			return err
		}
	}
	seenInit := false
	for i, ev := range cfg.Events {
		if ev.Kind == "" {
			return fmt.Errorf("ldp: event %d: kind is required", i)
		}
		if ev.Direction != "c2s" && ev.Direction != "s2c" {
			return fmt.Errorf("ldp: event %d: direction must be c2s or s2c", i)
		}
		validKinds := []string{"hello", "initialization", "keepalive", "address", "label_mapping", "label_request", "label_withdraw", "label_release", "notification"}
		if !slices.Contains(validKinds, ev.Kind) {
			return fmt.Errorf("ldp: event %d: unknown kind %q", i, ev.Kind)
		}
		if (ev.Kind == "label_mapping" || ev.Kind == "label_request" || ev.Kind == "label_withdraw" || ev.Kind == "label_release") && ev.FEC == "" {
			return fmt.Errorf("ldp: event %d: FEC is required for %s", i, ev.Kind)
		}
		if ev.FEC != "" {
			// Validate the prefix bound at validation time so an out-of-range
			// /len (e.g. /33) is rejected with a clear "prefix" error rather
			// than surfacing as "planner produced 0 packet configs" later.
			if _, _, err := resolveFEC(ev.FEC); err != nil {
				return err
			}
		}
		if ev.Kind == "label_mapping" && ev.Label == 0 {
			return fmt.Errorf("ldp: event %d: label is required for label_mapping", i)
		}
		if (ev.Kind == "label_mapping" || ev.Kind == "label_withdraw" || ev.Kind == "label_release") && ev.Label >= 1<<20 {
			return fmt.Errorf("ldp: event %d: label exceeds 20-bit bound", i)
		}
		if ev.Kind == "hello" && ev.HoldTime == 0 {
			ev.HoldTime = defaultHold
		}
		// RFC 5036 §2.5.4: KeepAlive implies an established session, which
		// requires a prior Initialization exchange. A config whose first
		// message is KeepAlive (no Initialization seen) is an invalid state
		// sequence and must be rejected, not emitted.
		if ev.Kind == "keepalive" && !seenInit {
			return fmt.Errorf("ldp: event %d: keepalive before initialization (invalid session state)", i)
		}
		if ev.Kind == "initialization" {
			seenInit = true
		}
	}
	return nil
}
