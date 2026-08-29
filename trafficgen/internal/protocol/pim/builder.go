package pim

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// PIM-SM message types (RFC 7761 §4).
const (
	typeHello          = 0x00
	typeRegister       = 0x01
	typeRegisterStop   = 0x02
	typeJoinPrune      = 0x03
	typeBootstrap      = 0x04
	typeAssert         = 0x05
	typeCandidateRPAdv = 0x08
)

// Hello option types (RFC 7761 §4.9).
const (
	optHoldtime      = 1  // 2-byte holdtime
	optLANPruneDelay = 2  // 4-byte: (T<<15|propagation) + override
	optDRPriority    = 19 // 4-byte DR priority
	optGenerationID  = 20 // 4-byte generation id
)

// Source flags in the PIMv2 encoded-source (dissect_pim_addr pimv2_source).
const (
	srcFlagSparse = 0x04
	srcFlagWild   = 0x02
	srcFlagRPT    = 0x01
)

// Register flag bits (RFC 7761 §4.9.1).
const (
	regFlagBorder = 0x80000000
	regFlagNull   = 0x40000000
)

// version is the PIM protocol version (RFC 7761 §4.1). Only version 2 is
// emitted by this package.
const version = 2

// checksum computes the RFC 1071 one's complement sum over the PIM message
// with the checksum field zeroed (RFC 7761 §4.2).
func checksum(b []byte) uint16 {
	if len(b)%2 != 0 {
		b = append(b, 0)
	}
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// to4 parses an IPv4 string and returns its 4-byte form, or an error.
func to4(addr string) ([]byte, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address %q", addr)
	}
	return ip, nil
}

// isIPv4 reports whether the address is non-empty IPv4. An empty address is
// treated as not-IPv4 (the caller decides whether that is an error).
func isIPv4(addr string) bool {
	return net.ParseIP(addr).To4() != nil
}

// encodeUnicast encodes a PIMv2 unicast address (RFC 7761 §4.3.1):
// [AF=1, ET=0] + 4-byte IP.
func encodeUnicast(addr string) ([]byte, error) {
	ip, err := to4(addr)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 6)
	out = append(out, 0x01, 0x00)
	out = append(out, ip...)
	return out, nil
}

// maskToLen converts a CIDR prefix ("239.0.0.0/8") to its mask length. A bare
// /32 group is expressed as a full-length prefix; a wildcard source uses the
// group's mask length on the wire.
func maskToLen(prefix string) (byte, error) {
	if prefix == "" {
		return 32, nil
	}
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR prefix %q", prefix)
	}
	ones, _ := ipnet.Mask.Size()
	return byte(ones), nil
}

// groupPrefixFor returns the group-prefix string ("239.0.0.0/8" or the bare
// group "239.1.1.1" → /32).
func groupPrefixFor(group string) string {
	if group == "" {
		return ""
	}
	if _, _, err := net.ParseCIDR(group); err == nil {
		return group
	}
	return group + "/32"
}

// groupIP extracts the bare IP from a group string ("239.1.1.1" or the CIDR
// prefix "239.0.0.0/8"), returning the 4-byte form.
func groupIP(group string) ([]byte, error) {
	if _, _, err := net.ParseCIDR(group); err == nil {
		ip, _, err := net.ParseCIDR(group)
		if err != nil {
			return nil, err
		}
		return ip.To4(), nil
	}
	return to4(group)
}

// encodeGroup encodes a PIMv2 group address (RFC 7761 §4.3.2):
// [AF=1, ET=0, flags=0, masklen] + 4-byte IP. maskLen is the CIDR prefix
// length (32 for a /32 group).
func encodeGroup(group string, maskLen byte) ([]byte, error) {
	ip, err := groupIP(group)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8)
	out = append(out, 0x01, 0x00, 0x00, maskLen)
	out = append(out, ip...)
	return out, nil
}

// encodeSource encodes a PIMv2 join/prune source (pimv2_source):
// [AF=1, ET=0, flags, masklen=32] + 4-byte IP. The wildcard (*,G) join sets
// the W bit and carries the source as 0.0.0.0.
func encodeSource(src string, wildcard bool, rpt bool) ([]byte, error) {
	ip := net.IPv4zero.To4()
	flags := byte(0)
	if wildcard {
		flags |= srcFlagWild
	} else {
		v, err := to4(src)
		if err != nil {
			return nil, err
		}
		ip = v
	}
	if rpt {
		flags |= srcFlagRPT
	}
	out := make([]byte, 0, 8)
	out = append(out, 0x01, 0x00, flags, 32)
	out = append(out, ip...)
	return out, nil
}

// buildPIM assembles the common 4-byte PIM header plus body, then computes or
// zeroes the checksum per checksumMode. checksumMode: ""/auto → correct
// checksum; invalid/bad → wrong checksum; zero → checksum zeroed.
func buildPIM(typ byte, body []byte, checksumMode string) ([]byte, error) {
	msg := make([]byte, 0, 4+len(body))
	msg = append(msg, (version<<4)|typ, 0x00, 0x00, 0x00)
	msg = append(msg, body...)
	switch checksumMode {
	case "invalid", "bad":
		// leave the checksum field as 0x0000 (an invalid checksum).
	default:
		// zero or auto → write correct checksum over the zeroed field.
		binary.BigEndian.PutUint16(msg[2:4], 0)
		if checksumMode != "zero" {
			binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
		}
	}
	return msg, nil
}

// buildHello builds a PIM hello message from an event.
func buildHello(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	var body []byte
	// Holdtime (RFC 7761 §4.9.2, mandatory): option 1, len 2, value = holdtime.
	// Always emitted; a zero holdtime is the immediate-expiry boundary.
	b := make([]byte, 0, 6)
	b = append(b, byte(optHoldtime>>8), byte(optHoldtime))
	b = append(b, 0, 2)
	b = append(b, byte(ev.Holdtime>>8), byte(ev.Holdtime))
	body = append(body, b...)
	// LAN Prune Delay (RFC 7761 §4.9.3): option 2, len 4.
	// value = (T_bit<<15 | propagation_delay) uint16 + override_interval uint16.
	if ev.LANPruneDelay != nil {
		delay := ev.LANPruneDelay
		b := make([]byte, 0, 8)
		b = append(b, byte(optLANPruneDelay>>8), byte(optLANPruneDelay))
		b = append(b, 0, 4)
		var propV uint16
		if delay.TBit {
			propV |= 0x8000
		}
		propV |= uint16(delay.Propagation & 0x7fff)
		b = append(b, byte(propV>>8), byte(propV))
		b = append(b, byte(delay.Override>>8), byte(delay.Override))
		body = append(body, b...)
	}
	// DR Priority (RFC 7761 §4.9.4): option 19, len 4.
	if ev.DRPriority != 0 {
		b := make([]byte, 0, 8)
		b = append(b, byte(optDRPriority>>8), byte(optDRPriority))
		b = append(b, 0, 4)
		b = binary.BigEndian.AppendUint32(b, uint32(ev.DRPriority))
		body = append(body, b...)
	}
	// Generation ID (RFC 7761 §4.9.5): option 20, len 4.
	if ev.GenerationID != "" {
		gen, err := parseGenID(ev.GenerationID)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 0, 8)
		b = append(b, byte(optGenerationID>>8), byte(optGenerationID))
		b = append(b, 0, 4)
		b = binary.BigEndian.AppendUint32(b, gen)
		body = append(body, b...)
	}
	return buildPIM(typeHello, body, checksumMode)
}

// buildJoinPrune builds a PIM join/prune message from an event.
func buildJoinPrune(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	up, err := encodeUnicast(ev.UpstreamNeighbor)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 64)
	body = append(body, up...)
	body = append(body, 0x00) // reserved, RFC 7761 §4.9.6
	body = append(body, byte(len(ev.Groups)))
	body = binary.BigEndian.AppendUint16(body, uint16(ev.Holdtime))
	for _, g := range ev.Groups {
		prefix := groupPrefixFor(g.Group)
		maskLen, err := maskToLen(prefix)
		if err != nil {
			return nil, err
		}
		ge, err := encodeGroup(g.Group, maskLen)
		if err != nil {
			return nil, err
		}
		body = append(body, ge...)
		body = binary.BigEndian.AppendUint16(body, uint16(len(g.JoinedSources)))
		body = binary.BigEndian.AppendUint16(body, uint16(len(g.PrunedSources)))
		for _, s := range g.JoinedSources {
			se, err := encodeSource(s.Source, s.Wildcard, false)
			if err != nil {
				return nil, err
			}
			body = append(body, se...)
		}
		for _, s := range g.PrunedSources {
			se, err := encodeSource(s.Source, s.Wildcard, false)
			if err != nil {
				return nil, err
			}
			body = append(body, se...)
		}
	}
	return buildPIM(typeJoinPrune, body, checksumMode)
}

// buildBootstrap builds a PIM bootstrap message from an event.
func buildBootstrap(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	bsr, err := encodeUnicast(ev.BSR)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 64)
	body = binary.BigEndian.AppendUint16(body, 1) // fragment tag (RFC 7761 §4.9.7)
	body = append(body, byte(ev.HashMaskLength))
	body = append(body, byte(ev.BSRPriority))
	body = append(body, bsr...)
	for _, set := range ev.RPSets {
		prefix := groupPrefixFor(set.GroupPrefix)
		maskLen, err := maskToLen(prefix)
		if err != nil {
			return nil, err
		}
		ge, err := encodeGroup(set.GroupPrefix, maskLen)
		if err != nil {
			return nil, err
		}
		body = append(body, ge...)
		body = append(body, byte(len(set.RPs))) // rp_count
		body = append(body, byte(len(set.RPs))) // frp_count
		body = append(body, 0x00, 0x00)         // reserved (2 bytes, RFC 7761 §4.9.7)
		for _, rp := range set.RPs {
			re, err := encodeUnicast(rp.RP)
			if err != nil {
				return nil, err
			}
			body = append(body, re...)
			body = binary.BigEndian.AppendUint16(body, uint16(rp.Holdtime))
			body = append(body, byte(rp.Priority))
			body = append(body, 0x00) // reserved
		}
	}
	return buildPIM(typeBootstrap, body, checksumMode)
}

// buildCandidateRPAdv builds a PIM candidate-RP-Advertisement message.
func buildCandidateRPAdv(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	rp, err := encodeUnicast(ev.RP)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 64)
	body = append(body, byte(len(ev.GroupPrefixes))) // prefix_count
	body = append(body, byte(ev.RPPriority))
	body = binary.BigEndian.AppendUint16(body, uint16(ev.Holdtime))
	body = append(body, rp...)
	for _, gp := range ev.GroupPrefixes {
		prefix := groupPrefixFor(gp)
		maskLen, err := maskToLen(prefix)
		if err != nil {
			return nil, err
		}
		ge, err := encodeGroup(gp, maskLen)
		if err != nil {
			return nil, err
		}
		body = append(body, ge...)
	}
	return buildPIM(typeCandidateRPAdv, body, checksumMode)
}

// buildRegister builds a PIM register message: register flags (4 bytes) then
// the encapsulated inner IPv4 packet. Per tshark/RFC 7761 the PIM checksum
// covers only the 8-byte prefix (4-byte header + 4-byte flags), NOT the
// encapsulated inner packet — so the checksum is computed over msg[:8].
func buildRegister(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	var flags uint32
	if ev.RegisterFlags != nil {
		if ev.RegisterFlags.BorderBit {
			flags |= regFlagBorder
		}
		if ev.RegisterFlags.NullRegister {
			flags |= regFlagNull
		}
	}
	inner, err := buildInnerIPv4(ev.InnerIPv4)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 4+len(inner))
	body = binary.BigEndian.AppendUint32(body, flags)
	body = append(body, inner...)
	msg := make([]byte, 0, 4+len(body))
	msg = append(msg, (version<<4)|typeRegister, 0x00, 0x00, 0x00)
	msg = append(msg, body...)
	switch checksumMode {
	case "invalid", "bad":
		// leave the checksum field as 0x0000 (an invalid checksum).
	default:
		// register checksum covers only the 8-byte prefix (RFC 7761 §4.9.1).
		if checksumMode != "zero" {
			binary.BigEndian.PutUint16(msg[2:4], 0)
			binary.BigEndian.PutUint16(msg[2:4], checksum(msg[:8]))
		}
	}
	return msg, nil
}

// buildRegisterStop builds a PIM register-stop message.
func buildRegisterStop(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	ge, err := encodeGroup(ev.Group, 32) // /32 group (RFC 7761 §4.9.8)
	if err != nil {
		return nil, err
	}
	se, err := encodeUnicast(ev.Source)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(ge)+len(se))
	body = append(body, ge...)
	body = append(body, se...)
	return buildPIM(typeRegisterStop, body, checksumMode)
}

// buildAssert builds a PIM assert message.
func buildAssert(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	ge, err := encodeGroup(ev.Group, 32)
	if err != nil {
		return nil, err
	}
	se, err := encodeUnicast(ev.Source)
	if err != nil {
		return nil, err
	}
	// rpt/metric_pref packed into a 4-byte word: R bit (0x80000000) + 31-bit
	// metric preference (RFC 7761 §4.9.9).
	var pref uint32
	if ev.RptBit {
		pref |= 0x80000000
	}
	pref |= uint32(ev.MetricPreference) & 0x7fffffff
	body := make([]byte, 0, len(ge)+len(se)+8)
	body = append(body, ge...)
	body = append(body, se...)
	body = binary.BigEndian.AppendUint32(body, pref)
	body = binary.BigEndian.AppendUint32(body, uint32(ev.RouteMetric))
	return buildPIM(typeAssert, body, checksumMode)
}

// hexDecode decodes a space- or non-separated hex string ("de ad be ef" or
// "deadbeef") into bytes.
func hexDecode(s string) ([]byte, error) {
	s = trimHex(s)
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid payload_hex %q", s)
	}
	return b, nil
}

// trimHex removes whitespace between hex pairs and validates even length.
func trimHex(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' {
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// parseGenID parses a generation-id string in "0x11223344" form into a
// uint32. The "0x" prefix is optional.
func parseGenID(s string) (uint32, error) {
	clean := trimHex(s)
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	if clean == "" {
		return 0, fmt.Errorf("invalid generation_id %q", s)
	}
	v, err := strconv.ParseUint(clean, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid generation_id %q", s)
	}
	return uint32(v), nil
}

// buildInnerIPv4 builds a minimal, valid inner IPv4 datagram for a register
// message. The inner header carries src/dst and a UDP (proto 17) payload; the
// payload bytes come from inner.PayloadHex. A full 8-byte UDP header precedes
// the payload: declaring proto=UDP without the UDP header makes tshark mark
// the inner packet malformed ("[Malformed Packet: UDP]").
func buildInnerIPv4(inner *core.PIMInnerIPv4) ([]byte, error) {
	if inner == nil {
		return nil, nil
	}
	src, err := to4(inner.Src)
	if err != nil {
		return nil, err
	}
	dst, err := to4(inner.Dst)
	if err != nil {
		return nil, err
	}
	payload, err := hexDecode(inner.PayloadHex)
	if err != nil {
		return nil, err
	}
	const headerLen = 20
	const udpLen = 8
	pkt := make([]byte, headerLen+udpLen+len(payload))
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(headerLen+udpLen+len(payload)))
	pkt[8] = 64 // TTL
	pkt[9] = core.ProtocolUDP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	// UDP header (src/dst port 0, length, checksum 0 — IPv4 allows 0x0000).
	binary.BigEndian.PutUint16(pkt[20:22], 0)
	binary.BigEndian.PutUint16(pkt[22:24], 0)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen+len(payload)))
	copy(pkt[headerLen+udpLen:], payload)
	// IPv4 header checksum over the 20-byte header (RFC 791).
	hdr := pkt[:headerLen]
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(hdr[10:12], uint16(^sum))
	return pkt, nil
}

// buildMessageByKind dispatches on the event kind to build the wire message.
func buildMessageByKind(ev core.PIMEvent, checksumMode string) ([]byte, error) {
	switch ev.Kind {
	case "hello":
		return buildHello(ev, checksumMode)
	case "join_prune":
		return buildJoinPrune(ev, checksumMode)
	case "bootstrap":
		return buildBootstrap(ev, checksumMode)
	case "candidate_rp_adv":
		return buildCandidateRPAdv(ev, checksumMode)
	case "register":
		return buildRegister(ev, checksumMode)
	case "register_stop":
		return buildRegisterStop(ev, checksumMode)
	case "assert":
		return buildAssert(ev, checksumMode)
	default:
		return nil, fmt.Errorf("pim: unsupported event kind %q", ev.Kind)
	}
}
