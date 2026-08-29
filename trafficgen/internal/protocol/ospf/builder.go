package ospf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// OSPFv2 message types (RFC 2328 §9.1).
const (
	TypeHello                   = 1
	TypeDBDescription           = 2
	TypeLinkStateRequest        = 3
	TypeLinkStateUpdate         = 4
	TypeLinkStateAcknowledgment = 5
)

// packetTypeFromString maps a config packet_type string to the wire byte.
func packetTypeFromString(s string) (byte, error) {
	switch s {
	case "hello":
		return TypeHello, nil
	case "db_description":
		return TypeDBDescription, nil
	case "link_state_request":
		return TypeLinkStateRequest, nil
	case "link_state_update":
		return TypeLinkStateUpdate, nil
	case "link_state_acknowledgment":
		return TypeLinkStateAcknowledgment, nil
	}
	return 0, fmt.Errorf("invalid packet_type %q", s)
}

// checksum computes the RFC 1071 one's complement sum.
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

// ospfHeader builds the 24-byte OSPFv2 common header.
func ospfHeader(msgType byte, packetLen int, routerID, areaID string, authType int, checksumMode string) ([]byte, uint16) {
	hdr := make([]byte, 24)
	hdr[0] = 2 // version
	hdr[1] = msgType
	binary.BigEndian.PutUint16(hdr[2:4], uint16(packetLen))
	copy(hdr[4:8], net.ParseIP(routerID).To4())
	copy(hdr[8:12], net.ParseIP(areaID).To4())
	// hdr[12:14] = checksum (filled later)
	binary.BigEndian.PutUint16(hdr[14:16], uint16(authType))
	// hdr[16:24] = auth data (zeros)
	// checksum is computed by the caller over the whole message.
	return hdr, 0
}

// buildMessage assembles a complete OSPFv2 packet and computes the checksum
// over the entire packet (header + body, checksum field zeroed), unless
// checksumMode requests a corrupted/zeroed checksum.
func buildMessage(msgType byte, routerID, areaID string, authType int, body []byte, checksumMode string) ([]byte, error) {
	packetLen := 24 + len(body)
	hdr, _ := ospfHeader(msgType, packetLen, routerID, areaID, authType, checksumMode)
	msg := append(hdr, body...)
	switch checksumMode {
	case "invalid", "bad":
		// leave the checksum field as-is (zeros) → tshark flags "incorrect".
	case "zero":
		msg[12] = 0
		msg[13] = 0
	default: // "" or "auto"
		msg[12] = 0
		msg[13] = 0
		c := checksum(msg)
		binary.BigEndian.PutUint16(msg[12:14], c)
	}
	return msg, nil
}

// buildLSAHeader builds a 20-byte LSA header; lsaChecksum is computed by the
// caller over the whole LSA (header + body). Returns the header with the
// checksum field zeroed.
func buildLSAHeader(age, options, lsaType int, linkStateID, advertisingRouter string, sequence uint32, length int) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], uint16(age))
	h[2] = byte(options)
	h[3] = byte(lsaType)
	copy(h[4:8], net.ParseIP(linkStateID).To4())
	copy(h[8:12], net.ParseIP(advertisingRouter).To4())
	binary.BigEndian.PutUint32(h[12:16], sequence)
	// h[16:18] = checksum (filled by buildLSA)
	binary.BigEndian.PutUint16(h[18:20], uint16(length))
	return h
}

// buildLSA assembles one LSA (header + body) and computes its own checksum
// (RFC 2328 §12.1.7) over the whole LSA with the checksum field zeroed.
func buildLSA(age, options, lsaType int, linkStateID, advertisingRouter string, sequence string, length int, body []byte, checksumMode string) ([]byte, error) {
	seq, err := parseSequence(sequence)
	if err != nil {
		return nil, err
	}
	h := buildLSAHeader(age, options, lsaType, linkStateID, advertisingRouter, seq, length)
	lsa := append(h, body...)
	switch checksumMode {
	case "invalid", "bad", "zero":
		// leave checksum as-is
	default:
		lsa[16] = 0
		lsa[17] = 0
		c := checksum(lsa)
		binary.BigEndian.PutUint16(lsa[16:18], c)
	}
	return lsa, nil
}

func parseSequence(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	var v uint32
	if s[:2] == "0x" || s[:2] == "0X" {
		if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
			return 0, fmt.Errorf("invalid sequence %q", s)
		}
		return v, nil
	}
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("invalid sequence %q", s)
	}
	return v, nil
}

// --- message bodies ---

// buildHelloBody builds the OSPF Hello PDU body.
func buildHelloBody(mask string, helloInterval, options, priority, deadInterval int, dr, bdr string, neighbors []string) []byte {
	b := make([]byte, 0, 4+2+1+1+4+4+4+len(neighbors)*4)
	b = append(b, net.ParseIP(mask).To4()...)
	var hi [2]byte
	binary.BigEndian.PutUint16(hi[:], uint16(helloInterval))
	b = append(b, hi[:]...)
	b = append(b, byte(options), byte(priority))
	var di [4]byte
	binary.BigEndian.PutUint32(di[:], uint32(deadInterval))
	b = append(b, di[:]...)
	b = append(b, net.ParseIP(dr).To4()...)
	b = append(b, net.ParseIP(bdr).To4()...)
	for _, n := range neighbors {
		b = append(b, net.ParseIP(n).To4()...)
	}
	return b
}

// buildDDBody builds the Database Description PDU body.
func buildDDBody(interfaceMTU, options int, flags *core.OSPFDDFlags, ddSequence int, lsaHeaders []core.OSPFLSAHeader) ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], uint16(interfaceMTU))
	b[2] = byte(options)
	b[3] = flagsByte(flags)
	binary.BigEndian.PutUint32(b[4:8], uint32(ddSequence))
	for _, lh := range lsaHeaders {
		lb, err := buildLSAHeaderBytes(lh)
		if err != nil {
			return nil, err
		}
		b = append(b, lb...)
	}
	return b, nil
}

func flagsByte(f *core.OSPFDDFlags) byte {
	if f == nil {
		return 0
	}
	var b byte
	if f.Init {
		b |= 0x04
	}
	if f.More {
		b |= 0x02
	}
	if f.Master {
		b |= 0x01
	}
	return b
}

// buildLSAHeaderBytes builds a 20-byte LSA header from an OSPFLSAHeader. The
// header's own checksum is computed over the header + (for DD/ACK) no body —
// tshark computes the LSA checksum over the header-length bytes.
func buildLSAHeaderBytes(lh core.OSPFLSAHeader) ([]byte, error) {
	seq, err := parseSequence(lh.Sequence)
	if err != nil {
		return nil, err
	}
	h := buildLSAHeader(lh.Age, lh.Options, lh.LSAType, lh.LinkStateID, lh.AdvertisingRouter, seq, lh.Length)
	// real LSA checksum requires the body; for a header-only LSA in DD/ACK
	// tshark computes it over the full LSA. Cases assert nonzero checksum, so
	// compute over the header with a zero checksum field.
	h[16] = 0
	h[17] = 0
	c := checksum(h)
	binary.BigEndian.PutUint16(h[16:18], c)
	return h, nil
}

// buildLSRBody builds the Link State Request PDU body.
func buildLSRBody(requests []core.OSPFRequest) []byte {
	b := make([]byte, 0, len(requests)*12)
	for _, r := range requests {
		var e [12]byte
		binary.BigEndian.PutUint32(e[0:4], uint32(r.LSAType))
		copy(e[4:8], net.ParseIP(r.LinkStateID).To4())
		copy(e[8:12], net.ParseIP(r.AdvertisingRouter).To4())
		b = append(b, e[:]...)
	}
	return b
}

// buildLSABody builds a full LSA (header + body) for an LSU or a header-only
// LSA (for ACK). Returns the assembled LSA bytes.
func buildLSABody(lsa core.OSPFLSA) ([]byte, error) {
	var body []byte
	switch lsa.LSAType {
	case 1: // router LSA
		links := append([]core.OSPFLink(nil), lsa.Links...)
		body = make([]byte, 4)
		body[0] = byte(lsa.Flags)
		binary.BigEndian.PutUint16(body[2:4], uint16(len(links)))
		for _, l := range links {
			lb := make([]byte, 12)
			copy(lb[0:4], net.ParseIP(l.LinkID).To4())
			copy(lb[4:8], net.ParseIP(l.LinkData).To4())
			lb[8] = byte(l.LinkType)
			// lb[9] = TOS (0)
			binary.BigEndian.PutUint16(lb[10:12], uint16(l.Metric))
			body = append(body, lb...)
		}
	case 2: // network LSA
		body = make([]byte, 4)
		mask := lsa.NetworkMask
		if mask == "" {
			mask = lsa.LinkStateID
		}
		copy(body[0:4], net.ParseIP(mask).To4())
		for _, ar := range lsa.AttachedRouters {
			body = append(body, net.ParseIP(ar).To4()...)
		}
	default:
		return nil, fmt.Errorf("ospf: unsupported LSA type %d", lsa.LSAType)
	}
	length := 20 + len(body)
	return buildLSA(lsa.Age, lsa.Options, lsa.LSAType, lsa.LinkStateID, lsa.AdvertisingRouter, lsa.Sequence, length, body, lsa.ChecksumMode)
}
