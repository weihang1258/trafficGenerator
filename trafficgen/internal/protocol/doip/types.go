// Package doip implements the DOIP (Diagnostic over IP, ISO 13400-2) planner.
//
// DOIP is a vehicle diagnostic protocol over TCP/UDP port 13400. The
// planner emits PacketConfig values for each DOIP message (16 PayloadTypes
// 0x0000-0x8003), covering the full business flow: vehicle discovery (UDP),
// entity status (UDP), power mode (UDP), routing activation (TCP),
// diagnostic messages (TCP), alive check (TCP), and generic NACK (TCP/UDP).
//
// Wire format (all PayloadTypes share an 8-byte header):
//
//	+-----+-----+------+------+-------------+
//	| PV  | IPV | PT(2)| PL(4)| Payload(PL) |
//	+-----+-----+------+------+-------------+
//
// PV = ProtocolVersion (0x02 V2 default, 0x01 V1). IPV = ~PV & 0xFF.
// PT = PayloadType (u16 BE). PL = PayloadLength (u32 BE, payload bytes only).
//
// Direction "up" = Tester->ECU, "down" = ECU->Tester, "" = PayloadType default.
package doip

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// DoIP default constants per ISO 13400-2:2019.
const (
	// DefaultProtocolVersion is DoIP V2 (ISO 13400-2:2019, scapy ISO13400_2012).
	DefaultProtocolVersion uint8 = 0x02

	// ProtocolVersionV1 is DoIP V1 (ISO 13400-2:2010, scapy ISO13400_2010).
	ProtocolVersionV1 uint8 = 0x01

	// DefaultTCPPort is the DOIP TCP service port (ISO 13400-2:2019 section 7).
	DefaultTCPPort uint16 = 13400

	// DefaultUDPPort is the DOIP UDP service port (ISO 13400-2:2019 section 7).
	DefaultUDPPort uint16 = 13400

	// DefaultAnnouncementCount is the ISO 13400-2:2019 section 8.5.1 default of 3
	// 0x0004 Vehicle Announcement messages.
	DefaultAnnouncementCount uint8 = 3

	// DefaultLogicalAddress is the fallback ECU logical address.
	DefaultLogicalAddress uint16 = 0x0001

	// DefaultTesterAddress is the common Tester logical address
	// (0x0E80 = diagnostic tester).
	DefaultTesterAddress uint16 = 0x0E80

	// DefaultMaxDataSize is the MaxDataSize fallback when EntityStatus is
	// configured without an explicit MaxDataSize (matches section 3.2 default).
	DefaultMaxDataSize uint32 = 4095

	// DefaultMSS is the TCP MSS fallback (mirrors tcp/sip/rtsp DefaultMSS).
	DefaultMSS uint16 = 1460

	// MinMSS per RFC 879 (576-byte minimum packet -> 536-byte MSS).
	MinMSS uint16 = 536

	// DefaultTTL is the IP TTL fallback when FlowSpec.TTL is 0.
	DefaultTTL uint8 = 64

	// DoIPHeaderLen is the fixed 8-byte DoIP header length (section 2.1).
	DoIPHeaderLen = 8

	// VINLength is the fixed 17-byte VIN length (section 2.6/section 2.7).
	VINLength = 17

	// EIDLength is the fixed 6-byte EID length (section 2.5/section 2.7).
	EIDLength = 6

	// GIDLength is the fixed 6-byte GID length (section 2.7).
	GIDLength = 6
)

// PayloadType values per ISO 13400-2:2019 section 2.2 (16 entries).
const (
	PTGenericNack           uint16 = 0x0000 // Generic DoIP Header NACK
	PTVehicleIDRequest      uint16 = 0x0001 // Vehicle Identification Request
	PTVehicleIDRequestEID   uint16 = 0x0002 // Vehicle Identification Request with EID
	PTVehicleIDRequestVIN   uint16 = 0x0003 // Vehicle Identification Request with VIN
	PTVehicleAnnouncement   uint16 = 0x0004 // Vehicle Announcement/Identification Response
	PTRoutingActivationReq  uint16 = 0x0005 // Routing Activation Request
	PTRoutingActivationResp uint16 = 0x0006 // Routing Activation Response
	PTAliveCheckRequest     uint16 = 0x0007 // Alive Check Request
	PTAliveCheckResponse    uint16 = 0x0008 // Alive Check Response
	PTEntityStatusRequest   uint16 = 0x4001 // DoIP Entity Status Request (v2.0.0)
	PTEntityStatusResponse  uint16 = 0x4002 // DoIP Entity Status Response (v2.0.0)
	PTPowerModeRequest      uint16 = 0x4003 // Diagnostic Power Mode Request
	PTPowerModeResponse     uint16 = 0x4004 // Diagnostic Power Mode Response
	PTDiagnosticMessage     uint16 = 0x8001 // Diagnostic Message
	PTDiagnosticMessageAck  uint16 = 0x8002 // Diagnostic Message Ack
	PTDiagnosticMessageNack uint16 = 0x8003 // Diagnostic Message Nack
)

// Default directions per PayloadType (section 1.6/section 3.2). Empty Direction on a
// message falls back to these values.
const (
	dirUp   = "up"
	dirDown = "down"
)

// defaultDirection returns the default direction for a PayloadType per section 1.6.
// "up" = Tester->ECU (request), "down" = ECU->Tester (response/announcement).
func defaultDirection(pt uint16) string {
	switch pt {
	case PTGenericNack, PTVehicleAnnouncement, PTRoutingActivationResp,
		PTAliveCheckRequest, PTEntityStatusResponse, PTPowerModeResponse:
		return dirDown
	case PTVehicleIDRequest, PTVehicleIDRequestEID, PTVehicleIDRequestVIN,
		PTRoutingActivationReq, PTAliveCheckResponse, PTEntityStatusRequest,
		PTPowerModeRequest:
		return dirUp
	case PTDiagnosticMessage, PTDiagnosticMessageAck, PTDiagnosticMessageNack:
		// Bidirectional -- caller must specify or planner infers from context.
		return dirUp
	}
	return dirUp
}

// u16BE writes a u16 in big-endian order.
func u16BE(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// u32BE writes a u32 in big-endian order.
func u32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// inverseProtocolVersion returns ~PV & 0xFF per section 2.1.
func inverseProtocolVersion(pv uint8) uint8 { return ^pv & 0xFF }

// ipv4Broadcast is the IPv4 limited broadcast address (section 3.3).
const ipv4Broadcast = "255.255.255.255"

// ipv4BroadcastMAC is the IPv4 broadcast MAC.
const ipv4BroadcastMAC = "ff:ff:ff:ff:ff:ff"

// ipv6AllNodesMulticast is the IPv6 all-nodes multicast (section 3.3).
const ipv6AllNodesMulticast = "ff02::1"

// ipv6MulticastMACPrefix is the RFC 2464 section 7 multicast MAC prefix.
const ipv6MulticastMACPrefix = "33:33:"

// ipv6MulticastMAC returns the RFC 2464 section 7 MAC for an IPv6 multicast address
// (last 32 bits of the address appended to 33:33:).
func ipv6MulticastMAC(multicastAddr string) string {
	ip := parseIPv6(multicastAddr)
	if ip == nil {
		return ipv6MulticastMACPrefix + "00:00:00:01"
	}
	b := ip.To16()
	return ipv6MulticastMACPrefix +
		hexByte(b[12]) + ":" + hexByte(b[13]) + ":" + hexByte(b[14]) + ":" + hexByte(b[15])
}

// hexByte formats a byte as two hex digits (uppercase).
func hexByte(b byte) string { return fmt.Sprintf("%02X", b) }

// parseIPv6 parses an IPv6 address string (wrapper around net.ParseIP for
// consistent IPv6 handling).
func parseIPv6(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if ip.To4() != nil {
		return nil
	}
	return ip
}

// isIPv6 returns true if the address string is IPv6.
func isIPv6(s string) bool { return parseIPv6(s) != nil }

// parseMAC parses a MAC address string (with or without colons) into a
// 6-byte slice. Returns nil on failure.
func parseMAC(mac string) []byte {
	if mac == "" {
		return nil
	}
	// Remove colons.
	s := strings.ReplaceAll(mac, ":", "")
	if len(s) != 12 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 6 {
		return nil
	}
	return b
}

// formatMAC formats a 6-byte MAC address as colon-separated hex.
func formatMAC(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

// normalizeDirection normalizes a direction string per section 1.6 (case-insensitive).
func normalizeDirection(dir string) string {
	switch strings.ToLower(dir) {
	case dirUp:
		return dirUp
	case dirDown:
		return dirDown
	default:
		return dir
	}
}
