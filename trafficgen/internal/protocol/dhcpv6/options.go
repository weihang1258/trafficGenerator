// Package dhcpv6 implements the DHCPv6 protocol planner (RFC 8415).
// This file contains helper functions for building DHCPv6 option bytes
// used by testpoints tests. These functions are shared between the planner
// and the test suite.

package dhcpv6

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IAAddress represents an IA Address sub-option (option 5) data.
// See RFC 8415 §21.6.
type IAAddress struct {
	IPv6Addr string // IPv6 地址
	Preferred uint32 // Preferred lifetime (首选有效期)
	Valid uint32 // Valid lifetime (有效有效期)
}

// IAPrefix represents an IA Prefix sub-option (option 26) data.
// See RFC 8415 §21.22.
type IAPrefix struct {
	Preferred uint32 // Preferred lifetime (首选有效期)
	Valid uint32 // Valid lifetime (有效有效期)
	Prefix string // IPv6 前缀
	PrefixLen uint8 // 前缀长度
}

// BuildIA_NA builds the wire bytes for an OPTION_IA_NA (option 3).
// data = IAID(4) + T1(4) + T2(4) + [sub-options].
func BuildIA_NA(iaid, t1, t2 uint32, subOptions []byte) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], iaid)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], t1)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], t2)
	buf = append(buf, b4[:]...)
	buf = append(buf, subOptions...)
	return buf
}

// BuildIA_TA builds the wire bytes for an OPTION_IA_TA (option 4).
// data = IAID(4) + [sub-options].
func BuildIA_TA(iaid uint32, subOptions []byte) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], iaid)
	buf = append(buf, b4[:]...)
	buf = append(buf, subOptions...)
	return buf
}

// BuildIAAddress builds the wire bytes for an OPTION_IAADDR (option 5).
// data = IPv6(16) + preferred(4) + valid(4) + [sub-options].
func BuildIAAddress(addr IAAddress, subOptions []byte) []byte {
	var buf []byte
	ip := net.ParseIP(addr.IPv6Addr)
	if ip == nil {
		// Fallback: all-zero
		ip = net.IPv6zero
	}
	ip16 := ip.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	buf = append(buf, ip16...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], addr.Preferred)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], addr.Valid)
	buf = append(buf, b4[:]...)
	buf = append(buf, subOptions...)
	return buf
}

// BuildORO builds the wire bytes for an OPTION_ORO (option 6).
// data = list of 2-byte option codes.
func BuildORO(codes []uint16) []byte {
	buf := make([]byte, 0, len(codes)*2)
	var b2 [2]byte
	for _, c := range codes {
		binary.BigEndian.PutUint16(b2[:], c)
		buf = append(buf, b2[:]...)
	}
	return buf
}

// BuildPreference builds the wire bytes for an OPTION_PREFERENCE (option 7).
// data = 1 byte.
func BuildPreference(val uint8) []byte {
	return []byte{val}
}

// BuildElapsedTime builds the wire bytes for an OPTION_ELAPSED_TIME (option 8).
// data = 2 bytes, in centiseconds (1/100 second).
func BuildElapsedTime(val uint16) []byte {
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], val)
	return b2[:]
}

// BuildRelayMessage builds the wire bytes for an OPTION_RELAY_MSG (option 9).
// data = encapsulated message bytes.
func BuildRelayMessage(innerMsg []byte) []byte {
	return innerMsg
}

// BuildRapidCommit builds the wire bytes for an OPTION_RAPID_COMMIT (option 14).
// data = empty.
func BuildRapidCommit() []byte {
	return nil
}

// BuildStatusCode builds the wire bytes for an OPTION_STATUS_CODE (option 13).
// data = status-code(2) + status-message(variable).
func BuildStatusCode(status uint16, message string) []byte {
	var buf []byte
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], status)
	buf = append(buf, b2[:]...)
	buf = append(buf, []byte(message)...)
	return buf
}

// BuildRDNSS builds the wire bytes for an OPTION_RDNSS (option 23).
// data = lifetime(4) + IPv6-addresses(variable, 16 bytes each).
func BuildRDNSS(lifetime uint32, servers []string) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], lifetime)
	buf = append(buf, b4[:]...)
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		ip16 := ip.To16()
		if ip16 != nil {
			buf = append(buf, ip16...)
		}
	}
	return buf
}

// BuildDNSSL builds the wire bytes for an OPTION_DNSSL (option 24).
// data = lifetime(4) + domain-names(variable, DNS wire format).
func BuildDNSSL(lifetime uint32, domains []string) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], lifetime)
	buf = append(buf, b4[:]...)
	for _, domain := range domains {
		buf = append(buf, encodeDNSName(domain)...)
	}
	return buf
}

// encodeDNSName encodes a domain name in DNS wire format (label-length prefixed).
func encodeDNSName(name string) []byte {
	if name == "" {
		return []byte{0x00}
	}
	var buf []byte
	labels := splitLabels(name)
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)
	return buf
}

// splitLabels splits a domain name into labels.
func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

// BuildIA_PD builds the wire bytes for an OPTION_IA_PD (option 25).
// data = IAID(4) + T1(4) + T2(4) + [sub-options].
func BuildIA_PD(iaid, t1, t2 uint32, subOptions []byte) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], iaid)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], t1)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], t2)
	buf = append(buf, b4[:]...)
	buf = append(buf, subOptions...)
	return buf
}

// BuildIAPrefix builds the wire bytes for an OPTION_IAPREFIX (option 26).
// data = preferred(4) + valid(4) + prefix-IPv6(16) + prefix-len(1).
func BuildIAPrefix(prefix IAPrefix) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], prefix.Preferred)
	buf = append(buf, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], prefix.Valid)
	buf = append(buf, b4[:]...)
	ip := net.ParseIP(prefix.Prefix)
	if ip == nil {
		ip = net.IPv6zero
	}
	ip16 := ip.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	buf = append(buf, ip16...)
	buf = append(buf, prefix.PrefixLen)
	return buf
}

// BuildFQDN builds the wire bytes for an OPTION_FQDN (option 39).
// data = flags(1) + domain-name(wire format).
func BuildFQDN(flags uint8, domain string) []byte {
	buf := []byte{flags}
	buf = append(buf, encodeDNSName(domain)...)
	return buf
}

// BuildClientLinkLayerAddr builds the wire bytes for option 79.
// data = link-layer-type(2) + link-layer-addr(variable).
func BuildClientLinkLayerAddr(linkLayerType uint16, addr []byte) []byte {
	var buf []byte
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], linkLayerType)
	buf = append(buf, b2[:]...)
	buf = append(buf, addr...)
	return buf
}

// BuildUserClass builds the wire bytes for OPTION_USER_CLASS (option 16).
// data = opaque-data-length(2) + opaque-data(variable) repeated.
func BuildUserClass(data [][]byte) []byte {
	var buf []byte
	for _, d := range data {
		var b2 [2]byte
		binary.BigEndian.PutUint16(b2[:], uint16(len(d)))
		buf = append(buf, b2[:]...)
		buf = append(buf, d...)
	}
	return buf
}

// BuildVendorClass builds the wire bytes for OPTION_VENDOR_CLASS (option 17).
// data = enterprise-number(4) + opaque-data-length(2) + opaque-data(variable) repeated.
func BuildVendorClass(enterpriseNum uint32, data [][]byte) []byte {
	var buf []byte
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], enterpriseNum)
	buf = append(buf, b4[:]...)
	for _, d := range data {
		var b2 [2]byte
		binary.BigEndian.PutUint16(b2[:], uint16(len(d)))
		buf = append(buf, b2[:]...)
		buf = append(buf, d...)
	}
	return buf
}

// BuildInterfaceID builds the wire bytes for OPTION_INTERFACE_ID (option 18).
func BuildInterfaceID(data []byte) []byte {
	return data
}

// BuildReconfMsg builds the wire bytes for OPTION_RECONF_MSG (option 19).
func BuildReconfMsg(msgType uint8) []byte {
	return []byte{msgType}
}

// BuildSNTPServers builds the wire bytes for OPTION_SNTP (option 31).
// data = list of IPv6 addresses (16 bytes each).
func BuildSNTPServers(servers []string) []byte {
	var buf []byte
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		ip16 := ip.To16()
		if ip16 != nil {
			buf = append(buf, ip16...)
		}
	}
	return buf
}

// BuildInfoRefreshTime builds the wire bytes for OPTION_INFORMATION_REFRESH_TIME (option 32).
func BuildInfoRefreshTime(refreshTime uint32) []byte {
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], refreshTime)
	return b4[:]
}

// ValidateIAAddrPreferredValid validates that preferred <= valid for an IA Address.
// Returns error if preferred > valid (RFC 8415 §21.6).
func ValidateIAAddrPreferredValid(preferred, valid uint32) error {
	if preferred > valid {
		return fmt.Errorf("IA Address: preferred-lifetime %d > valid-lifetime %d (must be <=)", preferred, valid)
	}
	return nil
}

// ValidateIAPrefixPreferredValid validates that preferred <= valid for an IA Prefix.
// Returns error if preferred > valid (RFC 8415 §21.22).
func ValidateIAPrefixPreferredValid(preferred, valid uint32) error {
	if preferred > valid {
		return fmt.Errorf("IA Prefix: preferred-lifetime %d > valid-lifetime %d (must be <=)", preferred, valid)
	}
	return nil
}

// ValidateIAPrefixLen validates that prefix-len is 0-128.
func ValidateIAPrefixLen(prefixLen uint8) error {
	if prefixLen > 128 {
		return fmt.Errorf("IA Prefix: prefix-len %d > 128 (max 128)", prefixLen)
	}
	return nil
}