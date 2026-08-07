// Package rip implements the RIP (RFC 1058 / RFC 2453 / RFC 2080 / RFC 4822) protocol planner.
package rip

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RIPHeader represents the parsed 4-byte RIP header.
type RIPHeader struct {
	Command uint8
	Version uint8
	Domain  uint16
}

// RIPv1Entry represents a parsed 20-byte RIPv1 route entry.
type RIPv1Entry struct {
	AFI    uint16
	IPAddr string
	Metric uint32
}

// RIPv2Entry represents a parsed 20-byte RIPv2 route entry.
type RIPv2Entry struct {
	AFI        uint16
	RouteTag   uint16
	IPAddr     string
	SubnetMask string
	NextHop    string
	Metric     uint32
}

// RIPngEntry represents a parsed 20-byte RIPng route entry.
type RIPngEntry struct {
	IPAddr    string
	RouteTag  uint16
	PrefixLen uint8
	Metric    uint8
}

// SimpleAuthEntry represents a parsed simple authentication entry.
type SimpleAuthEntry struct {
	AuthType uint16
	Password string
}

// MD5AuthEntry represents a parsed MD5 authentication entry.
type MD5AuthEntry struct {
	AuthType       uint16
	PacketLength   uint16
	KeyID          uint8
	AuthDataLen    uint8
	SequenceNumber uint32
}

// MD5Trailer represents a parsed MD5 trailer.
type MD5Trailer struct {
	AuthMarker uint16
	Type       uint16
	Digest     []byte
}

// ParseRIPHeader parses the 4-byte RIP header.
func ParseRIPHeader(data []byte) (*RIPHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("RIP header too short: %d bytes", len(data))
	}
	return &RIPHeader{
		Command: data[0],
		Version: data[1],
		Domain:  binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// ParseRIPv1Entry parses a 20-byte RIPv1 route entry.
func ParseRIPv1Entry(data []byte) (*RIPv1Entry, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("RIPv1 entry too short: %d bytes", len(data))
	}
	return &RIPv1Entry{
		AFI:    binary.BigEndian.Uint16(data[0:2]),
		IPAddr: net.IP(data[4:8]).String(),
		Metric: binary.BigEndian.Uint32(data[16:20]),
	}, nil
}

// ParseRIPv2Entry parses a 20-byte RIPv2 route entry.
func ParseRIPv2Entry(data []byte) (*RIPv2Entry, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("RIPv2 entry too short: %d bytes", len(data))
	}
	return &RIPv2Entry{
		AFI:        binary.BigEndian.Uint16(data[0:2]),
		RouteTag:   binary.BigEndian.Uint16(data[2:4]),
		IPAddr:     net.IP(data[4:8]).String(),
		SubnetMask: net.IP(data[8:12]).String(),
		NextHop:    net.IP(data[12:16]).String(),
		Metric:     binary.BigEndian.Uint32(data[16:20]),
	}, nil
}

// ParseRIPngEntry parses a 20-byte RIPng route entry.
func ParseRIPngEntry(data []byte) (*RIPngEntry, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("RIPng entry too short: %d bytes", len(data))
	}
	return &RIPngEntry{
		IPAddr:    net.IP(data[0:16]).String(),
		RouteTag:  binary.BigEndian.Uint16(data[16:18]),
		PrefixLen: data[18],
		Metric:    data[19],
	}, nil
}

// ParseSimpleAuthEntry parses a 20-byte simple authentication entry.
func ParseSimpleAuthEntry(data []byte) (*SimpleAuthEntry, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("simple auth entry too short: %d bytes", len(data))
	}
	pwd := make([]byte, 16)
	copy(pwd, data[4:20])
	// Trim trailing zero padding
	n := len(pwd)
	for n > 0 && pwd[n-1] == 0 {
		n--
	}
	return &SimpleAuthEntry{
		AuthType: binary.BigEndian.Uint16(data[2:4]),
		Password: string(pwd[:n]),
	}, nil
}

// ParseMD5AuthEntry parses a 20-byte MD5 authentication entry.
func ParseMD5AuthEntry(data []byte) (*MD5AuthEntry, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("MD5 auth entry too short: %d bytes", len(data))
	}
	return &MD5AuthEntry{
		AuthType:       binary.BigEndian.Uint16(data[2:4]),
		PacketLength:   binary.BigEndian.Uint16(data[4:6]),
		KeyID:          data[6],
		AuthDataLen:    data[7],
		SequenceNumber: binary.BigEndian.Uint32(data[8:12]),
	}, nil
}

// ParseMD5Trailer parses the MD5 trailer (header + digest).
func ParseMD5Trailer(data []byte, authDataLen int) (*MD5Trailer, error) {
	expectedLen := 4 + authDataLen
	if len(data) < expectedLen {
		return nil, fmt.Errorf("MD5 trailer too short: %d bytes, expected %d", len(data), expectedLen)
	}
	digest := make([]byte, authDataLen)
	copy(digest, data[4:4+authDataLen])
	return &MD5Trailer{
		AuthMarker: binary.BigEndian.Uint16(data[0:2]),
		Type:       binary.BigEndian.Uint16(data[2:4]),
		Digest:     digest,
	}, nil
}

// CountRouteEntries returns the number of 20-byte route entries in the payload
// (excluding the 4-byte header).
func CountRouteEntries(payload []byte) int {
	if len(payload) < 4 {
		return 0
	}
	return (len(payload) - 4) / 20
}

// IsAuthenticated checks if the first route entry is an authentication entry.
func IsAuthenticated(payload []byte) bool {
	if len(payload) < 24 { // 4-byte header + at least 20-byte entry
		return false
	}
	afi := binary.BigEndian.Uint16(payload[4:6])
	return afi == AFIAuth
}

// GetAuthType returns the authentication type from the first entry.
// Returns 0 if not authenticated.
func GetAuthType(payload []byte) uint16 {
	if !IsAuthenticated(payload) {
		return 0
	}
	return binary.BigEndian.Uint16(payload[6:8])
}
