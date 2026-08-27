package bgp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

type BGPConfig = core.BGPConfig

const (
	defaultVersion    = 4
	defaultASN        = 64512
	defaultHoldTime   = 90
	defaultIdentifier = "192.0.2.1"
	defaultProfile    = "bgp_rfc4271_ipv4_unicast"
	bgpHeaderLen      = 19
	bgpMaxLen         = 4096
)

func normalized(c *BGPConfig) BGPConfig {
	v := *c
	if v.Version == 0 {
		v.Version = defaultVersion
	}
	if v.ASN == 0 {
		v.ASN = defaultASN
	}
	if v.HoldTime == 0 { /* zero is valid and remains explicit */
	}
	if v.Identifier == "" {
		v.Identifier = defaultIdentifier
	}
	if v.WireProfile == "" {
		v.WireProfile = defaultProfile
	}
	return v
}

func ValidateConfig(c *BGPConfig) error {
	if c == nil {
		return fmt.Errorf("bgp: config is required")
	}
	v := normalized(c)
	if v.Version != 4 {
		return fmt.Errorf("bgp: version %d unsupported; only version 4 is supported", v.Version)
	}
	if v.ASN > 65535 {
		return fmt.Errorf("bgp: ASN %d exceeds two-octet range", v.ASN)
	}
	if ip := net.ParseIP(v.Identifier); ip == nil || ip.To4() == nil || ip.Equal(net.IPv4zero) {
		return fmt.Errorf("bgp: identifier %q must be a non-zero IPv4 address", v.Identifier)
	}
	if v.WireProfile != defaultProfile {
		return fmt.Errorf("bgp: profile %q unsupported", v.WireProfile)
	}
	if len(v.Capabilities) != 0 {
		return fmt.Errorf("bgp: capabilities are unsupported")
	}
	if len(v.Update) != 0 {
		return fmt.Errorf("bgp: UPDATE configuration is unsupported")
	}
	if len(v.Notification) != 0 {
		return fmt.Errorf("bgp: NOTIFICATION configuration is unsupported")
	}
	if len(v.Marker) != 0 && len(v.Marker) != 16 {
		return fmt.Errorf("bgp: marker must be 16 bytes")
	}
	for _, b := range v.Marker {
		if b != 0xff {
			return fmt.Errorf("bgp: marker must be all ones")
		}
	}
	if v.Length != 0 && (v.Length < bgpHeaderLen || v.Length > bgpMaxLen) {
		return fmt.Errorf("bgp: length %d outside 19..4096", v.Length)
	}
	return nil
}

func BuildOpen(c *BGPConfig) ([]byte, error) {
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	v := normalized(c)
	b := make([]byte, bgpHeaderLen+10)
	for i := range b[:16] {
		b[i] = 0xff
	}
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)))
	b[18] = 1
	b[19] = v.Version
	binary.BigEndian.PutUint16(b[20:22], uint16(v.ASN))
	binary.BigEndian.PutUint16(b[22:24], v.HoldTime)
	copy(b[24:28], net.ParseIP(v.Identifier).To4())
	b[28] = 0
	return b, nil
}

func BuildKeepalive() ([]byte, error) {
	b := make([]byte, bgpHeaderLen)
	for i := range b[:16] {
		b[i] = 0xff
	}
	binary.BigEndian.PutUint16(b[16:18], bgpHeaderLen)
	b[18] = 4
	return b, nil
}
