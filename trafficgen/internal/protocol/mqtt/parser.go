// Package mqtt implements the MQTT protocol planner.
package mqtt

import (
	"fmt"
)

// parsedPacket is the result of parsing one MQTT control packet from a
// byte stream.
type parsedPacket struct {
	Type         byte   // packet type (high nibble of first byte)
	Flags        byte   // flags (low nibble of first byte)
	RemainingLen int    // decoded remaining length
	Body         []byte // the bytes after the fixed header
}

// parseMQTTPacket parses the fixed header of a single MQTT packet from the
// given bytes. Returns the parsed header and the number of bytes consumed by
// the fixed header (1 type byte + VBI length). The caller is responsible for
// verifying that at least RemainingLength bytes follow.
func parseMQTTPacket(data []byte) (*parsedPacket, int, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("mqtt: packet too short")
	}
	first := data[0]
	rl, n, err := decodeVBI(data[1:])
	if err != nil {
		return nil, 0, fmt.Errorf("mqtt: bad remaining length: %w", err)
	}
	if len(data) < 1+n+rl {
		return nil, 0, fmt.Errorf("mqtt: truncated packet (need %d bytes, have %d)", 1+n+rl, len(data))
	}
	return &parsedPacket{
		Type:         first >> 4,
		Flags:        first & 0x0f,
		RemainingLen: rl,
		Body:         data[1+n : 1+n+rl],
	}, 1 + n, nil
}

// parseConnectFlags decodes the CONNECT flags byte into its named bits.
// Returns username, password, willRetain, willQoS, willFlag, cleanSession.
func parseConnectFlags(flags byte) (username, password, willRetain, willFlag, cleanSession bool, willQoS int) {
	username = flags&0x80 != 0
	password = flags&0x40 != 0
	willRetain = flags&0x20 != 0
	willQoS = int(flags>>3) & 0x03
	willFlag = flags&0x04 != 0
	cleanSession = flags&0x02 != 0
	return
}

// parseUTF8String decodes a 2-byte length-prefixed UTF-8 string at the start
// of data. Returns the string and the number of bytes consumed.
func parseUTF8String(data []byte) (string, int, error) {
	if len(data) < 2 {
		return "", 0, fmt.Errorf("mqtt: truncated string length")
	}
	l := int(data[0])<<8 | int(data[1])
	if len(data) < 2+l {
		return "", 0, fmt.Errorf("mqtt: truncated string body")
	}
	return string(data[2 : 2+l]), 2 + l, nil
}

// parsePacketID reads a 2-byte big-endian packet identifier.
func parsePacketID(data []byte) (uint16, int, error) {
	if len(data) < 2 {
		return 0, 0, fmt.Errorf("mqtt: truncated packet id")
	}
	return uint16(data[0])<<8 | uint16(data[1]), 2, nil
}
