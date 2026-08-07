// Package tftp implements TFTP wire-format packet parsing.
package tftp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ParsedPacket is the result of parsing a TFTP wire-format packet.
// Only the fields relevant to the opcode are populated.
type ParsedPacket struct {
	Opcode   uint16
	Filename string // RRQ/WRQ only
	Mode     string // RRQ/WRQ only
	BlockNum uint16 // DATA/ACK only
	Data     []byte // DATA only (references the input buffer)
	ErrCode  uint8  // ERROR only
	ErrorMsg string // ERROR only (without trailing NUL)
	Options  map[string]string // RRQ/WRQ/OACK options (lowercase names)
}

// ErrShortPacket is returned when a packet is too short to contain the
// minimum TFTP header (2-byte opcode).
var ErrShortPacket = errors.New("tftp: packet too short for opcode")

// ErrTruncated is returned when a packet ends unexpectedly mid-field.
var ErrTruncated = errors.New("tftp: packet truncated mid-field")

// Parse parses a TFTP wire-format packet. It does NOT copy the DATA payload
// for DATA packets — the returned Data slice references the input buffer.
// Callers that need to retain the data across buffer reuse should copy it.
func Parse(pkt []byte) (*ParsedPacket, error) {
	if len(pkt) < 2 {
		return nil, ErrShortPacket
	}
	opcode := binary.BigEndian.Uint16(pkt[0:2])
	p := &ParsedPacket{Opcode: opcode}
	rest := pkt[2:]
	switch opcode {
	case OpRRQ, OpWRQ:
		return parseRRQWRQ(p, rest)
	case OpDATA:
		return parseDATA(p, rest)
	case OpACK:
		return parseACK(p, rest)
	case OpERROR:
		return parseERROR(p, rest)
	case OpOACK:
		return parseOACK(p, rest)
	default:
		return nil, fmt.Errorf("tftp: unknown opcode %d", opcode)
	}
}

// parseRRQWRQ parses the body of an RRQ/WRQ: filename\0 mode\0 [opt\0 val\0]...
func parseRRQWRQ(p *ParsedPacket, rest []byte) (*ParsedPacket, error) {
	fields, err := splitCStrings(rest)
	if err != nil {
		return nil, err
	}
	if len(fields) < 2 {
		return nil, fmt.Errorf("tftp: RRQ/WRQ requires filename and mode, got %d fields", len(fields))
	}
	p.Filename = fields[0]
	p.Mode = fields[1]
	if len(fields) > 2 {
		p.Options = make(map[string]string, (len(fields)-2)/2)
		for i := 2; i+1 < len(fields); i += 2 {
			p.Options[lowerASCII(fields[i])] = fields[i+1]
		}
	}
	return p, nil
}

// parseDATA parses the body of a DATA packet: Block#(2) + Data(0..blksize).
func parseDATA(p *ParsedPacket, rest []byte) (*ParsedPacket, error) {
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	p.BlockNum = binary.BigEndian.Uint16(rest[0:2])
	p.Data = rest[2:]
	return p, nil
}

// parseACK parses the body of an ACK packet: Block#(2).
func parseACK(p *ParsedPacket, rest []byte) (*ParsedPacket, error) {
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	p.BlockNum = binary.BigEndian.Uint16(rest[0:2])
	return p, nil
}

// parseERROR parses the body of an ERROR packet: ErrCode(2) + ErrMsg\0.
func parseERROR(p *ParsedPacket, rest []byte) (*ParsedPacket, error) {
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	p.ErrCode = uint8(rest[1])
	msg := rest[2:]
	// ErrMsg is NUL-terminated; strip the terminator if present.
	if n := indexByte(msg, 0); n >= 0 {
		p.ErrorMsg = string(msg[:n])
	} else {
		p.ErrorMsg = string(msg)
	}
	return p, nil
}

// parseOACK parses the body of an OACK packet: [opt\0 val\0]...
func parseOACK(p *ParsedPacket, rest []byte) (*ParsedPacket, error) {
	fields, err := splitCStrings(rest)
	if err != nil {
		return nil, err
	}
	if len(fields)%2 != 0 {
		return nil, fmt.Errorf("tftp: OACK has odd number of fields (%d)", len(fields))
	}
	if len(fields) > 0 {
		p.Options = make(map[string]string, len(fields)/2)
		for i := 0; i+1 < len(fields); i += 2 {
			p.Options[lowerASCII(fields[i])] = fields[i+1]
		}
	}
	return p, nil
}

// splitCStrings splits a byte buffer at NUL bytes into a list of strings.
// The final field need not be NUL-terminated (lenient parse), but an empty
// buffer yields an empty slice.
func splitCStrings(buf []byte) ([]string, error) {
	var fields []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			fields = append(fields, string(buf[start:i]))
			start = i + 1
		}
	}
	if start < len(buf) {
		// Trailing field without NUL — include it for leniency.
		fields = append(fields, string(buf[start:]))
	}
	return fields, nil
}

// indexByte returns the index of the first occurrence of b in buf, or -1.
func indexByte(buf []byte, b byte) int {
	for i := 0; i < len(buf); i++ {
		if buf[i] == b {
			return i
		}
	}
	return -1
}

// lowerASCII returns the lowercase ASCII form of s (RFC 2347 case-insensitive).
func lowerASCII(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
