package gbt32960

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Message represents a parsed GBT32960 wire message (design §2.1).
type Message struct {
	Cmd         byte   // command unit
	Resp        byte   // response flag
	VIN         []byte // 17 bytes (raw, including pad bytes)
	Encrypt     byte   // encrypt rule
	Data        []byte // data unit (may be empty)
	BCC         byte   // BCC byte as read from the wire
	BCCOk       bool   // whether the recomputed BCC matches
	HeaderLen   int    // 24
	TotalLen    int    // 25 + len(Data)
	StartFlagOk bool   // whether the start flag is 0x23 0x23
}

// ParseMessage parses a single GBT32960 message from buf. It returns the
// parsed Message and the number of bytes consumed (25 + len(Data)), or
// an error if buf is too short or malformed. It does NOT require the
// BCC to be correct — the BCCOk field reports whether it matches
// (design §2.4).
func ParseMessage(buf []byte) (*Message, int, error) {
	if len(buf) < HeaderLen+BCCLen {
		return nil, 0, fmt.Errorf("gbt32960: buffer too short (%d bytes, min %d)", len(buf), HeaderLen+BCCLen)
	}
	m := &Message{HeaderLen: HeaderLen}
	if buf[0] != StartFlag0 || buf[1] != StartFlag1 {
		m.StartFlagOk = false
	} else {
		m.StartFlagOk = true
	}
	m.Cmd = buf[2]
	m.Resp = buf[3]
	m.VIN = make([]byte, VINLen)
	copy(m.VIN, buf[4:4+VINLen])
	m.Encrypt = buf[21]
	dataLen := int(binary.BigEndian.Uint16(buf[22:24]))
	if dataLen > DataUnitMaxLen {
		return nil, 0, fmt.Errorf("gbt32960: data length %d exceeds %d (reserved range)", dataLen, DataUnitMaxLen)
	}
	consumed := HeaderLen + dataLen + BCCLen
	if len(buf) < consumed {
		return nil, 0, fmt.Errorf("gbt32960: buffer too short for data unit (%d needed, %d available)", consumed, len(buf))
	}
	m.Data = make([]byte, dataLen)
	copy(m.Data, buf[HeaderLen:HeaderLen+dataLen])
	m.BCC = buf[HeaderLen+dataLen]
	m.TotalLen = consumed
	// BCC covers bytes [2 .. 24+N-1] = buf[2 : 24+N] (cmd through last data byte).
	expected := bccXOR(buf[2 : HeaderLen+dataLen])
	m.BCCOk = expected == m.BCC
	return m, consumed, nil
}

// SplitMessages splits a TCP stream buffer into a list of complete
// GBT32960 messages. It stops at the first byte that does not begin a
// valid message (e.g. a non-0x23 byte after a complete message). It
// returns the messages parsed and the number of bytes consumed.
func SplitMessages(buf []byte) ([]*Message, int, error) {
	var msgs []*Message
	consumed := 0
	for consumed < len(buf) {
		if buf[consumed] != StartFlag0 {
			break
		}
		if consumed+1 >= len(buf) || buf[consumed+1] != StartFlag1 {
			break
		}
		m, n, err := ParseMessage(buf[consumed:])
		if err != nil {
			return msgs, consumed, err
		}
		msgs = append(msgs, m)
		consumed += n
	}
	return msgs, consumed, nil
}

// DecodeBCDTime decodes a 6-byte BCD `YYMMDDHHMMSS` into a time.Time
// using the given location (design §4.5). Year is interpreted as
// 2000+YY (i.e. 26 → 2026). The location should reflect the timezone
// the BCD was encoded in (e.g. time.FixedZone("CST", 8*3600) for GMT+8).
func DecodeBCDTime(bcd []byte, loc *time.Location) (time.Time, error) {
	if len(bcd) != 6 {
		return time.Time{}, fmt.Errorf("gbt32960: BCD time length %d != 6", len(bcd))
	}
	yy := bcdToDec(bcd[0])
	mm := bcdToDec(bcd[1])
	dd := bcdToDec(bcd[2])
	hh := bcdToDec(bcd[3])
	min := bcdToDec(bcd[4])
	ss := bcdToDec(bcd[5])
	if mm < 1 || mm > 12 {
		return time.Time{}, fmt.Errorf("gbt32960: BCD month %d out of range", mm)
	}
	if dd < 1 || dd > 31 {
		return time.Time{}, fmt.Errorf("gbt32960: BCD day %d out of range", dd)
	}
	if hh > 23 || min > 59 || ss > 60 {
		return time.Time{}, fmt.Errorf("gbt32960: BCD time %02d:%02d:%02d out of range", hh, min, ss)
	}
	year := 2000 + yy
	if loc == nil {
		loc = time.UTC
	}
	return time.Date(year, time.Month(mm), dd, hh, min, ss, 0, loc), nil
}

func bcdToDec(b byte) int {
	return int(b>>4)*10 + int(b&0x0f)
}

// ErrNoMessage is returned by ParseStream when no complete message is
// available in the buffer.
var ErrNoMessage = errors.New("gbt32960: no complete message in buffer")
