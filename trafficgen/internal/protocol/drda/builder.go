package drda

import (
	"encoding/binary"
	"fmt"
)

// DRDA code points (design §3.3).
const (
	CPEXCSAT    = 0x1041 // Exchange Server Attributes
	CPEXCSATRD  = 0x1443 // EXCSAT response
	CPACCSEC    = 0x106d // Access Security
	CPACCSECRD  = 0x14ac // ACCSEC response
	CPSECCHK    = 0x106e // Security Check
	CPSECCHKRM  = 0x1219 // Security check result
	CPACCRDB    = 0x2001 // Associate RDB
	CPACCRDBRM  = 0x2201 // ACCRDB result
	CPSQLDTA    = 0x2412 // SQL data
	CPSQLCARD   = 0x2408 // SQL result
	CPSQLSTT    = 0x2414 // SQL statement
)

// DDM header magic/format (§3.1).
const (
	DDMMagic     = 0xd0
	DDMFormat    = 0x01
	DDMChained   = 0x41 // chained first DDM
)

// maxDDMLength caps a single DDM object length (16-bit length field).
const maxDDMLength = 0xffff

// ddmBuild assembles one DDM object: length(2) + magic(1) + format(1) +
// correlator(2) + length2(2) + code_point(2) + parameters. Each parameter is
// length(2) + code_point(2) + data. length2 starts counting from the code
// point (§3.1: length2 = length - 6)。
func ddmBuild(format byte, correlator uint16, codePoint uint16, params [][]byte, chained bool) ([]byte, error) {
	formatByte := format
	if formatByte == 0 {
		formatByte = DDMFormat
	}
	if chained {
		formatByte = DDMChained
	}
	var body []byte
	for _, p := range params {
		if len(p) < 4 {
			return nil, fmt.Errorf("drda: parameter shorter than 4 bytes")
		}
		if len(p) > maxDDMLength {
			return nil, fmt.Errorf("drda: parameter exceeds max DDM length")
		}
		body = append(body, p...)
	}
	total := 10 + len(body)
	if total < 10 || total > maxDDMLength {
		return nil, fmt.Errorf("drda: DDM length %d out of range [10,%d]", total, maxDDMLength)
	}
	length2 := 4 + len(body) // code_point(2) + params
	b := make([]byte, 0, total)
	b = append16(b, uint16(total))
	b = append(b, DDMMagic, formatByte)
	b = append16(b, correlator)
	b = append16(b, uint16(length2))
	b = append16(b, codePoint)
	b = append(b, body...)
	return b, nil
}

// param builds a parameter entry: length(2) + code_point(2) + data。
func param(codePoint uint16, data []byte) ([]byte, error) {
	if len(data) > maxDDMLength {
		return nil, fmt.Errorf("drda: parameter data exceeds max DDM length")
	}
	total := 4 + len(data)
	b := make([]byte, 0, total)
	b = append16(b, uint16(total))
	b = append16(b, codePoint)
	b = append(b, data...)
	return b, nil
}

// u16enc encodes a big-endian uint16 into a parameter data blob.
func u16enc(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// u32enc encodes a big-endian uint32 (input as int32 for signed SQLCODE).
func u32enc(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func append16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}