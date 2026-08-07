package dnp3

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/trafficgen/trafficgen/internal/core"
)

// CRC16 computes CRC-16/DNP (poly 0x3D65 reflected, xorout 0xFFFF).
func CRC16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFF
}

// BuildControl constructs a DNP3 link control byte.
func BuildControl(dir, prm, fcb, fcv bool, function uint8) byte {
	var c byte
	if dir { c |= 0x80 }
	if prm { c |= 0x40 }
	if fcb { c |= 0x20 }
	if fcv { c |= 0x10 }
	return c | function&0x0F
}

// BuildAppControl constructs FIR/FIN/CON/AppSeq.
func BuildAppControl(fir, fin, con bool, seq uint8) byte {
	var c byte
	if fir { c |= 0x80 }
	if fin { c |= 0x40 }
	if con { c |= 0x20 }
	return c | seq&0x0F
}

// BuildLinkFrame constructs header and independently CRC-protected 16-byte blocks.
func BuildLinkFrame(control byte, dst, src uint16, data []byte) ([]byte, error) {
	blocksLen := len(data) + 2*((len(data)+15)/16)
	if blocksLen > MaxLinkLength {
		return nil, fmt.Errorf("dnp3: link frame too large: length %d exceeds 255", blocksLen)
	}
	h := make([]byte, 10, 10+blocksLen)
	h[0], h[1], h[2], h[3] = Start1, Start2, byte(blocksLen), control
	binary.LittleEndian.PutUint16(h[4:6], dst)
	binary.LittleEndian.PutUint16(h[6:8], src)
	binary.LittleEndian.PutUint16(h[8:10], CRC16(h[:8]))
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) { end = len(data) }
		chunk := data[off:end]
		h = append(h, chunk...)
		crc := CRC16(chunk)
		h = append(h, byte(crc), byte(crc>>8))
	}
	return h, nil
}

// BuildAppFrame builds an ASDU. Response functions include IIN after FC.
func BuildAppFrame(control, function byte, iin uint16, objects []core.DNP3Object) ([]byte, error) {
	out := []byte{control, function}
	response := function == AppRespond || function == AppUnsolicitedRespond
	if response { out = append(out, byte(iin>>8), byte(iin)) }
	for _, obj := range objects {
		encoded, err := encodeObject(obj, function, response)
		if err != nil { return nil, err }
		out = append(out, encoded...)
	}
	return out, nil
}

func encodeObject(obj core.DNP3Object, function uint8, response bool) ([]byte, error) {
	q := obj.Qualifier
	if q == 0 && obj.IndexRange == [2]uint16{} && len(obj.Points) == 0 { q = 0x06 }
	out := []byte{obj.ObjectType, obj.Variation, q}
	switch q {
	case 0x00:
		if obj.IndexRange[0] > 255 || obj.IndexRange[1] > 255 { return nil, fmt.Errorf("dnp3: qualifier 0x00 index exceeds 255") }
		out = append(out, byte(obj.IndexRange[0]), byte(obj.IndexRange[1]))
	case 0x01:
		out = binary.LittleEndian.AppendUint16(out, obj.IndexRange[0])
		out = binary.LittleEndian.AppendUint16(out, obj.IndexRange[1])
	case 0x06:
	case 0x07, 0x17:
		count := obj.Count
		if count == 0 { count = uint16(len(obj.Points)) }
		if count > 255 { return nil, fmt.Errorf("dnp3: qualifier count exceeds 255") }
		out = append(out, byte(count))
	case 0x08, 0x28:
		count := obj.Count
		if count == 0 { count = uint16(len(obj.Points)) }
		out = binary.LittleEndian.AppendUint16(out, count)
	default:
		return nil, fmt.Errorf("dnp3: unsupported qualifier 0x%02X", q)
	}
	return encodePoints(out, obj, q, function, response)
}

func encodePoints(out []byte, obj core.DNP3Object, q, function uint8, response bool) ([]byte, error) {
	if q == 0x17 || q == 0x28 {
		for n, p := range obj.Points {
			if q == 0x17 { out = append(out, byte(p.Index)) } else { out = binary.LittleEndian.AppendUint16(out, p.Index) }
			var err error
			out, err = encodePoint(out, obj, n, function, response)
			if err != nil { return nil, err }
		}
		return out, nil
	}
	if (obj.ObjectType == 1 || obj.ObjectType == 2) && obj.Variation == 1 {
		for i := 0; i < len(obj.Points); i += 8 {
			var packed byte
			for bit := 0; bit < 8 && i+bit < len(obj.Points); bit++ { if obj.Points[i+bit].Value != 0 { packed |= 1 << bit } }
			out = append(out, packed)
		}
		return out, nil
	}
	for n := range obj.Points {
		var err error
		out, err = encodePoint(out, obj, n, function, response)
		if err != nil { return nil, err }
	}
	return out, nil
}

func flagAt(obj core.DNP3Object, i int) byte { if i < len(obj.Flags) { return obj.Flags[i] }; return 1 }
// encodePoint 不再依赖 &p 地址比较——range 变量地址在 Go 中并非每轮唯一，
// 直接接收调用方传入的索引 n（修复 N6：消除 &obj.Points[n]==&p 不可靠的隐患）。
func encodePoint(out []byte, obj core.DNP3Object, n int, function uint8, response bool) ([]byte, error) {
	p := obj.Points[n]
	switch {
	case obj.ObjectType == 12 && obj.Variation == 1:
		code := byte(p.Value); if code == 0 && p.Value != 0 { code = 3 }
		out = append(out, code, 1, 100, 0, 0xFF, 0xFF)
		if response { out = append(out, 0) }
	case obj.ObjectType == 10:
		out = append(out, flagAt(obj, n), byte(p.Value))
	case obj.ObjectType == 20 || obj.ObjectType == 21 || obj.ObjectType == 30 || obj.ObjectType == 40:
		out = append(out, flagAt(obj, n))
		switch obj.Variation {
		case 1: out = binary.LittleEndian.AppendUint32(out, uint32(p.Value))
		case 2: out = binary.LittleEndian.AppendUint16(out, uint16(p.Value))
		case 3, 5: out = binary.LittleEndian.AppendUint32(out, math.Float32bits(float32(p.Value)))
		case 6: out = binary.LittleEndian.AppendUint64(out, math.Float64bits(p.Value))
		default: return nil, fmt.Errorf("dnp3: unsupported object %d variation %d", obj.ObjectType, obj.Variation)
		}
	case obj.ObjectType == 50:
		v := uint64(p.Value); out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24), byte(v>>32), byte(v>>40))
	default:
		out = append(out, byte(p.Value))
	}
	return out, nil
}
