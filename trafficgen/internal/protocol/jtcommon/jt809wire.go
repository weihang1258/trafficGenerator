package jtcommon

// JT/T 809 线层共用面（D-JT809-1 裁定2）：CRC-16/校验+转义——809 族
// （jt809/jtt905）共用，808 面 XOR/Escape 不受影响。
//
// 校验：CRC-16 poly 0x1021 表语义（CRC-CCITT），init 0xFFFF，无终态反转；
// 范围=5B 后首字节至消息体末字节（不含 CRC 自身与 5D）。
// SmallChi/JT809 MessagePackReader.Decode 循环实录对齐，金向量单测钉。

// CRC809 computes the JT/T 809 frame checksum over the pre-escape bytes
// (header+body, no 5B/5D delimiters, no CRC itself).
func CRC809(buf []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range buf {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// Escape809 applies the JT/T 809 transfer escaping to header+body+CRC:
// 0x5B→5A 01, 0x5A→5A 02, 0x5D→5E 01, 0x5E→5E 02. Single left-to-right
// pass; emitted escape bytes are not re-scanned.
func Escape809(buf []byte) []byte {
	out := make([]byte, 0, len(buf)+8)
	for _, b := range buf {
		switch b {
		case 0x5B:
			out = append(out, 0x5A, 0x01)
		case 0x5A:
			out = append(out, 0x5A, 0x02)
		case 0x5D:
			out = append(out, 0x5E, 0x01)
		case 0x5E:
			out = append(out, 0x5E, 0x02)
		default:
			out = append(out, b)
		}
	}
	return out
}

// Unescape809 reverses Escape809.
func Unescape809(buf []byte) []byte {
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); i++ {
		switch buf[i] {
		case 0x5A:
			if i+1 < len(buf) && buf[i+1] == 0x01 {
				out = append(out, 0x5B)
				i++
			} else if i+1 < len(buf) && buf[i+1] == 0x02 {
				out = append(out, 0x5A)
				i++
			} else {
				out = append(out, buf[i])
			}
		case 0x5E:
			if i+1 < len(buf) && buf[i+1] == 0x01 {
				out = append(out, 0x5D)
				i++
			} else if i+1 < len(buf) && buf[i+1] == 0x02 {
				out = append(out, 0x5E)
				i++
			} else {
				out = append(out, buf[i])
			}
		default:
			out = append(out, buf[i])
		}
	}
	return out
}
