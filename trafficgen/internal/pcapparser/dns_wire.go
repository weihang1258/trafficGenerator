package pcapparser

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// 自研 DNS 报文解码（D-PARSE-1 裁定3：替换 gopacket layers.DNS——大响应/
// EDNS 场景 DecodeFailure 已实测，且 TCP 2B 前缀分帧需自控）。格式权威：
// RFC 1035 §4（头/Question/RR/名字压缩）；EDNS RFC 6891（OPT 按 RR 面
// 解析，type=41）。

// dnsMaxPtrDepth 名字压缩指针解环上限（负例锚词 "ptr loop"）。
const dnsMaxPtrDepth = 16

// DNSWireMessage is one decoded DNS message.
type DNSWireMessage struct {
	TXID                       uint16
	QR, Opcode, RCode          int
	AA, TC, RD, RA, AD, CD     bool
	QD, AN, NS, AR             int
	Questions                  []DNSWireQuestion
	Answers, Authority, Additionals []DNSWireRR
	WireLen                    int
}

// DNSWireQuestion is one entry of the question section.
type DNSWireQuestion struct {
	Name  string
	Type  int
	Class int
}

// DNSWireRR is one resource record (answer/authority/additional).
type DNSWireRR struct {
	Name  string
	Type  int
	Class int
	TTL   uint32
	RData string
}

// dnsTypeString maps an RR type code to its mnemonic (RFC 1035 §3.2.2 +
// 常用扩展；未知返回 "TYPE<n>").
func dnsTypeString(t int) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 41:
		return "OPT"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// decodeDNSName decodes a possibly-compressed domain name starting at off.
// Returns the name and the offset AFTER the name in the original stream
// (pointers don't advance the stream cursor). Errors: truncated / ptr loop /
// label too long.
func decodeDNSName(msg []byte, off, depth int) (string, int, error) {
	if depth > dnsMaxPtrDepth {
		return "", off, fmt.Errorf("dns ptr loop (depth>%d)", dnsMaxPtrDepth)
	}
	var sb strings.Builder
	cur := off
	advanced := false // 游标只在非指针路径前进
	for {
		if cur >= len(msg) {
			return "", off, fmt.Errorf("dns name truncated")
		}
		l := int(msg[cur])
		switch {
		case l == 0:
			cur++
			if !advanced {
				off = cur
			}
			name := sb.String()
			if name == "" {
				name = "."
			}
			return name, off, nil
		case l&0xC0 == 0xC0: // 压缩指针（RFC 1035 §4.1.4）
			if cur+1 >= len(msg) {
				return "", off, fmt.Errorf("dns name truncated (ptr)")
			}
			ptr := int(l&0x3F)<<8 | int(msg[cur+1])
			if !advanced {
				off = cur + 2
				advanced = true
			}
			inner, _, err := decodeDNSName(msg, ptr, depth+1)
			if err != nil {
				return "", off, err
			}
			if sb.Len() > 0 && inner != "." {
				return sb.String() + "." + inner, off, nil
			}
			if inner == "." {
				return sb.String(), off, nil
			}
			return inner, off, nil
		case l > 63:
			return "", off, fmt.Errorf("dns label too long (%d)", l)
		default:
			if cur+1+l > len(msg) {
				return "", off, fmt.Errorf("dns name truncated (label)")
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(msg[cur+1 : cur+1+l])
			cur += 1 + l
			if !advanced {
				off = cur
			}
		}
	}
}

// decodeDNSWire decodes one DNS message from wire bytes.
func decodeDNSWire(wire []byte) (*DNSWireMessage, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("dns truncated (header %d<12)", len(wire))
	}
	m := &DNSWireMessage{
		TXID:   binary.BigEndian.Uint16(wire[0:2]),
		WireLen: len(wire),
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	m.QR = int(flags >> 15 & 1)
	m.Opcode = int(flags >> 11 & 0xF)
	m.AA = flags>>10&1 == 1
	m.TC = flags>>9&1 == 1
	m.RD = flags>>8&1 == 1
	m.RA = flags>>7&1 == 1
	m.AD = flags>>5&1 == 1
	m.CD = flags>>4&1 == 1
	m.RCode = int(flags & 0xF)
	m.QD = int(binary.BigEndian.Uint16(wire[4:6]))
	m.AN = int(binary.BigEndian.Uint16(wire[6:8]))
	m.NS = int(binary.BigEndian.Uint16(wire[8:10]))
	m.AR = int(binary.BigEndian.Uint16(wire[10:12]))

	off := 12
	var err error
	for i := 0; i < m.QD; i++ {
		var q DNSWireQuestion
		q.Name, off, err = decodeDNSName(wire, off, 0)
		if err != nil {
			return nil, err
		}
		if off+4 > len(wire) {
			return nil, fmt.Errorf("dns truncated (question)")
		}
		q.Type = int(binary.BigEndian.Uint16(wire[off : off+2]))
		q.Class = int(binary.BigEndian.Uint16(wire[off+2 : off+4]))
		off += 4
		m.Questions = append(m.Questions, q)
	}
	decodeRRs := func(n int) ([]DNSWireRR, error) {
		var out []DNSWireRR
		for i := 0; i < n; i++ {
			var rr DNSWireRR
			rr.Name, off, err = decodeDNSName(wire, off, 0)
			if err != nil {
				return nil, err
			}
			if off+10 > len(wire) {
				return nil, fmt.Errorf("dns truncated (rr fixed)")
			}
			rr.Type = int(binary.BigEndian.Uint16(wire[off : off+2]))
			rr.Class = int(binary.BigEndian.Uint16(wire[off+2 : off+4]))
			rr.TTL = binary.BigEndian.Uint32(wire[off+4 : off+8])
			rdLen := int(binary.BigEndian.Uint16(wire[off+8 : off+10]))
			off += 10
			if off+rdLen > len(wire) {
				return nil, fmt.Errorf("dns truncated (rdata)")
			}
			rr.RData = renderDNSRData(wire, off, rdLen, rr.Type)
			off += rdLen
			out = append(out, rr)
		}
		return out, nil
	}
	var derr error
	m.Answers, derr = decodeRRs(m.AN)
	if derr == nil {
		m.Authority, derr = decodeRRs(m.NS)
	}
	if derr == nil {
		m.Additionals, derr = decodeRRs(m.AR)
	}
	if derr != nil {
		return nil, derr
	}
	return m, nil
}

// renderDNSRData renders RDATA by type (A/AAAA→IP, NS/CNAME/PTR→名（可压缩）,
// MX→pref+名, SRV→prio+weight+port+target, TXT→文本, SOA→mname rname serial,
// 其他→hex).
func renderDNSRData(msg []byte, off, rdLen, rtype int) string {
	data := msg[off : off+rdLen]
	switch rtype {
	case 1: // A
		if rdLen == 4 {
			return net.IP(data).String()
		}
	case 28: // AAAA
		if rdLen == 16 {
			return net.IP(data).String()
		}
	case 2, 5, 12: // NS/CNAME/PTR：名字可能压缩，需全报文视角
		if name, _, err := decodeDNSName(msg, off, 0); err == nil {
			return name
		}
	case 15: // MX
		if rdLen >= 3 {
			if name, _, err := decodeDNSName(msg, off+2, 0); err == nil {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(data), name)
			}
		}
	case 33: // SRV
		if rdLen >= 7 {
			if name, _, err := decodeDNSName(msg, off+6, 0); err == nil {
				return fmt.Sprintf("%d %d %d %s",
					binary.BigEndian.Uint16(data), binary.BigEndian.Uint16(data[2:4]),
					binary.BigEndian.Uint16(data[4:6]), name)
			}
		}
	case 16: // TXT
		var parts []string
		for i := 0; i < rdLen; {
			l := int(data[i])
			if i+1+l > rdLen {
				break
			}
			parts = append(parts, string(data[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(parts, "|")
	case 6: // SOA
		if mname, n, err := decodeDNSName(msg, off, 0); err == nil {
			if rname, n2, err := decodeDNSName(msg, n, 0); err == nil && n2+20 <= off+rdLen {
				return fmt.Sprintf("%s %s serial=%d", mname, rname,
					binary.BigEndian.Uint32(msg[n2:n2+4]))
			}
		}
	}
	if rdLen > 0 {
		return hex.EncodeToString(data)
	}
	return ""
}

// splitTCPDNSMessages iterates a length-prefixed DNS stream (RFC 1035 §4.2.2:
// 2B big-endian length prefix, 不含自身). Returns per-message wire slices and
// whether the prefixed walk matched; non-prefixed callers fall back to single
// message decode. 截断尾块随 truncated 标记返回。
func splitTCPDNSMessages(stream []byte) (msgs [][]byte, truncated bool, ok bool) {
	off := 0
	for off < len(stream) {
		if off+2 > len(stream) {
			return msgs, true, true // 尾部不足 2B：残前缀
		}
		l := int(binary.BigEndian.Uint16(stream[off : off+2]))
		off += 2
		// l==0 不特判：真前缀流可含 TXID=0x0000 首消息（RFC 1035 无禁令）；
		// 零长消息经 ParseTCPStream 全解码校验自然否决前缀假设回退单消息。
		if off+l > len(stream) {
			return msgs, true, true // 截断消息
		}
		msgs = append(msgs, stream[off:off+l])
		off += l
	}
	if len(msgs) == 0 {
		return nil, false, false
	}
	return msgs, truncated, true
}
