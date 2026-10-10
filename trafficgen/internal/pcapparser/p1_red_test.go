package pcapparser

import (
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// T-PARSE-1b/1c/1d 红测试（D-PARSE-1 P1 批，9.7 先红后绿）。
// 断言口径全部来自测试内独立构造的期望值。

// --- 1b: TCP DNS 2 字节长度前缀（RFC 1035 §4.2.2）---

// buildDNSQuery 构造一条最小 DNS 查询报文（txid 可钉）。
func buildP1DNSQuery(txid uint16, name string) []byte {
	msg := []byte{
		byte(txid >> 8), byte(txid), // txid
		0x01, 0x00, // flags: RD=1
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qd=1
	}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01) // null+A+IN
	return msg
}

// buildTCPDNSFrames 两条 TCP DNS 消息各占一个报文段（长度前缀在流内）。
func buildTCPDNSFrames(t *testing.T, txid uint16, name string) [][]byte {
	t.Helper()
	mk := func(seg []byte, seq uint32) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: 40000, DstPort: 53, PSH: true, ACK: true, Seq: seq, Window: 65535}
		tcp.SetNetworkLayerForChecksum(ipv4)
		if err := gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, tcp, gopacket.Payload(seg)); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		return buf.Bytes()
	}
	msg := buildP1DNSQuery(txid, name)
	// 流字节序：2B 长度前缀 + 报文（拆两段，seq 连续——同 seq 会被重组器当重传丢）
	prefixed := append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
	half := 8
	return [][]byte{mk(prefixed[:half], 1), mk(prefixed[half:], uint32(half)+1)}
}

// TestRed_TCPDNSLengthPrefix：修复前重组流直接喂 gopacket DNS，长度前缀
// 被当 TXID 高位 → 解析错位。修复后流级解析器剥前缀逐消息，txid 正确。
func TestRed_TCPDNSLengthPrefix(t *testing.T) {
	frames := buildTCPDNSFrames(t, 0xBEEF, "example.test")
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := analysis.Flows[0]
	if f.L7QueryName != "example.test" {
		t.Errorf("L7QueryName = %q, want example.test（TCP DNS 长度前缀错位 bug）", f.L7QueryName)
	}
}

// --- 1c: HTTP keep-alive 多事务 ---

func buildHTTPTransaction(t *testing.T, method, path_, host string, seq uint32) []byte {
	t.Helper()
	req := method + " " + path_ + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: tparse\r\n\r\n"
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 41000, DstPort: 80, PSH: true, ACK: true, Seq: seq, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ipv4)
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp, gopacket.Payload([]byte(req))); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

// TestRed_HTTPMultiTransaction：修复前只解析首个事务；修复后 transactions=2。
func TestRed_HTTPMultiTransaction(t *testing.T) {
	frames := [][]byte{
		buildHTTPTransaction(t, "GET", "/one", "a.test", 100),
		buildHTTPTransaction(t, "POST", "/two", "a.test", 150),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := analysis.Flows[0]
	// L7Metadata 兼容面：多事务解析器把逐事务 uri 累积为列表键（setL7 列表
	// append 语义既有）；修复前只解析首事务，"/two" 不出现。
	if !strings.Contains(f.L7Metadata, "/two") {
		t.Errorf("L7Metadata 缺第二事务 uri /two（单事务截断 bug）: %q", f.L7Metadata)
	}
}

// --- 1d: get_packet 大 DNS 响应 DecodeFailure ---

// buildBigDNSResponse 越过 gopacket DNS 解码舒适区的大响应（多 answer + 长
// 名字压缩链），UDP/53 单包。
func buildBigDNSResponse(t *testing.T) []byte {
	msg := []byte{
		0xAB, 0xCD, // txid
		0x81, 0x80, // response, RD+RA
		0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // qd=1 an=32
	}
	qname := []byte{3, 'w', 'w', 'w', 7, 'b', 'i', 'g', 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0}
	msg = append(msg, qname...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN
	// 32 个 answer：名字用压缩指针指回 question（0xC00C），A 记录
	for i := 0; i < 32; i++ {
		ans := append([]byte{0xC0, 0x0C}, 0x00, 0x01, 0x00, 0x01)
		ans = append(ans, 0x00, 0x00, 0x00, 0x1E) // ttl 30
		ans = append(ans, 0x00, 0x04, 10, 0, 0, byte(i+1))
		msg = append(msg, ans...)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	ipv4 := &layers.IPv4{SrcIP: ipB, DstIP: ipA, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 53, DstPort: 40000}
	udp.SetNetworkLayerForChecksum(ipv4)
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4},
		ipv4, udp, gopacket.Payload(msg)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

// TestRed_GetPacketBigDNSNoDecodeFailure：修复前 gopacket DNS 自动解码失败
// 出 DecodeFailure 层且无 dns 字段；修复后 get_packet 走自研解码出 dns 层。
func TestRed_GetPacketBigDNSNoDecodeFailure(t *testing.T) {
	frame := buildBigDNSResponse(t)
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkt := analysis.Packets[0]
	records, err := ParsePacket(path, pkt.RawOffset, pkt.Length, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	var hasDecodeFailure, hasDNS bool
	for _, rec := range records {
		if rec.Layer == "DecodeFailure" {
			hasDecodeFailure = true
		}
		if rec.Layer == "dns" {
			hasDNS = true
		}
	}
	if hasDecodeFailure {
		t.Errorf("get_packet 仍含 DecodeFailure 层（大响应解码 bug）")
	}
	if !hasDNS {
		t.Errorf("get_packet 无 dns 层记录（自研解码未接入 get_packet）")
	}
}
