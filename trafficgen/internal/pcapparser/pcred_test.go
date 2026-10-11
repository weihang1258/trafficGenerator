package pcapparser

// T-PARSE-PERF：300k 包基准（D-PARSE-1 §性能设计：提案值钉死用）。
// 生成混合语料（HTTP 事务流 + TCP 纯握手 + UDP/DNS + P2a/P2b/P2c 各端口
// 单包流），测 Parse 墙钟，产出 pps 对照 D-ENG-3 基线（~2.1k pps）。

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestBenchmarkParseP3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perf.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	const (
		HTTPFlows   = 30000 // 8 包/流 = 240k
		Handshakes  = 15000 // 3 包/流 = 45k
		UDPDatagrams = 15000 // 1 包/流
	)
	total := HTTPFlows*8 + Handshakes*3 + UDPDatagrams
	// 内存受限：流式写
	t0 := time.Now()
	_ = total
	emit := func(frames [][]byte) {
		for _, fr := range frames {
			w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(fr), Length: len(fr)}, fr)
		}
	}
	mkTCP := func(sport, dport layers.TCPPort, seq uint32, payload []byte) []byte {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			&layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP},
			&layers.TCP{SrcPort: sport, DstPort: dport, PSH: true, ACK: true, Seq: seq, Window: 65535},
			gopacket.Payload(payload))
		out := append([]byte{}, buf.Bytes()...)
		buf.Clear()
		return out
	}
	mkUDP := func(sport, dport layers.UDPPort, payload []byte) []byte {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			&layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP},
			&layers.UDP{SrcPort: sport, DstPort: dport},
			gopacket.Payload(payload))
		out := append([]byte{}, buf.Bytes()...)
		buf.Clear()
		return out
	}
	for i := 0; i < HTTPFlows; i++ {
		sport := layers.TCPPort(20000 + i%20000)
		emit([][]byte{
			mkTCP(sport, 80, uint32(i*100), []byte(fmt.Sprintf("GET /idx%d HTTP/1.1\r\nHost: h%d.test\r\n\r\n", i, i))),
			mkTCP(sport, 80, uint32(i*100+60), []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!")),
		})
		emit([][]byte{mkTCP(sport, 80, uint32(i*100+100), nil)})
		emit([][]byte{mkTCP(80, sport, uint32(i*100+7), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nAAAAA"))})
		emit([][]byte{mkTCP(sport, 80, uint32(i*100+110), []byte("GET /next HTTP/1.1\r\nHost: h.test\r\n\r\n"))})
		emit([][]byte{mkTCP(80, sport, uint32(i*100+160), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbbb"))})
		emit([][]byte{mkTCP(sport, 80, uint32(i*100+170), nil)})
		emit([][]byte{mkTCP(80, sport, uint32(i*100+200), nil)})
	}
	genTime := time.Since(t0)
	for i := 0; i < Handshakes; i++ {
		sport := layers.TCPPort(1000 + i%60000)
		emit([][]byte{
			mkTCP(sport, 443, 1, nil),
			mkTCP(443, sport, 2, nil),
			mkTCP(sport, 443, 2, nil),
		})
	}
	for i := 0; i < UDPDatagrams; i++ {
		var dport layers.UDPPort
		var payload []byte
		switch i % 3 {
		case 0:
			dport, payload = 53, buildP1DNSQuery(uint16(i), "perf.test")
		case 1:
			dport, payload = 123, make([]byte, 48)
			payload[0] = 0x23
		default:
			dport, payload = 161, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x00, 0xA0, 0x00}
		}
		emit([][]byte{mkUDP(layers.UDPPort(30000+i%20000), dport, payload)})
	}
	_ = total
	f.Close()
	_ = genTime

	t1 := time.Now()
	analysis, err := Parse(path, &Options{PcapAssetID: "perf", UserID: "u"})
	parseTime := time.Since(t1)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pps := float64(analysis.PacketCount) / parseTime.Seconds()
	fmt.Printf("PERF: packets=%d parse=%v pps=%.0f flows=%d\n",
		analysis.PacketCount, parseTime, pps, analysis.FlowCount)
	if analysis.PacketCount < 250000 {
		t.Fatalf("语料不足: %d", analysis.PacketCount)
	}
}
