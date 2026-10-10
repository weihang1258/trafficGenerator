package pcapparser

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// T-PARSE-1a（D-PARSE-1）：ICMPv6 流分组。修复前 ICMPv6 包逐包落 raw|offset
// 合成流（extractFields 无 ICMPv6 分支）；修复后同 (src,dst,type,id) 的
// echo request/reply 归同一条流，L4Protocol="icmpv6"，raw| 流数为 0。
func buildICMPv6EchoFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP,
	icmpType, icmpCode uint8, ident, seq uint16, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	icmp6 := &layers.ICMPv6{TypeCode: layers.ICMPv6TypeCode(uint16(icmpType)<<8 | uint16(icmpCode))}
	icmp6.SetNetworkLayerForChecksum(&layers.IPv6{
		SrcIP: srcIP, DstIP: dstIP, Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
	})
	ip6 := &layers.IPv6{SrcIP: srcIP, DstIP: dstIP, Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64}
	frame := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6},
		ip6,
		icmp6,
		&layers.ICMPv6Echo{Identifier: ident, SeqNumber: seq},
	}
	if len(payload) > 0 {
		frame = append(frame, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
		t.Fatalf("serialize icmpv6: %v", err)
	}
	return buf.Bytes()
}

func TestParse_ICMPv6FlowGrouping(t *testing.T) {
	ip6a := net.ParseIP("fd00::a")
	ip6b := net.ParseIP("fd00::b")
	frames := [][]byte{
		buildICMPv6EchoFrame(t, macA, macB, ip6a, ip6b, 128, 0, 0x1234, 1, []byte("ping")),
		buildICMPv6EchoFrame(t, macB, macA, ip6b, ip6a, 129, 0, 0x1234, 1, []byte("ping")),
	}
	path := writePcap(t, frames, []time.Time{time.Unix(0, 0), time.Unix(0, 1000)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a1", UserID: "u1"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(analysis.Flows) != 1 {
		t.Fatalf("icmpv6 echo req+reply must group into 1 flow, got %d (raw-per-packet bug)", len(analysis.Flows))
	}
	f := analysis.Flows[0]
	if f.L4Protocol != "icmpv6" {
		t.Fatalf("L4Protocol = %q, want icmpv6", f.L4Protocol)
	}
	if f.IPVersion != 6 {
		t.Fatalf("IPVersion = %d, want 6", f.IPVersion)
	}
	if f.PacketCount != 2 {
		t.Fatalf("PacketCount = %d, want 2", f.PacketCount)
	}
	for _, p := range analysis.Packets {
		if p.FlowID != f.ID {
			t.Fatalf("packet %d flow mismatch: both packets must share the flow", p.IndexInFlow)
		}
	}
}
