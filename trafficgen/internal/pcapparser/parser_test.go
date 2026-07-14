package pcapparser

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// writePcap writes the given frames (with per-frame timestamps) to a temp pcap
// file and returns its path. Used to build deterministic parser test inputs.
func writePcap(t *testing.T, frames [][]byte, timestamps []time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for i, frame := range frames {
		ts := time.Unix(0, 0)
		if i < len(timestamps) {
			ts = timestamps[i]
		}
		ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(frame), Length: len(frame)}
		if err := w.WritePacket(ci, frame); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	return path
}

// TCP flag bits (standard wire positions) used by buildTCPFrame.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

// buildTCPFrame serializes an Ethernet/IPv4/TCP frame with optional payload.
// Used to construct deterministic parser inputs.
func buildTCPFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort, seq, ack uint32, flags uint8, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{
		SrcPort: srcPort, DstPort: dstPort, Seq: seq, Ack: ack, Window: 65535,
		FIN: flags&flagFIN != 0, SYN: flags&flagSYN != 0, RST: flags&flagRST != 0,
		PSH: flags&flagPSH != 0, ACK: flags&flagACK != 0,
	}
	ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	layersToSerialize := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		tcp,
	}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func buildUDPFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP,
	srcPort, dstPort layers.UDPPort, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	udp.SetNetworkLayerForChecksum(ipv4)
	layersToSerialize := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
	}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

var (
	macA, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ = net.ParseMAC("bb:bb:bb:bb:bb:bb")
	ipA     = net.ParseIP("10.0.0.1")
	ipB     = net.ParseIP("10.0.0.2")
)

// TestFlowKey_Normalization verifies both directions of a TCP connection map to
// the same bidirectional-normalized flow key.
func TestFlowKey_Normalization(t *testing.T) {
	k1 := flowKeyTCPUDP(ipA, ipB, 1234, 80, 6)
	k2 := flowKeyTCPUDP(ipB, ipA, 80, 1234, 6)
	if k1 != k2 {
		t.Errorf("bidirectional keys differ: %q vs %q", k1, k2)
	}
	// Different connection -> different key.
	k3 := flowKeyTCPUDP(ipA, ipB, 1234, 81, 6)
	if k1 == k3 {
		t.Errorf("different port should yield different key")
	}
	// UDP vs TCP same 4-tuple -> different key (proto in key).
	k4 := flowKeyTCPUDP(ipA, ipB, 1234, 80, 17)
	if k1 == k4 {
		t.Errorf("different protocol should yield different key")
	}
}

// TestParse_TCPFlow verifies a TCP 3-way-handshake + data + FIN parses into one
// flow with correct stats, direction counts, and per-packet fields.
func TestParse_TCPFlow(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),                  // SYN c2s
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),  // SYN-ACK s2c
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),                // ACK c2s
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("hello")), // data c2s
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagFIN|flagACK, nil),  // FIN c2s
	}
	ts := []time.Time{
		time.UnixMicro(1000), time.UnixMicro(2000), time.UnixMicro(3000),
		time.UnixMicro(4000), time.UnixMicro(5000),
	}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("FlowCount = %d, want 1", analysis.FlowCount)
	}
	if analysis.PacketCount != 5 {
		t.Errorf("PacketCount = %d, want 5", analysis.PacketCount)
	}
	flow := analysis.Flows[0]
	if flow.L4Protocol != "tcp" {
		t.Errorf("L4Protocol = %q, want tcp", flow.L4Protocol)
	}
	if flow.PacketCount != 5 {
		t.Errorf("flow.PacketCount = %d, want 5", flow.PacketCount)
	}
	// c2s = SYN, ACK, data, FIN = 4; s2c = SYN-ACK = 1.
	if flow.C2SPackets != 4 || flow.S2CPackets != 1 {
		t.Errorf("c2s=%d s2c=%d, want 4/1", flow.C2SPackets, flow.S2CPackets)
	}
	if flow.FirstTsUs != 1000 || flow.LastTsUs != 5000 {
		t.Errorf("ts range = %d..%d, want 1000..5000", flow.FirstTsUs, flow.LastTsUs)
	}
	if flow.DurationUs != 4000 {
		t.Errorf("DurationUs = %d, want 4000", flow.DurationUs)
	}
	if flow.DirStatus != "classified" || flow.DirMethod != "syn" {
		t.Errorf("direction = %q/%q, want classified/syn (SYN calibrates)", flow.DirStatus, flow.DirMethod)
	}
	if flow.Client != "10.0.0.1:1234" || flow.Server != "10.0.0.2:80" {
		t.Errorf("Client/Server = %q/%q, want 10.0.0.1:1234 / 10.0.0.2:80", flow.Client, flow.Server)
	}
	if flow.ParserVersion != ParserVersion {
		t.Errorf("ParserVersion = %q, want %q", flow.ParserVersion, ParserVersion)
	}

	// Per-packet: verify RawOffset, Direction, IndexInFlow, PayloadHash.
	if len(analysis.Packets) != 5 {
		t.Fatalf("Packets = %d, want 5", len(analysis.Packets))
	}
	// Directions: c2s,s2c,c2s,c2s,c2s.
	wantDirs := []string{"c2s", "s2c", "c2s", "c2s", "c2s"}
	for i, p := range analysis.Packets {
		if p.Direction != wantDirs[i] {
			t.Errorf("packet %d direction = %q, want %q", i, p.Direction, wantDirs[i])
		}
		if p.IndexInFlow != i+1 {
			t.Errorf("packet %d IndexInFlow = %d, want %d", i, p.IndexInFlow, i+1)
		}
		if p.L4Protocol != "tcp" {
			t.Errorf("packet %d L4Protocol = %q, want tcp", i, p.L4Protocol)
		}
		if p.FlowID != flow.ID {
			t.Errorf("packet %d FlowID mismatch", i)
		}
		// Verify RawOffset points at the actual packet bytes in the file.
		got, err := readBytesAt(path, p.RawOffset, p.Length)
		if err != nil {
			t.Fatalf("read packet %d bytes: %v", i, err)
		}
		if string(got) != string(frames[i]) {
			t.Errorf("packet %d RawOffset bytes mismatch (len got=%d want=%d)", i, len(got), len(frames[i]))
		}
	}
	// Only the data packet has a payload -> only it has a non-empty PayloadHash.
	dataPkt := analysis.Packets[3]
	if dataPkt.PayloadHash == "" {
		t.Errorf("data packet PayloadHash empty, want sha256 of 'hello'")
	}
	for _, i := range []int{0, 1, 2, 4} {
		if analysis.Packets[i].PayloadHash != "" {
			t.Errorf("packet %d PayloadHash = %q, want empty (no payload)", i, analysis.Packets[i].PayloadHash)
		}
	}
}

// TestParse_MultipleFlows verifies packets from distinct flows group separately
// and interleave correctly (flow map keyed by normalized 5-tuple).
func TestParse_MultipleFlows(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1000, 80, 1, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("dns query")),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1000, 2, 2, flagSYN|flagACK, nil),
		buildUDPFrame(t, macB, macA, ipB, ipA, 53, 2000, []byte("dns resp")),
	}
	ts := []time.Time{time.UnixMicro(100), time.UnixMicro(200), time.UnixMicro(300), time.UnixMicro(400)}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 2 {
		t.Fatalf("FlowCount = %d, want 2 (one TCP + one UDP)", analysis.FlowCount)
	}
	if v := analysis.ProtocolDist["tcp"]; v != 2 {
		t.Errorf("ProtocolDist tcp = %d, want 2", v)
	}
	if v := analysis.ProtocolDist["udp"]; v != 2 {
		t.Errorf("ProtocolDist udp = %d, want 2", v)
	}
}

// TestParse_StreamingSink verifies PacketSink/FlowSink are called during parsing
// and PcapAnalysis.Packets/Flows are NOT populated when sinks are set.
func TestParse_StreamingSink(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("q")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})

	var gotPackets []storage.PacketModel
	var gotFlows []storage.FlowModel
	analysis, err := Parse(path, &Options{
		PcapAssetID: "ast1", UserID: "u1", BatchSize: 1,
		PacketSink: func(b []storage.PacketModel) error {
			gotPackets = append(gotPackets, b...)
			return nil
		},
		FlowSink: func(f storage.FlowModel) error {
			gotFlows = append(gotFlows, f)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Packets) != 0 {
		t.Errorf("Packets retained = %d, want 0 (sink set)", len(analysis.Packets))
	}
	if len(analysis.Flows) != 0 {
		t.Errorf("Flows retained = %d, want 0 (sink set)", len(analysis.Flows))
	}
	if len(gotPackets) != 2 {
		t.Errorf("sink packets = %d, want 2", len(gotPackets))
	}
	if len(gotFlows) != 2 {
		t.Errorf("sink flows = %d, want 2", len(gotFlows))
	}
}

// TestParse_AnomalyTruncated verifies a truncated packet (captured < original)
// is flagged and still indexed.
func TestParse_AnomalyTruncated(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	// Write a pcap where the recorded original length > captured length.
	path := filepath.Join(t.TempDir(), "trunc.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(1), CaptureLength: len(frame), Length: len(frame) + 100}
	w.WritePacket(ci, frame)
	f.Close()

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Packets) != 1 {
		t.Fatalf("packets = %d, want 1", len(analysis.Packets))
	}
	if analysis.Packets[0].AnomalyFlag != "truncated" {
		t.Errorf("AnomalyFlag = %q, want truncated", analysis.Packets[0].AnomalyFlag)
	}
}

// TestParse_RejectsPcapng verifies pcapng magic is detected and rejected.
func TestParse_RejectsPcapng(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.pcapng")
	f, _ := os.Create(path)
	// pcapng section header block magic: 0x0A0D0D0A
	f.Write([]byte{0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Close()
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil || !strings.Contains(err.Error(), "pcapng") {
		t.Errorf("expected pcapng rejection error, got %v", err)
	}
}

// TestParse_RejectsGzip verifies a gzipped pcap is rejected (RawOffset requires
// an uncompressed file).
func TestParse_RejectsGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.pcap.gz")
	f, _ := os.Create(path)
	// gzip magic 0x1f 0x8b
	f.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0})
	f.Close()
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("expected gzip rejection error, got %v", err)
	}
}

// TestParse_ARPFlowKey verifies ARP packets group by sender/target protocol
// address + operation (per §5 the key is (senderIP, targetIP, op) with IPs
// normalized). Two ARPs with the same op and IP pair but opposite directions
// group together; a different IP pair is separate.
func TestParse_ARPFlowKey(t *testing.T) {
	buildARP := func(op uint16, senderIP, targetIP net.IP) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		arp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         op,
			SourceHwAddress:   macA,
			SourceProtAddress: senderIP.To4(),
			DstHwAddress:      macB,
			DstProtAddress:    targetIP.To4(),
		}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeARP},
			arp)
		return buf.Bytes()
	}
	frames := [][]byte{
		buildARP(1, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")), // op=1, pair A
		buildARP(1, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1")), // op=1, pair A reversed -> same flow
		buildARP(1, net.ParseIP("10.0.0.3"), net.ParseIP("10.0.0.4")), // op=1, pair B -> separate
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 2 {
		t.Errorf("ARP FlowCount = %d, want 2 (reversed-direction same pair groups; separate pair separate)", analysis.FlowCount)
	}
}

// TestParse_ICMPFlowKey verifies ICMP packets group by IP pair + type + id (§5).
// Same type+id in opposite directions group; a different id is separate.
func TestParse_ICMPFlowKey(t *testing.T) {
	buildICMP := func(srcIP, dstIP net.IP, typ uint8, id uint16) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true} // checksums not needed for flow-key tests
		icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, 0), Id: id}
		ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, icmp)
		return buf.Bytes()
	}
	frames := [][]byte{
		buildICMP(ipA, ipB, 8, 100), // echo request id=100, A->B
		buildICMP(ipB, ipA, 8, 100), // echo request id=100, B->A -> same flow (normalized)
		buildICMP(ipA, ipB, 8, 200), // echo request id=200 -> separate
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 2 {
		t.Errorf("ICMP FlowCount = %d, want 2 (reversed-direction same type+id groups; different id separate)", analysis.FlowCount)
	}
}

func TestParse_RejectsNonEthernet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeRaw) // DLT_RAW, not Ethernet
	ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(1), CaptureLength: 4, Length: 4}
	w.WritePacket(ci, []byte{0x45, 0, 0, 0x14})
	f.Close()
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil || !strings.Contains(err.Error(), "Ethernet") {
		t.Errorf("expected non-Ethernet rejection, got %v", err)
	}
}

// TestExtractOffsetLayout verifies byte offsets for a standard Eth+IPv4+TCP
// frame. Ethernet(14) + IPv4(20) + TCP(20): SrcMAC=6, SrcIP=26, DstIP=30,
// SrcPort=34, Seq=38, TCPFlags=47, etc.
func TestExtractOffsetLayout(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)

	checks := map[string]int{
		"l2_start": 0, "dst_mac": 0, "src_mac": 6,
		"l3_start": 14, "src_ip": 26, "dst_ip": 30, "ttl": 22, "dscp_ecn": 15, "ip_flags_frag": 20, "ip_id": 18,
		"l4_start": 34, "src_port": 34, "dst_port": 36, "seq": 38, "ack": 42, "window": 48, "tcp_flags": 47,
	}
	for field, want := range checks {
		got := offsetField(layout, field)
		if got != want {
			t.Errorf("%s = %d, want %d", field, got, want)
		}
	}
	if layout.L4Protocol != "tcp" {
		t.Errorf("L4Protocol = %q, want tcp", layout.L4Protocol)
	}
	if layout.VlanTCO != -1 {
		t.Errorf("VlanTCO = %d, want -1 (no VLAN)", layout.VlanTCO)
	}
}

// offsetField reads a field from an OffsetLayout by name (test helper).
func offsetField(l OffsetLayout, name string) int {
	switch name {
	case "l2_start":
		return l.L2Start
	case "l3_start":
		return l.L3Start
	case "l4_start":
		return l.L4Start
	case "src_mac":
		return l.SrcMAC
	case "dst_mac":
		return l.DstMAC
	case "vlan_tco":
		return l.VlanTCO
	case "src_ip":
		return l.SrcIP
	case "dst_ip":
		return l.DstIP
	case "ttl":
		return l.TTL
	case "dscp_ecn":
		return l.DSCPECN
	case "ip_flags_frag":
		return l.IPFlagsFrag
	case "ip_id":
		return l.IPID
	case "src_port":
		return l.SrcPort
	case "dst_port":
		return l.DstPort
	case "seq":
		return l.Seq
	case "ack":
		return l.Ack
	case "window":
		return l.Window
	case "tcp_flags":
		return l.TCPFlags
	}
	return -999
}

// TestExtractOffsetLayout_VLAN verifies a VLAN-tagged frame has the VlanTCO set
// and subsequent layer offsets shifted by 4 (the Dot1Q tag size).
func TestExtractOffsetLayout_VLAN(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, Window: 65535, SYN: true}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{VLANIdentifier: 100, Priority: 3, Type: layers.EthernetTypeIPv4},
		ipv4, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)

	if layout.VlanTCO != 14 {
		t.Errorf("VlanTCO = %d, want 14", layout.VlanTCO)
	}
	// IPv4 starts after Eth(14)+Dot1Q(4)=18.
	if layout.L3Start != 18 {
		t.Errorf("L3Start = %d, want 18 (VLAN shifted)", layout.L3Start)
	}
	if layout.SrcIP != 30 {
		t.Errorf("SrcIP = %d, want 30 (18+12)", layout.SrcIP)
	}
	if layout.L4Start != 38 {
		t.Errorf("L4Start = %d, want 38 (18+20)", layout.L4Start)
	}
}

// TestParse_OffsetLayoutSerialized verifies Parse serializes the OffsetLayout
// into FlowModel.OffsetLayout as JSON for the replay rewriter.
func TestParse_OffsetLayoutSerialized(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(analysis.Flows))
	}
	jsonStr := analysis.Flows[0].OffsetLayout
	if jsonStr == "" || jsonStr == "{}" {
		t.Fatalf("OffsetLayout not serialized: %q", jsonStr)
	}
	var layout OffsetLayout
	if err := json.Unmarshal([]byte(jsonStr), &layout); err != nil {
		t.Fatalf("unmarshal OffsetLayout: %v", err)
	}
	if layout.SrcIP != 26 || layout.L4Protocol != "tcp" {
		t.Errorf("deserialized layout wrong: SrcIP=%d L4=%q", layout.SrcIP, layout.L4Protocol)
	}
}

// TestParsePacket_DynamicReparse verifies ParsePacket re-parses a packet from
// its RawOffset and returns LayerRecords with correct fields/offsets/ranges.
func TestParsePacket_DynamicReparse(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 42, 99, flagSYN|flagACK, []byte("hi"))
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pm := analysis.Packets[0]

	records, err := ParsePacket(path, pm.RawOffset, pm.Length, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	// Expect eth, ipv4, tcp layers (payload is not a separate LayerRecord).
	layerNames := make([]string, 0, len(records))
	for _, r := range records {
		layerNames = append(layerNames, r.Layer)
	}
	if !containsStr(layerNames, "eth") || !containsStr(layerNames, "ipv4") || !containsStr(layerNames, "tcp") {
		t.Errorf("layers = %v, want eth+ipv4+tcp", layerNames)
	}

	// Verify IPv4 fields round-trip correctly.
	var ipv4 *LayerRecord
	for i := range records {
		if records[i].Layer == "ipv4" {
			ipv4 = &records[i]
			break
		}
	}
	if ipv4 == nil {
		t.Fatalf("no ipv4 layer")
	}
	if ipv4.Fields["src_ip"] != ipA.String() || ipv4.Fields["dst_ip"] != ipB.String() {
		t.Errorf("ipv4 fields: src=%v dst=%v, want %s/%s", ipv4.Fields["src_ip"], ipv4.Fields["dst_ip"], ipA, ipB)
	}
	if ipv4.Offsets["src_ip"] != 26 {
		t.Errorf("ipv4 src_ip offset = %d, want 26", ipv4.Offsets["src_ip"])
	}
	if ipv4.Range != [2]int{14, 34} {
		t.Errorf("ipv4 range = %v, want [14,34)", ipv4.Range)
	}

	// Verify TCP fields (seq/ack/flags).
	var tcp *LayerRecord
	for i := range records {
		if records[i].Layer == "tcp" {
			tcp = &records[i]
			break
		}
	}
	if tcp == nil {
		t.Fatalf("no tcp layer")
	}
	if tcp.Fields["seq"] != uint32(42) || tcp.Fields["ack"] != uint32(99) {
		t.Errorf("tcp seq=%v ack=%v, want 42/99", tcp.Fields["seq"], tcp.Fields["ack"])
	}
	if tcp.Fields["flags"] != "SYN,ACK" {
		t.Errorf("tcp flags = %v, want SYN,ACK", tcp.Fields["flags"])
	}
}

// TestParsePacket_NonEthernet verifies ParsePacket rejects non-Ethernet link types.
func TestParsePacket_NonEthernet(t *testing.T) {
	_, err := ParsePacket("any", 0, 10, layers.LinkTypeRaw)
	if err == nil || !strings.Contains(err.Error(), "Ethernet") {
		t.Errorf("expected non-Ethernet rejection, got %v", err)
	}
}

// TestParse_Direction_SYNACKCorrection verifies a capture starting at the
// SYN-ACK (missing the SYN) still classifies direction: the SYN-ACK's src is
// the server, its dst is the client.
func TestParse_Direction_SYNACKCorrection(t *testing.T) {
	frames := [][]byte{
		// SYN-ACK from ipB:80 -> ipA:1234 (capture missed the SYN).
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil), // ACK c2s
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.DirStatus != "classified" || flow.DirMethod != "syn" {
		t.Errorf("direction = %q/%q, want classified/syn", flow.DirStatus, flow.DirMethod)
	}
	// SYN-ACK src (ipB:80) is the SERVER; dst (ipA:1234) is the CLIENT.
	if flow.Client != "10.0.0.1:1234" || flow.Server != "10.0.0.2:80" {
		t.Errorf("Client/Server = %q/%q, want 10.0.0.1:1234 / 10.0.0.2:80", flow.Client, flow.Server)
	}
	// Packet 2 (ACK from ipA:1234) is c2s (src == client).
	if analysis.Packets[1].Direction != "c2s" {
		t.Errorf("packet 2 direction = %q, want c2s (src is client)", analysis.Packets[1].Direction)
	}
}

// TestParse_Direction_UDPPortHint verifies a UDP flow to a well-known server
// port (53) classifies the :53 side as server.
func TestParse_Direction_UDPPortHint(t *testing.T) {
	frames := [][]byte{
		// DNS query from ipA:2000 -> ipB:53.
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("q")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.DirMethod != "port" || flow.DirStatus != "classified" {
		t.Errorf("direction = %q/%q, want port/classified", flow.DirStatus, flow.DirMethod)
	}
	if flow.Server != "10.0.0.2:53" {
		t.Errorf("Server = %q, want 10.0.0.2:53 (well-known port)", flow.Server)
	}
}

// TestParse_TCPReassembly verifies TCP reassembly: multi-packet data on one
// direction reassembles into a contiguous L7 stream materialized in .payloads,
// with correct C2SOffset/C2SLength, ReassemblyComplete=true, and TCP stats
// (handshake status, initial seq, flag counts).
func TestParse_TCPReassembly(t *testing.T) {
	// c2s: SYN(100) -> data "Hello "(101) -> data "World"(107) -> FIN(112)
	// s2c: SYN-ACK(200) -> ACK(201)
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),                  // pure ACK
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello ")),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 107, 201, flagPSH|flagACK, []byte("World")),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 112, 201, flagFIN|flagACK, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 201, 113, flagACK, nil), // final ACK
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5), time.UnixMicro(6), time.UnixMicro(7)}
	payloadsPath := filepath.Join(t.TempDir(), "test.payloads")
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("FlowCount = %d, want 1", analysis.FlowCount)
	}
	flow := analysis.Flows[0]

	// Handshake: SYN + SYN-ACK + ACK seen -> complete.
	if flow.HandshakeStatus != "complete" {
		t.Errorf("HandshakeStatus = %q, want complete", flow.HandshakeStatus)
	}
	// C2SInitSeq = SYN seq (100).
	if flow.C2SInitSeq != 100 {
		t.Errorf("C2SInitSeq = %d, want 100", flow.C2SInitSeq)
	}
	if flow.S2CInitSeq != 200 {
		t.Errorf("S2CInitSeq = %d, want 200", flow.S2CInitSeq)
	}
	// FlagsSummary has syn>=1, ack>=1, fin>=1.
	if !strings.Contains(flow.FlagsSummary, "syn") || !strings.Contains(flow.FlagsSummary, "fin") {
		t.Errorf("FlagsSummary = %q, want syn+fin counts", flow.FlagsSummary)
	}

	// Reassembly: c2s stream = "Hello " + "World" = "Hello World".
	if flow.C2SLength != int64(len("Hello World")) {
		t.Errorf("C2SLength = %d, want %d", flow.C2SLength, len("Hello World"))
	}
	if flow.StreamFile != payloadsPath {
		t.Errorf("StreamFile = %q, want %q", flow.StreamFile, payloadsPath)
	}
	if !flow.ReassemblyComplete {
		t.Errorf("ReassemblyComplete = false, want true (no gaps)")
	}
	// Read back the reassembled c2s stream from .payloads.
	got, err := readBytesAt(payloadsPath, flow.C2SOffset, int(flow.C2SLength))
	if err != nil {
		t.Fatalf("read payloads: %v", err)
	}
	if string(got) != "Hello World" {
		t.Errorf("reassembled c2s = %q, want 'Hello World'", string(got))
	}
}

// TestParse_TCPReassembly_Gap verifies a seq gap in the c2s direction marks
// ReassemblyComplete=false and records GapInfo.
func TestParse_TCPReassembly_Gap(t *testing.T) {
	// c2s: SYN(100) -> data "Hello"(101) -> data "World"(200) [gap: 101+5=106, but seq=200]
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello")),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 200, 201, flagPSH|flagACK, []byte("World")), // seq jumps 101->200 (gap)
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 205, 201, flagFIN|flagACK, nil),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5)}
	payloadsPath := filepath.Join(t.TempDir(), "gap.payloads")
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.ReassemblyComplete {
		t.Errorf("ReassemblyComplete = true, want false (seq gap)")
	}
	if flow.GapInfo == "" {
		t.Errorf("GapInfo empty, want gap description")
	}
}

// TestFragmentReassembler verifies IP fragment reassembly: two fragments of one
// IP datagram reassemble into the original IP payload, with the IP header's
// total-length/flags/frag-offset fields fixed and checksum recomputed.
func TestFragmentReassembler(t *testing.T) {
	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var flags layers.IPv4Flag
		if mf {
			flags = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{
			SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64,
			Protocol: layers.IPProtocolTCP, Flags: flags, FragOffset: fragOffsetUnits,
		}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	// Original IP payload = "ABCDEFGH" + "IJKLMNOP" (16 bytes, fragment 1) + "QRSTUVWXYZ" (10 bytes, fragment 2).
	// Fragment 1: offset 0 (0 units), MF=1, payload = first 16 bytes.
	// Fragment 2: offset 16 bytes (2 units), MF=0, payload = next 10 bytes.
	frag1 := buildFrag(0x1234, 0, true, []byte("ABCDEFGHIJKLMNOP"))
	frag2 := buildFrag(0x1234, 2, false, []byte("QRSTUVWXYZ"))

	r := NewFragmentReassembler()
	l3Start := 14 // after Ethernet
	// Add fragment 1 first; group not complete (no last fragment yet).
	if got := r.AddFragment("0x1234|10.0.0.1|10.0.0.2|6", frag1, l3Start, 0x1234, ipA, ipB, 6, 0, true); got != nil {
		t.Errorf("fragment 1 alone should not reassemble, got %d bytes", len(got))
	}
	// Add fragment 2 (last); group completes -> reassembled.
	reassembled := r.AddFragment("0x1234|10.0.0.1|10.0.0.2|6", frag2, l3Start, 0x1234, ipA, ipB, 6, 16, false)
	if reassembled == nil {
		t.Fatalf("fragment 2 did not complete reassembly")
	}
	// Reassembled IP payload (after 20-byte IP header) = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
	ihl := int(reassembled[l3Start]&0x0F) * 4
	ipPayload := reassembled[l3Start+ihl:]
	want := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if string(ipPayload) != want {
		t.Errorf("reassembled IP payload = %q, want %q", string(ipPayload), want)
	}
	// IP header: MF=0, frag offset=0, total length = 20 + 26 = 46.
	totalLen := binary.BigEndian.Uint16(reassembled[l3Start+2 : l3Start+4])
	if totalLen != 46 {
		t.Errorf("reassembled IP total length = %d, want 46", totalLen)
	}
	flagsFrag := binary.BigEndian.Uint16(reassembled[l3Start+6 : l3Start+8])
	if flagsFrag != 0 {
		t.Errorf("reassembled IP flags/frag = 0x%x, want 0 (MF=0, frag=0)", flagsFrag)
	}
	// Out-of-order: a fresh group with fragment 2 (last) first, then fragment 1.
	r2 := NewFragmentReassembler()
	if got := r2.AddFragment("g|10.0.0.1|10.0.0.2|6", frag2, l3Start, 0x1234, ipA, ipB, 6, 16, false); got != nil {
		t.Errorf("last fragment alone should not reassemble")
	}
	reassembled2 := r2.AddFragment("g|10.0.0.1|10.0.0.2|6", frag1, l3Start, 0x1234, ipA, ipB, 6, 0, true)
	if reassembled2 == nil {
		t.Fatalf("out-of-order reassembly failed")
	}
	ipPayload2 := reassembled2[l3Start+int(reassembled2[l3Start]&0x0F)*4:]
	if string(ipPayload2) != want {
		t.Errorf("out-of-order reassembled = %q, want %q", string(ipPayload2), want)
	}
}

// TestFragmentReassembler_Incomplete verifies an incomplete group (missing a
// fragment) does not reassemble and is discarded by Flush.
func TestFragmentReassembler_Incomplete(t *testing.T) {
	r := NewFragmentReassembler()
	// Only the first fragment (MF=1); no last fragment.
	frag := []byte{0x45, 0, 0x18, 0, 0, 0, 0x20, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD}
	// Pad to a valid-ish frame: Ethernet(14) + IP(20) + 4 bytes payload, MF set.
	frame := make([]byte, 14+len(frag))
	copy(frame[14:], frag)
	frame[14+6] = 0x20 // MF=1, frag=0
	got := r.AddFragment("g|10.0.0.1|10.0.0.2|6", frame, 14, 1, ipA, ipB, 6, 0, true)
	if got != nil {
		t.Errorf("incomplete group should not reassemble")
	}
	if discarded := r.Flush(); discarded != 1 {
		t.Errorf("Flush discarded = %d, want 1", discarded)
	}
}

// TestParse_FragmentedTCP verifies a TCP segment split across IP fragments
// reassembles correctly: IP fragments are reassembled first (§8), then the
// complete TCP segment is fed to the assembler, so the c2s stream contains the
// full payload.
func TestParse_FragmentedTCP(t *testing.T) {
	// Build the original data packet (Eth+IP+TCP+payload), then split its IP
	// payload into two fragments.
	origData := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello Fragmented World"))
	ipPayload := origData[34:] // after Eth(14)+IP(20)
	splitAt := 24              // 8-byte aligned (3 units)
	frag1Payload := ipPayload[:splitAt]
	frag2Payload := ipPayload[splitAt:]

	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var flags layers.IPv4Flag
		if mf {
			flags = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: flags, FragOffset: fragOffsetUnits}
		gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	frag1 := buildFrag(0xABCD, 0, true, frag1Payload)
	frag2 := buildFrag(0xABCD, 3, false, frag2Payload) // offset 24 bytes = 3 units

	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		frag1, frag2, // fragmented data packet
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 112, 201, flagFIN|flagACK, nil),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5), time.UnixMicro(6)}
	payloadsPath := filepath.Join(t.TempDir(), "frag.payloads")
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	// The c2s reassembled stream must contain the full payload despite the data
	// packet being fragmented across two IP fragments.
	got, err := readBytesAt(payloadsPath, flow.C2SOffset, int(flow.C2SLength))
	if err != nil {
		t.Fatalf("read payloads: %v", err)
	}
	if !strings.Contains(string(got), "Hello Fragmented World") {
		t.Errorf("fragmented TCP did not reassemble; c2s stream = %q", string(got))
	}
	// Both fragment packets are indexed with FragGroupID.
	var fragPkts int
	for _, p := range analysis.Packets {
		if p.FragGroupID != "" {
			fragPkts++
		}
	}
	if fragPkts != 2 {
		t.Errorf("fragment packets indexed = %d, want 2", fragPkts)
	}
}

// TestTrigramIndex_Search verifies the trigram index finds substrings in
// indexed segments: text, binary, short (<3B) patterns, and misses.
func TestTrigramIndex_Search(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("Hello World"))
	idx.AddSegment("f1", "s2c", []byte("Goodbye World"))
	idx.AddSegment("f2", "c2s", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02})

	// Text substring >= 3 bytes.
	m := idx.Search([]byte("World"))
	if len(m) != 2 {
		t.Errorf("'World' matches = %d, want 2 (c2s + s2c of f1)", len(m))
	}
	// Binary substring.
	m = idx.Search([]byte{0xAD, 0xBE, 0xEF})
	if len(m) != 1 || m[0].FlowID != "f2" {
		t.Errorf("binary match = %+v, want 1 in f2", m)
	}
	// Short pattern (< 3 bytes) via linear scan.
	m = idx.Search([]byte("Hi"))
	if len(m) != 0 {
		t.Errorf("'Hi' matches = %d, want 0", len(m))
	}
	m = idx.Search([]byte("ll"))
	if len(m) != 1 || m[0].FlowID != "f1" {
		t.Errorf("'ll' match = %+v, want 1 in f1 c2s", m)
	}
	// No match.
	m = idx.Search([]byte("missing"))
	if len(m) != 0 {
		t.Errorf("'missing' matches = %d, want 0", len(m))
	}
}

// TestParse_TrigramEndToEnd verifies the parser builds a trigram index over
// TCP reassembled streams and UDP payloads, and Search locates a substring in
// the right flow.
func TestParse_TrigramEndToEnd(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("GET /index.html HTTP/1.1")),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 122, 201, flagFIN|flagACK, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("DNS-QUERY-MAGIC")),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5), time.UnixMicro(6)}
	payloadsPath := filepath.Join(t.TempDir(), "tri.payloads")
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// TCP flow: search for a substring in the reassembled c2s stream.
	m := analysis.Trigram.Search([]byte("/index.html"))
	if len(m) != 1 {
		t.Fatalf("'/index.html' matches = %d, want 1", len(m))
	}
	tcpFlow := analysis.Flows[0] // TCP flow (first packet is SYN)
	if m[0].FlowID != tcpFlow.ID {
		t.Errorf("match FlowID = %s, want TCP flow %s", m[0].FlowID, tcpFlow.ID)
	}
	if m[0].Dir != "c2s" {
		t.Errorf("match Dir = %s, want c2s", m[0].Dir)
	}
	// UDP flow: search for the DNS magic.
	m = analysis.Trigram.Search([]byte("MAGIC"))
	if len(m) != 1 {
		t.Fatalf("'MAGIC' matches = %d, want 1", len(m))
	}
	udpFlow := analysis.Flows[1]
	if m[0].FlowID != udpFlow.ID {
		t.Errorf("UDP match FlowID = %s, want %s", m[0].FlowID, udpFlow.ID)
	}
}

// TestSearch_MultiCondition verifies the Search query engine combines a flow
// filter and a payload filter (AND).
func TestSearch_MultiCondition(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("password=secret"))
	idx.AddSegment("f2", "c2s", []byte("password=secret")) // same payload, different flow
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80},
		{ID: "f2", L4Protocol: "tcp", SrcIP: "10.0.0.3", DstIP: "10.0.0.2", DstPort: 443},
	}
	// Payload filter only -> both flows match (both contain "password").
	res, err := Search(flows, nil, idx, &SearchQuery{Payload: &PayloadFilter{Contains: []byte("password")}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("payload-only matches = %d, want 2", len(res))
	}
	// Payload + flow filter (DstPort=443) -> only f2.
	res, err = Search(flows, nil, idx, &SearchQuery{
		FlowFilter: &FlowFilter{DstPort: 443},
		Payload:    &PayloadFilter{Contains: []byte("password")},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 || res[0].Flow.ID != "f2" {
		t.Errorf("combined matches = %+v, want only f2", res)
	}
	// Hex encoding: search for "secret" as hex.
	res, err = Search(flows, nil, idx, &SearchQuery{
		Payload: &PayloadFilter{Contains: []byte("736563726574"), Encoding: "hex"},
	})
	if err != nil {
		t.Fatalf("Search hex: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("hex 'secret' matches = %d, want 2", len(res))
	}
}

// TestParse_HTTP_L7 verifies L7 parsing on a reassembled TCP stream: an HTTP
// request yields L7Protocol=http, L7Method=GET, L7Host, and the body offset
// points past the headers.
func TestParse_HTTP_L7(t *testing.T) {
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nrequest-body")
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, httpReq),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, uint32(101+len(httpReq)), 201, flagFIN|flagACK, nil),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5)}
	payloadsPath := filepath.Join(t.TempDir(), "http.payloads")
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.L7Protocol != "http" {
		t.Errorf("L7Protocol = %q, want http", flow.L7Protocol)
	}
	if flow.L7Method != "GET" {
		t.Errorf("L7Method = %q, want GET", flow.L7Method)
	}
	if flow.L7Host != "example.com" {
		t.Errorf("L7Host = %q, want example.com", flow.L7Host)
	}
	// Body offset: after the header block "GET...\r\n...\r\n\r\n".
	wantBodyOffset := int64(strings.Index(string(httpReq), "\r\n\r\n") + 4)
	if flow.C2SBodyOffset != wantBodyOffset {
		t.Errorf("C2SBodyOffset = %d, want %d", flow.C2SBodyOffset, wantBodyOffset)
	}
	if flow.C2SBodyLength != int64(len("request-body")) {
		t.Errorf("C2SBodyLength = %d, want %d", flow.C2SBodyLength, len("request-body"))
	}
}

// TestParse_DNS_L7 verifies L7 parsing of a UDP DNS query: L7Protocol=dns,
// L7QueryName set from the question.
func TestParse_DNS_L7(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	dns := &layers.DNS{
		ID: 0x1234, RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 2000, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, udp, dns)
	frames := [][]byte{buf.Bytes()}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.L7Protocol != "dns" {
		t.Errorf("L7Protocol = %q, want dns", flow.L7Protocol)
	}
	if !strings.Contains(flow.L7QueryName, "example.com") {
		t.Errorf("L7QueryName = %q, want example.com", flow.L7QueryName)
	}
}

func containsStr(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}

func readBytesAt(path string, offset int64, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// TestReparse verifies Reparse produces the same derived data as Parse (the
// pcap is the source of truth), and NeedsReparse detects version staleness.
func TestReparse(t *testing.T) {
	frames := [][]byte{buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	a1, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil { t.Fatalf("Parse: %v", err) }
	a2, err := Reparse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil { t.Fatalf("Reparse: %v", err) }
	if a1.PacketCount != a2.PacketCount || a1.FlowCount != a2.FlowCount {
		t.Errorf("Reparse diverged: packets %d vs %d, flows %d vs %d", a1.PacketCount, a2.PacketCount, a1.FlowCount, a2.FlowCount)
	}
	if a2.Flows[0].ParserVersion != ParserVersion {
		t.Errorf("ParserVersion = %q, want %q", a2.Flows[0].ParserVersion, ParserVersion)
	}
	if !NeedsReparse("0.0.1") { t.Error("NeedsReparse(old) = false, want true") }
	if NeedsReparse(ParserVersion) { t.Error("NeedsReparse(current) = true, want false") }
}
// MISSING-SCENARIO TESTS - appended to parser_test.go
// Each test builds a pcap (or uses the trigram/Search/fragment API directly),
// calls Parse or the relevant function, and asserts correctness with t.Errorf.

// ---------------------------------------------------------------------------
// 1. Empty pcap (0 packets) - Parse returns zero counts and no error.
// ---------------------------------------------------------------------------

func TestParse_EmptyPcap(t *testing.T) {
	path := writePcap(t, nil, nil)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse empty pcap: %v", err)
	}
	if analysis.PacketCount != 0 {
		t.Errorf("PacketCount = %d, want 0", analysis.PacketCount)
	}
	if analysis.FlowCount != 0 {
		t.Errorf("FlowCount = %d, want 0", analysis.FlowCount)
	}
	if analysis.ByteCount != 0 {
		t.Errorf("ByteCount = %d, want 0", analysis.ByteCount)
	}
	if analysis.FirstTsUs != 0 {
		t.Errorf("FirstTsUs = %d, want 0 (no packets)", analysis.FirstTsUs)
	}
	if analysis.LastTsUs != 0 {
		t.Errorf("LastTsUs = %d, want 0 (no packets)", analysis.LastTsUs)
	}
}

// ---------------------------------------------------------------------------
// 2. IPv6-only - an IPv6 UDP packet parses without error (v1 does not deeply
//    parse IPv6 but must not crash or reject the file).
// ---------------------------------------------------------------------------

// buildIPv6UDPFrame constructs an Ethernet/IPv6/UDP frame for testing.
func buildIPv6UDPFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP,
	srcPort, dstPort layers.UDPPort, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv6 := &layers.IPv6{SrcIP: srcIP, DstIP: dstIP, Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	udp.SetNetworkLayerForChecksum(ipv6)
	layersToSerialize := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6},
		ipv6,
		udp,
	}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		t.Fatalf("serialize IPv6 UDP: %v", err)
	}
	return buf.Bytes()
}

func TestParse_IPv6Only(t *testing.T) {
	ip6A := net.ParseIP("2001:db8::1")
	ip6B := net.ParseIP("2001:db8::2")
	frame := buildIPv6UDPFrame(t, macA, macB, ip6A, ip6B, 12345, 53, []byte("ipv6 dns query"))
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(42)})

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse IPv6 pcap: %v", err)
	}
	if analysis.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", analysis.PacketCount)
	}
	if analysis.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1", analysis.FlowCount)
	}
	flow := analysis.Flows[0]
	if flow.L4Protocol != "udp" {
		t.Errorf("L4Protocol = %q, want udp", flow.L4Protocol)
	}
	if flow.IPVersion != 6 {
		t.Errorf("IPVersion = %d, want 6", flow.IPVersion)
	}
	if len(analysis.Packets) != 1 {
		t.Fatalf("Packets = %d, want 1", len(analysis.Packets))
	}
	if analysis.Packets[0].L4Protocol != "udp" {
		t.Errorf("packet L4Protocol = %q, want udp", analysis.Packets[0].L4Protocol)
	}
}

// ---------------------------------------------------------------------------
// 3. UDP-only - multiple UDP packets, verify L4Protocol and direction.
// ---------------------------------------------------------------------------

func TestParse_UDPOnly(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("query")),
		buildUDPFrame(t, macB, macA, ipB, ipA, 53, 2000, []byte("response")),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("query2")),
	}
	ts := []time.Time{time.UnixMicro(100), time.UnixMicro(200), time.UnixMicro(300)}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("FlowCount = %d, want 1 (all packets same normalized 5-tuple)", analysis.FlowCount)
	}
	flow := analysis.Flows[0]
	if flow.L4Protocol != "udp" {
		t.Errorf("L4Protocol = %q, want udp", flow.L4Protocol)
	}
	if flow.PacketCount != 3 {
		t.Errorf("flow.PacketCount = %d, want 3", flow.PacketCount)
	}
	// Port 53 well-known hint: ipB:53 is server, ipA:2000 is client.
	if flow.DirMethod != "port" || flow.DirStatus != "classified" {
		t.Errorf("direction = %q/%q, want port/classified", flow.DirStatus, flow.DirMethod)
	}
	if len(analysis.Packets) != 3 {
		t.Fatalf("Packets = %d, want 3", len(analysis.Packets))
	}
	wantDirs := []string{"c2s", "s2c", "c2s"}
	for i, p := range analysis.Packets {
		if p.L4Protocol != "udp" {
			t.Errorf("packet %d L4Protocol = %q, want udp", i, p.L4Protocol)
		}
		if p.Direction != wantDirs[i] {
			t.Errorf("packet %d Direction = %q, want %q", i, p.Direction, wantDirs[i])
		}
	}
}

// ---------------------------------------------------------------------------
// 4. ARP-only - multiple ARP requests/replies, verify flows grouped correctly.
// ---------------------------------------------------------------------------

// buildARPFrame constructs an Ethernet/ARP frame.
func buildARPFrame(t *testing.T, op uint16, senderMAC, targetMAC net.HardwareAddr, senderIP, targetIP net.IP) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP.To4(),
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: senderMAC, DstMAC: targetMAC, EthernetType: layers.EthernetTypeARP},
		arp)
	return buf.Bytes()
}

func TestParse_ARPOnly(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	// ARP flow key is (op, normalized IP pair): same op + reversed-direction
	// IPs group together; different op is a separate flow.
	frames := [][]byte{
		buildARPFrame(t, 1, macA, macB, ip1, ip2), // request op=1, pair A
		buildARPFrame(t, 1, macB, macA, ip2, ip1), // request op=1, pair A reversed -> same flow
		buildARPFrame(t, 2, macA, macB, ip1, ip2), // reply op=2, pair A
		buildARPFrame(t, 2, macB, macA, ip2, ip1), // reply op=2, pair A reversed -> same flow
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4)}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.PacketCount != 4 {
		t.Errorf("PacketCount = %d, want 4", analysis.PacketCount)
	}
	// Two ARP flows: requests (op=1, 2 packets) and replies (op=2, 2 packets).
	if analysis.FlowCount != 2 {
		t.Fatalf("FlowCount = %d, want 2 (requests group; replies group)", analysis.FlowCount)
	}
	for _, flow := range analysis.Flows {
		if flow.L4Protocol != "arp" {
			t.Errorf("flow %s L4Protocol = %q, want arp", flow.ID, flow.L4Protocol)
		}
		if flow.PacketCount != 2 {
			t.Errorf("flow %s PacketCount = %d, want 2 (reversed-direction packets group)", flow.ID, flow.PacketCount)
		}
	}
	// Per-packet L4Protocol.
	for i, p := range analysis.Packets {
		if p.L4Protocol != "arp" {
			t.Errorf("packet %d L4Protocol = %q, want arp", i, p.L4Protocol)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. FirstTsUs sentinel bug - packet with ts=0 then a second at ts=100.
//    FirstTsUs must be 0 (the first packet's timestamp), not 100.
//    (0 is a valid timestamp, not an "unset" sentinel.)
// ---------------------------------------------------------------------------

func TestParse_FirstTsUsZero(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("first")),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("second")),
	}
	ts := []time.Time{time.UnixMicro(0), time.UnixMicro(100)}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FirstTsUs != 0 {
		t.Errorf("analysis.FirstTsUs = %d, want 0 (first packet at ts=0)", analysis.FirstTsUs)
	}
	if analysis.LastTsUs != 100 {
		t.Errorf("analysis.LastTsUs = %d, want 100", analysis.LastTsUs)
	}
	if len(analysis.Flows) > 0 {
		// Flow-level FirstTsUs should also be 0 (first packet timestamp).
		if analysis.Flows[0].FirstTsUs != 0 {
			t.Errorf("flow.FirstTsUs = %d, want 0", analysis.Flows[0].FirstTsUs)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Undersize frame - frame < 64 bytes triggers AnomalyFlag=undersize.
// ---------------------------------------------------------------------------

func TestParse_UndersizeFrame(t *testing.T) {
	// Build a minimal frame < 64 bytes.  Ethernet(14) + IPv4(20) + UDP(8) = 42.
	raw := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, nil)
	if len(raw) >= 64 {
		// If gopacket padded, truncate manually for the test.
		raw = raw[:42]
	}
	path := filepath.Join(t.TempDir(), "undersize.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(1), CaptureLength: len(raw), Length: len(raw)}
	w.WritePacket(ci, raw)
	f.Close()

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Packets) != 1 {
		t.Fatalf("Packets = %d, want 1", len(analysis.Packets))
	}
	if analysis.Packets[0].AnomalyFlag != "undersize" {
		t.Errorf("AnomalyFlag = %q, want undersize (frame len=%d)", analysis.Packets[0].AnomalyFlag, len(raw))
	}
}

// ---------------------------------------------------------------------------
// 7. Oversize frame - frame > 1518 bytes triggers AnomalyFlag=oversize.
// ---------------------------------------------------------------------------

func TestParse_OversizeFrame(t *testing.T) {
	// Build a UDP frame with a payload large enough to exceed 1518 bytes.
	// Ethernet(14) + IPv4(20) + UDP(8) + 1500 payload = 1542 > 1518.
	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	raw := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, payload)
	path := filepath.Join(t.TempDir(), "oversize.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(1), CaptureLength: len(raw), Length: len(raw)}
	w.WritePacket(ci, raw)
	f.Close()

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Packets) != 1 {
		t.Fatalf("Packets = %d, want 1", len(analysis.Packets))
	}
	if analysis.Packets[0].AnomalyFlag != "oversize" {
		t.Errorf("AnomalyFlag = %q, want oversize (frame len=%d)", analysis.Packets[0].AnomalyFlag, len(raw))
	}
}

// ---------------------------------------------------------------------------
// 8. ParsePacket zero-length - length=0 returns error.
// ---------------------------------------------------------------------------

func TestParsePacket_ZeroLength(t *testing.T) {
	_, err := ParsePacket("/nonexistent", 0, 0, layers.LinkTypeEthernet)
	if err == nil {
		t.Errorf("ParsePacket with length=0: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// 9. ParsePacket bad offset - offset past EOF returns error.
// ---------------------------------------------------------------------------

func TestParsePacket_BadOffset(t *testing.T) {
	// Create a valid pcap with one packet, then try ParsePacket at an offset
	// past the end.
	frame := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("hello"))
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})

	// The pcap file is small; offset 1<<30 is way past EOF.
	_, err := ParsePacket(path, 1<<30, 100, layers.LinkTypeEthernet)
	if err == nil {
		t.Errorf("ParsePacket at offset past EOF: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// 10. ExtractOffsetLayout for ARP - Eth+ARP frame: L4Start set, L4Protocol=arp,
//     IP offsets all -1.
// ---------------------------------------------------------------------------

func TestExtractOffsetLayout_ARP(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	frame := buildARPFrame(t, 1, macA, macB, ip1, ip2)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)

	if layout.L4Protocol != "arp" {
		t.Errorf("L4Protocol = %q, want arp", layout.L4Protocol)
	}
	if layout.L4Start < 0 {
		t.Errorf("L4Start = %d, want >=0 (ARP layer present)", layout.L4Start)
	}
	// All IP-layer fields should be -1 (no IP layer in pure ARP).
	if layout.SrcIP != -1 {
		t.Errorf("SrcIP = %d, want -1 (no IPv4 layer)", layout.SrcIP)
	}
	if layout.DstIP != -1 {
		t.Errorf("DstIP = %d, want -1 (no IPv4 layer)", layout.DstIP)
	}
	if layout.TTL != -1 {
		t.Errorf("TTL = %d, want -1", layout.TTL)
	}
	if layout.DSCPECN != -1 {
		t.Errorf("DSCPECN = %d, want -1", layout.DSCPECN)
	}
	if layout.IPFlagsFrag != -1 {
		t.Errorf("IPFlagsFrag = %d, want -1", layout.IPFlagsFrag)
	}
	if layout.IPID != -1 {
		t.Errorf("IPID = %d, want -1", layout.IPID)
	}
	// L2 fields should still be set.
	if layout.SrcMAC < 0 || layout.DstMAC < 0 {
		t.Errorf("L2 MAC offsets not set: SrcMAC=%d DstMAC=%d", layout.SrcMAC, layout.DstMAC)
	}
	if layout.L2Start != 0 {
		t.Errorf("L2Start = %d, want 0", layout.L2Start)
	}
}

// ---------------------------------------------------------------------------
// 11. No direction sync - pure P2P UDP (random ports, no well-known port):
//     DirStatus=uncertain, DirMethod=first_packet.
// ---------------------------------------------------------------------------

func TestParse_NoDirectionSync(t *testing.T) {
	// Both ports are ephemeral (no well-known port hint).
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 30000, 30001, []byte("hello")),
		buildUDPFrame(t, macB, macA, ipB, ipA, 30001, 30000, []byte("world")),
	}
	ts := []time.Time{time.UnixMicro(10), time.UnixMicro(20)}
	path := writePcap(t, frames, ts)

	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("FlowCount = %d, want 1", analysis.FlowCount)
	}
	flow := analysis.Flows[0]
	if flow.DirStatus != "uncertain" {
		t.Errorf("DirStatus = %q, want uncertain (no well-known port)", flow.DirStatus)
	}
	if flow.DirMethod != "first_packet" {
		t.Errorf("DirMethod = %q, want first_packet", flow.DirMethod)
	}
	// First-packet src is the client candidate.
	if flow.Client != "10.0.0.1:30000" {
		t.Errorf("Client = %q, want 10.0.0.1:30000 (first-packet src)", flow.Client)
	}
}

// ---------------------------------------------------------------------------
// 12. Trigram empty pattern - Search([]byte{}) returns nil.
// ---------------------------------------------------------------------------

func TestTrigram_EmptyPattern(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	m := idx.Search([]byte{})
	if m != nil {
		t.Errorf("Search([]byte{}) = %v, want nil", m)
	}
}

// ---------------------------------------------------------------------------
// 13. Trigram pattern longer than any segment - search returns nil.
// ---------------------------------------------------------------------------

func TestTrigram_PatternLongerThanSegment(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("short"))
	m := idx.Search([]byte("this pattern is much longer than any segment"))
	if len(m) != 0 {
		t.Errorf("overlong pattern matches = %d, want 0", len(m))
	}
}

// ---------------------------------------------------------------------------
// 14. Search with flow filter only (no payload filter) - returns matching
//     flows with empty Matches.
// ---------------------------------------------------------------------------

func TestSearch_FlowFilterOnly(t *testing.T) {
	// makeFlows returns a fresh slice each call so filterFlows (which reuses
	// its input's backing array) does not corrupt subsequent calls.
	makeFlows := func() []FlowModelView {
		return []FlowModelView{
			{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80},
			{ID: "f2", L4Protocol: "udp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 53},
			{ID: "f3", L4Protocol: "tcp", SrcIP: "10.0.0.3", DstIP: "10.0.0.4", DstPort: 443},
		}
	}
	// No trigram index (nil) - payload filter would panic, but flow-only is fine.
	res, err := Search(makeFlows(), nil, nil, &SearchQuery{
		FlowFilter: &FlowFilter{Protocol: "tcp"},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2 (f1 and f3 are tcp)", len(res))
	}
	// Each result should have empty Matches (no payload filter).
	for _, r := range res {
		if r.Flow.L4Protocol != "tcp" {
			t.Errorf("result flow %s protocol = %s, want tcp", r.Flow.ID, r.Flow.L4Protocol)
		}
		if len(r.Matches) != 0 {
			t.Errorf("result flow %s Matches = %d, want 0 (no payload filter)", r.Flow.ID, len(r.Matches))
		}
	}
	// Flow filter with DstPort=443: only f3.
	res, err = Search(makeFlows(), nil, nil, &SearchQuery{
		FlowFilter: &FlowFilter{DstPort: 443},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 || res[0].Flow.ID != "f3" {
		t.Errorf("DstPort=443 results = %+v, want only f3", res)
	}
}

// ---------------------------------------------------------------------------
// 15. Search with payload filter only (no flow filter) - all flows are
//     candidates, only those with matching payload content are returned.
// ---------------------------------------------------------------------------

func TestSearch_PayloadFilterOnly(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80},
		{ID: "f2", L4Protocol: "udp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 53},
	}
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("secret password"))
	idx.AddSegment("f2", "c2s", []byte("other data"))

	res, err := Search(flows, nil, idx, &SearchQuery{
		Payload: &PayloadFilter{Contains: []byte("password")},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1 (only f1 contains 'password')", len(res))
	}
	if res[0].Flow.ID != "f1" {
		t.Errorf("match Flow.ID = %s, want f1", res[0].Flow.ID)
	}
	if len(res[0].Matches) == 0 {
		t.Errorf("Matches empty, want at least 1 trigram match location")
	}
}

// ---------------------------------------------------------------------------
// 16. DecodePayloadFilter odd hex - "abc" (3 hex chars) -> error.
// ---------------------------------------------------------------------------

func TestDecodePayloadFilter_OddHex(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80},
	}
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))

	_, err := Search(flows, nil, idx, &SearchQuery{
		Payload: &PayloadFilter{Contains: []byte("abc"), Encoding: "hex"},
	})
	if err == nil {
		t.Errorf("odd hex 'abc': expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// 17. DecodePayloadFilter ASCII - encoding="ascii" passes through raw bytes,
//     no hex decoding.  Verify Search finds the match.
// ---------------------------------------------------------------------------

func TestDecodePayloadFilter_ASCII(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80},
	}
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world target"))

	res, err := Search(flows, nil, idx, &SearchQuery{
		Payload: &PayloadFilter{Contains: []byte("target"), Encoding: "ascii"},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
	if len(res[0].Matches) == 0 {
		t.Errorf("matches empty, 'target' should be found in f1")
	}
}

// ---------------------------------------------------------------------------
// 18. FragmentReassembler out-of-order - last fragment (MF=0) added first,
//     then first fragment (MF=1).  Verify reassembly completes and payload
//     is correct.
// ---------------------------------------------------------------------------

func TestFragmentReassembler_OutOfOrder(t *testing.T) {
	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var flags layers.IPv4Flag
		if mf {
			flags = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{
			SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64,
			Protocol: layers.IPProtocolTCP, Flags: flags, FragOffset: fragOffsetUnits,
		}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	key := "0x5678|10.0.0.1|10.0.0.2|6"
	l3Start := 14
	// 8-byte payloads so fragment offsets (8-byte units) are contiguous.
	frag1 := buildFrag(0x5678, 0, true, []byte("AAAAAAAA")) // offset 0, MF=1
	frag2 := buildFrag(0x5678, 1, false, []byte("BBBBBBBB")) // offset 8 bytes = 1 unit, MF=0

	r := NewFragmentReassembler()
	// Add last fragment first.
	if got := r.AddFragment(key, frag2, l3Start, 0x5678, ipA, ipB, 6, 8, false); got != nil {
		t.Errorf("last fragment alone should not reassemble")
	}
	// Add first fragment (completes the group).
	reassembled := r.AddFragment(key, frag1, l3Start, 0x5678, ipA, ipB, 6, 0, true)
	if reassembled == nil {
		t.Fatalf("out-of-order reassembly failed (first+last now complete)")
	}
	// Verify payload.
	ihl := int(reassembled[l3Start]&0x0F) * 4
	ipPayload := reassembled[l3Start+ihl:]
	want := "AAAAAAAABBBBBBBB"
	if string(ipPayload) != want {
		t.Errorf("reassembled payload = %q, want %q", string(ipPayload), want)
	}
}

// ---------------------------------------------------------------------------
// 19. FragmentReassembler duplicate - same fragment added twice does not
//     double-count the payload bytes (reassembly is idempotent).
// ---------------------------------------------------------------------------

func TestFragmentReassembler_Duplicate(t *testing.T) {
	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var flags layers.IPv4Flag
		if mf {
			flags = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{
			SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64,
			Protocol: layers.IPProtocolTCP, Flags: flags, FragOffset: fragOffsetUnits,
		}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	key := "0x9ABC|10.0.0.1|10.0.0.2|6"
	l3Start := 14
	// 8-byte payloads so offsets 0 and 8 are contiguous (no gap).
	frag1 := buildFrag(0x9ABC, 0, true, []byte("AAAAAAAA"))  // offset 0, MF=1
	frag2 := buildFrag(0x9ABC, 1, false, []byte("BBBBBBBB")) // offset 8 bytes, MF=0

	r := NewFragmentReassembler()
	// Add both fragments once.
	got := r.AddFragment(key, frag1, l3Start, 0x9ABC, ipA, ipB, 6, 0, true)
	if got != nil {
		t.Errorf("first fragment alone should not reassemble")
	}
	got = r.AddFragment(key, frag2, l3Start, 0x9ABC, ipA, ipB, 6, 8, false)
	if got == nil {
		t.Fatalf("second fragment should complete reassembly")
	}
	ihl := int(got[l3Start]&0x0F) * 4
	firstPayload := string(got[l3Start+ihl:])
	want := "AAAAAAAABBBBBBBB"
	if firstPayload != want {
		t.Fatalf("first reassembly payload = %q, want %q", firstPayload, want)
	}

	// Now add the same fragments again (same group key, but the group is
	// already marked reassembled and must not emit again).
	got2 := r.AddFragment(key, frag1, l3Start, 0x9ABC, ipA, ipB, 6, 0, true)
	if got2 != nil {
		t.Errorf("duplicate first fragment emitted reassembled frame again (got %d bytes)", len(got2))
	}
	got3 := r.AddFragment(key, frag2, l3Start, 0x9ABC, ipA, ipB, 6, 8, false)
	if got3 != nil {
		t.Errorf("duplicate last fragment emitted reassembled frame again (got %d bytes)", len(got3))
	}
}
