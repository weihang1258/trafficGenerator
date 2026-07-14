package pcapparser

// Test points for dynamic.go, derived from tools/test_points/pcapparser.md
// (components DY1-DY10). REAL tests exercising ParsePacket/populateFields/
// layerName/tcpFlagsString/netHw/netIPStr/decoderForLinkType directly.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// --- DY1: openCached ---

func TestOpenCached_OpenFail(t *testing.T) {
	_, err := openCached("/no/such/pcap.pcap")
	if err == nil || !strings.Contains(err.Error(), "open pcap for re-parse") {
		t.Errorf("openCached bad path: err=%v, want contains 'open pcap for re-parse'", err)
	}
}

func TestOpenCached_OpenSuccess(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})
	f, err := openCached(path)
	if err != nil {
		t.Fatalf("openCached: %v", err)
	}
	if f == nil {
		t.Fatal("openCached returned nil file")
	}
	// Second call returns cached handle (same pointer).
	f2, err := openCached(path)
	if err != nil {
		t.Fatalf("openCached second: %v", err)
	}
	if f2 != f {
		t.Error("openCached returned different handle on second call (expected cached)")
	}
	// Cleanup.
	CloseCachedFile(path)
}

// --- DY2: CloseCachedFile ---

func TestCloseCachedFile_Cached(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})
	openCached(path)
	CloseCachedFile(path)
	// After close, open should re-open.
	f, _ := openCached(path)
	if f == nil {
		t.Error("after close+reopen, file handle is nil")
	}
	CloseCachedFile(path)
}

func TestCloseCachedFile_NotCached(t *testing.T) {
	// Must not panic on uncached path.
	CloseCachedFile("/no/such/pcap.pcap")
}

// --- DY3: ParsePacket (negative) ---

func TestParsePacket_InvalidLength(t *testing.T) {
	_, err := ParsePacket("any", 0, 0, layers.LinkTypeEthernet)
	if err == nil || !strings.Contains(err.Error(), "invalid packet length") {
		t.Errorf("ParsePacket length=0: err=%v, want 'invalid packet length'", err)
	}
}

func TestParsePacket_UnsupportedLinkType(t *testing.T) {
	_, err := ParsePacket("any", 0, 10, layers.LinkTypeRaw)
	if err == nil || !strings.Contains(err.Error(), "Ethernet only") {
		t.Errorf("ParsePacket LinkTypeRaw: err=%v, want 'Ethernet only'", err)
	}
}

func TestParsePacket_FileOpenFail(t *testing.T) {
	_, err := ParsePacket("/no/such/pcap.pcap", 0, 10, layers.LinkTypeEthernet)
	if err == nil || !strings.Contains(err.Error(), "open pcap for re-parse") {
		t.Errorf("ParsePacket missing file: err=%v", err)
	}
}

func TestParsePacket_ReadAtFail(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})
	// Offset past EOF.
	_, err := ParsePacket(path, 1<<30, 100, layers.LinkTypeEthernet)
	if err == nil || !strings.Contains(err.Error(), "read packet bytes at") {
		t.Errorf("ParsePacket at wrong offset: err=%v, want 'read packet bytes at'", err)
	}
}

// --- DY3-INTG: ParsePacket round trip ---

func TestParse_ParsePacketRoundTrip(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 42, 99, flagSYN|flagACK, []byte("hello"))
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
	// Verify layer records match the flow's fields.
	for _, r := range records {
		switch r.Layer {
		case "ipv4":
			if r.Fields["src_ip"] != ipA.String() || r.Fields["dst_ip"] != ipB.String() {
				t.Errorf("IP fields: src=%v dst=%v", r.Fields["src_ip"], r.Fields["dst_ip"])
			}
		case "tcp":
			if r.Fields["src_port"] != uint16(1234) || r.Fields["dst_port"] != uint16(80) {
				t.Errorf("TCP ports: src=%v dst=%v", r.Fields["src_port"], r.Fields["dst_port"])
			}
			if r.Fields["seq"] != uint32(42) || r.Fields["ack"] != uint32(99) {
				t.Errorf("TCP seq/ack: %v/%v", r.Fields["seq"], r.Fields["ack"])
			}
		}
	}
}

// --- DY4: decoderForLinkType ---

func TestDecoderForLinkType_Ethernet(t *testing.T) {
	d, err := decoderForLinkType(layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("decoderForLinkType Ethernet: %v", err)
	}
	if d != layers.LayerTypeEthernet {
		t.Errorf("decoder = %v, want LayerTypeEthernet", d)
	}
}

func TestDecoderForLinkType_NonEthernet(t *testing.T) {
	_, err := decoderForLinkType(layers.LinkTypeRaw)
	if err == nil || !strings.Contains(err.Error(), "Ethernet only") {
		t.Errorf("decoderForLinkType Raw: err=%v", err)
	}
}

// --- DY5: buildLayerRecords ---

func TestBuildLayerRecords_EmptyPacket(t *testing.T) {
	pkt := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
	records := buildLayerRecords(pkt)
	// gopacket always produces a Payload layer for any input. Verify all
	// records have empty Fields (no recognized layers).
	for _, r := range records {
		if len(r.Fields) != 0 {
			t.Errorf("empty-packet record %s has Fields=%v, want empty", r.Layer, r.Fields)
		}
	}
}

func TestBuildLayerRecords_MultiLayer(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	records := buildLayerRecords(pkt)
	names := make([]string, len(records))
	for i, r := range records {
		names[i] = r.Layer
	}
	if len(records) < 3 {
		t.Fatalf("records = %d, want >=3 (eth+ipv4+tcp)", len(records))
	}
	if !containsStr(names, "eth") || !containsStr(names, "ipv4") || !containsStr(names, "tcp") {
		t.Errorf("layers = %v, want eth+ipv4+tcp", names)
	}
}

// --- DY6: layerName ---

func TestLayerName_Ethernet(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		t.Fatal("no Ethernet layer")
	}
	if got := layerName(eth); got != "eth" {
		t.Errorf("layerName(Ethernet) = %q, want eth", got)
	}
}

func TestLayerName_IPv4(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ipv4 := pkt.Layer(layers.LayerTypeIPv4)
	if ipv4 == nil {
		t.Fatal("no IPv4 layer")
	}
	if got := layerName(ipv4); got != "ipv4" {
		t.Errorf("layerName(IPv4) = %q, want ipv4", got)
	}
}

func TestLayerName_TCP(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	tcp := pkt.Layer(layers.LayerTypeTCP)
	if tcp == nil {
		t.Fatal("no TCP layer")
	}
	if got := layerName(tcp); got != "tcp" {
		t.Errorf("layerName(TCP) = %q, want tcp", got)
	}
}

func TestLayerName_UDP(t *testing.T) {
	frame := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("q"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	udp := pkt.Layer(layers.LayerTypeUDP)
	if udp == nil {
		t.Fatal("no UDP layer")
	}
	if got := layerName(udp); got != "udp" {
		t.Errorf("layerName(UDP) = %q, want udp", got)
	}
}

func TestLayerName_Unknown(t *testing.T) {
	// An unknown layer returns its LayerType string.
	lt := gopacket.LayerType(0x12345678)
	unknown := &simpleLayer{lt: lt}
	if got := layerName(unknown); got == "" {
		t.Errorf("layerName(unknown) = empty, want non-empty")
	}
}

// simpleLayer is a minimal gopacket.Layer implementation for testing.
type simpleLayer struct {
	lt gopacket.LayerType
}

func (s *simpleLayer) LayerType() gopacket.LayerType { return s.lt }
func (s *simpleLayer) LayerContents() []byte         { return nil }
func (s *simpleLayer) LayerPayload() []byte           { return nil }

// --- DY8: tcpFlagsString ---

func TestTCPFlagsString_FIN(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{FIN: true})
	if s != "FIN" {
		t.Errorf("FIN only = %q, want FIN", s)
	}
}

func TestTCPFlagsString_SYN(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{SYN: true})
	if s != "SYN" {
		t.Errorf("SYN only = %q, want SYN", s)
	}
}

func TestTCPFlagsString_RST(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{RST: true})
	if s != "RST" {
		t.Errorf("RST only = %q, want RST", s)
	}
}

func TestTCPFlagsString_PSH(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{PSH: true})
	if s != "PSH" {
		t.Errorf("PSH only = %q, want PSH", s)
	}
}

func TestTCPFlagsString_ACK(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{ACK: true})
	if s != "ACK" {
		t.Errorf("ACK only = %q, want ACK", s)
	}
}

func TestTCPFlagsString_URG(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{URG: true})
	if s != "URG" {
		t.Errorf("URG only = %q, want URG", s)
	}
}

func TestTCPFlagsString_Multiple(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{SYN: true, ACK: true})
	if s != "SYN,ACK" {
		t.Errorf("SYN+ACK = %q, want SYN,ACK", s)
	}
}

func TestTCPFlagsString_None(t *testing.T) {
	s := tcpFlagsString(&layers.TCP{})
	if s != "none" {
		t.Errorf("no flags = %q, want none", s)
	}
}

// --- DY9: netHw ---

func TestNetHw_6Bytes(t *testing.T) {
	got := netHw([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	if got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("netHw = %q, want aa:bb:cc:dd:ee:ff", got)
	}
}

func TestNetHw_OtherLen(t *testing.T) {
	got := netHw([]byte{0xaa, 0xbb})
	if got != "aabb" {
		t.Errorf("netHw 2 bytes = %q, want aabb", got)
	}
}

// --- DY10: netIPStr ---

func TestNetIPStr_4Bytes(t *testing.T) {
	got := netIPStr([]byte{10, 0, 0, 1})
	if got != "10.0.0.1" {
		t.Errorf("netIPStr 4-bytes = %q, want 10.0.0.1", got)
	}
}

func TestNetIPStr_16Bytes(t *testing.T) {
	got := netIPStr(net.ParseIP("2001:db8::1").To16())
	if got != "2001:db8::1" {
		t.Errorf("netIPStr 16-bytes = %q, want 2001:db8::1", got)
	}
}

func TestNetIPStr_OtherLen(t *testing.T) {
	got := netIPStr([]byte{0xaa, 0xbb})
	if got != "aabb" {
		t.Errorf("netIPStr 2-bytes = %q, want aabb", got)
	}
}