package pcapparser

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// TestAuditFix_ParseNilOptions (M2): Parse(path, nil) must not panic -- the
// documented contract says nil *Options uses defaults.
func TestAuditFix_ParseNilOptions(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, nil) // must not panic
	if err != nil {
		t.Fatalf("Parse(path, nil): %v", err)
	}
	if analysis.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", analysis.PacketCount)
	}
}

// TestAuditFix_TCPStatsPopulated (H2/H3): a TCP flow with a SYN carrying MSS +
// WindowScale options, a retransmission, and varying windows must populate
// RetransCount, MSS, WindowScale, WindowRange, and TCPOptions.
func TestAuditFix_TCPStatsPopulated(t *testing.T) {
	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}} // 1460
	wscale := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}
	sack := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2, OptionData: nil}
	buildSYN := func(seq uint32, opts []layers.TCPOption) []byte {
		buf := gopacket.NewSerializeBuffer()
		o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: seq, SYN: true, Window: 65535, Options: opts}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
		return buf.Bytes()
	}
	data := []byte("hello world")
	frames := [][]byte{
		buildSYN(100, []layers.TCPOption{mss, wscale, sack}),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, data),      // window 65535
		// Retransmission: same seq as the previous data packet.
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, data),
	}
	// Override the window on one packet to vary the range.
	frames[3] = buildTCPFrameWin(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, data, 8192)
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5)}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var flow *storage.FlowModel //nolint:unused
	for i := range analysis.Flows {
		if analysis.Flows[i].L4Protocol == "tcp" {
			flow = &analysis.Flows[i]
			break
		}
	}
	if flow == nil {
		t.Fatal("no TCP flow found")
	}
	if flow.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", flow.MSS)
	}
	if flow.WindowScale != 7 {
		t.Errorf("WindowScale = %d, want 7", flow.WindowScale)
	}
	if flow.RetransCount < 1 {
		t.Errorf("RetransCount = %d, want >=1", flow.RetransCount)
	}
	if flow.WindowRange == "" {
		t.Error("WindowRange empty, want populated")
	} else {
		var rng []uint16
		if err := json.Unmarshal([]byte(flow.WindowRange), &rng); err == nil && len(rng) == 2 {
			if rng[0] != 8192 || rng[1] != 65535 {
				t.Errorf("WindowRange = %v, want [8192 65535]", rng)
			}
		}
	}
	if flow.TCPOptions == "" {
		t.Error("TCPOptions empty, want populated with option kinds (2,3,4)")
	} else if !strings.Contains(flow.TCPOptions, "2") || !strings.Contains(flow.TCPOptions, "3") || !strings.Contains(flow.TCPOptions, "4") {
		t.Errorf("TCPOptions = %s, want kinds 2,3,4 (MSS,WindowScale,SACK)", flow.TCPOptions)
	}
}

// buildTCPFrameWin is like buildTCPFrame but lets the caller set the window.
func buildTCPFrameWin(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort, seq, ack uint32, flags uint8, payload []byte, window uint16) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{
		SrcPort: srcPort, DstPort: dstPort, Seq: seq, Ack: ack, Window: window,
		FIN: flags&flagFIN != 0, SYN: flags&flagSYN != 0, RST: flags&flagRST != 0,
		PSH: flags&flagPSH != 0, ACK: flags&flagACK != 0,
	}
	ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	layersToSerialize := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp,
	}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	gopacket.SerializeLayers(buf, opts, layersToSerialize...)
	return buf.Bytes()
}

// TestAuditFix_FullyFragmentedTCP (H1): a TCP data segment split across IP
// fragments with NO captured handshake must still reassemble into a flow with
// the payload in the c2s stream. Before the fix, the flow was never created
// and the reassembled datagram was silently discarded.
func TestAuditFix_FullyFragmentedTCP(t *testing.T) {
	origData := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello Fragmented Only"))
	ipPayload := origData[34:] // after Eth(14)+IP(20)
	splitAt := 24              // 8-byte aligned (3 units)
	frag1Payload := ipPayload[:splitAt]
	frag2Payload := ipPayload[splitAt:]

	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var fl layers.IPv4Flag
		if mf {
			fl = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: fl, FragOffset: fragOffsetUnits}
		gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	frames := [][]byte{
		buildFrag(0xABCD, 0, true, frag1Payload),
		buildFrag(0xABCD, 3, false, frag2Payload),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2)}
	payloadsPath := filepath.Join(t.TempDir(), "frag.payloads")
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Find the TCP flow (not a raw|N synthetic flow).
	var tcpFlow *storage.FlowModel
	for i := range analysis.Flows {
		if analysis.Flows[i].L4Protocol == "tcp" {
			tcpFlow = &analysis.Flows[i]
			break
		}
	}
	if tcpFlow == nil {
		t.Fatal("no TCP flow created from fully-fragmented data; reassembled datagram was discarded")
	}
	// The c2s reassembled stream must contain the payload.
	if tcpFlow.C2SLength == 0 {
		t.Fatal("C2SLength = 0; reassembled stream not materialized")
	}
	got, err := readBytesAt(payloadsPath, tcpFlow.C2SOffset, int(tcpFlow.C2SLength))
	if err != nil {
		t.Fatalf("read payloads: %v", err)
	}
	if !strings.Contains(string(got), "Hello Fragmented Only") {
		t.Errorf("fragmented-only TCP did not reassemble; c2s stream = %q", string(got))
	}
}

// TestAuditFix_PacketFilter (H4): PacketFilter narrows results by packet
// direction. A flow with both c2s and s2c packets, filtered to direction=c2s,
// returns the flow with only its c2s packets.
func TestAuditFix_PacketFilter(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	pkts := []PacketModelView{
		{ID: "p1", FlowID: "f1", Direction: "c2s", TimestampUs: 10, L4Protocol: "tcp"},
		{ID: "p2", FlowID: "f1", Direction: "s2c", TimestampUs: 20, L4Protocol: "tcp"},
		{ID: "p3", FlowID: "f1", Direction: "c2s", TimestampUs: 30, L4Protocol: "tcp"},
	}
	res, err := Search(flows, pkts, NewTrigramIndex(), &SearchQuery{
		PacketFilter: &PacketFilter{Direction: "c2s"},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
	if len(res[0].Packets) != 2 {
		t.Errorf("c2s packets = %d, want 2", len(res[0].Packets))
	}
	// Time range filter.
	res, err = Search(flows, pkts, NewTrigramIndex(), &SearchQuery{
		PacketFilter: &PacketFilter{TimeStartUs: 15, TimeEndUs: 25},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 || len(res[0].Packets) != 1 || res[0].Packets[0].ID != "p2" {
		t.Errorf("time-range filter wrong: %+v", res)
	}
	// A flow with no matching packets is excluded.
	res, err = Search(flows, pkts, NewTrigramIndex(), &SearchQuery{
		PacketFilter: &PacketFilter{Direction: "s2c", TimeStartUs: 100},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("no-match filter should exclude flow, got %d results", len(res))
	}
}

// TestAuditFix_MatchPreview (M4): MatchPreview returns flow IDs matching a
// FlowMatcher, with CIDR support on SrcIP/DstIP.
func TestAuditFix_MatchPreview(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", SrcPort: 1234, DstPort: 80},
		{ID: "f2", L4Protocol: "udp", SrcIP: "10.0.0.2", SrcPort: 5353, DstPort: 53},
		{ID: "f3", L4Protocol: "tcp", SrcIP: "192.168.1.1", SrcPort: 2000, DstPort: 443},
	}
	// Protocol + CIDR match.
	hits := MatchPreview(flows, FlowMatcher{Protocol: "tcp", SrcIP: "10.0.0.0/8"})
	if len(hits) != 1 || hits[0] != "f1" {
		t.Errorf("tcp+10.0.0.0/8 = %v, want [f1]", hits)
	}
	// Exact IP match.
	hits = MatchPreview(flows, FlowMatcher{SrcIP: "192.168.1.1"})
	if len(hits) != 1 || hits[0] != "f3" {
		t.Errorf("exact src_ip = %v, want [f3]", hits)
	}
	// Empty matcher = all flows.
	hits = MatchPreview(flows, FlowMatcher{})
	if len(hits) != 3 {
		t.Errorf("empty matcher = %v, want 3 flows", hits)
	}
}

// TestAuditFix_TrigramDiskFile (M3): when TrigramIndexPath is set, Parse writes
// a .trigram file that can be loaded back and searched.
func TestAuditFix_TrigramDiskFile(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 1234, 53, []byte("MAGICPAYLOAD")),
	}
	ts := []time.Time{time.UnixMicro(1)}
	triPath := filepath.Join(t.TempDir(), "out.trigram")
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", TrigramIndexPath: triPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.TrigramWriteError != nil {
		t.Fatalf("trigram write error: %v", analysis.TrigramWriteError)
	}
	if _, err := os.Stat(triPath); err != nil {
		t.Fatalf(".trigram file not written: %v", err)
	}
	loaded, err := LoadFromFile(triPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	m := loaded.Search([]byte("MAGIC"))
	if len(m) == 0 {
		t.Error("loaded trigram index search found nothing for MAGIC")
	}
}

// TestAuditFix_TLSMetadata (L1): the TLS parser extracts version, cipher
// suites, and SNI from a ClientHello.
func TestAuditFix_TLSMetadata(t *testing.T) {
	// Build a minimal ClientHello with SNI + cipher suite + version 0x0303.
	ch := buildTLSClientHello(t, "example.com")
	res, err := tlsParser{}.Parse(ch)
	if err != nil {
		t.Fatalf("tls parse: %v", err)
	}
	if res.Metadata["sni"] != "example.com" {
		t.Errorf("sni = %v, want example.com", res.Metadata["sni"])
	}
	if res.Metadata["version"] != "TLS 1.2" {
		t.Errorf("version = %v, want TLS 1.2", res.Metadata["version"])
	}
	codes, _ := res.Metadata["cipher_suites"].([]string)
	if len(codes) == 0 {
		t.Error("cipher_suites empty, want at least one")
	}
}

// buildTLSClientHello builds a minimal TLS ClientHello record with the given SNI.
func buildTLSClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	// ClientHello body (after handshake header).
	sniBytes := []byte(sni)
	sniExt := append([]byte{0, 0}, // ext type SNI
		byte((len(sniBytes)+5)>>8), byte(len(sniBytes)+5), // ext data len
		byte((len(sniBytes)+3)>>8), byte(len(sniBytes)+3), // server name list len
		0, // name type host_name
		byte(len(sniBytes)>>8), byte(len(sniBytes)), // name len
	)
	sniExt = append(sniExt, sniBytes...)
	extensions := append([]byte{byte(len(sniExt) >> 8), byte(len(sniExt))}, sniExt...)
	ciphers := []byte{0, 2, 0xc0, 0x2f} // 1 cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	compression := []byte{1, 0} // 1 method: null
	sid := []byte{0}            // empty session id

	body := []byte{0x03, 0x03} // version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, sid...)
	body = append(body, ciphers...)
	body = append(body, compression...)
	body = append(body, extensions...)

	// Handshake header: type(1) + length(3).
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	// Record header: type 0x16 + version 0x0303 + length.
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

// TestAuditFix_TrigramRarestSearch (L3): search still finds all occurrences
// after switching to rarest-trigram candidate selection (correctness preserved).
func TestAuditFix_TrigramRarestSearch(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	m := idx.Search([]byte("/index.html"))
	if len(m) != 1 {
		t.Errorf("search /index.html = %d matches, want 1", len(m))
	}
	m = idx.Search([]byte("Host"))
	if len(m) != 1 {
		t.Errorf("search Host = %d matches, want 1", len(m))
	}
	// No match.
	m = idx.Search([]byte("NOTPRESENT"))
	if len(m) != 0 {
		t.Errorf("search NOTPRESENT = %d matches, want 0", len(m))
	}
}
