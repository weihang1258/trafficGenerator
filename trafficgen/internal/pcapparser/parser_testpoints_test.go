package pcapparser

// Test points for parser.go (SIMULATED), derived from
// tools/test_points/pcapparser.md (components P1-P6). These supplement the
// tests in parser_test.go and audit_fixes_test.go by covering spec-required
// behavior paths not yet exercised.

import (
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

// --- P1.2: Parse missing file ---

func TestParse_OpenMissingFile(t *testing.T) {
	_, err := Parse("/no/such/x.pcap", nil)
	if err == nil || !strings.Contains(err.Error(), "open pcap") {
		t.Errorf("Parse missing file: err=%v, want contains 'open pcap'", err)
	}
}

// --- P1.3: Parse corrupt pcap header (bad magic 0xDEADBEEF) ---

func TestParse_CorruptPcapHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.pcap")
	if err := os.WriteFile(path, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0644); err != nil {
		t.Fatalf("write corrupt header: %v", err)
	}
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil {
		t.Fatal("Parse corrupt header: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parse pcap header") {
		t.Errorf("err=%v, want contains 'parse pcap header'", err)
	}
	if analysis != nil {
		t.Errorf("analysis non-nil on corrupt header")
	}
}

// --- P1.5: PayloadsPath unwritable ---

func TestParse_PayloadsPathUnwritable(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: "/no/dir/x.payloads"})
	if err == nil || !strings.Contains(err.Error(), "create payloads file") {
		t.Errorf("Parse with bad PayloadsPath: err=%v, want contains 'create payloads file'", err)
	}
}

// --- P1.7: Truncated record mid-stream ---

func TestParse_TruncatedRecordMidStream(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil)
	// Write a valid pcap header + 1 valid packet + second packet truncated to 8 bytes.
	path := filepath.Join(t.TempDir(), "trunc_mid.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(1), CaptureLength: len(frame), Length: len(frame)}
	if err := w.WritePacket(ci, frame); err != nil {
		t.Fatalf("write packet 1: %v", err)
	}
	// Manually corrupt: write only 8 bytes for the second packet's record.
	f.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // not enough for pcap record header (16 bytes)
	f.Close()
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil {
		t.Fatal("Parse truncated mid-stream: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "read packet at offset") {
		t.Errorf("err=%v, want contains 'read packet at offset'", err)
	}
	if analysis != nil {
		t.Error("analysis non-nil on truncated record")
	}
}

// --- P1.10: Unknown L2 (STP) -> raw flow ---

func TestParse_UnknownL2RawFlow(t *testing.T) {
	// Build a minimal L2-only frame with a non-IP/ARP EtherType (0x0026 = PTP).
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: 0x0026}
	gopacket.SerializeLayers(buf, opts, eth, gopacket.Payload([]byte("STP-like")))
	frames := [][]byte{buf.Bytes()}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse unknown L2: %v", err)
	}
	if analysis.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", analysis.PacketCount)
	}
	if analysis.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1 (raw|N synthetic flow)", analysis.FlowCount)
	}
	flow := analysis.Flows[0]
	if flow.L4Protocol != "" {
		t.Errorf("L4Protocol = %q, want empty (L2-only)", flow.L4Protocol)
	}
	// Flow key should be raw|<offset>
	if !strings.HasPrefix(flow.FlowKey, "raw|") {
		t.Errorf("FlowKey = %q, want prefix raw|", flow.FlowKey)
	}
}

// --- P1.13: New flow creation ---

func TestParse_NewFlowCreation(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("FlowCount = %d, want 1", analysis.FlowCount)
	}
	flow := analysis.Flows[0]
	if flow.FlowKey != "6|10.0.0.1:1234|10.0.0.2:80" {
		t.Errorf("FlowKey = %q, want 6|10.0.0.1:1234|10.0.0.2:80", flow.FlowKey)
	}
	if flow.SrcIP != "10.0.0.1" || flow.DstIP != "10.0.0.2" || flow.SrcPort != 1234 || flow.DstPort != 80 {
		t.Errorf("fields: src=%s:%d dst=%s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
	}
	if flow.OffsetLayout == "" || flow.OffsetLayout == "{}" {
		t.Errorf("OffsetLayout = %q, want non-empty JSON", flow.OffsetLayout)
	}
}

// --- P1.19: Frag reassembly incomplete (no tail fragment) ---

func TestParse_FragReassemblyIncomplete(t *testing.T) {
	origData := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello Fragmented World"))
	ipPayload := origData[34:]
	fragPayload := ipPayload[:24]
	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var fl layers.IPv4Flag
		if mf {
			fl = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: fl, FragOffset: fragOffsetUnits}
		gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	// Only first fragment (MF=1), no tail.
	frames := [][]byte{
		buildFrag(0xABCD, 0, true, fragPayload),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse incomplete frag: %v", err)
	}
	// Should not error; incomplete group gets flushed.
}

// --- P1.21: TCP no TCP layer (malformed) defensive ---

func TestParse_TCPNoTCPLayerDefensive(t *testing.T) {
	// Build a frame with IP proto=TCP but TCP header too short (gopacket won't produce TCP layer).
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	// IP header with protocol=TCP, but payload is just "AAAA" which is too short for TCP.
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}))
	frames := [][]byte{buf.Bytes()}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	// Must not panic.
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse malformed TCP: %v", err)
	}
	if analysis.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", analysis.PacketCount)
	}
}

// --- P1.22: TCP no network layer defensive ---

func TestParse_TCPNoNetworkLayerDefensive(t *testing.T) {
	// Build a frame with no IP layer (pure L2). Must not panic.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: 0x0026}, gopacket.Payload([]byte("no IP layer here")))
	frames := [][]byte{buf.Bytes()}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse no-IP frame: %v", err)
	}
	if analysis.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", analysis.PacketCount)
	}
}

// --- P1.24: UDP no payload skipped (trigram) ---

func TestParse_UDPNoPayloadSkipped(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.Trigram.SegmentCount() != 0 {
		t.Errorf("Trigram SegmentCount = %d, want 0 (empty payload should not be indexed)", analysis.Trigram.SegmentCount())
	}
	flow := analysis.Flows[0]
	if flow.L7Protocol != "" {
		t.Errorf("L7Protocol = %q, want empty (no payload to parse)", flow.L7Protocol)
	}
}

// --- P1.27: UDP L7 no match (random port + random payload) ---

func TestParse_UDPL7NoMatch(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 20000, 20001, []byte("random payload not matching any parser")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.L7Protocol != "" {
		t.Errorf("L7Protocol = %q, want empty (no L7 match)", flow.L7Protocol)
	}
}

// --- P1.28: Packet byte count global ---

func TestParse_PacketByteCountGlobal(t *testing.T) {
	p1 := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil)
	p2 := buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil)
	p3 := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil)
	frames := [][]byte{p1, p2, p3}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantBytes := int64(len(p1) + len(p2) + len(p3))
	if analysis.ByteCount != wantBytes {
		t.Errorf("ByteCount = %d, want %d", analysis.ByteCount, wantBytes)
	}
	if analysis.PacketCount != 3 {
		t.Errorf("PacketCount = %d, want 3", analysis.PacketCount)
	}
}

// --- P1.30: ProtocolDist skips empty L4 (STP) ---

func TestParse_ProtocolDistSkipsEmptyL4(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: 0x0026}, gopacket.Payload([]byte("STP-data")))
	path := writePcap(t, [][]byte{buf.Bytes()}, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, k := range []string{"tcp", "udp", "icmp", "arp"} {
		if analysis.ProtocolDist[k] != 0 {
			t.Errorf("ProtocolDist[%q] = %d, want 0 (empty L4 should not be counted)", k, analysis.ProtocolDist[k])
		}
	}
}

// --- P1.36: PacketSink success ---

func TestParse_PacketSinkSuccess(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("q")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	var sinkCount int
	analysis, err := Parse(path, &Options{
		PcapAssetID: "ast1", UserID: "u1", BatchSize: 1,
		PacketSink: func(b []storage.PacketModel) error {
			sinkCount += len(b)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sinkCount != 2 {
		t.Errorf("sink received %d packets, want 2", sinkCount)
	}
	if analysis.PacketCount != 2 {
		t.Errorf("PacketCount = %d, want 2", analysis.PacketCount)
	}
}

// --- P1.35: PacketSink error fails ---

func TestParse_PacketSinkErrorFails(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	_, err := Parse(path, &Options{
		PcapAssetID: "ast1", UserID: "u1", BatchSize: 1,
		PacketSink: func(b []storage.PacketModel) error {
			return errSinkFail
		},
	})
	if err == nil {
		t.Fatal("Parse: expected error from PacketSink, got nil")
	}
}

// sentinel error for sink failure tests.
type sinkError string

func (e sinkError) Error() string { return string(e) }

const errSinkFail = sinkError("sink forced failure")

// --- P1.38: No sink packets retained ---

func TestParse_NoSinkPacketsRetained(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("q")),
		buildUDPFrame(t, macB, macA, ipB, ipA, 53, 2000, []byte("r")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(analysis.Packets) != 3 {
		t.Errorf("Packets retained = %d, want 3 (no sink)", len(analysis.Packets))
	}
	for i, p := range analysis.Packets {
		if p.RawOffset <= 0 {
			t.Errorf("packet %d RawOffset = %d, want >0", i, p.RawOffset)
		}
	}
}

// --- P1.39: forwardPackets empty batch ---

func TestForwardPackets_EmptyBatch(t *testing.T) {
	// Directly call forwardPackets with an empty batch.
	opts := &Options{}
	analysis := &PcapAnalysis{}
	err := forwardPackets(opts, analysis, nil)
	if err != nil {
		t.Errorf("forwardPackets empty: %v", err)
	}
}

// --- P1.44: Flows sorted deterministically ---

func TestParse_FlowsSortedDeterministically(t *testing.T) {
	// Three different flows with different FirstTsUs.
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("b")),                 // flow A, ts=300
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),         // flow B, ts=100
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 123, []byte("c")),                 // flow C, ts=200
	}
	ts := []time.Time{time.UnixMicro(300), time.UnixMicro(100), time.UnixMicro(200)}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 3 {
		t.Fatalf("FlowCount = %d, want 3", analysis.FlowCount)
	}
	// Must be sorted by FirstTsUs ascending.
	for i := 1; i < len(analysis.Flows); i++ {
		if analysis.Flows[i].FirstTsUs < analysis.Flows[i-1].FirstTsUs {
			t.Errorf("flows not sorted by ts: flows[%d].FirstTsUs=%d < flows[%d].FirstTsUs=%d", i-1, analysis.Flows[i-1].FirstTsUs, i, analysis.Flows[i].FirstTsUs)
		}
	}
}

// --- P1.48: TCP L7 c2s success (HTTP) covered by TestParse_HTTP_L7.
// --- P1.49: TCP L7 c2s no match (HTTP port but encrypted/random bytes) ---

func TestParse_TCPL7C2SNoMatch(t *testing.T) {
	// TCP -> port 80, but payload is random/encrypted bytes.
	// The HTTP parser may still match on port (returns "http" with empty metadata),
	// but L7Method and L7Host should NOT be populated from random bytes.
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 111, 201, flagFIN|flagACK, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	// With random binary payload, the HTTP request line parser won't extract
	// a method or host. The L7Protocol may still be "http" because port matched.
	if flow.L7Method != "" {
		t.Errorf("L7Method = %q, want empty (random binary cannot produce HTTP method)", flow.L7Method)
	}
	if flow.L7Host != "" {
		t.Errorf("L7Host = %q, want empty (random binary cannot produce Host header)", flow.L7Host)
	}
}

// --- P1.56: Trigram no path (in-memory only) ---

func TestParse_TrigramNoPath(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("MAGIC_TRIGRAM_TEST")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.Trigram == nil {
		t.Fatal("Trigram = nil, want non-nil in-memory index")
	}
	m := analysis.Trigram.Search([]byte("MAGIC"))
	if len(m) == 0 {
		t.Error("Trigram.Search('MAGIC') = 0 matches, want >=1")
	}
}

// --- P1.55: Trigram persist failure non-fatal ---

func TestParse_TrigramPersistFailureNonFatal(t *testing.T) {
	frames := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("MAGIC_PAYLOAD_XYZ")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", TrigramIndexPath: "/no/dir/x.trigram"})
	if err != nil {
		t.Fatalf("Parse should not fail: %v", err)
	}
	if analysis.TrigramWriteError == nil {
		t.Error("TrigramWriteError = nil, want non-nil (write failed but was non-fatal)")
	}
	if analysis.Trigram == nil {
		t.Fatal("Trigram = nil, want non-nil in-memory fallback")
	}
	m := analysis.Trigram.Search([]byte("MAGIC_PAYLOAD"))
	if len(m) == 0 {
		t.Error("in-memory trigram search returned no results after write failure")
	}
}

// --- P2.x: openPcapReader (package-level access via exported helpers) ---

// openPcapReader is package-private; test it via Parse (which calls it).

func TestParse_TooSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "toosmall.pcap")
	if err := os.WriteFile(path, []byte{0, 0, 0}, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err == nil || !strings.Contains(err.Error(), "too small") {
		t.Errorf("Parse too-small: err=%v, want contains 'too small'", err)
	}
}

func TestParse_SeekFails(t *testing.T) {
	// Pipe file descriptor is not seekable. We can't easily pass a pipe to
	// Parse (which only takes a path). Skip this test for now: it's defensive
	// and tested in openPcapReader directly.
	t.Skip("P2.2: openPcapReader seek on pipe is covered by unit test structure; requires os.Pipe() which can't be passed by path")
}

// --- P3.x: Options.batchSize ---

func TestOptions_BatchSizeDefault(t *testing.T) {
	if got := (*Options)(nil).batchSize(); got != 1000 {
		t.Errorf("nil Options batchSize = %d, want 1000", got)
	}
	if got := (&Options{}).batchSize(); got != 1000 {
		t.Errorf("empty Options batchSize = %d, want 1000", got)
	}
	if got := (&Options{BatchSize: 0}).batchSize(); got != 1000 {
		t.Errorf("zero batchSize = %d, want 1000", got)
	}
	if got := (&Options{BatchSize: -1}).batchSize(); got != 1000 {
		t.Errorf("negative batchSize = %d, want 1000", got)
	}
}

func TestOptions_BatchSizeCustom(t *testing.T) {
	if got := (&Options{BatchSize: 50}).batchSize(); got != 50 {
		t.Errorf("batchSize 50 = %d, want 50", got)
	}
}

// --- P4.x: sortFlowStates (package-private, test via observation) ---

func TestSortFlowStates_Empty(t *testing.T) {
	got := sortFlowStates(nil)
	if len(got) != 0 {
		t.Errorf("sortFlowStates nil = %d, want 0", len(got))
	}
	got = sortFlowStates(map[string]*FlowState{})
	if len(got) != 0 {
		t.Errorf("sortFlowStates empty map = %d, want 0", len(got))
	}
}

func TestSortFlowStates_Single(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.FlowModel.FirstTsUs = 100
	m := map[string]*FlowState{"k": fs}
	got := sortFlowStates(m)
	if len(got) != 1 {
		t.Fatalf("single = %d, want 1", len(got))
	}
	if got[0].ID != fs.ID {
		t.Errorf("ID = %q, want %q", got[0].ID, fs.ID)
	}
}

func TestSortFlowStates_TiebreakByID(t *testing.T) {
	fsA := newTestFlowState("10.0.0.1", 1234, 80)
	fsA.FlowModel.FirstTsUs = 100
	fsA.FlowModel.ID = "b"
	fsB := newTestFlowState("10.0.0.2", 80, 1234)
	fsB.FlowModel.FirstTsUs = 100
	fsB.FlowModel.ID = "a"
	m := map[string]*FlowState{"b": fsA, "a": fsB}
	got := sortFlowStates(m)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	// ID "a" < "b" so a should come first on tie.
	if got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("tiebreak order = [%s, %s], want [a, b]", got[0].ID, got[1].ID)
	}
}

func TestSortFlowStates_ByTimestamp(t *testing.T) {
	fs200 := newTestFlowState("10.0.0.1", 1234, 80)
	fs200.FlowModel.FirstTsUs = 200
	fs200.FlowModel.ID = "x"
	fs100 := newTestFlowState("10.0.0.2", 80, 1234)
	fs100.FlowModel.FirstTsUs = 100
	fs100.FlowModel.ID = "y"
	m := map[string]*FlowState{"x": fs200, "y": fs100}
	got := sortFlowStates(m)
	if got[0].FirstTsUs != 100 || got[1].FirstTsUs != 200 {
		t.Errorf("ts order = [%d, %d], want [100, 200]", got[0].FirstTsUs, got[1].FirstTsUs)
	}
}

// --- P6.x: ProtocolDistJSON ---

func TestProtocolDistJSON_Marshal(t *testing.T) {
	a := &PcapAnalysis{ProtocolDist: map[string]int64{"tcp": 2, "udp": 1}}
	jsonStr := a.ProtocolDistJSON()
	if !strings.Contains(jsonStr, `"tcp":2`) || !strings.Contains(jsonStr, `"udp":1`) {
		t.Errorf("ProtocolDistJSON = %q, want tcp:2, udp:1", jsonStr)
	}
}

func TestProtocolDistJSON_Empty(t *testing.T) {
	a := &PcapAnalysis{}
	// Empty map serializes to "null" via json.Marshal (no error -> "null" returned).
	jsonStr := a.ProtocolDistJSON()
	if jsonStr == "" {
		t.Errorf("empty ProtocolDistJSON = empty string, want non-empty (null or {})")
	}
}