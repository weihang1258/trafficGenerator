package pcapparser

// Test points for flow.go, derived from tools/test_points/pcapparser.md
// (components F1-F20). These are REAL (pure-function) tests unless marked
// SIMULATED. They supplement the integration tests in parser_test.go /
// audit_fixes_test.go by exercising each branch directly.
//
// Known-bug test points assert the CORRECT behavior but use t.Skip with the
// bug description so the suite stays green; remove the skip when fixed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// filepathJoinTemp joins a temp-dir path with name (test helper).
func filepathJoinTemp(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// --- F1: compareEndpoints ---

func TestCompareEndpoints_IPDiffer(t *testing.T) {
	a := endpoint{IP: "1.1.1.1", Port: 80}
	b := endpoint{IP: "2.2.2.2", Port: 80}
	got := compareEndpoints(a, b)
	if got == 0 {
		t.Errorf("compareEndpoints(%v,%v) = 0, want non-zero", a, b)
	}
	// "1.1.1.1" < "2.2.2.2" lexicographically
	if got >= 0 {
		t.Errorf("compareEndpoints = %d, want < 0 (1.1.1.1 < 2.2.2.2)", got)
	}
}

func TestCompareEndpoints_PortLess(t *testing.T) {
	a := endpoint{IP: "10.0.0.1", Port: 10}
	b := endpoint{IP: "10.0.0.1", Port: 20}
	if got := compareEndpoints(a, b); got != -1 {
		t.Errorf("port-less compare = %d, want -1", got)
	}
}

func TestCompareEndpoints_PortGreater(t *testing.T) {
	a := endpoint{IP: "10.0.0.1", Port: 20}
	b := endpoint{IP: "10.0.0.1", Port: 10}
	if got := compareEndpoints(a, b); got != 1 {
		t.Errorf("port-greater compare = %d, want 1", got)
	}
}

func TestCompareEndpoints_Equal(t *testing.T) {
	a := endpoint{IP: "10.0.0.1", Port: 80}
	b := endpoint{IP: "10.0.0.1", Port: 80}
	if got := compareEndpoints(a, b); got != 0 {
		t.Errorf("equal compare = %d, want 0", got)
	}
}

// --- F2: flowKeyTCPUDP (exact key format) ---

func TestFlowKeyTCPUDP_NormalOrder(t *testing.T) {
	// ipA(10.0.0.1):1234 <= ipB(10.0.0.2):80 -> no swap
	got := flowKeyTCPUDP(ipA, ipB, 1234, 80, 6)
	want := "6|10.0.0.1:1234|10.0.0.2:80"
	if got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

func TestFlowKeyTCPUDP_ReversedOrder(t *testing.T) {
	// ipB:80 -> ipA:1234: endpoints swap so the smaller is first.
	got := flowKeyTCPUDP(ipB, ipA, 80, 1234, 6)
	want := "6|10.0.0.1:1234|10.0.0.2:80"
	if got != want {
		t.Errorf("reversed key = %q, want %q (normalized)", got, want)
	}
}

// --- F3: flowKeyICMP ---

func TestFlowKeyICMP_NormalOrder(t *testing.T) {
	got := flowKeyICMP(ipA, ipB, 8, 1)
	want := "1|10.0.0.1|10.0.0.2|8|1"
	if got != want {
		t.Errorf("icmp key = %q, want %q", got, want)
	}
}

func TestFlowKeyICMP_ReversedOrder(t *testing.T) {
	// src>dst -> IPs swap; type/id unchanged.
	got := flowKeyICMP(ipB, ipA, 8, 1)
	want := "1|10.0.0.1|10.0.0.2|8|1"
	if got != want {
		t.Errorf("icmp reversed key = %q, want %q", got, want)
	}
}

// --- F4: flowKeyARP ---

func TestFlowKeyARP_NormalOrder(t *testing.T) {
	got := flowKeyARP(ipA, ipB, 1)
	want := "arp|1|10.0.0.1|10.0.0.2"
	if got != want {
		t.Errorf("arp key = %q, want %q", got, want)
	}
}

func TestFlowKeyARP_ReversedOrder(t *testing.T) {
	got := flowKeyARP(ipB, ipA, 1)
	want := "arp|1|10.0.0.1|10.0.0.2"
	if got != want {
		t.Errorf("arp reversed key = %q, want %q", got, want)
	}
}

// --- F5: classifyDirection ---

func newTestFlowState(srcIP string, srcPort, dstPort uint16) *FlowState {
	return newFlowState("fid", "ast", "u", "key", firstPacketInfo{
		SrcIP: srcIP, DstIP: "10.0.0.2", SrcPort: srcPort, DstPort: dstPort,
		L4Proto: "tcp", IPVersion: 4, TsUs: 1,
	})
}

func TestClassifyDirection_ClientSrc(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	if got := fs.classifyDirection("10.0.0.1", 1234); got != "c2s" {
		t.Errorf("classify client src = %q, want c2s", got)
	}
}

func TestClassifyDirection_OtherSrc(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	if got := fs.classifyDirection("10.0.0.2", 80); got != "s2c" {
		t.Errorf("classify other src = %q, want s2c", got)
	}
}

// --- F6: addPacket ---

func TestAddPacket_C2SCounts(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.addPacket(storage.PacketModel{Direction: "c2s", Length: 100, TimestampUs: 10})
	if fs.C2SPackets != 1 || fs.C2SBytes != 100 {
		t.Errorf("c2s counts = %d/%d, want 1/100", fs.C2SPackets, fs.C2SBytes)
	}
	if fs.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", fs.PacketCount)
	}
}

func TestAddPacket_S2CCounts(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.addPacket(storage.PacketModel{Direction: "s2c", Length: 100, TimestampUs: 10})
	if fs.S2CPackets != 1 || fs.S2CBytes != 100 {
		t.Errorf("s2c counts = %d/%d, want 1/100", fs.S2CPackets, fs.S2CBytes)
	}
}

func TestAddPacket_FirstTsUsDecreases(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.FlowModel.FirstTsUs = 200
	fs.FlowModel.LastTsUs = 200
	fs.addPacket(storage.PacketModel{Direction: "c2s", Length: 10, TimestampUs: 100})
	if fs.FirstTsUs != 100 {
		t.Errorf("FirstTsUs = %d, want 100 (out-of-order earlier ts)", fs.FirstTsUs)
	}
}

func TestAddPacket_LastTsUsIncreases(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.FlowModel.FirstTsUs = 100
	fs.FlowModel.LastTsUs = 100
	fs.addPacket(storage.PacketModel{Direction: "c2s", Length: 10, TimestampUs: 300})
	if fs.LastTsUs != 300 {
		t.Errorf("LastTsUs = %d, want 300", fs.LastTsUs)
	}
}

func TestAddPacket_TsInRange(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.FlowModel.FirstTsUs = 100
	fs.FlowModel.LastTsUs = 300
	fs.addPacket(storage.PacketModel{Direction: "c2s", Length: 10, TimestampUs: 150})
	if fs.FirstTsUs != 100 || fs.LastTsUs != 300 {
		t.Errorf("ts in range changed bounds: First=%d Last=%d, want 100/300", fs.FirstTsUs, fs.LastTsUs)
	}
}

// --- F7: drainPackets ---

func TestDrainPackets_NonEmpty(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	p1 := storage.PacketModel{ID: "p1"}
	p2 := storage.PacketModel{ID: "p2"}
	fs.addPacket(p1)
	fs.addPacket(p2)
	out := fs.drainPackets()
	if len(out) != 2 {
		t.Fatalf("drain len = %d, want 2", len(out))
	}
	if fs.pendingPacketCount() != 0 {
		t.Errorf("after drain, pending = %d, want 0", fs.pendingPacketCount())
	}
}

func TestDrainPackets_Empty(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	out := fs.drainPackets()
	if out != nil {
		t.Errorf("drain empty = %v, want nil", out)
	}
}

// --- F8: setL7 ---

func TestSetL7_NilResultNoop(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(nil, "c2s")
	if fs.L7Protocol != "" {
		t.Errorf("L7Protocol = %q, want empty (nil result)", fs.L7Protocol)
	}
}

func TestSetL7_ProtocolSet(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Protocol: "http", Metadata: map[string]any{}}, "c2s")
	if fs.L7Protocol != "http" {
		t.Errorf("L7Protocol = %q, want http", fs.L7Protocol)
	}
}

func TestSetL7_MetadataMarshal(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Protocol: "http", Metadata: map[string]any{"status": "200"}}, "c2s")
	var m map[string]any
	if err := json.Unmarshal([]byte(fs.L7Metadata), &m); err != nil {
		t.Fatalf("L7Metadata not valid JSON: %v", err)
	}
	if m["status"] != "200" {
		t.Errorf("L7Metadata.status = %v, want 200", m["status"])
	}
}

func TestSetL7_MetadataMarshalFail(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	// chan cannot be JSON-marshaled -> Metadata stays empty.
	fs.setL7(&L7Result{Protocol: "http", Metadata: map[string]any{"x": make(chan int)}}, "c2s")
	if fs.L7Metadata != "" {
		t.Errorf("L7Metadata = %q, want empty (marshal failed)", fs.L7Metadata)
	}
}

func TestSetL7_MethodSet(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{"method": "GET"}}, "c2s")
	if fs.L7Method != "GET" {
		t.Errorf("L7Method = %q, want GET", fs.L7Method)
	}
}

func TestSetL7_HostSet(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{"host": "x.com"}}, "c2s")
	if fs.L7Host != "x.com" {
		t.Errorf("L7Host = %q, want x.com", fs.L7Host)
	}
}

func TestSetL7_SNIOverridesHost(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{"host": "x.com", "sni": "sni.com"}}, "c2s")
	if fs.L7Host != "sni.com" {
		t.Errorf("L7Host = %q, want sni.com (SNI overrides host)", fs.L7Host)
	}
}

func TestSetL7_QueryNameSet(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{"query_name": "a.com"}}, "c2s")
	if fs.L7QueryName != "a.com" {
		t.Errorf("L7QueryName = %q, want a.com", fs.L7QueryName)
	}
}

func TestSetL7_C2SBodyOffsets(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{}, BodyOffset: 4, BodyLength: 10}, "c2s")
	if fs.C2SBodyOffset != 4 || fs.C2SBodyLength != 10 {
		t.Errorf("c2s body offsets = %d/%d, want 4/10", fs.C2SBodyOffset, fs.C2SBodyLength)
	}
}

func TestSetL7_S2CBodyOffsets(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{}, BodyOffset: 5, BodyLength: 11}, "s2c")
	if fs.S2CBodyOffset != 5 || fs.S2CBodyLength != 11 {
		t.Errorf("s2c body offsets = %d/%d, want 5/11", fs.S2CBodyOffset, fs.S2CBodyLength)
	}
}

func TestSetL7_UnknownDirNoOffset(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.setL7(&L7Result{Metadata: map[string]any{}, BodyOffset: 4, BodyLength: 10}, "xyz")
	if fs.C2SBodyOffset != 0 || fs.S2CBodyOffset != 0 {
		t.Errorf("unknown dir set offsets: c2s=%d s2c=%d, want 0/0", fs.C2SBodyOffset, fs.S2CBodyOffset)
	}
}

// --- F9: setStream ---

func TestSetStream_C2S(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	s := &reassemblyStream{dir: "c2s"}
	fs.setStream("c2s", s)
	if fs.c2sStream != s {
		t.Error("c2sStream not set")
	}
}

func TestSetStream_S2C(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	s := &reassemblyStream{dir: "s2c"}
	fs.setStream("s2c", s)
	if fs.s2cStream != s {
		t.Error("s2cStream not set")
	}
}

// --- F10: seqLess (wraparound) ---

func TestSeqLess_NormalLess(t *testing.T) {
	if !seqLess(100, 200) {
		t.Error("seqLess(100,200) = false, want true")
	}
}

func TestSeqLess_NormalGreater(t *testing.T) {
	if seqLess(200, 100) {
		t.Error("seqLess(200,100) = true, want false")
	}
}

func TestSeqLess_Wraparound(t *testing.T) {
	// a=4294967200 (near max), b=100 (wrapped) -> b is "after" a.
	if !seqLess(4294967200, 100) {
		t.Error("seqLess(4294967200,100) = false, want true (wraparound)")
	}
}

func TestSeqLess_WraparoundReverse(t *testing.T) {
	if seqLess(100, 4294967200) {
		t.Error("seqLess(100,4294967200) = true, want false (wraparound reverse)")
	}
}

// --- F11: seqInRange ---

func TestSeqInRange_InRange(t *testing.T) {
	if !seqInRange(150, 100, 200) {
		t.Error("seqInRange(150,100,200) = false, want true")
	}
}

func TestSeqInRange_BelowMin(t *testing.T) {
	if seqInRange(50, 100, 200) {
		t.Error("seqInRange(50,100,200) = true, want false")
	}
}

func TestSeqInRange_AboveMax(t *testing.T) {
	if seqInRange(250, 100, 200) {
		t.Error("seqInRange(250,100,200) = true, want false")
	}
}

// --- F12: recordTCPStats (unit-level branch coverage) ---

// tcpFields is a helper building a packetFields for a TCP packet.
func tcpFields(seq uint32, flags uint8, payload []byte, window uint16) packetFields {
	return packetFields{
		l4Proto:    "tcp",
		tcpSYN:     flags&flagSYN != 0,
		tcpACK:     flags&flagACK != 0,
		tcpFIN:     flags&flagFIN != 0,
		tcpRST:     flags&flagRST != 0,
		tcpPSH:     flags&flagPSH != 0,
		tcpSeq:     seq,
		tcpWindow:  window,
		payload:    payload,
	}
}

func TestRecordTCPStats_FlagsCountInit(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	fs.finalizeTCPStats()
	if fs.FlagsSummary == "" {
		t.Errorf("FlagsSummary empty, want populated after TCP packet")
	}
}

func TestRecordTCPStats_SYNNoACK(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	if !fs.sawSYN {
		t.Error("sawSYN = false, want true")
	}
	if fs.C2SInitSeq != 100 {
		t.Errorf("C2SInitSeq = %d, want 100", fs.C2SInitSeq)
	}
}

func TestRecordTCPStats_SYNACK(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(200, flagSYN|flagACK, nil, 65535), "s2c")
	if !fs.sawSYNACK {
		t.Error("sawSYNACK = false, want true")
	}
	if fs.S2CInitSeq != 200 {
		t.Errorf("S2CInitSeq = %d, want 200", fs.S2CInitSeq)
	}
}

func TestRecordTCPStats_OptionsRecordedFirstSYN(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	f := tcpFields(100, flagSYN, nil, 65535)
	f.tcpMSS = 1460
	f.tcpWindowScale = 7
	f.tcpOptionKinds = []uint8{2, 3, 4}
	fs.recordTCPStats(f, "c2s")
	if fs.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", fs.MSS)
	}
	if fs.WindowScale != 7 {
		t.Errorf("WindowScale = %d, want 7", fs.WindowScale)
	}
	if fs.TCPOptions != "[2,3,4]" {
		t.Errorf("TCPOptions = %q, want [2,3,4]", fs.TCPOptions)
	}
}

func TestRecordTCPStats_OptionsNotReRecorded(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	f1 := tcpFields(100, flagSYN, nil, 65535)
	f1.tcpMSS = 1460
	f1.tcpOptionKinds = []uint8{2}
	fs.recordTCPStats(f1, "c2s")
	// Second SYN with different MSS: must not overwrite.
	f2 := tcpFields(200, flagSYN, nil, 65535)
	f2.tcpMSS = 999
	f2.tcpOptionKinds = []uint8{2}
	fs.recordTCPStats(f2, "s2c")
	if fs.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460 (not overwritten by 2nd SYN)", fs.MSS)
	}
	if !fs.tcpOptionsRecorded {
		t.Error("tcpOptionsRecorded = false, want true")
	}
}

func TestRecordTCPStats_ACKAfterSYNACK(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	// Full 3-way handshake: SYN (no ACK) -> SYN-ACK -> ACK.
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(200, flagSYN|flagACK, nil, 65535), "s2c")
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 65535), "c2s")
	if !fs.sawACKAfterSYN {
		t.Error("sawACKAfterSYN = false, want true")
	}
	fs.finalizeTCPStats()
	if fs.HandshakeStatus != "complete" {
		t.Errorf("HandshakeStatus = %q, want complete", fs.HandshakeStatus)
	}
}

func TestRecordTCPStats_ACKBeforeSYNACK(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	// ACK with no prior SYN-ACK: sawACKAfterSYN stays false.
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 65535), "c2s")
	if fs.sawACKAfterSYN {
		t.Error("sawACKAfterSYN = true, want false (no SYN-ACK yet)")
	}
	if fs.flagsCount["ack"] != 1 {
		t.Errorf("flagsCount[ack] = %d, want 1", fs.flagsCount["ack"])
	}
}

func TestRecordTCPStats_FlagCounts(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(102, flagFIN|flagACK, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(103, flagRST, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(104, flagPSH|flagACK, []byte("x"), 65535), "c2s")
	fs.finalizeTCPStats()
	for _, name := range []string{"syn", "ack", "fin", "rst", "psh"} {
		if !strings.Contains(fs.FlagsSummary, name) {
			t.Errorf("FlagsSummary = %q, want to contain %q", fs.FlagsSummary, name)
		}
	}
}

func TestRecordTCPStats_SeqMin(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(200, flagACK, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(100, flagACK, nil, 65535), "c2s")
	fs.finalizeTCPStats()
	if fs.seqMin != 100 {
		t.Errorf("seqMin = %d, want 100", fs.seqMin)
	}
	var rng []uint32
	if err := json.Unmarshal([]byte(fs.SeqRange), &rng); err != nil {
		t.Fatalf("SeqRange unmarshal: %v", err)
	}
	if len(rng) != 2 || rng[0] != 100 {
		t.Errorf("SeqRange = %v, want [100,...]", rng)
	}
}

func TestRecordTCPStats_SeqMax(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(300, flagACK, nil, 65535), "c2s")
	fs.finalizeTCPStats()
	if fs.seqMax != 300 {
		t.Errorf("seqMax = %d, want 300", fs.seqMax)
	}
	var rng []uint32
	json.Unmarshal([]byte(fs.SeqRange), &rng)
	if len(rng) != 2 || rng[1] != 300 {
		t.Errorf("SeqRange = %v, want [...,300]", rng)
	}
}

func TestRecordTCPStats_FirstInDir(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, []byte("0123456789"), 65535), "c2s")
	if !fs.c2sSeqSeen {
		t.Error("c2sSeqSeen = false, want true after first c2s packet")
	}
	if fs.c2sNextSeq != 110 {
		t.Errorf("c2sNextSeq = %d, want 110 (100+10)", fs.c2sNextSeq)
	}
}

func TestRecordTCPStats_RetransDetected(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, []byte("0123456789"), 65535), "c2s") // nextSeq=110
	fs.recordTCPStats(tcpFields(95, flagACK, []byte("0123456789"), 65535), "c2s")  // 95 < 110 -> retrans
	if fs.RetransCount != 1 {
		t.Errorf("RetransCount = %d, want 1", fs.RetransCount)
	}
}

func TestRecordTCPStats_OutOfOrderDetected(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, []byte("0123456789"), 65535), "c2s") // nextSeq=110
	fs.recordTCPStats(tcpFields(200, flagACK, []byte("0123456789"), 65535), "c2s")  // 200 > 110 -> ooo
	if fs.OutOfOrderCount != 1 {
		t.Errorf("OutOfOrderCount = %d, want 1", fs.OutOfOrderCount)
	}
	if fs.c2sNextSeq != 210 {
		t.Errorf("c2sNextSeq = %d, want 210 (200+10)", fs.c2sNextSeq)
	}
}

func TestRecordTCPStats_InOrderDelivery(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, []byte("0123456789"), 65535), "c2s") // nextSeq=110
	fs.recordTCPStats(tcpFields(110, flagACK, []byte("0123456789"), 65535), "c2s") // == nextSeq -> in order
	if fs.RetransCount != 0 || fs.OutOfOrderCount != 0 {
		t.Errorf("counts = %d/%d, want 0/0 (in-order)", fs.RetransCount, fs.OutOfOrderCount)
	}
	if fs.c2sNextSeq != 120 {
		t.Errorf("c2sNextSeq = %d, want 120", fs.c2sNextSeq)
	}
}

func TestRecordTCPStats_S2CRetransOOO(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	// s2c direction tracking.
	fs.recordTCPStats(tcpFields(200, flagACK, []byte("0123456789"), 65535), "s2c") // s2cNextSeq=210
	fs.recordTCPStats(tcpFields(205, flagACK, []byte("0123456789"), 65535), "s2c")  // 205<210 -> retrans
	if fs.RetransCount != 1 {
		t.Errorf("s2c RetransCount = %d, want 1", fs.RetransCount)
	}
	if !fs.s2cSeqSeen {
		t.Error("s2cSeqSeen = false, want true")
	}
}

func TestRecordTCPStats_WindowMin(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, nil, 8192), "c2s")
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 65535), "c2s")
	fs.finalizeTCPStats()
	var rng []uint16
	json.Unmarshal([]byte(fs.WindowRange), &rng)
	if len(rng) != 2 || rng[0] != 8192 {
		t.Errorf("WindowRange = %v, want [8192,...]", rng)
	}
}

func TestRecordTCPStats_WindowMax(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagACK, nil, 512), "c2s")
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 8192), "c2s")
	fs.finalizeTCPStats()
	var rng []uint16
	json.Unmarshal([]byte(fs.WindowRange), &rng)
	if len(rng) != 2 || rng[1] != 8192 {
		t.Errorf("WindowRange = %v, want [...,8192]", rng)
	}
}

// --- F12-INTG: TCP stats non-zero integration (all 6 fields) ---

// TestParse_TCPStatsNonZero_Integration asserts MSS, WindowScale, TCPOptions,
// RetransCount, OutOfOrderCount, and WindowRange are ALL populated non-zero
// from a single PCAP carrying SYN options + a retransmission + an out-of-order
// segment + a varying window. This is the core "TCP stats non-zero" test.
func TestParse_TCPStatsNonZero_Integration(t *testing.T) {
	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
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
	frames := [][]byte{
		buildSYN(100, []layers.TCPOption{mss, wscale, sack}),                                    // SYN c2s (MSS/WS/SACK)
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),        // SYN-ACK s2c
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),                // ACK c2s (completes handshake)
		buildTCPFrameWin(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("hello"), 8192), // data c2s, window 8192
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("hello")),        // retransmission (same seq)
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 120, 201, flagPSH|flagACK, []byte("world")),        // out-of-order (seq jumps)
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3), time.UnixMicro(4), time.UnixMicro(5), time.UnixMicro(6)}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var flow *storage.FlowModel
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
		t.Errorf("MSS = %d, want 1460 (non-zero)", flow.MSS)
	}
	if flow.WindowScale != 7 {
		t.Errorf("WindowScale = %d, want 7 (non-zero)", flow.WindowScale)
	}
	if flow.TCPOptions == "" {
		t.Error("TCPOptions empty, want non-zero with kinds 2,3,4")
	} else if !strings.Contains(flow.TCPOptions, "2") || !strings.Contains(flow.TCPOptions, "4") {
		t.Errorf("TCPOptions = %s, want kinds 2 and 4", flow.TCPOptions)
	}
	if flow.RetransCount < 1 {
		t.Errorf("RetransCount = %d, want >=1 (non-zero)", flow.RetransCount)
	}
	if flow.OutOfOrderCount < 1 {
		t.Errorf("OutOfOrderCount = %d, want >=1 (non-zero)", flow.OutOfOrderCount)
	}
	if flow.WindowRange == "" {
		t.Error("WindowRange empty, want non-zero")
	} else {
		var rng []uint16
		if err := json.Unmarshal([]byte(flow.WindowRange), &rng); err == nil && len(rng) == 2 {
			if rng[0] != 8192 {
				t.Errorf("WindowRange[0] = %d, want 8192", rng[0])
			}
		}
	}
	if flow.FlagsSummary == "" {
		t.Error("FlagsSummary empty, want non-zero")
	}
}

// --- F13: formatTCPOptions ---

func TestFormatTCPOptions_Empty(t *testing.T) {
	if got := formatTCPOptions(nil); got != "[]" {
		t.Errorf("formatTCPOptions(nil) = %q, want []", got)
	}
}

func TestFormatTCPOptions_Single(t *testing.T) {
	if got := formatTCPOptions([]uint8{2}); got != "[2]" {
		t.Errorf("formatTCPOptions([2]) = %q, want [2]", got)
	}
}

func TestFormatTCPOptions_Multiple(t *testing.T) {
	if got := formatTCPOptions([]uint8{2, 3, 4}); got != "[2,3,4]" {
		t.Errorf("formatTCPOptions([2,3,4]) = %q, want [2,3,4]", got)
	}
}

func TestFormatTCPOptions_Dedup(t *testing.T) {
	if got := formatTCPOptions([]uint8{2, 2, 3}); got != "[2,3]" {
		t.Errorf("formatTCPOptions([2,2,3]) = %q, want [2,3] (dedup)", got)
	}
}

// --- F14: flushStreams ---

func TestFlushStreams_NonTCP(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "udp"
	w, err := newPayloadsWriter("")
	if err != nil {
		t.Fatalf("newPayloadsWriter: %v", err)
	}
	fs.flushStreams(w, "")
	if fs.StreamFile != "" {
		t.Errorf("StreamFile = %q, want empty (non-TCP returns early)", fs.StreamFile)
	}
}

func TestFlushStreams_C2SAppendOK(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "tcp"
	fs.c2sStream = &reassemblyStream{buf: []byte("hello")}
	path := filepathJoinTemp(t, "c2sok.payloads")
	w, err := newPayloadsWriter(path)
	if err != nil {
		t.Fatalf("newPayloadsWriter: %v", err)
	}
	defer w.close()
	fs.flushStreams(w, path)
	if fs.C2SLength != int64(len("hello")) {
		t.Errorf("C2SLength = %d, want %d", fs.C2SLength, len("hello"))
	}
	if !fs.ReassemblyComplete {
		t.Error("ReassemblyComplete = false, want true (no gap)")
	}
}

func TestFlushStreams_C2SAppendFail(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "tcp"
	fs.c2sStream = &reassemblyStream{buf: []byte("hello")}
	fs.s2cStream = &reassemblyStream{buf: []byte("world")}
	w, err := newPayloadsWriter(filepathJoinTemp(t, "fail.payloads"))
	if err != nil {
		t.Fatalf("newPayloadsWriter: %v", err)
	}
	w.close() // close the file so appendStream fails
	fs.flushStreams(w, "x")
	// On write error flushStreams returns early; C2SOffset stays 0 and s2c skipped.
	if fs.C2SOffset != 0 {
		t.Errorf("C2SOffset = %d, want 0 (append failed -> early return)", fs.C2SOffset)
	}
}

func TestFlushStreams_C2SNil(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "tcp"
	// c2sStream nil, s2cStream present.
	fs.s2cStream = &reassemblyStream{buf: []byte("world")}
	w, _ := newPayloadsWriter(filepathJoinTemp(t, "nilc2s.payloads"))
	defer w.close()
	fs.flushStreams(w, "x")
	if fs.C2SLength != 0 {
		t.Errorf("C2SLength = %d, want 0 (c2s nil)", fs.C2SLength)
	}
	if fs.S2CLength != int64(len("world")) {
		t.Errorf("S2CLength = %d, want %d", fs.S2CLength, len("world"))
	}
}

func TestFlushStreams_GapC2SOnly(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "tcp"
	fs.c2sStream = &reassemblyStream{buf: []byte("hello"), gapDetected: true}
	fs.s2cStream = &reassemblyStream{buf: []byte("world")}
	w, _ := newPayloadsWriter(filepathJoinTemp(t, "gapc2s.payloads"))
	defer w.close()
	fs.flushStreams(w, "x")
	if fs.ReassemblyComplete {
		t.Error("ReassemblyComplete = true, want false (c2s gap)")
	}
	if !strings.Contains(fs.GapInfo, "c2s") {
		t.Errorf("GapInfo = %q, want contains c2s", fs.GapInfo)
	}
}

func TestFlushStreams_GapBoth(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "tcp"
	fs.c2sStream = &reassemblyStream{buf: []byte("hello"), gapDetected: true}
	fs.s2cStream = &reassemblyStream{buf: []byte("world"), gapDetected: true}
	w, _ := newPayloadsWriter(filepathJoinTemp(t, "gapboth.payloads"))
	defer w.close()
	fs.flushStreams(w, "x")
	if !strings.Contains(fs.GapInfo, "c2s") || !strings.Contains(fs.GapInfo, "s2c") {
		t.Errorf("GapInfo = %q, want contains both c2s and s2c", fs.GapInfo)
	}
}

// --- F15: finalize ---

func TestFinalize_DurationUs(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.FlowModel.FirstTsUs = 100
	fs.FlowModel.LastTsUs = 500
	fm, _ := fs.finalize()
	if fm.DurationUs != 400 {
		t.Errorf("DurationUs = %d, want 400", fm.DurationUs)
	}
}

func TestFinalize_OffsetLayoutMarshal(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.layout = OffsetLayout{L3Start: 14, L4Protocol: "tcp", SrcPort: 34}
	fm, _ := fs.finalize()
	if fm.OffsetLayout == "" || fm.OffsetLayout == "{}" {
		t.Fatalf("OffsetLayout = %q, want non-empty JSON", fm.OffsetLayout)
	}
	var layout OffsetLayout
	if err := json.Unmarshal([]byte(fm.OffsetLayout), &layout); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if layout.L3Start != 14 {
		t.Errorf("deserialized L3Start = %d, want 14", layout.L3Start)
	}
}

func TestFinalize_DrainsRemaining(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.addPacket(storage.PacketModel{ID: "p1", Direction: "c2s", Length: 10, TimestampUs: 1})
	_, rem := fs.finalize()
	if len(rem) != 1 || rem[0].ID != "p1" {
		t.Errorf("finalize rem = %v, want [p1]", rem)
	}
	if fs.pendingPacketCount() != 0 {
		t.Errorf("after finalize, pending = %d, want 0", fs.pendingPacketCount())
	}
}

// --- F16: finalizeTCPStats ---

func TestFinalizeTCPStats_NonTCP(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.L4Protocol = "udp"
	fs.finalizeTCPStats()
	if fs.HandshakeStatus != "" {
		t.Errorf("HandshakeStatus = %q, want empty (non-TCP)", fs.HandshakeStatus)
	}
}

func TestFinalizeTCPStats_CompleteHandshake(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.sawSYN = true
	fs.sawSYNACK = true
	fs.sawACKAfterSYN = true
	fs.finalizeTCPStats()
	if fs.HandshakeStatus != "complete" {
		t.Errorf("HandshakeStatus = %q, want complete", fs.HandshakeStatus)
	}
}

func TestFinalizeTCPStats_PartialHandshake(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.sawSYN = true
	fs.finalizeTCPStats()
	if fs.HandshakeStatus != "partial" {
		t.Errorf("HandshakeStatus = %q, want partial", fs.HandshakeStatus)
	}
}

func TestFinalizeTCPStats_NoHandshake(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.finalizeTCPStats()
	if fs.HandshakeStatus != "none" {
		t.Errorf("HandshakeStatus = %q, want none", fs.HandshakeStatus)
	}
}

func TestFinalizeTCPStats_FlagsCountNil(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.finalizeTCPStats()
	if fs.FlagsSummary != "" {
		t.Errorf("FlagsSummary = %q, want empty (no flags)", fs.FlagsSummary)
	}
}

func TestFinalizeTCPStats_NoSeqSeen(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.finalizeTCPStats()
	if fs.SeqRange != "" {
		t.Errorf("SeqRange = %q, want empty (no seq seen)", fs.SeqRange)
	}
}

func TestFinalizeTCPStats_NoWindowSeen(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.finalizeTCPStats()
	if fs.WindowRange != "" {
		t.Errorf("WindowRange = %q, want empty (no window seen)", fs.WindowRange)
	}
}

// --- F17: extractFields ---

func TestExtractFields_IPv4(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.srcIP.String() != ipA.String() || f.dstIP.String() != ipB.String() {
		t.Errorf("src/dst IP = %s/%s, want %s/%s", f.srcIP, f.dstIP, ipA, ipB)
	}
	if f.ipVersion != 4 {
		t.Errorf("ipVersion = %d, want 4", f.ipVersion)
	}
}

func TestExtractFields_IPv4NonFragmented(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 0, flagSYN, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.fragGroupID != "" {
		t.Errorf("fragGroupID = %q, want empty (non-fragmented)", f.fragGroupID)
	}
	if f.fragFirst {
		t.Error("fragFirst = true, want false")
	}
}

func TestExtractFields_IPv6(t *testing.T) {
	ip6A := net.ParseIP("2001:db8::1")
	ip6B := net.ParseIP("2001:db8::2")
	frame := buildIPv6UDPFrame(t, macA, macB, ip6A, ip6B, 12345, 53, []byte("q"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.ipVersion != 6 {
		t.Errorf("ipVersion = %d, want 6", f.ipVersion)
	}
	if f.srcIP.String() != ip6A.String() || f.dstIP.String() != ip6B.String() {
		t.Errorf("IPv6 src/dst = %s/%s", f.srcIP, f.dstIP)
	}
}

func TestExtractFields_NoNetworkLayer(t *testing.T) {
	// Pure ARP frame has no IP layer.
	frame := buildARPFrame(t, 1, macA, macB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.srcIP != nil || f.dstIP != nil {
		t.Errorf("srcIP/dstIP = %v/%v, want nil (no network layer)", f.srcIP, f.dstIP)
	}
	if f.ipVersion != 0 {
		t.Errorf("ipVersion = %d, want 0", f.ipVersion)
	}
}

func TestExtractFields_TCP(t *testing.T) {
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 42, 99, flagSYN|flagACK, []byte("hi"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.l4Proto != "tcp" {
		t.Errorf("l4Proto = %q, want tcp", f.l4Proto)
	}
	if f.srcPort != 1234 || f.dstPort != 80 {
		t.Errorf("ports = %d/%d, want 1234/80", f.srcPort, f.dstPort)
	}
	if f.tcpSeq != 42 {
		t.Errorf("tcpSeq = %d, want 42", f.tcpSeq)
	}
	if !f.tcpSYN || !f.tcpACK {
		t.Errorf("tcpSYN/ACK = %v/%v, want true/true", f.tcpSYN, f.tcpACK)
	}
	if string(f.payload) != "hi" {
		t.Errorf("payload = %q, want hi", string(f.payload))
	}
}

func TestExtractFields_TCPSYNOptionsParsed(t *testing.T) {
	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	wscale := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}
	sack := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, SYN: true, Window: 65535, Options: []layers.TCPOption{mss, wscale, sack}}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	// gopacket may auto-append EOL option (kind 0) — accept prefix match.
	if len(f.tcpOptionKinds) < 3 {
		t.Fatalf("tcpOptionKinds = %v, want >=3", f.tcpOptionKinds)
	}
	wantKinds := []uint8{2, 3, 4}
	for i, k := range wantKinds {
		if f.tcpOptionKinds[i] != k {
			t.Errorf("tcpOptionKinds[%d] = %d, want %d", i, f.tcpOptionKinds[i], k)
		}
	}
	if f.tcpMSS != 1460 {
		t.Errorf("tcpMSS = %d, want 1460", f.tcpMSS)
	}
	if f.tcpWindowScale != 7 {
		t.Errorf("tcpWindowScale = %d, want 7", f.tcpWindowScale)
	}
	if !f.tcpSACK {
		t.Error("tcpSACK = false, want true")
	}
}

func TestExtractFields_MSSInvalidLen(t *testing.T) {
	// MSS option with 1-byte data (invalid) -> tcpMSS stays 0.
	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 2, OptionData: []byte{0x05}}
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, SYN: true, Window: 65535, Options: []layers.TCPOption{mss}}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.tcpMSS != 0 {
		t.Errorf("tcpMSS = %d, want 0 (invalid 1-byte data skipped)", f.tcpMSS)
	}
}

func TestExtractFields_WindowScaleInvalidLen(t *testing.T) {
	// The packetFields.tcpWindowScale field is only set when OptionData has
	// exactly 1 byte. With 2 bytes of data, the default -1 remains.
	// Since gopacket normalizes OptionData length at serialize time, we test
	// the path by constructing the frame with mismatched OptionLength.
	// If gopacket normalizes, the value will be 7 (default); skip the test
	// rather than assert -1.
	t.Skip("F17.16: gopacket normalizes OptionData length; cannot reliably construct 2-byte WindowScale data")
}

func TestExtractFields_TCPSYNFalseNoOpts(t *testing.T) {
	// Non-SYN packet: tcpOptionKinds stays nil.
	frame := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 1, 2, flagACK, nil)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.tcpOptionKinds != nil {
		t.Errorf("tcpOptionKinds = %v, want nil (non-SYN)", f.tcpOptionKinds)
	}
}

func TestExtractFields_UDP(t *testing.T) {
	frame := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("query"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.l4Proto != "udp" {
		t.Errorf("l4Proto = %q, want udp", f.l4Proto)
	}
	if f.srcPort != 2000 || f.dstPort != 53 {
		t.Errorf("udp ports = %d/%d, want 2000/53", f.srcPort, f.dstPort)
	}
	if string(f.payload) != "query" {
		t.Errorf("udp payload = %q, want query", string(f.payload))
	}
}

func TestExtractFields_ICMPv4(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 42}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, icmp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.l4Proto != "icmp" {
		t.Errorf("l4Proto = %q, want icmp", f.l4Proto)
	}
	if f.icmpType != 8 {
		t.Errorf("icmpType = %d, want 8", f.icmpType)
	}
	if f.icmpID != 42 {
		t.Errorf("icmpID = %d, want 42", f.icmpID)
	}
}

func TestExtractFields_ARP(t *testing.T) {
	frame := buildARPFrame(t, 1, macA, macB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.l4Proto != "arp" {
		t.Errorf("l4Proto = %q, want arp", f.l4Proto)
	}
	if f.arpOp != 1 {
		t.Errorf("arpOp = %d, want 1", f.arpOp)
	}
	if f.arpSenderIP.String() != "10.0.0.1" {
		t.Errorf("arpSenderIP = %s, want 10.0.0.1", f.arpSenderIP)
	}
	if f.arpTargetIP.String() != "10.0.0.2" {
		t.Errorf("arpTargetIP = %s, want 10.0.0.2", f.arpTargetIP)
	}
}

func TestExtractFields_FirstFragPortsExtracted(t *testing.T) {
	// First fragment (offset 0, MF=1) of a TCP segment: ports parsed from
	// the IP payload's first 4 bytes (TCP src/dst ports).
	origData := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello Fragged"))
	ipPayload := origData[34:] // after Eth(14)+IP(20)
	frag1Payload := ipPayload[:24]
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: 0x1111, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: layers.IPv4MoreFragments, FragOffset: 0}
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload(frag1Payload))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.fragGroupID == "" {
		t.Fatal("fragGroupID empty, want populated")
	}
	if !f.fragFirst {
		t.Error("fragFirst = false, want true (offset 0)")
	}
	if f.srcPort != 1234 || f.dstPort != 80 {
		t.Errorf("first-frag ports = %d/%d, want 1234/80 (parsed from payload)", f.srcPort, f.dstPort)
	}
	if f.l4Proto != "tcp" {
		t.Errorf("l4Proto = %q, want tcp (recovered from IP protocol)", f.l4Proto)
	}
}

func TestExtractFields_FirstFragPortsTooShort(t *testing.T) {
	// First fragment with payload < 4 bytes: ports stay 0.
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: 0x2222, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: layers.IPv4MoreFragments, FragOffset: 0}
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload([]byte{0xAB, 0xCD}))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.srcPort != 0 || f.dstPort != 0 {
		t.Errorf("ports = %d/%d, want 0/0 (payload < 4 bytes)", f.srcPort, f.dstPort)
	}
}

func TestExtractFields_FragL4Unknown(t *testing.T) {
	// Fragmented IP with Protocol=ICMP -> l4Proto stays "" (raw key).
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: 0x3333, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4MoreFragments, FragOffset: 0}
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload([]byte("ABCDEFGH")))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	f := extractFields(pkt)
	if f.l4Proto != "" {
		t.Errorf("l4Proto = %q, want empty (ICMP fragment -> raw key)", f.l4Proto)
	}
}

// --- F18: computeFlowKey ---

func TestComputeFlowKey_TCP(t *testing.T) {
	f := packetFields{l4Proto: "tcp", srcIP: ipA, dstIP: ipB, srcPort: 1234, dstPort: 80}
	if got := computeFlowKey(f); got != "6|10.0.0.1:1234|10.0.0.2:80" {
		t.Errorf("computeFlowKey tcp = %q", got)
	}
}

func TestComputeFlowKey_UDP(t *testing.T) {
	f := packetFields{l4Proto: "udp", srcIP: ipA, dstIP: ipB, srcPort: 2000, dstPort: 53}
	if got := computeFlowKey(f); got != "17|10.0.0.1:2000|10.0.0.2:53" {
		t.Errorf("computeFlowKey udp = %q", got)
	}
}

func TestComputeFlowKey_ICMP(t *testing.T) {
	f := packetFields{l4Proto: "icmp", srcIP: ipA, dstIP: ipB, icmpType: 8, icmpID: 1}
	if got := computeFlowKey(f); got != "1|10.0.0.1|10.0.0.2|8|1" {
		t.Errorf("computeFlowKey icmp = %q", got)
	}
}

func TestComputeFlowKey_ARP(t *testing.T) {
	f := packetFields{l4Proto: "arp", arpSenderIP: ipA, arpTargetIP: ipB, arpOp: 1}
	if got := computeFlowKey(f); got != "arp|1|10.0.0.1|10.0.0.2" {
		t.Errorf("computeFlowKey arp = %q", got)
	}
}

func TestComputeFlowKey_Unknown(t *testing.T) {
	f := packetFields{l4Proto: ""}
	if got := computeFlowKey(f); got != "" {
		t.Errorf("computeFlowKey unknown = %q, want empty", got)
	}
}

// --- F19: payloadHash ---

func TestPayloadHash_Empty(t *testing.T) {
	if got := payloadHash([]byte{}); got != "" {
		t.Errorf("payloadHash(empty) = %q, want empty", got)
	}
}

func TestPayloadHash_NonEmpty(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	want := hex.EncodeToString(sum[:])
	if got := payloadHash([]byte("abc")); got != want {
		t.Errorf("payloadHash(abc) = %q, want %q", got, want)
	}
}

// --- F20: detectAnomaly ---

func TestDetectAnomaly_Truncated(t *testing.T) {
	if got := detectAnomaly(100, 60, 100); got != "truncated" {
		t.Errorf("detectAnomaly truncated = %q, want truncated", got)
	}
}

func TestDetectAnomaly_Oversize(t *testing.T) {
	if got := detectAnomaly(2000, 2000, 2000); got != "oversize" {
		t.Errorf("detectAnomaly oversize = %q, want oversize", got)
	}
}

func TestDetectAnomaly_Undersize(t *testing.T) {
	if got := detectAnomaly(40, 40, 40); got != "undersize" {
		t.Errorf("detectAnomaly undersize = %q, want undersize", got)
	}
}

func TestDetectAnomaly_Normal(t *testing.T) {
	if got := detectAnomaly(100, 100, 100); got != "" {
		t.Errorf("detectAnomaly normal = %q, want empty", got)
	}
}

// P1-11（2026-10-06 客户端复测）：合成流量每流 OutOfOrderCount=3——nextSeq
// 只加 payloadLen，SYN/FIN 各占 1 个序号未计入，干净流确定性产生 3 次假乱序：
// c2s 握手 ACK（SYN 占位）+ s2c 握手 ACK（SYN-ACK 占位）+ c2s 挥手末 ACK
//（FIN 占位）。本测试按真实报文序重放一条干净 TCP 流，必须 0 OOO / 0 retrans。
func TestRecordTCPStats_CleanFlowNoFalseOOO(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	data := make([]byte, 10)
	// 3-way handshake
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(200, flagSYN|flagACK, nil, 65535), "s2c")
	fs.recordTCPStats(tcpFields(101, flagACK, nil, 65535), "c2s")
	// data both ways
	fs.recordTCPStats(tcpFields(101, flagACK|flagPSH, data, 65535), "c2s")
	fs.recordTCPStats(tcpFields(201, flagACK|flagPSH, data, 65535), "s2c")
	// teardown: FIN both ways, then client's final ACK
	fs.recordTCPStats(tcpFields(111, flagFIN|flagACK, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(211, flagFIN|flagACK, nil, 65535), "s2c")
	fs.recordTCPStats(tcpFields(112, flagACK, nil, 65535), "c2s")
	if fs.OutOfOrderCount != 0 {
		t.Errorf("OutOfOrderCount = %d, want 0 on a perfectly ordered flow (SYN/FIN must consume seq)", fs.OutOfOrderCount)
	}
	if fs.RetransCount != 0 {
		t.Errorf("RetransCount = %d, want 0", fs.RetransCount)
	}
}

// 真 seq 空洞仍必须报 OOO——修占位记账不许把检测能力一起修没。
func TestRecordTCPStats_GenuineGapStillDetected(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.recordTCPStats(tcpFields(100, flagSYN, nil, 65535), "c2s")
	fs.recordTCPStats(tcpFields(101, flagACK|flagPSH, []byte{1, 2, 3, 4}, 65535), "c2s")
	// 跳到 150：期望位 105，空洞 → OOO。
	fs.recordTCPStats(tcpFields(150, flagACK|flagPSH, []byte{5}, 65535), "c2s")
	if fs.OutOfOrderCount != 1 {
		t.Errorf("OutOfOrderCount = %d, want 1 (genuine seq gap)", fs.OutOfOrderCount)
	}
	// 回填空洞（重传 105 起的数据）：seq < nextSeq → retrans。
	fs.recordTCPStats(tcpFields(105, flagACK|flagPSH, make([]byte, 45), 65535), "c2s")
	if fs.RetransCount != 1 {
		t.Errorf("RetransCount = %d, want 1 (overlap below nextSeq)", fs.RetransCount)
	}
}
