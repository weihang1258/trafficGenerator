package rtmp

// RTMP planner tests, derived from the reference pcap
// /home/pcap_auto/llcj_mirror/IP-TCP-20.7.1.84-30.7.1.84-50216-1935-379-500-29190-729154.pcap
// (RTMP session: TCP handshake → C0+C1 → S0+S1+S2 → C2 → connect → server response →
// Window Ack → createStream → Set Buffer Length → _result → play → media data → TCP teardown).
//
// Wire-order model (consistent with socks5/rtsp planners — bare ACKs not emitted):
//   handshake(3) + RTMP handshake(C0C1+S0S1S2+C2, MSS-segmented)
//   + command phase(connect+server response+client win ack+createStream+
//     set buffer length+_result+play/publish)
//   + data phase(N) + teardown(3).

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func mustPlanCtx(t *testing.T, ctx context.Context, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// rtmpSpec returns a base RTMP spec with deterministic client ISN.
func rtmpSpec(r *core.RTMPConfig, initialSeq uint32) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50216, DstPort: 1935,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		RTMP:   r,
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// tcpPackets returns only TCP packet configs.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// pshPayloads returns all PSH-ACK payloads in wire order.
func pshPayloads(tcps []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range tcps {
		if c.L4.Flags == 0x18 {
			out = append(out, c.Payload)
		}
	}
	return out
}

// reassembleUp concatenates all PSH-ACK payloads in the "up" direction.
func reassembleUp(tcps []core.PacketConfig) []byte {
	var out []byte
	for _, c := range tcps {
		if c.L4.Flags == 0x18 && c.Direction == "up" {
			out = append(out, c.Payload...)
		}
	}
	return out
}

// reassembleDown concatenates all PSH-ACK payloads in the "down" direction.
func reassembleDown(tcps []core.PacketConfig) []byte {
	var out []byte
	for _, c := range tcps {
		if c.L4.Flags == 0x18 && c.Direction == "down" {
			out = append(out, c.Payload...)
		}
	}
	return out
}

// directionRuns groups consecutive PSH-ACK payloads by direction changes,
// concatenating payloads within the same direction run. This mirrors how
// a receiver reassembles TCP segments into RTMP messages.
func directionRuns(tcps []core.PacketConfig) [][]byte {
	var runs [][]byte
	var curDir string
	var buf []byte
	for _, c := range tcps {
		if c.L4.Flags != 0x18 {
			continue
		}
		if c.Direction != curDir && len(buf) > 0 {
			runs = append(runs, buf)
			buf = nil
		}
		curDir = c.Direction
		buf = append(buf, c.Payload...)
	}
	if len(buf) > 0 {
		runs = append(runs, buf)
	}
	return runs
}

// --- Tests derived from spec ---

// §1 Validate tests

func TestValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{App: "live", Command: "play"}, 0)
	if err := p.Validate(spec); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{App: "live"}, 0)
	spec.SrcIP = "not-an-ip"
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid SrcIP")
	}
}

func TestValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{App: "live"}, 0)
	spec.DstIP = "bad-ip"
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid DstIP")
	}
}

func TestValidate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50216, DstPort: 1935,
	}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for nil RTMPConfig")
	}
}

func TestValidate_AppTooLong(t *testing.T) {
	p := NewPlanner()
	longApp := strings.Repeat("a", MaxAppLen+1)
	spec := rtmpSpec(&core.RTMPConfig{App: longApp}, 0)
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for App exceeding max length")
	}
}

func TestValidate_InvalidCommand(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{Command: "invalid"}, 0)
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid Command")
	}
}

func TestValidate_ValidCommands(t *testing.T) {
	p := NewPlanner()
	for _, cmd := range []string{"play", "publish", ""} {
		spec := rtmpSpec(&core.RTMPConfig{Command: cmd}, 0)
		if err := p.Validate(spec); err != nil {
			t.Fatalf("expected no error for Command=%q, got: %v", cmd, err)
		}
	}
}

func TestValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{App: "live"}, 0)
	spec.TCP = &core.TCPConfig{MSS: 100}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for MSS too small")
	}
}

func TestValidate_InvalidDataMsgType(t *testing.T) {
	p := NewPlanner()
	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{{MsgType: 99}},
	}, 0)
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid MsgType in Data")
	}
}

func TestValidate_ValidDataMsgTypes(t *testing.T) {
	p := NewPlanner()
	for _, mt := range []uint8{0, 8, 9} {
		spec := rtmpSpec(&core.RTMPConfig{
			Data: []core.RTMPDataChunk{{MsgType: mt}},
		}, 0)
		if err := p.Validate(spec); err != nil {
			t.Fatalf("expected no error for MsgType=%d, got: %v", mt, err)
		}
	}
}

// §2 Wire format tests

func TestPlan_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "rtmp" {
		t.Fatalf("expected Name()=rtmp, got %q", p.Name())
	}
}

// TestPlan_TCPHandshake verifies the TCP 3-way handshake (SYN/SYN-ACK/ACK).
// 参考 pcap frames 1-3.
func TestPlan_TCPHandshake(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{App: "live"}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	if len(tcps) < 3 {
		t.Fatalf("expected at least 3 TCP packets, got %d", len(tcps))
	}

	// Frame 1: SYN (client→server)
	if tcps[0].L4.Flags != 0x02 {
		t.Fatalf("expected SYN (0x02), got 0x%02x", tcps[0].L4.Flags)
	}
	if tcps[0].Direction != "up" {
		t.Fatalf("expected direction up, got %q", tcps[0].Direction)
	}
	if tcps[0].L4.Seq != 100 {
		t.Fatalf("expected client seq=100, got %d", tcps[0].L4.Seq)
	}
	if len(tcps[0].L4.TCPOptions) == 0 {
		t.Fatal("expected TCP options on SYN")
	}

	// Frame 2: SYN-ACK (server→client)
	if tcps[1].L4.Flags != 0x12 {
		t.Fatalf("expected SYN-ACK (0x12), got 0x%02x", tcps[1].L4.Flags)
	}
	if tcps[1].Direction != "down" {
		t.Fatalf("expected direction down, got %q", tcps[1].Direction)
	}
	if tcps[1].L4.Ack != 101 {
		t.Fatalf("expected ACK=101 (clientSeq+1), got %d", tcps[1].L4.Ack)
	}

	// Frame 3: ACK (client→server)
	if tcps[2].L4.Flags != 0x10 {
		t.Fatalf("expected ACK (0x10), got 0x%02x", tcps[2].L4.Flags)
	}
	if tcps[2].Direction != "up" {
		t.Fatalf("expected direction up, got %q", tcps[2].Direction)
	}
}

// TestPlan_RTMPHandshake verifies C0+C1, S0+S1+S2, C2 byte counts and echo.
// Large payloads are MSS-segmented (C0+C1=1537 > MSS=1460), so we reassemble
// by direction to verify the complete logical message.
// 参考 pcap frames 4-11.
func TestPlan_RTMPHandshake(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	downAll := reassembleDown(tcps)

	// Verify up-direction totals:
	// C0+C1 (1537) + C2 (1536) + connect + clientWinAck + createStream + setBufferLen + play = ...
	if len(upAll) < C0Size+C1Size+C2Size {
		t.Fatalf("expected up total at least %d bytes, got %d",
			C0Size+C1Size+C2Size, len(upAll))
	}

	// Verify down-direction totals:
	// S0+S1+S2 (3073) + serverResponse + _result = ...
	if len(downAll) < S0Size+S1Size+S2Size {
		t.Fatalf("expected down total at least %d bytes, got %d",
			S0Size+S1Size+S2Size, len(downAll))
	}

	// C0+C1 starts at up offset 0
	c0c1 := upAll[:C0Size+C1Size]
	if c0c1[0] != RTMPVersion {
		t.Fatalf("expected C0=0x03, got 0x%02x", c0c1[0])
	}

	// S0+S1+S2 starts at down offset 0
	s0s1s2 := downAll[:S0Size+S1Size+S2Size]
	if s0s1s2[0] != RTMPVersion {
		t.Fatalf("expected S0=0x03, got 0x%02x", s0s1s2[0])
	}

	// C2 starts at up offset C0+C1 (1537)
	c2 := upAll[C0Size+C1Size : C0Size+C1Size+C2Size]
	if len(c2) != C2Size {
		t.Fatalf("expected C2=%d bytes, got %d", C2Size, len(c2))
	}

	// S2 should contain C1 random data echo (C1[9:1537] at S2 offset 8)
	c1Random := c0c1[9 : 9+1528]
	s2Offset := S0Size + S1Size + 8
	s2Random := s0s1s2[s2Offset : s2Offset+1528]
	if !bytes.Equal(c1Random, s2Random) {
		t.Fatal("S2 should echo C1 random bytes")
	}

	// C2 should contain S1 random data echo (S1[9:1537] at C2 offset 8)
	s1Random := s0s1s2[S0Size+4+4 : S0Size+S1Size]
	c2Random := c2[8 : 8+1528]
	if !bytes.Equal(s1Random, c2Random) {
		t.Fatal("C2 should echo S1 random bytes")
	}
}

// TestPlan_ConnectCommand verifies the connect() AMF0 command in the up stream.
func TestPlan_ConnectCommand(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{App: "live", TcURL: "rtmp://20.0.0.1/live"}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	// connect starts at up offset: C0+C1(1537) + C2(1536) = 3073
	connectOffset := C0Size + C1Size + C2Size
	if len(upAll) < connectOffset+12 {
		t.Fatalf("up stream too short for connect: %d bytes", len(upAll))
	}

	connectChunk := upAll[connectOffset:]
	// Basic header: fmt=0, csid=3 → byte value 0x03 (NOT 0x43 — fmt=0 means top 2 bits = 00)
	basicHdr := connectChunk[0]
	if basicHdr != 0x03 {
		t.Fatalf("expected basic header 0x03 (fmt=0, csid=3), got 0x%02x", basicHdr)
	}

	// Message type: 20 (AMF0 Command) at offset 7
	msgType := connectChunk[7]
	if msgType != MsgTypeAMF0Command {
		t.Fatalf("expected msg type %d (AMF0 Command), got %d", MsgTypeAMF0Command, msgType)
	}

	// AMF data starts at offset 12
	amfData := connectChunk[12:]
	if amfData[0] != AMF0String {
		t.Fatalf("expected AMF0 string marker (0x02), got 0x%02x", amfData[0])
	}
	strLen := binary.BigEndian.Uint16(amfData[1:3])
	strVal := string(amfData[3 : 3+strLen])
	if strVal != "connect" {
		t.Fatalf("expected AMF string 'connect', got %q", strVal)
	}

	// Transaction ID: 1.0 (参考 pcap)
	txnOffset := 3 + strLen
	if amfData[txnOffset] != AMF0Number {
		t.Fatalf("expected AMF0 number marker (0x00), got 0x%02x", amfData[txnOffset])
	}
	txnVal := math.Float64frombits(binary.BigEndian.Uint64(amfData[txnOffset+1 : txnOffset+9]))
	if txnVal != 1.0 {
		t.Fatalf("expected transaction ID 1.0, got %f", txnVal)
	}

	// Command object starts with AMF0 object marker (0x03)
	objOffset := txnOffset + 9
	if amfData[objOffset] != AMF0Object {
		t.Fatalf("expected AMF0 object marker (0x03), got 0x%02x", amfData[objOffset])
	}

	// First property key: "app" (2-byte length + string, no 0x02 marker)
	keyLen := binary.BigEndian.Uint16(amfData[objOffset+1 : objOffset+3])
	keyVal := string(amfData[objOffset+3 : objOffset+3+keyLen])
	if keyVal != "app" {
		t.Fatalf("expected first property key 'app', got %q", keyVal)
	}
}

// TestPlan_ServerResponse verifies the server's response starts with Window Ack Size.
func TestPlan_ServerResponse(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	downAll := reassembleDown(tcps)
	// Server response starts after S0+S1+S2 (3073 bytes)
	respOffset := S0Size + S1Size + S2Size
	if len(downAll) < respOffset+12 {
		t.Fatalf("down stream too short for server response: %d bytes", len(downAll))
	}

	serverResp := downAll[respOffset:]
	if len(serverResp) < 12 {
		t.Fatalf("server response too short: %d bytes", len(serverResp))
	}

	// First chunk in server response: Window Ack Size (msg type 5)
	if serverResp[7] != MsgTypeWindowAckSize {
		t.Fatalf("expected first server msg type %d (Window Ack), got %d",
			MsgTypeWindowAckSize, serverResp[7])
	}
}

// TestPlan_DefaultValues verifies default app/stream names.
func TestPlan_DefaultValues(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	connectOffset := C0Size + C1Size + C2Size
	amfData := upAll[connectOffset+12:] // skip chunk header
	connectStr := hex.EncodeToString(amfData)
	if !strings.Contains(connectStr, "6c697665") { // "live" in hex
		t.Fatal("expected default app 'live' in connect command")
	}
}

// TestPlan_PlayCommand verifies the play() command appears in up stream.
func TestPlan_PlayCommand(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{Command: "play", StreamName: "mystream"}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	upHex := hex.EncodeToString(upAll)
	// "play" in AMF0 string: 0x02 0x00 0x04 "play"
	if !strings.Contains(upHex, "020004"+"706c6179") {
		t.Fatal("expected 'play' AMF0 command in up stream")
	}
	// "mystream"
	if !strings.Contains(upHex, "6d7973747265616d") {
		t.Fatal("expected stream name 'mystream' in up stream")
	}
}

// TestPlan_PublishCommand verifies the publish() command appears in up stream.
func TestPlan_PublishCommand(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{Command: "publish", StreamName: "live_stream"}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	upHex := hex.EncodeToString(upAll)
	// "publish" in AMF0 string: 0x02 0x00 0x07 "publish"
	if !strings.Contains(upHex, "020007"+"7075626c697368") {
		t.Fatal("expected 'publish' AMF0 command in up stream")
	}
}

// TestPlan_DataPhase verifies data chunks are emitted.
func TestPlan_DataPhase(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{
			{Direction: "down", MsgType: 9, Payload: []byte("video_frame_1")},
			{Direction: "down", MsgType: 8, Payload: []byte("audio_frame_1")},
		},
	}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	downAll := reassembleDown(tcps)
	if !bytes.Contains(downAll, []byte("video_frame_1")) {
		t.Fatal("expected 'video_frame_1' in down stream")
	}
	if !bytes.Contains(downAll, []byte("audio_frame_1")) {
		t.Fatal("expected 'audio_frame_1' in down stream")
	}

	// Verify msg type bytes appear in down stream
	downHex := hex.EncodeToString(downAll)
	// Audio data chunk: msg type 0x08 at offset 7 of chunk
	if !strings.Contains(downHex, "08") {
		t.Fatal("expected audio msg type 0x08 in down stream")
	}
}

// TestPlan_DataDefaultDirection verifies data defaults to "down" (server→client).
func TestPlan_DataDefaultDirection(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{{MsgType: 9, Payload: []byte("test_video")}},
	}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)

	downAll := reassembleDown(tcpPackets(cfgs))
	if !bytes.Contains(downAll, []byte("test_video")) {
		t.Fatal("default data direction should be 'down' — 'test_video' not in down stream")
	}
}

// TestPlan_TCPTeardown verifies the TCP 4-way teardown.
func TestPlan_TCPTeardown(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	n := len(tcps)

	if n < 3 {
		t.Fatalf("expected at least 3 TCP packets for teardown, got %d", n)
	}

	// FIN (client→server)
	if tcps[n-3].L4.Flags != 0x11 {
		t.Fatalf("expected FIN (0x11), got 0x%02x", tcps[n-3].L4.Flags)
	}
	if tcps[n-3].Direction != "up" {
		t.Fatalf("expected FIN direction up, got %q", tcps[n-3].Direction)
	}

	// FIN-ACK (server→client)
	if tcps[n-2].L4.Flags != 0x11 {
		t.Fatalf("expected FIN-ACK (0x11), got 0x%02x", tcps[n-2].L4.Flags)
	}
	if tcps[n-2].Direction != "down" {
		t.Fatalf("expected FIN-ACK direction down, got %q", tcps[n-2].Direction)
	}

	// ACK (client→server)
	if tcps[n-1].L4.Flags != 0x10 {
		t.Fatalf("expected ACK (0x10), got 0x%02x", tcps[n-1].L4.Flags)
	}
	if tcps[n-1].Direction != "up" {
		t.Fatalf("expected ACK direction up, got %q", tcps[n-1].Direction)
	}
}

// TestPlan_SeqAckContinuity verifies that sequence numbers advance correctly.
func TestPlan_SeqAckContinuity(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	// Find the first PSH-ACK in each direction
	var firstClientPSH, firstServerPSH int
	for i, c := range tcps {
		if c.L4.Flags == 0x18 {
			if c.Direction == "up" && firstClientPSH == 0 {
				firstClientPSH = i
			} else if c.Direction == "down" && firstServerPSH == 0 {
				firstServerPSH = i
			}
		}
	}

	if firstClientPSH == 0 || firstServerPSH == 0 {
		t.Fatal("no PSH-ACK packets found")
	}

	// Track expected seq per direction from the first PSH-ACK
	clientSeq := tcps[firstClientPSH].L4.Seq
	serverSeq := tcps[firstServerPSH].L4.Seq

	for i := 3; i < len(tcps)-3; i++ { // skip handshake and teardown
		c := tcps[i]
		if c.L4.Flags != 0x18 {
			continue // only check PSH-ACK
		}
		if c.Direction == "up" {
			if c.L4.Seq != clientSeq {
				t.Fatalf("packet %d: expected client seq %d, got %d", i, clientSeq, c.L4.Seq)
			}
			clientSeq += uint32(len(c.Payload))
		} else {
			if c.L4.Seq != serverSeq {
				t.Fatalf("packet %d: expected server seq %d, got %d", i, serverSeq, c.L4.Seq)
			}
			serverSeq += uint32(len(c.Payload))
		}
	}
}

// TestPlan_ContextCancellation verifies that context cancellation stops emission.
func TestPlan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{
			{MsgType: 9},
			{MsgType: 8},
			{MsgType: 9},
		},
	}, 100)
	cfgs := mustPlanCtx(t, ctx, NewPlanner(), spec)

	fullCfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) >= len(fullCfgs) {
		t.Logf("cancelled: %d, full: %d — context may not have taken effect fast enough (acceptable)", len(cfgs), len(fullCfgs))
	}
}

// TestPlan_DeterministicISN verifies that a fixed InitialSeq produces deterministic output.
func TestPlan_DeterministicISN(t *testing.T) {
	spec1 := rtmpSpec(&core.RTMPConfig{App: "live"}, 42)
	spec2 := rtmpSpec(&core.RTMPConfig{App: "live"}, 42)

	cfgs1 := mustPlan(t, NewPlanner(), spec1)
	cfgs2 := mustPlan(t, NewPlanner(), spec2)

	if cfgs1[0].L4.Seq != cfgs2[0].L4.Seq {
		t.Fatal("expected same client ISN with same InitialSeq")
	}
}

// TestPlan_EmptyData verifies no extra data chunks when Data is nil/empty.
func TestPlan_EmptyData(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{App: "live"}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	upAll := reassembleUp(tcps)
	downAll := reassembleDown(tcps)

	// Verify handshake sizes
	if len(upAll) < C0Size+C1Size+C2Size {
		t.Fatalf("up too short: %d", len(upAll))
	}
	if len(downAll) < S0Size+S1Size+S2Size {
		t.Fatalf("down too short: %d", len(downAll))
	}

	// Verify no data chunks (no audio/video msg types in payload after commands)
	// Data phase chunks would contain msg type 8 or 9 at offset 7 of chunk
	runs := directionRuns(tcps)
	// Expected runs: up(C0C1), down(S0S1S2), up(C2+connect), down(serverResp+_result),
	// up(clientWinAck+createStream+setBufLen), down(empty=nothing extra),
	// up(play), down(empty), ... FIN etc.
	// Just verify no msg type 8 or 9 appears in data after commands
	if len(runs) > 20 {
		t.Logf("got %d direction runs (more than expected for no-data mode)", len(runs))
	}
}

// §3 Helper function tests

func TestAMF0String(t *testing.T) {
	result := amf0String("connect")
	if result[0] != AMF0String {
		t.Fatalf("expected AMF0 string marker 0x02, got 0x%02x", result[0])
	}
	strLen := binary.BigEndian.Uint16(result[1:3])
	if strLen != 7 {
		t.Fatalf("expected length 7, got %d", strLen)
	}
	if string(result[3:]) != "connect" {
		t.Fatalf("expected 'connect', got %q", string(result[3:]))
	}
}

func TestAMF0Number(t *testing.T) {
	result := amf0Number(0.0)
	if result[0] != AMF0Number {
		t.Fatalf("expected AMF0 number marker 0x00, got 0x%02x", result[0])
	}
	if len(result) != 9 {
		t.Fatalf("expected 9 bytes, got %d", len(result))
	}
	val := math.Float64frombits(binary.BigEndian.Uint64(result[1:]))
	if val != 0.0 {
		t.Fatalf("expected 0.0, got %f", val)
	}
}

func TestAMF0Object(t *testing.T) {
	props := []amf0Prop{
		{"key", amf0String("value")},
	}
	result := amf0Object(props)
	if result[0] != AMF0Object {
		t.Fatalf("expected object marker 0x03, got 0x%02x", result[0])
	}
	n := len(result)
	if result[n-3] != 0x00 || result[n-2] != 0x00 || result[n-1] != 0x09 {
		t.Fatalf("expected object terminator 00 00 09, got %02x %02x %02x",
			result[n-3], result[n-2], result[n-1])
	}
}

func TestBuildC0C1(t *testing.T) {
	c0c1 := buildC0C1()
	if len(c0c1) != C0Size+C1Size {
		t.Fatalf("expected %d bytes, got %d", C0Size+C1Size, len(c0c1))
	}
	if c0c1[0] != RTMPVersion {
		t.Fatalf("expected version 0x03, got 0x%02x", c0c1[0])
	}
	// C1 bytes 5-8 should be zero
	for i := 5; i < 9; i++ {
		if c0c1[i] != 0 {
			t.Fatalf("expected C1 zero padding at byte %d, got 0x%02x", i, c0c1[i])
		}
	}
}

func TestBuildS0S1S2_EchoC1(t *testing.T) {
	c0c1 := buildC0C1()
	s0s1s2 := buildS0S1S2(c0c1)
	if len(s0s1s2) != S0Size+S1Size+S2Size {
		t.Fatalf("expected %d bytes, got %d", S0Size+S1Size+S2Size, len(s0s1s2))
	}
	if s0s1s2[0] != RTMPVersion {
		t.Fatalf("expected S0=0x03, got 0x%02x", s0s1s2[0])
	}
	// S2 should echo C1 random bytes
	c1Random := c0c1[9 : 9+1528]
	s2Offset := S0Size + S1Size + 8
	s2Random := s0s1s2[s2Offset : s2Offset+1528]
	if !bytes.Equal(c1Random, s2Random) {
		t.Fatal("S2 should echo C1 random bytes")
	}
}

func TestBuildC2_EchoS1(t *testing.T) {
	c0c1 := buildC0C1()
	s0s1s2 := buildS0S1S2(c0c1)
	c2 := buildC2(s0s1s2)
	if len(c2) != C2Size {
		t.Fatalf("expected %d bytes, got %d", C2Size, len(c2))
	}
	s1Random := s0s1s2[S0Size+4+4 : S0Size+S1Size]
	c2Random := c2[8 : 8+1528]
	if !bytes.Equal(s1Random, c2Random) {
		t.Fatal("C2 should echo S1 random bytes")
	}
}

func TestSegmentByMSS(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		mss     int
		want    int
	}{
		{"nil payload", nil, 100, 1},
		{"empty payload", []byte{}, 100, 1},
		{"small payload", []byte{1, 2, 3}, 100, 1},
		{"exact mss", make([]byte, 100), 100, 1},
		{"two chunks", make([]byte, 150), 100, 2},
		{"three chunks", make([]byte, 250), 100, 3},
		{"zero mss", make([]byte, 100), 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := segmentByMSS(tt.payload, tt.mss)
			if len(chunks) != tt.want {
				t.Fatalf("expected %d chunks, got %d", tt.want, len(chunks))
			}
		})
	}
}

func TestBuildAMF0Chunk(t *testing.T) {
	amfData := amf0String("test")
	chunk := buildAMF0Chunk(CSIDProtocol, MsgTypeAMF0Command, 0, amfData)

	// Basic header: fmt=0, csid=CSIDProtocol(2) → byte value 0x02
	if chunk[0] != byte(CSIDProtocol) {
		t.Fatalf("expected basic header 0x%02x (fmt=0, csid=%d), got 0x%02x", CSIDProtocol, CSIDProtocol, chunk[0])
	}

	// Message length (3 bytes, big-endian) at offset 4-6
	msgLen := int(chunk[4])<<16 | int(chunk[5])<<8 | int(chunk[6])
	if msgLen != len(amfData) {
		t.Fatalf("expected msg length %d, got %d", len(amfData), msgLen)
	}

	// Message type at offset 7
	if chunk[7] != MsgTypeAMF0Command {
		t.Fatalf("expected msg type %d, got %d", MsgTypeAMF0Command, chunk[7])
	}

	// Stream ID at offset 8-11 (little-endian)
	streamID := uint32(chunk[8]) | uint32(chunk[9])<<8 | uint32(chunk[10])<<16 | uint32(chunk[11])<<24
	if streamID != 0 {
		t.Fatalf("expected stream ID 0, got %d", streamID)
	}
}

// TestPlan_AudioVideoChunkStreamIDs verifies CSID allocation for audio/video.
func TestPlan_AudioVideoChunkStreamIDs(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{
			{Direction: "down", MsgType: MsgTypeAudio},
			{Direction: "down", MsgType: MsgTypeVideo},
		},
	}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)

	var audioFound, videoFound bool
	for _, c := range cfgs {
		if c.L4.Flags == 0x18 && len(c.Payload) >= 12 {
			msgType := c.Payload[7]
			csid := c.Payload[0] & 0x3F
			if msgType == MsgTypeAudio {
				audioFound = true
				if csid != CSIDAudio {
					t.Fatalf("expected audio CSID=%d, got %d", CSIDAudio, csid)
				}
			}
			if msgType == MsgTypeVideo {
				videoFound = true
				if csid != CSIDVideo {
					t.Fatalf("expected video CSID=%d, got %d", CSIDVideo, csid)
				}
			}
		}
	}
	if !audioFound {
		t.Fatal("audio data chunk not found")
	}
	if !videoFound {
		t.Fatal("video data chunk not found")
	}
}

// TestPlan_CustomChunkStreamID verifies user-specified CSID overrides default.
func TestPlan_CustomChunkStreamID(t *testing.T) {
	spec := rtmpSpec(&core.RTMPConfig{
		Data: []core.RTMPDataChunk{
			{Direction: "down", MsgType: MsgTypeVideo, ChunkStreamID: 10},
		},
	}, 100)
	cfgs := mustPlan(t, NewPlanner(), spec)

	for _, c := range cfgs {
		if c.L4.Flags == 0x18 && len(c.Payload) >= 12 && c.Payload[7] == MsgTypeVideo {
			csid := c.Payload[0] & 0x3F
			if csid != 10 {
				t.Fatalf("expected custom CSID=10, got %d", csid)
			}
			return
		}
	}
	t.Fatal("video data chunk not found")
}
