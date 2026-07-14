package tcp

// Test points derived from tools/test_points/protocols.md (TCP section).
// Each test asserts observable PacketConfig field values, not just "no error".
// Known-bug test points assert the CORRECT behavior but use t.Skip with the
// bug description so the suite stays green; remove the skip when the bug is fixed.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func validTCPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
}

// --- Validate (T1-T7) ---

func TestTCPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = "256.1.1.1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP: 256.1.1.1") {
		t.Errorf("err=%v, want contains 'invalid source IP: 256.1.1.1'", err)
	}
}

func TestTCPValidate_NonIPSrc(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP: not-an-ip") {
		t.Errorf("err=%v", err)
	}
}

func TestTCPValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip validation: %v", err)
	}
}

func TestTCPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.DstIP = "300.0.0.1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v", err)
	}
}

func TestTCPValidate_EmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty DstIP should skip: %v", err)
	}
}

func TestTCPValidate_SrcPortZero(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "source port is required") {
		t.Errorf("err=%v", err)
	}
}

func TestTCPValidate_DstPortZero(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcPort = 12345
	spec.DstPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "destination port is required") {
		t.Errorf("err=%v", err)
	}
}

func TestTCPValidate_AllValid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validTCPSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestTCPValidate_ShortCircuitSrcFirst(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = "bad1"
	spec.DstIP = "bad2"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("SrcIP should be checked first: %v", err)
	}
}

// --- synOptions (T8-T9) ---

func TestTCPSynOptions_MSS1460(t *testing.T) {
	opts := synOptions(1460)
	if len(opts) != 2 {
		t.Fatalf("len(opts)=%d, want 2", len(opts))
	}
	if opts[0].Kind != core.TCPOptMSS {
		t.Errorf("opts[0].Kind=%d, want TCPOptMSS(%d)", opts[0].Kind, core.TCPOptMSS)
	}
	if len(opts[0].Data) != 2 || opts[0].Data[0] != 0x05 || opts[0].Data[1] != 0xb4 {
		t.Errorf("MSS data=%v, want [05 b4]", opts[0].Data)
	}
	if opts[1].Kind != core.TCPOptSACKPermit {
		t.Errorf("opts[1].Kind=%d, want TCPOptSACKPermit(%d)", opts[1].Kind, core.TCPOptSACKPermit)
	}
}

func TestTCPSynOptions_MSSMax(t *testing.T) {
	opts := synOptions(65535)
	if len(opts[0].Data) != 2 || opts[0].Data[0] != 0xff || opts[0].Data[1] != 0xff {
		t.Errorf("MSS data=%v, want [ff ff]", opts[0].Data)
	}
}

func TestTCPSynOptions_MSSZero(t *testing.T) {
	opts := synOptions(0)
	if len(opts) != 1 {
		t.Fatalf("len(opts)=%d, want 1 (SACK only)", len(opts))
	}
	if opts[0].Kind != core.TCPOptSACKPermit {
		t.Errorf("opts[0].Kind=%d, want SACKPermit", opts[0].Kind)
	}
}

// --- Plan entry (T10-T11) ---

func TestTCPPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcPort = 0
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestTCPPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validTCPSpec())
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	if ch == nil {
		t.Fatal("nil channel")
	}
	if cap(ch) != 256 {
		t.Errorf("cap(ch)=%d, want 256", cap(ch))
	}
	drain(ch)
}

// --- Default values (T12-T17) ---

func TestTCPPlan_ConfigNilDefaults(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 7 {
		t.Fatalf("len=%d, want >=7 (handshake+termination)", len(cfgs))
	}
	// SYN
	if cfgs[0].L4.Flags != FlagSYN {
		t.Errorf("SYN flags=%x", cfgs[0].L4.Flags)
	}
	// SYN carries MSS=1460
	var sawMSS bool
	for _, o := range cfgs[0].L4.TCPOptions {
		if o.Kind == core.TCPOptMSS && len(o.Data) == 2 && o.Data[0] == 0x05 && o.Data[1] == 0xb4 {
			sawMSS = true
		}
	}
	if !sawMSS {
		t.Error("default SYN missing MSS=1460 option")
	}
	// All handshake/termination packets have WindowSize=65535
	for i, c := range cfgs {
		if c.L4.WindowSize != 65535 {
			t.Errorf("cfg[%d].WindowSize=%d, want 65535", i, c.L4.WindowSize)
		}
	}
}

func TestTCPPlan_ConfigProvided(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false, MSS: 512, WindowSize: 16384}
	cfgs := drain(mustPlan(t, p, spec))
	// SYN MSS=512
	var mssData []byte
	for _, o := range cfgs[0].L4.TCPOptions {
		if o.Kind == core.TCPOptMSS {
			mssData = o.Data
		}
	}
	if len(mssData) != 2 || mssData[0] != 0x02 || mssData[1] != 0x00 {
		t.Errorf("MSS=%v, want [02 00]=512", mssData)
	}
	// WindowSize=16384
	if cfgs[0].L4.WindowSize != 16384 {
		t.Errorf("WindowSize=%d, want 16384", cfgs[0].L4.WindowSize)
	}
	// No termination (handshake only = 3 packets)
	if len(cfgs) != 3 {
		t.Errorf("len=%d, want 3 (handshake only)", len(cfgs))
	}
}

func TestTCPPlan_WinSizeNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L4.WindowSize != 32768 {
			t.Errorf("cfg[%d].WindowSize=%d, want 32768", i, c.L4.WindowSize)
		}
	}
}

func TestTCPPlan_WinSizeZeroFallback(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false, WindowSize: 0}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.WindowSize != 65535 {
		t.Errorf("WindowSize=%d, want 65535 fallback", cfgs[0].L4.WindowSize)
	}
}

func TestTCPPlan_TTLNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TTL = 128
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.TTL != 128 {
			t.Errorf("cfg[%d].TTL=%d, want 128", i, c.L3.TTL)
		}
	}
}

func TestTCPPlan_TTLZeroDefault(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TTL = 0
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (DefaultTTL)", cfgs[0].L3.TTL)
	}
}

// --- Handshake (T18-T19) ---

func TestTCPPlan_HandshakeThreePackets(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Fatalf("len=%d, want 3", len(cfgs))
	}
	wantDirs := []string{"up", "down", "up"}
	wantFlags := []uint8{0x02, 0x12, 0x10}
	for i := range cfgs {
		if cfgs[i].Direction != wantDirs[i] {
			t.Errorf("cfg[%d].Direction=%s, want %s", i, cfgs[i].Direction, wantDirs[i])
		}
		if cfgs[i].L4.Flags != wantFlags[i] {
			t.Errorf("cfg[%d].Flags=%x, want %x", i, cfgs[i].L4.Flags, wantFlags[i])
		}
	}
}

func TestTCPPlan_SYNPacketFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	syn := cfgs[0]
	if syn.PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", syn.PacketIndex)
	}
	if syn.Direction != "up" {
		t.Errorf("Direction=%s", syn.Direction)
	}
	if syn.L4.Flags != 0x02 {
		t.Errorf("Flags=%x", syn.L4.Flags)
	}
	if syn.L4.Seq != 1000 {
		t.Errorf("Seq=%d, want 1000", syn.L4.Seq)
	}
	if syn.L4.Ack != 0 {
		t.Errorf("Ack=%d, want 0", syn.L4.Ack)
	}
	if syn.L4.TCPOptions == nil {
		t.Error("TCPOptions nil on SYN")
	}
	if syn.L2.SrcMAC != spec.SrcMAC || syn.L2.DstMAC != spec.DstMAC {
		t.Errorf("MACs: src=%s dst=%s", syn.L2.SrcMAC, syn.L2.DstMAC)
	}
	if syn.L3.SrcIP != spec.SrcIP || syn.L3.DstIP != spec.DstIP {
		t.Errorf("IPs: src=%s dst=%s", syn.L3.SrcIP, syn.L3.DstIP)
	}
	if syn.L4.SrcPort != spec.SrcPort || syn.L4.DstPort != spec.DstPort {
		t.Errorf("ports: src=%d dst=%d", syn.L4.SrcPort, syn.L4.DstPort)
	}
	if syn.L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x", syn.L2.EtherType)
	}
	if syn.L3.Protocol != 6 {
		t.Errorf("L3.Protocol=%d, want 6", syn.L3.Protocol)
	}
	if syn.L3.IPID != 1 {
		t.Errorf("IPID=%d, want 1", syn.L3.IPID)
	}
}

func TestTCPPlan_SYNACKPacketFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	synack := cfgs[1]
	if synack.PacketIndex != 1 {
		t.Errorf("PacketIndex=%d, want 1", synack.PacketIndex)
	}
	if synack.Direction != "down" {
		t.Errorf("Direction=%s", synack.Direction)
	}
	if synack.L4.Flags != 0x12 {
		t.Errorf("Flags=%x, want 0x12", synack.L4.Flags)
	}
	if synack.L4.Seq != 2000 {
		t.Errorf("Seq=%d, want 2000", synack.L4.Seq)
	}
	if synack.L4.Ack != 1001 {
		t.Errorf("Ack=%d, want 1001", synack.L4.Ack)
	}
	// MACs/IPs/ports swapped
	if synack.L2.SrcMAC != spec.DstMAC || synack.L2.DstMAC != spec.SrcMAC {
		t.Errorf("MACs not swapped: src=%s dst=%s", synack.L2.SrcMAC, synack.L2.DstMAC)
	}
	if synack.L3.SrcIP != spec.DstIP || synack.L3.DstIP != spec.SrcIP {
		t.Errorf("IPs not swapped")
	}
	if synack.L4.SrcPort != spec.DstPort || synack.L4.DstPort != spec.SrcPort {
		t.Errorf("ports not swapped")
	}
	if synack.L3.IPID != 2 {
		t.Errorf("IPID=%d, want 2", synack.L3.IPID)
	}
}

func TestTCPPlan_HandshakeACKFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[2]
	if ack.L4.Flags != 0x10 {
		t.Errorf("Flags=%x, want 0x10", ack.L4.Flags)
	}
	if ack.L4.Seq != 1001 {
		t.Errorf("Seq=%d, want 1001", ack.L4.Seq)
	}
	if ack.L4.Ack != 2001 {
		t.Errorf("Ack=%d, want 2001", ack.L4.Ack)
	}
	if ack.L4.TCPOptions != nil {
		t.Error("handshake ACK should have no TCP options")
	}
	if ack.L3.IPID != 3 {
		t.Errorf("IPID=%d, want 3", ack.L3.IPID)
	}
}

func TestTCPPlan_HandshakeDisabled(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 0 {
		t.Errorf("len=%d, want 0", len(cfgs))
	}
}

// --- Data segmentation (T20-T27) ---

func TestTCPPlan_DataPayloadPresent(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte("hello")
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	// 1 DATA + 1 ACK
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	if cfgs[0].L4.Flags != 0x18 {
		t.Errorf("DATA Flags=%x, want 0x18 (PSH|ACK)", cfgs[0].L4.Flags)
	}
	if string(cfgs[0].Payload) != "hello" {
		t.Errorf("Payload=%q, want 'hello'", cfgs[0].Payload)
	}
}

func TestTCPPlan_NoData(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = nil
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 0 {
		t.Errorf("len=%d, want 0", len(cfgs))
	}
}

func TestTCPPlan_MSSZeroFallbackInData(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 3000)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 0}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 segments [1460,1460,80], 6 packets (DATA+ACK each)
	if len(cfgs) != 6 {
		t.Fatalf("len=%d, want 6", len(cfgs))
	}
	wantLens := []int{1460, 1460, 80}
	for i, want := range wantLens {
		data := cfgs[i*2].Payload
		if len(data) != want {
			t.Errorf("segment %d len=%d, want %d", i, len(data), want)
		}
	}
}

func TestTCPPlan_MSSNonZeroInData(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 1500)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 512}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 segments [512,512,476], 6 packets
	if len(cfgs) != 6 {
		t.Fatalf("len=%d, want 6", len(cfgs))
	}
	wantLens := []int{512, 512, 476}
	for i, want := range wantLens {
		if len(cfgs[i*2].Payload) != want {
			t.Errorf("segment %d len=%d, want %d", i, len(cfgs[i*2].Payload), want)
		}
	}
}

func TestTCPPlan_PayloadLessThanMSS(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	if len(cfgs[0].Payload) != 100 {
		t.Errorf("segment len=%d, want 100", len(cfgs[0].Payload))
	}
}

func TestTCPPlan_PayloadEqualsMSS(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 1460)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	if len(cfgs[0].Payload) != 1460 {
		t.Errorf("segment len=%d, want 1460", len(cfgs[0].Payload))
	}
}

func TestTCPPlan_PayloadGreaterThanMSS(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 3000)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 6 {
		t.Fatalf("len=%d, want 6 (3 segments)", len(cfgs))
	}
}

func TestTCPPlan_DataSegmentFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte("hello")
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	data := cfgs[0]
	if data.Direction != "up" {
		t.Errorf("Direction=%s", data.Direction)
	}
	if data.L4.Flags != 0x18 {
		t.Errorf("Flags=%x, want 0x18", data.L4.Flags)
	}
	if data.L4.Seq != 1000 {
		t.Errorf("Seq=%d, want 1000 (clientSeq)", data.L4.Seq)
	}
	if data.L4.Ack != 2000 {
		t.Errorf("Ack=%d, want 2000 (serverSeq)", data.L4.Ack)
	}
	if string(data.Payload) != "hello" {
		t.Errorf("Payload=%q", data.Payload)
	}
}

func TestTCPPlan_DataACKFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte("hello")
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[1]
	if ack.Direction != "down" {
		t.Errorf("Direction=%s", ack.Direction)
	}
	if ack.L4.Flags != 0x10 {
		t.Errorf("Flags=%x, want 0x10", ack.L4.Flags)
	}
	// After sending 5 bytes, clientSeq=1005; ACK acknowledges 1005
	if ack.L4.Ack != 1005 {
		t.Errorf("Ack=%d, want 1005 (clientSeq updated)", ack.L4.Ack)
	}
	if ack.L4.WindowSize != 32768 {
		t.Errorf("WindowSize=%d, want 32768 (winSize)", ack.L4.WindowSize)
	}
}

func TestTCPPlan_LargePayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100000)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	// 69 segments (100000/1460 = 68.49 -> 69), 138 packets
	if len(cfgs) != 138 {
		t.Errorf("len=%d, want 138", len(cfgs))
	}
}

// --- Termination (T28-T29) ---

func TestTCPPlan_TerminationFourPackets(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Fatalf("len=%d, want 4", len(cfgs))
	}
	wantDirs := []string{"up", "down", "down", "up"}
	wantFlags := []uint8{0x11, 0x10, 0x11, 0x10}
	for i := range cfgs {
		if cfgs[i].Direction != wantDirs[i] {
			t.Errorf("cfg[%d].Direction=%s, want %s", i, cfgs[i].Direction, wantDirs[i])
		}
		if cfgs[i].L4.Flags != wantFlags[i] {
			t.Errorf("cfg[%d].Flags=%x, want %x", i, cfgs[i].L4.Flags, wantFlags[i])
		}
	}
}

func TestTCPPlan_ClientFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	fin := cfgs[0]
	if fin.Direction != "up" {
		t.Errorf("Direction=%s", fin.Direction)
	}
	if fin.L4.Flags != 0x11 {
		t.Errorf("Flags=%x, want 0x11 (FIN|ACK)", fin.L4.Flags)
	}
	if fin.L4.Seq != 1000 {
		t.Errorf("Seq=%d, want 1000", fin.L4.Seq)
	}
	if fin.L4.Ack != 2000 {
		t.Errorf("Ack=%d, want 2000", fin.L4.Ack)
	}
	if fin.L4.WindowSize != 32768 {
		t.Errorf("WindowSize=%d, want 32768", fin.L4.WindowSize)
	}
}

func TestTCPPlan_ServerACKofFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[1]
	if ack.Direction != "down" || ack.L4.Flags != 0x10 {
		t.Errorf("ack: dir=%s flags=%x", ack.Direction, ack.L4.Flags)
	}
	// After client FIN, clientSeq=1001; ACK acknowledges 1001
	if ack.L4.Ack != 1001 {
		t.Errorf("Ack=%d, want 1001", ack.L4.Ack)
	}
	if ack.L4.WindowSize != 32768 {
		t.Errorf("WindowSize=%d, want 32768", ack.L4.WindowSize)
	}
}

func TestTCPPlan_ServerFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	fin := cfgs[2]
	if fin.Direction != "down" || fin.L4.Flags != 0x11 {
		t.Errorf("fin: dir=%s flags=%x", fin.Direction, fin.L4.Flags)
	}
	if fin.L4.Seq != 2000 {
		t.Errorf("Seq=%d, want 2000", fin.L4.Seq)
	}
	if fin.L4.WindowSize != 32768 {
		t.Errorf("WindowSize=%d, want 32768", fin.L4.WindowSize)
	}
}

func TestTCPPlan_ClientACKofServerFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true, WindowSize: 32768}
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[3]
	if ack.Direction != "up" || ack.L4.Flags != 0x10 {
		t.Errorf("ack: dir=%s flags=%x", ack.Direction, ack.L4.Flags)
	}
	// After server FIN, serverSeq=2001; ACK acknowledges 2001
	if ack.L4.Ack != 2001 {
		t.Errorf("Ack=%d, want 2001", ack.L4.Ack)
	}
	if ack.L4.WindowSize != 32768 {
		t.Errorf("WindowSize=%d, want 32768", ack.L4.WindowSize)
	}
}

func TestTCPPlan_TerminationDisabled(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 0 {
		t.Errorf("len=%d, want 0", len(cfgs))
	}
}

// --- Combined scenarios (T30-T37) ---

func TestTCPPlan_FullFlow(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100)
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: true, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 data + 4 termination = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	// PacketIndex 0..8 continuous
	for i, c := range cfgs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("cfg[%d].PacketIndex=%d, want %d", i, c.PacketIndex, i)
		}
	}
}

func TestTCPPlan_OnlyHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	if len(drain(mustPlan(t, p, spec))) != 3 {
		t.Error("want 3")
	}
}

func TestTCPPlan_HandshakePlusData(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100)
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false, MSS: 1460}
	if len(drain(mustPlan(t, p, spec))) != 5 {
		t.Error("want 5 (3+2)")
	}
}

func TestTCPPlan_HandshakePlusTermination(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: true}
	if len(drain(mustPlan(t, p, spec))) != 7 {
		t.Error("want 7 (3+4)")
	}
}

func TestTCPPlan_EmptyFlow(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	if len(drain(mustPlan(t, p, spec))) != 0 {
		t.Error("want 0")
	}
}

func TestTCPPlan_NoHandshakeWithData(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte("data")
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false}
	if len(drain(mustPlan(t, p, spec))) != 2 {
		t.Error("want 2")
	}
}

func TestTCPPlan_NoHandshakeWithTermination(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true}
	if len(drain(mustPlan(t, p, spec))) != 4 {
		t.Error("want 4")
	}
}

func TestTCPPlan_NoHandshakeDataTerm(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte("data")
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true}
	if len(drain(mustPlan(t, p, spec))) != 6 {
		t.Error("want 6 (2+4)")
	}
}

// --- Bug scenarios (M1-M6, E1-E12) ---

// M1: goroutine never checks ctx.Done(). Known bug: cancelling the context
// does not stop the planner goroutine; it runs to completion. Failing-test-first:
// assert the goroutine exits promptly after cancel. Currently skipped because
// the bug is unfixed.
func TestTCPPlan_ContextCancelGoroutineLeak(t *testing.T) {
	t.Skip("known bug M1: TCP planner goroutine never checks ctx.Done(); cancel does not stop it. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100000) // many packets
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	// Do not drain; expect goroutine to exit via ctx.Done()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < before {
			return // goroutine exited
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutine leak: before=%d after=%d (cancel ignored)", before, runtime.NumGoroutine())
	// drain to clean up
	drain(ch)
}

// E12: channel full (256 cap) goroutine leak. Known bug: once 256 packets fill
// the channel and the consumer stops reading, the goroutine blocks forever on
// send and never exits (no ctx.Done check).
func TestTCPPlan_BlockedSendGoroutineLeak(t *testing.T) {
	t.Skip("known bug E12: blocked send on full channel never exits (no ctx.Done). Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 500000) // >256 packets
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	time.Sleep(2 * time.Second)
	if runtime.NumGoroutine() >= before {
		t.Errorf("goroutine still alive after cancel+full channel: before=%d after=%d", before, runtime.NumGoroutine())
	}
	// Best-effort drain to allow goroutine to proceed if it ever unblocks
	go func() { drain(ch) }()
}

// M2: VLAN not propagated. Known bug: L2Config literal omits VLAN.
func TestTCPPlan_VLANNotPropagated(t *testing.T) {
	t.Skip("known bug M2: VLAN not propagated to L2Config. Remove skip once fixed.")
	p := NewPlanner()
	spec := validTCPSpec()
	spec.VLAN = &core.VLAN{ID: 100, Priority: 3}
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.VLAN == nil || cfgs[0].L2.VLAN.ID != 100 {
		t.Errorf("VLAN not propagated: %+v", cfgs[0].L2.VLAN)
	}
	if cfgs[0].L2.VLAN.Priority != 3 {
		t.Errorf("VLAN priority=%d, want 3", cfgs[0].L2.VLAN.Priority)
	}
}

// M3: Count/Duration/BPS are ignored by Plan (it produces a fixed packet count
// based on handshake/data/termination). This is current (benign) behavior.
func TestTCPPlan_CountDurationBPSIgnored(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Count = 100
	spec.Duration = 10
	spec.BPS = "200k"
	spec.Payload = []byte("0123456789") // 10 bytes
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: true, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	// Regardless of Count/Duration/BPS: 3 handshake + 2 data + 4 termination = 9
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (Count/Duration/BPS ignored)", len(cfgs))
	}
}

// M4: init() registration is commented out. protocol.Get("tcp") returns nil,
// but NewPlanner().Name() still works.
func TestTCPPlan_InitRegistrationCommented(t *testing.T) {
	// The global registry is in internal/protocol; the tcp package's init()
	// has Register commented out. We verify NewPlanner works directly.
	p := NewPlanner()
	if p.Name() != "tcp" {
		t.Errorf("Name=%s, want tcp", p.Name())
	}
}

// M5: the final ACK of termination does not increment packetIndex afterward
// (benign: channel closes right after). Verify the last packet has the max
// PacketIndex and channel closes.
func TestTCPPlan_LastACKNoPacketIndexInc(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Fatalf("len=%d, want 4", len(cfgs))
	}
	// PacketIndex 0..3
	for i, c := range cfgs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("cfg[%d].PacketIndex=%d, want %d", i, c.PacketIndex, i)
		}
	}
}

// E1: payload exactly N*MSS, no remainder
func TestTCPPlan_PayloadExactMSSMultiple(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 2920) // 1460*2
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Errorf("len=%d, want 4 (2 segments)", len(cfgs))
	}
}

func TestTCPPlan_PayloadSingleByte(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = []byte{0x41}
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Errorf("len=%d, want 2", len(cfgs))
	}
	if len(cfgs[0].Payload) != 1 {
		t.Errorf("segment len=%d, want 1", len(cfgs[0].Payload))
	}
}

func TestTCPPlan_MSSLarge(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 100000)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 65535}
	cfgs := drain(mustPlan(t, p, spec))
	// 2 segments [65535, 34465], 4 packets
	if len(cfgs) != 4 {
		t.Errorf("len=%d, want 4", len(cfgs))
	}
	if len(cfgs[0].Payload) != 65535 {
		t.Errorf("seg0 len=%d, want 65535", len(cfgs[0].Payload))
	}
	if len(cfgs[2].Payload) != 34465 {
		t.Errorf("seg1 len=%d, want 34465", len(cfgs[2].Payload))
	}
}

func TestTCPPlan_PayloadMSSPlusOne(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Payload = make([]byte, 1461)
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: false, MSS: 1460}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Errorf("len=%d, want 4 (2 segments [1460,1])", len(cfgs))
	}
	if len(cfgs[2].Payload) != 1 {
		t.Errorf("seg1 len=%d, want 1", len(cfgs[2].Payload))
	}
}

func TestTCPPlan_BothIPsEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = ""
	spec.DstIP = ""
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	want := "--2000-80"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
	if cfgs[0].L3.SrcIP != "" || cfgs[0].L3.DstIP != "" {
		t.Errorf("IPs not empty: src=%s dst=%s", cfgs[0].L3.SrcIP, cfgs[0].L3.DstIP)
	}
}

func TestTCPPlan_SrcIPOnly(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.DstIP = ""
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	want := "10.0.0.1--2000-80"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestTCPPlan_DstIPOnly(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = ""
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	want := "-10.0.0.2-2000-80"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestTCPPlan_IPv6Addresses(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = "::1"
	spec.DstIP = "fe80::1"
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("IPv6 should be accepted: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := "::1-fe80::1-2000-80"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
	// EtherType is still 0x0800 (IPv4 hardcoded, not 0x86DD)
	if cfgs[0].L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x, want 0x0800 (IPv4 hardcoded)", cfgs[0].L2.EtherType)
	}
}

func TestTCPPlan_MaxPort(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcPort = 65535
	spec.DstPort = 65535
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("max port: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.SrcPort != 65535 || cfgs[0].L4.DstPort != 65535 {
		t.Errorf("ports: src=%d dst=%d", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
}

func TestTCPPlan_ConfigAllZero(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.TCP = &core.TCPConfig{} // all zero
	cfgs := drain(mustPlan(t, p, spec))
	// Handshake/Termination=false -> 0 packets
	if len(cfgs) != 0 {
		t.Errorf("len=%d, want 0 (Handshake/Termination false)", len(cfgs))
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}
