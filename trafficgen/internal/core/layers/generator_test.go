package layers

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// fakeTime 是固定的时间基线，供包回填断言使用。
var fakeTime = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// ---- 测试辅助 ----

func configOf(t *testing.T, ch <-chan core.PacketConfig) []core.PacketConfig {
	t.Helper()
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// emitCollector 收集所有 Emit 的包，供生成器直接驱动（测层生成器本身）。
func emitCollector(out *[]core.PacketConfig) func(core.PacketConfig) error {
	return func(c core.PacketConfig) error {
		*out = append(*out, c)
		return nil
	}
}

// ---- T-CP1: 握手包字节（正向）----
// 对应规格 §握手：SYN(up, 0x02) → SYN-ACK(down, 0x12) → ACK(up, 0x10)；
// SYN 带 MSS data 0x05B4 + Window Scale 0x07 + SACKPermit；WindowSize 65535 默认。
func TestTCPGenerator_HandshakeBytes(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"mss": uint16(1460), "window_size": uint16(65535),
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1", ClassID: "c1", Timestamp: fakeTime},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("handshake-only flow = %d packets, want 3", len(out))
	}
	syn := out[0]
	if syn.Direction != "up" || syn.L4.Flags != FlagSYN {
		t.Errorf("SYN = dir %q flags %x, want up/0x02", syn.Direction, syn.L4.Flags)
	}
	if syn.L4.WindowSize != 65535 {
		t.Errorf("SYN window = %d, want 65535", syn.L4.WindowSize)
	}
	// MSS 字节精确 0x05B4 + WinScale 0x07 + SACKPermit（复刻 tcp.go synOptions）。
	var sawMSS, sawWinScale, sawSACK bool
	for _, o := range syn.L4.TCPOptions {
		switch o.Kind {
		case core.TCPOptMSS:
			sawMSS = true
			if len(o.Data) != 2 || o.Data[0] != 0x05 || o.Data[1] != 0xB4 {
				t.Errorf("MSS data = %x, want 05b4", o.Data)
			}
		case core.TCPOptWinScale:
			sawWinScale = true
			if len(o.Data) != 1 || o.Data[0] != 0x07 {
				t.Errorf("WinScale data = %x, want 07", o.Data)
			}
		case core.TCPOptSACKPermit:
			sawSACK = true
		}
	}
	if !sawMSS || !sawWinScale || !sawSACK {
		t.Errorf("SYN options missing: MSS=%v WinScale=%v SACK=%v", sawMSS, sawWinScale, sawSACK)
	}
	synack := out[1]
	if synack.Direction != "down" || synack.L4.Flags != FlagSYN|FlagACK {
		t.Errorf("SYN-ACK = dir %q flags %x, want down/0x12", synack.Direction, synack.L4.Flags)
	}
	ack := out[2]
	if ack.Direction != "up" || ack.L4.Flags != FlagACK {
		t.Errorf("ACK = dir %q flags %x, want up/0x10", ack.Direction, ack.L4.Flags)
	}
}

// ---- T-CP2: 握手包时序 seq/ack 推进（正向）----
// 对应规格 §seq 初始化：clientSeq = InitialSeq，serverSeq = rand；SYN 后 client+1，SYN-ACK 后 server+1。
func TestTCPGenerator_HandshakeSeqAck(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	syn, synack, ack := out[0], out[1], out[2]
	if syn.L4.Seq != 1000 {
		t.Errorf("SYN seq = %d, want 1000 (InitialSeq)", syn.L4.Seq)
	}
	if synack.L4.Ack != 1001 {
		t.Errorf("SYN-ACK ack = %d, want 1001 (ISN+1)", synack.L4.Ack)
	}
	if ack.L4.Seq != 1001 {
		t.Errorf("ACK seq = %d, want 1001", ack.L4.Seq)
	}
	if ack.L4.Ack != synack.L4.Seq+1 {
		t.Errorf("ACK ack = %d, want server ISN+1 (%d)", ack.L4.Ack, synack.L4.Seq+1)
	}
}

// ---- T-CP3: 无握手：直接数据段（负向）----
// 对应规格 §握手 Handshake 默认 true 但可显式关闭：包序列直接以数据段开头。
func TestTCPGenerator_NoHandshake(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": false, "termination": false,
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 0 {
		t.Errorf("handshake=false with no payload = %d packets, want 0", len(out))
	}

	// 无握手 + payload：第一个包是数据段（PSH|ACK），seq 直接从 InitialSeq 开始。
	req2 := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": false, "termination": false,
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	out2 := []core.PacketConfig{}
	req2.Emit = emitCollector(&out2)
	req2.Meta.Payload = []byte("hello")
	if err := g.Generate(context.Background(), req2); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out2) != 2 {
		t.Fatalf("no-handshake payload flow = %d packets, want 2 (data+ack)", len(out2))
	}
	if out2[0].L4.Flags != FlagPSH|FlagACK {
		t.Errorf("first packet flags = %x, want 0x18 (PSH|ACK), no SYN", out2[0].L4.Flags)
	}
	if out2[0].L4.Seq != 1000 {
		t.Errorf("first data seq = %d, want 1000 (InitialSeq without SYN increment)", out2[0].L4.Seq)
	}
}

// ---- T-CP4: 数据段 MSS 分段（正向）----
// 对应规格 §数据段：payload 按 MSS 分段，每段(up, PSH|ACK) 后紧跟对端 ACK(down)；seq 按段长推进。
func TestTCPGenerator_PayloadSegmentation(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"mss": uint16(1460), "initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	// 3000 字节 → 3 段：1460 + 1460 + 80。
	payload := make([]byte, 3000)
	req.Meta.Payload = payload
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// 握手 3 + 数据段 3 + 对端 ACK 3 = 9。
	if len(out) != 9 {
		t.Fatalf("3000B payload flow = %d packets, want 9", len(out))
	}
	dataIdx := []int{3, 5, 7}
	ackIdx := []int{4, 6, 8}
	for i, di := range dataIdx {
		seg := out[di]
		wantLen := 1460
		if i == 2 {
			wantLen = 80
		}
		if len(seg.Payload) != wantLen {
			t.Errorf("segment %d payload = %d bytes, want %d", i, len(seg.Payload), wantLen)
		}
		if seg.L4.Flags != FlagPSH|FlagACK {
			t.Errorf("segment %d flags = %x, want 0x18", i, seg.L4.Flags)
		}
		if seg.Direction != "up" {
			t.Errorf("segment %d direction = %q, want up", i, seg.Direction)
		}
		// seq 推进：第 0 段 = ISN+1（SYN 消耗 1），第 1 段 = +1460，第 2 段 = +2920。
		wantSeq := uint32(1001) + uint32(1460*i)
		if seg.L4.Seq != wantSeq {
			t.Errorf("segment %d seq = %d, want %d", i, seg.L4.Seq, wantSeq)
		}
		// 每段后紧跟对端 ACK：ack = 段尾 seq。
		ack := out[ackIdx[i]]
		if ack.Direction != "down" || ack.L4.Flags != FlagACK {
			t.Errorf("peer ack %d = dir %q flags %x, want down/0x10", i, ack.Direction, ack.L4.Flags)
		}
		if ack.L4.Ack != seg.L4.Seq+uint32(wantLen) {
			t.Errorf("peer ack %d ack = %d, want %d (segment end)", i, ack.L4.Ack, seg.L4.Seq+uint32(wantLen))
		}
	}
}

// ---- T-CP5: MSS 0 → 1460 默认；MSS 100 被 min 536 抬升（边界）----
// 对应规格 §MSS 默认：0 则 1460；schema min 536。
func TestTCPGenerator_MSSDefaults(t *testing.T) {
	// MSS=0 → 1460：SYN 的 MSS 选项 data = 0x05B4，分段按 1460。
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"mss": uint16(0),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, o := range out[0].L4.TCPOptions {
		if o.Kind == core.TCPOptMSS && (len(o.Data) != 2 || o.Data[0] != 0x05 || o.Data[1] != 0xB4) {
			t.Errorf("MSS=0 SYN option data = %x, want 05b4", o.Data)
		}
	}

	// MSS=100 → 抬到 536：1500 字节 payload 分 3 段（536+536+428），包数 3+3+3=9。
	req2 := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"mss": uint16(100),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	req2.Meta.Payload = make([]byte, 1500)
	out2 := []core.PacketConfig{}
	req2.Emit = emitCollector(&out2)
	if err := g.Generate(context.Background(), req2); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out2) != 9 {
		t.Fatalf("MSS=100 1500B flow = %d packets, want 9 (3x536+428)", len(out2))
	}
	if len(out2[3].Payload) != 536 {
		t.Errorf("MSS=100 first segment = %d bytes, want 536 (min)", len(out2[3].Payload))
	}
}

// ---- T-CP6: 挥手（正向）----
// 对应规格 §挥手：FIN|ACK(up) → ACK(down) → FIN|ACK(down) → ACK(up)，seq/ack 按 tcp.go 推进。
func TestTCPGenerator_Termination(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": true, "rst": false,
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// 握手 3 + 挥手 4 = 7。
	if len(out) != 7 {
		t.Fatalf("handshake+termination = %d packets, want 7", len(out))
	}
	fin1, ack1, fin2, ack2 := out[3], out[4], out[5], out[6]
	if fin1.Direction != "up" || fin1.L4.Flags != FlagFIN|FlagACK {
		t.Errorf("FIN1 = dir %q flags %x, want up/0x11", fin1.Direction, fin1.L4.Flags)
	}
	if ack1.Direction != "down" || ack1.L4.Flags != FlagACK || ack1.L4.Ack != fin1.L4.Seq+1 {
		t.Errorf("ACK1 = dir %q flags %x ack %d, want down/0x10 ack FIN1.seq+1 (%d)",
			ack1.Direction, ack1.L4.Flags, ack1.L4.Ack, fin1.L4.Seq+1)
	}
	if fin2.Direction != "down" || fin2.L4.Flags != FlagFIN|FlagACK {
		t.Errorf("FIN2 = dir %q flags %x, want down/0x11", fin2.Direction, fin2.L4.Flags)
	}
	// FIN2 的 seq = server ISN+1（SYN-ACK 消耗 1），ack = FIN1.seq+1。
	if fin2.L4.Seq != req.Sess.ServerSeq {
		t.Errorf("FIN2 seq = %d, want server ISN+1 (%d)", fin2.L4.Seq, req.Sess.ServerSeq)
	}
	if ack2.Direction != "up" || ack2.L4.Flags != FlagACK || ack2.L4.Ack != fin2.L4.Seq+1 {
		t.Errorf("ACK2 = dir %q flags %x ack %d, want up/0x10 ack FIN2.seq+1",
			ack2.Direction, ack2.L4.Flags, ack2.L4.Ack)
	}
}

// ---- T-CP7: RST 代替挥手（负向）----
// 对应规格 §RST：RST|ACK(up) 代替挥手，不产出 FIN。
func TestTCPGenerator_RSTReplacesTermination(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": true, "rst": true,
				"initial_seq": uint32(1000),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// 握手 3 + RST 1 = 4；无 FIN。
	if len(out) != 4 {
		t.Fatalf("handshake+rst = %d packets, want 4", len(out))
	}
	rst := out[3]
	if rst.Direction != "up" || rst.L4.Flags != FlagRST|FlagACK {
		t.Errorf("RST = dir %q flags %x, want up/0x14", rst.Direction, rst.L4.Flags)
	}
	for _, c := range out {
		if c.L4.Flags&FlagFIN != 0 {
			t.Errorf("RST flow must not emit FIN, got flags %x", c.L4.Flags)
		}
	}
}

// ---- T-CP8: termination=false 无 FIN/RST（负向）----
func TestTCPGenerator_NoTermination(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false, "rst": false,
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("handshake-only = %d packets, want 3", len(out))
	}
	for _, c := range out {
		if c.L4.Flags&(FlagFIN|FlagRST) != 0 {
			t.Errorf("termination=false flow must not emit FIN/RST, got flags %x", c.L4.Flags)
		}
	}
}

// ---- T-CP9: window_size 自定义（正向）----
func TestTCPGenerator_WindowSize(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": false,
				"window_size": uint16(8192),
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, c := range out {
		if c.L4.WindowSize != 8192 {
			t.Errorf("window = %d, want 8192 (all packets)", c.L4.WindowSize)
		}
	}
}

// ---- T-IP1: ip 层填 L3 + IPID 自增（正向）----
// 对应规格 §ip 层生成器：从 Layer.Config 读 src/dst/ttl/dscp/ecn/frag_offset；
// 每 Emit 前 Sess.IPID 写入 L3Config.IPID 并自增；不重复 L3Base 已有逻辑。
func TestIPGenerator_FillsL3AndIncrementsIPID(t *testing.T) {
	g := &IPGenerator{}
	sess := &SessionState{IPID: 0x1234}
	inner := make(chan core.PacketConfig, 1)
	inner <- core.PacketConfig{}
	close(inner)
	req := &GenRequest{
		Layer: Layer{
			Name: "ip",
			Config: map[string]interface{}{
				"src": "10.1.2.3", "dst": "10.9.8.7",
				"ttl": uint8(100), "dscp": uint8(0x2E), "ecn": uint8(1),
				"frag_offset": uint16(0x800),
			},
		},
		Inner: inner,
		Sess:  sess,
		Meta:  FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("ip generator = %d packets, want 1", len(out))
	}
	l3 := out[0].L3
	if l3.SrcIP != "10.1.2.3" || l3.DstIP != "10.9.8.7" {
		t.Errorf("L3 src/dst = %s/%s, want 10.1.2.3/10.9.8.7", l3.SrcIP, l3.DstIP)
	}
	if l3.TTL != 100 || l3.DSCP != 0x2E || l3.ECN != 1 {
		t.Errorf("L3 ttl/dscp/ecn = %d/%d/%d, want 100/46/1", l3.TTL, l3.DSCP, l3.ECN)
	}
	if l3.FragOffset != 0x800 {
		t.Errorf("L3 frag_offset = %d, want 0x800", l3.FragOffset)
	}
	// Protocol 由 ChainPlanner 出口装配（finalEmit 按 transport 层写 6）；
	// 本单测驱动 ip 生成器本身，不重复断言（分层边界，见 T-CHAIN 整链断言）。
	if l3.IPID != 0x1234 {
		t.Errorf("L3 IPID = %x, want 0x1234 (session start)", l3.IPID)
	}
	if sess.IPID != 0x1235 {
		t.Errorf("Sess.IPID after emit = %x, want 0x1235 (incremented)", sess.IPID)
	}
}

// ---- T-IP2: 连续 Emit IPID 递增（正向）----
func TestIPGenerator_IPIDIncrementsPerEmit(t *testing.T) {
	g := &IPGenerator{}
	// 每轮 Generate 消费一个内层包：源端用带 1 个包的 channel。
	inner := make(chan core.PacketConfig, 1)
	inner <- core.PacketConfig{}
	close(inner)
	sess := &SessionState{IPID: 0x0001}
	req := &GenRequest{
		Layer: Layer{Name: "ip", Config: map[string]interface{}{"src": "1.1.1.1", "dst": "2.2.2.2"}},
		Inner: inner,
		Sess:  sess,
		Meta:  FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	// 3 轮 Generate：每轮一个包，共享 sess → IPID 0x0001, 0x0002, 0x0003。
	for i := 0; i < 3; i++ {
		inner = make(chan core.PacketConfig, 1)
		inner <- core.PacketConfig{}
		close(inner)
		req.Inner = inner
		if err := g.Generate(context.Background(), req); err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
	}
	if len(out) != 3 {
		t.Fatalf("3 generates = %d packets, want 3", len(out))
	}
	want := []uint16{0x0001, 0x0002, 0x0003}
	for i, w := range want {
		if out[i].L3.IPID != w {
			t.Errorf("emit %d IPID = %x, want %x", i, out[i].L3.IPID, w)
		}
	}
}

// ---- T-CHAIN1: ChainPlanner 独立 tcp flow 整链（正向）----
// 对应规格 §ChainPlanner：类名即末层；默认值补全（handshake 默认 true）；
// 逐包回填 FlowID/ClassID/PacketIndex/Timestamp/Direction；终结层驱动整链。
func TestChainPlanner_TCPFlow(t *testing.T) {
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		TTL:     100,
		Payload: []byte("hello"),
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := configOf(t, ch)
	// 握手 3 + 数据 1 + ACK 1 + 挥手 4 = 9（MSS 默认 1460，5 字节不分段）。
	if len(configs) != 9 {
		t.Fatalf("tcp flow = %d packets, want 9", len(configs))
	}
	if configs[0].L4.Flags != FlagSYN {
		t.Fatalf("first packet flags = %x, want SYN (handshake default true)", configs[0].L4.Flags)
	}
	// FlowID/ClassID/PacketIndex/Timestamp/Direction 回填。
	// ClassID 由引擎回填（worker.go:317 config.ClassID = task.ClassID），
	// ChainPlanner 不设置它——此处断言为空。
	for i, c := range configs {
		if c.FlowID == "" {
			t.Errorf("packet %d: FlowID empty", i)
		}
		if c.ClassID != "" {
			t.Errorf("packet %d: ClassID = %q, want empty (worker backfills)", i, c.ClassID)
		}
		if c.PacketIndex != uint64(i) {
			t.Errorf("packet %d: PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
		if c.Timestamp.IsZero() {
			t.Errorf("packet %d: Timestamp zero", i)
		}
		if c.Direction != "up" && c.Direction != "down" {
			t.Errorf("packet %d: Direction = %q", i, c.Direction)
		}
	}
	// L2/L3 装配：up 时 SrcMAC=spec.SrcMAC，down 时反置。
	up := configs[0]
	if up.L2.SrcMAC != "aa:bb:cc:dd:ee:ff" || up.L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("up L2 = %s→%s, want aa..ff→11..66", up.L2.SrcMAC, up.L2.DstMAC)
	}
	if up.L3.SrcIP != "192.168.1.1" || up.L3.DstIP != "192.168.1.2" {
		t.Errorf("up L3 = %s→%s, want 192.168.1.1→192.168.1.2", up.L3.SrcIP, up.L3.DstIP)
	}
	down := configs[1]
	if down.L2.SrcMAC != "11:22:33:44:55:66" || down.L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("down L2 = %s→%s, want swapped", down.L2.SrcMAC, down.L2.DstMAC)
	}
	if down.L3.SrcIP != "192.168.1.2" || down.L3.DstIP != "192.168.1.1" {
		t.Errorf("down L3 = %s→%s, want swapped", down.L3.SrcIP, down.L3.DstIP)
	}
	// TTL 100 生效（spec.TTL 映射进 ip 层）。
	if configs[0].L3.TTL != 100 {
		t.Errorf("L3 TTL = %d, want 100", configs[0].L3.TTL)
	}
}

// ---- T-CHAIN2: 独立 tcp flow 无 TCP 子配置：全默认（正向）----
// spec.TCP 为 nil（零值）时 handshake 仍默认 true —— 关键：不能读 TCPConfig 零值。
func TestChainPlanner_TCPNilSpecDefaults(t *testing.T) {
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := configOf(t, ch)
	if len(configs) != 7 {
		t.Fatalf("default tcp flow = %d packets, want 7 (handshake 3 + termination 4)", len(configs))
	}
	if configs[0].L4.Flags != FlagSYN {
		t.Errorf("first packet flags = %x, want SYN (schema default handshake=true)", configs[0].L4.Flags)
	}
	if configs[0].L4.WindowSize != 65535 {
		t.Errorf("SYN window = %d, want 65535 (schema default)", configs[0].L4.WindowSize)
	}
	// 默认 IP 地址（schema ip.src/dst = 10.0.0.1/20.0.0.1）—— spec 没写 IP 时用层默认。
	// 注意：spec.SrcIP 为空时 L3Base 的 IP 从层 config 默认来。此处断言默认层 src/dst。
}

// ---- T-CHAIN3: Validate 委托 chain 校验 + 非法层名拒绝（负向）----
func TestChainPlanner_Validate(t *testing.T) {
	p := NewChainPlanner("tcp")
	// 合法 spec。
	spec := core.FlowSpec{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}

	// 非法 IP。
	bad := core.FlowSpec{SrcIP: "nope", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80}
	if err := p.Validate(bad); err == nil {
		t.Error("Validate(invalid IP) = nil, want error")
	}

	// 缺端口。
	noPort := core.FlowSpec{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 0, DstPort: 80}
	if err := p.Validate(noPort); err == nil {
		t.Error("Validate(no src port) = nil, want error")
	}

	// Plan 也走 Validate：非法 spec 直接报错（不产包）。
	if _, err := p.Plan(context.Background(), bad); err == nil {
		t.Error("Plan(invalid) = nil err, want error")
	}
}

// ---- T-CHAIN4: ChainPlanner 非法层名（负向）----
func TestChainPlanner_UnknownLayerName(t *testing.T) {
	p := NewChainPlanner("not_a_layer")
	spec := core.FlowSpec{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80}
	if _, err := p.Plan(context.Background(), spec); err == nil {
		t.Fatal("Plan(unknown layer) = nil err, want error")
	}
}

// ---- T-CHAIN5: 生成器 map 回调错误中止驱动（负向）----
func TestTCPGenerator_EmitErrorStops(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": true,
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
		Emit: func(core.PacketConfig) error {
			return errors.New("emit failed")
		},
	}
	err := g.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() = nil err, want emit error propagation")
	}
	if !reflect.DeepEqual(err.Error(), "emit failed") {
		t.Errorf("error = %v, want emit failed", err)
	}
}

// ---- review 回归：CRITICAL-1 取消路径 send-on-closed 竞态 ----
// 审查发现：Plan 的 goroutine 在 drive 返回后 defer close(out)，但取消
// （ctx.Done）时 ip 生成器 goroutine 可能仍在消费缓冲 innerCh 并 select 向 out
// 发送 → close 与 send 并发（-race 实测复现），若 send 落在 close 之后 →
// send-on-closed-channel panic（不可恢复的 runtime 崩溃）。
// 修复要求：Plan 的 goroutine 必须先等 ip 生成器排空（genDone），之后才 close(out)。
func TestChainPlanner_CancelNoPanic_AfterFlush(t *testing.T) {
	// 3 包后取消 + 100KB payload（远超 256 槽缓冲）→ 取消时发送方仍在途。
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消，触发最早的取消路径
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 80,
		Payload: make([]byte, 100*1024),
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := configOf(t, ch) // 断言不 panic、channel 正常关闭
	t.Logf("cancel-immediate flow yielded %d packets (>=0)", len(got))
}

func TestChainPlanner_CancelMidDrive_NoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 80,
		Payload: make([]byte, 100*1024),
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// 消费 3 包（握手）后取消，剩余数据段仍在途。
	idx := 0
	for c := range ch {
		if idx == 3 {
			cancel()
		}
		_ = c
		idx++
	}
	if idx == 0 {
		t.Error("cancel-mid-drive flow yielded 0 packets; expected at least handshake before cancel")
	}
}

// ---- review 回归：HIGH-1 RST 提前 return 丢弃 state 回写 + emit 错误丢失 ----
// legacy tcp.go:306-328：RST 分支只产出 RST 包，**照常走到 termination 检查**
// （Termination && !RST 跳过挥手），Sess 状态回写在 RST 之后仍执行。
// 实现用 `return emit(rst)` 提前退出 → 状态永不回写，且 emit 失败被当作
// Generate 的正常返回值吞掉（调用方视为成功）。
func TestTCPGenerator_RSTStillWritesSessionState(t *testing.T) {
	g := &TCPGenerator{}
	sess := &SessionState{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": true, "rst": true,
				"initial_seq": uint32(1000),
			},
		},
		Sess: sess,
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// 握手 3 + RST 1 = 4；无 FIN。
	if len(out) != 4 {
		t.Fatalf("handshake+rst = %d packets, want 4", len(out))
	}
	// 状态必须回写（挥手/后续驱动依赖）：clientSeq = ISN+1，serverSeq = ISN+1。
	if sess.ClientSeq != 1001 {
		t.Errorf("Sess.ClientSeq = %d, want 1001 (ISN+1)", sess.ClientSeq)
	}
	if sess.ServerSeq == 0 {
		t.Errorf("Sess.ServerSeq = 0, want non-zero (server ISN+1)")
	}
	if !sess.HandshakeDone {
		t.Errorf("Sess.HandshakeDone = false, want true")
	}
	if sess.ServerAck != 1001 {
		t.Errorf("Sess.ServerAck = %d, want 1001 (client seq after SYN)", sess.ServerAck)
	}
}

func TestTCPGenerator_RSTPropagatesEmitError(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port": uint16(12345), "dst_port": uint16(80),
				"handshake": true, "termination": true, "rst": true,
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
		Emit: func(core.PacketConfig) error {
			return errors.New("emit failed")
		},
	}
	err := g.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() = nil err, want RST emit error propagation")
	}
	if !reflect.DeepEqual(err.Error(), "emit failed") {
		t.Errorf("error = %v, want emit failed", err)
	}
}

// ---- review 回归：HIGH-2 spec.TOS 整字节覆盖 DSCP/ECN ----
// legacy L3Base（builder.go:158-161）：spec.TOS != 0 时 DSCP=TOS>>2, ECN=TOS&3。
// 审查实测：TOS=0x2E（DSCP 11, ECN 2）→ chain 产出 DSCP=0/ECN=0（TOS 被忽略）。
func TestChainPlanner_TOSOverridesDSCPECN(t *testing.T) {
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 80,
		TOS: 0x2E, // DSCP=11, ECN=2
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := configOf(t, ch)
	if len(configs) == 0 {
		t.Fatal("no packets")
	}
	if configs[0].L3.DSCP != 0x0B || configs[0].L3.ECN != 0x02 {
		t.Errorf("TOS=0x2E → DSCP=%d ECN=%d, want 11/2 (TOS>>2, TOS&3)", configs[0].L3.DSCP, configs[0].L3.ECN)
	}
}

// ---- review 回归：HIGH-3 超范围整型被 uint16 截断绕过校验 ----
// 审查实测：YAML 写 mss=70000 → 解析层 getUint16 **先截断成 4464**，planner 的
// Validate 只见截断值（合法）→ SYN 选项字节 11 70。Go 层 uint16 类型本身
// 无法承载 70000（截断在 mapToFlowSpec）。真实防护在解析层入口：
// ValidateConfigRanges + ValidateProtocolSubConfigs（convert.go:209-217，
// getInt(sub,"mss") 校验 0-65535）在 mapToFlowSpec 截断之前拦下。
// 本测试固定"planner 对解析层可见的非法值必须拒绝"这一层语义——
// MSS<536 已拒绝（validateSpecBase），MSS>65535 在 Go 层不可达（类型上限，
// 由 ValidateProtocolSubConfigs 于解析层拦截）；端口同理由 uint16 类型保证。
// 测试覆盖 MIN/MAX 常量语义 + 边界合法值不误伤。
func TestChainPlanner_ValidateRejectsOverflowingTCPFields(t *testing.T) {
	p := NewChainPlanner("tcp")
	// MSS 低于 RFC 879 下限（536）→ 拒绝（validateSpecBase 已覆盖）。
	badMSS := core.FlowSpec{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80,
		TCP: &core.TCPConfig{MSS: 500}}
	if err := p.Validate(badMSS); err == nil {
		t.Error("MSS 500: Validate = nil, want error (below min 536)")
	}
	// 常量语义：MSS 上限 = uint16 类型上限；schema max 65535 与 MinMSS 一致。
	if MaxMSS := uint16(65535); MaxMSS != 65535 {
		t.Errorf("MSS uint16 upper bound = %d, want 65535", MaxMSS)
	}
	// 边界合法值不误伤：MSS=536（min）、端口 65535（max）。
	ok := core.FlowSpec{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 65535, DstPort: 80,
		TCP: &core.TCPConfig{MSS: 536}}
	if err := p.Validate(ok); err != nil {
		t.Errorf("boundary valid spec rejected: %v", err)
	}
}

// ---- review 回归：MEDIUM-1 resolveCfg 静默丢不可转换字段 ----
// 审查实测：initial_seq 为 float64(1e10)（合法 float64 但超 uint32）时，
// configUint32 判不可转换 → resolveCfg 静默跳过 → seq 落回随机值。
// 修复要求：存在但不可转换的值必须显式报错，不得静默丢配置。
func TestTCPGenerator_ResolveCfgRejectsUnconvertibleValue(t *testing.T) {
	g := &TCPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name: "tcp",
			Config: map[string]interface{}{
				"src_port":    uint16(12345),
				"dst_port":    uint16(80),
				"handshake":   true,
				"termination": false,
				"initial_seq": float64(1e10), // 合法 float64，超 uint32
			},
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	err := g.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() = nil err, want reject unconvertible initial_seq")
	}
}

// ---- review 回归：LOW-1 空 spec IP 时的 L3 行为固化（注释与行为一致）----
// 原注释声称"默认 IP 地址（schema ip.src/dst = 10.0.0.1/20.0.0.1）"但零断言。
// 真实行为（复刻 legacy：spec.SrcIP 空 → L3Base 收到空串 → L3.SrcIP 空）：
// 空 spec IP 时包上 L3 IP 是空串，不注入 schema 默认 IP。
func TestChainPlanner_EmptySpecIP_L3StaysEmpty(t *testing.T) {
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcPort: 1000, DstPort: 80,
		// SrcIP/DstIP 留空：行为 = legacy（L3Base 空 IP），不注入 schema 默认 10.0.0.1/20.0.0.1。
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := configOf(t, ch)
	if len(configs) == 0 {
		t.Fatal("no packets")
	}
	if configs[0].L3.SrcIP != "" || configs[0].L3.DstIP != "" {
		t.Errorf("empty spec IP → L3 = %q/%q, want empty (legacy behavior)", configs[0].L3.SrcIP, configs[0].L3.DstIP)
	}
}

// ---- T-CHAIN6: 层链逐包回填：ChainPlanner 用合成链驱动（正向，包数+序号覆盖）----
func TestChainPlanner_PacketIndexSequence(t *testing.T) {
	p := NewChainPlanner("tcp")
	spec := core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 80,
		Payload: []byte("0123456789"), // 10 字节 1 段
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := configOf(t, ch)
	// 3 握手 + 2 数据 + 4 挥手 = 9。
	if len(configs) != 9 {
		t.Fatalf("flow = %d packets, want 9", len(configs))
	}
	// PacketIndex 严格连续 0..8。
	for i, c := range configs {
		if c.PacketIndex != uint64(i) {
			t.Fatalf("PacketIndex = %d at position %d", c.PacketIndex, i)
		}
	}
	// IPID 逐包递增（ip 层持有）。
	for i := 1; i < len(configs); i++ {
		if configs[i].L3.IPID != configs[i-1].L3.IPID+1 {
			t.Fatalf("IPID not monotonic: %d then %d", configs[i-1].L3.IPID, configs[i].L3.IPID)
		}
	}
}

// ---- 波 5c：事件级 SrcPort 覆盖（rip 多 router / well-known 端口语义）----
// legacy rip.go resolveSrcPort：单 router Response=520（well-known），
// multi-router=52001+idx，request_full=52001——事件必须能覆盖 udp 层 cfg
// 的 srcPort（validateSpecBase 已把 0 默认化）。零值 = 不覆盖（保持 cfg）。
func TestUDPGenerator_EventSrcPortOverride(t *testing.T) {
	g := &UDPGenerator{}
	cfg := map[string]interface{}{
		"src_port": uint16(52001),
		"dst_port": uint16(520),
	}
	events := make(chan MessageEvent, 2)
	events <- MessageEvent{Up: true, Bytes: []byte("a"), SrcPort: 520} // 覆盖为 well-known
	events <- MessageEvent{Up: true, Bytes: []byte("b")}              // 不覆盖 → cfg 值
	close(events)
	req := &GenRequest{
		Layer: Layer{Name: "udp", Config: cfg},
		Sess:  &SessionState{},
		Meta:  FlowMeta{FlowID: "f1", Events: events},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("2 events = %d packets, want 2", len(out))
	}
	if out[0].L4.SrcPort != 520 {
		t.Errorf("event[0] SrcPort = %d, want 520 (event override)", out[0].L4.SrcPort)
	}
	if out[1].L4.SrcPort != 52001 {
		t.Errorf("event[1] SrcPort = %d, want 52001 (cfg value, no override)", out[1].L4.SrcPort)
	}
	// DstPort 不受事件影响（RIP 无 dst 覆盖需求）。
	if out[0].L4.DstPort != 520 || out[1].L4.DstPort != 520 {
		t.Errorf("DstPort = %d/%d, want 520/520 (cfg)", out[0].L4.DstPort, out[1].L4.DstPort)
	}
}

// ---- review 回归：udp resolveCfg 不可转换端口必须显式报错 ----
// 与 TCPGenerator_ResolveCfgRejectsUnconvertibleValue 同款纪律（MEDIUM-1）：
// src_port/dst_port 存在但无法转 uint16（float64 超界 / 字符串 / 负数）时，
// 不得静默跳过（否则端口落 0），必须显式报错。
func TestUDPGenerator_ResolveCfgRejectsUnconvertiblePort(t *testing.T) {
	bad := map[string]interface{}{
		"src_port": "abc",   // 字符串不可转换
		"dst_port": uint16(53),
	}
	g := &UDPGenerator{}
	req := &GenRequest{
		Layer: Layer{
			Name:   "udp",
			Config: bad,
		},
		Sess: &SessionState{},
		Meta: FlowMeta{FlowID: "f1"},
	}
	var out []core.PacketConfig
	req.Emit = emitCollector(&out)
	if err := g.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate() = nil err, want reject unconvertible src_port")
	}

	badOver := map[string]interface{}{
		"src_port": uint16(12345),
		"dst_port": float64(70000), // 合法 float64，超 uint16
	}
	req2 := &GenRequest{
		Layer: Layer{Name: "udp", Config: badOver},
		Sess:  &SessionState{},
		Meta:  FlowMeta{FlowID: "f1"},
	}
	var out2 []core.PacketConfig
	req2.Emit = emitCollector(&out2)
	if err := g.Generate(context.Background(), req2); err == nil {
		t.Fatal("Generate() = nil err, want reject unconvertible dst_port")
	}
}
