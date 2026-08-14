package nfs

// NFS terminal-layer generator tests (P4a)。NFSGenerator 复用 buildCall /
// buildReply 纯函数产事件——事件序列与 legacy Plan 的数据帧（TCP: flags=0x18
// PSH-ACK；UDP: 数据报 payload；握手/挥手过滤后）在方向/字节上逐帧一致
// （含 buildOpSequence 自动插入的 MOUNT/UMOUNT 对，XDR 编码）；链级测试通过
// ChainPlanner 驱动 [ip→tcp→nfs]（握手 3 + 数据 6 + 挥手 4 = 13 包）与
// [ip→udp→nfs]（2 数据报）完整链路。默认化（sessions 0→1 / xidBase 0→1 /
// transport ""→"tcp" / mountFH 16×0x01）与 legacy Plan 对齐，测试覆盖默认值
// 与显式值两路径；XIDIncr=0 显式支持（T-015 reply-echo）与 XID wrap 同款
// 覆盖。载体一致性（udp 载体 + 非 "udp" transport 拒绝）由 ChainPlanner
// ValidateSpec 结构性校验（chain_planner.go nfsTransportFromMetadata）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// mustPlanLegacy runs the legacy planner and returns all PacketConfigs in
// order（nfs_test.go 已有 mustPlan，命名避免冲突）。
func mustPlanLegacy(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// tcpPackets returns the TCP packet configs in wire order.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// layerNfsSpec returns a base NFSv3 spec with a deterministic ISN and one
// GETATTR op. initialSeq=0 → 不设 spec.TCP（链上 tcp 层随机 ISN）。
// （nfs_test.go 已有 nfsSpec，命名避免冲突。）
func layerNfsSpec(initialSeq uint32, cfg *NFSConfig) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50000, DstPort: 2049,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return AttachSpec(spec, cfg)
}

// collectEvents drives NFSGenerator.Generate and collects the emitted message
// events in order. 值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &NFSGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NFS: spec.Metadata[MetadataKey]},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return events
}

// legacyDataFrames runs the legacy planner and returns the NFS data frames
// (skip TCP handshake/teardown)。TCP 数据帧 flags=0x18 PSH-ACK（planSession
// 490-492 → emitTCPFrame），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	var out []core.PacketConfig
	for _, c := range tcpPackets(mustPlanLegacy(t, &Planner{}, spec)) {
		if c.L4.Flags == 0x18 { // data frame
			out = append(out, c)
		}
	}
	return out
}

// legacyUDPDatagrams runs the legacy planner and returns the UDP datagrams
// (UDP 无握手/挥手；每事件一数据报，方向端口交换)。
func legacyUDPDatagrams(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	var out []core.PacketConfig
	for _, c := range mustPlanLegacy(t, &Planner{}, spec) {
		if c.L4.Protocol == "udp" {
			out = append(out, c)
		}
	}
	return out
}

// assertEventsMatchLegacy 逐帧断言事件方向与字节与 legacy 数据帧一致。
func assertEventsMatchLegacy(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent) {
	t.Helper()
	legacy := legacyDataFrames(t, spec)
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy data frames = %d", len(events), len(legacy))
	}
	for i, ev := range events {
		pc := legacy[i]
		if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
		}
		if !bytes.Equal(ev.Bytes, pc.Payload) {
			t.Errorf("event[%d] payload = % X, legacy = % X", i, ev.Bytes, pc.Payload)
		}
	}
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy 数据帧在
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（默认化/显式版本/多 op/XID 变体/
// 错误注入/异常路径/显式 MOUNT/自定义 mountFH）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *NFSConfig
	}{
		// 默认化路径：XIDBase=0 → 1、Transport="" → "tcp"、Sessions=0 → 1。
		// nil MountFilehandle → 16×0x01。v3 自动插入 MOUNT(proc 1)+UMOUNT
		// (proc 3)（buildOpSequence §4.2 rule 1）。
		{"default v3 GETATTR", &NFSConfig{Version: 3, Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}},
		// 显式 Transport="tcp"（legacy 同款；空串默认化路径上面已覆盖）。
		{"explicit tcp transport", &NFSConfig{Version: 3, Transport: "tcp",
			Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}},
		// 多 op：MOUNT 自动对 + LOOKUP + WRITE（带 Data）+ UMOUNT 自动对。
		{"multi-op v3", &NFSConfig{Version: 3, Ops: []NFSOp{
			{Procedure: NFS3ProcLOOKUP, Filename: "file.txt"},
			{Procedure: NFS3ProcWRITE, Filehandle: []byte{0xAA}, Offset: 0, Count: 4,
				Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		}}},
		// XIDIncr=0 显式支持（T-015 reply-echo）：所有调用共享同一 XID。
		{"XIDIncr=0 reply-echo", &NFSConfig{Version: 3, XIDIncr: 0,
			Ops: []NFSOp{{Procedure: NFS3ProcNULL}, {Procedure: NFS3ProcNULL}}}},
		// XIDBase 显式非 1 + XIDIncr>1。
		{"XIDBase=100 XIDIncr=2", &NFSConfig{Version: 3, XIDBase: 100, XIDIncr: 2,
			Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}},
		// 显式 MOUNT 程序序列（Program=100005）：MOUNT 不自动插入，但
		// UMOUNT 尾部仍自动追加（nfs.go:616-634）。
		{"explicit mount op", &NFSConfig{Version: 3, Ops: []NFSOp{
			{Program: ProgramMount, ProgVersion: 3, Procedure: 1, DirPath: "/"},
		}}},
		// 自定义 mountFH（非默认 16×0x01）。
		{"custom mount filehandle", &NFSConfig{Version: 3,
			MountFilehandle: []byte{0xAA, 0xBB},
			Ops:             []NFSOp{{Procedure: NFS3ProcGETATTR}}}},
		// RPC 错误注入路径：RPCAcceptState=2（PROG_MISMATCH）。
		{"rpc accept error", &NFSConfig{Version: 3, Ops: []NFSOp{{
			Procedure: NFS3ProcGETATTR, RPCAcceptState: uint32Ptr(2),
		}}}},
		// 显式 Program（用户掌控程序序列，§4.2 注释：T-001 同款）。
		{"explicit nfs program", &NFSConfig{Version: 3, Ops: []NFSOp{{
			Program: ProgramNFS, ProgVersion: 3, Procedure: NFS3ProcGETATTR,
		}}}},
		// NFSv4.0（minorversion=0）COMPOUND：自动插入 SETCLIENTID +
		// SETCLIENTID_CONFIRM 两个独立 COMPOUND 对 + PUTROOTFH 前插 +
		// OPEN_CONFIRM 后插（用户提供显式 SETCLIENTID 固定 verifier 保
		// 确定性——auto 插入路径用 rand.Read，非确定性，NFSv4Deterministic
		// 测试显式覆盖）。
		{"explicit v4 setclientid", &NFSConfig{Version: 4, Ops: []NFSOp{{
			Procedure: NFS4ProcCOMPOUND,
			CompoundOps: []NFSv4CompoundOp{
				{Opcode: OP_SETCLIENTID, Client: &NFSClientId{
					Verifier: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
					Id:       "trafficgen-client-0",
				}},
				{Opcode: OP_SETCLIENTID_CONFIRM, Clientid: 0x10001,
					ClientidVerifier: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
			},
		}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := layerNfsSpec(0, tc.cfg)
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_NFS4Deterministic NFSv4 auto-insert（SETCLIENTID + CONFIRM +
// PUTROOTFH + OPEN_CONFIRM）：v4 config 不含显式 SETCLIENTID 时 auto 路径用
// rand.Read 生成 verifier（buildOpSequence 540-541）——同一生成内 call 的
// verifier 与 confirm call 的 verifier 相同（关联性），跨运行不可比。
// 断言 3 op × 2 = 6 事件 + 方向模式 + SETCLIENTID_CONFIRM call（事件 2）的
// clientid 编码（0x10001）与 verifier 回显结构。事件 2 布局（TCP RM 4B +
// RPC 头 24B + tag 4B + minorversion 4B + nops 4B + opcode 4B 后）：
// clientid 8B + verifier 8B。
func TestLayerGen_NFS4Deterministic(t *testing.T) {
	spec := layerNfsSpec(0, &NFSConfig{Version: 4, Ops: []NFSOp{{
		Procedure: NFS4ProcCOMPOUND,
		CompoundOps: []NFSv4CompoundOp{
			{Opcode: OP_OPEN, Seqid: 1},
		},
	}}})
	ev1 := collectEvents(t, spec)
	if len(ev1) != 6 {
		t.Fatalf("events = %d, want 6 (SETCLIENTID + CONFIRM + OPEN/PUTROOTFH/OPEN_CONFIRM × call/reply)", len(ev1))
	}
	for i, ev := range ev1 {
		if want := i%2 == 0; ev.Up != want {
			t.Errorf("event[%d] Up=%v, want %v (call up / reply down)", i, ev.Up, want)
		}
	}
	// 事件 2 = SETCLIENTID_CONFIRM call。TCP RM 4B + RPC 头 40B（xid/type/
	// rpcvers/prog/vers/proc 24B + cred flavor+len 8B + verf flavor+len 8B，
	// encodeRPCCallHeader 373-386）+ COMPOUND tag(4B len=0) + minorversion(4B)
	// + nops(4B=1) + opcode(4B=36) → clientid(8B=0x10001) + verifier(8B)。
	confirm := ev1[2].Bytes
	off := 4 + 40 // RM + RPC header
	off += 4      // tag (len=0)
	off += 4      // minorversion
	if got := binaryBigEndianU32(confirm[off : off+4]); got != 1 {
		t.Errorf("confirm nops = %d, want 1", got)
	}
	off += 4
	if got := binaryBigEndianU32(confirm[off : off+4]); got != OP_SETCLIENTID_CONFIRM {
		t.Errorf("confirm opcode = %d, want %d", got, OP_SETCLIENTID_CONFIRM)
	}
	off += 4
	if got := binaryBigEndianU64(confirm[off : off+8]); got != 0x10001 {
		t.Errorf("confirm clientid = %d, want 0x10001", got)
	}
}

// TestLayerGen_XIDWrap XID 回绕：XIDBase=0xFFFFFFFF + XIDIncr=1 → 第二 op
// XID=0（legacy nfs_test.go TestNFS3XIDWrap 同款语义）。
func TestLayerGen_XIDWrap(t *testing.T) {
	spec := layerNfsSpec(0, &NFSConfig{Version: 3, XIDBase: 0xFFFFFFFF, XIDIncr: 1,
		Ops: []NFSOp{{Procedure: NFS3ProcNULL}, {Procedure: NFS3ProcNULL}}})
	events := collectEvents(t, spec)
	// v3 auto-insert：MOUNT + NULL + NULL + UMOUNT = 4 op × 2 = 8 事件。
	if len(events) != 8 {
		t.Fatalf("events = %d, want 8 (MOUNT+NULL+NULL+UMOUNT × 2)", len(events))
	}
	// call 的 XID 在 RM 后：TCP 4B record mark + XID 4B。
	if got := binaryBigEndianU32(events[0].Bytes[4:8]); got != 0xFFFFFFFF {
		t.Errorf("call[0] XID = %d, want 0xFFFFFFFF", got)
	}
	if got := binaryBigEndianU32(events[2].Bytes[4:8]); got != 0 {
		t.Errorf("call[2] XID = %d, want 0 (wrap)", got)
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→nfs] 完整链路（握手 3 + 数据 6 + 挥手 4 = 13 包），数据帧与
// legacy 逐字节一致。挥手为 TCPGenerator 标准 4 包（FIN|ACK up → ACK down
// → FIN|ACK down → ACK up，generator.go:893-955）——legacy nfs.go 是 3 包
// 挥手（FIN up → FIN down → ACK up，emitTeardown 1601-1635），层模型意图的
// 文档化分歧（modbus/gbt32960 链测试同款断言形状）。数据帧方向与 legacy
// 一致（up 调用/down 回复）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := layerNfsSpec(1000, &NFSConfig{Version: 3,
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}})
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "nfs"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 1 op（MOUNT + GETATTR + UMOUNT = 3 op）→ 3 op × 2 = 6 数据帧。
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + data 6 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 6 帧；挥手 4 包。
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up",
		"up", "down", "up", "down", "up", "down",
		"up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if pkts[i].L4.Flags != wf {
			t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
		}
		if pkts[i].Direction != wantDir[i] {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
		}
	}
	// 数据帧方向/字节与 legacy 逐帧一致。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 6 {
		t.Fatalf("legacy data frames = %d, want 6", len(legacy))
	}
	for i, l := range legacy {
		seg := pkts[3+i]
		if !bytes.Equal(seg.Payload, l.Payload) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, seg.Payload, l.Payload)
		}
		if seg.Direction != l.Direction {
			t.Errorf("data frame %d direction = %s, legacy = %s", i, seg.Direction, l.Direction)
		}
	}
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 2049）。
	if pkts[4].L4.SrcPort != 2049 || pkts[4].L4.DstPort != 50000 {
		t.Errorf("down data frame ports = %d/%d, want 2049/50000", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性：FIN|ACK(up) pkts[9] 继承最后 up 数据帧（pkts[7] =
	// 第三 op 调用 up）尾部 seq；FIN|ACK(down) pkts[11] 继承最后 down
	// 数据帧（pkts[8] = 第三 op 回复 down）尾部 seq。
	if pkts[9].L4.Seq != pkts[7].L4.Seq+uint32(len(pkts[7].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[9].L4.Seq, pkts[7].L4.Seq+uint32(len(pkts[7].Payload)))
	}
	if pkts[11].L4.Seq != pkts[8].L4.Seq+uint32(len(pkts[8].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[11].L4.Seq, pkts[8].L4.Seq+uint32(len(pkts[8].Payload)))
	}
}

// TestLayerGen_ChainPlannerUDP 链级 UDP 载体：[ip→udp→nfs] 每事件一数据报
// （无握手/挥手），方向端口交换（down 数据报源端口 = DstPort 2049、目的 =
// SrcPort 50000，UDPGenerator 事件模式自动交换——NFS 事件不设
// L4PortOverride）。与 legacy UDP Plan 逐字节一致。
func TestLayerGen_ChainPlannerUDP(t *testing.T) {
	spec := layerNfsSpec(0, &NFSConfig{Version: 3, Transport: "udp",
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}})
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "udp"},
		{Name: "nfs"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// MOUNT + GETATTR + UMOUNT = 3 op × 2 = 6 数据报。
	if len(pkts) != 6 {
		t.Fatalf("got %d packets, want 6 (3 ops × call/reply)", len(pkts))
	}
	wantDir := []string{"up", "down", "up", "down", "up", "down"}
	for i, wd := range wantDir {
		if pkts[i].L4.Protocol != "udp" {
			t.Errorf("packet %d protocol = %q, want udp", i, pkts[i].L4.Protocol)
		}
		if pkts[i].Direction != wd {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wd)
		}
	}
	// down 数据报端口交换（up: 50000→2049；down: 2049→50000）。
	if pkts[0].L4.SrcPort != 50000 || pkts[0].L4.DstPort != 2049 {
		t.Errorf("up datagram ports = %d/%d, want 50000/2049", pkts[0].L4.SrcPort, pkts[0].L4.DstPort)
	}
	if pkts[1].L4.SrcPort != 2049 || pkts[1].L4.DstPort != 50000 {
		t.Errorf("down datagram ports = %d/%d, want 2049/50000", pkts[1].L4.SrcPort, pkts[1].L4.DstPort)
	}
	// 字节级与 legacy UDP 一致（无 RM 前缀，XID 在 offset 0）。
	legacy := legacyUDPDatagrams(t, spec)
	if len(legacy) != 6 {
		t.Fatalf("legacy udp datagrams = %d, want 6", len(legacy))
	}
	for i, l := range legacy {
		if !bytes.Equal(pkts[i].Payload, l.Payload) {
			t.Errorf("datagram %d payload = % X, legacy = % X", i, pkts[i].Payload, l.Payload)
		}
	}
	if got := binaryBigEndianU32(pkts[0].Payload[0:4]); got != 1 {
		t.Errorf("udp call XID = %d, want 1 (no RM, XID at offset 0)", got)
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 2049（validateSpecBase nfs 分支，legacy Plan 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := layerNfsSpec(1000, &NFSConfig{Version: 3,
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}})
	spec.DstPort = 0
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "nfs"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.DstPort != 2049 {
		t.Errorf("SYN dst_port = %d, want 2049 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_ChainPlannerSrcPortZero 源端口 0 保持 0：validateSpecBase 对
// nfs 分支不默认化 srcPort（legacy 单流用 spec.SrcPort 原值，0 也上包）。
func TestLayerGen_ChainPlannerSrcPortZero(t *testing.T) {
	spec := layerNfsSpec(1000, &NFSConfig{Version: 3,
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}})
	spec.SrcPort = 0
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "nfs"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.SrcPort != 0 {
		t.Errorf("SYN src_port = %d, want 0 (kept)", pkts[0].L4.SrcPort)
	}
}

// TestLayerGen_ChainRejectsTransportMismatch 载体一致性结构性校验
// （chain_planner.go ValidateSpec nfsTransportFromMetadata）：
//   - tcp 载体 + transport "udp" → 拒绝
//   - udp 载体 + transport ""（空，legacy 默认 "tcp"）→ 拒绝
//   - udp 载体 + transport "tcp" → 拒绝
//   - udp 载体 + transport "udp" → 通过（TestLayerGen_ChainPlannerUDP）
func TestLayerGen_ChainRejectsTransportMismatch(t *testing.T) {
	cases := []struct {
		name      string
		carrier   string
		transport string
		wantErr   string
	}{
		{"tcp carrier + udp transport", "tcp", "udp", `nfs transport "udp" requires a udp carrier`},
		{"udp carrier + empty transport", "udp", "", "udp carrier requires nfs transport"},
		{"udp carrier + tcp transport", "udp", "tcp", "udp carrier requires nfs transport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &NFSConfig{Version: 3, Transport: tc.transport,
				Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
			spec := layerNfsSpec(0, cfg)
			planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
				{Name: "ip"},
				{Name: tc.carrier},
				{Name: "nfs"},
			})
			_, err := planner.Plan(context.Background(), spec)
			if err == nil {
				t.Fatal("Plan with mismatched transport returned nil, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Plan error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLayerGen_MultiStreamRejected 多流展开拒绝（enip/modbus 同款纪律）：
// Sessions>1 生成器级显式报错（0 事件，包数缩水的静默单流是禁止语义）；
// 链级经 validator 在 Plan 期同步拒绝。
func TestLayerGen_MultiStreamRejected(t *testing.T) {
	cfg := &NFSConfig{Version: 3, Sessions: 2,
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
	// 生成器级：显式错误 + 0 事件。
	gen := &NFSGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NFS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	err := gen.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "not supported on a layer chain") {
		t.Fatalf("Generate error = %v, want multi-stream rejection", err)
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on multi-stream config, want 0", len(events))
	}
	// 链级：validator 同步拒绝（Plan 报错，非空流）。
	spec := layerNfsSpec(0, cfg)
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "nfs"},
	})
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Fatal("ChainPlanner Plan with sessions>1 returned nil, want error")
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发）。覆盖 legacy Validate 检查：
// version 非法、ops 为空、v4+udp。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("nfs", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "nfs"},
	})
	// version=5 非法（V1）。
	spec := layerNfsSpec(0, &NFSConfig{Version: 5, Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}})
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "version must be 3 or 4") {
		t.Fatalf("Plan with version=5 error = %v, want version must be 3 or 4", err)
	}
	// ops 为空（V4）。
	spec = layerNfsSpec(0, &NFSConfig{Version: 3, Ops: []NFSOp{}})
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "ops must not be empty") {
		t.Fatalf("Plan with empty ops error = %v, want ops must not be empty", err)
	}
	// v4+udp（V3，validator 先于结构性校验触发）。
	spec = layerNfsSpec(0, &NFSConfig{Version: 4, Transport: "udp",
		Ops: []NFSOp{{Procedure: NFS4ProcCOMPOUND, CompoundOps: []NFSv4CompoundOp{{Opcode: OP_PUTROOTFH}}}}})
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "NFSv4 requires TCP") {
		t.Fatalf("Plan with v4+udp error = %v, want NFSv4 requires TCP", err)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &NFSGenerator{}
	cfg := &NFSConfig{Version: 3, Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
	req := &layers.GenRequest{Meta: layers.FlowMeta{NFS: cfg}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 NFS 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &NFSGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with no config returned nil, want error")
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on invalid config, want 0", len(events))
	}
}

// TestLayerGen_ConfigFromMap 配置经 map 形态（strategy_convert mapToFlowSpec
// 的 nfs case 产物）到达生成器：JSON 解码子 map → nfsConfigFromJSONMap 往返
// 解析，事件字节与 *NFSConfig 直传形态一致。
func TestLayerGen_ConfigFromMap(t *testing.T) {
	cfg := &NFSConfig{Version: 3,
		Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
	spec := layerNfsSpec(0, cfg)
	// 模拟 strategy_convert：Metadata["nfs"] 为 JSON 解码子 map。
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	spec.Metadata[MetadataKey] = m

	var events []layers.MessageEvent
	gen := &NFSGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NFS: spec.Metadata[MetadataKey]},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate with map config: %v", err)
	}
	// 与 *NFSConfig 直传形态逐字节一致。
	direct := collectEvents(t, layerNfsSpec(0, cfg))
	if len(events) != len(direct) {
		t.Fatalf("map events = %d, direct events = %d", len(events), len(direct))
	}
	for i := range events {
		if !bytes.Equal(events[i].Bytes, direct[i].Bytes) || events[i].Up != direct[i].Up {
			t.Errorf("event[%d] map vs direct mismatch", i)
		}
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &NFSGenerator{}
	sentinel := errors.New("emit failed")
	cfg := &NFSConfig{Version: 3, Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NFS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：默认 v3 配置
// 产 8 事件（MOUNT/GETATTR/UMOUNT 3 op × call+reply），第 2 个事件后取消 →
// 返回 context 错误且只发出 2 事件。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &NFSGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	cfg := &NFSConfig{Version: 3, Ops: []NFSOp{{Procedure: NFS3ProcGETATTR}}}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NFS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（首个 op 的 call+reply 完成，第 2 op 前）
				cancel()
				cancelled = true
			}
			return nil
		},
	}
	err := gen.Generate(ctx, req)
	if !cancelled {
		t.Fatal("test did not reach cancel point")
	}
	if err == nil {
		t.Fatal("Generate after cancel returned nil, want context error")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want exactly 2 (cancelled mid-sequence)", len(events))
	}
}
