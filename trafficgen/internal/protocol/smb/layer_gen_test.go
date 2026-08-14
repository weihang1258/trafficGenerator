package smb

// SMB terminal-layer generator tests (P4a)。SMBGenerator 复用 build* 纯
// 函数产事件——事件序列与 legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/
// 挥手过滤后）在方向/字节上逐帧一致（NEGOTIATE → SESSION_SETUP ×N →
// TREE_CONNECT → CREATE → Operations → CLOSE → TREE_DISCONNECT → LOGOFF，
// Include* 门控与 ErrorOnCommand 错误注入语义同款）；链级测试通过
// ChainPlanner 驱动 [ip→tcp→smb] 完整链路验证握手→数据→挥手与 legacy
// 数据帧字节一致、seq 连续。
//
// 字节对比的共享状态掩码（mqtt autoClientID / modbus SharedTIDSpace 同款
// 先例——共享计数器/时间源字段不做逐字节对比）：
//   - SessionId：legacy 经包级原子 nextSessionID() 分配（smb.go:63-66），
//     事件生成与 legacy 对比各消耗一个计数值 → 掩码 SMB2 头偏移 40-47
//     （SessionId 字段）及 TRANSFORM_HEADER 的 SessionId（偏移 44-51）。
//   - 盐字节：fakeSalt 用 time.Now().UnixNano()（builder.go:101-111），
//     NEGOTIATE 请求的 Preauth 上下文盐区不可复现 → 掩码
//     PreauthIntegrityHashAlgorithms 上下文数据区（legacy 相同掩码函数）。
//   - ClientGuid/ServerGuid/FileId：applyDefaults 对零值随机化 → 所有对比
//     spec 显式设置确定性值（确定性即复现，无需掩码）。
//
// 另：READ 响应的 4096B 数据在 legacy 侧按 MSS 1460 分段为 3 个数据帧，
// 链上 tcp 层亦分段——同侧连续数据帧须重组为一条完整消息再对比（READ 响应
// 断言 DataLength 字段与数据长度）；其余 PDU 均 < MSS 单帧。

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// pduSessionIDMask masks the SessionId field (SMB2 header offset 40-47),
// the TRANSFORM_HEADER SessionId (offset 44-51), and the Signature
// placeholder region (SMB2 header offset 48-63; buildSMB2Header 写
// messageID^sessionID，跨运行不可复现) of a PDU。共享原子计数器的字段跨
// 运行不可复现（事件生成与 legacy 对比各消耗一个 nextSessionID 值）。
// 未签名 PDU 的签名区恒 0——无条件掩码安全。
func pduSessionIDMask(p []byte) []byte {
	out := append([]byte(nil), p...)
	if len(out) < 4 {
		return out
	}
	switch {
	case len(out) >= 4+48 && out[4] == 0xFD && out[5] == 0x53 && out[6] == 0x4D && out[7] == 0x42:
		// TRANSFORM_HEADER (52B) 包裹的 SMB2 PDU：th.SessionId 偏移 44-51，
		// 内层 SMB2 头从偏移 52 起：SessionId 偏移 52+40-47 = 92-99，
		// Signature 区 52+48-63 = 100-115。
		for _, r := range [][2]int{{44, 52}, {92, 100}, {100, 116}} {
			for i := r[0]; i < r[1] && i < len(out); i++ {
				out[i] = 0
			}
		}
	case len(out) >= 4+48 && out[4] == 0xFE && out[5] == 0x53 && out[6] == 0x4D && out[7] == 0x42:
		for i := 44; i < 52; i++ {
			out[i] = 0
		}
		for i := 52; i < 68; i++ {
			out[i] = 0
		}
	}
	return out
}

// maskSalt masks the fakeSalt bytes in a NEGOTIATE request Preauth context
// (time.Now().UnixNano() 时间源，跨运行不可复现)。SMB2 头 64B + 请求体：
// 固定 36B + dialects 2B×N + 8B 对齐 pad，之后是 context 列表；Preauth
// context 的 data 区（含 32B 盐）在 context 头 8B 之后。dialect 列表长度
// 由请求体偏移 2-3 的 DialectCount 字段决定（legacy 与生成器同款布局）。
// 仅 NEGOTIATE 请求（Command=0）且含 Preauth 上下文时执行掩码。
func maskSalt(p []byte) []byte {
	out := append([]byte(nil), p...)
	if len(out) < 4+64 || out[4] != 0xFE || out[5] != 0x53 || out[6] != 0x4D || out[7] != 0x42 {
		return out
	}
	if cmd := binary.LittleEndian.Uint16(out[4+12 : 4+14]); cmd != 0 { // NEGOTIATE
		return out
	}
	body := out[4+64:]
	if len(body) < 36 {
		return out
	}
	dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
	ctxCount := int(binary.LittleEndian.Uint16(body[32:34]))
	if ctxCount == 0 {
		return out
	}
	off := 36 + dialectCount*2
	// 请求体对齐 8B（buildNegotiateRequestBody:198-202 同款 pad）。
	off += (8 - off%8) % 8
	if off+8 > len(body) {
		return out
	}
	for c := 0; c < ctxCount; c++ {
		if off+8 > len(body) {
			break
		}
		ctxType := binary.LittleEndian.Uint16(body[off : off+2])
		ctxLen := int(binary.LittleEndian.Uint16(body[off+2 : off+4]))
		ctxData := off + 8
		if ctxType == 1 { // PreauthIntegrityHashAlgorithms: data 区含 32B 盐
			for i := ctxData; i < ctxData+ctxLen && i < len(body); i++ {
				out[4+64+i] = 0
			}
		}
		off = ctxData + ctxLen
		// 每个 context 8B 对齐（buildPreauthContext/buildEncryptionContext
		// 各自对齐，后续 ctx 从对齐处开始）。
		off += (8 - off%8) % 8
	}
	return out
}

// legacyDataFrames runs the legacy planner and returns the SMB data frames
// (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK（emitSMB2PDU →
// emitPayloadMSS 恒 0x18），与事件一一对应（READ 4096B 响应按 MSS 分段，
// 同侧连续帧重组后与事件对比——assertEventsMatchLegacy 的 readAssemble
// 模式）。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	spec2 := spec
	if spec.SMB != nil {
		c2 := *spec.SMB
		spec2.SMB = &c2
	}
	var out []core.PacketConfig
	for _, c := range mustPlan(t, &Planner{}, spec2) {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 {
			out = append(out, c)
		}
	}
	return out
}

// mustPlan runs the legacy planner and returns all PacketConfigs in order.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
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

// smbSpec returns a base SMB spec with deterministic GUIDs/FileId (随机化
// 字段显式设置——确定性即复现，字节对比无需掩码)、确定性 ISN (initialSeq)
// 与覆盖各阶段命令的完整配置。值拷贝 cfg：事件生成与 legacy 对比各持独立
// 实例（applyDefaults 不改原值）。
func smbSpec(initialSeq uint32) core.FlowSpec {
	guid := func(b byte) [16]byte {
		var g [16]byte
		for i := range g {
			g[i] = b
		}
		return g
	}
	cfg := &core.SMBConfig{
		Transport:                      "direct",
		Dialects:                       []string{"0x0202", "0x0210", "0x0300", "0x0302", "0x0311"},
		SelectedDialect:                "0x0311",
		ClientGuid:                     guid(0x11),
		ServerGuid:                     guid(0x22),
		FileId:                         guid(0x33),
		AuthMechanism:                  "ntlm",
		AuthRounds:                     3,
		TreeConnectShare:               "\\\\server\\share",
		FilePath:                       "layer-gen.txt",
		CreateDisposition:              1,
		AccessMask:                     0x00120089,
		FileAttributes:                 0x80,
		ShareAccess:                    0x07,
		PreauthIntegrityHashAlgorithms: []uint16{0x0001},
		EncryptionAlgorithm:            0x0001,
		MaxTransactSize:                65536,
		MaxReadSize:                    1048576,
		MaxWriteSize:                   1048576,
		Operations: []core.SMBOperation{
			{OpType: "read", Offset: 0, Length: 4096},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 49152,
		DstPort: 445,
		SrcMAC:  "00:11:22:33:44:55",
		DstMAC:  "66:77:88:99:aa:bb",
		TTL:     64,
		SMB:     cfg,
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// collectEvents drives SMBGenerator.Generate and collects the emitted message
// events in order。值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &SMBGenerator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	if spec.SMB != nil {
		c2 := *spec.SMB
		meta.SMB = &c2
	}
	req := &layers.GenRequest{
		Meta: meta,
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

// assertEventsMatchLegacy 逐事件断言方向与字节与 legacy 数据帧一致。
// maskSID: 掩码 SessionId 与签名占位区（SMB2 头 40-47/48-63 与 TRANSFORM_HEADER
// 44-51/内层同区——共享原子计数器与 messageID/sessionID 异或占位跨运行不可
// 复现）——默认 true；断言场景无需 SessionId 内容时关闭以保留全部字段的
// 严格对比。
// readAssemble: READ 响应（4096B 数据按 MSS 1460 分 3 段）legacy 侧多帧、
// 事件侧单帧——同侧连续数据帧重组为一条消息再对比。
func assertEventsMatchLegacy(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent, maskSID, readAssemble bool) {
	t.Helper()
	legacy := legacyDataFrames(t, spec)
	if readAssemble {
		legacy = assembleReadResponses(legacy)
	}
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy data frames = %d (maskSID=%v readAssemble=%v)", len(events), len(legacy), maskSID, readAssemble)
	}
	for i, ev := range events {
		pc := legacy[i]
		if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
		}
		evBytes := maskSalt(ev.Bytes)
		legacyBytes := maskSalt(pc.Payload)
		if maskSID {
			evBytes = pduSessionIDMask(evBytes)
			legacyBytes = pduSessionIDMask(legacyBytes)
		}
		if !bytes.Equal(evBytes, legacyBytes) {
			t.Errorf("event[%d] (up=%v) payload:\n  gen  = % X\n  legacy= % X", i, ev.Up, evBytes, legacyBytes)
		}
	}
}

// assembleReadResponses 将 legacy 侧同向连续数据帧重组为消息列表：除 READ
// 响应（4096B 数据按 MSS 1460 分 3 段）外，其余 PDU 单帧即一条消息。
// 重组规则 = 帧方向与首帧相同且帧头是 SMB2/NBSS（长度域与 SMB2 消息一致）
// 的后续帧为分段延续。事件侧恒单事件 = 完整 PDU（链上 tcp 层负责分段），
// 故 legacy 侧同向连续帧合并后与事件一一对应。
func assembleReadResponses(frames []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for i := 0; i < len(frames); {
		pc := frames[i]
		j := i + 1
		// NBSS 长度域（帧 1-3 字节大端）声明完整消息长度；后续同向帧是
		// 该消息的 MSS 分段（如 READ 响应 64+16+4096+4 > 1460）。
		msgLen := 0
		if len(pc.Payload) >= 4 && pc.Payload[0] == 0x00 {
			msgLen = int(pc.Payload[1])<<16 | int(pc.Payload[2])<<8 | int(pc.Payload[3])
		}
		for j < len(frames) && frames[j].Direction == pc.Direction {
			// 同向后续帧若自身是完整消息（NBSS 长度域与自身 payload 一致
			// 或长度域匹配其消息），则不是分段——停止合并。
			pj := frames[j].Payload
			if len(pj) >= 4 && pj[0] == 0x00 {
				selfLen := int(pj[1])<<16 | int(pj[2])<<8 | int(pj[3])
				if selfLen == len(pj)-4 && msgLen == 0 {
					break
				}
			}
			if msgLen > 0 && len(pc.Payload)-4 >= msgLen {
				break
			}
			pc.Payload = append(append([]byte(nil), pc.Payload...), pj...)
			j++
		}
		out = append(out, pc)
		i = j
	}
	return out
}

// smbCmd extracts the SMB2 Command from a PDU/event (NBSS 4B + SMB2 头
// 偏移 12-13；TRANSFORM_HEADER 包裹时跳过 52B 外层头)。
func smbCmd(p []byte) uint16 {
	off := 0
	if len(p) >= 4 && p[0] == 0x00 {
		off = 4
	}
	if len(p) >= off+14 && p[off] == 0xFD && p[off+1] == 0x53 && p[off+2] == 0x4D && p[off+3] == 0x42 {
		off += 52
	}
	if len(p) < off+14 {
		return 0xFFFF
	}
	return binary.LittleEndian.Uint16(p[off+12 : off+14])
}

// smbStatus extracts the SMB2 Status from a PDU/event (偏移 8-11)。
func smbStatus(p []byte) uint32 {
	off := 0
	if len(p) >= 4 && p[0] == 0x00 {
		off = 4
	}
	if len(p) >= off+12 && p[off] == 0xFD && p[off+1] == 0x53 && p[off+2] == 0x4D && p[off+3] == 0x42 {
		off += 52
	}
	if len(p) < off+12 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(p[off+8 : off+12])
}

// eventCmds returns the Command of every event (用于序列形状断言)。
func eventCmds(events []layers.MessageEvent) []uint16 {
	out := make([]uint16, len(events))
	for i, ev := range events {
		out[i] = smbCmd(ev.Bytes)
	}
	return out
}

// mustChainPlan drives [ip→tcp→smb] and returns all packets.
func mustChainPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	planner := layers.NewChainPlannerFromChain("smb", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "smb"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	return pkts
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy 数据帧在
// 方向/payload 上逐帧一致。覆盖核心场景矩阵：默认化配置、显式 transport=
// netbios（wire 字节不变，仅端口语义不同）、ErrorOnCommand 各阶段错误注入、
// 多操作序列（read/write/close/query_directory/query_info/lock/ioctl/echo/
// flush）、Include* 门控关闭。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	guid := func(b byte) [16]byte {
		var g [16]byte
		for i := range g {
			g[i] = b
		}
		return g
	}
	mkOp := func(opType string, mutate func(*core.SMBOperation)) core.SMBOperation {
		op := core.SMBOperation{OpType: opType}
		if mutate != nil {
			mutate(&op)
		}
		return op
	}
	cases := []struct {
		name         string
		cfg          *core.SMBConfig
		maskSID      bool
		readAssemble bool
	}{
		// 默认化路径：SMBConfig{}（Dialects 全量默认、ntlm/3 轮、
		// TreeConnectShare 默认 UNC、默认 ops [{read 4096}]）——ClientGuid/
		// ServerGuid/FileId 零值被 applyDefaults 随机化，须显式设置才能
		// 字节对比（确定性即复现）。READ 响应 4096B 按 MSS 1460 分 3 段。
		{"default config (ntlm 3 rounds, read 4096)", &core.SMBConfig{
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 显式 transport=netbios：wire 字节与 direct 一致（NBSS 前缀恒在），
		// 仅目的端口语义不同（validateSpecBase → 139，链级测试覆盖）。
		{"explicit transport netbios", &core.SMBConfig{
			Transport:  "netbios",
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 显式 dialects 短列表（SMB2.002 仅 2 方言：dialect 列表字节、
		// creditCharge=0、无 Preauth 盐上下文——覆盖 buildNegotiateRequestBody
		// 的 dialect 区布局与 masking 逻辑的不同长度路径）。
		{"short dialects smb2.002", &core.SMBConfig{
			Dialects: []string{"0x0202", "0x0210"}, SelectedDialect: "0x0210",
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// kerberos 认证（2 轮，非末轮响应无 Challenge blob）。
		{"kerberos auth 2 rounds", &core.SMBConfig{
			AuthMechanism: "kerberos", AuthRounds: 2,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 显式 2 轮 NTLM（末轮即第 2 轮，Challenge 在第 1 轮响应）。
		{"ntlm 2 rounds", &core.SMBConfig{
			AuthMechanism: "ntlm", AuthRounds: 2,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 匿名认证（1 轮）。
		{"anonymous auth 1 round", &core.SMBConfig{
			AuthMechanism: "anonymous", AuthRounds: 1,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// SigningRequired（FlagSigned + Signature 占位字节——签名区与
		// messageID/sessionID 相关，SessionId 掩码后签名区确定性）。
		{"signing required", &core.SMBConfig{
			SigningRequired: true,
			ClientGuid:      guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 无签名：signFlags 恒 0（覆盖 smbFlags 无签名分支）。
		{"no signing", &core.SMBConfig{
			SigningRequired: false,
			ClientGuid:      guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// ErrorOnCommand 各阶段（错误响应 + 阶段跳过规则逐命令对比）。
		{"error negotiate", &core.SMBConfig{
			ErrorOnCommand: "negotiate", ErrorResponseStatus: StatusInvalidParameter,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		{"error session_setup", &core.SMBConfig{
			ErrorOnCommand: "session_setup", ErrorResponseStatus: StatusAccessDenied,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		{"error tree_connect", &core.SMBConfig{
			ErrorOnCommand: "tree_connect", ErrorResponseStatus: StatusObjectNameNotFound,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		{"error create", &core.SMBConfig{
			ErrorOnCommand: "create", ErrorResponseStatus: StatusObjectNameNotFound,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		{"error read", &core.SMBConfig{
			ErrorOnCommand: "read", ErrorResponseStatus: StatusInvalidParameter,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		{"error write", &core.SMBConfig{
			ErrorOnCommand: "write", ErrorResponseStatus: StatusAccessDenied,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		{"error close", &core.SMBConfig{
			ErrorOnCommand: "close", ErrorResponseStatus: StatusInvalidParameter,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		{"error tree_disconnect", &core.SMBConfig{
			ErrorOnCommand: "tree_disconnect", ErrorResponseStatus: StatusAccessDenied,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		{"error logoff", &core.SMBConfig{
			ErrorOnCommand: "logoff", ErrorResponseStatus: StatusInvalidParameter,
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 多操作序列：全命令混合（read 4096/write 数据/close/query_directory/
		// query_info/lock/ioctl/echo/flush 顺序执行 + 末 CLOSE 拆解）。
		{"multi-op all commands", &core.SMBConfig{
			Operations: []core.SMBOperation{
				mkOp("read", nil),
				mkOp("write", func(o *core.SMBOperation) { o.Offset = 100; o.Data = []byte("hello smb write") }),
				mkOp("query_directory", nil),
				mkOp("query_info", nil),
				mkOp("lock", func(o *core.SMBOperation) { o.Offset = 0; o.Length = 4096 }),
				mkOp("ioctl", nil),
				mkOp("echo", nil),
				mkOp("flush", nil),
			},
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// 显式 close 操作（拆解时不再补 CLOSE——closeAlreadyEmitted 语义）。
		{"explicit close op", &core.SMBConfig{
			Operations: []core.SMBOperation{
				mkOp("read", nil),
				mkOp("close", nil),
			},
			ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// ops 错误后 close 拆解保留（read 错误 → break → 补 CLOSE 拆解）。
		{"read error keeps close teardown", &core.SMBConfig{
			Operations: []core.SMBOperation{
				mkOp("read", nil),
				mkOp("write", func(o *core.SMBOperation) { o.Data = []byte("never reached") }),
			},
			ErrorOnCommand:      "read",
			ErrorResponseStatus: StatusInvalidParameter,
			ClientGuid:          guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, false},
		// Include* 门控全部关闭：仅 LOGOFF 拆解对（无握手/挥手——TCP 层负责）。
		// 默认 ops [{read 4096}] 正常执行（未开错误注入）→ READ 响应 3 段。
		{"include flags all off", &core.SMBConfig{
			IncludeNegotiate:   boolPtrOf(false),
			IncludeAuth:        boolPtrOf(false),
			IncludeTreeConnect: boolPtrOf(false),
			IncludeTeardown:    boolPtrOf(false),
			ClientGuid:         guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// IncludeAuth 关闭：无 SESSION_SETUP，但 TREE_CONNECT/CREATE/ops/
		// 拆解正常（authErrored 恒 false）。
		{"include auth off", &core.SMBConfig{
			IncludeAuth: boolPtrOf(false),
			ClientGuid:  guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// IncludeTreeConnect 关闭：无 TREE_CONNECT（treeErrored 恒 false）。
		{"include tree connect off", &core.SMBConfig{
			IncludeTreeConnect: boolPtrOf(false),
			ClientGuid:         guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// IncludeTeardown 关闭：无 TREE_DISCONNECT/LOGOFF。
		{"include teardown off", &core.SMBConfig{
			IncludeTeardown: boolPtrOf(false),
			ClientGuid:      guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
		// EncryptionRequired（dialect 0x0311 > 0x0300）：认证后 PDU 全部
		// TRANSFORM_HEADER 包裹（S14 语义；掩码 transform 与内层 SessionId）。
		{"encryption required transform headers", &core.SMBConfig{
			EncryptionRequired: true,
			ClientGuid:         guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33),
		}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := smbSpec(0)
			c2 := *tc.cfg
			spec.SMB = &c2
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events, tc.maskSID, tc.readAssemble)
		})
	}
}

// TestLayerGen_EventSequenceShape 独立校验事件序列形状（不依赖 legacy 对比）：
// 默认配置（ntlm 3 轮 + read 4096）的命令/方向序列 = NEGOTIATE up/down ×1、
// SESSION_SETUP up/down ×3、TREE_CONNECT up/down ×1、CREATE up/down ×1、
// READ up/down ×1、CLOSE up/down ×1、TREE_DISCONNECT up/down ×1、LOGOFF
// up/down ×1 = 9 对 18 事件；MessageId 从 0 起、每响应后递增（事件序号 ×2
// 对应对内 MessageId）。
func TestLayerGen_EventSequenceShape(t *testing.T) {
	spec := smbSpec(0)
	events := collectEvents(t, spec)
	wantCmds := []uint16{
		CmdNegotiate, CmdNegotiate,
		CmdSessionSetup, CmdSessionSetup, CmdSessionSetup, CmdSessionSetup,
		CmdSessionSetup, CmdSessionSetup,
		CmdTreeConnect, CmdTreeConnect,
		CmdCreate, CmdCreate,
		CmdRead, CmdRead,
		CmdClose, CmdClose,
		CmdTreeDisconnect, CmdTreeDisconnect,
		CmdLogoff, CmdLogoff,
	}
	if len(events) != len(wantCmds) {
		t.Fatalf("events = %d, want %d (%v)", len(events), len(wantCmds), eventCmds(events))
	}
	for i, want := range wantCmds {
		if events[i].Up != (i%2 == 0) {
			t.Errorf("event[%d] Up=%v, want %v (request/response 交替)", i, events[i].Up, i%2 == 0)
		}
		if got := smbCmd(events[i].Bytes); got != want {
			t.Errorf("event[%d] command = 0x%04x, want 0x%04x", i, got, want)
		}
	}
	// MessageId 语义（BUG #5 修复）：request/response 共用同一 MessageId，
	// response 后递增——第 i 对事件的 MessageId = i。SMB2 头偏移 24-31。
	for i := 0; i < len(events); i += 2 {
		req := events[i].Bytes
		resp := events[i+1].Bytes
		wantID := uint64(i / 2)
		if got := binary.LittleEndian.Uint64(req[4+24 : 4+32]); got != wantID {
			t.Errorf("pair %d request MessageId = %d, want %d", i/2, got, wantID)
		}
		if got := binary.LittleEndian.Uint64(resp[4+24 : 4+32]); got != wantID {
			t.Errorf("pair %d response MessageId = %d, want %d (same as request)", i/2, got, wantID)
		}
	}
}

// TestLayerGen_ErrorNegotiateShape 错误注入序列形状（不依赖 legacy 对比）：
// negotiate 错误 → 仅 NEGOTIATE 对（错误响应）+ 无任何拆解；响应 Status =
// ErrorResponseStatus。错误响应体 = buildNegotiateErrorResponseBody（64B
// 固定部，StructureSize 65）。
func TestLayerGen_ErrorNegotiateShape(t *testing.T) {
	spec := smbSpec(0)
	spec.SMB.ErrorOnCommand = "negotiate"
	spec.SMB.ErrorResponseStatus = StatusInvalidParameter
	events := collectEvents(t, spec)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 (negotiate pair only)", len(events))
	}
	if !events[0].Up || events[1].Up {
		t.Errorf("directions = %v/%v, want up/down", events[0].Up, events[1].Up)
	}
	if got := smbStatus(events[1].Bytes); got != StatusInvalidParameter {
		t.Errorf("response status = 0x%08x, want 0x%08x", got, StatusInvalidParameter)
	}
	if got := smbCmd(events[1].Bytes); got != CmdNegotiate {
		t.Errorf("response command = 0x%04x, want NEGOTIATE", got)
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→smb] 完整链路，数据帧与 legacy 逐字节一致。挥手为 TCPGenerator
// 标准 4 包（FIN|ACK up → ACK down → FIN|ACK down → ACK up）——legacy
// smb.go 是 3 包挥手（FIN up → FIN down → ACK up，smb.go:310-317），层模型
// 意图的文档化分歧（modbus/dnp3/doip 链测试同款断言形状）。READ 4096B
// 数据在链上由 tcp 层按 MSS 1460 分段（同 legacy）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := smbSpec(1000) // 确定性 ISN
	// 默认配置包序列：握手 3 + 数据帧 22（10 对 PDU，READ 4096B 响应按 MSS
	// 1460 分 3 段 → 1 对 4 帧；NEGO/SS 3 轮/TC/CREATE/READ/CLOSE/TD/LOGOFF
	// 共 9 对单帧 + 1 对 4 帧 = 22）+ 挥手 4 = 29。legacy = 3 + 22 + 3 = 28
	// （legacy 3 包挥手，链上 4 包）。
	pkts := mustChainPlan(t, spec)
	if len(pkts) != 29 {
		t.Fatalf("got %d packets, want 29 (handshake 3 + data 22 + teardown 4)", len(pkts))
	}
	wantFlags := []uint8{0x02, 0x12, 0x10,
		0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
		0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up",
		"up", "down", "up", "down", "up", "down", "up", "down", "up", "down", "up", "down", "up", "down", "down", "down", "up", "down", "up", "down", "up", "down",
		"up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if i < len(pkts) {
			if pkts[i].L4.Flags != wf {
				t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
			}
			if pkts[i].Direction != wantDir[i] {
				t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
			}
		}
	}
	// 数据帧与 legacy 逐帧一致（READ 响应 3 段在同一方向上，legacy 同款
	// 分段形状）。方向断言覆盖"交换方向/错位包序"的静默错误。SessionId/
	// Signature 占位（共享原子计数器）与 NEGOTIATE 盐（时间源）跨运行不可
	// 复现：两侧同掩码（pduSessionIDMask + maskSalt，与
	// assertEventsMatchLegacy 同款策略）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 22 {
		t.Fatalf("legacy data frames = %d, want 22", len(legacy))
	}
	for i, l := range legacy {
		evBytes := maskSalt(pduSessionIDMask(pkts[3+i].Payload))
		legacyBytes := maskSalt(pduSessionIDMask(l.Payload))
		if !bytes.Equal(evBytes, legacyBytes) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, evBytes, legacyBytes)
		}
		if pkts[3+i].Direction != l.Direction {
			t.Errorf("data frame %d direction = %s, legacy = %s", i, pkts[3+i].Direction, l.Direction)
		}
	}
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 445）。
	if pkts[4].L4.SrcPort != 445 || pkts[4].L4.DstPort != 49152 {
		t.Errorf("down data frame ports = %d/%d, want 445/49152", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// READ 响应 3 段的 NBSS 长度域一致性（每段 carry 完整 PDU 的 NBSS 长度
	// ——链上 tcp 层把事件整体分段，非逐段重打包）：
	// 第 1 段 NBSS = 64+16+4096 = 4176，第 2/3 段同值；第 1 段数据偏移 4 起。
	// 事件对索引：READ req = pkts[15]，READ resp 3 段 = pkts[16..18]。
	readResp := pkts[16]
	if len(readResp.Payload) != 1460 {
		t.Errorf("READ resp seg1 len = %d, want 1460 (MSS)", len(readResp.Payload))
	}
	wantNBSS := 4176 // 64B SMB2 头 + 16B READ 响应头 + 4096B 数据
	if got := int(readResp.Payload[1])<<16 | int(readResp.Payload[2])<<8 | int(readResp.Payload[3]); got != wantNBSS {
		t.Errorf("READ resp seg1 NBSS = %d, want %d", got, wantNBSS)
	}
	// 挥手 seq 连续性（seq 只按同侧负载推进——up 侧只累加 up 帧长度）：
	// FIN|ACK(up) pkts[25] 继承最后 up 数据帧（pkts[23] = LOGOFF up，len=72）
	// 尾部 seq（2112+72=2184）；FIN|ACK(down) pkts[27] 继承最后 down 数据帧
	// （pkts[24] = LOGOFF down，len=72）尾部 seq。
	if pkts[25].L4.Seq != pkts[23].L4.Seq+uint32(len(pkts[23].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[25].L4.Seq, pkts[23].L4.Seq+uint32(len(pkts[23].Payload)))
	}
	if pkts[27].L4.Seq != pkts[24].L4.Seq+uint32(len(pkts[24].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[27].L4.Seq, pkts[24].L4.Seq+uint32(len(pkts[24].Payload)))
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 445（validateSpecBase smb 分支，strategy_convert 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := smbSpec(1000)
	spec.DstPort = 0
	pkts := mustChainPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.DstPort != 445 {
		t.Errorf("SYN dst_port = %d, want 445 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_ChainPlannerNetbiosPort transport=netbios → 目的端口 139
// （strategy_convert.go mapToFlowSpec smb case 同款）。
func TestLayerGen_ChainPlannerNetbiosPort(t *testing.T) {
	spec := smbSpec(1000)
	spec.DstPort = 0
	spec.SMB.Transport = "netbios"
	pkts := mustChainPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.DstPort != 139 {
		t.Errorf("SYN dst_port = %d, want 139 (netbios)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_ChainPlannerSrcPortZero 源端口 0 保持 0（validateSpecBase smb
// 分支不默认化，legacy emitTCPPacket 原值上包同款）。
func TestLayerGen_ChainPlannerSrcPortZero(t *testing.T) {
	spec := smbSpec(1000)
	spec.SrcPort = 0
	pkts := mustChainPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.SrcPort != 0 {
		t.Errorf("SYN src_port = %d, want 0 (kept)", pkts[0].L4.SrcPort)
	}
}

// TestLayerGen_ChainPlannerTeardownNotRun IncludeTeardown=false → 链上无挥手
// （数据帧后直接结束）。legacy 恒 3 包挥手无开关——链上 tcp 层 schema 的
// termination 默认 true 由 validator 强制，IncludeTeardown 只控制 SMB 拆解
// PDU（TREE_DISCONNECT/LOGOFF），TCP 挥手仍由 tcp 层执行（与 legacy 恒
// 挥手语义一致）。
func TestLayerGen_ChainPlannerTeardownNotRun(t *testing.T) {
	spec := smbSpec(1000)
	spec.SMB.IncludeTeardown = boolPtrOf(false)
	pkts := mustChainPlan(t, spec)
	// 3 握手 + 18 数据 + 挥手 4 = 25。数据帧 = NEGO/SS 3 轮/TC/CREATE/READ/
	// CLOSE 共 8 对（READ 响应按 MSS 分 3 段 → READ 对 4 帧；7 对单帧 + 4 =
	// 18；无 TREE_DISCONNECT/LOGOFF）。
	if len(pkts) != 3+18+4 {
		t.Fatalf("got %d packets, want %d (handshake 3 + data 18 + teardown 4)", len(pkts), 3+18+4)
	}
	for _, p := range pkts {
		if len(p.Payload) >= 16 && smbCmd(p.Payload) == CmdTreeDisconnect || smbCmd(p.Payload) == CmdLogoff {
			t.Errorf("unexpected teardown PDU (command 0x%04x)", smbCmd(p.Payload))
		}
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发）。覆盖 legacy Validate 的主要
// 检查：非法 transport、非法 dialect、非法 auth_mechanism、非法 OpType、
// ErrorResponseStatus 无 ErrorOnCommand。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("smb", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "smb"},
	})
	// 非法 transport。
	spec := smbSpec(0)
	spec.SMB.Transport = "socks5"
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "Transport must be direct or netbios") {
		t.Fatalf("Plan with transport=socks5 error = %v, want transport rejection", err)
	}
	// 非法 dialect。
	spec = smbSpec(0)
	spec.SMB.Dialects = []string{"0x9999"}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "not in allowed list") {
		t.Fatalf("Plan with dialect=0x9999 error = %v, want dialect rejection", err)
	}
	// 非法 auth_mechanism。
	spec = smbSpec(0)
	spec.SMB.AuthMechanism = "digest"
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "auth_mechanism") {
		t.Fatalf("Plan with auth_mechanism=digest error = %v, want auth rejection", err)
	}
	// 非法 OpType。
	spec = smbSpec(0)
	spec.SMB.Operations = []core.SMBOperation{{OpType: "chmod"}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "OpType must be") {
		t.Fatalf("Plan with op=chmod error = %v, want op rejection", err)
	}
	// ErrorResponseStatus 非零但 ErrorOnCommand 为空。
	spec = smbSpec(0)
	spec.SMB.ErrorResponseStatus = StatusAccessDenied
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "ErrorOnCommand must be set") {
		t.Fatalf("Plan with status-only error = %v, want ErrorOnCommand requirement", err)
	}
	// ErrorOnCommand 非零但 ErrorResponseStatus 为零。
	spec = smbSpec(0)
	spec.SMB.ErrorOnCommand = "read"
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "ErrorResponseStatus must be non-zero") {
		t.Fatalf("Plan with command-only error = %v, want ErrorResponseStatus requirement", err)
	}
	// 无 SMB 配置（spec.SMB=nil）——LookupSMBConfig 拒绝。
	spec = smbSpec(0)
	spec.SMB = nil
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "spec.SMB is required") {
		t.Fatalf("Plan with nil SMB error = %v, want missing config rejection", err)
	}
}

// TestLayerGen_NoConfig 无 SMB 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &SMBGenerator{}
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

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &SMBGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{SMB: &core.SMBConfig{}}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_ConfigFromMeta 元数据三形态解析：*SMBConfig 直传（经 Meta，
// 生产路径）、map[string]interface{} 与 json.RawMessage（strategy_convert
// 同款键；FlowMeta.SMB 是类型化字段，防御性解析直测 configFromMeta）。
func TestLayerGen_ConfigFromMeta(t *testing.T) {
	gen := &SMBGenerator{}
	run := func(cfg *core.SMBConfig) []layers.MessageEvent {
		var events []layers.MessageEvent
		req := &layers.GenRequest{
			Meta: layers.FlowMeta{SMB: cfg},
			EmitMsg: func(ev layers.MessageEvent) error {
				events = append(events, ev)
				return nil
			},
		}
		if err := gen.Generate(context.Background(), req); err != nil {
			t.Fatalf("Generate with *SMBConfig config: %v", err)
		}
		return events
	}
	cfg := &core.SMBConfig{ClientGuid: guid(0x11), ServerGuid: guid(0x22), FileId: guid(0x33)}
	// 形态 1：*SMBConfig（生产路径）。
	events := run(cfg)
	if len(events) == 0 {
		t.Fatal("no events from *SMBConfig meta")
	}
	// 形态 2：map（strategy_convert parseSMBConfig 同款键）→ configFromMeta。
	m := map[string]interface{}{
		"transport": "direct", "auth_mechanism": "anonymous", "auth_rounds": 1,
		"client_guid": "11111111111111111111111111111111",
		"server_guid": "22222222222222222222222222222222",
		"file_id":     "33333333333333333333333333333333",
	}
	c2, err := configFromMeta(m)
	if err != nil {
		t.Fatalf("configFromMeta(map): %v", err)
	}
	// 匿名 1 轮：NEGO/SS 1 轮/TC/CREATE/READ/CLOSE/TD/LOGOFF = 8 对 16 事件。
	events2 := run(c2)
	if len(events2) != 16 {
		t.Fatalf("events from map meta = %d, want 16 (anonymous 1 round)", len(events2))
	}
	// map 解析出的 GUID 必须与 hex 字符串一致（parseGUIDString 语义）。
	if c2.ClientGuid != guid(0x11) || c2.ServerGuid != guid(0x22) || c2.FileId != guid(0x33) {
		t.Fatalf("map GUIDs not decoded: client=%x server=%x file=%x",
			c2.ClientGuid, c2.ServerGuid, c2.FileId)
	}
	// 形态 3：json.RawMessage → configFromMeta。
	c3, err := configFromMeta(json.RawMessage(`{"transport":"direct","auth_mechanism":"anonymous","auth_rounds":1}`))
	if err != nil {
		t.Fatalf("configFromMeta(RawMessage): %v", err)
	}
	events3 := run(c3)
	if len(events3) != 16 {
		t.Fatalf("events from RawMessage meta = %d, want 16", len(events3))
	}
	// 形态 4：非法输入显式报错（nil、非法 map、非法 RawMessage、未知类型）。
	if _, err := configFromMeta(nil); err == nil || !strings.Contains(err.Error(), "no config") {
		t.Fatalf("configFromMeta(nil) error = %v, want no-config error", err)
	}
	if _, err := configFromMeta(map[string]interface{}{"client_guid": 42}); err == nil {
		t.Fatal("configFromMeta(map with bad guid) returned nil, want error")
	}
	if _, err := configFromMeta(json.RawMessage(`{`)); err == nil {
		t.Fatal("configFromMeta(bad raw) returned nil, want error")
	}
	if _, err := configFromMeta(42); err == nil || !strings.Contains(err.Error(), "unsupported smb config type") {
		t.Fatalf("configFromMeta(int) error = %v, want unsupported type", err)
	}
}

func guid(b byte) [16]byte {
	var g [16]byte
	for i := range g {
		g[i] = b
	}
	return g
}

// boolPtrOf returns a pointer to v (测试构造 *bool 配置字段用；包内 boolPtr
// 是解引用函数，勿混淆)。
func boolPtrOf(v bool) *bool { return &v }

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &SMBGenerator{}
	sentinel := errors.New("emit failed")
	c2 := *smbSpec(0).SMB
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{SMB: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：默认配置产
// 18 事件（9 对），第 3 个事件后取消 → 返回 context 错误且只发出 3 事件
// （TREE_CONNECT 前）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &SMBGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	c2 := *smbSpec(0).SMB
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{SMB: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 3 { // 第 3 个事件后取消（NEGOTIATE 对 + SESSION_SETUP req）
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
	if len(events) != 3 {
		t.Fatalf("emitted %d events, want exactly 3 (cancelled mid-sequence)", len(events))
	}
}
