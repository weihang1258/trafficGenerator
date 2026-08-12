package layers

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TCP flag values (replicated from internal/protocol/tcp/tcp.go so the
// layers package has no dependency on the protocol package).
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// Default values aligned with internal/protocol/tcp/tcp.go.
const (
	DefaultMSS        = 1460
	MinMSS            = 536 // RFC 879: minimum MSS
	DefaultWindowSize = 65535
	DefaultTTL        = 64
)

// LayerGenerator generates packet configs for one layer of a chain
// (层生成器)。Each generator reads its own completed layer config, wraps the
// inner generator's packets (tunnel layers), and hands the wrapped packet to
// the ChainPlanner via Emit. State shared across layers of one flow lives in
// SessionState; per-flow baseline values live in GenRequest.Meta.
type LayerGenerator interface {
	// Name returns the layer name this generator implements ("ip", "tcp", ...).
	Name() string
	// Generate drives this layer's packet sequence. req.Sess carries the
	// per-flow state across layer boundaries; req.Emit delivers each
	// wrapped packet to the ChainPlanner.
	Generate(ctx context.Context, req *GenRequest) error
	// GenEvents optionally marks a terminal generator that produces message
	// events (报文事件) for the transport layer instead of raw packets.
	// HTTPGenerator and future terminal generators (dns/ntp/...) implement
	// it; the ChainPlanner type-asserts and wires the event channel. A nil
	// return means the generator does not produce events (falls back to the
	// plain packet path).
	GenEvents() EventGenerator
}

// GenRequest carries one layer's generation context (一层生成上下文)。
type GenRequest struct {
	// Layer is this layer's config, already completed with schema defaults
	// (已补全、已应用 schema 默认值)。Generators read values from here, never
	// from the raw FlowSpec.
	Layer Layer
	// Inner is the inner generator's packet stream (内层包流, 内→外递归)。
	// Tunnel layers consume it; the terminal/transport/network layers ignore it.
	Inner <-chan core.PacketConfig
	// Emit delivers this layer's wrapped packet to the ChainPlanner.
	// Returning an error aborts the whole chain drive.
	Emit func(core.PacketConfig) error
	// Sess is the per-flow session state shared across layers.
	Sess *SessionState
	// Meta carries the flow baseline (FlowID/ClassID/Timestamp/Direction
	// source). Payload carries the flow-level application payload for
	// transport layers.
	Meta FlowMeta
	// EmitMsg delivers a terminal-layer message event (报文事件) to the
	// transport layer. Terminal generators (http, future dns/ntp/...) emit
	// message byte events here; the transport generator (TCPGenerator/UDPGenerator
	// Inner mode) consumes them from Meta.Events when present. The
	// ChainPlanner wires the two.
	EmitMsg func(MessageEvent) error
}

// MessageEvent is one terminal-layer message in the transport stream
// (一个报文事件：方向 + 完整报文字节)。The transport layer owns
// segmentation and seq/ack; the event only carries the direction and the
// fully-built message bytes.
type MessageEvent struct {
	// Up is true for the client→server direction (request), false for
	// server→client (response).
	Up bool
	// Bytes is the complete protocol message (e.g. full HTTP request/response).
	Bytes []byte
}

// EventGenerator produces the message-event stream for a terminal
// layer (终结层报文事件生成器)。Implemented by terminal-layer generators
// (e.g. the http generator in the protocol package); the ChainPlanner calls
// EmitEvent for each built message and closes the stream when generation is
// done.
type EventGenerator interface {
	// EmitEvent delivers one message event. The ChainPlanner wires
	// it to the transport layer's event channel.
	EmitEvent(ev MessageEvent) error
}

// FlowMeta is the per-flow baseline the ChainPlanner passes to every layer
// (每 flow 基线元数据)。
type FlowMeta struct {
	FlowID  string
	ClassID string
	// Timestamp is the per-packet timestamp source; zero = time.Now() per
	// packet (包时间戳，零值 = 每包取当前时间)。
	Timestamp time.Time
	// Payload is the flow-level application payload (spec.Payload)。
	Payload []byte
	// HTTP is the flow's HTTP config (注入到 http 层生成器，绕过 schema
	// 字段表——HTTPConfig 全量字段不落层 config，避免 ValidateLayerConfig
	// 的未知字段拒绝)。Only set for http chains.
	HTTP *core.HTTPConfig
	// DstIP is the flow destination IP (供终结层生成器构造 Host 头等，
	// legacy http.go:270 传 spec.DstIP 给 buildHTTPRequestBody)。
	DstIP string
	// Events is the transport layer's view of the terminal stream
	// (传输层 Inner 模式消费的报文事件流)。The ChainPlanner creates it,
	// the terminal generator writes via req.EmitMsg, the transport
	// generator reads it. When nil, the transport generator keeps the
	// legacy single-payload mode.
	Events <-chan MessageEvent
	// UDP is the flow's UDP config (注入到 udp 层生成器：IsResponse /
	// DisableChecksum，legacy udp.go 语义)。Only set for udp chains.
	UDP *core.UDPConfig
}

// SessionState is the per-flow state shared by all layer generators
// (每 flow 会话状态)。
type SessionState struct {
	ClientSeq, ServerSeq uint32 // tcp 层持有
	ClientAck, ServerAck uint32
	HandshakeDone        bool
	IPID                 uint16 // ip 层持有，每 Emit 前写入并自增
	// PacketIndex is the per-flow packet sequence number, advanced by the
	// ChainPlanner for every packet that leaves the chain (ChainPlanner 统一推进)。
	PacketIndex uint64
}

// flowConfigField reads a completed layer config field with a schema-type
// conversion. Returns (value, present). Values may arrive as the schema
// default's native type (uint8/uint16/uint32/bool/string) or as a raw JSON
// number/string when the config came from user input.
func flowConfigField(cfg map[string]interface{}, key string) (interface{}, bool) {
	if cfg == nil {
		return nil, false
	}
	v, ok := cfg[key]
	return v, ok && v != nil
}

// configUint64 converts a config value to uint64 (schema-typed defaults
// and raw numeric strings). ok=false when absent or unparseable.
func configUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case uint8:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case uint64:
		return n, true
	case int:
		return uint64(n), true
	case int64:
		return uint64(n), n >= 0
	case float64:
		if n < 0 || n != float64(uint64(n)) {
			return 0, false
		}
		return uint64(n), true
	case string:
		u, err := strconv.ParseUint(n, 0, 64)
		return u, err == nil
	}
	return 0, false
}

func configUint16(v interface{}) (uint16, bool) {
	u, ok := configUint64(v)
	if !ok || u > 65535 {
		return 0, false
	}
	return uint16(u), true
}

func configUint8(v interface{}) (uint8, bool) {
	u, ok := configUint64(v)
	if !ok || u > 255 {
		return 0, false
	}
	return uint8(u), true
}

func configUint32(v interface{}) (uint32, bool) {
	u, ok := configUint64(v)
	if !ok || u > 4294967295 {
		return 0, false
	}
	return uint32(u), true
}

func configString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func configBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		if b == "true" {
			return true, true
		}
		if b == "false" {
			return false, true
		}
	}
	return false, false
}

// synOptions builds the SYN TCP options: MSS + Window Scale + SACK-Permitted
// (字节复刻 internal/protocol/tcp/tcp.go:85-96)。MSS=0 归一为 DefaultMSS。
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// effectiveMSS resolves the effective MSS: 0 → DefaultMSS, below MinMSS →
// MinMSS (schema min 536, RFC 879).
func effectiveMSS(mss uint16) uint16 {
	if mss == 0 {
		return DefaultMSS
	}
	if mss < MinMSS {
		return MinMSS
	}
	return mss
}

// segmentByMSS splits payload into chunks of at most mss bytes. An empty
// payload returns a single empty chunk so the caller still emits one
// PSH-ACK segment (matching the legacy http.go:469-489 semantics — an
// empty HTTP body still produces one data packet).
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		// Defensive: caller resolves 0 → DefaultMSS before invoking.
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// ---- ip 层生成器 ----

// IPGenerator fills the L3 config for every packet it wraps (ip 层生成器)。
// It reads src/dst/ttl/dscp/ecn/frag_offset from its own completed layer
// config, writes Sess.IPID into L3Config.IPID and increments it before each
// Emit. It does NOT re-implement L3Base — the caller (ChainPlanner) already
// fills flow-level fields; this generator is the chain-level owner of IPID.
type IPGenerator struct{}

// Name returns "ip".
func (g *IPGenerator) Name() string { return "ip" }

// GenEvents is unimplemented for the ip layer (ip 层不是终结层，无报文事件)。
func (g *IPGenerator) GenEvents() EventGenerator { return nil }

// Generate wraps every packet from Inner with this layer's L3 config.
// Without Inner (standalone ip? never — ip is never a terminal layer) it
// emits nothing.
// 空串不覆盖（review LOW-1 修复）：src/dst 值为空字符串且非用户显式写入时
// （applySpecToChain 的 schema 默认只填 10.0.0.1/20.0.0.1 当 spec.SrcIP 为空
// ——review 实测）不得覆盖已填好的 IP（legacy 语义：spec IP 空 → L3 空）。
// 本层 Config 里 src/dst 是"用户写的层配置"或"applySpecToChain 注入的
// spec 值"，两者都是显式意图；空串表示"未指定"→ 保留已有值。
func (g *IPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg := req.Layer.Config
	src, srcSet := cfgValueString(cfg, "src")
	dst, dstSet := cfgValueString(cfg, "dst")
	v, _ := flowConfigField(cfg, "ttl")
	ttl, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "dscp")
	dscp, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "ecn")
	ecn, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "frag_offset")
	fragOffset, _ := configUint16(v)
	if req.Sess == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-req.Inner:
			if !ok {
				return nil
			}
			// 只在用户显式写了 src/dst 时覆盖（LOW-1：空串/未写 → 保留已有值）。
			if srcSet {
				pkt.L3.SrcIP = src
			}
			if dstSet {
				pkt.L3.DstIP = dst
			}
			if ttl != 0 {
				pkt.L3.TTL = ttl
			}
			pkt.L3.DSCP = dscp
			pkt.L3.ECN = ecn
			pkt.L3.FragOffset = fragOffset
			// IPID 每次 Emit 前写入并自增（tcp.go:137-141 语义）。
			pkt.L3.IPID = req.Sess.IPID
			req.Sess.IPID++
			if err := req.Emit(pkt); err != nil {
				return err
			}
		}
	}
}

// cfgValueString reads a config field's string value; present=false when the
// field is absent, nil, or not a string（字段是否存在且为字符串）。
func cfgValueString(cfg map[string]interface{}, key string) (string, bool) {
	v, ok := flowConfigField(cfg, key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// ---- tcp 层生成器 ----

// TCPGenerator drives the TCP packet sequence for one flow: handshake
// (SYN/SYN-ACK/ACK), MSS-segmented data segments with peer ACKs, and either
// an abortive RST or the four-way FIN teardown (tcp 层生成器, 字节级复刻
// internal/protocol/tcp/tcp.go:98-432 的包序列与 seq/ack 推进)。
type TCPGenerator struct{}

// Name returns "tcp".
func (g *TCPGenerator) Name() string { return "tcp" }

// GenEvents is unimplemented for the tcp layer (tcp 是传输层，消费事件流，
// 不产出报文事件)。
func (g *TCPGenerator) GenEvents() EventGenerator { return nil }

// tcpCfg is the resolved TCP layer configuration.
type tcpCfg struct {
	srcPort, dstPort uint16
	handshake        bool
	termination      bool
	rst              bool
	mss              uint16
	windowSize       uint16
	initialSeq       uint32
}

// resolveCfg resolves the TCP layer configuration from the completed layer
// config. 存在但不可转换的值（review MEDIUM-1 修复）：显式报错返回，绝不
// 静默丢配置（configUint16/32/8 判"不可转换"时，字段存在 → 用户写了
// 一个我们读不了的值 → 必须拒绝，而不是退回默认/随机）。
func (g *TCPGenerator) resolveCfg(req *GenRequest) (tcpCfg, error) {
	cfg := tcpCfg{
		handshake:   true, // schema 默认 true——不能读 TCPConfig 零值
		termination: true,
		windowSize:  DefaultWindowSize,
		mss:         DefaultMSS,
	}
	// 不可转换值报错；不存在（或 nil）字段跳过（走 schema 默认）。
	errInvalid := func(field string, v interface{}) error {
		return fmt.Errorf("tcp layer: field %q = %v invalid: cannot convert to %s",
			field, v, fieldType(field))
	}
	c := req.Layer.Config
	if v, ok := flowConfigField(c, "src_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.srcPort = p
		} else {
			return cfg, errInvalid("src_port", v)
		}
	}
	if v, ok := flowConfigField(c, "dst_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.dstPort = p
		} else {
			return cfg, errInvalid("dst_port", v)
		}
	}
	if v, ok := flowConfigField(c, "handshake"); ok {
		if b, ok := configBool(v); ok {
			cfg.handshake = b
		} else {
			return cfg, errInvalid("handshake", v)
		}
	}
	if v, ok := flowConfigField(c, "termination"); ok {
		if b, ok := configBool(v); ok {
			cfg.termination = b
		} else {
			return cfg, errInvalid("termination", v)
		}
	}
	if v, ok := flowConfigField(c, "rst"); ok {
		if b, ok := configBool(v); ok {
			cfg.rst = b
		} else {
			return cfg, errInvalid("rst", v)
		}
	}
	if v, ok := flowConfigField(c, "mss"); ok {
		if m, ok := configUint16(v); ok {
			cfg.mss = m
		} else {
			return cfg, errInvalid("mss", v)
		}
	}
	if v, ok := flowConfigField(c, "window_size"); ok {
		if w, ok := configUint16(v); ok {
			cfg.windowSize = w
		} else {
			return cfg, errInvalid("window_size", v)
		}
	}
	if v, ok := flowConfigField(c, "initial_seq"); ok {
		if s, ok := configUint32(v); ok {
			cfg.initialSeq = s
		} else {
			return cfg, errInvalid("initial_seq", v)
		}
	}
	cfg.mss = effectiveMSS(cfg.mss)
	return cfg, nil
}

// fieldType names the numeric type a field maps to, for error messages.
func fieldType(field string) string {
	switch field {
	case "initial_seq":
		return "uint32"
	case "handshake", "termination", "rst":
		return "bool"
	default:
		return "uint16"
	}
}

// Generate drives the TCP sequence for one flow. The flow-level payload
// comes from req.Meta.Payload; per-packet direction/L2/L3 assembly is
// delegated to the ChainPlanner via the wrapping layer chain (ip 层在上层
// 包装)。This generator emits L4-only packets through req.Emit.
func (g *TCPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg, err := g.resolveCfg(req)
	if err != nil {
		return err
	}
	sess := req.Sess
	if sess == nil {
		sess = &SessionState{}
		req.Sess = sess
	}
	// seq 初始化：clientSeq = InitialSeq（schema，0 则随机），serverSeq = 随机。
	clientSeq := cfg.initialSeq
	if clientSeq == 0 {
		clientSeq = rand.Uint32()
	}
	serverSeq := rand.Uint32()
	winSize := cfg.windowSize
	if winSize == 0 {
		winSize = DefaultWindowSize
	}
	synOpts := synOptions(cfg.mss)
	mss := int(cfg.mss)

	emit := func(pkt core.PacketConfig) error {
		if req.Emit == nil {
			return nil
		}
		return req.Emit(pkt)
	}

	// 握手（schema 默认 true）：SYN(up, 0x02) → SYN-ACK(down, 0x12) → ACK(up, 0x10)。
	if cfg.handshake {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		pkt := core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Flags:      FlagSYN,
				WindowSize: winSize,
				TCPOptions: synOpts,
			},
		}
		if err := emit(pkt); err != nil {
			return err
		}
		clientSeq++
		pkt = core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.dstPort,
				DstPort:    cfg.srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagSYN | FlagACK,
				WindowSize: winSize,
				TCPOptions: synOpts,
			},
		}
		if err := emit(pkt); err != nil {
			return err
		}
		serverSeq++
		pkt = core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}
		if err := emit(pkt); err != nil {
			return err
		}
	}
	// 会话状态回写：握手完成后 server 侧 seq 即固定（Sess 供外层/隧道层或
	// 后续驱动读取；挥手用到的也是这个 serverSeq）。回写在 RST 检查之前
	// （review HIGH-1 修复）：RST 分支不提前 return，保证状态永不被跳过。
	sess.ClientSeq = clientSeq
	sess.ServerSeq = serverSeq
	sess.ClientAck = serverSeq
	sess.ServerAck = clientSeq
	sess.HandshakeDone = true

	// 数据段：payload 按 MSS 分段，每段(up, PSH|ACK) 后紧跟对端 ACK(down)。
	// 事件模式（Meta.Events != nil）下跳过单 payload 段：终结层（http 等）
	// 自产报文，legacy http 从不读 spec.Payload，多发包会破坏字节兼容
	// （review CRITICAL 修复）。
	payload := req.Meta.Payload
	if len(payload) > 0 && req.Meta.Events == nil {
		for len(payload) > 0 {
			segmentSize := len(payload)
			if segmentSize > mss {
				segmentSize = mss
			}
			seg := core.PacketConfig{
				Direction: "up",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.srcPort,
					DstPort:    cfg.dstPort,
					Seq:        clientSeq,
					Ack:        serverSeq,
					Flags:      FlagPSH | FlagACK,
					WindowSize: winSize,
				},
				Payload: payload[:segmentSize],
			}
			if err := emit(seg); err != nil {
				return err
			}
			clientSeq += uint32(segmentSize)
			payload = payload[segmentSize:]
			ack := core.PacketConfig{
				Direction: "down",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.dstPort,
					DstPort:    cfg.srcPort,
					Seq:        serverSeq,
					Ack:        clientSeq,
					Flags:      FlagACK,
					WindowSize: winSize,
				},
			}
			if err := emit(ack); err != nil {
				return err
			}
		}
	}

	// ---- Inner 模式：终结层报文事件流（波 2 方案 A）----
	// 终结层（http）经 req.EmitMsg 产出"报文事件"（方向 + 完整字节），
	// tcp 层消费后按 http 语义发段：每报文按 MSS 分段，每段 0x18 PSH-ACK，
	// **段间不跟独立 ACK**（piggyback，ack 字段 = 对端当前 seq），双方向
	// seq 各自推进。与 legacy http.go:266-357 字节一致（测试精确断言段数
	// 与无 ACK 插入）。独立 tcp flow（无事件流）走上方旧逻辑。
	events := req.Meta.Events
	for events != nil {
		var ev MessageEvent
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok = <-events:
			if !ok {
				events = nil // 终结层关闭：数据段结束，进入挥手
				continue
			}
		}
		segments := segmentByMSS(ev.Bytes, mss)
		for _, seg := range segments {
			var direction string
			var seq, ack uint32
			if ev.Up {
				direction, seq, ack = "up", clientSeq, serverSeq
			} else {
				direction, seq, ack = "down", serverSeq, clientSeq
			}
			pkt := core.PacketConfig{
				Direction: direction,
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.srcPort,
					DstPort:    cfg.dstPort,
					Seq:        seq,
					Ack:        ack,
					Flags:      FlagPSH | FlagACK,
					WindowSize: winSize,
				},
				Payload: seg,
			}
			if err := emit(pkt); err != nil {
				return err
			}
			if ev.Up {
				clientSeq += uint32(len(seg))
			} else {
				serverSeq += uint32(len(seg))
			}
		}
	}

	// RST|ACK(up) 代替挥手（RFC 9293 §3.5）。
	// 与 legacy tcp.go:306-328 一致：RST 分支只产出 RST 包，不提前 return——
	// 状态回写已在上方完成，emit 错误照常传播（review HIGH-1 修复）。
	if cfg.rst {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagRST | FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		return nil
	}

	// 挥手：FIN|ACK(up) → ACK(down) → FIN|ACK(down) → ACK(up)。
	if cfg.termination {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		fin1 := core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagFIN | FlagACK,
				WindowSize: winSize,
			},
		}
		if err := emit(fin1); err != nil {
			return err
		}
		clientSeq++
		ack1 := core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.dstPort,
				DstPort:    cfg.srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}
		if err := emit(ack1); err != nil {
			return err
		}
		fin2 := core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.dstPort,
				DstPort:    cfg.srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagFIN | FlagACK,
				WindowSize: winSize,
			},
		}
		if err := emit(fin2); err != nil {
			return err
		}
		serverSeq++
		ack2 := core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}
		if err := emit(ack2); err != nil {
			return err
		}
	}
	return nil
}

// ---- udp 层生成器 ----

// UDPGenerator drives the UDP packet sequence for one flow (udp 层生成器,
// 字节级复刻 internal/protocol/udp/udp.go 的包序列)。UDP has no handshake,
// no segmentation, and no teardown: a request (up) always carries the flow
// payload; a response (down) is emitted only when spec.UDP.IsResponse is set.
// Two modes mirror the tcp generator's split:
//   - standalone payload mode: request payload = req.Meta.Payload。
//   - Inner mode (event-driven): terminal layer events (dns/ntp/...) arrive
//     on req.Meta.Events; events with Up=true take the up direction, Up=false
//     the down direction, each emitted as one datagram (no MSS segmentation).
type UDPGenerator struct{}

// Name returns "udp".
func (g *UDPGenerator) Name() string { return "udp" }

// GenEvents is unimplemented for the udp layer (udp 是传输层，消费事件流，
// 不产出报文事件)。
func (g *UDPGenerator) GenEvents() EventGenerator { return nil }

// udpCfg is the resolved UDP layer configuration.
type udpCfg struct {
	srcPort, dstPort uint16
}

// resolveCfg resolves the UDP layer configuration from the completed layer
// config. 存在但不可转换的值显式报错返回，绝不静默丢配置（与 tcp 层
// resolveCfg 同款纪律）。
func (g *UDPGenerator) resolveCfg(req *GenRequest) (udpCfg, error) {
	var cfg udpCfg
	c := req.Layer.Config
	if v, ok := flowConfigField(c, "src_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.srcPort = p
		} else {
			return cfg, fmt.Errorf("udp layer: field \"src_port\" = %v invalid: cannot convert to uint16", v)
		}
	}
	if v, ok := flowConfigField(c, "dst_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.dstPort = p
		} else {
			return cfg, fmt.Errorf("udp layer: field \"dst_port\" = %v invalid: cannot convert to uint16", v)
		}
	}
	return cfg, nil
}

// Generate drives the UDP sequence for one flow. 独立 [ip→udp] flow（无事件
// 流）发 1 包（request, up），spec.UDP.IsResponse 时再发 1 包（response,
// down）——顺序与 legacy udp.go Plan 逐字节一致。事件驱动模式（Meta.Events
// 非 nil，终结层如 dns/ntp 经 EmitMsg 接线）下每事件发 1 数据报，方向随事件；
// IsResponse 仅作用于独立模式（legacy udp.go 语义：事件流由终结层决定方向）。
// DisableChecksum 写 L4.Metadata["udp_disable_checksum"]（builder writeUDP
// :1320-1333 读取）。
func (g *UDPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg, err := g.resolveCfg(req)
	if err != nil {
		return err
	}
	emit := func(pkt core.PacketConfig) error {
		if req.Emit == nil {
			return nil
		}
		return req.Emit(pkt)
	}
	meta := func() map[string]interface{} {
		// 恒写键（review 波 3 M1 修复）：legacy udp.go 恒写
		// "udp_disable_checksum": false（false 也是显式键），
		// 只写 true 会让 false 语义漂移为"缺键"。
		return map[string]interface{}{"udp_disable_checksum": req.Meta.UDP != nil && req.Meta.UDP.DisableChecksum}
	}

	// ---- Inner 模式：终结层报文事件流（波 3）----
	// 每事件 1 数据报：UDP 无分段（IP 层处理碎片），事件方向决定包方向。
	if req.Meta.Events != nil {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ev, ok := <-req.Meta.Events:
				if !ok {
					return nil
				}
				direction := "up"
				srcPort, dstPort := cfg.srcPort, cfg.dstPort
				if !ev.Up {
					direction = "down"
					srcPort, dstPort = dstPort, srcPort
				}
				if err := emit(core.PacketConfig{
					Direction: direction,
					L4: core.L4Config{
						Protocol: "udp",
						SrcPort:  srcPort,
						DstPort:  dstPort,
					},
					Payload:  ev.Bytes,
					Metadata: meta(),
				}); err != nil {
					return err
				}
			}
		}
	}

	// ---- 独立 payload 模式：request + 可选 response ----
	if err := emit(core.PacketConfig{
		Direction: "up",
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  cfg.srcPort,
			DstPort:  cfg.dstPort,
		},
		Payload:  req.Meta.Payload,
		Metadata: meta(),
	}); err != nil {
		return err
	}
	if req.Meta.UDP != nil && req.Meta.UDP.IsResponse {
		if err := emit(core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  cfg.dstPort,
				DstPort:  cfg.srcPort,
			},
			Payload:  req.Meta.Payload,
			Metadata: meta(),
		}); err != nil {
			return err
		}
	}
	return nil
}
