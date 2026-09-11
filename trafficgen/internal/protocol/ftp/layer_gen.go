package ftp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// FTPGenerator is the ftp terminal-layer generator (ftp 终结层层生成器)。
// FTP（RFC 959）——多会话形状（D-FTP-1）：每会话一条独立控制 TCP 连接，
// 会话内事务有序执行；EmitDataChannel 的事务挂独立数据 TCP 连接
// （端口推导与 legacy emitTxDataChannel 同规则）。
//
// 事件模式（pop3/smtp 同款）：每条 wire 帧一个"报文事件"（方向 + 完整字节
// + 连接端口覆盖），TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
// 多会话/数据通道靠事件 SrcPort/DstPort 覆盖合成独立 connKey（Task 1 能力），
// tcp 层须 concurrent=true（chain 侧 isFTPChain 强制，mms/cwmp 同款）。
//
// 与 legacy Plan（ftp.go planSessions/emitTxDataChannel）的对应关系：
//   - 会话循环/事务顺序/banner/CRLF/空 cmd 跳过/OneWay：逐事件复刻。
//   - 数据通道端口推导：复用 scanTxForDataPort（已解析响应，T-FTP-4）+
//     控制端口+1（ftp.go:673,681 逻辑，抽为 dataChannelPorts helper）。
//   - 载荷解析：FileSource > PayloadB64 > Payload + AbortAfterBytes 截断
//     （ftp.go:700-715 同款）；整块发射，MSS 分段归 tcp 层。
//   - active 模式 divergence（基线 pcap 实测）：legacy 数据通道是 server
//     首 SYN（down，STOR 用例 pkt13 20→12371）；事件循环 handshake 恒
//     client 首 SYN（up）。STOR 类 parity 在 Task 6 实测钉，必要时扩展
//     MessageEvent（TCP 侧新 flag，L4PortOverride 是 UDP 专用不混用）。
type FTPGenerator struct{}

// Name returns "ftp".
func (g *FTPGenerator) Name() string { return "ftp" }

// Generate produces one message event per FTP wire frame in legacy
// planSessions order (banner → per-transaction cmd/response → data payload).
// CloseConn 搭在每会话最后一个数据事件上（tcp 层：数据先上路后挥手该 key；
// concurrent 模式从 connOrder 移除，流末不再重复挥手）。事件先缓冲后转发
// （空事件产空 PSH 段，绝不单独发空事件）；空会话零事件→tcp 层无 key 可挥，
// legacy 7 包等价见 emitWithSessionClose 注记。
func (g *FTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("ftp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.FTP
	if c == nil {
		// 与 legacy 同款（Plan 对 nil Config 走默认空会话）：无事件，
		// tcp 层走空事件流默认 7 包（握手+挥手）。
		c = &core.FTPConfig{}
	}
	flowIdx := req.Meta.FlowIndex
	collect := func(fn func(emit func(layers.MessageEvent) error) error) ([]layers.MessageEvent, error) {
		var evs []layers.MessageEvent
		if err := fn(func(ev layers.MessageEvent) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			evs = append(evs, ev)
			return nil
		}); err != nil {
			return nil, err
		}
		return evs, nil
	}
	emit := func(ev layers.MessageEvent) error {
		return g.emitMsg(ctx, req.EmitMsg, ev)
	}

	// 老形状（顶层 Banner/Commands/DataChannel，Sessions 为空）：单控制流。
	if len(c.Sessions) == 0 {
		evs, err := collect(func(e func(layers.MessageEvent) error) error {
			return g.emitLegacy(ctx, e, c, 0, flowIdx)
		})
		if err != nil {
			return err
		}
		return emitWithSessionClose(ctx, emit, evs)
	}
	for _, sess := range c.Sessions {
		evs, err := collect(func(e func(layers.MessageEvent) error) error {
			return g.emitSession(ctx, e, c, sess, flowIdx)
		})
		if err != nil {
			return err
		}
		if err := emitWithSessionClose(ctx, emit, evs); err != nil {
			return err
		}
	}
	return nil
}

// emitWithSessionClose forwards buffered session events, piggybacking
// CloseConn on the session's last event (tcp 层：数据先上路后挥手该 key）。
// 空会话零事件直接跳过：tcp 层无 key 可挥——legacy 7 包（独立握手+挥手）
// 等价在 Task 6 等价 harness 实测后定（若 parity 红，补空会话独立建连事件）。
func emitWithSessionClose(ctx context.Context, emit func(layers.MessageEvent) error, evs []layers.MessageEvent) error {
	if len(evs) == 0 {
		return nil
	}
	for i, ev := range evs {
		if i == len(evs)-1 {
			ev.CloseConn = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(ev); err != nil {
			return err
		}
	}
	return nil
}

// emitSession emits one control connection: banner + transactions in order,
// then a CloseConn event so the tcp layer tears this connection down
// (legacy planSessions 逐会话挥手语义；concurrent 模式 CloseConn 从
// connOrder 移除，流末不再重复挥手）。
func (g *FTPGenerator) emitSession(ctx context.Context, emit func(layers.MessageEvent) error, c *core.FTPConfig, sess core.FTPSession, flowIdx int) error {
	// 会话级动态（D-FTP-2）：静态非零优先，动态按流序号解析。
	srcPort := sess.SrcPort
	if sess.SrcPortDyn != nil && srcPort == 0 {
		if v := core.ResolvePortValue(sess.SrcPortDyn, flowIdx); v != 0 {
			srcPort = v
		}
	}
	banner := sess.Banner
	if sess.BannerDyn != nil && banner == "" {
		if v := core.ResolveStringValue(sess.BannerDyn, flowIdx); v != "" {
			banner = v
		}
	}
	ev := func(up bool, payload []byte) layers.MessageEvent {
		return layers.MessageEvent{Up: up, Bytes: payload, SrcPort: srcPort}
	}
	if banner != "" {
		if err := emit(ev(false, []byte(banner+"\r\n"))); err != nil {
			return err
		}
	}
	for _, rawTx := range sess.Transactions {
		tx := rawTx
		if hasDynFields(sess) {
			tx = resolveTx(rawTx, flowIdx)
		}
		for _, cmd := range tx.Commands {
			if cmd.Cmd != "" {
				if err := emit(ev(true, []byte(cmd.Cmd+"\r\n"))); err != nil {
					return err
				}
			}
			if cmd.Response != "" {
				if err := emit(ev(false, []byte(cmd.Response+"\r\n"))); err != nil {
					return err
				}
			}
		}
		if txHasDataChannel(tx) {
			if err := g.emitDataChannel(ctx, emit, tx, srcPort); err != nil {
				return err
			}
		}
	}
	// 会话挥手由 Generate 的 emitWithSessionClose 统一搭在会话末事件，
	// 此处不单独发（空事件产空 PSH 段）。
	return nil
}

// emitLegacy emits the old shape (top-level Banner/Commands/DataChannel).
func (g *FTPGenerator) emitLegacy(ctx context.Context, emit func(layers.MessageEvent) error, c *core.FTPConfig, srcPort uint16, flowIdx int) error {
	ev := func(up bool, payload []byte) layers.MessageEvent {
		return layers.MessageEvent{Up: up, Bytes: payload, SrcPort: srcPort}
	}
	if c.Banner != "" {
		if err := emit(ev(false, []byte(c.Banner+"\r\n"))); err != nil {
			return err
		}
	}
	for _, cmd := range c.Commands {
		if cmd.Cmd != "" {
			if err := emit(ev(true, []byte(cmd.Cmd+"\r\n"))); err != nil {
				return err
			}
		}
		if cmd.Response != "" {
			if err := emit(ev(false, []byte(cmd.Response+"\r\n"))); err != nil {
				return err
			}
		}
		if cmd.EmitDataChannel && c.DataChannel != nil {
			tx := core.FTPTransaction{Commands: []core.FTPCommand{cmd}, DataChannel: c.DataChannel}
			if err := g.emitDataChannel(ctx, emit, tx, srcPort); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitDataChannel emits one data connection: payload as a single event on
// the derived (clientPort, serverPort) key with CloseConn piggybacked
// (tcp 层：数据先上路后挥手该 key）。端口推导与 legacy emitTxDataChannel
// 同规则（T-FTP-4 事务域扫描）。
func (g *FTPGenerator) emitDataChannel(ctx context.Context, emit func(layers.MessageEvent) error, tx core.FTPTransaction, ctrlPort uint16) error {
	dc := tx.DataChannel
	mode := dc.Mode
	if mode == "" {
		mode = "passive"
	}
	isActive := strings.EqualFold(mode, "active")
	signalingDataPort := scanTxForDataPort(tx.Commands, isActive)
	clientDataPort, serverDataPort := dataChannelPorts(dc, signalingDataPort, ctrlPort)

	var payloadBytes []byte
	if dc.FileSource != nil {
		pc := core.PayloadCacheFrom(ctx)
		if pc == nil {
			return nil
		}
		payloadBytes, _ = pc.GetOrLoad(ctx, *dc.FileSource)
	} else if dc.PayloadB64 != "" {
		payloadBytes, _ = base64.StdEncoding.DecodeString(dc.PayloadB64)
	} else {
		payloadBytes = []byte(dc.Payload)
	}
	if dc.AbortAfterBytes > 0 && dc.AbortAfterBytes < len(payloadBytes) {
		payloadBytes = payloadBytes[:dc.AbortAfterBytes]
	}
	// Direction 缺省 down（parseFTPDataChannel 默认）：server→client。
	isDown := dc.Direction == "" || strings.EqualFold(dc.Direction, "down")
	// CloseConn 搭载荷事件（tcp 层：数据先上路后挥手该 key，legacy
	// 子流"数据→挥手"顺序；concurrent 模式从 connOrder 移除）。
	payloadEv := layers.MessageEvent{
		Up:        !isDown,
		Bytes:     payloadBytes,
		SrcPort:   clientDataPort,
		DstPort:   serverDataPort,
		CloseConn: true,
	}
	if err := g.emitMsg(ctx, emit, payloadEv); err != nil {
		return err
	}
	return nil
}

// dataChannelPorts derives (client, server) data ports (legacy
// emitTxDataChannel 端口块抽取：spec.SrcPort 参数化为 ctrlPort）。
func dataChannelPorts(dc *core.FTPDataChannel, signalingDataPort, ctrlPort uint16) (uint16, uint16) {
	clientDataPort := dc.SrcPort
	serverDataPort := dc.DstPort
	mode := dc.Mode
	if mode == "" {
		mode = "passive"
	}
	if strings.EqualFold(mode, "active") {
		if serverDataPort == 0 {
			serverDataPort = 20
		}
		if clientDataPort == 0 {
			if signalingDataPort != 0 {
				clientDataPort = signalingDataPort
			} else if ctrlPort == 65535 {
				clientDataPort = 1024
			} else {
				clientDataPort = ctrlPort + 1
			}
		}
	} else {
		if clientDataPort == 0 {
			if ctrlPort == 65535 {
				clientDataPort = 1024
			} else {
				clientDataPort = ctrlPort + 1
			}
		}
		if serverDataPort == 0 {
			if signalingDataPort != 0 {
				serverDataPort = signalingDataPort
			} else {
				serverDataPort = 50000
			}
		}
	}
	return clientDataPort, serverDataPort
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（pop3 layer_gen.go 同款 escape hatch）。
func (g *FTPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *FTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *FTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ftp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ftp", func() (layers.LayerGenerator, error) {
		return &FTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("ftp", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（pop3 layer_gen.go 同款陷阱）：
		// legacy ftp planner 恒产 TCP 握手/挥手——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
