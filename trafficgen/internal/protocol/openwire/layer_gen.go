package openwire

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// OpenWireGenerator 事件模式（thrift 同款）：每命令一个 MessageEvent，
// TCP 层负责握手/MSS 分段/挥手；连接级 SrcPort 边界触发 TCPGenerator 的
// 会话切换。自驱模式（连接声明显式 src_ip/dst_ip 的双栈用例）：生成器
// 自产完整 TCP 包（每连接独立握手/数据/挥手），与 ldp dual_adjacency
// 分支同构。
type OpenWireGenerator struct{}

func (g *OpenWireGenerator) Name() string                     { return "openwire" }
func (g *OpenWireGenerator) GenEvents() layers.EventGenerator { return g }
func (g *OpenWireGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("openwire generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate dispatches on the wiring: EmitMsg → event mode (normal
// [ip,tcp,openwire] chain); Emit → self-drive packet mode (dual-stack).
func (g *OpenWireGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("openwire generator: request is nil")
	}
	cfg := req.Meta.OpenWire
	if cfg == nil {
		cfg = defaultConfig()
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if req.EmitMsg != nil {
		return g.generateEvents(ctx, req.EmitMsg, cfg)
	}
	if req.Emit != nil {
		return g.generatePackets(ctx, req.Emit, cfg, req.Meta)
	}
	return fmt.Errorf("openwire generator: neither EmitMsg nor Emit is wired")
}

// msgRef is the resolved identity of a sent message (dispatch/ack 关联键)。
type msgRef struct {
	producerID uint64
	sessionID  uint64
	seq        uint64
}

// connGen is the per-connection encoder state (命令号计数与消息表)。
type connGen struct {
	conn       core.OpenWireConnection
	connID     string // 线上 ConnectionId.value 字符串
	clientCmd  uint32
	brokerCmd  uint32
	lastClient uint32
	sawClient  bool
	messages   map[string]msgRef
	msgCounter uint64
}

func (c *connGen) nextClient(override int) uint32 {
	if override > 0 {
		c.lastClient = uint32(override)
		c.sawClient = true
		return uint32(override)
	}
	c.clientCmd++
	c.lastClient = c.clientCmd
	c.sawClient = true
	return c.clientCmd
}

func (c *connGen) nextBroker(override int) uint32 {
	if override > 0 {
		return uint32(override)
	}
	c.brokerCmd++
	return c.brokerCmd
}

// resolveConnID returns the wire ConnectionId string: the client_id if set,
// else "conn-<id>"。
func resolveConnID(conn *core.OpenWireConnection) string {
	if conn.ClientID != "" {
		return conn.ClientID
	}
	return fmt.Sprintf("conn-%d", conn.ConnectionID)
}

// defaultEvents is the P0b empty-config default: the minimal negotiation
// sequence（client 协商 → 连接 → broker 确认）。
func defaultEvents() []core.OpenWireEvent {
	return []core.OpenWireEvent{
		{Kind: "wire_format_info", Direction: "c2s"},
		{Kind: "connection_info", Direction: "c2s"},
		{Kind: "connection_ack", Direction: "s2c"},
	}
}

// defaultConfig is the empty-config default flow (P0b)。
func defaultConfig() *core.OpenWireConfig {
	return &core.OpenWireConfig{
		Profile: "activemq_openwire_v12",
		Connections: []core.OpenWireConnection{{
			ConnectionID: 1,
			ClientID:     "conn-1",
			Events:       defaultEvents(),
		}},
	}
}

// effectiveConns returns the connections to generate (空配置默认化)。
func effectiveConns(cfg *core.OpenWireConfig) []core.OpenWireConnection {
	if len(cfg.Connections) > 0 {
		return cfg.Connections
	}
	return []core.OpenWireConnection{{ConnectionID: 1, ClientID: "conn-1", Events: defaultEvents()}}
}

// wireVersion resolves the negotiated version (缺省 12)。
func wireVersion(cfg *core.OpenWireConfig) int {
	if cfg != nil && cfg.WireFormat != nil && cfg.WireFormat.Version != 0 {
		return cfg.WireFormat.Version
	}
	return defaultVersion
}

// eventDirection resolves the event direction (缺省按 kind)。
func eventDirection(e *core.OpenWireEvent) (string, error) {
	if e.Direction != "" {
		if e.Direction != "c2s" && e.Direction != "s2c" {
			return "", fmt.Errorf("openwire: direction %q is invalid (want c2s or s2c)", e.Direction)
		}
		return e.Direction, nil
	}
	switch e.Kind {
	case "dispatch", "connection_ack", "response", "exception":
		return "s2c", nil
	default:
		return "c2s", nil
	}
}

// buildEventCommand encodes one event into its command frame, updating the
// per-connection state (命令号/消息表)。
func buildEventCommand(c *connGen, e *core.OpenWireEvent, cfg *core.OpenWireConfig) ([]byte, error) {
	version := wireVersion(cfg)
	switch e.Kind {
	case "wire_format_info":
		return BuildWireFormatInfo(version), nil
	case "connection_info":
		return frameCommand(cmdConnectionInfo, c.nextClient(e.CommandID), responseRequired(e, true), buildConnectionInfoFields(e, c.connID)), nil
	case "connection_ack":
		return frameCommand(cmdResponse, c.nextBroker(e.CommandID), responseRequired(e, false), buildResponseFields(c.correlationOf(e))), nil
	case "session_info":
		return frameCommand(cmdSessionInfo, c.nextClient(e.CommandID), responseRequired(e, true), buildSessionInfoFields(e, c.connID)), nil
	case "producer_info":
		fields, err := buildProducerInfoFields(e, c.connID)
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdProducerInfo, c.nextClient(e.CommandID), responseRequired(e, true), fields), nil
	case "consumer_info":
		fields, err := buildConsumerInfoFields(e, c.connID)
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdConsumerInfo, c.nextClient(e.CommandID), responseRequired(e, true), fields), nil
	case "message":
		producerID := e.ProducerID
		seq := messageSeqOf(e.MessageID)
		if seq == 0 {
			c.msgCounter++
			seq = c.msgCounter
		}
		if key := e.MessageID; key != "" {
			c.messages[key] = msgRef{producerID: producerID, sessionID: e.SessionID, seq: seq}
		}
		txID := uint64(0)
		hasTx := false
		if e.Transaction != nil {
			txID, hasTx = e.Transaction.ID, true
		}
		fields, err := buildMessageFields(e, c.connID, seq, txID, hasTx)
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdActiveMQMessage, c.nextClient(e.CommandID), responseRequired(e, true), fields), nil
	case "dispatch":
		ref, ok := c.messages[e.MessageID]
		if !ok {
			return nil, fmt.Errorf("openwire: dispatch message_id %q does not reference a known message (correlation)", e.MessageID)
		}
		dispatchCopy := *e
		dispatchCopy.ProducerID = ref.producerID
		dispatchCopy.SessionID = ref.sessionID
		fields, err := buildMessageDispatchFields(&dispatchCopy, c.connID, ref.seq, c.nextBroker(0))
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdMessageDispatch, c.nextBroker(e.CommandID), responseRequired(e, false), fields), nil
	case "ack":
		ref, ok := c.messages[e.MessageID]
		if !ok {
			return nil, fmt.Errorf("openwire: ack message_id %q does not reference a known message (correlation/message)", e.MessageID)
		}
		ackCopy := *e
		ackCopy.ProducerID = ref.producerID
		ackCopy.SessionID = ref.sessionID
		fields, err := buildMessageAckFields(&ackCopy, c.connID, ref.seq)
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdMessageAck, c.nextClient(e.CommandID), responseRequired(e, true), fields), nil
	case "transaction":
		fields, err := buildTransactionInfoFields(e, c.connID)
		if err != nil {
			return nil, err
		}
		return frameCommand(cmdTransactionInfo, c.nextClient(e.CommandID), responseRequired(e, true), fields), nil
	case "response":
		return frameCommand(cmdResponse, c.nextBroker(e.CommandID), responseRequired(e, false), buildResponseFields(c.correlationOf(e))), nil
	case "exception":
		return frameCommand(cmdExceptionResponse, c.nextBroker(e.CommandID), responseRequired(e, false), buildExceptionResponseFields(c.correlationOf(e), e.Exception)), nil
	case "remove":
		return frameCommand(cmdRemoveInfo, c.nextClient(e.CommandID), responseRequired(e, true), buildRemoveInfoFields(e, c.connID)), nil
	case "shutdown":
		return frameCommand(cmdShutdownInfo, c.nextClient(e.CommandID), responseRequired(e, false), nil), nil
	default:
		return nil, fmt.Errorf("openwire: unknown command type %q", e.Kind)
	}
}

// correlationOf resolves the Response/ExceptionResponse correlation id:
// explicit value must hit a seen client command (validator enforces); the
// default is the most recent client command id.
func (c *connGen) correlationOf(e *core.OpenWireEvent) uint32 {
	if e.CorrelationID > 0 {
		return uint32(e.CorrelationID)
	}
	return c.lastClient
}

// responseRequired resolves the override or the per-direction default。
func responseRequired(e *core.OpenWireEvent, def bool) bool {
	if e.ResponseRequired != nil {
		return *e.ResponseRequired
	}
	return def
}

// generateEvents emits one MessageEvent per command in config order; each
// event carries its connection's client source port (TCPGenerator 会话边界)。
func (g *OpenWireGenerator) generateEvents(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.OpenWireConfig) error {
	for i := range cfg.Connections {
		conn := &cfg.Connections[i]
		c := &connGen{conn: *conn, connID: resolveConnID(conn), messages: map[string]msgRef{}}
		for j := range conn.Events {
			e := &conn.Events[j]
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame, err := buildEventCommand(c, e, cfg)
			if err != nil {
				return fmt.Errorf("openwire: connection %d event %d (%s): %v", conn.ConnectionID, j, e.Kind, err)
			}
			ev := layers.MessageEvent{
				Up:      dir == "c2s",
				Bytes:   frame,
				SrcPort: conn.SrcPort,
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
	}
	return nil
}

// tcpFlowState tracks one self-driven connection's seq state。
type tcpFlowState struct {
	srcIP, dstIP    string
	srcPort, dstPort uint16
	clientSeq       uint32
	serverSeq       uint32
}

// emitSegment assembles one TCP segment packet for the self-drive path.
func emitSegment(emit func(core.PacketConfig) error, st *tcpFlowState, up bool, flags byte, payload []byte, seq, ack uint32) error {
	direction := "down"
	src, dst := st.dstPort, st.srcPort
	if up {
		direction = "up"
		src, dst = st.srcPort, st.dstPort
	}
	return emit(core.PacketConfig{
		Direction: direction,
		L3: core.L3Config{
			SrcIP:    st.srcIP,
			DstIP:    st.dstIP,
			Protocol: 6,
			TTL:      64,
		},
		L4: core.L4Config{
			Protocol:   "tcp",
			SrcPort:    src,
			DstPort:    dst,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: 65535,
		},
		Payload: payload,
	})
}

// generatePackets is the self-drive path (双栈用例)：每连接完整握手 → 事件
// 命令段（PSH|ACK）→ 四次挥手，方向交换在生成器内完成（链层不再交换）。
func (g *OpenWireGenerator) generatePackets(ctx context.Context, emit func(core.PacketConfig) error, cfg *core.OpenWireConfig, meta layers.FlowMeta) error {
	index := uint64(0)
	for i := range cfg.Connections {
		conn := &cfg.Connections[i]
		st := &tcpFlowState{
			srcIP:   conn.SrcIP,
			dstIP:   conn.DstIP,
			srcPort: conn.SrcPort,
		}
		if st.srcIP == "" {
			st.srcIP = meta.SrcIP
		}
		if st.dstIP == "" {
			st.dstIP = meta.DstIP
		}
		if st.srcPort == 0 {
			st.srcPort = meta.SrcPort
		}
		st.dstPort = defaultDstPort
		if meta.DstPort != 0 {
			st.dstPort = meta.DstPort
		}
		st.clientSeq = rand.Uint32()
		st.serverSeq = rand.Uint32()

		wrapEmit := func(pkt core.PacketConfig) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if pkt.FlowID == "" {
				pkt.FlowID = meta.FlowID
			}
			pkt.PacketIndex = index
			index++
			return emit(pkt)
		}

		// 握手 SYN / SYN-ACK / ACK。
		if err := emitSegment(wrapEmit, st, true, layers.FlagSYN, nil, st.clientSeq, 0); err != nil {
			return err
		}
		st.clientSeq++
		if err := emitSegment(wrapEmit, st, false, layers.FlagSYN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		st.serverSeq++
		if err := emitSegment(wrapEmit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}

		c := &connGen{conn: *conn, connID: resolveConnID(conn), messages: map[string]msgRef{}}
		for j := range conn.Events {
			e := &conn.Events[j]
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame, err := buildEventCommand(c, e, cfg)
			if err != nil {
				return fmt.Errorf("openwire: connection %d event %d (%s): %v", conn.ConnectionID, j, e.Kind, err)
			}
			up := dir == "c2s"
			seq, ack := st.clientSeq, st.serverSeq
			if err := emitSegment(wrapEmit, st, up, layers.FlagPSH|layers.FlagACK, frame, seq, ack); err != nil {
				return err
			}
			if up {
				st.clientSeq += uint32(len(frame))
			} else {
				st.serverSeq += uint32(len(frame))
			}
		}

		// 挥手 FIN|ACK(up) → ACK(down) → FIN|ACK(down) → ACK(up)。
		if err := emitSegment(wrapEmit, st, true, layers.FlagFIN|layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}
		st.clientSeq++
		if err := emitSegment(wrapEmit, st, false, layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		if err := emitSegment(wrapEmit, st, false, layers.FlagFIN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		st.serverSeq++
		if err := emitSegment(wrapEmit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}
	}
	return nil
}

// ---- validator ----

// connState is the per-connection protocol state machine (设计 §5)。
type connState struct {
	negotiated bool
	connected  bool
	closed     bool
	sessions   map[uint64]bool
	producers  map[uint64]uint64 // producerID → sessionID
	consumers  map[uint64]uint64 // consumerID → sessionID
	messages   map[string]msgRef
	txOpen     map[uint64]bool
	txDone     map[uint64]bool
	clientCmds map[uint32]bool
	sawClient  bool
}

// validateConnection walks one connection's events through the state machine。
func validateConnection(connIdx int, conn *core.OpenWireConnection) error {
	st := &connState{
		sessions:   map[uint64]bool{},
		producers:  map[uint64]uint64{},
		consumers:  map[uint64]uint64{},
		messages:   map[string]msgRef{},
		txOpen:     map[uint64]bool{},
		txDone:     map[uint64]bool{},
		clientCmds: map[uint32]bool{},
	}
	if len(conn.Events) == 0 {
		return fmt.Errorf("openwire: connection %d has no events — at least the wire_format_info negotiation is required", conn.ConnectionID)
	}
	for i := range conn.Events {
		e := &conn.Events[i]
		dir, err := eventDirection(e)
		if err != nil {
			return err
		}
		if st.closed {
			return fmt.Errorf("openwire: connection %d state error: event %d (%s) arrives after close — no new commands after remove/shutdown", conn.ConnectionID, i, e.Kind)
		}
		if !st.negotiated && e.Kind != "wire_format_info" {
			return fmt.Errorf("openwire: connection %d state error: %s cannot precede negotiation — the first command must be wire_format_info (TransportReady state)", conn.ConnectionID, e.Kind)
		}
		switch e.Kind {
		case "wire_format_info":
			st.negotiated = true
		case "connection_info":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d connection_info must be c2s, got %s", conn.ConnectionID, dir)
			}
			st.connected = true
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "connection_ack":
			if dir != "s2c" {
				return fmt.Errorf("openwire: connection %d connection_ack must be s2c, got %s", conn.ConnectionID, dir)
			}
			if !st.connected {
				return fmt.Errorf("openwire: connection %d state error: connection_ack before connection_info (state)", conn.ConnectionID)
			}
		case "session_info":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d session_info must be c2s, got %s", conn.ConnectionID, dir)
			}
			if !st.connected {
				return fmt.Errorf("openwire: connection %d state error: session_info before the connection is established (state/session)", conn.ConnectionID)
			}
			if e.SessionID == 0 {
				return fmt.Errorf("openwire: connection %d session_info requires a session_id", conn.ConnectionID)
			}
			if st.sessions[e.SessionID] {
				return fmt.Errorf("openwire: connection %d duplicate session %d (session ids are unique within a connection)", conn.ConnectionID, e.SessionID)
			}
			st.sessions[e.SessionID] = true
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "producer_info":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d producer_info must be c2s, got %s", conn.ConnectionID, dir)
			}
			if !st.sessions[e.SessionID] {
				return fmt.Errorf("openwire: connection %d entity scope error: producer %d references session %d which is not open in this connection — producer/consumer/session entities cannot cross connections (entity/connection)", conn.ConnectionID, e.ProducerID, e.SessionID)
			}
			if e.ProducerID == 0 {
				return fmt.Errorf("openwire: connection %d producer_info requires a producer_id", conn.ConnectionID)
			}
			if _, _, err := destinationParts(e.Destination); err != nil {
				return err
			}
			st.producers[e.ProducerID] = e.SessionID
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "consumer_info":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d consumer_info must be c2s, got %s", conn.ConnectionID, dir)
			}
			if !st.sessions[e.SessionID] {
				return fmt.Errorf("openwire: connection %d entity scope error: consumer %d references session %d which is not open in this connection — producer/consumer/session entities cannot cross connections (entity/connection)", conn.ConnectionID, e.ConsumerID, e.SessionID)
			}
			if e.ConsumerID == 0 {
				return fmt.Errorf("openwire: connection %d consumer_info requires a consumer_id", conn.ConnectionID)
			}
			if _, _, err := destinationParts(e.Destination); err != nil {
				return err
			}
			if _, ok := ackTypeByte(e.AckMode); !ok {
				return fmt.Errorf("openwire: unknown ack_mode %q (want auto|client|individual|dups_ok)", e.AckMode)
			}
			st.consumers[e.ConsumerID] = e.SessionID
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "message":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d message must be c2s, got %s", conn.ConnectionID, dir)
			}
			if !st.sessions[e.SessionID] {
				return fmt.Errorf("openwire: connection %d entity scope error: message references session %d which is not open in this connection — producer/consumer/session entities cannot cross connections (entity/connection)", conn.ConnectionID, e.SessionID)
			}
			if _, _, err := destinationParts(e.Destination); err != nil {
				return err
			}
			if e.Transaction != nil {
				if !st.txOpen[e.Transaction.ID] {
					return fmt.Errorf("openwire: connection %d message references transaction %d which is not open (transaction)", conn.ConnectionID, e.Transaction.ID)
				}
			}
			seq := messageSeqOf(e.MessageID)
			if seq == 0 {
				seq = uint64(len(st.messages) + 1)
			}
			if e.MessageID != "" {
				st.messages[e.MessageID] = msgRef{producerID: e.ProducerID, sessionID: e.SessionID, seq: seq}
			}
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "dispatch":
			if dir != "s2c" {
				return fmt.Errorf("openwire: connection %d dispatch must be s2c, got %s", conn.ConnectionID, dir)
			}
			if _, registered := st.consumers[e.ConsumerID]; !registered {
				return fmt.Errorf("openwire: connection %d correlation error: dispatch references consumer %d which is not registered (correlation/message)", conn.ConnectionID, e.ConsumerID)
			}
			if _, ok := st.messages[e.MessageID]; !ok {
				return fmt.Errorf("openwire: connection %d correlation error: dispatch message_id %q does not reference a known message (correlation/message)", conn.ConnectionID, e.MessageID)
			}
		case "ack":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d ack must be c2s, got %s", conn.ConnectionID, dir)
			}
			if _, registered := st.consumers[e.ConsumerID]; !registered {
				return fmt.Errorf("openwire: connection %d correlation error: ack references consumer %d which is not registered (correlation/message)", conn.ConnectionID, e.ConsumerID)
			}
			if _, ok := st.messages[e.MessageID]; !ok {
				return fmt.Errorf("openwire: connection %d correlation error: ack message_id %q does not reference a known message (correlation/message)", conn.ConnectionID, e.MessageID)
			}
			if _, ok := ackTypeByte(e.AckMode); !ok {
				return fmt.Errorf("openwire: unknown ack_mode %q (want auto|client|individual|dups_ok)", e.AckMode)
			}
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "transaction":
			if dir != "c2s" {
				return fmt.Errorf("openwire: connection %d transaction must be c2s, got %s", conn.ConnectionID, dir)
			}
			if e.Transaction == nil {
				return fmt.Errorf("openwire: connection %d transaction event requires a transaction block", conn.ConnectionID)
			}
			txnID := e.Transaction.ID
			switch e.Transaction.Kind {
			case "begin":
				if st.txOpen[txnID] || st.txDone[txnID] {
					return fmt.Errorf("openwire: connection %d transaction %d begin duplicates an existing transaction (transaction)", conn.ConnectionID, txnID)
				}
				st.txOpen[txnID] = true
			case "commit", "rollback":
				if !st.txOpen[txnID] {
					if st.txDone[txnID] {
						return fmt.Errorf("openwire: connection %d transaction %d %s after it already terminated — transactions terminate exactly once (transaction)", conn.ConnectionID, txnID, e.Transaction.Kind)
					}
					return fmt.Errorf("openwire: connection %d transaction %d %s without begin (transaction)", conn.ConnectionID, txnID, e.Transaction.Kind)
				}
				delete(st.txOpen, txnID)
				st.txDone[txnID] = true
			default:
				return fmt.Errorf("openwire: unknown transaction kind %q (want begin|prepare|commit|rollback)", e.Transaction.Kind)
			}
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "response":
			if dir != "s2c" {
				return fmt.Errorf("openwire: connection %d response must be s2c, got %s", conn.ConnectionID, dir)
			}
			if e.CorrelationID > 0 && !st.clientCmds[uint32(e.CorrelationID)] {
				return fmt.Errorf("openwire: connection %d correlation error: response correlation_id %d references an unknown client command (correlation/message)", conn.ConnectionID, e.CorrelationID)
			}
		case "exception":
			if dir != "s2c" {
				return fmt.Errorf("openwire: connection %d exception must be s2c, got %s", conn.ConnectionID, dir)
			}
			if e.CorrelationID > 0 && !st.clientCmds[uint32(e.CorrelationID)] {
				return fmt.Errorf("openwire: connection %d correlation error: exception correlation_id %d references an unknown client command (correlation/message)", conn.ConnectionID, e.CorrelationID)
			}
		case "remove":
			if _, registered := st.consumers[e.ConsumerID]; e.ConsumerID != 0 && !registered {
				return fmt.Errorf("openwire: connection %d correlation error: remove references consumer %d which is not registered (correlation/message)", conn.ConnectionID, e.ConsumerID)
			}
			if e.ConsumerID == 0 && e.SessionID == 0 {
				// 连接级 RemoveInfo 关闭连接；实体级 remove（消费者/会话）
				// 不是连接关闭——后续 shutdown/新命令仍然合法。
				st.closed = true
			}
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		case "shutdown":
			st.closed = true
			st.sawClient = true
			st.clientCmds[nextCmdID(st, e)] = true
		default:
			return fmt.Errorf("openwire: unknown command type %q", e.Kind)
		}
	}
	return nil
}

// nextCmdID mirrors the generator's auto command-id assignment for
// correlation validation (显式 CommandID 优先)。
func nextCmdID(st *connState, e *core.OpenWireEvent) uint32 {
	if e.CommandID > 0 {
		return uint32(e.CommandID)
	}
	return uint32(len(st.clientCmds) + 1)
}

// ValidateConfig rejects configs that must never reach the wire (设计 §4/§8):
// unknown profiles, tight/cached wire formats (tshark 3.6.14 不能解析), wire
// faults, and per-connection state machine violations. Explicit boundaries
// (empty body, all event kinds, explicit correlation to a real command) are
// legal and must NOT be rejected.
func ValidateConfig(cfg *core.OpenWireConfig) error {
	if cfg == nil {
		return nil
	}
	switch cfg.Profile {
	case "", "activemq_openwire_v12", "activemq_openwire_legacy":
	default:
		return fmt.Errorf("openwire: unknown profile %q — want activemq_openwire_v12 or activemq_openwire_legacy (profile)", cfg.Profile)
	}
	if wf := cfg.WireFormat; wf != nil {
		if wf.TightEncoding {
			return fmt.Errorf("openwire: tight_encoding is not supported — the negotiated wire format must stay loose (profile)")
		}
		if wf.CacheEnabled {
			return fmt.Errorf("openwire: cache_enabled is not supported — cached object references would corrupt the field encoding (profile)")
		}
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	for i := range cfg.Connections {
		if err := validateConnection(i, &cfg.Connections[i]); err != nil {
			return err
		}
	}
	return nil
}

// validateWireFault rejects every injected fault with its testcase-contract
// anchor word, and any unknown kind。
func validateWireFault(f *core.OpenWireWireFault) error {
	if f == nil || f.Kind == "" {
		return nil
	}
	switch f.Kind {
	case "short_frame":
		return fmt.Errorf("openwire: wire_fault short_frame — every command frame is length-prefixed; a frame shorter than the 5-byte header (4-byte length + data structure type) cannot be encoded (frame/length)")
	case "length_overrun":
		return fmt.Errorf("openwire: wire_fault length_overrun — the declared command length must equal the encoded bytes; a length beyond the stream or an integer overflow cannot be encoded (length)")
	case "bad_type":
		return fmt.Errorf("openwire: wire_fault bad_type — the command data structure type must be a known value; unknown types are rejected at validation (command/type)")
	default:
		return fmt.Errorf("openwire: unknown wire_fault kind %q", f.Kind)
	}
}

func init() {
	layers.RegisterLayerGenerator("openwire", func() (layers.LayerGenerator, error) {
		return &OpenWireGenerator{}, nil
	})
	layers.RegisterLayerValidator("openwire", func(spec *core.FlowSpec) error {
		// OpenWire 只走 TCP/61616：显式写其它目的端口即负例（tcp/port 锚词）；
		// 0 = 未写，由 FieldContract 补 61616。
		if spec.OpenWire != nil && spec.DstPort != 0 && spec.DstPort != defaultDstPort {
			return fmt.Errorf("openwire: destination port %d is not the OpenWire TCP port %d — non-TCP carriers or wrong ports are rejected", spec.DstPort, defaultDstPort)
		}
		return ValidateConfig(spec.OpenWire)
	})
}
