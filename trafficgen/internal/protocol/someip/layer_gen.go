package someip

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type SOMEIPGenerator struct{}

func (g *SOMEIPGenerator) Name() string { return "someip" }
func (g *SOMEIPGenerator) GenEvents() layers.EventGenerator { return g }
func (g *SOMEIPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("someip generator: EmitEvent is not wired")
}

func (g *SOMEIPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("someip generator: EmitMsg is nil")
	}
	cfg := req.Meta.SOMEIP
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（service 0x1234 默认单请求 +
		// auto RESPONSE）。与 Planner.Plan 的默认化一致。
		cfg = &core.SOMEIPConfig{}
	}

	// 顶层默认值
	serviceID := cfg.ServiceID
	if serviceID == 0 {
		serviceID = 0x1234
	}
	methodID := cfg.MethodID
	if methodID == 0 {
		methodID = 1
	}
	clientID := cfg.ClientID
	if clientID == 0 {
		clientID = 1
	}
	protocolVer := cfg.ProtocolVersion
	if protocolVer == 0 {
		protocolVer = 1
	}
	ifaceVer := cfg.InterfaceVersion
	if ifaceVer == 0 {
		ifaceVer = 1
	}
	sessionStart := cfg.SessionStart
	if sessionStart == 0 {
		sessionStart = 1
	}
	sessionInc := cfg.SessionInc
	if sessionInc == 0 {
		sessionInc = 1
	}
	autoResp := true
	if cfg.AutoResponse != nil {
		autoResp = *cfg.AutoResponse
	}

	// 顶层 message_type 解析（默认 request）
	baseType, ok := msgTypeFromString(cfg.MessageType)
	if !ok {
		return fmt.Errorf("someip: invalid message_type %v", cfg.MessageType)
	}

	// SD 报文分支配发
	if cfg.SD != nil {
		return g.generateSD(ctx, req, cfg, clientID, sessionStart)
	}

	// 事件序列（events 数组）——逐条展开
	if len(cfg.Events) > 0 {
		sess := sessionStart
		for i, ev := range cfg.Events {
			mtype, ok := msgTypeFromString(ev.MessageType)
			if !ok {
				return fmt.Errorf("someip: events[%d] invalid message_type %v", i, ev.MessageType)
			}
			mt := ev.MethodID
			if mt == 0 {
				mt = methodID
			}
			payload := ev.Payload
			direction := ev.Direction
			// 事件类型默认 down（server 事件/通知），方法调用默认 up
			if direction == "" {
				if mtype == MTNotification {
					direction = "down"
				} else {
					direction = "up"
				}
			}
			up := direction != "down"
			// REQUEST → autoResponse 补 RESPONSE；ERROR 显式 down 单发
			if err := emitMessage(ctx, req.EmitMsg, serviceID, mt, clientID, sess,
				protocolVer, ifaceVer, mtype, ev.ReturnCode, payload, up); err != nil {
				return err
			}
			sess += sessionInc
		}
		return nil
	}

	// 单条消息（无 events）：REQUEST 默认 autoResponse 双向
	payload := cfg.Payload
	up := cfg.Direction != "down"

	// TP 分段：payload 超长且启用 tp → 多条 MessageEvent
	if cfg.TP != nil && cfg.TP.Enabled && len(payload) > cfg.TP.SegmentSize {
		return g.generateTP(ctx, req, cfg, serviceID, methodID, clientID, sessionStart,
			protocolVer, ifaceVer, baseType, payload)
	}

	// 单条消息发送
	if err := emitMessage(ctx, req.EmitMsg, serviceID, methodID, clientID, sessionStart,
		protocolVer, ifaceVer, baseType, cfg.ReturnCode, payload, up); err != nil {
		return err
	}

	// autoResponse：REQUEST → RESPONSE（同 SessionID）
	if autoResp && baseType == MTRequest && up {
		// RESPONSE 回用请求 SessionID，returncode E_OK（未显式指定）
		return emitMessage(ctx, req.EmitMsg, serviceID, methodID, clientID, sessionStart,
			protocolVer, ifaceVer, MTResponse, 0, payload, false)
	}
	return nil
}

// emitMessage sends one SOME/IP message event.
func emitMessage(ctx context.Context, emit func(layers.MessageEvent) error, serviceID, methodID, clientID, sessionID uint16, protocolVer, interfaceVer, msgType, retCode byte, payload []byte, up bool) error {
	msg := buildMessage(serviceID, methodID, clientID, sessionID, protocolVer, interfaceVer, msgType, retCode, payload)
	return emitSel(ctx, emit, layers.MessageEvent{Up: up, Bytes: msg})
}

// generateSD emits SD FindService/OfferService/Subscribe/SubscribeAck events.
func (g *SOMEIPGenerator) generateSD(ctx context.Context, req *layers.GenRequest, cfg *core.SOMEIPConfig, clientID, sessionStart uint16) error {
	sd := cfg.SD
	sdType, ok := sdTypeFromString(sd.Type)
	if !ok {
		return fmt.Errorf("someip: invalid sd.type %q (want find|offer|subscribe|subscribe_ack)", sd.Type)
	}
	serviceID := sd.ServiceID
	if serviceID == 0 {
		serviceID = 0x1234
	}
	instanceID := sd.InstanceID
	if instanceID == 0 {
		instanceID = 1
	}
	majorVer := sd.MajorVersion
	if majorVer == 0 {
		majorVer = 1
	}
	ttl := sd.TTL
	if ttl == 0 {
		ttl = 0xFFFFFF
	}

	var options []SDOption
	for _, o := range sd.Options {
		optType := o.Type
		if optType == 0 {
			optType = SDOptionIPv4Endpoint
		}
		options = append(options, SDOption{Type: optType, IP: o.IP, Port: o.Port, Proto: o.Proto})
	}

	var flags byte
	// design §2.5: Flags bit7 Reboot / bit6 Unicast / bit5 ExpInit（维持 0，默认）.

	// FindService/Subscribe 是 up（client→SD）；OfferService/SubscribeAck 是 down。
	switch sdType {
	case SDEntryFind, SDEntrySubscribe:
		// up
		msg, err := buildSDMessage(sdType, serviceID, instanceID, majorVer, sd.MinorVersion, ttl, flags, sd.EventgroupID, sd.Counter, options, clientID, sessionStart)
		if err != nil {
			return err
		}
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: msg}); err != nil {
			return err
		}
		// SD 自动应答：Find→Offer（down，ttl 3，AUTOSAR Offer 常短 TTL）、Subscribe→SubscribeAck（down，counter 0）
		respType := sdType
		respTTL := ttl
		if sdType == SDEntryFind {
			respType = SDEntryOffer
			respTTL = 3
		} else if sdType == SDEntrySubscribe {
			respType = SDEntrySubAck
			respTTL = 0
		}
		msg2, err := buildSDMessage(respType, serviceID, instanceID, majorVer, sd.MinorVersion, respTTL, flags, sd.EventgroupID, 0, options, clientID, sessionStart)
		if err != nil {
			return err
		}
		return emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: msg2})
	default:
		// down 单发（OfferService / SubscribeAck）
		msg, err := buildSDMessage(sdType, serviceID, instanceID, majorVer, sd.MinorVersion, ttl, flags, sd.EventgroupID, sd.Counter, options, clientID, sessionStart)
		if err != nil {
			return err
		}
		return emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: msg})
	}
}

// generateTP segments a long payload into TP segments (§3.5).
func (g *SOMEIPGenerator) generateTP(ctx context.Context, req *layers.GenRequest, cfg *core.SOMEIPConfig, serviceID, methodID, clientID, sessionID uint16, protocolVer, interfaceVer, baseType byte, payload []byte) error {
	tp := cfg.TP
	segmentSize := tp.SegmentSize
	if segmentSize <= 0 {
		return fmt.Errorf("someip: tp segment_size must be > 0")
	}
	payloadLen := tp.PayloadLength
	if payloadLen <= 0 {
		payloadLen = len(payload)
	}
	// Offered Length = 16 + 原载荷总长（§3.5）
	offeredLen := uint32(16 + payloadLen)
	tpMsgType := msgTypeForTP(baseType)

	// 首段：完整消息头 + TP 头 + 首段载荷
	single := buildTPHeader(offeredLen, 0, true)
	// 包1 header: Service/Method/Client/Session/Length=8+8+segmentLen
	first := buildHeader(serviceID, methodID, clientID, sessionID, protocolVer, interfaceVer, tpMsgType, 0, 8+segmentSize)
	first = append(first, single...)
	first = append(first, payload[:min(segmentSize, len(payload))]...)
	if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: first}); err != nil {
		return err
	}

	// 后续段：只 TP 头 + 段载荷
	segID := byte(1)
	for off := segmentSize; off < len(payload); off += segmentSize {
		end := min(off+segmentSize, len(payload))
		more := end < len(payload)
		seg := buildTPHeader(offeredLen, segID, more)
		seg = append(seg, payload[off:end]...)
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: seg}); err != nil {
			return err
		}
		segID++
	}
	return nil
}

func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	layers.RegisterLayerGenerator("someip", func() (layers.LayerGenerator, error) { return &SOMEIPGenerator{}, nil })
	layers.RegisterLayerValidator("someip", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}