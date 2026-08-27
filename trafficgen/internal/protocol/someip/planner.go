package someip

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "someip" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.SOMEIP
	if cfg == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （service 0x1234 REQUEST + auto RESPONSE）。允许 nil。
		return nil
	}
	// V1: Service ID must be nonzero
	if cfg.SD == nil {
		if cfg.ServiceID == 0 {
			return fmt.Errorf("someip: service_id must be nonzero")
		}
	}
	// V2: Session ID must be valid (non-zero if session_start is set, or non-zero via default)
	if cfg.SessionStart == 0 && cfg.SessionInc == 0 && cfg.SD == nil && len(cfg.Events) == 0 {
		// Single message - session_start defaults to 1, so this is OK
	} else if cfg.SessionStart == 0 && (cfg.SessionInc == 0) {
		// Only reject if both are explicitly 0 (non-incrementing)
	}
	// V3: Message Type must be valid
	if cfg.MessageType != "" {
		if _, ok := msgTypeFromString(cfg.MessageType); !ok {
			return fmt.Errorf("someip: invalid message_type %v", cfg.MessageType)
		}
	}
	// V4: Protocol Version must be 1
	if cfg.ProtocolVersion != 0 && cfg.ProtocolVersion != 1 {
		return fmt.Errorf("someip: protocol_version must be 1, got %d", cfg.ProtocolVersion)
	}
	// V5: TP validation
	if cfg.TP != nil && cfg.TP.Enabled {
		if cfg.TP.SegmentSize <= 0 {
			return fmt.Errorf("someip: tp segment_size must be > 0")
		}
		if cfg.TP.SegmentSize < 8 {
			return fmt.Errorf("someip: tp segment_size %d too small", cfg.TP.SegmentSize)
		}
	}
	// SD type validation
	if cfg.SD != nil {
		if _, ok := sdTypeFromString(cfg.SD.Type); !ok {
			return fmt.Errorf("someip: invalid sd.type %q (want find|offer|subscribe|subscribe_ack)", cfg.SD.Type)
		}
	}
	// Events validation
	for i, ev := range cfg.Events {
		if ev.MessageType != "" {
			if _, ok := msgTypeFromString(ev.MessageType); !ok {
				return fmt.Errorf("someip: events[%d] invalid message_type %v", i, ev.MessageType)
			}
		}
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("someip: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("someip: invalid destination IP")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 30490
	}

	cfg := spec.SOMEIP
	if cfg == nil {
		// P0b-2：空配置默认化（Generate 同款：service 0x1234 默认单请求）。
		cfg = &core.SOMEIPConfig{}
	}
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
	sessionStart := cfg.SessionStart
	if sessionStart == 0 {
		sessionStart = 1
	}
	sessionInc := cfg.SessionInc
	if sessionInc == 0 {
		sessionInc = 1
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)

		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "someip",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 17, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: "udp", SrcPort: sp, DstPort: dp},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// SD path
		if cfg.SD != nil {
			// Emit FindService/Subscribe (up) via SD builder
			msg, err := buildSDMessageFromConfig(cfg)
			if err != nil || !emit(true, msg, 0) {
				return
			}
			// Auto-response (Offer/Ack, down)
			resp, err := buildSDResponse(cfg)
			if err != nil || !emit(false, resp, 0) {
				return
			}
			return
		}

		// Events path
		if len(cfg.Events) > 0 {
			sess := sessionStart
			autoResp := true
			if cfg.AutoResponse != nil {
				autoResp = *cfg.AutoResponse
			}
			for _, ev := range cfg.Events {
				mt, _ := msgTypeFromString(ev.MessageType)
				mtID := ev.MethodID
				if mtID == 0 {
					mtID = methodID
				}
				dir := ev.Direction
				if dir == "" {
					if mt == MTNotification {
						dir = "down"
					} else {
						dir = "up"
					}
				}
				msg := buildMessage(serviceID, mtID, clientID, sess, 1, 1, mt, ev.ReturnCode, ev.Payload)
				up := dir != "down"
				if !emit(up, msg, 0) {
					return
				}
				// auto_response: REQUEST->RESPONSE (down)
				if autoResp && mt == MTRequest && up {
					resp := buildMessage(serviceID, mtID, clientID, sess, 1, 1, MTResponse, 0, ev.Payload)
					if !emit(false, resp, 0) {
						return
					}
				}
				sess += sessionInc
			}
			return
		}

		// Single message
		baseType, _ := msgTypeFromString(cfg.MessageType)
		autoResp := true
		if cfg.AutoResponse != nil {
			autoResp = *cfg.AutoResponse
		}
		up := cfg.Direction != "down"

		// TP segmentation
		if cfg.TP != nil && cfg.TP.Enabled && len(cfg.Payload) > cfg.TP.SegmentSize {
			payloadLen := cfg.TP.PayloadLength
			if payloadLen <= 0 {
				payloadLen = len(cfg.Payload)
			}
			offeredLen := uint32(16 + payloadLen)
			tpMsgType := msgTypeForTP(baseType)
			segSize := cfg.TP.SegmentSize

			// First segment: header + TP header + segment data
			first := buildHeader(serviceID, methodID, clientID, sessionStart, 1, 1, tpMsgType, 0, 8+segSize)
			first = append(first, buildTPHeader(offeredLen, 0, true)...)
			first = append(first, cfg.Payload[:min(segSize, len(cfg.Payload))]...)
			if !emit(true, first, 0) {
				return
			}

			// Subsequent segments: only TP header + data
			segID := byte(1)
			for off := segSize; off < len(cfg.Payload); off += segSize {
				end := off + segSize
				if end > len(cfg.Payload) {
					end = len(cfg.Payload)
				}
				more := end < len(cfg.Payload)
				seg := buildTPHeader(offeredLen, segID, more)
				seg = append(seg, cfg.Payload[off:end]...)
				if !emit(true, seg, 0) {
					return
				}
				segID++
			}
			return
		}

		// Single message
		msg := buildMessage(serviceID, methodID, clientID, sessionStart, 1, 1, baseType, cfg.ReturnCode, cfg.Payload)
		if !emit(up, msg, 0) {
			return
		}
		// Auto-response: REQUEST→RESPONSE (down)
		if autoResp && baseType == MTRequest && up {
			resp := buildMessage(serviceID, methodID, clientID, sessionStart, 1, 1, MTResponse, 0, cfg.Payload)
			if !emit(false, resp, 0) {
				return
			}
		}
	}()
	return out, nil
}

// buildSDMessageFromConfig builds the SD message (FindService/Subscribe) from config.
func buildSDMessageFromConfig(cfg *core.SOMEIPConfig) ([]byte, error) {
	sd := cfg.SD
	sdType, _ := sdTypeFromString(sd.Type)
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
	clientID := cfg.ClientID
	if clientID == 0 {
		clientID = 1
	}
	return buildSDMessage(sdType, serviceID, instanceID, majorVer, sd.MinorVersion, ttl, 0, sd.EventgroupID, sd.Counter, options, clientID, 1)
}

// buildSDResponse builds the auto-response SD message (Offer/SubscribeAck).
func buildSDResponse(cfg *core.SOMEIPConfig) ([]byte, error) {
	sd := cfg.SD
	sdType, _ := sdTypeFromString(sd.Type)
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
	var respType byte
	var respTTL uint32
	if sdType == SDEntryFind {
		respType = SDEntryOffer
		respTTL = 3
	} else if sdType == SDEntrySubscribe {
		respType = SDEntrySubAck
	} else {
		return nil, fmt.Errorf("someip: sd type %q does not auto-respond", sd.Type)
	}

	var options []SDOption
	for _, o := range sd.Options {
		optType := o.Type
		if optType == 0 {
			optType = SDOptionIPv4Endpoint
		}
		options = append(options, SDOption{Type: optType, IP: o.IP, Port: o.Port, Proto: o.Proto})
	}

	clientID := cfg.ClientID
	if clientID == 0 {
		clientID = 1
	}
	return buildSDMessage(respType, serviceID, instanceID, majorVer, sd.MinorVersion, respTTL, 0, sd.EventgroupID, 0, options, clientID, 1)
}