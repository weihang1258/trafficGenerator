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
	// V2: Session ID must be valid — a session that cannot increment
	// (session_start != 0 && session_inc == 0) is rejected as "invalid session_id"
	// (design §9.1 V2, someip_neg_session: error_contains "invalid session_id").
	// The default single-message flow (both unset -> 0,0, defaulted to 1/1 inside
	// Plan) is legitimate and must NOT be rejected here.
	if cfg.SessionStart != 0 && cfg.SessionInc == 0 {
		return fmt.Errorf("someip: invalid session_id")
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
			// If the top-level message_type names a request (e.g. S4:
			// message_type:"request" + events:[ERROR]), emit that request FIRST,
			// without auto-response — the events carry its explicit response
			// (the ERROR uses the same session). Do NOT increment the session here:
			// the first event (the ERROR) is the response to this request and must
			// reuse its SessionID (same_as_packet). The auto-response rule below
			// applies only to REQUEST events inside the events array (S7).
			if cfg.MessageType != "" {
				top, topOK := msgTypeFromString(cfg.MessageType)
				if topOK && top == MTRequest {
					msg := buildMessage(serviceID, methodID, clientID, sess, 1, 1, MTRequest, 0, cfg.Payload)
					if !emit(true, msg, 0) {
						return
					}
				}
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
			tpMsgType := msgTypeForTP(baseType)
			segSize := cfg.TP.SegmentSize
			total := len(cfg.Payload)

			// First segment: SOME/IP header (type=0x20 TP variant) + 4B TP header
			// (offset=0, more=1) + first segSize payload bytes.
			firstData := cfg.Payload[:min(segSize, total)]
			more := len(firstData) < total
			first := buildHeader(serviceID, methodID, clientID, sessionStart, 1, 1, tpMsgType, 0, 4+len(firstData))
			first = append(first, buildTPHeader(0, more)...)
			first = append(first, firstData...)
			if !emit(true, first, 0) {
				return
			}

			// Subsequent segments: SOME/IP header + 4B TP header (offset = cumulative
			// data bytes so far, more=0 on the final segment) + segment data.
			run := len(firstData)
			for off := segSize; off < total; off += segSize {
				end := off + segSize
				if end > total {
					end = total
				}
				data := cfg.Payload[off:end]
				more := end < total
				hdr := buildHeader(serviceID, methodID, clientID, sessionStart, 1, 1, tpMsgType, 0, 4+len(data))
				hdr = append(hdr, buildTPHeader(uint32(run), more)...)
				hdr = append(hdr, data...)
				if !emit(true, hdr, 0) {
					return
				}
				run += len(data)
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
	clientID := cfg.ClientID
	if clientID == 0 {
		clientID = 1
	}
	// FindService/SubscribeEventgroup are discovery REQUESTS (typically broadcast
	// with no endpoint option); the endpoint option lives on the Offer/Ack
	// response (see buildSDResponse). So the request side emits no options.
	return buildSDMessage(sdType, serviceID, instanceID, majorVer, sd.MinorVersion, ttl, 0, sd.EventgroupID, sd.Counter, nil, clientID, 1)
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