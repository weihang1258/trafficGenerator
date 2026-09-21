package jt808

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// DefaultTTL (默认TTL) used when spec.TTL is zero.
const DefaultTTL = 64

// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460).
const DefaultMSS = 1460

// MinMSS per RFC 879.
const MinMSS = 536

// Planner implements the JT/T 808-2019 protocol planner. A single JT808
// flow models ONE terminal session over one TCP 4-tuple (design §6A).
//
// The planner is stateless across flows — every Plan call constructs a
// fresh MsgSN cursor set, so concurrent flows never share state (design
// §7A.11 multi-terminal race-safety).
type Planner struct{}

// NewPlanner creates a new JT808 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "jt808" }

// Validate validates a JT808 flow spec's L3/L4 fields. JT808 config
// validation is performed separately via ValidateConfig (the core
// FlowSpec does not carry a JT808 pointer until the main agent wires
// the integration; rule: do NOT modify core/* files).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("jt808: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("jt808: invalid DstIP %q", spec.DstIP)
		}
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("jt808: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
	}
	return nil
}

// ValidateConfig is the standalone config validator (callable without a
// full FlowSpec, used by tests and the local Config type).
func ValidateConfig(cfg *JT808Config) error {
	if cfg == nil {
		return fmt.Errorf("jt808: nil config")
	}
	// Phone: ^\d{12}$.
	if len(cfg.Phone) != 12 {
		return fmt.Errorf("jt808: Phone %q must be 12 digits", cfg.Phone)
	}
	for i := 0; i < len(cfg.Phone); i++ {
		if cfg.Phone[i] < '0' || cfg.Phone[i] > '9' {
			return fmt.Errorf("jt808: Phone %q contains non-digit", cfg.Phone)
		}
	}
	// Version.
	if cfg.Version != "" && cfg.Version != jtcommon.Version2011 &&
		cfg.Version != jtcommon.Version2013 && cfg.Version != jtcommon.Version2019 {
		return fmt.Errorf("jt808: invalid Version %q", cfg.Version)
	}
	// EncryptFlag.
	if cfg.EncryptFlag > 1 {
		return fmt.Errorf("jt808: EncryptFlag %d must be 0 or 1", cfg.EncryptFlag)
	}
	// LicenseColor: 0,1,2,3,4,5,9 (design §5A.1).
	switch cfg.LicenseColor {
	case 0, 1, 2, 3, 4, 5, 9:
	default:
		return fmt.Errorf("jt808: LicenseColor %d invalid (allowed 0,1,2,3,4,5,9)", cfg.LicenseColor)
	}
	// LicensePlate / LicenseColor consistency.
	if cfg.LicenseColor == LicenseColorNone && cfg.LicensePlate != "" {
		return fmt.Errorf("jt808: LicenseColor=0 but LicensePlate non-empty")
	}
	// ManufacturerId: 5 ASCII bytes.
	if len(cfg.ManufacturerId) > ManufacturerIDLen {
		return fmt.Errorf("jt808: ManufacturerId length %d > %d", len(cfg.ManufacturerId), ManufacturerIDLen)
	}
	for i := 0; i < len(cfg.ManufacturerId); i++ {
		if cfg.ManufacturerId[i] > 0x7F {
			return fmt.Errorf("jt808: ManufacturerId non-ASCII at %d", i)
		}
	}
	// TerminalModel: 1-20 bytes.
	if len(cfg.TerminalModel) > TerminalModelLen {
		return fmt.Errorf("jt808: TerminalModel length %d > %d", len(cfg.TerminalModel), TerminalModelLen)
	}
	// TerminalId: 7 bytes.
	if len(cfg.TerminalId) > TerminalIDLen {
		return fmt.Errorf("jt808: TerminalId length %d > %d", len(cfg.TerminalId), TerminalIDLen)
	}
	// AuthCode: when any procedure uses ProcAuth, AuthCode must be non-empty
	// (design §7A.2 H-07, A-07). The per-procedure override pr.AuthCode can
	// supply the value, but when absent the top-level cfg.AuthCode must be
	// non-empty.
	for _, pr := range cfg.Procedures {
		if pr.Type == ProcAuth && pr.AuthCode == "" && cfg.AuthCode == "" {
			return fmt.Errorf("jt808: AuthCode is empty (design §7A.2 H-07)")
		}
	}
	// Direction: 0-359.
	for _, pr := range cfg.Procedures {
		if pr.LocationData != nil {
			if pr.LocationData.Direction >= 360 {
				return fmt.Errorf("jt808: Direction %d >= 360", pr.LocationData.Direction)
			}
			if pr.LocationData.Latitude > 90000000 {
				return fmt.Errorf("jt808: Latitude %d > 90000000", pr.LocationData.Latitude)
			}
			if pr.LocationData.Longitude > 180000000 {
				return fmt.Errorf("jt808: Longitude %d > 180000000", pr.LocationData.Longitude)
			}
		}
		// ACKFlag: 0,1,2,3 only (design §7A.10 — no 99=other).
		if pr.Type == ProcPlatformGeneralResponse || pr.Type == ProcTerminalGeneralResponse ||
			pr.Type == ProcRegistrationResponse {
			if pr.ACKFlag > 3 {
				return fmt.Errorf("jt808: ACKFlag %d invalid (allowed 0,1,2,3)", pr.ACKFlag)
			}
		}
		if pr.Type == ProcRegistrationResponse && pr.RegistrationResult != nil {
			if *pr.RegistrationResult > 4 {
				return fmt.Errorf("jt808: RegistrationResult %d invalid (allowed 0-4)", *pr.RegistrationResult)
			}
		}
	}
	return nil
}

// Plan is not supported for JT808: the engine requires a full config which
// the core FlowSpec cannot carry. Returning an empty channel here made tasks
// report "completed" with 0 packets. Callers must use PlanWithConfig.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return nil, fmt.Errorf("jt808: Plan not supported, use PlanWithConfig or a layers config")
}

// PlanWithConfig generates packet configs for a JT808 flow using the
// provided local config (decoupled from core.FlowSpec for testability).
// It emits a TCP 3-way handshake, the JT808 message sequence (each as
// one PSH-ACK payload wrapped in 0x7e), and a TCP 3-way teardown.
func (p *Planner) PlanWithConfig(ctx context.Context, spec core.FlowSpec, cfg *JT808Config) (<-chan core.PacketConfig, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("jt808-%s-%d", cfg.Phone, cfg.InitialSN)
		groupID := hashPhone(cfg.Phone)

		// Defaults.
		version := cfg.Version
		if version == "" {
			version = jtcommon.Version2019
		}
		if cfg.ManufacturerId == "" {
			cfg.ManufacturerId = "TEST"
		}
		if cfg.TerminalModel == "" {
			cfg.TerminalModel = "TG-DEMO"
		}
		if cfg.TerminalId == "" {
			cfg.TerminalId = "0000001"
		}
		phoneBCD, _ := jtcommon.BCDEncode(cfg.Phone)

		// TCP setup.
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(0)
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randUint32()
		}
		serverSeq := randUint32()
		winSize := uint16(65535)

		// MsgSN counters (design §6A.2). msgSN starts at InitialSN and
		// increments after each terminal-upstream message. platformMsgSN
		// starts at PlatformInitialSN and increments after each
		// platform-downstream message. The two are fully independent.
		msgSN := cfg.InitialSN
		platformMsgSN := cfg.PlatformInitialSN

		// Auto-binding state (design §5A M-05): 0x8001 binds to the most
		// recent terminal-upstream message; 0x0001 binds to the most
		// recent platform-downstream message; 0x0201 binds to the most
		// recent 0x8201; 0x8100 binds to the most recent 0x0100.
		var lastSentMsgId, lastSentSN uint16  // terminal-upstream
		var lastDownMsgId, lastDownSN uint16  // platform-downstream
		var lastRegisterSN uint16             // most recent 0x0100
		var lastQuerySN uint16                // most recent 0x8201

		// emitTCP sends a TCP packet config to the channel.
		emitTCP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: winSize,
			}
			if flags == 0x02 || flags == 0x12 {
				l4.TCPOptions = synOpts
			}
			cfg2 := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  payload,
				Metadata: map[string]interface{}{"group_id": groupID},
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg2:
			}
			packetIndex++
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
				emitTCP(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// emitJT808Msg builds and emits one JT808 message. direction
		// "up" = terminal→platform (uses msgSN); direction "down" =
		// platform→terminal (uses platformMsgSN).
		emitJT808Msg := func(direction string, msgID uint16, body []byte, isTerminalUpstream bool) {
			var sn uint16
			if isTerminalUpstream {
				sn = msgSN
				msgSN++ // wrap-around handled by uint16 overflow
				lastSentMsgId = msgID
				lastSentSN = sn
				if msgID == MsgTerminalRegister {
					lastRegisterSN = sn
				}
			} else {
				sn = platformMsgSN
				platformMsgSN++
				lastDownMsgId = msgID
				lastDownSN = sn
				if msgID == MsgLocationQuery {
					lastQuerySN = sn
				}
			}
			// Fragmentation path (design §7A.12 (e)): when the body
			// exceeds MaxBodyLength, split into multiple frames. The
			// per-fragment props are recomputed inside buildFragmentedFrames
			// (body length = chunk length, package flag forced to 1).
			if len(body) > jtcommon.MaxBodyLength {
				vf, _ := jtcommon.ParseVersionFlag(version)
				baseProps := uint16(vf)<<10 | uint16(cfg.EncryptFlag&0x01)<<15
				frames := buildFragmentedFrames(msgID, baseProps, phoneBCD, sn, body, jtcommon.MaxBodyLength)
				var srcMAC, dstMAC, srcIP, dstIP string
				var srcPort, dstPort uint16
				if direction == "down" {
					srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
					srcIP, dstIP = spec.DstIP, spec.SrcIP
					srcPort, dstPort = spec.DstPort, spec.SrcPort
				} else {
					srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
					srcIP, dstIP = spec.SrcIP, spec.DstIP
					srcPort, dstPort = spec.SrcPort, spec.DstPort
				}
				for _, frame := range frames {
					if direction == "down" {
						serverSeq = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, frame)
					} else {
						clientSeq = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, frame)
					}
				}
				return
			}
			props, _ := jtcommon.EncodeMsgBodyProps(len(body), version, 0, cfg.EncryptFlag)
			frame := buildSimpleFrame(msgID, props, phoneBCD, sn, body)
			var srcMAC, dstMAC, srcIP, dstIP string
			var srcPort, dstPort uint16
			if direction == "down" {
				srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
				srcIP, dstIP = spec.DstIP, spec.SrcIP
				srcPort, dstPort = spec.DstPort, spec.SrcPort
			} else {
				srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
				srcIP, dstIP = spec.SrcIP, spec.DstIP
				srcPort, dstPort = spec.SrcPort, spec.DstPort
			}
			if direction == "down" {
				serverSeq = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, frame)
			} else {
				clientSeq = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, frame)
			}
		}

		// --- TCP 3-way handshake (design §10.5) ---
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- JT808 message sequence (design §6A) ---
		for _, pr := range cfg.Procedures {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := emitProcedure(pr, cfg, emitJT808Msg, lastSentMsgId, lastSentSN, lastDownMsgId, lastDownSN, lastRegisterSN, lastQuerySN); err != nil {
				return
			}
		}

		// --- TCP 3-way teardown ---
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// emitProcedure dispatches one procedure to the appropriate builder + emit
// callback. It returns an error when the procedure body fails to build.
// Auto-binding (design §5A M-05): responses bind by MsgId match:
//   - 0x8001 → most recent terminal-upstream message
//   - 0x0001 → most recent platform-downstream message
//   - 0x0201 → most recent 0x8201
//   - 0x8100 → most recent 0x0100
func emitProcedure(pr JT808Procedure, cfg *JT808Config, emit func(string, uint16, []byte, bool),
	lastMsgId, lastSN, lastDownMsgId, lastDownSN, lastRegisterSN, lastQuerySN uint16) error {
	switch pr.Type {
	case ProcRegister:
		body, err := buildRegisterBody(cfg)
		if err != nil {
			return err
		}
		emit("up", MsgTerminalRegister, body, true)
	case ProcAuth:
		imei := cfg.IMEI
		if pr.IMEI != nil {
			imei = *pr.IMEI
		}
		sw := cfg.SoftwareVersion
		if pr.SoftwareVersion != nil {
			sw = *pr.SoftwareVersion
		}
		body, err := buildAuthBody(cfg, cfg.AuthCode, imei, sw)
		if err != nil {
			return err
		}
		emit("up", MsgTerminalAuth, body, true)
	case ProcLocationReport:
		body, err := buildLocationBody(pr.LocationData)
		if err != nil {
			return err
		}
		emit("up", MsgLocationReport, body, true)
	case ProcLocationQueryResponse:
		querySN := pr.ResponseSN
		if querySN == 0 {
			querySN = lastQuerySN // auto-bind to most recent 0x8201
		}
		body, err := buildLocationQueryResponseBody(querySN, pr.LocationData)
		if err != nil {
			return err
		}
		emit("up", MsgLocationQueryResponse, body, true)
	case ProcCancel:
		emit("up", MsgTerminalCancel, nil, true)
	case ProcHeartbeat:
		// 0x0002 终端心跳（JT/T 808 §7.2）：空体上行，保活核心型——
		// 隔离复审 F4 勘误补齐。
		emit("up", 0x0002, nil, true)
	case ProcPropertyResponse:
		body, err := buildPropertyResponseBody(pr.PropertyData)
		if err != nil {
			return err
		}
		emit("up", MsgTerminalPropertyResponse, body, true)
	case ProcPlatformGeneralResponse:
		// 0x8001 platform → terminal, ACK'ing the most recent
		// terminal-upstream message.
		respSN := pr.ResponseSN
		if respSN == 0 {
			respSN = lastSN
		}
		respMsgId := pr.ResponseMsgId
		if respMsgId == 0 {
			respMsgId = lastMsgId
		}
		body := buildGeneralResponseBody(respSN, respMsgId, pr.ACKFlag)
		emit("down", MsgPlatformGeneralResponse, body, false)
	case ProcTerminalGeneralResponse:
		// 0x0001 terminal → platform, ACK'ing the most recent
		// platform-downstream message.
		respSN := pr.ResponseSN
		if respSN == 0 {
			respSN = lastDownSN
		}
		respMsgId := pr.ResponseMsgId
		if respMsgId == 0 {
			respMsgId = lastDownMsgId
		}
		body := buildGeneralResponseBody(respSN, respMsgId, pr.ACKFlag)
		emit("up", MsgTerminalGeneralResponse, body, true)
	case ProcRegistrationResponse:
		respSN := pr.ResponseSN
		if respSN == 0 {
			respSN = lastRegisterSN
		}
		result := cfg.RegistrationResult
		if pr.RegistrationResult != nil {
			result = *pr.RegistrationResult
		}
		authCode := cfg.AuthCode
		if pr.AuthCode != "" {
			authCode = pr.AuthCode
		}
		body, err := buildRegistrationResponseBody(respSN, result, authCode)
		if err != nil {
			return err
		}
		emit("down", MsgRegistrationResponse, body, false)
	case ProcSetParams:
		body, err := buildSetParamsBody(pr.Params)
		if err != nil {
			return err
		}
		emit("down", MsgSetTerminalParams, body, false)
	case ProcQueryParams:
		emit("down", MsgQueryTerminalParams, nil, false)
	case ProcQueryLocation:
		emit("down", MsgLocationQuery, nil, false)
	case ProcTextDown:
		body, err := buildTextDownBody(pr.TextFlag, pr.Text)
		if err != nil {
			return err
		}
		emit("down", MsgTextDown, body, false)
	default:
		return fmt.Errorf("jt808: unknown procedure type %q", pr.Type)
	}
	return nil
}

// hashPhone computes a stable GroupID from Phone (design §6A.2). Uses
// FNV-1a for simplicity; the exact hash is not wire-visible.
func hashPhone(phone string) string {
	h := uint32(2166136261)
	for i := 0; i < len(phone); i++ {
		h ^= uint32(phone[i])
		h *= 16777619
	}
	return fmt.Sprintf("jt808-%08x", h)
}

// randUint32 returns a random uint32 for ISN generation.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42
	}
	return uint32(n.Uint64())
}

// synOptions builds TCP options for SYN packets (matching socks5/gbt32960).
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

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
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
