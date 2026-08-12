// Package ntp implements the NTP (Network Time Protocol, 网络时间协议) planner.
//
// NTP is a UDP-based request/response protocol on port 123 (RFC 5905). The
// planner emits one or more PacketConfig values whose Payload carries the
// 48-byte fixed NTP header (LI/VN/Mode/Stratum/Poll/Precision + root timing
// fields + Reference ID + four 64-bit timestamps). Optional authentication
// (KeyID + MAC) and RFC 7822 extension fields append after the 48-byte header.
// Mode=6 (control, RFC 1305 App. B) uses a 12-byte control header instead.
//
// IPv6 / multicast MAC / VLAN behavior follows the cross-cutting rules:
// /tmp/l7_planner_design/multicast_ipv6_vlan.md
//
// Validate is read-only (per validate_conventions.md §1.1). Default values
// (Version=4, Mode=3, Stratum=0, Poll=6, Precision=-6, port 123) are applied
// in Plan's emit goroutine, never in Validate.
package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL is the IP TTL applied when FlowSpec.TTL is 0.
	DefaultTTL = 64

	// DefaultPort is the IANA-assigned NTP service port (RFC 5905 §7).
	DefaultPort = 123

	// NTPHeaderLen is the fixed 48-byte NTP basic header length (RFC 5905 §7.3).
	NTPHeaderLen = 48

	// NTPEpochOffset is the seconds between 1900-01-01 00:00:00 UTC (NTP
	// epoch) and 1970-01-01 00:00:00 UTC (Unix epoch). Used to convert
	// time.Time to the 32-bit NTP seconds field.
	NTPEpochOffset = 2208988800

	// ControlHeaderLen is the 12-byte Mode=6 control message header length
	// (RFC 1305 App. B / ntpd ntp_control.h: CTL_HEADER_LEN). Control packets
	// do NOT carry the 48-byte basic header. Layout:
	//	byte 0:      LI(2)|VN(3)|Mode(3)
	//	byte 1:      R(1)|E(1)|M(1)|OpCode(5)
	//	bytes 2-3:   Sequence (16-bit)
	//	bytes 4-5:   Status (16-bit)
	//	bytes 6-7:   Association ID (16-bit)
	//	bytes 8-9:   Offset (16-bit)
	//	bytes 10-11: Count (16-bit) = data length
	ControlHeaderLen = 12

	// MaxControlData is the maximum Mode=6 Data region size (ntpd
	// CTL_MAX_DATA_LEN = 468). Wireshark's dissector labels this region
	// "Data (468 octets max)".
	MaxControlData = 468

	// Mode constants (RFC 5905 §7.3).
	ModeReserved         = 0
	ModeSymmetricActive  = 1
	ModeSymmetricPassive = 2
	ModeClient           = 3
	ModeServer           = 4
	ModeBroadcast        = 5
	ModeControl          = 6
	ModePrivate          = 7

	// Version 4 (NTPv4, RFC 5905) is the default; Version 3 (NTPv3, RFC 1305)
	// is supported for compatibility.
	DefaultVersion   = 4
	DefaultMode      = ModeClient
	DefaultStratum   = 0
	DefaultPoll      = 6  // 64 seconds
	DefaultPrecision = -6 // ~15ms
)

// Planner implements the NTP protocol planner.
type Planner struct{}

// NewPlanner creates a new NTP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "ntp"
}

// Validate validates an NTP flow spec. Read-only: never mutates spec (per
// validate_conventions.md §1.1). Default values are applied in Plan's emit
// goroutine.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP addresses: accept IPv4 or IPv6 (NTP supports both per RFC 5905 §3).
	// Empty is allowed (filled by mapToFlowSpec's defaults).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("ntp: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("ntp: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// NTP config is required.
	if spec.NTP == nil {
		return fmt.Errorf("ntp: NTP config is required (set spec.ntp)")
	}

	return validateNTPConfig(spec)
}

// validateNTPConfig validates the NTP config portion of a flow spec
// (NTPConfig 非 nil、LI ≤ 3、Version 3/4、Mode 1-7、Stratum ≤ 16、MAC 长度
// 0/16/20、Extensions ≤ 65531、Mode=6 的 RequestCode ≤ 31 + ControlData
// ≤ 468)。波 4 起经 layer_gen.go 的 init 注册为 ntp 链的协议校验器，与
// legacy Validate 共用同一实现（配置部分），保证两条路径拒绝同一批 spec。
func validateNTPConfig(spec core.FlowSpec) error {
	if spec.NTP == nil {
		return fmt.Errorf("ntp: NTP config is required (set spec.ntp)")
	}
	cfg := spec.NTP

	// LeapIndicator is a 2-bit field (0-3). Values >3 cannot be encoded in
	// the header's high 2 bits without truncation, so reject at submit time.
	if cfg.LeapIndicator > 3 {
		return fmt.Errorf("ntp: LeapIndicator %d invalid (must be 0-3 per RFC 5905 §7.3)", cfg.LeapIndicator)
	}

	// Version is a 3-bit field. RFC 5905 §7.3 allows 3 (NTPv3) and 4 (NTPv4);
	// 0/1/2 are historical/obsolete, 5-7 are not assigned. Reject anything
	// other than 3 or 4.
	if cfg.Version != 3 && cfg.Version != 4 {
		return fmt.Errorf("ntp: Version %d invalid (must be 3 or 4 per RFC 5905 §7.3)", cfg.Version)
	}

	// Mode is a 3-bit field (0-7). Mode 0 is reserved (reject); 1-7 are
	// valid operational modes.
	if cfg.Mode > 7 {
		return fmt.Errorf("ntp: Mode %d invalid (must be 0-7 per RFC 5905 §7.3)", cfg.Mode)
	}
	if cfg.Mode == ModeReserved {
		return fmt.Errorf("ntp: Mode 0 reserved (must be 1-7 per RFC 5905 §7.3)")
	}

	// Stratum is 0-16. 0=unspecified/KoD, 1=primary, 2-15=secondary, 16=unsync.
	if cfg.Stratum > 16 {
		return fmt.Errorf("ntp: Stratum %d invalid (must be 0-16 per RFC 5905 §7.3)", cfg.Stratum)
	}

	// MAC length must be 0 (none), 16 (AES-CMAC/MD5), or 20 (SHA1) per
	// RFC 7822 §4.3. Other lengths produce malformed trailers.
	if n := len(cfg.MAC); n != 0 && n != 16 && n != 20 {
		return fmt.Errorf("ntp: MAC length %d invalid (must be 0, 16, or 20 per RFC 7822 §4.3)", n)
	}

	// RFC 7822 §4: extension field values must be 4-byte aligned. The
	// planner pads short values, so this is a soft check; reject values
	// that would overflow the 16-bit Length field (65535 - 4 header bytes).
	for i, ext := range cfg.Extensions {
		if len(ext.Value) > 65531 {
			return fmt.Errorf("ntp: Extensions[%d].Value length %d exceeds max (65531)", i, len(ext.Value))
		}
	}

	// Mode=6 control messages use a 12-byte control header (not the 48-byte
	// basic header). The Data region max is 468 bytes (ntpd CTL_MAX_DATA_LEN,
	// RFC 1305 App. B). RequestCode is a 5-bit OpCode field (max 31).
	if cfg.Mode == ModeControl {
		if cfg.RequestCode > 31 {
			return fmt.Errorf("ntp: RequestCode %d invalid (must be 0-31: OpCode is a 5-bit field per RFC 1305 App. B)", cfg.RequestCode)
		}
		if len(cfg.ControlData) > MaxControlData {
			return fmt.Errorf("ntp: ControlData length %d exceeds max %d per RFC 1305 App. B", len(cfg.ControlData), MaxControlData)
		}
	}

	return nil
}

// Plan generates packet configs for an NTP flow. Emits one or more
// PacketConfig values: a client request (Mode=3), optionally followed by a
// server response when IsResponse=true. Broadcast (Mode=5) and symmetric
// (Mode=1/2) modes emit RepeatCount packets. Control (Mode=6) emits a
// control request and optional control response.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Read needed fields once (avoid re-reading spec in the loop).
		// Per validate_conventions.md §1.5: defaults applied here, not in Validate.
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		effectiveDstPort := spec.DstPort
		if effectiveDstPort == 0 {
			effectiveDstPort = DefaultPort
		}
		// IPID seed used for deterministic ephemeral SrcPort. The IPID itself
		// is randomized each Plan call so concurrent flows don't collide.
		flowIDSeed := uint16(rand.Uint32())
		effectiveSrcPort := spec.SrcPort
		if effectiveSrcPort == 0 {
			// NTP clients use ephemeral source ports (>1024). We compute the
			// ephemeral from the flow's IPID seed so the chosen port is
			// deterministic given the seed (reproducible per process start).
			effectiveSrcPort = uint16(flowIDSeed%30000) + 30000
		}

		// Effective NTP config: shallow-copy so we can apply defaults without
		// mutating the caller's spec.NTP.
		cfg := *spec.NTP
		// Version=0 means "user did not set" -> default 4. Mode is guaranteed
		// non-zero by Validate (which rejects the reserved Mode=0).
		if cfg.Version == 0 {
			cfg.Version = DefaultVersion
		}
		// Poll=0 -> default 6 (64s). Precision=0 -> default -6 (~15ms).
		// Stratum=0 is a valid value (unspecified/KoD) so we don't default it.
		if cfg.Poll == 0 {
			cfg.Poll = DefaultPoll
		}
		if cfg.Precision == 0 {
			cfg.Precision = DefaultPrecision
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, effectiveSrcPort, effectiveDstPort)
		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// emit sends one PacketConfig on configChan. Returns false if ctx
		// was cancelled (caller should stop the loop and close the channel).
		emit := func(direction string, srcIP, dstIP, srcMAC, dstMAC string, srcPort, dstPort uint16, payload []byte) bool {
			select {
			case <-ctx.Done():
				return false
			case configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   time.Now(),
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
					VLAN:      spec.VLAN,
				},
				L3: core.L3Base(srcIP, dstIP, 17, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
				},
				Payload: payload,
			}:
				packetIndex++
				return true
			}
		}

		// Determine how many primary packets to emit. RepeatCount overrides
		// FlowSpec.Count for multi-packet modes (broadcast/symmetric/control).
		repeat := cfg.RepeatCount
		if repeat <= 0 {
			repeat = 1
		}

		switch cfg.Mode {
		case ModeClient:
			// Client mode: emit a request (Mode=3). If IsResponse, follow
			// with a server response (Mode=4) whose OriginTS echoes the
			// request's TransmitTS.
			var requestTransmitTS time.Time
			for i := 0; i < repeat; i++ {
				if i > 0 {
					requestTransmitTS = time.Time{} // reset for next iteration
				}
				payload, txTS := buildClientRequest(&cfg, now)
				requestTransmitTS = txTS
				if !emit("up", spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
				if cfg.IsResponse {
					respPayload := buildServerResponse(&cfg, now, requestTransmitTS)
					if !emit("down", spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC, effectiveDstPort, effectiveSrcPort, respPayload) {
						return
					}
				}
			}

		case ModeServer:
			// Server mode: emit a response (Mode=4). OriginTS defaults to
			// zero when the user did not set it (a real server would copy
			// from the request, but trafficgen may emit standalone).
			for i := 0; i < repeat; i++ {
				payload := buildServerResponse(&cfg, now, cfg.OriginTS)
				if !emit("down", spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC, effectiveDstPort, effectiveSrcPort, payload) {
					return
				}
			}

		case ModeBroadcast:
			// Broadcast mode: emit Mode=5 packets with Origin=0. Each packet
			// gets a distinct TransmitTS (incremented by PollInterval seconds
			// per iteration when set, else by 1 second).
			for i := 0; i < repeat; i++ {
				txTS := now.Add(time.Duration(i) * time.Duration(max(cfg.PollInterval, 1)) * time.Second)
				payload := buildBroadcast(&cfg, txTS)
				if !emit("down", spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
			}

		case ModeSymmetricActive, ModeSymmetricPassive:
			// Symmetric modes: emit peer packets. Mode=1 (active) sends
			// Mode=1; if IsResponse, also emit Mode=2 (passive) replies.
			for i := 0; i < repeat; i++ {
				txTS := now.Add(time.Duration(i) * time.Duration(max(cfg.PollInterval, 1)) * time.Second)
				payload := buildSymmetric(&cfg, txTS)
				dir := "up"
				if cfg.Mode == ModeSymmetricPassive {
					dir = "down"
				}
				if !emit(dir, spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
				if cfg.IsResponse {
					peerCfg := cfg
					peerCfg.Mode = ModeSymmetricPassive
					if cfg.Mode == ModeSymmetricPassive {
						peerCfg.Mode = ModeSymmetricActive
					}
					peerPayload := buildSymmetric(&peerCfg, txTS)
					peerDir := "down"
					if cfg.Mode == ModeSymmetricPassive {
						peerDir = "up"
					}
					if !emit(peerDir, spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC, effectiveDstPort, effectiveSrcPort, peerPayload) {
						return
					}
				}
			}

		case ModeControl:
			// Control mode (RFC 1305 App. B): emit a 12-byte control header +
			// ControlData. If IsResponse, emit a response with matching
			// Sequence and the R bit set.
			for i := 0; i < repeat; i++ {
				seq := cfg.Sequence
				if repeat > 1 {
					seq = cfg.Sequence + uint16(i)
				}
				payload := buildControlRequest(&cfg, seq)
				if !emit("up", spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
				if cfg.IsResponse {
					respPayload := buildControlResponse(&cfg, seq)
					if !emit("down", spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC, effectiveDstPort, effectiveSrcPort, respPayload) {
						return
					}
				}
			}

		case ModePrivate:
			// Private mode (Mode=7): emit a single 48-byte basic-header
			// packet (no standard semantics). Used for device identification
			// tests.
			for i := 0; i < repeat; i++ {
				payload := buildBasicHeader(&cfg, now)
				if !emit("up", spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
			}

		default:
			// Modes we do not specially handle (none -- 1-7 all covered
			// above). Fall back to a basic-header emission.
			for i := 0; i < repeat; i++ {
				payload := buildBasicHeader(&cfg, now)
				if !emit("up", spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC, effectiveSrcPort, effectiveDstPort, payload) {
					return
				}
			}
		}
	}()

	return configChan, nil
}

// buildClientRequest builds a Mode=3 client request. OriginTS=0 (client has
// not yet sent anything), ReceiveTS=0 (client has not received anything),
// TransmitTS=now (or user-provided). Returns the payload and the transmit
// timestamp used (so the response can echo it as OriginTS).
func buildClientRequest(cfg *core.NTPConfig, now time.Time) ([]byte, time.Time) {
	txTS := cfg.TransmitTS
	if txTS.IsZero() {
		txTS = now
	}
	// Client request: Origin=0, Receive=0, Reference=0 (unless user set).
	originTS := cfg.OriginTS
	receiveTS := cfg.ReceiveTS
	refTS := cfg.RefTimestamp
	payload := buildNTPPacket(cfg, refTS, originTS, receiveTS, txTS)
	return payload, txTS
}

// buildServerResponse builds a Mode=4 server response. OriginTS echoes the
// request's TransmitTS; ReceiveTS=now (server just received); TransmitTS=now
// (server sends now); ReferenceTS=user-provided (or zero).
func buildServerResponse(cfg *core.NTPConfig, now time.Time, requestTransmit time.Time) []byte {
	originTS := requestTransmit
	if !cfg.OriginTS.IsZero() {
		originTS = cfg.OriginTS
	}
	receiveTS := cfg.ReceiveTS
	if receiveTS.IsZero() {
		receiveTS = now
	}
	txTS := cfg.TransmitTS
	if txTS.IsZero() {
		txTS = now
	}
	return buildNTPPacket(cfg, cfg.RefTimestamp, originTS, receiveTS, txTS)
}

// buildBroadcast builds a Mode=5 broadcast packet. Origin=0, Receive=0,
// Transmit=txTS (caller-supplied, increments per packet for repeats).
func buildBroadcast(cfg *core.NTPConfig, txTS time.Time) []byte {
	return buildNTPPacket(cfg, cfg.RefTimestamp, time.Time{}, time.Time{}, txTS)
}

// buildSymmetric builds a Mode=1/2 symmetric packet. Uses user-provided
// timestamps or zero (the planner does not simulate state exchanges).
func buildSymmetric(cfg *core.NTPConfig, txTS time.Time) []byte {
	originTS := cfg.OriginTS
	receiveTS := cfg.ReceiveTS
	return buildNTPPacket(cfg, cfg.RefTimestamp, originTS, receiveTS, txTS)
}

// buildBasicHeader builds a 48-byte basic header with the given transmit
// timestamp. Used for Mode=7 (private) and as a fallback.
func buildBasicHeader(cfg *core.NTPConfig, txTS time.Time) []byte {
	return buildNTPPacket(cfg, cfg.RefTimestamp, cfg.OriginTS, cfg.ReceiveTS, txTS)
}

// buildNTPPacket builds a 48-byte NTP basic header (RFC 5905 §7.3) plus
// optional KeyID/MAC/Extensions. All multi-byte fields are network byte order
// (big-endian). Timestamps use the NTP 1900 epoch (32-bit seconds + 32-bit
// fraction). Zero time.Time values encode as 0x0000000000000000.
func buildNTPPacket(cfg *core.NTPConfig, refTS, originTS, receiveTS, transmitTS time.Time) []byte {
	// Compute total length: 48-byte header + optional extension fields +
	// optional KeyID (4 bytes) + optional MAC (16 or 20 bytes).
	extLen := 0
	for _, ext := range cfg.Extensions {
		vLen := len(ext.Value)
		// RFC 7822 §4: extension value padded to 4-byte boundary. The Length
		// field counts the 4-byte header + padded value.
		padded := (vLen + 3) &^ 3
		extLen += 4 + padded
	}
	trailerLen := 0
	if cfg.KeyID != 0 || len(cfg.MAC) > 0 {
		trailerLen += 4 // KeyID
		trailerLen += len(cfg.MAC)
	}
	totalLen := NTPHeaderLen + extLen + trailerLen

	buf := make([]byte, totalLen)

	// Byte 0: LI(2) | VN(3) | Mode(3)
	buf[0] = (cfg.LeapIndicator << 6) | ((cfg.Version & 0x07) << 3) | (cfg.Mode & 0x07)
	// Byte 1: Stratum
	buf[1] = cfg.Stratum
	// Byte 2: Poll (int8, encoded as the byte's two's-complement representation)
	buf[2] = byte(cfg.Poll)
	// Byte 3: Precision (int8)
	buf[3] = byte(cfg.Precision)
	// Bytes 4-7: Root Delay (16.16 fixed-point, big-endian)
	binary.BigEndian.PutUint32(buf[4:8], secondsToFixed16_16(cfg.RootDelay))
	// Bytes 8-11: Root Dispersion (16.16 fixed-point)
	binary.BigEndian.PutUint32(buf[8:12], secondsToFixed16_16(cfg.RootDispersion))
	// Bytes 12-15: Reference ID (uint32, big-endian)
	binary.BigEndian.PutUint32(buf[12:16], cfg.ReferenceID)
	// Bytes 16-23: Reference Timestamp (64-bit NTP)
	binary.BigEndian.PutUint64(buf[16:24], timeToNTPTimestamp(refTS))
	// Bytes 24-31: Origin Timestamp
	binary.BigEndian.PutUint64(buf[24:32], timeToNTPTimestamp(originTS))
	// Bytes 32-39: Receive Timestamp
	binary.BigEndian.PutUint64(buf[32:40], timeToNTPTimestamp(receiveTS))
	// Bytes 40-47: Transmit Timestamp
	binary.BigEndian.PutUint64(buf[40:48], timeToNTPTimestamp(transmitTS))

	// Optional extension fields (RFC 7822 §4): Type(2) + Length(2) + Value(padded)
	offset := NTPHeaderLen
	for _, ext := range cfg.Extensions {
		vLen := len(ext.Value)
		padded := (vLen + 3) &^ 3
		binary.BigEndian.PutUint16(buf[offset:offset+2], ext.Type)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], uint16(4+padded))
		copy(buf[offset+4:offset+4+vLen], ext.Value)
		// Padding bytes already zero from make()
		offset += 4 + padded
	}

	// Optional KeyID + MAC trailer
	if cfg.KeyID != 0 || len(cfg.MAC) > 0 {
		binary.BigEndian.PutUint32(buf[offset:offset+4], cfg.KeyID)
		offset += 4
		copy(buf[offset:offset+len(cfg.MAC)], cfg.MAC)
	}

	return buf
}

// buildControlRequest builds a 12-byte Mode=6 control header (RFC 1305 App. B
// / ntpd ntp_control.h struct ntp_control) followed by ControlData. The
// control header layout (all multi-byte fields big-endian):
//
//	byte 0:      LI(2) | VN(3) | Mode(3)   -- standard NTP byte 0 (RFC 5905
//	             §7.3); Mode=6 in the low 3 bits, VN holds the NTP version
//	             (3 or 4), LI holds the leap indicator.
//	byte 1:      R(1) | E(1) | M(1) | OpCode(5)
//	             R=Response (set on responses, clear on requests),
//	             E=Error, M=More (fragmented response),
//	             OpCode = 5-bit request code (cfg.RequestCode, 0-31).
//	bytes 2-3:   Sequence (16-bit, request/response pairing)
//	bytes 4-5:   Status (16-bit status word)
//	bytes 6-7:   Association ID (16-bit)
//	bytes 8-9:   Offset (16-bit, data offset for fragmented responses)
//	bytes 10-11: Count (16-bit) = Data region length
//	bytes 12+:   Data (ControlData, length = Count)
//
// Wireshark's dissect_ntp_ctrl reads exactly this 12-byte layout. An earlier
// revision emitted an 8-byte header (Sequence at byte 1, no AssocID/Offset,
// Count at bytes 6-7), which Wireshark reported as [Malformed Packet: NTP].
//
// Note: cfg.Implementation is retained for API compatibility but is NOT
// emitted -- RFC 1305 App. B has no Implementation byte; the 5-bit OpCode
// subsumes the old implementation/request-code split.
func buildControlRequest(cfg *core.NTPConfig, seq uint16) []byte {
	dataLen := len(cfg.ControlData)
	totalLen := ControlHeaderLen + dataLen
	buf := make([]byte, totalLen)
	// Byte 0: LI(2) | VN(3) | Mode(3). LI=user-provided, VN=cfg.Version
	// (3 or 4), Mode=6 (control).
	buf[0] = ((cfg.LeapIndicator & 0x03) << 6) | ((cfg.Version & 0x07) << 3) | (ModeControl & 0x07)
	// Byte 1: R(1) | E(1) | M(1) | OpCode(5). Requests have R=0.
	flags2 := byte(0)
	if cfg.Error {
		flags2 |= 0x40
	}
	if cfg.More {
		flags2 |= 0x20
	}
	flags2 |= cfg.RequestCode & 0x1F
	buf[1] = flags2
	// Bytes 2-3: Sequence (16-bit, big-endian).
	binary.BigEndian.PutUint16(buf[2:4], seq)
	// Bytes 4-5: Status word (16-bit). Error/More bits live in byte 1, not
	// here, per RFC 1305 App. B.
	binary.BigEndian.PutUint16(buf[4:6], cfg.StatusWord)
	// Bytes 6-7: Association ID.
	binary.BigEndian.PutUint16(buf[6:8], cfg.AssociationID)
	// Bytes 8-9: Offset.
	binary.BigEndian.PutUint16(buf[8:10], cfg.Offset)
	// Bytes 10-11: Count = data length.
	binary.BigEndian.PutUint16(buf[10:12], uint16(dataLen))
	// Bytes 12+: Data.
	copy(buf[12:], cfg.ControlData)
	return buf
}

// buildControlResponse builds a Mode=6 control response with matching
// Sequence. Same 12-byte layout as the request, but the R bit (byte 1 bit 7)
// is set to mark it as a response. Error/More/StatusWord come from the config
// (the planner does not simulate state machine transitions).
func buildControlResponse(cfg *core.NTPConfig, seq uint16) []byte {
	// Set the Response bit. Mutate a local copy so we do not alter the
	// caller's config (cfg is already a shallow copy from Plan's emit
	// goroutine, but be defensive).
	local := *cfg
	// Build the flags byte with R=1, then preserve E/M/OpCode from cfg.
	flags2 := byte(0x80) // R=1 (response)
	if cfg.Error {
		flags2 |= 0x40
	}
	if cfg.More {
		flags2 |= 0x20
	}
	flags2 |= cfg.RequestCode & 0x1F
	// Reuse buildControlRequest's body layout, then overwrite byte 1.
	payload := buildControlRequest(&local, seq)
	payload[1] = flags2
	return payload
}

// timeToNTPTimestamp converts a time.Time to a 64-bit NTP timestamp (32-bit
// seconds since 1900-01-01 UTC + 32-bit fraction). Zero time returns 0.
// Per RFC 5905 §7.3: seconds field wraps at 2^32 (2036-02-07 06:28:16 UTC,
// "era 1" begins); we emit the low 32 bits without era tracking.
func timeToNTPTimestamp(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	secs := uint64(t.Unix()) + NTPEpochOffset
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return (secs << 32) | frac
}

// secondsToFixed16_16 converts a float64 second count to a 16.16 fixed-point
// uint32 (RFC 5905 §7.3: high 16 bits = whole seconds, low 16 bits = 1/65536
// second units). Negative values are clamped to 0 (Root Delay/Dispersion are
// non-negative in practice).
func secondsToFixed16_16(seconds float64) uint32 {
	if seconds <= 0 {
		return 0
	}
	whole := uint32(seconds)
	frac := uint32((seconds - float64(whole)) * 65536.0)
	return (whole << 16) | (frac & 0xFFFF)
}

// max returns the larger of a or b. Used for PollInterval floor.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
