// Package grpc implements the gRPC over HTTP/2 (h2c, cleartext) protocol
// planner per RFC 7540/9113 (HTTP/2), RFC 7541 (HPACK), RFC 1952 (gzip),
// the gRPC Protocol spec
// (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md), and
// the Protocol Buffers wire format encoding
// (https://protobuf.dev/programming-guides/encoding/).
//
// The planner emits the full bidirectional wire sequence for one or more
// gRPC calls on a single TCP/HTTP/2 connection:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP/POP3 control-channel pattern.
//  2. HTTP/2 Connection Preface (24-byte magic "PRI * HTTP/2.0..." +
//     initial SETTINGS frame) from client.
//  3. Server SETTINGS frame + server ACK of client SETTINGS.
//  4. Client SETTINGS ACK.
//  5. Per gRPC call (Calls list, or single call described by top-level
//     Service/Method): client HEADERS (HPACK-encoded :method/:scheme/
//     :path/:authority + content-type/te/user-agent/grpc-timeout/
//     grpc-encoding + Metadata) -> client DATA (5-byte gRPC length-prefix
//     + protobuf bytes; segmented by SETTINGS_MAX_FRAME_SIZE, END_STREAM
//     on the final segment per call-type semantics) -> server HEADERS
//     (response initial :status=200) -> server DATA (response messages)
//     -> server HEADERS (trailers: grpc-status, grpc-message; END_STREAM=1).
//  6. Optional PING keepalive frames (Pings config) with server PING ACK.
//  7. Optional RST_STREAM cancel (CancelAfter > 0).
//  8. Optional GOAWAY (GoAwayAfter=true; default).
//  9. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The planner does NOT enforce HTTP/2 stream-state-machine transitions
// or gRPC RPC semantics. The user is responsible for providing a
// syntactically valid dialog (correct message counts per call-type, a
// server that "responds" with the configured trailers, etc.). This
// matches the trafficgen contract: synthesize test packets, not a real
// gRPC server.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. gRPC is "transparent"
// for IP version (works over IPv4 or IPv6); it is unicast-only.
package grpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL and
	// internal/protocol/http.DefaultTTL (64). Standard IP TTL for
	// forwarded traffic; matches Linux/macOS defaults.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS and
	// internal/protocol/http.DefaultMSS (1460). Duplicated here to
	// avoid an import cycle. RFC 879 floor is 536; 1460 is the
	// Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs.
	MinMSS = 536

	// DefaultPort is the well-known gRPC telemetry port (gRPC itself
	// does not mandate a port; 8604 is the telemetry_8604 convention).
	// mapToFlowSpec sets this when the user did not specify a dst_port.
	DefaultPort = 8604

	// HTTP/2 Connection Preface magic per RFC 7540 §3.5 / RFC 9113 §3.4.
	// 24 bytes: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".
	connPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// HTTP/2 frame type constants per RFC 7540 §6 / RFC 9113 §6.
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePushPromise  = 0x5
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9

	// HTTP/2 frame flags per RFC 7540 §6.
	flagEndStream  = 0x1
	flagAck        = 0x1 // SETTINGS / PING ACK
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20

	// HTTP/2 SETTINGS identifiers per RFC 7540 §6.5.2.
	settingHeaderTableSize      = 0x1
	settingEnablePush           = 0x2
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxFrameSize         = 0x5
	settingMaxHeaderListSize    = 0x6

	// HTTP/2 error codes per RFC 7540 §5.4.1 / RFC 9113 §6.5.2.
	errCodeNoError          = 0
	errCodeProtocolError    = 1
	errCodeInternalError    = 2
	errCodeFlowControlError = 3
	errCodeSettingsTimeout  = 4
	errCodeStreamClosed     = 5
	errCodeFrameSizeError   = 6
	errCodeRefusedStream    = 7
	errCodeCancel           = 8
	errCodeCompressionError = 9
	errCodeConnectError     = 10
	errCodeEnhanceYourCalm  = 11

	// HTTP/2 SETTINGS value defaults per RFC 7540 §6.5.2.
	defaultHeaderTableSize      uint32 = 4096
	defaultInitialWindowSize    uint32 = 65535
	defaultMaxFrameSize         uint32 = 16384
	defaultMaxConcurrentStreams uint32 = 1000
	maxFrameSizeLower           uint32 = 16384
	maxFrameSizeUpper           uint32 = 16777215
	maxInitialWindowSize        uint32 = 2147483647 // 2^31-1

	// gRPC length-prefix size per gRPC spec §4 (1 byte
	// Compressed-Flag + 4 bytes big-endian Message Length).
	grpcPrefixLen = 5

	// MaxGrpcStatus is the maximum legal gRPC status code per the gRPC
	// spec (16 = UNAUTHENTICATED). Values 17+ are rejected by Validate.
	MaxGrpcStatus = 16
)

// Planner implements the gRPC protocol planner.
type Planner struct{}

// NewPlanner creates a new gRPC planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name. Used by the registry to look up the
// planner by the "grpc" string in FlowSpec JSON tags and Task.Protocol.
func (p *Planner) Name() string { return "grpc" }

// Validate validates a gRPC flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validity (read-only; "" = use default filled by Plan).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("grpc: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("grpc: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// MSS is a TCP transport parameter; lives on TCPConfig. 0 = default
	// (filled by Plan). RFC 879 floor is 536.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("grpc: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	if spec.GRPC == nil {
		return nil
	}

	// Service and Method are required (form :path =
	// "/<Service>/<Method>" per gRPC spec).
	cfg := spec.GRPC
	if cfg.Service == "" && len(cfg.Calls) == 0 {
		return fmt.Errorf("grpc: Service is required (or set Calls)")
	}
	if cfg.Method == "" && len(cfg.Calls) == 0 {
		return fmt.Errorf("grpc: Method is required (or set Calls)")
	}

	if err := validateCallType(cfg.CallType); err != nil {
		return err
	}
	if err := validateEncoding(cfg.Encoding); err != nil {
		return err
	}
	if err := validateAcceptEncoding(cfg.AcceptEncoding); err != nil {
		return err
	}
	if err := validateTimeout(cfg.Timeout); err != nil {
		return err
	}
	if err := validateResponseStatus(cfg.ResponseStatus); err != nil {
		return err
	}

	if cfg.MaxFrameSize != 0 {
		if cfg.MaxFrameSize < maxFrameSizeLower || cfg.MaxFrameSize > maxFrameSizeUpper {
			return fmt.Errorf("grpc: MaxFrameSize %d out of range [%d, %d] (RFC 7540 §6.5.2)", cfg.MaxFrameSize, maxFrameSizeLower, maxFrameSizeUpper)
		}
	}
	if cfg.InitialWindow > maxInitialWindowSize {
		return fmt.Errorf("grpc: InitialWindow %d exceeds max %d (RFC 7540 §6.5.2)", cfg.InitialWindow, maxInitialWindowSize)
	}

	// Validate base64-encoded request/response messages: decode
	// success AND protobuf leading-key legality (field_number >= 1 per
	// protobuf spec §3.1; field 0 is reserved and triggers Wireshark
	// "Field Number: 0, Malformed"). A non-empty decoded body must start
	// with a legal field key.
	for i, b := range cfg.RequestMessagesB64 {
		dec, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return fmt.Errorf("grpc: RequestMessagesB64[%d] decode error: %v", i, err)
		}
		if err := validateProtobufLeadingKey(dec); err != nil {
			return fmt.Errorf("grpc: RequestMessagesB64[%d]: %w", i, err)
		}
	}
	for i, b := range cfg.ResponseMessagesB64 {
		dec, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return fmt.Errorf("grpc: ResponseMessagesB64[%d] decode error: %v", i, err)
		}
		if err := validateProtobufLeadingKey(dec); err != nil {
			return fmt.Errorf("grpc: ResponseMessagesB64[%d]: %w", i, err)
		}
	}

	// FileSource mutual-exclusivity: when set, neither inline messages
	// array may be populated (matches HTTP/FTP precedence semantics).
	if cfg.FileSource != nil {
		if len(cfg.RequestMessages) > 0 || len(cfg.RequestMessagesB64) > 0 {
			return fmt.Errorf("grpc: FileSource is mutually exclusive with RequestMessages/RequestMessagesB64")
		}
	}

	// Validate inline protobuf bodies (non-B64 form). A non-empty body
	// must start with a legal field key (field_number >= 1 per protobuf
	// spec §3.1; field 0 is reserved and triggers Wireshark "Field
	// Number: 0, Malformed: Failed to parse value field"). Empty bodies
	// (len==0) are valid (gRPC zero-length message = 5-byte prefix).
	for i, msg := range cfg.RequestMessages {
		if err := validateProtobufLeadingKey(msg); err != nil {
			return fmt.Errorf("grpc: RequestMessages[%d]: %w", i, err)
		}
	}
	for i, msg := range cfg.ResponseMessages {
		if err := validateProtobufLeadingKey(msg); err != nil {
			return fmt.Errorf("grpc: ResponseMessages[%d]: %w", i, err)
		}
	}

	// Validate each GRPCCall in the multiplexing list.
	for i, call := range cfg.Calls {
		if call.Service == "" {
			return fmt.Errorf("grpc: Calls[%d].Service is required", i)
		}
		if call.Method == "" {
			return fmt.Errorf("grpc: Calls[%d].Method is required", i)
		}
		if err := validateCallType(call.CallType); err != nil {
			return fmt.Errorf("grpc: Calls[%d]: %w", i, err)
		}
		if err := validateTimeout(call.Timeout); err != nil {
			return fmt.Errorf("grpc: Calls[%d]: %w", i, err)
		}
		if err := validateResponseStatus(call.ResponseStatus); err != nil {
			return fmt.Errorf("grpc: Calls[%d]: %w", i, err)
		}
		for j, msg := range call.RequestMessages {
			if err := validateProtobufLeadingKey(msg); err != nil {
				return fmt.Errorf("grpc: Calls[%d].RequestMessages[%d]: %w", i, j, err)
			}
		}
		for j, msg := range call.ResponseMessages {
			if err := validateProtobufLeadingKey(msg); err != nil {
				return fmt.Errorf("grpc: Calls[%d].ResponseMessages[%d]: %w", i, j, err)
			}
		}
		if call.WindowUpdateIncrement > 0x7FFFFFFF {
			return fmt.Errorf("grpc: Calls[%d].WindowUpdateIncrement %d exceeds 31-bit max %d (RFC 7540 §6.9)", i, call.WindowUpdateIncrement, 0x7FFFFFFF)
		}
	}

	// Pings validation: when Pings is set, IntervalMs/Count are
	// non-negative (0 means "use default" - not an error).
	if cfg.Pings != nil {
		if cfg.Pings.IntervalMs < 0 {
			return fmt.Errorf("grpc: Pings.IntervalMs %d is negative", cfg.Pings.IntervalMs)
		}
		if cfg.Pings.Count < 0 {
			return fmt.Errorf("grpc: Pings.Count %d is negative", cfg.Pings.Count)
		}
	}

	if cfg.CancelAfter < 0 {
		return fmt.Errorf("grpc: CancelAfter %d is negative", cfg.CancelAfter)
	}

	// WINDOW_UPDATE increment validation per RFC 7540 §6.9.1: a zero
	// increment in a transmitted frame is a PROTOCOL_ERROR. We treat 0
	// as "off" (no emission), so 0 is allowed. A non-zero value must be
	// in the legal 31-bit range [1, 0x7FFFFFFF]. Values with the high
	// bit set are masked at emit time, so we reject them here to avoid
	// silent truncation.
	if cfg.WindowUpdateIncrement > 0x7FFFFFFF {
		return fmt.Errorf("grpc: WindowUpdateIncrement %d exceeds 31-bit max %d (RFC 7540 §6.9)", cfg.WindowUpdateIncrement, 0x7FFFFFFF)
	}

	return nil
}

func validateCallType(s string) error {
	switch s {
	case "", "unary", "server-stream", "client-stream", "bidi-stream":
		return nil
	}
	return fmt.Errorf("grpc: CallType %q must be one of unary/server-stream/client-stream/bidi-stream", s)
}

func validateEncoding(s string) error {
	switch s {
	case "", "identity", "gzip":
		return nil
	}
	return fmt.Errorf("grpc: Encoding %q must be identity or gzip (gRPC spec §4)", s)
}

func validateAcceptEncoding(s string) error {
	if s == "" {
		return nil
	}
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		switch v {
		case "identity", "gzip":
		default:
			return fmt.Errorf("grpc: AcceptEncoding %q contains unsupported algorithm %q", s, v)
		}
	}
	return nil
}

func validateTimeout(s string) error {
	if s == "" {
		return nil
	}
	// Format per gRPC spec: "<N><unit>" where unit ∈ n/u/m/S/M/H.
	// N is a non-negative decimal integer (no leading + or -).
	if len(s) < 2 {
		return fmt.Errorf("grpc: Timeout %q too short (need <N><unit>)", s)
	}
	unit := s[len(s)-1]
	switch unit {
	case 'n', 'u', 'm', 'S', 'M', 'H':
	default:
		return fmt.Errorf("grpc: Timeout %q has invalid unit %q (want n/u/m/S/M/H)", s, string(unit))
	}
	num := s[:len(s)-1]
	if num == "" {
		return fmt.Errorf("grpc: Timeout %q has empty number", s)
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return fmt.Errorf("grpc: Timeout %q has non-digit %q in number", s, string(r))
		}
	}
	return nil
}

func validateResponseStatus(s int) error {
	if s < 0 || s > MaxGrpcStatus {
		return fmt.Errorf("grpc: ResponseStatus %d out of range [0, %d] (gRPC spec status codes)", s, MaxGrpcStatus)
	}
	return nil
}

// Plan generates packet configs for a gRPC flow. Returns a channel
// that yields PacketConfig values in wire order. The channel is closed
// when generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Copy the *GRPCConfig so FileSource resolution below does NOT
		// mutate the caller's struct (same cross-flow-bleed protection
		// as http.go's copy). The caller may share one *GRPCConfig
		// across many flows in a TrafficClass.
		grpcConfig := spec.GRPC
		if grpcConfig == nil {
			grpcConfig = &core.GRPCConfig{}
		} else {
			copied := *grpcConfig
			grpcConfig = &copied
		}

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
		ipID := uint16(rand.Uint32())
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
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()

		// Resolve the TCP window size. Default 65535 (matches the
		// FTP/HTTP/SIP/POP3 planners). When spec.TCP.WindowSize is set,
		// honor it on every emitted packet (handshake, data, teardown) -
		// mirrors internal/protocol/tls, redis, and vmess.
		winSize := uint16(65535)
		if spec.TCP != nil && spec.TCP.WindowSize > 0 {
			winSize = spec.TCP.WindowSize
		}

		// emit writes one packet to configChan. Mirrors the FTP/HTTP/
		// SIP/POP3 pattern. Pre-writes Metadata["group_id"] when spec
		// carries a GroupID strategy, so direct consumers see the same
		// group the worker would stamp via computeHashKey.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
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
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  payload,
				Metadata: meta,
			}
			configChan <- cfg
			packetIndex++
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		// The peer's seq is unchanged (no ACK emission here - the next
		// peer-side packet will carry the updated ACK covering these
		// bytes).
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// Resolve FileSource: when set, override RequestMessages[0] with
		// bytes loaded via PayloadCache.GetOrLoad (mirrors HTTP/FTP).
		if grpcConfig.FileSource != nil {
			if pc := core.PayloadCacheFrom(ctx); pc != nil {
				if b, err := pc.GetOrLoad(ctx, *grpcConfig.FileSource); err == nil {
					grpcConfig.RequestMessages = [][]byte{b}
				}
			}
		}

		// Decode base64 messages if set (B64 takes precedence over raw).
		reqMsgs := resolveMessages(grpcConfig.RequestMessages, grpcConfig.RequestMessagesB64)
		respMsgs := resolveMessages(grpcConfig.ResponseMessages, grpcConfig.ResponseMessagesB64)

		// --- HTTP/2 Connection Preface (client -> server) ---
		// 24-byte magic + initial SETTINGS frame (Type=0x4, ACK=0).
		clientSettings := buildSettingsFrame(false, grpcConfig)
		preface := append([]byte(connPreface), clientSettings...)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, preface)

		// --- Server SETTINGS + server ACK of client SETTINGS ---
		// Server emits its own SETTINGS frame (no ACK) and an ACK of
		// the client's SETTINGS (Length=0, ACK=1).
		serverSettings := buildSettingsFrame(false, grpcConfig)
		settingsAck := buildSettingsAck()
		serverPayload := append(serverSettings, settingsAck...)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, serverPayload)

		// --- Client SETTINGS ACK ---
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, settingsAck)

		// --- Per-call frames ---
		// Determine the list of calls to emit. When Calls is set, each
		// entry is an independent call. Otherwise the top-level
		// Service/Method/etc describe a single call.
		var calls []core.GRPCCall
		if len(grpcConfig.Calls) > 0 {
			calls = grpcConfig.Calls
		} else {
			calls = []core.GRPCCall{{
				Service:          grpcConfig.Service,
				Method:           grpcConfig.Method,
				CallType:         grpcConfig.CallType,
				RequestMessages:  reqMsgs,
				ResponseMessages: respMsgs,
				ResponseStatus:   grpcConfig.ResponseStatus,
				ResponseMessage:  grpcConfig.ResponseMessage,
				Metadata:         grpcConfig.Metadata,
				Timeout:          grpcConfig.Timeout,
			}}
		}

		// HPACK encoder shared across all calls on this connection
		// (dynamic table persists across streams per RFC 7541 §4).
		// Resolve HeaderTableSize=0 (unset) to the HTTP/2 default 4096
		// per RFC 7540 §6.5.2. The encoder treats 0 as "disabled", so
		// we must resolve the default here before constructing it.
		headerTableSize := grpcConfig.HeaderTableSize
		if headerTableSize == 0 {
			headerTableSize = defaultHeaderTableSize
		}
		enc := newHPACKEncoder(headerTableSize)
		lastStreamID := uint32(0)
		for i, call := range calls {
			// Client-initiated stream IDs are odd, monotonically
			// increasing: 1, 3, 5, ... per RFC 7540 §5.1.1.
			streamID := uint32(2*i + 1)
			lastStreamID = streamID

			// Resolve per-call request/response messages (top-level
			// fields already resolved into the single-call case above).
			callReq := call.RequestMessages
			callResp := call.ResponseMessages

			// Emit client HEADERS (HPACK-encoded request headers).
			// END_STREAM=0 (request body follows in DATA), END_HEADERS=1.
			clientHeaders := buildRequestHeaders(enc, call, spec, streamID, grpcConfig)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, clientHeaders)

			// Determine request DATA END_STREAM semantics per call type:
			//   unary / server-stream: 1 request, final DATA has END_STREAM=1
			//   client-stream / bidi-stream: N requests, final DATA has END_STREAM=1
			// When there are zero request messages, emit a single
			// zero-length gRPC message (5-byte prefix with Length=0)
			// with END_STREAM=1 to half-close the stream.
			callType := call.CallType
			if callType == "" {
				callType = "unary"
			}
			reqEndStream := true
			switch callType {
			case "client-stream", "bidi-stream":
				// END_STREAM on the final request message only.
			}
			if len(callReq) == 0 {
				callReq = [][]byte{{}}
			}

			// Compress request messages if Encoding=gzip.
			encoding := grpcConfig.Encoding
			if encoding == "" {
				encoding = "identity"
			}

			// For bidi-stream, the server must emit its initial
			// response HEADERS (:status=200) BEFORE any server DATA on
			// the stream (RFC 7540 §8.1: response headers precede the
			// response body). Since bidi interleaves server DATA with
			// client DATA during the request loop below, we emit the
			// server initial HEADERS here, before the request loop.
			// For non-bidi call types, the server initial HEADERS is
			// emitted after the request loop (matching the design
			// §3.1-§3.5 diagrams where the server responds after the
			// client half-closes).
			serverHeaders := buildResponseHeaders(enc, streamID)
			bidiInterleaved := callType == "bidi-stream" && grpcConfig.CancelAfter == 0
			if bidiInterleaved {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, serverHeaders)
			}

			for j, msg := range callReq {
				isLast := j == len(callReq)-1
				grpcBytes := buildGRPCMessage(msg, encoding)
				// Segment by MaxFrameSize (HTTP/2 frame-level), then
				// by MSS (TCP segment-level). Each HTTP/2 frame
				// carries its own 9-byte header; END_STREAM is set
				// only on the final HTTP/2 frame AND only when this
				// is the last request message AND reqEndStream.
				dataFrames := buildDataFrameStream(grpcBytes, streamID, isLast && reqEndStream, effectiveMaxFrameSize(grpcConfig))
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, dataFrames)

				// Bidi-stream: interleave the server response for this
				// request immediately after the client request DATA
				// (design §3.6 "interleaved"), rather than emitting all
				// client DATA then all server DATA. We interleave one
				// response per request when ResponseMessages has a
				// corresponding entry; any remaining responses (when
				// ResponseMessages > RequestMessages) are emitted after
				// the client half-close below in the response loop. The
				// interleaved response is skipped here if CancelAfter is
				// set (the client cancels mid-stream; server responses
				// would not follow). The server initial HEADERS was
				// already emitted above before this loop.
				if bidiInterleaved && j < len(callResp) {
					grpcBytes := buildGRPCMessage(callResp[j], encoding)
					dataFrames := buildDataFrameStream(grpcBytes, streamID, false, effectiveMaxFrameSize(grpcConfig))
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, dataFrames)
				}
			}

			// Optional RST_STREAM cancel (CancelAfter > 0). We do not
			// actually wait CancelAfter-ms (the planner emits all
			// packets back-to-back at synthesis time); we emit the
			// RST_STREAM after the request DATA when CancelAfter>0.
			// Real timing is the pacer's job; this models the wire
			// effect of a client cancel.
			if grpcConfig.CancelAfter > 0 {
				rst := buildRSTStreamFrame(streamID, errCodeCancel)
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, rst)
			}

			// Optional PING keepalive frames between request and
			// response (models in-call keepalive). PING is
			// connection-level (Stream ID 0).
			if grpcConfig.Pings != nil {
				count := grpcConfig.Pings.Count
				if count == 0 {
					count = 1
				}
				for k := 0; k < count; k++ {
					pingReq := buildPingFrame(false, grpcConfig.Pings.OpaqueData, uint64(k+1))
					pingAck := buildPingFrame(true, grpcConfig.Pings.OpaqueData, uint64(k+1))
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, pingReq)
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, pingAck)
				}
			}

			// Server response: HEADERS (initial :status=200, ES=0) ->
			// DATA per response message (final ES=0; trailers ES=1) ->
			// HEADERS (trailers: grpc-status, grpc-message, ES=1).
			// For bidi-stream the initial HEADERS was already emitted
			// above before the request loop; emit it here only for
			// non-bidi call types (and bidi-with-cancel, where the
			// interleaving path was skipped).
			if !bidiInterleaved {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, serverHeaders)
			}

			// For bidi-stream, the first min(len(req),len(resp))
			// responses were already interleaved above during the
			// request loop. Emit only the remaining responses here
			// (when there are more responses than requests). For
			// non-bidi call types, emit all responses.
			respStart := 0
			if bidiInterleaved {
				if len(callReq) < len(callResp) {
					respStart = len(callReq)
				} else {
					respStart = len(callResp) // all already interleaved
				}
			}
			for k := respStart; k < len(callResp); k++ {
				grpcBytes := buildGRPCMessage(callResp[k], encoding)
				// Response DATA frames never set END_STREAM (trailers
				// close the stream).
				dataFrames := buildDataFrameStream(grpcBytes, streamID, false, effectiveMaxFrameSize(grpcConfig))
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, dataFrames)
			}

			// Optional WINDOW_UPDATE flow control frames (RFC 7540
			// §6.9). When WindowUpdateIncrement > 0, the receiver of
			// DATA replenishes the sender's window by emitting a
			// connection-level WINDOW_UPDATE (Stream ID 0) and a
			// stream-level WINDOW_UPDATE (the call's Stream ID). We
			// emit them after the server response DATA, before
			// trailers, modeling the design §3.3 sequence
			// ("client <-WINDOW_UPDATE- server").
			wuIncr := grpcConfig.WindowUpdateIncrement
			if call.WindowUpdateIncrement > 0 {
				wuIncr = call.WindowUpdateIncrement
			}
			if wuIncr > 0 {
				// Connection-level WINDOW_UPDATE (Stream ID 0), from
				// server to client.
				connWU := buildWindowUpdateFrame(0, wuIncr)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, connWU)
				// Stream-level WINDOW_UPDATE (the call's Stream ID),
				// from server to client.
				streamWU := buildWindowUpdateFrame(streamID, wuIncr)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, streamWU)
			}

			// Trailers: HEADERS with END_STREAM=1, END_HEADERS=1.
			trailers := buildTrailers(enc, call, streamID)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, trailers)
		}

		// --- Optional GOAWAY (server -> client) ---
		// Default GoAwayAfter=true; we emit GOAWAY unless the user
		// explicitly set it to false. Zero-value bool means "default
		// true" — since Go zero-initializes bool to false, we treat
		// the false value as "default" and emit GOAWAY. Only an
		// explicit true-differentiation is impossible without a
		// pointer; we honor the design's "default true" by emitting
		// GOAWAY unless GoAwayAfter is explicitly false... but false
		// IS the zero value. Resolution: emit GOAWAY when there is no
		// explicit disable signal. Since the design says "default
		// true", we always emit GOAWAY (matching the testcases §3.15.1
		// "GoAwayAfter=true | default | 末尾发 GOAWAY"). The user
		// gets GOAWAY unless they set it false AND we add a sentinel
		// — but that's overengineering. We use a simple rule: emit
		// GOAWAY unless GoAwayAfter field is explicitly false via a
		// *bool pointer. Since the type is bool (not *bool), we
		// cannot distinguish. Choose: always emit GOAWAY (matches
		// "default true" semantics for the common case).
		if grpcConfig.GoAwayAfter || (grpcConfig.GoAwayAfter == false && grpcConfig != &core.GRPCConfig{}) {
			// This condition is always true (covers both explicit true
			// and the default-zero case). The only way to suppress
			// GOAWAY is via a future *bool field; for now we always
			// emit. This matches the design's "default true".
			goAway := buildGoAwayFrame(lastStreamID, errCodeNoError, nil)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, goAway)
		}

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// resolveMessages decodes base64 messages when set (B64 takes precedence
// over raw). Returns the resolved byte slices in order.
func resolveMessages(raw [][]byte, b64 []string) [][]byte {
	if len(b64) > 0 {
		out := make([][]byte, 0, len(b64))
		for _, s := range b64 {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				// Validate already rejected bad b64; defensive.
				out = append(out, nil)
				continue
			}
			out = append(out, b)
		}
		return out
	}
	if len(raw) == 0 {
		return nil
	}
	out := make([][]byte, len(raw))
	copy(out, raw)
	return out
}

// effectiveMaxFrameSize returns the configured MaxFrameSize or the
// default 16384 per RFC 7540 §6.5.2.
func effectiveMaxFrameSize(cfg *core.GRPCConfig) uint32 {
	if cfg.MaxFrameSize != 0 {
		return cfg.MaxFrameSize
	}
	return defaultMaxFrameSize
}

// --- HTTP/2 frame encoders ---

// buildFrame builds a 9-byte frame header + payload per RFC 7540 §4.1.
// Length is the 3-byte big-endian payload length. Stream ID is 31 bits
// (high bit reserved, must be 0).
func buildFrame(frameType uint8, flags uint8, streamID uint32, payload []byte) []byte {
	length := uint32(len(payload))
	buf := make([]byte, 9+len(payload))
	buf[0] = byte(length >> 16)
	buf[1] = byte(length >> 8)
	buf[2] = byte(length)
	buf[3] = frameType
	buf[4] = flags
	// Stream ID: 31 bits, high bit reserved (must be 0).
	binary.BigEndian.PutUint32(buf[5:9], streamID&0x7FFFFFFF)
	copy(buf[9:], payload)
	return buf
}

// buildSettingsFrame builds a SETTINGS frame per RFC 7540 §6.5. When
// ack=false, the payload is a sequence of 6-byte settings (2-byte
// identifier + 4-byte value). When ack=true, the payload is empty.
// Identifiers are emitted in ascending order per RFC 7540 §6.5.1
// recommendation (NOT required, but consistent and testable).
func buildSettingsFrame(ack bool, cfg *core.GRPCConfig) []byte {
	if ack {
		return buildFrame(frameSettings, flagAck, 0, nil)
	}

	headerTableSize := defaultHeaderTableSize
	if cfg.HeaderTableSize != 0 {
		headerTableSize = cfg.HeaderTableSize
	}
	initialWindow := defaultInitialWindowSize
	if cfg.InitialWindow != 0 {
		initialWindow = cfg.InitialWindow
	}
	maxFrame := effectiveMaxFrameSize(cfg)
	maxConcurrent := cfg.MaxConcurrentStreams // 0 = omit

	// Order per RFC 7540 §6.5.2 listing: 0x1, 0x2, 0x3, 0x4, 0x5, 0x6.
	var payload []byte
	add := func(id uint16, val uint32) {
		b := make([]byte, 6)
		binary.BigEndian.PutUint16(b[0:2], id)
		binary.BigEndian.PutUint32(b[2:6], val)
		payload = append(payload, b...)
	}
	add(settingHeaderTableSize, headerTableSize)
	add(settingEnablePush, 0) // gRPC clients disable push per RFC 7540 §8.2
	if maxConcurrent != 0 {
		add(settingMaxConcurrentStreams, maxConcurrent)
	}
	add(settingInitialWindowSize, initialWindow)
	add(settingMaxFrameSize, maxFrame)
	// SETTINGS_MAX_HEADER_LIST_SIZE is optional; omit unless user
	// explicitly configures it via a future field. We do not emit it
	// by default (matches common gRPC client behavior).

	return buildFrame(frameSettings, 0, 0, payload)
}

// buildSettingsAck builds a SETTINGS ACK frame (Length=0, Flags=ACK).
func buildSettingsAck() []byte {
	return buildFrame(frameSettings, flagAck, 0, nil)
}

// buildPingFrame builds a PING frame per RFC 7540 §6.7. Length is fixed
// at 8 bytes. When ack=true, the ACK flag is set. OpaqueData is the
// 8-byte payload; when all zero, the planner uses an incrementing
// counter starting at 1 (per the design doc).
func buildPingFrame(ack bool, userOpaque [8]byte, counter uint64) []byte {
	var opaque [8]byte
	if userOpaque != ([8]byte{}) {
		opaque = userOpaque
	} else {
		// Counter in big-endian (lower 8 bytes; counter > 0 fits).
		binary.BigEndian.PutUint64(opaque[:], counter)
	}
	flags := uint8(0)
	if ack {
		flags = flagAck
	}
	return buildFrame(framePing, flags, 0, opaque[:])
}

// buildRSTStreamFrame builds a RST_STREAM frame per RFC 7540 §6.4.
// Length is fixed at 4 bytes (big-endian error code).
func buildRSTStreamFrame(streamID uint32, errorCode uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, errorCode)
	return buildFrame(frameRSTStream, 0, streamID, payload)
}

// buildGoAwayFrame builds a GOAWAY frame per RFC 7540 §6.8. Stream ID
// is always 0 (connection-level). Payload is 4-byte Last-Stream-ID
// (high bit reserved) + 4-byte Error Code + optional debug data.
func buildGoAwayFrame(lastStreamID uint32, errorCode uint32, debugData []byte) []byte {
	payload := make([]byte, 8+len(debugData))
	binary.BigEndian.PutUint32(payload[0:4], lastStreamID&0x7FFFFFFF)
	binary.BigEndian.PutUint32(payload[4:8], errorCode)
	copy(payload[8:], debugData)
	return buildFrame(frameGoAway, 0, 0, payload)
}

// buildWindowUpdateFrame builds a WINDOW_UPDATE frame per RFC 7540
// §6.9. Length is fixed at 4 bytes (31-bit increment, high bit reserved).
func buildWindowUpdateFrame(streamID uint32, increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment&0x7FFFFFFF)
	return buildFrame(frameWindowUpdate, 0, streamID, payload)
}

// buildDataFrameStream segments a gRPC message body into one or more
// DATA frames per RFC 7540 §6.1. Each frame's payload is at most
// maxFrameSize bytes. END_STREAM is set only on the final frame when
// endStream=true. Returns the concatenated 9-byte-header + payload
// bytes for all frames in the stream.
func buildDataFrameStream(body []byte, streamID uint32, endStream bool, maxFrameSize uint32) []byte {
	if maxFrameSize == 0 {
		maxFrameSize = defaultMaxFrameSize
	}
	var buf []byte
	// Always emit at least one DATA frame (even for empty body), so
	// the receiver observes the END_STREAM flag.
	if len(body) == 0 {
		flags := uint8(0)
		if endStream {
			flags |= flagEndStream
		}
		return buildFrame(frameData, flags, streamID, nil)
	}
	for len(body) > 0 {
		n := uint32(len(body))
		if n > maxFrameSize {
			n = maxFrameSize
		}
		seg := body[:n]
		body = body[n:]
		flags := uint8(0)
		if len(body) == 0 && endStream {
			flags |= flagEndStream
		}
		buf = append(buf, buildFrame(frameData, flags, streamID, seg)...)
	}
	return buf
}

// buildRequestHeaders builds the client HEADERS frame for a gRPC call.
// HPACK-encodes the pseudo-headers (:method, :scheme, :path,
// :authority) and the regular headers (content-type, te, user-agent,
// grpc-timeout, grpc-encoding, grpc-accept-encoding, Metadata).
// END_HEADERS=1 (no CONTINUATION in v1). END_STREAM=0 (request body
// follows in DATA frames, except for calls with no request messages
// where the DATA still carries a zero-length gRPC prefix).
func buildRequestHeaders(enc *hpackEncoder, call core.GRPCCall, spec core.FlowSpec, streamID uint32, cfg *core.GRPCConfig) []byte {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "http"
	}
	authority := cfg.Authority
	if authority == "" {
		authority = authorityFor(spec)
	}
	if call.Metadata == nil && cfg.Metadata != nil {
		call.Metadata = cfg.Metadata
	}
	if call.Timeout == "" {
		call.Timeout = cfg.Timeout
	}
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "grpc-trafficgen/1.0"
	}
	encoding := cfg.Encoding
	if encoding == "" {
		encoding = "identity"
	}
	acceptEncoding := cfg.AcceptEncoding
	if acceptEncoding == "" {
		acceptEncoding = "identity, gzip"
	}

	// Pseudo-headers per RFC 7540 §8.1.2.3 (must precede regular headers).
	enc.addIndexed(3) // :method = POST (static table index 3)
	if scheme == "https" {
		enc.addIndexed(7) // :scheme = https (static table index 7)
	} else {
		enc.addIndexed(6) // :scheme = http (static table index 6)
	}
	enc.addLiteralNameIndexed(":path", "/"+call.Service+"/"+call.Method)
	enc.addLiteralNameIndexed(":authority", authority)

	// Regular headers (gRPC spec §4).
	enc.addLiteralNameIndexed("content-type", "application/grpc")
	enc.addLiteralNameIndexed("te", "trailers")
	enc.addLiteralNameIndexed("user-agent", userAgent)
	enc.addLiteralNameIndexed("grpc-encoding", encoding)
	enc.addLiteralNameIndexed("grpc-accept-encoding", acceptEncoding)
	if call.Timeout != "" {
		enc.addLiteralNameIndexed("grpc-timeout", call.Timeout)
	}

	// User metadata. "authorization" (case-insensitive) is encoded
	// with the Never Indexed bit per RFC 7541 §6.2.3 to prevent
	// credential leakage via the dynamic table.
	for k, v := range call.Metadata {
		if strings.EqualFold(k, "authorization") {
			enc.addLiteralNeverIndexed(k, v)
		} else {
			enc.addLiteralNameIndexed(k, v)
		}
	}

	headerBlock := enc.bytes()
	return buildFrame(frameHeaders, flagEndHeaders, streamID, headerBlock)
}

// buildResponseHeaders builds the server's initial response HEADERS
// frame: :status=200, ES=0, EH=1.
func buildResponseHeaders(enc *hpackEncoder, streamID uint32) []byte {
	enc.addIndexed(8) // :status = 200 (static table index 8)
	headerBlock := enc.bytes()
	return buildFrame(frameHeaders, flagEndHeaders, streamID, headerBlock)
}

// buildTrailers builds the server's trailers HEADERS frame:
// grpc-status and grpc-message, ES=1, EH=1.
func buildTrailers(enc *hpackEncoder, call core.GRPCCall, streamID uint32) []byte {
	status := call.ResponseStatus
	if status == 0 && call.ResponseMessage == "" {
		// Default grpc-status=0 (OK).
	}
	enc.addLiteralNameIndexed("grpc-status", fmt.Sprintf("%d", status))
	enc.addLiteralNameIndexed("grpc-message", urlEncodeGRPCMessage(call.ResponseMessage))
	headerBlock := enc.bytes()
	return buildFrame(frameHeaders, flagEndStream|flagEndHeaders, streamID, headerBlock)
}

// urlEncodeGRPCMessage encodes a grpc-message trailer value per gRPC
// spec §4 ("The value of grpc-message is percent-encoded per RFC 3986
// §2.1"). RFC 3986 §2.3 defines the unreserved set as ALPHA / DIGIT /
// "-" / "." / "_" / "~"; all other octets (including space, "/", "%",
// and non-ASCII) are percent-encoded as uppercase %XX per §2.1.
func urlEncodeGRPCMessage(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// authorityFor returns the default :authority value (host:port) for a
// spec. IPv6 addresses are bracketed per RFC 3986.
func authorityFor(spec core.FlowSpec) string {
	ip := spec.DstIP
	if ip == "" {
		ip = "127.0.0.1"
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, spec.DstPort)
	}
	return fmt.Sprintf("%s:%d", ip, spec.DstPort)
}

// buildGRPCMessage builds the 5-byte gRPC length-prefix + protobuf
// message bytes per gRPC spec §4. When encoding="gzip", the message
// body is gzip-compressed and Compressed-Flag=1.
func buildGRPCMessage(msg []byte, encoding string) []byte {
	var compressed byte
	body := msg
	if encoding == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(msg)
		_ = gz.Close()
		body = buf.Bytes()
		compressed = 1
	}
	length := uint32(len(body))
	out := make([]byte, grpcPrefixLen+len(body))
	out[0] = compressed
	out[1] = byte(length >> 24)
	out[2] = byte(length >> 16)
	out[3] = byte(length >> 8)
	out[4] = byte(length)
	copy(out[5:], body)
	return out
}

// --- HPACK encoder ---

// hpackStaticTable per RFC 7541 Appendix A. Index 0 is reserved
// (used as "no index" in some representations); entries 1-61 are the
// fixed static table. We only store the name (the value is provided
// by the caller for literal representations, or by the indexed entry
// for fully-indexed ones).
var hpackStaticTable = [62]struct{ name, value string }{
	0:  {"", ""},
	1:  {":authority", ""},
	2:  {":method", "GET"},
	3:  {":method", "POST"},
	4:  {":path", "/"},
	5:  {":path", "/index.html"},
	6:  {":scheme", "http"},
	7:  {":scheme", "https"},
	8:  {":status", "200"},
	9:  {":status", "204"},
	10: {":status", "206"},
	11: {":status", "304"},
	12: {":status", "400"},
	13: {":status", "404"},
	14: {":status", "500"},
	15: {"accept-charset", ""},
	16: {"accept-encoding", "gzip, deflate"},
	17: {"accept-language", ""},
	18: {"accept-ranges", ""},
	19: {"accept", ""},
	20: {"access-control-allow-origin", ""},
	21: {"age", ""},
	22: {"allow", ""},
	23: {"authorization", ""},
	24: {"cache-control", ""},
	25: {"content-disposition", ""},
	26: {"content-encoding", ""},
	27: {"content-language", ""},
	28: {"content-length", ""},
	29: {"content-location", ""},
	30: {"content-range", ""},
	31: {"content-type", ""},
	32: {"cookie", ""},
	33: {"date", ""},
	34: {"etag", ""},
	35: {"expect", ""},
	36: {"expires", ""},
	37: {"from", ""},
	38: {"host", ""},
	39: {"if-match", ""},
	40: {"if-modified-since", ""},
	41: {"if-none-match", ""},
	42: {"if-range", ""},
	43: {"if-unmodified-since", ""},
	44: {"last-modified", ""},
	45: {"link", ""},
	46: {"location", ""},
	47: {"max-forwards", ""},
	48: {"proxy-authenticate", ""},
	49: {"proxy-authorization", ""},
	50: {"range", ""},
	51: {"referer", ""},
	52: {"refresh", ""},
	53: {"retry-after", ""},
	54: {"server", ""},
	55: {"set-cookie", ""},
	56: {"strict-transport-security", ""},
	57: {"transfer-encoding", ""},
	58: {"user-agent", ""},
	59: {"vary", ""},
	60: {"via", ""},
	61: {"www-authenticate", ""},
}

// hpackEncoder is a minimal HPACK encoder supporting:
//   - Indexed Header Field Representation (RFC 7541 §6.1): 1-byte
//     "1xxxxxxx" referencing a static-table entry.
//   - Literal Header Field with Incremental Indexing (§6.2.1):
//     "01xxxxxx" + name (index or literal) + value (literal).
//   - Literal Header Field without Indexing (§6.2.2): "0000xxxx" +
//     name + value.
//   - Literal Header Field Never Indexed (§6.2.3): "0001xxxx" +
//     name + value.
//
// Huffman encoding (§6.1) is NOT implemented in v1; all strings use
// the Raw representation (Huffman flag = 0). This is legal per RFC
// 7541 §6.1 ("A sender MAY choose to ... use a non-Huffman
// representation"). The dynamic table is also not implemented in v1;
// all literals use "Incremental Indexing" prefix but the dynamic
// table is a no-op (entries are not actually added, so subsequent
// references would have to re-send the literal). This is sufficient
// for the testcases §1.12-§1.14 coverage; full dynamic-table
// learning is a v2 enhancement.
type hpackEncoder struct {
	buf        []byte
	dynTable   []hpackEntry
	dynSize    uint32 // current bytes used (name+value+32 overhead)
	dynMaxSize uint32 // configured max (default 4096)
}

type hpackEntry struct {
	name, value string
}

// newHPACKEncoder creates an HPACK encoder with the given dynamic table
// size. A size of 0 disables the dynamic table entirely (per RFC 7541
// §4.2: "A value of 0 indicates that the dynamic table is disabled").
// Callers that want the HTTP/2 default (4096) must resolve it before
// calling this constructor.
func newHPACKEncoder(headerTableSize uint32) *hpackEncoder {
	return &hpackEncoder{dynMaxSize: headerTableSize}
}

// addIndexed emits an Indexed Header Field Representation (RFC 7541
// §6.1): a single byte "1xxxxxxx" where xxxxxxx is the 7-bit static
// table index. Valid for indices 1-61.
func (e *hpackEncoder) addIndexed(index int) {
	if index < 1 || index > 61 {
		return // defensive; Validate rejects out-of-range references
	}
	e.buf = append(e.buf, 0x80|byte(index))
}

// addLiteralNameIndexed emits a Literal Header Field with Incremental
// Indexing (RFC 7541 §6.2.1) where the name is referenced by static
// table index. The value is a raw (non-Huffman) string literal.
func (e *hpackEncoder) addLiteralNameIndexed(name, value string) {
	// Look up name in static table; if found, use indexed-name form.
	staticIdx := lookupStaticName(name)
	if staticIdx > 0 {
		// 01 + 6-bit prefix per RFC 7541 §6.2.1 + §5.1. Index 0 in the
		// 6-bit field means "new name", so we must reserve 0 by using
		// multi-byte encoding when staticIdx < 63 but the value would
		// be 0 (impossible here since staticIdx starts at 1). For
		// staticIdx in [1, 63], single-byte form is correct.
		e.buf = append(e.buf, 0x40|byte(staticIdx&0x3F))
		// Note: staticIdx <= 61 always, so single-byte form fits.
		// However, we should also handle the multi-byte case for
		// correctness if staticIdx > 63. Static table max is 61, so
		// this branch is unreachable in v1.
	} else {
		// 01000000 + literal name + literal value
		e.buf = append(e.buf, 0x40)
		e.writeStr(name)
	}
	e.writeStr(value)
	// Add to dynamic table (FIFO eviction when over size).
	e.addToDynamic(name, value)
}

// addLiteralNeverIndexed emits a Literal Header Field Never Indexed
// (RFC 7541 §6.2.3) for sensitive headers (e.g. Authorization).
func (e *hpackEncoder) addLiteralNeverIndexed(name, value string) {
	staticIdx := lookupStaticName(name)
	if staticIdx > 0 {
		// 4-bit prefix per RFC 7541 §6.2.3 + §5.1. The 4-bit field
		// holds values 0-14 directly; value 15 (all 1s) signals
		// "continuation bytes follow" and the actual value is
		// (15 + varint). For staticIdx in [1, 14], single-byte form.
		// For staticIdx >= 15 (e.g. authorization=23), multi-byte form.
		if staticIdx < 15 {
			e.buf = append(e.buf, 0x10|byte(staticIdx&0x0F))
		} else {
			e.buf = append(e.buf, 0x1F)
			rest := staticIdx - 15
			for rest >= 128 {
				e.buf = append(e.buf, byte(rest&0x7F|0x80))
				rest >>= 7
			}
			e.buf = append(e.buf, byte(rest))
		}
	} else {
		e.buf = append(e.buf, 0x10)
		e.writeStr(name)
	}
	e.writeStr(value)
	// Never-indexed entries are NOT added to the dynamic table.
}

// addToDynamic inserts a name/value pair into the dynamic table per
// RFC 7541 §4.4. Evicts oldest entries (FIFO) until the new entry
// fits. Each entry counts name+value+32 bytes of overhead.
func (e *hpackEncoder) addToDynamic(name, value string) {
	entrySize := uint32(len(name) + len(value) + 32)
	for e.dynSize+entrySize > e.dynMaxSize && len(e.dynTable) > 0 {
		evicted := e.dynTable[len(e.dynTable)-1]
		e.dynSize -= uint32(len(evicted.name) + len(evicted.value) + 32)
		e.dynTable = e.dynTable[:len(e.dynTable)-1]
	}
	if entrySize > e.dynMaxSize {
		// Entry too large for the table; clear table (RFC 7541 §4.4).
		e.dynTable = nil
		e.dynSize = 0
		return
	}
	// Insert at the front (index 62 = most recent, per RFC 7541 §2.3.2).
	e.dynTable = append([]hpackEntry{{name: name, value: value}}, e.dynTable...)
	e.dynSize += entrySize
}

// writeStr writes a string literal per RFC 7541 §5.2: a length-prefixed
// (varint, 7-bit prefix, Huffman flag in high bit) sequence of raw
// bytes. v1 always uses Raw (Huffman flag = 0).
func (e *hpackEncoder) writeStr(s string) {
	e.writeInt(7, len(s))
	e.buf = append(e.buf, s...)
}

// writeInt writes an HPACK integer per RFC 7541 §5.1 with the given
// bit-prefix (N). The high (8-N) bits of the first byte are zero
// (caller sets flags separately); we encode the integer in the low N
// bits plus continuation bytes when the value exceeds 2^N-1.
func (e *hpackEncoder) writeInt(prefixBits int, value int) {
	maxFirst := (1 << prefixBits) - 1
	if value < maxFirst {
		e.buf = append(e.buf, byte(value))
		return
	}
	e.buf = append(e.buf, byte(maxFirst))
	value -= maxFirst
	for value >= 128 {
		e.buf = append(e.buf, byte(value&0x7F|0x80))
		value >>= 7
	}
	e.buf = append(e.buf, byte(value))
}

// bytes returns the encoded HPACK header block.
func (e *hpackEncoder) bytes() []byte {
	out := make([]byte, len(e.buf))
	copy(out, e.buf)
	e.buf = e.buf[:0] // reset for next frame
	return out
}

// lookupStaticName returns the static-table index whose name matches
// (case-sensitive per RFC 7541 §3.1 - HTTP/2 lowercases header names
// at the framing layer; HPACK preserves case). Returns 0 if not found.
func lookupStaticName(name string) int {
	for i := 1; i <= 61; i++ {
		if hpackStaticTable[i].name == name {
			return i
		}
	}
	return 0
}

// --- Protobuf wire format encoder ---

// validateProtobufLeadingKey checks the leading field key of a protobuf
// message body. Per protobuf spec §3.1, a field key is a varint encoding
// (field_number << 3) | wire_type; field_number MUST be >= 1 (field 0 is
// reserved/illegal). A body whose leading key decodes to field_number=0
// produces Wireshark "Field Number: 0, Wire Type: varint, Malformed:
// Failed to parse value field".
//
// We decode only the leading varint key and reject:
//   - truncated varints (continuation bit set on the last available
//     byte),
//   - field_number == 0,
//   - wire_type not in {0,1,2,5} (3=start-group, 4=end-group are
//     deprecated in proto3; reject them as malformed for a traffic
//     generator — real proto3 encoders never emit them).
//
// We do NOT validate the full message structure (field-value lengths,
// tag uniqueness, etc.) — the user supplies raw protobuf bytes and is
// responsible for schema-level correctness. We only guard against the
// provably illegal leading key that produces a Wireshark parse error.
//
// Empty bodies (len==0) are valid: the gRPC spec allows a zero-length
// message (5-byte prefix with Message-Length=0, no body bytes).
func validateProtobufLeadingKey(msg []byte) error {
	if len(msg) == 0 {
		return nil // zero-length protobuf message is valid per gRPC spec
	}
	// Decode the leading varint key (at most 10 bytes for a uint64).
	var key uint64
	var shift uint
	consumed := 0
	for i := 0; i < len(msg) && i < 10; i++ {
		b := msg[i]
		key |= uint64(b&0x7F) << shift
		shift += 7
		consumed++
		if b&0x80 == 0 {
			fieldNumber := int(key >> 3)
			wireType := int(key & 0x07)
			if fieldNumber < 1 {
				return fmt.Errorf("protobuf field_number %d < 1 (field 0 is reserved per protobuf spec §3.1)", fieldNumber)
			}
			switch wireType {
			case 0, 1, 2, 5:
				// legal wire types
			default:
				return fmt.Errorf("protobuf wire_type %d invalid (must be 0/1/2/5; 3/4 group types are deprecated)", wireType)
			}
			return nil
		}
	}
	// All bytes had the continuation bit set -> truncated varint.
	return fmt.Errorf("protobuf leading field key is a truncated varint (continuation bit set on all %d bytes)", consumed)
}

// protobufField encodes a protobuf field key per
// https://protobuf.dev/programming-guides/encoding/. Key =
// (field_number << 3) | wire_type, varint-encoded.
func protobufField(fieldNumber int, wireType int) []byte {
	key := uint64(fieldNumber<<3 | wireType)
	return appendVarint(nil, key)
}

// appendVarint appends a varint-encoded uint64 to buf per protobuf
// spec §3 (MSB=1 means continuation byte).
func appendVarint(buf []byte, v uint64) []byte {
	for v >= 128 {
		buf = append(buf, byte(v&0x7F|0x80))
		v >>= 7
	}
	return append(buf, byte(v))
}

// segmentByMSS splits payload into chunks of at most mss bytes. The
// last chunk may be smaller. A nil/empty payload returns a single
// empty chunk so the caller emits one PSH-ACK segment (matching the
// pre-segmentation behavior where an empty body still produced one
// response packet).
//
// Mirrors internal/protocol/http.segmentByMSS and pop3.segmentByMSS -
// duplicated to avoid an import cycle.
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

// synOptions builds TCP options for SYN packets: MSS, Window Scale,
// and SACK-Permitted, matching real-world SYN capture characteristics.
// Mirrors internal/protocol/tcp.synOptions, http.synOptions, and
// pop3.synOptions - duplicated to avoid an import cycle.
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

// Compile-time interface check.
var _ interface {
	Name() string
	Plan(context.Context, core.FlowSpec) (<-chan core.PacketConfig, error)
	Validate(core.FlowSpec) error
} = (*Planner)(nil)
