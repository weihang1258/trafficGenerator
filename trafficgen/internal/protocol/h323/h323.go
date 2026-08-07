// Package h323 implements the H.323 (H.225.0/Q.931 呼叫信令) planner.
//
// H.323 is an ITU-T standard for multimedia communication over IP networks.
// The call signaling uses Q.931 messages wrapped in TPKT (RFC 1006) over TCP
// (default port 1720). H.245 (媒体控制) is tunneled inside Q.931 FACILITY
// messages via the user-user IE.
//
// Reference pcap: /home/pcap_auto/llcj_pcap/
//
// IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-2271-1779.pcap
//
// Wire format per message (每个消息的线路格式):
//
//	TPKT header (4 bytes 字节): version(1)=0x03, reserved(1)=0x00, length(2)
//	Q.931 header: PD(1)=0x08, CRV_len(1)=0x02, CRV(2), msg_type(1)
//	Information elements (信息元素): Bearer capability, Calling/Called party
//	  number, Display IE (IA5 显示名称), User-User IE (H.225 PER data)
//
// Call flow (呼叫流程) for "full" scenario (完整场景):
//
//	Caller                           Callee
//	  |-- TCP SYN ------------------>|
//	  |<-- TCP SYN-ACK --------------|
//	  |-- TCP ACK ------------------>|
//	  |-- SETUP (0x05) ------------->|   建立请求
//	  |<-- CALL PROCEEDING (0x02) ---|   呼叫进行中
//	  |<-- FACILITY (0x62) ----------|   H.245 TCS+MSD (设施)
//	  |<-- ALERTING (0x01) ----------|   振铃
//	  |-- FACILITY (0x62) ---------->|   H.245 response
//	  |<-- FACILITY (0x62) ----------|   H.245 ack
//	  |-- FACILITY (0x62) ---------->|   H.245 ack
//	  |<-- CONNECT (0x07) ---------->|   接通
//	  |-- RELEASE COMPLETE (0x5A) -->|   释放完成
//	  |<-- RELEASE COMPLETE (0x5A) ---|   释放完成
//	  |-- TCP FIN ------------------>|
//	  |<-- TCP FIN-ACK --------------|
//	  |-- TCP ACK ------------------>|
package h323

import (
	"context"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical H.323 port.
	DefaultPort = 1720

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// TPKT version (TPKT版本号) per RFC 1006.
	TPKTVersion = 0x03

	// Q.931 Protocol Discriminator (Q.931协议鉴别符).
	Q931PD = 0x08

	// Call Reference Length (呼叫参考长度) is always 2 bytes.
	CRVLength = 0x02

	// CRV Flag Bit (CRV标志位) distinguishes sender role.
	// Originating side (主叫方): flag=0; terminating side (被叫方): flag=1.
	CRVFlagOriginating = 0x0000
	CRVFlagTerminating = 0x8000

	// Q.931 Message Types (Q.931消息类型).
	MsgTypeAlerting        = 0x01 // ALERTING (振铃)
	MsgTypeCallProceeding  = 0x02 // CALL PROCEEDING (呼叫进行中)
	MsgTypeSetup           = 0x05 // SETUP (建立请求)
	MsgTypeConnect         = 0x07 // CONNECT (接通)
	MsgTypeReleaseComplete = 0x5A // RELEASE COMPLETE (释放完成)
	MsgTypeFacility        = 0x62 // FACILITY (设施, H.245隧道)

	// DefaultCRV (默认呼叫参考值) from reference pcap.
	DefaultCRV = 0x2584

	// MaxDisplayNameLen (显示名称最大长度) is 254 bytes (IA5 encoded).
	// The Display IE length field is 1 byte, max 255, but the IEI+length
	// overhead leaves 254 bytes max for the string.
	MaxDisplayNameLen = 254
)

// Planner implements the H.323 call signaling planner.
type Planner struct{}

// NewPlanner creates a new H.323 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "h323" }

// Validate validates an H.323 flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("h323: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("h323: invalid DstIP %q", spec.DstIP)
		}
	}

	h := spec.H323
	if h == nil {
		return fmt.Errorf("h323: H323Config is required")
	}

	// Role (角色) validation. Empty defaults to "caller" (user > auto > none).
	role := normalizeRole(h.Role)
	if role == "" {
		role = "caller"
	}
	if role != "caller" && role != "callee" {
		return fmt.Errorf("h323: invalid role %q (must be caller or callee)", h.Role)
	}

	// Scenario (场景) validation. Empty defaults to "full".
	scenario := normalizeScenario(h.Scenario)
	if scenario == "" {
		scenario = "full"
	}
	if scenario != "full" && scenario != "tunnel_only" &&
		scenario != "ras_only" && scenario != "data_only" {
		return fmt.Errorf("h323: invalid scenario %q (must be full, tunnel_only, ras_only, or data_only)", h.Scenario)
	}

	// Calls (呼叫次数) validation. 0 defaults to 1 in Plan; negative is an error.
	if h.Calls < 0 {
		return fmt.Errorf("h323: calls must be >= 0, got %d", h.Calls)
	}

	// DisplayName (显示名称) validation.
	if len(h.DisplayName) > MaxDisplayNameLen {
		return fmt.Errorf("h323: display_name must be <= %d bytes (Display IE length is 1 byte), got %d", MaxDisplayNameLen, len(h.DisplayName))
	}

	// MSS (最大分段大小) validation.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("h323: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
		}
	}

	return nil
}

// Plan generates packet configs for an H.323 flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		h := spec.H323
		if h == nil {
			h = &core.H323Config{}
		}

		role := normalizeRole(h.Role)
		if role == "" {
			role = "caller"
		}
		scenario := normalizeScenario(h.Scenario)
		if scenario == "" {
			scenario = "full"
		}
		crv := h.Crv
		if crv == 0 {
			crv = DefaultCRV
		}
		displayName := h.DisplayName
		if displayName == "" {
			displayName = "Administrator"
		}
		calls := h.Calls
		if calls == 0 {
			calls = 1
		}

		// For data_only and ras_only scenarios, skip TCP entirely.
		if scenario == "data_only" {
			// Emit RTP media frames only (仅发送RTP媒体帧).
			if h.Media != nil && h.Media.Enabled {
				emitRTPMedia(ctx, h.Media, spec, configChan)
			}
			return
		}
		if scenario == "ras_only" {
			// Emit RAS messages only (仅发送RAS消息).
			if h.Ras != nil && h.Ras.Enabled {
				emitRASSignaling(ctx, h.Ras, spec, configChan)
			}
			return
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Resolve MSS (最大分段大小).
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		// Random ISN per RFC 6528.
		clientSeq := uint32(1000) // deterministic for testing
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = 1000
		}
		serverSeq := clientSeq + 5000

		winSize := uint16(65535)

		// emit (发送包) sends a TCP packet config to the channel.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, packetIndex *uint64) {
			if payload == nil {
				payload = []byte{}
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: *packetIndex,
				Direction:   direction,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(srcIP, dstIP, 6, effectiveTTL, uint16(*packetIndex), spec),
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    srcPort,
					DstPort:    dstPort,
					Seq:        seq,
					Ack:        ack,
					Flags:      flags,
					WindowSize: winSize,
				},
				Payload: payload,
			}
			if flags == 0x02 || flags == 0x12 {
				cfg.L4.TCPOptions = synOpts
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			*packetIndex++
		}

		// emitQ931 (发送Q.931消息) builds a TPKT-wrapped Q.931 message and
		// emits it as a PSH-ACK segment. Returns the new sender seq.
		emitQ931 := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, msgType byte, crvVal uint16, displayName string, packetIndex *uint64) uint32 {
			payload := buildQ931Message(msgType, crvVal, displayName)
			emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, payload, packetIndex)
			return senderSeq + uint32(len(payload))
		}

		packetIndex := uint64(0)

		// Run the call loop for each call (每个呼叫运行一次).
		for callNum := 0; callNum < calls; callNum++ {
			callCRV := crv + uint16(callNum)

			// --- TCP handshake (TCP三次握手) ---
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil, &packetIndex)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil, &packetIndex)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil, &packetIndex)

			// Determine directions based on role (根据角色确定方向).
			var upDir, downDir string
			var upMAC, downMAC string
			var upIP, downIP string
			var upPort, downPort uint16
			var crvFlagUp, crvFlagDown uint16

			if role == "caller" {
				upDir, downDir = "up", "down"
				upMAC, downMAC = spec.SrcMAC, spec.DstMAC
				upIP, downIP = spec.SrcIP, spec.DstIP
				upPort, downPort = spec.SrcPort, spec.DstPort
				crvFlagUp, crvFlagDown = CRVFlagOriginating, CRVFlagTerminating
			} else { // callee
				upDir, downDir = "down", "up"
				upMAC, downMAC = spec.DstMAC, spec.SrcMAC
				upIP, downIP = spec.DstIP, spec.SrcIP
				upPort, downPort = spec.DstPort, spec.SrcPort
				crvFlagUp, crvFlagDown = CRVFlagTerminating, CRVFlagOriginating
			}

			// --- Q.931 signaling (Q.931信令) ---
			if scenario == "full" {
				// Full scenario: SETUP, CP, FACILITY, ALERTING, FACILITY×3, CONNECT, RELCOMP×2
				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeSetup, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeCallProceeding, callCRV|crvFlagDown, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeFacility, callCRV|crvFlagDown, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeAlerting, callCRV|crvFlagDown, displayName, &packetIndex)
				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeFacility, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeFacility, callCRV|crvFlagDown, displayName, &packetIndex)
				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeFacility, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeConnect, callCRV|crvFlagDown, displayName, &packetIndex)

				// Emit RTP media if enabled (如果启用则发送RTP媒体).
				if h.Media != nil && h.Media.Enabled {
					emitRTPMedia(ctx, h.Media, spec, configChan)
				}

				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeReleaseComplete, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeReleaseComplete, callCRV|crvFlagDown, displayName, &packetIndex)
			} else {
				// tunnel_only scenario: SETUP, CP, ALERTING, CONNECT, RELCOMP×2
				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeSetup, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeCallProceeding, callCRV|crvFlagDown, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeAlerting, callCRV|crvFlagDown, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeConnect, callCRV|crvFlagDown, displayName, &packetIndex)
				clientSeq = emitQ931(upDir, upMAC, downMAC, upIP, downIP, upPort, downPort, clientSeq, serverSeq, MsgTypeReleaseComplete, callCRV|crvFlagUp, displayName, &packetIndex)
				serverSeq = emitQ931(downDir, downMAC, upMAC, downIP, upIP, downPort, upPort, serverSeq, clientSeq, MsgTypeReleaseComplete, callCRV|crvFlagDown, displayName, &packetIndex)
			}

			// --- TCP teardown (TCP三次挥手) ---
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil, &packetIndex)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil, &packetIndex)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil, &packetIndex)
		}
	}()

	return configChan, nil
}

// buildQ931Message builds a TPKT-wrapped Q.931 message (构造TPKT包装的Q.931消息).
// The message includes a minimal set of IEs to make it recognizable as H.323.
func buildQ931Message(msgType byte, crvVal uint16, displayName string) []byte {
	// Build Q.931 payload (构造Q.931载荷).
	q931 := []byte{
		Q931PD,    // Protocol Discriminator (协议鉴别符)
		CRVLength, // Call Reference Length (呼叫参考长度)
		byte(crvVal >> 8), byte(crvVal & 0xFF), // Call Reference Value (呼叫参考值)
		msgType, // Message Type (消息类型)
	}

	// Add Bearer Capability IE (承载能力信息元素) for SETUP/CONNECT.
	if msgType == MsgTypeSetup || msgType == MsgTypeConnect {
		q931 = append(q931, buildBearerCapabilityIE()...)
	}

	// Add Display IE (显示信息元素) if displayName is provided.
	if displayName != "" {
		q931 = append(q931, buildDisplayIE(displayName)...)
	}

	// Build TPKT header (构造TPKT报头).
	tpktLen := uint16(4 + len(q931)) // TPKT header + Q.931 payload
	tpkt := []byte{
		TPKTVersion,         // Version (版本号)
		0x00,                // Reserved (保留字节)
		byte(tpktLen >> 8),  // Length high byte (长度高字节)
		byte(tpktLen & 0xFF), // Length low byte (长度低字节)
	}

	return append(tpkt, q931...)
}

// buildBearerCapabilityIE builds the Bearer Capability IE (承载能力信息元素).
// Minimal IE for multimedia call (多媒体呼叫).
func buildBearerCapabilityIE() []byte {
	// IEI=0x04 (Bearer Capability), Length=3, Capability=0x10 (3.1kHz audio)
	return []byte{0x04, 0x03, 0x90, 0x90, 0xA3}
}

// buildDisplayIE builds the Display IE (显示信息元素) with IA5 (ASCII) encoding
// per ITU-T Q.931. The previous UTF-16BE encoding caused Wireshark to report
// "Trailing stray characters" because the Q.931 dissector interprets the
// Display IE content as a NUL-terminated string — the first 0x00 byte of
// UTF-16BE (high byte of each char) was treated as the string terminator.
func buildDisplayIE(displayName string) []byte {
	// Q.931 Display IE uses IA5 encoding (basically ASCII, no NUL terminator).
	data := []byte(displayName)
	if len(data) > 253 {
		data = data[:253] // length field is 1 byte, max 255 minus overhead
	}
	ie := []byte{0x28, byte(len(data))}
	ie = append(ie, data...)
	return ie
}

// emitRTPMedia emits RTP media frames (发送RTP媒体帧).
func emitRTPMedia(ctx context.Context, media *core.H323MediaConfig, spec core.FlowSpec, configChan chan<- core.PacketConfig) {
	frames := media.Frames
	if frames <= 0 {
		frames = 10
	}
	frameSize := media.FrameSize
	if frameSize == 0 {
		frameSize = 160
	}
	srcPort := media.SrcPort
	if srcPort == 0 {
		srcPort = 5062
	}
	dstPort := media.DstPort
	if dstPort == 0 {
		dstPort = 5063
	}

	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	effectiveTTL := spec.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	for i := 0; i < frames; i++ {
		// Build minimal RTP header (构造最小RTP报头).
		rtp := []byte{
			0x80,                              // V=2, P=0, X=0, CC=0
			byte(media.PayloadType & 0x7F),    // PT (载荷类型)
			0x00, byte(i),                     // Sequence number (序列号)
			0x00, 0x00, 0x00, 0x00,            // Timestamp (时间戳)
			0x00, 0x00, 0x00, 0x00,            // SSRC
		}
		// Add payload (添加载荷).
		payload := make([]byte, frameSize)
		rtp = append(rtp, payload...)

		cfg := core.PacketConfig{
			FlowID:      flowID + ":rtp",
			PacketIndex: uint64(i),
			Direction:   "up",
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 17, effectiveTTL, uint16(i), spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  srcPort,
				DstPort:  dstPort,
			},
			Payload: rtp,
		}
		select {
		case <-ctx.Done():
			return
		case configChan <- cfg:
		}
	}
}

// emitRASSignaling emits RAS messages (发送RAS信令).
func emitRASSignaling(ctx context.Context, ras *core.H323RasConfig, spec core.FlowSpec, configChan chan<- core.PacketConfig) {
	port := ras.Port
	if port == 0 {
		port = 1719
	}
	gkIP := ras.GatekeeperIP
	if gkIP == "" {
		gkIP = spec.DstIP
	}

	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	effectiveTTL := spec.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	// RAS message sequence (RAS消息序列):
	// Pre-call: GRQ→GCF, RRQ→RCF, ARQ→ACF (6 messages 消息)
	// Post-call: DRQ→DCF (2 messages 消息)
	// Total: 8 UDP packets (共8个UDP包)
	rasMessages := []struct {
		msgType byte
		dir     string
	}{
		{0x01, "up"},   // GRQ (Gatekeeper Request 网守请求)
		{0x02, "down"}, // GCF (Gatekeeper Confirm 网守确认)
		{0x03, "up"},   // RRQ (Registration Request 注册请求)
		{0x04, "down"}, // RCF (Registration Confirm 注册确认)
		{0x05, "up"},   // ARQ (Admission Request 准入请求)
		{0x06, "down"}, // ACF (Admission Confirm 准入确认)
		{0x07, "up"},   // DRQ (Disengage Request 脱离请求)
		{0x08, "down"}, // DCF (Disengage Confirm 脱离确认)
	}

	for i, msg := range rasMessages {
		// Build minimal RAS message (构造最小RAS消息).
		// H.225 RAS uses H.225.0 §7 PER encoding.
		rasPayload := []byte{
			0x00, msg.msgType, // Request Sequence Number (请求序列号)
			0x00, 0x01,        // Protocol Identifier (协议标识符)
		}
		// Add gatekeeper IP (添加网守IP).
		if ip := net.ParseIP(gkIP); ip != nil {
			rasPayload = append(rasPayload, ip.To4()...)
		}

		var srcIP, dstIP string
		var srcPort, dstPort uint16
		var srcMAC, dstMAC string

		if msg.dir == "up" {
			srcIP, dstIP = spec.SrcIP, gkIP
			srcPort, dstPort = spec.SrcPort, port
			srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
		} else {
			srcIP, dstIP = gkIP, spec.SrcIP
			srcPort, dstPort = port, spec.SrcPort
			srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
		}

		cfg := core.PacketConfig{
			FlowID:      flowID + ":ras",
			PacketIndex: uint64(i),
			Direction:   msg.dir,
			L2: core.L2Config{
				SrcMAC:    srcMAC,
				DstMAC:    dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3: core.L3Base(srcIP, dstIP, 17, effectiveTTL, uint16(i), spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  srcPort,
				DstPort:  dstPort,
			},
			Payload: rasPayload,
		}
		select {
		case <-ctx.Done():
			return
		case configChan <- cfg:
		}
	}
}

// synOptions builds TCP options for SYN packets (构造SYN包的TCP选项).
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

// normalizeRole normalizes the role string (角色字符串规范化).
func normalizeRole(r string) string {
	if r == "" {
		return ""
	}
	switch r {
	case "caller", "callee":
		return r
	default:
		return r
	}
}

// normalizeScenario normalizes the scenario string (场景字符串规范化).
func normalizeScenario(s string) string {
	if s == "" {
		return ""
	}
	switch s {
	case "full", "tunnel_only", "ras_only", "data_only":
		return s
	default:
		return s
	}
}
