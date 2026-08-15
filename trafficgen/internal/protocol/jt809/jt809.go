package jt809

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

// DefaultTTL and MSS mirror the jt808 package.
const (
	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536
)

// Planner implements the JT/T 809-2019 protocol planner. A JT809 session
// spans up to TWO independent TCP 4-tuples: the main link (lower→upper,
// port 8812) and an optional slave link (upper→lower, port 8813). Both
// share a GroupID so the engine routes them to one PacketWorker (design
// §3B.2, §10.4).
type Planner struct{}

// NewPlanner creates a new JT809 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "jt809" }

// Validate validates the L3/L4 fields of the spec. JT809 config validation
// is performed via ValidateConfig (core FlowSpec does not carry JT809
// pointer until main agent wires integration).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("jt809: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("jt809: invalid DstIP %q", spec.DstIP)
		}
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("jt809: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
	}
	return nil
}

// ValidateConfig validates a JT809 config (design §5B.1).
func ValidateConfig(cfg *JT809Config) error {
	if cfg == nil {
		return fmt.Errorf("jt809: nil config")
	}
	if cfg.GNSSCenterId > 999999999 {
		return fmt.Errorf("jt809: GNSSCenterId %d > 999999999", cfg.GNSSCenterId)
	}
	if len(cfg.UserName) > 5 {
		return fmt.Errorf("jt809: UserName length %d > 5", len(cfg.UserName))
	}
	if len(cfg.Password) > 10 {
		return fmt.Errorf("jt809: Password length %d > 10", len(cfg.Password))
	}
	if cfg.VersionFlag > 2 {
		return fmt.Errorf("jt809: VersionFlag %d > 2", cfg.VersionFlag)
	}
	if cfg.EncryptFlag > 1 {
		return fmt.Errorf("jt809: EncryptFlag %d > 1", cfg.EncryptFlag)
	}
	if cfg.LoginResult > 4 {
		return fmt.Errorf("jt809: LoginResult %d > 4 (allowed 0-4)", cfg.LoginResult)
	}
	for _, pr := range cfg.Procedures {
		if pr.Type == ProcMainDisconnectNotice && pr.DisconnectReason > 2 {
			return fmt.Errorf("jt809: DisconnectReason %d > 2 (allowed 0-2)", pr.DisconnectReason)
		}
		if pr.Type == ProcAlarmWithAttachment {
			url, err := jtcommon.GBKEncode(pr.FileUrl)
			if err != nil {
				return fmt.Errorf("jt809: FileUrl GBK: %w", err)
			}
			if len(url) > 256 {
				return fmt.Errorf("jt809: FileUrl GBK length %d > 256", len(url))
			}
		}
		if pr.LoginResult != nil && *pr.LoginResult > 4 {
			return fmt.Errorf("jt809: per-procedure LoginResult %d > 4", *pr.LoginResult)
		}
	}
	return nil
}

// Plan is not supported for JT809: the engine requires a full config which
// the core FlowSpec cannot carry. Returning an empty channel here made tasks
// report "completed" with 0 packets. Callers must use PlanWithConfig.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return nil, fmt.Errorf("jt809: Plan not supported, use PlanWithConfig or a layers config")
}

// PlanWithConfig generates packet configs for a JT809 flow. It emits
// the main-link TCP 3-way handshake, the main-link message sequence,
// optionally the slave-link TCP + slave messages, then TCP teardowns
// for both links.
func (p *Planner) PlanWithConfig(ctx context.Context, spec core.FlowSpec, cfg *JT809Config) (<-chan core.PacketConfig, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = MainLinkPort
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		mainFlowID := fmt.Sprintf("jt809-main-%d-%d", cfg.GNSSCenterId, cfg.InitialSN)
		slaveFlowID := fmt.Sprintf("jt809-slave-%d-%d", cfg.GNSSCenterId, cfg.InitialSN)
		groupID := hashGNSS(cfg.GNSSCenterId)

		// Defaults.
		if cfg.UserName == "" {
			cfg.UserName = defaultUserName(cfg.GNSSCenterId)
		}
		if cfg.Password == "" {
			cfg.Password = "0000000000"
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

		// Slave-link TCP sequence counters. Initialized lazily when the
		// slave link is opened (see openSlaveTCP below). Declared here so
		// the emitMsg closure captures them by reference before the slave
		// handshake runs.
		var slaveClientSeq, slaveServerSeq uint32

		// Per-link MsgSN counters (design §6B.3). Main and slave each
		// have an upstream (lower→upper) and a downstream (upper→lower)
		// counter. All four are independent:
		//   mainMsgSN: 下级→上级 on main link, starts at InitialSN.
		//   slaveMsgSN: 上级→下级 on slave link (slave-side upstream),
		//                starts at InitialSN.
		//   platformMainMsgSN: 上级→下级 on main link, starts at
		//                       PlatformInitialSN (default 0).
		//   platformSlaveMsgSN: 下级→上级 on slave link (slave-side
		//                        downstream), starts at PlatformInitialSN.
		mainMsgSN := cfg.InitialSN
		slaveMsgSN := cfg.InitialSN
		platformMainMsgSN := cfg.PlatformInitialSN
		platformSlaveMsgSN := cfg.PlatformInitialSN

		// emitTCP sends a TCP packet config to the channel.
		emitTCP := func(flowID, direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
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

		// emitData segments payload by MSS.
		emitData := func(flowID, direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
				emitTCP(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// emitMsg builds and emits one JT809 message. The SN counter is
		// selected by (link, direction):
		//   main + up   → mainMsgSN (下级→上级)
		//   main + down → platformMainMsgSN (上级→下级)
		//   slave + up  → platformSlaveMsgSN (下级→上级 on slave link;
		//                 the slave link's "up" direction is upper→lower
		//                 physically, but we treat slave-side downstream
		//                 as the lower→upper counter per design §6B.3)
		//   slave + down → slaveMsgSN (上级→下级)
		// To keep the callback signature simple, we pass useMainSN as a
		// 2-bit selector encoded in a uint8: 0=mainMsgSN, 1=platformMain,
		// 2=slaveMsgSN, 3=platformSlave.
		emitMsg := func(flowID, direction string, msgID uint16, vehicleColor uint8, vehiclePlate string, body []byte, link string) {
			var sn uint32
			switch link {
			case LinkSlave:
				if direction == "down" {
					sn = slaveMsgSN
					slaveMsgSN++
				} else {
					sn = platformSlaveMsgSN
					platformSlaveMsgSN++
				}
			default: // LinkMain
				if direction == "up" {
					sn = mainMsgSN
					mainMsgSN++
				} else {
					sn = platformMainMsgSN
					platformMainMsgSN++
				}
			}
			frame, err := buildFrame(sn, msgID, vehicleColor, vehiclePlate, body)
			if err != nil {
				return
			}
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
			// Slave link messages ride a different TCP 4-tuple (port 8813
			// on the lower side). Rewrite the lower-side port accordingly.
			// Upper side keeps spec.DstPort (its accepted-from-main port
			// is irrelevant; the upper side picks a fresh ephemeral per
			// JT/T 809-2019 §5.2, but for trafficgen we reuse spec.DstPort
			// since the engine only needs the 4-tuple to be consistent).
			if link == LinkSlave {
				if direction == "down" {
					// upper → lower: dstPort (lower side) becomes 8813.
					dstPort = SlaveLinkPort
				} else {
					// lower → upper: srcPort (lower side) becomes 8813.
					srcPort = SlaveLinkPort
				}
			}
			if direction == "down" {
				if link == LinkSlave {
					slaveServerSeq = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, slaveServerSeq, slaveClientSeq, frame)
				} else {
					serverSeq = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, frame)
				}
			} else {
				if link == LinkSlave {
					slaveClientSeq = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, slaveClientSeq, slaveServerSeq, frame)
				} else {
					clientSeq = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, frame)
				}
			}
		}

		// --- Main link TCP handshake ---
		emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emitTCP(mainFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// Determine whether any procedure routes to the slave link, so we
		// can decide whether to open a second TCP. SlaveLinkEnabled=true
		// forces a slave TCP even if no slave procedures are listed (handy
		// for connect-only traces / keep-alive tests).
		hasSlaveProc := false
		for _, pr := range cfg.Procedures {
			link := pr.Link
			if link == "" {
				if isSlaveMsgType(pr.Type) {
					link = LinkSlave
				} else {
					link = LinkMain
				}
			}
			if link == LinkSlave {
				hasSlaveProc = true
				break
			}
		}
		openSlaveTCP := cfg.SlaveLinkEnabled || hasSlaveProc

		// Slave link carries its own independent TCP 4-tuple. Per JT/T
		// 809-2019 §5.2, the slave connection is initiated by the UPPER
		// platform TO the lower platform on port 8813, i.e. the source is
		// the upper side (DstMAC/DstIP from spec) and the destination is
		// the lower side (SrcMAC/SrcIP from spec, port 8813). The lower
		// side's source port for the slave link is an ephemeral port,
		// modeled here by spec.SrcPort (the lower platform picks its own
		// ephemeral when accepting, so we use the same one configured for
		// the main link for simplicity). Upper side's source port for the
		// slave is its own ephemeral (DstPort from spec).
		if openSlaveTCP {
			slaveClientSeq = randUint32()
			slaveServerSeq = randUint32()
			// SYN: upper → lower (upper=spec.Dst, lower=spec.Src).
			emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, 0, 0x02, nil)
			slaveClientSeq++
			// SYN+ACK: lower → upper. Lower's ephemeral source port for
			// the slave link is spec.SrcPort (the lower platform's
			// accepted port).
			emitTCP(slaveFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, slaveServerSeq, slaveClientSeq, 0x12, nil)
			slaveServerSeq++
			// ACK: upper → lower.
			emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x10, nil)
		}

		// --- Main-link message sequence (and slave-link when applicable) ---
		for _, pr := range cfg.Procedures {
			select {
			case <-ctx.Done():
				return
			default:
			}
			link := pr.Link
			if link == "" {
				if isSlaveMsgType(pr.Type) {
					link = LinkSlave
				} else {
					link = LinkMain
				}
			}
			flowID := mainFlowID
			if link == LinkSlave {
				flowID = slaveFlowID
			}
			if err := emitJT809Procedure(pr, cfg, flowID, link, emitMsg); err != nil {
				return
			}
		}

		// --- Main link TCP teardown ---
		emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emitTCP(mainFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- Slave link TCP teardown (FIN/ACK + ACK). The half-close is
		// initiated by the upper side (closing the connect-side), matching
		// the slave handshake direction. ---
		if openSlaveTCP {
			// FIN+ACK: upper → lower.
			emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x11, nil)
			slaveClientSeq++
			// FIN+ACK: lower → upper (full close).
			emitTCP(slaveFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, slaveServerSeq, slaveClientSeq, 0x11, nil)
			slaveServerSeq++
			// Final ACK: upper → lower.
			emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x10, nil)
		}
	}()

	return configChan, nil
}

// emitJT809Procedure dispatches one procedure to the builder+emit callback.
func emitJT809Procedure(pr JT809Procedure, cfg *JT809Config, flowID, link string, emit func(string, string, uint16, uint8, string, []byte, string)) error {
	// For vehicle messages, use per-procedure override or fall back to cfg.
	vc := cfg.VehicleColor
	if pr.VehicleColor != nil {
		vc = *pr.VehicleColor
	}
	vp := cfg.VehiclePlate
	if pr.VehiclePlate != "" {
		vp = pr.VehiclePlate
	}
	// Non-vehicle MsgIds use VehicleColor=0 and empty plate (21 spaces).
	nonVehicle := false
	switch pr.Type {
	case ProcMainLogin, ProcMainLoginResponse, ProcMainLogout, ProcMainDisconnectNotice,
		ProcSlaveConnect, ProcSlaveConnectResponse:
		nonVehicle = true
	}
	if nonVehicle {
		vc = 0
		vp = ""
	}

	switch pr.Type {
	case ProcMainLogin:
		body := buildLoginBody(cfg)
		emit(flowID, "up", MsgMainLogin, vc, vp, body, link)
	case ProcMainLoginResponse:
		result := cfg.LoginResult
		if pr.LoginResult != nil {
			result = *pr.LoginResult
		}
		body := buildLoginRespBody(result, cfg.GNSSCenterId)
		emit(flowID, "down", MsgMainLoginResponse, vc, vp, body, link)
	case ProcMainLogout:
		emit(flowID, "up", MsgMainLogout, vc, vp, nil, link)
	case ProcMainDisconnectNotice:
		body := buildDisconnectNoticeBody(pr.DisconnectReason, cfg.GNSSCenterId)
		emit(flowID, "up", MsgMainDisconnectNotice, vc, vp, body, link)
	case ProcVehicleRegister:
		// Build 0x1201 SubBody with terminal fields. The caller can
		// override SubBody; otherwise the planner uses defaults.
		mid := jtcommon.PadRightZeroASCII("TEST", 5)
		tm := jtcommon.PadRightSpace("TG-DEMO", 20)
		tid := jtcommon.PadRightZeroASCII("0000001", 7)
		subBody := pr.SubBody
		if subBody == nil {
			subBody = buildVehicleRegisterSubBody(jtcommon.MustBCD("013800138000"), mid, tm, tid)
		}
		body := buildContainerBody(SubVehicleRegister, subBody)
		emit(flowID, "up", MsgVehicleDynamic, vc, vp, body, link)
	case ProcRealtimeLocation:
		locBody, err := buildRealtimeLocationSubBody(pr.LocationData)
		if err != nil {
			return err
		}
		body := buildContainerBody(SubRealtimeLocation, locBody)
		emit(flowID, "up", MsgVehicleDynamic, vc, vp, body, link)
	case ProcHistoryLocation:
		// History = TimeRange(12 BCD) + N × 0x0200 body. Simplified:
		// caller provides SubBody; planner wraps in container.
		body := buildContainerBody(SubHistoryLocation, pr.SubBody)
		emit(flowID, "up", MsgVehicleDynamic, vc, vp, body, link)
	case ProcAlarm:
		alarmBody, err := buildAlarmSubBody(pr.AlarmFlag, pr.PulseSpeed, pr.LocationData)
		if err != nil {
			return err
		}
		body := buildContainerBody(SubAlarm, alarmBody)
		emit(flowID, "up", MsgVehicleDynamic, vc, vp, body, link)
	case ProcAlarmWithAttachment:
		body, err := buildAlarmWithAttachmentBody(pr.AlarmFlag, pr.AlarmTime, pr.SubBody, pr.FileType, pr.FileUrl)
		if err != nil {
			return err
		}
		emit(flowID, "up", MsgAlarmWithAttachment, vc, vp, body, link)
	case ProcPlatformInteraction:
		body := buildContainerBody(pr.SubMsgId, pr.SubBody)
		emit(flowID, "down", MsgPlatformInteraction, vc, vp, body, link)
	case ProcVehicleStatic:
		body := buildContainerBody(pr.SubMsgId, pr.SubBody)
		emit(flowID, "up", MsgVehicleStatic, vc, vp, body, link)
	case ProcControlResponse:
		body := buildContainerBody(pr.SubMsgId, pr.SubBody)
		emit(flowID, "up", MsgVehicleControlResp, vc, vp, body, link)
	case ProcSlaveConnect:
		body := buildLoginBody(cfg)
		emit(flowID, "down", MsgSlaveConnect, vc, vp, body, link)
	case ProcSlaveConnectResponse:
		result := cfg.LoginResult
		if pr.LoginResult != nil {
			result = *pr.LoginResult
		}
		body := buildLoginRespBody(result, cfg.GNSSCenterId)
		emit(flowID, "up", MsgSlaveConnectResp, vc, vp, body, link)
	case ProcSlaveManagement:
		body := buildContainerBody(pr.SubMsgId, pr.SubBody)
		emit(flowID, "down", MsgSlaveManagement, vc, vp, body, link)
	case ProcSlaveVehicleControl:
		body := buildContainerBody(pr.SubMsgId, pr.SubBody)
		emit(flowID, "down", MsgSlaveVehicleControl, vc, vp, body, link)
	default:
		return fmt.Errorf("jt809: unknown procedure type %q", pr.Type)
	}
	return nil
}

// isSlaveMsgType returns true for procedure types that belong on the
// slave link by convention (0x9xxx).
func isSlaveMsgType(t string) bool {
	switch t {
	case ProcSlaveConnect, ProcSlaveConnectResponse, ProcSlaveManagement, ProcSlaveVehicleControl:
		return true
	}
	return false
}

// defaultUserName computes the design's default UserName = last 5 digits
// of GNSSCenterId zero-padded to 9 digits (design §4B.1).
func defaultUserName(id uint32) string {
	full := fmt.Sprintf("%09d", id)
	if len(full) < 5 {
		return full
	}
	return full[len(full)-5:]
}

// hashGNSS computes a stable GroupID from GNSSCenterId.
func hashGNSS(id uint32) string {
	h := uint32(2166136261)
	h ^= id
	h *= 16777619
	return fmt.Sprintf("jt809-%08x", h)
}

// randUint32 returns a random uint32.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42
	}
	return uint32(n.Uint64())
}

// synOptions builds TCP options for SYN packets.
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
