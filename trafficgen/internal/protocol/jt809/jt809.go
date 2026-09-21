package jt809

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// DefaultTTL and MSS mirror the jt808 package.
const (
	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536
)

// Planner implements the JT/T 809-2019 protocol planner. A JT809 session
// spans up to TWO independent TCP 4-tuples: the main link (lower→upper,
// port 8812) and an optional slave link (upper→lower, port 8813, opened
// iff SlaveProcedures is non-empty). Both share a GroupID so the engine
// routes them to one PacketWorker (design §3B.2, §10.4).
type Planner struct{}

// NewPlanner creates a new JT809 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "jt809" }

// Validate validates the L3/L4 fields of the spec. Business-side validation
// lives in ValidateConfig (chain validator anchor).
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

// ValidateConfig validates a JT809 config（D-JT809-1 裁定6 负例锚：
// T-11 gnss 超界 / T-12 version_flag 区间 / T-13 error_code 嵌套锚 /
// password≤8；procedures V9 不下探的拦截点=此处遍历）.
func ValidateConfig(cfg *JT809Config) error {
	if cfg == nil {
		return fmt.Errorf("jt809: nil config")
	}
	if cfg.GNSSCenterId > 999999999 {
		return fmt.Errorf("jt809: GNSSCenterId %d > 999999999", cfg.GNSSCenterId)
	}
	if cfg.VersionFlag > 2 {
		return fmt.Errorf("jt809: VersionFlag %d > 2", cfg.VersionFlag)
	}
	if cfg.EncryptFlag > 1 {
		return fmt.Errorf("jt809: EncryptFlag %d > 1", cfg.EncryptFlag)
	}
	if len(cfg.Password) > PasswordLen {
		return fmt.Errorf("jt809: Password length %d > %d", len(cfg.Password), PasswordLen)
	}
	if len(cfg.DownLinkIP) > DownLinkIPLen {
		return fmt.Errorf("jt809: DownLinkIP length %d > %d", len(cfg.DownLinkIP), DownLinkIPLen)
	}
	if cfg.VersionBytes != "" {
		if len(cfg.VersionBytes) != 6 {
			return fmt.Errorf("jt809: version_bytes %q must be 6 hex chars (3 bytes)", cfg.VersionBytes)
		}
		if _, err := hex.DecodeString(cfg.VersionBytes); err != nil {
			return fmt.Errorf("jt809: version_bytes %q not hex: %w", cfg.VersionBytes, err)
		}
	}
	for role, list := range map[string][]JT809Procedure{
		LinkMain:  cfg.Procedures,
		LinkSlave: cfg.SlaveProcedures,
	} {
		for i := range list {
			pr := &list[i]
			t, ok := msgTypeByName[pr.Type]
			if !ok {
				return fmt.Errorf("jt809: unknown procedure type %q (procedures[%d])", pr.Type, i)
			}
			if t.link != role {
				return fmt.Errorf("jt809: procedure %q belongs on the %s link (use %s list)",
					pr.Type, t.link, slaveListName(t.link))
			}
			if pr.Result > 4 {
				return fmt.Errorf("jt809: Result %d > 4 (allowed 0-4)", pr.Result)
			}
			// procedure 级覆盖值同界（隔离复审 M2：pr.Password/pr.DownLinkIP
			// 绕过 cfg 级校验即被 padRight 静默截断——裁定6 锚的旁路面）。
			if len(pr.Password) > PasswordLen {
				return fmt.Errorf("jt809: procedure Password length %d > %d", len(pr.Password), PasswordLen)
			}
			if len(pr.DownLinkIP) > DownLinkIPLen {
				return fmt.Errorf("jt809: procedure DownLinkIP length %d > %d", len(pr.DownLinkIP), DownLinkIPLen)
			}
			if pr.ErrorCode > 2 {
				return fmt.Errorf("jt809: ErrorCode %d > 2 (allowed 0-2)", pr.ErrorCode)
			}
			if pr.ReasonCode > 2 {
				return fmt.Errorf("jt809: ReasonCode %d > 2 (allowed 0-2)", pr.ReasonCode)
			}
		}
	}
	return nil
}

func slaveListName(link string) string {
	if link == LinkSlave {
		return "slave_procedures"
	}
	return "procedures"
}

// Plan is not supported for JT809: the engine requires a full config which
// the core FlowSpec cannot carry. Returning an empty channel here made tasks
// report "completed" with 0 packets. Callers must use PlanWithConfig.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return nil, fmt.Errorf("jt809: Plan not supported, use PlanWithConfig or a layers config")
}

// PlanWithConfig generates packet configs for a JT809 flow. Timeline
// (门1 §3：主链先从链后，从链握手在主链消息后)：main handshake → main
// procedures → slave handshake → slave procedures → main teardown →
// slave teardown.
func (p *Planner) PlanWithConfig(ctx context.Context, spec core.FlowSpec, cfg *JT809Config) (<-chan core.PacketConfig, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = MainLinkPort
	}

	// Resolved defaults (copy — 不改调用方 cfg)：
	// UserId 缺省=GNSSCenterId；Password 缺省 "00000000"；DownLinkIP
	// 缺省=本端 IP（0x1001 通告的从链服务端与从链 SYN 目标一致面）；
	// DownLinkPort 缺省 8813。
	rc := *cfg
	if rc.UserId == 0 {
		rc.UserId = rc.GNSSCenterId
	}
	if rc.Password == "" {
		rc.Password = "00000000"
	}
	if rc.DownLinkIP == "" {
		rc.DownLinkIP = spec.SrcIP
	}
	if rc.DownLinkPort == 0 {
		rc.DownLinkPort = SlaveLinkPort
	}
	ver, err := versionBytes(&rc)
	if err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		mainFlowID := fmt.Sprintf("jt809-main-%d-%d", rc.GNSSCenterId, rc.InitialSN)
		slaveFlowID := fmt.Sprintf("jt809-slave-%d-%d", rc.GNSSCenterId, rc.InitialSN)
		groupID := hashGNSS(rc.GNSSCenterId)

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

		// Slave-link TCP sequence counters, initialized lazily when the
		// slave link opens (see the slave handshake below).
		var slaveClientSeq, slaveServerSeq uint32

		// Per-link MsgSN counters (design §6B.3): four independent
		// counters — main up starts at InitialSN, main down at
		// PlatformInitialSN, slave down (upper→lower) at InitialSN,
		// slave up (lower→upper) at PlatformInitialSN.
		mainMsgSN := rc.InitialSN
		slaveMsgSN := rc.InitialSN
		platformMainMsgSN := rc.PlatformInitialSN
		platformSlaveMsgSN := rc.PlatformInitialSN

		// emitTCP sends a TCP packet config to the channel.
		emitTCP := func(flowID, direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) error {
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
				return ctx.Err()
			case configChan <- cfg2:
			}
			packetIndex++
			return nil
		}

		// emitData segments payload by MSS; returns the sender's next seq.
		emitData := func(flowID, direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (uint32, error) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq, ctx.Err()
				default:
				}
				if err := emitTCP(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg); err != nil {
					return senderSeq, err
				}
				senderSeq += uint32(len(seg))
			}
			return senderSeq, nil
		}

		// emitMsg builds one JT809 frame and emits it. SN counter by
		// (link, direction): main+up→mainMsgSN, main+down→platformMain,
		// slave+down→slaveMsgSN, slave+up→platformSlave.
		emitMsg := func(flowID, direction string, msgID uint16, body []byte, link string) error {
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
			frame, err := buildFrameVer(&rc, ver, sn, msgID, body)
			if err != nil {
				return err
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
			// Slave link rides the second 4-tuple: lower side port 8813.
			if link == LinkSlave {
				if direction == "down" {
					dstPort = SlaveLinkPort
				} else {
					srcPort = SlaveLinkPort
				}
			}
			if direction == "down" {
				if link == LinkSlave {
					slaveServerSeq, err = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, slaveServerSeq, slaveClientSeq, frame)
				} else {
					serverSeq, err = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, frame)
				}
			} else {
				if link == LinkSlave {
					slaveClientSeq, err = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, slaveClientSeq, slaveServerSeq, frame)
				} else {
					clientSeq, err = emitData(flowID, direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, frame)
				}
			}
			return err
		}

		// --- Main link TCP handshake ---
		if err := emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil); err != nil {
			return
		}
		clientSeq++
		if err := emitTCP(mainFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil); err != nil {
			return
		}
		serverSeq++
		if err := emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil); err != nil {
			return
		}

		// --- Main-link message sequence ---
		for i := range rc.Procedures {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pr := &rc.Procedures[i]
			if err := emitJT809Procedure(pr, &rc, mainFlowID, LinkMain, emitMsg); err != nil {
				return
			}
		}

		// --- Slave link (opened iff slave procedures exist) ---
		openSlaveTCP := len(rc.SlaveProcedures) > 0
		if openSlaveTCP {
			slaveClientSeq = randUint32()
			slaveServerSeq = randUint32()
			// SYN: upper → lower (upper=spec.Dst, lower=spec.Src:8813).
			if err := emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, 0, 0x02, nil); err != nil {
				return
			}
			slaveClientSeq++
			// SYN+ACK: lower:8813 → upper.
			if err := emitTCP(slaveFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, SlaveLinkPort, spec.DstPort, slaveServerSeq, slaveClientSeq, 0x12, nil); err != nil {
				return
			}
			slaveServerSeq++
			// ACK: upper → lower.
			if err := emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x10, nil); err != nil {
				return
			}

			for i := range rc.SlaveProcedures {
				select {
				case <-ctx.Done():
					return
				default:
				}
				pr := &rc.SlaveProcedures[i]
				if err := emitJT809Procedure(pr, &rc, slaveFlowID, LinkSlave, emitMsg); err != nil {
					return
				}
			}
		}

		// --- Main link TCP teardown ---
		if err := emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil); err != nil {
			return
		}
		clientSeq++
		if err := emitTCP(mainFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil); err != nil {
			return
		}
		serverSeq++
		if err := emitTCP(mainFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil); err != nil {
			return
		}

		// --- Slave link TCP teardown (upper closes first, matching the
		// slave handshake direction) ---
		if openSlaveTCP {
			if err := emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x11, nil); err != nil {
				return
			}
			slaveClientSeq++
			if err := emitTCP(slaveFlowID, "up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, SlaveLinkPort, spec.DstPort, slaveServerSeq, slaveClientSeq, 0x11, nil); err != nil {
				return
			}
			slaveServerSeq++
			if err := emitTCP(slaveFlowID, "down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, SlaveLinkPort, slaveClientSeq, slaveServerSeq, 0x10, nil); err != nil {
				return
			}
		}
	}()

	return configChan, nil
}

// emitJT809Procedure dispatches one procedure to the builder+emit callback
// (16 型链路管理族，裁定3；方向由 msgTypeByName.upstream 统一推导——
// 主链客户端=下级侧，从链客户端=上级侧).
func emitJT809Procedure(pr *JT809Procedure, cfg *JT809Config, flowID, link string, emit func(flowID, direction string, msgID uint16, body []byte, link string) error) error {
	t, ok := msgTypeByName[pr.Type]
	if !ok {
		return fmt.Errorf("jt809: unknown procedure type %q", pr.Type)
	}
	direction := "up"
	if !t.upstream {
		direction = "down"
	}
	var body []byte
	switch pr.Type {
	case ProcMainLogin:
		body = buildLoginBody(cfg, pr)
	case ProcMainLoginResp:
		body = buildLoginRespBody(pr.Result, pr.VerifyCode)
	case ProcMainLogout, ProcSlaveLogout:
		pw := pr.Password
		if pw == "" {
			pw = cfg.Password
		}
		body = buildLogoutBody(cfg.UserId, pw)
	case ProcMainDisconnect, ProcSlaveDisconnect:
		body = buildCodeBody(pr.ErrorCode)
	case ProcMainClose, ProcSlaveClose:
		body = buildCodeBody(pr.ReasonCode)
	case ProcSlaveConnect:
		body = buildVerifyCodeBody(pr.VerifyCode)
	case ProcSlaveConnectResp:
		body = buildCodeBody(pr.Result)
	default:
		// 空体族：0x1004/0x1005/0x1006/0x9004/0x9005/0x9006。
	}
	return emit(flowID, direction, t.id, body, link)
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
