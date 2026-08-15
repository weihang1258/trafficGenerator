package jtt905

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

const (
	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64
	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS.
	DefaultMSS = 1460
	// MinMSS per RFC 879.
	MinMSS = 536
)

// Planner implements the JT/T 905-2014 protocol planner. A single JTT905
// flow models ONE taxi ISU session over one TCP 4-tuple (design §6C).
type Planner struct{}

// NewPlanner creates a new JTT905 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "jtt905" }

// Validate validates the L3/L4 fields of the spec. Config validation is
// performed via ValidateConfig (core FlowSpec does not carry a JTT905
// pointer until the main agent wires integration).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("jtt905: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("jtt905: invalid DstIP %q", spec.DstIP)
		}
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("jtt905: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
	}
	return nil
}

// ValidateConfig validates a JTT905 config (design §5C.1).
func ValidateConfig(cfg *JTT905Config) error {
	if cfg == nil {
		return fmt.Errorf("jtt905: nil config")
	}
	// Phone: ^\d{12}$.
	if len(cfg.Phone) != 12 {
		return fmt.Errorf("jtt905: Phone %q must be 12 digits", cfg.Phone)
	}
	for i := 0; i < len(cfg.Phone); i++ {
		if cfg.Phone[i] < '0' || cfg.Phone[i] > '9' {
			return fmt.Errorf("jtt905: Phone %q contains non-digit", cfg.Phone)
		}
	}
	// Version.
	if cfg.Version != "" && cfg.Version != jtcommon.Version2011 &&
		cfg.Version != jtcommon.Version2013 && cfg.Version != jtcommon.Version2019 {
		return fmt.Errorf("jtt905: invalid Version %q", cfg.Version)
	}
	// EncryptFlag.
	if cfg.EncryptFlag > 1 {
		return fmt.Errorf("jtt905: EncryptFlag %d must be 0 or 1", cfg.EncryptFlag)
	}
	// DriverId: exactly 20 ASCII chars.
	if len(cfg.DriverId) != DriverIdLen {
		return fmt.Errorf("jtt905: DriverId length %d != %d", len(cfg.DriverId), DriverIdLen)
	}
	for i := 0; i < len(cfg.DriverId); i++ {
		if cfg.DriverId[i] > 0x7F {
			return fmt.Errorf("jtt905: DriverId non-ASCII at %d", i)
		}
	}
	// DriverName: GBK ≤ 16 bytes.
	dn, err := jtcommon.GBKEncode(cfg.DriverName)
	if err != nil {
		return fmt.Errorf("jtt905: DriverName GBK: %w", err)
	}
	if len(dn) > DriverNameLen {
		return fmt.Errorf("jtt905: DriverName GBK length %d > %d", len(dn), DriverNameLen)
	}
	// LicensePlate: GBK ≤ 21 bytes.
	plate, err := jtcommon.GBKEncode(cfg.LicensePlate)
	if err != nil {
		return fmt.Errorf("jtt905: LicensePlate GBK: %w", err)
	}
	if len(plate) > LicensePlateLen {
		return fmt.Errorf("jtt905: LicensePlate GBK length %d > %d", len(plate), LicensePlateLen)
	}
	// LicenseColor: 0,1,2,3,4,5,9.
	switch cfg.LicenseColor {
	case 0, 1, 2, 3, 4, 5, 9:
	default:
		return fmt.Errorf("jtt905: LicenseColor %d invalid (allowed 0,1,2,3,4,5,9)", cfg.LicenseColor)
	}
	// OnTime / OffTime: 12-digit BCD + valid date.
	if cfg.OnTime != "" {
		if _, err := jtcommon.EncodeTimeBCD(cfg.OnTime); err != nil {
			return fmt.Errorf("jtt905: OnTime: %w", err)
		}
	}
	if cfg.OffTime != "" {
		if _, err := jtcommon.EncodeTimeBCD(cfg.OffTime); err != nil {
			return fmt.Errorf("jtt905: OffTime: %w", err)
		}
	}
	// VehicleModel: ASCII ≤ 16.
	if len(cfg.VehicleModel) > VehicleModelLen {
		return fmt.Errorf("jtt905: VehicleModel length %d > %d", len(cfg.VehicleModel), VehicleModelLen)
	}
	for i := 0; i < len(cfg.VehicleModel); i++ {
		if cfg.VehicleModel[i] > 0x7F {
			return fmt.Errorf("jtt905: VehicleModel non-ASCII at %d", i)
		}
	}
	// HeartbeatCount / HeartbeatInterval: ≥ 0.
	if cfg.HeartbeatCount < 0 {
		return fmt.Errorf("jtt905: HeartbeatCount %d must be >= 0", cfg.HeartbeatCount)
	}
	if cfg.HeartbeatInterval < 0 {
		return fmt.Errorf("jtt905: HeartbeatInterval %d must be >= 0", cfg.HeartbeatInterval)
	}
	// Per-procedure ACKFlag: 0-3 only (design §7C.5 — no 99).
	for _, pr := range cfg.Procedures {
		if pr.Type == ProcCenterGeneralResponse || pr.Type == ProcISUGeneralResponse {
			if pr.ACKFlag > 3 {
				return fmt.Errorf("jtt905: ACKFlag %d invalid (allowed 0,1,2,3)", pr.ACKFlag)
			}
		}
	}
	return nil
}

// Plan is not supported for JTT905: the engine requires a full config which
// the core FlowSpec cannot carry. Returning an empty channel here made tasks
// report "completed" with 0 packets. Callers must use PlanWithConfig.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return nil, fmt.Errorf("jtt905: Plan not supported, use PlanWithConfig or a layers config")
}

// PlanWithConfig generates packet configs for a JTT905 flow. It emits a
// TCP 3-way handshake, the check-in → heartbeats → check-out message
// sequence (auto-generated when Procedures is empty, design §5C H-09),
// and a TCP 3-way teardown.
func (p *Planner) PlanWithConfig(ctx context.Context, spec core.FlowSpec, cfg *JTT905Config) (<-chan core.PacketConfig, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("jtt905-%s-%d", cfg.Phone, cfg.InitialSN)
		groupID := hashPhone(cfg.Phone)

		version := cfg.Version
		if version == "" {
			version = jtcommon.Version2019
		}
		phoneBCD, _ := jtcommon.BCDEncode(cfg.Phone)

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

		// MsgSN counters (design §6C.2). msgSN starts at InitialSN and
		// increments after each message; platformMsgSN starts at
		// PlatformInitialSN and increments after each response.
		msgSN := cfg.InitialSN
		platformMsgSN := cfg.PlatformInitialSN

		// Build the procedure list: explicit or auto-generated.
		procedures := cfg.Procedures
		if len(procedures) == 0 {
			procedures = autoProcedures(cfg)
		}

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

		// emitMsg builds and emits one JTT905 message. isISUUpstream=true
		// uses the ISU MsgSN counter; false uses the platform counter.
		emitMsg := func(direction string, msgID uint16, body []byte, isISUUpstream bool) {
			var sn uint16
			if isISUUpstream {
				sn = msgSN
				msgSN++
			} else {
				sn = platformMsgSN
				platformMsgSN++
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

		// --- TCP 3-way handshake ---
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- JTT905 message sequence ---
		for _, pr := range procedures {
			select {
			case <-ctx.Done():
				return
			default:
			}
			switch pr.Type {
			case ProcCheckIn:
				body, err := buildCheckInBody(cfg)
				if err != nil {
					return
				}
				emitMsg("up", MsgCheckIn, body, true)
			case ProcHeartbeat:
				emitMsg("up", MsgHeartbeat, nil, true)
			case ProcCheckOut:
				body, err := buildCheckOutBody(cfg)
				if err != nil {
					return
				}
				emitMsg("up", MsgCheckOut, body, true)
			case ProcCenterGeneralResponse:
				respSN := pr.ResponseSN
				respMsgId := pr.ResponseMsgId
				body := buildGeneralResponseBody(respSN, respMsgId, pr.ACKFlag)
				emitMsg("down", MsgCenterGeneralResp, body, false)
			case ProcISUGeneralResponse:
				respSN := pr.ResponseSN
				respMsgId := pr.ResponseMsgId
				body := buildGeneralResponseBody(respSN, respMsgId, pr.ACKFlag)
				emitMsg("up", MsgISUGeneralResponse, body, true)
			default:
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

// autoProcedures builds the default session when Procedures is empty
// (design §5C H-09):
//
//	1. check-in (0x1001), MsgSN = InitialSN
//	2. center_general_response (0x8001) ACK'ing 0x1001, platform SN starts
//	   at PlatformInitialSN
//	3. for i in 1..HeartbeatCount:
//	     heartbeat (0x0002), MsgSN = InitialSN + i
//	     center_general_response (0x8001) ACK'ing it
//	4. check-out (0x1002), MsgSN = InitialSN + HeartbeatCount + 1
//	5. center_general_response (0x8001) ACK'ing 0x1002
//
// When HeartbeatCount=0, step 3 is skipped (check-in → check-out).
func autoProcedures(cfg *JTT905Config) []JTT905Procedure {
	var procs []JTT905Procedure
	procs = append(procs, JTT905Procedure{Type: ProcCheckIn})
	// The response SNs are auto-bound by the planner at emit time via the
	// counters; the procedure entries only carry the type + ACKFlag.
	procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse, ACKFlag: ACKSuccess})
	for i := 0; i < cfg.HeartbeatCount; i++ {
		procs = append(procs, JTT905Procedure{Type: ProcHeartbeat})
		procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse, ACKFlag: ACKSuccess})
	}
	procs = append(procs, JTT905Procedure{Type: ProcCheckOut})
	procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse, ACKFlag: ACKSuccess})
	return procs
}

// hashPhone computes a stable GroupID from Phone.
func hashPhone(phone string) string {
	h := uint32(2166136261)
	for i := 0; i < len(phone); i++ {
		h ^= uint32(phone[i])
		h *= 16777619
	}
	return fmt.Sprintf("jtt905-%08x", h)
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
