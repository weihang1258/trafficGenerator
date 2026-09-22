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
	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536
)

// Planner implements the JT/T 905.2-2014 taxi ISU protocol planner. One
// flow = one ISU session over a single TCP 4-tuple (default port 10700).
type Planner struct{}

func NewPlanner() *Planner { return &Planner{} }

func (p *Planner) Name() string { return "jtt905" }

// Validate validates the L3/L4 spec fields. Business validation lives in
// ValidateConfig (chain validator anchor).
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

// ValidateConfig validates a JTT905 config（D-JTT905-1 裁定3/6 锚：
// isu_id 12 位/plate≤6 ASCII/Result 0-2/BCD 位数族——嵌套 procedures V9
// 不下探的拦截点=此处遍历）.
func ValidateConfig(cfg *JTT905Config) error {
	if cfg == nil {
		return fmt.Errorf("jtt905: nil config")
	}
	if len(cfg.ISUId) != 12 {
		return fmt.Errorf("jtt905: ISUId %q must be 12 digits", cfg.ISUId)
	}
	for i := 0; i < len(cfg.ISUId); i++ {
		if cfg.ISUId[i] < '0' || cfg.ISUId[i] > '9' {
			return fmt.Errorf("jtt905: ISUId %q contains non-digit", cfg.ISUId)
		}
	}
	if len(cfg.BusinessLicense) > LicenseLen {
		return fmt.Errorf("jtt905: BusinessLicense length %d > %d", len(cfg.BusinessLicense), LicenseLen)
	}
	for i := 0; i < len(cfg.BusinessLicense); i++ {
		if cfg.BusinessLicense[i] > 0x7F {
			return fmt.Errorf("jtt905: BusinessLicense non-ASCII at %d", i)
		}
	}
	if len(cfg.QualificationCode) > QualCodeLen {
		return fmt.Errorf("jtt905: QualificationCode length %d > %d", len(cfg.QualificationCode), QualCodeLen)
	}
	for i := 0; i < len(cfg.QualificationCode); i++ {
		if cfg.QualificationCode[i] > 0x7F {
			return fmt.Errorf("jtt905: QualificationCode non-ASCII at %d", i)
		}
	}
	if len(cfg.PlateNo) > PlateLen {
		return fmt.Errorf("jtt905: PlateNo length %d > %d", len(cfg.PlateNo), PlateLen)
	}
	for i := 0; i < len(cfg.PlateNo); i++ {
		if cfg.PlateNo[i] > 0x7F {
			return fmt.Errorf("jtt905: PlateNo non-ASCII at %d", i)
		}
	}
	// BCD 位数族（0x0B04；空=缺省全 0 合法）——长度+数字性双查
	//（复审 L1：等长非数字串不得漏到 BCDEncode 才以他锚词失败）。
	for _, f := range []struct {
		v   string
		n   int
		key string
	}{
		{cfg.TaximeterKValue, 4, "TaximeterKValue"},
		{cfg.OnDutyMileage, 6, "OnDutyMileage"},
		{cfg.OnDutyOperationMileage, 6, "OnDutyOperationMileage"},
		{cfg.TrainNumber, 4, "TrainNumber"},
		{cfg.TimingTime, 6, "TimingTime"},
		{cfg.TotalAmount, 6, "TotalAmount"},
		{cfg.CardAmount, 6, "CardAmount"},
		{cfg.CardCount, 4, "CardCount"},
		{cfg.OnDutyMileageBetween, 4, "OnDutyMileageBetween"},
		{cfg.TotalMileage, 8, "TotalMileage"},
		{cfg.TotalOperationMileage, 8, "TotalOperationMileage"},
		{cfg.UnitPrice, 4, "UnitPrice"},
	} {
		if f.v == "" {
			continue
		}
		if len(f.v) != f.n {
			return fmt.Errorf("jtt905: %s %q must be %d digits", f.key, f.v, f.n)
		}
		for i := 0; i < len(f.v); i++ {
			if f.v[i] < '0' || f.v[i] > '9' {
				return fmt.Errorf("jtt905: %s %q contains non-digit", f.key, f.v)
			}
		}
	}
	if err := checkTime12("OnDutyPowerOnTime", cfg.OnDutyPowerOnTime, "yyyyMMddHHmm"); err != nil {
		return err
	}
	if err := checkTime12("OnDutyPowerOffTime", cfg.OnDutyPowerOffTime, "yyyyMMddHHmm"); err != nil {
		return err
	}
	if cfg.Position != nil {
		if err := checkTime12("position Time", cfg.Position.Time, "yyMMddHHmmss"); err != nil {
			return err
		}
	}
	for i := range cfg.Procedures {
		pr := &cfg.Procedures[i]
		if _, ok := msgTypeByName[pr.Type]; !ok {
			return fmt.Errorf("jtt905: unknown procedure type %q (procedures[%d])", pr.Type, i)
		}
		if (pr.Type == ProcCenterGeneralResponse || pr.Type == ProcISUGeneralResponse) && pr.Result > 2 {
			return fmt.Errorf("jtt905: Result %d > 2 (allowed 0,1,2)", pr.Result)
		}
	}
	return nil
}

// Plan is not supported: the engine requires the full config. Use
// PlanWithConfig (唯一入口，防 0 包静默).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return nil, fmt.Errorf("jtt905: Plan not supported, use PlanWithConfig or a layers config")
}

// PlanWithConfig generates the ISU session: TCP 3-way handshake →
// check-in → center resp → (heartbeat → center resp)×N → check-out →
// center resp → TCP teardown（procedures 空时自动生成，裁定4）.
func (p *Planner) PlanWithConfig(ctx context.Context, spec core.FlowSpec, cfg *JTT905Config) (<-chan core.PacketConfig, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}

	// Resolved defaults（不改调用方 cfg）。
	rc := *cfg
	if rc.HeartbeatCount == 0 {
		rc.HeartbeatCount = 1
	}
	isuBCD, err := jtcommon.BCDEncode(rc.ISUId)
	if err != nil {
		return nil, fmt.Errorf("jtt905: ISUId: %w", err)
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("jtt905-%s-%d", rc.ISUId, rc.InitialSN)
		groupID := hashISU(rc.ISUId)

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

		// 双流水号计数器：ISU 侧（InitialSN 起）/中心侧（PlatformInitialSN 起）。
		isuSN := rc.InitialSN
		centerSN := rc.PlatformInitialSN
		lastUpMsgID := uint16(0)
		lastUpSN := uint16(0)

		emitTCP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) error {
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

		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (uint32, error) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq, ctx.Err()
				default:
				}
				if err := emitTCP(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg); err != nil {
					return senderSeq, err
				}
				senderSeq += uint32(len(seg))
			}
			return senderSeq, nil
		}

		// emitMsg builds one JTT905 frame; 计数器按方向选（裁定2/4）。
		emitMsg := func(direction string, msgID uint16, body []byte) error {
			var sn uint16
			isDown := direction == "down"
			if isDown {
				sn = centerSN
				centerSN++
			} else {
				sn = isuSN
				isuSN++
				lastUpMsgID = msgID
				lastUpSN = sn
			}
			frame, err := buildSimpleFrame(msgID, body, isuBCD, sn)
			if err != nil {
				return err
			}
			var srcMAC, dstMAC, srcIP, dstIP string
			var srcPort, dstPort uint16
			if isDown {
				srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
				srcIP, dstIP = spec.DstIP, spec.SrcIP
				srcPort, dstPort = spec.DstPort, spec.SrcPort
			} else {
				srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
				srcIP, dstIP = spec.SrcIP, spec.DstIP
				srcPort, dstPort = spec.SrcPort, spec.DstPort
			}
			if isDown {
				serverSeq, err = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, frame)
			} else {
				clientSeq, err = emitData(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, frame)
			}
			return err
		}

		// --- TCP 3-way handshake ---
		if err := emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil); err != nil {
			return
		}
		clientSeq++
		if err := emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil); err != nil {
			return
		}
		serverSeq++
		if err := emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil); err != nil {
			return
		}

		// --- message sequence ---
		procedures := rc.Procedures
		if len(procedures) == 0 {
			procedures = autoProcedures(&rc)
		}
		for i := range procedures {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pr := &procedures[i]
			t := msgTypeByName[pr.Type]
			direction := "up"
			if t.down {
				direction = "down"
			}
			var body []byte
			switch pr.Type {
			case ProcCheckIn:
				if body, err = buildCheckInBody(&rc); err != nil {
					return
				}
			case ProcCheckOut:
				if body, err = buildCheckOutBody(&rc); err != nil {
					return
				}
			case ProcCenterGeneralResponse:
				// 应答自动绑最近上行（reply_sn/reply_msg_id=0 时）。
				rsn, rid := pr.ReplySN, pr.ReplyMsgId
				if rsn == 0 {
					rsn = lastUpSN
				}
				if rid == 0 {
					rid = lastUpMsgID
				}
				body = buildGeneralResponseBody(rsn, rid, pr.Result)
			case ProcISUGeneralResponse:
				rsn, rid := pr.ReplySN, pr.ReplyMsgId
				if rsn == 0 {
					rsn = centerSN - 1
				}
				if rid == 0 {
					rid = MsgTextDownRef
				}
				body = buildGeneralResponseBody(rsn, rid, pr.Result)
			default: // ProcHeartbeat：空体
			}
			if err := emitMsg(direction, t.id, body); err != nil {
				return
			}
		}

		// --- TCP 3-way teardown ---
		if err := emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil); err != nil {
			return
		}
		clientSeq++
		if err := emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil); err != nil {
			return
		}
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// checkTime12 校验 BCD 时间串（长度+数字性；空=缺省合法）。
func checkTime12(key, v, layout string) error {
	if v == "" {
		return nil
	}
	if len(v) != 12 {
		return fmt.Errorf("jtt905: %s %q must be 12 digits (%s)", key, v, layout)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return fmt.Errorf("jtt905: %s %q contains non-digit", key, v)
		}
	}
	return nil
}

// MsgTextDownRef 是 isu_general_response 未给 reply_msg_id 时的缺省应答
// 对象（0x8300 文本下发——在库 probe 面最近似的中心下行命令）。
const MsgTextDownRef = 0x8300

// autoProcedures builds the default session（procedures 空）：签到→应答→
// (心跳→应答)×N→签退→应答（legacy H-09 形保留，MsgId 已实名化）。
func autoProcedures(cfg *JTT905Config) []JTT905Procedure {
	var procs []JTT905Procedure
	procs = append(procs, JTT905Procedure{Type: ProcCheckIn})
	procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse})
	for i := 0; i < cfg.HeartbeatCount; i++ {
		procs = append(procs, JTT905Procedure{Type: ProcHeartbeat})
		procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse})
	}
	procs = append(procs, JTT905Procedure{Type: ProcCheckOut})
	procs = append(procs, JTT905Procedure{Type: ProcCenterGeneralResponse})
	return procs
}

func hashISU(isu string) string {
	h := uint32(2166136261)
	for i := 0; i < len(isu); i++ {
		h ^= uint32(isu[i])
		h *= 16777619
	}
	return fmt.Sprintf("jtt905-%08x", h)
}

func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42
	}
	return uint32(n.Uint64())
}

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
