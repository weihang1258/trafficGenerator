// Package doip implements the DOIP (Diagnostic over IP, ISO 13400-2) planner.
package doip

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the DOIP protocol planner.
type Planner struct{}

// NewPlanner creates a new DOIP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "doip" }

// Validate validates a DOIP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("doip: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("doip: invalid DstIP %q", spec.DstIP)
		}
	}

	cfg := spec.DoIP
	if cfg == nil {
		return fmt.Errorf("doip: DoIP config is required")
	}

	pv := cfg.ProtocolVersion
	if pv == 0 {
		pv = DefaultProtocolVersion
	}
	if pv != 0x01 && pv != 0x02 {
		return fmt.Errorf("doip: ProtocolVersion must be 0x01 or 0x02, got 0x%02X", pv)
	}

	// V1 restrictions per section 1.3/section 8.1.
	if pv == ProtocolVersionV1 {
		if cfg.PowerMode != nil {
			return fmt.Errorf("doip: V1 does not support PowerMode (design choice, not ISO requirement)")
		}
		if cfg.Activation != nil && len(cfg.Activation.OEMSpecific) > 0 {
			return fmt.Errorf("doip: V1 does not support OEM-specific data")
		}
	}

	// Validate Discovery.
	if cfg.Discovery != nil {
		d := cfg.Discovery
		dir := normalizeDirection(d.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: Discovery.Direction must be \"up\", \"down\", or empty")
		}
		if d.RequestType != 0x0001 && d.RequestType != 0x0002 && d.RequestType != 0x0003 {
			if dir != dirDown {
				return fmt.Errorf("doip: Discovery.RequestType must be 0x0001, 0x0002, or 0x0003")
			}
		}
		if d.FurtherActionRequired != 0x00 && d.FurtherActionRequired != 0x10 {
			return fmt.Errorf("doip: FurtherActionRequired must be 0x00 or 0x10, got 0x%02X", d.FurtherActionRequired)
		}
		if d.SyncStatus != 0x00 && d.SyncStatus != 0x10 {
			return fmt.Errorf("doip: SyncStatus must be 0x00 or 0x10, got 0x%02X", d.SyncStatus)
		}
		if len(cfg.VIN) != 0 && len(cfg.VIN) != VINLength {
			return fmt.Errorf("doip: VIN must be %d bytes, got %d", VINLength, len(cfg.VIN))
		}
		if len(cfg.EID) != 0 && len(cfg.EID) != EIDLength*2 {
			return fmt.Errorf("doip: EID must be %d hex chars, got %d", EIDLength*2, len(cfg.EID))
		}
		if len(cfg.GID) != 0 && len(cfg.GID) != GIDLength*2 {
			return fmt.Errorf("doip: GID must be %d hex chars, got %d", GIDLength*2, len(cfg.GID))
		}
	}

	// Validate EntityStatus.
	if cfg.EntityStatus != nil {
		es := cfg.EntityStatus
		dir := normalizeDirection(es.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: EntityStatus.Direction must be \"up\", \"down\", or empty")
		}
		if es.NodeType != 0x00 && es.NodeType != 0x01 {
			return fmt.Errorf("doip: NodeType must be 0x00 or 0x01, got 0x%02X", es.NodeType)
		}
		if es.CurOpenSockets > es.MaxOpenSockets {
			return fmt.Errorf("doip: CurOpenSockets (%d) > MaxOpenSockets (%d)", es.CurOpenSockets, es.MaxOpenSockets)
		}
	}

	// Validate PowerMode.
	if cfg.PowerMode != nil {
		pm := cfg.PowerMode
		dir := normalizeDirection(pm.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: PowerMode.Direction must be \"up\", \"down\", or empty")
		}
		if pm.PowerMode != 0x00 && pm.PowerMode != 0x01 && pm.PowerMode != 0x02 {
			return fmt.Errorf("doip: PowerMode must be 0x00, 0x01, or 0x02, got 0x%02X", pm.PowerMode)
		}
	}

	// Validate Activation.
	if cfg.Activation != nil {
		act := cfg.Activation
		dir := normalizeDirection(act.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: Activation.Direction must be \"up\", \"down\", or empty")
		}
		if act.ActivationType != 0x00 && act.ActivationType != 0x01 {
			if act.ActivationType < 0xE0 {
				return fmt.Errorf("doip: ActivationType must be 0x00, 0x01, or 0xE0-0xFF, got 0x%02X", act.ActivationType)
			}
		}
		// ResponseCode per section 8.2: 0x00-0x07 (denied), 0x10 (success),
		// 0x11 (confirmation required); 0x08-0x0F and 0x12-0xFF rejected.
		if rc := act.ResponseCode; rc > 0x07 && rc != 0x10 && rc != 0x11 {
			return fmt.Errorf("doip: ResponseCode must be 0x00-0x07, 0x10, or 0x11, got 0x%02X", rc)
		}
	}

	// Messages require a successful routing activation first (section 4.4,
	// testcase T163: Activation=nil + Messages non-empty -> Validate error).
	if len(cfg.Messages) > 0 && cfg.Activation == nil {
		return fmt.Errorf("doip: Messages require Activation (diagnostic messages need routing activation first)")
	}

	// Effective addresses with section 3.2 defaults, so consistency checks
	// below do not misfire when the user left TesterAddress/LogicalAddress
	// unset (0) but set explicit SA/TA on messages or alive check.
	testerAddr := cfg.TesterAddress
	if testerAddr == 0 {
		testerAddr = DefaultTesterAddress
	}
	logicalAddr := cfg.LogicalAddress
	if logicalAddr == 0 {
		logicalAddr = DefaultLogicalAddress
	}

	// Validate Messages.
	for i, msg := range cfg.Messages {
		dir := normalizeDirection(msg.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: Messages[%d].Direction must be \"up\", \"down\", or empty", i)
		}
		if msg.AckCode != 0x00 {
			return fmt.Errorf("doip: Messages[%d].AckCode must be 0x00", i)
		}
		if msg.NackCode != nil {
			nc := *msg.NackCode
			if nc < 0x02 || nc > 0x08 {
				return fmt.Errorf("doip: Messages[%d].NackCode must be 0x02-0x08, got 0x%02X", i, nc)
			}
		}
		// SA/TA consistency check per section 8.3.
		if dir == dirUp || dir == "" {
			if msg.SourceAddress != 0 && msg.SourceAddress != testerAddr {
				return fmt.Errorf("doip: Messages[%d].SourceAddress (0x%04X) must match TesterAddress (0x%04X)", i, msg.SourceAddress, testerAddr)
			}
			if msg.TargetAddress != 0 && msg.TargetAddress != logicalAddr {
				return fmt.Errorf("doip: Messages[%d].TargetAddress (0x%04X) must match LogicalAddress (0x%04X)", i, msg.TargetAddress, logicalAddr)
			}
		}
		// UDS validation.
		if msg.UDS != nil {
			if err := validateUDS(msg.UDS, i); err != nil {
				return err
			}
		}
		// UserData length limits per section 8.5.
		// 1) PayloadLength u32 overflow guard (testcase T068): 0x8001
		//    PayloadLength = 4 + M, 0x8002/0x8003 = 5 + M, both must fit in
		//    u32, so M <= MaxUint32-5 (theoretical boundary, section 6.13.8).
		udLen := len(msg.UserData)
		if msg.UDS != nil {
			udLen = len(serializeUDS(msg.UDS))
		}
		if uint64(udLen) > uint64(math.MaxUint32-5) {
			return fmt.Errorf("doip: Messages[%d].UserData length (%d) exceeds u32 PayloadLength limit", i, udLen)
		}
		// 2) MaxDataSize check per section 8.5.
		if cfg.EntityStatus != nil && cfg.EntityStatus.MaxDataSize > 0 {
			if uint32(udLen) > cfg.EntityStatus.MaxDataSize {
				return fmt.Errorf("doip: Messages[%d].UserData length (%d) exceeds MaxDataSize (%d)", i, udLen, cfg.EntityStatus.MaxDataSize)
			}
		}
	}

	// Validate AliveCheck.
	if cfg.AliveCheck != nil {
		ac := cfg.AliveCheck
		dir := normalizeDirection(ac.Direction)
		if dir != "" && dir != dirUp && dir != dirDown {
			return fmt.Errorf("doip: AliveCheck.Direction must be \"up\", \"down\", or empty")
		}
		if ac.SourceAddress != 0 && ac.SourceAddress != testerAddr {
			return fmt.Errorf("doip: AliveCheck.SourceAddress (0x%04X) must match TesterAddress (0x%04X)", ac.SourceAddress, testerAddr)
		}
	}

	// Validate GenericNack.
	if cfg.GenericNack != nil {
		if cfg.GenericNack.NackCode > 0x04 {
			return fmt.Errorf("doip: GenericNack.NackCode must be 0x00-0x04, got 0x%02X", cfg.GenericNack.NackCode)
		}
	}

	// MSS check per section 8.5: spec.TCP.MSS > 0 is required when set;
	// MSS=0 is allowed to fall back to DefaultMSS (1460) per H5's "或"
	// policy ("Validate 报错 or fallback 1460，by caller choice"). This
	// implementation chooses the fallback branch when TCP is configured but
	// MSS is left at the zero value.
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("doip: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
	}

	return nil
}

// validateUDS validates a UDS configuration.
func validateUDS(uds *core.DoIPUDS, idx int) error {
	validSIDs := map[uint8]bool{
		0x10: true, 0x11: true, 0x22: true, 0x27: true, 0x2E: true,
		0x31: true, 0x34: true, 0x36: true, 0x37: true, 0x3E: true,
	}
	if !validSIDs[uds.ServiceID] {
		return fmt.Errorf("doip: Messages[%d].UDS.ServiceID 0x%02X is not supported", idx, uds.ServiceID)
	}

	// HasSubFunction validation per section 8.4.
	noSubFuncSIDs := map[uint8]bool{0x22: true, 0x2E: true, 0x34: true, 0x36: true, 0x37: true}
	if uds.HasSubFunction != nil && *uds.HasSubFunction {
		if noSubFuncSIDs[uds.ServiceID] {
			return fmt.Errorf("doip: Messages[%d].UDS.ServiceID 0x%02X does not support sub-function", idx, uds.ServiceID)
		}
	}

	// NRC validation per section 8.2.
	if uds.NegativeResponseCode != 0 {
		if uds.NegativeResponseCode < 0x01 || uds.NegativeResponseCode > 0x7F {
			return fmt.Errorf("doip: Messages[%d].UDS.NegativeResponseCode must be 0x01-0x7F, got 0x%02X", idx, uds.NegativeResponseCode)
		}
	}

	// ServiceID=0x27 Key validation per section 8.4 (H3).
	if uds.ServiceID == 0x27 && uds.IsResponse {
		// Even sub-function response should not have Key.
		if uds.SubFunction%2 == 0 && len(uds.Key) > 0 {
			return fmt.Errorf("doip: Messages[%d].UDS.Key must be empty for even sub-function response", idx)
		}
	}

	return nil
}

// Plan generates packet configs for a DOIP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		cfg := spec.DoIP
		if cfg == nil {
			return
		}

		pv := cfg.ProtocolVersion
		if pv == 0 {
			pv = DefaultProtocolVersion
		}
		invPV := inverseProtocolVersion(pv)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Resolve MSS.
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Determine if IPv6.
		ipv6 := isIPv6(spec.SrcIP)

		// Default addresses.
		srcIP := spec.SrcIP
		dstIP := spec.DstIP
		srcMAC := spec.SrcMAC
		dstMAC := spec.DstMAC

		// Resolve EID from DstMAC if empty.
		eid := cfg.EID
		if eid == "" {
			macBytes := parseMAC(dstMAC)
			if macBytes != nil {
				eid = strings.ReplaceAll(dstMAC, ":", "")
			}
		}
		if eid == "" {
			eid = "000000000000"
		}

		// Resolve GID.
		gid := cfg.GID
		if gid == "" {
			gid = "000000000000"
		}

		// Default VIN.
		vin := cfg.VIN
		if vin == "" {
			vin = "00000000000000000"
		}

		// Default addresses.
		testerAddr := cfg.TesterAddress
		if testerAddr == 0 {
			testerAddr = DefaultTesterAddress
		}
		logicalAddr := cfg.LogicalAddress
		if logicalAddr == 0 {
			logicalAddr = DefaultLogicalAddress
		}

		// TCP sequence state for the routing-activation TCP connection.
		// Populated after the 3-way handshake; emitDoIP advances the sender's
		// seq by the DoIP frame size (header+payload) so the Wireshark TCP
		// stream stays monotonic (testcase T175 阶段顺序 / S15 faithful flow).
		var tcpClientSeq, tcpServerSeq uint32

		// --- Helper: emit DoIP packet ---
		// direction "" falls back to the PayloadType default. "down" packets
		// (ECU->Tester) swap the L2/L3 endpoints and ports (the caller already
		// passes source/dest ports for the down direction; only MAC/IP swap is
		// handled here because the shared emitDoIP builds L2/L3 from its own
		// captured variables).
		emitDoIP := func(flowID, direction string, pt uint16, payload []byte, srcPort, dstPort uint16, proto string) {
			if direction == "" {
				direction = defaultDirection(pt)
			}

			// Down-direction frames originate from the ECU.
			sMAC, dMAC := srcMAC, dstMAC
			sIP, dIP := srcIP, dstIP
			if direction == dirDown {
				sMAC, dMAC = dMAC, sMAC
				sIP, dIP = dIP, sIP
			}

			// Build DoIP header.
			header := make([]byte, DoIPHeaderLen)
			header[0] = pv
			header[1] = invPV
			header[2] = byte(pt >> 8)
			header[3] = byte(pt)
			pl := uint32(len(payload))
			header[4] = byte(pl >> 24)
			header[5] = byte(pl >> 16)
			header[6] = byte(pl >> 8)
			header[7] = byte(pl)

			fullPayload := append(header, payload...)

			// Determine L2/L3/L4.
			var l4 core.L4Config
			if proto == "tcp" {
				var seq, ack uint32
				if direction == dirDown {
					seq, ack = tcpServerSeq, tcpClientSeq
				} else {
					seq, ack = tcpClientSeq, tcpServerSeq
				}
				l4 = core.L4Config{
					Protocol: "tcp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
					Seq:      seq,
					Ack:      ack,
					Flags:    0x18, // PSH-ACK
				}
				// TCP data packets advance the sender's sequence number by the
				// full DoIP frame length (header + payload).
				if direction == dirDown {
					tcpServerSeq += uint32(len(fullPayload))
				} else {
					tcpClientSeq += uint32(len(fullPayload))
				}
			} else {
				l4 = core.L4Config{
					Protocol: "udp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
				}
			}

			l3 := core.L3Base(sIP, dIP, 6, effectiveTTL, nextIPID(), spec)
			if proto == "udp" {
				l3.Protocol = 17
			}

			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   time.Now(),
				L2: core.L2Config{
					SrcMAC:    sMAC,
					DstMAC:    dMAC,
					EtherType: core.EtherTypeFor(sIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  fullPayload,
				Metadata: groupIDMeta(spec),
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// --- Phase 1: Vehicle Discovery (UDP) ---
		if cfg.Discovery != nil {
			disc := cfg.Discovery
			flowID := fmt.Sprintf("%s-%s-%d-%d:udp:disc", srcIP, dstIP, cfg.SrcPort, DefaultUDPPort)

			dir := normalizeDirection(disc.Direction)
			if dir == "" {
				dir = dirDown // default: ECU announcement
			}

			// Broadcast applies to the Tester->ECU requests (0x0001/0x0002/
			// 0x0003): per section 3.3, Broadcast=true overrides DstIP/DstMAC
			// with 255.255.255.255+ff:ff:ff:ff:ff:ff (IPv4) or ff02::1+
			// 33:33:00:00:00:01 (IPv6). The ECU announcement (down) stays a
			// unicast reply to the Tester. The dstIP/dstMAC variables are
			// captured by reference in emitDoIP, so temporarily overriding
			// them here affects only the request packets; restore afterwards
			// so later phases (EntityStatus/PowerMode/Activation) keep the
			// configured unicast addresses.
			origDstIP, origDstMAC := dstIP, dstMAC
			if disc.Broadcast && dir == dirUp {
				if ipv6 {
					dstIP = ipv6AllNodesMulticast
					dstMAC = ipv6MulticastMAC(ipv6AllNodesMulticast)
				} else {
					dstIP = ipv4Broadcast
					dstMAC = ipv4BroadcastMAC
				}
			}

			if dir == dirUp {
				// Tester -> ECU: 0x0001/0x0002/0x0003
				switch disc.RequestType {
				case 0x0001:
					// Vehicle Identification Request (no payload).
					emitDoIP(flowID, dirUp, PTVehicleIDRequest, nil, cfg.SrcPort, DefaultUDPPort, "udp")
				case 0x0002:
					// Vehicle Identification Request with EID.
					eidBytes := parseMAC(eid)
					if eidBytes == nil {
						eidBytes = make([]byte, 6)
					}
					emitDoIP(flowID, dirUp, PTVehicleIDRequestEID, eidBytes, cfg.SrcPort, DefaultUDPPort, "udp")
				case 0x0003:
					// Vehicle Identification Request with VIN.
					vinBytes := []byte(vin)
					if len(vinBytes) < VINLength {
						vinBytes = append(vinBytes, make([]byte, VINLength-len(vinBytes))...)
					}
					emitDoIP(flowID, dirUp, PTVehicleIDRequestVIN, vinBytes, cfg.SrcPort, DefaultUDPPort, "udp")
				}
			} else {
				// ECU -> Tester: 0x0004 Vehicle Announcement.
				count := disc.AnnouncementCount
				if count == 0 {
					count = DefaultAnnouncementCount
				}
				for i := uint8(0); i < count; i++ {
					payload := buildVehicleAnnouncement(vin, logicalAddr, eid, gid, disc.FurtherActionRequired, disc.SyncStatus, pv)
					emitDoIP(flowID, dirDown, PTVehicleAnnouncement, payload, DefaultUDPPort, cfg.SrcPort, "udp")
				}
			}
			dstIP, dstMAC = origDstIP, origDstMAC
		}

		// --- Phase 2: Entity Status (UDP) ---
		if cfg.EntityStatus != nil {
			es := cfg.EntityStatus
			flowID := fmt.Sprintf("%s-%s-%d-%d:udp:entity", srcIP, dstIP, cfg.SrcPort, DefaultUDPPort)

			dir := normalizeDirection(es.Direction)
			if dir == "" {
				dir = dirDown // default: ECU response
			}

			if dir == dirUp {
				// 0x4001 Entity Status Request (no payload).
				emitDoIP(flowID, dirUp, PTEntityStatusRequest, nil, cfg.SrcPort, DefaultUDPPort, "udp")
			} else {
				// 0x4002 Entity Status Response.
				payload := buildEntityStatusResponse(es)
				emitDoIP(flowID, dirDown, PTEntityStatusResponse, payload, DefaultUDPPort, cfg.SrcPort, "udp")
			}
		}

		// --- Phase 3: Power Mode (UDP) ---
		if cfg.PowerMode != nil {
			pm := cfg.PowerMode
			flowID := fmt.Sprintf("%s-%s-%d-%d:udp:power", srcIP, dstIP, cfg.SrcPort, DefaultUDPPort)

			dir := normalizeDirection(pm.Direction)
			if dir == "" {
				dir = dirDown // default: ECU response
			}

			// Broadcast only applies to the Tester->ECU 0x4003 request
			// (section 3.3): override DstIP/DstMAC for the request frame;
			// the ECU 0x4004 response stays a unicast reply to the Tester.
			// Restore afterwards (dstIP/dstMAC are captured by reference in
			// emitDoIP).
			origDstIP, origDstMAC := dstIP, dstMAC
			if pm.Broadcast && dir == dirUp {
				if ipv6 {
					dstIP = ipv6AllNodesMulticast
					dstMAC = ipv6MulticastMAC(ipv6AllNodesMulticast)
				} else {
					dstIP = ipv4Broadcast
					dstMAC = ipv4BroadcastMAC
				}
			}

			if dir == dirUp {
				// 0x4003 Power Mode Request (no payload).
				emitDoIP(flowID, dirUp, PTPowerModeRequest, nil, cfg.SrcPort, DefaultUDPPort, "udp")
			} else {
				// 0x4004 Power Mode Response.
				payload := []byte{pm.PowerMode}
				emitDoIP(flowID, dirDown, PTPowerModeResponse, payload, DefaultUDPPort, cfg.SrcPort, "udp")
			}
			dstIP, dstMAC = origDstIP, origDstMAC
		}

		// --- Phase 4: Routing Activation (TCP) ---
		activationSuccess := false
		if cfg.Activation != nil {
			act := cfg.Activation
			flowID := fmt.Sprintf("%s-%s-%d-%d:tcp:act", srcIP, dstIP, spec.SrcPort, DefaultTCPPort)

			// TCP handshake.
			clientSeq := rand.Uint32()
			serverSeq := rand.Uint32()

			// SYN.
			emitTCP(ctx, flowID, "up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, DefaultTCPPort,
				clientSeq, 0, 0x02, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
			clientSeq++
			// SYN-ACK.
			emitTCP(ctx, flowID, "down", dstMAC, srcMAC, dstIP, srcIP, DefaultTCPPort, spec.SrcPort,
				serverSeq, clientSeq, 0x12, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
			serverSeq++
			// ACK.
			emitTCP(ctx, flowID, "up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, DefaultTCPPort,
				clientSeq, serverSeq, 0x10, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)

			// Handshake done: emitDoIP advances these per data segment.
			tcpClientSeq, tcpServerSeq = clientSeq, serverSeq

			// 0x0005 Routing Activation Request.
			dir := normalizeDirection(act.Direction)
			if dir == "" {
				dir = dirUp
			}
			reqPayload := buildRoutingActivationRequest(testerAddr, act.ActivationType, act.OEMSpecific)
			emitDoIP(flowID, dirUp, PTRoutingActivationReq, reqPayload, spec.SrcPort, DefaultTCPPort, "tcp")

			// 0x0006 Routing Activation Response.
			respPayload := buildRoutingActivationResponse(testerAddr, logicalAddr, act.ResponseCode, act.OEMSpecific)
			emitDoIP(flowID, dirDown, PTRoutingActivationResp, respPayload, DefaultTCPPort, spec.SrcPort, "tcp")

			// Check if activation succeeded.
			if act.ResponseCode == 0x10 {
				activationSuccess = true
			}

			// Confirmation required (section 4.3 sub-phase): Tester re-sends
			// 0x0005, ECU answers with a final 0x0006. The final response
			// code is not modeled in DoIPActivation (single ResponseCode
			// field), so the final answer is the success 0x10 — the testcase
			// T027a rejection path (final 0x05 + TCP FIN) cannot be expressed
			// by the current config schema and is left for a schema extension.
			if act.ResponseCode == 0x11 && act.ConfirmationRequired {
				// Second 0x0005.
				emitDoIP(flowID, dirUp, PTRoutingActivationReq, reqPayload, spec.SrcPort, DefaultTCPPort, "tcp")
				// Second 0x0006 (final success).
				finalPayload := buildRoutingActivationResponse(testerAddr, logicalAddr, 0x10, act.OEMSpecific)
				emitDoIP(flowID, dirDown, PTRoutingActivationResp, finalPayload, DefaultTCPPort, spec.SrcPort, "tcp")
				activationSuccess = true
			}

			// If activation failed (ResponseCode 0x00-0x07, or 0x11 without
			// confirmation), the ECU closes the TCP connection with a FIN
			// (section 4.3/section 9.2) and Messages/AliveCheck are skipped.
			if !activationSuccess {
				// FIN from ECU.
				emitTCP(ctx, flowID, "down", dstMAC, srcMAC, dstIP, srcIP, DefaultTCPPort, spec.SrcPort,
					tcpServerSeq, tcpClientSeq, 0x11, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
				tcpServerSeq++
				// ACK from Tester.
				emitTCP(ctx, flowID, "up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, DefaultTCPPort,
					tcpClientSeq, tcpServerSeq, 0x10, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
				return
			}
		}

		// --- Phase 5: Diagnostic Messages (TCP) ---
		if len(cfg.Messages) > 0 && activationSuccess {
			flowID := fmt.Sprintf("%s-%s-%d-%d:tcp:diag", srcIP, dstIP, spec.SrcPort, DefaultTCPPort)

			for _, msg := range cfg.Messages {
				dir := normalizeDirection(msg.Direction)
				if dir == "" {
					dir = dirUp // default: Tester->ECU
				}

				// Determine SA/TA.
				sa := msg.SourceAddress
				ta := msg.TargetAddress
				if sa == 0 {
					sa = testerAddr
				}
				if ta == 0 {
					ta = logicalAddr
				}
				if dir == dirDown {
					sa, ta = ta, sa // swap for response direction
				}

				// Build UserData.
				userData := msg.UserData
				if msg.UDS != nil {
					userData = serializeUDS(msg.UDS)
				}

				// 0x36 TransferData segmentation per section 5.2: when the
				// serialized user data exceeds MSS-40 (TCP/IP header
				// overhead), split the data into chunks of MSS-40-2 (SID +
				// BlockSeq) bytes, each carried by its own 0x8001 with the
				// BlockSequenceCounter advancing n%256 (section 8.4).
				var chunks [][]byte
				if msg.UDS != nil && msg.UDS.ServiceID == 0x36 && len(userData) > int(mss)-40 {
					maxChunk := int(mss) - 40 - 2
					if maxChunk < 1 {
						maxChunk = 1
					}
					data := msg.UDS.TransferData
					blockSeq := msg.UDS.BlockSequenceCounter
					for len(data) > 0 {
						n := maxChunk
						if len(data) < n {
							n = len(data)
						}
						// SID byte is the serialized first byte (0x36 request
						// or 0x76 positive response).
						chunk := append([]byte{userData[0], blockSeq}, data[:n]...)
						chunks = append(chunks, chunk)
						data = data[n:]
						blockSeq++
					}
				}
				if len(chunks) == 0 {
					chunks = [][]byte{userData}
				}

				for _, ud := range chunks {
					// L4 ports follow the frame direction: Tester uses
					// spec.SrcPort, ECU uses 13400.
					msgSrcPort, msgDstPort := spec.SrcPort, DefaultTCPPort
					if dir == dirDown {
						msgSrcPort, msgDstPort = DefaultTCPPort, spec.SrcPort
					}

					// 0x8001 Diagnostic Message.
					diagPayload := buildDiagnosticMessage(sa, ta, ud)
					emitDoIP(flowID, dir, PTDiagnosticMessage, diagPayload, msgSrcPort, msgDstPort, "tcp")

					// 0x8002 Ack or 0x8003 Nack. The acknowledgement is sent
					// by the receiving side, i.e. in the opposite direction
					// of the 0x8001 (section 2.14/2.15: Ack SA = 0x8001 TA,
					// Ack TA = 0x8001 SA).
					ackDir := dirDown
					if dir == dirDown {
						ackDir = dirUp
					}
					ackSrcPort, ackDstPort := DefaultTCPPort, spec.SrcPort
					if ackDir == dirUp {
						ackSrcPort, ackDstPort = spec.SrcPort, DefaultTCPPort
					}
					if msg.NackCode == nil {
						ackPayload := buildDiagnosticMessageAck(ta, sa, ud)
						emitDoIP(flowID, ackDir, PTDiagnosticMessageAck, ackPayload, ackSrcPort, ackDstPort, "tcp")
					} else {
						nackPayload := buildDiagnosticMessageNack(ta, sa, *msg.NackCode, ud)
						emitDoIP(flowID, ackDir, PTDiagnosticMessageNack, nackPayload, ackSrcPort, ackDstPort, "tcp")
					}
				}
			}
		}

		// --- Phase 6: Alive Check (TCP) ---
		if cfg.AliveCheck != nil {
			ac := cfg.AliveCheck
			flowID := fmt.Sprintf("%s-%s-%d-%d:tcp:alive", srcIP, dstIP, spec.SrcPort, DefaultTCPPort)

			dir := normalizeDirection(ac.Direction)
			if dir == "" {
				dir = dirDown // default: ECU->Tester
			}

			if dir == dirDown {
				// 0x0007 Alive Check Request (no payload).
				emitDoIP(flowID, dirDown, PTAliveCheckRequest, nil, DefaultTCPPort, spec.SrcPort, "tcp")
			} else {
				// 0x0008 Alive Check Response.
				sa := ac.SourceAddress
				if sa == 0 {
					sa = testerAddr
				}
				payload := u16BE(sa)
				emitDoIP(flowID, dirUp, PTAliveCheckResponse, payload, spec.SrcPort, DefaultTCPPort, "tcp")
			}
		}

		// --- Phase 7: Generic NACK (TCP) ---
		if cfg.GenericNack != nil {
			flowID := fmt.Sprintf("%s-%s-%d-%d:nack", srcIP, dstIP, spec.SrcPort, DefaultTCPPort)
			payload := []byte{cfg.GenericNack.NackCode}
			emitDoIP(flowID, dirDown, PTGenericNack, payload, DefaultTCPPort, spec.SrcPort, "tcp")
		}

		// --- TCP teardown (section 6.15: FIN/FIN-ACK/ACK, 3 packets) ---
		// Emitted when routing activation succeeded and Termination is not
		// explicitly disabled (spec.TCP == nil means the flow-level default
		// applies: teardown on).
		if cfg.Activation != nil && activationSuccess &&
			(spec.TCP == nil || spec.TCP.Termination) {
			flowID := fmt.Sprintf("%s-%s-%d-%d:tcp:act", srcIP, dstIP, spec.SrcPort, DefaultTCPPort)
			// FIN from Tester.
			emitTCP(ctx, flowID, "up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, DefaultTCPPort,
				tcpClientSeq, tcpServerSeq, 0x11, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
			tcpClientSeq++
			// FIN-ACK from ECU.
			emitTCP(ctx, flowID, "down", dstMAC, srcMAC, dstIP, srcIP, DefaultTCPPort, spec.SrcPort,
				tcpServerSeq, tcpClientSeq, 0x11, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
			tcpServerSeq++
			// ACK from Tester.
			emitTCP(ctx, flowID, "up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, DefaultTCPPort,
				tcpClientSeq, tcpServerSeq, 0x10, nil, effectiveTTL, nextIPID(), spec, configChan, &packetIndex, now, mss)
		}
	}()

	return configChan, nil
}

// emitTCP emits a TCP packet.
func emitTCP(ctx context.Context, flowID, direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16,
	seq, ack uint32, flags uint8, payload []byte, ttl uint8, ipID uint16, spec core.FlowSpec,
	configChan chan<- core.PacketConfig, packetIndex *uint64, now time.Time, mss uint16) {

	synOpts := synOptions(mss)
	l3 := core.L3Base(srcIP, dstIP, 6, ttl, ipID, spec)
	l4 := core.L4Config{
		Protocol:   "tcp",
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seq,
		Ack:        ack,
		Flags:      flags,
		WindowSize: 65535,
	}
	if flags == 0x02 || flags == 0x12 {
		l4.TCPOptions = synOpts
	}
	cfg := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: *packetIndex,
		Direction:   direction,
		Timestamp:   time.Now(),
		L2: core.L2Config{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			EtherType: core.EtherTypeFor(srcIP),
		},
		L3:       l3,
		L4:       l4,
		Payload:  payload,
		Metadata: groupIDMeta(spec),
	}
	select {
	case <-ctx.Done():
		return
	case configChan <- cfg:
	}
	*packetIndex++
}

// groupIDMeta returns the group_id metadata when the spec has a GroupID
// strategy (keeps all DOIP sub-flows — UDP discovery/entity/power, TCP
// activation/diag/alive — on the same PacketWorker, preserving wire-order
// timing across phases, section 5.4). Mirrors the SOCKS5/RTSP convention.
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	return nil
}

// synOptions builds TCP SYN options with MSS.
func synOptions(mss uint16) []core.TCPOption {
	return []core.TCPOption{
		{Kind: 2, Data: []byte{byte(mss >> 8), byte(mss)}}, // MSS
		{Kind: 1},                  // NOP
		{Kind: 3, Data: []byte{7}}, // Window Scale
		{Kind: 1},                  // NOP
		{Kind: 1},                  // NOP
		{Kind: 4},                  // SACK permitted
	}
}

// buildVehicleAnnouncement builds 0x0004 payload.
func buildVehicleAnnouncement(vin string, logicalAddr uint16, eid, gid string, far, syncStatus, pv uint8) []byte {
	vinBytes := []byte(vin)
	if len(vinBytes) < VINLength {
		vinBytes = append(vinBytes, make([]byte, VINLength-len(vinBytes))...)
	}

	eidBytes := parseMAC(eid)
	if eidBytes == nil {
		eidBytes = make([]byte, EIDLength)
	}

	gidBytes := parseMAC(gid)
	if gidBytes == nil {
		gidBytes = make([]byte, GIDLength)
	}

	payload := make([]byte, 0, 33)
	payload = append(payload, vinBytes...)
	payload = append(payload, u16BE(logicalAddr)...)
	payload = append(payload, eidBytes...)
	payload = append(payload, gidBytes...)
	payload = append(payload, far)
	if pv != ProtocolVersionV1 {
		payload = append(payload, syncStatus)
	}
	return payload
}

// buildEntityStatusResponse builds 0x4002 payload.
func buildEntityStatusResponse(es *core.DoIPEntityStatus) []byte {
	payload := make([]byte, 7)
	payload[0] = es.NodeType
	payload[1] = es.MaxOpenSockets
	payload[2] = es.CurOpenSockets
	copy(payload[3:7], u32BE(es.MaxDataSize))
	return payload
}

// buildRoutingActivationRequest builds 0x0005 payload.
func buildRoutingActivationRequest(testerAddr uint16, actType uint8, oem []byte) []byte {
	payload := make([]byte, 0, 7+len(oem))
	payload = append(payload, u16BE(testerAddr)...)
	payload = append(payload, actType)
	payload = append(payload, u32BE(0)...) // Reserved ISO
	if len(oem) > 0 {
		payload = append(payload, oem...)
	}
	return payload
}

// buildRoutingActivationResponse builds 0x0006 payload.
func buildRoutingActivationResponse(testerAddr, logicalAddr uint16, respCode uint8, oem []byte) []byte {
	payload := make([]byte, 0, 9+len(oem))
	payload = append(payload, u16BE(testerAddr)...)
	payload = append(payload, u16BE(logicalAddr)...)
	payload = append(payload, respCode)
	payload = append(payload, u32BE(0)...) // Reserved ISO
	if len(oem) > 0 {
		payload = append(payload, oem...)
	}
	return payload
}

// buildDiagnosticMessage builds 0x8001 payload.
func buildDiagnosticMessage(sa, ta uint16, userData []byte) []byte {
	payload := make([]byte, 0, 4+len(userData))
	payload = append(payload, u16BE(sa)...)
	payload = append(payload, u16BE(ta)...)
	payload = append(payload, userData...)
	return payload
}

// buildDiagnosticMessageAck builds 0x8002 payload.
func buildDiagnosticMessageAck(sa, ta uint16, prevDiag []byte) []byte {
	payload := make([]byte, 0, 5+len(prevDiag))
	payload = append(payload, u16BE(sa)...)
	payload = append(payload, u16BE(ta)...)
	payload = append(payload, 0x00) // AckCode
	payload = append(payload, prevDiag...)
	return payload
}

// buildDiagnosticMessageNack builds 0x8003 payload.
func buildDiagnosticMessageNack(sa, ta uint16, nackCode uint8, prevDiag []byte) []byte {
	payload := make([]byte, 0, 5+len(prevDiag))
	payload = append(payload, u16BE(sa)...)
	payload = append(payload, u16BE(ta)...)
	payload = append(payload, nackCode)
	payload = append(payload, prevDiag...)
	return payload
}

// serializeUDS serializes a UDS message into bytes.
func serializeUDS(uds *core.DoIPUDS) []byte {
	// Negative response takes priority.
	if uds.NegativeResponseCode != 0 {
		return []byte{0x7F, uds.ServiceID, uds.NegativeResponseCode}
	}

	var b []byte

	if uds.IsResponse {
		// Positive response: SID | 0x40.
		b = append(b, uds.ServiceID|0x40)
	} else {
		b = append(b, uds.ServiceID)
	}

	// Sub-function for services that have it.
	hasSubFunc := false
	if uds.HasSubFunction != nil {
		hasSubFunc = *uds.HasSubFunction
	} else {
		// Auto-detect per section 8.4.
		switch uds.ServiceID {
		case 0x10, 0x11, 0x27, 0x31, 0x3E:
			hasSubFunc = true
		}
	}
	// 深度审计修复: ISO 14229-1 0x10/0x11/0x27/0x31/0x3E 的 SubFunction 列为
	// "Always"(必选字段)。此前 HasSubFunction=false 时直接跳过该字节, 生成
	// 单字节 SID 报文, Wireshark UDS dissector 越界读取 → "[Malformed Packet:
	// UDS]"。设计文档 §8.4 明确 "HasSubFunction=false 时仍输出 (sub-function
	// 是必需字段)" — 实现与文档不一致。hasSubFunc 仅控制 *是否输出*, 对
	// 必选 sub-function 的服务, false 时仍须输出 SubFunction 字节。
	subFuncRequired := false
	switch uds.ServiceID {
	case 0x10, 0x11, 0x27, 0x31, 0x3E:
		subFuncRequired = true
	}
	if hasSubFunc || subFuncRequired {
		b = append(b, uds.SubFunction)
	}

	// Service-specific fields.
	switch uds.ServiceID {
	case 0x22: // ReadDataByIdentifier
		if len(uds.DID) > 0 {
			b = append(b, uds.DID...)
		}
		if uds.IsResponse && len(uds.Data) > 0 {
			b = append(b, uds.Data...)
		}
	case 0x2E: // WriteDataByIdentifier
		if len(uds.DID) > 0 {
			b = append(b, uds.DID...)
		}
		if len(uds.Data) > 0 {
			b = append(b, uds.Data...)
		}
	case 0x27: // SecurityAccess
		if uds.IsResponse {
			// Odd sub-function response: include seed.
			if uds.SubFunction%2 == 1 && len(uds.Seed) > 0 {
				b = append(b, uds.Seed...)
			}
		} else {
			// Even sub-function request: include key.
			if uds.SubFunction%2 == 0 && len(uds.Key) > 0 {
				b = append(b, uds.Key...)
			}
		}
	case 0x31: // RoutineControl
		if len(uds.DID) > 0 {
			b = append(b, uds.DID...)
		}
		if len(uds.Data) > 0 {
			b = append(b, uds.Data...)
		}
	case 0x34: // RequestDownload
		if len(uds.AddressAndLength) > 0 {
			b = append(b, uds.AddressAndLength...)
		}
	case 0x36: // TransferData
		b = append(b, uds.BlockSequenceCounter)
		if len(uds.TransferData) > 0 {
			b = append(b, uds.TransferData...)
		}
	case 0x37: // RequestTransferExit
		// No additional data.
	case 0x3E: // TesterPresent
		// Sub-function already added.
	}

	return b
}
