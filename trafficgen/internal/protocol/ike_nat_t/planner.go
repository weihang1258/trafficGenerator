// Package ike_nat_t implements the IKE-NAT-T (IKEv2 with NAT Traversal,
// IKEv2 NAT 穿透扩展) protocol planner (RFC 3947/3948/7296).
//
// IKE-NAT-T extends IKEv2 (互联网密钥交换协议第 2 版, Internet Key Exchange
// Protocol Version 2) with NAT Traversal (NAT 穿透, Network Address
// Translation Traversal) features:
// - Non-ESP Marker (4 字节 0x00000000 前缀)
// - NAT-D Payload (类型 40/41, NAT 检测)
// - NAT-OA Payload (类型 42/43, NAT 前原始地址)
// - UDP-ESP 封装 (端口 4500 上 ESP 报文)
// - NAT-Keepalive (1 字节 0xFF, 周期发送)
//
// Transport runs over UDP port 4500 (floated from IKE port 500). Each IKE
// message on port 4500 is prefixed by a 4-byte Non-ESP Marker (0x00000000)
// to distinguish it from ESP-in-UDP frames.
//
// The planner synthesizes wire-format-compliant IKE-NAT-T messages: 4-byte
// Non-ESP Marker + 28-byte IKE Header (IKE 头, SPIi/SPIr/Next Payload/
// Version/Exchange Type/Flags/Message ID/Length) + payload chain. It
// performs NO real cryptography — payloads are filled with deterministic
// pseudo-bytes or user-provided opaque data.
//
// Design reference: /tmp/l7_planner_design/design_ike_nat_t.md
// Test reference: /tmp/l7_planner_design/testcases_ike_nat_t.md
package ike_nat_t

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Constants per RFC 7296 §3.1 (IKE Header field values) and
// RFC 3947/3948 (NAT-T specific).
const (
	// IKEHeaderLen is the fixed IKE Header size (28 bytes).
	IKEHeaderLen = 28

	// NonESPMarkerLen is the Non-ESP Marker size (4 bytes).
	NonESPMarkerLen = 4

	// IKEHeaderAtPort4500 is the total UDP payload overhead for IKE on port 4500:
	// Non-ESP Marker (4) + IKE Header (28) = 32 bytes.
	IKEHeaderAtPort4500 = NonESPMarkerLen + IKEHeaderLen

	// NATTPort is the IKE-NAT-T UDP port (4500, floated from 500).
	NATTPort uint16 = 4500

	// IKEPort is the standard IKE UDP port (500).
	IKEPort uint16 = 500

	// DefaultKeepaliveInterval is the default NAT-keepalive interval (seconds).
	DefaultKeepaliveInterval = 20

	// DefaultRetransmitTimeout is the default IKE_SA_INIT retransmit timeout (ms).
	DefaultRetransmitTimeout = 500

	// DefaultMaxRetransmits is the default maximum retransmit count.
	DefaultMaxRetransmits = 5

	// DefaultRetransmitBackoff is the default exponential backoff factor.
	DefaultRetransmitBackoff = 2.0

	// ESPHeaderMinLen is the minimum ESP header length: SPI(4) + Seq(4) = 8.
	ESPHeaderMinLen = 8

	// DefaultIVLength is the default IV length for ESP (AES-CBC).
	DefaultIVLength = 16

	// DefaultICVLength is the default ICV length for ESP (HMAC-SHA1).
	DefaultICVLength = 12

	// DefaultESPDataSize is the default ESP encrypted payload size (bytes).
	DefaultESPDataSize = 100

	// Exchange type wire values (RFC 7296 §3.1).
	ExchangeIKE_SA_INIT uint8 = 34
	ExchangeIKE_AUTH uint8 = 35
	ExchangeCREATE_CHILD_SA uint8 = 36
	ExchangeINFORMATIONAL uint8 = 37

	// Flags.
	FlagInitiator uint8 = 0x08 // bit0 (I flag)
	FlagResponse uint8 = 0x20 // bit5 (R flag)

	// IKE version (IKEv2).
	IKEv2Version uint8 = 0x20

	// Payload type wire values (RFC 7296 §3.2).
	PayloadSA uint8 = 33
	PayloadKE uint8 = 34
	PayloadIDi uint8 = 35
	PayloadIDr uint8 = 36
	PayloadCERT uint8 = 37
	PayloadCERTREQ uint8 = 38
	PayloadAUTH uint8 = 39
	PayloadNONCE uint8 = 40
	PayloadNOTIFY uint8 = 41
	PayloadDELETE uint8 = 42
	PayloadVENDOR uint8 = 43
	PayloadTSi uint8 = 44
	PayloadTSr uint8 = 45
	PayloadSK uint8 = 46
	PayloadCP uint8 = 47
	PayloadEAP uint8 = 48
	PayloadSKF uint8 = 53

	// NAT-D Notify Message Types (RFC 7296 §2.23).
	NotifyNATDetectionSourceIP uint16 = 16388
	NotifyNATDetectionDestIP uint16 = 16389

	// NAT-D Payload types (deprecated, use Notify with types above).
	PayloadNAT_D uint8 = 20 // type 20 in IKEv1, but IKEv2 uses Notify (41)
	PayloadNAT_OA uint8 = 21 // type 21 in IKEv1, but IKEv2 uses Notify (41)

	// Protocol ID values.
	ProtocolIKE uint8 = 1
	ProtocolESP uint8 = 3
)

// NAT-D Hash constants.
const (
	// NATDHashLen is the SHA-1 hash length for NAT-D (20 bytes).
	NATDHashLen = 20
)

// Planner is the IKE-NAT-T protocol planner.
type Planner struct{}

// NewPlanner returns a new IKE-NAT-T planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "ike_nat_t" }

// Validate validates an IKE-NAT-T FlowSpec. Read-only: never modifies spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("ike_nat_t: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("ike_nat_t: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	if spec.IKENATT == nil {
		return fmt.Errorf("ike_nat_t: IKENATT config is required")
	}
	cfg := spec.IKENATT

	// Validate Retransmit config (if set).
	if cfg.Retransmit != nil {
		if cfg.Retransmit.MaxRetransmits < 0 {
			return fmt.Errorf("ike_nat_t: Retransmit.MaxRetransmits %d cannot be negative", cfg.Retransmit.MaxRetransmits)
		}
		if cfg.Retransmit.Backoff > 0 && cfg.Retransmit.Backoff < 1.0 {
			return fmt.Errorf("ike_nat_t: Retransmit.Backoff %f must be >= 1.0", cfg.Retransmit.Backoff)
		}
	}

	// Validate Dialog (if set).
	for i := range cfg.Dialog {
		msg := &cfg.Dialog[i]
		if msg.Direction != "up" && msg.Direction != "down" {
			return fmt.Errorf("ike_nat_t: Dialog[%d].Direction %q invalid (must be 'up' or 'down')", i, msg.Direction)
		}
		if msg.ExchangeType != ExchangeIKE_SA_INIT &&
			msg.ExchangeType != ExchangeIKE_AUTH &&
			msg.ExchangeType != ExchangeCREATE_CHILD_SA &&
			msg.ExchangeType != ExchangeINFORMATIONAL {
			return fmt.Errorf("ike_nat_t: Dialog[%d].ExchangeType %d unknown", i, msg.ExchangeType)
		}
		// Validate payloads.
		for j := range msg.Payloads {
			pl := &msg.Payloads[j]
			switch pl.Type {
			case PayloadSA:
				if pl.SA == nil {
					return fmt.Errorf("ike_nat_t: Dialog[%d].Payloads[%d] Type=SA but SA field is nil", i, j)
				}
			case PayloadKE:
				if pl.KE == nil {
					return fmt.Errorf("ike_nat_t: Dialog[%d].Payloads[%d] Type=KE but KE field is nil", i, j)
				}
			case PayloadNONCE:
				if len(pl.Nonce) < 16 || len(pl.Nonce) > 256 {
					return fmt.Errorf("ike_nat_t: Dialog[%d].Payloads[%d] Nonce length %d out of range [16,256]", i, j, len(pl.Nonce))
				}
			case PayloadNOTIFY:
				if pl.Notify == nil {
					return fmt.Errorf("ike_nat_t: Dialog[%d].Payloads[%d] Type=Notify but Notify field is nil", i, j)
				}
				// NAT-D Notification Data must be 20 bytes.
				if (pl.Notify.NotifyMsgType == NotifyNATDetectionSourceIP ||
					pl.Notify.NotifyMsgType == NotifyNATDetectionDestIP) &&
					len(pl.Notify.NotificationData) != NATDHashLen {
					return fmt.Errorf("ike_nat_t: Dialog[%d].Payloads[%d] NAT-D NotificationData length %d != %d",
						i, j, len(pl.Notify.NotificationData), NATDHashLen)
				}
			}
		}
	}

	return nil
}

// Plan generates PacketConfigs for an IKE-NAT-T FlowSpec. The flow is read in
// the returned channel; close semantics follow the existing planners.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		p.runPlan(ctx, configChan, spec)
	}()

	return configChan, nil
}

// runPlan executes the plan in a goroutine.
func (p *Planner) runPlan(ctx context.Context, ch chan<- core.PacketConfig, spec core.FlowSpec) {
	cfg := spec.IKENATT
	if cfg == nil {
		return
	}

	// Apply defaults.
	applied := applyDefaults(cfg)

	// Generate the InitiatorSPI ONCE for the whole IKE SA. All messages in
	// one IKE SA share the same SPI pair (RFC 7296 §2.1: "the SPI is
	// created by the initiator and MUST be the same in all subsequent
	// exchanges of that IKE SA"). An earlier version regenerated a random
	// SPI per emitted message, violating SA consistency.
	if applied.InitiatorSPI == 0 {
		applied.InitiatorSPI = generateSPI()
	}

	// Resolve message sequence.
	var msgs []core.IKENATTMessage
	if len(applied.Dialog) > 0 {
		msgs = applied.Dialog
	} else {
		// Default dialog: standard IKE_SA_INIT + IKE_AUTH with NAT-D.
		msgs = buildDefaultDialog(applied, spec)
	}

	flowID := fmt.Sprintf("ikenatt-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	now := time.Now()
	pktIdx := uint64(0)

	// Determine if NAT-T is enabled (port floating + Non-ESP Marker).
	natTEnabled := applied.NATDetectedOnSource || applied.NATDetectedOnDest
	portFloated := natTEnabled && applied.PortFloat

	// Current ports (start at spec values, float if NAT detected).
	usePort4500 := portFloated
	// If DstPort == 4500 already, start with port 4500.
	if spec.DstPort == NATTPort {
		usePort4500 = true
	}

	// Track the learned ResponderSPI from IKE_SA_INIT response.
	learnedResponderSPI := applied.ResponderSPI

	for mi := range msgs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg := &msgs[mi]

		// Determine if this message needs Non-ESP Marker.
		needsMarker := usePort4500

		// Build the IKE message payload bytes.
		payloadBytes := buildIKENATTMessage(msg, applied, learnedResponderSPI, needsMarker)

		// Determine src/dst port based on direction and port float state.
		srcPort := spec.SrcPort
		dstPort := spec.DstPort
		if usePort4500 {
			// Port floated: use 4500.
			if srcPort == IKEPort || srcPort == 0 {
				srcPort = NATTPort
			}
			dstPort = NATTPort
		}

		// Direction-based swap.
		srcIP := spec.SrcIP
		dstIP := spec.DstIP
		srcMAC := spec.SrcMAC
		dstMAC := spec.DstMAC
		if msg.Direction == "down" {
			srcIP, dstIP = dstIP, srcIP
			srcMAC, dstMAC = dstMAC, srcMAC
			srcPort, dstPort = dstPort, srcPort
		}

		// IP ID: deterministic, incrementing.
		ipID := uint16(pktIdx & 0xFFFF)

		ttl := spec.TTL
		if ttl == 0 {
			ttl = 64
		}

		// Extract SPI values for metadata.
		spii := uint64(0)
		spir := uint64(0)
		if len(payloadBytes) >= IKEHeaderLen {
			spii = binary.BigEndian.Uint64(payloadBytes[0:8])
			spir = binary.BigEndian.Uint64(payloadBytes[8:16])
		}

		md := map[string]interface{}{
			"ike_nat_t_exchange_type": int(msg.ExchangeType),
			"ike_nat_t_message_id": int(msg.MessageID),
			"ike_nat_t_spi_i": spii,
			"ike_nat_t_spi_r": spir,
			"ike_nat_t_needs_marker": needsMarker,
		}

		pc := core.PacketConfig{
			FlowID: flowID,
			PacketIndex: pktIdx,
			Direction: msg.Direction,
			Timestamp: now,
			L2: core.L2Config{
				SrcMAC: srcMAC,
				DstMAC: dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3: core.L3Base(srcIP, dstIP, core.ProtocolUDP, ttl, ipID, spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort: srcPort,
				DstPort: dstPort,
			},
			Payload: payloadBytes,
			Metadata: md,
		}

		select {
		case ch <- pc:
			pktIdx++
		case <-ctx.Done():
			return
		}

		// Handle retransmits for IKE_SA_INIT request.
		if msg.ExchangeType == ExchangeIKE_SA_INIT && msg.Direction == "up" {
			pktIdx = p.handleRetransmits(ctx, ch, pc, pktIdx, applied.Retransmit)
			if pktIdx == 0 { // ctx cancelled
				return
			}
		}

		// Learn ResponderSPI from IKE_SA_INIT response.
		if msg.ExchangeType == ExchangeIKE_SA_INIT && msg.Direction == "down" {
			// Skip Non-ESP Marker (4 bytes) if present, then read SPIr at hdr offset 8.
			hdrOff := 0
			if needsMarker {
				hdrOff = NonESPMarkerLen
			}
			if len(payloadBytes) >= hdrOff+16 {
				rspi := binary.BigEndian.Uint64(payloadBytes[hdrOff+8 : hdrOff+16])
				if rspi != 0 {
					learnedResponderSPI = rspi
				}
			}
		}

		// If NAT detected and we have completed IKE_SA_INIT exchange, float port.
		if msg.ExchangeType == ExchangeIKE_SA_INIT && msg.Direction == "down" && natTEnabled && portFloated {
			usePort4500 = true
		}

		// Emit ESP sub-flows and keepalive after IKE_AUTH.
		if msg.ExchangeType == ExchangeIKE_AUTH && msg.Direction == "down" && applied.ChildSA != nil {
			pktIdx = p.emitESPSubFlows(ctx, ch, spec, flowID, msg.Direction, pktIdx, usePort4500, applied)
			if pktIdx == 0 {
				return
			}
			pktIdx = p.emitKeepaliveSubFlows(ctx, ch, spec, flowID, pktIdx, usePort4500, applied)
			if pktIdx == 0 {
				return
			}
		}
	}
}

// handleRetransmits emits retransmit copies of a packet (RFC 7296 §2.2).
// Returns the new packet index, or 0 if ctx was cancelled.
func (p *Planner) handleRetransmits(ctx context.Context, ch chan<- core.PacketConfig, base core.PacketConfig, pktIdx uint64, retransmit *core.RetransmitConfig) uint64 {
	if retransmit == nil {
		return pktIdx
	}
	maxRetransmits := retransmit.MaxRetransmits
	if maxRetransmits == 0 {
		return pktIdx
	}
	timeout := retransmit.Timeout
	if timeout == 0 {
		timeout = DefaultRetransmitTimeout
	}
	backoff := retransmit.Backoff
	if backoff == 0 {
		backoff = DefaultRetransmitBackoff
	}

	currentTimeout := timeout
	for i := 0; i < maxRetransmits; i++ {
		// Simulate retransmit timeout (not actually sleeping — just emit the copy).
		select {
		case <-ctx.Done():
			return 0
		default:
		}
		pc := base
		pc.PacketIndex = pktIdx
		select {
		case ch <- pc:
			pktIdx++
		case <-ctx.Done():
			return 0
		}
		// Exponential backoff for next retransmit timeout.
		currentTimeout = int(float64(currentTimeout) * backoff)
		_ = currentTimeout
	}
	return pktIdx
}

// emitESPSubFlows emits ESP-in-UDP sub-flows after IKE_AUTH.
func (p *Planner) emitESPSubFlows(ctx context.Context, ch chan<- core.PacketConfig, spec core.FlowSpec, flowID, direction string, pktIdx uint64, usePort4500 bool, cfg *core.IKENATTConfig) uint64 {
	childSA := cfg.ChildSA
	if childSA == nil {
		return pktIdx
	}

	spiOut := childSA.SPIout
	if spiOut == 0 {
		spiOut = 0xDEADBEEF
	}
	espCount := childSA.ESPCount
	if espCount <= 0 {
		espCount = 1
	}
	espDataSize := childSA.ESPDataSize
	if espDataSize <= 0 {
		espDataSize = DefaultESPDataSize
	}

	srcPort := spec.SrcPort
	dstPort := spec.DstPort
	if usePort4500 {
		srcPort = NATTPort
		dstPort = NATTPort
	}

	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcMAC := spec.SrcMAC
	dstMAC := spec.DstMAC
	if direction == "down" {
		srcIP, dstIP = dstIP, srcIP
		srcMAC, dstMAC = dstMAC, srcMAC
		srcPort, dstPort = dstPort, srcPort
	}

	ttl := spec.TTL
	if ttl == 0 {
		ttl = 64
	}

	for i := 0; i < espCount; i++ {
		select {
		case <-ctx.Done():
			return 0
		default:
		}

		seqNum := uint32(i + 1)
		iv := make([]byte, DefaultIVLength)
		payload := make([]byte, espDataSize)
		icv := make([]byte, DefaultICVLength)

		// ESP-in-UDP payload: SPI(4) + Seq(4) + IV + EncryptedPayload + ICV.
		espPayload := make([]byte, 8+len(iv)+len(payload)+len(icv))
		binary.BigEndian.PutUint32(espPayload[0:4], spiOut)
		binary.BigEndian.PutUint32(espPayload[4:8], seqNum)
		copy(espPayload[8:8+len(iv)], iv)
		copy(espPayload[8+len(iv):8+len(iv)+len(payload)], payload)
		copy(espPayload[8+len(iv)+len(payload):], icv)

		ipID := uint16(pktIdx & 0xFFFF)

		pc := core.PacketConfig{
			FlowID: flowID,
			PacketIndex: pktIdx,
			Direction: direction,
			Timestamp: time.Now(),
			L2: core.L2Config{
				SrcMAC: srcMAC,
				DstMAC: dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3: core.L3Base(srcIP, dstIP, core.ProtocolUDP, ttl, ipID, spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort: srcPort,
				DstPort: dstPort,
			},
			Payload: espPayload,
			Metadata: map[string]interface{}{"ike_nat_t_subflow": "esp"},
		}

		select {
		case ch <- pc:
			pktIdx++
		case <-ctx.Done():
			return 0
		}
	}
	return pktIdx
}

// emitKeepaliveSubFlows emits NAT-keepalive sub-flows.
func (p *Planner) emitKeepaliveSubFlows(ctx context.Context, ch chan<- core.PacketConfig, spec core.FlowSpec, flowID string, pktIdx uint64, usePort4500 bool, cfg *core.IKENATTConfig) uint64 {
	natDetected := cfg.NATDetectedOnSource || cfg.NATDetectedOnDest
	if !natDetected {
		return pktIdx
	}
	if cfg.Keepalive == nil {
		return pktIdx
	}

	ka := cfg.Keepalive
	count := ka.Count
	if count <= 0 {
		count = 1
	}
	direction := ka.Direction
	if direction == "" {
		direction = "up"
	}

	srcPort := spec.SrcPort
	dstPort := spec.DstPort
	if usePort4500 {
		srcPort = NATTPort
		dstPort = NATTPort
	}

	ttl := spec.TTL
	if ttl == 0 {
		ttl = 64
	}

	// Determine which directions to emit.
	emitUp := direction == "up" || direction == "both"
	emitDown := direction == "down" || direction == "both"

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return 0
		default:
		}

		// Keepalive payload: single byte 0xFF.
		kaPayload := []byte{0xFF}

		// Up direction (initiator -> responder).
		if emitUp {
			ipID := uint16(pktIdx & 0xFFFF)
			pc := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: pktIdx,
				Direction: "up",
				Timestamp: time.Now(),
				L2: core.L2Config{
					SrcMAC: spec.SrcMAC,
					DstMAC: spec.DstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.SrcIP, spec.DstIP, core.ProtocolUDP, ttl, ipID, spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort: srcPort,
					DstPort: dstPort,
				},
				Payload: kaPayload,
				Metadata: map[string]interface{}{"ike_nat_t_subflow": "keepalive"},
			}
			select {
			case ch <- pc:
				pktIdx++
			case <-ctx.Done():
				return 0
			}
		}

		// Down direction (responder -> initiator).
		if emitDown {
			ipID := uint16(pktIdx & 0xFFFF)
			pc := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: pktIdx,
				Direction: "down",
				Timestamp: time.Now(),
				L2: core.L2Config{
					SrcMAC: spec.DstMAC,
					DstMAC: spec.SrcMAC,
					EtherType: core.EtherTypeFor(spec.DstIP),
				},
				L3: core.L3Base(spec.DstIP, spec.SrcIP, core.ProtocolUDP, ttl, ipID, spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort: dstPort,
					DstPort: srcPort,
				},
				Payload: kaPayload,
				Metadata: map[string]interface{}{"ike_nat_t_subflow": "keepalive"},
			}
			select {
			case ch <- pc:
				pktIdx++
			case <-ctx.Done():
				return 0
			}
		}
	}
	return pktIdx
}

// applyDefaults fills in default values for IKENATTConfig.
func applyDefaults(cfg *core.IKENATTConfig) *core.IKENATTConfig {
	applied := *cfg // shallow copy

	// Default NAT-Detection: true.
	// Default PortFloat: true.
	// Default UDPEncapESP: true.

	// Keepalive default interval.
	if applied.Keepalive != nil {
		if applied.Keepalive.Interval == 0 {
			applied.Keepalive.Interval = DefaultKeepaliveInterval
		}
		if applied.Keepalive.Direction == "" {
			applied.Keepalive.Direction = "up"
		}
	}

	// Retransmit defaults.
	if applied.Retransmit != nil {
		if applied.Retransmit.Timeout == 0 {
			applied.Retransmit.Timeout = DefaultRetransmitTimeout
		}
		if applied.Retransmit.MaxRetransmits == 0 {
			applied.Retransmit.MaxRetransmits = DefaultMaxRetransmits
		}
		if applied.Retransmit.Backoff == 0 {
			applied.Retransmit.Backoff = DefaultRetransmitBackoff
		}
	}

	return &applied
}

// buildDefaultDialog returns a standard IKE_SA_INIT + IKE_AUTH dialog with NAT-D.
func buildDefaultDialog(cfg *core.IKENATTConfig, spec core.FlowSpec) []core.IKENATTMessage {
	// Generate SPI values.
	spii := cfg.InitiatorSPI
	if spii == 0 {
		spii = generateSPI()
	}
	spir := cfg.ResponderSPI

	// Compute NAT-D hash values.
	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcPort := spec.SrcPort
	dstPort := spec.DstPort
	if srcPort == 0 {
		srcPort = IKEPort
	}
	if dstPort == 0 {
		dstPort = IKEPort
	}

	// Compute NAT-D hashes (SHA-1).
	var natDHashSrc, natDHashDst []byte
	if cfg.NATDetection {
		natDHashSrc = computeNATDHash(spii, 0, net.ParseIP(srcIP), srcPort)
		natDHashDst = computeNATDHash(spii, 0, net.ParseIP(dstIP), dstPort)
	}

	// IKE_SA_INIT request (up): SA + KE + Nonce + NAT-D × 2.
	initReqPayloads := []core.IKENATTPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
			{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
				{Type: 1, ID: 12, KeyLengthBits: 128}, // ENCR_AES_CBC
				{Type: 2, ID: 5}, // PRF_HMAC_SHA2_256
				{Type: 3, ID: 12}, // INTEG_HMAC_SHA2_256_128
				{Type: 4, ID: 14}, // DH_2048_MODP
			}},
		}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14, KeyData: make([]byte, 256)}},
		{Type: PayloadNONCE, Nonce: make([]byte, 32)},
	}
	if cfg.NATDetection {
		initReqPayloads = append(initReqPayloads,
			core.IKENATTPayload{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
				ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
				NotificationData: natDHashSrc,
			}},
			core.IKENATTPayload{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
				ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionDestIP,
				NotificationData: natDHashDst,
			}},
		)
	}

	initReq := core.IKENATTMessage{
		Direction: "up",
		ExchangeType: ExchangeIKE_SA_INIT,
		MessageID: 0,
		Payloads: initReqPayloads,
	}

	// IKE_SA_INIT response (down): SA + KE + Nonce + NAT-D × 2.
	initRespPayloads := []core.IKENATTPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
			{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
				{Type: 1, ID: 12, KeyLengthBits: 128},
				{Type: 2, ID: 5},
				{Type: 3, ID: 12},
				{Type: 4, ID: 14},
			}},
		}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14, KeyData: make([]byte, 256)}},
		{Type: PayloadNONCE, Nonce: make([]byte, 32)},
	}
	if cfg.NATDetection {
		// Per RFC 7383 / RFC 4306, NAT-D Notify payloads are present in
		// BOTH the IKE_SA_INIT request AND response, regardless of whether
		// the ResponderSPI is known yet. In the response, the responder
		// uses its own freshly-allocated SPIr (which it echoes in the IKE
		// header). An earlier version gated this on `spir != 0`, which
		// suppressed NAT-D in the response whenever the caller left
		// ResponderSPI at 0 -- the common "let the planner pick one" path.
		natDHashSrcResp := computeNATDHash(spii, spir, net.ParseIP(dstIP), dstPort)
		natDHashDstResp := computeNATDHash(spii, spir, net.ParseIP(srcIP), srcPort)
		initRespPayloads = append(initRespPayloads,
			core.IKENATTPayload{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
				ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
				NotificationData: natDHashSrcResp,
			}},
			core.IKENATTPayload{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
				ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionDestIP,
				NotificationData: natDHashDstResp,
			}},
		)
	}

	initResp := core.IKENATTMessage{
		Direction: "down",
		ExchangeType: ExchangeIKE_SA_INIT,
		MessageID: 0,
		Payloads: initRespPayloads,
	}

	// IKE_AUTH request (up): IDi + AUTH + SA + TSi + TSr.
	authReq := core.IKENATTMessage{
		Direction: "up",
		ExchangeType: ExchangeIKE_AUTH,
		MessageID: 1,
		Payloads: []core.IKENATTPayload{
			{Type: PayloadIDi, Raw: []byte{0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01}},
			{Type: PayloadAUTH, Raw: make([]byte, 32)},
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
				{Number: 1, ProtocolID: ProtocolESP, Transforms: []core.IKETransform{
					{Type: 1, ID: 12, KeyLengthBits: 128},
					{Type: 3, ID: 12},
				}},
			}}},
		},
	}

	// IKE_AUTH response (down): IDr + AUTH + SA + TSi + TSr.
	authResp := core.IKENATTMessage{
		Direction: "down",
		ExchangeType: ExchangeIKE_AUTH,
		MessageID: 1,
		Payloads: []core.IKENATTPayload{
			{Type: PayloadIDr, Raw: []byte{0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x02}},
			{Type: PayloadAUTH, Raw: make([]byte, 32)},
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
				{Number: 1, ProtocolID: ProtocolESP, Transforms: []core.IKETransform{
					{Type: 1, ID: 12, KeyLengthBits: 128},
					{Type: 3, ID: 12},
				}},
			}}},
		},
	}

	return []core.IKENATTMessage{initReq, initResp, authReq, authResp}
}

// generateSPI returns a non-zero random 64-bit SPI value.
func generateSPI() uint64 {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	v := uint64(rng.Uint64())
	if v == 0 {
		v = 0xDEADBEEFCAFEBABE
	}
	return v
}

// computeNATDHash computes the SHA-1 hash for NAT-D payload (RFC 3947 §3).
// Input: InitiatorSPI(8) + ResponderSPI(8) + IP(4 or 16) + Port(2) -> SHA-1.
func computeNATDHash(initiatorSPI, responderSPI uint64, ipAddr net.IP, port uint16) []byte {
	if ipAddr == nil {
		ipAddr = net.ParseIP("0.0.0.0")
	}
	buf := make([]byte, 0, 8+8+16+2)
	buf = binary.BigEndian.AppendUint64(buf, initiatorSPI)
	buf = binary.BigEndian.AppendUint64(buf, responderSPI)
	if ip4 := ipAddr.To4(); ip4 != nil {
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, ipAddr...)
	}
	buf = binary.BigEndian.AppendUint16(buf, port)
	h := sha1.Sum(buf)
	return h[:]
}

// buildIKENATTMessage serializes an IKE-NAT-T message into its wire bytes.
// If needsMarker is true, prepends the 4-byte Non-ESP Marker (0x00000000).
func buildIKENATTMessage(msg *core.IKENATTMessage, cfg *core.IKENATTConfig, learnedSPIr uint64, needsMarker bool) []byte {
	// Build the payload chain.
	payloadBytes, nextPayload := encodeNATTPayloads(msg.Payloads)

	// Build the IKE Header.
	hdr := make([]byte, IKEHeaderLen)
	spii := cfg.InitiatorSPI
	if spii == 0 {
		spii = generateSPI()
	}
	spir := learnedSPIr
	if spir == 0 {
		spir = cfg.ResponderSPI
	}
	// For IKE_SA_INIT request, ResponderSPI must be 0.
	if msg.ExchangeType == ExchangeIKE_SA_INIT && msg.Direction == "up" {
		spir = 0
	}

	binary.BigEndian.PutUint64(hdr[0:8], spii)
	binary.BigEndian.PutUint64(hdr[8:16], spir)
	hdr[16] = nextPayload
	hdr[17] = IKEv2Version
	hdr[18] = msg.ExchangeType

	// Compute flags.
	var flags uint8
	if msg.Direction == "up" {
		flags |= FlagInitiator
	} else {
		flags |= FlagResponse
	}
	hdr[19] = flags

	binary.BigEndian.PutUint32(hdr[20:24], msg.MessageID)
	totalLen := uint32(IKEHeaderLen + len(payloadBytes))
	binary.BigEndian.PutUint32(hdr[24:28], totalLen)

	// Assemble the full payload.
	var full []byte
	if needsMarker {
		// Non-ESP Marker: 4 bytes of 0x00000000.
		marker := make([]byte, NonESPMarkerLen)
		full = append(full, marker...)
	}
	full = append(full, hdr...)
	full = append(full, payloadBytes...)

	return full
}

// encodeNATTPayloads serializes the payload chain for an IKE-NAT-T message.
// Returns (serialized bytes, next_payload for the IKE Header).
func encodeNATTPayloads(payloads []core.IKENATTPayload) ([]byte, uint8) {
	if len(payloads) == 0 {
		return nil, 0
	}

	var out []byte
	firstType := payloads[0].Type

	for i := range payloads {
		p := &payloads[i]
		isLast := i == len(payloads)-1

		nextType := uint8(0)
		if !isLast {
			nextType = payloads[i+1].Type
		}

		body := encodeNATTPayloadBody(p)
		payloadLen := uint16(4 + len(body))

		// Generic Payload Header: Next Payload(1) + Critical(1) + Length(2).
		hdr := make([]byte, 4)
		hdr[0] = nextType
		binary.BigEndian.PutUint16(hdr[2:4], payloadLen)

		out = append(out, hdr...)
		out = append(out, body...)
	}

	return out, firstType
}

// encodeNATTPayloadBody encodes a single payload body (without Generic Header).
func encodeNATTPayloadBody(p *core.IKENATTPayload) []byte {
	if len(p.Raw) > 0 {
		return p.Raw
	}

	switch p.Type {
	case PayloadSA:
		if p.SA != nil {
			return encodeSA(p.SA)
		}
	case PayloadKE:
		if p.KE != nil {
			return encodeKE(p.KE)
		}
	case PayloadNONCE:
		return p.Nonce
	case PayloadNOTIFY:
		if p.Notify != nil {
			return encodeNotifyForNATT(p.Notify)
		}
	}
	return nil
}

// encodeSA encodes an SA payload body (Proposal Substructures).
func encodeSA(sa *core.IKESA) []byte {
	if sa == nil || len(sa.Proposals) == 0 {
		return nil
	}
	var out []byte
	for i, prop := range sa.Proposals {
		isLast := i == len(sa.Proposals)-1
		lastByte := uint8(0)
		if !isLast {
			lastByte = 2 // More Proposals
		}
		out = append(out, encodeProposal(&prop, lastByte)...)
	}
	return out
}

// encodeProposal encodes a single Proposal Substructure.
func encodeProposal(p *core.IKEProposal, lastByte uint8) []byte {
	transformsBytes := encodeTransforms(p.Transforms)
	spiLen := len(p.SPI)
	propLen := 8 + spiLen + len(transformsBytes)
	body := make([]byte, propLen)
	body[0] = lastByte
	body[1] = 0 // reserved
	binary.BigEndian.PutUint16(body[2:4], uint16(propLen))
	body[4] = p.Number
	body[5] = p.ProtocolID
	body[6] = uint8(spiLen)
	body[7] = uint8(len(p.Transforms))
	copy(body[8:8+spiLen], p.SPI)
	copy(body[8+spiLen:], transformsBytes)
	return body
}

// encodeTransforms encodes a list of Transform Substructures.
func encodeTransforms(transforms []core.IKETransform) []byte {
	if len(transforms) == 0 {
		return nil
	}
	var out []byte
	for i, t := range transforms {
		isLast := i == len(transforms)-1
		lastByte := uint8(0)
		if !isLast {
			lastByte = 3 // More Transforms
		}
		attrs := t.RawAttributes
		if len(attrs) == 0 && t.KeyLengthBits > 0 {
			// Encode Key Length as a TV (short-form) Transform Attribute
			// (RFC 7296 §3.3.5). The Key Length attribute (type 14) is fixed
			// length and MUST use the Type/Value form with AF=1. Wire layout:
			//   AF(1 bit)=1 | Attribute Type(15 bits)=14 | Attribute Value(2 bytes)
			// For AES-128 this is 0x80 0x0E 0x00 0x80. Setting AF=0 (TLV form)
			// would make the following 2 bytes (0x00 0x80) be parsed as a
			// 128-byte Attribute Length, causing Wireshark to swallow the next
			// transforms as attribute value - exactly the malformed-packet
			// symptom reported on IKE_SA_INIT.
			attrs = []byte{0x80 | byte((14>>8)&0x7F), byte(14 & 0xFF), byte(t.KeyLengthBits >> 8), byte(t.KeyLengthBits & 0xFF)}
		}
		tLen := 8 + len(attrs)
		body := make([]byte, tLen)
		body[0] = lastByte
		body[1] = 0
		binary.BigEndian.PutUint16(body[2:4], uint16(tLen))
		body[4] = t.Type
		body[5] = 0
		binary.BigEndian.PutUint16(body[6:8], t.ID)
		copy(body[8:], attrs)
		out = append(out, body...)
	}
	return out
}

// encodeKE encodes a KE payload body: DH Group(2) + Reserved(2) + Key Data(N).
func encodeKE(ke *core.IKEKE) []byte {
	keyData := ke.KeyData
	if len(keyData) == 0 {
		keyData = make([]byte, 256) // Default 2048-bit MODP
	}
	body := make([]byte, 4+len(keyData))
	binary.BigEndian.PutUint16(body[0:2], ke.DHGroup)
	binary.BigEndian.PutUint16(body[2:4], 0) // reserved
	copy(body[4:], keyData)
	return body
}

// encodeNotifyForNATT encodes a NOTIFY payload body for NAT-T.
// Layout: Protocol ID(1) + SPI Size(1) + Notify Message Type(2) + Notification Data(N).
func encodeNotifyForNATT(n *core.NotifyPayload) []byte {
	body := make([]byte, 4+len(n.NotificationData))
	body[0] = n.ProtocolID
	body[1] = n.SPISize
	binary.BigEndian.PutUint16(body[2:4], n.NotifyMsgType)
	copy(body[4:], n.NotificationData)
	return body
}