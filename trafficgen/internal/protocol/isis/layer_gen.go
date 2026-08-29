package isis

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DefaultDstMAC is the IS-IS L2 multicast destination (this is the IS-IS
// "all Level-2 ISs" / "all ISs" MAC used by the cases).
const DefaultDstMAC = "01:80:c2:00:00:15"

type ISISGenerator struct{}

func (g *ISISGenerator) Name() string                     { return "isis" }
func (g *ISISGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits IS-IS PDUs via req.Emit (L2-only [eth, isis] chain). The
// ChainPlanner's isis branch fills L3=L3Config{}, L4.Protocol="isis", and
// forces L2.EtherType = EtherTypeISIS. Here we set the L2 MACs, the LLC header
// (for the iso10589_llc wire profile), Direction, and Payload.
func (g *ISISGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("isis generator: Emit is nil")
	}
	cfg := req.Meta.ISIS
	if cfg == nil {
		return fmt.Errorf("isis generator: ISIS config is nil")
	}
	if err := (Planner{}).Validate(core.FlowSpec{ISIS: cfg}); err != nil {
		return err
	}

	srcMAC := req.Meta.SrcMAC
	dstMAC := DefaultDstMAC
	profile := cfg.WireProfile
	if profile == "" {
		profile = "iso10589_llc"
	}

	emit := func(pdu []byte) error {
		pkt := core.PacketConfig{
			FlowID:    "isis",
			Direction: "up",
			L2: core.L2Config{
				SrcMAC: srcMAC,
				DstMAC: dstMAC,
			},
			L3: core.L3Config{},
			L4: core.L4Config{Protocol: "isis"},
		}
		// Two wire profiles, both carrying the ISO 10589 LLC header (DSAP/
		// SSAP/Control = fe fe 03):
		//   - iso10589_llc: IEEE 802.3 framing — bytes 12-13 = Length field,
		//     LLC(DAP 14/15/16) + PDU. Set pkt.L2.LLC so writeL2's LLC branch
		//     emits the 802.3 Length + LLC header; the PDU is the Payload.
		//   - iso10589_ethertype: Ethernet II framing — bytes 12-13 = EtherType
		//     0x8870, then LLC(3) + PDU. Set pkt.L2.EtherType=0x8870 (LLC is
		//     left nil so writeL2's 802.3 branch is skipped) and prepend the
		//     LLC header to the Payload. Without the LLC header tshark's eth
		//     dispatcher (0x8870 -> isis) decodes the PDU as LLC bytes and the
		//     IS-IS fields come back empty.
		var llc core.LLCConfig = *defaultLLC()
		if cfg.LLC != nil {
			llc = core.LLCConfig{
				DSAP:    uint8(cfg.LLC.DSAP),
				SSAP:    uint8(cfg.LLC.SSAP),
				Control: uint8(cfg.LLC.Control),
			}
		}
		if profile == "iso10589_ethertype" {
			pkt.L2.EtherType = core.EtherTypeISIS
			pdu = append([]byte{byte(llc.DSAP), byte(llc.SSAP), byte(llc.Control)}, pdu...)
			pkt.Payload = pdu
		} else {
			pkt.L2.LLC = &llc
			pkt.Payload = padPayload(pdu)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.Emit(pkt)
		}
	}

	// Event sequence (multi-PDU).
	if len(cfg.Events) > 0 {
		for i, ev := range cfg.Events {
			pdu, err := buildEventPDU(&ev)
			if err != nil {
				return fmt.Errorf("isis: events[%d] %v", i, err)
			}
			if err := emit(pdu); err != nil {
				return err
			}
		}
		return nil
	}

	// Single PDU.
	pdu, err := buildSinglePDU(cfg)
	if err != nil {
		return err
	}
	return emit(pdu)
}

// buildSinglePDU builds one PDU from a top-level ISISConfig.
func buildSinglePDU(cfg *core.ISISConfig) ([]byte, error) {
	level := cfg.Level
	if level == "" {
		level = "l1"
	}
	pduType := cfg.PDUType
	if pduType == "" {
		pduType = "lan_hello"
	}
	switch pduType {
	case "lan_hello":
		return buildIIH(level, cfg.SystemID, cfg.HoldingTimer, cfg.Priority, cfg.LANID, cfg.TLVs)
	case "lsp":
		return buildLSP(level, cfg.LSPID, cfg.RemainingLifetime, cfg.Sequence,
			cfg.Partition, cfg.CircuitType, cfg.TLVs, cfg.ChecksumMode)
	case "csnp":
		return buildCSNP(level, cfg.SystemID, cfg.StartLSPID, cfg.EndLSPID, cfg.TLVs)
	case "psnp":
		return buildPSNP(level, cfg.SystemID, cfg.TLVs)
	}
	return nil, fmt.Errorf("isis: unsupported pdu_type %q", pduType)
}

// buildEventPDU builds one PDU from an ISISEvent.
func buildEventPDU(ev *core.ISISEvent) ([]byte, error) {
	level := ev.Level
	if level == "" {
		level = "l1"
	}
	kind := ev.Kind
	if kind == "" {
		kind = ev.PDUType
	}
	switch kind {
	case "iih", "lan_hello":
		return buildIIH(level, ev.SystemID, ev.HoldingTimer, ev.Priority, ev.LANID, ev.TLVs)
	case "lsp":
		return buildLSP(level, ev.LSPID, ev.RemainingLifetime, ev.Sequence,
			ev.Partition, ev.CircuitType, ev.TLVs, ev.ChecksumMode)
	case "csnp":
		return buildCSNP(level, ev.SystemID, ev.PDUType, "", ev.TLVs)
	case "psnp":
		return buildPSNP(level, ev.SystemID, ev.TLVs)
	}
	return nil, fmt.Errorf("isis: unsupported event kind %q", kind)
}

// defaultLLC returns the ISO 10589 LLC header (DSAP/SSAP/Control = fe fe 03).
func defaultLLC() *core.LLCConfig {
	return &core.LLCConfig{DSAP: llcDSAP, SSAP: llcSSAP, Control: llcControl}
}

// padPayload pads the PDU to the IEEE 802.3 minimum LLC data field: the 802.3
// Length field must be max(46, LLC(3) + PDU), so the emitted payload is the
// PDU followed by zero padding to that size. The core builder writes
// len(payload) into the Length field.
func padPayload(pdu []byte) []byte {
	n := 3 + len(pdu)
	if n < minLLCPayload {
		n = minLLCPayload
	}
	if len(pdu) >= n {
		return pdu
	}
	out := make([]byte, n)
	copy(out, pdu)
	return out
}

func init() {
	layers.RegisterLayerGenerator("isis", func() (layers.LayerGenerator, error) { return &ISISGenerator{}, nil })
	layers.RegisterLayerValidator("isis", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
