package replay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
	"go.uber.org/zap"
)

// ReplayPlanner reads a pcap asset and produces a stream of PacketConfigs that
// carry the raw bytes + byte-patches for the rewriter (§16.12). It implements
// the replay planning flow: load flows + packets, precompute flow-level patches,
// iterate packets in file order, read raw bytes, assemble patches, emit.
type ReplayPlanner struct {
	db *storage.DB
}

// NewReplayPlanner creates a planner backed by the given DB.
func NewReplayPlanner(db *storage.DB) *ReplayPlanner {
	return &ReplayPlanner{db: db}
}

// flowCtx holds per-flow precomputed state for the planner.
type flowCtx struct {
	flow          storage.FlowModel
	layout        pcapparser.OffsetLayout
	flowPatches   []Patch // flow-level patches (mapping/field set)
	endpointRules []endpointRule
	offsetRules   []offsetRule   // field rules with apply:offset (per-packet, need original value)
	macmapRules   []RewriteRule  // macmap rules (per-packet, read MAC from raw)
}

// endpointRule is a matched endpoint rule with its resolved value.
type endpointRule struct {
	target string // client_ip | server_ip | client_port | server_port
	value  string // resolved value (IP string)
}

// offsetRule is a field rule with apply:offset (§6): the delta is added to the
// per-packet original value (new = orig + delta), preserving in-flow deltas.
// Applied per-packet because the original value varies per packet (seq/ack/ip_id).
type offsetRule struct {
	target string
	delta  uint32 // for seq/ack/ip_id (uint32/uint16); width from fieldSpec
}

// PlanReplay implements core.ReplayPlanner (the interface core dispatches to).
// It unmarshals the raw spec JSON and delegates to Plan. userID scopes all
// asset/flow/packet reads to the owning user (defense-in-depth isolation).
func (p *ReplayPlanner) PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string) (<-chan core.PacketConfig, error) {
	var spec ReplaySpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal replay spec: %w", err)
	}
	return p.Plan(ctx, spec, taskID, classID, userID)
}

// Plan produces a channel of PacketConfigs for the replay (§4). It runs in a
// goroutine and closes the channel when done (or on context cancel). The caller
// (ConfigWorker) drains the channel into the engine pipeline. userID scopes
// asset/flow/packet reads to the owning user.
func (p *ReplayPlanner) Plan(ctx context.Context, spec ReplaySpec, taskID, classID, userID string) (<-chan core.PacketConfig, error) {
	repo := storage.NewPcapRepository(p.db)

	// 1. Load + validate the asset (user-scoped).
	asset, err := repo.GetAsset(spec.PcapAssetID, userID)
	if err != nil {
		return nil, fmt.Errorf("pcap asset %s: %w", spec.PcapAssetID, err)
	}
	if asset.Status != "ready" {
		return nil, fmt.Errorf("pcap asset %s not ready (status %s)", spec.PcapAssetID, asset.Status)
	}

	// 2. Load flows + precompute per-flow patches (user-scoped).
	flows, _, err := repo.ListFlowsByAsset(asset.ID, userID, 1, 100000)
	if err != nil {
		return nil, fmt.Errorf("load flows: %w", err)
	}
	// Warn on uncertain direction classification (§8/§14): dual-port routing
	// and endpoint rewriting rely on direction; an uncertain flow is replayed
	// by best-guess direction. Surface this so the user can verify.
	for _, f := range flows {
		if f.DirStatus == "uncertain" {
			zap.L().Warn("replay: flow direction uncertain, replaying by guess",
				zap.String("task", taskID),
				zap.String("flow", f.ID),
				zap.String("flow_key", f.FlowKey))
		}
	}
	flowMap, err := buildFlowContexts(flows, spec.Rewrites)
	if err != nil {
		return nil, err
	}

	// 3. Load all packets in file order (by RawOffset), user-scoped.
	packets, err := repo.ListAllPacketsByAsset(asset.ID, userID)
	if err != nil {
		return nil, fmt.Errorf("load packets: %w", err)
	}

	checksumMode := spec.ChecksumMode
	if checksumMode == "" {
		checksumMode = "recompute"
	}
	pacer := NewPacer(spec.Speed)

	out := make(chan core.PacketConfig, 256)
	go func() {
		defer close(out)
		pcapFile, err := os.Open(asset.StoragePath)
		if err != nil {
			zap.L().Error("replay planner: open pcap file failed", zap.String("asset", asset.ID), zap.Error(err))
			return
		}
		defer pcapFile.Close()

		loops := spec.Loop
		if loops == 0 {
			loops = 1 // v1: 0 (infinite) capped to 1 pass for safety
		}
		// Compute pcap duration from the first/last packet timestamps for loop
		// timestamp offset (§10): each loop iteration shifts timestamps by
		// loopBase += pcapDuration, avoiding time going backwards.
		pcapDuration := time.Duration(0)
		if len(packets) > 1 {
			firstTs := packets[0].TimestampUs
			lastTs := packets[len(packets)-1].TimestampUs
			pcapDuration = time.Duration(lastTs-firstTs) * time.Microsecond
		}
		// Multi-flow amplification (§16.8): generate N clones per flow.
		if err := checkFlowScalingConflict(spec.FlowScaling, spec.Rewrites); err != nil {
			zap.L().Error("replay planner: flow scaling conflict", zap.String("task", taskID), zap.Error(err))
			return
		}
		interleaveSerial := spec.FlowScaling != nil && spec.FlowScaling.Interleave == "serial"
		// Serial mode: clone 1 all packets, then clone 2 all packets, etc.
		// Each clone gets its own iteration over the packet list.
		cloneCount := 0
		if spec.FlowScaling != nil {
			cloneCount = spec.FlowScaling.Count
		}
		// Determine the outer iteration scheme: for stack mode, it's loop → packet;
		// for serial mode, it's loop → clone → packet.
		stackCloneCount := 0
		if !interleaveSerial && cloneCount > 0 {
			stackCloneCount = cloneCount
		}
		loopBase := time.Duration(0)
		for loop := 0; loop < loops; loop++ {
			// For each loop iteration, generate fresh clones with new seq offsets
			// (§10: "每轮重随机 seq 偏移"). Re-generate clones so the seq offset
			// is re-randomized per round (M5).
			roundClones, err := generateClones(spec.FlowScaling)
			if err != nil {
				zap.L().Error("replay planner: generate clones failed", zap.String("task", taskID), zap.Error(err))
				return
			}
			// Serial mode: iterate over clones outer, then packets inner.
			if interleaveSerial && len(roundClones) > 0 {
				for ci := 0; ci < len(roundClones); ci++ {
					for _, pkt := range packets {
						if ctx.Err() != nil {
							return
						}
						if !emitPacket(pkt, flowMap, pcapFile, roundClones[ci], checksumMode, pacer, taskID, classID, loopBase, out, ctx) {
							return
						}
					}
				}
			} else {
				// Stack mode (default): iterate over packets outer, then clones inner.
				for _, pkt := range packets {
					if ctx.Err() != nil {
						return
					}
					fc, ok := flowMap[pkt.FlowID]
					if !ok {
						continue
					}
					raw := make([]byte, pkt.Length)
					if _, err := pcapFile.ReadAt(raw, pkt.RawOffset); err != nil {
						continue
					}
					basePatches := assemblePatches(fc, pkt, raw)
					if stackCloneCount > 0 {
						for ci := 0; ci < stackCloneCount; ci++ {
							patches := append(append([]Patch{}, basePatches...), clonePatches(roundClones[ci], fc.layout)...)
							if sp, ok := seqOffsetPatch(raw, roundClones[ci], fc.layout); ok {
								patches = append(patches, sp)
							}
							if !emitReplayCfg(pkt, fc, patches, raw, checksumMode, pacer, taskID, classID, loopBase, out, ctx) {
								return
							}
						}
					} else {
						if !emitReplayCfg(pkt, fc, basePatches, raw, checksumMode, pacer, taskID, classID, loopBase, out, ctx) {
							return
						}
					}
				}
			}
			// Advance loopBase by pcapDuration so the next loop iteration starts
			// from where the previous one ended §10/§16.9.
			loopBase += pcapDuration
		}
	}()
	return out, nil
}

// emitPacket reads one packet, assembles patches, and sends it to the output
// channel. Used by serial interleave mode. Returns false if context cancelled.
func emitPacket(pkt storage.PacketModel, flowMap map[string]*flowCtx, pcapFile *os.File, clone Clone, checksumMode string, pacer Pacer, taskID, classID string, loopBase time.Duration, out chan core.PacketConfig, ctx context.Context) bool {
	fc, ok := flowMap[pkt.FlowID]
	if !ok {
		return true
	}
	raw := make([]byte, pkt.Length)
	if _, err := pcapFile.ReadAt(raw, pkt.RawOffset); err != nil {
		return true
	}
	basePatches := assemblePatches(fc, pkt, raw)
	patches := append(append([]Patch{}, basePatches...), clonePatches(clone, fc.layout)...)
	if sp, ok := seqOffsetPatch(raw, clone, fc.layout); ok {
		patches = append(patches, sp)
	}
	return emitReplayCfg(pkt, fc, patches, raw, checksumMode, pacer, taskID, classID, loopBase, out, ctx)
}

// emitReplayCfg builds a PacketConfig with replay metadata and sends it.
func emitReplayCfg(pkt storage.PacketModel, fc *flowCtx, patches []Patch, raw []byte, checksumMode string, pacer Pacer, taskID, classID string, loopBase time.Duration, out chan core.PacketConfig, ctx context.Context) bool {
	// Timestamp: original pkt ts + loopBase offset (§10).
	ts := time.UnixMicro(pkt.TimestampUs).Add(loopBase)
	cfg := core.PacketConfig{
		FlowID:      pkt.FlowID,
		PacketIndex: uint64(pkt.IndexInFlow),
		ClassID:     classID,
		Direction:   mapDirection(pkt.Direction),
		Timestamp:   ts,
		Metadata: map[string]interface{}{
			"_replay":        true,
			"_raw":           raw,
			"_patches":       patches,
			"_checksum_mode": checksumMode,
			"_layout":        fc.layout,
			"_pacer":         pacer,
			"_task_id":       taskID,
			"_interface":     "", // filled by caller
		},
	}
	select {
	case out <- cfg:
		return true
	case <-ctx.Done():
		return false
	}
}

// buildFlowContexts precomputes per-flow patches + endpoint rules + offset rules.
func buildFlowContexts(flows []storage.FlowModel, rules []RewriteRule) (map[string]*flowCtx, error) {
	m := map[string]*flowCtx{}
	for _, flow := range flows {
		var layout pcapparser.OffsetLayout
		if flow.OffsetLayout != "" {
			if err := json.Unmarshal([]byte(flow.OffsetLayout), &layout); err != nil {
				return nil, fmt.Errorf("flow %s layout: %w", flow.ID, err)
			}
		} else {
			layout = pcapparser.OffsetLayout{SrcIP: -1, DstIP: -1, SrcPort: -1, DstPort: -1, SrcMAC: -1, DstMAC: -1, VlanTCO: -1, TTL: -1, DSCPECN: -1, IPFlagsFrag: -1, IPID: -1, Seq: -1, Ack: -1, Window: -1, TCPFlags: -1, L3Start: -1, L4Start: -1}
		}
		flowPatches, err := computeFlowPatches(flow, layout, rules)
		if err != nil {
			return nil, fmt.Errorf("flow %s: %w", flow.ID, err)
		}
		var endpoints []endpointRule
		var offsets []offsetRule
		var macmaps []RewriteRule
		for _, rule := range rules {
			if !matchRule(rule.Match, flow) {
				continue
			}
			switch rule.Kind {
			case "endpoint":
				val, err := resolveStrategyValue(rule.Strategy)
				if err != nil {
					return nil, fmt.Errorf("flow %s endpoint %s: %w", flow.ID, rule.Target, err)
				}
				endpoints = append(endpoints, endpointRule{target: rule.Target, value: val})
			case "field":
				// Collect apply:offset rules for per-packet processing.
				if rule.Apply == "offset" {
					delta, err := resolveOffsetDelta(rule)
					if err != nil {
						return nil, fmt.Errorf("flow %s offset %s: %w", flow.ID, rule.Target, err)
					}
					offsets = append(offsets, offsetRule{target: rule.Target, delta: delta})
				}
			case "macmap":
				macmaps = append(macmaps, rule)
			}
		}
		m[flow.ID] = &flowCtx{flow: flow, layout: layout, flowPatches: flowPatches, endpointRules: endpoints, offsetRules: offsets, macmapRules: macmaps}
	}
	return m, nil
}

// assemblePatches combines flow-level patches with per-packet endpoint patches
// (direction-dependent), apply:offset patches (original value + delta), and
// macmap patches (read MAC from raw, map, patch). raw is the packet's original
// bytes (needed for offset + macmap which depend on per-packet values).
func assemblePatches(fc *flowCtx, pkt storage.PacketModel, raw []byte) []Patch {
	patches := make([]Patch, 0, len(fc.flowPatches)+len(fc.endpointRules)+len(fc.offsetRules)+len(fc.macmapRules))
	// Copy flow patches.
	for _, p := range fc.flowPatches {
		patches = append(patches, p)
	}
	// Per-packet endpoint patches.
	for _, ep := range fc.endpointRules {
		p, err := endpointPatch(pkt.Direction, ep.target, parseIPValue(ep.value), fc.layout)
		if err != nil {
			continue
		}
		patches = append(patches, p)
	}
	// apply:offset patches: new = original + delta (§6).
	for _, or := range fc.offsetRules {
		if p, ok := offsetValuePatch(raw, or, fc.layout); ok {
			patches = append(patches, p)
		}
	}
	// macmap patches: read MAC from raw, look up in mapping, patch (§6).
	for _, rule := range fc.macmapRules {
		patches = append(patches, macmapPatches(raw, rule, fc.layout)...)
	}
	return patches
}

// offsetValuePatch reads the original value at the offset-rule's field offset
// from raw, adds the delta (with uint32 wraparound), and returns a SET patch.
// This preserves in-flow deltas (§6: "流内 delta 不变").
func offsetValuePatch(raw []byte, or offsetRule, layout pcapparser.OffsetLayout) (Patch, bool) {
	spec, ok := fieldSpecFor(layout, or.target)
	if !ok || spec.offset < 0 || spec.offset+spec.width > len(raw) {
		return Patch{}, false
	}
	switch spec.width {
	case 4:
		orig := binary.BigEndian.Uint32(raw[spec.offset : spec.offset+4])
		newVal := orig + or.delta // uint32 wraps naturally
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, newVal)
		return Patch{Field: or.target, Offset: spec.offset, Bytes: b, Layer: spec.layer}, true
	case 2:
		orig := binary.BigEndian.Uint16(raw[spec.offset : spec.offset+2])
		newVal := orig + uint16(or.delta)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, newVal)
		return Patch{Field: or.target, Offset: spec.offset, Bytes: b, Layer: spec.layer}, true
	}
	return Patch{}, false
}

// macmapPatches reads the src/dst MAC from raw and applies the macmap mapping
// (§6). MACs aren't in FlowModel, so macmap is per-packet.
func macmapPatches(raw []byte, rule RewriteRule, layout pcapparser.OffsetLayout) []Patch {
	var patches []Patch
	if layout.SrcMAC >= 0 && layout.SrcMAC+6 <= len(raw) {
		srcMAC := net.HardwareAddr(raw[layout.SrcMAC : layout.SrcMAC+6]).String()
		if newVal, ok := rule.Mapping[srcMAC]; ok {
			if hw, err := net.ParseMAC(newVal); err == nil {
				patches = append(patches, Patch{Field: "src_mac", Offset: layout.SrcMAC, Bytes: hw, Layer: "l2"})
			}
		}
	}
	if layout.DstMAC >= 0 && layout.DstMAC+6 <= len(raw) {
		dstMAC := net.HardwareAddr(raw[layout.DstMAC : layout.DstMAC+6]).String()
		if newVal, ok := rule.Mapping[dstMAC]; ok {
			if hw, err := net.ParseMAC(newVal); err == nil {
				patches = append(patches, Patch{Field: "dst_mac", Offset: layout.DstMAC, Bytes: hw, Layer: "l2"})
			}
		}
	}
	return patches
}

// parseIPValue parses a string as a net.IP (for endpoint rules).
func parseIPValue(s string) net.IP {
	return net.ParseIP(s)
}

// mapDirection converts the parser's "c2s"/"s2c" to the engine's "up"/"down".
// The replay path keeps c2s/s2c semantics (used for dual-port routing); the
// engine's Direction field uses up/down for synth traffic, so we map c2s->up,
// s2c->down for compatibility with the existing output routing.
func mapDirection(dir string) string {
	switch dir {
	case "c2s":
		return "up"
	case "s2c":
		return "down"
	}
	return dir
}
