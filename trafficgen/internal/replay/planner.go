package replay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
// fc carries the task-level flow-control state: non-nil means single-protocol
// path (not batch), and a non-nil fc.FlowCounter means a flows ceiling is
// active — each unique flow ID increments the counter and flows past the
// ceiling are skipped.
func (p *ReplayPlanner) PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string, fc *core.ReplayFC) (<-chan core.PacketConfig, error) {
	var spec ReplaySpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal replay spec: %w", err)
	}
	return p.Plan(ctx, spec, taskID, classID, userID, fc)
}

// Plan produces a channel of PacketConfigs for the replay (§4). It runs in a
// goroutine and closes the channel when done (or on context cancel). The caller
// (ConfigWorker) drains the channel into the engine pipeline. userID scopes
// asset/flow/packet reads to the owning user.
func (p *ReplayPlanner) Plan(ctx context.Context, spec ReplaySpec, taskID, classID, userID string, fc *core.ReplayFC) (<-chan core.PacketConfig, error) {
	// P1-13：loop 负值同步拒绝（goroutine 内无法报错）；省略=nil=单遍，
	// 0=无限。无限由 ctx 终止：emit 逐包检查 ctx，任务 stop 走同一取消路径。
	if spec.Loop != nil && *spec.Loop < 0 {
		return nil, fmt.Errorf("loop must be >= 0 (0 = infinite, omit for a single pass), got %d", *spec.Loop)
	}
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
	// M6: an asset with status=ready but zero parsed packets (e.g. parser
	// produced nothing -- truncated file with only a global header, or all
	// packets failed to parse) is a user-visible error, not a silent 0-packet
	// "completion". Without this check, Plan launches a goroutine that iterates
	// an empty list, closes the channel with 0 configs, and returns nil --
	// causing processReplayTask to report the task as "completed" with 0
	// packets.
	if len(packets) == 0 {
		return nil, fmt.Errorf("pcap asset %s has no packets to replay", asset.ID)
	}

	checksumMode := spec.ChecksumMode
	if checksumMode == "" {
		checksumMode = "recompute"
	}
	// Pacer selection (§16.9, R-F2 invariant: pacer and task-level bps ceiling
	// never coexist on the same packet). Two paths:
	//   - Batch (fc==nil): always use a Pacer -- original/multiplier via
	//     TimestampPacer, bps via TokenBucketPacer, empty via MaxPacer. processConfig
	//     sees _pacer in Metadata and routes through it (no engine child bucket
	//     exists for batch classes).
	//   - Single-protocol (fc!=nil): original/multiplier still use TimestampPacer
	//     (validated at Create/Start to forbid a task-level bps ceiling alongside);
	//     bps/empty drop the pacer (nil) so processConfig falls through to the
	//     engine's per-strategy child bucket (bps) or no rate limit at all (empty,
	//     only the optional task-level parent bucket applies).
	var pacer Pacer // nil = no in-packet pacer
	switch spec.Speed.Mode {
	case "original", "multiplier":
		pacer = NewPacer(spec.Speed)
	case "bps":
		if fc == nil {
			pacer = NewPacer(spec.Speed) // batch: TokenBucketPacer
		}
		// single-protocol: pacer stays nil, route through engine child bucket
	case "", "max":
		if fc == nil {
			pacer = NewPacer(spec.Speed) // batch: MaxPacer
		}
		// single-protocol: pacer stays nil, no rate limit (only parent bucket)
	}

	// Flow ceiling counter (§B1). Only active when fc != nil and
	// fc.FlowCounter != nil (single-protocol task with type=flows). The seen
	// map dedupes flow IDs so a multi-packet flow only counts once; skipped
	// records flows past the ceiling so subsequent packets of the same flow
	// are also skipped. Single goroutine owns seen/skipped (no race).
	//
	// M3 (known limitation, documented): the seen map is per-Plan-call (per-
	// strategy), but fc.FlowCounter is shared across strategies in the same
	// task. If two replay strategies in one task both contain flow X, each
	// strategy's seen map independently records X and increments the shared
	// counter -- so X is counted twice. This over-counts the total toward the
	// task-level ceiling, causing flows past the ceiling to be skipped earlier
	// than the user intended. The reverse (under-count) cannot happen: every
	// unique flow in every strategy increments the counter at least once.
	//
	// Fixing this requires hoisting seen/skipped to the fc level (shared across
	// strategies), which needs engine-side coordination because fc is currently
	// a plain struct passed by pointer. Deferred as low-priority because the
	// common case is one replay strategy per task, and multi-strategy tasks
	// with overlapping flow sets are rare.
	seen := map[string]bool{}
	skipped := map[string]bool{}
	countFlow := func(flowID string) bool {
		if fc == nil || fc.FlowCounter == nil {
			return true
		}
		if skipped[flowID] {
			return false
		}
		if !seen[flowID] {
			seen[flowID] = true
			if atomic.AddInt64(fc.FlowCounter, 1) > fc.Ceiling {
				skipped[flowID] = true
				// Exact signal for the worker's 0-config guard: the ceiling
				// (not a broken plan) is why packets were dropped. Written
				// before the output channel closes, so the consumer's read
				// after the close is happens-after (channel-close ordering).
				fc.SkippedAll = true
				return false
			}
		}
		return true
	}

	// Open the pcap file + validate flow scaling synchronously so failures
	// surface as Plan errors instead of silently closing the channel with 0
	// configs. Without this, processReplayTask would report the task as
	// "completed" with 0 packets when the file is missing/deleted/moved (M1).
	// The goroutine owns the file's Close via defer.
	pcapFile, err := os.Open(asset.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("open pcap file %s: %w", asset.StoragePath, err)
	}
	if err := checkFlowScalingConflict(spec.FlowScaling, spec.Rewrites); err != nil {
		pcapFile.Close()
		return nil, fmt.Errorf("flow scaling conflict: %w", err)
	}
	// Pre-generate clones once to catch generation errors before launching
	// the goroutine. The goroutine re-generates per loop for seq
	// re-randomization (M5); a loop-1+ failure is extremely unlikely for a
	// random generator and would still emit loop 0's packets before closing.
	if _, err := generateClones(spec.FlowScaling); err != nil {
		pcapFile.Close()
		return nil, fmt.Errorf("generate clones: %w", err)
	}

	out := make(chan core.PacketConfig, 256)
	go func() {
		defer close(out)
		defer pcapFile.Close()

		// P1-13（2026-10-05 客户端复测）：显式 0 = 无限（types.go 与工具
		// 描述同文）——v1 把 0 钳成 1 遍（"capped to 1 pass for safety"），
		// 与文档矛盾且压测长稳无法表达。省略（nil）保持单遍缺省不变。
		loops, infinite := 1, false
		if spec.Loop != nil {
			if *spec.Loop == 0 {
				infinite = true
			} else {
				loops = *spec.Loop
			}
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
		// checkFlowScalingConflict already validated synchronously above.
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
		for loop := 0; infinite || loop < loops; loop++ {
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
					gID := computeReplayGroupID(spec, taskID, classID, ci)
					for _, pkt := range packets {
						if ctx.Err() != nil {
							return
						}
						if !countFlow(pkt.FlowID) {
							continue
						}
						if !emitPacket(pkt, flowMap, pcapFile, roundClones[ci], checksumMode, pacer, taskID, classID, gID, loopBase, out, ctx) {
							return
						}
					}
				}
			} else {
				// Stack mode (default): iterate over packets outer, then clones inner.
				// Compute gID per clone (or single implicit gID if no FlowScaling).
				for _, pkt := range packets {
					if ctx.Err() != nil {
						return
					}
					if !countFlow(pkt.FlowID) {
						continue
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
							gID := computeReplayGroupID(spec, taskID, classID, ci)
							patches := append(append([]Patch{}, basePatches...), clonePatches(roundClones[ci], fc.layout)...)
							if sp, ok := seqOffsetPatch(raw, roundClones[ci], fc.layout); ok {
								patches = append(patches, sp)
							}
							if !emitReplayCfg(pkt, fc, patches, raw, checksumMode, pacer, taskID, classID, gID, loopBase, out, ctx) {
								return
							}
						}
					} else {
						// No FlowScaling: single implicit gID for whole asset
						// (computeReplayGroupID with cloneIdx=0 returns
						// taskID:classID when no FlowScaling).
						gID := computeReplayGroupID(spec, taskID, classID, 0)
						if !emitReplayCfg(pkt, fc, basePatches, raw, checksumMode, pacer, taskID, classID, gID, loopBase, out, ctx) {
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
func emitPacket(pkt storage.PacketModel, flowMap map[string]*flowCtx, pcapFile *os.File, clone Clone, checksumMode string, pacer Pacer, taskID, classID string, gID string, loopBase time.Duration, out chan core.PacketConfig, ctx context.Context) bool {
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
	return emitReplayCfg(pkt, fc, patches, raw, checksumMode, pacer, taskID, classID, gID, loopBase, out, ctx)
}

// emitReplayCfg builds a PacketConfig with replay metadata and sends it.
func emitReplayCfg(pkt storage.PacketModel, fc *flowCtx, patches []Patch, raw []byte, checksumMode string, pacer Pacer, taskID, classID, gID string, loopBase time.Duration, out chan core.PacketConfig, ctx context.Context) bool {
	// Timestamp: original pkt ts + loopBase offset (§10).
	ts := time.UnixMicro(pkt.TimestampUs).Add(loopBase)
	meta := map[string]interface{}{
		"_replay":        true,
		"_raw":           raw,
		"_patches":       patches,
		"_checksum_mode": checksumMode,
		"_layout":        fc.layout,
		"_task_id":       taskID,
		"_interface":     "", // filled by caller
		"group_id":       gID,
	}
	// Only attach a pacer when one is in use. nil pacer = single-protocol
	// bps/empty mode, where processConfig should fall through to the engine's
	// child/parent rate-limiter buckets instead.
	if pacer != nil {
		meta["_pacer"] = pacer
	}
	cfg := core.PacketConfig{
		FlowID:      pkt.FlowID,
		PacketIndex: uint64(pkt.IndexInFlow),
		ClassID:     classID,
		Direction:   mapDirection(pkt.Direction),
		Timestamp:   ts,
		Metadata:    meta,
	}
	select {
	case out <- cfg:
		return true
	case <-ctx.Done():
		return false
	}
}

// computeReplayGroupID derives the group id for a replay flow (spec §8.1).
//
// Priority:
//  1. ReplaySpec.GroupID non-nil with a strategy -> generate via strategy
//     (fixed/inc/pattern/list)
//  2. FlowScaling exists -> implicit "taskID:classID:cloneIdx" per clone
//  3. No FlowScaling -> implicit "taskID:classID" (whole asset, preserves
//     pcap order)
func computeReplayGroupID(spec ReplaySpec, taskID, classID string, cloneIdx int) string {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		g := genReplayGroupValue(*spec.GroupID, cloneIdx)
		if g != "" {
			return g
		}
	}
	if spec.FlowScaling != nil && spec.FlowScaling.Count > 0 {
		return taskID + ":" + classID + ":" + strconv.Itoa(cloneIdx)
	}
	return taskID + ":" + classID
}

// genReplayGroupValue mirrors core.genStringValue but lives in the replay
// package to avoid an import cycle (core can't import replay).
func genReplayGroupValue(s core.StrategyConfig, index int) string {
	switch s.Strategy {
	case "fixed", "":
		if v, ok := s.Value.(string); ok {
			return v
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return ""
		}
		return s.List[index%len(s.List)]
	case "pattern":
		return applyReplayPattern(s.Pattern, s.Range, index)
	case "inc":
		if len(s.Range) < 2 {
			return ""
		}
		start := replayToInt(s.Range[0])
		end := replayToInt(s.Range[1])
		if end < start {
			return ""
		}
		count := end - start + 1
		step := s.Step
		if step <= 0 {
			step = 1
		}
		return strconv.Itoa(start + (index*step)%count)
	case "rand":
		if len(s.Range) < 2 {
			return ""
		}
		start := replayToInt(s.Range[0])
		end := replayToInt(s.Range[1])
		if end < start {
			return ""
		}
		r := rand.New(rand.NewSource(s.Seed + int64(index)))
		return strconv.Itoa(start + r.Intn(end-start+1))
	}
	return ""
}

func applyReplayPattern(pattern string, nRange []interface{}, index int) string {
	if pattern == "" || len(nRange) < 2 {
		return ""
	}
	start := replayToInt(nRange[0])
	end := replayToInt(nRange[1])
	if end < start {
		return ""
	}
	count := end - start + 1
	if count <= 0 {
		return ""
	}
	n := start + (index % count)
	return strings.ReplaceAll(pattern, "{n}", strconv.Itoa(n))
}

func replayToInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
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
