package core

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// computeHashKey derives the routing key and group id for a flow.
//
// Priority (spec §3.2):
//  1. spec.GroupID non-nil with a strategy -> generate gID via StrategyConfig,
//     hashKey = gID
//  2. replay task (Mode == "replay" or len(Replay) > 0) with nil GroupID ->
//     implicit gID "taskID:classID", hashKey = gID (preserves pcap order in
//     one asset). Note: PlanReplay writes gID into Metadata before the
//     PacketConfig reaches this function; this branch is the fallback for
//     tasks where the planner didn't pre-compute it.
//  3. synth task with nil GroupID -> unordered 4-tuple,
//     hashKey = "minIP-maxIP-minPort-maxPort" string, gID = "" (fallback)
//
// flowIdx is the per-task flow index, used to advance pattern/inc strategies.
// Returns (hashKey, gID). gID is "" on the synth fallback path; otherwise it
// equals hashKey (both written to Metadata for debugging).
func computeHashKey(spec FlowSpec, task Task, flowIdx int) (hashKey, gID string) {
	// Case 1: explicit group_id strategy
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		g := genStringValue(*spec.GroupID, flowIdx)
		if g != "" {
			return g, g
		}
		// strategy set but generated empty (misconfiguration) -> fall through
	}

	// Case 2: replay with empty group_id -> implicit gID
	if task.Mode == "replay" || len(task.Replay) > 0 {
		implicit := task.ID + ":" + task.ClassID
		return implicit, implicit
	}

	// Case 3: synth fallback to unordered 4-tuple
	srcIP, dstIP := spec.SrcIP, spec.DstIP
	if dstIP < srcIP {
		srcIP, dstIP = dstIP, srcIP
	}
	srcPort, dstPort := spec.SrcPort, spec.DstPort
	if dstPort < srcPort {
		srcPort, dstPort = dstPort, srcPort
	}
	hashKey = fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, srcPort, dstPort)
	return hashKey, ""
}

// genStringValue generates a string value from a StrategyConfig (for group_id).
// Supports fixed/list/inc/rand/pattern. Returns "" if strategy unknown or
// config invalid. Deterministic per index (rand uses seed+index).
func genStringValue(s StrategyConfig, index int) string {
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
		return applyPattern(s.Pattern, s.Range, index)
	case "inc":
		if len(s.Range) < 2 {
			return ""
		}
		start := toInt(s.Range[0])
		end := toInt(s.Range[1])
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
		start := toInt(s.Range[0])
		end := toInt(s.Range[1])
		if end < start {
			return ""
		}
		r := rand.New(rand.NewSource(s.Seed + int64(index)))
		return strconv.Itoa(start + r.Intn(end-start+1))
	}
	return ""
}

// applyPattern substitutes {n} in the pattern with a value derived from
// n_range [start, end]. index 0 -> start, index k -> start + k, wraps after
// (end - start + 1) values.
func applyPattern(pattern string, nRange []interface{}, index int) string {
	if pattern == "" || len(nRange) < 2 {
		return ""
	}
	start := toInt(nRange[0])
	end := toInt(nRange[1])
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

// toInt converts interface{} (float64/int/int64/string) to int.
func toInt(v interface{}) int {
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

// FlowGroupIDValue evaluates a FlowSpec.GroupID strategy at the given flow
// index and returns the resulting group_id string. Returns "" when the
// strategy is empty / unset / invalid — callers should treat that as "no
// group_id", letting the engine's worker fall back to the unordered 4-tuple
// hash via computeHashKey.
//
// Exposed so planners (FTP, SIP, ...) can pre-write Metadata["group_id"]
// on their emitted PacketConfigs so external tools reading PacketConfig
// directly (parsers, replays, snapshots) see the same group the worker
// would stamp. The package-internal genStringValue is the source of truth
// — this is just a public wrapper.
func FlowGroupIDValue(s *StrategyConfig, flowIdx int) string {
	if s == nil {
		return ""
	}
	return genStringValue(*s, flowIdx)
}
