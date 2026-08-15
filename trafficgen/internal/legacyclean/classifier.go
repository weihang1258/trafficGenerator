// Package legacyclean implements the P5 legacy-strategy cleanup: it scans the
// strategies table, classifies each row as layer-chain (new format), legacy
// flat (delete target), unparseable, or replay, and deletes legacy rows with
// a JSON backup written before any deletion.
//
// Classification rule (design doc §11.2): a strategy is legacy iff mode is
// "synth" and its config JSON has no top-level "layers" key. Replay configs
// reject the layers key (strategy_handler.go), so replay is never legacy.
package legacyclean

import "encoding/json"

// Kind classifies a strategy row.
type Kind int

const (
	// KindLayerChain: synth + config has a top-level "layers" key (new format, keep).
	KindLayerChain Kind = iota
	// KindLegacy: synth + config parses + no "layers" key (flat format, delete target).
	KindLegacy
	// KindUnparseable: synth + config is not valid JSON. Cannot be a valid layer
	// chain, so it is a delete target, but it is counted separately.
	KindUnparseable
	// KindReplay: mode != "synth". Never a delete target.
	KindReplay
)

// Classify determines a strategy's kind from its mode and config JSON.
func Classify(mode, configJSON string) Kind {
	if mode != "synth" {
		return KindReplay
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &m); err != nil {
		return KindUnparseable
	}
	if _, ok := m["layers"]; ok {
		return KindLayerChain
	}
	return KindLegacy
}
