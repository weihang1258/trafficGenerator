package dameng

import (
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// knownProfiles is the set of valid wire profiles.
var knownProfiles = map[string]bool{
	"dm8_profile_pending": true,
	"length_boundary":     true,
}

// buildPacket assembles one Dameng message event from a config event.
func buildPacket(ev core.DamengEvent) ([]byte, error) {
	payload := profilePayload(ev.Profile)
	return payload, nil
}

// profilePayload returns a minimal non-empty placeholder payload for a given profile name.
// The payload is a contract name, not real DM8 wire bytes — it just needs to be
// non-empty so the packet has a valid length > 0. The design v1 explicitly does not
// fabricate DM8 version-specific bytes.
func profilePayload(profile string) []byte {
	if profile == "" {
		profile = "dm8"
	}
	return []byte(profile)
}

// wireFault is the negative-test fault injection: planner checks it before
// constructing any packet, returning a config error.
type wireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkWireFault parses the config wire_fault and returns a config error if the
// injected fault is in scope for this build.
func checkWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var f wireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("dameng: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "truncate_message":
		return fmt.Errorf("dameng: wire fault: truncated message length %v", f.Value)
	case "message_limit":
		return fmt.Errorf("dameng: wire fault: message over implementation limit %v", f.Value)
	default:
		return fmt.Errorf("dameng: wire fault: unknown kind %q", f.Kind)
	}
}