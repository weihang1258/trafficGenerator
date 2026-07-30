// Package rdp scenario-mode session templates.
//
// When RDPConfig.Scenario is set, the planner auto-populates the
// Channels / DataEvents / ServerResponses fields with sensible defaults
// for the named scenario before encoding. This lets users get a
// realistic end-to-end RDP session (full_session) or focus on a single
// protocol layer (cliprdr, rdpdr, input_events, etc.) without
// hand-crafting each connection phase.
//
// Supported scenarios (design_rdp.md §4):
//
//	""                    manual mode; planner uses whatever Channels/
//	                      DataEvents/ServerResponses the user supplied
//	                      (backward compatible default).
//	"full_session"        complete RDP session: TLS handshake + 4 static
//	                      channels (cliprdr/rdpdr/rdpsnd/drdynvc) +
//	                      keyboard/mouse input + bitmap output (the
//	                      realistic Win10 mstsc.exe flow).
//	"multi_channel"       4 static virtual channels with successful
//	                      Channel-Join Confirm results (all rt-successful).
//	"cliprdr"             clipboard redirection: cliprdr channel +
//	                      CB_FORMAT_LIST (CF_TEXT + CF_UNICODETEXT).
//	"rdpdr"               device redirection: rdpdr channel +
//	                      PAKID_CORE_DEVICELIST_ANNOUNCE with one disk
//	                      device (drive C:).
//	"input_events"        one FastPath Input keyboard event (Enter down)
//	                      + one FastPath Input mouse event (move).
//	"bitmap_update"       one FastPath Output Bitmap Update PDU.
//	"channel_join_failure" multi-channel session where the server
//	                      rejects the second Channel-Join with
//	                      rt-no-such-channel (result=4).
//	"disconnect"          minimal session that ends with Shutdown
//	                      Request + MCS Disconnect Provider Ultimatum
//	                      (reason=user-requested, 0x80) + TCP teardown.
//
// User-supplied Channels / DataEvents / ServerResponses are preserved
// (forwarder-style override): the scenario only fills in empty slots.
// This matches the design_rdp.md §6.2 rule "use defaults, override
// where user supplied" and is asserted by TestScenario_ManualConfig-
// OverridesScenario.
package rdp

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validateScenario validates the prerequisites for a scenario. Called
// from Planner.Validate when cfg.Scenario != "". Returns an error for
// an unknown scenario name.
func validateScenario(cfg *core.RDPConfig) error {
	switch cfg.Scenario {
	case "", "full_session", "multi_channel", "cliprdr", "rdpdr",
		"input_events", "bitmap_update", "channel_join_failure",
		"disconnect":
		return nil
	default:
		return fmt.Errorf("rdp: unknown scenario %q (want full_session/multi_channel/cliprdr/rdpdr/input_events/bitmap_update/channel_join_failure/disconnect)", cfg.Scenario)
	}
}

// applyScenarioDefaults fills in Channels / DataEvents / ServerResponses
// on cfg with the scenario's sensible defaults when those fields are
// empty. Already-populated fields are preserved (forwarder-style
// override). Returns the mutated cfg for convenience; the mutation is
// also visible to the caller via the same pointer.
func applyScenarioDefaults(cfg *core.RDPConfig) {
	if cfg == nil || cfg.Scenario == "" {
		return
	}
	switch cfg.Scenario {
	case "full_session":
		if len(cfg.Channels) == 0 {
			cfg.Channels = []core.RDPChannel{
				{Name: "cliprdr", Options: 0xC0000000},
				{Name: "rdpdr", Options: 0xC0000000},
				{Name: "rdpsnd", Options: 0xC0000000},
				{Name: "drdynvc", Options: 0xC0000000},
			}
		}
		if len(cfg.DataEvents) == 0 {
			cfg.DataEvents = []core.RDPDataEvent{
				{Type: "fastpath_input_keyboard"},
				{Type: "fastpath_input_mouse"},
			}
		}
		if len(cfg.ServerResponses) == 0 {
			cfg.ServerResponses = []core.RDPServerResponse{
				{Type: "bitmap_update"},
			}
		}
	case "multi_channel":
		if len(cfg.Channels) == 0 {
			cfg.Channels = []core.RDPChannel{
				{Name: "cliprdr", Options: 0xC0000000},
				{Name: "rdpdr", Options: 0xC0000000},
				{Name: "rdpsnd", Options: 0xC0000000},
				{Name: "drdynvc", Options: 0xC0000000},
			}
		}
	case "cliprdr":
		if len(cfg.Channels) == 0 {
			cfg.Channels = []core.RDPChannel{{Name: "cliprdr"}}
		}
		if len(cfg.DataEvents) == 0 {
			cfg.DataEvents = []core.RDPDataEvent{
				{Type: "cliprdr_format_list", Channel: "cliprdr"},
			}
		}
	case "rdpdr":
		if len(cfg.Channels) == 0 {
			cfg.Channels = []core.RDPChannel{{Name: "rdpdr"}}
		}
		if len(cfg.DataEvents) == 0 {
			cfg.DataEvents = []core.RDPDataEvent{
				{Type: "rdpdr_clientid_confirm", Channel: "rdpdr"},
				{Type: "rdpdr_client_name", Channel: "rdpdr"},
				{Type: "rdpdr_device_list", Channel: "rdpdr"},
			}
		}
	case "input_events":
		if len(cfg.DataEvents) == 0 {
			cfg.DataEvents = []core.RDPDataEvent{
				{Type: "fastpath_input_keyboard"},
				{Type: "fastpath_input_mouse"},
			}
		}
	case "bitmap_update":
		if len(cfg.ServerResponses) == 0 {
			cfg.ServerResponses = []core.RDPServerResponse{
				{Type: "bitmap_update"},
			}
		}
	case "channel_join_failure":
		// Two channels; second one is rejected.
		if len(cfg.Channels) == 0 {
			cfg.Channels = []core.RDPChannel{
				{Name: "cliprdr"},
				{Name: "rdpdr"},
			}
		}
		if len(cfg.ServerResponses) == 0 {
			cfg.ServerResponses = []core.RDPServerResponse{
				{Type: "channel_join_failure", Payload: []byte("rdpdr")},
			}
		}
	case "disconnect":
		// No defaults: the default Plan() already ends with Shutdown +
		// MCS Disconnect + TCP teardown.
	}
}