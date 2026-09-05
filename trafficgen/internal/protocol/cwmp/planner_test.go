package cwmp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trafficgen/trafficgen/internal/core"
)

// TestTransferCompleteResponsePendingKind is the failing-test-first repro for
// the validator bug at planner.go:273-282: the response kind check compares
// pendingKind (set to the request kind, e.g. "transfer_complete") against
// tx.Kind (the response kind, e.g. "transfer_complete_response") — they never
// match. The fix is to compare against the request kind
// (strings.TrimSuffix(tx.Kind, "_response")) — same pattern used in the error
// message itself.
func TestTransferCompleteResponsePendingKind(t *testing.T) {
	dl := "download"
	spec := core.FlowSpec{
		CWMP: &core.CWMPConfig{
			Sessions: []core.CWMPSession{{
				Role: "cpe",
				Transactions: []core.CWMPTransaction{
					{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "1 BOOT"}}},
					{Kind: "inform_response", ID: "1"},
					{Kind: "acs_request", Method: "download", ID: "2", CommandKey: "ck-1"},
					{Kind: "acs_response", Method: "download"},
					{Kind: "transfer_complete", ID: "3", CommandKey: "ck-1"},
					{Kind: "transfer_complete_response", ID: "3"},
					{Kind: "empty_post", ID: "4"},
					{Kind: "empty_response", ID: "4"},
				},
			}},
		},
	}
	_ = dl
	err := Validate(spec)
	require.NoError(t, err, "transfer_complete_response must match against request kind (TrimSuffix)")
}

func TestAutonomousTransferCompleteResponsePendingKind(t *testing.T) {
	spec := core.FlowSpec{
		CWMP: &core.CWMPConfig{
			Sessions: []core.CWMPSession{{
				Role: "cpe",
				Transactions: []core.CWMPTransaction{
					{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "1 BOOT"}}},
					{Kind: "inform_response", ID: "1"},
					{Kind: "acs_request", Method: "get_parameter_values", ID: "2"},
					{Kind: "acs_response", Method: "get_parameter_values"},
					{Kind: "autonomous_transfer_complete", ID: "3", CommandKey: "ck-aut"},
					{Kind: "autonomous_transfer_complete_response", ID: "3"},
					{Kind: "empty_post", ID: "4"},
					{Kind: "empty_response", ID: "4"},
				},
			}},
		},
	}
	err := Validate(spec)
	require.NoError(t, err, "autonomous_transfer_complete_response must match against request kind")
}

func TestRequestDownloadResponsePendingKind(t *testing.T) {
	spec := core.FlowSpec{
		CWMP: &core.CWMPConfig{
			Sessions: []core.CWMPSession{{
				Role: "cpe",
				Transactions: []core.CWMPTransaction{
					{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "1 BOOT"}}},
					{Kind: "inform_response", ID: "1"},
					{Kind: "acs_request", Method: "download", ID: "2"},
					{Kind: "acs_response", Method: "download"},
					{Kind: "request_download", ID: "3"},
					{Kind: "request_download_response", ID: "3"},
					{Kind: "empty_post", ID: "4"},
					{Kind: "empty_response", ID: "4"},
				},
			}},
		},
	}
	err := Validate(spec)
	require.NoError(t, err, "request_download_response must match against request kind")
}
