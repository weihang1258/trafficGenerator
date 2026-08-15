package protocolpcap

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSmbNegCases(t *testing.T) {
	ctx := t.Context()
	r, err := NewRunner(ctx, "http://127.0.0.1:8081/mcp", "dev-mcp-key", "/tmp/mcp-pcaps-smb")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := os.ReadFile("cases/smb.json")
	var cases []Case
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"smb_tneg_T226_dialect_invalid":      true,
		"smb_tneg_T227_smb1_string":          true,
		"smb_tneg_T228_authmech_invalid":     true,
		"smb_tneg_T229_anon_rounds3":         true,
		"smb_tneg_T230_rounds_oob":           true,
		"smb_tneg_T230a_ntlm_rounds1":        true,
		"smb_tneg_T231_disposition_oob":      true,
		"smb_tneg_T232_share_no_unc":         true,
		"smb_tneg_T233_optype_invalid":       true,
		"smb_tneg_T234_errorcmd_invalid":     true,
		"smb_tneg_T235_errstatus_unknown":    true,
		"smb_tneg_T236_maxtransact_oob":      true,
		"smb_tneg_T237_sharetype_oob":        true,
		"smb_tneg_T238_errstatus_no_errcmd":  true,
		"smb_tneg_T240_preauth_algo_invalid": true,
	}
	// Stop any in-flight tasks first; the dev server single-flights tasks.
	if _, err := r.Client.CallTool(ctx, "flowb_stop_all_tasks", map[string]any{}); err != nil {
		t.Logf("stop_all_tasks: %v", err)
	}
	time.Sleep(1 * time.Second)
	for _, c := range cases {
		if !want[c.ID] {
			continue
		}
		// Reset state between cases.
		_, _ = r.Client.CallTool(ctx, "flowb_stop_all_tasks", map[string]any{})
		time.Sleep(500 * time.Millisecond)
		res := r.RunCase(ctx, c, 30*time.Second)
		t.Logf("case %s: status=%s err=%s", c.ID, res.Status, res.Err)
		if res.Status != "pass" {
			t.Errorf("case %s failed: %s", c.ID, res.Err)
		}
		// Give the server a moment to settle between cases.
		time.Sleep(500 * time.Millisecond)
	}
}