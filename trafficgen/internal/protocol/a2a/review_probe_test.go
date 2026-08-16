package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Probe: does the response emitted for the Agent Card discovery GET byte-match
// the legacy planner's response data segment (with the down port swap)?
func TestReviewProbe_AgentCardRespBytes(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Discover = true
	spec := basicSpec(cfg)
	events := collectEvents(t, spec)
	// event[1] is the agent card response; build it via legacy builder.
	respBody, _ := json.Marshal(cfg.AgentCard)
	want := []byte(buildHTTPResponse(cfg, 200, "OK", "application/json", respBody, false))
	if !bytes.Equal(events[1].Bytes, want) {
		t.Fatalf("agent card response mismatch:\n got %q\nwant %q", events[1].Bytes, want)
	}
	// legacy plan: agent card response should be a PSH-ACK down data segment.
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var idx int
	var sbAll strings.Builder
	for pc := range ch {
		if pc.L4.Flags == 0x18 {
			sbAll.WriteString(fmt.Sprintf("seg[%d] dir=%s payload=%q\n", idx, pc.Direction, pc.Payload))
			idx++
		}
	}
	os.WriteFile("/tmp/probe_all.txt", []byte(sbAll.String()), 0644)
}

// Probe: validator default (Handshake/Termination nil) must write true into
// spec.TCP so the tcp layer performs handshake+teardown on the chain.
func TestReviewProbe_ValidatorWritesTrueDefaults(t *testing.T) {
	cfg := validA2AConfig()
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "a2a"},
	})
	validated, err := planner.ValidateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if validated.TCP == nil {
		t.Fatal("spec.TCP is nil after validation")
	}
	if !validated.TCP.Handshake || !validated.TCP.Termination {
		t.Fatalf("defaults not written: handshake=%v termination=%v", validated.TCP.Handshake, validated.TCP.Termination)
	}
}
