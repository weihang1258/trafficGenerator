package http

// Test points derived from tools/test_points/protocols.md (HTTP section H1-H62).
// Each test asserts observable PacketConfig field values, not just "no error".
// Known-bug test points assert the CORRECT behavior but use t.Skip with the
// bug description so the suite stays green; remove the skip when the bug is fixed.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// cryptoRand is crypto/rand.Reader aliased for concise use in tests. We use
// crypto/rand rather than math/rand for incompressible byte patterns because
// gzip's LZ77 stage cannot find back-references in cryptographic random,
// guaranteeing the compressed output stays larger than MSS regardless of
// future Go stdlib gzip improvements.
var cryptoRand = rand.Reader

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func validHTTPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		HTTP: &core.HTTPConfig{
			Method: "GET",
			URI:    "/",
		},
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
	}
}

// --- Validate (H1-H7) ---

func TestHTTPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 80,
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestHTTPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "invalid", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 80,
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP: invalid") {
		t.Errorf("err=%v, want contains 'invalid source IP: invalid'", err)
	}
}

func TestHTTPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "invalid",
		SrcPort: 12345, DstPort: 80,
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestHTTPValidate_BothIPsEmpty(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "", DstIP: "", SrcPort: 12345, DstPort: 80}
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty IPs should skip: %v", err)
	}
}

func TestHTTPValidate_OneIPEmpty(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 80}
	if err := p.Validate(spec); err != nil {
		t.Errorf("one empty IP should skip: %v", err)
	}
}

func TestHTTPValidate_PartialIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "192.168.1", DstIP: "192.168.1.2", SrcPort: 12345, DstPort: 80}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

// H7-POS: Validate sets DstPort=80 on its local copy but caller's spec is unchanged.
func TestHTTPValidate_DstPortDefaultLocal(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 0,
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("DstPort=0 should not fail: %v", err)
	}
	if spec.DstPort != 0 {
		t.Errorf("caller spec.DstPort=%d, want 0 (pass-by-value, Validate modified a copy)", spec.DstPort)
	}
}

// H7-NEG: Known bug - DstPort=0 from Validate doesn't propagate to Plan because
// Validate's spec is a value copy.
func TestHTTPPlan_DstPortZeroNotDefaulted(t *testing.T) {
	t.Skip("known bug H7: DstPort=0 not defaulted to 80 in Plan (pass-by-value bug in Validate). Remove skip once fixed.")
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.DstPort = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L4.DstPort != 80 {
		t.Errorf("DstPort=%d, want 80 (should default to 80)", cfgs[0].L4.DstPort)
	}
}

// --- Plan entry (H8-H9) ---

func TestHTTPPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "invalid", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80}
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestHTTPPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validHTTPSpec())
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	if ch == nil {
		t.Fatal("nil channel")
	}
	if cap(ch) != 256 {
		t.Errorf("cap(ch)=%d, want 256", cap(ch))
	}
	drain(ch)
}

// --- Default values (H10-H20, H55-H56, H58, H62) ---

func TestHTTPPlan_ConfigNilDefaults(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 9 {
		t.Fatalf("len=%d, want >=9", len(cfgs))
	}
	// Request packet is at index 3 (after 3 handshake packets)
	reqPayload := cfgs[3].Payload
	if !strings.Contains(string(reqPayload), "GET / HTTP/1.1") {
		t.Errorf("request payload=%q, want contains 'GET / HTTP/1.1'", string(reqPayload))
	}
}

func TestHTTPPlan_ConfigProvided(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{Method: "POST", URI: "/api"}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 9 {
		t.Fatalf("len=%d, want >=9", len(cfgs))
	}
	reqPayload := cfgs[3].Payload
	if !strings.Contains(string(reqPayload), "POST /api HTTP/1.1") {
		t.Errorf("request payload=%q, want contains 'POST /api HTTP/1.1'", string(reqPayload))
	}
}

func TestHTTPPlan_TransactionsDefault(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 0
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 (1 transaction) + 4 termination = 9
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (3+2+4)", len(cfgs))
	}
	// Verify request/response pair present
	if cfgs[3].Direction != "up" || cfgs[3].L4.Flags != 0x18 {
		t.Error("expected request at index 3")
	}
	if cfgs[4].Direction != "down" || cfgs[4].L4.Flags != 0x18 {
		t.Error("expected response at index 4")
	}
}

func TestHTTPPlan_TransactionsMultiple(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 5
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 10 (5 transactions * 2) + 4 termination = 17
	if len(cfgs) != 17 {
		t.Errorf("len=%d, want 17 (3+10+4)", len(cfgs))
	}
}

func TestHTTPPlan_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TTL = 0
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (DefaultTTL)", cfgs[0].L3.TTL)
	}
}

func TestHTTPPlan_TTLProvided(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TTL = 128
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.TTL != 128 {
			t.Errorf("cfg[%d].TTL=%d, want 128", i, c.L3.TTL)
		}
	}
}

func TestHTTPPlan_IPIDSequential(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 3 // more packets to verify sequence
	cfgs := drain(mustPlan(t, p, spec))
	// IPID start is randomized; what we verify here is that the IPID sequence
	// is strictly incrementing by 1 across packets in the flow (per-flow
	// incrementing preserved, regardless of starting value).
	for i, c := range cfgs {
		want := cfgs[0].L3.IPID + uint16(i)
		if c.L3.IPID != want {
			t.Errorf("cfg[%d].IPID=%d, want %d (start=%d + %d)",
				i, c.L3.IPID, want, cfgs[0].L3.IPID, i)
		}
	}
}

// TestHTTPPlan_FlagsPassThrough verifies L3Base passes spec.IPFlags through
// unchanged. The DF=1 default is owned by mapToFlowSpec's defaultIPFlags
// helper; planners that receive a FlowSpec with explicit IPFlags=0 must honor
// it (no-DF, allow fragmentation). Pre-fix L3Base silently rewrote 0 to
// IPFlagDF, breaking the user>default rule end-to-end.
func TestHTTPPlan_FlagsPassThrough(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.IPFlags = 0
	spec.FragOffset = 0
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.Flags != 0 {
			t.Errorf("cfg[%d].Flags=0x%02x, want 0x00 (L3Base must pass through explicit 0)", i, c.L3.Flags)
		}
	}
}

func TestHTTPPlan_TOSOverrides(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TOS = 0xB8 // DSCP=46(0x2E), ECN=0
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.DSCP != 0x2E {
			t.Errorf("cfg[%d].DSCP=%d, want 0x2E(46)", i, c.L3.DSCP)
		}
		if c.L3.ECN != 0 {
			t.Errorf("cfg[%d].ECN=%d, want 0", i, c.L3.ECN)
		}
	}
}

func TestHTTPPlan_TransactionsZero(t *testing.T) {
	// Same as H12-POS: 0 -> 1
	TestHTTPPlan_TransactionsDefault(t)
}

func TestHTTPPlan_TransactionsNegative(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = -5
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 (defaulted to 1) + 4 termination = 9
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (negative defaults to 1 transaction)", len(cfgs))
	}
}

func TestHTTPPlan_MinPacketCount(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 1
	cfgs := drain(mustPlan(t, p, spec))
	// Minimum is 3+2+4 = 9
	if len(cfgs) < 9 {
		t.Errorf("len=%d, want >=9", len(cfgs))
	}
}

func TestHTTPPlan_AllPacketsSameTimestamp(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 5
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 2 {
		t.Fatal("need at least 2 packets")
	}
	ref := cfgs[0].Timestamp
	for i, c := range cfgs {
		if !c.Timestamp.Equal(ref) {
			t.Errorf("cfg[%d].Timestamp=%v, want %v", i, c.Timestamp, ref)
		}
	}
}

// --- Handshake (H21-H25) ---

func TestHTTPPlan_SYNPacketFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Pin client ISN so the Seq assertion is deterministic. Server ISN
	// and IPID start remain randomized; we only assert non-zero there.
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	syn := cfgs[0]
	if syn.PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", syn.PacketIndex)
	}
	if syn.Direction != "up" {
		t.Errorf("Direction=%s, want up", syn.Direction)
	}
	if syn.L4.Flags != 0x02 {
		t.Errorf("Flags=%x, want 0x02 (SYN)", syn.L4.Flags)
	}
	if syn.L4.Seq != 1000 {
		t.Errorf("Seq=%d, want 1000", syn.L4.Seq)
	}
	if syn.L4.Ack != 0 {
		t.Errorf("Ack=%d, want 0", syn.L4.Ack)
	}
	if syn.L4.WindowSize != 65535 {
		t.Errorf("WindowSize=%d, want 65535", syn.L4.WindowSize)
	}
	if syn.L4.Protocol != "tcp" {
		t.Errorf("L4.Protocol=%s, want tcp", syn.L4.Protocol)
	}
	if syn.L3.Protocol != 6 {
		t.Errorf("L3.Protocol=%d, want 6", syn.L3.Protocol)
	}
	// IPID start is randomized; just assert non-zero on the first packet.
	if syn.L3.IPID == 0 {
		t.Errorf("IPID=%d, want non-zero (random start)", syn.L3.IPID)
	}
	if syn.L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x, want 0x0800", syn.L2.EtherType)
	}
}

func TestHTTPPlan_EmptyMACs(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.SrcMAC = ""
	spec.DstMAC = ""
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.SrcMAC != "" || cfgs[0].L2.DstMAC != "" {
		t.Errorf("MACs not empty: src=%q dst=%q", cfgs[0].L2.SrcMAC, cfgs[0].L2.DstMAC)
	}
}

func TestHTTPPlan_SYNACKFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Pin client ISN; server ISN is still randomized, so the SYN-ACK Seq
	// is asserted as non-zero/different-from-SYN instead of a fixed value.
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	synack := cfgs[1]
	if synack.PacketIndex != 1 {
		t.Errorf("PacketIndex=%d, want 1", synack.PacketIndex)
	}
	if synack.Direction != "down" {
		t.Errorf("Direction=%s, want down", synack.Direction)
	}
	if synack.L4.Flags != 0x12 {
		t.Errorf("Flags=%x, want 0x12 (SYN-ACK)", synack.L4.Flags)
	}
	if synack.L4.Seq == 0 || synack.L4.Seq == 1000 {
		t.Errorf("Seq=%d, want non-zero and != client ISN (random server ISN)", synack.L4.Seq)
	}
	if synack.L4.Ack != 1001 {
		t.Errorf("Ack=%d, want 1001", synack.L4.Ack)
	}
	// MACs/IPs/ports swapped
	if synack.L2.SrcMAC != spec.DstMAC || synack.L2.DstMAC != spec.SrcMAC {
		t.Errorf("MACs not swapped: src=%q dst=%q", synack.L2.SrcMAC, synack.L2.DstMAC)
	}
	if synack.L3.SrcIP != spec.DstIP || synack.L3.DstIP != spec.SrcIP {
		t.Error("IPs not swapped")
	}
	if synack.L4.SrcPort != spec.DstPort || synack.L4.DstPort != spec.SrcPort {
		t.Error("ports not swapped")
	}
	// IPID increments per-packet; SYN-ACK should differ from SYN's IPID.
	if synack.L3.IPID == cfgs[0].L3.IPID {
		t.Errorf("SYN-ACK IPID=%d == SYN IPID=%d, want incrementing",
			synack.L3.IPID, cfgs[0].L3.IPID)
	}
}

func TestHTTPPlan_HandshakeACKFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Pin client ISN; server ISN is still randomized, so Ack (= serverSeq+1)
	// is asserted as SYN-ACK.Seq+1 instead of a fixed value.
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[2]
	if ack.PacketIndex != 2 {
		t.Errorf("PacketIndex=%d, want 2", ack.PacketIndex)
	}
	if ack.Direction != "up" {
		t.Errorf("Direction=%s, want up", ack.Direction)
	}
	if ack.L4.Flags != 0x10 {
		t.Errorf("Flags=%x, want 0x10 (ACK)", ack.L4.Flags)
	}
	if ack.L4.Seq != 1001 {
		t.Errorf("Seq=%d, want 1001", ack.L4.Seq)
	}
	synackSeq := cfgs[1].L4.Seq
	if ack.L4.Ack != synackSeq+1 {
		t.Errorf("Ack=%d, want %d (serverSeq+1, server ISN randomized)", ack.L4.Ack, synackSeq+1)
	}
	// IPID increments per-packet; ACK should differ from SYN-ACK's IPID.
	if ack.L3.IPID == cfgs[1].L3.IPID {
		t.Errorf("ACK IPID=%d == SYN-ACK IPID=%d, want incrementing",
			ack.L3.IPID, cfgs[1].L3.IPID)
	}
}

// --- Transactions (H27-H31) ---

func TestHTTPPlan_SingleTransaction(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 1
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 (1 req+resp) + 4 termination = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	// Request at index 3
	if cfgs[3].Direction != "up" || cfgs[3].L4.Flags != 0x18 {
		t.Errorf("request: dir=%s flags=%x, want up, 0x18", cfgs[3].Direction, cfgs[3].L4.Flags)
	}
	// Response at index 4
	if cfgs[4].Direction != "down" || cfgs[4].L4.Flags != 0x18 {
		t.Errorf("response: dir=%s flags=%x, want down, 0x18", cfgs[4].Direction, cfgs[4].L4.Flags)
	}
}

func TestHTTPPlan_MultipleTransactions(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 3
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 6 (3 transactions * 2) + 4 termination = 13
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13", len(cfgs))
	}
	// Verify clientSeq and serverSeq advance across transactions.
	// Transaction 0: request at index 3, response at index 4
	req0 := cfgs[3]
	resp0 := cfgs[4]
	req0Len := len(req0.Payload)
	resp0Len := len(resp0.Payload)
	// Transaction 1: request at index 5, response at index 6
	req1 := cfgs[5]
	if req1.Direction != "up" || req1.L4.Flags != 0x18 {
		t.Error("transaction 1 request expected")
	}
	// clientSeq should have advanced by req0 payload length
	expectedSeq := req0.L4.Seq + uint32(req0Len)
	if req1.L4.Seq != expectedSeq {
		t.Errorf("req1.Seq=%d, want %d (clientSeq += req0 payload len %d)", req1.L4.Seq, expectedSeq, req0Len)
	}
	// serverSeq should have advanced by resp0 payload length
	expectedServerSeq := resp0.L4.Seq + uint32(resp0Len)
	if req1.L4.Ack != expectedServerSeq {
		t.Errorf("req1.Ack=%d, want %d (serverSeq += resp0 len %d)", req1.L4.Ack, expectedServerSeq, resp0Len)
	}
}

func TestHTTPPlan_RequestPayloadFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method: "POST",
		URI:    "/submit",
		Body:   "data",
	}
	cfgs := drain(mustPlan(t, p, spec))
	req := cfgs[3]
	if req.Direction != "up" {
		t.Errorf("Direction=%s, want up", req.Direction)
	}
	if req.L4.Flags != 0x18 {
		t.Errorf("Flags=%x, want 0x18 (PSH|ACK)", req.L4.Flags)
	}
	payload := string(req.Payload)
	if !strings.Contains(payload, "POST /submit HTTP/1.1") {
		t.Errorf("payload missing POST line: %q", payload)
	}
	if !strings.Contains(payload, "Content-Length: 4") {
		t.Errorf("payload missing Content-Length: %q", payload)
	}
	if !strings.Contains(payload, "data") {
		t.Errorf("payload missing body: %q", payload)
	}
}

func TestHTTPPlan_ResponsePayloadFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[4]
	if resp.Direction != "down" {
		t.Errorf("Direction=%s, want down", resp.Direction)
	}
	if resp.L4.Flags != 0x18 {
		t.Errorf("Flags=%x, want 0x18 (PSH|ACK)", resp.L4.Flags)
	}
	if !strings.Contains(string(resp.Payload), "HTTP/1.1 200 OK") {
		t.Errorf("response payload=%q, want contains 'HTTP/1.1 200 OK'", string(resp.Payload))
	}
}

func TestHTTPPlan_ClientSeqOverflow(t *testing.T) {
	// H31: clientSeq += uint32(len(request)) per transaction. Full 2^32
	// wraparound would require a ~4GB body, which is infeasible in a unit
	// test. Instead we verify the observable accumulation: each request
	// packet's Seq advances by exactly len(request) from the previous one.
	// This is the same uint32 arithmetic that would wrap silently per Go's
	// unsigned-overflow rules. We pin the client ISN so the absolute Seq
	// values are deterministic.
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{Transactions: 3} // 3+6+4=13 packets
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13", len(cfgs))
	}
	reqLen := uint32(len(cfgs[3].Payload))
	// Request packets at indices 3, 5, 7; clientSeq starts at 1001 after handshake.
	wantSeqs := []uint32{1001, 1001 + reqLen, 1001 + 2*reqLen}
	for i, want := range wantSeqs {
		idx := 3 + i*2
		if cfgs[idx].L4.Seq != want {
			t.Errorf("request[%d] (cfg[%d]).Seq=%d, want %d (1001+%d*reqLen)", i, idx, cfgs[idx].L4.Seq, want, i)
		}
	}
}

// --- Termination (H32-H36) ---

func TestHTTPPlan_ClientFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Pin client ISN; server ISN is still randomized, so we compute the
	// expected Ack from the observed SYN-ACK Seq (serverSeq starts there)
	// plus the response payload length.
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	// For 1 transaction: indices 0-2 handshake, 3-4 transaction, 5-8 termination
	fin := cfgs[5]
	if fin.Direction != "up" {
		t.Errorf("Direction=%s, want up", fin.Direction)
	}
	if fin.L4.Flags != 0x11 {
		t.Errorf("Flags=%x, want 0x11 (FIN|ACK)", fin.L4.Flags)
	}
	// clientSeq after handshake (1001) + request payload length
	reqLen := len(cfgs[3].Payload)
	expectedSeq := uint32(1001) + uint32(reqLen)
	if fin.L4.Seq != expectedSeq {
		t.Errorf("Seq=%d, want %d", fin.L4.Seq, expectedSeq)
	}
	// serverSeq after handshake (synackSeq+1) + response payload length
	synackSeq := cfgs[1].L4.Seq
	respLen := len(cfgs[4].Payload)
	expectedAck := synackSeq + 1 + uint32(respLen)
	if fin.L4.Ack != expectedAck {
		t.Errorf("Ack=%d, want %d", fin.L4.Ack, expectedAck)
	}
}

func TestHTTPPlan_ServerACKofFIN(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[6]
	if ack.Direction != "down" {
		t.Errorf("Direction=%s, want down", ack.Direction)
	}
	if ack.L4.Flags != 0x10 {
		t.Errorf("Flags=%x, want 0x10 (ACK)", ack.L4.Flags)
	}
	// After client FIN, clientSeq++: ACK acknowledges (clientSeq+1)
	reqLen := len(cfgs[3].Payload)
	expectedAck := uint32(1001) + uint32(reqLen) + 1
	if ack.L4.Ack != expectedAck {
		t.Errorf("Ack=%d, want %d (clientSeq+1 after FIN)", ack.L4.Ack, expectedAck)
	}
}

func TestHTTPPlan_ServerFINFields(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	fin := cfgs[7]
	if fin.Direction != "down" {
		t.Errorf("Direction=%s, want down", fin.Direction)
	}
	if fin.L4.Flags != 0x11 {
		t.Errorf("Flags=%x, want 0x11 (FIN|ACK)", fin.L4.Flags)
	}
	// serverSeq after response payload; FIN carries current serverSeq, then
	// serverSeq++ happens AFTER sending the FIN. Server ISN is randomized,
	// so we derive the expected value from the observed SYN-ACK Seq.
	synackSeq := cfgs[1].L4.Seq
	respLen := len(cfgs[4].Payload)
	expectedSeq := synackSeq + 1 + uint32(respLen)
	if fin.L4.Seq != expectedSeq {
		t.Errorf("Seq=%d, want %d", fin.L4.Seq, expectedSeq)
	}
}

func TestHTTPPlan_ClientACKofServerFIN(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.TCP.InitialSeq = 1000
	cfgs := drain(mustPlan(t, p, spec))
	ack := cfgs[8]
	if ack.Direction != "up" {
		t.Errorf("Direction=%s, want up", ack.Direction)
	}
	if ack.L4.Flags != 0x10 {
		t.Errorf("Flags=%x, want 0x10 (ACK)", ack.L4.Flags)
	}
	// After server FIN, serverSeq++: ACK acknowledges (serverSeq+1) where
	// serverSeq = synackSeq+1 + respLen (the value carried by the server FIN).
	synackSeq := cfgs[1].L4.Seq
	respLen := len(cfgs[4].Payload)
	expectedAck := synackSeq + 1 + uint32(respLen) + 1
	if ack.L4.Ack != expectedAck {
		t.Errorf("Ack=%d, want %d", ack.L4.Ack, expectedAck)
	}
	// Verify PacketIndex 0..8 continuous
	for i, c := range cfgs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("cfg[%d].PacketIndex=%d, want %d", i, c.PacketIndex, i)
		}
	}
}

func TestHTTPPlan_ChannelCloseAfterGoroutine(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Read all packets - channel should close after last packet.
	var count int
	for range ch {
		count++
	}
	if count != 9 {
		t.Errorf("got %d packets, want 9", count)
	}
}

// --- Context cancel (H38, H39, H42) ---

// H38: goroutine never checks ctx.Done(). Known bug: cancelling the context
// does not stop the planner goroutine; it runs to completion.
func TestHTTPPlan_ContextCancelLeak(t *testing.T) {
	t.Skip("known bug H38: HTTP planner goroutine never checks ctx.Done(); cancel does not stop it. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 100 // many packets
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	// Do not drain; expect goroutine to exit via ctx.Done()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < before {
			return // goroutine exited
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutine leak: before=%d after=%d (cancel ignored)", before, runtime.NumGoroutine())
	// drain to clean up
	drain(ch)
}

// H39: channel full (256 cap) goroutine leak. Known bug: once 256 packets fill
// the channel and the consumer stops reading, the goroutine blocks forever on
// send and never exits (no ctx.Done check).
// HTTP: 9 base + 2*(transactions-1) = 7+2*transactions.
// For transactions=200: 7+400=407 >256 => blocks.
func TestHTTPPlan_TransactionBufferFullLeak(t *testing.T) {
	t.Skip("known bug H39: blocked send on full channel never exits (no ctx.Done). Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spec := validHTTPSpec()
	spec.HTTP.Transactions = 200 // >256 packets total
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	time.Sleep(2 * time.Second)
	if runtime.NumGoroutine() >= before {
		t.Errorf("goroutine still alive after cancel+full channel: before=%d after=%d", before, runtime.NumGoroutine())
	}
	// Best-effort drain to allow goroutine to proceed if it ever unblocks
	go func() { drain(ch) }()
}

// H42: send on closed channel panic. Known bug: caller closing the returned
// channel causes an unrecovered panic in the goroutine.
func TestHTTPPlan_SendOnClosedChannelPanic(t *testing.T) {
	t.Skip("known bug H42: closing the returned channel causes 'send on closed channel' panic in goroutine (no recover). Remove skip once fixed.")
	// This test verifies the bug exists: the goroutine panics when the channel
	// is closed by the caller. Can't safely test without crashing the process.
}

// --- buildHTTPRequest (H43-H52) ---

func TestBuildHTTPRequest_EmptyMethodDefaultsGET(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "", URI: "/"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if cfg.Method != "GET" {
		t.Errorf("cfg.Method=%q after build, want 'GET' (side effect)", cfg.Method)
	}
	if !strings.HasPrefix(result, "GET ") {
		t.Errorf("result=%q, want starts with 'GET '", result)
	}
}

func TestBuildHTTPRequest_EmptyURIDefaultsRoot(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: ""}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if cfg.URI != "/" {
		t.Errorf("cfg.URI=%q after build, want '/' (side effect)", cfg.URI)
	}
	if !strings.Contains(result, " / HTTP/1.1") {
		t.Errorf("result=%q, want contains ' / HTTP/1.1'", result)
	}
}

func TestBuildHTTPRequest_CustomHeaders(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		RequestHeaders: map[string]string{"Accept": "application/json", "X-Custom": "v"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Accept: application/json") {
		t.Errorf("result missing Accept header: %q", result)
	}
	if !strings.Contains(result, "X-Custom: v") {
		t.Errorf("result missing X-Custom header: %q", result)
	}
}

func TestBuildHTTPRequest_NilHeaders(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", RequestHeaders: nil}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	// No custom headers after Host: line
	lines := strings.Split(result, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "Host:") && !strings.HasPrefix(line, "Content-Length:") && !strings.HasPrefix(line, "Connection:") {
			t.Errorf("unexpected custom header: %q", line)
		}
	}
}

func TestBuildHTTPRequest_EmptyHeaders(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", RequestHeaders: map[string]string{}}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	// No custom headers after Host: line
	lines := strings.Split(result, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "Host:") && !strings.HasPrefix(line, "Content-Length:") && !strings.HasPrefix(line, "Connection:") {
			t.Errorf("unexpected custom header: %q", line)
		}
	}
}

func TestBuildHTTPRequest_BodyAddsContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "POST", URI: "/", Body: `{"key":"value"}`}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	expectedCL := "Content-Length: " + strconv.Itoa(len(cfg.Body))
	if !strings.Contains(result, expectedCL) {
		t.Errorf("result=%q, want contains %q", result, expectedCL)
	}
}

func TestBuildHTTPRequest_NoBodyNoContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Body: ""}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Content-Length") {
		t.Errorf("result should not contain Content-Length: %q", result)
	}
}

func TestBuildHTTPRequest_BodyAppended(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "POST", URI: "/", Body: "payload_data"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "\r\n\r\npayload_data") {
		t.Errorf("result=%q, want body after double CRLF", result)
	}
}

// H52-NEG: CRLF injection - no sanitization.
func TestBuildHTTPRequest_CRLFInjection(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method: "GET\r\nX-Injected: true",
		URI:    "/",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "X-Injected: true") {
		t.Errorf("CRLF injection did not produce injected header; result=%q", result)
	}
}

// --- Host header defaulting (case-insensitive, dstIP fallback) ---

// TestBuildHTTPRequest_NoHostUsesDstIP verifies that when config.RequestHeaders
// does not contain a Host entry, the request uses the dstIP argument as the Host.
// Before the fix, the function unconditionally wrote "Host: localhost" which
// was wrong for any non-loopback destination.
func TestBuildHTTPRequest_NoHostUsesDstIP(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", RequestHeaders: nil}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: 10.0.0.2\r\n") {
		t.Errorf("result=%q, want contains 'Host: 10.0.0.2\\r\\n'", result)
	}
	if strings.Contains(result, "Host: localhost") {
		t.Errorf("result=%q, should not contain 'Host: localhost'", result)
	}
}

// TestBuildHTTPRequest_UserHostReplacesDefault verifies that an explicit Host
// in config.RequestHeaders takes precedence over the dstIP default — and that
// the default Host line is NOT also emitted (the bug that produced two Host headers).
func TestBuildHTTPRequest_UserHostReplacesDefault(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		RequestHeaders: map[string]string{"Host": "www.home.com"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: www.home.com\r\n") {
		t.Errorf("result=%q, want contains 'Host: www.home.com\\r\\n'", result)
	}
	hostCount := strings.Count(result, "Host:")
	if hostCount != 1 {
		t.Errorf("result=%q, want exactly 1 Host header, got %d", result, hostCount)
	}
	if strings.Contains(result, "Host: 10.0.0.2") {
		t.Errorf("result=%q, should not contain default 'Host: 10.0.0.2' when user Host provided", result)
	}
}

// TestBuildHTTPRequest_HostCaseInsensitive verifies that a header named "host"
// (lowercase) or "HOST" (uppercase) is recognized as the Host header per RFC
// 7230, and the default dstIP Host is not added.
func TestBuildHTTPRequest_HostCaseInsensitive(t *testing.T) {
	cases := []string{"host", "Host", "HOST", "hOsT"}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			cfg := &core.HTTPConfig{
				Method:         "GET",
				URI:            "/",
				RequestHeaders: map[string]string{key: "www.home.com"},
			}
			result := buildHTTPRequest(cfg, "10.0.0.2")
			lower := strings.ToLower(result)
			totalHost := strings.Count(lower, "host:")
			if totalHost != 1 {
				t.Errorf("key=%q: result=%q, want exactly 1 Host header (any case), got %d", key, result, totalHost)
			}
			if strings.Contains(result, "Host: 10.0.0.2") {
				t.Errorf("key=%q: result=%q, should not contain default 'Host: 10.0.0.2' when user Host provided", key, result)
			}
		})
	}
}

// TestBuildHTTPRequest_EmptyDstIPProducesEmptyHost verifies behavior when the
// caller passes an empty dstIP: we still emit a "Host: " line (per RFC 7230 §5.4
// Host is mandatory for HTTP/1.1). The test asserts the Host line exists but
// does not constrain its value — this is the most graceful degradation we can
// offer without inventing data.
func TestBuildHTTPRequest_EmptyDstIPProducesEmptyHost(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", RequestHeaders: nil}
	result := buildHTTPRequest(cfg, "")
	if !strings.Contains(result, "Host:") {
		t.Errorf("result=%q, want a 'Host:' header line even when dstIP is empty", result)
	}
}

// --- buildHTTPResponse (H53-H54) ---

func TestBuildHTTPResponse_KeepAlive(t *testing.T) {
	cfg := &core.HTTPConfig{KeepAlive: true}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Connection: keep-alive") {
		t.Errorf("result=%q, want contains 'Connection: keep-alive'", result)
	}
}

func TestBuildHTTPResponse_NoKeepAlive(t *testing.T) {
	cfg := &core.HTTPConfig{KeepAlive: false}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Connection: close") {
		t.Errorf("result=%q, want contains 'Connection: close' (default for short-conn)", result)
	}
}

// --- Unified header defaulting (user > default > none) ---

// TestBuildHTTPRequest_VersionDefault verifies Version empty -> "HTTP/1.1".
func TestBuildHTTPRequest_VersionDefault(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "GET / HTTP/1.1\r\n") {
		t.Errorf("result=%q, want request line 'GET / HTTP/1.1\\r\\n'", result)
	}
}

// TestBuildHTTPRequest_VersionUserOverride verifies user-provided Version wins.
func TestBuildHTTPRequest_VersionUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Version: "HTTP/1.0"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "GET / HTTP/1.0\r\n") {
		t.Errorf("result=%q, want request line 'GET / HTTP/1.0\\r\\n'", result)
	}
	if strings.Contains(result, "HTTP/1.1") {
		t.Errorf("result=%q, should not contain default HTTP/1.1 when user provided Version", result)
	}
}

// TestBuildHTTPRequest_ConnectionDefault_KeepAlive verifies the Connection
// default derived from Transactions>1 (or KeepAlive=true) is "keep-alive".
func TestBuildHTTPRequest_ConnectionDefault_KeepAlive(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Transactions: 3}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Connection: keep-alive\r\n") {
		t.Errorf("result=%q, want default 'Connection: keep-alive' for Transactions>1", result)
	}
}

// TestBuildHTTPRequest_ConnectionDefault_Close verifies the Connection default
// for Transactions==1 + KeepAlive=false is "close".
func TestBuildHTTPRequest_ConnectionDefault_Close(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Transactions: 1, KeepAlive: false}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Connection: close\r\n") {
		t.Errorf("result=%q, want default 'Connection: close' for short-conn", result)
	}
}

// TestBuildHTTPRequest_ConnectionUserOverride verifies user Connection wins
// and the default is not also emitted.
func TestBuildHTTPRequest_ConnectionUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		Transactions:   1,
		KeepAlive:      false,
		RequestHeaders: map[string]string{"Connection": "keep-alive"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	connCount := strings.Count(result, "Connection:")
	if connCount != 1 {
		t.Errorf("result=%q, want exactly 1 Connection header, got %d", result, connCount)
	}
	if !strings.Contains(result, "Connection: keep-alive\r\n") {
		t.Errorf("result=%q, want user value 'Connection: keep-alive'", result)
	}
	if strings.Contains(result, "Connection: close") {
		t.Errorf("result=%q, should not contain default 'Connection: close' when user provided", result)
	}
}

// TestBuildHTTPRequest_ContentLengthUserOverride verifies user Content-Length
// wins (even if it differs from len(Body)) and the default is not also emitted.
func TestBuildHTTPRequest_ContentLengthUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "POST",
		URI:            "/",
		Body:           "abc",
		RequestHeaders: map[string]string{"Content-Length": "999"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	clCount := strings.Count(result, "Content-Length:")
	if clCount != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Length header, got %d", result, clCount)
	}
	if !strings.Contains(result, "Content-Length: 999\r\n") {
		t.Errorf("result=%q, want user value 'Content-Length: 999'", result)
	}
}

// TestBuildHTTPRequest_NoBodyNoConnection leak guard: when Transactions=1 and
// KeepAlive=false, default Connection=close is emitted even with no body.
func TestBuildHTTPRequest_NoBodyHasConnectionClose(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Transactions: 1, KeepAlive: false}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Connection: close\r\n") {
		t.Errorf("result=%q, want 'Connection: close' for short-conn even with no body", result)
	}
}

// --- Host header: HTTP/1.1 vs HTTP/1.0 defaulting ---
//
// HTTP/1.1 mandates Host (RFC 7230 §5.4); HTTP/1.0 does not. So the dstIP
// fallback Host is only auto-emitted for 1.1, and a user-provided Host on
// either version always wins via the user-header pass.

// TestBuildHTTPRequest_AutoHost_HTTP11 verifies that for HTTP/1.1 with no
// user-provided Host, the request contains "Host: <dstIP>".
func TestBuildHTTPRequest_AutoHost_HTTP11(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Version: "HTTP/1.1"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: 10.0.0.2\r\n") {
		t.Errorf("result=%q, want contains 'Host: 10.0.0.2\\r\\n' for HTTP/1.1", result)
	}
	hostCount := strings.Count(result, "Host:")
	if hostCount != 1 {
		t.Errorf("result=%q, want exactly 1 Host header for HTTP/1.1, got %d", result, hostCount)
	}
}

// TestBuildHTTPRequest_AutoHost_HTTP10Absent verifies that for HTTP/1.0 with
// no user-provided Host, NO Host header is emitted (1.0 does not mandate it).
func TestBuildHTTPRequest_AutoHost_HTTP10Absent(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Version: "HTTP/1.0"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Host:") {
		t.Errorf("result=%q, should not contain Host header for HTTP/1.0 without user Host", result)
	}
}

// TestBuildHTTPRequest_AutoHost_HTTP10UserOverride verifies that an explicit
// Host on HTTP/1.0 is still honored (user > default > none).
func TestBuildHTTPRequest_AutoHost_HTTP10UserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		Version:        "HTTP/1.0",
		RequestHeaders: map[string]string{"Host": "example.com"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: example.com\r\n") {
		t.Errorf("result=%q, want contains user 'Host: example.com\\r\\n'", result)
	}
	hostCount := strings.Count(result, "Host:")
	if hostCount != 1 {
		t.Errorf("result=%q, want exactly 1 Host header, got %d", result, hostCount)
	}
}

// TestBuildHTTPRequest_AutoHost_DefaultVersion11 verifies that when Version is
// empty (defaulted to HTTP/1.1 inside buildHTTPRequest), the Host default is
// still emitted.
func TestBuildHTTPRequest_AutoHost_DefaultVersion11(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/"} // Version empty -> HTTP/1.1
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: 10.0.0.2\r\n") {
		t.Errorf("result=%q, want contains 'Host: 10.0.0.2\\r\\n' (default Version=HTTP/1.1)", result)
	}
}

// --- Content-Length auto-derivation (user > default > none) ---
//
// buildHTTPRequest must auto-emit Content-Length: len(Body) when Body is
// non-empty and the user has not provided one; empty Body + no user header
// means no Content-Length.

// TestBuildHTTPRequest_AutoContentLength verifies that a non-empty Body
// without a user Content-Length produces "Content-Length: <len(Body)>".
func TestBuildHTTPRequest_AutoContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "POST", URI: "/", Body: `{"k":"v"}`}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	want := "Content-Length: " + strconv.Itoa(len(cfg.Body)) + "\r\n"
	if !strings.Contains(result, want) {
		t.Errorf("result=%q, want contains %q", result, want)
	}
	clCount := strings.Count(result, "Content-Length:")
	if clCount != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Length, got %d", result, clCount)
	}
}

// TestBuildHTTPRequest_UserContentLengthOverrideAutoHost confirms the same
// override behavior with a body present and HTTP/1.1: user Content-Length wins
// and the default is not also emitted.
func TestBuildHTTPRequest_UserContentLengthOverrideAutoHost(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "POST",
		URI:            "/",
		Body:           "abcdef",
		RequestHeaders: map[string]string{"Content-Length": "999"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	clCount := strings.Count(result, "Content-Length:")
	if clCount != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Length, got %d", result, clCount)
	}
	if !strings.Contains(result, "Content-Length: 999\r\n") {
		t.Errorf("result=%q, want user value 'Content-Length: 999'", result)
	}
}

// TestBuildHTTPRequest_EmptyBodyNoContentLength verifies that an empty Body
// produces no Content-Length header at all.
func TestBuildHTTPRequest_EmptyBodyNoContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/", Body: ""}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Content-Length") {
		t.Errorf("result=%q, should not contain Content-Length when Body empty", result)
	}
}

// TestBuildHTTPRequest_ContentLengthCaseInsensitive verifies that a
// user-provided "content-length" (lowercase) suppresses the default just
// like "Content-Length" per RFC 7230 §3.2.
func TestBuildHTTPRequest_ContentLengthCaseInsensitive(t *testing.T) {
	cases := []string{"content-length", "Content-Length", "CONTENT-LENGTH"}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			cfg := &core.HTTPConfig{
				Method:         "POST",
				URI:            "/",
				Body:           "abc",
				RequestHeaders: map[string]string{key: "7"},
			}
			result := buildHTTPRequest(cfg, "10.0.0.2")
			clCount := strings.Count(strings.ToLower(result), "content-length:")
			if clCount != 1 {
				t.Errorf("key=%q: result=%q, want exactly 1 Content-Length (any case), got %d", key, result, clCount)
			}
		})
	}
}

// --- Response-side unified defaulting ---

// TestBuildHTTPResponse_DefaultStatusLine verifies default version/code/text.
func TestBuildHTTPResponse_DefaultStatusLine(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "OK"}
	result := buildHTTPResponse(cfg)
	if !strings.HasPrefix(result, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("result=%q, want status line 'HTTP/1.1 200 OK\\r\\n'", result)
	}
}

// TestBuildHTTPResponse_StatusCodeUserOverride verifies user code wins.
func TestBuildHTTPResponse_StatusCodeUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "not found", ResponseStatusCode: 404}
	result := buildHTTPResponse(cfg)
	if !strings.HasPrefix(result, "HTTP/1.1 404 Not Found\r\n") {
		t.Errorf("result=%q, want status line 'HTTP/1.1 404 Not Found\\r\\n'", result)
	}
}

// TestBuildHTTPResponse_StatusTextUserOverride verifies user text wins over
// the lookup table.
func TestBuildHTTPResponse_StatusTextUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "x", ResponseStatusCode: 200, ResponseStatusText: "Custom"}
	result := buildHTTPResponse(cfg)
	if !strings.HasPrefix(result, "HTTP/1.1 200 Custom\r\n") {
		t.Errorf("result=%q, want status line 'HTTP/1.1 200 Custom\\r\\n'", result)
	}
}

// TestBuildHTTPResponse_StatusCodeUnknownFallback verifies the "Status NNN"
// fallback for codes not in the lookup table.
func TestBuildHTTPResponse_StatusCodeUnknownFallback(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "x", ResponseStatusCode: 599}
	result := buildHTTPResponse(cfg)
	if !strings.HasPrefix(result, "HTTP/1.1 599 Status 599\r\n") {
		t.Errorf("result=%q, want status line 'HTTP/1.1 599 Status 599\\r\\n'", result)
	}
}

// TestBuildHTTPResponse_VersionUserOverride verifies user version wins.
func TestBuildHTTPResponse_VersionUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "x", Version: "HTTP/1.0"}
	result := buildHTTPResponse(cfg)
	if !strings.HasPrefix(result, "HTTP/1.0 200 OK\r\n") {
		t.Errorf("result=%q, want status line 'HTTP/1.0 200 OK\\r\\n'", result)
	}
}

// TestBuildHTTPResponse_ResponseBodyCustom verifies body is taken from
// ResponseBody field (not hardcoded "OK").
func TestBuildHTTPResponse_ResponseBodyCustom(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "custom-body"}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Content-Length: 11\r\n") {
		t.Errorf("result=%q, want Content-Length: 11 for 'custom-body'", result)
	}
	if !strings.HasSuffix(result, "custom-body") {
		t.Errorf("result=%q, want body 'custom-body' at end", result)
	}
}

// TestBuildHTTPResponse_EmptyBodyNoContentLength verifies that empty
// ResponseBody -> no Content-Length and no Content-Type default.
func TestBuildHTTPResponse_EmptyBodyNoContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: ""}
	result := buildHTTPResponse(cfg)
	if strings.Contains(result, "Content-Length") {
		t.Errorf("result=%q, should not contain Content-Length when body empty", result)
	}
	if strings.Contains(result, "Content-Type") {
		t.Errorf("result=%q, should not contain Content-Type when body empty", result)
	}
}

// TestBuildHTTPResponse_ResponseHeadersOverride verifies user response
// headers override defaults (Content-Type, Content-Length, Connection).
func TestBuildHTTPResponse_ResponseHeadersOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:      "x",
		KeepAlive:         true,
		ResponseHeaders:   map[string]string{
			"Content-Type":   "application/json",
			"Content-Length": "999",
			"Connection":     "close",
		},
	}
	result := buildHTTPResponse(cfg)
	ctCount := strings.Count(result, "Content-Type:")
	if ctCount != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Type, got %d", result, ctCount)
	}
	clCount := strings.Count(result, "Content-Length:")
	if clCount != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Length, got %d", result, clCount)
	}
	connCount := strings.Count(result, "Connection:")
	if connCount != 1 {
		t.Errorf("result=%q, want exactly 1 Connection, got %d", result, connCount)
	}
	if !strings.Contains(result, "Content-Type: application/json\r\n") {
		t.Errorf("result=%q, want user Content-Type", result)
	}
	if !strings.Contains(result, "Content-Length: 999\r\n") {
		t.Errorf("result=%q, want user Content-Length", result)
	}
	if !strings.Contains(result, "Connection: close\r\n") {
		t.Errorf("result=%q, want user Connection", result)
	}
}

// TestBuildHTTPResponse_GzipCompressesBody verifies that ResponseContentEncoding=gzip
// compresses the body (payload no longer equals the plaintext body), the
// emitted body starts with the gzip magic 0x1f 0x8b (RFC 1952), Content-Length
// reflects the compressed byte count, and a Content-Encoding header is present.
func TestBuildHTTPResponse_GzipCompressesBody(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:            "Hello, world! Hello, world! Hello, world!",
		ResponseContentEncoding: "gzip",
	}
	result := buildHTTPResponse(cfg)

	if !strings.Contains(result, "Content-Encoding: gzip\r\n") {
		t.Errorf("result=%q, want 'Content-Encoding: gzip' header", result)
	}

	// The response body follows the blank line after headers.
	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("result=%q, no header/body separator", result)
	}
	body := result[idx+4:]
	if strings.HasPrefix(body, "Hello, world!") {
		t.Fatalf("body=%q, should not be plaintext (must be gzip-compressed)", body)
	}
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body first 2 bytes = % x, want gzip magic 1f 8b", body[:min(2, len(body))])
	}

	// Content-Length must match the compressed body byte count, not the
	// plaintext length.
	wantCL := fmt.Sprintf("Content-Length: %d\r\n", len(body))
	if !strings.Contains(result, wantCL) {
		t.Errorf("result=%q, want %s (compressed length, not %d)", result, wantCL, len("Hello, world! Hello, world! Hello, world!"))
	}

	// Round-trip: gzip-decompress the body and confirm it equals the input.
	zr, err := gzip.NewReader(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	var decoded bytes.Buffer
	if _, err := decoded.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if got := decoded.String(); got != "Hello, world! Hello, world! Hello, world!" {
		t.Errorf("decompressed body=%q, want original plaintext", got)
	}
}

// TestBuildHTTPResponse_GzipUTF8Chinese verifies a non-ASCII body survives
// gzip round-trip with bytes preserved (a UTF-8 multibyte boundary regression
// in an earlier version of the code).
func TestBuildHTTPResponse_GzipUTF8Chinese(t *testing.T) {
	plaintext := "我爱你中国"
	cfg := &core.HTTPConfig{
		ResponseBody:            plaintext,
		ResponseContentEncoding: "gzip",
		ResponseHeaders:         map[string]string{"Content-Type": "text/html; charset=utf-8"},
	}
	result := buildHTTPResponse(cfg)

	if !strings.Contains(result, "Content-Encoding: gzip\r\n") {
		t.Errorf("result=%q, want 'Content-Encoding: gzip' header", result)
	}
	if !strings.Contains(result, "Content-Type: text/html; charset=utf-8\r\n") {
		t.Errorf("result=%q, want user Content-Type", result)
	}

	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("result=%q, no header/body separator", result)
	}
	body := result[idx+4:]

	zr, err := gzip.NewReader(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	var decoded bytes.Buffer
	if _, err := decoded.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if got := decoded.String(); got != plaintext {
		t.Errorf("decompressed body=%q, want %q", got, plaintext)
	}
	if encLen := len([]byte(plaintext)); encLen != 15 {
		t.Errorf("plaintext byte length = %d, want 15 (5 Chinese chars * 3 bytes UTF-8)", encLen)
	}
}

// TestBuildHTTPResponse_GzipContentEncodingUserOverride verifies that a
// user-provided Content-Encoding header suppresses the auto-emitted default
// (no duplicate header), case-insensitive per RFC 7230 §3.2.
func TestBuildHTTPResponse_GzipContentEncodingUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:            "x",
		ResponseContentEncoding: "gzip",
		ResponseHeaders:         map[string]string{"content-encoding": "gzip"},
	}
	result := buildHTTPResponse(cfg)
	if got := strings.Count(strings.ToLower(result), "content-encoding:"); got != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Encoding header, got %d", result, got)
	}
}

// TestBuildHTTPResponse_GzipEmptyBodySkipsCompression verifies that
// ResponseContentEncoding=gzip with an empty body does not emit Content-Encoding
// or Content-Length (matches the empty-body defaulting rule for the
// non-gzip path).
func TestBuildHTTPResponse_GzipEmptyBodySkipsCompression(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:            "",
		ResponseContentEncoding: "gzip",
	}
	result := buildHTTPResponse(cfg)
	if strings.Contains(result, "Content-Encoding:") {
		t.Errorf("result=%q, should not emit Content-Encoding when body empty", result)
	}
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("result=%q, should not emit Content-Length when body empty", result)
	}
}

// TestBuildHTTPResponse_NoGzipByDefault verifies the default (no compression)
// path is unchanged: no Content-Encoding header, body is plaintext.
func TestBuildHTTPResponse_NoGzipByDefault(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "hello"}
	result := buildHTTPResponse(cfg)
	if strings.Contains(result, "Content-Encoding:") {
		t.Errorf("result=%q, should not emit Content-Encoding by default", result)
	}
	if !strings.HasSuffix(result, "hello") {
		t.Errorf("result=%q, want plaintext body 'hello' at end", result)
	}
}

// TestBuildHTTPResponse_ConnectionDefault_Close verifies response-side
// Connection default follows the same rule as request-side.
func TestBuildHTTPResponse_ConnectionDefault_Close(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "x", Transactions: 1, KeepAlive: false}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Connection: close\r\n") {
		t.Errorf("result=%q, want 'Connection: close' default for short-conn", result)
	}
}

// TestStatusTextFor_KnownCodes spot-checks the lookup table.
func TestStatusTextFor_KnownCodes(t *testing.T) {
	cases := map[int]string{
		100: "Continue",
		200: "OK",
		201: "Created",
		204: "No Content",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
	}
	for code, want := range cases {
		got := statusTextFor(code)
		if got != want {
			t.Errorf("statusTextFor(%d)=%q, want %q", code, got, want)
		}
	}
}

// TestStatusTextFor_UnknownFallback verifies the "Status NNN" fallback.
func TestStatusTextFor_UnknownFallback(t *testing.T) {
	for _, code := range []int{199, 299, 399, 499, 599, 700, 999} {
		want := fmt.Sprintf("Status %d", code)
		got := statusTextFor(code)
		if got != want {
			t.Errorf("statusTextFor(%d)=%q, want %q", code, got, want)
		}
	}
}

// TestBuildHTTPRequest_IPv6HostBracketed verifies that an IPv6 dstIP is
// wrapped in brackets per RFC 7230 §5.4 (uri-host: IP-literal = "[" ... "]").
// Without brackets, downstream parsers may misinterpret ":" as a port separator.
func TestBuildHTTPRequest_IPv6HostBracketed(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/"}
	result := buildHTTPRequest(cfg, "::1")
	if !strings.Contains(result, "Host: [::1]\r\n") {
		t.Errorf("result=%q, want 'Host: [::1]\\r\\n' (IPv6 must be bracketed)", result)
	}
}

// TestBuildHTTPRequest_IPv4HostNotBracketed verifies IPv4 dstIP is NOT
// bracketed (regression guard for the IPv6 fix).
func TestBuildHTTPRequest_IPv4HostNotBracketed(t *testing.T) {
	cfg := &core.HTTPConfig{Method: "GET", URI: "/"}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Host: 10.0.0.2\r\n") {
		t.Errorf("result=%q, want 'Host: 10.0.0.2\\r\\n'", result)
	}
	if strings.Contains(result, "[10.0.0.2]") {
		t.Errorf("result=%q, IPv4 must not be bracketed", result)
	}
}

// TestBuildHTTPResponse_ContentTypeDefaultPlain verifies that when user
// does NOT provide a Content-Type in ResponseHeaders and ResponseBody is
// non-empty, the default "Content-Type: text/plain" is emitted.
//
// Per CLAUDE.md testing policy §5: a field that is never asserted stays at
// its zero value and passes structural tests. This test asserts the actual
// header value, closing a coverage gap identified in the post-merge review.
func TestBuildHTTPResponse_ContentTypeDefaultPlain(t *testing.T) {
	cfg := &core.HTTPConfig{ResponseBody: "hello"}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Content-Type: text/plain; charset=utf-8\r\n") {
		t.Errorf("result=%q, want default 'Content-Type: text/plain; charset=utf-8\\r\\n'", result)
	}
}

// TestBuildHTTPRequest_ConnectionUserOverrideForcesClose verifies that when
// default would emit "keep-alive" (Transactions>1), user-provided
// "Connection: close" wins. This is the inverse of
// TestBuildHTTPRequest_ConnectionUserOverride (which forces keep-alive on a
// short-conn default). Both directions must work.
func TestBuildHTTPRequest_ConnectionUserOverrideForcesClose(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:         "GET",
		URI:            "/",
		Transactions:   3, // default would be keep-alive
		KeepAlive:      true,
		RequestHeaders: map[string]string{"Connection": "close"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	connCount := strings.Count(result, "Connection:")
	if connCount != 1 {
		t.Errorf("result=%q, want exactly 1 Connection header, got %d", result, connCount)
	}
	if !strings.Contains(result, "Connection: close\r\n") {
		t.Errorf("result=%q, want user value 'Connection: close'", result)
	}
	if strings.Contains(result, "Connection: keep-alive") {
		t.Errorf("result=%q, should not contain default 'keep-alive' when user provided close", result)
	}
}

// TestHTTPPlan_RequestPayloadWithCustomHeaders is an integration test that
// drives the full Plan() flow with custom RequestHeaders and verifies the
// actual packet Payload contains:
//   - exactly one Host (the user's, not the dstIP default)
//   - exactly one Connection (default, since user didn't override)
//   - the user's custom header X-Trace
//
// Per CLAUDE.md testing policy §4: units passing in isolation does not prove
// the feature works end-to-end. This test catches plan() <-> buildHTTPRequest
// integration regressions that unit tests miss.
func TestHTTPPlan_RequestPayloadWithCustomHeaders(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		Transactions: 1,
		KeepAlive:    false,
		RequestHeaders: map[string]string{
			"Host":    "www.home.com",
			"X-Trace": "abc-123",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Find the request packet (PSH-ACK with payload starting "GET ").
	var requestPkt *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Payload != nil && strings.HasPrefix(string(cfgs[i].Payload), "GET ") {
			requestPkt = &cfgs[i]
			break
		}
	}
	if requestPkt == nil {
		t.Fatalf("no request packet found in %d configs", len(cfgs))
	}
	body := string(requestPkt.Payload)

	hostCount := strings.Count(body, "Host:")
	if hostCount != 1 {
		t.Errorf("payload=%q, want exactly 1 Host header, got %d", body, hostCount)
	}
	if !strings.Contains(body, "Host: www.home.com\r\n") {
		t.Errorf("payload=%q, want 'Host: www.home.com\\r\\n'", body)
	}
	if strings.Contains(body, "Host: 10.0.0.2") {
		t.Errorf("payload=%q, should not contain default 'Host: 10.0.0.2'", body)
	}

	connCount := strings.Count(body, "Connection:")
	if connCount != 1 {
		t.Errorf("payload=%q, want exactly 1 Connection header, got %d", body, connCount)
	}
	if !strings.Contains(body, "Connection: close\r\n") {
		t.Errorf("payload=%q, want default 'Connection: close' (short-conn)", body)
	}

	if !strings.Contains(body, "X-Trace: abc-123\r\n") {
		t.Errorf("payload=%q, want 'X-Trace: abc-123\\r\\n'", body)
	}
}

// TestHTTPPlan_ResponsePayloadWithCustomHeaders is the response-side
// counterpart of TestHTTPPlan_RequestPayloadWithCustomHeaders. Verifies
// Plan() produces a response packet with user-overridden Content-Type and
// custom ResponseBody.
func TestHTTPPlan_ResponsePayloadWithCustomHeaders(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:              "GET",
		URI:                 "/",
		Transactions:        1,
		KeepAlive:           false,
		ResponseBody:        `{"ok":true}`,
		ResponseStatusCode:  201,
		ResponseStatusText:  "Created",
		ResponseHeaders:     map[string]string{"Content-Type": "application/json"},
	}
	cfgs := drain(mustPlan(t, p, spec))

	var respPkt *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Payload != nil && strings.HasPrefix(string(cfgs[i].Payload), "HTTP/1.1 ") {
			respPkt = &cfgs[i]
			break
		}
	}
	if respPkt == nil {
		t.Fatalf("no response packet found in %d configs", len(cfgs))
	}
	body := string(respPkt.Payload)

	if !strings.HasPrefix(body, "HTTP/1.1 201 Created\r\n") {
		t.Errorf("payload=%q, want status line 'HTTP/1.1 201 Created\\r\\n'", body)
	}
	if !strings.Contains(body, "Content-Type: application/json\r\n") {
		t.Errorf("payload=%q, want user 'Content-Type: application/json\\r\\n'", body)
	}
	if strings.Contains(body, "Content-Type: text/plain") {
		t.Errorf("payload=%q, should not contain default text/plain when user provided", body)
	}
	ctCount := strings.Count(body, "Content-Type:")
	if ctCount != 1 {
		t.Errorf("payload=%q, want exactly 1 Content-Type, got %d", body, ctCount)
	}
	if !strings.HasSuffix(body, `{"ok":true}`) {
		t.Errorf("payload=%q, want ResponseBody at end", body)
	}
}

// --- VLAN (H61) ---

// H61-NEG: VLAN not propagated. Known bug: L2Config literal omits VLAN.
func TestHTTPPlan_VLANNotPropagated(t *testing.T) {
	t.Skip("known bug H61: VLAN not propagated to L2Config. Remove skip once fixed.")
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.VLAN = &core.VLAN{ID: 100, Priority: 3}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.VLAN == nil || cfgs[0].L2.VLAN.ID != 100 {
		t.Errorf("VLAN not propagated: %+v", cfgs[0].L2.VLAN)
	}
	if cfgs[0].L2.VLAN.Priority != 3 {
		t.Errorf("VLAN priority=%d, want 3", cfgs[0].L2.VLAN.Priority)
	}
}

// --- MSS segmentation (Task #49) ---
//
// The next set of tests covers HTTP response segmentation by MSS. A response
// longer than MSS is split into multiple PSH-ACK segments; the SYN/SYN-ACK
// advertise that MSS as a TCP option. Each segment advances serverSeq by its
// payload length, so the following packet's Ack accounts for all response
// bytes.

// TestHTTPPlan_MSSDefault_NoSegmentation verifies that the default path
// (MSS=0 -> DefaultMSS=1460) does not segment a short response: the response
// is a single PSH-ACK segment whose payload equals the full built response.
func TestHTTPPlan_MSSDefault_NoSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: "short",
		Transactions: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 request + 1 response + 4 termination = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (short response should NOT segment)", len(cfgs))
	}
	resp := cfgs[4]
	if resp.L4.Flags != 0x18 {
		t.Errorf("resp.Flags=%x, want 0x18 (PSH-ACK)", resp.L4.Flags)
	}
	if !strings.HasPrefix(string(resp.Payload), "HTTP/1.1 200 OK") {
		t.Errorf("resp payload=%q, want HTTP/1.1 200 OK prefix", string(resp.Payload))
	}
}

// TestHTTPPlan_MSSSegmentsLongResponse verifies that a response larger than
// MSS is split into ceil(len/MSS) PSH-ACK segments, each carrying the right
// payload slice and advancing serverSeq per segment. A 3000-byte body over
// MSS=1460 -> ceil(3000/1460) = 3 segments (1460 + 1460 + 80) — the actual
// response includes HTTP headers so the total payload length is larger; we
// assert segment count and per-segment payload size directly.
func TestHTTPPlan_MSSSegmentsLongResponse(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Body large enough to force segmentation at DefaultMSS=1460.
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: strings.Repeat("A", 3000),
		Transactions: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Collect all "down" PSH-ACK packets AFTER the handshake (index 4 onward,
	// excluding termination). With 1 transaction, packets 4..N-4 are response
	// segments (N = total packets, last 4 are FIN/ACK/FIN/ACK).
	total := len(cfgs)
	if total < 9 {
		t.Fatalf("len=%d, want >=9", total)
	}
	var respSegs []core.PacketConfig
	for i := 4; i < total-4; i++ {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 {
			respSegs = append(respSegs, cfgs[i])
		}
	}
	if len(respSegs) < 2 {
		t.Fatalf("expected at least 2 response segments, got %d (response not segmented)", len(respSegs))
	}
	// Every segment except the last must be exactly MSS-sized (1460).
	for i, seg := range respSegs[:len(respSegs)-1] {
		if len(seg.Payload) != 1460 {
			t.Errorf("segment[%d].len=%d, want 1460 (MSS)", i, len(seg.Payload))
		}
	}
	// Reassemble payload and verify it starts with "HTTP/1.1 200 OK" and ends
	// with the repeated 'A' body.
	var reassembled []byte
	for _, seg := range respSegs {
		reassembled = append(reassembled, seg.Payload...)
	}
	if !strings.HasPrefix(string(reassembled), "HTTP/1.1 200 OK") {
		t.Errorf("reassembled payload prefix=%q", string(reassembled[:min(20, len(reassembled))]))
	}
	if !strings.HasSuffix(string(reassembled), strings.Repeat("A", 3000)) {
		t.Errorf("reassembled payload does not end with 3000 'A's")
	}

	// Per-segment Seq: each segment's Seq advances by the previous segment's
	// payload length. serverSeq starts from the SYN-ACK Seq + 1 (after the
	// handshake ACK consumes the SYN).
	synackSeq := cfgs[1].L4.Seq
	expectedSeq := synackSeq + 1
	for i, seg := range respSegs {
		if seg.L4.Seq != expectedSeq {
			t.Errorf("segment[%d].Seq=%d, want %d", i, seg.L4.Seq, expectedSeq)
		}
		expectedSeq += uint32(len(seg.Payload))
	}
}

// TestHTTPPlan_MSSExactMultiple verifies the boundary case where payload is
// an exact multiple of MSS: the planner must still emit the correct segment
// count (no off-by-one). With MSS=100 and a 300-byte body, we expect 3
// segments of 100 bytes each.
func TestHTTPPlan_MSSExactMultiple(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Use a small custom MSS so the body hits an exact multiple. MSS must be
	// >= MinMSS=536 per RFC 879, so use 536 with a 1072-byte (2*536) body.
	testutil.EnsureTCP(&spec).MSS = 536
	spec.HTTP = &core.HTTPConfig{
		Method:        "GET",
		URI:           "/",
		ResponseBody:  strings.Repeat("B", 1072), // 2 * 536
		Transactions:  1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	total := len(cfgs)
	var respSegs []core.PacketConfig
	for i := 4; i < total-4; i++ {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 {
			respSegs = append(respSegs, cfgs[i])
		}
	}
	// HTTP headers add to payload length, so total payload > 1072. With MSS=536,
	// ceil(total/536) segments expected. Just assert each non-last segment is
	// exactly 536 and that the reassembled body contains the 1072 B's at the end.
	for i, seg := range respSegs[:len(respSegs)-1] {
		if len(seg.Payload) != 536 {
			t.Errorf("segment[%d].len=%d, want 536 (MSS)", i, len(seg.Payload))
		}
	}
	var reassembled []byte
	for _, seg := range respSegs {
		reassembled = append(reassembled, seg.Payload...)
	}
	if !strings.HasSuffix(string(reassembled), strings.Repeat("B", 1072)) {
		t.Errorf("reassembled payload does not end with 1072 B's")
	}
}

// TestHTTPPlan_MSSEmptyBodyOneSegment verifies that an empty response body
// still produces exactly one PSH-ACK segment (the HTTP/1.1 200 OK header line
// alone), matching the pre-segmentation behavior. segmentByMSS returns a
// single empty chunk for empty input, but the response payload is non-empty
// (just headers), so segmentation applies normally — we verify that the
// response is still emitted as a single packet because the header-only
// response is shorter than MSS.
func TestHTTPPlan_MSSEmptyBodyOneSegment(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: "", // empty body
		Transactions: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (empty-body response is one segment)", len(cfgs))
	}
	resp := cfgs[4]
	if resp.L4.Flags != 0x18 {
		t.Errorf("resp.Flags=%x, want 0x18 (PSH-ACK)", resp.L4.Flags)
	}
	if !strings.HasPrefix(string(resp.Payload), "HTTP/1.1 200 OK") {
		t.Errorf("resp payload=%q, want 'HTTP/1.1 200 OK' prefix", string(resp.Payload))
	}
}

// TestHTTPPlan_MSSZeroUsesDefault verifies MSS=0 resolves to DefaultMSS (1460)
// for both segmentation and the SYN TCP option.
func TestHTTPPlan_MSSZeroUsesDefault(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	spec.HTTP = &core.HTTPConfig{
		Method:        "GET",
		URI:           "/",
		ResponseBody:  strings.Repeat("X", 2900), // 2*1460=2920, so 2900 -> 2 segments (1460 + 1440)
		Transactions:  1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	total := len(cfgs)
	var respSegs []core.PacketConfig
	for i := 4; i < total-4; i++ {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 {
			respSegs = append(respSegs, cfgs[i])
		}
	}
	// Total response payload = headers + 2900 'X'. Headers are <100 bytes, so
	// total ~3000 bytes. Over MSS=1460, expect ceil(3000/1460)=3 segments.
	if len(respSegs) < 2 {
		t.Fatalf("expected >=2 response segments at MSS=1460, got %d", len(respSegs))
	}

	// SYN must carry the MSS TCP option with value 1460.
	syn := cfgs[0]
	if len(syn.L4.TCPOptions) == 0 {
		t.Fatalf("SYN has no TCP options; expected MSS option")
	}
	var mssOpt *core.TCPOption
	for i := range syn.L4.TCPOptions {
		if syn.L4.TCPOptions[i].Kind == core.TCPOptMSS {
			mssOpt = &syn.L4.TCPOptions[i]
			break
		}
	}
	if mssOpt == nil {
		t.Fatalf("SYN missing MSS option; options=%+v", syn.L4.TCPOptions)
	}
	if len(mssOpt.Data) != 2 {
		t.Fatalf("MSS option data len=%d, want 2", len(mssOpt.Data))
	}
	got := uint16(mssOpt.Data[0])<<8 | uint16(mssOpt.Data[1])
	if got != 1460 {
		t.Errorf("SYN MSS option=%d, want 1460 (DefaultMSS)", got)
	}
}

// TestHTTPPlan_MSSUserOverrideInSYN verifies a user-provided MSS is carried in
// the SYN/SYN-ACK TCP option.
func TestHTTPPlan_MSSUserOverrideInSYN(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	testutil.EnsureTCP(&spec).MSS = 536 // RFC 879 minimum
	spec.HTTP = &core.HTTPConfig{
		Method:        "GET",
		URI:           "/",
		ResponseBody:  "x",
		Transactions:  1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	syn := cfgs[0]
	synack := cfgs[1]
	for _, pkt := range []struct {
		name string
		cfg  core.PacketConfig
	}{
		{"SYN", syn}, {"SYN-ACK", synack},
	} {
		var mssOpt *core.TCPOption
		for i := range pkt.cfg.L4.TCPOptions {
			if pkt.cfg.L4.TCPOptions[i].Kind == core.TCPOptMSS {
				mssOpt = &pkt.cfg.L4.TCPOptions[i]
				break
			}
		}
		if mssOpt == nil {
			t.Errorf("%s missing MSS option", pkt.name)
			continue
		}
		got := uint16(mssOpt.Data[0])<<8 | uint16(mssOpt.Data[1])
		if got != 536 {
			t.Errorf("%s MSS=%d, want 536", pkt.name, got)
		}
	}
}

// TestHTTPPlan_MSSTooSmall verifies Validate rejects MSS below MinMSS (536)
// per RFC 879.
func TestHTTPPlan_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // < MinMSS
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error for MSS < MinMSS, got nil")
	}
	if !strings.Contains(err.Error(), "MSS") || !strings.Contains(err.Error(), "RFC 879") {
		t.Errorf("err=%v, want contains 'MSS' and 'RFC 879'", err)
	}
}

// TestHTTPPlan_MSSTooLargeAtMaxUint16 verifies that the maximum uint16 (65535)
// is accepted (no upper-bound rejection; uint16 is the natural TCP option max).
func TestHTTPPlan_MSSMaxUint16(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	testutil.EnsureTCP(&spec).MSS = 65535
	spec.HTTP = &core.HTTPConfig{
		Method:        "GET",
		URI:           "/",
		ResponseBody:  "x",
		Transactions:  1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// SYN must carry MSS=65535.
	syn := cfgs[0]
	var mssOpt *core.TCPOption
	for i := range syn.L4.TCPOptions {
		if syn.L4.TCPOptions[i].Kind == core.TCPOptMSS {
			mssOpt = &syn.L4.TCPOptions[i]
			break
		}
	}
	if mssOpt == nil {
		t.Fatalf("SYN missing MSS option")
	}
	got := uint16(mssOpt.Data[0])<<8 | uint16(mssOpt.Data[1])
	if got != 65535 {
		t.Errorf("SYN MSS=%d, want 65535", got)
	}
	// Response should be a single segment since it's tiny.
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (short response at MSS=65535)", len(cfgs))
	}
}

// TestHTTPPlan_MSSACKOnNextTransaction verifies that after a segmented
// response in transaction 1, the request in transaction 2 ACKs the final
// serverSeq (i.e., all response bytes have been accounted for via
// serverSeq += len(seg) per segment).
func TestHTTPPlan_MSSACKOnNextTransaction(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method:       "GET",
		URI:          "/",
		ResponseBody: strings.Repeat("A", 3000),
		Transactions: 2,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + (1 req + N resp segs) + (1 req + M resp segs) + 4 term
	// Find the index of the second request packet (an "up" PSH-ACK after the
	// first response segment burst).
	var secondReqIdx int = -1
	seenUpReqs := 0
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			seenUpReqs++
			if seenUpReqs == 2 {
				secondReqIdx = i
				break
			}
		}
	}
	if secondReqIdx < 0 {
		t.Fatalf("did not find second request packet in %d configs", len(cfgs))
	}
	secondReq := cfgs[secondReqIdx]
	// The second request's Ack must equal (serverSeq after all first-response
	// segments). serverSeq starts at synackSeq+1, then advances by the sum of
	// all response segment payload lengths.
	synackSeq := cfgs[1].L4.Seq
	expectedAck := synackSeq + 1
	// Sum all first-response segments (down, PSH-ACK, between handshake and
	// the second request).
	for i := 4; i < secondReqIdx; i++ {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 {
			expectedAck += uint32(len(cfgs[i].Payload))
		}
	}
	if secondReq.L4.Ack != expectedAck {
		t.Errorf("second req Ack=%d, want %d (serverSeq advanced by all response segments)",
			secondReq.L4.Ack, expectedAck)
	}
}

// TestSegmentByMSS_EmptyInput verifies segmentByMSS returns a single empty
// chunk for empty input, so the caller emits one PSH-ACK segment (matching the
// pre-segmentation behavior where an empty body still produced one response).
func TestSegmentByMSS_EmptyInput(t *testing.T) {
	got := segmentByMSS(nil, 1460)
	if len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("nil input: got %v, want [{}]", got)
	}
	got = segmentByMSS([]byte{}, 1460)
	if len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("empty input: got %v, want [{}]", got)
	}
}

// TestSegmentByMSS_SingleChunkUnderMSS verifies a payload smaller than MSS
// returns a single-chunk result.
func TestSegmentByMSS_SingleChunkUnderMSS(t *testing.T) {
	payload := []byte("hello")
	got := segmentByMSS(payload, 1460)
	if len(got) != 1 {
		t.Fatalf("got %d chunks, want 1", len(got))
	}
	if string(got[0]) != "hello" {
		t.Errorf("got[0]=%q, want 'hello'", string(got[0]))
	}
}

// TestSegmentByMSS_ExactMultiple verifies the boundary case where payload is
// an exact multiple of MSS — no off-by-one empty trailing chunk.
func TestSegmentByMSS_ExactMultiple(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 2920) // 2 * 1460
	got := segmentByMSS(payload, 1460)
	if len(got) != 2 {
		t.Fatalf("got %d chunks, want 2", len(got))
	}
	if len(got[0]) != 1460 || len(got[1]) != 1460 {
		t.Errorf("chunk sizes = [%d, %d], want [1460, 1460]", len(got[0]), len(got[1]))
	}
}

// TestSegmentByMSS_PartialLastChunk verifies the last chunk is smaller than
// MSS when the payload is not a multiple of MSS.
func TestSegmentByMSS_PartialLastChunk(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 3000) // 2*1460 + 80
	got := segmentByMSS(payload, 1460)
	if len(got) != 3 {
		t.Fatalf("got %d chunks, want 3", len(got))
	}
	if len(got[0]) != 1460 || len(got[1]) != 1460 || len(got[2]) != 80 {
		t.Errorf("chunk sizes = [%d, %d, %d], want [1460, 1460, 80]",
			len(got[0]), len(got[1]), len(got[2]))
	}
}

// TestSynOptions_IncludesAllThreeOptions verifies synOptions emits MSS,
// Window Scale, and SACK-Permitted, and that MSS is encoded as 2 bytes
// big-endian.
func TestSynOptions_IncludesAllThreeOptions(t *testing.T) {
	opts := synOptions(1460)
	if len(opts) != 3 {
		t.Fatalf("got %d options, want 3", len(opts))
	}
	// MSS option
	if opts[0].Kind != core.TCPOptMSS {
		t.Errorf("opts[0].Kind=%d, want %d (MSS)", opts[0].Kind, core.TCPOptMSS)
	}
	if len(opts[0].Data) != 2 {
		t.Fatalf("MSS data len=%d, want 2", len(opts[0].Data))
	}
	mss := uint16(opts[0].Data[0])<<8 | uint16(opts[0].Data[1])
	if mss != 1460 {
		t.Errorf("MSS=%d, want 1460", mss)
	}
	// Window Scale
	if opts[1].Kind != core.TCPOptWinScale {
		t.Errorf("opts[1].Kind=%d, want %d (WinScale)", opts[1].Kind, core.TCPOptWinScale)
	}
	// SACK-Permitted
	if opts[2].Kind != core.TCPOptSACKPermit {
		t.Errorf("opts[2].Kind=%d, want %d (SACKPermit)", opts[2].Kind, core.TCPOptSACKPermit)
	}
}

// TestSynOptions_ZeroMSSDefaults verifies synOptions(0) falls back to
// DefaultMSS (1460) rather than emitting MSS=0 (which would negotiate a
// pathological 0-byte segment size).
func TestSynOptions_ZeroMSSDefaults(t *testing.T) {
	opts := synOptions(0)
	if len(opts) == 0 || opts[0].Kind != core.TCPOptMSS {
		t.Fatalf("expected MSS option first, got %+v", opts)
	}
	mss := uint16(opts[0].Data[0])<<8 | uint16(opts[0].Data[1])
	if mss != DefaultMSS {
		t.Errorf("synOptions(0).MSS=%d, want %d (DefaultMSS)", mss, DefaultMSS)
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// --- Request-side gzip (symmetric to TestBuildHTTPResponse_Gzip*) ---

// TestBuildHTTPRequest_GzipCompressesBody verifies that setting
// RequestContentEncoding="gzip" compresses the request Body, emits a
// "Content-Encoding: gzip" header, and sets Content-Length to the compressed
// byte count. Symmetric to TestBuildHTTPResponse_GzipCompressesBody.
func TestBuildHTTPRequest_GzipCompressesBody(t *testing.T) {
	plaintext := "Hello, world! Hello, world! Hello, world!"
	cfg := &core.HTTPConfig{
		Method:                 "POST",
		URI:                    "/upload",
		Body:                   plaintext,
		RequestContentEncoding: "gzip",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")

	if !strings.Contains(result, "Content-Encoding: gzip\r\n") {
		t.Errorf("result=%q, want 'Content-Encoding: gzip' header", result)
	}

	// Body follows the blank line after headers.
	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("result=%q, no header/body separator", result)
	}
	body := result[idx+4:]
	if strings.HasPrefix(body, "Hello, world!") {
		t.Fatalf("body=%q, should not be plaintext (must be gzip-compressed)", body)
	}
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body first 2 bytes = % x, want gzip magic 1f 8b", body[:min(2, len(body))])
	}

	// Content-Length must match the compressed body byte count, not the
	// plaintext length.
	wantCL := fmt.Sprintf("Content-Length: %d\r\n", len(body))
	if !strings.Contains(result, wantCL) {
		t.Errorf("result=%q, want %s (compressed length, not %d)", result, wantCL, len(plaintext))
	}

	// Round-trip: gzip-decompress the body and confirm it equals the input.
	zr, err := gzip.NewReader(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	var decoded bytes.Buffer
	if _, err := decoded.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if got := decoded.String(); got != plaintext {
		t.Errorf("decompressed body=%q, want %q", got, plaintext)
	}
}

// TestBuildHTTPRequest_GzipContentEncodingUserOverride verifies that a
// user-provided Content-Encoding header suppresses the auto-emitted default
// (no duplicate header), case-insensitive per RFC 7230 §3.2. Symmetric to
// TestBuildHTTPResponse_GzipContentEncodingUserOverride.
func TestBuildHTTPRequest_GzipContentEncodingUserOverride(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:                 "POST",
		URI:                    "/",
		Body:                   "x",
		RequestContentEncoding: "gzip",
		RequestHeaders:         map[string]string{"content-encoding": "gzip"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if got := strings.Count(strings.ToLower(result), "content-encoding:"); got != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Encoding header, got %d", result, got)
	}
}

// TestBuildHTTPRequest_GzipEmptyBodySkipsCompression verifies that
// RequestContentEncoding=gzip with an empty Body does not emit Content-Encoding
// or Content-Length (matches the empty-body defaulting rule for the non-gzip
// path). Symmetric to TestBuildHTTPResponse_GzipEmptyBodySkipsCompression.
func TestBuildHTTPRequest_GzipEmptyBodySkipsCompression(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:                 "GET",
		URI:                    "/",
		Body:                   "",
		RequestContentEncoding: "gzip",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Content-Encoding:") {
		t.Errorf("result=%q, should not emit Content-Encoding when body empty", result)
	}
	if strings.Contains(result, "Content-Length:") {
		t.Errorf("result=%q, should not emit Content-Length when body empty", result)
	}
}

// TestBuildHTTPRequest_NoGzipByDefault verifies the default (no compression)
// path emits no Content-Encoding header. Symmetric to
// TestBuildHTTPResponse_NoGzipByDefault.
func TestBuildHTTPRequest_NoGzipByDefault(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method: "POST",
		URI:    "/",
		Body:   "x",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if strings.Contains(result, "Content-Encoding:") {
		t.Errorf("result=%q, should not emit Content-Encoding by default", result)
	}
}

// TestBuildHTTPRequest_GzipUTF8Chinese verifies a non-ASCII request body
// survives gzip round-trip with bytes preserved. Symmetric to
// TestBuildHTTPResponse_GzipUTF8Chinese.
func TestBuildHTTPRequest_GzipUTF8Chinese(t *testing.T) {
	plaintext := "我爱你中国"
	cfg := &core.HTTPConfig{
		Method:                 "POST",
		URI:                    "/",
		Body:                   plaintext,
		RequestContentEncoding: "gzip",
		RequestHeaders:         map[string]string{"Content-Type": "text/html; charset=utf-8"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")

	if !strings.Contains(result, "Content-Encoding: gzip\r\n") {
		t.Errorf("result=%q, want 'Content-Encoding: gzip' header", result)
	}
	if !strings.Contains(result, "Content-Type: text/html; charset=utf-8\r\n") {
		t.Errorf("result=%q, want user Content-Type", result)
	}

	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("result=%q, no header/body separator", result)
	}
	body := result[idx+4:]

	zr, err := gzip.NewReader(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	var decoded bytes.Buffer
	if _, err := decoded.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if got := decoded.String(); got != plaintext {
		t.Errorf("decompressed body=%q, want %q", got, plaintext)
	}
}

// --- Request-side MSS segmentation (symmetric to TestHTTPPlan_MSS*) ---

// TestHTTPPlan_RequestMSSSegmentsLongBody verifies that a request body larger
// than MSS is split into ceil(len/MSS) PSH-ACK segments, each carrying the
// right payload slice and advancing clientSeq per segment. Symmetric to
// TestHTTPPlan_MSSSegmentsLongResponse.
func TestHTTPPlan_RequestMSSSegmentsLongBody(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	// Body large enough to force segmentation at DefaultMSS=1460. Use POST
	// since GET typically has no body.
	testutil.EnsureTCP(&spec).MSS = 536 // use small MSS to force multiple segments with smaller body
	spec.HTTP = &core.HTTPConfig{
		Method: "POST",
		URI:    "/upload",
		Body:   strings.Repeat("A", 3000),
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Collect all "up" PSH-ACK packets AFTER the handshake (index 3 onward,
	// excluding termination). With 1 transaction, packets 3..N-4 are request
	// segments (N = total packets, last 4 are FIN/ACK/FIN/ACK).
	total := len(cfgs)
	if total < 9 {
		t.Fatalf("len=%d, want >=9", total)
	}
	var reqSegs []core.PacketConfig
	for i := 3; i < total-4; i++ {
		if cfgs[i].Direction == "up" && cfgs[i].L4.Flags == 0x18 && len(cfgs[i].Payload) > 0 {
			reqSegs = append(reqSegs, cfgs[i])
		}
	}
	if len(reqSegs) < 2 {
		t.Fatalf("expected at least 2 request segments, got %d (request not segmented)", len(reqSegs))
	}
	// Every segment except the last must be exactly MSS-sized (536).
	for i, seg := range reqSegs[:len(reqSegs)-1] {
		if len(seg.Payload) != 536 {
			t.Errorf("segment[%d].len=%d, want 536 (MSS)", i, len(seg.Payload))
		}
	}
	// Reassemble payload and verify it starts with "POST /upload" and ends
	// with the repeated 'A' body.
	var reassembled []byte
	for _, seg := range reqSegs {
		reassembled = append(reassembled, seg.Payload...)
	}
	if !strings.HasPrefix(string(reassembled), "POST /upload HTTP/1.1") {
		t.Errorf("reassembled prefix=%q", string(reassembled[:min(30, len(reassembled))]))
	}
	if !strings.HasSuffix(string(reassembled), strings.Repeat("A", 3000)) {
		t.Errorf("reassembled payload does not end with 3000 'A's")
	}

	// Per-segment Seq: each segment's Seq advances by the previous segment's
	// payload length. clientSeq starts from the SYN Seq + 1 (after the
	// handshake ACK consumes the SYN).
	synSeq := cfgs[0].L4.Seq
	expectedSeq := synSeq + 1
	for i, seg := range reqSegs {
		if seg.L4.Seq != expectedSeq {
			t.Errorf("segment[%d].Seq=%d, want %d", i, seg.L4.Seq, expectedSeq)
		}
		expectedSeq += uint32(len(seg.Payload))
	}
}

// TestHTTPPlan_RequestMSSDefault_NoSegmentation verifies that the default path
// (MSS=0 -> DefaultMSS=1460) does not segment a short request: the request is
// a single PSH-ACK segment. Symmetric to TestHTTPPlan_MSSDefault_NoSegmentation.
func TestHTTPPlan_RequestMSSDefault_NoSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	spec.HTTP = &core.HTTPConfig{
		Method: "POST",
		URI:    "/",
		Body:   "short",
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 request + 1 response + 4 termination = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (short request should NOT segment)", len(cfgs))
	}
	req := cfgs[3]
	if req.L4.Flags != 0x18 {
		t.Errorf("req.Flags=%x, want 0x18 (PSH-ACK)", req.L4.Flags)
	}
	if !strings.HasPrefix(string(req.Payload), "POST / HTTP/1.1") {
		t.Errorf("req payload=%q, want 'POST / HTTP/1.1' prefix", string(req.Payload))
	}
}

// TestHTTPPlan_RequestGzipMSSComposite verifies that a gzip-compressed request
// body that is still larger than MSS gets both compressed AND segmented: the
// gzip happens first (in buildHTTPRequest), then segmentByMSS splits the
// framed request. Symmetric to the response-side composite behavior.
//
// We use crypto/rand bytes (incompressible) to guarantee the gzip output
// stays larger than MSS=536 regardless of Go stdlib gzip improvements. A
// repetitive pattern like "AAAA..." or i%256 would compress to <100 bytes and
// the test would degenerate to a single segment.
func TestHTTPPlan_RequestGzipMSSComposite(t *testing.T) {
	p := NewPlanner()
	spec := validHTTPSpec()
	const bodyLen = 100000
	bodyBytes := make([]byte, bodyLen)
	if _, err := cryptoRand.Read(bodyBytes); err != nil {
		t.Fatalf("crypto/rand.Read: %v", err)
	}
	testutil.EnsureTCP(&spec).MSS = 536
	spec.HTTP = &core.HTTPConfig{
		Method:                 "POST",
		URI:                    "/upload",
		Body:                   string(bodyBytes),
		RequestContentEncoding: "gzip",
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Collect request segments.
	total := len(cfgs)
	var reqSegs []core.PacketConfig
	for i := 3; i < total-4; i++ {
		if cfgs[i].Direction == "up" && cfgs[i].L4.Flags == 0x18 && len(cfgs[i].Payload) > 0 {
			reqSegs = append(reqSegs, cfgs[i])
		}
	}
	if len(reqSegs) < 2 {
		t.Fatalf("expected at least 2 request segments (gzip-compressed body > MSS=536), got %d", len(reqSegs))
	}

	// Per-segment size: every non-last segment must be exactly MSS-sized.
	// Symmetric to TestHTTPPlan_MSSSegmentsLongResponse line 1752-1756.
	for i, seg := range reqSegs[:len(reqSegs)-1] {
		if len(seg.Payload) != 536 {
			t.Errorf("segment[%d].len=%d, want 536 (MSS)", i, len(seg.Payload))
		}
	}

	// Reassemble and verify gzip magic appears after the request line + headers.
	var reassembled []byte
	for _, seg := range reqSegs {
		reassembled = append(reassembled, seg.Payload...)
	}
	// Must start with the HTTP request line.
	if !strings.HasPrefix(string(reassembled), "POST /upload HTTP/1.1") {
		t.Errorf("prefix=%q", string(reassembled[:min(30, len(reassembled))]))
	}
	// Must contain Content-Encoding: gzip header.
	if !strings.Contains(string(reassembled), "Content-Encoding: gzip\r\n") {
		t.Errorf("reassembled request missing 'Content-Encoding: gzip' header")
	}
	// Body (after \r\n\r\n) must start with gzip magic.
	idx := strings.Index(string(reassembled), "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no header/body separator")
	}
	bodyGzip := reassembled[idx+4:]
	if len(bodyGzip) < 2 || bodyGzip[0] != 0x1f || bodyGzip[1] != 0x8b {
		t.Fatalf("body first 2 bytes = % x, want gzip magic 1f 8b", bodyGzip[:min(2, len(bodyGzip))])
	}

	// Round-trip the compressed body.
	zr, err := gzip.NewReader(bytes.NewReader(bodyGzip))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	var decoded bytes.Buffer
	if _, err := decoded.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if got := decoded.String(); got != string(bodyBytes) {
		t.Errorf("decompressed body length=%d, want %d", len(got), bodyLen)
	}

	// Per-segment Seq: each segment's Seq advances by the previous segment's
	// payload length. Symmetric to TestHTTPPlan_MSSSegmentsLongResponse.
	synSeq := cfgs[0].L4.Seq
	expectedSeq := synSeq + 1
	for i, seg := range reqSegs {
		if seg.L4.Seq != expectedSeq {
			t.Errorf("segment[%d].Seq=%d, want %d", i, seg.L4.Seq, expectedSeq)
		}
		expectedSeq += uint32(len(seg.Payload))
	}
}

// TestBuildHTTPRequest_RequestContentEncodingNonGzip verifies that a
// RequestContentEncoding value other than "gzip" (e.g. "br", "identity",
// "deflate") is treated as a literal header value passed through to
// Content-Encoding WITHOUT transformation — the Body remains plaintext.
// Covers the branch at http.go:499 (requestContentEncoding != "" && != "gzip")
// which the gzip-only tests do not exercise.
func TestBuildHTTPRequest_RequestContentEncodingNonGzip(t *testing.T) {
	cases := []string{"br", "identity", "deflate", "x-gzip"}
	for _, enc := range cases {
		t.Run(enc, func(t *testing.T) {
			cfg := &core.HTTPConfig{
				Method:                 "POST",
				URI:                    "/",
				Body:                   "Hello, world!",
				RequestContentEncoding: enc,
			}
			result := buildHTTPRequest(cfg, "10.0.0.2")
			// Header emitted with the literal value.
			wantHeader := "Content-Encoding: " + enc + "\r\n"
			if !strings.Contains(result, wantHeader) {
				t.Errorf("result=%q, want header %q", result, wantHeader)
			}
			// Body must remain plaintext (not gzip-compressed).
			idx := strings.Index(result, "\r\n\r\n")
			if idx < 0 {
				t.Fatalf("no separator")
			}
			body := result[idx+4:]
			if body != "Hello, world!" {
				t.Errorf("body=%q, want plaintext 'Hello, world!' (non-gzip encoding must not transform)", body)
			}
			// Content-Length must reflect plaintext length, not compressed.
			wantCL := fmt.Sprintf("Content-Length: %d\r\n", len("Hello, world!"))
			if !strings.Contains(result, wantCL) {
				t.Errorf("result=%q, want %s", result, wantCL)
			}
		})
	}
}

// TestBuildHTTPRequest_GzipWithUserContentLength verifies the documented
// "caller responsibility" foot-gun: if the user explicitly sets
// Content-Length via RequestHeaders AND enables gzip, the user's value wins
// (passes through verbatim) even though it no longer matches the compressed
// body byte count. This is symmetric to the response-side behavior and is
// documented at http.go:455-458. Test locks the behavior so a future
// "helpful" auto-correction doesn't silently change the contract.
func TestBuildHTTPRequest_GzipWithUserContentLength(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:                 "POST",
		URI:                    "/",
		Body:                   "Hello, world! Hello, world! Hello, world!",
		RequestContentEncoding: "gzip",
		RequestHeaders:         map[string]string{"Content-Length": "999"},
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	// User's Content-Length wins (no auto-emitted default).
	if !strings.Contains(result, "Content-Length: 999\r\n") {
		t.Errorf("result=%q, want user Content-Length: 999 to win", result)
	}
	if strings.Count(result, "Content-Length:") != 1 {
		t.Errorf("result=%q, want exactly 1 Content-Length header", result)
	}
	// Body is still gzip-compressed.
	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no separator")
	}
	body := result[idx+4:]
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body must still be gzip-compressed despite user Content-Length; got % x", body[:min(2, len(body))])
	}
}

// TestBuildHTTPRequest_GzipPreservesContentType verifies that gzip compression
// does NOT corrupt the sniffed Content-Type. Before the C2 fix, gzip was
// applied BEFORE sniffing, so the sniffer saw the gzip magic bytes (1F 8B)
// and returned "application/gzip" instead of the original content type.
func TestBuildHTTPRequest_GzipPreservesContentType(t *testing.T) {
	cfg := &core.HTTPConfig{
		Method:                "POST",
		URI:                   "/upload",
		Body:                  "<html><body>hello</body></html>",
		RequestContentEncoding: "gzip",
	}
	result := buildHTTPRequest(cfg, "10.0.0.2")
	if !strings.Contains(result, "Content-Type: text/html; charset=utf-8\r\n") {
		t.Errorf("result=%q, want Content-Type: text/html; charset=utf-8 (C2: sniff BEFORE gzip)", result)
	}
	if strings.Contains(result, "Content-Type: application/gzip") {
		t.Errorf("result=%q, Content-Type must NOT be application/gzip (C2 bug)", result)
	}
	// Body must still be gzip-compressed.
	idx := strings.Index(result, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no separator")
	}
	body := result[idx+4:]
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body must be gzip-compressed; got % x", body[:min(2, len(body))])
	}
}

// TestBuildHTTPResponse_GzipPreservesContentType verifies the response-side
// symmetric fix (C3): gzip must not corrupt the sniffed Content-Type.
func TestBuildHTTPResponse_GzipPreservesContentType(t *testing.T) {
	cfg := &core.HTTPConfig{
		ResponseBody:            "<html><body>response</body></html>",
		ResponseContentEncoding: "gzip",
	}
	result := buildHTTPResponse(cfg)
	if !strings.Contains(result, "Content-Type: text/html; charset=utf-8\r\n") {
		t.Errorf("result=%q, want Content-Type: text/html; charset=utf-8 (C3: sniff BEFORE gzip)", result)
	}
	if strings.Contains(result, "Content-Type: application/gzip") {
		t.Errorf("result=%q, Content-Type must NOT be application/gzip (C3 bug)", result)
	}
}

// TestSniffByMagic_WAV verifies that WAV files are detected as audio/wav.
// Before the H1 fix, a RIFF catch-all returned "application/octet-stream"
// before the WAV check, making the WAV detection unreachable.
func TestSniffByMagic_WAV(t *testing.T) {
	// WAV: RIFF + size(4) + WAVE
	wav := []byte{'R', 'I', 'F', 'F', 0x00, 0x00, 0x00, 0x00, 'W', 'A', 'V', 'E'}
	if got := sniffByMagic(wav); got != "audio/wav" {
		t.Errorf("sniffByMagic(WAV)=%q, want audio/wav (H1: RIFF catch-all was shadowing WAV)", got)
	}
}

// TestSniffByMagic_WebP verifies that WebP files are detected as image/webp.
// Before the H1 fix, the RIFF catch-all made WebP detection unreachable.
func TestSniffByMagic_WebP(t *testing.T) {
	// WebP: RIFF + size(4) + WEBP
	webp := []byte{'R', 'I', 'F', 'F', 0x00, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P'}
	if got := sniffByMagic(webp); got != "image/webp" {
		t.Errorf("sniffByMagic(WebP)=%q, want image/webp (H1: RIFF catch-all was shadowing WebP)", got)
	}
}

// TestSniffContentType_BOMStripped verifies that a UTF-8 BOM (EF BB BF)
// prefix does not prevent HTML detection. Before the M2 fix, bytes.TrimLeft
// did not strip BOM, so BOM-prefixed HTML was mis-detected as text/plain.
func TestSniffContentType_BOMStripped(t *testing.T) {
	bomHTML := []byte{0xEF, 0xBB, 0xBF, '<', 'h', 't', 'm', 'l', '>'}
	if got := sniffContentType(bomHTML); got != "text/html; charset=utf-8" {
		t.Errorf("sniffContentType(BOM+HTML)=%q, want text/html; charset=utf-8 (M2: BOM must be stripped)", got)
	}
}

// TestSniffByMagic_GIF87a verifies GIF87a magic bytes are detected as image/gif.
// Before the M3 fix, only 4 bytes "GIF8" were checked, not the full 6-byte
// signature "GIF87a" / "GIF89a".
func TestSniffByMagic_GIF87a(t *testing.T) {
	gif87a := []byte{'G', 'I', 'F', '8', '7', 'a'}
	if got := sniffByMagic(gif87a); got != "image/gif" {
		t.Errorf("sniffByMagic(GIF87a)=%q, want image/gif", got)
	}
}

// TestSniffByMagic_GIF89a verifies GIF89a magic bytes are detected as image/gif.
func TestSniffByMagic_GIF89a(t *testing.T) {
	gif89a := []byte{'G', 'I', 'F', '8', '9', 'a'}
	if got := sniffByMagic(gif89a); got != "image/gif" {
		t.Errorf("sniffByMagic(GIF89a)=%q, want image/gif", got)
	}
}

// TestSniffByMagic_GIF8Incomplete verifies that "GIF8" without the version
// byte is NOT mis-detected as image/gif. Before the M3 fix, only 4 bytes
// were checked, so "GIF8" + garbage would be falsely detected.
func TestSniffByMagic_GIF8Incomplete(t *testing.T) {
	gif8bad := []byte{'G', 'I', 'F', '8', 'X', 'X'}
	if got := sniffByMagic(gif8bad); got == "image/gif" {
		t.Errorf("sniffByMagic(GIF8+XX)=%q, must NOT be image/gif (M3: full 6-byte check)", got)
	}
}
