package replay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// drainTimeout drains configs from ch, stopping after d with whatever was
// collected. This prevents tests from blocking forever when the planner emits
// fewer configs than expected (e.g. on error/cancel).
func drainTimeout(ch <-chan core.PacketConfig, d time.Duration) []core.PacketConfig {
	var out []core.PacketConfig
	for {
		select {
		case cfg, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, cfg)
		case <-time.After(d):
			return out
		}
	}
}

// buildTestFrame constructs a standard Eth+IPv4+TCP frame for unit tests.
func buildTestFrame(t *testing.T, seq uint32, flags uint8) []byte {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: seq, Window: 65535,
		SYN: flags&2 != 0, ACK: flags&16 != 0, FIN: flags&1 != 0, PSH: flags&8 != 0}
	ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp)
	return buf.Bytes()
}

// buildTestFrameWithLayout builds a frame and extracts its OffsetLayout.
func buildTestFrameWithLayout(t *testing.T, seq uint32) ([]byte, pcapparser.OffsetLayout) {
	t.Helper()
	raw := buildTestFrame(t, seq, 2)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	return raw, pcapparser.ExtractOffsetLayout(pkt)
}

// writeTempFrame writes raw bytes to a temp file and returns the opened *os.File.
func writeTempFrame(t *testing.T, raw []byte) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "frame.bin")
	if err := os.WriteFile(p, raw, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

// =============================================================================
// mapDirection
// =============================================================================

func TestMapDirection_C2S(t *testing.T) {
	if got := mapDirection("c2s"); got != "up" {
		t.Errorf("mapDirection(c2s) = %q, want up", got)
	}
}

func TestMapDirection_S2C(t *testing.T) {
	if got := mapDirection("s2c"); got != "down" {
		t.Errorf("mapDirection(s2c) = %q, want down", got)
	}
}

func TestMapDirection_Empty(t *testing.T) {
	if got := mapDirection(""); got != "" {
		t.Errorf("mapDirection(\"\") = %q, want \"\"", got)
	}
}

func TestMapDirection_Unknown(t *testing.T) {
	if got := mapDirection("unknown"); got != "unknown" {
		t.Errorf("mapDirection(unknown) = %q, want unknown", got)
	}
}

// =============================================================================
// offsetValuePatch
// =============================================================================

func TestOffsetValuePatch_UnknownTarget(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 1000)
	_, ok := offsetValuePatch(raw, offsetRule{target: "unknown", delta: 100}, layout)
	if ok {
		t.Error("expected ok=false for unknown target")
	}
}

func TestOffsetValuePatch_NegativeOffset(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: -1, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 1000)
	_, ok := offsetValuePatch(raw, offsetRule{target: "seq", delta: 100}, layout)
	if ok {
		t.Error("expected ok=false for layout.Seq=-1")
	}
}

func TestOffsetValuePatch_OutOfBounds(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 40) // 38+4=42 > 40
	_, ok := offsetValuePatch(raw, offsetRule{target: "seq", delta: 100}, layout)
	if ok {
		t.Error("expected ok=false for out-of-bounds read")
	}
}

func TestOffsetValuePatch_SeqDelta(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 1000)
	p, ok := offsetValuePatch(raw, offsetRule{target: "seq", delta: 100}, layout)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := make([]byte, 4)
	binary.BigEndian.PutUint32(want, 1100)
	if !bytes.Equal(p.Bytes, want) {
		t.Errorf("Bytes = %v, want %v (BE 1100)", p.Bytes, want)
	}
	if p.Layer != "l4" {
		t.Errorf("Layer = %q, want l4", p.Layer)
	}
	if p.Offset != 38 {
		t.Errorf("Offset = %d, want 38", p.Offset)
	}
}

func TestOffsetValuePatch_WindowDelta(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint16(raw[48:50], 100)
	p, ok := offsetValuePatch(raw, offsetRule{target: "window", delta: 50}, layout)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := make([]byte, 2)
	binary.BigEndian.PutUint16(want, 150)
	if !bytes.Equal(p.Bytes, want) {
		t.Errorf("Bytes = %v, want %v (BE 150)", p.Bytes, want)
	}
	if len(p.Bytes) != 2 {
		t.Errorf("width = %d, want 2", len(p.Bytes))
	}
}

func TestOffsetValuePatch_TTLWidth1(t *testing.T) {
	layout := pcapparser.OffsetLayout{TTL: 22, Seq: 38, Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	_, ok := offsetValuePatch(raw, offsetRule{target: "ttl", delta: 1}, layout)
	if ok {
		t.Error("expected ok=false for width=1 (no case 1 in switch)")
	}
}

func TestOffsetValuePatch_SeqWrap(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint32(raw[38:42], 0xFFFFFFFF)
	p, ok := offsetValuePatch(raw, offsetRule{target: "seq", delta: 1}, layout)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := make([]byte, 4)
	binary.BigEndian.PutUint32(want, 0)
	if !bytes.Equal(p.Bytes, want) {
		t.Errorf("Bytes = %v, want %v (uint32 wrap to 0)", p.Bytes, want)
	}
}

func TestOffsetValuePatch_WindowWrap(t *testing.T) {
	layout := pcapparser.OffsetLayout{Window: 48, L4Protocol: "tcp", L4Start: 34}
	raw := make([]byte, 54)
	binary.BigEndian.PutUint16(raw[48:50], 0xFFFF)
	p, ok := offsetValuePatch(raw, offsetRule{target: "window", delta: 1}, layout)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := make([]byte, 2)
	binary.BigEndian.PutUint16(want, 0)
	if !bytes.Equal(p.Bytes, want) {
		t.Errorf("Bytes = %v, want %v (uint16 wrap to 0)", p.Bytes, want)
	}
}

// =============================================================================
// macmapPatches
// =============================================================================

func macmapTestRaw() []byte {
	raw := make([]byte, 54)
	copy(raw[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) // src MAC
	copy(raw[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})  // dst MAC
	return raw
}

func TestMacmapPatches_SrcMapped(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"11:22:33:44:55:66": "aa:aa:aa:aa:aa:aa",
	}}
	patches := macmapPatches(raw, rule, layout)
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1 (src only)", len(patches))
	}
	if patches[0].Field != "src_mac" {
		t.Errorf("field = %q, want src_mac", patches[0].Field)
	}
	want, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	if !bytes.Equal(patches[0].Bytes, want) {
		t.Errorf("bytes = %v, want %v", patches[0].Bytes, want)
	}
}

func TestMacmapPatches_NoMatch(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"99:99:99:99:99:99": "88:88:88:88:88:88",
	}}
	patches := macmapPatches(raw, rule, layout)
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0 (no match)", len(patches))
	}
}

func TestMacmapPatches_InvalidMAC(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"11:22:33:44:55:66": "notamac",
	}}
	patches := macmapPatches(raw, rule, layout)
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0 (invalid MAC value skipped)", len(patches))
	}
}

func TestMacmapPatches_SrcMACDisabled(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: -1, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"11:22:33:44:55:66": "aa:aa:aa:aa:aa:aa",
	}}
	patches := macmapPatches(raw, rule, layout)
	for _, p := range patches {
		if p.Field == "src_mac" {
			t.Error("src_mac patch produced despite SrcMAC=-1")
		}
	}
}

func TestMacmapPatches_SrcMACOutOfBounds(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := make([]byte, 10) // 6+6=12 > 10
	copy(raw[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"11:22:33:44:55:66": "aa:aa:aa:aa:aa:aa",
	}}
	patches := macmapPatches(raw, rule, layout)
	for _, p := range patches {
		if p.Field == "src_mac" {
			t.Error("src_mac patch produced despite out-of-bounds raw")
		}
	}
}

func TestMacmapPatches_DstMapped(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"aa:bb:cc:dd:ee:ff": "99:99:99:99:99:99",
	}}
	patches := macmapPatches(raw, rule, layout)
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1 (dst only)", len(patches))
	}
	if patches[0].Field != "dst_mac" {
		t.Errorf("field = %q, want dst_mac", patches[0].Field)
	}
	want, _ := net.ParseMAC("99:99:99:99:99:99")
	if !bytes.Equal(patches[0].Bytes, want) {
		t.Errorf("bytes = %v, want %v", patches[0].Bytes, want)
	}
}

func TestMacmapPatches_NeitherMapped(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcMAC: 6, DstMAC: 0}
	raw := macmapTestRaw()
	rule := RewriteRule{Kind: "macmap", Mapping: map[string]string{
		"00:00:00:00:00:01": "00:00:00:00:00:02",
	}}
	patches := macmapPatches(raw, rule, layout)
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0 (neither MAC in mapping)", len(patches))
	}
}

// =============================================================================
// buildFlowContexts
// =============================================================================

func tcpFlows() []storage.FlowModel {
	return []storage.FlowModel{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", SrcPort: 1234, DstIP: "10.0.0.2", DstPort: 80,
			OffsetLayout: `{"src_ip":26,"dst_ip":30,"ttl":22,"seq":38,"window":48,"l3_start":14,"l4_start":34,"l4_protocol":"tcp"}`},
	}
}

func TestBuildFlowContexts_Empty(t *testing.T) {
	m, err := buildFlowContexts(nil, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(m) != 0 {
		t.Errorf("map = %d, want 0", len(m))
	}
}

func TestBuildFlowContexts_ValidLayout(t *testing.T) {
	m, err := buildFlowContexts(tcpFlows(), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m["f1"].layout.SrcIP != 26 {
		t.Errorf("layout.SrcIP = %d, want 26", m["f1"].layout.SrcIP)
	}
}

func TestBuildFlowContexts_BadLayout(t *testing.T) {
	flows := []storage.FlowModel{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", OffsetLayout: "bad"},
	}
	_, err := buildFlowContexts(flows, nil)
	if err == nil {
		t.Fatal("expected error for bad layout JSON")
	}
	if !strings.Contains(err.Error(), "layout") {
		t.Errorf("err = %q, want substring 'layout'", err.Error())
	}
}

func TestBuildFlowContexts_EmptyLayout(t *testing.T) {
	flows := []storage.FlowModel{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", OffsetLayout: ""},
	}
	m, err := buildFlowContexts(flows, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m["f1"].layout.SrcIP != -1 {
		t.Errorf("layout.SrcIP = %d, want -1 (default for empty layout)", m["f1"].layout.SrcIP)
	}
}

func TestBuildFlowContexts_ConflictingFieldRules(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"}},
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "64"}},
	}
	_, err := buildFlowContexts(tcpFlows(), rules)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "flow") {
		t.Errorf("err = %q, want substring 'flow'", err.Error())
	}
}

func TestBuildFlowContexts_ProtocolMismatch(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "endpoint", Target: "client_ip", Match: FlowMatcher{Protocol: "udp"},
			Strategy: core.StrategyConfig{Strategy: "fixed", Value: "10.9.9.9"}},
	}
	m, err := buildFlowContexts(tcpFlows(), rules)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	fc := m["f1"]
	if len(fc.endpointRules) != 0 {
		t.Errorf("endpointRules = %d, want 0 (protocol mismatch)", len(fc.endpointRules))
	}
	if len(fc.offsetRules) != 0 {
		t.Errorf("offsetRules = %d, want 0", len(fc.offsetRules))
	}
	if len(fc.macmapRules) != 0 {
		t.Errorf("macmapRules = %d, want 0", len(fc.macmapRules))
	}
}

func TestBuildFlowContexts_EndpointRule(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "endpoint", Target: "client_ip", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "10.9.9.9"}},
	}
	m, err := buildFlowContexts(tcpFlows(), rules)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	fc := m["f1"]
	if len(fc.endpointRules) != 1 {
		t.Fatalf("endpointRules = %d, want 1", len(fc.endpointRules))
	}
	if fc.endpointRules[0].target != "client_ip" {
		t.Errorf("target = %q, want client_ip", fc.endpointRules[0].target)
	}
	if fc.endpointRules[0].value != "10.9.9.9" {
		t.Errorf("value = %q, want 10.9.9.9", fc.endpointRules[0].value)
	}
}

func TestBuildFlowContexts_EndpointBadStrategy(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "endpoint", Target: "client_ip", Strategy: core.StrategyConfig{Strategy: ""}},
	}
	_, err := buildFlowContexts(tcpFlows(), rules)
	if err == nil {
		t.Fatal("expected error for bad endpoint strategy")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("err = %q, want substring 'endpoint'", err.Error())
	}
}

func TestBuildFlowContexts_OffsetRule(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "field", Target: "seq", Apply: "offset", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "1000"}},
	}
	m, err := buildFlowContexts(tcpFlows(), rules)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	fc := m["f1"]
	if len(fc.offsetRules) != 1 {
		t.Fatalf("offsetRules = %d, want 1", len(fc.offsetRules))
	}
	if fc.offsetRules[0].delta != 1000 {
		t.Errorf("delta = %d, want 1000", fc.offsetRules[0].delta)
	}
}

func TestBuildFlowContexts_OffsetBadStrategy(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "field", Target: "seq", Apply: "offset", Strategy: core.StrategyConfig{Strategy: ""}},
	}
	_, err := buildFlowContexts(tcpFlows(), rules)
	if err == nil {
		t.Fatal("expected error for bad offset strategy")
	}
	if !strings.Contains(err.Error(), "offset") {
		t.Errorf("err = %q, want substring 'offset'", err.Error())
	}
}

func TestBuildFlowContexts_FieldSetRule(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"}},
	}
	m, err := buildFlowContexts(tcpFlows(), rules)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	fc := m["f1"]
	if len(fc.offsetRules) != 0 {
		t.Errorf("offsetRules = %d, want 0 (apply=set not offset)", len(fc.offsetRules))
	}
	found := false
	for _, p := range fc.flowPatches {
		if p.Field == "ttl" {
			found = true
		}
	}
	if !found {
		t.Error("flowPatches does not contain a ttl patch")
	}
}

func TestBuildFlowContexts_MacmapRule(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "macmap", Mapping: map[string]string{"aa:bb:cc:dd:ee:ff": "11:22:33:44:55:66"}},
	}
	m, err := buildFlowContexts(tcpFlows(), rules)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	fc := m["f1"]
	if len(fc.macmapRules) != 1 {
		t.Errorf("macmapRules = %d, want 1", len(fc.macmapRules))
	}
}

func TestBuildFlowContexts_UnknownKind(t *testing.T) {
	rules := []RewriteRule{
		{Kind: "unknown"},
	}
	_, err := buildFlowContexts(tcpFlows(), rules)
	if err == nil {
		t.Fatal("expected error for unknown rule kind")
	}
	if !strings.Contains(err.Error(), "unknown rule kind") {
		t.Errorf("err = %q, want substring 'unknown rule kind'", err.Error())
	}
}

// =============================================================================
// assemblePatches
// =============================================================================

func TestAssemblePatches_AllTypes(t *testing.T) {
	raw, layout := buildTestFrameWithLayout(t, 1000)
	fc := &flowCtx{
		flow:          storage.FlowModel{ID: "f1", L4Protocol: "tcp"},
		layout:        layout,
		flowPatches:   []Patch{{Field: "ttl", Offset: layout.TTL, Bytes: []byte{128}, Layer: "l3"}},
		endpointRules: []endpointRule{{target: "client_ip", value: "10.9.9.9"}},
		offsetRules:   []offsetRule{{target: "seq", delta: 100}},
		macmapRules: []RewriteRule{{Kind: "macmap", Mapping: map[string]string{
			"aa:aa:aa:aa:aa:aa": "11:11:11:11:11:11",
		}}},
	}
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s"}
	patches := assemblePatches(fc, pkt, raw)
	fields := map[string]bool{}
	for _, p := range patches {
		fields[p.Field] = true
	}
	for _, want := range []string{"ttl", "client_ip", "seq", "src_mac"} {
		if !fields[want] {
			t.Errorf("patches missing field %q (got %v)", want, fields)
		}
	}
}

func TestAssemblePatches_EndpointOffsetAbsent(t *testing.T) {
	raw, layout := buildTestFrameWithLayout(t, 1000)
	layout.SrcIP = -1
	fc := &flowCtx{
		layout:        layout,
		flowPatches:   []Patch{{Field: "ttl", Offset: layout.TTL, Bytes: []byte{128}, Layer: "l3"}},
		endpointRules: []endpointRule{{target: "client_ip", value: "10.9.9.9"}},
		offsetRules:   []offsetRule{{target: "seq", delta: 100}},
	}
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s"}
	patches := assemblePatches(fc, pkt, raw)
	for _, p := range patches {
		if p.Field == "client_ip" {
			t.Error("client_ip patch should be skipped when layout.SrcIP=-1")
		}
	}
	foundTTL := false
	for _, p := range patches {
		if p.Field == "ttl" {
			foundTTL = true
		}
	}
	if !foundTTL {
		t.Error("ttl patch should remain")
	}
}

func TestAssemblePatches_OffsetSeqAbsent(t *testing.T) {
	raw, layout := buildTestFrameWithLayout(t, 1000)
	layout.Seq = -1
	fc := &flowCtx{
		layout:        layout,
		flowPatches:   []Patch{{Field: "ttl", Offset: layout.TTL, Bytes: []byte{128}, Layer: "l3"}},
		endpointRules: []endpointRule{{target: "client_ip", value: "10.9.9.9"}},
		offsetRules:   []offsetRule{{target: "seq", delta: 100}},
	}
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s"}
	patches := assemblePatches(fc, pkt, raw)
	for _, p := range patches {
		if p.Field == "seq" {
			t.Error("seq patch should be skipped when layout.Seq=-1")
		}
	}
	foundTTL := false
	for _, p := range patches {
		if p.Field == "ttl" {
			foundTTL = true
		}
	}
	if !foundTTL {
		t.Error("ttl patch should remain")
	}
}

// =============================================================================
// emitReplayCfg
// =============================================================================

func TestEmitReplayCfg_Success(t *testing.T) {
	fc := &flowCtx{layout: pcapparser.OffsetLayout{SrcIP: 26, L4Protocol: "tcp", L3Start: 14, L4Start: 34}}
	out := make(chan core.PacketConfig, 1)
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", TimestampUs: 1000}
	raw := []byte{0, 1, 2, 3}
	patches := []Patch{{Field: "ttl", Offset: 22, Bytes: []byte{128}, Layer: "l3"}}
	ok := emitReplayCfg(pkt, fc, patches, raw, "recompute", MaxPacer{}, "t1", "cls1", "g1", 0, out, context.Background())
	if !ok {
		t.Fatal("expected true")
	}
	select {
	case cfg := <-out:
		if cfg.Metadata["_replay"] != true {
			t.Error("_replay not true")
		}
		if _, ok := cfg.Metadata["_raw"].([]byte); !ok {
			t.Error("_raw not []byte")
		}
		if _, ok := cfg.Metadata["_patches"].([]Patch); !ok {
			t.Error("_patches not []Patch")
		}
		if cfg.Metadata["_checksum_mode"] != "recompute" {
			t.Errorf("_checksum_mode = %v, want recompute", cfg.Metadata["_checksum_mode"])
		}
		if _, ok := cfg.Metadata["_layout"].(pcapparser.OffsetLayout); !ok {
			t.Error("_layout not OffsetLayout")
		}
		if cfg.Metadata["_pacer"] == nil {
			t.Error("_pacer nil")
		}
		if cfg.Metadata["_task_id"] != "t1" {
			t.Errorf("_task_id = %v, want t1", cfg.Metadata["_task_id"])
		}
	default:
		t.Fatal("no config on channel")
	}
}

func TestEmitReplayCfg_CtxCancelled(t *testing.T) {
	fc := &flowCtx{layout: pcapparser.OffsetLayout{SrcIP: 26}}
	out := make(chan core.PacketConfig) // unbuffered: ctx.Done() wins the select
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", TimestampUs: 1000}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok := emitReplayCfg(pkt, fc, nil, nil, "recompute", MaxPacer{}, "t1", "cls1", "g1", 0, out, ctx)
	if ok {
		t.Error("expected false for cancelled ctx")
	}
	select {
	case <-out:
		t.Error("channel should be empty")
	default:
	}
}

func TestEmitReplayCfg_FieldsMapped(t *testing.T) {
	fc := &flowCtx{layout: pcapparser.OffsetLayout{SrcIP: 26, L4Protocol: "tcp", L3Start: 14, L4Start: 34}}
	out := make(chan core.PacketConfig, 1)
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", TimestampUs: 1000}
	loopBase := 5 * time.Second
	ok := emitReplayCfg(pkt, fc, nil, nil, "recompute", MaxPacer{}, "t1", "cls1", "g1", loopBase, out, context.Background())
	if !ok {
		t.Fatal("expected true")
	}
	cfg := <-out
	if cfg.FlowID != "f1" {
		t.Errorf("FlowID = %q, want f1", cfg.FlowID)
	}
	if cfg.Direction != "up" {
		t.Errorf("Direction = %q, want up", cfg.Direction)
	}
	wantTs := time.UnixMicro(1000).Add(loopBase)
	if !cfg.Timestamp.Equal(wantTs) {
		t.Errorf("Timestamp = %v, want %v", cfg.Timestamp, wantTs)
	}
	if cfg.ClassID != "cls1" {
		t.Errorf("ClassID = %q, want cls1", cfg.ClassID)
	}
}

// =============================================================================
// emitPacket
// =============================================================================

func TestEmitPacket_FlowLookupMiss(t *testing.T) {
	flowMap := map[string]*flowCtx{} // empty: no flow for "ghost"
	raw := make([]byte, 60)
	f := writeTempFrame(t, raw)
	defer f.Close()
	pkt := storage.PacketModel{FlowID: "ghost", Direction: "c2s", Length: len(raw), RawOffset: 0}
	out := make(chan core.PacketConfig, 1)
	ok := emitPacket(pkt, flowMap, f, Clone{}, "recompute", MaxPacer{}, "t", "c", "g1", 0, out, context.Background())
	if !ok {
		t.Error("expected true for flow lookup miss (skip, not error)")
	}
	if len(out) != 0 {
		t.Error("expected no channel write on flow lookup miss")
	}
}

func TestEmitPacket_ReadAtFail(t *testing.T) {
	fc := &flowCtx{layout: pcapparser.OffsetLayout{}}
	flowMap := map[string]*flowCtx{"f1": fc}
	f := writeTempFrame(t, make([]byte, 100)) // only 100 bytes
	defer f.Close()
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", Length: 200, RawOffset: 0} // 200 > 100
	out := make(chan core.PacketConfig, 1)
	ok := emitPacket(pkt, flowMap, f, Clone{}, "recompute", MaxPacer{}, "t", "c", "g1", 0, out, context.Background())
	if !ok {
		t.Error("expected true for ReadAt fail (skip, not error)")
	}
	if len(out) != 0 {
		t.Error("expected no channel write on ReadAt fail")
	}
}

func TestEmitPacket_SeqOffsetApplied(t *testing.T) {
	raw := make([]byte, 60)
	binary.BigEndian.PutUint32(raw[38:42], 4096) // seq=4096 at offset 38
	f := writeTempFrame(t, raw)
	defer f.Close()
	fc := &flowCtx{layout: pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp", L4Start: 34}}
	flowMap := map[string]*flowCtx{"f1": fc}
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", Length: len(raw), RawOffset: 0, TimestampUs: 1000}
	clone := Clone{SeqOffset: 1000}
	out := make(chan core.PacketConfig, 1)
	ok := emitPacket(pkt, flowMap, f, clone, "recompute", MaxPacer{}, "t", "c", "g1", 0, out, context.Background())
	if !ok {
		t.Fatal("expected true")
	}
	cfg := <-out
	patches := cfg.Metadata["_patches"].([]Patch)
	var foundSeq bool
	for _, p := range patches {
		if p.Field == "seq" {
			got := binary.BigEndian.Uint32(p.Bytes)
			if got != 5096 {
				t.Errorf("seq patch = %d, want 5096 (4096+1000)", got)
			}
			foundSeq = true
		}
	}
	if !foundSeq {
		t.Error("no seq patch in emitted config")
	}
}

func TestEmitPacket_CtxCancelPropagate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fc := &flowCtx{layout: pcapparser.OffsetLayout{Seq: 38, L4Protocol: "tcp", L4Start: 34}}
	flowMap := map[string]*flowCtx{"f1": fc}
	raw := make([]byte, 60)
	f := writeTempFrame(t, raw)
	defer f.Close()
	pkt := storage.PacketModel{FlowID: "f1", Direction: "c2s", Length: len(raw), RawOffset: 0}
	out := make(chan core.PacketConfig) // unbuffered: ctx.Done() wins
	ok := emitPacket(pkt, flowMap, f, Clone{}, "recompute", MaxPacer{}, "t", "c", "g1", 0, out, ctx)
	if ok {
		t.Error("expected false for cancelled ctx propagating to emitReplayCfg")
	}
}

// =============================================================================
// Plan / PlanReplay
// =============================================================================

func TestPlanReplay_ValidJSON(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	specJSON, _ := json.Marshal(ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
	})
	ch, err := planner.PlanReplay(context.Background(), specJSON, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("PlanReplay: %v", err)
	}
	if ch == nil {
		t.Fatal("channel is nil")
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 3 {
		t.Errorf("configs = %d, want 3", len(configs))
	}
}

func TestPlanReplay_InvalidJSON(t *testing.T) {
	planner, _, _, _ := setupReplayAsset(t)
	ch, err := planner.PlanReplay(context.Background(), json.RawMessage(`{"bad`), "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("err = %q, want substring 'unmarshal'", err.Error())
	}
	if ch != nil {
		t.Error("channel should be nil on unmarshal error")
	}
}

func TestPlan_AssetNotFound(t *testing.T) {
	planner, _, _, _ := setupReplayAsset(t)
	_, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: "nope",
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("expected error for missing asset")
	}
	if !strings.Contains(err.Error(), "pcap asset") {
		t.Errorf("err = %q, want substring 'pcap asset'", err.Error())
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("err = %v, want errors.Is(gorm.ErrRecordNotFound)", err)
	}
}

func TestPlan_AssetWrongUser(t *testing.T) {
	planner, _, _, _ := setupReplayAsset(t)
	_, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: "ast1",
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u2", nil) // wrong user
	if err == nil {
		t.Fatal("expected error for wrong user")
	}
	if !strings.Contains(err.Error(), "pcap asset") {
		t.Errorf("err = %q, want substring 'pcap asset'", err.Error())
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("err = %v, want errors.Is(gorm.ErrRecordNotFound)", err)
	}
}

func TestPlan_AssetStatusImporting(t *testing.T) {
	planner, db, _, _ := setupReplayAsset(t)
	// Direct DB update: ready->importing is illegal via UpdateAssetStatus.
	db.Model(&storage.PcapAssetModel{}).Where("id = ?", "ast1").Update("status", "importing")
	_, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: "ast1",
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("expected error for importing status")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Errorf("err = %q, want substring 'not ready'", err.Error())
	}
	if !strings.Contains(err.Error(), "importing") {
		t.Errorf("err = %q, want substring 'importing'", err.Error())
	}
}

func TestPlan_AssetStatusError(t *testing.T) {
	planner, db, _, _ := setupReplayAsset(t)
	db.Model(&storage.PcapAssetModel{}).Where("id = ?", "ast1").Update("status", "error")
	_, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: "ast1",
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("expected error for error status")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Errorf("err = %q, want substring 'not ready'", err.Error())
	}
	if !strings.Contains(err.Error(), "error") {
		t.Errorf("err = %q, want substring 'error'", err.Error())
	}
}

func TestPlan_ChecksumModeDefault(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, ChecksumMode: ""}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	if configs[0].Metadata["_checksum_mode"] != "recompute" {
		t.Errorf("_checksum_mode = %v, want recompute (default)", configs[0].Metadata["_checksum_mode"])
	}
}

func TestPlan_ChecksumModePreserve(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, ChecksumMode: "preserve"}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	if configs[0].Metadata["_checksum_mode"] != "preserve" {
		t.Errorf("_checksum_mode = %v, want preserve", configs[0].Metadata["_checksum_mode"])
	}
}

func TestPlan_PacerOriginal(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "original"}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	tp, ok := configs[0].Metadata["_pacer"].(*TimestampPacer)
	if !ok {
		t.Fatalf("expected *TimestampPacer, got %T", configs[0].Metadata["_pacer"])
	}
	if tp.multiplier != 1.0 {
		t.Errorf("multiplier = %v, want 1.0", tp.multiplier)
	}
}

func TestPlan_PacerBPS(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "bps", BPS: "200k"}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	if _, ok := configs[0].Metadata["_pacer"].(*TokenBucketPacer); !ok {
		t.Errorf("expected *TokenBucketPacer, got %T", configs[0].Metadata["_pacer"])
	}
}

func TestPlan_PacerMax(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	if _, ok := configs[0].Metadata["_pacer"].(*MaxPacer); !ok {
		t.Errorf("expected *MaxPacer, got %T", configs[0].Metadata["_pacer"])
	}
}

func TestPlan_PacerEmpty(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) == 0 {
		t.Fatal("no configs")
	}
	if _, ok := configs[0].Metadata["_pacer"].(*MaxPacer); !ok {
		t.Errorf("expected *MaxPacer (empty mode defaults to max), got %T", configs[0].Metadata["_pacer"])
	}
}

func TestPlan_OpenPcapFailed(t *testing.T) {
	planner, db, _, _ := setupReplayAsset(t)
	db.Model(&storage.PcapAssetModel{}).Where("id = ?", "ast1").Update("storage_path", "/nonexistent.pcap")
	ch, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: "ast1",
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("Plan returned nil error for unopenable pcap file (M1: should surface as Plan error, not silent goroutine close)")
	}
	if ch != nil {
		t.Errorf("expected nil channel alongside Plan error")
	}
	if !strings.Contains(err.Error(), "open pcap file") {
		t.Errorf("err = %q, want substring 'open pcap file'", err.Error())
	}
}

func TestPlan_LoopZeroCappedToOne(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, Loop: 0}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 1*time.Second)
	if len(configs) != 3 {
		t.Errorf("configs = %d, want 3 (Loop=0 capped to 1)", len(configs))
	}
}

func TestPlan_LoopThree(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, Loop: 3}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 9 {
		t.Errorf("configs = %d, want 9 (3 packets x 3 loops)", len(configs))
	}
	// pcapDuration = lastTs - firstTs = 3000 - 1000 = 2000us.
	wantDelta := 2000 * time.Microsecond
	got := configs[3].Timestamp.Sub(configs[0].Timestamp)
	if got != wantDelta {
		t.Errorf("configs[3].ts - configs[0].ts = %v, want %v (pcapDuration)", got, wantDelta)
	}
}

func TestPlan_FlowScalingConflictAbort(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		FlowScaling: &FlowScaling{
			Count: 2,
			SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
		},
		Rewrites: []RewriteRule{{Kind: "field", Target: "src_ip", Apply: "set",
			Strategy: core.StrategyConfig{Strategy: "fixed", Value: "11.0.0.1"}}},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err == nil {
		t.Fatal("Plan returned nil error for flow scaling conflict (should surface as Plan error, not silent goroutine close)")
	}
	if ch != nil {
		t.Errorf("expected nil channel alongside Plan error")
	}
	if !strings.Contains(err.Error(), "flow scaling conflict") {
		t.Errorf("err = %q, want substring 'flow scaling conflict'", err.Error())
	}
}

func TestPlan_PerRoundCloneRegeneration(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		Loop:        2,
		FlowScaling: &FlowScaling{
			Count:     1,
			SeqOffset: core.StrategyConfig{Strategy: "fixed", Value: "1000"},
		},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 6 {
		t.Errorf("configs = %d, want 6 (3 packets x 1 clone x 2 loops)", len(configs))
	}
	// Every config should have a seq patch (orig + 1000).
	for i, cfg := range configs {
		patches := cfg.Metadata["_patches"].([]Patch)
		hasSeq := false
		for _, p := range patches {
			if p.Field == "seq" {
				hasSeq = true
			}
		}
		if !hasSeq {
			t.Errorf("config %d: no seq patch", i)
		}
	}
	// Loop timestamp offset: configs[3] is loop 2's first packet.
	wantDelta := 2000 * time.Microsecond
	got := configs[3].Timestamp.Sub(configs[0].Timestamp)
	if got != wantDelta {
		t.Errorf("configs[3].ts - configs[0].ts = %v, want %v", got, wantDelta)
	}
}

func TestPlan_SerialInterleaveOrder(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		FlowScaling: &FlowScaling{
			Count:      2,
			SrcIP:      core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
			DstIP:      core.StrategyConfig{Strategy: "fixed", Value: "22.0.0.1"},
			Interleave: "serial",
		},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 6 {
		t.Errorf("configs = %d, want 6", len(configs))
	}
	cloneIP := func(cfg core.PacketConfig) string {
		patches := cfg.Metadata["_patches"].([]Patch)
		for _, p := range patches {
			if p.Field == "src_ip" {
				return net.IP(p.Bytes).String()
			}
		}
		return ""
	}
	// Serial: first 3 = clone0 (11.0.0.1), last 3 = clone1 (11.0.0.2).
	for i := 0; i < 3; i++ {
		if got := cloneIP(configs[i]); got != "11.0.0.1" {
			t.Errorf("config %d: src_ip = %s, want 11.0.0.1", i, got)
		}
	}
	for i := 3; i < 6; i++ {
		if got := cloneIP(configs[i]); got != "11.0.0.2" {
			t.Errorf("config %d: src_ip = %s, want 11.0.0.2", i, got)
		}
	}
}

func TestPlan_StackModeOrder(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		FlowScaling: &FlowScaling{
			Count: 2,
			SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
			DstIP: core.StrategyConfig{Strategy: "fixed", Value: "22.0.0.1"},
		},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 6 {
		t.Errorf("configs = %d, want 6", len(configs))
	}
	cloneIP := func(cfg core.PacketConfig) string {
		patches := cfg.Metadata["_patches"].([]Patch)
		for _, p := range patches {
			if p.Field == "src_ip" {
				return net.IP(p.Bytes).String()
			}
		}
		return ""
	}
	// Stack: configs 0,2,4 = clone0 (11.0.0.1), configs 1,3,5 = clone1 (11.0.0.2).
	for i, cfg := range configs {
		want := "11.0.0.1"
		if i%2 == 1 {
			want = "11.0.0.2"
		}
		if got := cloneIP(cfg); got != want {
			t.Errorf("config %d: src_ip = %s, want %s", i, got, want)
		}
	}
}

func TestPlan_SerialNoClones(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	// Interleave="serial" but Count=0 -> no clones -> stack branch, 3 configs.
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		FlowScaling: &FlowScaling{Interleave: "serial"},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 3 {
		t.Errorf("configs = %d, want 3 (serial with no clones falls to stack branch)", len(configs))
	}
}

func TestPlan_SerialCtxCancel(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	// Use a large Loop so the goroutine is still emitting when we cancel
	// (the 256-buffer fills, blocking the goroutine so ctx.Done() is observed).
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		Loop:        100,
		FlowScaling: &FlowScaling{
			Count:      2,
			SrcIP:      core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
			Interleave: "serial",
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := planner.Plan(ctx, spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Read first config, then cancel.
	<-ch
	cancel()
	configs := drainTimeout(ch, 1*time.Second)
	// Should NOT get all 600 (3 packets x 2 clones x 100 loops).
	if len(configs) >= 600 {
		t.Errorf("configs = %d, want < 600 (ctx cancel should stop early)", len(configs))
	}
	if ctx.Err() != context.Canceled {
		t.Errorf("ctx.Err = %v, want Canceled", ctx.Err())
	}
}

func TestPlan_StackCtxCancel(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		Loop:        100,
		FlowScaling: &FlowScaling{
			Count: 2,
			SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := planner.Plan(ctx, spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	<-ch
	cancel()
	configs := drainTimeout(ch, 1*time.Second)
	if len(configs) >= 600 {
		t.Errorf("configs = %d, want < 600 (ctx cancel should stop early)", len(configs))
	}
	if ctx.Err() != context.Canceled {
		t.Errorf("ctx.Err = %v, want Canceled", ctx.Err())
	}
}

func TestPlan_CtxCancelBeforeGoroutine(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := planner.Plan(ctx, ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if ch == nil {
		t.Fatal("channel should be non-nil (goroutine checks ctx in loop)")
	}
	configs := drainTimeout(ch, 500*time.Millisecond)
	if len(configs) != 0 {
		t.Errorf("configs = %d, want 0 (ctx pre-cancelled)", len(configs))
	}
}

func TestPlan_StackFlowLookupMiss(t *testing.T) {
	planner, db, assetID, _ := setupReplayAsset(t)
	// Change one packet's FlowID to "ghost" so it's not in the flow map.
	db.Model(&storage.PacketModel{}).Where("pcap_asset_id = ? AND index_in_flow = ?", "ast1", 2).Update("flow_id", "ghost")
	ch, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 2 {
		t.Errorf("configs = %d, want 2 (1 packet skipped: flow lookup miss)", len(configs))
	}
}

func TestPlan_StackReadAtFail(t *testing.T) {
	planner, db, assetID, _ := setupReplayAsset(t)
	// Set one packet's RawOffset beyond EOF so ReadAt fails.
	db.Model(&storage.PacketModel{}).Where("pcap_asset_id = ? AND index_in_flow = ?", "ast1", 2).Update("raw_offset", 999999)
	ch, err := planner.Plan(context.Background(), ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
	}, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 2 {
		t.Errorf("configs = %d, want 2 (1 packet skipped: ReadAt fail)", len(configs))
	}
}

// =============================================================================
// Integration: Plan + ApplyPatches (end-to-end rewrite verification)
// =============================================================================

func TestIntegration_OffsetRewrite(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID:  assetID,
		Speed:        ReplaySpeed{Mode: "max"},
		ChecksumMode: "recompute",
		Rewrites: []RewriteRule{{
			Kind: "field", Target: "seq", Apply: "offset",
			Strategy: core.StrategyConfig{Strategy: "fixed", Value: "1000"},
		}},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 3 {
		t.Fatalf("configs = %d, want 3", len(configs))
	}
	for i, cfg := range configs {
		raw := cfg.Metadata["_raw"].([]byte)
		patches := cfg.Metadata["_patches"].([]Patch)
		layout := cfg.Metadata["_layout"].(pcapparser.OffsetLayout)
		origSeq := binary.BigEndian.Uint32(raw[layout.Seq : layout.Seq+4])
		out, err := ApplyPatches(raw, patches, layout, "recompute")
		if err != nil {
			t.Fatalf("config %d: ApplyPatches: %v", i, err)
		}
		pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			t.Fatalf("config %d: no TCP layer", i)
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.Seq != origSeq+1000 {
			t.Errorf("config %d: seq = %d, want %d (orig+1000)", i, tcp.Seq, origSeq+1000)
		}
	}
}

func TestIntegration_CloneScaling(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		FlowScaling: &FlowScaling{
			Count:     3,
			SrcIP:     core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.100"}, Step: 1},
			SeqOffset: core.StrategyConfig{Strategy: "fixed", Value: "1000"},
		},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	configs := drainTimeout(ch, 2*time.Second)
	if len(configs) != 9 {
		t.Errorf("configs = %d, want 9 (3 packets x 3 clones)", len(configs))
	}
	wantIPs := []string{"11.0.0.1", "11.0.0.2", "11.0.0.3"}
	for i, cfg := range configs {
		patches := cfg.Metadata["_patches"].([]Patch)
		var srcIP string
		hasSeq := false
		for _, p := range patches {
			if p.Field == "src_ip" {
				srcIP = net.IP(p.Bytes).String()
			}
			if p.Field == "seq" {
				hasSeq = true
			}
		}
		want := wantIPs[i%3]
		if srcIP != want {
			t.Errorf("config %d: src_ip = %s, want %s", i, srcIP, want)
		}
		if !hasSeq {
			t.Errorf("config %d: no seq patch (SeqOffset=1000)", i)
		}
	}
}
