package igmp

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildV1GeneralQuery(t *testing.T) {
	// v1 general query: type=0x11 maxresp=0 group=0.0.0.0, checksum correct.
	msg, err := buildIGMPMessage("v1", "query", "0.0.0.0", 0, 0, 0, 0, 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 8 {
		t.Fatalf("len=%d want 8", len(msg))
	}
	if msg[0] != 0x11 {
		t.Fatalf("type=%02x want 0x11", msg[0])
	}
	if msg[1] != 0 {
		t.Fatalf("maxresp=%d want 0", msg[1])
	}
	// checksum 0xeeff (verified against tshark)
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0xeeff {
		t.Fatalf("checksum=%04x want eeff", got)
	}
}

func TestBuildV2GroupQueryMaxResp(t *testing.T) {
	// v2 group-specific query: type=0x11 maxresp=10 group=239.1.1.1
	msg, err := buildIGMPMessage("v2", "query", "239.1.1.1", 10, 0, 0, 0, 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != 0x11 || msg[1] != 10 {
		t.Fatalf("type/maxresp=%02x/%d want 11/10", msg[0], msg[1])
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0xfef2 {
		t.Fatalf("checksum=%04x want fef2", got)
	}
}

func TestBuildV2Report(t *testing.T) {
	msg, err := buildIGMPMessage("v2", "report", "239.1.1.1", 0, 0, 0, 0, 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != 0x16 {
		t.Fatalf("type=%02x want 0x16", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0xf9fc {
		t.Fatalf("checksum=%04x want f9fc", got)
	}
}

func TestBuildV2Leave(t *testing.T) {
	msg, err := buildIGMPMessage("v2", "leave", "239.1.1.1", 0, 0, 0, 0, 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != 0x17 {
		t.Fatalf("type=%02x want 0x17", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0xf8fc {
		t.Fatalf("checksum=%04x want f8fc", got)
	}
}

func TestBuildV3GeneralQuery(t *testing.T) {
	// v3 general query: mrc=10, S=0, QRV=2, QQIC=125, 0 sources.
	msg, err := buildIGMPMessage("v3", "query", "0.0.0.0", 0, 10, 0, 2, 125, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 8 + 4 // header + body
	if len(msg) != wantLen {
		t.Fatalf("len=%d want %d", len(msg), wantLen)
	}
	if msg[0] != 0x11 || msg[1] != 10 {
		t.Fatalf("type/mrc=%02x/%d want 11/10", msg[0], msg[1])
	}
	if msg[8] != 0x02 { // (S<<3)|QRV = (0<<3)|2
		t.Fatalf("body[0]=%02x want 02", msg[8])
	}
	if msg[9] != 125 {
		t.Fatalf("qqic=%d want 125", msg[9])
	}
	if got := binary.BigEndian.Uint16(msg[10:12]); got != 0 {
		t.Fatalf("num_src=%d want 0", got)
	}
}

func TestBuildV3SourceSpecificQuery(t *testing.T) {
	srcs := []string{"198.51.100.1", "198.51.100.2"}
	msg, err := buildIGMPMessage("v3", "query", "239.1.1.1", 0, 10, 0, 2, 125, nil, srcs, "")
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 8 + 4 + 8
	if len(msg) != wantLen {
		t.Fatalf("len=%d want %d", len(msg), wantLen)
	}
	if got := binary.BigEndian.Uint16(msg[10:12]); got != 2 {
		t.Fatalf("num_src=%d want 2", got)
	}
	if string(msg[12:16]) != string([]byte{198, 51, 100, 1}) {
		t.Fatalf("src1=% x", msg[12:16])
	}
}

func TestBuildV3IncludeRecord(t *testing.T) {
	recs := []core.IGMPRecord{{RecordType: "mode_is_include", Group: "239.1.1.2", Sources: []string{"198.51.100.1"}}}
	msg, err := buildIGMPMessage("v3", "report", "239.1.1.2", 0, 0, 0, 0, 0, recs, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// 8 header + 8 rec + 4 src
	if len(msg) != 20 {
		t.Fatalf("len=%d want 20", len(msg))
	}
	if msg[0] != 0x22 {
		t.Fatalf("type=%02x want 0x22", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 1 {
		t.Fatalf("num_grp_recs=%d want 1", got)
	}
	if msg[8] != 1 {
		t.Fatalf("record_type=%d want 1 (mode_is_include)", msg[8])
	}
	if got := binary.BigEndian.Uint16(msg[10:12]); got != 1 {
		t.Fatalf("num_src=%d want 1", got)
	}
}

func TestBuildReorderRecordTypes(t *testing.T) {
	recs := []core.IGMPRecord{
		{RecordType: "change_to_include_mode", Group: "239.1.1.1"},
		{RecordType: "change_to_exclude_mode", Group: "239.1.1.2"},
		{RecordType: "allow_new_sources", Group: "239.1.1.3"},
		{RecordType: "block_old_sources", Group: "239.1.1.4"},
	}
	msg, err := buildIGMPMessage("v3", "report", "239.1.1.1", 0, 0, 0, 0, 0, recs, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 4 {
		t.Fatalf("num_grp_recs=%d want 4", got)
	}
	// record types at every 8 bytes (each record is 8B base + 4B per source;
	// these records have 0 sources so 8B each): 3,4,5,6
	want := []byte{3, 4, 5, 6}
	for i, rt := range want {
		if msg[8+i*8] != rt {
			t.Fatalf("record[%d].type=%02x want %02x", i, msg[8+i*8], rt)
		}
	}
}

func TestChecksumModeZero(t *testing.T) {
	msg, err := buildIGMPMessage("v2", "report", "239.1.1.1", 0, 0, 0, 0, 0, nil, nil, "zero")
	if err != nil {
		t.Fatal(err)
	}
	if msg[2] != 0 || msg[3] != 0 {
		t.Fatalf("checksum=%02x%02x want 0000 (zero mode)", msg[2], msg[3])
	}
}

func TestValidateRejectsIPv6(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{IGMP: &core.IGMPConfig{AddressFamily: "ipv6"}})
	if err == nil || !contains(err.Error(), "IPv6") {
		t.Fatalf("err=%v want IPv6", err)
	}
}

func TestValidateRejectsNonMulticastDst(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{DstIP: "192.0.2.1", IGMP: &core.IGMPConfig{}})
	if err == nil || !contains(err.Error(), "multicast") {
		t.Fatalf("err=%v want multicast", err)
	}
}

func TestValidateRejectsBadTTL(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{DstIP: "224.0.0.1", TTL: 2, IGMP: &core.IGMPConfig{}})
	if err == nil || !contains(err.Error(), "TTL") {
		t.Fatalf("err=%v want TTL", err)
	}
}

func TestValidateRejectsProfileKindMismatch(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{DstIP: "224.0.0.1", IGMP: &core.IGMPConfig{Profile: "v1", Kind: "leave"}})
	if err == nil || !contains(err.Error(), "profile") {
		t.Fatalf("err=%v want profile", err)
	}
}

func TestGenerateEmitsFullPacket(t *testing.T) {
	var pkt core.PacketConfig
	err := (&IGMPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SrcIP: "192.0.2.10", DstIP: "224.0.0.1", TTL: 1, IGMP: &core.IGMPConfig{Profile: "v1", Kind: "query", Group: "0.0.0.0"}},
		Emit: func(p core.PacketConfig) error { pkt = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.L3.Protocol != core.ProtocolIGMP {
		t.Fatalf("L3.Protocol=%d want 2", pkt.L3.Protocol)
	}
	if pkt.L3.SrcIP != "192.0.2.10" {
		t.Fatalf("src=%q", pkt.L3.SrcIP)
	}
	if pkt.L3.TTL != 1 {
		t.Fatalf("ttl=%d want 1", pkt.L3.TTL)
	}
	if len(pkt.Payload) != 8 {
		t.Fatalf("payload len=%d want 8", len(pkt.Payload))
	}
}

func TestGenerateEventSequence(t *testing.T) {
	evs := []core.IGMPEvent{
		{Profile: "v2", Kind: "query", Group: "0.0.0.0"},
		{Profile: "v2", Kind: "report", Group: "239.1.1.1"},
	}
	var count int
	err := (&IGMPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SrcIP: "192.0.2.10", IGMP: &core.IGMPConfig{Events: evs}},
		Emit: func(p core.PacketConfig) error { count++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("emitted=%d want 2", count)
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("igmp")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "igmp" {
		t.Fatalf("name=%q", g.Name())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
