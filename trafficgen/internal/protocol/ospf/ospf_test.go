package ospf

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestHelloLayoutFromProbe(t *testing.T) {
	// Verified against tshark probe: body at offset 24 =
	// mask(4)@24 hello_interval(2)@28 options(1)@30 priority(1)@31 dead(4)@32 dr(4)@36 bdr(4)@40 nbr(4)@44
	cfg := &core.OSPFConfig{
		Version: 2, PacketType: "hello", RouterID: "1.1.1.1", AreaID: "0.0.0.0",
		NetworkMask: "255.255.255.0", HelloInterval: 10, Options: 2, Priority: 1,
		DeadInterval: 40, DesignatedRouter: "10.0.0.2", BackupDesignatedRouter: "10.0.0.3",
		Neighbors: []string{"2.2.2.2"},
	}
	msg, _ := buildFromConfig(cfg)
	if binary.BigEndian.Uint16(msg[28:30]) != 10 {
		t.Fatalf("hello_interval=%d want 10", binary.BigEndian.Uint16(msg[28:30]))
	}
	if msg[30] != 2 {
		t.Fatalf("options=%d want 2", msg[30])
	}
	if msg[31] != 1 {
		t.Fatalf("priority=%d want 1", msg[31])
	}
	if binary.BigEndian.Uint32(msg[32:36]) != 40 {
		t.Fatalf("dead=%d want 40", binary.BigEndian.Uint32(msg[32:36]))
	}
	if string(msg[36:40]) != string([]byte{10, 0, 0, 2}) {
		t.Fatalf("dr=% x", msg[36:40])
	}
	if string(msg[44:48]) != string([]byte{2, 2, 2, 2}) {
		t.Fatalf("neighbor=% x", msg[44:48])
	}
}

func TestBuildDBDescription(t *testing.T) {
	cfg := &core.OSPFConfig{
		Version: 2, PacketType: "db_description", RouterID: "1.1.1.1", AreaID: "0.0.0.0",
		InterfaceMTU: 1500, Options: 2, Flags: &core.OSPFDDFlags{Init: true, More: true, Master: true},
		DDSequence: 100,
		LSAHeaders: []core.OSPFLSAHeader{{Age: 1, LSAType: 1, LinkStateID: "1.1.1.1", AdvertisingRouter: "1.1.1.1", Sequence: "0x80000001", Length: 36}},
	}
	msg, _ := buildFromConfig(cfg)
	// packet_length = 24 hdr + 8 dd body + 20 lsa header = 52
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 52 {
		t.Fatalf("packet_length=%d want 52", got)
	}
	if msg[1] != 2 {
		t.Fatalf("type=%d want 2", msg[1])
	}
	if binary.BigEndian.Uint16(msg[24:26]) != 1500 {
		t.Fatalf("mtu=%d want 1500", binary.BigEndian.Uint16(msg[24:26]))
	}
	if msg[27] != 0x07 { // flags: init(0x4)|more(0x2)|master(0x1)
		t.Fatalf("flags=%02x want 0x07", msg[27])
	}
	if binary.BigEndian.Uint32(msg[28:32]) != 100 {
		t.Fatalf("dd_sequence=%d want 100", binary.BigEndian.Uint32(msg[28:32]))
	}
	// lsa header at offset 32: type(1)@35
	if msg[35] != 1 {
		t.Fatalf("lsa type=%d want 1", msg[35])
	}
}

func TestBuildLSR(t *testing.T) {
	cfg := &core.OSPFConfig{
		Version: 2, PacketType: "link_state_request", RouterID: "2.2.2.2", AreaID: "0.0.0.0",
		Requests: []core.OSPFRequest{{LSAType: 1, LinkStateID: "1.1.1.1", AdvertisingRouter: "1.1.1.1"}},
	}
	msg, _ := buildFromConfig(cfg)
	// 24 hdr + 12 request = 36
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 36 {
		t.Fatalf("packet_length=%d want 36", got)
	}
	if msg[1] != 3 {
		t.Fatalf("type=%d want 3", msg[1])
	}
	// request at offset 24: type(4)@24
	if binary.BigEndian.Uint32(msg[24:28]) != 1 {
		t.Fatalf("req type=%d want 1", binary.BigEndian.Uint32(msg[24:28]))
	}
}

func TestBuildLSURouterLSA(t *testing.T) {
	cfg := &core.OSPFConfig{
		Version: 2, PacketType: "link_state_update", RouterID: "1.1.1.1", AreaID: "0.0.0.0",
		LSAs: []core.OSPFLSA{{
			Age: 1, Options: 0, LSAType: 1, LinkStateID: "1.1.1.1",
			AdvertisingRouter: "1.1.1.1", Sequence: "0x80000001", Length: 36,
			Flags: 0, Links: []core.OSPFLink{{LinkID: "10.0.0.2", LinkData: "255.255.255.0", LinkType: 2, Metric: 10}},
		}},
	}
	msg, _ := buildFromConfig(cfg)
	// 24 hdr + 4 count + 20 lsa hdr + 16 router body = 64
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 64 {
		t.Fatalf("packet_length=%d want 64", got)
	}
	if msg[1] != 4 {
		t.Fatalf("type=%d want 4", msg[1])
	}
	if binary.BigEndian.Uint32(msg[24:28]) != 1 {
		t.Fatalf("lsa_count=%d want 1", binary.BigEndian.Uint32(msg[24:28]))
	}
	// lsa header at 28: age(2)@28, opt@30, type@31, len@46:48
	if msg[31] != 1 {
		t.Fatalf("lsa type=%d want 1", msg[31])
	}
	if binary.BigEndian.Uint16(msg[46:48]) != 36 {
		t.Fatalf("lsa length=%d want 36", binary.BigEndian.Uint16(msg[46:48]))
	}
	// router body at 48: flags@48, numlinks@50:52, link type@...
	if msg[48] != 0 {
		t.Fatalf("flags=%d want 0", msg[48])
	}
	// link: link_id(4)@52 link_data(4)@56 type(1)@60 metric(2)@62
	if msg[60] != 2 {
		t.Fatalf("link type=%d want 2", msg[60])
	}
	if binary.BigEndian.Uint16(msg[62:64]) != 10 {
		t.Fatalf("metric=%d want 10", binary.BigEndian.Uint16(msg[62:64]))
	}
}

func TestBuildLSUNetworkLSA(t *testing.T) {
	cfg := &core.OSPFConfig{
		Version: 2, PacketType: "link_state_update", RouterID: "1.1.1.1", AreaID: "0.0.0.0",
		LSAs: []core.OSPFLSA{{
			Age: 1, Options: 0, LSAType: 2, LinkStateID: "10.0.0.2",
			AdvertisingRouter: "1.1.1.1", Sequence: "0x80000001", Length: 32,
			NetworkMask: "255.255.255.0", AttachedRouters: []string{"1.1.1.1", "2.2.2.2"},
		}},
	}
	msg, _ := buildFromConfig(cfg)
	// 24 + 4 + 20 + (4 mask + 8 routers) = 60
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 60 {
		t.Fatalf("packet_length=%d want 60", got)
	}
	if binary.BigEndian.Uint16(msg[46:48]) != 32 {
		t.Fatalf("lsa length=%d want 32", binary.BigEndian.Uint16(msg[46:48]))
	}
	// network body at 48: mask(4)@48 then routers
	if string(msg[48:52]) != string([]byte{255, 255, 255, 0}) {
		t.Fatalf("mask=% x", msg[48:52])
	}
}

func TestValidateRejectsIPv6Version(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{OSPF: &core.OSPFConfig{Version: 3, PacketType: "hello"}})
	if err == nil || !containsOspf(err.Error(), "rfc5340") {
		t.Fatalf("err=%v want rfc5340", err)
	}
}

func TestValidateRejectsBadPacketType(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{OSPF: &core.OSPFConfig{Version: 2, PacketType: "unknown"}})
	if err == nil || !containsOspf(err.Error(), "type") {
		t.Fatalf("err=%v want type", err)
	}
}

func TestValidateRejectsBadRouterID(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{OSPF: &core.OSPFConfig{Version: 2, PacketType: "hello", RouterID: "not-an-ip"}})
	if err == nil || !containsOspf(err.Error(), "router") {
		t.Fatalf("err=%v want router", err)
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("ospf")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "ospf" {
		t.Fatalf("name=%q", g.Name())
	}
}

func TestGenerateEmitsPacket(t *testing.T) {
	var pkt core.PacketConfig
	err := (&OSPFGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "224.0.0.5", OSPF: &core.OSPFConfig{
			Version: 2, PacketType: "hello", RouterID: "1.1.1.1", AreaID: "0.0.0.0",
			NetworkMask: "255.255.255.0", HelloInterval: 10,
		}},
		Emit: func(p core.PacketConfig) error { pkt = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.L3.Protocol != core.ProtocolOSPF {
		t.Fatalf("proto=%d want 89", pkt.L3.Protocol)
	}
	if pkt.L3.TTL != 1 {
		t.Fatalf("ttl=%d want 1", pkt.L3.TTL)
	}
	if len(pkt.Payload) < 24 {
		t.Fatalf("payload len=%d", len(pkt.Payload))
	}
}

func containsOspf(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
