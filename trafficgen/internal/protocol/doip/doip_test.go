// Package doip implements the DOIP (Diagnostic over IP, ISO 13400-2) protocol.
package doip

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Test Helpers ---

func ptrBool(b bool) *bool    { return &b }
func ptrUint8(v uint8) *uint8 { return &v }

func makeDoIPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "192.168.1.100",
		DstIP:   "192.168.1.200",
		SrcPort: 50000,
		DstPort: 13400,
		SrcMAC:  "00:11:22:33:44:55",
		DstMAC:  "00:11:22:33:44:66",
		DoIP: &core.DoIPConfig{
			ProtocolVersion: 0x02,
			VIN:             "WL00ABC0000000000",
			LogicalAddress:  0x0001,
			TesterAddress:   0x0E80,
			EID:             "001122334455",
			GID:             "000000000000",
		},
	}
}

func drainChan(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for p := range ch {
		out = append(out, p)
	}
	return out
}

// --- T001-T020: Basic Packet Format ---

// T001: DoIP header 8B V2.
func TestT001_DoIPHeaderV2(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:   "up",
		RequestType: 0x0001,
		Broadcast:   true,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) == 0 {
		t.Fatal("no packets generated")
	}

	payload := packets[0].Payload
	if len(payload) < 8 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	if payload[0] != 0x02 {
		t.Errorf("ProtocolVersion want 0x02, got 0x%02X", payload[0])
	}
	if payload[1] != 0xFD {
		t.Errorf("InverseProtocolVersion want 0xFD, got 0x%02X", payload[1])
	}
	pt := uint16(payload[2])<<8 | uint16(payload[3])
	if pt != PTVehicleIDRequest {
		t.Errorf("PayloadType want 0x%04X, got 0x%04X", PTVehicleIDRequest, pt)
	}
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 0 {
		t.Errorf("PayloadLength want 0, got %d", pl)
	}
}

// T002: InverseProtocolVersion check.
func TestT002_InverseProtocolVersion(t *testing.T) {
	if inverseProtocolVersion(0x02) != 0xFD {
		t.Error("inverse of 0x02 should be 0xFD")
	}
	if inverseProtocolVersion(0x01) != 0xFE {
		t.Error("inverse of 0x01 should be 0xFE")
	}
}

// T003: 0x0001 broadcast discovery.
func TestT003_VehicleIDRequestBroadcast(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:   "up",
		RequestType: 0x0001,
		Broadcast:   true,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 0 {
		t.Errorf("PayloadLength want 0, got %d", pl)
	}
}

// T004: 0x0002 EID discovery.
func TestT004_VehicleIDRequestEID(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:   "up",
		RequestType: 0x0002,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 6 {
		t.Errorf("PayloadLength want 6, got %d", pl)
	}
	if !bytes.Equal(payload[8:14], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("EID mismatch: %x", payload[8:14])
	}
}

// T005: 0x0003 VIN discovery.
func TestT005_VehicleIDRequestVIN(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:   "up",
		RequestType: 0x0003,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 17 {
		t.Errorf("PayloadLength want 17, got %d", pl)
	}
	vin := string(payload[8 : 8+17])
	if vin != "WL00ABC0000000000" {
		t.Errorf("VIN mismatch: %s", vin)
	}
}

// T006: 0x0004 announcement.
func TestT006_VehicleAnnouncement(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:             "down",
		RequestType:           0x0001,
		AnnouncementCount:     1,
		FurtherActionRequired: 0x00,
		SyncStatus:            0x00,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 33 {
		t.Errorf("PayloadLength want 33, got %d", pl)
	}
	far := payload[8+17+2+6+6]
	if far != 0x00 {
		t.Errorf("FurtherActionRequired want 0x00, got 0x%02X", far)
	}
	sync := payload[8+17+2+6+6+1]
	if sync != 0x00 {
		t.Errorf("SyncStatus want 0x00, got 0x%02X", sync)
	}
}

// T007: 0x0004 announcement 3 times.
func TestT007_AnnouncementCount3(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:             "down",
		RequestType:           0x0004,
		AnnouncementCount:     3,
		FurtherActionRequired: 0x00,
		SyncStatus:            0x00,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 3 {
		t.Fatalf("want 3 packets, got %d", len(packets))
	}
	for i, pkt := range packets {
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt != PTVehicleAnnouncement {
			t.Errorf("packet %d: PayloadType want 0x%04X, got 0x%04X", i, PTVehicleAnnouncement, pt)
		}
	}
}

// T008: 0x0005 routing activation.
func TestT008_RoutingActivationRequest(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{
		Direction:      "up",
		ActivationType: 0x00,
		ResponseCode:   0x10,
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	// SYN, SYN-ACK, ACK, 0x0005, 0x0006
	if len(packets) < 5 {
		t.Fatalf("want >= 5 packets, got %d", len(packets))
	}

	// Find 0x0005 packet.
	var raReq *core.PacketConfig
	for i := range packets {
		if len(packets[i].Payload) < 4 {
			continue
		}
		pt := uint16(packets[i].Payload[2])<<8 | uint16(packets[i].Payload[3])
		if pt == PTRoutingActivationReq {
			raReq = &packets[i]
			break
		}
	}
	if raReq == nil {
		t.Fatal("0x0005 packet not found")
	}
	pl := uint32(raReq.Payload[4])<<24 | uint32(raReq.Payload[5])<<16 | uint32(raReq.Payload[6])<<8 | uint32(raReq.Payload[7])
	if pl != 7 {
		t.Errorf("PayloadLength want 7, got %d", pl)
	}
	sa := uint16(raReq.Payload[8])<<8 | uint16(raReq.Payload[9])
	if sa != 0x0E80 {
		t.Errorf("SourceAddress want 0x0E80, got 0x%04X", sa)
	}
	at := raReq.Payload[10]
	if at != 0x00 {
		t.Errorf("ActivationType want 0x00, got 0x%02X", at)
	}
}

// T009: 0x0006 Success.
func TestT009_RoutingActivationResponseSuccess(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{
		Direction:      "up",
		ActivationType: 0x00,
		ResponseCode:   0x10,
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var raResp *core.PacketConfig
	for i := range packets {
		if len(packets[i].Payload) < 4 {
			continue
		}
		pt := uint16(packets[i].Payload[2])<<8 | uint16(packets[i].Payload[3])
		if pt == PTRoutingActivationResp {
			raResp = &packets[i]
			break
		}
	}
	if raResp == nil {
		t.Fatal("0x0006 packet not found")
	}
	pl := uint32(raResp.Payload[4])<<24 | uint32(raResp.Payload[5])<<16 | uint32(raResp.Payload[6])<<8 | uint32(raResp.Payload[7])
	if pl != 9 {
		t.Errorf("PayloadLength want 9, got %d", pl)
	}
	rc := raResp.Payload[12]
	if rc != 0x10 {
		t.Errorf("ResponseCode want 0x10, got 0x%02X", rc)
	}
}

// T010: 0x0007 alive check request.
func TestT010_AliveCheckRequest(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.AliveCheck = &core.DoIPAliveCheck{Direction: "down"}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var found bool
	for _, pkt := range packets {
		if len(pkt.Payload) < 4 {
			continue
		}
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt == PTAliveCheckRequest {
			found = true
			pl := uint32(pkt.Payload[4])<<24 | uint32(pkt.Payload[5])<<16 | uint32(pkt.Payload[6])<<8 | uint32(pkt.Payload[7])
			if pl != 0 {
				t.Errorf("PayloadLength want 0, got %d", pl)
			}
		}
	}
	if !found {
		t.Fatal("0x0007 packet not found")
	}
}

// T011: 0x0008 alive check response.
func TestT011_AliveCheckResponse(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.AliveCheck = &core.DoIPAliveCheck{Direction: "up", SourceAddress: 0x0E80}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var found bool
	for _, pkt := range packets {
		if len(pkt.Payload) < 4 {
			continue
		}
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt == PTAliveCheckResponse {
			found = true
			pl := uint32(pkt.Payload[4])<<24 | uint32(pkt.Payload[5])<<16 | uint32(pkt.Payload[6])<<8 | uint32(pkt.Payload[7])
			if pl != 2 {
				t.Errorf("PayloadLength want 2, got %d", pl)
			}
			sa := uint16(pkt.Payload[8])<<8 | uint16(pkt.Payload[9])
			if sa != 0x0E80 {
				t.Errorf("SourceAddress want 0x0E80, got 0x%04X", sa)
			}
		}
	}
	if !found {
		t.Fatal("0x0008 packet not found")
	}
}

// T012: 0x4001 Entity Status request.
func TestT012_EntityStatusRequest(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.EntityStatus = &core.DoIPEntityStatus{Direction: "up"}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	pt := uint16(packets[0].Payload[2])<<8 | uint16(packets[0].Payload[3])
	if pt != PTEntityStatusRequest {
		t.Errorf("PayloadType want 0x%04X, got 0x%04X", PTEntityStatusRequest, pt)
	}
	pl := uint32(packets[0].Payload[4])<<24 | uint32(packets[0].Payload[5])<<16 | uint32(packets[0].Payload[6])<<8 | uint32(packets[0].Payload[7])
	if pl != 0 {
		t.Errorf("PayloadLength want 0, got %d", pl)
	}
}

// T013: 0x4002 Entity Status response.
func TestT013_EntityStatusResponse(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.EntityStatus = &core.DoIPEntityStatus{
		Direction:      "down",
		NodeType:       0x01,
		MaxOpenSockets: 1,
		CurOpenSockets: 1,
		MaxDataSize:    4095,
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 7 {
		t.Errorf("PayloadLength want 7, got %d", pl)
	}
	if payload[8] != 0x01 {
		t.Errorf("NodeType want 0x01, got 0x%02X", payload[8])
	}
	mds := uint32(payload[11])<<24 | uint32(payload[12])<<16 | uint32(payload[13])<<8 | uint32(payload[14])
	if mds != 4095 {
		t.Errorf("MaxDataSize want 4095, got %d", mds)
	}
}

// T014: 0x4003 Power Mode request.
func TestT014_PowerModeRequest(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.PowerMode = &core.DoIPPowerMode{Direction: "up"}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	pt := uint16(packets[0].Payload[2])<<8 | uint16(packets[0].Payload[3])
	if pt != PTPowerModeRequest {
		t.Errorf("PayloadType want 0x%04X, got 0x%04X", PTPowerModeRequest, pt)
	}
	pl := uint32(packets[0].Payload[4])<<24 | uint32(packets[0].Payload[5])<<16 | uint32(packets[0].Payload[6])<<8 | uint32(packets[0].Payload[7])
	if pl != 0 {
		t.Errorf("PayloadLength want 0, got %d", pl)
	}
}

// T015: 0x4004 Power Mode response.
func TestT015_PowerModeResponse(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.PowerMode = &core.DoIPPowerMode{Direction: "down", PowerMode: 0x01}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	payload := packets[0].Payload
	pl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if pl != 1 {
		t.Errorf("PayloadLength want 1, got %d", pl)
	}
	if payload[8] != 0x01 {
		t.Errorf("PowerMode want 0x01, got 0x%02X", payload[8])
	}
}

// T016: 0x8001 diagnostic message.
func TestT016_DiagnosticMessage(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: []byte{0x10, 0x03}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var found bool
	for _, pkt := range packets {
		if len(pkt.Payload) < 4 {
			continue
		}
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt == PTDiagnosticMessage {
			found = true
			pl := uint32(pkt.Payload[4])<<24 | uint32(pkt.Payload[5])<<16 | uint32(pkt.Payload[6])<<8 | uint32(pkt.Payload[7])
			if pl != 6 {
				t.Errorf("PayloadLength want 6, got %d", pl)
			}
			sa := uint16(pkt.Payload[8])<<8 | uint16(pkt.Payload[9])
			if sa != 0x0E80 {
				t.Errorf("SA want 0x0E80, got 0x%04X", sa)
			}
			ta := uint16(pkt.Payload[10])<<8 | uint16(pkt.Payload[11])
			if ta != 0x0001 {
				t.Errorf("TA want 0x0001, got 0x%04X", ta)
			}
			if !bytes.Equal(pkt.Payload[12:14], []byte{0x10, 0x03}) {
				t.Errorf("UserData want 10 03, got %x", pkt.Payload[12:14])
			}
		}
	}
	if !found {
		t.Fatal("0x8001 packet not found")
	}
}

// T017: 0x8002 Ack.
func TestT017_DiagnosticMessageAck(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: []byte{0x10, 0x03}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var found bool
	for _, pkt := range packets {
		if len(pkt.Payload) < 4 {
			continue
		}
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt == PTDiagnosticMessageAck {
			found = true
			pl := uint32(pkt.Payload[4])<<24 | uint32(pkt.Payload[5])<<16 | uint32(pkt.Payload[6])<<8 | uint32(pkt.Payload[7])
			if pl != 7 {
				t.Errorf("PayloadLength want 7, got %d", pl)
			}
			ackCode := pkt.Payload[12]
			if ackCode != 0x00 {
				t.Errorf("AckCode want 0x00, got 0x%02X", ackCode)
			}
			if !bytes.Equal(pkt.Payload[13:15], []byte{0x10, 0x03}) {
				t.Errorf("PreviousDiagnosticMessage want 10 03, got %x", pkt.Payload[13:15])
			}
		}
	}
	if !found {
		t.Fatal("0x8002 packet not found")
	}
}

// T018: 0x8003 Nack.
func TestT018_DiagnosticMessageNack(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: []byte{0x22, 0xF1, 0x90}, NackCode: ptrUint8(0x02)},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)

	var found bool
	for _, pkt := range packets {
		if len(pkt.Payload) < 4 {
			continue
		}
		pt := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])
		if pt == PTDiagnosticMessageNack {
			found = true
			pl := uint32(pkt.Payload[4])<<24 | uint32(pkt.Payload[5])<<16 | uint32(pkt.Payload[6])<<8 | uint32(pkt.Payload[7])
			if pl != 8 {
				t.Errorf("PayloadLength want 8, got %d", pl)
			}
			nc := pkt.Payload[12]
			if nc != 0x02 {
				t.Errorf("NackCode want 0x02, got 0x%02X", nc)
			}
		}
	}
	if !found {
		t.Fatal("0x8003 packet not found")
	}
}

// T019: 0x0000 Generic NACK.
func TestT019_GenericNack(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.GenericNack = &core.DoIPGenericNack{NackCode: 0x01}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	if len(packets) != 1 {
		t.Fatalf("want 1 packet, got %d", len(packets))
	}
	pt := uint16(packets[0].Payload[2])<<8 | uint16(packets[0].Payload[3])
	if pt != PTGenericNack {
		t.Errorf("PayloadType want 0x%04X, got 0x%04X", PTGenericNack, pt)
	}
	pl := uint32(packets[0].Payload[4])<<24 | uint32(packets[0].Payload[5])<<16 | uint32(packets[0].Payload[6])<<8 | uint32(packets[0].Payload[7])
	if pl != 1 {
		t.Errorf("PayloadLength want 1, got %d", pl)
	}
	if packets[0].Payload[8] != 0x01 {
		t.Errorf("NackCode want 0x01, got 0x%02X", packets[0].Payload[8])
	}
}

// T020: default Direction empty.
func TestT020_DefaultDirection(t *testing.T) {
	if defaultDirection(PTVehicleIDRequest) != dirUp {
		t.Error("0x0001 default direction should be up")
	}
	if defaultDirection(PTVehicleAnnouncement) != dirDown {
		t.Error("0x0004 default direction should be down")
	}
}
