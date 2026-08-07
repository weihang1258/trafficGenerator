// Additional DOIP validation tests (T021-T050).
package doip

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Validation Tests ---

func TestValidate_InvalidProtocolVersion(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	// PV=0x00 is treated as "unset → default V2" per §1.3 line 94
	// ("默认 V2"). The struct field is uint8 (non-pointer), so Go's
	// zero value (0) is indistinguishable from an explicit 0x00. The
	// implementation follows §1.3 line 94's "default V2" semantics.
	// Only 0x03/0x04-0xFE are rejected per §1.3 line 95.
	spec.DoIP.ProtocolVersion = 0x03
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for PV=0x03")
	}
}

func TestValidate_V1OEMRejection(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.ProtocolVersion = 0x01
	spec.DoIP.Activation = &core.DoIPActivation{
		Direction:      "up",
		ActivationType: 0x00,
		ResponseCode:   0x10,
		OEMSpecific:    []byte{0x01, 0x02, 0x03, 0x04},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for V1+OEM")
	}
}

func TestValidate_V1PowerModeRejection(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.ProtocolVersion = 0x01
	spec.DoIP.PowerMode = &core.DoIPPowerMode{Direction: "up"}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for V1+PowerMode")
	}
}

func TestValidate_FurtherActionRequired(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:             "down",
		RequestType:           0x0004,
		FurtherActionRequired: 0x11,
		SyncStatus:            0x00,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for FAR=0x11")
	}
}

func TestValidate_SyncStatus(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Discovery = &core.DoIPDiscovery{
		Direction:   "down",
		RequestType: 0x0004,
		SyncStatus:  0x01,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for SyncStatus=0x01")
	}
}

func TestValidate_ActivationType(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{
		Direction:      "up",
		ActivationType: 0x02,
		ResponseCode:   0x10,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for ActivationType=0x02")
	}
}

func TestValidate_ResponseCode(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{
		Direction:      "up",
		ActivationType: 0x00,
		ResponseCode:   0x12,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for ResponseCode=0x12")
	}
}

func TestValidate_PowerMode(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.PowerMode = &core.DoIPPowerMode{Direction: "down", PowerMode: 0x03}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for PowerMode=0x03")
	}
}

func TestValidate_NackCode(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", NackCode: ptrUint8(0x00)},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for NackCode=0x00")
	}
}

func TestValidate_EntityStatus(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.EntityStatus = &core.DoIPEntityStatus{
		Direction:      "down",
		NodeType:       0x02,
		MaxOpenSockets: 1,
		CurOpenSockets: 1,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for NodeType=0x02")
	}
}

func TestValidate_CurOpenSockets(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.EntityStatus = &core.DoIPEntityStatus{
		Direction:      "down",
		NodeType:       0x01,
		MaxOpenSockets: 1,
		CurOpenSockets: 2,
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for CurOpenSockets > MaxOpenSockets")
	}
}

func TestValidate_UDSUnsupportedSID(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UDS: &core.DoIPUDS{ServiceID: 0xFF}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for unsupported SID=0xFF")
	}
}

func TestValidate_UDSInvalidNRC(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	// H6: NRC must be 0x01..0x7F. The struct field is uint8, so 0 means
	// "no NRC" (per §3.1 struct comment "非 0 → 生成否定响应"). Only
	// 0x80..0xFF (and 0x00 when explicitly set, which uint8 cannot
	// express) are rejected. Test the lower boundary 0x80.
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UDS: &core.DoIPUDS{ServiceID: 0x10, NegativeResponseCode: 0x80}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for NRC=0x80")
	}
}

func TestValidate_UDSInvalidNRCUpper(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UDS: &core.DoIPUDS{ServiceID: 0x10, NegativeResponseCode: 0xFF}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for NRC=0xFF")
	}
}

func TestValidate_HasSubFunction(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	trueVal := true
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UDS: &core.DoIPUDS{ServiceID: 0x22, HasSubFunction: &trueVal}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for HasSubFunction=true on SID=0x22")
	}
}

func TestValidate_UDSKeyOnEvenResponse(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UDS: &core.DoIPUDS{ServiceID: 0x27, IsResponse: true, SubFunction: 0x02, Key: []byte{0x55}}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for Key on even sub-function response")
	}
}

func TestValidate_MaxDataSize(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.EntityStatus = &core.DoIPEntityStatus{MaxDataSize: 100}
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	bigData := make([]byte, 200)
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: bigData},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for UserData > MaxDataSize")
	}
}

func TestValidate_AckCode(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", AckCode: 0x01},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for AckCode=0x01")
	}
}

func TestValidate_MSS(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.TCP = &core.TCPConfig{MSS: 100}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for MSS=100 (< MinMSS)")
	}
}

// T163: Messages without Activation must be rejected (section 4.4 requires
// routing activation success before diagnostic messages).
func TestValidate_MessagesRequireActivation(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: []byte{0x10, 0x03}},
	}
	// Activation deliberately left nil.
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for Messages without Activation")
	}
}

// T068: UserData exceeding u32 PayloadLength must be rejected
// (section 6.13.8 PayloadLength u32 overflow guard).
func TestValidate_UserDataU32Overflow(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	// MaxUint32-5+1 = 4294967292 bytes is past the limit.
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "up", UserData: make([]byte, 4294967292)},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for UserData > u32 PayloadLength")
	}
}

// Broadcast destination override (section 3.3, testcase T107/T108/T131/T132).
// Verifies that Discovery.Broadcast=true rewrites the DstIP/DstMAC of the
// Tester->ECU request frame to 255.255.255.255 / ff:ff:ff:ff:ff:ff while
// keeping the ECU->Tester announcement unicast.
func TestPlan_DiscoveryBroadcastOverridesDst(t *testing.T) {
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
	if packets[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("Broadcast DstIP want 255.255.255.255, got %q", packets[0].L3.DstIP)
	}
	if got, want := strings.ToUpper(packets[0].L2.DstMAC), "FF:FF:FF:FF:FF:FF"; got != want {
		t.Errorf("Broadcast DstMAC want %s, got %s", want, got)
	}
}

// TCP sequence monotonicity (T175 阶段顺序 / S15 faithful flow): after the
// 3-way handshake, the routing-activation 0x0005 must carry a Seq equal to
// client ISN+1, not the hard-coded 0 that breaks Wireshark's stream.
func TestPlan_ActivationDataSegmentsKeepTcpSeq(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
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
	if raReq.L4.Seq == 0 {
		t.Errorf("0x0005 Seq should be non-zero (ISN+1), got 0")
	}
	if raReq.L4.Ack == 0 {
		t.Errorf("0x0005 Ack should be non-zero (ISN+1), got 0")
	}
}

// Ack opposite-direction inversion (section 2.14/2.15 + section 4.4):
// a 0x8001 with Direction="down" must be followed by a 0x8002 with
// Direction="up" (Tester replies to ECU's diagnosis frame).
func TestPlan_DownMessageAckDirectionFlips(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.DoIP.Messages = []core.DoIPMessage{
		{Direction: "down", UserData: []byte{0x10, 0x03}},
	}
	spec.TCP = &core.TCPConfig{MSS: 1460}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	var ack *core.PacketConfig
	for i := range packets {
		if len(packets[i].Payload) < 4 {
			continue
		}
		pt := uint16(packets[i].Payload[2])<<8 | uint16(packets[i].Payload[3])
		if pt == PTDiagnosticMessageAck {
			ack = &packets[i]
			break
		}
	}
	if ack == nil {
		t.Fatal("0x8002 ack not found")
	}
	if ack.Direction != "up" {
		t.Errorf("Ack direction must be up (Tester -> ECU), got %q", ack.Direction)
	}
}

// TCP teardown (section 6.15: 3 packets, FIN/FIN-ACK/ACK) emitted after
// successful activation when termination is enabled. The 3-way handshake
// (SYN/SYN-ACK/ACK) carries no FIN flag, so the teardown contributes the
// only 2 FIN-flagged frames (FIN + FIN-ACK); the final ACK is flag 0x10.
func TestPlan_TCPTearDownEmittedByDefault(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.TCP = &core.TCPConfig{MSS: 1460, Termination: true}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	finCount := 0
	for _, pkt := range packets {
		if pkt.L4.Flags == 0x11 {
			finCount++
		}
	}
	if finCount != 2 {
		t.Errorf("expected exactly 2 FIN frames (teardown FIN + FIN-ACK), got %d", finCount)
	}
}

// Termination=false suppresses the teardown (T195/T196).
func TestPlan_TCPTearDownSkippedWhenTerminationDisabled(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	spec.TCP = &core.TCPConfig{MSS: 1460, Termination: false}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	// Without teardown, packets should be exactly 5:
	// SYN, SYN-ACK, ACK, 0x0005, 0x0006.
	if len(packets) != 5 {
		t.Errorf("expected 5 packets when Termination=false, got %d", len(packets))
	}
	for _, pkt := range packets {
		if pkt.L4.Flags == 0x11 {
			t.Errorf("unexpected FIN frame when Termination=false")
		}
	}
}

// Termination=false when no TCP config is provided (spec.TCP == nil) keeps
// the teardown enabled — spec.TCP == nil is the "default on" branch.
func TestPlan_TCPTearDownEmittedWhenNoTCPConfig(t *testing.T) {
	p := NewPlanner()
	spec := makeDoIPSpec()
	spec.DoIP.Activation = &core.DoIPActivation{ResponseCode: 0x10}
	// spec.TCP left nil.
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := drainChan(ch)
	finCount := 0
	for _, pkt := range packets {
		if pkt.L4.Flags == 0x11 {
			finCount++
		}
	}
	if finCount != 2 {
		t.Errorf("expected exactly 2 FIN frames (teardown FIN + FIN-ACK), got %d", finCount)
	}
}

// --- Parser Tests ---

func TestParser_GenericNack(t *testing.T) {
	parser := NewParser()
	data := []byte{0x02, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if res.PayloadType != PTGenericNack {
		t.Errorf("PayloadType want 0x%04X, got 0x%04X", PTGenericNack, res.PayloadType)
	}
	if res.PayloadLength != 1 {
		t.Errorf("PayloadLength want 1, got %d", res.PayloadLength)
	}
	nc, err := ParseGenericNack(res.Payload)
	if err != nil {
		t.Fatalf("ParseGenericNack failed: %v", err)
	}
	if nc != 0x01 {
		t.Errorf("NackCode want 0x01, got 0x%02X", nc)
	}
}

func TestParser_VehicleAnnouncement(t *testing.T) {
	parser := NewParser()
	payload := buildVehicleAnnouncement("WL00ABC0000000000", 0x0001, "001122334455", "000000000000", 0x00, 0x00, 0x02)
	data := append([]byte{0x02, 0xFD, 0x00, 0x04}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	vin, la, eid, _, far, sync, err := ParseVehicleAnnouncement(res.Payload, res.ProtocolVersion)
	if err != nil {
		t.Fatalf("ParseVehicleAnnouncement failed: %v", err)
	}
	if !strings.HasPrefix(vin, "WL00ABC") {
		t.Errorf("VIN mismatch: %s", vin)
	}
	if la != 0x0001 {
		t.Errorf("LogicalAddress want 0x0001, got 0x%04X", la)
	}
	if eid != "00:11:22:33:44:55" {
		t.Errorf("EID mismatch: %s", eid)
	}
	if far != 0x00 {
		t.Errorf("FAR want 0x00, got 0x%02X", far)
	}
	if sync != 0x00 {
		t.Errorf("SyncStatus want 0x00, got 0x%02X", sync)
	}
}

func TestParser_EntityStatus(t *testing.T) {
	es := &core.DoIPEntityStatus{NodeType: 0x01, MaxOpenSockets: 2, CurOpenSockets: 1, MaxDataSize: 4095}
	payload := buildEntityStatusResponse(es)
	data := append([]byte{0x02, 0xFD, 0x40, 0x02}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	nt, mos, cos, mds, err := ParseEntityStatusResponse(res.Payload)
	if err != nil {
		t.Fatalf("ParseEntityStatusResponse failed: %v", err)
	}
	if nt != 0x01 {
		t.Errorf("NodeType want 0x01, got 0x%02X", nt)
	}
	if mos != 2 {
		t.Errorf("MaxOpenSockets want 2, got %d", mos)
	}
	if cos != 1 {
		t.Errorf("CurOpenSockets want 1, got %d", cos)
	}
	if mds != 4095 {
		t.Errorf("MaxDataSize want 4095, got %d", mds)
	}
}

func TestParser_PowerMode(t *testing.T) {
	payload := []byte{0x01}
	data := append([]byte{0x02, 0xFD, 0x40, 0x04}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	pm, err := ParsePowerModeResponse(res.Payload)
	if err != nil {
		t.Fatalf("ParsePowerModeResponse failed: %v", err)
	}
	if pm != 0x01 {
		t.Errorf("PowerMode want 0x01, got 0x%02X", pm)
	}
}

func TestParser_DiagnosticMessage(t *testing.T) {
	payload := buildDiagnosticMessage(0x0E80, 0x0001, []byte{0x10, 0x03})
	data := append([]byte{0x02, 0xFD, 0x80, 0x01}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	sa, ta, ud, err := ParseDiagnosticMessage(res.Payload)
	if err != nil {
		t.Fatalf("ParseDiagnosticMessage failed: %v", err)
	}
	if sa != 0x0E80 {
		t.Errorf("SA want 0x0E80, got 0x%04X", sa)
	}
	if ta != 0x0001 {
		t.Errorf("TA want 0x0001, got 0x%04X", ta)
	}
	if len(ud) != 2 || ud[0] != 0x10 || ud[1] != 0x03 {
		t.Errorf("UserData mismatch: %x", ud)
	}
}

func TestParser_DiagnosticMessageAck(t *testing.T) {
	payload := buildDiagnosticMessageAck(0x0001, 0x0E80, []byte{0x10, 0x03})
	data := append([]byte{0x02, 0xFD, 0x80, 0x02}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	sa, ta, ack, prev, err := ParseDiagnosticMessageAck(res.Payload)
	if err != nil {
		t.Fatalf("ParseDiagnosticMessageAck failed: %v", err)
	}
	if sa != 0x0001 {
		t.Errorf("SA want 0x0001, got 0x%04X", sa)
	}
	if ta != 0x0E80 {
		t.Errorf("TA want 0x0E80, got 0x%04X", ta)
	}
	if ack != 0x00 {
		t.Errorf("AckCode want 0x00, got 0x%02X", ack)
	}
	if len(prev) != 2 || prev[0] != 0x10 || prev[1] != 0x03 {
		t.Errorf("PreviousDiagnosticMessage mismatch: %x", prev)
	}
}

func TestParser_DiagnosticMessageNack(t *testing.T) {
	payload := buildDiagnosticMessageNack(0x0001, 0x0E80, 0x02, []byte{0x22, 0xF1, 0x90})
	data := append([]byte{0x02, 0xFD, 0x80, 0x03}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	sa, ta, nack, prev, err := ParseDiagnosticMessageNack(res.Payload)
	if err != nil {
		t.Fatalf("ParseDiagnosticMessageNack failed: %v", err)
	}
	if sa != 0x0001 {
		t.Errorf("SA want 0x0001, got 0x%04X", sa)
	}
	if ta != 0x0E80 {
		t.Errorf("TA want 0x0E80, got 0x%04X", ta)
	}
	if nack != 0x02 {
		t.Errorf("NackCode want 0x02, got 0x%02X", nack)
	}
	if len(prev) != 3 || prev[0] != 0x22 || prev[1] != 0xF1 || prev[2] != 0x90 {
		t.Errorf("PreviousDiagnosticMessage mismatch: %x", prev)
	}
}

func TestParser_RoutingActivationRequest(t *testing.T) {
	payload := buildRoutingActivationRequest(0x0E80, 0x00, nil)
	data := append([]byte{0x02, 0xFD, 0x00, 0x05}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	sa, at, oem, err := ParseRoutingActivationRequest(res.Payload)
	if err != nil {
		t.Fatalf("ParseRoutingActivationRequest failed: %v", err)
	}
	if sa != 0x0E80 {
		t.Errorf("SourceAddress want 0x0E80, got 0x%04X", sa)
	}
	if at != 0x00 {
		t.Errorf("ActivationType want 0x00, got 0x%02X", at)
	}
	if len(oem) != 0 {
		t.Errorf("OEM want empty, got %x", oem)
	}
}

func TestParser_RoutingActivationResponse(t *testing.T) {
	payload := buildRoutingActivationResponse(0x0E80, 0x0001, 0x10, nil)
	data := append([]byte{0x02, 0xFD, 0x00, 0x06}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	cla, sla, rc, oem, err := ParseRoutingActivationResponse(res.Payload)
	if err != nil {
		t.Fatalf("ParseRoutingActivationResponse failed: %v", err)
	}
	if cla != 0x0E80 {
		t.Errorf("CLA want 0x0E80, got 0x%04X", cla)
	}
	if sla != 0x0001 {
		t.Errorf("SLA want 0x0001, got 0x%04X", sla)
	}
	if rc != 0x10 {
		t.Errorf("ResponseCode want 0x10, got 0x%02X", rc)
	}
	if len(oem) != 0 {
		t.Errorf("OEM want empty, got %x", oem)
	}
}

func TestParser_AliveCheckResponse(t *testing.T) {
	payload := []byte{0x0E, 0x80}
	data := append([]byte{0x02, 0xFD, 0x00, 0x08}, u32BE(uint32(len(payload)))...)
	data = append(data, payload...)
	parser := NewParser()
	res, err := parser.ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	sa, err := ParseAliveCheckResponse(res.Payload)
	if err != nil {
		t.Fatalf("ParseAliveCheckResponse failed: %v", err)
	}
	if sa != 0x0E80 {
		t.Errorf("SourceAddress want 0x0E80, got 0x%04X", sa)
	}
}
