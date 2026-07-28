package mdns

// Atomic test points for the mDNS planner. Each test corresponds to one or
// more test cases in /tmp/l7_planner_design/testcases_mdns.md.

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ===================================================================
// §1.1 Transaction ID (事务 ID, 偏移 0, 2 字节)
// ===================================================================

// 1.1.1: mDNS query Transaction ID = 0x0000
func TestMDNS_1_1_1_QueryTxID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// 1.1.2: mDNS response Transaction ID = 0x0000
func TestMDNS_1_1_2_ResponseTxID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// 1.1.3: mDNS probe Transaction ID = 0x0000
func TestMDNS_1_1_3_ProbeTxID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		ProbingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// 1.1.4: mDNS announce Transaction ID = 0x0000
func TestMDNS_1_1_4_AnnounceTxID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		AnnouncingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// 1.1.5: mDNS goodbye Transaction ID = 0x0000
func TestMDNS_1_1_5_GoodbyeTxID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// ===================================================================
// §1.2 Flags - QR bit (bit 15, 查询/响应位)
// ===================================================================

// 1.2.1: query Flags QR=0 -> Payload[2] = 0x00
func TestMDNS_1_2_1_QueryQR(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x00 {
		t.Errorf("Payload[2]=%02x, want 00", payload[2])
	}
}

// 1.2.2: response Flags QR=1 -> Payload[2] = 0x80
func TestMDNS_1_2_2_ResponseQR(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x84 {
		t.Errorf("Payload[2]=%02x, want 84", payload[2])
	}
}

// 1.2.3: announce Flags QR=1 -> Payload[2] = 0x80
func TestMDNS_1_2_3_AnnounceQR(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		AnnouncingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x84 {
		t.Errorf("Payload[2]=%02x, want 84", payload[2])
	}
}

// 1.2.4: goodbye Flags QR=1 -> Payload[2] = 0x80
func TestMDNS_1_2_4_GoodbyeQR(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x84 {
		t.Errorf("Payload[2]=%02x, want 84", payload[2])
	}
}

// ===================================================================
// §1.3 Flags - Opcode (bit 14-11, 操作码)
// ===================================================================

// 1.3.1: query Opcode=0 -> bit 14-11 = 0
func TestMDNS_1_3_1_QueryOpcode(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// Opcode is bits 14-11, check that Payload[2] & 0x78 == 0
	if len(payload) < 4 || (payload[2]&0x78) != 0 {
		t.Errorf("Payload[2]&0x78=%02x, want 00", payload[2]&0x78)
	}
}

// 1.3.2: response Opcode=0 -> bit 14-11 = 0
func TestMDNS_1_3_2_ResponseOpcode(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || (payload[2]&0x78) != 0 {
		t.Errorf("Payload[2]&0x78=%02x, want 00", payload[2]&0x78)
	}
}

// ===================================================================
// §1.4 Flags - AA bit (bit 10, 权威应答位)
// ===================================================================

// 1.4.1: query AA=0 -> bit 10 = 0
func TestMDNS_1_4_1_QueryAA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || (payload[2]&0x04) != 0 {
		t.Errorf("Payload[2]&0x04=%02x, want 00", payload[2]&0x04)
	}
}

// 1.4.2: response AA=1 -> Payload[2] = 0x84 (bit 10 = 1)
func TestMDNS_1_4_2_ResponseAA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x84 {
		t.Errorf("Payload[2]=%02x, want 84", payload[2])
	}
}

// ===================================================================
// §1.5 Flags - TC bit (bit 9, 截断位)
// ===================================================================

// 1.5.1: response TC=0 -> Payload[2] = 0x84 (bit 9 = 0)
func TestMDNS_1_5_1_ResponseTC0(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		TC: false,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x84 {
		t.Errorf("Payload[2]=%02x, want 84", payload[2])
	}
}

// 1.5.2: response TC=1 -> Payload[2] = 0x86
func TestMDNS_1_5_2_ResponseTC1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		TC: true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || payload[2] != 0x86 {
		t.Errorf("Payload[2]=%02x, want 86", payload[2])
	}
}

// ===================================================================
// §1.6 Flags - RD bit (bit 8, 递归期望位)
// ===================================================================

// 1.6.1: query RD=0 -> bit 8 = 0
func TestMDNS_1_6_1_QueryRD(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || (payload[2]&0x01) != 0 {
		t.Errorf("Payload[2]&0x01=%02x, want 00", payload[2]&0x01)
	}
}

// 1.6.2: response RD=0 -> bit 8 = 0
func TestMDNS_1_6_2_ResponseRD(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 4 || (payload[2]&0x01) != 0 {
		t.Errorf("Payload[2]&0x01=%02x, want 00", payload[2]&0x01)
	}
}

// ===================================================================
// §1.9 QDCOUNT (偏移 4, 2 字节, 问题计数)
// ===================================================================

// 1.9.2: 1 question -> QDCOUNT = 0x0001
func TestMDNS_1_9_2_QDCOUNT1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 6 {
		t.Fatal("payload too short")
	}
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount != 1 {
		t.Errorf("QDCOUNT=%d, want 1", qdCount)
	}
}

// 1.9.4: 0 questions (response) -> QDCOUNT = 0x0000
func TestMDNS_1_9_4_QDCOUNT0_Response(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 6 {
		t.Fatal("payload too short")
	}
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount != 0 {
		t.Errorf("QDCOUNT=%d, want 0", qdCount)
	}
}

// ===================================================================
// §1.10 ANCOUNT (偏移 6, 2 字节, 回答计数)
// ===================================================================

// 1.10.1: 0 answers (query) -> ANCOUNT = 0x0000
func TestMDNS_1_10_1_ANCOUNT0_Query(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 8 {
		t.Fatal("payload too short")
	}
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if anCount != 0 {
		t.Errorf("ANCOUNT=%d, want 0", anCount)
	}
}

// 1.10.2: 1 answer (response) -> ANCOUNT = 0x0001
func TestMDNS_1_10_2_ANCOUNT1_Response(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 8 {
		t.Fatal("payload too short")
	}
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if anCount != 1 {
		t.Errorf("ANCOUNT=%d, want 1", anCount)
	}
}

// 1.10.4: 100 answers -> ANCOUNT = 0x0064
func TestMDNS_1_10_4_ANCOUNT100(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	answers := make([]core.MDNSResourceRecord, 100)
	for i := range answers {
		answers[i] = core.MDNSResourceRecord{
			Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1",
		}
	}
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: answers,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 8 {
		t.Fatal("payload too short")
	}
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if anCount != 100 {
		t.Errorf("ANCOUNT=%d, want 100", anCount)
	}
}

// ===================================================================
// §1.11 NSCOUNT (偏移 8, 2 字节, 权威计数)
// ===================================================================

// 1.11.1: Authorities empty -> NSCOUNT = 0x0000
func TestMDNS_1_11_1_NSCOUNT0(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		Authorities: []core.MDNSResourceRecord{},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 10 {
		t.Fatal("payload too short")
	}
	nsCount := binary.BigEndian.Uint16(payload[8:10])
	if nsCount != 0 {
		t.Errorf("NSCOUNT=%d, want 0", nsCount)
	}
}

// 1.11.2: 1 authority -> NSCOUNT = 0x0001
func TestMDNS_1_11_2_NSCOUNT1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		Authorities: []core.MDNSResourceRecord{
			{Name: "ns1.local", Type: TypeA, IPAddress: "192.168.1.2"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 10 {
		t.Fatal("payload too short")
	}
	nsCount := binary.BigEndian.Uint16(payload[8:10])
	if nsCount != 1 {
		t.Errorf("NSCOUNT=%d, want 1", nsCount)
	}
}

// ===================================================================
// §1.12 ARCOUNT (偏移 10, 2 字节, 附加计数)
// ===================================================================

// 1.12.1: Additionals empty -> ARCOUNT = 0x0000
func TestMDNS_1_12_1_ARCOUNT0(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		Additionals: []core.MDNSResourceRecord{},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 12 {
		t.Fatal("payload too short")
	}
	arCount := binary.BigEndian.Uint16(payload[10:12])
	if arCount != 0 {
		t.Errorf("ARCOUNT=%d, want 0", arCount)
	}
}

// 1.12.2: 3 additionals -> ARCOUNT = 0x0003
func TestMDNS_1_12_2_ARCOUNT3(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		Additionals: []core.MDNSResourceRecord{
			{Name: "srv.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "target.local"},
			{Name: "txt.local", Type: TypeTXT, TXTEntries: []string{"key=val"}},
			{Name: "a.local", Type: TypeA, IPAddress: "192.168.1.2"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 12 {
		t.Fatal("payload too short")
	}
	arCount := binary.BigEndian.Uint16(payload[10:12])
	if arCount != 3 {
		t.Errorf("ARCOUNT=%d, want 3", arCount)
	}
}

// ===================================================================
// §1.14 QTYPE (问题类型, 2 字节)
// ===================================================================

// 1.14.1: QTYPE = 1 (A) -> 0x0001
func TestMDNS_1_14_1_QTYPE_A(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// QNAME encoded length = 1+4+5+0 = 10 (test.local)
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen // 12 header + qname
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeA {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeA)
	}
}

// 1.14.2: QTYPE = 28 (AAAA) -> 0x001C
func TestMDNS_1_14_2_QTYPE_AAAA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeAAAA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeAAAA {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeAAAA)
	}
}

// 1.14.3: QTYPE = 12 (PTR) -> 0x000C
func TestMDNS_1_14_3_QTYPE_PTR(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypePTR}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypePTR {
		t.Errorf("QTYPE=%d, want %d", qtype, TypePTR)
	}
}

// 1.14.4: QTYPE = 33 (SRV) -> 0x0021
func TestMDNS_1_14_4_QTYPE_SRV(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeSRV}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeSRV {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeSRV)
	}
}

// 1.14.5: QTYPE = 16 (TXT) -> 0x0010
func TestMDNS_1_14_5_QTYPE_TXT(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeTXT}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeTXT {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeTXT)
	}
}

// 1.14.6: QTYPE = 5 (CNAME) -> 0x0005
func TestMDNS_1_14_6_QTYPE_CNAME(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeCNAME}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeCNAME {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeCNAME)
	}
}

// 1.14.7: QTYPE = 255 (ANY) -> 0x00FF
func TestMDNS_1_14_7_QTYPE_ANY(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeANY}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qtypeOffset := 12 + qnameLen
	if len(payload) < qtypeOffset+2 {
		t.Fatal("payload too short")
	}
	qtype := binary.BigEndian.Uint16(payload[qtypeOffset : qtypeOffset+2])
	if qtype != TypeANY {
		t.Errorf("QTYPE=%d, want %d", qtype, TypeANY)
	}
}

// ===================================================================
// §1.15 QCLASS (问题类, 2 字节)
// ===================================================================

// 1.15.1: QCLASS = 0 (default) -> 0x0001 (IN)
func TestMDNS_1_15_1_QCLASS_Default(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2 // header + qname + qtype
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x0001 {
		t.Errorf("QCLASS=%04x, want 0001", qclass)
	}
}

// 1.15.2: QCLASS = 1 (IN) -> 0x0001
func TestMDNS_1_15_2_QCLASS_IN(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA, Class: 1}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x0001 {
		t.Errorf("QCLASS=%04x, want 0001", qclass)
	}
}

// 1.15.3: QCLASS = 0x8000 (QU bit) -> 0x8000
func TestMDNS_1_15_3_QCLASS_QU(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA, Class: 0x8000}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x8000 {
		t.Errorf("QCLASS=%04x, want 8000", qclass)
	}
}

// 1.15.4: QCLASS = 0x8001 (IN + QU) -> 0x8001
func TestMDNS_1_15_4_QCLASS_IN_QU(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA, Class: 0x8001}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x8001 {
		t.Errorf("QCLASS=%04x, want 8001", qclass)
	}
}

// ===================================================================
// §1.16 RR - TTL (生存时间, 4 字节)
// ===================================================================

// 1.16.5: TTL = 4500 -> 0x00001194
func TestMDNS_1_16_5_TTL4500(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 4500},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// Find TTL in the answer RR: header(12) + question(0) + NAME + TYPE(2) + CLASS(2) + TTL(4)
	// Skip question section is empty, so directly after header
	// NAME = encodeQName("test.local") = 10 bytes
	// TYPE(2) + CLASS(2) = 4 bytes
	// TTL starts at offset 12 + 10 + 4 = 26
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short: %d < %d", len(payload), ttlOffset+4)
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 4500 {
		t.Errorf("TTL=%d, want 4500", ttl)
	}
}

// 1.16.2: TTL = 0 (response) -> use DefaultTTL=4500 -> 0x00001194
func TestMDNS_1_16_2_TTL0_Default(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 0},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short")
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 4500 {
		t.Errorf("TTL=%d, want 4500", ttl)
	}
}

// 1.16.6: TTL = 2147483647 (2^31-1) -> 0x7FFFFFFF
func TestMDNS_1_16_6_TTLMax31(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 2147483647},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short")
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 2147483647 {
		t.Errorf("TTL=%d, want 2147483647", ttl)
	}
}

// ===================================================================
// §1.17 RR - cache-flush bit (CLASS 高位, 缓存刷新位)
// ===================================================================

// 1.17.1: CacheFlush=true + announce -> CLASS = 0x8001
func TestMDNS_1_17_1_CacheFlushTrue_Announce(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		AnnouncingRepeat: 1,
		CacheFlush: boolPtr(true),
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// CLASS field: offset = 12(header) + qname_len + 2(TYPE)
	classOffset := 12 + len(encodeQName("test.local")) + 2
	if len(payload) < classOffset+2 {
		t.Fatalf("payload too short")
	}
	class := binary.BigEndian.Uint16(payload[classOffset : classOffset+2])
	if class != 0x8001 {
		t.Errorf("CLASS=%04x, want 8001", class)
	}
}

// 1.17.2: CacheFlush=false + response -> CLASS = 0x0001
func TestMDNS_1_17_2_CacheFlushFalse_Response(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		CacheFlush: boolPtr(false),
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	classOffset := 12 + len(encodeQName("test.local")) + 2
	if len(payload) < classOffset+2 {
		t.Fatalf("payload too short")
	}
	class := binary.BigEndian.Uint16(payload[classOffset : classOffset+2])
	if class != 0x0001 {
		t.Errorf("CLASS=%04x, want 0001", class)
	}
}

// 1.17.3: CacheFlush unset + announce -> default true -> CLASS = 0x8001
func TestMDNS_1_17_3_CacheFlushDefault_Announce(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		AnnouncingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	classOffset := 12 + len(encodeQName("test.local")) + 2
	if len(payload) < classOffset+2 {
		t.Fatalf("payload too short")
	}
	class := binary.BigEndian.Uint16(payload[classOffset : classOffset+2])
	if class != 0x8001 {
		t.Errorf("CLASS=%04x, want 8001", class)
	}
}

// 1.17.5: goodbye -> CacheFlush=true -> CLASS = 0x8001
func TestMDNS_1_17_5_GoodbyeCacheFlush(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		CacheFlush: boolPtr(true),
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	classOffset := 12 + len(encodeQName("test.local")) + 2
	if len(payload) < classOffset+2 {
		t.Fatalf("payload too short")
	}
	class := binary.BigEndian.Uint16(payload[classOffset : classOffset+2])
	if class != 0x8001 {
		t.Errorf("CLASS=%04x, want 8001", class)
	}
}

// ===================================================================
// §1.18 RR - RDLENGTH (记录数据长度, 2 字节)
// ===================================================================

// 1.18.1: A record RDATA = "192.168.1.10" -> RDLENGTH = 4 -> 0x0004
func TestMDNS_1_18_1_ARDATA_Length(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.10"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// RDLENGTH offset = header(12) + qname + TYPE(2) + CLASS(2) + TTL(4)
	rdLenOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4
	if len(payload) < rdLenOffset+2 {
		t.Fatalf("payload too short: %d < %d", len(payload), rdLenOffset+2)
	}
	rdLen := binary.BigEndian.Uint16(payload[rdLenOffset : rdLenOffset+2])
	if rdLen != 4 {
		t.Errorf("RDLENGTH=%d, want 4", rdLen)
	}
}

// 1.18.2: AAAA record RDATA = "fe80::1234" -> RDLENGTH = 16 -> 0x0010
func TestMDNS_1_18_2_AAAARDATA_Length(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "33:33:00:00:00:FB",
		SrcIP: "fe80::1234",
		DstIP: "ff02::fb",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "response",
			Answers: []core.MDNSResourceRecord{
				{Name: "test.local", Type: TypeAAAA, IPAddress: "fe80::1234"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdLenOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4
	if len(payload) < rdLenOffset+2 {
		t.Fatalf("payload too short: %d < %d", len(payload), rdLenOffset+2)
	}
	rdLen := binary.BigEndian.Uint16(payload[rdLenOffset : rdLenOffset+2])
	if rdLen != 16 {
		t.Errorf("RDLENGTH=%d, want 16", rdLen)
	}
}

// ===================================================================
// §1.19 IPv4 multicast address (L3 DstIP, IPv4 多播地址)
// ===================================================================

// 1.19.1: IPv4 SrcIP, no MulticastGroup -> auto DstIP = 224.0.0.251
func TestMDNS_1_19_1_AutoIPv4Multicast(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.DstIP = ""
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.DstIP != "224.0.0.251" {
		t.Errorf("DstIP=%s, want 224.0.0.251", cfgs[0].L3.DstIP)
	}
}

// 1.19.2: Explicit MulticastGroup = 224.0.0.251
func TestMDNS_1_19_2_ExplicitIPv4Multicast(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		MulticastGroup: "224.0.0.251",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.DstIP != "224.0.0.251" {
		t.Errorf("DstIP=%s, want 224.0.0.251", cfgs[0].L3.DstIP)
	}
}

// ===================================================================
// §1.20 IPv6 multicast address (L3 DstIP, IPv6 多播地址)
// ===================================================================

// 1.20.1: IPv6 SrcIP, no MulticastGroup -> auto DstIP = ff02::fb
func TestMDNS_1_20_1_AutoIPv6Multicast(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.DstIP != "ff02::fb" {
		t.Errorf("DstIP=%s, want ff02::fb", cfgs[0].L3.DstIP)
	}
}

// 1.20.2: Explicit MulticastGroup = ff02::fb
func TestMDNS_1_20_2_ExplicitIPv6Multicast(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
			MulticastGroup: "ff02::fb",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.DstIP != "ff02::fb" {
		t.Errorf("DstIP=%s, want ff02::fb", cfgs[0].L3.DstIP)
	}
}

// 1.20.3: IPv6 -> L2 DstMAC = 33:33:00:00:00:FB
func TestMDNS_1_20_3_IPv6DstMAC(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L2.DstMAC != "33:33:00:00:00:FB" {
		t.Errorf("DstMAC=%s, want 33:33:00:00:00:FB", cfgs[0].L2.DstMAC)
	}
}

// 1.20.4: IPv6 -> L2 EtherType = 0x86DD
func TestMDNS_1_20_4_IPv6EtherType(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD", cfgs[0].L2.EtherType)
	}
}

// ===================================================================
// §1.21 L2 DstMAC (多播 MAC)
// ===================================================================

// 1.21.1: IPv4 -> L2 DstMAC = 01:00:5E:00:00:FB
func TestMDNS_1_21_1_IPv4DstMAC(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L2.DstMAC != "01:00:5E:00:00:FB" {
		t.Errorf("DstMAC=%s, want 01:00:5E:00:00:FB", cfgs[0].L2.DstMAC)
	}
}

// ===================================================================
// §1.22 L3 TTL / HopLimit (生存时间)
// ===================================================================

// 1.22.1: TTL = 0 (default) -> L3.TTL = 255
func TestMDNS_1_22_1_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.TTL = 0
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.TTL != 255 {
		t.Errorf("TTL=%d, want 255", cfgs[0].L3.TTL)
	}
}

// 1.22.2: TTL = 255 -> L3.TTL = 255
func TestMDNS_1_22_2_TTL255(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.TTL = 255
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.TTL != 255 {
		t.Errorf("TTL=%d, want 255", cfgs[0].L3.TTL)
	}
}

// 1.22.3: TTL = 64 -> planner overrides to 255
func TestMDNS_1_22_3_TTLOverride(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.TTL = 64
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L3.TTL != 255 {
		t.Errorf("TTL=%d, want 255", cfgs[0].L3.TTL)
	}
}

// ===================================================================
// §1.23 L4 Port (端口)
// ===================================================================

// 1.23.1: SrcPort = 0 -> auto-fill 5353
func TestMDNS_1_23_1_ZeroSrcPort(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.SrcPort = 0
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L4.SrcPort != 5353 {
		t.Errorf("SrcPort=%d, want 5353", cfgs[0].L4.SrcPort)
	}
}

// 1.23.4: DstPort = 0 -> auto-fill 5353
func TestMDNS_1_23_4_ZeroDstPort(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.DstPort = 0
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L4.DstPort != 5353 {
		t.Errorf("DstPort=%d, want 5353", cfgs[0].L4.DstPort)
	}
}

// ===================================================================
// §1.24 SRV RDATA (SRV 记录数据)
// ===================================================================

// 1.24.1: SRV Priority=0, Weight=0, Port=80, Target="MyServer.local"
func TestMDNS_1_24_1_SRVRDATA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "srv.test.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// RDATA starts after: header(12) + qname + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	// SRV RDATA = Priority(2) + Weight(2) + Port(2) + Target(QName)
	rdOffset := 12 + len(encodeQName("srv.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+6 {
		t.Fatalf("payload too short: %d < %d", len(payload), rdOffset+6)
	}
	priority := binary.BigEndian.Uint16(payload[rdOffset : rdOffset+2])
	weight := binary.BigEndian.Uint16(payload[rdOffset+2 : rdOffset+4])
	port := binary.BigEndian.Uint16(payload[rdOffset+4 : rdOffset+6])
	if priority != 0 {
		t.Errorf("Priority=%d, want 0", priority)
	}
	if weight != 0 {
		t.Errorf("Weight=%d, want 0", weight)
	}
	if port != 80 {
		t.Errorf("Port=%d, want 80", port)
	}
}

// ===================================================================
// §1.25 TXT RDATA (TXT 记录数据)
// ===================================================================

// 1.25.1: TXT TXTEntries=["txtvers=1"] -> RDATA = 0x09 + "txtvers=1"
func TestMDNS_1_25_1_TXTRDATA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "txt.test.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// RDATA starts after: header(12) + qname + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	rdOffset := 12 + len(encodeQName("txt.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+1 {
		t.Fatalf("payload too short")
	}
	// First byte should be 0x09 = len("txtvers=1")
	if payload[rdOffset] != 9 {
		t.Errorf("TXT entry length prefix = %d, want 9", payload[rdOffset])
	}
	// Next 9 bytes should be "txtvers=1"
	if len(payload) >= rdOffset+10 {
		entry := string(payload[rdOffset+1 : rdOffset+10])
		if entry != "txtvers=1" {
			t.Errorf("TXT entry = %q, want txtvers=1", entry)
		}
	}
}

// 1.25.2: TXT TXTEntries=["txtvers=1", "path=/"] -> two segments
func TestMDNS_1_25_2_TXTRDATATwo(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "txt.test.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1", "path=/"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("txt.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+2 {
		t.Fatalf("payload too short")
	}
	// "txtvers=1" length prefix = 9
	if payload[rdOffset] != 9 {
		t.Errorf("First entry length = %d, want 9", payload[rdOffset])
	}
	// After 9 bytes + 1 byte prefix for "txtvers=1"
	secondOffset := rdOffset + 1 + 9
	if len(payload) < secondOffset+1 {
		t.Fatalf("payload too short for second entry")
	}
	// "path=/" length prefix = 6
	if payload[secondOffset] != 6 {
		t.Errorf("Second entry length = %d, want 6", payload[secondOffset])
	}
}

// 1.25.3: TXT TXTEntries=[] -> RDATA = 0 bytes
func TestMDNS_1_25_3_TXTRDATAEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "txt.test.local", Type: TypeTXT, TXTEntries: []string{}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdLenOffset := 12 + len(encodeQName("txt.test.local")) + 2 + 2 + 4
	if len(payload) < rdLenOffset+2 {
		t.Fatalf("payload too short")
	}
	rdLen := binary.BigEndian.Uint16(payload[rdLenOffset : rdLenOffset+2])
	if rdLen != 0 {
		t.Errorf("RDLENGTH=%d, want 0", rdLen)
	}
}

// ===================================================================
// §1.18.A NSEC RDATA (NSEC 记录数据, RFC 4034 §4)
// ===================================================================

// 1.18.A.1.1: NSECNextName="next.local" -> RDATA starts with encoded QName
func TestMDNS_1_18_A_1_1_NSECNextName(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{1},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	expectedNextName := encodeQName("next.local")
	if len(payload) < rdOffset+len(expectedNextName) {
		t.Fatalf("payload too short")
	}
	gotNextName := payload[rdOffset : rdOffset+len(expectedNextName)]
	for i := range expectedNextName {
		if gotNextName[i] != expectedNextName[i] {
			t.Errorf("NSECNextName byte[%d]=%02x, want %02x", i, gotNextName[i], expectedNextName[i])
		}
	}
}

// 1.18.A.2.3: NSECTypes=[1] -> WindowNumber=0, BitmapLength=1, TypeBitmap=0x40
func TestMDNS_1_18_A_2_3_NSECTypes1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{1},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	// After next-name: WindowNumber(1) + BitmapLength(1) + TypeBitmap(1)
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+3 {
		t.Fatalf("payload too short")
	}
	if payload[windowOffset] != 0 {
		t.Errorf("WindowNumber=%d, want 0", payload[windowOffset])
	}
	if payload[windowOffset+1] != 1 {
		t.Errorf("BitmapLength=%d, want 1", payload[windowOffset+1])
	}
	if payload[windowOffset+2] != 0x40 {
		t.Errorf("TypeBitmap=%02x, want 40", payload[windowOffset+2])
	}
}

// 1.18.A.2.4: NSECTypes=[1, 28] -> WindowNumber=0, BitmapLength=4, TypeBitmap=0x40 0x00 0x00 0x08
func TestMDNS_1_18_A_2_4_NSECTypes1_28(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{1, 28},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+6 {
		t.Fatalf("payload too short")
	}
	if payload[windowOffset] != 0 {
		t.Errorf("WindowNumber=%d, want 0", payload[windowOffset])
	}
	if payload[windowOffset+1] != 4 {
		t.Errorf("BitmapLength=%d, want 4", payload[windowOffset+1])
	}
	// Type 1 = byte 0, bit 6 = 0x40
	if payload[windowOffset+2] != 0x40 {
		t.Errorf("TypeBitmap[0]=%02x, want 40", payload[windowOffset+2])
	}
	// Type 28 = byte 3, bit 3 = 0x08
	if payload[windowOffset+5] != 0x08 {
		t.Errorf("TypeBitmap[3]=%02x, want 08", payload[windowOffset+5])
	}
}

// 1.18.A.6.1: NSECNextName="a.local", NSECTypes=[1] -> full RDATA bytes
func TestMDNS_1_18_A_6_1_NSECFullRDATA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "a.local", Type: TypeNSEC,
				NSECNextName: "a.local",
				NSECTypes: []uint16{1},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("a.local")) + 2 + 2 + 4 + 2
	// Expected RDATA = encodeQName("a.local") + WindowNumber(0) + BitmapLength(1) + 0x40
	expectedNextName := encodeQName("a.local")
	expectedLen := len(expectedNextName) + 3
	if len(payload) < rdOffset+expectedLen {
		t.Fatalf("payload too short: %d < %d", len(payload), rdOffset+expectedLen)
	}
	// Check next-name
	for i, b := range expectedNextName {
		if payload[rdOffset+i] != b {
			t.Errorf("NextName byte[%d]=%02x, want %02x", i, payload[rdOffset+i], b)
		}
	}
	// Check WindowNumber
	if payload[rdOffset+len(expectedNextName)] != 0 {
		t.Errorf("WindowNumber=%02x, want 00", payload[rdOffset+len(expectedNextName)])
	}
	// Check BitmapLength
	if payload[rdOffset+len(expectedNextName)+1] != 1 {
		t.Errorf("BitmapLength=%02x, want 01", payload[rdOffset+len(expectedNextName)+1])
	}
	// Check TypeBitmap
	if payload[rdOffset+len(expectedNextName)+2] != 0x40 {
		t.Errorf("TypeBitmap=%02x, want 40", payload[rdOffset+len(expectedNextName)+2])
	}
}

// ===================================================================
// §4.1 Empty / zero values (空值 / 零值)
// ===================================================================

// 4.1.1: nil MDNSConfig -> default PTR query _http._tcp.local
func TestMDNS_4_1_1_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}
	if cfgs[0].L4.Protocol != "udp" {
		t.Errorf("Protocol=%s, want udp", cfgs[0].L4.Protocol)
	}
}

// ===================================================================
// §3.11 Direction (方向)
// ===================================================================

// 3.11.1: Mode=query -> Direction = "up"
func TestMDNS_3_11_1_QueryDirection(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
}

// 3.11.2: Mode=response -> Direction = "up"
func TestMDNS_3_11_2_ResponseDirection(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
}

// 3.11.3: Mode=probe -> Direction = "up"
func TestMDNS_3_11_3_ProbeDirection(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		ProbingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
}

// 3.11.4: Mode=announce -> Direction = "up"
func TestMDNS_3_11_4_AnnounceDirection(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
		AnnouncingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
}

// 3.11.5: Mode=goodbye -> Direction = "up"
func TestMDNS_3_11_5_GoodbyeDirection(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
}

// ===================================================================
// §3.12 ForceUnicastResponse (QU bit, 强制单播响应)
// ===================================================================

// 3.12.1: ForceUnicastResponse=true, Class=IN -> QCLASS = 0x8001
func TestMDNS_3_12_1_ForceUnicastResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA, Class: 1}},
		ForceUnicastResponse: true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x8001 {
		t.Errorf("QCLASS=%04x, want 8001", qclass)
	}
}

// 3.12.2: ForceUnicastResponse=false, Class=IN -> QCLASS = 0x0001
func TestMDNS_3_12_2_NoForceUnicastResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA, Class: 1}},
		ForceUnicastResponse: false,
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	qnameLen := len(encodeQName("test.local"))
	qclassOffset := 12 + qnameLen + 2
	if len(payload) < qclassOffset+2 {
		t.Fatal("payload too short")
	}
	qclass := binary.BigEndian.Uint16(payload[qclassOffset : qclassOffset+2])
	if qclass != 0x0001 {
		t.Errorf("QCLASS=%04x, want 0001", qclass)
	}
}

// ===================================================================
// §5.1 Concurrency (并发)
// ===================================================================

// 5.1: 2 concurrent Plan calls with same instance name
func TestMDNS_5_1_ConcurrentPlan(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		ProbingRepeat: 1,
	}

	done := make(chan struct{}, 2)
	go func() {
		cfgs := drain(mustPlan(t, p, spec))
		if len(cfgs) != 1 {
			t.Errorf("goroutine 1: packet count = %d, want 1", len(cfgs))
		}
		done <- struct{}{}
	}()
	go func() {
		cfgs := drain(mustPlan(t, p, spec))
		if len(cfgs) != 1 {
			t.Errorf("goroutine 2: packet count = %d, want 1", len(cfgs))
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// ===================================================================
// §6.1 Context cancellation (上下文取消)
// ===================================================================

// 6.2: ctx cancelled during probe -> early exit
func TestMDNS_6_2_CtxCancel(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
		ProbingRepeat: 5,
		ProbingInterval: 100,
		ProbingJitterMax: 0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	cfgs := drain(ch)
	// With 5 probes at 100ms interval, after 10ms we should have fewer than 5 packets.
	if len(cfgs) >= 5 {
		t.Errorf("expected early cancellation, got %d packets (want <5)", len(cfgs))
	}
}

// ===================================================================
// NSEC RDATA Edge Cases (NSEC RDATA 边界情况)
// ===================================================================

// NSECTypes=[1,7,8] -> BitmapLength=2, TypeBitmap=0x41 0x80
func TestMDNS_NSEC_Types_1_7_8(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{1, 7, 8},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+4 {
		t.Fatalf("payload too short")
	}
	// BitmapLength should be 2 (type 8 is in byte 1)
	if payload[windowOffset+1] != 2 {
		t.Errorf("BitmapLength=%d, want 2", payload[windowOffset+1])
	}
	// Type 1 = byte 0, bit 6 = 0x40
	// Type 7 = byte 0, bit 0 = 0x01
	// Type 8 = byte 1, bit 7 = 0x80
	if payload[windowOffset+2] != 0x41 {
		t.Errorf("TypeBitmap[0]=%02x, want 41", payload[windowOffset+2])
	}
	if payload[windowOffset+3] != 0x80 {
		t.Errorf("TypeBitmap[1]=%02x, want 80", payload[windowOffset+3])
	}
}

// NSECTypes=[256] -> WindowNumber=1, BitmapLength=1, TypeBitmap=0x80
func TestMDNS_NSEC_Type256(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{256},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+3 {
		t.Fatalf("payload too short")
	}
	if payload[windowOffset] != 1 {
		t.Errorf("WindowNumber=%d, want 1", payload[windowOffset])
	}
	if payload[windowOffset+1] != 1 {
		t.Errorf("BitmapLength=%d, want 1", payload[windowOffset+1])
	}
	if payload[windowOffset+2] != 0x80 {
		t.Errorf("TypeBitmap=%02x, want 80", payload[windowOffset+2])
	}
}

// NSECTypes=[1, 256] -> two windows
func TestMDNS_NSEC_TwoWindows(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{1, 256},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+6 {
		t.Fatalf("payload too short")
	}
	// Window 0: WindowNumber=0, BitmapLength=1, 0x40
	if payload[windowOffset] != 0 {
		t.Errorf("Window[0] Number=%d, want 0", payload[windowOffset])
	}
	if payload[windowOffset+1] != 1 {
		t.Errorf("Window[0] BitmapLength=%d, want 1", payload[windowOffset+1])
	}
	if payload[windowOffset+2] != 0x40 {
		t.Errorf("Window[0] TypeBitmap=%02x, want 40", payload[windowOffset+2])
	}
	// Window 1: WindowNumber=1, BitmapLength=1, 0x80
	w1Offset := windowOffset + 3
	if payload[w1Offset] != 1 {
		t.Errorf("Window[1] Number=%d, want 1", payload[w1Offset])
	}
	if payload[w1Offset+1] != 1 {
		t.Errorf("Window[1] BitmapLength=%d, want 1", payload[w1Offset+1])
	}
	if payload[w1Offset+2] != 0x80 {
		t.Errorf("Window[1] TypeBitmap=%02x, want 80", payload[w1Offset+2])
	}
}

// NSECTypes=[28, 1] (unsorted) -> should be sorted to [1, 28]
func TestMDNS_NSEC_Unsorted(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{28, 1},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	nextNameLen := len(encodeQName("next.local"))
	windowOffset := rdOffset + nextNameLen
	if len(payload) < windowOffset+6 {
		t.Fatalf("payload too short")
	}
	// Window 0 only: BitmapLength=4
	if payload[windowOffset+1] != 4 {
		t.Errorf("BitmapLength=%d, want 4", payload[windowOffset+1])
	}
	// Type 1 = byte 0, bit 6 = 0x40
	if payload[windowOffset+2] != 0x40 {
		t.Errorf("TypeBitmap[0]=%02x, want 40", payload[windowOffset+2])
	}
	// Type 28 = byte 3, bit 3 = 0x08
	if payload[windowOffset+5] != 0x08 {
		t.Errorf("TypeBitmap[3]=%02x, want 08", payload[windowOffset+5])
	}
}

// RawRDATA overrides typed NSEC fields
func TestMDNS_NSEC_RawRDATA(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "should_be_overridden.local",
				NSECTypes: []uint16{1},
				RawRDATA: []byte{0x01, 0x78, 0x00, 0x00, 0x01, 0x40}, // "x.local" + NSEC window for type 1
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	rdLen := binary.BigEndian.Uint16(payload[rdOffset-2 : rdOffset])
	if rdLen != 6 {
		t.Errorf("RDLENGTH=%d, want 6", rdLen)
	}
	// Check RawRDATA bytes
	if len(payload) < rdOffset+6 {
		t.Fatalf("payload too short")
	}
	for i, b := range []byte{0x01, 0x78, 0x00, 0x00, 0x01, 0x40} {
		if payload[rdOffset+i] != b {
			t.Errorf("RawRDATA[%d]=%02x, want %02x", i, payload[rdOffset+i], b)
		}
	}
}

// ===================================================================
// Direction "up" for all modes (所有模式方向为 up)
// ===================================================================

// 3.9.1: Mode=query, Question=_services._dns-sd._udp.local -> QNAME matches
func TestMDNS_3_9_1_ServiceEnumQuery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "_services._dns-sd._udp.local", Type: TypePTR},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	expectedQName := encodeQName("_services._dns-sd._udp.local")
	if len(payload) < 12+len(expectedQName) {
		t.Fatalf("payload too short")
	}
	qnameBytes := payload[12 : 12+len(expectedQName)]
	for i, b := range expectedQName {
		if qnameBytes[i] != b {
			t.Errorf("QNAME byte[%d]=%02x, want %02x", i, qnameBytes[i], b)
		}
	}
}

// ===================================================================
// Reverse lookup (反向解析)
// ===================================================================

// 3.8.1: Reverse query 10.1.168.192.in-addr.arpa
func TestMDNS_3_8_1_ReverseQuery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "10.1.168.192.in-addr.arpa", Type: TypePTR},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	expectedQName := encodeQName("10.1.168.192.in-addr.arpa")
	if len(payload) < 12+len(expectedQName) {
		t.Fatalf("payload too short")
	}
	qnameBytes := payload[12 : 12+len(expectedQName)]
	for i, b := range expectedQName {
		if qnameBytes[i] != b {
			t.Errorf("QNAME byte[%d]=%02x, want %02x", i, qnameBytes[i], b)
		}
	}
}

// ===================================================================
// Goodbye TTL=0 assertion (Goodbye TTL=0 断言)
// ===================================================================

// 3.6.1: Goodbye Answer[0].TTL=0 -> 0x00000000
func TestMDNS_3_6_1_GoodbyeTTL0(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 4500},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short")
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 0 {
		t.Errorf("TTL=%d, want 0", ttl)
	}
}

// ===================================================================
// AAAA record RDATA = 16 bytes (AAAA 记录 RDATA = 16 字节)
// ===================================================================

// 3.11.5: AAAA RDATA length = 16
func TestMDNS_3_11_5_AAAARDATALength(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "announce",
			Answers: []core.MDNSResourceRecord{
				{Name: "test.local", Type: TypeAAAA, IPAddress: "fe80::1234", TTL: 4500},
			},
			AnnouncingRepeat: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdLenOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4
	if len(payload) < rdLenOffset+2 {
		t.Fatalf("payload too short")
	}
	rdLen := binary.BigEndian.Uint16(payload[rdLenOffset : rdLenOffset+2])
	if rdLen != 16 {
		t.Errorf("RDLENGTH=%d, want 16", rdLen)
	}
}

// 3.11.6: AAAA RDATA bytes for fe80::1234
func TestMDNS_3_11_6_AAAARDATABytes(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1234",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "announce",
			Answers: []core.MDNSResourceRecord{
				{Name: "test.local", Type: TypeAAAA, IPAddress: "fe80::1234", TTL: 4500},
			},
			AnnouncingRepeat: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	expectedIP := net.ParseIP("fe80::1234").To16()
	if len(payload) < rdOffset+16 {
		t.Fatalf("payload too short")
	}
	for i, b := range expectedIP {
		if payload[rdOffset+i] != b {
			t.Errorf("AAAA RDATA byte[%d]=%02x, want %02x", i, payload[rdOffset+i], b)
			break
		}
	}
}

// ===================================================================
// 1.1.6: Default Transaction ID = 0x0000 (default config)
// ===================================================================

// 1.1.6: Default config -> TxID = 0x0000
func TestMDNS_1_1_6_DefaultTxID(t *testing.T) {
	// This is tested by TestMDNS_1_1_1_QueryTxID with nil-equivalent config
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 2 || payload[0] != 0 || payload[1] != 0 {
		t.Errorf("Payload[0:2]=%02x%02x, want 0000", payload[0], payload[1])
	}
}

// ===================================================================
// Edge case: SRV Port=0 -> 0x0000
// ===================================================================

// 1.24.3: SRV Port=0 -> 0x0000
func TestMDNS_1_24_3_SRVPort0(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "srv.test.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 0, Target: "target.local"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("srv.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+6 {
		t.Fatalf("payload too short")
	}
	port := binary.BigEndian.Uint16(payload[rdOffset+4 : rdOffset+6])
	if port != 0 {
		t.Errorf("Port=%d, want 0", port)
	}
}

// ===================================================================
// SRV Target="." -> QName encoding of "."
// ===================================================================

// 1.24.5: SRV Target="." -> RDATA = 6 bytes + 0x00
func TestMDNS_1_24_5_SRVDotTarget(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "srv.test.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "."},
		},
	}
	// Validate should accept "." as target
	err := p.Validate(spec)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("srv.test.local")) + 2 + 2 + 4 + 2
	// RDATA = Priority(2) + Weight(2) + Port(2) + Target(QName)
	// Target "." = encodeQName(".") = \x00
	if len(payload) < rdOffset+7 {
		t.Fatalf("payload too short")
	}
	// After the 6-byte header, the target should be \x00 (root)
	if payload[rdOffset+6] != 0 {
		t.Errorf("Target terminator = %02x, want 00", payload[rdOffset+6])
	}
}

// ===================================================================
// TXT entry empty string (空字符串 TXT entry)
// ===================================================================

// 1.25.4: TXT TXTEntries=[""] -> RDATA = \x00
func TestMDNS_1_25_4_TXTEmptyEntry(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "txt.test.local", Type: TypeTXT, TXTEntries: []string{""}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("txt.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+1 {
		t.Fatalf("payload too short")
	}
	if payload[rdOffset] != 0 {
		t.Errorf("TXT entry length prefix = %d, want 0", payload[rdOffset])
	}
}

// ===================================================================
// Edge case: NSEC RawRDATA with typed fields (both present)
// ===================================================================

// 1.18.A.5.1: RawRDATA overrides typed NSEC fields - check payload
func TestMDNS_1_18_A_5_1_RawRDATAOverride(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "ignored.local",
				NSECTypes: []uint16{1},
				RawRDATA: []byte{0x01, 0x78, 0x00, 0x00, 0x01, 0x40},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+6 {
		t.Fatalf("payload too short")
	}
	// Should contain RawRDATA, not the typed NSEC fields
	if payload[rdOffset] != 0x01 || payload[rdOffset+1] != 0x78 {
		t.Errorf("RawRDATA[0:2]=%02x%02x, want 0178", payload[rdOffset], payload[rdOffset+1])
	}
}

// ===================================================================
// Edge case: TTL boundary 2^31-1 and > 2^31-1
// ===================================================================

// 1.16.7: TTL = 4294967295 (2^32-1) -> Validate returns error
func TestMDNS_1_16_7_TTLTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 4294967295},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for TTL > 2^31-1, got nil")
	}
}

// ===================================================================
// Edge case: NSEC with empty NSECTypes -> Validate error
// ===================================================================

// 1.18.A.2.2: NSECTypes=[] (empty) -> Validate error
func TestMDNS_1_18_A_2_2_EmptyNSECTypes(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{
				Name: "test.local", Type: TypeNSEC,
				NSECNextName: "next.local",
				NSECTypes: []uint16{},
			},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty NSECTypes, got nil")
	}
}

// ===================================================================
// Edge case: QTYPE 65535 (ANY) is valid
// ===================================================================

// 1.14.10: QTYPE=65534 (reserved) should be rejected
func TestMDNS_1_14_10_QTYPEInvalid(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{{Name: "test.local", Type: 65534}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for invalid QTYPE 65534, got nil")
	}
}

// ===================================================================
// Edge case: 3 questions -> QDCOUNT = 3
// ===================================================================

func TestMDNS_1_9_3_QDCOUNT3(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "a.local", Type: TypeA},
			{Name: "b.local", Type: TypeA},
			{Name: "c.local", Type: TypeA},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 6 {
		t.Fatal("payload too short")
	}
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount != 3 {
		t.Errorf("QDCOUNT=%d, want 3", qdCount)
	}
}

// ===================================================================
// Edge case: 4 answers (PTR+SRV+TXT+A) -> ANCOUNT = 4
// ===================================================================

// 1.10.3: 4 answers -> ANCOUNT = 4
func TestMDNS_1_10_3_ANCOUNT4(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "a.local", Type: TypePTR, DomainName: "b.local"},
			{Name: "b.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "c.local"},
			{Name: "b.local", Type: TypeTXT, TXTEntries: []string{"key=val"}},
			{Name: "c.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 8 {
		t.Fatal("payload too short")
	}
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if anCount != 4 {
		t.Errorf("ANCOUNT=%d, want 4", anCount)
	}
}

// ===================================================================
// Edge case: 1 additional -> ARCOUNT = 1
// ===================================================================

// 1.12.3: 1 additional -> ARCOUNT = 1
func TestMDNS_1_12_3_ARCOUNT1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "a.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		Additionals: []core.MDNSResourceRecord{
			{Name: "b.local", Type: TypeA, IPAddress: "192.168.1.2"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if len(payload) < 12 {
		t.Fatal("payload too short")
	}
	arCount := binary.BigEndian.Uint16(payload[10:12])
	if arCount != 1 {
		t.Errorf("ARCOUNT=%d, want 1", arCount)
	}
}

// ===================================================================
// Edge case: Empty QName -> encodeQName returns root terminator
// ===================================================================

func TestMDNS_EncodeQName_Empty(t *testing.T) {
	got := encodeQName("")
	want := []byte{0}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("encodeQName('') = %v, want %v", got, want)
	}
}

// ===================================================================
// Edge case: SRV Port=65535 -> 0xFFFF
// ===================================================================

// 1.24.4: SRV Port=65535 -> 0xFFFF
func TestMDNS_1_24_4_SRVPort65535(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "srv.test.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 65535, Target: "target.local"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	rdOffset := 12 + len(encodeQName("srv.test.local")) + 2 + 2 + 4 + 2
	if len(payload) < rdOffset+6 {
		t.Fatalf("payload too short")
	}
	port := binary.BigEndian.Uint16(payload[rdOffset+4 : rdOffset+6])
	if port != 65535 {
		t.Errorf("Port=%d, want 65535", port)
	}
}

// ===================================================================
// TTL=1 and TTL=75 edge cases
// ===================================================================

// 1.16.3: TTL = 1 -> 0x00000001
func TestMDNS_1_16_3_TTL1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 1},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short")
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 1 {
		t.Errorf("TTL=%d, want 1", ttl)
	}
}

// 1.16.4: TTL = 75 -> 0x0000004B
func TestMDNS_1_16_4_TTL75(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 75},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	ttlOffset := 12 + len(encodeQName("test.local")) + 4
	if len(payload) < ttlOffset+4 {
		t.Fatalf("payload too short")
	}
	ttl := binary.BigEndian.Uint32(payload[ttlOffset : ttlOffset+4])
	if ttl != 75 {
		t.Errorf("TTL=%d, want 75", ttl)
	}
}

// ===================================================================
// Label length 63 (max valid)
// ===================================================================

// 1.13.5: Label length 63 -> prefix 0x3F
func TestMDNS_1_13_5_Label63(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	err := validateQName(label63 + ".local")
	if err != nil {
		t.Errorf("unexpected error for label length 63: %v", err)
	}
}

// ===================================================================
// QName total length 255 (max valid)
// ===================================================================

// 1.13.7: QName total length 255 -> Validate OK
func TestMDNS_1_13_7_QName255(t *testing.T) {
	// Build a QName that encodes to exactly 255 bytes
	// 50 labels of 5 chars each = 50*(1+5)+1 = 301 > 255, too long
	// Let's try: 4 labels of 62 chars each = 4*(1+62)+1 = 253 < 255, OK
	// 4 labels of 63 chars each = 4*(1+63)+1 = 257 > 255, too long
	// 3 labels of 63 chars + 1 label of 62 chars = 3*64 + 63 + 1 = 256 > 255
	// 3 labels of 63 chars + 1 label of 61 chars = 3*64 + 62 + 1 = 255, exactly
	parts := []string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}
	qname := strings.Join(parts, ".")
	err := validateQName(qname)
	if err != nil {
		t.Errorf("unexpected error for QName of 255 bytes: %v", err)
	}
}

// ===================================================================
// QName total length 256 (too long)
// ===================================================================

// 1.13.8: QName total length 256 -> Validate error
func TestMDNS_1_13_8_QName256(t *testing.T) {
	parts := []string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62), // 3*64 + 63 + 1 = 256 > 255
	}
	qname := strings.Join(parts, ".")
	err := validateQName(qname)
	if err == nil {
		t.Errorf("expected error for QName of 256 bytes, got nil")
	}
}

// ===================================================================
// Label length 64 -> Validate error
// ===================================================================

// 1.13.6: Label length 64 -> Validate error
func TestMDNS_1_13_6_Label64(t *testing.T) {
	label64 := strings.Repeat("a", 64)
	err := validateQName(label64 + ".local")
	if err == nil {
		t.Errorf("expected error for label length 64, got nil")
	}
}