// 外部测试包：snmp 链的字节级对比需要 legacy snmp.NewPlanner 与 chain
// （internal/protocol/snmp + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("snmp")）。
package layers_test

import (
	"bytes"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/snmp"
)

// snmpSpec builds a minimal v2c GetRequest spec (matches legacy planner_test
// "valid v2c GetRequest" shape; Community default "public").
func snmpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 40000,
		DstPort: 161,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		SNMP: &core.SNMPConfig{
			Version:   snmp.VersionSNMPv2c,
			Community: "public",
			PDUType:   snmp.PDUGetRequest,
			VarBinds: []core.SNMPVarBind{
				{Name: "1.3.6.1.2.1.1.1.0", Type: snmp.TagNull},
			},
		},
	}
}

// maskSNMPVolatile zeroes the volatile fields that differ between two
// independent runs: IPv4 ID (18-19), IP checksum (24-25), UDP checksum
// (40-41, covers the payload difference below) and the BER request-id
// INTEGER value (SNMP message starts at packet offset 42; the request-id is
// the first INTEGER inside the PDU, its value bytes are the two bytes after
// the 02 tag + length byte — located at the first 0x02 0x04 pattern after
// offset 42). Both planners start request-id from a random base.
func maskSNMPVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 41 {
		out[18], out[19] = 0, 0 // IPID
		out[24], out[25] = 0, 0 // IP header checksum
		out[40], out[41] = 0, 0 // UDP checksum
	}
	// SNMP message at 42: SEQUENCE > version INTEGER > community OCTET
	// STRING > PDU (context tag) > request-id INTEGER. DER minimally encodes
	// the random request-id (1-4 bytes), so the mask walks the TLV chain
	// instead of matching a fixed 02 04 pattern (3-byte IDs slipped through
	// and flaked the byte-compare).
	p := 42
	if p+1 >= len(out) || out[p] != 0x30 {
		return out
	}
	p += 2 // SEQUENCE header (short form)
	p += 3 // version INTEGER 02 01 xx
	if p+1 < len(out) && out[p] == 0x04 {
		p += 2 + int(out[p+1]) // community OCTET STRING
	}
	if p+2 < len(out) && out[p]&0xA0 == 0xA0 { // PDU context tag a0/a1/a2/a3
		p += 2
		if p+1 < len(out) && out[p] == 0x02 { // request-id INTEGER
			idLen := int(out[p+1])
			for j := 0; j < idLen && p+2+j < len(out); j++ {
				out[p+2+j] = 0
			}
		}
	}
	return out
}

// assertSNMPIdentical builds both packets and compares wire bytes after
// masking the volatile fields.
func assertSNMPIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
	t.Helper()
	b := core.NewBuilder()
	cb, err := b.Build(chain)
	if err != nil {
		t.Fatalf("Build(chain[%d]): %v", idx, err)
	}
	lb, err := b.Build(legacy)
	if err != nil {
		t.Fatalf("Build(legacy[%d]): %v", idx, err)
	}
	if !bytes.Equal(maskSNMPVolatile(cb), maskSNMPVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// TestChainPlanner_SNMP_Get verifies the [ip→udp→snmp] chain emits one up
// datagram carrying the v2c GetRequest, byte-identical to legacy
// snmp.NewPlanner (modulo IPID/request-id).
func TestChainPlanner_SNMP_Get(t *testing.T) {
	spec := snmpSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	legacy := collectPlanner(t, snmp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 40000 || chain[0].L4.DstPort != 161 {
		t.Errorf("L4 = %s %d/%d, want udp 40000/161", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("L3.Protocol = %d, want %d (UDP 17)", chain[0].L3.Protocol, core.ProtocolUDP)
	}
	// Message: SEQUENCE(30) > version INTEGER(02 01 01) + community OCTET
	// STRING(04 06 'public') + GetRequest PDU (A0).
	if chain[0].Payload[0] != 0x30 {
		t.Errorf("payload[0] = 0x%02x, want 0x30 (SEQUENCE)", chain[0].Payload[0])
	}
	if chain[0].Payload[2] != 0x02 || chain[0].Payload[3] != 0x01 || chain[0].Payload[4] != 0x01 {
		t.Errorf("version INTEGER = %x, want 02 01 01 (v2c)", chain[0].Payload[2:5])
	}
	assertSNMPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SNMP_GetResponse verifies IsResponse adds the down
// datagram (swapped ports/MACs, Response PDU tag 0xA2), matching legacy.
func TestChainPlanner_SNMP_GetResponse(t *testing.T) {
	spec := snmpSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: snmp.TagOctetString, StrValue: "Linux host"},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	legacy := collectPlanner(t, snmp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	if chain[0].Direction != "up" || chain[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down", chain[0].Direction, chain[1].Direction)
	}
	if chain[1].L4.SrcPort != 161 || chain[1].L4.DstPort != 40000 {
		t.Errorf("response ports = %d/%d, want 161/40000", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	if chain[1].L2.SrcMAC != "11:22:33:44:55:66" || chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("response MACs = %s→%s, want swapped", chain[1].L2.SrcMAC, chain[1].L2.DstMAC)
	}
	// Response PDU: tag 0xA2 with the response varbind value ("Linux host").
	if !bytes.Contains(chain[1].Payload, []byte{0xA2}) {
		t.Errorf("response payload has no 0xA2 (Response) PDU tag")
	}
	if !bytes.Contains(chain[1].Payload, []byte("Linux host")) {
		t.Errorf("response payload missing ResponseValues octet string")
	}
	// The two payloads share the same request-id; verify the PDU INTEGER
	// matches after masking.
	for i := 0; i < 2; i++ {
		assertSNMPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_SNMP_GetBulk verifies the GetBulk path (non-repeaters /
// max-repetitions INTEGERs in the PDU) matches legacy bytes.
func TestChainPlanner_SNMP_GetBulk(t *testing.T) {
	spec := snmpSpec()
	spec.SNMP.PDUType = snmp.PDUGetBulkRequest
	spec.SNMP.NonRepeaters = 1
	spec.SNMP.MaxRepetitions = 5
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	legacy := collectPlanner(t, snmp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// GetBulk PDU tag 0xA5; non-repeaters=1, max-repetitions=5 INTEGERs.
	if !bytes.Contains(chain[0].Payload, []byte{0xA5}) {
		t.Errorf("payload has no 0xA5 (GetBulk) PDU tag")
	}
	if !bytes.Contains(chain[0].Payload, []byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x05}) {
		t.Errorf("payload missing non-repeaters/max-repetitions INTEGERs 01 05")
	}
	assertSNMPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SNMP_TrapV2 verifies the v2c Trap path (PDU tag 0xA7)
// matches legacy bytes. NOTE: legacy 注释声称"planner synthesises sysUpTime
// + snmpTrapOID varbinds"，但实际 buildPDU 原样传 VarBinds（无合成实现），
// 空 VarBinds 产 `A7 ... 30 00` 畸形 PDU（RFC 3416 要求至少 sysUpTime.0 +
// snmpTrapOID.0）。这是 legacy 遗留行为，波 4 字节一致（测试固化 legacy
// 输出，防波 4 回归；合成修复属 legacy 范围）。
func TestChainPlanner_SNMP_TrapV2(t *testing.T) {
	spec := snmpSpec()
	spec.SNMP.PDUType = snmp.PDUSNMPv2Trap
	spec.SNMP.VarBinds = nil // legacy 无合成：空列表照原样编码
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	legacy := collectPlanner(t, snmp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if !bytes.Contains(chain[0].Payload, []byte{0xA7}) {
		t.Errorf("payload has no 0xA7 (SNMPv2-Trap) PDU tag")
	}
	// 空 varbind list：SEQUENCE 长度 0（`30 00`），与 legacy 畸形输出一致。
	if !bytes.Contains(chain[0].Payload, []byte{0x30, 0x00}) {
		t.Errorf("payload missing empty varbind list 30 00 (legacy 遗留行为)")
	}
	assertSNMPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SNMP_DefaultPorts verifies the chain defaults dst port by
// PDU type (161 for Get, 162 for trap) when the spec omits it.
func TestChainPlanner_SNMP_DefaultPorts(t *testing.T) {
	spec := snmpSpec()
	spec.DstPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	if chain[0].L4.DstPort != 161 {
		t.Errorf("dst port = %d, want 161 (Get default)", chain[0].L4.DstPort)
	}

	trap := snmpSpec()
	trap.DstPort = 0
	trap.SNMP.PDUType = snmp.PDUTrapV1
	chainTrap := collectPlanner(t, layers.NewChainPlanner("snmp"), trap)
	if chainTrap[0].L4.DstPort != 162 {
		t.Errorf("trap dst port = %d, want 162 (TrapV1 default)", chainTrap[0].L4.DstPort)
	}
}

// TestChainPlanner_SNMP_ValidateNegative mirrors the legacy Validate contract:
// nil SNMP config now defaults (P0b-2), bad version, PDUType 8, empty varbinds
// for Get, malformed OID must fail.
func TestChainPlanner_SNMP_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("snmp")

	spec := snmpSpec()
	spec.SNMP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(nil SNMP config) = %v, want nil (default flow, P0b-2)", err)
	}

	spec = snmpSpec()
	spec.SNMP.Version = 2
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Version 2) = nil, want error")
	}

	spec = snmpSpec()
	spec.SNMP.PDUType = 8
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(PDUType 8) = nil, want error")
	}

	spec = snmpSpec()
	spec.SNMP.VarBinds = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(empty varbinds Get) = nil, want error")
	}

	spec = snmpSpec()
	spec.SNMP.VarBinds = []core.SNMPVarBind{{Name: "1.3.6..1", Type: snmp.TagNull}}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(malformed OID) = nil, want error")
	}
}

// TestChainPlanner_SNMP_Repeat verifies RepeatCount produces repeated
// request/response pairs with incrementing request-ids, matching legacy.
func TestChainPlanner_SNMP_Repeat(t *testing.T) {
	spec := snmpSpec()
	spec.SNMP.RepeatCount = 2
	spec.SNMP.RequestID = 100 // deterministic start
	chain := collectPlanner(t, layers.NewChainPlanner("snmp"), spec)
	legacy := collectPlanner(t, snmp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// Request-id INTEGER (BER): scan for the 02 tag, read the length byte,
	// decode the value; the first INTEGER whose value fits uint32 is the
	// request-id (version comes first but is a 1-byte value 0/1/3). We look
	// for the value 100/101 by decoding every INTEGER and matching.
	for i := 0; i < 2; i++ {
		want := uint32(100 + i)
		found := false
		for j := 0; j+2 < len(chain[i].Payload); j++ {
			if chain[i].Payload[j] != 0x02 {
				continue
			}
			l := int(chain[i].Payload[j+1])
			if l <= 0 || l > 4 || j+2+l > len(chain[i].Payload) {
				continue
			}
			var v uint32
			for k := 0; k < l; k++ {
				v = v<<8 | uint32(chain[i].Payload[j+2+k])
			}
			if v == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("packet %d request-id = not found, want %d", i, want)
		}
		assertSNMPIdentical(t, chain[i], legacy[i], i)
	}
}
