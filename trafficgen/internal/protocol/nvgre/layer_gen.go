// Package nvgre implements the NVGRE (RFC 7637) terminal layer: outer IPv4/
// IPv6 (IP protocol 47 GRE) carrying an inner Ethernet frame, with the GRE
// header written by the core builder from L2Config.GRE and the inner frame
// bytes assembled here from the shared EncapEthernetFixture.
//
// 链形：[ip, nvgre]（raw-IP 终结层，同 igmp/ospf/pim 驱动分支）。与设计稿
// [ip,gre,nvgre] 的分歧已在层注册表文档化：gre 隧道层生成器要求内层包链
// 且 ProtocolType 限 0x0800/0x0806/0x86DD，NVGRE 内层是裸 Ethernet 帧——
// 故由本生成器自产完整包（外层 IP 头经 L3Config，GRE 头经 L2.GRE，内层
// Ethernet 帧作为 Payload 原样透传）。
package nvgre

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Wire-format constants (RFC 7637 §3 / RFC 2784 §2 / RFC 2890).
const (
	// flagsAndVersion is the GRE Flags+Version word for NVGRE: K=1 only
	// (C/R/S/s, Recursion and Version all clear).
	flagsAndVersion = 0x2000
	// protocolTypeTEB is Transparent Ethernet Bridging — the GRE Protocol
	// Type mandated for NVGRE payloads.
	protocolTypeTEB = 0x6558
	// maxVSID is the 24-bit VSID ceiling (RFC 7637 §3: VSID occupies the
	// Key's high 24 bits).
	maxVSID = 0xffffff
	// defaultTTL is the outer IPv4 TTL / IPv6 hop limit when nvgre.ttl is
	// not provided.
	defaultTTL = 64
	// innerProtoIPv4 / innerProtoIPv6NoNext: the inner L3 headers use a
	// deliberately unassigned IPv4 protocol (253, RFC 3692) and IPv6 No
	// Next Header (59) so tshark never dissects the inner payload into
	// malformed artifacts.
	innerProtoIPv4      = 253
	innerIPv6NoNextHdr  = 59
	innerDefaultTTL     = 64
	vlanTPID            = 0x8100
	innerIPv4HeaderLen  = 20
	innerIPv6HeaderLen  = 40
	outerIPv4GREOverhead = 14 + 20 + 8 // Eth + outer IPv4 + GRE base+Key
	// maxInnerPayload bounds the v4-inner payload so the encapsulated frame
	// still fits the outer IPv4 total-length field (16-bit, no wraparound):
	// total length = outerIPv4GREOverhead + 20(inner v4) + payload. The
	// v6-inner bound is smaller (40-byte inner header) and is computed
	// per-ether_type in validateFixture.
	maxInnerPayload = 0xffff - outerIPv4GREOverhead - innerIPv4HeaderLen
)

// NVGREGenerator emits complete NVGRE packets via req.Emit (raw-IP chain).
type NVGREGenerator struct{}

func (g *NVGREGenerator) Name() string                     { return "nvgre" }
func (g *NVGREGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits one packet per configured datagram (top-level VSID/FlowID/
// Inner when Datagrams is empty). The raw-IP branch of the ChainPlanner fills
// L2 MACs/EtherType, DSCP, FlowID and the timestamp, and swaps L3 addresses
// for "down" packets — this generator always emits up-oriented packets with
// meta.SrcIP/DstIP.
func (g *NVGREGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("nvgre generator: Emit is nil")
	}
	cfg := req.Meta.NVGRE
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	ttl := outerTTL(cfg)
	for i, d := range foldDatagrams(cfg) {
		inner, err := buildInnerFrame(effectiveInner(cfg, d))
		if err != nil {
			return fmt.Errorf("nvgre: datagram[%d] %v", i, err)
		}
		direction := "up"
		if d.up != nil && !*d.up {
			direction = "down"
		}
		pkt := core.PacketConfig{
			Direction: direction,
			L3: core.L3Config{
				SrcIP:    req.Meta.SrcIP,
				DstIP:    req.Meta.DstIP,
				Protocol: core.ProtocolGRE,
				TTL:      ttl,
			},
			L2: core.L2Config{
				GRE: &core.GREConfig{
					KeyPresent:   true,
					Key:          GREKey(d.vsid, d.flowID),
					ProtocolType: core.EtherTypeTEB,
				},
			},
			Payload: inner,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := req.Emit(pkt); err != nil {
				return err
			}
		}
	}
	return nil
}

// datagram is the folded per-packet unit (one emitted packet each).
type datagram struct {
	vsid   uint32
	flowID uint8
	up     *bool
	inner  *core.EncapEthernetFixture
}

// foldDatagrams maps the config onto the emitted packet list: empty
// Datagrams → a single packet from the top-level VSID/FlowID/Inner;
// otherwise one packet per entry (entry Inner nil → top-level Inner).
func foldDatagrams(cfg *core.NVGREConfig) []datagram {
	if cfg == nil {
		return []datagram{{vsid: 0, flowID: 0, inner: nil}}
	}
	if len(cfg.Datagrams) == 0 {
		return []datagram{{vsid: cfg.VSID, flowID: cfg.FlowID, inner: cfg.Inner}}
	}
	out := make([]datagram, 0, len(cfg.Datagrams))
	for i := range cfg.Datagrams {
		e := &cfg.Datagrams[i]
		inner := e.Inner
		if inner == nil {
			inner = cfg.Inner
		}
		out = append(out, datagram{vsid: e.VSID, flowID: e.FlowID, up: e.Up, inner: inner})
	}
	return out
}

// effectiveInner resolves the fixture for one datagram, falling back to the
// built-in default when neither the entry nor the config provides one
// (empty-config default flow, P0b 同款).
func effectiveInner(_ *core.NVGREConfig, d datagram) *core.EncapEthernetFixture {
	if d.inner != nil {
		return d.inner
	}
	return defaultFixture()
}

// defaultFixture is the empty-config default inner frame (合法可解析的
// 最小 fixture；显式配置永远覆盖它)。
func defaultFixture() *core.EncapEthernetFixture {
	return &core.EncapEthernetFixture{
		SrcMAC:    "02:00:00:00:00:01",
		DstMAC:    "02:00:00:00:00:02",
		EtherType: "ipv4",
		SrcIP:     "172.16.1.1",
		DstIP:     "172.16.1.2",
		Payload:   []byte("nvgre-default-inner"),
	}
}

// outerTTL resolves the outer TTL/hop limit: explicit *cfg.TTL wins (0/1/255
// are legal design boundaries and must not be defaulted), nil → 64.
func outerTTL(cfg *core.NVGREConfig) uint8 {
	if cfg == nil || cfg.TTL == nil {
		return defaultTTL
	}
	return *cfg.TTL
}

// GREKey encodes the 32-bit GRE Key in wire arithmetic:
// Key = VSID(24) << 8 | FlowID(8). The core builder serializes it with
// binary.BigEndian.PutUint32, so the wire bytes are exactly
// VSID[23:16] | VSID[15:8] | VSID[7:0] | FlowID (network byte order).
// VSID is never truncated to 16 bits and FlowID never leaks into VSID.
func GREKey(vsid uint32, flowID uint8) uint32 {
	return (vsid & maxVSID) << 8 | uint32(flowID)
}

// buildInnerFrame assembles the complete inner Ethernet frame:
// DstMAC(6) | SrcMAC(6) | [802.1Q(4)] | EtherType(2) | inner L3 | payload.
// Inner IPv4 headers carry a correct checksum (tshark flags bad ones as
// expert info, which fails the case); inner IPv6 uses next header 59.
func buildInnerFrame(fix *core.EncapEthernetFixture) ([]byte, error) {
	if fix == nil {
		fix = defaultFixture()
	}
	if err := validateFixture(fix); err != nil {
		return nil, err
	}
	dstMAC, _ := net.ParseMAC(fix.DstMAC)
	srcMAC, _ := net.ParseMAC(fix.SrcMAC)

	var l3, ipBytes []byte
	isV6 := fix.EtherType == "ipv6" || fix.EtherType == "vlan_ipv6"
	payloadLen := len(fix.Payload)
	if isV6 {
		l3 = make([]byte, innerIPv6HeaderLen)
		l3[0] = 6 << 4 // version 6, traffic class / flow label 0
		binary.BigEndian.PutUint16(l3[4:6], uint16(payloadLen))
		l3[6] = innerIPv6NoNextHdr
		l3[7] = innerDefaultTTL
		copy(l3[8:24], net.ParseIP(fix.SrcIP).To16())
		copy(l3[24:40], net.ParseIP(fix.DstIP).To16())
	} else {
		l3 = make([]byte, innerIPv4HeaderLen)
		l3[0] = 0x45 // version 4, IHL 5
		binary.BigEndian.PutUint16(l3[2:4], uint16(innerIPv4HeaderLen+payloadLen))
		l3[8] = innerDefaultTTL
		l3[9] = innerProtoIPv4
		copy(l3[12:16], net.ParseIP(fix.SrcIP).To4())
		copy(l3[16:20], net.ParseIP(fix.DstIP).To4())
		binary.BigEndian.PutUint16(l3[10:12], ipv4Checksum(l3))
	}

	frame := make([]byte, 0, len(dstMAC)+len(srcMAC)+4+2+len(l3)+payloadLen)
	frame = append(frame, dstMAC...)
	frame = append(frame, srcMAC...)
	if fix.EtherType == "vlan_ipv4" || fix.EtherType == "vlan_ipv6" {
		// 802.1Q tag: TPID 0x8100 + TCI = PCP(3)<<13 | DEI(0) | VID(12).
		tci := uint16(fix.VLANPriority&0x7)<<13 | fix.VLANID&0x0fff
		frame = append(frame, byte(vlanTPID>>8), byte(vlanTPID&0xff))
		frame = append(frame, byte(tci>>8), byte(tci))
	}
	if isV6 {
		ipBytes = []byte{0x86, 0xdd}
	} else {
		ipBytes = []byte{0x08, 0x00}
	}
	frame = append(frame, ipBytes...)
	frame = append(frame, l3...)
	frame = append(frame, fix.Payload...)
	return frame, nil
}

// ipv4Checksum computes the RFC 1071 header checksum over a zeroed
// checksum field (caller writes it back).
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		if i == 10 {
			continue // checksum field itself (already zero)
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// wireFaultKinds are the negative-case fault injections (validator/planner
// 消费——注入即拒绝，不是线上字段)。
const (
	faultNone              = ""
	faultFlagsReserved     = "flags_reserved"
	faultProtocolNotTEB    = "protocol_not_teb"
	faultKeyMissing        = "key_missing"
	faultKeyEndian         = "key_endian"
	faultVSIDFlowIsolation = "vsid_flow_isolation"
	faultCarrierProtocol   = "carrier_protocol"
	faultLengthWrap        = "length_wrap"
)

// ValidateConfig rejects configs that must never reach the wire (design §7):
// VSID beyond 24 bits, unknown wire faults, and inner Ethernet fixture
// faults. Explicit boundary values (VSID=0, FlowID=0, empty payload,
// VLAN VID=0) are legal and must NOT be rejected here.
func ValidateConfig(cfg *core.NVGREConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.VSID > maxVSID {
		return fmt.Errorf("nvgre: vsid %d exceeds 24-bit range 0..%d (RFC 7637 §3)", cfg.VSID, maxVSID)
	}
	for i := range cfg.Datagrams {
		if cfg.Datagrams[i].VSID > maxVSID {
			return fmt.Errorf("nvgre: datagrams[%d] vsid %d exceeds 24-bit range 0..%d (RFC 7637 §3)", i, cfg.Datagrams[i].VSID, maxVSID)
		}
	}
	if err := validateFixture(cfg.Inner); err != nil {
		return err
	}
	for i := range cfg.Datagrams {
		if err := validateFixture(cfg.Datagrams[i].Inner); err != nil {
			return fmt.Errorf("nvgre: datagrams[%d] %v", i, err)
		}
	}
	return validateWireFault(cfg.WireFault)
}

// validateWireFault rejects every injected fault (each with its testcase
// anchor word) and any unknown kind.
func validateWireFault(f *core.EncapWireFault) error {
	if f == nil {
		return nil
	}
	switch f.Kind {
	case faultNone:
		return nil
	case faultFlagsReserved:
		return fmt.Errorf("nvgre: wire_fault flags_reserved: GRE FlagsAndVersion must be 0x%04x (K bit only); C/R/S/s, reserved or version bits are invalid NVGRE flags (RFC 7637 §3)", flagsAndVersion)
	case faultProtocolNotTEB:
		return fmt.Errorf("nvgre: wire_fault protocol_not_teb: GRE protocol type must be 0x%04x (Transparent Ethernet Bridging, RFC 7637 §3), not 0x%04x", protocolTypeTEB, f.Value)
	case faultKeyMissing:
		return fmt.Errorf("nvgre: wire_fault key_missing: NVGRE requires the GRE K bit and a 4-byte key (RFC 7637 §3); a missing/truncated key is rejected")
	case faultKeyEndian:
		return fmt.Errorf("nvgre: wire_fault key_endian: the GRE key must be encoded network byte order as VSID(24)<<8|FlowID(8) (RFC 7637 §3); host byte order or truncated keys are rejected")
	case faultVSIDFlowIsolation:
		return fmt.Errorf("nvgre: wire_fault vsid_flow_isolation: cross-VSID/flow state reuse or undeclared replication breaks VSID isolation (design §7.8)")
	case faultCarrierProtocol:
		return fmt.Errorf("nvgre: wire_fault carrier_protocol: NVGRE rides IP protocol 47 GRE only; UDP/TCP/bare-IP carriers are rejected (design §7.1)")
	case faultLengthWrap:
		return fmt.Errorf("nvgre: wire_fault length_wrap: negative payload, length wraparound or beyond frame_max is rejected (design §7.9)")
	default:
		return fmt.Errorf("nvgre: unknown wire_fault kind %q", f.Kind)
	}
}

// validateFixture rejects inner Ethernet fixture faults: unparseable MACs,
// an unknown ether_type, a VID beyond 12 bits, a PCP beyond 3 bits, an
// inner IP family mismatching the ether_type, or an inner frame that would
// overflow the outer IPv4 total-length field.
func validateFixture(fix *core.EncapEthernetFixture) error {
	if fix == nil {
		return nil
	}
	srcMAC, err := net.ParseMAC(fix.SrcMAC)
	if err != nil || len(srcMAC) != 6 {
		return fmt.Errorf("nvgre: inner src_mac %q is not a valid 6-byte MAC", fix.SrcMAC)
	}
	dstMAC, err := net.ParseMAC(fix.DstMAC)
	if err != nil || len(dstMAC) != 6 {
		return fmt.Errorf("nvgre: inner dst_mac %q is not a valid 6-byte MAC", fix.DstMAC)
	}
	isV6 := false
	switch fix.EtherType {
	case "ipv4":
	case "ipv6":
		isV6 = true
	case "vlan_ipv4":
	case "vlan_ipv6":
		isV6 = true
	default:
		return fmt.Errorf("nvgre: inner ether_type %q not in {ipv4, ipv6, vlan_ipv4, vlan_ipv6}", fix.EtherType)
	}
	if fix.VLANID > 0x0fff {
		return fmt.Errorf("nvgre: inner vlan_id %d exceeds the 12-bit VID range 0..4095 (IEEE 802.1Q)", fix.VLANID)
	}
	if fix.VLANPriority > 7 {
		return fmt.Errorf("nvgre: inner vlan_priority %d exceeds the 3-bit PCP range 0..7 (IEEE 802.1Q)", fix.VLANPriority)
	}
	checkFamily := func(kind, addr string) error {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("nvgre: inner %s %q is not a valid IP address", kind, addr)
		}
		if (ip.To4() != nil) == isV6 {
			want := "IPv4"
			if isV6 {
				want = "IPv6"
			}
			return fmt.Errorf("nvgre: inner address family mismatch: ether_type %q requires %s %s, got %q", fix.EtherType, want, kind, addr)
		}
		return nil
	}
	if err := checkFamily("src_ip", fix.SrcIP); err != nil {
		return err
	}
	if err := checkFamily("dst_ip", fix.DstIP); err != nil {
		return err
	}
	if isV6 {
		if len(fix.Payload) > 0xffff-20-8-14-innerIPv6HeaderLen {
			return fmt.Errorf("nvgre: inner payload length %d exceeds the IPv6-inner encapsulation limit %d (outer IPv4 total length must not wrap around, design §7.9)", len(fix.Payload), 0xffff-20-8-14-innerIPv6HeaderLen)
		}
		return nil
	}
	if len(fix.Payload) > maxInnerPayload {
		return fmt.Errorf("nvgre: inner payload length %d exceeds the encapsulation limit %d (outer IPv4 total length must not wrap around, design §7.9)", len(fix.Payload), maxInnerPayload)
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("nvgre", func() (layers.LayerGenerator, error) {
		return &NVGREGenerator{}, nil
	})
	layers.RegisterLayerValidator("nvgre", func(spec *core.FlowSpec) error {
		return ValidateConfig(spec.NVGRE)
	})
}
