// Package geneve implements the GENEVE (RFC 8926) terminal layer: outer
// IPv4/IPv6 + UDP/6081 carrying an 8-byte base header, zero or more 4-byte
// aligned options, and an inner Ethernet frame. Event-mode generator
// (vxlan/socks5 同款)——每个数据报一个 MessageEvent，udp 层生成器逐事件上包
// （方向/事件级端口覆盖由事件携带），TCP/IP/以太网外层语义交给链上层。
//
// 线格式（RFC 8926 §3）：byte0 = Ver(2)+OptLen(6，单位 4B)、byte1 =
// OAM(bit7=0x80)+Critical(bit6=0x40)+Rsvd(低 6 bits 须零)、Protocol Type(2,
// BE，正例主档 0x6558 TEB)、VNI(3, BE)、Reserved(1, 零)。option 头 4B =
// Class(2)+Type(1)+Rsvd(3 bits 须零)+Length(5 bits，单位 4B)+data。GENEVE
// 基础头固定 8 字节，IPv4 外层起点 42、IPv6 外层 62，无 options 的内层
// Ethernet 起点 50/70（options 每增 4B 内层起点 +4）。
package geneve

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 线格式常量（RFC 8926）。
const (
	// geneveHeaderLen is the fixed 8-byte base header.
	geneveHeaderLen = 8
	// optionHeaderLen is the fixed 4-byte option header preceding each
	// option's data.
	optionHeaderLen = 4
	// flagOAM / flagCritical are bits 7/6 of base-header byte 1.
	flagOAM      = 0x80
	flagCritical = 0x40
	// maxVNI is the 24-bit VNI ceiling.
	maxVNI = 0xffffff
	// maxOptLen is the 6-bit Opt Len ceiling in 4-byte units (RFC 8926 §3:
	// 63 units = 252 option bytes).
	maxOptLen = 63
	// maxOptDataLen is the 5-bit per-option Length ceiling in 4-byte units
	// (RFC 8926 §3.4: 31 units = 124 option data bytes).
	maxOptDataLen = 31
	// protoTEB is the Protocol Type for Ethernet (Transparent Ethernet
	// Bridging); ProtocolType 0 defaults to it.
	protoTEB = 0x6558
	// udpPort is the IANA-assigned GENEVE UDP destination port.
	udpPort = 6081
)

// wireFaultKinds are the negative-case fault injections（validator 消费——
// 注入即拒绝，不是线上字段）。kind ↔ 设计 §4 锚词。
const (
	faultNone            = ""
	faultHeaderTruncated = "header_truncated" // → header/length
	faultReservedFlags   = "reserved_flags"   // → version/flag/reserved
	faultOptionLength    = "option_length"    // → option/length
	faultVNIOverflow     = "vni_overflow"     // → vni
	faultWrongUDPPort    = "wrong_udp_port"   // → port/transport
	faultInnerTruncated  = "inner_truncated"  // → inner
	faultChecksum        = "checksum"         // → checksum
)

// GeneveGenerator emits one message event per configured datagram（顶层
// VNI/Version/OAM/Critical/Options/Inner 折叠为单事件；Datagrams 非空逐项
// 一事件）。
type GeneveGenerator struct{}

func (g *GeneveGenerator) Name() string { return "geneve" }

// GenEvents marks this generator as a message event producer.
func (g *GeneveGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *GeneveGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("geneve generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate produces the GENEVE datagram event stream. Bytes = 8-byte base
// header + options + inner Ethernet frame（udp 层把事件包成 UDP 数据报）。
func (g *GeneveGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("geneve generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.Geneve
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	for i, d := range foldDatagrams(cfg) {
		inner, err := core.BuildEncapEthernetFrame(d.inner)
		if err != nil {
			return fmt.Errorf("geneve: datagram[%d] %v", i, err)
		}
		opts, err := buildOptions(d.options)
		if err != nil {
			return fmt.Errorf("geneve: datagram[%d] %v", i, err)
		}
		ev := layers.MessageEvent{
			Up:      d.up,
			Bytes:   append(buildGeneveHeader(d.vni, d.version, d.oam, d.critical, len(opts)/optionHeaderLen), opts...),
			SrcPort: d.srcPort,
		}
		ev.Bytes = append(ev.Bytes, inner...)
		if d.srcPort != 0 && !d.up {
			// down 方向显式端口用绝对语义（udp 层 L4PortOverride 跳过
			// up/down 端口交换）：SrcPort=6081 侧、DstPort=客户端端口。
			ev.SrcPort = udpPort
			ev.DstPort = d.srcPort
			ev.L4PortOverride = true
		}
		if err := g.emitMsg(ctx, req.EmitMsg, ev); err != nil {
			return err
		}
	}
	return nil
}

// emitMsg sends one event, honoring context cancellation（vxlan 同款
// escape hatch——传输层停止消费时生成器不能挂死）。
func (g *GeneveGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// datagram is the folded per-event unit.
type datagram struct {
	vni      uint32
	version  uint8
	oam      bool
	critical bool
	srcPort  uint16
	up       bool
	options  []core.GeneveOption
	inner    *core.EncapEthernetFixture
}

// foldDatagrams maps the config onto the event list: empty Datagrams → a
// single event from the top-level fields（空配置默认流：VNI=0、version=0、
// 无 flags/options、内建最小 fixture，P0b 同款）；否则逐项（entry Options/
// Inner nil → 顶层回退；entry Version/OAM/Critical nil → 顶层回退）。
func foldDatagrams(cfg *core.GeneveConfig) []datagram {
	if cfg == nil {
		return []datagram{{vni: 0, up: true, inner: defaultFixture()}}
	}
	if len(cfg.Datagrams) == 0 {
		return []datagram{{
			vni:      cfg.VNI,
			version:  cfg.Version,
			oam:      cfg.OAM,
			critical: cfg.Critical,
			up:       true,
			options:  cfg.Options,
			inner:    effectiveInner(cfg.Inner),
		}}
	}
	out := make([]datagram, 0, len(cfg.Datagrams))
	for i := range cfg.Datagrams {
		e := &cfg.Datagrams[i]
		version := cfg.Version
		if e.Version != nil {
			version = *e.Version
		}
		oam := cfg.OAM
		if e.OAM != nil {
			oam = *e.OAM
		}
		critical := cfg.Critical
		if e.Critical != nil {
			critical = *e.Critical
		}
		options := cfg.Options
		if e.Options != nil {
			options = e.Options
		}
		out = append(out, datagram{
			vni:      e.VNI,
			version:  version,
			oam:      oam,
			critical: critical,
			srcPort:  e.SrcPort,
			up:       e.Up == nil || *e.Up,
			options:  options,
			inner:    effectiveInner(e.Inner, cfg.Inner),
		})
	}
	return out
}

// effectiveInner resolves the fixture: first non-nil wins; both nil → the
// built-in default（空配置默认流，合法可解析最小 fixture）。
func effectiveInner(inners ...*core.EncapEthernetFixture) *core.EncapEthernetFixture {
	for _, f := range inners {
		if f != nil {
			return f
		}
	}
	return defaultFixture()
}

// defaultFixture is the empty-config default inner frame.
func defaultFixture() *core.EncapEthernetFixture {
	return &core.EncapEthernetFixture{
		SrcMAC:    "02:00:00:00:11:01",
		DstMAC:    "02:00:00:00:11:02",
		EtherType: "ipv4",
		SrcIP:     "10.11.0.1",
		DstIP:     "10.11.0.2",
		Payload:   []byte("geneve-default-inner"),
	}
}

// buildGeneveHeader encodes the fixed 8-byte base header: byte0 =
// Ver(2)+OptLen(6)，byte1 = OAM(bit7)+Critical(bit6)+Rsvd(零)，Protocol
// Type 0x6558（2, BE），VNI（3, BE），尾部保留零。optLenUnits 是 4-byte
// 单位的 options 总长（调用方已校验 ≤ 63）。
func buildGeneveHeader(vni uint32, version uint8, oam, critical bool, optLenUnits int) []byte {
	hdr := make([]byte, geneveHeaderLen)
	hdr[0] = version<<6 | uint8(optLenUnits)
	if oam {
		hdr[1] |= flagOAM
	}
	if critical {
		hdr[1] |= flagCritical
	}
	binary.BigEndian.PutUint16(hdr[2:4], protoTEB)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(vni>>8))
	hdr[6] = byte(vni)
	return hdr
}

// buildOptions encodes the option chain in config order: per option a 4-byte
// header (Class 2, Type 1, Rsvd 3 bits + Length 5 bits in 4-byte units)
// followed by the data. Data must be 4-byte aligned (validator enforces);
// a zero-length option encodes Length=0 (legal boundary, RFC 8926 §3.4).
func buildOptions(opts []core.GeneveOption) ([]byte, error) {
	total := 0
	for i := range opts {
		total += optionHeaderLen + len(opts[i].Data)
	}
	out := make([]byte, 0, total)
	for i := range opts {
		o := &opts[i]
		if len(o.Data)%optionHeaderLen != 0 {
			return nil, fmt.Errorf("option[%d] data length %d is not a multiple of 4 bytes (RFC 8926 options are 4-byte aligned)", i, len(o.Data))
		}
		hdr := make([]byte, optionHeaderLen)
		binary.BigEndian.PutUint16(hdr[0:2], o.Class)
		hdr[2] = o.Type
		hdr[3] = o.Rsvd<<5 | uint8(len(o.Data)/optionHeaderLen)
		out = append(out, hdr...)
		out = append(out, o.Data...)
	}
	return out, nil
}

// ValidateConfig rejects configs that must never reach the wire（设计 §4）:
// VNI beyond 24 bits, a nonzero version (RFC 8926 assigns version 0; higher
// versions are unparseable by this dissector), option length faults (data
// not 4-byte aligned, total beyond the 6-bit Opt Len range, nonzero option
// reserved bits), a protocol type other than TEB paired with an Ethernet
// inner fixture, unknown wire faults, and inner fixture faults. Explicit
// boundaries (VNI=0, empty payload, zero-length option, OAM/Critical set)
// are legal and must NOT be rejected.
func ValidateConfig(cfg *core.GeneveConfig) error {
	if cfg == nil {
		return nil
	}
	if err := validateVNI(cfg.VNI); err != nil {
		return err
	}
	if cfg.Version != 0 {
		return fmt.Errorf("geneve: version %d is not zero — RFC 8926 defines version 0 only; nonzero reserved version/flags are invalid", cfg.Version)
	}
	if err := validateOptions(cfg.Options); err != nil {
		return err
	}
	proto := cfg.ProtocolType
	if proto == 0 {
		proto = protoTEB
	}
	if err := validateProtoInner(proto, cfg.Inner); err != nil {
		return err
	}
	if err := core.ValidateEncapFixture(cfg.Inner, "geneve"); err != nil {
		return err
	}
	for i := range cfg.Datagrams {
		e := &cfg.Datagrams[i]
		if err := validateVNI(e.VNI); err != nil {
			return fmt.Errorf("geneve: datagrams[%d] %v", i, err)
		}
		version := cfg.Version
		if e.Version != nil {
			version = *e.Version
		}
		if version != 0 {
			return fmt.Errorf("geneve: datagrams[%d].version %d is not zero — RFC 8926 defines version 0 only; nonzero reserved version/flags are invalid", i, version)
		}
		if err := validateOptions(e.Options); err != nil {
			return fmt.Errorf("geneve: datagrams[%d] %v", i, err)
		}
		proto := cfg.ProtocolType
		if proto == 0 {
			proto = protoTEB
		}
		if err := validateProtoInner(proto, e.Inner); err != nil {
			return fmt.Errorf("geneve: datagrams[%d] %v", i, err)
		}
		if err := core.ValidateEncapFixture(e.Inner, "geneve"); err != nil {
			return fmt.Errorf("geneve: datagrams[%d] %v", i, err)
		}
	}
	return validateWireFault(cfg.WireFault)
}

// validateVNI rejects VNI values beyond the 24-bit field.
func validateVNI(vni uint32) error {
	if vni > maxVNI {
		return fmt.Errorf("geneve: vni %d exceeds 24-bit range 0..%d (RFC 8926 §3)", vni, maxVNI)
	}
	return nil
}

// validateOptions checks every option: data must be 4-byte aligned, the
// option reserved bits must be zero, and the chain total must fit the
// 6-bit Opt Len field (63 units = 252 bytes).
func validateOptions(opts []core.GeneveOption) error {
	total := 0
	for i := range opts {
		o := &opts[i]
		if len(o.Data)%optionHeaderLen != 0 {
			return fmt.Errorf("geneve: options[%d] data length %d is not a multiple of 4 bytes — Opt Len and option length are counted in 4-byte units (RFC 8926 §3.4)", i, len(o.Data))
		}
		if o.Rsvd != 0 {
			return fmt.Errorf("geneve: options[%d] reserved bits are nonzero — the 3 reserved bits above the option length field must be zero (RFC 8926 §3.4)", i)
		}
		if units := len(o.Data) / optionHeaderLen; units > maxOptDataLen {
			return fmt.Errorf("geneve: options[%d] data length %d exceeds the 5-bit option length field (%d units = %d bytes max) — option length overflow", i, len(o.Data), maxOptDataLen, maxOptDataLen*optionHeaderLen)
		}
		total += optionHeaderLen + len(o.Data)
	}
	if units := total / optionHeaderLen; units > maxOptLen {
		return fmt.Errorf("geneve: options total %d bytes exceeds the 6-bit Opt Len range (%d units = %d bytes) — option length overflow", total, maxOptLen, maxOptLen*optionHeaderLen)
	}
	return nil
}

// validateProtoInner rejects a non-TEB protocol type outright: this generator
// always emits an Ethernet inner frame（fixture 缺失时也有默认帧），声明其他
// protocol type 会产生线上字节与声明自相矛盾的包（protocol 锚词，设计 §4）。
func validateProtoInner(proto uint16, inner *core.EncapEthernetFixture) error {
	if proto != protoTEB {
		return fmt.Errorf("geneve: protocol type 0x%04x is not supported — only TEB 0x%04x (encapsulated Ethernet) can be generated", proto, protoTEB)
	}
	return nil
}

// validateWireFault rejects every injected fault with its design §4 anchor
// word, and any unknown kind.
func validateWireFault(f *core.EncapWireFault) error {
	if f == nil {
		return nil
	}
	switch f.Kind {
	case faultNone:
		return nil
	case faultHeaderTruncated:
		return fmt.Errorf("geneve: wire_fault header_truncated — the GENEVE base header is a fixed 8-byte length header; fewer bytes cannot be encoded (RFC 8926 §3)")
	case faultReservedFlags:
		return fmt.Errorf("geneve: wire_fault reserved_flags — nonzero version or OAM/Critical-adjacent reserved flags are invalid; reserved bits must be zero (RFC 8926 §3)")
	case faultOptionLength:
		return fmt.Errorf("geneve: wire_fault option_length — Opt Len must equal the options bytes/4 and every option data must be 4-byte aligned; truncated or misaligned options are rejected")
	case faultVNIOverflow:
		return fmt.Errorf("geneve: wire_fault vni_overflow — the VNI is a 24-bit field; values beyond 0xffffff or a polluted 4th byte are rejected")
	case faultWrongUDPPort:
		return fmt.Errorf("geneve: wire_fault wrong_udp_port — GENEVE rides UDP destination port 6081 only; TCP or other transports/ports are rejected")
	case faultInnerTruncated:
		return fmt.Errorf("geneve: wire_fault inner_truncated — the inner Ethernet frame must not truncate inside MAC/VLAN/EtherType/IP headers (length conflict)")
	case faultChecksum:
		return fmt.Errorf("geneve: wire_fault checksum — IPv6 UDP checksum zero or a mismatching checksum is rejected (RFC 768/8200)")
	default:
		return fmt.Errorf("geneve: unknown wire_fault kind %q", f.Kind)
	}
}

func init() {
	layers.RegisterLayerGenerator("geneve", func() (layers.LayerGenerator, error) {
		return &GeneveGenerator{}, nil
	})
	layers.RegisterLayerValidator("geneve", func(spec *core.FlowSpec) error {
		// GENEVE 只走 UDP/6081：显式写非 6081 目的端口即负例（udp_carrier
		// 锚词 "port"）；0 = 未写，由 FieldContract 补 6081。
		if spec.Geneve != nil && spec.DstPort != 0 && spec.DstPort != udpPort {
			return fmt.Errorf("geneve: wire_fault wrong_udp_port — destination port %d is not the IANA GENEVE UDP port %d; TCP or other transports/ports are rejected", spec.DstPort, udpPort)
		}
		return ValidateConfig(spec.Geneve)
	})
}
