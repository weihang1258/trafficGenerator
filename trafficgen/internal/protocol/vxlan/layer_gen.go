// Package vxlan implements the VXLAN (RFC 7348) terminal layer: outer
// IPv4/IPv6 + UDP/4789 carrying an 8-byte VXLAN header and an inner Ethernet
// frame. Event-mode generator (socks5/gtp 同款)——每个数据报一个
// MessageEvent，udp 层生成器逐事件上包（方向/事件级端口覆盖由事件携带），
// TCP/IP/以太网外层语义交给链上层。
//
// 线格式（RFC 7348 §4）：Flags(1, I=bit3→0x08) + Reserved(3) + VNI(3,
// big-endian) + Reserved(1)；VXLAN 头固定 8 字节，IPv4 外层起点 42、IPv6
// 外层 62，内层 Ethernet 起点 50/70。VNI=0 与 VNI=0xffffff 是合法 24-bit
// 边界值；I flag 未置位/保留位非零进负例（validator 拒绝）。
package vxlan

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 线格式常量（RFC 7348）。
const (
	// flagI is the I bit (bit 3) in the VXLAN flags byte——I 置位时 VNI
	// 才是有效网络标识；本版全部数据面正例要求置位。
	flagI = 0x08
	// vxlanHeaderLen is the fixed 8-byte VXLAN header.
	vxlanHeaderLen = 8
	// maxVNI is the 24-bit VNI ceiling.
	maxVNI = 0xffffff
	// udpPort is the IANA-assigned VXLAN UDP destination port.
	udpPort = 4789
)

// wireFaultKinds are the negative-case fault injections（validator 消费——
// 注入即拒绝，不是线上字段）。kind ↔ 设计 §10 锚词。
const (
	faultNone            = ""
	faultHeaderTruncated = "header_truncated"  // → header
	faultReservedFlags   = "reserved_flags"    // → flag/reserved
	faultVNIOverflow     = "vni_overflow"      // → vni
	faultWrongUDPPort    = "wrong_udp_port"    // → port
	faultInnerTruncated  = "inner_truncated"   // → inner
	faultChecksum        = "checksum"          // → checksum
)

// VXLANGenerator emits one message event per configured datagram（顶层
// VNI/IFlag/Inner 折叠为单事件；Datagrams 非空逐项一事件）。
type VXLANGenerator struct{}

func (g *VXLANGenerator) Name() string { return "vxlan" }

// GenEvents marks this generator as a message event producer.
func (g *VXLANGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *VXLANGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("vxlan generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate produces the VXLAN datagram event stream. Bytes = 8-byte VXLAN
// header + inner Ethernet frame（udp 层把事件包成 UDP 数据报）。
func (g *VXLANGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("vxlan generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.VXLAN
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	for i, d := range foldDatagrams(cfg) {
		inner, err := core.BuildEncapEthernetFrame(d.inner)
		if err != nil {
			return fmt.Errorf("vxlan: datagram[%d] %v", i, err)
		}
		ev := layers.MessageEvent{
			Up:     d.up,
			Bytes:  append(buildVXLANHeader(d.vni, d.iFlag), inner...),
			SrcPort: d.srcPort,
		}
		if d.srcPort != 0 && !d.up {
			// down 方向显式端口用绝对语义（udp 层 L4PortOverride 跳过
			// up/down 端口交换）：SrcPort=4789 侧、DstPort=客户端端口。
			ev.SrcPort = udpPort
			ev.DstPort = d.srcPort
			ev.L4PortOverride = true
		}
		if d.zeroChecksum {
			ev.Metadata = map[string]interface{}{"udp_disable_checksum": true}
		}
		if err := g.emitMsg(ctx, req.EmitMsg, ev); err != nil {
			return err
		}
	}
	return nil
}

// emitMsg sends one event, honoring context cancellation（socks5 同款
// escape hatch——传输层停止消费时生成器不能挂死）。
func (g *VXLANGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// datagram is the folded per-event unit.
type datagram struct {
	vni          uint32
	iFlag        bool
	srcPort      uint16
	up           bool
	inner        *core.EncapEthernetFixture
	zeroChecksum bool
}

// foldDatagrams maps the config onto the event list: empty Datagrams → a
// single event from the top-level VNI/IFlag/Inner（空配置默认流：VNI=0、
// I 置位、内建最小 fixture，P0b 同款）；否则逐项（entry Inner nil → 顶层
// Inner 回退）。
func foldDatagrams(cfg *core.VXLANConfig) []datagram {
	if cfg == nil {
		return []datagram{{vni: 0, iFlag: true, up: true, inner: defaultFixture()}}
	}
	iflag := cfg.IFlag == nil || *cfg.IFlag
	if len(cfg.Datagrams) == 0 {
		return []datagram{{
			vni: cfg.VNI, iFlag: iflag, up: true, inner: effectiveInner(cfg.Inner),
		}}
	}
	out := make([]datagram, 0, len(cfg.Datagrams))
	for i := range cfg.Datagrams {
		e := &cfg.Datagrams[i]
		entryIFlag := iflag
		if e.IFlag != nil {
			entryIFlag = *e.IFlag
		}
		out = append(out, datagram{
			vni:          e.VNI,
			iFlag:        entryIFlag,
			srcPort:      e.SrcPort,
			up:           e.Up == nil || *e.Up,
			inner:        effectiveInner(e.Inner, cfg.Inner),
			zeroChecksum: e.UDPSumZero,
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
		SrcMAC:    "02:00:00:00:10:01",
		DstMAC:    "02:00:00:00:10:02",
		EtherType: "ipv4",
		SrcIP:     "10.10.0.1",
		DstIP:     "10.10.0.2",
		Payload:   []byte("vxlan-default-inner"),
	}
}

// buildVXLANHeader encodes the fixed 8-byte header: flags byte
// (I=bit3→0x08, 其余保留零) + Reserved(3) + VNI(3, BE) + Reserved(1)。
func buildVXLANHeader(vni uint32, iFlag bool) []byte {
	hdr := make([]byte, vxlanHeaderLen)
	if iFlag {
		hdr[0] = flagI
	}
	binary.BigEndian.PutUint16(hdr[4:6], uint16(vni>>8))
	hdr[6] = byte(vni)
	return hdr
}

// ValidateConfig rejects configs that must never reach the wire（design §10）:
// VNI beyond 24 bits, I flag cleared（正例全要求置位——未置位进 reserved_flags
// 负例）, unknown wire faults, and inner fixture faults. Explicit boundaries
// (VNI=0, empty payload, VID=0/4095) are legal and must NOT be rejected.
func ValidateConfig(cfg *core.VXLANConfig) error {
	if cfg == nil {
		return nil
	}
	if err := validateVNI(cfg.VNI); err != nil {
		return err
	}
	if cfg.IFlag != nil && !*cfg.IFlag {
		return fmt.Errorf("vxlan: i_flag=false leaves the I bit clear — the VNI is then not a valid VXLAN network identifier and reserved flags are nonzero (RFC 7348 §4)")
	}
	if err := core.ValidateEncapFixture(cfg.Inner, "vxlan"); err != nil {
		return err
	}
	for i := range cfg.Datagrams {
		e := &cfg.Datagrams[i]
		if err := validateVNI(e.VNI); err != nil {
			return fmt.Errorf("vxlan: datagrams[%d] %v", i, err)
		}
		if e.IFlag != nil && !*e.IFlag {
			return fmt.Errorf("vxlan: datagrams[%d].i_flag=false leaves the I bit clear — reserved flags are nonzero (RFC 7348 §4)", i)
		}
		if err := core.ValidateEncapFixture(e.Inner, "vxlan"); err != nil {
			return fmt.Errorf("vxlan: datagrams[%d] %v", i, err)
		}
	}
	return validateWireFault(cfg.WireFault)
}

// validateVNI rejects VNI values beyond the 24-bit field.
func validateVNI(vni uint32) error {
	if vni > maxVNI {
		return fmt.Errorf("vxlan: vni %d exceeds 24-bit range 0..%d (RFC 7348 §4)", vni, maxVNI)
	}
	return nil
}

// validateWireFault rejects every injected fault with its design §10 anchor
// word, and any unknown kind.
func validateWireFault(f *core.EncapWireFault) error {
	if f == nil {
		return nil
	}
	switch f.Kind {
	case faultNone:
		return nil
	case faultHeaderTruncated:
		return fmt.Errorf("vxlan: wire_fault header_truncated — the VXLAN header is a fixed 8-byte length header; fewer bytes cannot be encoded (RFC 7348 §4)")
	case faultReservedFlags:
		return fmt.Errorf("vxlan: wire_fault reserved_flags — flags/reserved bytes beyond the I bit must be zero; nonzero reserved flags are invalid (RFC 7348 §4)")
	case faultVNIOverflow:
		return fmt.Errorf("vxlan: wire_fault vni_overflow — the VNI is a 24-bit field; values beyond 0xffffff or a polluted 4th byte are rejected")
	case faultWrongUDPPort:
		return fmt.Errorf("vxlan: wire_fault wrong_udp_port — VXLAN rides UDP destination port 4789 only; other transports/ports are rejected")
	case faultInnerTruncated:
		return fmt.Errorf("vxlan: wire_fault inner_truncated — the inner Ethernet frame must not truncate inside MAC/VLAN/EtherType/IP headers (length conflict)")
	case faultChecksum:
		return fmt.Errorf("vxlan: wire_fault checksum — IPv6 UDP checksum zero or a mismatching checksum is rejected (RFC 768/8200)")
	default:
		return fmt.Errorf("vxlan: unknown wire_fault kind %q", f.Kind)
	}
}

func init() {
	layers.RegisterLayerGenerator("vxlan", func() (layers.LayerGenerator, error) {
		return &VXLANGenerator{}, nil
	})
	layers.RegisterLayerValidator("vxlan", func(spec *core.FlowSpec) error {
		// VXLAN 只走 UDP/4789：显式写非 4789 目的端口即负例（udp_carrier
		// 锚词 "port"）；0 = 未写，由 FieldContract 补 4789。
		if spec.VXLAN != nil && spec.DstPort != 0 && spec.DstPort != udpPort {
			return fmt.Errorf("vxlan: wire_fault wrong_udp_port — destination port %d is not the IANA VXLAN UDP port %d; other transports/ports are rejected", spec.DstPort, udpPort)
		}
		return ValidateConfig(spec.VXLAN)
	})
}
