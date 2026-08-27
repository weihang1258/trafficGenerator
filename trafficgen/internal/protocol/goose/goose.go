package goose

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

const DefaultDstMAC = "01:0c:cd:01:02:03"

type Planner struct{}

func NewPlanner() *Planner    { return &Planner{} }
func (*Planner) Name() string { return "goose" }

func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.GOOSE == nil {
		return fmt.Errorf("goose config is required")
	}
	c := spec.GOOSE
	if c.APPID > 0x3fff {
		return fmt.Errorf("goose appid 0x%04x outside GOOSE range 0x0000-0x3fff", c.APPID)
	}
	if c.GOCBRef == "" || c.DatSet == "" {
		return fmt.Errorf("goose gocb_ref and dat_set are required")
	}
	if len(c.GOCBRef) > 255 || len(c.DatSet) > 255 || len(c.GOID) > 255 {
		return fmt.Errorf("goose control-block strings exceed 255 bytes")
	}
	if c.TALMs == 0 || c.TALMs > 0xffffffff {
		return fmt.Errorf("goose tal_ms must be in 1..4294967295")
	}
	if c.ConfRev == 0 {
		return fmt.Errorf("goose conf_rev must be non-zero")
	}
	if c.StartSTNum == ^uint32(0) || c.StartSQNum == ^uint32(0) {
		return fmt.Errorf("goose state counters must not overflow")
	}
	if len(c.Data) == 0 {
		return fmt.Errorf("goose exactly one boolean allData member is required")
	}
	if len(c.Data) != 1 || c.Data[0].Type != "boolean" {
		return fmt.Errorf("goose supports exactly one boolean allData member")
	}
	if _, ok := c.Data[0].Value.(bool); !ok && c.Data[0].Value != nil {
		return fmt.Errorf("goose boolean member value must be boolean")
	}
	if spec.SrcIP != "" || spec.DstIP != "" || spec.SrcPort != 0 || spec.DstPort != 0 {
		return fmt.Errorf("goose is Layer 2 only and must not use IP or transport fields")
	}
	if spec.VLAN != nil && (spec.VLAN.ID > 4095 || spec.VLAN.Priority > 7) {
		return fmt.Errorf("goose VLAN is out of range")
	}
	if c.VLANEnabled && (c.VLANID > 4095 || c.VLANPriority > 7) {
		return fmt.Errorf("goose VLAN is out of range")
	}
	return nil
}

func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	c := *spec.GOOSE
	count := c.Count
	if count == 0 {
		count = spec.Count
	}
	if count <= 0 {
		count = 1
	}
	out := make(chan core.PacketConfig, count)
	go func() {
		defer close(out)
		st, sq := c.StartSTNum, c.StartSQNum
		if st == 0 {
			st = 1
		}
		dst := c.DstMAC
		if dst == "" {
			dst = DefaultDstMAC
		}
		vlan := spec.VLAN
		if c.VLANEnabled {
			vlan = &core.VLAN{ID: c.VLANID, Priority: c.VLANPriority}
		}
		for i := 0; i < count; i++ {
			payload, err := BuildPayload(&c, st, sq)
			if err != nil {
				return
			}
			pkt := core.PacketConfig{FlowID: fmt.Sprintf("goose-%s-%s", spec.SrcMAC, dst), PacketIndex: uint64(i), Direction: "up", Timestamp: time.Now(), L2: core.L2Config{SrcMAC: spec.SrcMAC, DstMAC: dst, EtherType: core.EtherTypeGOOSE, VLAN: vlan}, L4: core.L4Config{Protocol: "goose"}, Payload: payload}
			select {
			case out <- pkt:
			case <-ctx.Done():
				return
			}
			sq++
		}
	}()
	return out, nil
}

func berLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n <= 255 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}
func tlv(tag byte, v []byte) []byte {
	b := []byte{tag}
	b = append(b, berLen(len(v))...)
	return append(b, v...)
}
func uintVal(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	i := 0
	for i < 3 && b[i] == 0 {
		i++
	}
	return append([]byte(nil), b[i:]...)
}
func boolVal(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
func strVal(v string) []byte { return []byte(v) }

func BuildPayload(c *core.GOOSEConfig, st, sq uint32) ([]byte, error) {
	data := c.Boolean
	if len(c.Data) != 1 || c.Data[0].Type != "boolean" {
		return nil, fmt.Errorf("goose supports exactly one boolean member")
	}
	if v, ok := c.Data[0].Value.(bool); ok {
		data = v
	}
	now := time.Now()
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.UnixNano()/1000000)<<16)
	apduContent := []byte{}
	apduContent = append(apduContent, tlv(0x80, strVal(c.GOCBRef))...)
	apduContent = append(apduContent, tlv(0x81, uintVal(c.TALMs))...)
	apduContent = append(apduContent, tlv(0x82, strVal(c.DatSet))...)
	apduContent = append(apduContent, tlv(0x83, strVal(c.GOID))...)
	apduContent = append(apduContent, tlv(0x84, ts)...)
	apduContent = append(apduContent, tlv(0x85, boolVal(c.Test))...)
	apduContent = append(apduContent, tlv(0x86, uintVal(st))...)
	apduContent = append(apduContent, tlv(0x87, boolVal(c.NDSCom))...)
	apduContent = append(apduContent, tlv(0x88, uintVal(c.ConfRev))...)
	apduContent = append(apduContent, tlv(0x89, uintVal(sq))...)
	apduContent = append(apduContent, tlv(0x8a, []byte{1})...)
	apduContent = append(apduContent, tlv(0xab, tlv(0x83, boolVal(data)))...)
	apdu := tlv(0x61, apduContent)
	if len(apdu)+8 > 0xffff {
		return nil, fmt.Errorf("goose payload too large")
	}
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], c.APPID)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(apdu)+8))
	return append(hdr, apdu...), nil
}

type Generator struct{}

func (*Generator) Name() string                     { return "goose" }
func (*Generator) GenEvents() layers.EventGenerator { return nil }
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.GOOSE == nil {
		return fmt.Errorf("goose generator: invalid request")
	}
	c := req.Meta.GOOSE
	count := c.Count
	if count <= 0 {
		count = 1
	}
	st := c.StartSTNum
	if st == 0 {
		st = 1
	}
	sq := c.StartSQNum
	dst := c.DstMAC
	if dst == "" {
		dst = DefaultDstMAC
	}
	src := req.Meta.SrcMAC
	for i := 0; i < count; i++ {
		b, err := BuildPayload(c, st, sq)
		if err != nil {
			return err
		}
		v := (*core.VLAN)(nil)
		if c.VLANEnabled {
			v = &core.VLAN{ID: c.VLANID, Priority: c.VLANPriority}
		}
		p := core.PacketConfig{Direction: "up", L2: core.L2Config{SrcMAC: src, DstMAC: dst, EtherType: core.EtherTypeGOOSE, VLAN: v}, L4: core.L4Config{Protocol: "goose"}, Payload: b}
		if err := req.Emit(p); err != nil {
			return err
		}
		sq++
	}
	return nil
}
func init() {
	layers.RegisterLayerGenerator("goose", func() (layers.LayerGenerator, error) { return &Generator{}, nil })
	layers.RegisterLayerValidator("goose", func(s *core.FlowSpec) error { return (&Planner{}).Validate(*s) })
}
