package sv

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"time"
)

const DefaultDstMAC = "01:0c:cd:04:00:01"

type Planner struct{}

func NewPlanner() *Planner                      { return &Planner{} }
func (*Planner) Name() string                   { return "sv" }
func (*Planner) Validate(s core.FlowSpec) error { return validate(s) }
func validate(s core.FlowSpec) error {
	if s.SV == nil {
		return fmt.Errorf("sv config is required")
	}
	c := s.SV
	if c.APPID < 0x4000 || c.APPID > 0x7fff {
		return fmt.Errorf("sv appid 0x%04x outside SV range 0x4000-0x7fff", c.APPID)
	}
	if c.SVID == "" || len(c.SVID) > 255 {
		return fmt.Errorf("sv svID is required and must be <=255 bytes")
	}
	if c.ConfRev == 0 {
		return fmt.Errorf("sv confRev must be non-zero")
	}
	if c.SamplesPerCycle == 0 {
		return fmt.Errorf("sv samples_per_cycle must be >= 1")
	}
	if c.SMPSynch > 2 {
		return fmt.Errorf("sv smpSynch must be 0, 1 or 2")
	}
	if len(c.Data) == 0 {
		return fmt.Errorf("sv data is required")
	}
	for _, d := range c.Data {
		if d.Type != "int32" && d.Type != "float32" {
			return fmt.Errorf("sv data type %q unsupported; only int32 and float32 are supported", d.Type)
		}
	}
	if s.SrcIP != "" || s.DstIP != "" || s.SrcPort != 0 || s.DstPort != 0 {
		return fmt.Errorf("sv is Layer 2 only and must not use IP or transport fields")
	}
	return nil
}
func (*Planner) Plan(ctx context.Context, s core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := validate(s); err != nil {
		return nil, err
	}
	c := *s.SV
	n := c.Count
	if n <= 0 {
		n = s.Count
	}
	if n <= 0 {
		n = 1
	}
	out := make(chan core.PacketConfig, n)
	go func() {
		defer close(out)
		step := 1
		if c.DoubleSend {
			step = 2
		}
		for i := 0; i < n; i++ {
			p, err := packet(s, c, uint16((i/step)%int(c.SamplesPerCycle)))
			if err != nil {
				return
			}
			select {
			case out <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
func packet(s core.FlowSpec, c core.SVConfig, cnt uint16) (core.PacketConfig, error) {
	b, e := BuildPayload(&c, cnt)
	if e != nil {
		return core.PacketConfig{}, e
	}
	dst := c.DstMAC
	if dst == "" {
		dst = DefaultDstMAC
	}
	v := (*core.VLAN)(nil)
	if c.VLANEnabled {
		v = &core.VLAN{ID: c.VLANID, Priority: c.VLANPriority}
	}
	return core.PacketConfig{Direction: "up", Timestamp: time.Now(), L2: core.L2Config{SrcMAC: s.SrcMAC, DstMAC: dst, EtherType: core.EtherTypeSV, VLAN: v}, L4: core.L4Config{Protocol: "sv"}, Payload: b}, nil
}
func bl(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	return []byte{0x81, byte(n)}
}
func tlv(tag byte, v []byte) []byte { return append(append([]byte{tag}, bl(len(v))...), v...) }
func BuildPayload(c *core.SVConfig, cnt uint16) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("sv config is required")
	}
	asduFields := []byte{}
	asduFields = append(asduFields, tlv(0x80, []byte(c.SVID))...)
	if c.DatSet != "" {
		asduFields = append(asduFields, tlv(0x81, []byte(c.DatSet))...)
	}
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], cnt)
	asduFields = append(asduFields, tlv(0x82, x[:])...)
	var r [4]byte
	binary.BigEndian.PutUint32(r[:], c.ConfRev)
	asduFields = append(asduFields, tlv(0x83, r[:])...)
	asduFields = append(asduFields, tlv(0x85, []byte{c.SMPSynch})...)
	if c.SMPRate > 0 {
		binary.BigEndian.PutUint16(x[:], c.SMPRate)
		asduFields = append(asduFields, tlv(0x86, x[:])...)
	}
	// seqData: 每通道值 4 字节 + 可选 quality 4 字节。带 quality 的通道为
	// 8 字节（标准 9-2LE，4i4v）；无 quality 的通道为 4 字节（非 9-2LE
	// 自定义数据集，sv_custom_dataset）。float32 通道值按 IEEE 754 单精度
	// 字节（tests/sv.json 1.5=0x3fc00000）。
	data := make([]byte, 0, len(c.Data)*8)
	for _, d := range c.Data {
		var v [4]byte
		if d.Type == "float32" {
			binary.BigEndian.PutUint32(v[:], math.Float32bits(d.InstMagF))
		} else {
			binary.BigEndian.PutUint32(v[:], uint32(d.InstMag))
		}
		data = append(data, v[:]...)
		if d.HasQuality {
			var q [4]byte
			binary.BigEndian.PutUint32(q[:], d.Quality)
			data = append(data, q[:]...)
		}
	}
	asduFields = append(asduFields, tlv(0x87, data)...)
	asdu := tlv(0x30, asduFields)
	seqASDU := tlv(0xa2, asdu)
	apdu := tlv(0x60, append(tlv(0x80, []byte{1}), seqASDU...))
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[:2], c.APPID)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+len(apdu)))
	return append(p, apdu...), nil
}

type Generator struct{}

func (*Generator) Name() string                     { return "sv" }
func (*Generator) GenEvents() layers.EventGenerator { return nil }
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.SV == nil {
		return fmt.Errorf("sv generator: invalid request")
	}
	c := req.Meta.SV
	n := c.Count
	if n <= 0 {
		n = 1
	}
	// double_send: 每样本连发 2 帧（同一 smpCnt），frame count = c.Count。
	// 样本索引按步进分组：no-double 每帧即一样本；double 两帧共享一
	// 样本（smpCnt 0,0,1,1,...）。总帧数恒为 n。
	step := 1
	if c.DoubleSend {
		step = 2
	}
	for i := 0; i < n; i++ {
		sampleIdx := uint16((i / step) % int(c.SamplesPerCycle))
		p, e := packet(core.FlowSpec{SrcMAC: req.Meta.SrcMAC}, *c, sampleIdx)
		if e != nil {
			return e
		}
		if e = req.Emit(p); e != nil {
			return e
		}
	}
	return nil
}
func init() {
	layers.RegisterLayerGenerator("sv", func() (layers.LayerGenerator, error) { return &Generator{}, nil })
	layers.RegisterLayerValidator("sv", func(s *core.FlowSpec) error { return validate(*s) })
}
