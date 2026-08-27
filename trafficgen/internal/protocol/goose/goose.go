package goose

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
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
	if c.StartSTNum == ^uint32(0) {
		return fmt.Errorf("goose stNum must not overflow (got 0x%08x)", c.StartSTNum)
	}
	if c.StartSQNum == ^uint32(0) {
		return fmt.Errorf("goose sqNum must not overflow (got 0x%08x)", c.StartSQNum)
	}
	if len(c.Data) == 0 {
		return fmt.Errorf("goose at least one allData member is required")
	}
	for _, m := range c.Data {
		if !isValidDataMember(m) {
			return fmt.Errorf("goose unsupported data type %q", m.Type)
		}
	}
	// event_seq 的 sqNum 步进必须为 1（GOOSE 单调 +1 重传契约）；>1 表示
	// 非连续跳号，负例 neg_sqnum 用它校验"该拒未拒"缺口。
	for _, ev := range c.EventSeq {
		if ev.SqNumStep > 1 {
			return fmt.Errorf("goose sqNum step %d violates monotonic +1 (got; retransmit burst must be contiguous)", ev.SqNumStep)
		}
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
		if sq == 0 {
			sq = 1
		}
		emit := func(pkt core.PacketConfig) error {
			pkt.FlowID = fmt.Sprintf("goose-%s-%s", spec.SrcMAC, c.DstMAC)
			pkt.Timestamp = time.Now()
			if pkt.FlowID == "goose--" {
				pkt.FlowID = fmt.Sprintf("goose-%s-%s", spec.SrcMAC, DefaultDstMAC)
			}
			select {
			case out <- pkt:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		// PackageIndex 递增由 emitGooseFrames 按发送序补（用局部计数）。
		_ = emitGooseFrames(ctx, emit, &c, count, st, sq, spec.SrcMAC)
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

// intVal encodes a signed integer with minimal big-endian bytes (含符号位,
// design §3.6 最小编码). Zero → single 0x00 byte.
func intVal(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	i := 0
	for i < 7 {
		// keep the sign-bearing byte: skip leading 0x00 (followed by <0x80)
		// and leading 0xff (followed by >=0x80).
		if b[i] == 0x00 && b[i+1] < 0x80 {
			i++
		} else if b[i] == 0xff && b[i+1] >= 0x80 {
			i++
		} else {
			break
		}
	}
	return append([]byte(nil), b[i:]...)
}

// uint64Val encodes an unsigned integer with minimal big-endian bytes.
func uint64Val(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 7 && b[i] == 0 {
		i++
	}
	return append([]byte(nil), b[i:]...)
}

// bitStringVal encodes a bit string from a hex string (e.g. "fe"). First byte
// is the number of unused bits in the final byte (0 when byte-aligned).
func bitStringVal(v interface{}) []byte {
	s := toString(v)
	var raw []byte
	nibble := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		var val byte
		switch {
		case c >= '0' && c <= '9':
			val = c - '0'
		case c >= 'a' && c <= 'f':
			val = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			val = c - 'A' + 10
		default:
			continue
		}
		if i%2 == 0 {
			nibble = val << 4
		} else {
			raw = append(raw, nibble|val)
		}
	}
	if len(s)%2 == 1 {
		raw = append(raw, nibble)
	}
	// byte-aligned -> 0 unused bits.
	return append([]byte{0}, raw...)
}

// encodeFloat32 encodes an IEC 61850 FLOAT32 (format-width 32, exponent-width 8)
// per design §3.7: length 5, 1 exponent sign + 1 mantissa sign + 6 exponent +
// 4 mantissa bytes. Uses IEEE 754 single-precision bits.
func encodeFloat32(v float32) []byte {
	bits := math.Float32bits(v)
	return []byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)}
}

// binaryTimeVal returns a 6-byte binary time (design §3.6 0x8C).
func binaryTimeVal() []byte {
	return make([]byte, 6)
}

// utcTimeVal returns an 8-byte CP time (design §3.6 0x91).
func utcTimeVal() []byte {
	t := time.Now()
	ms := t.UnixMilli()
	return utcTimeBytes(ms)
}

func utcTimeBytes(ms int64) []byte {
	// 8 bytes: 4-byte seconds + 2-byte milliseconds + reserved(2). CP time is
	// not day-of-year based; here we use a compact epoch encoding.
	b := make([]byte, 8)
	if ms >= 0 {
		sec := ms / 1000
		milli := ms % 1000
		b[0] = byte(sec >> 24)
		b[1] = byte(sec >> 16)
		b[2] = byte(sec >> 8)
		b[3] = byte(sec)
		b[4] = byte(milli >> 8)
		b[5] = byte(milli)
	}
	return b
}

func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case float64:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

func toUint64(v interface{}) (uint64, error) {
	switch n := v.(type) {
	case int:
		return uint64(n), nil
	case int32:
		return uint64(n), nil
	case int64:
		return uint64(n), nil
	case uint32:
		return uint64(n), nil
	case uint64:
		return n, nil
	case float64:
		return uint64(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, err
		}
		return uint64(i), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to uint64", v)
	}
}

func toFloat32(v interface{}) (float32, bool) {
	switch n := v.(type) {
	case float32:
		return n, true
	case float64:
		return float32(n), true
	case int:
		return float32(n), true
	case int32:
		return float32(n), true
	case int64:
		return float32(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return float32(f), true
	default:
		return 0, false
	}
}

func toString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", s)
	}
}

// isValidDataMember reports whether the member type is supported (design §3.8).
func isValidDataMember(m core.GOOSEData) bool {
	switch m.Type {
	case "boolean", "bit_string", "int32", "int64", "uint32", "uint64",
		"float32", "octet_string", "visible_string", "binary_time", "utc_time":
		return true
	default:
		return false
	}
}

func BuildPayload(c *core.GOOSEConfig, st, sq uint32) ([]byte, error) {
	if len(c.Data) == 0 {
		return nil, fmt.Errorf("goose at least one data member is required")
	}
	// goID (0x83) 是可选字段（Wireshark dissector BER_FLAGS_OPTIONAL），但
	// IEC 61850 工具惯例将其缺省为与 gocbRef 相同——用例也按 goID=gocbRef
	// 校验 APDU 偏移。空时回填 gocbRef，保证帧长与字节对齐稳定。
	goID := c.GOID
	if goID == "" {
		goID = c.GOCBRef
	}
	now := time.Now()
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.UnixNano()/1000000)<<16)
	apduContent := []byte{}
	apduContent = append(apduContent, tlv(0x80, strVal(c.GOCBRef))...)
	apduContent = append(apduContent, tlv(0x81, uintVal(c.TALMs))...)
	apduContent = append(apduContent, tlv(0x82, strVal(c.DatSet))...)
	apduContent = append(apduContent, tlv(0x83, strVal(goID))...)
	apduContent = append(apduContent, tlv(0x84, ts)...)
	apduContent = append(apduContent, tlv(0x85, uintVal(st))...)
	apduContent = append(apduContent, tlv(0x86, uintVal(sq))...)
	apduContent = append(apduContent, tlv(0x87, boolVal(c.Test))...)
	apduContent = append(apduContent, tlv(0x88, uintVal(c.ConfRev))...)
	apduContent = append(apduContent, tlv(0x89, boolVal(c.NDSCom))...)
	apduContent = append(apduContent, tlv(0x8a, uintVal(uint32(len(c.Data))))...)

	// Encode allData members per MMS Data BER table (design §3.6).
	var allData []byte
	for _, m := range c.Data {
		mb, err := encodeDataMember(m)
		if err != nil {
			return nil, err
		}
		allData = append(allData, mb...)
	}
	apduContent = append(apduContent, tlv(0xab, allData)...)
	apdu := tlv(0x61, apduContent)
	if len(apdu)+8 > 0xffff {
		return nil, fmt.Errorf("goose payload too large")
	}
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], c.APPID)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(apdu)+8))
	return append(hdr, apdu...), nil
}

// encodeDataMember encodes one GOOSE allData member using MMS Data BER tags
// (design §3.6/3.7): boolean=0x83, bit_string=0x84, int32/int64=0x85,
// uint32/uint64=0x86, float32=0x87, octet_string=0x89, visible_string=0x8A,
// binary_time=0x8C, utc_time=0x91.
func encodeDataMember(m core.GOOSEData) ([]byte, error) {
	switch m.Type {
	case "boolean":
		v, ok := m.Value.(bool)
		if !ok {
			return nil, fmt.Errorf("goose boolean member %q value must be boolean", m.Name)
		}
		return tlv(0x83, boolVal(v)), nil
	case "bit_string":
		return tlv(0x84, bitStringVal(m.Value)), nil
	case "int32", "int64":
		v, err := toInt64(m.Value)
		if err != nil {
			return nil, err
		}
		return tlv(0x85, intVal(v)), nil
	case "uint32", "uint64":
		v, err := toUint64(m.Value)
		if err != nil {
			return nil, err
		}
		return tlv(0x86, uint64Val(v)), nil
	case "float32":
		v, ok := toFloat32(m.Value)
		if !ok {
			return nil, fmt.Errorf("goose float member %q value must be numeric", m.Name)
		}
		return tlv(0x87, encodeFloat32(v)), nil
	case "octet_string":
		return tlv(0x89, strVal(toString(m.Value))), nil
	case "visible_string":
		return tlv(0x8a, strVal(toString(m.Value))), nil
	case "binary_time":
		return tlv(0x8c, binaryTimeVal()), nil
	case "utc_time":
		return tlv(0x91, utcTimeVal()), nil
	default:
		return nil, fmt.Errorf("goose unsupported data type %q", m.Type)
	}
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
	if sq == 0 {
		sq = 1
	}
	dst := c.DstMAC
	if dst == "" {
		dst = DefaultDstMAC
	}
	src := req.Meta.SrcMAC
	return emitGooseFrames(ctx, req.Emit, c, count, st, sq, src)
}

// emitGooseFrames drives the GOOSE frame sequence per the event_seq model
// (P3 T4.2): one initial heartbeat, then for each event_seq entry a state-
// change burst (stNum bumps, sqNum resets to 0, then `retransmits` fast-
// retransmit frames sqNum=1..retransmits), then remaining heartbeats continue
// sqNum. Matches cases goose_retransmit/goose_dataset_change.
func emitGooseFrames(ctx context.Context, emit func(core.PacketConfig) error, c *core.GOOSEConfig, count int, st, sq uint32, src string) error {
	v := (*core.VLAN)(nil)
	if c.VLANEnabled {
		v = &core.VLAN{ID: c.VLANID, Priority: c.VLANPriority}
	}
	dst := c.DstMAC
	if dst == "" {
		dst = DefaultDstMAC
	}
	send := func(st, sq uint32) error {
		b, err := BuildPayload(c, st, sq)
		if err != nil {
			return err
		}
		p := core.PacketConfig{Direction: "up", L2: core.L2Config{SrcMAC: src, DstMAC: dst, EtherType: core.EtherTypeGOOSE, VLAN: v}, L4: core.L4Config{Protocol: "goose"}, Payload: b}
		return emit(p)
	}
	emitted := 0
	// 首帧心跳（若有 event_seq，事件前的固定 1 帧心跳；无则全心跳）。
	preEvent := 1
	if len(c.EventSeq) == 0 {
		preEvent = 0
	}
	for emitted < count && emitted < preEvent {
		if err := send(st, sq); err != nil {
			return err
		}
		emitted++
		sq++
	}
	// 事件爆发：每个 event_seq 触发 stNum++、sqNum 复位 0，播 retransmits+1
	// 帧（sqNum 0..retransmits）。
	for _, ev := range c.EventSeq {
		if emitted >= count {
			break
		}
		st++
		sq = 0
		frames := ev.Retransmits + 1
		for j := 0; j < frames && emitted < count; j++ {
			if err := send(st, sq); err != nil {
				return err
			}
			emitted++
			sq++
		}
	}
	// 剩余帧为心跳，sqNum 继续自增。
	for emitted < count {
		if err := send(st, sq); err != nil {
			return err
		}
		emitted++
		sq++
	}
	return nil
}
func init() {
	layers.RegisterLayerGenerator("goose", func() (layers.LayerGenerator, error) { return &Generator{}, nil })
	layers.RegisterLayerValidator("goose", func(s *core.FlowSpec) error { return (&Planner{}).Validate(*s) })
}
