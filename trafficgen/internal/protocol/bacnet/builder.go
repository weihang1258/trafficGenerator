// Package bacnet — BACnet/IP（Annex J）终结层。
//
// Register* functions run at init() time (in builder.go), wiring the
// bacnet layer into the chain planner and generator factory. The
// side-effect import _ "…/protocol/bacnet" activates this registration.
//
// BACNET = [ip → udp → bacnet]（udp-only 族；DependsOn ["udp"]；
// FieldContract udp.dst_port=47808）。UDP 无连接：每事件一数据报，
// 无握手/挥手；自动应答（I-Am/ACK/BVLC-Result/Router-Ack/SegmentACK）
// 按事件 respond 配置展开（设计 §5 规则①-⑦）。全协议大端。
//
// 无符号宽度策略（用例 §4 实测钉死字节反推）：u16 域字段（max-APDU、
// 厂商 ID、RFD TTL、lifetime、time-remaining、time-duration、DNET/SNET/
// 端口）恒 2B 大端；其余无符号/枚举（低/高限、进程 ID、优先级、下标、
// 属性、错误类/码、分段能力）最短式 ≥1B（0 → 1B 00）。"最短式"指
// ≤4B 直存 LVT、不用扩展长度（设计 §3.4 v2.0.1 策略），非最小字节数。
package bacnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- fixtures（契约 §3 常量预算 + 用例 §4 逐例同源）----

const (
	FixtureDeviceInstance = 100  // 正例 1 I-Am 设备实例
	FixtureMaxAPDU        = 1476 // 正例 1 max-APDU（码 5）
	FixtureSegmentation   = 3    // 正例 1 分段能力 3=none
	FixtureVendorID       = 15   // 正例 1 厂商 ID
	FixtureProperty       = 85   // present-value
)

// Segmented-Request 协商档（正例 29：max-segs 码 2 / max-APDU 码 3=480B /
// 提议窗口 2）。segmented_ack 缺省窗口 4（正例 30）。
const (
	segmentedMaxByte = 0x23
	segmentedMaxAPDU = 480
	segmentedWindow  = 2
	ackWindow        = 4
)

// unconfirmedMaxByte is the Confirmed-REQ max-segs/max-APDU byte for plain
// requests（正例 16：max-segs 0 未指定 / max-APDU 码 5=1476）。
const unconfirmedMaxByte = 0x05

// ---- 标签编码（§3.4）----

// putTag appends one tag byte: tag number (0-14, or 15+ext byte), class
// bit3 (0=application, 1=context), LVT bits2-0.
func putTag(b []byte, tag int, context bool, lvt int) []byte {
	num, l := tag, lvt
	if tag > 14 {
		l = 15
	}
	b = append(b, byte(num<<4)|boolByte(context)|byte(l))
	if tag > 14 {
		b = append(b, byte(tag))
	}
	return b
}

func boolByte(v bool) byte {
	if v {
		return 0x08
	}
	return 0
}

// putLength extends an LVT=5 tag with the extended-length marker（三档：
// ≤4 直存由 lvtFor 处理；5-253 → 1B；≤65535 → 254+2B BE）.
func putLength(b []byte, n int) []byte {
	switch {
	case n <= 253:
		return append(b, byte(n))
	case n <= 65535:
		return append(b, 254, byte(n>>8), byte(n))
	default:
		return append(b, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func lvtFor(n int) int {
	if n <= 4 {
		return n
	}
	return 5
}

// putU16 appends a fixed-width 2-byte big-endian value（u16 域字段）.
func putU16(b []byte, v int) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

// putUnsigned appends a shortest-form unsigned (≥1B；0 → 1B 00).
func putUnsigned(b []byte, v uint64) []byte {
	if v == 0 {
		return append(b, 0)
	}
	var tmp [8]byte
	n := 0
	for v > 0 {
		tmp[7-n] = byte(v)
		v >>= 8
		n++
	}
	return append(b, tmp[8-n:]...)
}

func unsignedBytes(v uint64) []byte { return putUnsigned(nil, v) }

// ---- 应用标签值（13 标签，§3.4/§3.5）----

func appTag(b []byte, v *core.BACNETValue) ([]byte, error) {
	switch v.Type {
	case "null":
		return putTag(b, 0, false, 0), nil
	case "boolean":
		lvt := 0
		if b2, _ := v.Value.(bool); b2 {
			lvt = 1
		}
		return putTag(b, 1, false, lvt), nil
	case "unsigned":
		u, err := uintOf(v.Value)
		if err != nil {
			return nil, err
		}
		c := unsignedBytes(u)
		b = putTag(b, 2, false, lvtFor(len(c)))
		return append(b, c...), nil
	case "enumerated":
		u, err := uintOf(v.Value)
		if err != nil {
			return nil, err
		}
		c := unsignedBytes(u)
		b = putTag(b, 9, false, lvtFor(len(c)))
		return append(b, c...), nil
	case "int":
		i, err := intOf(v.Value)
		if err != nil {
			return nil, err
		}
		c := signedBytes(i)
		b = putTag(b, 3, false, lvtFor(len(c)))
		return append(b, c...), nil
	case "real":
		f, err := floatOf(v.Value)
		if err != nil {
			return nil, err
		}
		b = putTag(b, 4, false, 4)
		return binary.BigEndian.AppendUint32(b, math.Float32bits(float32(f))), nil
	case "double":
		f, err := floatOf(v.Value)
		if err != nil {
			return nil, err
		}
		b = putTag(b, 5, false, 8)
		return binary.BigEndian.AppendUint64(b, math.Float64bits(f)), nil
	case "octet_string":
		c, err := hexOf(v.Value)
		if err != nil {
			return nil, err
		}
		b = putTag(b, 6, false, lvtFor(len(c)))
		b = putLength(b, len(c))
		return append(b, c...), nil
	case "bit_string":
		c, err := hexOf(v.Value)
		if err != nil {
			return nil, err
		}
		if len(c) == 0 {
			return nil, fmt.Errorf("bacnet: bit_string content empty")
		}
		total := len(c) + 1
		b = putTag(b, 8, false, lvtFor(total))
		b = putLength(b, total)
		b = append(b, byte(v.UnusedBits))
		return append(b, c...), nil
	case "char_string":
		s, ok := v.Value.(string)
		if !ok {
			return nil, fmt.Errorf("bacnet: char_string value must be a string")
		}
		c, err := charContent(s, v.Charset)
		if err != nil {
			return nil, err
		}
		b = putTag(b, 7, false, lvtFor(len(c)))
		b = putLength(b, len(c))
		return append(b, c...), nil
	case "date":
		m, ok := v.Value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("bacnet: date value must be {year,month,day,weekday}")
		}
		b = putTag(b, 10, false, 4)
		return append(b, byte(getI(m, "year")-1900), byte(getI(m, "month")), byte(getI(m, "day")), byte(getI(m, "weekday"))), nil
	case "time":
		m, ok := v.Value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("bacnet: time value must be {hour,minute,second,century}")
		}
		b = putTag(b, 11, false, 4)
		return append(b, byte(getI(m, "hour")), byte(getI(m, "minute")), byte(getI(m, "second")), byte(getI(m, "century"))), nil
	case "object_id":
		b = putTag(b, 12, false, 4)
		return binary.BigEndian.AppendUint32(b, objectID(v.ObjType, v.ObjInstance)), nil
	}
	return nil, fmt.Errorf("bacnet: unknown value type %q", v.Type)
}

// ---- 上下文标签形状（§3.6 服务参数）----

func ctxTag(b []byte, tag int, content []byte) []byte {
	b = putTag(b, tag, true, lvtFor(len(content)))
	return append(b, content...)
}
func ctxOpen(b []byte, tag int) []byte  { return putTag(b, tag, true, 6) }
func ctxClose(b []byte, tag int) []byte { return putTag(b, tag, true, 7) }
func ctxUnsigned(b []byte, tag int, v uint64) []byte {
	return ctxTag(b, tag, unsignedBytes(v))
}
func ctxUnsigned16(b []byte, tag int, v int) []byte {
	return ctxTag(b, tag, putU16(nil, v))
}
func ctxEnumerated(b []byte, tag int, v uint64) []byte {
	return ctxTag(b, tag, unsignedBytes(v))
}
func ctxObjectID(b []byte, tag int, objType, instance int) []byte {
	return binary.BigEndian.AppendUint32(putTag(b, tag, true, 4), objectID(objType, instance))
}
func ctxBool(b []byte, tag int, v bool) []byte {
	c := byte(0)
	if v {
		c = 1
	}
	return ctxTag(b, tag, []byte{c})
}
func ctxCharString(b []byte, tag int, s string, charset int) ([]byte, error) {
	c, err := charContent(s, charset)
	if err != nil {
		return nil, err
	}
	b = putTag(b, tag, true, lvtFor(len(c)))
	b = putLength(b, len(c))
	return append(b, c...), nil
}

// ---- GenEvents 接口（终结层事件面）----

func (g *BACNETGenerator) GenEvents() layers.EventGenerator { return g }
func (g *BACNETGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("bacnet generator: EmitEvent is not wired")
}

func objectID(objType, instance int) uint32 {
	return uint32(objType)<<22 | uint32(instance)&0x3FFFFF
}

// charContent builds charset byte + string bytes (0=ANSI/UTF-8, 4=UCS-2BE).
func charContent(s string, charset int) ([]byte, error) {
	switch charset {
	case 0:
		return append([]byte{0}, s...), nil
	case 4:
		out := make([]byte, 0, 1+2*len([]rune(s)))
		out = append(out, 4)
		for _, c := range s {
			out = binary.BigEndian.AppendUint16(out, uint16(c))
		}
		return out, nil
	}
	return nil, fmt.Errorf("bacnet: unsupported charset %d (0=ANSI/4=UCS-2)", charset)
}

func uintOf(v interface{}) (uint64, error) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, fmt.Errorf("bacnet: negative unsigned %v", n)
		}
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("bacnet: negative unsigned %v", n)
		}
		return uint64(n), nil
	}
	return 0, fmt.Errorf("bacnet: unsigned value must be a number")
}
func intOf(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	}
	return 0, fmt.Errorf("bacnet: int value must be a number")
}
func floatOf(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	}
	return 0, fmt.Errorf("bacnet: real value must be a number")
}
func hexOf(v interface{}) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("bacnet: hex value must be a string")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("bacnet: hex value %q has odd length", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := hexNibble(s[2*i]), hexNibble(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("bacnet: hex value %q has non-hex character", s)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}
func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// signedBytes minimal two's-complement big-endian (0 → 1B).
func signedBytes(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	neg := v < 0
	var tmp [8]byte
	n := 0
	u := uint64(v)
	for {
		tmp[7-n] = byte(u)
		u >>= 8
		n++
		if u == 0 && ((tmp[8-n]&0x80) == 0) == !neg {
			break
		}
		if n == 8 {
			break
		}
	}
	return append([]byte{}, tmp[8-n:]...)
}
func getI(m map[string]interface{}, k string) int {
	v, _ := m[k].(float64)
	return int(v)
}

// ---- NPDU（§3.2；hop 紧跟 DADR——135-2016 §6.2.2/tshark 解码面，见裁定）----

func buildNPDU(b []byte, npdu *core.BACNETNPDU, netMsg bool, nsdu []byte) []byte {
	b = append(b, 0x01)
	var control byte
	if npdu != nil {
		if npdu.Dest != nil {
			control |= 0x20
		}
		if npdu.Src != nil {
			control |= 0x08
		}
		control |= byte(npdu.Priority & 0x03)
		if npdu.ExpectReply {
			control |= 0x04
		}
	}
	if netMsg {
		control |= 0x80
	}
	b = append(b, control)
	if npdu != nil && npdu.Dest != nil {
		b = putU16(b, npdu.Dest.Net)
		if npdu.Dest.IP != "" && npdu.Dest.Port != 0 {
			b = append(b, 6)
			b = append(b, addrBytes(npdu.Dest.IP, npdu.Dest.Port)...)
		} else {
			b = append(b, 0) // DLEN=0 = DNET 内广播
		}
		b = append(b, 0xFF) // Hop Count（仅随 DNET，初值 0xFF）
	}
	if npdu != nil && npdu.Src != nil {
		b = putU16(b, npdu.Src.Net)
		b = append(b, 6)
		b = append(b, addrBytes(npdu.Src.IP, npdu.Src.Port)...)
	}
	return append(b, nsdu...)
}

// addrBytes renders a 6-byte B/IP address (IP 4B + port 2B, 大端).
func addrBytes(ip string, port uint16) []byte {
	out := make([]byte, 4)
	for i, p := range strings.SplitN(ip, ".", 4) {
		if i >= 4 {
			break
		}
		var n int
		fmt.Sscanf(p, "%d", &n)
		out[i] = byte(n)
	}
	return binary.BigEndian.AppendUint16(out, port)
}

// ---- 服务参数（§3.6，原子单元列表——分段不越单元）----

func serviceParams(ev *core.BACNETEvent) ([][]byte, error) {
	var units [][]byte
	if ev.Kind == "segmented_request" {
		// 分段请求当前承载 WriteProperty 形态（正例 29/43；服务码 15 由
		// renderEvent 定）。参数形状与 write_property 一致（对象/属性/
		// [下标]/开[3] 值 闭[3]/[优先级]）——原子单元切分在 segmentFrames。
		wp := *ev
		wp.Kind = "write_property"
		return serviceParams(&wp)
	}
	switch ev.Kind {
	case "who_is":
		if ev.Low != nil {
			units = append(units, ctxUnsigned(nil, 0, uint64(*ev.Low)))
		}
		if ev.High != nil {
			units = append(units, ctxUnsigned(nil, 1, uint64(*ev.High)))
		}
	case "who_has":
		if ev.Low != nil {
			units = append(units, ctxUnsigned(nil, 0, uint64(*ev.Low)))
		}
		if ev.High != nil {
			units = append(units, ctxUnsigned(nil, 1, uint64(*ev.High)))
		}
		if ev.ObjectName != "" {
			c, err := ctxCharString(nil, 3, ev.ObjectName, 0)
			if err != nil {
				return nil, err
			}
			units = append(units, c)
		} else {
			units = append(units, ctxObjectID(nil, 2, ev.ObjectType, ev.Instance))
		}
	case "i_am":
		ins := effectiveIAM(ev, nil)
		objid := append([]byte{0xC4}, putU32(nil, objectID(8, ins.deviceInstance))...)
		units = append(units,
			objid,
			append([]byte{0x22}, putU16(nil, ins.maxAPDU)...),
			append([]byte{0x91}, unsignedBytes(uint64(ins.segmentation))...),
			append([]byte{0x22}, putU16(nil, ins.vendorID)...),
		)
	case "i_have":
		dev := append([]byte{0xC4}, putU32(nil, objectID(8, ev.DeviceInstance))...)
		obj := append([]byte{0xC4}, putU32(nil, objectID(ev.ObjectType, ev.Instance))...)
		name, err := appTag(nil, &core.BACNETValue{Type: "char_string", Value: ev.ObjectName})
		if err != nil {
			return nil, err
		}
		units = append(units, dev, obj, name)
	case "read_property":
		units = append(units,
			ctxObjectID(nil, 0, ev.ObjectType, ev.Instance),
			ctxEnumerated(nil, 1, uint64(ev.Property)))
		if ev.ArrayIndex != nil {
			units = append(units, ctxUnsigned(nil, 2, uint64(*ev.ArrayIndex)))
		}
	case "write_property":
		units = append(units,
			ctxObjectID(nil, 0, ev.ObjectType, ev.Instance),
			ctxEnumerated(nil, 1, uint64(ev.Property)))
		if ev.ArrayIndex != nil {
			units = append(units, ctxUnsigned(nil, 2, uint64(*ev.ArrayIndex)))
		}
		units = append(units, ctxOpen(nil, 3))
		v, err := appTag(nil, valueOrFixture(ev.Value))
		if err != nil {
			return nil, err
		}
		units = append(units, v, ctxClose(nil, 3))
		if ev.Priority != nil {
			units = append(units, ctxUnsigned(nil, 4, uint64(*ev.Priority)))
		}
	case "rpm":
		for _, r := range ev.Reads {
			units = append(units, ctxObjectID(nil, 0, r.ObjectType, r.Instance))
			units = append(units, ctxOpen(nil, 1))
			for _, p := range r.Props {
				units = append(units, ctxEnumerated(nil, 0, uint64(p.Property)))
				if p.ArrayIndex != nil {
					units = append(units, ctxUnsigned(nil, 1, uint64(*p.ArrayIndex)))
				}
			}
			units = append(units, ctxClose(nil, 1))
		}
	case "subscribe_cov":
		units = append(units,
			ctxUnsigned(nil, 0, uint64(ev.ProcessID)),
			ctxObjectID(nil, 1, ev.ObjectType, ev.Instance))
		if ev.IssueConfirmed != nil {
			units = append(units, ctxBool(nil, 2, *ev.IssueConfirmed))
		}
		if ev.Lifetime != nil {
			units = append(units, ctxUnsigned16(nil, 3, *ev.Lifetime))
		}
	case "cov_notification":
		units = append(units,
			ctxUnsigned(nil, 0, uint64(ev.ProcessID)),
			ctxObjectID(nil, 1, 8, ev.InitiatingDevice),
			ctxObjectID(nil, 2, ev.ObjectType, ev.Instance),
			ctxUnsigned16(nil, 3, ev.TimeRemaining))
		for _, cv := range ev.CovValues {
			u := ctxOpen(nil, 4)
			u = append(u, ctxEnumerated(nil, 0, uint64(cv.Property))...)
			u = append(u, ctxOpen(nil, 2)...)
			v, err := appTag(u, valueOrFixture(cv.Value))
			if err != nil {
				return nil, err
			}
			v = append(v, ctxClose(nil, 2)...)
			v = append(v, ctxClose(nil, 4)...)
			units = append(units, v)
		}
	case "dcc":
		if ev.Duration != nil {
			units = append(units, ctxUnsigned16(nil, 0, *ev.Duration))
		}
		if ev.Disable != nil {
			units = append(units, ctxEnumerated(nil, 1, uint64(*ev.Disable)))
		}
		if ev.Password != "" {
			c, err := ctxCharString(nil, 2, ev.Password, 0)
			if err != nil {
				return nil, err
			}
			units = append(units, c)
		}
	default:
		return nil, fmt.Errorf("bacnet: kind %q takes no service params", ev.Kind)
	}
	return units, nil
}

func putU32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

func valueOrFixture(v *core.BACNETValue) *core.BACNETValue {
	if v != nil {
		return v
	}
	return &core.BACNETValue{Type: "boolean", Value: true}
}

// effectiveIAM resolves the I-Am identity（事件声明 > 会话缺省 > fixture——
// 单解析权威，validator 同源）.
type iamIdentity struct{ deviceInstance, maxAPDU, segmentation, vendorID int }

func effectiveIAM(ev *core.BACNETEvent, sess *core.BACNETSession) iamIdentity {
	r := iamIdentity{FixtureDeviceInstance, FixtureMaxAPDU, FixtureSegmentation, FixtureVendorID}
	if sess != nil {
		if sess.DeviceInstance != 0 {
			r.deviceInstance = sess.DeviceInstance
		}
		if sess.MaxAPDU != 0 {
			r.maxAPDU = sess.MaxAPDU
		}
		if sess.Segmentation != nil {
			r.segmentation = *sess.Segmentation
		}
		if sess.VendorID != 0 {
			r.vendorID = sess.VendorID
		}
	}
	if ev != nil {
		if ev.DeviceInstance != 0 {
			r.deviceInstance = ev.DeviceInstance
		}
		if ev.MaxAPDU != 0 {
			r.maxAPDU = ev.MaxAPDU
		}
		if ev.Segmentation != nil {
			r.segmentation = *ev.Segmentation
		}
		if ev.VendorID != 0 {
			r.vendorID = ev.VendorID
		}
	}
	return r
}

// ---- Invoke 单解析权威（生成器与 validator 同源同序）----

// invokeWalker：声明值采纳（n>ctr 才推进）、缺省迭代递增；首个确认请求
// 缺省 = 1（正例 35 序列 1,2；正例 34 声明 0 合法边界）。
type invokeWalker struct{ ctr int }

func (w *invokeWalker) request(declared *int) int {
	if declared != nil {
		if *declared > w.ctr {
			w.ctr = *declared
		}
		return *declared
	}
	w.ctr++
	return w.ctr
}

// pendingInvoke resolves the response target transaction（声明值优先，
// 否则取最旧 open 事务；ok=false = 无 open 事务）.
func pendingInvoke(open map[int]bool, declared *int) (int, bool) {
	if declared != nil {
		return *declared, open[*declared]
	}
	ids := make([]int, 0, len(open))
	for id := range open {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		return 0, false
	}
	return ids[0], true
}

// ---- BVLC 帧（§3.1）----

func bvlcHeader(b []byte, fn byte, totalLen int) []byte {
	return append(b, 0x81, fn, byte(totalLen>>8), byte(totalLen))
}

func buildBVLCResult(code int) []byte {
	return putU16(bvlcHeader(nil, 0x00, 6), code)
}

// wrapBVLC frames an NPDU with the Original-Unicast/Broadcast BVLC header.
func wrapBVLC(fn byte, npdu []byte) []byte {
	b := bvlcHeader(nil, fn, 4+len(npdu))
	return append(b, npdu...)
}

// buildTableEntry renders one BDT (ip+port+mask) or FDT (ip+port+ttl+timeout)
// 10-byte entry.
func buildTableEntry(e *core.BACNETTableEntry, fdt bool) []byte {
	out := addrBytes(e.IP, e.Port)
	if fdt {
		out = putU16(out, e.TTL)
		out = putU16(out, e.Timeout)
	} else {
		var mask [4]byte
		for i := 0; i < 4 && 2*i+1 < len(e.Mask); i++ {
			hi, lo := hexNibble(e.Mask[2*i]), hexNibble(e.Mask[2*i+1])
			if hi >= 0 && lo >= 0 {
				mask[i] = byte(hi<<4 | lo)
			}
		}
		out = append(out, mask[:]...)
	}
	return out
}

// ---- 事件渲染（含自动派生 ①-⑦——设计 §5）----

type frame struct {
	up    bool
	bytes []byte
}

func apduUnconfirmed(service int, units [][]byte) []byte {
	b := []byte{0x10, byte(service)}
	for _, u := range units {
		b = append(b, u...)
	}
	return b
}

// renderEvent renders one event into its datagram frames.
// renderEvent 的 fnUp 是 up 方向帧的 BVLC 功能码（0x0A 单播 / 0x0B
// 广播——目的 IP 为定向广播时用 Original-Broadcast-NPDU，正例 3；down
// 恒 0x0A，正例 1 帧 2）。
func renderEvent(ev *core.BACNETEvent, sess *core.BACNETSession, inv *invokeWalker, open map[int]bool, fnUp byte) ([]frame, error) {
	switch ev.Kind {
	case "register_foreign_device", "write_bdt", "read_bdt", "read_fdt",
		"delete_fdt", "distribute_broadcast", "forwarded_npdu":
		return renderBVLC(ev)
	case "router_discovery", "raw_npdu":
		mt := ev.NetMsgType
		if ev.Kind == "router_discovery" {
			mt = 0 // Who-Is-Router-To-Network
		}
		var body []byte
		if mt == 0 && len(ev.Nets) > 0 {
			body = putU16(nil, ev.Nets[0]) // 可选 2B DNET
		}
		nl := append([]byte{byte(mt)}, body...)
		up := mt == 0
		npduOut := ev.NPDU
		if up {
			// Who-Is-Router 期望回复（control 0x84——正例 14 帧 1）；
			// I-Am-Router 0x80 无期望回复（帧 2）。
			npduOut = npduExpectReply(npduOut)
		}
		frames := []frame{{up, wrapBVLC(fnUp, buildNPDU(nil, npduOut, true, nl))}}
		if ev.Kind == "router_discovery" && ev.Respond != nil && len(ev.Respond.Nets) > 0 {
			// 规则⑦：I-Am-Router-To-Network（DNET 列表 = respond.nets）。
			var b []byte
			b = append(b, 0x01)
			for _, n := range ev.Respond.Nets {
				b = putU16(b, n)
			}
			frames = append(frames, frame{false, wrapBVLC(0x0A, buildNPDU(nil, nil, true, b))})
		}
		return frames, nil
	case "i_am":
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, ev.NPDU, false, apduUnconfirmed(0, params)))}}, nil
	case "i_have":
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, ev.NPDU, false, apduUnconfirmed(1, params)))}}, nil
	case "cov_notification":
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, ev.NPDU, false, apduUnconfirmed(2, params)))}}, nil
	case "who_is":
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		// Who-Is = unconfirmed service 8（NPDU control 缺省 0x00——非确认
		// 不期望回复，正例 1）。
		frames := []frame{{true, wrapBVLC(fnUp, buildNPDU(nil, ev.NPDU, false, apduUnconfirmed(8, params)))}}
		if ev.RespondIAM {
			// 规则①：自动补 I-Am（身份四元 = 事件声明 > 会话缺省 > fixture）。
			ins := effectiveIAM(nil, sess)
			seg := ins.segmentation
			params, err := serviceParams(&core.BACNETEvent{
				Kind:           "i_am",
				DeviceInstance: ins.deviceInstance,
				MaxAPDU:        ins.maxAPDU,
				Segmentation:   &seg,
				VendorID:       ins.vendorID,
			})
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, apduUnconfirmed(0, params)))})
		}
		return frames, nil
	case "who_has":
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		return []frame{{true, wrapBVLC(fnUp, buildNPDU(nil, ev.NPDU, false, apduUnconfirmed(7, params)))}}, nil
	case "error", "reject", "abort":
		id, ok := pendingInvoke(open, ev.InvokeID)
		if !ok {
			return nil, fmt.Errorf("bacnet: %s event has no open confirmed request (state)", ev.Kind)
		}
		delete(open, id)
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, ev.NPDU, false, buildFailureAPDU(ev, id)))}}, nil
	case "segmented_ack":
		// 分段 ComplexACK（正例 30）：对象/属性/值拆段下行 + SegmentACK
		// 上行（SRV=0）。
		id, ok := pendingInvoke(open, ev.InvokeID)
		if !ok {
			return nil, fmt.Errorf("bacnet: segmented_ack has no open confirmed request (state)")
		}
		delete(open, id)
		units := [][]byte{
			ctxObjectID(nil, 0, ev.ObjectType, ev.Instance),
			ctxEnumerated(nil, 1, uint64(ev.Property)),
		}
		if ev.ArrayIndex != nil {
			units = append(units, ctxUnsigned(nil, 2, uint64(*ev.ArrayIndex)))
		}
		units = append(units, ctxOpen(nil, 3))
		v, err := appTag(nil, valueOrFixture(ev.Value))
		if err != nil {
			return nil, err
		}
		units = append(units, v, ctxClose(nil, 3))
		window := ev.WindowSize
		if window == 0 {
			window = ackWindow
		}
		return segmentFrames(units, 0, byte(id), 12, window, false, npduExpectReply(ev.NPDU)), nil
	case "segmented_request":
		// 分段 Confirmed-REQ（正例 29/43，承载 WriteProperty 服务 15）：
		// 拆段上行 + SegmentACK 下行（SRV=1）。
		params, err := serviceParams(ev)
		if err != nil {
			return nil, err
		}
		id := inv.request(ev.InvokeID)
		if open[id] {
			return nil, fmt.Errorf("bacnet: invoke id %d reused while transaction open (invoke)", id)
		}
		open[id] = true
		window := ev.WindowSize
		if window == 0 {
			window = segmentedWindow
		}
		return segmentFrames(params, segmentedMaxByte, byte(id), 15, window, true, npduExpectReply(ev.NPDU)), nil
	}

	// --- 确认请求族（read_property 12 / rpm 14 / write_property 15 /
	// subscribe_cov 5 / dcc 17）---
	service, params, err := confirmedRequest(ev)
	if err != nil {
		return nil, err
	}
	id := inv.request(ev.InvokeID)
	if open[id] {
		return nil, fmt.Errorf("bacnet: invoke id %d reused while transaction open (invoke)", id)
	}
	open[id] = true
	b0 := byte(0x00)
	if ev.SA {
		b0 = 0x02 // SA bit1：客户端声明接受分段响应（正例 52）
	}
	apdu := []byte{b0, unconfirmedMaxByte, byte(id), byte(service)}
	for _, u := range params {
		apdu = append(apdu, u...)
	}
	frames := []frame{{true, wrapBVLC(fnUp, buildNPDU(nil, npduExpectReply(ev.NPDU), false, apdu))}}
	if ev.Respond != nil {
		rf, err := renderRespond(ev, id, service)
		if err != nil {
			return nil, err
		}
		frames = append(frames, rf...)
		if rf != nil {
			delete(open, id) // 事务完成
		}
	}
	return frames, nil
}

func confirmedRequest(ev *core.BACNETEvent) (int, [][]byte, error) {
	params, err := serviceParams(ev)
	if err != nil {
		return 0, nil, err
	}
	switch ev.Kind {
	case "read_property":
		return 12, params, nil
	case "rpm":
		return 14, params, nil
	case "write_property":
		return 15, params, nil
	case "subscribe_cov":
		return 5, params, nil
	case "dcc":
		return 17, params, nil
	}
	return 0, nil, fmt.Errorf("bacnet: kind %q is not a confirmed request", ev.Kind)
}

// npduExpectReply forces control bit2 on message classes that inherently
// expect a reply (confirmed requests / segmented frames——正例 16 帧 1
// control 0x04、正例 29 分段 control 0x04；SimpleACK/ComplexACK 末段回包
// control 0x00——正例 16 帧 2)。其余方向语义按声明。
func npduExpectReply(npdu *core.BACNETNPDU) *core.BACNETNPDU {
	if npdu == nil {
		return &core.BACNETNPDU{ExpectReply: true}
	}
	cp := *npdu
	cp.ExpectReply = true
	return &cp
}

// buildFailureAPDU renders Error/Reject/Abort（§3.3 首字节表）.
func buildFailureAPDU(ev *core.BACNETEvent, id int) []byte {
	switch ev.Kind {
	case "error":
		b := []byte{0x50, byte(id), byte(ev.ServiceChoice), 0x91}
		b = append(b, unsignedBytes(uint64(ev.ErrClass))...)
		b = append(b, 0x91)
		return append(b, unsignedBytes(uint64(ev.ErrCode))...)
	case "reject":
		return []byte{0x60, byte(id), byte(ev.RejectReason)}
	default: // abort
		b0 := byte(0x70)
		if ev.SRV != nil && *ev.SRV {
			b0 |= 1
		}
		return []byte{b0, byte(id), byte(ev.AbortReason)}
	}
}

// renderRespond renders one auto-derived response（规则②③：simple/
// complex ACK 或 Error/Reject/Abort 替代；nil = 未配置不自动补）.
func renderRespond(ev *core.BACNETEvent, id, service int) ([]frame, error) {
	r := ev.Respond
	if r.Error != nil {
		er := &core.BACNETEvent{Kind: "error", ServiceChoice: service, ErrClass: r.Error.Class, ErrCode: r.Error.Code}
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, buildFailureAPDU(er, id)))}}, nil
	}
	if r.Reject != nil {
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, buildFailureAPDU(&core.BACNETEvent{Kind: "reject", RejectReason: *r.Reject}, id)))}}, nil
	}
	if r.Abort != nil {
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, buildFailureAPDU(&core.BACNETEvent{Kind: "abort", AbortReason: *r.Abort}, id)))}}, nil
	}
	switch r.Ack {
	case "simple":
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, []byte{0x20, byte(id), byte(service)}))}}, nil
	case "complex":
		var units [][]byte
		if len(r.Results) > 0 {
			// RPM 多对象应答：ctx0 对象 + 开[1] + {ctx2 属性 [+ctx3 下标] +
			// 开[4] 值 闭[4]}* + 闭[1]。
			for _, res := range r.Results {
				units = append(units, ctxObjectID(nil, 0, res.ObjectType, res.Instance))
				units = append(units, ctxOpen(nil, 1))
				for _, p := range res.Props {
					u := ctxEnumerated(nil, 2, uint64(p.Property))
					if p.ArrayIndex != nil {
						u = append(u, ctxUnsigned(nil, 3, uint64(*p.ArrayIndex))...)
					}
					u = append(u, ctxOpen(nil, 4)...)
					v, err := appTag(u, valueOrFixture(p.Value))
					if err != nil {
						return nil, err
					}
					v = append(v, ctxClose(nil, 4)...)
					units = append(units, v)
				}
				units = append(units, ctxClose(nil, 1))
			}
		} else {
			// 单值 RP 应答：ctx0 对象 + ctx1 属性 [+ctx2 下标] + 开[3] 值 闭[3]。
			units = append(units,
				ctxObjectID(nil, 0, ev.ObjectType, ev.Instance),
				ctxEnumerated(nil, 1, uint64(ev.Property)))
			if ev.ArrayIndex != nil {
				units = append(units, ctxUnsigned(nil, 2, uint64(*ev.ArrayIndex)))
			}
			units = append(units, ctxOpen(nil, 3))
			v, err := appTag(nil, valueOrFixture(r.Value))
			if err != nil {
				return nil, err
			}
			units = append(units, v, ctxClose(nil, 3))
		}
		if r.Segmented {
			// 声明分段 ComplexACK（正例 30）：拆段下行 + SegmentACK 上行
			// （SRV=0）。window 0 = 缺省 4。
			window := r.Window
			if window == 0 {
				window = ackWindow
			}
			return segmentFrames(units, 0, byte(id), byte(service), window, false, npduExpectReply(nil)), nil
		}
		apdu := []byte{0x30, byte(id), byte(service)}
		for _, u := range units {
			apdu = append(apdu, u...)
		}
		return []frame{{false, wrapBVLC(0x0A, buildNPDU(nil, nil, false, apdu))}}, nil
	}
	return nil, nil
}

// renderBVLC renders the BBMD management frame family（§3.1 功能表 +
// 自动派生 ⑤⑥）.
func renderBVLC(ev *core.BACNETEvent) ([]frame, error) {
	switch ev.Kind {
	case "register_foreign_device":
		b := putU16(bvlcHeader(nil, 0x05, 6), ev.TTL)
		return []frame{{true, b}, {false, autoResult(ev)}}, nil
	case "write_bdt":
		var load []byte
		for i := range ev.Entries {
			load = append(load, buildTableEntry(&ev.Entries[i], false)...)
		}
		b := bvlcHeader(nil, 0x01, 4+len(load))
		return []frame{{true, append(b, load...)}, {false, autoResult(ev)}}, nil
	case "delete_fdt":
		if len(ev.Entries) != 1 {
			return nil, fmt.Errorf("bacnet: delete_fdt needs exactly one entry")
		}
		b := bvlcHeader(nil, 0x08, 10)
		b = append(b, addrBytes(ev.Entries[0].IP, ev.Entries[0].Port)...)
		return []frame{{true, b}, {false, autoResult(ev)}}, nil
	case "read_bdt", "read_fdt":
		fn := byte(0x02)
		if ev.Kind == "read_fdt" {
			fn = 0x06
		}
		frames := []frame{{true, bvlcHeader(nil, fn, 4)}}
		// 规则⑥：Read-BDT/FDT-Ack（表项 = respond.entries，可空表 Length 4）。
		var load []byte
		fdt := ev.Kind == "read_fdt"
		if ev.Respond != nil {
			for i := range ev.Respond.Entries {
				load = append(load, buildTableEntry(&ev.Respond.Entries[i], fdt)...)
			}
		}
		ackFn := byte(0x03)
		if fdt {
			ackFn = 0x07
		}
		b := bvlcHeader(nil, ackFn, 4+len(load))
		frames = append(frames, frame{false, append(b, load...)})
		return frames, nil
	case "distribute_broadcast":
		// 规则⑤ 例外：Distribute-Broadcast 静默转发不补 Result（Annex J）。
		npdu, err := innerNPDU(ev.Inner)
		if err != nil {
			return nil, err
		}
		b := bvlcHeader(nil, 0x09, 4+len(npdu))
		return []frame{{true, append(b, npdu...)}}, nil
	case "forwarded_npdu":
		npdu, err := innerNPDU(ev.Inner)
		if err != nil {
			return nil, err
		}
		b := bvlcHeader(nil, 0x04, 10+len(npdu))
		b = append(b, addrBytes(ev.FwdIP, ev.FwdPort)...)
		return []frame{{false, append(b, npdu...)}}, nil
	}
	return nil, fmt.Errorf("bacnet: kind %q is not a BVLC frame", ev.Kind)
}

// autoResult builds the auto BVLC-Result（默认 0x0000，respond.result 覆盖）.
func autoResult(ev *core.BACNETEvent) []byte {
	code := 0
	if ev.Respond != nil && ev.Respond.Result != nil {
		code = *ev.Respond.Result
	}
	return buildBVLCResult(code)
}

// innerNPDU renders the inner event (who_is only) as a bare NPDU.
func innerNPDU(inner *core.BACNETEvent) ([]byte, error) {
	if inner == nil || inner.Kind != "who_is" {
		return nil, fmt.Errorf("bacnet: forwarded/distribute inner payload must be a who_is event")
	}
	params, err := serviceParams(inner)
	if err != nil {
		return nil, err
	}
	return buildNPDU(nil, inner.NPDU, false, apduUnconfirmed(8, params)), nil
}

// segmentFrames splits service param units into segmented APDU frames with
// paired SegmentACKs（窗口规则：每收满 window 段或收到末段即回——正例
// 29 window 2 单 ACK / 43 window 1 逐段 / 43 window 255 整窗）。
// segMaxByte 非 0 = Confirmed-REQ（b0+maxbyte+invoke+seq+window+svc 六字节
// 头，max-APDU 480）；0 = ComplexACK（b0+invoke+seq+window+svc 五字节头）。
// isRequest 决定段方向与 SegmentACK 侧（请求→设备回 SRV=1 down；
// 应答→客户回 SRV=0 up）。
func segmentFrames(units [][]byte, segMaxByte byte, id, service byte, window int, isRequest bool, npdu *core.BACNETNPDU) []frame {
	headerLen := 5
	if segMaxByte != 0 {
		headerLen = 6
	}
	capacity := segmentedMaxAPDU - headerLen
	type segT struct {
		units [][]byte
		size  int
	}
	var segs []segT
	cur := segT{}
	for _, u := range units {
		if cur.size+len(u) > capacity && cur.size > 0 {
			segs = append(segs, cur)
			cur = segT{}
		}
		cur.units = append(cur.units, u)
		cur.size += len(u)
	}
	if cur.size > 0 {
		segs = append(segs, cur)
	}
	// declared-split（正例 30：14B 服务数据单段可容纳仍拆两段）→ 在首个
	// 上下文开标签（LVT=6）后强制切分——值边界分割（正例 29 同一规则
	// 天然生效：470B 值单元塞不进首段剩余 466B）。
	if len(segs) == 1 {
		for i, u := range units {
			// 上下文开标签：class bit3=1 且 LVT(bit2-0)=6。
			if u[0]&0x08 != 0 && u[0]&0x07 == 6 {
				if i+1 < len(units) {
					segs = []segT{{units: units[:i+1]}, {units: units[i+1:]}}
				}
				break
			}
		}
	}
	if window <= 0 {
		window = 1
	}
	segUp := isRequest
	ackUp := !isRequest
	srv := byte(0)
	if isRequest {
		srv = 1
	}
	frames := make([]frame, 0, len(segs)+1)
	for i, sg := range segs {
		mor := byte(0)
		if i < len(segs)-1 {
			mor = 0x04 // MOR=1 还有段
		}
		var apdu []byte
		if segMaxByte != 0 {
			// 首字节 = 类型 0 + SEG(0x08)|MOR(0x04)（正例 29：首段 0x0c、
			// 末段 0x08）。
			apdu = []byte{0x08 | mor, segMaxByte, id, byte(i), byte(window), service}
		} else {
			apdu = []byte{0x38 | mor, id, byte(i), byte(window), service}
		}
		for _, u := range sg.units {
			apdu = append(apdu, u...)
		}
		frames = append(frames, frame{segUp, wrapBVLC(0x0A, buildNPDU(nil, npdu, false, apdu))})
		if i == len(segs)-1 || (i+1)%window == 0 {
			ack := []byte{0x40 | srv, id, byte(i), byte(window)}
			frames = append(frames, frame{ackUp, wrapBVLC(0x0A, buildNPDU(nil, nil, false, ack))})
		}
	}
	return frames
}

// ---- Generate（链驱动入口）----

// BACNETGenerator is the terminal-layer generator for bacnet chains.
type BACNETGenerator struct{}

func (g *BACNETGenerator) Name() string { return "bacnet" }

func (g *BACNETGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("bacnet generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("bacnet generator: EmitMsg is nil")
	}
	cfg := req.Meta.BACNET
	if cfg == nil {
		cfg = &core.BACNETConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		BACNET:  cfg,
	}); err != nil {
		return err
	}
	frames, err := BuildFrames(cfg, req.Meta.DstIP)
	if err != nil {
		return err
	}
	// 会话端点覆盖。up：SrcIP/SrcPort 直落（留空走链层默认）；down：会话
	// 声明了 SrcIP 时显式路由 服务端(=流 dst)→会话客户端——MessageEvent 的
	// SrcIP 不参与交换、DstIP 覆盖为绝对目标（跳过 down 交换），多会话
	// 双客户端（正例 37/47）的应答才能回到正确客户端；未声明 SrcIP 的
	// 会话 down 留空走链层交换（单会话零变化）。
	for _, ef := range frames {
		for _, fr := range ef.frames {
			ev := layers.MessageEvent{Up: fr.up, Bytes: fr.bytes}
			if fr.up {
				if ef.srcIP != "" {
					ev.SrcIP = ef.srcIP
				}
				if ef.srcPort != 0 {
					ev.SrcPort = ef.srcPort
				}
			} else if ef.srcIP != "" {
				ev.SrcIP = req.Meta.DstIP
				ev.DstIP = ef.srcIP
				ev.OverrideDstIP = true
			}
			if ef.dstPort != 0 {
				ev.DstPort = ef.dstPort
			}
			if err := req.EmitMsg(ev); err != nil {
				return err
			}
		}
	}
	return nil
}

// eventFrames is one event's rendered frames + endpoint overrides.
type eventFrames struct {
	frames  []frame
	srcIP   string
	srcPort uint16
	dstPort uint16
}

// BuildFrames renders all sessions' events in replay order（按序整块回放，
// 第二会话包号起点 = 前会话总包数 + 1；concurrent=true 按 event index
// round-robin 交错——v2.1 C-1）。缺省（无 sessions）发一条 8B BACnet/IP
// 最小帧 Who-Is 基线。
func BuildFrames(cfg *core.BACNETConfig, dstIP string) ([]eventFrames, error) {
	fnUp := byte(0x0A)
	if strings.HasSuffix(dstIP, ".255") || dstIP == "255.255.255.255" {
		fnUp = 0x0B
	}
	if cfg == nil || len(cfg.Sessions) == 0 {
		b := wrapBVLC(fnUp, []byte{0x01, 0x00, 0x10, 0x08})
		return []eventFrames{{frames: []frame{{true, b}}}}, nil
	}
	perSession := make([][]eventFrames, len(cfg.Sessions))
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		var inv invokeWalker
		open := map[int]bool{}
		out := make([]eventFrames, 0, len(sess.Events))
		for ei := range sess.Events {
			ev := &sess.Events[ei]
			frs, err := renderEvent(ev, sess, &inv, open, fnUp)
			if err != nil {
				return nil, fmt.Errorf("bacnet: sessions[%d].events[%d] (%s): %w", si, ei, ev.Kind, err)
			}
			out = append(out, eventFrames{frames: frs, srcIP: sess.SrcIP, srcPort: sess.SrcPort, dstPort: sess.DstPort})
		}
		perSession[si] = out
	}
	var out []eventFrames
	if cfg.Concurrent {
		// 交错：event index round-robin（xmrmining C-07 同款；各会话内部
		// 事件序/事务配对不放宽）。
		maxEvents := 0
		for _, s := range perSession {
			if len(s) > maxEvents {
				maxEvents = len(s)
			}
		}
		for idx := 0; idx < maxEvents; idx++ {
			for si := range perSession {
				if idx < len(perSession[si]) {
					out = append(out, perSession[si][idx])
				}
			}
		}
		return out, nil
	}
	for _, s := range perSession {
		out = append(out, s...)
	}
	return out, nil
}

// ---- 注册 ----

func init() {
	layers.RegisterLayerGenerator("bacnet", func() (layers.LayerGenerator, error) { return &BACNETGenerator{}, nil })
	layers.RegisterLayerValidator("bacnet", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
