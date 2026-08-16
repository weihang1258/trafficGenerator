package dnp3

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements DNP3 over TCP or UDP.
type Planner struct{}
func NewPlanner() *Planner { return &Planner{} }
func (p *Planner) Name() string { return "dnp3" }

// Validate validates DNP3 role, transport, scenarios, objects, and fan-out.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.DNP3 == nil { return fmt.Errorf("dnp3: config is required") }
	c := spec.DNP3
	if c.LinkType != "" && c.LinkType != "master" && c.LinkType != "outstation" { return fmt.Errorf("dnp3: invalid link_type %q", c.LinkType) }
	if c.Transport != "" && c.Transport != "tcp" && c.Transport != "udp" { return fmt.Errorf("dnp3: invalid transport %q", c.Transport) }
	if c.AppSeq > 15 { return fmt.Errorf("dnp3: app_seq out of range [0..15]") }
	if c.LinkFCB > 1 { return fmt.Errorf("dnp3: link_fcb out of range [0..1]") }
	if c.LinkFC > 11 { return fmt.Errorf("dnp3: link_fc out of range [0..11]") }
	if c.DstAddr == 0xFFFF && c.ConfirmRequired { return fmt.Errorf("dnp3: broadcast cannot require confirm") }
	if c.Scenario == "unsolicited" && c.LinkType != "" && c.LinkType != "outstation" { return fmt.Errorf("dnp3: scenario 'unsolicited' requires link_type='outstation'") }
	if c.AppFunc != "" { if _, ok := appFunctions[c.AppFunc]; !ok { return fmt.Errorf("dnp3: invalid app_func %q", c.AppFunc) } }
	if c.AppFuncCode == 31 { return fmt.Errorf("dnp3: FC=31 is Reserved in IEEE 1815-2012") }
	if c.AppFuncCode == 215 { return fmt.Errorf("dnp3: FC=215 is Reserved in IEEE 1815-2012 (Configure deprecated)") }
	for i, o := range c.Objects {
		if o.Qualifier != 0 && o.Qualifier != 1 && o.Qualifier != 6 && o.Qualifier != 7 && o.Qualifier != 8 && o.Qualifier != 0x17 && o.Qualifier != 0x28 { return fmt.Errorf("dnp3: object %d invalid qualifier 0x%02X", i, o.Qualifier) }
		if o.IndexRange[0] > o.IndexRange[1] { return fmt.Errorf("dnp3: object %d index start exceeds stop", i) }
		if o.Qualifier == 0x00 && (o.IndexRange[0] > 255 || o.IndexRange[1] > 255) { return fmt.Errorf("dnp3: object %d qualifier 0x00 index exceeds 255", i) }
		if o.Qualifier == 0x17 { for _, p := range o.Points { if p.Index > 255 { return fmt.Errorf("dnp3: object %d qualifier 0x17 point index %d exceeds 255", i, p.Index) } } }
		if o.ObjectType == 20 && o.Variation > 2 { return fmt.Errorf("dnp3: object 20 variation must be 1 (32-bit) or 2 (16-bit)") }
		if isResponse(c) && o.Variation == 0 { return fmt.Errorf("dnp3: response frame must use concrete Variation, not 0") }
		// CROB Status (design §7.6.5 T66): Status is response-only, echoed by
		// the outstation. A request frame carrying it would emit the 7-byte
		// form instead of the 6-byte form (encodePoint appends Status only
		// for responses), silently dropping the field — reject instead.
		if o.ObjectType == 12 && o.Variation == 1 && !isResponse(c) {
			for _, p := range o.Points {
				if p.Status != nil { return fmt.Errorf("dnp3: CROB request must not carry Status field; Status is response-only") }
			}
		}
	}
	if m := c.MultiOutstation; m != nil {
		if m.OutstationCount <= 0 { return fmt.Errorf("dnp3: outstation_count must be > 0") }
		if len(m.OutstationIPList) > 0 && len(m.OutstationIPList) != m.OutstationCount { return fmt.Errorf("dnp3: outstation_ip_list length mismatch") }
		if m.OutstationCount > 1 {
			if len(m.OutstationIPList) == 0 && net.ParseIP(m.OutstationIPStart) == nil { return fmt.Errorf("dnp3: outstation_ip required when outstation_count > 1") }
			if m.SrcPortStart == 0 { return fmt.Errorf("dnp3: src_port_start must be set when outstation_count > 1") }
			if int(m.SrcPortStart)+m.OutstationCount-1 > 65535 { return fmt.Errorf("dnp3: src_port_start + outstation_count exceeds 65535") }
		}
	}
	return nil
}

func isResponse(c *core.DNP3Config) bool {
	return c.LinkType == "outstation" || c.AppFunc == "respond" || c.AppFunc == "unsolicited_respond" || c.Scenario == "unsolicited" || c.Scenario == "multi_object_response" || c.Scenario == "respond"
}

// Plan expands canonical scenarios into TCP segments or UDP datagrams.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil { return nil, err }
	out := make(chan core.PacketConfig, 256)
	go func() {
		defer close(out)
		c := spec.DNP3
		count := 1
		if c.MultiOutstation != nil { count = c.MultiOutstation.OutstationCount }
		for i := 0; i < count; i++ {
			flow := spec; cfg := *c; flow.DNP3 = &cfg
			if c.MultiOutstation != nil { applyOutstation(&flow, &cfg, i) }
			if !p.planFlow(ctx, flow, out, i) { return }
		}
	}()
	return out, nil
}

func applyOutstation(spec *core.FlowSpec, c *core.DNP3Config, i int) {
	m := c.MultiOutstation
	base := m.OutstationAddrStart; if base == 0 { base = 1024 }
	c.DstAddr = base + uint16(i); spec.SrcPort = m.SrcPortStart + uint16(i)
	if len(m.OutstationIPList) > 0 { spec.DstIP = m.OutstationIPList[i] } else { spec.DstIP = incrementIPv4(m.OutstationIPStart, i) }
}
func incrementIPv4(s string, n int) string { ip := net.ParseIP(s).To4(); if ip == nil { return s }; v := binary.BigEndian.Uint32(ip)+uint32(n); b:=make(net.IP,4); binary.BigEndian.PutUint32(b,v); return b.String() }

func (p *Planner) planFlow(ctx context.Context, spec core.FlowSpec, out chan<- core.PacketConfig, rtu int) bool {
	c := spec.DNP3; transport:=c.Transport; if transport=="" { transport="tcp" }
	if spec.DstPort==0 { spec.DstPort=DefaultPort }; if spec.SrcPort==0 { spec.SrcPort=DefaultPort }
	flowID:=fmt.Sprintf("%s-%s-%d-%d-RTU-%d",spec.SrcIP,spec.DstIP,spec.SrcPort,spec.DstPort,rtu)
	ttl:=spec.TTL; if ttl==0 { ttl=DefaultTTL }
	// 起始时间戳；每帧推进 step。
	// 即使 ThinkTime=0 也按 1µs 递增，保证 Timestamp 单调递增（修复 N2）。
	now:=time.Now()
	stepNanos:=int64(c.ThinkTime)*int64(time.Millisecond)
	if stepNanos<=0 { stepNanos=int64(time.Microsecond) }
	idx:=uint64(0); ipid:=uint16(rand.Uint32())
	clientSeq,serverSeq:=rand.Uint32(),rand.Uint32()
	// step 计算 ThinkTime 延时（毫秒）。返回 false 表示 ctx 取消或发送失败。
	sleepStep:=func()bool{
		select { case <-time.After(time.Duration(stepNanos)): case <-ctx.Done(): return false }; return true
	}
	emit:=func(dir string, flags uint8, payload []byte) bool {
		up:=dir=="up"; sip,dip:=spec.SrcIP,spec.DstIP; smac,dmac:=spec.SrcMAC,spec.DstMAC; sp,dp:=spec.SrcPort,spec.DstPort; seq,ack:=clientSeq,serverSeq
		if !up { sip,dip=dip,sip; smac,dmac=dmac,smac; sp,dp=dp,sp; seq,ack=serverSeq,clientSeq }
		proto:=uint8(6); if transport=="udp" { proto=17; flags=0 }
		// 每帧先推进 now，再写入 PacketConfig.Timestamp，保证时间戳严格递增（修复 N2）。
		now = now.Add(time.Duration(stepNanos))
		pc:=core.PacketConfig{FlowID:flowID,PacketIndex:idx,Direction:dir,Timestamp:now,L2:core.L2Config{SrcMAC:smac,DstMAC:dmac,EtherType:core.EtherTypeFor(sip)},L3:core.L3Base(sip,dip,proto,ttl,ipid,spec),L4:core.L4Config{Protocol:transport,SrcPort:sp,DstPort:dp,Seq:seq,Ack:ack,Flags:flags,WindowSize:65535},Payload:payload,Metadata:map[string]interface{}{"group_id":flowID}}
		select { case out<-pc: case <-ctx.Done(): return false }; idx++; ipid++
		if transport=="tcp" { if flags&2!=0 { if up {clientSeq++} else {serverSeq++} }; if flags&1!=0 {if up{clientSeq++}else{serverSeq++}}; if len(payload)>0 {if up{clientSeq+=uint32(len(payload))}else{serverSeq+=uint32(len(payload))}} }
		// 帧间插入 ThinkTime 延时（修复 N1）：仅当不是最后一帧且未取消时延时。
		return true
	}
	handshake:=true; if c.Handshake!=nil {handshake=*c.Handshake}; termination:=true; if c.Termination!=nil {termination=*c.Termination}
	// 统计总帧数以便除最后一帧外都延时。
	totalFrames:=0
	if transport=="tcp"&&handshake { totalFrames+=3 }
	frames,err:=scenarioFrames(c); if err!=nil{return false}; totalFrames+=len(frames)
	if transport=="tcp"&&termination { totalFrames+=4 }
	// emitAll 在每帧后插入 ThinkTime 延时（除最后一帧），返回 false 表示 ctx 取消。
	emitCount:=0
	emitAll:=func(dir string, flags uint8, payload []byte) bool {
		if !emit(dir, flags, payload) { return false }
		emitCount++
		if emitCount<totalFrames { if !sleepStep() { return false } }
		return true
	}
	if transport=="tcp"&&handshake { if !emitAll("up",2,nil)||!emitAll("down",0x12,nil)||!emitAll("up",0x10,nil){return false} }
	udpSeq:=byte(0)
	for _,f:=range frames {
		payload:=f.data
		if transport=="udp" { payload=append([]byte{byte(len(payload))|0x80,udpSeq},payload...); udpSeq++ }
		if !emitAll(f.direction,0x18,payload){return false}
	}
	if transport=="tcp"&&termination { if !emitAll("up",0x11,nil)||!emitAll("down",0x10,nil)||!emitAll("down",0x11,nil)||!emitAll("up",0x10,nil){return false} }
	return true
}
