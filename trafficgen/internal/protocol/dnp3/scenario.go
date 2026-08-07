package dnp3

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type plannedFrame struct { direction string; data []byte }

func scenarioFrames(c *core.DNP3Config) ([]plannedFrame, error) {
	master := c.LinkType != "outstation"
	src,dst:=c.SrcAddr,c.DstAddr
	if src==0&&dst==0 { if master {src,dst=1,1024}else{src,dst=1024,1} }
	build:=func(direction string, control byte, app []byte)(plannedFrame,error){
		fdst,fsrc:=dst,src; if direction=="down" {fdst,fsrc=src,dst}
		b,err:=BuildLinkFrame(control,fdst,fsrc,app); if err!=nil{return plannedFrame{},err}
		if c.MalformedLength!=0 {b[2]=c.MalformedLength}
		if c.MalformedCRC {b[len(b)-1]^=1}
		return plannedFrame{direction,b},nil
	}
	add:=func(frames *[]plannedFrame,direction string,ctrl byte,app []byte) error { f,e:=build(direction,ctrl,app);if e==nil{*frames=append(*frames,f)};return e }
	linkFC:=func(def uint8)uint8{if c.LinkFC!=0{return c.LinkFC};return def}
	fcbToggle := func() bool { fcb := c.LinkFCB == 1; c.LinkFCB ^= 1; return fcb }
	var frames []plannedFrame
	reset:=func()error{if err:=add(&frames,"up",BuildControl(true,true,false,false,linkFC(LinkReset)),nil);err!=nil{return err};return add(&frames,"down",BuildControl(false,false,false,false,LinkReset),nil)}
	ack:=func(direction string)error{return add(&frames,direction,BuildControl(direction=="up",false,false,false,LinkReset),nil)}
	request:=func(fc,seq uint8,objects []core.DNP3Object,con bool)error{
		app,err:=BuildAppFrame(BuildAppControl(true,true,con,seq),fc,0,objects);if err!=nil{return err}
		return add(&frames,"up",BuildControl(true,true,fcbToggle(),true,linkFC(LinkUserConfirm)),app)
	}
	respond:=func(seq uint8,objects []core.DNP3Object)error{
		iin:=effectiveIIN(c);app,err:=BuildAppFrame(BuildAppControl(true,true,false,seq),AppRespond,iin,objects);if err!=nil{return err}
		return add(&frames,"down",BuildControl(false,false,false,false,LinkUserConfirm),app)
	}
	exchange:=func(fc,seq uint8,objects []core.DNP3Object,con bool)error{if err:=request(fc,seq,objects,con);err!=nil{return err};if c.DstAddr==0xFFFF||fc==AppDirectOperateNoAck||fc==AppFreezeNoAck||fc==AppFreezeClearNoAck{return nil};if err:=ack("down");err!=nil{return err};if err:=respond(seq,responseObjects(c,fc,objects));err!=nil{return err};return ack("up")}

	scenario:=c.Scenario
	if scenario=="reset_link" { return frames,reset() }
	if scenario=="read_class0"||scenario=="read_class123" {if err:=reset();err!=nil{return nil,err}}
	objects:=c.Objects
	if len(objects)==0 { objects=defaultObjects(scenario) }
	seq:=c.AppSeq&15
	switch scenario {
	case "read_class0", "read_class123": return frames,exchange(AppRead,seq,objects,false)
	case "write_single": return frames,exchange(AppWrite,seq,objects,false)
	case "select_operate":
		// DNP3 select-then-operate: Select 与 Operate 必须使用相同的 FCB 位，
		// 防止在两次 exchange() 之间 fcbToggle() 翻转 c.LinkFCB 导致 operate FCB 不一致。
		savedFCB := c.LinkFCB
		if err:=exchange(AppSelect,seq,objects,true);err!=nil{return nil,err}
		c.LinkFCB = savedFCB
		return frames,exchange(AppOperate,seq,objects,true)
	case "direct_operate": return frames,exchange(AppDirectOperate,seq,objects,false)
	case "freeze": return frames,exchange(AppFreeze,seq,objects,false)
	case "freeze_clear": return frames,exchange(AppFreezeClear,seq,objects,false)
	case "enable_unsolicited": return frames,exchange(AppEnableUnsolicited,seq,objects,false)
	case "disable_unsolicited": return frames,exchange(AppDisableUnsolicited,seq,objects,false)
	case "assign_class": return frames,exchange(AppAssignClass,seq,objects,false)
	case "delay_measurement": return frames,exchange(AppDelayMeasurement,seq,objects,false)
	case "cold_restart": return frames,exchange(AppColdRestart,seq,objects,false)
	case "warm_restart": return frames,exchange(AppWarmRestart,seq,objects,false)
	case "unsolicited":
		app,err:=BuildAppFrame(BuildAppControl(true,true,true,seq),AppUnsolicitedRespond,effectiveIIN(c),objects);if err!=nil{return nil,err}
		if err=add(&frames,"up",BuildControl(false,false,false,false,LinkUserNoConfirm),app);err!=nil{return nil,err}
		confirm,_:=BuildAppFrame(BuildAppControl(true,true,false,seq),AppConfirm,0,nil)
		return frames,add(&frames,"down",BuildControl(true,true,false,false,LinkUserNoConfirm),confirm)
	case "multi_object_response", "respond":
		return frames,respond(seq,objects)
	case "":
		fc:=AppRead;if c.AppFunc!=""{fc=appFunctions[c.AppFunc]};if c.AppFuncCode!=0{fc=c.AppFuncCode};if c.UnknownFunc{fc=200}
		if isResponse(c){return frames,respond(seq,objects)}
		return frames,exchange(fc,seq,objects,c.AppCON==1)
	default:return nil,fmt.Errorf("dnp3: unsupported scenario %q",scenario)
	}
}

func defaultObjects(s string) []core.DNP3Object {
	switch s {
	case "read_class0": return []core.DNP3Object{{ObjectType:60,Variation:1,Qualifier:6}}
	case "read_class123","enable_unsolicited","disable_unsolicited": return []core.DNP3Object{{ObjectType:60,Variation:2,Qualifier:6},{ObjectType:60,Variation:3,Qualifier:6},{ObjectType:60,Variation:4,Qualifier:6}}
	case "freeze","freeze_clear": return []core.DNP3Object{{ObjectType:20,Variation:1,Qualifier:6}}
	case "delay_measurement": return nil
	}
	return nil
}
func responseObjects(c *core.DNP3Config,fc uint8,in []core.DNP3Object) []core.DNP3Object {
	if c.UnknownObject{return []core.DNP3Object{{ObjectType:255,Variation:0,Qualifier:6}}}
	if fc==AppDelayMeasurement{return []core.DNP3Object{{ObjectType:52,Variation:2,Qualifier:7,Count:1,Points:[]core.DNP3Point{{Value:1}}}}}
	if fc==AppColdRestart||fc==AppWarmRestart{return []core.DNP3Object{{ObjectType:51,Variation:1,Qualifier:7,Count:1,Points:[]core.DNP3Point{{Value:1}}}}}
	if fc==AppRead{return nil};return in
}
func effectiveIIN(c *core.DNP3Config) uint16 {
	i:=c.IIN;if c.IINBroadcast{i|=0x8000};if c.IINClass1{i|=0x4000};if c.IINClass2{i|=0x2000};if c.IINClass3{i|=0x1000};if c.IINNeedTime{i|=0x0800};if c.IINLocalControl{i|=0x0400};if c.IINDeviceTrouble{i|=0x0200};if c.IINDeviceRestart{i|=0x0100};if c.IINConfigCorrupt{i|=0x80};if c.IINFuncNotSupported||c.UnknownFunc{i|=0x40};if c.IINObjectUnknown||c.UnknownObject{i|=0x20};if c.IINParameterError{i|=0x10};if c.IINEventBufferOverflow{i|=0x08};if c.IINAlreadyExecuting{i|=0x04};return i
}
