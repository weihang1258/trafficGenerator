package dnp3

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestCRC16KnownVectors(t *testing.T) {
	for _, tc := range []struct{ in []byte; want uint16 }{{nil,0xFFFF},{[]byte{0},0xFFFF},{[]byte("123456789"),0xEA82}} {
		if got:=CRC16(tc.in);got!=tc.want{t.Fatalf("CRC16(%x)=0x%04X want 0x%04X",tc.in,got,tc.want)}
	}
}
// TestBuildLinkFrameResetAndParse verifies the reset link frame carries a
// non-empty user data block: IEEE 1815 requires Length >= 5 (>=1 data byte +
// 2-byte CRC), and Wireshark flags Length<5 as malformed. Real reset frames
// carry 3 zero bytes (opendnp3 convention).
func TestBuildLinkFrameResetAndParse(t *testing.T) {
	f,err:=BuildLinkFrame(0xC0,1024,1,[]byte{0,0,0});if err!=nil{t.Fatal(err)}
	if len(f)!=15||f[2]!=5||!bytes.Equal(f[:8],[]byte{5,0x64,5,0xC0,0,4,1,0}){t.Fatalf("frame=% X",f)}
	p,err:=ParseLinkFrame(f);if err!=nil{t.Fatal(err)};if p.DstAddr!=1024||p.SrcAddr!=1{t.Fatalf("addresses=%d/%d",p.DstAddr,p.SrcAddr)}
}
func TestBuildLinkFrameBlockIndependence(t *testing.T) {
	data:=append(make([]byte,16),0xFF);f,err:=BuildLinkFrame(0xC3,1024,1,data);if err!=nil{t.Fatal(err)}
	if f[2]!=21||!bytes.Equal(f[26:28],[]byte{0xFF,0xFF})||!bytes.Equal(f[29:31],[]byte{0xCA,0xED}){t.Fatalf("blocks=% X",f[10:])}
}
func TestBuildAppFrameReadClass123(t *testing.T) {
	objs:=[]core.DNP3Object{{ObjectType:60,Variation:2,Qualifier:6},{ObjectType:60,Variation:3,Qualifier:6},{ObjectType:60,Variation:4,Qualifier:6}}
	got,err:=BuildAppFrame(0xC2,AppRead,0,objs);if err!=nil{t.Fatal(err)}
	want:=[]byte{0xC2,1,0x3C,2,6,0x3C,3,6,0x3C,4,6};if !bytes.Equal(got,want){t.Fatalf("got % X",got)}
}
func TestBuildAppFrameCROB(t *testing.T) {
	o:=core.DNP3Object{ObjectType:12,Variation:1,Qualifier:0,IndexRange:[2]uint16{5,5},Points:[]core.DNP3Point{{Value:3}}}
	got,err:=BuildAppFrame(0xC3,AppSelect,0,[]core.DNP3Object{o});if err!=nil{t.Fatal(err)}
	want:=[]byte{0xC3,3,12,1,0,5,5,3,1,100,0,0xFF,0xFF};if !bytes.Equal(got,want){t.Fatalf("got % X",got)}
}
// TestAppFunctionCodesIEEE1815 pins the application-layer function codes to
// IEEE 1815-2012 values. A prior version had them inverted (13=respond,
// 129=cold restart), which real outstations read as the wrong function.
func TestAppFunctionCodesIEEE1815(t *testing.T) {
	want := map[uint8]uint8{
		AppRespond: 0x81, AppUnsolicitedRespond: 0x82, AppConfirm: 0x00,
		AppColdRestart: 0x0D, AppWarmRestart: 0x0E,
	}
	for fc, wantVal := range want {
		if fc != wantVal {
			t.Errorf("App FC value mismatch: got 0x%02X want 0x%02X", fc, wantVal)
		}
	}
}
func TestValidate(t *testing.T) {
	p:=NewPlanner();if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{}});err!=nil{t.Fatal(err)}
	if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{LinkType:"slave"}});err==nil{t.Fatal("expected invalid link type")}
	if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{DstAddr:0xFFFF,ConfirmRequired:true}});err==nil{t.Fatal("expected broadcast error")}
}
func TestPlanResetLink(t *testing.T) {
	p:=NewPlanner();ch,err:=p.Plan(context.Background(),core.FlowSpec{SrcIP:"10.0.0.1",DstIP:"10.0.0.2",SrcPort:5000,DNP3:&core.DNP3Config{Scenario:"reset_link"}});if err!=nil{t.Fatal(err)}
	var packets []core.PacketConfig;for pc:=range ch{packets=append(packets,pc)}
	if len(packets)!=9{t.Fatalf("packet count=%d",len(packets))}
	// reset 帧 Length=6（4 字节全零用户数据 + CRC）：Wireshark dissector
	// 对走 transport 路径的功能码要求 Length>=6（data_len = dl_len-5），
	// reset 本身跳过解析但统一走 padApp 保证所有帧 >=6。
	if !bytes.Equal(packets[3].Payload[:8],[]byte{5,0x64,6,0xC0,0,4,1,0}){t.Fatalf("reset=% X",packets[3].Payload)}
}
func TestPlanUDP(t *testing.T) {
	ch,err:=NewPlanner().Plan(context.Background(),core.FlowSpec{SrcIP:"10.0.0.1",DstIP:"10.0.0.2",DNP3:&core.DNP3Config{Transport:"udp",Scenario:"reset_link"}});if err!=nil{t.Fatal(err)}
	var n int;for pc:=range ch{n++;if pc.L4.Protocol!="udp"||len(pc.Payload)<12||pc.Payload[0]&0x80==0{t.Fatalf("packet=%+v",pc)}};if n!=2{t.Fatalf("count=%d",n)}
}
func TestIINBits(t *testing.T) {
	c:=&core.DNP3Config{IINClass1:true,IINNeedTime:true,IINObjectUnknown:true};if got:=effectiveIIN(c);got!=0x4820{t.Fatalf("IIN=0x%04X",got)}
}

// N2 修复验证：ThinkTime=0 时每帧 Timestamp 仍严格递增（≥1µs 步进）。
func TestPlanTimestampMonotonicEvenWhenThinkTimeZero(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5000, DstPort: 5001,
		DNP3: &core.DNP3Config{Scenario: "reset_link"}, // ThinkTime 默认 0
	})
	if err != nil { t.Fatal(err) }
	var prev time.Time
	n := 0
	for pc := range ch {
		if n > 0 {
			if !pc.Timestamp.After(prev) {
				t.Fatalf("frame %d Timestamp %v not strictly after prev %v", n, pc.Timestamp, prev)
			}
			// 步进至少 1µs
			if pc.Timestamp.Sub(prev) < time.Microsecond {
				t.Fatalf("frame %d step=%v < 1µs", n, pc.Timestamp.Sub(prev))
			}
		}
		prev = pc.Timestamp
		n++
	}
	if n == 0 { t.Fatal("no packets emitted") }
}

// N1 修复验证：ThinkTime>0 时帧间产生实际延时。
// 用 50ms ThinkTime + 已取消 ctx（deadline 在 200ms 内），预期收到 ≤3 帧就被取消。
func TestPlanThinkTimeDelaysEmission(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	ch, err := p.Plan(ctx, core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5000, DstPort: 5001,
		DNP3: &core.DNP3Config{Scenario: "reset_link", ThinkTime: 50}, // 每帧 50ms 延时
	})
	if err != nil { t.Fatal(err) }
	var got int
	for range ch { got++ }
	// 9 帧理论耗时 ≈ 8*50ms=400ms > 200ms 超时，必被 ctx 取消。
	if got >= 9 { t.Fatalf("ThinkTime did not delay: got %d/9 packets in 200ms", got) }
	if got < 2 { t.Fatalf("expected partial progress before timeout, got %d", got) }
}

// N3 修复验证：select_operate 中 Select 与 Operate 请求帧使用相同的 FCB 位。
func TestSelectOperatePreservesFCBBit(t *testing.T) {
	c := &core.DNP3Config{Scenario: "select_operate", LinkFCB: 0,
		Objects: []core.DNP3Object{{ObjectType: 12, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{0, 0}, Points: []core.DNP3Point{{Value: 1}}}}}
	frames, err := scenarioFrames(c)
	if err != nil { t.Fatal(err) }
	var selectFCB, operateFCB *bool
	for _, f := range frames {
		dir := f.direction
		if dir != "up" { continue }
		if len(f.data) < 12 { continue }
		ctrl := f.data[3]
		fcb := (ctrl & 0x20) != 0
		// ASDU 紧跟 link header (10B)，起始 [10]=app control [11]=app FC
		fc := f.data[11]
		switch fc {
		case AppSelect:
			selectFCB = &fcb
		case AppOperate:
			operateFCB = &fcb
		}
	}
	if selectFCB == nil || operateFCB == nil { t.Fatalf("did not observe both select and operate requests (select=%v operate=%v)", selectFCB, operateFCB) }
	if *selectFCB != *operateFCB {
		t.Fatalf("select FCB(%v) != operate FCB(%v); spec says they MUST match", *selectFCB, *operateFCB)
	}
}

// N6 修复验证：encodePoint 通过索引 n 而非 &p 地址比较，确保 Points[0..n-1] 的 flag 取自对应位置。
// 若仍用 &p 比较，由于 range 变量地址逃逸不可靠，flag 会被错填。
func TestEncodePointIndexBased(t *testing.T) {
	// Object 30 (Analog Input Event) Variation 2，需要 flag 字节。
	flags := []uint8{0x01, 0x02, 0x03}
	objs := []core.DNP3Object{{ObjectType: 30, Variation: 2, Qualifier: 7, Count: 3,
		Points: []core.DNP3Point{{Index: 0, Value: 10}, {Index: 1, Value: 20}, {Index: 2, Value: 30}}, Flags: flags}}
	got, err := BuildAppFrame(0xC0, AppRead, 0, objs)
	if err != nil { t.Fatal(err) }
	// 期望 flag 在每个 16-bit value 前：01 0A00, 02 1400, 03 1E00
	want := []byte{0xC0, AppRead, 30, 2, 7, 3, 0x01, 0x0A, 0x00, 0x02, 0x14, 0x00, 0x03, 0x1E, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X want % X", got, want)
	}
}

// 设计文档 §7.6.5 T69：qualifier 0x00 + IndexRange 超出单字节范围时，
// encodeObject 的 "qualifier 0x00 index exceeds 255" 错误被 planFlow 的
// scenarioFrames err 吞掉（dnp3.go:113 return false），任务 0 包完成。
// Validate 必须先拒绝该配置，让错误经 worker.go planner.Validate 传播。
func TestValidateQualifier0IndexRangeTooLarge(t *testing.T) {
	p := NewPlanner()
	o := core.DNP3Object{ObjectType: 12, Variation: 1, Qualifier: 0x00, IndexRange: [2]uint16{300, 300}}
	err := p.Validate(core.FlowSpec{DNP3: &core.DNP3Config{Objects: []core.DNP3Object{o}}})
	if err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("Validate = %v, want error containing \"index\"", err)
	}
	// Plan 必须同步拒绝（错误传播到任务失败而非 0 包完成）。
	if _, err := p.Plan(context.Background(), core.FlowSpec{DNP3: &core.DNP3Config{Objects: []core.DNP3Object{o}}}); err == nil {
		t.Fatal("Plan accepted qualifier-0x00 index > 255")
	}
}

// 设计文档 §7.6.5 T69（变体）：qualifier 0x17（8-bit 索引前缀）下
// 点索引超出 255 会被 encodePoints 静默截断（uint16→byte），
// Validate 必须拒绝。
func TestValidateQualifier17PointIndexTooLarge(t *testing.T) {
	p := NewPlanner()
	o := core.DNP3Object{ObjectType: 1, Variation: 1, Qualifier: 0x17, Count: 1,
		Points: []core.DNP3Point{{Index: 300, Value: 1}}}
	err := p.Validate(core.FlowSpec{DNP3: &core.DNP3Config{Objects: []core.DNP3Object{o}}})
	if err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("Validate = %v, want error containing \"index\"", err)
	}
	if _, err := p.Plan(context.Background(), core.FlowSpec{DNP3: &core.DNP3Config{Objects: []core.DNP3Object{o}}}); err == nil {
		t.Fatal("Plan accepted qualifier-0x17 point index > 255")
	}
}

// 设计文档 §7.6.5 T66：CROB（Object 12.1）请求不得携带 Status 字段
// （Status 是响应回显字段）。当前 encodePoint 对请求固定输出 6B 并静默
// 丢弃 Points.Status，Validate 必须拒绝。
func TestValidateCROBRequestStatusRejected(t *testing.T) {
	p := NewPlanner()
	status := uint8(0)
	o := core.DNP3Object{ObjectType: 12, Variation: 1, Qualifier: 0x00, IndexRange: [2]uint16{5, 5},
		Points: []core.DNP3Point{{Value: 3, Status: &status}}}
	for _, scenario := range []string{"select_operate", "direct_operate"} {
		err := p.Validate(core.FlowSpec{DNP3: &core.DNP3Config{Scenario: scenario, Objects: []core.DNP3Object{o}}})
		if err == nil || !strings.Contains(err.Error(), "Status") {
			t.Fatalf("scenario %s: Validate = %v, want error containing \"Status\"", scenario, err)
		}
	}
	// 响应（respond 场景）携带 Status 是合法回显（T68），不得误杀。
	ok := p.Validate(core.FlowSpec{DNP3: &core.DNP3Config{Scenario: "respond", Objects: []core.DNP3Object{o}}})
	if ok != nil {
		t.Fatalf("respond with Status=0 must be accepted, got %v", ok)
	}
}

// 设计文档 §7.6.5 T66（encode 层）：响应帧 CROB 必须输出 7B（含 Status=0x00）。
func TestBuildAppFrameCROBResponseStatus(t *testing.T) {
	status := uint8(0)
	o := core.DNP3Object{ObjectType: 12, Variation: 1, Qualifier: 0x00, IndexRange: [2]uint16{5, 5},
		Points: []core.DNP3Point{{Value: 3, Status: &status}}}
	got, err := BuildAppFrame(0xC3, AppRespond, 0, []core.DNP3Object{o})
	if err != nil { t.Fatal(err) }
	// C3 81 <IIN 2B> 0C 01 00 05 05 03 01 64 00 FF FF 00 (T68)。
	// AppRespond=0x81 per IEEE 1815-2012（设计文档 §7.6.5 T68 行的 0x0D 是
	// 早期 App-FC 颠倒 bug 的残留值，wire 正确值见 §7.6.11 与审计修复）。
	want := []byte{0xC3, AppRespond, 0x00, 0x00, 12, 1, 0x00, 5, 5, 3, 1, 100, 0, 0xFF, 0xFF, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X want % X", got, want)
	}
	// 显式 Status=7（设备损坏）必须回显，而非固定 0（T66 的字段级语义）。
	status7 := uint8(7)
	o.Points[0].Status = &status7
	got2, err := BuildAppFrame(0xC3, AppRespond, 0, []core.DNP3Object{o})
	if err != nil { t.Fatal(err) }
	if len(got2) != 16 || got2[15] != 7 {
		t.Fatalf("explicit Status=7 not echoed: got % X", got2)
	}
}

// T44 regression: malformed_length=0 must FORCE the Length byte to 0x00
// (nil pointer = no override; explicit 0 = force zero). A uint8 zero value
// made the override dead code and the case silently emitted valid frames.
func TestMalformedLengthZeroForcesLengthByte(t *testing.T) {
	zero := uint8(0)
	five := uint8(5)
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		DNP3: &core.DNP3Config{Scenario: "read_class0", MalformedLength: &zero},
	})
	if err != nil { t.Fatal(err) }
	var reset []byte
	for pc := range ch {
		if len(pc.Payload) > 10 && pc.Payload[0] == 0x05 && pc.Payload[1] == 0x64 && pc.Payload[3] == 0xC0 {
			reset = pc.Payload
			break
		}
	}
	if reset == nil { t.Fatal("no reset link frame emitted") }
	if reset[2] != 0 { t.Fatalf("Length byte = %d, want 0 (forced)", reset[2]) }
	// Control case: no override -> Length reflects real payload (>= 5).
	ch2, _ := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		DNP3: &core.DNP3Config{Scenario: "read_class0", MalformedLength: &five},
	})
	var reset2 []byte
	for pc := range ch2 {
		if len(pc.Payload) > 10 && pc.Payload[0] == 0x05 && pc.Payload[1] == 0x64 && pc.Payload[3] == 0xC0 {
			reset2 = pc.Payload
			break
		}
	}
	if reset2 == nil { t.Fatal("no reset frame (control)") }
	if reset2[2] != 5 { t.Fatalf("Length byte = %d, want 5 (override value)", reset2[2]) }
}

// T26/T46/T25/T39 深度审计修复：走 transport 解析路径的 User Data 帧
// （link func 0x02/0x03/0x04）数据区必须 >= 4B（tr 1B + app >= 3B），
// 否则 Wireshark dissector 的 data_len = dl_len - 5 得到 0 字节数据区，
// 对空 AL tvb 抛 "Malformed Packet: DNP 3.0"。
func TestUserDataFramesHaveMinLength6(t *testing.T) {
	cases := []struct {
		name string
		c    *core.DNP3Config
	}{
		{"cold_restart", &core.DNP3Config{Scenario: "cold_restart", LinkType: "master", SrcAddr: 1, DstAddr: 1024}},
		{"unknown_func", &core.DNP3Config{Scenario: "", AppFuncCode: 200, UnknownFunc: true, LinkType: "master", SrcAddr: 1, DstAddr: 1024}},
		{"unsolicited", &core.DNP3Config{Scenario: "unsolicited", LinkType: "outstation", SrcAddr: 1024, DstAddr: 1}},
		{"test_link", &core.DNP3Config{Scenario: "reset_link", LinkFC: LinkStatus, LinkType: "master", SrcAddr: 1, DstAddr: 1024}},
	}
	for _, tc := range cases {
		frames, err := scenarioFrames(tc.c)
		if err != nil { t.Fatalf("%s: %v", tc.name, err) }
		var userData int
		for _, f := range frames {
			if len(f.data) < 10 { continue }
			ln := int(f.data[2])
			funcCode := f.data[3] & 0x0F
			// 只有走 transport 解析路径的功能码才要求 Length>=6。
			if funcCode == 0x00 || funcCode == 0x09 || funcCode == 0x0B { continue }
			userData++
			if ln < 6 {
				t.Fatalf("%s: user-data frame ctrl=0x%02X length=%d < 6 (data=%dB); Wireshark reports malformed for Length<6",
					tc.name, f.data[3], ln, len(f.data)-10)
			}
		}
		if userData == 0 { t.Fatalf("%s: expected at least one user-data frame", tc.name) }
	}
}
