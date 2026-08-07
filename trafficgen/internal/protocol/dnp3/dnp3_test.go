package dnp3

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestCRC16KnownVectors(t *testing.T) {
	for _, tc := range []struct{ in []byte; want uint16 }{{nil,0xFFFF},{[]byte{0},0xFFFF},{[]byte("123456789"),0xEA82}} {
		if got:=CRC16(tc.in);got!=tc.want{t.Fatalf("CRC16(%x)=0x%04X want 0x%04X",tc.in,got,tc.want)}
	}
}
func TestBuildLinkFrameResetAndParse(t *testing.T) {
	f,err:=BuildLinkFrame(0xC0,1024,1,nil);if err!=nil{t.Fatal(err)}
	if len(f)!=10||!bytes.Equal(f[:8],[]byte{5,0x64,0,0xC0,0,4,1,0}){t.Fatalf("frame=% X",f)}
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
func TestValidate(t *testing.T) {
	p:=NewPlanner();if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{}});err!=nil{t.Fatal(err)}
	if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{LinkType:"slave"}});err==nil{t.Fatal("expected invalid link type")}
	if err:=p.Validate(core.FlowSpec{DNP3:&core.DNP3Config{DstAddr:0xFFFF,ConfirmRequired:true}});err==nil{t.Fatal("expected broadcast error")}
}
func TestPlanResetLink(t *testing.T) {
	p:=NewPlanner();ch,err:=p.Plan(context.Background(),core.FlowSpec{SrcIP:"10.0.0.1",DstIP:"10.0.0.2",SrcPort:5000,DNP3:&core.DNP3Config{Scenario:"reset_link"}});if err!=nil{t.Fatal(err)}
	var packets []core.PacketConfig;for pc:=range ch{packets=append(packets,pc)}
	if len(packets)!=9{t.Fatalf("packet count=%d",len(packets))};if !bytes.Equal(packets[3].Payload[:8],[]byte{5,0x64,0,0xC0,0,4,1,0}){t.Fatalf("reset=% X",packets[3].Payload)}
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
