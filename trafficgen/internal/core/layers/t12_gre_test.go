// T12 集成测试（P2e）：隧道层内层委托（18 号文档 §13.3 T12 = §9.2/§12.3）。
// gre+http 链 [ip → gre → ip → tcp → http]（补全自 {"gre":{}}+{"http":{}}，
// §12.3）经 BuildLayersPlanner → ChainPlanner 驱动 → 真实 core.Builder 序列化：
// 外层帧必须携带 GRE 头（builder validateGREConfig 要求 L3.Protocol=47 且
// L4 为空），内层必须是完整 IP 包，最内层是逐字节正确的 HTTP 请求。
//
// 与 T11 的 engine 级不同，这里用同一 Builder 直接序列化 Plan 的 PacketConfig
// ——T11 已证明 engine 流水线把 PacketConfig 字节写进 writer，隧道链只需验证
// 字节内容本身（外层 GRE 语义 + 内层委托正确），不用再启动 engine。
package layers_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gre"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
)

// greHTTPChainSpec is the shared T12 spec: outer tunnel endpoints
// (spec.SrcIP/DstIP, also the inner addresses via GREConfig defaults)。
func greHTTPChainSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 8080,
		Count: 1,
	}
}

// buildGREChain builds the T12 chain planner and runs the full Plan →
// serialization pipeline, returning the wire frames.
func buildGREChain(t *testing.T, layersJSON string) [][]byte {
	t.Helper()
	p, err := layers.BuildLayersPlanner("gre", json.RawMessage(layersJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), greHTTPChainSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("gre chain produced 0 packets (silent empty flow)")
	}
	b := core.NewBuilder()
	frames := make([][]byte, len(pkts))
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v", i, err)
		}
		frames[i] = f
	}
	return frames
}

// TestT12_GREChainCompletesAndDrives: gre+http 补全必须产出双层 ip 链
// [ip → gre → ip → tcp → http]（§12.3），且驱动不报错、每包经真实 builder
// 序列化成功（builder 的 validateGREConfig 会拒绝 L3.Protocol≠47 或 L4 非空
// 的包——若驱动未把 GRE 语义落到 PacketConfig，序列化在此失败）。
func TestT12_GREChainCompletesAndDrives(t *testing.T) {
	p, err := layers.BuildLayersPlanner("gre", json.RawMessage(`[{"gre":{}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// 补全正确性：ChainPlanner 持内链 [ip, gre, ip, tcp, http]（gre 在外层 ip
	// 之内、内层 ip 之上；§12.3 双层 ip 各司其职）。若外层 ip 缺失，Builder
	// 序列化会失败（L3.Protocol=47 要求外层 ip）；若内层 ip 缺失，内层字节
	// 不是完整 IP 包（T12 字节断言将失败）——链结构错误在此即暴露。
	ch, err := p.Plan(context.Background(), greHTTPChainSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("gre chain produced 0 packets (silent empty flow)")
	}
	b := core.NewBuilder()
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v (outer L3 protocol must be 47 and L4 empty for GRE)", i, err)
		}
		if f == nil {
			t.Fatalf("packet %d built nil frame", i)
		}
	}
}

// TestT12_GREOuterAndInnerBytes: 外层帧结构（eth+outer-ip proto 47+GRE 头）
// 与内层委托字节（完整内层 IP 包 → TCP 握手 → HTTP 报文，字段级断言）。
func TestT12_GREOuterAndInnerBytes(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{}},{"http":{}}]`)
	// 完整 HTTP 事务 = 3 握手 + 请求段 + 响应段 + 4 挥手 = 9 段，每段一外层帧。
	if len(frames) < 9 {
		t.Fatalf("gre chain produced %d frames, want >= 9 (3-way handshake + request + response + teardown)", len(frames))
	}
	// 首帧：外层 SYN。
	f0 := frames[0]
	if len(f0) < 14+20+4+20 {
		t.Fatalf("first frame too short: %d bytes (< eth14+ip20+gre4+tcp20)", len(f0))
	}
	// 外层 L2/L3。
	if got := be(f0, 12, 2); got != core.EtherTypeIPv4 {
		t.Errorf("eth ethertype = %#04x, want 0x0800", got)
	}
	if got := f0[23]; got != core.ProtocolGRE {
		t.Errorf("outer ip protocol = %d, want 47 (IPPROTO_GRE)", got)
	}
	if got := be(f0, 30, 4); got != 0x0a000002 {
		t.Errorf("outer ip dst = %#08x, want 10.0.0.2 (tunnel endpoint)", got)
	}
	// GRE 头（outer ip 20B 后）：flags 0x0000（无 K/C/S/R 位）+ proto 0x0800。
	if got := be(f0, 34, 2); got != 0x0000 {
		t.Errorf("gre flags = %#04x, want 0 (no options)", got)
	}
	if got := be(f0, 36, 2); got != core.EtherTypeIPv4 {
		t.Errorf("gre protocol type = %#04x, want 0x0800 (inner IPv4)", got)
	}
	// 内层 IP（GRE 头 4B 后 = 偏移 38）：ver/ihl 0x45、proto 6（TCP）、
	// src 10.0.0.1 → dst 10.0.0.2（GREConfig 空 = spec 地址）。
	if got := f0[38] >> 4; got != 4 {
		t.Errorf("inner ip version = %d, want 4", got)
	}
	if got := f0[38] & 0x0f; got != 5 {
		t.Errorf("inner ihl = %d, want 5", got)
	}
	if got := f0[47]; got != 6 {
		t.Errorf("inner ip protocol = %d, want 6 (tcp)", got)
	}
	if got := be(f0, 50, 4); got != 0x0a000001 {
		t.Errorf("inner ip src = %#08x, want 10.0.0.1", got)
	}
	if got := be(f0, 54, 4); got != 0x0a000002 {
		t.Errorf("inner ip dst = %#08x, want 10.0.0.2", got)
	}
	// 内层 TCP（内层 ip 20B 后 = 偏移 58）：SYN，src 40000 → dst 8080。
	if got := be(f0, 58, 2); got != 40000 {
		t.Errorf("inner tcp src port = %d, want 40000", got)
	}
	if got := be(f0, 60, 2); got != 8080 {
		t.Errorf("inner tcp dst port = %d, want 8080", got)
	}
	if f0[71]&0x02 == 0 {
		t.Errorf("inner tcp flags = %#02x, want SYN set", f0[71])
	}
	// 内层 IP 校验和必须有效（legacy gre planner 的 buildInnerIPv4Packet 计算
	// 真实校验和；链驱动若跳过它，内层包被对端丢弃——委托字节必须完整）。
	// 头 20B 从偏移 38 起：版本/IHL、总长、IPID、flags/offset、TTL、proto、
	// 校验和、src、dst。校验和字段在 48:50（= 38+10）。
	if got := ipChecksum16(f0[38:58]); got != 0 {
		t.Errorf("inner ip header checksum = %#04x, want 0 (valid, RFC 791 §3.1)", got)
	}
	// 内层 TCP 校验和（RFC 793 pseudo-header 覆盖内层 ip src/dst + tcp 段）。
	innerTCP := f0[58:]
	if got := tcpChecksum(innerTCP, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}); got != 0 {
		t.Errorf("inner tcp checksum = %#04x, want 0 (valid, RFC 793)", got)
	}
}

// TestT12_GREHTTPInnerMessage: 内层 HTTP 报文段字节必须与 legacy http 一致
// （GET / HTTP/1.1 请求 + HTTP/1.1 响应，§9.2 内层委托）。HTTP 段 = eth14 +
// outer ip 20 + gre 4 + inner ip 20 + tcp 20 = 78B 起。
func TestT12_GREHTTPInnerMessage(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{}},{"http":{}}]`)
	if len(frames) < 9 {
		t.Fatalf("gre chain produced %d frames, want >= 9", len(frames))
	}
	// 内层 HTTP 段偏移（78B，见测试头注释）；数据段经 MSS 分段，最长 1460B。
	innerOff := 14 + 20 + 4 + 20 + 20
	foundReq, foundResp := false, false
	for _, f := range frames {
		if len(f) < innerOff+4 {
			continue
		}
		// 内层 tcp src port（58:60）。请求段上行（40000），响应段下行（8080）。
		sp := be(f, 58, 2)
		inner := f[innerOff:]
		if sp == 40000 && len(inner) >= 16 && string(inner[:16]) == "GET / HTTP/1.1\r\n" {
			foundReq = true
		}
		if sp == 8080 && len(inner) >= 9 && string(inner[:9]) == "HTTP/1.1 " {
			foundResp = true
		}
	}
	if !foundReq {
		t.Error("no inner HTTP GET request segment found (inner http bytes never emitted)")
	}
	if !foundResp {
		t.Error("no inner HTTP/1.1 response segment found (inner http bytes never emitted)")
	}
}

// TestT12_GREKeyOptionAndSequence: gre 层 config 的 key/checksum/sequence 必须
// 落到 GRE 头字节（schema 字段 §4.4；T12 规格 §12.3 示例 {"gre":{"key":100}}）。
func TestT12_GREKeyOptionAndSequence(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{"key":100,"checksum":true,"sequence":true}},{"http":{}}]`)
	if len(frames) < 1 {
		t.Fatal("gre chain produced 0 frames")
	}
	f0 := frames[0]
	if len(f0) < 14+20+16 {
		t.Fatalf("first frame too short: %d bytes (< eth14+ip20+gre16)", len(f0))
	}
	// flags = C|K|S = 0x8000|0x2000|0x1000 = 0xb000；proto 0x0800。
	if got := be(f0, 34, 2); got != 0xb000 {
		t.Errorf("gre flags = %#04x, want 0xb000 (C|K|S)", got)
	}
	// 头布局（RFC 2890）：base4 + C 4（checksum+reserved）+ K 4 + S 4 = 16B。
	if got := be(f0, 42, 4); got != 100 {
		t.Errorf("gre key = %d, want 100 (layer config key lost)", got)
	}
	// Checksum 域在 K 之前（偏移 38:42，checksum 38:40 + reserved 40:42），
	// 校验和计算覆盖 GRE 头 + 内层负载（RFC 2784 §3.1）：C 位置位时不得为 0。
	if got := be(f0, 38, 2); got == 0 {
		t.Errorf("gre checksum field = 0, want computed nonzero (RFC 2784 §3.1)")
	}
	// S 域在 K 之后（偏移 46:50）：首帧 sequence = 0（base 0 + frame 0），
	// 第二帧 = 1（legacy gre planner cfg.Sequence + i 语义）。
	if got := be(f0, 46, 4); got != 0 {
		t.Errorf("gre sequence = %d, want 0 (first frame from base 0)", got)
	}
	if len(frames) < 2 {
		t.Fatal("want >= 2 frames for sequence increment check")
	}
	if got := be(frames[1], 46, 4); got != 1 {
		t.Errorf("gre sequence frame 2 = %d, want 1 (per-frame increment)", got)
	}
}

// TestT12_GRELayerConfigKeyThroughPipeline: {"gre":{"key":100}} 的 key 必须
// 从层 config 翻译到每帧的 GRE 头（P2c-3 同款断言：层 config 不得丢失）。
func TestT12_GRELayerConfigKeyThroughPipeline(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{"key":100}},{"http":{}}]`)
	if len(frames) < 1 {
		t.Fatal("gre chain produced 0 frames")
	}
	// K 位（0x2000）置位 → key 域在 base4 之后（偏移 34+4=38）。
	f0 := frames[0]
	if got := be(f0, 34, 2); got&0x2000 == 0 {
		t.Fatalf("gre flags = %#04x, want K bit set", got)
	}
	if got := be(f0, 38, 4); got != 100 {
		t.Errorf("gre key = %d, want 100 (layer config key lost)", got)
	}
}

// TestT12_GREChainValidateAndUnknownFields: 隧道链的校验面——协议级校验
// （spec.GRE 空：策略含 gre 层但 spec.GRE 为 nil 时驱动仍产出默认 GRE 头，
// 校验不报错）+ 未知层字段（V9）必须拒绝（{"gre":{"bogus":1}}）。
func TestT12_GREChainValidateAndUnknownFields(t *testing.T) {
	// 未知字段 V9 拒绝（schema 只认 key/checksum/sequence）。
	if _, err := layers.BuildLayersPlanner("gre", json.RawMessage(`[{"gre":{"bogus":1}},{"http":{}}]`)); err == nil {
		t.Error("BuildLayersPlanner accepted unknown gre layer field (want V9 rejection)")
	}
	// 已知字段合法 + spec.GRE 为 nil（flat 未配 gre）：校验通过、驱动出包。
	p, err := layers.BuildLayersPlanner("gre", json.RawMessage(`[{"gre":{"key":7}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(greHTTPChainSpec()); err != nil {
		t.Fatalf("Validate: %v (gre chain with spec.GRE nil must validate)", err)
	}
	frames := buildGREChain(t, `[{"gre":{"key":7}},{"http":{}}]`)
	if len(frames) == 0 {
		t.Fatal("gre chain produced 0 frames")
	}
	if got := be(frames[0], 34, 2); got&0x2000 == 0 {
		t.Fatalf("gre flags = %#04x, want K bit set (key 7)", got)
	}
	if got := be(frames[0], 38, 4); got != 7 {
		t.Errorf("gre key = %d, want 7", got)
	}
}

// TestT12_GREInnerErrorPropagates: 内层 IPv6 必须**同步拒绝**（review HIGH-2）。
// drive 的运行时错误按既有契约静默吞掉（Plan goroutine 报错 → 空流），而
// IPv6-over-GRE 是**结构性**错误（GREGenerator 只支持 IPv4 内层，To4 检查；
// builder writeGRE 的 ProtocolType 0x0800 即内层裸 IPv4）——结构性错误必须在
// Validate/Plan 同步报错（与生成器不可实例化、事件接线配错同款先例，
// chain_planner.go:266-270），否则调用方拿到 0 包空流而非明确错误。
func TestT12_GREInnerErrorPropagates(t *testing.T) {
	// spec 内层 IPv6（outer 也 v6 才能通过 validateSpecBase 的版本一致性检查）
	// → 隧道链校验必须报错（IPv6-over-GRE 不支持）。
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcPort: 40000, DstPort: 8080,
		Count: 1,
	}
	p, err := layers.BuildLayersPlanner("gre", json.RawMessage(`[{"gre":{}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// Plan 与 Validate 双路径必须同步拒绝（failing-test-first：当前实现
	// Validate 通过 + Plan 返回空流，此测试先失败）。
	if err := p.Validate(spec); err == nil {
		t.Error("Validate: IPv6-over-GRE chain accepted, want sync rejection (inner addresses must be IPv4)")
	}
	if ch, err := p.Plan(context.Background(), spec); err == nil {
		// Plan 通过了（不应发生）——但即使走了，也必须不得静默空流。
		for range ch {
		}
		t.Error("Plan: IPv6-over-GRE chain accepted, want sync rejection (drive must not swallow as empty flow)")
	}
	// 空地址同样必须拒绝（review MEDIUM：spec 空 → applySpecToChain 删除 ip 层
	// src/dst → 内层无地址，合法"legacy 默认"在链路径不存在——链路径没有
	// schema 默认回退）。
	empty := core.FlowSpec{SrcPort: 40000, DstPort: 8080, Count: 1}
	if err := p.Validate(empty); err == nil {
		t.Error("Validate: gre chain with empty src/dst accepted, want sync rejection (no inner addresses)")
	}
}

// TestT12_GREOuterDownFrame: down 方向帧（SYN-ACK）的内层/外层地址交换 +
// 内层校验和（review GRE-wire E：三段交互——GREGenerator 内层交换 → 外层
// ip 覆盖 → finalEmit down 交换——必须逐字节锁定）。
func TestT12_GREOuterDownFrame(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{}},{"http":{}}]`)
	if len(frames) < 2 {
		t.Fatalf("gre chain produced %d frames, want >= 2 (up SYN + down SYN-ACK)", len(frames))
	}
	f1 := frames[1]
	// 外层：eth14 + outer ip20，down 交换后 outer src=10.0.0.2/dst=10.0.0.1
	//（finalEmit down swap；tunnel 端点镜像）。
	if got := be(f1, 26, 4); got != 0x0a000002 {
		t.Errorf("outer ip src = %#08x, want 10.0.0.2 (down: src mirrored to dst endpoint)", got)
	}
	if got := be(f1, 30, 4); got != 0x0a000001 {
		t.Errorf("outer ip dst = %#08x, want 10.0.0.1 (down: dst mirrored to src endpoint)", got)
	}
	// 内层（GRE 头 4B 后 = 偏移 38）：内层 ip src/dst 必须已交换
	//（GREGenerator down swap，legacy inSrc/inDst 语义）。
	if got := be(f1, 50, 4); got != 0x0a000002 {
		t.Errorf("inner ip src = %#08x, want 10.0.0.2 (down: inner addresses swapped)", got)
	}
	if got := be(f1, 54, 4); got != 0x0a000001 {
		t.Errorf("inner ip dst = %#08x, want 10.0.0.1 (down: inner addresses swapped)", got)
	}
	// 内层 TCP 校验和覆盖**交换后**的地址（pseudo-header 用内层 ip 头的
	// src/dst——buildInnerL4 以传入参数计算，交换先于构造）。
	innerTCP := f1[58:]
	if got := tcpChecksum(innerTCP, []byte{10, 0, 0, 2}, []byte{10, 0, 0, 1}); got != 0 {
		t.Errorf("down inner tcp checksum = %#04x, want 0 (checksum must cover swapped addresses)", got)
	}
	// SYN-ACK 标志。
	if f1[71]&0x12 != 0x12 {
		t.Errorf("down inner tcp flags = %#02x, want SYN|ACK (0x12)", f1[71])
	}
}

// TestT12_GREUDPInner: gre 内层为 udp 时（{"gre":{}}+{"dns":{}} 补全
// [ip,gre,ip,udp,dns]），内层 IP 协议号必须 17、UDP 校验和正确（review
// MEDIUM-2：innerProtoFor 的 udp 分支零覆盖，回归成恒 6 无感；dns 是 udp
// 终结层——udp 本身是传输层，不能作链末层）。
func TestT12_GREUDPInner(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 53,
		Count: 1,
	}
	p, err := layers.BuildLayersPlanner("gre", json.RawMessage(`[{"gre":{}},{"dns":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) < 1 {
		t.Fatal("gre+udp chain produced 0 packets")
	}
	b := core.NewBuilder()
	var frames [][]byte
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v", i, err)
		}
		frames = append(frames, f)
	}
	// 内层 IP proto = 17（UDP）——innerProtoFor udp 分支（回归成恒 6 会失败）。
	if got := frames[0][47]; got != 17 {
		t.Errorf("inner ip protocol = %d, want 17 (udp)", got)
	}
	// 内层 UDP 校验和（RFC 768：pseudo-header 覆盖内层 ip src/dst + udp 段）。
	innerUDP := frames[0][58:]
	if got := udpChecksum(innerUDP, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}); got != 0 {
		t.Errorf("inner udp checksum = %#04x, want 0 (valid, RFC 768)", got)
	}
}

// TestT12_GREChecksumFold: 外层 GRE checksum 的 0xFFFF 折叠（review MEDIUM-1）。
// fillGREChecksum（builder.go:877-879）在计算和为 0 时必须以 0xFFFF 传输
// （RFC 2784 §3.1）。T12 的 checksum=true 配置（C|K|S 帧）必须走到该分支并
// 由独立算法对拍：1) 校验和覆盖 [greStart, outerPayloadEnd)（GRE 头含选项 +
// 内层负载，外层 IP 校验和不算入）；2) 未折叠 0。
func TestT12_GREChecksumFold(t *testing.T) {
	frames := buildGREChain(t, `[{"gre":{"checksum":true}},{"http":{}}]`)
	if len(frames) < 1 {
		t.Fatal("gre chain produced 0 frames")
	}
	greStart := 14 + 20 // eth + outer ip
	f0 := frames[0]
	if got := be(f0, 34, 2); got&0x8000 == 0 {
		t.Fatalf("gre flags = %#04x, want C bit set", got)
	}
	// 外层 IP 总长（offset 16:18）= 头20 + GRE(4) + 内层包。checksum 覆盖
	// [greStart, greStart+len(GRE头)+内层) = 到外层 IP payload 结束（排除
	// Ethernet padding）。
	outerTotal := be(f0, 16, 2)
	payloadEnd := 14 + int(outerTotal) // eth + outer ip payload end
	// 独立对拍：RFC 2784 §3.1（零化 checksum 域 + 4B 对齐 padding + 补码和）。
	// 与 builder_gre_test.go:504 的 greChecksumIndependent 同算法，但覆盖
	// 外层 IP 头（该 helper 只吃 GRE 段）。校验和必须折叠成非 0（若计算为
	// 0 必须传输 0xFFFF，两值都不能在此帧出现——C|K|S 帧头 + HTTP 请求负载
	// 补码和几乎不可能为 0，出现即 0xFFFF 折叠被断言为有效）。
	sum := uint32(0)
	for i := greStart; i+1 < payloadEnd; i += 2 {
		// 零化 checksum 域（偏移 38:40）：RFC 2784 §3.1 计算时该域必须为 0。
		w := binary.BigEndian.Uint16(f0[i : i+2])
		if i == greStart+4 {
			w = 0
		}
		sum += uint32(w)
	}
	if (payloadEnd-greStart)%2 == 1 {
		sum += uint32(f0[payloadEnd-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	want := ^uint16(sum)
	if want == 0 {
		want = 0xFFFF
	}
	got := be(f0, 38, 2) // GRE checksum 域（C 位 → 偏移 34+4=38）
	if got != uint64(want) {
		t.Errorf("gre checksum field = %#04x, want %#04x (RFC 2784 §3.1 over GRE hdr + inner payload)", got, want)
	}
	if got == 0 {
		t.Error("gre checksum field = 0, want nonzero (0x0000 means 'no checksum' on the wire)")
	}
}

// TestT12_GREUDPInnerChecksum: gre+udp 内层链的 UDP 校验和必须有效
//（review MEDIUM-2 细化：innerProtoFor 的 udp 分支 + 内层 L4 校验和构造
// 必须逐字节锁定，不能只断言协议号）。

// ---- 校验和小工具（RFC 791/RFC 793 对拍）----

// be reads n big-endian bytes at offset off of frame（字节断言小工具，
// T11 core_test 同款）。
func be(frame []byte, off, n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(frame[off+i])
	}
	return v
}

// ipChecksum16 computes the IPv4 header checksum (RFC 791 §3.1) over b.
func ipChecksum16(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum with the IPv4 pseudo-header
// (RFC 793) over the tcp segment, returning the expected value: 0 when the
// segment's checksum field matches the computed sum over pseudo+tcp.
func tcpChecksum(tcp []byte, src, dst []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < 4; i++ {
		sum += uint32(src[i]) << (8 * (3 - i))
		sum += uint32(dst[i]) << (8 * (3 - i))
	}
	sum += 6 // protocol TCP
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(uint16(tcp[i])<<8 | uint16(tcp[i+1]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// udpChecksum validates the UDP checksum with the IPv4 pseudo-header
// (RFC 768) over the udp segment, returning the expected value: 0 when the
// segment's checksum field matches the computed sum over pseudo+udp. Like
// tcpChecksum, the segment's own checksum field is INCLUDED in the sum —
// a correct segment folds the total to 0xFFFF (returns 0); only the
// generator zeroes the field while computing.
func udpChecksum(udp []byte, src, dst []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < 4; i++ {
		sum += uint32(src[i]) << (8 * (3 - i))
		sum += uint32(dst[i]) << (8 * (3 - i))
	}
	sum += 17 // protocol UDP
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(uint16(udp[i])<<8 | uint16(udp[i+1]))
	}
	if len(udp)%2 == 1 { // odd-length segment: last byte in the high octet
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
