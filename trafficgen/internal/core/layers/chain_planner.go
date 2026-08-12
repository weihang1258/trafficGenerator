package layers

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ChainPlanner drives a layer chain to generate a full packet stream
// (层链规划器)。It implements core.ProtocolPlanner with the same signature as
// the legacy per-protocol planners, so it can be registered in place of them.
// The chain is derived from the protocol name: for "tcp" the chain starts as
// [{tcp}] and completion fills [ip → tcp] (类名即末层)。
//
// Plan 流程（规格 §ChainPlanner）：
//  1. chain = []Layer{{Name: p.name}}（类名即末层名）
//  2. 把 flow 级 spec 值映射进各层 Layer.Config（手动值 > schema 默认值；
//     spec.TCP 为 nil 时信任 schema 默认，绝不用 TCPConfig 零值覆盖）
//  3. DefaultRegistry().CompleteChain(chain)
//  4. validateChain（仅豁免"合成链末层即协议层本身"这一条 V4/V5 末层检查）
//  5. 按链自内向外实例化生成器；通道连接相邻层
//  6. 驱动：终结层/传输层生成器（tcp 自身）发起包序列
//  7. 逐包回填 FlowID/ClassID/PacketIndex/Timestamp/Direction
type ChainPlanner struct {
	name string
}

// NewChainPlanner creates a chain planner for the named protocol layer.
func NewChainPlanner(name string) *ChainPlanner {
	return &ChainPlanner{name: name}
}

// Name returns the protocol name.
func (p *ChainPlanner) Name() string { return p.name }

// Validate validates a flow spec plus the derived layer chain.
func (p *ChainPlanner) Validate(spec core.FlowSpec) error {
	if err := validateSpecBase(spec); err != nil {
		return err
	}
	if err := p.validateChain(); err != nil {
		return err
	}
	return nil
}

// validateChain builds the completed chain and validates it, applying the
// planner-specific V4/V5 exemption (合成链末层是协议层本身，传输层当末层合法)。
func (p *ChainPlanner) validateChain() error {
	_, err := p.completedChain()
	return err
}

// validateSpecBase mirrors the legacy tcp planner's spec checks (IP parse,
// ports required, MSS bounds) so ChainPlanner rejects the same specs the old
// planner rejected (tcp_test.go TestPlanner_Validate 负向用例)。
func validateSpecBase(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.SrcPort == 0 {
		return fmt.Errorf("source port is required")
	}
	if spec.DstPort == 0 {
		return fmt.Errorf("destination port is required")
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("MSS %d too small (min 536 per RFC 879)", spec.TCP.MSS)
		}
		if spec.TCP.MSS > 65535 {
			return fmt.Errorf("MSS %d too large (max 65535)", spec.TCP.MSS)
		}
	}
	return nil
}

// Plan generates the full packet stream for the flow (驱动整条层链产包)。
func (p *ChainPlanner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	chain, err := p.completedChain()
	if err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)
	go func() {
		// 关闭协议（review CRITICAL-1 修复）：驱动失败或取消时，ip 生成器
		// goroutine 可能仍在消费 innerCh 并向 out 发送 → 必须先等生产完全
		// 结束（drive 返回）再 close(out)，否则 close 与 send 并发
		// （send-on-closed panic，-race 实测复现）。
		defer close(out)
		packets, err := p.drive(ctx, chain, spec)
		if err != nil {
			// 驱动失败：通道随后关闭，包流为空，调用方（worker）会按空流处理。
			return
		}
		// 逐包回填（无锁单一 goroutine）：IPID 已在 ip 层生成器写入
		// （每次 Emit 前写入并自增）；这里只回填 ChainPlanner 持有的元数据。
		for i := range packets {
			packets[i].FlowID = flowID(spec)
			packets[i].PacketIndex = uint64(i)
			packets[i].Timestamp = time.Now()
		}
		for _, pkt := range packets {
			out <- pkt
		}
	}()
	return out, nil
}

// flowID mirrors the legacy per-flow ID format (tcp.go:89, http.go:89):
// "srcIP-dstIP-srcPort-dstPort"（每 flow 唯一标识）。
func flowID(spec core.FlowSpec) string {
	return fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
}

// completedChain completes the derived chain and validates it, applying the
// V4/V5 exemption for the synthesized chain (末层即协议层本身)。
func (p *ChainPlanner) completedChain() ([]Layer, error) {
	r := DefaultRegistry()
	if !r.Has(p.name) {
		return nil, fmt.Errorf("layers: unknown layer %q", p.name)
	}
	chain, err := r.CompleteChain([]Layer{{Name: p.name}})
	if err != nil {
		// CompleteChain 末尾自带 validateChain，会先拦 V4/V5"末层必须是终结层"
		// （complete.go 补全后统一校验）。合成链的末层就是协议层本身
		// （类名即末层，tcp 独立 flow），属豁免场景。
		if !isTerminalEndError(err) {
			return nil, err
		}
		s, _ := r.Get(p.name)
		if len(s.InnerRequired) > 0 {
			// 隧道层补全会把末层换成内层起点（gre → [ip, gre, ip]），
			// 末层不再是协议层 → 不豁免。
			return nil, err
		}
		// 手动补全：depends_on 只向外插，末层保持协议层（tcp → [ip, tcp]）。
		chain = completeSynthesized(r, p.name)
	}
	if err := p.validateChainForPlanner(r, chain); err != nil {
		return nil, err
	}
	return chain, nil
}

// completeSynthesized completes a synthesized chain manually for the V4-exempt
// case: CompleteChain's internal validation rejects a transport last layer, so
// the exemption path rebuilds the chain by iteratively inserting depends_on
// layers outward (等价 CompleteChain 第一趟；depends_on 只向外插，末层永远是
// 协议层本身)。
func completeSynthesized(r *Registry, name string) []Layer {
	chain := []Layer{{Name: name}}
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(chain); i++ {
			s, _ := r.Get(chain[i].Name)
			for _, dep := range s.DependsOn {
				if outerHasLayer(chain, i, dep) {
					continue
				}
				chain = append(chain[:i], append([]Layer{{Name: dep}}, chain[i:]...)...)
				changed = true
				i++ // 跳过刚插入的层
			}
		}
	}
	return chain
}

// outerHasLayer reports whether a layer named want appears outward of index i.
func outerHasLayer(chain []Layer, i int, want string) bool {
	for k := 0; k < i; k++ {
		if chain[k].Name == want {
			return true
		}
	}
	return false
}

// validateChainForPlanner validates the completed chain. The transport layer
// as last layer is legal for a chain whose outermost layer is the protocol
// itself (a standalone tcp flow); the registry's V4/V5 rule exists for
// USER-written chains, which must end in a terminal layer. ChainPlanner
// bypasses only that last-layer-terminal check and keeps every other rule
// (V1-V3, V6-V10) intact.
func (p *ChainPlanner) validateChainForPlanner(r *Registry, chain []Layer) error {
	if len(chain) == 0 {
		return fmt.Errorf("layers: empty layer chain")
	}
	for _, l := range chain {
		if err := r.ValidateLayerConfig(l); err != nil {
			return err
		}
	}
	if err := r.ValidateChain(chain); err != nil {
		if isTerminalEndError(err) && chain[len(chain)-1].Name == p.name {
			// 豁免：合成链的末层就是协议层本身（tcp/udp 独立 flow）。
			// 用户手写的链（将来经解析层）仍走完整 V4/V5。
			return nil
		}
		return err
	}
	return nil
}

// isTerminalEndError reports whether the error is the V4/V5 "must end with a
// terminal layer" family.
func isTerminalEndError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "must end with a terminal layer")
}

// drive instantiates the generators inner→outer, wires the channels, and
// drives the outermost generator of the chain — which for a standalone tcp
// flow is the tcp generator itself (终结/传输层驱动整链)。Each packet flows
// inner → outer: the tcp generator emits L4-only packets into innerCh, the ip
// generator consumes them, fills the L3 config (src/dst/ttl/dscp/ecn/frag +
// IPID), and hands each wrapped packet to finalEmit, which assembles L2 (MACs
// swapped per direction), derives the direction-dependent src/dst IP swap,
// and backfills FlowID/PacketIndex/Timestamp.
//
// 返回完整包序列（全量收集于内存，review CRITICAL-1 修复）：驱动失败/取消时
// 返回已收集的包 + 错误；ip 生成器退出后（genDone）drive 才返回，Plan 的
// goroutine 据此在**所有生产结束后**才 close(out)（消除 send-on-closed 竞态）。
// 取消路径（ctx.Done）经 select 在 finalEmit 传播，ip goroutine 正常退出，
// 不会产生泄漏。
func (p *ChainPlanner) drive(ctx context.Context, chain []Layer, spec core.FlowSpec) ([]core.PacketConfig, error) {
	sess := &SessionState{IPID: uint16(rand.Uint32())}
	meta := FlowMeta{
		FlowID:  flowID(spec),
		Payload: spec.Payload,
		// HTTP/DstIP 注入给 http 层生成器（波 2 方案 A）：HTTPConfig 全量字段
		// 不落层 config（ValidateLayerConfig 拒绝未知字段），经 Meta 直传。
		HTTP:  spec.HTTP,
		DstIP: spec.DstIP,
	}
	// ClassID 由引擎回填（worker.go:317 config.ClassID = task.ClassID）。
	// Direction 由各层包序列自定（tcp 握手 up 发起）。

	// 1. 把 flow 级 spec 值映射进各层 config（手动值 > schema 默认值）。
	chain = applySpecToChain(chain, spec)

	// 2. 自内向外实例化生成器；相邻层用通道连接（内层产出 → 外层消费）。
	gens := make([]LayerGenerator, len(chain))
	innerCh := make(chan core.PacketConfig, 256)
	for i := len(chain) - 1; i >= 0; i-- {
		gen, err := newGenerator(chain[i].Name)
		if err != nil {
			return nil, err
		}
		gens[i] = gen
	}

	// 3. 驱动：最外层生成器（ip）包内层；最内层生成器（tcp 或 http）产出。
	//    通用模式：外层生成器消费内层通道；最内层生成器不消费 innerCh。
	var ipGen *IPGenerator
	var ipLayer Layer
	for i, l := range chain {
		if l.Name == "ip" {
			ipGen = gens[i].(*IPGenerator)
			ipLayer = chain[i]
		}
	}
	if ipGen == nil {
		// 理论不可达：ip 是 transport 的 depends_on，补全必插入。
		return nil, fmt.Errorf("layers: chain for %q has no ip layer", p.name)
	}
	ipCfg := ipLayer.Config

	// 4. 出口：包齐 L2/L3 方向装配 + 元数据回填（全量收集于内存）。
	packets := make([]core.PacketConfig, 0, 64)
	finalEmit := func(pkt core.PacketConfig) error {
		pkt.L2 = l2For(pkt.Direction, spec)
		// 方向相关 src/dst 交换 + flow 级字段。IPID 已由 ip 层生成器写入
		// （每次 Emit 前写入并自增），这里只换 IP 不换 ID。
		if pkt.Direction == "down" {
			pkt.L3.SrcIP, pkt.L3.DstIP = pkt.L3.DstIP, pkt.L3.SrcIP
		}
		pkt.L3.Protocol = core.ProtocolTCP
		pkt.L3.TTL = ipTTL(ipCfg)
		// TOS 整字节覆盖（review HIGH-2 修复，legacy L3Base builder.go:158-161
		// 语义）：spec.TOS != 0 时 DSCP=TOS>>2、ECN=TOS&3，覆盖 DSCP/ECN 直配。
		if spec.TOS != 0 {
			pkt.L3.DSCP = spec.TOS >> 2
			pkt.L3.ECN = spec.TOS & 0x03
		} else {
			pkt.L3.DSCP = spec.DSCP
			pkt.L3.ECN = spec.ECN
		}
		pkt.L3.Flags = spec.IPFlags
		pkt.L3.FragOffset = spec.FragOffset
		pkt.L3.HopByHop = spec.HopByHop
		packets = append(packets, pkt)
		// 取消检测在驱动循环中处理（ip 生成器 select ctx.Done）：这里只收集。
		return nil
	}

	ipReq := &GenRequest{
		Layer: ipLayer,
		Inner: innerCh,
		Emit:  finalEmit,
		Sess:  sess,
		Meta:  meta,
	}

	// 5. 驱动：先启动外层（消费 innerCh），再驱动内层（往 innerCh 里写）。
	//    末层若是终结层生成器（http），把其报文事件流接入 tcp 层的
	//    Meta.HTTPEvents，tcp 层在"单 payload 模式"后消费事件流（波 2 方案 A）。
	//    内层序列结束后关闭 innerCh：外层生成器排空后退出（否则 drive
	//    永远等不到 genDone，Plan 的 goroutine 不返回，worker 的 for-range 挂死）。
	genDone := make(chan error, 1)
	go func() { genDone <- ipGen.Generate(ctx, ipReq) }()

	lastGen := gens[len(chain)-1]
	var lastErr error

	// 末层事件生成器（http）与 tcp 层事件通道的接线。
	if eg, ok := lastGen.(interface{ GenHTTP() HTTPEventGenerator }); ok && eg.GenHTTP() != nil {
		eventCh := make(chan HTTPEvent, 64)
		tcpGen := gens[len(chain)-2].(*TCPGenerator)
		meta.HTTPEvents = eventCh
		tcpReq := &GenRequest{
			Layer: chain[len(chain)-2], // tcp 层
			Emit: func(pkt core.PacketConfig) error {
				select {
				case innerCh <- pkt:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Sess: sess,
			Meta: meta,
		}
		// http 生成器的 EmitHTTP 转发到事件通道。
		reqForHTTP := &GenRequest{
			Layer: chain[len(chain)-1],
			EmitHTTP: func(ev HTTPEvent) error {
				select {
				case eventCh <- ev:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Sess: sess,
			Meta: meta,
		}
		tcpDone := make(chan error, 1)
		go func() { tcpDone <- tcpGen.Generate(ctx, tcpReq) }()
		lastErr = lastGen.Generate(ctx, reqForHTTP)
		close(eventCh)
		if lastErr != nil {
			// http 生成器失败：tcp 层仍会排空事件流并完成挥手
			// （事件流关闭视为数据段结束）。等待其退出，不泄漏。
			<-tcpDone
			close(innerCh)
			<-genDone
			return packets, lastErr
		}
		if err := <-tcpDone; err != nil {
			close(innerCh)
			<-genDone
			return packets, err
		}
		close(innerCh)
		if err := <-genDone; err != nil {
			return packets, err
		}
		return packets, nil
	}

	// 无事件生成器：末层直接产包（波 1 的 [ip → tcp] 独立 tcp flow 路径）。
	tcpReq := &GenRequest{
		Layer: chain[len(chain)-1], // 末层 = tcp（协议层本身）
		Emit: func(pkt core.PacketConfig) error {
			select {
			case innerCh <- pkt:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Sess: sess,
		Meta: meta,
	}
	lastErr = lastGen.Generate(ctx, tcpReq)
	close(innerCh)
	if lastErr != nil {
		return packets, lastErr
	}
	if err := <-genDone; err != nil {
		return packets, err
	}
	return packets, nil
}

// applySpecToChain maps flow-level spec values into each layer's config.
// 手动值 > schema 默认值：只有 spec 上非零/非空的值才写入 config；spec.TCP
// 为 nil 时（独立 tcp flow 无子配置）完全不动 tcp 层 config，让 schema 默认
// 生效（handshake=true / termination=true / mss=1460 / window_size=65535）——
// 绝不能把 TCPConfig 零值 false 覆盖成用户意图。
func applySpecToChain(chain []Layer, spec core.FlowSpec) []Layer {
	r := DefaultRegistry()
	out := make([]Layer, len(chain))
	for i, l := range chain {
		// 以 schema 默认值为底（手动值 > 默认值：只覆盖用户显式写的）。
		s, _ := r.Get(l.Name)
		cfg := make(map[string]interface{}, len(s.Fields))
		for k, f := range s.Fields {
			if f.Default != nil {
				cfg[k] = f.Default
			}
		}
		for k, v := range l.Config {
			cfg[k] = v
		}
		switch l.Name {
		case "ip":
			// 只有 spec 显式写了 IP 才注入层 config；spec IP 为空时**移除**
			// schema 默认的 10.0.0.1/20.0.0.1（review LOW-1 修复）：legacy
			// 语义是"spec IP 空 → L3 空"，链上 ip 层默认只服务独立 ip flow
			// 的合成链，不允许把默认 IP 静默注入包（与 legacy L3Base 一致）。
			// 安全前提（review 注记）：此处只可能删除 **schema 注入的默认值**
			// ——合成链（completeSynthesized/CompleteChain 以 {Name:name} 起步）
			// 的 ip 层 Config 恒为 nil，delete 无对象可删；ChainPlanner 目前
			// 不驱动用户手写链（手写链只经 registry 校验，不进 applySpecToChain），
			// 所以 delete 永不触碰用户显式写入的 src/dst。若未来支持手写链，
			// 需改为按"值 == schema 默认值"精确删除，而不是无差别 delete。
			if spec.SrcIP != "" {
				cfg["src"] = spec.SrcIP
			} else {
				delete(cfg, "src")
			}
			if spec.DstIP != "" {
				cfg["dst"] = spec.DstIP
			} else {
				delete(cfg, "dst")
			}
			if spec.TTL != 0 {
				cfg["ttl"] = uint8(spec.TTL)
			}
			if spec.DSCP != 0 {
				cfg["dscp"] = uint8(spec.DSCP)
			}
			if spec.ECN != 0 {
				cfg["ecn"] = uint8(spec.ECN)
			}
			if spec.FragOffset != 0 {
				cfg["frag_offset"] = uint16(spec.FragOffset)
			}
		case "tcp":
			cfg["src_port"] = uint16(spec.SrcPort)
			cfg["dst_port"] = uint16(spec.DstPort)
			if t := spec.TCP; t != nil {
				// http 链强制 legacy http 语义（review LOW-3 修复）：legacy
				// http.go 只读 spec.TCP 的 MSS/InitialSeq（http.go:126-151），
				// 从不读 Handshake/Termination/RST——握手恒全开、无 RST、
				// 窗口恒 schema 默认 65535。http 链在这里除 MSS/InitialSeq 外
				// 一律不注入：开关保持 schema 默认（true/true/false），与
				// legacy http 包序列逐字节一致（126 个 legacy 测试断言 9/11 包、
				// 恒 65535 的窗口）。
				if isHTTPChain(chain) {
					if t.MSS != 0 {
						cfg["mss"] = uint16(t.MSS)
					}
					if t.InitialSeq != 0 {
						cfg["initial_seq"] = t.InitialSeq
					}
					break
				}
				// mapToFlowSpec 已把显式值默认化（getBool(sub,"handshake",true)
				// 等），这里"非零/非空才写"不会丢掉显式 false：显式
				// handshake=false 已存进 t.Handshake，非零判断对 bool 用
				// 直接赋值。MSS/WindowSize/InitialSeq 是数值，0 = 用 schema 默认。
				if t.MSS != 0 {
					cfg["mss"] = uint16(t.MSS)
				}
				if t.WindowSize != 0 {
					cfg["window_size"] = uint16(t.WindowSize)
				}
				if t.InitialSeq != 0 {
					cfg["initial_seq"] = t.InitialSeq
				}
				cfg["handshake"] = t.Handshake
				cfg["termination"] = t.Termination
				cfg["rst"] = t.RST
			}
		}
		out[i] = Layer{Name: l.Name, Config: cfg}
	}
	return out
}

// isHTTPChain reports whether the chain's terminal layer is http
// (http 链判定：末层即协议层）。Used by applySpecToChain to force the
// legacy http TCP semantics (忽略 handshake/termination/rst 开关)。
func isHTTPChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "http"
}

// newGenerator instantiates the generator for a chain layer. Only layers with
// generators implemented can appear in a driven chain (P2a 波 1: ip + tcp;
// 波 2 方案 A: + http，由 protocol/http 包提供生成器)。
func newGenerator(name string) (LayerGenerator, error) {
	switch name {
	case "ip":
		return &IPGenerator{}, nil
	case "tcp":
		return &TCPGenerator{}, nil
	case "http":
		// http 层生成器实现在 protocol/http 包（newHTTPGenerator），
		// 避免 layers → protocol/http 的依赖环（http 依赖 core + layers）。
		return newHTTPGenerator()
	}
	return nil, fmt.Errorf("layers: generator not implemented for layer %q", name)
}

// newHTTPGenerator is set by the protocol/http package via
// RegisterHTTPGenerator (波 2 方案 A)。它返回 http 层生成器实例，
// 避免 layers → protocol/http 依赖环（http 包 import layers 反向注册）。
var newHTTPGenerator = func() (LayerGenerator, error) {
	return nil, fmt.Errorf("layers: http generator not registered (protocol/http package not imported)")
}

// RegisterHTTPGenerator installs the http layer generator factory
// (由 protocol/http 包在 init 中调用)。
func RegisterHTTPGenerator(factory func() (LayerGenerator, error)) {
	newHTTPGenerator = factory
}

// NewHTTPGenerator returns a fresh http layer generator (供测试与
// protocol/http 包内部使用；等价 newGenerator("http"))。
func NewHTTPGenerator() (LayerGenerator, error) {
	return newHTTPGenerator()
}

// NewGenRequestForHTTP builds a GenRequest for a standalone http generator
// test (供 protocol/http 包测试构造请求)。The spec's HTTP config flows into
// Meta.HTTP; the returned request's EmitHTTP must be set by the caller.
func NewGenRequestForHTTP(spec core.FlowSpec) (*GenRequest, error) {
	if spec.HTTP == nil {
		return nil, fmt.Errorf("layers: NewGenRequestForHTTP: spec.HTTP is nil")
	}
	return &GenRequest{
		Meta: FlowMeta{
			FlowID: flowID(spec),
			HTTP:   spec.HTTP,
		},
	}, nil
}

// l2For assembles the L2 config for a direction: up = spec.SrcMAC→DstMAC,
// down = swapped; EtherType derived from the source IP (IPv6 flows get 0x86DD)。
// 与 tcp.go 每包 L2 装配字节一致。
func l2For(direction string, spec core.FlowSpec) core.L2Config {
	l2 := core.L2Config{EtherType: core.EtherTypeFor(spec.SrcIP)}
	if direction == "down" {
		l2.SrcMAC = spec.DstMAC
		l2.DstMAC = spec.SrcMAC
	} else {
		l2.SrcMAC = spec.SrcMAC
		l2.DstMAC = spec.DstMAC
	}
	return l2
}

// ipTTL resolves the effective TTL from the ip layer's completed config
// (schema 默认 64；显式 0 表示"未设置"退回默认)。
func ipTTL(ipCfg map[string]interface{}) uint8 {
	ttl := uint8(DefaultTTL)
	if v, ok := flowConfigField(ipCfg, "ttl"); ok {
		if t, ok := configUint8(v); ok && t != 0 {
			ttl = t
		}
	}
	return ttl
}
