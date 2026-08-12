package layers

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
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
	// registry is the registry used to complete/validate the chain; nil =
	// DefaultRegistry (测试注入自定义注册表时经 NewChainPlannerWithRegistry 指定)。
	registry *Registry
}

// NewChainPlanner creates a chain planner for the named protocol layer.
func NewChainPlanner(name string) *ChainPlanner {
	return &ChainPlanner{name: name}
}

// NewChainPlannerWithRegistry creates a chain planner that completes and
// validates chains against a custom registry (默认 NewChainPlanner 用
// DefaultRegistry；测试需要注入自定义层时用它)。The registry is read-only
// for the planner's lifetime.
func NewChainPlannerWithRegistry(name string, r *Registry) *ChainPlanner {
	return &ChainPlanner{name: name, registry: r}
}

// effectiveRegistry resolves the planner's registry.
func (p *ChainPlanner) effectiveRegistry() *Registry {
	if p.registry != nil {
		return p.registry
	}
	return DefaultRegistry()
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
	// 同步实例化生成器并校验事件接线（review 波 3 修复）：drive 运行在
	// goroutine 内，其错误被 Plan 的 goroutine 静默吞掉（表现为空流 + nil
	// err）。结构性错误——生成器不可实例化、终结层事件流配了非 tcp/udp
	// 传输层——必须在此同步报错，与 Validate 口径一致；drive 只保留运行时
	// 错误（生成器内部失败、ctx 取消），维持既有"驱动失败 → 空流"契约。
	gens, err := instantiateGens(chain)
	if err != nil {
		return nil, err
	}
	if err := assertEventWiring(chain, gens); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)
	go func() {
		// 关闭协议（review CRITICAL-1 修复）：驱动失败或取消时，ip 生成器
		// goroutine 可能仍在消费 innerCh 并向 out 发送 → 必须先等生产完全
		// 结束（drive 返回）再 close(out)，否则 close 与 send 并发
		// （send-on-closed panic，-race 实测复现）。
		defer close(out)
		packets, err := p.drive(ctx, chain, gens, spec)
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
	r := p.effectiveRegistry()
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
	// 预检生成器可实例化（review：实例化失败曾导致 Plan 静默空流——新层
	// 已注册但生成器未实现时，错误被驱动阶段吞掉）。终结层与内置层在此
	// 同步报错，与 Validate 口径一致。
	for _, l := range chain {
		if _, err := newGenerator(l.Name); err != nil {
			return nil, err
		}
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

// instantiateGens instantiates the generator for every chain layer, inner →
// outer (索引对齐 chain：gens[i] 对应 chain[i])。与 completedChain 的预检
// 合并使用：结构性错误（生成器未实现）在 Plan 同步报错，不再被 drive
// goroutine 吞掉。
func instantiateGens(chain []Layer) ([]LayerGenerator, error) {
	gens := make([]LayerGenerator, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		gen, err := newGenerator(chain[i].Name)
		if err != nil {
			return nil, err
		}
		gens[i] = gen
	}
	return gens, nil
}

// assertEventWiring validates the event-wiring contract synchronously
// (review 波 3 修复)：when the last layer's generator is an event producer
// (GenEvents != nil), the transport layer beneath it must be a TCP or UDP
// generator — the only two generators that consume Meta.Events. Any other
// transport (gre, ...) is a chain-configuration error that must fail Plan
// synchronously instead of being swallowed by the drive goroutine.
// 无事件生成器（独立 [ip→tcp]/[ip→udp] flow）时不检查。
func assertEventWiring(chain []Layer, gens []LayerGenerator) error {
	if len(chain) < 2 {
		return nil
	}
	lastGen := gens[len(chain)-1]
	eg, ok := lastGen.(interface{ GenEvents() EventGenerator })
	if !ok || eg.GenEvents() == nil {
		return nil
	}
	transportLayer := chain[len(chain)-2]
	switch gens[len(chain)-2].(type) {
	case *TCPGenerator, *UDPGenerator:
		return nil
	default:
		return fmt.Errorf("layers: layer %q cannot consume terminal events (unsupported transport generator %T)",
			transportLayer.Name, gens[len(chain)-2])
	}
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
// gens 由 Plan 同步预实例化并传入（review 波 3 修复：生成器实例化与事件
// 接线断言的结构性错误同步报错，drive 只承担运行时驱动）。
//
// 返回完整包序列（全量收集于内存，review CRITICAL-1 修复）：驱动失败/取消时
// 返回已收集的包 + 错误；ip 生成器退出后（genDone）drive 才返回，Plan 的
// goroutine 据此在**所有生产结束后**才 close(out)（消除 send-on-closed 竞态）。
// 取消路径（ctx.Done）经 select 在 finalEmit 传播，ip goroutine 正常退出，
// 不会产生泄漏。
func (p *ChainPlanner) drive(ctx context.Context, chain []Layer, gens []LayerGenerator, spec core.FlowSpec) ([]core.PacketConfig, error) {
	sess := &SessionState{IPID: uint16(rand.Uint32())}
	meta := FlowMeta{
		FlowID:  flowID(spec),
		Payload: spec.Payload,
		// HTTP/DstIP 注入给 http 层生成器（波 2 方案 A）：HTTPConfig 全量字段
		// 不落层 config（ValidateLayerConfig 拒绝未知字段），经 Meta 直传。
		// UDP 同款：UDPConfig 经 Meta.UDP 直传 udp 层生成器（波 3）。
		HTTP:  spec.HTTP,
		UDP:   spec.UDP,
		DstIP: spec.DstIP,
	}
	// ClassID 由引擎回填（worker.go:317 config.ClassID = task.ClassID）。
	// Direction 由各层包序列自定（tcp 握手 up 发起）。

	// 1. 把 flow 级 spec 值映射进各层 config（手动值 > schema 默认值）。
	chain = p.applySpecToChain(chain, spec)

	// 2. 自内向外实例化生成器；相邻层用通道连接（内层产出 → 外层消费）。
	//    gens 已由 Plan 预实例化（instantiateGens），此处直接使用。
	innerCh := make(chan core.PacketConfig, 256)

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
		// L3 协议号随传输层（tcp=6 / udp=17；legacy L3Base 语义）。
		// 传输层是链上 ip 之下最后一层：独立 tcp/udp flow 的末层，
		// 或终结层链（http/dns...）的倒数第二层。
		pkt.L3.Protocol = transportProtocol(chain)
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
	//    末层若是终结层生成器（http/dns/...），把其报文事件流接入传输层的
	//    Meta.Events，传输层在"单 payload 模式"后消费事件流（波 2 方案 A /
	//    波 3 泛化）。事件接线的 transport 断言已在 Plan 同步校验
	//    （assertEventWiring），此处断言必过，只做类型收窄。
	//    内层序列结束后关闭 innerCh：外层生成器排空后退出（否则 drive
	//    永远等不到 genDone，Plan 的 goroutine 不返回，worker 的 for-range 挂死）。
	genDone := make(chan error, 1)
	go func() { genDone <- ipGen.Generate(ctx, ipReq) }()

	lastGen := gens[len(chain)-1]
	var lastErr error

	// 末层事件生成器（http/dns/...）与传输层（tcp/udp）事件通道的接线。
	// 传输层类型断言保持通用：tcp → TCPGenerator（MSS 分段 + seq/ack），
	// udp → UDPGenerator（每事件一数据报）。
	if eg, ok := lastGen.(interface{ GenEvents() EventGenerator }); ok && eg.GenEvents() != nil {
		eventCh := make(chan MessageEvent, 64)
		transportLayer := chain[len(chain)-2]
		transportGen := gens[len(chain)-2]
		meta.Events = eventCh
		transportReq := &GenRequest{
			Layer: transportLayer,
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
		// 终结层生成器的 EmitMsg 转发到事件通道。
		reqForTerminal := &GenRequest{
			Layer: chain[len(chain)-1],
			EmitMsg: func(ev MessageEvent) error {
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
		var transport interface {
			Generate(ctx context.Context, req *GenRequest) error
		}
		switch tg := transportGen.(type) {
		case *TCPGenerator:
			transport = tg
		case *UDPGenerator:
			transport = tg
		default:
			// assertEventWiring 已同步拦截，理论不可达。
			return nil, fmt.Errorf("layers: layer %q cannot consume terminal events (unsupported transport generator %T)",
				transportLayer.Name, transportGen)
		}
		transportDone := make(chan error, 1)
		go func() { transportDone <- transport.Generate(ctx, transportReq) }()
		lastErr = lastGen.Generate(ctx, reqForTerminal)
		close(eventCh)
		if lastErr != nil {
			// 终结层生成器失败：传输层仍会排空事件流（事件流关闭视为
			// 数据段结束，tcp 进入挥手 / udp 直接结束）。等待其退出，不泄漏。
			<-transportDone
			close(innerCh)
			<-genDone
			return packets, lastErr
		}
		if err := <-transportDone; err != nil {
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
func (p *ChainPlanner) applySpecToChain(chain []Layer, spec core.FlowSpec) []Layer {
	r := p.effectiveRegistry()
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
		case "udp":
			// 与 tcp 同构：spec 端口直接注入 udp 层（独立 [ip→udp] flow）。
			// UDPConfig 无 schema 字段，经 FlowMeta.UDP 直传生成器。
			cfg["src_port"] = uint16(spec.SrcPort)
			cfg["dst_port"] = uint16(spec.DstPort)
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

// transportProtocol resolves the IP protocol number from the chain's
// transport layer (tcp=6 / udp=17)。独立 transport flow（[ip→udp]，传输层即
// 末层）看末层；终结层链（[ip→tcp→http]）看倒数第二层。无传输层时回退 TCP
// （理论不可达：transport 层是 ip 的 depends_on 补全必插入）。
func transportProtocol(chain []Layer) uint8 {
	if len(chain) > 0 {
		switch chain[len(chain)-1].Name {
		case "udp":
			return core.ProtocolUDP
		case "tcp":
			return core.ProtocolTCP
		}
	}
	if len(chain) > 1 {
		switch chain[len(chain)-2].Name {
		case "udp":
			return core.ProtocolUDP
		case "tcp":
			return core.ProtocolTCP
		}
	}
	return core.ProtocolTCP
}

// newGenerator instantiates the generator for a chain layer. Only layers with
// generators implemented can appear in a driven chain (P2a 波 1: ip + tcp;
// 波 2 方案 A: + http，由 protocol/http 包提供生成器)。
func newGenerator(name string) (LayerGenerator, error) {
	// 测试注入的生成器优先（测试终结层等）。
	testGenMu.RLock()
	factory, ok := testGenerators[name]
	testGenMu.RUnlock()
	if ok {
		return factory()
	}
	switch name {
	case "ip":
		return &IPGenerator{}, nil
	case "tcp":
		return &TCPGenerator{}, nil
	case "udp":
		return &UDPGenerator{}, nil
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

// RegisterLayerGeneratorForTest installs a generator factory for a layer
// name (测试专用：注入测试终结层生成器；生产层经各自包的 init 反向注册，
// 无需调用)。The factory overrides newGenerator for that name; multiple
// registrations for the same name replace the previous factory. It returns a
// cleanup function removing the registration (review 波 3 L1 修复)：测试间
// 残留注册会污染后续驱动 DefaultRegistry 链的测试，cleanup 消除泄漏。
// 注册表由 RWMutex 保护：Plan 的 drive goroutine 读 newGenerator 与测试
// 主 goroutine 注册/注销并发安全（裸 map 并发读写会 fatal error，-race 实测）。
func RegisterLayerGeneratorForTest(name string, factory func() (LayerGenerator, error)) func() {
	testGenMu.Lock()
	defer testGenMu.Unlock()
	testGenerators[name] = factory
	return func() { UnregisterLayerGeneratorForTest(name) }
}

// UnregisterLayerGeneratorForTest removes a test-injected generator factory
// (测试专用，与 RegisterLayerGeneratorForTest 对称；t.Cleanup 注销消除
// 测试间残留注册污染)。Concurrent with active Plan goroutines via testGenMu.
func UnregisterLayerGeneratorForTest(name string) {
	testGenMu.Lock()
	defer testGenMu.Unlock()
	delete(testGenerators, name)
}

// testGenerators holds test-only generator factories (测试注入的层生成器，
// 优先级高于内置 newGenerator 分支——仅测试使用，避免给内置表加依赖)。
// 并发访问由 testGenMu 保护（RegisterLayerGeneratorForTest 的写 + newGenerator
// 在驱动 goroutine 中的读）。
var (
	testGenerators = map[string]func() (LayerGenerator, error){}
	testGenMu      sync.RWMutex
)

// NewGenRequestForHTTP builds a GenRequest for a standalone http generator
// test (供 protocol/http 包测试构造请求)。The spec's HTTP config flows into
// Meta.HTTP; the returned request's EmitMsg must be set by the caller.
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
