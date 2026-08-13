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

// eventDstOverrideKey is the internal metadata marker the udp generator sets
// when a terminal event overrides the datagram target (波 5 多播基础设施)。
// finalEmit consumes it and removes it, so it never leaks into output
// metadata. Keyed off Metadata (not a field) to keep MessageEvent/PacketConfig
// untouched beyond the override fields themselves.
const eventDstOverrideKey = "__event_dst_override__"

// mdnsPort is the mDNS well-known port (RFC 6762 §5.4, 5353)。layers 包内
// 复刻（不能引用 protocol/mdns 的 MDNSPort——protocol 包反向依赖 layers）。
const mdnsPort = 5353

// ssdpPort is the SSDP well-known port (1900, UPnP/SSDP)。layers 包内复刻
// （不能引用 protocol/ssdp 的 DefaultPort——protocol 包反向依赖 layers）。
const ssdpPort = 1900

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

// Validate validates a flow spec plus the derived layer chain (ProtocolPlanner
// 接口；结果与 ValidateSpec 一致，丢弃默认化后的 spec)。
func (p *ChainPlanner) Validate(spec core.FlowSpec) error {
	_, err := p.ValidateSpec(spec)
	return err
}

// ValidateSpec validates a flow spec plus the derived layer chain and
// returns the spec with protocol-level defaults applied (端口默认等，legacy
// 各 planner 在 Plan 时同款默认)——调用方（Plan）用默认化后的 spec 驱动链，
// 保证层 config / 包序列 / flowID 三者端口一致。
func (p *ChainPlanner) ValidateSpec(spec core.FlowSpec) (core.FlowSpec, error) {
	if err := validateSpecBase(p.name, &spec); err != nil {
		return spec, err
	}
	// 协议级校验（波 4 起）：终结层协议包经 RegisterLayerValidator 注册
	// 其 Validate（如 dns 包对 DNSConfig 的检查），链上未注册校验器的层
	// 跳过。校验器只校验不默认化（默认化由 validateSpecBase 统一负责）。
	if v := protocolValidator(p.name); v != nil {
		if err := v(&spec); err != nil {
			return spec, err
		}
	}
	if err := p.validateChain(); err != nil {
		return spec, err
	}
	return spec, nil
}

// validateChain builds the completed chain and validates it, applying the
// planner-specific V4/V5 exemption (合成链末层是协议层本身，传输层当末层合法)。
func (p *ChainPlanner) validateChain() error {
	_, err := p.completedChain()
	return err
}

// validateSpecBase mirrors the legacy tcp planner's spec checks (IP parse,
// ports required, MSS bounds) so ChainPlanner rejects the same specs the old
// planner rejected (tcp_test.go TestPlanner_Validate 负向用例)。波 4 起
// 对终结层 udp 链（dns/ntp/snmp/syslog）做协议级端口默认（legacy 各
// planner 在 Plan 时同款默认）。
func validateSpecBase(name string, spec *core.FlowSpec) error {
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
	// IP 版本匹配（legacy 各 planner Validate 同款，防 L3 builder 混淆）：
	// v4-src/v6-dst 混合拒绝。
	if spec.SrcIP != "" && spec.DstIP != "" {
		src := net.ParseIP(spec.SrcIP)
		dst := net.ParseIP(spec.DstIP)
		if src != nil && dst != nil && (src.To4() != nil) != (dst.To4() != nil) {
			return fmt.Errorf("SrcIP %s and DstIP %s must be same IP version", spec.SrcIP, spec.DstIP)
		}
	}
	if spec.SrcPort == 0 {
		// 协议级源端口默认：独立 transport flow（tcp/udp）无默认，
		// 必须显式（legacy tcp.go/udp.go 同款）。终结层 udp 链（dns/ntp/
		// snmp/syslog/mdns）由各自 legacy planner 在 Plan 时默认：dns/snmp/
		// syslog 源端口沿用 spec（可为 0，legacy 同样带 0 上包）；
		// ntp 用 30000+(seed%30000) 的确定性临时端口（planner.go:203-206，
		// seed=IPID 种子，每次 Plan 随机）；mdns 源端口强制 5353
		// （RFC 6762 §5.4，legacy planner.go:428-432 同款：spec 为 0 时默认）。
		switch name {
		case "ntp":
			spec.SrcPort = uint16(30000 + (uint32(rand.Uint32()) % 30000))
		case "mdns":
			spec.SrcPort = mdnsPort
		case "ssdp":
			// SSDP 源端口强制 1900（legacy planner.go:236-239 同款：spec 为
			// 0 时默认；RFC 6970 规定 SSDP 用 1900）。
			spec.SrcPort = ssdpPort
		case "rip":
			// RIP 源端口 0 保持 0：终结层生成器按 legacy resolveSrcPort 语义
			// 逐事件解析（单 router Response=520、multi-router=52001+idx、
			// request_full=52001，rip.go:579-587），不在此默认化。
		case "dhcp":
			// DHCP 源端口 0 保持 0：终结层生成器按角色解析（client→68、
			// server/relay→67，dhcp planner.go:643-679 resolvePorts 语义）。
		case "dhcpv6":
			// DHCPv6 源端口 0 保持 0：终结层生成器按方向逐事件解析
			// （up=client 546、down=server 547，dhcpv6 planner.go:435-456
			// resolveAddrs 语义，IPv6-only 链）。
		case "dns", "snmp", "syslog":
			// 允许 0 上包（legacy 语义）
		default:
			return fmt.Errorf("source port is required")
		}
	}
	if spec.DstPort == 0 {
		// 协议级目的端口默认（legacy Plan 时默认，与 strategy_convert 的
		// mapToFlowSpec 默认值一致）：dns→53、syslog→514（tls 载体 6514）、
		// snmp→按 PDU 类型（trap/inform 162，其余 161）、ntp→123、
		// mdns→5353（legacy mdns planner.go:433-436 同款）。
		switch name {
		case "dns":
			spec.DstPort = 53
		case "mdns":
			spec.DstPort = mdnsPort
		case "syslog":
			// tls 分支不可达（validator 拒绝 tls 载体，layer_gen.go 同款
			// 暂缓），保留只为与 legacy 默认一致。
			if spec.Syslog != nil && spec.Syslog.Transport == "tls" {
				spec.DstPort = 6514
			} else {
				spec.DstPort = 514
			}
		case "snmp":
			if spec.SNMP != nil {
				switch spec.SNMP.PDUType {
				case 4, 5, 6: // trap v1 / snmpv2 trap / inform
					spec.DstPort = 162
				default:
					spec.DstPort = 161
				}
			} else {
				spec.DstPort = 161
			}
		case "ntp":
			spec.DstPort = 123
		case "ssdp":
			spec.DstPort = ssdpPort
		case "rip":
			// RIP 目的端口 0 保持 0：终结层生成器按版本默认（v1/v2→520、
			// ng→521，legacy getDstPort 语义），事件携带 DstPort。
		case "dhcp":
			// DHCP 目的端口 0 保持 0：终结层生成器按角色解析（client→67、
			// server/relay→67，dhcp planner.go:643-679 resolvePorts 语义）。
		case "dhcpv6":
			// DHCPv6 目的端口 0 保持 0：终结层生成器按方向逐事件解析
			// （up=server 547、down=client 546，dhcpv6 planner.go:435-456
			// resolveAddrs 语义）。
		default:
			return fmt.Errorf("destination port is required")
		}
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
	spec, err := p.ValidateSpec(spec)
	if err != nil {
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
			// 事件级 flow 标识（波 5c）：终结层事件可携带 FlowID/PacketIndex
			// 覆盖（rip legacy 每 router 独立 flowID、request_full 共享 0/1）——
			// 两者成对，FlowID 非空即事件已覆盖，回填尊重之（否则默认回填
			// spec 级 flowID + 全局递增索引）。MessageEvent 无独立标记位，
			// 以 FlowID=="" 判别（udp 层把事件字段直落 PacketConfig，见
			// generator.go UDPGenerator）。
			if packets[i].FlowID == "" {
				packets[i].FlowID = flowID(spec)
				packets[i].PacketIndex = uint64(i)
			}
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
				if outerHas(chain, i, dep) {
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
		// DNS/NTP/SNMP/Syslog 同款（波 4）：协议配置经 Meta 直传终结层生成器。
		// MDNS 同款（波 5a）。SSDP 同款（波 5b）：配置 + 默认端口经 Meta 直传
		// ssdp 层生成器（端口 validateSpecBase 已默认化 1900）。
		HTTP:   spec.HTTP,
		UDP:    spec.UDP,
		DNS:    spec.DNS,
		NTP:    spec.NTP,
		SNMP:   spec.SNMP,
		Syslog: spec.Syslog,
		MDNS:   spec.MDNS,
		SSDP:   spec.SSDP,
		RIP:    spec.RIP,
		DHCP:   spec.DHCP,
		// DHCPv6 同款（波 5e）：配置经 Meta 直传 dhcpv6 层生成器（DUID/
		// scenario/relay 解析全部在生成器内，planner.go Plan 同款）。
		DHCPv6:  spec.DHCPv6,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
		DstIP:   spec.DstIP,
		SrcIP:   spec.SrcIP,
		// DSCP/SrcMAC 直传终结层生成器（波 5c：rip 生成器透传 spec.DSCP——
		// legacy rip.go:494-498 的 CS6 默认是死参数——与 L2Base 的
		// spec.SrcMAC）。
		DSCP:   spec.DSCP,
		SrcMAC: spec.SrcMAC,
		// DstMAC 直传终结层生成器（波 5d：dhcp 生成器 resolveMACs 缺省回退
		// BroadcastMAC 前的 spec.DstMAC，与 role!=client 的 chaddr 回退）。
		DstMAC: spec.DstMAC,
		// TTL 直传终结层生成器（波 5b）：ssdp 生成器 honor spec.TTL 非零值
		// （legacy planner.go:282-285 同款），零值回退协议默认 4。
		TTL: spec.TTL,
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
		// 波 5 多播覆盖：udp 层事件显式写入 L3.DstIP/L2.DstMAC（多播组/
		// 广播地址）时，同时写 Metadata[eventDstOverrideKey] 标记，该目标
		// 是绝对的——不参与 down 交换，MAC 也原样落（多播/广播 MAC 不可
		// 推导或须保持 legacy 显式值）。无覆盖事件（波 3/4 协议）无标记，
		// 走下方 legacy 语义。标记消费后移除，不泄漏到输出元数据。
		_, overrideDst := pkt.Metadata[eventDstOverrideKey]
		if overrideDst {
			delete(pkt.Metadata, eventDstOverrideKey)
			if pkt.L2.DstMAC == "" {
				pkt.L2.DstMAC = multicastDstMAC(pkt.L3.DstIP)
				if pkt.L2.DstMAC == "" {
					pkt.L2.DstMAC = l2For(pkt.Direction, spec).DstMAC
				}
			}
			// 事件级源 MAC（波 5d：dhcp down 方向 reply 源 MAC 按角色交换/
			// 回退，udp 层已写入事件值）；空（无覆盖事件）→ spec.SrcMAC。
			if pkt.L2.SrcMAC == "" {
				pkt.L2.SrcMAC = spec.SrcMAC
			}
			pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
		} else {
			pkt.L2 = l2For(pkt.Direction, spec)
			// 方向相关 src/dst 交换 + flow 级字段。IPID 已由 ip 层生成器写入
			// （每次 Emit 前写入并自增），这里只换 IP 不换 ID。
			if pkt.Direction == "down" {
				pkt.L3.SrcIP, pkt.L3.DstIP = pkt.L3.DstIP, pkt.L3.SrcIP
			}
			pkt.L3.TTL = ipTTL(ipCfg)
		}
		// L3 协议号随传输层（tcp=6 / udp=17；legacy L3Base 语义）。
		// 传输层是链上 ip 之下最后一层：独立 tcp/udp flow 的末层，
		// 或终结层链（http/dns...）的倒数第二层。
		pkt.L3.Protocol = transportProtocol(chain)
		// TTL 已按分支赋值（覆盖事件保留 udp 层写入的 255，普通包走
		// ipTTL）；TOS 整字节覆盖（review HIGH-2 修复，legacy L3Base
		// builder.go:158-161 语义）：spec.TOS != 0 时 DSCP=TOS>>2、
		// ECN=TOS&3，覆盖 DSCP/ECN 直配。
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
				// 波 5c：rip 链 spec.DstIP 为空时不删 schema 默认——RIP 生成器
				// 按版本推导默认目标（v1/v2→224.0.0.9、ng→FF02::9），事件级
				// 覆盖后 ip 层 dst 覆盖被标记跳过，schema 默认只服务最终回退。
				// 波 5d：dhcp 链同款——DHCP 生成器按角色推导默认目标（缺省
				// 广播 255.255.255.255，resolveIPs 语义），事件级覆盖后 ip 层
				// dst 覆盖同样被标记跳过，schema 默认只服务最终回退。
				if !isRIPChain(chain) && !isDHCPChain(chain) && !isDHCPv6Chain(chain) {
					delete(cfg, "dst")
				}
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
			// 终结层链（[ip→udp→dns/ntp/snmp/syslog]，波 4）同款注入：
			// udp 层生成器从层 config 读端口装配数据报（src/dst 换向用
			// cfg.srcPort/dstPort，validateSpecBase 已默认化终结层协议端口）。
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

// isRIPChain reports whether the chain's terminal layer is rip（波 5c）：
// RIP 链的 ip 层 dst 默认注入豁免（spec.DstIP 为空时保留 schema 默认，RIP
// 生成器按版本推导默认目标并事件级覆盖，见 applySpecToChain ip 分支）。
func isRIPChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "rip"
}

// isDHCPChain reports whether the chain's terminal layer is dhcp（波 5d）：
// DHCP 链的 ip 层 dst 默认注入豁免（spec.DstIP 为空时保留 schema 默认，DHCP
// 生成器按角色推导默认目标——缺省广播 255.255.255.255，resolveIPs 语义——
// 并事件级覆盖，见 applySpecToChain ip 分支）。
func isDHCPChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "dhcp"
}

// isDHCPv6Chain reports whether the chain's terminal layer is dhcpv6（波 5e）：
// DHCPv6 链的 ip 层 dst 默认注入豁免（spec.DstIP 为空时保留 schema 默认，
// DHCPv6 生成器按 legacy resolveAddrs 语义取 spec.DstIP 直配——IPv6 目的
// 恒为 spec 值，无广播/组播推导——与 dhcp 同构，见 applySpecToChain ip 分支）。
func isDHCPv6Chain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "dhcpv6"
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
// 波 2 方案 A: + http，由 protocol/http 包提供生成器；波 4: + dns/ntp/snmp/
// syslog，由各自协议包经 RegisterLayerGenerator 反向注册)。
func newGenerator(name string) (LayerGenerator, error) {
	// 测试注入的生成器优先（测试终结层等）。
	testGenMu.RLock()
	factory, ok := testGenerators[name]
	testGenMu.RUnlock()
	if ok {
		return factory()
	}
	// 生产终结层生成器（协议包 init 反向注册，如 http/dns/ntp/snmp/syslog）。
	if factory, ok := registeredGenerators[name]; ok {
		return factory()
	}
	if name == "http" {
		// http 层生成器实现在 protocol/http 包（newHTTPGenerator），
		// 避免 layers → protocol/http 的依赖环（http 依赖 core + layers）。
		return newHTTPGenerator()
	}
	switch name {
	case "ip":
		return &IPGenerator{}, nil
	case "tcp":
		return &TCPGenerator{}, nil
	case "udp":
		return &UDPGenerator{}, nil
	}
	return nil, fmt.Errorf("layers: generator not implemented for layer %q", name)
}

// registeredGenerators holds production terminal-layer generator factories
// (生产终结层生成器工厂，由协议包 init 经 RegisterLayerGenerator 注册；
// 反向注册避免 layers → protocol 包的依赖环，同 http 的
// RegisterHTTPGenerator 模式)。注册表只读于链驱动路径（init 期写完后
// 不变），无需锁；测试注入走独立的 testGenerators（testGenMu 保护）。
var registeredGenerators = map[string]func() (LayerGenerator, error){}

// RegisterLayerGenerator installs a terminal-layer generator factory
// (注册终结层生成器工厂，由协议包在 init 中调用；波 4 泛化自 http 的
// RegisterHTTPGenerator——http 保留其专用接口以兼容既有调用方)。
func RegisterLayerGenerator(name string, factory func() (LayerGenerator, error)) {
	registeredGenerators[name] = factory
}

// registeredValidators holds production terminal-layer spec validators
// (协议级 spec 校验器，由协议包 init 经 RegisterLayerValidator 注册；
// 校验器接收默认化后的 spec，只校验不修改。未注册校验器的层跳过)。
var registeredValidators = map[string]func(*core.FlowSpec) error{}

// RegisterLayerValidator installs a terminal-layer spec validator
// (注册终结层 spec 校验器，由协议包在 init 中调用；波 4 起 ChainPlanner
// 用它复刻 legacy 各 planner 的 Validate 协议配置检查)。
func RegisterLayerValidator(name string, v func(*core.FlowSpec) error) {
	registeredValidators[name] = v
}

// protocolValidator returns the registered validator for a layer, or nil.
func protocolValidator(name string) func(*core.FlowSpec) error {
	return registeredValidators[name]
}

// NewLayerGenerator returns a fresh generator for a registered layer
// (等价 newGenerator 的注册表路径，供协议包测试与内部使用)。
func NewLayerGenerator(name string) (LayerGenerator, error) {
	factory, ok := registeredGenerators[name]
	if !ok {
		return nil, fmt.Errorf("layers: generator %q not registered (protocol package not imported)", name)
	}
	return factory()
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
// VLAN 传播（波 4）：spec.VLAN 在终结层链（ntp，legacy planner 显式写
// spec.VLAN）传播，为统一语义 dns/snmp/syslog 链同样传播（legacy 丢弃，
// 已声明行为分歧）；独立 tcp/udp 链 legacy 不写 VLAN（tcp.go/udp.go/
// http.go/dns.go/snmp.go 均无 VLAN），保持不变。
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
	if spec.VLAN != nil {
		l2.VLAN = spec.VLAN
	}
	return l2
}

// multicastDstMAC derives the L2 multicast MAC from a multicast/broadcast IP
// (波 5 多播基础设施, RFC 1112 §6.4 IPv4 / RFC 2464 §7 IPv6)：IPv4 multicast
// → 01:00:5e + low 23 bits; IPv6 multicast → 33:33 + low 32 bits; broadcast
// 255.255.255.255 → ff:ff:ff:ff:ff:ff; non-multicast → empty (caller falls
// back to l2For). 与 legacy mdns planner 的 multicastDstMAC / ssdp planner
// resolveMulticastMAC / dhcp BroadcastMAC 语义一致。
func multicastDstMAC(dstIP string) string {
	parsed := net.ParseIP(dstIP)
	if parsed == nil {
		return ""
	}
	if ip4 := parsed.To4(); ip4 != nil {
		if ip4[0] >= 224 && ip4[0] <= 239 {
			low23 := (uint32(ip4[1]&0x7f) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
			return fmt.Sprintf("01:00:5e:%02x:%02x:%02x",
				byte(low23>>16), byte(low23>>8), byte(low23))
		}
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return "ff:ff:ff:ff:ff:ff"
		}
		return ""
	}
	if len(parsed) == 16 && parsed[0] == 0xff {
		low32 := (uint32(parsed[12]) << 24) | (uint32(parsed[13]) << 16) |
			(uint32(parsed[14]) << 8) | uint32(parsed[15])
		return fmt.Sprintf("33:33:%02x:%02x:%02x:%02x",
			byte(low32>>24), byte(low32>>16), byte(low32>>8), byte(low32))
	}
	return ""
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
