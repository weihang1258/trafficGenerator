package layers

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Package layers is part of the layer-chain architecture (v3) for
// the trafficgen core. This file is one of the five chain_planner*.go
// files split from the original monolithic chain_planner.go
// (T1.3 of docs/superpowers/plans/2026-09-03-layerchain-implementation.md).
//
// Original file: 2,893 lines (5 sections, 65 functions).
// This file: chain_planner_chain.go
//   - Chain completion, validation, generator instantiation, applySpecToChain (chain lifecycle).
//
// Per-package conventions: type names (ChainPlanner, FlowMeta, etc.)
// are package-local; only file boundaries change.

func flowMetaFor(spec core.FlowSpec) FlowMeta {
	// CksumEngine 恒挂（T3.3）：IPCksumComputer 无状态、零成本，端到端
	// 校验器/集成测试经 Meta.CksumEngine 复算 IPv4 头校验和与伪头求和
	// （生成路径的 builder 内联计算不变，此句柄只作对拍用途）。
	return FlowMeta{
		SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC,
		SV: spec.SV, GOOSE: spec.GOOSE, ISIS: spec.ISIS,
		FlowIndex: spec.FlowIndex,
		CksumEngine: NewIPCksumComputer(),
	}
}

// flowID mirrors the legacy per-flow ID format// "srcIP-dstIP-srcPort-dstPort"（每 flow 唯一标识）。
func flowID(spec core.FlowSpec) string {
	return fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
}

// completedChain completes the derived chain and validates it, applying the
// V4/V5 exemption for the synthesized chain (末层即协议层本身)。Result is
// cached — a pure function of (name, chain, registry); callers must not
// mutate the returned slice or its layers' Config maps (applySpecToChain
// copies per-Plan, so the cached chain is never written).
func (p *ChainPlanner) completedChain() ([]Layer, error) {
	p.mu.Lock()
	if p.completed != nil || p.completedErr != nil {
		chain, err := p.completed, p.completedErr
		p.mu.Unlock()
		return chain, err
	}
	p.mu.Unlock()
	chain, err := p.completedChainUncached()
	p.mu.Lock()
	p.completed, p.completedErr = chain, err
	p.mu.Unlock()
	return chain, err
}

func (p *ChainPlanner) completedChainUncached() ([]Layer, error) {
	r := p.effectiveRegistry()
	// P2c: user-supplied chain — already completed+validated by ValidateLayers
	// (BuildLayersPlanner 补全后传入, CRITICAL-1 修复)。Generator precheck runs
	// here so a chain containing a layer with no implemented generator fails
	// Plan synchronously (不静默空流).
	if p.chain != nil {
		if len(p.chain) == 0 {
			return nil, fmt.Errorf("layers: empty layer chain")
		}
		for _, l := range p.chain {
			if _, err := newGenerator(l.Name); err != nil {
				return nil, err
			}
		}
		return p.chain, nil
	}
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
// 协议层本身)。Synthesized chains start from a bare protocol name and carry
// no config, so no layer config can be lost.
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

// completeChainPreservingConfig completes a USER-written chain manually for
// the V4-exempt single-layer case (P2c): same depends_on-outward insertion as
// completeSynthesized, but the user's original layer config is preserved on
// its layer (completeSynthesized starts from a bare protocol name and would
// drop it). Called when CompleteChain rejects the chain only on the
// terminal-layer rule; the completed chain drives generation (BuildLayersPlanner),
// so dropping config would silently generate schema-default packets.
func completeChainPreservingConfig(r *Registry, user []Layer) []Layer {
	chain := make([]Layer, len(user))
	copy(chain, user)
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
// T13 泛化：transport 按生成器类型定位（tls 链 [ip→tcp→tls→http] 的 tcp 在
// index 1，不在 len-2——tls 是 transport 之内的事件变换器，不产包）；终结层
// 与 transport 之间的每层必须是事件变换器（EventTransformer 标记），否则
// 结构性错误同步拒绝（变换器不实现标记会在 drive 静默透传/关闭事件流）。
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
	transportIdx := transportIndex(gens)
	if transportIdx < 0 {
		// 链中无 TCP/UDP 生成器：终结层相邻内层（len-2）必须能消费事件。
		// 旧语义（波 3）：该位置不是 tcp/udp → "cannot consume terminal
		// events"。transportIndex 找不到时必然走 default（否则就会找到）。
		return fmt.Errorf("layers: layer %q cannot consume terminal events (unsupported transport generator %T)",
			chain[len(chain)-2].Name, gens[len(chain)-2])
	}
	// 终结层与 transport 之间的层必须是事件变换器（tls）。
	for i := transportIdx + 1; i < len(chain)-1; i++ {
		tr, ok := gens[i].(EventTransformer)
		if !ok || !tr.TransformEvents() {
			return fmt.Errorf("layers: layer %q cannot transform terminal events (unsupported transformer %T)",
				chain[i].Name, gens[i])
		}
	}
	return nil
}

// transportIndex returns the index of the transport generator (tcp/udp) in
// gens, or -1. 类型扫描而非 len-2 定位：tls 隧道链 [ip→tcp→tls→http] 的
// len-2 是 tls（TLS record 是 TCP payload，tls 在 tcp 之内），传输层按
// 生成器类型唯一确定。
func transportIndex(gens []LayerGenerator) int {
	for i, gen := range gens {
		switch gen.(type) {
		case *TCPGenerator, *UDPGenerator:
			return i
		}
	}
	return -1
}

// layerNames renders the chain names for error messages.
func layerNames(chain []Layer) string {
	names := make([]string, len(chain))
	for i, l := range chain {
		names[i] = l.Name
	}
	return "[" + strings.Join(names, " → ") + "]"
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
			// 的 ip 层 Config 恒为 nil，delete 无对象可删；用户手写链（P2c，
			// NewChainPlannerFromChain 的 p.chain）的 ip 层 config 也可能含
			// 用户显式 src/dst——spec.SrcIP 空时 delete 会移除它们。用户链
			// 的 ip 层 config 由 ValidateLayers 校验（V9 字段范围），spec 空
			// IP 时删掉层 config 的 src/dst 与 legacy "spec IP 空 → L3 空"
			// 语义一致（用户要固定 IP 应在 flat spec 写 src_ip）。
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
			// ftp 链强制并发会话语义（mms/cwmp 同款）：FTP 多会话/数据通道
			// 靠事件 SrcPort/DstPort 覆盖合成独立 connKey；concurrent=true
			// 使 tcp 层按 key 独立建连/恢复 seq/流末统一挥手。termination
			// 保持 true，会话/数据 CloseConn 内联挥手（sawEvent 守卫防双 FIN）。
			if isFTPChain(chain) {
				cfg["concurrent"] = true
			}
			// mms 链强制并发会话语义（同 http 链强制 legacy 模式）：MMS 关联
			// 会话不挥 TCP 手（设计 §6.1 connect_establish 7 帧止于 DT2；所有
			// case 包数均不含 FIN），multiSession 是并发会话（按 SrcPort 保持
			// 独立连接，事件循环恢复 seq 状态）。层链 case（cases/mms.json）
			// 没有顶层 tcp 子映射 → spec.TCP 为 nil，注入必须在 nil 检查之外。
			if isMMSChain(chain) {
				if t := spec.TCP; t != nil {
					if t.MSS != 0 {
						cfg["mss"] = uint16(t.MSS)
					}
					if t.WindowSize != 0 {
						cfg["window_size"] = uint16(t.WindowSize)
					}
					if t.InitialSeq != 0 {
						cfg["initial_seq"] = t.InitialSeq
					}
				}
				cfg["termination"] = false
				cfg["concurrent"] = true
			}
			// cwmp 链强制并发会话语义（isMMSChain 同款）：两种触发——
			// (a) spec.CWMP.Flows 存在：flows[] 副连接在主会话事件流中途插入
			// 独立四元组（副连接 GET/PUT + CloseConn 挥手），顺序挥旧握新语义
			// 会把副连接与主会话搅成同一连接状态；per-connKey 并发恢复才是
			// 正确语义（设计 §5 流关联）。(b) spec.CWMP.Concurrent：生成器按
			// 事务索引 round-robin 交织多会话事件（用例 #96 cwmp_concurrent_
			// sessions），tcp 层若仍是顺序挥旧握新，每次交织切换都 teardown+
			// 重握手（事件数 ×7 包风暴，双会话 4 事件实测 64 包而非 22）。
			// 这里的竞争是同一 chain planner 内的串行事件流（生成器侧
			// round-robin 交织由 cwmp layer_gen 发射顺序决定，tcp 层按 key
			// 恢复 seq——非并发锁竞争），concurrent=true 仅切换连接状态索引方式。
			if isCWMPChainWithFlows(chain) && spec.CWMP != nil &&
				(len(spec.CWMP.Flows) > 0 || spec.CWMP.Concurrent) {
				cfg["concurrent"] = true
			}
			// nmea 链会话级 termination:"rst" 翻译（69-nmea §5 正例 46）：
			// 任一会话声明 rst 即切 tcp 层 RST 形态——rst=true 使
			// TCPGenerator 以单帧 RST|ACK(up) 短路收尾（3+N+1），并关
			// termination 抑制 FIN 挥手分支。默认（无声明）保持 FIN：
			// 3+N+4（回归护栏 TestNMEAChainDefaultStillFINTeardown）。
			if len(chain) > 0 && chain[len(chain)-1].Name == "nmea" && nmeaSessionRST(spec.NMEA) {
				cfg["rst"] = true
				cfg["termination"] = false
			}
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
				// T3.3 retransmit：spec.TCP.Retransmit → tcp 层开关。
				cfg["retransmit"] = t.Retransmit
			}
		}
		out[i] = Layer{Name: l.Name, Config: cfg}
	}
	return out
}
