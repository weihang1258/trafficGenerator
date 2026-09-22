package layers

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Package layers is part of the layer-chain architecture (v3) for
// the trafficgen core. This file is one of the five chain_planner*.go
// files split from the original monolithic chain_planner.go
// (T1.3 of docs/superpowers/plans/2026-09-03-layerchain-implementation.md).
//
// Original file: 2,893 lines (5 sections, 65 functions).
// This file: chain_planner.go
//   - ChainPlanner struct + Validate + ValidateSpec + validateSpecBase + Plan (top-level driver).
//
// Per-package conventions: type names (ChainPlanner, FlowMeta, etc.)
// are package-local; only file boundaries change.

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

// doipPort is the DoIP TCP/UDP service port (ISO 13400-2 §7, 13400)。
// layers 包内复刻（不能引用 protocol/doip 的 DefaultTCPPort——protocol 包
// 反向依赖 layers）。
const doipPort = 13400

// gbtPort is the GBT32960 platform listener port (GB/T 32960.3-2016,
// 10020)。layers 包内复刻（不能引用 protocol/gbt32960 的 DefaultPort——
// protocol 包反向依赖 layers）。
const gbtPort = 10020

// mcpStdioPort is the MCP stdio default port (22, plan.go:61-68 同款)。
// layers 包内复刻（不能引用 protocol/mcp 的 DefaultPortStdio——protocol 包
// 反向依赖 layers）。
const mcpStdioPort = 22

// mcpHTTPPort is the MCP HTTP-mode default port (8081, plan.go:61-68 同款：
// http_sse / streamable 共用)。
// layers 包内复刻（不能引用 protocol/mcp 的 DefaultPortHTTP——protocol 包
// 反向依赖 layers）。
const mcpHTTPPort = 8081

// nfsPort is the NFS service port (RFC 5531 §9 / RFC 1813, 2049)。
// layers 包内复刻（不能引用 protocol/nfs 的 DefaultPort——protocol 包反向
// 依赖 layers）。
const nfsPort = 2049

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
	// chain is the user-supplied layer chain (P2c: 策略 config 的 layers 键，
	// 经 ValidateLayers 解析+补全后得到). nil = derive the chain from the
	// protocol name (legacy synthesized chain). 用户链同样适用 V4 单层豁免
	// （[tcp] 合法，末层即协议层）——BuildLayersPlanner 负责豁免补全并传入
	// 已完成链，ChainPlanner 只驱动、不重补。
	chain []Layer
	// registry is the registry used to complete/validate the chain; nil =
	// DefaultRegistry (测试注入自定义注册表时经 NewChainPlannerWithRegistry 指定)。
	registry *Registry
	// completed caches completedChain() (T23: it re-derived + revalidated the
	// chain on every Plan — pure function of name/chain/registry, so cached
	// under mu; Plan may run concurrently on one planner instance from
	// multiple engine workers).
	mu           sync.Mutex
	completed    []Layer
	completedErr error
}

// NewChainPlanner creates a chain planner for the named protocol layer.
func NewChainPlanner(name string) *ChainPlanner {
	return &ChainPlanner{name: name}
}

// NewChainPlannerFromChain creates a chain planner driven by a user-supplied
// layer chain (P2c 层链驱动生成). The chain is the completed+validated output
// of ValidateLayers — re-completion is not needed, but the generator
// precheck and event-wiring checks still run at Plan time. The planner's
// name is the strategy protocol (whitelist key); generation is driven by the
// chain, so name and chain's outermost layer may differ for tunnel chains
// (e.g. name "gre" + chain [ip, gre, ip, tcp, http]).
func NewChainPlannerFromChain(name string, chain []Layer) *ChainPlanner {
	return &ChainPlanner{name: name, chain: chain}
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
	// P2c-3 终结层配置翻译（layers 数组的层 config → spec 协议配置）：
	// 生成器契约是"读已补全的层 config，不读原始 FlowSpec"（generator.go），
	// 但 http/dns 终结层生成器实际读 req.Meta.HTTP/req.Meta.DNS（= spec 值），
	// 而 flat 路径（strategy_convert mapToFlowSpec）只读 cfg["http"]/cfg["dns"]
	// 子映射——layers 数组中的层 config 从不被翻译，{"http":{"method":"POST"}}
	// 静默回退 GET /、{"dns":{}} 验证失败 "DNS config is required"
	// （validate_layers.go:112-115 的 validated-but-not-yet-effective）。
	// 翻译必须在协议级 validator 之前：dns validator 要求 spec.DNS 非 nil，
	// worker.go:218 的 planner.Validate(task.Spec) 先于 Plan 运行。
	p.translateTerminalConfig(&spec)
	// 协议级校验（波 4 起）：终结层协议包经 RegisterLayerValidator 注册
	// 其 Validate（如 dns 包对 DNSConfig 的检查），链上未注册校验器的层
	// 跳过。校验器只校验不默认化（默认化由 validateSpecBase 统一负责）。
	if v := protocolValidator(p.name); v != nil {
		if err := v(&spec); err != nil {
			return spec, err
		}
	}
	chain, err := p.completedChain()
	if err != nil {
		return spec, err
	}
	// 层值回填 spec（Task 6 修正）：用户在 tcp/udp 层显式写的 src_port/
	// dst_port 是链形状的四元组真相，spec 侧在 Task 5 扁平判死后恒为
	// mapToFlowSpec 的缺省值（12345/80 或 worker 自动递增基址）——不回填
	// 则 flowID/包序列/事件 key 三者端口分裂（txindex_dual 实测首包
	// 12345 而非层值 22000）。仅当层内显式写（非 nil）时回填；层内 dyn
	// 对象（map）跳过——dyn 由 worker.resolveLayerTuple 按流解析进 spec，
	// 此处是单 spec 默认化，不得抢占逐流值。
	for _, l := range chain {
		if l.Name != "tcp" && l.Name != "udp" {
			continue
		}
		if v, ok := l.Config["src_port"]; ok && v != nil {
			if _, isObj := v.(map[string]interface{}); !isObj {
				if up, ok := configUint16(v); ok && up != 0 {
					spec.SrcPort = up
				}
			}
		}
		if v, ok := l.Config["dst_port"]; ok && v != nil {
			if _, isObj := v.(map[string]interface{}); !isObj {
				if up, ok := configUint16(v); ok && up != 0 {
					spec.DstPort = up
				}
			}
		}
	}
	// 链上 vlan 层 → spec.VLAN（D-GRE-3 通用路径）：tag 落定走既有 l2For
	// 的 spec.VLAN 传播分支（chain_planner_gen.go:207），本处只做供给。
	// 层值赢 flat（spec.VLAN 已由 mapToFlowSpec 从顶层 vlan_id 填）：补全链
	// 首个 vlan 层显式值覆盖；缺席不动（flat legacy 语义保留）。出现即打
	// tag（含 id=0：OptionalOn 已保证不写层即无 tag，写了就是显式意图）。
	for _, l := range chain {
		if l.Name != "vlan" {
			continue
		}
		// 缺键（id 未写）= 不启用，不动 spec（flat legacy 语义保留）；
		// id 显式写（含 0）= 启用覆盖。V9 已保范围（0..4095/0..7）。
		// 此处读的是补全链 Config（含 schema 默认）：{"vlan":{}} 空配置
		// complement 后 Config 恒空 map（BuildLayersPlanner 传原始用户层，
		// 默认注入只发生在 applySpecToChain 的副本 cfg，不回写链）——缺键
		// 即用户没写，不误触发。
		rawID, hasID := l.Config["id"]
		if !hasID || rawID == nil {
			break
		}
		id, idOK := configUint16(rawID)
		if !idOK {
			break
		}
		prio, _ := configUint8(l.Config["priority"])
		spec.VLAN = &core.VLAN{ID: id, Priority: prio}
		break
	}
	// 链上 ip 层 hop_by_hop → spec.HopByHop（D-SRV6-1 通用路径）：扁平键
	// 判死后 HBH 的住处是 ip 层（vlan 先例）；消费点 spec.HopByHop 既有
	// （finalEmit/raw-IP 驱动写 L3，builder 装配 NH=0 链）。读用户原始层
	// （BuildLayersPlanner 传原始用户层，缺键即用户没写，不误触发）；
	// 层值赢 flat（spec.HopByHop 已由 mapToFlowSpec 从顶层 hop_by_hop 填，
	// 扁平判死后该路径消亡，回填恒为唯一供给）。
	for _, l := range chain {
		if l.Name != "ip" {
			continue
		}
		if v, has := l.Config["hop_by_hop"]; has && v != nil {
			spec.HopByHop = core.ParseHopByHopOptions(v)
		}
		break
	}
	// 隧道结构性校验（P2e T12 review HIGH-2 起；D-GRE-2 重写 gre 专属；
	// D-GRE-3 泛化为通用隧道块——用户裁定 A：拼积木归位框架）。
	// 触发 = 链上任一 CategoryTunnel 层其直接内层邻居是 ip（gre 形）。
	// tls 链天然豁免（tls 后是终结层非 ip，不触发；tls 自有下段版本/角色块）。
	// 外层（spec 地址=首个 ip 层）与内层（内层 ip 层显式 src/dst，缺席回退
	// spec 值）各自必须非空、可解析、两地址同族；**外内族可异**（4in6/6in4
	// 合法，D-GRE-2 §4 矩阵）。必须在此同步拒绝——drive 期生成器报错会被
	// Plan goroutine 吞成 0 包空流（既有契约），调用方拿到空流而非明确错误。
	// 锚词子串与 D-GRE-2 一致（前缀 gre chain: → tunnel chain:；用例
	// error_contains 全是子串，不断言前缀，不漂移）。
	r := p.effectiveRegistry()
	for i, l := range chain {
		schema, ok := r.Get(l.Name)
		if !ok || schema.Category != CategoryTunnel {
			continue
		}
		if i+1 >= len(chain) || chain[i+1].Name != "ip" {
			continue
		}
		if spec.SrcIP == "" || spec.DstIP == "" {
			return spec, fmt.Errorf("tunnel chain: outer ip addresses required (tunnel endpoints come from the outer ip layer)")
		}
		inSrc, inDst := spec.SrcIP, spec.DstIP
		if v, ok := chain[i+1].Config["src"].(string); ok && v != "" {
			inSrc = v
		}
		if v, ok := chain[i+1].Config["dst"].(string); ok && v != "" {
			inDst = v
		}
		for _, pair := range []struct{ name, val string }{{"src", inSrc}, {"dst", inDst}} {
			if net.ParseIP(pair.val) == nil {
				return spec, fmt.Errorf("tunnel chain: inner ip layer %s %q is not a valid IP address", pair.name, pair.val)
			}
		}
		if s, d := net.ParseIP(inSrc), net.ParseIP(inDst); (s.To4() != nil) != (d.To4() != nil) {
			return spec, fmt.Errorf("tunnel chain: inner ip layer addresses %s/%s must be the same IP version", inSrc, inDst)
		}
		break
	}
	// 隧道层（tls）结构性校验（P2e T13）：层链只实现 tls1.3 client 快速路径
	// （TLSGenerator 的握手 record 序列 = legacy tls1.3 fast path）。其它版本
	// /角色在链上无实现，必须在此同步拒绝（同 gre HIGH-2 先例：生成器运行时
	// 报错被 drive 吞成 0 包空流）。
	for _, l := range chain {
		if l.Name != "tls" {
			continue
		}
		cfg := l.Config
		version, _ := cfg["version"].(string)
		if version == "" {
			version = "tls1.3"
		}
		if version != "tls1.3" {
			return spec, fmt.Errorf("tls chain: version %q not supported in the layer chain yet (only \"tls1.3\")", version)
		}
		role, _ := cfg["role"].(string)
		if role == "" {
			role = "client"
		}
		if role != "client" {
			return spec, fmt.Errorf("tls chain: role %q not supported in the layer chain yet (only \"client\")", role)
		}
		// SNI 长度上限 253（RFC 1035；legacy Validate 同款，测试点 4.2.1）：
		// 超长 SNI 使扩展块超 uint16 时 buildClientHello 截断，产出非法
		// ClientHello（review tls-layer finding 2）。
		if sni, _ := cfg["sni"].(string); len(sni) > 253 {
			return spec, fmt.Errorf("tls chain: SNI length %d exceeds max 253 bytes (RFC 1035)", len(sni))
		}
		// ALPN 协议名单字节长度前缀（buildALPNExtension 的 byte(len)），
		// 协议名 >255 字节必然截断，同步拒绝（同 finding 2）。
		if alpn, _ := cfg["alpn"].([]interface{}); alpn != nil {
			for _, v := range alpn {
				s, _ := v.(string)
				if len(s) > 255 {
					return spec, fmt.Errorf("tls chain: ALPN protocol name length %d exceeds max 255 bytes", len(s))
				}
			}
		}
		// D-TLS-2: cert 结构性校验。cert 缺席=全默认（合法）；cert 非对象
		// （字符串/数字）→ 同步拒绝；子键枚举在本地做，业务约束（key_type
		// 枚举/日期/SAN/DN）在 tls 层生成器侧（parseCertConfig + validate，
		// 单真相——layers 不 import protocol/tls，core 反向依赖禁忌）。
		// 动态对象（subject/san 的 strategy map）在 ValidateLayers 已下钻
		// 校验+剥离，到这里只剩标量——对象残留（key_type 等关字段/引擎直调）
		// 同步拒绝，不静默跳过。
		if rawCert, hasCert := cfg["cert"]; hasCert && rawCert != nil {
			certMap, isObj := rawCert.(map[string]interface{})
			if !isObj {
				return spec, fmt.Errorf("tls chain: cert must be an object")
			}
			for k, v := range certMap {
				switch k {
				case "subject", "key_type", "not_before", "not_after":
					if _, ok := v.(string); !ok {
						if isDynObject(v) && k == "subject" {
							continue // 开字段动态对象：ValidateLayers 已校验
						}
						return spec, fmt.Errorf("tls chain: cert.%s must be a string", k)
					}
				case "san":
					switch t := v.(type) {
					case string:
						_ = t
					case []interface{}:
						for _, item := range t {
							if _, ok := item.(string); !ok {
								return spec, fmt.Errorf("tls chain: cert.san must be a string or string array")
							}
						}
					default:
						if isDynObject(v) {
							continue // 开字段动态对象
						}
						return spec, fmt.Errorf("tls chain: cert.san must be a string or string array")
					}
				default:
					return spec, fmt.Errorf("tls chain: cert: unknown field %q", k)
				}
			}
			if msg := validateTLSCertScalars(certMap); msg != "" {
				return spec, fmt.Errorf("%s", msg)
			}
		}
		break
	}
	// FINS carrier validation: TCP carries Frame Send envelopes; UDP carries raw FINS frames.
	for _, l := range chain {
		if l.Name != "fins" {
			continue
		}
		carrier := "tcp"
		if len(chain) > 1 && chain[len(chain)-2].Name == "udp" {
			carrier = "udp"
		}
		t, _ := finsTransportFromMetadata(spec.Metadata["fins"])
		if t == "" {
			t = carrier
			setFinsTransport(spec.Metadata["fins"], carrier)
		}
		if carrier != t {
			return spec, fmt.Errorf("fins chain: %s carrier requires fins transport %q (got %q)", carrier, carrier, t)
		}
		break
	}
	// NFS 载体一致性结构性校验（P4a）：NFS 是双载体终结层——tcp 载体产
	// RM 记录标记帧（默认），udp 载体产裸 RPC 数据报。链的载体（末层 nfs
	// 时看倒数第二层）必须与 spec.Metadata["nfs"] 的 transport 一致，否则是
	// **结构性**错误，必须在此同步拒绝（同 gre/tls HIGH-2 先例：drive 期
	// 生成器报错会被 Plan goroutine 吞成 0 包空流）。校验读链载体 + 元数据
	// transport 字符串（不 import protocol/nfs，nfsTransportFromMetadata），
	// 缺省按 legacy 默认 "tcp"（planSession 438-441 同款）判定：
	//   - tcp 载体 + transport "udp" → 拒绝（与 udp 载体 + "tcp" 对称）。
	//   - udp 载体 + transport 缺省/""/"tcp" → 拒绝：空串按 legacy 默认
	//     "tcp" 处理，会把 TCP RM 记录标记字节写进 UDP 数据报（对 UDP 载荷
	//     是非法字节）——UDP 载体必须显式 transport "udp"（legacy
	//     nfs_test.go TestNFS3UDP 同款显式设置）。
	for _, l := range chain {
		if l.Name != "nfs" {
			continue
		}
		carrier := "tcp"
		if len(chain) > 1 && chain[len(chain)-2].Name == "udp" {
			carrier = "udp"
		}
		t, _ := nfsTransportFromMetadata(spec.Metadata["nfs"])
		if t == "" {
			t = "tcp" // legacy Plan 同款默认（planSession 438-441）
		}
		if carrier == "udp" && t != "udp" {
			return spec, fmt.Errorf("nfs chain: udp carrier requires nfs transport \"udp\" (got %q; empty defaults to \"tcp\" which would write TCP record-mark bytes on a UDP datagram)", t)
		}
		if carrier == "tcp" && t == "udp" {
			return spec, fmt.Errorf("nfs chain: nfs transport \"udp\" requires a udp carrier (chain carrier is tcp)")
		}
		break
	}
	// PostgreSQL carrier + port validation (P0a 共享 PG v3 wire 层，depends_on=tcp)。
	// 端口由 postgresql 层 FieldContract 驱动（design §1.3/§10.3 R1）：
	//   - dialect=postgresql → tcp.dst_port=5432；dialect=kingbase → 54321。
	//   - 用户显式写 tcp.dst_port 时，域校验强制等于该 dialect 的契约端口
	//     （§1.6 "优先级 vs 领域校验"：超出合法值域仍由 validator 拒绝）——
	//     dialect=kingbase 下写 54322 → 拒绝，报错含 "54321"。
	//   - 未显式写时，把 spec.DstPort 设为契约端口（applySpecToChain 据此装配
	//     tcp 层 dst_port，flowID/包序列端口三者一致）。
	// 载体：postgresql 只承载在 TCP 上；链中存在 UDP 传输层 → 拒绝（UDP 载体
	// 负例 kingbase_neg_udp，报错含 "tcp"）。
	for _, l := range chain {
		if l.Name != "postgresql" {
			continue
		}
		termCfg := l.Config
		dialect := "postgresql"
		if v, ok := termCfg["dialect"].(string); ok && v != "" {
			dialect = v
		}
		// 载体检查：链上任意 udp 层 → 拒绝（postgresql 只走 tcp）。
		if hasLayer(chain, "udp") {
			return spec, fmt.Errorf("postgresql chain: carrier must be tcp (found udp; postgresql/kingbase only ride on tcp)")
		}
		contractPort := fieldContractDstPort(chain, p.effectiveRegistry())
		if contractPort == 0 {
			// 理论不可达（postgresql schema FieldContract 恒有 tcp.dst_port），
			// 防御性回退。
			contractPort = 5432
		}
		if dialect == "kingbase" {
			contractPort = 54321
		}
		// 用户显式写 tcp.dst_port → 域校验须等于契约端口。
		if len(chain) >= 2 && chain[len(chain)-2].Name == "tcp" {
			if v, ok := chain[len(chain)-2].Config["dst_port"]; ok && v != nil {
				if up, ok := configUint16(v); ok && up != 0 && up != contractPort {
					return spec, fmt.Errorf("postgresql chain: destination port %d is not the default %d (dialect=%s)", up, contractPort, dialect)
				}
			}
		}
		// 未显式写 → 以契约端口为准（FieldContract 驱动，非硬编码 case）。
		spec.DstPort = contractPort
		break
	}
	// 通用 FieldContract 端口应用（P0b-1 通用化，design §1.3/§10.3 R2）：
	// switch 未覆盖且用户未显式写的层（amqp/bgp/dameng/drda/hds/hls/http/
	// http_flv/iec104/mongodb/s7/thrift/tns），其目的端口由 terminal 层
	// FieldContract 的 <carrier>.dst_port 常量补齐（fieldContractDstPort 读
	// tcp/udp 两载体）。若契约也未声明，才报 destination port is required。
	//
	// 只对 switch **未覆盖**的层生效：validateSpecBase 的 DstPort switch 已
	// 处理所有 case 层（含 rip/dhcp/dhcpv6 刻意保持 0、由生成器按版本/角色/
	// 方向运行时解析）。这些层即使后续补了 FieldContract，也不应被此处静态
	// 契约覆盖——否则会破坏生成器的动态端口解析。
	if spec.DstPort == 0 && !validateBaseDstPortHandled(p.name) {
		// 用户显式写 transport 层 dst_port（层数组 [ip,tcp(,http),<term>] 的
		// tcp/http 条目）→ 尊重用户值（用户显式 > FieldContract，设计 §8 优先级，
		// review P2 修复）。不落此契约块，并把用户值回填 spec.DstPort 保证
		// flowID / applySpecToChain / 包序列端口三者一致。
		carrierIdx := len(chain) - 2
		if carrierIdx >= 0 {
			if v, ok := chain[carrierIdx].Config["dst_port"]; ok && v != nil {
				if up, ok := configUint16(v); ok && up != 0 {
					spec.DstPort = up
				}
			}
		}
		if spec.DstPort == 0 {
			if cp := fieldContractDstPort(chain, p.effectiveRegistry()); cp != 0 {
				spec.DstPort = cp
			} else {
				return spec, fmt.Errorf("destination port is required")
			}
		}
	}
	return spec, nil
}

// validateBaseDstPortHandled reports whether name's destination-port semantics
// are handled outside the generic FieldContract application in ValidateSpec
// (chain_planner.go). True for the DstPort switch cases AND for layers
// validateSpecBase exempts entirely (goose/sv: eth terminal layers with no
// port concept — DstPort==0 is legal). The generic FieldContract application
// must NOT touch any of these, or it would overwrite dynamic-port layers
// (rip/dhcp/dhcpv6 resolve port at runtime) or reject port-less layers
// (goose/sv).
func validateBaseDstPortHandled(name string) bool {
	switch name {
	case "opcua", "mms", "fins", "coap", "dns", "mdns", "syslog", "snmp",
		"ntp", "ssdp", "stun", "rtmfp", "ldp", "pcep", "cflow", "rip", "dhcp",
		"dhcpv6", "doip", "gbt32960", "mcp", "modbus", "mqtt", "nfs", "smb",
		"tds", "moxa", "someip", "postgresql", "goose", "sv",
		"igmp", "ospf", "pim", "isis", "icmpv6", "h323", "mpls",
		// D-NGAP-1：ngap 端口住层（SCTP 联结端口语义），同 h323/mpls。
		// D-TELNET-1：telnet 同款（TCP 联结端口语义）。
		// D-SIP-1：sip 同款（TCP 信令联结端口语义）。
		// D-RADIUS-1：radius 同款（UDP 联结端口语义）。
		"ngap",
		"telnet",
		"sip",
		"radius",
		// B4 nvgre：无传输层、无端口概念（raw-IP 同款），目的端口 0 合法。
		// vxlan/geneve 不在豁免名单——它们的默认 4789/6081 走 FieldContract
		// 通用块（validateBaseDstPortHandled 之外的 amqp/bgp 同款）。
		"nvgre",
		// D-SRV6-1 srv6：SRH 扩展头无端口概念（内层端口住 srv6 层，
		// 回退 spec 逐流值），目的端口 0 合法（raw-IP 同款）。
		"srv6",
		// D-PPPOE-1 pppoe：帧无外层传输层（内层 L4 端口住 spec，链路径
		// 0 合法，raw-IP 同款）。
		"pppoe",
		// D-LDAP-1 ldap：自建 TCP 载体（目的端口 389 由生成器 Plan
		// 缺省），层 config 无端口位，0 合法（radius 同款）。
		"ldap",
		// D-RTMP-1 rtmp：自建 TCP 载体（目的端口 1935 由生成器 Plan
		// 缺省），层 config 无端口位，0 合法（ldap 同款）。
		"rtmp",
		// D-RTSP-1 rtsp：同款（协议级目的端口缺省 554 由下方 DstPort
		// switch 承接，dns→53 同款——legacy 554 缺省住 mapToFlowSpec
		// setDefaultDstPort，链路径在 validateSpecBase 补齐）。
		"rtsp",
		// D-PPTP-1 pptp：自建 TCP 载体（控制通道 1723 由生成器 Plan
		// :404 缺省），层 config 无端口位，0 合法（pppoe 同款）。
		"pptp",
		// D-VNC-1 vnc：自建 TCP 载体（控制通道 5900 由生成器 Plan
		// :561 缺省），层 config 无端口位，0 合法（pptp 同款）。
		"vnc",
		// D-XMPP-1 xmpp：自建 TCP 载体（控制通道 5222 由下方 DstPort
		// switch 承接——legacy Plan 无内部缺省，rtsp 式必选）。
		"xmpp",
		// D-SCTP-1 sctp：SCTP 自成 L4（IP proto 132），端口住 sctp 层
		// （1.12 补位：translate 回填 spec），无协议级缺省（flat 同口径
		// 不静默改 80），0 合法。
		"sctp",
		// D-JT808-1 jt808：自建 TCP 载体（控制通道 7611 由生成器
		// PlanWithConfig :166 内部缺省），层 config 无端口位，0 合法
		//（vnc/pptp 变体）。
		"jt808",
		// D-JT809-1 jt809：自建双 TCP 载体（主链 8812 由生成器
		// PlanWithConfig 内部缺省+mapToFlowSpec case 先补；从链 8813=
		// 生成器合成面），层 config 无端口位，0 合法。
		"jt809",
		// D-JTT905-1 jtt905：自建 TCP 载体（默认 10700 由生成器
		// PlanWithConfig 内部缺省+mapToFlowSpec case 先补），层 config
		// 无端口位，0 合法。
		"jtt905",
		// stateless UDP protocols: ports defaulted by the DstPort switch above.
		// radius 已在上方 D-RADIUS-1 豁免块登记，此处不重复列。
		"tftp":
		return true
	}
	return false
}

// isUniversalDefault reports whether v equals the generic HTTP default (80).
// Used to detect the "universal default leaks" path: mapToFlowSpec writes 80 to
// spec.DstPort when the user omitted dst_port, bypassing the spec.DstPort==0 gate
// in validateSpecBase's DstPort switch. When the value is 80 for a protocol that
// carries no HTTP semantics, we override to the protocol's well-known port.
func isUniversalDefault(v uint16) bool {
	return v == 80
}

// isUniversalDefaultSrcPort reports whether (name, v) represents the universal
// default source port (12345) leaking through mapToFlowSpec. When true, the
// value is treated as 0 and the protocol's SrcPort switch applies. Used for
// protocols whose terminal layer validates SrcPort against a specific value
// (ssdp rejects src != 1900, mdns rejects src != 5353) — the universal default
// 12345 would otherwise hit the validator and fail the task.
func isUniversalDefaultSrcPort(name string, v uint16) bool {
	if v != 12345 {
		return false
	}
	switch name {
	// ssdp/mdns terminal layers validate SrcPort: RFC 6970 requires 1900 for SSDP,
	// RFC 6762 §5.4 requires 5353 for mDNS. Universal default 12345 would be rejected.
	case "ssdp", "mdns":
		return true
	}
	return false
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
	if name == "goose" || name == "sv" || name == "isis" {
		// L2-only 终结层（goose/sv/isis）：无 IP/端口概念，直接放行。
		return nil
	}
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
	// D-FTP-4 豁免：ip.src/ip.dst 任一端是层动态对象时（spec.HasLayerDynIP，
	// mapToFlowSpec 随 LayerDyn 置位），解析前 spec 仍带 flat 默认（另一族），
	// 不得做静态同族检查——逐流解析值的同族性由 ValidateLayers 形状层保证
	// （混族对象在 create 400 / 启动预检 error，此处放行后 worker 逐流解析、
	// drive 注入解析值，线上地址恒同族）。
	if !spec.HasLayerDynIP && spec.SrcIP != "" && spec.DstIP != "" {
		src := net.ParseIP(spec.SrcIP)
		dst := net.ParseIP(spec.DstIP)
		if src != nil && dst != nil && (src.To4() != nil) != (dst.To4() != nil) {
			return fmt.Errorf("SrcIP %s and DstIP %s must be same IP version", spec.SrcIP, spec.DstIP)
		}
	}
	if spec.SrcPort == 0 || isUniversalDefaultSrcPort(name, spec.SrcPort) {
		// 协议级源端口默认：独立 transport flow（tcp/udp）无默认，
		// 必须显式（legacy tcp.go/udp.go 同款）。终结层 udp 链（dns/ntp/
		// snmp/syslog/mdns）由各自 legacy planner 在 Plan 时默认：dns/snmp/
		// syslog 源端口沿用 spec（可为 0，legacy 同样带 0 上包）；
		// ntp 用 30000+(seed%30000) 的确定性临时端口（planner.go:203-206，
		// seed=IPID 种子，每次 Plan 随机）；mdns 源端口强制 5353
		// （RFC 6762 §5.4，legacy planner.go:428-432 同款：spec 为 0 时默认）。
		//
		// T2.1 后续（failing-test-first 修复）：mapToFlowSpec 把通用默认
		// 12345 写进 spec.SrcPort，ssdp/mdns 终结层校验"src 非 0/协议端口
		// 则拒绝"，12345 落拒绝分支 → 任务失败。isUniversalDefaultSrcPort
		// 兜底：等于通用默认 12345 的值按 0 语义处理（协议端口默认仍由本
		// switch 接管）；用户显式写 12345 的其它协议不受影响。
		switch name {
		case "ntp":
			spec.SrcPort = uint16(30000 + (uint32(rand.Uint32()) % 30000))
		case "mdns":
			spec.SrcPort = mdnsPort
		case "ssdp":
			// SSDP 源端口强制 1900（legacy planner.go:236-239 同款：spec 为
			// 0 时默认；RFC 6970 规定 SSDP 用 1900）。universal default
			// 12345 也走此分支（见上）。
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
		case "dns", "snmp", "syslog", "stun", "rtmfp", "wireguard", "l2tp", "gtp", "ike_nat_t",
			"vxlan", "geneve":
			// 允许 0 上包（legacy 语义；vxlan/geneve B4 封装类同款——用例
			// 显式写源端口，空配置默认 0 数据报照样封装）
		case "doip":
			// DoIP 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （0 也上包，emitDoIP 的 srcPort 参数直传），不在此默认化。
		case "gbt32960":
			// GBT32960 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （gbt32960.go:672-727 同款：emitTCP 的 srcPort 参数直传），
			// 不在此默认化。
		case "mcp":
			// MCP 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emit.go emitAppData 的 srcPort 参数直传），不在此默认化。
		case "modbus":
			// Modbus 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planFlow 418-436：多流派生 baseSrcPort+idx；单流 idx=0 时
			// 即 spec.SrcPort 原值，0 也上包），不在此默认化。
		case "mqtt":
			// MQTT 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitAll 852-856：Sessions 为空单流直传 spec.SrcPort，0 也
			// 上包；多流派生不适用——链拒绝多流），不在此默认化。
		case "redis":
			// Redis 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitData 闭包直传 spec.SrcPort，0 也上包），不在此默认化。
		case "pop3":
			// POP3 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitData/emit 直传，0 也上包），不在此默认化。
		case "imap":
			// IMAP 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitData/emit 直传，0 也上包），不在此默认化。
		case "mysql":
			// MySQL 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitMySQLUp/Down 直传，0 也上包），不在此默认化。
		case "nfs":
			// NFS 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planSession 430-442 同款：emit 的 srcPort 参数直传，0 也
			// 上包），不在此默认化。
		case "smb":
			// SMB 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （emitTCPPacket 的 srcPort 参数直传，0 也上包），不在此
			// 默认化。
		case "smtp":
			// SMTP 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go:215 同款：SYN 的 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "grpc":
			// gRPC 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go 同款：SYN/HTTP2 帧 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "ssh":
			// SSH 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go 同款：SYN/BPP 帧 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "rdp":
			// RDP 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go 同款：SYN/PDU 帧 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "vmess":
			// VMess 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go 同款：SYN/帧 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "shadowsocks":
			// Shadowsocks 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （planner.go 同款：SYN/帧 srcPort 直传，0 也上包），
			// 不在此默认化。
		case "tds":
			// TDS 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （tds.go:449 同款：up 帧 srcPort 参数直传，0 也上包），
			// 不在此默认化。
		case "moxa":
		// Moxa 源端口 0 保持 0：透传单连接，多流由 worker 递增。
		case "igmp", "ospf", "pim", "isis", "nvgre", "srv6", "icmpv6", "h323", "mpls", "ngap", "telnet", "sip", "radius", "pppoe", "ldap", "rtmp", "rtsp", "pptp", "vnc", "xmpp", "sctp", "jt808", "jt809", "jtt905":
			// pppoe（D-PPPOE-1）同列：帧无外层传输层，链路径无端口可写
			// （内层 IPv4 数据面的 L4 端口住 spec，0 由生成器合成面承担）。
			// raw-IP 路由终结层（P3 T5）与 nvgre（B4 封装类）/srv6
			// （D-SRV6-1，SRH 扩展头）同样无传输层：无端口概念，源/目的
			// 端口 0 保持 0（内层端口住 srv6 层，回退 spec 逐流值）。
			// h323（D-H323-1）同列：端口概念存在但住 h323 层，translate
			// 期才落到 spec（base 检查期 0 保持 0）。
			// radius（D-RADIUS-1）同列：端口住 radius 层，validateSpecBase
			// 先于 translate 执行，base 检查期 0 保持 0；src 缺席单流 0
			// 上包（legacy mapToFlowSpec 扁平路径才默认 12345，链路径语义
			// 对齐 mcp/modbus 直传族），多流 worker 按 12345+i 注入。
		default:
			return fmt.Errorf("source port is required")
		}
	}
	if spec.DstPort == 0 || isUniversalDefault(spec.DstPort) {
		// 协议级目的端口默认（legacy Plan 时默认，与 strategy_convert 的
		// mapToFlowSpec 默认值一致）：dns→53、syslog→514（tls 载体 6514）、
		// snmp→按 PDU 类型（trap/inform 162，其余 161）、ntp→123、
		// mdns→5353（legacy mdns planner.go:433-436 同款）。
		//
		// T2.1 后续（failing-test-first 修复）：mapToFlowSpec 把通用默认 80
		// 写进 spec.DstPort（universal default），导致 spec.DstPort==0 的
		// gate 在 chain path 永远不触发，协议端口默认被旁路，packets 携带
		// 端口 80 而非协议端口。isUniversalDefault 兜底：spec.DstPort 等于
		// 通用默认 80 时也走 switch 应用协议端口——用户显式写 80 仍按
		// 显式处理（其它协议显式 dst_port=80 如 sip/hls 直发不受影响）。
		switch name {
		case "opcua":
			spec.DstPort = 4840
		case "mms":
			spec.DstPort = 102
		case "fins":
			spec.DstPort = 9600
		case "coap":
			spec.DstPort = 5683
		case "dns":
			spec.DstPort = 53
		case "rtsp":
			// D-RTSP-1：RTSP 控制通道 554（IANA；legacy mapToFlowSpec
			// setDefaultDstPort(&spec, cfg, 554) 链路径等价承接）。
			spec.DstPort = 554
		case "xmpp":
			// D-XMPP-1：XMPP client-to-server 5222（RFC 6120 §13.3；
			// legacy 缺省住 mapToFlowSpec setDefaultDstPort(&spec, cfg,
			// 5222) :944，Plan 无内部缺省——链路径必须 switch 承接）。
			spec.DstPort = 5222
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
		case "tftp":
			// TFTP 目的端口默认 69（RFC 1350 well-known TID；
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 69
		case "radius":
			// RADIUS 目的端口默认 1812 (authentication) / 1813 (accounting)
			// per RFC 2865 §3 / RFC 2866 §3; 选 1813 仅当 RADIUS code=4
			// (Accounting-Request)。strategy_convert mapToFlowSpec 同款默认。
			if spec.Radius != nil && spec.Radius.Code == 4 {
				spec.DstPort = 1813
			} else {
				spec.DstPort = 1812
			}
		case "stun":
			// STUN 目的端口默认 3478（UDP）或 5349（TLS，TCP 载体下终结层为
			// tls 时——validateSpecBase 405-417 同款默认；TLS 链 dst_port 5349
			// 由用例显式写，这里只补裸 stun 链的默认）。
			spec.DstPort = 3478
		case "rtmfp":
			// RTMFP 目的端口默认 1935（Adobe RTMFP 标准；strategy_convert
			// mapToFlowSpec 同款默认——用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 1935
		case "wireguard":
			// WireGuard 目的端口默认 51820（legacy DefaultPort=51820，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 51820
		case "l2tp":
			// L2TP 目的端口默认 1701（RFC 2661；legacy Plan 内
			// effectiveDstPort==0→DefaultPort 同款——validate 返回明确值，
			// 用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 1701
		case "openvpn":
			// OpenVPN 目的端口默认 1194（legacy DefaultPort=1194，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 1194
		case "gtp":
			// GTP 目的端口按平面默认（TS 29.281 §5.1 / TS 29.060 §6）：
			// Mode=c → 2123，其余（u/空）→ 2152。legacy Plan 内
			// port=DefaultPortGTPU/GTPC 同款——用户显式写 dst_port 时已
			// 非零不落此分支。
			if spec.GTP != nil && spec.GTP.Mode == "c" {
				spec.DstPort = 2123
			} else {
				spec.DstPort = 2152
			}
		case "ike":
			// IKE 目的端口默认 500（RFC 7296 §1.2；legacy DefaultPort=500，
			// Validate 允许 DstPort=0 或 500——用户显式写 dst_port 且非 0/500
			// 时由 ike Validate 拒绝，不在此分支）。
			spec.DstPort = 500
		case "ike_nat_t":
			// IKE-NAT-T 目的端口默认 4500（RFC 3948 NATTPort；legacy Plan 内
			// NATTPort=4500 同款——用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 4500
		case "ldp":
			spec.DstPort = 646
		case "pcep":
			spec.DstPort = 4189
		case "cflow":
			spec.DstPort = 2055
		case "rip":
			// RIP 目的端口 0 保持 0：终结层生成器按版本默认（v1/v2→520、
			// ng→521，legacy getDstPort 语义），事件携带 DstPort。
			// isUniversalDefault 入口的 80 必须重置回 0（T5.2 修复）：
			// resolvePorts/getDstPort 只对 0 做动态解析，80 会原样落
			// udp 层 cfg → 线上端口 80 而非 520/521。动态端口层上 80 无
			// 协议语义，重置无歧义。
			spec.DstPort = 0
		case "dhcp":
			// DHCP 目的端口 0 保持 0：终结层生成器按角色解析（client→67、
			// server/relay→67，dhcp planner.go:643-679 resolvePorts 语义）。
			// 同 rip：universal default 80 重置回 0，否则 resolvePorts 视
			// 80 为用户显式值直落线上（dhcp_smoke_01 曾回归：dstport=80）。
			spec.DstPort = 0
		case "dhcpv6":
			// DHCPv6 目的端口 0 保持 0：终结层生成器按方向逐事件解析
			// （up=server 547、down=client 546，dhcpv6 planner.go:435-456
			// resolveAddrs 语义）。同 rip：universal default 80 重置回 0。
			spec.DstPort = 0
		case "doip":
			// DoIP 目的端口默认 13400（legacy Plan 用 DefaultTCPPort，
			// strategy_convert mapToFlowSpec 同款默认）。
			spec.DstPort = doipPort
		case "gbt32960":
			// GBT32960 目的端口默认 10020（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = gbtPort
		case "mcp":
			// MCP 目的端口默认（legacy Plan plan.go:61-68 同款）：
			// stdio → 22（DefaultPortStdio）、http_sse/streamable → 8081
			// （DefaultPortHTTP）。Transport 为空时按 stdio 处理（Plan
			// 默认化在 validator 之后，validateSpecBase 以原始字符串
			// 判空——空串按 stdio 同款默认 22）。
			if spec.MCP != nil && spec.MCP.Transport != "" && spec.MCP.Transport != "stdio" {
				spec.DstPort = mcpHTTPPort
			} else {
				spec.DstPort = mcpStdioPort
			}
		case "modbus":
			// Modbus 目的端口默认 502（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 502
		case "mqtt":
			// MQTT 目的端口默认 1883（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 1883
		case "redis":
			// Redis 目的端口默认 6379（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 6379
		case "pop3":
			// POP3 目的端口默认 110（RFC 1939，legacy DefaultPort 同款——
			// 用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 110
		case "ftp":
			// FTP 目的端口默认 21（RFC 959 控制通道；strategy_convert
			// mapToFlowSpec setDefaultDstPort(&spec, cfg, 21) 同款——
			// 用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 21
		case "imap":
			// IMAP 目的端口默认 143（RFC 3501，legacy DefaultPort=143 同款——
			// 用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 143
		case "mysql":
			// MySQL 目的端口默认 3306（legacy DefaultPort 同款——用户显式
			// 写 dst_port 时已非零不落此分支）。
			spec.DstPort = 3306
		case "grpc":
			// gRPC 目的端口默认 8604（telemetry_8604；legacy DefaultPort
			// 同款——用户显式写 dst_port 时已非零不落此分支，与
			// strategy_convert mapToFlowSpec 默认一致）。
			spec.DstPort = 8604
		case "ssh":
			// SSH 目的端口默认 22（IANA/bog-standard；strategy_convert
			// mapToFlowSpec 同款默认——用户显式写 dst_port 时已非零不落
			// 此分支）。
			spec.DstPort = 22
		case "rdp":
			// RDP 目的端口默认 3389（MS-RDPBCGR §1.3；legacy Validate 强制
			// DstPort 必须 0 或 3389——用户显式写 3389 不落此分支，写其它
			// 值由 rdp Validate 拒绝）。
			spec.DstPort = 3389
		case "vmess":
			// VMess 目的端口默认 443（legacy DefaultPort=443；strategy_convert
			// mapToFlowSpec 无默认（用户须指定），链上给默认以支持裸链——用户
			// 显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 443
		case "shadowsocks":
			// Shadowsocks 目的端口默认 8388（legacy DefaultPort=8388；用户显式
			// 写 dst_port 时已非零不落此分支）。
			spec.DstPort = 8388
		case "nfs":
			// NFS 目的端口默认 2049（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = nfsPort
		case "smb":
			// SMB 目的端口默认（strategy_convert.go mapToFlowSpec 同款）：
			// transport=netbios → 139（NetBIOS Session Service），其余
			// （direct/空）→ 445（Direct TCP）。legacy Plan 无端口默认
			// （原值上包），链上默认与 strategy_convert 对齐——用户显式
			// 写 dst_port 时已非零不落此分支。
			if spec.SMB != nil && spec.SMB.Transport == "netbios" {
				spec.DstPort = 139
			} else {
				spec.DstPort = 445
			}
		case "tds":
			// TDS 目的端口默认 1433（legacy Plan 用 DefaultPort，
			// strategy_convert mapToFlowSpec 同款默认——用户显式写
			// dst_port 时已非零不落此分支）。
			spec.DstPort = 1433
		case "moxa":
			spec.DstPort = 4800
		case "someip":
			spec.DstPort = 30490
		case "postgresql":
			// PostgreSQL 目的端口由 postgresql 层 FieldContract 驱动（T2 维度二，
			// design §1.3/§10.3 R1）：dialect=postgresql→5432、kingbase→54321。
			// 这里不放 default——validateSpecBase 先于契约块（272-315）运行，
			// 若在此拒绝 0 会挡住契约赋值。保持 0，让契约块写入契约端口。
		default:
			// 不在此报错——switch 未覆盖的层（amqp/bgp/dameng/drda/hds/hls/http/
			// http_flv/iec104/mongodb/s7/thrift/tns）其目的端口由 terminal 层
			// FieldContract 的 <carrier>.dst_port 常量声明（design §1.3/§10.3
			// R2 通用化）。validateSpecBase 无 chain 无法读契约，故保持 0 继续，
			// 由 ValidateSpec 主函数构建链后经 fieldContractDstPort 统一补齐；
			// 若契约也未声明，才在主函数报"destination port is required"。
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
	// 混合载体链（[ip→ldp] dual_adjacency）：终结层自产完整包，不消费
	// Meta.Events（无传输层），跳过事件接线断言。
	if !isCarrierMixedChain(p.name, chain) {
		if err := assertEventWiring(chain, gens); err != nil {
			return nil, err
		}
	}

	if p.name == "sv" || p.name == "goose" || p.name == "isis" {
		out := make(chan core.PacketConfig, 256)
		go func() {
			defer close(out)
			gen := gens[len(gens)-1]
			req := &GenRequest{Meta: flowMetaFor(spec), Emit: func(pkt core.PacketConfig) error {
				// 保留生成器已装配的 L2（含 VLAN）：goose/sv 的 VLAN 来自
				// 配置 vlan_enabled，由生成器写入 pkt.L2.VLAN。不能用
				// l2For 覆盖——l2For 读 spec.VLAN（顶层的 vlan 键），而
				// goose/sv 的 VLAN 在协议子映射里，spec.VLAN 恒 nil，
				// 覆盖会丢掉 VLAN 标签。
				if pkt.L2.SrcMAC == "" {
					l2 := l2For(pkt.Direction, spec)
					pkt.L2.SrcMAC = l2.SrcMAC
					pkt.L2.DstMAC = l2.DstMAC
				}
				if p.name == "sv" {
					pkt.L2.EtherType = core.EtherTypeSV
				}
				if p.name == "goose" {
					pkt.L2.EtherType = core.EtherTypeGOOSE
				}
				if p.name == "isis" {
					pkt.L2.EtherType = core.EtherTypeISIS
				}
				pkt.L3 = core.L3Config{}
				pkt.L4.Protocol = p.name
				select {
				case out <- pkt:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			_ = gen.Generate(ctx, req)
		}()
		return out, nil
	}
	// raw-IP 终结层链（[ip→igmp/ospf/pim]，P3 T5）：无 tcp/udp 传输层，
	// drive 的 transportIndex 必然 -1 → "chain has no transport layer"。与
	// goose/sv L2-only 分支同构：终结层生成器直接产完整包（自设 L3.SrcIP/
	// DstIP/Protocol + Payload），finalEmit 只补 L2 + TTL/DSCP。L3.Protocol
	// 恒非 0（生成器按协议固写 2/89/103），finalEmit 的"仅 0 时填充"不会覆盖。
	// 双载体终结层链（[ip→ldp] dual_adjacency）：与 raw-IP 分支同构——
	// 无 tcp/udp 传输层，终结层生成器自产完整包（UDP Hello 与 TCP 会话
	// 混合，自设 L3/L4/Payload），finalEmit 只补 L2/TTL。
	if isCarrierMixedChain(p.name, chain) && spec.LDP != nil && len(spec.LDP.Adjacencies) > 0 {
		out := make(chan core.PacketConfig, 256)
		go func() {
			defer close(out)
			gen := gens[len(gens)-1]
			sess := &SessionState{IPID: uint16(rand.Uint32())}
			meta := flowMetaFor(spec)
			meta.SrcIP = spec.SrcIP
			meta.DstIP = spec.DstIP
			meta.TTL = spec.TTL
			meta.LDP = spec.LDP
			req := &GenRequest{
				Meta: meta,
				Sess: sess,
				Emit: func(pkt core.PacketConfig) error {
					// 方向交换由生成器完成（down 帧 L3/L4 已按发送方翻转）；
					// 这里只补 MAC/EtherType/TTL/时间戳，不再交换 IP。
					if pkt.L2.SrcMAC == "" {
						l2 := l2For(pkt.Direction, spec)
						pkt.L2.SrcMAC = l2.SrcMAC
						pkt.L2.DstMAC = l2.DstMAC
					}
					if pkt.L2.EtherType == 0 {
						pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
					}
					if pkt.L3.TTL == 0 {
						pkt.L3.TTL = spec.TTL
					}
					if pkt.FlowID == "" {
						pkt.FlowID = flowID(spec)
					}
					pkt.Timestamp = time.Now()
					select {
					case out <- pkt:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				},
			}
			_ = gen.Generate(ctx, req)
		}()
		return out, nil
	}
	// B5 终结层双栈自驱链（[ip→tcp→openwire/ams] + 连接级显式 src_ip/dst_ip）：
	// 显式地址的连接（如 v6）无法经事件路径——L3 家族恒随 spec 的 ip 层，
	// down 交换也只认 spec 地址。生成器整体自产完整 TCP 包（每连接独立
	// 握手/命令段/挥手，L3 按连接家族装配），finalEmit 只补 MAC/EtherType/
	// 时间戳——与 ldp dual_adjacency 分支同构（方向交换由生成器完成）。
	openwireSelf := p.name == "openwire" && spec.OpenWire != nil && openwireNeedsSelfDrive(spec.OpenWire)
	amsSelf := p.name == "ams" && spec.AMS != nil && amsNeedsSelfDrive(spec.AMS)
	swarmSelf := p.name == "swarm" && spec.Swarm != nil && swarmNeedsSelfDrive(spec.Swarm)
	gnutellaSelf := p.name == "gnutella" && spec.Gnutella != nil && gnutellaNeedsSelfDrive(spec.Gnutella)
	nmeaSelf := p.name == "nmea" && nmeaNeedsSelfDrive(spec.NMEA)
	if openwireSelf || amsSelf || swarmSelf || gnutellaSelf || nmeaSelf {
		out := make(chan core.PacketConfig, 256)
		go func() {
			defer close(out)
			gen := gens[len(gens)-1]
			sess := &SessionState{IPID: uint16(rand.Uint32())}
			meta := flowMetaFor(spec)
			meta.SrcIP = spec.SrcIP
			meta.DstIP = spec.DstIP
			meta.SrcPort = spec.SrcPort
			meta.DstPort = spec.DstPort
			meta.TTL = spec.TTL
			meta.FlowID = flowID(spec)
			meta.OpenWire = spec.OpenWire
			meta.AMS = spec.AMS
			meta.Swarm = spec.Swarm
			meta.Gnutella = spec.Gnutella
			meta.NMEA = spec.NMEA
			index := uint64(0)
			req := &GenRequest{
				Meta: meta,
				Sess: sess,
				Emit: func(pkt core.PacketConfig) error {
					// 方向交换由生成器完成（down 帧 L3/L4 已按发送方翻转）；
					// 这里只补 MAC/EtherType/时间戳与序号回填。
					if pkt.L2.SrcMAC == "" {
						l2 := l2For(pkt.Direction, spec)
						pkt.L2.SrcMAC = l2.SrcMAC
						pkt.L2.DstMAC = l2.DstMAC
					}
					if pkt.L2.EtherType == 0 {
						pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
					}
					pkt.Timestamp = time.Now()
					if pkt.FlowID == "" {
						pkt.FlowID = flowID(spec)
					}
					if pkt.PacketIndex == 0 {
						pkt.PacketIndex = index
					}
					index++
					select {
					case out <- pkt:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				},
			}
			_ = gen.Generate(ctx, req)
		}()
		return out, nil
	}
	if isRawIPChain(p.name, chain) {
		out := make(chan core.PacketConfig, 256)
		go func() {
			defer close(out)
			gen := gens[len(gens)-1]
			sess := &SessionState{IPID: uint16(rand.Uint32())}
			meta := flowMetaFor(spec)
			// raw-IP 生成器需要 SrcIP/DstIP/TTL（构造 L3 头）与协议配置。
			// flowMetaFor 只含 SrcMAC/DstMAC/SV/GOOSE——其余字段在此补齐。
			meta.SrcIP = spec.SrcIP
			meta.DstIP = spec.DstIP
			meta.TTL = spec.TTL
			meta.IGMP = spec.IGMP
			meta.OSPF = spec.OSPF
			meta.PIM = spec.PIM
			meta.NVGRE = spec.NVGRE
			meta.SRv6 = spec.SRv6
			// D-PPPOE-1：pppoe raw 链同款（层 config 经 translate 落
			// spec.PPPoE，此处直传终结层生成器）。
			meta.PPPoE = spec.PPPoE
			// D-LDAP-1：ldap raw 链同款。
			meta.LDAP = spec.LDAP
			// D-RTMP-1：rtmp raw 链同款。
			meta.RTMP = spec.RTMP
			// D-RTSP-1：rtsp raw 链同款。
			meta.RTSP = spec.RTSP
			// D-PPTP-1：pptp raw 链同款。
			meta.PPTP = spec.PPTP
			// D-VNC-1：vnc raw 链同款。
			meta.VNC = spec.VNC
			// D-XMPP-1：xmpp raw 链同款。
			meta.Xmpp = spec.Xmpp
			// D-SCTP-1：sctp raw 链同款。
			meta.SCTP = spec.SCTP
			// D-JT808-1：jt808 raw 链同款。
			meta.JT808 = spec.JT808
			// D-JT809-1：jt809 raw 链同款。
			meta.JT809 = spec.JT809
			// D-JTT905-1：jtt905 raw 链同款。
			meta.JTT905 = spec.JTT905
			// srv6 内层端口回退链（inner 端口缺省→spec 端口）依赖这两个值；
			// 多流时 worker.go 已按流注入 spec.SrcPort=12345+i。igmp/ospf/
			// pim/nvgre 生成器不读端口字段，赋值对它们无副作用。
			meta.SrcPort = spec.SrcPort
			meta.DstPort = spec.DstPort
			req := &GenRequest{
				Meta: meta,
				Sess: sess,
				Emit: func(pkt core.PacketConfig) error {
					if pkt.Direction == "down" {
						pkt.L3.SrcIP, pkt.L3.DstIP = pkt.L3.DstIP, pkt.L3.SrcIP
					}
					if pkt.L2.SrcMAC == "" {
						l2 := l2For(pkt.Direction, spec)
						pkt.L2.SrcMAC = l2.SrcMAC
						pkt.L2.DstMAC = l2.DstMAC
					}
					if pkt.L2.DstMAC == "" {
						pkt.L2.DstMAC = multicastDstMAC(pkt.L3.DstIP)
					}
					if pkt.L2.EtherType == 0 {
						pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
					}
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
					if pkt.L3.TTL == 0 {
						pkt.L3.TTL = spec.TTL
					}
					if pkt.FlowID == "" {
						pkt.FlowID = flowID(spec)
					}
					pkt.Timestamp = time.Now()
					select {
					case out <- pkt:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				},
			}
			_ = gen.Generate(ctx, req)
		}()
		return out, nil
	}
	// 事件分支的 transport 配置预检（review transform-wiring F3）：transport
	// 生成器在 resolveCfg 失败时立即退出，transformCh[1]（64 缓冲）失去
	// 消费者，变换器转发塞满后同步写者阻塞挂死（直到 ctx 取消才收敛）。
	// resolveCfg 错误在真实链上可达（V9 对无 Min/Max 边界的字段如
	// initial_seq 只跳过范围检查，字符串等不可转换值穿透补全到达生成器）。
	// 预检必须在 Plan 同步执行——drive 运行在 goroutine 内，其错误被吞成
	// 空流（驱动失败契约），放 drive 里就退化成静默空流而非同步拒绝。
	// 同键二态豁免（D-FTP-2 v2）：transport 层端口是动态对象（有 strategy
	// 键的 map）时，drive 的 applySpecToChain 会用 worker 逐流解析值
	// （spec.SrcPort/DstPort）替换对象——对象本身不是可用端口，预检不得
	// 读原始链。预检读 drive 同款注入结果（applySpecToChain(chain, spec)），
	// 标量链注入前后一致（无条件注入幂等 / 层值优先不动），对象链预检的是
	// 解析/默认形态——形状违规仍同步拒绝（V9 已放行对象，非法标量照旧拦）。
	if eg, ok := gens[len(chain)-1].(interface{ GenEvents() EventGenerator }); ok && eg.GenEvents() != nil {
		if idx := transportIndex(gens); idx >= 0 {
			effChain := p.applySpecToChain(chain, spec)
			switch g := gens[idx].(type) {
			case *TCPGenerator:
				if _, err := g.resolveCfg(&GenRequest{Layer: effChain[idx]}); err != nil {
					return nil, err
				}
			case *UDPGenerator:
				if _, err := g.resolveCfg(&GenRequest{Layer: effChain[idx]}); err != nil {
					return nil, err
				}
			}
		}
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
