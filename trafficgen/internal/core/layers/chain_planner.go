package layers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strconv"
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
	// 隧道层（gre）结构性校验（P2e T12 review HIGH-2）：GRE 只支持 IPv4
	// 内层（GREGenerator 的 To4 检查 + builder writeGRE 的 ProtocolType
	// 0x0800 即内层裸 IPv4 包）。IPv6 内层/空地址是**结构性**错误，必须在此
	// 同步拒绝——drive 期生成器报错会被 Plan goroutine 吞成 0 包空流
	// （chain_planner.go:266-270 的既有契约），调用方拿到空流而非明确错误。
	// 校验读 spec 地址（applySpecToChain 把 spec.SrcIP/DstIP 注入每个 ip 层，
	// 外层与内层同值；flat spec.GRE 的 InnerSrcIP/InnerDstIP 默认即 spec
	// 地址，同受此约束）。
	for _, l := range chain {
		if l.Name != "gre" {
			continue
		}
		if spec.SrcIP == "" || spec.DstIP == "" {
			return spec, fmt.Errorf("gre chain: inner IPv4 addresses required (tunnel chains derive inner addresses from spec src_ip/dst_ip; empty spec addresses leave no inner addresses)")
		}
		if net.ParseIP(spec.SrcIP).To4() == nil || net.ParseIP(spec.DstIP).To4() == nil {
			return spec, fmt.Errorf("gre chain: IPv6-over-GRE not supported yet (inner addresses %s/%s must be IPv4)",
				spec.SrcIP, spec.DstIP)
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
		"tds", "moxa", "someip", "postgresql", "goose", "sv":
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
	if name == "goose" || name == "sv" {
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
		case "dns", "snmp", "syslog", "stun", "rtmfp", "wireguard", "l2tp", "gtp", "ike_nat_t":
			// 允许 0 上包（legacy 语义）
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
		case "tds":
			// TDS 源端口 0 保持 0：legacy Plan 用 spec.SrcPort 原值
			// （tds.go:449 同款：up 帧 srcPort 参数直传，0 也上包），
			// 不在此默认化。
		case "moxa":
		// Moxa 源端口 0 保持 0：透传单连接，多流由 worker 递增。
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
		case "dhcp":
			// DHCP 目的端口 0 保持 0：终结层生成器按角色解析（client→67、
			// server/relay→67，dhcp planner.go:643-679 resolvePorts 语义）。
		case "dhcpv6":
			// DHCPv6 目的端口 0 保持 0：终结层生成器按方向逐事件解析
			// （up=server 547、down=client 546，dhcpv6 planner.go:435-456
			// resolveAddrs 语义）。
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
		case "imap":
			// IMAP 目的端口默认 143（RFC 3501，legacy DefaultPort=143 同款——
			// 用户显式写 dst_port 时已非零不落此分支）。
			spec.DstPort = 143
		case "mysql":
			// MySQL 目的端口默认 3306（legacy DefaultPort 同款——用户显式
			// 写 dst_port 时已非零不落此分支）。
			spec.DstPort = 3306
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
	if err := assertEventWiring(chain, gens); err != nil {
		return nil, err
	}

	if p.name == "sv" || p.name == "goose" {
		out := make(chan core.PacketConfig, 256)
		go func() {
			defer close(out)
			gen := gens[len(gens)-1]
			req := &GenRequest{Meta: flowMetaFor(spec), Emit: func(pkt core.PacketConfig) error {
				pkt.L2 = l2For(pkt.Direction, spec)
				if p.name == "sv" {
					pkt.L2.EtherType = core.EtherTypeSV
				}
				if p.name == "goose" {
					pkt.L2.EtherType = core.EtherTypeGOOSE
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
	// 事件分支的 transport 配置预检（review transform-wiring F3）：transport
	// 生成器在 resolveCfg 失败时立即退出，transformCh[1]（64 缓冲）失去
	// 消费者，变换器转发塞满后同步写者阻塞挂死（直到 ctx 取消才收敛）。
	// resolveCfg 错误在真实链上可达（V9 对无 Min/Max 边界的字段如
	// initial_seq 只跳过范围检查，字符串等不可转换值穿透补全到达生成器）。
	// 预检必须在 Plan 同步执行——drive 运行在 goroutine 内，其错误被吞成
	// 空流（驱动失败契约），放 drive 里就退化成静默空流而非同步拒绝。
	if eg, ok := gens[len(chain)-1].(interface{ GenEvents() EventGenerator }); ok && eg.GenEvents() != nil {
		if idx := transportIndex(gens); idx >= 0 {
			switch g := gens[idx].(type) {
			case *TCPGenerator:
				if _, err := g.resolveCfg(&GenRequest{Layer: chain[idx]}); err != nil {
					return nil, err
				}
			case *UDPGenerator:
				if _, err := g.resolveCfg(&GenRequest{Layer: chain[idx]}); err != nil {
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

func flowMetaFor(spec core.FlowSpec) FlowMeta {
	return FlowMeta{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, SV: spec.SV, GOOSE: spec.GOOSE}
}

// flowID mirrors the legacy per-flow ID format// "srcIP-dstIP-srcPort-dstPort"（每 flow 唯一标识）。
func flowID(spec core.FlowSpec) string {
	return fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
}

// completedChain completes the derived chain and validates it, applying the
// V4/V5 exemption for the synthesized chain (末层即协议层本身)。
func (p *ChainPlanner) completedChain() ([]Layer, error) {
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
		DHCPv6: spec.DHCPv6,
		// TFTP 同款（P4a）：配置经 Meta 直传 tftp 终结层生成器（Plan 内
		// 复刻——同一 Validate/默认化/emit 序列）。
		TFTP: spec.TFTP,
		// ENIP 同款（P4a）：配置经 Meta 直传 enip 终结层生成器（命令即
		// 数据段，事件按 buildENIPPacket 逐命令产出，字节级一致）。
		ENIP: spec.ENIP,
		// DNP3 同款（P4a）：配置经 Meta 直传 dnp3 终结层生成器（scenario
		// 展开逐帧事件，scenarioFrames 复用）。
		DNP3: spec.DNP3,
		// DoIP 同款（P4a）：配置经 Meta 直传 doip 终结层生成器（阶段逐
		// 报文事件，build* 纯函数复用）。
		DoIP: spec.DoIP,
		// GBT32960 同款（P4a）：配置经 Meta 直传 gbt32960 终结层生成器
		// （状态机逐消息事件，buildMessage 纯函数复用）。
		GBT32960: spec.GBT32960,
		// MCP 同款（P4a）：配置经 Meta 直传 mcp 终结层生成器（会话状态机
		// 逐消息事件，build* 纯函数复用）。
		MCP: spec.MCP,
		// MODBUS 同款（P4a）：配置经 Meta 直传 modbus 终结层生成器（事务
		// 循环逐帧事件，build* 纯函数复用）。
		MODBUS: spec.MODBUS,
		// MQTT 同款（P4a）：配置经 Meta 直传 mqtt 终结层生成器（会话序列
		// 逐帧事件，build* 纯函数复用）。
		MQTT: spec.MQTT,
		// NFS 同款（P4a）：配置经 Meta 直传 nfs 终结层生成器（RPC 调用/回复
		// 逐事件产出，buildCall/buildReply 纯函数复用）。interface{}——
		// core 无法 import protocol/nfs（protocol 包反向依赖 core），经
		// spec.Metadata["nfs"] 原样传递（mapToFlowSpec 存 JSON 解码子 map），
		// 生成器侧解析。
		NFS:        spec.Metadata["nfs"],
		FINS:       spec.Metadata["fins"],
		S7:         spec.S7,
		IEC104:     spec.IEC104,
		GOOSE:      spec.GOOSE,
		SV:         spec.SV,
		OPCUA:      spec.OPCUA,
		MMS:        spec.MMS,
		BGP:        spec.BGP,
		STUN:       spec.STUN,
		HTTPFLV:    spec.HTTPFLV,
		HLS:        spec.HLS,
		HDS:        spec.HDS,
		MOXA:       spec.MOXA,
		SOMEIP:     spec.SOMEIP,
		DRDA:       spec.DRDA,
		Thrift:     spec.Thrift,
		TNS:        spec.TNS,
		MongoDB:    spec.MongoDB,
		Dameng:     spec.Dameng,
		KingBase:   spec.KingBase,
		PostgreSQL: spec.PostgreSQL,
		CQL:        spec.CQL,
		LDP:        spec.LDP,
		PCEP:       spec.PCEP,
		CFlow:      spec.CFlow,
		AMQP:       spec.AMQP,
		RTMFP:      spec.RTMFP,
		// SMB 同款（P4a）：配置经 Meta 直传 smb 终结层生成器（SMB2 会话
		// NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE → Operations →
		// CLOSE → TREE_DISCONNECT → LOGOFF 逐 PDU 事件，build* 纯函数复用）。
		SMB: spec.SMB,
		// SMTP 同款（P3）：配置经 Meta 直传 smtp 终结层生成器（banner + Dialog
		// 命令/响应对逐事件产出，buildSMTPEmailBody 纯函数复用）。
		SMTP: spec.SMTP,
		// Redis 同款（P3）：配置经 Meta 直传 redis 终结层生成器（RESP 会话
		// 逐帧事件，encodeRESP* 纯函数复用）。
		Redis: spec.Redis,
		// POP3 同款（P3）：配置经 Meta 直传 pop3 终结层生成器（banner + 命令/
		// 响应对逐事件产出，buildMailDropResponse/buildTopResponse 纯函数复用）。
		POP3: spec.POP3,
		// IMAP 同款（P3）：配置经 Meta 直传 imap 终结层生成器（greeting +
		// 命令/literal/IDLE 逐事件产出，formatCommandLine 纯函数复用）。
		IMAP: spec.IMAP,
		// MySQL 同款（P3）：配置经 Meta 直传 mysql 终结层生成器（Greeting →
		// auth → 命令逐事件产出，encode*/buildReplyPackets 纯函数复用）。
		MySQL: spec.MySQL,
		// WireGuard 同款（P3）：配置经 Meta 直传 wireguard 终结层生成器
		// （UDP 数据报序列，build* 纯函数复用）。
		WireGuard: spec.WireGuard,
		// L2TP 同款（P3）：配置经 Meta 直传 l2tp 终结层生成器（UDP 隧道
		// 控制/PPP 数据报文列，build* 纯函数复用）。
		L2TP: spec.L2TP,
		// GTP 同款（P3）：配置经 Meta 直传 gtp 终结层生成器（GTP-U/C 隧道
		// 报文序列，buildGTPMessage/buildInnerIPv4Packet 纯函数复用）。
		GTP: spec.GTP,
		// IKE 同款（P3）：配置经 Meta 直传 ike 终结层生成器（IKE 消息序列 +
		// ESP 数据面，buildIKEMessageBytes 纯函数复用）。
		IKE: spec.IKE,
		// IKE-NAT-T 同款（P3）：配置经 Meta 直传 ike_nat_t 终结层生成器
		// （端口浮动 + Non-ESP Marker 的 NAT 穿透 IKE 消息序列，build*
		// 纯函数复用）。
		IKENATT: spec.IKENATT,
		// TCP 同款（P4a）：doip 0x36 分段读 spec.TCP.MSS。
		TCP:     spec.TCP,
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
			// 隧道链（gre）有两个 ip 层：外层（隧道端点）+ 内层（内层包）。
			// 外层生成器是链的出口，必须选**第一个**（outermost）ip 层——
			// 旧实现保留最后一个，对内层 ip 层生成器包帧后 finalEmit 再包
			// 一层，结构错乱。
			ipGen = gens[i].(*IPGenerator)
			ipLayer = chain[i]
			break
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
			// 隧道链（gre）：GREGenerator 已把 wire GRE 配置写进 L2.GRE，
			// l2For 全量重建会覆盖它——重建前先保留，装配后再恢复
			// （顺序必须如此：先取 gre 再 l2For，反了取到的是 nil）。
			gre := pkt.L2.GRE
			pkt.L2 = l2For(pkt.Direction, spec)
			if gre != nil {
				pkt.L2.GRE = gre
			}
			// 方向相关 src/dst 交换 + flow 级字段。IPID 已由 ip 层生成器写入
			// （每次 Emit 前写入并自增），这里只换 IP 不换 ID。
			if pkt.Direction == "down" {
				pkt.L3.SrcIP, pkt.L3.DstIP = pkt.L3.DstIP, pkt.L3.SrcIP
			}
			pkt.L3.TTL = ipTTL(ipCfg)
		}
		// L3 协议号随传输层（tcp=6 / udp=17；legacy L3Base 语义）。
		// 传输层是链上 ip 之下最后一层：独立 tcp/udp flow 的末层，
		// 或终结层链（http/dns...）的倒数第二层。隧道链（gre）由隧道层
		// 生成器已写入 47（IPPROTO_GRE）——只在 0 时填充，绝不覆盖。
		if p.name == "goose" || isGOOSEChain(chain) || p.name == "sv" || isSVChain(chain) {
			pkt.L2.EtherType = core.EtherTypeSV
			if p.name == "goose" || isGOOSEChain(chain) {
				pkt.L2.EtherType = core.EtherTypeGOOSE
			}
			pkt.L3 = core.L3Config{}
		} else if pkt.L3.Protocol == 0 {
			pkt.L3.Protocol = transportProtocol(chain)
		}
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
		Chain: chain,
		Layer: ipLayer,
		Inner: innerCh,
		Emit:  finalEmit,
		Sess:  sess,
		Meta:  meta,
	}

	// 5. 驱动：先启动外层（消费 innerCh），再驱动内层（往 innerCh 里写）。
	//    逐层 goroutine 管线（隧道链 P2e T12 泛化）：外层 ip 生成器消费
	//    innerCh 并把包交给 finalEmit；其下每层（gre、tcp、udp...）各跑一个
	//    goroutine，从自己的内层通道消费、经 req.Emit 写入上一层通道。
	//    末层若是终结层生成器（http/dns/...），把其报文事件流接入传输层的
	//    Meta.Events，传输层在"单 payload 模式"后消费事件流（波 2 方案 A /
	//    波 3 泛化）。事件接线的 transport 断言已在 Plan 同步校验
	//    （assertEventWiring），此处断言必过，只做类型收窄。
	//    内层序列结束后关闭 innerCh：外层生成器排空后退出（否则 drive
	//    永远等不到 genDone，Plan 的 goroutine 不返回，worker 的 for-range 挂死）。
	//    与既有单 ip 层链的差异：泛化后 wrapper 层（gre）也占一个 goroutine
	//    并从自己的通道排空——ip 层不再"直接"消费传输层产出，而是消费
	//    wrapper 层的产出（包数、顺序不变，只多一跳通道）。
	genDone := make(chan error, 1)
	go func() { genDone <- ipGen.Generate(ctx, ipReq) }()

	lastGen := gens[len(chain)-1]
	var lastErr error

	// 6. 管线接线（隧道链 T12/T13 泛化）：每层一条通道，逐层 goroutine 级联。
	//    transportIdx 是传输层（tcp/udp）索引，按 Category 定位——不能再用
	//    len-2：tls 隧道链 [ip→tcp→tls→http] 里 len-2 是 tls（tls 在 tcp 之内，
	//    TLS record 是 TCP payload），传输层是 chain[1]。wrapper 层是链上 ip
	//    与 transport 之间的隧道层（gre/内层 ip），transport 之内到终结层之间
	//    的隧道层（tls）是**事件变换器**——它不产包，只变换终结层事件流。
	//    既有链（[ip→tcp]/[ip→udp]/[ip→tcp→http]）无 wrapper 层，通道形状与
	//    旧实现完全相同。
	//
	//    通道方向（包从内向外流）：层 i>0 读 pipeCh[i]、写 pipeCh[i-1]
	//    （更外层的输入）；pipeCh[0] = innerCh（外层 ip 读）；transport
	//    （i=transportIdx）只写 pipeCh[transportIdx-1]。关闭者 = 写者：
	//    每通道恰一个关闭者，wrapper goroutine 退出时关闭自己的输出，
	//    transport 结束后关闭 pipeCh[transportIdx-1]（无 wrapper 时即
	//    innerCh）。级联拆除：transport 关 → wrapper 排空退出逐层关 →
	//    最内层 wrapper 关 innerCh → 外层 ip 排空退出。
	transportIdx := transportIndex(gens)
	if transportIdx < 0 {
		return nil, fmt.Errorf("layers: chain %s has no transport layer", layerNames(chain))
	}
	// pipeCh 只在有 wrapper 层时存在（[ip→tcp]/[ip→tcp→http] 无 wrapper 不建
	// 数组）；pipeCh[0]=innerCh 是外层 ip 的输入（gre wrapper 的输出目标）。
	// transportIdx==0 的 [ip→tcp] 链直接走 transportOut==innerCh，无 pipeCh。
	pipeCh := make([]chan core.PacketConfig, transportIdx)
	if transportIdx > 0 {
		pipeCh[0] = innerCh
	}
	wrapperDone := make([]chan error, 0, max(transportIdx-1, 0))
	for i := 1; i < transportIdx; i++ {
		ch := make(chan core.PacketConfig, 256)
		pipeCh[i] = ch
		// 每层独立 Sess 副本：IPGenerator 写 Sess.IPID，外层 ip（ipGen，
		// Sess: sess）与内层 ip（本循环内 wrapper）若共享同一指针会并发
		// 双写（data race）；各层副本从同一基值起步、互不相干。
		sessLayer := *sess
		wrapperReq := &GenRequest{
			Chain: chain,
			Layer: chain[i],
			Inner: pipeCh[i],
			Emit: func(pkt core.PacketConfig) error {
				// 本层产出交给更外层：写 pipeCh[i-1]（下一层输入）。
				// 注意：不是 ch（= pipeCh[i] 本层输入）——写回自己的输入
				// 会把包裹循环化且无人消费（曾致 send on closed channel）。
				select {
				case pipeCh[i-1] <- pkt:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Sess: &sessLayer,
			Meta: meta,
		}
		done := make(chan error, 1)
		wrapperDone = append(wrapperDone, done)
		go func(req *GenRequest, out chan core.PacketConfig, done chan error) {
			err := gens[i].Generate(ctx, req)
			// 级联拆除：本层退出即关闭**自己写入的**通道（pipeCh[i-1]），
			// 每通道单写者单关闭者——外层排空后退出。
			close(out)
			done <- err
		}(wrapperReq, pipeCh[i-1], done)
	}
	// transportOut 是传输层的输出通道（下一层输入）：无 wrapper
	// （[ip→tcp]/[ip→udp]/[ip→tcp→http]，transportIdx<=1）时即 innerCh——外层
	// ip 直接消费传输层产出，与旧实现同形状；有 wrapper 时是 wrapper 循环
	// 创建的最内层 wrapper 的输入通道（pipeCh[transportIdx-1]，如
	// [ip,gre,ip,tcp,http] 的 transport→内层 ip）。必须在循环后取——
	// 循环内 pipeCh[transportIdx-1] 尚未就位。
	transportOut := innerCh
	if transportIdx > 1 {
		transportOut = pipeCh[transportIdx-1]
	}
	// transportReq 是传输层生成器（tcp/udp）的驱动请求。Layer 按分支区分
	// （旧实现即如此）：事件分支（末层 http/dns）用 chain[transportIdx]——
	// tcp/udp 层读自己的层 config（窗口/MSS 等由层 config 携带）；非事件
	// 分支（独立 tcp/udp flow，[ip→tcp]）用 chain[len-1]——协议层即末层，
	// 其层 config 是协议参数（src_port/dst_port 等独立 flow 字段）。
	transportReq := &GenRequest{
		Chain: chain,
		Layer: chain[transportIdx],
		Emit: func(pkt core.PacketConfig) error {
			select {
			case transportOut <- pkt:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Sess: sess,
		Meta: meta,
	}
	// 事件生成器接线（http/dns/... 终结层）：事件流接入传输层 Meta.Events，
	// 传输层在"单 payload 模式"后消费事件流。T13 泛化（tls 变换器链）：
	// transport 之内的 CategoryTunnel 层（tls）不产包——它是**事件变换器**，
	// 经普通 Generate 驱动：从 req.Meta.Events 消费内层终结层事件流，变换
	// 后（tls 包成 ApplicationData record，握手 record 先注入）经 req.EmitMsg
	// 转发给更外层。事件流方向（内→外）：终结层 → 变换器链 → transport。
	// 关闭者 = 写者：终结层结束后关闭最内层变换器输入；变换器退出时关闭
	// 自己的输出；transport 消费到关闭退出。事件流关闭语义与单终结层一致：
	// tcp 把关闭视为数据段结束进入挥手。
	//
	// 每个变换器持自己的 FlowMeta 副本（Meta.Events = 自己的输入通道）——
	// 与 T12 的 sessLayer 副本同款：共享 meta 会让所有变换器读同一个输入流。
	if eg, ok := lastGen.(interface{ GenEvents() EventGenerator }); ok && eg.GenEvents() != nil {
		// 变换器链：transport 之内的层（i ∈ (transportIdx, len-1)）。终结层
		// 之前可能有多个变换器（[ip→tcp→tls→grpc→http] 式未来链）；当前
		// 只有 tls。transformers[0] = 最内层变换器（紧邻终结层）。
		var transformers []LayerGenerator
		for i := len(chain) - 2; i > transportIdx; i-- {
			transformers = append(transformers, gens[i])
		}
		n := len(transformers)
		// transformCh[k] = transformers[k] 的输入；transformCh[n] = transport
		// 的最终事件流。transformCh[0] 的写者 = 终结层（主线程驱动）。
		transformCh := make([]chan MessageEvent, n+1)
		for i := range transformCh {
			transformCh[i] = make(chan MessageEvent, 64)
		}
		meta.Events = transformCh[n]
		transportReq.Meta = meta
		// 变换器 goroutine（自最外层向最内层启动；各自阻塞读输入）。
		transformDone := make([]chan error, n)
		for k := 0; k < n; k++ {
			metaK := meta
			metaK.Events = transformCh[k]
			layerCfg := chain[transportIdx+1+k] // transformers[k] 的层 config
			out := transformCh[k+1]
			done := make(chan error, 1)
			transformDone[k] = done
			go func(gen LayerGenerator, layerCfg Layer, metaK FlowMeta, out chan MessageEvent, done chan error) {
				err := gen.Generate(ctx, &GenRequest{
					Layer: layerCfg,
					EmitMsg: func(ev MessageEvent) error {
						select {
						case out <- ev:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					},
					Sess: sess,
					Meta: metaK,
				})
				// 级联拆除：本变换器是 out 的唯一写者，退出即关闭。
				close(out)
				done <- err
			}(transformers[k], layerCfg, metaK, out, done)
		}
		// 终结层生成器的 EmitMsg 转发到最内层变换器输入（无变换器时即
		// transport 最终事件流，与旧实现同形状）。
		// Meta 契约（review T13 LOW-4）：终结层生成器经 Meta 读**配置值**
		// （Meta.HTTP/DNS/... 与 DstIP 等），绝不读 Meta.Events——Events 已被
		// 覆写为 transport 的最终事件流（transformCh[n]），终结层读它会把
		// 自己的输出当输入（自食）。事件流只经 req.EmitMsg 单向流出。
		reqForTerminal := &GenRequest{
			Chain: chain,
			Layer: chain[len(chain)-1],
			EmitMsg: func(ev MessageEvent) error {
				select {
				case transformCh[0] <- ev:
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
		switch tg := gens[transportIdx].(type) {
		case *TCPGenerator:
			transport = tg
		case *UDPGenerator:
			transport = tg
		default:
			// assertEventWiring 已同步拦截，理论不可达。
			return nil, fmt.Errorf("layers: layer %q cannot consume terminal events (unsupported transport generator %T)",
				chain[transportIdx].Name, gens[transportIdx])
		}
		transportDone := make(chan error, 1)
		go func() {
			err := transport.Generate(ctx, transportReq)
			// transport 是唯一写者，退出即关闭输出（级联拆除起点）。
			close(transportOut)
			transportDone <- err
		}()
		lastErr = lastGen.Generate(ctx, reqForTerminal)
		close(transformCh[0])
		// 变换器层级联排空退出（各自关闭输出），全部等待，不泄漏。
		// ctx 取消逃生口（review T13 MED-1）：变换器在错误/取消路径可能
		// 长时间排空输入或阻塞——等待必须能被 ctx 打断，否则取消/超时
		// 时 Plan 永久挂死。
		for _, done := range transformDone {
			select {
			case err := <-done:
				if err != nil && lastErr == nil {
					lastErr = err
				}
			case <-ctx.Done():
				// 取消逃生口（review T13 MED-1）：变换器阻塞排空时不能挂死。
				// 返回前必须等 ip 生成器退出（review transform-wiring F2）：
				// ip goroutine 可能在 finalEmit 里 append(packets)，Plan 的
				// goroutine 随后遍历 packets——并发读写 slice 头是数据竞态。
				// 错误路径（err != nil）Plan 本就不发包，但防御性等待保持
				// "ip 退出后 drive 才返回"契约在所有分支成立（LOW-3 同款）。
				<-genDone
				return packets, ctx.Err()
			}
		}
		if lastErr != nil {
			// 终结层/变换器失败：传输层仍会排空事件流（事件流关闭视为
			// 数据段结束，tcp 进入挥手 / udp 直接结束）。等待其退出，不泄漏。
			<-transportDone
		} else if err := <-transportDone; err != nil {
			lastErr = err
		}
		// wrapper 层级联排空退出（各自关闭输出），全部等待，不泄漏。
		for _, done := range wrapperDone {
			<-done
		}
		if err := <-genDone; err != nil {
			return packets, err
		}
		return packets, lastErr
	}

	// 无事件生成器：末层直接产包（波 1 的 [ip → tcp] 独立 tcp flow 路径）。
	// 非事件分支的 Layer 是末层（协议层本身，旧实现 tcpReq.Layer =
	// chain[len-1] 语义）——[ip→tcp] 链 transportIdx=0 时 chain[0] 是 ip 层，
	// TCPGenerator 读它拿不到端口/MSS。
	transportReq.Layer = chain[len(chain)-1]
	lastErr = lastGen.Generate(ctx, transportReq)
	close(transportOut)
	// 先等 wrapper/ip 级联退出再返回（review T13 LOW-3 修复）：提前返回会
	// 与 ip goroutine 的 finalEmit append 竞态（drive 返回后 Plan goroutine
	// 遍历 packets 与仍在 append 的 ip goroutine 并发）——关闭协议要求
	// "ip 生成器退出后（genDone）drive 才返回"在**所有**分支成立。
	for _, done := range wrapperDone {
		<-done
	}
	if err := <-genDone; err != nil {
		if lastErr == nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return packets, lastErr
	}
	return packets, nil
}

// translateTerminalConfig translates the chain's terminal layer config into
// the flow spec's protocol config (终结层配置翻译)。The chain passed in via
// NewChainPlannerFromChain carries the user's completed layer configs; the
// terminal generators (http/dns) read req.Meta.HTTP / req.Meta.DNS (= spec
// values), NOT the layer config, so without translation
// {"http":{"method":"POST"}} silently falls back to GET / and {"dns":{}} fails
// validation with "DNS config is required" (validate_layers.go 的
// validated-but-not-yet-effective)。
//
// Semantics:
//   - Flat path is authoritative: when spec.HTTP/spec.DNS is already set
//     (mapToFlowSpec read cfg["http"]/cfg["dns"]), translation is skipped and
//     the layer config is ignored — flat and layer configs are two ways to
//     express the same terminal protocol, and a strategy may carry either
//     (flat wins when both present).
//   - Only layers with a schema Field 说明书 are translated (http/dns; ftp/
//     smtp have schema fields but no generators). Other terminal layers
//     (ntp/snmp/... 无字段) leave the spec untouched.
//   - Field values come from the layer config with schema defaults applied
//     (V9 已保证 config 类型合法), falling back to the registry default when
//     absent — for http, empty strings are left as zero so buildHTTPRequest's
//     build-time defaults (Method→GET, URI→/, Version→"HTTP/1.1") apply;
//     for dns, the "name" default "example.com" must be materialized because
//     buildDNSQuery would encode an empty domain as an empty label.
func (p *ChainPlanner) translateTerminalConfig(spec *core.FlowSpec) {
	if len(p.chain) == 0 {
		return
	}
	r := p.effectiveRegistry()
	term := p.chain[len(p.chain)-1]
	s, ok := r.Get(term.Name)
	if !ok {
		return
	}
	if term.Name == "bgp" && spec.BGP == nil {
		spec.BGP = &core.BGPConfig{}
	}
	if term.Name == "pcep" && spec.PCEP == nil {
		spec.PCEP = &core.PCEPConfig{}
	}
	if term.Name == "ldp" && spec.LDP == nil {
		spec.LDP = &core.LDPConfig{}
	}
	if term.Name == "cflow" && spec.CFlow == nil {
		spec.CFlow = &core.CFlowConfig{}
	}
	if term.Name == "http_flv" && spec.HTTPFLV == nil {
		spec.HTTPFLV = &core.HTTPFLVConfig{}
	}
	if term.Name == "http_flv" && spec.HTTPFLV != nil {
		// 默认模板：空 Flags → 0x05 (audio+video)，空 Tags → onMetaData + AAC + AVC
		if spec.HTTPFLV.Flags == 0 {
			spec.HTTPFLV.Flags = 0x05
		}
		if spec.HTTPFLV.Tags == nil {
			spec.HTTPFLV.Tags = []core.FLVTag{
				{Type: "script", Timestamp: 0},
				{Type: "audio", Timestamp: 0, Data: []byte{0x11, 0x90}},
				{Type: "video", Timestamp: 0, Data: []byte{0x01, 0x42, 0x00, 0x1e, 0xff, 0xe1, 0x00, 0x1c, 0x67, 0x42, 0x00, 0x1e, 0x99, 0xa0, 0x0b, 0xf0, 0xf1, 0x70, 0x11, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x32, 0x0f, 0x16, 0x32, 0x78, 0x80, 0x01, 0x00, 0x07, 0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}},
			}
		}
		if spec.HTTPFLV.Rounds == 0 {
			spec.HTTPFLV.Rounds = 1
		}
	}
	if term.Name == "hls" && spec.HLS == nil {
		spec.HLS = &core.HLSConfig{}
	}
	if term.Name == "hls" && spec.HLS != nil {
		for i, s := range spec.HLS.Sessions {
			if s.Rounds == 0 {
				spec.HLS.Sessions[i].Rounds = 1
			}
		}
	}
	if term.Name == "hds" && spec.HDS == nil {
		spec.HDS = &core.HDSConfig{}
	}
	if term.Name == "hds" && spec.HDS != nil {
		for i, s := range spec.HDS.Sessions {
			if s.Rounds == 0 {
				spec.HDS.Sessions[i].Rounds = 1
			}
		}
	}
	if len(s.Fields) == 0 {
		return
	}
	switch term.Name {
	case "goose":
		return
	case "mms":
		if spec.MMS == nil {
			spec.MMS = &core.MMSConfig{}
		}
		return
	case "http":
		if spec.HTTP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		cfg := completedConfig(s, term.Config)
		spec.HTTP = &core.HTTPConfig{}
		if v, ok := configString(cfg["method"]); ok {
			spec.HTTP.Method = v
		}
		if v, ok := configString(cfg["uri"]); ok {
			spec.HTTP.URI = v
		}
		if v, ok := configString(cfg["version"]); ok {
			// 层 config 的 version 是裸版本号（schema 默认 "1.1"），
			// HTTPConfig.Version 契约是完整 "HTTP/1.1"（types.go:487；
			// builder 只默认空串，见 http.go:563-565）——prefix 归一，
			// 与 flat 路径一致（mapToFlowSpec 从 cfg["http"]["version"] 取
			// 裸值也是经 builder 渲染成 "HTTP/1.1" 的隐含依赖）。
			if !strings.HasPrefix(v, "HTTP/") {
				spec.HTTP.Version = "HTTP/" + v
			} else {
				spec.HTTP.Version = v
			}
		}
		if h, ok := cfg["headers"]; ok {
			if m, ok := h.(map[string]interface{}); ok {
				spec.HTTP.RequestHeaders = make(map[string]string, len(m))
				for k, v := range m {
					spec.HTTP.RequestHeaders[k] = fmt.Sprint(v)
				}
			}
		}
		if v, ok := configString(cfg["body"]); ok {
			spec.HTTP.Body = v
		}
	case "dns":
		if spec.DNS != nil {
			return // flat 权威
		}
		cfg := completedConfig(s, term.Config)
		spec.DNS = &core.DNSConfig{
			Domain:    "example.com", // schema 默认；buildDNSQuery 不默认空域名
			QueryType: 1,             // schema 默认（A 记录）
		}
		if v, ok := configString(cfg["name"]); ok {
			spec.DNS.Domain = v
		}
		if v, ok := configUint16(cfg["query_type"]); ok {
			spec.DNS.QueryType = v
		}
	case "postgresql":
		if spec.PostgreSQL != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 config（dialect/wire_profile/events/sessions/wire_fault）经 JSON
		// 往返解码为 core.PostgreSQLConfig：json tag 覆盖全部字段（含
		// events[].authtype *int32），比逐字段 map 取值更忠实。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return // 理论不可达（config 已是 JSON 可编码 map）
		}
		var pg core.PostgreSQLConfig
		if err := json.Unmarshal(raw, &pg); err == nil {
			// 默认值兜底：schema 默认已由 completedConfig 填充，这里再显式
			// 断言 dialect/wire_profile 非空（transcribe 防御）。
			if pg.Dialect == "" {
				pg.Dialect = "postgresql"
			}
			if pg.WireProfile == "" {
				pg.WireProfile = "postgresql_v3"
			}
			spec.PostgreSQL = &pg
		} else {
			// config 含非 JSON 可编码值（极端）→ 用一个最小默认，让后续
			// validator 报错而不是静默空流。
			spec.PostgreSQL = &core.PostgreSQLConfig{Dialect: "postgresql", WireProfile: "postgresql_v3"}
		}
	}
}

// completedConfig overlays the user layer config onto the schema defaults
// (用户层 config > schema 默认值，applySpecToChain 同款语义)。
func completedConfig(s LayerSchema, user map[string]interface{}) map[string]interface{} {
	cfg := make(map[string]interface{}, len(s.Fields))
	for k, f := range s.Fields {
		if f.Default != nil {
			cfg[k] = f.Default
		}
	}
	for k, v := range user {
		cfg[k] = v
	}
	return cfg
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
func isGOOSEChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "goose"
}

func isSVChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "sv"
}

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

// hasLayer reports whether the chain contains a layer named name.
func hasLayer(chain []Layer, name string) bool {
	for _, l := range chain {
		if l.Name == name {
			return true
		}
	}
	return false
}

// fieldContractDstPort resolves the terminal layer's FieldContract-driven
// destination port for the chain's transport layer (design §1.3/§10.3 R1).
// It reads the terminal layer's EffectiveFieldContract (dialect overrides
// applied) for a "tcp.dst_port"/"udp.dst_port" key and parses the constant to
// uint16. Returns 0 when the terminal declares no such contract.
func fieldContractDstPort(chain []Layer, r *Registry) uint16 {
	if len(chain) == 0 {
		return 0
	}
	fc := r.EffectiveFieldContract(chain[len(chain)-1])
	if fc == nil {
		return 0
	}
	for _, key := range []string{"tcp.dst_port", "udp.dst_port"} {
		if v, ok := fc[key]; ok {
			n, err := strconv.ParseUint(v, 10, 16)
			if err == nil {
				return uint16(n)
			}
		}
	}
	return 0
}

// nfsTransportFromMetadata extracts the NFS transport string from the flow
// metadata (P4a 载体一致性校验用)。core 无法 import protocol/nfs——元数据是
// spec.Metadata["nfs"]，生成器侧支持 *NFSConfig / map[string]interface{} /
// json.RawMessage 三种形态，此处只解析 transport 字段（配置缺失/字段缺失/
// 类型不符 → ""，由调用方按 legacy 默认 "tcp" 处理）。
func nfsTransportFromMetadata(v interface{}) (string, bool) {
	switch m := v.(type) {
	case nil:
		return "", false
	case map[string]interface{}:
		s, ok := m["transport"].(string)
		return s, ok
	case json.RawMessage:
		var tmp struct {
			Transport string `json:"transport"`
		}
		if err := json.Unmarshal(m, &tmp); err != nil {
			return "", false
		}
		return tmp.Transport, tmp.Transport != ""
	default:
		// 生成器侧已解析的 *NFSConfig（测试直驱等场景）——反射读字段，
		// 避免 layers → protocol/nfs 的依赖环。
		rv := reflect.ValueOf(m)
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}
		if rv.Kind() == reflect.Struct {
			f := rv.FieldByName("Transport")
			if f.IsValid() && f.Kind() == reflect.String {
				return f.String(), f.String() != ""
			}
		}
	}
	return "", false
}

func setFinsTransport(v interface{}, transport string) {
	switch m := v.(type) {
	case map[string]interface{}:
		m["transport"] = transport
	default:
		if v == nil {
			return
		}
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Ptr || rv.IsNil() {
			return
		}
		field := rv.Elem().FieldByName("Transport")
		if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
			field.SetString(transport)
		}
	}
}

func finsTransportFromMetadata(v interface{}) (string, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		s, ok := m["transport"].(string)
		return s, ok
	case json.RawMessage:
		var raw struct {
			Transport string `json:"transport"`
		}
		if err := json.Unmarshal(m, &raw); err != nil {
			return "", false
		}
		return raw.Transport, raw.Transport != ""
	default:
		if v == nil {
			return "", false
		}
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Ptr {
			if rv.IsNil() {
				return "", false
			}
			rv = rv.Elem()
		}
		if rv.Kind() == reflect.Struct {
			field := rv.FieldByName("Transport")
			if field.IsValid() && field.Kind() == reflect.String {
				return field.String(), field.String() != ""
			}
		}
	}
	return "", false
}

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
	case "eth":
		// eth 是 L2 占位层（goose/sv 链 [eth→goose/sv]）：L2 头由终结层
		// 生成器自行构建完整 PacketConfig（含 SrcMAC/DstMAC/EtherType），
		// eth 层只要求可实例化、不产包（Generate 直通返回 nil）。
		return &ethPlaceholderGenerator{}, nil
	case "goose":
		if factory, ok := registeredGenerators["goose"]; ok {
			return factory()
		}
	}
	if name == "sv" {
		if factory, ok := registeredGenerators["sv"]; ok {
			return factory()
		}
	}
	return nil, fmt.Errorf("layers: generator not implemented for layer %q", name)
}

// ethPlaceholderGenerator is the L2 eth-layer generator (goose/sv 链
// [eth→goose/sv] 的占位层). 终结层生成器自行构建完整 PacketConfig（含
// SrcMAC/DstMAC/EtherType），eth 层只需可实例化、不产包——Generate 直通。
type ethPlaceholderGenerator struct{}

func (*ethPlaceholderGenerator) Name() string { return "eth" }

func (*ethPlaceholderGenerator) Generate(ctx context.Context, req *GenRequest) error {
	return nil
}

func (*ethPlaceholderGenerator) GenEvents() EventGenerator { return nil }

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
