package layers

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Package layers is part of the layer-chain architecture (v3) for
// the trafficgen core. This file is one of the five chain_planner*.go
// files split from the original monolithic chain_planner.go
// (T1.3 of docs/superpowers/plans/2026-09-03-layerchain-implementation.md).
//
// Original file: 2,893 lines (5 sections, 65 functions).
// This file: chain_planner_gen.go
//   - newGenerator() + Register*LayerGenerator API + eth placeholder + l2For/multicastDstMAC/ipTTL (per-packet L2/L3 helpers).
//
// Per-package conventions: type names (ChainPlanner, FlowMeta, etc.)
// are package-local; only file boundaries change.


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
	case "vlan":
		// vlan 是 L2 wrapper 占位层（D-GRE-3）：tag 由 ValidateSpec 提取进
		// spec.VLAN、经 l2For 在 finalEmit 落定；生成器只逐包透传。
		return &vlanPassthroughGenerator{}, nil
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

// vlanPassthroughGenerator is the L2 vlan-layer generator (D-GRE-3).
// 与 eth 占位层不同：eth 恒为 chain[0]（非 wrapper，Generate 永不被调）、
// vlan 恒为 wrapper 层（drive 级联为每个 wrapper 起 goroutine 从 Inner 消费）。
// nil 直返会 strand 封包（内层产出无人消费→静默空流），故必须逐包透传 Emit。
type vlanPassthroughGenerator struct{}

func (*vlanPassthroughGenerator) Name() string { return "vlan" }

func (*vlanPassthroughGenerator) Generate(ctx context.Context, req *GenRequest) error {
	if req.Inner == nil || req.Emit == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-req.Inner:
			if !ok {
				return nil
			}
			if err := req.Emit(pkt); err != nil {
				return err
			}
		}
	}
}

func (*vlanPassthroughGenerator) GenEvents() EventGenerator { return nil }

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
