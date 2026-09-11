package layers

import (
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Package layers is part of the layer-chain architecture (v3) for
// the trafficgen core. This file is one of the five chain_planner*.go
// files split from the original monolithic chain_planner.go
// (T1.3 of docs/superpowers/plans/2026-09-03-layerchain-implementation.md).
//
// Original file: 2,893 lines (5 sections, 65 functions).
// This file: chain_planner_util.go
//   - is*Chain helpers + per-config reflection (nfs/fins transport extraction) + transportProtocol/hasLayer/fieldContractDstPort.
//
// Per-package conventions: type names (ChainPlanner, FlowMeta, etc.)
// are package-local; only file boundaries change.

// isHTTPChain reports whether the chain's terminal layer is http
// (http 链判定：末层即协议层）。Used by applySpecToChain to force the
// legacy http TCP semantics (忽略 handshake/termination/rst 开关)。
func isGOOSEChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "goose"
}

func isSVChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "sv"
}

// isRawIPChain reports whether the chain's terminal layer is a raw-IP routing
// protocol (P3 T5: [ip→igmp/ospf/pim]) with no tcp/udp transport, or the B4
// nvgre terminal layer ([ip→nvgre], self-built outer IP proto 47 + L2.GRE).
// These emit full packets via the terminal generator (drive's transportIndex
// would be -1, so they need a dedicated branch like the goose/sv L2-only
// path).
func isRawIPChain(name string, chain []Layer) bool {
	if len(chain) == 0 {
		return false
	}
	switch chain[len(chain)-1].Name {
	case "igmp", "ospf", "pim", "nvgre":
		return true
	}
	return name == "igmp" || name == "ospf" || name == "pim" || name == "nvgre"
}

// isCarrierMixedChain reports whether the terminal layer self-drives mixed
// UDP+TCP carriers (ldp dual_adjacency: UDP discovery Hello + TCP session on
// one flow). Like raw-IP chains, the [ip, ldp] chain has no transport layer
// and the terminal generator assembles complete packets.
func isCarrierMixedChain(name string, chain []Layer) bool {
	if name != "ldp" {
		return false
	}
	// 用户显式写 tcp 传输层 → 由事件路径负责（plain event path）；合成链
	// 携带的 udp 层（ldp DependsOn）不算——dual_adjacency 自产完整包。
	for _, l := range chain {
		if l.Name == "tcp" {
			return false
		}
	}
	return true
}

// openwireNeedsSelfDrive reports whether any openwire connection declares
// its own L3 addresses（双栈自驱触发条件——显式地址连接无法经 v4 spec 的
// ip 层事件路径，见 Plan 的 B5 自驱分支）。
func openwireNeedsSelfDrive(cfg *core.OpenWireConfig) bool {
	for i := range cfg.Connections {
		if cfg.Connections[i].SrcIP != "" || cfg.Connections[i].DstIP != "" {
			return true
		}
	}
	return false
}

// gnutellaNeedsSelfDrive is the Gnutella same-shape trigger (B5 双栈自驱)。
func gnutellaNeedsSelfDrive(cfg *core.GnutellaConfig) bool {
	for i := range cfg.Connections {
		if cfg.Connections[i].SrcIP != "" || cfg.Connections[i].DstIP != "" {
			return true
		}
	}
	return false
}

// swarmNeedsSelfDrive is the Swarm same-shape trigger (B5 双栈自驱)。
func swarmNeedsSelfDrive(cfg *core.SwarmConfig) bool {
	for i := range cfg.Connections {
		if cfg.Connections[i].SrcIP != "" || cfg.Connections[i].DstIP != "" {
			return true
		}
	}
	return false
}

// amsNeedsSelfDrive is the AMS same-shape trigger (B5 双栈/多流自驱)。
func amsNeedsSelfDrive(cfg *core.AMSConfig) bool {
	for i := range cfg.Connections {
		if cfg.Connections[i].SrcIP != "" || cfg.Connections[i].DstIP != "" {
			return true
		}
	}
	return false
}

// nmeaNeedsSelfDrive reports whether any nmea session declares transport:"udp"
// (会话级 transport 路由，nmea_tcp_udp_coexist 双载体 fixture：终结层需按
// transport 字段把事件分发到不同载体，TCP 自产握手/挥手，UDP 自产数据报）。
// 单一 transport（全部 tcp 或全部 ""）走既有事件接线路径即可，无需自驱。
func nmeaNeedsSelfDrive(cfg *core.NMEAConfig) bool {
	if cfg == nil {
		return false
	}
	for i := range cfg.Sessions {
		if cfg.Sessions[i].Transport == "udp" {
			return true
		}
	}
	return false
}

func isHTTPChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "http"
}

// isMMSChain reports whether the chain's terminal layer is mms（mms 链强制
// 并发会话 TCP 语义：termination=false + concurrent=true）。
func isMMSChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "mms"
}

// isFTPChain reports whether the chain's terminal layer is ftp（FTP 链化：
// 多会话/数据通道靠事件端口覆盖合成独立 connKey，tcp 层须 concurrent=true）。
func isFTPChain(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "ftp"
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

// isCWMPChainWithFlows reports whether the chain's terminal layer is cwmp
// (flows[] side connections insert independent four-tuples mid-stream — side
// GET/PUT + CloseConn teardown — so the tcp layer must run
// concurrent=true; the sequential 挥旧握新 semantic would tangle side and
// main connections. See applySpecToChain tcp 分支, 设计 §5 流关联).
func isCWMPChainWithFlows(chain []Layer) bool {
	return len(chain) > 0 && chain[len(chain)-1].Name == "cwmp"
}

// nmeaSessionRST reports whether any nmea session or the nmea config block
// declares termination:"rst"（设计 69-nmea §5 正例 46：RST 异常中断 =
// 3+N+1 单侧 RST、无 FIN 挥手）。会话级声明必须翻译到 tcp 层 rst=true
//（cfg.rst 使 TCPGenerator 以单帧 RST|ACK(up) 短路收尾），否则 tcp 层
// 按默认 FIN 挥手出 3+N+4。NMEAConfig.Termination 是全 session 默认
// 覆盖（NMEAConfig 缺省，per-session 优先）；per-session
// Termination="" 时回退到 config-level 声明。
// 见 applySpecToChain tcp 分支。
func nmeaSessionRST(cfg *core.NMEAConfig) bool {
	if cfg == nil {
		return false
	}
	if cfg.Termination == "rst" {
		return true
	}
	for _, s := range cfg.Sessions {
		if s.Termination == "rst" {
			return true
		}
	}
	return false
}

// transportProtocol resolves the IP protocol number from the chain's
// transport layer (tcp=6 / udp=17)。独立 transport flow（[ip→udp]，传输层即
// 末层）看末层；终结层链（[ip→tcp→http]）看倒数第二层。raw-IP 终结层
// （[ip→igmp/ospf/pim]）看末层协议号（2/89/103）。无传输层时回退 TCP
// （理论不可达：transport 层是 ip 的 depends_on 补全必插入）。
func transportProtocol(chain []Layer) uint8 {
	if len(chain) > 0 {
		switch chain[len(chain)-1].Name {
		case "udp":
			return core.ProtocolUDP
		case "tcp":
			return core.ProtocolTCP
		case "igmp":
			return core.ProtocolIGMP
		case "ospf":
			return core.ProtocolOSPF
		case "pim":
			return core.ProtocolPIM
		}
	}
	if len(chain) > 1 {
		switch chain[len(chain)-2].Name {
		case "udp":
			return core.ProtocolUDP
		case "tcp":
			return core.ProtocolTCP
		case "igmp":
			return core.ProtocolIGMP
		case "ospf":
			return core.ProtocolOSPF
		case "pim":
			return core.ProtocolPIM
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
