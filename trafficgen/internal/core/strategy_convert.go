package core

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// Default field values applied by mapToFlowSpec when the user did not
// provide a value. Per the "user > default > none" rule, explicit user
// values (including 0 for numeric fields where 0 is a valid choice) MUST
// be honored -- defaults only fill in gaps.
const (
	// NFSMetadataKey is the FlowSpec.Metadata key used by the NFS planner.
	// core cannot import protocol/nfs (import cycle), so the strategy
	// converter writes the raw "nfs" sub-map under this key and
	// nfs.GetConfig deserializes it.
	NFSMetadataKey = "nfs"

	// DefaultSrcMAC / DefaultDstMAC: locally-administered IEEE 802 MACs
	// (02: prefix) so trafficgen packets are visually distinct from real
	// hosts on the wire. Filter: ether src 02:00:00:00:00:00/16
	DefaultSrcMAC = "02:00:00:00:00:01"
	DefaultDstMAC = "02:00:00:00:00:02"

	// DefaultSrcIP / DefaultDstIP: 10.0.0.1 / 20.0.0.1 -- different /24
	// subnets so DPI/firewall tests see a routed (inter-subnet) flow rather
	// than a switched (intra-subnet) one. Formerly 192.0.2.1/192.0.2.2 (RFC
	// 5737 TEST-NET-1, same /24) which made src and dst DPI land in the same
	// subnet and defeated cross-subnet test scenarios.
	// These are SYNTHETIC test IPs (not assigned to any real NIC) -- per
	// trafficgen's "fake packets for testing" contract, they must not match
	// system NIC addresses. Users running real-traffic tests override with
	// actual routable IPs.
	DefaultSrcIP = "10.0.0.1"
	DefaultDstIP = "20.0.0.1"

	// DefaultSrcPort: high non-privileged port (>1024) typical of client
	// ephemeral ports. Multi-flow scenarios should use batch tuples to
	// vary src_port per flow.
	DefaultSrcPort = 12345

	// DefaultDstPort: 80 (HTTP) is the most common test target for TCP/UDP.
	// Protocol-specific defaults (DNS=53) still override this in their
	// switch cases.
	DefaultDstPort = 80

	// DefaultDSCP: CS1 (Class Selector 1, 0x08=8). Visible in the IP TOS
	// byte as 0x20 (0x08<<2). CS1 is RFC 4594 "less than best-effort" --
	// background traffic class that does NOT compete with business traffic
	// for the default (BE) queue. Marks every trafficgen IP packet so it
	// can be filtered out of noisy captures:
	//   tcpdump 'ip[1] & 0xfc == 0x20'
	// User can override with dscp=0 for plain best-effort, or dscp=0x2E
	// for EF (legacy behavior, affects business traffic).
	DefaultDSCP = 0x08

	// DefaultIPFlags: DF=1 (Don't Fragment). Matches modern OS TCP defaults
	// (Linux/macOS/Windows set DF=1 for TCP PMTU discovery). User can
	// override with flags=0 to allow fragmentation.
	DefaultIPFlags = 0x02 // IPFlagDF
)

// StrategyModelToTask converts a StrategyModel + TaskModel into a core.Task for the engine.
// Each strategy produces one engine task with a composite ID "{taskID}-{strategyID}".
// ifaceOverride, when non-empty, overrides the interface name (resolved from port_group by caller).
func StrategyModelToTask(taskModel *storage.TaskModel, strategy *storage.StrategyModel, ifaceOverride string) (*Task, error) {
	// Output config from task model — parsed first because replay and synth
	// branches both need it.
	var outputCfg struct {
		PortGroupID string `json:"port_group_id"`
		PcapPath    string `json:"pcap_path"`
	}
	json.Unmarshal([]byte(taskModel.OutputConfig), &outputCfg)

	outputMode := "pcap"
	iface := ""
	pcapFile := outputCfg.PcapPath
	if taskModel.OutputType == "port_group" {
		outputMode = "interface"
		pcapFile = ""
		iface = ifaceOverride
	} else if outputCfg.PcapPath != "" {
		pcapFile = outputCfg.PcapPath
	}

	// Task-level flow control: parsed into typed fields for the engine to
	// consume as an aggregate ceiling (parent rate bucket / shared flow
	// counter / parent context deadline). Unlike the legacy behaviour, this
	// does NOT overwrite spec.BPS/Count/Duration — the strategy-level limits
	// remain in spec and the task-level value caps the aggregate on top.
	var taskFC struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	}
	if taskModel.FlowControl != "" {
		json.Unmarshal([]byte(taskModel.FlowControl), &taskFC)
	}

	// Replay branch: no protocol planner, no mapToFlowSpec. The raw strategy
	// Config is passed as Replay JSON for the replay planner to interpret.
	if strategy.Mode == "replay" {
		task := &Task{
			ID:           fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
			Name:         strategy.Name,
			Mode:         "replay",
			Replay:       json.RawMessage(strategy.Config),
			ClassID:      fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
			ParentTaskID: taskModel.ID,
			Interface:    iface,
			OutputMode:   outputMode,
			PcapFile:     pcapFile,
			TaskFCType:   taskFC.Type,
			TaskFCValue:  taskFC.Value,
			UserID:       taskModel.UserID,
		}
		// bps mode: extract speed.bps into Spec.BPS so the engine creates a
		// per-strategy child rate-limiter bucket for this task (same as synth).
		var rs struct {
			Speed struct {
				Mode string `json:"mode"`
				BPS  string `json:"bps"`
			} `json:"speed"`
		}
		if json.Unmarshal([]byte(strategy.Config), &rs) == nil && rs.Speed.Mode == "bps" {
			task.Spec.BPS = rs.Speed.BPS
		}
		return task, nil
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(strategy.Config), &cfg); err != nil {
		return nil, fmt.Errorf("invalid strategy config JSON: %w", err)
	}

	spec := mapToFlowSpec(cfg, strategy.Protocol)

	// Flow control from strategy
	var fc struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	}
	if strategy.FlowControl != "" {
		json.Unmarshal([]byte(strategy.FlowControl), &fc)
	}
	switch fc.Type {
	case "bps":
		spec.BPS = formatBPS(fc.Value)
	case "flows":
		spec.Count = int(fc.Value)
	case "time":
		spec.Duration = int(fc.Value)
	}

	return &Task{
		ID:           fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
		Name:         strategy.Name,
		Protocol:     strategy.Protocol,
		Spec:         spec,
		ClassID:      fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
		ParentTaskID: taskModel.ID,
		Interface:    iface,
		OutputMode:   outputMode,
		PcapFile:     pcapFile,
		TaskFCType:   taskFC.Type,
		TaskFCValue:  taskFC.Value,
	}, nil
}

// mapToFlowSpec builds a FlowSpec from a config map and protocol name. It
// populates L2/L3/L4 and protocol-specific fields. It does NOT set BPS/Count/
// Duration (those come from flow control and are the caller's responsibility).
// Shared by StrategyModelToTask (single-protocol tasks) and the mixed-traffic
// batch path (TrafficClass.Config).
//
// Defaulting follows the unified rule (user > default > none): when a field
// is absent from cfg, the corresponding Default* constant fills in. Numeric
// fields where 0 is a valid user choice (DSCP=best-effort, IPFlags=no-DF) use
// hasKey to distinguish "absent" from "explicitly 0".
//
// Backward compatibility: several fields were renamed to remove ambiguity —
// "flags" -> "ip_flags" (was ambiguous with TCP flags), "content_encoding"
// -> "response_content_encoding" (sounded global but only affects response),
// "response" -> "is_response" (UDP/DNS, was ambiguous with FTP response
// bodies). The new name is preferred when present; the legacy name is read
// as fallback so existing DB rows keep working.
// mapToFlowSpec converts a strategy config map to a FlowSpec with defaults.
// Follows "user > default > none" rule for all fields.
//
// Default values (from strategy_convert.go constants):
//   - src_ip: 10.0.0.1 (TEST-NET-1, different /24 for routed flow testing)
//   - dst_ip: 20.0.0.1 (TEST-NET-1)
//   - src_mac: 02:00:00:00:00:01 (locally-administered, trafficgen marker)
//   - dst_mac: 02:00:00:00:00:02 (locally-administered)
//   - src_port: 12345 (high non-privileged port)
//   - dst_port: 80 (HTTP default); DNS overrides to 53
//   - ttl: 64
//   - dscp: 0x08 (CS1, background traffic, TOS byte 0x20)
//   - ip_flags: 0x02 (DF=1, matches modern OS TCP defaults)
//
// User-provided values (including 0, empty string, or null) override defaults.
// The presence-check pattern (v, ok := cfg[key]; ok && v != nil) distinguishes
// "user didn't provide" from "user explicitly provided 0/empty".
//
// Multi-flow scenarios: when flowCount > 1 and user didn't explicitly provide
// src_port, the worker auto-increments src_port per flow (simulating ephemeral
// ports). This prevents 4-tuple collisions that confuse Wireshark. See
// worker.go processTask for the increment logic.
// isL2OnlyProtocol reports whether the protocol is an L2-only terminal layer
// (goose/sv: DependsOn eth, no ip/tcp/udp 承载层). These ride directly on eth
// with no L3/L4, so mapToFlowSpec must not fill the default src_ip/dst_ip/
// src_port/dst_port (10.0.0.1/20.0.0.1/12345/80) — those are fake values on a
// chain without an IP layer and get rejected by the terminal layer's "L2 only"
// validator. goose/sv are L2-only by nature; any chain that adds an ip/tcp
// layer is itself invalid and left to the validator to reject.
func isL2OnlyProtocol(protocol string) bool {
	switch protocol {
	case "goose", "sv", "arp":
		return true
	}
	return false
}

// defaultL2String mirrors defaultString for L2-only chains: user value when
// present AND non-nil, def when absent. For L2-only chains def is "" (no IP).
func defaultL2String(cfg map[string]interface{}, key string, l2Only bool, def string) string {
	if l2Only {
		def = ""
	}
	return defaultString(cfg, key, def)
}

// defaultL2Port mirrors defaultPort for L2-only chains: user value when present
// AND non-nil, def when absent. For L2-only chains def is 0 (no port).
func defaultL2Port(cfg map[string]interface{}, key string, l2Only bool, def uint16) uint16 {
	if l2Only {
		def = 0
	}
	return defaultPort(cfg, key, def)
}

// extractLayerSrcDst returns the explicit src/dst addresses from the ip layer
// of a layers-chain config (分层架构: IP 属于 ip 层，层链的 IP 真相在
// layers[ip].src/dst，而 flat src_ip/dst_ip 是 legacy 默认). Returns empty
// strings for chains that do not explicitly write ip.src/dst. layersVal is the
// decoded "layers" array: []interface{}{map[string]interface{}{"ip": {...}}, ...}.
// extractLayerMACs returns the explicit static src_mac/dst_mac from the eth
// layer of a layers-chain config (D-REWORK-1，CORE_MEMORY 1.11：MAC 真相住
// eth 层，顶层 src_mac/dst_mac 与 layers 并存已被 checkLayerFlatConflict
// 拒绝）。只提静态标量；动态对象照旧走 parseLayerDyn→resolveLayerTuple
// 逐流写入 spec。Returns empty strings when absent.
func extractLayerMACs(layersVal interface{}) (src, dst string) {
	arr, _ := layersVal.([]interface{})
	for _, item := range arr {
		layer, _ := item.(map[string]interface{})
		ethCfg, _ := layer["eth"].(map[string]interface{})
		if ethCfg == nil {
			continue
		}
		if s, ok := ethCfg["src_mac"].(string); ok {
			src = s
		}
		if d, ok := ethCfg["dst_mac"].(string); ok {
			dst = d
		}
		return src, dst
	}
	return "", ""
}

// extractLayerIPTTL returns the explicit ttl from the ip layer of a
// layers-chain config（D-REWORK-1：http_ttl_custom 顶层影子迁除后，ip 层
// 显式 ttl 是唯一真相）。Present-but-zero 与顶层 getIntDefault 口径一致。
func extractLayerIPTTL(layersVal interface{}) (ttl uint8, present bool) {
	arr, _ := layersVal.([]interface{})
	for _, item := range arr {
		layer, _ := item.(map[string]interface{})
		ipCfg, _ := layer["ip"].(map[string]interface{})
		if ipCfg == nil {
			continue
		}
		v, ok := ipCfg["ttl"]
		if !ok || v == nil {
			return 0, false
		}
		switch n := v.(type) {
		case float64:
			return uint8(n), true
		case int:
			return uint8(n), true
		}
		return 0, false
	}
	return 0, false
}

func extractLayerSrcDst(layersVal interface{}) (src, dst string) {
	arr, _ := layersVal.([]interface{})
	for _, item := range arr {
		layer, _ := item.(map[string]interface{})
		ipCfg, _ := layer["ip"].(map[string]interface{})
		if ipCfg == nil {
			continue
		}
		if s, _ := ipCfg["src"].(string); s != "" {
			src = s
		}
		if d, _ := ipCfg["dst"].(string); d != "" {
			dst = d
		}
		return src, dst
	}
	return "", ""
}

func mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	// L2-only 链（goose/sv：DependsOn eth，无 ip/tcp/udp 承载层）没有 L3/L4，
	// 填默认的 src_ip/dst_ip/src_port/dst_port 是假值（10.0.0.1/20.0.0.1/
	// 12345/80），且会被终结层"L2 only"校验拒收。此时默认应为空/0，仅保留
	// 用户显式值（显式写 IP/port 交由终结层校验拒绝）。
	l2Only := isL2OnlyProtocol(protocol)
	spec := FlowSpec{
		SrcIP:      defaultL2String(cfg, "src_ip", l2Only, DefaultSrcIP),
		DstIP:      defaultL2String(cfg, "dst_ip", l2Only, DefaultDstIP),
		SrcPort:    defaultL2Port(cfg, "src_port", l2Only, DefaultSrcPort),
		DstPort:    defaultL2Port(cfg, "dst_port", l2Only, DefaultDstPort),
		SrcMAC:     defaultMAC(cfg, "src_mac", DefaultSrcMAC),
		DstMAC:     defaultMAC(cfg, "dst_mac", DefaultDstMAC),
		TTL:        uint8(getIntDefault(cfg, "ttl", 64)),
		TOS:        uint8(getInt(cfg, "tos")),
		DSCP:       defaultDSCP(cfg),
		ECN:        uint8(getInt(cfg, "ecn")),
		IPFlags:    defaultIPFlags(cfg),
		FragOffset: uint16(getInt(cfg, "frag_offset")),
		HopByHop:   parseHopByHopOptions(cfg["hop_by_hop"]),
		Payload:    []byte(getString(cfg, "payload")),
	}

	// Track whether user explicitly provided src_port (for multi-flow auto-increment)
	if _, ok := cfg["src_port"]; ok && cfg["src_port"] != nil {
		spec.HasExplicitSrcPort = true
	}
	// D-SV-1 ⑥（P5 sv_mac_dyn_inc 实测红转绿）：L2-only（goose/sv）无端口
	// 概念——worker 多流保底递增（worker.go DefaultSrcPort+i）会注入假端
	// 口，被终结层 "Layer 2 only" 校验拒收。l2Only 恒置 HasExplicitSrcPort
	// =worker 跳过递增，spec 端口保持 0 值真相（校验器零值口径不变）。
	// goose 同享（12.9 MAC 动态逃生口的 flows 面一并打通）。
	if l2Only {
		spec.HasExplicitSrcPort = true
	}

	// Task 5（扁平删除，FTP 层链收尾计划）：protocol==ftp 的扁平配置判死。
	// create/update 已在 schema 层 400（core.CheckFTPFlat 单一真相）；此处
	// 覆盖在库旧策略（扁平形状入库、任务启动时才转换）与引擎直调路径 →
	// spec.ValidationErrors，worker 预检终态 error。放在 D-FTP-3 §5 对象
	// 检查之前：ftp 语境下"必须是标量"是错误指引，正确指引是迁层链。
	if protocol == "ftp" {
		if msg := CheckFTPFlat(cfg); msg != "" {
			spec.ValidationErrors = append(spec.ValidationErrors, msg)
		}
	}
	// D-HTTP-1 重走步骤 3：http 族在库旧策略顶层 http → ValidationErrors
	// （新建/更新已在 schema 层经 CheckProtoFlat 400；此处覆盖存量行启动）。
	switch protocol {
	case "http", "http_flv", "hls", "hds", "gbt", "getwork", "cwmp", "doh", "onvif":
		if v, ok := cfg["http"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-MQTT-1：mqtt 在库旧策略顶层 mqtt → ValidationErrors（存量行启动
	// 即 error，worker 预检终态；新建/更新已在 schema 层经 CheckProtoFlat
	// 400）。空 map 也死（presence 语义）。
	if protocol == "mqtt" {
		if v, ok := cfg["mqtt"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-CWMP-1：cwmp 在库旧策略顶层 cwmp → ValidationErrors（mqtt 同款；
	// B6 注入形退役——2026-09-22 在库实测 0|0 无存量迁移面，纯防御）。
	if protocol == "cwmp" {
		if v, ok := cfg["cwmp"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-MEGACO-1：megaco 在库旧策略顶层 megaco → ValidationErrors（cwmp
	// 同款；B6 注入形退役——在库实测 0 行无存量迁移面，纯防御）。
	if protocol == "megaco" {
		if v, ok := cfg["megaco"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-SMB-1：smb 在库旧策略顶层 smb → ValidationErrors（sstp 同款；
	// 空 map 也死——testcase §4.3 判死形状「层链+顶层空子映射并存」wired 面）。
	if protocol == "smb" {
		if v, ok := cfg["smb"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-SSTP-1：sstp 在库旧策略顶层 sstp → ValidationErrors（hl7/mmse 同款；
	// 空 map 也死——契约 §16-P2 判死形状「层链+顶层空子映射并存」wired 面）。
	if protocol == "sstp" {
		if v, ok := cfg["sstp"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-TDS-1：tds 在库旧策略顶层 tds → ValidationErrors（sstp 同款；空
	// map 也死——顶层 tds 子映射 presence 判死，层链形状不触发）。
	if protocol == "tds" {
		if v, ok := cfg["tds"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-TFTP-1：tftp 在库旧策略顶层 tftp → ValidationErrors（sstp 同款；
	// 空 map 也死——契约 §13-P2 判死形状「层链+顶层空子映射并存」wired 面）。
	if protocol == "tftp" {
		if v, ok := cfg["tftp"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-NFS-1：nfs 在库旧策略顶层 nfs → ValidationErrors（mmse 同款；
	// 在库 0 行纯防御——新协议去扁平后顶层 nfs 即判死）。
	if protocol == "nfs" {
		if v, ok := cfg["nfs"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-ENIP-1（G-ENIP-3，§14-P2）：enip 在库旧策略顶层 enip →
	// ValidationErrors（sstp 同款；空 map 也死——判死形状「层链+顶层空子
	// 映射并存」wired 面；135/135 例并存现状的执法口）。
	if protocol == "enip" {
		if v, ok := cfg["enip"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-HL7-1：hl7 在库旧策略顶层 hl7 → ValidationErrors（megaco 同款；
	// 在库 0 行纯防御）。
	if protocol == "hl7" {
		if v, ok := cfg["hl7"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}

	// D-MMSE-1：mmse 在库旧策略顶层 mmse → ValidationErrors（hl7 同款；
	// 在库 0 行纯防御）。
	if protocol == "mmse" {
		if v, ok := cfg["mmse"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-OCSP-1：ocsp 在库旧策略顶层 ocsp → ValidationErrors（mmse 同款；
	// 在库 0 行纯防御——新协议无存量迁移面）。
	if protocol == "ocsp" {
		if v, ok := cfg["ocsp"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-AMQP-1：amqp 在库旧策略顶层 amqp → ValidationErrors（ocsp 同款；
	// 在库 0 行纯防御——新协议无存量迁移面）。
	if protocol == "amqp" {
		if v, ok := cfg["amqp"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}
	// D-MMS-2（G-MMS-1，§14-P2）：mms 在库旧策略顶层 mms → ValidationErrors
	// （amqp 同款；在库 0 行纯防御——新协议无存量迁移面）。
	if protocol == "mms" {
		if v, ok := cfg["mms"]; ok && v != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, CheckProtoFlat(protocol, cfg))
		}
	}

	// D-FTP-3 §5: 扁平四键收动态对象（引擎直调路径，REST 形状层已先 400）→
	// spec.ValidationErrors 拒绝并指路层字段，worker 预检终态 error，绝不
	// 静默回退缺省。注意 defaultString/defaultPort 对对象值恒回缺省，本分支
	// 必须在缺省读入之后、parseLayerDyn 之前——对象值在此被判死，不会流入
	// 静态 spec，也不会被误判为"显式标量"触发层链静态复制（该门只看层内）。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port"} {
		if m, ok := cfg[k].(map[string]any); ok && m != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				"flat four-tuple field "+k+" must be a scalar (四元组动态请写层字段：ip.src/ip.dst、tcp/udp.src_port/dst_port)")
		}
	}

	// 层链 IP 真相在 layers[ip].src/dst（分层架构：IP 属于 ip 层）。flat
	// src_ip/dst_ip 是 legacy 默认（10.0.0.1/20.0.0.1），层链显式写 ip 层
	// src/dst（含 IPv6）时必须以此为准，否则默认 IPv4 会顶掉层里的显式
	// IPv6 地址（EtherType 也据此选 IPv6）。空值保留 spec 默认。
	// D-FTP-4 注记：extractLayerSrcDst 只提字符串标量——动态对象端自然落空、
	// 保留 flat 默认，逐流真相由 worker resolveLayerTuple 写入 spec；对象端
	// 与静态端的族一致性由 ValidateLayers 形状层保证（混族即 400），此处不判。
	if layersVal, ok := cfg["layers"]; ok {
		if src, dst := extractLayerSrcDst(layersVal); src != "" || dst != "" {
			if src != "" {
				spec.SrcIP = src
			}
			if dst != "" {
				spec.DstIP = dst
			}
		}
		// D-REWORK-1（CORE_MEMORY 1.11）：MAC 真相住 eth 层、TTL 真相住
		// ip 层——层内显式值回填 spec，顶层同名键已被 checkLayerFlatConflict
		// 拒绝（混用 400），此回填是层链形状的唯一消费路径。
		if src, dst := extractLayerMACs(layersVal); src != "" || dst != "" {
			if src != "" {
				spec.SrcMAC = src
			}
			if dst != "" {
				spec.DstMAC = dst
			}
		}
		if ttl, present := extractLayerIPTTL(layersVal); present {
			spec.TTL = ttl
		}
	}

	// VLAN
	if vlanID := getUint16(cfg, "vlan_id"); vlanID > 0 {
		spec.VLAN = &VLAN{
			ID:       vlanID,
			Priority: uint8(getInt(cfg, "vlan_priority")),
		}
	}

	// Universal TCP sub-config: applies to any TCP-based protocol
	// (tcp/http/ftp/sip). Must run before the protocol-specific switch so
	// the switch only handles protocol-specific fields (HTTP/FTP/SIP/...).
	// Before this, cfg["tcp"] was only read inside case "tcp", leaving
	// spec.TCP nil for http/ftp/sip -- a regression from the MSS relocation
	// that silently dropped MSS/InitialSeq/Handshake/Termination for those
	// protocols.
	if sub, ok := cfg["tcp"].(map[string]interface{}); ok {
		spec.TCP = &TCPConfig{
			Handshake:   getBool(sub, "handshake", true),
			Termination: getBool(sub, "termination", true),
			RST:         getBool(sub, "rst", false),
			MSS:         getUint16(sub, "mss"),
			WindowSize:  getUint16(sub, "window_size"),
			InitialSeq:  getUint32(sub, "initial_seq"),
			Retransmit:  getBool(sub, "retransmit", false),
		}
	}

	// Universal HTTP sub-config, mirroring the universal TCP read above.
	// Before this, cfg["http"] was only read inside case "http", so a
	// non-HTTP protocol (e.g. tftp, which is UDP-only) silently dropped a
	// coexisting "http" sub-map: spec.HTTP stayed nil and the planner's
	// cross-protocol mutual-exclusion check (tftp.go V20
	// "http field must not be set") was unreachable. Parsing here makes
	// the V20 checks fire for any protocol, matching the universal TCP
	// behavior. Field decoding is ParseHTTPConfigFromMap (single truth
	// with layers.translateTerminalConfig).
	if sub, ok := cfg["http"].(map[string]interface{}); ok {
		spec.HTTP = ParseHTTPConfigFromMap(sub)
	}

	// Universal DNS/FTP/ICMP/SCTP sub-configs, same rationale as the
	// universal TCP/HTTP reads above: before these, cfg["dns"] etc. were
	// only read inside their own protocol case, so a non-matching protocol
	// (e.g. tftp, which is UDP-only) silently dropped coexisting
	// sub-maps: spec.DNS/FTP/ICMP/SCTP stayed nil and the tftp planner's
	// cross-protocol mutual-exclusion checks (V20 "dns/ftp/icmp/sctp field
	// must not be set") were unreachable. Parsing here makes the V20
	// checks fire for any protocol, matching the universal TCP/HTTP
	// behavior. All consumers (dns/ftp/icmp/sctp/ngap planners) nil-guard
	// before use.
	if sub, ok := cfg["dns"].(map[string]interface{}); ok {
		spec.DNS = &DNSConfig{
			Domain:         getString(sub, "domain"),
			QueryType:      uint16(getIntDefault(sub, "query_type", 1)),
			IsResponse:     getBoolWithFallback(sub, "is_response", "response", false),
			ResponseIP:     getString(sub, "response_ip"),
			TxID:           uint16(getInt(sub, "txid")),
			EDNS0Enabled:   getBool(sub, "edns0_enabled", false),
			UDPPayloadSize: uint16(getIntDefault(sub, "udp_payload_size", 4096)),
			DnssecOK:       getBool(sub, "dnssec_ok", false),
			Transport:      getString(sub, "transport"),
			RCode:          uint8(getInt(sub, "rcode")),
			TTL:            getUint32(sub, "ttl"),
			Questions:      parseDNSQuestions(sub["questions"]),
			Answers:        parseDNSRRs(sub["answers"]),
			Authority:      parseDNSRRs(sub["authority"]),
		}
	}
	if sub, ok := cfg["ftp"].(map[string]interface{}); ok {
		spec.FTP = &FTPConfig{
			Banner:      getString(sub, "banner"),
			Commands:    parseFTPCommands(sub["commands"]),
			DataChannel: parseFTPDataChannel(sub["data_channel"]),
			Sessions:    parseFTPSessions(sub["sessions"]),
		}
	}
	if sub, ok := cfg["icmp"].(map[string]interface{}); ok {
		spec.ICMP = &ICMPConfig{
			Type:       uint8(getIntDefault(sub, "type", 8)),
			Code:       uint8(getIntDefault(sub, "code", 0)),
			Identifier: uint16(getInt(sub, "identifier")),
			Sequence:   uint16(getIntDefault(sub, "sequence", 1)),
			Data:       []byte(getStringDefault(sub, "data", "ping")),
			Pattern:    parseICMPPattern(sub["pattern"]),
		}
	}
	if sub, ok := cfg["sctp"].(map[string]interface{}); ok {
		spec.SCTP = &SCTPConfig{
			VerificationTag: getUint32(sub, "verification_tag"),
			InitiateTag:     getUint32(sub, "initiate_tag"),
			Chunks:          parseSCTPChunks(sub["chunks"]),
			Heartbeats:      parseSCTPHeartbeats(sub["heartbeats"]),
			Abort:           getBool(sub, "abort", false),
			FragmentSize:    getInt(sub, "fragment_size"),
		}
	}
	if sub, ok := cfg["jt808"].(map[string]interface{}); ok {
		spec.JT808 = ParseJT808ConfigFromMap(sub)
	}

	// Protocol-specific config
	switch protocol {
	case "stun":
		if sub, ok := cfg["stun"].(map[string]interface{}); ok {
			parseSubconfigJSON[*STUNConfig](&spec, sub, "stun", &spec.STUN)
		}
	case "rtmfp":
		if sub, ok := cfg["rtmfp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*RTMFPConfig](&spec, sub, "rtmfp", &spec.RTMFP)
		}
		// RTMFP (Adobe Real-Time Media Flow Protocol) 默认端口 1935.
		// 仅当用户未指定 dst_port 时覆盖 — 与 DNS/FTP/SIP/RTSP 模式一致.
	case "amqp":
		if sub, ok := cfg["amqp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*AMQPConfig](&spec, sub, "amqp", &spec.AMQP)
		}
		// AMQP (Advanced Message Queuing Protocol) 默认端口 5672.
		// 仅当用户未指定 dst_port 时覆盖 — 与 DNS/FTP/SIP/RTSP 模式一致.
		setDefaultDstPort(&spec, cfg, 5672)
	case "http_flv":
		if sub, ok := cfg["http_flv"].(map[string]interface{}); ok {
			parseSubconfigJSON[*HTTPFLVConfig](&spec, sub, "http_flv", &spec.HTTPFLV)
		}
		// http_flv 依赖 http 层，目的端口 80 默认由 http 层处理，不在此默认化。
	case "hls":
		if sub, ok := cfg["hls"].(map[string]interface{}); ok {
			parseSubconfigJSON[*HLSConfig](&spec, sub, "hls", &spec.HLS)
		}
		// hls 依赖 http 层，目的端口 80 默认由 http 层处理，不在此默认化。
	case "hds":
		if sub, ok := cfg["hds"].(map[string]interface{}); ok {
			parseSubconfigJSON[*HDSConfig](&spec, sub, "hds", &spec.HDS)
		}
		// hds 依赖 http 层，目的端口 80 默认由 http 层处理，不在此默认化。
	case "gbt":
		if sub, ok := cfg["gbt"].(map[string]interface{}); ok {
			parseSubconfigJSON[*GBTConfig](&spec, sub, "gbt", &spec.GBT)
		}
		// gbt 依赖 http 层，目的端口 8332 由 FieldContract（tcp.dst_port）补齐，
		// 不在此默认化。
	case "getwork":
		if sub, ok := cfg["getwork"].(map[string]interface{}); ok {
			parseSubconfigJSON[*GetWorkConfig](&spec, sub, "getwork", &spec.GetWork)
		}
		// getwork 依赖 http 层，目的端口 8332 由 FieldContract（tcp.dst_port）
		// 补齐，不在此默认化。
	case "cwmp":
		if sub, ok := cfg["cwmp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*CWMPConfig](&spec, sub, "cwmp", &spec.CWMP)
		}
		// cwmp 依赖 http 层，目的端口 7547 由 FieldContract（tcp.dst_port）
		// 补齐，不在此默认化。
	case "stratum":
		if sub, ok := cfg["stratum"].(map[string]interface{}); ok {
			parseSubconfigJSON[*StratumConfig](&spec, sub, "stratum", &spec.Stratum)
		}
		// stratum 依赖 tcp 层，目的端口 3333 由 FieldContract（tcp.dst_port）
		// 补齐，不在此默认化。
	case "ethmining":
		if sub, ok := cfg["ethmining"].(map[string]interface{}); ok {
			parseSubconfigJSON[*ETHMiningConfig](&spec, sub, "ethmining", &spec.ETHMining)
		}
		// ethmining 依赖 tcp 层，目的端口 4444 由 FieldContract（tcp.dst_port）
		// 补齐，非默认端口（3353 等）由用户显式覆盖。
	case "nmea":
		if sub, ok := cfg["nmea"].(map[string]interface{}); ok {
			parseSubconfigJSON[*NMEAConfig](&spec, sub, "nmea", &spec.NMEA)
		}
		// nmea 双载体终结层（默认 tcp / 会话级 transport udp），目的端口
		// 10110 由 FieldContract（tcp.dst_port/udp.dst_port）补齐，非默认
		// 端口（4001 等）由用户显式覆盖。
	case "doh":
		if sub, ok := cfg["doh"].(map[string]interface{}); ok {
			parseSubconfigJSON[*DOHConfig](&spec, sub, "doh", &spec.DOH)
		}
		// doh 依赖 http 层（[tcp,http,doh]，tcp→doh 直连在 ValidateLayers
		// 拒绝），目的端口 80 由 FieldContract（tcp.dst_port）补齐，非默认
		// 端口（8080）由用户显式覆盖。
	case "onvif":
		if sub, ok := cfg["onvif"].(map[string]interface{}); ok {
			parseSubconfigJSON[*ONVIFConfig](&spec, sub, "onvif", &spec.ONVIF)
		}
		// onvif 依赖 http 层（[tcp,http,onvif]，tcp→onvif 直连在
		// ValidateLayers 拒绝），目的端口 80 由 FieldContract
		// （tcp.dst_port）补齐，非默认端口由用户显式覆盖。
	case "tcp":
		// TCP sub-config already read above; nothing protocol-specific to add.
	case "udp":
		if sub, ok := cfg["udp"].(map[string]interface{}); ok {
			spec.UDP = &UDPConfig{
				IsResponse:      getBoolWithFallback(sub, "is_response", "response", false),
				DisableChecksum: getBool(sub, "disable_checksum", false),
			}
		}
	case "http":
		// HTTP sub-config already read in the universal section above;
		// nothing protocol-specific to add.
		// HTTP defaults to port 80, same as DefaultDstPort. No override
		// needed here -- mapToFlowSpec's defaultPort call already set it.
	case "dns":
		// DNS sub-config already read in the universal section above.
		// DstPort 默认 53 已收敛至 ChainPlanner.ValidateSpec（chain_planner.go
		// validateSpecBase 的 DstPort switch，mapToFlowSpec 不再重复设默认）。
	case "icmp":
		// ICMP sub-config already read in the universal section above.
		// ICMP does not use ports（D-ICMP-1：icmpv6 同款——L4 恒不发射，
		// 清端口防 stale 值干扰包检查）。
		spec.SrcPort = 0
		spec.DstPort = 0
	case "arp":
		if sub, ok := cfg["arp"].(map[string]interface{}); ok {
			spec.ARP = &ARPConfig{
				Operation: uint16(getIntDefault(sub, "operation", 1)),
				TargetMAC: getString(sub, "target_mac"),
				TargetIP:  getString(sub, "target_ip"),
			}
		}
	case "goose":
		if sub, ok := cfg["goose"].(map[string]interface{}); ok {
			spec.GOOSE = parseGOOSEConfig(sub)
		}
		if spec.GOOSE != nil && spec.GOOSE.Count == 0 {
			// 帧数权威在 config 顶层 `count`（用例惯例：goose/sv 无
			// flow_control，顶层 count 即单流帧数）。goose 子映射未写
			// count 时回填，保证生成器按 spec.GOOSE.Count 发帧。
			if n := getInt(cfg, "count"); n > 0 {
				spec.GOOSE.Count = n
			}
		}
	case "sv":
		if sub, ok := cfg["sv"].(map[string]interface{}); ok {
			spec.SV = parseSVConfig(sub)
		}
		if spec.SV != nil && spec.SV.Count == 0 {
			if n := getInt(cfg, "count"); n > 0 {
				spec.SV.Count = n
			}
		}
	case "igmp":
		if sub, ok := cfg["igmp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*IGMPConfig](&spec, sub, "igmp", &spec.IGMP)
		}
		// igmp 的 profile_matrix/retransmit_state/multi_group_sessions 用例把
		// `events` 放在顶层（而非 igmp 子映射内）：逐一解析为 IGMPEvent 序列
		// 填充 spec.IGMP.Events。无 igmp 子映射时先建一个空的 IGMPConfig。
		if evs, ok := cfg["events"].([]interface{}); ok && len(evs) > 0 {
			if spec.IGMP == nil {
				spec.IGMP = &IGMPConfig{}
			}
			b, _ := json.Marshal(evs)
			var v []IGMPEvent
			if err := json.Unmarshal(b, &v); err != nil {
				spec.ValidationErrors = append(spec.ValidationErrors, "igmp events: "+err.Error())
			} else {
				spec.IGMP.Events = v
			}
		}
	case "ospf":
		if sub, ok := cfg["ospf"].(map[string]interface{}); ok {
			parseSubconfigJSON[*OSPFConfig](&spec, sub, "ospf", &spec.OSPF)
		}
	case "pim":
		if sub, ok := cfg["pim"].(map[string]interface{}); ok {
			parseSubconfigJSON[*PIMConfig](&spec, sub, "pim", &spec.PIM)
		}
	case "isis":
		if sub, ok := cfg["isis"].(map[string]interface{}); ok {
			parseSubconfigJSON[*ISISConfig](&spec, sub, "isis", &spec.ISIS)
		}
	case "ftp":
		// FTP sub-config already read in the universal section above.
		// FTP defaults to port 21 (control channel). Only override when
		// the user did not specify a dst_port — matches the DNS override
		// pattern.
		setDefaultDstPort(&spec, cfg, 21)
	case "edp":
		// EDP (OneNET Enhanced Device Protocol): TCP-only family.
		// Config is carried in the edp layer sub-map; top-level edp key
		// is rejected by CheckProtoFlat.
		if sub, ok := cfg["edp"].(map[string]interface{}); ok {
			spec.EDP = parseEDPConfig(sub)
		}
		// EDP defaults to port 4472. Only override when the user did not
		// specify a dst_port.
		setDefaultDstPort(&spec, cfg, 4472)
	case "xmrmining":
		// XMRMining (Monero stratum): TCP-only family. Config is carried in
		// the xmrmining layer sub-map; top-level xmrmining key is rejected by
		// CheckProtoFlat.
		if sub, ok := cfg["xmrmining"].(map[string]interface{}); ok {
			spec.XMR = parseXMRConfig(sub)
		}
		// XMR defaults to fixture port 18081 (裁定2：daemon RPC 端口假设；
		// 非默认端口显式声明合法). Only override when unset.
		setDefaultDstPort(&spec, cfg, 18081)
	case "bacnet":
		// BACnet/IP (Annex J): UDP-only family. Config is carried in the
		// bacnet layer sub-map; top-level bacnet key is rejected by
		// CheckProtoFlat. Struct-tag 解析（事件级严格解码由 BACNETEvent
		// UnmarshalJSON 提供）.
		if sub, ok := cfg["bacnet"].(map[string]interface{}); ok {
			parseSubconfigJSON[*BACNETConfig](&spec, sub, "bacnet", &spec.BACNET)
		}
		// BACnet defaults to Annex J standard port 47808 (tshark 自动解码
		// 依赖；非默认端口显式声明合法——正例 46). Only override when unset.
		setDefaultDstPort(&spec, cfg, 47808)
	case "dcerpc":
		// DCE/RPC v5 over TCP: config in dcerpc layer sub-map; top-level
		// dcerpc key rejected by CheckProtoFlat.
		if sub, ok := cfg["dcerpc"].(map[string]interface{}); ok {
			parseSubconfigJSON[*DCERPCConfig](&spec, sub, "dcerpc", &spec.DCERPC)
		}
		// EPM 标准端口 135（tshark 自动解码依赖；动态端口显式声明合法）。
		setDefaultDstPort(&spec, cfg, 135)
	case "dtls":
		// DTLS (RFC 6347): UDP-only family. Config in dtls layer sub-map
		// (authoritative); a top-level dtls sub-map alongside layers is
		// tolerated with silent flat-wins (translateTerminalConfig early-
		// returns when spec.DTLS is already set, skipping the layer chain
		// config). Strict decode via DTLSConfig UnmarshalJSON.
		if sub, ok := cfg["dtls"].(map[string]interface{}); ok {
			parseSubconfigJSON[*DTLSConfig](&spec, sub, "dtls", &spec.DTLS)
		}
		// DTLS 标准端口 4433（tshark 自动解码依赖；显式声明合法）。
		setDefaultDstPort(&spec, cfg, 4433)
	case "kerberos":
		// Kerberos V5 (RFC 4120): dual-carrier family (udp datagram / tcp
		// 4B BE record framing). Config in kerberos layer sub-map
		// (authoritative); a top-level kerberos sub-map alongside layers is
		// tolerated with silent flat-wins (translateTerminalConfig early-
		// returns when spec.Kerberos is already set). Strict decode via
		// KerberosConfig UnmarshalJSON.
		if sub, ok := cfg["kerberos"].(map[string]interface{}); ok {
			parseSubconfigJSON[*KerberosConfig](&spec, sub, "kerberos", &spec.Kerberos)
		}
		// KDC 标准端口 88（tshark 自动解码依赖；显式声明合法）。
		setDefaultDstPort(&spec, cfg, 88)
	case "ntlm":
		// NTLM（MS-NLMP）：配置住 ntlm 层子映射（顶层 ntlm 子映射由
		// CheckProtoFlat 判死）；严格解码经 NTLMConfig UnmarshalJSON。
		if sub, ok := cfg["ntlm"].(map[string]interface{}); ok {
			parseSubconfigJSON[*NTLMConfig](&spec, sub, "ntlm", &spec.NTLM)
		}
		// 端口按 profile 缺省：smb2 → 445（Direct TCP）、http-negotiate → 80
		// （tshark 自动解码依赖；显式声明合法）。
		port := uint16(445)
		if spec.NTLM != nil && spec.NTLM.Profile == "http-negotiate" {
			port = 80
		}
		setDefaultDstPort(&spec, cfg, port)
	case "sstp":
		// SSTP (MS-SSTP): terminal layer over the tls carrier ([ip, tcp,
		// tls, sstp]); config lives in the sstp layer sub-map only
		// (authoritative). A top-level sstp sub-map alongside layers is dead
		// config — CheckProtoFlat judges it (presence), so nothing is parsed
		// here: one truth (the layer chain), no second decode path. Strict
		// decode via SSTPConfig UnmarshalJSON in translateTerminalConfig.
		// HTTPS 载体端口 443（tls 层 FieldContract 同值；tshark tls
		// dissector 自动解码依赖）。
		setDefaultDstPort(&spec, cfg, 443)
	case "ocsp":
		// OCSP (RFC 6960/8954): TCP 载体 + 可选 http 层双 profile（D-OCSP-1）。
		// Config in ocsp layer sub-map (authoritative); a top-level ocsp
		// sub-map alongside layers is tolerated with silent flat-wins
		// (translateTerminalConfig early-returns when spec.OCSP is already
		// set). Strict decode via OCSPConfig UnmarshalJSON.
		if sub, ok := cfg["ocsp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*OCSPConfig](&spec, sub, "ocsp", &spec.OCSP)
		}
		// OCSP 明文 HTTP 惯用端口 80（tshark 自动解码依赖；裸 TCP 8080
		// fixture 与显式声明合法——D-OCSP-1 §8.7）。
		setDefaultDstPort(&spec, cfg, 80)
	case "spnego":
		// SPNEGO（RFC 4178）：配置住 spnego 层子映射（顶层 spnego 子映射由
		// CheckProtoFlat 判死）；严格解码经 SPNEGOConfig UnmarshalJSON。
		if sub, ok := cfg["spnego"].(map[string]interface{}); ok {
			parseSubconfigJSON[*SPNEGOConfig](&spec, sub, "spnego", &spec.SPNEGO)
		}
		// 端口按 profile 缺省：tcp → 445（契约 §11.1：445 是 SMB/SPNEGO 惯用
		// 端口，本协议裸 TCP fixture 沿用）、http → 80（tshark http dissector
		// 自动解码依赖）；显式声明合法（门1 §13）。
		portS := uint16(445)
		if spec.SPNEGO != nil && strings.EqualFold(strings.TrimSpace(spec.SPNEGO.Profile), "http") {
			portS = 80
		}
		setDefaultDstPort(&spec, cfg, portS)
	case "sip":
		if sub, ok := cfg["sip"].(map[string]interface{}); ok {
			spec.SIP = &SIPConfig{
				Dialog:     parseSIPDialog(sub["dialog"]),
				Media:      parseSIPMedia(sub["media"]),
				Sessions:   ParseSIPSessions(sub["sessions"]),
				Medias:     ParseSIPMedias(sub["medias"]),
				Interleave: getBool(sub, "interleave", false),
				NAT:        parseSIPNAT(sub["nat"]),
			}
		}
		// SIP defaults to port 5060 (signaling). Only override when the
		// user did not specify a dst_port — matches DNS/FTP pattern.
		setDefaultDstPort(&spec, cfg, 5060)
	case "rtsp":
		if sub, ok := cfg["rtsp"].(map[string]interface{}); ok {
			spec.RTSP = &RTSPConfig{
				Dialog: parseRTSPDialog(sub["dialog"]),
				Media:  parseRTSPMedia(sub["media"]),
			}
		}
		// RTSP defaults to port 554 (control channel). Only override when
		// the user did not specify a dst_port — matches DNS/FTP/SIP pattern.
		setDefaultDstPort(&spec, cfg, 554)
	case "rtmp":
		if sub, ok := cfg["rtmp"].(map[string]interface{}); ok {
			spec.RTMP = parseRTMPConfig(sub)
		}
		// RTMP (Adobe Real-Time Messaging Protocol) 默认端口 1935.
		// 仅当用户未指定 dst_port 时覆盖 — 与 DNS/FTP/SIP/RTSP 模式一致.
		setDefaultDstPort(&spec, cfg, 1935)
	case "sctp":
		// SCTP sub-config already read in the universal section above.
		// SCTP has no universal default port (common ports: 38412 for NGAP,
		// 2905 for M3UA, 9 for discard). Unlike HTTP/FTP/SIP, the user must
		// specify dst_port; otherwise mapToFlowSpec's generic default of
		// DefaultDstPort (80) is left in place — which is almost never what
		// an SCTP test wants. We do not silently override 80 → 38412.
	case "icmpv6":
		if sub, ok := cfg["icmpv6"].(map[string]interface{}); ok {
			spec.ICMPv6 = &ICMPv6Config{
				Type:       uint8(getIntDefault(sub, "type", 128)),
				Code:       uint8(getIntDefault(sub, "code", 0)),
				Identifier: uint16(getInt(sub, "identifier")),
				Sequence:   uint16(getIntDefault(sub, "sequence", 1)),
				Data:       []byte(getStringDefault(sub, "data", "ping")),
				Pattern:    parseICMPv6Pattern(sub["pattern"]),
				FileSource: parseFileSource(sub),
			}
		}
		// ICMPv6 does not use ports (it is a Layer 3 protocol like ICMP).
		// Clear src_port/dst_port to 0 so the L4 header — which is never
		// emitted for ICMP — does not carry stale values that confuse
		// packet inspection. ICMPv6 packets over the wire carry no L4.
		spec.SrcPort = 0
		spec.DstPort = 0
	// --- Phase 3 L7 protocols. Each case is a placeholder the protocol's
	// implementer fills in. The default branch only sets spec.<Proto> to a
	// zero-valued pointer when the cfg sub-map is present, so mapToFlowSpec
	// round-trips (JSON unmarshal test) work before the implementer adds
	// real field parsing. Implementer replaces the body with real parsing.
	case "dhcp":
		if sub, ok := cfg["dhcp"].(map[string]interface{}); ok {
			spec.DHCP = parseDHCPConfig(sub)
		}
		// DstPort 角色解析由 dhcp 终结层生成器 resolvePorts 完成
		// （client→67 / server→68，legacy 同款），mapToFlowSpec 不再预填。
	case "dhcpv6":
		if sub, ok := cfg["dhcpv6"].(map[string]interface{}); ok {
			spec.DHCPv6 = parseDHCPv6Config(sub)
		}
		// DstPort 方向解析由 dhcpv6 终结层生成器 resolveAddrs 完成
		// （up=server 547、down=client 546，legacy 同款），
		// mapToFlowSpec 不再预填。
	case "grpc":
		if sub, ok := cfg["grpc"].(map[string]interface{}); ok {
			spec.GRPC = parseGRPCConfig(sub)
		}
	case "ike":
		if sub, ok := cfg["ike"].(map[string]interface{}); ok {
			spec.IKE = parseIKEConfig(sub)
		}
	case "ike_nat_t":
		if sub, ok := cfg["ike_nat_t"].(map[string]interface{}); ok {
			spec.IKENATT = parseIKENATTConfig(sub)
		}
	case "imap":
		if sub, ok := cfg["imap"].(map[string]interface{}); ok {
			spec.IMAP = ParseIMAPConfigFromMap(sub)
		}
		// IMAP defaults to port 143 per RFC 9051 §2.1. Only override when
		// the user did not specify a dst_port - matches the POP3/SMTP
		// override pattern (D-IMAP-1: pop3 :799 / smtp :883 同款行为对齐).
		setDefaultDstPort(&spec, cfg, 143)
	case "l2tp":
		if sub, ok := cfg["l2tp"].(map[string]interface{}); ok {
			spec.L2TP = parseL2TPConfig(sub)
		}
	case "pppoe":
		if sub, ok := cfg["pppoe"].(map[string]interface{}); ok {
			spec.PPPoE = parsePPPoEConfig(sub)
		}
	case "gre":
		if sub, ok := cfg["gre"].(map[string]interface{}); ok {
			spec.GRE = parseGREConfig(sub)
		}
	case "mpls":
		if sub, ok := cfg["mpls"].(map[string]interface{}); ok {
			spec.MPLS = parseMPLSConfig(sub)
		}
	case "gtp":
		if sub, ok := cfg["gtp"].(map[string]interface{}); ok {
			spec.GTP = parseGTPConfig(sub)
		}
	case "mdns":
		if sub, ok := cfg["mdns"].(map[string]interface{}); ok {
			spec.MDNS = parseMDNSConfig(sub)
		}
		// DstPort 默认 5353 已收敛至 ChainPlanner.ValidateSpec (mdnsPort)。
	case "mysql":
		if sub, ok := cfg["mysql"].(map[string]interface{}); ok {
			spec.MySQL = parseMySQLConfig(sub)
		}
	case "ngap":
		spec.NGAP = parseNGAPConfig(cfg["ngap"])
		// NGAP default port 38412 (5G核心网信令端口). Only override when
		// the user did not specify a dst_port — matches DNS/FTP/SIP pattern.
		setDefaultDstPort(&spec, cfg, 38412)
	case "ntp":
		if sub, ok := cfg["ntp"].(map[string]interface{}); ok {
			spec.NTP = &NTPConfig{
				LeapIndicator:  uint8(getIntDefault(sub, "leap_indicator", 0)),
				Version:        uint8(getIntDefault(sub, "version", 4)),
				Mode:           uint8(getIntDefault(sub, "mode", 3)),
				Stratum:        uint8(getIntDefault(sub, "stratum", 0)),
				Poll:           int8(getIntDefault(sub, "poll", 6)),
				Precision:      int8(getIntDefault(sub, "precision", -6)),
				RootDelay:      getFloatDefault(sub, "root_delay", 0),
				RootDispersion: getFloatDefault(sub, "root_dispersion", 0),
				ReferenceID:    getUint32(sub, "reference_id"),
				RefTimestamp:   getTime(sub, "ref_timestamp"),
				OriginTS:       getTime(sub, "origin_ts"),
				ReceiveTS:      getTime(sub, "receive_ts"),
				TransmitTS:     getTime(sub, "transmit_ts"),
				KeyID:          getUint32(sub, "key_id"),
				MAC:            getByteSlice(sub, "mac"),
				Extensions:     parseNTPExtensions(sub["extensions"]),
				IsResponse:     getBool(sub, "is_response", false),
				PollInterval:   getInt(sub, "poll_interval"),
				RepeatCount:    getInt(sub, "repeat_count"),
				Sequence:       uint16(getIntDefault(sub, "sequence", 0)),
				Implementation: uint8(getIntDefault(sub, "implementation", 0)),
				RequestCode:    uint8(getIntDefault(sub, "request_code", 0)),
				AssociationID:  uint16(getIntDefault(sub, "association_id", 0)),
				Offset:         uint16(getIntDefault(sub, "offset", 0)),
				Error:          getBool(sub, "error", false),
				More:           getBool(sub, "more", false),
				StatusWord:     uint16(getInt(sub, "status_word")),
				ControlData:    getByteSlice(sub, "control_data"),
			}
		}
		// NTP 默认端口 123 (RFC 5905) 已收敛至 ChainPlanner.ValidateSpec。
	case "openvpn":
		if sub, ok := cfg["openvpn"].(map[string]interface{}); ok {
			spec.OpenVPN = parseOpenVPNConfig(sub)
		}
	case "postgresql":
		if sub, ok := cfg["postgresql"].(map[string]interface{}); ok {
			spec.PostgreSQL = parsePostgreSQLConfig(sub)
		}
	case "pop3":
		if sub, ok := cfg["pop3"].(map[string]interface{}); ok {
			spec.POP3 = &POP3Config{
				Banner:   getString(sub, "banner"),
				Commands: parsePOP3Commands(sub["commands"]),
				Mailbox:  parsePOP3Mailbox(sub["mailbox"]),
			}
		}
		// POP3 defaults to port 110 per RFC 1939 §6. Only override when
		// the user did not specify a dst_port - matches the DNS/FTP/SIP
		// override pattern (D-POP3-1: previously comment-only, smtp :882 同款).
		setDefaultDstPort(&spec, cfg, 110)
	case "rdp":
		if sub, ok := cfg["rdp"].(map[string]interface{}); ok {
			spec.RDP = parseRDPConfig(sub)
		}
	case "redis":
		if sub, ok := cfg["redis"].(map[string]interface{}); ok {
			spec.Redis = parseRedisConfig(sub)
		}
	case "radius":
		if sub, ok := cfg["radius"].(map[string]interface{}); ok {
			spec.Radius = parseRadiusConfig(sub)
		}
		// RADIUS 暂无 layer 生成器（仍走 legacy NewPlanner 路径），
		// mapToFlowSpec 保留 1812/1813 默认；accounting code=4 选 1813
		// (RFC 2865 §3 / RFC 2866 §3)。chain planner 同时持有 DstPort=1812/1813
		// 默认（统一架构 v3 落地后由 chain 接管，届时移除此处重复）。
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1812
			if sub, ok := cfg["radius"].(map[string]interface{}); ok {
				if code := getInt(sub, "code"); code == 4 {
					spec.DstPort = 1813
				}
			}
		}
	case "ldap":
		if sub, ok := cfg["ldap"].(map[string]interface{}); ok {
			spec.LDAP = parseLDAPConfig(sub)
		}
		// LDAP defaults to port 389 (RFC 4511). Only override when the
		// user did not specify a dst_port.
		setDefaultDstPort(&spec, cfg, 389)
	case "jt808":
		if sub, ok := cfg["jt808"].(map[string]interface{}); ok {
			spec.JT808 = ParseJT808ConfigFromMap(sub)
		}
		// JT/T 808 defaults to TCP port 7611 (JT/T 808-2019 §4; 部标车载终
		// 端平台惯例端口). legacy PlanWithConfig :166 内部缺省——mapToFlowSpec
		// 先补（universal 80 已在 :334 占位，协议缺省必须在此覆盖，vnc/pptp
		// 同款），链路径 spec 亦经此处（D-JT808-1 P5 实测勘误：缺此 case
		// 时 80 穿透到线上）。
		setDefaultDstPort(&spec, cfg, 7611)
	case "jt809":
		if sub, ok := cfg["jt809"].(map[string]interface{}); ok {
			spec.JT809 = ParseJT809ConfigFromMap(sub)
		}
		// JT/T 809 defaults to main-link TCP port 8812 (JT/T 809-2019 §5).
		// legacy PlanWithConfig 内部缺省——mapToFlowSpec 先补（universal 80
		// 已在 :334 占位，协议缺省必须在此覆盖，jt808 7611 同款——缺此 case
		// 时 80 穿透到线上，D-JT808-1 P5 勘误教训移植）。从链 8813=生成器
		// 合成面，无 spec 字段。
		setDefaultDstPort(&spec, cfg, 8812)
	case "jtt905":
		if sub, ok := cfg["jtt905"].(map[string]interface{}); ok {
			spec.JTT905 = ParseJTT905ConfigFromMap(sub)
		}
		// JT/T 905 defaults to TCP port 10700 (legacy 自选缺省；标准未定
		// 端口)。legacy PlanWithConfig 内部缺省——mapToFlowSpec 先补
		// （jt808 80 穿透教训移植；在库 probe 面 dst_port=80 即此病征）。
		setDefaultDstPort(&spec, cfg, 10700)
	case "vnc":
		if sub, ok := cfg["vnc"].(map[string]interface{}); ok {
			// Parse-level errors (e.g. non-numeric encodings entries) are
			// appended to ValidationErrors so the task fails loudly instead
			// of silently coercing the value to 0.
			var errs []string
			spec.VNC, errs = parseVNCConfig(sub)
			spec.ValidationErrors = append(spec.ValidationErrors, errs...)
		}
		// VNC defaults to port 5900 (RFC 6143 §1.1, range 5900-5909).
		// Only override when the user did not specify a dst_port.
		setDefaultDstPort(&spec, cfg, 5900)
	case "pptp":
		if sub, ok := cfg["pptp"].(map[string]interface{}); ok {
			spec.PPTP = parsePPTPConfig(sub)
		}
		// PPTP defaults to port 1723 (RFC 2637 §1, TCP control plane).
		// Only override when the user did not specify a dst_port.
		setDefaultDstPort(&spec, cfg, 1723)
	case "h323":
		if sub, ok := cfg["h323"].(map[string]interface{}); ok {
			var errs []string
			spec.H323, errs = parseH323Config(sub)
			spec.ValidationErrors = append(spec.ValidationErrors, errs...)
		}
		// H.323 defaults to port 1720 (ITU-T H.225.0 §7.3, Q.931 call
		// signaling). Only override when the user did not specify dst_port.
		setDefaultDstPort(&spec, cfg, 1720)
	case "xmpp":
		if sub, ok := cfg["xmpp"].(map[string]interface{}); ok {
			spec.Xmpp = parseXmppConfig(sub)
		}
		// XMPP defaults to port 5222 (RFC 6120 §13.3, client-to-server).
		// Only override when the user did not specify a dst_port.
		setDefaultDstPort(&spec, cfg, 5222)
	case "shadowsocks":
		if sub, ok := cfg["shadowsocks"].(map[string]interface{}); ok {
			spec.Shadowsocks = parseShadowsocksConfig(sub)
		}
		// shadowsocks has no canonical port; user must specify.
	case "smtp":
		if sub, ok := cfg["smtp"].(map[string]interface{}); ok {
			spec.SMTP = &SMTPConfig{
				Banner: getString(sub, "banner"),
				Email:  parseSMTPEmail(sub["email"]),
				Dialog: parseSMTPDialog(sub["dialog"]),
			}
		}
		// SMTP defaults to port 25 (RFC 5321 §3.1). Only override when
		// the user did not specify a dst_port - matches the DNS/FTP
		// pattern. Submission (587) and SMTPS (465) are also valid but
		// the user must set dst_port explicitly for those.
		setDefaultDstPort(&spec, cfg, 25)
	case "snmp":
		if sub, ok := cfg["snmp"].(map[string]interface{}); ok {
			// Version is presence-checked: 0 is a legitimate value (SNMPv1,
			// RFC 1157), distinct from "absent". Default to v2c (1) only when
			// the key is absent or null. Using getIntDefault would collapse
			// explicit version=0 into the v2c default, silently emitting the
			// wrong protocol version (the bug behind SNMP.3.x failures).
			var snmpVersion uint8 = 1 // default v2c (0=v1, 1=v2c, 3=v3)
			if v, ok := sub["version"]; ok && v != nil {
				snmpVersion = uint8(getInt(sub, "version"))
			}
			spec.SNMP = &SNMPConfig{
				Version:                  snmpVersion,
				Community:                getStringDefault(sub, "community", "public"),
				UserName:                 getString(sub, "user_name"),
				AuthProtocol:             getString(sub, "auth_protocol"),
				AuthPassword:             getString(sub, "auth_password"),
				PrivProtocol:             getString(sub, "priv_protocol"),
				PrivPassword:             getString(sub, "priv_password"),
				AuthoritativeEngineID:    getString(sub, "authoritative_engine_id"),
				AuthoritativeEngineBoots: getUint32(sub, "authoritative_engine_boots"),
				AuthoritativeEngineTime:  getUint32(sub, "authoritative_engine_time"),
				PDUType:                  uint8(getIntDefault(sub, "pdu_type", 0)),
				RequestID:                getUint32(sub, "request_id"),
				NonRepeaters:             uint8(getInt(sub, "non_repeaters")),
				MaxRepetitions:           uint8(getIntDefault(sub, "max_repetitions", 1)),
				VarBinds:                 parseSNMPVarBinds(sub["var_binds"]),
				IsResponse:               getBool(sub, "is_response", false),
				ResponseError:            uint8(getInt(sub, "response_error")),
				ResponseErrorIndex:       uint8(getInt(sub, "response_error_index")),
				ResponseValues:           parseSNMPVarBinds(sub["response_values"]),
				Enterprise:               getString(sub, "enterprise"),
				AgentAddr:                getString(sub, "agent_addr"),
				GenericTrap:              uint8(getInt(sub, "generic_trap")),
				SpecificTrap:             uint8(getInt(sub, "specific_trap")),
				TimeStamp:                getUint32(sub, "time_stamp"),
				PollInterval:             getInt(sub, "poll_interval"),
				RepeatCount:              getInt(sub, "repeat_count"),
				EngineIDOverride:         getString(sub, "engine_id_override"),
				MaxSize:                  getUint32(sub, "max_size"),
				ContextName:              getString(sub, "context_name"),
			}
		}
		// SNMP 默认端口 161/162 (按 PDUType 选) 已收敛至 ChainPlanner.ValidateSpec。
	case "socks5":
		if sub, ok := cfg["socks"].(map[string]interface{}); ok {
			spec.Socks = parseSocks5Config(sub)
		}
		// SOCKS defaults to port 1080 (canonical proxy port). Only override
		// when the user did not specify a dst_port - matches DNS/FTP/SIP
		// pattern.
	case "vxlan":
		// B4 封装类：VXLAN（RFC 7348）配置 json 往返解析（stun 同款——
		// 结构体字段即契约，未知字段拒绝进 ValidationErrors）。目的端口
		// 4789（IANA 指派；FieldContract 同值兜底，用户显式写优先）。
		if sub, ok := cfg["vxlan"].(map[string]interface{}); ok {
			parseSubconfigJSON[*VXLANConfig](&spec, sub, "vxlan", &spec.VXLAN)
		}
	case "geneve":
		// B4 封装类：GENEVE（RFC 8926）配置 json 往返解析。目的端口 6081
		// （IANA 指派；FieldContract 同值兜底）。
		if sub, ok := cfg["geneve"].(map[string]interface{}); ok {
			parseSubconfigJSON[*GeneveConfig](&spec, sub, "geneve", &spec.Geneve)
		}
	case "nvgre":
		// B4 封装类：NVGRE（RFC 7637）配置 json 往返解析。无传输层（IP
		// proto 47），无端口默认。
		if sub, ok := cfg["nvgre"].(map[string]interface{}); ok {
			parseSubconfigJSON[*NVGREConfig](&spec, sub, "nvgre", &spec.NVGRE)
		}
	case "openwire":
		// B5：OpenWire（ActiveMQ）TCP 终结层配置 json 往返解析。目的端口
		// 61616（ActiveMQ 默认；FieldContract 同值兜底，用户显式写优先）。
		if sub, ok := cfg["openwire"].(map[string]interface{}); ok {
			parseSubconfigJSON[*OpenWireConfig](&spec, sub, "openwire", &spec.OpenWire)
		}
	case "ams":
		// B5：AMS（ActiveMQ Management）TCP 终结层配置 json 往返解析。目的
		// 端口 61616（FieldContract 同值兜底，用户显式写优先）。
		if sub, ok := cfg["ams"].(map[string]interface{}); ok {
			parseSubconfigJSON[*AMSConfig](&spec, sub, "ams", &spec.AMS)
		}
	case "swarm":
		// B5：Swarm discovery/storage 双承载配置 json 往返解析。目的端口
		// 1634（FieldContract 同值兜底，用户显式写优先）。
		if sub, ok := cfg["swarm"].(map[string]interface{}); ok {
			parseSubconfigJSON[*SwarmConfig](&spec, sub, "swarm", &spec.Swarm)
		}
	case "gnutella":
		// B5：Gnutella TCP 终结层配置 json 往返解析。目的端口 6346。
		if sub, ok := cfg["gnutella"].(map[string]interface{}); ok {
			parseSubconfigJSON[*GnutellaConfig](&spec, sub, "gnutella", &spec.Gnutella)
		}
	case "ssdp":
		if sub, ok := cfg["ssdp"].(map[string]interface{}); ok {
			spec.SSDP = parseSSDPConfig(sub)
		}
		// SSDP 默认端口 1900 (UPnP/SSDP) 已收敛至 ChainPlanner.ValidateSpec。
	case "ssh":
		if sub, ok := cfg["ssh"].(map[string]interface{}); ok {
			spec.SSH = parseSSHConfig(sub)
		}
	case "syslog":
		if sub, ok := cfg["syslog"].(map[string]interface{}); ok {
			spec.Syslog = &SyslogConfig{
				Facility:       uint8(getIntDefault(sub, "facility", 1)),
				Severity:       uint8(getIntDefault(sub, "severity", 6)),
				Version:        uint8(getIntDefault(sub, "version", 1)),
				Timestamp:      getString(sub, "timestamp"),
				Hostname:       getString(sub, "hostname"),
				AppName:        getString(sub, "app_name"),
				ProcID:         getString(sub, "proc_id"),
				MsgID:          getString(sub, "msg_id"),
				StructuredData: parseSyslogStructuredData(sub["structured_data"]),
				Msg:            getString(sub, "msg"),
				MsgHasBOM:      getBool(sub, "msg_has_bom", false),
				Format:         getStringDefault(sub, "format", "rfc5424"),
				Transport:      getStringDefault(sub, "transport", "udp"),
				TCPFraming:     getStringDefault(sub, "tcp_framing", "octet_counting"),
				Count:          uint32(getIntDefault(sub, "count", 1)),
				SignBlocks:     parseSyslogSignBlocks(sub["sign_blocks"]),
				Messages:       parseSyslogMessages(sub["messages"]),
			}
		}
		// Syslog 默认端口 (udp/tcp=514, tls=6514) 已收敛至 ChainPlanner.ValidateSpec。
	case "telnet":
		if sub, ok := cfg["telnet"].(map[string]interface{}); ok {
			spec.Telnet = &TelnetConfig{
				Banner:       getString(sub, "banner"),
				Dialog:       parseTelnetDialog(sub["dialog"]),
				TerminalType: getString(sub, "terminal_type"),
				WindowCols:   getUint16(sub, "window_cols"),
				WindowRows:   getUint16(sub, "window_rows"),
				FileSource:   parseFileSource(sub),
				Scenario:     getString(sub, "scenario"),
				Username:     getString(sub, "username"),
				Password:     getString(sub, "password"),
				Commands:     getStringSlice(sub, "commands"),
			}
		}
		// Telnet defaults to port 23 (RFC 854). Only override when the
		// user did not specify a dst_port — matches the DNS/FTP override
		// pattern.
		setDefaultDstPort(&spec, cfg, 23)
	case "tls":
		if sub, ok := cfg["tls"].(map[string]interface{}); ok {
			spec.TLS = parseTLSConfig(sub)
		}
		setDefaultDstPort(&spec, cfg, 443)
	case "vmess":
		if sub, ok := cfg["vmess"].(map[string]interface{}); ok {
			spec.Vmess = parseVmessConfig(sub)
		}
		// vmess has no canonical port; user must specify.
	case "wireguard":
		if sub, ok := cfg["wireguard"].(map[string]interface{}); ok {
			spec.WireGuard = parseWireGuardConfig(sub)
		}
	case "srv6":
		if sub, ok := cfg["srv6"].(map[string]interface{}); ok {
			spec.SRv6 = parseSRv6Config(sub)
		}
	case "gbt32960":
		if sub, ok := cfg["gbt32960"].(map[string]interface{}); ok {
			spec.GBT32960 = parseGBT32960Config(sub)
		}
		// GBT32960 defaults to port 10020 (GB/T 32960.3-2016 platform
		// listener). Only override when the user did not specify a dst_port.
	case "tftp":
		if sub, ok := cfg["tftp"].(map[string]interface{}); ok {
			spec.TFTP = parseTFTPConfig(sub)
		}
		// TFTP 默认端口 69 (RFC 1350) 已收敛至 ChainPlanner.ValidateSpec。
	case "mqtt":
		if sub, ok := cfg["mqtt"].(map[string]interface{}); ok {
			spec.MQTT = parseMQTTConfig(sub)
		}
	case "modbus":
		if sub, ok := cfg["modbus"].(map[string]interface{}); ok {
			spec.MODBUS = parseMODBUSConfig(sub)
		}
		// Modbus 默认端口 502 (RFC 793) 已收敛至 ChainPlanner.ValidateSpec。
	case "rip":
		if sub, ok := cfg["rip"].(map[string]interface{}); ok {
			spec.RIP = parseRIPConfig(sub)
		}
		setDefaultDstPort(&spec, cfg, 520)
	case "dnp3":
		if sub, ok := cfg["dnp3"].(map[string]interface{}); ok {
			spec.DNP3 = parseDNP3Config(sub)
		}
		setDefaultDstPort(&spec, cfg, 20000)
	case "enip":
		if sub, ok := cfg["enip"].(map[string]interface{}); ok {
			spec.ENIP = parseENIPConfig(sub)
		}
		setDefaultDstPort(&spec, cfg, 44818)
	case "doip":
		if sub, ok := cfg["doip"].(map[string]interface{}); ok {
			spec.DoIP = parseDoIPConfig(sub)
		}
		setDefaultDstPort(&spec, cfg, 13400)
	case "smb":
		if sub, ok := cfg["smb"].(map[string]interface{}); ok {
			spec.SMB = parseSMBConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			// NBSS Session Service (transport=netbios) listens on TCP 139;
			// direct SMB (the default) uses TCP 445.
			if spec.SMB != nil && spec.SMB.Transport == "netbios" {
				spec.DstPort = 139
			} else {
				spec.DstPort = 445
			}
		}
	case "mcp":
		if sub, ok := cfg["mcp"].(map[string]interface{}); ok {
			spec.MCP = parseMCPConfig(sub)
		}
	case "tds":
		// D-TDS-1：存量兼容路径（在库旧策略仍带顶层 tds → 上方
		// `if protocol == "tds"` 块已记 ValidationErrors，此处只填
		// Payload 供 planner 消费；mqtt 同款分工）。层链形状（纯
		// layers）走 translateTerminalConfig 的 tds case 搬层条目进
		// spec.Payload。planner 从 spec.Payload unmarshal（protocol/tds
		// configFromSpec）。
		if sub, ok := cfg["tds"].(map[string]interface{}); ok && sub != nil {
			if raw, err := json.Marshal(sub); err == nil {
				spec.Payload = raw
			}
		}
	case "a2a":
		// A2A carries its config as A2AConfig JSON in spec.Payload; the
		// planner unmarshals it (protocol/a2a configFromSpec).
		if sub, ok := cfg["a2a"].(map[string]interface{}); ok {
			if raw, err := json.Marshal(sub); err == nil {
				spec.Payload = raw
			}
		}
	case "mms":
		if sub, ok := cfg["mms"].(map[string]interface{}); ok {
			parseSubconfigJSON[*MMSConfig](&spec, sub, "mms", &spec.MMS)
		}
	case "opcua":
		if sub, ok := cfg["opcua"].(map[string]interface{}); ok {
			parseSubconfigJSON[*OPCUAConfig](&spec, sub, "opcua", &spec.OPCUA)
		}
	case "s7":
		if sub, ok := cfg["s7"].(map[string]interface{}); ok {
			parseSubconfigJSON[*S7Config](&spec, sub, "s7", &spec.S7)
		}
	case "iec104":
		if sub, ok := cfg["iec104"].(map[string]interface{}); ok {
			parseSubconfigJSON[*IEC104Config](&spec, sub, "iec104", &spec.IEC104)
		}
	case "bgp":
		if sub, ok := cfg["bgp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*BGPConfig](&spec, sub, "bgp", &spec.BGP)
		}
	case "coap":
		if sub, ok := cfg["coap"].(map[string]interface{}); ok {
			if raw, err := json.Marshal(sub); err == nil {
				var coap CoAPConfig
				if json.Unmarshal(raw, &coap) == nil {
					spec.CoAP = &coap
				}
			}
		}
	case "fins":
		if sub, ok := cfg["fins"].(map[string]interface{}); ok {
			if spec.Metadata == nil {
				spec.Metadata = make(map[string]interface{})
			}
			spec.Metadata["fins"] = sub
		}
		setDefaultDstPort(&spec, cfg, 9600)
	case "nfs":
		// D-NFS-1：配置住 nfs 层子映射（顶层 nfs 子映射由 CheckProtoFlat
		// 判死）；此处仅守 out-of-band 配置（引擎直调/存量行带类型配置），
		// fins 同款——层链形状下顶层 nfs 不可达。目的端口默认 2049
		// （legacy Plan 同款）。
		setDefaultDstPort(&spec, cfg, 2049)
	case "moxa":
		if sub, ok := cfg["moxa"].(map[string]interface{}); ok {
			parseSubconfigJSON[*MOXAConfig](&spec, sub, "moxa", &spec.MOXA)
		}
	case "someip":
		if sub, ok := cfg["someip"].(map[string]interface{}); ok {
			parseSubconfigJSON[*SOMEIPConfig](&spec, sub, "someip", &spec.SOMEIP)
		}
	case "tns":
		if sub, ok := cfg["tns"].(map[string]interface{}); ok {
			parseSubconfigJSON[*TNSConfig](&spec, sub, "tns", &spec.TNS)
		}
	case "mongodb":
		if sub, ok := cfg["mongodb"].(map[string]interface{}); ok {
			parseSubconfigJSON[*MongoDBConfig](&spec, sub, "mongodb", &spec.MongoDB)
		}
	case "dameng":
		if sub, ok := cfg["dameng"].(map[string]interface{}); ok {
			parseSubconfigJSON[*DamengConfig](&spec, sub, "dameng", &spec.Dameng)
		}
		// case "kingbase" 已收敛：kingbase 不再独立解析，改由 postgresql 层 +
		// dialect=kingbase 表达（18-layer-config-design.md §2.2/§4.3/§7 F4）。
		// 配置走 case "postgresql"（spec.PostgreSQL，dialect=kingbase）。
	case "cql":
		if sub, ok := cfg["cql"].(map[string]interface{}); ok {
			parseSubconfigJSON[*CQLConfig](&spec, sub, "cql", &spec.CQL)
		}
	case "ldp":
		if sub, ok := cfg["ldp"].(map[string]interface{}); ok {
			parseSubconfigJSON[*LDPConfig](&spec, sub, "ldp", &spec.LDP)
		}
	case "pcep":
		if sub, ok := cfg["pcep"].(map[string]interface{}); ok {
			parseSubconfigJSON[*PCEPConfig](&spec, sub, "pcep", &spec.PCEP)
		}
	case "drda":
		if sub, ok := cfg["drda"].(map[string]interface{}); ok {
			parseSubconfigJSON[*DRDAConfig](&spec, sub, "drda", &spec.DRDA)
		}
	case "thrift":
		if sub, ok := cfg["thrift"].(map[string]interface{}); ok {
			parseSubconfigJSON[*ThriftConfig](&spec, sub, "thrift", &spec.Thrift)
		}
	case "cflow":
		if sub, ok := cfg["cflow"].(map[string]interface{}); ok {
			parseSubconfigJSON[*CFlowConfig](&spec, sub, "cflow", &spec.CFlow)
		}
	}

	// GroupID: optional strategy for cross-flow ordering. When cfg has
	// "group_id" as a map, unmarshal into StrategyConfig; absent = nil
	// (fall back to 4-tuple hash).
	if gCfg, ok := cfg["group_id"].(map[string]interface{}); ok && gCfg != nil {
		if raw, err := json.Marshal(gCfg); err == nil {
			var g StrategyConfig
			if err := json.Unmarshal(raw, &g); err == nil {
				spec.GroupID = &g
			}
		}
	}

	// LayerDyn: per-flow dynamic strategies from the layers array (D-FTP-3).
	// Malformed dynamic objects are recorded in spec.ValidationErrors (worker
	// precheck fails the task); shape-level malformation is already rejected
	// at create/update by ValidateLayers.
	// HasLayerDynIP (D-FTP-4): ip.src/ip.dst 任一端是动态对象即 true——
	// validateSpecBase 据此跳过解析前 spec 的静态同族门（逐流解析值同族性由
	// 形状层保证，此处 flat 默认不得参与族检查）。
	if layersVal, ok := cfg["layers"]; ok && layersVal != nil {
		if ld, errs := parseLayerDyn(layersVal); ld != nil || len(errs) > 0 {
			spec.LayerDyn = ld
			spec.ValidationErrors = append(spec.ValidationErrors, errs...)
		}
		if ld := spec.LayerDyn; ld != nil && (ld.IP.Src != nil || ld.IP.Dst != nil) {
			spec.HasLayerDynIP = true
		}
	}

	// InitialSeq backward compat: pre-rename strategies stored this at the
	// top-level cfg. After the rename it lives inside the "tcp" sub-map. We
	// prefer spec.TCP.InitialSeq (set above from the tcp sub-map) and fall
	// back to the top-level "initial_seq" key when TCP is nil or its
	// InitialSeq is 0. This preserves reproducible-ISN configs that still
	// use the legacy top-level location.
	//
	// When creating a new TCPConfig here (no "tcp" sub-map was present),
	// Handshake/Termination default to true so HTTP/FTP/SIP flows still
	// get a proper handshake/teardown -- without this, the zero-value false
	// would skip the SYN handshake and FIN teardown, breaking the flow.
	if v, ok := cfg["initial_seq"]; ok && v != nil {
		legacy := getUint32(cfg, "initial_seq")
		if spec.TCP == nil {
			spec.TCP = &TCPConfig{
				Handshake:   true,
				Termination: true,
				InitialSeq:  legacy,
			}
		} else if spec.TCP.InitialSeq == 0 {
			spec.TCP.InitialSeq = legacy
		}
	}

	// PadMinFrame: optional Ethernet padding toggle. nil (absent) = default
	// ON; explicit true = ON; explicit false = OFF. Presence-checked so
	// user false (don't pad) is honored rather than replaced with the
	// default true.
	if v, ok := cfg["pad_min_frame"]; ok && v != nil {
		if b, ok := v.(bool); ok {
			spec.PadMinFrame = &b
		}
	}

	// SubFlows: generic multi-flow binding (FTP data channel, SIP RTP,
	// SCTP multi-homing). Parsed protocol-independently so any planner
	// can emit sub-flows without its own map[]-decoder. Absent = no
	// sub-flows (the default for every protocol unless the user sets it
	// or the planner injects one internally, e.g. FTP's DataChannel).
	//
	// Two-stage decode: first unmarshal into a typed slice (decodes
	// numeric/most fields), and if that fails fall back to nil. We
	// tolerate individual field decode errors (e.g. Payload field
	// receiving a non-base64 string into []byte) by using a json.RawMessage
	// intermediate and then re-decoding field by field, so one bad field
	// doesn't drop the whole sub-flow.
	if sCfg, ok := cfg["sub_flows"]; ok && sCfg != nil {
		if raw, err := json.Marshal(sCfg); err == nil {
			var subs []SubFlowSpec
			if err := json.Unmarshal(raw, &subs); err == nil {
				spec.SubFlows = subs
			} else {
				// Fallback: decode each entry individually. A sub-flow with
				// an un-decodable field (e.g. Payload that isn't valid base64)
				// still gets its other fields populated; bad fields are left
				// at their zero value.
				var raws []json.RawMessage
				if err := json.Unmarshal(raw, &raws); err == nil {
					for _, r := range raws {
						var sub SubFlowSpec
						_ = json.Unmarshal(r, &sub)
						spec.SubFlows = append(spec.SubFlows, sub)
					}
				}
			}
		}
	}

	// FileSource (protocol-agnostic): parsed unconditionally so any
	// protocol can carry a file_source. Planners that don't consume it
	// simply ignore the field. Per-protocol FileSource fields (set below)
	// take precedence over this top-level one.
	spec.FileSource = parseFileSource(cfg)

	// Per-protocol FileSource overrides. Each lives inside its protocol's
	// sub-map under the "file_source" key. We only set the field when the
	// sub-map is present (parseFileSource returns nil for absent/empty
	// sources, so existing configs that don't use file_source stay
	// zero-value and don't serialize).
	if spec.FTP != nil && spec.FTP.DataChannel != nil {
		if dcFS := parseFileSource(getMap(cfg, "ftp", "data_channel")); dcFS != nil {
			spec.FTP.DataChannel.FileSource = dcFS
		}
	}
	if spec.SIP != nil && spec.SIP.Media != nil {
		if mFS := parseFileSource(getMap(cfg, "sip", "media")); mFS != nil {
			spec.SIP.Media.FileSource = mFS
		}
	}
	if spec.RTSP != nil && spec.RTSP.Media != nil {
		if mFS := parseFileSource(getMap(cfg, "rtsp", "media")); mFS != nil {
			spec.RTSP.Media.FileSource = mFS
		}
	}
	if spec.HTTP != nil {
		// file_source already parsed inside ParseHTTPConfigFromMap (layer-map
		// inner key); the top-level override below is a no-op safety net for
		// rows parsed before the single-truth refactor.
		if hFS := parseFileSource(getMap(cfg, "http")); hFS != nil {
			spec.HTTP.FileSource = hFS
		}
	}
	if spec.ICMP != nil {
		if iFS := parseFileSource(getMap(cfg, "icmp")); iFS != nil {
			spec.ICMP.FileSource = iFS
		}
	}
	if spec.ICMPv6 != nil {
		if i6FS := parseFileSource(getMap(cfg, "icmpv6")); i6FS != nil {
			spec.ICMPv6.FileSource = i6FS
		}
	}
	// SCTP chunks: FileSource parsing is handled inside parseSCTPChunks
	// itself (each chunk is constructed there with its FileSource assigned
	// from the chunk map's "file_source" key). The earlier dispatch loop
	// here walked cfg["sctp"]["chunks"][i] and indexed into
	// spec.SCTP.Chunks[i] — but parseSCTPChunks filters non-map entries,
	// so len(parsed) < len(raw) whenever any entry was a non-map. The
	// length-safety check failed and silently dropped ALL chunk
	// FileSources, including valid ones at aligned indices. Pushing the
	// parse into parseSCTPChunks eliminates the index-aliasing bug.

	// Validate all FileSource instances surfaced above. parseFileSource
	// returns nil for absent/empty sources, so nil-check first. A Validate
	// failure is a user-facing input error and fails the task loudly —
	// silent acceptance of, e.g., Fill.Bytes=-1 would panic make([]byte, n)
	// deep in the planner and produce a confusing stack trace.
	if err := spec.FileSource.Validate(); err != nil {
		spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
	}
	if spec.FTP != nil && spec.FTP.DataChannel != nil {
		if err := spec.FTP.DataChannel.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.SIP != nil && spec.SIP.Media != nil {
		if err := spec.SIP.Media.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.HTTP != nil {
		if err := spec.HTTP.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.ICMP != nil {
		if err := spec.ICMP.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.ICMPv6 != nil {
		if err := spec.ICMPv6.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.SCTP != nil {
		for i := range spec.SCTP.Chunks {
			if err := spec.SCTP.Chunks[i].FileSource.Validate(); err != nil {
				spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
			}
		}
	}
	if spec.Socks != nil {
		for i := range spec.Socks.Data {
			if err := spec.Socks.Data[i].FileSource.Validate(); err != nil {
				spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
			}
		}
	}

	return spec
}

// MapToFlowSpec is the exported wrapper around mapToFlowSpec. It exists so
// external test packages (core_test) can exercise the parser without
// duplicating the dispatch logic. Production code continues to call
// mapToFlowSpec directly.
func MapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	return mapToFlowSpec(cfg, protocol)
}

// parseFileSource extracts a *FileSource from cfg["file_source"] (a map).
// Returns nil when absent, not a map, or all fields zero — so a config
// without a file_source serializes as nil (no null in JSON output thanks
// to omitempty on the field tags).
//
// The four source kinds (File, Literal, Fill, Random) are parsed
// independently; at most one is expected to be set, but we don't enforce
// that here (priority resolution happens at consume time in PayloadCache).
//
// Numeric coercion: JSON decode produces float64 for numbers (and
// json.Number when UseNumber is set); test map literals produce int. We
// delegate to the package-level toInt (defined in shard_router.go) which
// handles float64/int/int64/string so the parser works identically in
// production and in tests.
func parseFileSource(cfg map[string]interface{}) *filesystem.FileSource {
	src, ok := cfg["file_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	fs := &filesystem.FileSource{}
	if v, ok := src["file"].(string); ok {
		fs.File = v
	}
	if v, ok := src["literal"].(string); ok {
		fs.Literal = v
	}
	if fill, ok := src["fill"].(map[string]interface{}); ok {
		fs.Fill = &filesystem.Fill{
			Byte:  byte(toInt(fill["byte"])),
			Bytes: toInt(fill["bytes"]),
		}
	}
	if r, ok := src["random"].(map[string]interface{}); ok {
		fs.Random = &filesystem.Random{
			MinBytes: toInt(r["min_bytes"]),
			MaxBytes: toInt(r["max_bytes"]),
			Seed:     int64(toInt(r["seed"])),
		}
	}
	// If all fields are zero, treat as nil. This prevents a non-nil pointer
	// to a zero-value FileSource from being serialized as "file_source": {}
	// and from confusing planners that test `if spec.FileSource != nil`.
	if fs.File == "" && fs.Literal == "" && fs.Fill == nil && fs.Random == nil {
		return nil
	}
	return fs
}

// parseFileSourceField reads a "file_source" sub-map from the given map and
// delegates to parseFileSource for the actual field parsing. Used when the
// caller already has the protocol-specific sub-map (e.g. inside an IMAP
// command entry) rather than the top-level cfg.
func parseFileSourceField(m map[string]interface{}) *filesystem.FileSource {
	src, ok := m["file_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	fs := &filesystem.FileSource{}
	if v, ok := src["file"].(string); ok {
		fs.File = v
	}
	if v, ok := src["literal"].(string); ok {
		fs.Literal = v
	}
	if fill, ok := src["fill"].(map[string]interface{}); ok {
		fs.Fill = &filesystem.Fill{
			Byte:  byte(toInt(fill["byte"])),
			Bytes: toInt(fill["bytes"]),
		}
	}
	if r, ok := src["random"].(map[string]interface{}); ok {
		fs.Random = &filesystem.Random{
			MinBytes: toInt(r["min_bytes"]),
			MaxBytes: toInt(r["max_bytes"]),
			Seed:     int64(toInt(r["seed"])),
		}
	}
	if fs.File == "" && fs.Literal == "" && fs.Fill == nil && fs.Random == nil {
		return nil
	}
	return fs
}

// getMap walks cfg through a chain of keys, returning the nested map at the
// end of the chain or nil if any intermediate is missing or not a map. It
// never panics on missing keys or nil maps.
func getMap(cfg map[string]interface{}, keys ...string) map[string]interface{} {
	var cur map[string]interface{} = cfg
	for _, k := range keys {
		if cur == nil {
			return nil
		}
		next, ok := cur[k].(map[string]interface{})
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func formatBPS(val float64) string {
	switch {
	case val >= 1e9:
		return fmt.Sprintf("%.0fG", val/1e9)
	case val >= 1e6:
		return fmt.Sprintf("%.0fM", val/1e6)
	case val >= 1e3:
		return fmt.Sprintf("%.0fk", val/1e3)
	default:
		return fmt.Sprintf("%.0f", val)
	}
}

// parseHopByHopOptions converts the JSON-decoded "hop_by_hop" value (an
// array of {type, value} option objects, RFC 8200 §4.2) into a
// []IPv6Option. Returns nil for absent/non-array input so the builder emits
// a plain IPv6 header. "value" is the raw option data (the string's bytes).
// ParseHopByHopOptions is the exported single-truth parser for the IPv6
// hop-by-hop option list（D-SRV6-1：ip 层 hop_by_hop → spec.HopByHop 回填
// 由 layers 包经此复用，扁平路径 parseHopByHopOptions 同一实现）。
func ParseHopByHopOptions(v interface{}) []IPv6Option {
	return parseHopByHopOptions(v)
}

func parseHopByHopOptions(v interface{}) []IPv6Option {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IPv6Option, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IPv6Option{
			Type:  uint8(getInt(m, "type")),
			Value: []byte(getString(m, "value")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseICMPPattern converts the JSON-decoded "pattern" value (an array of
// step objects) into a []ICMPStep. Returns nil for absent/non-array input
// so the planner falls back to the single-ping path. Each step inherits
// Type/Code defaults from the parent config when absent (Type=8, Code=0);
// Sequence defaults to step index+1 when 0 (per RFC 792 ping session
// semantics: Identifier groups, Sequence increments per ping).
func parseICMPPattern(v interface{}) []ICMPStep {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ICMPStep, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := uint8(getIntDefault(m, "type", 8))
		code := uint8(getIntDefault(m, "code", 0))
		seq := uint16(getInt(m, "sequence"))
		if seq == 0 {
			seq = uint16(len(out) + 1)
		}
		data := []byte(getStringDefault(m, "data", "ping"))
		out = append(out, ICMPStep{
			Type:     typ,
			Code:     code,
			Sequence: seq,
			Data:     data,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseStrategyConfigDyn (D-FTP-2 v2 同键二态，用户裁定)：同一键的值形态
// 决定静态/动态——标量走既有静态路径，对象走动态解析。`*_dyn` 平行键已撤销
// （v1 形状，用户否决），解析层只认同键对象。本函数只做"对象→配置"映射，
// 调用方负责把同键原始值传进来。
func parseStrategyConfigDyn(v interface{}) *StrategyConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var s StrategyConfig
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

// parseFTPCommands converts the JSON-decoded "commands" value (an array
// of {cmd, response} objects) into a []FTPCommand. Returns nil for
// absent/non-array input — the planner then emits only TCP handshake +
// teardown (an empty FTP session, which is a valid degenerate test).
func parseFTPCommands(v interface{}) []FTPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]FTPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, FTPCommand{
			Cmd:             getString(m, "cmd"),
			Response:        getString(m, "response"),
			EmitDataChannel: getBool(m, "emit_data_channel", false),
			CmdDyn:          parseStrategyConfigDyn(m["cmd"]),
			ResponseDyn:     parseStrategyConfigDyn(m["response"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePOP3Commands converts the JSON-decoded "commands" value (an array
// of {cmd, response, multiline, emit_mail_drop, msg_num} objects) into a
// []POP3Command. Returns nil for absent/non-array input - the planner then
// emits only TCP handshake + teardown (an empty POP3 session, which is a
// valid degenerate test). Mirrors parseFTPCommands.
func parsePOP3Commands(v interface{}) []POP3Command {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]POP3Command, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, POP3Command{
			Cmd:          getString(m, "cmd"),
			Response:     getString(m, "response"),
			Multiline:    getBool(m, "multiline", false),
			EmitMailDrop: getBool(m, "emit_mail_drop", false),
			EmitTop:      getBool(m, "emit_top", false),
			TopLines:     getUint32(m, "top_lines"),
			MsgNum:       getUint32(m, "msg_num"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePOP3Mailbox converts the JSON-decoded "mailbox" sub-map into a
// *POP3Mailbox. Returns nil for absent/non-map input - the planner then
// cannot synthesize RETR responses (EmitMailDrop=true commands will fail
// Validate). Mirrors parseFTPDataChannel.
func parsePOP3Mailbox(v interface{}) *POP3Mailbox {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	mb := &POP3Mailbox{}
	if msgs, ok := m["messages"].([]interface{}); ok {
		for _, item := range msgs {
			mi, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			msg := POP3Message{
				UID:      getString(mi, "uid"),
				Body:     getString(mi, "body"),
				Boundary: getString(mi, "boundary"),
				Size:     getUint32(mi, "size"),
			}
			if headers, ok := mi["headers"].([]interface{}); ok {
				for _, h := range headers {
					if s, ok := h.(string); ok {
						msg.Headers = append(msg.Headers, s)
					}
				}
			}
			if parts, ok := mi["mime_parts"].([]interface{}); ok {
				for _, p := range parts {
					pi, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					part := POP3MIMEPart{
						Body:    getString(pi, "body"),
						BodyB64: getString(pi, "body_b64"),
					}
					if ph, ok := pi["headers"].([]interface{}); ok {
						for _, h := range ph {
							if s, ok := h.(string); ok {
								part.Headers = append(part.Headers, s)
							}
						}
					}
					msg.MIMEParts = append(msg.MIMEParts, part)
				}
			}
			mb.Messages = append(mb.Messages, msg)
		}
	}
	if len(mb.Messages) == 0 {
		return nil
	}
	return mb
}

// parseSMTPDialog converts the JSON-decoded "dialog" value (an array of
// {cmd, response, direction} objects) into a []SMTPCommand. Returns nil
// for absent/non-array input - the planner then emits a default SMTP
// session per design_smtp.md §6.6. Mirrors parsePOP3Commands.
func parseSMTPDialog(v interface{}) []SMTPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SMTPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, SMTPCommand{
			Cmd:       getString(m, "cmd"),
			Response:  getString(m, "response"),
			Direction: getString(m, "direction"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSMTPEmail converts the JSON-decoded "email" sub-map into an
// *SMTPEmail. Returns nil for absent/non-map input - the planner then
// plays back the Dialog verbatim (backward-compatible path).
//
// Attachments is parsed from the "attachments" array; each attachment
// has filename, content_type, data (byte slice/string), and
// data_b64 (pre-encoded base64). Mirrors parsePOP3Mailbox's MIME part
// parsing for consistency.
func parseSMTPEmail(v interface{}) *SMTPEmail {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	email := &SMTPEmail{
		TextBody: getString(m, "text_body"),
		HTMLBody: getString(m, "html_body"),
		Boundary: getString(m, "boundary"),
	}
	if headers, ok := m["headers"].([]interface{}); ok {
		for _, h := range headers {
			if s, ok := h.(string); ok {
				email.Headers = append(email.Headers, s)
			}
		}
	}
	if atts, ok := m["attachments"].([]interface{}); ok {
		for _, a := range atts {
			am, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			att := SMTPAttachment{
				Filename:    getString(am, "filename"),
				ContentType: getString(am, "content_type"),
				Data:        getByteSlice(am, "data"),
				DataB64:     getString(am, "data_b64"),
			}
			email.Attachments = append(email.Attachments, att)
		}
	}
	return email
}

// parseFTPDataChannel converts the JSON-decoded "data_channel" sub-map
// into an *FTPDataChannel. Returns nil for absent/non-map input — the
// planner then emits only the control channel (the default for backward
// compatibility with pre-data-channel specs).
// parseFTPSessions parses ftp.sessions[] into the multi-session shape
// (D-FTP-1). Each session: src_port (0 = inherit spec), banner, and an
// ordered transaction list; each transaction carries commands plus an
// optional data channel (parsed by parseFTPDataChannel so defaults
// mode=passive/direction=down apply identically).
func parseFTPSessions(v interface{}) []FTPSession {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]FTPSession, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		sess := FTPSession{
			SrcPort:    getUint16(m, "src_port"),
			Banner:     getString(m, "banner"),
			SrcPortDyn: parseStrategyConfigDyn(m["src_port"]),
			BannerDyn:  parseStrategyConfigDyn(m["banner"]),
		}
		if txs, ok := m["transactions"].([]interface{}); ok {
			for _, txItem := range txs {
				txm, ok := txItem.(map[string]interface{})
				if !ok {
					continue
				}
				tx := FTPTransaction{
					Commands:    parseFTPCommands(txm["commands"]),
					DataChannel: parseFTPDataChannel(txm["data_channel"]),
				}
				sess.Transactions = append(sess.Transactions, tx)
			}
		}
		out = append(out, sess)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseFTPDataChannel(v interface{}) *FTPDataChannel {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	dc := &FTPDataChannel{
		Mode:            getString(m, "mode"),
		SrcPort:         getUint16(m, "src_port"),
		DstPort:         getUint16(m, "dst_port"),
		Direction:       getString(m, "direction"),
		Payload:         getString(m, "payload"),
		PayloadB64:      getString(m, "payload_b64"),
		MSS:             getUint16(m, "mss"),
		AbortAfterBytes: getInt(m, "abort_after_bytes"),
		PayloadDyn:      parseStrategyConfigDyn(m["payload"]),
	}
	// Defaults: Mode="passive", Direction="down" — matches the most
	// common FTP test shape (PASV + RETR download). Zero-value check
	// leaves room for the planner to derive ports.
	if dc.Mode == "" {
		dc.Mode = "passive"
	}
	if dc.Direction == "" {
		dc.Direction = "down"
	}
	return dc
}

// parseSSHConfig converts the JSON-decoded "ssh" sub-map into an *SSHConfig.
// Returns nil for absent/non-map input. Empty string fields are left empty so
// the planner can apply its own defaults.
func parseSSHConfig(m map[string]interface{}) *SSHConfig {
	if m == nil {
		return nil
	}
	return &SSHConfig{
		ServerVersion:         getString(m, "server_version"),
		ClientVersion:         getString(m, "client_version"),
		KexAlgorithms:         getString(m, "kex_algorithms"),
		HostKeyAlgorithms:     getString(m, "host_key_algorithms"),
		EncryptionAlgorithms:  getString(m, "encryption_algorithms"),
		MACAlgorithms:         getString(m, "mac_algorithms"),
		CompressionAlgorithms: getString(m, "compression_algorithms"),
		KEX:                   getString(m, "kex"),
		AuthMethods:           parseSSHMessages(m["auth_methods"]),
		ExtInfo:               getBool(m, "ext_info", false),
		Channels:              parseChannelEntries(m["channels"]),
		RekeyAfter:            getUint32(m, "rekey_after"),
		DisconnectOnClose:     getBool(m, "disconnect_on_close", false),
		Scenario:              getString(m, "scenario"),
		Command:               getString(m, "command"),
		Stdout:                getByteSlice(m, "stdout"),
		Stderr:                getByteSlice(m, "stderr"),
	}
}

// parseSSHMessages converts the JSON-decoded "auth_methods" array into a
// []SSHMessage. Returns nil for absent/non-array input.
func parseSSHMessages(v interface{}) []SSHMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SSHMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := SSHMessage{
			Type:                       getString(m, "type"),
			Direction:                  getString(m, "direction"),
			ServiceName:                getString(m, "service_name"),
			MethodName:                 getString(m, "method_name"),
			Username:                   getString(m, "username"),
			Password:                   getString(m, "password"),
			HasPasswordChange:          getBool(m, "has_password_change", false),
			NewPassword:                getString(m, "new_password"),
			PublicKeyAlgorithm:         getString(m, "public_key_algorithm"),
			PublicKeyBlob:              getByteSlice(m, "public_key_blob"),
			HasSignature:               getBool(m, "has_signature", false),
			Signature:                  getByteSlice(m, "signature"),
			Submethods:                 getString(m, "submethods"),
			Prompt:                     getString(m, "prompt"),
			Response:                   getString(m, "response"),
			AuthMethodsThatCanContinue: getString(m, "auth_methods_that_can_continue"),
			PartialSuccess:             getBool(m, "partial_success", false),
			Banner:                     getString(m, "banner"),
			LanguageTag:                getString(m, "language_tag"),
			Name:                       getString(m, "name"),
			Instruction:                getString(m, "instruction"),
			PromptCount:                getUint32(m, "prompt_count"),
			Prompts:                    getString(m, "prompts"),
			Echo:                       getBool(m, "echo", false),
			NumResponses:               getUint32(m, "num_responses"),
			Responses:                  getString(m, "responses"),
			ReasonCode:                 getUint32(m, "reason_code"),
			Description:                getString(m, "description"),
			ReceiveSeq:                 getUint32(m, "receive_seq"),
			AlwaysDisplay:              getBool(m, "always_display", false),
			Message:                    getString(m, "message"),
			Data:                       getByteSlice(m, "data"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseChannelEntries converts the JSON-decoded "channels" array into a
// []ChannelEntry. Returns nil for absent/non-array input.
func parseChannelEntries(v interface{}) []ChannelEntry {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ChannelEntry, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		entry := ChannelEntry{
			Type:              getString(m, "type"),
			Direction:         getString(m, "direction"),
			SenderChannel:     getUint32(m, "sender_channel"),
			RecipientChannel:  getUint32(m, "recipient_channel"),
			ChannelType:       getString(m, "channel_type"),
			InitialWindowSize: getUint32(m, "initial_window_size"),
			MaximumPacketSize: getUint32(m, "maximum_packet_size"),
			DestHost:          getString(m, "dest_host"),
			DestPort:          getUint32(m, "dest_port"),
			OriginatorIP:      getString(m, "originator_ip"),
			OriginatorPort:    getUint32(m, "originator_port"),
			RequestType:       getString(m, "request_type"),
			WantReply:         getBool(m, "want_reply", false),
			Term:              getString(m, "term"),
			WidthChars:        getUint32(m, "width_chars"),
			HeightRows:        getUint32(m, "height_rows"),
			WidthPixels:       getUint32(m, "width_pixels"),
			HeightPixels:      getUint32(m, "height_pixels"),
			TTYModes:          getByteSlice(m, "tty_modes"),
			Command:           getString(m, "command"),
			EnvVarName:        getString(m, "env_var_name"),
			EnvVarValue:       getString(m, "env_var_value"),
			SubsystemName:     getString(m, "subsystem_name"),
			SignalName:        getString(m, "signal_name"),
			ExitStatus:        getUint32(m, "exit_status"),
			Data:              getByteSlice(m, "data"),
			DataTypeCode:      getUint32(m, "data_type_code"),
			BytesToAdd:        getUint32(m, "bytes_to_add"),
			OpenReasonCode:    getUint32(m, "open_reason_code"),
			OpenReasonText:    getString(m, "open_reason_text"),
			GlobalRequestName: getString(m, "global_request_name"),
			Address:           getString(m, "address"),
			Port:              getUint32(m, "port"),
			X11AuthProtocol:   getString(m, "x11_auth_protocol"),
			X11AuthCookie:     getByteSlice(m, "x11_auth_cookie"),
			X11ScreenNumber:   getUint32(m, "x11_screen_number"),
			SingleConnection:  getBool(m, "single_connection", false),
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPConfig converts the JSON-decoded "dhcp" sub-map into a
// *DHCPConfig. Returns nil for absent/non-map input. Each field maps to a
// DHCPConfig struct field; per-message overrides live inside parseDHCPMessages.
// Default field inheritance (DefaultClientIP, DefaultLeaseTime, etc.) is
// applied by the planner at emit time when message-level overrides are empty.
func parseDHCPConfig(m map[string]interface{}) *DHCPConfig {
	if m == nil {
		return nil
	}
	cfg := &DHCPConfig{
		Role:                    getString(m, "role"),
		Xid:                     getUint32(m, "xid"),
		Scenario:                getString(m, "scenario"),
		Messages:                parseDHCPMessages(m["messages"]),
		ClientMAC:               getString(m, "client_mac"),
		HType:                   uint8(getInt(m, "h_type")),
		HLen:                    uint8(getInt(m, "h_len")),
		BroadcastFlag:           getBool(m, "broadcast_flag", false),
		Secs:                    getUint16(m, "secs"),
		Sname:                   getString(m, "sname"),
		File:                    getString(m, "file"),
		DefaultClientIP:         getString(m, "default_client_ip"),
		DefaultYourIP:           getString(m, "default_your_ip"),
		DefaultServerIP:         getString(m, "default_server_ip"),
		DefaultRelayAgentIP:     getString(m, "default_relay_agent_ip"),
		DefaultServerIdentifier: getString(m, "default_server_identifier"),
		DefaultLeaseTime:        getUint32(m, "default_lease_time"),
		DefaultT1:               getUint32(m, "default_t1"),
		DefaultT2:               getUint32(m, "default_t2"),
		DefaultSubnetMask:       getString(m, "default_subnet_mask"),
		DefaultRouters:          getStringSlice(m, "default_routers"),
		DefaultDNS:              getStringSlice(m, "default_dns"),
		DefaultDomainName:       getString(m, "default_domain_name"),
		DefaultHostname:         getString(m, "default_hostname"),
		DefaultDomainSearch:     getStringSlice(m, "default_domain_search"),
		DefaultClientID:         getByteSlice(m, "default_client_id"),
		DefaultRequestedIP:      getString(m, "default_requested_ip"),
		DefaultParamRequestList: getUint8Slice(m, "default_param_request_list"),
		DefaultVendorClass:      getString(m, "default_vendor_class"),
		DefaultRelayAgentInfo:   getByteSlice(m, "default_relay_agent_info"),
	}
	return cfg
}

// parseDHCPMessages converts the "messages" array into []DHCPMessage. Each
// message carries MessageType + per-message overrides; empty fields inherit
// from DHCPConfig defaults at emit time.
func parseDHCPMessages(v interface{}) []DHCPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := DHCPMessage{
			Type:             uint8(getInt(m, "type")),
			Direction:        getString(m, "direction"),
			ClientIP:         getString(m, "client_ip"),
			YourIP:           getString(m, "your_ip"),
			ServerIP:         getString(m, "server_ip"),
			RelayAgentIP:     getString(m, "relay_agent_ip"),
			Hops:             uint8(getInt(m, "hops")),
			ServerIdentifier: getString(m, "server_identifier"),
			LeaseTime:        getUint32(m, "lease_time"),
			T1:               getUint32(m, "t1"),
			T2:               getUint32(m, "t2"),
			SubnetMask:       getString(m, "subnet_mask"),
			Routers:          getStringSlice(m, "routers"),
			DNS:              getStringSlice(m, "dns"),
			DomainName:       getString(m, "domain_name"),
			Hostname:         getString(m, "hostname"),
			DomainSearch:     getStringSlice(m, "domain_search"),
			ClientID:         getByteSlice(m, "client_id"),
			RequestedIP:      getString(m, "requested_ip"),
			ParamRequestList: getUint8Slice(m, "param_request_list"),
			VendorClass:      getString(m, "vendor_class"),
			RelayAgentInfo:   getByteSlice(m, "relay_agent_info"),
			ExtraOptions:     parseDHCPOptions(m["extra_options"]),
			Broadcast:        getBoolPtr(m, "broadcast"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPOptions converts the "extra_options" array into []DHCPOption.
func parseDHCPOptions(v interface{}) []DHCPOption {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPOption, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DHCPOption{
			Code: uint8(getInt(m, "code")),
			Data: getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPv6Config converts the JSON-decoded "dhcpv6" sub-map into a
// *DHCPv6Config. Returns nil for absent/non-map input.
func parseDHCPv6Config(m map[string]interface{}) *DHCPv6Config {
	if m == nil {
		return nil
	}
	cfg := &DHCPv6Config{
		Messages:                 parseDHCPv6Messages(m["messages"]),
		Scenario:                 getString(m, "scenario"),
		ClientDUID:               parseDUID(m["client_duid"]),
		ServerDUID:               parseDUID(m["server_duid"]),
		RelayConfig:              parseDHCPv6RelayConfig(m["relay_config"]),
		DefaultLeasedAddr:        getString(m, "default_leased_addr"),
		DefaultIAID:              getUint32(m, "default_iaid"),
		DefaultPreferredLifetime: getUint32(m, "default_preferred_lifetime"),
		DefaultValidLifetime:     getUint32(m, "default_valid_lifetime"),
		DefaultT1:                getUint32(m, "default_t1"),
		DefaultT2:                getUint32(m, "default_t2"),
		DefaultPreference:        uint8(getInt(m, "default_preference")),
		DefaultStatusCode:        getUint16(m, "default_status_code"),
		DefaultStatusMessage:     getString(m, "default_status_message"),
		DefaultORO:               getUint16Slice(m, "default_oro"),
		DefaultDNSServers:        getStringSlice(m, "default_dns_servers"),
		DefaultDNSSearch:         getStringSlice(m, "default_dns_search"),
		DefaultSNTPServers:       getStringSlice(m, "default_sntp_servers"),
		DefaultInfoRefreshTime:   getUint32(m, "default_info_refresh_time"),
	}
	return cfg
}

// parseDHCPv6Messages converts the "messages" array into []DHCPv6Message.
func parseDHCPv6Messages(v interface{}) []DHCPv6Message {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPv6Message, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var txID [3]byte
		if t := getByteSlice(m, "transaction_id"); len(t) >= 3 {
			copy(txID[:], t[:3])
		}
		msg := DHCPv6Message{
			MsgType:       uint8(getInt(m, "msg_type")),
			TransactionID: txID,
			Direction:     getString(m, "direction"),
			Options:       parseDHCPv6Options(m["options"]),
			RelayFields:   parseDHCPv6RelayFields(m["relay_fields"]),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDUID converts a DUID sub-map into *DUID.
func parseDUID(v interface{}) *DUID {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &DUID{
		Type:           uint8(getInt(m, "type")),
		HardwareType:   getUint16(m, "hardware_type"),
		Time:           getUint32(m, "time"),
		EnterpriseNum:  getUint32(m, "enterprise_num"),
		VendorSpecific: getByteSlice(m, "vendor_specific"),
		LinkLayerAddr:  getString(m, "link_layer_addr"),
	}
}

// parseDHCPv6Options converts an array of {code, data} into []DHCPv6Option.
func parseDHCPv6Options(v interface{}) []DHCPv6Option {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPv6Option, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DHCPv6Option{
			Code: getUint16(m, "code"),
			Data: getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPv6RelayFields converts a relay_fields sub-map into *RelayFields.
func parseDHCPv6RelayFields(v interface{}) *RelayFields {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RelayFields{
		HopCount:    uint8(getInt(m, "hop_count")),
		LinkAddress: getString(m, "link_address"),
		PeerAddress: getString(m, "peer_address"),
	}
}

// parseDHCPv6RelayConfig converts a relay_config sub-map into *RelayConfig.
func parseDHCPv6RelayConfig(v interface{}) *RelayConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RelayConfig{
		RelayIP:          getString(m, "relay_ip"),
		RelayMAC:         getString(m, "relay_mac"),
		HopCount:         uint8(getInt(m, "hop_count")),
		InterfaceID:      getByteSlice(m, "interface_id"),
		IncludeClientMAC: getBool(m, "include_client_mac", false),
	}
}

// parseGRPCConfig converts the JSON-decoded "grpc" sub-map into a
// *GRPCConfig. Returns nil for absent/non-map input. Request/Response
// messages accept both raw-bytes arrays ([][]byte) and base64 strings
// ([]string); the planner decodes base64 at Plan time.
func parseGRPCConfig(m map[string]interface{}) *GRPCConfig {
	if m == nil {
		return nil
	}
	cfg := &GRPCConfig{
		Service:               getString(m, "service"),
		Method:                getString(m, "method"),
		Authority:             getString(m, "authority"),
		Scheme:                getString(m, "scheme"),
		CallType:              getString(m, "call_type"),
		RequestMessages:       getByteSlices(m, "request_messages"),
		RequestMessagesB64:    getStringSlice(m, "request_messages_b64"),
		ResponseMessages:      getByteSlices(m, "response_messages"),
		ResponseMessagesB64:   getStringSlice(m, "response_messages_b64"),
		ResponseStatus:        getInt(m, "response_status"),
		ResponseMessage:       getString(m, "response_message"),
		Timeout:               getString(m, "timeout"),
		Encoding:              getString(m, "encoding"),
		AcceptEncoding:        getString(m, "accept_encoding"),
		Metadata:              getStringMap(m, "metadata"),
		UserAgent:             getString(m, "user_agent"),
		MaxFrameSize:          getUint32(m, "max_frame_size"),
		InitialWindow:         getUint32(m, "initial_window"),
		MaxConcurrentStreams:  getUint32(m, "max_concurrent_streams"),
		HeaderTableSize:       getUint32(m, "header_table_size"),
		Pings:                 parseGRPCPingConfig(m["pings"]),
		CancelAfter:           getInt(m, "cancel_after"),
		GoAwayAfter:           getBool(m, "go_away_after", false),
		WindowUpdateIncrement: getUint32(m, "window_update_increment"),
		Calls:                 parseGRPCCalls(m["calls"]),
		FileSource:            parseFileSourceField(m),
	}
	return cfg
}

// parseGRPCPingConfig converts the "pings" sub-map into *GRPCPingConfig.
func parseGRPCPingConfig(v interface{}) *GRPCPingConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	var opaque [8]byte
	if b := getByteSlice(m, "opaque_data"); len(b) >= 8 {
		copy(opaque[:], b[:8])
	}
	return &GRPCPingConfig{
		IntervalMs: getInt(m, "interval_ms"),
		Count:      getInt(m, "count"),
		OpaqueData: opaque,
	}
}

// parseGRPCCalls converts the "calls" array into []GRPCCall.
func parseGRPCCalls(v interface{}) []GRPCCall {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GRPCCall, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GRPCCall{
			Service:               getString(m, "service"),
			Method:                getString(m, "method"),
			CallType:              getString(m, "call_type"),
			RequestMessages:       getByteSlices(m, "request_messages"),
			ResponseMessages:      getByteSlices(m, "response_messages"),
			ResponseStatus:        getInt(m, "response_status"),
			ResponseMessage:       getString(m, "response_message"),
			Metadata:              getStringMap(m, "metadata"),
			Timeout:               getString(m, "timeout"),
			WindowUpdateIncrement: getUint32(m, "window_update_increment"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKEConfig converts the JSON-decoded "ike" sub-map into *IKEConfig.
func parseIKEConfig(m map[string]interface{}) *IKEConfig {
	if m == nil {
		return nil
	}
	cfg := &IKEConfig{
		VersionMajor:           uint8(getIntDefault(m, "version_major", 2)),
		VersionMinor:           uint8(getIntDefault(m, "version_minor", 0)),
		InitiatorSPI:           getUint64(m, "initiator_spi"),
		ResponderSPI:           getUint64(m, "responder_spi"),
		StartMessageID:         getUint32(m, "start_message_id"),
		Role:                   getString(m, "role"),
		Strict:                 getBool(m, "strict", false),
		FaultInjection:         getBool(m, "fault_injection", false),
		Messages:               parseIKEMessages(m["messages"]),
		Scenario:               getString(m, "scenario"),
		DefaultProposal:        parseIKEProposal(m["default_proposal"]),
		DefaultDHGroup:         getUint16(m, "default_dh_group"),
		DefaultNonceSize:       getUint16(m, "default_nonce_size"),
		DefaultAuthMethod:      uint8(getInt(m, "default_auth_method")),
		AllowNullAuth:          getBool(m, "allow_null_auth", false),
		EAPOnly:                getBool(m, "eap_only", false),
		FragmentationSupported: getBool(m, "fragmentation_supported", false),
		FragmentThreshold:      getUint16(m, "fragment_threshold"),
		ChildSAs:               parseIKEChildSAs(m["child_sas"]),
		DPDCount:               getInt(m, "dpd_count"),
		RetransmitCount:        getInt(m, "retransmit_count"),
		EncryptMode:            getString(m, "encrypt_mode"),
		OpaqueKeySeed:          getUint64(m, "opaque_key_seed"),
		ESPDataPlane:           parseESPDataPlaneConfig(m["esp_data_plane"]),
	}
	return cfg
}

// parseIKEMessages converts the "messages" array into []IKEMessage.
func parseIKEMessages(v interface{}) []IKEMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := IKEMessage{
			Direction:              getString(m, "direction"),
			ExchangeType:           uint8(getInt(m, "exchange_type")),
			IsResponse:             getBool(m, "is_response", false),
			FromOriginalInitiator:  getBool(m, "from_original_initiator", false),
			HigherVersionSupported: getBool(m, "higher_version_supported", false),
			MessageID:              getUint32Ptr(m, "message_id"),
			InitiatorSPI:           getUint64Ptr(m, "initiator_spi"),
			ResponderSPI:           getUint64Ptr(m, "responder_spi"),
			Payloads:               parseIKEPayloads(m["payloads"]),
			Encrypted:              parseIKEEncryptedBody(m["encrypted"]),
			Retransmit:             getInt(m, "retransmit"),
			DelayMillis:            getInt(m, "delay_ms"),
			RawLengthOverride:      getUint32Ptr(m, "raw_length_override"),
			RawNextPayloadOverride: getUint8Ptr(m, "raw_next_payload_override"),
			RawFlagsOverride:       getUint8Ptr(m, "raw_flags_override"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKEPayloads converts the "payloads" array into []IKEPayload.
func parseIKEPayloads(v interface{}) []IKEPayload {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEPayload, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		pl := IKEPayload{
			Type:                   uint8(getInt(m, "type")),
			Critical:               getBool(m, "critical", false),
			SA:                     parseIKESA(m["sa"]),
			KE:                     parseIKEKE(m["ke"]),
			ID:                     parseIKEIdentity(m["id"]),
			Certificate:            parseIKECertificate(m["certificate"]),
			CertificateRequest:     parseIKECertificateRequest(m["certificate_request"]),
			Auth:                   parseIKEAuth(m["auth"]),
			Nonce:                  getByteSlice(m, "nonce"),
			Notify:                 parseIKENotify(m["notify"]),
			Delete:                 parseIKEDelete(m["delete"]),
			VendorID:               getByteSlice(m, "vendor_id"),
			TrafficSelectors:       parseIKETrafficSelectors(m["traffic_selectors"]),
			Config:                 parseIKEConfiguration(m["config"]),
			EAP:                    parseIKEEAP(m["eap"]),
			Fragment:               parseIKEFragment(m["fragment"]),
			Raw:                    getByteSlice(m, "raw"),
			RawLengthOverride:      getUint16Ptr(m, "raw_length_override"),
			RawNextPayloadOverride: getUint8Ptr(m, "raw_next_payload_override"),
		}
		out = append(out, pl)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEProposal(v interface{}) *IKEProposal {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEProposal{
		Number:     uint8(getInt(m, "number")),
		ProtocolID: uint8(getInt(m, "protocol_id")),
		SPI:        getByteSlice(m, "spi"),
		Transforms: parseIKETransforms(m["transforms"]),
	}
}

func parseIKETransforms(v interface{}) []IKETransform {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKETransform, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKETransform{
			Type:          uint8(getInt(m, "type")),
			ID:            getUint16(m, "id"),
			KeyLengthBits: getUint16(m, "key_length_bits"),
			RawAttributes: getByteSlice(m, "raw_attributes"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKESA(v interface{}) *IKESA {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKESA{
		Proposals: parseIKEProposals(m["proposals"]),
	}
}

func parseIKEProposals(v interface{}) []IKEProposal {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEProposal, 0, len(arr))
	for _, item := range arr {
		if p := parseIKEProposal(item); p != nil {
			out = append(out, *p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEKE(v interface{}) *IKEKE {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEKE{
		DHGroup: getUint16(m, "dh_group"),
		KeyData: getByteSlice(m, "key_data"),
	}
}

func parseIKEIdentity(v interface{}) *IKEIdentity {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEIdentity{
		IDType: uint8(getInt(m, "id_type")),
		Data:   getByteSlice(m, "data"),
	}
}

func parseIKECertificate(v interface{}) *IKECertificate {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKECertificate{
		Encoding: uint8(getInt(m, "encoding")),
		Data:     getByteSlice(m, "data"),
	}
}

func parseIKECertificateRequest(v interface{}) *IKECertificateRequest {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKECertificateRequest{
		Encoding: uint8(getInt(m, "encoding")),
		CAs:      getByteSlices(m, "cas"),
	}
}

func parseIKEAuth(v interface{}) *IKEAuth {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEAuth{
		Method: uint8(getInt(m, "method")),
		Data:   getByteSlice(m, "data"),
	}
}

func parseIKENotify(v interface{}) *IKENotify {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKENotify{
		ProtocolID:  uint8(getInt(m, "protocol_id")),
		SPI:         getByteSlice(m, "spi"),
		MessageType: getUint16(m, "message_type"),
		Data:        getByteSlice(m, "data"),
	}
}

func parseIKEDelete(v interface{}) *IKEDelete {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEDelete{
		ProtocolID: uint8(getInt(m, "protocol_id")),
		SPISize:    uint8(getInt(m, "spi_size")),
		SPIs:       getByteSlices(m, "spis"),
	}
}

func parseIKETrafficSelectors(v interface{}) []IKETrafficSelector {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKETrafficSelector, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKETrafficSelector{
			TSType:       uint8(getInt(m, "ts_type")),
			IPProtocolID: uint8(getInt(m, "ip_protocol_id")),
			StartPort:    getUint16(m, "start_port"),
			EndPort:      getUint16(m, "end_port"),
			StartAddress: getByteSlice(m, "start_address"),
			EndAddress:   getByteSlice(m, "end_address"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEConfiguration(v interface{}) *IKEConfiguration {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEConfiguration{
		CFGType:    uint8(getInt(m, "cfg_type")),
		Attributes: parseIKEConfigAttributes(m["attributes"]),
	}
}

func parseIKEConfigAttributes(v interface{}) []IKEConfigAttribute {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEConfigAttribute, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKEConfigAttribute{
			Type:  getUint16(m, "type"),
			Value: getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEEAP(v interface{}) *IKEEAP {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEEAP{
		Code:       uint8(getInt(m, "code")),
		Identifier: uint8(getInt(m, "identifier")),
		Type:       getUint8Ptr(m, "type"),
		Data:       getByteSlice(m, "data"),
	}
}

func parseIKEEncryptedBody(v interface{}) *IKEEncryptedBody {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEEncryptedBody{
		InnerPayloads: parseIKEPayloads(m["inner_payloads"]),
		OpaqueData:    getByteSlice(m, "opaque_data"),
		IVLength:      getUint16(m, "iv_length"),
		ICVLength:     getUint16(m, "icv_length"),
		PadTo:         getUint16(m, "pad_to"),
	}
}

func parseIKEFragment(v interface{}) *IKEFragment {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEFragment{
		FragmentNumber: getUint16(m, "fragment_number"),
		TotalFragments: getUint16(m, "total_fragments"),
		Data:           getByteSlice(m, "data"),
	}
}

func parseIKEChildSAs(v interface{}) []IKEChildSA {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEChildSA, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKEChildSA{
			Proposal:    parseIKEProposal(m["proposal"]),
			TSi:         parseIKETrafficSelectors(m["ts_i"]),
			TSr:         parseIKETrafficSelectors(m["ts_r"]),
			EmitSubFlow: getBool(m, "emit_sub_flow", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKENATTConfig converts the JSON-decoded "ike_nat_t" sub-map into
// *IKENATTConfig. Returns nil for absent/non-map input.
func parseIKENATTConfig(m map[string]interface{}) *IKENATTConfig {
	if m == nil {
		return nil
	}
	cfg := &IKENATTConfig{
		InitiatorSPI:        getUint64(m, "initiator_spi"),
		ResponderSPI:        getUint64(m, "responder_spi"),
		NATDetection:        getBool(m, "nat_detection", false),
		NATDetectedOnSource: getBool(m, "nat_detected_on_source", false),
		NATDetectedOnDest:   getBool(m, "nat_detected_on_dest", false),
		PortFloat:           getBool(m, "port_float", false),
		UDPEncapESP:         getBool(m, "udp_encap_esp", false),
		Keepalive:           parseNATKeepaliveConfig(m["keepalive"]),
		Retransmit:          parseRetransmitConfig(m["retransmit"]),
		Dialog:              parseIKENATTMessages(m["dialog"]),
		ChildSA:             parseESPChildSAConfig(m["child_sa"]),
	}
	return cfg
}

func parseNATKeepaliveConfig(v interface{}) *NATKeepaliveConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &NATKeepaliveConfig{
		Interval:  getInt(m, "interval"),
		Count:     getInt(m, "count"),
		Direction: getString(m, "direction"),
	}
}

func parseRetransmitConfig(v interface{}) *RetransmitConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RetransmitConfig{
		Timeout:        getInt(m, "timeout"),
		MaxRetransmits: getInt(m, "max_retransmits"),
		Backoff:        getFloatDefault(m, "backoff", 0),
	}
}

func parseIKENATTMessages(v interface{}) []IKENATTMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKENATTMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKENATTMessage{
			Direction:    getString(m, "direction"),
			ExchangeType: uint8(getInt(m, "exchange_type")),
			MessageID:    getUint32(m, "message_id"),
			Payloads:     parseIKENATTPayloads(m["payloads"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKENATTPayloads(v interface{}) []IKENATTPayload {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKENATTPayload, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKENATTPayload{
			Type:   uint8(getInt(m, "type")),
			SA:     parseIKESA(m["sa"]),
			KE:     parseIKEKE(m["ke"]),
			Nonce:  getByteSlice(m, "nonce"),
			Notify: parseNotifyPayload(m["notify"]),
			Raw:    getByteSlice(m, "raw"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseNotifyPayload(v interface{}) *NotifyPayload {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &NotifyPayload{
		ProtocolID:       uint8(getInt(m, "protocol_id")),
		SPISize:          uint8(getInt(m, "spi_size")),
		NotifyMsgType:    getUint16(m, "notify_msg_type"),
		NotificationData: getByteSlice(m, "notification_data"),
	}
}

func parseESPChildSAConfig(v interface{}) *ESPChildSAConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &ESPChildSAConfig{
		SPIout:      getUint32(m, "spi_out"),
		SPIin:       getUint32(m, "spi_in"),
		ESPDataSize: getInt(m, "esp_data_size"),
		ESPCount:    getInt(m, "esp_count"),
		Algorithm:   getString(m, "algorithm"),
		Mode:        getString(m, "mode"),
	}
}

// parseESPDataPlaneConfig converts the JSON-decoded "esp_data_plane"
// sub-map of the IKE config into *ESPDataPlaneConfig. Returns nil for
// absent/non-map input.
func parseESPDataPlaneConfig(v interface{}) *ESPDataPlaneConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &ESPDataPlaneConfig{
		SPI:              getUint32(m, "spi"),
		Count:            getInt(m, "count"),
		Mode:             getString(m, "mode"),
		Direction:        getString(m, "direction"),
		IVLength:         getInt(m, "iv_length"),
		ICVLength:        getInt(m, "icv_length"),
		InnerSrcIP:       getString(m, "inner_src_ip"),
		InnerDstIP:       getString(m, "inner_dst_ip"),
		InnerProto:       uint8(getInt(m, "inner_proto")),
		InnerSrcPort:     getUint16(m, "inner_src_port"),
		InnerDstPort:     getUint16(m, "inner_dst_port"),
		InnerPayloadSize: getInt(m, "inner_payload_size"),
	}
}

func parseIMAPCommands(v interface{}) []IMAPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IMAPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		cmd := IMAPCommand{
			Tag:                  getString(m, "tag"),
			Cmd:                  getString(m, "cmd"),
			Responses:            getStringSlice(m, "responses"),
			LiteralBody:          getString(m, "literal_body"),
			LiteralBodyB64:       getString(m, "literal_body_b64"),
			FileSource:           parseFileSourceField(m),
			EmitIDLE:             getBool(m, "emit_idle", false),
			CancelAfterResponses: getInt(m, "cancel_after_responses"),
			UIDCacheInvalidation: getBool(m, "uid_cache_invalidation", false),
			MIMEBody:             parseIMAPMIMEBody(m["mime_body"]),
		}
		out = append(out, cmd)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIMAPIDLE(v interface{}) *IMAPIDLE {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IMAPIDLE{
		PushResponses:         getStringSlice(m, "push_responses"),
		DoneTag:               getString(m, "done_tag"),
		DoneResponse:          getString(m, "done_response"),
		ServerTimeoutBehavior: getString(m, "server_timeout_behavior"),
	}
}

// ParseIMAPConfigFromMap decodes an imap layer/terminal config map into an
// *IMAPConfig (single truth with the flat cfg["imap"] path — same parse,
// same defaults). nil input → nil (absent). Empty map → non-nil zero
// config (presence, same as an explicit map).
//
// Attachment byte convention (SMTP DataB64 family): mime_body attachments
// carry "data" as raw text ([]byte(raw) verbatim — NOT base64) and
// "data_b64" as pre-encoded base64 text. This matters because Go's JSON
// []byte semantics demand base64 text: a bare JSON round-trip of the layer
// config into IMAPConfig fails the WHOLE config on any raw-text attachment
// (spec.IMAP stays nil → silent empty session). Hence the layer path must
// use THIS function, never a JSON round-trip.
func ParseIMAPConfigFromMap(m map[string]interface{}) *IMAPConfig {
	if m == nil {
		return nil
	}
	cfg := &IMAPConfig{
		Banner:            getString(m, "banner"),
		Commands:          parseIMAPCommands(m["commands"]),
		IDLE:              parseIMAPIDLE(m["idle"]),
		PipelinedCommands: getBool(m, "pipelined_commands", false),
		AllowUTF8Mailbox:  getBool(m, "allow_utf8_mailbox", false),
	}
	return cfg
}

func parseIMAPMIMEBody(v interface{}) *IMAPMIMEBody {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	body := &IMAPMIMEBody{
		Headers:  getStringSlice(m, "headers"),
		Boundary: getString(m, "boundary"),
		Text:     getString(m, "text"),
	}
	// Parts
	if arr, ok := m["parts"].([]interface{}); ok {
		for _, item := range arr {
			pm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			body.Parts = append(body.Parts, IMAPMIMEPart{
				ContentType: getString(pm, "content_type"),
				Body:        getString(pm, "body"),
				Headers:     getStringSlice(pm, "headers"),
			})
		}
	}
	// Attachments
	if arr, ok := m["attachments"].([]interface{}); ok {
		for _, item := range arr {
			am, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			att := IMAPAttachment{
				Filename:    getString(am, "filename"),
				ContentType: getString(am, "content_type"),
			}
			// Data may be a base64 string (data_b64) or raw text (data).
			if b64 := getString(am, "data_b64"); b64 != "" {
				if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
					att.Data = decoded
				}
			}
			if raw := getString(am, "data"); raw != "" && att.Data == nil {
				att.Data = []byte(raw)
			}
			body.Attachments = append(body.Attachments, att)
		}
	}
	return body
}

// parseL2TPConfig converts the JSON-decoded "l2tp" sub-map into *L2TPConfig.
func parseL2TPConfig(m map[string]interface{}) *L2TPConfig {
	if m == nil {
		return nil
	}
	cfg := &L2TPConfig{
		Version:           uint8(getInt(m, "version")),
		Role:              getString(m, "role"),
		LocalTunnelID:     getUint16(m, "local_tunnel_id"),
		PeerTunnelID:      getUint16(m, "peer_tunnel_id"),
		LocalSessionID:    getUint16(m, "local_session_id"),
		PeerSessionID:     getUint16(m, "peer_session_id"),
		LocalSessionID32:  getUint32(m, "local_session_id_32"),
		PeerSessionID32:   getUint32(m, "peer_session_id_32"),
		HostName:          getString(m, "host_name"),
		VendorName:        getString(m, "vendor_name"),
		FirmwareRev:       getUint16(m, "firmware_rev"),
		FramingCaps:       getUint32(m, "framing_caps"),
		BearerCaps:        getUint32(m, "bearer_caps"),
		ReceiveWindowSize: getUint16(m, "receive_window_size"),
		InitialNs:         getUint16(m, "initial_ns"),
		TieBreaker:        getUint64(m, "tie_breaker"),
		ProtocolVersion:   getUint16(m, "protocol_version"),
		Cookie:            getByteSlice(m, "cookie"),
		Scenarios:         parseL2TPSteps(m["scenarios"]),
		HelloInterval:     getInt(m, "hello_interval"),
		PPPFrames:         parseL2TPPPPFrames(m["ppp_frames"]),
		CustomAVPs:        parseL2TPAVPs(m["custom_avps"]),
		ResultCode:        getUint16(m, "result_code"),
		ErrorCode:         getUint16(m, "error_code"),
		ErrorMessage:      getString(m, "error_message"),
		Scenario:          getString(m, "scenario"),
		InnerIP:           parseL2TPInnerIP(m["inner_ip"]),
	}
	return cfg
}

func parseL2TPSteps(v interface{}) []L2TPStep {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPStep, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPStep{
			Type:              getString(m, "type"),
			Direction:         getString(m, "direction"),
			AVPs:              parseL2TPAVPs(m["avps"]),
			TunnelIDOverride:  getUint16Ptr(m, "tunnel_id_override"),
			SessionIDOverride: getUint16Ptr(m, "session_id_override"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseL2TPAVPs(v interface{}) []L2TPAVP {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPAVP, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPAVP{
			Mandatory: getBool(m, "mandatory", false),
			Hidden:    getBool(m, "hidden", false),
			VendorID:  getUint16(m, "vendor_id"),
			AttrType:  getUint16(m, "attr_type"),
			Value:     getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseL2TPPPPFrames(v interface{}) []L2TPPPPFrame {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPPPPFrame, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPPPPFrame{
			Protocol:    getUint16(m, "protocol"),
			Data:        getByteSlice(m, "data"),
			Direction:   getString(m, "direction"),
			L2PPPHeader: getBool(m, "l2_ppp_header", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseL2TPInnerIP converts the JSON-decoded "inner_ip" sub-map into
// *L2TPInnerIP (the inner IPv4 packet config for the tunnel_with_data
// scenario).
func parseL2TPInnerIP(v interface{}) *L2TPInnerIP {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &L2TPInnerIP{
		SrcIP:      getString(m, "src_ip"),
		DstIP:      getString(m, "dst_ip"),
		Proto:      uint8(getInt(m, "proto")),
		SrcPort:    getUint16(m, "src_port"),
		DstPort:    getUint16(m, "dst_port"),
		TTL:        uint8(getInt(m, "ttl")),
		Payload:    getByteSlice(m, "payload"),
		DataFrames: getInt(m, "data_frames"),
	}
}

// parsePPTPConfig converts the JSON-decoded "pptp" sub-map into
// *PPTPConfig. Numeric fields use getIntPresence: absent = the reference
// pcap default (design_pptp.md §3), an explicit 0 is preserved — for most
// fields the planner's resolveDefaults re-applies "0 = use the default"
// (so explicit values need to be nonzero to take effect), but the frame
// counts (data_frames/down_data_frames/sli_count) honor an explicit 0
// (zero frames is a legal config).
// ParsePPTPConfigFromMap exports parsePPTPConfig for the layer-translate
// path (parse helpers are package-local; ParseLDAPConfigFromMap precedent).
func ParsePPTPConfigFromMap(m map[string]interface{}) *PPTPConfig {
	return parsePPTPConfig(m)
}

// ParseSCTPConfigFromMap exports the universal-section SCTP read for the
// layer-translate path (ParseXmppConfigFromMap precedent). SCTP 无 switch
// case——sub-config 在 mapToFlowSpec universal 段读取（:517），此处复用同一
// 段逻辑等价形（六键逐字一致）。
// ParseJT808ConfigFromMap parses a jt808 layer/flat config map into the
// core JT808Config (D-JT808-1：单一真相——translate 与扁平同函数；链路径
// 空 map 也出非 nil 缺省壳，与 vnc/xmpp/sctp 同款). 数值键全直传（V9 区间
// 锚=registry；嵌套 procedures 不下探，语义锚=protocol ValidateConfig）。
// ParseJT809ConfigFromMap parses a jt809 layer/flat config map into the
// core JT809Config (D-JT809-1：单一真相——translate 与扁平同函数；链路径
// 空 map 也出非 nil 缺省壳). 数值键全直传（V9 区间锚=registry；嵌套
// procedures/slave_procedures 不下探，语义锚=protocol ValidateConfig）。
func ParseJT809ConfigFromMap(m map[string]interface{}) *JT809Config {
	if m == nil {
		return nil
	}
	cfg := &JT809Config{
		GNSSCenterId:      uint32(getInt(m, "gnss_center_id")),
		UserId:            uint32(getInt(m, "user_id")),
		Password:          getString(m, "password"),
		VersionFlag:       uint8(getInt(m, "version_flag")),
		VersionBytes:      getString(m, "version_bytes"),
		EncryptFlag:       uint8(getInt(m, "encrypt_flag")),
		EncryptKey:        uint32(getInt(m, "encrypt_key")),
		TimeSec:           uint64(getInt(m, "time_sec")),
		DownLinkIP:        getString(m, "down_link_ip"),
		DownLinkPort:      uint16(getInt(m, "down_link_port")),
		InitialSN:         uint32(getInt(m, "initial_sn")),
		PlatformInitialSN: uint32(getInt(m, "platform_initial_sn")),
	}
	for name, dst := range map[string]*[]JT809Procedure{
		"procedures":       &cfg.Procedures,
		"slave_procedures": &cfg.SlaveProcedures,
	} {
		v, ok := m[name].([]interface{})
		if !ok {
			continue
		}
		for _, item := range v {
			pm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			*dst = append(*dst, JT809Procedure{
				Type:         getString(pm, "type"),
				VerifyCode:   uint32(getInt(pm, "verify_code")),
				Result:       uint8(getInt(pm, "result")),
				Password:     getString(pm, "password"),
				DownLinkIP:   getString(pm, "down_link_ip"),
				DownLinkPort: uint16(getInt(pm, "down_link_port")),
				ErrorCode:    uint8(getInt(pm, "error_code")),
				ReasonCode:   uint8(getInt(pm, "reason_code")),
			})
		}
	}
	return cfg
}

// ParseJTT905ConfigFromMap parses a jtt905 layer/flat config map into the
// core JTT905Config (D-JTT905-1：单一真相；链路径空 map 也出非 nil 缺省壳).
// 数值/位数键直传（V9 区间锚=registry；嵌套 procedures/position 不下探，
// 语义锚=protocol ValidateConfig）。
func ParseJTT905ConfigFromMap(m map[string]interface{}) *JTT905Config {
	if m == nil {
		return nil
	}
	cfg := &JTT905Config{
		ISUId:                  getString(m, "isu_id"),
		InitialSN:              uint16(getInt(m, "initial_sn")),
		PlatformInitialSN:      uint16(getInt(m, "platform_initial_sn")),
		BusinessLicense:        getString(m, "business_license"),
		QualificationCode:      getString(m, "qualification_code"),
		PlateNo:                getString(m, "plate_no"),
		TaximeterKValue:        getString(m, "taximeter_k_value"),
		OnDutyPowerOnTime:      getString(m, "on_duty_power_on_time"),
		OnDutyPowerOffTime:     getString(m, "on_duty_power_off_time"),
		OnDutyMileage:          getString(m, "on_duty_mileage"),
		OnDutyOperationMileage: getString(m, "on_duty_operation_mileage"),
		TrainNumber:            getString(m, "train_number"),
		TimingTime:             getString(m, "timing_time"),
		TotalAmount:            getString(m, "total_amount"),
		CardAmount:             getString(m, "card_amount"),
		CardCount:              getString(m, "card_count"),
		OnDutyMileageBetween:   getString(m, "on_duty_mileage_between"),
		TotalMileage:           getString(m, "total_mileage"),
		TotalOperationMileage:  getString(m, "total_operation_mileage"),
		UnitPrice:              getString(m, "unit_price"),
		TotalOperations:        uint32(getInt(m, "total_operations")),
		SignType:               uint8(getInt(m, "sign_type")),
		HeartbeatCount:         getInt(m, "heartbeat_count"),
	}
	if pm, ok := m["position"].(map[string]interface{}); ok {
		cfg.Position = &JTT905Position{
			AlarmFlag:  uint32(getInt(pm, "alarm_flag")),
			StatusFlag: uint32(getInt(pm, "status_flag")),
			Lat:        uint32(getInt(pm, "lat")),
			Lng:        uint32(getInt(pm, "lng")),
			Speed:      uint16(getInt(pm, "speed")),
			Direction:  uint8(getInt(pm, "direction")),
			Time:       getString(pm, "time"),
		}
	}
	if v, ok := m["procedures"].([]interface{}); ok {
		for _, item := range v {
			prm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			cfg.Procedures = append(cfg.Procedures, JTT905Procedure{
				Type:       getString(prm, "type"),
				Result:     uint8(getInt(prm, "result")),
				ReplySN:    uint16(getInt(prm, "reply_sn")),
				ReplyMsgId: uint16(getInt(prm, "reply_msg_id")),
			})
		}
	}
	return cfg
}

func ParseJT808ConfigFromMap(m map[string]interface{}) *JT808Config {
	if m == nil {
		return nil
	}
	cfg := &JT808Config{
		Phone:              getString(m, "phone"),
		Version:            getString(m, "version"),
		EncryptFlag:        uint8(getInt(m, "encrypt_flag")),
		LicenseColor:       uint8(getInt(m, "license_color")),
		LicensePlate:       getString(m, "license_plate"),
		ProvinceId:         uint16(getInt(m, "province_id")),
		CityId:             uint16(getInt(m, "city_id")),
		ManufacturerId:     getString(m, "manufacturer_id"),
		TerminalModel:      getString(m, "terminal_model"),
		TerminalId:         getString(m, "terminal_id"),
		TerminalType:       uint8(getInt(m, "terminal_type")),
		InitialSN:          uint16(getInt(m, "initial_sn")),
		PlatformInitialSN:  uint16(getInt(m, "platform_initial_sn")),
		AuthCode:           getString(m, "auth_code"),
		IMEI:               getString(m, "imei"),
		SoftwareVersion:    getString(m, "software_version"),
		RegistrationResult: uint8(getInt(m, "registration_result")),
	}
	if v, ok := m["procedures"].([]interface{}); ok {
		for _, item := range v {
			pm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			pr := JT808Procedure{
				Type:          getString(pm, "type"),
				ACKFlag:       uint8(getInt(pm, "ack_flag")),
				ResponseSN:    uint16(getInt(pm, "response_sn")),
				ResponseMsgId: uint16(getInt(pm, "response_msg_id")),
				AuthCode:      getString(pm, "auth_code"),
				Text:          getString(pm, "text"),
				TextFlag:      uint8(getInt(pm, "text_flag")),
			}
			// 指针三态键：registry nil=不覆盖（registration_result 覆盖/
			// imei/software_version 覆盖；presence 语义=显式才覆盖）。
			if v, ok := pm["registration_result"]; ok && v != nil {
				if n, ok := v.(float64); ok {
					u := uint8(n)
					pr.RegistrationResult = &u
				}
			}
			if v, ok := pm["imei"]; ok && v != nil {
				if str, ok := v.(string); ok {
					pr.IMEI = &str
				}
			}
			if v, ok := pm["software_version"]; ok && v != nil {
				if str, ok := v.(string); ok {
					pr.SoftwareVersion = &str
				}
			}
			if lm, ok := pm["location_data"].(map[string]interface{}); ok {
				pr.LocationData = parseJT808Location(lm)
			}
			if pv, ok := pm["property_data"].(map[string]interface{}); ok {
				pr.PropertyData = &JT808Property{
					DeviceType:      uint8(getInt(pv, "device_type")),
					ManufacturerId:  getString(pv, "manufacturer_id"),
					TerminalModel:   getString(pv, "terminal_model"),
					TerminalId:      getString(pv, "terminal_id"),
					IccId:           getString(pv, "icc_id"),
					Imei:            getString(pv, "imei"),
					SoftwareVersion: getString(pv, "software_version"),
					GnssModule:      uint8(getInt(pv, "gnss_module")),
					CommModule:      uint8(getInt(pv, "comm_module")),
					ProvinceId:      uint16(getInt(pv, "province_id")),
					CityId:          uint16(getInt(pv, "city_id")),
					CountyId:        uint16(getInt(pv, "county_id")),
					TownId:          uint16(getInt(pv, "town_id")),
					Operator:        uint8(getInt(pv, "operator")),
					APN:             getString(pv, "apn"),
					HardwareVersion: getString(pv, "hardware_version"),
					MaxSpeed:        uint16(getInt(pv, "max_speed")),
				}
			}
			if arr, ok := pm["params"].([]interface{}); ok {
				for _, pi := range arr {
					pmm, ok := pi.(map[string]interface{})
					if !ok {
						continue
					}
					pr.Params = append(pr.Params, JT808Param{
						Id:    uint32(getInt(pmm, "id")), // DWORD（F2 勘误）
						Value: getByteSlice(pmm, "value"),
					})
				}
			}
			cfg.Procedures = append(cfg.Procedures, pr)
		}
	}
	return cfg
}

// parseJT808Location parses one 0x0200 location_data object (28B 固定面 +
// TLV 附加项 + 状态位合并 *bool 三态).
func parseJT808Location(m map[string]interface{}) *JT808Location {
	loc := &JT808Location{
		AlarmFlag:  getUint32(m, "alarm_flag"),
		StatusFlag: getUint32(m, "status_flag"),
		Latitude:   getUint32(m, "latitude"),
		Longitude:  getUint32(m, "longitude"),
		Altitude:   uint16(getInt(m, "altitude")),
		Speed:      uint16(getInt(m, "speed")),
		Direction:  uint16(getInt(m, "direction")),
		Time:       getString(m, "time"),
	}
	for key, dst := range map[string]**bool{
		"acc":         &loc.ACC,
		"door_status": &loc.DoorStatus,
		"oil_circuit": &loc.OilCircuit,
		"run_status":  &loc.RunStatus,
	} {
		if v, ok := m[key]; ok && v != nil {
			if b, ok2 := v.(bool); ok2 {
				*dst = &b
			}
		}
	}
	if arr, ok := m["extra_items"].([]interface{}); ok {
		for _, item := range arr {
			em, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			loc.ExtraItems = append(loc.ExtraItems, JT808Extra{
				Type:   uint8(getInt(em, "type")),
				Length: uint8(getInt(em, "length")),
				Value:  getByteSlice(em, "value"),
			})
		}
	}
	return loc
}

func ParseSCTPConfigFromMap(m map[string]interface{}) *SCTPConfig {
	if m == nil {
		return nil
	}
	return &SCTPConfig{
		VerificationTag: getUint32(m, "verification_tag"),
		InitiateTag:     getUint32(m, "initiate_tag"),
		Chunks:          parseSCTPChunks(m["chunks"]),
		Heartbeats:      parseSCTPHeartbeats(m["heartbeats"]),
		Abort:           getBool(m, "abort", false),
		FragmentSize:    getInt(m, "fragment_size"),
	}
}

// ParseXmppConfigFromMap exports parseXmppConfig for the layer-translate
// path (ParseVNCConfigFromMap precedent).
func ParseXmppConfigFromMap(m map[string]interface{}) *XmppConfig {
	return parseXmppConfig(m)
}

// ParseVNCConfigFromMap exports parseVNCConfig for the layer-translate
// path (ParsePPTPConfigFromMap precedent). parseVNCConfig 的 errs 通道
// （encodings 列表非数值项）在链面不外露——链路径无 ValidationErrors
// 消费点（translate :1901 注记：schema 层先拦），姊妹协议 wrapper 同为
// 单值形；B′ 账本注记该残差，扁平面仍大声失败。
func ParseVNCConfigFromMap(m map[string]interface{}) *VNCConfig {
	cfg, _ := parseVNCConfig(m)
	return cfg
}

func parsePPTPConfig(m map[string]interface{}) *PPTPConfig {
	if m == nil {
		return nil
	}
	cfg := &PPTPConfig{
		Role:              getString(m, "role"),
		Scenario:          getString(m, "scenario"),
		Calls:             getIntPresence(m, "calls", 1),
		Version:           uint16(getIntPresence(m, "version", 0x0100)),
		FramingCaps:       uint32(getIntPresence(m, "framing_caps", 1)),
		BearerCaps:        uint32(getIntPresence(m, "bearer_caps", 1)),
		MaxChannels:       getUint16(m, "max_channels"),
		FirmwareRevision:  getUint16(m, "firmware_revision"),
		HostName:          getString(m, "host_name"),
		VendorName:        getStringDefault(m, "vendor_name", "Microsoft"),
		ScrpResult:        uint8(getIntPresence(m, "scrp_result", 1)),
		ScrpError:         uint8(getInt(m, "scrp_error")),
		ScrpFramingCaps:   uint32(getIntPresence(m, "scrp_framing_caps", 2)),
		ScrpBearerCaps:    uint32(getIntPresence(m, "scrp_bearer_caps", 3)),
		ScrpFirmwareRev:   uint16(getIntPresence(m, "scrp_firmware_rev", 0x0ece)),
		CallID:            uint16(getIntPresence(m, "call_id", 0xa9c0)),
		PeerCallID:        uint16(getIntPresence(m, "peer_call_id", 0x35c9)),
		CallSerial:        uint16(getIntPresence(m, "call_serial", 3)),
		MinBPS:            uint32(getIntPresence(m, "min_bps", 300)),
		MaxBPS:            uint32(getIntPresence(m, "max_bps", 100000000)),
		BearerType:        uint32(getIntPresence(m, "bearer_type", 3)),
		FramingType:       uint32(getIntPresence(m, "framing_type", 3)),
		WindowSize:        uint16(getIntPresence(m, "window_size", 64)),
		PacketDelay:       getUint16(m, "packet_delay"),
		PhoneNumber:       getString(m, "phone_number"),
		SubAddress:        getString(m, "sub_address"),
		OcrpResult:        uint8(getIntPresence(m, "ocrp_result", 1)),
		OcrpError:         uint8(getInt(m, "ocrp_error")),
		CauseCode:         getUint16(m, "cause_code"),
		ConnectSpeed:      uint32(getIntPresence(m, "connect_speed", 14808325)),
		OcrpWindowSize:    uint16(getIntPresence(m, "ocrp_window_size", 16384)),
		OcrpDelay:         getUint16(m, "ocrp_delay"),
		PhysicalChannelID: getUint32(m, "physical_channel_id"),
		SendACCM:          uint32(getIntPresence(m, "send_accm", 0xffffffff)),
		ReceiveACCM:       uint32(getIntPresence(m, "receive_accm", 0xffffffff)),
		SLICount:          getIntPresence(m, "sli_count", 5),
		SliPeerCallID:     getUint16(m, "sli_peer_call_id"),
		StopReason:        uint8(getIntPresence(m, "stop_reason", 1)),
		StopResult:        uint8(getIntPresence(m, "stop_result", 1)),
		StopError:         uint8(getInt(m, "stop_error")),
		CcdnResult:        uint8(getInt(m, "ccdn_result")),
		CcdnError:         uint8(getInt(m, "ccdn_error")),
		CcdnCause:         getUint16(m, "ccdn_cause"),
		Echo:              getBool(m, "echo", false),
		WEN:               getBool(m, "wen", false),
		IncomingCall:      getBool(m, "incoming_call", false),
		DialedNumber:      getString(m, "dialed_number"),
		DialingNumber:     getString(m, "dialing_number"),
		DataFrames:        getIntPresence(m, "data_frames", 3),
		DownDataFrames:    getIntPresence(m, "down_data_frames", 2),
		InnerIP:           parsePPTPInnerIP(m["inner_ip"]),
	}
	return cfg
}

// parsePPTPInnerIP converts the JSON-decoded "inner_ip" sub-map into
// *PPTPInnerIP (the inner IPv4 packet config for the PPTP-GRE data plane).
func parsePPTPInnerIP(v interface{}) *PPTPInnerIP {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &PPTPInnerIP{
		SrcIP:   getString(m, "src_ip"),
		DstIP:   getString(m, "dst_ip"),
		Proto:   uint8(getIntPresence(m, "proto", 17)),
		SrcPort: getUint16(m, "src_port"),
		DstPort: getUint16(m, "dst_port"),
		TTL:     uint8(getIntPresence(m, "ttl", 64)),
		Payload: getByteSlice(m, "payload"),
	}
}

// parseH323Config converts the JSON-decoded "h323" sub-map into *H323Config.
// Design defaults are applied at parse time via getIntPresence, which keeps
// explicit 0 values intact so the planner can distinguish "absent" from
// "explicitly 0" (the same convention PPTP uses for its frame counts).
//
// Parse-level errors are returned so the "h323" case can append them to
// spec.ValidationErrors and fail the task loudly - getInt would silently
// coerce "abc" to 0.
func parseH323Config(m map[string]interface{}) (*H323Config, []string) {
	if m == nil {
		return nil, nil
	}
	var errs []string
	cfg := &H323Config{
		Role:        getStringDefault(m, "role", "caller"),
		Scenario:    getStringDefault(m, "scenario", "full"),
		Crv:         uint16(getIntPresence(m, "crv", 0x2584)),
		DisplayName: getStringDefault(m, "display_name", "Administrator"),
		Calls:       getIntPresence(m, "calls", 1),
		RewriteAddr: getBool(m, "rewrite_addr", false),
	}
	if cfg.Role != "caller" && cfg.Role != "callee" {
		errs = append(errs, "h323.role must be \"caller\" or \"callee\"")
	}
	if cfg.Scenario != "full" && cfg.Scenario != "tunnel_only" &&
		cfg.Scenario != "ras_only" && cfg.Scenario != "data_only" {
		errs = append(errs, "h323.scenario must be full|tunnel_only|ras_only|data_only")
	}
	if cfg.Calls <= 0 {
		errs = append(errs, "h323.calls must be >= 1")
	}
	if len(cfg.DisplayName) > 254 {
		errs = append(errs, "h323.display_name must be <= 254 bytes (Display IE length is 1 byte)")
	}
	if mm, ok := m["media"].(map[string]interface{}); ok {
		mc := &H323MediaConfig{
			Enabled:     getBool(mm, "enabled", false),
			SrcPort:     uint16(getIntPresence(mm, "src_port", 5062)),
			DstPort:     uint16(getIntPresence(mm, "dst_port", 5063)),
			Frames:      getIntPresence(mm, "frames", 10),
			PayloadType: uint8(getIntPresence(mm, "payload_type", 0)),
			FrameSize:   getIntPresence(mm, "frame_size", 160),
		}
		if mc.Frames < 0 {
			errs = append(errs, "h323.media.frames must be >= 0")
		}
		if mc.FrameSize < 0 {
			errs = append(errs, "h323.media.frame_size must be >= 0")
		}
		cfg.Media = mc
	}
	if rm, ok := m["ras"].(map[string]interface{}); ok {
		rc := &H323RasConfig{
			Enabled:      getBool(rm, "enabled", false),
			GatekeeperIP: getStringDefault(rm, "gatekeeper_ip", "10.12.184.53"),
			Port:         uint16(getIntPresence(rm, "port", 1719)),
			EndpointType: getStringDefault(rm, "endpoint_type", "terminal"),
		}
		if rc.EndpointType != "terminal" && rc.EndpointType != "gateway" {
			errs = append(errs, "h323.ras.endpoint_type must be terminal|gateway")
		}
		cfg.Ras = rc
	}
	return cfg, errs
}

// parseXmppConfig converts the JSON-decoded "xmpp" sub-map into
// *XmppConfig (解析XMPP配置). Follows the "user > default > none" rule:
// empty fields stay zero-valued here and get defaulted in the planner.
func parseXmppConfig(m map[string]interface{}) *XmppConfig {
	if m == nil {
		return nil
	}
	cfg := &XmppConfig{
		From:          getString(m, "from"),
		JID:           getString(m, "jid"),
		Resource:      getString(m, "resource"),
		StreamID:      getString(m, "stream_id"),
		AuthMechanism: getString(m, "auth_mechanism"),
		Username:      getString(m, "username"),
		Password:      getString(m, "password"),
		Presence:      getBoolPtr(m, "presence"),
		Messages:      parseXmppMessages(m["messages"]),
	}
	return cfg
}

// parseXmppMessages converts the JSON-decoded "messages" list into
// []XmppMessage (解析XMPP消息列表).
func parseXmppMessages(v interface{}) []XmppMessage {
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]XmppMessage, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, XmppMessage{
				Direction: getString(m, "direction"),
				To:        getString(m, "to"),
				Body:      getString(m, "body"),
			})
		}
	}
	return out
}

// length/discovery_tags) are for the builder when crafting single frames;
// the session-level fields (skip_discovery/ac_name/service_name/cookie/
// mru/magic_number/auth/username/password/data_frames/data_payload/
// inner_proto/data_direction) drive the internal/protocol/pppoe planner's
// full-session state machine.
func parsePPPoEConfig(m map[string]interface{}) *PPPoEConfig {
	if m == nil {
		return nil
	}
	cfg := &PPPoEConfig{
		Code:          uint8(getInt(m, "code")),
		SessionID:     getUint16(m, "session_id"),
		PPPProtocol:   getUint16(m, "ppp_protocol"),
		PayloadLength: getUint16(m, "payload_length"),
		DiscoveryTags: parsePPPoETags(m["discovery_tags"]),
		SkipDiscovery: getBool(m, "skip_discovery", false),
		ACName:        getString(m, "ac_name"),
		ServiceName:   getString(m, "service_name"),
		Cookie:        getByteSlice(m, "cookie"),
		MRU:           getUint16(m, "mru"),
		MagicNumber:   getUint32(m, "magic_number"),
		Auth:          getString(m, "auth"),
		Username:      getString(m, "username"),
		Password:      getString(m, "password"),
		DataFrames:    getInt(m, "data_frames"),
		DataPayload:   getByteSlice(m, "data_payload"),
		InnerProto:    uint8(getInt(m, "inner_proto")),
		DataDirection: getString(m, "data_direction"),
		// PADT 指针三态（缺省 true）：false=抑制终止帧——此前漏解析致
		// 层链路径 padt:false 被静默丢弃（T-2 首跑抓出，ParseSIPSessions
		// 漏 Medias 同型）。
		PADT:     getBoolPtr(m, "padt"),
		Sessions: ParsePPPoESessions(m["sessions"]),
	}
	return cfg
}

// ParsePPPoEConfigFromMap exports parsePPPoEConfig for the layer-translate
// path (parse helpers are package-local; ParseFTPConfigFromMap precedent).
func ParsePPPoEConfigFromMap(m map[string]interface{}) *PPPoEConfig {
	return parsePPPoEConfig(m)
}

// ParsePPPoESessions converts the JSON-decoded "sessions" array into
// []PPPoESession (D-PPPOE-1 9.49: one full lifecycle per entry). Exported
// for the layer-translate path, which reuses parsePPPoEConfig.
func ParsePPPoESessions(v interface{}) []PPPoESession {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PPPoESession, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, PPPoESession{
			SessionID:     getUint16(m, "session_id"),
			SessionIDDyn:  parseStrategyConfigDyn(m["session_id"]),
			SkipDiscovery: getBool(m, "skip_discovery", false),
			DataFrames:    getInt(m, "data_frames"),
			DataPayload:   getByteSlice(m, "data_payload"),
			InnerProto:    uint8(getInt(m, "inner_proto")),
			DataDirection: getString(m, "data_direction"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parsePPPoETags(v interface{}) []PPPoETag {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PPPoETag, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, PPPoETag{
			Type:  getUint16(m, "type"),
			Value: getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseGREConfig converts the JSON-decoded "gre" sub-map into *GREConfig.
// Wire-level fields (protocol_type/checksum/key_present/key/sequence_
// present/sequence/routing_present/routing) drive the builder's GRE header
// emission; the tunnel-level fields (inner_src_ip/inner_dst_ip/inner_proto/
// inner_ttl/inner_ipid/inner_payload/frames/direction) drive the
// internal/protocol/gre planner's inner-packet construction.
func parseGREConfig(m map[string]interface{}) *GREConfig {
	if m == nil {
		return nil
	}
	return &GREConfig{
		ProtocolType:    getUint16(m, "protocol_type"),
		Checksum:        getBool(m, "checksum", false),
		KeyPresent:      getBool(m, "key_present", false),
		SequencePresent: getBool(m, "sequence_present", false),
		Key:             getUint32(m, "key"),
		Sequence:        getUint32(m, "sequence"),
		RoutingPresent:  getBool(m, "routing_present", false),
		Routing:         getByteSlice(m, "routing"),
		InnerSrcIP:      getString(m, "inner_src_ip"),
		InnerDstIP:      getString(m, "inner_dst_ip"),
		InnerProto:      uint8(getInt(m, "inner_proto")),
		InnerTTL:        uint8(getInt(m, "inner_ttl")),
		InnerIPID:       getUint16(m, "inner_ipid"),
		InnerPayload:    getByteSlice(m, "inner_payload"),
		TCPOptions:      parseGREConfigTCPOptions(m["tcp_options"]),
		Frames:          getInt(m, "frames"),
		Direction:       getString(m, "direction"),
	}
}

// parseGREConfigTCPOptions converts a JSON-decoded "tcp_options" list into
// []TCPOption (each entry: kind + optional data), for the inner TCP header
// of GRE tunnels.
func parseGREConfigTCPOptions(v interface{}) []TCPOption {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]TCPOption, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, TCPOption{
			Kind: uint8(getInt(m, "kind")),
			Data: getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMPLSConfig converts the JSON-decoded "mpls" sub-map into
// *MPLSConfig. The wire-level fields (labels/multicast) drive the builder's
// label-stack emission; the tunnel-level fields (inner_proto/
// inner_payload/frames/direction) drive the internal/protocol/mpls
// planner's inner-packet construction.
func parseMPLSConfig(m map[string]interface{}) *MPLSConfig {
	if m == nil {
		return nil
	}
	return &MPLSConfig{
		Labels:       parseMPLSLabels(m["labels"]),
		Multicast:    getBool(m, "multicast", false),
		InnerProto:   uint8(getInt(m, "inner_proto")),
		InnerPayload: getByteSlice(m, "inner_payload"),
		Frames:       getInt(m, "frames"),
		Direction:    getString(m, "direction"),
	}
}

// parseMPLSLabels converts the JSON-decoded "labels" list into []MPLSLabel
// (each entry: label + optional tc/s/ttl). The list order is the
// transmission order: entry 0 = top of stack, last entry = bottom of stack
// (S auto-corrected to 1 by the builder).
func parseMPLSLabels(v interface{}) []MPLSLabel {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MPLSLabel, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MPLSLabel{
			Label: uint32(getInt(m, "label")),
			TC:    uint8(getInt(m, "tc")),
			S:     getBool(m, "s", false),
			TTL:   uint8(getInt(m, "ttl")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseGTPConfig converts the JSON-decoded "gtp" sub-map into *GTPConfig.
// The wire-level fields (mode/version/pt/teid/sequence_present/sequence/
// npdu_present/npdu_value/extension_present/extension_type/extension_data)
// drive the GTPv1 message header (TS 29.281 §5.1); the scenario steps
// (scenarios) drive the GTP-C signaling dialog; the tunnel-level fields
// (inner_src_ip/inner_dst_ip/inner_proto/inner_ttl/inner_ipid/
// inner_payload/tcp_options/frames/direction) drive the GTP-U T-PDU inner
// packet construction in internal/protocol/gtp.
func parseGTPConfig(m map[string]interface{}) *GTPConfig {
	if m == nil {
		return nil
	}
	return &GTPConfig{
		Mode:             getString(m, "mode"),
		Version:          uint8(getInt(m, "version")),
		PT:               uint8(getInt(m, "pt")),
		TEID:             getUint32(m, "teid"),
		SequencePresent:  getBool(m, "sequence_present", false),
		Sequence:         getUint16(m, "sequence"),
		NPDUPresent:      getBool(m, "npdu_present", false),
		NPDUValue:        uint8(getInt(m, "npdu_value")),
		ExtensionPresent: getBool(m, "extension_present", false),
		ExtensionType:    uint8(getInt(m, "extension_type")),
		ExtensionData:    getByteSlice(m, "extension_data"),
		Scenarios:        parseGTPSteps(m["scenarios"]),
		InnerSrcIP:       getString(m, "inner_src_ip"),
		InnerDstIP:       getString(m, "inner_dst_ip"),
		InnerProto:       uint8(getInt(m, "inner_proto")),
		InnerTTL:         uint8(getInt(m, "inner_ttl")),
		InnerIPID:        getUint16(m, "inner_ipid"),
		InnerPayload:     getByteSlice(m, "inner_payload"),
		TCPOptions:       parseGREConfigTCPOptions(m["tcp_options"]),
		Frames:           getInt(m, "frames"),
		Direction:        getString(m, "direction"),
	}
}

// parseGTPSteps converts the JSON-decoded "scenarios" list into []GTPStep
// (each entry: message_type + optional teid_override/sequence/direction/
// ies).
func parseGTPSteps(v interface{}) []GTPStep {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GTPStep, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GTPStep{
			MessageType:  uint8(getInt(m, "message_type")),
			TEIDOverride: getUint32Ptr(m, "teid_override"),
			Sequence:     getUint16(m, "sequence"),
			Direction:    getString(m, "direction"),
			IEs:          parseGTPIEs(m["ies"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseGTPIEs converts the JSON-decoded "ies" list into []GTPIE (each
// entry: type + value bytes).
func parseGTPIEs(v interface{}) []GTPIE {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GTPIE, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GTPIE{
			Type:  uint8(getInt(m, "type")),
			Value: getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMDNSConfig converts the JSON-decoded "mdns" sub-map into *MDNSConfig.
func parseMDNSConfig(m map[string]interface{}) *MDNSConfig {
	if m == nil {
		return nil
	}
	cfg := &MDNSConfig{
		Mode:                 getString(m, "mode"),
		Questions:            parseMDNSQuestions(m["questions"]),
		Answers:              parseMDNSResourceRecords(m["answers"]),
		Authorities:          parseMDNSResourceRecords(m["authorities"]),
		Additionals:          parseMDNSResourceRecords(m["additionals"]),
		ProbingRepeat:        getInt(m, "probing_repeat"),
		ProbingInterval:      getInt(m, "probing_interval"),
		ProbingJitterMax:     getInt(m, "probing_jitter_max"),
		ProbingJitterSeed:    int64(getInt(m, "probing_jitter_seed")),
		AnnouncingRepeat:     getInt(m, "announcing_repeat"),
		AnnouncingInterval:   getInt(m, "announcing_interval"),
		ResponseDelay:        getInt(m, "response_delay"),
		MulticastGroup:       getString(m, "multicast_group"),
		ForceUnicastResponse: getBool(m, "force_unicast_response", false),
		CacheFlush:           getBoolPtr(m, "cache_flush"),
		DefaultTTL:           getUint32(m, "default_ttl"),
		TC:                   getBool(m, "tc", false),
	}
	return cfg
}

// parseDNSQuestions converts a JSON-decoded list of "questions" entries
// into []DNSQuestion (RFC 1035 §4.1.2). Each entry must be an object with
// at least name+type; class defaults to IN (1) when omitted.
func parseDNSQuestions(v interface{}) []DNSQuestion {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DNSQuestion, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DNSQuestion{
			Name:  getString(m, "name"),
			Type:  getUint16(m, "type"),
			Class: getUint16(m, "class"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDNSRRs converts a JSON-decoded list of resource-record entries into
// []DNSRR. Supports A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV/NAPTR/DS/DNSKEY by
// reading the type-appropriate fields; see DNSRR docs for the mapping.
func parseDNSRRs(v interface{}) []DNSRR {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DNSRR, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		rr := DNSRR{
			Name:       getString(m, "name"),
			Type:       getUint16(m, "type"),
			Class:      getUint16(m, "class"),
			TTL:        getUint32(m, "ttl"),
			IP:         getString(m, "ip"),
			Target:     getString(m, "target"),
			Preference: getUint16(m, "preference"),
			Text:       getString(m, "text"),
			MName:      getString(m, "mname"),
			RName:      getString(m, "rname"),
			Serial:     getUint32(m, "serial"),
			Refresh:    getUint32(m, "refresh"),
			Retry:      getUint32(m, "retry"),
			Expire:     getUint32(m, "expire"),
			Minimum:    getUint32(m, "minimum"),
			Priority:   getUint16(m, "priority"),
			Weight:     getUint16(m, "weight"),
			Port:       getUint16(m, "port"),
			Order:      getUint16(m, "order"),
			Flags:      getString(m, "flags"),
			Service:    getString(m, "service"),
			Regexp:     getString(m, "regexp"),
			KeyTag:     getUint16(m, "key_tag"),
			Algorithm:  uint8(getInt(m, "algorithm")),
			DigestType: uint8(getInt(m, "digest_type")),
			Digest:     getString(m, "digest"),
			KeyFlags:   getUint16(m, "key_flags"),
			Protocol:   uint8(getInt(m, "protocol")),
			PublicKey:  getString(m, "public_key"),
		}
		out = append(out, rr)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMDNSQuestions(v interface{}) []MDNSQuestion {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MDNSQuestion, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MDNSQuestion{
			Name:  getString(m, "name"),
			Type:  getUint16(m, "type"),
			Class: getUint16(m, "class"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMDNSResourceRecords(v interface{}) []MDNSResourceRecord {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MDNSResourceRecord, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MDNSResourceRecord{
			Name:         getString(m, "name"),
			Type:         getUint16(m, "type"),
			Class:        getUint16(m, "class"),
			TTL:          getUint32(m, "ttl"),
			IPAddress:    getString(m, "ip_address"),
			DomainName:   getString(m, "domain_name"),
			Priority:     getUint16(m, "priority"),
			Weight:       getUint16(m, "weight"),
			Port:         getUint16(m, "port"),
			Target:       getString(m, "target"),
			TXTEntries:   getStringSlice(m, "txt_entries"),
			NSECNextName: getString(m, "nsec_next_name"),
			NSECTypes:    getUint16Slice(m, "nsec_types"),
			RawRDATA:     getByteSlice(m, "raw_rdata"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMySQLConfig converts the JSON-decoded "mysql" sub-map into *MySQLConfig.
func parseMySQLConfig(m map[string]interface{}) *MySQLConfig {
	if m == nil {
		return nil
	}
	cfg := &MySQLConfig{
		ServerVersion:    getString(m, "server_version"),
		ThreadID:         getUint32(m, "thread_id"),
		AuthPlugin:       getString(m, "auth_plugin"),
		Username:         getString(m, "username"),
		Password:         getString(m, "password"),
		Scramble:         getByteSlice(m, "scramble"),
		Database:         getString(m, "database"),
		CapabilityFlags:  getUint32(m, "capability_flags"),
		MaxPacketSize:    getUint32(m, "max_packet_size"),
		CharacterSet:     uint8(getInt(m, "character_set")),
		Commands:         parseMySQLCommands(m["commands"]),
		ServerBypassAuth: getBool(m, "server_bypass_auth", false),
	}
	return cfg
}

func parseMySQLCommands(v interface{}) []MySQLCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		cmd := MySQLCommand{
			Opcode:         uint8(getInt(m, "opcode")),
			Body:           getString(m, "body"),
			BodyEncoding:   getString(m, "body_encoding"),
			ReplyMode:      getString(m, "reply_mode"),
			ReplyBytes:     getString(m, "reply_bytes"),
			ReplyEncoding:  getString(m, "reply_encoding"),
			ColDefs:        parseMySQLColDefs(m["col_defs"]),
			Rows:           parseMySQLRows(m["rows"]),
			StmtID:         getUint32(m, "stmt_id"),
			IterationCount: getUint32(m, "iteration_count"),
			EmitOkExtended: getBool(m, "emit_ok_extended", false),
			Params:         parseMySQLColDefs(m["params"]),
			WarningCount:   getUint16(m, "warning_count"),
			ErrCode:        getUint16(m, "err_code"),
			ErrSQLState:    getString(m, "err_sqlstate"),
			ErrMessage:     getString(m, "err_message"),
			AffectedRows:   getUint64(m, "affected_rows"),
			LastInsertID:   getUint64(m, "last_insert_id"),
			StatusFlags:    getUint16(m, "status_flags"),
			Warnings:       getUint16(m, "warnings"),
			StmtFlags:      uint8(getInt(m, "stmt_flags")),
			StmtParams:     parseMySQLStmtParams(m["stmt_params"]),
		}
		out = append(out, cmd)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMySQLColDefs(v interface{}) []MySQLColDef {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLColDef, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MySQLColDef{
			Catalog:  getString(m, "catalog"),
			Schema:   getString(m, "schema"),
			Table:    getString(m, "table"),
			OrgTable: getString(m, "org_table"),
			Name:     getString(m, "name"),
			OrgName:  getString(m, "org_name"),
			Charset:  getUint16(m, "charset"),
			Length:   getUint32(m, "length"),
			Type:     uint8(getInt(m, "type")),
			Flags:    getUint16(m, "flags"),
			Decimals: uint8(getInt(m, "decimals")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMySQLRows(v interface{}) []MySQLRow {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLRow, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		row := MySQLRow{
			Values:        getStringSlice(m, "values"),
			ValueEncoding: getString(m, "value_encoding"),
		}
		// is_null is a parallel bool array
		if nulls, ok := m["is_null"].([]interface{}); ok {
			for _, n := range nulls {
				if b, ok := n.(bool); ok {
					row.IsNull = append(row.IsNull, b)
				}
			}
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseOpenVPNConfig converts the JSON-decoded "openvpn" sub-map into *OpenVPNConfig.
func parseOpenVPNConfig(m map[string]interface{}) *OpenVPNConfig {
	if m == nil {
		return nil
	}
	cfg := &OpenVPNConfig{
		Proto:                 getString(m, "proto"),
		Version:               getString(m, "version"),
		KeyID:                 uint8(getInt(m, "key_id")),
		SessionID:             getUint64(m, "session_id"),
		TLSAuth:               getBool(m, "tls_auth", false),
		TLSCrypt:              getBool(m, "tls_crypt", false),
		TLSCryptV2:            getBool(m, "tls_crypt_v2", false),
		DataCipher:            getString(m, "data_cipher"),
		NCPDisable:            getBool(m, "ncp_disable", false),
		TLSVersion:            getString(m, "tls_version"),
		TLSRole:               getString(m, "tls_role"),
		SNI:                   getString(m, "sni"),
		Mssfix:                getUint16(m, "mssfix"),
		TLSAuthHMAC:           getByteSlice(m, "tls_auth_hmac"),
		TLSCryptWrappedKey:    getByteSlice(m, "tls_crypt_wrapped_key"),
		DataPayload:           getByteSlice(m, "data_payload"),
		DataPacketCount:       getInt(m, "data_packet_count"),
		PerformSoftReset:      getBool(m, "perform_soft_reset", false),
		StaticKeyMode:         getBool(m, "static_key_mode", false),
		KeyDirection:          uint8(getInt(m, "key_direction")),
		StaticKey:             getByteSlice(m, "static_key"),
		AuthUserPass:          getBool(m, "auth_user_pass", false),
		AuthUser:              getString(m, "auth_user"),
		AuthPass:              getString(m, "auth_pass"),
		AuthAlg:               getString(m, "auth_alg"),
		FragmentSize:          getUint16(m, "fragment_size"),
		KeepalivePingInterval: getUint16(m, "keepalive_ping"),
		KeepalivePingRestart:  getUint16(m, "keepalive_ping_restart"),
		ExitNotifyCount:       uint8(getInt(m, "exit_notify_count")),
		ExitNotifyInterval:    getUint16(m, "exit_notify_interval"),
		TunMTU:                getUint16(m, "tun_mtu"),
		InnerIPPackets:        parseOpenVPNInnerIPPackets(m["inner_ip_packets"]),
	}
	return cfg
}

// parseOpenVPNInnerIPPackets converts the JSON-decoded "inner_ip_packets"
// array into []OpenVPNInnerIP. Each entry describes a complete inner IPv4/IPv6
// packet carried inside a P_DATA_V2 as the encrypted data-channel payload.
func parseOpenVPNInnerIPPackets(v interface{}) []OpenVPNInnerIP {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]OpenVPNInnerIP, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, OpenVPNInnerIP{
			SrcIP:   getString(m, "src_ip"),
			DstIP:   getString(m, "dst_ip"),
			Proto:   uint8(getInt(m, "proto")),
			SrcPort: getUint16(m, "src_port"),
			DstPort: getUint16(m, "dst_port"),
			TTL:     uint8(getInt(m, "ttl")),
			Payload: getByteSlice(m, "payload"),
		})
	}
	return out
}

// parsePostgreSQLConfig converts the JSON-decoded "postgresql" sub-map into
// *PostgreSQLConfig.
func parsePostgreSQLConfig(m map[string]interface{}) *PostgreSQLConfig {
	if m == nil {
		return nil
	}
	// ColumnTypes has int->int32 map; we need to fetch values from JSON map
	var colTypes map[int]int32
	if v, ok := m["column_types"].(map[string]interface{}); ok && len(v) > 0 {
		colTypes = make(map[int]int32, len(v))
		for k, val := range v {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
				continue
			}
			switch n := val.(type) {
			case float64:
				colTypes[idx] = int32(n)
			case json.Number:
				if j, err := n.Int64(); err == nil {
					colTypes[idx] = int32(j)
				}
			}
		}
	}
	cfg := &PostgreSQLConfig{
		ProtocolVersion:     int32(getInt(m, "protocol_version")),
		StartupParams:       getStringMap(m, "startup_params"),
		AuthMethod:          getString(m, "auth_method"),
		Username:            getString(m, "username"),
		Password:            getString(m, "password"),
		MD5Salt:             getByteSlice(m, "md5_salt"),
		Operations:          parsePGOperations(m["operations"]),
		Pipeline:            getBool(m, "pipeline", false),
		RowCount:            getInt(m, "row_count"),
		ColumnTypes:         colTypes,
		NotificationPayload: getString(m, "notification_payload"),
		WALDataSize:         getInt(m, "wal_data_size"),
		EmitHandshake:       getBoolPtr(m, "emit_handshake"),
		EmitTeardown:        getBoolPtr(m, "emit_teardown"),
		Dialect:             getString(m, "dialect"),
		WireProfile:         getString(m, "wire_profile"),
		Events:              parsePostgreSQLEvents(m["events"]),
		Sessions:            parsePostgreSQLSessions(m["sessions"]),
		WireFault:           rawMessageFrom(m, "wire_fault"),
	}
	return cfg
}

// parsePostgreSQLEvents converts the JSON-decoded "events" value (an array of
// {kind, direction, profile, authtype, name, value, pid, secret, sql, tag, ...}
// objects) into a []PostgreSQLEvent for the shared postgresql layer's
// event-driven generator. Returns nil for absent/non-array input.
func parsePostgreSQLEvents(v interface{}) []PostgreSQLEvent {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PostgreSQLEvent, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ev := PostgreSQLEvent{
			Kind:      getString(m, "kind"),
			Direction: getString(m, "direction"),
			Profile:   getString(m, "profile"),
			User:      getString(m, "user"),
			Database:  getString(m, "database"),
			Result:    getString(m, "result"),
			SQL:       getString(m, "sql"),
			Tag:       getString(m, "tag"),
			Name:      getString(m, "name"),
			Value:     getString(m, "value"),
			PID:       int32(getInt(m, "pid")),
			Secret:    int32(getInt(m, "secret")),
		}
		if _, ok := m["authtype"]; ok {
			at := int32(getInt(m, "authtype"))
			ev.Authtype = &at
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePostgreSQLSessions converts the JSON-decoded "sessions" value (an array
// of {src_port, events} objects) into a []PostgreSQLSession. Returns nil for
// absent/non-array input.
func parsePostgreSQLSessions(v interface{}) []PostgreSQLSession {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PostgreSQLSession, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		evs := parsePostgreSQLEvents(m["events"])
		out = append(out, PostgreSQLSession{
			SrcPort: uint16(getInt(m, "src_port")),
			Events:  evs,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rawMessageFrom extracts a json.RawMessage from m[key] when present (map or
// raw JSON string). Returns nil when absent/null.
func rawMessageFrom(m map[string]interface{}, key string) json.RawMessage {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		if b, err := json.Marshal(val); err == nil {
			return b
		}
	case string:
		if val != "" {
			return json.RawMessage(val)
		}
	case json.RawMessage:
		return val
	}
	return nil
}

func parsePGOperations(v interface{}) []PGOperation {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PGOperation, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		op := PGOperation{
			Kind:             getString(m, "kind"),
			SQL:              getString(m, "sql"),
			Statement:        getString(m, "statement"),
			Portal:           getString(m, "portal"),
			Mode:             getString(m, "mode"),
			MaxRows:          int32(getInt(m, "max_rows")),
			ParamCount:       getInt(m, "param_count"),
			ParamValues:      getStringSlice(m, "param_values"),
			Channel:          getString(m, "channel"),
			CopyData:         getStringSlice(m, "copy_data"),
			ReplicationSlot:  getString(m, "replication_slot"),
			ReplicationLSN:   getString(m, "replication_lsn"),
			ReplicationKind:  getString(m, "replication_kind"),
			EmitAsServer:     getBool(m, "emit_as_server", false),
			NotifyChannel:    getString(m, "notify_channel"),
			NotifyPayload:    getString(m, "notify_payload"),
			FunctionOID:      int32(getInt(m, "function_oid")),
			ResultFormatCode: int16(getInt(m, "result_format_code")),
			ErrorFields:      parsePGErrorFields(m["error_fields"]),
			ExpectNoData:     getBool(m, "expect_no_data", false),
			ErrorSegment:     getInt(m, "error_segment"),
		}
		// ArgumentFormatCodes is int16 slice
		if arr, ok := m["argument_format_codes"].([]interface{}); ok {
			for _, c := range arr {
				switch n := c.(type) {
				case float64:
					op.ArgumentFormatCodes = append(op.ArgumentFormatCodes, int16(n))
				case json.Number:
					if j, err := n.Int64(); err == nil {
						op.ArgumentFormatCodes = append(op.ArgumentFormatCodes, int16(j))
					}
				}
			}
		}
		out = append(out, op)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePGErrorFields converts the JSON-decoded "error_fields" array into
// []PGErrorField. Each entry is a {type, value} pair where type is a
// 1-byte ASCII letter (e.g. 'V', 'C', 'M') and value is the C-string text.
func parsePGErrorFields(v interface{}) []PGErrorField {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PGErrorField, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		f := PGErrorField{
			Value: getString(m, "value"),
		}
		// Type is a single byte; accept either an int or a 1-char string.
		switch t := m["type"].(type) {
		case float64:
			f.Type = byte(uint8(t))
		case json.Number:
			if j, err := t.Int64(); err == nil {
				f.Type = byte(uint8(j))
			}
		case string:
			if len(t) > 0 {
				f.Type = t[0]
			}
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRDPConfig converts the JSON-decoded "rdp" sub-map into *RDPConfig.
func parseRDPConfig(m map[string]interface{}) *RDPConfig {
	if m == nil {
		return nil
	}
	cfg := &RDPConfig{
		SecurityLayer:               getString(m, "security_layer"),
		RequestedProtocols:          getUint32(m, "requested_protocols"),
		RestrictedAdmin:             getBool(m, "restricted_admin", false),
		RedirectedAuth:              getBool(m, "redirected_auth", false),
		Cookie:                      getString(m, "cookie"),
		ClientName:                  getString(m, "client_name"),
		ClientBuild:                 getUint32(m, "client_build"),
		KeyboardLayout:              getUint32(m, "keyboard_layout"),
		KeyboardType:                getUint32(m, "keyboard_type"),
		KeyboardSubType:             getUint32(m, "keyboard_sub_type"),
		KeyboardFunctionKey:         getUint32(m, "keyboard_function_key"),
		DesktopWidth:                getUint16(m, "desktop_width"),
		DesktopHeight:               getUint16(m, "desktop_height"),
		ColorDepth:                  getUint16(m, "color_depth"),
		HighColorDepth:              getUint16(m, "high_color_depth"),
		SupportedColorDepths:        getUint16(m, "supported_color_depths"),
		ConnectionType:              uint8(getInt(m, "connection_type")),
		ServerSelectedProtocol:      getUint32(m, "server_selected_protocol"),
		EncryptionMethods:           getUint32(m, "encryption_methods"),
		ExtEncryptionMethods:        getUint32(m, "ext_encryption_methods"),
		Domain:                      getString(m, "domain"),
		UserName:                    getString(m, "user_name"),
		Password:                    getString(m, "password"),
		AlternateShell:              getString(m, "alternate_shell"),
		WorkingDir:                  getString(m, "working_dir"),
		Channels:                    parseRDPChannels(m["channels"]),
		AutoLogon:                   getBool(m, "auto_logon", false),
		InfoUnicode:                 getBool(m, "info_unicode", false),
		InfoLogonNotify:             getBool(m, "info_logon_notify", false),
		InfoCompression:             getBool(m, "info_compression", false),
		CodePage:                    getUint32(m, "code_page"),
		Flags2:                      getUint16(m, "flags2"),
		SkipMCSChannelJoin:          getBool(m, "skip_mcs_channel_join", false),
		SkipSecurityExchange:        getBool(m, "skip_security_exchange", false),
		SkipLicense:                 getBool(m, "skip_license", false),
		SkipCapability:              getBool(m, "skip_capability", false),
		ForceRDPVersion:             getUint32(m, "force_rdp_version"),
		EncryptionLevel:             getUint32(m, "encryption_level"),
		EncryptionMethod:            getUint32(m, "encryption_method"),
		ServerRandom:                getByteSlice(m, "server_random"),
		ServerCertVersion:           getUint32(m, "server_cert_version"),
		SecurityExchangeRSAKeyBytes: getInt(m, "security_exchange_rsa_key_bytes"),
		Scenario:                    getString(m, "scenario"),
		DataEvents:                  parseRDPDataEvents(m["data_events"]),
		ServerResponses:             parseRDPServerResponses(m["server_responses"]),
	}
	return cfg
}

func parseRDPChannels(v interface{}) []RDPChannel {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPChannel, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RDPChannel{
			Name:    getString(m, "name"),
			Options: getUint32(m, "options"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRDPDataEvents(v interface{}) []RDPDataEvent {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPDataEvent, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ev := RDPDataEvent{
			Type:       getString(m, "type"),
			Channel:    getString(m, "channel"),
			Direction:  getString(m, "direction"),
			Payload:    getByteSlice(m, "payload"),
			PayloadB64: getString(m, "payload_b64"),
		}
		// Decode base64 payload if provided
		if ev.Payload == nil && ev.PayloadB64 != "" {
			if b, err := decodeBase64(ev.PayloadB64); err == nil {
				ev.Payload = b
			}
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRDPServerResponses(v interface{}) []RDPServerResponse {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPServerResponse, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RDPServerResponse{
			Type:    getString(m, "type"),
			Payload: getByteSlice(m, "payload"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRedisConfig converts the JSON-decoded "redis" sub-map into *RedisConfig.
func parseRedisConfig(m map[string]interface{}) *RedisConfig {
	if m == nil {
		return nil
	}
	cfg := &RedisConfig{
		Version:           getInt(m, "version"),
		SkipHello:         getBool(m, "skip_hello", false),
		Username:          getString(m, "username"),
		Password:          getString(m, "password"),
		SelectDB:          getInt(m, "select_db"),
		ClientName:        getString(m, "client_name"),
		Commands:          parseRedisCommands(m["commands"]),
		SubscribeTo:       getStringSlice(m, "subscribe_to"),
		SubscribePatterns: getStringSlice(m, "subscribe_patterns"),
		PublishMessages:   parseRedisPublish(m["publish_messages"]),
		PipelineSize:      getInt(m, "pipeline_size"),
	}
	return cfg
}

func parseRedisCommands(v interface{}) []RedisCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RedisCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RedisCommand{
			Args:       getStringSlice(m, "args"),
			ArgsBase64: getStringSlice(m, "args_base64"),
			Reply:      getString(m, "reply"),
			AutoReply:  getString(m, "auto_reply"),
			EmitAsPush: getBool(m, "emit_as_push", false),
			Channel:    getString(m, "channel"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRedisPublish(v interface{}) []RedisPublish {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RedisPublish, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RedisPublish{
			Channel:    getString(m, "channel"),
			Message:    getString(m, "message"),
			MessageB64: getString(m, "message_b64"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseShadowsocksConfig converts the JSON-decoded "shadowsocks" sub-map
// into *ShadowsocksConfig.
func parseShadowsocksConfig(m map[string]interface{}) *ShadowsocksConfig {
	if m == nil {
		return nil
	}
	cfg := &ShadowsocksConfig{
		Mode:               getString(m, "mode"),
		Cipher:             getString(m, "cipher"),
		SOCKS5Handshake:    getBool(m, "socks5_handshake", false),
		SOCKS5AuthMethod:   getString(m, "socks5_auth_method"),
		SOCKS5Username:     getString(m, "socks5_username"),
		SOCKS5Password:     getString(m, "socks5_password"),
		SOCKS5Cmd:          getString(m, "socks5_cmd"),
		SOCKS5DstAddr:      getString(m, "socks5_dst_addr"),
		SOCKS5DstPort:      getUint16(m, "socks5_dst_port"),
		SOCKS5BNDAddr:      getString(m, "socks5_bnd_addr"),
		SOCKS5BNDPort:      getUint16(m, "socks5_bnd_port"),
		Chunks:             getInt(m, "chunks"),
		ChunkPayloadSize:   getInt(m, "chunk_payload_size"),
		Obfuscation:        getString(m, "obfuscation"),
		ObfMethod:          getString(m, "obf_method"),
		ObfHeaders:         getStringMap(m, "obf_headers"),
		PayloadBytesFormat: getString(m, "payload_bytes_format"),
		FRAG:               uint8(getInt(m, "frag")),
		FileSource:         parseFileSourceField(m),
	}
	return cfg
}

// parseSocks5Config converts the JSON-decoded "socks" sub-map into
// *SocksConfig.
func parseSocks5Config(m map[string]interface{}) *SocksConfig {
	if m == nil {
		return nil
	}
	cfg := &SocksConfig{
		Version:    getString(m, "version"),
		AuthMethod: getString(m, "auth_method"),
		Username:   getString(m, "username"),
		Password:   getString(m, "password"),
		Cmd:        getString(m, "cmd"),
		DstAddr:    getString(m, "dst_addr"),
		DstPort:    getUint16(m, "dst_port"),
		Rep:        getInt(m, "rep"),
		BndAddr:    getString(m, "bnd_addr"),
		BndPort:    getUint16(m, "bnd_port"),
		UserID:     getString(m, "user_id"),
		Data:       parseSocksDataMessages(m["data"]),
	}
	if sub, ok := m["udp"].(map[string]interface{}); ok && sub != nil {
		cfg.UDP = &Socks5UDP{
			SrcPort:   getUint16(sub, "src_port"),
			DstPort:   getUint16(sub, "dst_port"),
			Frames:    getInt(sub, "frames"),
			FrameSize: getInt(sub, "frame_size"),
			DstAddr:   getString(sub, "dst_addr"),
			Direction: getString(sub, "direction"),
		}
	}
	return cfg
}

// parseSocksDataMessages converts the JSON-decoded "data" array into
// []SocksDataMessage. Each element's FileSource is parsed inline (SCTP
// chunk pattern) so index aliasing is impossible.
func parseSocksDataMessages(v interface{}) []SocksDataMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SocksDataMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, SocksDataMessage{
			Direction:  getString(m, "direction"),
			Payload:    getString(m, "payload"),
			FileSource: parseFileSourceField(m),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseRTMPConfigFromMap exports parseRTMPConfig for the layer-translate
// path (parse helpers are package-local; ParseLDAPConfigFromMap precedent).
func ParseRTMPConfigFromMap(m map[string]interface{}) *RTMPConfig {
	return parseRTMPConfig(m)
}

// parseRTMPConfig converts the JSON-decoded "rtmp" sub-map into *RTMPConfig.
// RTMP (Adobe Real-Time Messaging Protocol) 配置解析.
// 空/缺失 map 返回 nil — 与 socks5/radius/vnc 模式一致.
func parseRTMPConfig(m map[string]interface{}) *RTMPConfig {
	if m == nil {
		return nil
	}
	cfg := &RTMPConfig{
		App:        getString(m, "app"),
		TcURL:      getString(m, "tc_url"),
		Command:    getString(m, "command"),
		StreamName: getString(m, "stream_name"),
	}
	// Parse data plane chunks (数据面 chunk 列表).
	if data, ok := m["data"]; ok {
		if arr, ok := data.([]interface{}); ok {
			for _, item := range arr {
				chunk, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				dc := RTMPDataChunk{
					Direction:     getString(chunk, "direction"),
					MsgType:       uint8(getInt(chunk, "msg_type")),
					ChunkStreamID: uint8(getInt(chunk, "chunk_stream_id")),
				}
				// Payload: support both base64 (payload_b64) and raw string (payload).
				if b64 := getString(chunk, "payload_b64"); b64 != "" {
					if decoded, err := decodeBase64(b64); err == nil {
						dc.Payload = decoded
					}
				} else if raw := getString(chunk, "payload"); raw != "" {
					dc.Payload = []byte(raw)
				}
				cfg.Data = append(cfg.Data, dc)
			}
		}
	}
	return cfg
}

// parseRadiusConfig converts the JSON-decoded "radius" sub-map into
// *RadiusConfig. Attributes and response attributes are parsed with
// parseRadiusAttributes (index-safe, no aliasing).
func parseRadiusConfig(m map[string]interface{}) *RadiusConfig {
	if m == nil {
		return nil
	}
	cfg := &RadiusConfig{
		Code:               getInt(m, "code"),
		Identifier:         uint8(getInt(m, "identifier")),
		Authenticator:      getString(m, "authenticator"),
		Attributes:         parseRadiusAttributes(m["attributes"]),
		ResponseCode:       uint8(getInt(m, "response_code")),
		ResponseAttributes: parseRadiusAttributes(m["response_attributes"]),
		Rounds:             getInt(m, "rounds"),
	}
	return cfg
}

// parseRadiusAttributes converts the JSON-decoded attribute array into
// []RadiusAttribute.
func parseRadiusAttributes(v interface{}) []RadiusAttribute {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RadiusAttribute, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RadiusAttribute{
			Type:     uint8(getInt(m, "type")),
			Format:   getString(m, "format"),
			Value:    getString(m, "value"),
			VendorID: uint32(getInt(m, "vendor_id")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMQTTConfig converts the JSON-decoded "mqtt" sub-map into *MQTTConfig.
// Pointer fields (KeepAlive *int, CleanSession *bool, Disconnect *bool) use
// presence-check so explicit 0/false is honored rather than replaced with the
// default. Slice fields (Messages/Subscriptions/Properties/Will) parse to nil
// when absent so the planner can distinguish "omitted" from "empty".
func parseMQTTConfig(m map[string]interface{}) *MQTTConfig {
	if m == nil {
		return nil
	}
	cfg := &MQTTConfig{
		Version:                  getInt(m, "version"),
		ClientID:                 getString(m, "client_id"),
		Username:                 getString(m, "username"),
		Password:                 getString(m, "password"),
		ConnectAckCode:           getInt(m, "connect_ack_code"),
		ConnectAckSessionPresent: getBool(m, "connect_ack_session_present", false),
		PingAfterMessages:        getBool(m, "ping_after_messages", false),
		Subscriptions:            parseMQTTSubscriptions(m["subscriptions"]),
		Messages:                 parseMQTTMessages(m["messages"]),
		Properties:               parseMQTTProperties(m["properties"]),
		ConnackProperties:        parseMQTTProperties(m["connack_properties"]),
		Sessions:                 parseMQTTSessions(m["sessions"]),
	}
	if v, ok := m["keep_alive"]; ok && v != nil {
		n := getInt(m, "keep_alive")
		cfg.KeepAlive = &n
	}
	if v, ok := m["clean_session"].(bool); ok {
		b := v
		cfg.CleanSession = &b
	}
	if v, ok := m["disconnect"].(bool); ok {
		b := v
		cfg.Disconnect = &b
	}
	if v, ok := m["disconnect_reason"]; ok && v != nil {
		n := getInt(m, "disconnect_reason")
		cfg.DisconnectReason = &n
	}
	if sub, ok := m["will"].(map[string]interface{}); ok && sub != nil {
		cfg.Will = parseMQTTWill(sub)
	}
	return cfg
}

// parseMQTTWill converts the JSON-decoded "will" sub-map into *MQTTWill.
func parseMQTTWill(m map[string]interface{}) *MQTTWill {
	if m == nil {
		return nil
	}
	return &MQTTWill{
		Topic:         getString(m, "topic"),
		Payload:       getString(m, "payload"),
		QoS:           getInt(m, "qos"),
		Retain:        getBool(m, "retain", false),
		DelayInterval: getInt(m, "delay_interval"),
	}
}

// parseMQTTMessages converts the JSON-decoded "messages" array into
// []MQTTMessage.
func parseMQTTMessages(v interface{}) []MQTTMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MQTTMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MQTTMessage{
			Topic:      getString(m, "topic"),
			Payload:    getString(m, "payload"),
			QoS:        getInt(m, "qos"),
			Retain:     getBool(m, "retain", false),
			DUP:        getBool(m, "dup", false),
			PacketID:   uint16(getInt(m, "packet_id")),
			Direction:  getString(m, "direction"),
			Properties: parseMQTTProperties(m["properties"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMQTTSubscriptions converts the JSON-decoded "subscriptions" array
// into []MQTTSubscribe.
func parseMQTTSubscriptions(v interface{}) []MQTTSubscribe {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MQTTSubscribe, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		sub := MQTTSubscribe{
			PacketID:       uint16(getInt(m, "packet_id")),
			Filters:        parseMQTTTopicFilters(m["filters"]),
			AckReasonCodes: parseIntList(m["ack_reason_codes"]),
			Properties:     parseMQTTProperties(m["properties"]),
		}
		out = append(out, sub)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMQTTTopicFilters converts the JSON-decoded "filters" array into
// []MQTTTopicFilter.
func parseMQTTTopicFilters(v interface{}) []MQTTTopicFilter {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MQTTTopicFilter, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MQTTTopicFilter{
			Filter:            getString(m, "filter"),
			QoS:               getInt(m, "qos"),
			NoLocal:           getBool(m, "no_local", false),
			RetainAsPublished: getBool(m, "retain_as_published", false),
			RetainHandling:    getInt(m, "retain_handling"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMQTTProperties converts the JSON-decoded "properties" array into
// []MQTTProperty.
func parseMQTTProperties(v interface{}) []MQTTProperty {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MQTTProperty, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MQTTProperty{
			Identifier: getInt(m, "identifier"),
			Format:     getString(m, "format"),
			Value:      getString(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMQTTSessions converts the JSON-decoded "sessions" array into
// []MQTTSession. Inherits pointer-field semantics from parseMQTTConfig.
func parseMQTTSessions(v interface{}) []MQTTSession {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MQTTSession, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		s := MQTTSession{
			ClientID: getString(m, "client_id"),
			Username: getString(m, "username"),
			Password: getString(m, "password"),
			// Bug fix: PingAfterMessages is now *bool on MQTTSession so a
			// session can explicitly override top-level true→false. nil
			// means "inherit" (do not pass a default), so use getBoolPtr
			// instead of getBool.
			PingAfterMessages: getBoolPtr(m, "ping_after_messages"),
			Subscriptions:     parseMQTTSubscriptions(m["subscriptions"]),
			Messages:          parseMQTTMessages(m["messages"]),
			Properties:        parseMQTTProperties(m["properties"]),
			SrcPort:           uint16(getInt(m, "src_port")),
			DstPort:           uint16(getInt(m, "dst_port")),
		}
		if v, ok := m["keep_alive"]; ok && v != nil {
			n := getInt(m, "keep_alive")
			s.KeepAlive = &n
		}
		if v, ok := m["clean_session"].(bool); ok {
			b := v
			s.CleanSession = &b
		}
		if v, ok := m["disconnect"].(bool); ok {
			b := v
			s.Disconnect = &b
		}
		// Bug fix: session-level disconnect_reason was silently dropped, so a
		// session override never reached the planner's whitelist check.
		// Same pattern as the top-level field: nil means "inherit".
		if v, ok := m["disconnect_reason"]; ok && v != nil {
			n := getInt(m, "disconnect_reason")
			s.DisconnectReason = &n
		}
		if sub, ok := m["will"].(map[string]interface{}); ok && sub != nil {
			s.Will = parseMQTTWill(sub)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIntList converts the JSON-decoded array into []int (used for
// AckReasonCodes).
func parseIntList(v interface{}) []int {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, int(n))
		case json.Number:
			i, err := n.Int64()
			if err == nil {
				out = append(out, int(i))
			}
		case int:
			out = append(out, n)
		case int64:
			out = append(out, int(n))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseLDAPConfig converts the JSON-decoded "ldap" sub-map into
// *LDAPConfig. Unbind defaults to true (send unbindRequest at session
// end); the planner treats nil as true, false as skip.
// ParseLDAPConfigFromMap exports parseLDAPConfig for the layer-translate
// path (parse helpers are package-local; ParsePPPoEConfigFromMap precedent).
func ParseLDAPConfigFromMap(m map[string]interface{}) *LDAPConfig {
	return parseLDAPConfig(m)
}

func parseLDAPConfig(m map[string]interface{}) *LDAPConfig {
	if m == nil {
		return nil
	}
	cfg := &LDAPConfig{
		Rounds:        getInt(m, "rounds"),
		MessageIDBase: uint16(getInt(m, "message_id_base")),
		Version:       getInt(m, "version"),
		BindDN:        getString(m, "bind_dn"),
		BindPassword:  getString(m, "bind_password"),
		SearchBaseDN:  getString(m, "search_base_dn"),
		SearchScope:   getInt(m, "search_scope"),
		SizeLimit:     getInt(m, "size_limit"),
		TimeLimit:     getInt(m, "time_limit"),
		FilterType:    getString(m, "filter_type"),
		SearchFilter:  getString(m, "search_filter"),
		FilterValue:   getString(m, "filter_value"),
		Attributes:    parseStringList(m["attributes"]),
		ResultCode:    uint8(getInt(m, "result_code")),
	}
	if b, ok := m["unbind"].(bool); ok {
		v := b
		cfg.Unbind = &v
	}
	return cfg
}

// parseVNCConfig converts the JSON-decoded "vnc" sub-map into *VNCConfig.
// Design defaults are applied at parse time via getIntPresence, which keeps
// explicit 0 values intact so Validate can reject them (e.g. security_type=0,
// width=0) and the planner can emit them (e.g. pointer_x=0). nil pointers and
// nil lists mean "use the structural default" (the planner applies them).
//
// Parse-level errors (e.g. non-numeric encodings entries) are returned so
// the "vnc" case can append them to spec.ValidationErrors and fail the task
// loudly - getInt would silently coerce "abc" to 0.
func parseVNCConfig(m map[string]interface{}) (*VNCConfig, []string) {
	if m == nil {
		return nil, nil
	}
	var errs []string
	cfg := &VNCConfig{
		SecurityType:         getIntPresence(m, "security_type", 16),
		AuthResult:           getInt(m, "auth_result"),
		AuthReason:           getString(m, "auth_reason"),
		ShareDesktop:         getBoolPtr(m, "share_desktop"),
		Width:                getIntPresence(m, "width", 1024),
		Height:               getIntPresence(m, "height", 768),
		ServerName:           getStringDefault(m, "server_name", "QTMS:1 (ykaul)"),
		Rounds:               getIntPresence(m, "rounds", 1),
		PointerX:             getIntPresence(m, "pointer_x", 507),
		PointerY:             getIntPresence(m, "pointer_y", 320),
		PointerButton:        getInt(m, "pointer_button"),
		FBUUpdateInterval:    getIntPresence(m, "fbu_update_interval", 1),
		ClientSetPixelFormat: getBoolPtr(m, "client_set_pixel_format"),
		ClientSetEncodings:   getBoolPtr(m, "client_set_encodings"),
		Bell:                 getBool(m, "bell", false),
		ServerCutText:        getString(m, "server_cut_text"),
		ClientCutText:        getString(m, "client_cut_text"),
		ChallengeSeed:        getUint64(m, "challenge_seed"),
		ResponseSeed:         getUint64(m, "response_seed"),
	}
	if pm, ok := m["pixel_format"].(map[string]interface{}); ok {
		cfg.PixelFormat = &VNCPixelFormatConfig{
			BitsPerPixel: getIntPresence(pm, "bits_per_pixel", 32),
			Depth:        getIntPresence(pm, "depth", 24),
			BigEndian:    getBool(pm, "big_endian", false),
			TrueColor:    getBool(pm, "true_color", true),
			RedMax:       getIntPresence(pm, "red_max", 255),
			GreenMax:     getIntPresence(pm, "green_max", 255),
			BlueMax:      getIntPresence(pm, "blue_max", 255),
			RedShift:     getIntPresence(pm, "red_shift", 16),
			GreenShift:   getIntPresence(pm, "green_shift", 8),
			BlueShift:    getInt(pm, "blue_shift"),
		}
	}
	if cm, ok := m["interaction_caps"].(map[string]interface{}); ok {
		ic := &VNCInteractionCapsConfig{
			ServerMsgTypes: getInt(cm, "server_msg_types"),
			ClientMsgTypes: getIntPresence(cm, "client_msg_types", 11),
			EncodingTypes:  getInt(cm, "encoding_types"),
		}
		if v, ok := cm["caps"]; ok {
			if arr, ok := v.([]interface{}); ok {
				caps := make([]VNCCapabilityConfig, 0, len(arr))
				for _, item := range arr {
					capm, ok := item.(map[string]interface{})
					if !ok {
						continue
					}
					caps = append(caps, VNCCapabilityConfig{
						Code:   getInt(capm, "code"),
						Vendor: getString(capm, "vendor"),
						Name:   getString(capm, "name"),
					})
				}
				ic.Caps = caps
			}
		}
		cfg.InteractionCaps = ic
	}
	if v, ok := m["key_events"]; ok {
		if arr, ok := v.([]interface{}); ok {
			list := make([]VNCKeyEventConfig, 0, len(arr))
			for _, item := range arr {
				km, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				list = append(list, VNCKeyEventConfig{
					Down: getBool(km, "down", false),
					Key:  getInt(km, "key"),
				})
			}
			cfg.KeyEvents = list
		}
	}
	if v, ok := m["encodings"]; ok {
		arr, ok := v.([]interface{})
		if !ok {
			errs = append(errs, fmt.Sprintf("invalid vnc encoding list %v", v))
		} else {
			list := make([]int, 0, len(arr))
			for _, item := range arr {
				n, ok := numToInt(item)
				if !ok {
					errs = append(errs, fmt.Sprintf("invalid vnc encoding %v", item))
					continue
				}
				list = append(list, n)
			}
			cfg.Encodings = list
		}
	}
	if v, ok := m["initial_fbu"]; ok {
		cfg.InitialFBU = parseVNCRects(v)
	}
	if v, ok := m["update_rects"]; ok {
		cfg.UpdateRects = parseVNCRects(v)
	}
	if sm, ok := m["set_colour_map_entries"].(map[string]interface{}); ok {
		cfg.SetColourMapEntries = &VNCColourMapConfig{
			First:  getInt(sm, "first"),
			Colors: parseStringList(sm["colors"]),
		}
	}
	return cfg, errs
}

// getIntPresence reads an int when the key is present (even 0) and returns
// def when absent. Unlike getIntDefault, an explicit 0 is preserved so
// validators can reject it and planners can emit it.
func getIntPresence(m map[string]interface{}, key string, def int) int {
	if _, ok := m[key]; ok {
		return getInt(m, key)
	}
	return def
}

// parseVNCRects converts a JSON array of rect sub-maps into []VNCRectConfig.
func parseVNCRects(v interface{}) []VNCRectConfig {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]VNCRectConfig, 0, len(arr))
	for _, item := range arr {
		rm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, VNCRectConfig{
			X:               getInt(rm, "x"),
			Y:               getInt(rm, "y"),
			Width:           getInt(rm, "width"),
			Height:          getInt(rm, "height"),
			Encoding:        getString(rm, "encoding"),
			HextileTileData: getString(rm, "hextile_tile_data"),
			XCursorBlob:     getString(rm, "xcursor_blob"),
		})
	}
	return out
}

// numToInt converts a JSON-decoded numeric value to int. Returns false for
// non-numeric values (strings, bools, nested structures) so callers can
// report parse-level errors instead of silently coercing to 0.
func numToInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}

// parseStringList converts a JSON string array into []string.
func parseStringList(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSSDPConfig converts the JSON-decoded "ssdp" sub-map into *SSDPConfig.
func parseSSDPConfig(m map[string]interface{}) *SSDPConfig {
	if m == nil {
		return nil
	}
	cfg := &SSDPConfig{
		MessageType:        getString(m, "message_type"),
		SearchTarget:       getString(m, "search_target"),
		USN:                getString(m, "usn"),
		Location:           getString(m, "location"),
		Server:             getString(m, "server"),
		MaxAge:             getInt(m, "max_age"),
		MX:                 getInt(m, "mx"),
		BootID:             getUint32(m, "boot_id"),
		ConfigID:           getUint32(m, "config_id"),
		NextBootID:         getUint32(m, "next_boot_id"),
		SearchPort:         getUint16(m, "search_port"),
		ResponseCount:      getInt(m, "response_count"),
		ResponseDelayMinMs: getInt(m, "response_delay_min_ms"),
		ResponseDelayMaxMs: getInt(m, "response_delay_max_ms"),
		RepeatCount:        getInt(m, "repeat_count"),
		Date:               getString(m, "date"),
		MulticastGroup:     getString(m, "multicast_group"),
		OmitExt:            getBool(m, "omit_ext", false),
		Body:               getString(m, "body"),
		EmitContentLength:  getBool(m, "emit_content_length", false),
		RepeatIntervalMs:   getInt(m, "repeat_interval_ms"),
	}
	return cfg
}

// parseTLSConfig converts the JSON-decoded "tls" sub-map into *TLSConfig.
func parseTLSConfig(m map[string]interface{}) *TLSConfig {
	if m == nil {
		return nil
	}
	cfg := &TLSConfig{
		Version:             getString(m, "version"),
		Role:                getString(m, "role"),
		SNI:                 getString(m, "sni"),
		ALPN:                getStringSlice(m, "alpn"),
		CipherSuites:        getUint16Slice(m, "cipher_suites"),
		SupportedGroups:     getUint16Slice(m, "supported_groups"),
		SignatureAlgorithms: getUint16Slice(m, "signature_algorithms"),
		ClientCertificate:   parseX509Ref(m["client_certificate"]),
		ServerCertificate:   parseX509Ref(m["server_certificate"]),
		PSKs:                parsePSKIdentities(m["psks"]),
		AllowEarlyData:      getBool(m, "allow_early_data", false),
		AlertPath:           parseAlertStep(m["alert_path"]),
		OCSPStapling:        getBool(m, "ocsp_stapling", false),
	}
	return cfg
}

func parseX509Ref(v interface{}) *X509Ref {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &X509Ref{
		Subject:    getString(m, "subject"),
		San:        getStringSlice(m, "san"),
		NotBefore:  int64(getInt(m, "not_before")),
		NotAfter:   int64(getInt(m, "not_after")),
		KeyType:    getString(m, "key_type"),
		FileSource: parseFileSourceField(m),
	}
}

func parsePSKIdentities(v interface{}) []PSKIdentity {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PSKIdentity, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, PSKIdentity{
			Identity:      getByteSlice(m, "identity"),
			ObfuscatedAge: getUint32(m, "obfuscated_age"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseAlertStep(v interface{}) *AlertStep {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &AlertStep{
		After:       getString(m, "after"),
		Description: uint8(getInt(m, "description")),
		Level:       uint8(getInt(m, "level")),
	}
}

// parseVmessConfig converts the JSON-decoded "vmess" sub-map into *VmessConfig.
func parseVmessConfig(m map[string]interface{}) *VmessConfig {
	if m == nil {
		return nil
	}
	cfg := &VmessConfig{
		UUID:            getString(m, "uuid"),
		AlterID:         getUint16(m, "alter_id"),
		Encryption:      getString(m, "encryption"),
		Command:         uint8(getInt(m, "command")),
		AddressType:     uint8(getInt(m, "address_type")),
		Address:         getString(m, "address"),
		Port:            getUint16(m, "port"),
		HeaderPadLen:    uint8(getInt(m, "header_pad_len")),
		Payload:         getByteSlice(m, "payload"),
		ResponsePayload: getByteSlice(m, "response_payload"),
		FileSource:      parseFileSourceField(m),
		Heartbeat:       getBool(m, "heartbeat", false),
		HeartbeatCount:  getInt(m, "heartbeat_count"),
		MuxStreams:      parseVmessMuxStreams(m["mux_streams"]),
	}
	return cfg
}

func parseVmessMuxStreams(v interface{}) []VmessMuxStream {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]VmessMuxStream, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, VmessMuxStream{
			SessionID:  getUint16(m, "session_id"),
			Frames:     parseVmessMuxFrames(m["frames"]),
			TargetAddr: getString(m, "target_addr"),
			TargetPort: getUint16(m, "target_port"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseVmessMuxFrames(v interface{}) []VmessMuxFrame {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]VmessMuxFrame, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, VmessMuxFrame{
			Status:  uint8(getInt(m, "status")),
			Payload: getByteSlice(m, "payload"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseWireGuardConfig converts the JSON-decoded "wireguard" sub-map into
// *WireGuardConfig.
func parseWireGuardConfig(m map[string]interface{}) *WireGuardConfig {
	if m == nil {
		return nil
	}
	cfg := &WireGuardConfig{
		Role:                 getString(m, "role"),
		LocalStaticPubKey:    getByteSlice(m, "local_static_pub_key"),
		PeerStaticPubKey:     getByteSlice(m, "peer_static_pub_key"),
		LocalEphemeralPubKey: getByteSlice(m, "local_ephemeral_pub_key"),
		SenderIndex:          getUint32(m, "sender_index"),
		PSK:                  getByteSlice(m, "psk"),
		Cookie:               getByteSlice(m, "cookie"),
		InitialCounter:       getUint64(m, "initial_counter"),
		RekeyAfter:           getUint64(m, "rekey_after"),
		RekeyAfterTime:       getInt(m, "rekey_after_time"),
		KeepaliveInterval:    getInt(m, "keepalive_interval"),
		CookieReplyThreshold: getInt(m, "cookie_reply_threshold"),
		TransportPayloads:    getByteSlices(m, "transport_payloads"),
		FileSource:           parseFileSourceField(m),
		Direction:            getString(m, "direction"),
		InnerIP:              parseWireGuardInnerIP(m["inner_ip"]),
	}
	return cfg
}

// parseSRv6Config converts the JSON-decoded "srv6" sub-map into *SRv6Config.
// The segment_list is the user-facing processing order (entry 0 = first
// segment); the planner REVERSES it to wire order (RFC 8754 §2). See
// internal/protocol/srv6 for the planner/validator and design §5.1.
// D-SRV6-1：层链翻译（layers 包）经 ParseSRv6ConfigFromMap 复用同一解析
// （单一真相，防 JSON 往返 base64 误读 inner_payload []byte 字符串语义）。
func parseSRv6Config(m map[string]interface{}) *SRv6Config {
	return ParseSRv6ConfigFromMap(m)
}

// ParseSRv6ConfigFromMap is the exported single-truth parser for the "srv6"
// sub-map (flat 路径与 layers 翻译共用；layers → core 单向依赖，imap
// ParseIMAPConfigFromMap 先例)。
func ParseSRv6ConfigFromMap(m map[string]interface{}) *SRv6Config {
	if m == nil {
		return nil
	}
	// SegmentsLeft/LastEntry: use *uint8 so nil vs *uint8(0) is
	// distinguishable (uint8 zero value cannot distinguish "explicit 0"
	// from "unset").
	var slPtr *uint8
	if v, ok := m["segments_left"].(float64); ok {
		u := uint8(v)
		slPtr = &u
	}
	var lePtr *uint8
	if v, ok := m["last_entry"].(float64); ok {
		u := uint8(v)
		lePtr = &u
	}
	return &SRv6Config{
		SrcIPv6:         getString(m, "src_ipv6"),
		DstIPv6:         getString(m, "dst_ipv6"),
		SegmentList:     getStringSlice(m, "segment_list"),
		SegmentsLeft:    uint8(getInt(m, "segments_left")),
		SegmentsLeftPtr: slPtr,
		LastEntry:       uint8(getInt(m, "last_entry")),
		LastEntryPtr:    lePtr,
		// ReducedPtr takes precedence over Reduced inside the srv6 package's
		// resolveReduced: nil = SegType default, non-nil = explicit (incl. an
		// explicit false). Reduced stays populated for backward compatibility
		// with code/tests that read it directly. Both are driven by the same
		// "reduced" key so they never disagree.
		Reduced:         getBool(m, "reduced", false),
		ReducedPtr:      getBoolPtr(m, "reduced"),
		Flags:           uint8(getInt(m, "flags")),
		Tag:             uint16(getInt(m, "tag")),
		SegType:         getString(m, "seg_type"),
		PayloadProtocol: getString(m, "payload_protocol"),
		InnerPayload:    getByteSlice(m, "inner_payload"),
		InnerSrcPort:    uint16(getInt(m, "inner_src_port")),
		InnerDstPort:    uint16(getInt(m, "inner_dst_port")),
		TLV:             parseSRv6TLVs(m["tlv"]),
		Frames:          getInt(m, "frames"),
		Direction:       getString(m, "direction"),
	}
}

// parseSRv6TLVs converts the JSON-decoded "tlv" list into []SRv6TLV. Each
// entry is {type: uint8, value: bytes}.
func parseSRv6TLVs(v interface{}) []SRv6TLV {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SRv6TLV, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, SRv6TLV{
			Type:  uint8(getInt(m, "type")),
			Value: getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseWireGuardInnerIP converts the JSON-decoded "inner_ip" sub-map into
// *WireGuardInnerIP (the inner IPv4/IPv6 packet config for the
// dual-encapsulation tunnel scenario).
func parseWireGuardInnerIP(v interface{}) *WireGuardInnerIP {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &WireGuardInnerIP{
		SrcIP:      getString(m, "src_ip"),
		DstIP:      getString(m, "dst_ip"),
		Proto:      uint8(getInt(m, "proto")),
		SrcPort:    getUint16(m, "src_port"),
		DstPort:    getUint16(m, "dst_port"),
		TTL:        uint8(getInt(m, "ttl")),
		Payload:    getByteSlice(m, "payload"),
		DataFrames: getInt(m, "data_frames"),
	}
}

// parseTelnetDialog converts the JSON-decoded "dialog" array into a
// []TelnetEvent. Returns nil for absent/non-array input - the planner then
// falls back to its built-in defaultDialog() (a minimal login shape per
// design_telnet.md §6.6).
//
// Each event carries Type (data/will/wont/do/dont/sb/ttype_send/ttype_is/
// naws/ip/dm/nop/ayt/brk/ao/ec/el/ga/synch), Direction ("up"/"down", empty
// defaults to "up" in the planner), and type-specific fields (Option/Data/
// DataB64/SubData/SubDataB64/Value/Cols/Rows). SubData may be a JSON array
// of byte integers or a string (raw bytes).
func parseTelnetDialog(v interface{}) []TelnetEvent {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]TelnetEvent, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ev := TelnetEvent{
			Type:       getString(m, "type"),
			Direction:  getString(m, "direction"),
			Option:     uint8(getInt(m, "option")),
			Data:       getString(m, "data"),
			DataB64:    getString(m, "data_b64"),
			SubData:    parseByteSlice(m["sub_data"]),
			SubDataB64: getString(m, "sub_data_b64"),
			Value:      getString(m, "value"),
			Cols:       getUint16(m, "cols"),
			Rows:       getUint16(m, "rows"),
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseByteSlice converts a JSON-decoded value into a []byte. Accepts a
// JSON array of integers (each 0-255) or a string (raw bytes). Returns nil
// for absent/non-array/non-string input. Mirrors the SCTP chunk data
// parseSNMPVarBinds converts the JSON-decoded "var_binds" or "response_values"
// value (an array of {name, type, value, str_value} objects) into a
// []SNMPVarBind. Returns nil for absent/non-array input - the planner then
// emits a PDU with an empty varbind list (valid for Trap/Inform, where the
// planner synthesises sysUpTime + snmpTrapOID; rejected by Validate for
// Get/GetNext/Set/GetBulk).
//
// Type is the BER tag (0x05 NULL / 0x02 INTEGER / 0x04 OCTET STRING / 0x06 OID
// / 0x40 IpAddress / 0x41 Counter32 / 0x42 Gauge32 / 0x43 TimeTicks / 0x46
// Counter64 / 0x80 noSuchObject / 0x81 noSuchInstance / 0x82 EndOfMibView).
// Value is the raw bytes of the value body (without tag/length); for NULL and
// exception types it is empty. StrValue, when set on an OCTET STRING varbind,
// is encoded as the UTF-8 bytes of the string (convenience for DisplayString).
func parseSNMPVarBinds(v interface{}) []SNMPVarBind {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SNMPVarBind, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		vb := SNMPVarBind{
			Name:     getString(m, "name"),
			Type:     uint8(getInt(m, "type")),
			Value:    parseByteSlice(m["value"]),
			StrValue: getString(m, "str_value"),
		}
		// When Type is OCTET STRING (0x04) and Value is empty but StrValue
		// is set, copy StrValue into Value so the encoder emits the string
		// bytes. This is the DisplayString convenience path.
		if vb.Type == 0x04 && len(vb.Value) == 0 && vb.StrValue != "" {
			vb.Value = []byte(vb.StrValue)
		}
		out = append(out, vb)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsing pattern.
func parseByteSlice(v interface{}) []byte {
	switch d := v.(type) {
	case string:
		return []byte(d)
	case []interface{}:
		out := make([]byte, 0, len(d))
		for _, b := range d {
			if n, ok := b.(float64); ok {
				out = append(out, byte(int(n)))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

func parseMySQLStmtParams(v interface{}) []MySQLStmtParam {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLStmtParam, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MySQLStmtParam{
			Type:          uint8(getInt(m, "type")),
			Unsigned:      getBool(m, "unsigned", false),
			Value:         getString(m, "value"),
			ValueEncoding: getString(m, "value_encoding"),
			IsNull:        getBool(m, "is_null", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSIPDialog converts the JSON-decoded "dialog" value into a
// []SIPMessage. Returns nil for absent/non-array input - the planner then
// emits only TCP handshake + teardown (an empty SIP session, which is a
// valid degenerate test).
//
// Each message may carry Method+URI (request) or StatusCode+StatusText
// (response). Direction is "up" or "down"; when empty, the planner infers
// it from Method/StatusCode (Method set -> up request; StatusCode set ->
// down response). Headers is a list of "Name: Value" strings; the planner
// auto-appends Content-Length when Body is non-empty. Body is the optional
// message body (e.g. SDP).
func parseSIPDialog(v interface{}) []SIPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SIPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := SIPMessage{
			Method:     getString(m, "method"),
			URI:        getString(m, "uri"),
			StatusCode: getInt(m, "status_code"),
			StatusText: getString(m, "status_text"),
			Direction:  getString(m, "direction"),
			Body:       getString(m, "body"),
			EmitMedia:  getBool(m, "emit_media", false),
		}
		if headers, ok := m["headers"].([]interface{}); ok {
			for _, h := range headers {
				if s, ok := h.(string); ok {
					msg.Headers = append(msg.Headers, s)
				}
			}
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSIPMedia converts the JSON-decoded "media" sub-map into a *SIPMedia.
// Returns nil for absent/non-map input — the planner then emits only
// signaling (backward compat with pre-media specs).
//
// Direction: parsed here so the JSON {"media":{"direction":"down"}} path
// parseSIPNAT decodes sip "nat" into the RFC 3581 switch set (D-SIP-2
// WP-C). Returns nil for absent/non-map input — nil means verbatim
// pass-through (the engine default).
func parseSIPNAT(v interface{}) *SIPNAT {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &SIPNAT{RPort: getBool(m, "rport", false)}
}

// ParseSIPMedias decodes sip "medias[]" into the multi-stream media shape
// (D-SIP-2 WP-B). Exported for layers.translateTerminalConfig (single truth
// with the flat cfg["sip"] branch — ParseSIPSessions precedent). Each entry
// reuses parseSIPMedia (direction/frames/payload_type/file_source) plus the
// dynamic-object forms of the ports. Returns nil for absent/non-array input.
func ParseSIPMedias(v interface{}) []SIPMedia {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SIPMedia, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		e := parseSIPMedia(m)
		if e == nil {
			continue
		}
		e.SrcPortDyn = parseStrategyConfigDyn(m["src_port"])
		e.DstPortDyn = parseStrategyConfigDyn(m["dst_port"])
		out = append(out, *e)
	}
	return out
}

// ParseSIPSessions decodes sip "sessions[]" into the multi-session shape
// (D-SIP-2 WP-A). Exported for layers.translateTerminalConfig (single
// truth with the flat cfg["sip"] branch above — ParseFTPConfigFromMap
// precedent). Each session: src_port/dst_port (0 = inherit spec ports,
// planner derives collision-free defaults when omitted), optional call_id
// (empty = planner derives "{flowIdx}-{sessIdx}@{srcIP}"), the session's
// dialog messages and optional media. Dynamic-object forms of the ports
// and call_id are parsed into the Dyn fields (same-key two-state,
// resolved at spec.FlowIndex by the planner). Returns nil for
// absent/non-array input.
func ParseSIPSessions(v interface{}) []SIPSession {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SIPSession, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		sess := SIPSession{
			SrcPort: getUint16(m, "src_port"),
			DstPort: getUint16(m, "dst_port"),
			CallID:  getString(m, "call_id"),
			Dialog:  parseSIPDialog(m["dialog"]),
			Media:   parseSIPMedia(m["media"]),
			// D-SIP-2 补强批：per-session medias[]/interleave 接线——
			// 此前漏解析被静默丢弃（SIPSession 有字段无 parse 填充，
			// planner 层直构 spec 的单测覆盖不到，T-SIP-87 首跑抓出）。
			Medias:     ParseSIPMedias(m["medias"]),
			Interleave: getBool(m, "interleave", false),
			SrcPortDyn: parseStrategyConfigDyn(m["src_port"]),
			DstPortDyn: parseStrategyConfigDyn(m["dst_port"]),
			CallIDDyn:  parseStrategyConfigDyn(m["call_id"]),
		}
		out = append(out, sess)
	}
	return out
}

// is wired through. Without this, the user's explicit direction override
// is silently dropped and the planner falls through to the SDP-derived
// default (or "up"). FileSource is parsed separately after this function
// returns (strategy_convert.go:~768) so it can be patched in even if the
// media sub-map was present without a file_source key.
func parseSIPMedia(v interface{}) *SIPMedia {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &SIPMedia{
		Direction:   getString(m, "direction"),
		SrcPort:     getUint16(m, "src_port"),
		DstPort:     getUint16(m, "dst_port"),
		Frames:      getInt(m, "frames"),
		PayloadType: uint8(getInt(m, "payload_type")),
		SampleRate:  uint32(getInt(m, "sample_rate")),
		FrameSize:   getInt(m, "frame_size"),
	}
}

// parseRTSPDialog converts the JSON-decoded "dialog" value into a
// []RTSPMessage. Returns nil for absent/non-array input — the planner then
// emits only TCP handshake + teardown (an empty RTSP session, which is a
// valid degenerate test).
//
// Each message may carry Method+URI (request) or StatusCode+StatusText
// (response). Direction is "up" or "down"; when empty, the planner infers
// it from Method/StatusCode. Headers is a list of "Name: Value" strings;
// CSeq/Session/Transport/Content-Length are auto-completed by the
// planner. Body is the optional message body (e.g. SDP).
// ParseRTSPConfigFromMap converts the JSON-decoded "rtsp" sub-map into
// *RTSPConfig (mirror of the mapToFlowSpec case "rtsp" body; exported for
// the layer-translate path — ParseLDAPConfigFromMap precedent).
func ParseRTSPConfigFromMap(m map[string]interface{}) *RTSPConfig {
	if m == nil {
		return nil
	}
	return &RTSPConfig{
		Dialog: parseRTSPDialog(m["dialog"]),
		Media:  parseRTSPMedia(m["media"]),
	}
}

func parseRTSPDialog(v interface{}) []RTSPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RTSPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := RTSPMessage{
			Method:     getString(m, "method"),
			URI:        getString(m, "uri"),
			StatusCode: getInt(m, "status_code"),
			StatusText: getString(m, "status_text"),
			Direction:  getString(m, "direction"),
			Body:       getString(m, "body"),
			EmitMedia:  getBool(m, "emit_media", false),
		}
		if headers, ok := m["headers"].([]interface{}); ok {
			for _, h := range headers {
				if s, ok := h.(string); ok {
					msg.Headers = append(msg.Headers, s)
				}
			}
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRTSPMedia converts the JSON-decoded "media" sub-map into a *RTSPMedia.
// Returns nil for absent/non-map input — the planner then emits only
// signaling (SETUP Transport headers are left entirely to the user).
func parseRTSPMedia(v interface{}) *RTSPMedia {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RTSPMedia{
		Direction:   getString(m, "direction"),
		SrcPort:     getUint16(m, "src_port"),
		DstPort:     getUint16(m, "dst_port"),
		Frames:      getInt(m, "frames"),
		PayloadType: uint8(getInt(m, "payload_type")),
		SampleRate:  uint32(getInt(m, "sample_rate")),
		FrameSize:   getInt(m, "frame_size"),
	}
}

// Each chunk carries TSN/SID/SSN/PPID/Data/Direction. TSN 0 = planner
// auto-increments per direction. Direction "up" = client→server, "down"
// = server→client; empty defaults to "up".
func parseSCTPChunks(v interface{}) []SCTPChunk {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SCTPChunk, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var data []byte
		switch d := m["data"].(type) {
		case string:
			data = []byte(d)
		case []interface{}:
			data = make([]byte, 0, len(d))
			for _, b := range d {
				if n, ok := b.(float64); ok {
					data = append(data, byte(int(n)))
				}
			}
		}
		chunk := SCTPChunk{
			TSN:        getUint32(m, "tsn"),
			SID:        getUint16(m, "sid"),
			SSN:        getUint16(m, "ssn"),
			PPID:       getUint32(m, "ppid"),
			Data:       data,
			Direction:  getString(m, "direction"),
			FileSource: parseFileSource(m),
		}
		out = append(out, chunk)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSCTPHeartbeats converts the JSON-decoded "heartbeats" value into an
// *SCTPHeartbeatConfig. Returns nil for absent/non-map input so the planner
// skips heartbeat emission. Count 0 = 1 pair default. AltPath is optional
// — nil means primary-path heartbeats (still useful for liveness).
func parseSCTPHeartbeats(v interface{}) *SCTPHeartbeatConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	hb := &SCTPHeartbeatConfig{
		Count: getInt(m, "count"),
	}
	if alt, ok := m["alt_path"].(map[string]interface{}); ok && alt != nil {
		hb.AltPath = &SCTPAltPath{
			SrcIP:  getString(alt, "alt_src_ip"),
			DstIP:  getString(alt, "alt_dst_ip"),
			SrcMAC: getString(alt, "alt_src_mac"),
			DstMAC: getString(alt, "alt_dst_mac"),
		}
	}
	return hb
}

// parseICMPv6Pattern converts the JSON-decoded "pattern" value (an array of
// step objects) into a []ICMPv6Step. Returns nil for absent/non-array input
// so the planner falls back to the single-ping path. Each step inherits
// Type/Code defaults from the parent config when absent (Type=128, Code=0);
// Sequence defaults to step index+1 when 0 (per RFC 4443 ping session
// semantics: Identifier groups, Sequence increments per ping).
func parseICMPv6Pattern(v interface{}) []ICMPv6Step {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ICMPv6Step, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := uint8(getIntDefault(m, "type", 128))
		code := uint8(getIntDefault(m, "code", 0))
		seq := uint16(getInt(m, "sequence"))
		if seq == 0 {
			seq = uint16(len(out) + 1)
		}
		data := []byte(getStringDefault(m, "data", "ping"))
		out = append(out, ICMPv6Step{
			Type:     typ,
			Code:     code,
			Sequence: seq,
			Data:     data,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// JSON helper functions with sensible defaults

// parseSyslogStructuredData converts the JSON-decoded "structured_data" field
// into a []string. Accepts both a list of strings (preferred, each entry is
// a pre-framed SD-ELEMENT like `[origin ip="1.2.3.4"]` or a bare body like
// `origin ip="1.2.3.4"`) and a list of maps with `id` + `parameters` keys
// (structured form). Returns nil for absent/non-list input.
func parseSyslogStructuredData(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		switch s := item.(type) {
		case string:
			if s != "" {
				out = append(out, s)
			}
		case map[string]interface{}:
			// Structured form: {id: "origin", parameters: {ip: "1.2.3.4"}}
			id, _ := item.(map[string]interface{})["id"].(string)
			if id == "" {
				continue
			}
			params, _ := item.(map[string]interface{})["parameters"].(map[string]interface{})
			var b strings.Builder
			b.WriteByte('[')
			b.WriteString(id)
			// Iterate params in SORTED key order so the wire output is
			// deterministic across runs. Go map iteration is randomized
			// (design_syslog.md §1.8.4 requires stable output for tests
			// like 3.7.1: `[meta sequenceId="1234" sysUpTime="0"]`).
			paramKeys := make([]string, 0, len(params))
			for k := range params {
				paramKeys = append(paramKeys, k)
			}
			sort.Strings(paramKeys)
			for _, k := range paramKeys {
				vs, _ := params[k].(string)
				b.WriteString(` `)
				b.WriteString(k)
				b.WriteString(`="`)
				b.WriteString(escapeSDValue(vs))
				b.WriteString(`"`)
			}
			b.WriteByte(']')
			out = append(out, b.String())
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSyslogMessages converts the JSON-decoded "messages" field into
// []SyslogMessage. Each entry is a map mirroring SyslogMessage fields.
// Returns nil for absent/non-list input or empty list.
//
// Per-message fields (Timestamp/Hostname/AppName/ProcID/MsgID/SD/Msg/
// MsgHasBOM/SignBlocks) override the top-level SyslogConfig fields for
// that one message. Protocol-level fields (Facility/Severity/Version/
// Format/Transport/TCPFraming/Count) are NOT per-message — they remain
// at the top-level SyslogConfig.
func parseSyslogMessages(v interface{}) []SyslogMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SyslogMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		entry := SyslogMessage{
			Timestamp:      getString(m, "timestamp"),
			Hostname:       getString(m, "hostname"),
			AppName:        getString(m, "app_name"),
			ProcID:         getString(m, "proc_id"),
			MsgID:          getString(m, "msg_id"),
			StructuredData: parseSyslogStructuredData(m["structured_data"]),
			Msg:            getString(m, "msg"),
			MsgHasBOM:      getBool(m, "msg_has_bom", false),
			SignBlocks:     parseSyslogSignBlocks(m["sign_blocks"]),
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSyslogSignBlocks converts the JSON-decoded "sign_blocks" field into
// a []string. Accepts a list of strings (each is a base64 signature value).
// Returns nil for absent/non-list input.
func parseSyslogSignBlocks(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// escapeSDValue escapes `"`, `\`, `]` in a STRUCTURED-DATA PARAM-VALUE per
// RFC 5424 §6.2.8. Returns the escaped string.
func escapeSDValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func getString(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func getStringDefault(m map[string]interface{}, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

// parseUintFromString parses a numeric value from a string, supporting both
// decimal ("3221225524") and hex ("0xC0000034") forms. MCP pcap cases pass
// status codes and bitmasks as hex strings; without this the uint helpers
// returned 0 via the default branch, silently dropping the value.
// Returns (value, ok); ok=false for empty or unparseable strings.
func parseUintFromString(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func getUint16(m map[string]interface{}, key string) uint16 {
	switch v := m[key].(type) {
	case float64:
		return uint16(v)
	case json.Number:
		n, _ := v.Int64()
		return uint16(n)
	case string:
		n, ok := parseUintFromString(v)
		if !ok {
			return 0
		}
		return uint16(n)
	default:
		return 0
	}
}

func getUint32(m map[string]interface{}, key string) uint32 {
	switch v := m[key].(type) {
	case float64:
		return uint32(v)
	case json.Number:
		n, _ := v.Int64()
		return uint32(n)
	case string:
		n, ok := parseUintFromString(v)
		if !ok {
			return 0
		}
		return uint32(n)
	default:
		return 0
	}
}

// getUint64 reads a uint64 from the map. Supports float64 (JSON decode),
// json.Number (UseNumber path), int/int64, and decimal/hex strings
// (e.g. "0xC0000034"); missing key returns 0. Used by IKE SPI fields.
func getUint64(m map[string]interface{}, key string) uint64 {
	switch v := m[key].(type) {
	case float64:
		return uint64(v)
	case json.Number:
		n, _ := v.Int64()
		return uint64(n)
	case int:
		return uint64(v)
	case int64:
		return uint64(v)
	case string:
		n, ok := parseUintFromString(v)
		if !ok {
			return 0
		}
		return n
	default:
		return 0
	}
}

func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	default:
		return 0
	}
}

func getIntDefault(m map[string]interface{}, key string, def int) int {
	v := getInt(m, key)
	if v == 0 {
		return def
	}
	return v
}

// defaultDSCP returns the user-provided DSCP value when the "dscp" key is
// present in cfg AND non-nil (even if 0 = best-effort), and DefaultDSCP when
// the key is absent or explicitly null. The presence + nil check is required
// because:
//   - DSCP=0 is a valid user choice (clean best-effort traffic with no
//     trafficgen marker), which the older getIntDefault helper would silently
//     override with the default.
//   - JSON null (cfg["dscp"]=nil) should be treated as "not set", not as
//     "explicitly 0" -- otherwise a config like {"dscp": null} silently
//     disables the trafficgen marker.
func defaultDSCP(cfg map[string]interface{}) uint8 {
	if v, ok := cfg["dscp"]; ok && v != nil {
		return uint8(getInt(cfg, "dscp"))
	}
	return DefaultDSCP
}

// defaultIPFlags returns the user-provided IP flags when the "ip_flags" key
// is present in cfg AND non-nil (even if 0 = allow fragmentation), and
// DefaultIPFlags (DF=1) when the key is absent or null. Same presence + nil
// check rationale as defaultDSCP: flags=0 is a valid user choice.
//
// Backward compat: pre-rename strategies used the key "flags". We prefer
// "ip_flags" when present and fall back to "flags" so existing DB rows keep
// working. The "flags" key is ambiguous on a FlowSpec (TCP flags vs IP flags)
// — the rename makes the intent unambiguous.
func defaultIPFlags(cfg map[string]interface{}) uint8 {
	if v, ok := cfg["ip_flags"]; ok && v != nil {
		return uint8(getInt(cfg, "ip_flags"))
	}
	if v, ok := cfg["flags"]; ok && v != nil {
		return uint8(getInt(cfg, "flags"))
	}
	return DefaultIPFlags
}

// defaultMAC returns the user-provided MAC when the "key" field is present
// AND non-empty (allowing explicit "" to produce an all-zero MAC on the wire
// for ARP probe scenarios), and def when absent or null. The presence check
// is required because empty string is a legitimate user value (zero MAC),
// which getStringDefault would silently replace with the default.
func defaultMAC(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// defaultString returns the user-provided string when the "key" field is
// present AND non-nil (even if ""), and def when absent or null. Same
// presence + nil rationale as defaultMAC: empty string is a legitimate
// user value (e.g., empty domain for DNS wildcard, empty URI for root).
func defaultString(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// defaultPort returns the user-provided port when the "port_key" field is
// present AND non-nil (even if 0), and def when absent or null. Port 0 is a
// valid user choice (let OS pick ephemeral port), which getUint16 would
// silently override with the default. Same presence-check pattern as
// defaultDSCP.
func defaultPort(cfg map[string]interface{}, key string, def uint16) uint16 {
	if v, ok := cfg[key]; ok && v != nil {
		return getUint16(cfg, key)
	}
	return def
}

func getBool(m map[string]interface{}, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	// JSON decodes 0/1 to float64; accept them so configs written as
	// {"down": 1} behave identically to {"down": true} instead of
	// silently falling back to the default.
	switch n := m[key].(type) {
	case float64:
		if n == 0 {
			return false
		}
		if n == 1 {
			return true
		}
	case json.Number:
		i, err := n.Int64()
		if err == nil && (i == 0 || i == 1) {
			return i == 1
		}
	case int:
		if n == 0 {
			return false
		}
		if n == 1 {
			return true
		}
	case int64:
		if n == 0 {
			return false
		}
		if n == 1 {
			return true
		}
	}
	return def
}

// getBoolWithFallback reads a bool from preferredKey, falling back to
// legacyKey when preferredKey is absent. Used for renamed bool fields
// (e.g. "is_response" replacing "response" on UDP/DNS) so existing DB
// rows keep working.
func getBoolWithFallback(m map[string]interface{}, preferredKey, legacyKey string, def bool) bool {
	if v, ok := m[preferredKey].(bool); ok {
		return v
	}
	if v, ok := m[legacyKey].(bool); ok {
		return v
	}
	return def
}

// getStringWithFallback reads a string from preferredKey, falling back to
// legacyKey when preferredKey is absent. Used for renamed string fields
// (e.g. "response_content_encoding" replacing "content_encoding") so
// existing DB rows keep working.
func getStringWithFallback(m map[string]interface{}, preferredKey, legacyKey string) string {
	if v, ok := m[preferredKey].(string); ok {
		return v
	}
	if v, ok := m[legacyKey].(string); ok {
		return v
	}
	return ""
}

func getStringMap(m map[string]interface{}, key string) map[string]string {
	result := make(map[string]string)
	if sub, ok := m[key].(map[string]interface{}); ok {
		for k, v := range sub {
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
	}
	return result
}

// getFloatDefault returns the float64 value for key when present and non-nil
// (0.0 is a valid user value for RootDelay/RootDispersion), and def when the
// key is absent or null. Mirrors the presence-check pattern of defaultDSCP
// /defaultIPFlags so explicit 0 is honored rather than silently replaced.
func getFloatDefault(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key]; ok && v != nil {
		switch f := v.(type) {
		case float64:
			return f
		case int:
			return float64(f)
		case int64:
			return float64(f)
		case json.Number:
			n, err := f.Float64()
			if err == nil {
				return n
			}
		}
	}
	return def
}

// getTime parses an RFC 3339 timestamp string into time.Time. Empty string,
// missing key, or null returns the zero time.Time (which the NTP planner
// treats as "not set" and emits as 0). Parse errors also return the zero
// time -- mapToFlowSpec collects parse errors elsewhere; here we want a
// best-effort conversion so the planner can still emit a packet.
func getTime(m map[string]interface{}, key string) time.Time {
	v, ok := m[key]
	if !ok || v == nil {
		return time.Time{}
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// getByteSlice converts a JSON-decoded value into []byte. Accepts a string
// (taken as raw bytes) or an array of numbers (each byte 0-255). nil/missing
// returns nil so the planner skips the field entirely.
func getByteSlice(m map[string]interface{}, key string) []byte {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch b := v.(type) {
	case string:
		return []byte(b)
	case []interface{}:
		out := make([]byte, 0, len(b))
		for _, n := range b {
			if f, ok := n.(float64); ok {
				out = append(out, byte(int(f)))
			}
		}
		return out
	}
	return nil
}

// getHexBytes parses a hex string field into bytes, per the DoIP design
// doc: AddressAndLength/TransferData 等字段以 "00 44 ..." 十六进制字符串
// 输入（§6.10/T041），字符串值先 hex 解码；数组值保持逐字节语义。非法 hex
// 按原样使用（与既有 ASCII 字段兼容）。
func getHexBytes(m map[string]interface{}, key string) []byte {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch b := v.(type) {
	case string:
		s := strings.ReplaceAll(b, " ", "")
		if s == "" {
			return nil
		}
		if out, err := hex.DecodeString(s); err == nil {
			return out
		}
		return []byte(b)
	case []interface{}:
		out := make([]byte, 0, len(b))
		for _, n := range b {
			if f, ok := n.(float64); ok {
				out = append(out, byte(int(f)))
			}
		}
		return out
	}
	return nil
}

// parseNTPExtensions converts the JSON-decoded "extensions" value (an array
// of {type, value} objects) into a []NTPExt. Returns nil for absent/non-array
// input so the planner skips extension emission. Each extension's Value may
// be a string (raw bytes) or a number array (each byte 0-255); the planner
// 0-pads to a 4-byte boundary before emitting.
// Pointer-typed helpers for fields where the zero value is meaningful
// (e.g. *bool, *uint32). These return nil when the key is absent, so the
// planner can distinguish "user did not set" from "user set to 0/false".
// Used by IKE MessageID/InitiatorSPI/ResponderSPI, PostgreSQL
// EmitHandshake/EmitTeardown, MDNS CacheFlush, etc.

func getBoolPtr(m map[string]interface{}, key string) *bool {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func getUint8Ptr(m map[string]interface{}, key string) *uint8 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint8(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint8(i)
		return &u
	}
	return nil
}

func getUint16Ptr(m map[string]interface{}, key string) *uint16 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint16(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint16(i)
		return &u
	}
	return nil
}

func getUint32Ptr(m map[string]interface{}, key string) *uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint32(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint32(i)
		return &u
	}
	return nil
}

func getUint64Ptr(m map[string]interface{}, key string) *uint64 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint64(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint64(i)
		return &u
	}
	return nil
}

func getInt32Ptr(m map[string]interface{}, key string) *int32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		i := int32(n)
		return &i
	case json.Number:
		j, err := n.Int64()
		if err != nil {
			return nil
		}
		i := int32(j)
		return &i
	}
	return nil
}

// getIntPtr reads a JSON number into an *int (used for fields whose
// zero value is meaningful, e.g. ENIPIOData.SourceCommandIndex).
func getIntPtr(m map[string]interface{}, key string) *int {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		i := int(n)
		return &i
	case json.Number:
		j, err := n.Int64()
		if err != nil {
			return nil
		}
		i := int(j)
		return &i
	}
	return nil
}

// getUint16Slice reads a JSON array of numbers into a []uint16.
func getUint16Slice(m map[string]interface{}, key string) []uint16 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint16(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint16(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getUint8Slice reads a JSON array of numbers into a []uint8.
func getUint8Slice(m map[string]interface{}, key string) []uint8 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint8, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint8(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint8(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getUint32Slice reads a JSON array of numbers into a []uint32.
func getUint32Slice(m map[string]interface{}, key string) []uint32 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint32(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint32(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getStringSlice reads a JSON array of strings into a []string.
func getStringSlice(m map[string]interface{}, key string) []string {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getByteSlices reads a JSON array of byte-array/string entries into a [][]byte.
// Each entry may be a string (raw bytes) or an array of integers (0-255).
func getByteSlices(m map[string]interface{}, key string) [][]byte {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(arr))
	for _, item := range arr {
		b := parseByteSlice(item)
		if b != nil {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getInt32MapKeysValues reads a map[int]int32 (used by PostgreSQL ColumnTypes).
func getInt32MapValues(m map[string]interface{}, key string) map[int]int32 {
	sub, ok := m[key].(map[string]interface{})
	if !ok || len(sub) == 0 {
		return nil
	}
	out := make(map[int]int32, len(sub))
	for k, v := range sub {
		// JSON keys are strings; parse to int
		var idx int
		if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
			continue
		}
		switch n := v.(type) {
		case float64:
			out[idx] = int32(n)
		case json.Number:
			if j, err := n.Int64(); err == nil {
				out[idx] = int32(j)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeBase64 decodes a standard base64-encoded string. Used by RDP
// payload_b64 / shadowsocks / IKE raw fields. Returns nil on error (the
// caller treats nil as "no payload set" which is the correct fallback).
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func parseNTPExtensions(v interface{}) []NTPExt {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]NTPExt, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ext := NTPExt{
			Type:  uint16(getInt(m, "type")),
			Value: getByteSlice(m, "value"),
		}
		out = append(out, ext)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseNGAPConfig converts the JSON-decoded "ngap" sub-map into *NGAPConfig.
// NGAP (Next Generation Application Protocol, 5G核心网信令协议) runs over SCTP.
// nil/empty input returns nil.
func parseNGAPConfig(v interface{}) *NGAPConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	cfg := &NGAPConfig{
		AMFName:          getString(m, "amf_name"),
		DefaultPagingDRX: getInt(m, "default_paging_drx"),
		RANUENGAPID:      uint32(getInt(m, "ran_ue_ngap_id")),
		AMFUENGAPID:      uint32(getInt(m, "amf_ue_ngap_id")),
		InitialUEMessage: getBool(m, "initial_ue_message", false),
		UEContextRelease: getBool(m, "ue_context_release", false),
		InitialNAS:       getByteSlice(m, "initial_nas"),
		DownlinkNAS:      getByteSlice(m, "downlink_nas"),
		UplinkNAS:        getByteSlice(m, "uplink_nas"),
	}
	// Parse GlobalRANNodeID (全局RAN节点标识).
	if g, ok := m["global_ran_node_id"].(map[string]interface{}); ok {
		cfg.GlobalRANNodeID = &NGAPGlobalRANNodeID{
			PLMNMCC: getInt(g, "plmn_mcc"),
			PLMNMNC: getInt(g, "plmn_mnc"),
			GNBID:   uint32(getInt(g, "gnb_id")),
		}
	}
	// Parse SupportedTAList (支持的TA列表).
	if tas, ok := m["supported_ta_list"].([]interface{}); ok {
		for _, item := range tas {
			taMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			ta := NGAPSupportedTA{
				PLMNMCC: getInt(taMap, "plmn_mcc"),
				PLMNMNC: getInt(taMap, "plmn_mnc"),
			}
			if tacs, ok := taMap["tacs"].([]interface{}); ok {
				for _, t := range tacs {
					ta.TACs = append(ta.TACs, uint32(getInt(map[string]interface{}{"v": t}, "v")))
				}
			}
			cfg.SupportedTAList = append(cfg.SupportedTAList, ta)
		}
	}
	// Parse PDUSessionSetup (PDU会话建立).
	if ps, ok := m["pdu_session_setup"].(map[string]interface{}); ok {
		cfg.PDUSessionSetup = &NGAPPDUSessionSetup{
			PDUSessionID: getInt(ps, "pdu_session_id"),
			SST:          getInt(ps, "sst"),
			SD:           uint32(getInt(ps, "sd")),
		}
	}
	return cfg
}

// parseTFTPConfig converts the JSON-decoded "tftp" sub-map into a
// *TFTPConfig. Returns nil for absent input so mapToFlowSpec's round-trip
// (JSON unmarshal test) works before the planner is wired.
func parseTFTPConfig(m map[string]interface{}) *TFTPConfig {
	if m == nil {
		return nil
	}
	cfg := &TFTPConfig{
		Mode:                   getString(m, "mode"),
		Filename:               getString(m, "filename"),
		TransferMode:           getString(m, "transfer_mode"),
		BlkSize:                getUint16(m, "blksize"),
		Timeout:                uint8(getInt(m, "timeout")),
		ClientTSize:            getUint32(m, "client_tsize"),
		ServerTSize:            getUint32(m, "server_tsize"),
		ServerTID:              getUint16(m, "server_tid"),
		ErrorCode:              uint8(getInt(m, "error_code")),
		ErrorMsg:               getString(m, "error_msg"),
		ErrorAfterBlock:        getUint32(m, "error_after_block"),
		ErrorSide:              getString(m, "error_side"),
		BlocksCount:            getUint32(m, "blocks_count"),
		AutoAppendFinalBlock:   getBoolPtr(m, "auto_append_final_block"),
		FinalBlockZero:         getBool(m, "final_block_zero", false),
		WrapBlockNumber:        getBool(m, "wrap_block_number", false),
		DataPayloadPattern:     getByteSlice(m, "data_payload_pattern"),
		IncludeOACK:            getBool(m, "include_oack", false),
		RetransmitBlocks:       getUint32Slice(m, "retransmit_blocks"),
		ServerTIDChange:        getBool(m, "server_tid_change", false),
		ServerTIDChangeAtBlock: getUint32(m, "server_tid_change_at_block"),
		ServerTIDNew:           getUint16(m, "server_tid_new"),
		WindowSize:             getUint16(m, "windowsize"),
	}
	return cfg
}

// parseGBT32960Config converts the JSON-decoded "gbt32960" map into a
// GBT32960Config. Nested structs (AlarmData, RemoteControl,
// PlatformLogin, Reports, ReissueReports, StatusChangeTrace) are
// parsed via JSON marshal/unmarshal round-trip for safety.
func parseGBT32960Config(m map[string]interface{}) *GBT32960Config {
	if m == nil {
		return nil
	}
	cfg := &GBT32960Config{
		Role:                         getString(m, "role"),
		VIN:                          getString(m, "vin"),
		SIM:                          getString(m, "sim"),
		EncryptRule:                  getString(m, "encrypt_rule"),
		LoginSerialNumber:            getInt(m, "login_serial_number"),
		LogoutSerialNumber:           getInt(m, "logout_serial_number"),
		RechargeableSubsysCount:      getInt(m, "rechargeable_subsys_count"),
		RechargeableSubsysCodeLength: getInt(m, "rechargeable_subsys_code_length"),
		RechargeableSubsysCodes:      getStringSlice(m, "rechargeable_subsys_codes"),
		LoginTime:                    getString(m, "login_time"),
		LogoutTime:                   getString(m, "logout_time"),
		Reports:                      parseGBT32960Reports(m["reports"]),
		ReissueReports:               parseGBT32960Reports(m["reissue_reports"]),
		AlarmData:                    parseGBT32960AlarmData(m["alarm_data"]),
		RemoteControl:                parseGBT32960RemoteControl(m["remote_control"]),
		PlatformLogin:                parseGBT32960PlatformLogin(m["platform_login"]),
		PlatformID:                   getString(m, "platform_id"),
		PlatformDomain:               getString(m, "platform_domain"),
		SetPlatformDomain:            getString(m, "set_platform_domain"),
		ConnectID:                    getString(m, "connect_id"),
		HeartbeatCount:               getInt(m, "heartbeat_count"),
		ResponseFlags:                getString(m, "response_flags"),
		StatusChangeTrace:            parseGBT32960StatusChangeTrace(m["status_change_trace"]),
		CustomFields:                 getString(m, "custom_fields"),
		InjectBCCError:               getBool(m, "inject_bcc_error", false),
		BCCErrorIndex:                getInt(m, "bcc_error_index"),
	}
	if v, ok := m["vin_pad_byte"].(float64); ok {
		b := byte(v)
		cfg.VINPadByte = &b
	}
	if v, ok := m["is_trans_battery_data"].(bool); ok {
		b := v
		cfg.IsTransBatteryData = &b
	}
	return cfg
}

// parseGBT32960AlarmData parses the nested alarm_data field.
func parseGBT32960AlarmData(v interface{}) *GBT32960AlarmData {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &GBT32960AlarmData{
		MaxAlarmLevel:     uint8(getInt(m, "max_alarm_level")),
		GeneralAlarmFlags: getString(m, "general_alarm_flags"),
	}
}

// parseGBT32960RemoteControl parses the nested remote_control field.
func parseGBT32960RemoteControl(v interface{}) *GBT32960RemoteControl {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &GBT32960RemoteControl{
		ControlType:   uint8(getInt(m, "control_type")),
		Params:        getString(m, "params"),
		ResponseFlags: getString(m, "response_flags"),
	}
}

// parseGBT32960PlatformLogin parses the nested platform_login field.
func parseGBT32960PlatformLogin(v interface{}) *GBT32960PlatformLogin {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &GBT32960PlatformLogin{
		User:       getString(m, "user"),
		Password:   getString(m, "password"),
		EncryptSeq: getString(m, "encrypt_seq"),
	}
}

// parseGBT32960Reports parses the reports/reissue_reports array.
func parseGBT32960Reports(v interface{}) []GBT32960Report {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GBT32960Report, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GBT32960Report{
			Time:         getString(m, "time"),
			AlarmData:    parseGBT32960AlarmData(m["alarm_data"]),
			CustomFields: getString(m, "custom_fields"),
		})
	}
	return out
}

// parseGBT32960StatusChangeTrace parses the status_change_trace array.
func parseGBT32960StatusChangeTrace(v interface{}) []GBT32960StatusChange {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GBT32960StatusChange, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GBT32960StatusChange{
			AtReportIndex: getInt(m, "at_report_index"),
			AlarmData:     parseGBT32960AlarmData(m["alarm_data"]),
			CustomFields:  getString(m, "custom_fields"),
		})
	}
	return out
}

// parseMEIObjects extracts the FC 0x2B "mei_objects" array: the first
// object's ID seeds the request Object ID; the last object's value seeds
// the default response object value. Returns (objectID, objValue, present):
// present=false when the key is absent or not a non-empty array.
func parseMEIObjects(v interface{}) (uint16, string, bool) {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return 0, "", false
	}
	present := false
	var objID uint16
	var objValue string
	first := true
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		present = true
		// object_id may be a number or a numeric string ("0"); decode both.
		// Only the FIRST object's ID seeds the request Object ID; later
		// objects must not overwrite it (they only supply response values).
		if first {
			objID = getUint16(m, "object_id")
			first = false
		}
		if s, ok := m["object_value"].(string); ok {
			objValue = s
		}
	}
	return objID, objValue, present
}

// parseMODBUSOperations parses the transactions array of a modbus config.
// Semantics (T-074/T-075): an absent key or non-array value → nil (the
// planner injects one default FC=0x03 transaction); an explicit empty
// array "[]" → non-nil empty slice (the planner emits zero transactions,
// handshake + teardown only).
//
// FC 0x2B derivation (deep audit 2026-08): a transaction with
// mei_objects/conformity_level but no explicit "values" must still produce
// a well-formed Read Device Identification request PDU (2B 0E <code> <obj>),
// so Values is derived from conformity_level → Read Device ID Code
// (0x01/0x02/0x03/0x04 = Basic/Regular/Extended/Specific; 0x81-0x83 →
// 0x01-0x03) and from the first mei_object's object_id (or starting_address)
// → Object ID.
func parseMODBUSOperations(v interface{}) []MODBUSOperation {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	if len(arr) == 0 {
		return []MODBUSOperation{}
	}
	out := make([]MODBUSOperation, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		op := MODBUSOperation{
			FunctionCode:    uint8(getInt(m, "function_code")),
			ExceptionCode:   uint8(getInt(m, "exception_code")),
			StartingAddress: getUint16(m, "starting_address"),
			Quantity:        getUint16(m, "quantity"),
			ReadAddress:     getUint16(m, "read_address"),
			WriteAddress:    getUint16(m, "write_address"),
			ReadQuantity:    getUint16(m, "read_quantity"),
			WriteQuantity:   getUint16(m, "write_quantity"),
			WriteValue:      getUint16(m, "write_value"),
			Values:          getByteSlice(m, "values"),
			ResponseValues:  getByteSlice(m, "response_values"),
			SubFunction:     getUint16(m, "sub_function"),
			MaskAnd:         getUint16(m, "mask_and"),
			MaskOr:          getUint16(m, "mask_or"),
			ResponseMode:    getString(m, "response_mode"),
			Direction:       getString(m, "direction"),
		}
		if op.FunctionCode == 0x2B && len(op.Values) == 0 {
			// §3.3.17: derive the mandatory Read Device ID Code + Object ID
			// bytes so the request PDU is well-formed.
			code := uint8(getInt(m, "conformity_level"))
			switch {
			case code >= 0x81 && code <= 0x83:
				code &= 0x03 // private variants (0x81-0x83) → base level
			case code >= 0x01 && code <= 0x04:
				// Basic/Regular/Extended/Specific keep their value.
			default:
				code = 0x01 // default Basic
			}
			objID, _, meiPresent := parseMEIObjects(m["mei_objects"])
			if !meiPresent {
				objID = op.StartingAddress // T-025/S15: starting_address → Object ID
			}
			op.Values = []byte{code, uint8(objID)}
		}
		out = append(out, op)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMODBUSConfig converts the JSON-decoded "modbus" sub-map into a
// core.MODBUSConfig. UnitID is *uint8 so explicit 0 (broadcast) survives
// JSON decoding.
func parseMODBUSConfig(m map[string]interface{}) *MODBUSConfig {
	if m == nil {
		return nil
	}
	return &MODBUSConfig{
		UnitID:            getUint8Ptr(m, "unit_id"),
		SuppressBroadcast: getBool(m, "suppress_broadcast", false),
		Transactions:      parseMODBUSOperations(m["transactions"]),
		MasterCount:       getInt(m, "master_count"),
		FlowCount:         getInt(m, "flow_count"),
		SharedTIDSpace:    getBool(m, "shared_tid_space", false),
	}
}

// parseRIPRoutes parses the routes array of a RIP config.
func parseRIPRoutes(v interface{}) []RIPRoute {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RIPRoute, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RIPRoute{
			AFI:        getUint16(m, "afi"),
			RouteTag:   getUint16(m, "route_tag"),
			IPAddr:     getString(m, "ip_addr"),
			SubnetMask: getString(m, "subnet_mask"),
			PrefixLen:  uint8(getInt(m, "prefix_len")),
			NextHop:    getString(m, "next_hop"),
			Metric:     uint8(getInt(m, "metric")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRIPRouters parses the routers array of a RIP config.
func parseRIPRouters(v interface{}) []RIPRouter {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RIPRouter, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RIPRouter{
			SrcIP:   getString(m, "src_ip"),
			SrcPort: getUint16(m, "src_port"),
			DstIP:   getString(m, "dst_ip"),
			DstPort: getUint16(m, "dst_port"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRIPConfig converts the JSON-decoded "rip" sub-map into a
// core.RIPConfig.
func parseRIPConfig(m map[string]interface{}) *RIPConfig {
	if m == nil {
		return nil
	}
	return &RIPConfig{
		Version:         getString(m, "version"),
		Command:         getString(m, "command"),
		Domain:          getUint16(m, "domain"),
		Routes:          parseRIPRoutes(m["routes"]),
		Auth:            parseRIPAuth(m["auth"]),
		Multicast:       getBool(m, "multicast", false),
		Scenario:        getString(m, "scenario"),
		Routers:         parseRIPRouters(m["routers"]),
		Rounds:          getInt(m, "rounds"),
		TriggeredUpdate: getBool(m, "triggered_update", false),
		SplitHorizon:    getBool(m, "split_horizon", false),
		PoisonReverse:   getBool(m, "poison_reverse", false),
	}
}

// parseRIPAuth parses the auth sub-map of a RIP config.
func parseRIPAuth(v interface{}) *RIPAuth {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &RIPAuth{
		Type:           getString(m, "type"),
		Password:       getString(m, "password"),
		KeyID:          uint8(getInt(m, "key_id")),
		AuthDataLen:    getUint8Ptr(m, "auth_data_len"),
		SequenceNumber: getUint32(m, "sequence_number"),
	}
}

// parseDNP3Points parses the points array of a DNP3 object.
func parseDNP3Points(v interface{}) []DNP3Point {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DNP3Point, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DNP3Point{
			Value:  getFloat64(m, "value"),
			Index:  getUint16(m, "index"),
			Status: getUint8Ptr(m, "status"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDNP3Objects parses the objects array of a DNP3 config.
func parseDNP3Objects(v interface{}) []DNP3Object {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DNP3Object, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var idx [2]uint16
		if r := getUint16Slice(m, "index_range"); len(r) == 2 {
			idx = [2]uint16{r[0], r[1]}
		}
		out = append(out, DNP3Object{
			ObjectType: uint8(getInt(m, "object_type")),
			Variation:  uint8(getInt(m, "variation")),
			Qualifier:  uint8(getInt(m, "qualifier")),
			IndexRange: idx,
			Count:      getUint16(m, "count"),
			Points:     parseDNP3Points(m["points"]),
			Flags:      getUint8Slice(m, "flags"),
			Times:      getUint64Slice(m, "times"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDNP3MultiOutstation parses the multi_outstation sub-map of a DNP3 config.
func parseDNP3MultiOutstation(v interface{}) *DNP3MultiOutstation {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DNP3MultiOutstation{
		OutstationCount:     getInt(m, "outstation_count"),
		OutstationAddrStart: getUint16(m, "outstation_addr_start"),
		OutstationIPStart:   getString(m, "outstation_ip_start"),
		OutstationIPList:    getStringSlice(m, "outstation_ip_list"),
		SrcPortStart:        getUint16(m, "src_port_start"),
	}
}

// parseDNP3Config converts the JSON-decoded "dnp3" sub-map into a
// core.DNP3Config.
func parseDNP3Config(m map[string]interface{}) *DNP3Config {
	if m == nil {
		return nil
	}
	return &DNP3Config{
		LinkType:               getString(m, "link_type"),
		Transport:              getString(m, "transport"),
		SrcAddr:                getUint16(m, "src_addr"),
		DstAddr:                getUint16(m, "dst_addr"),
		LinkFCB:                uint8(getInt(m, "link_fcb")),
		LinkFC:                 uint8(getInt(m, "link_fc")),
		AppSeq:                 uint8(getInt(m, "app_seq")),
		AppFunc:                getString(m, "app_func"),
		AppFuncCode:            uint8(getInt(m, "app_func_code")),
		AppCON:                 uint8(getInt(m, "app_con")),
		Objects:                parseDNP3Objects(m["objects"]),
		Scenario:               getString(m, "scenario"),
		IsEvent:                getBool(m, "is_event", false),
		IsUnsolicited:          getBool(m, "is_unsolicited", false),
		ConfirmRequired:        getBool(m, "confirm_required", false),
		IIN:                    getUint16(m, "iin"),
		IINClass1:              getBool(m, "iin_class1", false),
		IINClass2:              getBool(m, "iin_class2", false),
		IINClass3:              getBool(m, "iin_class3", false),
		IINAlreadyExecuting:    getBool(m, "iin_already_executing", false),
		IINEventBufferOverflow: getBool(m, "iin_event_buffer_overflow", false),
		IINNeedTime:            getBool(m, "iin_need_time", false),
		IINDeviceTrouble:       getBool(m, "iin_device_trouble", false),
		IINLocalControl:        getBool(m, "iin_local_control", false),
		IINBroadcast:           getBool(m, "iin_broadcast", false),
		IINDeviceRestart:       getBool(m, "iin_device_restart", false),
		IINConfigCorrupt:       getBool(m, "iin_config_corrupt", false),
		IINObjectUnknown:       getBool(m, "iin_object_unknown", false),
		IINParameterError:      getBool(m, "iin_parameter_error", false),
		IINFuncNotSupported:    getBool(m, "iin_func_not_supported", false),
		MultiOutstation:        parseDNP3MultiOutstation(m["multi_outstation"]),
		Handshake:              getBoolPtr(m, "handshake"),
		Termination:            getBoolPtr(m, "termination"),
		MSS:                    getUint16(m, "mss"),
		ThinkTime:              getInt(m, "think_time"),
		MalformedCRC:           getBool(m, "malformed_crc", false),
		MalformedLength:        getUint8Ptr(m, "malformed_length"),
		UnknownObject:          getBool(m, "unknown_object", false),
		UnknownFunc:            getBool(m, "unknown_func", false),
	}
}

// getUint64Slice reads a JSON array of numbers into a []uint64.
func getUint64Slice(m map[string]interface{}, key string) []uint64 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint64(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint64(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getFloat64 reads a JSON number into a float64. Returns 0 when absent.
func getFloat64(m map[string]interface{}, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	default:
		return 0
	}
}

// parseENIPSubRequests parses the sub_requests array of an ENIP command.
func parseENIPSubRequests(v interface{}) []ENIPSubRequest {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ENIPSubRequest, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, ENIPSubRequest{
			Service:     uint8(getInt(m, "service")),
			ClassID:     getUint16(m, "class_id"),
			InstanceID:  getUint32(m, "instance_id"),
			AttributeID: getUint16(m, "attribute_id"),
			Data:        getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseENIPCPFItems parses the cpf_items array of an ENIP command.
func parseENIPCPFItems(v interface{}) []CPFItem {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]CPFItem, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, CPFItem{
			TypeID: getUint16(m, "type_id"),
			Length: getUint16(m, "length"),
			Data:   getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseENIPCommands parses the commands array of an ENIP config.
func parseENIPCommands(v interface{}) []ENIPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ENIPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, ENIPCommand{
			Command:                     getUint16(m, "command"),
			Length:                      getUint16(m, "length"),
			SessionHandle:               getUint32(m, "session_handle"),
			SessionHandleStrategy:       getENIPSessionHandleStrategy(m),
			Status:                      getUint32(m, "status"),
			SenderContext:               getUint64(m, "sender_context"),
			Options:                     getUint32(m, "options"),
			Payload:                     getByteSlice(m, "payload"),
			ProtocolVersion:             getUint16(m, "protocol_version"),
			OptionFlag:                  getUint16(m, "option_flag"),
			InterfaceHandle:             getUint32(m, "interface_handle"),
			Timeout:                     getUint16(m, "timeout"),
			PriorityTimeTick:            uint8(getInt(m, "priority_time_tick")),
			TimeoutTicks:                uint8(getInt(m, "timeout_ticks")),
			CPFItems:                    parseENIPCPFItems(m["cpf_items"]),
			CIPService:                  uint8(getInt(m, "cip_service")),
			ClassID:                     getUint16(m, "class_id"),
			InstanceID:                  getUint32(m, "instance_id"),
			AttributeID:                 getUint16(m, "attribute_id"),
			ConnSerialNum:               getUint16(m, "conn_serial_number"),
			OrigVendorID:                getUint16(m, "originator_vendor_id"),
			OrigSerialNum:               getUint32(m, "originator_serial_number"),
			O2TConnID:                   getUint32(m, "o2t_connection_id"),
			T2OConnID:                   getUint32(m, "t2o_connection_id"),
			O2TRPI:                      getUint32(m, "o2t_rpi"),
			T2ORPI:                      getUint32(m, "t2o_rpi"),
			O2TConnParams:               getUint32(m, "o2t_connection_parameters"),
			T2OConnParams:               getUint32(m, "t2o_connection_parameters"),
			TransportClassTrigger:       uint8(getInt(m, "transport_class_trigger")),
			ConnectionPath:              getByteSlice(m, "connection_path"),
			ConnectionPathSize:          uint8(getInt(m, "connection_path_size")),
			ConnectionTimeoutMultiplier: uint8(getInt(m, "connection_timeout_multiplier")),
			SubRequests:                 parseENIPSubRequests(m["sub_requests"]),
			Direction:                   getString(m, "direction"),
			GeneralStatus:               uint8(getInt(m, "general_status")),
			AdditionalStatus:            getUint16Slice(m, "additional_status"),
			SourceCommandIndex:          getInt(m, "source_command_index"),
			FromResponseField:           getString(m, "from_response_field"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getENIPSessionHandleStrategy extracts the strategy key when session_handle
// is configured as a strategy map ({"strategy":"inc",...} 等)。设计 §7.3
// T-090/091：session_handle 仅允许 fixed/from_response 策略，inc/rand 等
// 非法策略由 planner.Validate 拒绝；这里仅透传原始 strategy 字符串，
// 不吞掉配置（此前 getUint32 对 map 恒返回 0，校验永不触发）。
func getENIPSessionHandleStrategy(m map[string]interface{}) string {
	sub, ok := m["session_handle"].(map[string]interface{})
	if !ok {
		return ""
	}
	if s, ok := sub["strategy"].(string); ok {
		return s
	}
	return ""
}
func parseENIPIOData(v interface{}) *ENIPIOData {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &ENIPIOData{
		O2TConnectionID:       getUint32(m, "o2t_connection_id"),
		T2OConnectionID:       getUint32(m, "t2o_connection_id"),
		SequenceStart:         getUint16(m, "sequence_start"),
		SequenceStep:          getUint16(m, "sequence_step"),
		FrameCount:            getInt(m, "frame_count"),
		FrameInterval:         getUint32(m, "frame_interval"),
		FrameSize:             getUint16(m, "frame_size"),
		Payload:               getByteSlice(m, "payload"),
		TransportClassTrigger: uint8(getInt(m, "transport_class_trigger")),
		SourceCommandIndex:    getIntPtr(m, "source_command_index"),
	}
}

// parseENIPConfig converts the JSON-decoded "enip" sub-map into a
// core.ENIPConfig.
func parseENIPConfig(m map[string]interface{}) *ENIPConfig {
	if m == nil {
		return nil
	}
	return &ENIPConfig{
		Scenario:         getString(m, "scenario"),
		Transport:        getString(m, "transport"),
		SessionCount:     getInt(m, "session_count"),
		FlowCount:        getInt(m, "flow_count"),
		Commands:         parseENIPCommands(m["commands"]),
		IOData:           parseENIPIOData(m["io_data"]),
		VendorID:         getUint16(m, "vendor_id"),
		DeviceType:       getUint16(m, "device_type"),
		ProductCode:      getUint16(m, "product_code"),
		FirmwareMajorRev: uint8(getInt(m, "firmware_major_rev")),
		FirmwareMinorRev: uint8(getInt(m, "firmware_minor_rev")),
		ProductName:      getString(m, "product_name"),
		SerialNumber:     getUint32(m, "serial_number"),
		DeviceStatus:     getUint16(m, "device_status"),
		DeviceState:      uint8(getInt(m, "device_state")),
	}
}

// parseDoIPUDS parses the uds sub-map of a DoIP message.
func parseDoIPUDS(v interface{}) *DoIPUDS {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPUDS{
		ServiceID:            uint8(getInt(m, "service_id")),
		IsResponse:           getBool(m, "is_response", false),
		HasSubFunction:       getBoolPtr(m, "has_sub_function"),
		SubFunction:          uint8(getInt(m, "sub_function")),
		DID:                  getByteSlice(m, "did"),
		Data:                 getHexBytes(m, "data"),
		AddressAndLength:     getHexBytes(m, "address_and_length"),
		BlockSequenceCounter: uint8(getInt(m, "block_sequence_counter")),
		TransferData:         getHexBytes(m, "transfer_data"),
		Seed:                 getByteSlice(m, "seed"),
		Key:                  getByteSlice(m, "key"),
		NegativeResponseCode: uint8(getInt(m, "negative_response_code")),
	}
}

// parseDoIPMessages parses the messages array of a DoIP config.
func parseDoIPMessages(v interface{}) []DoIPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DoIPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var nackPtr *uint8
		if v, present := m["nack_code"]; present && v != nil {
			n := uint8(toInt(v))
			nackPtr = &n
		}
		out = append(out, DoIPMessage{
			Direction:     getString(m, "direction"),
			SourceAddress: getUint16(m, "source_address"),
			TargetAddress: getUint16(m, "target_address"),
			AckCode:       uint8(getInt(m, "ack_code")),
			NackCode:      nackPtr,
			UserData:      getByteSlice(m, "user_data"),
			UDS:           parseDoIPUDS(m["uds"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDoIPDiscovery parses the discovery sub-map of a DoIP config.
func parseDoIPDiscovery(v interface{}) *DoIPDiscovery {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPDiscovery{
		Direction:             getString(m, "direction"),
		RequestType:           getUint16(m, "request_type"),
		Broadcast:             getBool(m, "broadcast", false),
		AnnouncementCount:     uint8(getInt(m, "announcement_count")),
		FurtherActionRequired: uint8(getInt(m, "further_action_required")),
		SyncStatus:            uint8(getInt(m, "sync_status")),
	}
}

// parseDoIPEntityStatus parses the entity_status sub-map of a DoIP config.
func parseDoIPEntityStatus(v interface{}) *DoIPEntityStatus {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPEntityStatus{
		Direction:      getString(m, "direction"),
		NodeType:       uint8(getInt(m, "node_type")),
		MaxOpenSockets: uint8(getInt(m, "max_open_sockets")),
		CurOpenSockets: uint8(getInt(m, "cur_open_sockets")),
		MaxDataSize:    getUint32(m, "max_data_size"),
	}
}

// parseDoIPPowerMode parses the power_mode sub-map of a DoIP config.
func parseDoIPPowerMode(v interface{}) *DoIPPowerMode {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPPowerMode{
		Direction: getString(m, "direction"),
		PowerMode: uint8(getInt(m, "power_mode")),
		Broadcast: getBool(m, "broadcast", false),
	}
}

// parseDoIPActivation parses the activation sub-map of a DoIP config.
func parseDoIPActivation(v interface{}) *DoIPActivation {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPActivation{
		Direction:            getString(m, "direction"),
		ActivationType:       uint8(getInt(m, "activation_type")),
		ResponseCode:         uint8(getInt(m, "response_code")),
		OEMSpecific:          getByteSlice(m, "oem_specific"),
		ConfirmationRequired: getBool(m, "confirmation_required", false),
	}
}

// parseDoIPAliveCheck parses the alive_check sub-map of a DoIP config.
func parseDoIPAliveCheck(v interface{}) *DoIPAliveCheck {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPAliveCheck{
		Direction:     getString(m, "direction"),
		SourceAddress: getUint16(m, "source_address"),
	}
}

// parseDoIPGenericNack parses the generic_nack sub-map of a DoIP config.
func parseDoIPGenericNack(v interface{}) *DoIPGenericNack {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return &DoIPGenericNack{
		NackCode: uint8(getInt(m, "nack_code")),
	}
}

// parseDoIPConfig converts the JSON-decoded "doip" sub-map into a
// core.DoIPConfig.
func parseDoIPConfig(m map[string]interface{}) *DoIPConfig {
	if m == nil {
		return nil
	}
	return &DoIPConfig{
		ProtocolVersion: uint8(getInt(m, "protocol_version")),
		SrcIP:           getString(m, "src_ip"),
		DstIP:           getString(m, "dst_ip"),
		SrcPort:         getUint16(m, "src_port"),
		VIN:             getString(m, "vin"),
		LogicalAddress:  getUint16(m, "logical_address"),
		TesterAddress:   getUint16(m, "tester_address"),
		EID:             getString(m, "eid"),
		GID:             getString(m, "gid"),
		Discovery:       parseDoIPDiscovery(m["discovery"]),
		EntityStatus:    parseDoIPEntityStatus(m["entity_status"]),
		PowerMode:       parseDoIPPowerMode(m["power_mode"]),
		Activation:      parseDoIPActivation(m["activation"]),
		Messages:        parseDoIPMessages(m["messages"]),
		AliveCheck:      parseDoIPAliveCheck(m["alive_check"]),
		GenericNack:     parseDoIPGenericNack(m["generic_nack"]),
	}
}

// parseSMBOperations parses the operations array of an SMB config.
func parseSMBOperations(v interface{}) []SMBOperation {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SMBOperation, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, SMBOperation{
			OpType:        getString(m, "op_type"),
			Offset:        getUint64(m, "offset"),
			Length:        getUint32(m, "length"),
			Data:          getByteSlice(m, "data"),
			DataB64:       getString(m, "data_b64"),
			FileName:      getString(m, "file_name"),
			InfoClass:     uint8(getInt(m, "info_class")),
			InfoType:      uint8(getInt(m, "info_type")),
			FileInfoClass: uint8(getInt(m, "file_info_class")),
			MinimumCount:  getUint32(m, "minimum_count"),
			Flags:         getUint32(m, "flags"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSMBConfig converts the JSON-decoded "smb" sub-map into a
// core.SMBConfig.
func parseSMBConfig(m map[string]interface{}) *SMBConfig {
	if m == nil {
		return nil
	}
	cfg := &SMBConfig{
		Transport:                      getString(m, "transport"),
		Dialects:                       getStringSlice(m, "dialects"),
		SelectedDialect:                getString(m, "selected_dialect"),
		ClientCapabilities:             getUint32(m, "client_capabilities"),
		ServerCapabilities:             getUint32(m, "server_capabilities"),
		SecurityMode:                   getUint16(m, "security_mode"),
		SigningRequired:                getBool(m, "signing_required", false),
		AuthMechanism:                  getString(m, "auth_mechanism"),
		Username:                       getString(m, "username"),
		Domain:                         getString(m, "domain"),
		Password:                       getString(m, "password"),
		SecurityBlob:                   getByteSlice(m, "security_blob"),
		AuthRounds:                     getInt(m, "auth_rounds"),
		TreeConnectShare:               getString(m, "tree_connect_share"),
		ShareType:                      uint8(getInt(m, "share_type")),
		FilePath:                       getString(m, "file_path"),
		CreateDisposition:              uint8(getInt(m, "create_disposition")),
		AccessMask:                     getUint32(m, "access_mask"),
		FileAttributes:                 getUint32(m, "file_attributes"),
		ShareAccess:                    uint8(getInt(m, "share_access")),
		CreateOptions:                  getUint32(m, "create_options"),
		Operations:                     parseSMBOperations(m["operations"]),
		PreauthIntegrityHashAlgorithms: getUint16Slice(m, "preauth_integrity_hash_algorithms"),
		EncryptionAlgorithm:            getUint16(m, "encryption_algorithm"),
		ErrorOnCommand:                 getString(m, "error_on_command"),
		ErrorResponseStatus:            getUint32(m, "error_response_status"),
		// Sizes (NBSS 24-bit limit = 16777215)
		MaxTransactSize: getUint32(m, "max_transact_size"),
		MaxReadSize:     getUint32(m, "max_read_size"),
		MaxWriteSize:    getUint32(m, "max_write_size"),
		// SMB3 高级
		EncryptionRequired: getBool(m, "encryption_required", false),
		// 会话拆解控制
		IncludeNegotiate:   getBoolPtr(m, "include_negotiate"),
		IncludeAuth:        getBoolPtr(m, "include_auth"),
		IncludeTreeConnect: getBoolPtr(m, "include_tree_connect"),
		IncludeTeardown:    getBoolPtr(m, "include_teardown"),
		PreviousSessionId:  getUint64(m, "previous_session_id"),
	}
	// ops-level file_id hex string → per-op FileId ([16]byte only decodes
	// numeric arrays via encoding/json, so the tolerant flat decoder fills
	// it here; translateSMBConfigFromMap reuses this function).
	if arr, ok := m["operations"].([]interface{}); ok {
		for i, item := range arr {
			if i >= len(cfg.Operations) {
				break
			}
			om, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if f, ok := om["file_id"].(string); ok && len(f) >= 32 {
				parseGUIDString(f, &cfg.Operations[i].FileId)
			}
		}
	}
	// GUIDs: parse if provided as JSON hex string ("01020304...")
	if g, ok := m["client_guid"].(string); ok && len(g) >= 32 {
		parseGUIDString(g, &cfg.ClientGuid)
	}
	if g, ok := m["server_guid"].(string); ok && len(g) >= 32 {
		parseGUIDString(g, &cfg.ServerGuid)
	}
	if f, ok := m["file_id"].(string); ok && len(f) >= 32 {
		parseGUIDString(f, &cfg.FileId)
	}
	return cfg
}

// parseGUIDString decodes a 32-char hex string into dst. Invalid hex or wrong
// length is silently ignored (applyDefaults will fill zeros).
func parseGUIDString(s string, dst *[16]byte) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) < 32 {
		return
	}
	for i := 0; i < 16; i++ {
		hi, hOK := hexValue(s[2*i])
		lo, lOK := hexValue(s[2*i+1])
		if !hOK || !lOK {
			return
		}
		dst[i] = byte(hi<<4 | lo)
	}
}

func hexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// parseMCPConfig converts the JSON-decoded "mcp" sub-map into a
// core.MCPConfig. The config is round-tripped through encoding/json
// because its nested fields use json.RawMessage / map[string]any whose
// helpers (getString etc.) cannot represent generic JSON faithfully.
func parseMCPConfig(m map[string]interface{}) *MCPConfig {
	if m == nil {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var cfg MCPConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	return &cfg
}

func parseSVConfig(m map[string]interface{}) *SVConfig {
	c := &SVConfig{SVID: getString(m, "sv_id"), DatSet: getString(m, "dat_set"), APPID: uint16(getInt(m, "appid")), ConfRev: uint32(getInt(m, "conf_rev")), SamplesPerCycle: uint16(getInt(m, "samples_per_cycle")), SMPSynch: uint8(getInt(m, "smp_synch")), SMPRate: uint16(getInt(m, "smp_rate")), PeriodUS: getInt(m, "period_us"), Count: getInt(m, "count"), DstMAC: getString(m, "dst_mac"), DoubleSend: getBool(m, "double_send", false), VLANEnabled: getBool(m, "vlan_enabled", false), VLANID: uint16(getInt(m, "vlan_id")), VLANPriority: uint8(getInt(m, "vlan_priority"))}
	if a, ok := m["data"].([]interface{}); ok {
		for _, v := range a {
			if x, ok := v.(map[string]interface{}); ok {
				typ := getString(x, "type")
				d := SVData{Name: getString(x, "name"), Type: typ, InstMag: int32(getInt(x, "inst_mag")), Quality: uint32(getInt(x, "quality"))}
				if _, ok := x["quality"]; ok {
					d.HasQuality = true
				}
				if typ == "float32" {
					d.InstMagF = float32(getFloat64(x, "inst_mag"))
				}
				c.Data = append(c.Data, d)
			}
		}
	}
	return c
}
func parseGOOSEConfig(m map[string]interface{}) *GOOSEConfig {
	b := &GOOSEConfig{
		APPID: uint16(getInt(m, "appid")), GOCBRef: getString(m, "gocb_ref"),
		DatSet: getString(m, "dat_set"), GOID: getString(m, "go_id"),
		TALMs: uint32(getInt(m, "tal_ms")), ConfRev: uint32(getInt(m, "conf_rev")),
		StartSTNum: uint32(getInt(m, "start_stnum")), StartSQNum: uint32(getInt(m, "start_sqnum")),
		Test: getBool(m, "test", false), NDSCom: getBool(m, "nds_com", false),
		Boolean: getBool(m, "boolean", false), Count: getInt(m, "count"),
		DstMAC: getString(m, "dst_mac"), VLANEnabled: getBool(m, "vlan_enabled", false),
		VLANID: uint16(getInt(m, "vlan_id")), VLANPriority: uint8(getInt(m, "vlan_priority")),
	}
	if data, ok := m["data"].([]interface{}); ok {
		for _, raw := range data {
			if item, ok := raw.(map[string]interface{}); ok {
				b.Data = append(b.Data, GOOSEData{Name: getString(item, "name"), Type: getString(item, "type"), Value: item["value"], BitLength: getInt(item, "bit_length")})
			}
		}
	}
	if seq, ok := m["event_seq"].([]interface{}); ok {
		for _, raw := range seq {
			if item, ok := raw.(map[string]interface{}); ok {
				b.EventSeq = append(b.EventSeq, GOOSEEventSeq{
					DataIdx:     getInt(item, "data_idx"),
					DelayMs:     getInt(item, "delay_ms"),
					Retransmits: getInt(item, "retransmits"),
					SqNumStep:   getInt(item, "sqnum_step"),
				})
			}
		}
	}
	return b
}

// CheckProtoFlat (Step 1 全协议扁平删除)：除 ftp 外的全体协议，顶层
// src_ip/dst_ip/src_port/dst_port/count 任一出现即拒绝，返回通用迁移指引
// 文案（层链形状：地址进 ip 层、端口进 tcp/udp 层、数量走 flow_control）。
// ftp 委托原 CheckFTPFlat（文案锁死，逐字一致）。schema 层（strategy
// create/update 400）与 convert.go ValidateBatchSpec（batch 类 shape 门）
// 共用此函数，保证文案不漂移。nil 值视为未出现（JSON null = 缺省）；
// 层链形状（无顶层扁平键）与顶层同名子映射（现行协议配置载体，各协议
// P-PIPE 改写时才迁入层内）不触发。导出供 schema 包调用
// （schema import core，反向不可）。
func CheckProtoFlat(protocol string, cfg map[string]interface{}) string {
	if protocol == "ftp" {
		return CheckFTPFlat(cfg)
	}
	if cfg == nil {
		return ""
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		if v, ok := cfg[k]; ok && v != nil {
			return "protocol " + protocol + " no longer accepts flat config field " + k +
				" (use a layers chain: ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports, flow_control for the flow count)"
		}
	}
	// D-HTTP-1 重走步骤 3：http 族 9 协议顶层 http 子映射 presence 判死
	// （ftp 范本同构；空 map 也判死——presence 语义与 ParseHTTPConfigFromMap
	// 一致：{"http":{}} 即显式走默认）。非 http 族协议的顶层 http 沿旧口径
	// （tftp V20 互斥门仍由 planner 报 "http field must not be set"）。
	switch protocol {
	case "http", "http_flv", "hls", "hds", "gbt", "getwork", "cwmp", "doh", "onvif":
		if v, ok := cfg["http"]; ok && v != nil {
			return "protocol " + protocol + " no longer accepts a top-level http sub-config (move it into the http layer of a [ip,tcp,http] layers chain)"
		}
	}
	// D-DNS-1：dns 顶层 dns 子映射 presence 判死（http 族先例；空 map 也
	// 死——presence 语义与 ParseHTTPConfigFromMap 一致）。层链形状不触发。
	if protocol == "dns" {
		if v, ok := cfg["dns"]; ok && v != nil {
			return "protocol dns no longer accepts a top-level dns sub-config (move it into the dns layer of an [ip,udp,dns] layers chain)"
		}
	}
	// D-MQTT-1：mqtt 顶层 mqtt 子映射 presence 判死（dns 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "mqtt" {
		if v, ok := cfg["mqtt"]; ok && v != nil {
			return "protocol mqtt no longer accepts a top-level mqtt sub-config (move it into the mqtt layer of an [ip,tcp,mqtt] layers chain)"
		}
	}
	// D-CWMP-1：cwmp 顶层 cwmp 子映射 presence 判死（mqtt 先例；空 map 也
	// 死——B6 注入形退役，配置迁 cwmp 层六键）。层链形状不触发。
	if protocol == "cwmp" {
		if v, ok := cfg["cwmp"]; ok && v != nil {
			return "protocol cwmp no longer accepts a top-level cwmp sub-config (move it into the cwmp layer of a [ip,tcp,http,cwmp] layers chain)"
		}
	}
	// D-MEGACO-1：megaco 顶层 megaco 子映射 presence 判死（cwmp 先例；空
	// map 也死——B6 顶层注入形退役，配置迁 megaco 层七键）。层链形状不触发。
	if protocol == "megaco" {
		if v, ok := cfg["megaco"]; ok && v != nil {
			return "protocol megaco no longer accepts a top-level megaco sub-config (move it into the megaco layer of an [ip,udp,megaco] layers chain; tcp carrier = [ip,tcp,megaco] with RFC 1006 TPKT framing)"
		}
	}
	// D-HL7-1：hl7 顶层 hl7 子映射 presence 判死（megaco 先例；空 map 也
	// 死——B6 扁平注入形退役，配置迁 hl7 层八键）。层链形状不触发。
	if protocol == "hl7" {
		if v, ok := cfg["hl7"]; ok && v != nil {
			return "protocol hl7 no longer accepts a top-level hl7 sub-config (move it into the hl7 layer of an [ip,tcp,hl7] layers chain; MLLP framing lives in the hl7 layer)"
		}
	}
	// D-MMSE-1：mmse 顶层 mmse 子映射 presence 判死（hl7 先例；空 map 也
	// 死——B6 扁平注入形退役，配置迁 mmse 层五键）。层链形状不触发。
	if protocol == "mmse" {
		if v, ok := cfg["mmse"]; ok && v != nil {
			return "protocol mmse no longer accepts a top-level mmse sub-config (move it into the mmse layer of an [ip,tcp,http,mmse] layers chain; WAP-209 PDU config lives in the mmse layer)"
		}
	}
	// D-NTLM-1：ntlm 顶层 ntlm 子映射 presence 判死（bacnet 先例；空 map
	// 也死——1.11–1.13 白名单制：顶层只允许 layers/flow_control 家族/output）。
	// 层链形状不触发。
	if protocol == "ntlm" {
		if v, ok := cfg["ntlm"]; ok && v != nil {
			return "protocol ntlm no longer accepts a top-level ntlm sub-config (move it into the ntlm layer of an [ip,tcp,ntlm] layers chain)"
		}
	}
	// D-OCSP-1：ocsp 顶层 ocsp 子映射 presence 判死（mmse 先例；空 map 也
	// 死——新协议无扁平存量，配置迁 ocsp 层键，层链形状不触发）。
	if protocol == "ocsp" {
		if v, ok := cfg["ocsp"]; ok && v != nil {
			return "protocol ocsp no longer accepts a top-level ocsp sub-config (move it into the ocsp layer of an [ip,tcp,http,ocsp] layers chain; RFC 6960/8954 OCSP config lives in the ocsp layer)"
		}
	}
	// D-SPNEGO-1：spnego 顶层 spnego 子映射 presence 判死（ntlm 先例；空
	// map 也死——1.11–1.13 白名单制：顶层只允许 layers/flow_control 家族/
	// output）。层链形状不触发。
	if protocol == "spnego" {
		if v, ok := cfg["spnego"]; ok && v != nil {
			return "protocol spnego no longer accepts a top-level spnego sub-config (move it into the spnego layer of an [ip,tcp,spnego] layers chain)"
		}
	}
	// D-AMQP-1：amqp 顶层 amqp 子映射 presence 判死（ocsp 先例；空 map 也
	// 死——新协议无扁平存量，配置迁 amqp 层键，层链形状不触发）。
	if protocol == "amqp" {
		if v, ok := cfg["amqp"]; ok && v != nil {
			return "protocol amqp no longer accepts a top-level amqp sub-config (move it into the amqp layer of an [ip,tcp,amqp] layers chain; AMQP 0-9-1 config lives in the amqp layer)"
		}
	}
	// D-EDP-1：edp 顶层 edp 子映射 presence 判死（mmse 先例；空 map 也
	// 死——B6 扁平注入形退役，配置迁 edp 层三键）。层链形状不触发。
	if protocol == "edp" {
		if v, ok := cfg["edp"]; ok && v != nil {
			return "protocol edp no longer accepts a top-level edp sub-config (move it into the edp layer of an [ip,tcp,edp] layers chain; OneNET EDP framing lives in the edp layer)"
		}
	}
	// D-XMR-1：xmrmining 顶层 xmrmining 子映射 presence 判死（edp 先例；空
	// map 也死——B6 扁平注入形退役，配置迁 xmrmining 层键）。层链形状不触发。
	if protocol == "xmrmining" {
		if v, ok := cfg["xmrmining"]; ok && v != nil {
			return "protocol xmrmining no longer accepts a top-level xmrmining sub-config (move it into the xmrmining layer of an [ip,tcp,xmrmining] layers chain; Monero stratum framing lives in the xmrmining layer)"
		}
	}
	// D-SMB-1：smb 顶层 smb 子映射 presence 判死（bacnet 先例；空 map 也
	// 死——B6 扁平注入形退役，配置迁 smb 层 34 键）。层链形状不触发。
	if protocol == "smb" {
		if v, ok := cfg["smb"]; ok && v != nil {
			return "protocol smb no longer accepts a top-level smb sub-config (move it into the smb layer of an [ip,tcp,smb] layers chain)"
		}
	}
	// D-BACNET-1：bacnet 顶层 bacnet 子映射 presence 判死（xmrmining 先例；
	// 空 map 也死——B6 扁平注入形退役，配置迁 bacnet 层键）。层链形状不触发。
	if protocol == "bacnet" {
		if v, ok := cfg["bacnet"]; ok && v != nil {
			return "protocol bacnet no longer accepts a top-level bacnet sub-config (move it into the bacnet layer of an [ip,udp,bacnet] layers chain; BACnet/IP Annex J framing lives in the bacnet layer)"
		}
	}
	// D-SMTP-1：smtp 顶层 smtp 子映射 presence 判死（mqtt 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "smtp" {
		if v, ok := cfg["smtp"]; ok && v != nil {
			return "protocol smtp no longer accepts a top-level smtp sub-config (move it into the smtp layer of an [ip,tcp,smtp] layers chain)"
		}
	}
	// D-POP3-1：pop3 顶层 pop3 子映射 presence 判死（smtp 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "pop3" {
		if v, ok := cfg["pop3"]; ok && v != nil {
			return "protocol pop3 no longer accepts a top-level pop3 sub-config (move it into the pop3 layer of an [ip,tcp,pop3] layers chain)"
		}
	}
	// D-NFS-1：nfs 顶层 nfs 子映射 presence 判死（pop3 先例；空 map 也
	// 死——配置住 nfs 层，层链是唯一真相）。层链形状不触发。
	if protocol == "nfs" {
		if v, ok := cfg["nfs"]; ok && v != nil {
			return "protocol nfs no longer accepts a top-level nfs sub-config (move it into the nfs layer of an [ip,tcp,nfs] layers chain)"
		}
	}
	// D-SSTP-1：sstp 顶层 sstp 子映射 presence 判死（kerberos 之后的 sstp
	// 层链唯一真相；空 map 也死——契约 §16-P2 点名形状「层链+顶层空子映射
	// 并存=判死负例」）。层链形状不触发。
	if protocol == "sstp" {
		if v, ok := cfg["sstp"]; ok && v != nil {
			return "protocol sstp no longer accepts a top-level sstp sub-config (move it into the sstp layer of an [ip,tcp,tls,sstp] layers chain; the layer chain is the only config truth)"
		}
	}
	// D-TFTP-1：tftp 顶层 tftp 子映射 presence 判死（sstp 先例；空 map 也
	// 死——契约 §13-P2 点名形状「层链+顶层空子映射并存=判死负例」）。
	// 层链形状不触发。
	if protocol == "tftp" {
		if v, ok := cfg["tftp"]; ok && v != nil {
			return "protocol tftp no longer accepts a top-level tftp sub-config (move it into the tftp layer of an [ip,udp,tftp] layers chain; the layer chain is the only config truth)"
		}
	}
	// D-IMAP-1：imap 顶层 imap 子映射 presence 判死（pop3 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "imap" {
		if v, ok := cfg["imap"]; ok && v != nil {
			return "protocol imap no longer accepts a top-level imap sub-config (move it into the imap layer of an [ip,tcp,imap] layers chain)"
		}
	}
	// D-MCP-1：mcp 顶层 mcp 子映射 presence 判死（imap 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "mcp" {
		if v, ok := cfg["mcp"]; ok && v != nil {
			return "protocol mcp no longer accepts a top-level mcp sub-config (move it into the mcp layer of an [ip,tcp,mcp] layers chain)"
		}
	}
	// D-SRV6-1：srv6 顶层 srv6 子映射 presence 判死（mcp 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "srv6" {
		if v, ok := cfg["srv6"]; ok && v != nil {
			return "protocol srv6 no longer accepts a top-level srv6 sub-config (move it into the srv6 layer of an [ip,srv6] layers chain)"
		}
	}
	// D-FINS-1：fins 顶层 fins 子映射 presence 判死（srv6 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "fins" {
		if v, ok := cfg["fins"]; ok && v != nil {
			return "protocol fins no longer accepts a top-level fins sub-config (move it into the fins layer of a layers chain: ip + udp/tcp carrier + fins)"
		}
	}
	// D-GOOSE-1：goose 顶层 goose 子映射 presence 判死（fins 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "goose" {
		if v, ok := cfg["goose"]; ok && v != nil {
			return "protocol goose no longer accepts a top-level goose sub-config (move it into the goose layer of an [eth,goose] layers chain)"
		}
	}
	// D-SV-1：sv 顶层 sv 子映射 presence 判死（goose 先例；空 map 也
	// 死）。层链形状不触发。
	if protocol == "sv" {
		if v, ok := cfg["sv"]; ok && v != nil {
			return "protocol sv no longer accepts a top-level sv sub-config (move it into the sv layer of an [eth,sv] layers chain)"
		}
	}
	// D-ICMPV6-1：icmpv6 顶层 icmpv6 子映射 presence 判死（sv 先例；空
	// map 也死）。层链形状不触发。
	if protocol == "icmpv6" {
		if v, ok := cfg["icmpv6"]; ok && v != nil {
			return "protocol icmpv6 no longer accepts a top-level icmpv6 sub-config (move it into the icmpv6 layer of an [ip,icmpv6] layers chain)"
		}
	}
	// D-H323-1：h323 顶层 h323 子映射 presence 判死（icmpv6 先例；空
	// map 也死）。层链形状不触发。
	if protocol == "h323" {
		if v, ok := cfg["h323"]; ok && v != nil {
			return "protocol h323 no longer accepts a top-level h323 sub-config (move it into the h323 layer of an [ip,h323] layers chain)"
		}
	}
	// D-MPLS-1：mpls 顶层 mpls 子映射 presence 判死（h323 先例；空
	// map 也死）。层链形状不触发。
	if protocol == "mpls" {
		if v, ok := cfg["mpls"]; ok && v != nil {
			return "protocol mpls no longer accepts a top-level mpls sub-config (move it into the mpls layer of an [ip,mpls] layers chain)"
		}
	}
	// D-NGAP-1：ngap 顶层 ngap 子映射 presence 判死（h323/mpls 同款；
	// 空 map 也死）。层链形状不触发。
	if protocol == "ngap" {
		if v, ok := cfg["ngap"]; ok && v != nil {
			return "protocol ngap no longer accepts a top-level ngap sub-config (move it into the ngap layer of an [ip,ngap] layers chain)"
		}
	}
	// D-TELNET-1：telnet 顶层 telnet 子映射 presence 判死（h323/mpls/ngap
	// 同款；空 map 也死）。层链形状不触发。
	if protocol == "telnet" {
		if v, ok := cfg["telnet"]; ok && v != nil {
			return "protocol telnet no longer accepts a top-level telnet sub-config (move it into the telnet layer of an [ip,telnet] layers chain)"
		}
	}
	// D-SIP-1：sip 顶层 sip 子映射 presence 判死（前四协议同款；空 map
	// 也死）。层链形状不触发。
	if protocol == "sip" {
		if v, ok := cfg["sip"]; ok && v != nil {
			return "protocol sip no longer accepts a top-level sip sub-config (move it into the sip layer of an [ip,sip] layers chain)"
		}
	}
	// D-RADIUS-1：radius 顶层 radius 子映射 presence 判死（前六协议同款；
	// 空 map 也死）。层链形状不触发。
	if protocol == "radius" {
		if v, ok := cfg["radius"]; ok && v != nil {
			return "protocol radius no longer accepts a top-level radius sub-config (move it into the radius layer of an [ip,radius] layers chain)"
		}
	}
	// D-TDS-1：tds 顶层 tds 子映射 presence 判死（mqtt 先例；空 map 也
	// 死——B6 扁平注入形退役，配置迁 tds 层十六键）。层链形状不触发。
	if protocol == "tds" {
		if v, ok := cfg["tds"]; ok && v != nil {
			return "protocol tds no longer accepts a top-level tds sub-config (move it into the tds layer of an [ip,tcp,tds] layers chain)"
		}
	}
	// D-ENIP-1（G-ENIP-3，§14-P2）：enip 顶层 enip 子映射 presence 判死
	// （sstp 先例；空 map 也死——135/135 例并存现状的执法口；§14.1 六键
	// commands/io_data/transport/scenario/session_count/flow_count 迁
	// layers[i].enip）。层链形状不触发。
	if protocol == "enip" {
		if v, ok := cfg["enip"]; ok && v != nil {
			return "protocol enip no longer accepts a top-level enip sub-config (move it into the enip layer of an [ip,tcp,enip] layers chain; the layer chain is the only config truth)"
		}
	}
	// D-MMS-2（G-MMS-1，§14-P2）：mms 顶层 mms 子映射 presence 判死
	// （enip 先例；空 map 也死——配置迁 mms 层 12 键，层链是唯一真相）。
	// 层链形状不触发。
	if protocol == "mms" {
		if v, ok := cfg["mms"]; ok && v != nil {
			return "protocol mms no longer accepts a top-level mms sub-config (move it into the mms layer of an [ip,tcp,mms] layers chain; the layer chain is the only config truth)"
		}
	}
	// D-*-1 raw 自驱八协议：顶层同名子映射 presence 判死（mcp 先例；空
	// map 也死）。这些协议的顶层子映射在 mapToFlowSpec（universal 段 :517
	// 或 flat case）先于 translateTerminalConfig 填 spec，层链形状下顶层
	// 子映射静默赢层配置（隔离复审 F1 探针实证 abort 走顶层、chunks 走
	// 层链的混搭缝）——必须在此判死。层链形状不触发。
	rawWrapChains := map[string]string{
		"pppoe": "[ip,pppoe]", "ldap": "[ip,ldap]", "rtmp": "[ip,rtmp]",
		"rtsp": "[ip,rtsp]", "pptp": "[ip,pptp]", "vnc": "[ip,vnc]",
		"xmpp": "[ip,xmpp]", "sctp": "[ip,sctp]",
		"jt808": "[ip,jt808]", "jt809": "[ip,jt809]", "jtt905": "[ip,jtt905]",
		"arp": "[eth,arp]", "icmp": "[ip,icmp]",
	}
	if chainHint, ok := rawWrapChains[protocol]; ok {
		if v, ok := cfg[protocol]; ok && v != nil {
			return "protocol " + protocol + " no longer accepts a top-level " + protocol +
				" sub-config (move it into the " + protocol + " layer of a " + chainHint + " layers chain)"
		}
	}
	return ""
}

// CheckFTPFlat (Task 5 扁平删除, FTP 层链收尾计划): protocol==ftp 时顶层
// src_ip/dst_ip/src_port/dst_port/count 任一或顶层 ftp 子映射出现即拒绝，
// 返回 checkLayerFlatConflict 家族文案（给迁移指引）。schema 层
// （strategy create/update 400）与 mapToFlowSpec（在库旧策略/引擎直调 →
// spec.ValidationErrors）共用此函数，保证两处文案不漂移。nil 值视为未出现
// （JSON null = 缺省）；层链形状（无顶层扁平键）不触发。导出供
// schema 包调用（schema import core，反向不可）。
func CheckFTPFlat(cfg map[string]interface{}) string {
	if cfg == nil {
		return ""
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		if v, ok := cfg[k]; ok && v != nil {
			return "protocol ftp no longer accepts flat config field " + k +
				" (FTP requires a layers chain: ip.src/ip.dst for addresses, tcp src_port/dst_port for ports, flow_control for the flow count)"
		}
	}
	if v, ok := cfg["ftp"]; ok && v != nil {
		return "protocol ftp no longer accepts a top-level ftp sub-config (move it into the ftp layer of an [ip,tcp,ftp] layers chain)"
	}
	return ""
}

// ParseFTPConfigFromMap decodes an ftp layer/terminal config map into an
// *FTPConfig (exported for layers.translateTerminalConfig; single truth with
// the flat cfg["ftp"] branch of mapToFlowSpec — same parse functions, same
// defaults). Returns nil for absent/non-map input. file_source inside
// data_channel (and per-transaction data_channel) is honored, mirroring the
// flat FileSource override block.
func ParseFTPConfigFromMap(m map[string]interface{}) *FTPConfig {
	if m == nil {
		return nil
	}
	fc := &FTPConfig{
		Banner:      getString(m, "banner"),
		Commands:    parseFTPCommands(m["commands"]),
		DataChannel: parseFTPDataChannel(m["data_channel"]),
		Sessions:    parseFTPSessions(m["sessions"]),
	}
	if fc.DataChannel != nil {
		if dcFS := parseFileSource(getMap(m, "data_channel")); dcFS != nil {
			fc.DataChannel.FileSource = dcFS
		}
	}
	for si := range fc.Sessions {
		for ti := range fc.Sessions[si].Transactions {
			dc := fc.Sessions[si].Transactions[ti].DataChannel
			if dc == nil {
				continue
			}
			if dcFS := parseFileSource(getTxDataChannelMap(m, si, ti)); dcFS != nil {
				dc.FileSource = dcFS
			}
		}
	}
	if fc.Banner == "" && fc.Commands == nil && fc.DataChannel == nil && fc.Sessions == nil {
		return nil
	}
	return fc
}

// ParseHTTPConfigFromMap decodes an http layer/terminal config map into an
// *HTTPConfig (D-HTTP-1 重走步骤 2; exported for layers.translateTerminalConfig;
// single truth with the universal cfg["http"] read above — same parse, same
// defaults). nil input → nil (absent). Empty map → non-nil zero config
// (presence: {"http":{}} takes GET///200 defaults, same as an explicit map).
// version is stored bare (no "HTTP/" prefix); the layer-translation side
// prefixes, the universal-read side leaves bare for the builder default.
func ParseHTTPConfigFromMap(m map[string]interface{}) *HTTPConfig {
	if m == nil {
		return nil
	}
	// Backward compat: pre-rename strategies stored request headers
	// under the "headers" key. Prefer the new "request_headers" key
	// when present; fall back to legacy key so existing DB rows do
	// not silently lose user-configured headers.
	reqHeaders := getStringMap(m, "request_headers")
	if len(reqHeaders) == 0 {
		reqHeaders = getStringMap(m, "headers")
	}
	hc := &HTTPConfig{
		Method:                   getStringDefault(m, "method", "GET"),
		URI:                      getStringDefault(m, "uri", "/"),
		Version:                  getString(m, "version"),
		RequestHeaders:           reqHeaders,
		Body:                     getString(m, "body"),
		BodyB64:                  getString(m, "body_b64"),
		KeepAlive:                getBool(m, "keep_alive", false),
		Transactions:             getInt(m, "transactions"),
		ResponseHeaders:          getStringMap(m, "response_headers"),
		ResponseBody:             getString(m, "response_body"),
		ResponseBodyB64:          getString(m, "response_body_b64"),
		ResponseStatusCode:       getInt(m, "response_status_code"),
		ResponseStatusText:       getString(m, "response_status_text"),
		ResponseContentEncoding:  getStringWithFallback(m, "response_content_encoding", "content_encoding"),
		RequestContentEncoding:   getString(m, "request_content_encoding"),
		RequestTransferEncoding:  getString(m, "request_transfer_encoding"),
		ResponseTransferEncoding: getString(m, "response_transfer_encoding"),
		ChunkSize:                getInt(m, "chunk_size"),
		Pipelined:                getBool(m, "pipelined", false),
	}
	if hFS := parseFileSource(m); hFS != nil {
		hc.FileSource = hFS
	}
	return hc
}

// getTxDataChannelMap navigates sessions[si].transactions[ti].data_channel
// inside a decoded ftp config map. Returns nil when any level is absent.
func getTxDataChannelMap(m map[string]interface{}, si, ti int) map[string]interface{} {
	sessArr, ok := m["sessions"].([]interface{})
	if !ok || si < 0 || si >= len(sessArr) {
		return nil
	}
	sessm, ok := sessArr[si].(map[string]interface{})
	if !ok {
		return nil
	}
	txArr, ok := sessm["transactions"].([]interface{})
	if !ok || ti < 0 || ti >= len(txArr) {
		return nil
	}
	txm, ok := txArr[ti].(map[string]interface{})
	if !ok {
		return nil
	}
	dcm, ok := txm["data_channel"].(map[string]interface{})
	if !ok {
		return nil
	}
	return dcm
}

// parseEDPConfig converts the JSON-decoded "edp" sub-map into an *EDPConfig.
// Returns nil for absent/non-map input. Empty fields are left empty so
// the planner can apply its own defaults.
func parseEDPConfig(m map[string]interface{}) *EDPConfig {
	if m == nil {
		return nil
	}
	cfg := &EDPConfig{
		Profile:    getString(m, "profile"),
		WireFault:  getString(m, "wire_fault"),
		Concurrent: getBool(m, "concurrent", false),
	}
	if sessArr, ok := m["sessions"].([]interface{}); ok {
		for _, si := range sessArr {
			sessm, ok := si.(map[string]interface{})
			if !ok {
				continue
			}
			sess := EDPSession{
				SrcPort:    getUint16(sessm, "src_port"),
				DstPort:    getUint16(sessm, "dst_port"),
				Concurrent: getBool(sessm, "concurrent", false),
				Coalesce:   getBool(sessm, "coalesce", false),
			}
			if evArr, ok := sessm["events"].([]interface{}); ok {
				for _, ei := range evArr {
					evm, ok := ei.(map[string]interface{})
					if !ok {
						continue
					}
					ev := EDPEvent{
						Kind:       getString(evm, "kind"),
						Auth:       getString(evm, "auth"),
						Devid:      getString(evm, "devid"),
						APIKey:     getString(evm, "apikey"),
						UserID:     getString(evm, "userid"),
						AuthInfo:   getString(evm, "authinfo"),
						KeepTime:   getUint16Ptr(evm, "keep_time"),
						ConnackRtn: getIntPtr(evm, "connack_rtn"),
						Direction:  getString(evm, "direction"),
						DevidFlag:  getInt(evm, "devid_flag"),
						MsgIDFlag:  getInt(evm, "msg_id_flag"),
						MsgID:      getUint16Ptr(evm, "msg_id"),
						Format:     getInt(evm, "format"),
						JSONStr:    getString(evm, "json"),
						Desc:       getString(evm, "desc"),
						BinB64:     getString(evm, "bin_b64"),
						ErrCode:    getIntPtr(evm, "err_code"),
						DataB64:    getString(evm, "data_b64"),
						CmdID:      getString(evm, "cmdid"),
						ReqB64:     getString(evm, "req_b64"),
						RespB64:    getString(evm, "resp_b64"),
						WireFault:  getString(evm, "wire_fault"),
					}
					if ackVal, ok := evm["ack"].(bool); ok {
						ev.Ack = &ackVal
					}
					sess.Events = append(sess.Events, ev)
				}
			}
			cfg.Sessions = append(cfg.Sessions, sess)
		}
	}
	return cfg
}

// parseXMRConfig converts the JSON-decoded "xmrmining" sub-map into an
// *XMRConfig. Returns nil for absent/non-map input. Empty fields are left
// empty so the planner can apply its own defaults. 请求 id 在 map 面是
// float64——整数值还原为 JSON number 字面量（json.RawMessage）。
func parseXMRConfig(m map[string]interface{}) *XMRConfig {
	if m == nil {
		return nil
	}
	cfg := &XMRConfig{
		Profile:    getString(m, "profile"),
		WireFault:  getString(m, "wire_fault"),
		Concurrent: getBool(m, "concurrent", false),
	}
	if sessArr, ok := m["sessions"].([]interface{}); ok {
		for _, si := range sessArr {
			sessm, ok := si.(map[string]interface{})
			if !ok {
				continue
			}
			sess := XMRSession{
				SrcPort:    getUint16(sessm, "src_port"),
				DstPort:    getUint16(sessm, "dst_port"),
				Concurrent: getBool(sessm, "concurrent", false),
			}
			if evArr, ok := sessm["events"].([]interface{}); ok {
				for _, ei := range evArr {
					evm, ok := ei.(map[string]interface{})
					if !ok {
						continue
					}
					ev := XMREvent{
						Kind:           getString(evm, "kind"),
						Login:          getString(evm, "login"),
						Pass:           getString(evm, "pass"),
						Agent:          getString(evm, "agent"),
						Rigid:          getString(evm, "rigid"),
						SessionID:      getString(evm, "session_id"),
						Status:         getString(evm, "status"),
						KeepaliveAlias: getBool(evm, "keepalive_alias", false),
						Legacy:         getBool(evm, "legacy", false),
						JobID:          getString(evm, "job_id"),
						FBlob:          getString(evm, "blob"),
						FTarget:        getString(evm, "target"),
						FAlgo:          getString(evm, "f_algo"),
						FHeight:        getInt(evm, "height"),
						FSeedHash:      getString(evm, "seed_hash"),
						Nonce:          getString(evm, "nonce"),
						Result:         getString(evm, "result"),
						Algo:           getString(evm, "algo"),
						Sig:            getString(evm, "sig"),
						Commitment:     getString(evm, "commitment"),
						ErrCode:        getInt(evm, "err_code"),
						ErrMsg:         getString(evm, "err_msg"),
						WireFault:      getString(evm, "wire_fault"),
					}
					ev.PackNext = getBool(evm, "pack_next", false)
					if id, ok := jsonNumber(evm, "id"); ok {
						ev.ID = id
					}
					if extArr, ok := evm["extensions"].([]interface{}); ok {
						for _, ex := range extArr {
							if exs, ok := ex.(string); ok {
								ev.Extensions = append(ev.Extensions, exs)
							}
						}
					}
					if jm, ok := evm["job"].(map[string]interface{}); ok {
						ev.Job = &XMRJob{
							Blob:     getString(jm, "blob"),
							Algo:     getString(jm, "algo"),
							Height:   getInt(jm, "height"),
							SeedHash: getString(jm, "seed_hash"),
							JobID:    getString(jm, "job_id"),
							Target:   getString(jm, "target"),
							ID:       getString(jm, "id"),
						}
					}
					sess.Events = append(sess.Events, ev)
				}
			}
			cfg.Sessions = append(cfg.Sessions, sess)
		}
	}
	return cfg
}

// jsonNumber renders an integral JSON number member (map 面 float64) back to
// its literal bytes; non-integral or absent values are rejected（请求 id 恒
// 整数——login 恒 1、后续递增）.
func jsonNumber(m map[string]interface{}, key string) (json.RawMessage, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) {
		return nil, false
	}
	return json.RawMessage(strconv.FormatInt(int64(f), 10)), true
}
