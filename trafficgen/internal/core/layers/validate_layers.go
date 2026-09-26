package layers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// BuildLayersPlanner is the engine's injected layer-planner factory (P2c 层链
// 驱动生成): parses a raw "layers" config JSON into a per-task ChainPlanner.
// It re-runs the same parsing + completion + validation as ValidateLayers
// (strategy-creation-time validation is belt; this is braces — the stored
// config is trusted data, but a config edited out-of-band, or a layers JSON
// assembled by a non-validating caller, must still fail loudly at submit
// rather than silently generate a chain the registry would reject). The
// returned planner's Name is the effective protocol (given or inferred), so
// the worker's per-task lookup keys on it consistently with the legacy
// protocol-name planners. The protocol arg is the strategy's protocol field;
// when empty it is inferred from the chain (matching ValidateLayers).
func BuildLayersPlanner(protocol string, layersJSON json.RawMessage) (core.ProtocolPlanner, error) {
	// D-HL7-1 裁定2：tcp-only 载体在 ValidateLayers（含链补全）之前即拦
	// ——hl7 DependsOn tcp 会自动补 tcp 层，用户显式 udp 载体会先触发通用
	// "transport layer duplicated"（锚词到不了 carrier）。
	if protocol == "hl7" {
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			for _, item := range probe {
				if _, ok := item["udp"]; ok {
					return nil, fmt.Errorf("hl7 chain: udp carrier is not supported — hl7 rides tcp only (MLLP over a byte stream) (carrier)")
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						src, _ := ipcfg["src"].(string)
						dst, _ := ipcfg["dst"].(string)
						if src != "" && dst != "" && strings.Contains(src, ":") != strings.Contains(dst, ":") {
							return nil, fmt.Errorf("hl7 chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (address)", src, dst)
						}
					}
				}
			}
		}
	}
	if protocol == "edp" {
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			for _, item := range probe {
				if _, ok := item["udp"]; ok {
					return nil, fmt.Errorf("edp chain: udp carrier is not supported — edp rides tcp only (OneNET EDP over a byte stream) (carrier)")
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						src, _ := ipcfg["src"].(string)
						dst, _ := ipcfg["dst"].(string)
						if src != "" && dst != "" && strings.Contains(src, ":") != strings.Contains(dst, ":") {
							return nil, fmt.Errorf("edp chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (address)", src, dst)
						}
					}
				}
			}
		}
	}
	if protocol == "xmrmining" {
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			for _, item := range probe {
				if _, ok := item["udp"]; ok {
					return nil, fmt.Errorf("xmrmining chain: udp carrier is not supported — xmrmining rides tcp only (Monero stratum over a byte stream) (carrier)")
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						src, _ := ipcfg["src"].(string)
						dst, _ := ipcfg["dst"].(string)
						if src != "" && dst != "" && strings.Contains(src, ":") != strings.Contains(dst, ":") {
							return nil, fmt.Errorf("xmrmining chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (address)", src, dst)
						}
					}
				}
			}
		}
	}
	if protocol == "bacnet" {
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			hasUDP := false
			for _, item := range probe {
				if _, ok := item["tcp"]; ok {
					return nil, fmt.Errorf("bacnet chain: tcp carrier is not supported — BACnet/IP rides udp only (Annex J virtual link layer) (carrier)")
				}
				if _, ok := item["udp"]; ok {
					hasUDP = true
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						src, _ := ipcfg["src"].(string)
						dst, _ := ipcfg["dst"].(string)
						if src != "" && dst != "" && strings.Contains(src, ":") != strings.Contains(dst, ":") {
							return nil, fmt.Errorf("bacnet chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (family)", src, dst)
						}
					}
				}
			}
			if !hasUDP {
				return nil, fmt.Errorf("bacnet chain: missing udp carrier — BACnet/IP requires an [ip,udp,bacnet] chain (carrier)")
			}
		}
	}
	if protocol == "dcerpc" {
		// D-DCERPC-1 裁定1：缺 tcp 载体在 ValidateLayers（含链补全）之前拦
		// ——DependsOn tcp 会自动补 tcp 层，用户裸 dcerpc 层会被补全掩盖
		//（bacnet 缺 udp 预检同构，hl7 裁定2 注记先例）；混合地址族同面预检。
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			hasTCP := false
			for _, item := range probe {
				if _, ok := item["tcp"]; ok {
					hasTCP = true
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						srcS, _ := ipcfg["src"].(string)
						dstS, _ := ipcfg["dst"].(string)
						if srcS != "" && dstS != "" && strings.Contains(srcS, ":") != strings.Contains(dstS, ":") {
							return nil, fmt.Errorf("dcerpc chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (family)", srcS, dstS)
						}
					}
				}
			}
			if !hasTCP {
				return nil, fmt.Errorf("dcerpc chain: missing tcp carrier — DCE/RPC v5 requires an [ip,tcp,dcerpc] chain (carrier)")
			}
		}
	}
	if protocol == "dtls" {
		// D-DTLS-1：缺 udp 载体预检 + tcp 拒（bacnet/dcerpc 预检同构——
		// DependsOn udp 自动补全前拦，裸 dtls 层不被补全掩盖）；混合地址族同面。
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			hasUDP := false
			for _, item := range probe {
				if _, ok := item["tcp"]; ok {
					return nil, fmt.Errorf("dtls chain: tcp carrier is not supported — DTLS rides udp only (RFC 6347 datagram semantics) (carrier)")
				}
				if _, ok := item["udp"]; ok {
					hasUDP = true
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						srcD, _ := ipcfg["src"].(string)
						dstD, _ := ipcfg["dst"].(string)
						if srcD != "" && dstD != "" && strings.Contains(srcD, ":") != strings.Contains(dstD, ":") {
							return nil, fmt.Errorf("dtls chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (family)", srcD, dstD)
						}
					}
				}
			}
			if !hasUDP {
				return nil, fmt.Errorf("dtls chain: missing udp carrier — DTLS requires an [ip,udp,dtls] chain (carrier)")
			}
		}
	}
	if protocol == "kerberos" {
		// D-KERBEROS-1：双载体族预检（bacnet/dcerpc/dtls 预检同构——
		// DependsOn udp 自动补全前拦，裸 kerberos 层不被补全掩盖）。
		// udp 与 tcp 各自是合法载体（裁定1），但同链并存 = 载体冲突拒；
		// 缺载体同面拒。混合地址族同 dtls/bacnet 面（IPv4/IPv6 均合法，
		// 但 src/dst 必须同族——设计 §9）。
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			hasUDP, hasTCP := false, false
			for _, item := range probe {
				if _, ok := item["udp"]; ok {
					hasUDP = true
				}
				if _, ok := item["tcp"]; ok {
					hasTCP = true
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						srcD, _ := ipcfg["src"].(string)
						dstD, _ := ipcfg["dst"].(string)
						if srcD != "" && dstD != "" && strings.Contains(srcD, ":") != strings.Contains(dstD, ":") {
							return nil, fmt.Errorf("kerberos chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (family)", srcD, dstD)
						}
					}
				}
			}
			if hasUDP && hasTCP {
				return nil, fmt.Errorf("kerberos chain: udp and tcp carriers both present — one kerberos flow rides a single carrier (carrier)")
			}
			if !hasUDP && !hasTCP {
				return nil, fmt.Errorf("kerberos chain: missing udp/tcp carrier — kerberos requires an [ip,udp,kerberos] or [ip,tcp,kerberos] chain (carrier)")
			}
			// 会话 src_ip 覆盖是 UDP 面（datagram 端点覆盖——bacnet/dtls
			// 先例）；TCP 连接身份 = 四元组 connKey，带 DstIP 覆盖的 down
			// 事件会被折叠成第二条连接——tcp 载体 + src_ip 声明即拒。
			// 守卫住同步预检面（生成期错误会被 Plan goroutine 吞成空流
			// ——megaco 修轮⑨同教训）。
			if hasTCP {
				for _, item := range probe {
					rawK, ok := item["kerberos"]
					if !ok {
						continue
					}
					var kcfg struct {
						Sessions []map[string]json.RawMessage `json:"sessions"`
					}
					if json.Unmarshal(rawK, &kcfg) == nil {
						for si, se := range kcfg.Sessions {
							if v, ok := se["src_ip"]; ok && string(v) != `""` && string(v) != "null" {
								return nil, fmt.Errorf("kerberos chain: sessions[%d].src_ip override rides the udp carrier only — tcp flow identity is the connection four-tuple (carrier)", si)
							}
						}
					}
				}
			}
		}
	}
	if protocol == "ocsp" {
		// D-OCSP-1：双 profile 预检（dcerpc/dtls/kerberos 预检同构——
		// DependsOn tcp 自动补全前拦，裸 ocsp 层不被补全掩盖）。
		// ① profile↔http 层有无一致性（§11.4 裁定1：http profile 要求 http
		// 层在链、tcp profile 要求不在——nfs 链载体↔transport 同款结构性
		// 校验，不一致同步拒）；②缺 http/tcp 双载体同面拒；③混合地址族同
		// dtls/bacnet/kerberos 面。
		var probe []map[string]json.RawMessage
		if err := json.Unmarshal(layersJSON, &probe); err == nil {
			hasHTTP, hasTCP := false, false
			profiles := map[string]string{}
			for _, item := range probe {
				if _, ok := item["http"]; ok {
					hasHTTP = true
				}
				if _, ok := item["tcp"]; ok {
					hasTCP = true
				}
				if rawIP, ok := item["ip"]; ok && len(rawIP) > 0 {
					var ipcfg map[string]interface{}
					if err := json.Unmarshal(rawIP, &ipcfg); err == nil {
						srcD, _ := ipcfg["src"].(string)
						dstD, _ := ipcfg["dst"].(string)
						if srcD != "" && dstD != "" && strings.Contains(srcD, ":") != strings.Contains(dstD, ":") {
							return nil, fmt.Errorf("ocsp chain: mixed address family in ip layer (src %q / dst %q) — src and dst must be the same family (family)", srcD, dstD)
						}
					}
				}
				if rawO, ok := item["ocsp"]; ok && len(rawO) > 0 {
					var ocfg struct {
						Profile  string `json:"profile"`
						Sessions []struct {
							Profile string `json:"profile"`
						} `json:"sessions"`
					}
					if json.Unmarshal(rawO, &ocfg) == nil {
						if ocfg.Profile != "" {
							profiles["ocsp"] = ocfg.Profile
						}
						for si, se := range ocfg.Sessions {
							if se.Profile != "" {
								profiles[fmt.Sprintf("sessions[%d]", si)] = se.Profile
							}
						}
					}
				}
			}
			if !hasTCP {
				return nil, fmt.Errorf("ocsp chain: missing tcp carrier — ocsp requires an [ip,tcp,ocsp] or [ip,tcp,http,ocsp] chain (carrier)")
			}
			for where, prof := range profiles {
				switch prof {
				case "http-post", "http-get":
					if !hasHTTP {
						return nil, fmt.Errorf("ocsp chain: %s declares profile %q but no http layer in chain — http profile requires [ip,tcp,http,ocsp] (carrier)", where, prof)
					}
				case "tcp":
					if hasHTTP {
						return nil, fmt.Errorf("ocsp chain: %s declares profile %q but http layer present — tcp profile requires [ip,tcp,ocsp] without http (carrier)", where, prof)
					}
				}
			}
		}
	}
	effective, err := ValidateLayers(layersJSON, protocol)
	if err != nil {
		return nil, err
	}
	if effective == "" {
		return nil, fmt.Errorf("layers: no layers config")
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(layersJSON, &raw); err != nil {
		return nil, fmt.Errorf("layers: invalid layers JSON: %w", err)
	}
	chain := make([]Layer, 0, len(raw))
	for i, item := range raw {
		if len(item) != 1 {
			return nil, fmt.Errorf("layers[%d]: each layer entry must contain exactly one layer name", i)
		}
		for name, cfgRaw := range item {
			var cfg map[string]interface{}
			if len(cfgRaw) > 0 {
				if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
					return nil, fmt.Errorf("layers[%d] (%s): invalid config: %w", i, name, err)
				}
			}
			chain = append(chain, Layer{Name: name, Config: cfg})
		}
	}
	// Precheck generator instantiation so a chain containing a layer with no
	// implemented generator fails here (submit time), not at Plan time — the
	// same guard the planner's completedChain runs, surfaced earlier.
	for _, l := range chain {
		if _, err := newGenerator(l.Name); err != nil {
			return nil, err
		}
	}
	// CRITICAL-1 修复：传给 ChainPlanner 的必须是**补全后**的链——Plan 的
	// drive 从链上找 ip 层装配 L3，未补全的 [tcp] 会报 "no ip layer"，错误被
	// 驱动 goroutine 吞掉 → 任务报 completed 且 0 包（静默空流）。补全逻辑
	// 与 ValidateLayers 逐字一致：优先 CompleteChain（保留用户层 config）；
	// 单层链 legacy 豁免（V4 例外，传输层可作末层）时 CompleteChain 的
	// validateChain 拒绝末层，回退手动补全（depends_on 只向外插）——但必须
	// 保留 config 的变体：completeSynthesized 从裸协议名重建，config 全丢，
	// 会静默生成 schema 默认的包。补全必须在 factory 内完成（链要驱动生成），
	// 不能留到 Plan（completedChain 的 p.chain 分支无法识别豁免条件）。
	r := DefaultRegistry()
	// CWMP 载体检查：cwmp 终结层事件是完整 HTTP 帧（透传变换器），链上
	// 必须有 http 层（设计 §2：[tcp, http, cwmp]，tcp→cwmp 直连拒绝）。
	if hasLayer(chain, "cwmp") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("cwmp: terminal layer requires the http carrier layer ([tcp, http, cwmp]; tcp→cwmp direct chain rejected)")
	}
	// DOH 载体检查（66-doh 设计 §2/§7 wire fault layer_chain）：doh 终结层
	// 事件是完整 HTTP 帧（POST/GET + 响应），链上必须有 http 层（[tcp, http,
	// doh]，tcp→doh 直连拒绝）。
	if hasLayer(chain, "doh") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("doh: terminal layer requires the http carrier layer ([tcp, http, doh]; tcp→doh direct chain rejected, carrier missing)")
	}
	// ONVIF 载体检查（67-onvif v2.1.1 设计 §2）：onvif 终结层事件是完整
	// HTTP 帧（SOAP 1.2 透传变换器），链上必须有 http 层（[tcp, http, onvif]，
	// tcp→onvif 直连拒绝）。
	if hasLayer(chain, "onvif") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("onvif: terminal layer requires the http carrier layer ([tcp, http, onvif]; tcp→onvif direct chain rejected, carrier missing)")
	}
	// MMSE 载体检查（71-mmse v2.1.0 设计 §2，D-MMSE-1 裁定2）：mmse 终结
	// 层事件是完整 HTTP 帧（透传变换器），链上必须有 http 层（[tcp, http,
	// mmse]，tcp→mmse 直连拒绝）。DependsOn http 使补全恒供给——自然配置
	// 结构不可达（carrier_no_http 书面豁免），本预检为纵深位。
	if hasLayer(chain, "mmse") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("mmse: terminal layer requires the http carrier layer ([tcp, http, mmse]; tcp→mmse direct chain rejected, carrier missing)")
	}
	// D-HTTP-1 §5：gbt/getwork/hls/hds/http_flv 载体检查（cwmp/doh/onvif
	// 同款）。5 家终结层事件都经 http 层（帧变换或透传），链上无 http 层
	// 即结构性错误——Plan/Validate 期同步拒绝（drive 期报错会被吞成空流）。
	if hasLayer(chain, "gbt") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("gbt: terminal layer requires the http carrier layer ([tcp, http, gbt]; tcp→gbt direct chain rejected, carrier missing)")
	}
	if hasLayer(chain, "getwork") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("getwork: terminal layer requires the http carrier layer ([tcp, http, getwork]; tcp→getwork direct chain rejected, carrier missing)")
	}
	if hasLayer(chain, "hls") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("hls: terminal layer requires the http carrier layer ([tcp, http, hls]; tcp→hls direct chain rejected, carrier missing)")
	}
	if hasLayer(chain, "hds") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("hds: terminal layer requires the http carrier layer ([tcp, http, hds]; tcp→hds direct chain rejected, carrier missing)")
	}
	if hasLayer(chain, "http_flv") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("http_flv: terminal layer requires the http carrier layer ([tcp, http, http_flv]; tcp→http_flv direct chain rejected, carrier missing)")
	}
	completed, err := r.CompleteChain(chain)
	if err != nil {
		exempt := len(chain) == 1 && outerCategory(r, chain[0]) != CategoryTunnel
		if !(exempt && isTerminalEndError(err)) {
			return nil, err
		}
		completed = completeChainPreservingConfig(r, chain)
	}
	return NewChainPlannerFromChain(effective, completed), nil
}

// checkLayerDynObjects validates dynamic_value objects in one user-chain
// layer config (D-FTP-3 §1). Object on a non-allowlisted field →
// "does not support dynamic"; malformed object → indexed field-path error.
// Returns the config minus dynamic objects (scalars only) for the V9 path.
func checkLayerDynObjects(i int, lname string, cfg map[string]interface{}) (map[string]interface{}, error) {
	stripped := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		// D-MQTT-1：mqtt messages[] 下钻——topic/payload 槽位键的动态对象
		// （有 strategy 键）走 string 面形状门，通过后从 item 剥离（V9 只
		// 见标量）；标量/其他键/item 原样保留。item 浅拷贝替换，不动原对象
		//（ValidateLayers 只读校验）。无动态对象时原 slice 直通。
		if lname == "mqtt" && k == "messages" {
			if arr, ok := v.([]interface{}); ok {
				out, err := stripMQTTMessagesDyn(i, arr)
				if err != nil {
					return nil, err
				}
				stripped[k] = out
				continue
			}
		}
		m, isObj := v.(map[string]interface{})
		if !isObj {
			stripped[k] = v
			continue
		}
		// 非动态结构化值（wire_fault/mailbox/data_channel…，无 strategy
		// 键）不是动态对象：原样保留走 legacy V9 路径（无界字段跳过）。
		// D-TLS-2 例外：tls.cert 块本身无 strategy 键但内含动态子键——下钻
		// 处理（subject/san 开 string 面；key_type/not_before/not_after
		// 对象即 does not support dynamic；未知子键拒绝）。
		if _, looksDyn := m["strategy"]; !looksDyn {
			if lname == "tls" && k == "cert" {
				sub, err := checkTLSCertDynObjects(i, m)
				if err != nil {
					return nil, err
				}
				stripped[k] = sub
				continue
			}
			stripped[k] = v
			continue
		}
		where := fmt.Sprintf("layers[%d](%s).%s", i, lname, k)
		if !core.LayerDynAllowlisted(lname, k) {
			return nil, fmt.Errorf("%s does not support dynamic", where)
		}
		if msg := core.CheckLayerDynShape(lname, k, m); msg != "" {
			reason := msg
			if j := indexColonSpace(msg); j >= 0 {
				reason = msg[j+2:]
			}
			return nil, fmt.Errorf("%s: %s", where, reason)
		}
	}
	return stripped, nil
}

// checkTLSCertDynObjects 下钻 tls.cert 块（D-TLS-2）：子键逐个处理——
// subject/san 的动态对象（有 strategy 键）走 string 面形状门，通过后从
// stripped 剥离（V9 只见标量）；标量原样保留；key_type/not_before/
// not_after 的对象即 does not support dynamic（关字段）；未知子键拒绝。
// 返回剥离动态对象后的 cert map（调用方直接装回 stripped["cert"]）。
func checkTLSCertDynObjects(i int, cert map[string]interface{}) (map[string]interface{}, error) {
	sub := make(map[string]interface{}, len(cert))
	for k, v := range cert {
		m, isObj := v.(map[string]interface{})
		if !isObj {
			sub[k] = v
			continue
		}
		if _, looksDyn := m["strategy"]; !looksDyn {
			sub[k] = v
			continue
		}
		where := fmt.Sprintf("layers[%d](tls).cert.%s", i, k)
		switch k {
		case "subject", "san":
			if msg := core.CheckLayerDynShape("tls", "cert."+k, m); msg != "" {
				reason := msg
				if j := indexColonSpace(msg); j >= 0 {
					reason = msg[j+2:]
				}
				return nil, fmt.Errorf("%s: %s", where, reason)
			}
			// 通过：剥离（不进 stripped，V9 不见对象）。
		case "key_type", "not_before", "not_after":
			return nil, fmt.Errorf("%s does not support dynamic", where)
		default:
			return nil, fmt.Errorf("%s: unknown cert field %q", where, k)
		}
	}
	return sub, nil
}

// stripMQTTMessagesDyn 下钻 mqtt messages[] 数组（D-MQTT-1）：每 item 的
// topic/payload 键若为动态对象（有 strategy 键）→ string 面形状门
// （CheckLayerDynShape "mqtt","topic"/"payload"，client_id 直键走
// checkLayerDynObjects 通用 allowlist 门）；通过后从 item 剥离（V9 只见
// 标量），形状坏 → 错误（create 期 400）。item 浅拷贝替换——原对象不动。
// 无动态对象时返回的 slice 含相同的 item 引用（调用方直通）。
func stripMQTTMessagesDyn(i int, arr []interface{}) ([]interface{}, error) {
	out := make([]interface{}, 0, len(arr))
	for _, item := range arr {
		im, isMap := item.(map[string]interface{})
		if !isMap {
			out = append(out, item)
			continue
		}
		copied := false
		for _, key := range []string{"topic", "payload"} {
			m, isObj := im[key].(map[string]interface{})
			if !isObj || m == nil {
				continue
			}
			if _, looksDyn := m["strategy"]; !looksDyn {
				continue
			}
			where := fmt.Sprintf("layers[%d](mqtt).messages[].%s", i, key)
			if msg := core.CheckLayerDynShape("mqtt", key, m); msg != "" {
				reason := msg
				if j := indexColonSpace(msg); j >= 0 {
					reason = msg[j+2:]
				}
				return nil, fmt.Errorf("%s: %s", where, reason)
			}
			if !copied {
				cp := make(map[string]interface{}, len(im))
				for k, v := range im {
					cp[k] = v
				}
				im = cp
				copied = true
			}
			delete(im, key)
		}
		out = append(out, im)
	}
	return out, nil
}

// validateTLSCertScalars 校验 cert 块内标量子键的业务约束（D-TLS-2，
// chain_planner.go tls 结构性段调用）：key_type 枚举（本轮仅 ecdsa-p256）、
// 日期 RFC3339 可解析且 not_after > not_before、SAN 条目 ≤253B、subject
// DN 可解析（含 CN）。动态对象残留（ValidateLayers 漏剥/引擎直调）→
// 同步拒绝。certgen.go 的 validateCertRef 是同语义的 tls 包侧实现——
// 此处是 layers 包侧镜像（import 禁忌，见 chain_planner.go 注释）。
func validateTLSCertScalars(cert map[string]interface{}) string {
	strOf := func(k string) (string, bool) {
		s, ok := cert[k].(string)
		return s, ok
	}
	if v, ok := cert["key_type"]; ok && v != nil {
		s, isStr := strOf("key_type")
		if !isStr {
			return "tls chain: cert.key_type must be a string"
		}
		if s != "" && s != "ecdsa-p256" {
			return fmt.Sprintf("tls chain: cert.key_type %q not supported yet (only \"ecdsa-p256\")", s)
		}
	}
	nbStr, _ := strOf("not_before")
	naStr, _ := strOf("not_after")
	var nb, na time.Time
	var err error
	if nbStr != "" {
		if nb, err = time.Parse(time.RFC3339, nbStr); err != nil {
			return fmt.Sprintf("tls chain: cert.not_before %q invalid RFC3339 timestamp: %v", nbStr, err)
		}
	}
	if naStr != "" {
		if na, err = time.Parse(time.RFC3339, naStr); err != nil {
			return fmt.Sprintf("tls chain: cert.not_after %q invalid RFC3339 timestamp: %v", naStr, err)
		}
	}
	if nbStr != "" && naStr != "" && !na.After(nb) {
		return "tls chain: cert.not_after must be after not_before"
	}
	if v, ok := cert["san"]; ok && v != nil {
		switch t := v.(type) {
		case string:
			if len(t) > 253 {
				return fmt.Sprintf("tls chain: cert.san entry length %d exceeds max 253 bytes", len(t))
			}
		case []interface{}:
			for _, item := range t {
				s, _ := item.(string)
				if len(s) > 253 {
					return fmt.Sprintf("tls chain: cert.san entry length %d exceeds max 253 bytes", len(s))
				}
			}
		}
	}
	if v, ok := cert["subject"]; ok && v != nil {
		if s, isStr := strOf("subject"); isStr && s != "" {
			if msg := validateTLSCertDN(s); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// validateTLSCertDN 校验 subject DN 串（CN 必填；属性集 CN/O/OU/L/ST/C）。
func validateTLSCertDN(s string) string {
	hasCN := false
	for _, kv := range splitTLSCertDN(s) {
		eq := -1
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				eq = i
				break
			}
		}
		if eq < 0 {
			return fmt.Sprintf("tls chain: cert.subject %q invalid DN (want K=V pairs)", s)
		}
		k, v := trimTLSCertSpace(kv[:eq]), trimTLSCertSpace(kv[eq+1:])
		if v == "" {
			return fmt.Sprintf("tls chain: cert.subject %q has empty value for %q", s, k)
		}
		switch k {
		case "CN":
			hasCN = true
		case "O", "OU", "L", "ST", "C":
		default:
			return fmt.Sprintf("tls chain: cert.subject has unknown attribute %q", k)
		}
	}
	if !hasCN {
		return fmt.Sprintf("tls chain: cert.subject %q missing CN", s)
	}
	return ""
}

func splitTLSCertDN(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trimTLSCertSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func indexColonSpace(s string) int {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == ':' && s[i+1] == ' ' {
			return i
		}
	}
	return -1
}

// ValidateLayers validates a user-supplied layer chain at strategy-creation
// time (P3, design §10.2 创建时校验清单): parse the "layers" array, complete
// hard dependencies (V8), then apply V1-V10. protocol is the strategy's
// protocol field; when empty it is inferred from the chain (§6.2). Returns
// the effective protocol (given or inferred) — the caller persists the
// inferred value back when protocol was empty.
//
// Entry point lives in this package — not core — because core cannot import
// layers (layers already imports core for FlowSpec/PacketConfig), and the
// registry/validation machinery is here. Callers (api/rest) import layers
// directly.
//
// V10/推断的"最外层"语义（§6.1 完整示例 [ip, gre, ip, tcp, http] +
// protocol "gre"）：最外层 = 补全后链上第一个非脚手架层——L3/L2/传输层
// （ip/eth/vlan/mpls/pppoe/tcp/udp）与隧道层 tls 是承载骨架，不算用户
// 意图；gre/http/dns 等用户协议层才算。全链都是骨架（独立 [ip→tcp] 传输
// flow）时回退末层。
//
// 单层链（[tcp]、[http]…）是 legacy 每协议风格——类名即末层，传输层当
// 末层合法（V4 豁免，ChainPlanner 合成链同口径）。隧道层单层（[tls]、
// [gre]）不豁免：隧道必须包内层（V6）。豁免路径改用手动补全
// （depends_on 只向外插，末层保持用户层），跳过 V4 继续走其余规则。
//
// Field-range checking (V9) applies to explicitly-present config keys only:
// a user-written "dst_port": 0 is an explicit request for 0 (§6.4), while an
// absent key is filled from the schema default at generation time (R2), so
// absent keys are never range-checked here. Explicit 0 on a field whose
// minimum is > 0 (mss ≥ 536) means "use the schema default" — same
// convention as the flat-config validator — and is not range-checked either.
//
// P3 scope (设计 §14.1): this stage validates and infers protocol only —
// the generated chain does NOT drive packet construction yet. Generation
// (P2c 层链驱动生成) consumes top-level flat keys via mapToFlowSpec and
// derives the chain from the protocol name; the layers config is validated
// here and persisted, but its field values are not applied until the
// generation stage wires the chain in. A layers config that passes
// validation but whose fields the flat path ignores (e.g. 单层 [mpls],
// 生成走 legacy flat 路径) is therefore validated-but-not-yet-effective;
// the mislead risk is tracked in P2c 集成测试 (T11-T13).
func ValidateLayers(layersJSON json.RawMessage, protocol string) (string, error) {
	if len(layersJSON) == 0 {
		return "", nil // no layers field = legacy flat config path
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(layersJSON, &raw); err != nil {
		return "", fmt.Errorf("layers: invalid layers JSON: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("layers: empty layer chain")
	}
	chain := make([]Layer, 0, len(raw))
	for i, item := range raw {
		// 每项 = { 层名: 配置 }（设计 §3.1：层名即键，值是该层字段配置）。
		// 一个条目必须恰好一个层（多键 = 一条里塞了两层，拒绝）。
		if len(item) != 1 {
			return "", fmt.Errorf("layers[%d]: each layer entry must contain exactly one layer name", i)
		}
		for name, cfgRaw := range item {
			var cfg map[string]interface{}
			if len(cfgRaw) > 0 {
				if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
					return "", fmt.Errorf("layers[%d] (%s): invalid config: %w", i, name, err)
				}
			}
			chain = append(chain, Layer{Name: name, Config: cfg})
		}
	}

	r := DefaultRegistry()
	for i := range chain {
		if !r.Has(chain[i].Name) {
			return "", errf("layers: unknown layer %q (position %d)", chain[i].Name, i)
		}
	}

	completed, err := r.CompleteChain(chain)
	// 单层链 legacy 豁免（V4 例外，ChainPlanner 合成链同口径）：[tcp] 的
	// 末层就是协议层本身，传输层当末层合法。隧道层（tls/gre）不豁免——
	// 隧道必须包内层（V6）。豁免路径改用手动补全（depends_on 只向外插，
	// 末层保持用户层），跳过 V4 继续走其余规则。
	exempt := len(chain) == 1 && outerCategory(r, chain[0]) != CategoryTunnel
	if err != nil {
		if !(exempt && isTerminalEndError(err)) {
			return "", err
		}
		completed = completeSynthesized(r, chain[0].Name)
	}
	if err := r.ValidateChain(completed); err != nil {
		// 同上豁免：手动补全后的链末层仍是用户层（tcp），V4 仍会拒绝，
		// 豁免条件下吞掉该错误，其余规则原样生效。
		if !(exempt && isTerminalEndError(err)) {
			return "", err
		}
	}
	// 字段范围（V9）：用户链各层（config 只保留在用户层上——
	// completeSynthesized 丢弃 config，单层豁免路径必须回到用户层校验）
	// + 补全后全链（插入的依赖层，config 为空天然通过）。
	firstIP := true
	for i := range chain {
		// D-GRE-2 §12：内层 ip 层（隧道载荷侧，非首个 ip 层）动态对象拒绝
		// ——LayerDynValues 只有一套 ip 值，双层动态会静默打架（外层对象
		// 被内层顶掉，2026-09-15 探针 C）。单四元组模型下内层地址静态。
		if chain[i].Name == "ip" {
			if !firstIP {
				for _, f := range []string{"src", "dst", "ttl"} {
					if isDynObject(chain[i].Config[f]) {
						return "", fmt.Errorf("layers[%d](ip).%s: inner ip layer does not support dynamic (tunnel inner addresses are static; vary the outer ip layer instead)", i, f)
					}
				}
			}
			firstIP = false
		}
		// D-FTP-3 §1: 动态对象先行——同键二态：对象值走 dynamic_value
		// 形状检查（带用户链下标的精确路径），标量走既有 V9。
		stripped, err := checkLayerDynObjects(i, chain[i].Name, chain[i].Config)
		if err != nil {
			return "", err
		}
		if err := r.ValidateLayerConfig(Layer{Name: chain[i].Name, Config: stripped}); err != nil {
			return "", err
		}
	}
	for i := range completed {
		// D-FTP-3: 补全链沿用用户层 config 引用（含已校验的动态对象）——
		// 用户循环已逐个校验，这里只剥离对象值走标量 V9（插入的依赖层
		// config 为空，天然无对象）。
		strippedDone := make(map[string]interface{}, len(completed[i].Config))
		for k, v := range completed[i].Config {
			if _, isObj := v.(map[string]interface{}); isObj {
				continue
			}
			strippedDone[k] = v
		}
		if err := r.ValidateLayerConfig(Layer{Name: completed[i].Name, Config: strippedDone}); err != nil {
			return "", err
		}
	}

	// V10 + 推断：protocol 必须等于最外层协议层（非脚手架层）。
	outermost := outermostProtocol(completed)
	if protocol != "" {
		if outermost != protocol {
			// 隧道层特例：protocol 显式指定为隧道层（如 "tls"）时，最外层是
			// 内层协议（如 "http"），因为隧道层在 outermostProtocol 中被跳过
			// （tls 承载骨架、非用户协议意图）。仅当 protocol 是隧道层且确实
			// 在链上时允许该不匹配。
			if schema, ok := r.Get(protocol); ok && schema.Category == CategoryTunnel {
				found := false
				for _, l := range completed {
					if l.Name == protocol {
						found = true
						break
					}
				}
				if found {
					return protocol, nil
				}
			}
			// 变换器特例：protocol 是 TransformEvents 标记层（如 http 之于
			// http_flv 链 [ip→tcp→http→http_flv]），在链上非末层位置充当事件
			// 变换器（不产自己的协议报文）。与 tls 承载骨架同类豁免。
			// 豁免必须校验位置：仅当 protocol 层出现在**非末层**位置才成立
			// ——若它当末层（如 [ip,gre,ip,tcp,http] + protocol "http"），
			// 它是真正的终结层而非变换器，V10 应照常拒绝不匹配。
			if schema, ok := r.Get(protocol); ok && schema.TransformEvents {
				for i, l := range completed {
					if l.Name == protocol && i < len(completed)-1 {
						return protocol, nil
					}
				}
			}
			return "", errf("layers: protocol %q does not match outermost layer %q", protocol, outermost)
		}
		return protocol, nil // 显式 protocol 原样返回（调用方仅 protocol=="" 时回填）
	}
	return outermost, nil
}

// outermostProtocol resolves the strategy's protocol from a completed chain:
// the outermost layer that is not L3/L2/transport scaffolding (承载骨架,
// §6.1 完整示例 [ip, gre, ip, tcp, http] + protocol "gre")。tls 是隧道层
// （隧道必须包内层 V6），作为 TLS 承载的协议（如 tls→stun）并非用户协议
// 意图，同样计入骨架被跳过；gre 例外——它是自成一体的用户协议层，不跳过。
// 全链都是骨架（独立 [ip→tcp] 传输 flow）时回退末层。
func outermostProtocol(completed []Layer) string {
	for i := range completed {
		switch completed[i].Name {
		case "ip", "eth", "vlan", "mpls", "pppoe", "tcp", "udp", "tls", "http":
			continue
		}
		return completed[i].Name
	}
	return completed[len(completed)-1].Name
}

// outerCategory returns the registry category of a user chain's first layer
// (单层链豁免判定用；层已确认存在)。
func outerCategory(r *Registry, l Layer) LayerCategory {
	s, _ := r.Get(l.Name)
	return s.Category
}
