package core

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

// Layer-dynamic allowlist (D-FTP-3 §4): only these layer fields accept a
// dynamic object. Anything else seeing an object is rejected by ValidateLayers
// ("field X does not support dynamic"); parseLayerDyn only READS allowlisted
// fields so a non-allowlisted object never reaches resolution (defense in
// depth — ValidateLayers is authoritative).
var layerDynAllowlist = map[string]map[string]bool{
	"ip":  {"src": true, "dst": true, "ttl": true},
	"tcp": {"src_port": true, "dst_port": true},
	"udp": {"src_port": true, "dst_port": true},
	"eth": {"src_mac": true, "dst_mac": true},
	// D-HTTP-1 重走步骤 4：http 业务 6 开（string 面 5 + int 面 1；其余 15 关，
	// 对象即 does not support dynamic）。map 型两键（request_headers/
	// response_headers）无动态形状，直接关。
	"http": {"uri": true, "body": true, "body_b64": true, "response_body": true, "response_body_b64": true, "response_status_code": true},
	// D-TLS-1 步骤 2：tls 业务 sni 开 1 个（string 面；alpn/version/role 关，
	// 对象即 does not support dynamic）。sni 是域名逐流变（T-TLS-5/6/7）；
	// alpn 关：列表无允许的解析面且现状无轮转需求（D-TLS-1 适用性段）。
	// D-TLS-2：cert 块是嵌套对象——allowlist 只登记顶层 "cert"（值为对象即
	// 下钻，不直接 parse）；子键开关在 checkTLSCertDynShape：subject/san 开
	// string 面，key_type/not_before/not_after 关。
	"tls": {"sni": true, "cert": true},
	// D-DNS-1：dns 业务 3 开（name string 面 / query_type·txid int 面；
	// 其余 11 关，对象即 does not support dynamic）。name 是查询域名逐流变
	// （T-DNS-8，sni 同款）；query_type/txid 是逐流 int（T-DNS-9/10，
	// response_status_code 先例）。
	"dns": {"name": true, "query_type": true, "txid": true},
	// D-MQTT-1：mqtt 业务 3 开（client_id/topic/payload 全 string 面）。
	// 顶行只登记 client_id——它是层直键（checkLayerDynObjects 通用 allowlist
	// 门在此拦）；topic/payload 是 messages[] 槽位键（非层顶字段，顶层出现
	// 对象按未知/关字段拒绝），其动态执法在 parseLayerDyn/translateMQTTDyn/
	// checkLayerDynObjects 三处的 messages 下钻点（CheckLayerDynShape
	// "mqtt","topic"/"payload"）。其余 14 关，对象即 does not support dynamic。
	"mqtt": {"client_id": true},
	// D-H323-1 决策 E1（用户已批）：h323 层端口 2 键开（对象=逐流端口池，
	// 12.13 与 tcp/udp 端口语义对齐）；业务 8 键全关（结构选择器/会话
	// 语义，icmpv6 同判），对象即 does not support dynamic。
	"h323": {"src_port": true, "dst_port": true},
	// D-MPLS-1 决策 E1（h323 已批延续）：mpls 层端口 2 键开（内层端口语义
	// 属终层标签流，逐流端口池）；业务 5 键全关（labels=路径身份/
	// multicast=EtherType 选择器/inner_proto=内层选择器/direction=方向
	// 选择器/inner_payload=载荷），对象即 does not support dynamic。
	"mpls": {"src_port": true, "dst_port": true},
	// D-NGAP-1 决策 E1（h323/mpls 已批延续）：ngap 层端口 2 键开（SCTP
	// 联结端口语义住层）；业务 12 键全关（结构选择器/联结身份/载荷，
	// 逐流变破坏 gNB↔AMF 联结语义），对象即 does not support dynamic。
	"ngap": {"src_port": true, "dst_port": true},
	// D-TELNET-1 决策 E1（h323/mpls/ngap 已批延续）：telnet 层端口 2 键
	// 开（TCP 联结端口语义住层）；业务 10 键全关（banner/dialog=会话
	// 身份、scenario=结构选择器、credentials=凭据面，逐流变破坏交互
	// 语义），对象即 does not support dynamic。
	"telnet": {"src_port": true, "dst_port": true},
}

// parseLayerDyn extracts per-flow dynamic strategies from a decoded layers
// array ([]any of single-key {layer: config} maps). Object values on
// allowlisted fields become *StrategyConfig; malformed objects produce
// "layers[i](name).field: ..." errors for spec.ValidationErrors. Returns
// (nil, nil) when no dynamic object is present.
func parseLayerDyn(layersVal interface{}) (*LayerDynValues, []string) {
	arr, ok := layersVal.([]interface{})
	if !ok {
		return nil, nil
	}
	out := &LayerDynValues{}
	var errs []string
	set := func(where, lname, field string, dst **StrategyConfig, v interface{}) {
		m, ok := v.(map[string]interface{})
		if !ok {
			return // scalar or absent: not dynamic
		}
		raw, err := json.Marshal(m)
		if err != nil {
			errs = append(errs, where+": invalid object")
			return
		}
		var sc StrategyConfig
		if err := json.Unmarshal(raw, &sc); err != nil {
			errs = append(errs, where+": invalid object")
			return
		}
		if msg := checkDynShape(where, lname, field, &sc); msg != "" {
			errs = append(errs, msg)
			return
		}
		*dst = &sc
	}
	firstIP := true
	for i, item := range arr {
		layer, _ := item.(map[string]interface{})
		if layer == nil {
			continue
		}
		// D-GRE-2 §12：内层 ip 层动态对象拒绝（与 ValidateLayers 同锚词，
		// 双侧执法——本函数是 worker 逐流解析入口，引擎直调绕过
		// ValidateLayers 时此处兜底）。单四元组模型：双层动态静默打架
		// （外层对象被内层顶掉，2026-09-15 探针 C）。
		if sub, ok := layer["ip"].(map[string]interface{}); ok {
			if !firstIP {
				for _, f := range []string{"src", "dst", "ttl"} {
					if m, isObj := sub[f].(map[string]interface{}); isObj {
						if _, looksDyn := m["strategy"]; looksDyn {
							errs = append(errs, fmt.Sprintf("layers[%d](ip).%s: inner ip layer does not support dynamic (tunnel inner addresses are static; vary the outer ip layer instead)", i, f))
						}
					}
				}
			}
			firstIP = false
		}
		for lname, allowed := range layerDynAllowlist {
			sub, _ := layer[lname].(map[string]interface{})
			if sub == nil {
				continue
			}
			for f := range allowed {
				v, ok := sub[f]
				if !ok || v == nil {
					continue
				}
				where := fmt.Sprintf("layers[%d](%s).%s", i, lname, f)
				switch lname {
				case "ip":
					switch f {
					case "src":
						set(where, lname, f, &out.IP.Src, v)
					case "dst":
						set(where, lname, f, &out.IP.Dst, v)
					case "ttl":
						set(where, lname, f, &out.IP.TTL, v)
					}
				case "tcp":
					if f == "src_port" {
						set(where, lname, f, &out.TCP.SrcPort, v)
					} else {
						set(where, lname, f, &out.TCP.DstPort, v)
					}
				case "udp":
					if f == "src_port" {
						set(where, lname, f, &out.UDP.SrcPort, v)
					} else {
						set(where, lname, f, &out.UDP.DstPort, v)
					}
				case "eth":
					if f == "src_mac" {
						set(where, lname, f, &out.Eth.SrcMAC, v)
					} else {
						set(where, lname, f, &out.Eth.DstMAC, v)
					}
				case "http":
					switch f {
					case "uri":
						set(where, lname, f, &out.HTTP.URI, v)
					case "body":
						set(where, lname, f, &out.HTTP.Body, v)
					case "body_b64":
						set(where, lname, f, &out.HTTP.BodyB64, v)
					case "response_body":
						set(where, lname, f, &out.HTTP.ResponseBody, v)
					case "response_body_b64":
						set(where, lname, f, &out.HTTP.ResponseBodyB64, v)
					case "response_status_code":
						set(where, lname, f, &out.HTTP.ResponseStatusCode, v)
					}
				case "tls":
					// D-TLS-1 步骤 2：sni 是本轮唯一开的业务键（string 面）。
					if f == "sni" {
						set(where, lname, f, &out.TLS.SNI, v)
					}
					// D-TLS-2：cert 块下钻（subject/san 开 string 面；
					// key_type/not_before/not_after 关——checkTLSCertDynShape
					// 先拦 does not support dynamic，不进 parse）。
					// san 的 list 端点是域名串：checkDynEndpoints 的
					// isIP/isMAC/isPort/isTTL 全假→只判非空，不做类型解析。
					if f == "cert" {
						certMap, ok := v.(map[string]interface{})
						if !ok || certMap == nil {
							continue
						}
						if sv, ok := certMap["subject"]; ok && sv != nil {
							if sm, isObj := sv.(map[string]interface{}); isObj {
								if _, looksDyn := sm["strategy"]; looksDyn {
									set(where+".cert.subject", lname, "cert.subject", &out.TLS.CertSubject, sv)
								}
							}
						}
						if sv, ok := certMap["san"]; ok && sv != nil {
							if sm, isObj := sv.(map[string]interface{}); isObj {
								if _, looksDyn := sm["strategy"]; looksDyn {
									set(where+".cert.san", lname, "cert.san", &out.TLS.CertSAN, sv)
								}
							}
						}
					}
				case "dns":
					// D-DNS-1：name/query_type/txid 三开（其余 11 关——
					// allowlist 门已拦对象，到不了这里）。
					switch f {
					case "name":
						set(where, lname, f, &out.DNS.Name, v)
					case "query_type":
						set(where, lname, f, &out.DNS.QueryType, v)
					case "txid":
						set(where, lname, f, &out.DNS.TxID, v)
					}
				case "mqtt":
					// D-MQTT-1：client_id 直键（string 面）。topic/payload
					// 是 messages[] 槽位键——下方下钻处理，层顶无此二键
					//（allowlist 顶行只登记 client_id）。
					if f == "client_id" {
						set(where, lname, f, &out.MQTT.ClientID, v)
					}
				case "h323":
					// D-H323-1 决策 E1：端口 2 键 int 面（tcp/udp 同款，
					// checkDynShape default 分支天然覆盖）。
					if f == "src_port" {
						set(where, lname, f, &out.H323.SrcPort, v)
					} else {
						set(where, lname, f, &out.H323.DstPort, v)
					}
				case "mpls":
					// D-MPLS-1 决策 E1：同 h323 端口 int 面。
					if f == "src_port" {
						set(where, lname, f, &out.MPLS.SrcPort, v)
					} else {
						set(where, lname, f, &out.MPLS.DstPort, v)
					}
				case "ngap":
					// D-NGAP-1 决策 E1：同 h323/mpls 端口 int 面。
					if f == "src_port" {
						set(where, lname, f, &out.NGAP.SrcPort, v)
					} else {
						set(where, lname, f, &out.NGAP.DstPort, v)
					}
				case "telnet":
					// D-TELNET-1 决策 E1：同前三端口 int 面。
					if f == "src_port" {
						set(where, lname, f, &out.TELNET.SrcPort, v)
					} else {
						set(where, lname, f, &out.TELNET.DstPort, v)
					}
				}
			}
			// D-MQTT-1：mqtt messages[] 下钻——topic/payload 槽位键的动态
			// 对象逐槽提取（首遇策略进单槽，单策略语义；形状坏 →
			// ValidationErrors）。静态槽/其他键不碰。
			if lname == "mqtt" {
				if msgs, ok := sub["messages"].([]interface{}); ok {
					for j, item := range msgs {
						im, isMap := item.(map[string]interface{})
						if !isMap {
							continue
						}
						for _, key := range []string{"topic", "payload"} {
							m, isObj := im[key].(map[string]interface{})
							if !isObj || m == nil {
								continue
							}
							if _, looksDyn := m["strategy"]; !looksDyn {
								continue
							}
							msgWhere := fmt.Sprintf("layers[%d](mqtt).messages[%d].%s", i, j, key)
							if key == "topic" && out.MQTT.Topic == nil {
								set(msgWhere, lname, key, &out.MQTT.Topic, m)
							}
							if key == "payload" && out.MQTT.Payload == nil {
								set(msgWhere, lname, key, &out.MQTT.Payload, m)
							}
						}
					}
				}
			}
		}
	}
	if !out.HasAny() && len(errs) == 0 {
		return nil, nil
	}
	if !out.HasAny() {
		return nil, errs
	}
	return out, errs
}

// checkDynShape validates one dynamic object (same rules as FTP
// validateDynFields + MAC/TTL allowlist): unknown strategy, bad range,
// empty list, bad pattern, pattern on IP/port/MAC/TTL. Range/list endpoints
// must parse in the field's type (IP/MAC/port/TTL) — unparseable endpoints
// are loud errors here, never silent empty resolutions downstream.
// D-HTTP-1 重走裁定表 F：http string 面 5 字段仅 fixed/list/pattern
// （inc/rand 无意义，形状层拒绝）；response_status_code 走 int 面
// fixed/inc/rand/list（pattern 无意义，拒绝）。
// D-TLS-1 步骤 2：tls.sni 走 string 面（fixed/list/pattern；inc/rand/
// unknown 同 http 裁定表 F 锚词 `not supported for string field`）。
// alpn/version/role 不进本函数——allowlist 关门，由 checkLayerDynObjects
// 先拦 `does not support dynamic`。
// checkTLSCertDynShape 校验 cert 块内单个子键的动态对象（D-TLS-2，
// checkLayerDynObjects 下钻调用）：subject/san 走 string 面
// fixed/list/pattern（inc/rand/unknown 同 sni 裁定表 F 锚词）；
// key_type/not_before/not_after 走到这里即关字段拒绝。
func checkTLSCertDynShape(where, sub string, s *StrategyConfig) string {
	switch sub {
	case "subject", "san":
		switch s.Strategy {
		case "fixed", "":
			return ""
		case "list":
			if len(s.List) == 0 {
				return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
			}
			return ""
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Sprintf("%s: pattern strategy requires a template and a 2-element range", where)
			}
			return ""
		case "inc", "rand":
			return fmt.Sprintf("%s: %s strategy is not supported for string field", where, s.Strategy)
		default:
			return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
		}
	default:
		return fmt.Sprintf("%s: does not support dynamic", where)
	}
}

// tlsCertSub 把 checkDynShape 的 field 名映射为 cert 子键
// （"cert.subject"→"subject"；非 cert 字段原样返回）。
func tlsCertSub(field string) string {
	if field == "cert.subject" {
		return "subject"
	}
	if field == "cert.san" {
		return "san"
	}
	return field
}

func checkDynShape(where, lname, field string, s *StrategyConfig) string {
	if lname == "tls" && (field == "cert.subject" || field == "cert.san") {
		return checkTLSCertDynShape(where, tlsCertSub(field), s)
	}
	// D-DNS-1：dns.name 走 tls-sni 同款 string 面（fixed/list/pattern；
	// inc/rand 对域名无意义，拒绝）。query_type/txid 走 http-
	// response_status_code 同款 int 面（fixed/inc/rand/list；pattern 对
	// 数字无意义，拒绝）——两支都由下方 default 分支天然覆盖（int 面：
	// inc/rand 走 2 元素 range 端点检查；list 要求非空；pattern 落到
	// checkLayerDynObjects 前 default 分支报 unknown 或 pattern 分支拒绝），
	// 这里只特化 name 的 string 面。
	if lname == "dns" && field == "name" {
		switch s.Strategy {
		case "fixed", "":
			return ""
		case "list":
			if len(s.List) == 0 {
				return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
			}
			return ""
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Sprintf("%s: pattern strategy requires a template and a 2-element range", where)
			}
			return ""
		case "inc", "rand":
			return fmt.Sprintf("%s: %s strategy is not supported for string field", where, s.Strategy)
		default:
			return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
		}
	}
	if lname == "dns" && (field == "query_type" || field == "txid") && s.Strategy == "pattern" {
		return fmt.Sprintf("%s: pattern strategy is not supported for numeric dns fields", where)
	}
	// D-MQTT-1：mqtt 三开全 string 面（client_id 层直键 / topic·payload
	// messages[] 槽位键；dns.name/tls.sni 同款：fixed/list/pattern 开，
	// inc/rand 关——域名/文本无意义）。
	if lname == "mqtt" && (field == "client_id" || field == "topic" || field == "payload") {
		switch s.Strategy {
		case "fixed", "":
			return ""
		case "list":
			if len(s.List) == 0 {
				return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
			}
			return ""
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Sprintf("%s: pattern strategy requires a template and a 2-element range", where)
			}
			return ""
		case "inc", "rand":
			return fmt.Sprintf("%s: %s strategy is not supported for string field", where, s.Strategy)
		default:
			return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
		}
	}
	if lname == "tls" && field == "sni" {
		switch s.Strategy {
		case "fixed", "":
			return ""
		case "list":
			if len(s.List) == 0 {
				return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
			}
			return ""
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Sprintf("%s: pattern strategy requires a template and a 2-element range", where)
			}
			return ""
		case "inc", "rand":
			return fmt.Sprintf("%s: %s strategy is not supported for string field", where, s.Strategy)
		default:
			return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
		}
	}
	if lname == "http" && field != "response_status_code" {
		switch s.Strategy {
		case "fixed", "":
			return ""
		case "list":
			if len(s.List) == 0 {
				return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
			}
			return ""
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Sprintf("%s: pattern strategy requires a template and a 2-element range", where)
			}
			return ""
		case "inc", "rand":
			return fmt.Sprintf("%s: %s strategy is not supported for string field", where, s.Strategy)
		default:
			return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
		}
	}
	if lname == "http" && field == "response_status_code" && s.Strategy == "pattern" {
		return fmt.Sprintf("%s: pattern strategy is not supported for layer address/port fields", where)
	}
	switch s.Strategy {
	case "fixed", "":
		return ""
	case "inc", "rand":
		if len(s.Range) != 2 {
			return fmt.Sprintf("%s: %s strategy requires a 2-element range", where, s.Strategy)
		}
		if msg := checkDynEndpoints(where, lname, field, s.Range); msg != "" {
			return msg
		}
		a, b := dynIntEnds(s.Range)
		if a > b {
			return fmt.Sprintf("%s: %s range start must not exceed end", where, s.Strategy)
		}
		// D-FTP-4: IP range 顺序按地址族比较——dynIntEnds 只懂十进制整型，
		// IPv6 端点经 Atoi 全得 0 会 neighbourhood 误判。IP 字段走 ipRangeOrder。
		if lname == "ip" && field != "ttl" {
			if msg := checkIPRangeOrder(where, s.Range); msg != "" {
				return msg
			}
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
		}
		vals := make([]interface{}, len(s.List))
		for i, v := range s.List {
			vals[i] = v
		}
		if msg := checkDynEndpoints(where, lname, field, vals); msg != "" {
			return msg
		}
		return ""
	case "pattern":
		// Pattern is only meaningful for string-ish fields resolved via
		// genStringValue. IP/port/MAC/TTL use typed algorithms that have no
		// pattern case — reject here so the failure is loud, not a silent
		// empty resolution.
		return fmt.Sprintf("%s: pattern strategy is not supported for layer address/port fields", where)
	default:
		return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
	}
}

// dynIntEnds mirrors core.toInt for range endpoint comparison.
func dynIntEnds(r []interface{}) (int, int) {
	toI := func(v interface{}) int {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(x)
			return n
		}
		return 0
	}
	return toI(r[0]), toI(r[1])
}

// checkDynEndpoints verifies range/list endpoints parse in the field type.
func checkDynEndpoints(where, lname, field string, vals []interface{}) string {
	isIP := lname == "ip" && field != "ttl"
	isMAC := lname == "eth"
	isPort := (lname == "tcp" || lname == "udp")
	isTTL := lname == "ip" && field == "ttl"
	for _, v := range vals {
		switch {
		case isIP:
			str, _ := v.(string)
			if !validIP(str) {
				return fmt.Sprintf("%s: invalid IP endpoint %q", where, fmt.Sprint(v))
			}
		case isMAC:
			if _, ok := parseMAC(v); !ok {
				return fmt.Sprintf("%s: invalid MAC endpoint %q", where, fmt.Sprint(v))
			}
		case isPort:
			if toPort(v) == 0 && fmt.Sprint(v) != "0" {
				// toPort returns 0 for both "0" and garbage; only garbage is an error.
				return fmt.Sprintf("%s: invalid port endpoint %q", where, fmt.Sprint(v))
			}
		case isTTL:
			n := toInt(v)
			if n < 0 || n > 255 {
				return fmt.Sprintf("%s: invalid ttl endpoint %q", where, fmt.Sprint(v))
			}
		}
	}
	// MAC order check for inc/rand is done at resolve time (low-byte order);
// cross-OUI ranges resolve empty (no-op). Keep loud-shape vs quiet-resolve
// split: shape guarantees parseability, resolve guarantees bounds.
// IP mixed-family check is loud too (D-FTP-4): a range/list mixing v4 and
// v6 endpoints is rejected here, never silently resolved in one family.
	if isIP && len(vals) == 2 {
		if msg := checkIPFamilyMix(where, vals); msg != "" {
			return msg
		}
	}
	return ""
}

// checkIPRangeOrder compares IP range endpoints within their family
// (D-FTP-4): IPv4 by u32, IPv6 by u128. Mixed families are rejected by
// checkIPFamilyMix (called from checkDynEndpoints before this runs); this
// function only orders same-family pairs. Unparseable endpoints are already
// rejected by checkDynEndpoints — defensive empty return here.
func checkIPRangeOrder(where string, r []interface{}) string {
	a, b := asString(r[0]), asString(r[1])
	if isV6Literal(a) || isV6Literal(b) {
		sa, ok1 := ip6ToU128(a)
		sb, ok2 := ip6ToU128(b)
		if !ok1 || !ok2 {
			return ""
		}
		if u128Cmp(sb, sa) < 0 {
			return fmt.Sprintf("%s: inc range start must not exceed end", where)
		}
		return ""
	}
	sa, ok1 := ipToU32(a)
	sb, ok2 := ipToU32(b)
	if !ok1 || !ok2 {
		return ""
	}
	if sb < sa {
		return fmt.Sprintf("%s: inc range start must not exceed end", where)
	}
	return ""
}

// checkIPFamilyMix rejects a range/list mixing IPv4 and IPv6 endpoints.
func checkIPFamilyMix(where string, vals []interface{}) string {
	seenV4, seenV6 := false, false
	for _, v := range vals {
		str, _ := v.(string)
		if isV6Literal(str) {
			seenV6 = true
		} else if validIPv4(str) {
			seenV4 = true
		}
	}
	if seenV4 && seenV6 {
		return fmt.Sprintf("%s: IPv4 and IPv6 endpoints must not mix (both ends must be the same family)", where)
	}
	return ""
}

// isV6Literal reports whether s parses as IPv6 (not IPv4).
func isV6Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// validIP reports whether s is a parseable IPv4 or IPv6 literal (D-FTP-4
// 双栈：既有 validIPv4 口径零变化 + net.ParseIP 的 IPv6 分支）。
func validIP(s string) bool {
	if validIPv4(s) {
		return true
	}
	return isV6Literal(s)
}

// validIPv4 reports whether s is a parseable dotted IPv4 address.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// genMAC resolves a MAC StrategyConfig at flow index i (D-FTP-3 §4):
// fixed/list as-is; inc/rand advance the low 3 bytes with OUI (high 3 bytes)
// preserved and wrap; pattern unsupported (rejected by checkDynShape).
func genMAC(s StrategyConfig, index int) string {
	switch s.Strategy {
	case "fixed", "":
		if v, ok := s.Value.(string); ok {
			return v
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return ""
		}
		return s.List[index%len(s.List)]
	case "inc", "rand":
		if len(s.Range) != 2 {
			return ""
		}
		start, ok1 := parseMAC(s.Range[0])
		end, ok2 := parseMAC(s.Range[1])
		if !ok1 || !ok2 {
			return ""
		}
		startLo := start & 0xFFFFFF
		endLo := end & 0xFFFFFF
		if endLo < startLo {
			return ""
		}
		oui := start & 0xFF0000000000
		count := endLo - startLo + 1
		var off uint64
		if s.Strategy == "inc" {
			step := s.Step
			if step <= 0 {
				step = 1
			}
			off = uint64((index * step) % int(count))
		} else {
			r := rand.New(rand.NewSource(s.Seed + int64(index)))
			off = uint64(r.Int63n(int64(count)))
		}
		return formatMAC(oui | ((startLo + off) & 0xFFFFFF))
	default:
		return ""
	}
}

// parseMAC parses "xx:xx:xx:xx:xx:xx" to a uint64.
func parseMAC(v interface{}) (uint64, bool) {
	str, _ := v.(string)
	parts := strings.Split(str, ":")
	if len(parts) != 6 {
		return 0, false
	}
	var n uint64
	for _, p := range parts {
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return 0, false
		}
		n = n<<8 | b
	}
	return n, true
}

// formatMAC formats a uint64 as "xx:xx:xx:xx:xx:xx".
func formatMAC(n uint64) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		(n>>40)&0xFF, (n>>32)&0xFF, (n>>24)&0xFF,
		(n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}

// genSmallInt resolves a small-integer StrategyConfig (TTL) at flow index i:
// fixed/list/inc/rand clamped to [min,max]; pattern unsupported.
func genSmallInt(s StrategyConfig, index int, min, max int) int {
	switch s.Strategy {
	case "fixed", "":
		return toInt(s.Value)
	case "list":
		if len(s.List) == 0 {
			return min
		}
		return toInt(s.List[index%len(s.List)])
	case "inc", "rand":
		if len(s.Range) != 2 {
			return min
		}
		start, end := toInt(s.Range[0]), toInt(s.Range[1])
		if end < start {
			return min
		}
		count := end - start + 1
		var v int
		if s.Strategy == "inc" {
			step := s.Step
			if step <= 0 {
				step = 1
			}
			v = start + (index*step)%count
		} else {
			r := rand.New(rand.NewSource(s.Seed + int64(index)))
			v = start + r.Intn(count)
		}
		if v < min {
			return min
		}
		if v > max {
			return max
		}
		return v
	default:
		return min
	}
}

// resolveLayerTuple applies parsed layer dynamics at flow index i onto the
// per-flow spec copy (D-FTP-3 §3). Non-zero resolutions win; zero/empty is a
// no-op preserving the static/default chain. Read-only on LayerDyn.
func resolveLayerTuple(spec *FlowSpec, i int) {
	ld := spec.LayerDyn
	if ld == nil {
		return
	}
	if ld.IP.Src != nil {
		if v := ResolveIPValue(ld.IP.Src, i); v != "" {
			spec.SrcIP = v
		}
	}
	if ld.IP.Dst != nil {
		if v := ResolveIPValue(ld.IP.Dst, i); v != "" {
			spec.DstIP = v
		}
	}
	if ld.IP.TTL != nil {
		if v := genSmallInt(*ld.IP.TTL, i, 0, 255); v != 0 {
			spec.TTL = uint8(v)
		}
	}
	if ld.TCP.SrcPort != nil {
		if v := ResolvePortValue(ld.TCP.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.TCP.DstPort != nil {
		if v := ResolvePortValue(ld.TCP.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	if ld.UDP.SrcPort != nil {
		if v := ResolvePortValue(ld.UDP.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.UDP.DstPort != nil {
		if v := ResolvePortValue(ld.UDP.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	// D-H323-1 决策 E1：h323 层端口逐流解析落 spec（与 tcp/udp 同款
	// "non-zero wins"；legacy Plan 按 spec 端口组装信令/媒体面）。
	// 顺序在 worker auto-increment 之后（同 tcp：层动态覆盖保底）。
	if ld.H323.SrcPort != nil {
		if v := ResolvePortValue(ld.H323.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.H323.DstPort != nil {
		if v := ResolvePortValue(ld.H323.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	// D-MPLS-1 决策 E1：mpls 层端口逐流解析落 spec（h323 同款）。
	if ld.MPLS.SrcPort != nil {
		if v := ResolvePortValue(ld.MPLS.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.MPLS.DstPort != nil {
		if v := ResolvePortValue(ld.MPLS.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	// D-NGAP-1 决策 E1：ngap 层端口逐流解析落 spec（h323/mpls 同款；
	// legacy Plan 按 spec 端口组装 SCTP 联结）。
	if ld.NGAP.SrcPort != nil {
		if v := ResolvePortValue(ld.NGAP.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.NGAP.DstPort != nil {
		if v := ResolvePortValue(ld.NGAP.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	// D-TELNET-1 决策 E1：telnet 层端口逐流解析落 spec（前三同款）。
	if ld.TELNET.SrcPort != nil {
		if v := ResolvePortValue(ld.TELNET.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.TELNET.DstPort != nil {
		if v := ResolvePortValue(ld.TELNET.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	if ld.Eth.SrcMAC != nil {
		if v := genMAC(*ld.Eth.SrcMAC, i); v != "" {
			spec.SrcMAC = v
		}
	}
	if ld.Eth.DstMAC != nil {
		if v := genMAC(*ld.Eth.DstMAC, i); v != "" {
			spec.DstMAC = v
		}
	}
	// D-HTTP-1 重走步骤 4：http 业务 6 回填。string 面经 ResolveStringValue
	// （fixed/list/pattern；空值 no-op 保留静态）；status_code 经 genSmallInt
	// int 面（fixed/inc/rand/list；0 值 no-op——0 即 builder 默认 200，保持
	// "non-zero wins" 与既有四元组同口径）。spec.HTTP nil 时建空补后再写
	// （层翻译已建非 nil，防御性补建）；只写回填字段，不碰其余 14 键。
	// 无跨流污染：回填值只读进标量字段（URI/Body/…），shared 指针
	// （RequestHeaders/ResponseHeaders map、FileSource）从不写；
	// 生成器侧 generateTerminal:117 + legacy http.go:91-107 逐流浅拷贝
	// struct 后再做 FileSource 解析，同 D-FTP-2 resolveTx 只写副本语义。
	// 注意：本函数只服务 mapToFlowSpec 直调/单测口径；层链引擎路径
	// （BuildLayersPlanner→translateTerminalConfig translateHTTPDyn）
	// 才是生产真相——worker resolveLayerTuple 跑在 Plan 之后，HTTP 已定。
	if ld.HTTP.URI != nil || ld.HTTP.Body != nil || ld.HTTP.BodyB64 != nil ||
		ld.HTTP.ResponseBody != nil || ld.HTTP.ResponseBodyB64 != nil ||
		ld.HTTP.ResponseStatusCode != nil {
		if spec.HTTP == nil {
			spec.HTTP = &HTTPConfig{}
		}
		if ld.HTTP.URI != nil {
			if v := ResolveStringValue(ld.HTTP.URI, i); v != "" {
				spec.HTTP.URI = v
			}
		}
		if ld.HTTP.Body != nil {
			if v := ResolveStringValue(ld.HTTP.Body, i); v != "" {
				spec.HTTP.Body = v
			}
		}
		if ld.HTTP.BodyB64 != nil {
			if v := ResolveStringValue(ld.HTTP.BodyB64, i); v != "" {
				spec.HTTP.BodyB64 = v
			}
		}
		if ld.HTTP.ResponseBody != nil {
			if v := ResolveStringValue(ld.HTTP.ResponseBody, i); v != "" {
				spec.HTTP.ResponseBody = v
			}
		}
		if ld.HTTP.ResponseBodyB64 != nil {
			if v := ResolveStringValue(ld.HTTP.ResponseBodyB64, i); v != "" {
				spec.HTTP.ResponseBodyB64 = v
			}
		}
		if ld.HTTP.ResponseStatusCode != nil {
			if v := genSmallInt(*ld.HTTP.ResponseStatusCode, i, 0, 65535); v != 0 {
				spec.HTTP.ResponseStatusCode = v
			}
		}
	}
	// D-TLS-1 步骤 2：tls 业务 sni 回填。string 面经 ResolveStringValue
	// （fixed/list/pattern；空值 no-op 保留静态）。spec.TLS nil 时建空补后
	// 再写（链上 spec.TLS 恒 nil 是合法态，防御性补建）；只写 SNI 一键，
	// 不碰 Version/Role/ALPN（关字段，对象进不来）。
	// 注意：http 段同款"只服务直调/单测口径"注记同样适用——链引擎路径
	// （translateTLS 消费段）才是生产真相，见 chain_planner_translate.go。
	if ld.TLS.SNI != nil {
		if spec.TLS == nil {
			spec.TLS = &TLSConfig{}
		}
		if v := ResolveStringValue(ld.TLS.SNI, i); v != "" {
			spec.TLS.SNI = v
		}
	}
	// D-TLS-2：cert subject/san 回填。string 面经 ResolveStringValue
	// （fixed/list/pattern；空值 no-op）。写入 spec.TLS.ServerCertificate
	//（只写解析键：Subject 整串替换/San 单元素；其余键留给 certgen 默认——
	// 与"缺省给全"同效）。spec.TLS nil 时建空补后再写（sni 段同款）。
	if ld.TLS.CertSubject != nil || ld.TLS.CertSAN != nil {
		if spec.TLS == nil {
			spec.TLS = &TLSConfig{}
		}
		if spec.TLS.ServerCertificate == nil {
			spec.TLS.ServerCertificate = &X509Ref{}
		}
		if ld.TLS.CertSubject != nil {
			if v := ResolveStringValue(ld.TLS.CertSubject, i); v != "" {
				spec.TLS.ServerCertificate.Subject = v
			}
		}
		if ld.TLS.CertSAN != nil {
			if v := ResolveStringValue(ld.TLS.CertSAN, i); v != "" {
				spec.TLS.ServerCertificate.San = []string{v}
			}
		}
	}
	// D-DNS-1：dns 业务 3 键回填。name 走 string 面（fixed/list/pattern；
	// 空值 no-op）；query_type/txid 走 int 面（fixed/inc/rand/list；0 值
	// no-op——0 即 builder 默认：query_type 0 无意义保静态、txid 0 即 0x1234
	// 回退，保持 "non-zero wins" 与既有四元组同口径）。spec.DNS nil 时建空
	// 补后再写（层翻译已建非 nil，防御性补建）；只写三键，不碰其余 11 键。
	// 注意：http/tls 段同款"只服务直调/单测口径"注记同样适用——链引擎路径
	// （translateDNSDyn）才是生产真相，见 chain_planner_translate.go。
	if ld.DNS.Name != nil || ld.DNS.QueryType != nil || ld.DNS.TxID != nil {
		if spec.DNS == nil {
			spec.DNS = &DNSConfig{}
		}
		if ld.DNS.Name != nil {
			if v := ResolveStringValue(ld.DNS.Name, i); v != "" {
				spec.DNS.Domain = v
			}
		}
		if ld.DNS.QueryType != nil {
			if v := ResolvePortValue(ld.DNS.QueryType, i); v != 0 {
				spec.DNS.QueryType = v
			}
		}
		if ld.DNS.TxID != nil {
			if v := ResolvePortValue(ld.DNS.TxID, i); v != 0 {
				spec.DNS.TxID = v
			}
		}
	}
	// D-MQTT-1：mqtt 业务 3 键回填（client_id string 面直写；topic/payload
	// 单策略语义——直调口径把解析值写进全部 Messages 槽。链引擎路径
	// translateMQTTDyn 逐槽独立解析（静态槽不动），混合静态/动态槽配置请走
	// 层链——http/tls/dns 段同款"只服务直调/单测口径"注记同样适用，生产
	// 真相见 chain_planner_translate.go）。空值 no-op 保留静态；spec.MQTT
	// nil 时建空补后再写（无 Messages 槽时 topic/payload 无处可写，no-op）。
	if ld.MQTT.ClientID != nil || ld.MQTT.Topic != nil || ld.MQTT.Payload != nil {
		if spec.MQTT == nil {
			spec.MQTT = &MQTTConfig{}
		}
		if ld.MQTT.ClientID != nil {
			if v := ResolveStringValue(ld.MQTT.ClientID, i); v != "" {
				spec.MQTT.ClientID = v
			}
		}
		if len(spec.MQTT.Messages) > 0 {
			for j := range spec.MQTT.Messages {
				if ld.MQTT.Topic != nil {
					if v := ResolveStringValue(ld.MQTT.Topic, i); v != "" {
						spec.MQTT.Messages[j].Topic = v
					}
				}
				if ld.MQTT.Payload != nil {
					if v := ResolveStringValue(ld.MQTT.Payload, i); v != "" {
						spec.MQTT.Messages[j].Payload = v
					}
				}
			}
		}
	}
}

// CheckLayerDynShape validates a decoded dynamic object for a layer field
// (exported for layers.checkLayerDynObjects; single truth with parseLayerDyn's
// checkDynShape). Returns "" when valid, else a human message prefixed with
// "lname.field: " (caller strips it and re-anchors to layers[i](name).field).
func CheckLayerDynShape(lname, field string, m map[string]interface{}) string {
	raw, err := json.Marshal(m)
	if err != nil {
		return "invalid object"
	}
	var sc StrategyConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		return "invalid object"
	}
	return checkDynShape(lname+"."+field, lname, field, &sc)
}

// LayerDynAllowlisted reports whether a layer field accepts dynamic objects
// (D-FTP-3 §4 allowlist; single truth shared by core parse and layers validate).
func LayerDynAllowlisted(lname, field string) bool {
	allowed, ok := layerDynAllowlist[lname]
	return ok && allowed[field]
}
