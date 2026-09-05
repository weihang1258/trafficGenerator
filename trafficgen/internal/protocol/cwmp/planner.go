// Package cwmp planner: negative-path validation (design §7 六负例族
// config/http_wire/xml_soap/session_state/correlation/length —— 每个被拒
// spec 的错误文本必含该族主锚词，error_contains 断言逐字对上) plus
// structural config checks. Every rejected spec must surface as a task
// error — never a completed/0-packet or TCP/HTTP-shell fake success.
package cwmp

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ouiPattern is the DeviceId OUI form: exactly six uppercase hex digits.
var ouiPattern = regexp.MustCompile(`^[0-9A-F]{6}$`)

// eventCodes is the fixture event-code value domain (design §3.5 实现子集
// 14/15 项 — "12 AUTONOMOUS DU STATE CHANGE COMPLETE" excluded per §1).
var eventCodes = map[string]bool{
	"0 BOOTSTRAP": true, "1 BOOT": true, "2 PERIODIC": true, "3 SCHEDULED": true,
	"4 VALUE CHANGE": true, "5 KICKED": true, "6 CONNECTION REQUEST": true,
	"7 TRANSFER COMPLETE": true, "8 DIAGNOSTICS COMPLETE": true,
	"9 REQUEST DOWNLOAD": true, "10 AUTONOMOUS TRANSFER COMPLETE": true,
	"M Download": true, "M Reboot": true, "M Upload": true, "M ScheduleDownload": true,
}

// maxEvents is the EventStruct array upper bound (A.3.3.1 EventStruct[64]).
const maxEvents = 64

// ACSReqKinds is the ACS RPC method domain (design §6 baseline RPC enum,
// snake_case). The named transaction kinds map onto these; acs_request's
// method field must be one of them.
var ACSReqKinds = map[string]bool{
	"get_parameter_values": true, "get_parameter_names": true,
	"set_parameter_values": true, "get_parameter_attributes": true,
	"set_parameter_attributes": true, "add_object": true, "delete_object": true,
	"factory_reset": true, "get_rpc_methods": true, "download": true,
	"upload": true, "schedule_download": true, "schedule_upload": true,
	"reboot": true, "kicked": true,
}

// maxIDLen is the cwmp:ID string(32) bound (§3.5 Table 4).
const maxIDLen = 32

// stringMax enumerates the string(64) DeviceId fields.
func Validate(spec core.FlowSpec) error {
	cfg := spec.CWMP
	if cfg == nil {
		// 空配置默认流（P0b）：生成器补基线单会话（inform→inform_response→
		// 空POST→204），validator 放行（gbt 同款先例）。
		return nil
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(cfg, sess, si); err != nil {
			return err
		}
	}
	return validateFlows(cfg)
}

// validateConfig checks the config-level fields (profile/namespace/carrier
// family).
func validateConfig(cfg *core.CWMPConfig) error {
	switch cfg.Profile {
	case "", "cwmp_http_v1", "cwmp_ipv6_v1":
	case "cwmp_https_boundary":
		// HTTPS 边界 profile 在明文 HTTP 链上是端口/载体声明矛盾（§1）。
		return fmt.Errorf("cwmp: profile %q is a TLS-only boundary profile: carrier mismatch on the plaintext http chain", cfg.Profile)
	default:
		return fmt.Errorf("cwmp: unknown profile %q (supported: cwmp_http_v1, cwmp_ipv6_v1)", cfg.Profile)
	}
	switch cfg.Namespace {
	case "", FixtureNamespace, "urn:dslforum-org:cwmp-1-1", "urn:dslforum-org:cwmp-1-2":
	default:
		if strings.Contains(cfg.Namespace, "www.w3.org") {
			// SOAP 1.2 envelope namespace — wire-format error (§1/§3.5).
			return fmt.Errorf("cwmp: namespace %q is a SOAP envelope namespace, not a CWMP data-model namespace (SOAP 1.2 envelope is a wire-format error)", cfg.Namespace)
		}
		return fmt.Errorf("cwmp: unknown namespace %q (supported: cwmp-1-0/-1-1/-1-2)", cfg.Namespace)
	}
	if err := validateAuth(cfg.Auth, "cwmp: config auth"); err != nil {
		return err
	}
	return nil
}

// validateSession walks one session's transactions: kind/direction legality,
// the strict HTTP alternation state machine (§5), correlation (cwmp:ID echo,
// CommandKey provenance), and the value/length domain.
//
// 方向模型：HTTP 严格一请求一响应——每笔事务恰是一帧；客户端帧（UP）只能跟
// 在服务端帧（DOWN）之后，反之亦然。定向 kind 钉死方向（inform/empty_post/
// 上报类是 CPE POST；inform_response/empty_response/挑战类是服务端帧）；
// 弹性 kind（acs_request/acs_response 含具名 *_response 族、fault）取前一
// 帧的反方向：acs_request 跟在 DOWN 帧后是 CPE 直接 POST（设计 §6 范例），
// 跟在 UP 帧后则是内嵌响应体下发（§4 场景② AcsRequests）。收尾 204 只认
// 应答空 POST 的那次（§5 收尾教义）；应答非空 POST 的 204 是中段 204，
// 会话继续（用例 #14）。Inform 被 Fault 应答：8005 → 原样重发（§3.7.1.6），
// 非 8005 → 会话失败终止（#105，无空 POST 直接挥手）；非 Inform 请求被
// Fault 应答 → 会话继续（#13）。
func validateSession(cfg *core.CWMPConfig, sess core.CWMPSession, si int) error {
	role := sess.Role
	if role == "" {
		role = "cpe"
	}
	if role != "cpe" && role != "acs_cr" {
		return fmt.Errorf("cwmp: sessions[%d]: unknown role %q (cpe|acs_cr)", si, sess.Role)
	}
	// cwmp:ID 上界（string(32)，Table 4）。
	if len(sess.URI) > 256 {
		return fmt.Errorf("cwmp: sessions[%d]: uri length %d exceeds 256", si, len(sess.URI))
	}
	if sess.DeviceID != nil {
		if err := validateDeviceID(sess.DeviceID, fmt.Sprintf("cwmp: sessions[%d]", si)); err != nil {
			return err
		}
	}

	// 状态机游标。
	lastWasUP := false  // 交替游标：上一帧的方向
	informSeen := false // Inform 建会话（A.3.3.1）
	terminated := false // 终态 204/200 空体或失败终止
	pendingKind := ""   // 等待其 DOWN 响应的 UP POST（"" = 无未决）
	pendingID := ""     // 该 UP POST 的 cwmp:ID（响应回带校验）
	lastInformID := ""  // 8005 重发的 id 对比基准
	idCounter := 0
	issued := map[string]bool{} // download/upload/reboot/schedule 下发的 CommandKey
	expectInformResend := false // Inform 被 8005 应答：下一笔必须是原样重发

	for ti, tx := range sess.Transactions {
		prefix := fmt.Sprintf("cwmp: sessions[%d].transactions[%d]", si, ti)
		if tx.Close && ti != len(sess.Transactions)-1 {
			// Close 只允许收尾响应携带（提前 close 会让后续事务无处安放）。
			return fmt.Errorf("%s: close flag on a non-final transaction (session would terminate mid-sequence)", prefix)
		}
		// cwmp:ID 长度上界。
		if len(tx.ID) > maxIDLen {
			return fmt.Errorf("%s: cwmp id length %d exceeds %d (string(32))", prefix, len(tx.ID), maxIDLen)
		}
		// HTTP wire-format negatives (§7 设计：HTTP method != POST、SOAPAction 非空、
		// Content-Type 非 text/xml、Content-Length 与实体不符、envelope 命名空间
		// 非 SOAP 1.1、Raw body 非法 XML）—— 任一显式注入即拒，与 §7 锚词
		// (method/SOAPAction/Content-Type/Content-Length/envelope) 一致。
		if err := validateHTTPWireFormat(prefix, tx); err != nil {
			return err
		}
		// Envelope namespace override（仅 Inform/InformResponse）：CWMP 规定 SOAP 1.1
		// envelope ns (http://schemas.xmlsoap.org/soap/envelope/)；覆盖为 SOAP 1.2
		// ns 是负例（§7 negative: envelope）。
		if tx.NamespaceOverride != "" {
			if strings.Contains(tx.NamespaceOverride, "2003/05/soap-envelope") {
				return fmt.Errorf("%s: value envelope namespace override %q (SOAP 1.2 not allowed, SOAP 1.1 required, §3.5)", prefix, tx.NamespaceOverride)
			}
		}
		// Download delay_seconds 范围：unsignedInt 上界为 2^32-1；≥2^32 即超界。
		// 700000 (≈ 8 days) 是合法值——设计 §3.4.3 要求 ≥ 2^32 (4294967296)
		// 才触发负例；uint32 unmarshal 接受它，所以这里用严格上界过滤。
		if tx.DelaySeconds != nil {
			if uint64(*tx.DelaySeconds) >= 1<<32 {
				return fmt.Errorf("%s: value download delay_seconds %d out of unsignedInt range (≥ 2^32, §3.4.3)", prefix, *tx.DelaySeconds)
			}
		}
		// 终态后的任何事务都是状态机违规。
		if terminated && tx.Kind != "" {
			return fmt.Errorf("%s: session state %q after the terminating empty post/response pair (no further transactions allowed, §5)", prefix, tx.Kind)
		}
		if expectInformResend && tx.Kind != "inform" {
			return fmt.Errorf("%s: session state %q after Inform was answered by an 8005 fault — the next transaction must be the verbatim Inform resend (§3.7.1.6)", prefix, tx.Kind)
		}

		// kind 归一：具名 ACS 请求/响应族折叠到 acs_request/acs_response
		// （method = 具名 kind / 去掉 _response 后缀）。
		kind := tx.Kind
		method := ""
		switch {
		case isACSRequestKind(kind):
			method = kind
			kind = "acs_request"
		case isACSResponseKind(kind):
			method = strings.TrimSuffix(kind, "_response")
			kind = "acs_response"
		case kind == "acs_request" || kind == "acs_response" || kind == "cpe_response":
			method = tx.Method
			if method != "" && !ACSReqKinds[method] {
				return fmt.Errorf("%s: unknown acs method %q", prefix, method)
			}
		}

		switch kind {
		case "inform":
			if role == "acs_cr" {
				return fmt.Errorf("%s: session state inform in an acs_cr (connection request) session (wrong role)", prefix)
			}
			if lastWasUP {
				return fmt.Errorf("%s: session state inform must be a client frame (previous transaction was also a client frame — HTTP alternation)", prefix)
			}
			if informSeen && !expectInformResend {
				return fmt.Errorf("%s: session state inform must be the first transaction of a session (A.3.3.1)", prefix)
			}
			if expectInformResend {
				// 8005 重发必须原样：显式 id 时须与首次 Inform 同值。
				if tx.ID != "" && tx.ID != lastInformID {
					return fmt.Errorf("%s: correlation the 8005 inform resend id %q must repeat the original id %q verbatim (§3.7.1.6)", prefix, tx.ID, lastInformID)
				}
			}
			if err := validateInformBody(prefix, tx); err != nil {
				return err
			}
			// 事件组合规则（§3.7.1.5/负例 146-149）。
			if err := validateEventCombo(prefix, tx.Events); err != nil {
				return err
			}
			idCounter++
			pendingID = resolveID(tx.ID, idCounter)
			lastInformID = pendingID
			pendingKind = "inform"
			informSeen = true
			expectInformResend = false
			lastWasUP = true
		case "inform_response":
			if !lastWasUP || pendingKind != "inform" {
				return fmt.Errorf("%s: session state inform response with no pending inform to answer (§5)", prefix)
			}
			if err := checkIDCorrelation(prefix, tx, pendingID, "correlation"); err != nil {
				return err
			}
			pendingKind = ""
			pendingID = ""
			lastWasUP = false
		case "empty_post":
			if role == "acs_cr" {
				return fmt.Errorf("%s: session state empty post in an acs_cr session (wrong role)", prefix)
			}
			if !informSeen {
				return fmt.Errorf("%s: session state first transaction must be inform (got empty post)", prefix)
			}
			idCounter++
			pendingID = resolveID(tx.ID, idCounter)
			pendingKind = "empty_post"
			lastWasUP = true
		case "empty_response":
			if role == "acs_cr" {
				return fmt.Errorf("%s: session state 204 empty response in an acs_cr session (use empty_ok 200)", prefix)
			}
			if !lastWasUP {
				return fmt.Errorf("%s: session state empty response with no pending request to answer (§5)", prefix)
			}
			if err := checkIDCorrelation(prefix, tx, pendingID, "correlation"); err != nil {
				return err
			}
			// 收尾教义：应答空 POST 的 204 终止会话；应答非空 POST 的
			// 204 是中段 204（ACS 无后续请求），会话继续（#14）。
			if pendingKind == "empty_post" {
				terminated = true
			}
			pendingKind = ""
			pendingID = ""
			lastWasUP = false
		case "empty_ok":
			if !lastWasUP {
				return fmt.Errorf("%s: session state 200 empty response with no pending request to answer (§5)", prefix)
			}
			terminated = true
			pendingKind = ""
			pendingID = ""
			lastWasUP = false
		case "transfer_complete", "autonomous_transfer_complete", "request_download":
			if role == "acs_cr" {
				return fmt.Errorf("%s: session state CPE report %q in an acs_cr session", prefix, tx.Kind)
			}
			if lastWasUP {
				return fmt.Errorf("%s: session state CPE report %q while a response to the pending %s is owed", prefix, tx.Kind, pendingKind)
			}
			if !informSeen {
				return fmt.Errorf("%s: session state CPE request before inform (first transaction must be inform)", prefix)
			}
			if tx.Kind == "transfer_complete" {
				// 关联：CommandKey 必须回指本会话或前会话 Download/Upload。
				if !issued[tx.CommandKey] {
					return fmt.Errorf("%s: correlation transfer_complete command key %q has no issuing download/upload (§5)", prefix, tx.CommandKey)
				}
			}
			idCounter++
			pendingID = resolveID(tx.ID, idCounter)
			pendingKind = tx.Kind
			lastWasUP = true
		case "transfer_complete_response", "autonomous_transfer_complete_response", "request_download_response":
			// pendingKind holds the request kind ("transfer_complete") but tx.Kind is the
			// response kind ("transfer_complete_response") — compare against the request kind.
			reqKind := strings.TrimSuffix(tx.Kind, "_response")
			if !lastWasUP || pendingKind != reqKind {
				return fmt.Errorf("%s: session state %s with no pending %s to answer (§5)", prefix, tx.Kind, reqKind)
			}
			if err := checkIDCorrelation(prefix, tx, pendingID, "correlation"); err != nil {
				return err
			}
			pendingKind = ""
			pendingID = ""
			lastWasUP = false
		case "connection_request", "connection_request_authorized":
			if role != "acs_cr" {
				return fmt.Errorf("%s: session state connection request outside an acs_cr session (role %q)", prefix, sess.Role)
			}
			if lastWasUP {
				return fmt.Errorf("%s: session state connection request must be a client frame (HTTP alternation)", prefix)
			}
			pendingKind = "connection_request"
			lastWasUP = true
		case "auth_challenge":
			if role != "acs_cr" {
				return fmt.Errorf("%s: session state auth challenge outside an acs_cr session (401 rides the reverse connection)", prefix)
			}
			if !lastWasUP {
				return fmt.Errorf("%s: session state auth challenge with no pending connection request to answer (§5)", prefix)
			}
			pendingKind = ""
			pendingID = ""
			lastWasUP = false
		case "acs_request":
			if method == "" {
				return fmt.Errorf("%s: acs_request missing method", prefix)
			}
			if role != "cpe" {
				return fmt.Errorf("%s: session state ACS request %q on a non-cpe session (direction error)", prefix, method)
			}
			if err := validateACSRequest(prefix, tx, method); err != nil {
				return err
			}
			if lastWasUP {
				// 内嵌响应体下发（§4 场景②）：响应应答未决 UP POST 并
				// 携带 ACS 请求，CPE 下一 POST 必须是其 Response。
				idCounter++
				pendingID = resolveID(tx.ID, idCounter)
				pendingKind = "acs_riding:" + method
			} else {
				// CPE 直接 POST（设计 §6 范例；get_rpc_methods_cpe_to_acs
				// 同款）。
				if !informSeen {
					return fmt.Errorf("%s: session state CPE request before inform (first transaction must be inform)", prefix)
				}
				idCounter++
				pendingID = resolveID(tx.ID, idCounter)
				pendingKind = "acs_request:" + method
			}
			if tx.CommandKey != "" && (method == "download" || method == "upload" || method == "reboot" || method == "schedule_download") {
				issued[tx.CommandKey] = true
			}
			lastWasUP = !lastWasUP
		case "acs_response":
			if lastWasUP {
				// 形状 a：DOWN 帧应答直接 POST 的 ACS 请求。
				if !strings.HasPrefix(pendingKind, "acs_request:") {
					return fmt.Errorf("%s: session state response with no pending ACS request to answer (§5)", prefix)
				}
				if err := checkIDCorrelation(prefix, tx, pendingID, "correlation"); err != nil {
					return err
				}
				pendingKind = ""
				pendingID = ""
			} else {
				// 形状 b：UP 帧——CPE POST 对内嵌下发 ACS 请求的响应。
				if !strings.HasPrefix(pendingKind, "acs_riding:") {
					return fmt.Errorf("%s: session state response with no pending ACS request to answer (§5)", prefix)
				}
				if err := checkIDCorrelation(prefix, tx, pendingID, "correlation"); err != nil {
					return err
				}
				// acs_response completes the acs_riding. Clear pendingKind — no further
				// response is owed. pendingID tracks the acs_response.id for next riding.
				idCounter++
				pendingID = resolveID(tx.ID, idCounter)
				pendingKind = "" // not "acs_response:*" — shape b ends the transaction pair
			}
			lastWasUP = !lastWasUP
		case "fault":
			// Fault 只能作为对请求的响应出现（§3.4）。
			if tx.Fault != nil {
				if err := validateFault(prefix, tx.Fault); err != nil {
					return err
				}
			}
			// 无未决请求时 Fault 无对象可应答（§3.5 negative）：DOWN 帧
			// 且 pendingKind 为空（即 empty_post 已收 204 收尾）即拒。
			if lastWasUP && pendingKind == "" && !terminated {
				return fmt.Errorf("%s: session state fault with no pending request to answer (Fault answers a request, never a response/Fault, §3.5)", prefix)
			}
			if lastWasUP {
				// DOWN 帧：应答未决 UP 请求。
				if pendingKind == "inform" {
					if tx.Fault != nil && tx.Fault.Code == 8005 {
						// 原样重发（§3.7.1.6）；lastInformID 保留供重发
						// id 对比。
						expectInformResend = true
					} else {
						// Inform 收非 8005 Fault：会话失败终止（#105）。
						terminated = true
					}
				}
				// 非 Inform 请求收 Fault：会话继续（#13）。
				pendingKind = ""
				pendingID = ""
			} else {
				// UP 帧：CPE POST 对内嵌下发 ACS 请求的 Fault 应答。
				if !strings.HasPrefix(pendingKind, "acs_riding:") {
					return fmt.Errorf("%s: sequence fault with no pending request to answer (Fault answers a request, never another response/Fault, §3.5)", prefix)
				}
				idCounter++
				pendingID = resolveID(tx.ID, idCounter)
				pendingKind = "acs_response:fault"
			}
			lastWasUP = !lastWasUP
		case "empty_ok_204":
			return fmt.Errorf("%s: unknown kind %q (empty_ok is 200, empty_response is 204)", prefix, tx.Kind)
		default:
			return fmt.Errorf("%s: unknown kind %q", prefix, tx.Kind)
		}
	}
	if expectInformResend {
		return fmt.Errorf("cwmp: sessions[%d]: session ends awaiting the 8005 inform resend (§3.7.1.6)", si)
	}
	return nil
}

// resolveID returns the transaction's explicit id or the auto-derived
// per-session counter value.
func resolveID(explicit string, counter int) string {
	if explicit != "" {
		return explicit
	}
	return strconv.Itoa(counter)
}

// checkIDCorrelation asserts the response's echoed cwmp:ID matches the
// pending request's id (Table 4 — explicit for_id only checked when given;
// mismatches are the correlation negative).
func checkIDCorrelation(prefix string, tx core.CWMPTransaction, pendingReqID, anchor string) error {
	if pendingReqID == "" {
		return nil
	}
	got := tx.ForID
	if got == "" {
		got = tx.ID
	}
	if got == "" {
		return nil // generator echoes the pending id
	}
	if got != pendingReqID {
		return fmt.Errorf("%s: %s response cwmp id %q does not match the request id %q", prefix, anchor, got, pendingReqID)
	}
	return nil
}

// validateEventCombo enforces the M-combo and mutual-exclusion rules
// (design §3.7.1.5 + 负例 146-149): M Download/M Upload require 7 TRANSFER
// COMPLETE in the same Inform; M Reboot requires 1 BOOT; 0 BOOTSTRAP and
// 1 BOOT are mutually exclusive.
func validateEventCombo(prefix string, events []core.CWMPSOAPEvent) error {
	has7, hasBoot, hasBootstrap, mDownload, mUpload, mReboot := false, false, false, false, false, false
	for _, ev := range events {
		switch ev.Code {
		case "7 TRANSFER COMPLETE":
			has7 = true
		case "1 BOOT":
			hasBoot = true
		case "0 BOOTSTRAP":
			hasBootstrap = true
		case "M Download":
			mDownload = true
		case "M Upload":
			mUpload = true
		case "M Reboot":
			mReboot = true
		}
	}
	if (mDownload || mUpload) && !has7 {
		return fmt.Errorf("%s: value M Download/M Upload event requires a same-inform 7 TRANSFER COMPLETE event (§3.7.1.5)", prefix)
	}
	if mReboot && !hasBoot {
		return fmt.Errorf("%s: value M Reboot event requires a same-inform 1 BOOT event (§3.7.1.5)", prefix)
	}
	if hasBootstrap && hasBoot {
		return fmt.Errorf("%s: value 0 BOOTSTRAP and 1 BOOT are mutually exclusive in one Inform (first boot vs reboot boot)", prefix)
	}
	return nil
}

// validateInformBody checks the inform transaction's nested value domains.
func validateInformBody(prefix string, tx core.CWMPTransaction) error {
	if len(tx.Events) > maxEvents {
		return fmt.Errorf("%s: length event array has %d entries, exceeds the EventStruct[64] bound", prefix, len(tx.Events))
	}
	for i, ev := range tx.Events {
		if !eventCodes[ev.Code] {
			return fmt.Errorf("%s: value event code %q invalid (not in the fixture event-code domain)", prefix, ev.Code)
		}
		if len(ev.Code) > 64 {
			return fmt.Errorf("%s: length event code %d chars exceeds string(64)", prefix, i)
		}
		if len(ev.CommandKey) > 32 {
			return fmt.Errorf("%s: parameter event command key length %d exceeds string(32)", prefix, len(ev.CommandKey))
		}
	}
	for _, p := range tx.ParameterList {
		if len(p.Name) > 256 {
			return fmt.Errorf("%s: length parameter name length %d exceeds string(256)", prefix, len(p.Name))
		}
	}
	return validateDeviceIDRef(prefix, tx.DeviceID)
}

func validateDeviceIDRef(prefix string, dev *core.CWMPDeviceID) error {
	if dev == nil {
		return nil
	}
	return validateDeviceID(dev, prefix)
}

func validateDeviceID(dev *core.CWMPDeviceID, prefix string) error {
	if !ouiPattern.MatchString(dev.OUI) {
		return fmt.Errorf("%s: value oui %q is not six uppercase hex digits (^[0-9A-F]{6}$)", prefix, dev.OUI)
	}
	for _, f := range []struct{ name, v string }{
		{"manufacturer", dev.Manufacturer}, {"product_class", dev.ProductClass},
		{"serial", dev.SerialNumber},
	} {
		if len(f.v) > 64 {
			return fmt.Errorf("%s: length device %s length %d exceeds string(64)", prefix, f.name, len(f.v))
		}
	}
	return nil
}

// validateACSRequest checks the named ACS request transactions' value
// domains (FileType enum, URL userinfo, lengths).
func validateACSRequest(prefix string, tx core.CWMPTransaction, method string) error {
	switch method {
	case "download", "upload", "schedule_download", "schedule_upload":
		if tx.FileType != "" && !fileTypeValid(tx.FileType) {
			return fmt.Errorf("%s: value file type %q invalid (not in the FileType enum)", prefix, tx.FileType)
		}
		if err := validateTransferURL(prefix, tx.URL); err != nil {
			return err
		}
		if len(tx.CommandKey) > 32 {
			return fmt.Errorf("%s: parameter command key length %d exceeds string(32)", prefix, len(tx.CommandKey))
		}
	case "reboot":
		if len(tx.CommandKey) > 32 {
			return fmt.Errorf("%s: parameter command key length %d exceeds string(32)", prefix, len(tx.CommandKey))
		}
	case "set_parameter_values", "add_object", "delete_object":
		if len(tx.ParameterKey) > 32 {
			return fmt.Errorf("%s: parameter parameter key length %d exceeds string(32)", prefix, len(tx.ParameterKey))
		}
		for _, p := range tx.ParameterList {
			if len(p.Name) > 256 {
				return fmt.Errorf("%s: length parameter name length %d exceeds string(256)", prefix, len(p.Name))
			}
		}
		if len(tx.ObjectName) > 256 {
			return fmt.Errorf("%s: length object name length %d exceeds string(256)", prefix, len(tx.ObjectName))
		}
	}
	return nil
}

// fileTypeValid checks the FileType enum (Table 33: "1 Firmware Upgrade
// Image" ... "6 Stored Firmware Image" or vendor "X <vendor> <id>").
func fileTypeValid(ft string) bool {
	switch ft {
	case "1 Firmware Upgrade Image", "2 Web Content", "3 Vendor Configuration File",
		"4 Tone File", "5 Ringer File", "6 Stored Firmware Image":
		return true
	}
	if strings.HasPrefix(ft, "X ") {
		return true // vendor extension form
	}
	return false
}

// validateTransferURL rejects userinfo components (§3.5 A.3.2.8 URL
// string(256) 禁止 userinfo).
func validateTransferURL(prefix, rawURL string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s: value url %q does not parse: %v", prefix, rawURL, err)
	}
	if u.User != nil {
		return fmt.Errorf("%s: value url %q carries a userinfo component (forbidden, §3.5)", prefix, rawURL)
	}
	return nil
}

// validateFault checks a fault config's code domain (A.5.1/A.5.2).
func validateFault(prefix string, fault *core.CWMPFault) error {
	return validateFaultCode(prefix, fault.Code)
}

func validateFaultCode(prefix string, code int) error {
	switch {
	case code >= 8000 && code <= 8006, code >= 8800 && code <= 8899:
		return nil // ACS
	case code >= 9000 && code <= 9009, code >= 9010 && code <= 9020,
		code >= 9800 && code <= 9899:
		return nil // CPE
	}
	return fmt.Errorf("%s: value fault code %d is outside the CPE (9000-9009/9010-9020/9800-9899) and ACS (8000-8006/8800-8899) domains", prefix, code)
}

// validateHTTPWireFormat checks per-transaction HTTP wire-format fields for
// §7 negative cases (method/SOAPAction/Content-Type/Content-Length/envelope).
func validateHTTPWireFormat(prefix string, tx core.CWMPTransaction) error {
	if tx.HTTPMethod != "" && tx.HTTPMethod != "POST" {
		return fmt.Errorf("%s: value http method %q (SOAP must be POST, §3.4.1)", prefix, tx.HTTPMethod)
	}
	if tx.SoapAction != nil && *tx.SoapAction != "" {
		return fmt.Errorf("%s: value SOAPAction %q (must be empty, §3.4.1)", prefix, *tx.SoapAction)
	}
	if tx.ContentType != "" && tx.ContentType != "text/xml" {
		return fmt.Errorf("%s: value Content-Type %q (must be text/xml, §3.4.1)", prefix, tx.ContentType)
	}
	if tx.ContentLengthOverride != nil {
		return fmt.Errorf("%s: value Content-Length override %d (mismatch = wire error, §3.4.1)", prefix, *tx.ContentLengthOverride)
	}
	// Raw body: if provided, it must be a well-formed XML SOAP envelope with
	// the SOAP 1.1 namespace (http://schemas.xmlsoap.org/soap/envelope/).
	if tx.RawBody != "" {
		// Quick namespace scan (avoids full XML parse of large envelopes).
		hasSOAP11NS := strings.Contains(tx.RawBody, "http://schemas.xmlsoap.org/soap/envelope/")
		hasSOAP12NS := strings.Contains(tx.RawBody, "http://www.w3.org/2003/05/soap-envelope")
		if !hasSOAP11NS || hasSOAP12NS {
			return fmt.Errorf("%s: value raw body namespace (envelope: SOAP 1.1 required, §3.5)", prefix)
		}
		// Well-formed XML check.
		decoder := xml.NewDecoder(strings.NewReader(tx.RawBody))
		for {
			_, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("%s: value raw body is not well-formed XML (xml_soap: %v)", prefix, err)
			}
		}
	}
	return nil
}

// validateFlows checks the flow-correlation side connections' config and
// their driven_by anchors (design §5/§6: the anchor must reference an
// existing main-session transaction of the transfer family).
func validateFlows(cfg *core.CWMPConfig) error {
	for fi, fl := range cfg.Flows {
		prefix := fmt.Sprintf("cwmp: flows[%d]", fi)
		switch fl.Kind {
		case "http_get", "http_put":
		default:
			return fmt.Errorf("%s: unknown kind %q (http_get|http_put)", prefix, fl.Kind)
		}
		if fl.SrcPort == 0 {
			return fmt.Errorf("%s: src port 0 (side connections need an independent four-tuple)", prefix)
		}
		if fl.Host == "" {
			return fmt.Errorf("%s: missing host (file server address required)", prefix)
		}
		if fl.Port == 0 {
			return fmt.Errorf("%s: missing port (file server port required)", prefix)
		}
		if fl.DrivenBy == nil {
			return fmt.Errorf("%s: missing driven_by (flow correlation requires an explicit anchor, design §5)", prefix)
		}
		// 锚点核对：session 下标有效，transaction 是该会话中实际出现的
		// 事务 kind（驱动事务 = download/upload/download_response/
		// upload_response 之一——设计 §5 插入位置锚定）。
		if fl.DrivenBy.Session < 0 || fl.DrivenBy.Session >= len(cfg.Sessions) {
			return fmt.Errorf("%s: correlation driven_by session %d does not exist (config has %d sessions)", prefix, fl.DrivenBy.Session, len(cfg.Sessions))
		}
		sess := cfg.Sessions[fl.DrivenBy.Session]
		found := false
		for _, tx := range sess.Transactions {
			if tx.Kind == fl.DrivenBy.Transaction {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: correlation driven_by transaction %q not found in sessions[%d] (anchor must reference an existing transaction kind)", prefix, fl.DrivenBy.Transaction, fl.DrivenBy.Session)
		}
	}
	return nil
}

// validateAuth checks the digest auth material's value domain (qop must be
// auth; algorithm MD5/MD5-sess).
func validateAuth(auth *core.CWMPAuth, prefix string) error {
	if auth == nil {
		return nil
	}
	if auth.QOP != "" && auth.QOP != "auth" && auth.QOP != "auth-int" {
		return fmt.Errorf("%s: value qop %q invalid (auth|auth-int)", prefix, auth.QOP)
	}
	if auth.Algorithm != "" && auth.Algorithm != "MD5" && auth.Algorithm != "MD5-sess" {
		return fmt.Errorf("%s: value algorithm %q invalid (MD5|MD5-sess)", prefix, auth.Algorithm)
	}
	return nil
}
