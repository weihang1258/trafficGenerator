// Package megaco planner: negative-path validation (31 wire_fault kinds per
// design §7 / testcase §4) plus structural config checks. Every rejected
// spec must surface as a task error — never a completed/0-packet or
// transport-shell fake success.
package megaco

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wireFaultAnchors maps each wire_fault kind to its error_contains anchor
// (设计 §7/testcase §5 主锚词钉死). All negatives must surface as a task
// error carrying this anchor.
var wireFaultAnchors = map[string]string{
	// encoding
	"encoding_text_as_ber":   "encoding",
	"encoding_port_mismatch": "encoding",
	// line-format (start line / version / mId / body / services)
	"syntax_start_line":              "message",
	"syntax_version_zero":            "version",
	"syntax_version_three_digits":    "version",
	"syntax_mid_missing":             "mid",
	"syntax_mid_invalid":             "mid",
	"syntax_body_form":               "message",
	"syntax_services_missing_params": "message",
	// state-machine
	"command_pre_registration":      "command",
	"command_modify_nonexistent":    "command",
	"command_reply_choose_all":      "command",
	"command_uncreated_context":     "command",
	"command_first_error_continues": "command",
	// transaction correlation
	"pairing_reply_id_mismatch":   "transaction",
	"pairing_pending_id_mismatch": "transaction",
	"pairing_duplicate_transid":   "transaction",
	"pairing_ack_unconfirmed":     "transaction",
	"pairing_ia_without_pending":  "transaction",
	"pairing_observed_requestid":  "transaction",
	// length
	"length_message_truncated":   "length",
	"length_termid_over_64":      "length",
	"length_transid_over_uint32": "length",
	"length_digitmap_timer":      "length",
	"length_context_reserved":    "length",
	// carrier
	"carrier_layer_mismatch":      "carrier",
	"carrier_entry_port_encoding": "carrier",
	"carrier_invalid_port":        "port",
	"carrier_return_address":      "carrier",
	"carrier_udp_mtu_exceeded":    "length",
	// services parameter
	"services_address_mgcidtotry_conflict": "services",
}

// commandNames is the RFC 3525 eight-command domain (§3.4).
var commandNames = map[string]bool{
	"Add": true, "Modify": true, "Subtract": true, "Move": true,
	"AuditValue": true, "AuditCapability": true, "Notify": true, "ServiceChange": true,
}

// contextIDReserved are the ContextID reserved values that may not appear
// as concrete numeric Contexts (§8.1.2; negative 71).
var contextIDReserved = map[uint64]bool{
	0: true, 0xFFFFFFFE: true, 0xFFFFFFFF: true,
}

// Validate runs all megaco config validation. nil cfg = empty default stream
// (one registration on UDP/2944).
func Validate(spec core.FlowSpec) error {
	cfg := spec.Megaco
	if cfg == nil {
		// empty config default flow (P0b baseline): one MG→MGC SC(Restart)
		// on UDP/2944. Validator放行，generator补基线。
		return nil
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.WireFault != "" {
		anchor, ok := wireFaultAnchors[cfg.WireFault]
		if !ok {
			return fmt.Errorf("megaco: unknown wire_fault %q (must be one of 31 design §7 kinds)", cfg.WireFault)
		}
		// doh/onvif/hl7 家族约定：已知 wire_fault 必拒并携带主锚词——所有
		// 负例以 task error 形态呈现，绝不静默放行成 0 包假成功。
		return fmt.Errorf("megaco: wire fault %q injected (%s)", cfg.WireFault, anchor)
	}
	carrier, _ := spec.Metadata["megaco_carrier"].(string)
	for si, sess := range cfg.Sessions {
		if err := validateSession(cfg, sess, si); err != nil {
			return err
		}
		// D-MEGACO-1 修轮 F5/F1：UDP 单数据报 ≤1472（1500-20-8，Annex D.1
		// 不做 IP 分片依赖）；TCP TPKT PDU ≤0xFFFF（RFC 1006 16-bit 长度域）。
		sizes, rerr := sessionRenderSizes(cfg, sess, spec.SrcIP, spec.DstIP)
		if rerr != nil {
			return rerr
		}
		for ei, n := range sizes {
			switch carrier {
			case "udp":
				if n > 1472 {
					return fmt.Errorf("megaco: sessions[%d].events[%d]: UDP datagram %d bytes exceeds the MTU budget 1472 — use a tcp carrier for long messages (%s)", si, ei, n, "length")
				}
			case "tcp":
				if n+4 > 0xFFFF {
					return fmt.Errorf("megaco: sessions[%d].events[%d]: TPKT PDU %d bytes exceeds the RFC 1006 16-bit length domain (%s)", si, ei, n+4, "length")
				}
			}
		}
	}
	return nil
}

func validateConfig(cfg *core.MegacoConfig) error {
	switch cfg.Profile {
	case "", "megaco_v1_text", "mgcp_alias", "megaco_v1_ber":
	default:
		return fmt.Errorf("megaco: profile %q is not supported (megaco_v1_text|mgcp_alias|megaco_v1_ber)", cfg.Profile)
	}
	if cfg.Encoding != "" && cfg.Encoding != "text" {
		// D-MEGACO-1 修轮 F6：ber 仅是 profile 边界声明，本版不产 BER 载荷
		//（契约 §1/负例 47）——自然面即拒（旧版放行 "ber" 使该故障只能经
		// wire_fault 表达）。
		return fmt.Errorf("megaco: encoding %q is not produced in this version (text only; ber is a boundary declaration, not a payload)", cfg.Encoding)
	}
	if cfg.Version < 0 || cfg.Version > 99 {
		return fmt.Errorf("megaco: version %d out of 1*2 DIGIT range", cfg.Version)
	}
	switch cfg.TokenForm {
	case "", "long", "abbrev":
	default:
		return fmt.Errorf("megaco: token_form %q invalid (long|abbrev)", cfg.TokenForm)
	}
	switch cfg.Whitespace {
	case "", "cr", "comment", "lwsp":
	default:
		return fmt.Errorf("megaco: whitespace %q invalid (cr|comment|lwsp)", cfg.Whitespace)
	}
	return nil
}

// validateSession enforces the §5.2 state machine and §3 text-shape rules.
func validateSession(cfg *core.MegacoConfig, sess core.MegacoSession, si int) error {
	prefix := fmt.Sprintf("megaco: sessions[%d]", si)
	if sess.Role != "" && sess.Role != "mg" && sess.Role != "mgc" {
		return fmt.Errorf("%s: role %q invalid (mg|mgc)", prefix, sess.Role)
	}
	// mId 四形校验（§3.1：domainAddress [..][:port] / domainName <..> /
	// mtpAddress MTP{hex} / deviceName pathNAME）——显式写的 mid/peer_mid
	// 必须落四形之一（D-MEGACO-1 修2：neg53 自然面守卫，长度仍 ≤64）。
	if err := validateMidForm(prefix+": mid", sess.Mid); err != nil {
		return err
	}
	if err := validateMidForm(prefix+": peer_mid", sess.PeerMid); err != nil {
		return err
	}
	role := sess.Role
	if role == "" {
		role = "mg"
	}
	// Build the set of "established numeric Contexts" as we walk the events.
	// We start empty; reply transactions may add to it. Reply transactions
	// carrying $-ctx or numeric Context that is not yet created are rejected
	// (neg 59). Numeric Context in request is allowed (it's a concrete
	// address; creation semantics belong to Add).
	createdContexts := map[uint64]bool{}
	choseRequested := false            // a request used $-CHOOSE; next reply may fill numeric ctx
	eventsPending := map[uint32]bool{} // pending Transactions
	confirmedTransactions := map[uint32]bool{}
	seenTransIDs := map[uint32]bool{}
	requestOrder := []uint32{}            // insertion-order of request ids (for same_as_request:N)
	observedReqIDs := map[string]uint32{} // terminationID -> last active Events RequestID（neg66 关联校验收口）

	// Walk events in order. State-machine rules per §5.2.
	for ei, ev := range sess.Events {
		evPrefix := fmt.Sprintf("%s.events[%d]", prefix, ei)
		if ev.Kind != "" && ev.Kind != "message" {
			return fmt.Errorf("%s: kind %q invalid (message)", evPrefix, ev.Kind)
		}
		if ev.Direction != "" && ev.Direction != "c2s" && ev.Direction != "s2c" {
			return fmt.Errorf("%s: direction %q invalid (c2s|s2c)", evPrefix, ev.Direction)
		}
		// 注册前违规（neg56）不设自然面守卫：契约 §5.2 初始状态规则——
		// 首事件为 MG 注册类 SC 才从 Unregistered 起步，否则会话初始即
		// Registered 等价态（声明式回放的预配置控制关联，注册只是可选首
		// 事件）——自然配置下"未注册先发命令"不可构造，该故障唯一入口=
		// wire_fault command_pre_registration（闭包枚举已拒）。
		// Transactions inside this message. Per-event wire_fault rejects
		// with the anchor (fault-isolation: one bad event fails the spec).
		if ev.WireFault != "" {
			anchor, ok := wireFaultAnchors[ev.WireFault]
			if !ok {
				return fmt.Errorf("%s: unknown wire_fault %q (must be one of 31 design §7 kinds)", evPrefix, ev.WireFault)
			}
			return fmt.Errorf("%s: wire fault %q injected (%s)", evPrefix, ev.WireFault, anchor)
		}
		for ti, tx := range ev.Transactions {
			txPrefix := fmt.Sprintf("%s.transactions[%d]", evPrefix, ti)
			if err := validateTransaction(txPrefix, tx, role, &createdContexts, &choseRequested, &eventsPending, &confirmedTransactions, &seenTransIDs, &requestOrder, &observedReqIDs); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTransaction(
	prefix string,
	tx core.MegacoTransaction,
	role string,
	createdContexts *map[uint64]bool,
	choseRequested *bool,
	eventsPending *map[uint32]bool,
	confirmedTransactions *map[uint32]bool,
	seenTransIDs *map[uint32]bool,
	requestOrder *[]uint32,
	observedReqIDs *map[string]uint32,
) error {
	switch tx.Type {
	case "", "request":
		// errorDescriptor is a reply-side construct (§8.2.3); a request
		// carrying it is a shape error.
		if tx.Error != nil {
			return fmt.Errorf("%s: error descriptor only valid on type=reply (message)", prefix)
		}
		// Remember the request's id so reply/pending can reference it.
		// "auto" is the generator-side alias for a per-session counter
		// starting at 1; for validator purposes we treat it as id 1 (the
		// first auto-allocated id) so that same_as_request:0 alias on the
		// reply side resolves correctly.
		if tx.ID != "" {
			idStr := tx.ID
			if idStr == "auto" {
				idStr = "1"
			}
			// D-MEGACO-1 修轮 F4：显式 transactionId 必须 parse 为 UINT32
			//（契约 §8 ">4294967295 拒绝"）——旧版解析失败静默跳过，越界值
			// 原样落线（probe11 实证）。
			v, perr := strconv.ParseUint(idStr, 10, 32)
			if perr != nil {
				return fmt.Errorf("%s: transaction id %q is not a UINT32 decimal (1..4294967295) (%s)", prefix, tx.ID, "length")
			}
			// D-MEGACO-1 修轮 F9：同会话 transactionId 作用域唯一（RFC 3525
			// §8.1.1；重复 = At-Most-Once 去重失效，锚 transaction）。
			if (*seenTransIDs)[uint32(v)] {
				return fmt.Errorf("%s: duplicate transaction id %d within the session scope (%s)", prefix, v, "transaction")
			}
			(*seenTransIDs)[uint32(v)] = true
			*requestOrder = append(*requestOrder, uint32(v))
		}
		// validate per-action below
	case "reply":
		// check transactionId resolves and matches the request.
		id, err := resolveTxID(tx.ID, prefix, false, seenTransIDs, confirmedTransactions, requestOrder)
		if err != nil {
			return err
		}
		// Transaction-level errorDescriptor (RFC 3525 §8.2.3):
		// actionReplyList / errorDescriptor are mutually exclusive. A reply
		// carrying Error must not also carry Actions; Error on non-reply
		// types is rejected below via the same rule.
		if tx.Error != nil && len(tx.Actions) > 0 {
			return fmt.Errorf("%s: reply carries both error descriptor and actions — transactionReply is (actionReplyList / errorDescriptor), not both (message)", prefix)
		}
		// Pairing checks: reply must reference an existing pending/issued
		// request. We don't require perfect pairing ordering here (the
		// state machine allows interleaved events), but we DO require that
		// a reply references a known transaction.
		if tx.ID == "" {
			// Reply without id: invalid (replies must echo a request id).
			return fmt.Errorf("%s: reply transaction missing id (must echo request id, %s)", prefix, "transaction")
		}
		// transid 0 is reserved for the error reply to a missing-id request
		// (RFC 3525 §8.1.1; testcase #28) — it passes pairing unconditionally.
		if id != 0 {
			if _, ok := (*seenTransIDs)[id]; !ok {
				return fmt.Errorf("%s: transaction reply id %d does not match any issued request (%s)", prefix, id, "transaction")
			}
		}
		// ImmAckRequired without prior PN (neg 65) — only flagged when
		// there was no Pending for this id in our local state map.
		if tx.ImmAckRequired {
			if !(*eventsPending)[id] {
				return fmt.Errorf("%s: transaction reply %d carries ImmAckRequired but no prior Pending was emitted (%s)", prefix, id, "transaction")
			}
			delete(*eventsPending, id)
		}
		// Move id from seen to confirmed.
		(*confirmedTransactions)[id] = true
	case "pending":
		if tx.ID == "" {
			return fmt.Errorf("%s: pending transaction missing id (%s)", prefix, "transaction")
		}
		id, err := resolveTxID(tx.ID, prefix, false, seenTransIDs, confirmedTransactions, requestOrder)
		if err != nil {
			return err
		}
		if _, ok := (*seenTransIDs)[id]; !ok {
			return fmt.Errorf("%s: pending id %d does not match any issued request (%s)", prefix, id, "transaction")
		}
		(*eventsPending)[id] = true
	case "response_ack":
		// ack must be a single id or a range "a-b"; both endpoints must be
		// in confirmedTransactions.
		if tx.Ack == "" {
			return fmt.Errorf("%s: response_ack missing ack coverage (%s)", prefix, "transaction")
		}
		if err := checkAckCoverage(tx.Ack, confirmedTransactions, prefix); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: type %q invalid (request|reply|pending|response_ack)", prefix, tx.Type)
	}

	// Validate per-action content.
	if tx.Type != "pending" && tx.Type != "response_ack" {
		for ai, act := range tx.Actions {
			ap := fmt.Sprintf("%s.actions[%d]", prefix, ai)
			if err := validateAction(ap, act, tx.Type, role, tx, createdContexts, choseRequested, observedReqIDs); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveTxID(id string, prefix string, isRequest bool, seenTransIDs *map[uint32]bool, confirmedTransactions *map[uint32]bool, requestOrder *[]uint32) (uint32, error) {
	if id == "" {
		return 0, nil
	}
	// same_as_request:<i> is a generator-side alias resolved to the i-th
	// request's id (in insertion order, from requestOrder).
	if strings.HasPrefix(id, "same_as_request:") {
		idxStr := strings.TrimPrefix(id, "same_as_request:")
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return 0, fmt.Errorf("%s: same_as_request: invalid index %q", prefix, idxStr)
		}
		if requestOrder == nil || idx < 0 || idx >= len(*requestOrder) {
			return 0, fmt.Errorf("%s: same_as_request:%d out of range (have %d requests)", prefix, idx, len(*requestOrder))
		}
		return (*requestOrder)[idx], nil
	}
	v, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: id %q does not parse as UINT32: %v", prefix, id, err)
	}
	return uint32(v), nil
}

func checkAckCoverage(ack string, confirmed *map[uint32]bool, prefix string) error {
	if strings.Contains(ack, "-") {
		parts := strings.SplitN(ack, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%s: ack range %q malformed (%s)", prefix, ack, "transaction")
		}
		a, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return fmt.Errorf("%s: ack range start %q invalid: %v (%s)", prefix, parts[0], err, "transaction")
		}
		b, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("%s: ack range end %q invalid: %v (%s)", prefix, parts[1], err, "transaction")
		}
		if a > b {
			return fmt.Errorf("%s: ack range %q start > end", prefix, ack)
		}
		for i := a; i <= b; i++ {
			if !(*confirmed)[uint32(i)] {
				return fmt.Errorf("%s: ack range %d-%d covers unconfirmed transaction %d (%s)", prefix, a, b, i, "transaction")
			}
		}
		return nil
	}
	v, err := strconv.ParseUint(ack, 10, 32)
	if err != nil {
		return fmt.Errorf("%s: ack %q invalid: %v (%s)", prefix, ack, err, "transaction")
	}
	if !(*confirmed)[uint32(v)] {
		return fmt.Errorf("%s: ack %d covers unconfirmed transaction (%s)", prefix, v, "transaction")
	}
	return nil
}

func validateAction(
	prefix string,
	act core.MegacoAction,
	txType, role string,
	tx core.MegacoTransaction,
	createdContexts *map[uint64]bool,
	choseRequested *bool,
	observedReqIDs *map[string]uint32,
) error {
	// Context validation: $-/* in reply → reject (neg 58). Numeric Context
	// in reply must already be created (neg 59). Reserved values rejected
	// (neg 71). CHOOSE-fill carve-out: a prior request action with "$" is
	// answered by a reply carrying the MG-allocated numeric ContextID
	// (RFC 3525 §3.3 CHOOSE semantics; testcase #4/#9) — any non-reserved
	// numeric is accepted once "$" was requested.
	ctx := act.Context
	switch ctx {
	case "-", "$", "*":
		if txType == "reply" && (ctx == "$" || ctx == "*") {
			return fmt.Errorf("%s: context %q not allowed in reply (CHOOSE/ALL only request-side, %s)", prefix, ctx, "command")
		}
		if (txType == "" || txType == "request") && ctx == "$" {
			*choseRequested = true
		}
	case "":
		// empty is treated as "-" (NULL) per the on-wire serialization
		// (§3.3 — NULL context allowed for ROOT-class operations).
	default:
		v, err := strconv.ParseUint(ctx, 10, 32)
		if err != nil {
			return fmt.Errorf("%s: context %q does not parse as UINT32: %v (%s)", prefix, ctx, err, "length")
		}
		if contextIDReserved[v] {
			return fmt.Errorf("%s: context %d is a reserved value (0/0xFFFFFFFE/0xFFFFFFFF) — not a concrete Context (%s)", prefix, v, "length")
		}
		if txType == "reply" {
			// An Add command in the reply echoes back the MG's allocated
			// ContextID — the MG created it, the MGC echoes it back. Accept
			// it even if not yet marked as created. This covers both the
			// CHOOSE-fill case (reply carries the MG-allocated id) and
			// direct Add-echo (the MGC accepts a requested numeric id from
			// the MG). Only Add creates contexts; Modify/Subtract/Move on a
			// non-created ctx are real errors.
			ctxCreatedByReply := false
			for _, replyAct := range tx.Actions {
				if replyAct.Context == ctx && len(replyAct.Commands) > 0 {
					for _, cmd := range replyAct.Commands {
						if cmd.Name == "Add" {
							ctxCreatedByReply = true
							break
						}
					}
				}
				if ctxCreatedByReply {
					break
				}
			}
			if !(*createdContexts)[v] && !*choseRequested && !ctxCreatedByReply {
				return fmt.Errorf("%s: reply references context %d which has not been created (%s)", prefix, v, "command")
			}
			// The reply's numeric Context is now established for later
			// transactions.
			(*createdContexts)[v] = true
			*choseRequested = false
		} else if txType == "" || txType == "request" {
			// numeric context in request: remember as created.
			(*createdContexts)[v] = true
		}
	}

	// Per-command state tracking: Add creates a context, Move/Subtract are
	// address-existing-context operations. RFC 3525 §6.2.1: a context is
	// "created" when an Add command with a numeric ContextID is accepted by
	// the MGC (the reply echoes the same ContextID back, or a CHOOSE-fill
	// reply picks one). For the test-side happy path (validator mirror) the
	// simplest sound model is: any Add request on a numeric ContextID marks
	// that ContextID as established for subsequent transactions.
	for ci, cmd := range act.Commands {
		cp := fmt.Sprintf("%s.commands[%d]", prefix, ci)
		if !commandNames[cmd.Name] {
			return fmt.Errorf("%s: command name %q invalid (Add|Modify|Subtract|Move|AuditValue|AuditCapability|Notify|ServiceChange)", cp, cmd.Name)
		}
		if cmd.Termination == "" {
			return fmt.Errorf("%s: termination required (ROOT|pathNAME|$|*)", cp)
		}
		// TerminationID ≤64 chars; >64 → reject (neg 68).
		if len(cmd.Termination) > 64 {
			return fmt.Errorf("%s: termination %q length %d exceeds 64-char pathNAME bound (%s)", cp, cmd.Termination, len(cmd.Termination), "length")
		}
		// Modify/Subtract on non-existent termination (neg 57) is injected
		// via the wire_fault channel ("command_modify_nonexistent").
		// RFC 3525 §6.2.1: physical terminations exist for the entire life
		// of the MG — Modify-first on a pathNAME is the canonical
		// idle-programming flow (design §4 scenario 2), so the plain-config
		// path must not reject it; only ephemeral ($-chosen) terminations
		// have Add-creation semantics, and those are unnameable in a
		// scripted replay config.
		// Descriptor parameter checks.
		if cmd.Descriptor != nil {
			if err := validateDescriptor(cp, cmd, txType, observedReqIDs); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDescriptor(prefix string, cmd core.MegacoCommand, txType string, observedReqIDs *map[string]uint32) error {
	d := cmd.Descriptor
	if d == nil {
		return nil
	}
	// ServiceChange: Services block must have Method + Reason (neg 55).
	// Replies (s2c) commonly carry only Profile/Version to acknowledge — see
	// RFC 3525 §6.2: "The Services descriptor in a reply may contain only
	// the profile and version of the MG" — so we only require Method+Reason
	// in requests.
	if cmd.Name == "ServiceChange" && d.Services != nil {
		s := d.Services
		// Only enforce method+reason for requests (c2s side). Replies may
		// carry just the MGC profile/handshake to acknowledge the request.
		if s.Method == "" && txType != "reply" {
			return fmt.Errorf("%s: services.method required (Restart|Graceful|...) (%s)", prefix, "message")
		}
		if s.Reason == "" && txType != "reply" {
			return fmt.Errorf("%s: services.reason required (quoted reason string, %s)", prefix, "message")
		}
		// Mutual exclusion: ServiceChangeAddress and MgcIdToTry (neg 77).
		if s.ServiceChangeAddress != "" && s.MgcIDToTry != "" {
			return fmt.Errorf("%s: services.service_change_address and services.mgc_id_to_try are mutually exclusive (ABNF at most one of either, %s)", prefix, "services")
		}
	}
	// D-MEGACO-1 修：DigitMap 定时器域校验独立于 ServiceChange/Services——
	// 旧版嵌在 `ServiceChange && d.Services != nil` 块内，Modify{DigitMap
	// T:200} 这类非 SC 载体漏检。T>99 或 S/L=0 越界（T=0 合法，D-4 口径）。
	if d.DigitMap != nil {
		if d.DigitMap.T != nil && *d.DigitMap.T > 99 {
			return fmt.Errorf("%s: digit_map.t=%d exceeds 99 (%s)", prefix, *d.DigitMap.T, "length")
		}
		if d.DigitMap.S != nil && *d.DigitMap.S == 0 {
			return fmt.Errorf("%s: digit_map.s=0 is a boundary violation (%s)", prefix, "length")
		}
		if d.DigitMap.L != nil && *d.DigitMap.L == 0 {
			return fmt.Errorf("%s: digit_map.l=0 is a boundary violation (%d)", prefix, *d.DigitMap.L)
		}
	}
	// Notify 的 ObservedEvents RequestID 必须与该终结点生效 Events 的
	// RequestID 一致（neg66 自然面守卫；contract §7.1.9/§7.1.17）。
	if cmd.Name == "Notify" && d.ObservedEvents != nil && cmd.Termination != "" {
		if eff, ok := (*observedReqIDs)[cmd.Termination]; ok && eff != d.ObservedEvents.RequestID {
			return fmt.Errorf("%s: Notify ObservedEvents request_id %d does not match active Events request_id %d on %q (%s)",
				prefix, d.ObservedEvents.RequestID, eff, cmd.Termination, "transaction")
		}
	}
	// Events 描述符记录该终结点的生效 RequestID（供后续 Notify 关联校验）。
	if d.Events != nil && d.Events.RequestID != 0 && cmd.Termination != "" {
		(*observedReqIDs)[cmd.Termination] = d.Events.RequestID
	}
	return nil
}

// validateMidForm checks one explicitly-configured mId against the four
// RFC 3525 Annex B forms (D-MEGACO-1 修2): domainAddress ([v4]/[v6][:port]),
// domainName (<name>), mtpAddress (MTP{hex}), deviceName (pathNAME). Empty
// is legal (generator derives it from the role's address).
func validateMidForm(where, mid string) error {
	if mid == "" {
		return nil
	}
	switch {
	// domainAddress: [v4]/[v6] 或带端口 [v4]:port / [v6]:port——括号内必须
	// 是可解析 IP 字面量（修轮 F11："[bad mid with spaces]" 旧版放行并原样
	// 落线破坏起始行 SEP 结构）。
	case strings.HasPrefix(mid, "[") && (strings.HasSuffix(mid, "]") || strings.Contains(mid, "]:")):
		inner := strings.TrimPrefix(mid, "[")
		if idx := strings.LastIndex(inner, "]:"); idx >= 0 {
			port := inner[idx+2:]
			inner = inner[:idx]
			if perr := port; perr == "" {
				return fmt.Errorf("%s %q domainAddress port is empty (mid)", where, mid)
			} else if _, perr2 := strconv.Atoi(port); perr2 != nil {
				return fmt.Errorf("%s %q domainAddress port %q is not numeric (mid)", where, mid, port)
			}
		}
		inner = strings.TrimSuffix(inner, "]")
		if net.ParseIP(inner) == nil {
			return fmt.Errorf("%s %q domainAddress %q is not an IP literal (mid)", where, mid, inner)
		}
		return nil
	// domainName: <name>（尖括号）。
	case strings.HasPrefix(mid, "<") && strings.HasSuffix(mid, ">"):
		return nil
	// mtpAddress: MTP{hex}（花括号包十六进制 token，D-3 口径）。
	case strings.HasPrefix(mid, "MTP{") && strings.HasSuffix(mid, "}"):
		return nil
	// deviceName/pathNAME: 裸 token，不含保留定界符。
	case !strings.ContainsAny(mid, "[]{}<>,;=\" "):
		return nil
	}
	return fmt.Errorf("%s %q is not one of the four mId forms ([addr][:port]|<domain>|MTP{hex}|deviceName) (mid)", where, mid)
}

// sessionRenderSizes renders each of the session's messages exactly the way
// the generator will (same transactionId resolution, same mId derivation) and
// returns their byte lengths. D-MEGACO-1 修轮 F5/F1：长度类上界（UDP MTU、
// TPKT 16-bit 域）必须在 Validate 同步面执法——生成期错误会被 Plan goroutine
// 吞成空流（既有的"驱动失败 → 空流"契约），负例锚词就到不了 task error。
func sessionRenderSizes(cfg *core.MegacoConfig, sess core.MegacoSession, srcIP, dstIP string) ([]int, error) {
	ctrlSeq := uint32(0)
	var requestIDs []uint32
	sizes := make([]int, 0, len(sess.Events))
	form := cfg.TokenForm
	if form == "" {
		form = "long"
	}
	for _, ev := range sess.Events {
		txs := make([]core.MegacoTransaction, len(ev.Transactions))
		for i, tx := range ev.Transactions {
			switch tx.Type {
			case "request":
				if tx.ID == "" || tx.ID == "auto" {
					ctrlSeq++
					tx.ID = strconv.FormatUint(uint64(ctrlSeq), 10)
				}
				if v, err := strconv.ParseUint(tx.ID, 10, 32); err == nil {
					requestIDs = append(requestIDs, uint32(v))
				}
			case "reply", "pending":
				if strings.HasPrefix(tx.ID, "same_as_request:") {
					idxStr := strings.TrimPrefix(tx.ID, "same_as_request:")
					idx, aerr := strconv.Atoi(idxStr)
					if aerr != nil || idx < 0 || idx >= len(requestIDs) {
						return nil, fmt.Errorf("same_as_request:%d unresolvable", idx)
					}
					tx.ID = strconv.FormatUint(uint64(requestIDs[idx]), 10)
				}
			}
			txs[i] = tx
		}
		mid := pickMid(sess, ev.Direction, srcIP, dstIP)
		body := BuildMessageText(cfg, versionFor(cfg), mid, txs, form)
		sizes = append(sizes, len(body))
	}
	return sizes, nil
}
