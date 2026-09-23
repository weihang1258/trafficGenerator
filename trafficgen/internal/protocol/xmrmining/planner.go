// Package xmrmining planner：负例校验（39 wire_fault 一行一注入——契约 §7
// 表逐行，与契约 §6 枚举/用例 §5 表三方同序）+ 矿机侧会话状态机（契约 §5
// 五态）+ 关联校验（id/session/job 三族）。每个被拒 spec 必须传播为 task
// error——绝不产出 completed/0-packet 或只剩 TCP 外壳的假成功。
//
// 自然面守卫（处置表 26 值）在 validateSession 状态机与值域走查中真拒绝；
// 仅注入/结构不可达 13 值经 validateWireFault 分发拒（D-XMR-1：26+13=39
// 可复算）。勘误注记：B6 参考 c477ecc 的 login-reject 后续事件检查是死代码
// （算 closed 从不返回错误）——本实现据实拒绝（state_after_login_reject/
// state_after_close 自然面）。
package xmrmining

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wireFaultAnchors maps each of the 39 sanctioned single-injection faults to
// its 主锚词 (契约 §7 rows 26–64, testcase §5 same order — error_contains
// asserts this literal).
var wireFaultAnchors = map[string]string{
	"json_truncated":            "json",
	"json_unclosed":             "json",
	"json_notobject":            "json",
	"framing_no_lf":             "newline",
	"framing_crlf":              "crlf",
	"framing_length_prefix":     "framing",
	"method_unknown":            "method",
	"method_direction":          "direction",
	"method_btc_array":          "params",
	"params_login_missing":      "login",
	"params_login_type":         "params",
	"params_submit_missing":     "submit",
	"params_submit_type":        "params",
	"params_getjob_missing":     "getjob",
	"params_keepalived_missing": "keepalived",
	"hex_blob_odd":              "blob",
	"hex_blob_nonhex":           "blob",
	"hex_blob_short":            "blob",
	"hex_blob_overflow":         "blob",
	"hex_seed_hash":             "seed_hash",
	"hex_target":                "target",
	"hex_nonce":                 "nonce",
	"hex_result":                "result",
	"hex_prefix":                "hex",
	"state_first_login":         "login",
	"state_submit_before_login": "submit",
	"state_after_login_reject":  "login",
	"state_after_close":         "state",
	"id_resp_mismatch":          "id",
	"result_id_missing":         "result",
	"id_notify_fake":            "id",
	"id_reuse":                  "id",
	"job_unknown":               "job",
	"job_session_mismatch":      "session",
	"carrier_missing_tcp":       "carrier",
	"carrier_udp":               "carrier",
	"carrier_port_conflict":     "port",
	"prop_swallowed":            "propagat",
	"prop_fake_success":         "task",
}

// Validate checks an xmrmining flow spec. cfg == nil（bare {"xmrmining":{}}
// 层或缺键）通过：生成器发缺省基线会话（login only）.
func Validate(spec core.FlowSpec) error {
	cfg := spec.XMR
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 会话间 dst_port 一致性（裁定2：会话级覆盖必须彼此一致——port_conflict
	// 自然面，edp 修轮 F10 同款守卫）.
	dst := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if dst != 0 && dst != p {
				return fmt.Errorf("xmrmining: sessions[%d] dst_port %d conflicts with earlier session dst_port %d (port)", i, p, dst)
			}
			dst = p
		}
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si); err != nil {
			return err
		}
	}
	return nil
}

// validateSession walks one session's events enforcing the miner-side state
// machine (契约 §5) and per-message value domains (§3.9). State tracked:
// logged-in / login-rejected(=closed) / seen jobs / open request ids.
func validateSession(sess core.XMRSession, si int) error {
	prefix := fmt.Sprintf("xmrmining: sessions[%d]", si)
	loggedIn := false
	closed := false
	firstApp := true
	seenJobs := map[string]bool{}
	openIDs := map[string]bool{}
	var ids idWalker // 与生成器同源（单解析权威，终审 H1 勘误）
	sessionRef := "" // 本会话 id（login 声明值或 fixture 缺省）
	for ei, ev := range sess.Events {
		ep := fmt.Sprintf("%s.events[%d]", prefix, ei)
		if ev.Kind == "" {
			return fmt.Errorf("%s: missing kind (method)", ep)
		}
		if closed {
			// login 拒绝后 Closed 终态：不得再排任何业务事件（xmrig-impl
			// close() 语义；state_after_login_reject / state_after_close
			// 自然面——错误词同时含两负例锚）.
			return fmt.Errorf("%s: session closed after rejected login — no further events allowed (state machine: login)", ep)
		}
		if firstApp {
			if ev.Kind != "login" {
				return fmt.Errorf("%s: first application message must be login (state machine: login)", ep)
			}
			firstApp = false
		}
		switch ev.Kind {
		case "login":
			if loggedIn {
				return fmt.Errorf("%s: login already completed in this session (state machine: login)", ep)
			}
			// params_login_missing 负例由 wire_fault 通道承载（逐故障单一
			// 注入）——空 Login 走生成器 fixture 默认，不构成独立校验失败。
			if ev.Status == "error" {
				closed = true // login 拒绝（正例 2 形态）→ Closed
			} else {
				loggedIn = true
				// 登录响应自动携带初始 job——validator 与生成器同源登记
				// effective job_id（红例④实证：不登记则 submit 引用 login
				// 初始 job 被 job_unknown 误拒——generator/validator 语义
				// 分叉，红例先红后绿）。
				seenJobs[mergedJob(ev).JobID] = true
				sessionRef = sessionID(ev)
			}
		case "job":
			// 矿池→矿机通知（事件编排里 job 事件本身即矿池侧行，合法；
			// 方向违例由 wire_fault method_direction 注入通道承载）。校验
			// effective job（嵌套+flat 合并后形态——与生成器同源，单解析
			// 权威）并登记其 job_id。
			eff := mergedJob(ev)
			if err := checkJobFields(ep, &eff); err != nil {
				return err
			}
			seenJobs[eff.JobID] = true
		case "submit":
			if !loggedIn {
				return fmt.Errorf("%s: submit before successful login (state machine: submit)", ep)
			}
			// 事件未声明 nonce/result 时走生成器同源 fixture 默认——
			// params_submit_missing 负例由 wire_fault 通道逐故障注入.
			nonce := ev.Nonce
			if nonce == "" {
				nonce = FixtureNonce
			}
			if err := checkHexField(ep, "nonce", nonce, 8); err != nil {
				return err
			}
			result := ev.Result
			if result == "" {
				result = FixtureResult
			}
			if err := checkHexField(ep, "result", result, 64); err != nil {
				return err
			}
			// submit job_id 关联（job_unknown）：事件未声明 job 时生成器
			// 默认 FixtureJobID2——validator 同步默认再查已收 job 集合.
			jid := ev.JobID
			if jid == "" && ev.Job != nil {
				jid = ev.Job.JobID
			}
			if jid == "" {
				jid = FixtureJobID2
			}
			if !seenJobs[jid] {
				return fmt.Errorf("%s: submit job_id %q not from this session's jobs (job)", ep, jid)
			}
			// session id 关联（job_session_mismatch）：effective 值（声明
			// 优先、未声明继承会话引用）必须等于本会话 id——生成器同源.
			if sid := effectiveSessionID(ev, sessionRef); sid != sessionRef {
				return fmt.Errorf("%s: submit params.id %q does not match this session's id %q (session)", ep, sid, sessionRef)
			}
		case "keepalived":
			if !loggedIn {
				return fmt.Errorf("%s: keepalived before successful login (state machine: keepalived)", ep)
			}
			// 会话 id 等值守卫（终审 H2：契约 §7 负例 59 明文含 keepalived
			//——effective 值必须等于本会话 id，红例⑲ 先红后绿）.
			if sid := effectiveSessionID(ev, sessionRef); sid != sessionRef {
				return fmt.Errorf("%s: keepalived params.id %q does not match this session's id %q (session)", ep, sid, sessionRef)
			}
		case "getjob":
			if !loggedIn {
				return fmt.Errorf("%s: getjob before successful login (state machine: getjob)", ep)
			}
			// getjob 响应自动携带 job 对象——与生成器同源登记（终审 M1
			// 勘误：不登记则合法 getjob→submit 新 job_id 被 job_unknown
			// 误拒——红例⑳ 先红后绿）.
			seenJobs[mergedJob(ev).JobID] = true
			if sid := effectiveSessionID(ev, sessionRef); sid != sessionRef {
				return fmt.Errorf("%s: getjob params.id %q does not match this session's id %q (session)", ep, sid, sessionRef)
			}
		default:
			return fmt.Errorf("%s: unknown event kind %q (method_unknown)", ep, ev.Kind)
		}
		// id uniqueness within session（契约 §3.1：请求 id 会话内唯一——
		// 对 EFFECTIVE 值查重：声明值采纳、缺省值迭代，与生成器同源同序；
		// job 通知无 id 不参与。终审 H1：仅查声明值会漏缺省复用）.
		if ev.Kind != "job" {
			effID := string(ids.resolve(ev))
			if openIDs[effID] {
				return fmt.Errorf("%s: request id %s reused within session (id_reuse)", ep, effID)
			}
			openIDs[effID] = true
		}
	}
	return nil
}

// effectiveSessionID mirrors the generator's eventSessionID（声明优先、未
// 声明继承会话引用；引用未立时 fixture 兜底——与生成器同源）.
func effectiveSessionID(ev core.XMREvent, sessionRef string) string {
	if ev.SessionID != "" {
		return ev.SessionID
	}
	if sessionRef != "" {
		return sessionRef
	}
	return FixtureSession
}

// checkJobFields validates the job object hex domains（契约 §3.9）.
func checkJobFields(prefix string, job *core.XMRJob) error {
	if err := checkBlobField(prefix, job.Blob); err != nil {
		return err
	}
	if job.Target != "" {
		if err := checkHexField(prefix, "target", job.Target, 0); err != nil {
			return err
		}
		if len(job.Target) != 8 && len(job.Target) != 16 {
			return fmt.Errorf("%s: target length must be 4 or 8 bytes (8 or 16 hex), got %d (target)", prefix, len(job.Target))
		}
	}
	if err := checkHexField(prefix, "seed_hash", job.SeedHash, 64); err != nil {
		return err
	}
	return nil
}

// checkBlobField validates blob: even-length lowercase hex (no 0x prefix)
// whose decoded byte size ∈ [43, 407] (xmrig-impl setBlob: <43 or ≥408
// reject; nonce 字段 offset 39 4B).
func checkBlobField(prefix, val string) error {
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "0x") || strings.HasPrefix(val, "0X") {
		return fmt.Errorf("%s: blob must not carry the 0x prefix (hex)", prefix)
	}
	if len(val)%2 != 0 {
		return fmt.Errorf("%s: blob length %d is odd (blob)", prefix, len(val))
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: blob contains non-hex character %q (blob)", prefix, c)
		}
	}
	size := len(val) / 2
	if size < 43 {
		return fmt.Errorf("%s: blob decodes to %d bytes, below the 43-byte lower bound (blob)", prefix, size)
	}
	if size >= 408 {
		return fmt.Errorf("%s: blob decodes to %d bytes, at/above the 408-byte upper bound (blob)", prefix, size)
	}
	return nil
}

// checkHexField enforces the hex field rules (契约 §3.1): ASCII lowercase
// hex, even length, no 0x prefix; width>0 additionally pins the length.
func checkHexField(prefix, name, val string, width int) error {
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "0x") || strings.HasPrefix(val, "0X") {
		return fmt.Errorf("%s: %s must not carry the 0x prefix (hex)", prefix, name)
	}
	if len(val)%2 != 0 {
		return fmt.Errorf("%s: %s length %d is odd (hex)", prefix, name, len(val))
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: %s contains non-hex character %q (hex)", prefix, name, c)
		}
	}
	if width > 0 && len(val) != width {
		return fmt.Errorf("%s: %s length must be exactly %d hex characters (hex)", prefix, name, width)
	}
	return nil
}

// validateWireFault dispatches the 39 sanctioned single-injection faults
// (契约 §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(kind string) error {
	anchor, ok := wireFaultAnchors[kind]
	if !ok {
		return fmt.Errorf("xmrmining: unknown wire_fault kind %q", kind)
	}
	return fmt.Errorf("xmrmining: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
