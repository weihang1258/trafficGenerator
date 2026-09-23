package core

import (
	"bytes"
	"encoding/json"
)

// XMRMining（Monero stratum，D-XMR-1 #40，契约 74-xmrmining v2.0.2）配置类型。
// 字段名对齐契约 §6 typedef：sessions[] 事件编排会话（每事件 = 一笔 stratum
// 行式事务一侧，自动应答按事件配置展开——契约 §5 派生规则①-⑤），多会话按序
// 整块回放、concurrent=true 时交错（v2.0.1 C-07 翻案，cwmp⑦ 判例链）。
// 链形 [ip→tcp→xmrmining]：行式 JSON + 单 LF（0x0a）终结层，无长度前缀无记录
// 头，消息边界只由 LF 决定；TCP 拥有分段/握手/挥手；无协议 dissector，断言
// 全走 tcp.payload/frames。
//
// 紧凑形态成员顺序钉死（裁定5，Go struct 序=线序）：请求 id,jsonrpc,method,
// params；响应 id,jsonrpc,error,result；通知 jsonrpc,method,params——通知
// 省略顶层 id 成员（裁定3，≠"id":null）。jsonrpc 恒 "2.0"。

// XMRConfig is the flow's xmrmining terminal-layer configuration.
type XMRConfig struct {
	// Profile is informational（xmrmining_stratum_v1 主档 / xmrmining_job_
	// legacy_v1 仅影响 job 事件形态，不校验拒绝）；wire 形态由事件配置决定。
	Profile string `json:"profile,omitempty"`
	// Concurrent enables interleaved multi-session replay（契约 §5 C-07）：
	// 会话事件按 event index round-robin 交错；tcp 层须同时 concurrent:true
	// 以保独立连接 per SrcPort。
	Concurrent bool         `json:"concurrent,omitempty"`
	Sessions   []XMRSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（39 值枚举，契约 §7 表逐行，
	// 与契约 §6 枚举/用例 §5 表三方同序）：json_truncated|json_unclosed|
	// json_notobject|framing_no_lf|framing_crlf|framing_length_prefix|
	// method_unknown|method_direction|method_btc_array|
	// params_login_missing|params_login_type|params_submit_missing|
	// params_submit_type|params_getjob_missing|params_keepalived_missing|
	// hex_blob_odd|hex_blob_nonhex|hex_blob_short|hex_blob_overflow|
	// hex_seed_hash|hex_target|hex_nonce|hex_result|hex_prefix|
	// state_first_login|state_submit_before_login|state_after_login_reject|
	// state_after_close|id_resp_mismatch|result_id_missing|id_notify_fake|
	// id_reuse|job_unknown|job_session_mismatch|carrier_missing_tcp|
	// carrier_udp|carrier_port_conflict|prop_swallowed|prop_fake_success.
	WireFault string `json:"wire_fault,omitempty"`
}

// XMRSession is one miner connection（一条 TCP 会话）：端点覆盖 + 有序事件列。
// 会话身份 = SrcPort 覆盖（0 = 流缺省源端口）；多会话按序整块回放（第二会话
// 起点 = 前会话总包 + 1），concurrent 时按 event index 交错。
type XMRSession struct {
	// SrcPort overrides the miner-side source port for this session
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = 继承链级缺省
	// 18081 via FieldContract；validator 守会话间一致性).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Concurrent interleaves this session with others（会话级声明与 config
	// 级同语义）.
	Concurrent bool `json:"concurrent,omitempty"`
	// Events is the session's ordered event list；首事件必为 login（状态机
	// §5），login 拒绝后不得再排业务事件（Closed 终态），请求 id 会话内唯一。
	Events []XMREvent `json:"events,omitempty"`
}

// XMRJob is the job object shared by login 响应 / job 通知 / getjob 响应
// （现代形态成员顺序 blob,algo,height,seed_hash,job_id,target,id——mo-pool
// buildStandardJobPayload；legacy 形态仅 blob,job_id,target——spec §job verbatim）。
type XMRJob struct {
	// Blob is the RandomX block template hex（偶数 hex、解码字节数 ∈
	// [43,407]；nonce 字段 offset 39 4B 小端——xmrig-impl Job.h）.
	Blob string `json:"blob,omitempty"`
	// Algo is the RandomX algorithm string ("rx/0"; modern form only).
	Algo string `json:"algo,omitempty"`
	// Height is the block height (JSON number; modern form only).
	Height int `json:"height,omitempty"`
	// SeedHash is the RandomX DAG seed（恰 64 hex / 32B——xmrig-impl
	// setSeedHash 校验; modern form only).
	SeedHash string `json:"seed_hash,omitempty"`
	// JobID is the submit correlation key（opaque 任意长度，spec 示例 28 字符
	// 含 +/；不套 hex 校验）.
	JobID string `json:"job_id,omitempty"`
	// Target is the compact difficulty hex（4B=8 hex 或 8B=16 hex——xmrig-impl
	// setTarget 两态）.
	Target string `json:"target,omitempty"`
	// ID is the optional session id echo (modern form only).
	ID string `json:"id,omitempty"`
}

// XMREvent is one event of the XMR stratum script：矿机请求（login/submit/
// keepalived/getjob）或矿池侧 job 通知，自动应答形态在事件内配置（契约 §5
// 自动派生规则①-④）。
type XMREvent struct {
	// Kind: login|job|submit|keepalived|getjob.
	Kind string `json:"kind,omitempty"`
	// PackNext merges this event's last line with the NEXT event's first
	// line into one TCP segment（多行粘连单段正例 18：job 通知 + submit
	// 请求 = 653B 单段；跨方向粘连是引擎回放构造物，契约 §8）.
	PackNext bool `json:"pack_next,omitempty"`
	// ID is the JSON number request id（login 恒 1、后续递增、会话内唯一），
	// verbatim 作为 JSON number 字面量；响应同值回带。
	ID json.RawMessage `json:"id,omitempty"`

	// --- login ---
	// Login is the wallet address（fixture 95 字符）or wallet.worker.
	Login string `json:"login,omitempty"`
	// Pass is the password（fixture "x"）.
	Pass string `json:"pass,omitempty"`
	// Agent is the miner UA（fixture 51 字符）.
	Agent string `json:"agent,omitempty"`
	// Rigid is the optional rig identifier（fixture "rig-01"）.
	Rigid string `json:"rigid,omitempty"`
	// SessionID is the session id（fixture 36 字符 UUID 形态）——login 响应
	// result.id、后续 submit/getjob/keepalived 的 params.id 关联键。
	SessionID string `json:"session_id,omitempty"`
	// Job is the initial job carried in the login response result.job.
	Job *XMRJob `json:"job,omitempty"`
	// Status is the auto-response control: ""（OK）| "error"（错误对象按
	// ErrCode/ErrMsg 展开）——login 拒绝闭会话、submit 拒绝会话继续.
	Status string `json:"status,omitempty"`
	// Extensions is the optional login-response extensions array.
	Extensions []string `json:"extensions,omitempty"`
	// KeepaliveAlias renders the keepalived request with method name
	// "keepalive"（无 d；mo-pool 别名；正例 12）.
	KeepaliveAlias bool `json:"keepalive_alias,omitempty"`

	// --- job（notify，现代/legacy 两形态；契约 §6 flat keys）---
	// Legacy renders the job object in the spec-verbatim three-field form
	// (blob/job_id/target only; 正例 6).
	Legacy bool `json:"legacy,omitempty"`
	// Flat job fields for job events（契约 §6：{"kind":"job","job_id":…,
	// "blob":…}）；嵌套 Job 非空时优先。FAlgo 的 tag 是 "f_algo"（内部形）——
	// wire 键 "algo" 与 submit 可选成员共享，UnmarshalJSON 按 ev.Kind 路由。
	JobID     string `json:"job_id,omitempty"`
	FBlob     string `json:"blob,omitempty"`
	FTarget   string `json:"target,omitempty"`
	FAlgo     string `json:"f_algo,omitempty"`
	FHeight   int    `json:"height,omitempty"`
	FSeedHash string `json:"seed_hash,omitempty"`

	// --- submit ---
	// Nonce is the 4B (8 hex) submit nonce；Result is the 32B (64 hex) PoW
	// hash；Algo/Sig/Commitment 为可选成员（xmrig-impl 条件成员）.
	Nonce      string `json:"nonce,omitempty"`
	Result     string `json:"result,omitempty"`
	Algo       string `json:"algo,omitempty"`
	Sig        string `json:"sig,omitempty"`
	Commitment string `json:"commitment,omitempty"`

	// ErrCode / ErrMsg shape the auto error response object
	// ({"code":-1,"message":"..."}; login 拒绝闭会话、submit 拒绝继续).
	ErrCode int    `json:"err_code,omitempty"`
	ErrMsg  string `json:"err_msg,omitempty"`

	// WireFault injects a per-event wire fault（覆盖会话级；故障隔离用）.
	WireFault string `json:"wire_fault,omitempty"`
}

// UnmarshalJSON routes the shared "algo" key by event kind（契约 §6 typedef
// 在 job 事件与 submit 事件上用同名键：job flat 字段 → FAlgo、submit 可选
// 成员 → Algo。单键不能映射两个 struct 字段，普通解码落在 Algo，此钩子对
// job kind 搬运到 FAlgo）。
func (e *XMREvent) UnmarshalJSON(b []byte) error {
	type xmrEventAlias XMREvent
	var alias xmrEventAlias
	// 严格解码（DisallowUnknownFields）：自定义 UnmarshalJSON 会绕过外层
	// decoder 的严格设置（红例⑮ 实证——session 级拒而 event 级放行），
	// 事件级必须自带严格性（裁定8 三级未知键全拒）。
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	var probe struct {
		Algo *string         `json:"algo"`
		Kind json.RawMessage `json:"kind"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	*e = XMREvent(alias)
	if probe.Algo != nil && string(probe.Kind) == `"job"` {
		e.FAlgo, e.Algo = *probe.Algo, ""
	}
	return nil
}

// 39 wire_fault 值（契约 §7 表逐行同序）——仅注入/结构不可达 13 值在
// planner validateWireFault 分发拒；26 自然守卫在 validateSession 状态机
// 与值域走查拒（处置表 D-XMR-1：26+13=39 可复算）。
const (
	XMRWireFaultJSONTruncated        = "json_truncated"
	XMRWireFaultJSONUnclosed         = "json_unclosed"
	XMRWireFaultJSONNotobject        = "json_notobject"
	XMRWireFaultFramingNoLF          = "framing_no_lf"
	XMRWireFaultFramingCRLF          = "framing_crlf"
	XMRWireFaultFramingLengthPrefix  = "framing_length_prefix"
	XMRWireFaultMethodUnknown        = "method_unknown"
	XMRWireFaultMethodDirection      = "method_direction"
	XMRWireFaultMethodBTCArray       = "method_btc_array"
	XMRWireFaultParamsLoginMissing   = "params_login_missing"
	XMRWireFaultParamsLoginType      = "params_login_type"
	XMRWireFaultParamsSubmitMissing  = "params_submit_missing"
	XMRWireFaultParamsSubmitType     = "params_submit_type"
	XMRWireFaultParamsGetjobMissing  = "params_getjob_missing"
	XMRWireFaultParamsKeepalivedMiss = "params_keepalived_missing"
	XMRWireFaultHexBlobOdd           = "hex_blob_odd"
	XMRWireFaultHexBlobNonhex        = "hex_blob_nonhex"
	XMRWireFaultHexBlobShort         = "hex_blob_short"
	XMRWireFaultHexBlobOverflow      = "hex_blob_overflow"
	XMRWireFaultHexSeedHash          = "hex_seed_hash"
	XMRWireFaultHexTarget            = "hex_target"
	XMRWireFaultHexNonce             = "hex_nonce"
	XMRWireFaultHexResult            = "hex_result"
	XMRWireFaultHexPrefix            = "hex_prefix"
	XMRWireFaultStateFirstLogin      = "state_first_login"
	XMRWireFaultSubmitBeforeLogin    = "state_submit_before_login"
	XMRWireFaultAfterLoginReject     = "state_after_login_reject"
	XMRWireFaultStateAfterClose      = "state_after_close"
	XMRWireFaultIDRespMismatch       = "id_resp_mismatch"
	XMRWireFaultResultIDMissing      = "result_id_missing"
	XMRWireFaultIDNotifyFake         = "id_notify_fake"
	XMRWireFaultIDReuse              = "id_reuse"
	XMRWireFaultJobUnknown           = "job_unknown"
	XMRWireFaultJobSessionMismatch   = "job_session_mismatch"
	XMRWireFaultCarrierMissingTCP    = "carrier_missing_tcp"
	XMRWireFaultCarrierUDP           = "carrier_udp"
	XMRWireFaultCarrierPortConflict  = "carrier_port_conflict"
	XMRWireFaultPropSwallowed        = "prop_swallowed"
	XMRWireFaultPropFakeSuccess      = "prop_fake_success"
)
