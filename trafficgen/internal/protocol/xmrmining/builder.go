// Package xmrmining implements the Monero stratum terminal layer
// (xmrmining 终结层, [ip,]tcp,xmrmining 链): newline-delimited JSON over a
// plain TCP stream — one JSON object per line, single LF (0x0a) delimited,
// compact serialization with pinned member order (requests
// id,jsonrpc,method,params; responses id,jsonrpc,error,result; notifications
// jsonrpc,method,params — 通知省略顶层 id 成员). No dissector exists for this
// protocol, so all assertions run on tcp.payload / frames.
//
// Wire-format authority: docs/protocol-designs/74-xmrmining-design.md v2.0.2
// §3 — 5 methods (login/job/submit/keepalived[/keepalive alias]/getjob),
// compact form, jsonrpc constant "2.0", hex fields lowercase even-length no
// 0x prefix, modern job member order blob,algo,height,seed_hash,job_id,
// target,id (mo-pool buildStandardJobPayload), legacy job blob,job_id,target.
// Fixture constants pinned by testcase §3; 行长公式（§3.8）由链级单测自检.
package xmrmining

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Fixture constants (testcase §3 — 全量钉死).
const (
	FixtureWallet   = "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD" // 95 字符
	FixturePass     = "x"
	FixtureAgent    = "XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0" // 51 字符
	FixtureRigid    = "rig-01"
	FixtureSession  = "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"                                                                                                                     // 36 字符
	FixtureSession2 = "2cf1c8c7-c26b-58cf-b28e-57c3a02d08e1"                                                                                                                     // 会话 2
	FixtureBlob1    = "070780e6b9d60586ba419a0c224e3c6c3e134cc45c4fa04d8ee2d91c2595463c57eef0a4f0796c000000002fcc4d62fa6c77e76c30017c768be5c61d83ec9d3a085d524ba8053ecc3224660d" // 152 hex (76B)
	FixtureBlob2    = "0707d5efb9d6057e95a35f868231780b3a8649c4e57f3c77eaf437329243eef0b9f4b6987d05b900000000cae7754cb85a0ad8eebf3e0bf55f3ec5e754a1d6b05d46e5c358f907dbcbb72b01" // 152 hex (76B)
	FixtureJobID1   = "q7PLUPL25UV0z5Ij14IyMk8htXbj"                                                                                                                             // 28 字符
	FixtureJobID2   = "4BiGm3/RgGQzgkTI/xV0smdA+EGZ"                                                                                                                             // 28 字符
	FixtureJobID3   = "zZyYxXwWvV4eRtY6yTpQ2LmNoPqRsTuV"                                                                                                                         // 会话 2 job
	FixtureTarget   = "b88d0600"                                                                                                                                                 // 8 hex (4B)
	FixtureSeed     = "c9aa8bd62b73d8cb5f956956e3d5cbcf8dd13e17e1c2a1fcfa88c4d26b9815db"                                                                                         // 64 hex
	FixtureNonce    = "d0030040"                                                                                                                                                 // 8 hex
	FixtureResult   = "e1364b8782719d7683e2ccd3d8f724bc59dfa780a9e960e7c0e0046acdb40100"                                                                                         // 64 hex (32B)
	// 错误文案（契约 §3.3/§3.5 spec verbatim 钉死）.
	FixtureErrLogin  = "Invalid payment address provided"
	FixtureErrSubmit = "Low difficulty share"
	// blob 满值上界前缀（正例 20）：fixture 43B 前缀 + ab×364 = 407B（BlobMax）.
	BlobMaxPrefix = "070780e6b9d60586ba419a0c224e3c6c3e134cc45c4fa04d8ee2d91c2595463c57eef0a4f0796c00000000"
)

// LineLongJobIDPad appends the MSS pressure padding (testcase #19:
// job_id = "J"×1500 → job 通知行 1892B > MSS 1460 → 2 段).
func LineLongJobIDPad() string { return strings.Repeat("J", 1500) }

// BlobMax returns the 407B upper-bound blob (testcase #20: fixture 43B
// prefix + "ab"×364 = 814 hex = 407B total).
func BlobMax() string {
	return BlobMaxPrefix + strings.Repeat("ab", 364)
}

func intStr(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func quoteJSON(s string) string {
	if isASCIIPlain(s) {
		return `"` + s + `"`
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func isASCIIPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// hexArray renders ["a","b"] from an extensions slice.
func hexArray(items []string) string {
	if len(items) == 0 {
		return `[]`
	}
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = quoteJSON(s)
	}
	return `[` + strings.Join(parts, ",") + `]`
}

// renderJob renders the job object（现代形态 blob,algo,height,seed_hash,
// job_id,target,id；legacy 形态 blob,job_id,target——裁定5 成员序钉死）.
func renderJob(job *coreJob) string {
	if job.Legacy {
		return `{"blob":` + quoteJSON(job.Blob) +
			`,"job_id":` + quoteJSON(job.JobID) +
			`,"target":` + quoteJSON(job.Target) + `}`
	}
	s := `{"blob":` + quoteJSON(job.Blob)
	if job.Algo != "" {
		s += `,"algo":` + quoteJSON(job.Algo)
	}
	if job.Height > 0 {
		s += `,"height":` + intStr(job.Height)
	}
	if job.SeedHash != "" {
		s += `,"seed_hash":` + quoteJSON(job.SeedHash)
	}
	s += `,"job_id":` + quoteJSON(job.JobID) +
		`,"target":` + quoteJSON(job.Target)
	if job.ID != "" {
		s += `,"id":` + quoteJSON(job.ID)
	}
	return s + `}`
}

// coreJob is the builder-side job object (decoupled from core.XMRJob so the
// builder stays a pure string renderer; the generator converts).
type coreJob struct {
	Blob, Algo, SeedHash, JobID, Target, ID string
	Height                                  int
	Legacy                                  bool
}

func ln(s string) []byte { return []byte(s + "\n") }

// ---- line builders (compact JSON + LF; member order pinned 契约 §3.1) ----

// BuildLoginReq: {"id":<id>,"jsonrpc":"2.0","method":"login","params":{"login":"<w>","pass":"x","agent":"<ua>"[,"rigid":"<r>]"}}\n
func BuildLoginReq(id json.RawMessage, login, pass, agent, rigid string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	if pass == "" {
		pass = FixturePass
	}
	s := `{"id":` + string(id) + `,"jsonrpc":"2.0","method":"login","params":{"login":` +
		quoteJSON(login) + `,"pass":` + quoteJSON(pass) + `,"agent":` + quoteJSON(agent)
	if rigid != "" {
		s += `,"rigid":` + quoteJSON(rigid)
	}
	return ln(s + `}}`)
}

// BuildLoginRespOK: {"id":<id>,"jsonrpc":"2.0","error":null,"result":{"id":"<session>","job":{<job>},"status":"OK"[,"extensions":[…]]}}\n
func BuildLoginRespOK(id json.RawMessage, session string, job *coreJob, extensions []string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	s := `{"id":` + string(id) + `,"jsonrpc":"2.0","error":null,"result":{"id":` +
		quoteJSON(session) + `,"job":` + renderJob(job) + `,"status":"OK"`
	if len(extensions) > 0 {
		s += `,"extensions":` + hexArray(extensions)
	}
	return ln(s + `}}`)
}

// BuildErrorResp: {"id":<id>,"jsonrpc":"2.0","error":{"code":<code>,"message":"<msg>"}}\n
// (login 拒绝闭会话、submit 拒绝继续——闭会话判定在生成器/validator.)
func BuildErrorResp(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","error":{"code":` +
		intStr(code) + `,"message":` + quoteJSON(msg) + `}}`)
}

// BuildJobNotify: {"jsonrpc":"2.0","method":"job","params":{<job>}}\n — 通知
// 省略顶层 id 成员（裁定3：spec §job verbatim + mo-pool pushMessage；伪 id 进
// 负例仅注入）.
func BuildJobNotify(job *coreJob) []byte {
	return ln(`{"jsonrpc":"2.0","method":"job","params":` + renderJob(job) + `}`)
}

// BuildSubmitReq: {"id":<id>,"jsonrpc":"2.0","method":"submit","params":{"id":"<session>","job_id":"<jid>","nonce":"<n>","result":"<r>"[,"algo":"<a>"][,"sig":"<s>"][,"commitment":"<c>]"}}\n
func BuildSubmitReq(id json.RawMessage, session, jobID, nonce, result, algo, sig, commitment string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	s := `{"id":` + string(id) + `,"jsonrpc":"2.0","method":"submit","params":{"id":` +
		quoteJSON(session) + `,"job_id":` + quoteJSON(jobID) + `,"nonce":` +
		quoteJSON(nonce) + `,"result":` + quoteJSON(result)
	if algo != "" {
		s += `,"algo":` + quoteJSON(algo)
	}
	if sig != "" {
		s += `,"sig":` + quoteJSON(sig)
	}
	if commitment != "" {
		s += `,"commitment":` + quoteJSON(commitment)
	}
	return ln(s + `}}`)
}

// BuildSubmitRespOK: {"id":<id>,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}\n
func BuildSubmitRespOK(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}`)
}

// BuildKeepalivedReq: {"id":<id>,"jsonrpc":"2.0","method":"keepalived","params":{"id":"<session>"}}\n
// (keepalive_alias renders method "keepalive" — mo-pool 别名, 正例 12.)
func BuildKeepalivedReq(id json.RawMessage, session string, alias bool) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`3`)
	}
	method := "keepalived"
	if alias {
		method = "keepalive"
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","method":` + quoteJSON(method) +
		`,"params":{"id":` + quoteJSON(session) + `}}`)
}

// BuildKeepalivedResp: {"id":<id>,"jsonrpc":"2.0","error":null,"result":{"status":"KEEPALIVED"}}\n
func BuildKeepalivedResp(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`3`)
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","error":null,"result":{"status":"KEEPALIVED"}}`)
}

// BuildGetjobReq: {"id":<id>,"jsonrpc":"2.0","method":"getjob","params":{"id":"<session>"}}\n
func BuildGetjobReq(id json.RawMessage, session string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`4`)
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","method":"getjob","params":{"id":` +
		quoteJSON(session) + `}}`)
}

// BuildGetjobResp: {"id":<id>,"jsonrpc":"2.0","error":null,"result":{<job>}}\n
// — result 直接为 job 对象（契约 §3.7 mo-pool handleGetJobRequest 形态）.
func BuildGetjobResp(id json.RawMessage, job *coreJob) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`4`)
	}
	return ln(`{"id":` + string(id) + `,"jsonrpc":"2.0","error":null,"result":` + renderJob(job) + `}`)
}

// ---- generator（会话循环 + pack 粘连 + 并发交错）----

// XMRGenerator is the xmrmining terminal-layer generator.
type XMRGenerator struct{}

// Name returns "xmrmining".
func (g *XMRGenerator) Name() string { return "xmrmining" }

// GenEvents marks this generator as a terminal event producer.
func (g *XMRGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *XMRGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("xmrmining generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// idWalker resolves request ids（契约 §3.1：由矿机迭代、会话内唯一、login
// 恒 1——声明值采纳并推进计数，缺省值迭代递增。生成器渲染与 validator
// 唯一性预演共用单解析权威，终审 H1 勘误：原按 kind 硬编码缺省 2/3/4，
// 同会话双 submit 线上复用 id=2 违契约）.
type idWalker struct{ ctr int }

func (w *idWalker) resolve(ev core.XMREvent) json.RawMessage {
	if len(ev.ID) > 0 && string(ev.ID) != "null" {
		var n int
		if err := json.Unmarshal(ev.ID, &n); err == nil && n > w.ctr {
			w.ctr = n
		}
		return ev.ID
	}
	w.ctr++
	return json.RawMessage(strconv.Itoa(w.ctr))
}

// sessionRun is the per-session generation state（契约 §5 状态机）.
type sessionRun struct {
	sess     core.XMRSession
	loggedIn bool
	seenJobs map[string]bool
	// sessionRef is this session's id（login 声明值或 fixture 缺省）——后续
	// 事件未声明 session_id 时继承本值（终审 H2 勘误：原事件局部 fixture
	// 缺省可把错 id 发上线）.
	sessionRef string
	ids        idWalker
	pending    []byte
	// pendingUp marks the flushed run's direction（最近吸收行方向——跨方向
	// 粘连段的方向取末行，testcase #18 语义）.
	pendingUp bool
	// packWithNext carries the previous event's PackNext declaration across
	// buildOne calls（testcase #18：job(pack_next) 开的粘连段跨事件边界吸收
	// 下一事件首行）; packConsumed marks the absorption done.
	packWithNext bool
	hasPending   bool
}

// defaultFlow is the bare-config baseline: one login event on TCP（tcp 层走
// 链级缺省端口——不在此硬编码 18081，裁定2 端口继承链级）.
func defaultFlow() *core.XMRConfig {
	return &core.XMRConfig{
		Profile: "xmrmining_stratum_v1",
		Sessions: []core.XMRSession{{
			Events: []core.XMREvent{{
				Kind:      "login",
				ID:        json.RawMessage(`1`),
				Login:     FixtureWallet,
				Pass:      FixturePass,
				Agent:     FixtureAgent,
				SessionID: FixtureSession,
				Job: &core.XMRJob{
					Blob: FixtureBlob1, Algo: "rx/0", Height: 2652853,
					SeedHash: FixtureSeed, JobID: FixtureJobID1,
					Target: FixtureTarget, ID: FixtureSession,
				},
			}},
		}},
	}
}

// mergedJob resolves the EFFECTIVE job object for an event（嵌套 Job 优先、
// flat keys 覆盖、缺省 fixture 补齐）——生成器渲染与 validator 值域/关联
// 校验共用同一解析（单解析权威，hl7 修轮先例），防两处语义分叉。
func mergedJob(ev core.XMREvent) core.XMRJob {
	var j core.XMRJob
	if ev.Job != nil {
		j = *ev.Job
	}
	legacy := ev.Legacy
	// §6 flat keys override (job events declare {"kind":"job","job_id":…,
	// "blob":…}; nested Job wins only where flat unset).
	if ev.JobID != "" {
		j.JobID = ev.JobID
	}
	if ev.FBlob != "" {
		j.Blob = ev.FBlob
	}
	if ev.FTarget != "" {
		j.Target = ev.FTarget
	}
	if ev.FAlgo != "" {
		j.Algo = ev.FAlgo
	}
	if ev.FHeight > 0 {
		j.Height = ev.FHeight
	}
	if ev.FSeedHash != "" {
		j.SeedHash = ev.FSeedHash
	}
	if j.Blob == "" {
		j.Blob = FixtureBlob1
	}
	if j.Algo == "" && !legacy {
		j.Algo = "rx/0"
	}
	if j.Height == 0 && !legacy {
		j.Height = 2652853
	}
	if j.SeedHash == "" && !legacy {
		j.SeedHash = FixtureSeed
	}
	if j.JobID == "" {
		j.JobID = FixtureJobID1
	}
	if j.Target == "" {
		j.Target = FixtureTarget
	}
	if j.ID == "" && !legacy {
		j.ID = ev.SessionID
		if j.ID == "" {
			j.ID = FixtureSession
		}
	}
	return j
}

// eventJob converts the effective job to the builder-side render object.
func eventJob(ev core.XMREvent) *coreJob {
	j := mergedJob(ev)
	return &coreJob{Blob: j.Blob, Algo: j.Algo, Height: j.Height,
		SeedHash: j.SeedHash, JobID: j.JobID, Target: j.Target, ID: j.ID,
		Legacy: ev.Legacy}
}

// sessionID resolves the session id of a LOGIN event (event override →
// fixture)——login 响应的 result.id 即会话引用值.
func sessionID(ev core.XMREvent) string {
	if ev.SessionID != "" {
		return ev.SessionID
	}
	return FixtureSession
}

// eventSessionID resolves a request event's params.id：声明值优先，未声明
// 继承本会话引用（validator 同源同序）.
func (run *sessionRun) eventSessionID(ev core.XMREvent) string {
	if ev.SessionID != "" {
		return ev.SessionID
	}
	if run.sessionRef != "" {
		return run.sessionRef
	}
	return FixtureSession
}

// builtLine is one complete line with its direction.
type builtLine struct {
	up    bool
	bytes []byte
}

// renderEvent builds one event's line(s) in wire order（请求 up / job 通知恒
// down + 自动派生响应 opposite——契约 §5 派生规则①-④）.
func (run *sessionRun) renderEvent(ev core.XMREvent) ([]builtLine, error) {
	switch ev.Kind {
	case "login":
		id := run.ids.resolve(ev)
		login, pass, agent := ev.Login, ev.Pass, ev.Agent
		if login == "" {
			login = FixtureWallet
		}
		if pass == "" {
			pass = FixturePass
		}
		if agent == "" {
			agent = FixtureAgent
		}
		lines := []builtLine{{up: true, bytes: BuildLoginReq(id, login, pass, agent, ev.Rigid)}}
		if ev.Status == "error" {
			code := ev.ErrCode
			if code == 0 {
				code = -1
			}
			msg := ev.ErrMsg
			if msg == "" {
				msg = FixtureErrLogin
			}
			lines = append(lines, builtLine{up: false, bytes: BuildErrorResp(id, code, msg)})
			run.loggedIn = false // login 失败 → 连接关闭（不得再排业务事件）
			return lines, nil
		}
		run.loggedIn = true
		run.sessionRef = sessionID(ev)
		job := eventJob(ev)
		run.seenJobs[job.JobID] = true
		lines = append(lines, builtLine{up: false, bytes: BuildLoginRespOK(id, run.sessionRef, job, ev.Extensions)})
		return lines, nil
	case "job":
		job := eventJob(ev)
		run.seenJobs[job.JobID] = true
		return []builtLine{{up: false, bytes: BuildJobNotify(job)}}, nil
	case "submit":
		id := run.ids.resolve(ev)
		jobID := ev.JobID
		if jobID == "" && ev.Job != nil {
			jobID = ev.Job.JobID
		}
		if jobID == "" {
			jobID = FixtureJobID2
		}
		nonce := ev.Nonce
		if nonce == "" {
			nonce = FixtureNonce
		}
		result := ev.Result
		if result == "" {
			result = FixtureResult
		}
		lines := []builtLine{{up: true, bytes: BuildSubmitReq(id, run.eventSessionID(ev), jobID, nonce, result, ev.Algo, ev.Sig, ev.Commitment)}}
		if ev.Status == "error" {
			code := ev.ErrCode
			if code == 0 {
				code = -1
			}
			msg := ev.ErrMsg
			if msg == "" {
				msg = FixtureErrSubmit
			}
			lines = append(lines, builtLine{up: false, bytes: BuildErrorResp(id, code, msg)})
		} else {
			lines = append(lines, builtLine{up: false, bytes: BuildSubmitRespOK(id)})
		}
		return lines, nil
	case "keepalived":
		id := run.ids.resolve(ev)
		lines := []builtLine{{up: true, bytes: BuildKeepalivedReq(id, run.eventSessionID(ev), ev.KeepaliveAlias)}}
		lines = append(lines, builtLine{up: false, bytes: BuildKeepalivedResp(id)})
		return lines, nil
	case "getjob":
		id := run.ids.resolve(ev)
		job := eventJob(ev)
		run.seenJobs[job.JobID] = true
		return []builtLine{
			{up: true, bytes: BuildGetjobReq(id, run.eventSessionID(ev))},
			{up: false, bytes: BuildGetjobResp(id, job)},
		}, nil
	}
	return nil, fmt.Errorf("xmrmining: unknown event kind %q (method_unknown)", ev.Kind)
}

// Generate walks the sessions' events and emits one MessageEvent per line
// run（逐行缺省；PackNext 粘连跨事件边界）。Sequential mode walks session by
// session; concurrent mode interleaves round-robin by event index（契约 §5
// C-07）。端口：事件级 SrcPort/DstPort=0 继承链级缺省（裁定2——不在此硬编码
// 18081），会话级覆盖经 sessionPort 闭包逐会话生效（validator 守会话间一致性）.
func (g *XMRGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("xmrmining generator: EmitMsg is nil")
	}
	cfg := req.Meta.XMR
	if cfg == nil || len(cfg.Sessions) == 0 {
		cfg = defaultFlow()
	}

	sessionPort := func(si int) uint16 {
		if si < len(cfg.Sessions) {
			return cfg.Sessions[si].DstPort
		}
		return 0
	}

	runs := make([]*sessionRun, len(cfg.Sessions))
	for i := range cfg.Sessions {
		runs[i] = &sessionRun{sess: cfg.Sessions[i], seenJobs: map[string]bool{}}
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	buildOne := func(si int, run *sessionRun, ev core.XMREvent) error {
		lines, err := run.renderEvent(ev)
		if err != nil {
			return err
		}
		packConsumed := false
		for i, msg := range lines {
			// 方向交替处冲刷——除非 pack_next 开段且尚未吸收（testcase #18:
			// job 通知 + submit 请求跨方向粘连 = 653B 单段；submit 自动响应
			// 不粘连）.
			if run.hasPending && msg.up != run.pendingUp && (!run.packWithNext || packConsumed) {
				if err := run.flush(sessionPort(si), cfg.Sessions[si].SrcPort, emit); err != nil {
					return err
				}
			}
			if run.hasPending && run.packWithNext {
				packConsumed = true
			}
			run.pendingUp = msg.up
			run.hasPending = true
			run.pending = append(run.pending, msg.bytes...)
			// 粘连段仅在 PackNext 事件后跨边界保持；未声明则事件末行冲刷.
			if i == len(lines)-1 {
				if ev.PackNext {
					run.packWithNext = true
				} else {
					run.packWithNext = false
					if err := run.flush(sessionPort(si), cfg.Sessions[si].SrcPort, emit); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for j := 0; j < maxLen; j++ {
			for si, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				if err := buildOne(si, r, r.sess.Events[j]); err != nil {
					return err
				}
			}
		}
	} else {
		for si, r := range runs {
			for _, ev := range r.sess.Events {
				if err := buildOne(si, r, ev); err != nil {
					return err
				}
			}
		}
	}
	for i, r := range runs {
		if r.hasPending {
			return fmt.Errorf("xmrmining: sessions[%d] ends with a pack_next event (packed run must terminate with a plain event)", i)
		}
	}
	return nil
}

// flush emits the accumulated same-direction run as one MessageEvent.
func (run *sessionRun) flush(dstPort, srcPort uint16, emit func(layers.MessageEvent) error) error {
	if !run.hasPending {
		return nil
	}
	if err := emit(layers.MessageEvent{
		Up:      run.pendingUp,
		Bytes:   run.pending,
		DstPort: dstPort,
		SrcPort: srcPort,
	}); err != nil {
		return err
	}
	run.pending = nil
	run.hasPending = false
	return nil
}

// init registers the xmrmining generator and validator with the layer
// registry（side-effect import 激活）.
func init() {
	layers.RegisterLayerGenerator("xmrmining", func() (layers.LayerGenerator, error) {
		return &XMRGenerator{}, nil
	})
	layers.RegisterLayerValidator("xmrmining", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
