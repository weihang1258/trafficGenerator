package ethmining

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ETHMiningGenerator is the ethmining terminal-layer generator
// ([tcp→ethmining]). Each event becomes one MessageEvent carrying the
// COMPLETE line bytes (compact JSON + LF; a miner request event emits
// request+pool-response as two events per design §5 自动派生). The tcp layer
// owns segmentation, handshake, and teardown; PackNext merges two
// same-direction lines into one segment (多行粘连单段正例).
type ETHMiningGenerator struct{}

// Name returns "ethmining".
func (g *ETHMiningGenerator) Name() string { return "ethmining" }

// sessionRun is the per-session generation state (design §5 状态机).
type sessionRun struct {
	sess       core.ETHMiningSession
	subscribed bool
	authorized string // authorized username ("" = none)
	extranonce string // current extranonce hex body (no prefix)
	jobs       map[string]bool
	prefix     string // session hex prefix ("" or "0x")
	pending    []byte
	pendingUp  bool
	hasPending bool
}

// Generate walks the sessions' events and emits one MessageEvent per line
// (or per packed run). Sessions replay session-by-session (design §5 多会话
// 展开: 按序整块回放, second session's packet start = prior session's total + 1).
func (g *ETHMiningGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("ethmining generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.ETHMining
	if cfg == nil {
		cfg = &core.ETHMiningConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线订阅会话（subscribe 请求 + 订阅响应，
		// fixture 基线值）。9 包（3 握手 + 2 行 + 4 挥手）。
		sessions = []core.ETHMiningSession{{
			Events: []core.ETHMiningEvent{{Kind: "subscribe", ID: jsonNum(1)}},
		}}
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		runs[i] = &sessionRun{sess: s, jobs: map[string]bool{}, prefix: cfg.HexPrefix}
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	flush := func(run *sessionRun) error {
		out := layers.MessageEvent{Up: run.pendingUp, Bytes: run.pending}
		if p := run.sess.SrcPort; p != 0 {
			out.SrcPort = p
		}
		if err := emit(out); err != nil {
			return err
		}
		run.pending = nil
		run.hasPending = false
		return nil
	}

	buildOne := func(run *sessionRun, ev core.ETHMiningEvent) error {
		lines, err := buildEventLines(run, ev)
		if err != nil {
			return err
		}
		for i, msg := range lines {
			if run.hasPending && msg.up != run.pendingUp {
				// Direction change within one event (request → auto-response):
				// the accumulated run closes as its own segment first — pack
				// merging is only defined for adjacent same-direction lines
				// (design §3.1 pack 条款: 方向交替处不合并).
				if err := flush(run); err != nil {
					return err
				}
			}
			if !run.hasPending {
				run.pendingUp = msg.up
				run.hasPending = true
			}
			run.pending = append(run.pending, msg.bytes...)
			// The run stays open across the event boundary only when this
			// event asked to pack with the next one (多行粘连单段, case 17);
			// if the next event's first line runs the other way, the run
			// closes there (degrades to per-line segments, never mixes).
			if i == len(lines)-1 && !ev.PackNext {
				if err := flush(run); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, r := range runs {
		for _, ev := range r.sess.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := buildOne(r, ev); err != nil {
				return err
			}
		}
	}
	for i, r := range runs {
		if r.hasPending {
			return fmt.Errorf("ethmining: sessions[%d] ends with a pack_next event (packed run must terminate with a plain event)", i)
		}
	}
	return nil
}

// builtLine is one complete line with its direction.
type builtLine struct {
	up    bool
	bytes []byte
}

// hexOf renders a hex data field with the session prefix ("" or "0x").
func (r *sessionRun) hexOf(v string) string {
	if r.prefix == "" || v == "" {
		return v
	}
	return r.prefix + v
}

// buildEventLines builds one event's line(s): a miner request emits the
// request line plus the auto-response line (design §5 自动派生规则①-④); a
// pool notification emits one down line.
func buildEventLines(run *sessionRun, ev core.ETHMiningEvent) ([]builtLine, error) {
	switch ev.Kind {
	case "subscribe":
		run.subscribed = true
		ua := ev.UserAgent
		if ua == "" {
			ua = FixtureUserAgent
		}
		proto := ev.Protocol
		if proto == "" {
			proto = FixtureProtocol
		}
		subID := ev.SubscriptionID
		if subID == "" {
			subID = FixtureSubID
		}
		en := ev.Extranonce
		if en == "" {
			en = FixtureExtranonce
		}
		run.extranonce = stripHexPrefix(en, run.prefix)
		return []builtLine{
			{up: true, bytes: BuildSubscribeReq(ev.ID, ua, proto)},
			{up: false, bytes: BuildSubscribeResp(ev.ID, run.hexOf(subID), proto, run.hexOf(en))},
		}, nil

	case "extranonce_subscribe":
		return []builtLine{
			{up: true, bytes: BuildExtranonceSubscribeReq(ev.ID)},
			{up: false, bytes: BuildTrueResp(ev.ID)},
		}, nil

	case "authorize":
		user := ev.Username
		if user == "" {
			user = FixtureUsername
		}
		pass := ev.Password
		if pass == "" {
			pass = FixturePassword
		}
		if ev.Result != nil && string(ev.Result) == "false" {
			// 拒绝路径：authorize 拒绝后不得再授权成功（状态机）。
			code, msg := ev.ErrorCode, ev.ErrorMsg
			if code == 0 {
				code = FixtureErrCodeAuth
			}
			if msg == "" {
				msg = FixtureErrUnauthorized
			}
			return []builtLine{
				{up: true, bytes: BuildAuthorizeReq(ev.ID, user, pass)},
				{up: false, bytes: BuildErrorResp(ev.ID, code, msg)},
			}, nil
		}
		run.authorized = user
		return []builtLine{
			{up: true, bytes: BuildAuthorizeReq(ev.ID, user, pass)},
			{up: false, bytes: BuildTrueResp(ev.ID)},
		}, nil

	case "set_difficulty":
		return []builtLine{{up: false, bytes: BuildSetDifficulty(ev.Difficulty)}}, nil

	case "notify":
		job := ev.JobID
		if job == "" {
			job = FixtureJobA
		}
		seed := ev.SeedHash
		if seed == "" {
			seed = FixtureSeedHash
		}
		header := ev.HeaderHash
		if header == "" {
			header = FixtureHeaderHashA
		}
		run.jobs[stripHexPrefix(job, run.prefix)] = true
		return []builtLine{{up: false, bytes: BuildNotify(run.hexOf(job), run.hexOf(seed), run.hexOf(header), ev.CleanJobs)}}, nil

	case "set_extranonce":
		en := ev.NewExtranonce
		if en == "" {
			en = FixtureExtranonce3
		}
		run.extranonce = stripHexPrefix(en, run.prefix)
		return []builtLine{{up: false, bytes: BuildSetExtranonce(run.hexOf(en))}}, nil

	case "submit":
		user := ev.Username
		if user == "" {
			user = run.authorized
		}
		if user == "" {
			user = FixtureUsername
		}
		job := ev.JobID
		if job == "" {
			job = FixtureJobA
		}
		nonce := ev.MinerNonce
		if nonce == "" {
			// 互补规则（spec §III）：minernonce 字节数 = 8 − extranonce 字节数。
			switch len(run.extranonce) / 2 {
			case 3:
				nonce = FixtureMinerNonce5
			default:
				nonce = FixtureMinerNonce6
			}
		}
		if ev.Result != nil && string(ev.Result) == "false" {
			code, msg := ev.ErrorCode, ev.ErrorMsg
			if code == 0 {
				code = FixtureErrCodeSubmit
			}
			if msg == "" {
				msg = FixtureErrJobNotFound
			}
			return []builtLine{
				{up: true, bytes: BuildSubmitReq(ev.ID, user, run.hexOf(job), run.hexOf(nonce))},
				{up: false, bytes: BuildErrorResp(ev.ID, code, msg)},
			}, nil
		}
		return []builtLine{
			{up: true, bytes: BuildSubmitReq(ev.ID, user, run.hexOf(job), run.hexOf(nonce))},
			{up: false, bytes: BuildTrueResp(ev.ID)},
		}, nil

	case "close":
		// 连接关闭由 tcp 层 FIN 挥手承载（正例恒 FIN 优雅终止，设计 §4⑩）；
		// close 事件仅标记状态机终止（planner 校验关闭后不得再排事件）。
		return nil, nil
	}
	return nil, fmt.Errorf("ethmining: unknown event kind %q", ev.Kind)
}

func jsonNum(n int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf("%d", n))
}

// GenEvents marks this generator as a message event producer.
func (g *ETHMiningGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *ETHMiningGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ethmining generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ethmining", func() (layers.LayerGenerator, error) {
		return &ETHMiningGenerator{}, nil
	})
	layers.RegisterLayerValidator("ethmining", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
