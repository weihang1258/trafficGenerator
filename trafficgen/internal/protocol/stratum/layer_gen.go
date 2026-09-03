package stratum

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// StratumGenerator is the stratum terminal-layer generator ([tcp→stratum]).
// Each event becomes one MessageEvent carrying the COMPLETE line bytes
// (compact JSON + LF; a pool request event emits request+miner-response as
// two events per design §5 自动派生). The tcp layer owns segmentation,
// handshake, and teardown; PackNext merges two same-direction lines into one
// segment (多行粘连单段正例).
type StratumGenerator struct{}

// Name returns "stratum".
func (g *StratumGenerator) Name() string { return "stratum" }

// sessionRun is the per-session generation state (design §5 状态机).
type sessionRun struct {
	sess       core.StratumSession
	subscribed bool
	authorized string // authorized username ("" = none)
	en2Size    int    // current extranonce2 byte size (0 = none)
	jobs       map[string]bool
	vrActive   bool // version-rolling active (mining.configure seen)
	pending    []byte
	pendingUp  bool
	hasPending bool
}

// Generate walks the sessions' events and emits one MessageEvent per line
// (or per packed run). Sequential mode walks session by session; concurrent
// mode interleaves round-robin by event index (设计 §5 并发会话).
func (g *StratumGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("stratum generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.Stratum
	if cfg == nil {
		cfg = &core.StratumConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线订阅会话（subscribe 请求 + 订阅响应，
		// fixture 会话 1 值）。9 包（3 握手 + 2 行 + 4 挥手）。
		sessions = []core.StratumSession{{
			Events: []core.StratumEvent{{Kind: "subscribe", ID: jsonNum(1)}},
		}}
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		runs[i] = &sessionRun{sess: s, jobs: map[string]bool{}}
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

	buildOne := func(run *sessionRun, ev core.StratumEvent) error {
		lines, err := buildEventLines(run, ev)
		if err != nil {
			return err
		}
		for i, msg := range lines {
			if run.hasPending && msg.up != run.pendingUp {
				// Direction change within one event (request → auto-response):
				// the accumulated run closes as its own segment first — pack
				// merging is only defined for adjacent same-direction lines
				// (design §6: pack 相邻同方向行合并为一段).
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
			// event asked to pack with the next one (多行粘连单段, case 21);
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

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for j := 0; j < maxLen; j++ {
			for _, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := buildOne(r, r.sess.Events[j]); err != nil {
					return err
				}
			}
		}
	} else {
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
	}
	for i, r := range runs {
		if r.hasPending {
			return fmt.Errorf("stratum: sessions[%d] ends with a pack_next event (packed run must terminate with a plain event)", i)
		}
	}
	return nil
}

// builtLine is one complete line with its direction.
type builtLine struct {
	up    bool
	bytes []byte
}

// buildEventLines builds one event's line(s): a miner request emits the
// request line plus the auto-response line (design §5 自动派生规则①-④); a
// pool notification emits one down line; client.get_version emits the pool
// request (down) then the miner response (up).
func buildEventLines(run *sessionRun, ev core.StratumEvent) ([]builtLine, error) {
	switch ev.Kind {
	case "subscribe":
		run.subscribed = true
		size := ev.Extranonce2Size
		if size == 0 {
			size = 4
		}
		run.en2Size = size
		subs := ev.Subscriptions
		if len(subs) == 0 {
			subs = FixtureSubsS1
		}
		en1 := ev.Extranonce1
		if en1 == "" {
			en1 = FixtureExtranonce1
		}
		return []builtLine{
			{up: true, bytes: BuildSubscribeReq(ev.ID, ev.UserAgent)},
			{up: false, bytes: BuildSubscribeResp(ev.ID, subs, en1, size)},
		}, nil

	case "extranonce_subscribe":
		return []builtLine{
			{up: true, bytes: BuildExtranonceSubscribeReq(ev.ID)},
			{up: false, bytes: BuildTrueResp(ev.ID)},
		}, nil

	case "authorize":
		user := ev.Username
		if user == "" {
			user = FixtureUsername1
		}
		pass := ev.Password
		if pass == "" {
			pass = FixturePassword
		}
		if ev.Result != nil && string(ev.Result) == "false" {
			// 拒绝路径：authorize 拒绝后不得再授权成功（状态机）。
			return []builtLine{
				{up: true, bytes: BuildAuthorizeReq(ev.ID, user, pass)},
				{up: false, bytes: BuildErrorResp(ev.ID, 24, FixtureErrUnauthorized)},
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
		prevhash := ev.Prevhash
		if prevhash == "" {
			prevhash = FixturePrevhashWire // 线序（反转展示序）
		}
		coinb1, coinb2 := ev.Coinb1, ev.Coinb2
		if coinb1 == "" {
			coinb1 = FixtureCoinb1
		}
		if coinb2 == "" {
			coinb2 = FixtureCoinb2
		}
		merkle := ev.MerkleBranch
		if merkle == nil {
			merkle = []string{FixtureMerkleStep}
		}
		version, nbits, ntime := ev.Version, ev.Nbits, ev.Ntime
		if version == "" {
			version = FixtureVersion
		}
		if nbits == "" {
			nbits = FixtureNbits
		}
		if ntime == "" {
			ntime = FixtureNtime
		}
		run.jobs[job] = true
		return []builtLine{{up: false, bytes: BuildNotify(job, prevhash, coinb1, coinb2, merkle, version, nbits, ntime, ev.CleanJobs)}}, nil

	case "set_extranonce":
		en1 := ev.Extranonce1
		if en1 == "" {
			en1 = FixtureExtranonce1Rot
		}
		size := ev.Extranonce2Size
		if size == 0 {
			size = 8
		}
		run.en2Size = size
		return []builtLine{{up: false, bytes: BuildSetExtranonce(en1, size)}}, nil

	case "submit":
		user := ev.Username
		if user == "" {
			user = run.authorized
		}
		if user == "" {
			user = FixtureUsername1
		}
		job := ev.JobID
		if job == "" {
			job = FixtureJobA
		}
		en2 := ev.Extranonce2
		if en2 == "" {
			if run.en2Size >= 8 {
				en2 = FixtureExtranonce2Sz8
			} else {
				en2 = FixtureExtranonce2
			}
		}
		ntime := ev.Ntime
		if ntime == "" {
			ntime = FixtureNtime
		}
		nonce := ev.Nonce
		if nonce == "" {
			nonce = FixtureNonce
		}
		vbits := ev.VersionBits
		if vbits == "" && run.vrActive {
			vbits = FixtureVersionBit
		}
		if ev.Result != nil && string(ev.Result) == "false" {
			return []builtLine{
				{up: true, bytes: BuildSubmitReq(ev.ID, user, job, en2, ntime, nonce, vbits)},
				{up: false, bytes: BuildErrorResp(ev.ID, 21, FixtureErrJobNotFound)},
			}, nil
		}
		return []builtLine{
			{up: true, bytes: BuildSubmitReq(ev.ID, user, job, en2, ntime, nonce, vbits)},
			{up: false, bytes: BuildTrueResp(ev.ID)},
		}, nil

	case "get_version":
		// 矿池→矿机反向请求：请求行（down）+ 矿机自动响应行（up）。
		ver := FixtureUserAgent
		if len(ev.Result) > 0 {
			ver = unquote(ev.Result)
		}
		return []builtLine{
			{up: false, bytes: BuildGetVersionReq(ev.ID)},
			{up: true, bytes: BuildVersionResp(ev.ID, ver)},
		}, nil

	case "show_message":
		return []builtLine{{up: false, bytes: BuildShowMessage(ev.Message)}}, nil

	case "configure":
		run.vrActive = true
		return []builtLine{
			{up: true, bytes: BuildConfigureReq(ev.ID, nil, ev.Params)},
			{up: false, bytes: BuildConfigureResp(ev.ID, ev.CfgResult)},
		}, nil
	case "set_version_mask":
		mask := ev.Mask
		if mask == "" {
			mask = FixturePushMask
		}
		return []builtLine{{up: false, bytes: BuildSetVersionMask(mask)}}, nil
	}
	return nil, fmt.Errorf("stratum: unknown event kind %q", ev.Kind)
}

// unquote strips the surrounding quotes of a JSON string literal.
func unquote(raw []byte) string {
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func jsonNum(n int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf("%d", n))
}

// GenEvents marks this generator as a message event producer.
func (g *StratumGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *StratumGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("stratum generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("stratum", func() (layers.LayerGenerator, error) {
		return &StratumGenerator{}, nil
	})
	layers.RegisterLayerValidator("stratum", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
