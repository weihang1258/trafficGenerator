package gbt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GBTGenerator is the gbt terminal-layer generator ([ip→tcp→http→gbt]).
// Each event becomes one MessageEvent carrying the COMPLETE HTTP frame
// bytes (request line / status line / pinned headers / body); the http layer
// forwards them verbatim (identity transformer) and the tcp layer owns
// segmentation, handshake, and teardown.
type GBTGenerator struct{}

// Name returns "gbt".
func (g *GBTGenerator) Name() string { return "gbt" }

// sessionRun is the per-session generation state.
type sessionRun struct {
	sess  core.GBTSession
	state TemplateState // latest template (workid/longpollid/refresh base)
	hasTpl bool         // whether a template response was seen
	// lastReqID is the latest request id (response auto-echo, design §6
	// auto-derivation ②).
	lastReqID json.RawMessage
	// pending accumulates join_next coalesced message bytes (多消息粘单段).
	pending []byte
	// pendingUp is the accumulated run's direction (requests or responses).
	pendingUp bool
}

// Generate walks the sessions' events and emits one MessageEvent per
// message (or per join_next run). Sequential mode walks session by session;
// concurrent mode interleaves round-robin by event index (设计 §5 并发会话).
func (g *GBTGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("gbt generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.GBT
	if cfg == nil {
		cfg = &core.GBTConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线单会话——取模板事务（请求 id=1 空参 +
		// 响应 18 键模板），带默认 Basic 头。9 包（3 握手 + 2 消息 + 4 挥手）。
		sessions = []core.GBTSession{{
			Role:   "miner",
			Auth:   &core.GBTAuth{User: "user", Pass: "pass"},
			Events: []core.GBTEvent{
				{Kind: "request", ID: json.RawMessage(`1`), Method: "getblocktemplate", Params: json.RawMessage(`[]`)},
				{Kind: "response", ResultKind: "template", Template: "full"},
			},
		}}
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		runs[i] = &sessionRun{sess: s}
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	buildOne := func(run *sessionRun, ev core.GBTEvent) error {
		msg, err := buildMessage(run, ev, req.Meta)
		if err != nil {
			return err
		}
		if len(run.pending) == 0 {
			run.pendingUp = msg.up
		} else if msg.up != run.pendingUp {
			// join_next run mixing directions is a config error (requests
			// and responses never share a coalesced segment in the fixture).
			return fmt.Errorf("gbt: join_next run mixes request and response messages (session events must coalesce per direction)")
		}
		run.pending = append(run.pending, msg.bytes...)
		if !ev.JoinNext {
			// Flush the accumulated run as one event on this session's port.
			out := layers.MessageEvent{Up: run.pendingUp, Bytes: run.pending}
			if p := run.sess.SrcPort; p != 0 {
				out.SrcPort = p
			}
			if err := emit(out); err != nil {
				return err
			}
			run.pending = nil
		}
		return nil
	}

	if cfg.Concurrent {
		// 并发会话：按事件索引轮转交错（会话内部顺序保持；tcp 层
		// concurrent:true 下按端口独立连接，流结束统一挥手）。
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
		// 多会话按序：会话 0 全部事件 → 会话 1 …（tcp 层按事件 SrcPort 切换
		// 连接：挥旧握新，第二会话握手包号 = 前会话总包数 + 1）。
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
	// 会话未冲刷的 join_next 尾巴（最后事件仍标 join_next）：配置错误——
	// 粘包 run 必须以非 join_next 事件收尾。
	for i, r := range runs {
		if len(r.pending) > 0 {
			return fmt.Errorf("gbt: sessions[%d] ends with a join_next event (coalesced run must terminate with a plain event)", i)
		}
	}
	return nil
}

// builtMessage is one event's complete HTTP frame.
type builtMessage struct {
	up    bool
	bytes []byte
}

// buildMessage builds one event's HTTP frame and updates the session state.
func buildMessage(run *sessionRun, ev core.GBTEvent, meta layers.FlowMeta) (builtMessage, error) {
	sess := run.sess
	switch ev.Kind {
	case "request":
		if len(ev.ID) == 0 {
			return builtMessage{}, fmt.Errorf("gbt: request event missing id")
		}
		run.lastReqID = ev.ID
		uri := ev.URI
		if uri == "" {
			uri = sess.URI
		}
		if uri == "" && sess.URIFrom == "template.longpolluri" {
			uri = longpollPath(run.state.LongpollURI)
		}
		if uri == "" {
			uri = "/"
		}
		params := substituteFromTokens(ev.Params, run.state)
		jsonrpc2 := sess.JSONRPCVersion == "2.0"
		body := BuildRequestJSON(ev.ID, ev.Method, params, jsonrpc2)
		authB64 := ""
		if sess.Auth != nil {
			authB64 = base64.StdEncoding.EncodeToString([]byte(sess.Auth.User + ":" + sess.Auth.Pass))
		}
		version := sess.HTTPVersion
		if version == "" {
			version = "HTTP/1.1"
		}
		connection := "keep-alive"
		if version == "HTTP/1.0" {
			connection = "close"
		}
		frame := BuildHTTPRequest(version, "POST", uri, hostLiteral(meta), authB64, body, connection)
		return builtMessage{up: true, bytes: frame}, nil

	case "response":
		id := ev.ID
		if len(id) == 0 {
			id = run.lastReqID
			if len(id) == 0 {
				return builtMessage{}, fmt.Errorf("gbt: response event with no id and no prior request to echo")
			}
		}
		jsonrpc2 := sess.JSONRPCVersion == "2.0"
		version := sess.HTTPVersion
		if version == "" {
			version = "HTTP/1.1"
		}
		connection := "keep-alive"
		if ev.Close {
			connection = "close"
		}
		// 401: 无 body（不构造 JSON）。
		if ev.Status == 401 {
			return builtMessage{up: false, bytes: BuildHTTP401(version, "jsonrpc", connection)}, nil
		}
		var body []byte
		switch ev.ResultKind {
		case "template":
			body = buildTemplateResult(run, ev.Template)
		case "accepted_null":
			body = BuildResponseJSON(id, []byte(`null`), jsonrpc2)
		case "reject_reason", "proposal_reject":
			reason := ev.Reason
			if reason == "" {
				reason = FixtureReason
			}
			body = BuildResponseJSON(id, []byte(quoteJSON(reason)), jsonrpc2)
		case "proposal_true":
			body = BuildResponseJSON(id, []byte(`true`), jsonrpc2)
		case "error_object":
			code := ev.ErrorCode
			if code == 0 {
				code = FixtureErrorCode
			}
			msg := ev.ErrorMessage
			if msg == "" {
				msg = FixtureErrorMessage
			}
			body = BuildErrorJSON(id, code, msg)
		default:
			// 空结果（bare 200）：默认模板事务响应。
			body = buildTemplateResult(run, ev.Template)
		}
		status := ev.Status
		if status == 0 {
			if ev.ResultKind == "error_object" {
				status = 500
			} else {
				status = 200
			}
		}
		return builtMessage{up: false, bytes: BuildHTTPResponse(version, status, body, connection)}, nil
	}
	return builtMessage{}, fmt.Errorf("gbt: unknown event kind %q", ev.Kind)
}

// buildTemplateResult builds the template response body and updates the
// session state (workid/longpollid/height/curtime 派生源).
func buildTemplateResult(run *sessionRun, variant string) []byte {
	switch variant {
	case "refresh":
		if !run.hasTpl {
			// planner 已拒绝（refresh 无前序模板）；防御性取基态。
			run.state = BaseTemplateState()
		}
		run.state = run.state.Refresh()
		run.hasTpl = true
		return BuildResponseJSON(run.lastReqID, BuildTemplateFull(run.state), false)
	case "plain":
		h := FixtureHeight
		if run.hasTpl {
			h = run.state.Height
		}
		run.state.Height, run.state.CurTime = h, FixtureCurTime
		return BuildResponseJSON(run.lastReqID, BuildTemplatePlain(h), false)
	case "tx1":
		h := FixtureHeight
		if run.hasTpl {
			h = run.state.Height
		}
		run.state.Height, run.state.CurTime = h, FixtureCurTime
		return BuildResponseJSON(run.lastReqID, BuildTemplateTx1(h), false)
	case "big":
		return BuildResponseJSON(run.lastReqID, BuildTemplateBig(), false)
	default: // "full" or ""
		if !run.hasTpl {
			run.state = BaseTemplateState()
		}
		run.hasTpl = true
		return BuildResponseJSON(run.lastReqID, BuildTemplateFull(run.state), false)
	}
}

// substituteFromTokens replaces the JSON string elements "workid_from" /
// "longpollid_from" with the session state's latest template values
// (design §6: params 内联或 *_from 引用会话最近模板派生). The tokens appear
// as complete JSON string literals inside the raw params bytes.
func substituteFromTokens(params json.RawMessage, st TemplateState) json.RawMessage {
	if len(params) == 0 {
		return params
	}
	s := string(params)
	if strings.Contains(s, `"workid_from"`) {
		s = strings.ReplaceAll(s, `"workid_from"`, quoteJSON(st.WorkID))
	}
	if strings.Contains(s, `"longpollid_from"`) {
		s = strings.ReplaceAll(s, `"longpollid_from"`, quoteJSON(st.LongpollID))
	}
	return json.RawMessage(s)
}

// longpollPath extracts the request path from a longpolluri
// ("http://host:port/longpoll" → "/longpoll"): the substring from the third
// slash; a URI without a path yields "/".
func longpollPath(uri string) string {
	rest := uri
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[i:]
	}
	return "/"
}

// hostLiteral builds the Host header value: bracketed IPv6 literals, plain
// IPv4, with the destination port.
func hostLiteral(meta layers.FlowMeta) string {
	host := meta.DstIP
	if strings.Contains(host, ":") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + host + "]"
		}
	}
	return host + ":" + strconv.Itoa(int(meta.DstPort))
}

// GenEvents marks this generator as a message event producer.
func (g *GBTGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *GBTGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("gbt generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("gbt", func() (layers.LayerGenerator, error) {
		return &GBTGenerator{}, nil
	})
	layers.RegisterLayerValidator("gbt", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
