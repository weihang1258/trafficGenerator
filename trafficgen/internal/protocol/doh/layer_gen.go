// Package doh layer generator: walks sessions (concurrent = round-robin per
// event index, like gbt/cwmp; sequential = session by session) and emits two
// MessageEvents per query transaction — the complete HTTP request frame (up:
// POST body or GET base64url query parameter) and the auto-answered response
// frame (down: 2xx + DNS wire with ID echo, or the non-2xx empty shape per
// RFC 8484 §4.2.1). The http layer forwards both verbatim (identity
// transformer); the tcp layer owns segmentation, handshake, and teardown.
//
// Per-request Connection policy (design §5 H2 钉死): every request in a
// multi-transaction session carries Connection: keep-alive; only the final
// transaction carries close (default).
package doh

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DOHGenerator is the doh terminal-layer generator ([ip→tcp→http→doh]).
type DOHGenerator struct{}

// Name returns "doh".
func (g *DOHGenerator) Name() string { return "doh" }

// Generate walks the sessions' query transactions and emits the request/
// response frame pair per event.
func (g *DOHGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("doh generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.DOH
	if cfg == nil {
		cfg = &core.DOHConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线单事务——POST www.example.com A →
		// 200 NOERROR + A 192.0.2.1 TTL 300。9 包（3 握手 + 2 帧 + 4 挥手）。
		sessions = []core.DOHSession{{
			Events: []core.DOHEvent{{
				Kind:  "query",
				DNSID: DefaultDNSID,
				Name:  FixtureName,
				QType: "A",
				Response: &core.DOHResponse{
					Status:  200,
					RCode:   "NOERROR",
					Answers: []core.DOHAnswer{{Name: FixtureName, Type: "A", TTL: FixtureTTL, RData: FixtureA}},
				},
			}},
		}}
	}

	dstIP := req.Meta.DstIP
	if dstIP == "" {
		dstIP = FixtureDstIP
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	buildOne := func(run *sessionRun, ev core.DOHEvent, isLast bool) error {
		reqFrame, respFrame, err := run.buildTransaction(ev, dstIP, isLast)
		if err != nil {
			return err
		}
		out := layers.MessageEvent{Up: true, Bytes: reqFrame}
		if p := run.sess.SrcPort; p != 0 {
			out.SrcPort = p
		}
		if err := emit(out); err != nil {
			return err
		}
		out = layers.MessageEvent{Up: false, Bytes: respFrame}
		if p := run.sess.SrcPort; p != 0 {
			out.SrcPort = p
		}
		return emit(out)
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		runs[i] = &sessionRun{sess: s, cfg: cfg}
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
				if err := buildOne(r, r.sess.Events[j], j == len(r.sess.Events)-1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, r := range runs {
		for i, ev := range r.sess.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := buildOne(r, ev, i == len(r.sess.Events)-1); err != nil {
				return err
			}
		}
	}
	return nil
}

// sessionRun is the per-session generation state.
type sessionRun struct {
	sess core.DOHSession
	cfg  *core.DOHConfig
}

// buildTransaction renders one query's request + response frames.
func (run *sessionRun) buildTransaction(ev core.DOHEvent, dstIP string, isLast bool) (reqFrame, respFrame []byte, err error) {
	rd := true
	if ev.RD != nil {
		rd = *ev.RD
	}
	qname, err := EncodeQName(ev.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("doh: %v", err)
	}
	qtype, err := ParseQType(ev.QType)
	if err != nil {
		return nil, nil, fmt.Errorf("doh: %v", err)
	}
	qclass, err := ParseQClass(ev.QClass)
	if err != nil {
		return nil, nil, fmt.Errorf("doh: %v", err)
	}
	q := QuerySpec{ID: uint16(ev.DNSID), Name: ev.Name, QName: qname, QType: qtype, QClass: qclass, RD: rd}

	// HTTP mapping: event > session > config > POST.
	method := ev.Method
	if method == "" {
		method = run.sess.Method
	}
	if method == "" {
		method = run.cfg.Method
	}
	if method == "" {
		method = "POST"
	}
	uri := ev.URI
	if uri == "" {
		uri = run.sess.URI
	}
	if uri == "" {
		uri = run.cfg.URI
	}
	if uri == "" {
		uri = FixtureURI
	}
	connection := "keep-alive"
	if isLast {
		connection = "close"
	}
	var reqOverrides map[string]string
	if ev.HTTP != nil {
		reqOverrides = ev.HTTP.RequestHeaders
	}

	queryWire := EncodeQueryWire(q)
	if method == "GET" {
		reqFrame = BuildGETRequest(uri, hostHeader(dstIP, reqOverrides), Base64URL(queryWire), ev.ExtraQuery, connection, reqOverrides)
	} else {
		reqFrame = BuildPOSTRequest(uri, hostHeader(dstIP, reqOverrides), queryWire, connection, reqOverrides)
	}

	// Auto-answer.
	resp := ev.Response
	if resp == nil {
		resp = &core.DOHResponse{}
	}
	status := resp.Status
	if status == 0 {
		status = 200
	}
	if status < 200 || status > 299 {
		// 非 2xx 确定性规则（design §5/H1）：状态行 + Content-Length: 0，
		// 无 DNS wire。
		return reqFrame, BuildErrorResponse(status), nil
	}
	rspec, maxAge, err := run.buildResponseSpec(q, *resp)
	if err != nil {
		return nil, nil, err
	}
	respWire := EncodeResponseWire(rspec)
	if len(respWire) > MaxDNSWire {
		return nil, nil, fmt.Errorf("doh: response dns message is %d bytes, exceeds the 65535 length bound", len(respWire))
	}
	var respOverrides map[string]string
	if ev.HTTP != nil {
		respOverrides = ev.HTTP.ResponseHeaders
	}
	return reqFrame, Build2xxResponse(status, respWire, maxAge, respOverrides), nil
}

// buildResponseSpec resolves the response wire shape + the Cache-Control
// max-age (answers' min TTL; no answers → SOA MINIMUM from authority; else 0
// — design §3.6).
func (run *sessionRun) buildResponseSpec(q QuerySpec, resp core.DOHResponse) (ResponseSpec, int64, error) {
	rcode, err := ParseRCode(resp.RCode)
	if err != nil {
		return ResponseSpec{}, 0, fmt.Errorf("doh: %v", err)
	}
	ra := true
	if resp.RA != nil {
		ra = *resp.RA
	}
	rspec := ResponseSpec{ID: q.ID, Query: q, RCode: rcode, AA: resp.AA, TC: resp.TC, RA: ra}

	minTTL := int64(-1)
	take := func(t int64) {
		if t >= 0 && (minTTL < 0 || t < minTTL) {
			minTTL = t
		}
	}
	for _, ans := range resp.Answers {
		rr, err := encodeAnswer(ans)
		if err != nil {
			return ResponseSpec{}, 0, err
		}
		rspec.Answers = append(rspec.Answers, rr)
		take(ans.TTL)
	}
	for _, ans := range resp.Authority {
		rr, err := encodeAnswer(ans)
		if err != nil {
			return ResponseSpec{}, 0, err
		}
		rspec.Authority = append(rspec.Authority, rr)
		take(int64(ans.Minimum))
	}
	if minTTL < 0 {
		minTTL = 0
	}
	return rspec, minTTL, nil
}

// encodeAnswer renders one DOHAnswer into its wire RR.
func encodeAnswer(ans core.DOHAnswer) (EncodedRR, error) {
	name := ans.Name
	if name == "" {
		return EncodedRR{}, fmt.Errorf("doh: answer name is required")
	}
	qn, err := EncodeQName(name)
	if err != nil {
		return EncodedRR{}, fmt.Errorf("doh: %v", err)
	}
	rtype, err := ParseQType(ans.Type)
	if err != nil {
		return EncodedRR{}, fmt.Errorf("doh: %v", err)
	}
	rclass, err := ParseQClass(ans.Class)
	if err != nil {
		return EncodedRR{}, fmt.Errorf("doh: %v", err)
	}
	ttl := uint32(ans.TTL)

	var rdata []byte
	switch ans.Type {
	case "A":
		rdata, err = BuildA(ans.RData)
	case "AAAA":
		rdata, err = BuildAAAA(ans.RData)
	case "TXT":
		strs := ans.TXTStrings
		if len(strs) == 0 {
			strs = []string{ans.RData}
		}
		rdata, err = BuildTXT(strs)
	case "CNAME", "NS", "PTR":
		rdata, err = EncodeQName(ans.RData)
	case "MX":
		pref := make([]byte, 2)
		pref[0] = byte(ans.MxPref >> 8)
		pref[1] = byte(ans.MxPref)
		var exch []byte
		exch, err = EncodeQName(ans.RData)
		if err == nil {
			rdata = append(pref, exch...)
		}
	case "SOA":
		var mn, rn []byte
		mn, err = EncodeQName(ans.MName)
		if err == nil {
			rn, err = EncodeQName(ans.RName)
		}
		if err == nil {
			rdata = mn
			rdata = append(rdata, rn...)
			for _, v := range []uint32{ans.Serial, ans.Refresh, ans.Retry, ans.Expire, ans.Minimum} {
				rdata = append(rdata, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
			}
		}
	case "HTTPS", "SVCB":
		rdata = make([]byte, 2)
		rdata[0] = byte(ans.Priority >> 8)
		rdata[1] = byte(ans.Priority)
		var tgt []byte
		tgt, err = EncodeQName(ans.Target)
		if err == nil {
			rdata = append(rdata, tgt...)
			for _, p := range ans.Params {
				var sp []byte
				sp, err = BuildSvcParam(p.Key, p.ValueHex)
				if err != nil {
					break
				}
				rdata = append(rdata, sp...)
			}
		}
	default:
		// 未知数值类型：RDATA 由 hex 直配（fixture 透传通道）。
		if ans.RData == "" {
			return EncodedRR{}, fmt.Errorf("doh: unknown-type answer requires hex rdata")
		}
		rdata, err = hex.DecodeString(strings.ToLower(ans.RData))
	}
	if err != nil {
		return EncodedRR{}, fmt.Errorf("doh: %v", err)
	}
	return EncodeRR(qn, rtype, rclass, ttl, rdata)
}

// hostHeader resolves the Host value: an explicit Host override (any case
// spelling) wins, else dst_ip (RFC 7230 §5.4 default per design §3.1).
func hostHeader(dstIP string, overrides map[string]string) string {
	for k, v := range overrides {
		if strings.EqualFold(k, "Host") && v != "" {
			return v
		}
	}
	return dstIP
}

// GenEvents marks this generator as a message event producer.
func (g *DOHGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *DOHGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("doh generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("doh", func() (layers.LayerGenerator, error) {
		return &DOHGenerator{}, nil
	})
	layers.RegisterLayerValidator("doh", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
