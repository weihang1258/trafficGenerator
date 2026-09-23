// Package mmse generator: 会话编排回放（D-MMSE-1，契约 §5 声明式回放——
// 配置是剧本、引擎是回放者）。逐事件产出完整 HTTP 帧 MessageEvent（请求行/
// 状态行/Host/Content-Type/Content-Length + PDU 体），http 层透传转发
// （cwmp/doh/onvif 同款），tcp 层管分段/握手/挥手。顺序模式逐会话整块回放
// （第二会话握手包号 = 前会话总包数 + 1）；concurrent 模式按事件下标
// round-robin 交错（C-1）。TID/MsgID 绑定经 buildTxBindings 预计算（与
// validator 同函数同序，裁定5）。
package mmse

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MMSEGenerator is the mmse terminal-layer generator ([ip→tcp→http→mmse]).
type MMSEGenerator struct{}

// Name returns "mmse".
func (g *MMSEGenerator) Name() string { return "mmse" }

// sessRun is one session's generation state（端点解析结果 + 预计算绑定）。
type sessRun struct {
	idx      int
	sess     core.MMSESession
	srcPort  uint16
	dstIP    string
	dstPort  uint16
	bindings []*txBinding
}

// Generate walks the sessions' events and emits one MessageEvent per event.
func (g *MMSEGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("mmse generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.MMSE
	if cfg == nil {
		cfg = &core.MMSEConfig{}
	}
	if len(cfg.Sessions) == 0 {
		// 空配置默认流（P0b 基线）：最小提交事务（无 multipart——CT 裸
		// text/plain 形）+ Ok 确认。TCP 8 包（3 握手 + POST + 200 + 3 挥手）。
		// 浅拷贝 cfg——默认会话必须同时进 buildTxBindings（绑定预计算与
		// 回放同源），不得只换局部变量。
		yes := true
		cp := *cfg
		cp.Sessions = []core.MMSESession{{
			Role: "ua",
			Events: []core.MMSEEvent{
				{Kind: "send_req", TransactionID: "auto", Date: int64Ptr(1725000000),
					From:           &core.MMSEFrom{Address: "+8613800138000/TYPE=PLMN"},
					To:             []string{"+8613911223344/TYPE=PLMN"},
					DeliveryReport: &yes},
				{Kind: "send_conf", TransactionID: "auto", ResponseStatus: "ok", MessageID: "auto"},
			},
		}}
		cfg = &cp
	}
	sessions := cfg.Sessions
	// concurrent：config 级强制全部；会话级 flag 亦可单会话声明。
	concurrent := cfg.Concurrent
	runs := make([]*sessRun, len(sessions))
	for i := range sessions {
		s := sessions[i]
		r := &sessRun{idx: i, sess: s}
		r.srcPort = s.SrcPort // 0 = 链层缺省（tcp 层回退 cfg src port）
		r.dstIP = s.DstIP
		r.dstPort = s.DstPort
		if r.dstPort == 0 {
			r.dstPort = uint16(req.Meta.DstPort)
		}
		if r.dstPort == 0 {
			r.dstPort = 80 // IANA HTTP（FieldContract 缺省，裁定3）
		}
		if concurrent || s.Concurrent {
			concurrent = true
		}
		runs[i] = r
	}
	// 绑定预计算：与 validator 同函数同序（裁定5 唯一解析权威）。
	bindings, err := buildTxBindings(cfg)
	if err != nil {
		return err
	}
	for i := range runs {
		runs[i].bindings = bindings[i]
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	if concurrent {
		// round-robin 按事件下标交错（cwmp_concurrent_sessions 同款）。
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for ei := 0; ei < maxLen; ei++ {
			for _, r := range runs {
				if ei < len(r.sess.Events) {
					if err := g.renderEvent(r, ei, cfg, emit); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for _, r := range runs {
		for ei := range r.sess.Events {
			if err := g.renderEvent(r, ei, cfg, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderEvent emits one event as a complete HTTP frame MessageEvent.
func (g *MMSEGenerator) renderEvent(r *sessRun, ei int, cfg *core.MMSEConfig, emit func(layers.MessageEvent) error) error {
	ev := &r.sess.Events[ei]
	b := r.bindings[ei]
	host := hostHeader(r.dstIP, r.dstPort)
	var frame []byte
	if ev.Kind == "retrieve" {
		frame = buildHTTPRequest("GET", b.URI, host, ev.HTTP, nil)
	} else {
		pdu, err := buildPDU(cfg, ev, b)
		if err != nil {
			return fmt.Errorf("mmse session %d event %d: %w", r.idx, ei, err)
		}
		if b.IsRequest {
			uri := ev.URI
			if uri == "" {
				uri = "/mms"
			}
			frame = buildHTTPRequest("POST", uri, host, ev.HTTP, pdu)
		} else {
			frame = buildHTTPResponse(200, host, ev.HTTP, pdu)
		}
	}
	evm := layers.MessageEvent{Up: b.IsRequest, Bytes: frame}
	setEventEndpoint(&evm, r)
	return emit(evm)
}

// setEventEndpoint stamps the event with the session's connection endpoints
// （srcPort=0 回退链层 cfg 值；SrcIP 非空即覆盖——MessageEvent.SrcIP 无标记
// 契约「空串 = 链层默认」；DstIP 覆盖须伴 OverrideDstIP——down 方向跳过
// 交换，mmsc 回放方向四元组是绝对的）。
func setEventEndpoint(ev *layers.MessageEvent, r *sessRun) {
	if r.srcPort != 0 {
		ev.SrcPort = r.srcPort
	}
	if r.sess.SrcIP != "" {
		ev.SrcIP = r.sess.SrcIP
	}
	if r.dstIP != "" {
		ev.DstIP = r.dstIP
		ev.OverrideDstIP = true
	}
	if r.dstPort != 0 {
		ev.DstPort = r.dstPort
	}
}

// hostHeader renders the Host header value（IPv6 字面量加方括号）。
func hostHeader(dstIP string, dstPort uint16) string {
	host := dstIP
	if host == "" {
		return ""
	}
	if containsByte(host, ':') && host[0] != '[' {
		host = "[" + host + "]"
	}
	return host + ":" + itoa(uint64(dstPort))
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func int64Ptr(v int64) *int64 { return &v }

// GenEvents marks this generator as a message event producer.
func (g *MMSEGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *MMSEGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("mmse generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("mmse", func() (layers.LayerGenerator, error) {
		return &MMSEGenerator{}, nil
	})
	layers.RegisterLayerValidator("mmse", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
