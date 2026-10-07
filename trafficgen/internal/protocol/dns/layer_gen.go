package dns

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DNSGenerator is the dns terminal-layer generator (dns 终结层层生成器,
// 波 4)。It produces one MessageEvent per DNS message (query + optional
// response) into the transport layer's event stream; the udp layer emits one
// datagram per event. Event bytes reuse the legacy builders (buildDNSQuery /
// buildDNSMessage / buildDNSResponse / buildDNSResponseGeneral), so the wire
// output is byte-identical to the legacy dns.NewPlanner (dns.go Plan).
//
// 与 legacy 的差异（已接受，见 11-dnp3-design.md 波 4 节）：DNS-over-TCP 由
// TCPGenerator 全握手承载，而 legacy 是无握手 PSH+ACK——TCP 变体不在本
// 生成器范围（链名 "dns" 解析为 udp 依赖链）；Transport=="tcp" 时显式
// 报错，防止静默产生与 legacy 语义不同的包。
type DNSGenerator struct{}

// Name returns "dns".
func (g *DNSGenerator) Name() string { return "dns" }

// Generate produces the DNS query event (Up) and, when IsResponse is set,
// the response event (Down), reusing the legacy message builders.
func (g *DNSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.DNS
	if cfg == nil {
		cfg = &core.DNSConfig{}
	}
	if cfg.Transport != "" && cfg.Transport != "udp" {
		return fmt.Errorf("dns generator: transport %q not supported (udp only; tcp deferred to wave 4 TCP variant)", cfg.Transport)
	}

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("dns generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	// Query message: multi-question path through buildDNSMessage, single
	// question through the legacy buildDNSQuery (mirrors dns.go:230-251).
	var queryMsg []byte
	if len(cfg.Questions) > 0 {
		txid := cfg.TxID
		if txid == 0 {
			txid = 0x1234
		}
		qs := make([]wireQuestion, 0, len(cfg.Questions))
		for _, q := range cfg.Questions {
			qc := q.Class
			if qc == 0 {
				qc = 1 // IN
			}
			qs = append(qs, wireQuestion{name: q.Name, qtype: q.Type, qclass: qc})
		}
		var additional []wireRR
		if cfg.EDNS0Enabled {
			additional = []wireRR{optWireRR(cfg.UDPPayloadSize, cfg.DnssecOK)}
		}
		queryMsg = buildDNSMessage(txid, 0x0100, qs, nil, nil, additional)
	} else {
		queryMsg = buildDNSQuery(cfg.Domain, cfg.QueryType, cfg.TxID, cfg.EDNS0Enabled, cfg.UDPPayloadSize, cfg.DnssecOK)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: queryMsg}); err != nil {
		return err
	}
	// 响应判定（D-DNS-2 反转，2026-10-07）：缺省即一问一答——"一请求一
	// 响应才是正常业务"。query_only 显式纯查询（1 事件）；is_response
	// 沿现状语义（true=一问一答，false=legacy 显式查询）。互斥校验在
	// validateDNSConfig（Plan/Validate 期同步失败，不拖到 drive 期）。
	wantResponse := !cfg.QueryOnly
	if !wantResponse {
		return nil
	}

	// Response message: general builder when the spec carries multiple
	// answers, an authority section, a non-zero rcode, or multiple questions;
	// legacy single-RR builder otherwise (dns.go:293-303 同款分派)。
	var responseMsg []byte
	if len(cfg.Answers) > 0 || len(cfg.Authority) > 0 || cfg.RCode != 0 || len(cfg.Questions) > 0 {
		responseMsg = buildDNSResponseGeneral(cfg)
	} else {
		responseMsg = buildDNSResponse(cfg.Domain, cfg.QueryType, cfg.ResponseIP, cfg.TxID)
	}
	return emit(layers.MessageEvent{Up: false, Bytes: responseMsg})
}

// GenEvents marks this generator as a message event producer.
func (g *DNSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *DNSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("dns generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 dns 层生成器工厂 + 协议校验器（layers 包不依赖 dns 包）。
	layers.RegisterLayerGenerator("dns", func() (layers.LayerGenerator, error) {
		return &DNSGenerator{}, nil
	})
	layers.RegisterLayerValidator("dns", func(spec *core.FlowSpec) error {
		if err := validateDNSConfig(*spec); err != nil {
			return err
		}
		// TCP 载体变体延后（TCPGenerator 全握手 vs legacy 无握手 PSH+ACK），
		// 链上显式拒绝——不能在 drive 期才报（生成器错误被吞成空流），
		// 必须在 Plan/Validate 期同步失败。
		if spec.DNS.Transport == "tcp" {
			return fmt.Errorf("dns: tcp transport not supported by the layer chain yet (udp only; tcp deferred)")
		}
		return nil
	})
}
