package syslog

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SyslogGenerator is the syslog terminal-layer generator (syslog 终结层层
// 生成器, 波 4)。It produces one MessageEvent per syslog datagram into the
// transport layer's event stream; the udp layer emits one datagram per event
// (always up — syslog UDP is fire-and-forget, RFC 5426 §3). Event bytes reuse
// the legacy encoders (encodeRFC5424 / encodeBSD), so the wire output is
// byte-identical to the legacy syslog.NewPlanner UDP path — modulo
// IPID/checksum already handled by the tests.
//
// Per-event Metadata carries the legacy keys (syslog_priority,
// syslog_transport), merged into the datagram Metadata by the udp layer.
type SyslogGenerator struct{}

// Name returns "syslog".
func (g *SyslogGenerator) Name() string { return "syslog" }

// Generate produces syslog message events: one per entry when Messages is
// non-empty (Count ignored), else Count copies of the single encoded message
// — mirrors planner.go Plan 的 encode 分支 + emitUDP 语义。
func (g *SyslogGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.Syslog
	if cfg == nil {
		cfg = &core.SyslogConfig{}
	} else {
		copied := *cfg
		cfg = &copied
	}

	emit := func(ev layers.MessageEvent) error {
		if req.EmitMsg == nil {
			return fmt.Errorf("syslog generator: EmitMsg is nil (generator not wired to a transport layer)")
		}
		return req.EmitMsg(ev)
	}

	// Defaults (planner.go Plan goroutine 同款): Version 1, Format rfc5424,
	// Transport udp, Count 1.
	version := cfg.Version
	if version == 0 {
		version = DefaultVersion
	}
	format := cfg.Format
	if format == "" {
		format = "rfc5424"
	}
	// Transport: only udp is reachable here (tcp/tls rejected by the chain
	// validator); kept for parity with legacy encode defaults.
	facility := cfg.Facility
	severity := cfg.Severity
	count := cfg.Count
	if count == 0 {
		count = 1
	}

	// Encode messages (planner.go:392-406 同款): multi-payload path emits one
	// datagram per entry; else Count copies of the single message.
	var msgBytesList [][]byte
	if len(cfg.Messages) > 0 {
		msgBytesList = make([][]byte, 0, len(cfg.Messages))
		for i := range cfg.Messages {
			entry := buildPerMessageCfg(cfg, &cfg.Messages[i])
			if format == "bsd" {
				msgBytesList = append(msgBytesList, encodeBSD(entry, facility, severity))
			} else {
				msgBytesList = append(msgBytesList, encodeRFC5424(entry, facility, severity, version))
			}
		}
	} else {
		single := encodeSingleMsg(cfg, format, facility, severity, version)
		msgBytesList = [][]byte{single}
	}

	priority := int(cfg.Facility)*8 + int(cfg.Severity)
	metadata := map[string]interface{}{
		"syslog_priority":  priority,
		"syslog_transport": "udp",
	}

	if len(msgBytesList) > 1 {
		for _, m := range msgBytesList {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := emit(layers.MessageEvent{Up: true, Bytes: m, Metadata: metadata}); err != nil {
				return err
			}
		}
		return nil
	}
	for i := uint32(0); i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(layers.MessageEvent{Up: true, Bytes: msgBytesList[0], Metadata: metadata}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *SyslogGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SyslogGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("syslog generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	// 反向注册 syslog 层生成器工厂 + 协议校验器（layers 包不依赖 syslog 包）。
	layers.RegisterLayerGenerator("syslog", func() (layers.LayerGenerator, error) {
		return &SyslogGenerator{}, nil
	})
	layers.RegisterLayerValidator("syslog", func(spec *core.FlowSpec) error {
		if err := validateSyslogConfig(*spec); err != nil {
			return err
		}
		if spec.Syslog != nil && (spec.Syslog.Transport == "tcp" || spec.Syslog.Transport == "tls") {
			return fmt.Errorf("syslog: %s transport not supported by the layer chain yet (udp only; tcp/tls deferred)", spec.Syslog.Transport)
		}
		return nil
	})
}
