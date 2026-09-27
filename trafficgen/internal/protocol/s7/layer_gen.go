package s7

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type S7Generator struct{}

func (g *S7Generator) Name() string { return "s7" }

func (g *S7Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("s7 generator: EmitMsg is nil")
	}
	cfg := req.Meta.S7
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）。与 Planner.Plan 的默认化一致——默认 read DB1 在下方补。
		cfg = &S7Config{Transport: "tcp"}
	}
	// count 型多会话（P0a 模式）：sessions=N 每会话一条独立 TCP 连接，源端口
	// = 顶层 src_port + i（legacy planner 的老语义），事件带上 SrcPort 供 tcp
	// 层判定会话边界（挥旧握新）。
	n := cfg.Sessions
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		var srcPort uint16
		if n > 1 {
			base := req.Meta.SrcPort
			if base == 0 {
				base = 12345
			}
			srcPort = base + uint16(i)
		}
		if err := emitSession(ctx, cfg, srcPort, req); err != nil {
			return err
		}
	}
	return nil
}

// emitSession emits one S7 session (connection setup + commands); srcPort is
// the session's TCP source port override (0 = default flow port).
func emitSession(ctx context.Context, cfg *S7Config, srcPort uint16, req *layers.GenRequest) error {
	emit := func(up bool, b []byte) error {
		return emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: b, SrcPort: srcPort})
	}
	// P0b-2：空配置默认化并产默认流——仅当 commands 字段**缺省**(nil)时注入默认
	// read DB1；显式 `commands: []` 表示 setup-only 会话（业务命令为空），不注入。
	if cfg.Commands == nil {
		copyCfg := *cfg
		copyCfg.Commands = []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}
		cfg = &copyCfg
	}
	// Normalize the session base so setup and the command counter agree: setup
	// is the first S7 PDU (ref = base), commands increment from base (§4.4.1).
	if cfg.PDURef == 0 {
		copyCfg := *cfg
		copyCfg.PDURef = sessionBaseRef(cfg)
		cfg = &copyCfg
	}
	cr, err := BuildConnectionRequest(cfg)
	if err != nil {
		return err
	}
	if err := emit(true, cr); err != nil {
		return err
	}
	cc := BuildConnectConfirm()
	if err := emit(false, cc); err != nil {
		return err
	}
	setup, err := BuildSetup(cfg, false)
	if err != nil {
		return err
	}
	if err := emit(true, setup); err != nil {
		return err
	}
	setupResponse, err := BuildSetup(cfg, true)
	if err != nil {
		return err
	}
	if err := emit(false, setupResponse); err != nil {
		return err
	}
	// PduRef is a per-session counter starting at the base (setup is the first
	// S7 PDU); each subsequent business command increments (§4.4.1).
	nextRef := sessionBaseRef(cfg)
	for _, cmd := range cfg.Commands {
		nextRef++
		msg, resp, respond, err := buildS7Pair(cfg, cmd, nextRef)
		if err != nil {
			return err
		}
		if msg != nil {
			if err := emit(true, msg); err != nil {
				return err
			}
		}
		if !respond {
			continue // keep-alive has no response
		}
		if err := emit(false, resp); err != nil {
			return err
		}
	}
	return nil
}

// sessionBaseRef returns the base PDU reference for the session (the setup
// request's own PduRef). Defaults to 2 when unset, matching the design's S3
// template (setup pduref 0x0002 → commands 0x0003, 0x0004, … per §4.4.1).
func sessionBaseRef(cfg *S7Config) uint16 {
	if cfg != nil && cfg.PDURef != 0 {
		return cfg.PDURef
	}
	return 2
}

// buildS7Pair returns the request and response bytes for one command, plus
// whether a response should be emitted. Keep-alive has no response. The caller
// supplies the command's PduRef (auto-incrementing per session).
func buildS7Pair(cfg *S7Config, cmd S7Command, ref uint16) (req, res []byte, respond bool, err error) {
	cmd.PDURef = ref
	switch cmd.Kind {
	case "", kindRead:
		req, err = BuildRead(cfg, cmd)
	case "write":
		req, err = BuildWrite(cfg, cmd)
	case "readsZL", "read_szl":
		req, err = BuildReadSZL(cfg, cmd)
	case "keepalive":
		req, err = BuildKeepalive(cfg)
		if err != nil {
			return nil, nil, false, err
		}
		return req, nil, false, nil
	case "error":
		// error command: no request, only the error Ack_Data response.
		res, err = BuildErrorAck(cfg, cmd)
		if err != nil {
			return nil, nil, false, err
		}
		return nil, res, true, nil
	default:
		// D-S7-85 §14 ②（G-S7-2）：未知 kind 拒绝——此前 default 分支静默当
		// read，拼错的配置产出合法 read 会话（假成功）。Planner.Validate
		// 先拦；此处是直调路径的背 door。
		return nil, nil, false, fmt.Errorf("s7: unknown kind %q", cmd.Kind)
	}
	if err != nil {
		return nil, nil, false, err
	}
	// response per kind
	res, err = buildS7Response(cfg, cmd)
	if err != nil {
		return nil, nil, false, err
	}
	return req, res, true, nil
}

// buildS7Response builds the matching Ack_Data/Userdata response for a command.
func buildS7Response(cfg *S7Config, cmd S7Command) ([]byte, error) {
	switch cmd.Kind {
	case "write":
		return BuildWriteAck(cfg, cmd)
	case "readsZL", "read_szl":
		return BuildReadSZLAck(cfg, cmd)
	case "", kindRead:
		return BuildReadAck(cfg, cmd)
	default:
		return nil, fmt.Errorf("s7: unknown kind %q", cmd.Kind)
	}
}

func emitS7Event(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}
func (g *S7Generator) GenEvents() layers.EventGenerator { return g }
func (g *S7Generator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("s7 generator: EmitEvent is not wired")
}

func init() {
	layers.RegisterLayerGenerator("s7", func() (layers.LayerGenerator, error) { return &S7Generator{}, nil })
	layers.RegisterLayerValidator("s7", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
