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
	// 每条 layer chain 只产一个流（一个 src_port）；多会话各自独立四元组需要
	// 框架 SubFlow 机制（T3 课题）。比照着 mongodb/mqtt/nfs/modbus 显式拒绝，
	// 而非静默只发 session[0] 的错包。
	if cfg.Sessions > 1 {
		return fmt.Errorf("s7 generator: sessions (%d) multi-stream expansion is not supported on a layer chain (one flow per chain)", cfg.Sessions)
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
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: cr}); err != nil {
		return err
	}
	cc := BuildConnectConfirm()
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: cc}); err != nil {
		return err
	}
	setup, err := BuildSetup(cfg, false)
	if err != nil {
		return err
	}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: setup}); err != nil {
		return err
	}
	setupResponse, err := BuildSetup(cfg, true)
	if err != nil {
		return err
	}
	if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: setupResponse}); err != nil {
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
			if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: msg}); err != nil {
				return err
			}
		}
		if !respond {
			continue // keep-alive has no response
		}
		if err := emitS7Event(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: resp}); err != nil {
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
	default: // read
		req, err = BuildRead(cfg, cmd)
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
	default:
		return BuildReadAck(cfg, cmd)
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
