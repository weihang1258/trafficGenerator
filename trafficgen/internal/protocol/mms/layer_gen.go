package mms

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type MMSGenerator struct{}

func (*MMSGenerator) Name() string                     { return "mms" }
func (*MMSGenerator) GenEvents() layers.EventGenerator { return &MMSGenerator{} }
func (*MMSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("mms generator: EmitEvent is not wired")
}
func (g *MMSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("mms generator: EmitMsg is nil")
	}
	if req.Meta.MMS == nil {
		// P0b-2：空配置默认化并产默认流。与设计 §6.1 一致：默认是
		// association-only（CR/CC + 关联对，7 包），不默认 read——
		// mms_connect_establish case 断言 7 包。
		req.Meta.MMS = &core.MMSConfig{}
	}
	cfg := req.Meta.MMS
	// 多会话（镜像 drda，但 mms 是**并发**会话语义）：会话 0 = 主配置（默认
	// 流端口），MultiSession[i] = 会话 1+i（SrcPort 40000+i 覆盖）。tcp 层
	// 并发会话模式下按事件端口维护独立连接（首次见端口→握手，切回→恢复，
	// 无挥手——mms 链 termination=false）。交错顺序与 case 断言一致：
	// CR_A CR_B CC_A CC_B DT1_A DT1_B DT2_A DT2_B svcA req/resp svcB req/resp。
	if len(cfg.MultiSession) > 0 {
		sessions := make([]*core.MMSConfig, len(cfg.MultiSession)+1)
		sessions[0] = cfg
		for i := 0; i < len(cfg.MultiSession); i++ {
			// 会话继承主配置的 association/service 设置，仅覆盖对象列表
			// （case 语义：multiSession 条目只写 objects）。
			sess := *cfg
			over := cfg.MultiSession[i]
			if len(over.Objects) > 0 {
				sess.Objects = over.Objects
			}
			sess.MultiSession = nil
			sessions[i+1] = &sess
		}
		// 会话 0 用默认流端口（尊重 spec.SrcPort），会话 i+1 = 40000+i。
		port := func(i int) uint16 {
			if i == 0 {
				return 0
			}
			return uint16(40000 + i)
		}
		// 阶段 1a：所有会话发 CR（新端口触发 tcp 层握手，交错出 hsB 在
		// CR_A 与 CR_B 之间——case 断言 4=CR_A、8=CR_B）。
		for i := 0; i < len(sessions); i++ {
			cr, err := BuildCR()
			if err != nil {
				return err
			}
			if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: cr}, port(i)); err != nil {
				return err
			}
		}
		// 阶段 1b：所有会话发 CC。
		for i := 0; i < len(sessions); i++ {
			cc, err := BuildCC()
			if err != nil {
				return err
			}
			if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: cc}, port(i)); err != nil {
				return err
			}
		}
		// 阶段 2：所有会话发关联请求 DT1，再所有会话发关联响应 DT2。
		for i := 0; i < len(sessions); i++ {
			b, err := BuildAssociate(sessions[i], false)
			if err != nil {
				return err
			}
			if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: b}, port(i)); err != nil {
				return err
			}
		}
		for i := 0; i < len(sessions); i++ {
			b, err := BuildAssociate(sessions[i], true)
			if err != nil {
				return err
			}
			if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: b}, port(i)); err != nil {
				return err
			}
		}
		// 阶段 3：服务交换按会话串行（A 完整 req/resp 后 B）。
		for i := 0; i < len(sessions); i++ {
			if err := emitServices(ctx, req, sessions[i], port(i)); err != nil {
				return err
			}
		}
		return nil
	}
	return emitFull(ctx, req, cfg, 0)
}

// emitCRCC emits one session's COTP CR (up) and CC (down).
func emitCRCC(ctx context.Context, req *layers.GenRequest, cfg *core.MMSConfig, srcPort uint16) error {
	cr, err := BuildCR()
	if err != nil {
		return err
	}
	if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: cr}, srcPort); err != nil {
		return err
	}
	cc, err := BuildCC()
	if err != nil {
		return err
	}
	return emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: cc}, srcPort)
}

// emitAssociate emits one session's ACSE association pair: DT1 (request,
// up) and DT2 (response, down).
func emitAssociate(ctx context.Context, req *layers.GenRequest, cfg *core.MMSConfig, srcPort uint16) error {
	b, err := BuildAssociate(cfg, false)
	if err != nil {
		return err
	}
	if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: b}, srcPort); err != nil {
		return err
	}
	b, err = BuildAssociate(cfg, true)
	if err != nil {
		return err
	}
	return emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: b}, srcPort)
}

// emitServices emits the configured service exchanges (request up, response
// down; report down only) for one session.
func emitServices(ctx context.Context, req *layers.GenRequest, cfg *core.MMSConfig, srcPort uint16) error {
	steps := []string{"read"}
	if cfg.Sequence != nil && len(cfg.Sequence.Steps) > 0 {
		steps = cfg.Sequence.Steps
	}
	invoke := byte(1)
	var err error
	for _, step := range steps {
		if !serviceEnabled(cfg, step) {
			continue
		}
		var request, response []byte
		switch step {
		case "read":
			request, err = BuildReadRequest(cfg, invoke)
			if err == nil {
				if cfg.ErrorClassName != "" {
					response, err = BuildServiceError(cfg, invoke)
				} else {
					response, err = BuildReadResponse(cfg, invoke)
				}
			}
		case "write":
			request, err = BuildWriteRequest(cfg, invoke)
			if err == nil {
				if cfg.ErrorClassName != "" {
					response, err = BuildServiceError(cfg, invoke)
				} else {
					response, err = BuildWriteResponse(cfg, invoke)
				}
			}
		case "getnmlist":
			request, err = BuildGetNameListRequest(invoke)
			if err == nil {
				response, err = BuildGetNameListResponse(cfg, invoke)
			}
		case "identify":
			request, err = BuildIdentifyRequest(invoke)
			if err == nil {
				response, err = BuildIdentifyResponse(cfg, invoke)
			}
		case "report":
			request, err = BuildInformationReport(cfg)
		}
		if err != nil {
			return err
		}
		if step == "report" {
			wrapped, err := cotpDT(request)
			if err != nil {
				return err
			}
			if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: wrapped}, srcPort); err != nil {
				return err
			}
			continue
		}
		wrappedReq, err := cotpDT(request)
		if err != nil {
			return err
		}
		if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: wrappedReq}, srcPort); err != nil {
			return err
		}
		wrappedResp, err := cotpDT(response)
		if err != nil {
			return err
		}
		if err := emitS(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: wrappedResp}, srcPort); err != nil {
			return err
		}
		invoke++
	}
	return nil
}

// emitFull emits one complete MMS session (CR/CC + association pair +
// services) with the session SrcPort override (0 = default flow port).
func emitFull(ctx context.Context, req *layers.GenRequest, cfg *core.MMSConfig, srcPort uint16) error {
	if cfg.Association != nil && cfg.Association.NoAssociate {
		return emitServices(ctx, req, cfg, srcPort)
	}
	if err := emitCRCC(ctx, req, cfg, srcPort); err != nil {
		return err
	}
	if err := emitAssociate(ctx, req, cfg, srcPort); err != nil {
		return err
	}
	return emitServices(ctx, req, cfg, srcPort)
}

func serviceEnabled(cfg *core.MMSConfig, step string) bool {
	switch step {
	case "read":
		return cfg.EnableRead
	case "write":
		return cfg.EnableWrite
	case "getnmlist":
		return cfg.EnableGetNameList
	case "identify":
		return cfg.EnableIdentify
	case "report":
		return cfg.EnableInformationReport
	default:
		return false
	}
}
func emit(ctx context.Context, fn func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fn(ev)
	}
}

// emitS is emit with a per-session SrcPort override (0 = default flow port).
func emitS(ctx context.Context, fn func(layers.MessageEvent) error, ev layers.MessageEvent, srcPort uint16) error {
	if srcPort != 0 {
		ev.SrcPort = srcPort
	}
	return emit(ctx, fn, ev)
}
func init() {
	layers.RegisterLayerGenerator("mms", func() (layers.LayerGenerator, error) { return &MMSGenerator{}, nil })
	layers.RegisterLayerValidator("mms", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
