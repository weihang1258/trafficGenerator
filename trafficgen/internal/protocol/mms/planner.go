package mms

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "mms" }
func (Planner) Validate(spec core.FlowSpec) error {
	if spec.MMS == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （association + read）。允许 nil。
		return nil
	}
	if spec.MMS.Transport != "" && spec.MMS.Transport != "tcp" {
		return fmt.Errorf("mms: transport %q invalid; MMS requires tcp", spec.MMS.Transport)
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("mms: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("mms: invalid destination IP")
	}
	for _, o := range spec.MMS.Objects {
		if len(o.Name) == 0 || len([]byte(o.Name)) > 32 {
			return fmt.Errorf("mms: object name %q exceeds 32 bytes or is empty", o.Name)
		}
		if o.Domain != "" && len([]byte(o.Domain)) > 32 {
			return fmt.Errorf("mms: domain exceeds 32 bytes")
		}
		if !validType(o.Datatype) {
			return fmt.Errorf("mms: datatype %q invalid", o.Datatype)
		}
		if len(o.Members) > 0 {
			// §2.3 同类死配置：members 无任何编码路径读取（builder 零命中），
			// 且其唯一有意义的载体类型 structure 已在 G-MMS-3 拒收——配上
			// 不生效，判死并指路。
			return fmt.Errorf("mms: object %q members is not supported (the builder never reads it; emit one object per value instead)", o.Name)
		}
	}
	if s := spec.MMS.Sequence; s != nil {
		// 契约 §4.2 行「sequence 负值」的锚词保留（负值仍是独立的拒绝面）。
		if s.Loop < 0 || s.StepGap < 0 || s.InjectOn < 0 {
			return fmt.Errorf("mms: sequence values cannot be negative")
		}
		// G-MMS-2（契约 §2.3）：loop/stepGap/injectOn 在 layer_gen 零消费——
		// 正值配上不生效即死配置，拒收（接线方案会改线上帧序，无契约要求）。
		if s.Loop != 0 {
			return fmt.Errorf("mms: sequence.loop is not supported (the field has no effect; remove it)")
		}
		if s.StepGap != 0 {
			return fmt.Errorf("mms: sequence.stepGap is not supported (the field has no effect; remove it)")
		}
		if s.InjectOn != 0 {
			return fmt.Errorf("mms: sequence.injectOn is not supported (the field has no effect; drive reports with steps=[\"report\"] + enableInformationReport)")
		}
		for _, step := range s.Steps {
			if !validStep(step) {
				return fmt.Errorf("mms: sequence step %q invalid", step)
			}
		}
	}
	if spec.MMS.ErrorClassName != "" && spec.MMS.ErrorClassName != "definition" && spec.MMS.ErrorClassName != "service" && spec.MMS.ErrorClassName != "access" {
		return fmt.Errorf("mms: error class %q invalid", spec.MMS.ErrorClassName)
	}
	// multiSession 子会话（契约 §2.2）：每项只覆盖 objects，其余键继承主配置
	// （layer_gen.go:40-45 实证）。objects 走**同一条编码路径**，故同一套门
	// 必须覆盖——否则主配置拒掉的错编码 datatype / 超长名配在子会话里照旧
	// 落线（G-MMS-3 第二入口）；objects 之外的键则读都不读，属死配置，按
	// §2.3 判死并点名（layer_gen 显式 `sess.MultiSession = nil` 丢弃嵌套）。
	for i := range spec.MMS.MultiSession {
		sub := &spec.MMS.MultiSession[i]
		where := fmt.Sprintf("multiSession[%d]", i)
		for _, o := range sub.Objects {
			if len(o.Name) == 0 || len([]byte(o.Name)) > 32 {
				return fmt.Errorf("mms: %s object name %q exceeds 32 bytes or is empty", where, o.Name)
			}
			if o.Domain != "" && len([]byte(o.Domain)) > 32 {
				return fmt.Errorf("mms: %s domain exceeds 32 bytes", where)
			}
			if !validType(o.Datatype) {
				return fmt.Errorf("mms: %s datatype %q invalid", where, o.Datatype)
			}
			if len(o.Members) > 0 {
				return fmt.Errorf("mms: %s object %q members is not supported (the builder never reads it; emit one object per value instead)", where, o.Name)
			}
		}
		for _, k := range deadMultiSessionKeys(sub) {
			return fmt.Errorf("mms: %s.%s is not supported (a sub-session overrides objects only; every other key is inherited from the main config and this one is never read; remove it)", where, k)
		}
	}
	return nil
}

// deadMultiSessionKeys reports which sub-session keys the generator never
// reads (everything but Objects) — see the multiSession block in Validate.
func deadMultiSessionKeys(sub *core.MMSConfig) []string {
	var out []string
	if sub.Transport != "" {
		out = append(out, "transport")
	}
	if sub.Association != nil {
		out = append(out, "association")
	}
	if sub.IEDName != "" {
		out = append(out, "iedName")
	}
	if sub.EnableRead {
		out = append(out, "enableRead")
	}
	if sub.EnableWrite {
		out = append(out, "enableWrite")
	}
	if sub.EnableInformationReport {
		out = append(out, "enableInformationReport")
	}
	if sub.EnableGetNameList {
		out = append(out, "enableGetNameList")
	}
	if sub.EnableIdentify {
		out = append(out, "enableIdentify")
	}
	if sub.Sequence != nil {
		out = append(out, "sequence")
	}
	if len(sub.MultiSession) > 0 {
		out = append(out, "multiSession")
	}
	if sub.ErrorClassName != "" {
		out = append(out, "errorClassName")
	}
	if sub.ErrorValue != 0 {
		out = append(out, "errorValue")
	}
	return out
}

// validType gates the datatypes the builder encodes for real. float /
// binaryTime / structure fell through dataValue's default branch and emitted
// ber(0x80, nil) — bytes that contradict the declared type (G-MMS-3), so the
// validator rejects them rather than letting a mis-encoded value reach the
// wire. "" stays accepted (unchanged): its wire semantics are undetermined in
// the contract, and this batch only closes the mis-encoding face.
func validType(s string) bool {
	switch s {
	case "", "boolean", "integer", "unsigned", "octetString", "visibleString", "utcTime":
		return true
	}
	return false
}
func validStep(s string) bool {
	switch s {
	case "read", "write", "getnmlist", "identify", "report":
		return true
	}
	return false
}
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 102
	}
	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{FlowID: "mms", PacketIndex: idx, Direction: dir, L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload, Timestamp: time.Now()}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		cfg := spec.MMS
		if cfg == nil {
			// P0b-2：空配置默认化（Generate 同款：association-only，设计 §6.1
			// connect_establish 7 帧，不默认 read）。
			cfg = &core.MMSConfig{}
		}
		a := cfg.Association
		no := a != nil && a.NoAssociate
		if !no {
			cr, _ := BuildCR()
			if !emit(true, cr, 0x18) {
				return
			}
			cc, _ := BuildCC()
			if !emit(false, cc, 0x18) {
				return
			}
			req, _ := BuildAssociate(cfg, false)
			if !emit(true, req, 0x18) {
				return
			}
			resp, _ := BuildAssociate(cfg, true)
			if !emit(false, resp, 0x18) {
				return
			}
		}
		steps := []string{"read"}
		if cfg.Sequence != nil && len(cfg.Sequence.Steps) > 0 {
			steps = cfg.Sequence.Steps
		}
		invoke := byte(1)
		for _, step := range steps {
			if step == "read" && cfg.EnableRead || step == "write" && cfg.EnableWrite || step == "report" && cfg.EnableInformationReport || step == "getnmlist" && cfg.EnableGetNameList || step == "identify" && cfg.EnableIdentify {
				var req, resp []byte
				var err error
				switch step {
				case "read":
					req, err = BuildReadRequest(cfg, invoke)
					if err == nil {
						if cfg.ErrorClassName != "" {
							resp, err = BuildServiceError(cfg, invoke)
						} else {
							resp, err = BuildReadResponse(cfg, invoke)
						}
					}
				case "write":
					req, err = BuildWriteRequest(cfg, invoke)
					if err == nil {
						if cfg.ErrorClassName != "" {
							resp, err = BuildServiceError(cfg, invoke)
						} else {
							resp, err = BuildWriteResponse(cfg, invoke)
						}
					}
				case "getnmlist":
					req, err = BuildGetNameListRequest(invoke)
					if err == nil {
						resp, err = BuildGetNameListResponse(cfg, invoke)
					}
				case "identify":
					req, err = BuildIdentifyRequest(invoke)
					if err == nil {
						resp, err = BuildIdentifyResponse(cfg, invoke)
					}
				case "report":
					req, err = BuildInformationReport(cfg)
				}
				if err != nil {
					return
				}
				reqPkt, err := cotpDT(req)
				if err != nil || !emit(step != "report", reqPkt, 0x18) {
					return
				}
				if step != "report" {
					respPkt, err := cotpDT(resp)
					if err != nil || !emit(false, respPkt, 0x18) {
						return
					}
				}
				invoke++
			}
		}

		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
