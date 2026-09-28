package iec104

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "iec104" }
func (Planner) Validate(spec core.FlowSpec) error {
	if spec.IEC104 == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。
		return nil
	}
	if spec.IEC104.Transport != "" && spec.IEC104.Transport != transportTCP {
		return fmt.Errorf("iec104: transport %q is invalid", spec.IEC104.Transport)
	}
	// 端口契约（设计 §1 不变式 1 / testcase §1）：IEC104 恒 TCP 2404，层内
	// 显式写非 2404 即拒（drda 446 / enip 44818 同款）。链路径的层值经
	// validateSpecBase 的 enip/dameng/cflow/drda 前置回填块写进 spec.DstPort
	// 后到达本校验器；0 = 未写，由 FieldContract 补齐 2404。
	if spec.DstPort != 0 && spec.DstPort != dstPortIEC104 {
		return fmt.Errorf("iec104: dst_port must be %d (IEC 60870-5-104 rides TCP %d only)", dstPortIEC104, dstPortIEC104)
	}
	cfg := spec.IEC104
	if cfg.TypeID != 0 && !validType(cfg.TypeID) {
		return fmt.Errorf("iec104: invalid type %d", cfg.TypeID)
	}
	if cfg.Cause > 63 || (cfg.TypeID != 0 && cfg.Cause == 0) {
		return fmt.Errorf("iec104: invalid cause %d", cfg.Cause)
	}
	for _, event := range cfg.Events {
		if event.Kind != "startdt_act" && event.Kind != "startdt_con" && event.Kind != "stopdt_act" && event.Kind != "stopdt_con" && event.Kind != "testfr_act" && event.Kind != "testfr_con" && event.Kind != "s" && event.Kind != "i" {
			return fmt.Errorf("iec104: invalid control event kind %q", event.Kind)
		}
		if event.Kind == "i" {
			if !validType(event.TypeID) {
				return fmt.Errorf("iec104: unknown type_id %d", event.TypeID)
			}
			if event.Cause == 0 || event.Cause > 63 {
				return fmt.Errorf("iec104: invalid cause %d", event.Cause)
			}
			if event.IOA > 0xffffff {
				return fmt.Errorf("iec104: IOA %d exceeds 24-bit range", event.IOA)
			}
			// G-IEC104-8：信息体是 16-bit（NVA 2B；SCO/DCO 取低 8 位），
			// builder 走 `uint16(cfg.Value)` 截断——负值回绕、>65535 丢高位，
			// 静默产出看似合法的字节。Validate 显式拒收（负例走 task error，
			// 零假成功）。
			if event.Value < 0 || event.Value > 0xffff {
				return fmt.Errorf("iec104: value %d out of range [0,65535]", event.Value)
			}
		}
	}
	if cfg.MaxAPDULength > 0 && cfg.MaxAPDULength > maxAPDULength {
		return fmt.Errorf("iec104: APDU too long: max %d", cfg.MaxAPDULength)
	}
	// G-IEC104-8 同面：顶层单对象快捷键 value 与事件内同域（同 builder 截断）。
	if cfg.Value < 0 || cfg.Value > 0xffff {
		return fmt.Errorf("iec104: value %d out of range [0,65535]", cfg.Value)
	}
	for _, c := range cfg.Commands {
		if !validType(c.TypeID) {
			return fmt.Errorf("iec104: invalid type %d", c.TypeID)
		}
		if c.Cause == 0 || c.Cause > 63 {
			return fmt.Errorf("iec104: invalid cause %d", c.Cause)
		}
		if c.Value < 0 || c.Value > 0xffff {
			return fmt.Errorf("iec104: value %d out of range [0,65535]", c.Value)
		}
	}
	return nil
}
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.IEC104
	if cfg == nil {
		cfg = &IEC104Config{}
	}
	if len(cfg.Commands) == 0 {
		c := *cfg
		if c.TypeID == 0 {
			c.TypeID = TypeMSpNa
		}
		if c.Cause == 0 {
			c.Cause = 3
		}
		cfg = &c
	}
	out := make(chan core.PacketConfig, 16)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
			}
			select {
			case out <- core.PacketConfig{FlowID: "iec104", PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		u, _ := BuildUFrame(UStartDTAct)
		if !emit(true, u, 0x18) {
			return
		}
		u, _ = BuildUFrame(UStartDTCon)
		if !emit(false, u, 0x18) {
			return
		}
		for _, c := range cfg.Commands {
			cc := c
			b, _ := BuildInformation(&IEC104Config{TypeID: cc.TypeID, Cause: cc.Cause, CommonAddress: cc.CommonAddress, InformationObjectAddress: cc.InformationObjectAddress, Value: cc.Value}, 0, 0)
			if !emit(true, b, 0x18) || !emit(false, b, 0x18) {
				return
			}
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
