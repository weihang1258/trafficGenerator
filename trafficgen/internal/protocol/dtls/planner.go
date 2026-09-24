// Package dtls planner：负例校验（6 wire_fault 一行一注入——设计 §10 与
// 用例 §4/§5 三方同序）+ 会话状态守卫（epoch/sequence 单调、cookie 仅限
// HVR、分片越界）+ 值域走查。每个被拒 spec 必须传播为 task error——绝不
// 产出 completed/0-packet 或只剩 UDP 外壳的假成功。
//
// 处置表：6 负例中 5 走 validateWireFault 注入拒（record_length/
// version_epoch/sequence_overflow/fragment_bounds/cookie_state——生成路径
// 结构上恒自洽，注入是唯一通道）；carrier_udp 注入拒 + 自然面预检双通道
// （transport-dup/缺 udp/混合地址族在 ValidateLayers 预检拦，bacnet 同构）。
// 自然守卫（不占负例号，链级红例覆盖）：epoch 回退、seq 回退/复用、
// cookie 非 HVR、kind 未知、版本非法——walker 与 handshakeBody 单权威。
package dtls

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type (coap/bacnet 同款：层校验器经
// (&Planner{}).Validate 调用).
type Planner struct{}

// Validate checks a dtls flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"dtls":{}} 层或缺键）通过：生成器发一条
// 最小 ClientHello 基线 datagram。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.DTLS
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 会话间 dst_port 一致性（bacnet/edp/xmrmining 同款守卫）。
	dst := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if dst != 0 && dst != p {
				return fmt.Errorf("dtls: sessions[%d] dst_port %d conflicts with earlier session dst_port %d (port)", i, p, dst)
			}
			dst = p
		}
	}
	for si := range cfg.Sessions {
		if err := validateSession(&cfg.Sessions[si], si); err != nil {
			return err
		}
	}
	return nil
}

// validateSession walks one session's events: walker 状态守卫 + 值域。
// 与 BuildFrames 同一条 renderEvent 路径（单解析权威——校验即生成前置
// 演练，不做第二套规则）。
func validateSession(sess *core.DTLSSession, si int) error {
	prefix := fmt.Sprintf("dtls: sessions[%d]", si)
	if _, err := versionBytes(sess.Version); err != nil {
		return fmt.Errorf("%s: %v", prefix, err)
	}
	w := newWalker()
	for ei := range sess.Events {
		ev := &sess.Events[ei]
		// 版本合并语义与 renderEvent 同源：事件声明 > 会话缺省 > "1.2"。
		effVersion := ev.Version
		if effVersion == "" {
			effVersion = sess.Version
		}
		if _, err := versionBytes(effVersion); err != nil {
			return fmt.Errorf("%s.events[%d]: %v", prefix, ei, err)
		}
		if ev.Kind == "handshake" && ev.Handshake == nil {
			return fmt.Errorf("%s.events[%d] (%s): handshake event requires a handshake object (handshake)", prefix, ei, ev.Kind)
		}
		if _, _, err := w.nextRecord(fmt.Sprintf("%s.events[%d] (%s)", prefix, ei, ev.Kind), ev); err != nil {
			return err
		}
		msgSeq := 0
		if ev.Kind == "handshake" {
			dir := 0
			if ev.Up {
				dir = 1
			}
			msgSeq = w.nextMsgSeq(dir, ev.Handshake)
		}
		if _, err := eventPayload(ev, msgSeq); err != nil {
			return fmt.Errorf("%s.events[%d]: %v", prefix, ei, err)
		}
	}
	return nil
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；DescribeDTLSWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeDTLSWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("dtls: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
