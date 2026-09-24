// Package kerberos planner：负例校验（6 wire_fault 一行一注入——设计 §10 与
// 用例 §4/§5 三方同序）+ 会话状态守卫（tag↔msg-type 一致性裁定6、krb_error
// 必带 error_code、dst_port 会话间一致）。每个被拒 spec 必须传播为 task
// error——绝不产出 completed/0-packet 假成功。
//
// 处置表：6 负例三通道——3 走 validateWireFault 注入拒（record_truncated/
// tcp_length/encrypted_boundary：生成路径结构上恒自洽，注入是唯一通道）；
// 2 走自然非法配置（message_tag：声明 msg_type≠kind 派生值经 tag 守卫拒；
// time_nonce_replay：skew/nonce 状态声明面经守卫拒）；1 走 validate_layers
// 预检拒（carrier：缺载体/双载体并存，dcerpc+dtls 预检同构）。
package kerberos

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type (coap/bacnet/dtls 同款).
type Planner struct{}

// Validate checks a kerberos flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"kerberos":{}} 层或缺键）通过：生成器
// 发一条最小 AS-REQ 基线（bacnet/dtls 空配置缺省家族同款——裸层不静默
// 0 包；会话事件面由 sessions[] 显式声明）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.Kerberos
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 会话间 dst_port 一致性（bacnet/dtls 同款守卫）。
	dst := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if dst != 0 && dst != p {
				return fmt.Errorf("kerberos: sessions[%d] dst_port %d conflicts with earlier session dst_port %d (port)", i, p, dst)
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

// validateSession walks one session's events: 结构守卫 + 值域（与
// buildMessage 同一权威——校验即生成前置演练，不做第二套规则）。
func validateSession(sess *core.KerberosSession, si int) error {
	for ei := range sess.Events {
		if _, err := buildMessage(&sess.Events[ei]); err != nil {
			return fmt.Errorf("kerberos: sessions[%d].events[%d]: %v", si, ei, err)
		}
	}
	return nil
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；DescribeKerberosWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeKerberosWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("kerberos: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
