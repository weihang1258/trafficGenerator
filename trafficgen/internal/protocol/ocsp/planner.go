// Package ocsp planner：负例校验（6 wire_fault 一行一注入——契约 §2 与用例
// §4/§7 三方同序）+ 自然面守卫（算法↔hash 长度绑定 / requestList 批量项
// 匹配 / nonce 长度 / 签名算法名 / 状态与 profile 值域）。每个被拒 spec
// 必须传播为 task error——绝不产出 completed/0-packet 假成功（契约 §7）。
//
// 处置表：6 负例两通道——1 走 validateWireFault 注入拒（der_truncated：
// 生成路径结构上恒自洽，注入是唯一通道）；4 走自然非法配置（certid_hash：
// 算法↔hash 长度绑定；request_response：request_count 与 request.certs
// 批量项数冲突；nonce：nonce 长度越界；signature：未知签名算法名）；
// 1 走 validate_layers 预检拒（carrier：profile↔http 层有无不一致——
// dcerpc/dtls/kerberos 预检同构）。
package ocsp

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type (kerberos/dtls 同款).
type Planner struct{}

// Validate checks an ocsp flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"ocsp":{}} 层或缺键）通过：生成器发一条
// 基线 request/response（bacnet/dtls/kerberos 空配置缺省家族同款——裸层
// 不静默 0 包；会话/事务面由 sessions[] 显式声明）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.OCSP
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 会话间 dst_port 一致性（bacnet/dtls/kerberos 同款守卫）：同一条 ocsp
	// 流的会话共享链级目标端口，会话级覆盖必须一致。
	dst := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if dst != 0 && dst != p {
				return fmt.Errorf("ocsp: sessions[%d] dst_port %d conflicts with earlier session dst_port %d (port)", i, p, dst)
			}
			dst = p
		}
	}
	// 逐会话逐事务走查（校验即生成前置演练；hasHTTP 面由 validate_layers
	// 预检承担——本函数只看 spec 内部自洽）。
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		for ti := range sess.Transactions {
			if _, err := resolvePlan(cfg, true, sess, si, ti); err != nil {
				return err
			}
		}
	}
	if len(cfg.Sessions) == 0 {
		// 基线面演练（空配置缺省事务同样必须可渲染）。
		base := &core.OCSPSession{ID: "baseline", Transactions: []core.OCSPTransaction{{ID: "t1"}}}
		if _, err := resolvePlan(cfg, true, base, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；DescribeOCSPWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeOCSPWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("ocsp: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
