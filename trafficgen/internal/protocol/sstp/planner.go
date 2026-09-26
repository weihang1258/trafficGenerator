// Package sstp planner：负例校验（6 wire_fault 一行一注入——契约 §2/§11
// 逐字）+ 会话结构守卫（会话 ID/TLS session 独立、双权威形状拒、
// 未知 kind/属性、越序、跨连接引用）。每个被拒 spec 必须传播为 task
// error——绝不产出 completed/0-packet 假成功（契约 §11）。
//
// 处置表：6 负例三通道——
//   - 3 走 validateWireFault 注入拒（header_length/attribute_length/tls_boundary：
//     生成路径结构上恒自洽，注入是唯一通道——契约 §11 表逐行）；
//   - 2 走自然守卫（state：越序 CONNECTED/PPP；ppp_framing：压缩形/地址族
//     不匹配）；
//   - 1 走 validate_layers 预检拒（carrier：缺 TLS 载体/裸 TCP/UDP/错端口，
//     见 internal/core/layers/validate_layers.go 的 sstp 块）。
package sstp

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Planner is the layer-validator entry type (kerberos/bacnet/dtls 同款).
type Planner struct{}

// Validate checks an sstp flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec.SSTP) }

// ValidateSSTPSpec is the exported spec-level validator（契约 §17 接口签名；
// 与 Planner.Validate 同一实现）。
func ValidateSSTPSpec(spec core.FlowSpec) error { return validateSpec(spec.SSTP) }

// validateSpec: cfg == nil（bare {"sstp":{}} 层或缺键）通过：生成器发一条
// 最小 CALL CONNECT REQUEST 基线（bacnet/dtls/kerberos 空配置缺省家族同款
// ——裸层不静默 0 包）。
//
// 校验与生成同路径单权威：事务结构/状态机/属性/PPP 的守卫都住在 walkSession
// 与 builder，这里只做"能不能走完"的前置演练，不做第二套规则。
func validateSpec(cfg *core.SSTPConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 版本：唯一合法值 0x10（MAJOR 1 / MINOR 0）；指针缺席 = 缺省，显式
	// 他值（含 0）拒——契约 §12-1 单版本协议，他版本面走负例 #15。
	if cfg.Version != nil && *cfg.Version != versionByte {
		return fmt.Errorf("sstp: version %d is not supported — SSTP version 1.0 (Version byte 0x%02x) only (version)", *cfg.Version, versionByte)
	}
	// 两种会话形状并存且都非空 = 双权威（sessions[] 与 events[] 各写一半），拒。
	if len(cfg.Sessions) > 0 && len(cfg.Events) > 0 {
		return fmt.Errorf("sstp: both sessions[] and events[] are declared — pick one session shape (sessions[] for multi-connection, events[] for a single connection) (presence)")
	}
	seenID := map[string]bool{}
	seenTLS := map[string]bool{}
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		// 会话 ID / TLS session 不得跨连接复用（契约 §6："连接 ID、transaction
		// 状态和属性不能跨 TLS connection 复用"）。
		if sess.ID != "" {
			if seenID[sess.ID] {
				return fmt.Errorf("sstp: sessions[%d] id %q duplicates an earlier session — connection ids are not reusable across TLS connections (state)", si, sess.ID)
			}
			seenID[sess.ID] = true
		}
		if sess.TLSSession != "" {
			if seenTLS[sess.TLSSession] {
				return fmt.Errorf("sstp: sessions[%d] tls_session %q duplicates an earlier session — each SSTP connection owns an independent TLS session (state)", si, sess.TLSSession)
			}
			seenTLS[sess.TLSSession] = true
		}
		// 空会话 = 空流（P0b 空配置默认流红线），拒而不是产 0 包。
		if len(sess.Transactions) == 0 {
			return fmt.Errorf("sstp: sessions[%d] declares no transactions — an SSTP connection starts with CALL CONNECT REQUEST (state)", si)
		}
		if _, _, err := walkSession(sess, si); err != nil {
			return err
		}
	}
	// events[] 单会话短形同路径演练（会话序与 sessions[] 等价）。
	if len(cfg.Sessions) == 0 && len(cfg.Events) > 0 {
		sess := core.SSTPSession{ID: "s1", Transactions: cfg.Events}
		if _, _, err := walkSession(&sess, 0); err != nil {
			return err
		}
	}
	return nil
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；core.DescribeSSTPWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeSSTPWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("sstp: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}

// resolveCarrier 守 sstp 的直接外层是 tls（DependsOn 自动补全之外的第二道
// 防线：out-of-band 组链/直调生成器同样不能绕过——kerberos resolveCarrier
// 同款纪律）。生成期错误不得被吞成空流。
func resolveCarrier(chain []layers.Layer) error {
	for i, l := range chain {
		if l.Name != "sstp" {
			continue
		}
		if i == 0 {
			return fmt.Errorf("sstp: no carrier layer before sstp in chain — SSTP rides TLS application data on TCP/443 (tls)")
		}
		if chain[i-1].Name != "tls" {
			return fmt.Errorf("sstp: carrier layer %q is not tls — SSTP rides TLS application data on TCP/443 only (tls)", chain[i-1].Name)
		}
		return nil
	}
	return fmt.Errorf("sstp: no sstp layer in chain (tls)")
}

// init registers the generator + validator（kerberos 同款接线）。
func init() {
	layers.RegisterLayerGenerator("sstp", func() (layers.LayerGenerator, error) { return &SSTPGenerator{}, nil })
	layers.RegisterLayerValidator("sstp", func(spec *core.FlowSpec) error { return validateSpec(spec.SSTP) })
}
