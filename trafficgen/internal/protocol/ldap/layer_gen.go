// Package ldap: layer-chain wiring (D-LDAP-1 裁定1/裁定2). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：自建 TCP
// 握手/MSS 分段/BER 消息面/挥手全套复用，零分叉) and re-emits each packet
// through the raw-IP drive branch.
//
// 方向处理（防双换，pppoe/srv6 同款）：legacy Plan 对方向已在包内部完成
// MAC/IP/端口换向并置 Direction="down"；raw-IP drive 的 Emit 包装对
// "down" 包会再换一次 L3 地址（nvgre/igmp 契约：生成器产 up 向包）。本
// 生成器统一把每包 Direction 改写为 "up" 后转 Emit——L3/L4 保持 legacy
// 换向结果，L2 MAC/EtherType 保持 legacy 写入值（非空，drive 的回填跳过），
// 语义与 legacy 扁平路径逐字节一致。目的端口 389 由 legacy Plan 缺省
// （spec.DstPort==0 → DefaultPort），链路径无端口位自洽。
package ldap

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// LDAPGenerator is the ldap raw-IP terminal-layer generator (D-LDAP-1).
type LDAPGenerator struct{}

func (g *LDAPGenerator) Name() string                     { return "ldap" }
func (g *LDAPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured LDAP session via req.Emit (raw-IP chain).
func (g *LDAPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("ldap generator: Emit is nil")
	}
	cfg := req.Meta.LDAP
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.LDAPConfig{}
	}
	spec := core.FlowSpec{
		LDAP:      cfg,
		SrcIP:     req.Meta.SrcIP,
		DstIP:     req.Meta.DstIP,
		SrcMAC:    req.Meta.SrcMAC,
		DstMAC:    req.Meta.DstMAC,
		SrcPort:   req.Meta.SrcPort,
		DstPort:   req.Meta.DstPort,
		TTL:       req.Meta.TTL,
		Payload:   req.Meta.Payload,
		FlowIndex: req.Meta.FlowIndex,
	}
	ch, err := NewPlanner().Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		pkt.Direction = "up" // 防 raw-IP drive 二次换向（见包注释）
		if err := req.Emit(pkt); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("ldap", func() (layers.LayerGenerator, error) {
		return &LDAPGenerator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（pppoe 决策 G
	// 同款：不注册则 7 锚全漏）。
	layers.RegisterLayerValidator("ldap", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
