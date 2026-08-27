package rdp

// RDPGenerator is the rdp terminal-layer generator (rdp 终结层层生成器, P3)。
// RDP (MS-RDPBCGR)——一次 flow = 一个 4-tuple 上的一条 TCP 连接 + 一个 RDP
// 会话：X.224 CR/CC + Negotiation → [TLS 握手占位] → MCS Connect-Initial/
// Response → MCS Erect-Domain → Attach-User Request/Confirm → Channel-Join ×N
// → Security Exchange → Client Info → License → Capability Exchange →
// DataEvents/ServerResponses → Shutdown + Disconnect。每条 PDU 一个"报文事件"
//（方向 + 完整 X.224 TPKT 字节），构建字节由 encodeTPKT/encodeX224DT/
// encodeMCS*/encodeSecurityExchange/encodeClientInfoPDU/encodeDemandActivePDU
// 等纯函数产出（复用，不重写）。事件模式（mqtt/grpc/ssh 同款）：TCP 语义
// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go Plan）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包 SYN/SYN-ACK/ACK，planner.go:534-538）与
//     挥手（4 包 FIN-ACK/ACK/FIN-ACK/ACK，planner.go:778-781）——事件模式
//     不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层 schema
//     默认 true 执行，validator 强制校准 true（legacy rdp.go 恒产握手/挥手，
//     从不读 spec.TCP.Handshake/Termination，语义一致）。
//   - TLS 模式（SecurityLayer=tls/nla/nla_ex）链上不支持：legacy 产 TLS
//     握手占位 + tlsActive 后 wrapTLSAppData 包裹每个 PDU；链上 tcp 层无
//     等价 TLS 包裹。validator 显式拒绝 TLS 模式（tls 链版本/角色同款先例，
//     layer_gen.go 校验 + validateSpecBase 结构性拒绝双保险）。
//   - legacy 逐包 Timestamp：legacy 恒 now；链上由 ChainPlanner 统一回填
//     （chain_planner.go:400），事件流不产。
//   - 握手 seq/ipID：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN；链上由
//     tcp 层生成器持有，事件流不产。
//   - dstPort：legacy Validate 强制 DstPort 必须 0 或 3389（planner.go:321），
//     Plan 数据帧恒用 DefaultRDPPort。链上 validateSpecBase 默认化 3389，
//     生成器用 req.Meta.DstPort（= 默认后的值，恒 3389）——与 legacy 一致。
//   - srcPort：legacy 单流用 spec.SrcPort 原值（up/down 包装器直传）；
//     validateSpecBase 对 rdp 分支不默认化 srcPort，与 legacy 一致。
//   - applyScenarioDefaults 在 generator Generate 内调用（同 legacy Plan
//     planner.go:419）：scenario 填充默认 Channels/DataEvents/ServerResponses，
//     空时用用户值（forwarder 同款）。
//
// 生成器内部顺序与 legacy Plan（544-775）逐 PDU 一致；事件方向/字节与 legacy
// 数据帧（flags=0x18 PSH-ACK payload）一一对应。none-TLS 链（默认 standard
// security）下 wrapTLSAppData 是 no-op，事件字节即原始 X.224 TPKT。

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// RDPGenerator is the rdp terminal-layer generator.
type RDPGenerator struct{}

// Name returns "rdp".
func (g *RDPGenerator) Name() string { return "rdp" }

// Generate produces one message event per RDP PDU in legacy Plan order
// （Phase 2 X.224 CR → ... → Phase 10 shutdown/disconnect）。TCP 层生成器负责
// 握手/seq-ack/挥手/MSS 分段。
func (g *RDPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("rdp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.RDP
	if cfg == nil {
		return fmt.Errorf("rdp generator: no config (spec.rdp required)")
	}

	// Scenario 填充（legacy Plan planner.go:419 同款：scenario 只在空槽填充，
	// 用用户值 forwarder 覆盖）。
	applyScenarioDefaults(cfg)

	// TLS 模式链上不支持（validator 已同步拒绝；此处双保险防御，理论上不可达）。
	if needsTLSHandshake(cfg) {
		return fmt.Errorf("rdp generator: SecurityLayer %q (TLS/NLA) is not supported on the layer chain (tcp layer cannot wrap RDP PDUs in TLS)", cfg.SecurityLayer)
	}

	// emit 单事件（direction + 完整 X.224 TPKT 字节）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- Phase 2: X.224 CR + Negotiation Request ---
	x224cr := encodeTPKT(encodeX224CR(cfg))
	if err := emit(true, x224cr); err != nil {
		return err
	}
	// --- Phase 2 response: X.224 CC + Negotiation Response ---
	x224cc := encodeTPKT(encodeX224CC(cfg))
	if err := emit(false, x224cc); err != nil {
		return err
	}

	// --- Phase 4: MCS Connect-Initial (with GCC Connect-Data) ---
	mcsCI := encodeTPKT(encodeX224DT(encodeMCSConnectInitial(cfg)))
	if err := emit(true, mcsCI); err != nil {
		return err
	}
	// --- Phase 4 response: MCS Connect-Response ---
	mcsCR := encodeTPKT(encodeX224DT(encodeMCSConnectResponse(cfg)))
	if err := emit(false, mcsCR); err != nil {
		return err
	}

	// --- Phase 5: MCS Erect-Domain Request ---
	ed := encodeTPKT(encodeX224DT(encodeMCSErectDomainRequest()))
	if err := emit(true, ed); err != nil {
		return err
	}
	// --- Phase 5: MCS Attach-User Request ---
	auReq := encodeTPKT(encodeX224DT(encodeMCSAttachUserRequest()))
	if err := emit(true, auReq); err != nil {
		return err
	}
	// --- Phase 5 response: MCS Attach-User Confirm ---
	auConf := encodeTPKT(encodeX224DT(encodeMCSAttachUserConfirm(MCSUserIDClient)))
	if err := emit(false, auConf); err != nil {
		return err
	}

	// --- Phase 5: MCS Channel-Join for I/O Channel (1003) + each static channel ---
	if !cfg.SkipMCSChannelJoin {
		cjReq := encodeTPKT(encodeX224DT(encodeMCSChannelJoinRequest(MCSUserIDClient, MCSIOChannel)))
		if err := emit(true, cjReq); err != nil {
			return err
		}
		cjConf := encodeTPKT(encodeX224DT(encodeMCSChannelJoinConfirm(MCSUserIDClient, MCSIOChannel, 0)))
		if err := emit(false, cjConf); err != nil {
			return err
		}
		for i, ch := range cfg.Channels {
			channelID := uint16(MCSFirstStaticChan) + uint16(i)
			if channelID > MCSLastStaticChan {
				break
			}
			cjReq := encodeTPKT(encodeX224DT(encodeMCSChannelJoinRequest(MCSUserIDClient, channelID)))
			if err := emit(true, cjReq); err != nil {
				return err
			}
			result := uint8(0)
			if hasChannelJoinFailure(cfg, ch.Name) {
				result = 4
			}
			cjConf := encodeTPKT(encodeX224DT(encodeMCSChannelJoinConfirm(MCSUserIDClient, channelID, result)))
			if err := emit(false, cjConf); err != nil {
				return err
			}
		}
	}

	// --- Phase 6: Security Exchange (Standard RDP Security only) ---
	if cfg.SecurityLayer == "standard" && !cfg.SkipSecurityExchange {
		secEx := encodeTPKT(encodeX224DT(encodeSecurityExchange(cfg)))
		if err := emit(true, secEx); err != nil {
			return err
		}
	}

	// --- Phase 7: Client Info PDU (skipped in NLA mode) ---
	if cfg.SecurityLayer != "nla" && cfg.SecurityLayer != "nla_ex" {
		info := encodeTPKT(encodeX224DT(encodeClientInfoPDU(cfg)))
		if err := emit(true, info); err != nil {
			return err
		}
	}

	// --- Phase 7 response: License Request + Client License Info ---
	if !cfg.SkipLicense {
		licReq := encodeTPKT(encodeX224DT(encodeLicensePDU(LicenseRequest, LicensePktFlag, nil)))
		if err := emit(false, licReq); err != nil {
			return err
		}
		licInfo := encodeTPKT(encodeX224DT(encodeLicensePDU(ClientLicenseInfo, LicensePktFlag, nil)))
		if err := emit(true, licInfo); err != nil {
			return err
		}
	}

	// --- Phase 8: Capability Exchange (Demand Active -> Confirm Active + sync) ---
	if !cfg.SkipCapability {
		demandActive := encodeTPKT(encodeX224DT(encodeDemandActivePDU(cfg)))
		if err := emit(false, demandActive); err != nil {
			return err
		}
		confirmActive := encodeTPKT(encodeX224DT(encodeConfirmActivePDU(cfg)))
		if err := emit(true, confirmActive); err != nil {
			return err
		}
		// Server Synchronize + Control Cooperate + Control Grant + Font Map.
		sync := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
		if err := emit(false, sync); err != nil {
			return err
		}
		coop := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
		if err := emit(false, coop); err != nil {
			return err
		}
		grant := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
		if err := emit(false, grant); err != nil {
			return err
		}
		fontMap := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2FontMap, nil)))
		if err := emit(false, fontMap); err != nil {
			return err
		}
	}

	// --- Phase 9: Data events (Active phase) ---
	for _, ev := range cfg.DataEvents {
		payload := ev.Payload
		if len(ev.PayloadB64) > 0 {
			if b, err := base64.StdEncoding.DecodeString(ev.PayloadB64); err == nil {
				payload = b
			}
		}
		pdu := encodeDataEvent(cfg, ev, payload)
		if pdu == nil {
			continue
		}
		dir := ev.Direction
		if dir == "" {
			dir = "up"
		}
		if err := emit(dir != "down", pdu); err != nil {
			return err
		}
	}

	// --- Phase 9: Server responses (FastPath Output etc.) ---
	for _, resp := range cfg.ServerResponses {
		pdu := encodeServerResponse(resp)
		if pdu == nil {
			continue
		}
		if err := emit(false, pdu); err != nil {
			return err
		}
	}

	// --- Phase 10: Shutdown + MCS Disconnect Provider Ultimatum ---
	shutdown := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2ShutdownRequest, nil)))
	if err := emit(true, shutdown); err != nil {
		return err
	}
	disconnect := encodeTPKT(encodeX224DT(encodeMCSDisconnectProviderUltimatum()))
	if err := emit(true, disconnect); err != nil {
		return err
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *RDPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *RDPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *RDPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("rdp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("rdp", func() (layers.LayerGenerator, error) {
		return &RDPGenerator{}, nil
	})
	layers.RegisterLayerValidator("rdp", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// TLS 模式链上不支持（tls 链版本/角色同款先例）：legacy
		// SecurityLayer=tls/nla/nla_ex 产 TLS 握手占位 + tlsActive 后
		// wrapTLSAppData 包裹每个 PDU；链上 tcp 层无等价 TLS 包裹。同步
		// 拒绝（validateSpecBase 无 chain 层面不做，此处校验器检查）。
		if spec.RDP != nil && needsTLSHandshake(spec.RDP) {
			return fmt.Errorf("rdp: SecurityLayer %q is not supported on the layer chain (tcp layer cannot wrap RDP PDUs in TLS)", spec.RDP.SecurityLayer)
		}
		// 握手/挥手校准进 spec.TCP（mqtt/redis/modbus layer_gen.go 同款陷阱）：
		// legacy rdp planner.go 恒产 TCP 握手/挥手（534-538/778-781 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须写
		// 默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：rdp 链上的握手/挥手不可关。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
