package ssh

// SSHGenerator is the ssh terminal-layer generator (ssh 终结层层生成器, P3)。
// SSH (RFC 4253 transport + RFC 4254 connection)——一次 flow = 一个 4-tuple 上
// 的一条 TCP 连接 + 一个 SSH 会话：server version (text) → client version (text)
// → KEXINIT ×2 → KEXDH_INIT/REPLY → NEWKEYS ×2 → [EXT_INFO] → SERVICE_REQUEST/
// ACCEPT → USERAUTH dialog → channel dialog → [DISCONNECT]。每条 BPP 帧一个
// "报文事件"（方向 + 完整 BPP 字节），构建字节由 buildBPP/encodeKexInit/
// encodeKexDHInit/encodeUserAuthRequest/encodeChannelOpen 等纯函数产出
// （复用，不重写）。事件模式（mqtt/grpc/redis 同款）：TCP 语义（握手/seq-ack/
// 挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go Plan）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包 SYN/SYN-ACK/ACK，planner.go:438-442）与
//     挥手（4 包 FIN-ACK/ACK/FIN-ACK/ACK，planner.go:646-651）——事件模式
//     不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层 schema
//     默认 true 执行，validator 强制校准 true（legacy ssh.go 恒产握手/挥手，
//     从不读 spec.TCP.Handshake/Termination，语义一致）。
//   - legacy 逐包 Timestamp：legacy 恒 now；链上由 ChainPlanner 统一回填
//     （chain_planner.go:400），事件流不产。
//   - 握手 seq/ipID：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN；链上由
//     tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 单流用 spec.SrcPort 原值（emit 闭包直传）；
//     validateSpecBase 对 ssh 分支不默认化 srcPort，与 legacy 一致。
//   - dstPort 默认化：legacy Plan 内默认 22（strategy_convert mapToFlowSpec
//     同款）；链上由 validateSpecBase 默认化（chain_planner.go dst 端口 ssh
//     分支），生成器不再默认。
//   - RekeyAfter：legacy Plan 从不使用（死参数——parsed 但 Plan 内无 re-KEX
//     逻辑），生成器亦忽略。
//   - cookieGen 依赖 rand 状态（测试侧依赖唯一性）；链上生成器复用同一
//     cookieGen，行为一致。
//
// 生成器内部顺序与 legacy Plan（444-643）逐帧一致；事件方向/字节与 legacy
// 数据帧（flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SSHGenerator is the ssh terminal-layer generator.
type SSHGenerator struct{}

// Name returns "ssh".
func (g *SSHGenerator) Name() string { return "ssh" }

// Generate produces one message event per SSH wire frame in legacy Plan order
//（server version → client version → KEXINIT → KEXDH → NEWKEYS → [EXT_INFO] →
// SERVICE → USERAUTH → channel → [DISCONNECT]）。TCP 层生成器负责握手/seq-ack/
// 挥手/MSS 分段。
func (g *SSHGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("ssh generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	sshCfg := req.Meta.SSH
	if sshCfg == nil {
		// 与 legacy Plan 同款（planner.go:263-266：sshCfg==nil →
		// &core.SSHConfig{}）空配置走默认：手动模式默认 auth/channel。
		sshCfg = &core.SSHConfig{}
	}

	// 默认化（planner.go:302-330 同款）。
	serverVersion := sshCfg.ServerVersion
	clientVersion := sshCfg.ClientVersion
	kexAlgs := sshCfg.KexAlgorithms
	if kexAlgs == "" {
		kexAlgs = DefaultKexAlgorithms
	}
	hostKeyAlgs := sshCfg.HostKeyAlgorithms
	if hostKeyAlgs == "" {
		hostKeyAlgs = DefaultHostKeyAlgorithms
	}
	encAlgs := sshCfg.EncryptionAlgorithms
	if encAlgs == "" {
		encAlgs = DefaultEncryptionAlgorithms
	}
	macAlgs := sshCfg.MACAlgorithms
	if macAlgs == "" {
		macAlgs = DefaultMACAlgorithms
	}
	compAlgs := sshCfg.CompressionAlgorithms
	if compAlgs == "" {
		compAlgs = DefaultCompressionAlgorithms
	}
	kex := sshCfg.KEX
	if kex == "" {
		kex = "curve25519-sha256"
	}

	// Scenario mode（planner.go:270-296 同款）：Scenario 非空时合成 auth/channel，
	// 覆盖手动列表。
	var scenarioAuth []core.SSHMessage
	var scenarioChannels []core.ChannelEntry
	if sshCfg.Scenario != "" {
		scenarioAuth = buildScenarioAuth(sshCfg)
		scenarioChannels = buildScenarioChannels(sshCfg)
	}

	authMethods := sshCfg.AuthMethods
	if scenarioAuth != nil {
		authMethods = scenarioAuth
	} else if len(authMethods) == 0 {
		authMethods = defaultAuthMethods()
	}

	channels := sshCfg.Channels
	if scenarioChannels != nil {
		channels = scenarioChannels
	} else if len(channels) == 0 {
		channels = defaultChannels()
	}

	// emit 单事件（direction + 完整帧字节）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}
	// emitBPP 包装给定 payload 为 BPP 帧（buildBPP 纯函数）并 emit。
	emitBPP := func(direction string, payload []byte, cipher string, postNewKeys bool) error {
		cipherBlock := blockSizeForCipher(cipher)
		macLen := MACNone
		if postNewKeys {
			macLen = MAC256
		}
		frame := buildBPP(payload, cipherBlock, macLen)
		return emit(direction == "up", frame)
	}

	// --- Version exchange (text, no BPP) ---
	// server 先（Rfc 4253 §4.2）；ServerVersion 空且 ClientVersion 也空时跳过两者。
	if serverVersion != "" || clientVersion != "" {
		sv := serverVersion
		if sv == "" {
			sv = SSHVersionPrefix + SSHVersionDefault
		}
		if err := emit(false, []byte(sv+SSHVersionCRLF)); err != nil {
			return err
		}
		cv := clientVersion
		if cv == "" {
			cv = SSHVersionPrefix + SSHVersionDefault
		}
		if err := emit(true, []byte(cv+SSHVersionCRLF)); err != nil {
			return err
		}
	}

	// --- KEXINIT (BPP, "none" cipher, no MAC) ---
	cookieClient := cookieGen()
	cookieServer := cookieGen()
	kexInitPayload := encodeKexInit(cookieClient, kexAlgs, hostKeyAlgs, encAlgs, macAlgs, compAlgs)
	if err := emitBPP("up", kexInitPayload, CipherNone, false); err != nil {
		return err
	}
	kexInitPayloadSrv := encodeKexInit(cookieServer, kexAlgs, hostKeyAlgs, encAlgs, macAlgs, compAlgs)
	if err := emitBPP("down", kexInitPayloadSrv, CipherNone, false); err != nil {
		return err
	}

	// --- KEXDH_INIT / KEXDH_REPLY ---
	dhClientLen := dhPayloadLenForKEX(kex)
	dhInit := encodeKexDHInit(make([]byte, dhClientLen))
	if err := emitBPP("up", dhInit, CipherNone, false); err != nil {
		return err
	}
	reply := encodeKexDHReply(make([]byte, 294), make([]byte, dhClientLen), make([]byte, 256))
	if err := emitBPP("down", reply, CipherNone, false); err != nil {
		return err
	}

	// --- NEWKEYS (both directions, still "none" cipher until after) ---
	newKeys := []byte{MsgNewKeys}
	if err := emitBPP("up", newKeys, CipherNone, false); err != nil {
		return err
	}
	if err := emitBPP("down", newKeys, CipherNone, false); err != nil {
		return err
	}

	// --- EXT_INFO (optional, RFC 8308) ---
	if sshCfg.ExtInfo {
		extUp := encodeExtInfo([]string{"ext-info-c"})
		if err := emitBPP("up", extUp, CipherAES, true); err != nil {
			return err
		}
		extDown := encodeExtInfo([]string{"ext-info-s"})
		if err := emitBPP("down", extDown, CipherAES, true); err != nil {
			return err
		}
	}

	// --- SERVICE_REQUEST / SERVICE_ACCEPT ---
	svcReq := encodeServiceRequest("ssh-userauth")
	if err := emitBPP("up", svcReq, CipherAES, true); err != nil {
		return err
	}
	svcAcc := encodeServiceAccept("ssh-userauth")
	if err := emitBPP("down", svcAcc, CipherAES, true); err != nil {
		return err
	}

	// --- USERAUTH dialog ---
	disconnectEmitted := false
	for _, m := range authMethods {
		switch m.Type {
		case "userauth_request":
			if err := emitBPP("up", encodeUserAuthRequest(m), CipherAES, true); err != nil {
				return err
			}
		case "userauth_failure":
			if err := emitBPP("down", encodeUserAuthFailure(m), CipherAES, true); err != nil {
				return err
			}
		case "userauth_success":
			if err := emitBPP("down", encodeUserAuthSuccess(), CipherAES, true); err != nil {
				return err
			}
		case "userauth_banner":
			if err := emitBPP("down", encodeUserAuthBanner(m), CipherAES, true); err != nil {
				return err
			}
		case "userauth_info_request":
			if err := emitBPP("down", encodeUserAuthInfoRequest(m), CipherAES, true); err != nil {
				return err
			}
		case "userauth_info_response":
			if err := emitBPP("up", encodeUserAuthInfoResponse(m), CipherAES, true); err != nil {
				return err
			}
		case "service_request":
			payload := encodeServiceRequest(m.ServiceName)
			if m.Direction == "down" {
				if err := emitBPP("down", payload, CipherAES, true); err != nil {
					return err
				}
			} else {
				if err := emitBPP("up", payload, CipherAES, true); err != nil {
					return err
				}
			}
		case "service_accept":
			if err := emitBPP("down", encodeServiceAccept(m.ServiceName), CipherAES, true); err != nil {
				return err
			}
		case "disconnect":
			payload := encodeDisconnect(m.ReasonCode, m.Description, m.LanguageTag)
			if m.Direction == "down" {
				if err := emitBPP("down", payload, CipherAES, true); err != nil {
					return err
				}
			} else {
				if err := emitBPP("up", payload, CipherAES, true); err != nil {
					return err
				}
			}
			disconnectEmitted = true
		case "ignore":
			payload := encodeIgnore(m.Data)
			if m.Direction == "down" {
				if err := emitBPP("down", payload, CipherAES, true); err != nil {
					return err
				}
			} else {
				if err := emitBPP("up", payload, CipherAES, true); err != nil {
					return err
				}
			}
		case "unimplemented":
			payload := encodeUnimplemented(m.ReceiveSeq)
			if m.Direction == "down" {
				if err := emitBPP("down", payload, CipherAES, true); err != nil {
					return err
				}
			} else {
				if err := emitBPP("up", payload, CipherAES, true); err != nil {
					return err
				}
			}
		case "debug":
			payload := encodeDebug(m.AlwaysDisplay, m.Message, m.LanguageTag)
			if m.Direction == "down" {
				if err := emitBPP("down", payload, CipherAES, true); err != nil {
					return err
				}
			} else {
				if err := emitBPP("up", payload, CipherAES, true); err != nil {
					return err
				}
			}
		}
	}

	// --- Channel dialog ---
	var nextSender uint32
	if !disconnectEmitted {
		for _, ch := range channels {
			switch ch.Type {
			case "channel_open":
				sc := ch.SenderChannel
				if sc == 0 {
					sc = nextSender
				}
				nextSender = sc + 1
				if err := emitBPP("up", encodeChannelOpen(sc, ch.ChannelType, ch.InitialWindowSize, ch.MaximumPacketSize, ch), CipherAES, true); err != nil {
					return err
				}
			case "channel_open_confirmation":
				if err := emitBPP("down", encodeChannelOpenConfirmation(ch.RecipientChannel, ch.SenderChannel, ch.InitialWindowSize, ch.MaximumPacketSize), CipherAES, true); err != nil {
					return err
				}
			case "channel_open_failure":
				if err := emitBPP("down", encodeChannelOpenFailure(ch.RecipientChannel, ch.OpenReasonCode, ch.OpenReasonText, ""), CipherAES, true); err != nil {
					return err
				}
			case "channel_request":
				if err := emitBPP("up", encodeChannelRequest(ch.RecipientChannel, ch.RequestType, ch.WantReply, ch), CipherAES, true); err != nil {
					return err
				}
			case "channel_data":
				payload := encodeChannelData(ch.RecipientChannel, ch.Data)
				if ch.Direction == "down" {
					if err := emitBPP("down", payload, CipherAES, true); err != nil {
						return err
					}
				} else {
					if err := emitBPP("up", payload, CipherAES, true); err != nil {
						return err
					}
				}
			case "channel_extended_data":
				payload := encodeChannelExtendedData(ch.RecipientChannel, ch.DataTypeCode, ch.Data)
				if ch.Direction == "down" {
					if err := emitBPP("down", payload, CipherAES, true); err != nil {
						return err
					}
				} else {
					if err := emitBPP("up", payload, CipherAES, true); err != nil {
						return err
					}
				}
			case "channel_eof":
				payload := encodeChannelEOF(ch.RecipientChannel)
				if ch.Direction == "down" {
					if err := emitBPP("down", payload, CipherAES, true); err != nil {
						return err
					}
				} else {
					if err := emitBPP("up", payload, CipherAES, true); err != nil {
						return err
					}
				}
			case "channel_close":
				payload := encodeChannelClose(ch.RecipientChannel)
				if ch.Direction == "down" {
					if err := emitBPP("down", payload, CipherAES, true); err != nil {
						return err
					}
				} else {
					if err := emitBPP("up", payload, CipherAES, true); err != nil {
						return err
					}
				}
			case "channel_window_adjust":
				payload := encodeChannelWindowAdjust(ch.RecipientChannel, ch.BytesToAdd)
				if ch.Direction == "down" {
					if err := emitBPP("down", payload, CipherAES, true); err != nil {
						return err
					}
				} else {
					if err := emitBPP("up", payload, CipherAES, true); err != nil {
						return err
					}
				}
			case "global_request":
				if err := emitBPP("up", encodeGlobalRequest(ch), CipherAES, true); err != nil {
					return err
				}
			case "request_success":
				if err := emitBPP("down", encodeRequestSuccess(ch.Port), CipherAES, true); err != nil {
					return err
				}
			case "request_failure":
				if err := emitBPP("down", encodeRequestFailure(), CipherAES, true); err != nil {
					return err
				}
			}
		}
	}

	// --- 可选 DISCONNECT before teardown ---
	if sshCfg.DisconnectOnClose && !disconnectEmitted {
		disc := encodeDisconnect(DiscByApplication, "client closed connection", "")
		if err := emitBPP("up", disc, CipherAES, true); err != nil {
			return err
		}
	}

	return nil
}

// cookieGen emits deterministic-looking 16-byte cookies per KEXINIT
// (planner.go:355-363 同款；依赖 rand 状态，测试侧要求唯一性)。
func cookieGen() []byte {
	c := make([]byte, 16)
	for i := 0; i < 4; i++ {
		v := rand.Uint32()
		binary.BigEndian.PutUint32(c[i*4:], v)
	}
	return c
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *SSHGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *SSHGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SSHGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ssh generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ssh", func() (layers.LayerGenerator, error) {
		return &SSHGenerator{}, nil
	})
	layers.RegisterLayerValidator("ssh", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（mqtt/redis/modbus layer_gen.go 同款陷阱）：
		// legacy ssh planner.go 恒产 TCP 握手/挥手（438-442/646-651 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须写
		// 默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：ssh 链上的握手/挥手不可关。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
