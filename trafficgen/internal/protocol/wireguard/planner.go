// Package wireguard implements the WireGuard VPN protocol planner.
//
// WireGuard (WireGuard VPN) is a modern VPN (虚拟专用网络, Virtual Private
// Network) protocol based on UDP with the Noise Protocol Framework (Noise 协议框架).
// It uses Noise_IKpsk2 mode for key exchange and ChaCha20-Poly1305 AEAD (认证加密,
// Authenticated Encryption with Associated Data) for transport encryption.
//
// The planner synthesizes wire-format-compliant WireGuard messages — Handshake
// Initiation (type=1, 148 bytes), Handshake Response (type=2, 92 bytes), Cookie
// Reply (type=3, 64 bytes), and Transport Data (type=4, 32+N bytes). It performs
// NO real cryptography — all encrypted fields (enc_static, enc_timestamp, enc_empty,
// enc_payload) and MAC fields (mac1, mac2) are filled with deterministic pseudo-bytes
// derived from a seed based on sender_index.
//
// Transport follows the existing UDP-planner pattern (openvpn/syslog/ntp/snmp):
// every WireGuard message becomes one UDP PacketConfig (包配置) on the configured
// 4-tuple with L2/L3 carried by core.L3Base + core.EtherTypeFor.
//
// Design reference: /tmp/l7_planner_design/design_wireguard.md
// Test reference: /tmp/l7_planner_design/testcases_wireguard.md
package wireguard

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Constants per WireGuard whitepaper §3 (message type wire values and field sizes).
const (
	// DefaultPort is the well-known WireGuard UDP port (51820).
	DefaultPort = 51820

	// DefaultTTL is the default IP TTL for WireGuard packets.
	DefaultTTL = 64

	// Message type wire values (whitepaper §3, §4).
	MsgHandshakeInitiation uint8 = 1 // Handshake Initiation (握手发起)
	MsgHandshakeResponse uint8 = 2 // Handshake Response (握手响应)
	MsgCookieReply uint8 = 3 // Cookie Reply (Cookie 应答)
	MsgTransportData uint8 = 4 // Transport Data (传输数据)

	// Fixed message sizes in bytes (whitepaper §3, §4).
	SizeHandshakeInitiation = 148 // 1 + 3 + 4 + 32 + 48 + 28 + 16 + 16
	SizeHandshakeResponse = 92 // 1 + 3 + 4 + 4 + 32 + 16 + 16 + 16
	SizeCookieReply = 64 // 1 + 3 + 4 + 24 + 32
	SizeTransportHeader = 16 // 1 + 3 + 4 + 8 (message_type + reserved + receiver_index + counter)

	// Field sizes within messages.
	SizeEphemeral = 32 // X25519 public key (X25519 公钥, 32 bytes)
	SizeEncStatic = 48 // Encrypted static public key + AEAD tag (加密静态公钥, 32 + 16)
	SizeEncTimestamp = 28 // Encrypted timestamp + AEAD tag (加密时间戳, 12 + 16)
	SizeEncEmpty = 16 // Encrypted empty payload — AEAD tag only (加密空, 0 + 16)
	SizeMAC1 = 16 // BLAKE2s MAC1 (第一层消息认证码, 16 bytes)
	SizeMAC2 = 16 // BLAKE2s MAC2 (第二层消息认证码, 16 bytes)
	SizeCookieNonce = 24 // XChaCha20-Poly1305 nonce (24 bytes)
	SizeEncCookie = 32 // Encrypted cookie (16 bytes cookie + 16 bytes tag)
	SizeAEADTag = 16 // ChaCha20-Poly1305 AEAD authentication tag (16 bytes)
	SizeTai64n = 12 // Tai64n timestamp (8 bytes seconds + 4 bytes nanoseconds)
	SizeReceiverIndex = 4 // receiver_index field (4 bytes, uint32 little-endian)
	SizeSenderIndex = 4 // sender_index field (4 bytes, uint32 little-endian)
	SizeCounter = 8 // counter field (8 bytes, uint64 little-endian)
	SizeReserved3 = 3 // reserved_zero field (3 bytes, must be 0x000000)

	// MaxTransportPayload (最大传输负载) is the maximum inner IP packet payload
	// per WireGuard MTU constraint (design §2.5).
	MaxTransportPayload = 1440

	// DefaultRekeyAfter is the default rekey threshold in packets (2^60).
	DefaultRekeyAfter = 1 << 60

	// DefaultRekeyAfterTimeSec is the default rekey time threshold in seconds.
	DefaultRekeyAfterTimeSec = 120

	// MaxSenderIndex is the maximum valid sender_index (uint32 max, 2^32-1).
	MaxSenderIndex = 1<<32 - 1
)

// Planner implements the WireGuard protocol planner.
type Planner struct{}

// NewPlanner creates a new WireGuard planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "wireguard" }

// Validate validates a WireGuard flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("wireguard: SrcIP %q is not a valid IP address", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("wireguard: DstIP %q is not a valid IP address", spec.DstIP)
	}
	if spec.WireGuard == nil {
		return nil
	}
	wg := spec.WireGuard

	// Validate Role (必须为 initiator 或 responder)
	if wg.Role != "" && wg.Role != "initiator" && wg.Role != "responder" {
		return fmt.Errorf("wireguard: Role must be initiator or responder")
	}

	// Validate Direction (必须为 up/down/both/空)
	if wg.Direction != "" && wg.Direction != "up" && wg.Direction != "down" && wg.Direction != "both" {
		return fmt.Errorf("wireguard: Direction must be up, down, or both")
	}

	// Validate key lengths (密钥长度校验)
	if len(wg.LocalStaticPubKey) > 0 && len(wg.LocalStaticPubKey) != 32 {
		return fmt.Errorf("wireguard: LocalStaticPubKey must be 32 bytes (X25519)")
	}
	if len(wg.PeerStaticPubKey) > 0 && len(wg.PeerStaticPubKey) != 32 {
		return fmt.Errorf("wireguard: PeerStaticPubKey must be 32 bytes (X25519)")
	}
	if len(wg.LocalEphemeralPubKey) > 0 && len(wg.LocalEphemeralPubKey) != 32 {
		return fmt.Errorf("wireguard: LocalEphemeralPubKey must be 32 bytes (X25519)")
	}

	// Validate PSK (预共享密钥)
	if len(wg.PSK) > 0 && len(wg.PSK) != 32 {
		return fmt.Errorf("wireguard: PSK must be 32 bytes (Noise_IKpsk2)")
	}

	// Validate Cookie (16 字节)
	if len(wg.Cookie) > 0 && len(wg.Cookie) != 16 {
		return fmt.Errorf("wireguard: Cookie must be 16 bytes (BLAKE2s output)")
	}

	// Validate SenderIndex (不可为 0)
	if wg.SenderIndex == 0 && wg.Role == "" {
		// 0 is allowed for auto-generate; only error if user explicitly set 0
		// We can't distinguish "not set" from "set to 0" in Go, so we skip this.
		// The whitepaper says sender_index must be > 0, but the planner auto-generates.
	}

	// Validate RekeyAfter (不能超过 2^60)
	if wg.RekeyAfter > 0 && wg.RekeyAfter >= 1<<60 {
		return fmt.Errorf("wireguard: RekeyAfter too large (recommend < 2^60)")
	}

	// Validate KeepaliveInterval (必须 >= 0)
	if wg.KeepaliveInterval < 0 {
		return fmt.Errorf("wireguard: KeepaliveInterval must be >= 0")
	}

	// Validate TransportPayloads MTU (不能超过 1440 字节)
	for i, p := range wg.TransportPayloads {
		if len(p) > MaxTransportPayload {
			return fmt.Errorf("wireguard: Transport payload[%d] exceeds MTU (max %d)", i, MaxTransportPayload)
		}
	}

	// Validate FileSource (文件源)
	if wg.FileSource != nil {
		if err := wg.FileSource.Validate(); err != nil {
			return fmt.Errorf("wireguard: FileSource: %w", err)
		}
	}

	// Validate Reserved fields (not stored in config, computed by planner)
	// Per design §2.1, reserved_zero must always be 0 — planner always emits 0.
	// No config-level validation needed.
	return nil
}

// Plan generates packet configs for a WireGuard flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)

		wg := spec.WireGuard
		if wg == nil {
			wg = &core.WireGuardConfig{}
		}

		// Apply defaults (默认值填充) — done in Plan(), not Validate().
		role := wg.Role
		if role == "" {
			role = "initiator" // default role (默认角色: 发起方)
		}
		direction := wg.Direction
		if direction == "" {
			direction = "up" // default direction (默认方向: 上行)
		}
		// Handshake defaults to true (nil means default).
		// *bool pattern: nil or *true = emit handshake, *false = skip.
		handshake := true
		if wg.Handshake != nil && !*wg.Handshake {
			handshake = false
		}
		// Response defaults to true.
		doResponse := true
		if wg.Response != nil && !*wg.Response {
			doResponse = false
		}

		// Resolve FileSource (文件源解析) via injected PayloadCache (负载缓存).
		// FileSource takes precedence over TransportPayloads (传输负载).
		// When FileSource is set but no cache is injected (e.g. unit tests
		// that forgot core.WithPayloadCache), skip and fall through to
		// TransportPayloads — mirroring HTTP/FTP/SCTP conventions.
		var fileBytes []byte
		if wg.FileSource != nil {
			if pc := core.PayloadCacheFrom(ctx); pc != nil {
				if b, err := pc.GetOrLoad(ctx, *wg.FileSource); err == nil {
					fileBytes = b
				}
			}
		}

		// Effective TTL and IPID (有効 TTL 和 IPID)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		ipID := uint16(rand.Uint32())
		packetIndex := uint64(0)
		now := time.Now()

		// Flow ID (流标识) based on 4-tuple.
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Resolve transport payloads from FileSource or TransportPayloads.
		// FileSource (文件源) takes precedence over TransportPayloads (传输负载).
		var transportPayloads [][]byte
		if len(fileBytes) > 0 {
			// FileSource resolved bytes: split into individual payloads
			// (one per transport packet) or use as single payload.
			transportPayloads = [][]byte{fileBytes}
		} else if len(wg.TransportPayloads) > 0 {
			transportPayloads = wg.TransportPayloads
		}
		// Default: single 1-byte dummy payload (默认: 1 字节 dummy 负载)
		if len(transportPayloads) == 0 {
			transportPayloads = [][]byte{{0x00}}
		}

		// Sender index (发送方索引): auto-generate if 0.
		senderIndex := wg.SenderIndex
		if senderIndex == 0 {
			senderIndex = 1 // first session (首个会话)
		}
		responderIndex := senderIndex + 1 // responder gets next index

		// Transport counter (传输计数器)
		counter := wg.InitialCounter

		// Rekey thresholds (重密钥阈值)
		rekeyAfter := wg.RekeyAfter
		if rekeyAfter == 0 {
			rekeyAfter = DefaultRekeyAfter
		}
		_ = wg.RekeyAfterTime // time-based rekey not simulated in planner

		// Keepalive interval (保活间隔)
		keepaliveInterval := wg.KeepaliveInterval

		// Cookie (16 bytes or zero)
		var cookie []byte
		if len(wg.Cookie) == 16 {
			cookie = wg.Cookie
		}

		// Local ephemeral key (本地临时公钥)
		ephemeral := wg.LocalEphemeralPubKey
		if len(ephemeral) == 0 {
			ephemeral = make([]byte, SizeEphemeral)
			fillDeterministic(ephemeral, senderIndex, 0)
		}

		// emit sends one packet in the given direction. Returns false
		// when ctx is cancelled (caller should return to close channel).
		emit := func(direction string, payload []byte, metadata map[string]interface{}) bool {
			// Determine source/dest MAC and IP based on direction (方向).
			smac, dmac := spec.SrcMAC, spec.DstMAC
			sip, dip := spec.SrcIP, spec.DstIP
			sport, dport := uint16(spec.SrcPort), uint16(spec.DstPort)
			if direction == "down" {
				smac, dmac = dmac, smac
				sip, dip = dip, sip
				sport, dport = dport, sport
			}
			if dport == 0 {
				dport = DefaultPort
			}

			cfg := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: direction,
				Timestamp: now,
				L2: core.L2Config{
					SrcMAC: smac,
					DstMAC: dmac,
					EtherType: core.EtherTypeFor(sip),
				},
				L3: core.L3Base(sip, dip, 17, effectiveTTL, ipID, spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort: sport,
					DstPort: dport,
				},
				Payload: payload,
				Metadata: metadata,
			}
			// Propagate GroupID (组标识) from spec if configured.
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					if cfg.Metadata == nil {
						cfg.Metadata = make(map[string]interface{})
					}
					cfg.Metadata["group_id"] = g
				}
			}
			select {
			case out <- cfg:
				packetIndex++
				ipID++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// --- Handshake phase (握手阶段) ---

		// If Handshake is disabled, skip directly to transport data.
		if handshake {
			// Role: initiator (发起方) — send Handshake Initiation (type=1)
			if role == "initiator" {
				initiation := buildInitiation(senderIndex, ephemeral, cookie)
				meta := map[string]interface{}{
					"wireguard_message_type": int(MsgHandshakeInitiation),
					"wireguard_sender_index": senderIndex,
				}
				if !emit("up", initiation, meta) {
					return
				}

				// Response from responder (type=2, down direction)
				respEphemeral := make([]byte, SizeEphemeral)
				fillDeterministic(respEphemeral, responderIndex, 0)
				response := buildResponse(responderIndex, senderIndex, respEphemeral, cookie)
				metaResp := map[string]interface{}{
					"wireguard_message_type": int(MsgHandshakeResponse),
					"wireguard_sender_index": responderIndex,
					"wireguard_receiver_index": senderIndex,
				}
				if !emit("down", response, metaResp) {
					return
				}
			}

			// Role: responder (响应方) — send Handshake Response (type=2)
			if role == "responder" && doResponse {
				respEphemeral := make([]byte, SizeEphemeral)
				fillDeterministic(respEphemeral, responderIndex, 0)

				// Initiator's sender_index (发起方 sender_index) — use responderIndex+1 as the initiator's index
				initiatorIndex := responderIndex + 1
				response := buildResponse(responderIndex, initiatorIndex, respEphemeral, cookie)
				meta := map[string]interface{}{
					"wireguard_message_type": int(MsgHandshakeResponse),
					"wireguard_sender_index": responderIndex,
					"wireguard_receiver_index": initiatorIndex,
				}
				if !emit("down", response, meta) {
					return
				}
			}

			// Cookie Reply (type=3) — responder sends when under load
			if role == "responder" && wg.CookieReplyThreshold > 0 {
				initiatorIndex := senderIndex
				if role == "responder" {
					initiatorIndex = responderIndex + 1
				}
				cookieReply := buildCookieReply(initiatorIndex)
				meta := map[string]interface{}{
					"wireguard_message_type": int(MsgCookieReply),
					"wireguard_receiver_index": initiatorIndex,
				}
				if !emit("down", cookieReply, meta) {
					return
				}
			}
		}

		// --- Transport data phase (传输数据阶段) ---
		rekeyTriggered := false
		for i, payload := range transportPayloads {
			// Check rekey threshold (检查重密钥阈值)
			if counter >= rekeyAfter && !rekeyTriggered {
				// Insert rekey handshake (插入重密钥握手)
				rekeyTriggered = true
				senderIndex += 2 // new session indices (新会话索引)
				ephemeral = make([]byte, SizeEphemeral)
				fillDeterministic(ephemeral, senderIndex, 0)

				initiation := buildInitiation(senderIndex, ephemeral, cookie)
				meta := map[string]interface{}{
					"wireguard_message_type": int(MsgHandshakeInitiation),
					"wireguard_sender_index": senderIndex,
				}
				if !emit("up", initiation, meta) {
					return
				}

				respEphemeral := make([]byte, SizeEphemeral)
				fillDeterministic(respEphemeral, senderIndex+1, 0)
				response := buildResponse(senderIndex+1, senderIndex, respEphemeral, cookie)
				metaResp := map[string]interface{}{
					"wireguard_message_type": int(MsgHandshakeResponse),
					"wireguard_sender_index": senderIndex + 1,
					"wireguard_receiver_index": senderIndex,
				}
				if !emit("down", response, metaResp) {
					return
				}
				counter = 0 // reset counter after rekey (重密钥后计数器重置)
			}

			// Determine packet direction (确定包方向)
			pktDir := resolveDirection(direction, i)

			// Build transport data (构建传输数据)
			transport := buildTransportData(responderIndex, counter, payload)
			meta := map[string]interface{}{
				"wireguard_message_type": int(MsgTransportData),
				"wireguard_receiver_index": responderIndex,
				"wireguard_counter": counter,
			}
			if !emit(pktDir, transport, meta) {
				return
			}
			counter++
		}

		// --- Keepalive (保活) ---
		if keepaliveInterval > 0 {
			keepalive := buildTransportData(responderIndex, counter, nil)
			meta := map[string]interface{}{
				"wireguard_message_type": int(MsgTransportData),
				"wireguard_receiver_index": responderIndex,
				"wireguard_counter": counter,
			}
			pktDir := resolveDirection(direction, len(transportPayloads))
			if !emit(pktDir, keepalive, meta) {
				return
			}
		}
	}()

	return out, nil
}

// buildInitiation constructs a Handshake Initiation message (type=1, 148 bytes).
// 构建握手发起消息 (type=1, 148 字节).
func buildInitiation(senderIndex uint32, ephemeral []byte, cookie []byte) []byte {
	buf := make([]byte, SizeHandshakeInitiation)

	// message_type (1 byte) = 1
	buf[0] = MsgHandshakeInitiation

	// reserved_zero (3 bytes) = 0x000000
	// Already zero-filled.

	// sender_index (4 bytes, little-endian 小端)
	binary.LittleEndian.PutUint32(buf[4:8], senderIndex)

	// ephemeral (32 bytes) — X25519 public key
	copy(buf[8:40], ephemeral)

	// enc_static (48 bytes) — encrypted static public key + AEAD tag
	encStatic := make([]byte, SizeEncStatic)
	fillDeterministic(encStatic, senderIndex, 1)
	copy(buf[40:88], encStatic)

	// enc_timestamp (28 bytes) — encrypted timestamp + AEAD tag
	encTimestamp := make([]byte, SizeEncTimestamp)
	fillDeterministic(encTimestamp, senderIndex, 2)
	copy(buf[88:116], encTimestamp)

	// mac1 (16 bytes) — BLAKE2s MAC1
	mac1 := make([]byte, SizeMAC1)
	fillDeterministic(mac1, senderIndex, 3)
	copy(buf[116:132], mac1)

	// mac2 (16 bytes) — BLAKE2s MAC2
	mac2 := make([]byte, SizeMAC2)
	if len(cookie) == 16 {
		// With cookie: deterministic non-zero (有 cookie: 非零 deterministic)
		fillDeterministic(mac2, senderIndex, 4)
	} else {
		// Without cookie: all zeros (无 cookie: 全零)
		// Already zero-filled.
		_ = mac2
	}
	copy(buf[132:148], mac2)

	return buf
}

// buildResponse constructs a Handshake Response message (type=2, 92 bytes).
// 构建握手响应消息 (type=2, 92 字节).
func buildResponse(senderIndex, receiverIndex uint32, ephemeral []byte, cookie []byte) []byte {
	buf := make([]byte, SizeHandshakeResponse)

	// message_type (1 byte) = 2
	buf[0] = MsgHandshakeResponse

	// reserved_zero (3 bytes) = 0x000000
	// Already zero-filled.

	// sender_index (4 bytes, little-endian 小端)
	binary.LittleEndian.PutUint32(buf[4:8], senderIndex)

	// receiver_index (4 bytes, little-endian 小端)
	binary.LittleEndian.PutUint32(buf[8:12], receiverIndex)

	// ephemeral (32 bytes) — X25519 public key
	copy(buf[12:44], ephemeral)

	// enc_empty (16 bytes) — AEAD tag only (0 bytes ciphertext)
	encEmpty := make([]byte, SizeEncEmpty)
	fillDeterministic(encEmpty, senderIndex, 5)
	copy(buf[44:60], encEmpty)

	// mac1 (16 bytes) — BLAKE2s MAC1
	mac1 := make([]byte, SizeMAC1)
	fillDeterministic(mac1, senderIndex, 6)
	copy(buf[60:76], mac1)

	// mac2 (16 bytes) — BLAKE2s MAC2
	mac2 := make([]byte, SizeMAC2)
	if len(cookie) == 16 {
		fillDeterministic(mac2, senderIndex, 7)
	}
	// Without cookie: all zeros (already zero-filled)
	copy(buf[76:92], mac2)

	return buf
}

// buildCookieReply constructs a Cookie Reply message (type=3, 64 bytes).
// 构建 Cookie 应答消息 (type=3, 64 字节).
func buildCookieReply(receiverIndex uint32) []byte {
	buf := make([]byte, SizeCookieReply)

	// message_type (1 byte) = 3
	buf[0] = MsgCookieReply

	// reserved_zero (3 bytes) = 0x000000
	// Already zero-filled.

	// receiver_index (4 bytes, little-endian 小端)
	binary.LittleEndian.PutUint32(buf[4:8], receiverIndex)

	// nonce (24 bytes) — XChaCha20-Poly1305 nonce
	nonce := make([]byte, SizeCookieNonce)
	fillDeterministic(nonce, receiverIndex, 8)
	copy(buf[8:32], nonce)

	// enc_cookie (32 bytes) — encrypted cookie (16 bytes cookie + 16 bytes tag)
	encCookie := make([]byte, SizeEncCookie)
	fillDeterministic(encCookie, receiverIndex, 9)
	copy(buf[32:64], encCookie)

	return buf
}

// buildTransportData constructs a Transport Data message (type=4, 32+N bytes).
// 构建传输数据消息 (type=4, 32+N 字节).
// If payload is nil or empty, the message is a keepalive (32 bytes, AEAD tag only).
func buildTransportData(receiverIndex uint32, counter uint64, payload []byte) []byte {
	payloadLen := len(payload)
	totalLen := SizeTransportHeader + payloadLen + SizeAEADTag

	buf := make([]byte, totalLen)

	// message_type (1 byte) = 4
	buf[0] = MsgTransportData

	// reserved_zero (3 bytes) = 0x000000
	// Already zero-filled.

	// receiver_index (4 bytes, little-endian 小端)
	binary.LittleEndian.PutUint32(buf[4:8], receiverIndex)

	// counter (8 bytes, little-endian 小端)
	binary.LittleEndian.PutUint64(buf[8:16], counter)

	// enc_payload (16 + N bytes) — AEAD ciphertext + tag
	// For zero-length payload, this is just the 16-byte AEAD tag.
	encPayload := make([]byte, payloadLen+SizeAEADTag)
	if payloadLen > 0 {
		// Copy raw payload then add deterministic tag (复制原始负载后添加 deterministic tag)
		copy(encPayload, payload)
	}
	tag := encPayload[payloadLen:]
	fillDeterministic(tag, uint32(counter), 10)
	copy(buf[16:], encPayload)

	return buf
}

// fillDeterministic fills buf with deterministic pseudo-random bytes derived
// from the given seed values. This ensures reproducible output for the same
// inputs while avoiding real cryptography.
// 用确定性伪随机字节填充 buf, 保证可重现性。
func fillDeterministic(buf []byte, seeds ...uint32) {
	// Simple XOR-shift based PRNG seeded from the combined seeds.
	seed := uint64(0xDEADBEEF)
	for _, s := range seeds {
		seed ^= uint64(s) * 0x9E3779B97F4A7C15
	}
	rng := rand.New(rand.NewSource(int64(seed)))
	for i := range buf {
		buf[i] = byte(rng.Uint32())
	}
}

// resolveDirection determines the packet direction based on the configured
// direction mode and the packet index.
// 根据配置的方向模式和包索引确定包方向。
func resolveDirection(direction string, index int) string {
	switch direction {
	case "up":
		return "up"
	case "down":
		return "down"
	case "both":
		// Alternate (交替): odd index = down, even index = up
		if index%2 == 0 {
			return "up"
		}
		return "down"
	default:
		return "up"
	}
}