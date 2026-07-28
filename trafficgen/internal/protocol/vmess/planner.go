// Package vmess implements the V2Ray VMess protocol planner.
//
// vmess (V2Ray VMess 协议) is a session-level, AEAD-encrypted binary proxy
// protocol running on top of TCP (default) or UDP. The planner emits:
//
// TCP mode (默认, 端口 443):
// 1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
// 2. VMess Request header (AEAD mode):
// - Request Version (1 byte, 0x01)
// - Request IV (16 bytes: 12B nonce + 4B counter for AEAD; 16B random for Legacy)
// - Request Encrypted Body (AEAD ciphertext: UUID + Version + Cmd + AddrType + Addr + Port + PadLen + Pad + [PayloadLen])
// - Request Payload (opaque bytes, segmented by MSS)
// - Request HMAC / Tag (16 bytes)
// 3. VMess Response header:
// - Response Version (1 byte, 0x01)
// - Response IV (16 bytes)
// - Response Encrypted Body (UUID + Version + Cmd + PadLen + Pad + [ResponsePayloadLen])
// - Response Payload (opaque bytes)
// - Response HMAC / Tag (16 bytes)
// 4. Optional MUX frames (when Command=0x03)
// 5. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK)
//
// UDP mode (Command=0x02):
// 1. VMess Request (Cmd=UDP) — one datagram
// 2. VMess Response — one datagram
//
// The planner does NOT implement real cryptography. Per design §8, it emits
// random (or zeros) bytes in encrypted-payload/tag slots, ensuring
// wire-conformant framing without cryptographic validity (无真实加密,
// 仅生成格式合规的随机字节).
package vmess

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical VMess port (443).
	DefaultPort = 443

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	// Duplicated here to avoid an import cycle.
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// VersionAEAD (AEAD协议版本) is the protocol version for AEAD mode (0x01).
	VersionAEAD = 0x01

	// VersionLegacy (Legacy协议版本) is the protocol version for Legacy mode (0x00).
	VersionLegacy = 0x00

	// IVLen (IV长度) is the fixed Request/Response IV length (16 bytes).
	IVLen = 16

	// NonceLen (Nonce长度) is the AEAD nonce length within the 16B IV (12 bytes).
	NonceLen = 12

	// CounterLen (计数器长度) is the AEAD counter length within the 16B IV (4 bytes).
	CounterLen = 4

	// UUIDLen (UUID长度) is the UUID binary length (16 bytes).
	UUIDLen = 16

	// TagLen (认证标签长度) is the fixed AEAD auth tag / HMAC length (16 bytes).
	TagLen = 16

	// HMACLen (HMAC长度) is the Legacy HMAC SHA-256 truncated length (16 bytes).
	HMACLen = 16

	// KeyLen (密钥长度) is the encryption key length for synth bytes (16 bytes).
	KeyLen = 16

	// MaxHeaderPadLen (最大头部填充长度) is the max header padding per vmess spec (16).
	MaxHeaderPadLen = 16

	// MaxDomainLen (最大域名长度) is the max domain name length per vmess spec (253).
	MaxDomainLen = 253

	// MaxPayloadLen (最大载荷长度) is the max PayloadLen field value (65535).
	MaxPayloadLen = 65535

	// MaxChunkPayload (每块最大负载) is the maximum payload per AEAD chunk (0x3FFF).
	// Used when segmenting large payloads.
	MaxChunkPayload = 0x3FFF

	// CmdTCP (TCP命令) is the TCP command byte (0x01).
	CmdTCP = 0x01

	// CmdUDP (UDP命令) is the UDP command byte (0x02).
	CmdUDP = 0x02

	// CmdMUX (MUX命令) is the MUX command byte (0x03).
	CmdMUX = 0x03

	// AddrTypeIPv4 (IPv4地址类型) is the IPv4 address type (0x01).
	AddrTypeIPv4 = 0x01

	// AddrTypeDomain (域名地址类型) is the Domain address type (0x02).
	AddrTypeDomain = 0x02

	// AddrTypeIPv6 (IPv6地址类型) is the IPv6 address type (0x03).
	AddrTypeIPv6 = 0x03

	// ResponseAuthLen (响应认证长度) is the vmess response auth field length (4 bytes).
	ResponseAuthLen = 4

	// MuxStatusNEW (MUX新会话) is the MUX NEW frame status (0x01).
	MuxStatusNEW = 0x01

	// MuxStatusKEEP (MUX保持/数据) is the MUX KEEP frame status (0x02).
	MuxStatusKEEP = 0x02

	// MuxStatusEND (MUX关闭) is the MUX END frame status (0x03).
	MuxStatusEND = 0x03

	// MuxStatusKEEPALIVE (MUX保活) is the MUX KEEPALIVE frame status (0x04).
	MuxStatusKEEPALIVE = 0x04
)

// TCP flag bits (TCP标志位, RFC 9293 §3.1).
const (
	flagSYN = 0x02
	flagSYNACK = 0x12
	flagACK = 0x10
	flagPSHACK = 0x18
	flagFINACK = 0x11
	flagRSTACK = 0x14
)

// supportedEncryptions (支持的加密算法) lists all supported encryption names.
var supportedEncryptions = map[string]bool{
	"aead_chacha20_poly1305": true,
	"aead_aes_128_gcm": true,
	"legacy_aes_128_cfb": true,
}

// isAEADEncryption returns true if the encryption mode uses AEAD framing.
func isAEADEncryption(enc string) bool {
	return enc == "aead_chacha20_poly1305" || enc == "aead_aes_128_gcm"
}

// Planner implements the VMess protocol planner.
type Planner struct{}

// NewPlanner creates a new VMess planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "vmess" }

// Validate validates a VMess flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("vmess: SrcIP %q is not a valid IP address", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("vmess: DstIP %q is not a valid IP address", spec.DstIP)
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("vmess: TCP.MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
	}

	v := spec.Vmess
	if v == nil {
		return fmt.Errorf("vmess: VmessConfig is required")
	}

	// UUID validation (UUID验证)
	if v.UUID == "" {
		return fmt.Errorf("vmess: uuid required")
	}
	if _, err := parseUUID(v.UUID); err != nil {
		return fmt.Errorf("vmess: invalid uuid %q: %w", v.UUID, err)
	}

	// Encryption validation (加密算法验证)
	enc := normalizeEncryption(v.Encryption)
	if enc != "" && !supportedEncryptions[enc] {
		return fmt.Errorf("vmess: unsupported encryption %q (supported: aead_chacha20_poly1305, aead_aes_128_gcm, legacy_aes_128_cfb)", v.Encryption)
	}

	// alterId validation (AlterID验证)
	if isAEADEncryption(enc) && v.AlterID > 0 {
		// AEAD with alter_id>0: warn but still generate (test expectation: server rejects)
	}
	if enc == "legacy_aes_128_cfb" && v.AlterID == 0 {
		// Legacy with alter_id=0: warn but still generate
	}

	// Command validation (命令字节验证)
	if v.Command != 0 && v.Command != CmdTCP && v.Command != CmdUDP && v.Command != CmdMUX {
		return fmt.Errorf("vmess: invalid command 0x%02x (must be 0x01=TCP, 0x02=UDP, 0x03=MUX)", v.Command)
	}

	// Address validation (地址验证)
	if v.Address != "" {
		if err := validateAddress(v.AddressType, v.Address); err != nil {
			return fmt.Errorf("vmess: %w", err)
		}
	} else if v.AddressType != 0 {
		return fmt.Errorf("vmess: address_type set but address is empty")
	}

	// Port validation (端口验证)
	if v.Port == 0 {
		return fmt.Errorf("vmess: port required")
	}
	if v.Port > MaxPayloadLen {
		return fmt.Errorf("vmess: port %d exceeds max 65535", v.Port)
	}

	// HeaderPadLen validation (头部填充长度验证)
	if v.HeaderPadLen > MaxHeaderPadLen {
		return fmt.Errorf("vmess: header_pad_len %d exceeds max %d", v.HeaderPadLen, MaxHeaderPadLen)
	}

	// Payload length validation (载荷长度验证)
	if len(v.Payload) > MaxPayloadLen && isAEADEncryption(enc) {
		return fmt.Errorf("vmess: payload too large for AEAD (%d bytes, max %d)", len(v.Payload), MaxPayloadLen)
	}
	if len(v.ResponsePayload) > MaxPayloadLen && isAEADEncryption(enc) {
		return fmt.Errorf("vmess: response payload too large (%d bytes, max %d)", len(v.ResponsePayload), MaxPayloadLen)
	}

	// MuxStreams validation (MUX多路复用流验证)
	for i, ms := range v.MuxStreams {
		if ms.SessionID == 0 {
			return fmt.Errorf("vmess: MuxStreams[%d].SessionID must be non-zero", i)
		}
		for j, f := range ms.Frames {
			if f.Status < MuxStatusNEW || f.Status > MuxStatusKEEPALIVE {
				return fmt.Errorf("vmess: MuxStreams[%d].Frames[%d].Status 0x%02x invalid", i, j, f.Status)
			}
		}
	}

	return nil
}

// validateAddress validates the address fields.
func validateAddress(addrType uint8, addr string) error {
	switch addrType {
	case AddrTypeIPv4:
		if net.ParseIP(addr) == nil || net.ParseIP(addr).To4() == nil {
			return fmt.Errorf("invalid IPv4 address %q", addr)
		}
	case AddrTypeIPv6:
		if net.ParseIP(addr) == nil || net.ParseIP(addr).To16() == nil {
			return fmt.Errorf("invalid IPv6 address %q", addr)
		}
	case AddrTypeDomain:
		if addr == "" {
			return fmt.Errorf("domain address cannot be empty")
		}
		if len(addr) > MaxDomainLen {
			return fmt.Errorf("domain too long (%d bytes, max %d)", len(addr), MaxDomainLen)
		}
	case 0:
		// Auto-detect: validate by parsing
		if ip := net.ParseIP(addr); ip != nil {
			return nil
		}
		if addr == "" {
			return fmt.Errorf("address cannot be empty")
		}
		if len(addr) > MaxDomainLen {
			return fmt.Errorf("domain too long (%d bytes, max %d)", len(addr), MaxDomainLen)
		}
	default:
		return fmt.Errorf("invalid address_type 0x%02x (must be 0x01=IPv4, 0x02=Domain, 0x03=IPv6)", addrType)
	}
	return nil
}

// Plan generates packet configs for a VMess flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		v := spec.Vmess
		if v == nil {
			v = &core.VmessConfig{}
		}

		// Resolve defaults (默认值解析)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		windowSize := uint16(65535)
		if spec.TCP != nil && spec.TCP.WindowSize > 0 {
			windowSize = spec.TCP.WindowSize
		}
		enc := normalizeEncryption(v.Encryption)
		if enc == "" {
			enc = "aead_chacha20_poly1305"
		}
		cmd := v.Command
		if cmd == 0 {
			cmd = CmdTCP
		}
		heartbeatCount := v.HeartbeatCount
		if heartbeatCount <= 0 {
			heartbeatCount = 1
		}

		// Resolve address type (地址类型解析)
		addrType, addrBytes := resolveAddress(v.AddressType, v.Address)

		// Parse UUID bytes (UUID字节解析)
		uuidBytes, _ := parseUUID(v.UUID)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(0)
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Random ISN per RFC 6528 (随机初始序列号).
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randUint32()
		}
		serverSeq := randUint32()

		// emit (发送包) sends a packet config to the channel.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol: "tcp",
				SrcPort: srcPort,
				DstPort: dstPort,
				Seq: seq,
				Ack: ack,
				Flags: flags,
				WindowSize: windowSize,
			}
			if flags == flagSYN || flags == flagSYNACK {
				l4.TCPOptions = synOptions(mss)
			}
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			cfg := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: direction,
				Timestamp: now,
				L2: core.L2Config{
					SrcMAC: srcMAC,
					DstMAC: dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: l3,
				L4: l4,
				Payload: payload,
				Metadata: meta,
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// emitUDP (发送UDP包) sends a UDP packet config.
		emitUDP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
			l3 := core.L3Base(srcIP, dstIP, 17, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol: "udp",
				SrcPort: srcPort,
				DstPort: dstPort,
			}
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			cfg := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: direction,
				Timestamp: now,
				L2: core.L2Config{
					SrcMAC: srcMAC,
					DstMAC: dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: l3,
				L4: l4,
				Payload: payload,
				Metadata: meta,
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// emitData (发送数据段) segments payload by MSS and emits each chunk
		// as a PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, flagPSHACK, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		emitFINACK := func(cSeq, sSeq uint32) {
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, cSeq, sSeq, flagFINACK, nil)
				cSeq++
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, sSeq, cSeq, flagACK, nil)
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, sSeq, cSeq, flagFINACK, nil)
				sSeq++
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, cSeq, sSeq, flagACK, nil)
			}

			// --- Determine transport mode (传输模式判断) ---
		isUDP := cmd == CmdUDP

		if isUDP {
			// === UDP mode (UDP模式) ===
			// Build VMess Request payload for UDP
			reqPayload := buildVMessRequestPayload(v, uuidBytes, enc, addrType, addrBytes)
			emitUDP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, reqPayload)

			// Build VMess Response payload for UDP
			respPayload := buildVMessResponsePayload(v, uuidBytes, enc)
			emitUDP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, respPayload)
			return
		}

		// === TCP mode (TCP模式) ===

		// --- TCP handshake (TCP三次握手) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, flagSYN, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagSYNACK, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagACK, nil)

		// --- Heartbeat mode (心跳模式) ---
		if v.Heartbeat {
			for i := 0; i < heartbeatCount; i++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Minimal VMess Request (最小VMess请求): HeaderPad=8, Payload=nil
				hbV := *v
				hbV.HeaderPadLen = 8
				hbV.Payload = nil

				reqPayload := buildVMessRequestPayload(&hbV, uuidBytes, enc, addrType, addrBytes)
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, reqPayload)

				// Empty VMess Response (空VMess响应)
				hbVresp := *v
				hbVresp.ResponsePayload = nil
				respPayload := buildVMessResponsePayload(&hbVresp, uuidBytes, enc)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, respPayload)
			}

			// Heartbeat mode skips regular request/response and MUX
			// (心跳模式跳过常规请求/响应和MUX) but still does teardown
			emitFINACK(clientSeq, serverSeq)
			return
		}

		// --- VMess Request (VMess请求) ---
		reqPayload := buildVMessRequestPayload(v, uuidBytes, enc, addrType, addrBytes)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, reqPayload)

		// If there is user payload data, emit it (请求载荷数据)
		if len(v.Payload) > 0 {
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, v.Payload)
		} else if isAEADEncryption(enc) && len(v.Payload) == 0 {
			// AEAD mode: emit empty chunk frame (2-byte length=0 + 16-byte tag)
			emptyChunk := make([]byte, 2+TagLen)
			rand.Read(emptyChunk[2:]) // random tag
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, emptyChunk)
		}

		// --- VMess Response (VMess响应) ---
		respPayload := buildVMessResponsePayload(v, uuidBytes, enc)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, respPayload)

		// If there is response payload data, emit it (响应载荷数据)
		if len(v.ResponsePayload) > 0 {
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, v.ResponsePayload)
		} else if isAEADEncryption(enc) && len(v.ResponsePayload) == 0 {
			// AEAD mode: emit empty response chunk
			emptyChunk := make([]byte, 2+TagLen)
			rand.Read(emptyChunk[2:])
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, emptyChunk)
		}

		// --- MUX mode (MUX多路复用模式) ---
		if cmd == CmdMUX && len(v.MuxStreams) > 0 {
			for _, ms := range v.MuxStreams {
				select {
				case <-ctx.Done():
					return
				default:
				}

				for _, frame := range ms.Frames {
					muxFrame := buildMUXFrame(ms.SessionID, frame, ms.TargetAddr, ms.TargetPort)
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, muxFrame)
				}
			}
		}

		// --- TCP teardown (TCP四次挥手) or RST (TCP重置) ---
		if spec.TCP != nil && spec.TCP.RST {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagRSTACK, nil)
		} else {
			emitFINACK(clientSeq, serverSeq)
		}

	}()

	return configChan, nil
}

// buildVMessRequestPayload builds the VMess Request wire format payload.
// Wire layout (AEAD mode):
//
//	[Version 1B][IV 16B][EncryptedBody (variable)][Payload (variable)][HMAC/Tag 16B]
//
// EncryptedBody layout (AEAD mode):
//
//	[UUID 16B][Version 1B][Cmd 1B][AddrType 1B][Addr N B][Port 2B][PadLen 1B][Pad PadLen B][PayloadLen 2B]
//
// EncryptedBody layout (Legacy mode):
//
//	[UUID 16B][AlterID 1B][Cmd 1B][AddrType 1B][Addr N B][Port 2B][PadLen 1B][Pad PadLen B]
func buildVMessRequestPayload(v *core.VmessConfig, uuidBytes []byte, enc string, addrType byte, addrBytes []byte) []byte {
	isAEAD := isAEADEncryption(enc)
	ver := byte(VersionAEAD)
	if enc == "legacy_aes_128_cfb" {
		ver = VersionLegacy
	}

	// Build the payload buffer
	var buf []byte

	// Version (协议版本, 1 byte)
	buf = append(buf, ver)

	// IV (初始化向量, 16 bytes)
	iv := make([]byte, IVLen)
	if isAEAD {
		// AEAD mode: 12B random nonce + 4B zero counter
		rand.Read(iv[:NonceLen])
		// offset 12-15 = 0x00000000 (counter initial value, 计数器初始值)
	} else {
		// Legacy mode: 16B all random
		rand.Read(iv)
	}
	buf = append(buf, iv...)

	// Encrypted Body (加密请求体) — build plaintext body then fill with random bytes
	bodyPlain := buildVMessRequestBodyPlain(v, uuidBytes, enc, addrType, addrBytes)
	// Encrypted body: same length as plaintext, filled with random (synth ciphertext, 合成密文)
	bodyEnc := make([]byte, len(bodyPlain))
	rand.Read(bodyEnc)
	buf = append(buf, bodyEnc...)

	// Payload (载荷) — synth ciphertext
	if len(v.Payload) > 0 {
		payloadEnc := make([]byte, len(v.Payload))
		rand.Read(payloadEnc)
		buf = append(buf, payloadEnc...)
	} else if isAEAD {
		// AEAD mode: emit empty payload frame (2B len=0 + 16B tag, even when no payload)
		// The PayloadLen in the body already accounts for 0 payload.
		// No extra bytes needed here since we handle it separately.
	}

	// HMAC / Tag (认证标签, 16 bytes)
	tag := make([]byte, TagLen)
	rand.Read(tag)
	buf = append(buf, tag...)

	return buf
}

// buildVMessRequestBodyPlain builds the plaintext body of the VMess Request
// (before "encryption" — i.e. the byte structure before AEAD opaque fill).
func buildVMessRequestBodyPlain(v *core.VmessConfig, uuidBytes []byte, enc string, addrType byte, addrBytes []byte) []byte {
	isAEAD := isAEADEncryption(enc)
	ver := byte(VersionAEAD)
	if enc == "legacy_aes_128_cfb" {
		ver = VersionLegacy
	}

	var body []byte

	// UUID (用户身份标识, 16 bytes)
	body = append(body, uuidBytes...)

	if !isAEAD {
		// Legacy mode: AlterID (变更标识, 1 byte) before Cmd. No Version
		// byte inside body (Version is only at outer offset 0 of request).
		body = append(body, byte(v.AlterID))
	} else {
		// AEAD mode: Version (明文字节, 1 byte) inside body — no alterId
		body = append(body, ver)
	}

	// Command (命令字节, 1 byte)
	cmd := v.Command
	if cmd == 0 {
		cmd = CmdTCP
	}
	body = append(body, cmd)

	// Address Type (地址类型, 1 byte)
	body = append(body, addrType)

	// Address (地址, variable)
	body = append(body, addrBytes...)

	// Port (端口, 2 bytes big-endian)
	body = append(body, byte(v.Port>>8), byte(v.Port))

	// Header Padding Length (头部填充长度, 1 byte)
	padLen := v.HeaderPadLen
	if padLen > MaxHeaderPadLen {
		padLen = 0
	}
	body = append(body, padLen)

	// Header Padding (头部填充, padLen bytes)
	pad := make([]byte, padLen)
	rand.Read(pad)
	body = append(body, pad...)

	// Payload Length (载荷长度, 2 bytes big-endian) — AEAD mode only
	if isAEAD {
		payloadLen := uint16(len(v.Payload))
		body = append(body, byte(payloadLen>>8), byte(payloadLen))
	}

	return body
}

// buildVMessResponsePayload builds the VMess Response wire format payload.
// Wire layout (AEAD mode):
//
//	[Version 1B][IV 16B][EncryptedBody (variable)][ResponsePayload (variable)][HMAC/Tag 16B]
//
// EncryptedBody layout (AEAD mode):
//
//	[UUID 16B][Version 1B][Cmd 1B][PadLen 1B][Pad PadLen B][ResponsePayloadLen 2B]
func buildVMessResponsePayload(v *core.VmessConfig, uuidBytes []byte, enc string) []byte {
	ver := byte(VersionAEAD)
	if enc == "legacy_aes_128_cfb" {
		ver = VersionLegacy
	}

	var buf []byte

	// Version (响应版本, 1 byte)
	buf = append(buf, ver)

	// IV (响应初始化向量, 16 bytes)
	iv := make([]byte, IVLen)
	rand.Read(iv)
	buf = append(buf, iv...)

	// Encrypted Body (加密响应体) — build plaintext then fill with random
	bodyPlain := buildVMessResponseBodyPlain(v, uuidBytes, enc)
	bodyEnc := make([]byte, len(bodyPlain))
	rand.Read(bodyEnc)
	buf = append(buf, bodyEnc...)

	// Response Payload (响应载荷) — synth ciphertext
	if len(v.ResponsePayload) > 0 {
		payloadEnc := make([]byte, len(v.ResponsePayload))
		rand.Read(payloadEnc)
		buf = append(buf, payloadEnc...)
	}

	// HMAC / Tag (认证标签, 16 bytes)
	tag := make([]byte, TagLen)
	rand.Read(tag)
	buf = append(buf, tag...)

	return buf
}

// buildVMessResponseBodyPlain builds the plaintext body of the VMess Response.
func buildVMessResponseBodyPlain(v *core.VmessConfig, uuidBytes []byte, enc string) []byte {
	isAEAD := isAEADEncryption(enc)
	ver := byte(VersionAEAD)
	if enc == "legacy_aes_128_cfb" {
		ver = VersionLegacy
	}

	var body []byte

	// UUID (回显客户端UUID, 16 bytes)
	body = append(body, uuidBytes...)

	// Version (响应版本, 1 byte)
	body = append(body, ver)

	// Command (响应命令, 1 byte) — echo request command
	cmd := v.Command
	if cmd == 0 {
		cmd = CmdTCP
	}
	body = append(body, cmd)

	// Response Header Padding Length (响应头填充长度, 1 byte)
	padLen := v.HeaderPadLen
	if padLen > MaxHeaderPadLen {
		padLen = 0
	}
	body = append(body, padLen)

	// Response Header Padding (响应头填充, padLen bytes)
	pad := make([]byte, padLen)
	rand.Read(pad)
	body = append(body, pad...)

	// Response Payload Length (响应载荷长度, 2 bytes big-endian) — AEAD mode only
	if isAEAD {
		respPayloadLen := uint16(len(v.ResponsePayload))
		body = append(body, byte(respPayloadLen>>8), byte(respPayloadLen))
	}

	return body
}

// buildMUXFrame builds a MUX frame payload.
// MUX frame layout: [session_id 2B big-endian][status 1B][length 2B big-endian][payload]
func buildMUXFrame(sessionID uint16, frame core.VmessMuxFrame, targetAddr string, targetPort uint16) []byte {
	var buf []byte

	// Session ID (会话标识, 2 bytes big-endian)
	buf = binary.BigEndian.AppendUint16(buf, sessionID)

	// Status (帧状态, 1 byte)
	buf = append(buf, frame.Status)

	// For NEW frame (status=0x01), the payload includes target address + port
	var framePayload []byte
	if frame.Status == MuxStatusNEW && targetAddr != "" {
		// Encode target address (编码目标地址)
		atyp, addr := encodeAddress(targetAddr)
		framePayload = append(framePayload, atyp)
		framePayload = append(framePayload, addr...)
		framePayload = binary.BigEndian.AppendUint16(framePayload, targetPort)
	} else {
		framePayload = append(framePayload, frame.Payload...)
	}

	// Length (长度, 2 bytes big-endian)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(framePayload)))

	// Payload (帧载荷)
	buf = append(buf, framePayload...)

	return buf
}

// resolveAddress returns the address type byte and encoded address bytes.
func resolveAddress(addrType uint8, addr string) (byte, []byte) {
	if addrType != 0 {
		// User-specified type (用户指定类型)
		switch addrType {
		case AddrTypeIPv4:
			if ip := net.ParseIP(addr); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					return AddrTypeIPv4, ip4
				}
			}
			return AddrTypeIPv4, []byte{0, 0, 0, 0}
		case AddrTypeIPv6:
			if ip := net.ParseIP(addr); ip != nil {
				if ip16 := ip.To16(); ip16 != nil {
					return AddrTypeIPv6, ip16
				}
			}
			return AddrTypeIPv6, make([]byte, 16)
		case AddrTypeDomain:
			return AddrTypeDomain, encodeDomain(addr)
		}
	}

	// Auto-detect (自动推导)
	return encodeAddress(addr)
}

// encodeAddress returns the address type byte and encoded address bytes for a
// given address string, auto-detecting the type.
func encodeAddress(addr string) (byte, []byte) {
	if addr == "" {
		return AddrTypeIPv4, []byte{0, 0, 0, 0}
	}

	if ip := net.ParseIP(addr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return AddrTypeIPv4, ip4
		}
		return AddrTypeIPv6, ip.To16()
	}

	// Domain name (域名)
	return AddrTypeDomain, encodeDomain(addr)
}

// encodeDomain returns a length-prefixed domain name (1B len + N bytes).
func encodeDomain(domain string) []byte {
	if len(domain) > MaxDomainLen {
		domain = domain[:MaxDomainLen]
	}
	b := make([]byte, 1+len(domain))
	b[0] = byte(len(domain))
	copy(b[1:], domain)
	return b
}

// parseUUID parses a UUID string into 16 bytes. Accepts:
// - Standard text form: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (36 chars with dashes)
// - Hex form: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" (32 chars, no dashes)
// - Uppercase variants also accepted
func parseUUID(s string) ([]byte, error) {
	// Remove dashes (去除连字符)
	s = strings.ReplaceAll(s, "-", "")

	if len(s) == 32 {
		// Hex form (十六进制形式)
		b := make([]byte, 16)
		for i := 0; i < 16; i++ {
			high := hexNibble(s[i*2])
			low := hexNibble(s[i*2+1])
			if high < 0 || low < 0 {
				return nil, fmt.Errorf("invalid hex character in UUID")
			}
			b[i] = byte(high<<4) | byte(low)
		}
		return b, nil
	}

	return nil, fmt.Errorf("UUID string must be 32 hex chars (with or without dashes), got %d chars", len(s))
}

// hexNibble converts a hex character to its nibble value (0-15), or -1 on invalid.
func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// normalizeEncryption normalizes the encryption name to lowercase.
func normalizeEncryption(enc string) string {
	return strings.ToLower(strings.TrimSpace(enc))
}

// segmentByMSS splits payload into chunks of at most mss bytes. Mirrors
// redis/shadowsocks segmentByMSS - duplicated to avoid import cycle.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	out := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		out = append(out, payload[:n])
		payload = payload[n:]
	}
	return out
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted. Mirrors redis/shadowsocks synOptions.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	return []core.TCPOption{
		{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: core.TCPOptWinScale, Data: []byte{0x07}},
		{Kind: core.TCPOptSACKPermit},
	}
}

// randUint32 returns a random uint32.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42 // fallback
	}
	return uint32(n.Uint64())
}