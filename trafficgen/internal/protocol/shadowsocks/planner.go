// Package shadowsocks implements the Shadowsocks protocol planner.
//
// Shadowsocks（影梭）is a SOCKS5-based proxy protocol with pluggable
// encryption, primarily used to bypass GFW (Great Firewall, 中国国家互联网
// 防火墙). The planner emits:
//
// TCP mode:
// 1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
// options.
// 2. Optional SOCKS5 handshake (RFC 1928): greeting -> method response ->
// [username/password sub-negotiation] -> request -> reply.
// 3. Optional HTTP obfuscation header (some shadowsocks-android forks).
// 4. Shadowsocks salt: 32 random bytes (skipped for cipher="none").
// 5. AEAD chunk loop: N chunks, each [encLen(2) + len_tag(16) + payload(N) + payload_tag(16)].
// cipher="none" omits tag.
// 6. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// UDP mode:
// 1. Per-datagram: salt(32) + AEAD(RSV|FRAG|ATYP|ADDR|PORT|PAYLOAD) + tag(16).
// cipher="none" omits salt and tag (plaintext).
//
// The planner does NOT implement real cryptography. Per design §2.7, it
// emits random (or zeros) bytes in encrypted-payload/tag slots, ensuring
// wire-conformant framing without cryptographic validity.
package shadowsocks

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
	// DefaultPort (默认端口) is the canonical Shadowsocks port (8388 per
	// shadowsocks-rust). The controller's mapToFlowSpec fills this in when
	// the user omits dst_port; the planner does not override it.
	DefaultPort = 8388

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	// Duplicated here to avoid an import cycle.
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// SaltLen (盐值长度) is the fixed AEAD salt length (32 bytes).
	SaltLen = 32

	// TagLen (认证标签长度) is the fixed AEAD auth tag length (16 bytes).
	TagLen = 16

	// MaxChunkPayload (每块最大负载) is the maximum payload per AEAD chunk (0x3FFF).
	MaxChunkPayload = 0x3FFF

	// NonceLen (Nonce长度) is the AEAD nonce length (12 bytes).
	NonceLen = 12

	// SOCKS5 VER (SOCKS5协议版本) is fixed 0x05 per RFC 1928.
	SOCKS5Ver = 0x05

	// SOCKS5AuthVer (SOCKS5认证子协商版本) is fixed 0x01 per RFC 1929.
	SOCKS5AuthVer = 0x01

	// SOCKS5 reserved byte (保留字节).
	SOCKS5RSV = 0x00

	// SOCKS5 CMD values (命令值).
	SOCKS5CmdConnect = 0x01 // CONNECT (连接)
	SOCKS5CmdBind = 0x02 // BIND (绑定)
	SOCKS5CmdUDPAssociate = 0x03 // UDP ASSOCIATE (UDP关联)

	// SOCKS5 ATYP values (地址类型).
	SOCKS5ATYPIPv4 = 0x01 // IPv4 address (IPv4地址)
	SOCKS5ATYPDomain = 0x03 // Domain name (域名)
	SOCKS5ATYPIPv6 = 0x04 // IPv6 address (IPv6地址)

	// SOCKS5 METHOD values (认证方法).
	SOCKS5MethodNoAuth = 0x00 // No authentication (无认证)
	SOCKS5MethodPassword = 0x02 // Username/password (用户名密码)
	SOCKS5MethodNoAcceptable = 0xFF // No acceptable methods (无可用方法)

	// SOCKS5 REP values (响应码).
	SOCKS5RepSuccess = 0x00 // Succeeded (成功)
	SOCKS5RepGeneralFailure = 0x01 // General SOCKS server failure (通用故障)
	SOCKS5RepNotAllowed = 0x02 // Connection not allowed (不允许)
	SOCKS5RepNetUnreachable = 0x03 // Network unreachable (网络不可达)
	SOCKS5RepHostUnreachable = 0x04 // Host unreachable (主机不可达)
	SOCKS5RepConnRefused = 0x05 // Connection refused (连接拒绝)
	SOCKS5RepTTLExpired = 0x06 // TTL expired (TTL超时)
	SOCKS5RepCmdNotSupported = 0x07 // Command not supported (命令不支持)
	SOCKS5RepAtypNotSupported = 0x08 // Address type not supported (地址类型不支持)

	// UDP RSV (UDP保留字段) fixed 0x0000 per shadowsocks-rust spec.
	UDPRSV = 0x0000

	// UDP FRAG (UDP分片) default 0x00 (single/only fragment).
	UDPFRAGSingle = 0x00
)

// supportedCiphers (支持的加密算法) lists all supported cipher names.
var supportedCiphers = map[string]bool{
	"aes-128-gcm": true,
	"aes-256-gcm": true,
	"chacha20-ietf-poly1305": true,
	"none": true,
	"2022-blake3-aes-128-gcm": true,
	"2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
}

// isAEADCipher returns true if the cipher uses AEAD framing (salt + tag).
// Empty cipher is treated as the default "aes-256-gcm" (AEAD).
func isAEADCipher(cipher string) bool {
	if cipher == "" {
		return true // default cipher is AEAD
	}
	return cipher != "none"
}

// isSIP022Cipher returns true if the cipher uses SIP022 AEAD 2022 framework.
func isSIP022Cipher(cipher string) bool {
	return strings.HasPrefix(cipher, "2022-blake3-")
}

// Planner implements the Shadowsocks protocol planner.
type Planner struct{}

// NewPlanner creates a new Shadowsocks planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "shadowsocks" }

// Validate validates a Shadowsocks flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("shadowsocks: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("shadowsocks: invalid DstIP %q", spec.DstIP)
		}
	}

	ss := spec.Shadowsocks
	if ss == nil {
		return fmt.Errorf("shadowsocks: ShadowsocksConfig is required")
	}

	// Cipher (加密算法) validation
	cipher := normalizeCipher(ss.Cipher)
	if cipher == "" {
		cipher = "aes-256-gcm"
	}
	if !supportedCiphers[cipher] {
		return fmt.Errorf("shadowsocks: unsupported cipher %q (supported: AES-n/none/2022-*)", ss.Cipher)
	}

	// Mode validation
	if ss.Mode != "" && ss.Mode != "tcp" && ss.Mode != "udp" {
		return fmt.Errorf("shadowsocks: invalid mode %q (must be tcp or udp)", ss.Mode)
	}

	// Obfuscation vs SOCKS5 mutual exclusion. Validated BEFORE
	// SOCKS5-specific checks so the mutual-exclusion error surfaces
	// first when both are set (otherwise DstPort=0 would mask it).
	if ss.Obfuscation == "http" {
		if ss.SOCKS5Handshake {
			return fmt.Errorf("shadowsocks: obfuscation=http is mutually exclusive with SOCKS5Handshake=true")
		}
		mode := normalizeMode(ss.Mode)
		if mode == "udp" {
			return fmt.Errorf("shadowsocks: obfuscation=http requires Mode=tcp")
		}
	}

	// MSS validation
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("shadowsocks: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
		}
	}

	// Chunk payload size validation
	if ss.ChunkPayloadSize > MaxChunkPayload {
		return fmt.Errorf("shadowsocks: ChunkPayloadSize %d exceeds max %d", ss.ChunkPayloadSize, MaxChunkPayload)
	}

	// SOCKS5 validation
	if ss.SOCKS5Handshake {
		// Validate auth method (validated before DstPort so password
		// missing-username errors surface first).
		if ss.SOCKS5AuthMethod == "password" {
			if ss.SOCKS5Username == "" {
				return fmt.Errorf("shadowsocks: SOCKS5Username required when SOCKS5AuthMethod=password")
			}
			if len(ss.SOCKS5Username) > 255 {
				return fmt.Errorf("shadowsocks: SOCKS5Username exceeds 255 bytes")
			}
			if ss.SOCKS5Password == "" {
				return fmt.Errorf("shadowsocks: SOCKS5Password required when SOCKS5AuthMethod=password")
			}
			if len(ss.SOCKS5Password) > 255 {
				return fmt.Errorf("shadowsocks: SOCKS5Password exceeds 255 bytes")
			}
		} else if ss.SOCKS5AuthMethod != "" && ss.SOCKS5AuthMethod != "none" {
			return fmt.Errorf("shadowsocks: unsupported SOCKS5AuthMethod %q (supported: none, password)", ss.SOCKS5AuthMethod)
		}

		// Validate CMD vs Mode (validate before DstPort so the
		// cmd/mode mismatch surfaces even when DstPort is also 0).
		cmd := normalizeSOCKS5Cmd(ss.SOCKS5Cmd)
		mode := normalizeMode(ss.Mode)
		if cmd == "udp_associate" && mode != "udp" {
			return fmt.Errorf("shadowsocks: CMD=udp_associate requires Mode=udp")
		}
		if cmd == "bind" && mode == "udp" {
			return fmt.Errorf("shadowsocks: CMD=bind is not valid with Mode=udp")
		}

		// Validate dst_port
		if ss.SOCKS5DstPort == 0 {
			return fmt.Errorf("shadowsocks: SOCKS5DstPort must be non-zero when SOCKS5Handshake=true")
		}

		// Validate dst_addr
		if ss.SOCKS5DstAddr != "" {
			if len(ss.SOCKS5DstAddr) > 255 && net.ParseIP(ss.SOCKS5DstAddr) == nil {
				return fmt.Errorf("shadowsocks: SOCKS5DstAddr exceeds 255 bytes for domain name")
			}
		}
	}

	return nil
}

// Plan generates packet configs for a Shadowsocks flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

			flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		ss := spec.Shadowsocks
		if ss == nil {
			ss = &core.ShadowsocksConfig{}
	}

	effectiveTTL := spec.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	// Resolve MSS
	mss := uint16(DefaultMSS)
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		mss = spec.TCP.MSS
	}
	synOpts := synOptions(mss)

	now := time.Now()
	packetIndex := uint64(0)
	ipID := uint16(0)
	nextIPID := func() uint16 {
		id := ipID
		ipID++
		return id
	}

	// Random ISN per RFC 6528.
	clientSeq := uint32(0)
	if spec.TCP != nil {
		clientSeq = spec.TCP.InitialSeq
	}
	if clientSeq == 0 {
		clientSeq = randUint32()
	}
	serverSeq := randUint32()

	winSize := uint16(65535)

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
			WindowSize: winSize,
		}
		if flags == 0x02 || flags == 0x12 {
			l4.TCPOptions = synOpts
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
			emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
			senderSeq += uint32(len(seg))
		}
		return senderSeq
	}

	// --- Determine mode (模式判断) ---
	mode := normalizeMode(ss.Mode)

	if mode == "udp" {
		// === UDP mode ===
		count := spec.Count
		if count <= 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			payloadSize := ss.ChunkPayloadSize
			if payloadSize <= 0 {
				if len(spec.Payload) > 0 {
					payloadSize = len(spec.Payload)
				} else {
					payloadSize = 0
				}
			}

			udpPayload := buildUDPPacket(ss, spec, payloadSize)

			// Build direction: default "up", but support response
			direction := "up"
			if spec.UDP != nil && spec.UDP.IsResponse {
				direction = "down"
			}
			emitUDP(direction, spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, udpPayload)
		}
		return
	}

	// === TCP mode ===

	// --- TCP handshake (TCP三次握手) ---
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
	clientSeq++
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
	serverSeq++
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

	// --- Optional SOCKS5 handshake (可选SOCKS5握手) ---
	if ss.SOCKS5Handshake {
		// 1. Greeting (握手请求)
		greeting := buildSOCKS5Greeting(ss)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, greeting)

		// 2. Method Response (方法响应, server -> client)
		methodResp := buildSOCKS5MethodResponse(ss)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, methodResp)

		// 3. Username/password sub-negotiation (用户名密码子协商, optional)
		if ss.SOCKS5AuthMethod == "password" {
			authReq := buildSOCKS5AuthRequest(ss)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authReq)

			// Auth response (认证响应, server -> client)
			authResp := buildSOCKS5AuthResponse()
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, authResp)
		}

		// 4. SOCKS5 Request (SOCKS5请求)
		socks5Req := buildSOCKS5Request(ss)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, socks5Req)

		// 5. SOCKS5 Reply (SOCKS5响应, server -> client)
		socks5Reply := buildSOCKS5Reply(ss)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, socks5Reply)
	}

	// --- Optional HTTP obfuscation (可选HTTP混淆) ---
	if ss.Obfuscation == "http" {
		obfHeader := buildHTTPObfuscation(ss)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, obfHeader)
	}

	// --- Shadowsocks Salt (影子盐值, 32 bytes) ---
	cipher := normalizeCipher(ss.Cipher)
	if isAEADCipher(cipher) {
		salt := make([]byte, SaltLen)
		if ss.PayloadBytesFormat == "zeros" {
			// zeros: keep zero-initialized
		} else {
			rand.Read(salt)
		}
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, salt)
	}

	// --- AEAD Chunk loop (AEAD数据块循环) ---
	// Determine chunk payload sizes. When Chunks > 0, use explicit count.
	// When Chunks == 0 and spec.Payload is provided, split the payload into
	// chunks of MaxChunkPayload (or ChunkPayloadSize if set).
	var chunkSizes []int
	if ss.Chunks > 0 {
		payloadSize := ss.ChunkPayloadSize
		if payloadSize <= 0 {
			if len(spec.Payload) > 0 {
				payloadSize = len(spec.Payload)
				if payloadSize > MaxChunkPayload {
					payloadSize = MaxChunkPayload
				}
			} else {
				payloadSize = 0
			}
		}
		for i := 0; i < ss.Chunks; i++ {
			chunkSizes = append(chunkSizes, payloadSize)
		}
	} else if len(spec.Payload) > 0 {
		chunkSize := ss.ChunkPayloadSize
		if chunkSize <= 0 || chunkSize > MaxChunkPayload {
			chunkSize = MaxChunkPayload
		}
		remaining := len(spec.Payload)
		for remaining > 0 {
			sz := chunkSize
			if sz > remaining {
				sz = remaining
			}
			chunkSizes = append(chunkSizes, sz)
			remaining -= sz
		}
	} else {
		chunkSizes = append(chunkSizes, ss.ChunkPayloadSize)
	}

	for _, sz := range chunkSizes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		chunk := buildAEADChunk(ss, sz)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, chunk)
	}

	// --- TCP teardown (TCP四次挥手) ---
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
	clientSeq++
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
	serverSeq++
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
}()

	return configChan, nil
}

// buildSOCKS5Greeting builds the SOCKS5 greeting message (RFC 1928 §3).
func buildSOCKS5Greeting(ss *core.ShadowsocksConfig) []byte {
	var methods []byte
	switch ss.SOCKS5AuthMethod {
	case "password":
		methods = []byte{0x02}
	default:
		methods = []byte{0x00}
	}
	msg := []byte{SOCKS5Ver, byte(len(methods))}
	msg = append(msg, methods...)
	return msg
}

// buildSOCKS5MethodResponse builds the SOCKS5 method response.
func buildSOCKS5MethodResponse(ss *core.ShadowsocksConfig) []byte {
	method := byte(SOCKS5MethodNoAuth)
	if ss.SOCKS5AuthMethod == "password" {
		method = SOCKS5MethodPassword
	}
	return []byte{SOCKS5Ver, method}
}

// buildSOCKS5AuthRequest builds the SOCKS5 username/password auth request
// per RFC 1929.
func buildSOCKS5AuthRequest(ss *core.ShadowsocksConfig) []byte {
	username := ss.SOCKS5Username
	if username == "" {
		username = "user"
	}
	password := ss.SOCKS5Password
	if password == "" {
		password = "pass"
	}
	msg := []byte{SOCKS5AuthVer, byte(len(username))}
	msg = append(msg, []byte(username)...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, []byte(password)...)
	return msg
}

// buildSOCKS5AuthResponse builds the SOCKS5 auth response (STATUS=0x00 success).
func buildSOCKS5AuthResponse() []byte {
	return []byte{SOCKS5AuthVer, 0x00}
}

// buildSOCKS5Request builds the SOCKS5 request per RFC 1928 §4.
func buildSOCKS5Request(ss *core.ShadowsocksConfig) []byte {
	cmd := socks5CmdValue(ss.SOCKS5Cmd)
	atyp, addr := socks5AddrFields(ss.SOCKS5DstAddr)
	port := ss.SOCKS5DstPort

	msg := []byte{SOCKS5Ver, cmd, SOCKS5RSV, atyp}
	msg = append(msg, addr...)
	msg = append(msg, byte(port>>8), byte(port))
	return msg
}

// buildSOCKS5Reply builds the SOCKS5 reply per RFC 1928 §6.
func buildSOCKS5Reply(ss *core.ShadowsocksConfig) []byte {
	// Default bind address: 0.0.0.0:0
	bndAddr := ss.SOCKS5BNDAddr
	bndPort := ss.SOCKS5BNDPort

	atyp := byte(SOCKS5ATYPIPv4)
	var addr []byte
	if bndAddr != "" {
		atyp, addr = socks5AddrFields(bndAddr)
	} else {
		addr = []byte{0x00, 0x00, 0x00, 0x00}
	}

	msg := []byte{SOCKS5Ver, SOCKS5RepSuccess, SOCKS5RSV, atyp}
	msg = append(msg, addr...)
	msg = append(msg, byte(bndPort>>8), byte(bndPort))
	return msg
}

// buildHTTPObfuscation builds the HTTP CONNECT obfuscation header.
func buildHTTPObfuscation(ss *core.ShadowsocksConfig) []byte {
	var sb strings.Builder

	obfMethod := ss.ObfMethod
	if obfMethod == "" {
		obfMethod = "CONNECT"
	}

	dstAddr := ss.SOCKS5DstAddr
	if dstAddr == "" {
		dstAddr = "example.com"
	}
	dstPort := ss.SOCKS5DstPort
	if dstPort == 0 {
		dstPort = 443
	}

	if obfMethod == "CONNECT" {
		sb.WriteString(fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\n", dstAddr, dstPort))
	} else {
		sb.WriteString("POST / HTTP/1.1\r\n")
	}
	sb.WriteString(fmt.Sprintf("Host: %s:%d\r\n", dstAddr, dstPort))

	// Custom headers
	for k, v := range ss.ObfHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	// Blank line (空行)
	sb.WriteString("\r\n")

	return []byte(sb.String())
}

// buildAEADChunk builds a single AEAD chunk.
// AEAD chunk layout (SIP003): [encrypted_len 2B][len_tag 16B][encrypted_payload NB][payload_tag 16B]
// Each chunk has TWO 16-byte auth tags: one for the encrypted length, one for
// the encrypted payload. Per shadowsocks.org AEAD spec, the length-prefix and
// the payload are each independently AEAD-encrypted, each producing its own tag.
// For cipher="none": [plain_len 2B][plain_payload NB] (no tags)
func buildAEADChunk(ss *core.ShadowsocksConfig, payloadSize int) []byte {
	cipher := normalizeCipher(ss.Cipher)
	isAEAD := isAEADCipher(cipher)

	// Payload bytes
	var payload []byte
	if payloadSize > 0 {
		payload = make([]byte, payloadSize)
		if ss.PayloadBytesFormat == "zeros" {
			// Already zero-filled
		} else if ss.FileSource != nil {
			// FileSource not supported in simple planner; fall through to random
			rand.Read(payload)
		} else {
			rand.Read(payload)
		}
	}

	if isAEAD {
		// AEAD chunk: [encLen 2B][len_tag 16B][payload N B][payload_tag 16B]
		// Encrypted length (加密长度): 2 bytes, AEAD output simulation
		encLen := make([]byte, 2)
		rand.Read(encLen)

		// Length auth tag (长度认证标签): 16 bytes
		lenTag := make([]byte, TagLen)
		rand.Read(lenTag)

		// Payload auth tag (载荷认证标签): 16 bytes
		payloadTag := make([]byte, TagLen)
		rand.Read(payloadTag)

		chunk := make([]byte, 0, 2+TagLen+len(payload)+TagLen)
		chunk = append(chunk, encLen...)
		chunk = append(chunk, lenTag...)
		chunk = append(chunk, payload...)
		chunk = append(chunk, payloadTag...)
		return chunk
	}

	// None cipher: [plain_len 2B][plain_payload NB] (no tags)
	encLen := make([]byte, 2)
	encLen[0] = byte(payloadSize >> 8)
	encLen[1] = byte(payloadSize)

	chunk := make([]byte, 0, 2+len(payload))
	chunk = append(chunk, encLen...)
	chunk = append(chunk, payload...)
	return chunk
}

// buildUDPPacket builds a single shadowsocks UDP relay packet.
// Layout: [salt 32B] [AEAD(RSV|FRAG|ATYP|ADDR|PORT|PAYLOAD)] for AEAD ciphers
// For none: [RSV|FRAG|ATYP|ADDR|PORT|PAYLOAD] (plaintext)
func buildUDPPacket(ss *core.ShadowsocksConfig, spec core.FlowSpec, payloadSize int) []byte {
	cipher := normalizeCipher(ss.Cipher)
	isAEAD := isAEADCipher(cipher)

	// Build plaintext header
	atyp, addr := socks5AddrFields(ss.SOCKS5DstAddr)
	port := ss.SOCKS5DstPort

	// Plaintext: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + PAYLOAD
	var plaintext []byte
	plaintext = binary.BigEndian.AppendUint16(plaintext, UDPRSV)
	plaintext = append(plaintext, ss.FRAG)
	plaintext = append(plaintext, atyp)
	plaintext = append(plaintext, addr...)
	plaintext = append(plaintext, byte(port>>8), byte(port))

	// Payload
	var payload []byte
	if payloadSize > 0 {
		payload = make([]byte, payloadSize)
		if ss.PayloadBytesFormat == "zeros" {
			// Zero-filled
		} else {
			rand.Read(payload)
		}
	}
	plaintext = append(plaintext, payload...)

	if isAEAD {
		// AEAD mode: salt(32) + AEAD(plaintext) + tag(16)
		salt := make([]byte, SaltLen)
		rand.Read(salt)

		// Encrypted output simulation: emit random bytes of correct length
		encrypted := make([]byte, len(plaintext))
		rand.Read(encrypted)

		tag := make([]byte, TagLen)
		rand.Read(tag)

		pkt := make([]byte, 0, SaltLen+len(encrypted)+TagLen)
		pkt = append(pkt, salt...)
		pkt = append(pkt, encrypted...)
		pkt = append(pkt, tag...)
		return pkt
	}

	// None cipher: plaintext directly
	return plaintext
}

// socks5CmdValue returns the SOCKS5 CMD byte value.
func socks5CmdValue(cmd string) byte {
	switch normalizeSOCKS5Cmd(cmd) {
	case "connect":
		return SOCKS5CmdConnect
	case "bind":
		return SOCKS5CmdBind
	case "udp_associate":
		return SOCKS5CmdUDPAssociate
	default:
		return SOCKS5CmdConnect
	}
}

// socks5AddrFields (SOCKS5地址字段) returns the ATYP byte and address bytes
// for the given address string.
func socks5AddrFields(addrStr string) (atyp byte, addr []byte) {
	if addrStr == "" {
		return SOCKS5ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}
	}

	// Try parse as IP
	if ip := net.ParseIP(addrStr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return SOCKS5ATYPIPv4, ip4
		}
		// IPv6
		return SOCKS5ATYPIPv6, ip.To16()
	}

	// Domain name (域名)
	domainLen := len(addrStr)
	if domainLen > 255 {
		domainLen = 255
	}
	addr = make([]byte, 1+domainLen)
	addr[0] = byte(domainLen)
	copy(addr[1:], addrStr[:domainLen])
	return SOCKS5ATYPDomain, addr
}

// normalizeCipher normalizes the cipher name to lowercase.
func normalizeCipher(cipher string) string {
	return strings.ToLower(strings.TrimSpace(cipher))
}

// normalizeMode normalizes the mode string.
func normalizeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "tcp"
	}
	return mode
}

// normalizeSOCKS5Cmd normalizes the SOCKS5 command string.
func normalizeSOCKS5Cmd(cmd string) string {
	return strings.ToLower(strings.TrimSpace(cmd))
}

// randUint32 returns a random uint32.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42 // fallback
	}
	return uint32(n.Uint64())
}

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}