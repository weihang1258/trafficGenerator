// Package openvpn implements the OpenVPN protocol planner.
//
// OpenVPN is a session-level, encrypted, layered protocol that wraps either UDP
// (--proto udp, default) or TCP-over-TLS (--proto tcp) and runs an OpenVPN-specific
// 控制通道 (control channel) 和数据通道 (data channel) on top. The planner emits
// P_CONTROL_HARD_RESET_CLIENT_V2 / SERVER_V2, P_DATA_V2, optional tls-auth HMAC,
// optional tls-crypt wrapped key, optional keepalive ping/pong, and teardown.
//
// Wire format (UDP mode):
//
//	[UDP header] [OpenVPN opcode+key_id(1B)] [session_id(3B V2/V3)] [packet_id(variadic)]
//	 [tls-auth HMAC(20B)] [tls-crypt wrap] [payload(TLS Record or encrypted data)]
//
// Encryption is NOT implemented: post-TLS-finished payload is opaque (dummy bytes).
// HMAC, tls-crypt auth-tag, AEAD IV, and AEAD tag are deterministic filler
// (0xAA/0xBB/0xCC/0xDD/0xEE), structurally correct but not cryptographically valid.
package openvpn

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL is the default IP TTL for OpenVPN packets.
	DefaultTTL = 64

	// DefaultPort is the default OpenVPN port (UDP/TCP 1194).
	DefaultPort = 1194

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum packet).
	MinMSS = 536

	// OpenVPN opcodes (opcode 编码)
	OpcodeHARDResetClientV1 uint8 = 1 // P_CONTROL_HARD_RESET_CLIENT_V1
	OpcodeHARDResetServerV1 uint8 = 2 // P_CONTROL_HARD_RESET_SERVER_V1
	OpcodeSOFTResetV1 uint8 = 3 // P_CONTROL_SOFT_RESET_V1
	OpcodeHARDResetClientV2 uint8 = 4 // P_CONTROL_HARD_RESET_CLIENT_V2
	OpcodeHARDResetServerV2 uint8 = 5 // P_CONTROL_HARD_RESET_SERVER_V2
	OpcodeHARDResetClientV3 uint8 = 6 // P_CONTROL_HARD_RESET_CLIENT_V3
	OpcodeDATAV1 uint8 = 7 // P_DATA_V1
	OpcodeDATAV2 uint8 = 9 // P_DATA_V2
)

const (
	// DefaultDataPayloadLen is the default P_DATA payload length in bytes.
	DefaultDataPayloadLen = 64
	// DefaultDataPacketCount is the default number of P_DATA packets per direction.
	DefaultDataPacketCount = 5
	// DefaultExitNotifyIntervalMS is the default interval between exit_notify packets in ms.
	DefaultExitNotifyIntervalMS = 1000
)

// validCiphers lists all supported data channel ciphers.
var validCiphers = map[string]bool{
	"BF-CBC": true, "AES-128-CBC": true, "AES-192-CBC": true, "AES-256-CBC": true,
	"DES-CBC": true, "DES-EDE3-CBC": true, "NONE": true,
	"AES-128-GCM": true, "AES-192-GCM": true, "AES-256-GCM": true,
	"CHACHA20-POLY1305": true,
}

// validAuthAlgs lists all supported HMAC algorithms.
var validAuthAlgs = map[string]int{
	"SHA1": 20,
	"SHA256": 32,
	"SHA512": 64,
	"MD5": 16,
	"none": 0,
}

// validTLSVersions lists all supported TLS versions.
var validTLSVersions = map[string]bool{
	"1.0": true, "1.1": true, "1.2": true, "1.3": true,
}

// Planner implements the OpenVPN protocol planner.
type Planner struct{}

// NewPlanner creates a new OpenVPN planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "openvpn" }

// Validate validates an OpenVPN flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}

	cfg := spec.OpenVPN
	if cfg == nil {
		return fmt.Errorf("openvpn config is required")
	}

	// 2. Proto validation (协议校验): empty|"udp"|"tcp"
	proto := cfg.Proto
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return fmt.Errorf("openvpn proto must be 'udp' or 'tcp', got %q", cfg.Proto)
	}

	// 3. DstPort default 1194
	if spec.DstPort == 0 {
		// default applied in Plan
	}

	// 4. Version validation (版本校验): empty|"1"|"2"|"3"
	ver := cfg.Version
	if ver == "" {
		ver = "2"
	}
	if ver != "1" && ver != "2" && ver != "3" {
		return fmt.Errorf("openvpn version must be '1', '2', or '3', got %q", cfg.Version)
	}

	// 5. key_id range: [0,31] for V1/V2, [0,7] for V3
	if ver == "3" && cfg.KeyID > 7 {
		return fmt.Errorf("V3 key_id max is 7, got %d", cfg.KeyID)
	}
	if ver != "3" && cfg.KeyID > 31 {
		return fmt.Errorf("key_id max is 31 for V1/V2, got %d", cfg.KeyID)
	}

	// 6. session_id must fit in 24 bits
	if cfg.SessionID > 0xFFFFFF {
		return fmt.Errorf("session_id must fit in 24 bits, got 0x%X", cfg.SessionID)
	}

	// 7. DataCipher validation (数据通道加密算法校验)
	if cfg.DataCipher != "" && !validCiphers[cfg.DataCipher] {
		return fmt.Errorf("unsupported data_cipher: %s", cfg.DataCipher)
	}

	// 8. AuthAlg validation (HMAC 算法校验)
	if cfg.AuthAlg != "" {
		if _, ok := validAuthAlgs[cfg.AuthAlg]; !ok {
			return fmt.Errorf("unsupported auth_alg: %s", cfg.AuthAlg)
		}
	}

	// 9. TLSVersion validation
	if cfg.TLSVersion != "" && !validTLSVersions[cfg.TLSVersion] {
		return fmt.Errorf("tls_version must be 1.0, 1.1, 1.2, or 1.3, got %q", cfg.TLSVersion)
	}

	// 10. tls_crypt_v2 requires tls_crypt
	if cfg.TLSCryptV2 && !cfg.TLSCrypt {
		return fmt.Errorf("tls_crypt_v2 requires tls_crypt=true")
	}

	// 11. V1 does not support tls_auth or tls_crypt
	if ver == "1" {
		if cfg.TLSAuth {
			return fmt.Errorf("V1 does not support tls_auth")
		}
		if cfg.TLSCrypt {
			return fmt.Errorf("V1 does not support tls_crypt")
		}
	}

	// 12. proto=udp requires spec.UDP
	if proto == "udp" && spec.UDP == nil {
		return fmt.Errorf("proto=udp requires spec.udp (UDPConfig)")
	}

	// 13. proto=tcp requires spec.TCP
	if proto == "tcp" && spec.TCP == nil {
		return fmt.Errorf("proto=tcp requires spec.tcp (TCPConfig)")
	}

	// 14. data_packet_count <= 1000
	if cfg.DataPacketCount > 1000 {
		return fmt.Errorf("data_packet_count must be <= 1000, got %d", cfg.DataPacketCount)
	}

	// 15. mssfix range [576, 1500]
	if cfg.Mssfix > 0 && cfg.Mssfix < 576 {
		return fmt.Errorf("mssfix must be >= 576, got %d", cfg.Mssfix)
	}
	if cfg.Mssfix > 1500 {
		return fmt.Errorf("mssfix must be <= 1500, got %d", cfg.Mssfix)
	}

	// 16. data_payload length <= 16384
	if len(cfg.DataPayload) > 16384 {
		return fmt.Errorf("data_payload must be <= 16384 bytes, got %d", len(cfg.DataPayload))
	}

	// 17. StaticKeyMode validation (静态密钥模式校验)
	if cfg.StaticKeyMode {
		if cfg.TLSAuth || cfg.TLSCrypt {
			return fmt.Errorf("static_key_mode is mutually exclusive with tls_auth/tls_crypt")
		}
		if cfg.KeyDirection > 1 {
			return fmt.Errorf("key_direction must be 0 or 1, got %d", cfg.KeyDirection)
		}
		if len(cfg.StaticKey) > 0 && len(cfg.StaticKey) != 256 {
			return fmt.Errorf("static_key must be exactly 256 bytes, got %d", len(cfg.StaticKey))
		}
	}

	// 18. AuthUserPass validation (用户名密码认证校验)
	if cfg.AuthUserPass {
		if len(cfg.AuthUser) < 1 || len(cfg.AuthUser) > 64 {
			return fmt.Errorf("auth_user must be 1..64 bytes, got %d", len(cfg.AuthUser))
		}
		if len(cfg.AuthPass) < 1 || len(cfg.AuthPass) > 64 {
			return fmt.Errorf("auth_pass must be 1..64 bytes, got %d", len(cfg.AuthPass))
		}
		// Check for control characters (控制字符检查)
		for i := 0; i < len(cfg.AuthUser); i++ {			if cfg.AuthUser[i] < 0x20 {				return fmt.Errorf("auth_user contains control characters at position %d", i)
			}
		}
	}

	// 19. FragmentSize validation (分片大小校验)
	if cfg.FragmentSize > 0 && cfg.FragmentSize < 64 {
		return fmt.Errorf("fragment_size must be in [64, 1500], got %d", cfg.FragmentSize)
	}
	if cfg.FragmentSize > 1500 {
		return fmt.Errorf("fragment_size must be <= 1500, got %d", cfg.FragmentSize)
	}

	// 20. Keepalive validation (心跳保活校验)
	if cfg.KeepalivePingInterval > 0 {
		if cfg.KeepalivePingRestart <= cfg.KeepalivePingInterval {
			return fmt.Errorf("keepalive ping must be less than restart")
		}
	}

	// 21. ExitNotify validation (显式退出通知校验)
	if cfg.ExitNotifyCount > 3 {
		return fmt.Errorf("exit_notify_count must be 0 or in [1, 3], got %d", cfg.ExitNotifyCount)
	}
	if cfg.ExitNotifyCount > 0 && proto != "udp" {
		return fmt.Errorf("exit_notify only valid for proto=udp")
	}

	// 22. TunMTU validation
	if cfg.TunMTU > 0 && cfg.TunMTU < 576 {
		return fmt.Errorf("tun_mtu below IPv4 minimum (576), got %d", cfg.TunMTU)
	}
	if cfg.TunMTU > 65535 {
		return fmt.Errorf("tun_mtu must be <= 65535, got %d", cfg.TunMTU)
	}

	// 23. MSS vs TunMTU conflict detection (MSS 与 TUN MTU 冲突检测)
	if cfg.Mssfix > 0 && cfg.TunMTU > 0 {
		isIPv6 := false
		if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) != nil {
			if net.ParseIP(spec.SrcIP).To4() == nil {
				isIPv6 = true
			}
		}
		overhead := 40 // IPv4 20 + TCP 20
		if isIPv6 {
			overhead = 60 // IPv6 40 + TCP 20
		}
		if cfg.TunMTU < uint16(overhead) {
			return fmt.Errorf("tun_mtu %d too small for overhead %d", cfg.TunMTU, overhead)
		}
		if int(cfg.Mssfix) > int(cfg.TunMTU)-overhead {
			return fmt.Errorf("mssfix %d exceeds tunnel capacity (tun_mtu %d - overhead %d = %d)",
				cfg.Mssfix, cfg.TunMTU, overhead, int(cfg.TunMTU)-overhead)
		}
	}

	// 24. MSS (TCP mode)
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	return nil
}

// Plan generates packet configs for an OpenVPN flow.
// 生成 OpenVPN 流的包配置 (packet configs).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)
	cfg := spec.OpenVPN
	if cfg == nil {
		cfg = &core.OpenVPNConfig{}
	}

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Resolve config defaults
		proto := cfg.Proto
		if proto == "" {
			proto = "udp"
		}
		ver := cfg.Version
		if ver == "" {
			ver = "2"
		}
		dstPort := spec.DstPort
		if dstPort == 0 {
			dstPort = DefaultPort
		}
		srcPort := spec.SrcPort
		if srcPort == 0 {
			srcPort = uint16(1024 + rand.Intn(64511))
		}

		keyID := cfg.KeyID
		sessionID := cfg.SessionID
		if sessionID == 0 {
			sessionID = uint32(rand.Intn(0x1000000)) // 3 bytes (24 bits)
		}
		peerSessionID := sessionID

		dataCipher := cfg.DataCipher
		if dataCipher == "" {
			dataCipher = "AES-256-CBC"
		}
		tlsVersion := cfg.TLSVersion
		if tlsVersion == "" {
			tlsVersion = "1.3"
		}
		tlsRole := cfg.TLSRole
		if tlsRole == "" {
			tlsRole = "client"
		}
		authAlg := cfg.AuthAlg
		if authAlg == "" {
			authAlg = "SHA1"
		}
		hmacLen := validAuthAlgs[authAlg]

		dataPacketCount := cfg.DataPacketCount
		if dataPacketCount <= 0 {
			dataPacketCount = DefaultDataPacketCount
		}
		dataPayload := cfg.DataPayload
		if len(dataPayload) == 0 && !cfg.StaticKeyMode {
			dataPayload = make([]byte, DefaultDataPayloadLen)
			for i := range dataPayload {
				dataPayload[i] = 0xDD // deterministic filler (确定性填充)
			}
		}

		// Determine if we use TCP mode
		isTCP := proto == "tcp"

		// TCP-specific state
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		winSize := uint16(65535)
		clientSeq := uint32(0)
		serverSeq := uint32(0)
		if isTCP {
			if spec.TCP != nil {
				clientSeq = spec.TCP.InitialSeq
			}
			if clientSeq == 0 {
				clientSeq = rand.Uint32()
			}
			serverSeq = rand.Uint32()
		}

		// emitPacket sends a single packet config to the channel.
		// 发送单个包配置到通道.
		emitPacket := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, l3Protocol uint8, tcpSeq, tcpAck uint32, tcpFlags uint8) {
			var l3 core.L3Config
			var l4 core.L4Config
			if isTCP {
				l3 = core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
				l4 = core.L4Config{
					Protocol: "tcp",
					SrcPort: srcPort,
					DstPort: dstPort,
					Seq: tcpSeq,
					Ack: tcpAck,
					Flags: tcpFlags,
					WindowSize: winSize,
				}
				if tcpFlags == 0x02 || tcpFlags == 0x12 {
					l4.TCPOptions = synOptions(mss)
				}
			} else {
				l3 = core.L3Base(srcIP, dstIP, 17, effectiveTTL, nextIPID(), spec)
				l4 = core.L4Config{
					Protocol: "udp",
					SrcPort: srcPort,
					DstPort: dstPort,
				}
			}
			configChan <- core.PacketConfig{
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
			}
			packetIndex++
		}

		// emitTCPData segments payload by MSS and emits each chunk as PSH-ACK.
		emitTCPData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq *uint32, payload []byte) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emitPacket(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, seg, 6, *senderSeq, *peerSeq, 0x18)
				*senderSeq += uint32(len(seg))
			}
		}

		// --- TCP handshake (TCP mode only) ---
		if isTCP {
			// SYN (client -> server)
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, 0, 0x02)
			clientSeq++
			// SYN-ACK (server -> client)
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x12)
			serverSeq++
			// ACK (client -> server)
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x10)
		}

		// --- StaticKeyMode (P2P 静态密钥模式, 无 TLS 握手) ---
		if cfg.StaticKeyMode {
			// Build static key payload (StaticKeyNonce 16B + StaticKeyCiphertext + StaticKeyHMAC 20B)
			staticKey := cfg.StaticKey
			if len(staticKey) == 0 {
				staticKey = make([]byte, 256)
				for i := range staticKey {
					staticKey[i] = 0xFF
				}
			}
			dataLen := len(dataPayload)
			if dataLen == 0 {
				dataLen = 64
			}
			// Per design: P_DATA_V1 with KeyDirection + StaticKeyNonce(16B) + StaticKeyCiphertext(N) + StaticKeyHMAC(20B)
			// In P2P mode, we use synth crypto (确定性填充): nonce=0xCC, ciphertext=0xDD, HMAC=0xAA
			nonce := make([]byte, 16)
			for i := range nonce {
				nonce[i] = 0xCC
			}
			ciphertext := make([]byte, dataLen)
			for i := range ciphertext {
				ciphertext[i] = 0xDD
			}
			hmac := make([]byte, 20)
			for i := range hmac {
				hmac[i] = 0xAA
			}

			// client->server P_DATA_V1
			clientPayload := buildDataV1(0, keyID, 0 /* packet_id */, dataPayload, dataCipher, hmacLen)
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, clientPayload, 6, clientSeq, serverSeq, 0x18)

			// server->client P_DATA_V1
			serverPayload := buildDataV1(0, keyID, 0, dataPayload, dataCipher, hmacLen)
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, serverPayload, 6, serverSeq, clientSeq, 0x18)

			// 如果配置了多个数据包, 发送更多 P_DATA_V1
			for i := 1; i < dataPacketCount; i++ {
				cp := buildDataV1(uint64(i), keyID, uint64(i), dataPayload, dataCipher, hmacLen)
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, cp, 6, clientSeq, serverSeq, 0x18)
				sp := buildDataV1(uint64(i), keyID, uint64(i), dataPayload, dataCipher, hmacLen)
				emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, sp, 6, serverSeq, clientSeq, 0x18)
			}
			return
		}

		// --- OpenVPN UDP-mode: each packet is a single UDP datagram ---
		// --- OpenVPN TCP-mode: each packet is sent over TCP stream ---

		// Build TLS inner payload (TLS 内部握手字节, 合成填充)
		clientHello := buildSynthClientHello(tlsVersion)
		serverHello := buildSynthServerHello(tlsVersion)

		// --- Step 1: P_CONTROL_HARD_RESET_CLIENT_V2 (opcode=4, 客户端握手) ---
		clientResetPayload := buildHardResetClientV2(keyID, sessionID, 0, cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, clientHello, isTCP)
		if isTCP {
			emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, clientResetPayload)
		} else {
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, clientResetPayload, 17, 0, 0, 0)
		}

		// --- Step 2: P_CONTROL_HARD_RESET_SERVER_V2 (opcode=5, 服务端响应) ---
		serverResetPayload := buildHardResetServerV2(keyID, sessionID, 0, cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, serverHello, isTCP)
		if isTCP {
			emitTCPData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, serverResetPayload)
		} else {
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, serverResetPayload, 17, 0, 0, 0)
		}

		// --- Step 3: AuthUserPass (用户名密码认证, TLS 握手完成后) ---
		if cfg.AuthUserPass {
			authPayload := buildAuthUserPass(cfg.AuthUser, cfg.AuthPass, tlsVersion)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, authPayload)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, authPayload, 17, 0, 0, 0)
			}
		}

		// --- Step 4: P_DATA_V2 packets (数据通道包) ---
		// client->server
		for i := 0; i < dataPacketCount; i++ {
			payload := dataPayload
			// Fragment if enabled (分片处理)
			encryptedPayload := buildEncryptedPayload(payload, dataCipher, hmacLen)

			var pkt []byte
			if cfg.FragmentSize > 0 && len(encryptedPayload) > int(cfg.FragmentSize) {
				// Fragment the data payload (应用层分片)
				pkt = buildFragmentedDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, cfg.FragmentSize, dataCipher, hmacLen)
			} else {
				// 如果启用了分片但 payload 小于分片大小, 也走 first fragment (单 fragment)
				if cfg.FragmentSize > 0 {
					fragFirst := buildFragmentHeader(0, uint16(i), uint16(len(encryptedPayload)))
					encryptedPayload = append(fragFirst, encryptedPayload...)
				}
				pkt = buildDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, dataCipher, hmacLen)
			}

			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, pkt)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, pkt, 17, 0, 0, 0)
			}
		}

		// server->client
		for i := 0; i < dataPacketCount; i++ {
			payload := dataPayload
			encryptedPayload := buildEncryptedPayload(payload, dataCipher, hmacLen)

			var pkt []byte
			if cfg.FragmentSize > 0 && len(encryptedPayload) > int(cfg.FragmentSize) {
				pkt = buildFragmentedDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, cfg.FragmentSize, dataCipher, hmacLen)
			} else {
				if cfg.FragmentSize > 0 {
					fragFirst := buildFragmentHeader(0, uint16(i), uint16(len(encryptedPayload)))
					encryptedPayload = append(fragFirst, encryptedPayload...)
				}
				pkt = buildDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, dataCipher, hmacLen)
			}

			if isTCP {
				emitTCPData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, pkt)
			} else {
				emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, pkt, 17, 0, 0, 0)
			}
		}

		// --- Step 5: Keepalive (心跳保活) ---
		if cfg.KeepalivePingInterval > 0 {
			// Emit one keepalive P_DATA_V2 (empty payload)
			keepalivePayload := buildEncryptedPayload(nil, dataCipher, hmacLen)
			kaPkt := buildDataV2(uint64(dataPacketCount), keyID, peerSessionID, keepalivePayload, dataCipher, hmacLen)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, kaPkt)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, kaPkt, 17, 0, 0, 0)
			}
		}

		// --- Step 6: SOFT_RESET (密钥重协商) ---
		if cfg.PerformSoftReset {
			newKeyID := keyID + 1
			softResetPayload := buildSoftReset(newKeyID, sessionID, uint64(dataPacketCount*2), cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, isTCP)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, softResetPayload)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, softResetPayload, 17, 0, 0, 0)
			}

			// Re-key data packets with new key_id
			for i := 0; i < dataPacketCount; i++ {
				encPayload := buildEncryptedPayload(dataPayload, dataCipher, hmacLen)
				pkt := buildDataV2(uint64(i), newKeyID, peerSessionID, encPayload, dataCipher, hmacLen)
				if isTCP {
					emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, pkt)
				} else {
					emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, pkt, 17, 0, 0, 0)
				}
			}
		}

		// --- Step 7: ExitNotify (显式退出通知, UDP only) ---
		if cfg.ExitNotifyCount > 0 {
			for i := uint8(0); i < cfg.ExitNotifyCount; i++ {
				exitPayload := []byte{0x05} // type=0x05 (exit_notify)
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, exitPayload, 17, 0, 0, 0)
			}
		}

		// --- Step 8: TCP teardown (TCP mode only) ---
		if isTCP {
			// Client FIN
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x11)
			clientSeq++
			// Server ACK
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x10)
			// Server FIN
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x11)
			serverSeq++
			// Client ACK
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x10)
		}
	}()

	return configChan, nil
}

// --- OpenVPN packet builders (包构建辅助函数) ---

// buildHardResetClientV2 builds the P_CONTROL_HARD_RESET_CLIENT_V2 packet bytes.
// 构建 P_CONTROL_HARD_RESET_CLIENT_V2 包字节.
func buildHardResetClientV2(keyID uint8, sessionID uint32, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, innerPayload []byte, isTCP bool) []byte {
	var b []byte
	// opcode + key_id: opcode=4, (4<<5)|(keyID&0x1F)
	b = append(b, (4<<5)|(keyID&0x1F))
	// session_id: 3 bytes BE
	b = append(b, byte(sessionID>>16), byte(sessionID>>8), byte(sessionID))
	// packet_id: V2 variadic
	b = append(b, writePktID(packetID)...)
	// tls-auth HMAC (if enabled)
	if tlsAuth {
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	}
	// tls-crypt wrapped key (if enabled)
	if tlsCrypt {
		wrappedKey := buildWrappedKey(tlsCryptV2)
		b = append(b, wrappedKey...)
	}
	// inner payload (TLS ClientHello)
	b = append(b, innerPayload...)
	return b
}

// buildHardResetServerV2 builds the P_CONTROL_HARD_RESET_SERVER_V2 packet bytes.
// 构建 P_CONTROL_HARD_RESET_SERVER_V2 包字节.
func buildHardResetServerV2(keyID uint8, sessionID uint32, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, innerPayload []byte, isTCP bool) []byte {
	var b []byte
	// opcode + key_id: opcode=5, (5<<5)|(keyID&0x1F)
	b = append(b, (5<<5)|(keyID&0x1F))
	// session_id: echo client's session_id (3 bytes BE)
	b = append(b, byte(sessionID>>16), byte(sessionID>>8), byte(sessionID))
	// packet_id: V2 variadic
	b = append(b, writePktID(packetID)...)
	// tls-auth HMAC (if enabled)
	if tlsAuth {
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	}
	// tls-crypt wrapped key (if enabled)
	if tlsCrypt {
		wrappedKey := buildWrappedKey(tlsCryptV2)
		b = append(b, wrappedKey...)
	}
	// inner payload (TLS ServerHello + ...)
	b = append(b, innerPayload...)
	return b
}

// buildSoftReset builds the P_CONTROL_SOFT_RESET_V1 packet bytes.
// 构建 P_CONTROL_SOFT_RESET_V1 包字节.
func buildSoftReset(newKeyID uint8, sessionID uint32, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, isTCP bool) []byte {
	var b []byte
	// opcode + key_id: opcode=3, (3<<5)|(newKeyID&0x1F)
	b = append(b, (3<<5)|(newKeyID&0x1F))
	// session_id: 3 bytes BE
	b = append(b, byte(sessionID>>16), byte(sessionID>>8), byte(sessionID))
	// packet_id: V2 variadic
	b = append(b, writePktID(packetID)...)
	// tls-auth HMAC (if enabled)
	if tlsAuth {
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	}
	// tls-crypt wrapped key (if enabled)
	if tlsCrypt {
		wrappedKey := buildWrappedKey(tlsCryptV2)
		b = append(b, wrappedKey...)
	}
	// payload: TLS re-handshake stub (合成 TLS 重协商 stub)
	b = append(b, 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00) // minimal TLS record
	return b
}

// buildDataV2 builds the P_DATA_V2 packet bytes.
// 构建 P_DATA_V2 包字节.
func buildDataV2(packetID uint64, keyID uint8, peerSessionID uint32, encryptedPayload []byte, cipher string, hmacLen int) []byte {
	var b []byte
	// opcode + key_id: P_DATA_V2 opcode=9, high 3 bits = 100b = 0x40
	b = append(b, 0x40|(keyID&0x1F))
	// peer_session_id: 3 bytes BE
	b = append(b, byte(peerSessionID>>16), byte(peerSessionID>>8), byte(peerSessionID))
	// packet_id: V2 variadic
	b = append(b, writePktID(packetID)...)
	// encrypted payload
	b = append(b, encryptedPayload...)
	return b
}

// buildDataV1 builds the P_DATA_V1 packet bytes.
// 构建 P_DATA_V1 包字节.
func buildDataV1(packetID uint64, keyID uint8, _ uint64, payload []byte, cipher string, hmacLen int) []byte {
	var b []byte
	// opcode + key_id: opcode=7, (7<<5)|(keyID&0x1F)
	b = append(b, (7<<5)|(keyID&0x1F))
	// packet_id: 4 bytes BE (V1 uses uint32)
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	// encrypted payload
	b = append(b, buildEncryptedPayload(payload, cipher, hmacLen)...)
	return b
}

// buildEncryptedPayload builds the encrypted data for P_DATA packet.
// 构建 P_DATA 加密负载 (合成填充, 不真实加密).
func buildEncryptedPayload(payload []byte, cipher string, hmacLen int) []byte {
	var b []byte
	switch cipher {
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305":
		// AEAD mode: nonce(12) + encrypted_pkt_id(4) + encrypted_payload + tag(16)
		nonce := make([]byte, 12)
		for i := range nonce {
			nonce[i] = 0xDD
		}
		b = append(b, nonce...)
		// encrypted_pkt_id
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		// encrypted_payload
		if len(payload) > 0 {
			encPayload := make([]byte, len(payload))
			for i := range encPayload {
				encPayload[i] = 0xDD
			}
			b = append(b, encPayload...)
		}
		// AEAD tag
		tag := make([]byte, 16)
		for i := range tag {
			tag[i] = 0xEE
		}
		b = append(b, tag...)
	case "BF-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		// CBC mode: IV(16) + encrypted_pkt_id(4) + encrypted_payload + HMAC(20)
		iv := make([]byte, 16)
		for i := range iv {
			iv[i] = 0xDD
		}
		b = append(b, iv...)
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		if len(payload) > 0 {
			encPayload := make([]byte, len(payload))
			for i := range encPayload {
				encPayload[i] = 0xDD
			}
			b = append(b, encPayload...)
		}
		// HMAC tag
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	case "DES-CBC", "DES-EDE3-CBC":
		// Legacy CBC: IV(8) + encrypted_pkt_id(4) + encrypted_payload + HMAC(20)
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = 0xDD
		}
		b = append(b, iv...)
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		if len(payload) > 0 {
			encPayload := make([]byte, len(payload))
			for i := range encPayload {
				encPayload[i] = 0xDD
			}
			b = append(b, encPayload...)
		}
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	case "NONE":
		// Null cipher: plaintext payload, no IV, no tag
		if len(payload) > 0 {
			b = append(b, payload...)
		}
	default:
		// Default to AES-256-CBC behavior
		iv := make([]byte, 16)
		for i := range iv {
			iv[i] = 0xDD
		}
		b = append(b, iv...)
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		if len(payload) > 0 {
			encPayload := make([]byte, len(payload))
			for i := range encPayload {
				encPayload[i] = 0xDD
			}
			b = append(b, encPayload...)
		}
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	}
	return b
}

// buildWrappedKey builds the tls-crypt wrapped key (合成 tls-crypt 包裹密钥).
func buildWrappedKey(tlsCryptV2 bool) []byte {
	var b []byte
	// tls-crypt-v2: wrapped_key_id (4 bytes BE) + length prefix (2 bytes BE)
	if tlsCryptV2 {
		// wrapped_key_id = 1
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		// length prefix = 80 (32+16+32)
		b = append(b, 0x00, 0x50)
	}
	// auth-tag(32) 0xBB filler
	authTag := make([]byte, 32)
	for i := range authTag {
		authTag[i] = 0xBB
	}
	b = append(b, authTag...)
	// IV(16) 0xCC filler
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0xCC
	}
	b = append(b, iv...)
	// cipher_key: encrypted packet_id(4) + payload (合成)
	cipherKey := make([]byte, 32)
	for i := range cipherKey {
		cipherKey[i] = 0xDD
	}
	b = append(b, cipherKey...)
	return b
}

// buildSynthClientHello builds a synthetic TLS ClientHello payload (合成 TLS ClientHello).
func buildSynthClientHello(tlsVersion string) []byte {
	tlsVer := tlsVersionBytes(tlsVersion)
	// TLS Record: ContentType=22, Version, Length, HandshakeType=1 (ClientHello)
	// Body: legacy_version(2) + random(32) + session_id(1+0) + cipher_suites(2) + compression(1) + extensions
	body := make([]byte, 0, 64)
	body = append(body, tlsVer[0], tlsVer[1]) // legacy_version
	// random (32 bytes 合成)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	body = append(body, random...)
	// session_id length = 0
	body = append(body, 0x00)
	// cipher_suites length = 2, TLS_AES_128_GCM_SHA256 (0x1301)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	// compression methods length = 1, null (0x00)
	body = append(body, 0x01, 0x00)
	// extensions length = 0
	body = append(body, 0x00, 0x00)

	// TLS Record header
	record := make([]byte, 0, 5+len(body))
	record = append(record, 0x16) // ContentType=22 (Handshake)
	record = append(record, tlsVer[0], tlsVer[1])
	record = append(record, byte(len(body)>>8), byte(len(body)))
	// Handshake header
	record = append(record, 0x01) // HandshakeType=1 (ClientHello)
	record = append(record, byte((len(body))>>16), byte((len(body))>>8), byte(len(body)))
	record = append(record, body...)
	return record
}

// buildSynthServerHello builds a synthetic TLS ServerHello payload (合成 TLS ServerHello).
func buildSynthServerHello(tlsVersion string) []byte {
	tlsVer := tlsVersionBytes(tlsVersion)
	// Simplified ServerHello body
	body := make([]byte, 0, 64)
	body = append(body, tlsVer[0], tlsVer[1]) // legacy_version
	// random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 0x10)
	}
	body = append(body, random...)
	// session_id length = 0
	body = append(body, 0x00)
	// cipher_suite = TLS_AES_128_GCM_SHA256 (0x1301)
	body = append(body, 0x13, 0x01)
	// compression = null (0x00)
	body = append(body, 0x00)
	// extensions
	if tlsVersion == "1.3" {
		// supported_versions extension
		body = append(body, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	} else {
		body = append(body, 0x00, 0x00)
	}

	// TLS Record header
	record := make([]byte, 0, 5+len(body))
	record = append(record, 0x16) // ContentType=22 (Handshake)
	record = append(record, tlsVer[0], tlsVer[1])
	record = append(record, byte(len(body)>>8), byte(len(body)))
	// Handshake header
	record = append(record, 0x02) // HandshakeType=2 (ServerHello)
	record = append(record, byte((len(body))>>16), byte((len(body))>>8), byte(len(body)))
	record = append(record, body...)
	return record
}

// buildAuthUserPass builds the TLS AppData for --auth-user-pass (用户名密码认证).
func buildAuthUserPass(username, password, tlsVersion string) []byte {
	tlsVer := tlsVersionBytes(tlsVersion)
	// TLS AppData (ContentType=23) carrying username\npassword
	plaintext := []byte(username)
	plaintext = append(plaintext, 0x0A) // newline
	plaintext = append(plaintext, []byte(password)...)

	record := make([]byte, 0, 5+len(plaintext))
	record = append(record, 0x17) // ContentType=23 (Application Data)
	record = append(record, tlsVer[0], tlsVer[1])
	record = append(record, byte(len(plaintext)>>8), byte(len(plaintext)))
	record = append(record, plaintext...)
	return record
}

// buildFragmentHeader builds the fragment header (1B info + 2B id + 2B size).
// 构建应用层分片头部 (fragment header).
// fragType: 0=first, 1=middle, 2=last
func buildFragmentHeader(fragType uint8, fragmentID uint16, fragmentSize uint16) []byte {
	// frag_info byte: bit 7 reserved(0), bit 6-5 frag_type, bit 4-0 fragment_id_low5
	var fragInfo byte
	switch fragType {
	case 0:
		fragInfo = 0x00 // first
	case 1:
		fragInfo = 0x20 // middle (bit 5=1)
	case 2:
		fragInfo = 0x40 // last (bit 6=1)
	}
	return []byte{fragInfo, byte(fragmentID >> 8), byte(fragmentID), byte(fragmentSize >> 8), byte(fragmentSize)}
}

// buildFragmentedDataV2 builds P_DATA_V2 with application-layer fragmentation.
// 构建带应用层分片的 P_DATA_V2.
func buildFragmentedDataV2(packetID uint64, keyID uint8, peerSessionID uint32, data []byte, fragmentSize uint16, cipher string, hmacLen int) []byte {
	var fragments []byte
	fragmentID := uint16(packetID)
	totalLen := len(data)
	offset := 0
	fragmentIndex := 0
	for offset < totalLen {
		end := offset + int(fragmentSize)
		if end > totalLen {
			end = totalLen
		}
		chunk := data[offset:end]
		fragType := uint8(1) // middle
		if offset == 0 {
			fragType = 0 // first
		}
		if end >= totalLen {
			fragType = 2 // last
		}
		fragHeader := buildFragmentHeader(fragType, fragmentID, uint16(len(chunk)))
		fragments = append(fragments, fragHeader...)
		fragments = append(fragments, chunk...)
		fragmentIndex++
		offset = end
	}

	// Build P_DATA_V2 with fragments as payload
	var b []byte
	// opcode + key_id: P_DATA_V2 opcode=9, high 3 bits = 100b = 0x40
	b = append(b, 0x40|(keyID&0x1F))
	// peer_session_id: 3 bytes BE
	b = append(b, byte(peerSessionID>>16), byte(peerSessionID>>8), byte(peerSessionID))
	// packet_id: V2 variadic
	b = append(b, writePktID(packetID)...)
	// fragmented payload
	b = append(b, fragments...)
	return b
}

// writePktID encodes a packet ID as V2 variadic encoding (V2 变长编码).
// OpenSourc openvpn-2.4 pkt_id_write: 0-4 bytes header + data.
func writePktID(packetID uint64) []byte {
	switch {
	case packetID < 0x80:
		// 1 byte: 0x00-0x7F
		return []byte{byte(packetID)}
	case packetID < 0x4000:
		// 2 bytes: 0x80 | (packetID >> 8), packetID & 0xFF
		return []byte{0x80 | byte(packetID>>8), byte(packetID)}
	case packetID < 0x200000:
		// 3 bytes
		return []byte{0xC0 | byte(packetID>>16), byte(packetID >> 8), byte(packetID)}
	case packetID < 0x10000000:
		// 4 bytes
		return []byte{0xE0 | byte(packetID>>24), byte(packetID >> 16), byte(packetID >> 8), byte(packetID)}
	case packetID < 0x800000000:
		// 5 bytes
		return []byte{0xF0 | byte(packetID>>32), byte(packetID >> 24), byte(packetID >> 16), byte(packetID >> 8), byte(packetID)}
	case packetID < 0x40000000000:
		// 6 bytes
		return []byte{0xF8 | byte(packetID>>40), byte(packetID >> 32), byte(packetID >> 24), byte(packetID >> 16), byte(packetID >> 8), byte(packetID)}
	case packetID < 0x2000000000000:
		// 7 bytes
		return []byte{0xFC | byte(packetID>>48), byte(packetID >> 40), byte(packetID >> 32), byte(packetID >> 24), byte(packetID >> 16), byte(packetID >> 8), byte(packetID)}
	default:
		// 8 bytes (max 56-bit)
		return []byte{0xFE, byte(packetID >> 48), byte(packetID >> 40), byte(packetID >> 32), byte(packetID >> 24), byte(packetID >> 16), byte(packetID >> 8), byte(packetID)}
	}
}

// tlsVersionBytes converts TLS version string to 2-byte version bytes.
// TLS 版本字符串转 2 字节版本号.
func tlsVersionBytes(version string) []byte {
	switch version {
	case "1.0":
		return []byte{0x03, 0x01}
	case "1.1":
		return []byte{0x03, 0x02}
	case "1.2":
		return []byte{0x03, 0x03}
	case "1.3":
		return []byte{0x03, 0x03} // legacy_version = 1.2
	default:
		return []byte{0x03, 0x03}
	}
}

// segmentByMSS splits payload into chunks of at most mss bytes.
// The last chunk may be smaller. Returns one empty chunk when payload is empty.
// Mirrors internal/protocol/sip.segmentByMSS.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	var segments [][]byte
	for len(payload) > 0 {
		segSize := mss
		if len(payload) < segSize {
			segSize = len(payload)
		}
		segments = append(segments, payload[:segSize])
		payload = payload[segSize:]
	}
	return segments
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and SACK-Permitted.
// Mirrors internal/protocol/sip.synOptions.
func synOptions(mss uint16) []core.TCPOption {
	return []core.TCPOption{
		{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: core.TCPOptWinScale, Data: []byte{7}},
		{Kind: core.TCPOptSACKPermit},
	}
}