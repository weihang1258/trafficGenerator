// Package openvpn implements the OpenVPN protocol planner.
//
// OpenVPN is a session-level, encrypted, layered protocol that wraps either UDP
// (--proto udp, default) or TCP-over-TLS (--proto tcp) and runs an OpenVPN-specific
// 控制通道 (control channel) 和数据通道 (data channel) on top. The planner emits
// P_CONTROL_HARD_RESET_CLIENT_V2 / SERVER_V2, P_DATA_V2, optional tls-auth HMAC,
// optional tls-crypt wrapped key, optional keepalive ping/pong, and teardown.
//
// Wire format (UDP mode, verified against OpenVPN src/openvpn/ssl_pkt.c /
// ssl_pkt.h and Wireshark epan/dissectors/packet-openvpn.c):
//
//	P_CONTROL (no tls-auth): opcode|key_id(1B) | session_id(8B) |
//	  ack_count(1B) | ack_packet_id[ack_count](4B each) |
//	  remote_session_id(8B, if ack_count>0) | message_packet_id(4B) | TLS payload
//	P_CONTROL (tls-auth): opcode|key_id(1B) | session_id(8B) | hmac(H) |
//	  replay_packet_id(4B) | net_time(4B) | ack_count(1B) | ... | payload
//	P_CONTROL (tls-crypt): opcode|key_id(1B) | session_id(8B) | encrypted_body
//	P_DATA_V1: opcode|key_id(1B) | encrypted_payload (no session_id, no packet_id)
//	P_DATA_V2: opcode|key_id(1B) | peer_id(3B) | encrypted_payload (no packet_id)
//
// Header byte = (opcode << 3) | (key_id & 0x07) [opcode in high 5 bits,
// key_id in low 3 bits, P_OPCODE_SHIFT=3, P_KEY_ID_MASK=0x07].
//
// Encryption is NOT implemented: post-TLS-finished payload is opaque (dummy bytes).
// HMAC, tls-crypt auth-tag, AEAD IV, and AEAD tag are deterministic filler
// (0xAA/0xBB/0xCC/0xDD/0xEE), structurally correct but not cryptographically valid.
package openvpn

import (
	"context"
	"encoding/binary"
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

	// OpenVPN opcodes (opcode 编码). Values are the REAL OpenVPN wire values
	// from src/openvpn/ssl_pkt.h, NOT the simplified/legacy numbers used in
	// earlier revisions of this file.
	OpcodeHARDResetClientV1 uint8 = 1  // P_CONTROL_HARD_RESET_CLIENT_V1
	OpcodeHARDResetServerV1 uint8 = 2  // P_CONTROL_HARD_RESET_SERVER_V1
	OpcodeSOFTResetV1   uint8 = 3  // P_CONTROL_SOFT_RESET_V1
	OpcodeControlV1     uint8 = 4  // P_CONTROL_V1
	OpcodeACKV1         uint8 = 5  // P_ACK_V1
	OpcodeDATAV1        uint8 = 6  // P_DATA_V1
	OpcodeHARDResetClientV2 uint8 = 7  // P_CONTROL_HARD_RESET_CLIENT_V2
	OpcodeHARDResetServerV2 uint8 = 8  // P_CONTROL_HARD_RESET_SERVER_V2
	OpcodeDATAV2        uint8 = 9  // P_DATA_V2
	OpcodeHARDResetClientV3 uint8 = 10 // P_CONTROL_HARD_RESET_CLIENT_V3
	OpcodeControlWKCV1  uint8 = 11 // P_CONTROL_WKC_V1

	// P_OPCODE_SHIFT and P_KEY_ID_MASK from src/openvpn/ssl_pkt.h. The
	// header byte is (opcode << P_OPCODE_SHIFT) | (key_id & P_KEY_ID_MASK),
	// i.e. opcode in the high 5 bits and key_id in the low 3 bits.
	POpcodeShift  = 3
	PKeyIDMask    = 0x07
	// SIDSize is the OpenVPN session ID size in bytes (src/openvpn/ssl_pkt.h
	// SID_SIZE). Parsed as 8 bytes by Wireshark for all control/ack opcodes.
	SIDSize = 8
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

	// 5. key_id range: real OpenVPN uses a 3-bit key_id (P_KEY_ID_MASK=0x07)
	// for ALL versions (src/openvpn/ssl_pkt.h). Valid range is [0,7].
	if cfg.KeyID > 7 {
		return fmt.Errorf("key_id max is 7 (3-bit field), got %d", cfg.KeyID)
	}

	// 6. session_id is 8 bytes (SID_SIZE). Any uint64 value is valid; 0 is
	// treated as "random" in Plan(). (Real OpenVPN session_id is 8 bytes;
	// no bit-width constraint beyond the uint64 range.)

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

	// 12. proto=udp runs over UDP but the planner doesn't read spec.UDP
	// (it emits raw datagrams via the L4 dispatcher); only spec.TCP is
	// consulted, and only in TCP mode. So we don't require spec.UDP here.
	// The case "openvpn" branch in mapToFlowSpec also doesn't parse cfg["udp"]
	// into spec.UDP, which would otherwise make every UDP-mode spec fail.

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

	// 25. InnerIPPackets validation (内层 IP 业务流校验)
	if cfg.StaticKeyMode && len(cfg.InnerIPPackets) > 0 {
		return fmt.Errorf("inner_ip_packets is not supported in static_key_mode (static-key mode uses P_DATA_V1 with its own data path; inner IP business is for the TLS-mode data channel)")
	}
	for i := range cfg.InnerIPPackets {
		if err := validateInnerIP(&cfg.InnerIPPackets[i]); err != nil {
			return fmt.Errorf("inner_ip_packets[%d]: %w", i, err)
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
			sessionID = rand.Uint64() // 8 bytes (SID_SIZE)
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
		// 发送单个包配置到通道. meta may be nil.
		emitPacket := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, l3Protocol uint8, tcpSeq, tcpAck uint32, tcpFlags uint8, meta map[string]interface{}) {
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
				Metadata: meta,
			}
			packetIndex++
		}

		// emitTCPData segments payload by MSS and emits each chunk as PSH-ACK.
		//
		// OpenVPN-over-TCP framing: each OpenVPN packet is prefixed with a
		// 2-byte big-endian length (the byte count of the following OpenVPN
		// packet, excluding the prefix itself) so the receiver can delimit
		// individual OpenVPN packets on the TCP byte stream. This matches the
		// real OpenVPN protocol (src/openvpn/mtu.c frame_link_mtu_set +
		// forward.c). UDP mode needs no prefix (datagrams are self-delimiting
		// and do not go through this function).
		emitTCPData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq *uint32, payload []byte, meta map[string]interface{}) {
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
			framed := make([]byte, 0, 2+len(payload))
			framed = append(framed, lenBuf[:]...)
			framed = append(framed, payload...)
			for _, seg := range segmentByMSS(framed, int(mss)) {
				emitPacket(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, seg, 6, *senderSeq, *peerSeq, 0x18, meta)
				*senderSeq += uint32(len(seg))
			}
		}

		// --- TCP handshake (TCP mode only) ---
		if isTCP {
			// SYN (client -> server)
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, 0, 0x02, nil)
			clientSeq++
			// SYN-ACK (server -> client)
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x12, nil)
			serverSeq++
			// ACK (client -> server)
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x10, nil)
		}

		// --- StaticKeyMode (P2P 静态密钥模式, 无 TLS 握手) ---
		if cfg.StaticKeyMode {
			// Per design §2.10.2 + §6.3: P_DATA_V1 in static key mode contains
			// KeyDirection(implicit) + StaticKeyNonce(16B) + StaticKeyCiphertext(NB) + StaticKeyHMAC(20B).
			// P_DATA_V1 header: opcode+key_id(1B) + packet_id(4B BE).
			// Synth crypto (确定性填充): nonce=0xCC, ciphertext=0xDD, HMAC=0xAA.
			dataLen := len(dataPayload)
			if dataLen == 0 {
				dataLen = 64
			}

			// emitStaticKeyData emits a static-key P_DATA_V1 packet on the
			// appropriate transport. TCP mode routes through emitTCPData so the
			// 2-byte big-endian length prefix (OpenVPN TCP stream framing, see
			// emitTCPData doc) is applied — without it Wireshark cannot delimit
			// the P_DATA_V1 packet on the TCP byte stream. UDP mode sends the
			// raw P_DATA_V1 datagram (no prefix; datagrams are self-delimiting).
			emitStaticKeyData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, sPort, dPort uint16, senderSeq, peerSeq *uint32, packetID uint64) {
				payload := buildStaticKeyDataV1(packetID, keyID, dataLen)
				if isTCP {
					emitTCPData(direction, srcMAC, dstMAC, srcIP, dstIP, sPort, dPort, senderSeq, peerSeq, payload, nil)
				} else {
					emitPacket(direction, srcMAC, dstMAC, srcIP, dstIP, sPort, dPort, payload, 17, 0, 0, 0, nil)
				}
			}

			// client->server P_DATA_V1
			emitStaticKeyData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, 0)

			// server->client P_DATA_V1
			emitStaticKeyData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, 0)

			// 如果配置了多个数据包, 发送更多 P_DATA_V1
			for i := 1; i < dataPacketCount; i++ {
				emitStaticKeyData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, uint64(i))
				emitStaticKeyData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, uint64(i))
			}
			return
		}

		// --- OpenVPN UDP-mode: each packet is a single UDP datagram ---
		// --- OpenVPN TCP-mode: each packet is sent over TCP stream ---

		// Build TLS inner payload (TLS 内部握手字节, 合成填充)
		clientHello := buildSynthClientHello(tlsVersion)
		serverHello := buildSynthServerHello(tlsVersion)

		// --- Step 1: P_CONTROL_HARD_RESET_CLIENT (version-dependent opcode) ---
		// V1 -> opcode 1; V2 -> opcode 7; V3 -> opcode 10 (real ssl_pkt.h).
		var clientResetPayload []byte
		switch ver {
		case "1":
			clientResetPayload = buildHardResetClientV1(keyID, sessionID, 0, clientHello)
		case "3":
			clientResetPayload = buildHardResetClientV3(keyID, sessionID, 0, cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, clientHello, isTCP)
		default: // "2"
			clientResetPayload = buildHardResetClientV2(keyID, sessionID, 0, cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, clientHello, isTCP)
		}
		if isTCP {
			emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, clientResetPayload, nil)
		} else {
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, clientResetPayload, 17, 0, 0, 0, nil)
		}

		// --- Step 2: P_CONTROL_HARD_RESET_SERVER (V1 -> opcode 2; V2/V3 -> opcode 8) ---
		var serverResetPayload []byte
		switch ver {
		case "1":
			serverResetPayload = buildHardResetServerV1(keyID, sessionID, 0, serverHello)
		default: // "2" or "3" — V3 server uses V2 opcode=8
			serverResetPayload = buildHardResetServerV2(keyID, sessionID, 0, cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, serverHello, isTCP)
		}
		if isTCP {
			emitTCPData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, serverResetPayload, nil)
		} else {
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, serverResetPayload, 17, 0, 0, 0, nil)
		}

		// --- Step 3: AuthUserPass (用户名密码认证, TLS 握手完成后) ---
		if cfg.AuthUserPass {
			authPayload := buildAuthUserPass(cfg.AuthUser, cfg.AuthPass, tlsVersion)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, authPayload, nil)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, authPayload, 17, 0, 0, 0, nil)
			}
		}

		// --- Step 4: P_DATA packets (数据通道包) ---
		// V1 -> P_DATA_V1 (opcode=6); V2/V3 -> P_DATA_V2 (opcode=9).
		//
		// When InnerIPPackets is non-empty, each entry produces one
		// client->server P_DATA_V2 carrying the complete inner IP packet
		// in the encrypted-payload region (the inner IP bytes occupy the
		// ciphertext slot; IV/nonce/packet_id/tag remain synthetic
		// filler). This REPLACES the default DataPacketCount loop and
		// models the production tunnel scenario: tunneled ping/TCP/UDP
		// business traffic flowing through the OpenVPN data channel.
		// A matching server->client P_DATA_V2 is emitted per inner IP
		// entry for bidirectional tunnel traffic.
		isV1 := ver == "1"

		// innerIPMeta builds the metadata map recording the inner IP
		// 5-tuple so downstream consumers can identify the tunneled flow.
		innerIPMeta := func(idx int, ip *core.OpenVPNInnerIP) map[string]interface{} {
			proto := ip.Proto
			if proto == 0 {
				proto = 17 // default UDP
			}
			src := ip.SrcIP
			if src == "" {
				src = "10.10.10.1"
			}
			dst := ip.DstIP
			if dst == "" {
				dst = "10.10.10.2"
			}
			return map[string]interface{}{
				"openvpn_inner_src_ip": src,
				"openvpn_inner_dst_ip": dst,
				"openvpn_inner_proto":  proto,
				"openvpn_inner_index":  idx,
			}
		}

		// buildInnerDataV2 builds a P_DATA_V2 carrying an inner IP packet.
		// The inner IP bytes are placed in the ciphertext slot of the
		// encrypted payload (after the synthetic IV/nonce + packet_id and
		// before the HMAC/AEAD tag), so the inner IP is findable in the
		// encrypted region by tools that parse the decrypted body.
		buildInnerDataV2 := func(packetID uint64, ip *core.OpenVPNInnerIP) []byte {
			inner := buildInnerIPPacket(ip, uint16(packetID+1))
			encryptedPayload := buildEncryptedPayloadInner(inner, dataCipher, hmacLen)
			return buildDataV2(packetID, keyID, peerSessionID, encryptedPayload, dataCipher, hmacLen)
		}

		// innerIPPacketsCount drives the P_DATA loop count when configured.
		innerCount := len(cfg.InnerIPPackets)

		if innerCount > 0 {
			// client->server: one P_DATA_V2 per inner IP packet
			for i := 0; i < innerCount; i++ {
				ip := &cfg.InnerIPPackets[i]
				meta := innerIPMeta(i, ip)
				var pkt []byte
				if isV1 {
					// V1 P_DATA_V1: inner IP goes in the encrypted payload.
					inner := buildInnerIPPacket(ip, uint16(i+1))
					pkt = buildDataV1Inner(keyID, inner, dataCipher, hmacLen)
				} else {
					pkt = buildInnerDataV2(uint64(i), ip)
				}
				if isTCP {
					emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, pkt, meta)
				} else {
					emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, pkt, 17, 0, 0, 0, meta)
				}
			}

			// server->client: matching P_DATA_V2 per inner IP packet
			for i := 0; i < innerCount; i++ {
				ip := &cfg.InnerIPPackets[i]
				meta := innerIPMeta(i, ip)
				var pkt []byte
				if isV1 {
					inner := buildInnerIPPacket(ip, uint16(i+1))
					pkt = buildDataV1Inner(keyID, inner, dataCipher, hmacLen)
				} else {
					pkt = buildInnerDataV2(uint64(i), ip)
				}
				if isTCP {
					emitTCPData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, pkt, meta)
				} else {
					emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, pkt, 17, 0, 0, 0, meta)
				}
			}
		} else {
			// Legacy mode: DataPacketCount P_DATA packets with synthetic
			// 0xDD filler (backward compatible).
			// client->server
			for i := 0; i < dataPacketCount; i++ {
				payload := dataPayload

				var pkt []byte
				if isV1 {
					// buildDataV1 encrypts internally; pass raw payload.
					pkt = buildDataV1(uint64(i), keyID, uint64(i), payload, dataCipher, hmacLen)
				} else {
					// Fragment if enabled (分片处理)
					encryptedPayload := buildEncryptedPayload(payload, dataCipher, hmacLen)
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
				}

				if isTCP {
					emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, pkt, nil)
				} else {
					emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, pkt, 17, 0, 0, 0, nil)
				}
			}

			// server->client
			for i := 0; i < dataPacketCount; i++ {
				payload := dataPayload

				var pkt []byte
				if isV1 {
					pkt = buildDataV1(uint64(i), keyID, uint64(i), payload, dataCipher, hmacLen)
				} else {
					encryptedPayload := buildEncryptedPayload(payload, dataCipher, hmacLen)
					if cfg.FragmentSize > 0 && len(encryptedPayload) > int(cfg.FragmentSize) {
						pkt = buildFragmentedDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, cfg.FragmentSize, dataCipher, hmacLen)
					} else {
						if cfg.FragmentSize > 0 {
							fragFirst := buildFragmentHeader(0, uint16(i), uint16(len(encryptedPayload)))
							encryptedPayload = append(fragFirst, encryptedPayload...)
						}
						pkt = buildDataV2(uint64(i), keyID, peerSessionID, encryptedPayload, dataCipher, hmacLen)
					}
				}

				if isTCP {
					emitTCPData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, &serverSeq, &clientSeq, pkt, nil)
				} else {
					emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, pkt, 17, 0, 0, 0, nil)
				}
			}
		}

		// --- Step 5: Keepalive (心跳保活) ---
		if cfg.KeepalivePingInterval > 0 {
			// Emit one keepalive P_DATA_V2 (empty payload)
			keepalivePayload := buildEncryptedPayload(nil, dataCipher, hmacLen)
			kaPkt := buildDataV2(uint64(dataPacketCount), keyID, peerSessionID, keepalivePayload, dataCipher, hmacLen)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, kaPkt, nil)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, kaPkt, 17, 0, 0, 0, nil)
			}
		}

		// --- Step 6: SOFT_RESET (密钥重协商) ---
		if cfg.PerformSoftReset {
			newKeyID := keyID + 1
			softResetPayload := buildSoftReset(newKeyID, sessionID, uint64(dataPacketCount*2), cfg.TLSAuth, cfg.TLSCrypt, cfg.TLSCryptV2, hmacLen, isTCP)
			if isTCP {
				emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, softResetPayload, nil)
			} else {
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, softResetPayload, 17, 0, 0, 0, nil)
			}

			// Re-key data packets with new key_id
			for i := 0; i < dataPacketCount; i++ {
				encPayload := buildEncryptedPayload(dataPayload, dataCipher, hmacLen)
				pkt := buildDataV2(uint64(i), newKeyID, peerSessionID, encPayload, dataCipher, hmacLen)
				if isTCP {
					emitTCPData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, &clientSeq, &serverSeq, pkt, nil)
				} else {
					emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, pkt, 17, 0, 0, 0, nil)
				}
			}
		}

		// --- Step 7: ExitNotify (显式退出通知, UDP only) ---
		// Per design §2.10.5: exit_notify is a P_CONTROL message carrying
		// 1-byte type=0x05, not a bare 0x05 byte. We frame it as a
		// P_CONTROL_HARD_RESET_CLIENT_V2 with the exit_notify type in the
		// payload (the OpenVPN control channel requires an opcode header).
		if cfg.ExitNotifyCount > 0 {
			for i := uint8(0); i < cfg.ExitNotifyCount; i++ {
				exitPayload := buildExitNotify(keyID, sessionID, uint64(i))
				emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, exitPayload, 17, 0, 0, 0, nil)
			}
		}

		// --- Step 8: TCP teardown (TCP mode only) ---
		if isTCP {
			// Client FIN
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x11, nil)
			clientSeq++
			// Server ACK
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x10, nil)
			// Server FIN
			emitPacket("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, nil, 6, serverSeq, clientSeq, 0x11, nil)
			serverSeq++
			// Client ACK
			emitPacket("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, srcPort, dstPort, nil, 6, clientSeq, serverSeq, 0x10, nil)
		}
	}()

	return configChan, nil
}

// --- OpenVPN packet builders (包构建辅助函数) ---

// headerByte encodes the 1-byte OpenVPN header: opcode in the high 5 bits
// (shifted P_OPCODE_SHIFT=3) and key_id in the low 3 bits (masked
// P_KEY_ID_MASK=0x07). Mirrors src/openvpn/ssl_pkt.h.
func headerByte(opcode, keyID uint8) byte {
	return (opcode << POpcodeShift) | (keyID & PKeyIDMask)
}

// appendSessionID appends the 8-byte big-endian session_id (SID_SIZE) that
// Wireshark parses for all control/ack opcodes.
func appendSessionID(b []byte, sid uint64) []byte {
	return append(b,
		byte(sid>>56), byte(sid>>48), byte(sid>>40), byte(sid>>32),
		byte(sid>>24), byte(sid>>16), byte(sid>>8), byte(sid),
	)
}

// appendControlHeader writes the common control-packet header used by all
// P_CONTROL / P_ACK opcodes (V1/V2/V3) when tls-auth is NOT enabled. Per
// Wireshark packet-openvpn.c dissect_openvpn_msg_common, the on-wire layout
// is:
//
//	opcode|key_id(1B) | session_id(8B) | ack_count(1B) |
//	ack_packet_id[ack_count](4B each) |
//	remote_session_id(8B, only if ack_count>0 and >=8B remain) |
//	message_packet_id(4B, skipped for P_ACK_V1) | TLS payload
//
// For the synth generator we always emit ack_count=0 (no acks carried) and a
// single 4-byte message_packet_id. The remote_session_id field is omitted
// because ack_count==0.
func appendControlHeader(b []byte, opcode, keyID uint8, sid uint64, messagePacketID uint32) []byte {
	b = append(b, headerByte(opcode, keyID))
	b = appendSessionID(b, sid)
	b = append(b, 0x00) // ack_count = 0
	// No ack array, no remote_session_id (ack_count == 0).
	// message_packet_id (4B BE), present for all non-ACK opcodes.
	b = append(b, byte(messagePacketID>>24), byte(messagePacketID>>16),
		byte(messagePacketID>>8), byte(messagePacketID))
	return b
}

// appendControlHeaderTLSAuth writes the control-packet header when tls-auth
// is enabled. Per Wireshark (tls_auth branch):
//
//	opcode|key_id(1B) | session_id(8B) | hmac(hmacLen) |
//	replay_packet_id(4B) | net_time(4B, long format default) |
//	ack_count(1B) | ack array | remote_session_id(8B if ack>0) |
//	message_packet_id(4B) | payload
//
// We emit hmac=0xAA filler, replay_packet_id=messagePacketID, net_time=0,
// ack_count=0, and message_packet_id=messagePacketID.
func appendControlHeaderTLSAuth(b []byte, opcode, keyID uint8, sid uint64, messagePacketID uint32, hmacLen int) []byte {
	b = append(b, headerByte(opcode, keyID))
	b = appendSessionID(b, sid)
	// tls-auth HMAC filler (deterministic, not cryptographically valid).
	hmac := make([]byte, hmacLen)
	for i := range hmac {
		hmac[i] = 0xAA
	}
	b = append(b, hmac...)
	// replay_packet_id (4B BE).
	b = append(b, byte(messagePacketID>>24), byte(messagePacketID>>16),
		byte(messagePacketID>>8), byte(messagePacketID))
	// net_time (4B BE, long format default = 0).
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	// ack_count = 0.
	b = append(b, 0x00)
	// message_packet_id (4B BE).
	b = append(b, byte(messagePacketID>>24), byte(messagePacketID>>16),
		byte(messagePacketID>>8), byte(messagePacketID))
	return b
}

// appendControlHeaderTLSCrypt writes the control-packet header when tls-crypt
// is enabled. Per Wireshark (tls_crypt branch): the entire body after the
// 8-byte session_id is encrypted, so there is NO visible ack_count /
// message_packet_id. We emit the wrapped key + payload directly after the
// session_id (the wrapped key is the first part of the encrypted body).
func appendControlHeaderTLSCrypt(b []byte, opcode, keyID uint8, sid uint64) []byte {
	b = append(b, headerByte(opcode, keyID))
	b = appendSessionID(b, sid)
	return b
}

// buildHardResetClientV1 builds the P_CONTROL_HARD_RESET_CLIENT_V1 packet.
// Real OpenVPN V1 control packets still carry the 8-byte session_id and the
// ack/message_id structure (Wireshark parses session_id for opcode 1). V1
// has no HMAC and no tls-crypt (mutually excluded by Validate).
func buildHardResetClientV1(keyID uint8, sessionID uint64, packetID uint64, innerPayload []byte) []byte {
	b := appendControlHeader(nil, OpcodeHARDResetClientV1, keyID, sessionID, uint32(packetID))
	b = append(b, innerPayload...)
	return b
}

// buildHardResetServerV1 builds the P_CONTROL_HARD_RESET_SERVER_V1 packet.
func buildHardResetServerV1(keyID uint8, sessionID uint64, packetID uint64, innerPayload []byte) []byte {
	b := appendControlHeader(nil, OpcodeHARDResetServerV1, keyID, sessionID, uint32(packetID))
	b = append(b, innerPayload...)
	return b
}

// buildHardResetClientV2 builds the P_CONTROL_HARD_RESET_CLIENT_V2 packet.
func buildHardResetClientV2(keyID uint8, sessionID uint64, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, innerPayload []byte, isTCP bool) []byte {
	var b []byte
	switch {
	case tlsCrypt:
		b = appendControlHeaderTLSCrypt(b, OpcodeHARDResetClientV2, keyID, sessionID)
		b = append(b, buildWrappedKey(tlsCryptV2)...)
	case tlsAuth:
		b = appendControlHeaderTLSAuth(b, OpcodeHARDResetClientV2, keyID, sessionID, uint32(packetID), hmacLen)
	default:
		b = appendControlHeader(b, OpcodeHARDResetClientV2, keyID, sessionID, uint32(packetID))
	}
	b = append(b, innerPayload...)
	return b
}

// buildHardResetClientV3 builds the P_CONTROL_HARD_RESET_CLIENT_V3 packet.
// V3 uses opcode 10. With tls-crypt enabled (the V3 default), the body after
// the session_id is encrypted; for the synth generator we emit the wrapped
// key + payload in the clear (structurally the header is correct).
func buildHardResetClientV3(keyID uint8, sessionID uint64, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, innerPayload []byte, isTCP bool) []byte {
	var b []byte
	switch {
	case tlsCrypt:
		b = appendControlHeaderTLSCrypt(b, OpcodeHARDResetClientV3, keyID, sessionID)
		b = append(b, buildWrappedKey(tlsCryptV2)...)
	case tlsAuth:
		b = appendControlHeaderTLSAuth(b, OpcodeHARDResetClientV3, keyID, sessionID, uint32(packetID), hmacLen)
	default:
		b = appendControlHeader(b, OpcodeHARDResetClientV3, keyID, sessionID, uint32(packetID))
	}
	b = append(b, innerPayload...)
	return b
}

// buildHardResetServerV2 builds the P_CONTROL_HARD_RESET_SERVER_V2 packet.
func buildHardResetServerV2(keyID uint8, sessionID uint64, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, innerPayload []byte, isTCP bool) []byte {
	var b []byte
	switch {
	case tlsCrypt:
		b = appendControlHeaderTLSCrypt(b, OpcodeHARDResetServerV2, keyID, sessionID)
		b = append(b, buildWrappedKey(tlsCryptV2)...)
	case tlsAuth:
		b = appendControlHeaderTLSAuth(b, OpcodeHARDResetServerV2, keyID, sessionID, uint32(packetID), hmacLen)
	default:
		b = appendControlHeader(b, OpcodeHARDResetServerV2, keyID, sessionID, uint32(packetID))
	}
	b = append(b, innerPayload...)
	return b
}

// buildSoftReset builds the P_CONTROL_SOFT_RESET_V1 packet.
func buildSoftReset(newKeyID uint8, sessionID uint64, packetID uint64, tlsAuth, tlsCrypt, tlsCryptV2 bool, hmacLen int, isTCP bool) []byte {
	var b []byte
	switch {
	case tlsCrypt:
		b = appendControlHeaderTLSCrypt(b, OpcodeSOFTResetV1, newKeyID, sessionID)
		b = append(b, buildWrappedKey(tlsCryptV2)...)
	case tlsAuth:
		b = appendControlHeaderTLSAuth(b, OpcodeSOFTResetV1, newKeyID, sessionID, uint32(packetID), hmacLen)
	default:
		b = appendControlHeader(b, OpcodeSOFTResetV1, newKeyID, sessionID, uint32(packetID))
	}
	// payload: TLS re-handshake stub (合成 TLS 重协商 stub)
	b = append(b, 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00) // minimal TLS record
	return b
}

// buildDataV2 builds the P_DATA_V2 packet bytes.
// Real wire format (Wireshark P_DATA_V2 branch):
//
//	opcode|key_id(1B) | peer_id(3B) | encrypted_payload...
//
// No session_id, no packet_id is parsed after peer_id.
func buildDataV2(packetID uint64, keyID uint8, peerSessionID uint64, encryptedPayload []byte, cipher string, hmacLen int) []byte {
	b := []byte{headerByte(OpcodeDATAV2, keyID)}
	// peer_id: 3 bytes BE (FT_UINT24 in Wireshark). We use the low 24 bits
	// of peerSessionID as the peer_id.
	pid := uint32(peerSessionID & 0xFFFFFF)
	b = append(b, byte(pid>>16), byte(pid>>8), byte(pid))
	// encrypted payload (the encrypted packet_id + data + tag/IV are all
	// opaque bytes that Wireshark does not further dissect for P_DATA_V2).
	b = append(b, encryptedPayload...)
	return b
}

// buildDataV1 builds the P_DATA_V1 packet bytes.
// Real wire format (Wireshark P_DATA_V1 branch):
//
//	opcode|key_id(1B) | encrypted_payload...
//
// No session_id and no packet_id field is parsed — everything after the
// opcode byte is opaque encrypted payload.
func buildDataV1(packetID uint64, keyID uint8, _ uint64, payload []byte, cipher string, hmacLen int) []byte {
	b := []byte{headerByte(OpcodeDATAV1, keyID)}
	// Encrypted payload directly after the opcode byte. The encrypted
	// payload (IV + encrypted data + HMAC/tag) is opaque to Wireshark.
	b = append(b, buildEncryptedPayload(payload, cipher, hmacLen)...)
	return b
}

// buildDataV1Inner builds a P_DATA_V1 carrying an inner IP packet. Like
// buildDataV1 but the ciphertext slot contains the actual inner IP bytes
// (not 0-DD filler) so the inner IP is findable in the encrypted region.
func buildDataV1Inner(keyID uint8, payload []byte, cipher string, hmacLen int) []byte {
	b := []byte{headerByte(OpcodeDATAV1, keyID)}
	b = append(b, buildEncryptedPayloadInner(payload, cipher, hmacLen)...)
	return b
}

// buildStaticKeyDataV1 builds a P_DATA_V1 packet for static-key P2P mode.
// Per design §2.10.2 + §6.3 step 4: the P_DATA_V1 payload in static-key mode
// contains StaticKeyNonce(16B) + StaticKeyCiphertext(N B) + StaticKeyHMAC(20B).
// Per the real wire format, P_DATA_V1 is opcode(1B) + opaque payload, so the
// nonce/ciphertext/HMAC all live in the payload region.
// Synth crypto: nonce=0xCC, ciphertext=0xDD, HMAC=0xAA (design §4.6).
func buildStaticKeyDataV1(packetID uint64, keyID uint8, dataLen int) []byte {
	b := []byte{headerByte(OpcodeDATAV1, keyID)}
	// StaticKeyNonce: 16 bytes 0xCC
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = 0xCC
	}
	b = append(b, nonce...)
	// StaticKeyCiphertext: dataLen bytes 0xDD
	ciphertext := make([]byte, dataLen)
	for i := range ciphertext {
		ciphertext[i] = 0xDD
	}
	b = append(b, ciphertext...)
	// StaticKeyHMAC: 20 bytes 0xAA
	hmac := make([]byte, 20)
	for i := range hmac {
		hmac[i] = 0xAA
	}
	b = append(b, hmac...)
	return b
}

// buildExitNotify builds a framed exit_notify P_CONTROL message.
// Per design §2.10.5: exit_notify is carried inside a P_CONTROL message
// (opcode header + session_id + ack/message_id) with a 1-byte type=0x05
// payload, NOT a bare 0x05 byte. We reuse the V2 control framing.
func buildExitNotify(keyID uint8, sessionID uint64, packetID uint64) []byte {
	b := appendControlHeader(nil, OpcodeHARDResetClientV2, keyID, sessionID, uint32(packetID))
	// exit_notify type byte
	b = append(b, 0x05)
	return b
}

// buildEncryptedPayload builds the encrypted data for P_DATA packet.
// 构建 P_DATA 加密负载 (合成填充, 不真实加密). The ciphertext slot is
// filled with 0xDD synthetic filler (legacy mode).
func buildEncryptedPayload(payload []byte, cipher string, hmacLen int) []byte {
	return buildEncryptedPayloadRaw(payload, cipher, hmacLen, true)
}

// buildEncryptedPayloadInner builds the encrypted data for a P_DATA packet
// carrying an inner IP business packet. It is identical to
// buildEncryptedPayload EXCEPT the ciphertext slot contains the actual
// inner IP packet bytes (not 0-DD filler), so the inner IP header is
// findable in the encrypted region by tools that parse the decrypted body.
// The IV/nonce, encrypted_pkt_id, and HMAC/AEAD tag remain synthetic
// filler. This represents "what the encrypted body decrypts to" without
// performing real cryptography.
func buildEncryptedPayloadInner(payload []byte, cipher string, hmacLen int) []byte {
	return buildEncryptedPayloadRaw(payload, cipher, hmacLen, false)
}

// buildEncryptedPayloadRaw is the shared encrypted-payload builder. When
// useFiller is true, the ciphertext slot is 0-DD synthetic filler (legacy
// mode, backward compatible). When false, the ciphertext slot contains the
// actual payload bytes (inner IP mode - represents the decrypted body).
// The IV/nonce, encrypted_pkt_id, and HMAC/AEAD tag are always synthetic
// filler regardless of useFiller.
func buildEncryptedPayloadRaw(payload []byte, cipher string, hmacLen int, useFiller bool) []byte {
	// ciphertextSlot returns the bytes for the encrypted-data region:
	// 0-DD filler (legacy) or the actual payload (inner IP).
	ciphertextSlot := func() []byte {
		if len(payload) == 0 {
			return nil
		}
		if useFiller {
			f := make([]byte, len(payload))
			for i := range f {
				f[i] = 0xDD
			}
			return f
		}
		// Inner IP mode: copy the actual payload (inner IP packet) so it
		// is findable in the encrypted region.
		c := make([]byte, len(payload))
		copy(c, payload)
		return c
	}
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
		b = append(b, ciphertextSlot()...)
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
		b = append(b, ciphertextSlot()...)
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
		b = append(b, ciphertextSlot()...)
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
		b = append(b, ciphertextSlot()...)
		hmac := make([]byte, hmacLen)
		for i := range hmac {
			hmac[i] = 0xAA
		}
		b = append(b, hmac...)
	}
	return b
}

// buildWrappedKey builds the tls-crypt wrapped key (合成 tls-crypt 包裹密钥).
// Per design §2.5.1 + §2.6: tls-crypt-v2 field order is
//   length_prefix(2B BE) + wrapped_key_id(4B BE) + auth-tag(32B) + IV(16B) + cipher_key(32B).
// tls-crypt-v1 omits both the length prefix and wrapped_key_id.
func buildWrappedKey(tlsCryptV2 bool) []byte {
	var b []byte
	// tls-crypt-v2: length prefix (2B BE) FIRST, then wrapped_key_id (4B BE).
	// Design §2.5.1 byte example: 0x00 0x50 (len=80) then 0x00 0x00 0x00 0x01.
	if tlsCryptV2 {
		// length prefix = 80 (32+16+32), covering auth-tag + IV + cipher_key
		b = append(b, 0x00, 0x50)
		// wrapped_key_id = 1
		b = append(b, 0x00, 0x00, 0x00, 0x01)
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

	// Handshake header: type(1B) + length(3B). The TLS Record Length field
	// (RFC 8446 §5.2) covers the entire fragment = handshake header + body,
	// so it must be len(body) + 4, not len(body).
	fragmentLen := len(body) + 4

	// TLS Record header
	record := make([]byte, 0, 5+fragmentLen)
	record = append(record, 0x16) // ContentType=22 (Handshake)
	record = append(record, tlsVer[0], tlsVer[1])
	record = append(record, byte(fragmentLen>>8), byte(fragmentLen))
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

	// TLS Record Length = handshake header (4B) + body.
	fragmentLen := len(body) + 4

	// TLS Record header
	record := make([]byte, 0, 5+fragmentLen)
	record = append(record, 0x16) // ContentType=22 (Handshake)
	record = append(record, tlsVer[0], tlsVer[1])
	record = append(record, byte(fragmentLen>>8), byte(fragmentLen))
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
func buildFragmentedDataV2(packetID uint64, keyID uint8, peerSessionID uint64, data []byte, fragmentSize uint16, cipher string, hmacLen int) []byte {
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

	// Build P_DATA_V2 with fragments as payload: opcode(1) + peer_id(3) + payload
	b := []byte{headerByte(OpcodeDATAV2, keyID)}
	pid := uint32(peerSessionID & 0xFFFFFF)
	b = append(b, byte(pid>>16), byte(pid>>8), byte(pid))
	// fragmented payload (no separate packet_id; Wireshark treats P_DATA_V2
	// post-peer_id bytes as opaque data).
	b = append(b, fragments...)
	return b
}

// writePktID encodes a packet ID as the legacy V2 variadic encoding. This
// function is retained for backward compatibility with tests that assert the
// variadic encoding directly, but it is NOT used by the real wire-format
// builders: real OpenVPN control packets use a fixed 4-byte replay packet_id
// (+ optional 4-byte net_time for the long format), and P_DATA_V1/V2 carry no
// packet_id field that Wireshark parses. The variadic scheme here was based
// on an earlier incorrect reading of the protocol.
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

// --- Inner IP packet builders (内层 IP 包构建) ---
//
// buildInnerIPPacket builds a complete inner IPv4 or IPv6 packet (header +
// L4 + payload) for encapsulation inside an OpenVPN P_DATA_V2 encrypted
// payload. IPv4 headers carry a correct checksum (RFC 791 §3.1); IPv6 has
// no header checksum (RFC 8200 §3). L4 checksums are computed for TCP
// (mandatory) and ICMP; UDP checksum=0 is valid over IPv4 (RFC 768) but
// mandatory over IPv6 (so we compute it for v6). Mirrors the
// WireGuardInnerIP / L2TPInnerIP tunnel patterns.
func buildInnerIPPacket(ip *core.OpenVPNInnerIP, ipid uint16) []byte {
	srcIP := ip.SrcIP
	if srcIP == "" {
		srcIP = "10.10.10.1"
	}
	dstIP := ip.DstIP
	if dstIP == "" {
		dstIP = "10.10.10.2"
	}
	proto := ip.Proto
	if proto == 0 {
		proto = 17 // default UDP
	}
	ttl := ip.TTL
	if ttl == 0 {
		ttl = 64
	}
	parsedSrc := net.ParseIP(srcIP)
	if parsedSrc == nil {
		// Should never happen (Validate rejects it); fall back to v4 default.
		return nil
	}
	isV6 := parsedSrc.To4() == nil
	if isV6 {
		return buildInnerIPv6Packet(srcIP, dstIP, proto, ip.SrcPort, ip.DstPort, ttl, ip.Payload, ipid)
	}
	return buildInnerIPv4Packet(srcIP, dstIP, proto, ip.SrcPort, ip.DstPort, ttl, ip.Payload, ipid)
}

// buildInnerIPv4Packet builds a complete inner IPv4 packet (header + L4 +
// payload) with a correct header checksum per RFC 791 §3.1. The L4
// checksum is computed for TCP (mandatory) and ICMP; UDP checksum=0 is
// valid over IPv4 (RFC 768).
func buildInnerIPv4Packet(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, ttl uint8, payload []byte, ipid uint16) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()

	l4 := buildInnerL4(proto, srcPort, dstPort, payload, src, dst)

	totalLen := uint16(20 + len(l4))
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version=4, IHL=5
	// TOS = 0.
	binary.BigEndian.PutUint16(hdr[2:4], totalLen)
	binary.BigEndian.PutUint16(hdr[4:6], ipid)
	// Flags=DF (0x4000), FragOffset=0.
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000)
	hdr[8] = ttl
	hdr[9] = proto
	// Checksum at [10:12] computed below.
	if len(src) == 4 {
		copy(hdr[12:16], src)
	}
	if len(dst) == 4 {
		copy(hdr[16:20], dst)
	}
	binary.BigEndian.PutUint16(hdr[10:12], innerIPv4Checksum(hdr))

	return append(hdr, l4...)
}

// buildInnerIPv6Packet builds a complete inner IPv6 packet (40-byte fixed
// header + L4 + payload) per RFC 8200 §3. IPv6 has no header checksum; L4
// checksums use the IPv6 pseudo-header (RFC 2460 §8.1). UDP checksum is
// mandatory over IPv6; ICMPv6 (proto 58) checksum uses the pseudo-header.
func buildInnerIPv6Packet(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, hopLimit uint8, payload []byte, flowLabel uint16) []byte {
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()

	l4 := buildInnerL4v6(proto, srcPort, dstPort, payload, src, dst)

	payloadLen := uint16(len(l4))
	hdr := make([]byte, 40)
	// Version(4)=6 + TrafficClass(8)=0 + FlowLabel(20). We encode the
	// low 20 bits of flowLabel into the flow label field.
	hdr[0] = 0x60 // version=6, TC high=0
	fl := uint32(flowLabel) & 0xFFFFF
	hdr[1] = byte(fl >> 16)
	hdr[2] = byte(fl >> 8)
	hdr[3] = byte(fl)
	binary.BigEndian.PutUint16(hdr[4:6], payloadLen)
	hdr[6] = proto // Next Header
	hdr[7] = hopLimit
	if len(src) == 16 {
		copy(hdr[8:24], src)
	}
	if len(dst) == 16 {
		copy(hdr[24:40], dst)
	}

	return append(hdr, l4...)
}

// buildInnerL4 builds the L4 segment for IPv4. UDP checksum=0 is valid over
// IPv4 (RFC 768). TCP checksum is mandatory (RFC 793). ICMP checksum covers
// the whole ICMP message (RFC 792).
func buildInnerL4(proto uint8, srcPort, dstPort uint16, payload, src, dst []byte) []byte {
	switch proto {
	case 6: // TCP (RFC 793)
		l4 := make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		// Seq=0, Ack=0.
		l4[12] = 5 << 4 // Data offset = 5 (20 bytes), no flags.
		binary.BigEndian.PutUint16(l4[14:16], 65535) // window
		copy(l4[20:], payload)
		binary.BigEndian.PutUint16(l4[16:18], innerL4Checksum(l4, proto, src, dst))
		return l4
	case 17: // UDP (RFC 768)
		l4 := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		// UDP checksum = 0 is valid over IPv4 (RFC 768). Leave 0.
		copy(l4[8:], payload)
		return l4
	case 1: // ICMP (RFC 792)
		l4 := make([]byte, 8+len(payload))
		l4[0] = 8 // echo request
		copy(l4[8:], payload)
		binary.BigEndian.PutUint16(l4[2:4], innerIPv4Checksum(l4))
		return l4
	default:
		return payload
	}
}

// buildInnerL4v6 builds the L4 segment for IPv6. UDP checksum is MANDATORY
// over IPv6 (RFC 8200 §8.1), so we always compute it. ICMPv6 (proto 58)
// checksum uses the pseudo-header; for proto 1 we still build an ICMPv6
// echo request (type 128) since ICMPv6 is the IPv6 equivalent.
func buildInnerL4v6(proto uint8, srcPort, dstPort uint16, payload, src, dst []byte) []byte {
	switch proto {
	case 6: // TCP
		l4 := make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		l4[12] = 5 << 4
		binary.BigEndian.PutUint16(l4[14:16], 65535)
		copy(l4[20:], payload)
		binary.BigEndian.PutUint16(l4[16:18], innerL4Checksum(l4, 6, src, dst))
		return l4
	case 17: // UDP - checksum mandatory over IPv6
		l4 := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		copy(l4[8:], payload)
		binary.BigEndian.PutUint16(l4[6:8], innerL4Checksum(l4, 17, src, dst))
		return l4
	case 1: // ICMPv6 echo request (type 128, RFC 4443)
		l4 := make([]byte, 8+len(payload))
		l4[0] = 128 // ICMPv6 echo request
		copy(l4[8:], payload)
		binary.BigEndian.PutUint16(l4[2:4], innerL4Checksum(l4, 58, src, dst))
		return l4
	default:
		return payload
	}
}

// innerIPv4Checksum computes the 16-bit one's-complement checksum used by
// IPv4 headers and ICMP messages (RFC 791 §3.1, RFC 792).
func innerIPv4Checksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// innerL4Checksum computes the TCP/UDP checksum with the IPv4 or IPv6
// pseudo-header (RFC 793 / RFC 768 / RFC 2460 §8.1). The pseudo-header
// carries the L4 length and the protocol number (or Next Header). Works for
// both IPv4 (16-byte zero-padded) and IPv6 by using the 16-byte form.
func innerL4Checksum(l4 []byte, proto uint8, src, dst net.IP) uint16 {
	srcB := src.To16()
	dstB := dst.To16()
	if srcB == nil {
		srcB = make([]byte, 16)
	}
	if dstB == nil {
		dstB = make([]byte, 16)
	}
	// Pseudo-header: SrcIP(16) + DstIP(16) + UpperLayerLen(4) + zero(3) +
	// NextHeader(1).
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], srcB)
	copy(pseudo[16:32], dstB)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(l4)))
	pseudo[39] = proto

	buf := make([]byte, 0, len(pseudo)+len(l4))
	buf = append(buf, pseudo...)
	buf = append(buf, l4...)
	return innerIPv4Checksum(buf)
}

// validateInnerIP validates the OpenVPNInnerIP config. IPs must be valid
// and the same address family; Proto must be 0 (default), 1, 6, or 17.
func validateInnerIP(ip *core.OpenVPNInnerIP) error {
	if ip == nil {
		return nil
	}
	srcIP := ip.SrcIP
	dstIP := ip.DstIP
	if srcIP == "" {
		srcIP = "10.10.10.1"
	}
	if dstIP == "" {
		dstIP = "10.10.10.2"
	}
	src := net.ParseIP(srcIP)
	if src == nil {
		return fmt.Errorf("SrcIP %q is not a valid IP address", ip.SrcIP)
	}
	dst := net.ParseIP(dstIP)
	if dst == nil {
		return fmt.Errorf("DstIP %q is not a valid IP address", ip.DstIP)
	}
	srcIsV4 := src.To4() != nil
	dstIsV4 := dst.To4() != nil
	if srcIsV4 != dstIsV4 {
		return fmt.Errorf("SrcIP and DstIP must be the same address family (got v4/v6 mix)")
	}
	if ip.Proto != 0 && ip.Proto != 1 && ip.Proto != 6 && ip.Proto != 17 {
		return fmt.Errorf("Proto %d not in supported list (allowed: 1=ICMP, 6=TCP, 17=UDP)", ip.Proto)
	}
	return nil
}