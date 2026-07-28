// Package tls implements the TLS (Transport Layer Security, 传输层安全协议) protocol
// planner per RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 4346 (TLS 1.1), and
// RFC 2246 (TLS 1.0).
//
// The planner emits the full bidirectional wire sequence for one TLS session on a
// single TCP connection:
//
// 1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options,
// mirroring the FTP/HTTP/SIP/POP3 control-channel pattern.
// 2. TLS 1.3 fast path: ClientHello (Record ContentType=22) -> ServerHello +
// EncryptedExtensions + Certificate + CertificateVerify + Finished (all in
// Record ContentType=22 with legacy_version=0x0303) -> client Finished ->
// ApplicationData (ContentType=23).
// 3. TLS 1.2 path: ClientHello -> ServerHello + Certificate + ServerKeyExchange +
// ServerHelloDone -> ClientKeyExchange + ChangeCipherSpec (ContentType=20) +
// Finished -> server CCS + Finished -> AppData.
// 4. TLS 1.0/1.1 path: same as 1.2 but legacy_version=0x0301/0x0302.
// 5. Alert path (close_notify or fatal Alert) per AlertPath config.
// 6. TCP 4-way teardown (FIN-ACK/ACK/FIN-ACK/ACK) or RST.
//
// IMPORTANT: No real crypto (HKDF/HMAC/AES-GCM) is implemented. Encrypted portions
// use synth ciphertext (随机密文) — random bytes of the correct length. verify_data
// and signatures are random bytes of correct length (32 bytes for SHA-256 Finished
// in 1.3, 12 bytes in 1.2; signatures 64-256 bytes depending on algorithm). This is
// a packet-generation program, not network equipment.
package tls

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
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL (64).
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460). RFC 879
	// floor is 536; 1460 is the Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs.
	MinMSS = 536

	// DefaultPort is the well-known TLS port (HTTPS default).
	DefaultPort = 443

	// TLS Record ContentType (RFC 8446 §5.1 / RFC 5246 §6.2.1).
	// ContentType (内容类型) 标识 Record 载荷的协议层。
	contentTypeChangeCipherSpec = 20 // 0x14 — ChangeCipherSpec (TLS 1.2 only)
	contentTypeAlert = 21 // 0x15 — Alert
	contentTypeHandshake = 22 // 0x16 — Handshake
	contentTypeApplicationData = 23 // 0x17 — ApplicationData

	// HandshakeType (RFC 8446 §4 / RFC 5246 §7.4).
	// HandshakeType (握手消息类型) 标识握手消息的类型。
	handshakeTypeHelloRequest = 0 // HelloRequest
	handshakeTypeClientHello = 1 // ClientHello
	handshakeTypeServerHello = 2 // ServerHello
	handshakeTypeNewSessionTicket = 4 // NewSessionTicket
	handshakeTypeEndOfEarlyData = 5 // EndOfEarlyData
	handshakeTypeEncryptedExtensions = 8 // EncryptedExtensions
	handshakeTypeCertificate = 11 // Certificate
	handshakeTypeServerKeyExchange = 12 // ServerKeyExchange
	handshakeTypeCertificateRequest = 13 // CertificateRequest
	handshakeTypeServerHelloDone = 14 // ServerHelloDone
	handshakeTypeCertificateVerify = 15 // CertificateVerify
	handshakeTypeClientKeyExchange = 16 // ClientKeyExchange
	handshakeTypeFinished = 20 // Finished
	handshakeTypeKeyUpdate = 24 // KeyUpdate

	// ProtocolVersion (协议版本) — legacy_version 字段。
	protocolVersionTLS10 = 0x0301 // TLS 1.0
	protocolVersionTLS11 = 0x0302 // TLS 1.1
	protocolVersionTLS12 = 0x0303 // TLS 1.2 / TLS 1.3 (legacy)
	protocolVersionTLS13 = 0x0304 // TLS 1.3 (in supported_versions extension)

	// Extension types (RFC 8446 / RFC 6066 / RFC 7301).
	// Extension types (扩展类型) 标识 TLS 扩展。
	extensionSNI = 0x0000 // server_name (SNI, 服务器名称指示)
	extensionStatusRequest = 0x0005 // status_request (OCSP Stapling)
	extensionSupportedGroups = 0x000a // supported_groups
	extensionSignatureAlgorithms = 0x000d // signature_algorithms
	extensionALPN = 0x0010 // application_layer_protocol_negotiation (ALPN, 应用层协议协商)
	extensionStatusRequestV2 = 0x0012 // status_request_v2
	extensionExtendedMasterSecret = 0x0017 // extended_master_secret
	extensionSessionTicket = 0x0023 // session_ticket
	extensionPreSharedKey = 0x0029 // pre_shared_key (PSK, 预共享密钥)
	extensionEarlyData = 0x002a // early_data (0-RTT)
	extensionSupportedVersions = 0x002b // supported_versions
	extensionPSKKeyExchangeModes = 0x002d // psk_key_exchange_modes
	extensionKeyShare = 0x0033 // key_share
	extensionSignatureAlgorithmsCert = 0x0050 // signature_algorithms_cert
	extensionRenegotiationInfo = 0xff01 // renegotiation_info
	extensionPadding = 0x0015 // padding
	extensionRecordSizeLimit = 0x001D // record_size_limit
	extensionCookie = 0x002c // cookie
	extensionECPointFormats = 0x000b // ec_point_formats

	// Supported Groups (Named Curves) 支持的椭圆曲线组。
	groupX25519 = 0x001D // X25519 (RFC 7748)
	groupSecp256r1 = 0x0017 // secp256r1 (NIST P-256)
	groupSecp384r1 = 0x0018 // secp384r1 (NIST P-384)
	groupSecp521r1 = 0x0019 // secp521r1 (NIST P-521)

	// CipherSuite IDs (密码套件代码).
	cipherTLS13AES128GCM256 = 0x1301 // TLS_AES_128_GCM_SHA256 (1.3)
	cipherTLS13AES256GCM384 = 0x1302 // TLS_AES_256_GCM_SHA384 (1.3)
	cipherTLS13CHACHA20POLY1305 = 0x1303 // TLS_CHACHA20_POLY1305_SHA256 (1.3)
	cipherTLS13AES128CCM = 0x1304 // TLS_AES_128_CCM_SHA256 (1.3)
	cipherTLS13AES128CCM8 = 0x1305 // TLS_AES_128_CCM_8_SHA256 (1.3)
	cipherECDHEECDSAAES128GCM256 = 0xC02B // ECDHE-ECDSA-AES128-GCM-SHA256 (1.2)
	cipherECDHERSA128GCM256 = 0xC02C // ECDHE-RSA-AES128-GCM-SHA256 (1.2)
	cipherECDHERSA128SHA = 0xC02F // ECDHE-RSA-AES128-SHA (1.2)
	cipherECDHERSA256SHA = 0xC030 // ECDHE-RSA-AES256-SHA (1.2)
	cipherECDHERSA256GCM384 = 0xC035 // ECDHE-RSA-AES256-GCM-SHA384 (1.2)
	cipherDHERSA128GCM256 = 0x009E // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (1.2)
	cipherDHERSA256GCM384 = 0x009F // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (1.2)
	cipherTLSPSK128GCM256 = 0xC091 // TLS_PSK_WITH_AES_128_GCM_SHA256 (PSK)
	cipherTLSECECHACHA20POLY1305 = 0xCCA8 // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

	// Signature Algorithm codes (hash<<8 | sig) (签名算法代码).
	sigECDSA256r1 = 0x0403 // ecdsa_secp256r1_sha256
	sigRSA256 = 0x0401 // rsa_pkcs1_sha256
	sigRSA256PSS = 0x0804 // rsa_pss_rsae_sha256 (or 0x0809)
)

// TCP flag bits (RFC 9293 §3.1).
const (
	flagSYN = 0x02
	flagSYNACK = 0x12
	flagACK = 0x10
	flagPSHACK = 0x18
	flagFINACK = 0x11
	flagRSTACK = 0x14
)

// Planner implements the TLS protocol planner.
type Planner struct{}

// NewPlanner creates a new TLS planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "tls" }

// Validate validates a TLS flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("tls: SrcIP %q is not a valid IP address", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("tls: DstIP %q is not a valid IP address", spec.DstIP)
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("tls: TCP.MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
	}
	if spec.TLS == nil {
		return nil
	}
	t := spec.TLS
	// Validate version string.
	if t.Version != "" {
		switch t.Version {
		case "tls1.0", "tls1.1", "tls1.2", "tls1.3":
		default:
			return fmt.Errorf("tls: Version %q invalid (must be tls1.0/tls1.1/tls1.2/tls1.3)", t.Version)
		}
	}
	// Validate role.
	if t.Role != "" {
		switch t.Role {
		case "client", "server":
		default:
			return fmt.Errorf("tls: Role %q invalid (must be client or server)", t.Role)
		}
	}
	// SNI length: max 253 bytes per RFC 1035.
	if len(t.SNI) > 253 {
		return fmt.Errorf("tls: SNI length %d exceeds max 253 bytes (RFC 1035)", len(t.SNI))
	}
	// Validate AlertPath.
	if t.AlertPath != nil {
		a := t.AlertPath
		switch a.After {
		case "server_hello", "certificate", "server_hello_done":
		default:
			return fmt.Errorf("tls: AlertPath.After %q invalid (must be server_hello/certificate/server_hello_done)", a.After)
		}
		if a.Level != 1 && a.Level != 2 {
			return fmt.Errorf("tls: AlertPath.Level %d invalid (must be 1=warning or 2=fatal)", a.Level)
		}
	}
	// Validate PSK if present.
	for i, psk := range t.PSKs {
		if len(psk.Identity) == 0 {
			return fmt.Errorf("tls: PSKs[%d] has empty Identity", i)
		}
	}
	return nil
}

// Plan generates packet configs for a TLS flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)

		t := spec.TLS
		if t == nil {
			t = &core.TLSConfig{Version: "tls1.3"}
		}

		// Effective defaults applied here (not in Validate).
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
		handshake, termination := true, true
		if spec.TCP != nil {
			handshake = spec.TCP.Handshake
			termination = spec.TCP.Termination
		}

		// Random ISN per RFC 6528. User can override via spec.TCP.InitialSeq.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()
		ipID := uint16(rand.Uint32())
		packetIndex := uint64(0)
		now := time.Now()

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Determine effective version and legacy_version.
		effectiveVersion := t.Version
		if effectiveVersion == "" {
			effectiveVersion = "tls1.3"
		}
		var legacyVersion uint16
		switch effectiveVersion {
		case "tls1.0":
			legacyVersion = protocolVersionTLS10
		case "tls1.1":
			legacyVersion = protocolVersionTLS11
		case "tls1.2":
			legacyVersion = protocolVersionTLS12
		case "tls1.3":
			legacyVersion = protocolVersionTLS12 // 0x0303 for legacy_version
		}

		// Resolve ALPN list.
		alpnList := t.ALPN
		if len(alpnList) == 0 {
			alpnList = []string{"h2", "http/1.1"}
		}

		// Resolve cipher suites.
		cipherSuites := t.CipherSuites
		if len(cipherSuites) == 0 {
			if effectiveVersion == "tls1.3" {
				cipherSuites = []uint16{cipherTLS13AES128GCM256, cipherTLS13AES256GCM384, cipherTLS13CHACHA20POLY1305}
			} else {
				cipherSuites = []uint16{cipherECDHERSA128GCM256, cipherECDHERSA256GCM384, cipherECDHERSA128SHA}
			}
		}

		// Resolve supported groups.
		supportedGroups := t.SupportedGroups
		if len(supportedGroups) == 0 {
			supportedGroups = []uint16{groupX25519, groupSecp256r1, groupSecp384r1}
		}

		// Resolve signature algorithms.
		sigAlgs := t.SignatureAlgorithms
		if len(sigAlgs) == 0 {
			sigAlgs = []uint16{sigECDSA256r1, sigRSA256PSS, sigRSA256}
		}

		// emit sends one packet in the given direction.
		emit := func(direction, smac, dmac, sip, dip string, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) bool {
			l4 := core.L4Config{
				Protocol: "tcp",
				SrcPort: sport,
				DstPort: dport,
				Seq: seq,
				Ack: ack,
				Flags: flags,
				WindowSize: windowSize,
			}
			if flags == flagSYN || flags == flagSYNACK {
				l4.TCPOptions = synOptions(mss)
			}
			cfg := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: direction,
				Timestamp: now,
				L2: core.L2Config{
					SrcMAC: smac,
					DstMAC: dmac,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(sip, dip, 6, effectiveTTL, ipID, spec),
				L4: l4,
				Payload: payload,
			}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					cfg.Metadata = map[string]interface{}{"group_id": g}
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

		// emitUp emits a single up-direction packet with payload.
		emitUp := func(payload []byte) bool {
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagPSHACK, payload) {
				return false
			}
			clientSeq += uint32(len(payload))
			return true
		}

		// emitDown emits a single down-direction packet with payload.
		emitDown := func(payload []byte) bool {
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagPSHACK, payload) {
				return false
			}
			serverSeq += uint32(len(payload))
			return true
		}

		// --- TCP handshake ---
		if handshake {
			// SYN (client -> server)
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, flagSYN, nil) {
				return
			}
			clientSeq++
			// SYN-ACK (server -> client)
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagSYNACK, nil) {
				return
			}
			serverSeq++
			// ACK (client -> server)
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagACK, nil) {
				return
			}
		}

		// --- TLS handshake ---
		isTLS13 := (effectiveVersion == "tls1.3")
		isTLS12 := (effectiveVersion == "tls1.2")
		_ = isTLS12 // used below

		// Build ClientHello body.
		clientHelloBody := buildClientHello(legacyVersion, t.SNI, cipherSuites, supportedGroups, sigAlgs, alpnList, t.PSKs, t.AllowEarlyData, t.OCSPStapling, effectiveVersion)
		clientHelloRecord := buildRecord(contentTypeHandshake, legacyVersion, clientHelloBody)
		if !emitUp(clientHelloRecord) {
			return
		}

		// Check AlertPath: after "server_hello"
		if t.AlertPath != nil && t.AlertPath.After == "server_hello" {
			// ServerHello record then Alert
			serverHelloBody := buildServerHello(legacyVersion, supportedGroups[0], cipherSuites[0], isTLS13)
			serverHelloRecord := buildRecord(contentTypeHandshake, legacyVersion, serverHelloBody)
			if !emitDown(serverHelloRecord) {
				return
			}
			alertBody := buildAlert(t.AlertPath.Level, t.AlertPath.Description)
			alertRecord := buildRecord(contentTypeAlert, legacyVersion, alertBody)
			if !emitDown(alertRecord) {
				return
			}
			goto teardown
		}

		if isTLS13 {
			// --- TLS 1.3 fast path ---
			// ServerHello
			serverHelloBody := buildServerHello13(cipherSuites[0], supportedGroups[0])
			serverHelloRecord := buildRecord(contentTypeHandshake, legacyVersion, serverHelloBody)
			if !emitDown(serverHelloRecord) {
				return
			}

			// Check AlertPath: after "certificate" (before EncryptedExtensions)
			if t.AlertPath != nil && t.AlertPath.After == "certificate" {
				// Send EncryptedExtensions and Certificate, then alert
				eeBody := buildEncryptedExtensions(alpnList[0])
				eeRecord := buildRecord(contentTypeHandshake, legacyVersion, eeBody)
				if !emitDown(eeRecord) {
					return
				}
				certBody := buildCertificate13(t.ServerCertificate, t.ClientCertificate != nil)
				certRecord := buildRecord(contentTypeHandshake, legacyVersion, certBody)
				if !emitDown(certRecord) {
					return
				}
				alertBody := buildAlert(t.AlertPath.Level, t.AlertPath.Description)
				alertRecord := buildRecord(contentTypeAlert, legacyVersion, alertBody)
				if !emitDown(alertRecord) {
					return
				}
				goto teardown
			}

			// EncryptedExtensions
			eeBody := buildEncryptedExtensions(alpnList[0])
			eeRecord := buildRecord(contentTypeHandshake, legacyVersion, eeBody)
			if !emitDown(eeRecord) {
				return
			}

			// Certificate
			certBody := buildCertificate13(t.ServerCertificate, t.ClientCertificate != nil)
			certRecord := buildRecord(contentTypeHandshake, legacyVersion, certBody)
			if !emitDown(certRecord) {
				return
			}

			// Check AlertPath: after "server_hello_done" (after Certificate)
			if t.AlertPath != nil && t.AlertPath.After == "server_hello_done" {
				alertBody := buildAlert(t.AlertPath.Level, t.AlertPath.Description)
				alertRecord := buildRecord(contentTypeAlert, legacyVersion, alertBody)
				if !emitDown(alertRecord) {
					return
				}
				goto teardown
			}

			// CertificateVerify
			certVerifyBody := buildCertificateVerify(sigECDSA256r1, 64)
			certVerifyRecord := buildRecord(contentTypeHandshake, legacyVersion, certVerifyBody)
			if !emitDown(certVerifyRecord) {
				return
			}

			// Server Finished (32 bytes verify_data for SHA-256)
			serverFinishedBody := buildFinished(32)
			serverFinishedRecord := buildRecord(contentTypeHandshake, legacyVersion, serverFinishedBody)
			if !emitDown(serverFinishedRecord) {
				return
			}

			// Client Finished
			clientFinishedBody := buildFinished(32)
			clientFinishedRecord := buildRecord(contentTypeHandshake, legacyVersion, clientFinishedBody)
			if !emitUp(clientFinishedRecord) {
				return
			}

			// NewSessionTicket (if PSK configured)
			if len(t.PSKs) > 0 {
				nstBody := buildNewSessionTicket()
				nstRecord := buildRecord(contentTypeHandshake, legacyVersion, nstBody)
				if !emitDown(nstRecord) {
					return
				}
			}

			// 0-RTT early data (if configured)
			if t.AllowEarlyData && len(t.PSKs) > 0 {
				// Early data record: ApplicationData with synth payload
				earlyData := make([]byte, 64)
				rand.Read(earlyData)
				earlyRecord := buildRecord(contentTypeApplicationData, legacyVersion, earlyData)
				if !emitUp(earlyRecord) {
					return
				}
			}

			// ApplicationData (synth encrypted payload)
			appData := make([]byte, 128)
			rand.Read(appData)
			appRecord := buildRecord(contentTypeApplicationData, legacyVersion, appData)
			if !emitUp(appRecord) {
				return
			}

			// Server AppData response
			serverAppData := make([]byte, 128)
			rand.Read(serverAppData)
			serverAppRecord := buildRecord(contentTypeApplicationData, legacyVersion, serverAppData)
			if !emitDown(serverAppRecord) {
				return
			}

		} else {
			// --- TLS 1.2 / 1.1 / 1.0 path ---
			// ServerHello
			serverHelloBody := buildServerHello12(legacyVersion, cipherSuites[0])
			serverHelloRecord := buildRecord(contentTypeHandshake, legacyVersion, serverHelloBody)
			if !emitDown(serverHelloRecord) {
				return
			}

			// Check AlertPath: after "certificate"
			if t.AlertPath != nil && t.AlertPath.After == "certificate" {
				// Send Certificate then alert
				certBody := buildCertificate12(t.ServerCertificate)
				certRecord := buildRecord(contentTypeHandshake, legacyVersion, certBody)
				if !emitDown(certRecord) {
					return
				}
				alertBody := buildAlert(t.AlertPath.Level, t.AlertPath.Description)
				alertRecord := buildRecord(contentTypeAlert, legacyVersion, alertBody)
				if !emitDown(alertRecord) {
					return
				}
				goto teardown
			}

			// Certificate
			certBody := buildCertificate12(t.ServerCertificate)
			certRecord := buildRecord(contentTypeHandshake, legacyVersion, certBody)
			if !emitDown(certRecord) {
				return
			}

			// ServerKeyExchange (ECDHE)
			skeBody := buildServerKeyExchange()
			skeRecord := buildRecord(contentTypeHandshake, legacyVersion, skeBody)
			if !emitDown(skeRecord) {
				return
			}

			// ServerHelloDone
			shdBody := buildServerHelloDone()
			shdRecord := buildRecord(contentTypeHandshake, legacyVersion, shdBody)
			if !emitDown(shdRecord) {
				return
			}

			// Check AlertPath: after "server_hello_done"
			if t.AlertPath != nil && t.AlertPath.After == "server_hello_done" {
				alertBody := buildAlert(t.AlertPath.Level, t.AlertPath.Description)
				alertRecord := buildRecord(contentTypeAlert, legacyVersion, alertBody)
				if !emitDown(alertRecord) {
					return
				}
				goto teardown
			}

			// ClientKeyExchange (ECDHE)
			ckeBody := buildClientKeyExchange()
			ckeRecord := buildRecord(contentTypeHandshake, legacyVersion, ckeBody)
			if !emitUp(ckeRecord) {
				return
			}

			// Client ChangeCipherSpec
			ccsRecord := buildRecord(contentTypeChangeCipherSpec, legacyVersion, []byte{0x01})
			if !emitUp(ccsRecord) {
				return
			}

			// Client Finished (12 bytes verify_data for 1.2 SHA-256)
			clientFinishedBody := buildFinished(12)
			clientFinishedRecord := buildRecord(contentTypeHandshake, legacyVersion, clientFinishedBody)
			if !emitUp(clientFinishedRecord) {
				return
			}

			// Server ChangeCipherSpec
			serverCCSRecord := buildRecord(contentTypeChangeCipherSpec, legacyVersion, []byte{0x01})
			if !emitDown(serverCCSRecord) {
				return
			}

			// Server Finished (12 bytes)
			serverFinishedBody := buildFinished(12)
			serverFinishedRecord := buildRecord(contentTypeHandshake, legacyVersion, serverFinishedBody)
			if !emitDown(serverFinishedRecord) {
				return
			}

			// ApplicationData (synth encrypted payload)
			appData := make([]byte, 128)
			rand.Read(appData)
			appRecord := buildRecord(contentTypeApplicationData, legacyVersion, appData)
			if !emitUp(appRecord) {
				return
			}

			// Server AppData response
			serverAppData := make([]byte, 128)
			rand.Read(serverAppData)
			serverAppRecord := buildRecord(contentTypeApplicationData, legacyVersion, serverAppData)
			if !emitDown(serverAppRecord) {
				return
			}
		}

	teardown:
		// --- Alert close_notify (if not already an alert path) ---
		if t.AlertPath == nil {
			closeNotifyBody := buildAlert(1, 0) // warning, close_notify
			closeNotifyRecord := buildRecord(contentTypeAlert, legacyVersion, closeNotifyBody)
			if !emitUp(closeNotifyRecord) {
				return
			}
		}

		// --- RST or TCP teardown ---
		if spec.TCP != nil && spec.TCP.RST {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagRSTACK, nil)
			return
		}
		if termination {
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagFINACK, nil) {
				return
			}
			clientSeq++
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagACK, nil) {
				return
			}
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagFINACK, nil) {
				return
			}
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagACK, nil)
		}
	}()

	return out, nil
}

// --- Builder functions ---

// buildRecord wraps a TLS record header around the payload.
// Format: ContentType(1) + ProtocolVersion(2) + Length(2) + Payload.
func buildRecord(contentType uint8, version uint16, payload []byte) []byte {
	record := make([]byte, 5+len(payload))
	record[0] = contentType
	binary.BigEndian.PutUint16(record[1:3], version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[5:], payload)
	return record
}

// buildHandshakeHeader wraps a handshake header around the body.
// Format: HandshakeType(1) + Length(3) + Body.
func buildHandshakeHeader(hsType uint8, body []byte) []byte {
	hs := make([]byte, 4+len(body))
	hs[0] = hsType
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	return hs
}

// buildClientHello builds a ClientHello body (HandshakeType=1).
func buildClientHello(legacyVersion uint16, sni string, cipherSuites, supportedGroups, sigAlgs []uint16, alpnList []string, psks []core.PSKIdentity, allowEarlyData, ocspStapling bool, effectiveVersion string) []byte {
	// Random: 32 bytes
	random := make([]byte, 32)
	rand.Read(random)

	// Session ID: 0 (null for 1.3, can be set for 1.2 resume)
	sessionID := []byte{0x00} // length byte

	// Cipher suites: length(2) + suites
	csLen := len(cipherSuites) * 2
	csBytes := make([]byte, 2+csLen)
	binary.BigEndian.PutUint16(csBytes[0:2], uint16(csLen))
	for i, cs := range cipherSuites {
		binary.BigEndian.PutUint16(csBytes[2+i*2:4+i*2], cs)
	}

	// Compression methods: length(1) + [0x00]
	compression := []byte{0x01, 0x00}

	// Build extensions
	var extBuf []byte

	// SNI extension
	if sni != "" {
		sniBytes := []byte(sni)
		sniList := make([]byte, 3+len(sniBytes))
		sniList[0] = 0x00 // name_type = host_name
		binary.BigEndian.PutUint16(sniList[1:3], uint16(len(sniBytes)))
		copy(sniList[3:], sniBytes)
		extBuf = appendExtension(extBuf, extensionSNI, sniList)
	}

	// ALPN extension
	if len(alpnList) > 0 {
		alpnBody := buildALPNExtension(alpnList)
		extBuf = appendExtension(extBuf, extensionALPN, alpnBody)
	}

	// supported_versions extension
	if effectiveVersion == "tls1.3" {
		svBody := []byte{0x04, 0x03, 0x04, 0x03, 0x03} // len=4, 0x0304, 0x0303
		extBuf = appendExtension(extBuf, extensionSupportedVersions, svBody)
	}

	// supported_groups extension
	sgBody := make([]byte, 2+len(supportedGroups)*2)
	binary.BigEndian.PutUint16(sgBody[0:2], uint16(len(supportedGroups)*2))
	for i, g := range supportedGroups {
		binary.BigEndian.PutUint16(sgBody[2+i*2:4+i*2], g)
	}
	extBuf = appendExtension(extBuf, extensionSupportedGroups, sgBody)

	// signature_algorithms extension
	sigBody := make([]byte, 2+len(sigAlgs)*2)
	binary.BigEndian.PutUint16(sigBody[0:2], uint16(len(sigAlgs)*2))
	for i, s := range sigAlgs {
		binary.BigEndian.PutUint16(sigBody[2+i*2:4+i*2], s)
	}
	extBuf = appendExtension(extBuf, extensionSignatureAlgorithms, sigBody)

	// key_share extension (TLS 1.3)
	if effectiveVersion == "tls1.3" {
		// Client shares: one X25519 key share (32 bytes)
		keyShare := make([]byte, 32)
		rand.Read(keyShare)
		entry := make([]byte, 4+32)
		binary.BigEndian.PutUint16(entry[0:2], groupX25519)
		binary.BigEndian.PutUint16(entry[2:4], 32)
		copy(entry[4:], keyShare)
		ksBody := make([]byte, 2+len(entry))
		binary.BigEndian.PutUint16(ksBody[0:2], uint16(len(entry)))
		copy(ksBody[2:], entry)
		extBuf = appendExtension(extBuf, extensionKeyShare, ksBody)
	}

	// signature_algorithms_cert extension (TLS 1.3)
	if effectiveVersion == "tls1.3" {
		sigCertBody := make([]byte, 2+len(sigAlgs)*2)
		binary.BigEndian.PutUint16(sigCertBody[0:2], uint16(len(sigAlgs)*2))
		for i, s := range sigAlgs {
			binary.BigEndian.PutUint16(sigCertBody[2+i*2:4+i*2], s)
		}
		extBuf = appendExtension(extBuf, extensionSignatureAlgorithmsCert, sigCertBody)
	}

	// session_ticket extension (empty = presence-only)
	if len(psks) > 0 {
		extBuf = appendExtension(extBuf, extensionSessionTicket, []byte{0x00, 0x00})
	}

	// psk_key_exchange_modes (for PSK)
	if len(psks) > 0 {
		extBuf = appendExtension(extBuf, extensionPSKKeyExchangeModes, []byte{0x01, 0x01}) // modes_len=1, psk_dhe_ke=0x01
	}

	// pre_shared_key extension (for PSK resumption)
	if len(psks) > 0 {
		pskBody := buildPSKExtension(psks)
		extBuf = appendExtension(extBuf, extensionPreSharedKey, pskBody)
	}

	// early_data extension (0-RTT)
	if allowEarlyData && len(psks) > 0 {
		extBuf = appendExtension(extBuf, extensionEarlyData, []byte{0x00, 0x00})
	}

	// OCSP Stapling (status_request)
	if ocspStapling {
		srBody := []byte{0x01, 0x00, 0x00, 0x00, 0x00} // status_type=1(ocsp), responder_id_list_len=0, request_extensions_len=0
		extBuf = appendExtension(extBuf, extensionStatusRequest, srBody)
	}

	// ec_point_formats (for 1.2 ECDHE)
	if effectiveVersion != "tls1.3" {
		extBuf = appendExtension(extBuf, extensionECPointFormats, []byte{0x01, 0x00}) // formats_len=1, uncompressed=0
	}

	// Put extensions into a length-prefixed block.
	extBlock := make([]byte, 2+len(extBuf))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(extBuf)))
	copy(extBlock[2:], extBuf)

	// Assemble body: legacy_version(2) + random(32) + session_id(1+var) + cipher_suites(2+var) + compression(1+var) + extensions(2+var)
	body := make([]byte, 0, 2+32+len(sessionID)+len(csBytes)+len(compression)+len(extBlock))
	body = append(body, byte(legacyVersion>>8), byte(legacyVersion))
	body = append(body, random...)
	body = append(body, sessionID...)
	body = append(body, csBytes...)
	body = append(body, compression...)
	body = append(body, extBlock...)

	return buildHandshakeHeader(handshakeTypeClientHello, body)
}

// buildServerHello13 builds a TLS 1.3 ServerHello body.
func buildServerHello13(cipherSuite uint16, group uint16) []byte {
	// legacy_version = 0x0303
	random := make([]byte, 32)
	rand.Read(random)

	// session_id echo: 0 (null)
	sessionID := []byte{0x00}

	// cipher_suite (2 bytes)
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherSuite)

	// compression_method = 0
	compression := byte(0x00)

	// Extensions: supported_versions=0x0304, key_share
	var extBuf []byte
	svBody := []byte{0x03, 0x04} // 0x0304 (ServerHello.supported_versions is 2 bytes, no length)
	extBuf = appendExtension(extBuf, extensionSupportedVersions, svBody)

	// key_share server share
	keyShare := make([]byte, 32)
	rand.Read(keyShare)
	entry := make([]byte, 4+32)
	binary.BigEndian.PutUint16(entry[0:2], group)
	binary.BigEndian.PutUint16(entry[2:4], 32)
	copy(entry[4:], keyShare)
	extBuf = appendExtension(extBuf, extensionKeyShare, entry)

	extBlock := make([]byte, 2+len(extBuf))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(extBuf)))
	copy(extBlock[2:], extBuf)

	body := make([]byte, 0, 2+32+len(sessionID)+2+1+len(extBlock))
	body = append(body, 0x03, 0x03) // legacy_version = 0x0303
	body = append(body, random...)
	body = append(body, sessionID...)
	body = append(body, cs...)
	body = append(body, compression)
	body = append(body, extBlock...)

	return buildHandshakeHeader(handshakeTypeServerHello, body)
}

// buildServerHello12 builds a TLS 1.2 ServerHello body.
func buildServerHello12(legacyVersion uint16, cipherSuite uint16) []byte {
	random := make([]byte, 32)
	rand.Read(random)

	sessionID := []byte{0x00}
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherSuite)
	compression := byte(0x00)

	// No extensions needed for basic 1.2 ServerHello
	extBlock := []byte{0x00, 0x00} // extensions_len=0

	body := make([]byte, 0, 2+32+len(sessionID)+2+1+len(extBlock))
	body = append(body, byte(legacyVersion>>8), byte(legacyVersion))
	body = append(body, random...)
	body = append(body, sessionID...)
	body = append(body, cs...)
	body = append(body, compression)
	body = append(body, extBlock...)

	return buildHandshakeHeader(handshakeTypeServerHello, body)
}

// buildServerHello builds a generic ServerHello (delegates to version-specific).
func buildServerHello(legacyVersion uint16, group uint16, cipherSuite uint16, isTLS13 bool) []byte {
	if isTLS13 {
		return buildServerHello13(cipherSuite, group)
	}
	return buildServerHello12(legacyVersion, cipherSuite)
}

// buildEncryptedExtensions builds a TLS 1.3 EncryptedExtensions body with ALPN.
func buildEncryptedExtensions(alpnSelected string) []byte {
	var extBuf []byte
	// ALPN extension in EncryptedExtensions
	alpnBody := buildALPNExtension([]string{alpnSelected})
	extBuf = appendExtension(extBuf, extensionALPN, alpnBody)

	extBlock := make([]byte, 2+len(extBuf))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(extBuf)))
	copy(extBlock[2:], extBuf)

	return buildHandshakeHeader(handshakeTypeEncryptedExtensions, extBlock)
}

// buildCertificate13 builds a TLS 1.3 Certificate body (with certificate_request_context).
func buildCertificate13(serverCert *core.X509Ref, clientAuth bool) []byte {
	// certificate_request_context: 0 for server, 1 byte for client auth
	ctx := []byte{0x00}
	if clientAuth {
		ctx = []byte{0x01, 0x00} // length=1, context=0
	}

	// certificate_list: one self-signed cert entry
	certData := make([]byte, 256)
	rand.Read(certData)

	// CertificateEntry: cert_len(3) + cert_data(N) + extensions(2) in 1.3
	entry := make([]byte, 3+len(certData)+2)
	entry[0] = byte(len(certData) >> 16)
	entry[1] = byte(len(certData) >> 8)
	entry[2] = byte(len(certData))
	copy(entry[3:], certData)
	// extensions: empty (2 bytes len=0)
	entry[3+len(certData)] = 0x00
	entry[3+len(certData)+1] = 0x00

	// certificates_list_len(3) + entries
	body := make([]byte, 3+len(entry))
	body[0] = byte(len(entry) >> 16)
	body[1] = byte(len(entry) >> 8)
	body[2] = byte(len(entry))
	copy(body[3:], entry)

	// Prepend certificate_request_context
	fullBody := append(ctx, body...)

	return buildHandshakeHeader(handshakeTypeCertificate, fullBody)
}

// buildCertificate12 builds a TLS 1.2 Certificate body (no certificate_request_context).
func buildCertificate12(serverCert *core.X509Ref) []byte {
	certData := make([]byte, 256)
	rand.Read(certData)

	entry := make([]byte, 3+len(certData))
	entry[0] = byte(len(certData) >> 16)
	entry[1] = byte(len(certData) >> 8)
	entry[2] = byte(len(certData))
	copy(entry[3:], certData)

	// certificates_list_len(3) + entries (no 1.3 extensions)
	body := make([]byte, 3+len(entry))
	body[0] = byte(len(entry) >> 16)
	body[1] = byte(len(entry) >> 8)
	body[2] = byte(len(entry))
	copy(body[3:], entry)

	return buildHandshakeHeader(handshakeTypeCertificate, body)
}

// buildServerKeyExchange builds a TLS 1.2 ECDHE ServerKeyExchange body.
func buildServerKeyExchange() []byte {
	// ECDHE: curve_type(1)=3(named_curve) + named_curve(2) + pub_key_len(1) + pub_key + sig_len(2) + signature
	pubKey := make([]byte, 32) // X25519 pub key
	rand.Read(pubKey)

	sig := make([]byte, 64) // ECDSA signature
	rand.Read(sig)

	body := make([]byte, 0, 1+2+1+len(pubKey)+2+len(sig))
	body = append(body, 0x03) // curve_type = named_curve
	body = append(body, 0x00, 0x1D) // X25519
	body = append(body, byte(len(pubKey)))
	body = append(body, pubKey...)
	body = append(body, byte(len(sig)>>8), byte(len(sig)))
	body = append(body, sig...)

	return buildHandshakeHeader(handshakeTypeServerKeyExchange, body)
}

// buildServerHelloDone builds a TLS 1.2 ServerHelloDone body (empty).
func buildServerHelloDone() []byte {
	return buildHandshakeHeader(handshakeTypeServerHelloDone, []byte{})
}

// buildClientKeyExchange builds a TLS 1.2 ECDHE ClientKeyExchange body.
func buildClientKeyExchange() []byte {
	pubKey := make([]byte, 32)
	rand.Read(pubKey)

	body := make([]byte, 1+len(pubKey))
	body[0] = byte(len(pubKey))
	copy(body[1:], pubKey)

	return buildHandshakeHeader(handshakeTypeClientKeyExchange, body)
}

// buildCertificateVerify builds a CertificateVerify body.
func buildCertificateVerify(algorithm uint16, sigLen int) []byte {
	sig := make([]byte, sigLen)
	rand.Read(sig)

	body := make([]byte, 2+2+sigLen)
	binary.BigEndian.PutUint16(body[0:2], algorithm)
	binary.BigEndian.PutUint16(body[2:4], uint16(sigLen))
	copy(body[4:], sig)

	return buildHandshakeHeader(handshakeTypeCertificateVerify, body)
}

// buildFinished builds a Finished body with verify_data of given length.
func buildFinished(verifyLen int) []byte {
	verifyData := make([]byte, verifyLen)
	rand.Read(verifyData)

	return buildHandshakeHeader(handshakeTypeFinished, verifyData)
}

// buildAlert builds an Alert body: Level(1) + Description(1).
func buildAlert(level, description uint8) []byte {
	return []byte{level, description}
}

// buildNewSessionTicket builds a TLS 1.3 NewSessionTicket body.
func buildNewSessionTicket() []byte {
	// ticket_lifetime(4) + ticket_age_add(4) + ticket_nonce(1+len) + ticket(2+len)
	ticket := make([]byte, 32)
	rand.Read(ticket)

	body := make([]byte, 0, 4+4+1+0+2+len(ticket))
	// ticket_lifetime = 7200 seconds
	body = append(body, 0x00, 0x00, 0x1C, 0x20)
	// ticket_age_add = random 4 bytes
	ageAdd := make([]byte, 4)
	rand.Read(ageAdd)
	body = append(body, ageAdd...)
	// ticket_nonce: length 0
	body = append(body, 0x00)
	// ticket: 2 byte length + data
	body = append(body, byte(len(ticket)>>8), byte(len(ticket)))
	body = append(body, ticket...)

	return buildHandshakeHeader(handshakeTypeNewSessionTicket, body)
}

// buildALPNExtension builds the body for an ALPN extension.
func buildALPNExtension(protocols []string) []byte {
	var protoList []byte
	for _, p := range protocols {
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, []byte(p)...)
	}
	body := make([]byte, 2+len(protoList))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(protoList)))
	copy(body[2:], protoList)
	return body
}

// buildPSKExtension builds the pre_shared_key extension body.
func buildPSKExtension(psks []core.PSKIdentity) []byte {
	// identities_len(2) + Identity[] + binders_len(2) + Binder[]
	var identities []byte
	for _, psk := range psks {
		id := psk.Identity
		idLen := make([]byte, 2)
		binary.BigEndian.PutUint16(idLen, uint16(len(id)))
		identities = append(identities, idLen...)
		identities = append(identities, id...)
		age := make([]byte, 4)
		binary.BigEndian.PutUint32(age, psk.ObfuscatedAge)
		identities = append(identities, age...)
	}

	// Binder: one 32-byte binder per PSK
	var binders []byte
	for range psks {
		binder := make([]byte, 32)
		rand.Read(binder)
		binderLen := make([]byte, 2)
		binary.BigEndian.PutUint16(binderLen, uint16(len(binder)))
		binders = append(binders, binderLen...)
		binders = append(binders, binder...)
	}

	body := make([]byte, 0, 2+len(identities)+2+len(binders))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(identities)))
	body = append(body, identities...)
	binderBlock := make([]byte, 2+len(binders))
	binary.BigEndian.PutUint16(binderBlock[0:2], uint16(len(binders)))
	copy(binderBlock[2:], binders)
	body = append(body, binderBlock...)

	return body
}

// appendExtension appends a TLS extension (type+length+data) to buf.
func appendExtension(buf []byte, extType uint16, data []byte) []byte {
	ext := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(ext[0:2], extType)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(data)))
	copy(ext[4:], data)
	return append(buf, ext...)
}

// segmentByMSS splits payload into chunks of at most mss bytes.
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

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and SACK-Permitted.
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