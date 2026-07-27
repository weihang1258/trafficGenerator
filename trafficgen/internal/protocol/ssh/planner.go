// Package ssh implements the SSH (Secure Shell, 安全外壳协议) protocol
// planner per RFC 4250-4254/4344/5647/5656/6668/8308/8731.
//
// SSH is a session-level, encrypted, multi-layer binary protocol. TCP
// carries Version Exchange (text) → BPP (Binary Packet Protocol, 二进制包
// 协议) → message layer (transport/user-auth/connection).
//
// Encryption is NOT implemented: post-NEWKEYS payload bytes are opaque
// (dummy or user-supplied). The planner emits correct BPP framing
// (packet_length + padding_length + payload + padding + MAC), correct
// message numbers, and correct per-message field encoding so that
// Wireshark can parse the SSH layer and display message_number + field
// lengths — but the encrypted content is indistinguishable from real SSH
// to any DPI that doesn't terminate SSH.
//
// The planner does NOT implement Option negotiation state (RFC 1143 Q
// method); it emits the dialog verbatim as specified by the user. This
// matches the trafficgen contract: synthesize test packets, not a real
// SSH server.
package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Defaults per RFC 4253 and OpenSSH 8.9 reference behavior.
const (
	DefaultTTL       = 64
	DefaultMSS       = 1460
	DefaultSSHPort   = 22
	DefaultWindow    = uint16(65535)
	DefaultChanWin   = uint32(2097152) // 2 MiB
	DefaultChanPkt   = uint32(32768)   // 32 KiB
	DefaultMinPad    = 4
	DefaultMaxPad    = 255
	DefaultCipherBlk = 8 // RFC 4253 §6 block size for "none" / DES / 3DES
	DefaultAESBlk    = 16
)

// RFC 4253 §4.2 SSH version exchange constants.
const (
	SSHVersionPrefix  = "SSH-2.0-"
	SSHVersionDefault = "trafficgen_1.0"
	SSHVersionCRLF    = "\r\n"
	SSHVersionMaxSoft = 255 // practical cap; RFC does not strict-limit
)

// RFC 4253 §6 — Cipher block sizes (for BPP alignment).
// 0 = "none" or stream cipher (no alignment required, but minimum packet
// size rule still applies via padding_length >= 4).
const (
	CipherNone   = "none"
	CipherAES    = "aes128-ctr"             // representative AES-CTR; all AES-CTR use 16
	CipherAESGCM = "aes128-gcm@openssh.com" // AEAD: 12-byte IV + 16 tag
)

// MAC lengths in bytes after NEWKEYS (RFC 4253/6668).
const (
	MACNone = 0
	MACSHA1 = 20
	MAC256  = 32
	MAC512  = 64
)

// Message numbers (RFC 4250 §4.4 / 4252 / 4253 / 4254 / 8308).
const (
	MsgDisconnect           uint8 = 1
	MsgIgnore               uint8 = 2
	MsgUnimplemented        uint8 = 3
	MsgDebug                uint8 = 4
	MsgServiceRequest       uint8 = 5
	MsgServiceAccept        uint8 = 6
	MsgExtInfo              uint8 = 7
	MsgKexInit              uint8 = 20
	MsgNewKeys              uint8 = 21
	MsgKexDHInit            uint8 = 30
	MsgKexDHReply           uint8 = 31
	MsgUserAuthRequest      uint8 = 50
	MsgUserAuthFailure      uint8 = 51
	MsgUserAuthSuccess      uint8 = 52
	MsgUserAuthBanner       uint8 = 53
	MsgUserAuthInfoRequest  uint8 = 60
	MsgUserAuthInfoResponse uint8 = 61
	MsgGlobalRequest        uint8 = 80
	MsgRequestSuccess       uint8 = 81
	MsgRequestFailure       uint8 = 82
	MsgChannelOpen          uint8 = 90
	MsgChannelOpenConf      uint8 = 91
	MsgChannelOpenFailure   uint8 = 92
	MsgChannelWindowAdjust  uint8 = 93
	MsgChannelData          uint8 = 94
	MsgChannelExtendedData  uint8 = 95
	MsgChannelEOF           uint8 = 96
	MsgChannelClose         uint8 = 97
	MsgChannelRequest       uint8 = 98
	MsgChannelSuccess       uint8 = 99
	MsgChannelFailure       uint8 = 100
)

// SSH_DISCONNECT reason codes (RFC 4253 §11.1).
const (
	DiscHostNotAllowed        uint32 = 1
	DiscProtocolError         uint32 = 2
	DiscKeyExchangeFailed     uint32 = 3
	DiscReserved              uint32 = 4
	DiscMACError              uint32 = 5
	DiscCompressionError      uint32 = 6
	DiscServiceNotAvailable   uint32 = 7
	DiscProtocolVersionNotSup uint32 = 8
	DiscHostKeyNotVerifiable  uint32 = 9
	DiscConnectionLost        uint32 = 10
	DiscByApplication         uint32 = 11
	DiscTooManyConnections    uint32 = 12
	DiscAuthCancelledByUser   uint32 = 13
	DiscNoMoreAuthMethods     uint32 = 14
	DiscIllegalUserName       uint32 = 15
)

// SSH_OPEN reason codes (RFC 4254 §5.2).
const (
	OpenAdministrativelyProhibited uint32 = 1
	OpenConnectFailed              uint32 = 2
	OpenUnknownChannelType         uint32 = 3
	OpenResourceShortage           uint32 = 4
)

// Reserved sender_channel value (RFC 4254 §5.1).
const ReservedChannel uint32 = 0xFFFFFFFF

// Planner implements the SSH protocol planner.
type Planner struct{}

// NewPlanner creates a new SSH planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "ssh" }

// Validate validates an SSH flow spec. Read-only — does NOT mutate spec.
// Defaults (port 22, MSS 1460, etc.) are applied in Plan's emit goroutine,
// not here, per validate_conventions.md §1.1.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("ssh: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("ssh: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < 536 {
			return fmt.Errorf("ssh: TCP.MSS %d too small (min 536 per RFC 879)", spec.TCP.MSS)
		}
		if spec.TCP.MSS > 65535 {
			return fmt.Errorf("ssh: TCP.MSS %d too large (max 65535)", spec.TCP.MSS)
		}
	}
	// Validate SSHConfig fields when set.
	cfg := spec.SSH
	if cfg == nil {
		return nil
	}
	if hasCRorLF(cfg.ServerVersion) {
		return fmt.Errorf("ssh: server_version contains CR/LF (RFC 4253 §4.2)")
	}
	if hasCRorLF(cfg.ClientVersion) {
		return fmt.Errorf("ssh: client_version contains CR/LF (RFC 4253 §4.2)")
	}
	for _, list := range []string{cfg.KexAlgorithms, cfg.HostKeyAlgorithms, cfg.EncryptionAlgorithms, cfg.MACAlgorithms, cfg.CompressionAlgorithms} {
		if hasCRorLF(list) {
			return fmt.Errorf("ssh: algorithm list contains CR/LF (RFC 4253 §6)")
		}
	}
	for i, m := range cfg.AuthMethods {
		if containsNUL(m.Username) {
			return fmt.Errorf("ssh: AuthMethods[%d].username contains NUL (RFC 4252 §5.2)", i)
		}
		if containsNUL(m.Password) {
			return fmt.Errorf("ssh: AuthMethods[%d].password contains NUL (RFC 4252 §5.2)", i)
		}
		if containsNUL(m.NewPassword) {
			return fmt.Errorf("ssh: AuthMethods[%d].new_password contains NUL (RFC 4252 §5.2)", i)
		}
	}
	for i, ch := range cfg.Channels {
		if ch.Type == "channel_open" {
			if ch.SenderChannel == ReservedChannel {
				return fmt.Errorf("ssh: Channels[%d].sender_channel 0xFFFFFFFF is reserved (RFC 4254 §5.1)", i)
			}
			if ch.MaximumPacketSize == 0 {
				return fmt.Errorf("ssh: Channels[%d].maximum_packet_size must be >= 1 (RFC 4254 §5.1)", i)
			}
			if ch.InitialWindowSize > 0 && ch.MaximumPacketSize > 0 && ch.InitialWindowSize < ch.MaximumPacketSize {
				// Warning, not error per RFC 4254 §5.1; do not reject.
			}
		}
	}
	// Reason code validation (SSHMessage.Disconnect)
	for i, m := range cfg.AuthMethods {
		if m.Type == "disconnect" && m.ReasonCode == 0 {
			return fmt.Errorf("ssh: AuthMethods[%d] disconnect reason_code 0 is reserved (RFC 4253 §11.1)", i)
		}
	}
	return nil
}

// hasCRorLF reports whether s contains CR (0x0D) or LF (0x0A). Per RFC
// 4253 §4.2 the version identification string MUST NOT contain CR or LF.
func hasCRorLF(s string) bool {
	return bytes.IndexByte([]byte(s), '\r') >= 0 || bytes.IndexByte([]byte(s), '\n') >= 0
}

// containsNUL reports whether s contains a NUL byte. Per RFC 4252 §5.2
// the user_name and password strings MUST NOT contain NUL.
func containsNUL(s string) bool {
	return bytes.IndexByte([]byte(s), 0) >= 0
}

// Plan generates packet configs for an SSH flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Effective defaults — applied here, not in Validate.
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		// Resolve SSH config (nil -> default minimal dialog).
		sshCfg := spec.SSH
		if sshCfg == nil {
			sshCfg = &core.SSHConfig{}
		}

		// Default auth flow when user provided none: a minimal but realistic
		// password-shaped dialog so the planner still emits something
		// observable. Per design §4.
		authMethods := sshCfg.AuthMethods
		if len(authMethods) == 0 {
			authMethods = defaultAuthMethods()
		}

		// Default channel flow.
		channels := sshCfg.Channels
		if len(channels) == 0 {
			channels = defaultChannels()
		}

		// Resolve version strings. Empty -> default "SSH-2.0-trafficgen_1.0".
		// Default behavior per design §4: emit BOTH server and client version
		// strings when user did not opt out. (Server is "down" first per
		// RFC 4253 §4.2 — server speaks first.)
		serverVersion := sshCfg.ServerVersion
		clientVersion := sshCfg.ClientVersion

		// Default algorithm lists.
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

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
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
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()
		winSize := DefaultWindow

		// cookieGen emits deterministic-looking 16-byte cookies per KEXINIT.
		// (Test-side: relies on rand state for uniqueness; not a true
		// cryptographic cookie — encryption not implemented.)
		cookieGen := func() []byte {
			c := make([]byte, 16)
			// 16 bytes from 4 uint32s.
			for i := 0; i < 4; i++ {
				v := rand.Uint32()
				binary.BigEndian.PutUint32(c[i*4:], v)
			}
			return c
		}

		// emit sends one packet in the given direction.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: winSize,
			}
			if flags == 0x02 || flags == 0x12 {
				l4.TCPOptions = synOpts
			}
			// Pre-write Metadata["group_id"] when spec carries GroupID.
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  payload,
				Metadata: meta,
			}
			configChan <- cfg
			packetIndex++
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// emitBPP wraps the given SSH message payload in BPP framing
		// (packet_length + padding_length + payload + padding + MAC) and
		// emits it as PSH-ACK in the given direction, advancing senderSeq.
		// cipher selects block size for padding alignment:
		//   "none" -> 8 byte block (RFC 4253 §6: min block)
		//   aes128-ctr/aes192-ctr/aes256-ctr -> 16
		//   aes128-gcm/aes256-gcm -> AEAD (12 IV + 16 tag, padding=0)
		// postNewKeys toggles MAC inclusion (HMAC dummy bytes).
		emitBPP := func(direction string, senderSeq, peerSeq uint32, payload []byte, cipher string, postNewKeys bool) (newSenderSeq uint32) {
			cipherBlock := blockSizeForCipher(cipher)
			macLen := MACNone
			if postNewKeys {
				macLen = MAC256 // default hmac-sha2-256 (32B); finer per-cipher omitted for dummy
			}
			frame := buildBPP(payload, cipherBlock, macLen)
			if direction == "up" {
				return emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, senderSeq, peerSeq, frame)
			}
			return emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, senderSeq, peerSeq, frame)
		}

		// --- TCP 3-way handshake ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- Version exchange (text, no BPP) ---
		// Per design §4: server emits version FIRST. Client version AFTER.
		// VersionExchange skip rule: if ServerVersion is empty AND user did
		// not provide ClientVersion, skip both (BPP-only flow). When the
		// user provides either, emit both sides using defaults.
		if serverVersion != "" || clientVersion != "" {
			sv := serverVersion
			if sv == "" {
				sv = SSHVersionPrefix + SSHVersionDefault
			}
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(sv+SSHVersionCRLF))

			cv := clientVersion
			if cv == "" {
				cv = SSHVersionPrefix + SSHVersionDefault
			}
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(cv+SSHVersionCRLF))
		}

		// --- KEXINIT (BPP, "none" cipher, no MAC) ---
		cookieClient := cookieGen()
		cookieServer := cookieGen()
		kexInitPayload := encodeKexInit(cookieClient, kexAlgs, hostKeyAlgs, encAlgs, macAlgs, compAlgs)
		clientSeq = emitBPP("up", clientSeq, serverSeq, kexInitPayload, CipherNone, false)
		kexInitPayloadSrv := encodeKexInit(cookieServer, kexAlgs, hostKeyAlgs, encAlgs, macAlgs, compAlgs)
		serverSeq = emitBPP("down", serverSeq, clientSeq, kexInitPayloadSrv, CipherNone, false)

		// --- KEXDH_INIT / KEXDH_REPLY ---
		dhClientLen := dhPayloadLenForKEX(kex)
		dhInit := encodeKexDHInit(make([]byte, dhClientLen))
		clientSeq = emitBPP("up", clientSeq, serverSeq, dhInit, CipherNone, false)

		// KEXDH_REPLY: host_key + f + signature (dummy bytes).
		reply := encodeKexDHReply(make([]byte, 294), make([]byte, dhClientLen), make([]byte, 256))
		serverSeq = emitBPP("down", serverSeq, clientSeq, reply, CipherNone, false)

		// --- NEWKEYS (both directions, still "none" cipher until after) ---
		newKeys := []byte{MsgNewKeys}
		clientSeq = emitBPP("up", clientSeq, serverSeq, newKeys, CipherNone, false)
		serverSeq = emitBPP("down", serverSeq, clientSeq, newKeys, CipherNone, false)

		// --- EXT_INFO (optional, RFC 8308) ---
		if sshCfg.ExtInfo {
			extUp := encodeExtInfo([]string{"ext-info-c"})
			clientSeq = emitBPP("up", clientSeq, serverSeq, extUp, CipherAES, true)
			extDown := encodeExtInfo([]string{"ext-info-s"})
			serverSeq = emitBPP("down", serverSeq, clientSeq, extDown, CipherAES, true)
		}

		// --- SERVICE_REQUEST / SERVICE_ACCEPT ---
		// Per design §4: SERVICE_REQUEST "ssh-userauth" (up) + SERVICE_ACCEPT (down).
		// Subsequent SERVICE_REQUEST "ssh-connection" is implicit on auth
		// success; we don't emit it (matches OpenSSH behavior; some servers
		// auto-upgrade).
		svcReq := encodeServiceRequest("ssh-userauth")
		clientSeq = emitBPP("up", clientSeq, serverSeq, svcReq, CipherAES, true)
		svcAcc := encodeServiceAccept("ssh-userauth")
		serverSeq = emitBPP("down", serverSeq, clientSeq, svcAcc, CipherAES, true)

		// --- USERAUTH dialog ---
		disconnectEmitted := false
		for _, m := range authMethods {
			switch m.Type {
			case "userauth_request":
				payload := encodeUserAuthRequest(m)
				clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
			case "userauth_failure":
				payload := encodeUserAuthFailure(m)
				serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
			case "userauth_success":
				payload := encodeUserAuthSuccess()
				serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
			case "userauth_banner":
				payload := encodeUserAuthBanner(m)
				serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
			case "userauth_info_request":
				payload := encodeUserAuthInfoRequest(m)
				serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
			case "userauth_info_response":
				payload := encodeUserAuthInfoResponse(m)
				clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
			case "service_request":
				payload := encodeServiceRequest(m.ServiceName)
				if m.Direction == "down" {
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				} else {
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				}
			case "service_accept":
				payload := encodeServiceAccept(m.ServiceName)
				serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
			case "disconnect":
				payload := encodeDisconnect(m.ReasonCode, m.Description, m.LanguageTag)
				if m.Direction == "down" {
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				} else {
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				}
				// DISCONNECT terminates the session; skip channel dialog.
				disconnectEmitted = true
			case "ignore":
				payload := encodeIgnore(m.Data)
				if m.Direction == "down" {
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				} else {
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				}
			case "unimplemented":
				payload := encodeUnimplemented(m.ReceiveSeq)
				if m.Direction == "down" {
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				} else {
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				}
			case "debug":
				payload := encodeDebug(m.AlwaysDisplay, m.Message, m.LanguageTag)
				if m.Direction == "down" {
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				} else {
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				}
			}
		}

		// --- Channel dialog ---
		// Track auto-incremented sender_channel per design §3.10.
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
					payload := encodeChannelOpen(sc, ch.ChannelType, ch.InitialWindowSize, ch.MaximumPacketSize, ch)
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				case "channel_open_confirmation":
					payload := encodeChannelOpenConfirmation(ch.RecipientChannel, ch.SenderChannel, ch.InitialWindowSize, ch.MaximumPacketSize)
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				case "channel_open_failure":
					payload := encodeChannelOpenFailure(ch.RecipientChannel, ch.OpenReasonCode, ch.OpenReasonText, "")
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				case "channel_request":
					payload := encodeChannelRequest(ch.RecipientChannel, ch.RequestType, ch.WantReply, ch)
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				case "channel_data":
					payload := encodeChannelData(ch.RecipientChannel, ch.Data)
					if ch.Direction == "down" {
						serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
					} else {
						clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
					}
				case "channel_extended_data":
					payload := encodeChannelExtendedData(ch.RecipientChannel, ch.DataTypeCode, ch.Data)
					if ch.Direction == "down" {
						serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
					} else {
						clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
					}
				case "channel_eof":
					payload := encodeChannelEOF(ch.RecipientChannel)
					if ch.Direction == "down" {
						serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
					} else {
						clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
					}
				case "channel_close":
					payload := encodeChannelClose(ch.RecipientChannel)
					if ch.Direction == "down" {
						serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
					} else {
						clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
					}
				case "channel_window_adjust":
					payload := encodeChannelWindowAdjust(ch.RecipientChannel, ch.BytesToAdd)
					if ch.Direction == "down" {
						serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
					} else {
						clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
					}
				case "global_request":
					payload := encodeGlobalRequest(ch)
					clientSeq = emitBPP("up", clientSeq, serverSeq, payload, CipherAES, true)
				case "request_success":
					payload := encodeRequestSuccess(ch.Port)
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				case "request_failure":
					payload := encodeRequestFailure()
					serverSeq = emitBPP("down", serverSeq, clientSeq, payload, CipherAES, true)
				}
			}
		}

		// --- Optional DISCONNECT before teardown ---
		if sshCfg.DisconnectOnClose && !disconnectEmitted {
			disc := encodeDisconnect(DiscByApplication, "client closed connection", "")
			clientSeq = emitBPP("up", clientSeq, serverSeq, disc, CipherAES, true)
		}

		// --- TCP 4-way teardown ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}
