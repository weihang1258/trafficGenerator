// Package ssh encoders.go - BPP framing and per-message payload encoders.
//
// These helpers implement the SSH Binary Packet Protocol (BPP, RFC 4253 §6)
// framing and the per-message payload encoders invoked by planner.go.
//
// Encryption is NOT implemented. The padding bytes are pseudo-random
// deterministic filler, and the post-NEWKEYS MAC bytes (when present) are
// likewise dummy filler. Real SSH would use the negotiated cipher and MAC;
// the planner's outputs are wire-shaped but cryptographically meaningless -
// suitable for traffic pattern testing, not for deceiving a server that
// actually terminates SSH.
package ssh

import (
	"encoding/binary"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Algorithm defaults ---
//
// Per RFC 8308 / OpenSSH 8.9 reference. These lists are what KEXINIT offers
// when the user does not supply explicit lists. The lists are deliberately
// "modern" - they exclude deprecated algorithms (RC4, 3DES, hmac-sha1,
// diffie-hellman-group1-sha1) per OpenSSH defaults.

// DefaultKexAlgorithms is the comma-separated KEX algorithm list offered in
// KEXINIT when the user did not supply one. Per RFC 8308 §4 / RFC 8731.
const DefaultKexAlgorithms = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ext-info-c"

// DefaultHostKeyAlgorithms is the default host key algorithm list.
const DefaultHostKeyAlgorithms = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"

// DefaultEncryptionAlgorithms is the default encryption algorithm list.
const DefaultEncryptionAlgorithms = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"

// DefaultMACAlgorithms is the default MAC algorithm list.
const DefaultMACAlgorithms = "umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512"

// DefaultCompressionAlgorithms is the default compression algorithm list.
// "none" is required by RFC 4253 §6.2 to be supported.
const DefaultCompressionAlgorithms = "none,zlib@openssh.com"

// --- TCP helpers (mirror telnet) ---

// segmentByMSS splits payload into chunks no larger than mss. Mirrors
// internal/protocol/telnet.segmentByMSS.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{payload}
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

// synOptions builds TCP options for SYN packets. Mirrors telnet.synOptions.
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

// --- BPP framing helpers ---

// blockSizeForCipher returns the cipher block size used for padding
// alignment. "none" and stream ciphers use 8 (RFC 4253 §6.1 minimum block
// size). AES-CTR/AES-CBC use 16. AEAD (aes128-gcm/aes256-gcm) uses 1 (no
// alignment required per RFC 5647 §3, but the min-padding rule still
// applies via paddingLengthForBPP).
func blockSizeForCipher(cipher string) int {
	switch cipher {
	case CipherAES, "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc":
		return DefaultAESBlk
	case CipherAESGCM, "aes256-gcm@openssh.com":
		return 1 // AEAD: no alignment; padding still >= 4 unless 0 (RFC 5647)
	case CipherNone, "":
		return DefaultCipherBlk
	default:
		return DefaultCipherBlk
	}
}

// paddingLengthForBPP computes the padding length per RFC 4253 §6.1:
//   - random padding of at least 4 bytes
//   - total packet (packet_length || padding_length || payload || padding)
//     must be a multiple of the cipher block size (8 minimum)
//   - padding_length <= 255
//
// AEAD ciphers (block size 1) skip alignment but still enforce >= 4 unless
// the user opts out; we keep the 4-byte minimum for consistency with
// Wireshark dissection.
func paddingLengthForBPP(payloadLen, blockSize, macLen int) int {
	if blockSize < 1 {
		blockSize = DefaultCipherBlk
	}
	// Length of (packet_length || padding_length || payload) = 4+1+payload.
	// Add padding so total (4+1+payload+pad) is a multiple of blockSize.
	minPad := 4
	// Compute the smallest pad >= minPad such that (5+payload+pad) % blockSize == 0.
	// First compute the alignment requirement.
	for pad := minPad; pad <= DefaultMaxPad; pad++ {
		if (5+payloadLen+pad)%blockSize == 0 {
			return pad
		}
	}
	// Fallback: alignment not achievable within 4..255; return minimum 4.
	return minPad
}

// buildBPP constructs a single BPP frame:
//
//	packet_length (4B BE) || padding_length (1B) || payload || padding || MAC
//
// Padding bytes are pseudo-random (deterministic given rand state). MAC
// bytes are present only when macLen > 0 (post-NEWKEYS).
func buildBPP(payload []byte, blockSize, macLen int) []byte {
	padLen := paddingLengthForBPP(len(payload), blockSize, macLen)
	// packet_length = len(payload) + 1 + padLen (per RFC 4253 §6: does NOT
	// include the 4-byte packet_length field itself, nor the MAC).
	pktLen := uint32(1 + len(payload) + padLen)
	buf := make([]byte, 0, 4+1+len(payload)+padLen+macLen)
	pl := make([]byte, 4)
	binary.BigEndian.PutUint32(pl, pktLen)
	buf = append(buf, pl...)
	buf = append(buf, byte(padLen))
	buf = append(buf, payload...)
	// Pseudo-random padding - deterministic but looks random.
	pad := make([]byte, padLen)
	// Use math/rand for determinism across runs (no seed source - same plan
	// produces same bytes; tests do not depend on specific values).
	for i := range pad {
		pad[i] = byte(rand.Uint32())
	}
	buf = append(buf, pad...)
	if macLen > 0 {
		mac := make([]byte, macLen)
		for i := range mac {
			mac[i] = byte(rand.Uint32())
		}
		buf = append(buf, mac...)
	}
	return buf
}

// --- SSH wire-format primitives (RFC 4251 §5) ---

// encString appends a uint32-length-prefixed byte string to buf.
func encString(buf []byte, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	buf = append(buf, s...)
	return buf
}

// encStringStr is a string-typed convenience wrapper for encString.
func encStringStr(buf []byte, s string) []byte {
	return encString(buf, []byte(s))
}

// encUint32 appends a uint32 in network byte order.
func encUint32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

// encBool appends a single boolean byte (0 or 1).
func encBool(buf []byte, v bool) []byte {
	if v {
		return append(buf, 0x01)
	}
	return append(buf, 0x00)
}

// --- Default dialogs ---

// defaultAuthMethods returns a minimal but realistic password-auth dialog:
// USERAUTH_REQUEST (password) up -> USERAUTH_SUCCESS down. Per design §4.
func defaultAuthMethods() []core.SSHMessage {
	return []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: "alice", Password: "secret"},
		{Type: "userauth_success"},
	}
}

// defaultChannels returns a minimal session dialog: open session channel,
// send "exit\r\n" data, EOF, close. Per design §4.
func defaultChannels() []core.ChannelEntry {
	return []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_data", RecipientChannel: 0, Direction: "up", Data: []byte("exit\r\n")},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "up"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "up"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "down"},
	}
}

// dhPayloadLenForKEX returns the dummy DH payload byte length for the given
// KEX algorithm. These are representative sizes - not real cryptographic
// values. Used to size the dummy DH_INIT payload.
func dhPayloadLenForKEX(kex string) int {
	switch kex {
	case "curve25519-sha256", "curve25519-sha256@libssh.org":
		return 32 // X25519 public key
	case "ecdh-sha2-nistp256":
		return 65 // P-256 uncompressed point
	case "ecdh-sha2-nistp384":
		return 97 // P-384 uncompressed point
	case "ecdh-sha2-nistp521":
		return 133 // P-521 uncompressed point
	case "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1":
		return 256 // 2048-bit group
	case "diffie-hellman-group16-sha512":
		return 384 // 4096-bit group
	case "diffie-hellman-group18-sha512":
		return 512 // 8192-bit group
	case "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1":
		return 256 // negotiated group (assume 2048-bit)
	default:
		return 32
	}
}

// --- KEX layer encoders ---

// encodeKexInit builds the SSH_MSG_KEXINIT payload (msg 20) per RFC 4253 §7.1.
// All algorithm lists are sent identically in both directions (c2s and s2c).
// The cookie is 16 random bytes. first_kex_packet_follows=false, reserved=0.
func encodeKexInit(cookie []byte, kexAlgs, hostKeyAlgs, encAlgs, macAlgs, compAlgs string) []byte {
	if len(cookie) < 16 {
		c := make([]byte, 16)
		copy(c, cookie)
		cookie = c
	} else {
		cookie = cookie[:16]
	}
	buf := make([]byte, 0, 1+16+8*4+len(kexAlgs)+len(hostKeyAlgs)+2*len(encAlgs)+2*len(macAlgs)+2*len(compAlgs)+8+1+4)
	buf = append(buf, MsgKexInit)
	buf = append(buf, cookie...)
	buf = encStringStr(buf, kexAlgs)     // kex_algorithms
	buf = encStringStr(buf, hostKeyAlgs) // server_host_key_algorithms
	buf = encStringStr(buf, encAlgs)     // encryption_algorithms_c2s
	buf = encStringStr(buf, encAlgs)     // encryption_algorithms_s2c
	buf = encStringStr(buf, macAlgs)     // mac_algorithms_c2s
	buf = encStringStr(buf, macAlgs)     // mac_algorithms_s2c
	buf = encStringStr(buf, compAlgs)    // compression_algorithms_c2s
	buf = encStringStr(buf, compAlgs)    // compression_algorithms_s2c
	buf = encStringStr(buf, "")          // languages_c2s
	buf = encStringStr(buf, "")          // languages_s2c
	buf = encBool(buf, false)            // first_kex_packet_follows
	buf = encUint32(buf, 0)              // reserved (uint32)
	return buf
}

// encodeKexDHInit builds the SSH_MSG_KEXDH_INIT payload (msg 30) per RFC
// 4253 §8.1 / RFC 8731 §3.1: message || string(e). For curve25519, e is a
// 32-byte public key.
func encodeKexDHInit(e []byte) []byte {
	buf := make([]byte, 0, 1+4+len(e))
	buf = append(buf, MsgKexDHInit)
	buf = encString(buf, e)
	return buf
}

// encodeKexDHReply builds the SSH_MSG_KEXDH_REPLY payload (msg 31) per RFC
// 4253 §8.2 / RFC 8731 §3.2: message || string(K_S) || string(f) ||
// string(signature). All three are dummy opaque byte strings.
func encodeKexDHReply(hostKey, f, sig []byte) []byte {
	buf := make([]byte, 0, 1+4+len(hostKey)+4+len(f)+4+len(sig))
	buf = append(buf, MsgKexDHReply)
	buf = encString(buf, hostKey)
	buf = encString(buf, f)
	buf = encString(buf, sig)
	return buf
}

// encodeExtInfo builds the SSH_MSG_EXT_INFO payload (msg 7) per RFC 8308 §2.2:
// message || uint32 nr-extensions || (string name || string value)[].
// We emit a no-op "server-sig-algs" extension to make Wireshark happy.
func encodeExtInfo(names []string) []byte {
	buf := make([]byte, 0, 1+4)
	buf = append(buf, MsgExtInfo)
	buf = encUint32(buf, uint32(len(names)))
	for _, n := range names {
		buf = encStringStr(buf, n)
		buf = encStringStr(buf, "") // empty value (placeholder)
	}
	return buf
}

// --- Service-layer encoders ---

// encodeServiceRequest builds the SSH_MSG_SERVICE_REQUEST payload (msg 5)
// per RFC 4254 §10: message || string(service_name).
func encodeServiceRequest(name string) []byte {
	buf := make([]byte, 0, 1+4+len(name))
	buf = append(buf, MsgServiceRequest)
	buf = encStringStr(buf, name)
	return buf
}

// encodeServiceAccept builds the SSH_MSG_SERVICE_ACCEPT payload (msg 6)
// per RFC 4254 §10: message || string(service_name).
func encodeServiceAccept(name string) []byte {
	buf := make([]byte, 0, 1+4+len(name))
	buf = append(buf, MsgServiceAccept)
	buf = encStringStr(buf, name)
	return buf
}

// --- User-auth encoders ---

// encodeUserAuthRequest builds the SSH_MSG_USERAUTH_REQUEST payload (msg 50)
// per RFC 4252 §5. Supports "password", "publickey", "keyboard-interactive"
// (RFC 4256), "hostbased", and "none" methods.
func encodeUserAuthRequest(m core.SSHMessage) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, MsgUserAuthRequest)
	buf = encStringStr(buf, m.Username)
	buf = encStringStr(buf, "ssh-connection") // service name always "ssh-connection" after USERAUTH
	buf = encStringStr(buf, m.MethodName)
	switch m.MethodName {
	case "password":
		buf = encBool(buf, m.HasPasswordChange)
		buf = encStringStr(buf, m.Password)
		if m.HasPasswordChange {
			buf = encStringStr(buf, m.NewPassword)
		}
	case "publickey":
		buf = encBool(buf, m.HasSignature)
		buf = encStringStr(buf, m.PublicKeyAlgorithm)
		buf = encString(buf, m.PublicKeyBlob)
		if m.HasSignature {
			buf = encString(buf, m.Signature)
		}
	case "keyboard-interactive":
		buf = encStringStr(buf, m.Submethods)
	case "hostbased":
		buf = encStringStr(buf, m.PublicKeyAlgorithm)
		buf = encString(buf, m.PublicKeyBlob)
		buf = encStringStr(buf, m.Username) // client host name
		buf = encString(buf, m.Signature)
	case "none":
		// No method-specific fields.
	}
	return buf
}

// encodeUserAuthFailure builds the SSH_MSG_USERAUTH_FAILURE payload (msg 51)
// per RFC 4252 §5.3: message || name-list(methods) || boolean(partial_success).
func encodeUserAuthFailure(m core.SSHMessage) []byte {
	buf := make([]byte, 0, 1+4+len(m.AuthMethodsThatCanContinue)+1)
	buf = append(buf, MsgUserAuthFailure)
	buf = encStringStr(buf, m.AuthMethodsThatCanContinue)
	buf = encBool(buf, m.PartialSuccess)
	return buf
}

// encodeUserAuthSuccess builds the SSH_MSG_USERAUTH_SUCCESS payload (msg 52):
// just the message byte (RFC 4252 §5.4).
func encodeUserAuthSuccess() []byte {
	return []byte{MsgUserAuthSuccess}
}

// encodeUserAuthBanner builds the SSH_MSG_USERAUTH_BANNER payload (msg 53)
// per RFC 4252 §5.4: message || string(message) || string(language_tag).
func encodeUserAuthBanner(m core.SSHMessage) []byte {
	buf := make([]byte, 0, 1+4+len(m.Banner)+4+len(m.LanguageTag))
	buf = append(buf, MsgUserAuthBanner)
	buf = encStringStr(buf, m.Banner)
	buf = encStringStr(buf, m.LanguageTag)
	return buf
}

// encodeUserAuthInfoRequest builds the SSH_MSG_USERAUTH_INFO_REQUEST payload
// (msg 60) per RFC 4256 §5.3: message || string(name) || string(instruction)
// || string(language_tag) || uint32(num-prompts) ||
// (string(prompt) || boolean(echo))[num-prompts].
// We model prompts as a single prompt for simplicity (PromptCount controls
// how many prompt||echo pairs we emit, each using the same Prompt string).
func encodeUserAuthInfoRequest(m core.SSHMessage) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, MsgUserAuthInfoRequest)
	buf = encStringStr(buf, m.Name)
	buf = encStringStr(buf, m.Instruction)
	buf = encStringStr(buf, m.LanguageTag)
	n := m.PromptCount
	if n == 0 {
		n = 1
	}
	buf = encUint32(buf, n)
	for i := uint32(0); i < n; i++ {
		buf = encStringStr(buf, m.Prompt)
		buf = encBool(buf, m.Echo)
	}
	return buf
}

// encodeUserAuthInfoResponse builds the SSH_MSG_USERAUTH_INFO_RESPONSE
// payload (msg 61) per RFC 4256 §5.4: message || uint32(num-responses) ||
// string(responses)[num-responses].
func encodeUserAuthInfoResponse(m core.SSHMessage) []byte {
	buf := make([]byte, 0, 1+4+len(m.Responses))
	buf = append(buf, MsgUserAuthInfoResponse)
	n := m.NumResponses
	if n == 0 {
		n = 1
	}
	buf = encUint32(buf, n)
	for i := uint32(0); i < n; i++ {
		buf = encStringStr(buf, m.Response)
	}
	return buf
}

// --- Generic transport-layer encoders ---

// encodeDisconnect builds the SSH_MSG_DISCONNECT payload (msg 1) per RFC
// 4253 §11.1: message || uint32(reason) || string(description) ||
// string(language_tag).
func encodeDisconnect(reason uint32, description, language string) []byte {
	buf := make([]byte, 0, 1+4+4+len(description)+4+len(language))
	buf = append(buf, MsgDisconnect)
	buf = encUint32(buf, reason)
	buf = encStringStr(buf, description)
	buf = encStringStr(buf, language)
	return buf
}

// encodeIgnore builds the SSH_MSG_IGNORE payload (msg 2) per RFC 4253 §11.2:
// message || string(data).
func encodeIgnore(data []byte) []byte {
	buf := make([]byte, 0, 1+4+len(data))
	buf = append(buf, MsgIgnore)
	buf = encString(buf, data)
	return buf
}

// encodeUnimplemented builds the SSH_MSG_UNIMPLEMENTED payload (msg 3) per
// RFC 4253 §11.3: message || uint32(seq).
func encodeUnimplemented(seq uint32) []byte {
	buf := make([]byte, 0, 5)
	buf = append(buf, MsgUnimplemented)
	buf = encUint32(buf, seq)
	return buf
}

// encodeDebug builds the SSH_MSG_DEBUG payload (msg 4) per RFC 4253 §11.4:
// message || boolean(always_display) || string(message) ||
// string(language_tag).
func encodeDebug(alwaysDisplay bool, message, language string) []byte {
	buf := make([]byte, 0, 1+1+4+len(message)+4+len(language))
	buf = append(buf, MsgDebug)
	buf = encBool(buf, alwaysDisplay)
	buf = encStringStr(buf, message)
	buf = encStringStr(buf, language)
	return buf
}

// --- Channel-layer encoders (RFC 4254) ---

// encodeChannelOpen builds the SSH_MSG_CHANNEL_OPEN payload (msg 90) per RFC
// 4254 §5.1: message || string(type) || uint32(sender) || uint32(window) ||
// uint32(max_pkt) || ... type-specific. For "direct-tcpip" we append the
// dest host/port + originator host/port. For "session" there are no extras.
func encodeChannelOpen(sender uint32, channelType string, window, maxPkt uint32, ch core.ChannelEntry) []byte {
	if window == 0 {
		window = DefaultChanWin
	}
	if maxPkt == 0 {
		maxPkt = DefaultChanPkt
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, MsgChannelOpen)
	buf = encStringStr(buf, channelType)
	buf = encUint32(buf, sender)
	buf = encUint32(buf, window)
	buf = encUint32(buf, maxPkt)
	switch channelType {
	case "direct-tcpip":
		buf = encStringStr(buf, ch.DestHost)
		buf = encUint32(buf, ch.DestPort)
		buf = encStringStr(buf, ch.OriginatorIP)
		buf = encUint32(buf, ch.OriginatorPort)
	case "forwarded-tcpip":
		buf = encStringStr(buf, ch.Address)
		buf = encUint32(buf, ch.Port)
		buf = encStringStr(buf, ch.OriginatorIP)
		buf = encUint32(buf, ch.OriginatorPort)
	case "x11":
		buf = encStringStr(buf, ch.OriginatorIP)
		buf = encUint32(buf, ch.OriginatorPort)
	}
	return buf
}

// encodeChannelOpenConfirmation builds the SSH_MSG_CHANNEL_OPEN_CONFIRMATION
// payload (msg 91) per RFC 4254 §5.1: message || uint32(recipient) ||
// uint32(sender) || uint32(window) || uint32(max_pkt).
func encodeChannelOpenConfirmation(recipient, sender, window, maxPkt uint32) []byte {
	if window == 0 {
		window = DefaultChanWin
	}
	if maxPkt == 0 {
		maxPkt = DefaultChanPkt
	}
	buf := make([]byte, 0, 17)
	buf = append(buf, MsgChannelOpenConf)
	buf = encUint32(buf, recipient)
	buf = encUint32(buf, sender)
	buf = encUint32(buf, window)
	buf = encUint32(buf, maxPkt)
	return buf
}

// encodeChannelOpenFailure builds the SSH_MSG_CHANNEL_OPEN_FAILURE payload
// (msg 92) per RFC 4254 §5.2: message || uint32(recipient) ||
// uint32(reason) || string(description) || string(language).
func encodeChannelOpenFailure(recipient, reason uint32, description, language string) []byte {
	if reason == 0 {
		reason = OpenConnectFailed
	}
	buf := make([]byte, 0, 1+4+4+4+len(description)+4+len(language))
	buf = append(buf, MsgChannelOpenFailure)
	buf = encUint32(buf, recipient)
	buf = encUint32(buf, reason)
	buf = encStringStr(buf, description)
	buf = encStringStr(buf, language)
	return buf
}

// encodeChannelRequest builds the SSH_MSG_CHANNEL_REQUEST payload (msg 98)
// per RFC 4254 §6.x: message || uint32(recipient) || string(type) ||
// boolean(want_reply) || ... type-specific. We support the common request
// types: pty-req, exec, shell, env, subsystem, signal, exit-status,
// x11-req, window-change.
func encodeChannelRequest(recipient uint32, reqType string, wantReply bool, ch core.ChannelEntry) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, MsgChannelRequest)
	buf = encUint32(buf, recipient)
	buf = encStringStr(buf, reqType)
	buf = encBool(buf, wantReply)
	switch reqType {
	case "pty-req":
		buf = encStringStr(buf, ch.Term)
		buf = encUint32(buf, ch.WidthChars)
		buf = encUint32(buf, ch.HeightRows)
		buf = encUint32(buf, ch.WidthPixels)
		buf = encUint32(buf, ch.HeightPixels)
		buf = encString(buf, ch.TTYModes)
	case "exec":
		buf = encStringStr(buf, ch.Command)
	case "shell":
		// no extra fields
	case "env":
		buf = encStringStr(buf, ch.EnvVarName)
		buf = encStringStr(buf, ch.EnvVarValue)
	case "subsystem":
		buf = encStringStr(buf, ch.SubsystemName)
	case "signal":
		buf = encStringStr(buf, ch.SignalName)
	case "exit-status":
		buf = encUint32(buf, ch.ExitStatus)
	case "exit-signal":
		buf = encStringStr(buf, ch.SignalName)
		buf = encBool(buf, false)   // core dumped
		buf = encStringStr(buf, "") // error message
		buf = encStringStr(buf, "") // language
	case "window-change":
		buf = encUint32(buf, ch.WidthChars)
		buf = encUint32(buf, ch.HeightRows)
		buf = encUint32(buf, ch.WidthPixels)
		buf = encUint32(buf, ch.HeightPixels)
	case "x11-req":
		buf = encBool(buf, ch.SingleConnection)
		buf = encStringStr(buf, ch.X11AuthProtocol)
		buf = encString(buf, ch.X11AuthCookie)
		buf = encUint32(buf, ch.X11ScreenNumber)
	}
	return buf
}

// encodeChannelData builds the SSH_MSG_CHANNEL_DATA payload (msg 94) per
// RFC 4254 §6.1: message || uint32(recipient) || string(data).
func encodeChannelData(recipient uint32, data []byte) []byte {
	buf := make([]byte, 0, 1+4+4+len(data))
	buf = append(buf, MsgChannelData)
	buf = encUint32(buf, recipient)
	buf = encString(buf, data)
	return buf
}

// encodeChannelExtendedData builds the SSH_MSG_CHANNEL_EXTENDED_DATA payload
// (msg 95) per RFC 4254 §6.2: message || uint32(recipient) ||
// uint32(data_type) || string(data).
func encodeChannelExtendedData(recipient, dataType uint32, data []byte) []byte {
	buf := make([]byte, 0, 1+4+4+4+len(data))
	buf = append(buf, MsgChannelExtendedData)
	buf = encUint32(buf, recipient)
	buf = encUint32(buf, dataType)
	buf = encString(buf, data)
	return buf
}

// encodeChannelEOF builds the SSH_MSG_CHANNEL_EOF payload (msg 96) per RFC
// 4254 §6.3: message || uint32(recipient).
func encodeChannelEOF(recipient uint32) []byte {
	buf := make([]byte, 0, 5)
	buf = append(buf, MsgChannelEOF)
	buf = encUint32(buf, recipient)
	return buf
}

// encodeChannelClose builds the SSH_MSG_CHANNEL_CLOSE payload (msg 97) per
// RFC 4254 §6.4: message || uint32(recipient).
func encodeChannelClose(recipient uint32) []byte {
	buf := make([]byte, 0, 5)
	buf = append(buf, MsgChannelClose)
	buf = encUint32(buf, recipient)
	return buf
}

// encodeChannelWindowAdjust builds the SSH_MSG_CHANNEL_WINDOW_ADJUST payload
// (msg 93) per RFC 4254 §6.5: message || uint32(recipient) ||
// uint32(bytes_to_add).
func encodeChannelWindowAdjust(recipient, bytesToAdd uint32) []byte {
	buf := make([]byte, 0, 9)
	buf = append(buf, MsgChannelWindowAdjust)
	buf = encUint32(buf, recipient)
	buf = encUint32(buf, bytesToAdd)
	return buf
}

// encodeGlobalRequest builds the SSH_MSG_GLOBAL_REQUEST payload (msg 80) per
// RFC 4254 §7: message || string(name) || boolean(want_reply) || ...
// name-specific. We support "tcpip-forward" and "cancel-tcpip-forward".
func encodeGlobalRequest(ch core.ChannelEntry) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, MsgGlobalRequest)
	buf = encStringStr(buf, ch.GlobalRequestName)
	buf = encBool(buf, ch.WantReply)
	switch ch.GlobalRequestName {
	case "tcpip-forward", "cancel-tcpip-forward":
		buf = encStringStr(buf, ch.Address)
		buf = encUint32(buf, ch.Port)
	case "no-more-sessions@openssh.com":
		// no extras
	}
	return buf
}

// encodeRequestSuccess builds the SSH_MSG_REQUEST_SUCCESS payload (msg 81)
// per RFC 4254 §7: for tcpip-forward, contains the bound port (uint32).
func encodeRequestSuccess(port uint32) []byte {
	buf := make([]byte, 0, 5)
	buf = append(buf, MsgRequestSuccess)
	if port > 0 {
		buf = encUint32(buf, port)
	}
	return buf
}

// encodeRequestFailure builds the SSH_MSG_REQUEST_FAILURE payload (msg 82)
// per RFC 4254 §7: just the message byte.
func encodeRequestFailure() []byte {
	return []byte{MsgRequestFailure}
}
