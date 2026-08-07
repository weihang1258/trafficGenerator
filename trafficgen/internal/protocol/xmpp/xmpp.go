// Package xmpp implements the XMPP (Extensible Messaging and Presence
// Protocol, 可扩展消息与存在协议) planner (RFC 6120, port 5222).
//
// Reference pcap: /home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.89-20.3.1.89-
// 58340-5222-11-7-1203-1392.pcap (18 frames, SCRAM-SHA-1 session that
// fails with <invalid-authzid/> — trafficgen only generates the happy path).
//
// The planner emits a complete XMPP session over TCP:
//
//  1. TCP 3-way handshake (SYN/SYN-ACK/ACK) with MSS/WinScale/SACK options.
//  2. Stream opening: client sends <stream:stream to='...' ...>,
//     server replies with <stream:stream ...><stream:features>...
//     (advertises STARTTLS, SASL mechanisms, compression, roster version).
//  3. SASL authentication (SASL认证):
//     a. PLAIN (RFC 4616): single <auth mechanism='PLAIN'>AGJvYgBzZWNyZXQ=
//        (base64 of \0user\0pass), server replies <success/>.
//     b. DIGEST-MD5 (RFC 2831): <auth/>, server <challenge/>,
//        client <response/>, server <challenge/>, client <response/>,
//        server <success/>.
//  4. Stream restart (流重启): client reopens <stream:stream> after auth.
//     Server replies with new <stream:features> (bind, session).
//  5. Resource binding (资源绑定): client <iq type='set'><bind/></iq>,
//     server <iq type='result'><bind><jid>...</jid></bind></iq>.
//  6. Session establishment (会话建立): client <iq type='set'><session/></iq>,
//     server <iq type='result'/>.
//  7. Presence (存在状态): client <presence/> (optional, default on).
//  8. Messages (消息): zero or more <message> stanzas, direction up/down.
//  9. Stream close (流关闭): client </stream:stream>, server </stream:stream>.
// 10. TCP 3-way teardown (TCP三次挥手): FIN/FIN-ACK/ACK.
//
// The fixed signaling phase (2-6) is protocol-driven; messages (8) and
// presence (7) are user-controlled.
package xmpp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical XMPP client port (RFC 6120 §13.3).
	DefaultPort = 5222

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// TCP flags (TCP标志位).
	tcpSYN    = 0x02 // SYN (同步)
	tcpSYNACK = 0x12 // SYN-ACK (同步确认)
	tcpACK    = 0x10 // ACK (确认)
	tcpPSHACK = 0x18 // PSH-ACK (推送确认)
	tcpFINACK = 0x11 // FIN-ACK (结束确认)

	// XMPP namespace URIs (XMPP命名空间).
	nsXMPPClient = "jabber:client"
	nsStream     = "http://etherx.jabber.org/streams"
	nsSASL       = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsTLS        = "urn:ietf:params:xml:ns:xmpp-tls"
	nsBind       = "urn:ietf:params:xml:ns:xmpp-bind"
	nsSession    = "urn:ietf:params:xml:ns:xmpp-session"
	nsCompress   = "http://jabber.org/features/compress"
	nsRosterVer  = "urn:xmpp:features:rosterver"

	// Default values (默认值) for config fields when empty.
	defaultFrom      = "example.com"    // 默认服务器域名
	defaultJID       = "user@example.com" // 默认Jabber ID
	defaultResource  = "trafficgen"      // 默认资源名
	defaultStreamID  = "a1b2c3d4e5f6"   // 默认流ID
	defaultAuthMech  = "PLAIN"           // 默认认证机制
	defaultUsername  = "user"            // 默认用户名
	defaultPassword  = "pass"            // 默认密码
	defaultMessageTo = "bob@example.com" // 默认消息接收方
)

// Planner implements the XMPP protocol planner (XMPP协议规划器).
type Planner struct{}

// NewPlanner creates a new XMPP planner (创建新的XMPP规划器).
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name (返回协议名称).
func (p *Planner) Name() string { return "xmpp" }

// Validate validates an XMPP flow spec (验证XMPP流规格).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("xmpp: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("xmpp: invalid DstIP %q", spec.DstIP)
		}
	}

	x := spec.Xmpp
	if x == nil {
		return fmt.Errorf("xmpp: XmppConfig is required")
	}

	// AuthMechanism (认证机制) validation. Empty defaults to PLAIN
	// (design: user > default > none pattern).
	mech := normalizeAuthMech(x.AuthMechanism)
	if mech == "" {
		mech = defaultAuthMech
	}
	switch mech {
	case "PLAIN", "DIGEST-MD5", "SCRAM-SHA-1", "ANONYMOUS":
	default:
		return fmt.Errorf("xmpp: unsupported auth mechanism %q (supported: PLAIN, DIGEST-MD5, SCRAM-SHA-1, ANONYMOUS)", x.AuthMechanism)
	}

	// MSS (最大分段大小) validation.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("xmpp: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
		}
	}

	// Messages (消息) validation: direction must be "up" or "down".
	for i, m := range x.Messages {
		dir := normalizeDirection(m.Direction)
		if dir != "" && dir != "up" && dir != "down" {
			return fmt.Errorf("xmpp: message[%d] invalid direction %q (must be up or down)", i, m.Direction)
		}
	}

	return nil
}

// Plan generates packet configs for an XMPP session (生成XMPP会话的包配置).
//
// The method returns a channel of PacketConfig representing the full XMPP
// session from TCP handshake through stream close and TCP teardown.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		x := spec.Xmpp
		if x == nil {
			x = &core.XmppConfig{}
		}

		// Apply defaults (应用默认值).
		fromDomain := x.From
		if fromDomain == "" {
			fromDomain = defaultFrom
		}
		jid := x.JID
		if jid == "" {
			jid = defaultJID
		}
		resource := x.Resource
		if resource == "" {
			resource = defaultResource
		}
		streamID := x.StreamID
		if streamID == "" {
			streamID = defaultStreamID
		}
		mech := normalizeAuthMech(x.AuthMechanism)
		if mech == "" {
			mech = defaultAuthMech
		}
		username := x.Username
		if username == "" {
			username = defaultUsername
		}
		password := x.Password
		if password == "" {
			password = defaultPassword
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Resolve MSS (最大分段大小).
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

		// Random ISN per RFC 6528 (每RFC 6528的随机初始序列号).
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randUint32()
		}
		serverSeq := randUint32()

		winSize := uint16(65535)

		// emit (发送包) sends a TCP packet config to the channel.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
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
			if flags == tcpSYN || flags == tcpSYNACK {
				l4.TCPOptions = synOpts
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
				Metadata: groupIDMeta(spec),
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// emitData (发送数据段) sends a payload as PSH-ACK, advancing seq.
		// Payloads are assumed to fit within MSS (XMPP stanzas are small).
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, tcpPSHACK, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- Phase 1: TCP 3-way handshake (TCP三次握手) ---
		// Frame 1: SYN (client→server, 客户端发送同步)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, tcpSYN, nil)
		clientSeq++
		// Frame 2: SYN-ACK (server→client, 服务端回复同步确认)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpSYNACK, nil)
		serverSeq++
		// Frame 3: ACK (client→server, 客户端确认)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)

		// --- Phase 2: Stream opening (流开启, RFC 6120 §4.2) ---
		// Frame 4: Client → <stream:stream to='domain' xmlns='jabber:client' ...>
		streamOpen := buildStreamOpen(fromDomain)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, streamOpen)

		// Frame 5: Server → stream opening + features (流开启+功能特性)
		// Per reference pcap frame 6, the stream features include STARTTLS,
		// SASL mechanisms (CRAM-MD5, LOGIN, PLAIN, DIGEST-MD5, SCRAM-SHA-1),
		// compression (zlib), and roster version (optional).
		featuresResp := buildStreamFeatures(fromDomain, streamID)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, featuresResp)

		// --- Phase 3: SASL authentication (SASL认证, RFC 6120 §6) ---
		switch mech {
		case "PLAIN":
			// PLAIN (RFC 4616, 简单认证): single auth + success exchange.
			// Auth payload: base64("\0" + username + "\0" + password)
			// 客户端发送认证请求
			authPlain := buildAuthPlain(username, password)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authPlain)

			// 服务端回复成功 (trafficgen only generates success path)
			success := buildSuccess()
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, success)

		case "DIGEST-MD5":
			// DIGEST-MD5 (RFC 2831): multi-step challenge/response exchange.
			// Per reference pcap pattern (frames 8-15, SCRAM-SHA-1 variant):
			// auth → challenge(empty) → response → challenge(nonce) → response → success.
			// trafficgen generates a simplified but wire-valid exchange.

			// 客户端发起认证 (empty auth element)
			authDigest := buildAuthMechanism("DIGEST-MD5")
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authDigest)

			// 服务端发送挑战 (server challenge with nonce)
			challenge1 := buildChallenge(defaultDigestChallenge)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, challenge1)

			// 客户端回复 (client response with digest)
			response1 := buildResponse(defaultDigestResponse)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, response1)

			// 服务端确认 (server success with rspauth)
			success := buildSuccessWithContent(defaultDigestRspauth)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, success)

		case "SCRAM-SHA-1":
			// SCRAM-SHA-1 (RFC 5802): multi-step exchange matching the
			// reference pcap pattern (frames 8-14, SCRAM-SHA-1 variant).

			// 客户端发起认证 (auth with mechanism)
			authScram := buildAuthMechanism("SCRAM-SHA-1")
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authScram)

			// 服务端空挑战 (empty challenge, per reference pcap frame 9)
			challenge1 := buildChallenge("")
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, challenge1)

			// 客户端第一次回复 (client-first response)
			response1 := buildResponse(defaultScramResponse1)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, response1)

			// 服务端挑战 (server challenge with nonce, per reference frame 12)
			challenge2 := buildChallenge(defaultScramChallenge)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, challenge2)

			// 客户端第二次回复 (client-final response)
			response2 := buildResponse(defaultScramResponse2)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, response2)

			// 服务端成功 (success with verification)
			success := buildSuccessWithContent(defaultScramVerification)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, success)

		case "ANONYMOUS":
			// ANONYMOUS (匿名认证, RFC 4505): single auth + success.

			// 客户端发送匿名认证
			authAnon := buildAuthAnonymous()
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authAnon)

			// 服务端确认成功
			success := buildSuccess()
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, success)
		}

		// --- Phase 4: Stream restart (流重启, RFC 6120 §4.3.3.2) ---
		// After SASL success the client MUST re-open a new stream.
		// 认证后客户端必须重新开启流
		streamRestart := buildStreamOpen(fromDomain)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, streamRestart)

		// 服务端回复新流+绑定/会话功能特性
		postAuthFeatures := buildPostAuthFeatures(fromDomain, streamID)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, postAuthFeatures)

		// --- Phase 5: Resource binding (资源绑定, RFC 6120 §7) ---
		bindReq := buildBindRequest(jid, resource)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, bindReq)

		bindResult := buildBindResult(jid, resource)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, bindResult)

		// --- Phase 6: Session establishment (会话建立, RFC 3921 §3) ---
		sessReq := buildSessionRequest()
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, sessReq)

		sessResult := buildSessionResult()
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, sessResult)

		// --- Phase 7: Presence (存在状态, RFC 6121 §4) ---
		// Default: client sends initial presence (客户端发送初始存在状态).
		// Presence is *bool: nil or *true → emit; *false → skip.
		emitPresence := true
		if x.Presence != nil {
			emitPresence = *x.Presence
		}
		if emitPresence {
			presence := []byte("<presence/>")
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, presence)
		}

		// --- Phase 8: Messages (消息交换, RFC 6121 §5) ---
		for _, msg := range x.Messages {
			select {
			case <-ctx.Done():
				return
			default:
			}
			dir := normalizeDirection(msg.Direction)
			if dir == "" {
				dir = "up"
			}
			to := msg.To
			if to == "" {
				to = defaultMessageTo
			}
			body := msg.Body
			if body == "" {
				body = "Hello from trafficgen"
			}

			stanza := buildMessageStanza(to, body)

			if dir == "down" {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, stanza)
			} else {
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, stanza)
			}
		}

		// --- Phase 9: Stream close (流关闭, RFC 6120 §4.4) ---
		// 客户端发送流结束标签
		streamClose := []byte("</stream:stream>")
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, streamClose)

		// 服务端回复流结束标签
		serverStreamClose := []byte("</stream:stream>")
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, serverStreamClose)

		// --- Phase 10: TCP teardown (TCP三次挥手) ---
		// Frame N: FIN-ACK (client→server)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpFINACK, nil)
		clientSeq++
		// Frame N+1: FIN-ACK (server→client)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpFINACK, nil)
		serverSeq++
		// Frame N+2: ACK (client→server)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)
	}()

	return configChan, nil
}

// --- Helper functions (辅助函数) ---

// groupIDMeta returns the group_id metadata (返回组ID元数据) when the spec
// has a GroupID strategy (keeps sub-flows on the same PacketWorker).
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	return nil
}

// buildStreamOpen builds the client stream opening tag (构建客户端流开启标签):
// `<?xml version='1.0' ?><stream:stream to='domain' xmlns='jabber:client'
// xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`.
// Matches reference pcap frame 4.
func buildStreamOpen(to string) []byte {
	return []byte(fmt.Sprintf(
		"<?xml version='1.0' ?><stream:stream to='%s' xmlns='%s' xmlns:stream='%s' version='1.0'>",
		to, nsXMPPClient, nsStream,
	))
}

// buildStreamFeatures builds the server stream response + features
// (构建服务端流回复+功能特性). Matches reference pcap frame 6.
//
// Features include:
//   - <starttls/> (TLS协商)
//   - <mechanisms> with available SASL mechanisms (SASL认证机制列表)
//   - <compression> with zlib (压缩方式)
//   - <ver> with <optional/> (名册版本, RFC 6121 §2.5)
func buildStreamFeatures(from, streamID string) []byte {
	// Build mechanisms list matching reference pcap: CRAM-MD5, LOGIN,
	// PLAIN, DIGEST-MD5, SCRAM-SHA-1.
	mechs := []string{"CRAM-MD5", "LOGIN", "PLAIN", "DIGEST-MD5", "SCRAM-SHA-1"}
	mechXML := ""
	for _, m := range mechs {
		mechXML += fmt.Sprintf("<mechanism>%s</mechanism>", m)
	}
	return []byte(fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' from='%s' id='%s' version='1.0'>"+
			"<stream:features>"+
			"<starttls xmlns='%s'/>"+
			"<mechanisms xmlns='%s'>%s</mechanisms>"+
			"<compression xmlns='%s'><method>zlib</method></compression>"+
			"<ver xmlns='%s'><optional/></ver>"+
			"</stream:features>",
		nsXMPPClient, nsStream, from, streamID,
		nsTLS,
		nsSASL, mechXML,
		nsCompress,
		nsRosterVer,
	))
}

// buildPostAuthFeatures builds the server stream features after authentication
// (构建认证后服务端流功能特性). After SASL success, the stream restart shows
// the bind and session features (RFC 6120 §4.3.3.2).
func buildPostAuthFeatures(from, streamID string) []byte {
	return []byte(fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' from='%s' id='%s' version='1.0'>"+
			"<stream:features>"+
			"<bind xmlns='%s'/>"+
			"<session xmlns='%s'/>"+
			"<ver xmlns='%s'/>"+
			"</stream:features>",
		nsXMPPClient, nsStream, from, streamID,
		nsBind,
		nsSession,
		nsRosterVer,
	))
}

// buildAuthPlain builds the PLAIN auth stanza (构建PLAIN认证节):
// `<auth xmlns='...' mechanism='PLAIN'>base64(\0user\0pass)</auth>`.
// RFC 4616: authzid\0authcid\0passwd.
func buildAuthPlain(username, password string) []byte {
	// PLAIN format (RFC 4616): authorization-id NUL authentication-id NUL password
	plainBytes := fmt.Sprintf("\x00%s\x00%s", username, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(plainBytes))
	return []byte(fmt.Sprintf(
		"<auth xmlns='%s' mechanism='PLAIN'>%s</auth>",
		nsSASL, encoded,
	))
}

// buildAuthMechanism builds an empty auth element (构建空认证元素) for
// challenge-response mechanisms like DIGEST-MD5 and SCRAM-SHA-1.
func buildAuthMechanism(mech string) []byte {
	return []byte(fmt.Sprintf(
		"<auth xmlns='%s' mechanism='%s'/>",
		nsSASL, mech,
	))
}

// buildAuthAnonymous builds the ANONYMOUS auth stanza (构建匿名认证节).
// RFC 4505: mechanism='ANONYMOUS' with optional trace info.
func buildAuthAnonymous() []byte {
	return []byte(fmt.Sprintf(
		"<auth xmlns='%s' mechanism='ANONYMOUS'/>",
		nsSASL,
	))
}

// buildSuccess builds a bare <success/> stanza (构建成功节).
func buildSuccess() []byte {
	return []byte(fmt.Sprintf("<success xmlns='%s'/>", nsSASL))
}

// buildSuccessWithContent builds a <success> with content (构建带内容的成功节),
// used by DIGEST-MD5 (rspauth) and SCRAM-SHA-1 (server-signature).
func buildSuccessWithContent(content string) []byte {
	return []byte(fmt.Sprintf("<success xmlns='%s'>%s</success>", nsSASL, content))
}

// buildChallenge builds a <challenge> stanza (构建挑战节).
// Empty content → `<challenge ...></challenge>` (per reference pcap frame 9).
func buildChallenge(content string) []byte {
	return []byte(fmt.Sprintf("<challenge xmlns='%s'>%s</challenge>", nsSASL, content))
}

// buildResponse builds a <response> stanza (构建响应节).
func buildResponse(content string) []byte {
	return []byte(fmt.Sprintf("<response xmlns='%s'>%s</response>", nsSASL, content))
}

// buildBindRequest builds the resource binding request (构建资源绑定请求):
// `<iq type='set' id='bind_1'><bind xmlns='...'><resource>name</resource></bind></iq>`.
func buildBindRequest(jid, resource string) []byte {
	return []byte(fmt.Sprintf(
		"<iq type='set' id='bind_1'><bind xmlns='%s'><resource>%s</resource></bind></iq>",
		nsBind, resource,
	))
}

// buildBindResult builds the bind result response (构建绑定结果响应):
// `<iq type='result' id='bind_1'><bind xmlns='...'><jid>user@domain/res</jid></bind></iq>`.
func buildBindResult(jid, resource string) []byte {
	fullJID := jid + "/" + resource
	return []byte(fmt.Sprintf(
		"<iq type='result' id='bind_1'><bind xmlns='%s'><jid>%s</jid></bind></iq>",
		nsBind, fullJID,
	))
}

// buildSessionRequest builds the session establishment request (构建会话建立请求):
// `<iq type='set' id='sess_1'><session xmlns='...'/></iq>`.
func buildSessionRequest() []byte {
	return []byte(fmt.Sprintf(
		"<iq type='set' id='sess_1'><session xmlns='%s'/></iq>",
		nsSession,
	))
}

// buildSessionResult builds the session result response (构建会话结果响应):
// `<iq type='result' id='sess_1'/>`.
func buildSessionResult() []byte {
	return []byte(fmt.Sprintf(
		"<iq type='result' id='sess_1'/>",
	))
}

// buildMessageStanza builds an XMPP message stanza (构建消息节):
// `<message to='...' type='chat'><body>...</body></message>`.
func buildMessageStanza(to, body string) []byte {
	return []byte(fmt.Sprintf(
		"<message to='%s' type='chat'><body>%s</body></message>",
		to, body,
	))
}

// --- Normalization helpers (归一化辅助函数) ---

// normalizeAuthMech normalizes the auth mechanism string to canonical form.
func normalizeAuthMech(m string) string {
	s := strings.TrimSpace(m)
	switch strings.ToUpper(s) {
	case "PLAIN":
		return "PLAIN"
	case "DIGEST-MD5":
		return "DIGEST-MD5"
	case "SCRAM-SHA-1":
		return "SCRAM-SHA-1"
	case "ANONYMOUS":
		return "ANONYMOUS"
	default:
		return s
	}
}

// normalizeDirection normalizes a direction string to lowercase (归一化方向字符串).
func normalizeDirection(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// --- Random / utility helpers (随机/工具辅助函数) ---

// randUint32 returns a random uint32 (返回随机uint32).
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42 // fallback
	}
	return uint32(n.Uint64())
}

// segmentByMSS splits payload into chunks of at most mss bytes (按MSS分段).
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

// synOptions builds TCP options for SYN packets (构建SYN包的TCP选项).
// MSS + WinScale(7) + SACK-Permitted, matching reference pcap.
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

// --- Default challenge/response data for multi-step SASL mechanisms ---
// These are base64-encoded placeholder values matching the reference pcap
// pattern (real crypto is not needed for trafficgen — the wire format is
// what matters for DPI/protocol tests).

// defaultDigestChallenge is a placeholder DIGEST-MD5 challenge (nonce + realm).
var defaultDigestChallenge = base64.StdEncoding.EncodeToString([]byte(
	`realm="example.com",nonce="dGhpcyBpcyBhIG5vbmNl",qop="auth",charset=utf-8,algorithm=md5-sess`,
))

// defaultDigestResponse is a placeholder DIGEST-MD5 response.
var defaultDigestResponse = base64.StdEncoding.EncodeToString([]byte(
	`username="user",realm="example.com",nonce="dGhpcyBpcyBhIG5vbmNl",cnonce="b3JpZ2luYWxseSBhIGNsaWVudCBub25jZQ==",nc=00000001,qop=auth,digest-uri="xmpp/example.com",response=d388ced5e8e294761a2800c29322a67f,charset=utf-8`,
))

// defaultDigestRspauth is the rspauth content in the server success (DIGEST-MD5).
var defaultDigestRspauth = base64.StdEncoding.EncodeToString([]byte(
	`rspauth=ea40f60335c427b5527b84dbabcdfffd`,
))

// defaultScramResponse1 is the SCRAM-SHA-1 client-first-message
// (matching reference pcap frame 11: biwsbj1rb21hX3Rlc3Qscj1oeWRyYQ==).
var defaultScramResponse1 = "biwsbj1rb21hX3Rlc3Qscj1oeWRyYQ=="

// defaultScramChallenge is the SCRAM-SHA-1 server-first-message
// (matching reference pcap frame 12 pattern).
var defaultScramChallenge = "cj1oeWRyYTRPam9GQkdGSnl6VGFCV0tpR2Z1cU5NK3Y5ckRBMHduLHM9cWdpSklKUXNRUGh2QW90SldWTkhQUT09LGk9NDA5Ng=="

// defaultScramResponse2 is the SCRAM-SHA-1 client-final-message
// (matching reference pcap frame 14 pattern).
var defaultScramResponse2 = "Yz1iaXdzLHI9aHlkcmE0T2pvRkJHRkp5elRhQldLaUdmdXFOTSt2OXJEQTB3bixwPWFudnhSUnY3U1ZLSXd3c0ozWTYvMGhLQzBZVT0="

// defaultScramVerification is the SCRAM-SHA-1 server-signature in success.
var defaultScramVerification = "dj1yb0lqTzRVaFg3a0l6VU5YUWJXcEVWbExrPQ=="
