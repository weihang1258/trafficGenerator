// Package socks5 implements the SOCKS proxy protocol planner (RFC 1928
// SOCKS5, RFC 1929 username/password auth, and the unofficial SOCKS4/SOCKS4a
// protocol). Reference pcaps: llcj dport=1080 (10 SOCKS4 + 14 SOCKS5
// sessions, all wire-identical).
//
// A single SOCKS session is one TCP 4-tuple carrying both signaling and
// tunneled data (SOCKS is a proxy protocol: the client asks the proxy to
// reach a target, then payload bytes flow through the same TCP connection).
// The planner emits:
//
// SOCKS5 (RFC 1928):
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options.
//  2. Fixed signaling phase, one PSH-ACK per message, order protocol-fixed
//     (unlike RTSP's user-driven dialog):
//     a. Greeting (up) `05 01 <METHOD>` -> Method Response (down) `05 <M>`.
//     b. AuthMethod=password: RFC 1929 auth request (up) -> auth response
//     (down, STATUS always 0x00 — trafficgen only generates success).
//     c. Request (up) `05 <CMD> 00 <ATYP> <ADDR> <PORT>` -> Reply (down)
//     `05 <REP> 00 <ATYP> <BND.ADDR> <BND.PORT>`.
//  3. Data plane when Rep=0: each Data message is tunneled as one PSH-ACK
//     (MSS-segmented if oversized), direction per message (default "up").
//     Cmd=udp_associate: UDP relay sub-flow (RFC 1928 §7), each datagram =
//     RSV(2)+FRAG(1)+ATYP+ADDR+PORT header + payload, direction per config
//     (default "down" = proxy→client).
//  4. TCP 3-way teardown (FIN, FIN-ACK, ACK) — reference pcap frames 12-14.
//
// SOCKS4 (no RFC, see www.openssh.com/txt/socks4.protocol):
//  1. TCP 3-way handshake.
//  2. Request (up) `04 <CD> <DSTPORT> <DSTIP> <USERID> 00` -> Reply (down)
//     `00 5A|5B <BNDPORT> <BNDIP>`. No greeting/auth phase.
//  3. Data plane when granted (Rep=0) — reference pcaps carry tunneled HTTP.
//  4. TCP 3-way teardown (FIN, FIN-ACK, ACK).
//
// SOCKS4a extension: when Version=socks4 and DstAddr is a domain name,
// DSTIP=0.0.0.1 and the domain follows the USERID terminator directly
// (0x00-terminated, NO length prefix).
package socks5

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
	// DefaultPort (默认端口) is the canonical SOCKS port. The controller's
	// mapToFlowSpec fills this in when the user omits dst_port; the planner
	// does not override it.
	DefaultPort = 1080

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	// Duplicated here to avoid an import cycle.
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// SOCKS5 VER (SOCKS5版本) is fixed 0x05 per RFC 1928.
	SOCKS5Ver = 0x05

	// SOCKS5AuthVer (认证子协商版本) is fixed 0x01 per RFC 1929.
	SOCKS5AuthVer = 0x01

	// SOCKS5RSV (保留字节) is fixed 0x00.
	SOCKS5RSV = 0x00

	// SOCKS5 CMD values (命令值, RFC 1928 §4).
	SOCKS5CmdConnect      = 0x01 // CONNECT (连接)
	SOCKS5CmdBind         = 0x02 // BIND (绑定)
	SOCKS5CmdUDPAssociate = 0x03 // UDP ASSOCIATE (UDP关联)

	// SOCKS5 ATYP values (地址类型, RFC 1928 §4).
	SOCKS5ATYPIPv4   = 0x01 // IPv4 address (IPv4地址)
	SOCKS5ATYPDomain = 0x03 // Domain name (域名)
	SOCKS5ATYPIPv6   = 0x04 // IPv6 address (IPv6地址)

	// SOCKS5 METHOD values (认证方法, RFC 1928 §3).
	SOCKS5MethodNoAuth   = 0x00 // No authentication (无认证)
	SOCKS5MethodPassword = 0x02 // Username/password (用户名密码)
	SOCKS5MethodGSSAPI   = 0x01 // GSSAPI (不支持)
	SOCKS5MethodNoAccept = 0xFF // No acceptable methods (无可用方法)

	// SOCKS5 REP values (响应码, RFC 1928 §6).
	SOCKS5RepSuccess          = 0x00 // Succeeded (成功)
	SOCKS5RepGeneralFailure   = 0x01 // General SOCKS server failure (通用故障)
	SOCKS5RepNotAllowed       = 0x02 // Connection not allowed (不允许)
	SOCKS5RepNetUnreachable   = 0x03 // Network unreachable (网络不可达)
	SOCKS5RepHostUnreachable  = 0x04 // Host unreachable (主机不可达)
	SOCKS5RepConnRefused      = 0x05 // Connection refused (连接拒绝)
	SOCKS5RepTTLExpired       = 0x06 // TTL expired (TTL超时)
	SOCKS5RepCmdNotSupported  = 0x07 // Command not supported (命令不支持)
	SOCKS5RepAtypNotSupported = 0x08 // Address type not supported (地址类型不支持)

	// SOCKS4 VN (SOCKS4版本) is fixed 0x04.
	SOCKS4VN = 0x04

	// SOCKS4 CD values (命令值).
	SOCKS4CmdConnect = 0x01 // CONNECT (连接)
	SOCKS4CmdBind    = 0x02 // BIND (绑定)

	// SOCKS4 reply codes (回复码): 0x5A=90 granted, 0x5B=91 rejected.
	SOCKS4ReplyGranted  = 0x5A
	SOCKS4ReplyRejected = 0x5B

	// Socks4aMarkerIP (SOCKS4a标记IP) is DSTIP 0.0.0.1 signalling that a
	// domain name follows the USERID terminator.
	Socks4aMarkerIP = "0.0.0.1"

	// UDP RSV (UDP保留字段) fixed 0x0000 per RFC 1928 §7.
	UDPRSV = 0x0000

	// UDPFRAG (UDP分片) default 0x00 (single/only fragment).
	UDPFRAG = 0x00

	// MaxDomainLen (域名最大长度) is the 1-byte length field limit of
	// SOCKS5 ATYP=3 (RFC 1928 §4). Longer names are truncated.
	MaxDomainLen = 255
)

// Planner implements the SOCKS proxy protocol planner.
type Planner struct{}

// NewPlanner creates a new SOCKS planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "socks5" }

// Validate validates a SOCKS flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("socks5: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("socks5: invalid DstIP %q", spec.DstIP)
		}
	}

	s := spec.Socks
	if s == nil {
		return fmt.Errorf("socks5: SocksConfig is required")
	}

	// Version (版本) validation. Empty defaults to socks5 (design §5 S1:
	// user > auto > none) — must be accepted here or Plan's defaulting is
	// unreachable.
	version := normalizeVersion(s.Version)
	if version == "" {
		version = "socks5"
	}
	if version != "socks5" && version != "socks4" {
		return fmt.Errorf("socks5: invalid version %q (must be socks5 or socks4)", s.Version)
	}

	// AuthMethod (认证方法) validation — SOCKS5 only. Empty defaults to
	// no_auth (design §5 S2); the other validations below must stay
	// reachable for empty configs.
	if version == "socks5" {
		auth := normalizeAuthMethod(s.AuthMethod)
		if auth == "" {
			auth = "no_auth"
		}
		if auth != "no_auth" && auth != "password" {
			return fmt.Errorf("socks5: invalid AuthMethod %q (supported: no_auth, password)", s.AuthMethod)
		}
		if auth == "password" {
			if len(s.Username) > MaxDomainLen {
				return fmt.Errorf("socks5: Username exceeds %d bytes", MaxDomainLen)
			}
			if len(s.Password) > MaxDomainLen {
				return fmt.Errorf("socks5: Password exceeds %d bytes", MaxDomainLen)
			}
		}
	}

	// Cmd (命令) validation. SOCKS4 has no UDP ASSOCIATE (design §8.4):
	// Plan downgrades it to connect, so Validate stays permissive.
	cmd := normalizeCmd(s.Cmd)
	switch cmd {
	case "", "connect", "bind", "udp_associate":
	default:
		return fmt.Errorf("socks5: invalid Cmd %q (supported: connect, bind, udp_associate)", s.Cmd)
	}

	// DstAddr (目标地址) validation: an IP-lookalike that fails to parse is
	// an error; anything else is treated as a domain name.
	if s.DstAddr != "" {
		if err := validateAddr(s.DstAddr, "DstAddr"); err != nil {
			return fmt.Errorf("socks5: %w", err)
		}
		// SOCKS4 DSTIP must be 4 bytes (design §8, testcase §1.6.5).
		if version == "socks4" && net.ParseIP(s.DstAddr) != nil && strings.Contains(s.DstAddr, ":") {
			return fmt.Errorf("socks5: SOCKS4 DstAddr must be IPv4 or domain, got IPv6 %q", s.DstAddr)
		}
	}

	// SOCKS4 BNDIP must be 4 bytes (reply layout is fixed 8 bytes).
	if version == "socks4" && s.BndAddr != "" {
		ip := net.ParseIP(s.BndAddr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("socks5: SOCKS4 BndAddr must be an IPv4 address, got %q", s.BndAddr)
		}
	}

	// MSS (最大分段大小) validation.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("socks5: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
		}
	}

	return nil
}

// validateAddr rejects address strings that look like IPs but fail to
// parse: IPv6 candidates contain ':', IPv4 candidates are digits+dots
// only. Anything else is a valid domain name.
func validateAddr(addr, field string) error {
	if strings.Contains(addr, ":") {
		if net.ParseIP(addr) == nil {
			return fmt.Errorf("invalid %s %q (malformed IPv6)", field, addr)
		}
		return nil
	}
	digitsDotsOnly := true
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if (c < '0' || c > '9') && c != '.' {
			digitsDotsOnly = false
			break
		}
	}
	if digitsDotsOnly && net.ParseIP(addr) == nil {
		return fmt.Errorf("invalid %s %q (malformed IPv4)", field, addr)
	}
	return nil
}

// Plan generates packet configs for a SOCKS flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		s := spec.Socks
		if s == nil {
			s = &core.SocksConfig{}
		}

		version := normalizeVersion(s.Version)
		if version == "" {
			version = "socks5"
		}
		auth := normalizeAuthMethod(s.AuthMethod)
		if version == "socks5" && auth == "" {
			auth = "no_auth"
		}
		cmd := normalizeCmd(s.Cmd)
		if cmd == "" {
			cmd = "connect"
		}
		// SOCKS4 has no UDP ASSOCIATE (design §8.4): downgrade to connect.
		if version == "socks4" && cmd == "udp_associate" {
			cmd = "connect"
		}
		rep := s.Rep

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
			if flags == 0x02 || flags == 0x12 {
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

		// emitUDP (发送UDP包) sends one UDP relay datagram. The relay
		// sub-flow shares the parent's GroupID but uses its own FlowID so
		// it resequences as a distinct sub-flow (RTSP RTP pattern).
		emitUDP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
			cfg := core.PacketConfig{
				FlowID:      flowID + ":udp",
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3:       core.L3Base(srcIP, dstIP, 17, effectiveTTL, nextIPID(), spec),
				L4:       core.L4Config{Protocol: "udp", SrcPort: srcPort, DstPort: dstPort},
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

		// --- TCP handshake (TCP三次握手) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- SOCKS5 signaling (SOCKS5信令) ---
		if version == "socks5" {
			// 1. Greeting (握手请求, RFC 1928 §3).
			greeting := buildGreeting(auth)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, greeting)

			// 2. Method Response (方法响应, server -> client).
			methodResp := buildMethodResponse(auth)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, methodResp)

			// 3. Username/password sub-negotiation (RFC 1929, optional).
			if auth == "password" {
				authReq := buildAuthRequest(s.Username, s.Password)
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, authReq)

				// Auth response (认证响应, server -> client; STATUS 恒 0x00 —
				// trafficgen 只造成功路径, design §8.9).
				authResp := buildAuthResponse()
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, authResp)
			}

			// 4. Request (SOCKS5请求, RFC 1928 §4).
			req := buildSocks5Request(cmd, s.DstAddr, s.DstPort)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, req)

			// 5. Reply (SOCKS5响应, RFC 1928 §6, server -> client).
			reply := buildSocks5Reply(rep, s.BndAddr, s.BndPort)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, reply)
		} else {
			// --- SOCKS4 signaling (SOCKS4信令, two phases only) ---
			req := buildSocks4Request(cmd, s.DstAddr, s.DstPort, s.UserID)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, req)

			reply := buildSocks4Reply(rep, s.BndAddr, s.BndPort)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, reply)
		}

		// --- Data plane (数据面) ---
		if rep == 0 && len(s.Data) > 0 {
			for _, msg := range s.Data {
				select {
				case <-ctx.Done():
					return
				default:
				}
				dir := normalizeDirection(msg.Direction)
				if dir == "" {
					dir = "up"
				}
				var payload []byte
				if msg.FileSource != nil {
					pc := core.PayloadCacheFrom(ctx)
					if pc == nil {
						continue
					}
					payload, _ = pc.GetOrLoad(ctx, *msg.FileSource)
				} else {
					payload = []byte(msg.Payload)
				}
				var srcMAC, dstMAC, srcIP, dstIP string
				var srcPort, dstPort uint16
				if dir == "down" {
					srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
					srcIP, dstIP = spec.DstIP, spec.SrcIP
					srcPort, dstPort = spec.DstPort, spec.SrcPort
				} else {
					srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
					srcIP, dstIP = spec.SrcIP, spec.DstIP
					srcPort, dstPort = spec.SrcPort, spec.DstPort
				}
				if dir == "down" {
					serverSeq = emitData("down", srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, payload)
				} else {
					clientSeq = emitData("up", srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, payload)
				}
			}
		}

		// --- UDP relay sub-flow (UDP中继子面, RFC 1928 §7) ---
		if rep == 0 && version == "socks5" && cmd == "udp_associate" && s.UDP != nil {
			emitUDPRelay(ctx, s.UDP, spec, emitUDP)
		}

		// --- TCP teardown (TCP三次挥手, reference pcap: FIN → FIN-ACK →
		// ACK, frames 12-14) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// groupIDMeta returns the group_id metadata when the spec has a GroupID
// strategy (keeps sub-flows on the same PacketWorker — wire order = emit
// order). Mirrors the RTSP/Shadowsocks convention.
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	return nil
}

// emitUDPRelay emits the UDP relay datagrams for udp_associate (RFC 1928
// §7). Each datagram carries the relay header (RSV 0x0000 + FRAG 0x00 +
// ATYP + DST.ADDR + DST.PORT of the relay target) followed by the payload.
// Direction "down" (default) = proxy→client: src=spec.DstIP:SrcPort,
// dst=spec.SrcIP:DstPort (RTSP RTP sub-flow pattern).
func emitUDPRelay(
	ctx context.Context,
	udp *core.Socks5UDP,
	spec core.FlowSpec,
	emitUDP func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte),
) {
	frames := udp.Frames
	if frames <= 0 {
		frames = 1
	}
	frameSize := udp.FrameSize
	if frameSize == 0 {
		frameSize = 100
	}
	dir := normalizeDirection(udp.Direction)
	if dir == "" {
		dir = "down"
	}

	// Relay target: header ATYP/ADDR/PORT (design §2.3; empty → 0.0.0.0:0).
	atyp, addr := socks5AddrFields(udp.DstAddr)
	targetPort := udp.DstPort

	var srcMAC, dstMAC, srcIP, dstIP string
	var srcPortWire, dstPortWire uint16
	if dir == "down" {
		srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
		srcIP, dstIP = spec.DstIP, spec.SrcIP
		srcPortWire, dstPortWire = udp.SrcPort, udp.DstPort
	} else {
		srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
		srcIP, dstIP = spec.SrcIP, spec.DstIP
		srcPortWire, dstPortWire = udp.DstPort, udp.SrcPort
	}

	for i := 0; i < frames; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		header := make([]byte, 0, 10)
		header = binary.BigEndian.AppendUint16(header, UDPRSV)
		header = append(header, UDPFRAG)
		header = append(header, atyp)
		header = append(header, addr...)
		header = append(header, byte(targetPort>>8), byte(targetPort))

		payload := make([]byte, frameSize)
		udpPayload := append(header, payload...)
		emitUDP(dir, srcMAC, dstMAC, srcIP, dstIP, srcPortWire, dstPortWire, udpPayload)
	}
}

// buildGreeting builds the SOCKS5 greeting (RFC 1928 §3): VER=5, NMETHODS,
// METHODS. no_auth → `05 01 00`; password → `05 01 02` (reference pcap).
func buildGreeting(auth string) []byte {
	var methods []byte
	if auth == "password" {
		methods = []byte{SOCKS5MethodPassword}
	} else {
		methods = []byte{SOCKS5MethodNoAuth}
	}
	msg := []byte{SOCKS5Ver, byte(len(methods))}
	msg = append(msg, methods...)
	return msg
}

// buildMethodResponse builds the SOCKS5 method response (RFC 1928 §3):
// the server echoes the selected method (`05 00` / `05 02`).
func buildMethodResponse(auth string) []byte {
	method := byte(SOCKS5MethodNoAuth)
	if auth == "password" {
		method = SOCKS5MethodPassword
	}
	return []byte{SOCKS5Ver, method}
}

// buildAuthRequest builds the RFC 1929 auth request:
// `01 <ULEN> <UNAME> <PLEN> <PASSWD>`. Empty username/password default to
// "user"/"pass" (design §5 S8).
func buildAuthRequest(username, password string) []byte {
	if username == "" {
		username = "user"
	}
	if password == "" {
		password = "pass"
	}
	msg := []byte{SOCKS5AuthVer, byte(len(username))}
	msg = append(msg, []byte(username)...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, []byte(password)...)
	return msg
}

// buildAuthResponse builds the RFC 1929 auth response (STATUS=0x00).
func buildAuthResponse() []byte {
	return []byte{SOCKS5AuthVer, 0x00}
}

// buildSocks5Request builds the SOCKS5 request (RFC 1928 §4):
// `05 <CMD> 00 <ATYP> <DST.ADDR> <DST.PORT>`. Empty DstAddr defaults to
// "www.example.com" (design §5 S4, reference pcap target); DstPort 0 is
// the "empty" marker and defaults to 80 (S5, reference pcap port).
func buildSocks5Request(cmd, dstAddr string, dstPort uint16) []byte {
	if dstAddr == "" {
		dstAddr = "www.example.com"
	}
	if dstPort == 0 {
		dstPort = 80
	}
	atyp, addr := socks5AddrFields(dstAddr)
	msg := []byte{SOCKS5Ver, socks5CmdValue(cmd), SOCKS5RSV, atyp}
	msg = append(msg, addr...)
	msg = append(msg, byte(dstPort>>8), byte(dstPort))
	return msg
}

// buildSocks5Reply builds the SOCKS5 reply (RFC 1928 §6):
// `05 <REP> 00 <ATYP> <BND.ADDR> <BND.PORT>`. Empty BndAddr/BndPort →
// 0.0.0.0:0 (reference pcap reply bytes).
func buildSocks5Reply(rep int, bndAddr string, bndPort uint16) []byte {
	atyp := byte(SOCKS5ATYPIPv4)
	var addr []byte
	if bndAddr != "" {
		atyp, addr = socks5AddrFields(bndAddr)
	} else {
		addr = []byte{0x00, 0x00, 0x00, 0x00}
	}
	msg := []byte{SOCKS5Ver, byte(rep), SOCKS5RSV, atyp}
	msg = append(msg, addr...)
	msg = append(msg, byte(bndPort>>8), byte(bndPort))
	return msg
}

// buildSocks4Request builds the SOCKS4 request:
// `04 <CD> <DSTPORT> <DSTIP> <USERID> 00` (SOCKS4) or, when DstAddr is a
// domain, the SOCKS4a form: DSTIP=0.0.0.1 + USERID 00 + domain 00 (no
// length prefix — the domain is 0x00-terminated). Empty DstAddr defaults
// to the reference pcap target IP 93.184.216.119:80.
func buildSocks4Request(cmd, dstAddr string, dstPort uint16, userID string) []byte {
	dst := dstAddr
	if dst == "" {
		dst = "93.184.216.119"
	}
	if dstPort == 0 {
		dstPort = 80
	}
	cd := byte(SOCKS4CmdConnect)
	if normalizeCmd(cmd) == "bind" {
		cd = SOCKS4CmdBind
	}
	msg := []byte{SOCKS4VN, cd, byte(dstPort >> 8), byte(dstPort)}

	if ip := net.ParseIP(dst); ip != nil && ip.To4() != nil {
		msg = append(msg, ip.To4()...)
	} else {
		// SOCKS4a: marker IP + USERID terminator + domain (0x00-terminated).
		msg = append(msg, 0x00, 0x00, 0x00, 0x01)
		msg = append(msg, []byte(userID)...)
		msg = append(msg, 0x00)
		msg = append(msg, []byte(dst)...)
		msg = append(msg, 0x00)
		return msg
	}
	msg = append(msg, []byte(userID)...)
	msg = append(msg, 0x00)
	return msg
}

// buildSocks4Reply builds the SOCKS4 reply (fixed 8 bytes):
// `00 5A|5B <BNDPORT> <BNDIP>`. Rep=0 → 0x5A granted; non-zero → 0x5B
// rejected. Empty BndAddr/BndPort → 0.0.0.0:0.
func buildSocks4Reply(rep int, bndAddr string, bndPort uint16) []byte {
	code := byte(SOCKS4ReplyGranted)
	if rep != 0 {
		code = SOCKS4ReplyRejected
	}
	var bndIP []byte
	if ip := net.ParseIP(bndAddr); ip != nil && ip.To4() != nil {
		bndIP = ip.To4()
	} else {
		bndIP = []byte{0x00, 0x00, 0x00, 0x00}
	}
	msg := []byte{0x00, code, byte(bndPort >> 8), byte(bndPort)}
	msg = append(msg, bndIP...)
	return msg
}

// socks5CmdValue returns the SOCKS5 CMD byte value.
func socks5CmdValue(cmd string) byte {
	switch normalizeCmd(cmd) {
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
// for the given address string (RFC 1928 §4): IPv4 → 1 (4 bytes), IPv6 →
// 4 (16 bytes), otherwise a domain → 3 (1-byte length + name, truncated to
// 255 bytes). Empty → IPv4 0.0.0.0.
func socks5AddrFields(addrStr string) (atyp byte, addr []byte) {
	if addrStr == "" {
		return SOCKS5ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}
	}
	if ip := net.ParseIP(addrStr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return SOCKS5ATYPIPv4, ip4
		}
		return SOCKS5ATYPIPv6, ip.To16()
	}
	domainLen := len(addrStr)
	if domainLen > MaxDomainLen {
		domainLen = MaxDomainLen
	}
	addr = make([]byte, 1+domainLen)
	addr[0] = byte(domainLen)
	copy(addr[1:], addrStr[:domainLen])
	return SOCKS5ATYPDomain, addr
}

// normalizeVersion normalizes the version string.
func normalizeVersion(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// normalizeAuthMethod normalizes the auth method string.
func normalizeAuthMethod(a string) string { return strings.ToLower(strings.TrimSpace(a)) }

// normalizeCmd normalizes the command string.
func normalizeCmd(c string) string { return strings.ToLower(strings.TrimSpace(c)) }

// normalizeDirection normalizes a direction string to lowercase.
func normalizeDirection(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

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
