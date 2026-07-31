// Package dhcpv6 implements the DHCPv6 protocol planner (RFC 8415).
//
// DHCPv6 (Dynamic Host Configuration Protocol for IPv6, IPv6 动态主机配置协议)
// runs over UDP on ports 546 (client) / 547 (server and relay). The planner
// emits each message in Messages as a separate UDP datagram, sharing the same
// 4-tuple (one flow). IPv6 only — EtherType=0x86DD, IPv6 pseudo-header checksum.
//
// Wire format (RFC 8415 §7):
//  1. Client/Server message header (4 bytes):
//     - msg-type (1 byte): 1-13 (see design §2.4)
//     - transaction-id (3 bytes): 24-bit random
//  2. Options TLV (variable):
//     - option-code (2 bytes BE)
//     - option-len (2 bytes BE)
//     - option-data (variable)
//  3. Relay message header (34 bytes, msg-type 12/13):
//     - msg-type (1 byte)
//     - hop-count (1 byte)
//     - link-address (16 bytes IPv6)
//     - peer-address (16 bytes IPv6)
//     - options (TLV, including option 9 Relay Message carrying inner msg)
//
// The planner emits the exact message sequence the user provides — it does NOT
// enforce the full RFC 8415 state machine. This matches the trafficgen contract:
// synthesize test packets, not a real DHCPv6 client/server.
package dhcpv6

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
	// DefaultTTL mirrors other IPv6 planners (icmpv6/sctp).
	DefaultTTL = 64

	// DHCPv6 ports (DHCPv6 端口)
	ClientPort = 546 // 客户端端口
	ServerPort = 547 // 服务器/中继端口

	// MaxOptionsLen is the maximum options length (options 最大长度):
	// 1500 (MTU) - 40 (IPv6) - 8 (UDP) = 1452 字节
	MaxOptionsLen = 1452

	// MaxDUIDLen is the maximum DUID length per RFC 8415 §11 (1-128 bytes).
	MaxDUIDLen = 128

	// MaxHopCount is the relay HOP_COUNT_LIMIT per RFC 8415 §7.2.
	MaxHopCount = 32

	// HeaderLen is the fixed client/server header length (4 字节固定头).
	HeaderLen = 4

	// RelayHeaderLen is the fixed relay header length (34 字节中继头).
	RelayHeaderLen = 34

	// HardwareTypeEthernet = 1 (Ethernet, 以太网)
	HardwareTypeEthernet = 1

	// DUID types (DUID 类型, RFC 8415 §11)
	DUIDTypeLLT = 1 // DUID-LLT (Link-Layer + Time)
	DUIDTypeEN  = 2 // DUID-EN (Enterprise Number)
	DUIDTypeLL  = 3 // DUID-LL (Link-Layer Only)

	// DUID-LLT fixed part: type(2) + hw-type(2) + time(4) = 8 bytes
	duidLLTFixedLen = 8
	// DUID-EN fixed part: type(2) + enterprise-number(4) = 6 bytes
	duidENFixedLen = 6
	// DUID-LL fixed part: type(2) + hw-type(2) = 4 bytes
	duidLLFixedLen = 4
)

// DHCPv6 message types (RFC 8415 §7.3, 消息类型)
const (
	MsgTypeSolicit            = 1  // SOLICIT (客户端发起服务发现)
	MsgTypeAdvertise          = 2  // ADVERTISE (服务器响应 SOLICIT)
	MsgTypeRequest           = 3  // REQUEST (客户端正式请求地址/前缀)
	MsgTypeConfirm           = 4  // CONFIRM (客户端移动后确认地址)
	MsgTypeRenew             = 5  // RENEW (T1 超时后续约)
	MsgTypeRebind            = 6  // REBIND (T2 超时后向任意服务器续约)
	MsgTypeReply             = 7  // REPLY (服务器对请求的回应)
	MsgTypeRelease           = 8  // RELEASE (客户端主动释放地址)
	MsgTypeDecline           = 9  // DECLINE (DAD 失败后撤销地址)
	MsgTypeReconfigure       = 10 // RECONFIGURE (服务器主动触发客户端重新获取)
	MsgTypeInformationRequest = 11 // INFORMATION-REQUEST (无状态查询)
	MsgTypeRelayForw         = 12 // RELAY-FORW (中继转发, client→server)
	MsgTypeRelayRepl         = 13 // RELAY-REPL (中继回应, server→client)
)

// DHCPv6 option codes (RFC 8415 §21, 选项码)
const (
	OptClientID         uint16 = 1  // OPTION_CLIENTID (客户端标识)
	OptServerID         uint16 = 2  // OPTION_SERVERID (服务器标识)
	OptIANA             uint16 = 3  // OPTION_IA_NA (非临时地址 IA)
	OptIATA             uint16 = 4  // OPTION_IA_TA (临时地址 IA)
	OptIAAddr           uint16 = 5  // OPTION_IAADDR (IA Address 子选项)
	OptORO              uint16 = 6  // OPTION_ORO (Option Request)
	OptPreference       uint16 = 7  // OPTION_PREFERENCE (服务器优先级)
	OptElapsedTime      uint16 = 8  // OPTION_ELAPSED_TIME (经过时间)
	OptRelayMsg         uint16 = 9  // OPTION_RELAY_MSG (中继消息)
	OptAuth             uint16 = 11 // OPTION_AUTH (认证)
	OptStatusCode       uint16 = 13 // OPTION_STATUS_CODE (状态码)
	OptRapidCommit      uint16 = 14 // OPTION_RAPID_COMMIT (Rapid Commit)
	OptUserClass        uint16 = 16 // OPTION_USER_CLASS (用户类别)
	OptVendorClass      uint16 = 17 // OPTION_VENDOR_CLASS (厂商类别)
	OptInterfaceID      uint16 = 18 // OPTION_INTERFACE_ID (接口标识)
	OptReconfMsg        uint16 = 19 // OPTION_RECONF_MSG (重配消息类型)
	OptIAPD             uint16 = 25 // OPTION_IA_PD (前缀委派 IA)
	OptIAPrefix         uint16 = 26 // OPTION_IAPREFIX (IA Prefix 子选项)
	OptRDNSS            uint16 = 23 // OPTION_RDNSS (递归 DNS 服务器)
	OptDNSSL            uint16 = 24 // OPTION_DNSSL (DNS 搜索列表)
	OptSNTP             uint16 = 31 // OPTION_SNTP (SNTP 服务器)
	OptInfoRefreshTime  uint16 = 32 // OPTION_INFORMATION_REFRESH_TIME (信息刷新时间)
	OptFQDN             uint16 = 39 // OPTION_FQDN (客户端 FQDN)
	OptClientLinkLayer   uint16 = 79 // OPTION_CLIENT_LINKLAYER_ADDR (客户端链路层地址)
)

// Link-layer types for option 79 (RFC 6939)
const (
	LinkLayerTypeEthernet = 1
)

// Planner implements the DHCPv6 protocol planner (DHCPv6 协议规划器).
type Planner struct{}

// NewPlanner creates a new DHCPv6 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "dhcpv6" }

// Validate validates a DHCPv6 flow spec (验证 DHCPv6 流规格).
// IPv6 addresses are required (DHCPv6 is IPv6-only).
// Per validate_conventions.md: read-only, never modifies spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// 1. DHCPv6 requires IPv6 addresses (DHCPv6 强制 IPv6)
	if spec.SrcIP != "" {
		ip := net.ParseIP(spec.SrcIP)
		if ip == nil {
			return fmt.Errorf("dhcpv6: invalid source IP: %s", spec.SrcIP)
		}
		if ip.To4() != nil {
			return fmt.Errorf("dhcpv6: source IP must be IPv6 (got IPv4): %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		ip := net.ParseIP(spec.DstIP)
		if ip == nil {
			return fmt.Errorf("dhcpv6: invalid destination IP: %s", spec.DstIP)
		}
		if ip.To4() != nil {
			return fmt.Errorf("dhcpv6: destination IP must be IPv6 (got IPv4): %s", spec.DstIP)
		}
	}

	// 2. DHCPv6 config is required
	if spec.DHCPv6 == nil {
		return fmt.Errorf("dhcpv6: config is required")
	}
	cfg := spec.DHCPv6

	// 2b. Scenario mode: validate scenario-specific prerequisites. When
	// Scenario is set, the planner auto-generates the Messages list from
	// the RFC 8415 state machine; the manual Messages field is ignored.
	// Empty Scenario = manual mode (backward-compatible).
	if cfg.Scenario != "" {
		if err := validateScenario(cfg); err != nil {
			return err
		}
		// Scenario mode synthesizes Messages at Plan time; skip the
		// manual-Messages validation below, but still validate DUIDs and
		// RelayConfig.
	} else {
		// 3. Messages non-empty (manual mode only)
		if len(cfg.Messages) == 0 {
			return fmt.Errorf("dhcpv6: at least one message is required")
		}

		// 4. Validate each message
		for i, msg := range cfg.Messages {
			// 4a. msg-type range check
			if msg.MsgType < 1 || msg.MsgType > 13 {
				return fmt.Errorf("dhcpv6: message[%d]: invalid msg-type %d (must be 1-13)", i, msg.MsgType)
			}

			// 4b. Relay message validation (msg-type 12/13)
			isRelay := msg.MsgType == MsgTypeRelayForw || msg.MsgType == MsgTypeRelayRepl
			if isRelay {
				if msg.RelayFields == nil {
					return fmt.Errorf("dhcpv6: message[%d]: relay message requires relay_fields", i)
				}
				if msg.RelayFields.HopCount > MaxHopCount {
					return fmt.Errorf("dhcpv6: message[%d]: hop-count %d exceeds limit %d", i, msg.RelayFields.HopCount, MaxHopCount)
				}
				if msg.RelayFields.LinkAddress == "" {
					return fmt.Errorf("dhcpv6: message[%d]: relay link-address is required", i)
				}
				if net.ParseIP(msg.RelayFields.LinkAddress) == nil || net.ParseIP(msg.RelayFields.LinkAddress).To4() != nil {
					return fmt.Errorf("dhcpv6: message[%d]: invalid relay link-address (must be IPv6): %s", i, msg.RelayFields.LinkAddress)
				}
				if msg.RelayFields.PeerAddress == "" {
					return fmt.Errorf("dhcpv6: message[%d]: relay peer-address is required", i)
				}
				if net.ParseIP(msg.RelayFields.PeerAddress) == nil || net.ParseIP(msg.RelayFields.PeerAddress).To4() != nil {
					return fmt.Errorf("dhcpv6: message[%d]: invalid relay peer-address (must be IPv6): %s", i, msg.RelayFields.PeerAddress)
				}
			}

			// 4c. Direction check
			if msg.Direction != "" && msg.Direction != "up" && msg.Direction != "down" {
				return fmt.Errorf("dhcpv6: message[%d]: invalid direction %q (must be up or down)", i, msg.Direction)
			}

			// 4d. Validate options total length doesn't exceed MTU-IPv6-UDP
			optionsLen := 0
			for _, opt := range msg.Options {
				optionsLen += 4 + len(opt.Data) // 2(code) + 2(len) + len(data)
			}
			// Relay messages have option 9 (Relay Message) which contains inner msg bytes;
			// the inner msg bytes are counted in the outer message's options length.
			// For non-relay messages, the options are the user-supplied ones.
			if optionsLen > MaxOptionsLen {
				return fmt.Errorf("dhcpv6: message[%d]: options length %d exceeds MTU limit %d", i, optionsLen, MaxOptionsLen)
			}
		}
	}

	// 5. Validate DUIDs if provided
	if cfg.ClientDUID != nil {
		if err := validateDUID(cfg.ClientDUID); err != nil {
			return fmt.Errorf("dhcpv6: client DUID: %w", err)
		}
	}
	if cfg.ServerDUID != nil {
		if err := validateDUID(cfg.ServerDUID); err != nil {
			return fmt.Errorf("dhcpv6: server DUID: %w", err)
		}
	}

	// 5b. When ClientDUID is nil (auto-generation via autoClientDUID), the
	// planner builds a DUID-LLT from spec.SrcMAC. An empty SrcMAC would
	// produce a DUID with an empty LinkLayerAddr, which serializeDUID
	// rejects (parseMAC returns "empty MAC"), causing the Plan goroutine
	// to silently emit zero packets. Catch this early with a clear error.
	if cfg.ClientDUID == nil && spec.SrcMAC == "" {
		return fmt.Errorf("dhcpv6: src_mac is required when client_duid is not set (auto DUID-LLT needs a MAC)")
	}

	// 6. Validate RelayConfig if provided
	if cfg.RelayConfig != nil {
		if cfg.RelayConfig.RelayIP == "" {
			return fmt.Errorf("dhcpv6: relay_config.relay_ip is required")
		}
		if net.ParseIP(cfg.RelayConfig.RelayIP) == nil || net.ParseIP(cfg.RelayConfig.RelayIP).To4() != nil {
			return fmt.Errorf("dhcpv6: relay_config.relay_ip must be IPv6: %s", cfg.RelayConfig.RelayIP)
		}
	}

	return nil
}

// validateDUID validates a DUID structure (验证 DUID).
func validateDUID(d *core.DUID) error {
	if d == nil {
		return nil
	}
	// Check type
	switch d.Type {
	case DUIDTypeLLT, DUIDTypeEN, DUIDTypeLL:
		// valid types
	default:
		return fmt.Errorf("invalid DUID type %d (must be 1=LLT, 2=EN, or 3=LL)", d.Type)
	}

	// Serialize and check length
	serialized, err := serializeDUID(d)
	if err != nil {
		return err
	}
	if len(serialized) < 1 {
		return fmt.Errorf("DUID too short (min 1 byte, got %d)", len(serialized))
	}
	if len(serialized) > MaxDUIDLen {
		return fmt.Errorf("DUID too long (max %d bytes, got %d)", MaxDUIDLen, len(serialized))
	}
	return nil
}

// Plan generates packet configs for a DHCPv6 flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		cfg := spec.DHCPv6

		// Resolve DUIDs (解析 DUID)
		clientDUID := cfg.ClientDUID
		if clientDUID == nil {
			clientDUID = autoClientDUID(spec.SrcMAC)
		}
		serverDUID := cfg.ServerDUID
		if serverDUID == nil {
			serverDUID = autoServerDUID()
		}

		// Resolve the message sequence. Scenario mode auto-generates
		// the full RFC 8415 dialog (SARR/Renew/Rebind/.../Relay) with a
		// shared transaction-id and correct option chains; manual mode
		// uses the user-provided Messages list as-is.
		messages := cfg.Messages
		if cfg.Scenario != "" {
			messages = buildScenarioMessages(cfg, clientDUID, serverDUID)
		}

		// Resolve ports and IPs based on direction (per-message basis).
		// Like DHCPv4, the flow's 4-tuple is fixed; per-message direction
		// determines the L2/L3/L4 src/dst swap.
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		now := time.Now()
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Track previously-seen XIDs to detect "new transaction" transitions.
		// Per RFC 8415: each new client-initiated transaction uses a new XID;
		// server replies copy the request's XID; RECONFIGURE uses a new XID.
		// The planner: if TransactionID is zero, generate a random one; if
		// it matches a previous one (user-set), reuse it.
		var lastXID [3]byte

		for i, msg := range messages {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Determine direction (确定方向)
			direction := msg.Direction
			if direction == "" {
				direction = inferDirection(msg.MsgType)
			}

			// Determine XID (确定事务 ID)
			xid := msg.TransactionID
			isRelay := msg.MsgType == MsgTypeRelayForw || msg.MsgType == MsgTypeRelayRepl
			if !isRelay {
				if xid == [3]byte{} {
					// No XID set: if this is a server reply (down), copy the
					// last client XID; if this is a client message (up) or
					// RECONFIGURE, generate a new random XID.
					if direction == "down" && msg.MsgType != MsgTypeReconfigure {
						xid = lastXID
					} else {
						xid = randomXID()
					}
				}
				lastXID = xid
			}

			// Build payload (构建载荷)
			payload, err := buildMessage(msg, cfg, clientDUID, serverDUID, xid)
			if err != nil {
				// Serialization failure: stop (mirrors DHCPv4 planner behavior)
				return
			}

			// Resolve per-message L2/L3/L4
			srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort := resolveAddrs(spec, cfg, direction, msg)

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: uint64(i),
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3: core.L3Base(srcIP, dstIP, core.ProtocolUDP, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
				},
				Payload: payload,
			}
		}
	}()

	return configChan, nil
}

// inferDirection infers the direction from DHCPv6 message type.
// Client messages (1,3,4,5,6,8,9,11) and RELAY-FORW (12) are "up".
// Server messages (2,7,10) and RELAY-REPL (13) are "down".
func inferDirection(msgType uint8) string {
	switch msgType {
	case MsgTypeSolicit, MsgTypeRequest, MsgTypeConfirm, MsgTypeRenew,
		MsgTypeRebind, MsgTypeRelease, MsgTypeDecline,
		MsgTypeInformationRequest, MsgTypeRelayForw:
		return "up"
	case MsgTypeAdvertise, MsgTypeReply, MsgTypeReconfigure, MsgTypeRelayRepl:
		return "down"
	default:
		return "up"
	}
}

// resolveAddrs resolves the L2/L3/L4 addresses for a given message.
// The flow's 4-tuple is the client→server path (up); for down messages,
// src/dst are swapped.
func resolveAddrs(spec core.FlowSpec, cfg *core.DHCPv6Config, direction string, msg core.DHCPv6Message) (srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16) {
	// Default ports: client=546, server/relay=547
	srcPort = spec.SrcPort
	dstPort = spec.DstPort
	if srcPort == 0 {
		srcPort = ClientPort
	}
	if dstPort == 0 {
		dstPort = ServerPort
	}

	srcMAC = spec.SrcMAC
	dstMAC = spec.DstMAC
	srcIP = spec.SrcIP
	dstIP = spec.DstIP

	// For server messages, swap MACs/IPs/ports (服务器消息交换方向)
	if direction == "down" {
		srcMAC = spec.DstMAC
		dstMAC = spec.SrcMAC
		srcIP = spec.DstIP
		dstIP = spec.SrcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// For relay messages, the relay's MAC/IP is from RelayConfig.
	// RELAY-FORW (up) uses relay as source; RELAY-REPL (down) uses relay as dest.
	// If RelayConfig is set, the user wants the relay to be the L2/L3 endpoint
	// for the relay message itself.
	if cfg.RelayConfig != nil && (msg.MsgType == MsgTypeRelayForw || msg.MsgType == MsgTypeRelayRepl) {
		if msg.MsgType == MsgTypeRelayForw {
			// RELAY-FORW: relay→server (or upstream relay)
			srcMAC = cfg.RelayConfig.RelayMAC
			srcIP = cfg.RelayConfig.RelayIP
			// dst stays as server
			srcPort = ServerPort
			dstPort = ServerPort
		} else {
			// RELAY-REPL: server→relay
			dstMAC = cfg.RelayConfig.RelayMAC
			dstIP = cfg.RelayConfig.RelayIP
			srcPort = ServerPort
			dstPort = ServerPort
		}
	}

	return
}

// buildMessage builds the wire-format DHCPv6 message payload.
func buildMessage(msg core.DHCPv6Message, cfg *core.DHCPv6Config, clientDUID, serverDUID *core.DUID, xid [3]byte) ([]byte, error) {
	isRelay := msg.MsgType == MsgTypeRelayForw || msg.MsgType == MsgTypeRelayRepl
	if isRelay {
		return buildRelayMessage(msg, cfg)
	}
	return buildClientServerMessage(msg, cfg, clientDUID, serverDUID, xid)
}

// buildClientServerMessage builds a 4-byte-header DHCPv6 message (msg-type 1-11).
func buildClientServerMessage(msg core.DHCPv6Message, cfg *core.DHCPv6Config, clientDUID, serverDUID *core.DUID, xid [3]byte) ([]byte, error) {
	buf := make([]byte, 0, HeaderLen+64)
	// Header (4 字节固定头)
	buf = append(buf, msg.MsgType)
	buf = append(buf, xid[:]...)

	// Resolve options ordering: ClientID first, ServerID second, then user options.
	// We only auto-add ClientID/ServerID if the user did not include them.
	hasClientID := false
	hasServerID := false
	for _, opt := range msg.Options {
		if opt.Code == OptClientID {
			hasClientID = true
		}
		if opt.Code == OptServerID {
			hasServerID = true
		}
	}

	// Auto-prepend ClientID for client messages (1,3,4,5,6,8,9,11) and
	// ServerID for server messages (2,7,10). INFORMATION-REQUEST also
	// carries ClientID per RFC 8415 (testcases §5.2 correction).
	isClientMsg := msg.MsgType == MsgTypeSolicit || msg.MsgType == MsgTypeRequest ||
		msg.MsgType == MsgTypeConfirm || msg.MsgType == MsgTypeRenew ||
		msg.MsgType == MsgTypeRebind || msg.MsgType == MsgTypeRelease ||
		msg.MsgType == MsgTypeDecline || msg.MsgType == MsgTypeInformationRequest
	isServerMsg := msg.MsgType == MsgTypeAdvertise || msg.MsgType == MsgTypeReply ||
		msg.MsgType == MsgTypeReconfigure

	if isClientMsg && !hasClientID && clientDUID != nil {
		duidBytes, err := serializeDUID(clientDUID)
		if err != nil {
			return nil, fmt.Errorf("serialize client DUID: %w", err)
		}
		buf = appendOption(buf, OptClientID, duidBytes)
	}
	if isServerMsg {
		if !hasServerID && serverDUID != nil {
			duidBytes, err := serializeDUID(serverDUID)
			if err != nil {
				return nil, fmt.Errorf("serialize server DUID: %w", err)
			}
			buf = appendOption(buf, OptServerID, duidBytes)
		}
		if !hasClientID && clientDUID != nil {
			duidBytes, err := serializeDUID(clientDUID)
			if err != nil {
				return nil, fmt.Errorf("serialize client DUID: %w", err)
			}
			buf = appendOption(buf, OptClientID, duidBytes)
		}
	}

	// REQUEST/RENEW/RELEASE/DECLINE must carry ServerID; auto-add if missing.
	needsServerID := msg.MsgType == MsgTypeRequest || msg.MsgType == MsgTypeRenew ||
		msg.MsgType == MsgTypeRelease || msg.MsgType == MsgTypeDecline
	if needsServerID && !hasServerID && serverDUID != nil {
		duidBytes, err := serializeDUID(serverDUID)
		if err != nil {
			return nil, fmt.Errorf("serialize server DUID: %w", err)
		}
		buf = appendOption(buf, OptServerID, duidBytes)
	}

	// Append user-provided options in declared order
	for _, opt := range msg.Options {
		buf = appendOption(buf, opt.Code, opt.Data)
	}

	return buf, nil
}

// buildRelayMessage builds a 34-byte-header DHCPv6 relay message (msg-type 12/13).
// The user must provide option 9 (Relay Message) in Options to carry the inner
// message bytes. The planner does NOT auto-encapsulate.
func buildRelayMessage(msg core.DHCPv6Message, cfg *core.DHCPv6Config) ([]byte, error) {
	if msg.RelayFields == nil {
		return nil, fmt.Errorf("relay message requires relay_fields")
	}
	buf := make([]byte, 0, RelayHeaderLen+64)
	// Header (34 字节中继头)
	buf = append(buf, msg.MsgType)
	buf = append(buf, msg.RelayFields.HopCount)
	linkAddr := net.ParseIP(msg.RelayFields.LinkAddress)
	if linkAddr == nil {
		return nil, fmt.Errorf("invalid link-address: %s", msg.RelayFields.LinkAddress)
	}
	linkAddr16 := linkAddr.To16()
	if linkAddr16 == nil {
		return nil, fmt.Errorf("link-address not IPv6: %s", msg.RelayFields.LinkAddress)
	}
	buf = append(buf, linkAddr16...)
	peerAddr := net.ParseIP(msg.RelayFields.PeerAddress)
	if peerAddr == nil {
		return nil, fmt.Errorf("invalid peer-address: %s", msg.RelayFields.PeerAddress)
	}
	peerAddr16 := peerAddr.To16()
	if peerAddr16 == nil {
		return nil, fmt.Errorf("peer-address not IPv6: %s", msg.RelayFields.PeerAddress)
	}
	buf = append(buf, peerAddr16...)

	// Append options (user provides option 9 + optionally option 18/79)
	for _, opt := range msg.Options {
		buf = appendOption(buf, opt.Code, opt.Data)
	}

	return buf, nil
}

// appendOption appends a TLV option to buf and returns the extended buffer.
func appendOption(buf []byte, code uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], code)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(data)))
	buf = append(buf, hdr...)
	buf = append(buf, data...)
	return buf
}

// serializeDUID serializes a DUID to wire bytes per RFC 8415 §11.
// Returns the DUID data (without option code/len wrapper).
func serializeDUID(d *core.DUID) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("nil DUID")
	}
	switch d.Type {
	case DUIDTypeLLT:
		// type(2) + hw-type(2) + time(4) + link-layer-addr(variable)
		mac, err := parseMAC(d.LinkLayerAddr)
		if err != nil {
			return nil, fmt.Errorf("DUID-LLT: invalid link-layer-addr: %w", err)
		}
		buf := make([]byte, 0, duidLLTFixedLen+len(mac))
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], DUIDTypeLLT)
		buf = append(buf, b[:]...)
		hwType := d.HardwareType
		if hwType == 0 {
			hwType = HardwareTypeEthernet
		}
		binary.BigEndian.PutUint16(b[:], hwType)
		buf = append(buf, b[:]...)
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], d.Time)
		buf = append(buf, b4[:]...)
		buf = append(buf, mac...)
		return buf, nil
	case DUIDTypeEN:
		// type(2) + enterprise-number(4) + vendor-specific(variable)
		buf := make([]byte, 0, duidENFixedLen+len(d.VendorSpecific))
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], DUIDTypeEN)
		buf = append(buf, b[:]...)
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], d.EnterpriseNum)
		buf = append(buf, b4[:]...)
		buf = append(buf, d.VendorSpecific...)
		return buf, nil
	case DUIDTypeLL:
		// type(2) + hw-type(2) + link-layer-addr(variable)
		mac, err := parseMAC(d.LinkLayerAddr)
		if err != nil {
			return nil, fmt.Errorf("DUID-LL: invalid link-layer-addr: %w", err)
		}
		buf := make([]byte, 0, duidLLFixedLen+len(mac))
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], DUIDTypeLL)
		buf = append(buf, b[:]...)
		hwType := d.HardwareType
		if hwType == 0 {
			hwType = HardwareTypeEthernet
		}
		binary.BigEndian.PutUint16(b[:], hwType)
		buf = append(buf, b[:]...)
		buf = append(buf, mac...)
		return buf, nil
	default:
		return nil, fmt.Errorf("unknown DUID type: %d", d.Type)
	}
}

// parseMAC parses a MAC address string into bytes (解析 MAC 字符串).
// Accepts standard notations like "00:11:22:33:44:55".
func parseMAC(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty MAC")
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	return hw, nil
}

// randomXID returns a random 24-bit transaction ID (3 字节随机事务 ID).
func randomXID() [3]byte {
	var x [3]byte
	// Use crypto/rand-style non-deterministic random; fall back to math/rand
	// for simplicity (mirrors DHCPv4 planner's rand.Uint32 usage).
	v := rand.Uint32() & 0xFFFFFF
	x[0] = byte(v >> 16)
	x[1] = byte(v >> 8)
	x[2] = byte(v)
	return x
}

// autoClientDUID generates a DUID-LLT from the client MAC (自动生成客户端 DUID-LLT).
// time = seconds since 2000-01-01 UTC.
func autoClientDUID(srcMAC string) *core.DUID {
	// Use DUID-LLT with hardware-type=1 (Ethernet) and time=0 (epoch 2000-01-01).
	// If MAC is invalid, fall back to all-zero MAC.
	return &core.DUID{
		Type:          DUIDTypeLLT,
		HardwareType:  HardwareTypeEthernet,
		Time:          uint32(time.Now().Unix() - duidEpoch2000),
		LinkLayerAddr: srcMAC,
	}
}

// autoServerDUID generates a DUID-EN with enterprise-number=0 and
// vendor-specific=[]byte("trafficgen") (自动生成服务器 DUID-EN).
func autoServerDUID() *core.DUID {
	return &core.DUID{
		Type:            DUIDTypeEN,
		EnterpriseNum:   0,
		VendorSpecific:  []byte("trafficgen"),
	}
}

// duidEpoch2000 is the Unix timestamp of 2000-01-01 00:00:00 UTC.
const duidEpoch2000 = 946684800
