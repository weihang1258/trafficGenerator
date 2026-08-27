// Package dhcp implements the DHCPv4 protocol planner (RFC 2131).
//
// DHCP (Dynamic Host Configuration Protocol，动态主机配置协议) runs over UDP
// on ports 67 (server) / 68 (client). The planner emits each message in
// Messages as a separate UDP datagram, sharing the same xid (transaction ID,
// 事务ID) and 4-tuple (one flow).
//
// Wire format:
// 1. BOOTP fixed header (236 bytes): op/htype/hlen/hops/xid/secs/flags/
// ciaddr/yiaddr/siaddr/giaddr/chaddr/sname/file
// 2. Magic cookie (4 bytes): 0x63825363
// 3. DHCP options (TLV): code(1)+len(1)+data(N), terminated by END (255)
//
// The planner emits the exact message sequence the user provides — it does NOT
// enforce the full RFC 2131 state machine. This matches the trafficgen contract:
// we synthesize test packets, not a real DHCP client/server.
package dhcp

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
	DefaultTTL = 64

	// DHCP ports (DHCP 端口)
	ServerPort = 67
	ClientPort = 68

	// Broadcast IP (广播地址)
	BroadcastIP = "255.255.255.255"

	// Broadcast MAC (广播MAC)
	BroadcastMAC = "ff:ff:ff:ff:ff:ff"

	// DefaultServerMAC is the fallback source MAC for server-role reply
	// (BOOTREPLY) packets when no server MAC is configured (服务器回退源MAC).
	// Per RFC 2131 §4.1 the server's reply carries the server interface's
	// hardware address as the Ethernet source. When the user leaves both
	// spec.SrcMAC and spec.DstMAC empty (relying on the broadcast fallback),
	// the server reply's L2 source would otherwise be all-zero
	// (00:00:00:00:00:00) — a malformed frame. This locally-administered
	// MAC (locally administered, 本地管理地址, L bit set) avoids that.
	DefaultServerMAC = "02:00:00:00:00:02"

	// Magic cookie (魔术cookie): 0x63825363
	MagicCookie = 0x63825363

	// BOOTP header length (BOOTP 固定头长度)
	BootpHeaderLen = 236

	// Magic cookie length (魔术cookie长度)
	MagicCookieLen = 4

	// MaxOptionsLen is the maximum options length (options 最大长度):
	// 1472 (UDP payload max) - 236 (BOOTP) - 4 (magic) = 1232
	MaxOptionsLen = 1232

	// DHCP Message Types (DHCP 消息类型)
	MsgTypeDiscover = 1
	MsgTypeOffer    = 2
	MsgTypeRequest  = 3
	MsgTypeDecline  = 4
	MsgTypeAck      = 5
	MsgTypeNak      = 6
	MsgTypeRelease  = 7
	MsgTypeInform   = 8

	// Op codes (操作码)
	OpBootrequest = 1 // BOOTREQUEST, 客户端发出
	OpBootreply   = 2 // BOOTREPLY, 服务器发出

	// Hardware type (硬件类型)
	HTypeEthernet = 1

	// Broadcast flag (广播标志)
	BroadcastFlag = 0x8000
)

// Planner implements the DHCPv4 protocol planner (DHCPv4 协议规划器).
type Planner struct{}

// NewPlanner creates a new DHCP planner (创建 DHCP 规划器).
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name (返回协议名称).
func (p *Planner) Name() string {
	return "dhcp"
}

// Validate validates a DHCP flow spec (验证 DHCP 流规格).
// IPv6 addresses are rejected because DHCPv4 is IPv4-only.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// 1. DHCPv4 requires IPv4 addresses (DHCPv4 要求 IPv4 地址)
	if spec.SrcIP != "" {
		ip := net.ParseIP(spec.SrcIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("DHCPv4 requires IPv4 addresses: src_ip=%s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		ip := net.ParseIP(spec.DstIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("DHCPv4 requires IPv4 addresses: dst_ip=%s", spec.DstIP)
		}
	}

	// 2. DHCP config is optional — empty config defaults to a single DISCOVER
	// (P0b-2：空配置默认化产默认流)。
	if spec.DHCP == nil {
		return nil
	}

	dhcp := spec.DHCP

	// 2b. Scenario mode: validate scenario-specific prerequisites. When
	// Scenario is set, the planner auto-generates the Messages list; the
	// manual Messages field is ignored. Empty Scenario = manual mode
	// (backward-compatible). The config-level checks below (steps 6-13)
	// still apply to scenario mode, so we do NOT return early here.
	if dhcp.Scenario != "" {
		if err := validateScenario(dhcp); err != nil {
			return err
		}
	}

	// 3. Validate Role (验证角色)
	role := dhcp.Role
	if role == "" {
		role = "client"
	}
	if role != "client" && role != "server" && role != "relay" {
		return fmt.Errorf("invalid DHCP role: %s (must be client, server, or relay)", role)
	}

	// 4. Validate Messages non-empty (消息列表非空)
	// In scenario mode the planner synthesizes Messages at Plan time, so
	// the manual list may be empty. Skip this and the per-message loop
	// (step 5) in scenario mode; the synthesized messages are validated
	// structurally by buildScenarioMessages.
	if dhcp.Scenario == "" {
		if len(dhcp.Messages) == 0 {
			return fmt.Errorf("DHCP messages is required (at least 1 message)")
		}

		// 5. Validate each message type (验证每条消息类型)
		for i, msg := range dhcp.Messages {
			if msg.Type < 1 || msg.Type > 8 {
				return fmt.Errorf("message[%d]: unknown DHCP message type %d", i, msg.Type)
			}

			// Validate IP fields are IPv4
			if msg.ClientIP != "" {
				ip := net.ParseIP(msg.ClientIP)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid client IP: %s", i, msg.ClientIP)
				}
			}
			if msg.YourIP != "" {
				ip := net.ParseIP(msg.YourIP)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid your IP: %s", i, msg.YourIP)
				}
			}
			if msg.ServerIP != "" {
				ip := net.ParseIP(msg.ServerIP)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid server IP: %s", i, msg.ServerIP)
				}
			}
			if msg.RelayAgentIP != "" {
				ip := net.ParseIP(msg.RelayAgentIP)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid relay agent IP: %s", i, msg.RelayAgentIP)
				}
			}
			if msg.ServerIdentifier != "" {
				ip := net.ParseIP(msg.ServerIdentifier)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid server identifier: %s", i, msg.ServerIdentifier)
				}
			}
			if msg.RequestedIP != "" {
				ip := net.ParseIP(msg.RequestedIP)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid requested IP: %s", i, msg.RequestedIP)
				}
			}
			for j, r := range msg.Routers {
				ip := net.ParseIP(r)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid router address: %s", i, r)
				}
				_ = j
			}
			for j, d := range msg.DNS {
				ip := net.ParseIP(d)
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("message[%d]: invalid DNS address: %s", i, d)
				}
				_ = j
			}

			// Validate option 12/15 length <= 255
			if len(msg.Hostname) > 255 {
				return fmt.Errorf("message[%d]: hostname exceeds 255 bytes", i)
			}
			if len(msg.DomainName) > 255 {
				return fmt.Errorf("message[%d]: domain name exceeds 255 bytes", i)
			}

			// Validate option 55 length <= 255
			if len(msg.ParamRequestList) > 255 {
				return fmt.Errorf("message[%d]: param request list exceeds 255 bytes", i)
			}

			// Validate option 60 length <= 255
			if len(msg.VendorClass) > 255 {
				return fmt.Errorf("message[%d]: vendor class exceeds 255 bytes", i)
			}

			// Validate option 12/15 length <= 255 on defaults (from DHCPConfig level)
			// Validate option 82 length <= 255
			if len(msg.RelayAgentInfo) > 255 {
				return fmt.Errorf("message[%d]: relay agent info exceeds 255 bytes", i)
			}

			// Validate extra options
			for _, opt := range msg.ExtraOptions {
				if opt.Code == 52 {
					return fmt.Errorf("option overload not supported (code 52 in message[%d])", i)
				}
				if opt.Code == 255 {
					return fmt.Errorf("option 255 END is reserved (message[%d])", i)
				}
			}

			// Validate direction is valid if set
			if msg.Direction != "" && msg.Direction != "up" && msg.Direction != "down" {
				return fmt.Errorf("message[%d]: invalid direction: %s", i, msg.Direction)
			}
		}
	} // end of scenario=="" block (manual message validation)

	// 6. Validate ClientMAC length (if non-empty, 6 bytes)
	if dhcp.ClientMAC != "" {
		mac, err := net.ParseMAC(dhcp.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client MAC: %s", dhcp.ClientMAC)
		}
		if len(mac) != 6 {
			return fmt.Errorf("invalid client MAC length: %d bytes (need 6)", len(mac))
		}
	}

	// 7. Validate HType/HLen consistency (HType=1 Ethernet -> HLen=6)
	htype := dhcp.HType
	if htype == 0 {
		htype = HTypeEthernet
	}
	hlen := dhcp.HLen
	if hlen == 0 {
		hlen = 6
	}
	if htype == HTypeEthernet && hlen != 6 {
		return fmt.Errorf("HType=1 requires HLen=6, got HLen=%d", hlen)
	}

	// 8. Validate HLen range (0-16)
	if hlen > 16 {
		return fmt.Errorf("HLen must be <= 16, got %d", hlen)
	}

	// 9. Validate Sname length <= 64
	if len(dhcp.Sname) > 64 {
		return fmt.Errorf("sname exceeds 64 bytes")
	}
	// Validate File length <= 128
	if len(dhcp.File) > 128 {
		return fmt.Errorf("file exceeds 128 bytes")
	}

	// 10. Validate default IP fields are IPv4
	for _, field := range []struct {
		name  string
		value string
	}{
		{"default_client_ip", dhcp.DefaultClientIP},
		{"default_your_ip", dhcp.DefaultYourIP},
		{"default_server_ip", dhcp.DefaultServerIP},
		{"default_relay_agent_ip", dhcp.DefaultRelayAgentIP},
		{"default_server_identifier", dhcp.DefaultServerIdentifier},
		{"default_subnet_mask", dhcp.DefaultSubnetMask},
		{"default_requested_ip", dhcp.DefaultRequestedIP},
	} {
		if field.value != "" {
			ip := net.ParseIP(field.value)
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("DHCPv4 requires IPv4 addresses: %s=%s", field.name, field.value)
			}
		}
	}
	for _, r := range dhcp.DefaultRouters {
		ip := net.ParseIP(r)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("DHCPv4 requires IPv4 addresses: default_router=%s", r)
		}
	}
	for _, d := range dhcp.DefaultDNS {
		ip := net.ParseIP(d)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("DHCPv4 requires IPv4 addresses: default_dns=%s", d)
		}
	}

	// 11. Validate option 12/15 length <= 255 on defaults
	if len(dhcp.DefaultHostname) > 255 {
		return fmt.Errorf("default hostname exceeds 255 bytes")
	}
	if len(dhcp.DefaultDomainName) > 255 {
		return fmt.Errorf("default domain name exceeds 255 bytes")
	}
	// Validate option 55 length <= 255
	if len(dhcp.DefaultParamRequestList) > 255 {
		return fmt.Errorf("default param request list exceeds 255 bytes")
	}
	// Validate option 60 length <= 255
	if len(dhcp.DefaultVendorClass) > 255 {
		return fmt.Errorf("default vendor class exceeds 255 bytes")
	}
	// Validate option 82 length <= 255
	if len(dhcp.DefaultRelayAgentInfo) > 255 {
		return fmt.Errorf("default relay agent info exceeds 255 bytes")
	}
	// Validate option 61 length >= 2 when set
	if len(dhcp.DefaultClientID) > 0 && len(dhcp.DefaultClientID) < 2 {
		return fmt.Errorf("default client ID too short (minimum 2 bytes)")
	}

	// 12. Validate options total length <= MaxOptionsLen
	// In scenario mode, Messages may be empty (synthesized at Plan time);
	// validate against the first synthesized message instead.
	var firstMsg core.DHCPMessage
	if dhcp.Scenario != "" {
		synthesized := buildScenarioMessages(dhcp)
		if len(synthesized) == 0 {
			return fmt.Errorf("scenario %q produced no messages", dhcp.Scenario)
		}
		firstMsg = synthesized[0]
	} else {
		if len(dhcp.Messages) == 0 {
			return fmt.Errorf("DHCP messages is required (at least 1 message)")
		}
		firstMsg = dhcp.Messages[0]
	}
	estLen, err := estimateOptionsLen(dhcp, firstMsg)
	if err != nil {
		return err
	}
	if estLen > MaxOptionsLen {
		return fmt.Errorf("options exceed MTU (estimated %d > max %d)", estLen, MaxOptionsLen)
	}

	// 13. Validate relay: client must have empty giaddr
	if role == "client" && dhcp.DefaultRelayAgentIP != "" {
		return fmt.Errorf("client must have empty giaddr")
	}

	// 14. Validate extra options on DHCPConfig level
	// In scenario mode, check the first synthesized message; otherwise
	// check the first user-provided message.
	for _, opt := range firstMsg.ExtraOptions {
		if opt.Code == 52 {
			return fmt.Errorf("option overload not supported")
		}
	}

	return nil
}

// Plan generates packet configs for a DHCP flow (生成 DHCP 流的数据包配置).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		dhcp := spec.DHCP
		if dhcp == nil {
			// P0b-2：空配置默认化（Generate 同款：client 角色单 DISCOVER）。
			dhcp = &core.DHCPConfig{Role: "client", Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}}}
			spec.DHCP = dhcp
		}
		role := dhcp.Role
		if role == "" {
			role = "client"
		}

		// Scenario mode: auto-generate the message sequence from the
		// RFC 2131 state machine. The synthesized messages carry the
		// correct option chain (50/54/51/55) and ciaddr/yiaddr per
		// RFC 2131 §3.1/§4.3. Manual mode uses the user-provided
		// Messages list as-is.
		var messages []core.DHCPMessage
		var effectiveDHCP *core.DHCPConfig
		if dhcp.Scenario != "" {
			messages = buildScenarioMessages(dhcp)
			// Use a config copy with cleared option defaults so the
			// synthesized messages are self-contained — RFC option
			// presence/absence is enforced structurally.
			effectiveDHCP = scenarioConfig(dhcp)
		} else {
			messages = dhcp.Messages
			effectiveDHCP = dhcp
		}

		// Resolve xid (事务ID): 0 = random
		xid := dhcp.Xid
		if xid == 0 {
			xid = rand.Uint32()
		}

		// Resolve HType/HLen
		htype := dhcp.HType
		if htype == 0 {
			htype = HTypeEthernet
		}
		hlen := dhcp.HLen
		if hlen == 0 {
			hlen = 6
		}

		// Resolve ClientMAC (客户端MAC)
		clientMAC := dhcp.ClientMAC
		if clientMAC == "" {
			if role == "client" {
				clientMAC = spec.SrcMAC
			} else {
				clientMAC = spec.DstMAC
			}
		}

		// Resolve ports and IPs based on role (基于角色解析端口和IP)
		srcPort, dstPort := resolvePorts(role, spec)
		srcIP, dstIP := resolveIPs(role, spec, dhcp)

		// Resolve MACs (解析MAC地址)
		srcMAC, dstMAC := resolveMACs(role, spec, dstIP)

		// Resolve secs (秒数)
		secs := dhcp.Secs

		// Resolve broadcast flag (广播标志)
		broadcastFlag := dhcp.BroadcastFlag

		// Resolve sname/file
		sname := dhcp.Sname
		file := dhcp.File

		flowID := fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, srcPort, dstPort)
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

		for i, msg := range messages {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Infer op (操作码) from message type
			op := inferOpFromType(msg.Type)

			// Infer direction (方向) from message type
			direction := msg.Direction
			if direction == "" {
				direction = inferDirectionFromType(msg.Type)
			}

			// Resolve per-message broadcast flag (解析每条消息的广播标志)
			msgBroadcast := broadcastFlag
			if msg.Broadcast != nil {
				msgBroadcast = *msg.Broadcast
			}

			// Resolve flags (标志位)
			flags := uint16(0)
			if msgBroadcast {
				flags = BroadcastFlag
			}

			// Resolve hops (跳数)
			hops := msg.Hops
			if hops == 0 && role == "client" {
				hops = 0
			}

			// Merge defaults + per-message overrides (合并默认值和每条消息的覆盖)
			ciaddr := resolveStr(msg.ClientIP, effectiveDHCP.DefaultClientIP, "0.0.0.0")
			yiaddr := resolveStr(msg.YourIP, effectiveDHCP.DefaultYourIP, "0.0.0.0")
			siaddr := resolveStr(msg.ServerIP, effectiveDHCP.DefaultServerIP, "0.0.0.0")
			giaddr := resolveStr(msg.RelayAgentIP, effectiveDHCP.DefaultRelayAgentIP, "0.0.0.0")

			// Build DHCP message payload (构建 DHCP 报文载荷)
			payload, err := buildDHCPMessage(
				msg, effectiveDHCP, op, htype, hlen, hops, xid, secs, flags,
				ciaddr, yiaddr, siaddr, giaddr,
				clientMAC, sname, file,
			)
			if err != nil {
				// If serialization fails, we can't send this packet; skip
				return
			}

			// Determine L2 MACs for this message based on direction and role.
			//
			// Role=client perspective (the common case): spec.SrcMAC is the
			// client MAC, spec.DstMAC is the server MAC. Request (up) packets
			// are src=client/dst=server (or broadcast). Reply (down) packets
			// are emitted from the server's perspective, so src=server/dst=client
			// — i.e. the down branch swaps the resolved MACs.
			//
			// Role=server perspective: spec.SrcMAC is already the server MAC
			// and spec.DstMAC is already the client MAC, so the down branch
			// must NOT swap (swapping would put the client MAC as the reply
			// source). Pre-fix the down branch swapped unconditionally, which
			// for role=server produced a reply whose source was the client MAC
			// and whose destination was all-zero when spec.SrcMAC was empty.
			//
			// The resolved srcMAC/dstMAC (from resolveMACs) carry the
			// BroadcastMAC fallback for an empty destination. But for a server
			// reply the SOURCE must be a server MAC, never broadcast (broadcast
			// is destination-only on Ethernet) and never all-zero. So when the
			// server MAC is empty we fall back to DefaultServerMAC.
			msgSrcMAC := srcMAC
			msgDstMAC := dstMAC

			if direction == "down" {
				if role == "server" {
					// Already in server perspective: src=server, dst=client.
					// No swap; just ensure the server source is non-zero.
					if msgSrcMAC == "" {
						msgSrcMAC = DefaultServerMAC
					}
				} else {
					// role=client (or relay): swap so the reply is src=server,
					// dst=client. The server MAC is the resolved dstMAC; if it
					// was empty resolveMACs turned it into BroadcastMAC, which
					// is invalid as a *source* — fall back to DefaultServerMAC.
					msgSrcMAC = dstMAC
					msgDstMAC = srcMAC
					if msgSrcMAC == "" || msgSrcMAC == BroadcastMAC {
						msgSrcMAC = DefaultServerMAC
					}
				}
			}

			// Override DstMAC for broadcast (广播时覆盖 DstMAC)
			if msgBroadcast {
				msgDstMAC = BroadcastMAC
			}

			// Determine L3 IPs for this message
			msgSrcIP := srcIP
			msgDstIP := dstIP

			// For client messages without IP, use 0.0.0.0 (客户端无IP时使用0.0.0.0)
			if direction == "up" && (msg.Type == MsgTypeDiscover || msg.Type == MsgTypeRequest || msg.Type == MsgTypeDecline) {
				if ciaddr == "0.0.0.0" || ciaddr == "" {
					msgSrcIP = "0.0.0.0"
				}
			}

			// For server messages, swap IPs (服务器消息交换IP)
			if direction == "down" {
				msgSrcIP = spec.DstIP
				msgDstIP = spec.SrcIP
				if msgSrcIP == "" {
					msgSrcIP = "0.0.0.0"
				}
				if msgDstIP == "" {
					msgDstIP = "0.0.0.0"
				}
			}

			// For up direction, DstIP is broadcast when client has no IP
			if direction == "up" && msgBroadcast {
				msgDstIP = BroadcastIP
				if msgSrcIP == "" || msgSrcIP == "0.0.0.0" {
					msgSrcIP = "0.0.0.0"
				}
			}

			// For RELEASE and INFORM, use ciaddr as srcIP when client has IP
			if direction == "up" && (msg.Type == MsgTypeRelease || msg.Type == MsgTypeInform) {
				if ciaddr != "0.0.0.0" && ciaddr != "" {
					msgSrcIP = ciaddr
				}
			}

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: uint64(i),
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    msgSrcMAC,
					DstMAC:    msgDstMAC,
					EtherType: core.EtherTypeFor(msgSrcIP),
				},
				L3: core.L3Base(msgSrcIP, msgDstIP, core.ProtocolUDP, effectiveTTL, nextIPID(), spec),
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

// resolvePorts resolves source/destination ports based on role (基于角色解析端口).
func resolvePorts(role string, spec core.FlowSpec) (uint16, uint16) {
	switch role {
	case "client":
		src := spec.SrcPort
		if src == 0 {
			src = ClientPort
		}
		dst := spec.DstPort
		if dst == 0 {
			dst = ServerPort
		}
		return src, dst
	case "server":
		src := spec.SrcPort
		if src == 0 {
			src = ServerPort
		}
		dst := spec.DstPort
		if dst == 0 {
			dst = ClientPort
		}
		return src, dst
	case "relay":
		// Relay forwards both directions; default to server port
		src := spec.SrcPort
		if src == 0 {
			src = ServerPort
		}
		dst := spec.DstPort
		if dst == 0 {
			dst = ServerPort
		}
		return src, dst
	default:
		return ClientPort, ServerPort
	}
}

// resolveIPs resolves source/destination IPs based on role (基于角色解析IP).
func resolveIPs(role string, spec core.FlowSpec, dhcp *core.DHCPConfig) (string, string) {
	srcIP := spec.SrcIP
	dstIP := spec.DstIP

	if role == "client" || role == "" {
		if srcIP == "" {
			srcIP = "0.0.0.0"
		}
		if dstIP == "" {
			dstIP = BroadcastIP
		}
	}

	if role == "server" {
		if srcIP == "" {
			srcIP = "0.0.0.0"
		}
		if dstIP == "" {
			dstIP = BroadcastIP
		}
	}

	if role == "relay" {
		if srcIP == "" {
			srcIP = "0.0.0.0"
		}
		if dstIP == "" {
			dstIP = BroadcastIP
		}
	}

	return srcIP, dstIP
}

// resolveMACs resolves source/destination MACs based on role (基于角色解析MAC).
func resolveMACs(role string, spec core.FlowSpec, dstIP string) (string, string) {
	srcMAC := spec.SrcMAC
	dstMAC := spec.DstMAC

	if role == "client" || role == "" {
		// Client sends to broadcast MAC by default
		if dstMAC == "" {
			dstMAC = BroadcastMAC
		}
	}

	if role == "server" {
		// Server sends to client MAC or broadcast
		if dstMAC == "" {
			dstMAC = BroadcastMAC
		}
	}

	if role == "relay" {
		if dstMAC == "" {
			dstMAC = BroadcastMAC
		}
	}

	return srcMAC, dstMAC
}

// resolveStr returns the override value if non-empty, else the default value,
// else the fallback (解析字符串值: 覆盖 > 默认 > 回退).
func resolveStr(override, def, fallback string) string {
	if override != "" {
		return override
	}
	if def != "" {
		return def
	}
	return fallback
}

// inferOpFromType infers the BOOTP op field from DHCP message type (从消息类型推断操作码).
func inferOpFromType(msgType uint8) uint8 {
	switch msgType {
	case MsgTypeDiscover, MsgTypeRequest, MsgTypeDecline, MsgTypeRelease, MsgTypeInform:
		return OpBootrequest
	case MsgTypeOffer, MsgTypeAck, MsgTypeNak:
		return OpBootreply
	default:
		return OpBootrequest
	}
}

// inferDirectionFromType infers the direction from DHCP message type (从消息类型推断方向).
func inferDirectionFromType(msgType uint8) string {
	switch msgType {
	case MsgTypeDiscover, MsgTypeRequest, MsgTypeDecline, MsgTypeRelease, MsgTypeInform:
		return "up"
	case MsgTypeOffer, MsgTypeAck, MsgTypeNak:
		return "down"
	default:
		return "up"
	}
}

// buildDHCPMessage builds a complete DHCP message payload (构建完整 DHCP 报文载荷).
// Returns the raw bytes: BOOTP header + magic cookie + options + END + padding.
func buildDHCPMessage(
	msg core.DHCPMessage,
	dhcp *core.DHCPConfig,
	op, htype, hlen, hops uint8,
	xid uint32,
	secs, flags uint16,
	ciaddr, yiaddr, siaddr, giaddr string,
	clientMAC, sname, file string,
) ([]byte, error) {
	// Encode BOOTP header (编码 BOOTP 固定头)
	bootpHeader, err := encodeBootpHeader(op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, clientMAC, sname, file)
	if err != nil {
		return nil, fmt.Errorf("encode bootp header: %w", err)
	}

	// Encode magic cookie (编码魔术cookie)
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, MagicCookie)

	// Encode DHCP options (编码 DHCP 选项)
	options, err := encodeOptions(msg, dhcp)
	if err != nil {
		return nil, fmt.Errorf("encode options: %w", err)
	}

	// Combine: BOOTP header + magic + options (合并)
	payload := make([]byte, 0, len(bootpHeader)+len(magic)+len(options))
	payload = append(payload, bootpHeader...)
	payload = append(payload, magic...)
	payload = append(payload, options...)

	// Verify total options length (验证 options 总长度)
	optionsTotal := len(options)
	if optionsTotal > MaxOptionsLen {
		return nil, fmt.Errorf("options exceed MTU (actual %d > max %d)", optionsTotal, MaxOptionsLen)
	}

	return payload, nil
}

// encodeBootpHeader serializes the BOOTP fixed header (236 bytes) (序列化 BOOTP 固定头).
func encodeBootpHeader(
	op, htype, hlen, hops uint8,
	xid uint32,
	secs, flags uint16,
	ciaddr, yiaddr, siaddr, giaddr string,
	clientMAC, sname, file string,
) ([]byte, error) {
	buf := make([]byte, BootpHeaderLen)

	// Byte 0: op (操作码)
	buf[0] = op

	// Byte 1: htype (硬件类型)
	buf[1] = htype

	// Byte 2: hlen (硬件地址长度)
	buf[2] = hlen

	// Byte 3: hops (跳数)
	buf[3] = hops

	// Bytes 4-7: xid (事务ID)
	binary.BigEndian.PutUint32(buf[4:8], xid)

	// Bytes 8-9: secs (秒数)
	binary.BigEndian.PutUint16(buf[8:10], secs)

	// Bytes 10-11: flags (标志位)
	binary.BigEndian.PutUint16(buf[10:12], flags)

	// Bytes 12-15: ciaddr (客户端IP)
	ip4 := net.ParseIP(ciaddr).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid ciaddr: %s", ciaddr)
	}
	copy(buf[12:16], ip4)

	// Bytes 16-19: yiaddr (你的IP)
	ip4 = net.ParseIP(yiaddr).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid yiaddr: %s", yiaddr)
	}
	copy(buf[16:20], ip4)

	// Bytes 20-23: siaddr (服务器IP)
	ip4 = net.ParseIP(siaddr).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid siaddr: %s", siaddr)
	}
	copy(buf[20:24], ip4)

	// Bytes 24-27: giaddr (中继代理IP)
	ip4 = net.ParseIP(giaddr).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid giaddr: %s", giaddr)
	}
	copy(buf[24:28], ip4)

	// Bytes 28-43: chaddr (客户端硬件地址, 16 bytes)
	if clientMAC != "" {
		mac, err := net.ParseMAC(clientMAC)
		if err != nil {
			return nil, fmt.Errorf("invalid client MAC: %s: %w", clientMAC, err)
		}
		// chaddr[0:6] = MAC, chaddr[6:16] = 0
		copy(buf[28:34], mac)
		// Bytes 34-43 are already zero
	}

	// Bytes 44-107: sname (服务器主机名, 64 bytes)
	if sname != "" {
		copy(buf[44:44+len(sname)], sname)
		// Rest is zero-filled
	}

	// Bytes 108-235: file (启动文件名, 128 bytes)
	if file != "" {
		copy(buf[108:108+len(file)], file)
		// Rest is zero-filled
	}

	return buf, nil
}

// encodeOptions encodes all DHCP options (TLV) for a message (编码 DHCP 选项).
// Returns the options bytes including option 53, all user options, END, and padding.
func encodeOptions(msg core.DHCPMessage, dhcp *core.DHCPConfig) ([]byte, error) {
	var buf []byte

	// Option 53: DHCP Message Type (DHCP 消息类型) - always first
	buf = append(buf, encodeOptionUint8(53, msg.Type)...)

	// Option 50: Requested IP Address (请求的IP地址)
	if ip := resolveStr(msg.RequestedIP, dhcp.DefaultRequestedIP, ""); ip != "" {
		opt, err := encodeOptionIP(50, ip)
		if err != nil {
			return nil, err
		}
		buf = append(buf, opt...)
	}

	// Option 54: Server Identifier (服务器标识)
	if sid := resolveStr(msg.ServerIdentifier, dhcp.DefaultServerIdentifier, ""); sid != "" {
		opt, err := encodeOptionIP(54, sid)
		if err != nil {
			return nil, err
		}
		buf = append(buf, opt...)
	}

	// Option 51: IP Address Lease Time (租期)
	leaseTime := msg.LeaseTime
	if leaseTime == 0 {
		leaseTime = dhcp.DefaultLeaseTime
	}
	if leaseTime > 0 {
		buf = append(buf, encodeOptionUint32(51, leaseTime)...)
	}

	// Option 58: T1 Renewal Time (续约时间)
	t1 := msg.T1
	if t1 == 0 {
		t1 = dhcp.DefaultT1
	}
	if t1 > 0 {
		buf = append(buf, encodeOptionUint32(58, t1)...)
	}

	// Option 59: T2 Rebinding Time (重绑定时间)
	t2 := msg.T2
	if t2 == 0 {
		t2 = dhcp.DefaultT2
	}
	if t2 > 0 {
		buf = append(buf, encodeOptionUint32(59, t2)...)
	}

	// Option 1: Subnet Mask (子网掩码)
	if mask := resolveStr(msg.SubnetMask, dhcp.DefaultSubnetMask, ""); mask != "" {
		opt, err := encodeOptionIP(1, mask)
		if err != nil {
			return nil, err
		}
		buf = append(buf, opt...)
	}

	// Option 3: Router (路由器)
	routers := msg.Routers
	if len(routers) == 0 {
		routers = dhcp.DefaultRouters
	}
	if len(routers) > 0 {
		opt, err := encodeOptionIPList(3, routers)
		if err != nil {
			return nil, err
		}
		buf = append(buf, opt...)
	}

	// Option 6: DNS Servers (DNS服务器)
	dns := msg.DNS
	if len(dns) == 0 {
		dns = dhcp.DefaultDNS
	}
	if len(dns) > 0 {
		opt, err := encodeOptionIPList(6, dns)
		if err != nil {
			return nil, err
		}
		buf = append(buf, opt...)
	}

	// Option 12: Host Name (主机名)
	if hostname := resolveStr(msg.Hostname, dhcp.DefaultHostname, ""); hostname != "" {
		buf = append(buf, encodeOptionString(12, hostname)...)
	}

	// Option 15: Domain Name (域名)
	if domain := resolveStr(msg.DomainName, dhcp.DefaultDomainName, ""); domain != "" {
		buf = append(buf, encodeOptionString(15, domain)...)
	}

	// Option 119: Domain Search (域名搜索列表)
	domainSearch := msg.DomainSearch
	if len(domainSearch) == 0 {
		domainSearch = dhcp.DefaultDomainSearch
	}
	if len(domainSearch) > 0 {
		encoded, err := encodeDomainSearch(domainSearch)
		if err != nil {
			return nil, err
		}
		// If encoded data > 255 bytes, split per RFC 3396 (RFC 3396 拆分)
		for len(encoded) > 0 {
			chunk := encoded
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			buf = append(buf, encodeOptionBytes(119, chunk)...)
			encoded = encoded[len(chunk):]
		}
	}

	// Option 55: Parameter Request List (参数请求列表)
	prl := msg.ParamRequestList
	if len(prl) == 0 {
		prl = dhcp.DefaultParamRequestList
	}
	if len(prl) > 0 {
		buf = append(buf, encodeOptionList(55, prl)...)
	}

	// Option 60: Vendor Class Identifier (厂商类别标识)
	if vc := resolveStr(msg.VendorClass, dhcp.DefaultVendorClass, ""); vc != "" {
		buf = append(buf, encodeOptionString(60, vc)...)
	}

	// Option 61: Client Identifier (客户端标识符)
	clientID := msg.ClientID
	if len(clientID) == 0 {
		clientID = dhcp.DefaultClientID
	}
	if len(clientID) > 0 {
		buf = append(buf, encodeOptionBytes(61, clientID)...)
	}

	// Option 82: Relay Agent Information (中继代理信息)
	relayInfo := msg.RelayAgentInfo
	if len(relayInfo) == 0 {
		relayInfo = dhcp.DefaultRelayAgentInfo
	}
	if len(relayInfo) > 0 {
		buf = append(buf, encodeOptionBytes(82, relayInfo)...)
	}

	// Extra options (额外选项)
	for _, opt := range msg.ExtraOptions {
		if opt.Code == 0 || opt.Code == 255 {
			continue // PAD and END are handled separately
		}
		buf = append(buf, encodeOption(opt.Code, opt.Data)...)
	}

	// Option 255: END (结束标记)
	buf = append(buf, 255)

	// Pad to 4-byte boundary (填充到4字节边界)
	for len(buf)%4 != 0 {
		buf = append(buf, 0) // PAD
	}

	return buf, nil
}

// estimateOptionsLen estimates the total options length for validation (估算选项总长度).
func estimateOptionsLen(dhcp *core.DHCPConfig, msg core.DHCPMessage) (int, error) {
	// Start with option 53 (3 bytes: code + len + data)
	total := 3

	// Estimate each option: 1 (code) + 1 (len) + len(data)
	estimateOption := func(dataLen int) int {
		return 1 + 1 + dataLen
	}

	// Option 50: Requested IP
	if msg.RequestedIP != "" || dhcp.DefaultRequestedIP != "" {
		total += estimateOption(4)
	}

	// Option 54: Server Identifier
	if msg.ServerIdentifier != "" || dhcp.DefaultServerIdentifier != "" {
		total += estimateOption(4)
	}

	// Option 51: Lease Time
	if msg.LeaseTime > 0 || dhcp.DefaultLeaseTime > 0 {
		total += estimateOption(4)
	}

	// Option 58: T1
	if msg.T1 > 0 || dhcp.DefaultT1 > 0 {
		total += estimateOption(4)
	}

	// Option 59: T2
	if msg.T2 > 0 || dhcp.DefaultT2 > 0 {
		total += estimateOption(4)
	}

	// Option 1: Subnet Mask
	if msg.SubnetMask != "" || dhcp.DefaultSubnetMask != "" {
		total += estimateOption(4)
	}

	// Option 3: Router
	routers := msg.Routers
	if len(routers) == 0 {
		routers = dhcp.DefaultRouters
	}
	if len(routers) > 0 {
		total += estimateOption(len(routers) * 4)
	}

	// Option 6: DNS
	dns := msg.DNS
	if len(dns) == 0 {
		dns = dhcp.DefaultDNS
	}
	if len(dns) > 0 {
		total += estimateOption(len(dns) * 4)
	}

	// Option 12: Hostname
	hostname := msg.Hostname
	if hostname == "" {
		hostname = dhcp.DefaultHostname
	}
	if len(hostname) > 0 {
		total += estimateOption(len(hostname))
	}

	// Option 15: Domain Name
	domain := msg.DomainName
	if domain == "" {
		domain = dhcp.DefaultDomainName
	}
	if len(domain) > 0 {
		total += estimateOption(len(domain))
	}

	// Option 119: Domain Search (rough estimate)
	domainSearch := msg.DomainSearch
	if len(domainSearch) == 0 {
		domainSearch = dhcp.DefaultDomainSearch
	}
	for _, ds := range domainSearch {
		// Rough estimate: each label + 1 byte for length + 1 for final 0
		total += estimateOption(len(ds) + 2)
	}

	// Option 55: Param Request List
	prl := msg.ParamRequestList
	if len(prl) == 0 {
		prl = dhcp.DefaultParamRequestList
	}
	if len(prl) > 0 {
		total += estimateOption(len(prl))
	}

	// Option 60: Vendor Class
	vc := msg.VendorClass
	if vc == "" {
		vc = dhcp.DefaultVendorClass
	}
	if len(vc) > 0 {
		total += estimateOption(len(vc))
	}

	// Option 61: Client ID
	clientID := msg.ClientID
	if len(clientID) == 0 {
		clientID = dhcp.DefaultClientID
	}
	if len(clientID) > 0 {
		total += estimateOption(len(clientID))
	}

	// Option 82: Relay Agent Info
	relayInfo := msg.RelayAgentInfo
	if len(relayInfo) == 0 {
		relayInfo = dhcp.DefaultRelayAgentInfo
	}
	if len(relayInfo) > 0 {
		total += estimateOption(len(relayInfo))
	}

	// Extra options
	for _, opt := range msg.ExtraOptions {
		total += estimateOption(len(opt.Data))
	}

	// END (1 byte) + padding to 4 bytes
	total += 1
	for total%4 != 0 {
		total++
	}

	return total, nil
}

// --- TLV encoding helpers (TLV 编码辅助函数) ---

// encodeOption encodes a DHCP option as TLV (编码 DHCP 选项为 TLV 格式).
func encodeOption(code uint8, data []byte) []byte {
	buf := make([]byte, 2+len(data))
	buf[0] = code
	buf[1] = byte(len(data))
	copy(buf[2:], data)
	return buf
}

// encodeOptionString encodes a string as a DHCP option (编码字符串选项).
func encodeOptionString(code uint8, s string) []byte {
	return encodeOption(code, []byte(s))
}

// encodeOptionIPList encodes a list of IPv4 addresses as a DHCP option (编码 IPv4 列表选项).
func encodeOptionIPList(code uint8, ips []string) ([]byte, error) {
	var data []byte
	for _, ip := range ips {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", ip)
		}
		data = append(data, ip4...)
	}
	return encodeOption(code, data), nil
}

// encodeOptionIP encodes a single IPv4 address as a DHCP option (编码单个 IPv4 选项).
func encodeOptionIP(code uint8, ip string) ([]byte, error) {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return encodeOption(code, ip4), nil
}

// encodeOptionUint32 encodes a uint32 as a DHCP option (编码 uint32 选项).
func encodeOptionUint32(code uint8, v uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, v)
	return encodeOption(code, data)
}

// encodeOptionUint8 encodes a uint8 as a DHCP option (编码 uint8 选项).
func encodeOptionUint8(code uint8, v uint8) []byte {
	return []byte{code, 1, v}
}

// encodeOptionList encodes a list of bytes as a DHCP option (编码字节列表选项).
func encodeOptionList(code uint8, items []uint8) []byte {
	return encodeOption(code, items)
}

// encodeOptionBytes encodes raw bytes as a DHCP option (编码原始字节选项).
func encodeOptionBytes(code uint8, data []byte) []byte {
	return encodeOption(code, data)
}

// encodeDomainSearch encodes domain names per RFC 3397 DNS compression (编码域名搜索列表).
func encodeDomainSearch(names []string) ([]byte, error) {
	var buf []byte
	for _, name := range names {
		encoded := encodeDNSName(name)
		buf = append(buf, encoded...)
	}
	return buf, nil
}

// encodeDNSName encodes a single domain name in DNS label format (编码 DNS 域名).
func encodeDNSName(name string) []byte {
	var buf []byte
	labels := splitLabels(name)
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label
	return buf
}

// splitLabels splits a domain name into labels (分割域名为标签).
func splitLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}
