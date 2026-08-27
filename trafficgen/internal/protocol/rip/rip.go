// Package rip implements the RIP (RFC 1058 / RFC 2453 / RFC 2080 / RFC 4822) protocol planner.
package rip

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// RIP v1/v2 default port (RFC 2453).
	PortRIP = 520
	// RIPng default port (RFC 2080).
	PortRIPng = 521

	// RIP Commands.
	CommandRequest  = 1
	CommandResponse = 2

	// RIP Versions.
	VersionRIP   = 1
	VersionRIPv2 = 2
	VersionRIPng = 1 // RIPng also uses version 1

	// AFI constants.
	AFIIPv4        = 2
	AFIRequestFull = 0      // AFI=0 for request full routes (RFC 2453 §3.9.1)
	AFIAuth        = 0xFFFF // Authentication entry marker

	// Auth Types.
	AuthTypeSimple = 0x0002
	AuthTypeMD5    = 0x0003

	// MD5 trailer header Type (RFC 4822 §2.1).
	MD5TrailerType = 0x0001

	// Max RTE per packet (without auth).
	MaxRTEPerPacket = 25

	// RTE size in bytes.
	RTESize = 20

	// RIP header size.
	HeaderSize = 4

	// Default DSCP for network control traffic (CS6).
	DefaultDSCP = 0xC0

	// Default TTL for unicast.
	DefaultTTL = 64
)

// defaultRoutes are the 5 example routes for response_default scenario.
var defaultRoutes = []RIPRoute{
	{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1},
	{IPAddr: "172.16.0.0", SubnetMask: "255.255.0.0", Metric: 1},
	{IPAddr: "192.168.0.0", SubnetMask: "255.255.0.0", Metric: 1},
	{IPAddr: "0.0.0.0", SubnetMask: "0.0.0.0", Metric: 1}, // default route
	{IPAddr: "192.168.1.0", SubnetMask: "255.255.255.0", Metric: 1},
}

// Planner implements the RIP protocol planner.
type Planner struct{}

// NewPlanner creates a new RIP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "rip"
}

// versionFromString converts version string to internal representation.
func versionFromString(v string) string {
	switch v {
	case "v1":
		return "v1"
	case "v2", "":
		return "v2"
	case "ng":
		return "ng"
	default:
		return v
	}
}

// commandFromString converts command string to byte value.
func commandFromString(cmd string) (uint8, error) {
	switch cmd {
	case "request":
		return CommandRequest, nil
	case "response", "":
		return CommandResponse, nil
	default:
		return 0, fmt.Errorf("invalid command: %s (allowed: request, response)", cmd)
	}
}

// Validate validates a RIP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
	// （v2 response_default 5 条示例路由）。允许 nil。
	if spec.RIP == nil {
		return nil
	}
	cfg := spec.RIP

	// Validate version
	version := versionFromString(cfg.Version)
	if version != "v1" && version != "v2" && version != "ng" {
		return fmt.Errorf("invalid version: %s (allowed: v1, v2, ng)", cfg.Version)
	}

	// Validate SrcIP/DstIP parseability and address-family consistency with
	// the version (design §8.7: RIPng SrcIP must be IPv6; v1/v2 must be IPv4).
	if spec.SrcIP != "" {
		src := net.ParseIP(spec.SrcIP)
		if src == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
		if err := validateIPFamily(spec.SrcIP, version, "source IP"); err != nil {
			return err
		}
	}
	// Multicast overrides DstIP (design T-ERR-14), so family check only
	// applies to unicast.
	if spec.DstIP != "" && !cfg.Multicast {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
		if err := validateIPFamily(spec.DstIP, version, "destination IP"); err != nil {
			return err
		}
	}

	// Validate command
	if cfg.Command != "" {
		if _, err := commandFromString(cfg.Command); err != nil {
			return err
		}
	}

	// Validate auth compatibility
	if cfg.Auth != nil {
		if version == "v1" {
			return fmt.Errorf("RIP v1 does not support authentication")
		}
		if version == "ng" {
			return fmt.Errorf("RIPng does not support authentication (use IPsec)")
		}
		// Validate auth type
		if cfg.Auth.Type != "" && cfg.Auth.Type != "simple" && cfg.Auth.Type != "md5" {
			return fmt.Errorf("invalid auth type: %s (allowed: simple, md5)", cfg.Auth.Type)
		}
		// Validate simple auth password length
		if (cfg.Auth.Type == "" || cfg.Auth.Type == "simple") && cfg.Auth.Password != "" {
			if len(cfg.Auth.Password) > 16 {
				return fmt.Errorf("simple auth password must be <= 16 bytes, got %d", len(cfg.Auth.Password))
			}
		}
		// Validate MD5 auth data length
		if cfg.Auth.Type == "md5" && cfg.Auth.AuthDataLen != nil {
			if *cfg.Auth.AuthDataLen == 0 {
				return fmt.Errorf("md5 auth_data_len must be > 0")
			}
		}
	}

	// Validate routes
	for i, route := range cfg.Routes {
		if err := validateRoute(route, version, i); err != nil {
			return err
		}
	}

	// Validate routers
	for i, router := range cfg.Routers {
		if router.SrcIP == "" && router.SrcPort == 0 && router.DstIP == "" && router.DstPort == 0 {
			return fmt.Errorf("router[%d]: at least one field must be non-empty", i)
		}
		if router.SrcIP != "" {
			if net.ParseIP(router.SrcIP) == nil {
				return fmt.Errorf("router[%d]: invalid source IP: %s", i, router.SrcIP)
			}
			if err := validateIPFamily(router.SrcIP, version, "router source IP"); err != nil {
				return fmt.Errorf("router[%d]: %v", i, err)
			}
		}
		if router.DstIP != "" && !cfg.Multicast {
			if net.ParseIP(router.DstIP) == nil {
				return fmt.Errorf("router[%d]: invalid destination IP: %s", i, router.DstIP)
			}
			if err := validateIPFamily(router.DstIP, version, "router destination IP"); err != nil {
				return fmt.Errorf("router[%d]: %v", i, err)
			}
		}
	}

	// Warning-only combinations (design §6.15 T-ERR-14/T-ERR-15/T-ERR-18).
	// SplitHorizon/PoisonReverse take effect only in unicast; multicast has no
	// concrete receiver, so the planner skips filtering (design §8.5).

	return nil
}

// validateIPFamily checks that an IP literal matches the address family of the
// configured RIP version (v1/v2 = IPv4, ng = IPv6; design §8.7).
func validateIPFamily(ip, version, what string) error {
	is6 := net.ParseIP(ip).To4() == nil
	if version == "ng" && !is6 {
		return fmt.Errorf("%s must be IPv6 for RIPng: %s", what, ip)
	}
	if version != "ng" && is6 {
		return fmt.Errorf("%s must be IPv4 for version %s: %s", what, version, ip)
	}
	return nil
}

// validateRoute validates a single route entry.
func validateRoute(route RIPRoute, version string, idx int) error {
	// Validate metric (1-16)
	if route.Metric == 0 {
		return fmt.Errorf("route[%d]: metric must be >= 1", idx)
	}
	if route.Metric > 16 {
		return fmt.Errorf("route[%d]: metric must be <= 16", idx)
	}

	// Validate IP address
	if route.IPAddr == "" {
		return fmt.Errorf("route[%d]: ip_addr is required", idx)
	}
	ip := net.ParseIP(route.IPAddr)
	if ip == nil {
		return fmt.Errorf("route[%d]: invalid IP address: %s", idx, route.IPAddr)
	}
	// Address family must match the version: v1/v2 carry 4-byte IPv4
	// addresses, RIPng carries 16-byte IPv6 prefixes. A mismatched literal
	// would silently serialize into a bogus entry (e.g. IPv4 -> ::ffff:x.x.x.x).
	if version == "ng" && ip.To4() != nil {
		return fmt.Errorf("route[%d]: ip_addr must be IPv6 for RIPng: %s", idx, route.IPAddr)
	}
	if version != "ng" && ip.To4() == nil {
		return fmt.Errorf("route[%d]: ip_addr must be IPv4 for version %s: %s", idx, version, route.IPAddr)
	}

	// Validate AFI
	if route.AFI != 0 {
		if route.AFI == AFIAuth {
			return fmt.Errorf("route[%d]: AFI=0xFFFF is reserved for authentication", idx)
		}
		if route.AFI != AFIIPv4 {
			return fmt.Errorf("route[%d]: invalid AFI: %d (allowed: 0, 2)", idx, route.AFI)
		}
	}

	// Validate subnet mask for v2
	if version == "v2" && route.SubnetMask != "" {
		maskIP := net.ParseIP(route.SubnetMask)
		if maskIP == nil || maskIP.To4() == nil {
			return fmt.Errorf("route[%d]: invalid subnet mask: %s", idx, route.SubnetMask)
		}
	}

	// Validate prefix length for ng
	if version == "ng" {
		if route.PrefixLen > 128 {
			return fmt.Errorf("route[%d]: prefix_len must be <= 128", idx)
		}
	}

	// Validate next hop IP matches version
	if route.NextHop != "" {
		nhIP := net.ParseIP(route.NextHop)
		if nhIP == nil {
			return fmt.Errorf("route[%d]: invalid next_hop: %s", idx, route.NextHop)
		}
		// RIPng has no Next Hop field (RFC 2080 §2.1.1); reject explicitly
		// (design §3: implementation chooses the stricter error path).
		if version == "ng" {
			return fmt.Errorf("route[%d]: RIPng does not support next_hop field", idx)
		}
		// v1/v2 carry a 4-byte IPv4 next hop; a v6 literal cannot be encoded
		// and would silently serialize as 0.0.0.0 (design T-ERR-13).
		if nhIP.To4() == nil {
			return fmt.Errorf("route[%d]: next_hop must be IPv4 for version %s: %s", idx, version, route.NextHop)
		}
	}

	// Validate IPv4 route address is a network address, not a broadcast.
	if route.IPAddr == "255.255.255.255" {
		return fmt.Errorf("route[%d]: broadcast address cannot be used as route", idx)
	}

	return nil
}

// getVersionByte returns the version byte for RIP header.
func getVersionByte(version string) uint8 {
	switch version {
	case "v1":
		return VersionRIP
	case "v2":
		return VersionRIPv2
	case "ng":
		return VersionRIPng
	default:
		return VersionRIPv2
	}
}

// getDstIP returns the destination IP based on version and multicast setting.
func getDstIP(version string, multicast bool, userDstIP string) string {
	if multicast {
		switch version {
		case "v1":
			return "255.255.255.255" // v1 only supports broadcast
		case "v2":
			return "224.0.0.9"
		case "ng":
			return "FF02::9"
		}
	}
	if userDstIP != "" {
		return userDstIP
	}
	// v1 traditional behavior: broadcast even when multicast=false
	// (design §6.4 / R-3-MED-5).
	if version == "v1" {
		return "255.255.255.255"
	}
	if version == "ng" {
		return "FF02::9"
	}
	// v2 without explicit DstIP falls back to the default multicast group,
	// matching the default scenario behavior.
	return "224.0.0.9"
}

// getDstPort returns the destination port based on version.
func getDstPort(version string) uint16 {
	if version == "ng" {
		return PortRIPng
	}
	return PortRIP
}

// filterRoutes applies Split Horizon and Poison Reverse filtering.
func filterRoutes(routes []RIPRoute, dstIP string, splitHorizon, poisonReverse bool) []RIPRoute {
	if !splitHorizon && !poisonReverse {
		return routes
	}

	// Compare parsed IPs instead of raw strings so equivalent textual forms
	// (e.g. "192.168.1.2" vs "192.168.1.02") still match.
	dst := net.ParseIP(dstIP)

	filtered := make([]RIPRoute, 0, len(routes))
	for _, route := range routes {
		if route.NextHop != "" && dst != nil && net.ParseIP(route.NextHop).Equal(dst) {
			if poisonReverse {
				// Poison reverse: set metric to 16
				route.Metric = 16
				filtered = append(filtered, route)
			}
			// Split horizon without poison reverse: skip
			continue
		}
		filtered = append(filtered, route)
	}
	return filtered
}

// randomIPID returns a random 16-bit IP ID.
func randomIPID() uint16 {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0x1234
	}
	return binary.BigEndian.Uint16(b)
}

// Plan generates packet configs for a RIP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	cfg := spec.RIP
	if cfg == nil {
		// P0b-2：空配置默认化（Generate 同款：v2 response_default）。写回
		// spec.RIP——emitRIPPacket 直接读 spec.RIP.Auth。
		cfg = &core.RIPConfig{Version: "v2"}
		spec.RIP = cfg
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		select {
		case <-ctx.Done():
			return
		default:
		}

		version := versionFromString(cfg.Version)

		cmd := uint8(CommandResponse)
		if cfg.Command != "" {
			cmd, _ = commandFromString(cfg.Command)
		}

		// request_full is a fixed request+response sequence; TriggeredUpdate
		// only affects ordinary scenarios and cannot cancel it (design §6.1
		// priority: Scenario > Command > TriggeredUpdate, R-3-HIGH-3).
		triggered := cfg.TriggeredUpdate && cfg.Scenario != "request_full"
		if triggered {
			cmd = CommandResponse
		}

		// Scenario derivation (design §3/§6.1): only when Routes is empty.
		scenario := cfg.Scenario
		if scenario == "" && len(cfg.Routes) == 0 {
			if cmd == CommandRequest {
				scenario = "request_full"
			} else {
				scenario = "response_default"
			}
		}

		// Effective routes. nil (field absent) means "use the scenario default"
		// (T-POS-18/T-EDGE-20); an explicit empty slice means "zero routes"
		// and yields a bare 4-byte header response (T-EDGE-6/T-POS-19).
		routes := cfg.Routes
		if routes == nil {
			if scenario == "response_default" {
				routes = defaultRoutes
			}
			// request_full: the Request packet uses the builder-generated
			// special entry (routes stays nil); the auto-Response falls back
			// to defaultRoutes in its own branch below.
		}

		// Routers: empty Routers means a single router using the FlowSpec's
		// own 4-tuple (design §6.14 T-EDGE-21).
		routers := cfg.Routers
		if len(routers) == 0 {
			routers = []RIPRouter{{}}
		}

		rounds := cfg.Rounds
		if rounds <= 0 {
			rounds = 1
		}

		// Process each router: each router gets its own independent 4-tuple,
		// FlowID (with router index), and per-router packet index / IPID.
		for routerIdx, router := range routers {
			srcIP := router.SrcIP
			if srcIP == "" {
				srcIP = spec.SrcIP
			}
			dstIP := router.DstIP
			if dstIP == "" {
				dstIP = spec.DstIP
			}
			srcPort := router.SrcPort
			if srcPort == 0 {
				srcPort = spec.SrcPort
			}
			dstPort := router.DstPort
			if dstPort == 0 {
				dstPort = spec.DstPort
			}

			// Multicast destination (design §8.3): multicast overrides DstIP;
			// otherwise use the user DstIP or the version default.
			multicast := cfg.Multicast
			effectiveDstIP := getDstIP(version, multicast, dstIP)
			if effectiveDstIP == "" {
				effectiveDstIP = dstIP
			}

			// TTL: multicast/broadcast = 1, unicast = spec.TTL or default.
			ttl := spec.TTL
			if multicast {
				ttl = 1
			} else if ttl == 0 {
				ttl = DefaultTTL
			}

			// DSCP: default CS6 for network-control traffic, user can override.
			dscp := spec.DSCP
			if dscp == 0 {
				dscp = DefaultDSCP
			}

			// Split Horizon / Poison Reverse only apply in unicast; multicast
			// has no concrete receiver so filtering is skipped (design §8.5).
			filteredRoutes := routes
			if !multicast {
				filteredRoutes = filterRoutes(routes, effectiveDstIP, cfg.SplitHorizon, cfg.PoisonReverse)
			}

			// request_full: the router is the requesting host, so its response
			// uses the same 4-tuple (design §6.1 same-direction simulation).
			isRequestingRouter := scenario == "request_full" && cmd == CommandRequest
			if srcPort == 0 {
				srcPort = resolveSrcPort(version, srcPort, !isRequestingRouter, len(routers) > 1, routerIdx)
			}
			if dstPort == 0 {
				dstPort = getDstPort(version)
			}

			flowID := fmt.Sprintf("%s-%s-%d-%d", srcIP, effectiveDstIP, srcPort, dstPort)
			if len(routers) > 1 {
				flowID = fmt.Sprintf("router%d-%s", routerIdx, flowID)
			}

			now := time.Now()
			ipID := randomIPID()
			nextIPID := func() uint16 {
				id := ipID
				ipID++
				return id
			}

			// request_full: Request + automatically appended Response on the
			// same 4-tuple, shared FlowID, PacketIndex 0/1... (design §6.1,
			// T-POS-1b). Both packets are independent RIP messages, so auth
			// applies to both (the Request's auth entry includes the request
			// entry in its Packet Length).
			if scenario == "request_full" && cmd == CommandRequest {
				// Request packet: the special request entry (AFI=0, metric=16).
				p.emitRIPPacket(configChan, ctx, version, CommandRequest, cfg.Domain,
					srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
					nil, flowID, 0, now, nextIPID, spec, true, true)

				// Auto Response: user routes when present, else the default
				// 5 routes (design §6.1 priority: Routes > default).
				responseRoutes := filteredRoutes
				if len(responseRoutes) == 0 {
					responseRoutes = defaultRoutes
				}
				packetIndex := uint64(1)
				p.emitRIPRoutes(configChan, ctx, version, CommandResponse, cfg.Domain,
					srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
					responseRoutes, cfg.Auth, flowID, &packetIndex, now, nextIPID, spec, true)
				continue
			}

			// Ordinary scenario: send per round; each round is an independent
			// RIP Response message and carries its own auth entry on its first
			// packet (design §5.3, T-POS-7).
			packetIndex := uint64(0)
			for r := 0; r < rounds; r++ {
				p.emitRIPRoutes(configChan, ctx, version, cmd, cfg.Domain,
					srcIP, effectiveDstIP, srcPort, dstPort, ttl, dscp,
					filteredRoutes, cfg.Auth, flowID, &packetIndex, now, nextIPID, spec, true)
			}
		}
	}()

	return configChan, nil
}

// resolveSrcPort computes the source port when neither the router nor the
// FlowSpec set one explicitly.
//
// Priority (design §2.7/§6.13):
//  1. explicit router/FlowSpec SrcPort (handled by the caller);
//  2. Response packets use the well-known port 520/521 (RFC 2453 §3.6);
//  3. Request packets use ephemeral ports;
//  4. multi-router: each router gets 52001+routerIdx so the 4-tuple can
//     distinguish routers and PacketWorker can keep per-4-tuple ordering
//     (trafficgen-specific non-RFC behavior, design §6.13).
func resolveSrcPort(version string, userSrcPort uint16, isResponse bool, multiRouter bool, routerIdx int) uint16 {
	if userSrcPort != 0 {
		return userSrcPort
	}
	if isResponse && !multiRouter {
		return getDstPort(version)
	}
	return uint16(52001 + routerIdx)
}

// emitRIPRoutes emits RIP packets with the given routes, handling multi-packet
// splitting (max 25 route entries per packet; 24 when the first packet carries
// an auth entry, design §2.8). authFirst controls whether the first packet of
// this batch carries the auth entry (it is true when this batch represents an
// independent RIP message; false only if the batch is a continuation from a
// previous batch on the same sequence — the request_full auto-Response always
// passes true since it is a distinct message).
func (p *Planner) emitRIPRoutes(configChan chan<- core.PacketConfig, ctx context.Context,
	version string, command uint8, domain uint16,
	srcIP, dstIP string, srcPort, dstPort uint16, ttl uint8, dscp uint8,
	routes []RIPRoute, auth *RIPAuth, flowID string, packetIndex *uint64,
	now time.Time, nextIPID func() uint16, spec core.FlowSpec, authFirst bool) {

	// 每个 packet 独立计算 maxRTE：首包因携带 auth entry 最多 24 条路由，
	// 后续包恢复 25 条（RFC 4822 §2.1: MD5 trailer 仅出现在首包）。
	// 修复 B-17：之前 maxRTE 在循环外一次性计算，导致后续包也被限制为 24。
	// 步进量使用本次实际发射的路由数（pktMaxRTE），避免与 end 计算不一致。
	if len(routes) == 0 {
		p.emitRIPPacket(configChan, ctx, version, command, domain,
			srcIP, dstIP, srcPort, dstPort, ttl, dscp, nil, flowID,
			*packetIndex, now, nextIPID, spec, false, authFirst)
		(*packetIndex)++
		return
	}

	for start := 0; start < len(routes); {
		// Auth entry (and MD5 trailer) only in the first packet of a
		// multi-packet message (RFC 4822 §2.1, design §2.8.2 / T-POS-31).
		isFirstPacket := authFirst && start == 0
		// 首包有 auth entry 时限 24 条；后续包恢复 25 条
		pktMaxRTE := MaxRTEPerPacket
		if isFirstPacket && auth != nil {
			pktMaxRTE = MaxRTEPerPacket - 1
		}
		end := start + pktMaxRTE
		if end > len(routes) {
			end = len(routes)
		}
		p.emitRIPPacket(configChan, ctx, version, command, domain,
			srcIP, dstIP, srcPort, dstPort, ttl, dscp, routes[start:end], flowID,
			*packetIndex, now, nextIPID, spec, false, isFirstPacket)
		(*packetIndex)++
		start = end
	}
}

// emitRIPPacket emits a single RIP packet.
func (p *Planner) emitRIPPacket(configChan chan<- core.PacketConfig, ctx context.Context,
	version string, command uint8, domain uint16,
	srcIP, dstIP string, srcPort, dstPort uint16, ttl uint8, dscp uint8,
	routes []RIPRoute, flowID string, packetIndex uint64, now time.Time,
	nextIPID func() uint16, spec core.FlowSpec, isRequestFull bool, isFirstPacket bool) {

	// Use builder to construct the packet payload.
	// The auth entry and the MD5 trailer appear only in the first packet of a
	// multi-packet split (RFC 4822 §2.1; design §2.8.2 / T-POS-31).
	payload := BuildRIPPacket(version, command, domain, routes, spec.RIP.Auth, isRequestFull, isFirstPacket)

	// EtherType derived from srcIP: IPv6 for ng, IPv4 otherwise.
	etherType := core.EtherTypeFor(srcIP)

	// Build PacketConfig
	cfg := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: packetIndex,
		Direction:   "up",
		Timestamp:   now,
		L2: core.L2Config{
			SrcMAC:    spec.SrcMAC,
			DstMAC:    spec.DstMAC,
			EtherType: etherType,
		},
		L3: core.L3Base(srcIP, dstIP, 17, ttl, nextIPID(), spec),
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  srcPort,
			DstPort:  dstPort,
		},
		Payload: payload,
	}

	select {
	case configChan <- cfg:
	case <-ctx.Done():
	}
}
