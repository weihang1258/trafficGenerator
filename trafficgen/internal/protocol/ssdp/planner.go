// Package ssdp implements the SSDP (Simple Service Discovery Protocol,
// 简单服务发现协议) planner.
//
// SSDP (Simple Service Discovery Protocol, 简单服务发现协议) is the discovery
// layer of UPnP (Universal Plug and Play, 通用即插即用), carrying HTTP-formatted
// text over UDP port 1900 to either IPv4 multicast 239.255.255.250 or IPv6
// multicast ff02::c.
//
// The planner generates NOTIFY (device announce/bye/update, sent to the
// multicast group), M-SEARCH (control point search, sent to the multicast
// group, with singlecast 200 OK responses), or standalone 200 OK responses.
// Each message is a self-contained UDP datagram — there is no TCP-style state
// machine, no connection, no keep-alive. SSDP borrows HTTP/1.1 message syntax
// only (request/status line + CRLF-terminated headers + blank line + body);
// HTTP semantics (chunked, keep-alive, 100-continue) do NOT apply.
//
// Wire format per design §2:
// - NOTIFY (multicast advertisement):
// NOTIFY * HTTP/1.1\r\nHOST: ...\r\nNT: ...\r\nNTS: ...\r\nUSN: ...\r\n\r\n
// - M-SEARCH (multicast search):
// M-SEARCH * HTTP/1.1\r\nHOST: ...\r\nMAN: "ssdp:discover"\r\nMX: ...\r\nST: ...\r\n\r\n
// - M-SEARCH response (unicast):
// HTTP/1.1 200 OK\r\nCACHE-CONTROL: ...\r\nEXT:\r\nLOCATION: ...\r\nST: ...\r\nUSN: ...\r\n\r\n
package ssdp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL is the IP TTL applied when FlowSpec.TTL is 0.
	// SSDP uses TTL=4 per RFC draft-cai-ssdp-v1-03 §6.2 to prevent
	// multicast packets from crossing routers.
	DefaultTTL = 4

	// DefaultPort is the IANA-assigned SSDP service port (1900).
	// Both IPv4 multicast 239.255.255.250 and IPv6 multicast ff02::c
	// use this port.
	DefaultPort = 1900

	// DefaultMaxAge is the default Cache-Control max-age value (1800 seconds =
	// 30 minutes per UPnP DA 1.1 §1.2.2).
	DefaultMaxAge = 1800

	// DefaultMX is the default MX (Maximum Wait Time) value for M-SEARCH
	// (3 seconds per UPnP DA 1.1 §1.3).
	DefaultMX = 3

	// DefaultResponseCount is the default number of 200 OK responses to emit
	// for an M-SEARCH when ResponseCount is 0 or 1.
	DefaultResponseCount = 1

	// DefaultResponseDelayMinMs is the default minimum response delay (0ms).
	DefaultResponseDelayMinMs = 0

	// DefaultResponseDelayMaxMs maps MX=3 default to 3000ms.
	DefaultResponseDelayMaxMs = 3000

	// IPv4MulticastGroup is the default SSDP IPv4 multicast group.
	IPv4MulticastGroup = "239.255.255.250"

	// IPv6MulticastGroup is the default SSDP IPv6 multicast group.
	IPv6MulticastGroup = "ff02::c"

	// ServerHeaderMaxWarning is the recommended Server header length limit
	// (256 bytes). Exceeding this triggers a Validate warning.
	ServerHeaderMaxWarning = 256

	// ServerHeaderMaxError is the hard Server header length limit (4096 bytes).
	// Exceeding this triggers a Validate error.
	ServerHeaderMaxError = 4096

	// USNMaxSize is the maximum allowed USN header size (4096 bytes).
	USNMaxSize = 4096
)

// Planner implements the SSDP protocol planner.
type Planner struct{}

// NewPlanner creates a new SSDP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "ssdp" }

// validateSSDPConfig validates the SSDP protocol config (单一实现：链层
// 校验器与 legacy Planner.Validate 共用，杜绝双份拷贝漂移——178-green
// 事故教训)。只校验不默认化。
func validateSSDPConfig(cfg core.SSDPConfig) error {
	// MessageType (消息类型) is required.
	if cfg.MessageType == "" {
		return fmt.Errorf("ssdp message_type is required")
	}
	switch cfg.MessageType {
	case "alive", "byebye", "update", "msearch", "response":
		// valid
	default:
		return fmt.Errorf("ssdp unknown message_type: %s", cfg.MessageType)
	}

	// SearchTarget (搜索目标) is required for all types.
	if cfg.SearchTarget == "" {
		if cfg.MessageType == "msearch" {
			return fmt.Errorf("ssdp st (search_target) is required for msearch")
		}
		return fmt.Errorf("ssdp nt (search_target) is required for %s", cfg.MessageType)
	}

	// USN (唯一服务名) is required for NOTIFY and response.
	switch cfg.MessageType {
	case "alive", "byebye", "update", "response":
		if cfg.USN == "" {
			return fmt.Errorf("ssdp usn is required for %s", cfg.MessageType)
		}
	}

	// USN size limit.
	if len(cfg.USN) > USNMaxSize {
		return fmt.Errorf("ssdp usn exceeds maximum header size %d", USNMaxSize)
	}

	// Server header length validation.
	if len(cfg.Server) > ServerHeaderMaxError {
		return fmt.Errorf("ssdp server header exceeds maximum %d bytes", ServerHeaderMaxError)
	}

	// MaxAge validation (only for alive).
	if cfg.MessageType == "alive" {
		if cfg.MaxAge > 1800 {
			return fmt.Errorf("ssdp max-age exceeds UPnP 1.1 limit (1800)")
		}
		if cfg.MaxAge < 0 {
			return fmt.Errorf("ssdp max-age must be >= 1 (use 0 for default 1800)")
		}
	}

	// MX validation (only for msearch).
	if cfg.MessageType == "msearch" {
		if cfg.MX > 5 {
			return fmt.Errorf("ssdp mx exceeds UPnP recommended max (5)")
		}
		if cfg.MX < 0 {
			return fmt.Errorf("ssdp mx must be >= 1 (use 0 for default 3)")
		}
	}

	// ResponseDelay validation.
	if cfg.MessageType == "msearch" && cfg.ResponseCount > 1 {
		if cfg.ResponseDelayMinMs > cfg.ResponseDelayMaxMs {
			return fmt.Errorf("ssdp response_delay_min_ms (%d) > response_delay_max_ms (%d)",
				cfg.ResponseDelayMinMs, cfg.ResponseDelayMaxMs)
		}
		if cfg.ResponseDelayMaxMs > int(^uint32(0)>>1) {
			return fmt.Errorf("ssdp response delay exceeds mx")
		}
	}

	return nil
}

// Validate validates an SSDP flow spec. Read-only: never modifies spec.
// 协议级校验委托 validateSSDPConfig（单一实现：链层校验器与 legacy
// Planner 共用，杜绝双份拷贝漂移——178-green 事故教训）。
// Spec 级检查（IP parse、端口）保留于此：legacy Plan 前直校验 spec 原值
// （端口 0=未设置），链层 validateSpecBase 先默认化端口再调协议校验器。
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("ssdp: SrcIP %q is not a valid IP address", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("ssdp: DstIP %q is not a valid IP address", spec.DstIP)
	}
	if spec.SSDP == nil {
		return fmt.Errorf("ssdp: SSDP config is required (set spec.ssdp)")
	}
	if err := validateSSDPConfig(*spec.SSDP); err != nil {
		return err
	}

	// Port validation: SSDP requires dst_port=1900.
	if spec.DstPort != 0 && spec.DstPort != DefaultPort {
		return fmt.Errorf("ssdp destination port must be 1900")
	}
	// SrcPort validation: only 1900 or 0 (ephemeral) allowed.
	if spec.SrcPort != 0 && spec.SrcPort != DefaultPort {
		return fmt.Errorf("ssdp source port must be 1900 or ephemeral (0)")
	}

	return nil
}

// Plan generates packet configs for an SSDP flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)

		cfg := spec.SSDP

		// Effective defaults (applied here, not in Validate, per conventions).
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// ipID (IP标识) starts at a random value and increments per packet.
		ipID := uint16(rand.Uint32())

		// Determine multicast group (多播组) and host header.
		multicastGroup := cfg.MulticastGroup
		if multicastGroup == "" {
			if net.ParseIP(spec.SrcIP) != nil && net.ParseIP(spec.SrcIP).To4() == nil {
				multicastGroup = IPv6MulticastGroup
			} else {
				multicastGroup = IPv4MulticastGroup
			}
		}

		// Determine the effective destination IP.
		dstIP := spec.DstIP
		if dstIP == "" {
			dstIP = multicastGroup
		}

		// Determine the effective destination port.
		dstPort := spec.DstPort
		if dstPort == 0 {
			dstPort = DefaultPort
		}

		// Determine the effective source port.
		srcPort := spec.SrcPort
		if srcPort == 0 {
			srcPort = DefaultPort
		}

		// Build the host header value (RFC 3986 §3.2.2 for IPv6 literal).
		hostHeader := buildHostHeader(multicastGroup, dstPort)

		// FlowID (流标识) for all packets in this flow.
		flowID := fmt.Sprintf("ssdp-%s-%s-%d-%d", spec.SrcIP, dstIP, srcPort, dstPort)

		packetIndex := uint64(0)

		// resolveMulticastMAC derives the multicast MAC address from the
		// destination IP, per RFC 1112 §6.4 (IPv4) and RFC 2464 §7 (IPv6).
		// Returns empty string if the IP is not a multicast address or if
		// spec.DstMAC is already set (user override).
		resolveMulticastMAC := func(ip string) string {
			if spec.DstMAC != "" {
				// Normalize: check if the MAC is all zeros (not a user-set value).
				normalized := strings.ToLower(strings.ReplaceAll(spec.DstMAC, ":", ""))
				if normalized != "000000000000" {
					return spec.DstMAC
				}
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return ""
			}
			if parsed.To4() != nil {
				// IPv4 multicast: 224.0.0.0/4
				// RFC 1112 §6.4: MAC = 01:00:5e | (IP low 23 bits)
				ip4 := parsed.To4()
				if ip4[0] >= 224 && ip4[0] <= 239 {
					// Extract low 23 bits of the IP.
					// IP bytes: b0 b1 b2 b3
					// Low 23 bits: b1 & 0x7f, b2, b3
					low23 := (uint32(ip4[1]&0x7f) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
					return fmt.Sprintf("01:00:5e:%02x:%02x:%02x",
						byte(low23>>16), byte(low23>>8), byte(low23))
				}
				return ""
			}
			// IPv6 multicast: ff00::/8
			// RFC 2464 §7: MAC = 33:33 | (IP low 32 bits)
			if len(parsed) == 16 && parsed[0] == 0xff {
				low32 := (uint32(parsed[12]) << 24) | (uint32(parsed[13]) << 16) |
					(uint32(parsed[14]) << 8) | uint32(parsed[15])
				return fmt.Sprintf("33:33:%02x:%02x:%02x:%02x",
					byte(low32>>24), byte(low32>>16), byte(low32>>8), byte(low32))
			}
			return ""
		}

		// emitWithIndex sends a packet with the current packetIndex and
		// increments it.
		emitWithIndex := func(payload []byte, direction string, dmac string, dip string, dport uint16) bool {
			etherType := core.EtherTypeFor(spec.SrcIP)
			l2 := core.L2Config{
				SrcMAC: spec.SrcMAC,
				DstMAC: dmac,
				EtherType: etherType,
			}
			l3 := core.L3Base(spec.SrcIP, dip, 17, effectiveTTL, ipID, spec)
			l4 := core.L4Config{
				Protocol: "udp",
				SrcPort: srcPort,
				DstPort: dport,
			}
			pkt := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: direction,
				Timestamp: time.Now(),
				L2: l2,
				L3: l3,
				L4: l4,
				Payload: payload,
			}
			select {
			case out <- pkt:
				packetIndex++
				ipID++
				return true
			case <-ctx.Done():
				return false
			}
		}

		switch cfg.MessageType {
		case "alive", "byebye", "update":
			repeat := cfg.RepeatCount
			if repeat < 1 {
				repeat = 1
			}
			// Inter-packet delay for repeats (MaxAge/3 seconds, per UPnP 1.1 §1.2.2).
			repeatDelay := time.Duration(0)
			if repeat > 1 {
				if cfg.RepeatIntervalMs > 0 {
					repeatDelay = time.Duration(cfg.RepeatIntervalMs) * time.Millisecond
				} else {
					maxAge := cfg.MaxAge
					if maxAge <= 0 {
						maxAge = DefaultMaxAge
					}
					repeatDelay = time.Duration(maxAge/3) * time.Second
				}
			}
			for i := 0; i < repeat; i++ {
				payload := buildSSDPNotify(cfg, spec, hostHeader, multicastGroup)
				dmac := resolveMulticastMAC(dstIP)
				if !emitWithIndex(payload, "up", dmac, dstIP, dstPort) {
					return
				}
				if i < repeat-1 && repeatDelay > 0 {
					select {
					case <-time.After(repeatDelay):
					case <-ctx.Done():
						return
					}
				}
			}

		case "msearch":
			payload := buildSSDPMSearch(cfg, hostHeader)
			dmac := resolveMulticastMAC(dstIP)
			if !emitWithIndex(payload, "up", dmac, dstIP, dstPort) {
				return
			}

			// Emit ResponseCount singlecast 200 OK responses.
			responseCount := cfg.ResponseCount
			if responseCount < 1 {
				responseCount = DefaultResponseCount
			}
			if responseCount > 1 {
				// Use the response delay range or default.
				minDelay := cfg.ResponseDelayMinMs
				if minDelay <= 0 {
					minDelay = DefaultResponseDelayMinMs
				}
				maxDelay := cfg.ResponseDelayMaxMs
				if maxDelay <= 0 {
					if cfg.MX > 0 {
						maxDelay = cfg.MX * 1000
					} else {
						maxDelay = DefaultResponseDelayMaxMs
					}
				}
				for k := 0; k < responseCount; k++ {
					delay := time.Duration(minDelay+rand.Intn(maxDelay-minDelay+1)) * time.Millisecond
					// Clamp to MX seconds per UPnP 1.1 §1.3.4.
					mxMs := DefaultMX * 1000
					if cfg.MX > 0 {
						mxMs = cfg.MX * 1000
					}
					if delay > time.Duration(mxMs)*time.Millisecond {
						delay = time.Duration(mxMs) * time.Millisecond
					}
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return
					}
					respPayload := buildSSDPResponse(cfg, hostHeader, spec.SrcIP, srcPort)
					// Response is singlecast back to the client.
					if !emitWithIndex(respPayload, "up", "", spec.SrcIP, srcPort) {
						return
					}
				}
			} else if responseCount == 1 {
				// Single response with MX delay.
				mxMs := DefaultMX * 1000
				if cfg.MX > 0 {
					mxMs = cfg.MX * 1000
				}
				delay := time.Duration(rand.Intn(mxMs)) * time.Millisecond
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
				respPayload := buildSSDPResponse(cfg, hostHeader, spec.SrcIP, srcPort)
				if !emitWithIndex(respPayload, "up", "", spec.SrcIP, srcPort) {
					return
				}
			}

		case "response":
			payload := buildSSDPResponse(cfg, hostHeader, spec.SrcIP, srcPort)
			if !emitWithIndex(payload, "up", "", dstIP, dstPort) {
				return
			}
		}
	}()

	return out, nil
}

// buildHostHeader constructs the HOST header value for SSDP messages.
// IPv6 addresses are wrapped in square brackets per RFC 3986 §3.2.2.
func buildHostHeader(host string, port uint16) string {
	parsed := net.ParseIP(host)
	if parsed != nil && parsed.To4() == nil {
		// IPv6 literal with brackets.
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// buildSSDPNotify constructs the NOTIFY message payload for alive/byebye/update.
// Wire format per design §2.2 and §2.4:
//
// NOTIFY * HTTP/1.1\r\n
// HOST: <host>\r\n
// [CACHE-CONTROL: max-age=<N>\r\n] (alive/update, omitted for byebye)
// [LOCATION: <url>\r\n] (alive/update only, if Location is set)
// NT: <search_target>\r\n
// NTS: ssdp:<type>\r\n
// [SERVER: <server>\r\n] (alive only, if Server is set)
// USN: <usn>\r\n
// [BOOTID.UPNP.ORG: <n>\r\n] (alive/update only, if BootID > 0)
// [CONFIGID.UPNP.ORG: <n>\r\n] (alive/update only, if ConfigID > 0)
// [NEXTBOOTID.UPNP.ORG: <n>\r\n] (update only, if NextBootID > 0)
// [SEARCHPORT.UPNP.ORG: <n>\r\n] (update only, if SearchPort > 0)
// \r\n
func buildSSDPNotify(cfg *core.SSDPConfig, spec core.FlowSpec, hostHeader, multicastGroup string) []byte {
	var b strings.Builder

	// Request line (请求行).
	b.WriteString("NOTIFY * HTTP/1.1\r\n")

	// HOST header (多播组地址+端口).
	b.WriteString("HOST: ")
	b.WriteString(hostHeader)
	b.WriteString("\r\n")

	// CACHE-CONTROL: max-age (alive and update per UPnP DA 1.1 §1.2.3 /
	// design §3.3: update carries MAX-AGE as an optional header).
	if cfg.MessageType != "byebye" {
		maxAge := cfg.MaxAge
		if maxAge <= 0 {
			maxAge = DefaultMaxAge
		}
		b.WriteString(fmt.Sprintf("CACHE-CONTROL: max-age=%d\r\n", maxAge))
	}

	// LOCATION header (alive/update, if Location is set).
	if cfg.MessageType != "byebye" && cfg.Location != "" {
		b.WriteString("LOCATION: ")
		b.WriteString(cfg.Location)
		b.WriteString("\r\n")
	}

	// NT header (通知类型).
	b.WriteString("NT: ")
	b.WriteString(cfg.SearchTarget)
	b.WriteString("\r\n")

	// NTS header (通知子类型).
	b.WriteString("NTS: ssdp:")
	b.WriteString(cfg.MessageType)
	b.WriteString("\r\n")

	// SERVER header (alive only, if Server is set).
	if cfg.MessageType == "alive" && cfg.Server != "" {
		b.WriteString("SERVER: ")
		b.WriteString(cfg.Server)
		b.WriteString("\r\n")
	}

	// USN header (唯一服务名).
	b.WriteString("USN: ")
	b.WriteString(cfg.USN)
	b.WriteString("\r\n")

	// BOOTID.UPNP.ORG (alive/update only, if BootID > 0).
	if cfg.MessageType != "byebye" && cfg.BootID > 0 {
		b.WriteString(fmt.Sprintf("BOOTID.UPNP.ORG: %d\r\n", cfg.BootID))
	}

	// CONFIGID.UPNP.ORG (alive/update only, if ConfigID > 0).
	if cfg.MessageType != "byebye" && cfg.ConfigID > 0 {
		b.WriteString(fmt.Sprintf("CONFIGID.UPNP.ORG: %d\r\n", cfg.ConfigID))
	}

	// NEXTBOOTID.UPNP.ORG (update only, if NextBootID > 0).
	// Per UPnP DA 1.1 §1.2.3: ssdp:update carries NEXTBOOTID to indicate
	// the new boot ID when it changes during the configuration update.
	if cfg.MessageType == "update" && cfg.NextBootID > 0 {
		b.WriteString(fmt.Sprintf("NEXTBOOTID.UPNP.ORG: %d\r\n", cfg.NextBootID))
	}

	// SEARCHPORT.UPNP.ORG (update only, if SearchPort > 0).
	// Per UPnP DA 1.1 §1.2.3: ssdp:update carries SEARCHPORT to indicate
	// the port on which the device listens for M-SEARCH after the update.
	if cfg.MessageType == "update" && cfg.SearchPort > 0 {
		b.WriteString(fmt.Sprintf("SEARCHPORT.UPNP.ORG: %d\r\n", cfg.SearchPort))
	}

	// Empty line (头结束标记).
	b.WriteString("\r\n")

	return []byte(b.String())
}

// buildSSDPMSearch constructs the M-SEARCH message payload.
// Wire format per design §2.2 and §2.4:
//
// M-SEARCH * HTTP/1.1\r\n
// HOST: <host>\r\n
// MAN: "ssdp:discover"\r\n
// MX: <n>\r\n
// ST: <search_target>\r\n
// [USER-AGENT: <server>\r\n] (if Server is set)
// \r\n
func buildSSDPMSearch(cfg *core.SSDPConfig, hostHeader string) []byte {
	var b strings.Builder

	// Request line (请求行).
	b.WriteString("M-SEARCH * HTTP/1.1\r\n")

	// HOST header.
	b.WriteString("HOST: ")
	b.WriteString(hostHeader)
	b.WriteString("\r\n")

	// MAN header (固定值 "ssdp:discover").
	b.WriteString("MAN: \"ssdp:discover\"\r\n")

	// MX header (最大等待时间).
	mx := cfg.MX
	if mx <= 0 {
		mx = DefaultMX
	}
	b.WriteString(fmt.Sprintf("MX: %d\r\n", mx))

	// ST header (搜索目标).
	b.WriteString("ST: ")
	b.WriteString(cfg.SearchTarget)
	b.WriteString("\r\n")

	// USER-AGENT header (if Server is set).
	if cfg.Server != "" {
		b.WriteString("USER-AGENT: ")
		b.WriteString(cfg.Server)
		b.WriteString("\r\n")
	}

	// Empty line (头结束标记).
	b.WriteString("\r\n")

	return []byte(b.String())
}

// buildSSDPResponse constructs the M-SEARCH 200 OK response payload.
// Wire format per design §2.2 and §2.4:
//
// HTTP/1.1 200 OK\r\n
// CACHE-CONTROL: max-age=<N>\r\n
// [DATE: <date>\r\n] (if Date is set)
// EXT:\r\n (UPnP 1.1 §1.3 mandatory, unless OmitExt=true)
// LOCATION: <url>\r\n (if Location is set)
// SERVER: <server>\r\n (if Server is set)
// ST: <search_target>\r\n
// USN: <usn>\r\n
// [CONTENT-LENGTH: <n>\r\n] (if EmitContentLength and Body is non-empty)
// \r\n
// [body] (if Body is non-empty)
func buildSSDPResponse(cfg *core.SSDPConfig, hostHeader, clientIP string, clientPort uint16) []byte {
	var b strings.Builder

	// Status line (状态行).
	b.WriteString("HTTP/1.1 200 OK\r\n")

	// CACHE-CONTROL: max-age.
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	b.WriteString(fmt.Sprintf("CACHE-CONTROL: max-age=%d\r\n", maxAge))

	// DATE header (if Date is set).
	if cfg.Date != "" {
		b.WriteString("DATE: ")
		b.WriteString(cfg.Date)
		b.WriteString("\r\n")
	}

	// EXT header (UPnP 1.1 §1.3 mandatory, empty value).
	if !cfg.OmitExt {
		b.WriteString("EXT:\r\n")
	}

	// LOCATION header (if Location is set).
	if cfg.Location != "" {
		b.WriteString("LOCATION: ")
		b.WriteString(cfg.Location)
		b.WriteString("\r\n")
	}

	// SERVER header (if Server is set).
	if cfg.Server != "" {
		b.WriteString("SERVER: ")
		b.WriteString(cfg.Server)
		b.WriteString("\r\n")
	}

	// ST header (搜索目标).
	b.WriteString("ST: ")
	b.WriteString(cfg.SearchTarget)
	b.WriteString("\r\n")

	// USN header (唯一服务名).
	b.WriteString("USN: ")
	b.WriteString(cfg.USN)
	b.WriteString("\r\n")

	// Content-Length (if EmitContentLength and Body is non-empty).
	if cfg.EmitContentLength && cfg.Body != "" {
		b.WriteString(fmt.Sprintf("CONTENT-LENGTH: %d\r\n", len(cfg.Body)))
	}

	// Empty line (头结束标记).
	b.WriteString("\r\n")

	// Body (if non-empty).
	if cfg.Body != "" {
		b.WriteString(cfg.Body)
	}

	return []byte(b.String())
}