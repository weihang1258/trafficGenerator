// Package http implements the HTTP protocol planner.
package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
	// DefaultMSS is the default TCP Maximum Segment Size used when MSS is 0.
	// Same value as internal/protocol/tcp.DefaultMSS (1460) — duplicated here
	// to avoid an import cycle (tcp imports core, not http). RFC 879 floor
	// is 536; 1460 is the Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS is the minimum acceptable MSS per RFC 879 (IP+TCP header 20+20
	// +536 = 576-byte minimum packet). Smaller values produce malformed
	// frames or pathological fragmentation.
	MinMSS = 536
)

// Planner implements the HTTP protocol planner.
type Planner struct{}

// NewPlanner creates a new HTTP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "http"
}

// Validate validates an HTTP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// Validate IP addresses
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

	// Validate ports
	if spec.DstPort == 0 {
		spec.DstPort = 80 // Default HTTP port
	}

	// Validate MSS range. RFC 879: minimum MSS is 536 (IP+TCP header 20+20
	// +536 = 576-byte minimum packet). uint16 max is 65535. Out-of-range
	// MSS produces malformed SYNs or pathological fragmentation.
	// MSS is a TCP transport parameter; it lives on TCPConfig (spec.TCP.MSS).
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	return nil
}

// Plan generates packet configs for an HTTP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Get HTTP config
		httpConfig := spec.HTTP
		if httpConfig == nil {
			httpConfig = &core.HTTPConfig{
				Method:       "GET",
				URI:          "/",
				ResponseBody: "OK",
			}
		}

		transactions := httpConfig.Transactions
		if transactions <= 0 {
			transactions = 1
		}

		// Resolve effective TTL from spec
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())

		// Initialize sequence numbers. Random per flow to avoid seq collisions
		// across flows (real TCP randomizes ISN per RFC 6528). User can override
		// client seq via spec.TCP.InitialSeq for reproducible tests.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Resolve MSS: 0 -> DefaultMSS (1460). MSS is a TCP transport
		// parameter; it lives on TCPConfig (spec.TCP.MSS). The same value
		// drives both SYN/SYN-ACK option emission and response/request
		// segmentation, so the advertised MSS matches what the planner
		// actually emits on the wire.
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		// TCP Handshake
		// SYN
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.SrcPort,
				DstPort:    spec.DstPort,
				Seq:        clientSeq,
				Flags:      0x02, // SYN
				WindowSize: 65535,
				TCPOptions: synOpts,
			},
		}
		packetIndex++
		clientSeq++

		// SYN-ACK
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "down",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.DstMAC,
				DstMAC:    spec.SrcMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.DstPort,
				DstPort:    spec.SrcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      0x12, // SYN-ACK
				WindowSize: 65535,
				TCPOptions: synOpts,
			},
		}
		packetIndex++
		serverSeq++

		// ACK (completes 3-way handshake)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.SrcPort,
				DstPort:    spec.DstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      0x10, // ACK
				WindowSize: 65535,
			},
		}
		packetIndex++

		// HTTP Transactions (keep-alive: multiple request/response pairs in one TCP connection)
		// Pre-decode bodies once before the loop so base64 (BodyB64/ResponseBodyB64)
		// is not re-decoded on every iteration.
		//
		// FileSource resolution (Task 12): when httpConfig.FileSource is
		// set, the resolved bytes override the inline Body/BodyB64 fields.
		// We mutate httpConfig.Body / BodyB64 ONCE here (before the
		// transaction loop) so buildHTTPRequestBody sees the resolved
		// bytes on every iteration. The resolution precedence:
		//  1. httpConfig.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *httpConfig.FileSource)
		//     - bytes go into Body (text, via core.IsText) or BodyB64 (binary)
		//  2. else inline Body / BodyB64 (unchanged behavior)
		//
		// When FileSource is set but no cache is injected, we leave the
		// inline fields untouched (do NOT silently fall through to Body).
		// This is the "do not override user-set Body" caveat from the
		// brief: it applies when FileSource is nil — don't override
		// user-set Body with empty bytes. When FileSource is non-nil,
		// FileSource wins (matches FTP precedence). Production engine
		// (Task 13) always injects the cache.
		if httpConfig.FileSource != nil {
			pc := core.PayloadCacheFrom(ctx)
			if pc != nil {
				if bytes, err := pc.GetOrLoad(ctx, *httpConfig.FileSource); err == nil {
					if core.IsText(bytes) {
						httpConfig.Body = string(bytes)
						httpConfig.BodyB64 = "" // text wins over b64 when FileSource resolves
					} else {
						httpConfig.BodyB64 = base64.StdEncoding.EncodeToString(bytes)
						httpConfig.Body = "" // b64 wins over text for binary bytes
					}
				}
			}
		}
		requestBody := resolveRequestBody(httpConfig)
		responseBody := resolveResponseBody(httpConfig)
		for i := 0; i < transactions; i++ {
			// HTTP Request — segment by MSS. Symmetric to the response path:
			// a 4000-byte request body over MSS=1460 becomes 3 segments
			// (1460+1460+1080). Each segment advances clientSeq by its
			// payload length, so the next transaction's response ACKs all
			// request bytes. Small requests (the common case <MSS) produce
			// a single segment, matching the captured samples and the
			// pre-segmentation behavior.
			request := buildHTTPRequestBody(httpConfig, spec.DstIP, requestBody)
			for _, seg := range segmentByMSS([]byte(request), int(mss)) {
				configChan <- core.PacketConfig{
					FlowID:      flowID,
					PacketIndex: packetIndex,
					Direction:   "up",
					Timestamp:   now,
					L2: core.L2Config{
						SrcMAC:    spec.SrcMAC,
						DstMAC:    spec.DstMAC,
						EtherType: core.EtherTypeFor(spec.SrcIP),
					},
					L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
					L4: core.L4Config{
						Protocol:   "tcp",
						SrcPort:    spec.SrcPort,
						DstPort:    spec.DstPort,
						Seq:        clientSeq,
						Ack:        serverSeq,
						Flags:      0x18, // PSH-ACK
						WindowSize: 65535,
					},
					Payload: seg,
				}
				packetIndex++
				clientSeq += uint32(len(seg))
			}

			// HTTP Response — segment by MSS. A 3066-byte response over
			// MSS=1460 becomes 3 segments (1460 + 1460 + 146). Intermediate
			// segments are PSH-ACK (matching the captured samples); the
			// final segment is PSH-ACK as well. Each segment advances
			// serverSeq by its payload length, so the next transaction's
			// request ACKs all response bytes.
			response := buildHTTPResponseBody(httpConfig, responseBody)
			for _, seg := range segmentByMSS([]byte(response), int(mss)) {
				configChan <- core.PacketConfig{
					FlowID:      flowID,
					PacketIndex: packetIndex,
					Direction:   "down",
					Timestamp:   now,
					L2: core.L2Config{
						SrcMAC:    spec.DstMAC,
						DstMAC:    spec.SrcMAC,
						EtherType: core.EtherTypeFor(spec.SrcIP),
					},
					L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
					L4: core.L4Config{
						Protocol:   "tcp",
						SrcPort:    spec.DstPort,
						DstPort:    spec.SrcPort,
						Seq:        serverSeq,
						Ack:        clientSeq,
						Flags:      0x18, // PSH-ACK
						WindowSize: 65535,
					},
					Payload: seg,
				}
				packetIndex++
				serverSeq += uint32(len(seg))
			}
		}

		// TCP Termination (FIN, ACK, FIN, ACK)
		// FIN (client)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.SrcPort,
				DstPort:    spec.DstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      0x11, // FIN-ACK
				WindowSize: 65535,
			},
		}
		packetIndex++
		clientSeq++

		// ACK (server acknowledges client FIN)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "down",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.DstMAC,
				DstMAC:    spec.SrcMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.DstPort,
				DstPort:    spec.SrcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      0x10, // ACK
				WindowSize: 65535,
			},
		}
		packetIndex++

		// FIN (server)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "down",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.DstMAC,
				DstMAC:    spec.SrcMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.DstPort,
				DstPort:    spec.SrcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      0x11, // FIN-ACK
				WindowSize: 65535,
			},
		}
		packetIndex++
		serverSeq++

		// ACK (client acknowledges server FIN)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.SrcPort,
				DstPort:    spec.DstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      0x10, // ACK
				WindowSize: 65535,
			},
		}
	}()

	return configChan, nil
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Caller is responsible for ensuring mss >= MinMSS (validated upstream).
// We do not cap mss here — the SYN advertises whatever the user asked for,
// and segmentation must match.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		// Defensive: should never happen — caller resolves 0 -> DefaultMSS
		// before invoking. Fall back to one segment to avoid an infinite
		// loop on bad input.
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

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted, matching real-world SYN capture characteristics. Mirrors
// internal/protocol/tcp.synOptions — duplicated here to avoid an import
// cycle (tcp already imports core; http importing tcp would create a
// dependency we don't need elsewhere).
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	// Window Scale option (RFC 7323): shift count 7 expands the 16-bit
	// window field to 65535 << 7 = ~8MB, enough for high-bandwidth paths.
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// buildHTTPRequest builds an HTTP request string. dstIP is the fallback Host
// when RequestHeaders does not contain a Host entry.
//
// Defaulting follows the unified rule (user > default > none) for every
// output field:
//
//   - Method: empty -> "GET"
//   - URI: empty -> "/"
//   - Version: empty -> "HTTP/1.1"
//   - Host: not user-provided + Version=HTTP/1.1 -> dstIP
//     (HTTP/1.0 does not mandate Host, so none is emitted)
//   - Content-Type: not user-provided + Body non-empty -> sniffed from body
//     (text: HTML/XML/JSON/plain; binary: magic bytes; fallback text/plain)
//   - Content-Length: not user-provided + Body non-empty -> len(Body)
//   - Connection: not user-provided -> "keep-alive" if Transactions>1 or
//     KeepAlive=true, else "close"
//
// Body source: BodyB64 (base64) takes precedence over Body (string) when set,
// so binary payloads (PNG/JPEG/PDF/ZIP/...) can be carried via BodyB64. The
// decoded bytes feed Content-Length, Content-Type sniffing, gzip compression,
// and MSS segmentation. A string Body still works for text payloads.
//
// When RequestContentEncoding == "gzip", Body is gzip-compressed (RFC 1952);
// the compressed bytes replace the body, Content-Length reflects the
// compressed byte count, and a "Content-Encoding: gzip" header is emitted
// (still overridable via RequestHeaders, case-insensitive per RFC 7230 §3.2).
// Any RequestContentEncoding value other than "" or "gzip" is treated as a
// literal header value passed through to Content-Encoding without
// transformation (caller responsibility — only "gzip" triggers actual
// compression here). Symmetric to buildHTTPResponse's response-side gzip.
//
// User-provided RequestHeaders are emitted verbatim and suppress the
// corresponding default (case-insensitive match per RFC 7230 §3.2).
func buildHTTPRequest(config *core.HTTPConfig, dstIP string) string {
	return buildHTTPRequestBody(config, dstIP, resolveRequestBody(config))
}

func buildHTTPRequestBody(config *core.HTTPConfig, dstIP string, body []byte) string {
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.URI == "" {
		config.URI = "/"
	}
	if config.Version == "" {
		config.Version = "HTTP/1.1"
	}

	// Sniff Content-Type from the ORIGINAL body (before gzip) so HTML/JSON/
	// binary types are detected correctly, not as application/gzip.
	var contentType string
	if len(body) > 0 && !hasHeader(config.RequestHeaders, "Content-Type") {
		contentType = sniffContentType(body)
	}

	// Apply gzip AFTER sniffing. Content-Length reflects compressed bytes.
	requestContentEncoding := strings.ToLower(strings.TrimSpace(config.RequestContentEncoding))
	if len(body) > 0 && requestContentEncoding == "gzip" {
		body = gzipBytes(body)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s %s\r\n", config.Method, config.URI, config.Version))

	// HTTP/1.1 mandates Host (RFC 7230 §5.4); HTTP/1.0 does not, so we only
	// auto-emit Host for 1.1 (user-provided Host on any version always wins
	// via the user-header pass below).
	if !hasHeader(config.RequestHeaders, "Host") && isHTTP11(config.Version) {
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP)))
	}
	if !hasHeader(config.RequestHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", defaultConnection(config)))
	}
	if contentType != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if len(body) > 0 && !hasHeader(config.RequestHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	if requestContentEncoding != "" && len(body) > 0 && !hasHeader(config.RequestHeaders, "Content-Encoding") {
		sb.WriteString(fmt.Sprintf("Content-Encoding: %s\r\n", requestContentEncoding))
	}

	for key, value := range config.RequestHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// resolveRequestBody decodes the request body to bytes. BodyB64 wins over
// Body when set, so binary payloads (PNG/JPEG/PDF/ZIP/...) can be carried
// via base64. Invalid base64 falls back to the text Body (preserves the
// legacy string-only behavior and avoids a hard failure on a misconfigured
// field).
func resolveRequestBody(config *core.HTTPConfig) []byte {
	if b64 := strings.TrimSpace(config.BodyB64); b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return decoded
		}
	}
	return []byte(config.Body)
}

// resolveResponseBody is the response-side symmetric of resolveRequestBody.
func resolveResponseBody(config *core.HTTPConfig) []byte {
	if b64 := strings.TrimSpace(config.ResponseBodyB64); b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return decoded
		}
	}
	return []byte(config.ResponseBody)
}

// hasHeader reports whether headers contains the given field name using the
// case-insensitive comparison RFC 7230 requires for HTTP header names.
func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// defaultConnection returns the default Connection header value derived from
// the TCP behavior implied by Transactions and KeepAlive:
//   - Transactions > 1 (multiple HTTP transactions in one TCP connection)
//   - KeepAlive = true
// Either condition -> "keep-alive"; otherwise "close".
func defaultConnection(config *core.HTTPConfig) string {
	if config.Transactions > 1 || config.KeepAlive {
		return "keep-alive"
	}
	return "close"
}

// isHTTP11 reports whether version is HTTP/1.1, using the case-insensitive
// comparison RFC 7230 §3.1.1 allows for HTTP version tokens. Empty input is
// treated as HTTP/1.1 to match the Version default applied above.
func isHTTP11(version string) bool {
	if version == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(version), "HTTP/1.1")
}

// bracketHost wraps an IPv6 literal in brackets for use in a Host header
// value, per RFC 7230 §5.4 (uri-host production: IP-literals use "[" ... "]").
// IPv4 and non-IP strings pass through unchanged.
func bracketHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// buildHTTPResponse builds an HTTP response string.
//
// Defaulting follows the unified rule (user > default > none) for every
// output field:
//
//   - Version: empty -> "HTTP/1.1"
//   - StatusCode: 0 -> 200
//   - StatusText: empty -> looked up from StatusCode; unknown -> "Status NNN"
//   - Content-Type: not user-provided + ResponseBody non-empty -> sniffed
//     (text: HTML/XML/JSON/plain; binary: magic bytes; fallback text/plain)
//   - Content-Length: not user-provided + ResponseBody non-empty -> len(body)
//   - Connection: not user-provided -> "keep-alive" if Transactions>1 or
//     KeepAlive=true, else "close"
//
// ResponseBodyB64 (base64) takes precedence over ResponseBody (string) when
// set, so binary payloads (PNG/JPEG/PDF/ZIP/...) can be carried via
// ResponseBodyB64. The decoded bytes feed Content-Type sniffing, gzip
// compression, Content-Length, and MSS segmentation. A string ResponseBody
// still works for text payloads. Symmetric to buildHTTPRequest's body
// resolution on the request side.
//
// When ResponseContentEncoding == "gzip", ResponseBody is gzip-compressed
// (RFC 1952); the compressed bytes replace the body, Content-Length reflects
// the compressed byte count, and a "Content-Encoding: gzip" header is emitted
// (still overridable via ResponseHeaders, case-insensitive per RFC 7230 §3.2).
// Any ResponseContentEncoding value other than "" or "gzip" is treated as a
// literal header value passed through to Content-Encoding without
// transformation (caller responsibility — only "gzip" triggers actual
// compression here).
//
// User-provided ResponseHeaders are emitted verbatim and suppress the
// corresponding default (case-insensitive match per RFC 7230 §3.2).
func buildHTTPResponse(config *core.HTTPConfig) string {
	return buildHTTPResponseBody(config, resolveResponseBody(config))
}

func buildHTTPResponseBody(config *core.HTTPConfig, body []byte) string {
	version := config.Version
	if version == "" {
		version = "HTTP/1.1"
	}
	statusCode := config.ResponseStatusCode
	if statusCode == 0 {
		statusCode = 200
	}
	statusText := config.ResponseStatusText
	if statusText == "" {
		statusText = statusTextFor(statusCode)
	}

	// Sniff Content-Type from the ORIGINAL body (before gzip) so HTML/JSON/
	// binary types are detected correctly, not as application/gzip.
	var contentType string
	if len(body) > 0 && !hasHeader(config.ResponseHeaders, "Content-Type") {
		contentType = sniffContentType(body)
	}

	// Apply gzip AFTER sniffing. Content-Length reflects compressed bytes.
	contentEncoding := strings.ToLower(strings.TrimSpace(config.ResponseContentEncoding))
	if len(body) > 0 && contentEncoding == "gzip" {
		body = gzipBytes(body)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", version, statusCode, statusText))

	if contentType != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if len(body) > 0 && !hasHeader(config.ResponseHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	if contentEncoding != "" && len(body) > 0 && !hasHeader(config.ResponseHeaders, "Content-Encoding") {
		sb.WriteString(fmt.Sprintf("Content-Encoding: %s\r\n", contentEncoding))
	}
	if !hasHeader(config.ResponseHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", defaultConnection(config)))
	}

	for key, value := range config.ResponseHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// sniffContentType infers the MIME type from the body bytes. Text bodies are
// detected by leading-content patterns (HTML/XML/JSON); binary bodies are
// detected by magic-byte signatures (PNG/JPEG/GIF/PDF/ZIP/...). Unknown
// bodies fall back to text/plain (the historical default — preserves
// Wireshark's text rendering for plain-text payloads and keeps the
// decompressed body readable in the dissection tree).
//
// This is a sniff, not a strict MIME type check: it only inspects the leading
// bytes, not the whole body. The goal is a reasonable Content-Type default
// when the user does not provide one, so Wireshark's HTTP dissector picks the
// right sub-dissector (html for text/html, json for application/json, image
// for image/png, ...). User-provided Content-Type always wins.
func sniffContentType(body []byte) string {
	if len(body) == 0 {
		return "text/plain; charset=utf-8"
	}

	// Binary magic bytes — check first so binary content is not mis-sniffed
	// as text when its first bytes happen to be printable.
	if ct := sniffByMagic(body); ct != "" {
		return ct
	}

	// Text patterns. Trim leading whitespace so a body starting with "<html"
	// after whitespace is still detected as HTML. Also strip UTF-8 BOM
	// (EF BB BF) so BOM-prefixed HTML/XML/JSON is detected correctly.
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	trimmed = bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
	switch {
	case bytes.HasPrefix(trimmed, []byte("<!DOCTYPE html")),
		bytes.HasPrefix(trimmed, []byte("<!DOCTYPE HTML")),
		bytes.HasPrefix(trimmed, []byte("<html")),
		bytes.HasPrefix(trimmed, []byte("<HTML")),
		bytes.HasPrefix(trimmed, []byte("<!doctype html")):
		return "text/html; charset=utf-8"
	case bytes.HasPrefix(trimmed, []byte("<?xml")):
		return "application/xml; charset=utf-8"
	case isJSON(trimmed):
		return "application/json; charset=utf-8"
	}

	return "text/plain; charset=utf-8"
}

// sniffByMagic returns a MIME type for known binary magic byte signatures,
// or "" when no signature matches (caller falls back to text sniffing or
// text/plain). Signatures follow the common IANA registered types.
func sniffByMagic(body []byte) string {
	// PNG: 89 50 4E 47 0D 0A 1A 0A
	if len(body) >= 8 && body[0] == 0x89 && body[1] == 0x50 && body[2] == 0x4E && body[3] == 0x47 &&
		body[4] == 0x0D && body[5] == 0x0A && body[6] == 0x1A && body[7] == 0x0A {
		return "image/png"
	}
	// JPEG: FF D8 FF
	if len(body) >= 3 && body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF {
		return "image/jpeg"
	}
	// GIF: 47 49 46 38 37 61 (GIF87a) or 47 49 46 38 39 61 (GIF89a)
	if len(body) >= 6 && body[0] == 0x47 && body[1] == 0x49 && body[2] == 0x46 &&
		body[3] == 0x38 && (body[4] == 0x37 || body[4] == 0x39) && body[5] == 0x61 {
		return "image/gif"
	}
	// PDF: 25 50 44 46 (%PDF)
	if len(body) >= 4 && body[0] == 0x25 && body[1] == 0x50 && body[2] == 0x44 && body[3] == 0x46 {
		return "application/pdf"
	}
	// ZIP/GZIP/etc. (PK\x03\x04) — includes .docx/.xlsx/.zip
	if len(body) >= 4 && body[0] == 0x50 && body[1] == 0x4B && body[2] == 0x03 && body[3] == 0x04 {
		return "application/zip"
	}
	// GZIP: 1F 8B
	if len(body) >= 2 && body[0] == 0x1F && body[1] == 0x8B {
		return "application/gzip"
	}
	// BZIP2: 42 5A 68 (BZh)
	if len(body) >= 3 && body[0] == 0x42 && body[1] == 0x5A && body[2] == 0x68 {
		return "application/x-bzip2"
	}
	// BMP: 42 4D (BM)
	if len(body) >= 2 && body[0] == 0x42 && body[1] == 0x4D {
		return "image/bmp"
	}
	// MP3: 49 44 33 (ID3) or FF FB / FF F3 / FF F2
	if (len(body) >= 3 && body[0] == 0x49 && body[1] == 0x44 && body[2] == 0x33) ||
		(len(body) >= 2 && body[0] == 0xFF && (body[1] == 0xFB || body[1] == 0xF3 || body[1] == 0xF2)) {
		return "audio/mpeg"
	}
	// WAV (RIFF.WAVE): 52 49 46 46 ?? ?? ?? ?? 57 41 56 45
	if len(body) >= 12 && body[0] == 0x52 && body[1] == 0x49 && body[2] == 0x46 && body[3] == 0x46 &&
		body[8] == 0x57 && body[9] == 0x41 && body[10] == 0x56 && body[11] == 0x45 {
		return "audio/wav"
	}
	// WebP (RIFF.WEBP): 52 49 46 46 ?? ?? ?? ?? 57 45 42 50
	if len(body) >= 12 && body[0] == 0x52 && body[1] == 0x49 && body[2] == 0x46 && body[3] == 0x46 &&
		body[8] == 0x57 && body[9] == 0x45 && body[10] == 0x42 && body[11] == 0x50 {
		return "image/webp"
	}
	// ICO: 00 00 01 00
	if len(body) >= 4 && body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x01 && body[3] == 0x00 {
		return "image/x-icon"
	}
	return ""
}

// isJSON reports whether body looks like JSON: first non-whitespace byte is
// '{' or '[' and the body parses (or at least starts plausibly). We don't
// require full parse — a body starting with '{' or '[' is the strongest
// single-signal heuristic for JSON, and false positives (text starting with
// '{') are rare in practice. The caller already trimmed leading whitespace.
func isJSON(trimmed []byte) bool {
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

// gzipBytes gzip-compresses data (UTF-8 bytes or binary) using the standard
// library with the default (RFC 1952) compression level. The gzip header
// magic 0x1f 0x8b is what Wireshark/tshark recognize as "GZIP-encoded data"
// (a content encoding of HTTP, not to be confused with a gzipped *pcap*
// stream). Replaces gzipBody (which took a string) so binary payloads from
// BodyB64 can be compressed too.
func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		// gzip.Writer.Write only returns an error after the first Flush/Close,
		// so this branch is unreachable in practice for an in-memory buffer.
		// Fall back to the uncompressed body on a defensive error rather than
		// silently emitting truncated/empty compressed bytes.
		return data
	}
	if err := zw.Close(); err != nil {
		return data
	}
	return buf.Bytes()
}

// statusTextFor returns the RFC 7231 reason phrase for the given status code,
// or "Status NNN" for unrecognized codes.
func statusTextFor(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 411:
		return "Length Required"
	case 413:
		return "Payload Too Large"
	case 414:
		return "URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	}
	return fmt.Sprintf("Status %d", code)
}
