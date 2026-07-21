// Package http implements the HTTP protocol planner.
package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
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
		// client seq via spec.InitialSeq for reproducible tests.
		clientSeq := spec.InitialSeq
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

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
				EtherType: 0x0800,
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    spec.SrcPort,
				DstPort:    spec.DstPort,
				Seq:        clientSeq,
				Flags:      0x02, // SYN
				WindowSize: 65535,
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
				EtherType: 0x0800,
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
				EtherType: 0x0800,
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
		for i := 0; i < transactions; i++ {
			// HTTP Request
			request := buildHTTPRequest(httpConfig, spec.DstIP)
			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "up",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.SrcMAC,
					DstMAC:    spec.DstMAC,
					EtherType: 0x0800,
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
				Payload: []byte(request),
			}
			packetIndex++
			clientSeq += uint32(len(request))

			// HTTP Response
			response := buildHTTPResponse(httpConfig)
			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: 0x0800,
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
				Payload: []byte(response),
			}
			packetIndex++
			serverSeq += uint32(len(response))
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
				EtherType: 0x0800,
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
				EtherType: 0x0800,
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
				EtherType: 0x0800,
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
				EtherType: 0x0800,
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
//   - Content-Length: not user-provided + Body non-empty -> len(Body)
//   - Connection: not user-provided -> "keep-alive" if Transactions>1 or
//     KeepAlive=true, else "close"
//
// User-provided RequestHeaders are emitted verbatim and suppress the
// corresponding default (case-insensitive match per RFC 7230 §3.2).
func buildHTTPRequest(config *core.HTTPConfig, dstIP string) string {
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.URI == "" {
		config.URI = "/"
	}
	if config.Version == "" {
		config.Version = "HTTP/1.1"
	}

	request := fmt.Sprintf("%s %s %s\r\n", config.Method, config.URI, config.Version)

	// HTTP/1.1 mandates Host (RFC 7230 §5.4); HTTP/1.0 does not, so we only
	// auto-emit Host for 1.1 (user-provided Host on any version always wins
	// via the user-header pass below).
	if !hasHeader(config.RequestHeaders, "Host") && isHTTP11(config.Version) {
		request += fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP))
	}
	if !hasHeader(config.RequestHeaders, "Connection") {
		request += fmt.Sprintf("Connection: %s\r\n", defaultConnection(config))
	}
	if config.Body != "" && !hasHeader(config.RequestHeaders, "Content-Length") {
		request += fmt.Sprintf("Content-Length: %d\r\n", len(config.Body))
	}

	for key, value := range config.RequestHeaders {
		request += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	request += "\r\n"

	if config.Body != "" {
		request += config.Body
	}

	return request
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
//   - Content-Type: not user-provided + ResponseBody non-empty -> "text/plain"
//   - Content-Length: not user-provided + ResponseBody non-empty -> len(body)
//   - Connection: not user-provided -> "keep-alive" if Transactions>1 or
//     KeepAlive=true, else "close"
//
// When ContentEncoding == "gzip", ResponseBody is gzip-compressed (RFC 1952);
// the compressed bytes replace the body, Content-Length reflects the
// compressed byte count, and a "Content-Encoding: gzip" header is emitted
// (still overridable via ResponseHeaders, case-insensitive per RFC 7230 §3.2).
// Any ContentEncoding value other than "" or "gzip" is treated as a literal
// header value passed through to Content-Encoding without transformation
// (caller responsibility — only "gzip" triggers actual compression here).
//
// User-provided ResponseHeaders are emitted verbatim and suppress the
// corresponding default (case-insensitive match per RFC 7230 §3.2).
func buildHTTPResponse(config *core.HTTPConfig) string {
	body := config.ResponseBody
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

	// Apply gzip compression when requested. Compression happens before
	// header emission so Content-Length reflects the compressed byte count.
	// The Content-Encoding header is emitted below unless the user already
	// provided one (case-insensitive).
	contentEncoding := strings.ToLower(strings.TrimSpace(config.ContentEncoding))
	if body != "" && contentEncoding == "gzip" {
		body = gzipBody(body)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", version, statusCode, statusText))

	if body != "" && !hasHeader(config.ResponseHeaders, "Content-Type") {
		sb.WriteString("Content-Type: text/plain\r\n")
	}
	if body != "" && !hasHeader(config.ResponseHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	if contentEncoding != "" && body != "" && !hasHeader(config.ResponseHeaders, "Content-Encoding") {
		sb.WriteString(fmt.Sprintf("Content-Encoding: %s\r\n", contentEncoding))
	}
	if !hasHeader(config.ResponseHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", defaultConnection(config)))
	}

	for key, value := range config.ResponseHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

// gzipBody gzip-compresses s (UTF-8 bytes) using the standard library with
// the default (RFC 1952) compression level. The gzip header magic 0x1f 0x8b
// is what Wireshark/tshark recognize as "GZIP-encoded data" (a content
// encoding of HTTP, not to be confused with a gzipped *pcap* stream).
func gzipBody(s string) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		// gzip.Writer.Write only returns an error after the first Flush/Close,
		// so this branch is unreachable in practice for an in-memory buffer.
		// Fall back to the uncompressed body on a defensive error rather than
		// silently emitting truncated/empty compressed bytes.
		return s
	}
	if err := zw.Close(); err != nil {
		return s
	}
	return buf.String()
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
