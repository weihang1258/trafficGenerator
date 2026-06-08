// Package http implements the HTTP protocol planner.
package http

import (
	"context"
	"fmt"
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
				Method: "GET",
				URI:    "/",
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
		ipID := uint16(1)

		// Initialize sequence numbers
		clientSeq := uint32(1000)
		serverSeq := uint32(2000)

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
			L3: core.L3Config{
				SrcIP:    spec.SrcIP,
				DstIP:    spec.DstIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			L3: core.L3Config{
				SrcIP:    spec.DstIP,
				DstIP:    spec.SrcIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			L3: core.L3Config{
				SrcIP:    spec.SrcIP,
				DstIP:    spec.DstIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			request := buildHTTPRequest(httpConfig)
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
				L3: core.L3Config{
					SrcIP:    spec.SrcIP,
					DstIP:    spec.DstIP,
					Protocol: 6,
					TTL:      effectiveTTL,
					IPID:     nextIPID(),
				},
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
				L3: core.L3Config{
					SrcIP:    spec.DstIP,
					DstIP:    spec.SrcIP,
					Protocol: 6,
					TTL:      effectiveTTL,
					IPID:     nextIPID(),
				},
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
			L3: core.L3Config{
				SrcIP:    spec.SrcIP,
				DstIP:    spec.DstIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			L3: core.L3Config{
				SrcIP:    spec.DstIP,
				DstIP:    spec.SrcIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			L3: core.L3Config{
				SrcIP:    spec.DstIP,
				DstIP:    spec.SrcIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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
			L3: core.L3Config{
				SrcIP:    spec.SrcIP,
				DstIP:    spec.DstIP,
				Protocol: 6,
				TTL:      effectiveTTL,
				IPID:     nextIPID(),
			},
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

// buildHTTPRequest builds an HTTP request string.
func buildHTTPRequest(config *core.HTTPConfig) string {
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.URI == "" {
		config.URI = "/"
	}

	request := fmt.Sprintf("%s %s HTTP/1.1\r\n", config.Method, config.URI)
	request += fmt.Sprintf("Host: localhost\r\n")

	for key, value := range config.Headers {
		request += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	if config.Body != "" {
		request += fmt.Sprintf("Content-Length: %d\r\n", len(config.Body))
	}

	request += "\r\n"

	if config.Body != "" {
		request += config.Body
	}

	return request
}

// buildHTTPResponse builds an HTTP response string.
func buildHTTPResponse(config *core.HTTPConfig) string {
	body := "OK"

	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Type: text/plain\r\n")
	sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	if config.KeepAlive {
		sb.WriteString("Connection: keep-alive\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}
