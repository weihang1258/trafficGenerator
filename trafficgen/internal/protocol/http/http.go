// Package http implements the HTTP protocol planner.
package http

import (
	"context"
	"fmt"
	"net"
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

		now := time.Now()
		packetIndex := uint64(0)

		// Initialize sequence numbers
		clientSeq := uint32(1000)
		serverSeq := uint32(2000)

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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
				Seq:      clientSeq,
				Flags:    0x02, // SYN
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.DstPort,
				DstPort:  spec.SrcPort,
				Seq:      serverSeq,
				Ack:      clientSeq,
				Flags:    0x12, // SYN-ACK
			},
		}
		packetIndex++
		serverSeq++

		// ACK
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
				Seq:      clientSeq,
				Ack:      serverSeq,
				Flags:    0x10, // ACK
			},
		}
		packetIndex++

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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
				Seq:      clientSeq,
				Ack:      serverSeq,
				Flags:    0x18, // PSH-ACK
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.DstPort,
				DstPort:  spec.SrcPort,
				Seq:      serverSeq,
				Ack:      clientSeq,
				Flags:    0x18, // PSH-ACK
			},
			Payload: []byte(response),
		}
		packetIndex++
		serverSeq += uint32(len(response))

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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
				Seq:      clientSeq,
				Ack:      serverSeq,
				Flags:    0x11, // FIN-ACK
			},
		}
		packetIndex++
		clientSeq++

		// ACK (server)
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.DstPort,
				DstPort:  spec.SrcPort,
				Seq:      serverSeq,
				Ack:      clientSeq,
				Flags:    0x10, // ACK
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.DstPort,
				DstPort:  spec.SrcPort,
				Seq:      serverSeq,
				Ack:      clientSeq,
				Flags:    0x11, // FIN-ACK
			},
		}
		packetIndex++
		serverSeq++

		// ACK (client)
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
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "tcp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
				Seq:      clientSeq,
				Ack:      serverSeq,
				Flags:    0x10, // ACK
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
	response := "HTTP/1.1 200 OK\r\n"
	response += "Content-Type: text/plain\r\n"
	response += "Content-Length: 2\r\n"
	response += "\r\n"
	response += "OK"
	return response
}
