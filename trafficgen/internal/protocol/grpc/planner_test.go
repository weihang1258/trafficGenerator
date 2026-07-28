// Package grpc implements the gRPC over HTTP/2 protocol planner per
// RFC 7540/9113 (HTTP/2), RFC 7541 (HPACK), and the gRPC Protocol spec
// (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).
//
// Tests in this file drive the planner through the public Plan/Validate
// API and assert observable wire bytes. The detailed byte-level testpoints
// (per /tmp/l7_planner_design/testcases_grpc.md) live in
// planner_testpoints_test.go; this file holds the structural tests
// (Name/Validate/Plan shape).
package grpc

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "grpc" {
		t.Errorf("Name() = %q, want %q", got, "grpc")
	}
}

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name: "valid unary call",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service: "telemetry.Telemetry",
					Method:  "Subscribe",
				},
			},
			wantErr: false,
		},
		{
			name: "missing Service",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Method: "Subscribe",
				},
			},
			wantErr: true,
		},
		{
			name: "missing Method",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service: "telemetry.Telemetry",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid CallType",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service:  "telemetry.Telemetry",
					Method:   "Subscribe",
					CallType: "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ResponseStatus",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service:        "telemetry.Telemetry",
					Method:         "Subscribe",
					ResponseStatus: 17,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid Encoding",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service:  "telemetry.Telemetry",
					Method:   "Subscribe",
					Encoding: "snappy",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid Timeout unit",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service: "telemetry.Telemetry",
					Method:  "Subscribe",
					Timeout: "1X",
				},
			},
			wantErr: true,
		},
		{
			name: "MaxFrameSize too small",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 8604,
				GRPC: &core.GRPCConfig{
					Service:     "telemetry.Telemetry",
					Method:      "Subscribe",
					MaxFrameSize: 1024,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPlanner_Plan_Structure verifies the high-level packet sequence for
// a unary gRPC call: TCP 3-way handshake -> HTTP/2 preface (magic +
// SETTINGS) -> server SETTINGS + ACK -> client SETTINGS ACK -> client
// HEADERS + DATA -> server HEADERS + DATA + trailers -> TCP 4-way
// teardown. The exact byte-level assertions live in testpoints.
func TestPlanner_Plan_Structure(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 8604,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		GRPC: &core.GRPCConfig{
			Service:          "telemetry.Telemetry",
			Method:           "Subscribe",
			CallType:         "unary",
			RequestMessages:  [][]byte{{0x08, 0x96, 0x01}},
			ResponseMessages: [][]byte{{0x08, 0x96, 0x01}},
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for c := range configChan {
		configs = append(configs, c)
	}

	// Minimum sequence:
	//   3 (handshake) + 1 (preface) + 1 (server SETTINGS+ACK) + 1 (client ACK)
	// + 1 (client HEADERS) + 1 (client DATA) + 1 (server HEADERS) +
	//   1 (server DATA) + 1 (trailers) + 4 (teardown) = 15
	if len(configs) < 15 {
		t.Fatalf("expected at least 15 packets, got %d", len(configs))
	}

	// TCP handshake: SYN, SYN-ACK, ACK
	if configs[0].L4.Flags != 0x02 {
		t.Errorf("packet 0: want SYN (0x02), got 0x%02x", configs[0].L4.Flags)
	}
	if configs[1].L4.Flags != 0x12 {
		t.Errorf("packet 1: want SYN-ACK (0x12), got 0x%02x", configs[1].L4.Flags)
	}
	if configs[2].L4.Flags != 0x10 {
		t.Errorf("packet 2: want ACK (0x10), got 0x%02x", configs[2].L4.Flags)
	}

	// Packet 3 = client HTTP/2 connection preface (magic + SETTINGS).
	// Payload must start with the 24-byte magic.
	preface := configs[3].Payload
	const magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if len(preface) < 24 {
		t.Fatalf("preface payload len %d < 24", len(preface))
	}
	if string(preface[:24]) != magic {
		t.Errorf("preface magic mismatch: got %q", string(preface[:24]))
	}

	// TCP teardown: last 4 packets are FIN-ACK, ACK, FIN-ACK, ACK.
	n := len(configs)
	if configs[n-4].L4.Flags != 0x11 {
		t.Errorf("packet %d: want FIN-ACK (0x11), got 0x%02x", n-4, configs[n-4].L4.Flags)
	}
	if configs[n-3].L4.Flags != 0x10 {
		t.Errorf("packet %d: want ACK (0x10), got 0x%02x", n-3, configs[n-3].L4.Flags)
	}
	if configs[n-2].L4.Flags != 0x11 {
		t.Errorf("packet %d: want FIN-ACK (0x11), got 0x%02x", n-2, configs[n-2].L4.Flags)
	}
	if configs[n-1].L4.Flags != 0x10 {
		t.Errorf("packet %d: want ACK (0x10), got 0x%02x", n-1, configs[n-1].L4.Flags)
	}
}
