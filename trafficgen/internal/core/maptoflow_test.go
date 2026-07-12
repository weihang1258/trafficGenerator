package core

import (
	"testing"
)

func TestMapToFlowSpec_TCP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(12345),
		"dst_port": float64(80),
		"ttl":      float64(128),
		"tcp": map[string]interface{}{
			"handshake":   true,
			"termination": false,
			"mss":         float64(1460),
			"window_size": float64(65535),
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != "10.0.0.1" || spec.DstIP != "10.0.0.2" {
		t.Errorf("IPs = %s/%s", spec.SrcIP, spec.DstIP)
	}
	if spec.SrcPort != 12345 || spec.DstPort != 80 {
		t.Errorf("ports = %d/%d", spec.SrcPort, spec.DstPort)
	}
	if spec.TTL != 128 {
		t.Errorf("TTL = %d, want 128", spec.TTL)
	}
	if spec.TCP == nil {
		t.Fatal("TCP nil")
	}
	if spec.TCP.MSS != 1460 || spec.TCP.WindowSize != 65535 {
		t.Errorf("TCP MSS=%d Win=%d", spec.TCP.MSS, spec.TCP.WindowSize)
	}
	if !spec.TCP.Handshake || spec.TCP.Termination {
		t.Errorf("TCP flags handshake=%v termination=%v", spec.TCP.Handshake, spec.TCP.Termination)
	}
}

func TestMapToFlowSpec_HTTPDefaultPort(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method": "POST",
			"uri":    "/api",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil || spec.HTTP.Method != "POST" || spec.HTTP.URI != "/api" {
		t.Errorf("HTTP = %+v", spec.HTTP)
	}
	if spec.DstPort != 80 {
		t.Errorf("HTTP default DstPort = %d, want 80", spec.DstPort)
	}
}

func TestMapToFlowSpec_DNSDefaultPort(t *testing.T) {
	cfg := map[string]interface{}{
		"dns": map[string]interface{}{
			"domain": "example.com",
		},
	}
	spec := mapToFlowSpec(cfg, "dns")
	if spec.DNS == nil || spec.DNS.Domain != "example.com" {
		t.Errorf("DNS = %+v", spec.DNS)
	}
	if spec.DstPort != 53 {
		t.Errorf("DNS default DstPort = %d, want 53", spec.DstPort)
	}
}

func TestMapToFlowSpec_VLAN(t *testing.T) {
	cfg := map[string]interface{}{
		"vlan_id":       float64(100),
		"vlan_priority": float64(3),
	}
	spec := mapToFlowSpec(cfg, "udp")
	if spec.VLAN == nil || spec.VLAN.ID != 100 || spec.VLAN.Priority != 3 {
		t.Errorf("VLAN = %+v", spec.VLAN)
	}
}
