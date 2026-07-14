package pcapparser

// Test points for direction.go, derived from tools/test_points/pcapparser.md
// (component D1). REAL tests exercising updateDirection/setClient directly.

import (
	"testing"
	"time"
)

// --- D1.1: Already locked ---

func TestUpdateDirection_AlreadyLocked(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.dirLocked = true
	fs.updateDirection(packetFields{l4Proto: "tcp", tcpSYN: true, tcpACK: false})
	// Must not change client.
	if fs.Client != "10.0.0.1:1234" {
		t.Errorf("Client = %q, want unchanged 10.0.0.1:1234 (locked)", fs.Client)
	}
}

// --- D1.2: TCP SYN client ---

func TestUpdateDirection_TCPSYNClient(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.updateDirection(packetFields{l4Proto: "tcp", tcpSYN: true, tcpACK: false, srcIP: ipA, srcPort: 1234, dstIP: ipB, dstPort: 80})
	if fs.Client != "10.0.0.1:1234" {
		t.Errorf("Client = %q, want 10.0.0.1:1234", fs.Client)
	}
	if fs.Server != "10.0.0.2:80" {
		t.Errorf("Server = %q, want 10.0.0.2:80", fs.Server)
	}
	if fs.DirMethod != "syn" {
		t.Errorf("DirMethod = %q, want syn", fs.DirMethod)
	}
	if fs.DirStatus != "classified" {
		t.Errorf("DirStatus = %q, want classified", fs.DirStatus)
	}
	if !fs.dirLocked {
		t.Error("dirLocked = false, want true")
	}
}

// --- D1.3: TCP SYN-ACK corrects ---

func TestUpdateDirection_TCPSYNACKCorrects(t *testing.T) {
	// First packet is SYN-ACK -> src is the server, dst is the client.
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.updateDirection(packetFields{l4Proto: "tcp", tcpSYN: true, tcpACK: true, srcIP: ipB, srcPort: 80, dstIP: ipA, dstPort: 1234})
	// Client should be ipA:1234 (dst of SYN-ACK), server = ipB:80 (src of SYN-ACK).
	if fs.Client != "10.0.0.1:1234" {
		t.Errorf("Client = %q, want 10.0.0.1:1234 (corrected by SYN-ACK)", fs.Client)
	}
	if fs.Server != "10.0.0.2:80" {
		t.Errorf("Server = %q, want 10.0.0.2:80 (corrected by SYN-ACK)", fs.Server)
	}
	if fs.serverPort != 80 {
		t.Errorf("serverPort = %d, want 80 (corrected to real server port)", fs.serverPort)
	}
}

// --- D1.4: TCP non-handshake ---

func TestUpdateDirection_TCPNonHandshake(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.updateDirection(packetFields{l4Proto: "tcp", tcpACK: true, tcpSYN: false, srcIP: ipA, srcPort: 1234, dstIP: ipB, dstPort: 80})
	if fs.DirStatus != "uncertain" {
		t.Errorf("DirStatus = %q, want uncertain (no SYN)", fs.DirStatus)
	}
	if fs.dirLocked {
		t.Error("dirLocked = true, want false (no handshake)")
	}
}

// --- D1.5: UDP src well-known port -> server ---

func TestUpdateDirection_UDPSrcWellKnown(t *testing.T) {
	fs := newTestFlowState("10.0.0.2", 53, 2000) // first packet: src=server:53, dst=client:2000
	fs.updateDirection(packetFields{l4Proto: "udp", srcIP: ipB, srcPort: 53, dstIP: ipA, dstPort: 2000})
	// src=53 is well-known server -> dst is client.
	if fs.Client != "10.0.0.1:2000" {
		t.Errorf("Client = %q, want 10.0.0.1:2000 (dst of server port)", fs.Client)
	}
	if fs.Server != "10.0.0.2:53" {
		t.Errorf("Server = %q, want 10.0.0.2:53", fs.Server)
	}
}

// --- D1.6: UDP dst well-known port -> client ---

func TestUpdateDirection_UDPDstWellKnown(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 2000, 53) // first packet: src=client:2000, dst=server:53
	fs.updateDirection(packetFields{l4Proto: "udp", srcIP: ipA, srcPort: 2000, dstIP: ipB, dstPort: 53})
	if fs.Client != "10.0.0.1:2000" {
		t.Errorf("Client = %q, want 10.0.0.1:2000", fs.Client)
	}
	if fs.Server != "10.0.0.2:53" {
		t.Errorf("Server = %q, want 10.0.0.2:53", fs.Server)
	}
}

// --- D1.7: UDP both well-known (or both unknown) ---

func TestUpdateDirection_UDPBothWellKnown(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 53, 53) // both ports 53
	fs.updateDirection(packetFields{l4Proto: "udp", srcIP: ipA, srcPort: 53, dstIP: ipB, dstPort: 53})
	if fs.DirStatus != "uncertain" {
		t.Errorf("DirStatus = %q, want uncertain (both ports well-known -> no hint)", fs.DirStatus)
	}
}

// --- D1.8: Non-TCP/UDP ---

func TestUpdateDirection_NonTCPUDP(t *testing.T) {
	fs := newTestFlowState("10.0.0.1", 1234, 80)
	fs.updateDirection(packetFields{l4Proto: "icmp"})
	if fs.DirStatus != "uncertain" {
		t.Errorf("DirStatus = %q, want uncertain (ICMP -> no direction hint)", fs.DirStatus)
	}
}

// --- D1-INTG: Direction SYN-ACK start (SIMULATED via Parse) ---

func TestParse_DirectionSYNACKStart(t *testing.T) {
	// Capture starting at SYN-ACK: the first packet is SYN-ACK from ipB:80 -> ipA:1234.
	// updateDirection must correct the client to ipA:1234 and server to ipB:80.
	// Then subsequent data from ipA:1234 -> ipB:80 must be classified as c2s.
	frames := [][]byte{
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil), // SYN-ACK s2c (first packet)
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),          // ACK c2s
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("data")), // data c2s
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	flow := analysis.Flows[0]
	if flow.Client != "10.0.0.1:1234" || flow.Server != "10.0.0.2:80" {
		t.Errorf("Client/Server = %q/%q, want 10.0.0.1:1234 / 10.0.0.2:80", flow.Client, flow.Server)
	}
	if flow.DirMethod != "syn" {
		t.Errorf("DirMethod = %q, want syn", flow.DirMethod)
	}
	// Packet directions: SYN-ACK src (ipB:80) != client -> s2c, ACK src (ipA:1234) == client -> c2s.
	wantDirs := []string{"s2c", "c2s", "c2s"}
	for i, p := range analysis.Packets {
		if p.Direction != wantDirs[i] {
			t.Errorf("packet %d direction = %q, want %q", i, p.Direction, wantDirs[i])
		}
	}
}