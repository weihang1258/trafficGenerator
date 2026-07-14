package pcapparser

// Test points for reassembly.go, derived from tools/test_points/pcapparser.md
// (components R1-R6). REAL tests exercising reassemblyStream/reassemblyFactory/
// netIPFromEndpoint/portFromEndpoint directly.

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// --- R1: reassemblyStream Gap/NoGap ---

func TestReassemblyStream_GapDetected(t *testing.T) {
	s := &reassemblyStream{}
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 1, Bytes: []byte("hello")}})
	if !s.gapDetected {
		t.Error("gapDetected = false, want true (Skip=1)")
	}
}

func TestReassemblyStream_NoGap(t *testing.T) {
	s := &reassemblyStream{}
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 0, Bytes: []byte("hello")}})
	if s.gapDetected {
		t.Error("gapDetected = true, want false (Skip=0)")
	}
	if string(s.buf) != "hello" {
		t.Errorf("buf = %q, want hello", string(s.buf))
	}
}

func TestReassemblyStream_EmptySegment(t *testing.T) {
	s := &reassemblyStream{buf: []byte("existing")}
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 0, Bytes: nil}})
	if string(s.buf) != "existing" {
		t.Errorf("buf = %q, want 'existing' (nil bytes unchanged)", string(s.buf))
	}
}

func TestReassemblyStream_NonEmpty(t *testing.T) {
	s := &reassemblyStream{}
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 0, Bytes: []byte("abc")}})
	if string(s.buf) != "abc" {
		t.Errorf("buf = %q, want abc", string(s.buf))
	}
}

func TestReassemblyStream_MultipleSegments(t *testing.T) {
	s := &reassemblyStream{}
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 0, Bytes: []byte("Hello ")}})
	s.Reassembled([]tcpassembly.Reassembly{{Skip: 0, Bytes: []byte("World")}})
	if string(s.buf) != "Hello World" {
		t.Errorf("buf = %q, want 'Hello World'", string(s.buf))
	}
}

// --- R2: ReassemblyComplete ---

func TestReassemblyStream_Complete(t *testing.T) {
	s := &reassemblyStream{}
	s.ReassemblyComplete()
	if !s.complete {
		t.Error("complete = false after ReassemblyComplete()")
	}
}

// --- R3: nullStream ---

func TestNullStream_ReassembledNoop(t *testing.T) {
	ns := nullStream{}
	ns.Reassembled([]tcpassembly.Reassembly{{Skip: 1, Bytes: []byte("x")}})
	// Must not panic.
}

func TestNullStream_CompleteNoop(t *testing.T) {
	ns := nullStream{}
	ns.ReassemblyComplete()
	// Must not panic.
}

// --- R4: reassemblyFactory ---

func TestReassemblyFactory_NilIP(t *testing.T) {
	// 6-byte endpoint (MAC) -> netIPFromEndpoint returns nil -> nullStream.
	macEp := gopacket.NewEndpoint(layers.EndpointMAC, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	tcpEp := gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0, 80})
	netFlow := gopacket.NewFlow(layers.EndpointMAC, macEp.Raw(), macEp.Raw())
	tcpFlow := gopacket.NewFlow(layers.EndpointTCPPort, tcpEp.Raw(), tcpEp.Raw())
	f := &reassemblyFactory{flows: map[string]*FlowState{}}
	s := f.New(netFlow, tcpFlow)
	if _, ok := s.(nullStream); !ok {
		t.Errorf("factory returned %T, want nullStream (non-IP endpoint)", s)
	}
}

func TestReassemblyFactory_FlowNotFound(t *testing.T) {
	// Endpoints not in flows map -> nullStream.
	ipEp1 := gopacket.NewEndpoint(layers.EndpointIPv4, []byte{10, 0, 0, 1})
	ipEp2 := gopacket.NewEndpoint(layers.EndpointIPv4, []byte{10, 0, 0, 2})
	tcpEp1 := gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0, 80})
	tcpEp2 := gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0x04, 0xD2}) // 1234
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, ipEp1.Raw(), ipEp2.Raw())
	tcpFlow := gopacket.NewFlow(layers.EndpointTCPPort, tcpEp1.Raw(), tcpEp2.Raw())
	f := &reassemblyFactory{flows: map[string]*FlowState{}}
	s := f.New(netFlow, tcpFlow)
	if _, ok := s.(nullStream); !ok {
		t.Errorf("factory returned %T, want nullStream (flow not found)", s)
	}
}

// --- R5: netIPFromEndpoint ---

func TestNetIPFromEndpoint_IPv4(t *testing.T) {
	ep := gopacket.NewEndpoint(layers.EndpointIPv4, []byte{10, 0, 0, 1})
	ip := netIPFromEndpoint(ep)
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("netIPFromEndpoint 4-byte = %v, want 10.0.0.1", ip)
	}
}

func TestNetIPFromEndpoint_IPv6(t *testing.T) {
	ep := gopacket.NewEndpoint(layers.EndpointIPv6, net.ParseIP("2001:db8::1").To16())
	ip := netIPFromEndpoint(ep)
	if ip == nil || ip.String() != "2001:db8::1" {
		t.Errorf("netIPFromEndpoint 16-byte = %v, want 2001:db8::1", ip)
	}
}

func TestNetIPFromEndpoint_NonIP(t *testing.T) {
	ep := gopacket.NewEndpoint(layers.EndpointMAC, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	ip := netIPFromEndpoint(ep)
	if ip != nil {
		t.Errorf("netIPFromEndpoint 6-byte = %v, want nil", ip)
	}
}

// --- R6: portFromEndpoint ---

func TestPortFromEndpoint_Valid(t *testing.T) {
	ep := gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0x00, 0x50}) // 80
	port := portFromEndpoint(ep)
	if port != 80 {
		t.Errorf("portFromEndpoint = %d, want 80", port)
	}
}

func TestPortFromEndpoint_InvalidLen(t *testing.T) {
	ep := gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0x00}) // 1 byte
	port := portFromEndpoint(ep)
	if port != 0 {
		t.Errorf("portFromEndpoint 1-byte = %d, want 0", port)
	}
}