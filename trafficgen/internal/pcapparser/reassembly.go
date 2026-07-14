package pcapparser

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// reassemblyStream buffers reassembled TCP bytes for one direction (c2s or s2c)
// of a flow, implementing tcpassembly.Stream. Bytes are buffered in memory and
// flushed to the .payloads file at finalize (single-threaded, so no interleaving
// conflicts). Gaps (seq holes) are detected via Reassembly.Skip.
type reassemblyStream struct {
	fs          *FlowState
	dir         string // c2s|s2c
	buf         []byte
	gapDetected bool
	complete    bool
}

// Reassembled is called by the assembler with consecutive reassembled segments.
// Reassembly objects are reused after the call, so we copy r.Bytes into s.buf.
func (s *reassemblyStream) Reassembled(seg []tcpassembly.Reassembly) {
	for _, r := range seg {
		if r.Skip != 0 {
			s.gapDetected = true
		}
		s.buf = append(s.buf, r.Bytes...)
	}
}

// ReassemblyComplete is called when the assembler decides the stream is done
// (FIN/RST seen, or flushed by FlushOlderThan/FlushAll). We mark it complete;
// the parser flushes the buffer to .payloads at finalize.
func (s *reassemblyStream) ReassemblyComplete() {
	s.complete = true
}

// nullStream discards all reassembled bytes. Used when the assembler sees a
// TCP direction whose flow we don't know (e.g. packets before the flow map was
// populated -- shouldn't normally happen, but defensive).
type nullStream struct{}

func (nullStream) Reassembled([]tcpassembly.Reassembly) {}
func (nullStream) ReassemblyComplete()                   {}

var nullStreamInstance tcpassembly.Stream = nullStream{}

// reassemblyFactory implements tcpassembly.StreamFactory. The assembler calls
// New(netFlow, tcpFlow) the first time it sees a TCP direction; the factory
// maps that to the flow's FlowState + direction and returns a stream that
// buffers into the right c2s/s2c slot.
type reassemblyFactory struct {
	flows map[string]*FlowState // by normalized flow key
}

func (f *reassemblyFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	srcIP := netIPFromEndpoint(netFlow.Src())
	dstIP := netIPFromEndpoint(netFlow.Dst())
	srcPort := portFromEndpoint(tcpFlow.Src())
	dstPort := portFromEndpoint(tcpFlow.Dst())
	if srcIP == nil || dstIP == nil {
		return nullStreamInstance
	}
	key := flowKeyTCPUDP(srcIP, dstIP, srcPort, dstPort, 6)
	fs, ok := f.flows[key]
	if !ok {
		return nullStreamInstance
	}
	dir := fs.classifyDirection(srcIP.String(), srcPort)
	s := &reassemblyStream{fs: fs, dir: dir}
	fs.setStream(dir, s)
	return s
}

// netIPFromEndpoint converts a gopacket network-layer endpoint (raw IP bytes)
// to a net.IP. Returns nil for non-IP endpoints.
func netIPFromEndpoint(ep gopacket.Endpoint) net.IP {
	raw := ep.Raw()
	if len(raw) == 4 || len(raw) == 16 {
		ip := make(net.IP, len(raw))
		copy(ip, raw)
		return ip
	}
	return nil
}

// portFromEndpoint converts a gopacket transport-layer endpoint (2-byte big-endian
// port) to a uint16.
func portFromEndpoint(ep gopacket.Endpoint) uint16 {
	raw := ep.Raw()
	if len(raw) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

// assemblerHelper wraps the tcpassembly Assembler + StreamPool + factory for use
// during a single Parse pass. It tracks created streams so the parser can flush
// their buffers to .payloads at finalize.
type assemblerHelper struct {
	factory   *reassemblyFactory
	pool      *tcpassembly.StreamPool
	assembler *tcpassembly.Assembler
}

func newAssemblerHelper(flows map[string]*FlowState) *assemblerHelper {
	factory := &reassemblyFactory{flows: flows}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)
	// Bound memory per connection (§7: "控制内存"). 4 buffered pages is enough
	// for typical reordering without unbounded growth on a stuck stream.
	assembler.MaxBufferedPagesPerConnection = 4
	return &assemblerHelper{factory: factory, pool: pool, assembler: assembler}
}

// assemble feeds a TCP packet to the assembler. netFlow is the network-layer
// flow (directional); tcp is the TCP layer. The assembler calls the factory's
// New for new directions and the stream's Reassembled/ReassemblyComplete.
func (a *assemblerHelper) assemble(netFlow gopacket.Flow, tcp *layers.TCP, tsUs int64) {
	// tcpassembly uses the timestamp for FlushOlderThan (not used in v1
	// single-pass), but pass the capture timestamp for correctness.
	a.assembler.AssembleWithTimestamp(netFlow, tcp, time.UnixMicro(tsUs))
}

// flushAll flushes all buffered streams (called at end-of-file). Returns the
// count of streams closed.
func (a *assemblerHelper) flushAll() int {
	return a.assembler.FlushAll()
}
