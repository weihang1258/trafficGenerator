package pcapparser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// ParserVersion is the semantic version of the parsing engine. Stored on each
// FlowModel so a future logic upgrade can detect stale indexes and trigger a
// reparse (§17.12).
const ParserVersion = "1.0.0"

// pcapGlobalHeaderLen is the size of the pcap file global header (24 bytes),
// consumed by pcapgo.NewReader before the first packet record.
const pcapGlobalHeaderLen = 24

// pcapRecordHeaderLen is the per-packet pcap record header (ts_sec, ts_usec,
// incl_len, orig_len) preceding each packet's bytes.
const pcapRecordHeaderLen = 16

// PcapAnalysis is the output of Parse: asset-level metadata + finalized flows.
// Packets are delivered streaming via Options.PacketSink during the parse; if no
// sink is configured they are retained in Packets (suitable only for small
// pcaps / tests).
type PcapAnalysis struct {
	LinkType     layers.LinkType
	Snaplen      uint32
	PacketCount  int64
	ByteCount    int64
	FlowCount    int64
	FirstTsUs    int64
	LastTsUs     int64
	ProtocolDist map[string]int64 // protocol -> packet count
	Flows        []storage.FlowModel
	Packets      []storage.PacketModel // populated only when no PacketSink
	// Trigram is the payload-substring index (§11), built during the parse over
	// TCP reassembled streams and UDP per-packet payloads. Nil if not needed.
	Trigram *TrigramIndex
	// TrigramWriteError is set if persisting the trigram index to
	// Options.TrigramIndexPath failed (non-fatal; search falls back to in-memory).
	TrigramWriteError error
}

// Options controls Parse behavior. A nil *Options uses defaults.
type Options struct {
	// PacketSink receives batches of PacketModel during parsing (streaming,
	// bounded memory). If nil, packets are retained in PcapAnalysis.Packets.
	PacketSink func([]storage.PacketModel) error
	// FlowSink receives each finalized FlowModel as its flow ends (streaming).
	// If nil, flows are retained in PcapAnalysis.Flows.
	FlowSink func(storage.FlowModel) error
	// BatchSize is the packet-batch size forwarded to PacketSink (default 1000).
	BatchSize int
	// UserID stamps every FlowModel/PacketModel for user isolation.
	UserID string
	// PcapAssetID stamps every FlowModel/PacketModel with the owning asset.
	PcapAssetID string
	// PayloadsPath is where reassembled TCP L7 streams are materialized
	// ({pcap_id}.payloads, §10). If empty, reassembly still runs but streams
	// are not written to disk (FlowModel.StreamFile stays empty).
	PayloadsPath string
	// TrigramIndexPath is where the trigram index is persisted
	// ({pcap_id}.trigram, §11). If empty, the index is built in memory only
	// and not written to disk (lost when the process exits).
	TrigramIndexPath string
}

func (o *Options) batchSize() int {
	if o == nil || o.BatchSize <= 0 {
		return 1000
	}
	return o.BatchSize
}

// Parse reads a pcap file in a single pass and produces FlowModel/PacketModel
// records (§4). It groups packets into bidirectional-normalized flows, builds
// minimal per-packet indexes, and streams them to the configured sinks.
//
// v1 supports the classic pcap format (DLT_EN10MB / Ethernet) with precise
// RawOffset tracking. pcapng is detected and rejected with a clear error until
// a block-aware reader is added.
func Parse(path string, opts *Options) (*PcapAnalysis, error) {
	// A nil *Options uses defaults (documented contract, §2). Normalize early so
	// the rest of Parse can dereference opts without per-field nil guards.
	if opts == nil {
		opts = &Options{}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	reader, linkType, snaplen, err := openPcapReader(f)
	if err != nil {
		return nil, err
	}
	if linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("unsupported link type %d: v1 supports Ethernet (DLT_EN10MB) only", linkType)
	}

	batchSize := opts.batchSize()
	analysis := &PcapAnalysis{
		LinkType:     linkType,
		Snaplen:      snaplen,
		ProtocolDist: map[string]int64{},
		Trigram:      NewTrigramIndex(),
	}

	// Reassembly: .payloads materialization + TCP assembler (§7/§10).
	payloads, err := newPayloadsWriter(opts.PayloadsPath)
	if err != nil {
		return nil, err
	}
	defer payloads.close()

	flows := map[string]*FlowState{} // active flows, keyed by normalized flow key
	// fragFlowMap maps an IP fragment group ID to the real flow key, so non-first
	// fragments (which carry no L4 header and thus no ports) still group into the
	// correct flow (§8). Seeded when the first fragment (offset 0) is seen.
	fragFlowMap := map[string]string{}
	asm := newAssemblerHelper(flows)
	fragReassembler := NewFragmentReassembler()
	l7reg := NewRegistry()

	decoder := layers.LayerTypeEthernet
	recordOffset := int64(pcapGlobalHeaderLen) // byte offset of the next record header

	for {
		dataOffset := recordOffset + pcapRecordHeaderLen // packet data starts after the 16B record header
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet at offset %d: %w", recordOffset, err)
		}
		capturedLen := len(data)
		recordOffset += int64(pcapRecordHeaderLen + capturedLen)

		tsUs := ci.Timestamp.UnixMicro()
		pkt := gopacket.NewPacket(data, decoder, gopacket.Default)
		fields := extractFields(pkt)

		// Build the PacketModel (minimal index, §17.4).
		pm := storage.PacketModel{
			ID:          uuid.New().String(),
			PcapAssetID: opts.PcapAssetID,
			UserID:      opts.UserID,
			RawOffset:   dataOffset,
			Length:      capturedLen,
			TimestampUs: tsUs,
			L4Protocol:  fields.l4Proto,
			PayloadHash: payloadHash(fields.payload),
			AnomalyFlag: detectAnomaly(ci.Length, capturedLen, ci.Length),
			FragGroupID: fields.fragGroupID,
			FragOffset:  fields.fragOffset,
		}

		// Group into a flow.
		key := computeFlowKey(fields)
		// Non-first fragments have no ports (no L4 header), so computeFlowKey
		// returns "" or a port-less key. Look up the real flow key via the
		// fragment-group map so they join the first fragment's flow (§8).
		if fields.fragGroupID != "" && !fields.fragFirst {
			if fk, ok := fragFlowMap[fields.fragGroupID]; ok {
				key = fk
			}
		}
		if key == "" {
			// Unknown/ungroupable L2: still index the packet under a synthetic
			// per-packet flow so it is not lost. Uses the RawOffset as the key.
			key = fmt.Sprintf("raw|%d", dataOffset)
		}
		// Record the fragment-group -> flow-key mapping from the first fragment
		// so subsequent non-first fragments can find the flow.
		if fields.fragFirst && fields.fragGroupID != "" && !strings.HasPrefix(key, "raw|") {
			fragFlowMap[fields.fragGroupID] = key
		}
		fs, ok := flows[key]
		if !ok {
			fs = newFlowState(uuid.New().String(), opts.PcapAssetID, opts.UserID, key, firstPacketInfo{
				SrcIP:     fields.srcIP.String(),
				DstIP:     fields.dstIP.String(),
				SrcPort:   fields.srcPort,
				DstPort:   fields.dstPort,
				L4Proto:   fields.l4Proto,
				IPVersion: fields.ipVersion,
				TsUs:      tsUs,
			})
			// First packet defines the offset layout (encapsulation-constant).
			fs.setLayout(ExtractOffsetLayout(pkt))
			flows[key] = fs
		}
		pm.FlowID = fs.FlowModel.ID
		fs.updateDirection(fields)
		pm.Direction = fs.classifyDirection(fields.srcIP.String(), fields.srcPort)
		fs.addPacket(pm)

		// TCP stats (handshake/seq/flags) accumulate per packet. Skip fragments:
		// a fragment carries no TCP flags/seq (only the first has ports), so
		// counting it would pollute handshake/seq/window stats. Fragmented TCP
		// is IP-reassembled first (§8): fragments are buffered, and only the
		// complete datagram is fed to the assembler (non-first fragments have no
		// L4 header, so they can't be fed directly).
		if fields.l4Proto == "tcp" && fields.fragGroupID == "" {
			fs.recordTCPStats(fields, pm.Direction)
		}
		if fields.fragGroupID != "" {
			reassembled := fragReassembler.AddFragment(
				fields.fragGroupID, data, fs.layout.L3Start,
				fields.ipID, fields.srcIP, fields.dstIP, 6,
				fields.fragOffset*8, fields.ipMF)
			if reassembled != nil {
				feedReassembledToAssembler(asm, flows, reassembled, tsUs, opts)
			}
		} else if fields.l4Proto == "tcp" {
			if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				if nl := pkt.NetworkLayer(); nl != nil {
					asm.assemble(nl.NetworkFlow(), tcp, tsUs)
				}
			}
		}

		// Trigram index: UDP payloads are indexed per-packet (each is an
		// independent L7 message). TCP is indexed from reassembled streams
		// after the assembler flushes (below).
		if fields.l4Proto == "udp" && len(fields.payload) > 0 {
			analysis.Trigram.AddSegment(fs.FlowModel.ID, pm.Direction, fields.payload)
			// L7 parse (first packet with payload sets the flow's L7 metadata).
			// Use the calibrated server port so a capture starting at a server->client
			// response still hints the right L7 parser.
			if !fs.l7Parsed {
				if res := l7reg.ParseStream(fs.serverPort, fields.payload); res != nil {
					fs.setL7(res, pm.Direction)
					fs.l7Parsed = true
				}
			}
		}

		// Global stats.
		analysis.PacketCount++
		analysis.ByteCount += int64(capturedLen)
		if fields.l4Proto != "" {
			analysis.ProtocolDist[fields.l4Proto]++
		}
		// FirstTsUs uses PacketCount==1 (not ==0) as the "first packet" signal:
		// 0 is a valid Unix-microsecond timestamp, so it cannot serve as an
		// "unset" sentinel (a first packet at ts=0 would otherwise be
		// overwritten by any later packet).
		if analysis.PacketCount == 1 || tsUs < analysis.FirstTsUs {
			analysis.FirstTsUs = tsUs
		}
		if tsUs > analysis.LastTsUs {
			analysis.LastTsUs = tsUs
		}

		// Stream packet batches.
		if fs.pendingPacketCount() >= batchSize {
			batch := fs.drainPackets()
			if err := forwardPackets(opts, analysis, batch); err != nil {
				return nil, err
			}
		}
	}

	// Flush the assembler so remaining TCP streams get ReassemblyComplete, then
	// materialize each flow's reassembled bytes to .payloads (§7/§10). Discard
	// any incomplete IP fragment groups first.
	fragReassembler.Flush()
	asm.flushAll()
	// Iterate flows in deterministic order (by first-packet ts) so analysis.Flows
	// and trigram segments are stable across runs despite map iteration order.
	sortedFlows := sortFlowStates(flows)
	for _, fs := range sortedFlows {
		fs.flushStreams(payloads, opts.PayloadsPath)
		// Index reassembled TCP streams into the trigram index (one segment per
		// direction). The stream buffers are still on the FlowState after flush.
		if fs.c2sStream != nil && len(fs.c2sStream.buf) > 0 {
			analysis.Trigram.AddSegment(fs.FlowModel.ID, "c2s", fs.c2sStream.buf)
			// L7 parse on the c2s reassembled stream. Use the calibrated server
			// port (not FlowModel.DstPort, which reflects the first packet's dst
			// and may be the client port if capture started at the SYN-ACK).
			if res := l7reg.ParseStream(fs.serverPort, fs.c2sStream.buf); res != nil {
				fs.setL7(res, "c2s")
			}
		}
		if fs.s2cStream != nil && len(fs.s2cStream.buf) > 0 {
			analysis.Trigram.AddSegment(fs.FlowModel.ID, "s2c", fs.s2cStream.buf)
			if res := l7reg.ParseStream(fs.serverPort, fs.s2cStream.buf); res != nil {
				fs.setL7(res, "s2c")
			}
		}
	}

	// Finalize all flows at end-of-file (mid-stream FIN/RST/timeout
	// finalization is an optimization left for large-pcap tuning; v1 finalizes
	// at EOF, bounded by active-stream memory).
	for _, fs := range sortedFlows {
		fm, rem := fs.finalize()
		fm.ParserVersion = ParserVersion
		analysis.FlowCount++
		if err := forwardPackets(opts, analysis, rem); err != nil {
			return nil, err
		}
		if err := forwardFlow(opts, analysis, fm); err != nil {
			return nil, err
		}
	}
	// Persist the trigram index to disk if a path was given (§11/§16). The
	// in-memory index is also returned in analysis.Trigram for same-process use.
	if opts.TrigramIndexPath != "" && analysis.Trigram != nil {
		if _, err := analysis.Trigram.WriteToFile(opts.TrigramIndexPath); err != nil {
			// Non-fatal: search falls back to in-memory / rebuild. Log via the
			// returned analysis rather than failing the whole parse.
			analysis.TrigramWriteError = err
		}
	}
	return analysis, nil
}

// sortFlowStates returns the FlowState values sorted by FirstTsUs then ID, for
// deterministic output order.
func sortFlowStates(m map[string]*FlowState) []*FlowState {
	out := make([]*FlowState, 0, len(m))
	for _, fs := range m {
		out = append(out, fs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FlowModel.FirstTsUs != out[j].FlowModel.FirstTsUs {
			return out[i].FlowModel.FirstTsUs < out[j].FlowModel.FirstTsUs
		}
		return out[i].FlowModel.ID < out[j].FlowModel.ID
	})
	return out
}

// feedReassembledToAssembler parses a reassembled IP datagram and feeds its TCP
// layer to the assembler. Used after IP fragment reassembly (§8) so fragmented
// TCP segments are reassembled correctly. If the flow doesn't yet exist (a
// fully-fragmented flow where no non-fragmented packet created it, or the first
// fragment was never captured), it is created here from the reassembled datagram
// so the assembler has a stream to buffer into -- otherwise the reassembled
// bytes would be silently discarded (nullStream).
func feedReassembledToAssembler(asm *assemblerHelper, flows map[string]*FlowState, frame []byte, tsUs int64, opts *Options) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	fields := extractFields(pkt)
	if fields.l4Proto != "tcp" {
		return
	}
	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}
	key := computeFlowKey(fields)
	if key == "" {
		return
	}
	// Ensure the flow exists so the assembler's factory can find it.
	if _, ok := flows[key]; !ok {
		fs := newFlowState(uuid.New().String(), opts.PcapAssetID, opts.UserID, key, firstPacketInfo{
			SrcIP:     fields.srcIP.String(),
			DstIP:     fields.dstIP.String(),
			SrcPort:   fields.srcPort,
			DstPort:   fields.dstPort,
			L4Proto:   fields.l4Proto,
			IPVersion: fields.ipVersion,
			TsUs:      tsUs,
		})
		fs.setLayout(ExtractOffsetLayout(pkt))
		flows[key] = fs
	}
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return
	}
	asm.assemble(nl.NetworkFlow(), tcp, tsUs)
}

// openPcapReader opens a pcap (not pcapng) reader and returns the link type +
// snaplen. It peeks the magic to reject pcapng and gzip with clear errors:
//   - pcapng is not supported by the v1 block-unaware reader.
//   - gzip is rejected because RawOffset must be a byte offset into the file
//     (for dynamic re-parse + replay); a gzip stream's decompressed offsets do
//     not map back to file bytes. Callers must decompress to a plain .pcap first.
//
// It also raises the reader's snaplen to at least 65535 so pcaps written by
// tools that don't enforce snaplen (e.g. dpkt, which defaults to 1500 but writes
// full-size packets) don't trigger pcapgo's "capture length exceeds snap length"
// error on every packet.
func openPcapReader(f *os.File) (*pcapgo.Reader, layers.LinkType, uint32, error) {
	peek := make([]byte, 4)
	n, _ := f.Read(peek)
	if n < 4 {
		return nil, 0, 0, fmt.Errorf("file too small to be a pcap: %d bytes", n)
	}
	// Rewind so pcapgo.NewReader reads the full header.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, 0, fmt.Errorf("seek pcap start: %w", err)
	}
	// gzip magic 0x1f 0x8b (pcapgo would transparently decompress, but then
	// RawOffset arithmetic would point into the decompressed stream, not the
	// file -- breaking dynamic re-parse and replay).
	if peek[0] == 0x1f && peek[1] == 0x8b {
		return nil, 0, 0, fmt.Errorf("gzipped pcap not supported (RawOffset requires an uncompressed file); decompress first")
	}
	// pcapng section header block magic (0x0A0D0D0A) in either byte order.
	if (peek[0] == 0x0A && peek[1] == 0x0D && peek[2] == 0x0D && peek[3] == 0x0A) ||
		(peek[0] == 0x0D && peek[1] == 0x0A && peek[2] == 0x0A && peek[3] == 0x0D) {
		return nil, 0, 0, fmt.Errorf("pcapng not supported by v1 parser; convert to pcap")
	}
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("parse pcap header: %w", err)
	}
	if reader.Snaplen() < 65535 {
		reader.SetSnaplen(65535)
	}
	return reader, reader.LinkType(), reader.Snaplen(), nil
}

// forwardPackets delivers a packet batch to the sink, or appends to the
// analysis if no sink is configured.
func forwardPackets(opts *Options, analysis *PcapAnalysis, batch []storage.PacketModel) error {
	if len(batch) == 0 {
		return nil
	}
	if opts != nil && opts.PacketSink != nil {
		return opts.PacketSink(batch)
	}
	analysis.Packets = append(analysis.Packets, batch...)
	return nil
}

// forwardFlow delivers a finalized flow to the sink, or appends to the analysis.
func forwardFlow(opts *Options, analysis *PcapAnalysis, fm storage.FlowModel) error {
	if opts != nil && opts.FlowSink != nil {
		return opts.FlowSink(fm)
	}
	analysis.Flows = append(analysis.Flows, fm)
	return nil
}

// ProtocolDistJSON marshals the protocol distribution for storage in
// PcapAssetModel.ProtocolDist (JSON text column).
func (a *PcapAnalysis) ProtocolDistJSON() string {
	b, err := json.Marshal(a.ProtocolDist)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// DurationUs returns the capture span in microseconds.
func (a *PcapAnalysis) DurationUs() int64 {
	return a.LastTsUs - a.FirstTsUs
}
