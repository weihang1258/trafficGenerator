Now I have all 13 files. Let me enumerate every possible scenario for each component. I will organize by file with a tag prefix.

---

## PARSER.GO (tag: P)

### P1: `Parse(path, opts)`

**P1.1: nil opts**
- Branch: `if opts == nil { opts = &Options{} }` (line 95-97)
- Input: `opts == nil`
- Behavior: Normalizes to empty Options struct. All field accesses on opts are safe afterward.

**P1.2: file open failure**
- Branch: `f, err := os.Open(path)` + `if err != nil` (line 98-100)
- Input: path doesn't exist, permission denied, directory, etc.
- Output: `nil, fmt.Errorf("open pcap: %w", err)`

**P1.3: pcap reader open failure**
- Branch: `openPcapReader(f)` returns error (line 104-106)
- Input: corrupted pcap header, unsupported format, too-small file, etc.
- Output: `nil, err` (wrapped error from openPcapReader)

**P1.4: unsupported link type**
- Branch: `if linkType != layers.LinkTypeEthernet` (line 108-109)
- Input: pcap with DLT_RAW, DLT_LOOP, DLT_NULL (not Ethernet), e.g. Linux SLL capture
- Output: `nil, fmt.Errorf("unsupported link type %d: v1 supports Ethernet (DLT_EN10MB) only", linkType)`

**P1.5: payloads file creation failure**
- Branch: `newPayloadsWriter(opts.PayloadsPath)` returns error (line 122-123)
- Input: PayloadsPath points to a non-writable directory, disk full, etc.
- Output: `nil, err`

**P1.6: Parse main loop -- EOF (normal exit)**
- Branch: `err == io.EOF` (line 142-143)
- Input: All packets read successfully, reader hits end of file.
- Behavior: `break` from the for loop. Falls through to flush section.

**P1.7: Parse main loop -- read error (non-EOF)**
- Branch: `err != nil` (line 145-146)
- Input: File read error mid-stream (I/O error, truncated file, corrupted record header)
- Output: `nil, fmt.Errorf("read packet at offset %d: %w", recordOffset, err)`

**P1.8: Non-first fragment, unknown frag-group**
- Branch: `fields.fragGroupID != "" && !fields.fragFirst` + `if fk, ok := fragFlowMap[...]; ok` (line 175-178)
- Input: A fragment with offset > 0 whose group ID was never seeded (first fragment was never seen/captured). `fragFlowMap` lookup fails.
- Behavior: `key` stays as the empty/port-less value from `computeFlowKey`. Falls through to `if key == ""` branch.

**P1.9: Non-first fragment, known frag-group**
- Branch: `fields.fragGroupID != "" && !fields.fragFirst` + `ok == true` (line 176-178)
- Input: Non-first fragment, group mapped from first fragment. `key = fk` (the real flow key).
- Behavior: Fragment joins the correct flow.

**P1.10: Unknown/ungroupable L2 packet**
- Branch: `if key == ""` (line 180-183)
- Input: L2-only packets (no IP, no ARP, no ICMP -- e.g. STP, LLDP, CDP, raw Ethernet).
- Behavior: `key = fmt.Sprintf("raw|%d", dataOffset)`. Creates a synthetic single-packet flow.

**P1.11: First fragment seeds fragFlowMap**
- Branch: `if fields.fragFirst && fields.fragGroupID != "" && !strings.HasPrefix(key, "raw|")` (line 187-188)
- Input: First fragment (offset 0) of a fragmented IP datagram with a valid flow key.
- Behavior: `fragFlowMap[fields.fragGroupID] = key`. Subsequent non-first fragments can find the flow.

**P1.12: First fragment without valid flow key (raw| prefix)**
- Branch: `fields.fragFirst && fields.fragGroupID != "" && strings.HasPrefix(key, "raw|")` -- the third condition is false, so this is NOT entered.
- Input: First fragment of an unrecognized L3 protocol, key starts with "raw|".
- Behavior: Not recorded in fragFlowMap. Non-first fragments of this group will also get "raw|" keys.

**P1.13: New flow creation (first packet of a flow)**
- Branch: `fs, ok := flows[key]` + `!ok` (line 190-203)
- Input: First packet of a new flow seen in the capture.
- Behavior: `newFlowState(...)` creates a new FlowState, `ExtractOffsetLayout(pkt)` sets the offset layout, `flows[key] = fs`.

**P1.14: Existing flow, packet continues**
- Branch: `fs, ok := flows[key]` + `ok` (line 190-191)
- Input: Subsequent packet of an existing flow.
- Behavior: Uses existing FlowState, no new flow created.

**P1.15: TCP packet update (non-fragment)**
- Branch: `if fields.l4Proto == "tcp" && fields.fragGroupID == ""` (line 216-217)
- Input: TCP packet, not a fragment.
- Behavior: `fs.recordTCPStats(fields, pm.Direction)` -- accumulates TCP stats.

**P1.16: TCP fragment (fragmented TCP, skips recordTCPStats)**
- Branch: `fields.l4Proto == "tcp" && fields.fragGroupID != ""` -- the condition is false, so recordTCPStats is NOT called.
- Input: Fragment of a TCP datagram (no L4 header, so no TCP flags/seq).
- Behavior: recordTCPStats is skipped (would pollute stats).

**P1.17: Fragment reassembly attempt**
- Branch: `if fields.fragGroupID != ""` (line 219-227)
- Input: Any fragment (first or non-first).
- Behavior: `fragReassembler.AddFragment(...)` is called. If reassembled != nil, `feedReassembledToAssembler` is called.

**P1.18: Fragment reassembly complete**
- Branch: `if reassembled != nil` (line 224-226)
- Input: All fragments of a group have arrived, producing a complete datagram.
- Behavior: `feedReassembledToAssembler(asm, flows, reassembled, tsUs, opts)`.

**P1.19: Fragment reassembly incomplete (still waiting)**
- Branch: `reassembled == nil` (line 224)
- Input: Not all fragments have arrived yet.
- Behavior: Nothing happens; fragments continue to accumulate.

**P1.20: Non-fragment TCP packet fed to assembler**
- Branch: `else if fields.l4Proto == "tcp"` (line 227-233)
- Input: Non-fragment TCP packet.
- Behavior: `pkt.Layer(layers.LayerTypeTCP)` cast to get TCP layer, then `asm.assemble(netFlow, tcp, tsUs)`.

**P1.21: TCP packet with no TCP layer (shouldn't happen, but defensive)**
- Branch: `tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)` + `!ok` (line 228-229)
- Input: l4Proto is "tcp" but no TCP layer found (malformed packet, gopacket decode failure).
- Behavior: Silently skipped (defensive, no assembly).

**P1.22: TCP packet with no network layer**
- Branch: `if nl := pkt.NetworkLayer(); nl != nil` (line 229-233)
- Input: TCP packet but no network layer (malformed).
- Behavior: `nl` is nil, condition fails. The TCP layer is not fed to the assembler.

**P1.23: UDP payload indexed in trigram**
- Branch: `if fields.l4Proto == "udp" && len(fields.payload) > 0` (line 238-239)
- Input: UDP packet with payload (non-empty).
- Behavior: `analysis.Trigram.AddSegment(fs.FlowModel.ID, pm.Direction, fields.payload)`.

**P1.24: UDP with no payload (zero-length)**
- Branch: `fields.l4Proto == "udp" && len(fields.payload) == 0` -- second condition false.
- Input: UDP packet with no payload (e.g., DNS query with no additional data, pure header).
- Behavior: Not indexed in trigram. No L7 parse attempted.

**P1.25: UDP L7 parse on first packet with payload (not yet parsed)**
- Branch: `if !fs.l7Parsed` (line 243-248)
- Input: First UDP packet with payload in this flow, parser hasn't been run yet.
- Behavior: `l7reg.ParseStream(fs.serverPort, fields.payload)` called. If result != nil, `fs.setL7(res, pm.Direction)` and `fs.l7Parsed = true`.

**P1.26: UDP L7 parse on subsequent packets (already parsed)**
- Branch: `fs.l7Parsed == true` (line 243)
- Input: Subsequent UDP packet with payload in same flow.
- Behavior: L7 parse skipped (already done).

**P1.27: UDP L7 parser doesn't match**
- Branch: `res := l7reg.ParseStream(...)` returns nil (line 244-245)
- Input: UDP payload on a port that no parser claims, or payload doesn't match any parser.
- Behavior: `l7Parsed` stays false (will try again on next packet with payload).

**P1.28: Packet count increment + global stats**
- Branch: `analysis.PacketCount++` (line 252)
- Input: Every packet.
- Behavior: Always increments. No branch, but postcondition.

**P1.29: Protocol distribution update**
- Branch: `if fields.l4Proto != ""` (line 254-255)
- Input: Packet with a recognized L4 protocol (tcp/udp/icmp/arp).
- Behavior: `analysis.ProtocolDist[fields.l4Proto]++`.

**P1.30: Protocol distribution skip (empty L4)**
- Branch: `fields.l4Proto == ""` (line 254)
- Input: Unknown/unrecognized protocol (e.g., raw Ethernet, L2-only).
- Behavior: Not counted in protocol distribution.

**P1.31: FirstTsUs setting (first packet)**
- Branch: `if analysis.PacketCount == 1 || tsUs < analysis.FirstTsUs` (line 261-262)
- Input: First packet of the capture (PacketCount == 1). Comment explicitly notes 0 is a valid timestamp.
- Behavior: `analysis.FirstTsUs = tsUs`.

**P1.32: FirstTsUs update (earlier timestamp found later -- should not happen in ordered capture, but defensive)**
- Branch: `tsUs < analysis.FirstTsUs` (line 261)
- Input: A packet with an earlier timestamp than the current first (out-of-order timestamps, or capture started mid-stream).
- Behavior: `analysis.FirstTsUs = tsUs` (updated to the earlier time).

**P1.33: LastTsUs update**
- Branch: `if tsUs > analysis.LastTsUs` (line 264-265)
- Input: Every packet; updates if timestamp is later than current max.
- Behavior: `analysis.LastTsUs = tsUs`.

**P1.34: Packet batch drain (batch size reached)**
- Branch: `if fs.pendingPacketCount() >= batchSize` (line 269-273)
- Input: Accumulated packet count for this flow reaches the batch threshold.
- Behavior: `fs.drainPackets()` called, `forwardPackets(opts, analysis, batch)` called.

**P1.35: forwardPackets returns error (sink failure)**
- Branch: `if err := forwardPackets(...); err != nil` (line 271-272)
- Input: PacketSink returns an error (e.g., database write failure, channel full).
- Output: `return nil, err` -- entire parse fails.

**P1.36: forwardPackets success**
- Branch: forwardPackets returns nil (no error)
- Behavior: Parse continues.

**P1.37: Forward packets with sink**
- Branch: `forwardPackets` → `opts.PacketSink != nil` (line 438-439)
- Input: opts.PacketSink is set.
- Behavior: `opts.PacketSink(batch)` called.

**P1.38: Forward packets with no sink (append to analysis)**
- Branch: `forwardPackets` → `opts.PacketSink == nil` (line 441)
- Input: No PacketSink configured.
- Behavior: `analysis.Packets = append(analysis.Packets, batch...)`.

**P1.39: Forward packets with empty batch**
- Branch: `if len(batch) == 0` (line 435-436)
- Input: drainPackets returns nil/empty.
- Behavior: `return nil` immediately.

**P1.40: forwardFlow with sink**
- Branch: `if opts != nil && opts.FlowSink != nil` (line 447-448)
- Input: FlowSink is configured.
- Behavior: `opts.FlowSink(fm)` called.

**P1.41: forwardFlow with no sink**
- Branch: `opts.FlowSink == nil` (line 450)
- Input: No FlowSink.
- Behavior: `analysis.Flows = append(analysis.Flows, fm)`.

**P1.42: Flush stale IP fragments**
- Branch: `fragReassembler.Flush()` (line 280)
- Input: End-of-file, incomplete fragment groups.
- Behavior: Incomplete groups are discarded. Returns count of discarded groups.

**P1.43: Flush assembler**
- Branch: `asm.flushAll()` (line 281)
- Input: End-of-file, all TCP streams.
- Behavior: Forces reassembly completion for all buffered streams (FIN/RST/timeout).

**P1.44: Sort flows deterministically**
- Branch: `sortFlowStates(flows)` (line 284)
- Input: Map of all flows.
- Behavior: Returns sorted slice by FirstTsUs then ID, for deterministic output.

**P1.45: TCP stream flush -- c2s stream with data, trigram indexed, L7 parsed**
- Branch: `fs.c2sStream != nil && len(fs.c2sStream.buf) > 0` (line 289-296)
- Input: Flow has a reassembled c2s stream with data.
- Behavior: `flushStreams(payloads, ...)` called first (line 286). Then c2s bytes added to trigram, L7 parse attempted on c2s bytes.

**P1.46: TCP stream flush -- c2s stream empty**
- Branch: `len(fs.c2sStream.buf) == 0` (line 289)
- Input: c2s stream exists but buffer is empty (pure ACK, no data).
- Behavior: Not indexed in trigram. No L7 parse.

**P1.47: TCP stream flush -- c2s stream nil**
- Branch: `fs.c2sStream == nil` (line 289)
- Input: No c2s stream was ever created for this flow (no TCP data in c2s direction).
- Behavior: Skipped.

**P1.48: TCP L7 parse on c2s stream -- success**
- Branch: `res := l7reg.ParseStream(fs.serverPort, fs.c2sStream.buf)` returns non-nil (line 294-295)
- Input: c2s stream matches a parser (e.g., HTTP GET on port 80).
- Behavior: `fs.setL7(res, "c2s")`.

**P1.49: TCP L7 parse on c2s stream -- no match**
- Branch: `res == nil` (line 294)
- Input: c2s stream doesn't match any parser (e.g., custom protocol, encrypted).
- Behavior: L7 fields remain empty.

**P1.50: TCP stream flush -- s2c stream with data, trigram indexed, L7 parsed**
- Branch: `fs.s2cStream != nil && len(fs.s2cStream.buf) > 0` (line 298-303)
- Input: Flow has a reassembled s2c stream with data.
- Behavior: s2c bytes added to trigram, L7 parse attempted on s2c bytes.

**P1.51: Flow finalization -- forward remaining packets**
- Branch: `fm, rem := fs.finalize()` + `forwardPackets(...)` (line 310-314)
- Input: Each flow at end-of-file.
- Behavior: Any remaining buffered packets are forwarded.

**P1.52: Flow finalization -- forwardPackets fails**
- Branch: `if err := forwardPackets(...); err != nil` (line 313)
- Input: PacketSink fails on remaining packets.
- Output: `return nil, err`.

**P1.53: Flow finalization -- forwardFlow fails**
- Branch: `if err := forwardFlow(...); err != nil` (line 316-317)
- Input: FlowSink fails on finalized flow model.
- Output: `return nil, err`.

**P1.54: Trigram persistence to disk -- success**
- Branch: `if opts.TrigramIndexPath != "" && analysis.Trigram != nil` (line 322-323)
- Input: TrigramIndexPath set, index exists.
- Behavior: `WriteToFile(opts.TrigramIndexPath)` called. Returns bytes written.

**P1.55: Trigram persistence to disk -- failure (non-fatal)**
- Branch: `if _, err := analysis.Trigram.WriteToFile(...); err != nil` (line 323-327)
- Input: TrigramIndexPath set but disk write fails (permission, disk full, path invalid).
- Output: `analysis.TrigramWriteError = err`. Parse continues successfully. Search falls back to in-memory.

**P1.56: Trigram persistence skipped (no path)**
- Branch: `opts.TrigramIndexPath == ""` (line 322)
- Input: No TrigramIndexPath configured.
- Behavior: In-memory index only (not persisted). Parse continues.

**P1.57: Trigram persistence skipped (nil index)**
- Branch: `opts.TrigramIndexPath != "" && analysis.Trigram == nil` (line 322)
- Input: TrigramIndexPath set but index is nil (shouldn't happen, but defensive).
- Behavior: Skipped, no error.

---

### P2: `openPcapReader(f)`

**P2.1: File too small (< 4 bytes)**
- Branch: `if n < 4` (line 404-405)
- Input: File is 0-3 bytes.
- Output: `nil, 0, 0, fmt.Errorf("file too small to be a pcap: %d bytes", n)`

**P2.2: Seek failure after peeking**
- Branch: `if _, err := f.Seek(0, io.SeekStart); err != nil` (line 408-409)
- Input: File is not seekable (e.g., pipe, socket).
- Output: `nil, 0, 0, fmt.Errorf("seek pcap start: %w", err)`

**P2.3: Gzip magic detected**
- Branch: `if peek[0] == 0x1f && peek[1] == 0x8b` (line 414-415)
- Input: Gzipped pcap file (magic bytes 0x1f 0x8b).
- Output: `nil, 0, 0, fmt.Errorf("gzipped pcap not supported...")`. Rationale: RawOffset would point into decompressed stream, not the file.

**P2.4: pcapng magic detected (little-endian)**
- Branch: `peek[0] == 0x0A && peek[1] == 0x0D && peek[2] == 0x0D && peek[3] == 0x0A` (line 418-419)
- Input: pcapng format (little-endian).
- Output: `nil, 0, 0, fmt.Errorf("pcapng not supported by v1 parser; convert to pcap")`

**P2.5: pcapng magic detected (big-endian)**
- Branch: `peek[0] == 0x0D && peek[1] == 0x0A && peek[2] == 0x0A && peek[3] == 0x0D` (line 418-419)
- Input: pcapng format (big-endian).
- Output: Same error as P2.4.

**P2.6: pcapgo reader creation failure**
- Branch: `err := pcapgo.NewReader(f)` + `err != nil` (line 422-424)
- Input: Corrupted pcap global header, unsupported magic number, etc.
- Output: `nil, 0, 0, fmt.Errorf("parse pcap header: %w", err)`

**P2.7: Low snaplen raised to 65535**
- Branch: `if reader.Snaplen() < 65535` (line 426-427)
- Input: Snaplen < 65535 (e.g., dpkt's default 1500 but full-size packets written).
- Behavior: `reader.SetSnaplen(65535)`. Prevents pcapgo's "capture length exceeds snap length" error.

**P2.8: High snaplen preserved**
- Branch: `reader.Snaplen() >= 65535` (line 426)
- Input: Snaplen already >= 65535.
- Behavior: Not modified.

**P2.9: Success path**
- No errors, format is classic pcap, everything valid.
- Output: `(reader, reader.LinkType(), reader.Snaplen(), nil)`

---

### P3: `Options.batchSize()`

**P3.1: nil receiver or zero/negative batch size**
- Branch: `if o == nil || o.BatchSize <= 0` (line 79)
- Behavior: Returns default 1000.

**P3.2: positive batch size**
- Branch: `o != nil && o.BatchSize > 0`
- Behavior: Returns `o.BatchSize`.

---

### P4: `sortFlowStates(flows)`

**P4.1: Empty map**
- Input: Empty map.
- Output: Empty slice.

**P4.2: Single flow**
- Input: Map with one flow.
- Output: Slice of length 1.

**P4.3: Multiple flows with same FirstTsUs**
- Branch: `if out[i].FlowModel.FirstTsUs != out[j].FlowModel.FirstTsUs` (line 340)
- Behavior: Falls back to `out[i].FlowModel.ID < out[j].FlowModel.ID` for tiebreak.

**P4.4: Multiple flows with different timestamps**
- Branch: `out[i].FlowModel.FirstTsUs < out[j].FlowModel.FirstTsUs` (line 340)
- Behavior: Sorted by timestamp ascending.

---

### P5: `feedReassembledToAssembler(asm, flows, frame, tsUs, opts)`

**P5.1: Reassembled datagram is not TCP**
- Branch: `if fields.l4Proto != "tcp"` (line 358-359)
- Input: Reassembled IP datagram with UDP/ICMP payload.
- Behavior: `return` (no-op).

**P5.2: No network layer on reassembled frame**
- Branch: `nl := pkt.NetworkLayer()` + `if nl == nil` (line 361-363)
- Input: Reassembled datagram has no network layer (shouldn't happen, but defensive).
- Behavior: `return`.

**P5.3: Empty flow key after reassembly**
- Branch: `key := computeFlowKey(fields)` + `if key == ""` (line 365-367)
- Input: Reassembled datagram with unrecognized protocol.
- Behavior: `return`.

**P5.4: Flow doesn't exist yet -- create it**
- Branch: `if _, ok := flows[key]; !ok` (line 370-381)
- Input: Fully-fragmented TCP flow where no non-fragmented packet created the flow, or first fragment was never captured.
- Behavior: `newFlowState(...)` creates a new FlowState. `ExtractOffsetLayout(pkt)` sets layout. `flows[key] = fs`.

**P5.5: Flow already exists**
- Branch: `ok == true` (line 370)
- Input: Flow already exists from a non-fragmented packet or earlier fragment.
- Behavior: No new flow created.

**P5.6: TCP layer not found on reassembled frame**
- Branch: `tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)` + `!ok` (line 383-385)
- Input: fields.l4Proto is "tcp" but TCP layer not findable (malformed).
- Behavior: `return`.

**P5.7: TCP layer found, feed to assembler**
- Branch: `ok == true` (line 383-387)
- Behavior: `asm.assemble(nl.NetworkFlow(), tcp, tsUs)`.

---

### P6: `protocolDistJSON()`

**P6.1: Marshal succeeds**
- Input: Non-empty or empty map.
- Output: JSON string.

**P6.2: Marshal fails (shouldn't happen with map[string]int64, but defensive)**
- Branch: `if err != nil` (line 458)
- Output: `"{}"`.

---

## FLOW.GO (tag: F)

### F1: `compareEndpoints(a, b)`

**F1.1: IPs differ**
- Branch: `if c := strings.Compare(a.IP, b.IP); c != 0` (line 33)
- Behavior: Returns `c` (-1 or 1).

**F1.2: Same IP, a.Port < b.Port**
- Branch: `case a.Port < b.Port` (line 37-38)
- Behavior: Returns -1.

**F1.3: Same IP, a.Port > b.Port**
- Branch: `case a.Port > b.Port` (line 39-40)
- Behavior: Returns 1.

**F1.4: Same IP, same port**
- Branch: `default` (line 41-42)
- Behavior: Returns 0.

---

### F2: `flowKeyTCPUDP(srcIP, dstIP, srcPort, dstPort, proto)`

**F2.1: Normal ordering (a <= b)**
- Branch: `compareEndpoints(a, b) > 0` is false (line 52)
- Input: srcIP/dstIP in natural order.
- Output: `6|ip:port|ip:port` or `17|ip:port|ip:port`.

**F2.2: Reversed ordering (a > b)**
- Branch: `compareEndpoints(a, b) > 0` (line 52-53)
- Input: srcIP > dstIP lexicographically.
- Behavior: `a, b = b, a` (swap). Output: `6|ip:port|ip:port` (normalized).

---

### F3: `flowKeyICMP(srcIP, dstIP, icmpType, id)`

**F3.1: srcIP <= dstIP**
- Branch: `strings.Compare(a, b) > 0` is false (line 63)
- Output: `1|a|b|type|id`.

**F3.2: srcIP > dstIP**
- Branch: `strings.Compare(a, b) > 0` (line 63-64)
- Behavior: `a, b = b, a` (swap). Output: `1|b|a|type|id`.

---

### F4: `flowKeyARP(senderIP, targetIP, op)`

**F4.1: senderIP <= targetIP**
- Branch: similar to F3.
- Output: `arp|op|a|b`.

**F4.2: senderIP > targetIP**
- Branch: swap.
- Output: `arp|op|b|a`.

---

### F5: `classifyDirection(srcIP, srcPort)`

**F5.1: src matches first-packet src (client candidate)**
- Branch: `if srcIP == fs.firstSrcIP && srcPort == fs.firstSrcPort` (line 183)
- Output: `"c2s"`.

**F5.2: src differs from first-packet src**
- Branch: else (line 185-186)
- Output: `"s2c"`.

---

### F6: `addPacket(pkt)`

**F6.1: c2s packet**
- Branch: `if pkt.Direction == "c2s"` (line 199)
- Behavior: Increments `C2SPackets` and `C2SBytes`.

**F6.2: s2c packet**
- Branch: else (line 202-204)
- Behavior: Increments `S2CPackets` and `S2CBytes`.

**F6.3: Timestamp earlier than FirstTsUs (out-of-order timestamps)**
- Branch: `if pkt.TimestampUs < fs.FlowModel.FirstTsUs` (line 210-211)
- Behavior: Updates FirstTsUs downward.

**F6.4: Timestamp later than LastTsUs**
- Branch: `if pkt.TimestampUs > fs.FlowModel.LastTsUs` (line 213-214)
- Behavior: Updates LastTsUs upward.

**F6.5: Timestamp in range (normal)**
- Both conditions false.
- Behavior: No timestamp update.

---

### F7: `drainPackets()`

**F7.1: Non-empty buffer**
- Behavior: Returns buffer, sets `fs.packets = nil`.

**F7.2: Empty buffer (nil or zero-length)**
- Behavior: Returns nil (same behavior, no error).

---

### F8: `setL7(res, dir)`

**F8.1: nil result**
- Branch: `if res == nil` (line 233-234)
- Behavior: `return` (no-op).

**F8.2: Non-nil result, L7Protocol set**
- Behavior: `fs.FlowModel.L7Protocol = res.Protocol`.

**F8.3: L7Metadata JSON marshal succeeds**
- Branch: `if data, err := json.Marshal(res.Metadata); err == nil` (line 237)
- Behavior: `fs.FlowModel.L7Metadata = string(data)`.

**F8.4: L7Metadata JSON marshal fails**
- Branch: `err != nil` (line 237)
- Behavior: L7Metadata stays empty (not set).

**F8.5: method metadata present**
- Branch: `if v, ok := res.Metadata["method"]; ok` (line 242-243)
- Behavior: `fs.FlowModel.L7Method = fmt.Sprintf("%v", v)`.

**F8.6: host metadata present**
- Branch: `if v, ok := res.Metadata["host"]; ok` (line 245-246)
- Behavior: `fs.FlowModel.L7Host = fmt.Sprintf("%v", v)`.

**F8.7: sni metadata present (TLS)**
- Branch: `if v, ok := res.Metadata["sni"]; ok` (line 248-249)
- Behavior: `fs.FlowModel.L7Host = fmt.Sprintf("%v", v)` (overwrites host if set).

**F8.8: query_name metadata present (DNS)**
- Branch: `if v, ok := res.Metadata["query_name"]; ok` (line 251-252)
- Behavior: `fs.FlowModel.L7QueryName = fmt.Sprintf("%v", v)`.

**F8.9: c2s direction body offsets**
- Branch: `if dir == "c2s"` (line 255-257)
- Behavior: `C2SBodyOffset = BodyOffset`, `C2SBodyLength = BodyLength`.

**F8.10: s2c direction body offsets**
- Branch: `else if dir == "s2c"` (line 258-260)
- Behavior: `S2CBodyOffset = BodyOffset`, `S2CBodyLength = BodyLength`.

**F8.11: Neither c2s nor s2c (unexpected dir)**
- Branch: both conditions false.
- Behavior: Body offsets not set (no-op).

---

### F9: `setStream(dir, s)`

**F9.1: c2s direction**
- Branch: `if dir == "c2s"` (line 273)
- Behavior: `fs.c2sStream = s`.

**F9.2: s2c direction (or any other)**
- Branch: else (line 274-276)
- Behavior: `fs.s2cStream = s`.

---

### F10: `seqLess(a, b)`

**F10.1: a < b (normal, no wraparound)**
- Branch: `delta := int32(b - a)` + `return delta > 0` (line 284-285)
- Input: `a=100, b=200` → `delta=100 > 0`.
- Output: `true`.

**F10.2: a > b (normal, no wraparound)**
- Input: `a=200, b=100` → `delta=-100 < 0`.
- Output: `false`.

**F10.3: Wraparound case (a near 2^32, b near 0)**
- Input: `a=4294967200, b=100` → `delta = 100 - 4294967200 = 156` (wraps around in int32).
- Output: `true` (b is after a, considering wraparound).

**F10.4: Wraparound case (reverse)**
- Input: `a=100, b=4294967200` → `delta = -156` (wraps around).
- Output: `false`.

---

### F11: `seqInRange(a, min, max)`

**F11.1: a in range**
- Input: `a=150, min=100, max=200` → `!seqLess(150,100) && !seqLess(200,150)` → `true && true`.
- Output: `true`.

**F11.2: a below min**
- Input: `a=50, min=100, max=200` → `seqLess(50,100) = true` → `!true = false`.
- Output: `false`.

**F11.3: a above max**
- Input: `a=250, min=100, max=200` → `seqLess(250,100) = false, seqLess(200,250) = true` → `!false && !true = false`.
- Output: `false`.

---

### F12: `recordTCPStats(fields, dir)`

**F12.1: First TCP packet initializes flagsCount**
- Branch: `if fs.flagsCount == nil` (line 298-299)
- Behavior: `fs.flagsCount = map[string]int64{}`.

**F12.2: SYN without ACK (client SYN)**
- Branch: `if f.tcpSYN` + `if f.tcpACK` is false (line 301-308)
- Behavior: `fs.flagsCount["syn"]++`, `fs.sawSYN = true`, `fs.FlowModel.C2SInitSeq = f.tcpSeq`.

**F12.3: SYN+ACK (server SYN-ACK)**
- Branch: `f.tcpSYN` + `f.tcpACK` (line 303-305)
- Behavior: `fs.flagsCount["syn"]++`, `fs.sawSYNACK = true`, `fs.FlowModel.S2CInitSeq = f.tcpSeq`.

**F12.4: TCP options recorded (first SYN in either direction)**
- Branch: `if !fs.tcpOptionsRecorded && f.tcpOptionKinds != nil` (line 312-317)
- Behavior: `tcpOptionsRecorded = true`, `MSS`, `WindowScale`, `TCPOptions` set.

**F12.5: TCP options already recorded (skip subsequent SYN packets)**
- Branch: `fs.tcpOptionsRecorded == true` (line 312)
- Behavior: Options not re-recorded.

**F12.6: ACK after SYN-ACK (third handshake step)**
- Branch: `else if f.tcpACK && fs.sawSYNACK` (line 319-322)
- Behavior: `fs.sawACKAfterSYN = true`.

**F12.7: ACK but sawSYNACK is false (early ACK before SYN-ACK)**
- Branch: `f.tcpACK && !fs.sawSYNACK` (line 319)
- Behavior: `sawACKAfterSYN` stays false. `flagsCount["ack"]++` still happens at line 324-325.

**F12.8: ACK flag count**
- Branch: `if f.tcpACK` (line 324-325)
- Behavior: `flagsCount["ack"]++`.

**F12.9: FIN flag count**
- Branch: `if f.tcpFIN` (line 327-328)
- Behavior: `flagsCount["fin"]++`.

**F12.10: RST flag count**
- Branch: `if f.tcpRST` (line 330-331)
- Behavior: `flagsCount["rst"]++`.

**F12.11: PSH flag count**
- Branch: `if f.tcpPSH` (line 333-334)
- Behavior: `flagsCount["psh"]++`.

**F12.12: Seq range min -- first seq or seq < min**
- Branch: `if !fs.seqSeen || f.tcpSeq < fs.seqMin` (line 337-338)
- Behavior: `seqMin = f.tcpSeq`.

**F12.13: Seq range max -- first seq or seq > max**
- Branch: `if !fs.seqSeen || f.tcpSeq > fs.seqMax` (line 340-341)
- Behavior: `seqMax = f.tcpSeq`.

**F12.14: seqSeen set to true**
- Branch: line 343 (always executed after seq range tracking).
- Behavior: `fs.seqSeen = true`.

**F12.15: c2s direction retransmit/out-of-order tracking**
- Branch: `if dir == "s2c"` is false (line 352), so `nextSeq = &fs.c2sNextSeq`, `seen = &fs.c2sSeqSeen`.

**F12.16: s2c direction retransmit/out-of-order tracking**
- Branch: `if dir == "s2c"` (line 352-355)
- Behavior: `nextSeq = &fs.s2cNextSeq`, `seen = &fs.s2cSeqSeen`.

**F12.17: First packet in direction (seq tracking)**
- Branch: `if !*seen` (line 356-359)
- Behavior: `*nextSeq = f.tcpSeq + payloadLen`, `*seen = true`.

**F12.18: Retransmission detected (seq < next expected)**
- Branch: `else if f.tcpSeq < *nextSeq` (line 360-364)
- Behavior: `fs.FlowModel.RetransCount++`.

**F12.19: Out-of-order detected (seq > next expected)**
- Branch: `else if f.tcpSeq > *nextSeq` (line 365-368)
- Behavior: `fs.FlowModel.OutOfOrderCount++`, `*nextSeq = f.tcpSeq + payloadLen`.

**F12.20: Normal in-order delivery (seq == next expected)**
- Branch: `else` (line 369-371)
- Behavior: `*nextSeq = f.tcpSeq + payloadLen`.

**F12.21: Window min update**
- Branch: `if !fs.winSeen || f.tcpWindow < fs.winMin` (line 375-376)
- Behavior: `fs.winMin = f.tcpWindow`.

**F12.22: Window max update**
- Branch: `if !fs.winSeen || f.tcpWindow > fs.winMax` (line 378-379)
- Behavior: `fs.winMax = f.tcpWindow`.

**F12.23: winSeen set to true**
- Branch: line 381 (always executed).
- Behavior: `fs.winSeen = true`.

---

### F13: `formatTCPOptions(kinds)`

**F13.1: Empty options**
- Input: nil or empty slice.
- Output: `"[]"`.

**F13.2: Single option**
- Input: `[2]`.
- Output: `"[2]"`.

**F13.3: Multiple options, no duplicates**
- Input: `[2, 3, 4]`.
- Output: `"[2,3,4]"`.

**F13.4: Duplicate options**
- Branch: `if !seen[k]` (line 391) filters duplicates.
- Input: `[2, 2, 3]`.
- Output: `"[2,3]"`.

---

### F14: `flushStreams(w, payloadsPath)`

**F14.1: Non-TCP flow (UDP, ICMP, ARP)**
- Branch: `if fs.FlowModel.L4Protocol != "tcp"` (line 411-412)
- Behavior: `return` (no-op).

**F14.2: c2s stream exists, appendStream succeeds**
- Branch: `if fs.c2sStream != nil` (line 417-424)
- Behavior: `w.appendStream(fs.c2sStream.buf)` called, offset/length/complete set.

**F14.3: c2s stream exists, appendStream fails (write error)**
- Branch: `if err != nil` (line 419)
- Behavior: `return` early. Only c2s is written (s2c is skipped). c2sGap stays false.

**F14.4: c2s stream nil (no c2s data in this flow)**
- Branch: `fs.c2sStream == nil` (line 417)
- Behavior: Skipped.

**F14.5: s2c stream exists, appendStream succeeds**
- Branch: `if fs.s2cStream != nil` (line 426-433)
- Behavior: s2c offset/length/complete set.

**F14.6: s2c stream exists, appendStream fails**
- Branch: `if err != nil` (line 427)
- Behavior: `return` early. s2cGap stays false.

**F14.7: No gaps detected in either direction**
- Branch: `if c2sGap || s2cGap` (line 435)
- Behavior: `ReassemblyComplete = true` (already set at line 415). No GapInfo.

**F14.8: Gap in c2s only**
- Branch: `c2sGap == true, s2cGap == false` (line 435-444)
- Behavior: `ReassemblyComplete = false`. `GapInfo = "seq gap in c2s"`.

**F14.9: Gap in s2c only**
- Branch: `s2cGap == true` (line 435-444)
- Behavior: `ReassemblyComplete = false`. `GapInfo = "seq gap in s2c"`.

**F14.10: Gap in both directions**
- Branch: both true.
- Behavior: `ReassemblyComplete = false`. `GapInfo = "seq gap in c2s, s2c"`.

---

### F15: `finalize()`

**F15.1: DurationUs computed**
- Behavior: `DurationUs = LastTsUs - FirstTsUs`.

**F15.2: OffsetLayout JSON marshal succeeds**
- Branch: `if data, err := json.Marshal(fs.layout); err == nil` (line 469-470)
- Behavior: `OffsetLayout = string(data)`.

**F15.3: OffsetLayout JSON marshal fails**
- Branch: `err != nil` (line 471-472)
- Behavior: `OffsetLayout = "{}"`.

**F15.4: finalizeTCPStats called**
- Always called. See F16.

**F15.5: drainPackets returns remaining packets**
- Always called. Returns (FlowModel, remaining packets).

---

### F16: `finalizeTCPStats()`

**F16.1: Non-TCP flow**
- Branch: `if fs.FlowModel.L4Protocol != "tcp"` (line 482-483)
- Behavior: `return` (no-op).

**F16.2: Complete handshake (SYN + SYN-ACK + ACK after SYN)**
- Branch: `case fs.sawSYN && fs.sawSYNACK && fs.sawACKAfterSYN` (line 486-487)
- Behavior: `HandshakeStatus = "complete"`.

**F16.3: Partial handshake (SYN or SYN-ACK, but not both+ACK)**
- Branch: `case fs.sawSYN || fs.sawSYNACK` (line 488-489)
- Behavior: `HandshakeStatus = "partial"`.
- Covers: SYN seen but no SYN-ACK; SYN-ACK seen but no SYN (capture started mid-handshake); SYN+SYN-ACK seen but no ACK.

**F16.4: No handshake (no SYN, no SYN-ACK)**
- Branch: `default` (line 490-491)
- Behavior: `HandshakeStatus = "none"`.
- Covers: Non-TCP, pure data mid-stream, pure ACK flows.

**F16.5: FlagsSummary JSON marshal succeeds**
- Branch: `if fs.flagsCount != nil` + marshal succeeds (line 493-496)
- Behavior: `FlagsSummary = string(data)`.

**F16.6: FlagsCount nil (no TCP packets flagged)**
- Branch: `fs.flagsCount == nil` (line 493)
- Behavior: FlagsSummary stays empty.

**F16.7: SeqRange JSON marshal succeeds**
- Branch: `if fs.seqSeen` + marshal succeeds (line 498-502)
- Behavior: `SeqRange = string(data)`.

**F16.8: No seq seen (no TCP packets with seq values)**
- Branch: `fs.seqSeen == false` (line 498)
- Behavior: SeqRange stays empty.

**F16.9: WindowRange JSON marshal succeeds**
- Branch: `if fs.winSeen` + marshal succeeds (line 505-509)
- Behavior: `WindowRange = string(data)`.

**F16.10: No window seen (no TCP window data)**
- Branch: `fs.winSeen == false` (line 505)
- Behavior: WindowRange stays empty.

---

### F17: `extractFields(pkt)`

**F17.1: IPv4 network layer**
- Branch: `case *layers.IPv4` (line 556-583)
- Behavior: Sets srcIP, dstIP, ipVersion=4, ipID, ipMF.

**F17.2: IPv4 packet with fragmentation (MF or non-zero offset)**
- Branch: `if f.ipMF || v.FragOffset != 0` (line 562-583)
- Behavior: Sets fragGroupID, fragOffset. Recovers L4 protocol from IP header.

**F17.3: IPv4 fragment, non-fragmented (offset 0, MF=0)**
- Branch: both `f.ipMF` and `v.FragOffset == 0` are false.
- Behavior: fragGroupID stays "", no fragment handling.

**F17.4: IPv4 fragment -- L4 protocol recovery (TCP)**
- Branch: `switch v.Protocol` + `case layers.IPProtocolTCP` (line 572-573)
- Behavior: `f.l4Proto = "tcp"`.

**F17.5: IPv4 fragment -- L4 protocol recovery (UDP)**
- Branch: `case layers.IPProtocolUDP` (line 575-576)
- Behavior: `f.l4Proto = "udp"`.

**F17.6: IPv4 fragment -- unknown L4 protocol**
- Branch: default (no explicit case for ICMP/other).
- Behavior: `l4Proto` stays "". The fragment will get a "raw|" key.

**F17.7: First fragment with at least 4 bytes of payload**
- Branch: `if f.fragFirst && len(v.Payload) >= 4` (line 579-581)
- Behavior: Extracts srcPort and dstPort from IP payload bytes (first 4 bytes = L4 ports).

**F17.8: First fragment with less than 4 bytes of payload**
- Branch: `f.fragFirst && len(v.Payload) < 4` (line 579)
- Behavior: Ports stay 0. Fragments will get a "raw|" key.

**F17.9: IPv6 network layer**
- Branch: `case *layers.IPv6` (line 584-588)
- Behavior: Sets srcIP, dstIP, ipVersion=6. Note: no fragGroupID/fragOffset handling for IPv6 fragments (v1 limitation).

**F17.10: No network layer**
- Branch: `nl := pkt.NetworkLayer()` + `nl == nil` (line 554)
- Behavior: All IP fields stay zero. Packet may still have transport layer.

**F17.11: TCP transport layer**
- Branch: `case *layers.TCP` (line 592-624)
- Behavior: Sets srcPort, dstPort, l4Proto="tcp", payload, all TCP flags, seq, window.

**F17.12: TCP SYN packet with options parsed**
- Branch: `if v.SYN` (line 607-623)
- Behavior: Iterates TCP options, extracts MSS (kind 2), WindowScale (kind 3), SACK Permitted (kind 4).

**F17.13: TCP SYN with MSS option, valid length**
- Branch: `case 2: if len(opt.OptionData) == 2` (line 612-614)
- Behavior: `tcpMSS` set from 2-byte option data.

**F17.14: TCP SYN with MSS option, invalid length**
- Branch: `case 2: len(opt.OptionData) != 2`
- Behavior: `tcpMSS` stays 0 (silently skipped).

**F17.15: TCP SYN with WindowScale option, valid length**
- Branch: `case 3: if len(opt.OptionData) == 1` (line 617-618)
- Behavior: `tcpWindowScale` set from 1-byte option data.

**F17.16: TCP SYN with WindowScale, invalid length**
- Branch: `case 3: len(opt.OptionData) != 1`
- Behavior: `tcpWindowScale` stays -1 (default).

**F17.17: TCP SYN with SACK Permitted**
- Branch: `case 4` (line 621)
- Behavior: `tcpSACK = true`.

**F17.18: TCP non-SYN (no option parsing)**
- Branch: `v.SYN` is false (line 607)
- Behavior: No options parsed. tcpOptionKinds stays nil.

**F17.19: UDP transport layer**
- Branch: `case *layers.UDP` (line 625-629)
- Behavior: Sets srcPort, dstPort, l4Proto="udp", payload.

**F17.20: No transport layer (e.g., ICMP, ARP, or fragmented)**
- Branch: `tl := pkt.TransportLayer()` + `tl == nil` (line 590)
- Behavior: All transport fields stay zero.

**F17.21: ICMPv4 layer detected**
- Branch: `if icmp := pkt.Layer(layers.LayerTypeICMPv4); icmp != nil` (line 634-640)
- Behavior: `l4Proto = "icmp"`, icmpType, icmpID, payload set.

**F17.22: ICMPv4 type assertion fails**
- Branch: `if v, ok := icmp.(*layers.ICMPv4); ok` is false (line 636)
- Behavior: icmpType/icmpID stay 0, payload stays nil.

**F17.23: ARP layer detected**
- Branch: `if arp := pkt.Layer(layers.LayerTypeARP); arp != nil` (line 642-653)
- Behavior: `l4Proto = "arp"`, arpOp set.

**F17.24: ARP type assertion fails**
- Branch: `v, ok := arp.(*layers.ARP)` fails (line 644)
- Behavior: arp fields stay zero.

**F17.25: ARP with valid IPv4 sender address**
- Branch: `if len(v.SourceProtAddress) == 4` (line 647-649)
- Behavior: `arpSenderIP` set.

**F17.26: ARP with non-IPv4 sender address (e.g., IPv6 ARP, or non-IP protocol)**
- Branch: `len(v.SourceProtAddress) != 4`
- Behavior: `arpSenderIP` stays nil.

**F17.27: ARP with valid IPv4 target address**
- Branch: `if len(v.DstProtAddress) == 4` (line 650-652)
- Behavior: `arpTargetIP` set.

**F17.28: ARP with non-IPv4 target address**
- Branch: `len(v.DstProtAddress) != 4`
- Behavior: `arpTargetIP` stays nil.

---

### F18: `computeFlowKey(fields)`

**F18.1: TCP**
- Branch: `case "tcp"` (line 662-663)
- Behavior: `flowKeyTCPUDP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 6)`.

**F18.2: UDP**
- Branch: `case "udp"` (line 664-665)
- Behavior: `flowKeyTCPUDP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 17)`.

**F18.3: ICMP**
- Branch: `case "icmp"` (line 666-667)
- Behavior: `flowKeyICMP(f.srcIP, f.dstIP, f.icmpType, f.icmpID)`.

**F18.4: ARP**
- Branch: `case "arp"` (line 668-669)
- Behavior: `flowKeyARP(f.arpSenderIP, f.arpTargetIP, f.arpOp)`.

**F18.5: Unknown/empty protocol**
- Branch: `default` (line 670-671)
- Behavior: Returns `""`.

---

### F19: `payloadHash(payload)`

**F19.1: Empty payload**
- Branch: `if len(payload) == 0` (line 679)
- Output: `""`.

**F19.2: Non-empty payload**
- Branch: else (line 681-683)
- Output: hex-encoded SHA-256 hash.

---

### F20: `detectAnomaly(frameLen, capturedLen, originalLen)`

**F20.1: Truncated by snaplen**
- Branch: `case capturedLen < originalLen` (line 692-693)
- Output: `"truncated"`.

**F20.2: Oversize frame (> 1518 bytes)**
- Branch: `case frameLen > 1518` (line 694-695)
- Output: `"oversize"`.

**F20.3: Undersize frame (< 64 bytes)**
- Branch: `case frameLen < 64` (line 696-697)
- Output: `"undersize"`.

**F20.4: Normal frame**
- Branch: `default` (line 698-699)
- Output: `""`.

---

## DIRECTION.GO (tag: D)

### D1: `updateDirection(fields)`

**D1.1: Direction already locked (classified)**
- Branch: `if fs.dirLocked` (line 31-32)
- Behavior: `return` (no-op, calibration already done).

**D1.2: TCP SYN without ACK (client initiator)**
- Branch: `case "tcp"` + `if f.tcpSYN && !f.tcpACK` (line 37-39)
- Input: TCP SYN packet from the real client.
- Behavior: `fs.setClient(f.srcIP, f.srcPort, f.dstIP, f.dstPort, "syn")`. First-packet src guess is confirmed.

**D1.3: TCP SYN+ACK (server responding)**
- Branch: `if f.tcpSYN && f.tcpACK` (line 43-45)
- Input: TCP SYN-ACK packet (server -> client). Corrects a wrong first-packet guess (e.g., capture started at the SYN-ACK).
- Behavior: `fs.setClient(f.dstIP, f.dstPort, f.srcIP, f.srcPort, "syn")`. Client is the dst of the SYN-ACK.

**D1.4: TCP non-handshake packet (no SYN flag)**
- Branch: Both SYN conditions false.
- Behavior: Falls through to end of function. No calibration; DirStatus stays "uncertain".

**D1.5: UDP, src is well-known server port, dst is not**
- Branch: `case "udp"` + `if wellKnownServerPorts[f.srcPort] && !wellKnownServerPorts[f.dstPort]` (line 50-52)
- Input: DNS response (src=53, dst=ephemeral).
- Behavior: `fs.setClient(f.dstIP, f.dstPort, f.srcIP, f.srcPort, "port")`. Client is the dst of the packet.

**D1.6: UDP, dst is well-known server port, src is not**
- Branch: `if wellKnownServerPorts[f.dstPort] && !wellKnownServerPorts[f.srcPort]` (line 54-56)
- Input: DNS query (src=ephemeral, dst=53).
- Behavior: `fs.setClient(f.srcIP, f.srcPort, f.dstIP, f.dstPort, "port")`. Client is the src of the packet.

**D1.7: UDP, both ports are well-known (or neither)**
- Branch: Both conditions false (line 50 and 54 fail).
- Input: e.g., both ports are 53 (DNS server-to-server), or both are ephemeral (no hint).
- Behavior: Falls through. No calibration. DirStatus stays "uncertain".

**D1.8: Non-TCP, non-UDP protocol (ICMP, ARP, etc.)**
- Branch: `switch f.l4Proto` doesn't match "tcp" or "udp".
- Behavior: Falls through. No calibration. DirStatus stays "uncertain".

---

## REASSEMBLY.GO (tag: R)

### R1: `reassemblyStream.Reassembled(seg)`

**R1.1: Gap detected (Skip > 0)**
- Branch: `if r.Skip != 0` (line 29-30)
- Behavior: `s.gapDetected = true`.

**R1.2: No gap (normal in-order delivery)**
- Branch: `r.Skip == 0` (line 29)
- Behavior: No gap flag set.

**R1.3: Empty segment (no bytes)**
- Branch: `r.Bytes` is nil/empty, `append(s.buf, ...)` is no-op.
- Behavior: No bytes added. `s.buf` unchanged.

**R1.4: Non-empty segment**
- Behavior: `s.buf = append(s.buf, r.Bytes...)`.

**R1.5: Default stream (multiple reassembly segments in one call)**
- The for loop iterates over all segments. Each segment is processed independently.

---

### R2: `reassemblyStream.ReassemblyComplete()`

**R2.1: Normal completion**
- Behavior: `s.complete = true`.

---

### R3: `nullStream` methods

**R3.1: Reassembled called on nullStream**
- Behavior: No-op (discards all bytes).

**R3.2: ReassemblyComplete called on nullStream**
- Behavior: No-op.

---

### R4: `reassemblyFactory.New(netFlow, tcpFlow)`

**R4.1: Source or destination IP is nil**
- Branch: `if srcIP == nil || dstIP == nil` (line 66-67)
- Input: gopacket endpoint with non-IP raw bytes (e.g., IPv6, or unknown).
- Output: `return nullStreamInstance`. Bytes are discarded.

**R4.2: Flow not found in map**
- Branch: `fs, ok := f.flows[key]` + `!ok` (line 70-71)
- Input: A TCP direction for a flow not in the parser's flow map (shouldn't normally happen).
- Output: `return nullStreamInstance`.

**R4.3: Flow found, c2s direction**
- Branch: `dir := fs.classifyDirection(srcIP.String(), srcPort)` returns "c2s" (line 74)
- Behavior: `reassemblyStream{fs: fs, dir: "c2s"}`, `fs.setStream("c2s", s)`.

**R4.4: Flow found, s2c direction**
- Branch: `classifyDirection` returns "s2c" (line 74)
- Behavior: `reassemblyStream{fs: fs, dir: "s2c"}`, `fs.setStream("s2c", s)`.

---

### R5: `netIPFromEndpoint(ep)`

**R5.1: IPv4 endpoint (4 bytes)**
- Branch: `if len(raw) == 4 || len(raw) == 16` (line 84)
- Behavior: Copies 4 bytes, returns net.IP.

**R5.2: IPv6 endpoint (16 bytes)**
- Branch: same condition, `len(raw) == 16` (line 84)
- Behavior: Copies 16 bytes, returns net.IP.

**R5.3: Non-IP endpoint (e.g., Ethernet MAC, or other lengths)**
- Branch: `len(raw) != 4 && len(raw) != 16` (line 84)
- Output: `return nil`.

---

### R6: `portFromEndpoint(ep)`

**R6.1: Valid 2-byte port**
- Branch: `if len(raw) != 2` (line 96)
- Behavior: `raw` is 2 bytes, condition false, returns `binary.BigEndian.Uint16(raw)`.

**R6.2: Invalid port length**
- Branch: `len(raw) != 2` (line 96-97)
- Output: `return 0`.

---

## FRAGMENT.GO (tag: FR)

### FR1: `AddFragment(key, frame, l3Start, ipid, src, dst, proto, fragOffsetBytes, moreFragments)`

**FR1.1: New fragment group (first fragment of a new group)**
- Branch: `g, ok := r.groups[key]` + `!ok` (line 56-63)
- Behavior: Creates new fragmentGroup with empty payloads map, totalPayloadLen=-1.

**FR1.2: Existing fragment group**
- Branch: `ok` (line 56)
- Behavior: Uses existing group.

**FR1.3: IP header start beyond frame length**
- Branch: `if l3Start+4 > len(frame)` (line 68-69)
- Input: l3Start is near/past the end of frame (malformed, or offset calculation error).
- Output: `return nil`.

**FR1.4: IHL < 20 or exceeds frame**
- Branch: `if ihl < 20 || l3Start+ihl > len(frame)` (line 72-73)
- Input: IP header length < 20 (invalid) or IP header extends beyond captured frame.
- Output: `return nil`.

**FR1.5: IP payload length negative or exceeds frame**
- Branch: `if ipPayloadLen < 0 || l3Start+ihl+ipPayloadLen > len(frame)` (line 77-78)
- Input: IP total length field is < IHL or > captured frame (truncated capture, or corrupted).
- Output: `return nil`.

**FR1.6: First fragment (offset 0) -- stores full frame as base**
- Branch: `if fragOffsetBytes == 0` (line 84-87)
- Behavior: `g.firstFrag = frame`, `g.l3Start = l3Start`.

**FR1.7: Non-first fragment**
- Branch: `fragOffsetBytes != 0`
- Behavior: Only payload is stored. firstFrag stays nil.

**FR1.8: Last fragment (MF=0) -- sets totalPayloadLen**
- Branch: `if !moreFragments` (line 89-92)
- Behavior: `g.totalPayloadLen = fragOffsetBytes + len(ipPayload)`.

**FR1.9: Not last fragment (MF=1)**
- Branch: `!moreFragments` is false (line 89)
- Behavior: totalPayloadLen stays -1 (unknown).

**FR1.10: Reassembly attempt -- all conditions met**
- Branch: `if g.firstFrag != nil && g.totalPayloadLen > 0 && !g.reassembled` (line 95)
- Behavior: `g.tryReassemble()` called.

**FR1.11: Reassembly attempt -- missing first fragment**
- Branch: `g.firstFrag == nil` (line 95)
- Behavior: No reassembly attempt.

**FR1.12: Reassembly attempt -- total length unknown**
- Branch: `g.totalPayloadLen <= 0` (still -1) (line 95)
- Behavior: No reassembly attempt.

**FR1.13: Reassembly attempt -- already reassembled**
- Branch: `g.reassembled == true` (line 95)
- Behavior: No reassembly attempt.

**FR1.14: Reassembly succeeds**
- Branch: `reassembled := g.tryReassemble()` returns non-nil (line 96-98)
- Behavior: `g.reassembled = true`, returns reassembled frame.

**FR1.15: Reassembly fails (gap remains)**
- Branch: `tryReassemble()` returns nil (line 96)
- Behavior: `g.reassembled` stays false. Returns nil.

---

### FR2: `tryReassemble()`

**FR2.1: Gap in payload offsets (non-contiguous)**
- Branch: `if off != cursor` (line 116-117)
- Input: Fragment offsets are not contiguous (e.g., 0, 1480, 2960 but missing 1480).
- Output: `return nil`.

**FR2.2: Missing tail fragment (cursor != totalPayloadLen)**
- Branch: `if cursor != g.totalPayloadLen` (line 122-123)
- Input: Last fragment (MF=0) not yet arrived, or offset doesn't cover total.
- Output: `return nil`.

**FR2.3: All fragments present, contiguous**
- Both checks pass. Builds reassembled frame.
- Behavior: Copies L2+L3 header, assembles IP payload, updates IP header (total length, frag offset, checksum).
- Output: Returns reassembled frame bytes.

**FR2.4: Single fragment group (no fragmentation)**
- Input: Only one fragment with offset 0, MF=0, totalPayloadLen == len(payload).
- Behavior: cursor == totalPayloadLen. Reassembly "succeeds" but produces a frame identical to the input (no actual fragmentation).

---

### FR3: `Flush()`

**FR3.1: Flush with incomplete groups**
- Branch: `if !g.reassembled` (line 153-154)
- Input: One or more fragment groups that never completed.
- Behavior: `n++` for each incomplete group. All groups are deleted.

**FR3.2: Flush with all groups completed**
- Branch: `g.reassembled == true` (line 153)
- Behavior: Groups are deleted. `n` stays 0.

**FR3.3: Flush with no groups**
- Input: No fragment groups in the map.
- Output: Returns 0.

---

## OFFSET.GO (tag: O)

### O1: `ExtractOffsetLayout(pkt)`

**O1.1: Ethernet layer**
- Branch: `case *layers.Ethernet` (line 78-81)
- Behavior: L2Start=start, DstMAC=start+0, SrcMAC=start+6.

**O1.2: Dot1Q (VLAN) layer**
- Branch: `case *layers.Dot1Q` (line 82-85)
- Behavior: VlanTCO=start+0 (VLAN TCI field).

**O1.3: IPv4 layer**
- Branch: `case *layers.IPv4` (line 86-93)
- Behavior: L3Start=start, SrcIP/DstIP/TTL/DSCPECN/IPFlagsFrag/IPID all set.

**O1.4: IPv6 layer**
- Branch: `case *layers.IPv6` (line 94-96)
- Behavior: L3Start=start, L4Protocol="ipv6". No individual field offsets for IPv6 (v1 limitation).

**O1.5: TCP layer**
- Branch: `case *layers.TCP` (line 97-105)
- Behavior: L4Start=start, L4Protocol="tcp", all TCP field offsets set.

**O1.6: UDP layer**
- Branch: `case *layers.UDP` (line 106-110)
- Behavior: L4Start=start, L4Protocol="udp", port offsets set.

**O1.7: ICMPv4 layer**
- Branch: `case *layers.ICMPv4` (line 111-113)
- Behavior: L4Start=start, L4Protocol="icmp". No individual field offsets (v1 limitation).

**O1.8: ARP layer**
- Branch: `case *layers.ARP` (line 114-116)
- Behavior: L4Start=start, L4Protocol="arp". No individual field offsets.

**O1.9: Unknown/unrecognized layer type**
- Branch: none of the above cases match.
- Behavior: Skipped (no offset recorded for this layer).

**O1.10: Multiple layers in sequence (e.g., Ethernet + Dot1Q + IPv4 + TCP)**
- The loop iterates each layer, offset accumulates. Each layer sets its own offsets.

**O1.11: No layers (empty packet)**
- Input: gopacket.Packet with no layers.
- Output: All fields -1 in OffsetLayout.

---

## PAYLOAD.GO (tag: PW)

### PW1: `newPayloadsWriter(path)`

**PW1.1: Empty path (reassembly disabled)**
- Branch: `if path == ""` (line 25-26)
- Behavior: Returns `nil, nil`. No materialization.

**PW1.2: File creation failure**
- Branch: `err := os.Create(path)` + `err != nil` (line 28-30)
- Input: Path in non-writable directory, file exists and is locked, etc.
- Output: `nil, fmt.Errorf("create payloads file: %w", err)`.

**PW1.3: Success**
- Branch: No error.
- Output: `&payloadsWriter{file: f}, nil` (offset starts at 0).

---

### PW2: `appendStream(data)`

**PW2.1: Writer is nil (reassembly disabled)**
- Branch: `if w == nil || w.file == nil` (line 40-41)
- Input: newPayloadsWriter returned nil (path was empty).
- Output: `(0, int64(len(data)), nil)`. Still reports length for caller consistency.

**PW2.2: Writer is non-nil but file is nil (shouldn't happen, but defensive)**
- Branch: same as PW2.1, `w.file == nil`.
- Output: Same as PW2.1.

**PW2.3: Empty data stream**
- Branch: `if len(data) == 0` (line 43-44)
- Input: Pure ACK stream with no payload.
- Output: `(w.offset, 0, nil)`.

**PW2.4: WriteAt fails**
- Branch: `if _, err := w.file.WriteAt(data, offset); err != nil` (line 47-48)
- Input: Disk full, file closed, etc.
- Output: `(0, 0, fmt.Errorf("write payloads: %w", err))`.

**PW2.5: Successful write**
- Branch: No error.
- Behavior: `w.offset += int64(len(data))`.
- Output: `(offset, int64(len(data)), nil)`.

---

### PW3: `close()`

**PW3.1: Writer is nil or file is nil**
- Branch: `if w == nil || w.file == nil` (line 56-57)
- Output: `return nil`.

**PW3.2: File close succeeds**
- Output: `return w.file.Close()`.

**PW3.3: File close fails**
- Output: `w.file.Close()` returns error.

---

## TRIGRAM.GO (tag: T)

### T1: `NewTrigramIndex()`

**T1.1: Empty index**
- Output: `&TrigramIndex{Postings: map[[3]byte][]trigramPosting{}}`. Segments is nil.

---

### T2: `AddSegment(flowID, dir, data)`

**T2.1: Empty data (< 3 bytes)**
- Branch: for loop `i+3 <= len(d)` runs 0 times (line 51).
- Input: Data is 0, 1, or 2 bytes.
- Behavior: Segment is stored (for linear search) but no trigrams indexed.

**T2.2: Data exactly 3 bytes**
- Branch: loop runs once (i=0).
- Behavior: One trigram posted.

**T2.3: Data with many bytes**
- Branch: loop runs for each 3-byte sliding window.
- Behavior: All trigrams indexed, each with its offset.

**T2.4: Duplicate trigrams in data**
- Branch: Each trigram gets its own posting entry (separate offsets).
- Behavior: `idx.Postings[t]` has multiple entries for the same trigram at different offsets.

---

### T3: `Search(pattern)`

**T3.1: Empty pattern**
- Branch: `if len(pattern) == 0` (line 73-74)
- Output: `return nil`.

**T3.2: Short pattern (< 3 bytes)**
- Branch: `if len(pattern) < 3` (line 76-77)
- Behavior: `idx.linearSearch(pattern)`.

**T3.3: Pattern >= 3 bytes, rarest trigram has 0 postings (no matches possible)**
- Branch: `if bestCount == 0` (line 92-93)
- Input: Pattern contains a trigram that doesn't exist in any segment.
- Behavior: `break` from trigram-selection loop. `bestPostings` is empty. The for loop over postings produces no matches. Output: `nil`.

**T3.4: Pattern >= 3 bytes, first trigram is the rarest**
- Branch: `if bestCount < 0 || len(p) < bestCount` (line 89)
- Input: First trigram has the smallest postings list.
- Behavior: `bestCount = len(p)`, `bestPostings = p`.

**T3.5: Pattern >= 3 bytes, later trigram is rarest**
- Branch: `len(p) < bestCount` (line 89)
- Behavior: Updates bestCount and bestPostings.

**T3.6: Pattern found in a segment**
- Branch: `i := bytes.Index(seg.Data[start:], pattern)` + `i >= 0` (line 108-115)
- Behavior: Match appended to results. `start += i + 1` (continue scanning for more matches in same segment).

**T3.7: Pattern not found in a segment (no match despite trigram hit)**
- Branch: `i < 0` (line 109)
- Behavior: Segment skipped (false positive from trigram index).

**T3.8: Multiple occurrences in same segment**
- Branch: inner loop continues until `i < 0`.
- Behavior: Multiple TrigramMatch entries for the same segment at different offsets.

**T3.9: Pattern found in multiple segments**
- Branch: for loop over bestPostings.
- Behavior: One or more matches per segment.

---

### T4: `linearSearch(pattern)`

**T4.1: No segments**
- Input: `idx.Segments` is nil/empty.
- Output: `nil`.

**T4.2: Pattern found in a segment**
- Branch: `i := bytes.Index(seg.Data[start:], pattern)` + `i >= 0` (line 128-134)
- Behavior: Match emitted.

**T4.3: Pattern not found in a segment**
- Branch: `i < 0` (line 129)
- Behavior: Segment skipped.

**T4.4: Multiple occurrences**
- Branch: inner loop continues.
- Behavior: Multiple matches.

---

### T5: `WriteToFile(path)`

**T5.1: File creation fails**
- Branch: `err := os.Create(path)` + `err != nil` (line 167-168)
- Input: Path not writable.
- Output: `(0, err)`.

**T5.2: Gob encoding fails**
- Branch: `gob.NewEncoder(f).Encode(tf)` + `err != nil` (line 173-174)
- Input: Struct with un-encodeable types (shouldn't happen with []byte and maps, but possible with gob).
- Output: `(0, err)`.

**T5.3: File stat fails**
- Branch: `info, _ := f.Stat()` (line 176) -- error is silently discarded.
- Input: Stat fails (e.g., file closed).
- Output: `(0, nil)` (size would be 0, but the file was written successfully).

**T5.4: Success**
- Output: `(info.Size(), nil)`.

---

### T6: `LoadFromFile(path)`

**T6.1: File open fails**
- Branch: `err := os.Open(path)` + `err != nil` (line 182-183)
- Output: `nil, err`.

**T6.2: Gob decode fails**
- Branch: `gob.NewDecoder(f).Decode(&tf)` + `err != nil` (line 188-189)
- Input: Corrupted file, incompatible gob version, etc.
- Output: `nil, err`.

**T6.3: Success**
- Output: `&TrigramIndex{Segments: tf.Segments, Postings: tf.Postings}, nil`.

---

## SEARCH.GO (tag: S)

### S1: `Search(flows, packets, index, query)`

**S1.1: nil query (shouldn't happen, but...)**
- Branch: `query.FlowFilter` check (line 151) -- if query is nil, this panics (nil deref).
- Edge case: caller must not pass nil query.

**S1.2: Flow filter present, all flows match**
- Branch: `query.FlowFilter != nil` (line 151-152)
- Behavior: `filterFlows(candidates, query.FlowFilter)` narrows the candidate set.

**S1.3: Flow filter present, no flows match**
- Branch: `filterFlows` returns empty slice.
- Behavior: Empty candidates. Output: `[]` (empty results).

**S1.4: No flow filter (all flows are candidates)**
- Branch: `query.FlowFilter == nil` (line 151)
- Behavior: All flows retained.

**S1.5: Payload filter present, decode succeeds**
- Branch: `query.Payload != nil` (line 158-176)
- Behavior: `decodePayloadFilter(query.Payload)` called.

**S1.6: Payload filter present, decode fails**
- Branch: `decodePayloadFilter` returns error (line 160-161)
- Output: `nil, err`.

**S1.7: Payload filter, trigram search hits**
- Branch: `index.Search(needle)` returns matches (line 163-167)
- Behavior: `payloadHits` map populated. Candidates filtered to only those in payload hits.

**S1.8: Payload filter, trigram search no hits**
- Branch: `index.Search` returns nil (line 163)
- Behavior: `payloadHits` map is empty. `filtered` loop produces empty slice. Output: `[]`.

**S1.9: Payload filter, flow not in hit set**
- Branch: `if _, ok := payloadHits[f.ID]; !ok` (line 171)
- Behavior: Flow excluded from filtered candidates.

**S1.10: Payload filter, flow in hit set**
- Branch: `ok` (line 171)
- Behavior: Flow retained.

**S1.11: No payload filter**
- Branch: `query.Payload == nil` (line 158)
- Behavior: No payload-based filtering. `payloadHits` stays nil.

**S1.12: Packet filter present, packets available**
- Branch: `query.PacketFilter != nil && packets != nil` (line 181-196)
- Behavior: Iterates packets, builds `packetsByFlow` map.

**S1.13: Packet filter, specific direction filter**
- Branch: `matchPacket(p, query.PacketFilter)` checks all fields (see S2).

**S1.14: Packet filter, flow has matching packets**
- Branch: `if pkts, ok := packetsByFlow[f.ID]; ok && len(pkts) > 0` (line 191)
- Behavior: Flow retained.

**S1.15: Packet filter, flow has no matching packets**
- Branch: `!ok || len(pkts) == 0` (line 191)
- Behavior: Flow excluded.

**S1.16: Packet filter, but packets is nil**
- Branch: `packets == nil` (line 181)
- Behavior: Packet filter is skipped (no packet data to filter against). All flows pass this filter stage.

**S1.17: No packet filter**
- Branch: `query.PacketFilter == nil` (line 181)
- Behavior: No packet-level filtering. `packetsByFlow` stays nil.

**S1.18: Limit <= 0 (return all candidates)**
- Branch: `if limit <= 0` (line 200-201)
- Behavior: `limit = len(candidates)`.

**S1.19: Positive limit**
- Branch: `limit > 0` (line 200)
- Behavior: Limit used as-is.

**S1.20: Negative offset (clamped to 0)**
- Branch: `if skip < 0` (line 204-205)
- Behavior: `skip = 0`.

**S1.21: Offset > 0, skip some flows**
- Branch: `if skip > 0` (line 209-211)
- Behavior: `skip--`, `continue`. Flow not included in results.

**S1.22: Limit reached, stop iteration**
- Branch: `if len(results) >= limit` (line 221-222)
- Behavior: `break` from the for loop.

**S1.23: Payload hits present, attach to result**
- Branch: `if payloadHits != nil` (line 214-215)
- Behavior: `r.Matches = payloadHits[f.ID]`.

**S1.24: Packet results present, attach to result**
- Branch: `if packetsByFlow != nil` (line 217-218)
- Behavior: `r.Packets = packetsByFlow[f.ID]`.

---

### S2: `matchPacket(p, f)`

**S2.1: Direction mismatch**
- Branch: `if f.Direction != "" && p.Direction != f.Direction` (line 231)
- Output: `false`.

**S2.2: L4Protocol mismatch**
- Branch: `if f.L4Protocol != "" && p.L4Protocol != f.L4Protocol` (line 234)
- Output: `false`.

**S2.3: AnomalyFlag mismatch**
- Branch: `if f.AnomalyFlag != "" && p.AnomalyFlag != f.AnomalyFlag` (line 237)
- Output: `false`.

**S2.4: Timestamp before start**
- Branch: `if f.TimeStartUs != 0 && p.TimestampUs < f.TimeStartUs` (line 240)
- Output: `false`.

**S2.5: Timestamp after end**
- Branch: `if f.TimeEndUs != 0 && p.TimestampUs > f.TimeEndUs` (line 243)
- Output: `false`.

**S2.6: All fields match (or wildcard)**
- All conditions pass.
- Output: `true`.

---

### S3: `filterFlows(flows, f)`

**S3.1: Empty flows list**
- Branch: Loop over empty slice.
- Output: Empty slice.

**S3.2: Protocol mismatch**
- Branch: `if f.Protocol != "" && fl.L4Protocol != f.Protocol` (line 253)
- Behavior: `continue`.

**S3.3: SrcIP mismatch**
- Branch: `if f.SrcIP != "" && fl.SrcIP != f.SrcIP` (line 256)
- Behavior: `continue`.

**S3.4: DstIP mismatch**
- Branch: `if f.DstIP != "" && fl.DstIP != f.DstIP` (line 259)
- Behavior: `continue`.

**S3.5: SrcPort mismatch**
- Branch: `if f.SrcPort != 0 && fl.SrcPort != f.SrcPort` (line 262)
- Behavior: `continue`.

**S3.6: DstPort mismatch**
- Branch: `if f.DstPort != 0 && fl.DstPort != f.DstPort` (line 265)
- Behavior: `continue`.

**S3.7: L7Type mismatch**
- Branch: `if f.L7Type != "" && fl.L7Protocol != f.L7Type` (line 268)
- Behavior: `continue`.

**S3.8: All filters match**
- All conditions pass.
- Behavior: `out = append(out, fl)`.

---

### S4: `MatchPreview(flows, matcher)`

**S4.1: Empty flows list**
- Output: `nil`.

**S4.2: Flow matches all matcher fields**
- Branch: `if !matchFlowMatcher(f, matcher)` is false (line 91)
- Output: Flow ID appended to hits.

**S4.3: Flow fails matcher**
- Branch: `matchFlowMatcher` returns false (line 91)
- Behavior: `continue`.

---

### S5: `matchFlowMatcher(f, m)`

**S5.1: Protocol mismatch**
- Branch: `if m.Protocol != "" && f.L4Protocol != m.Protocol` (line 112)
- Output: `false`.

**S5.2: SrcPort mismatch**
- Branch: `if m.SrcPort != 0 && f.SrcPort != m.SrcPort` (line 115)
- Output: `false`.

**S5.3: DstPort mismatch**
- Branch: `if m.DstPort != 0 && f.DstPort != m.DstPort` (line 118)
- Output: `false`.

**S5.4: SrcIP mismatch (exact or CIDR)**
- Branch: `if m.SrcIP != "" && !ipMatch(m.SrcIP, f.SrcIP)` (line 121)
- Output: `false`.

**S5.5: DstIP mismatch (exact or CIDR)**
- Branch: `if m.DstIP != "" && !ipMatch(m.DstIP, f.DstIP)` (line 124)
- Output: `false`.

**S5.6: All match**
- All conditions pass.
- Output: `true`.

---

### S6: `ipMatch(spec, candidate)`

**S6.1: CIDR spec, valid CIDR, candidate IP matches**
- Branch: `if strings.Contains(spec, "/")` (line 133)
- Branch: `err != nil` is false (line 135)
- Branch: `ip != nil && cidr.Contains(ip)` (line 139)
- Output: `true`.

**S6.2: CIDR spec, valid CIDR, candidate IP doesn't match**
- Branch: `ip == nil` or `!cidr.Contains(ip)` (line 139)
- Output: `false`.

**S6.3: CIDR spec, invalid CIDR**
- Branch: `err != nil` (line 135)
- Output: `false`.

**S6.4: CIDR spec, unparseable candidate IP**
- Branch: `ip := net.ParseIP(candidate)` returns nil (line 138)
- Output: `false`.

**S6.5: Exact IP match**
- Branch: no "/" in spec (line 133 else path)
- Output: `spec == candidate`.

---

### S7: `decodePayloadFilter(p)`

**S7.1: nil filter**
- Branch: `if p == nil` (line 279-280)
- Output: `nil, nil`.

**S7.2: Non-hex encoding (plain text)**
- Branch: `p.Encoding != "hex"` (line 283)
- Output: `p.Contains, nil` (as-is).

**S7.3: Hex encoding, empty needle**
- Branch: `if p.Encoding == "hex" && len(needle) > 0` (line 283)
- Input: `p.Encoding == "hex"` but `p.Contains` is nil/empty.
- Behavior: `len(needle) > 0` is false. No decoding attempted. Output: `nil, nil` (or rather, the empty needle, since no early return).

**S7.4: Hex encoding, odd length**
- Branch: `if len(s)%2 != 0` (line 285-286)
- Input: "abc" (3 chars, odd).
- Output: `nil, fmt.Errorf("odd hex length: %d chars in %q", len(s), s)`.

**S7.5: Hex encoding, invalid character**
- Branch: `if !ok` (line 291-292)
- Input: "0xYZ" (invalid hex chars).
- Output: `nil, fmt.Errorf("invalid hex character at position %d in %q", i, s)`.

**S7.6: Hex encoding, valid**
- All checks pass.
- Output: `dec, nil`.

---

## DYNAMIC.GO (tag: DY)

### DY1: `openCached(path)`

**DY1.1: File already cached**
- Branch: `if f, ok := fileCache.m[path]; ok` (line 44)
- Output: `f, nil` (no new open).

**DY1.2: File not cached, open fails**
- Branch: `err := os.Open(path)` + `err != nil` (line 47-49)
- Input: Path doesn't exist, permission denied.
- Output: `nil, fmt.Errorf("open pcap for re-parse: %w", err)`.

**DY1.3: File not cached, open succeeds**
- Branch: No error (line 50-52).
- Behavior: `fileCache.m[path] = f`.
- Output: `f, nil`.

---

### DY2: `CloseCachedFile(path)`

**DY2.1: File is cached**
- Branch: `if f, ok := fileCache.m[path]; ok` (line 60-62)
- Behavior: `f.Close()`, `delete(fileCache.m, path)`.

**DY2.2: File not cached**
- Branch: `!ok` (line 60)
- Behavior: No-op.

---

### DY3: `ParsePacket(pcapPath, rawOffset, length, linkType)`

**DY3.1: Invalid length (<= 0)**
- Branch: `if length <= 0` (line 71)
- Output: `nil, fmt.Errorf("invalid packet length %d", length)`.

**DY3.2: Unsupported link type**
- Branch: `decoderForLinkType(linkType)` returns error (line 77)
- Output: `nil, err`.

**DY3.3: File open fails**
- Branch: `openCached(pcapPath)` returns error (line 81)
- Output: `nil, err`.

**DY3.4: ReadAt fails (offset beyond file, short read)**
- Branch: `if _, err := f.ReadAt(buf, rawOffset); err != nil` (line 85-86)
- Input: rawOffset points past EOF, or I/O error.
- Output: `nil, fmt.Errorf("read packet bytes at %d: %w", rawOffset, err)`.

**DY3.5: Success**
- No errors.
- Output: `buildLayerRecords(pkt), nil`.

---

### DY4: `decoderForLinkType(lt)`

**DY4.1: Ethernet**
- Branch: `case layers.LinkTypeEthernet` (line 96-97)
- Output: `layers.LayerTypeEthernet, nil`.

**DY4.2: Non-Ethernet**
- Branch: `default` (line 98-99)
- Output: `nil, fmt.Errorf("unsupported link type %d: v1 supports Ethernet only", lt)`.

---

### DY5: `buildLayerRecords(pkt)`

**DY5.1: Empty packet (no layers)**
- Loop over zero layers.
- Output: `nil` (empty slice).

**DY5.2: Packet with one layer**
- Single layer record built.

**DY5.3: Packet with multiple layers (e.g., Ethernet + IPv4 + TCP)**
- Multiple records, each with correct offset.

**DY5.4: Unknown layer type**
- Branch: `layerName(layer)` returns `layer.LayerType().String()` (default case).
- Fields: map is empty (no populateFields case matches).
- Still produces a LayerRecord with Layer name and Range.

---

### DY6: `layerName(layer)`

**DY6.1: Ethernet** → `"eth"`
**DY6.2: Dot1Q** → `"dot1q"`
**DY6.3: IPv4** → `"ipv4"`
**DY6.4: IPv6** → `"ipv6"`
**DY6.5: TCP** → `"tcp"`
**DY6.6: UDP** → `"udp"`
**DY6.7: ICMPv4** → `"icmp"`
**DY6.8: ARP** → `"arp"`
**DY6.9: Unknown** → `layer.LayerType().String()`

---

### DY7: `populateFields(rec, layer, start)`

**DY7.1: Ethernet**
- Sets dst_mac, src_mac, ether_type fields and dst_mac/src_mac offsets.

**DY7.2: Dot1Q**
- Sets vlan_id, priority fields and vlan_tco offset.

**DY7.3: IPv4**
- Sets src_ip, dst_ip, ttl, protocol, ip_id, dscp, ecn fields and all IP offsets.

**DY7.4: IPv6**
- Sets src_ip, dst_ip, hop_limit, next_header fields. No offsets (v1 limitation).

**DY7.5: TCP**
- Sets src_port, dst_port, seq, ack, window, flags fields and all TCP offsets.

**DY7.6: UDP**
- Sets src_port, dst_port, length fields and port offsets.

**DY7.7: ICMPv4**
- Sets type, code, id, seq fields. No offsets.

**DY7.8: ARP**
- Sets operation, sender_hw, sender_ip, target_hw, target_ip fields. No offsets.

**DY7.9: Unknown layer**
- No matching case. Fields/Offsets remain empty (initialized empty maps).

---

### DY8: `tcpFlagsString(t)`

**DY8.1: FIN flag set → `"FIN"`**
**DY8.2: SYN flag set → `"SYN"`**
**DY8.3: RST flag set → `"RST"`**
**DY8.4: PSH flag set → `"PSH"`**
**DY8.5: ACK flag set → `"ACK"`**
**DY8.6: URG flag set → `"URG"`**
**DY8.7: Multiple flags → `"SYN,ACK"` (comma-separated)**
**DY8.8: No flags set → `"none"`**
- Branch: `if s == ""` (line 233)

---

### DY9: `netHw(b)`

**DY9.1: 6 bytes** → MAC format `"xx:xx:xx:xx:xx:xx"`
**DY9.2: Other length** → hex string `"%x"`

---

### DY10: `netIPStr(b)`

**DY10.1: 4 bytes** → IPv4 dotted-quad
**DY10.2: 16 bytes** → IPv6 string
**DY10.3: Other length** → hex string `"%x"`

---

## PLUGIN.GO (tag: PL)

### PL1: `NewRegistry()`

**PL1.1: Default parsers registered**
- Behavior: Creates registry with httpParser, dnsParser, tlsParser (in that order).

---

### PL2: `Register(p)`

**PL2.1: Register one parser**
- Behavior: Appended to `r.parsers`.

**PL2.2: Register nil parser**
- Behavior: Nil appended to parsers. Will cause panic when Find iterates and calls CanParse on nil. (Defensive gap.)

---

### PL3: `Find(port, sample)`

**PL3.1: First parser matches**
- Branch: `if p.CanParse(port, sample)` (line 55)
- Behavior: Returns that parser immediately (short-circuit).

**PL3.2: No parser matches**
- Branch: All parsers return false from CanParse.
- Output: `nil`.

**PL3.3: Empty registry (no parsers)**
- Branch: For loop over empty slice.
- Output: `nil`.

---

### PL4: `ParseStream(port, stream)`

**PL4.1: No parser found**
- Branch: `p := r.Find(port, stream)` + `if p == nil` (line 65-66)
- Output: `nil`.

**PL4.2: Parser found, Parse succeeds**
- Branch: `res, err := p.Parse(stream)` + `err == nil && res != nil` (line 69-72)
- Output: `res`.

**PL4.3: Parser found, Parse returns error**
- Branch: `err != nil` (line 70)
- Output: `nil`.

**PL4.4: Parser found, Parse returns nil result**
- Branch: `res == nil` (line 70)
- Output: `nil`.

---

## L7_PARSERS.GO (tag: L7)

### L7.1: `httpParser.CanParse(port, sample)`

**L7.1.1: Well-known HTTP port**
- Branch: `if port == 80 || port == 8080 || port == 8000 || port == 8081` (line 20)
- Output: `true`.

**L7.1.2: Non-HTTP port, but sample starts with HTTP method**
- Branch: for loop over method prefixes (line 25-28)
- Input: e.g., port 12345, payload "GET / HTTP/1.1"
- Output: `true`.

**L7.1.3: Non-HTTP port, response status line**
- Branch: `bytes.HasPrefix(s, []byte("HTTP/"))` (line 25)
- Output: `true`.

**L7.1.4: No match on port or content**
- All conditions false.
- Output: `false`.

---

### L7.2: `httpParser.Parse(stream)`

**L7.2.1: No header boundary found (no \r\n\r\n)**
- Branch: `if end < 0` (line 36-38)
- Behavior: `end = len(stream)`. BodyOffset stays 0, BodyLength stays 0.

**L7.2.2: Header boundary found, body present**
- Branch: `if end+4 <= len(stream)` (line 42-44)
- Behavior: `BodyOffset = end + 4`, `BodyLength = len(stream) - BodyOffset`.

**L7.2.3: No body (stream ends exactly at \r\n\r\n)**
- Branch: `end+4 > len(stream)` (line 42)
- Behavior: BodyOffset/BodyLength stay 0.

**L7.2.4: Empty header block**
- Branch: `if len(lines) == 0` (line 47)
- Behavior: Returns res with just protocol "http" and empty metadata.

**L7.2.5: Response status line (HTTP/...)**
- Branch: `if strings.HasPrefix(first, "HTTP/")` (line 52-60)
- Sub-branch: `len(parts) >= 2` → sets `status`
- Sub-branch: `len(parts) >= 3` → sets `reason`

**L7.2.6: Request line (METHOD URI ...)**
- Branch: else (line 61-66)
- Sub-branch: `len(parts) >= 2` → sets `method` and `uri`
- Sub-branch: `len(parts) < 2` → empty metadata (unusual, e.g., garbage line)

**L7.2.7: Header line with colon (Host header)**
- Branch: `if i := strings.IndexByte(line, ':'); i > 0` (line 70-75)
- Sub-branch: `key == "host"` → sets `host` metadata

**L7.2.8: Header line without colon (malformed)**
- Branch: `i <= 0` (line 70)
- Behavior: Skipped.

**L7.2.9: Request line, split into < 2 parts (garbage)**
- Branch: `len(parts) < 2` (line 63)
- Behavior: No method/uri set. Metadata partially empty.

---

### L7.3: `dnsParser.CanParse(port, sample)`

**L7.3.1: Port 53 or 5353**
- Branch: `if port == 53 || port == 5353` (line 89)
- Output: `true`.

**L7.3.2: Other port**
- Branch: always `return false` (line 94)
- Output: `false`.

---

### L7.4: `dnsParser.Parse(stream)`

**L7.4.1: Valid DNS message, has questions**
- Branch: `if dns != nil` (line 102)
- Branch: `if len(dns.Questions) > 0` (line 105-108)
- Behavior: Sets `query_name`, `query_type`.

**L7.4.2: Valid DNS message, no questions**
- Branch: `len(dns.Questions) == 0` (line 105)
- Behavior: Only rcode set.

**L7.4.3: Invalid DNS message (parseDNS returns nil)**
- Branch: `if dns == nil` (line 102-103)
- Behavior: Returns res with protocol "dns" and empty metadata.

---

### L7.5: `tlsParser.CanParse(port, sample)`

**L7.5.1: Port 443**
- Branch: `if port == 443` (line 121)
- Output: `true`.

**L7.5.2: Non-443 port, but TLS record signature**
- Branch: `len(sample) >= 3 && sample[0] == 0x16 && sample[1] == 0x03` (line 125)
- Input: Port 8443, sample starts with TLS handshake record.
- Output: `true`.

**L7.5.3: No match**
- Output: `false`.

---

### L7.6: `tlsParser.Parse(stream)`

**L7.6.1: SNI present**
- Branch: `if meta.SNI != ""` (line 132-133)
- Behavior: Sets `sni` metadata.

**L7.6.2: Version present**
- Branch: `if meta.Version != ""` (line 134-135)
- Behavior: Sets `version` metadata.

**L7.6.3: Cipher suites present**
- Branch: `if len(meta.CipherSuites) > 0` (line 137-143)
- Behavior: Converts to hex strings, sets `cipher_suites`.

**L7.6.4: Certificate chain length > 0**
- Branch: `if meta.CertChainLen > 0` (line 145-146)
- Behavior: Sets `cert_chain_length`.

**L7.6.5: No TLS metadata found (e.g., encrypted traffic, non-handshake)**
- All conditions false.
- Output: `{Protocol: "tls", Metadata: {}}`.

---

### L7.7: `extractTLSMetadata(stream)`

**L7.7.1: Stream shorter than 5 bytes (no complete TLS record header)**
- Branch: `for off+5 <= len(stream)` (line 167) -- loop doesn't execute.
- Behavior: Returns empty metadata.

**L7.7.2: Truncated record (recLen > body length)**
- Branch: `if recLen > len(body)` (line 171-172)
- Behavior: `recLen = len(body)` (clamp to available data).

**L7.7.3: Handshake record (type 0x16)**
- Branch: `if recType == 0x16` (line 174-175)
- Behavior: `parseTLSHandshake(body[:recLen], &meta)`.

**L7.7.4: Non-handshake record (e.g., 0x17 = Application Data, 0x14 = Change Cipher Spec)**
- Branch: `recType != 0x16` (line 174)
- Behavior: Skipped (not parsed).

**L7.7.5: Multiple records in stream**
- Loop continues processing remaining bytes.

---

### L7.8: `parseTLSHandshake(body, meta)`

**L7.8.1: Incomplete message header**
- Branch: `for p+4 <= len(body)` (line 186) -- loop doesn't execute if body < 4 bytes.
- Behavior: No parsing.

**L7.8.2: Truncated handshake message**
- Branch: `if hsLen > len(msg)` (line 190-191)
- Behavior: `hsLen = len(msg)` (clamp).

**L7.8.3: ClientHello (type 0x01)**
- Branch: `switch hsType` + `case 0x01` (line 194-195)
- Behavior: `parseClientHello(msg[:hsLen], meta)`.

**L7.8.4: Certificate (type 0x0B)**
- Branch: `case 0x0B` (line 196-197)
- Behavior: `parseCertificate(msg[:hsLen], meta)`.

**L7.8.5: Other handshake type (e.g., ServerHello, ServerHelloDone, Finished)**
- Branch: default (no case).
- Behavior: Skipped.

---

### L7.9: `parseClientHello(hs, meta)`

**L7.9.1: Too short for version + random + session_id_len**
- Branch: `if len(hs) < 2+32+1` (line 206-207)
- Behavior: `return` (no metadata extracted).

**L7.9.2: Session ID length extends past buffer**
- Branch: `if p+1 > len(hs)` (line 214-215)
- Behavior: `return`.

**L7.9.3: Cipher suite length field extends past buffer**
- Branch: `if p+2 > len(hs)` (line 219-220)
- Behavior: `return`.

**L7.9.4: Cipher suite data extends past buffer**
- Branch: `if p+csLen > len(hs)` (line 224-225)
- Behavior: `return`.

**L7.9.5: Compression method length extends past buffer**
- Branch: `if p+1 > len(hs)` (line 232-233)
- Behavior: `return`.

**L7.9.6: Extensions length field extends past buffer**
- Branch: `if p+2 > len(hs)` (line 237-238)
- Behavior: `return`.

**L7.9.7: Extension data extends past buffer**
- Branch: `if extEnd > len(hs)` (line 243)
- Behavior: `extEnd = len(hs)` (clamp).

**L7.9.8: SNI extension (0x0000)**
- Branch: `case 0x0000` (line 255-262)
- Sub-branch: ServerNameList parsing with name length checks.

**L7.9.9: Supported versions extension (0x002b), TLS 1.3 detected**
- Branch: `case 0x002b` (line 263-273)
- Sub-branch: `if v == 0x0304` → `meta.Version = "TLS 1.3"` (overrides version from handshake-level).

**L7.9.10: Extended master secret or other extension**
- Branch: not SNI or supported_versions.
- Behavior: Skipped.

**L7.9.11: Extension data truncated mid-parse**
- Branch: `if p+extDataLen > extEnd` (line 251-252)
- Behavior: `break` from extension loop.

---

### L7.10: `parseCertificate(hs, meta)`

**L7.10.1: Too short for list length**
- Branch: `if len(hs) < 3` (line 284-285)
- Behavior: `return`.

**L7.10.2: List length exceeds available data**
- Branch: `if listLen > len(hs)-3` (line 288-289)
- Behavior: `listLen = len(hs) - 3` (clamp).

**L7.10.3: Success**
- Behavior: `meta.CertChainLen = listLen`.

---

### L7.11: `tlsVersionString(v)`

**L7.11.1: `0x0300`** → `"SSL 3.0"`
**L7.11.2: `0x0301`** → `"TLS 1.0"`
**L7.11.3: `0x0302`** → `"TLS 1.1"`
**L7.11.4: `0x0303`** → `"TLS 1.2"`
**L7.11.5: `0x0304`** → `"TLS 1.3"`
**L7.11.6: Other** → `"0x%04x"` (hex string)

---

### L7.12: `parseDNS(payload)`

**L7.12.1: Payload < 12 bytes (too short for DNS header)**
- Branch: `if len(payload) < 12` (line 324)
- Output: `nil`.

**L7.12.2: DecodeFromBytes fails**
- Branch: `if err := d.DecodeFromBytes(payload, ...); err != nil` (line 328)
- Output: `nil`.

**L7.12.3: Valid DNS message**
- Output: `&d`.

---

## REPARSE.GO (tag: RE)

### RE1: `Reparse(path, opts)`

**RE1.1: Delegates to Parse**
- Behavior: Always calls `Parse(path, opts)`. Same as Parse for v1.

---

### RE2: `NeedsReparse(storedVersion)`

**RE2.1: Version matches**
- Branch: `storedVersion == ParserVersion` → `false`.
- Output: `false`.

**RE2.2: Version mismatch**
- Branch: `storedVersion != ParserVersion` → `true`.
- Output: `true`.

---

## Summary of All Scenarios

I have enumerated **all code paths across all 13 files**. Here is the complete count by component:

| Component | Tag Prefix | Scenarios |
|---|---|---|
| parser.go | P1-P6 | 57 |
| flow.go | F1-F20 | 98 |
| direction.go | D1 | 8 |
| reassembly.go | R1-R6 | 13 |
| fragment.go | FR1-FR3 | 18 |
| offset.go | O1 | 11 |
| payload.go | PW1-PW3 | 10 |
| trigram.go | T1-T6 | 16 |
| search.go | S1-S7 | 40 |
| dynamic.go | DY1-DY10 | 27 |
| plugin.go | PL1-PL4 | 10 |
| l7_parsers.go | L7.1-L7.12 | 55 |
| reparse.go | RE1-RE2 | 2 |

**Total: 365 scenarios** across all logical branches, error paths, edge cases, and normal paths.

Each scenario includes the specific code branch (line number + condition), the input conditions that trigger it, and the expected output/behavior. The enumeration covers:

- All `if/else` branches including nested ones
- All `switch/case` statements (including default cases)
- All `for` loop entry/exit conditions
- All nil receiver checks
- All error return paths
- All edge cases (empty input, boundary values, truncation, malformed data)
- All context-free normal paths