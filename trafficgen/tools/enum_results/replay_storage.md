Now I have all the files. Let me compile the comprehensive enumeration of every business scenario, branch, error path, edge case, and context cancellation path across all these components.

---

## 1. PLANNER (`planner.go`)

### PlanReplay (line 58-64)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP1 | PlanReplay | Valid JSON spec | Unmarshal succeeds, delegates to Plan | Line 60: `json.Unmarshal` success, line 63 |
| RP2 | PlanReplay | Invalid JSON spec | Return error wrapping unmarshal failure | Line 60: `err != nil`, line 61 return |

### Plan (line 70-216)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP3 | Plan.GetAsset | Valid asset ID + userID | Asset loaded, continue | Line 74: err == nil |
| RP4 | Plan.GetAsset | Non-existent asset ID / wrong userID | Return error "pcap asset X: not found" | Line 75: `err != nil`, line 76 return |
| RP5 | Plan.AssetStatus | asset.Status == "ready" | Continue to load flows | Line 78: check passes |
| RP6 | Plan.AssetStatus | asset.Status == "importing" | Return error "not ready" | Line 78: `!= "ready"`, line 79 return |
| RP7 | Plan.AssetStatus | asset.Status == "error" | Return error "not ready" | Line 78: `!= "ready"`, line 79 return |
| RP8 | Plan.AssetStatus | asset.Status == "reindexing" | Return error "not ready" | Line 78: `!= "ready"`, line 79 return |
| RP9 | Plan.ListFlowsByAsset | DB query succeeds | flows loaded, total returned | Line 83-84: err == nil |
| RP10 | Plan.ListFlowsByAsset | DB query fails | Return error "load flows: ..." | Line 84-85: `err != nil`, line 85 return |
| RP11 | Plan.ListFlowsByAsset | Zero flows returned | Empty flowMap, no packets emitted | Line 83: len(flows)==0, but no error; flowMap empty at line 98 |
| RP12 | Plan.DirStatus | flow.DirStatus == "uncertain" | Log warning, continue | Line 91: `f.DirStatus == "uncertain"`, line 92-96 |
| RP13 | Plan.DirStatus | flow.DirStatus == "classified" | No warning, silent continue | Line 91: condition false, loop continues |
| RP14 | Plan.buildFlowContexts | All flows parse OK | flowMap returned | Line 99: err == nil |
| RP15 | Plan.buildFlowContexts | Flow layout JSON parse error | Return error | Line 99: `err != nil`, line 100 return |
| RP16 | Plan.buildFlowContexts | Rule resolve error (strategy, endpoint) | Return error | Line 99: `err != nil`, line 100 return |
| RP17 | Plan.ListAllPacketsByAsset | DB query succeeds | All packets loaded in file order | Line 104: err == nil |
| RP18 | Plan.ListAllPacketsByAsset | DB query fails | Return error "load packets: ..." | Line 105: `err != nil`, line 106 return |
| RP19 | Plan.ChecksumMode | spec.ChecksumMode == "" | Default to "recompute" | Line 110: `checksumMode == ""`, line 111 set |
| RP20 | Plan.ChecksumMode | spec.ChecksumMode == "preserve" | Use "preserve" | Line 110: condition false, keep value |
| RP21 | Plan.NewPacer | spec.Speed.Mode == "original" | TimestampPacer{multiplier:1.0} | Line 113 delegation |
| RP22 | Plan.NewPacer | spec.Speed.Mode == "bps" | TokenBucketPacer | Line 113 delegation |
| RP23 | Plan.NewPacer | spec.Speed.Mode == "max" | MaxPacer | Line 113 delegation |
| RP24 | Plan.NewPacer | spec.Speed.Mode == "" | MaxPacer | Line 113 delegation |
| RP25 | Plan.OpenPcapFile | File exists, readable | File handle obtained | Line 118: err == nil |
| RP26 | Plan.OpenPcapFile | File missing / permission denied | Log error, close channel, return | Line 119: `err != nil`, line 120-121 log+return |
| RP27 | Plan.Loop | spec.Loop == 0 (infinite) | Capped to 1 pass | Line 126: `loops == 0`, line 127 set to 1 |
| RP28 | Plan.Loop | spec.Loop == 3 | 3 loop iterations | Line 126: condition false, loops=3 |
| RP29 | Plan.Loop | spec.Loop == 1 | 1 loop iteration | Line 126: condition false, loops=1 |
| RP30 | Plan.PcapDuration | len(packets) > 1 | Duration from first/last ts | Line 133: `len(packets) > 1`, lines 134-136 |
| RP31 | Plan.PcapDuration | len(packets) == 0 | pcapDuration stays 0 | Line 133: condition false |
| RP32 | Plan.PcapDuration | len(packets) == 1 | pcapDuration stays 0 (no range) | Line 133: condition false |
| RP33 | Plan.FlowScalingConflict | No conflict | Continue | Line 139: err == nil |
| RP34 | Plan.FlowScalingConflict | FlowScaling varies field that a field rule sets | Log error, close channel, return | Line 140: `err != nil`, lines 140-141 |
| RP35 | Plan.InterleaveSerial | FlowScaling != nil && Interleave == "serial" | interleaveSerial = true | Line 143: both conditions true |
| RP36 | Plan.InterleaveSerial | FlowScaling == nil | interleaveSerial = false | Line 143: short-circuit false |
| RP37 | Plan.InterleaveSerial | FlowScaling != nil && Interleave != "serial" | interleaveSerial = false | Line 143: second condition false |
| RP38 | Plan.CloneCount | FlowScaling != nil | cloneCount = FlowScaling.Count | Line 147-148 |
| RP39 | Plan.CloneCount | FlowScaling == nil | cloneCount = 0 | Line 147: condition false |
| RP40 | Plan.StackCloneCount | !interleaveSerial && cloneCount > 0 | stackCloneCount = cloneCount | Line 153: both true |
| RP41 | Plan.StackCloneCount | interleaveSerial is true | stackCloneCount = 0 | Line 153: first condition false |
| RP42 | Plan.StackCloneCount | cloneCount == 0 | stackCloneCount = 0 | Line 153: second condition false |
| RP43 | Plan.generateClones | Clone generation succeeds | roundClones returned | Line 161: err == nil |
| RP44 | Plan.generateClones | Clone generation fails (e.g. invalid IP) | Log error, close channel, return | Line 162: `err != nil`, lines 163-164 |
| RP45 | Plan.generateClones | FlowScaling == nil | roundClones is nil | Line 161: generateClones returns nil,nil |
| RP46 | Plan.SerialModeOuter | interleaveSerial && len(roundClones) > 0 | Serial mode: clone-outer loop | Line 167: both true |
| RP47 | Plan.SerialModeOuter | interleaveSerial false | Stack mode (else branch) | Line 167: first condition false, line 178 |
| RP48 | Plan.SerialModeOuter | interleaveSerial true but no clones | Stack mode (else branch) | Line 167: second condition false, line 178 |
| RP49 | Plan.SerialCloneLoop | ci from 0 to len(roundClones)-1 | Each clone iterated | Line 168: `for ci < len(roundClones)` |
| RP50 | Plan.SerialCloneLoop | len(roundClones) == 0 | Loop body never entered | Line 168: 0 iterations |
| RP51 | Plan.SerialPacketLoop | ctx.Err() != nil | Goroutine returns, channel closed | Line 170: `ctx.Err() != nil`, line 171 return |
| RP52 | Plan.SerialPacketLoop | ctx not cancelled | emitPacket called | Line 170: condition false, line 173 |
| RP53 | Plan.SerialPacketLoop | emitPacket returns false | Goroutine returns | Line 173-174: `!emitPacket(...)` → return |
| RP54 | Plan.SerialPacketLoop | emitPacket returns true | Continue to next packet | Line 173-174: condition false |
| RP55 | Plan.StackPacketLoop | ctx.Err() != nil | Goroutine returns | Line 181: `ctx.Err() != nil`, line 182 return |
| RP56 | Plan.StackPacketLoop | ctx not cancelled | Process packet | Line 181: condition false |
| RP57 | Plan.StackFlowLookup | flowMap[pkt.FlowID] exists | fc returned, continue | Line 184: `ok == true` |
| RP58 | Plan.StackFlowLookup | flowMap[pkt.FlowID] not found | Skip packet (continue) | Line 185: `!ok`, line 186 continue |
| RP59 | Plan.StackReadAt | pcapFile.ReadAt succeeds | raw bytes read | Line 189: err == nil |
| RP60 | Plan.StackReadAt | pcapFile.ReadAt fails (disk error, truncated) | Skip packet (continue) | Line 190: `err != nil`, line 190 continue |
| RP61 | Plan.StackReadAt | pkt.RawOffset past EOF | ReadAt returns error, skip | Line 190: `err != nil`, continue |
| RP62 | Plan.StackCloneMode | stackCloneCount > 0 | Clone inner loop | Line 193: condition true |
| RP63 | Plan.StackCloneMode | stackCloneCount == 0 | No clones, emit single packet | Line 193: condition false, line 203 |
| RP64 | Plan.StackCloneInnerLoop | ci from 0 to stackCloneCount-1 | Each clone processed | Line 194 |
| RP65 | Plan.StackCloneInnerLoop | stackCloneCount == 0 | Inner loop never entered | Line 193: already false |
| RP66 | Plan.StackClonePatches | clonePatches + seqOffsetPatch | Patches assembled | Lines 195-198 |
| RP67 | Plan.StackCloneSeqOffset | seqOffsetPatch returns ok=true | Seq patch appended | Line 196-197: ok true |
| RP68 | Plan.StackCloneSeqOffset | seqOffsetPatch returns ok=false | No seq patch | Line 196-197: ok false |
| RP69 | Plan.StackCloneEmit | emitReplayCfg returns false | Goroutine returns | Line 199: `!emitReplayCfg(...)` |
| RP70 | Plan.StackCloneEmit | emitReplayCfg returns true | Continue to next clone | Line 199: condition false |
| RP71 | Plan.StackNoCloneEmit | emitReplayCfg returns false | Goroutine returns | Line 204: `!emitReplayCfg(...)` |
| RP72 | Plan.StackNoCloneEmit | emitReplayCfg returns true | Continue to next packet | Line 204: condition false |
| RP73 | Plan.LoopBaseAdvance | After each loop iteration | loopBase += pcapDuration | Line 212 |
| RP74 | Plan.LoopBaseAdvance | pcapDuration == 0 | loopBase unchanged | Line 212: +0 |
| RP75 | Plan.LoopCount | loops == 0 (shouldn't happen, capped) | 0 iterations — but capped to 1 | See RP27, guards at line 126 |
| RP76 | Plan.LoopIteration | loop=0, packets=0 | No packets emitted, loopBase advances, loop ends | Lines 157-213 |

### Context Cancellation Paths in Plan goroutine

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-C1 | Plan.SerialMode | ctx cancelled during serial packet loop | Goroutine returns, channel closed | Line 170: `ctx.Err() != nil` → return |
| RP-C2 | Plan.StackMode | ctx cancelled during stack packet loop | Goroutine returns, channel closed | Line 181: `ctx.Err() != nil` → return |
| RP-C3 | Plan.SerialMode | ctx cancelled during emitReplayCfg select | emitReplayCfg returns false → goroutine returns | Line 261: `<-ctx.Done()` → return false |
| RP-C4 | Plan.StackMode | ctx cancelled during emitReplayCfg select (clone path) | emitReplayCfg returns false → goroutine returns | Line 261: `<-ctx.Done()` → return false |
| RP-C5 | Plan.StackMode | ctx cancelled during emitReplayCfg select (no-clone path) | emitReplayCfg returns false → goroutine returns | Line 261: `<-ctx.Done()` → return false |
| RP-C6 | Plan | ctx cancelled before goroutine starts | Channel returned but goroutine never runs; caller drains, gets empty channel close | Lines 115-116: goroutine created after channel; ctx check inside goroutine only |
| RP-C7 | Plan | ctx cancelled during generateClones | No ctx check at line 161; goroutine continues to log error or proceeds | Missing ctx check at line 161-162: if generateClones takes long, no cancellation |
| RP-C8 | Plan | ctx cancelled during checkFlowScalingConflict | No ctx check at line 139 | Missing ctx check at line 139 |
| RP-C9 | Plan | ctx cancelled during os.Open | No ctx check at line 118 | Missing ctx check at line 118 |
| RP-C10 | Plan | ctx cancelled during pcapDuration computation | No ctx check before line 133 | Missing ctx check at lines 133-137 |

### emitPacket (line 220-235)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-E1 | emitPacket | FlowID not in flowMap | Return true (skip) | Line 222: `!ok`, line 223 return true |
| RP-E2 | emitPacket | ReadAt fails | Return true (skip) | Line 226: `err != nil`, line 227 return true |
| RP-E3 | emitPacket | ReadAt succeeds | Process packet | Line 226: err == nil, continue |
| RP-E4 | emitPacket | seqOffsetPatch returns ok=true | Seq patch appended | Line 231-232: ok true |
| RP-E5 | emitPacket | seqOffsetPatch returns ok=false | No seq patch | Line 231-232: ok false |
| RP-E6 | emitPacket | emitReplayCfg returns false | Return false (propagate cancel) | Line 234: false → return false |
| RP-E7 | emitPacket | emitReplayCfg returns true | Return true (continue) | Line 234: true → return true |

### emitReplayCfg (line 238-264)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-F1 | emitReplayCfg | Channel send succeeds | Return true | Line 259: `out <- cfg` selected |
| RP-F2 | emitReplayCfg | Context cancelled | Return false | Line 261: `<-ctx.Done()` selected |

### buildFlowContexts (line 267-312)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-B1 | buildFlowContexts | Zero flows | Empty map returned | Line 269: loop has 0 iterations, line 311 return `m` |
| RP-B2 | buildFlowContexts | Flow has OffsetLayout | Parse JSON layout | Line 271: `flow.OffsetLayout != ""` |
| RP-B3 | buildFlowContexts | Flow OffsetLayout valid JSON | Layout parsed successfully | Line 272: err == nil |
| RP-B4 | buildFlowContexts | Flow OffsetLayout invalid JSON | Return error | Line 273: `err != nil`, line 273 return |
| RP-B5 | buildFlowContexts | Flow has no OffsetLayout (empty string) | Default layout with -1 offsets | Line 275: else branch, line 276 |
| RP-B6 | buildFlowContexts | computeFlowPatches succeeds | Flow patches returned | Line 279: err == nil |
| RP-B7 | buildFlowContexts | computeFlowPatches fails (rule conflict) | Return error | Line 280: `err != nil`, line 280 return |
| RP-B8 | buildFlowContexts | Zero rewrite rules | Empty endpoint/offset/macmap slices | Line 285: loop has 0 iterations |
| RP-B9 | buildFlowContexts | Rule does not match flow | Rule skipped | Line 286: `!matchRule(...)` → continue |
| RP-B10 | buildFlowContexts | Endpoint rule, strategy resolves | endpointRule appended | Line 289-294: case "endpoint" |
| RP-B11 | buildFlowContexts | Endpoint rule, strategy fails (no value, empty list) | Return error | Line 292: `err != nil`, line 293 return |
| RP-B12 | buildFlowContexts | Field rule, apply:offset, delta resolves | offsetRule appended | Line 296-303: case "field" + Apply=="offset" |
| RP-B13 | buildFlowContexts | Field rule, apply:offset, delta fails | Return error | Line 300: `err != nil`, line 301 return |
| RP-B14 | buildFlowContexts | Field rule, not apply:offset | No offsetRule, flowPatches already handles it | Line 298: `rule.Apply != "offset"` |
| RP-B15 | buildFlowContexts | Macmap rule | macmap rule appended to slice | Line 305-306: case "macmap" |
| RP-B16 | buildFlowContexts | Unknown rule kind | No-op (ignored — not matched by switch) | No matching case; falls through switch silently |

### assemblePatches (line 318-343)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-A1 | assemblePatches | All patch types present | Combined patch list returned | Lines 319-342 |
| RP-A2 | assemblePatches | No flow patches | Empty patch list initialized | Line 319: cap=0+... |
| RP-A3 | assemblePatches | endpointPatch returns error | Skip that endpoint | Line 327: `err != nil`, line 328 continue |
| RP-A4 | assemblePatches | endpointPatch succeeds | Append patch | Line 327: err == nil, line 330 |
| RP-A5 | assemblePatches | offsetValuePatch returns ok=false | Skip that offset | Line 334: `!ok` |
| RP-A6 | assemblePatches | offsetValuePatch returns ok=true | Append patch | Line 334: ok true, line 335 |
| RP-A7 | assemblePatches | macmapPatches returns empty | Nothing appended | Line 340: result may be empty |
| RP-A8 | assemblePatches | macmapPatches returns patches | All appended | Line 340: spread into slice |

### offsetValuePatch (line 348-368)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-O1 | offsetValuePatch | fieldSpecFor returns false | Return false | Line 349: `!ok` |
| RP-O2 | offsetValuePatch | offset < 0 (field absent in layout) | Return false | Line 350: `spec.offset < 0` |
| RP-O3 | offsetValuePatch | offset+width > len(raw) | Return false (out of bounds) | Line 350: second condition |
| RP-O4 | offsetValuePatch | width == 4 (seq/ack/ip_id) | Read uint32, add delta, return patch | Line 353-359 |
| RP-O5 | offsetValuePatch | width == 2 (window/ip_id/port) | Read uint16, add delta, return patch | Line 354-365 |
| RP-O6 | offsetValuePatch | width other (e.g. 1 for ttl) | Return false (unsupported width) | Line 367: default, return false |
| RP-O7 | offsetValuePatch | uint32 overflow (0xFFFFFFFF + 1) | Wraps to 0 naturally | Line 356: `orig + or.delta` unsigned wrap |
| RP-O8 | offsetValuePatch | uint16 overflow (0xFFFF + 1) | Wraps to 0 naturally | Line 362: `orig + uint16(or.delta)` unsigned wrap |

### macmapPatches (line 372-391)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-M1 | macmapPatches | SrcMAC offset valid, src MAC in mapping | Patch appended | Lines 374-379 |
| RP-M2 | macmapPatches | SrcMAC offset valid, src MAC NOT in mapping | No patch | Line 376: `!ok` |
| RP-M3 | macmapPatches | SrcMAC offset valid, mapping value invalid MAC | Parse error, skip | Line 377: `err != nil` |
| RP-M4 | macmapPatches | SrcMAC offset < 0 | Skip src MAC | Line 374: condition false |
| RP-M5 | macmapPatches | SrcMAC+6 > len(raw) | Skip src MAC (out of bounds) | Line 374: second condition false |
| RP-M6 | macmapPatches | DstMAC offset valid, dst MAC in mapping | Patch appended | Lines 382-387 |
| RP-M7 | macmapPatches | DstMAC offset valid, dst MAC NOT in mapping | No patch | Line 384: `!ok` |
| RP-M8 | macmapPatches | DstMAC offset valid, mapping value invalid MAC | Parse error, skip | Line 385: `err != nil` |
| RP-M9 | macmapPatches | DstMAC offset < 0 | Skip dst MAC | Line 382: condition false |
| RP-M10 | macmapPatches | DstMAC+6 > len(raw) | Skip dst MAC (out of bounds) | Line 382: second condition false |
| RP-M11 | macmapPatches | Both src and dst MAC match | Two patches returned | Both branches hit |
| RP-M12 | macmapPatches | Neither MAC matches | Empty slice returned | Neither branch creates patch |

### mapDirection (line 402-410)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RP-D1 | mapDirection | "c2s" | Return "up" | Line 404-405 |
| RP-D2 | mapDirection | "s2c" | Return "down" | Line 406-407 |
| RP-D3 | mapDirection | "" (empty) | Return "" | Line 409: default |
| RP-D4 | mapDirection | "unknown" | Return "unknown" | Line 409: default |

---

## 2. REWRITER (`rewriter.go`)

### ApplyPatches (line 21-51)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RW1 | ApplyPatches | Empty patches list | Copy frame, no checksum recompute | Line 26: loop 0 iterations; line 42: `checksumMode=="recompute"` check |
| RW2 | ApplyPatches | Single patch, valid bounds | Patch applied | Line 27-30: bounds ok, copy |
| RW3 | ApplyPatches | Patch offset < 0 | Return error | Line 27: `p.Offset < 0` |
| RW4 | ApplyPatches | Patch offset+len > frame length | Return error | Line 27: `p.Offset+len(p.Bytes) > len(out)` |
| RW5 | ApplyPatches | Patch layer == "l3" | touchedL3 = true | Line 32-33 |
| RW6 | ApplyPatches | Patch layer == "l4" | touchedL4 = true | Line 34-35 |
| RW7 | ApplyPatches | Patch layer == "l2" | No flag set | Line 31: no matching case |
| RW8 | ApplyPatches | Patch layer unknown (e.g. "l5") | No flag set | Line 31: no matching case |
| RW9 | ApplyPatches | checksumMode="recompute", no L3/L4 patches | IP checksum recomputed, L4 checksum recomputed | Line 42: true; line 43: true; line 46: true |
| RW10 | ApplyPatches | checksumMode="preserve", L3 patch | IP checksum recomputed, L4 checksum recomputed | Line 42: touchedL3=true; line 43: true; line 46: true |
| RW11 | ApplyPatches | checksumMode="preserve", L4 patch | IP checksum NOT recomputed, L4 checksum recomputed | Line 42: touchedL4=true; line 43: false (touchedL3 false, checksumMode!="recompute"); line 46: true |
| RW12 | ApplyPatches | checksumMode="preserve", L2 patch only | Neither checksum recomputed | Line 42: all false |
| RW13 | ApplyPatches | checksumMode="preserve", no patches | Neither checksum recomputed | Line 42: all false |
| RW14 | ApplyPatches | checksumMode="recompute", L3+L4 patches | Both checksums recomputed | Line 42: true; line 43: true; line 46: true |
| RW15 | ApplyPatches | checksumMode="recompute", L2 patch only | Both checksums recomputed (mode forces it) | Line 42: true; line 43: true; line 46: true |
| RW16 | ApplyPatches | Multiple patches, one out of bounds mid-loop | Error returned, partial copy discarded | Line 27: bounds check on that patch |
| RW17 | ApplyPatches | Multiple patches at same offset (last one wins) | Last patch value survives | Line 30: each copy overwrites |
| RW18 | ApplyPatches | checksumMode="preserve", touchedL3=true but touchedL4=false | Only IP checksum recomputed, L4 checksum NOT recomputed (wait — check: line 46 is `touchedL3 || touchedL4 || recompute` — so L4 IS recomputed) | Line 42: true; line 43: true; line 46: true |
| RW19 | ApplyPatches | checksumMode="preserve", touchedL3=false, touchedL4=true | IP checksum NOT recomputed, L4 checksum recomputed | Line 42: true; line 43: false; line 46: true |

---

## 3. RULE (`rule.go`)

### matchRule (line 19-50)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU1 | matchRule | Protocol set, flow protocol doesn't match | Return false | Line 20: `m.Protocol != "" && flow.L4Protocol != m.Protocol` |
| RU2 | matchRule | Protocol set, flow protocol matches | Continue to IP/port checks | Line 20: condition false |
| RU3 | matchRule | Protocol empty | Continue to IP/port checks | Line 20: first condition false |
| RU4 | matchRule | Both SrcIP and DstIP set, both directions match | Return true | Line 31-35: pair1 or pair2 true |
| RU5 | matchRule | Both SrcIP and DstIP set, neither direction matches full pair | Return false | Line 32-34: `!pair1 && !pair2`, line 35 return false |
| RU6 | matchRule | Both SrcIP and DstIP set, but cross-matched (A->B matcher, B->A flow) | pair2 matches, return true | Line 33: `ipMatch(m.SrcIP, flow.DstIP) && ipMatch(m.DstIP, flow.SrcIP)` |
| RU7 | matchRule | Only SrcIP set, srcIPMatch fails | Return false | Line 37: `!srcIPMatch` |
| RU8 | matchRule | Only SrcIP set, srcIPMatch succeeds | Continue to port check | Line 37: first condition false |
| RU9 | matchRule | Only DstIP set, dstIPMatch fails | Return false | Line 37: `!dstIPMatch` |
| RU10 | matchRule | Only DstIP set, dstIPMatch succeeds | Continue to port check | Line 37: condition false |
| RU11 | matchRule | Neither SrcIP nor DstIP set | Skip IP check entirely | Line 31: `m.SrcIP != ""` false, line 37: `!srcIPMatch` — srcIPMatch is true (m.SrcIP=="") |
| RU12 | matchRule | Both SrcPort and DstPort set, pair matches | Return true | Line 40-43: pair1 or pair2 true |
| RU13 | matchRule | Both SrcPort and DstPort set, no pair matches | Return false | Line 42-43: `!pair1 && !pair2`, line 43 return false |
| RU14 | matchRule | Both SrcPort and DstPort set, cross-matched | pair2 matches (srcPort matches flow dstPort) | Line 41: `m.SrcPort == flow.DstPort && m.DstPort == flow.SrcPort` |
| RU15 | matchRule | Only SrcPort set, srcPortMatch fails | Return false | Line 46: `!srcPortMatch` |
| RU16 | matchRule | Only SrcPort set, srcPortMatch succeeds | Continue to final return | Line 46: condition false |
| RU17 | matchRule | Only DstPort set, dstPortMatch fails | Return false | Line 46: `!dstPortMatch` |
| RU18 | matchRule | Only DstPort set, dstPortMatch succeeds | Return true | Line 46: condition false, line 49 |
| RU19 | matchRule | Neither port set | Return true | Line 40: both false, line 46: both portMatch true (0==0) |
| RU20 | matchRule | All fields wildcard | Return true | All conditions pass: line 20 false, line 31 false, line 37: both true, line 40 false, line 46: both true |

### ipMatch (line 54-67)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU21 | ipMatch | Exact match | Return true | Line 55: `pattern == ipStr` |
| RU22 | ipMatch | Valid CIDR, IP matches | Return true | Line 58-66: CIDR parse OK, IP parse OK, Contains true |
| RU23 | ipMatch | Valid CIDR, IP does NOT match | Return false | Line 66: Contains returns false |
| RU24 | ipMatch | Invalid CIDR (not a CIDR and not exact) | Return false | Line 58-59: ParseCIDR error, line 60 return false |
| RU25 | ipMatch | Valid CIDR, ipStr not a valid IP | Return false | Line 62-63: ParseIP returns nil, line 64 return false |
| RU26 | ipMatch | Empty pattern | Return false (not exact match, ParseCIDR fails) | Line 55: false, line 58-59: ParseCIDR error, line 60 return false |
| RU27 | ipMatch | Empty ipStr | Return false (not exact match, ParseIP nil) | Line 55: false, line 58-59: CIDR parse OK, line 62-63: ParseIP nil, line 64 return false |

### fieldSpecFor (line 84-116)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU28 | fieldSpecFor | "src_ip" | l3, 4 bytes, layout.SrcIP offset | Line 87 |
| RU29 | fieldSpecFor | "dst_ip" | l3, 4 bytes, layout.DstIP offset | Line 88 |
| RU30 | fieldSpecFor | "src_port" | l4, 2 bytes, layout.SrcPort offset | Line 90-91 |
| RU31 | fieldSpecFor | "dst_port" | l4, 2 bytes, layout.DstPort offset | Line 92-93 |
| RU32 | fieldSpecFor | "src_mac" | l2, 6 bytes, layout.SrcMAC offset | Line 94-95 |
| RU33 | fieldSpecFor | "dst_mac" | l2, 6 bytes, layout.DstMAC offset | Line 96-97 |
| RU34 | fieldSpecFor | "ttl" | l3, 1 byte, layout.TTL offset | Line 98-99 |
| RU35 | fieldSpecFor | "dscp" | l3, 1 byte, layout.DSCPECN offset | Line 100-101 |
| RU36 | fieldSpecFor | "ecn" | l3, 1 byte, layout.DSCPECN offset (same byte as dscp) | Line 102-103 |
| RU37 | fieldSpecFor | "ip_id" | l3, 2 bytes, layout.IPID offset | Line 104-105 |
| RU38 | fieldSpecFor | "seq" | l4, 4 bytes, layout.Seq offset | Line 106-107 |
| RU39 | fieldSpecFor | "ack" | l4, 4 bytes, layout.Ack offset | Line 108-109 |
| RU40 | fieldSpecFor | "window" | l4, 2 bytes, layout.Window offset | Line 110-111 |
| RU41 | fieldSpecFor | "tcp_flags" | l4, 1 byte, layout.TCPFlags offset | Line 112-113 |
| RU42 | fieldSpecFor | Unknown target | Return false | Line 114-115 default |

### encodeValue (line 119-173)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU43 | encodeValue | "src_mac", valid MAC | Return MAC bytes | Line 123-128 |
| RU44 | encodeValue | "src_mac", invalid MAC | Return error | Line 124-127 |
| RU45 | encodeValue | "src_ip", valid IPv4 | Return 4-byte IP | Line 122-134 |
| RU46 | encodeValue | "src_ip", invalid IP string | Return error | Line 130-131 |
| RU47 | encodeValue | "src_ip", valid IPv6 | Return error "IPv6 not supported" | Line 133-136 |
| RU48 | encodeValue | "dst_ip", valid IPv4 | Return 4-byte IP | Line 122-134 |
| RU49 | encodeValue | "src_port", valid uint16 | Return 2-byte BE | Line 137-144 |
| RU50 | encodeValue | "src_port", invalid parse | Return error | Line 138-140 |
| RU51 | encodeValue | "dst_port", valid | Return 2-byte BE | Line 137-144 |
| RU52 | encodeValue | "ttl", valid uint8 | Return 1 byte | Line 145-150 |
| RU53 | encodeValue | "ttl", invalid parse | Return error | Line 146-148 |
| RU54 | encodeValue | "tcp_flags", valid uint8 | Return 1 byte | Line 145-150 |
| RU55 | encodeValue | "dscp", valid uint8 | Return byte << 2 | Line 151-156 |
| RU56 | encodeValue | "dscp", invalid parse | Return error | Line 152-154 |
| RU57 | encodeValue | "ecn", valid uint8 | Return byte & 0x03 | Line 157-162 |
| RU58 | encodeValue | "ecn", invalid parse | Return error | Line 158-160 |
| RU59 | encodeValue | "seq", valid uint32 | Return 4-byte BE | Line 163-171 |
| RU60 | encodeValue | "seq", invalid parse | Return error | Line 164-166 |
| RU61 | encodeValue | "ack", valid uint32 | Return 4-byte BE | Line 163-171 |
| RU62 | encodeValue | "ack", invalid parse | Return error | Line 164-166 |
| RU63 | encodeValue | "window", valid uint16 | Return 2-byte BE | Line 137-144 |
| RU64 | encodeValue | Unknown target | Return error | Line 172: default |

### resolveStrategyValue (line 178-193)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU65 | resolveStrategyValue | "fixed" with value | Return formatted value | Line 180-184 |
| RU66 | resolveStrategyValue | "fixed" with nil value | Return error | Line 181-182 |
| RU67 | resolveStrategyValue | "fixed" with int value 42 | Return "42" | Line 183: `fmt.Sprintf("%v", 42)` |
| RU68 | resolveStrategyValue | "list" with elements | Return first element | Line 185-187 |
| RU69 | resolveStrategyValue | "list" empty | Return error | Line 188-189 |
| RU70 | resolveStrategyValue | "inc" | Return error (inc not supported for flow-level) | Line 190-191 default |
| RU71 | resolveStrategyValue | "random" | Return error | Line 190-191 default |
| RU72 | resolveStrategyValue | Unknown strategy | Return error | Line 190-191 default |

### computeFlowPatches (line 202-257)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU73 | computeFlowPatches | No rules | Empty patches, no error | Line 206: loop 0 iterations, line 256 return |
| RU74 | computeFlowPatches | Rule doesn't match flow | Skip rule | Line 207: `!matchRule(...)` → continue |
| RU75 | computeFlowPatches | genFlowPatches succeeds | Continue to conflict detection | Line 210: err == nil |
| RU76 | computeFlowPatches | genFlowPatches fails (bad rule) | Return error | Line 211: `err != nil`, line 212 return |
| RU77 | computeFlowPatches | Same field, same offset, same value | Continue (idempotent) | Line 219-225: offsetSeen hit, firstName==p.Field, bytesEqual true |
| RU78 | computeFlowPatches | Same field, same offset, DIFFERENT value | Return conflict error | Line 219-224: offsetSeen hit, firstName==p.Field, !bytesEqual, line 224 return error |
| RU79 | computeFlowPatches | DSCP then ECN (different fields, same offset) | Merged TOS byte | Line 229: firstName "dscp" && p.Field "ecn" → merge |
| RU80 | computeFlowPatches | ECN then DSCP (different fields, same offset) | Merged TOS byte | Line 229: firstName "ecn" && p.Field "dscp" → merge |
| RU81 | computeFlowPatches | DSCP+ECN merge — existing DSCP, new ECN | merged[0] = existingDSCP \| (newECN & 0x03) | Line 234-235 |
| RU82 | computeFlowPatches | DSCP+ECN merge — existing ECN, new DSCP | merged[0] = (newDSCP & 0xFC) \| (existingECN & 0x03) | Line 236-237 |
| RU83 | computeFlowPatches | DSCP+ECN merge — existing patch replaced | Old patch in patches list replaced with merged value | Lines 240-245 |
| RU84 | computeFlowPatches | Two different fields at same offset, not DSCP/ECN | Return conflict error | Line 248: `return nil, fmt.Errorf("conflict: offset %d ...")` |
| RU85 | computeFlowPatches | New field, new offset | Patches appended | Line 251-253 |
| RU86 | computeFlowPatches | Three patches: DSCP, ECN, then another DSCP | Second DSCP conflicts with existing DSCP (same field, same offset, different value — see RU78) | Line 219-224 |
| RU87 | computeFlowPatches | Three patches: DSCP, ECN, then another ECN | Second ECN conflicts with existing ECN | Line 219-224 |

### applyIPMap (line 263-284)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU88 | applyIPMap | SrcIP layout valid, IP found in mapping | SrcIP patch appended | Lines 265-272 |
| RU89 | applyIPMap | SrcIP layout valid, IP NOT found | No src patch | Line 266: `!ok` |
| RU90 | applyIPMap | SrcIP layout invalid (< 0) | Skip src | Line 265: condition false |
| RU91 | applyIPMap | SrcIP found but encode fails | Return error | Line 267: `err != nil`, line 268-269 return |
| RU92 | applyIPMap | DstIP layout valid, IP found in mapping | DstIP patch appended | Lines 274-281 |
| RU93 | applyIPMap | DstIP layout valid, IP NOT found | No dst patch | Line 275: `!ok` |
| RU94 | applyIPMap | DstIP layout invalid (< 0) | Skip dst | Line 274: condition false |
| RU95 | applyIPMap | DstIP found but encode fails | Return error | Line 276: `err != nil`, line 277-278 return |
| RU96 | applyIPMap | Both SrcIP and DstIP found | Two patches | Both branches hit |

### lookupIPMap (line 289-318)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU97 | lookupIPMap | ipStr not a valid IP | Return "", false | Line 291: `ip == nil`, line 292 return |
| RU98 | lookupIPMap | Exact match in mapping | Return value, true | Line 295: found |
| RU99 | lookupIPMap | Exact match, value is CIDR target | Return the CIDR string as-is | Line 295-296: just returns the value |
| RU100 | lookupIPMap | No exact match, iterate CIDR keys | Loop over mapping | Line 302: for loop |
| RU101 | lookupIPMap | Key is not a valid CIDR | Skip to next key | Line 303-304: ParseCIDR error, continue |
| RU102 | lookupIPMap | CIDR key does not contain IP | Skip to next key | Line 306-307: `!cidr.Contains(ip)`, continue |
| RU103 | lookupIPMap | CIDR key matches, more specific than previous | Update best | Lines 309-314: `ones > bestMask` |
| RU104 | lookupIPMap | CIDR key matches, less specific than previous | Skip | Line 311: `ones > bestMask` false |
| RU105 | lookupIPMap | Multiple CIDR keys match, most specific wins | Return best CIDR translation | Line 317: `bestNew, found` |
| RU106 | lookupIPMap | No exact match, no CIDR matches | Return "", false | Line 317: found=false |
| RU107 | lookupIPMap | Mapping is empty | Return "", false | Line 302: loop 0 iterations, found=false |

### translateCIDR (line 323-353)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU108 | translateCIDR | targetSpec is not a valid CIDR, is a valid IP | Return IP string | Line 324: ParseCIDR error, line 327: ParseIP not nil, line 328 return |
| RU109 | translateCIDR | targetSpec is not a CIDR, not an IP either | Return targetSpec as-is | Line 324: ParseCIDR error, line 327: ParseIP nil, line 330 return |
| RU110 | translateCIDR | ip is not IPv4 (IPv6) | Return target as IP string | Line 334: `v4 == nil`, line 335-338 |
| RU111 | translateCIDR | ip is not IPv4, target not an IP | Return targetSpec as-is | Line 334: v4==nil, line 335: ParseIP nil, line 338 |
| RU112 | translateCIDR | Valid IPv4, valid CIDR target | Compute host offset, translate | Lines 340-352 |
| RU113 | translateCIDR | dst subnet smaller than src subnet | Host offset restricted to dst host bits | Line 347: `dstHostBits < srcHostBits`, line 348 |
| RU114 | translateCIDR | dst subnet larger than src subnet | Full host offset preserved | Line 347: condition false |
| RU115 | translateCIDR | src has /0 (all IPs) | hostOffset = full 32-bit value; dstBase | 0, newIP = hostOffset | Line 343: srcHostBits=32, maskLowBits(32) = 0xFFFFFFFF |
| RU116 | translateCIDR | src has /32 (single IP) | hostOffset = 0, newIP = dstBase | Line 343: srcHostBits=0, maskLowBits(0) = 0 |

### maskLowBits (line 370-378)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU117 | maskLowBits | n <= 0 | Return 0 | Line 372: `n <= 0` |
| RU118 | maskLowBits | n >= 32 | Return 0xFFFFFFFF | Line 374: `n >= 32` |
| RU119 | maskLowBits | n = 8 | Return 0xFF | Line 376: `(1 << 8) - 1` |
| RU120 | maskLowBits | n = 16 | Return 0xFFFF | Line 376 |

### genFlowPatches (line 381-415)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU121 | genFlowPatches | kind="ipmap" | Delegate to applyIPMap | Line 383-384 |
| RU122 | genFlowPatches | kind="portmap", src port in mapping, layout valid | Src port patch | Lines 387-394 |
| RU123 | genFlowPatches | kind="portmap", src port in mapping, layout invalid | Skip src | Line 389: `layout.SrcPort >= 0` false |
| RU124 | genFlowPatches | kind="portmap", src port in mapping, encode fails | Return error | Line 390: err != nil |
| RU125 | genFlowPatches | kind="portmap", src port NOT in mapping | Skip src | Line 389: `!ok` |
| RU126 | genFlowPatches | kind="portmap", dst port in mapping, layout valid | Dst port patch | Lines 396-401 |
| RU127 | genFlowPatches | kind="portmap", dst port in mapping, layout invalid | Skip dst | Line 396: `layout.DstPort >= 0` false |
| RU128 | genFlowPatches | kind="portmap", dst port in mapping, encode fails | Return error | Line 397: err != nil |
| RU129 | genFlowPatches | kind="portmap", dst port NOT in mapping | Skip dst | Line 396: `!ok` |
| RU130 | genFlowPatches | kind="macmap" | Return nil (handled per-packet) | Line 404-407 |
| RU131 | genFlowPatches | kind="field" | Delegate to genFieldPatches | Line 408-409 |
| RU132 | genFlowPatches | kind="endpoint" | Return nil (handled per-packet) | Line 410-412 |
| RU133 | genFlowPatches | Unknown kind | Return error | Line 413-414 |

### genFieldPatches (line 421-442)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU134 | genFieldPatches | apply="offset" | Return nil (handled per-packet by planner) | Line 422-424 |
| RU135 | genFieldPatches | fieldSpecFor returns false | Return error | Line 427-428 |
| RU136 | genFieldPatches | field offset < 0 (absent in layout) | Return error | Line 430-431 |
| RU137 | genFieldPatches | resolveStrategyValue fails | Return error | Line 434-435 |
| RU138 | genFieldPatches | encodeValue fails | Return error | Line 437-439 |
| RU139 | genFieldPatches | All succeed | Return single patch | Line 441 |

### resolveOffsetDelta (line 446-456)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU140 | resolveOffsetDelta | resolveStrategyValue fails | Return 0, error | Line 447-449 |
| RU141 | resolveOffsetDelta | ParseUint fails | Return error | Line 451-453 |
| RU142 | resolveOffsetDelta | Valid uint value | Return uint32 | Line 454-455 |
| RU143 | resolveOffsetDelta | Value > 2^32 | ParseUint succeeds (uint64), truncates to uint32 | Line 451-454: ParseUint(_, 10, 64) accepts up to 2^64-1, then uint32(v) truncates |

### endpointPatch (line 461-510)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| RU144 | endpointPatch | target="client_ip", dir="c2s" | offset = SrcIP | Line 464-466 |
| RU145 | endpointPatch | target="client_ip", dir="s2c" | offset = DstIP | Line 467-468 |
| RU146 | endpointPatch | target="server_ip", dir="c2s" | offset = DstIP | Line 470-472 |
| RU147 | endpointPatch | target="server_ip", dir="s2c" | offset = SrcIP | Line 473-474 |
| RU148 | endpointPatch | target="client_port", dir="c2s" | offset = SrcPort | Line 476-478 |
| RU149 | endpointPatch | target="client_port", dir="s2c" | offset = DstPort | Line 479-480 |
| RU150 | endpointPatch | target="server_port", dir="c2s" | offset = DstPort | Line 482-484 |
| RU151 | endpointPatch | target="server_port", dir="s2c" | offset = SrcPort | Line 485-486 |
| RU152 | endpointPatch | Unknown target | Return error | Line 488-489 |
| RU153 | endpointPatch | Resolved offset < 0 | Return error | Line 491-492 |
| RU154 | endpointPatch | newVal.To4() returns nil (IPv6 or nil) | Return error | Line 494-496 |
| RU155 | endpointPatch | target ends with "_port", width==2 | Return error "port patching not supported via IP path" | Line 499-507 |
| RU156 | endpointPatch | target="client_ip", valid IPv4, valid offset | Return L3 patch | Line 509 |
| RU157 | endpointPatch | target="server_ip", valid IPv4, valid offset | Return L3 patch | Line 509 |

---

## 4. FLOWSCALING (`flowscaling.go`)

### generateClones (line 17-51)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS1 | generateClones | fs == nil | Return nil, nil | Line 18: first condition true |
| FS2 | generateClones | fs.Count <= 0 | Return nil, nil | Line 18: second condition true |
| FS3 | generateClones | fs.Count == 0 | Return nil, nil | Line 18: second condition true |
| FS4 | generateClones | fs.Count = 5 | 5 clones generated | Line 21: make([], 5) |
| FS5 | generateClones | SrcIP resolution fails | Return error | Line 23-25 |
| FS6 | generateClones | DstIP resolution fails | Return error | Line 27-29 |
| FS7 | generateClones | SrcPort resolution fails | Return error | Line 31-33 |
| FS8 | generateClones | DstPort resolution fails | Return error | Line 35-37 |
| FS9 | generateClones | SrcMAC resolution fails | Error silently ignored, srcMAC="" | Line 39: error ignored with `_` |
| FS10 | generateClones | DstMAC resolution fails | Error silently ignored, dstMAC="" | Line 40: error ignored with `_` |
| FS11 | generateClones | SeqOffset resolution fails | Return error | Line 41-43 |
| FS12 | generateClones | All fields resolved | Return clone slice | Lines 45-48, line 50 |

### resolveCloneStr (line 55-94)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS13 | resolveCloneStr | Strategy "" (empty), Value nil | Return "", nil | Line 57: Strategy "" falls into case "","fixed"; line 58: Value nil; line 59 return |
| FS14 | resolveCloneStr | Strategy "fixed", Value="192.168.1.1" | Return "192.168.1.1" | Line 57-61 |
| FS15 | resolveCloneStr | Strategy "fixed", Value=nil | Return "", nil | Line 58-59 |
| FS16 | resolveCloneStr | Strategy "inc", Range length < 2 | Return error | Line 63-64 |
| FS17 | resolveCloneStr | Strategy "inc", Range valid, step=0, isIP=true | step set to 1, incIP called | Line 68-69: step==0 → step=1; line 72 |
| FS18 | resolveCloneStr | Strategy "inc", step=5, isIP=true | incIP(start, k*5) | Line 72 |
| FS19 | resolveCloneStr | Strategy "inc", isIP=true, IP invalid | incIP returns error | Line 72: err != nil, propagated |
| FS20 | resolveCloneStr | Strategy "inc", isIP=false, numeric start | Parse int, add offset, return | Lines 74-79 |
| FS21 | resolveCloneStr | Strategy "inc", isIP=false, non-numeric start | ParseInt error, return start unchanged | Line 77: err != nil, line 78 return start |
| FS22 | resolveCloneStr | Strategy "random", Range length < 2 | Return error | Line 81-82 |
| FS23 | resolveCloneStr | Strategy "random", valid range, isIP=true | randomInRange with IP | Lines 84-86 |
| FS24 | resolveCloneStr | Strategy "random", valid range, isIP=false | randomInRange numeric | Lines 84-86 |
| FS25 | resolveCloneStr | Strategy "random", IP range invalid | randomInRange returns error | Line 86: propagated |
| FS26 | resolveCloneStr | Strategy "list", empty list | Return error | Line 88-89 |
| FS27 | resolveCloneStr | Strategy "list", 3 elements, clone 5 | Return sc.List[5%3=2] | Line 90-91 |
| FS28 | resolveCloneStr | Strategy "list", 1 element, any clone | Return sc.List[0] | Line 91: k%1 = 0 |
| FS29 | resolveCloneStr | Unknown strategy | Return error | Line 93: default |

### resolveClonePort (line 97-107)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS30 | resolveClonePort | resolveCloneStr returns error | Return 0, error | Line 99: err != nil |
| FS31 | resolveClonePort | resolveCloneStr returns "" | Return 0, nil | Line 99: s == "" |
| FS32 | resolveClonePort | resolveCloneStr returns "8080" | Return 8080, nil | Lines 102-106 |
| FS33 | resolveClonePort | resolveCloneStr returns "99999" (overflow) | ParseUint error | Lines 102-104 |

### resolveCloneSeq (line 110-127)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS34 | resolveCloneSeq | Strategy "", Value nil | Return 0, nil | Line 111-113 |
| FS35 | resolveCloneSeq | Strategy "fixed", Value=1000 | Return 1000, nil | Lines 111-116 |
| FS36 | resolveCloneSeq | Strategy "fixed", Value=nil | Return 0, nil | Lines 111-113 |
| FS37 | resolveCloneSeq | Strategy "fixed", Value="abc" | Return 0, parse error | Lines 115-116 |
| FS38 | resolveCloneSeq | Strategy "inc" | Delegate to resolveCloneStr | Lines 118-126 |
| FS39 | resolveCloneSeq | resolveCloneStr returns error or "" | Return 0, err | Lines 119-120 |
| FS40 | resolveCloneSeq | resolveCloneStr returns value, parse fails | Return error | Lines 122-124 |

### incIP (line 130-144)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS41 | incIP | Invalid IP string | Return error | Line 132: ip == nil |
| FS42 | incIP | IPv6 address | Return error "not IPv4" | Line 136: v4 == nil |
| FS43 | incIP | "10.0.0.1", n=5 | "10.0.0.6" | Lines 139-143 |
| FS44 | incIP | "255.255.255.255", n=1 | "0.0.0.0" (uint32 wraps) | Line 140: uint32 overflow wraps |

### randomInRange (line 148-180)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS45 | randomInRange | isIP=true, loIP or hiIP nil | Return error | Lines 150-153 |
| FS46 | randomInRange | isIP=true, hiV < loV | Swap lo/hi | Lines 157-158 |
| FS47 | randomInRange | isIP=true, valid range | Random IP in [lo, hi] | Lines 160-164 |
| FS48 | randomInRange | isIP=false, lo parse error | Return error | Lines 166-168 |
| FS49 | randomInRange | isIP=false, hi parse error | Return error | Lines 169-171 |
| FS50 | randomInRange | isIP=false, hiN < loN | Swap lo/hi | Lines 174-175 |
| FS51 | randomInRange | isIP=false, valid range | Random int in [lo, hi] | Lines 177-179 |

### newRand (line 183-188)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS52 | newRand | seed=0, k=2 | seed=1, source seeded with 1+2=3 | Line 184-185 |
| FS53 | newRand | seed=42, k=2 | source seeded with 44 | Line 187 |
| FS54 | newRand | seed=1, k=0 | source seeded with 1 | Line 187 |

### clonePatches (line 192-225)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS55 | clonePatches | SrcIP set, layout valid, encode succeeds | SrcIP patch appended | Lines 194-197 |
| FS56 | clonePatches | SrcIP set, layout invalid (SrcIP < 0) | Skip | Line 194: `layout.SrcIP >= 0` false |
| FS57 | clonePatches | SrcIP set, layout valid, encode fails | Skip (error ignored) | Line 195: err != nil, no-op |
| FS58 | clonePatches | SrcIP empty | Skip | Line 194: `c.SrcIP != ""` false |
| FS59 | clonePatches | DstIP set, layout valid, encode succeeds | DstIP patch appended | Lines 199-202 |
| FS60 | clonePatches | DstIP set, layout invalid | Skip | Line 199: condition false |
| FS61 | clonePatches | DstIP set, encode fails | Skip | Line 200: err != nil |
| FS62 | clonePatches | SrcPort non-zero, layout valid | Port patch appended | Lines 204-207 |
| FS63 | clonePatches | SrcPort non-zero, layout invalid | Skip | Line 204: `layout.SrcPort >= 0` false |
| FS64 | clonePatches | SrcPort = 0 | Skip | Line 204: `c.SrcPort != 0` false |
| FS65 | clonePatches | DstPort non-zero, layout valid | Port patch appended | Lines 209-212 |
| FS66 | clonePatches | DstPort non-zero, layout invalid | Skip | Line 209: condition false |
| FS67 | clonePatches | DstPort = 0 | Skip | Line 209: condition false |
| FS68 | clonePatches | SrcMAC set, layout valid, encode succeeds | MAC patch appended | Lines 214-217 |
| FS69 | clonePatches | SrcMAC set, layout invalid | Skip | Line 214: condition false |
| FS70 | clonePatches | SrcMAC set, encode fails | Skip | Line 215: err != nil |
| FS71 | clonePatches | DstMAC set, layout valid, encode succeeds | MAC patch appended | Lines 219-222 |
| FS72 | clonePatches | DstMAC set, layout invalid | Skip | Line 219: condition false |
| FS73 | clonePatches | DstMAC set, encode fails | Skip | Line 220: err != nil |

### seqOffsetPatch (line 229-238)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS74 | seqOffsetPatch | SeqOffset == 0 | Return false | Line 230: first condition |
| FS75 | seqOffsetPatch | SeqOffset != 0, layout.Seq < 0 | Return false | Line 230: second condition |
| FS76 | seqOffsetPatch | SeqOffset != 0, layout.Seq+4 > len(raw) | Return false | Line 230: third condition |
| FS77 | seqOffsetPatch | Valid offset, SeqOffset=1000 | Return patch with origSeq+1000 | Lines 233-237 |
| FS78 | seqOffsetPatch | origSeq = 0xFFFFFFFF, SeqOffset = 1 | Return patch with 0x00000000 (uint32 wrap) | Lines 233-234: wrap |

### checkFlowScalingConflict (line 243-283)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| FS79 | checkFlowScalingConflict | fs == nil | Return nil | Line 244: condition true |
| FS80 | checkFlowScalingConflict | fs.SrcIP.Strategy != "" | varied["src_ip"] = true | Line 249-250 |
| FS81 | checkFlowScalingConflict | fs.SrcIP.Strategy == "" | Not varied | Line 249: condition false |
| FS82 | checkFlowScalingConflict | fs.DstIP.Strategy != "" | varied["dst_ip"] = true | Line 252-253 |
| FS83 | checkFlowScalingConflict | fs.SrcPort.Strategy != "" | varied["src_port"] = true | Line 255-256 |
| FS84 | checkFlowScalingConflict | fs.DstPort.Strategy != "" | varied["dst_port"] = true | Line 258-259 |
| FS85 | checkFlowScalingConflict | fs.SrcMAC.Strategy != "" | varied["src_mac"] = true | Line 261-262 |
| FS86 | checkFlowScalingConflict | fs.DstMAC.Strategy != "" | varied["dst_mac"] = true | Line 264-265 |
| FS87 | checkFlowScalingConflict | field rule with varied target | Return conflict error | Lines 273-274 |
| FS88 | checkFlowScalingConflict | field rule with non-varied target | No conflict | Line 273: `varied[rule.Target]` false |
| FS89 | checkFlowScalingConflict | endpoint rule, target maps to varied field | Return conflict error | Lines 276-279 |
| FS90 | checkFlowScalingConflict | endpoint rule, target doesn't map to varied field | No conflict | Line 277: endpointField[target] not found OR varied[f] false |
| FS91 | checkFlowScalingConflict | No rules | No conflict | Line 272: loop 0 iterations |
| FS92 | checkFlowScalingConflict | ipmap/portmap/macmap rule, varied field | No conflict (mapping rules allow overlap) | Line 273: kind != "field" and kind != "endpoint" |

---

## 5. PACING (`pacing.go`)

### NewPacer (line 25-43)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| PA1 | NewPacer | Mode="original" | TimestampPacer{multiplier:1.0} | Line 27-28 |
| PA2 | NewPacer | Mode="multiplier", Multiplier=1.5 | TimestampPacer{multiplier:1.5} | Line 29-33 |
| PA3 | NewPacer | Mode="multiplier", Multiplier=0 | TimestampPacer{multiplier:1.0} | Line 31: m <= 0, set to 1.0 |
| PA4 | NewPacer | Mode="multiplier", Multiplier=-1 | TimestampPacer{multiplier:1.0} | Line 31: m <= 0, set to 1.0 |
| PA5 | NewPacer | Mode="bps" | TokenBucketPacer{bps: speed.BPS} | Line 35-36 |
| PA6 | NewPacer | Mode="pps" | PPSPacer{pps: speed.PPS} | Line 37-38 |
| PA7 | NewPacer | Mode="max" | MaxPacer{} | Line 39-40 |
| PA8 | NewPacer | Mode="" (empty) | MaxPacer{} | Line 39-40 |
| PA9 | NewPacer | Unknown mode "random" | MaxPacer{} (default) | Line 42: return after switch |

### TimestampPacer.Wait (line 64-91)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| PA10 | TimestampPacer.Wait | First call (not init) | Set firstTsUs, startWall, init=true, return nil | Lines 67-72 |
| PA11 | TimestampPacer.Wait | Subsequent calls, packet on time (scheduled > now) | Sleep until scheduled time | Lines 74-83 |
| PA12 | TimestampPacer.Wait | Subsequent calls, scheduled time is past | Absorb drift, return immediately | Lines 84-89 |
| PA13 | TimestampPacer.Wait | Context cancelled during sleep | Return ctx.Err() | Line 81-82 |
| PA14 | TimestampPacer.Wait | multiplier=0 | delta=0, scheduled == startWall+drift, may be in past | Lines 74-89 |
| PA15 | TimestampPacer.Wait | multiplier=2.0, delta doubled | Sleeps twice as long between packets | Line 74 |
| PA16 | TimestampPacer.Wait | multiplier=0.5 | Sleeps half as long between packets | Line 74 |
| PA17 | TimestampPacer.Wait | Multiple late packets in a row | Drift accumulates, each late packet continues to absorb | Lines 85-89: drift += now.Sub(scheduled) |
| PA18 | TimestampPacer.Wait | Concurrent calls (mutex) | Mutex serializes state access | Lines 65, 71, 76, 86, 88 |
| PA19 | TimestampPacer.Wait | drift gets very large | Scheduled time keeps shifting forward | Line 75: `startWall.Add(delta).Add(p.drift)` |

### MaxPacer.Wait (line 96)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| PA20 | MaxPacer.Wait | Any call | Return nil immediately | Line 96 |

### TokenBucketPacer.Wait (line 107-123)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| PA21 | TokenBucketPacer.Wait | First call, valid BPS | Init bucket, wait on token | Lines 108-118 |
| PA22 | TokenBucketPacer.Wait | First call, ParseBPS error | bucket stays nil | Lines 109-110: err != nil, return from fn |
| PA23 | TokenBucketPacer.Wait | First call, bps <= 0 | bucket stays nil | Line 110: bps <= 0 |
| PA24 | TokenBucketPacer.Wait | bps=8, rateBytesPerSec=1 | Rate = 1 byte/sec | Line 114-115 |
| PA25 | TokenBucketPacer.Wait | bps=1, rateBytesPerSec=0 | Clamped to 1 | Lines 113-115 |
| PA26 | TokenBucketPacer.Wait | bucket is nil (failed init) | Return nil (no limiting) | Line 119-120 |
| PA27 | TokenBucketPacer.Wait | bucket exists, Wait succeeds | Return nil | Line 122: err == nil |
| PA28 | TokenBucketPacer.Wait | bucket exists, Wait fails (ctx cancelled) | Return ctx.Err() | Line 122: err != nil, propagated |
| PA29 | TokenBucketPacer.Wait | Multiple goroutines, first call racing | sync.Once ensures only one init | Line 108: `p.once.Do(...)` |

### PPSPacer.Wait (line 137-156)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| PA30 | PPSPacer.Wait | First call, pps > 0 | Compute interval | Lines 138-141 |
| PA31 | PPSPacer.Wait | First call, pps = 0 | interval stays 0 | Line 139: pps > 0 false |
| PA32 | PPSPacer.Wait | First call, pps = 1000 | interval = 1ms | Line 140: `time.Duration(float64(time.Second) / 1000)` |
| PA33 | PPSPacer.Wait | interval <= 0 | Return nil (no pacing) | Line 143-144 |
| PA34 | PPSPacer.Wait | interval > 0, sleep completes | Return nil | Line 151: `time.After(p.interval)` selected |
| PA35 | PPSPacer.Wait | ctx cancelled during sleep | Return ctx.Err() | Line 152-153 |
| PA36 | PPSPacer.Wait | Concurrent calls | Mutex serializes, enforcing global PPS | Lines 148-149 |
| PA37 | PPSPacer.Wait | pps = 0.5 (fractional) | interval = 2 seconds | Line 140: compute |

---

## 6. CHECKSUM (`checksum.go`)

### setIPChecksum (line 12-26)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| CS1 | setIPChecksum | l3 < 0 | Return (no-op) | Line 14: `l3 < 0` |
| CS2 | setIPChecksum | l3+20 > len(frame) | Return (no-op, frame too short) | Line 14: second condition |
| CS3 | setIPChecksum | l3=14, frame length >= 34 | Zero checksum, compute, write | Lines 17-25 |
| CS4 | setIPChecksum | IP header spans 20 bytes at L3 | Correct sum computed | Line 20: 10 iterations |
| CS5 | setIPChecksum | Frame has IP options (IHL > 5) | Still only sums 20 bytes (ignores options) | Line 20: hardcoded 20 |

### setL4Checksum (line 31-79)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| CS6 | setL4Checksum | l3 < 0 | Return (no-op) | Line 34: first condition |
| CS7 | setL4Checksum | l4 < 0 | Return (no-op) | Line 34: second condition |
| CS8 | setL4Checksum | l4 >= len(frame) | Return (no-op) | Line 34: third condition |
| CS9 | setL4Checksum | L4Protocol="tcp" | proto=6, cksumOff=l4+16 | Line 39-41 |
| CS10 | setL4Checksum | L4Protocol="udp" | proto=17, cksumOff=l4+6 | Line 42-44 |
| CS11 | setL4Checksum | L4Protocol="icmp" | Return (no pseudo-header checksum) | Line 46-47 default |
| CS12 | setL4Checksum | L4Protocol="arp" | Return (no pseudo-header checksum) | Line 46-47 default |
| CS13 | setL4Checksum | L4Protocol="" | Return (no pseudo-header checksum) | Line 46-47 default |
| CS14 | setL4Checksum | cksumOff+2 > len(frame) | Return (no-op) | Line 49: bounds check |
| CS15 | setL4Checksum | l3+20 <= len(frame) | Include pseudo-header IPs | Line 59: true, lines 60-63 |
| CS16 | setL4Checksum | l3+20 > len(frame) | Skip pseudo-header IPs (partial frame) | Line 59: false |
| CS17 | setL4Checksum | l4Len is even | No padding needed | Line 72: `l4Len%2 == 1` false |
| CS18 | setL4Checksum | l4Len is odd | Pad with zero byte (network order) | Lines 73-74 |
| CS19 | setL4Checksum | l4Len = 0 (empty payload) | Only pseudo-header summed | Line 69: loop 0 iterations |
| CS20 | setL4Checksum | TCP with zero checksum originally | Zeroed then recomputed | Line 53: zero, then lines 55-78 |

---

## 7. TYPES (`types.go`) — Structural, no runtime branches

Types is purely structural. No runtime branches, but the struct fields influence behavior throughout the codebase.

| Tag | Component | Notes |
|-----|-----------|-------|
| TY1 | ReplaySpec.Loop | 0 = infinite (capped to 1 in planner) |
| TY2 | ReplaySpec.ChecksumMode | "" defaults to "recompute" |
| TY3 | ReplaySpec.FlowScaling | nil = no amplification |
| TY4 | ReplaySpec.Inject | v2 reserved, not used in v1 |
| TY5 | ReplaySpeed.Mode | empty = "max" |
| TY6 | FlowScaling.Interleave | "" = "stack" (default) |
| TY7 | Patch.Layer | "l2" | "l3" | "l4" — drives checksum recompute scope |

---

## 8. STORAGE — PCAP REPOSITORY (`pcap_repository.go`)

### CreateAsset (line 26-28)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST1 | CreateAsset | gorm.Create succeeds | Return nil | Line 27: err == nil |
| ST2 | CreateAsset | gorm.Create fails (duplicate key, DB err) | Return error | Line 27: err != nil, propagated |

### GetAsset (line 32-38)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST3 | GetAsset | Asset exists, user matches | Return asset | Line 34: err == nil |
| ST4 | GetAsset | Asset doesn't exist | Return gorm.ErrRecordNotFound | Line 34: err != nil |
| ST5 | GetAsset | Asset exists but wrong userID | Return gorm.ErrRecordNotFound | Line 34: Where clause filters by userID |
| ST6 | GetAsset | DB connection error | Return error | Line 34: err != nil |

### GetAssetByHash (line 43-50)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST7 | GetAssetByHash | Matching hash found | Return asset | Line 45: err == nil |
| ST8 | GetAssetByHash | No matching hash | Return nil, err (gorm.ErrRecordNotFound) | Line 45: err != nil |

### UpdateAsset (line 53-55)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST9 | UpdateAsset | Save succeeds | Return nil | Line 54: err == nil |
| ST10 | UpdateAsset | Save fails (record gone, DB error) | Return error | Line 54: err != nil |

### UpdateAssetStatus (line 75-90)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST11 | UpdateAssetStatus | Asset not found | Return error | Line 78: err != nil |
| ST12 | UpdateAssetStatus | Current status not in validStatusTransitions map | Return illegal transition error | Line 82: `!ok` |
| ST13 | UpdateAssetStatus | Current="importing", target="importing" | Allow (self-transition) | Line 82: allowed["importing"] true |
| ST14 | UpdateAssetStatus | Current="importing", target="error" | Allow | Line 82: allowed["error"] true |
| ST15 | UpdateAssetStatus | Current="importing", target="reindexing" | ILLEGAL | Line 82: allowed["reindexing"] false |
| ST16 | UpdateAssetStatus | Current="ready", target="importing" | ILLEGAL (blocks rewind) | Line 82: allowed["importing"] false |
| ST17 | UpdateAssetStatus | Current="ready", target="error" | Allow | Line 82: allowed["error"] true |
| ST18 | UpdateAssetStatus | Current="ready", target="reindexing" | Allow | Line 82: allowed["reindexing"] true |
| ST19 | UpdateAssetStatus | Current="error", target="reindexing" | Allow (retry) | Line 82: allowed["reindexing"] true |
| ST20 | UpdateAssetStatus | Current="error", target="importing" | Allow (reparse) | Line 82: allowed["importing"] true |
| ST21 | UpdateAssetStatus | Current="error", target="ready" | Allow (retry succeeded) | Line 82: allowed["ready"] true |
| ST22 | UpdateAssetStatus | Current="", target="importing" | Allow (new asset) | Line 82: allowed["importing"] true |
| ST23 | UpdateAssetStatus | Current="", target="ready" | ILLEGAL | Line 82: allowed["ready"] false |
| ST24 | UpdateAssetStatus | Updates call fails | Return error | Line 89: err != nil |
| ST25 | UpdateAssetStatus | Valid transition, Updates succeeds | Return nil | Line 89: err == nil |

### ListAssets (line 94-110)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST26 | ListAssets | status = "" | Count all assets for user | Line 99: condition false |
| ST27 | ListAssets | status = "ready" | Filter by status | Line 99: true, line 100 |
| ST28 | ListAssets | Count query fails | Return error | Line 102: err != nil |
| ST29 | ListAssets | Find query fails | Return error | Line 106: err != nil |
| ST30 | ListAssets | Successful query | Return assets + total | Line 109 |
| ST31 | ListAssets | page=1, size=0 | offset=0, LIMIT 0 → empty result | Line 105: offset=0, line 106: Limit(0) |
| ST32 | ListAssets | page=0, size=10 | offset=-10, SQL error | Line 105: `(0-1)*10 = -10` |

### DeleteAsset (line 115-117)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST33 | DeleteAsset | Delete succeeds | Return nil | Line 116: err == nil |
| ST34 | DeleteAsset | Delete fails (record not found) | Return error | Line 116: err != nil |

### DeleteAssetComplete (line 126-158)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST35 | DeleteAssetComplete | Asset not found | Return nil, err | Line 128: err != nil |
| ST36 | DeleteAssetComplete | Transaction: delete packets fails | Return error, transaction rolled back | Line 133: err != nil, line 134 return |
| ST37 | DeleteAssetComplete | Transaction: delete flows fails | Return error, transaction rolled back | Line 136: err != nil, line 137 return |
| ST38 | DeleteAssetComplete | Transaction: delete asset fails | Return error, transaction rolled back | Line 139: err != nil, line 140 return |
| ST39 | DeleteAssetComplete | Transaction succeeds, all paths non-empty, all removes succeed | DB cleared, all files removed | Lines 133-145, 148-155 |
| ST40 | DeleteAssetComplete | StoragePath == "" | Skip file removal | Line 149: path == "" continue |
| ST41 | DeleteAssetComplete | PayloadsPath == "" | Skip file removal | Line 149: path == "" continue |
| ST42 | DeleteAssetComplete | TrigramIndexPath == "" | Skip file removal | Line 149: path == "" continue |
| ST43 | DeleteAssetComplete | os.Remove fails, file not exist | No-op (IsNotExist) | Line 152: `os.IsNotExist(err)` true |
| ST44 | DeleteAssetComplete | os.Remove fails, other error | Log warning, continue | Line 152: `!os.IsNotExist(err)`, line 154 |
| ST45 | DeleteAssetComplete | os.Remove succeeds | No-op | Line 152: err == nil |
| ST46 | DeleteAssetComplete | Transaction succeeds, file removal fails for all paths | DB records gone, stale files remain harmless | Line 157: return asset |

### DeleteAssetFlowsAndPackets (line 163-173)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST47 | DeleteAssetFlowsAndPackets | Delete packets fails | Transaction rollback, return error | Line 165: err != nil |
| ST48 | DeleteAssetFlowsAndPackets | Delete flows fails | Transaction rollback, return error | Line 168: err != nil |
| ST49 | DeleteAssetFlowsAndPackets | Both succeed | Return nil | Line 171: return nil |

### CountReplayReferences (line 187-243)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST50 | CountReplayReferences | Strategies query fails | Return 0, err | Line 191: err != nil |
| ST51 | CountReplayReferences | Strategy config is empty | Skip | Line 198-199: `s.Config == ""` |
| ST52 | CountReplayReferences | Strategy config is malformed JSON | Skip (tolerant) | Line 201: err != nil, continue |
| ST53 | CountReplayReferences | Strategy config matches assetID | Count++ | Line 204: `cfg.PcapAssetID == assetID` |
| ST54 | CountReplayReferences | Strategy config doesn't match | Skip | Line 204: condition false |
| ST55 | CountReplayReferences | Tasks query fails | Return 0, err | Line 210: err != nil |
| ST56 | CountReplayReferences | Task batch config is empty | Skip | Line 214-215: `tk.BatchConfig == ""` |
| ST57 | CountReplayReferences | Task batch config is malformed JSON | Skip | Line 223: err != nil, continue |
| ST58 | CountReplayReferences | Class is not "replay" | Skip | Line 227: `c.Type != "replay"` |
| ST59 | CountReplayReferences | Class is "replay" but Replay is empty | Skip | Line 227: `len(c.Replay) == 0` |
| ST60 | CountReplayReferences | Class replay config is malformed JSON | Skip | Line 233: err != nil, continue |
| ST61 | CountReplayReferences | Class replay config matches assetID | Count++, break inner loop | Lines 236-238 |
| ST62 | CountReplayReferences | No references | Return 0, nil | Line 242 |
| ST63 | CountReplayReferences | Multiple references | Return count > 0 | Lines 194-241 |

### CreateFlows (line 249-254)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST64 | CreateFlows | Empty slice | Return nil | Line 250: `len(flows) == 0` |
| ST65 | CreateFlows | Non-empty, CreateInBatches fails | Return error | Line 253: err != nil |
| ST66 | CreateFlows | Non-empty, CreateInBatches succeeds | Return nil | Line 253: err == nil |

### ListFlowsByAsset (line 258-270)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST67 | ListFlowsByAsset | Count fails | Return error | Line 262: err != nil |
| ST68 | ListFlowsByAsset | Find fails | Return error | Line 266: err != nil |
| ST69 | ListFlowsByAsset | Success | Return flows, total, nil | Line 269 |

### GetFlow (line 273-279)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST70 | GetFlow | Flow found, user matches | Return flow | Line 275: err == nil |
| ST71 | GetFlow | Flow not found | Return error | Line 275: err != nil |
| ST72 | GetFlow | Wrong userID | Return error (not found) | Line 275: Where filters |

### CountFlowsByAsset (line 282-285)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST73 | CountFlowsByAsset | Query fails | Return 0, error | Line 284: err != nil |
| ST74 | CountFlowsByAsset | Success | Return count, nil | Line 284 |

### CreatePackets (line 291-296)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST75 | CreatePackets | Empty slice | Return nil | Line 292: `len(packets) == 0` |
| ST76 | CreatePackets | Non-empty, fails | Return error | Line 295: err != nil |
| ST77 | CreatePackets | Non-empty, succeeds | Return nil | Line 295: err == nil |

### ListPacketsByFlow (line 300-312)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST78 | ListPacketsByFlow | Count fails | Return error | Line 304: err != nil |
| ST79 | ListPacketsByFlow | Find fails | Return error | Line 308: err != nil |
| ST80 | ListPacketsByFlow | Success | Return packets, total, nil | Line 311 |

### ListPacketsByAsset (line 316-328)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST81 | ListPacketsByAsset | Count fails | Return error | Line 320: err != nil |
| ST82 | ListPacketsByAsset | Find fails | Return error | Line 324: err != nil |
| ST83 | ListPacketsByAsset | Success | Return packets, total, nil | Line 327 |

### ListAllPacketsByAsset (line 333-339)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST84 | ListAllPacketsByAsset | Query fails | Return error | Line 335: err != nil |
| ST85 | ListAllPacketsByAsset | Success | Return packets, nil | Line 338 |

### GetPacket (line 342-348)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST86 | GetPacket | Packet found, user matches | Return packet | Line 344: err == nil |
| ST87 | GetPacket | Not found | Return error | Line 344: err != nil |

### CountPacketsByAsset (line 351-354)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST88 | CountPacketsByAsset | Query fails | Return 0, error | Line 353: err != nil |
| ST89 | CountPacketsByAsset | Success | Return count, nil | Line 353 |

### SearchFlows (line 371-392)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| ST90 | SearchFlows | Column not in allowlist | Skip (defensive no-op) | Line 376: `!flowFilterColumns[col]` → continue |
| ST91 | SearchFlows | Column in allowlist, value is empty string | Skip | Line 379: type assertion ok, s == "" |
| ST92 | SearchFlows | Column in allowlist, value is non-empty string | Add filter | Lines 379-382 |
| ST93 | SearchFlows | Column in allowlist, value is non-string type | Add filter | Line 379: type assertion fails, falls through to line 382 |
| ST94 | SearchFlows | Empty filters map | No filters added | Line 375: loop 0 iterations |
| ST95 | SearchFlows | Count fails | Return error | Line 384: err != nil |
| ST96 | SearchFlows | Find fails | Return error | Line 388: err != nil |
| ST97 | SearchFlows | Success | Return flows, total, nil | Line 391 |

---

## 9. STORAGE — DB (`db.go`)

### NewDBWithAdmin (line 31-81)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB1 | NewDBWithAdmin | cfg.Type="postgres" | Open postgres connection | Line 40-41 |
| DB2 | NewDBWithAdmin | cfg.Type="sqlite" | Open sqlite connection | Line 42-43 |
| DB3 | NewDBWithAdmin | cfg.Type="" | Return error | Line 44-45 default |
| DB4 | NewDBWithAdmin | cfg.Type="mysql" | Return error | Line 44-45 default |
| DB5 | NewDBWithAdmin | gorm.Open fails | Return error | Line 49-50 |
| DB6 | NewDBWithAdmin | db.DB() fails | Return error | Line 54-55 |
| DB7 | NewDBWithAdmin | AutoMigrate fails | Return error | Line 64-65 |
| DB8 | NewDBWithAdmin | adminCfg == nil | Skip admin init | Line 74: condition false |
| DB9 | NewDBWithAdmin | adminCfg provided, initAdminUser fails | Return error | Line 75-76 |
| DB10 | NewDBWithAdmin | All succeeds | Return database, nil | Line 80 |

### initAdminUser (line 84-133)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB11 | initAdminUser | Count query fails | Return error | Line 87: err != nil |
| DB12 | initAdminUser | Admin exists, password matches | Return nil | Lines 91-92, 99: bcrypt matches, line 110 return nil |
| DB13 | initAdminUser | Admin exists, password doesn't match | Update password | Lines 91-92, 99: bcrypt mismatch, lines 101-108 |
| DB14 | initAdminUser | Admin exists, password update, GenerateFromPassword fails | Return error | Line 101-102 |
| DB15 | initAdminUser | Admin exists, password update, Save fails | Return error | Line 106-107 |
| DB16 | initAdminUser | Admin doesn't exist, create fails | Return error | Lines 128-129 |
| DB17 | initAdminUser | Admin doesn't exist, create succeeds | Return nil | Line 132 |

### Close (line 136-142)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB18 | Close | db.DB() fails | Return error | Line 137-138 |
| DB19 | Close | sqlDB.Close() fails | Return error | Line 140-141 |
| DB20 | Close | Success | Return nil | Line 141 |

### Ping (line 145-151)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB21 | Ping | db.DB() fails | Return error | Line 146-147 |
| DB22 | Ping | PingContext fails | Return error | Line 149-150 |
| DB23 | Ping | Success | Return nil | Line 150 |

### IsConnected (line 154-158)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB24 | IsConnected | Ping succeeds | Return true | Line 157: `== nil` |
| DB25 | IsConnected | Ping fails | Return false | Line 157: `!= nil` |

### GetSettings (line 162-176)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB26 | GetSettings | Row exists | Return settings | Line 164: err == nil, line 175 |
| DB27 | GetSettings | Row not found | Seed default, return seeded | Line 165: `gorm.ErrRecordNotFound`, lines 166-170 |
| DB28 | GetSettings | Row not found, Create fails | Return error | Lines 167-168 |
| DB29 | GetSettings | Other DB error | Return nil, err | Lines 172-173 |

### SaveSettings (line 179-182)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB30 | SaveSettings | Save succeeds | Return nil | Line 181: err == nil |
| DB31 | SaveSettings | Save fails | Return error | Line 181: err != nil |

### CountActiveTasks (line 185-191)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB32 | CountActiveTasks | Query fails | Return 0, error | Line 187: err != nil |
| DB33 | CountActiveTasks | Success | Return count, nil | Line 190 |

### CountTasksByProtocol (line 194-208)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| DB34 | CountTasksByProtocol | Query fails | Return nil, error | Line 200: err != nil |
| DB35 | CountTasksByProtocol | Success | Return protocol → count map | Lines 203-207 |

---

## 10. STORAGE — MODELS + AutoMigrate (`models.go`)

### AutoMigrate (line 314-347)

| Tag | Component | Input | Expected Behavior | Code Branch |
|-----|-----------|-------|-------------------|-------------|
| STM1 | AutoMigrate | AutoMigrate fails | Return error | Line 328: err != nil |
| STM2 | AutoMigrate | Create composite index fails | Return error | Line 335: err != nil |
| STM3 | AutoMigrate | Create unique index fails | Return error | Line 343: err != nil |
| STM4 | AutoMigrate | All succeeds | Return nil | Line 346 |

---

## Cross-Cutting Concern: Context Cancellation Summary

Components that DO check ctx cancellation:

| Path | Mechanism | Location |
|------|-----------|----------|
| Plan goroutine, serial mode packet loop | `ctx.Err() != nil` | planner.go:170 |
| Plan goroutine, stack mode packet loop | `ctx.Err() != nil` | planner.go:181 |
| emitReplayCfg | `select { case <-ctx.Done() }` | planner.go:261 |
| TimestampPacer.Wait (future case) | `select { case <-ctx.Done() }` | pacing.go:81 |
| TokenBucketPacer.Wait | Delegates to `core.TokenBucket.Wait(ctx, ...)` | pacing.go:122 |
| PPSPacer.Wait | `select { case <-ctx.Done() }` | pacing.go:152 |

Components that do NOT check ctx cancellation:

| Missing Path | Risk | Location |
|-------------|------|----------|
| Before os.Open in goroutine | Goroutine doesn't abort if ctx cancelled before file open | planner.go:118 |
| Before checkFlowScalingConflict | Non-blocking, low risk | planner.go:139 |
| Before generateClones | Could be slow with many clones, no cancel check | planner.go:161 |
| Before pcapDuration computation | Non-blocking, low risk | planner.go:133 |
| Before assemblePatches | Non-blocking, low risk | planner.go:192 |
| Stack mode ReadAt | Blocking I/O — no cancel check | planner.go:189 |
| buildFlowContexts | Runs in caller goroutine, not in the Plan goroutine | planner.go:98 |
| All storage DB operations | No ctx passed to DB methods | pcap_repository.go passim |

This covers all 10 files, every function, every if/else/switch/case/for/select branch, every error path, every edge case, every context cancellation path, and all valid and invalid status transitions.