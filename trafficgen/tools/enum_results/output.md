Now I have all three files. Let me enumerate every scenario comprehensively.

---

## PCAPWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/pcap.go`)

### NewPCAPWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P1 | NewPCAPWriter | Valid path, file creation succeeds, header write succeeds | Returns `(*PCAPWriter, nil)` | `os.Create(path)` succeeds (L39), `writeGlobalHeader()` returns nil (L51) |
| P2 | NewPCAPWriter | Invalid path (bad directory, permissions) | Returns `(nil, error)` wrapping os.Create error | `os.Create(path)` fails, L40-41 |
| P3 | NewPCAPWriter | Path valid, file created, but header write fails (disk full, etc.) | File closed, returns `(nil, error)` | L51: `writeGlobalHeader()` fails, L52: `file.Close()` called, L53: return nil, err |

### writeGlobalHeader

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P4 | writeGlobalHeader | Buffer write succeeds | Returns `nil` | L82: `w.bw.Write(header)` returns nil |
| P5 | writeGlobalHeader | Buffer write fails | Returns `error` | L82: `w.bw.Write(header)` returns err |

### Write (packets [][]byte)

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P6 | Write | Non-nil packets, writer not closed, all writes succeed | Returns `nil`; `w.written` incremented by `len(packet)+16` per packet | L95: `w.file == nil` false; loop at L100; L109+L112 writes succeed; L115 increments |
| P7 | Write | Any packets, writer already closed (`w.file == nil`) | Returns `error("pcap writer closed: ...")` | L95-96: early return |
| P8 | Write | Packets, writer open, buf header write fails on packet N | Returns error from `bw.Write(buf[:])` on packet N; packets 0..N-1 header+body written to buffer but not flushed; written counter incremented for N-1 only | L109: `w.bw.Write(buf[:])` returns err |
| P9 | Write | Packets, writer open, header write succeeds, body write fails on packet N | Returns error from `bw.Write(packet)` on packet N; header bytes already enqueued in buffer but not flushed; written counter not incremented for packet N | L112: `w.bw.Write(packet)` returns err |
| P10 | Write | Empty slice `[][]byte{}` or nil | Returns `nil`; no bytes written | Loop at L100 iterates zero times |

### WriteTimed (packets []TimedPacket)

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P11 | WriteTimed | All packets have non-zero `Timestamp` | Returns `nil`; all packets written with their scheduled timestamps | L144: `ts.IsZero()` false for all |
| P12 | WriteTimed | Some packets have zero `Timestamp` | Returns `nil`; zero-TS packets get `time.Now()` fallback | L144: `ts.IsZero()` true → L145: `ts = time.Now()` |
| P13 | WriteTimed | Any packets, writer closed (`w.file == nil`) | Returns `error("pcap writer closed: ...")` | L137-138: early return |
| P14 | WriteTimed | Packets, buf header write fails on packet N | Returns error from `bw.Write(buf[:])` | L153: `w.bw.Write(buf[:])` returns err |
| P15 | WriteTimed | Packets, header write succeeds, body write fails on packet N | Returns error from `bw.Write(tp.Data)` | L156: `w.bw.Write(tp.Data)` returns err |
| P16 | WriteTimed | Empty slice `[]TimedPacket{}` or nil | Returns `nil`; no bytes written | Loop at L142 iterates zero times |

### Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P17 | Close | File open, flush/sync/close all succeed | Returns `nil`; `w.file` set to nil | L170: `w.file != nil`; L173: `w.bw != nil`; L174: Flush nil; L178: Sync nil; L181: Close nil; L184: `w.file = nil` |
| P18 | Close | Flush fails, Sync and Close succeed | Returns flush error; `w.file` set to nil | L174: Flush returns flushErr, `err = flushErr`; L178+L181 succeed; L184: `w.file = nil` |
| P19 | Close | Flush succeeds, Sync fails, Close succeeds | Returns sync error | L174: Flush nil; L178: Sync returns syncErr, `err == nil` → `err = syncErr`; L181: Close nil; L184: `w.file = nil` |
| P20 | Close | Flush succeeds, Sync succeeds, Close fails | Returns close error | L174: nil; L178: nil; L181: Close returns closeErr, `err == nil` → `err = closeErr`; L184: `w.file = nil` |
| P21 | Close | Flush fails, Sync fails, Close fails | Returns flush error (first error only); subsequent errors dropped | L174: flushErr, `err = flushErr`; L178: Sync returns syncErr, `err != nil` → skip; L181: Close returns closeErr, `err != nil` → skip; L184: `w.file = nil` |
| P22 | Close | Already closed file (`w.file == nil`), second call | Returns `nil` (idempotent) | L170: `w.file == nil` → skip block, L187: return nil |
| P23 | Close | `w.bw` is nil (impossible via constructor, but guarded) | Skips Flush, proceeds to Sync+Close | L173: `w.bw != nil` false → skip to L178 |

### Path / Written

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| P24 | Path | Any PCAPWriter | Returns `w.path` | No branch, L191-193 |
| P25 | Written | Any PCAPWriter | Returns `w.written` | No branch, L196-198 |

---

## RotatingPCAPWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/pcap.go`)

### NewRotatingPCAPWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| R1 | NewRotatingPCAPWriter | Valid basePath, maxSize, maxFiles; initial rotate succeeds | Returns `(*RotatingPCAPWriter, nil)` | L219: `rotate()` succeeds |
| R2 | NewRotatingPCAPWriter | Initial rotate fails (cannot create file) | Returns `(nil, error)` | L219-220: `rotate()` returns err |

### RotatingPCAPWriter.Write

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| R3 | Write | `w.current != nil`, `w.currentSize + totalSize <= w.maxSize`, inner write succeeds | Returns `nil`; `currentSize` incremented | L242: both conditions false; L248: write succeeds; L252: size incremented |
| R4 | Write | Size threshold exceeded, rotate succeeds, inner write succeeds | Returns `nil`; new file created, `currentSize` reset then incremented | L242: `w.currentSize+totalSize > w.maxSize` true; L243: rotate succeeds; L248: write succeeds; L252: size incremented |
| R5 | Write | `w.current == nil` (prior rotation failure left it nil), rotate succeeds, inner write succeeds | Self-recovering: retries rotation, writes to new file | L242: `w.current == nil` true; L243: rotate creates new file; L248: write succeeds |
| R6 | Write | Rotation needed (nil or size exceeded), rotate fails | Returns error from rotate; `w.current` stays nil; `currentSize` unchanged | L242: trigger true; L243: rotate returns err; L244: return err |
| R7 | Write | `w.current != nil`, size OK, inner `w.current.Write()` fails | Returns error from inner writer; `currentSize` NOT incremented | L242: no rotation; L248: Write returns err; L249: return err; L252 skipped |
| R8 | Write | Empty packet slice, `w.current != nil`, size OK | Returns `nil`; `totalSize = 0`; `currentSize += 0` | L232-235: totalSize = 0; L242: no trigger; L248: empty write to inner returns nil; L252: size unchanged |

### RotatingPCAPWriter.Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| R9 | Close | `w.current != nil`, inner close succeeds | Returns `nil` | L261-262: `w.current.Close()` succeeds |
| R10 | Close | `w.current == nil` | Returns `nil` (no-op) | L261: skip to L264 |
| R11 | Close | `w.current != nil`, inner close fails | Returns error from `w.current.Close()` | L261-262: Close returns err |

### rotate

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| R12 | rotate | Previous file exists, close succeeds, new file creation succeeds, maxFiles enforce | Returns `nil`; new file is current; old file closed | L274: `w.current != nil`; L275: Close nil; L286-287: w.current=nil, size=0; L301: NewPCAPWriter succeeds; L309-310: set current; L315: maxFiles>0 → enforce |
| R13 | rotate | Previous file close fails (logged), new file creation succeeds | Returns `nil`; close error logged as warning, not propagated | L275: Close returns err; L276-279: warn log; L286-287: reset; L301: NewPCAPWriter succeeds |
| R14 | rotate | Previous file close fails, new file creation fails | Returns error from NewPCAPWriter; `w.current` remains nil; `currentSize` remains 0 | L275: Close error logged; L286-287: reset; L301: NewPCAPWriter fails; L302-306: return err |
| R15 | rotate | First call (no previous file), new file creation succeeds | Returns `nil` | L274: `w.current == nil` → skip; L286-287: already nil/0; L301: succeeds |
| R16 | rotate | First call, new file creation fails | Returns error; `w.current` stays nil | L274: skip; L301: NewPCAPWriter fails; L302-306: return err |
| R17 | rotate | `maxFiles > 0`, enforceMaxFiles deletes excess files | Returns `nil`; old files cleaned up | L315: `w.maxFiles > 0` true; L316: enforceMaxFiles runs |
| R18 | rotate | `maxFiles == 0` (disabled) | Returns `nil`; no cleanup | L315: `w.maxFiles > 0` false → skip |

### enforceMaxFiles

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| R19 | enforceMaxFiles | Glob matches, `len(matches) <= maxFiles` | No-op, returns | L327: `len(matches) <= w.maxFiles` true → L328: return |
| R20 | enforceMaxFiles | Glob error (bad pattern) | No-op, returns | L327: `err != nil` → short-circuit → return |
| R21 | enforceMaxFiles | Glob matches > maxFiles, all `os.Remove` succeed | Excess files deleted, no warnings | L327: false; L331: sort; L333: loop; L334: all rmErr == nil |
| R22 | enforceMaxFiles | Glob matches > maxFiles, some `os.Remove` fail | Deletes continue; warnings logged for each failure | L334: `rmErr != nil` → L335-338: warn log; loop continues to next file |

---

## InterfaceWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/interface.go`)

### NewInterfaceWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| I1 | NewInterfaceWriter | Valid interface name, `pcap.OpenLive` succeeds | Returns `(*InterfaceWriter, nil)` | L26-31: OpenLive succeeds |
| I2 | NewInterfaceWriter | Invalid interface, permissions, or other pcap error | Returns `(nil, error)` | L32: OpenLive fails → L33: return error |

### InterfaceWriter.Write

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| I3 | Write | Non-nil packets, handle open, all writes succeed | Returns `nil`; `w.sent` incremented per packet | L50: `w.handle == nil` false; L56: all WritePacketData succeed; L67: `w.sent++` each |
| I4 | Write | Any packets, handle nil (closed) | Returns `error("interface writer closed: ...")` | L50-51: early return |
| I5 | Write | Some packets succeed, some fail | Returns `firstErr` (first failure); `w.sent` incremented for successes; `w.errors` incremented per failure | L56: error path → L57: `w.errors++`, L62-63: `firstErr` set on first failure, L65: `continue`; L67: successes only |
| I6 | Write | All packets fail | Returns `firstErr`; `w.sent` unchanged; `w.errors` incremented per packet | Every iteration enters L56 error path; `w.sent` never incremented |
| I7 | Write | Empty slice or nil | Returns `nil` | Loop at L55 doesn't iterate |

### InterfaceWriter.Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| I8 | Close | Handle open | Returns `nil`; handle closed and set to nil | L78: `w.handle != nil` → L79: Close, L80: `w.handle = nil` |
| I9 | Close | Handle already nil (already closed) | Returns `nil` (idempotent) | L78: `w.handle == nil` → skip |
| I10 | Close | Double close | Returns `nil`; second call no-op | L78: handle nil from first close → skip |

### InterfaceWriter.Stats

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| I11 | Stats | `duration > 0` (non-trivial elapsed time since creation) | Returns map with computed PPS = `float64(w.sent) / duration` | L92: `duration > 0` true → L93: pps computed |
| I12 | Stats | `duration <= 0` (called immediately after creation, ~0 elapsed) | Returns map with PPS = 0 (not computed) | L92: `duration > 0` false → pps stays 0.0 |

### InjectPacket

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| I13 | InjectPacket | Valid gopacket.Packet | Delegates to `Write([][]byte{packet.Data()})` | L248: wraps packet.Data() in single-element slice, calls Write |

---

## BatchInterfaceWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/interface.go`)

### NewBatchInterfaceWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| B1 | NewBatchInterfaceWriter | Valid iface, batchSize, flushInterval; NewInterfaceWriter succeeds | Returns `(*BatchInterfaceWriter, nil)`; timer armed; flushLoop goroutine started | L119: NewInterfaceWriter succeeds; L134: timer created; L145: `go bw.flushLoop()` |
| B2 | NewBatchInterfaceWriter | NewInterfaceWriter fails (bad interface, permissions) | Returns `(nil, error)` | L119-120: NewInterfaceWriter fails |

### BatchInterfaceWriter.Write

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| B3 | Write | Packets appended, cumulative batch < batchSize | Returns `nil`; batch grows; no flush | L156: append; L158: `len(w.batch) >= w.batchSize` false throughout |
| B4 | Write | Packets appended, batch exactly reaches batchSize | Returns `nil`; flushLocked called, batch cleared | L158: true; L159: `flushLocked()` succeeds |
| B5 | Write | Packets appended, batch overfills (multiple flush cycles, e.g. 2*batchSize+1 packets) | Returns `nil`; multiple flushes; all packets processed | L158: true multiple times; each flush clears batch; loop continues with remaining packets |
| B6 | Write | Batch fills, flushLocked returns error | Returns error from flushLocked; remaining packets in this Write call NOT processed | L159: `flushLocked()` returns err → L160: return err immediately |

### flushLoop (goroutine)

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| B7 | flushLoop | `done` channel closed via Close() | Goroutine exits via `<-w.done` | L177: `<-w.done` → L178: return |
| B8 | flushLoop | `flushChan` receives signal from timer, flush succeeds | Batch flushed; timer reset; loop continues | L179: `<-w.flushChan`; L180-181: flushLocked succeeds; L193: timer.Reset |
| B9 | flushLoop | `flushChan` receives signal, flush returns error | Error logged via `zap.L().Warn`; timer reset; loop continues | L181: flushLocked returns err; L182-186: warn log; L193: timer.Reset |
| B10 | flushLoop | Timer callback fires after `done` is closed (race) | Callback returns without sending to flushChan | L138-142: select `<-bw.done` → return; no send to flushChan |
| B11 | flushLoop | Timer callback fires, flushChan buffer already full (default case) | Tick dropped; no send to flushChan | L138-142: `default` case taken |
| B12 | flushLoop | Timer callback fires after flushLoop has already exited, timer.Reset arms one more tick | Callback selects `<-bw.done`, returns; no second re-arm | L138-139: `<-bw.done` → return; loop already exited |

### flushLocked

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| B13 | flushLocked | Empty batch (`len(w.batch) == 0`) | Returns `nil` (no-op) | L201: early return |
| B14 | flushLocked | Non-empty batch, handle nil (write-after-close) | Batch cleared via `w.batch = w.batch[:0]`; returns error | L204: `w.handle == nil` → L205: clear batch, L206: return error |
| B15 | flushLocked | Non-empty batch, handle open, all writes succeed | Returns `nil`; `w.sent` incremented per packet; batch cleared | L210: all WritePacketData succeed; L218: `w.sent++` each; L221: batch cleared |
| B16 | flushLocked | Non-empty batch, some writes succeed, some fail | Returns `firstErr`; `w.sent` for successes, `w.errors` for failures; batch cleared | L211: error path → L212: `w.errors++`, L213-214: firstErr; L216: continue; L218: successes only; L221: batch cleared |
| B17 | flushLocked | Non-empty batch, all writes fail | Returns `firstErr`; `w.sent` unchanged; `w.errors += len(batch)`; batch cleared | Every iteration enters L211 error path; L221: batch cleared |

### Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| B18 | Close | Active writer, flushLocked succeeds, InterfaceWriter.Close succeeds | Returns `nil` | L230: once.Do closes done; L232: timer.Stop; L236: flushLocked nil; L239: InterfaceWriter.Close nil |
| B19 | Close | FlushLocked returns error, InterfaceWriter.Close also returns error | Returns flushErr (prioritized; closeErr dropped) | L236: flushLocked returns err; L240: `flushErr != nil` → L241: return flushErr (closeErr never checked) |
| B20 | Close | FlushLocked succeeds, InterfaceWriter.Close fails | Returns closeErr | L236: flushLocked nil; L240: `flushErr == nil` → L243: return closeErr |
| B21 | Close | Double close (second call) | once.Do no-op second time; timer.Stop on already-stopped timer (safe); flushLocked on empty batch returns nil; InterfaceWriter.Close on nil handle returns nil | L230: once.Do skipped; L232: timer.Stop (safe); L236: empty batch flushLocked nil; L239: InterfaceWriter.Close nil handle → nil |
| B22 | Close | Timer fires concurrently with timer.Stop | timer.Stop returns false (safe, no panic) | Comment at L189-192 documents mutex-protected internal safety |

---

## MultiWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/output.go`)

### NewMultiWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| M1 | NewMultiWriter | One or more Writers | Returns `(*MultiWriter, ...)` | L28-31: stores all writers |
| M2 | NewMultiWriter | No writers (empty call) | Returns `(*MultiWriter, [])` | Same code, empty slice |

### MultiWriter.Write

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| M3 | Write | All writers return nil | Returns `nil` | L41: no errors → lastErr stays nil |
| M4 | Write | Some writers fail, some succeed | Returns lastErr (last error, not first; earlier errors overwritten); each error logged | L41: err != nil → L42: `lastErr = err`, L43: error logged; L44: continue to next writer |
| M5 | Write | All writers fail | Returns lastErr (from last writer); all errors logged | Each iteration sets lastErr; last writer's error returned |
| M6 | Write | Empty writers list | Returns `nil` | Loop at L40 doesn't iterate |

### MultiWriter.Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| M7 | Close | All writers return nil on Close | Returns `nil` | L56: no errors → lastErr stays nil |
| M8 | Close | Some writers return error | Returns lastErr (last error); continues to all writers | L56: err != nil → `lastErr = err` |
| M9 | Close | All writers return error | Returns lastErr (last writer's error) | Same as M8, accumulates |
| M10 | Close | Empty writers list | Returns `nil` | Loop at L55 doesn't iterate |

### AddWriter

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| M11 | AddWriter | Any Writer | Appends to writers slice | L65-67: lock, append, unlock |

---

## Manager (`/home/weihang/trafficGenerator/trafficgen/internal/output/output.go`)

### NewManager / Register / Get / List

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| G1 | NewManager | None | Returns `(*Manager, empty map)` | L78: make(map) |
| G2 | Register | New name, new Writer | Writer stored in map | L85-87: m.writers[name] = writer |
| G3 | Register | Name already exists | Silently overwrites previous writer | Same as G2, map assignment replaces |
| G4 | Get | Name that exists | Returns `(Writer, true)` | L94: `ok == true` |
| G5 | Get | Name that does not exist | Returns `(nil, false)` | L94: `ok == false` |
| G17 | List | Map with names | Returns `[]string` of all names | L148-156: iterate map, collect keys |
| G18 | List | Empty map | Returns `[]string{}` | L152: empty iteration → empty slice |

### Manager.Write

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| G6 | Write | Name exists, Write succeeds | Returns `nil` | L104: ok true; L107: Write returns nil |
| G7 | Write | Name exists, Write fails | Returns error from writer.Write | L104: ok true; L107: Write returns err |
| G8 | Write | Name does not exist | Returns `error("writer not found: ...")` | L104: `!ok` → L105: return error |

### Manager.WriteAll

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| G9 | WriteAll | All writers return nil | Returns `nil` | L117: all succeed → lastErr stays nil |
| G10 | WriteAll | Some writers fail | Returns lastErr (last error); all errors logged with writer name | L117: err != nil → L118: `lastErr = err`, L119-122: error logged; continues to next writer |
| G11 | WriteAll | All writers fail | Returns lastErr (last writer's error) | Each iteration sets lastErr |
| G12 | WriteAll | Empty writer map | Returns `nil` | Loop at L116 doesn't iterate |

### Manager.Close

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| G13 | Close | All writers close successfully | Returns `nil`; all writers deleted from map | L135: Close succeeds; L142: delete(m.writers, name) |
| G14 | Close | Some writers close with error | Returns lastErr (last error); each error logged with writer name; each writer deleted from map regardless | L135: Close returns err → L136-140: error logged, `lastErr = err`; L142: deleted anyway |
| G15 | Close | All writers close with error | Returns lastErr (last writer's error); all deleted from map | Same as G14 for all iterations |
| G16 | Close | Empty writer map | Returns `nil` | Loop at L134 doesn't iterate |

---

## OutputWorker (`/home/weihang/trafficGenerator/trafficgen/internal/output/output.go`)

### NewOutputWorker / Start / Stop / GetStats

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| O1 | NewOutputWorker | id, packetChan, writer, wg | Returns `(*OutputWorker, ...)` | L179: context.WithCancel creates ctx+cancel |
| O2 | Start | Any OutputWorker | Launches goroutine running `w.run()`; returns immediately | L192: `go w.run()` |
| O3 | Stop | Any OutputWorker | Cancels context; no direct wait for goroutine exit | L197: `w.cancel()` |
| O10 | GetStats | Any OutputWorker | Returns `w.stats` (raw struct copy; no synchronization) | L228: return w.stats — **potential data race** if read concurrently with run() |

### run (goroutine)

| Tag | Function | Input | Expected Behavior | Code Branch |
|---|---|---|---|---|
| O4 | run | Context cancelled (Stop called) | `defer w.wg.Done()` called; goroutine exits | L206: `<-w.ctx.Done()` → L207: return |
| O5 | run | packetChan closed by producer | `defer w.wg.Done()` called; goroutine exits | L208-209: `ok == false` → L210: return |
| O6 | run | Packet received, writer.Write succeeds | Stats updated: PacketsWritten += len(packets), BytesWritten += sum(len(p)); loop continues | L213: Write returns nil; L218-221: iterate packets, accumulate stats |
| O7 | run | Packet received, writer.Write fails | Stats: w.stats.Errors++ ; PacketsWritten/BytesWritten NOT updated; loop continues | L213: Write returns err → L214: `w.stats.Errors++`, L215: `continue` |
| O8 | run | Both ctx cancelled AND packet available simultaneously | Either path is equally likely (Go select random); if ctx: exit; if packet: process, then next iteration sees closed ctx | L205-208: select picks randomly between ready cases |
| O9 | run | Any exit path | `defer w.wg.Done()` always executes | L202: deferred call runs regardless of how the function returns |

---

## Cross-cutting / Concurrency Observations

Not full scenarios, but notable design properties:

1. **OutputWorker.GetStats data race**: `w.stats` is a plain struct field read via `GetStats()` without a mutex or atomic, while `run()` writes to it (L214, L219-221) in a different goroutine. This is a race condition if `GetStats()` is called from any goroutine other than `run()`.

2. **PCAPWriter.Write / Close lock ordering**: Both use `w.mu` with no nested lock acquisition; safe.

3. **RotatingPCAPWriter.Write / Close lock ordering**: Both use `w.mu`; `rotate()` is called while holding `w.mu` (via Write) but its own `rotate()` does not attempt to acquire `w.mu` again; no deadlock.

4. **BatchInterfaceWriter.done channel**: Never closed by flushLoop, only by `Close()`. `flushLoop` selects on `done` and `flushChan`; `Close` closes `done` and calls `timer.Stop()`. The timer callback also selects on `done` before sending to `flushChan`. This prevents send-on-closed-channel panic.

5. **BatchInterfaceWriter.once.Do**: Guards `close(w.done)` against double-close panic. All other work in `Close()` (timer.Stop, flushLocked, InterfaceWriter.Close) is safe to call multiple times.

6. **Manager.Close deletes while iterating**: Uses `delete(m.writers, name)` inside the range loop. This is safe in Go (the delete does not affect the iteration order), but the map is modified during iteration.