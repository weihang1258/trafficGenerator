Now I have the complete picture. Here is the exhaustive enumeration of every scenario, branch, and edge case in the HTTP planner.

---

## FULL ENUMERATION OF ALL SCENARIOS IN HTTP PLANNER

### FILE: `/home/weihang/trafficGenerator/trafficgen/internal/protocol/http/http.go`

---

## H1-H7: `Planner.Validate(spec core.FlowSpec) error` (lines 32-51)

### H1: Valid spec with both IPs populated
- **Function**: `Validate`
- **Input**: `spec.SrcIP = "192.168.1.1"`, `spec.DstIP = "192.168.1.2"`, `spec.DstPort = 80`
- **Expected output**: `nil`
- **Branch**: Line 34 (`SrcIP != ""` → true) → Line 35 (`net.ParseIP("192.168.1.1") == nil` → false, skip) → Line 39 (`DstIP != ""` → true) → Line 40 (`net.ParseIP("192.168.1.2") == nil` → false, skip) → Line 46 (`DstPort == 0` → false, skip) → Line 50 return nil

### H2: Invalid source IP
- **Function**: `Validate`
- **Input**: `spec.SrcIP = "invalid"`, `spec.DstIP = "192.168.1.2"`
- **Expected output**: `error` "invalid source IP: invalid"
- **Branch**: Line 34 (`SrcIP != ""` → true) → Line 35 (`net.ParseIP("invalid") == nil` → true) → Line 36 return error. **Short-circuits** — DstIP validation never runs.

### H3: Invalid destination IP
- **Function**: `Validate`
- **Input**: `spec.SrcIP = "192.168.1.1"`, `spec.DstIP = "invalid"`
- **Expected output**: `error` "invalid destination IP: invalid"
- **Branch**: Line 34 → Line 35 passes → Line 39 (`DstIP != ""` → true) → Line 40 (`net.ParseIP("invalid") == nil` → true) → Line 41 return error

### H4: Both IPs empty (empty strings, skipped validation)
- **Function**: `Validate`
- **Input**: `spec.SrcIP = ""`, `spec.DstIP = ""`, `spec.DstPort = 80`
- **Expected output**: `nil`
- **Branch**: Line 34 (`SrcIP != ""` → false, skip) → Line 39 (`DstIP != ""` → false, skip) → Line 46 (`DstPort == 0` → false, skip) → return nil.
- **Note**: This flows through to `Plan` which will call `L3Base("", "", ...)` — the builder will receive empty IP strings and likely fail to parse them.

### H5: One IP empty, one IP valid
- **Function**: `Validate`
- **Input**: `spec.SrcIP = ""`, `spec.DstIP = "10.0.0.1"`
- **Expected output**: `nil` (empty string passes validation)
- **Branch**: Line 34 (false, skip) → Line 39 (true) → Line 40 (`net.ParseIP("10.0.0.1") == nil` → false, skip) → return nil
- **Note**: Same downstream issue as H4 — empty SrcIP passed to L3Base.

### H6: Invalid IP with hex/colon separator (ambiguous parse)
- **Function**: `Validate`
- **Input**: `spec.SrcIP = "192.168.1"` (partial IP)
- **Expected output**: `error` "invalid source IP: 192.168.1"
- **Branch**: Line 34 (true) → Line 35 (`net.ParseIP("192.168.1") == nil` → true) → return error.
- **Note**: `net.ParseIP` returns nil for any non-parseable string, including IPv4-mapped-IPv6 literals without brackets, unicode, trailing garbage.

### H7: DstPort defaults to 80 when zero
- **Function**: `Validate`
- **Input**: `spec.SrcIP = "1.1.1.1"`, `spec.DstIP = "2.2.2.2"`, `spec.DstPort = 0`
- **Expected output**: `nil` (with DstPort set to 80 in the local copy)
- **Branch**: Line 46 (`DstPort == 0` → true) → Line 47 (`spec.DstPort = 80`) → return nil
- **Note**: This only modifies the local copy of the struct passed by value, so the caller's DstPort is unchanged. Inside `Plan`, the original `spec.DstPort` is used, so this default has NO EFFECT on the actual generated packets.

---

## H8-H20: `Planner.Plan(ctx, spec)` — Top-level control flow (lines 54-332)

### H8: Validation failure in Plan
- **Function**: `Plan`
- **Input**: `spec` with invalid IP
- **Expected output**: `(nil, error)` — error from Validate propagated
- **Branch**: Line 55 (`err := p.Validate(spec); err != nil` → true) → Line 56 return nil, err
- **Note**: Channel is NOT created on validation failure.

### H9: Validation passes, channel created, goroutine starts
- **Function**: `Plan`
- **Input**: Valid spec
- **Expected output**: `(chan, nil)`
- **Branch**: Line 55 (false, skip) → Line 59 (make channel) → Line 61-329 (launch goroutine) → Line 331 return configChan, nil
- **Note**: Goroutine runs concurrently with the caller. The caller receives the channel before any packets are produced (race-free because the goroutine hasn't sent yet).

### H10: `spec.HTTP` is nil — default to GET /
- **Function**: `Plan` goroutine (line 69)
- **Input**: `spec.HTTP` is nil
- **Expected output**: Internal `httpConfig` becomes `&core.HTTPConfig{Method: "GET", URI: "/"}`
- **Branch**: Line 69 (`httpConfig == nil` → true) → Lines 70-73 allocate default

### H11: `spec.HTTP` is non-nil — use as-is
- **Function**: `Plan` goroutine (line 69)
- **Input**: `spec.HTTP` is a non-nil pointer
- **Expected output**: `httpConfig` points to the caller's HTTPConfig
- **Branch**: Line 69 (false, skip)

### H12: `httpConfig.Transactions <= 0` — default to 1 transaction
- **Function**: `Plan` goroutine (line 77)
- **Input**: `httpConfig.Transactions = 0` or negative
- **Expected output**: `transactions = 1`
- **Branch**: Line 77 (`transactions <= 0` → true) → Line 78 `transactions = 1`

### H13: `httpConfig.Transactions > 0` — use as-is
- **Function**: `Plan` goroutine (line 77)
- **Input**: `httpConfig.Transactions = 5`
- **Expected output**: `transactions = 5`
- **Branch**: Line 77 (false, skip)

### H14: `spec.TTL == 0` — default to 64
- **Function**: `Plan` goroutine (line 83)
- **Input**: `spec.TTL = 0`
- **Expected output**: `effectiveTTL = 64`
- **Branch**: Line 83 (`effectiveTTL == 0` → true) → Line 84 `effectiveTTL = DefaultTTL`

### H15: `spec.TTL != 0` — use spec value
- **Function**: `Plan` goroutine (line 83)
- **Input**: `spec.TTL = 128`
- **Expected output**: `effectiveTTL = 128`
- **Branch**: Line 83 (false, skip)

### H16: `nextIPID()` closure — normal operation
- **Function**: `Plan` goroutine (lines 95-99)
- **Input**: Initial `ipID = 1`
- **Expected output**: Returns 1, 2, 3, ... incrementing each call
- **Branch**: Line 96 (`id := ipID`), Line 97 (`ipID++`), Line 98 (`return id`)

### H17: `nextIPID()` closure — overflow at 65535
- **Function**: `Plan` goroutine (lines 95-99)
- **Input**: After 65535 calls, `ipID` wraps from 65535 to 0
- **Expected output**: Returns 65535, then next call returns 0, then 1, ...
- **Branch**: Same code path, `uint16` overflow is silent in Go
- **Note**: Each flow has exactly 8 + 2*transactions packets. Even with transactions=32764, overflow starts. For a single transaction (9 packets total), IPID overflow is impossible.

### H18: `spec.Flags == 0 && spec.FragOffset == 0` — L3Base sets DF
- **Function**: Called via `L3Base` in every packet (8 times per flow + 2*transactions)
- **Input**: `spec.Flags = 0`, `spec.FragOffset = 0`
- **Expected output**: L3Config.Flags = 0x02 (IPFlagDF)
- **Branch**: `L3Base` line 37 (`flags == 0 && spec.FragOffset == 0` → true) → line 38 `flags = IPFlagDF`

### H19: `spec.Flags != 0` or `spec.FragOffset != 0` — L3Base preserves caller flags
- **Function**: `L3Base`
- **Input**: `spec.Flags = 0x01` (MF)
- **Expected output**: L3Config.Flags = 0x01
- **Branch**: `L3Base` line 37 (false, skip)

### H20: `spec.TOS != 0` — L3Base overrides DSCP/ECN
- **Function**: `L3Base`
- **Input**: `spec.TOS = 0xB8` (example)
- **Expected output**: L3Config.DSCP = 0x2E, L3Config.ECN = 0x00
- **Branch**: `L3Base` line 51 (`spec.TOS != 0` → true) → line 52 `l3.DSCP = spec.TOS >> 2`, line 53 `l3.ECN = spec.TOS & 0x03`
- **Note**: This overrides any value set in `spec.DSCP`/`spec.ECN` directly.

---

## H21-H36: `Plan` — TCP Handshake packets (lines 102-173)

### H21: SYN packet generation
- **Function**: `Plan` goroutine (line 103)
- **Input**: `clientSeq = 1000`, `packetIndex = 0`, `ipID = 1`
- **Expected output**: PacketConfig sent to channel with FlowID, PacketIndex=0, Direction="up", L3.Protocol=6, L4.Protocol="tcp", L4.Flags=0x02, L4.Seq=1000, L4.WindowSize=65535
- **Branch**: Lines 103-122, unconditional. Always runs.

### H22: SYN packet — empty MAC addresses
- **Function**: `Plan` goroutine (line 103)
- **Input**: `spec.SrcMAC = ""`, `spec.DstMAC = ""`
- **Expected output**: L2Config.SrcMAC = "", L2Config.DstMAC = ""
- **Branch**: Lines 109-110, no validation on MACs. Builder will receive empty strings.

### H23: SYN packet — `spec.SrcPort` and `spec.DstPort` after Validate
- **Function**: `Plan` goroutine (line 103)
- **Input**: `spec.DstPort = 0` (default didn't propagate because Validate uses pass-by-value)
- **Expected output**: L4.DstPort = 0
- **Branch**: Line 117. The Validate function's `spec.DstPort = 80` modifies a local copy, so the original spec.DstPort=0 passes through to the actual packet.

### H24: SYN-ACK packet generation
- **Function**: `Plan` goroutine (line 127)
- **Input**: `serverSeq = 2000`, `packetIndex = 1`, `clientSeq = 1001`
- **Expected output**: PacketConfig with Direction="down", L4.Flags=0x12, L4.Seq=2000, L4.Ack=1001, swapped MACs and IPs and ports
- **Branch**: Lines 127-147, unconditional. Always runs.

### H25: Handshake ACK packet generation
- **Function**: `Plan` goroutine (line 152)
- **Input**: `packetIndex = 2`, `clientSeq = 1001`, `serverSeq = 2001`
- **Expected output**: PacketConfig with Direction="up", L4.Flags=0x10, L4.Seq=1001, L4.Ack=2001, original MACs/IPs/ports
- **Branch**: Lines 152-172, unconditional. Always runs.

---

## H27-H31: `Plan` — HTTP Transactions loop (lines 176-230)

### H27: Single transaction (transactions=1)
- **Function**: `Plan` goroutine (line 176)
- **Input**: `transactions = 1`
- **Expected output**: Loop body executes once — 1 HTTP request + 1 HTTP response = 2 packets
- **Branch**: Line 176 (`for i := 0; i < 1; i++` → runs once)

### H28: Multiple transactions (transactions=5)
- **Function**: `Plan` goroutine (line 176)
- **Input**: `transactions = 5`
- **Expected output**: Loop body executes 5 times — 5 request + 5 response = 10 packets, all within the same TCP connection (no new handshake/teardown between transactions)
- **Branch**: Line 176 (`for i := 0; i < 5; i++` → runs 5 times)

### H29: HTTP Request packet inside transaction loop
- **Function**: `Plan` goroutine (lines 178-202)
- **Input**: Current `clientSeq`, `packetIndex`
- **Expected output**: PacketConfig with Direction="up", L4.Flags=0x18 (PSH-ACK), Payload=[]byte(request), clientSeq increased by len(request), packetIndex incremented
- **Branch**: Lines 178-202, unconditional inside loop

### H30: HTTP Response packet inside transaction loop
- **Function**: `Plan` goroutine (lines 205-229)
- **Input**: Current `serverSeq`, `packetIndex`
- **Expected output**: PacketConfig with Direction="down", L4.Flags=0x18 (PSH-ACK), Payload=[]byte(response), serverSeq increased by len(response), packetIndex incremented
- **Branch**: Lines 205-229, unconditional inside loop

### H31: clientSeq overflow during transactions
- **Function**: `Plan` goroutine (line 202)
- **Input**: `clientSeq` approaching 2^32-1, body length causes overflow
- **Expected output**: `clientSeq` wraps around (uint32). TCP allows this, but the planner never resets or handles it.
- **Branch**: Line 202 `clientSeq += uint32(len(request))` — arithmetic overflow is defined in Go for unsigned integers (wraps).

---

## H32-H37: `Plan` — TCP Termination (lines 232-329)

### H32: Client FIN packet
- **Function**: `Plan` goroutine (line 234)
- **Input**: Current `clientSeq`, `serverSeq`, `packetIndex`
- **Expected output**: PacketConfig with Direction="up", L4.Flags=0x11 (FIN-ACK), L4.Seq=clientSeq, L4.Ack=serverSeq
- **Branch**: Lines 234-256, unconditional. Always runs after transaction loop.

### H33: Server ACK of client FIN
- **Function**: `Plan` goroutine (line 259)
- **Input**: `clientSeq+1`, `serverSeq`
- **Expected output**: PacketConfig with Direction="down", L4.Flags=0x10 (ACK), L4.Seq=serverSeq, L4.Ack=clientSeq
- **Branch**: Lines 259-279, unconditional. Always runs.

### H34: Server FIN packet
- **Function**: `Plan` goroutine (line 283)
- **Input**: `serverSeq`
- **Expected output**: PacketConfig with Direction="down", L4.Flags=0x11 (FIN-ACK), L4.Seq=serverSeq, L4.Ack=clientSeq
- **Branch**: Lines 283-305, unconditional. Always runs.

### H35: Client ACK of server FIN
- **Function**: `Plan` goroutine (line 308)
- **Input**: `clientSeq`, `serverSeq+1`
- **Expected output**: PacketConfig with Direction="up", L4.Flags=0x10 (ACK), L4.Seq=clientSeq, L4.Ack=serverSeq
- **Branch**: Lines 308-328, unconditional. Always runs.

### H36: `configChan` close after goroutine exits
- **Function**: `Plan` goroutine
- **Input**: All packets sent
- **Expected output**: `close(configChan)` called via defer
- **Branch**: Line 62 `defer close(configChan)`. Closes when goroutine exits after line 328.

---

## H37-H42: Context cancellation paths (CRITICAL)

### H37: Context cancelled before `Plan` returns
- **Function**: `Plan` (line 55)
- **Input**: `ctx` already cancelled before calling `Plan`
- **Expected output**: `p.Validate` returns nil (no context check), channel is created, goroutine launches, goroutine starts sending packets unconditionally
- **Branch**: Line 55 (Validate passes) → Lines 59-331 (full execution with no ctx.Done() check)
- **Note**: The goroutine has no way to detect that the context is cancelled. It will run to completion.

### H38: Context cancelled during channel consumption
- **Function**: `Plan` goroutine (lines 103, 127, 152, 179, 206, 234, 259, 283, 308)
- **Input**: `ctx` cancelled, caller stops reading from channel
- **Expected output**: **Goroutine leak.** The goroutine blocks on `configChan <-` when the 256-element buffer is full. The goroutine never exits because `configChan <-` is a plain send with no select on `ctx.Done()`.
- **Branch**: All send sites. None have a `select` with `ctx.Done()`.

### H39: Channel full during heavy transaction count
- **Function**: `Plan` goroutine
- **Input**: `transactions = 1000` (2000 transaction packets + 9 handshake/teardown = 2009 packets)
- **Expected output**: First 256 packets fill the buffer, then the goroutine **blocks indefinitely** on the 257th send, waiting for a consumer to read.
- **Branch**: All send sites. Buffer capacity is 256, no backpressure mechanism.

### H40: Context cancelled exactly at buffer-full watermark
- **Function**: `Plan` goroutine (line 179)
- **Input**: 256 packets already sent, buffer full, goroutine blocked on send, context cancelled
- **Expected output**: **Deadlock.** The goroutine is blocked on `configChan <-` with no way to observe the context cancellation. The goroutine leaks.

### H41: `ctx` passed to `Plan` but never used
- **Function**: `Plan` (line 54)
- **Input**: Any context
- **Expected output**: The `ctx` parameter is only used implicitly — it's never queried, never stored, never passed to sub-calls. The `ctx` is effectively dead code.
- **Branch**: The function signature accepts `ctx context.Context` but never references it.

### H42: Caller closes channel before goroutine finishes
- **Function**: `Plan` goroutine (all send sites)
- **Input**: Caller closes the returned channel early
- **Expected output**: **Panic:** `send on closed channel`. The goroutine will panic when it tries to `configChan <-` on a closed channel.
- **Branch**: Not handled — no recover, no guard.

---

## H43-H52: `buildHTTPRequest(config *core.HTTPConfig) string` (lines 335-361)

### H43: Empty method defaults to GET
- **Function**: `buildHTTPRequest`
- **Input**: `config.Method = ""`, `config.URI = "/test"`
- **Expected output**: `"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"`
- **Branch**: Line 336 (`config.Method == ""` → true) → Line 337 `config.Method = "GET"`
- **Note**: **Mutates the caller's config** (pointer receiver).

### H44: Empty URI defaults to /
- **Function**: `buildHTTPRequest`
- **Input**: `config.Method = "POST"`, `config.URI = ""`
- **Expected output**: `"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"`
- **Branch**: Line 339 (`config.URI == ""` → true) → Line 340 `config.URI = "/"`
- **Note**: **Mutates the caller's config** (pointer receiver).

### H45: Custom headers present
- **Function**: `buildHTTPRequest`
- **Input**: `config.Headers = {"Accept": "application/json", "X-Custom": "value"}`
- **Expected output**: Request line includes `Accept: application/json\r\nX-Custom: value\r\n`
- **Branch**: Line 346 (`for key, value := range config.Headers`) — iterates all entries.
- **Note**: Order is non-deterministic for Go maps (Go randomizes map iteration order).

### H46: Headers map is nil
- **Function**: `buildHTTPRequest`
- **Input**: `config.Headers = nil`
- **Expected output**: No custom headers appended. `range nil` is safe in Go.
- **Branch**: Line 346 — range over nil map iterates 0 times.

### H47: Headers map is empty
- **Function**: `buildHTTPRequest`
- **Input**: `config.Headers = map[string]string{}`
- **Expected output**: No custom headers appended.
- **Branch**: Line 346 — range over empty map iterates 0 times.

### H48: Non-empty body adds Content-Length header
- **Function**: `buildHTTPRequest`
- **Input**: `config.Body = "{\"key\":\"value\"}"`
- **Expected output**: `Content-Length: 15\r\n` before the final `\r\n`
- **Branch**: Line 350 (`config.Body != ""` → true) → Line 351 append Content-Length

### H49: Empty body omits Content-Length header
- **Function**: `buildHTTPRequest`
- **Input**: `config.Body = ""`
- **Expected output**: No Content-Length header
- **Branch**: Line 350 (false, skip)

### H50: Non-empty body appended after headers
- **Function**: `buildHTTPRequest`
- **Input**: `config.Body = "payload_data"`
- **Expected output**: Body appended after the blank line separator: `"GET / HTTP/1.1\r\nHost: localhost\r\n\r\npayload_data"`
- **Branch**: Line 356 (`config.Body != ""` → true) → Line 357 append body

### H51: Empty body omitted after headers
- **Function**: `buildHTTPRequest`
- **Input**: `config.Body = ""`
- **Expected output**: Request ends with `\r\n\r\n` (no body)
- **Branch**: Line 356 (false, skip)

### H52: Method with special characters (no validation)
- **Function**: `buildHTTPRequest`
- **Input**: `config.Method = "GET\r\nX-Injected: true"` (CRLF injection)
- **Expected output**: Malformed HTTP request with injected headers
- **Branch**: Line 343 — `fmt.Sprintf` simply interpolates the method into the format string. No sanitization.
- **Note**: This is a security concern — no input validation on Method, URI, or Header keys/values.

---

## H53-H54: `buildHTTPResponse(config *core.HTTPConfig) string` (lines 364-377)

### H53: KeepAlive is true — adds Connection header
- **Function**: `buildHTTPResponse`
- **Input**: `config.KeepAlive = true`
- **Expected output**: Response includes `Connection: keep-alive\r\n` before the final `\r\n`
- **Branch**: Line 371 (`config.KeepAlive` → true) → Line 372 append keep-alive header

### H54: KeepAlive is false — omits Connection header
- **Function**: `buildHTTPResponse`
- **Input**: `config.KeepAlive = false`
- **Expected output**: Response does NOT include Connection header
- **Branch**: Line 371 (false, skip)

---

## H55-H62: Edge cases and boundary conditions

### H55: Transactions = 0 (defaulted to 1)
- **Function**: `Plan` (line 77)
- **Input**: `httpConfig.Transactions = 0`
- **Expected output**: `transactions = 1`, exactly 1 HTTP request-response pair (2 packets + 9 handshake/teardown = 11 total)
- **Branch**: Line 77 (`transactions <= 0` → true) → line 78 `transactions = 1`

### H56: Transactions = negative (defaulted to 1)
- **Function**: `Plan` (line 77)
- **Input**: `httpConfig.Transactions = -5`
- **Expected output**: `transactions = 1` (same as zero)
- **Branch**: Line 77 (`transactions <= 0` → true) → line 78 `transactions = 1`

### H57: `spec.HTTP` is nil but `spec.HTTP.Transactions` would panic
- **Function**: `Plan` (lines 68-74)
- **Input**: `spec.HTTP = nil`
- **Expected output**: Handled gracefully — nil check at line 69 defaults to `&core.HTTPConfig{Method:"GET", URI:"/"}`. The `transactions` field is 0 in the default, so line 77 sets it to 1.
- **Branch**: Line 69 (true) → lines 70-73 (default alloc) → line 77 (transactions <= 0 → true) → line 78 (transactions = 1)

### H58: Zero packets (impossible — always 9 + 2*transactions >= 11)
- **Function**: `Plan`
- **Input**: Any valid spec
- **Expected output**: Minimum 11 packets: 3 handshake + 2 transaction + 4 termination = 9 + 2*1 = 11
- **Branch**: Unconditional sends. No codepath produces fewer than 11 packets.

### H59: Enormous body causing seq number overflow
- **Function**: `Plan` (lines 202, 229)
- **Input**: `config.Body = strings.Repeat("A", 4*1024*1024*1024)` (4GB body, triggers uint32 overflow on clientSeq addition)
- **Expected output**: `clientSeq += uint32(len(request))` wraps around silently. TCP sequence numbers are 32-bit, so this is technically valid but unexpected.
- **Branch**: Line 202/229 — no overflow check.

### H60: `spec.FlowID` reused across calls
- **Function**: `Plan` (line 65)
- **Input**: Two calls with same `(SrcIP, DstIP, SrcPort, DstPort)`
- **Expected output**: Same flowID string: `"1.1.1.1-2.2.2.2-12345-80"`
- **Branch**: Line 65 — `fmt.Sprintf` with unchanged tuple. The resequencer will see interleaved packets from two separate `Plan` calls with the same flowID, potentially causing packet index confusion.

### H61: `spec.VLAN` is set
- **Function**: `Plan` (all L2Config sites)
- **Input**: `spec.VLAN = &core.VLAN{ID: 100, Priority: 3}`
- **Expected output**: L2Config.VLAN is empty (nil) — the spec's VLAN field is **never propagated** to any L2Config in the HTTP planner.
- **Branch**: All L2Config struct literals omit the VLAN field, leaving it as the zero value (nil).

### H62: All packets use the same `Timestamp` (line 87)
- **Function**: `Plan` (line 87)
- **Input**: `now := time.Now()` captured once at goroutine start
- **Expected output**: All packets in the flow have the exact same timestamp, even if the goroutine runs for seconds (many transactions). No per-packet timing.
- **Branch**: Line 87 — single capture, reused across all 11+ packets.

---

## SUMMARY: ALL BRANCHES BY TYPE

| Category | Count |
|---|---|
| `if/else` branches in `Validate` | 5 |
| `if/else` branches in `Plan` | 6 |
| `for` loop iterations in `Plan` | 1 (transactions loop) |
| `for` range loop in `buildHTTPRequest` | 1 (headers) |
| `if/else` branches in `buildHTTPRequest` | 4 |
| `if/else` branches in `buildHTTPResponse` | 1 |
| Sub-branches in `L3Base` (called 8+ times) | 2 |
| Unconditional send sites | 9 (SYN, SYN-ACK, ACK, REQ, RESP, FIN, ACK, FIN, ACK per loop iteration) |
| **Total logical branches** | **29** |
| **Context cancellation paths** | **6** (all MISSING — no ctx.Done() check anywhere) |
| **Goroutine leak scenarios** | **3** (H38, H39, H40) |
| **Panic scenarios** | **1** (H42 — send on closed channel) |

## KEY FINDINGS

1. **Context cancellation is completely ignored.** The `ctx` parameter is accepted but never checked. The goroutine cannot be cancelled, leading to guaranteed goroutine leaks if the caller cancels or times out.

2. **`DstPort` default in Validate is ineffective.** The `spec` is passed by value, so `spec.DstPort = 80` on line 47 modifies the local copy. The caller's `spec.DstPort = 0` reaches `Plan` unchanged.

3. **VLAN is never propagated.** The `spec.VLAN` field is ignored by all L2Config struct literals.

4. **No backpressure mechanism.** The 256-element buffered channel fills up with large transactions, then the goroutine blocks indefinitely with no escape via ctx cancellation.

5. **Mutating side effects in `buildHTTPRequest`.** The function modifies `config.Method` and `config.URI` on the caller's pointer, which is a shared `*HTTPConfig`. If called multiple times (multiple transactions), the mutation only happens on the first call (already populated on subsequent calls).

6. **All packets share the same timestamp.** `time.Now()` is called once; all packets get the same timestamp regardless of how long generation takes.