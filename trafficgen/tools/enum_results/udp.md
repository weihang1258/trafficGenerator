Now I have the complete picture. Here is the exhaustive scenario enumeration for the UDP planner.

---

## Comprehensive UDP Planner Scenario Enumeration

### Constants
- `DefaultTTL = 64` (used when `spec.TTL == 0`)

---

### Function: `NewPlanner()` / `Name()`

These are trivial -- no branches, no state. Not enumerated further.

---

### Function: `Validate(spec core.FlowSpec) error`

File line 31-49. Evaluates conditions sequentially; returns on first error.

**Input fields used:** `SrcIP`, `DstIP`, `SrcPort`, `DstPort`

| Tag | Branch Location | Input | Expected Output | Explanation |
|-----|----------------|-------|-----------------|-------------|
| U1  | Line 33 (`net.ParseIP` on SrcIP) | `SrcIP="192.168.1.1"`, other fields valid | `nil` (pass) | Non-empty SrcIP, valid IP |
| U2  | Line 32 (`if SrcIP != ""`), then 33 | `SrcIP="not-an-ip"` | `fmt.Errorf("invalid source IP: not-an-ip")` | Non-empty SrcIP fails `net.ParseIP` |
| U3  | Line 32 (`if SrcIP != ""`) | `SrcIP=""` (empty), `SrcPort=12345`, `DstPort=53` | Falls through to DstIP check | Empty SrcIP skips the entire SrcIP block |
| U4  | Line 37+38 (`if DstIP != ""` + `net.ParseIP`) | `DstIP="10.0.0.1"`, other fields valid | `nil` (pass) | Non-empty DstIP, valid IP |
| U5  | Line 37+38 | `DstIP="bad-address"` | `fmt.Errorf("invalid destination IP: bad-address")` | Non-empty DstIP fails `net.ParseIP` |
| U6  | Line 37 (`if DstIP != ""`) | `DstIP=""` (empty) | Falls through to SrcPort check | Empty DstIP skips the entire DstIP block |
| U7  | Line 42 (`if spec.SrcPort == 0`) | `SrcPort=0, DstPort=53` | `fmt.Errorf("source port is required")` | Zero SrcPort is caught **before** DstPort check |
| U8  | Line 42 | `SrcPort=12345, DstPort=0` | Falls through to DstPort check | Non-zero SrcPort passes |
| U9  | Line 45 (`if spec.DstPort == 0`) | `SrcPort=12345, DstPort=0` | `fmt.Errorf("destination port is required")` | Zero DstPort caught |
| U10 | Line 45 | `SrcPort=12345, DstPort=53` | Falls through to `return nil` | Both ports non-zero |
| U11 | Line 32+33 (SrcIP block), then 37+38 (DstIP block) | `SrcIP="bad1", DstIP="good"` | `fmt.Errorf("invalid source IP: bad1")` | SrcIP checked first -- returns on SrcIP error before reaching DstIP |
| U12 | Lines 32+33, then 37+38 | `SrcIP="", DstIP="bad2"` | `fmt.Errorf("invalid destination IP: bad2")` | Empty SrcIP skipped; DstIP fails |
| U13 | Line 42 | `SrcIP="1.2.3.4", DstIP="5.6.7.8", SrcPort=0, DstPort=0` | `fmt.Errorf("source port is required")` | Both ports zero; SrcPort error returned first |
| U14 | Line 45 | `SrcIP valid, DstIP valid, SrcPort=12345, DstPort=0` | `fmt.Errorf("destination port is required")` | Only DstPort is zero |
| U15 | Line 48 (`return nil`) | All of: SrcIP empty-or-valid, DstIP empty-or-valid, SrcPort>0, DstPort>0 | `nil` | The one and only success return |

**Validation path matrix** (the 4 input fields each have a "pass" or "fail" path, but note SrcIP/DstIP have an additional "empty/skip" path):

| SrcIP | DstIP | SrcPort | DstPort | Behavior | Maps to |
|-------|-------|---------|---------|----------|---------|
| valid | valid | >0 | >0 | pass | U1+U4+U8+U10 |
| valid | valid | >0 | 0 | "destination port is required" | U14 |
| valid | valid | 0 | >0 | "source port is required" | U13 |
| valid | valid | 0 | 0 | "source port is required" | U13 |
| valid | empty | >0 | >0 | pass (DstIP block skipped) | U1+U6+U8+U10 |
| valid | empty | >0 | 0 | "destination port is required" | U14 |
| valid | empty | 0 | 0 | "source port is required" | U13 |
| valid | invalid | any | any | "invalid destination IP" | U5 |
| empty | valid | >0 | >0 | pass (SrcIP skipped) | U3+U4+U8+U10 |
| empty | empty | >0 | >0 | pass (both IP checks skipped) | U3+U6+U8+U10 |
| empty | invalid | any | any | "invalid destination IP" | U12 |
| invalid | any | any | any | "invalid source IP" | U2 (early return) |

---

### Function: `Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error)`

File line 52-122.

#### Pre-goroutine validation check

| Tag | Branch Location | Input | Expected Output | Explanation |
|-----|----------------|-------|-----------------|-------------|
| U16 | Line 53 (`if err := p.Validate(spec); err != nil`) | Any spec that fails Validate (U2, U5, U7, U9, U11, U12, U13, U14) | `return nil, err` | Validation error; no goroutine launched, both return values are non-nil (nil channel + non-nil error) |
| U17 | Line 53 | Any spec that passes Validate (U1, U3, U6, U10, U15) | `return configChan, nil` | Validation passes; goroutine is launched, buffered channel (cap 256) returned |

#### Goroutine: TTL logic

| Tag | Branch Location | Input | Effective TTL | Explanation |
|-----|----------------|-------|---------------|-------------|
| U18 | Line 64 (`if effectiveTTL == 0`) | `spec.TTL = 0` (zero/unspecified) | `64` (DefaultTTL) | TTL defaults to 64 |
| U19 | Line 64 | `spec.TTL = 1` | `1` | Minimum valid TTL passes through |
| U20 | Line 64 | `spec.TTL = 64` | `64` | Explicit 64 passes through (same as default) |
| U21 | Line 64 | `spec.TTL = 255` | `255` | Maximum valid uint8 passes through |

#### Goroutine: Response packet emission

| Tag | Branch Location | Input | Packets Emitted | Explanation |
|-----|----------------|-------|-----------------|-------------|
| U22 | Line 99 (`if spec.UDP != nil && spec.UDP.Response`) | `spec.UDP == nil` | 1 (request only) | nil pointer -- short-circuit `&&`, second operand not evaluated, block skipped |
| U23 | Line 99 | `spec.UDP = &UDPConfig{Response: false}` | 1 (request only) | Pointer non-nil, but `Response` is false; block skipped |
| U24 | Line 99 | `spec.UDP = &UDPConfig{Response: true}` | 2 (request + response) | Both conditions true; response packet emitted on channel |

#### Goroutine: flowID format

| Tag | Input combination | flowID String | Explanation |
|-----|-------------------|---------------|-------------|
| U25 | All IPs and ports set | `"192.168.1.1-10.0.0.2-12345-53"` | Normal case |
| U26 | `SrcIP=""`, rest set | `"-10.0.0.2-0-53"` | Empty SrcIP, SrcPort=0 still shows "0" in format (Srv validation would've rejected port 0, but ports can be non-zero even with empty IPs) |
| U27 | All empty | `"--0-0"` | All empty -- valid per Validate (U3+U6) but U26/U27 are also technically possible when valid but empty |

Wait, U26 above is wrong. If SrcPort is 0, Validate would have rejected it (U7). So ports 0 cannot reach the goroutine. Let me fix: only IPs can be empty when ports are non-zero.

| U25 | `SrcIP="1.1.1.1", DstIP="2.2.2.2", SrcPort=100, DstPort=200` | `"1.1.1.1-2.2.2.2-100-200"` | All 4 fields populated |
| U26 | `SrcIP="", DstIP="2.2.2.2", SrcPort=100, DstPort=200` | `"-2.2.2.2-100-200"` | Empty SrcIP, populated DstIP |
| U27 | `SrcIP="1.1.1.1", DstIP="", SrcPort=100, DstPort=200` | `"1.1.1.1--100-200"` | Populated SrcIP, empty DstIP |
| U28 | `SrcIP="", DstIP="", SrcPort=100, DstPort=200` | `"--100-200"` | Both IPs empty (valid per U9) |

#### Goroutine: nextIPID sequencing

| Tag | Scenario | Request IPID | Response IPID | Explanation |
|-----|----------|-------------|---------------|-------------|
| U29 | U22/U23 (no response) | 1 | N/A | nextIPID init=1, called once |
| U30 | U24 (with response) | 1 | 2 | nextIPID init=1, called twice |

#### Goroutine: Direction and MAC/IP/port swapping (request vs response)

| Tag | Scenario | Request: Direction | Request: L2 MACs | Request: L3 IPs | Request: L4 ports | Response: Dir | Response: L2 MACs | Response: L3 IPs | Response: L4 ports |
|-----|----------|-------------------|-------------------|------------------|--------------------|---------------|-------------------|------------------|--------------------| 
| U31 | U22/U23 (no response) | `"up"` | SrcMAC/DstMAC from spec | SrcIP/DstIP from spec | SrcPort/DstPort from spec | N/A | N/A | N/A | N/A |
| U32 | U24 (response) | `"up"` | SrcMAC/DstMAC from spec | SrcIP/DstIP from spec | SrcPort/DstPort from spec | `"down"` | spec.DstMAC / spec.SrcMAC (swapped) | spec.DstIP / spec.SrcIP (swapped) | spec.DstPort / spec.SrcPort (swapped) |

#### Goroutine: Payload handling

| Tag | spec.Payload value | Request Payload | Response Payload | Explanation |
|-----|--------------------|-----------------|------------------|-------------|
| U33 | `nil` (omitted) | `nil` | `nil` (if response) | nil propagates directly |
| U34 | `[]byte{}` (empty) | `[]byte{}` | `[]byte{}` (if response) | Empty slice propagates |
| U35 | `[]byte("hello")` | `[]byte("hello")` | `[]byte("hello")` (if response) | Data propagates -- note: **same backing array** (shared reference, not a copy) |

#### Goroutine: L2 MAC values

| Tag | spec.SrcMAC / spec.DstMAC | Request L2 MACs | Response L2 MACs (if response) | Explanation |
|-----|--------------------------|-----------------|--------------------------------|-------------|
| U36 | Both empty | `"", ""` | `"", ""` (swapped, still empty) | Empty strings propagate |
| U37 | Both set | Spec values | Swapped spec values | Normal case |
| U38 | Only SrcMAC set | SrcMAC set, DstMAC empty | SrcMAC=empty, DstMAC=SrcMAC (swapped) | Partially configured MACs |
| U39 | Only DstMAC set | SrcMAC empty, DstMAC set | SrcMAC=DstMAC, DstMAC=empty (swapped) | Partially configured MACs |

#### Goroutine: Timestamp behavior

| Tag | Behavior | Explanation |
|-----|----------|-------------|
| U40 | `time.Now()` captured once at goroutine start | Both request and response (if any) share the **same timestamp value**; no per-packet timestamp |

#### Goroutine: L4 protocol field

| Tag | Location | Value | Explanation |
|-----|----------|-------|-------------|
| U41 | Lines 91 and 113 | Hard-coded `"udp"` | Always "udp" regardless of spec |

#### Goroutine: L3 protocol field (via `core.L3Base`)

| Tag | Location | Value | Explanation |
|-----|----------|-------|-------------|
| U42 | L3Base call | `17` (UDP protocol number) | Hard-coded, passed as literal to L3Base |

#### Goroutine: EtherType

| Tag | Location | Value | Explanation |
|-----|----------|-------|-------------|
| U43 | Lines 86 and 108 | `0x0800` (IPv4) | Hard-coded -- **Note: no IPv6 support** |

---

### Context Cancellation Paths

The `ctx` parameter is passed to `Plan()` but **is never inspected inside the goroutine**. There are zero `select` statements, zero `ctx.Done()` checks, and zero `ctx.Err()` checks anywhere in this file.

| Tag | When Context is Cancelled | Behavior | Outcome | Explanation |
|-----|---------------------------|----------|---------|-------------|
| U44 | Before `Plan()` is called | Validate still runs normally; Plan returns before goroutine launch | Normal return (or error if Validate fails) | Context not checked by Validate or Plan |
| U45 | After `Plan()` returns but before goroutine starts scheduling | Goroutine scheduled eventually | Goroutine runs, sends packets | No ctx check; goroutine runs oblivious |
| U46 | During goroutine execution (before or after sends) | Goroutine continues running to completion | Packets sent, channel closed normally | **Bug: no ctx.Done() select** -- cancellation has no effect on goroutine |
| U47 | Context cancelled AND caller stops reading from configChan | Goroutine blocks on `configChan <- core.PacketConfig{...}` | **Goroutine leak** -- goroutine blocked on send indefinitely | Buffer cap is 256; if caller abandons reading, the first 256 sends succeed, then the (potential) 257th send (for response) blocks forever |
| U48 | Context cancelled AND caller panics/killed | Channel receiver gone | **Goroutine leak** if goroutine hasn't finished; or panic if send to closed channel (if caller closed channel) | Depends on exact caller behavior |

---

### Channel Close / Completion Paths

| Tag | Scenario | Sequence |
|-----|----------|----------|
| U49 | U22/U23 (1 packet, no response) | Send request -> goroutine falls off end -> `defer close(configChan)` -> caller sees channel close after 1 packet |
| U50 | U24 (2 packets, with response) | Send request -> send response -> goroutine falls off end -> `defer close(configChan)` -> caller sees channel close after 2 packets |
| U51 | Goroutine panics | `defer close(configChan)` runs as panic unwinds stack; channel is closed, then panic propagates up, crashing the process if unrecovered |

---

### Complete Branch Coverage Map

Here is every boolean decision point in the file with all outcomes:

| Line | Expression | True Outcome | False Outcome | Tags |
|------|-----------|-------------|--------------|------|
| 32 | `spec.SrcIP != ""` | Enter SrcIP validation block | Skip to DstIP block | U1/U2 vs U3 |
| 33 | `net.ParseIP(spec.SrcIP) == nil` | **Return** "invalid source IP" | Fall through to DstIP block | U2 vs U1 |
| 37 | `spec.DstIP != ""` | Enter DstIP validation block | Skip to SrcPort check | U4/U5 vs U6 |
| 38 | `net.ParseIP(spec.DstIP) == nil` | **Return** "invalid destination IP" | Fall through to SrcPort check | U5 vs U4 |
| 42 | `spec.SrcPort == 0` | **Return** "source port is required" | Fall through to DstPort check | U7/U13 vs U8/others |
| 45 | `spec.DstPort == 0` | **Return** "destination port is required" | Fall through to `return nil` | U9/U14 vs U10/U15 |
| 53 | `p.Validate(spec) != nil` | **Return** `nil, err` | Continue to goroutine setup | U16 vs U17 |
| 64 | `effectiveTTL == 0` | Set `effectiveTTL = DefaultTTL` | Keep `spec.TTL` as-is | U18 vs U19/U20/U21 |
| 99 | `spec.UDP != nil && spec.UDP.Response` | Emit response packet | Skip response block | U24 vs U22/U23 |

**Edge case note on line 99:** `spec.UDP != nil` is evaluated first (short-circuit `&&`). If `spec.UDP` is nil, `spec.UDP.Response` is never accessed, avoiding a nil-pointer dereference. This is correctly guarded.

---

### Summary Statistics

- **Total business scenarios enumerated:** 51 (U1-U51)
- **Unique code branches covered:** 10 binary decision points = 20 outcomes + goroutine lifecycle paths
- **Context cancellation bug:** 1 significant issue (U46, U47) -- context cancellation is **never checked** in the goroutine, so:
  - Cancellation does **not** stop packet generation
  - If the caller stops reading from the channel after cancellation, the goroutine can **leak** (block forever on send)
- **No `select` or `ctx.Done()`** anywhere in the file
- **No race conditions** in the single-goroutine design (all work is sequential within one goroutine)
- **Shared mutable state** concern: `spec.Payload` is a slice header (reference type) -- both request and response (if any) share the **same backing array** (U35). If the caller modifies the `FlowSpec` after `Plan()` returns, the packet data could be corrupted since the goroutine may not have sent the payload yet.