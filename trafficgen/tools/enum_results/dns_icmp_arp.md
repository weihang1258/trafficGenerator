Now I have all the information needed. Let me compile the exhaustive enumeration.

---

# DNS Planner (`dns.go`) -- Full Scenario Enumeration

## Validate() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/dns/dns.go:39-66`

**D1:** `spec.SrcIP != ""`, is valid
- Input: `spec.SrcIP = "192.168.1.1"`
- Expected: no error returned
- Branch: line 41 `if net.ParseIP(spec.SrcIP) == nil` evaluates false

**D2:** `spec.SrcIP != ""`, is invalid
- Input: `spec.SrcIP = "not-an-ip"`
- Expected: error `"invalid source IP: not-an-ip"`
- Branch: line 42-43 `net.ParseIP(spec.SrcIP) == nil` is true

**D3:** `spec.SrcIP == ""` (empty)
- Input: `spec.SrcIP = ""`
- Expected: skip validation, no error
- Branch: line 41 `if spec.SrcIP != ""` is false

**D4:** `spec.DstIP != ""`, is valid
- Input: `spec.DstIP = "10.0.0.1"`
- Expected: no error returned
- Branch: line 47 `if net.ParseIP(spec.DstIP) == nil` false

**D5:** `spec.DstIP != ""`, is invalid
- Input: `spec.DstIP = "bad"`
- Expected: error `"invalid destination IP: bad"`
- Branch: line 47-49 `net.ParseIP(spec.DstIP) == nil` is true

**D6:** `spec.DstIP == ""` (empty)
- Input: `spec.DstIP = ""`
- Expected: skip validation, no error
- Branch: line 46 `if spec.DstIP != ""` is false

**D7:** `spec.DstPort == 0` (unset)
- Input: `spec.DstPort = 0`
- Expected: spec.DstPort mutated to 53 (default DNS port)
- Branch: line 53-54 `if spec.DstPort == 0` is true

**D8:** `spec.DstPort != 0` (explicitly set)
- Input: `spec.DstPort = 5353`
- Expected: port kept as-is (5353)
- Branch: line 53 `if spec.DstPort == 0` is false

**D9:** `spec.DNS == nil`
- Input: `spec.DNS = nil`
- Expected: error `"DNS config is required"`
- Branch: line 58-59 `if spec.DNS == nil` is true

**D10:** `spec.DNS != nil` but `spec.DNS.Domain == ""`
- Input: `spec.DNS = &DNSConfig{Domain: ""}`
- Expected: error `"domain is required"`
- Branch: line 61-62 `if spec.DNS.Domain == ""` is true

**D11:** Validation passes (both IPs valid or empty, DstPort set or defaulted, DNS config present with non-empty domain)
- Input: well-formed spec
- Expected: `return nil`
- Branch: falls through line 65

---

## Plan() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/dns/dns.go:69-143`

**D12:** Validation failure propagates
- Input: any invalid spec (per D2/D5/D9/D10)
- Expected: `return nil, err`
- Branch: line 70 `if err := p.Validate(spec); err != nil` is true

**D13:** Validation passes, goroutine launches
- Input: valid spec
- Expected: channel created (buffer 256), goroutine spawned, channel returned immediately
- Branch: line 74 goroutine with `defer close(configChan)`

**D14:** TTL not set (zero)
- Input: `spec.TTL = 0`
- Expected: `effectiveTTL = 64` (DefaultTTL)
- Branch: line 81 `if effectiveTTL == 0` is true

**D15:** TTL explicitly set
- Input: `spec.TTL = 128`
- Expected: `effectiveTTL = 128`
- Branch: line 81 `if effectiveTTL == 0` is false

**D16:** DNS query packet sent (always)
- Input: any valid spec
- Expected: one `PacketConfig` sent to channel with `Direction: "up"`, `PacketIndex: 0`, protocol `17` (UDP), EtherType `0x0800` (IPv4), L4 protocol `"udp"`, payload = DNS query bytes
- Branch: line 97-114 (unconditional channel send)

**D17:** `spec.DNS.Response == true` -- response packet sent
- Input: `spec.DNS.Response = true`, `spec.DNS.ResponseIP = "1.2.3.4"`
- Expected: second `PacketConfig` sent with `Direction: "down"`, `PacketIndex: 1`, swapped src/dst MAC/IP/ports, payload = DNS response bytes
- Branch: line 118 `if spec.DNS.Response` is true

**D18:** `spec.DNS.Response == false` -- no response packet
- Input: `spec.DNS.Response = false`
- Expected: only query sent, goroutine exits, channel closed
- Branch: line 118 `if spec.DNS.Response` is false

## Context Cancellation (DNS)

**D19:** Context cancelled before/during Plan()
- Input: `ctx` already cancelled when `Plan()` is called (e.g., `cancel()` before call)
- Expected: goroutine is fire-and-forget with no `ctx.Done()` check, so it runs to completion anyway and writes to channel. The caller never reads from the channel, but the goroutine exits after the single send. Channel is eventually GC'd when unreferenced.
- Notable: There is NO `select { case <-ctx.Done(): ... }` anywhere in Plan(). The `ctx` parameter is accepted but never consulted.

**D20:** Context cancelled during goroutine execution
- Same as D19 -- no cancellation check exists in the goroutine.

---

## buildDNSResponse() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/dns/dns.go:172-213`

**D21:** `responseIP` is a valid IPv4 address
- Input: `responseIP = "8.8.8.8"`
- Expected: `ip.To4()` returns 4-byte slice; response constructed with that IP

**D22:** `responseIP` is invalid/unparseable (including empty string)
- Input: `responseIP = "bad"` or `responseIP = ""`
- Expected: falls back to `"127.0.0.1"` silently
- Branch: line 198-199 `if ip == nil` is true

**D23:** `responseIP` is a valid IPv6 address (AAAA query)
- Input: `responseIP = "2001:db8::1"`, `queryType = 28`
- Expected: `ip.To4()` returns nil (IPv6 has no 4-byte representation). The `ipBytes` variable at line 201 is `nil`. Append of nil to result appends nothing -- the answer section has zero bytes for the RDATA field. This is a bug: response is malformed for AAAA replies.
- Branch: line 197-201 -- `ip.To4()` returns nil, but no nil-check on `ipBytes` before append at line 210.

---

## splitLabels() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/dns/dns.go:230-248`

**D24:** Normal domain
- Input: `"example.com"`
- Output: `["example", "com"]`
- Branch: loop at `.` splits correctly; trailing `start < len(domain)` is true.

**D25:** Single-label domain (no dots)
- Input: `"localhost"`
- Output: `["localhost"]`
- Branch: loop never sets `start` past 0; `start < len(domain)` is true.

**D26:** Empty string
- Input: `""`
- Output: `[""]` (or `[""]` from trailing check -- a zero-length label, which becomes length byte 0x00 in the encoded form, just like root)
- Branch: loop runs 0 times; `start(0) < len(domain)(0)` is false. Output is `[]` (empty). But wait -- let me re-check: `start = 0`, `len(domain) = 0`, so `start < len(domain)` is false. Output is `[]`. Then in `encodeDomainName`, the for loop iterates zero times, and null terminator 0x00 is appended. Result: `[0x00]` -- which is the root label. This is correct for a degenerate case.

**D27:** Trailing dot
- Input: `"example.com."`
- On `i == 11`, `domain[11] == '.'`, `i > start` is true, appends `"com"`, sets `start = 12`. After loop, `start(12) < len(domain)(12)` is false. Output: `["example", "com"]`. Correct -- the trailing dot creates no empty trailing label.

**D28:** Consecutive dots (empty label)
- Input: `"example..com"`
- At first dot: appends `"example"`, `start = 8`. At second dot (i=8): `domain[8] == '.'`, but `i > start` is false (both 8). No label appended. Output: `["example", "com"]`. The empty label between dots is silently dropped -- this creates a subtly wrong DNS encoding (should be encoded as length-byte 0x00 but is omitted).

**D29:** Domain ending at a dot with no other labels
- Input: `"."`
- `i=0`, `domain[0] == '.'`, `i > start` (0 > 0) is false. No label appended. `start = 1`. After loop, `start(1) < len(domain)(1)` is false. Output: `[]`. Encodes as root label `[0x00]`. This is actually correct (root query).

---

## encodeDomainName() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/dns/dns.go:216-227`

**D30:** Normal multi-label domain
- Input: `["example", "com"]`
- Output: `[7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0]`
- Branch: loop iterates twice; null terminator always appended.

**D31:** Empty labels slice (from splitLabels on "")
- Input: `[]`
- Output: `[0]` -- just the null terminator
- Branch: loop body never executes.

---

# ICMP Planner (`icmp.go`) -- Full Scenario Enumeration

## Validate() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/icmp/icmp.go:34-46`

**I1:** `spec.SrcIP != ""`, is valid
- Input: `spec.SrcIP = "10.0.0.1"`
- Expected: no error
- Branch: line 36 `if net.ParseIP(spec.SrcIP) == nil` false

**I2:** `spec.SrcIP != ""`, is invalid
- Input: `spec.SrcIP = "bad"`
- Expected: error `"invalid source IP: bad"`
- Branch: line 36-37 true

**I3:** `spec.SrcIP == ""`
- Input: `spec.SrcIP = ""`
- Expected: skip
- Branch: line 35 false

**I4:** `spec.DstIP != ""`, is valid
- Input: `spec.DstIP = "10.0.0.2"`
- Expected: no error
- Branch: line 41 false

**I5:** `spec.DstIP != ""`, is invalid
- Input: `spec.DstIP = "bad"`
- Expected: error `"invalid destination IP: bad"`
- Branch: line 41-42 true

**I6:** `spec.DstIP == ""`
- Input: `spec.DstIP = ""`
- Expected: skip
- Branch: line 40 false

**I7:** Validation passes (both valid or empty)
- Input: any spec with valid-or-empty IPs
- Expected: `return nil`

---

## Plan() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/icmp/icmp.go:49-139`

**I8:** Validation failure
- Input: `spec.SrcIP = "bad"`
- Expected: `return nil, err`
- Branch: line 50-51 true

**I9:** Validation passes, goroutine starts
- Input: valid spec
- Expected: channel (buf 256), goroutine, channel returned

**I10:** TTL not set
- Input: `spec.TTL = 0`
- Expected: `effectiveTTL = 64`
- Branch: line 64 true

**I11:** TTL explicitly set
- Input: `spec.TTL = 255`
- Expected: `effectiveTTL = 255`
- Branch: line 64 false

**I12:** `spec.ICMP == nil` (default config)
- Input: `spec.ICMP = nil`
- Expected: defaults to `Type=EchoRequest(8)`, `Code=0`, `Sequence=1`, `Data="ping"`
- Branch: line 75-82 `if icmpConfig == nil` is true

**I13:** `spec.ICMP != nil` (user-provided config)
- Input: `spec.ICMP = &ICMPConfig{Type: 8, Code: 0, Sequence: 42, Data: []byte("custom")}`
- Expected: uses provided config directly
- Branch: line 75 false

**I14:** Echo Request packet sent (unconditional)
- Input: any valid spec
- Expected: first `PacketConfig` with `Direction: "up"`, `PacketIndex: 0`, protocol `1` (ICMP), L4 `"icmp"`, payload from `buildICMPPayload`
- Branch: line 85-104 unconditional

**I15:** `icmpConfig.Type == TypeEchoRequest (8)` -- Echo Reply generated
- Input: `spec.ICMP.Type = 8`
- Expected: second `PacketConfig` with `Direction: "down"`, `PacketIndex: 1`, swapped src/dst, reply payload, metadata `icmp_type: 0`
- Branch: line 107 `if icmpConfig.Type == TypeEchoRequest` is true

**I16:** `icmpConfig.Type != TypeEchoRequest` -- no Echo Reply
- Input: `spec.ICMP.Type = 3` (Destination Unreachable, a non-echo type)
- Expected: only request packet sent, goroutine exits
- Branch: line 107 false

**I17:** ICMP Type = EchoReply (0) as primary packet
- Input: `spec.ICMP.Type = 0`
- Expected: single packet with Type=0 sent. No reply generated. (Type 0 is not == TypeEchoRequest 8)
- Branch: line 107 false

## Context Cancellation (ICMP)

**I18:** Context cancelled
- Same as D19 -- no `ctx.Done()` check anywhere in Plan(). The goroutine runs to completion regardless.

---

## buildICMPPayload() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/icmp/icmp.go:142-166`

No conditionals in the function body. Always produces 8-byte header + data payload with correct checksum.

### calculateChecksum() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/icmp/icmp.go:169-183`

**I19:** Even-length payload
- Input: 8 bytes (standard ICMP header only, no data)
- Expected: correct one's complement checksum; loop condition `i < len(data)-1` covers all pairs; parity check `len(data)%2 == 1` false
- Branch: line 176 false

**I20:** Odd-length payload
- Input: 9 bytes (header + 1 data byte)
- Expected: last byte treated as high byte of a zero-padded word. Checksum correct.
- Branch: line 176-177 `len(data)%2 == 1` true

**I21:** Empty payload
- Input: `[]byte{}`
- Expected: loop doesn't execute (len=0, so `0 < -1` is false), sum=0, `^uint16(0)` = 0xFFFF
- Branch: line 172 condition false; line 176 false (0%2==0)

**I22:** Single-byte payload
- Input: `[]byte{0x08}`
- Expected: loop `0 < 0` false (len-1=0). Parity: `1%2==1`, sum += 0x0800. Result: `^uint16(0x0800)`
- Branch: line 172 false; line 176-177 true

---

# ARP Planner (`arp.go`) -- Full Scenario Enumeration

## Validate() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/arp/arp.go:35-54`

**A1:** `spec.SrcIP != ""`, valid
- Input: `spec.SrcIP = "192.168.1.1"`
- Expected: no error
- Branch: line 38 false

**A2:** `spec.SrcIP != ""`, invalid
- Input: `spec.SrcIP = "bad"`
- Expected: error `"invalid source IP: bad"`
- Branch: line 38-39 true

**A3:** `spec.SrcIP == ""`
- Input: `spec.SrcIP = ""`
- Expected: skip
- Branch: line 37 false

**A4:** `spec.DstIP != ""`, valid
- Input: `spec.DstIP = "192.168.1.2"`
- Expected: no error
- Branch: line 43 false

**A5:** `spec.DstIP != ""`, invalid
- Input: `spec.DstIP = "bad"`
- Expected: error `"invalid destination IP: bad"`
- Branch: line 43-44 true

**A6:** `spec.DstIP == ""`
- Input: `spec.DstIP = ""`
- Expected: skip
- Branch: line 42 false

**A7:** `spec.ARP == nil`
- Input: `spec.ARP = nil`
- Expected: error `"ARP config is required"`
- Branch: line 49-50 true

**A8:** Validation passes
- Input: valid-or-empty IPs, `spec.ARP != nil`
- Expected: `return nil`
- Branch: falls through line 53

---

## Plan() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/arp/arp.go:57-148`

**A9:** Validation failure
- Input: `spec.ARP = nil`
- Expected: `return nil, err`
- Branch: line 58-59 true

**A10:** Validation passes, goroutine starts
- Input: valid spec
- Expected: channel (buf 16), goroutine, channel returned

**A11:** `spec.ARP == nil` despite validation passing (defensive, unreachable if Validate ran)
- Input: impossible from normal flow (Validate checks this)
- Expected: default `ARPConfig{Operation: OperationRequest(1)}`
- Branch: line 74-78 `if arpConfig == nil` is true

**A12:** `spec.ARP != nil`
- Input: `spec.ARP = &ARPConfig{Operation: 2}`
- Expected: uses provided config
- Branch: line 74 false

**A13:** ARP packet sent (unconditional)
- Input: any valid spec
- Expected: first `PacketConfig` with `Direction: "up"`, `PacketIndex: 0`, `DstMAC: "ff:ff:ff:ff:ff:ff"` (broadcast), `EtherType: 0x0806` (ARP), L3 Protocol: 0 (no L3), L4: `"arp"`, payload = 28-byte ARP packet, metadata `arp_operation`
- Branch: line 96-116 unconditional

**A14:** `arpConfig.Operation == OperationRequest (1)` -- ARP Reply generated
- Input: `spec.ARP.Operation = 1`
- Expected: second `PacketConfig` with `Direction: "down"`, `PacketIndex: 1`, swapped MACs, metadata `arp_operation: 2` (OperationReply)
- Branch: line 119 `if arpConfig.Operation == OperationRequest` is true

**A15:** `arpConfig.Operation != OperationRequest` -- no ARP Reply
- Input: `spec.ARP.Operation = 2` (Reply-only mode, or any non-1 value)
- Expected: only request sent, goroutine exits
- Branch: line 119 false

## Context Cancellation (ARP)

**A16:** Context cancelled
- Same pattern as DNS/ICMP: no `ctx.Done()` check in Plan(). Goroutine runs to completion.

---

## buildARPPacket() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/arp/arp.go:151-211`

**A17:** Operation from spec.ARP
- Input: `spec.ARP != nil`, `spec.ARP.Operation = 2`
- Expected: `operation = 2`, bytes at offset 6-7 set to 0x0002
- Branch: line 171-172 `if spec.ARP != nil` true

**A18:** Operation default (spec.ARP == nil)
- Input: `spec.ARP = nil`
- Expected: `operation = OperationRequest (1)`, bytes at offset 6-7 set to 0x0001
- Branch: line 171 false

**A19:** Source MAC parse succeeds (6 bytes)
- Input: `spec.SrcMAC = "00:11:22:33:44:55"`
- Expected: MAC copied to bytes 8-13
- Branch: line 179 `if len(srcMAC) == 6` true

**A20:** Source MAC parse fails or wrong length
- Input: `spec.SrcMAC = "invalid"` or `spec.SrcMAC = ""` or `spec.SrcMAC = "00:11:22:33:44:55:66"` (7 bytes)
- Expected: bytes 8-13 remain zero (`net.ParseMAC` error is silently discarded)
- Branch: line 178-181 -- `net.ParseMAC` returns zero-length MAC, `len(srcMAC) == 6` false

**A21:** Source IP parse succeeds, IPv4
- Input: `spec.SrcIP = "10.0.0.1"`
- Expected: IP copied to bytes 14-17
- Branch: line 185 `srcIP != nil` true; line 187 `len(srcIP) == 4` true

**A22:** Source IP parse fails (nil)
- Input: `spec.SrcIP = ""` (empty)
- Expected: bytes 14-17 remain zero
- Branch: line 185 `srcIP != nil` false

**A23:** Source IP is IPv6 (e.g. "::1" or left empty but still parses)
- Input: `spec.SrcIP = "::1"`
- Expected: `srcIP.To4()` returns nil, `len(srcIP) == 4` false, bytes 14-17 remain zero. ARP is IPv4-only at line level (Protocol address length = 4 bytes).
- Branch: line 185 true; line 186 `srcIP.To4()` returns nil; line 187 false

**A24:** Target MAC provided and valid
- Input: `spec.ARP.TargetMAC = "aa:bb:cc:dd:ee:ff"`
- Expected: MAC copied to bytes 18-23
- Branch: line 194 `spec.ARP != nil && spec.ARP.TargetMAC != ""` true; line 196 `len(dstMAC) == 6` true

**A25:** Target MAC absent (spec.ARP nil or TargetMAC empty)
- Input: `spec.ARP.TargetMAC = ""` or `spec.ARP = nil`
- Expected: bytes 18-23 remain zero (standard for ARP request -- unknown target MAC)
- Branch: line 194 false

**A26:** Target MAC provided but invalid
- Input: `spec.ARP.TargetMAC = "bad"`
- Expected: parse error silently discarded, bytes remain zero
- Branch: line 194 true; `net.ParseMAC` fails, len(dstMAC) != 6, line 196 false

**A27:** Target IP parse succeeds, IPv4
- Input: `spec.DstIP = "10.0.0.2"`
- Expected: IP copied to bytes 24-27
- Branch: line 203 `dstIP != nil` true; line 205 `len(dstIP) == 4` true

**A28:** Target IP parse fails (nil)
- Input: `spec.DstIP = ""`
- Expected: bytes 24-27 remain zero
- Branch: line 203 false

**A29:** Target IP is IPv6
- Input: `spec.DstIP = "2001:db8::1"`
- Expected: `dstIP.To4()` returns nil, bytes 24-27 remain zero
- Branch: line 203 true; line 204-206 `len(dstIP) == 4` false

---

## buildARPReply() -- `/home/weihang/trafficGenerator/trafficgen/internal/protocol/arp/arp.go:214-266`

**A30:** Reply sender hardware address (from spec.DstMAC) valid
- Input: `spec.DstMAC = "aa:bb:cc:dd:ee:ff"`
- Expected: copied to bytes 8-13
- Branch: line 237 `len(dstMAC) == 6` true

**A31:** Reply sender hardware address invalid
- Input: `spec.DstMAC = ""`
- Expected: bytes 8-13 remain zero
- Branch: line 237 false

**A32:** Reply sender IP (from spec.DstIP) valid IPv4
- Input: `spec.DstIP = "10.0.0.2"`
- Expected: copied to bytes 14-17
- Branch: line 243 true; line 245 true

**A33:** Reply sender IP parse fails
- Input: `spec.DstIP = ""`
- Expected: bytes 14-17 remain zero
- Branch: line 243 false

**A34:** Reply sender IP is IPv6
- Input: `spec.DstIP = "::1"`
- Expected: `dstIP.To4()` nil, bytes remain zero
- Branch: line 243 true; line 244-246 false

**A35:** Reply target hardware address (from spec.SrcMAC) valid
- Input: `spec.SrcMAC = "00:11:22:33:44:55"`
- Expected: copied to bytes 18-23
- Branch: line 252 `len(srcMAC) == 6` true

**A36:** Reply target hardware address invalid
- Input: `spec.SrcMAC = ""`
- Expected: bytes 18-23 remain zero
- Branch: line 252 false

**A37:** Reply target IP (from spec.SrcIP) valid IPv4
- Input: `spec.SrcIP = "10.0.0.1"`
- Expected: copied to bytes 24-27
- Branch: line 258 true; line 260 true

**A38:** Reply target IP parse fails
- Input: `spec.SrcIP = ""`
- Expected: bytes 24-27 remain zero
- Branch: line 258 false

**A39:** Reply target IP is IPv6
- Input: `spec.SrcIP = "::1"`
- Expected: `srcIP.To4()` nil, bytes remain zero
- Branch: line 258 true; line 259-261 false

---

# Cross-Cutting Observations

| Issue | Planner | Description |
|---|---|---|
| IPv6 support gap | DNS (D23), ARP (A23, A29, A34, A39) | All three planners hardcode IPv4 assumptions. `L3Base` works with IPv6 strings, but ARP binary format uses 4-byte `To4()` only. DNS response for AAAA queries (Type 28) has a nil `ipBytes` payload. ICMP has no explicit IPv4 dependency in its binary format, but `L3Base` sets no IP version field -- this is presumably handled by the upstream frame builder. |
| No context cancellation | DNS (D19-20), ICMP (I18), ARP (A16) | None of the three planners ever read from `ctx.Done()`. The goroutines are brief, so in practice this is a latent issue only if the planner were ever extended with retries or loops. |
| Silent parse failures | DNS (D22), ARP (A20, A26, A31, A36) | `net.ParseMAC` errors are discarded with `_`. Invalid MACs or IPs silently produce zero-filled fields. The only explicit fallback is in `buildDNSResponse` (falls back to 127.0.0.1). |
| Duplicate flow IDs | All | The flow ID format differs per planner. If multiple flows of the same type have identical parameters, they get the same flow ID which could confuse the resequencer. |
| No `Count`/`Duration` loop | All | These planners generate exactly 1 packet (or 2 with response). They do not read `spec.Count` or `spec.Duration` to generate multiple repetitions -- the caller/replay layer must handle iteration. |
| Missing label preservation in DNS | D28 | Consecutive dots (empty labels) are silently dropped by `splitLabels`, producing a potentially incorrect DNS encoding. The DNS wire format requires empty labels to be encoded as length byte 0x00, not omitted. |