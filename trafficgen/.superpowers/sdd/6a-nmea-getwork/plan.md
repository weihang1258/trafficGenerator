# Task 6a: NMEA 0183 + getwork/stratum 实现计划

**Goal:** 为 NMEA 0183 和 getwork/stratum 实现完整层链架构支持

**Architecture:** NMEA 0183 是双载体（TCP/UDP）GPS 协议，sessions[]/events[] 事件编排，XOR 校验和。getwork 是比特币挖矿代理，支持 getwork JSON-RPC 2.0 和 stratum V1 两种形态。

**Spec:** docs/protocol-designs/69-nmea-design.md, docs/protocol-designs/75-stratum-design.md, docs/protocol-designs/76-getwork-design.md

---

## Task 1: NMEA 0183 — registry + layer_gen.go

**Files:**
- Modify: `internal/core/layers/registry.go` (NMEA FieldContract: TransportOn=[tcp,udp])
- Create: `internal/protocol/nmea/layer_gen.go`
- Create: `internal/protocol/nmea/layer_gen_test.go`

**Step 1: Read design doc**

Read `/home/weihang/trafficGenerator/docs/protocol-designs/69-nmea-design.md` in full.

**Step 2: Read similar protocol for pattern**

Read `internal/protocol/dns/layer_gen.go` — it's a UDP/TCP dual-carrier protocol with sessions/events. Use it as the template pattern.

**Step 3: Read DNS chain_planner for sessions/events pattern**

Read `internal/protocol/dns/chain_planner.go` — see how sessions[]/events[] are handled.

**Step 4: Read gbt protocol for session[].src_port pattern**

Read `internal/protocol/gbt/chain_planner.go` — see how multiple sessions with per-session src_port work (gbt_concurrent_sessions case).

**Step 5: Register NMEA in registry.go**

Add to `registry.go`:
```go
// NMEA0183 — GPS NMEA 0183 sentences
// TransportOn=[tcp,udp]; DependsOn=[tcp] or [udp]
registry["nmea"] = LayerSpec{
    Name:       "nmea",
    Category:   CategoryTerminal,
    DependsOn:  []string{"tcp", "udp"}, // actually handled via TransportOn
    TransportOn: []string{"tcp", "udp"},
    FieldContract: FieldContract{
        // NMEA fields (sentence builder only, no dst_port contract)
    },
    FieldSchema: FieldSchema{
        "talker":    {Type: TypeString, Default: "GP"},
        "sentence":   {Type: TypeString, Default: ""},
        "fields":     {Type: TypeSlice, Default: nil},
        "checksum":   {Type: TypeString, Default: ""},
        "timestamp":  {Type: TypeString, Default: ""},
        "latitude":   {Type: TypeFloat, Default: 0.0},
        "longitude":  {Type: TypeFloat, Default: 0.0},
        "altitude":   {Type: TypeFloat, Default: 0.0},
        "speed":      {Type: TypeFloat, Default: 0.0},
        "course":     {Type: TypeFloat, Default: 0.0},
        "date":       {Type: TypeString, Default: ""},
        "time":       {Type: TypeString, Default: ""},
    },
}
```

Actually, NMEA's layer_gen.go just needs to provide BuildLayers that takes config and returns the NMEA layer bytes. The XOR checksum computation is the key.

**Step 6: Create layer_gen.go**

Key methods:
```go
func NMEABuild(cfg map[string]interface{}) gLayers.Layer
func XORChecksum(sentence string) uint8  // XOR all chars between $ and *
func BuildSentence(talker, sentenceID string, fields []string) string  // $GPxxx,...*CS
func BuildLayers(ctx context.Context, cfg map[string]interface{}) ([]gLayers.Layer, error)
```

BuildSentence computes XOR and appends *HH at the end.

**Step 7: Create layer_gen_test.go**

Test cases:
- `TestXORChecksum`: Verify $GPGGA,...*75 for known NMEA sentences
- `TestBuildSentence`: Verify full sentence construction
- `TestBuildLayers`: Verify layer output shape

---

## Task 2: NMEA 0183 — chain_planner.go + metadata integration

**Files:**
- Create: `internal/protocol/nmea/chain_planner.go`

**Step 1: Read DNS chain_planner for sessions pattern**

Read `internal/protocol/dns/chain_planner.go` — DNS sessions[]/events[] implementation.

**Step 2: Read gbt chain_planner for concurrent sessions**

Read `internal/protocol/gbt/chain_planner.go` — multiple concurrent sessions with per-session src_port.

**Step 3: Create chain_planner.go**

Key types:
```go
type NMEASession struct {
    Events []NMEAEvent  // each event = one NMEA sentence
}
type NMEAEvent struct {
    TalkerID  string
    Sentence  string
    Fields    []string
    Timestamp string  // HHMMSS.SSS format
}
```

Plan() function:
1. Read sessions from spec.Metadata["nmea"]
2. For each session, spawn a goroutine
3. Each event generates one NMEA sentence with XOR checksum
4. Channel output to PacketConfig stream

**Step 4: Integrate in strategy_convert.go**

Read DNS integration in strategy_convert.go for the pattern:
```go
case "nmea":
    if sub, ok := cfg["nmea"].(map[string]interface{}); ok {
        if spec.Metadata == nil {
            spec.Metadata = make(map[string]interface{})
        }
        spec.Metadata["nmea"] = sub  // raw JSON for protocol planner to deserialize
    }
```

**Step 5: Verify builds**

```bash
go build ./internal/protocol/nmea/...
```

---

## Task 3: NMEA 0183 — chain equivalence test

**Files:**
- Create: `internal/core/layers/chain_equivalence_nmea_test.go`

**Step 1: Read existing equivalence test for pattern**

Read `internal/core/layers/chain_equivalence_dns_test.go` — DNS equivalence test (the 8 migrated protocols use this pattern).

**Step 2: Create test**

Since NMEA is NEW (not legacy), the test verifies chain path works correctly:
- Build a FlowSpec with NMEA sessions
- Call NewChainPlanner("nmea").Plan
- Verify PacketConfig stream outputs NMEA sentences with correct XOR checksums

---

## Task 4: NMEA 0183 — 49 test cases

**Files:**
- Create: `test/protocol_pcap/cases/nmea.json`

**Step 1: Read NMEA design doc testcase section**

Read `/home/weihang/trafficGenerator/docs/protocol-designs/69-nmea-testcase.md` sections 1-4 for case structure.

**Step 2: Read DNS cases for JSON format**

Read `test/protocol_pcap/cases/dns.json` — see how DNS sessions/events are structured in test cases.

**Step 3: Create 49 cases**

Structure:
- `nmea_basic_*` (5 cases): GGA, RMC, GSV, GLL, VTG basic
- `nmea_tcp_*` (5 cases): TCP transport variants
- `nmea_udp_*` (5 cases): UDP transport variants  
- `nmea_multi_session_*` (4 cases): 2-4 sessions concurrent
- `nmea_mixed_transport` (1 case): sessions[0] TCP + sessions[1] transport:"udp"
- `nmea_event_*` (4 cases): different event types
- `nmea_checksum_*` (5 cases): XOR checksum verification
- `nmea_latlon_*` (5 cases): lat/lon parsing
- `nmea_timestamp_*` (3 cases): timestamp formatting
- `nmea_custom_*` (5 cases): custom talker/sentence
- `nmea_full_*` (3 cases): full GPS solution (GGA+RMC+GSV)
- `nmea_error_*` (4 cases): invalid checksum, unknown sentence, etc.

Each case uses spec_json with layers: [ip, tcp/nmea] or [ip, udp/nmea].

---

## Task 5: getwork/stratum — registry + layer_gen.go

**Files:**
- Modify: `internal/core/layers/registry.go` (getwork FieldContract)
- Create: `internal/protocol/getwork/layer_gen.go`
- Create: `internal/protocol/getwork/layer_gen_test.go`

**Step 1: Read stratum design doc**

Read `/home/weihang/trafficGenerator/docs/protocol-designs/75-stratum-design.md` and `76-getwork-design.md`.

**Step 2: Read gbt protocol for getwork RPC pattern**

Read `internal/protocol/gbt/layer_gen.go` — BTC general block header + getwork RPC.

**Step 3: Create getwork/layer_gen.go**

Key types:
```go
// getwork RPC (JSON-RPC 2.0 over HTTP-like TCP framing)
// Request: {"id":1,"method":"getwork","params":[]}\n
// Response: {"id":1,"result":{"data":"...","hash1":"...","midstate":"..."}}\n

// stratum V1 (JSON-RPC 2.0 with mining extensions)
// Request: {"id":null,"method":"mining.subscribe","params":["agent","extranonce1","extranonce2_size"]}
// Response: {"id":null,"result":["...","extranonce1","extranonce2_size"]}

type GetworkRequest struct {
    ID     interface{}   `json:"id"`
    Method string        `json:"method"`
    Params []interface{} `json:"params,omitempty"`
}

type GetworkResponse struct {
    ID     interface{}   `json:"id"`
    Result interface{}   `json:"result,omitempty"`
    Error  []interface{} `json:"error,omitempty"`
}
```

Build functions:
- `GetworkBuild(cfg)` → Layer (HTTP-like framing)
- `StratumBuild(cfg)` → Layer (stratum V1 TLV)
- `BuildLayers(ctx, cfg)` → []Layer

**Step 4: Create test cases for XOR/XMD5 in stratum**

Stratum uses XOR-based extranonce communication. Test these patterns.

**Step 5: Register in registry.go**

```go
registry["getwork"] = LayerSpec{
    Name:       "getwork",
    Category:   CategoryTerminal,
    DependsOn:  []string{"tcp"},
    FieldSchema: FieldSchema{
        "method": {Type: TypeString},
        "params": {Type: TypeSlice},
        "result": {Type: TypeAny},
        "session_id": {Type: TypeString},
        "extranonce1": {Type: TypeString},
        "extranonce2": {Type: TypeString},
        "difficulty": {Type: TypeFloat},
    },
}
```

---

## Task 6: getwork/stratum — chain_planner.go + metadata integration

**Files:**
- Create: `internal/protocol/getwork/chain_planner.go`

**Step 1: Create chain_planner.go**

Similar to NMEA but with JSON-RPC framing:
```go
type GetworkSession struct {
    Events []GetworkEvent
}
type GetworkEvent struct {
    Method string   // getwork, getblocktemplate, mining.subscribe, etc.
    Params []interface{}
    Result interface{}  // nil = request, set = response
}
```

**Step 2: Integrate in strategy_convert.go**

Same Metadata pattern as NMEA:
```go
case "getwork":
    if sub, ok := cfg["getwork"].(map[string]interface{}); ok {
        if spec.Metadata == nil {
            spec.Metadata = make(map[string]interface{})
        }
        spec.Metadata["getwork"] = sub
    }
```

---

## Task 7: getwork/stratum — 31 test cases

**Files:**
- Create: `test/protocol_pcap/cases/getwork.json`

**Step 1: Read stratum design doc testcase section**

Read `/home/weihang/trafficGenerator/docs/protocol-designs/75-stratum-testcase.md` sections 1-4.

**Step 2: Create 31 cases**

Structure:
- `getwork_basic_*` (5 cases): getwork RPC basic
- `getwork_stratum_*` (5 cases): stratum V1 methods
- `getwork_multi_session_*` (4 cases): concurrent sessions
- `getwork_concurrent_sessions` (1 case): concurrent=true sessions
- `getwork_tcp_*` (4 cases): TCP framing variants
- `getwork_stratum_tcp_*` (4 cases): stratum over TCP
- `getwork_error_*` (3 cases): invalid JSON, unknown method, etc.
- `getwork_extranonce_*` (5 cases): extranonce exchange

---

## Task 8: Smoke verification

**Step 1: NMEA smoke**

```bash
PCAP_ROOT=/tmp/mcp-pcaps MCP_API_KEY=dev-mcp-key \
  CASE_PROTO=nmea CASE_MAX=2 go test ./test/protocol_pcap/... \
  -run TestProtocolPcapDrive -count=1 -timeout=120s
```

**Step 2: getwork smoke**

```bash
PCAP_ROOT=/tmp/mcp-pcaps MCP_API_KEY=dev-mcp-key \
  CASE_PROTO=getwork CASE_MAX=2 go test ./test/protocol_pcap/... \
  -run TestProtocolPcapDrive -count=1 -timeout=120s
```

**Step 3: Full test suite (subset)**

```bash
go test ./internal/core/layers/... -count=1 -timeout=120s
```
