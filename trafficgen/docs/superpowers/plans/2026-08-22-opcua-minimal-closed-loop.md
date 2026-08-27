# OPC UA Minimal Closed Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a usable OPC UA TCP terminal layer that emits HEL/ACK, OPN, one MSG Read exchange, optional CLO, validates malformed configuration, and works over IPv4 and IPv6 through the existing layer-chain/TCP transport.

**Architecture:** Reuse the existing `[ip] → [tcp] → terminal` event architecture. A new `internal/protocol/opcua` package owns typed configuration, validation, UA-TCP/UA-SC/UA-SC MSG byte builders, and an event generator; `core.FlowSpec`/`layers.FlowMeta` carry the config, the registry and strategy converter expose the `opcua` layer, and `cmd/server/main.go` imports/registers the package and planner. TCP owns handshake, MSS segmentation, sequence/ACK behavior, and termination; OPC UA emits complete application messages only.

**Tech Stack:** Go, existing `internal/core`, `internal/core/layers`, `encoding/binary`, Go unit tests, `go test -race`, `go vet`, `gofmt`.

## Global Constraints

- Do not modify unrelated protocol code or overwrite existing user changes.
- Follow TDD: each behavior gets a failing test run before implementation.
- Every code modification is reviewed from the actual diff and surrounding files before tests; fixes require another review before retesting.
- Do not commit git changes.
- Use streaming event generation and propagate context cancellation and emitter errors.
- HEL/ACK and OPN/MSG/CLO lengths are little-endian UA-TCP MessageSize fields; invalid sizes/configuration fail synchronously through `Validate`/`Plan`.
- `security_mode` supports `none` and structural `sign`; no cryptographic verification is attempted.

## File Map

- Create `internal/protocol/opcua/types.go`: `core` aliases/constants and OPC UA configuration types.
- Create `internal/protocol/opcua/builder.go`: pure byte builders for HEL, ACK, OPN, MSG Read request/response, and CLO plus UA-TCP length checks.
- Create `internal/protocol/opcua/planner.go`: legacy planner validation/Plan fallback and message sequence semantics.
- Create `internal/protocol/opcua/layer_gen.go`: `layers.LayerGenerator`, event emission, registry/validator init registration.
- Create `internal/protocol/opcua/opcua_test.go`: spec-derived builder, validation, planner, and generator tests.
- Modify `internal/core/types.go`: add `OPCUAConfig` and `FlowSpec.OPCUA`.
- Modify `internal/core/layers/generator.go`: add `FlowMeta.OPCUA`.
- Modify `internal/core/layers/registry.go`: register `opcua` as a TCP terminal layer.
- Modify `internal/core/layers/chain_planner.go`: carry `spec.OPCUA` into `FlowMeta`, translate layer config defaults, and default destination port 4840.
- Modify `internal/core/strategy_convert.go`: parse flat `opcua` config and default port 4840.
- Modify `cmd/server/main.go`: blank-import OPC UA package and register `layers.NewChainPlanner("opcua")`.
- Create/modify `internal/core/layers/build_layers_planner_test.go` only if needed for a cross-package chain assertion; otherwise keep coverage in OPC UA package tests.

### Task 1: Core Configuration and Converter Failure Tests

**Files:**
- Modify: `internal/core/types.go`
- Modify: `internal/core/strategy_convert.go`
- Test: `internal/protocol/opcua/opcua_test.go`

- [ ] **Step 1: Write failing tests** for JSON conversion of `{opcua:{security_mode:"none",read:true,close:true}}`, default `dst_port=4840`, explicit `dst_port` preservation, and typed `FlowSpec.OPCUA` population.
- [ ] **Step 2: Run** `go test ./internal/protocol/opcua -run 'Test.*Convert|Test.*DefaultPort' -count=1`; expected failure because package/config/converter fields do not exist.
- [ ] **Step 3: Add** `OPCUAConfig` with `SecurityMode string`, `Read bool`, `Close bool`, and `SkipChannel bool` (plus `BadMessageSize bool`, `BadLength bool` for negative cases), and add `OPCUA *OPCUAConfig` to `FlowSpec`.
- [ ] **Step 4: Add** `case "opcua"` in `mapToFlowSpec`, JSON-unmarshal the sub-map, append conversion errors to `ValidationErrors`, and default destination port only when absent.
- [ ] **Step 5: Run the focused tests and verify PASS; inspect explicit zero/false handling so absent defaults do not overwrite user values.

### Task 2: UA-TCP/UA-SC Builder TDD

**Files:**
- Create: `internal/protocol/opcua/types.go`
- Create: `internal/protocol/opcua/builder.go`
- Test: `internal/protocol/opcua/opcua_test.go`

- [ ] **Step 1: Write failing pure-builder tests** asserting exact bytes and lengths: HEL starts `HEL F`, size 32 for empty EndpointUrl; ACK starts `ACK F`, size 28; OPN starts `OPN F` and has channel id at offset 8; MSG starts `MSG F` and contains little-endian request handle/node id; CLO starts `CLO F`.
- [ ] **Step 2: Run** `go test ./internal/protocol/opcua -run 'TestBuild' -count=1`; expected failure because builders are absent.
- [ ] **Step 3: Implement** little-endian helpers and builders. HEL fields are five UInt32 values plus UA String length `0`; ACK has protocol/revision/receive/send/max message/max chunk fields; OPN includes secure-channel id and symmetric placeholder body; MSG Read includes token id, request handle, timestamps/timeout placeholders, type id, and one FourByte NodeId (`ns=0;i=1001` default); response mirrors a valid service result/status structure. Use `binary.LittleEndian` and calculate MessageSize after append.
- [ ] **Step 4: Implement CLO with secure-channel id/token placeholders and a valid UA-TCP size field.
- [ ] **Step 5: Run focused builder tests and assert observable bytes, not only non-empty output.

### Task 3: Validation and Legacy Planner TDD

**Files:**
- Create: `internal/protocol/opcua/planner.go`
- Test: `internal/protocol/opcua/opcua_test.go`

- [ ] **Step 1: Add failing tests** for missing config, invalid `security_mode`, `bad_message_size`, `bad_length`, and `skip_channel` with Read; error text must contain `MessageSize`, `length`, or `secureChannel` respectively.
- [ ] **Step 2: Run** `go test ./internal/protocol/opcua -run 'TestValidate|TestPlan' -count=1`; expected failure.
- [ ] **Step 3: Implement** `Planner{Name, Validate, Plan}`. Validation defaults empty security mode to `none`, rejects non-TCP transport if represented, rejects malformed flags before any event, and rejects Read when `SkipChannel` is true. Plan emits HEL up, ACK down, OPN up/down, optional MSG Read up/down, optional CLO up/down or symmetric single event according to established terminal patterns, with context cancellation and emitter error propagation.
- [ ] **Step 4: Run planner tests and assert event order, direction, exact prefixes, and no events after validation errors.

### Task 4: Layer Generator and Chain Wiring TDD

**Files:**
- Create: `internal/protocol/opcua/layer_gen.go`
- Modify: `internal/core/layers/generator.go`
- Modify: `internal/core/layers/registry.go`
- Modify: `internal/core/layers/chain_planner.go`
- Test: `internal/protocol/opcua/opcua_test.go`
- Test: `internal/core/layers/build_layers_planner_test.go` if a package-level chain test is required.

- [ ] **Step 1: Write failing layer tests** that instantiate the registered generator with `layers.NewLayerGenerator("opcua")`, emit events using `GenRequest.Meta.OPCUA`, and drive `[ip,tcp,opcua]`; assert the event bytes survive TCP, ports are 4840, TCP payload segments retain complete UA prefixes, and IPv4/IPv6 EtherType is 0x0800/0x86dd.
- [ ] **Step 2: Run** `go test ./internal/protocol/opcua ./internal/core/layers -run 'Test.*Layer|Test.*Chain|Test.*IPv6' -count=1`; expected failure due to missing registration/meta/config.
- [ ] **Step 3: Add** `FlowMeta.OPCUA`, map `spec.OPCUA` in `ChainPlanner.drive`, and register `opcua` schema with `DependsOn: []string{"tcp"}`.
- [ ] **Step 4: Extend terminal translation for `opcua` defaults (`security_mode=none`, read/close policy) and add an OPC UA destination-port branch in `validateSpecBase`.
- [ ] **Step 5: Implement `OPCUAGenerator.Generate`, `GenEvents`, and registration of generator plus validator in `init`.
- [ ] **Step 6: Run chain tests and verify packet count/directions, UA prefixes at application payload, IPv4/IPv6 addresses, and close behavior.

### Task 5: Strategy Layer Config and Server Registration

**Files:**
- Modify: `internal/core/strategy_convert.go` if layer-config translation needs a dedicated branch.
- Modify: `cmd/server/main.go`.
- Test: `internal/core/layers/build_layers_planner_test.go` or `internal/protocol/opcua/opcua_test.go`.

- [ ] **Step 1: Write a failing integration test** for `BuildLayersPlanner("opcua", [{"opcua":{"security_mode":"none","read":true,"close":true}}])`, proving the layer config reaches `FlowMeta.OPCUA` rather than silently falling back to nil.
- [ ] **Step 2: Run the focused integration test and confirm failure.
- [ ] **Step 3: Translate OPC UA layer config into `spec.OPCUA` when flat config is absent, preserving flat-authoritative behavior when both are present.
- [ ] **Step 4: Blank-import `internal/protocol/opcua` and register `layers.NewChainPlanner("opcua")` in `initEngine` beside S7/IEC104.
- [ ] **Step 5: Run the integration test and `go test ./cmd/server ./internal/core/layers ./internal/protocol/opcua -count=1`.

### Task 6: Full Verification and Review Gate

**Files:** all changed files above.

- [ ] **Step 1: Review every changed file and diff line-by-line**, checking UA-TCP offsets, little-endian lengths, TCP port direction, IPv4/IPv6 EtherType, event ordering, cancellation/error propagation, and all call sites.
- [ ] **Step 2: If review finds a defect, add a reproducing failing test first, fix it, review the fix again, and rerun the relevant test.
- [ ] **Step 3: Run** `gofmt -w` on changed Go files.
- [ ] **Step 4: Run** `go vet ./internal/protocol/opcua ./internal/core/... ./cmd/server`.
- [ ] **Step 5: Run** `go test -race ./internal/protocol/opcua ./internal/core/layers ./internal/core`.
- [ ] **Step 6: Run the OPC UA protocol PCAP cases with `go test -race ./test/protocol_pcap -run OPCUA -count=1` if the harness exposes the suite; record unsupported cases separately rather than weakening assertions.
- [ ] **Step 7: Perform a final self-review and report actual files, test commands/results, and self-review round count. Do not commit.
