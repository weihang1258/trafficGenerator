# BGP RFC 4271 Minimal TCP Closed Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a BGP RFC 4271 terminal layer that emits a deterministic TCP session with OPEN, bidirectional KEEPALIVE messages, and TCP termination, while rejecting unsupported UPDATE/NOTIFICATION/capability profiles and malformed configuration.

**Architecture:** Reuse the existing `[ip, tcp, bgp]` event-driven chain. `core.BGPConfig` owns validated session values; `internal/protocol/bgp` owns exact BGP message encoding, validation, planner compatibility, and terminal event generation. The layer registry, strategy conversion, FlowMeta, server blank import, and chain registration are wired using the S7/IEC104 terminal-layer pattern. IPv6 refers to the TCP/IP transport addresses while the RFC 4271 BGP Identifier remains a valid IPv4 address.

**Tech Stack:** Go, existing `internal/core`, `internal/core/layers`, `encoding/binary`, `net`, `go test`, `go vet`, `go test -race`.

## Global Constraints

- Scope is BGP only; do not modify unrelated protocol behavior.
- Tests must be written and reviewed before implementation, and the new test must fail before production code exists.
- Default session is OPEN (up), OPEN (down), KEEPALIVE (up), KEEPALIVE (down), KEEPALIVE (up), KEEPALIVE (down); TCP handshake and termination remain owned by the TCP layer.
- Every BGP message uses the 16-byte all-ones marker, a two-byte big-endian total message length, and a one-byte type.
- Supported profile is RFC 4271 IPv4 unicast with two-octet ASN; IPv6 transport is allowed but IPv6 NLRI/MP-BGP capabilities are rejected explicitly.
- UPDATE and NOTIFICATION configuration is rejected explicitly; no silent fallback from unsupported configuration.
- OPEN version must be 4, ASN must fit uint16, hold time is 0..65535, BGP Identifier must be IPv4 and non-zero, marker must be all ones, and message length must be 19..4096.
- No git commit is created.

## Files to change

- Create `internal/protocol/bgp/types.go`: BGP constants and core aliases.
- Create `internal/protocol/bgp/builder.go`: pure OPEN and KEEPALIVE encoders with validation.
- Create `internal/protocol/bgp/planner.go`: protocol validation and legacy packet planner compatibility.
- Create `internal/protocol/bgp/layer_gen.go`: terminal event generator and registration.
- Create `internal/protocol/bgp/bgp_test.go`: exact builder, validation, planner, generator tests.
- Modify `internal/core/types.go`: `BGPConfig`, `FlowSpec.BGP`.
- Modify `internal/core/layers/generator.go`: `FlowMeta.BGP`.
- Modify `internal/core/layers/chain_planner.go`: inject `spec.BGP` into FlowMeta and recognize BGP-specific chain defaults where needed.
- Modify `internal/core/layers/registry.go`: register `bgp` as a TCP terminal layer.
- Modify `internal/core/strategy_convert.go`: decode `bgp` config and default destination port 179.
- Modify `cmd/server/main.go`: blank import BGP and register `NewChainPlanner("bgp")`.

### Task 1: Failing BGP tests

- [ ] Add tests for exact RFC 4271 OPEN bytes, KEEPALIVE length/bytes, IPv6 transport acceptance with IPv4 identifier, and rejection of marker/length/version/ASN/identifier/capability/UPDATE/NOTIFICATION/UDP configurations.
- [ ] Add planner and generator tests asserting TCP direction, event order, exact payloads, and TCP handshake/termination packet shape through the chain.
- [ ] Review the test file for exact offsets and observables.
- [ ] Run `go test ./internal/protocol/bgp`; expect failure because the package/types do not exist.

### Task 2: Core configuration and exact BGP builders

- [ ] Add `BGPConfig` fields: `Version uint8`, `ASN uint32`, `HoldTime uint16`, `Identifier string`, `Marker []byte`, `Length uint16`, `WireProfile string`, `Capabilities []byte`, `Update []byte`, `Notification []byte`.
- [ ] Implement `ValidateConfig` with explicit error text for unsupported profile/features and malformed values.
- [ ] Implement `BuildOpen(*BGPConfig) ([]byte,error)` producing marker + length + type 1 + version + ASN + hold time + IPv4 identifier + opt-param length 0.
- [ ] Implement `BuildKeepalive()` producing 19-byte marker/length/type 4.
- [ ] Review byte layout and bounds.
- [ ] Run focused builder tests, then `go test ./internal/protocol/bgp`.

### Task 3: Planner and terminal layer generator

- [ ] Implement `Planner.Validate` requiring BGP config, TCP transport, defaulting profile/version/ASN/hold/id only in planner copy semantics, and preserving explicit zero hold time.
- [ ] Implement `Planner.Plan` for TCP handshake, OPEN up/down, KEEPALIVE up/down twice, and TCP FIN termination using existing packet conventions.
- [ ] Implement `BGPGenerator.Generate` emitting the same four application events (OPEN each direction, KEEPALIVE twice each direction), with context cancellation and nil checks.
- [ ] Review event order, direction, and no duplicate TCP handshake in terminal generator.
- [ ] Run protocol tests and relevant layer tests.

### Task 4: Chain integration and conversion

- [ ] Add core BGP pointer and FlowMeta field.
- [ ] Add registry schema `bgp` depending on `tcp`.
- [ ] Wire `translateTerminalConfig`/chain metadata and strategy conversion for `bgp`, including port 179 and JSON validation errors.
- [ ] Add BGP blank import and chain planner registration in server.
- [ ] Add integration tests for `NewChainPlanner("bgp")`, IPv4 and IPv6 addresses, exact application payloads, directional TCP four-tuples, and rejection through the production chain.
- [ ] Review all call sites and ensure only BGP files/branches change.

### Task 5: Verification

- [ ] Run `gofmt` on changed Go files.
- [ ] Run code review against the complete diff, checking marker/length/offsets, endian order, direction swapping, IPv4 identifier validation, explicit zero hold time, unsupported feature rejection, and registry/conversion call sites.
- [ ] Run `go vet ./internal/protocol/bgp ./internal/core/... ./cmd/server/...`.
- [ ] Run `go test -race ./internal/protocol/bgp ./internal/core/layers ./internal/core ./cmd/server`.
- [ ] Report tests and any pre-existing failures without committing.

## Self-review

Coverage: builder fields and offsets, all requested negative paths, IPv4/IPv6 transport distinction, event generator and legacy planner, registry/conversion/FlowMeta/server wiring, and end-to-end chain assertions are each mapped to tasks. No placeholders or unresolved type names remain; all introduced interfaces are named in the file list and tasks. The plan intentionally excludes UPDATE/NOTIFICATION wire generation and rejects those configuration fields, satisfying the minimal scope.
