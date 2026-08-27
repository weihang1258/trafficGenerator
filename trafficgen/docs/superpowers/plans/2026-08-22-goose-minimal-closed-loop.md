# IEC 61850 GOOSE Minimal Closed Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal IEC 61850 GOOSE generator that emits one boolean `allData` member in direct Ethernet frames with EtherType `0x88B8`, and wire it through strategy conversion, layer-chain planning, and server registration.

**Architecture:** GOOSE is a Layer 2 terminal protocol. The planner emits complete GOOSE payload bytes in `PacketConfig.Payload`; the core builder treats `0x88B8` as a non-IP EtherType and writes Ethernet/VLAN plus payload without an IPv4/IPv6 header. The layer registry contains an `eth` scaffold and `goose` terminal; the protocol package registers a layer generator and validator through the existing reverse-registration API.

**Tech Stack:** Go, `encoding/binary`, BER-style TLV encoding, existing core layer-chain and planner APIs, Go test/vet/race.

## Global Constraints

- Implement GOOSE only; do not modify OPC UA or unrelated protocols.
- GOOSE must not depend on IPv4, IPv6, TCP, or UDP; invalid IP-layer use is rejected.
- Wire EtherType is `0x88B8`; APPID is in the GOOSE range `0x0000..0x3FFF`.
- The supported `allData` set is exactly one boolean member; other member types are rejected.
- Every code change is reviewed before tests; after fixes, repeat review and tests.
- Do not commit changes.

### Task 1: Core Ethernet and configuration contracts

**Files:**
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/builder.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/types.go`
- Test: `/home/weihang/trafficGenerator/trafficgen/internal/core/builder_goose_test.go`

- [ ] Define `EtherTypeGOOSE = 0x88B8` beside the existing Ethernet constants.
- [ ] Ensure `Builder.Build` treats `0x88B8` like ARP as direct Ethernet payload and never allocates/writes an IP header.
- [ ] Add `GOOSE *GOOSEConfig` to `FlowSpec`; define fields for APPID, GOCB reference, dataset, TAL, confRev, stNum, sqNum, test, ndsCom, boolean value, count/retransmit mode, destination MAC, and optional VLAN controls.
- [ ] Keep `L3Config` ignored for GOOSE and reject non-empty IP-layer use in the GOOSE planner/validator rather than fabricating an IP packet.
- [ ] Run `PATH=/home/weihang/go/go/bin:$PATH go test ./internal/core -run 'TestBuilder_GOOSE' -count=1`; expected initial failure is resolved after implementation.

### Task 2: GOOSE BER/APDU builder and planner tests first

**Files:**
- Create: `/home/weihang/trafficGenerator/trafficgen/internal/protocol/goose/builder.go`
- Create: `/home/weihang/trafficGenerator/trafficgen/internal/protocol/goose/planner.go`
- Test: `/home/weihang/trafficGenerator/trafficgen/internal/protocol/goose/goose_test.go`

- [ ] Add failing tests for exact Ethernet payload layout: APPID, GOOSE length, reserved fields, APDU tag `0x61`, GOCBRef, timeAllowedToLive, datSet, goID, timestamp, test/ndsCom, confRev, stNum, sqNum, numDatSetEntries, and one boolean `allData` member.
- [ ] Add failing tests for BER short/long lengths, boolean true/false encoding, invalid APPID, zero/overflow TAL/confRev, invalid control-block strings, unsupported data type, and APDU/payload length overflow.
- [ ] Add failing tests for packet direction and destination multicast MAC `01:0c:cd:01:02:03`, VLAN offset propagation, and explicit rejection of IPv4/IPv6 chains.
- [ ] Implement minimal BER helpers with bounds checks, GOOSE header encoding, and `Planner.Validate`/`Planner.Plan`; emit finite frames according to `spec.Count`, with deterministic state counters and no retransmit sequence gaps.
- [ ] Make planner output L2-only `PacketConfig` values with EtherType `core.EtherTypeGOOSE`, empty/unused L3/L4, payload containing the GOOSE header and APDU, and direction metadata.

### Task 3: Layer-chain generator and registry

**Files:**
- Create: `/home/weihang/trafficGenerator/trafficgen/internal/protocol/goose/layer_gen.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/layers/registry.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/layers/generator.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/layers/chain_planner.go`
- Test: `/home/weihang/trafficGenerator/trafficgen/internal/core/layers/chain_planner_goose_test.go`

- [ ] Register `goose` as a terminal layer with no IP/transport dependency; allow `eth` as the required outer scaffold and preserve VLAN when supplied.
- [ ] Add a production generator factory path through `RegisterLayerGenerator("goose", ...)` and expose GOOSE in `FlowMeta`.
- [ ] Drive the GOOSE generator as a direct packet producer, bypassing TCP/UDP event wiring, and make final emission retain L2 EtherType/MAC/VLAN while not swapping multicast destination into a bogus unicast address.
- [ ] Add chain tests for `[eth, goose]`, `[goose]` completion behavior, generator registration, generated packet fields, and rejection of `[ip, goose]` / `[tcp, goose]`.

### Task 4: Strategy conversion, validation, and server registration

**Files:**
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/strategy_convert.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/convert.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/internal/core/validate.go`
- Modify: `/home/weihang/trafficGenerator/trafficgen/cmd/server/main.go`
- Test: `/home/weihang/trafficGenerator/trafficgen/internal/core/convert_goose_test.go`
- Test: `/home/weihang/trafficGenerator/trafficgen/internal/core/strategy_convert_goose_test.go`

- [ ] Add `goose` to synth and batch protocol allowlists and conversion protocol lists.
- [ ] Parse the `goose` map into `GOOSEConfig` without truncating invalid numeric input before validation.
- [ ] Validate APPID range, required GOCB/dataset references, TAL/control-block bounds, supported boolean data type, and absence of IP/transport config.
- [ ] Import the GOOSE package and register `layers.NewChainPlanner("goose")` in `initEngine`.
- [ ] Add conversion and server-registration tests that assert the actual generated packet, not only non-nil config.

### Task 5: Full review and verification

**Files:**
- Review all changed files above in context.

- [ ] Walk every byte offset and length calculation, including VLAN/non-VLAN header offsets, long-form BER lengths, reserved fields, and minimum Ethernet padding.
- [ ] Run `gofmt` on every changed Go file.
- [ ] Run `PATH=/home/weihang/go/go/bin:$PATH go vet ./internal/core/... ./internal/protocol/goose/... ./cmd/server/...`.
- [ ] Run `PATH=/home/weihang/go/go/bin:$PATH go test ./internal/core/... ./internal/protocol/goose/... ./cmd/server/... -count=1`.
- [ ] Run `PATH=/home/weihang/go/go/bin:$PATH go test -race ./internal/core/... ./internal/protocol/goose/... ./cmd/server/... -count=1`.
- [ ] If review or tests expose a defect, write a reproducing failing test first, fix it, re-review, and rerun the complete relevant verification.
