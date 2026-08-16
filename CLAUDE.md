# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Modification & Review Policy (Mandatory)

**Any code modification MUST be followed by a code review before considering the work done.** This is a binding workflow rule, not a suggestion:

1. **After writing/changing code → review the changed code first.** Do not jump straight to testing. Review the diff for correctness, newly introduced bugs (races, deadlocks, double-close, nil deref, off-by-one), missed call sites/edge cases, regressions, and resource leaks. Read the actual changed files in context, not just the diff.
2. **Then run tests.** Build, vet, and run the relevant test suite (including `-race`).
3. **If tests or review find bugs → fix them → review the fix.** Every bug fix is itself a code modification, so it must be reviewed too (a fix can introduce a new bug). Repeat the review→test→fix→review loop until clean.
4. **In short: every code change — feature, fix, or refactor — must be reviewed.** No exceptions for "small" or "obvious" changes.

5. **Sub-agent completion definition (Mandatory)**: For code-generation and code-modification sub-agents, the task is NOT complete when the code is written or fixed. The agent MUST, after making all changes, immediately self-review (walkthrough) its own changed code — line-by-line checks of offsets, byte order, boundary conditions, field layouts, and impact on call sites — and fix any issues found, then re-review, looping until the self-review passes clean. The final report MUST include the self-review conclusion ("passed N rounds, last round clean"). This applies to every fix round, not just the first. Independent walkthrough review agents (read-only) run separately afterward.

For non-trivial changesets, prefer a thorough review: parallel reviewers per changed area + adversarial verification of each finding (try to refute it by reading the actual code; default to "not a bug" if uncertain or if the behavior is intentional/by-design). Report confirmed issues ranked by severity, then fix and re-verify.

## Testing Policy (Mandatory)

**Tests must be derived from the spec and must actually cover the behavior they claim to--not merely pass.** This is a binding workflow rule, not a suggestion. It exists because a prior changeset shipped with 178 tests green and a 4-way adversarial code review clean, yet a follow-up spec-vs-implementation audit found 33 issues (7 CRITICAL). The tests passed because they tested the wrong thing. The rules below prevent a repeat.

### 1. Spec-driven test derivation, not ad-hoc

Every table, field list, and error-handling row in the design spec is a test-case checklist. Before writing tests, enumerate the spec sections that cover the changed code and convert each row/field into at least one test. **Do not write tests organically ("I can test this feature"); write them from the spec ("§X requires behavior Y on row Z, so I need a test for it").** Concrete anti-patterns that bit us: a FlowModel with 28 spec fields where 6 (RetransCount, MSS, WindowScale, ...) had zero tests and stayed silently zero-valued forever; an error-handling table with 10 rows where only 1 was tested.

### 2. Cover failure paths, not just the happy path

Every feature needs both a success test AND negative-path tests: invalid input, missing/unready dependency, broken mid-operation state, empty/zero/boundary values. **A test that only feeds valid input through the success path is incomplete.** Anti-patterns that bit us: the fragmented-TCP test always established the flow with a non-fragmented handshake first, so the fully-fragmented-flow case (where the first packet is a fragment) was never exercised; the ipmap test used exact-match keys only, so CIDR keys were never tested; every e2e test asserted "task does not fail" but none injected a broken spec to verify the task *does* fail when it should--so a planner error that got silently swallowed (task reported "completed" with 0 packets) passed every test.

### 3. Test the right function/scope--one test per code path

When a feature spans multiple functions or methods, each path needs its own test. **Do not test function A and assume function B works because they are "related".** Anti-patterns that bit us: CIDR was tested in the matcher (`matchRule`) but not in the ipmap rewriter (a different function) -- the rewriter's CIDR path was unimplemented and no test caught it; user-isolation was tested for `GetAssetByHash` only, leaving 10 other Get/List methods with no `WHERE user_id` clause untested; `apply:offset` semantics were declared on a rule field but never read, and no test ever set `apply:"offset"`. If a method/branch exists, it needs a test that exercises it.

### 4. Integration tests, not just unit tests

Units passing in isolation does not prove the feature works end-to-end. **For any feature spanning layers (API -> engine -> output, or planner -> worker -> writer), add a test that drives the full path.** Anti-patterns that bit us: `RegisterDualWriter` was tested by calling it directly on the engine, but the production path (task handler -> engine) never called it, so dual-port output was dead code that passed its test; `Plan()` correctly returned an error, but no test verified that error propagated through the pipeline to fail the task; every test used `PacketWorkers: 1` so the default `PacketWorkers: 8` file-ordering bug was never hit.

### 5. Assert observable outcomes, not just structure

Tests must assert output values and observable behavior, not merely "it didn't panic" or "the object exists." **A field that is never populated stays at its zero value and passes any structural assertion.** Anti-patterns that bit us: TCP-stat fields (RetransCount, MSS, WindowScale) were never asserted non-zero, so the code that forgot to populate them passed; the pacer concurrency test checked `-race` was clean (no data race) but never measured the actual aggregate rate, so 8 workers each sleeping independently (8x the configured rate) passed.

### 6. Concurrency tests must verify correctness, not just race-safety

`-race` clean means no data race; it does NOT mean the logic is correct under concurrency. **For any shared-state or shared-rate component, write a test that measures the aggregate observable behavior under N concurrent workers** (e.g., actual total throughput vs configured rate, actual ordering vs expected ordering). Anti-pattern: a shared Pacer across workers had a correct mutex (no race) but no mutual exclusion on the rate-defining sleep, so total throughput scaled with worker count.

### 7. Failing-test-first for every bug fix

When fixing a bug (from review, audit, or report), **write a failing test that reproduces the bug FIRST, then fix the code so the test passes.** This proves the fix covers the bug and guards against regression. Do not fix-then-hope. If you cannot write a failing test, you do not understand the bug yet.

### 8. Adversarial review of test quality (not just code quality)

When reviewing, do not stop at "tests pass." For each test, ask: Does it test the right code path? What input would break this that the test does not feed? Does it assert the outcome or just the setup? Is there a spec row/field this test does not correspond to? **A green suite that tests the wrong things is worse than no tests--it creates false confidence.** Treat test coverage as a first-class review dimension alongside correctness.

## Project Overview

This is a **high-performance network traffic generator** implemented as a single Python file (`high_performance_traffic_generator.py`, ~2336 lines). It uses a multiprocessing pipeline architecture to generate TCP/UDP/HTTP traffic with precise rate control and memory efficiency.

## Core Architecture

### Multiprocess Pipeline Design

The system uses a **strict pipeline architecture** with the following stages:

```
Main Process (API/Control)
    ↓ (task submission)
Config Generator Processes (producers)
    ↓ (packet configs via Queue)
Packet Builder Processes (consumer/producer)
    ↓ (Ethernet frames via Queue)
Collector Thread (resequencer)
    ↓ (ordered packets)
Ring Buffers (up/down/combined)
    ↓ (API retrieval)
```

**Critical Constraints:**
- **Streaming only**: All generation uses Python generators (yield). Never aggregate all packets in memory.
- **Bounded queues**: All inter-process queues have `maxsize` to prevent unbounded memory growth.
- **Process isolation**: Config generation and packet building are completely independent processes, communicating only via queues.
- **Windows compatibility**: Uses `multiprocessing.Process` with top-level functions (not lambdas) for Windows spawn compatibility.

### Key Classes and Responsibilities

1. **HighPerformanceTrafficGenerator** (line 603): Main controller
   - Manages the entire pipeline
   - Provides `submit_*()` methods for async task submission
   - Provides `get_packets()` for batch retrieval
   - Maintains three buffer views: up/down/combined

2. **ConfigGenerator** (line 484): Manages config generation processes
   - Workers run `config_worker_main()` (line 359)
   - Converts flow specs into packet-level configs
   - Uses streaming generators (never aggregates)

3. **PacketBuilder** (line 543): Manages packet construction processes
   - Workers run `packet_worker_main()` (line 449)
   - Converts configs to binary Ethernet frames
   - Applies rate limiting per class

4. **PacketBuffer** (line 249): Ring buffer with overflow protection
   - Bounded size (count and/or bytes)
   - Returns False on overflow (triggers fatal error)
   - Thread-safe with locks

5. **SharedTokenBucket** (line 29): Cross-process rate limiter
   - Uses `multiprocessing.Value` for shared state
   - Byte-level token bucket algorithm
   - Per-class rate limiting

### Protocol Flow Planning

Each protocol has a planning function that yields packet configs:

- **TCP**: `plan_tcp_flow_packet_configs_iter()` (line 1132)
  - Full handshake → data segments → termination
  - Automatic MSS-based segmentation
  - Bidirectional ACK handling

- **UDP**: `plan_udp_flow_packet_configs_iter()` (line 1308)
  - Simple request/response pattern

- **HTTP**: `plan_http_sessions_iter()` (line 1428)
  - TCP handshake → multiple HTTP transactions → TCP termination
  - Supports keep-alive with think_time between transactions

### Packet Construction Flow

`build_packet_from_config_static()` (line 1078) constructs frames bottom-up:
1. L4 header (TCP/UDP with pseudo-header checksum)
2. L3 header (IPv4 with auto-checksum)
3. L2 header (Ethernet with optional VLAN)
4. Concatenate: Eth + IP + L4 + Payload

## Configuration Patterns

### Strategy Pattern for Variable Parameters

All variable parameters (IPs, ports, HTTP headers, etc.) use a strategy pattern:

```python
# Fixed value
{'strategy': 'fixed', 'value': 80}

# Increment with wrap
{'strategy': 'inc', 'range': [1, 100], 'step': 1}

# Random (reproducible with seed)
{'strategy': 'rand', 'range': [1024, 65535], 'seed': 42}

# Pattern with increment
{'strategy': 'pattern', 'pattern': 'user{n}', 'n_range': [1, 1000]}

# List selection
{'strategy': 'list', 'list': ['GET', 'POST']}
```

Key generator classes:
- `ValueCycler` (line 1677): Increment with wrap
- `ValueRandom` (line 1693): Random with optional seed
- `TupleGenerator` (line 1704): Generates 4-tuples (src_ip, dst_ip, sport, dport)

### Memory-Optimized Body Generation

`BodyGenerator` (line 1774) uses a **mixed strategy** to minimize memory:

```python
'body': {
    'strategy': 'mixed',
    'parts': [
        {'type': 'static', 'content': '{"id":'},      # Cached once
        {'type': 'increment', 'pattern': '{n}', ...}, # Dynamic
        {'type': 'static', 'content': '}'}            # Cached once
    ]
}
```

- Static parts are cached by content hash (deduplication)
- File contents are cached
- Only dynamic parts are generated per-packet

## Running the Code

### Basic Usage

```python
from high_performance_traffic_generator import HighPerformanceTrafficGenerator

# Create and start
hptg = HighPerformanceTrafficGenerator(
    config_processes=2,
    packet_processes=2,
    buffer_size=2048
)
hptg.start()

# Submit flows (async)
hptg.submit_tcp_flow(flow_spec, count=20)
hptg.submit_http_sessions(http_spec, count=30)

# Retrieve packets
packets = hptg.get_packets(100, mode='combined')

# Stop
hptg.stop()
```

### Batch Mixed Traffic

```python
batch_spec = {
    'classes': [
        {
            'id': 'tcp_bulk',
            'type': 'tcp',
            'bps': '200k',  # Rate limit
            'tuples': {...},
            'tcp': {...}
        }
    ],
    'flows': {'count': 100}
}

runner = hptg.start_batch_mixed(batch_spec)
status = runner.get_status()
runner.stop()
```

## Important Design Patterns

### Resequencing (line 719)

Multi-process packet building can cause out-of-order delivery. The `_resequencer_accept()` method:
- Tracks expected packet_index per flow_id
- Buffers out-of-order packets in `_seq_hold`
- Releases packets in order (cascade when gap is filled)
- Drops duplicate/late packets

### Overflow Protection

When `PacketBuffer.put()` returns False (buffer full):
1. Sets `_fatal_error_message`
2. Stops the entire pipeline
3. Raises `BufferOverflowError` in collector thread

This prevents silent data loss. Users must:
- Increase `buffer_size`
- Reduce submission rate
- Add `count` limits to flows
- Disable unused buffer views

### Rate Limiting

Per-class rate limiting via `set_class_rate_limit(class_id, bps)`:
- Shared `SharedTokenBucket` across all packet processes
- Byte-level granularity (not packet-level)
- Supports burst (default 65536 bytes)
- Parse bps strings: '200k', '100M', '1g'

## Key Constraints to Maintain

1. **Never aggregate in memory**: Always use generators (yield) for streaming
2. **Bounded queues**: Always set `maxsize` on multiprocessing.Queue
3. **Top-level functions**: Process entry points must be top-level (not nested) for Windows
4. **No shared mutable state**: Processes communicate only via queues
5. **Graceful shutdown**: Call `runner.stop()` before `hptg.stop()` to drain queues

## Testing Considerations

When testing or modifying:
- Use small `count` values to limit packet generation
- Monitor `get_buffer_status()` to avoid overflow
- Use `directionless=True` to write to combined buffer only
- Set `seed` in random strategies for reproducibility
- Check `_fatal_error_message` for pipeline failures

## Common Modifications

- **Add new protocol**: Create `plan_*_iter()` generator and add submit method
- **Add new strategy**: Implement in parameter generators section (line 1677+)
- **Custom L2/L3**: Modify `build_packet_from_config_static()` and header builders
- **Change buffer policy**: Adjust `enable_*_buffer` flags and `store` metadata field
