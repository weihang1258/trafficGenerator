# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
