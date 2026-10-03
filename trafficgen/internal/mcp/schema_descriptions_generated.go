// Code generated from trafficgen/schemas/v1 by internal/mcp/schemagen. DO NOT EDIT.
// Descriptions below come from schema title/description fields (single truth).
package mcp

// schema v1/strategy.json flattened title/description table.
var schemaDocsStrategy = map[string]string{
	"":                                  "Strategy: A strategy is one single-protocol traffic template with its own quantity/rate envelope. mode=synth synthesizes packets from config via a planner; mode=replay replays a pcap asset (protocol is informational, real protocols come from the pcap).",
	"/properties/config":                "Strategy config: Synth: flat base fields plus layers array plus protocol sub-maps. Replay: replay spec (pcap_asset_id/speed/direction/checksum_mode).",
	"/properties/config/properties/arp": "ARP options: ARP operation.",
	"/properties/config/properties/arp/properties/operation":      "ARP operation: ARP operation 0-65535.",
	"/properties/config/properties/arp/properties/target_ip":      "Target IP: ARP target protocol address. Format checked by Go validation.",
	"/properties/config/properties/arp/properties/target_mac":     "Target MAC: ARP target hardware address XX:XX:XX:XX:XX:XX. Format checked by Go validation.",
	"/properties/config/properties/checksum_mode":                 "Checksum mode: Replay only: recompute or preserve checksums. Omit to use the engine default recompute; explicit null or other values are rejected (null: omit the key; values: ValidateReplaySpec).",
	"/properties/config/properties/direction":                     "Replay direction: Replay only: single or dual interface. Omit to use the engine default single; explicit null or other values are rejected (null: omit the key; values: ValidateReplaySpec).",
	"/properties/config/properties/dns":                           "DNS options: DNS query/response options.",
	"/properties/config/properties/dns/properties/query_type":     "Query type: DNS query type 0-65535.",
	"/properties/config/properties/dscp":                          "DSCP: DSCP 0-63. Absent = 0x08 (CS1).",
	"/properties/config/properties/dst_ip":                        "Destination IP: Destination IPv4/IPv6 address. Absent = 20.0.0.1 default. Format checked by Go validation (validateConfigNetwork).",
	"/properties/config/properties/dst_mac":                       "Destination MAC: Destination MAC XX:XX:XX:XX:XX:XX. Absent = 02:00:00:00:00:02.",
	"/properties/config/properties/dst_port":                      "Destination port: Destination port 0-65535. Absent = 80 (DNS overrides to 53).",
	"/properties/config/properties/ecn":                           "ECN: ECN 0-3.",
	"/properties/config/properties/file_source":                   "File source: Payload bytes from file/literal/fill/random instead of inline payload.",
	"/properties/config/properties/frag_offset":                   "Fragment offset: Fragment offset 0-8191 in 8-byte units.",
	"/properties/config/properties/group_id":                      "Worker binding: Routes flows with the same generated id to one PacketWorker.",
	"/properties/config/properties/icmp":                          "ICMP options: ICMP type/code/sequence.",
	"/properties/config/properties/icmp/properties/code":          "ICMP code: ICMP code 0-255.",
	"/properties/config/properties/icmp/properties/sequence":      "ICMP sequence: ICMP sequence 0-65535.",
	"/properties/config/properties/icmp/properties/type":          "ICMP type: ICMP type 0-255.",
	"/properties/config/properties/icmpv6":                        "ICMPv6 options: ICMPv6 type/code/sequence.",
	"/properties/config/properties/icmpv6/properties/code":        "ICMPv6 code: ICMPv6 code 0-255.",
	"/properties/config/properties/icmpv6/properties/sequence":    "ICMPv6 sequence: ICMPv6 sequence 0-65535.",
	"/properties/config/properties/icmpv6/properties/type":        "ICMPv6 type: ICMPv6 type 0-255.",
	"/properties/config/properties/ip_flags":                      "IP flags: IP flags 0-7 (DF=0x02 default). Legacy key flags still accepted.",
	"/properties/config/properties/layers":                        "Layer chain: Ordered layer objects outermost (L2) first, innermost application layer last, e.g. [{\"ip\":{}},{\"tcp\":{}},{\"http\":{}}]. Presence switches validation to layer-chain mode; protocol is inferred from the outermost non-scaffolding layer. Per-layer fields follow the layer registry (flowb_query_layers); unknown fields are rejected by Go validation.",
	"/properties/config/properties/pcap_asset_id":                 "Pcap asset id: Replay only: previously imported pcap asset to replay.",
	"/properties/config/properties/speed":                         "Replay speed: Replay only: original pace, multiplier of original, or capped bits per second. Omit to use the engine default; explicit null is rejected (omit the key instead).",
	"/properties/config/properties/speed/properties/bps":          "Speed cap: Bits-per-second cap in bps mode, e.g. 1000 or 1g.",
	"/properties/config/properties/speed/properties/mode":         "Speed mode: original, multiplier, or bps.",
	"/properties/config/properties/speed/properties/multiplier":   "Speed multiplier: Must be > 0 in multiplier mode.",
	"/properties/config/properties/src_ip":                        "Source IP: Source IPv4/IPv6 address. Absent = 10.0.0.1 default. Format checked by Go validation (validateConfigNetwork); the pattern rejects empty shapes only. Layers configs must not carry this key (mixed-use rejected; write ip.src/ip.dst or tcp/udp ports inside layers).",
	"/properties/config/properties/src_mac":                       "Source MAC: Source MAC XX:XX:XX:XX:XX:XX. Absent = 02:00:00:00:00:01.",
	"/properties/config/properties/src_port":                      "Source port: Source port 0-65535. Absent = 12345. Layers configs must not carry this key (mixed-use rejected; write ip.src/ip.dst or tcp/udp ports inside layers).",
	"/properties/config/properties/sub_flows":                     "Secondary flows: Generic secondary flows bound to the primary (FTP data channel, SIP RTP, SCTP multi-homing).",
	"/properties/config/properties/tcp":                           "TCP transport options: TCP transport parameters (any TCP-based protocol). mss splits payloads longer than MSS; initial_seq pins the client ISN for reproducible tests.",
	"/properties/config/properties/tcp/properties/handshake":      "Handshake: Emit TCP handshake.",
	"/properties/config/properties/tcp/properties/initial_seq":    "Initial sequence: Client ISN override, 0 = random.",
	"/properties/config/properties/tcp/properties/mss":            "TCP MSS: MSS 0-65535, 0 = 1460 default.",
	"/properties/config/properties/tcp/properties/retransmit":     "Retransmit: Simulate TCP retransmission.",
	"/properties/config/properties/tcp/properties/rst":            "RST: Abortive RST close instead of FIN.",
	"/properties/config/properties/tcp/properties/termination":    "Termination: Emit TCP teardown.",
	"/properties/config/properties/tcp/properties/window_size":    "Window size: Window 0-65535.",
	"/properties/config/properties/tftp":                          "TFTP options: TFTP mode and option negotiation.",
	"/properties/config/properties/tftp/properties/blksize":       "Block size: Negotiated block size 8-65464.",
	"/properties/config/properties/tftp/properties/error_code":    "Error code: ERROR code 0-8.",
	"/properties/config/properties/tftp/properties/error_side":    "Error side: Which side sends ERROR.",
	"/properties/config/properties/tftp/properties/mode":          "TFTP mode: read = download, write = upload.",
	"/properties/config/properties/tftp/properties/server_tid":    "Server TID: Pinned server transfer port; must be >= 1024 and is rejected when flows > 1 in one strategy.",
	"/properties/config/properties/tftp/properties/timeout":       "Timeout: Retransmit timeout 1-255 seconds.",
	"/properties/config/properties/tftp/properties/transfer_mode": "Transfer mode: netascii or octet; mail is rejected.",
	"/properties/config/properties/tftp/properties/windowsize":    "Window size: Sliding window 1-65535.",
	"/properties/config/properties/tos":                           "TOS byte: Legacy whole-byte TOS 0-255, overrides DSCP/ECN when non-zero.",
	"/properties/config/properties/ttl":                           "TTL: IP TTL 0-255. Absent = 64.",
	"/properties/config/properties/vlan_id":                       "VLAN id: VLAN id 0-4095. Absent = no VLAN tag.",
	"/properties/config/properties/vlan_priority":                 "VLAN priority: VLAN priority 0-7.",
	"/properties/flow_control":                                    "Strategy flow control: This template's own envelope. Absent on synth = flows/1. Replay only accepts time.",
	"/properties/mode":                                            "Strategy mode: synth (default) synthesizes from config; replay replays a pcap asset.",
	"/properties/name":                                            "Strategy name: Human-readable strategy name.",
	"/properties/protocol":                                        "Protocol: Terminal protocol name for synth strategies. Empty when layers infers it; ignored for replay.",
}

// schema v1/task.json flattened title/description table.
var schemaDocsTask = map[string]string{
	"":                          "Task: A task runs one or more strategies (strategy_ids) or one inline batch spec, with its own output routing and an aggregate flow-control ceiling. The task ceiling caps the total without rewriting any strategy envelope.",
	"/properties/batch":         "Batch spec: Inline mixed-traffic batch (multiple protocol classes in one engine task). Either this or strategy_ids, not both.",
	"/properties/flow_control":  "Task flow control: Aggregate ceiling over all strategies/classes. Never rewrites strategy envelopes.",
	"/properties/name":          "Task name: Human-readable task name.",
	"/properties/output_config": "Output configuration: Port group or pcap path matching output_type.",
	"/properties/output_type":   "Output type: port_group sends to wire interfaces; pcap writes a file.",
	"/properties/strategy_ids":  "Strategy ids: Strategies to run together (at least one). Either this or batch, not both.",
}

// schema v1/batch.json flattened title/description table.
var schemaDocsBatch = map[string]string{
	"":                    "Batch spec: Mixed-traffic batch: multiple protocol classes running concurrently in one engine task. Each class carries its own rate, tuple pool, config, and optional replay spec or worker binding.",
	"/properties/classes": "Traffic classes: At least one class; ids must be unique within the batch.",
	"/properties/classes/items/properties/bps":                                           "Class rate: Per-class rate limit, e.g. 200k, 1M.",
	"/properties/classes/items/properties/config":                                        "Class config: Raw per-protocol config map (same flat base as strategy config).",
	"/properties/classes/items/properties/flow_count":                                    "Flow count: Number of flows. Must be > 0 except replay classes.",
	"/properties/classes/items/properties/flows_per_second":                              "Flows per second: Class flow spawn rate.",
	"/properties/classes/items/properties/group_id":                                      "Worker binding: Routes same-id flows of this class to one PacketWorker.",
	"/properties/classes/items/properties/id":                                            "Class id: Unique within the batch.",
	"/properties/classes/items/properties/replay":                                        "Replay spec: Replay classes only: pcap_asset_id/speed/direction/checksum_mode.",
	"/properties/classes/items/properties/replay/properties/checksum_mode":               "Checksum mode: recompute or preserve checksums. Omit to use the engine default recompute; explicit null is rejected (omit the key instead).",
	"/properties/classes/items/properties/replay/properties/direction":                   "Replay direction: single or dual interface. Omit to use the engine default single; explicit null is rejected (omit the key instead).",
	"/properties/classes/items/properties/replay/properties/pcap_asset_id":               "Pcap asset id: Previously imported pcap asset to replay.",
	"/properties/classes/items/properties/replay/properties/speed":                       "Replay speed: original pace, multiplier, or bps cap.",
	"/properties/classes/items/properties/replay/properties/speed/properties/bps":        "Speed cap: Bits-per-second cap in bps mode.",
	"/properties/classes/items/properties/replay/properties/speed/properties/mode":       "Speed mode: original, multiplier, or bps.",
	"/properties/classes/items/properties/replay/properties/speed/properties/multiplier": "Speed multiplier: Must be > 0 in multiplier mode.",
	"/properties/classes/items/properties/tuples":                                        "Tuple pool: Four-tuple generation pool for this class.",
	"/properties/classes/items/properties/type":                                          "Class protocol: Protocol name, or replay for pcap replay classes.",
	"/properties/global":                             "Global batch settings: Batch-wide totals and duration.",
	"/properties/global/properties/duration_seconds": "Duration seconds: Batch-wide duration in seconds.",
	"/properties/global/properties/total_flows":      "Total flows: Batch-wide flow total.",
}

// schema v1/defs.json flattened title/description table.
var schemaDocsDefs = map[string]string{
	"":                                     "Shared definitions: Shared strategy/task/batch building blocks: flow control, output routing, per-flow dynamic values, tuple pools, worker binding. Single truth for these shapes; REST, MCP and frontend descriptions derive from here.",
	"/$defs/dynamic_value":                 "Per-flow dynamic value: How a per-flow field varies across flows of one template. Flow i resolves deterministically (rand uses seed+i, wraps at range end). Matches StrategyConfig semantics in internal/core (tuple_generator.go, shard_router.go).",
	"/$defs/dynamic_value/properties/list": "Rotation list: Entries rotated per flow for list strategy.",
	"/$defs/dynamic_value/properties/pattern":       "Pattern template: Template with {n} placeholder for pattern strategy.",
	"/$defs/dynamic_value/properties/range":         "Value range: Inclusive [start, end] for inc/rand/pattern strategies.",
	"/$defs/dynamic_value/properties/seed":          "Random seed: Seed for rand strategy; same seed+index yields the same value.",
	"/$defs/dynamic_value/properties/step":          "Increment step: Step for inc strategy. Non-positive falls back to 1.",
	"/$defs/dynamic_value/properties/strategy":      "Variation strategy: fixed = constant, inc = step through range, rand = seeded random in range, list = rotate entries, pattern = substitute {n} from range.",
	"/$defs/dynamic_value/properties/value":         "Fixed value: Constant for fixed strategy (string, number, or boolean).",
	"/$defs/flow_control":                           "Flow control: Quantity or rate envelope. Strategy level sets the template's own envelope; task level caps the aggregate without rewriting strategies.",
	"/$defs/flow_control/properties/type":           "Flow control type: flows = flow count, bps = bits per second, time = seconds.",
	"/$defs/flow_control/properties/value":          "Flow control value: Flow count, bits per second, or seconds. Must be positive.",
	"/$defs/group_id":                               "Worker binding: Routes flows with the same generated id to one PacketWorker, preserving cross-flow timing (e.g. signaling plus data). Same dynamic_value semantics.",
	"/$defs/output_config":                          "Output configuration: Where generated packets go: a port group for wire replay, or a pcap file. interface2 enables dual-port replay.",
	"/$defs/output_config/properties/interface2":    "Second interface: Second interface for dual-port replay.",
	"/$defs/output_config/properties/pcap_path":     "Pcap path: Pcap file path (output_type=pcap).",
	"/$defs/output_config/properties/port_group_id": "Port group id: Port group for wire output (output_type=port_group).",
	"/$defs/tuple_config":                           "Tuple pool: Four-tuple generation pool for batch classes. Each endpoint accepts a static value or a dynamic_value object.",
	"/$defs/tuple_config/properties/dst_ip":         "Destination IP pool: Destination IPv4 pool: static address or dynamic_value.",
	"/$defs/tuple_config/properties/dst_port":       "Destination port pool: Destination port pool: static 0-65535 or dynamic_value.",
	"/$defs/tuple_config/properties/src_ip":         "Source IP pool: Source IPv4 pool: static address or dynamic_value.",
	"/$defs/tuple_config/properties/src_port":       "Source port pool: Source port pool: static 0-65535 or dynamic_value.",
}

// schema v1/layers.json flattened title/description table.
var schemaDocsLayers = map[string]string{
	"": "Layer chain: Layer-chain shape rules: ordered single-key objects, outermost (L2) first. Chain semantics (completion, inference, per-field values) are owned by Go (layers.ValidateLayers); per-layer field tables come from generated/layers.generated.json (registry dump, never hand-written). Layer fields accept a scalar (static) or a dynamic_value object (per-flow dynamic) on the allowlisted four-tuple-ish fields (ip.src/ip.dst, tcp/udp src_port/dst_port, eth src_mac/dst_mac, ip.ttl); other fields take scalars only. Flat four-tuple keys alongside layers are rejected.",
}

// schemaConfigBlurb is the Config-field help shared by strategy and
// workflow tools. Assembled from schema docs; every hint below is
// asserted by internal/mcp/tools_schema_test.go — do not trim.
const schemaConfigBlurb = "strategy config. " +
	"layer-chain is the only accepted format (flat config is gone): {\"layers\":[{\"ip\":{\"src\":\"10.0.0.1\",\"dst\":\"20.0.0.1\"}}," +
	"{\"udp\":{\"dst_port\":53}},{\"dns\":{\"name\":\"a.com\"}}],\"flow_control\":{\"type\":\"flows\",\"value\":1}} — " +
	"ordered layers, outermost (L2/L3) first; protocol inferred from outermost non-scaffolding layer, " +
	"explicit protocol must match. " +
	"Only schema-declared fields accepted: unknown fields rejected (all reported at once), " +
	"hard depends_on auto-completed. " +
	"ALWAYS call flowb_query_layers action=examples for the target protocol BEFORE composing a config — " +
	"it returns verified copy-paste examples (field names like ip.src / http.response_status_code " +
	"come from there, do not guess); action=schema lists fields/types/defaults/depends_on. " +
	"Top-level src_ip/dst_ip/src_port/dst_port/count are rejected (flat config is gone). " +
	"group_id {strategy,value/range/list/step/seed/pattern}: fixed/inc/rand/pattern/list " +
	"bind same-id flows to one worker."
