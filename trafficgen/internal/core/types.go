// Package core provides core data structures for the traffic generator.
package core

import (
	"context"
	"encoding/json"
	"time"
)

// Task represents a traffic generation task.
type Task struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id,omitempty"` // owning user (for user-scoped asset access during replay)
	Protocol    string                 `json:"protocol"` // tcp, udp, http, dns, icmp, arp
	Spec        FlowSpec               `json:"spec"`     // single-protocol mode
	Batch       *BatchSpec             `json:"batch,omitempty"` // mixed-traffic mode (Spec XOR Batch)

	// Mode selects the source of packet configs. "synth" (default) synthesizes
	// packets from Spec via a planner. "replay" replays a recorded pcap via the
	// registered ReplayPlanner; the pcap's own protocols populate the wire bytes
	// (Protocol is informational). Replay and synth share the same task-level
	// flow-control ceiling (bps/flows/time) -- no exceptions.
	Mode string `json:"mode,omitempty"`

	// Replay holds the raw ReplaySpec JSON for Mode=="replay" tasks, passed
	// verbatim to ReplayPlanner.PlanReplay. Not used for synth mode.
	Replay json.RawMessage `json:"replay,omitempty"`

	ClassID     string                 `json:"class_id"`
	Interface   string                 `json:"interface"`   // output interface name (client side / primary)
	Interface2  string                 `json:"interface2,omitempty"` // server side (dual-port replay); empty = single
	OutputMode  string                 `json:"output_mode"` // interface, pcap, both
	PcapFile    string                 `json:"pcap_file,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// ParentTaskID is the REST-level task ID (parent) that owns this engine
	// task. A multi-strategy task spawns one engine task per strategy, each
	// sharing the same ParentTaskID. It keys the task-level flow-control
	// ceiling (parent rate-limiter bucket + shared flow counter).
	ParentTaskID string `json:"parent_task_id,omitempty"`

	// TaskFCType/TaskFCValue carry the task-level flow-control ceiling
	// (from TaskModel.FlowControl). Empty TaskFCType = no task-level ceiling.
	// Type is "bps" (parent bucket), "flows" (shared counter), or "time"
	// (parent context deadline). Unlike strategy-level FC, this does NOT
	// override the per-strategy spec; it caps the aggregate.
	TaskFCType  string  `json:"task_fc_type,omitempty"`
	TaskFCValue float64 `json:"task_fc_value,omitempty"`

	Ctx context.Context `json:"-"` // per-task context for cancellation
}

// TaskStatus represents the current status of a task.
type TaskStatus struct {
	TaskID      string    `json:"task_id"`
	Status      string    `json:"status"` // created, running, paused, completed, failed
	Progress    float64   `json:"progress"`
	Stats       TaskStats `json:"stats"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// TaskStats contains runtime statistics for a task.
type TaskStats struct {
	PacketsSent   int64   `json:"packets_sent"`
	BytesSent     int64   `json:"bytes_sent"`
	FlowsCount    int     `json:"flows_count"`
	CurrentPPS    float64 `json:"current_pps"`
	CurrentBPS    float64 `json:"current_bps"`
	PacketsFailed int64   `json:"packets_failed"`
}

// FlowSpec defines the specification for a traffic flow.
type FlowSpec struct {
	// Four-tuple
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`

	// L2 configuration
	SrcMAC string `json:"src_mac,omitempty"`
	DstMAC string `json:"dst_mac,omitempty"`
	VLAN   *VLAN  `json:"vlan,omitempty"`

	// L3 configuration
	TTL uint8 `json:"ttl,omitempty"`
	TOS uint8 `json:"tos,omitempty"` // legacy whole-byte TOS (overrides DSCP/ECN if non-zero)

	// DSCP/ECN and fragmentation (L3). When set, flow-level and applied to
	// every packet in the flow.
	DSCP       uint8  `json:"dscp,omitempty"`
	ECN        uint8  `json:"ecn,omitempty"`
	Flags      uint8  `json:"flags,omitempty"`       // IPFlagDF / IPFlagMF
	FragOffset uint16 `json:"frag_offset,omitempty"`

	// Protocol specific configuration
	TCP     *TCPConfig     `json:"tcp,omitempty"`
	UDP     *UDPConfig     `json:"udp,omitempty"`
	HTTP    *HTTPConfig    `json:"http,omitempty"`
	DNS     *DNSConfig     `json:"dns,omitempty"`
	ICMP    *ICMPConfig    `json:"icmp,omitempty"`
	ARP     *ARPConfig     `json:"arp,omitempty"`
	FTP     *FTPConfig     `json:"ftp,omitempty"`
	SIP     *SIPConfig     `json:"sip,omitempty"`
	SCTP    *SCTPConfig    `json:"sctp,omitempty"`
	ICMPv6  *ICMPv6Config  `json:"icmpv6,omitempty"`

	// Common configuration
	Payload  []byte `json:"payload,omitempty"`
	Count    int    `json:"count,omitempty"`
	Duration int    `json:"duration,omitempty"` // seconds
	BPS      string `json:"bps,omitempty"`     // rate limit, e.g., "200k", "1M"

	// InitialSeq overrides the random initial sequence number for TCP flows.
	// 0 = random per flow (default, RFC 6528 ISN randomization). Non-zero
	// forces a deterministic client ISN for reproducible tests.
	InitialSeq uint32 `json:"initial_seq,omitempty"`

	// GroupID routes flows with the same generated id to one PacketWorker,
	// preserving cross-flow timing (e.g. SIP signaling + RTP data). nil/empty =
	// fall back to unordered 4-tuple hash (single-flow ordering only).
	GroupID *StrategyConfig `json:"group_id,omitempty"`

	// PadMinFrame controls Ethernet padding to the minimum frame size (60
	// bytes, excluding FCS per IEEE 802.3). nil = padding ON (default —
	// short frames like ARP or small ICMP are padded to 60 bytes so real
	// NICs don't reject them); false = padding OFF (frame emitted at its
	// natural size, useful for testing how a DUT handles runt frames);
	// true = padding ON (explicit).
	//
	// The 60-byte threshold is fixed (standard Ethernet minimum). Padding
	// bytes are zero-filled and appended AFTER the L3/L4 payload — the IP
	// total-length field reflects only the actual payload, so receivers
	// strip padding based on IP total length.
	PadMinFrame *bool `json:"pad_min_frame,omitempty"`
}

// VLAN configuration.
type VLAN struct {
	ID       uint16 `json:"id"`
	Priority uint8  `json:"priority"`
}

// TCPConfig for TCP protocol.
type TCPConfig struct {
	Handshake   bool   `json:"handshake"`
	Termination bool   `json:"termination"`
	MSS         uint16 `json:"mss"`
	WindowSize  uint16 `json:"window_size"`
	Flags       uint8  `json:"flags"`
	Seq         uint32 `json:"seq,omitempty"`
	Ack         uint32 `json:"ack,omitempty"`
}

// UDPConfig for UDP protocol.
type UDPConfig struct {
	Response bool `json:"response"`
}

// HTTPConfig for HTTP protocol.
//
// Field defaulting follows a single rule for every output field
// (request line, status line, and headers):
//
//	user-provided value > derived default > not emitted
//
// User-provided headers live in RequestHeaders / ResponseHeaders and are
// matched case-insensitively (RFC 7230 §3.2). When a header is present in
// the user map, the corresponding default is NOT also emitted (preventing
// duplicate Host / Content-Length / Connection headers).
type HTTPConfig struct {
	Method       string            `json:"method"`
	URI          string            `json:"uri"`
	Version      string            `json:"version"` // empty -> "HTTP/1.1"
	RequestHeaders map[string]string `json:"request_headers"`
	Body         string            `json:"body"`
	KeepAlive    bool              `json:"keep_alive"`
	Transactions int               `json:"transactions"`
	ThinkTime    int               `json:"think_time"` // milliseconds

	// Response-side fields. ResponseHeaders overrides generated defaults
	// (Content-Type/Content-Length/Connection). ResponseBody empty -> no
	// Content-Length, no Content-Type default. ResponseStatusCode 0 -> 200.
	// ResponseStatusText empty -> looked up from ResponseStatusCode.
	//
	// ContentEncoding, when set to "gzip", compresses ResponseBody with gzip
	// before framing. Content-Length reflects the compressed byte count, and
	// a "Content-Encoding: gzip" header is emitted (overridable via
	// ResponseHeaders, case-insensitive). Empty/unset -> no compression.
	//
	// MSS governs response (and request) segmentation: payloads longer than
	// MSS are split into multiple TCP segments (each PSH-ACK), so a 3066-byte
	// HTTP response over MSS=1460 becomes 3 segments (1460+1460+146). 0 ->
	// DefaultMSS (1460). The SYN/SYN-ACK carry this MSS as a TCP option.
	ResponseHeaders     map[string]string `json:"response_headers"`
	ResponseBody        string            `json:"response_body"`
	ResponseStatusCode  int               `json:"response_status_code"`
	ResponseStatusText  string            `json:"response_status_text"`
	ContentEncoding     string            `json:"content_encoding"`
	MSS                 uint16            `json:"mss"`
}

// DNSConfig for DNS protocol.
type DNSConfig struct {
	Domain     string `json:"domain"`
	QueryType  uint16 `json:"query_type"` // A=1, AAAA=28
	Response   bool   `json:"response"`
	ResponseIP string `json:"response_ip,omitempty"`
}

// ICMPConfig for ICMP protocol.
//
// Per RFC 792, an Echo Request/Reply carries two separate 16-bit fields:
// Identifier (bytes 4-5) and Sequence (bytes 6-7). Identifier groups pings
// into a session; Sequence increments per ping within that session.
//
// Backward compatibility: when Identifier == 0, buildICMPPayload falls back
// to using Sequence as the Identifier (the pre-field behavior wrote Sequence
// to both positions). Callers that want distinct values must set Identifier
// to a non-zero value.
//
// Pattern (Task #51): when non-empty, the planner iterates the steps and
// emits each as a separate ping within the same flow (multi-session ping).
// Each step carries its own Type/Code/Sequence; the planner auto-fills
// Identifier from the top-level field (or falls back to Sequence per the
// rule above). An empty Pattern falls back to the legacy single-ping path
// (request + auto-reply) so existing configs keep working unchanged.
type ICMPConfig struct {
	Type       uint8       `json:"type"`      // 8=Echo Request, 0=Echo Reply
	Code       uint8       `json:"code"`
	Identifier uint16      `json:"identifier"` // Echo session ID; 0 -> fallback to Sequence
	Sequence   uint16      `json:"sequence"`
	Data       []byte      `json:"data"`
	Pattern    []ICMPStep  `json:"pattern,omitempty"` // multi-session ping steps
}

// ICMPStep is a single ping within a multi-session ICMP flow. The planner
// emits Type (and its auto-reply if Type=EchoRequest) for each step, with
// Sequence incrementing per step. Data is the per-ping payload.
type ICMPStep struct {
	Type     uint8  `json:"type"`     // 8=Echo Request, 0=Echo Reply
	Code     uint8  `json:"code"`
	Sequence uint16 `json:"sequence"` // per-step sequence; if 0, planner uses step index+1
	Data     []byte `json:"data"`
}

// ARPConfig for ARP protocol.
type ARPConfig struct {
	Operation uint16 `json:"operation"` // 1=Request, 2=Reply
	TargetMAC string `json:"target_mac"`
	TargetIP  string `json:"target_ip"`
}

// FTPConfig for FTP protocol. FTP is a session-level protocol: a single TCP
// connection on port 21 (the control channel) carries a sequence of
// command/response pairs. The planner emits a TCP handshake, followed by
// each FTP command (client → server) and its response (server → client),
// then a TCP teardown — all within one flow (one 4-tuple, one sequence
// space per direction).
//
// Each FTPCommand carries the command string (e.g. "USER anonymous") and
// the expected response (e.g. "331 Anonymous access allowed"). The
// response is emitted verbatim — the planner does not validate FTP state
// transitions, it just plays back the dialog the user specified. This
// matches the trafficgen contract: we synthesize test packets, not a
// real FTP server.
//
// Banner: when non-empty, the server emits this as the first FTP payload
// (right after the handshake ACK). Real FTP servers send "220 ..." as a
// greeting; the user can set it explicitly or leave it empty to skip.
type FTPConfig struct {
	Banner   string       `json:"banner,omitempty"` // server greeting, e.g. "220 ..."; empty = skip
	Commands []FTPCommand `json:"commands"`
	// MSS drives segmentation of long payloads (response or command bodies).
	// 0 -> DefaultMSS (1460). Pulled from the HTTP MSS constant via the
	// planner package to avoid a core->http import.
	MSS uint16 `json:"mss,omitempty"`
}

// FTPCommand is a single command/response pair within an FTP session.
type FTPCommand struct {
	Cmd      string `json:"cmd"`               // e.g. "USER anonymous"; sent client -> server
	Response string `json:"response"`           // e.g. "331 ..."; sent server -> client
}

// SIPConfig for SIP protocol. SIP (RFC 3261) is a session-level protocol:
// a single TCP (or UDP) connection on port 5060 carries a sequence of
// SIP signaling messages (INVITE → 100 → 180 → 200 → ACK → BYE → 200).
// The planner emits a TCP handshake, followed by each SIP message in
// Dialog (as PSH-ACK payload), then a TCP teardown — all within one flow.
//
// Each SIPMessage carries either a request (Method + URI) or a response
// (StatusCode + StatusText). Direction "up" = client→server, "down" =
// server→client. Headers is a list of "Name: Value" strings; the planner
// appends CRLF per RFC 3261 §7 (each line ends with CRLF, body separated
// from headers by a blank CRLF line). Body is the optional message body
// (e.g. SDP); when non-empty, the planner emits a Content-Length header
// derived from len(Body) unless the user supplied one in Headers.
//
// This planner does NOT generate RTP media traffic. RTP runs over UDP
// on a separate 4-tuple (negotiated inside SDP); users who need media
// run a second trafficgen flow with protocol=udp. The SIP signaling
// session is what defines a "SIP flow" for testing purposes.
type SIPConfig struct {
	Dialog []SIPMessage `json:"dialog"`
	// MSS drives segmentation of long SIP messages (INVITE with a large
	// SDP body can exceed MSS). 0 -> DefaultMSS (1460). The SYN/SYN-ACK
	// carry this MSS as a TCP option.
	MSS uint16 `json:"mss,omitempty"`
}

// SIPMessage is a single message within a SIP dialog. A request sets
// Method+URI (e.g. Method="INVITE", URI="sip:callee@spirent.com"); a
// response sets StatusCode+StatusText (e.g. 200, "OK"). Direction "up"
// = client→server (request), "down" = server→client (response).
type SIPMessage struct {
	Method     string   `json:"method,omitempty"`      // e.g. "INVITE", "ACK", "BYE"; empty for responses
	URI        string   `json:"uri,omitempty"`         // e.g. "sip:callee@spirent.com"; empty for responses
	StatusCode int      `json:"status_code,omitempty"` // e.g. 200; 0 for requests
	StatusText string   `json:"status_text,omitempty"` // e.g. "OK"; empty for requests
	Headers    []string `json:"headers,omitempty"`    // each "Name: Value"; Content-Length auto-added when Body non-empty
	Body       string   `json:"body,omitempty"`        // e.g. SDP content; empty = no body
	Direction  string   `json:"direction,omitempty"`   // "up" or "down"; empty -> planner infers from Method/StatusCode
}

// SCTPConfig for the SCTP protocol. SCTP (RFC 4960) is a session-level,
// message-oriented transport carrying IP protocol 132. Unlike TCP's 3-way
// handshake, SCTP uses a 4-way handshake (INIT → INIT-ACK → COOKIE-ECHO →
// COOKIE-ACK) with a Verification Tag that identifies each association and a
// per-direction TSN (Transmission Sequence Number) that numbers every DATA
// chunk in order.
//
// The planner emits the 4-way handshake, then each SCTPChunk in Chunks as a
// DATA chunk (type 0) carrying TSN/SID/SSN/PPID, then the 3-way SHUTDOWN
// teardown (SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE) — all within one
// 4-tuple (one flow) with one continuous TSN space per direction.
//
// Chunk layout (RFC 4960 §3.2): Type(1) + Flags(1) + Length(2) + value.
// The Length field includes the 4-byte header and is padded to a 4-byte
// boundary at the end. DATA chunks add TSN(4) + SID(2) + SSN(2) + PPID(4)
// in front of the user data (16 bytes of per-chunk header + data).
//
// Verification Tag handling: the client picks the server's InitiateTag (from
// INIT-ACK) as the destination Verification Tag for all packets it sends
// to the server, and vice versa. For test purposes, when the user leaves
// VerificationTag at 0, the planner auto-generates a random non-zero tag
// for each side and ensures INIT carries 0 in the Verification Tag field
// per RFC 4960 §5.1.1 (INIT must carry 0; the peer's tag is learned from
// the INIT-ACK).
type SCTPConfig struct {
	// VerificationTag is the client-side (local) verification tag — the tag
	// the server should put in packets it sends to the client. 0 = random.
	VerificationTag uint32 `json:"verification_tag,omitempty"`
	// InitiateTag is the tag the client puts in the Verification Tag field
	// of packets it sends to the server. Per RFC 4960 §5.1.1, INIT carries
	// 0 in this field; the value is learned from the INIT-ACK. 0 = random.
	InitiateTag uint32 `json:"initiate_tag,omitempty"`
	// Chunks are the SCTP message chunks in order. Each becomes one SCTP
	// packet (IP/SCTP + DATA chunk) carrying the user-supplied payload.
	Chunks []SCTPChunk `json:"chunks,omitempty"`
}

// SCTPChunk models a single SCTP chunk. For DATA chunks, TSN is the
// transmission sequence number (increments per chunk per direction), SID is
// the stream identifier, SSN is the per-stream sequence number, and PPID
// is the payload protocol identifier (e.g. 60 for NGAP, 47 for M3UA).
// Data is the user payload bytes carried in the chunk.
//
// Direction "up" = client→server, "down" = server→client. Empty defaults
// to "up" (most DATA chunks in a test flow go up).
type SCTPChunk struct {
	TSN       uint32 `json:"tsn,omitempty"`        // 0 = planner auto-increments per direction
	SID       uint16 `json:"sid,omitempty"`        // stream identifier
	SSN       uint16 `json:"ssn,omitempty"`        // per-stream sequence
	PPID      uint32 `json:"ppid,omitempty"`       // payload protocol id
	Data      []byte `json:"data,omitempty"`       // user payload
	Direction string `json:"direction,omitempty"`  // "up" or "down"; empty -> "up"
}

// ICMPv6Config for the ICMPv6 protocol (RFC 4443). ICMPv6 is the IPv6
// equivalent of ICMP — same Echo Request/Reply model (types 128/129), same
// session semantics (Identifier groups pings into a session, Sequence
// increments per ping). The planner emits each ping as an up packet
// (client→server) followed by an auto-reply down packet (server→client)
// when Type=EchoRequest, all within one flow (one IPv6 2-tuple).
//
// Pattern mirrors the ICMPv4 multi-session path: when non-empty, the
// planner iterates the steps and emits each as a separate ping within the
// same flow. Identifier is shared across steps (RFC 4443 §4.1). An empty
// Pattern falls back to the single-ping path (request + auto-reply).
//
// ICMPv6 checksum uses the IPv6 pseudo-header (srcIP + dstIP + length +
// nextHeader=58), NOT the IPv4-style pseudo-header. The planner computes
// it during payload serialization (see calculateIPv6PseudoHeader in
// builder.go). The pseudo-header requirement means src/dst IP MUST be
// valid IPv6 addresses for the checksum to be non-zero — IPv4 addresses
// produce a zero checksum (matching IPv4's invalid-input behavior).
type ICMPv6Config struct {
	Type       uint8          `json:"type"`                // 128=Echo Request, 129=Echo Reply
	Code       uint8          `json:"code"`
	Identifier uint16         `json:"identifier"`          // Echo session ID; 0 -> fallback to Sequence
	Sequence   uint16         `json:"sequence"`
	Data       []byte         `json:"data"`
	Pattern    []ICMPv6Step   `json:"pattern,omitempty"`   // multi-session ping steps
}

// ICMPv6Step is a single ping within a multi-session ICMPv6 flow. The
// planner emits Type (and its auto-reply if Type=EchoRequest) for each
// step, with Sequence incrementing per step. Data is the per-ping payload.
type ICMPv6Step struct {
	Type     uint8  `json:"type"`     // 128=Echo Request, 129=Echo Reply
	Code     uint8  `json:"code"`
	Sequence uint16 `json:"sequence"` // per-step sequence; if 0, planner uses step index+1
	Data     []byte `json:"data"`
}

// PacketConfig represents the configuration for building a single packet.
type PacketConfig struct {
	FlowID      string                 `json:"flow_id"`
	PacketIndex uint64                 `json:"packet_index"`
	ClassID     string                 `json:"class_id"`
	Direction   string                 `json:"direction"` // up, down
	Timestamp   time.Time              `json:"timestamp"`

	L2      L2Config `json:"l2"`
	L3      L3Config `json:"l3"`
	L4      L4Config `json:"l4"`
	Payload []byte   `json:"payload"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// L2Config for Layer 2 (Ethernet).
type L2Config struct {
	SrcMAC    string `json:"src_mac"`
	DstMAC    string `json:"dst_mac"`
	EtherType uint16 `json:"ether_type"` // 0x0800=IPv4, 0x0806=ARP
	VLAN      *VLAN  `json:"vlan,omitempty"`

	// Pad controls padding to MinEthernetFrame (60 bytes, excluding FCS).
	// nil = pad (default ON — short frames like ARP or small ICMP are padded
	// so real NICs don't reject them); *true = pad; *false = don't pad
	// (emit at natural size, useful for testing runt-frame handling).
	// Propagated from FlowSpec.PadMinFrame by the worker; planners leave
	// this nil so the builder applies its default.
	Pad *bool `json:"pad,omitempty"`
}

// L3Config for Layer 3 (IP).
type L3Config struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol uint8  `json:"protocol"` // 1=ICMP, 6=TCP, 17=UDP
	TTL      uint8  `json:"ttl"`
	IPID     uint16 `json:"ip_id,omitempty"`

	// DSCP (6-bit DiffServ codepoint) and ECN (2-bit Explicit Congestion
	// Notification). Encoded into the TOS byte as (DSCP<<2)|(ECN&0x03).
	DSCP uint8 `json:"dscp,omitempty"`
	ECN  uint8 `json:"ecn,omitempty"`

	// Flags (3-bit: reserved|DF|MF) and FragOffset (13-bit, in 8-byte units).
	// Encoded into bytes 6:8 as (Flags<<13)|(FragOffset&0x1FFF).
	// Use IPFlagDF / IPFlagMF constants. Default Flags=IPFlagDF (0x4000).
	Flags       uint8  `json:"flags,omitempty"`
	FragOffset  uint16 `json:"frag_offset,omitempty"`
}

// IP flags bit positions within the L3Config.Flags field.
const (
	IPFlagReserved uint8 = 0x04 // bit 2 (must be 0)
	IPFlagDF       uint8 = 0x02 // bit 1 - Don't Fragment
	IPFlagMF       uint8 = 0x01 // bit 0 - More Fragments
)

// L4Config for Layer 4 (TCP/UDP).
type L4Config struct {
	Protocol   string `json:"protocol"` // tcp, udp
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	WindowSize uint16 `json:"window_size,omitempty"`

	// TCP specific
	Seq   uint32 `json:"seq,omitempty"`
	Ack   uint32 `json:"ack,omitempty"`
	Flags uint8  `json:"flags,omitempty"`

	// TCP options (MSS, Window Scale, SACK-Permitted, Timestamp, ...).
	// Encoded after the 20-byte TCP header; data offset grows accordingly.
	TCPOptions []TCPOption `json:"tcp_options,omitempty"`
}

// TCPOption is a single TCP option. Kind 0 (End) and 1 (NOP) are 1-byte
// options with no length field or data; all other kinds are encoded as
// kind + length(2+len(Data)) + Data.
type TCPOption struct {
	Kind uint8  `json:"kind"`
	Data []byte `json:"data,omitempty"`
}

// TCP option kinds.
const (
	TCPOptEnd       uint8 = 0 // End of Option List
	TCPOptNOP       uint8 = 1 // No-Operation (padding)
	TCPOptMSS       uint8 = 2 // Maximum Segment Size
	TCPOptWinScale  uint8 = 3 // Window Scale
	TCPOptSACKPermit uint8 = 4 // SACK-Permitted
	TCPOptTimestamp uint8 = 8 // Timestamp
)

// BatchSpec for batch traffic generation.
type BatchSpec struct {
	Classes []TrafficClass `json:"classes"`
	Global  GlobalConfig   `json:"global"`
}

// TrafficClass represents a class of traffic.
type TrafficClass struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	BPS            string                 `json:"bps"`
	FlowsPerSecond int                    `json:"flows_per_second"`
	FlowCount      int                    `json:"flow_count"`
	Tuples         TupleConfig            `json:"tuples"`
	Config         map[string]interface{} `json:"config"`
	// Replay holds the ReplaySpec JSON for type=="replay" classes. It's raw JSON
	// (not a typed replay.ReplaySpec) to avoid a core<->replay import cycle; the
	// registered ReplayPlanner unmarshals it.
	Replay json.RawMessage `json:"replay,omitempty"`
	// GroupID routes all flows of this class with the same generated id to one
	// PacketWorker. See FlowSpec.GroupID.
	GroupID *StrategyConfig `json:"group_id,omitempty"`
}

// TupleConfig for generating 4-tuples.
type TupleConfig struct {
	SrcIP   StrategyConfig `json:"src_ip"`
	DstIP   StrategyConfig `json:"dst_ip"`
	SrcPort StrategyConfig `json:"src_port"`
	DstPort StrategyConfig `json:"dst_port"`
}

// StrategyConfig for value generation strategies.
type StrategyConfig struct {
	Strategy string `json:"strategy,omitempty"` // fixed, inc, random, pattern, list
	Value    interface{}   `json:"value,omitempty"`
	Range    []interface{} `json:"range,omitempty"`
	Step     int           `json:"step,omitempty"`
	Seed     int64         `json:"seed,omitempty"`
	Pattern  string        `json:"pattern,omitempty"`
	List     []string      `json:"list,omitempty"`
}

// GlobalConfig for global batch settings.
type GlobalConfig struct {
	TotalFlows      int `json:"total_flows"`
	DurationSeconds int `json:"duration_seconds"`
}
