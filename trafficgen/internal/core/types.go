// Package core provides core data structures for the traffic generator.
package core

import (
	"context"
	"encoding/json"
	"time"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// Task represents a traffic generation task.
type Task struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	UserID      string     `json:"user_id,omitempty"` // owning user (for user-scoped asset access during replay)
	Protocol    string     `json:"protocol"`          // tcp, udp, http, dns, icmp, arp
	Spec        FlowSpec   `json:"spec"`              // single-protocol mode
	Batch       *BatchSpec `json:"batch,omitempty"`   // mixed-traffic mode (Spec XOR Batch)

	// Mode selects the source of packet configs. "synth" (default) synthesizes
	// packets from Spec via a planner. "replay" replays a recorded pcap via the
	// registered ReplayPlanner; the pcap's own protocols populate the wire bytes
	// (Protocol is informational). Replay and synth share the same task-level
	// flow-control ceiling (bps/flows/time) -- no exceptions.
	Mode string `json:"mode,omitempty"`

	// Replay holds the raw ReplaySpec JSON for Mode=="replay" tasks, passed
	// verbatim to ReplayPlanner.PlanReplay. Not used for synth mode.
	Replay json.RawMessage `json:"replay,omitempty"`

	ClassID    string                 `json:"class_id"`
	Interface  string                 `json:"interface"`            // output interface name (client side / primary)
	Interface2 string                 `json:"interface2,omitempty"` // server side (dual-port replay); empty = single
	OutputMode string                 `json:"output_mode"`          // interface, pcap, both
	PcapFile   string                 `json:"pcap_file,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`

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
	IPFlags    uint8  `json:"ip_flags,omitempty"` // IPFlagDF / IPFlagMF (was "flags")
	FragOffset uint16 `json:"frag_offset,omitempty"`

	// Protocol specific configuration
	TCP    *TCPConfig    `json:"tcp,omitempty"`
	UDP    *UDPConfig    `json:"udp,omitempty"`
	HTTP   *HTTPConfig   `json:"http,omitempty"`
	DNS    *DNSConfig    `json:"dns,omitempty"`
	ICMP   *ICMPConfig   `json:"icmp,omitempty"`
	ARP    *ARPConfig    `json:"arp,omitempty"`
	FTP    *FTPConfig    `json:"ftp,omitempty"`
	SIP    *SIPConfig    `json:"sip,omitempty"`
	SCTP   *SCTPConfig   `json:"sctp,omitempty"`
	ICMPv6 *ICMPv6Config `json:"icmpv6,omitempty"`

	// Common configuration
	Payload  []byte `json:"payload,omitempty"`
	Count    int    `json:"count,omitempty"`
	Duration int    `json:"duration,omitempty"` // seconds
	BPS      string `json:"bps,omitempty"`      // rate limit, e.g., "200k", "1M"

	// FileSource (protocol-agnostic): when set, planners obtain payload
	// bytes via PayloadCache.GetOrLoad(src) instead of using inline
	// Payload. May be overridden per-protocol (e.g. FTPDataChannel.
	// FileSource takes precedence over FlowSpec.FileSource). nil means
	// no file source — planners fall back to Payload.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`

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

	// SubFlows is a generic list of secondary flows bound to this primary
	// flow (e.g. FTP data channel, SIP RTP media, SCTP multi-homing). The
	// primary protocol's planner iterates SubFlows and emits each as a
	// separate PacketConfig stream into the same configChan — packets share
	// the parent's GroupID so they route to the same PacketWorker, which
	// preserves cross-flow timing (signaling first, data after, then
	// signaling resumes).
	//
	// This field is NOT protocol-specific. Any planner can emit sub-flows
	// — FTP, SIP, SCTP use it for their respective data-plane needs, and
	// future protocols can reuse the same mechanism without touching
	// FlowSpec again.
	SubFlows []SubFlowSpec `json:"sub_flows,omitempty"`

	// ValidationErrors collects user-facing input errors found during
	// mapToFlowSpec (e.g. Fill.Bytes=-1, Random.MinBytes>MaxBytes). Empty
	// means valid. Planners/engine should check this before calling Plan
	// and fail the task with a clear aggregated message rather than
	// letting the error surface deep in a make([]byte, n) panic.
	ValidationErrors []string `json:"validation_errors,omitempty"`

	// --- L7 protocol configurations (phase 3 batch). Appended at end per
	// flowspec_extension.md §2.3 to avoid touching existing field layout.
	// Each pointer is nil when the protocol is not selected; planners must
	// nil-check before dereferencing. Implementers populate the struct
	// bodies in core/types.go (their own region) -- DO NOT move these.

	DHCP        *DHCPConfig        `json:"dhcp,omitempty"`
	DHCPv6      *DHCPv6Config      `json:"dhcpv6,omitempty"`
	GRPC        *GRPCConfig        `json:"grpc,omitempty"`
	IKE         *IKEConfig         `json:"ike,omitempty"`
	IKENATT     *IKENATTConfig     `json:"ike_nat_t,omitempty"`
	IMAP        *IMAPConfig        `json:"imap,omitempty"`
	L2TP        *L2TPConfig        `json:"l2tp,omitempty"`
	MDNS        *MDNSConfig        `json:"mdns,omitempty"`
	MySQL       *MySQLConfig       `json:"mysql,omitempty"`
	NTP         *NTPConfig         `json:"ntp,omitempty"`
	OpenVPN     *OpenVPNConfig     `json:"openvpn,omitempty"`
	PostgreSQL  *PostgreSQLConfig  `json:"postgresql,omitempty"`
	POP3        *POP3Config        `json:"pop3,omitempty"`
	RDP         *RDPConfig         `json:"rdp,omitempty"`
	Redis       *RedisConfig       `json:"redis,omitempty"`
	Shadowsocks *ShadowsocksConfig `json:"shadowsocks,omitempty"`
	SMTP        *SMTPConfig        `json:"smtp,omitempty"`
	SNMP        *SNMPConfig        `json:"snmp,omitempty"`
	SSDP        *SSDPConfig        `json:"ssdp,omitempty"`
	SSH         *SSHConfig         `json:"ssh,omitempty"`
	Syslog      *SyslogConfig      `json:"syslog,omitempty"`
	Telnet      *TelnetConfig      `json:"telnet,omitempty"`
	TLS         *TLSConfig         `json:"tls,omitempty"`
	Vmess       *VmessConfig       `json:"vmess,omitempty"`
	WireGuard   *WireGuardConfig   `json:"wireguard,omitempty"`
}

// SubFlowSpec describes a secondary flow bound to a primary flow. The
// primary protocol's planner emits sub-flow packets into the same
// configChan as the primary flow, after the signaling that negotiates the
// sub-flow (e.g. after FTP's PASV response, after SIP's 200 OK). The
// sub-flow inherits the parent's GroupID so all packets route to the same
// PacketWorker — preserving wire-order timing between signaling and data.
//
// Protocol selects the L4 behavior:
//   - "tcp": full handshake (SYN/SYN-ACK/ACK) → payload segments →
//     4-way teardown (FIN-ACK/ACK/FIN-ACK/ACK), MSS-segmented
//   - "udp": single-direction or bidirectional payload datagrams
//   - "sctp": 4-way handshake → DATA chunks → 3-way SHUTDOWN
//
// Direction describes which way the payload bytes flow, INDEPENDENT of
// which side opened the TCP connection: "up" = client→server (e.g. FTP
// STOR upload), "down" = server→client (e.g. FTP RETR download). Use
// ServerInitiated to control who sends the SYN.
//
// SrcPort/DstPort: client's port / server's port (always, regardless of
// who opens the connection). 0 means the planner derives a port. For FTP,
// the planner parses the PASV/PORT response to fill these; for SIP/RTP,
// the planner derives from the SDP; users can also set explicit ports.
type SubFlowSpec struct {
	Protocol    string `json:"protocol"`              // "tcp", "udp", "sctp"
	SrcPort     uint16 `json:"src_port,omitempty"`    // client's port (0 = derive from parent)
	DstPort     uint16 `json:"dst_port,omitempty"`    // server's port (0 = derive from parent)
	Direction   string `json:"direction,omitempty"`   // "up"=client→server data flow, "down"=server→client
	Payload     string `json:"payload,omitempty"`     // raw text bytes (file body / RTP frames); []byte conversion at emit
	PayloadB64  string `json:"payload_b64,omitempty"` // base64 alternative; overrides Payload when set (for binary)
	Handshake   bool   `json:"handshake,omitempty"`   // TCP/SCTP: emit handshake (default true)
	Termination bool   `json:"termination,omitempty"` // TCP/SCTP: emit teardown (default true)
	MSS         uint16 `json:"mss,omitempty"`         // TCP segmentation size (0 = 1460)

	// ServerInitiated: when true, the server opens the TCP connection —
	// SYN goes server→client (Direction="down", SrcPort=sub.DstPort,
	// DstPort=sub.SrcPort). Used for FTP active mode (PORT) where the
	// server connects from port 20 to the client's data port. Default
	// false (client opens, e.g. FTP passive mode, SIP RTP).
	ServerInitiated bool `json:"server_initiated,omitempty"`

	// AltSrcIP/AltDstIP: when non-empty, the sub-flow uses a different
	// 4-tuple than the primary (e.g. SCTP multi-homing uses an alternate
	// path). Empty = inherit parent's SrcIP/DstIP.
	AltSrcIP string `json:"alt_src_ip,omitempty"`
	AltDstIP string `json:"alt_dst_ip,omitempty"`

	// AltSrcMAC/AltDstMAC: when non-empty, the sub-flow uses different MACs
	// (multi-homing often implies a different NIC). Empty = inherit.
	AltSrcMAC string `json:"alt_src_mac,omitempty"`
	AltDstMAC string `json:"alt_dst_mac,omitempty"`

	// GroupID overrides the parent's GroupID for routing the sub-flow's
	// packets to a specific PacketWorker shard. When nil, EmitSubFlow
	// inherits the parent's GroupID (so control + data plane stay on one
	// worker and preserve wire-order timing). When set, the sub-flow's
	// packets route independently of the parent -- used to split a noisy
	// data plane onto its own worker so a fat FTP/SIP transfer does not
	// starve the control plane's pacing.
	//
	// Mirrors FlowSpec.GroupID: same StrategyConfig semantics (fixed / inc /
	// rand / pattern / list). nil = inherit parent.
	GroupID *StrategyConfig `json:"group_id,omitempty"`
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
	RST         bool   `json:"rst,omitempty"`
	MSS         uint16 `json:"mss"`
	WindowSize  uint16 `json:"window_size"`
	Flags       uint8  `json:"flags"`
	Seq         uint32 `json:"seq,omitempty"`
	Ack         uint32 `json:"ack,omitempty"`

	// InitialSeq overrides the random initial sequence number for TCP flows.
	// 0 = random per flow (default, RFC 6528 ISN randomization). Non-zero
	// forces a deterministic client ISN for reproducible tests. Moved here
	// from FlowSpec because it is TCP-specific.
	InitialSeq uint32 `json:"initial_seq,omitempty"`
}

// UDPConfig for UDP protocol.
type UDPConfig struct {
	IsResponse      bool `json:"is_response"` // was "response"
	DisableChecksum bool `json:"disable_checksum,omitempty"`
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
//
// Body / ResponseBody hold text payloads as a UTF-8 string. For binary
// payloads (PNG/JPEG/PDF/ZIP/...), set BodyB64 / ResponseBodyB64 instead —
// a base64-encoded string that the planner decodes to []byte. When both
// the text and b64 fields of a side are set, b64 wins. The planner uses
// the decoded bytes to compute Content-Length, gzip compression, and MSS
// segmentation.
//
// Content-Type: when the user does not provide one, the planner sniffs it
// from the payload (text: HTML/XML/JSON/text/plain; binary: magic bytes).
type HTTPConfig struct {
	Method         string            `json:"method"`
	URI            string            `json:"uri"`
	Version        string            `json:"version"` // empty -> "HTTP/1.1"
	RequestHeaders map[string]string `json:"request_headers"`
	Body           string            `json:"body"`
	BodyB64        string            `json:"body_b64,omitempty"` // base64-encoded binary body; overrides Body when set
	KeepAlive      bool              `json:"keep_alive"`
	Transactions   int               `json:"transactions"`
	ThinkTime      int               `json:"think_time"` // milliseconds

	// Response-side fields. ResponseHeaders overrides generated defaults
	// (Content-Type/Content-Length/Connection). ResponseBody empty -> no
	// Content-Length, no Content-Type default. ResponseStatusCode 0 -> 200.
	// ResponseStatusText empty -> looked up from ResponseStatusCode.
	//
	// ResponseContentEncoding, when set to "gzip", compresses ResponseBody
	// with gzip before framing. Content-Length reflects the compressed byte
	// count, and a "Content-Encoding: gzip" header is emitted (overridable
	// via ResponseHeaders, case-insensitive). Empty/unset -> no compression.
	// (Renamed from ContentEncoding — the old name was ambiguous: it sounded
	// global but only affected the response side.)
	//
	// RequestContentEncoding is the symmetric field for the request side:
	// when set to "gzip", compresses Body with gzip before framing.
	// Content-Length reflects the compressed byte count, and a
	// "Content-Encoding: gzip" header is emitted (overridable via
	// RequestHeaders, case-insensitive). Empty/unset -> no compression.
	//
	// MSS is governed by TCPConfig.MSS (MSS is a TCP transport parameter,
	// not an HTTP one). Planners read spec.TCP.MSS for both request and
	// response segmentation.
	ResponseHeaders         map[string]string `json:"response_headers"`
	ResponseBody            string            `json:"response_body"`
	ResponseBodyB64         string            `json:"response_body_b64,omitempty"` // base64-encoded binary body; overrides ResponseBody when set
	ResponseStatusCode      int               `json:"response_status_code"`
	ResponseStatusText      string            `json:"response_status_text"`
	ResponseContentEncoding string            `json:"response_content_encoding"`
	RequestContentEncoding  string            `json:"request_content_encoding"`

	// FileSource, when set, supplies the HTTP REQUEST body bytes via
	// PayloadCache.GetOrLoad(src). The response body continues to use
	// inline ResponseBody / ResponseBodyB64. May be overridden per-protocol
	// in future revisions.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// DNSConfig for DNS protocol.
type DNSConfig struct {
	Domain     string `json:"domain"`
	QueryType  uint16 `json:"query_type"`  // A=1, AAAA=28
	IsResponse bool   `json:"is_response"` // was "response"
	ResponseIP string `json:"response_ip,omitempty"`

	// TxID is the 16-bit DNS Transaction ID (RFC 1035 §4.1.1). The client
	// chooses it; the response MUST echo it. 0 (unset) → planner uses the
	// historical default 0x1234 for backward compatibility.
	TxID uint16 `json:"txid,omitempty"`

	// EDNS0 OPT pseudo-record controls (RFC 6891). When EDNS0Enabled is
	// true the planner appends an OPT RR to the Additional section of the
	// query (ARCOUNT=1). UDPPayloadSize is the OPT CLASS field (max UDP
	// payload the client accepts); 0 is treated as 4096 when EDNS0Enabled.
	// DnssecOK sets the DO bit (bit 15 of the OPT TTL) per RFC 4033.
	EDNS0Enabled   bool   `json:"edns0_enabled,omitempty"`
	UDPPayloadSize uint16 `json:"udp_payload_size,omitempty"`
	DnssecOK       bool   `json:"dnssec_ok,omitempty"`
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
	Type       uint8      `json:"type"` // 8=Echo Request, 0=Echo Reply
	Code       uint8      `json:"code"`
	Identifier uint16     `json:"identifier"` // Echo session ID; 0 -> fallback to Sequence
	Sequence   uint16     `json:"sequence"`
	Data       []byte     `json:"data"`
	Pattern    []ICMPStep `json:"pattern,omitempty"` // multi-session ping steps

	// FileSource, when set, supplies the ICMP echo data bytes via
	// PayloadCache.GetOrLoad(src) instead of inline Data. nil = use Data.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// ICMPStep is a single ping within a multi-session ICMP flow. The planner
// emits Type (and its auto-reply if Type=EchoRequest) for each step, with
// Sequence incrementing per step. Data is the per-ping payload.
type ICMPStep struct {
	Type     uint8  `json:"type"` // 8=Echo Request, 0=Echo Reply
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
//
// DataChannel: when non-nil, the planner emits a second TCP flow (the
// data channel) carrying the file body, interleaved into the control
// channel at the point where the data-channel-bearing command (RETR/STOR/
// LIST) appears. See FTPDataChannel for mode/direction semantics.
type FTPConfig struct {
	Banner      string          `json:"banner,omitempty"` // server greeting, e.g. "220 ..."; empty = skip
	Commands    []FTPCommand    `json:"commands"`
	DataChannel *FTPDataChannel `json:"data_channel,omitempty"`
	// MSS is governed by TCPConfig.MSS. FTP runs over TCP, so the planner
	// reads spec.TCP.MSS for segmentation of long FTP payloads.
}

// FTPCommand is a single command/response pair within an FTP session.
type FTPCommand struct {
	Cmd      string `json:"cmd"`      // e.g. "USER anonymous"; sent client -> server
	Response string `json:"response"` // e.g. "331 ..."; sent server -> client

	// EmitDataChannel, when true on a command, triggers the planner to emit
	// the FTP data channel sub-flow immediately AFTER this command's
	// response. This is how the user models "RETR /file.bin" -> server
	// "150 Opening data connection" -> [DATA CHANNEL PACKETS] -> server
	// "226 Transfer complete". The data channel is emitted as a separate
	// TCP flow (own handshake / seq space / teardown) but shares the
	// parent's GroupID so it routes to the same PacketWorker — wire order
	// = emit order, so the data packets land between 150 and 226.
	//
	// This is a bool flag rather than a sub-flow spec on the command
	// because the data channel's spec lives once on FTPConfig.DataChannel
	// (one data channel per FTP session is the common case). For multiple
	// data channels in one session (rare — e.g. LIST then RETR), use
	// FlowSpec.SubFlows directly.
	EmitDataChannel bool `json:"emit_data_channel,omitempty"`
}

// FTPDataChannel describes the FTP data connection. The data channel is a
// second TCP flow (separate 4-tuple, separate handshake/teardown) that
// carries file bytes or directory listings. The control channel negotiates
// which side listens (active vs passive) and which port; the planner
// derives the data-channel ports from that negotiation.
//
// Mode:
//   - "active" (PORT): the client tells the server "I'm listening on
//     port X, you connect to me." Server opens a TCP connection from
//     port 20 to client:port X. Direction is still "down" for RETR
//     (server→client file bytes) or "up" for STOR (client→server).
//   - "passive" (PASV): the server tells the client "I'm listening on
//     port Y, you connect to me." Client opens a TCP connection from
//     an ephemeral port to server:port Y. Direction semantics same as
//     active — Direction describes which way the file bytes flow, not
//     who opened the connection.
//
// SrcPort/DstPort: 0 means the planner derives them:
//   - active: SrcPort=20 (server's data port), DstPort=ephemeral
//     derived from control-channel SrcPort+1 (e.g. ctrl 20000 -> data
//     20001)
//   - passive: SrcPort=ephemeral derived from control-channel SrcPort+1,
//     DstPort=derived from PASV response (or 50000 if no PASV in dialog)
//
// Payload: the file body bytes (for RETR/STOR). For LIST, the user
// provides the directory-listing bytes as Payload (the planner doesn't
// generate listing content). PayloadB64 lets users embed binary file
// bytes (e.g. a PNG) via JSON.
type FTPDataChannel struct {
	Mode       string `json:"mode,omitempty"`        // "active" (PORT) or "passive" (PASV); default "passive"
	SrcPort    uint16 `json:"src_port,omitempty"`    // 0 = derive (20 for active, ephemeral for passive)
	DstPort    uint16 `json:"dst_port,omitempty"`    // 0 = derive (ephemeral for active, PASV-negotiated or ephemeral for passive)
	Direction  string `json:"direction,omitempty"`   // "up"=STOR (upload), "down"=RETR (download); default "down"
	Payload    string `json:"payload,omitempty"`     // file body (text)
	PayloadB64 string `json:"payload_b64,omitempty"` // file body (base64, for binary)
	MSS        uint16 `json:"mss,omitempty"`         // 0 = inherit parent TCPConfig.MSS or 1460

	// FileSource, when set, supplies the data-channel file body bytes via
	// PayloadCache.GetOrLoad(src) instead of inline Payload / PayloadB64.
	// nil = use inline payload fields. Takes precedence over
	// FlowSpec.FileSource for FTP data-channel bytes.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
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
// Media: when non-nil, the planner emits a UDP sub-flow carrying RTP
// media frames after the dialog's ACK message (the message that
// completes the session establishment). The sub-flow shares the parent's
// GroupID so it routes to the same PacketWorker — wire order = emit
// order, so RTP frames land between ACK and BYE in the pcap, exactly
// where real media would appear.
type SIPConfig struct {
	Dialog []SIPMessage `json:"dialog"`
	Media  *SIPMedia    `json:"media,omitempty"`
	// MSS is governed by TCPConfig.MSS. SIP runs over TCP (or UDP), so the
	// planner reads spec.TCP.MSS for segmentation of long SIP messages.
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
	Headers    []string `json:"headers,omitempty"`     // each "Name: Value"; Content-Length auto-added when Body non-empty
	Body       string   `json:"body,omitempty"`        // e.g. SDP content; empty = no body
	Direction  string   `json:"direction,omitempty"`   // "up" or "down"; empty -> planner infers from Method/StatusCode

	// EmitMedia, when true on a message, triggers the planner to emit the
	// RTP media sub-flow immediately AFTER this message. Typically set on
	// the ACK that completes INVITE/200/ACK (the "session established"
	// moment). RTP frames then appear between this ACK and the next
	// message (usually BYE).
	//
	// Flag is per-message (rather than auto-detected on ACK) so the user
	// has explicit control: a re-INVITE without media, or a session that
	// starts media mid-dialog, can both be modeled.
	EmitMedia bool `json:"emit_media,omitempty"`
}

// SIPMedia describes the RTP media plane for a SIP session. RTP (RFC
// 3550) runs over UDP on a separate 4-tuple from the SIP signaling;
// the SDP body of INVITE/200 OK negotiates the RTP ports. The planner
// emits N RTP frames as a UDP sub-flow, each frame = 12-byte RTP header
// + FrameSize bytes of payload.
//
// SrcPort/DstPort: 0 means the planner derives them. RTP ports are
// typically even (per RFC 3550 §9); the planner uses 5004 (the default
// RTP port for audio) when unset. The user should set these to match
// the SDP body of their INVITE/200.
//
// Frames: number of RTP packets to emit. Each is one UDP datagram. A
// 20ms G.711 call produces 50 packets/second, so Frames=100 models 2
// seconds of one-way audio.
//
// PayloadType: RTP payload type (0=PCMU/G.711u, 8=PCMA/G.711a, 9=G.722,
// etc.). The planner writes this into the RTP header's PT field so
// receivers can decode the payload correctly.
//
// SampleRate: RTP clock rate in Hz (8000 for G.711, 16000 for G.722).
// Drives the RTP timestamp increment per frame.
//
// FrameSize: bytes of audio payload per RTP packet. For G.711 20ms,
// FrameSize=160 (8kHz * 0.02s * 1 byte/sample). For G.722 20ms,
// FrameSize=320 (16kHz * 0.02s * 1 byte/sample).
type SIPMedia struct {
	SrcPort     uint16 `json:"src_port,omitempty"`     // 0 = 5004 (default RTP audio)
	DstPort     uint16 `json:"dst_port,omitempty"`     // 0 = 5004 (default RTP audio)
	Frames      int    `json:"frames,omitempty"`       // number of RTP packets; 0 = 1
	PayloadType uint8  `json:"payload_type,omitempty"` // 0 = PCMU; 8 = PCMA; 9 = G.722
	SampleRate  uint32 `json:"sample_rate,omitempty"`  // 0 = 8000 (G.711)
	FrameSize   int    `json:"frame_size,omitempty"`   // 0 = 160 (G.711 20ms)

	// Direction: which way RTP frames flow. "up" = caller→callee (the
	// caller-side RTP stream, default), "down" = callee→caller. Real RTP
	// is bidirectional; users model each direction with one SIPMedia.
	// Empty defaults to "up".
	Direction string `json:"direction,omitempty"`

	// FileSource, when set, supplies the RTP frame payload bytes via
	// PayloadCache.GetOrLoad(src) instead of synthesizing G.711-style
	// payload. nil = synthesize per PayloadType/FrameSize.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
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
	// Heartbeats configures optional HEARTBEAT/HEARTBEAT-ACK chunks
	// (RFC 4960 §3.5.1) sent on the primary path or, when AltPath is
	// set, on an alternate path (multi-homing). nil = no heartbeats.
	Heartbeats *SCTPHeartbeatConfig `json:"heartbeats,omitempty"`
	// Abort, when true, replaces the 3-way SHUTDOWN teardown with a
	// single ABORT chunk (RFC 4960 §9.1) — the abrupt-close path used
	// for fault-injection scenarios where the side tears the association
	// down without negotiating TSN exchange. false (default) = 3-way
	// SHUTDOWN. The ABORT is sent client→server (up) with VerificationTag
	// = serverVerTag, after all DATA chunks.
	Abort bool `json:"abort,omitempty"`
}

// SCTPHeartbeatConfig configures HEARTBEAT emission. HEARTBEAT chunks
// probe path availability; the peer replies with HEARTBEAT-ACK. When
// AltPath is set, heartbeats carry the alternate IP/MAC tuple (multi-
// homing per RFC 4960 §6/C5). When nil, heartbeats go on the primary
// path (still useful for liveness modeling).
type SCTPHeartbeatConfig struct {
	// Count is the number of heartbeat PAIRS (HEARTBEAT + ACK) to emit.
	// 0 = 1 pair. Each pair is two packets.
	Count int `json:"count,omitempty"`
	// AltPath, when set, routes heartbeats on an alternate 4-tuple
	// (different SrcIP/SrcMAC + DstIP/DstMAC). Ports inherit the
	// parent's. nil = primary path.
	AltPath *SCTPAltPath `json:"alt_path,omitempty"`
}

// SCTPAltPath describes the alternate path for multi-homing heartbeats.
// At least one of SrcIP/DstIP should differ from the parent for the
// sub-flow to be a genuine alternate path.
type SCTPAltPath struct {
	SrcIP  string `json:"alt_src_ip,omitempty"`
	DstIP  string `json:"alt_dst_ip,omitempty"`
	SrcMAC string `json:"alt_src_mac,omitempty"`
	DstMAC string `json:"alt_dst_mac,omitempty"`
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
	TSN       uint32 `json:"tsn,omitempty"`       // 0 = planner auto-increments per direction
	SID       uint16 `json:"sid,omitempty"`       // stream identifier
	SSN       uint16 `json:"ssn,omitempty"`       // per-stream sequence
	PPID      uint32 `json:"ppid,omitempty"`      // payload protocol id
	Data      []byte `json:"data,omitempty"`      // user payload
	Direction string `json:"direction,omitempty"` // "up" or "down"; empty -> "up"

	// FileSource, when set, supplies the SCTP DATA chunk payload bytes
	// via PayloadCache.GetOrLoad(src) instead of inline Data. nil = use
	// Data.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
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
	Type       uint8        `json:"type"` // 128=Echo Request, 129=Echo Reply
	Code       uint8        `json:"code"`
	Identifier uint16       `json:"identifier"` // Echo session ID; 0 -> fallback to Sequence
	Sequence   uint16       `json:"sequence"`
	Data       []byte       `json:"data"`
	Pattern    []ICMPv6Step `json:"pattern,omitempty"` // multi-session ping steps

	// FileSource, when set, supplies the ICMPv6 echo data bytes via
	// PayloadCache.GetOrLoad(src) instead of inline Data. nil = use Data.
	// Mirrors ICMPConfig.FileSource for consistency with the ICMPv4 planner.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// ICMPv6Step is a single ping within a multi-session ICMPv6 flow. The
// planner emits Type (and its auto-reply if Type=EchoRequest) for each
// step, with Sequence incrementing per step. Data is the per-ping payload.
type ICMPv6Step struct {
	Type     uint8  `json:"type"` // 128=Echo Request, 129=Echo Reply
	Code     uint8  `json:"code"`
	Sequence uint16 `json:"sequence"` // per-step sequence; if 0, planner uses step index+1
	Data     []byte `json:"data"`
}

// PacketConfig represents the configuration for building a single packet.
type PacketConfig struct {
	FlowID      string    `json:"flow_id"`
	PacketIndex uint64    `json:"packet_index"`
	ClassID     string    `json:"class_id"`
	Direction   string    `json:"direction"` // up, down
	Timestamp   time.Time `json:"timestamp"`

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
	Flags      uint8  `json:"flags,omitempty"`
	FragOffset uint16 `json:"frag_offset,omitempty"`
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
	TCPOptEnd        uint8 = 0 // End of Option List
	TCPOptNOP        uint8 = 1 // No-Operation (padding)
	TCPOptMSS        uint8 = 2 // Maximum Segment Size
	TCPOptWinScale   uint8 = 3 // Window Scale
	TCPOptSACKPermit uint8 = 4 // SACK-Permitted
	TCPOptTimestamp  uint8 = 8 // Timestamp
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
	Strategy string        `json:"strategy,omitempty"` // fixed, inc, random, pattern, list
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

// --- Phase 3 L7 protocol config placeholders. Each protocol's implementer
// fills in the struct body for their own protocol (and only their own).
// All structs are exported because FlowSpec fields use pointer-to-struct
// and the planner packages need to read/write fields. Keep each protocol's
// struct definition within the marked region to avoid git merge conflicts
// when 25 implementers work in parallel.

// DHCPConfig holds DHCPv4 protocol configuration (RFC 2131). DHCP is a session-level
// protocol over UDP on ports 67 (server) / 68 (client). The planner emits each message
// in Messages as a separate UDP datagram, sharing the same xid (transaction ID) and
// 4-tuple (one flow).
//
// Role selects the source/destination port pair:
// - "client" (default): SrcPort=68, DstPort=67; broadcast DISCOVER/REQUEST
// to 255.255.255.255 when client has no IP; unicast INFORM/RELEASE/
// RENEWING-REQUEST to known server when client has IP.
// - "server": SrcPort=67, DstPort=68; OFFER/ACK/NAK to client
// (broadcast or unicast per flags).
// - "relay": SrcPort=67, DstPort=67; forwards both directions,
// fills giaddr/hops/option 82 on incoming, strips/restores on outgoing.
type DHCPConfig struct {
	// Role selects the port pair and broadcast/unicast behavior.
	// Empty defaults to "client".
	Role string `json:"role,omitempty"`

	// Xid is the 4-byte transaction ID shared across all messages in
	// a session. 0 = random per session (recommended).
	Xid uint32 `json:"xid,omitempty"`

	// Messages is the ordered sequence of DHCP messages to emit.
	// Each message carries MessageType + per-message field overrides.
	// The planner emits one UDP datagram per message.
	Messages []DHCPMessage `json:"messages"`

	// ClientMAC is the chaddr field (16 bytes, right-padded with 0).
	// Empty = use spec.SrcMAC (Role="client") or spec.DstMAC (Role="server").
	ClientMAC string `json:"client_mac,omitempty"`

	// HType is the BOOTP hardware type (1=Ethernet). Default 1.
	HType uint8 `json:"h_type,omitempty"`

	// HLen is the hardware address length (6 for Ethernet). Default 6.
	HLen uint8 `json:"h_len,omitempty"`

	// BroadcastFlag, when true, sets flags=0x8000 (broadcast response).
	// Default false (0x0000, unicast response).
	BroadcastFlag bool `json:"broadcast_flag,omitempty"`

	// Secs is the seconds-since-start field. Default 0.
	Secs uint16 `json:"secs,omitempty"`

	// Sname is the server host name field (64 bytes). Optional.
	Sname string `json:"sname,omitempty"`

	// File is the boot file name field (128 bytes). Optional.
	File string `json:"file,omitempty"`

	// Default options inherited by all messages (per-message overrides win).
	DefaultClientIP string `json:"default_client_ip,omitempty"` // ciaddr
	DefaultYourIP string `json:"default_your_ip,omitempty"` // yiaddr
	DefaultServerIP string `json:"default_server_ip,omitempty"` // siaddr
	DefaultRelayAgentIP string `json:"default_relay_agent_ip,omitempty"` // giaddr
	DefaultServerIdentifier string `json:"default_server_identifier,omitempty"` // option 54
	DefaultLeaseTime uint32 `json:"default_lease_time,omitempty"` // option 51
	DefaultT1 uint32 `json:"default_t1,omitempty"` // option 58
	DefaultT2 uint32 `json:"default_t2,omitempty"` // option 59
	DefaultSubnetMask string `json:"default_subnet_mask,omitempty"` // option 1
	DefaultRouters []string `json:"default_routers,omitempty"` // option 3
	DefaultDNS []string `json:"default_dns,omitempty"` // option 6
	DefaultDomainName string `json:"default_domain_name,omitempty"` // option 15
	DefaultHostname string `json:"default_hostname,omitempty"` // option 12
	DefaultDomainSearch []string `json:"default_domain_search,omitempty"` // option 119
	DefaultClientID []byte `json:"default_client_id,omitempty"` // option 61
	DefaultRequestedIP string `json:"default_requested_ip,omitempty"` // option 50
	DefaultParamRequestList []uint8 `json:"default_param_request_list,omitempty"` // option 55
	DefaultVendorClass string `json:"default_vendor_class,omitempty"` // option 60
	DefaultRelayAgentInfo []byte `json:"default_relay_agent_info,omitempty"` // option 82
}

// DHCPMessage is a single DHCP message in a session.
type DHCPMessage struct {
	// Type is option 53 (DHCP Message Type):
	// 1=DISCOVER, 2=OFFER, 3=REQUEST, 4=DECLINE, 5=ACK, 6=NAK,
	// 7=RELEASE, 8=INFORM
	Type uint8 `json:"type"`

	// Direction "up" = client->server, "down" = server->client.
	// Empty = planner infers from Type.
	Direction string `json:"direction,omitempty"`

	// Per-message field overrides (empty = inherit from DHCPConfig).
	ClientIP string `json:"client_ip,omitempty"` // ciaddr
	YourIP string `json:"your_ip,omitempty"` // yiaddr
	ServerIP string `json:"server_ip,omitempty"` // siaddr
	RelayAgentIP string `json:"relay_agent_ip,omitempty"` // giaddr
	Hops uint8 `json:"hops,omitempty"`
	ServerIdentifier string `json:"server_identifier,omitempty"` // option 54
	LeaseTime uint32 `json:"lease_time,omitempty"` // option 51
	T1 uint32 `json:"t1,omitempty"` // option 58
	T2 uint32 `json:"t2,omitempty"` // option 59
	SubnetMask string `json:"subnet_mask,omitempty"` // option 1
	Routers []string `json:"routers,omitempty"` // option 3
	DNS []string `json:"dns,omitempty"` // option 6
	DomainName string `json:"domain_name,omitempty"` // option 15
	Hostname string `json:"hostname,omitempty"` // option 12
	DomainSearch []string `json:"domain_search,omitempty"` // option 119
	ClientID []byte `json:"client_id,omitempty"` // option 61
	RequestedIP string `json:"requested_ip,omitempty"` // option 50
	ParamRequestList []uint8 `json:"param_request_list,omitempty"` // option 55
	VendorClass string `json:"vendor_class,omitempty"` // option 60
	RelayAgentInfo []byte `json:"relay_agent_info,omitempty"` // option 82

	// ExtraOptions is a list of arbitrary options for testing rare or
	// vendor-specific options not covered above.
	ExtraOptions []DHCPOption `json:"extra_options,omitempty"`

	// Broadcast overrides DHCPConfig.BroadcastFlag for this message.
	Broadcast *bool `json:"broadcast,omitempty"`
}

// DHCPOption is a single raw DHCP option (TLV).
type DHCPOption struct {
	Code uint8 `json:"code"`
	Data []byte `json:"data,omitempty"`
}

// DHCPv6Config holds DHCPv6 protocol configuration. Fields populated by
// internal/protocol/dhcpv6 implementer per design_dhcpv6.md.
type DHCPv6Config struct {
	// Messages 是对话中的消息序列，按 wire 顺序输出。每条消息含
	// msg-type/transaction-id/options/direction。
	Messages []DHCPv6Message `json:"messages,omitempty"`

	// ClientDUID 是客户端标识（用于 ClientID option）。所有客户端消息
	// 共享同一个 DUID。nil = planner 自动生成 DUID-LLT 基于客户端 MAC。
	ClientDUID *DUID `json:"client_duid,omitempty"`

	// ServerDUID 是服务器标识（用于 ServerID option）。所有服务器消息
	// 共享同一个 DUID。nil = planner 自动生成 DUID-EN enterprise=0。
	ServerDUID *DUID `json:"server_duid,omitempty"`

	// RelayConfig 配置中继封装。nil = 不做中继封装（直连 client↔server）。
	RelayConfig *RelayConfig `json:"relay_config,omitempty"`
}

// DHCPv6Message 是一条 DHCPv6 消息（客户端/服务器/中继）。
type DHCPv6Message struct {
	// MsgType: 1-13。1-11 为客户端/服务器消息；12-13 为中继消息。
	// 当 MsgType=12/13 时，planner 使用 34 字节中继头，否则使用 4 字节标准头。
	MsgType uint8 `json:"msg_type"`

	// TransactionID: 3 字节事务 ID（transaction ID，事务标识符）。中继消息（12/13）不用此字段。
	// 全零 = planner 自动生成随机 XID；非零 = 用户指定（用于跨消息一致性）。
	TransactionID [3]byte `json:"transaction_id,omitempty"`

	// Direction: "up" = client→server, "down" = server→client。
	Direction string `json:"direction,omitempty"`

	// Options: 消息携带的 DHCPv6 选项列表，按用户指定顺序输出。
	Options []DHCPv6Option `json:"options,omitempty"`

	// RelayFields: 仅 MsgType=12/13 时使用。
	RelayFields *RelayFields `json:"relay_fields,omitempty"`
}

// RelayFields 是 RELAY-FORW/RELAY-REPL 的中继特定字段。
type RelayFields struct {
	HopCount    uint8  `json:"hop_count"`
	LinkAddress string `json:"link_address"`
	PeerAddress string `json:"peer_address"`
}

// DUID 标识客户端/服务器（DHCPv6 Unique Identifier，DHCPv6 唯一标识符）。
type DUID struct {
	Type            uint8  `json:"type"`                       // 1=LLT, 2=EN, 3=LL
	HardwareType    uint16 `json:"hardware_type,omitempty"`    // DUID-LLT/LL 用；1=Ethernet
	Time            uint32 `json:"time,omitempty"`              // DUID-LLT 用；自 2000-01-01 UTC 秒
	EnterpriseNum   uint32 `json:"enterprise_num,omitempty"`   // DUID-EN 用
	VendorSpecific  []byte `json:"vendor_specific,omitempty"`  // DUID-EN 用
	LinkLayerAddr   string `json:"link_layer_addr,omitempty"`  // MAC 地址字符串，如 "00:11:22:33:44:55"
}

// DHCPv6Option 是一个 TLV 选项。Code/LEN 由 planner 自动填，Data 是
// 选项的 OPTION_DATA 字段（已序列化的字节）。
type DHCPv6Option struct {
	Code uint16 `json:"code"` // OPTION_* 常量，如 1=ClientID
	Data []byte `json:"data,omitempty"` // 已序列化的 OPTION_DATA
}

// RelayConfig 配置中继封装行为。
type RelayConfig struct {
	// RelayIP: 中继代理的全球 IPv6 地址（用于 link-address）。
	RelayIP string `json:"relay_ip"`
	// RelayMAC: 中继代理的 MAC（用于 L2）。
	RelayMAC string `json:"relay_mac"`
	// HopCount: 起始 hop-count，默认 1。
	HopCount uint8 `json:"hop_count,omitempty"`
	// InterfaceID: 中继代理的接口标识（option 18），可为空。
	InterfaceID []byte `json:"interface_id,omitempty"`
	// IncludeClientMAC: 是否在 RELAY-FORW 中携带 option 79 (Client MAC)。
	IncludeClientMAC bool `json:"include_client_mac,omitempty"`
}

// GRPCConfig holds gRPC/HTTP2 telemetry protocol configuration. gRPC runs
// over HTTP/2 (h2c by default — cleartext HTTP/2). A single TCP/HTTP/2
// connection carries one or more streams (each a separate gRPC call); the
// planner emits a connection preface, SETTINGS exchange, then per-call
// HEADERS/DATA/trailers frames. See design_grpc.md for the full protocol
// field table.
type GRPCConfig struct {
	// Service is the fully-qualified gRPC service name, e.g.
	// "telemetry.Telemetry". Combined with Method to form :path =
	// "/<Service>/<Method>". Required.
	Service string `json:"service"`
	// Method is the gRPC method name, e.g. "Subscribe". Required.
	Method string `json:"method"`
	// Authority is the :authority pseudo-header value (host:port). When
	// empty, the planner uses DstIP:DstPort (bracketed for IPv6).
	Authority string `json:"authority,omitempty"`
	// Scheme is the :scheme pseudo-header value. "http" (h2c, default) or
	// "https".
	Scheme string `json:"scheme,omitempty"`
	// CallType selects the gRPC call pattern:
	//   "unary" (default): 1 request + 1 response
	//   "server-stream": 1 request + N responses
	//   "client-stream": N requests + 1 response
	//   "bidi-stream": N requests + M responses
	CallType string `json:"call_type,omitempty"`
	// RequestMessages is the list of protobuf-encoded request messages.
	// Each entry is the raw protobuf bytes (without the 5-byte gRPC
	// length-prefix; the planner adds it). unary/server-stream: 1 entry;
	// client-stream/bidi: N entries. When empty, the planner emits a single
	// zero-length request message (5-byte gRPC prefix with Length=0).
	RequestMessages [][]byte `json:"request_messages,omitempty"`
	// RequestMessagesB64 is the base64-encoded form of RequestMessages,
	// for JSON embedding of binary protobuf. Takes precedence over
	// RequestMessages when both are set. Each string is decoded
	// independently; decode failure is a Validate error.
	RequestMessagesB64 []string `json:"request_messages_b64,omitempty"`
	// ResponseMessages is the list of protobuf-encoded response messages
	// the server emits. unary: 1; server-stream/bidi: N; client-stream:
	// 1. The planner emits these verbatim (no RPC semantics enforcement).
	ResponseMessages [][]byte `json:"response_messages,omitempty"`
	// ResponseMessagesB64 is the base64-encoded form of
	// ResponseMessages. Takes precedence over ResponseMessages when both
	// are set.
	ResponseMessagesB64 []string `json:"response_messages_b64,omitempty"`
	// ResponseStatus is the grpc-status trailer value, 0-16. Defaults to
	// 0 (OK). Out-of-range values are a Validate error.
	ResponseStatus int `json:"response_status,omitempty"`
	// ResponseMessage is the grpc-message trailer value (human-readable
	// error text). The planner URL-encodes per gRPC spec §4 when it
	// contains characters outside the printable ASCII range.
	ResponseMessage string `json:"response_message,omitempty"`
	// Timeout is the grpc-timeout header value, format "<N><unit>" where
	// unit is one of n/u/m/S/M/H. Empty = no grpc-timeout header sent.
	Timeout string `json:"timeout,omitempty"`
	// Encoding is the grpc-encoding header value: "identity" (default) or
	// "gzip". When "gzip", the planner gzip-compresses each request and
	// response message body and sets Compressed-Flag=1 in the gRPC
	// length-prefix.
	Encoding string `json:"encoding,omitempty"`
	// AcceptEncoding is the grpc-accept-encoding header value. Defaults
	// to "identity, gzip".
	AcceptEncoding string `json:"accept_encoding,omitempty"`
	// Metadata holds application-level custom headers (e.g.
	// "authorization": "Bearer ...", "x-trace-id": "abc"). Keys with the
	// prefix "authorization" (case-insensitive) are encoded with the
	// HPACK "Never Indexed" bit to prevent index-table leakage of
	// credentials. Other keys use "Incremental Indexing".
	Metadata map[string]string `json:"metadata,omitempty"`
	// UserAgent is the user-agent header value. Defaults to
	// "grpc-trafficgen/1.0".
	UserAgent string `json:"user_agent,omitempty"`
	// MaxFrameSize is the SETTINGS_MAX_FRAME_SIZE value, 16384-16777215.
	// 0 = 16384 (default). Out-of-range is a Validate error.
	MaxFrameSize uint32 `json:"max_frame_size,omitempty"`
	// InitialWindow is the SETTINGS_INITIAL_WINDOW_SIZE value, 0-2147483647
	// (RFC 7540 §6.5.2: max is 2^31-1). 0 = 65535 (default).
	InitialWindow uint32 `json:"initial_window,omitempty"`
	// MaxConcurrentStreams is the SETTINGS_MAX_CONCURRENT_STREAMS value.
	// 0 = omit the setting (no advertised limit).
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams,omitempty"`
	// HeaderTableSize is the SETTINGS_HEADER_TABLE_SIZE value (HPACK
	// dynamic table size in bytes). 0 = 4096 (default).
	HeaderTableSize uint32 `json:"header_table_size,omitempty"`
	// Pings configures PING frame emission for keepalive. nil = no PING
	// frames.
	Pings *GRPCPingConfig `json:"pings,omitempty"`
	// CancelAfter is the number of milliseconds after sending the request
	// HEADERS+DATA before the client emits RST_STREAM (error=CANCEL) on
	// the stream. 0 = no cancellation.
	CancelAfter int `json:"cancel_after,omitempty"`
	// GoAwayAfter controls whether the server emits a GOAWAY frame after
	// all streams complete. Default true (graceful close).
	GoAwayAfter bool `json:"go_away_after,omitempty"`
	// Calls is the list of independent gRPC calls multiplexed on the same
	// HTTP/2 connection (each gets its own stream ID). When non-empty, the
	// planner emits each call in order; the top-level Service/Method/etc
	// fields describe a single call only when Calls is empty.
	Calls []GRPCCall `json:"calls,omitempty"`
	// FileSource, when set, overrides RequestMessages[0] with bytes
	// loaded via PayloadCache.GetOrLoad. Mutually exclusive with
	// RequestMessagesB64; takes precedence over RequestMessages.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// GRPCCall describes one gRPC call on a shared HTTP/2 connection. Each
// call gets its own stream ID (client-initiated, odd, monotonically
// increasing). All calls in a Calls list share the connection-level
// SETTINGS exchange and HPACK dynamic table.
type GRPCCall struct {
	Service          string            `json:"service"`
	Method           string            `json:"method"`
	CallType         string            `json:"call_type,omitempty"`
	RequestMessages  [][]byte          `json:"request_messages,omitempty"`
	ResponseMessages [][]byte          `json:"response_messages,omitempty"`
	ResponseStatus   int               `json:"response_status,omitempty"`
	ResponseMessage  string            `json:"response_message,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
}

// GRPCPingConfig configures PING frame emission on the HTTP/2 connection.
// PING frames are keepalive probes: the client sends PING with 8 bytes of
// opaque data, the server echoes them back in a PING ACK.
type GRPCPingConfig struct {
	// IntervalMs is the milliseconds between PING frames. 0 = 30000
	// (30s, gRPC default keepalive interval).
	IntervalMs int `json:"interval_ms,omitempty"`
	// Count is the total number of PING frames to send. 0 = 1.
	Count int `json:"count,omitempty"`
	// OpaqueData is the 8-byte payload for the PING frame. When all zero,
	// the planner uses an incrementing counter starting at 1.
	OpaqueData [8]byte `json:"opaque_data,omitempty"`
}

// IKEConfig holds IKEv2 protocol configuration per RFC 7296. Fields are
// populated by internal/protocol/ike per design_ike.md. Defaults are applied
// in the ike planner's Plan goroutine (per validate_conventions.md §1.3 —
// Validate is read-only).
type IKEConfig struct {
	// VersionMajor / VersionMinor encode the IKE version. Default 2.0
	// (RFC 7296). 1.0 selects IKEv1 (RFC 2409) compatibility mode and
	// disables the IKEv2 state machine.
	VersionMajor uint8 `json:"version_major,omitempty"` // default 2
	VersionMinor uint8 `json:"version_minor,omitempty"` // default 0

	// InitiatorSPI / ResponderSPI are the 64-bit Security Parameter Indices.
	// InitiatorSPI=0 with Role=initiator means the planner derives a
	// deterministic non-zero value from OpaqueKeySeed. ResponderSPI=0 on
	// the first INIT request is mandatory (RFC 7296 §1.2).
	InitiatorSPI uint64 `json:"initiator_spi,omitempty"`
	ResponderSPI uint64 `json:"responder_spi,omitempty"`

	// StartMessageID overrides the initial Message ID (normally 0).
	StartMessageID uint32 `json:"start_message_id,omitempty"`

	// Role: "initiator" (default) or "responder".
	Role string `json:"role,omitempty"`

	// Strict enforces RFC 7296 semantics (reject malformed fields).
	// FaultInjection permits explicit malformed field overrides.
	Strict         bool `json:"strict,omitempty"`
	FaultInjection bool `json:"fault_injection,omitempty"`

	// Messages is an explicit sequence of IKE messages. When non-empty,
	// the planner emits them verbatim. Scenario expands to a built-in
	// template. Setting both is rejected by Validate.
	Messages []IKEMessage `json:"messages,omitempty"`
	Scenario string       `json:"scenario,omitempty"`

	// DefaultProposal is used by scenario templates when an individual
	// message does not override it.
	DefaultProposal *IKEProposal `json:"default_proposal,omitempty"`

	// DefaultDHGroup is the DH Transform ID used by templates (default 14 =
	// 2048-bit MODP, RFC 7296 §14.3).
	DefaultDHGroup uint16 `json:"default_dh_group,omitempty"`

	// DefaultNonceSize is the nonce byte length (default 32, range 16..256
	// per RFC 7296 §3.9).
	DefaultNonceSize uint16 `json:"default_nonce_size,omitempty"`

	// DefaultAuthMethod is the AUTH payload method (1=RSA, 2=Shared Key,
	// 9=ECDSA, 13=NULL per RFC 7296 §3.10).
	DefaultAuthMethod uint8 `json:"default_auth_method,omitempty"`

	// AllowNullAuth permits AUTH Method=13 (RFC 7619). Default false to
	// avoid accidentally emitting unauthenticated sessions.
	AllowNullAuth bool `json:"allow_null_auth,omitempty"`

	// EAPOnly enables RFC 5998 EAP-only authentication (initiator omits
	// traditional AUTH).
	EAPOnly bool `json:"eap_only,omitempty"`

	// FragmentationSupported advertises IKEV2_FRAGMENTATION_SUPPORTED
	// (RFC 7383). FragmentThreshold is the byte limit above which an SK
	// payload is split into SKF (type 53) fragments. 0 = no SKF.
	FragmentationSupported bool   `json:"fragmentation_supported,omitempty"`
	FragmentThreshold      uint16 `json:"fragment_threshold,omitempty"`

	// ChildSAs configures CHILD SA creations for scenario templates.
	ChildSAs []IKEChildSA `json:"child_sas,omitempty"`

	// DPDCount emits N empty INFORMATIONAL DPD exchanges after ESTABLISHED.
	DPDCount int `json:"dpd_count,omitempty"`

	// RetransmitCount is the default per-message retransmission count.
	RetransmitCount int `json:"retransmit_count,omitempty"`

	// EncryptMode must be "opaque" (default). Real crypto modes are
	// rejected — the planner does not perform AES/HMAC/PRF/DH.
	EncryptMode string `json:"encrypt_mode,omitempty"`

	// OpaqueKeySeed seeds the deterministic pseudo-byte generator for
	// SK/SKF/KE/NONCE/AUTH data. 0 = derive from InitiatorSPI.
	OpaqueKeySeed uint64 `json:"opaque_key_seed,omitempty"`
}

// IKEMessage is a single IKE message (one UDP datagram on port 500).
type IKEMessage struct {
	// Direction: "up" (initiator→responder) or "down" (responder→initiator).
	Direction string `json:"direction"`

	// ExchangeType per RFC 7296 §3.1: 34=IKE_SA_INIT, 35=IKE_SA_AUTH,
	// 36=CREATE_CHILD_SA, 37=INFORMATIONAL, 38=IKE_SESSION_RESUME,
	// 43=IKE_INTERMEDIATE (RFC 8784).
	ExchangeType uint8 `json:"exchange_type"`

	// IsResponse sets the R flag. FromOriginalInitiator sets the I flag.
	// HigherVersionSupported sets the V flag (RFC 7296 §3.1).
	IsResponse             bool `json:"is_response,omitempty"`
	FromOriginalInitiator  bool `json:"from_original_initiator,omitempty"`
	HigherVersionSupported bool `json:"higher_version_supported,omitempty"`

	// MessageID, if nil, is derived from the sequence position. If set,
	// it overrides the sequential counter (used for explicit fault tests).
	MessageID *uint32 `json:"message_id,omitempty"`

	// InitiatorSPI / ResponderSPI, if nil, inherit from IKEConfig.
	InitiatorSPI *uint64 `json:"initiator_spi,omitempty"`
	ResponderSPI *uint64 `json:"responder_spi,omitempty"`

	// Payloads is the cleartext payload chain. When Encrypted is set, the
	// payloads go inside an SK (type 46) payload.
	Payloads []IKEPayload `json:"payloads,omitempty"`

	// Encrypted wraps the payloads in an SK payload. When nil, the
	// Payloads are emitted as cleartext (only valid for IKE_SA_INIT or
	// fault injection).
	Encrypted *IKEEncryptedBody `json:"encrypted,omitempty"`

	// Retransmit emits N exact byte-identical copies of this message.
	Retransmit int `json:"retransmit,omitempty"`

	// DelayMillis adds a virtual inter-message delay (metadata only).
	DelayMillis int `json:"delay_ms,omitempty"`

	// RawLengthOverride / RawNextPayloadOverride / RawFlagsOverride are
	// fault-injection overrides for the IKE Header fields. Only honored
	// when FaultInjection=true.
	RawLengthOverride      *uint32 `json:"raw_length_override,omitempty"`
	RawNextPayloadOverride *uint8  `json:"raw_next_payload_override,omitempty"`
	RawFlagsOverride       *uint8  `json:"raw_flags_override,omitempty"`
}

// IKEPayload is the union of all IKE payload types (RFC 7296 §3.2).
// Type is the IANA wire value (33=SA, 34=KE, 35=IDi, 36=IDr, 37=CERT,
// 38=CERTREQ, 39=AUTH, 40=NONCE, 41=NOTIFY, 42=DELETE, 43=VENDOR,
// 44=TS_i, 45=TS_r, 46=SK, 47=CP, 48=EAP, 53=SKF).
type IKEPayload struct {
	Type     uint8 `json:"type"`
	Critical bool  `json:"critical,omitempty"`

	SA                 *IKESA                 `json:"sa,omitempty"`
	KE                 *IKEKE                 `json:"ke,omitempty"`
	ID                 *IKEIdentity           `json:"id,omitempty"`
	Certificate        *IKECertificate        `json:"certificate,omitempty"`
	CertificateRequest *IKECertificateRequest `json:"certificate_request,omitempty"`
	Auth               *IKEAuth               `json:"auth,omitempty"`
	Nonce              []byte                 `json:"nonce,omitempty"`
	Notify             *IKENotify             `json:"notify,omitempty"`
	Delete             *IKEDelete             `json:"delete,omitempty"`
	VendorID           []byte                 `json:"vendor_id,omitempty"`
	TrafficSelectors   []IKETrafficSelector   `json:"traffic_selectors,omitempty"`
	Config             *IKEConfiguration      `json:"config,omitempty"`
	EAP                *IKEEAP                `json:"eap,omitempty"`
	Fragment           *IKEFragment           `json:"fragment,omitempty"`

	// Raw is the opaque payload body (used for unknown types or fault
	// injection). When non-empty, it overrides the typed encoder.
	Raw []byte `json:"raw,omitempty"`

	// RawLengthOverride / RawNextPayloadOverride are fault-injection
	// overrides for the Generic Payload Header.
	RawLengthOverride      *uint16 `json:"raw_length_override,omitempty"`
	RawNextPayloadOverride *uint8  `json:"raw_next_payload_override,omitempty"`
}

// IKEProposal is a Proposal Substructure inside an SA payload (RFC 7296
// §3.3.1).
type IKEProposal struct {
	Number     uint8          `json:"number"`
	ProtocolID uint8          `json:"protocol_id"` // 1=IKE, 2=AH, 3=ESP
	SPI        []byte         `json:"spi,omitempty"`
	Transforms []IKETransform `json:"transforms"`
}

// IKETransform is a Transform Substructure (RFC 7296 §3.3.2).
type IKETransform struct {
	Type          uint8  `json:"type"` // 1=ENCR, 2=PRF, 3=INTEG, 4=D-H, 5=ESN
	ID            uint16 `json:"id"`
	KeyLengthBits uint16 `json:"key_length_bits,omitempty"`
	RawAttributes []byte `json:"raw_attributes,omitempty"`
}

// IKESA is the body of an SA payload (type 33).
type IKESA struct {
	Proposals []IKEProposal `json:"proposals"`
}

// IKEKE is the body of a KE payload (type 34).
type IKEKE struct {
	DHGroup uint16 `json:"dh_group"`
	KeyData []byte `json:"key_data,omitempty"` // empty = derive from seed
}

// IKEIdentity is the body of an IDi (35) or IDr (36) payload.
type IKEIdentity struct {
	IDType uint8  `json:"id_type"` // 1=IPv4, 2=FQDN, 3=RFC822, 5=IPv6, 11=KEY_ID
	Data   []byte `json:"data"`
}

// IKECertificate is the body of a CERT payload (type 37).
type IKECertificate struct {
	Encoding uint8  `json:"encoding"` // 4=X.509 Signature, etc.
	Data     []byte `json:"data"`
}

// IKECertificateRequest is the body of a CERTREQ payload (type 38).
type IKECertificateRequest struct {
	Encoding uint8    `json:"encoding"`
	CAs      [][]byte `json:"cas"` // SHA-1 hashes of acceptable CA DNs
}

// IKEAuth is the body of an AUTH payload (type 39).
type IKEAuth struct {
	Method uint8  `json:"method"` // 1=RSA, 2=Shared Key, 9=ECDSA, 13=NULL
	Data   []byte `json:"data"`
}

// IKENotify is the body of a NOTIFY payload (type 41).
type IKENotify struct {
	ProtocolID  uint8  `json:"protocol_id,omitempty"` // 0=None, 1=IKE, 2=AH, 3=ESP
	SPI         []byte `json:"spi,omitempty"`
	MessageType uint16 `json:"message_type"`
	Data        []byte `json:"data,omitempty"`
}

// IKEDelete is the body of a DELETE payload (type 42).
type IKEDelete struct {
	ProtocolID uint8    `json:"protocol_id"` // 1=IKE, 2=AH, 3=ESP
	SPISize    uint8    `json:"spi_size"`    // IKE=0, AH/ESP=4
	SPIs       [][]byte `json:"spis,omitempty"`
}

// IKETrafficSelector is a single Traffic Selector substructure (RFC 7296
// §3.13.1). Used inside TS_i (44) and TS_r (45) payloads.
type IKETrafficSelector struct {
	TSType       uint8  `json:"ts_type"`        // 7=IPv4_RANGE, 8=IPv6_RANGE
	IPProtocolID uint8  `json:"ip_protocol_id"` // 0=any, 6=TCP, 17=UDP
	StartPort    uint16 `json:"start_port"`
	EndPort      uint16 `json:"end_port"`
	StartAddress []byte `json:"start_address"` // 4 or 16 bytes
	EndAddress   []byte `json:"end_address"`   // 4 or 16 bytes
}

// IKEConfiguration is the body of a CP payload (type 47).
type IKEConfiguration struct {
	CFGType    uint8                `json:"cfg_type"` // 1=REQUEST, 2=REPLY, 3=SET, 4=ACK
	Attributes []IKEConfigAttribute `json:"attributes,omitempty"`
}

// IKEConfigAttribute is a single CP attribute (TLV or TV form).
type IKEConfigAttribute struct {
	Type  uint16 `json:"type"`
	Value []byte `json:"value,omitempty"`
}

// IKEEAP is the body of an EAP payload (type 48, RFC 3748).
type IKEEAP struct {
	Code       uint8  `json:"code"`        // 1=Request, 2=Response, 3=Success, 4=Failure
	Identifier uint8  `json:"identifier"`
	Type       *uint8 `json:"type,omitempty"` // nil for Success/Failure
	Data       []byte `json:"data,omitempty"`
}

// IKEEncryptedBody is the cleartext-inside-SK description. The planner
// serializes InnerPayloads, then pads/wraps with opaque IV/Ciphertext/ICV.
// OpaqueData, when non-empty, replaces the derived ciphertext bytes.
type IKEEncryptedBody struct {
	InnerPayloads []IKEPayload `json:"inner_payloads,omitempty"`
	OpaqueData    []byte       `json:"opaque_data,omitempty"`
	IVLength      uint16       `json:"iv_length,omitempty"`  // default 16
	ICVLength     uint16       `json:"icv_length,omitempty"` // default 16
	PadTo         uint16       `json:"pad_to,omitempty"`     // 0 = no padding
}

// IKEFragment is the body of an SKF payload (type 53, RFC 7383).
type IKEFragment struct {
	FragmentNumber uint16 `json:"fragment_number"`
	TotalFragments uint16 `json:"total_fragments"`
	Data           []byte `json:"data"`
}

// IKEChildSA configures a CHILD SA creation (used by scenario templates).
type IKEChildSA struct {
	Proposal    *IKEProposal         `json:"proposal,omitempty"`
	TSi         []IKETrafficSelector `json:"ts_i,omitempty"`
	TSr         []IKETrafficSelector `json:"ts_r,omitempty"`
	EmitSubFlow bool                 `json:"emit_sub_flow,omitempty"`
}

// IKENATTConfig holds IKE-NAT-T protocol configuration. Fields populated
// by internal/protocol/ike_nat_t implementer per design_ike_nat_t.md.
//
// IKE-NAT-T (IKEv2 NAT 穿透扩展, IKEv2 NAT Traversal extension) extends
// IKEv2 (RFC 7296) with NAT-Traversal (RFC 3947/3948) — Non-ESP Marker (4
// bytes 0x00000000), NAT-D/NAT-OA payloads, UDP-ESP encapsulation, and
// NAT-keepalive (1 byte 0xFF). The default port is 4500 (floated from 500).
type IKENATTConfig struct {
	// InitiatorSPI 是发起方 SPI（8 字节）。0 = planner 自动生成。IKE 生命周期内不变。
	InitiatorSPI uint64 `json:"initiator_spi,omitempty"`

	// ResponderSPI 是响应方 SPI（8 字节）。IKE_SA_INIT 请求阶段为 0；
	// 后续交换从响应方 IKE_SA_INIT 响应中学习。
	ResponderSPI uint64 `json:"responder_spi,omitempty"`

	// NATDetection 控制是否在 IKE_SA_INIT 中发送 NAT-D Notify。
	// true = 携带 NAT_DETECTION_SOURCE_IP + NAT_DETECTION_DESTINATION_IP
	NATDetection bool `json:"nat_detection,omitempty"`

	// NATDetectedOnSource 表示发起方->响应方方向是否检测到 NAT。
	// true = 触发端口浮动 + UDP-ESP 封装 + 周期 keepalive
	NATDetectedOnSource bool `json:"nat_detected_on_source,omitempty"`

	// NATDetectedOnDest 表示响应方->发起方方向是否检测到 NAT。
	NATDetectedOnDest bool `json:"nat_detected_on_dest,omitempty"`

	// PortFloat 控制是否在 NAT 检测后进行端口浮动 500->4500。
	PortFloat bool `json:"port_float,omitempty"`

	// UDPEncapESP 控制是否对 ESP 报文进行 UDP-ESP 封装。
	UDPEncapESP bool `json:"udp_encap_esp,omitempty"`

	// Keepalive 控制周期发送 NAT-keepalive (1 字节 0xFF)。
	// 仅在 NATDetectedOnSource/Dest = true 时生效。
	Keepalive *NATKeepaliveConfig `json:"keepalive,omitempty"`

	// Retransmit 控制 IKE_SA_INIT 请求的重传策略（RFC 7296 §2.2）。
	// nil = 使用默认值（Timeout=500ms, MaxRetransmits=5, Backoff=2.0）。
	Retransmit *RetransmitConfig `json:"retransmit,omitempty"`

	// Dialog 是 IKE 消息序列（IKE_SA_INIT 请求/响应, IKE_AUTH 请求/响应, ...）。
	// 每条消息携带方向 (up/down) + Exchange Type + Payloads。
	Dialog []IKENATTMessage `json:"dialog,omitempty"`

	// ChildSA 描述 IKE_AUTH 后建立的 Child SA，用于 ESP-in-UDP 子流。
	// nil = 不建立 Child SA（仅 IKE 协商）。
	ChildSA *ESPChildSAConfig `json:"child_sa,omitempty"`
}

// NATKeepaliveConfig 配置 NAT-keepalive 周期发送。
type NATKeepaliveConfig struct {
	// Interval 是 keepalive 发送周期（秒）。0 = 默认 20s。
	Interval int `json:"interval,omitempty"`
	// Count 是 keepalive 报文数。0 = 1 个；正数 N = 发送 N 个。
	Count int `json:"count,omitempty"`
	// Direction 控制哪个方向发送 keepalive。"up" = 发起方->响应方；
	// "down" = 响应方->发起方；"both" = 双方均发送。
	Direction string `json:"direction,omitempty"`
}

// RetransmitConfig 配置 IKE_SA_INIT 请求的重传策略（RFC 7296 §2.2）。
type RetransmitConfig struct {
	// Timeout 是首次重传超时（毫秒）。0 = 默认 500ms。
	Timeout int `json:"timeout,omitempty"`
	// MaxRetransmits 是最大重传次数。0 = 不重传；默认 5。
	MaxRetransmits int `json:"max_retransmits,omitempty"`
	// Backoff 是指数退避因子。0 = 默认 2.0；小于 1.0 被 Validate 拒绝。
	Backoff float64 `json:"backoff,omitempty"`
}

// IKENATTMessage 是 IKE-NAT-T 对话中的一条消息。
type IKENATTMessage struct {
	// Direction: "up" = 发起方->响应方；"down" = 响应方->发起方。
	Direction string `json:"direction"`
	// ExchangeType: 34=IKE_SA_INIT, 35=IKE_AUTH, 37=INFORMATIONAL, ...
	ExchangeType uint8 `json:"exchange_type"`
	// MessageID: 此消息的 ID；IKE_SA_INIT 双方均从 0 开始。
	MessageID uint32 `json:"message_id,omitempty"`
	// Payloads: 此消息携带的 IKE payload 列表（SAi/KEi/Ni/NAT-D/NAT-OA/...）。
	Payloads []IKENATTPayload `json:"payloads,omitempty"`
}

// IKENATTPayload 描述 IKE payload。OneOf 风格（一个字段对应一种 payload 类型）。
type IKENATTPayload struct {
	// Type: 33=SA, 34=KE, 40=Nonce, 41=Notify (含 NAT-D), 53=Encrypted, ...
	Type uint8 `json:"type"`
	// 各 payload 类型对应的数据（仅一个非 nil）
	SA     *IKESA      `json:"sa,omitempty"`
	KE     *IKEKE      `json:"ke,omitempty"`
	Nonce  []byte      `json:"nonce,omitempty"`
	Notify *NotifyPayload `json:"notify,omitempty"`

	// Raw 是原始 payload 体（用于故障注入或未知类型）。
	Raw []byte `json:"raw,omitempty"`
}

// NotifyPayload 描述 IKE Notify payload。NAT 检测 Notify 携带 20 字节 SHA-1。
type NotifyPayload struct {
	ProtocolID      uint8  `json:"protocol_id,omitempty"`
	SPISize         uint8  `json:"spi_size,omitempty"`
	NotifyMsgType   uint16 `json:"notify_msg_type"`
	NotificationData []byte `json:"notification_data,omitempty"`
}

// ESPChildSAConfig 描述建立 Child SA 后的 ESP 子流配置。
type ESPChildSAConfig struct {
	// SPIout 是发送方出方向 SPI（4 字节）。0 = planner 自动分配。
	SPIout uint32 `json:"spi_out,omitempty"`
	// SPIin 是接收方入方向 SPI（4 字节）。从对端 IKE_AUTH 中学习。
	SPIin uint32 `json:"spi_in,omitempty"`
	// ESPDataSize 是每个 ESP 报文承载的加密数据字节数。0 = 默认 100 字节。
	ESPDataSize int `json:"esp_data_size,omitempty"`
	// ESPCount 是 ESP 报文数量。0 = 1。
	ESPCount int `json:"esp_count,omitempty"`
	// Algorithm 是 ESP 加密/认证算法（仅元数据，本 planner 不实现真正加密）。
	Algorithm string `json:"algorithm,omitempty"`
	// Mode: "tunnel" = 整 IP 包加密；"transport" = 仅上层 PDU 加密
	Mode string `json:"mode,omitempty"`
}

// IMAPConfig holds IMAP4rev2 (Internet Message Access Protocol version 4
// revision 2, 因特网邮件访问协议第四版第二修订) protocol configuration per
// RFC 9051. IMAP is a session-level mail-retrieval protocol on TCP port
// 143; a single TCP connection carries a sequence of tagged client
// commands and tagged / untagged / continuation server responses across
// four states (NOT-AUTHENTICATED → AUTHENTICATED → SELECTED → LOGOUT).
//
// The planner emits:
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP/POP3 control-channel pattern.
//  2. Optional server greeting (e.g. "* OK [CAPABILITY IMAP4rev2 ...]
//     imap.example.com ready") as the first PSH-ACK payload. Real IMAP
//     servers send this greeting right after the handshake.
//  3. For each IMAPCommand: client command (PSH-ACK up) + one or more
//     server responses (PSH-ACK down). Multi-response sequences model
//     tagged/untagged/continuation interleaving per RFC 9051 §2.2.4.
//  4. Optional IMAP IDLE mode (RFC 2177) per cmd.EmitIDLE: the planner
//     emits "+ idling" continuation, any IDLE.PushResponses (server
//     pushes), the "DONE" terminator from the client, the IDLE
//     completion tagged response, and (optionally) a server timeout
//     BYE per IDLE.ServerTimeoutBehavior.
//  5. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// IMAP literals (the "{N}\r\n<N bytes>" syntax used by APPEND and
// FETCH BODY[]) are synthesized from LiteralBody / LiteralBodyB64 /
// FileSource on a per-command basis. FileSource takes precedence over
// LiteralBodyB64 over LiteralBody. Payloads longer than MSS are
// segmented; each segment advances the sender's sequence number by its
// byte length.
//
// The planner does NOT enforce IMAP state-machine transitions or
// tag-matching. The user is responsible for providing a syntactically
// valid dialog (LOGIN before SELECT, DONE to exit IDLE, LOGOUT to end).
// This matches the trafficgen contract: synthesize test packets, not a
// real IMAP server.
//
// IPv6 behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. IMAP is "transparent"
// for IP version (works over IPv4 or IPv6); it is unicast-only.
type IMAPConfig struct {
	// Banner is the optional server greeting emitted as the first
	// PSH-ACK payload after the TCP handshake. Real IMAP servers send
	// something like:
	//   "* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED] \
	//      imap.example.com ready\r\n"
	// Empty = no greeting. When set, the planner appends "\r\n" if the
	// user did not include it (single-line untagged greeting per RFC
	// 9051 §2.2; multi-line greeting format is the user's
	// responsibility).
	Banner string `json:"banner,omitempty"`

	// Commands is the ordered list of IMAP commands the client issues
	// in this session. Each IMAPCommand emits one client command
	// (PSH-ACK up) and one or more server responses (PSH-ACK down),
	// plus optional IDLE mode and optional literal body.
	Commands []IMAPCommand `json:"commands,omitempty"`

	// IDLE is the session-wide IMAP IDLE configuration (RFC 2177).
	// When non-nil, IDLE entries inside individual IMAPCommand entries
	// (via EmitIDLE) reference this struct for push responses, DONE
	// tag/response, and server-timeout behavior. Per-command IDLE
	// parameters are not duplicated here to keep the design simple;
	// when you need per-command IDLE variation, use multiple sessions.
	// NOTE: as designed in design_imap.md §7.1, IDLE parameters live
	// on IMAPIDLE rather than on IMAPCommand. The EmitIDLE bool on
	// IMAPCommand simply toggles whether this command enters IDLE mode
	// using the session-wide IMAPConfig.IDLE settings.
	IDLE *IMAPIDLE `json:"idle,omitempty"`

	// PipelinedCommands, when true, emits multiple client commands
	// back-to-back in a single PSH-ACK burst (no server-response ACK
	// between them). Mirrors RFC 9051 §5.4 / RFC 3501 §2.2.2 pipelining.
	// When false (default), the planner emits each command followed by
	// its responses before the next command, matching the on-the-wire
	// semantics of non-pipelined IMAP clients. See edge case
	// C-IMAP-1.5.
	PipelinedCommands bool `json:"pipelined_commands,omitempty"`

	// AllowUTF8Mailbox, when true, permits 8-bit mailbox names per
	// RFC 6855 (UTF-8 mailbox names). When false (default), the planner
	// rejects any IMAPCommand.Cmd whose mailbox argument contains
	// bytes with the high bit set (Validate error C-IMAP-1.7). When
	// true, the planner passes 8-bit mailbox names through verbatim.
	AllowUTF8Mailbox bool `json:"allow_utf8_mailbox,omitempty"`
}

// IMAPCommand represents one IMAP client command and its expected server
// responses. The planner emits the command (PSH-ACK up) and then each
// response in order (PSH-ACK down). Multi-response sequences model
// tagged/untagged/continuation interleaving (e.g. an untagged "*"
// SEARCH response before a tagged "A001 OK SEARCH completed" response).
type IMAPCommand struct {
	// Tag is the client command tag, e.g. "A001". RFC 9051 §2.2.1: tag
	// is 1-128 chars, must not contain CR/LF. When empty, the planner
	// auto-generates tags A001, A002, ... per RFC 9051 §2.2.1
	// recommendation. Tag mismatch between command and tagged response
	// is the user's responsibility (planner does NOT validate; see edge
	// case C-IMAP-1.4).
	Tag string `json:"tag,omitempty"`

	// Cmd is the IMAP command line WITHOUT the tag and WITHOUT the
	// trailing CRLF, e.g. "LOGIN alice secret". The planner
	// synthesizes "<tag> <cmd>\r\n" on the wire (RFC 9051 §2.2.1).
	// Must not contain CRLF (planner rejects with a Validate error).
	// When Cmd is empty, the planner skips the command packet (lets
	// users model server-only turns, e.g. for AUTHENTICATE cancellation
	// where the client sends "*\r\n" instead of credentials — use a
	// dedicated EmitIDLE-free IMAPCommand with just Responses for that).
	Cmd string `json:"cmd,omitempty"`

	// Responses is the ordered list of server responses emitted as
	// PSH-ACK packets down after the client command. Each entry is one
	// response line; the planner appends "\r\n" to single-line
	// responses (untagged "*" / tagged "<tag>" / continuation "+").
	// For multi-line responses (e.g. FETCH BODY[] literals), the user
	// includes the literal bytes verbatim in the entry; the planner
	// emits them unchanged. To emit a "{N}\r\n<N bytes>" literal
	// without manually building the wire format, use LiteralBody /
	// LiteralBodyB64 / FileSource instead and let the planner
	// synthesize it.
	Responses []string `json:"responses,omitempty"`

	// LiteralBody is the IMAP literal payload (the bytes that follow
	// the "{N}\r\n" prefix on the wire). When set, the planner
	// synthesizes a multi-response sequence:
	//   1. server response line ending in "{N}\r\n" (continuation, +)
	//   2. the literal payload bytes (PSH-ACK down, segmented by MSS)
	//   3. the user-provided responses continue (tagged completion, ...)
	// where N = len(LiteralBody). The "{" + N + "}\r\n" prefix is
	// appended to the LAST entry in Responses (typically the
	// untagged "+" continuation from the server before the literal).
	// LiteralBody and LiteralBodyB64 and FileSource are mutually
	// exclusive; precedence: FileSource > LiteralBodyB64 > LiteralBody.
	// Empty = no literal.
	LiteralBody string `json:"literal_body,omitempty"`

	// LiteralBodyB64 is the base64-encoded form of LiteralBody, for
	// JSON embedding of binary blobs (e.g. raw APPEND message bytes).
	// Takes precedence over LiteralBody when both are set. The planner
	// base64-decodes it; decode failure is a Validate error. Empty =
	// use LiteralBody instead.
	LiteralBodyB64 string `json:"literal_body_b64,omitempty"`

	// FileSource is the file-based literal payload per the unified
	// FileSource pattern (see pkg/filesystem/types.go). Takes
	// precedence over LiteralBody / LiteralBodyB64 when set. The
	// planner loads the file via the PayloadCache and uses the loaded
	// bytes as the literal payload. The {N} prefix is synthesized from
	// the loaded byte length. When FileSource is set but no
	// PayloadCache is present in ctx, the planner returns silently
	// without emitting the literal packet (matches the FTP contract;
	// see edge case C-IMAP-1.1 for cross-segment PSH-ACK semantics).
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`

	// EmitIDLE, when true, marks this command as entering IMAP IDLE
	// mode (RFC 2177). The planner emits:
	//   1. The client command "IDLE\r\n" (Cmd is ignored when
	//      EmitIDLE=true; the planner synthesizes the IDLE command).
	//   2. Server "+ idling" continuation (per IMAPConfig.IDLE).
	//   3. Each IDLE.PushResponses as server pushes (PSH-ACK down).
	//   4. Client "DONE\r\n" terminator (per IMAPConfig.IDLE).
	//   5. Server done-tagged response (per IMAPConfig.IDLE).
	//   6. Optional server timeout BYE per IMAPConfig.IDLE.
	//      ServerTimeoutBehavior ("close_after_idle" / "keep_idle" /
	//      "none"). See edge case C-IMAP-1.2.
	EmitIDLE bool `json:"emit_idle,omitempty"`

	// CancelAfterResponses, when > 0, cancels an in-progress IMAP
	// AUTHENTICATE command (RFC 3501 §6.2.2) after N responses. The
	// planner emits a client "*\r\n" cancel line after the Nth
	// response. Use with caution: AUTHENTICATE state machine is the
	// user's responsibility. See edge case C-IMAP-1.3.
	CancelAfterResponses int `json:"cancel_after_responses,omitempty"`

	// UIDCacheInvalidation, when true, appends an
	//   "* OK [HIGHESTMODSEQ 1] mailbox cache invalidated\r\n"
	// response after the command's normal responses, modeling RFC
	// 7162 CONDSTORE cache invalidation. The planner synthesizes this
	// response verbatim — the user does NOT need to add it to
	// Responses. See edge case C-IMAP-1.9.
	UIDCacheInvalidation bool `json:"uid_cache_invalidation,omitempty"`
}

// IMAPIDLE holds the IMAP IDLE mode (RFC 2177) configuration. It is
// referenced by IMAPCommand.EmitIDLE; all IDLE behavior is controlled
// here so per-command IDLE entries stay compact.
type IMAPIDLE struct {
	// PushResponses is the list of server "*" untagged pushes the
	// server emits while the client is IDLEing. Each entry is one
	// response line; the planner appends "\r\n" to single-line
	// pushes. Common examples: "* 1 EXISTS\r\n" / "* 1 RECENT\r\n".
	PushResponses []string `json:"push_responses,omitempty"`

	// DoneTag is the tag used for the client "DONE" terminator and the
	// server completion response. RFC 2177 recommends a fresh tag
	// (e.g. "A002"). When empty, the planner auto-generates the next
	// tag in sequence (A002, A003, ...) from the IMAP command
	// sequence. The DONE terminator is "DONE\r\n" (untagged per RFC
	// 2177 §4) when DoneTag is empty, or "<DoneTag> DONE\r\n" when
	// DoneTag is set.
	DoneTag string `json:"done_tag,omitempty"`

	// DoneResponse is the server's response to the client's DONE
	// terminator, typically a tagged "OK IDLE completed" line. Empty
	// = skip the done response.
	DoneResponse string `json:"done_response,omitempty"`

	// ServerTimeoutBehavior controls how the planner models the
	// RFC 2177 29-minute server timeout. One of:
	//   "" (default) / "none"        : no timeout BYE emitted.
	//   "close_after_idle"           : emit "* BYE IDLE timeout\r\n"
	//                                  after the done response, then
	//                                  proceed to TCP teardown.
	//   "keep_idle"                  : emit "* BYE IDLE timeout\r\n"
	//                                  after the done response but do
	//                                  NOT teardown the TCP connection
	//                                  (the next command continues
	//                                  reusing the same TCP stream).
	// See edge case C-IMAP-1.2.
	ServerTimeoutBehavior string `json:"server_timeout_behavior,omitempty"`
}

// L2TPConfig holds L2TPv2/v3 (Layer 2 Tunneling Protocol, 二层隧道协议)
// configuration. L2TP runs over UDP 1701 and models either an L2TP tunnel
// establishment dialog, an Incoming-Call / Outgoing-Call sequence on top of
// an existing tunnel, or just PPP (Point-to-Point Protocol) data
// encapsulation in a pre-existing session. The planner reads both the
// static config and the Scenarios/PPPFrames slices to emit the right packet
// stream (control vs data) on the configured 4-tuple.
//
// References: RFC 2661 (L2TPv2), RFC 3931 (L2TPv3), RFC 1661 (PPP).
type L2TPConfig struct {
	// Version selects the L2TP version. 2 = RFC 2661 (L2TPv2, the common
	// VPN case). 3 = RFC 3931 (L2TPv3, simplified data plane). The
	// planner switches the data-message header layout based on this.
	Version uint8 `json:"version,omitempty"` // 0 = 2

	// Role selects side of the tunnel. "lac" = L2TP Access Concentrator
	// (initiates SCCRQ and OCRQ). "lns" = L2TP Network Server (responds
	// with SCCRP and accepts/rejects calls).
	Role string `json:"role,omitempty"` // "lac" (default) | "lns"

	// LocalTunnelID is this side's tunnel identifier (used as the Tunnel
	// ID field in messages from this side → peer). Empty = 1 per RFC
	// 2661 §5.1 (starts at 1; 0 is the "unknown" ID).
	LocalTunnelID uint16 `json:"local_tunnel_id,omitempty"`

	// PeerTunnelID is the peer's assigned Tunnel ID (set via
	// SCCRP/SCCCN Assigned Tunnel ID AVP).
	PeerTunnelID uint16 `json:"peer_tunnel_id,omitempty"`

	// LocalSessionID mirrors LocalTunnelID for the session identifier
	// used in OCRQ/ICRQ and during data exchanges. 0 = 1.
	LocalSessionID uint16 `json:"local_session_id,omitempty"`

	// PeerSessionID is the peer's Session ID (assigned by the peer via
	// OCRP/ICRP Assigned Session ID AVP).
	PeerSessionID uint16 `json:"peer_session_id,omitempty"`

	// LocalSessionID32 is the 32-bit Session ID for L2TPv3 (RFC 3931).
	// L2TPv2 uses LocalSessionID (16 bits); L2TPv3 uses LocalSessionID32.
	// When Version=3 and LocalSessionID32 > 0, the planner writes the
	// 32-bit value into the data/control Session ID field. When
	// LocalSessionID32 = 0, falls back to LocalSessionID (truncated).
	LocalSessionID32 uint32 `json:"local_session_id_32,omitempty"`

	// PeerSessionID32 is the 32-bit peer Session ID for L2TPv3.
	PeerSessionID32 uint32 `json:"peer_session_id_32,omitempty"`

	// HostName is the value for the Host Name AVP (type 7). "" = "trafficgen".
	HostName string `json:"host_name,omitempty"`

	// VendorName is the value for the Vendor Name AVP (type 8).
	VendorName string `json:"vendor_name,omitempty"`

	// FirmwareRev is the Firmware Revision AVP (type 6).
	FirmwareRev uint16 `json:"firmware_rev,omitempty"`

	// FramingCaps is the Framing Capabilities AVP (type 3, uint32 bit
	// map). Bit 0=Async, 1=Sync. 0 = Async+Sync.
	FramingCaps uint32 `json:"framing_caps,omitempty"`

	// BearerCaps is the Bearer Capabilities AVP (type 4, uint32 bit map).
	// Bit 0=Analog, 1=Digital. 0 = Digital.
	BearerCaps uint32 `json:"bearer_caps,omitempty"`

	// ReceiveWindowSize is the Receive Window Size AVP (type 10).
	// 0 = 4.
	ReceiveWindowSize uint16 `json:"receive_window_size,omitempty"`

	// InitialNs sets the starting value of Ns (send sequence number).
	InitialNs uint16 `json:"initial_ns,omitempty"`

	// TieBreaker is used when both peers pick the same Tunnel ID; the
	// numeric-higher Tie Breaker wins (RFC 2661 §5.3). 0 = 1.
	TieBreaker uint64 `json:"tie_breaker,omitempty"`

	// ProtocolVersion is the Protocol Version AVP (type 2). 0 = 0x0101.
	ProtocolVersion uint16 `json:"protocol_version,omitempty"`

	// Cookie (L2TPv3 only) is the optional data-message Cookie field
	// (RFC 3931 §3.1). Length is implied by len(Cookie) (0/4/8/16).
	Cookie []byte `json:"cookie,omitempty"`

	// Scenarios is the ordered list of L2TP message exchanges. Each
	// entry is one logical step ("sccrq", "sccrp", "scccn", "stopccn",
	// "hello", "ocrq", "ocrp", "occn", "icrq", "icrp", "iccn", "cdn",
	// "wen", "sli"). The planner emits each step as one packet.
	Scenarios []L2TPStep `json:"scenarios,omitempty"`

	// HelloInterval is the seconds between two HELLO messages when the
	// flow contains "hello" steps. 0 = 60.
	HelloInterval int `json:"hello_interval,omitempty"`

	// PPPFrames is the list of PPP frame payloads to encapsulate in
	// Data messages.
	PPPFrames []L2TPPPPFrame `json:"ppp_frames,omitempty"`

	// CustomAVPs are user-supplied extra AVPs to append to control
	// messages (each Step may reference its own AVPs).
	CustomAVPs []L2TPAVP `json:"custom_avps,omitempty"`

	// ResultCode is the Result Code to use in StopCCN / CDN. 0 = 1.
	ResultCode uint16 `json:"result_code,omitempty"`

	// ErrorCode is the secondary Error Code in Result Code AVP (type 1).
	ErrorCode uint16 `json:"error_code,omitempty"`

	// ErrorMessage is the human-readable Error Message in Result Code
	// AVP. "" = "user request".
	ErrorMessage string `json:"error_message,omitempty"`
}

// L2TPStep is a single control-message step in the L2TP dialog. Direction
// "up" = this side → peer; "down" = peer → this side. Planner infers
// direction from Role + Type when Direction == "". AVPs override the
// auto-generated AVP set from the L2TPConfig fields.
type L2TPStep struct {
	// Type is the message type: "sccrq" | "sccrp" | "scccn" | "stopccn"
	// | "hello" | "ocrq" | "ocrp" | "occn" | "icrq" | "icrp" |
	// "iccn" | "cdn" | "wen" | "sli".
	Type string `json:"type"`

	// Direction forces direction; "" = auto.
	Direction string `json:"direction,omitempty"`

	// AVPs are extra AVPs to attach to this message.
	AVPs []L2TPAVP `json:"avps,omitempty"`

	// TunnelIDOverride and SessionIDOverride replace the auto-resolved
	// Tunnel/Session ID for this step.
	TunnelIDOverride *uint16 `json:"tunnel_id_override,omitempty"`
	SessionIDOverride *uint16 `json:"session_id_override,omitempty"`
}

// L2TPAVP is a single AVP (RFC 2661 §4.1). Mandatory flag, hidden flag,
// vendor ID, type, and value.
type L2TPAVP struct {
	Mandatory bool   `json:"mandatory,omitempty"` // M bit
	Hidden    bool   `json:"hidden,omitempty"`    // H bit
	VendorID  uint16 `json:"vendor_id,omitempty"` // 0 = IETF
	AttrType  uint16 `json:"attr_type"`           // Attribute Type
	Value     []byte `json:"value,omitempty"`     // raw value bytes
}

// L2TPPPPFrame is one PPP frame encapsulated in an L2TPv2 Data message
// (or L2TPv3 Data message with Session ID / Cookie). Direction "up" =
// LAC → LNS, "down" = LNS → LAC. PPP header is built from Protocol +
// Data; the planner prepends Address(0xFF) + Control(0x03) when
// L2PPPHeader is true.
type L2TPPPPFrame struct {
	Protocol    uint16 `json:"protocol"`               // 0x0021=IPv4, 0xC021=LCP
	Data        []byte `json:"data,omitempty"`         // PPP Information field
	Direction   string `json:"direction,omitempty"`    // "up" (default) | "down"
	L2PPPHeader bool   `json:"l2_ppp_header,omitempty"` // true = include 0xFF03 HDLC
}

// MDNSConfig holds mDNS (Multicast DNS, 多播 DNS) protocol configuration
// (RFC 6762). mDNS reuses the DNS wire format (header + question/answer/
// authority/additional sections) but adds:
//   - Transaction ID MUST be 0 (not 0x1234)
//   - Source port MUST be 5353 (or the receiver treats as legacy unicast)
//   - Destination IP is the multicast group (224.0.0.251 for IPv4, ff02::fb for IPv6)
//   - IP TTL/HopLimit MUST be 255
//   - cache-flush bit (0x8000) on the CLASS field of authoritative RRs
//   - Default TTL for RRs is 4500 seconds (not 64/300)
//
// The planner synthesizes either a single query OR a single response per
// flow (no implicit pairing — mDNS is multicast, one sender, many
// receivers). For unsolicited announcement (no query), set IsResponse=true
// and leave Questions empty.
type MDNSConfig struct {
	// Mode selects the mDNS message type:
	//   "query"      — emit a multicast query (Question section)
	//   "response"   — emit a multicast response (Answer + Additional sections)
	//   "probe"      — emit a probe (Question section with QU=1, sent 3 times)
	//   "announce"   — emit an unsolicited response (Answer section, cache-flush=1)
	//   "goodbye"    — emit a response with TTL=0 for all records in Answers
	// Empty defaults to "query".
	Mode string `json:"mode,omitempty"`

	// Questions is the Question section. For "query"/"probe" modes, this
	// is what gets sent. For "response"/"announce"/"goodbye", Questions
	// may be empty (unsolicited) or echo the original query (solicited).
	Questions []MDNSQuestion `json:"questions,omitempty"`

	// Answers is the Answer section. Used by "response"/"announce"/
	// "goodbye" modes. For "goodbye", the planner overrides TTL=0 on
	// every record.
	Answers []MDNSResourceRecord `json:"answers,omitempty"`

	// Authorities is the Authority section. mDNS typically leaves this
	// empty (NSCOUNT=0). Included for completeness.
	Authorities []MDNSResourceRecord `json:"authorities,omitempty"`

	// Additionals is the Additional section. mDNS responses commonly
	// place SRV/TXT/A here (related to a PTR in Answers).
	Additionals []MDNSResourceRecord `json:"additionals,omitempty"`

	// ProbingRepeat is the number of probe packets to emit in "probe"
	// mode. Default 3 per RFC 6762 §8.1. Each probe is separated by
	// ProbingInterval.
	ProbingRepeat int `json:"probing_repeat,omitempty"`

	// ProbingInterval is the base delay between probes in milliseconds.
	// Default 250ms per RFC 6762 §8.1. Combined with ProbingJitterMax
	// (0-250ms random), the actual inter-probe gap is:
	//   t_n = t_(n-1) + ProbingInterval + rand[0, ProbingJitterMax]
	// Set ProbingInterval=0 to disable the base delay (jitter only).
	ProbingInterval int `json:"probing_interval,omitempty"`

	// ProbingJitterMax is the maximum random jitter added to each
	// ProbingInterval gap, in milliseconds. Default 250ms per RFC 6762
	// §8.1. Set to 0 to disable jitter entirely (deterministic gap).
	// 0-250 ms range; values >250 return Validate error.
	ProbingJitterMax int `json:"probing_jitter_max,omitempty"`

	// ProbingJitterSeed is the seed for the random jitter. Same seed
	// produces identical probe timestamps (useful for tests). 0 means
	// use crypto-random or time-based seed.
	ProbingJitterSeed int64 `json:"probing_jitter_seed,omitempty"`

	// AnnouncingRepeat is the number of announcement packets to emit in
	// "announce" mode. Default 2 per RFC 6762 §8.3.
	AnnouncingRepeat int `json:"announcing_repeat,omitempty"`

	// AnnouncingInterval is the delay between announcements in
	// milliseconds. Default 1000ms per RFC 6762 §8.3.
	AnnouncingInterval int `json:"announcing_interval,omitempty"`

	// ResponseDelay is the random delay before sending a multicast
	// response, in milliseconds. Default 20-120ms per RFC 6762 §6.0.
	// 0 means no delay (immediate response).
	ResponseDelay int `json:"response_delay,omitempty"`

	// MulticastGroup selects the destination IP. Default "224.0.0.251"
	// (IPv4). For IPv6, the planner auto-selects "ff02::fb" based on
	// spec.SrcIP. Explicit override is rare but allowed.
	MulticastGroup string `json:"multicast_group,omitempty"`

	// ForceUnicastResponse, when true, sets the QU bit on Questions (QCLASS
	// high bit) — requests receivers to respond via unicast. Used in
	// "query"/"probe" modes.
	ForceUnicastResponse bool `json:"force_unicast_response,omitempty"`

	// CacheFlush, when true, sets the cache-flush bit (0x8000) on the
	// CLASS field of all RRs in Answers/Additionals. Default true for
	// "announce"/"goodbye" modes (per RFC 6762 §10.2), false otherwise.
	CacheFlush *bool `json:"cache_flush,omitempty"`

	// DefaultTTL is the TTL to use when a Resource Record's TTL field is
	// 0. Default 4500 (mDNS standard). Per-record TTL overrides this.
	DefaultTTL uint32 `json:"default_ttl,omitempty"`

	// TC (Truncation, 截断) when true sets the TC bit in the DNS header
	// Flags field. Only valid for response modes. Default false.
	TC bool `json:"tc,omitempty"`
}

// MDNSQuestion is one entry in the Question section of an mDNS message.
type MDNSQuestion struct {
	// Name is the QNAME, e.g. "_http._tcp.local" or "MyServer.local".
	Name string `json:"name"`
	// Type is the QTYPE: A=1, AAAA=28, PTR=12, SRV=33, TXT=16, ANY=255.
	Type uint16 `json:"type"`
	// Class is the QCLASS. 0 defaults to IN (1). Bit 15 (0x8000) sets
	// the QU bit (unicast response request).
	Class uint16 `json:"class,omitempty"`
}

// MDNSResourceRecord is one entry in Answer/Authority/Additional sections.
type MDNSResourceRecord struct {
	// Name is the owner name.
	Name string `json:"name"`
	// Type is the RR type: A=1, AAAA=28, PTR=12, SRV=33, TXT=16, NSEC=47.
	Type uint16 `json:"type"`
	// Class is the RR class. 0 defaults to IN (1). Bit 15 (0x8000) sets
	// the cache-flush bit.
	Class uint16 `json:"class,omitempty"`
	// TTL in seconds. 0 = use DefaultTTL. Explicit 0 only via Goodbye mode.
	TTL uint32 `json:"ttl,omitempty"`

	// RDATA fields, populated per Type:
	//   A    → IPAddress (IPv4)
	//   AAAA → IPAddress (IPv6)
	//   PTR  → DomainName
	//   CNAME→ DomainName
	//   SRV  → Priority, Weight, Port, Target
	//   TXT  → TXTEntries (each becomes <len>str in RDATA)
	//   NSEC → NSECNextName + NSECTypes (encoder builds RFC 4034 §4
	//          window blocks and 1-32 byte type bitmaps)
	IPAddress  string   `json:"ip_address,omitempty"`
	DomainName string   `json:"domain_name,omitempty"`
	Priority   uint16   `json:"priority,omitempty"`
	Weight     uint16   `json:"weight,omitempty"`
	Port       uint16   `json:"port,omitempty"`
	Target     string   `json:"target,omitempty"`
	TXTEntries []string `json:"txt_entries,omitempty"`

	// NSEC typed RDATA fields (Type=47 only). NSECNextName is encoded as
	// QName (compression allowed). NSECTypes is grouped by window T/256;
	// each block is WindowNumber(1) + BitmapLength(1, range 1-32) +
	// TypeBitmap(BitmapLength). Empty fields are invalid for Type=47.
	NSECNextName string   `json:"nsec_next_name,omitempty"`
	NSECTypes    []uint16 `json:"nsec_types,omitempty"`

	// RawRDATA, when non-nil, overrides the typed fields above and is
	// emitted verbatim as RDATA. Used only for testing malformed records;
	// normal NSEC records MUST use NSECNextName + NSECTypes.
	RawRDATA []byte `json:"raw_rdata,omitempty"`
}

// MySQLConfig for the MySQL Client/Server Protocol (MySQL 8.0+).
//
// MySQL is a session-level protocol: a single TCP connection on port
// 3306 carries a sequence of request/response packets in the MySQL
// binary frame format. Each packet is framed by a 4-byte header
// (3-byte little-endian length + 1-byte sequence ID). The planner emits
// a TCP handshake, then:
//
//  1. Server Greeting (down) — 0x0a protocol + version + thread_id +
//     auth_data + capabilities + auth_plugin_name.
//  2. Client Handshake Response (up) — capabilities + max_packet_size +
//     username + auth_data + database + auth_plugin_name.
//  3. Server Auth OK / ERR (down) — depending on the auth method
//     (mysql_native_password / caching_sha2_password / sha256_password).
//  4. Each MySQLCommand in Commands as an up packet (request) followed
//     by the matching down packet (response — auto-derived OK / ERR /
//     Result Set / etc.).
//
// Encryption: this design does NOT implement TLS. The connect payload
// is plaintext MySQL. A plain MySQL listener that decrypts nothing
// matches the recorder view (the planner emits valid binary shape).
type MySQLConfig struct {
	// ServerVersion sets the server version string in the Greeting
	// packet (e.g. "8.0.36", "5.7.42-log"). Empty defaults to
	// "8.0.36".
	ServerVersion string `json:"server_version,omitempty"`

	// ThreadID is the server's thread_id sent in Greeting. 0 = planner
	// picks a deterministic value per flow (seq+1) for reproducibility.
	ThreadID uint32 `json:"thread_id,omitempty"`

	// AuthPlugin selects which auth plugin the Greeting advertises.
	// The Client Handshake Response must match this value (or respond
	// to an Auth Switch with the requested plugin). Values:
	//   "mysql_native_password" (default; SHA1-based)
	//   "caching_sha2_password" (SHA256 + optional RSA cache miss)
	//   "sha256_password"        (always RSA-encrypted)
	AuthPlugin string `json:"auth_plugin,omitempty"`

	// Username is the client user (sent null-terminated in the
	// Handshake Response). Empty defaults to "root".
	Username string `json:"username,omitempty"`

	// Password is the cleartext password used to compute the auth
	// response. Empty defaults to "" (no password). The exact algorithm
	// depends on AuthPlugin:
	//   - mysql_native_password: SHA1(SHA1(p) XOR SHA1(s + SHA1(SHA1(p))))
	//   - caching_sha2_password fast: XOR(SHA256(p), SHA256(s + SHA256(SHA256(p))))
	//   - sha256_password / caching_sha2_password cache miss: RSA encrypt p.
	Password string `json:"password,omitempty"`

	// Scramble is the 20-byte auth challenge (8 bytes server Greeting
	// Part 1 + 12 bytes of Part 2). Empty = planner generates a fixed
	// deterministic scramble for reproducible tests; non-empty = use the
	// user-provided bytes (must be exactly 20 bytes if set).
	Scramble []byte `json:"scramble,omitempty"`

	// Database, when non-empty and CLIENT_CONNECT_WITH_DB is set,
	// causes client to send "db\0" after auth.
	Database string `json:"database,omitempty"`

	// CapabilityFlags overrides the planner-computed capability bitmask
	// (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION |
	// CLIENT_PLUGIN_AUTH). 0 = planner uses a sensible default
	// matching MySQL 8.0 client behavior.
	CapabilityFlags uint32 `json:"capability_flags,omitempty"`

	// MaxPacketSize is the max_packet_size field in the Handshake
	// Response. 0 = 0x01000000 (16 MB).
	MaxPacketSize uint32 `json:"max_packet_size,omitempty"`

	// CharacterSet is the connection character_set_client (1 byte).
	// 0 = 0x21 (utf8 / utf8_general_ci); 45 = utf8mb4.
	CharacterSet uint8 `json:"character_set,omitempty"`

	// Commands is the ordered list of client→server request packets
	// (each a 0x0X command opcode + body) paired with the expected
	// server→client response.
	Commands []MySQLCommand `json:"commands,omitempty"`

	// ServerBypassAuth, when true, skips the auth roundtrip entirely
	// (the planner omits the Handshake Response). Useful for replaying
	// an already-authenticated flow.
	ServerBypassAuth bool `json:"server_bypass_auth,omitempty"`

	// MSS is governed by TCPConfig.MSS. MySQL runs over TCP; planners
	// read spec.TCP.MSS to segment long packets (notably Result Set
	// rows and large COM_QUERY payloads).
}

// MySQLCommand is a single client command paired with its expected
// server response.
//
// Opcode selects which 0x0X command byte to send. Body is the bytes
// AFTER the opcode; for COM_QUERY it's the SQL text (raw, no null
// terminator added by the planner since MySQL sends SQL not null-
// terminated — but the body length is encoded by the packet header).
//
// ReplyMode + ReplyBytes describe the down packet(s) the planner
// emits. ReplyBytes holds the literal reply payload (without its own
// 4-byte header; planner prepends header per packet) and may itself
// be split into multiple packets if longer than MaxPacketSize.
//
// For result-set commands (COM_QUERY that returns rows, COM_STMT_
// EXECUTE) the planner supports the AutoReply modes below; the user
// can also hand-encode every column definition + row in ReplyBytes.
type MySQLCommand struct {
	// Opcode is the 1-byte command code (0x01..0x20). See design §2.5.
	Opcode uint8 `json:"opcode"`

	// Body is the payload AFTER the opcode (hex/base64/text depending
	// on BodyEncoding). For text commands (COM_QUERY / COM_INIT_DB /
	// COM_CREATE_DB / COM_DROP_DB / COM_FIELD_LIST) Body is the SQL or
	// name as raw bytes (no null terminator; command text is the body).
	// For binary commands (COM_STMT_EXECUTE, COM_STMT_PREPARE params)
	// Body is the binary payload.
	Body string `json:"body,omitempty"`

	// BodyEncoding: "text" (default), "hex", or "base64". "text" →
	// body treated as raw bytes (UTF-8). "hex" → body parsed as
	// "0a1b2c..." hex string. "base64" → body parsed as base64.
	BodyEncoding string `json:"body_encoding,omitempty"`

	// ReplyMode:
	//   "ok"           — emit a single OK packet (auto-derive affected_rows=0,
	//                    last_insert_id=0, status_flags=0x0002, warnings=0).
	//   "ok-insert"    — like ok but with affected_rows=1 and last_insert_id=42.
	//   "err"          — emit ERR(1064 #HY000 syntax error).
	//   "err-perm"     — emit ERR(1044 #42000 access denied).
	//   "result-set"   — emit column_count=1, col_defs=[user provided], EOF,
	//                    rows=[user provided], EOF. See ColDefs/Rows.
	//   "binary-result"— for COM_STMT_EXECUTE: each value is lenenc-str
	//                    (no column defs re-sent).
	//   "raw"          — use ReplyBytes verbatim, splitting into packets by
	//                    max_packet_size.
	ReplyMode string `json:"reply_mode,omitempty"`

	// ReplyBytes is the literal reply payload (without its 4-byte
	// header). Used when ReplyMode="raw"; planner frames it across
	// one or more packets (4-byte header each, seq incremented).
	ReplyBytes string `json:"reply_bytes,omitempty"`

	// ReplyEncoding: "text" / "hex" / "base64" for ReplyBytes.
	ReplyEncoding string `json:"reply_encoding,omitempty"`

	// For ReplyMode="result-set":
	ColDefs []MySQLColDef `json:"col_defs,omitempty"`
	Rows    []MySQLRow    `json:"rows,omitempty"`

	// For COM_STMT_EXECUTE: stmt_id (required), iteration_count (default 1),
	// null_bitmap (hex/base64).
	StmtID         uint32 `json:"stmt_id,omitempty"`
	IterationCount uint32 `json:"iteration_count,omitempty"`

	// EmitOkExtended: when true with ReplyMode="ok", emit the 5.7+
	// extended OK packet (info + session state changes).
	EmitOkExtended bool `json:"emit_ok_extended,omitempty"`
}

// MySQLColDef is a column definition packet body (without 4-byte header)
// for COM_QUERY / COM_STMT_PREPARE result sets.
type MySQLColDef struct {
	Catalog  string `json:"catalog"`            // usually "def"
	Schema   string `json:"schema"`             // database name
	Table    string `json:"table"`              // table name
	OrgTable string `json:"org_table"`          // alias
	Name     string `json:"name"`                // column name
	OrgName  string `json:"org_name"`            // alias
	Charset  uint16 `json:"charset"`             // character set id
	Length   uint32 `json:"length"`              // column display length (e.g. 11 for INT)
	Type     uint8  `json:"type"`                // MySQL type byte (0x03=LONGLONG, 0xf7=GEOMETRY, etc.)
	Flags    uint16 `json:"flags"`               // column flags (NOT_NULL, PRI_KEY, etc.)
	Decimals uint8  `json:"decimals"`            // decimal precision
}

// MySQLRow is a single row packet body (without 4-byte header).
// Values are encoded as length-encoded strings except for SQL NULL
// (encoded as 0xfb).
type MySQLRow struct {
	// Values as raw bytes; each Value is wrapped in a length-encoded
	// prefix by the planner. To insert SQL NULL, use a single byte 0xfb
	// (set Value = "\xfb" or use IsNull flag).
	Values []string `json:"values,omitempty"`
	IsNull []bool   `json:"is_null,omitempty"` // parallel to Values

	// ValueEncoding matches MySQLCommand.BodyEncoding.
	ValueEncoding string `json:"value_encoding,omitempty"`
}

// NTPConfig holds NTP protocol configuration (RFC 5905). The 48-byte fixed
// header carries LeapIndicator/Version/Mode/Stratum/Poll/Precision, root
// timing fields, Reference ID, and the four 64-bit NTP timestamps
// (Reference/Origin/Receive/Transmit). Optional authentication (KeyID + MAC)
// and RFC 7822 Extension Fields append after the 48-byte header. Mode=6
// (control, RFC 5906) uses an 8-byte control header instead of the 48-byte
// basic header and carries its own Sequence/Implementation/RequestCode/Data.
//
// All multi-byte fields are encoded in network byte order (big-endian) per
// RFC 5905 §7.3. NTP timestamps use the 1900-01-01 00:00:00 UTC epoch with
// 32-bit seconds + 32-bit fraction. The 2036-02-07 06:28:16 UTC rollover
// wraps seconds back to 0 (era 1 begins).
//
// Field defaulting (per validate_conventions.md §1.3) happens in Plan's emit
// goroutine, never in Validate. Zero values mean "not set" for the user-facing
// fields below; the planner substitutes documented defaults at emit time.
type NTPConfig struct {
	// 48-byte fixed header fields (RFC 5905 §7.3).
	LeapIndicator  uint8     `json:"leap_indicator"`      // 0-3, 0=none, 3=alarm
	Version        uint8     `json:"version"`             // 3 or 4, default 4
	Mode           uint8     `json:"mode"`                // 1-7, default 3 (client); 0 reserved
	Stratum        uint8     `json:"stratum"`             // 0-16, 0=unspecified/KoD, 16=unsync
	Poll           int8      `json:"poll"`                // 4-17 (log2 seconds), default 6 (64s)
	Precision      int8      `json:"precision"`           // log2 seconds (negative), default -6 (~15ms)
	RootDelay      float64   `json:"root_delay"`          // seconds, 16.16 fixed-point on the wire
	RootDispersion float64   `json:"root_dispersion"`     // seconds, 16.16 fixed-point on the wire
	ReferenceID    uint32    `json:"reference_id"`        // Stratum 0: KO ASCII; 1: ref source; 2+: upstream IPv4
	RefTimestamp   time.Time `json:"ref_timestamp"`       // zero = not set (emitted as 0)
	OriginTS       time.Time `json:"origin_ts"`           // zero = not set
	ReceiveTS      time.Time `json:"receive_ts"`          // zero = not set
	TransmitTS     time.Time `json:"transmit_ts"`         // zero = not set

	// Optional authentication / extensions (RFC 7822). KeyID=0 and MAC=nil
	// mean no authentication trailer. MAC length must be 0, 16 (AES-CMAC/MD5),
	// or 20 (SHA1) per RFC 7822 §4.3. Extension values must be 4-byte aligned
	// (the planner pads with zeros if needed).
	KeyID      uint32   `json:"key_id,omitempty"`
	MAC        []byte   `json:"mac,omitempty"`
	Extensions []NTPExt `json:"extensions,omitempty"`

	// Behavior controls. IsResponse=true in client mode (Mode=3) emits a
	// server response after the request; in symmetric modes (Mode=1/2) emits
	// the peer-to-peer reply; in control mode (Mode=6) emits the control
	// response. RepeatCount overrides FlowSpec.Count for multi-packet modes
	// (broadcast, symmetric, control sequences). PollInterval is informational
	// only (the planner does not sleep; pacing is the worker's job).
	IsResponse   bool `json:"is_response,omitempty"`
	PollInterval int  `json:"poll_interval,omitempty"`
	RepeatCount  int  `json:"repeat_count,omitempty"`

	// Control message fields (Mode=6, RFC 1305 App. B / ntpd ntp_control.h).
	// The control header is 12 bytes:
	//   byte 0: LI(2)|VN(3)|Mode(3)
	//   byte 1: R(1)|E(1)|M(1)|OpCode(5)
	//   bytes 2-3: Sequence (16-bit)
	//   bytes 4-5: Status (16-bit)
	//   bytes 6-7: Association ID (16-bit)
	//   bytes 8-9: Offset (16-bit)
	//   bytes 10-11: Count (16-bit) = data length
	//   bytes 12+: Data (max 468 = ntpd CTL_MAX_DATA_LEN)
	// RequestCode is the 5-bit OpCode (0-31, ntpd CTL_OP_*). Sequence,
	// AssociationID, and Offset are 16-bit. ControlData is the variable-length
	// Data region (max 468 bytes; total packet max 480).
	Sequence       uint16 `json:"sequence,omitempty"`
	Implementation uint8  `json:"implementation,omitempty"`
	RequestCode    uint8  `json:"request_code,omitempty"`
	AssociationID  uint16 `json:"association_id,omitempty"`
	Offset         uint16 `json:"offset,omitempty"`
	Error          bool   `json:"error,omitempty"`
	More           bool   `json:"more,omitempty"`
	StatusWord     uint16 `json:"status_word,omitempty"`
	ControlData    []byte `json:"control_data,omitempty"`
}

// NTPExt is a single RFC 7822 extension field. Type is the 16-bit Field Type,
// Value is the variable-length payload (the planner 0-pads to a 4-byte
// boundary before emitting). The 4-byte (Type+Length) header is added by the
// planner; users only supply Type and Value.
type NTPExt struct {
	Type  uint16 `json:"type"`
	Value []byte `json:"value,omitempty"`
}

// OpenVPNConfig holds OpenVPN protocol configuration.
//
// OpenVPN is a session-level, encrypted, layered protocol that wraps either UDP
// (--proto udp, default) or TCP-over-TLS (--proto tcp) and runs an OpenVPN-specific
// 控制通道 (control channel) 和数据通道 (data channel) on top. The planner emits
// P_CONTROL_HARD_RESET_V1/V2/V3, P_DATA_V1/V2, optional tls-auth HMAC, optional
// tls-crypt wrapped key, optional keepalive ping/pong, and teardown.
//
// Encryption is NOT implemented: post-TLS-finished payload is opaque (dummy bytes
// or user-supplied). HMAC, tls-crypt auth-tag, AEAD IV, and AEAD tag are
// deterministic filler (0xAA/0xBB/0xCC/0xDD/0xEE), structurally correct but not
// cryptographically valid. This preserves OpenVPN wire format for DPI testing.
type OpenVPNConfig struct {
	// Proto selects the L4 transport. "udp" (default, port 1194) carries
	// OpenVPN packets in UDP datagrams; "tcp" carries TLS-in-TCP where
	// OpenVPN application data flows as TLS AppData. Empty defaults to
	// "udp". Maps to OpenVPN --proto udp|--proto tcp.
	Proto string `json:"proto,omitempty"`

	// Version selects OpenVPN protocol version 1, 2, or 3. Empty defaults
	// to "2" (V2, the openvpn-2.4+ default). Maps to OpenVPN internal
	// negotiation. V1 uses OPCODE 1-3 + OCC; V2/V3 use 4-6 with
	// HMAC/tls-crypt.
	Version string `json:"version,omitempty"`

	// KeyID is the OpenVPN key slot. 0 = client, 1 = server (matches
	// default OpenVPN server config). Encoded as key_id field (5 bits for
	// V1/V2, 3 bits for V3).
	KeyID uint8 `json:"key_id,omitempty"`

	// SessionID is the OpenVPN session ID. Real OpenVPN uses an 8-byte
	// session_id (SID_SIZE=8 in src/openvpn/ssl_pkt.h), parsed as 8 bytes by
	// Wireshark for all control/ack opcodes. 0 = random. Stored as uint64
	// to hold the full 64-bit value; emitted as 8 bytes big-endian on the
	// wire for V1/V2/V3 control packets. P_DATA_V1 emits no session_id;
	// P_DATA_V2 emits a 3-byte peer_id instead.
	SessionID uint64 `json:"session_id,omitempty"`

	// TLSAuth, when true, prepends HMAC-SHA1 tag (20 bytes) to each
	// P_CONTROL payload. Maps to --tls-auth file. false = no tls-auth.
	TLSAuth bool `json:"tls_auth,omitempty"`

	// TLSCrypt, when true, prepends wrapped_key (tls-crypt: auth-tag 32B +
	// IV 16B + cipher_key wrapped) to each P_CONTROL payload. Maps to
	// --tls-crypt file (or --tls-crypt-v2). false = no tls-crypt (default).
	TLSCrypt bool `json:"tls_crypt,omitempty"`

	// TLSCryptV2, when true, emits --tls-crypt-v2 format with explicit
	// wrapped_key_id (4 bytes) at start of wrapped_key. Requires
	// TLSCrypt=true. false = --tls-crypt (default).
	TLSCryptV2 bool `json:"tls_crypt_v2,omitempty"`

	// DataCipher selects the data channel cipher. One of:
	// "AES-256-CBC" (default with HMAC-SHA1 20B tag), "AES-128-GCM"
	// (AEAD 16B tag), "AES-256-GCM", "CHACHA20-POLY1305". Affects
	// P_DATA padding/IV/tag structure.
	DataCipher string `json:"data_cipher,omitempty"`

	// NCPDisable, when true, disables NCP (--ncp-disable) cipher
	// negotiation. Use the cipher exactly as configured.
	NCPDisable bool `json:"ncp_disable,omitempty"`

	// TLSVersion selects the inner TLS protocol version: "1.2" or "1.3".
	// Empty defaults to "1.3". Maps to tls.Config.Version.
	TLSVersion string `json:"tls_version,omitempty"`

	// TLSRole selects the OpenVPN-side TLS role:
	// "client" (default): emit ClientHello first, expect ServerHello.
	// "server": emit ServerHello first (only for asymmetric / replay scenarios).
	TLSRole string `json:"tls_role,omitempty"`

	// SNI is the inner TLS server_name (RFC 6066). Default "openvpn".
	// Affects inner TLS ClientHello's server_name extension.
	SNI string `json:"sni,omitempty"`

	// Mssfix sets the OpenVPN --mssfix size. 0 = 1450 (default for
	// tap), else specified value. Not a packet field but stored in
	// metadata for downstream processing.
	Mssfix uint16 `json:"mssfix,omitempty"`

	// TLSAuthHMAC, when non-empty (20 bytes), overrides the
	// deterministic 0xAA HMAC filler.
	TLSAuthHMAC []byte `json:"tls_auth_hmac,omitempty"`

	// TLSCryptWrappedKey, when non-empty, overrides the deterministic
	// 0xBB/0xCC/0xEE tls-crypt filler. Format: auth-tag(32)||IV(16)||cipher_key(...).
	TLSCryptWrappedKey []byte `json:"tls_crypt_wrapped_key,omitempty"`

	// DataPayload is the plaintext payload for P_DATA encryption (V1/V2).
	// Empty = no payload, just keepalive. Default: 64 bytes synthesized data.
	DataPayload []byte `json:"data_payload,omitempty"`

	// DataPacketCount is how many P_DATA packets to emit per direction.
	// 0 = 1 packet. Default 5.
	DataPacketCount int `json:"data_packet_count,omitempty"`

	// PerformSoftReset, when true, after P_DATA exchange, emit
	// P_CONTROL_SOFT_RESET_V1 (opcode=3) to simulate key renegotiation.
	// After soft reset, subsequent P_DATA uses incremented key_id.
	PerformSoftReset bool `json:"perform_soft_reset,omitempty"`

	// StaticKeyMode, when true, switches to --secret/--static-key P2P
	// mode. No TLS handshake, no P_CONTROL_HARD_RESET. Emits P_DATA_V1
	// directly. Default false. Mutually exclusive with TLSAuth/TLSCrypt.
	StaticKeyMode bool `json:"static_key_mode,omitempty"`

	// KeyDirection selects the static-key direction: 0 = client->server,
	// 1 = server->client. Only used when StaticKeyMode=true.
	KeyDirection uint8 `json:"key_direction,omitempty"`

	// StaticKey is the 256-byte pre-shared secret for P2P static-key mode.
	// Format: 128B encrypt key || 128B HMAC key. Empty = random fill.
	// Only used when StaticKeyMode=true.
	StaticKey []byte `json:"static_key,omitempty"`

	// AuthUserPass, when true, enables --auth-user-pass username/password
	// authentication. After TLS handshake completes, the client emits
	// "username\npassword" in TLS AppData. Default false.
	AuthUserPass bool `json:"auth_user_pass,omitempty"`

	// AuthUser is the username for --auth-user-pass. ASCII/UTF-8, 1..64 bytes.
	// Default "anonymous". Only used when AuthUserPass=true.
	AuthUser string `json:"auth_user,omitempty"`

	// AuthPass is the password for --auth-user-pass. ASCII/UTF-8, 1..64 bytes.
	// Default "anonymous". Only used when AuthUserPass=true.
	AuthPass string `json:"auth_pass,omitempty"`

	// AuthAlg selects the --auth HMAC algorithm. One of:
	// "SHA1" (default, 20B HMAC), "SHA256" (32B), "SHA512" (64B),
	// "MD5" (16B, legacy), "none" (0B, no HMAC). Affects tls-auth HMAC
	// tag byte length. Empty defaults to "SHA1".
	AuthAlg string `json:"auth_alg,omitempty"`

	// FragmentSize, when >0, enables --fragment application-layer
	// fragmentation with this payload size in bytes. 0 = disabled (default).
	// When enabled, each P_DATA_V2 payload is fragmented into first/middle/last	// pieces with fragment header (1B info + 2B id + 2B size). Must be in [64,1500].
	FragmentSize uint16 `json:"fragment_size,omitempty"`

	// KeepalivePingInterval sets the --keepalive <ping> interval in
	// seconds (1..65535). 0 = disabled (no keepalive). When enabled,
	// planner inserts empty P_DATA_V2 keepalive packets every PingInterval seconds.
	KeepalivePingInterval uint16 `json:"keepalive_ping,omitempty"`

	// KeepalivePingRestart sets the --keepalive <restart> timeout in
	// seconds (1..65535). 0 = disabled. Triggered after PingInterval of silence.
	KeepalivePingRestart uint16 `json:"keepalive_ping_restart,omitempty"`

	// ExitNotifyCount sets --explicit-exit-notify N (1..3). 0 = disabled.
	// Only valid for proto=udp (TCP mode uses TLS close_notify).
	ExitNotifyCount uint8 `json:"exit_notify_count,omitempty"`

	// ExitNotifyInterval sets the interval between exit_notify packets
	// in milliseconds (0..65535). Default 1000ms. Only used when ExitNotifyCount>0.
	ExitNotifyInterval uint16 `json:"exit_notify_interval,omitempty"`

	// TunMTU sets the --tun-mtu value in bytes (64..65535). Default 1500.
	// Affects IP fragmentation boundary; NOT packet field - stored in
	// PacketConfig.Metadata as metadata["openvpn_tun_mtu"].
	TunMTU uint16 `json:"tun_mtu,omitempty"`
}

// PostgreSQLConfig holds PostgreSQL frontend/backend protocol v3 / v3.1
// configuration. PostgreSQL is a session-level protocol: a single TCP
// connection on port 5432 carries StartupMessage → authentication →
// ready → query traffic → Terminate. The planner emits a TCP handshake
// (caller may disable via EmitHandshake=false), then StartupMessage,
// then a paired sequence of backend→frontend status frames
// (Authentication*, ParameterStatus*, BackendKeyData, ReadyForQuery) and
// frontend→backend requests (Query / Parse / Bind / Describe / Execute /
// Sync / Terminate / CopyData), all within one flow.
//
// PostgreSQL uses a custom binary frame format: every regular message has
// a 1-byte type + 4-byte big-endian length (the length INCLUDES itself
// but NOT the type byte). StartupMessage is the only exception — it has
// no type byte, just a 4-byte length.
//
// The planner models the byte-level format faithfully so Wireshark's
// PostgreSQL dissector can parse the resulting packets. The planner does
// NOT validate authentication cryptography (MD5 / SCRAM) — it emits
// correctly-shaped bytes that match the protocol's field layout, but real
// PostgreSQL servers will reject the resulting handshake. That is
// acceptable for traffic-generation purposes (the goal is "wire-format
// correct", not "session authenticated").
//
// Authentication methods (AuthMethod): "trust" skips challenge entirely
// (server sends AuthenticationOk directly); "md5" requests MD5Password;
// "scram-sha-256" runs SCRAM-SHA-256; "cleartext" requests plaintext
// password; "gss" / "sspi" are stubbed (the planner emits a GSS/SSPI
// authentication request followed by AuthOk — actual Kerberos bytes are
// opaque).
//
// Pipeline mode (v3.1): set ProtocolVersion=0x00030001 + Pipeline=true to
// allow the planner to emit multiple Parse/Bind/Describe/Execute sequences
// before Sync.
//
// COPY / replication / LISTEN are modeled via scenario names in
// Operations — see the Operations field docs.
type PostgreSQLConfig struct {
	// ProtocolVersion: 0x00030000 (3.0, default) or 0x00030001 (3.1
	// with pipeline). 0 defaults to 3.0.
	ProtocolVersion int32 `json:"protocol_version,omitempty"`

	// Startup parameters: key/val pairs for StartupMessage. Common keys:
	// "user" (required), "database" (defaults to user), "client_encoding"
	// (default UTF8), "application_name", "options", "extra_float_digits",
	// "TimeZone", "replication" ("true" / "database" / "logical").
	StartupParams map[string]string `json:"startup_params,omitempty"`

	// AuthMethod: "trust" / "md5" / "scram-sha-256" / "cleartext" / "gss"
	// / "sspi". Default "trust" — planner emits AuthOk directly. When set
	// to "md5" / "scram-sha-256" / "cleartext" the planner emits the
	// appropriate challenge → response → AuthOk sequence.
	AuthMethod string `json:"auth_method,omitempty"`

	// Username used by md5 / scram-sha-256 hashing. Empty = use
	// StartupParams["user"] or "postgres" if that is also empty.
	Username string `json:"username,omitempty"`

	// Password used by cleartext / md5 / scram-sha-256 challenges. Any
	// string; the planner does not check cryptography. Empty = planner
	// generates a fixed test value (e.g. "testpass").
	Password string `json:"password,omitempty"`

	// MD5Salt: 4 random bytes for MD5Password challenge. When empty or
	// not exactly 4 bytes, planner generates fixed test bytes
	// (0x12 0x34 0x56 0x78).
	MD5Salt []byte `json:"md5_salt,omitempty"`

	// Operations is the ordered list of post-auth operations:
	// {kind, ...}. Each operation emits one or more messages in the
	// correct direction (up = frontend→backend, down = backend→frontend).
	//
	// Kinds:
	//   "query"     → Simple Query (client→server: Q; server→client: T*/D*/C/Z)
	//   "parse"     → Extended Query Parse + ParseComplete
	//   "bind"      → Extended Query Bind + BindComplete (uses prior stmt)
	//   "describe"  → Extended Query Describe + (T/n) [uses prior stmt or portal]
	//   "execute"   → Extended Query Execute + (DataRow*/C/s)
	//   "sync"      → Sync + ReadyForQuery
	//   "close"     → Close + CloseComplete
	//   "flush"     → Flush (server flushes pending buffer)
	//   "copy-from" → Q "COPY t FROM STDIN" + CopyInResponse → CopyData* + CopyDone + C + Z
	//   "copy-to"   → Q "COPY t TO STDOUT" + CopyOutResponse → CopyData* + C + Z
	//   "listen"    → Q "LISTEN ch" + C + Z + optional async NotificationResponse
	//   "unlisten"  → Q "UNLISTEN *" + C + Z
	//   "replication-identify" → Q "IDENTIFY_SYSTEM" + T + D + C + Z
	//   "replication-start"    → Q "START_REPLICATION ..." + W (CopyBothResponse)
	//                            + XLogData* + PrimaryKeepalive*
	//   "terminate" → X + TCP close (no server response)
	//   "function-call" → F (FunctionCall) + V (FunctionCallResponse)
	//
	// The planner reads these in order and emits the appropriate
	// frontend/backend frames, segmented via spec.TCP.MSS as needed.
	Operations []PGOperation `json:"operations,omitempty"`

	// Pipeline: when true (and ProtocolVersion >= 0x00030001), groups
	// Extended Query operations into batches. The planner still emits
	// one frame per Operation in the order given, but the user is
	// expected to provide P/B/D/E sequences followed by Sync.
	Pipeline bool `json:"pipeline,omitempty"`

	// RowCount controls how many synthetic DataRow frames the planner
	// emits for SELECT-like queries that produce rows (default 1). When
	// RowCount=0, the planner emits CommandComplete only (for INSERT/
	// UPDATE/DELETE/COPY without rowset).
	RowCount int `json:"row_count,omitempty"`

	// ColumnTypes describes the column types for RowDescription rows.
	// Keys are 1-indexed column positions; values are PostgreSQL type
	// OIDs (23=int4, 25=text, 16=bool, 20=int8, 701=float8, ...). Empty
	// = planner uses default int4 column type.
	ColumnTypes map[int]int32 `json:"column_types,omitempty"`

	// NotificationPayload, when non-empty, makes the planner emit a
	// NotificationResponse (A) frame after the LISTEN operation, with
	// this string as the payload. Length 0 = no async notification.
	NotificationPayload string `json:"notification_payload,omitempty"`

	// WALDataSize: for replication-start operations, the planner emits
	// this many bytes of synthetic XLogData per frame. Default 64.
	WALDataSize int `json:"wal_data_size,omitempty"`

	// EmitHandshake: when nil or true (default), planner emits the TCP SYN /
	// SYN-ACK / ACK triplet before the first PG frame. Set to a pointer to
	// false to suppress (useful for unit tests that want predictable
	// packet indices). Pointer so the zero value (nil) means "use default
	// true" rather than "suppress".
	EmitHandshake *bool `json:"emit_handshake,omitempty"`

	// EmitTeardown: when nil or true (default), planner emits the TCP
	// FIN-ACK 4-way teardown after the final PG frame. Set to a pointer to
	// false to suppress.
	EmitTeardown *bool `json:"emit_teardown,omitempty"`
}

// PGOperation is a single post-auth operation. Most operations carry a
// query/prepare text or statement/portal name as needed.
type PGOperation struct {
	// Kind: see PostgreSQLConfig.Operations docs for the full list.
	Kind string `json:"kind"`

	// SQL is the query / PREPARE text for "query" / "parse".
	SQL string `json:"sql,omitempty"`

	// Statement is the prepared statement name (for "parse" / "bind" /
	// "describe" / "close" with Mode="statement").
	Statement string `json:"statement,omitempty"`

	// Portal is the portal name (for "bind" / "describe" / "execute" /
	// "close" with Mode="portal").
	Portal string `json:"portal,omitempty"`

	// Mode: "statement" or "portal" — used by "describe" and "close".
	Mode string `json:"mode,omitempty"`

	// MaxRows: int32 limit for "execute" — 0 = no limit (all rows).
	MaxRows int32 `json:"max_rows,omitempty"`

	// ParamCount: int16 number of $1/$2/... parameters for "parse" /
	// "bind". 0 = no params.
	ParamCount int `json:"param_count,omitempty"`

	// ParamValues: N strings for "bind" (each becomes a Text value).
	ParamValues []string `json:"param_values,omitempty"`

	// Channel is the LISTEN / NOTIFY channel name.
	Channel string `json:"channel,omitempty"`

	// CopyData is the COPY row payload (one string per row) for
	// "copy-from" / "copy-to" (Text format with tab/newline).
	CopyData []string `json:"copy_data,omitempty"`

	// ReplicationSlot is the slot name for "replication-start".
	ReplicationSlot string `json:"replication_slot,omitempty"`

	// ReplicationLSN is the start LSN (e.g. "0/1000000") for
	// "replication-start".
	ReplicationLSN string `json:"replication_lsn,omitempty"`

	// ReplicationKind: "physical" or "logical" — for "replication-start".
	ReplicationKind string `json:"replication_kind,omitempty"`

	// EmitAsServer: when true, planner emits this operation's frames as
	// backend→frontend (down direction). Used to inject synthetic
	// server-driven pushes (NotificationResponse, XLogData) at desired
	// points without authoring a custom Operations list.
	EmitAsServer bool `json:"emit_as_server,omitempty"`

	// NotifyChannel / NotifyPayload for asynchronous
	// NotificationResponse (used when EmitAsServer=true and
	// Kind="notification").
	NotifyChannel string `json:"notify_channel,omitempty"`
	NotifyPayload string `json:"notify_payload,omitempty"`

	// FunctionOID is the PostgreSQL function OID (函数对象标识符) for
	// Kind="function-call". 0 defaults to 1244 (nextval).
	FunctionOID int32 `json:"function_oid,omitempty"`

	// ArgumentFormatCodes (参数格式码) is the per-argument format code
	// list for Kind="function-call". 0 = text, 1 = binary. Empty = all
	// text (default).
	ArgumentFormatCodes []int16 `json:"argument_format_codes,omitempty"`

	// ResultFormatCode (结果格式码) is the format code for the
	// FunctionCall result. 0 = text (default), 1 = binary.
	ResultFormatCode int16 `json:"result_format_code,omitempty"`
}

// PGErrorField is a single field in ErrorResponse or NoticeResponse.
// PostgreSQL errors are a sequence of (1-byte type + C-string value)
// pairs terminated by a single \0 byte. Common type letters: S (severity
// localized), V (severity non-localized), C (5-char SQLSTATE), M
// (primary message), D (detail), H (hint), P (position), W (where),
// F (file), L (line), R (routine), q (internal query), s (internal
// position).
type PGErrorField struct {
	Type  byte   `json:"type"`
	Value string `json:"value"`
}

// PGField is one column descriptor in RowDescription. Each field carries
// the column name, table OID, column attribute number, type OID, type
// length, type modifier, and format code (0=text, 1=binary).
type PGField struct {
	Name       string `json:"name"`
	TableOID   int32  `json:"table_oid,omitempty"`
	Column     int16  `json:"column,omitempty"`
	TypeOID    int32  `json:"type_oid"`
	TypeLen    int16  `json:"type_len"`
	TypeMod    int32  `json:"type_mod,omitempty"`
	FormatCode int16  `json:"format_code,omitempty"`
}

// POP3Config for POP3 protocol (RFC 1939, 邮局协议第三版). POP3 is a
// session-level protocol: a single TCP connection on port 110 carries a
// sequence of command/response pairs across three states
// (AUTHORIZATION/TRANSACTION/UPDATE). The planner emits a TCP handshake,
// optional server banner, each POP3Command (client command + server
// response; multi-line responses are dot-terminated per RFC 1939 §3), then
// a TCP teardown - all within one flow (one 4-tuple, one sequence space
// per direction).
//
// Each POP3Command carries the command string (e.g. "USER alice") and the
// expected response. The response is emitted verbatim - the planner does
// NOT validate POP3 state transitions; it plays back the dialog the user
// specified. This matches the trafficgen contract: synthesize test
// packets, not a real POP3 server.
//
// Banner: when non-empty, the server emits this as the first POP3 payload
// (right after the handshake ACK). Real POP3 servers send
// "+OK POP3 server ready <timestamp@domain>" as the greeting; the APOP
// timestamp is parsed from it by real clients.
//
// Mailbox: when non-nil, the planner can synthesize RETR responses for
// commands flagged with EmitMailDrop=true. The response is built from the
// POP3Message at the specified 1-based index, including dot-stuffing and
// the CRLF.CRLF terminator. Lets users model bulk mail-download scenarios
// without hand-writing each message's wire bytes.
type POP3Config struct {
	Banner   string         `json:"banner,omitempty"` // server greeting, e.g. "+OK POP3 server ready"; empty = skip
	Commands []POP3Command  `json:"commands"`
	Mailbox  *POP3Mailbox   `json:"mailbox,omitempty"`
	// MSS is governed by TCPConfig.MSS. POP3 runs over TCP, so the planner
	// reads spec.TCP.MSS for segmentation of long POP3 responses.
}

// POP3Command is a single command/response pair within a POP3 session.
type POP3Command struct {
	// Cmd: the command string sent client -> server (e.g. "USER alice",
	// "RETR 1"). Appended with CRLF per RFC 1939 §3. Empty = skip command
	// emission (server-only turn, useful for AUTH PLAIN's intermediate
	// "+" challenge which is a server->client-only message).
	Cmd string `json:"cmd,omitempty"`

	// Response: the server response sent server -> client. Single-line
	// responses (e.g. "+OK", "-ERR no such message") get CRLF appended
	// automatically when Multiline=false. Multi-line responses (RETR/TOP/
	// LIST/UIDL/CAPA) must include the terminating "\r\n.\r\n" when the
	// user sets Multiline=true; the planner does NOT auto-add the
	// terminator in that case (matches FTP's verbatim contract). Empty =
	// skip response emission.
	Response string `json:"response,omitempty"`

	// Multiline: when true, the response is a multi-line POP3 response
	// (RFC 1939 §3). The planner emits the response as-is (no CRLF
	// appended) and the user is responsible for including the
	// CRLF.CRLF terminator. When false (default), the planner appends
	// CRLF to the response (single-line +OK/-ERR per RFC 1939 §3).
	Multiline bool `json:"multiline,omitempty"`

	// EmitMailDrop: when true, the planner synthesizes a RETR-like
	// multi-line response from Mailbox.Messages[MsgNum-1] and emits it
	// as the response INSTEAD of any user-provided Response. Requires
	// Mailbox to be set; Validate rejects EmitMailDrop=true with nil
	// Mailbox or out-of-range MsgNum. Useful for bulk mail download
	// scenarios (RETR 1, RETR 2, ... DELE N).
	EmitMailDrop bool `json:"emit_mail_drop,omitempty"`

	// MsgNum: 1-based message number for EmitMailDrop. Ignored when
	// EmitMailDrop is false. Out-of-range -> Validate returns error.
	MsgNum uint32 `json:"msg_num,omitempty"`
}

// POP3Mailbox describes the server-side maildrop state. Used to auto-
// generate RETR responses based on message content. When Mailbox is set,
// the planner can fill in responses for RETR commands flagged with
// EmitMailDrop=true even when the user leaves Response empty.
type POP3Mailbox struct {
	Messages []POP3Message `json:"messages"`
}

// POP3Message is a single email in the maildrop.
type POP3Message struct {
	// UID: the unique identifier for UIDL (1-70 chars, ASCII per RFC 1939
	// §7 UIDL). Empty = planner does NOT auto-generate (the user must
	// provide UIDL responses explicitly if they want UIDL tested). This
	// matches the design doc §6.2 contract.
	UID string `json:"uid,omitempty"`

	// Headers: email headers as a list of "Name: Value" strings (e.g.
	// "From: alice@example.com"). The planner emits each followed by CRLF
	// in RETR responses. Empty = no headers in the synthesized response.
	Headers []string `json:"headers,omitempty"`

	// Body: the email body (after the blank line separating headers from
	// body). Dot-stuffing is applied by the planner: lines starting with
	// "." get an extra "." prepended per RFC 1939 §3.
	Body string `json:"body,omitempty"`

	// Size: total size in octets (headers + blank line + body). 0 =
	// planner computes from Headers + Body. Used in the "+OK <size> octets"
	// status line of the RETR response.
	Size uint32 `json:"size,omitempty"`
}

// RDPConfig holds RDP (Remote Desktop Protocol) configuration. RDP is a
// multi-layer protocol stack on TCP/3389: TPKT (RFC 1006) → X.224
// (ISO 8073) → MCS (T.122) → GCC (T.124) → RDP Security/Info/Capability.
// Fields are populated by internal/protocol/rdp implementer per
// design_rdp.md §6.2.
//
// SecurityLayer selects the security layer negotiated via X.224 CC:
//   - "standard" — Standard RDP Security (RC4 + Security Exchange)
//   - "tls"      — TLS 1.x over TCP (no RC4)
//   - "nla"      — NLA / CredSSP (TLS + SPNEGO + TSCred)
//   - "nla_ex"   — NLA + Early User Authorization (PROTOCOL_HYBRID_EX)
//
// When RequestedProtocols is 0, the planner derives the bitmask from
// SecurityLayer. When non-zero, the user-supplied value is used verbatim
// (bitmask: 0x01 PROTOCOL_RDP, 0x02 PROTOCOL_SSL, 0x08 PROTOCOL_HYBRID,
// 0x20 PROTOCOL_HYBRID_EX — MS-RDPBCGR §2.2.1.1.1).
//
// RestrictedAdmin / RedirectedAuth map to X.224 CR Negotiation Request
// flags 0x01 / 0x02 respectively (MS-RDPBCGR §2.2.1.1).
//
// ClientName is UTF-16LE encoded into a FIXED 16-byte field per
// MS-RDPBCGR §2.2.1.3.2 (max 8 chars / 16 bytes; longer names are
// rejected at Validate time, shorter names are NULL-padded). ClientBuild
// is the OS build number (e.g. 0x00000A28 for Windows 10).
//
// Channels declares static virtual channels (cliprdr / rdpdr / rdpsnd /
// drdynvc etc.). The planner emits one MCS Channel-Join Request per
// channel (channel IDs 1004..1003+N per C-RDP-2), plus the implicit I/O
// channel (1003).
//
// SkipMCSChannelJoin / SkipSecurityExchange / SkipLicense / SkipCapability
// are test-only escapes that let the caller omit individual connection
// phases (used to exercise failure paths).
//
// ForceRDPVersion overrides the auto-derived version in Client Core Data
// (0x00080001=RDP5, 0x00080004=RDP6/7, 0x00080007=RDP8, 0x0008000a=RDP10).
//
// DataEvents drives the Active-phase payloads (FastPath Input, channel
// PDUs). ServerResponses drives the simulated server replies.
type RDPConfig struct {
	SecurityLayer      string `json:"security_layer,omitempty"` // "" / "standard" / "tls" / "nla" / "nla_ex"
	RequestedProtocols uint32 `json:"requested_protocols,omitempty"`

	// Negotiation Request flags (MS-RDPBCGR §2.2.1.1).
	RestrictedAdmin bool `json:"restricted_admin,omitempty"`
	RedirectedAuth  bool `json:"redirected_auth,omitempty"`

	// Cookie prepended to X.224 CR before Negotiation Request.
	// Format: "Cookie: mstshash=NAME\r\n". Empty = no cookie.
	Cookie string `json:"cookie,omitempty"`

	// Client identity.
	ClientName          string `json:"client_name,omitempty"`
	ClientBuild         uint32 `json:"client_build,omitempty"`
	KeyboardLayout      uint32 `json:"keyboard_layout,omitempty"`
	KeyboardType        uint32 `json:"keyboard_type,omitempty"`
	KeyboardSubType     uint32 `json:"keyboard_sub_type,omitempty"`
	KeyboardFunctionKey uint32 `json:"keyboard_function_key,omitempty"`

	// Desktop geometry.
	DesktopWidth         uint16 `json:"desktop_width,omitempty"`
	DesktopHeight        uint16 `json:"desktop_height,omitempty"`
	ColorDepth           uint16 `json:"color_depth,omitempty"`
	HighColorDepth       uint16 `json:"high_color_depth,omitempty"`
	SupportedColorDepths uint16 `json:"supported_color_depths,omitempty"`
	ConnectionType       uint8  `json:"connection_type,omitempty"`

	// ServerSelectedProtocol reflected back into Client Core Data
	// (MS-RDPBCGR §2.2.1.3.2). 0 = not negotiated yet.
	ServerSelectedProtocol uint32 `json:"server_selected_protocol,omitempty"`

	// Client Security Data (MS-RDPBCGR §2.2.1.4.2).
	EncryptionMethods    uint32 `json:"encryption_methods,omitempty"`
	ExtEncryptionMethods uint32 `json:"ext_encryption_methods,omitempty"`

	// Credentials (Client Info PDU §2.2.1.11).
	Domain         string `json:"domain,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	Password       string `json:"password,omitempty"`
	AlternateShell string `json:"alternate_shell,omitempty"`
	WorkingDir     string `json:"working_dir,omitempty"`

	// Static virtual channels.
	Channels []RDPChannel `json:"channels,omitempty"`

	// Client Info PDU flags.
	AutoLogon       bool   `json:"auto_logon,omitempty"`
	InfoUnicode     bool   `json:"info_unicode,omitempty"`
	InfoLogonNotify bool   `json:"info_logon_notify,omitempty"`
	InfoCompression bool   `json:"info_compression,omitempty"`
	CodePage        uint32 `json:"code_page,omitempty"`
	Flags2          uint16 `json:"flags2,omitempty"`

	// Phase-skip controls (test-only).
	SkipMCSChannelJoin   bool `json:"skip_mcs_channel_join,omitempty"`
	SkipSecurityExchange bool `json:"skip_security_exchange,omitempty"`
	SkipLicense          bool `json:"skip_license,omitempty"`
	SkipCapability       bool `json:"skip_capability,omitempty"`

	// ForceRDPVersion overrides Client Core version.
	ForceRDPVersion uint32 `json:"force_rdp_version,omitempty"`

	// Server Security Data (§2.2.1.4.3).
	EncryptionLevel   uint32 `json:"encryption_level,omitempty"`
	EncryptionMethod  uint32 `json:"encryption_method,omitempty"`
	ServerRandom      []byte `json:"server_random,omitempty"`
	ServerCertVersion uint32 `json:"server_cert_version,omitempty"`

	// SecurityExchangeRSAKeyBytes: dummy encryptedClientRandom length.
	// 0=default 128 (RSA-1024). Caller may set 64/128/256/512.
	SecurityExchangeRSAKeyBytes int `json:"security_exchange_rsa_key_bytes,omitempty"`

	// DataEvents are Active-phase payloads (client→server).
	DataEvents []RDPDataEvent `json:"data_events,omitempty"`

	// ServerResponses are simulated server replies during the session.
	ServerResponses []RDPServerResponse `json:"server_responses,omitempty"`
}

// RDPChannel is a single static virtual channel declaration
// (MS-RDPBCGR §2.2.1.3.4 ChannelDef). Name is a 7-char ASCII string
// padded to 8 bytes on the wire. Options bitmask:
//   0x00400000 REMOTE, 0x00800000 COMPRESS, 0x01000000 COMPRESS_RDP,
//   0x02000000 SHOW_PROTOCOL, 0x04000000 ENCRYPT_CS, 0x08000000 ENCRYPT_SC.
type RDPChannel struct {
	Name    string `json:"name"`
	Options uint32 `json:"options,omitempty"`
}

// RDPDataEvent is an Active-phase payload. Type selects the PDU shape
// (FastPath Input / Output, CLIPRDR / RDPDR / RDPSND / DRDYNVC).
// Channel selects the MCS channel name (e.g. "cliprdr"). Direction is
// "up" (default, client→server) or "down" (server→client). Payload is
// the business PDU bytes; if empty, the planner synthesises a minimal
// PDU of the requested type.
type RDPDataEvent struct {
	Type       string `json:"type"`
	Channel    string `json:"channel,omitempty"`
	Direction  string `json:"direction,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	PayloadB64 string `json:"payload_b64,omitempty"`
}

// RDPServerResponse is a server-driven Active-phase or capability-phase
// PDU. Type selects the PDU shape; Payload is the business PDU bytes.
// If Payload is empty, the planner synthesises a minimal PDU.
type RDPServerResponse struct {
	Type    string `json:"type"`
	Payload []byte `json:"payload,omitempty"`
}

// RedisConfig holds Redis RESP protocol configuration. Fields populated
// by internal/protocol/redis implementer per design_redis.md.
//
// Redis (RESP2/RESP3) is a session-level protocol: a single TCP
// connection on port 6379 carries command/reply frames. The planner
// emits a TCP handshake, optional HELLO/AUTH/SELECT/CLIENT SETNAME
// bootstrap, optional SUBSCRIBE/PSUBSCRIBE, each user command paired
// with its reply (or auto-derived reply), and finally QUIT + TCP
// teardown. See design_redis.md §7.
type RedisConfig struct {
	// Version selects RESP version (2 = classic, 3 = RESP3). Empty
	// defaults to 2. RESP3 requires HELLO 3 first; the planner emits
	// HELLO 3 (or HELLO 3 AUTH ...) at connection start when Version=3
	// unless SkipHello is true.
	Version int `json:"version,omitempty"`

	// SkipHello, when true, suppresses the auto-emitted HELLO 3 at the
	// top of the connection (RESP3 users who want to send HELLO 3 later
	// in their Commands). Default false.
	SkipHello bool `json:"skip_hello,omitempty"`

	// Auth fields: when non-empty, the planner prepends HELLO <V> AUTH
	// <u> <p> (RESP3) or AUTH <u> <p> (RESP2). Empty username with
	// password = legacy ACL step (single-arg AUTH).
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// SelectDB selects the logical database index (0..15) via SELECT n
	// right after auth/hello. -1 = skip.
	SelectDB int `json:"select_db,omitempty"`

	// ClientName is sent via CLIENT SETNAME <name> after hello/auth.
	// Empty = no CLIENT SETNAME.
	ClientName string `json:"client_name,omitempty"`

	// Commands is the ordered list of client→server command frames +
	// paired server→client reply frames. Each command becomes one RESP
	// array of bulk strings; replies are paired (Default behavior).
	//
	// When PipelineSize>1, the planner groups N consecutive commands
	// into one or more sends and emits N replies after the last send.
	Commands []RedisCommand `json:"commands,omitempty"`

	// SubscribeTo lists channels to subscribe in order (after auth). The
	// planner emits SUBSCRIBE c1 c2 ... as a single command frame and
	// emits the matching server "subscribe" confirmations.
	SubscribeTo []string `json:"subscribe_to,omitempty"`

	// SubscribePatterns lists glob patterns to PSUBSCRIBE.
	SubscribePatterns []string `json:"subscribe_patterns,omitempty"`

	// PublishMessages emits PUBLISH commands after SUBSCRIBE for
	// interaction testing: when set, the planner will emit PUBs on a
	// different "src port" if needed; otherwise PUBLISH is just another
	// entry in Commands.
	//
	// For the common subscribe-from-one-port / publish-from-another
	// simulation, users emit two flows (one SUBSCRIBE flow, one PUBLISH
	// flow on different SrcPort) — same approach as SIP signaling/media.
	PublishMessages []RedisPublish `json:"publish_messages,omitempty"`

	// PipelineSize controls how many commands the planner groups per
	// send before emitting replies. 0/1 = strict 1:1 (default). >1 =
	// pipeline: N commands, then N replies in order.
	PipelineSize int `json:"pipeline_size,omitempty"`

	// MSS is governed by TCPConfig.MSS. Planners read spec.TCP.MSS to
	// segment long command/reply frames so each fits in one TCP segment.
}

// RedisCommand is a single command paired with its expected reply.
//
// Args is the argument list (args[0] is the command name). The planner
// serializes each as a RESP bulk string ($<len>\r\n<data>\r\n); binary
// safe (no escaping needed). ArgsBase64 lets users embed binary args via
// JSON.
//
// Reply is the server→client reply; the planner emits it verbatim as
// the matching reply frame. Empty Reply + AutoReply=autoReplyOK means the
// planner will auto-derive a Simple String "+OK" reply; AutoReply=
// autoReplyQueued -> "+QUEUED"; AutoReply=autoReplyNone -> no reply frame
// (used for pipeline, where replies are consolidated at the end).
type RedisCommand struct {
	Args       []string `json:"args,omitempty"`
	ArgsBase64 []string `json:"args_base64,omitempty"`

	// Reply is the literal reply bytes (complete RESP frame including
	// leading type byte and trailing CRLF). The planner emits these
	// verbatim. Leading bytes:
	//   '+' = Simple String
	//   '-' = Error
	//   ':' = Integer
	//   '$' = Bulk String
	//   '*' = Array
	//   '#' / ',' / '_' / '(' / '!' / '=' / '%' / '~' / '>' / '|' = RESP3 types
	// Empty + AutoReply != none = planner auto-derives a reply.
	Reply string `json:"reply,omitempty"`

	// AutoReply controls auto-derivation when Reply is empty.
	//   "none"      (default): Reply must be provided; planner errors out.
	//   "ok"        : emit "+OK\r\n"
	//   "queued"    : emit "+QUEUED\r\n" (used inside MULTI)
	//   "pong"      : emit "+PONG\r\n"
	//   "nil"       : emit "$-1\r\n"  (NIL bulk, e.g. GET miss)
	//   "nil-array" : emit "*-1\r\n"  (e.g. BLPOP timeout)
	//   "integer-n" : n (int64) → emit ":<n>\r\n"
	//   "empty-arr" : emit "*0\r\n" (e.g. HGETALL on empty)
	AutoReply string `json:"auto_reply,omitempty"`

	// EmitAsPush, when true, makes the planner emit the Reply as a
	// server→client Push frame (RESP3 ">" prefix) instead of a normal
	// reply. Used to model server PUSH frames in pub/sub or invalidation.
	EmitAsPush bool `json:"emit_as_push,omitempty"`

	// Channel, when set, causes the planner to serialize a 1-element
	// command with Args=[Channel,V] as a binary-safe Request. (Used by
	// PUBLISH.) This is a convenience field; explicit Args still work.
	Channel string `json:"channel,omitempty"`
}

// RedisPublish describes a PUBLISH frame for the publish sub-flow. Used
// when the user wants one flow for SUBSCRIBE and another for PUBLISH.
type RedisPublish struct {
	Channel    string `json:"channel,omitempty"`
	Message    string `json:"message,omitempty"`
	MessageB64 string `json:"message_b64,omitempty"`
}

// AutoReply constant values used in RedisCommand.AutoReply.
const (
	RedisAutoReplyNone    = "none"     // default
	RedisAutoReplyOK      = "ok"
	RedisAutoReplyQueued  = "queued"
	RedisAutoReplyPong    = "pong"
	RedisAutoReplyNilBulk = "nil"
	RedisAutoReplyNilArr  = "nil-array"
	RedisAutoReplyIntZero = "integer-0"
	RedisAutoReplyIntOne  = "integer-1"
	RedisAutoReplyEmpty   = "empty-arr"
)

// ShadowsocksConfig holds Shadowsocks protocol configuration. Shadowsocks
// is a SOCKS5-based proxy protocol with pluggable encryption, primarily
// used to bypass GFW (Great Firewall, 中国国家互联网防火墙). The planner
// emits a TCP handshake (optional SOCKS5 negotiation + mandatory
// shadowsocks AEAD framing) or UDP datagrams, all carrying AEAD-encrypted
// payloads over the 4-tuple.
//
// Because shadowsocks encryption is non-decryptable from the test
// perspective, the planner focuses on byte-format conformance (salt
// length, chunk framing, tag presence, length fields), not on producing
// real cryptographic output. Use Mode="tcp" (default) or "udp".
type ShadowsocksConfig struct {
	// Mode (模式): "tcp" (default) or "udp". TCP emits handshake + salt +
	// AEAD chunks; UDP emits one (salt + AEAD-encrypted packet) per
	// datagram, no handshake.
	Mode string `json:"mode,omitempty"`

	// Cipher (加密算法) selects the AEAD cipher. Supported:
	// "aes-128-gcm" — AES-128-GCM, key=16B, salt=32B, tag=16B, nonce=12B
	// "aes-256-gcm" — AES-256-GCM, key=32B, salt=32B, tag=16B, nonce=12B
	// "chacha20-ietf-poly1305" — ChaCha20-Poly1305, key=32B, salt=32B, tag=16B, nonce=12B
	// "none" — SIP004 plaintext, no salt/tag
	// "2022-blake3-aes-128-gcm" — SIP022 AEAD 2022 (BLAKE3 KDF)
	// "2022-blake3-aes-256-gcm" — SIP022 AEAD 2022 (BLAKE3 KDF)
	// "2022-blake3-chacha20-poly1305" — SIP022 AEAD 2022 (BLAKE3 KDF)
	// Default: "aes-256-gcm" (most common modern deployment).
	Cipher string `json:"cipher,omitempty"`

	// SOCKS5Handshake (SOCKS5握手), when true, emits a plain SOCKS5 negotiation
	// (RFC 1928) BEFORE the shadowsocks salt + AEAD chunks. Default
	// false (modern shadowsocks clients skip the SOCKS5 layer; the
	// traffic between client and proxy is raw shadowsocks AEAD).
	// When true, the planner additionally reads SOCKS5 fields below.
	SOCKS5Handshake bool `json:"socks5_handshake,omitempty"`

	// SOCKS5AuthMethod (SOCKS5认证方法): "none" (default) or "password". When
	// SOCKS5Handshake=true, the planner emits the corresponding
	// method in METHODS and the matching sub-negotiation
	// (RFC 1929 USERNAME/PASSWORD when "password").
	SOCKS5AuthMethod string `json:"socks5_auth_method,omitempty"`

	// SOCKS5Username / SOCKS5Password (SOCKS5用户名/密码): required when
	// SOCKS5AuthMethod="password". UTF-8 strings.
	SOCKS5Username string `json:"socks5_username,omitempty"`
	SOCKS5Password string `json:"socks5_password,omitempty"`

	// SOCKS5Cmd (SOCKS5命令): "connect" (default, value 0x01), "bind" (0x02),
	// or "udp_associate" (0x03). UDP_ASSOCIATE requires Mode="udp".
	SOCKS5Cmd string `json:"socks5_cmd,omitempty"`

	// SOCKS5DstAddr / SOCKS5DstPort (SOCKS5目标地址/端口): target address/port for the
	// SOCKS5 CONNECT/BIND request. Type (IPv4/IPv6/domain) is
	// inferred from the address format. For ATYP=0x03 (domain),
	// pass the ASCII domain as SOCKS5DstAddr.
	SOCKS5DstAddr string `json:"socks5_dst_addr,omitempty"`
	SOCKS5DstPort uint16 `json:"socks5_dst_port,omitempty"`

	// SOCKS5BNDAddr / SOCKS5BNDPort (SOCKS5绑定地址/端口): bound address/port in the
	// SOCKS5 reply from the proxy. Empty = 0.0.0.0:0 (default reply).
	SOCKS5BNDAddr string `json:"socks5_bnd_addr,omitempty"`
	SOCKS5BNDPort uint16 `json:"socks5_bnd_port,omitempty"`

	// Chunks (AEAD数据块数量): number of AEAD chunks to emit. 0 = derive from
	// FlowSpec.Payload (chunk payload_size <= 0x3FFF). Each chunk
	// carries Payload bytes (or random bytes when Payload empty).
	// Default 1.
	Chunks int `json:"chunks,omitempty"`

	// ChunkPayloadSize (每块负载大小): bytes per chunk (<= 0x3FFF). 0 = use
	// FlowSpec.Payload split, or 0x3FFF if Payload empty.
	ChunkPayloadSize int `json:"chunk_payload_size,omitempty"`

	// Obfuscation (混淆): "" (default, raw AEAD) or "http" (prepend
	// HTTP CONNECT header before salt; some shadowsocks-android
	// forks). Requires SOCKS5Handshake=false (mutually exclusive
	// with SOCKS5 framing layer).
	Obfuscation string `json:"obfuscation,omitempty"`

	// ObfMethod (混淆HTTP方法): "CONNECT" (default) or "POST" for HTTP obfuscation.
	ObfMethod string `json:"obf_method,omitempty"`

	// ObfHeaders (混淆HTTP头): optional custom HTTP headers for obfuscation.
	ObfHeaders map[string]string `json:"obf_headers,omitempty"`

	// PayloadBytesFormat (负载字节格式): "random" (default, bytes 0..255 random)
	// or "zeros" (all 0x00) for the encrypted payload / UDP payload
	// content. Encryption is NOT applied — the planner emits
	// correctly-framed but random/plaintext bytes.
	PayloadBytesFormat string `json:"payload_bytes_format,omitempty"`

	// FRAG (UDP分片ID): UDP fragment ID (0x00 default). Used in UDP relay mode.
	FRAG uint8 `json:"frag,omitempty"`

	// FileSource (文件源), when set, supplies the AEAD chunk payload bytes
	// via PayloadCache.GetOrLoad(src) instead of synthesizing
	// per-chunk random/zeros. Each Chunks iteration reads the
	// next ChunkPayloadSize bytes from the cached file. nil = use
	// PayloadBytesFormat synthesis.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// SMTPConfig holds SMTP (RFC 5321) protocol configuration. SMTP is a
// session-level text protocol: a single TCP connection on port 25 carries
// a sequence of command/response pairs. The planner emits a TCP
// handshake, the server banner (220 greeting), each SMTPCommand in
// Dialog (as PSH-ACK payload), then a TCP teardown - all within one
// flow.
//
// Each SMTPCommand carries a client command string (Cmd, e.g.
// "HELO client.example.org") and/or a server response string (Response,
// e.g. "250 OK"). The planner appends CRLF per RFC 5321 §2.3 to both.
// When Direction is empty the planner infers it: Cmd non-empty -> "up"
// (client->server); Response non-empty -> "down" (server->client). The
// Direction field lets the user override the inference for unusual
// cases (e.g. an empty Cmd with a Response that should still go "up").
//
// The planner plays back the Dialog verbatim - it does NOT implement a
// real SMTP state machine, matching the trafficgen contract (synthesize
// test packets, not a real server). When Dialog is empty, the planner
// emits a default session (HELO + MAIL FROM + RCPT TO + DATA + empty
// body + QUIT) so trivial specs produce a complete SMTP pcap.
//
// DATA terminator: per RFC 5321 §4.1.1.4 the body is terminated by
// "\r\n.\r\n" (CRLF, period, CRLF). The user supplies the body Cmd
// ending with "\r\n." and the planner's appended "\r\n" completes the
// terminator. Dot-stuffing (RFC 5321 §4.5.2) is the user's
// responsibility - the planner emits body bytes verbatim.
type SMTPConfig struct {
	// Banner is the server greeting (220 response). When empty, the
	// planner auto-generates "220 <DstIP> ESMTP trafficgen" per
	// design_smtp.md §8.6.
	Banner string `json:"banner,omitempty"`

	// Dialog is the SMTP command/response sequence (executed in order).
	// When nil/empty, the planner emits a default session per §6.6.
	Dialog []SMTPCommand `json:"dialog"`

	// MSS is governed by TCPConfig.MSS. SMTP runs over TCP, so the
	// planner reads spec.TCP.MSS for segmentation of long SMTP payloads.
}

// SMTPCommand is a single command/response pair within an SMTP session.
// Either Cmd or Response may be empty - an empty Cmd with a non-empty
// Response models a server-only turn (e.g. the 354 response after
// DATA), and a non-empty Cmd with an empty Response models a
// client-only turn (e.g. the DATA body itself, which has no immediate
// response).
type SMTPCommand struct {
	// Cmd is the client command line (e.g. "HELO client.example.org"),
	// sent client -> server. The planner appends "\r\n". Empty = skip
	// the command packet. For the DATA body, the user supplies the body
	// ending with "\r\n." so the appended "\r\n" completes the
	// "\r\n.\r\n" terminator.
	Cmd string `json:"cmd,omitempty"`

	// Response is the server response line (e.g. "250 2.1.0 Ok"), sent
	// server -> client. The planner appends "\r\n". Multi-line
	// responses (e.g. EHLO capability list) are supplied as a single
	// string with embedded "\r\n" - the planner emits the bytes
	// verbatim. Empty = skip the response packet.
	Response string `json:"response,omitempty"`

	// Direction overrides the default direction inference. Empty = infer
	// (Cmd non-empty -> "up"; Response non-empty -> "down"). "up" =
	// client->server; "down" = server->client. Use this when both Cmd
	// and Response are set but should go the same direction (rare), or
	// when only one is set but should go the non-default direction.
	Direction string `json:"direction,omitempty"`
}

// SNMPConfig holds SNMP protocol configuration. Fields populated by
// internal/protocol/snmp implementer per design_snmp.md.
type SNMPConfig struct {
	// Version & authentication (认证).
	Version      uint8  `json:"version"`       // 0=v1, 1=v2c, 3=v3; default 1 (v2c)
	Community    string `json:"community"`     // v1/v2c plaintext (default "public"); v3 unused
	UserName     string `json:"user_name"`     // v3 user name (discovery uses "")
	AuthProtocol string `json:"auth_protocol"` // v3: none/md5/sha1/sha224/sha256/sha384/sha512
	AuthPassword string `json:"auth_password"` // v3 auth password (planner derives localizedKey)
	PrivProtocol string `json:"priv_protocol"` // v3: none/des/aes128/aes192/aes256
	PrivPassword string `json:"priv_password"` // v3 priv password

	// Engine parameters (v3 required; filled after discovery, 引擎参数).
	AuthoritativeEngineID    string `json:"authoritative_engine_id"`    // hex string, 1-32 bytes
	AuthoritativeEngineBoots uint32 `json:"authoritative_engine_boots"` // engine restart count
	AuthoritativeEngineTime  uint32 `json:"authoritative_engine_time"`  // seconds since last boot

	// Operation config (操作配置).
	PDUType        uint8         `json:"pdu_type"`        // 0=Get, 1=GetNext, 2=Set, 3=GetBulk, 4=TrapV1, 5=TrapV2, 6=Inform
	RequestID      uint32        `json:"request_id"`      // 0 = incrementing from random start
	NonRepeaters   uint8         `json:"non_repeaters"`   // GetBulk: non-repeating varbind count
	MaxRepetitions uint8         `json:"max_repetitions"` // GetBulk: repeating varbind max-repetitions
	VarBinds       []SNMPVarBind `json:"var_binds"`       // variable bindings (变量绑定)

	// Response / trap config (响应/陷阱配置).
	IsResponse         bool          `json:"is_response"`          // emit Response PDU after request
	ResponseError      uint8         `json:"response_error"`       // Response error-status (0=noError)
	ResponseErrorIndex uint8         `json:"response_error_index"` // Response error-index
	ResponseValues     []SNMPVarBind `json:"response_values"`      // Response varbinds (overrides VarBinds)

	// Behavior control (行为控制).
	PollInterval     int    `json:"poll_interval"`      // ms between repeats
	RepeatCount      int    `json:"repeat_count"`       // total emissions (overrides spec.Count)
	EngineIDOverride string `json:"engine_id_override"` // skip discovery, use this ID

	// v3 message-level fields (v3 消息字段).
	MaxSize     uint32 `json:"max_size"`     // msgMaxSize (default 484)
	ContextName string `json:"context_name"` // scopedPDU contextName
}

// SNMPVarBind is a single variable binding (变量绑定): OID + value.
type SNMPVarBind struct {
	Name     string `json:"name"`                // OID string, e.g. "1.3.6.1.2.1.1.1.0"
	Type     uint8  `json:"type,omitempty"`      // BER tag: 0x05 NULL / 0x02 INTEGER / 0x04 OCTET STRING / 0x06 OID / 0x40 IpAddress / 0x41 Counter32 / 0x42 Gauge32 / 0x43 TimeTicks / 0x46 Counter64 / 0x80 noSuchObject / 0x81 noSuchInstance / 0x82 EndOfMibView
	Value    []byte `json:"value,omitempty"`     // raw bytes (NULL/exception types: empty)
	StrValue string `json:"str_value,omitempty"` // string-form value for DisplayString convenience
}

// SSDPConfig holds SSDP (Simple Service Discovery Protocol, 简单服务发现协议)
// configuration. SSDP is the discovery layer of UPnP (Universal Plug and Play,
// 通用即插即用), carrying HTTP-formatted text over UDP port 1900 to either IPv4
// multicast 239.255.255.250 or IPv6 multicast ff02::c.
//
// The planner generates either a NOTIFY (device announce/bye/update, sent
// to the multicast group) or an M-SEARCH (control point search, sent to
// the multicast group, with singlecast 200 OK responses). Each message is
// a self-contained UDP datagram — there is no TCP-style state machine, no
// connection, no keep-alive. SSDP borrows HTTP/1.1 message syntax only
// (request/status line + CRLF-terminated headers + blank line + body);
// HTTP semantics (chunked, keep-alive, 100-continue) do NOT apply.
//
// MessageType selects the role:
// - "alive": NOTIFY * HTTP/1.1 + NTS=ssdp:alive + mandatory headers.
// - "byebye": NOTIFY * HTTP/1.1 + NTS=ssdp:byebye + minimal headers.
// - "update": NOTIFY * HTTP/1.1 + NTS=ssdp:update.
// - "msearch": M-SEARCH * HTTP/1.1 + MAN="ssdp:discover" + ST + MX.
// - "response": HTTP/1.1 200 OK (singlecast reply to msearch).
type SSDPConfig struct {
	// MessageType (消息类型): "alive" / "byebye" / "update" / "msearch" /
	// "response". Required. Validate returns error when empty or unknown.
	MessageType string `json:"message_type"`

	// SearchTarget (搜索目标): NT for NOTIFY, ST for M-SEARCH/response.
	// Examples: "upnp:rootdevice", "ssdp:all", "uuid:<UUID>",
	// "urn:schemas-upnp-org:device:MediaServer:1". Required for all
	// message types.
	SearchTarget string `json:"search_target"`

	// USN (Unique Service Name, 唯一服务名). Required for NOTIFY and response.
	// Format: "uuid:<UUID>" or "uuid:<UUID>::<NT>". M-SEARCH does NOT carry USN.
	USN string `json:"usn"`

	// Location (设备描述文档URL). Used by alive and response (LOCATION header).
	// Format: "http://<ip>:<port>/<path>". Empty -> header omitted.
	Location string `json:"location,omitempty"`

	// Server (设备信息字符串). Used by alive / response (SERVER header) and
	// msearch (USER-AGENT header). Empty -> header omitted. Max 256 bytes
	// recommended, 4096 bytes hard limit (Validate error).
	Server string `json:"server,omitempty"`

	// MaxAge (缓存寿命秒数). Used by alive (Cache-Control: max-age=N).
	// 0 means "use default 1800". Validate enforces 1 <= MaxAge <= 1800.
	MaxAge int `json:"max_age,omitempty"`

	// MX (最大等待时间秒). Used by msearch (MX: N).
	// 0 means "use default 3". Validate enforces 1 <= MX <= 5.
	MX int `json:"mx,omitempty"`

	// BootID (设备启动ID). Optional on alive/update (BOOTID.UPNP.ORG header).
	// 0 -> header omitted. uint32 range (1 to 2^31-1 sensible).
	BootID uint32 `json:"boot_id,omitempty"`

	// ConfigID (设备配置ID). Optional on alive/update (CONFIGID.UPNP.ORG).
	// 0 -> header omitted.
	ConfigID uint32 `json:"config_id,omitempty"`

	// NextBootID (新启动ID). Optional on update (NEXTBOOTID.UPNP.ORG header,
	// UPnP DA 1.1 §1.2.3). When a device sends ssdp:update, NEXTBOOTID.UPNP.ORG
	// indicates the new boot ID if it is changing. 0 -> header omitted.
	NextBootID uint32 `json:"next_boot_id,omitempty"`

	// SearchPort (搜索端口). Optional on update (SEARCHPORT.UPNP.ORG header,
	// UPnP DA 1.1 §1.2.3). Indicates the port on which the device listens for
	// M-SEARCH responses after the configuration change. 0 -> header omitted.
	SearchPort uint16 `json:"search_port,omitempty"`

	// ResponseCount. Used by msearch: number of singlecast 200 OK responses
	// to emit (simulating K devices replying). 0/1 = 1 response. Each
	// response shares flow_id but increments packet_index.
	ResponseCount int `json:"response_count,omitempty"`

	// ResponseDelayMinMs / ResponseDelayMaxMs. Used by msearch when
	// ResponseCount > 1: random delay in [Min, Max] ms between each
	// 200 OK response (UPnP 1.1 §1.3.4 mandates 0..MX seconds uniform).
	// Default: 0..3000 (mapping MX=3 default). Validate requires Min<=Max.
	ResponseDelayMinMs int `json:"response_delay_min_ms,omitempty"`
	ResponseDelayMaxMs int `json:"response_delay_max_ms,omitempty"`

	// RepeatCount. Used by alive/update: emit the same message N times
	// within the same flow (each as its own PacketConfig with packet_index
	// increment). 0/1 = 1 packet (default). Inter-packet delay defaults to
	// MaxAge/3 seconds (UPnP 1.1 §1.2.2 re-announce pattern); override via
	// RepeatIntervalMs.
	RepeatCount int `json:"repeat_count,omitempty"`

	// Date (HTTP-date格式). Used by response (DATE header).
	// Format: RFC 7231 §7.1.1.1, e.g. "Sun, 28 Jul 2026 12:34:56 GMT".
	// Empty -> header omitted.
	Date string `json:"date,omitempty"`

	// MulticastGroup override (多播组覆盖). Defaults to "239.255.255.250"
	// for IPv4 and "ff02::c" for IPv6. Planner emits this in the HOST
	// header AND uses it as the IP destination. For point-to-point tests,
	// set to a unicast IP (legal for response messages).
	MulticastGroup string `json:"multicast_group,omitempty"`

	// OmitExt controls whether the EXT header is omitted in response
	// messages. Default false (EXT header is emitted per UPnP 1.1 §1.3).
	// Setting true suppresses the EXT header for negative testing.
	OmitExt bool `json:"omit_ext,omitempty"`

	// Body (可选报文主体). Empty -> no body. Used by response for optional
	// device description XML payload.
	Body string `json:"body,omitempty"`

	// EmitContentLength controls whether Content-Length header is emitted.
	// Default false (SSDP convention omits Content-Length for empty body).
	// When true and Body is non-empty, Content-Length: <len> is emitted.
	EmitContentLength bool `json:"emit_content_length,omitempty"`

	// RepeatIntervalMs overrides the default MaxAge/3 seconds between
	// repeat packets (used when RepeatCount > 1). 0 = use default.
	RepeatIntervalMs int `json:"repeat_interval_ms,omitempty"`
}

// SSHConfig holds SSH protocol configuration. Fields populated by
// internal/protocol/ssh implementer per design_ssh.md.
//
// SSH is a session-level, encrypted, multi-layer protocol: TCP carries
// Version Exchange (text) → BPP binary packets (with KEXINIT/KEXDH/NEWKEYS/
// SERVICE/USERAUTH/CHANNEL messages) → encrypted channel (post-NEWKEYS).
//
// Encryption is NOT implemented: post-NEWKEYS payload bytes are opaque
// (dummy or user-supplied). Wireshark can still parse BPP framing and
// display message_number + field lengths, but the encrypted content is
// indistinguishable from real SSH to a DPI that doesn't terminate SSH.
type SSHConfig struct {
	// ServerVersion is the SSH-2.0-<softwareversion><SP comments> string
	// the server emits FIRST (before client version). Empty = use default
	// "SSH-2.0-trafficgen_1.0".
	ServerVersion string `json:"server_version,omitempty"`

	// ClientVersion is the SSH-2.0-<softwareversion> string the client
	// emits AFTER server version. Empty = use default
	// "SSH-2.0-trafficgen_1.0".
	ClientVersion string `json:"client_version,omitempty"`

	// KexAlgorithms is the comma-separated list of KEX algorithms offered
	// by both sides in KEXINIT. Empty = use RFC 8308 default.
	KexAlgorithms string `json:"kex_algorithms,omitempty"`

	// HostKeyAlgorithms is the comma-separated list of host key algorithms
	// in KEXINIT. Empty = use default.
	HostKeyAlgorithms string `json:"host_key_algorithms,omitempty"`

	// EncryptionAlgorithms is the comma-separated list of encryption
	// algorithms in KEXINIT. Empty = use default.
	EncryptionAlgorithms string `json:"encryption_algorithms,omitempty"`

	// MACAlgorithms is the comma-separated list of MAC algorithms in
	// KEXINIT. Empty = use default.
	MACAlgorithms string `json:"mac_algorithms,omitempty"`

	// CompressionAlgorithms is the comma-separated list of compression
	// algorithms in KEXINIT. Empty = use default.
	CompressionAlgorithms string `json:"compression_algorithms,omitempty"`

	// KEX is the KEX method. Empty = "curve25519-sha256" (most common).
	KEX string `json:"kex,omitempty"`

	// AuthMethods is the ordered list of user authentication attempts.
	AuthMethods []SSHMessage `json:"auth_methods,omitempty"`

	// ExtInfo, when true, adds SSH_MSG_EXT_INFO (RFC 8308) after NEWKEYS.
	ExtInfo bool `json:"ext_info,omitempty"`

	// Channels is the ordered list of channel-layer activities after
	// USERAUTH_SUCCESS.
	Channels []ChannelEntry `json:"channels,omitempty"`

	// RekeyAfter, when >0, triggers a re-KEX after Nth BPP packet.
	RekeyAfter uint32 `json:"rekey_after,omitempty"`

	// DisconnectOnClose, when true, emits SSH_MSG_DISCONNECT before TCP
	// teardown.
	DisconnectOnClose bool `json:"disconnect_on_close,omitempty"`
}

// SSHMessage is a single SSH message in the User Auth dialog or as a
// special disconnect message. Direction "up" = client→server, "down" =
// server→client.
type SSHMessage struct {
	// Type identifies the message. One of:
	//   "service_request", "service_accept", "userauth_request",
	//   "userauth_failure", "userauth_success", "userauth_banner",
	//   "userauth_info_request", "userauth_info_response",
	//   "disconnect" (post-AUTH).
	Type string `json:"type,omitempty"`

	// Direction "up" (client→server) or "down" (server→client). Empty →
	// planner infers from Type.
	Direction string `json:"direction,omitempty"`

	// ServiceName (Type=service_request|service_accept).
	ServiceName string `json:"service_name,omitempty"`

	// --- USERAUTH_REQUEST fields ---
	MethodName          string `json:"method_name,omitempty"`
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	HasPasswordChange   bool   `json:"has_password_change,omitempty"`
	NewPassword         string `json:"new_password,omitempty"`
	PublicKeyAlgorithm  string `json:"public_key_algorithm,omitempty"`
	PublicKeyBlob       []byte `json:"public_key_blob,omitempty"`
	HasSignature        bool   `json:"has_signature,omitempty"`
	Signature           []byte `json:"signature,omitempty"`
	Submethods          string `json:"submethods,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
	Response            string `json:"response,omitempty"`

	// --- USERAUTH_FAILURE fields ---
	AuthMethodsThatCanContinue string `json:"auth_methods_that_can_continue,omitempty"`
	PartialSuccess             bool   `json:"partial_success,omitempty"`

	// --- USERAUTH_BANNER fields ---
	Banner      string `json:"banner,omitempty"`
	LanguageTag string `json:"language_tag,omitempty"`

	// --- USerauth_INFO_REQUEST fields ---
	Name        string `json:"name,omitempty"`
	Instruction string `json:"instruction,omitempty"`
	PromptCount uint32 `json:"prompt_count,omitempty"`
	Prompts     string `json:"prompts,omitempty"`
	Echo        bool   `json:"echo,omitempty"`
	NumResponses uint32 `json:"num_responses,omitempty"`
	Responses    string `json:"responses,omitempty"`

	// --- DISCONNECT fields ---
	ReasonCode  uint32 `json:"reason_code,omitempty"`
	Description string `json:"description,omitempty"`

	// --- UNIMPLEMENTED fields ---
	ReceiveSeq uint32 `json:"receive_seq,omitempty"`

	// --- DEBUG fields ---
	AlwaysDisplay bool `json:"always_display,omitempty"`
	Message       string `json:"message,omitempty"`

	// --- IGNORE / generic data ---
	Data []byte `json:"data,omitempty"`
}

// ChannelEntry is a single channel-layer activity. The planner emits
// channel-layer entries in order after USERAUTH_SUCCESS, all under
// encryption (opaque payload).
type ChannelEntry struct {
	// Type identifies the entry. One of:
	//   "channel_open", "channel_open_confirmation", "channel_open_failure",
	//   "channel_request", "channel_data", "channel_extended_data",
	//   "channel_eof", "channel_close", "channel_window_adjust",
	//   "global_request".
	Type string `json:"type,omitempty"`

	// Direction "up" (client→server) or "down" (server→client).
	Direction string `json:"direction,omitempty"`

	// SenderChannel (Type=channel_open). 0 = planner auto-increments.
	SenderChannel uint32 `json:"sender_channel,omitempty"`

	// RecipientChannel for channel_open_confirmation / _failure /
	// channel_request / channel_data / etc. 0 = planner uses most
	// recently opened channel.
	RecipientChannel uint32 `json:"recipient_channel,omitempty"`

	// ChannelType (Type=channel_open).
	ChannelType string `json:"channel_type,omitempty"`

	// InitialWindowSize (Type=channel_open). 0 = 2097152 (2MB).
	InitialWindowSize uint32 `json:"initial_window_size,omitempty"`

	// MaximumPacketSize (Type=channel_open). 0 = 32768 (32KB).
	MaximumPacketSize uint32 `json:"maximum_packet_size,omitempty"`

	// --- direct-tcpip fields ---
	DestHost       string `json:"dest_host,omitempty"`
	DestPort       uint32 `json:"dest_port,omitempty"`
	OriginatorIP   string `json:"originator_ip,omitempty"`
	OriginatorPort uint32 `json:"originator_port,omitempty"`

	// --- CHANNEL_REQUEST fields ---
	RequestType string `json:"request_type,omitempty"`
	WantReply   bool   `json:"want_reply,omitempty"`

	// --- pty-req fields ---
	Term         string `json:"term,omitempty"`
	WidthChars   uint32 `json:"width_chars,omitempty"`
	HeightRows   uint32 `json:"height_rows,omitempty"`
	WidthPixels  uint32 `json:"width_pixels,omitempty"`
	HeightPixels uint32 `json:"height_pixels,omitempty"`
	TTYModes     []byte `json:"tty_modes,omitempty"`

	// --- exec field ---
	Command string `json:"command,omitempty"`

	// --- env field ---
	EnvVarName  string `json:"env_var_name,omitempty"`
	EnvVarValue string `json:"env_var_value,omitempty"`

	// --- subsystem field ---
	SubsystemName string `json:"subsystem_name,omitempty"`

	// --- signal field ---
	SignalName string `json:"signal_name,omitempty"`

	// --- exit-status field ---
	ExitStatus uint32 `json:"exit_status,omitempty"`

	// --- channel_data / channel_extended_data fields ---
	Data         []byte `json:"data,omitempty"`
	DataTypeCode uint32 `json:"data_type_code,omitempty"`

	// --- channel_window_adjust field ---
	BytesToAdd uint32 `json:"bytes_to_add,omitempty"`

	// --- channel_open_failure field ---
	OpenReasonCode uint32 `json:"open_reason_code,omitempty"`
	OpenReasonText string `json:"open_reason_text,omitempty"`

	// --- GLOBAL_REQUEST fields ---
	GlobalRequestName string `json:"global_request_name,omitempty"`
	Address           string `json:"address,omitempty"`
	Port              uint32 `json:"port,omitempty"`

	// --- x11-req fields ---
	X11AuthProtocol  string `json:"x11_auth_protocol,omitempty"`
	X11AuthCookie    []byte `json:"x11_auth_cookie,omitempty"`
	X11ScreenNumber  uint32 `json:"x11_screen_number,omitempty"`
	SingleConnection bool   `json:"single_connection,omitempty"`
}

// SyslogConfig holds Syslog protocol configuration per RFC 5424/5425/5426/
// 6587/5848/3164. Field naming follows design_syslog.md §6.1; defaults are
// applied in the syslog planner's Plan goroutine (per validate_conventions.md
// §1.3 - Validate is read-only).
type SyslogConfig struct {
	// Facility 0-23 (RFC 5424 §6.2.1). 0=kern, 1=user, ..., 23=reserved.
	Facility uint8 `json:"facility"`
	// Severity 0-7 (RFC 5424 §6.2.1). 0=emerg, ..., 7=debug.
	Severity uint8 `json:"severity"`
	// Version is the protocol version. 1 for RFC 5424 (required when
	// Format="rfc5424"); 0 with Format="bsd" selects RFC 3164 layout.
	Version uint8 `json:"version"`
	// Timestamp is an RFC 3339 string. "" or "-" emits NILVALUE "-"
	// (RFC 5424 §6.2.3). Non-empty non-"-" must parse as RFC 3339.
	Timestamp string `json:"timestamp,omitempty"`
	// Hostname 1-255 bytes (RFC 5424 §6.2.4). "" emits NILVALUE "-".
	Hostname string `json:"hostname,omitempty"`
	// AppName 1-48 bytes (RFC 5424 §6.2.5). "" emits NILVALUE "-".
	AppName string `json:"app_name,omitempty"`
	// ProcID 1-128 bytes (RFC 5424 §6.2.6). "" emits NILVALUE "-".
	ProcID string `json:"proc_id,omitempty"`
	// MsgID 1-32 bytes (RFC 5424 §6.2.7). "" emits NILVALUE "-".
	MsgID string `json:"msg_id,omitempty"`
	// StructuredData is a list of pre-framed SD-ELEMENT strings (RFC 5424
	// §6.2.8), e.g. `origin ip="192.0.2.1"` or the full `[origin ip="..."]`.
	// Elements are concatenated without spaces. Empty list emits NILVALUE "-".
	// The planner wraps bare `id` or `id key="val"` forms with `[...]`.
	StructuredData []string `json:"structured_data,omitempty"`
	// Msg is the message body (RFC 5424 §6.2.9), UTF-8. Empty allowed.
	Msg string `json:"msg,omitempty"`
	// MsgHasBOM prepends UTF-8 BOM (EF BB BF) before Msg per RFC 5424 §6.4.4.
	// BOM replaces the SP separator between STRUCTURED-DATA and MSG. Ignored
	// when Msg is empty.
	MsgHasBOM bool `json:"msg_has_bom,omitempty"`
	// Format selects layout: "rfc5424" (default) or "bsd" (RFC 3164).
	Format string `json:"format,omitempty"`
	// Transport selects L4: "udp" (default, port 514, RFC 5426),
	// "tcp" (port 514, RFC 6587), or "tls" (port 6514, RFC 5425).
	Transport string `json:"transport,omitempty"`
	// TCPFraming selects TCP frame format: "octet_counting" (default,
	// RFC 6587 §3) or "non_transparent" (RFC 6587 §4). Only meaningful
	// when Transport is tcp or tls.
	TCPFraming string `json:"tcp_framing,omitempty"`
	// Count is the number of syslog messages emitted per flow. 0 = 1.
	Count uint32 `json:"count,omitempty"`
	// SignBlocks carries RFC 5848 syslog-sign signature values. Each value
	// is wrapped as `[sign@32473 signature="<value>"]` and appended to
	// STRUCTURED-DATA. The planner escapes `"`, `\`, `]` per RFC 5424 §6.2.8.
	SignBlocks []string `json:"sign_blocks,omitempty"`
}

// TelnetConfig holds Telnet protocol configuration per design_telnet.md.
//
// Telnet (RFC 854) is a session-level protocol running over a single TCP
// connection on port 23. The stream is a mix of NVT (Network Virtual
// Terminal) ASCII data bytes and IAC (Interpret As Command, 0xFF) command
// sequences. The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
//  2. Optional server banner (e.g. "login: ") as the first PSH-ACK payload.
//  3. Each TelnetEvent in Dialog, in order (data/will/wont/do/dont/sb/
//     ttype_send/ttype_is/naws/ip/dm/nop/ayt/brk/ao/ec/el/ga/synch).
//  4. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The planner does NOT implement Option negotiation state (RFC 1143 Q
// method); it emits the dialog verbatim as specified by the user.
type TelnetConfig struct {
	// Banner is the optional server greeting (NVT ASCII, e.g. "login: ").
	// Empty = skip banner. Emitted as PSH-ACK payload right after the
	// handshake ACK. 0xFF bytes are auto-escaped to 0xFF 0xFF.
	Banner string `json:"banner,omitempty"`

	// Dialog is the ordered list of Telnet events. Each event is either
	// a data string (NVT ASCII) or an IAC command. The planner emits
	// each event as one or more PSH-ACK segments (MSS-segmented for long
	// data; IAC commands are never split across segments).
	// nil/empty -> planner uses defaultDialog() (a minimal login shape).
	Dialog []TelnetEvent `json:"dialog,omitempty"`

	// TerminalType is the terminal type string sent in response to
	// SB TTYPE SEND (e.g. "xterm-256color"). Empty = "xterm" default.
	// Used by the planner when a TelnetEvent of type "ttype_is" is
	// emitted without an explicit Value.
	TerminalType string `json:"terminal_type,omitempty"`

	// WindowCols / WindowRows are the initial NAWS value sent in
	// SB NAWS <cols> <rows>. Zero values = skip NAWS negotiation
	// (planner falls back to 80x24 when an explicit naws event has
	// Cols/Rows=0). Used when a TelnetEvent of type "naws" is emitted
	// without explicit Cols/Rows.
	WindowCols uint16 `json:"window_cols,omitempty"`
	WindowRows uint16 `json:"window_rows,omitempty"`

	// FileSource, when set, supplies NVT ASCII data bytes via
	// PayloadCache.GetOrLoad(src) instead of inline Data. The bytes
	// are emitted as a single data event (MSS-segmented) BEFORE the
	// Dialog events. 0xFF bytes in the file are auto-escaped.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// TelnetEvent is a single event in a Telnet dialog. Exactly one of the
// type-specific fields should be set per event. Empty Type is treated as
// "data" with the Data field (empty Data -> event skipped).
type TelnetEvent struct {
	// Type controls how the event is rendered:
	//
	//   "data"       - NVT ASCII text (Data field). 0xFF auto-escaped.
	//                  Direction "up" (client->server) or "down" (server->client).
	//
	//   "will"       - IAC WILL <Option> (server or client declares it WILL
	//                  enable an option). Option field is the option code.
	//                  Direction determines who sends.
	//
	//   "wont"       - IAC WONT <Option>. Same shape as "will".
	//
	//   "do"         - IAC DO <Option>. Request peer to enable.
	//
	//   "dont"       - IAC DONT <Option>. Request peer to disable.
	//
	//   "sb"         - IAC SB <Option> <SubData> IAC SE. Sub-option block.
	//                  SubData is raw bytes (0xFF auto-escaped).
	//
	//   "ttype_send" - IAC SB TTYPE SEND IAC SE (shortcut; no data).
	//   "ttype_is"   - IAC SB TTYPE IS <Value> IAC SE (Value = terminal
	//                  string; defaults to TelnetConfig.TerminalType, then "xterm").
	//
	//   "naws"       - IAC SB NAWS <Cols> <Rows> IAC SE. Defaults to
	//                  TelnetConfig.WindowCols/Rows, then 80x24.
	//
	//   "ip"         - IAC IP (Interrupt Process, 244). No payload.
	//   "dm"         - IAC DM (Data Mark, 242). Sent without TCP URG
	//                  (documented limitation - core.L4Config has no
	//                  UrgentPointer field).
	//   "nop"        - IAC NOP (No Operation, 241).
	//   "ayt"        - IAC AYT (Are You There, 246).
	//   "brk"        - IAC BRK (Break, 243).
	//   "ao"         - IAC AO (Abort Output, 245).
	//   "ec"         - IAC EC (Erase Character, 247).
	//   "el"         - IAC EL (Erase Line, 248).
	//   "ga"         - IAC GA (Go Ahead, 249).
	//
	//   "synch"      - IAC IP followed by IAC DM (Synch signal shortcut).
	//
	// Empty Type = "data" with empty Data (event is skipped).
	Type string `json:"type"`

	// Direction: "up" (client->server, default) or "down" (server->client).
	// Empty = "up". Used by all event types.
	Direction string `json:"direction,omitempty"`

	// Option is the option code (0-255) for "will"/"wont"/"do"/"dont"/"sb".
	Option uint8 `json:"option,omitempty"`

	// Data is the NVT ASCII text for "data" events. 0xFF bytes are
	// auto-escaped to 0xFF 0xFF on the wire. CR is followed by LF or NUL
	// per RFC 854 - the user provides the raw text and the planner does
	// NOT alter CR/LF (the user is responsible for proper line endings).
	Data string `json:"data,omitempty"`

	// DataB64 is the base64-encoded alternative for "data" events when
	// the bytes are not valid UTF-8 (e.g. binary Telnet streams in
	// BINARY mode). Overrides Data when set. 0xFF bytes are still
	// auto-escaped after base64 decoding.
	DataB64 string `json:"data_b64,omitempty"`

	// SubData is the raw sub-option bytes for "sb" events (between SB
	// and IAC SE). 0xFF bytes are auto-escaped.
	SubData []byte `json:"sub_data,omitempty"`

	// SubDataB64 overrides SubData for binary sub-option data.
	SubDataB64 string `json:"sub_data_b64,omitempty"`

	// Value is the terminal type string for "ttype_is" events.
	Value string `json:"value,omitempty"`

	// Cols/Rows are the window dimensions for "naws" events.
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// TLSConfig holds TLS protocol configuration. Fields populated by
// internal/protocol/tls implementer per design_tls.md.
//
// TLS (Transport Layer Security, 传输层安全协议) is a cryptographic protocol
// designed to provide secure communications over a TCP connection. The planner
// supports TLS 1.0/1.1/1.2/1.3 and emits wire-protocol bytes for handshake,
// record layer, alert, and application data. No real crypto is used; encrypted
// portions use synth ciphertext (随机密文) — random bytes of the correct length.
type TLSConfig struct {
	// Version 协商 / 选择: "tls1.3" (default), "tls1.2", "tls1.1", "tls1.0".
	Version string `json:"version,omitempty"`
	// Role 客户端角色: "client" (default) — 发出 ClientHello, 含 client 证书 (mTLS);
	// "server" — 发出 ServerHello, 发送 server 证书。
	Role string `json:"role,omitempty"`
	// SNI (Server Name Indication, 服务器名称指示) — e.g. "api.example.com".
	// 空 = 不发送 server_name 扩展。
	SNI string `json:"sni,omitempty"`
	// ALPN (Application-Layer Protocol Negotiation, 应用层协议协商) 候选列表,
	// 按优先级排序。空 = 默认 ["h2","http/1.1"]。
	ALPN []string `json:"alpn,omitempty"`
	// CipherSuites 密码套件, 代码值, 按 client 提供顺序。
	// 默认 ["TLS_AES_128_GCM_SHA256"(0x1301), "TLS_AES_256_GCM_SHA384"(0x1302),
	// "TLS_CHACHA20_POLY1305_SHA256"(0x1303), ...]。
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`
	// SupportedGroups (支持的椭圆曲线), e.g. [X25519(0x001D), secp256r1(0x0017), secp384r1(0x0018)]。
	SupportedGroups []uint16 `json:"supported_groups,omitempty"`
	// SignatureAlgorithms (签名算法), e.g. [ecdsa_secp256r1_sha256(0x0403), rsa_pkcs1_sha256(0x0401)]。
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	// ClientCertificate (客户端证书, mTLS 时使用)。留空走合成自签测试证书。
	ClientCertificate *X509Ref `json:"client_certificate,omitempty"`
	// ServerCertificate (服务端证书)。留空走合成自签测试证书。
	ServerCertificate *X509Ref `json:"server_certificate,omitempty"`
	// PSKs (Pre-Shared Keys, 预共享密钥) — 用于 Session Resumption / 0-RTT。
	PSKs []PSKIdentity `json:"psks,omitempty"`
	// AllowEarlyData 决定是否在 0-RTT 时随 ClientHello 同发 application data。
	AllowEarlyData bool `json:"allow_early_data,omitempty"`
	// AlertPath 模拟服务器在握手某阶段后立即发 Alert。
	AlertPath *AlertStep `json:"alert_path,omitempty"`
	// OCSPStapling (OCSP 装订) 控制是否发送 status_request 扩展。
	OCSPStapling bool `json:"ocsp_stapling,omitempty"`
}

// X509Ref 引用一个 X.509 证书, 用于 TLS 握手中的证书链。
type X509Ref struct {
	Subject string `json:"subject,omitempty"` // 自定义 subject (CN=...,O=...)
	San []string `json:"san,omitempty"` // DNS SANs
	NotBefore int64 `json:"not_before,omitempty"` // unix seconds; 0 = now
	NotAfter int64 `json:"not_after,omitempty"` // unix seconds; 0 = now+30d
	KeyType string `json:"key_type,omitempty"` // "rsa-2048"/"rsa-4096"/"ecdsa-p256"
	// FileSource 提供预生成的 p12/der 证书文件。
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// PSKIdentity (预共享密钥身份) 用于 TLS 1.3 PSK 会话恢复。
type PSKIdentity struct {
	Identity []byte `json:"identity,omitempty"` // PSK identity 字节
	ObfuscatedAge uint32 `json:"obfuscated_age,omitempty"` // 混淆年龄 (用于 binder)
}

// AlertStep (警报步骤) 配置服务器在握手某个阶段后发送 Alert。
type AlertStep struct {
	After string `json:"after,omitempty"` // "server_hello", "certificate", "server_hello_done"
	Description uint8 `json:"description,omitempty"` // RFC AlertDescription 编码
	Level uint8 `json:"level,omitempty"` // 1=warning, 2=fatal
}

// VmessConfig holds vmess protocol configuration. vmess is a session-level,
// AEAD-encrypted binary proxy protocol running on top of TCP (default) or
// UDP. The planner emits a TCP/UDP handshake (L4 transport), then the
// VMess Request header (Version + IV + encrypted body + HMAC), then the
// encrypted payload (opaque bytes), then the server's VMess Response, then
// payload data — all within one flow. Encrypted fields (IV, body, HMAC,
// payload) are opaque bytes from the planner's perspective — the planner
// generates the BYTE STRUCTURE (Version byte, UUID bytes, command byte,
// address type byte, port bytes) but treats encryption as a
// "format-compliant opaque fill" — the bytes are well-formed but not
// cryptographically meaningful (no real encryption key, 没有真实密钥).
//
// UUID (用户身份标识, RFC 4122): 16 bytes. Text form
// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (36 chars with dashes) is
// accepted and converted to bytes internally; hex form
// "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" (32 chars) is also accepted.
//
// AlterID (变更标识): vmess AEAD requires alter_id=0. Non-zero alter_id
// with AEAD is a protocol violation; Legacy mode requires alter_id>0.
//
// Encryption (加密算法): "aead_chacha20_poly1305" (default),
// "aead_aes_128_gcm", "legacy_aes_128_cfb". The planner emits bytes
// matching the encryption-mode framing — encrypted content is opaque
// fill, but the framing offsets differ.
//
// Address (目标地址): the target the vmess server should proxy to. IPv4
// (4 bytes, type 0x01), Domain (len-prefixed string, type 0x02), or IPv6
// (16 bytes, type 0x03).
type VmessConfig struct {
	// UUID (用户身份标识) is the 16-byte user identifier per RFC 4122.
	// Accepts standard text form "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	// (36 chars with dashes), hex form (32 chars, no dashes), or
	// uppercase variants. Required field.
	UUID string `json:"uuid"`

	// AlterID (变更标识): 0 = AEAD mode (vmess v5); >0 = Legacy mode
	// (vmess v4, AES-128-CFB + HMAC SHA-256). AEAD with alter_id>0 is
	// a protocol violation (Validate warns). Legacy with alter_id=0 is
	// also invalid (Legacy requires alter_id>0).
	AlterID uint16 `json:"alter_id,omitempty"`

	// Encryption (加密算法) selects the cipher and framing layout:
	//   "aead_chacha20_poly1305" (default) — AEAD, 16B IV (12B nonce + 4B counter)
	//   "aead_aes_128_gcm"           — AEAD, 16B IV (12B nonce + 4B counter)
	//   "legacy_aes_128_cfb"         — Legacy, 16B IV (random), HMAC SHA-256 (16B truncated)
	// Empty defaults to "aead_chacha20_poly1305".
	Encryption string `json:"encryption,omitempty"`

	// Command (命令字节): 0x01=TCP (default), 0x02=UDP, 0x03=MUX. The
	// planner uses Command=0x02 to select UDP transport; otherwise TCP.
	Command uint8 `json:"command,omitempty"`

	// AddressType (地址类型): 0x01=IPv4, 0x02=Domain, 0x03=IPv6. When 0
	// (default), the planner derives the type from Address's parse
	// result (IPv4 → 0x01, IPv6 → 0x03, otherwise Domain → 0x02).
	AddressType uint8 `json:"address_type,omitempty"`

	// Address (目标地址) is the target IPv4/Domain/IPv6 the vmess
	// server should proxy to. For Domain, length must be 1-253 bytes.
	Address string `json:"address,omitempty"`

	// Port (目标端口) is the target port (1-65535, big-endian on wire).
	Port uint16 `json:"port,omitempty"`

	// HeaderPadLen (头部填充长度): 0-16 (default: random 0-16). Random
	// padding bytes emitted after the Port field to obscure protocol
	// fingerprint. Values >16 are invalid (vmess spec limit).
	HeaderPadLen uint8 `json:"header_pad_len,omitempty"`

	// Payload (请求载荷) is the user data (HTTP request / SOCKS5 bytes /
	// raw TCP) sent as the Request Payload (encrypted with the AEAD
	// body). When nil, the planner emits a single empty-chunk frame
	// (2-byte length=0 + 16-byte tag) for AEAD mode, or no payload
	// bytes for Legacy mode.
	Payload []byte `json:"payload,omitempty"`

	// ResponsePayload (响应载荷) is the data sent back as the Response
	// Payload (server -> client direction, encrypted). nil = no response
	// payload (planner still emits ResponsePayloadLen=0 for AEAD mode).
	ResponsePayload []byte `json:"response_payload,omitempty"`

	// FileSource (文件来源), when set, supplies the Request Payload via
	// PayloadCache.GetOrLoad(src) instead of inline Payload. Takes
	// precedence over Payload.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`

	// Heartbeat (心跳), when true, emits a minimal VMess Request
	// (HeaderPad=8, Payload=nil) followed by a VMess Response with empty
	// payload — simulating a keepalive probe. Server typically responds
	// within 1s.
	Heartbeat bool `json:"heartbeat,omitempty"`

	// HeartbeatCount (心跳次数): number of heartbeat request/response
	// cycles to emit. 0 (default) = 1. Used to model long-lived
	// connections with periodic keepalives (e.g. SSH-over-vmess idle).
	HeartbeatCount int `json:"heartbeat_count,omitempty"`

	// MuxStreams (多路复用流): when Command=0x03, MuxStreams generates
	// multiple inner TCP streams within a single VMess connection. Each
	// stream carries its own MUX frame (session_id + status + length +
	// payload). Empty when Command != 0x03.
	MuxStreams []VmessMuxStream `json:"mux_streams,omitempty"`
}

// VmessMuxStream (MUX多路复用流) describes one inner stream within a vmess
// MUX connection. The planner emits each stream's frames (NEW / KEEP / END)
// after the outer VMess Request/Response handshake.
type VmessMuxStream struct {
	// SessionID (会话标识) is the 2-byte MUX session identifier (1-65535).
	SessionID uint16 `json:"session_id"`

	// Frames (MUX帧) lists the frames to emit for this stream.
	Frames []VmessMuxFrame `json:"frames"`

	// TargetAddr (目标地址, for NEW frame only) is the destination
	// address the stream connects to. Empty for KEEP/END/KEEPALIVE.
	TargetAddr string `json:"target_addr,omitempty"`

	// TargetPort (目标端口, for NEW frame only) is the destination port.
	TargetPort uint16 `json:"target_port,omitempty"`
}

// VmessMuxFrame (MUX帧) is one MUX frame within a vmess stream.
type VmessMuxFrame struct {
	// Status (帧状态): 0x01=NEW (新会话), 0x02=KEEP (保持/数据), 0x03=END (关闭), 0x04=KEEPALIVE (保活).
	Status uint8 `json:"status"`

	// Payload (帧载荷) carries the data bytes for KEEP frames, or nil
	// for NEW (carries target address in outer frame)/END/KEEPALIVE.
	Payload []byte `json:"payload,omitempty"`
}

// WireGuardConfig holds WireGuard protocol configuration. Fields
// populated by internal/protocol/wireguard implementer per
// design_wireguard.md.
type WireGuardConfig struct {
	// Role (角色): "initiator" (default, 发起方) or "responder" (响应方)
	Role string `json:"role,omitempty"`

	// LocalStaticPubKey (本地静态公钥) is the local X25519 static public key (32 bytes)
	LocalStaticPubKey []byte `json:"local_static_pub_key,omitempty"`

	// PeerStaticPubKey (对端静态公钥) is the peer's X25519 static public key (32 bytes)
	PeerStaticPubKey []byte `json:"peer_static_pub_key,omitempty"`

	// LocalEphemeralPubKey (本地临时公钥) is the local ephemeral X25519 public key (32 bytes)
	LocalEphemeralPubKey []byte `json:"local_ephemeral_pub_key,omitempty"`

	// SenderIndex (发送方索引) is the local session index; 0 = auto-generate (1..2^32-1)
	SenderIndex uint32 `json:"sender_index,omitempty"`

	// PSK (预共享密钥) is the Noise_IKpsk2 pre-shared key (32 bytes); nil = zero-filled
	PSK []byte `json:"psk,omitempty"`

	// Cookie (mac2 派生) is the 16-byte BLAKE2s cookie for mac2; nil = zero (no cookie)
	Cookie []byte `json:"cookie,omitempty"`

	// InitialCounter (初始计数器) is the starting transport counter; 0 = start at 0
	InitialCounter uint64 `json:"initial_counter,omitempty"`

	// RekeyAfter (重密钥阈值) is the packet-count threshold for rekey; 0 = 2^60
	RekeyAfter uint64 `json:"rekey_after,omitempty"`

	// RekeyAfterTime (重密钥时间) is the time threshold in seconds for rekey; 0 = 120s
	RekeyAfterTime int `json:"rekey_after_time,omitempty"`

	// KeepaliveInterval (保活间隔) in seconds; 0 = disabled, 10 = 10s
	KeepaliveInterval int `json:"keepalive_interval,omitempty"`

	// CookieReplyThreshold (Cookie应答阈值) controls when responder sends Cookie Reply;
	// 0 = never (default)
	CookieReplyThreshold int `json:"cookie_reply_threshold,omitempty"`

	// TransportPayloads (传输负载) is the list of inner IP packets to send as transport data
	TransportPayloads [][]byte `json:"transport_payloads,omitempty"`

	// FileSource (文件源) provides payload bytes; takes precedence over TransportPayloads
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`

	// Direction (方向): "up" (client->server, default), "down" (server->client), "both"
	Direction string `json:"direction,omitempty"`

	// Handshake (是否握手) controls whether to emit handshake initiation/response;
	// nil or true = emit handshake (default), explicit false = skip handshake
	Handshake *bool `json:"handshake,omitempty"`

	// Response (是否响应) controls whether responder emits Response (type=2);
	// nil or true = emit response (default), explicit false = skip response
	Response *bool `json:"response,omitempty"`
}
