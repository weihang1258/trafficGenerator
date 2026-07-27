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

// DHCPConfig holds DHCPv4 protocol configuration. Fields populated by
// internal/protocol/dhcp implementer per design_dhcp.md.
type DHCPConfig struct {
	// TODO(phase3-dhcp): populate fields per design_dhcp.md
}

// DHCPv6Config holds DHCPv6 protocol configuration. Fields populated by
// internal/protocol/dhcpv6 implementer per design_dhcpv6.md.
type DHCPv6Config struct {
	// TODO(phase3-dhcpv6): populate fields per design_dhcpv6.md
}

// GRPCConfig holds gRPC/HTTP2 telemetry protocol configuration. Fields
// populated by internal/protocol/grpc implementer per design_grpc.md.
type GRPCConfig struct {
	// TODO(phase3-grpc): populate fields per design_grpc.md
}

// IKEConfig holds IKEv2 protocol configuration. Fields populated by
// internal/protocol/ike implementer per design_ike.md.
type IKEConfig struct {
	// TODO(phase3-ike): populate fields per design_ike.md
}

// IKENATTConfig holds IKE-NAT-T protocol configuration. Fields populated
// by internal/protocol/ike_nat_t implementer per design_ike_nat_t.md.
type IKENATTConfig struct {
	// TODO(phase3-ike_nat_t): populate fields per design_ike_nat_t.md
}

// IMAPConfig holds IMAP4rev2 protocol configuration. Fields populated by
// internal/protocol/imap implementer per design_imap.md.
type IMAPConfig struct {
	// TODO(phase3-imap): populate fields per design_imap.md
}

// L2TPConfig holds L2TPv2/v3 protocol configuration. Fields populated by
// internal/protocol/l2tp implementer per design_l2tp.md.
type L2TPConfig struct {
	// TODO(phase3-l2tp): populate fields per design_l2tp.md
}

// MDNSConfig holds mDNS protocol configuration. Fields populated by
// internal/protocol/mdns implementer per design_mdns.md.
type MDNSConfig struct {
	// TODO(phase3-mdns): populate fields per design_mdns.md
}

// MySQLConfig holds MySQL client/server protocol configuration. Fields
// populated by internal/protocol/mysql implementer per design_mysql.md.
type MySQLConfig struct {
	// TODO(phase3-mysql): populate fields per design_mysql.md
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

	// Control message fields (Mode=6, RFC 5906). The control header is 8
	// bytes: Version(2)|LI(2)|Mode(4) | Sequence | Implementation |
	// RequestCode | (Error|More|StatusWord 16-bit) | DataSize. ControlData is
	// the variable-length Data region (max 464 bytes; total packet max 472).
	Sequence       uint8  `json:"sequence,omitempty"`
	Implementation uint8  `json:"implementation,omitempty"`
	RequestCode    uint8  `json:"request_code,omitempty"`
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

// OpenVPNConfig holds OpenVPN protocol configuration. Fields populated by
// internal/protocol/openvpn implementer per design_openvpn.md.
type OpenVPNConfig struct {
	// TODO(phase3-openvpn): populate fields per design_openvpn.md
}

// PostgreSQLConfig holds PostgreSQL frontend/backend protocol
// configuration. Fields populated by internal/protocol/postgresql
// implementer per design_postgresql.md.
type PostgreSQLConfig struct {
	// TODO(phase3-postgresql): populate fields per design_postgresql.md
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

// RDPConfig holds RDP protocol configuration. Fields populated by
// internal/protocol/rdp implementer per design_rdp.md.
type RDPConfig struct {
	// TODO(phase3-rdp): populate fields per design_rdp.md
}

// RedisConfig holds Redis RESP protocol configuration. Fields populated
// by internal/protocol/redis implementer per design_redis.md.
type RedisConfig struct {
	// TODO(phase3-redis): populate fields per design_redis.md
}

// ShadowsocksConfig holds Shadowsocks protocol configuration. Fields
// populated by internal/protocol/shadowsocks implementer per
// design_shadowsocks.md.
type ShadowsocksConfig struct {
	// TODO(phase3-shadowsocks): populate fields per design_shadowsocks.md
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

// SSDPConfig holds SSDP protocol configuration. Fields populated by
// internal/protocol/ssdp implementer per design_ssdp.md.
type SSDPConfig struct {
	// TODO(phase3-ssdp): populate fields per design_ssdp.md
}

// SSHConfig holds SSH protocol configuration. Fields populated by
// internal/protocol/ssh implementer per design_ssh.md.
type SSHConfig struct {
	// TODO(phase3-ssh): populate fields per design_ssh.md
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
type TLSConfig struct {
	// TODO(phase3-tls): populate fields per design_tls.md
}

// VmessConfig holds vmess protocol configuration. Fields populated by
// internal/protocol/vmess implementer per design_vmess.md.
type VmessConfig struct {
	// TODO(phase3-vmess): populate fields per design_vmess.md
}

// WireGuardConfig holds WireGuard protocol configuration. Fields
// populated by internal/protocol/wireguard implementer per
// design_wireguard.md.
type WireGuardConfig struct {
	// TODO(phase3-wireguard): populate fields per design_wireguard.md
}
