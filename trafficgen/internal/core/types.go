// Package core provides core data structures for the traffic generator.
package core

import (
	"context"
	"encoding/json"
	"fmt"
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

	// Layers is the raw "layers" config JSON (P2c 层链驱动生成), set when the
	// strategy config has a "layers" key (strategy_convert.go). nil = derive
	// the chain from Protocol via the default synthesized path. core cannot
	// import layers (layers imports core), so this stays raw JSON; the
	// engine's injected layer-planner factory (SetLayerPlannerFactory,
	// wired in cmd/server/main.go) parses it into a ChainPlanner.
	Layers json.RawMessage `json:"-"`

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

// BGPConfig configures a minimal RFC 4271 BGP session over TCP.
// Events is the ordered application-event sequence (design §2). Sessions
// carries multi-session expansion (each with its own source port); it is a
// T3 framework multi-flow topic and the layer chain rejects sessions>1.
type BGPConfig struct {
	Transport    string       `json:"transport,omitempty"`
	Version      uint8        `json:"version,omitempty"`
	ASN          uint32       `json:"asn,omitempty"`
	HoldTime     uint16       `json:"hold_time,omitempty"`
	Identifier   string       `json:"identifier,omitempty"`
	Marker       []byte       `json:"marker,omitempty"`
	Length       uint16       `json:"length,omitempty"`
	WireProfile  string       `json:"wire_profile,omitempty"`
	Capabilities []byte       `json:"capabilities,omitempty"`
	Update       []byte       `json:"update,omitempty"`
	Notification []byte       `json:"notification,omitempty"`
	Events       []BGPEvent   `json:"events,omitempty"`
	Sessions     []BGPSession `json:"sessions,omitempty"`
}

// BGPEvent is one BGP application event in the ordered sequence. Only the
// fields relevant to the event's kind are meaningful; the rest stay zero.
type BGPEvent struct {
	Kind              string               `json:"kind,omitempty"`               // open/keepalive/update/notification/wire_fault
	Direction         string               `json:"direction,omitempty"`          // c2s, s2c
	Version           uint8                `json:"version,omitempty"`            // OPEN version
	MyAS              uint32               `json:"my_as,omitempty"`              // OPEN My AS (moved to uint32 so 2-octet overflow is rejected by validation, not silently wrapped by JSON)
	HoldTime          uint16               `json:"hold_time,omitempty"`          // OPEN hold time
	Identifier        string               `json:"identifier,omitempty"`         // OPEN BGP identifier (IPv4)
	WithdrawnPrefixes []string             `json:"withdrawn_prefixes,omitempty"` // UPDATE withdrawn routes
	NLRI              []string             `json:"nlri,omitempty"`               // UPDATE NLRI prefixes
	Attributes        *BGPUpdateAttributes `json:"attributes,omitempty"`         // UPDATE path attributes
	ErrorCode         uint8                `json:"error_code,omitempty"`         // NOTIFICATION error code
	ErrorSubcode      uint8                `json:"error_subcode,omitempty"`      // NOTIFICATION error subcode
	FaultKind         string               `json:"fault_kind,omitempty"`         // wire_fault: marker/length/type
	Value             *uint16              `json:"value,omitempty"`              // wire_fault: injected value (length/type)
}

// BGPUpdateAttributes are the RFC 4271 path attributes carried by an UPDATE.
type BGPUpdateAttributes struct {
	Origin        *uint8   `json:"origin,omitempty"`          // ORIGIN: 0 IGP / 1 EGP / 2 INCOMPLETE (pointer so IGP=0 is distinguishable from absent)
	ASPath        []uint16 `json:"as_path,omitempty"`         // AS_SEQUENCE list (2-octet ASNs)
	NextHop       string   `json:"next_hop,omitempty"`        // NEXT_HOP IPv4 address
	MultiExitDisc uint32   `json:"multi_exit_disc,omitempty"` // MULTI_EXIT_DISC metric
	LocalPref     uint32   `json:"local_pref,omitempty"`      // LOCAL_PREF preference
	Communities   []string `json:"communities,omitempty"`     // COMMUNITIES (e.g. NO_EXPORT)
}

// BGPSession is one independent BGP session with its own source port and events.
type BGPSession struct {
	SrcPort uint16     `json:"src_port,omitempty"`
	Events  []BGPEvent `json:"events,omitempty"`
}

// IEC104Config configures an IEC 60870-5-104 session.
type IEC104Config struct {
	Transport                string          `json:"transport,omitempty"`
	Role                     string          `json:"role,omitempty"`
	CommonAddress            uint16          `json:"common_address,omitempty"`
	StartDT                  bool            `json:"startdt,omitempty"`
	StopDT                   bool            `json:"stopdt,omitempty"`
	Events                   []IEC104Event   `json:"events,omitempty"`
	Commands                 []IEC104Command `json:"commands,omitempty"`
	TypeID                   uint8           `json:"type_id,omitempty"`
	Cause                    uint8           `json:"cause,omitempty"`
	InformationObjectAddress uint32          `json:"ioa,omitempty"`
	Value                    int32           `json:"value,omitempty"`
	SIQ                      uint8           `json:"siq,omitempty"`
	QDS                      uint8           `json:"qds,omitempty"`
	DIQ                      uint8           `json:"diq,omitempty"`
	SCO                      uint8           `json:"sco,omitempty"`
	DCO                      uint8           `json:"dco,omitempty"`
	QOI                      uint8           `json:"qoi,omitempty"`
	Select                   bool            `json:"select,omitempty"`
	Time                     string          `json:"time,omitempty"`
	MaxAPDULength            uint16          `json:"max_apdu_length,omitempty"`
	Repeat                   int             `json:"repeat,omitempty"`
}

type IEC104Event struct {
	Direction string `json:"direction,omitempty"`
	Kind      string `json:"kind,omitempty"`
	TypeID    uint8  `json:"type_id,omitempty"`
	Cause     uint8  `json:"cause,omitempty"`
	IOA       uint32 `json:"ioa,omitempty"`
	Value     int32  `json:"value,omitempty"`
	RX        uint16 `json:"rx,omitempty"`
	SIQ       uint8  `json:"siq,omitempty"`
	QDS       uint8  `json:"qds,omitempty"`
	DIQ       uint8  `json:"diq,omitempty"`
	SCO       uint8  `json:"sco,omitempty"`
	DCO       uint8  `json:"dco,omitempty"`
	QOI       uint8  `json:"qoi,omitempty"`
	Select    bool   `json:"select,omitempty"`
	Time      string `json:"time,omitempty"`
}

type IEC104Command struct {
	TypeID                   uint8  `json:"type_id,omitempty"`
	Cause                    uint8  `json:"cause,omitempty"`
	CommonAddress            uint16 `json:"common_address,omitempty"`
	InformationObjectAddress uint32 `json:"ioa,omitempty"`
	Value                    int32  `json:"value,omitempty"`
}

// STUNConfig configures an RFC 5389/8489 Binding transaction. One config is an
// ordered event sequence (Events); a single event can carry attributes and a
// wire fault drives the negative cases.
type STUNConfig struct {
	Profile   string      `json:"profile,omitempty"`
	Method    string      `json:"method,omitempty"`
	Events    []STUNEvent `json:"events,omitempty"`
	WireFault *STUNFault  `json:"wire_fault,omitempty"`
}

// STUNEvent is one STUN message in a transaction sequence.
type STUNEvent struct {
	Kind             string          `json:"kind,omitempty"`
	Direction        string          `json:"direction,omitempty"`
	Attributes       []STUNAttribute `json:"attributes,omitempty"`
	Retransmit       bool            `json:"retransmit,omitempty"`
	TransactionGroup string          `json:"transaction_group,omitempty"`
}

// STUNAttribute is one STUN attribute descriptor carried by an event.
type STUNAttribute struct {
	Type    string `json:"type,omitempty"`
	Value   string `json:"value,omitempty"`
	Family  string `json:"family,omitempty"`
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Key     string `json:"key,omitempty"`
	Code    uint16 `json:"code,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// STUNFault is a wire fault injected for negative test cases.
type STUNFault struct {
	Kind           string `json:"kind,omitempty"`
	DeclaredBytes  uint16 `json:"declared_bytes,omitempty"`
	DeclaredLength uint16 `json:"declared_length,omitempty"`
	Type           uint16 `json:"type,omitempty"`
	Cookie         string `json:"cookie,omitempty"`
	Key            string `json:"key,omitempty"`
	Carrier        string `json:"carrier,omitempty"`
	Framing        string `json:"framing,omitempty"`
	Method         string `json:"method,omitempty"`
}

// RTMFPConfig configures an Adobe RTMFP (Real-Time Media Flow Protocol) UDP
// session. It drives a session/event state machine producing deterministic
// wire bytes for handshake, reliable/unreliable data, fragment, ack, ping/pong,
// and close. Wire faults are injected for negative test cases.
type RTMFPConfig struct {
	Profile           string         `json:"profile,omitempty"`            // rtmfp_baseline, rtmfp_low_latency
	Role              string         `json:"role,omitempty"`               // initiator, responder
	KeepaliveInterval int            `json:"keepalive_interval,omitempty"` // seconds between pings
	PingCount         int            `json:"ping_count,omitempty"`         // max ping/pong rounds
	WireFault         *RTMFPFault    `json:"wire_fault,omitempty"`         // negative test only
	Sessions          []RTMFPSession `json:"sessions,omitempty"`
}

// RTMFPSession is one independent RTMFP session with its own cookie/session ID.
type RTMFPSession struct {
	SessionID uint32       `json:"session_id,omitempty"`
	SrcPort   uint16       `json:"src_port,omitempty"` // override source port (multi-session)
	Events    []RTMFPEvent `json:"events,omitempty"`
}

// RTMFPEvent is one RTMFP message in a session event sequence.
type RTMFPEvent struct {
	Kind       string         `json:"kind,omitempty"`      // hello/hello_ack/cookie/session_confirm/reliable/unreliable/fragment/ack/ping/pong/close/error
	Direction  string         `json:"direction,omitempty"` // c2s, s2c
	FlowID     uint32         `json:"flow_id,omitempty"`
	Sequence   uint32         `json:"sequence,omitempty"`
	Message    string         `json:"message,omitempty"`     // text payload
	MessageB64 string         `json:"message_b64,omitempty"` // base64 payload (takes precedence)
	Cookie     string         `json:"cookie,omitempty"`      // explicit cookie bytes (hex)
	SessionID  *uint32        `json:"session_id,omitempty"`  // override session ID for this event
	Ranges     [][2]uint32    `json:"ranges,omitempty"`      // ACK ranges: [[start,end],...]
	Fragment   *RTMFPFragment `json:"fragment,omitempty"`
}

// RTMFPFragment carries fragment metadata for reassembly.
type RTMFPFragment struct {
	Index       uint32 `json:"index,omitempty"`
	Count       uint32 `json:"count,omitempty"`
	TotalLength uint32 `json:"total_length,omitempty"`
	Payload     string `json:"payload,omitempty"`
}

// RTMFPFault is a wire fault injected for negative test cases.
type RTMFPFault struct {
	Kind     string `json:"kind,omitempty"`     // short_header, bad_length, session_mismatch, sequence_regress, fragment_gap, ack_unknown, state_order, session_leak
	Declared uint32 `json:"declared,omitempty"` // declared length/count
	Actual   uint32 `json:"actual,omitempty"`   // actual length/count
}

// AMQPConfig configures an AMQP 0-9-1 connection/channel session over TCP
// ([ip, tcp, amqp]). The generator emits protocol header + frame events
// (METHOD/HEADER/BODY/HEARTBEAT) per connection event sequence; TCP framing,
// handshake and termination are provided by the tcp layer generator.
type AMQPConfig struct {
	Profile     string           `json:"profile,omitempty"` // amqp091_rabbitmq, amqp091_minimal, amqp091_tls_boundary(未来)
	FrameMax    uint32           `json:"frame_max,omitempty"`
	ChannelMax  uint16           `json:"channel_max,omitempty"`
	Heartbeat   uint16           `json:"heartbeat,omitempty"`
	Connections []AMQPConnection `json:"connections,omitempty"`
	WireFault   string           `json:"wire_fault,omitempty"` // negative test only
}

// AMQPConnection is one AMQP connection with its own 4-tuple, handshake,
// channel table and delivery/consumer state. 4-tuple overrides the flow
// baseline when non-zero.
type AMQPConnection struct {
	SrcIP   string      `json:"src_ip,omitempty"`
	DstIP   string      `json:"dst_ip,omitempty"`
	SrcPort uint16      `json:"src_port,omitempty"`
	DstPort uint16      `json:"dst_port,omitempty"`
	Events  []AMQPEvent `json:"events,omitempty"`
}

// AMQPEvent is one AMQP wire exchange in a connection event sequence.
// Kind selects the byte builder: protocol_header, method, header, body,
// heartbeat, close, close_ok.
type AMQPEvent struct {
	Kind      string `json:"kind,omitempty"`      // protocol_header/method/header/body/heartbeat
	Direction string `json:"direction,omitempty"` // c2s, s2c
	Channel   uint16 `json:"channel,omitempty"`
	ClassID   uint16 `json:"class_id,omitempty"`
	MethodID  uint16 `json:"method_id,omitempty"`
	// Arguments are method arguments (encoding order per class/method table).
	// Body holds body bytes (or hex when body_hex set). It is typed `any`
	// rather than []byte so a plain string like "Hello!" is NOT base64-
	// decoded by json.Unmarshal (Go decodes []byte JSON fields from base64).
	// resolveBody converts string / []byte / nil to the wire bytes.
	Arguments        map[string]any `json:"arguments,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	Body             any            `json:"body,omitempty"`
	BodyHex          string         `json:"body_hex,omitempty"`           // hex body, takes precedence over Body
	BodySizeOverride *uint64        `json:"body_size_override,omitempty"` // negative test only
}

// HTTPFLVConfig configures an HTTP-FLV session (HTTP/1.1 GET carrying FLV
// byte stream over http layer). HTTP framing (method/URI/headers) is handled
// by the http layer; http_flv only controls the FLV byte content.
// Multi-session is expressed by multiple flows, not by a Sessions count.
type HTTPFLVConfig struct {
	Flags     uint8    `json:"flags,omitempty"`      // audio=0x04, video=0x01; 0 → 0x05 (both)
	Tags      []FLVTag `json:"tags,omitempty"`       // 空 → 默认模板 (onMetaData + AAC + AVC)
	Rounds    int      `json:"rounds,omitempty"`     // HTTP GET/200 轮数；0 → 1
	WireFault string   `json:"wire_fault,omitempty"` // negative test only
}

// FLVTag is one FLV tag in an HTTP-FLV stream.
type FLVTag struct {
	Type                 string  `json:"type,omitempty"` // script/audio/video
	Timestamp            uint32  `json:"timestamp,omitempty"`
	Data                 []byte  `json:"data,omitempty"`
	DataSizeOverride     *uint32 `json:"data_size_override,omitempty"`     // negative test only
	PreviousSizeOverride *uint32 `json:"previous_size_override,omitempty"` // negative test only
}

// HLSConfig configures an HLS (HTTP Live Streaming, RFC 8216) session.
// The http layer's transformer mode wraps HLS body events in HTTP GET/200
// frames; hls only controls the playlist/segment bytes.
type HLSConfig struct {
	Profile           string       `json:"profile,omitempty"`            // rfc8216_v7 / apple_ll_hls
	Sessions          []HLSSession `json:"sessions,omitempty"`           // ordered session events
	Live              *HLSLive     `json:"live,omitempty"`               // live sliding window
	LLHLS             *HLSLLHLS    `json:"ll_hls,omitempty"`             // LL-HLS (apple_ll_hls only)
	WireFault         string       `json:"wire_fault,omitempty"`         // negative test only
	EmptyBody         bool         `json:"empty_body,omitempty"`         // negative test only
	MissingExtM3U     bool         `json:"missing_extm3u,omitempty"`     // negative test only
	BadTag            string       `json:"bad_tag,omitempty"`            // negative test only
	BadBandwidth      bool         `json:"bad_bandwidth,omitempty"`      // negative test only
	TruncateBody      bool         `json:"truncate_body,omitempty"`      // negative test only
	InvalidURI        bool         `json:"invalid_uri,omitempty"`        // negative test only
	KeyMismatch       bool         `json:"key_mismatch,omitempty"`       // negative test only
	SequenceRegress   bool         `json:"sequence_regress,omitempty"`   // negative test only
	DiscontinuityIncr bool         `json:"discontinuity_incr,omitempty"` // negative test only
	LLWithoutProfile  bool         `json:"ll_without_profile,omitempty"` // negative test only
	CrossSessionRef   bool         `json:"cross_session_ref,omitempty"`  // negative test only
}

// HLSSession is one HLS event: master/media/refresh/segment/key.
type HLSSession struct {
	Kind                string          `json:"kind,omitempty"`               // master/media/refresh/segment/key
	SessionID           string          `json:"session_id,omitempty"`         // default session when empty
	URI                 string          `json:"uri,omitempty"`                // playlist/segment/key resource URI
	PlaylistType        string          `json:"playlist_type,omitempty"`      // master/media
	PlaylistMode        string          `json:"playlist_mode,omitempty"`      // EVENT/VOD
	TargetDuration      float64         `json:"target_duration,omitempty"`    // #EXT-X-TARGETDURATION
	MediaSequence       int             `json:"media_sequence,omitempty"`     // #EXT-X-MEDIA-SEQUENCE
	MediaSequenceEnd    *int            `json:"media_sequence_end,omitempty"` // target sequence for refresh regression check
	DiscontinuitySeq    int             `json:"discontinuity_sequence,omitempty"`
	Segments            []HLSSegment    `json:"segments,omitempty"`             // ordered segment entries
	Variants            []HLSVariant    `json:"variants,omitempty"`             // master variants
	Renditions          []HLSRendition  `json:"renditions,omitempty"`           // EXT-X-MEDIA groups
	Key                 *HLSKey         `json:"key,omitempty"`                  // AES-128 key
	Parts               []HLSPart       `json:"parts,omitempty"`                // LL-HLS partial segments
	PreloadHint         *HLSPreloadHint `json:"preload_hint,omitempty"`         // LL-HLS preload
	Map                 *HLSMap         `json:"map,omitempty"`                  // fMP4 init map
	Body                string          `json:"body,omitempty"`                 // explicit playlist body (negative fixtures)
	ResponseStatusCode  int             `json:"response_status_code,omitempty"` // 200/206/404/...
	ResponseContentType string          `json:"response_content_type,omitempty"`
	ResponseBody        string          `json:"response_body,omitempty"`
	ResponseBodyB64     string          `json:"response_body_b64,omitempty"`
	ByteRange           *HLSByteRange   `json:"byte_range,omitempty"`
	ResourceLength      int             `json:"resource_length,omitempty"`
	PlaylistContentType string          `json:"playlist_content_type,omitempty"`
	IndependentSegments bool            `json:"independent_segments,omitempty"`
	Endlist             bool            `json:"endlist,omitempty"`
	Rounds              int             `json:"rounds,omitempty"` // HTTP GET/200 rounds; 0 → 1
}

// HLSSegment is one media segment entry in a playlist.
type HLSSegment struct {
	URI             string        `json:"uri,omitempty"`
	Duration        float64       `json:"duration,omitempty"`
	Title           string        `json:"title,omitempty"`
	ByteRange       *HLSByteRange `json:"byte_range,omitempty"`
	KeyRef          string        `json:"key_ref,omitempty"`
	Discontinuity   bool          `json:"discontinuity,omitempty"`
	ProgramDateTime string        `json:"program_date_time,omitempty"`
}

// HLSVariant is one #EXT-X-STREAM-INF variant of a master playlist.
type HLSVariant struct {
	URI              string `json:"uri,omitempty"`
	Bandwidth        int    `json:"bandwidth,omitempty"`
	AverageBandwidth int    `json:"average_bandwidth,omitempty"`
	Codecs           string `json:"codecs,omitempty"`
	Resolution       string `json:"resolution,omitempty"`
	FrameRate        string `json:"frame_rate,omitempty"`
	Audio            string `json:"audio,omitempty"`
}

// HLSRendition is one #EXT-X-MEDIA rendition group.
type HLSRendition struct {
	Type       string `json:"type,omitempty"` // AUDIO/VIDEO/SUBTITLES/CLOSED-CAPTIONS
	GroupID    string `json:"group_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Default    *bool  `json:"default,omitempty"`
	AutoSelect *bool  `json:"autoselect,omitempty"`
	URI        string `json:"uri,omitempty"`
}

// HLSByteRange is one #EXT-X-BYTERANGE range.
type HLSByteRange struct {
	Length int `json:"length,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// HLSKey is one #EXT-X-KEY encryption directive.
type HLSKey struct {
	Method string `json:"method,omitempty"` // AES-128 / NONE
	URI    string `json:"uri,omitempty"`
	IV     string `json:"iv,omitempty"` // 0x... 128-bit hex
}

// HLSPart is one LL-HLS partial segment entry.
type HLSPart struct {
	URI         string  `json:"uri,omitempty"`
	Duration    float64 `json:"duration,omitempty"`
	Independent *bool   `json:"independent,omitempty"`
}

// HLSPreloadHint is one LL-HLS #EXT-X-PRELOAD-HINT entry.
type HLSPreloadHint struct {
	Type string `json:"type,omitempty"` // PART / MAP
	URI  string `json:"uri,omitempty"`
}

// HLSMap is one #EXT-X-MAP fMP4 init segment directive.
type HLSMap struct {
	URI       string        `json:"uri,omitempty"`
	ByteRange *HLSByteRange `json:"byte_range,omitempty"`
}

// HLSLive is the live sliding-window configuration.
type HLSLive struct {
	Window          int `json:"window,omitempty"`
	RefreshCount    int `json:"refresh_count,omitempty"`
	RefreshInterval int `json:"refresh_interval,omitempty"`
}

// HDSConfig configures an HDS (Adobe HTTP Dynamic Streaming) session.
// The http layer's transformer mode wraps HDS body events in HTTP GET/200
// frames; hds only controls the manifest/bootstrap/fragment bytes.
type HDSConfig struct {
	Profile   string       `json:"profile,omitempty"`    // hds_http1
	Sessions  []HDSSession `json:"sessions,omitempty"`   // ordered session events
	Method    string       `json:"method,omitempty"`     // default GET
	Version   string       `json:"version,omitempty"`    // default HTTP/1.1
	KeepAlive bool         `json:"keep_alive,omitempty"` // default true
	Manifest  *HDSManifest `json:"manifest,omitempty"`   // manifest config
	WireFault string       `json:"wire_fault,omitempty"` // negative test injection
}

// HDSSession is one HDS event: manifest/bootstrap/fragment.
type HDSSession struct {
	Kind        string `json:"kind,omitempty"`         // manifest/bootstrap/fragment
	URI         string `json:"uri,omitempty"`          // resource URI
	ManifestURI string `json:"manifest_uri,omitempty"` // manifest URI for bootstrap/fragment ref
	SrcPort     int    `json:"src_port,omitempty"`     // override source port (multi-session)
	Rounds      int    `json:"rounds,omitempty"`       // HTTP GET/200 rounds; 0 → 1
}

// HDSManifest is the F4M manifest configuration.
type HDSManifest struct {
	ID             string             `json:"id,omitempty"`
	StreamType     string             `json:"stream_type,omitempty"` // live or recorded
	URI            string             `json:"uri,omitempty"`         // manifest request URI
	Media          []HDSMedia         `json:"media,omitempty"`
	BootstrapInfos []HDSBootstrapInfo `json:"bootstrap_infos,omitempty"`
}

// HDSMedia is one media entry in the manifest.
type HDSMedia struct {
	StreamID        string        `json:"stream_id,omitempty"`
	Href            string        `json:"href,omitempty"`
	URL             string        `json:"url,omitempty"`
	Bitrate         uint32        `json:"bitrate,omitempty"`
	BootstrapInfoID string        `json:"bootstrap_info_id,omitempty"`
	Fragments       []HDSFragment `json:"fragments,omitempty"`
	BootstrapBytes  string        `json:"bootstrap_bytes,omitempty"` // base64 bootstrap for inline
}

// HDSBootstrapInfo is one bootstrap info entry in the manifest.
type HDSBootstrapInfo struct {
	ID      string `json:"id,omitempty"`
	Profile string `json:"profile,omitempty"` // "named"
	Base64  string `json:"base64,omitempty"`  // base64-encoded bootstrap box bytes
	URL     string `json:"url,omitempty"`
}

// HDSFragment is one media fragment.
type HDSFragment struct {
	Segment   uint32 `json:"segment,omitempty"`
	Fragment  uint32 `json:"fragment,omitempty"`
	Timestamp uint64 `json:"timestamp,omitempty"`
	Duration  uint32 `json:"duration,omitempty"`
	Body      string `json:"body,omitempty"`     // text body
	BodyB64   string `json:"body_b64,omitempty"` // base64 body
}

// HLSLLHLS is the LL-HLS profile configuration.
type HLSLLHLS struct {
	PartTarget    float64 `json:"part_target,omitempty"`
	ServerControl string  `json:"server_control,omitempty"`
}

// LDPConfig configures a minimal RFC 5036 LDP session.
type LDPConfig struct {
	Transport          string         `json:"transport,omitempty"`
	WireProfile        string         `json:"wire_profile,omitempty"`
	Carrier            string         `json:"carrier,omitempty"`
	Events             []LDPEvent     `json:"events,omitempty"`
	Sessions           []LDPSession   `json:"sessions,omitempty"`
	Adjacencies        []LDPAdjacency `json:"adjacencies,omitempty"`
	LSRID              string         `json:"lsr_id,omitempty"`
	LabelSpace         uint16         `json:"label_space,omitempty"`
	HoldTime           uint16         `json:"hold_time,omitempty"`
	Targeted           bool           `json:"targeted,omitempty"`
	KeepaliveTime      uint16         `json:"keepalive_time,omitempty"`
	LabelControl       string         `json:"label_control,omitempty"`
	LabelAdvertisement string         `json:"label_advertisement,omitempty"`
	FaultKind          string         `json:"fault_kind,omitempty"`
}

// LDPSession is one independent TCP session in a multi-session LDP config
// (P0a pattern A: sessions[] inside the protocol config).
type LDPSession struct {
	SrcPort  uint16     `json:"src_port,omitempty"`
	SrcLSRID string     `json:"src_lsr_id,omitempty"`
	DstLSRID string     `json:"dst_lsr_id,omitempty"`
	Events   []LDPEvent `json:"events,omitempty"`
}

// LDPAdjacency is one adjacency in a dual-adjacency LDP config: either a
// UDP discovery adjacency (single Hello PDU) or a TCP session adjacency
// (full event sequence on its own connection).
type LDPAdjacency struct {
	Kind      string     `json:"kind,omitempty"`      // basic|targeted|session
	Carrier   string     `json:"carrier,omitempty"`   // udp_discovery|tcp_session
	Direction string     `json:"direction,omitempty"` // c2s|s2c
	MessageID uint32     `json:"message_id,omitempty"`
	Targeted  bool       `json:"targeted,omitempty"`
	SrcPort   uint16     `json:"src_port,omitempty"`
	DstPort   uint16     `json:"dst_port,omitempty"`
	Events    []LDPEvent `json:"events,omitempty"`
}

// LDPEvent is one LDP protocol event.
type LDPEvent struct {
	Kind          string   `json:"kind,omitempty"`
	Direction     string   `json:"direction,omitempty"`
	MessageID     uint32   `json:"message_id,omitempty"`
	LSRID         string   `json:"lsr_id,omitempty"`
	ReceiverLSRID string   `json:"receiver_lsr_id,omitempty"`
	HoldTime      uint16   `json:"hold_time,omitempty"`
	KeepaliveTime uint16   `json:"keepalive_time,omitempty"`
	Targeted      bool     `json:"targeted,omitempty"`
	FEC           string   `json:"fec,omitempty"`
	PrefixLength  uint8    `json:"prefix_length,omitempty"`
	Label         uint32   `json:"label,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	StatusCode    uint32   `json:"status_code,omitempty"`
}

// PCEPConfig configures a minimal RFC 5440 PCEP session.
type PCEPConfig struct {
	Transport string      `json:"transport,omitempty"`
	Profile   string      `json:"profile,omitempty"`
	Events    []PCEPEvent `json:"events,omitempty"`
	// Sessions enables multi-session expansion (P0a pattern): each session
	// gets its own TCP connection (src_port) and replays its events; the TCP
	// generator's connection-boundary mechanism tears down the previous
	// connection when SrcPort changes.
	Sessions []PCEPSession `json:"sessions,omitempty"`
}

// PCEPSession is one independent TCP session in a multi-session PCEP config.
type PCEPSession struct {
	SrcPort uint16      `json:"src_port,omitempty"`
	Events  []PCEPEvent `json:"events,omitempty"`
}

// PCEPEvent is one PCEP protocol event.
type PCEPEvent struct {
	Kind         string            `json:"kind,omitempty"`
	Direction    string            `json:"direction,omitempty"`
	Keepalive    uint8             `json:"keepalive,omitempty"`
	Deadtime     uint8             `json:"deadtime,omitempty"`
	SID          uint8             `json:"sid,omitempty"`
	RequestID    uint32            `json:"request_id,omitempty"`
	MessageType  uint8             `json:"message_type,omitempty"`
	Endpoint     *PCEPEndpoint     `json:"endpoint,omitempty"`
	Objects      []json.RawMessage `json:"objects,omitempty"`
	Capabilities []PCEPCapability  `json:"capabilities,omitempty"`
	WireFault    *PCEPFault        `json:"wire_fault,omitempty"`
}

// PCEPEndpoint represents an endpoint in PCEP events.
type PCEPEndpoint struct {
	SourceIPv4      string `json:"source_ipv4,omitempty"`
	DestinationIPv4 string `json:"destination_ipv4,omitempty"`
	SourceIPv6      string `json:"source_ipv6,omitempty"`
	DestinationIPv6 string `json:"destination_ipv6,omitempty"`
}

// PCEPCapability represents a PCEP capability TLV (e.g. stateful PCE).
type PCEPCapability struct {
	Kind             string `json:"kind,omitempty"`
	LSPUpdate        bool   `json:"lsp_update,omitempty"`
	IncludeDBVersion bool   `json:"include_db_version,omitempty"`
}

// PCEPFault represents a wire fault injection for negative test cases.
type PCEPFault struct {
	Kind     string `json:"kind,omitempty"`
	Declared uint16 `json:"declared,omitempty"`
}

// CFlowConfig configures a cflow export packet/message (NetFlow v9 RFC 3954
// or IPFIX RFC 7011). One flow = UDP export packet(s); a single config emits
// one Export Packet (v9) / Message (IPFIX) unless Exporters/Sessions fan out.
type CFlowConfig struct {
	Profile             string          `json:"profile,omitempty"`
	Version             uint16          `json:"version,omitempty"`
	SourceID            uint32          `json:"source_id,omitempty"`
	Sequence            uint32          `json:"sequence,omitempty"`
	SysUptime           uint32          `json:"sys_uptime,omitempty"`
	ObservationDomainID uint32          `json:"observation_domain_id,omitempty"`
	ExportTime          uint32          `json:"export_time,omitempty"`
	UnixSecs            uint32          `json:"unix_secs,omitempty"`
	Templates           []CFlowTemplate `json:"templates,omitempty"`
	Records             []CFlowRecord   `json:"records,omitempty"`
	Sets                []CFlowSet      `json:"sets,omitempty"`
	Options             *CFlowOptions   `json:"options,omitempty"`
	Exporters           []CFlowExporter `json:"exporters,omitempty"`
	Sessions            []CFlowSession  `json:"sessions,omitempty"`
	WireFault           *CFlowFault     `json:"wire_fault,omitempty"`
}

// CFlowTemplate is one Template/Options Template descriptor.
type CFlowTemplate struct {
	Kind         string       `json:"kind,omitempty"`
	TemplateID   uint16       `json:"template_id,omitempty"`
	Fields       []CFlowField `json:"fields,omitempty"`
	ScopeFields  []CFlowField `json:"scope_fields,omitempty"`
	OptionFields []CFlowField `json:"option_fields,omitempty"`
	FieldCount   uint16       `json:"field_count,omitempty"`
	WireFault    *CFlowFault  `json:"wire_fault,omitempty"`
}

// CFlowField is one field descriptor in a template.
type CFlowField struct {
	ElementID uint16 `json:"element_id,omitempty"`
	Length    uint16 `json:"length,omitempty"`
	PEN       uint32 `json:"pen,omitempty"`
}

// CFlowRecord is one data record referencing a registered template.
type CFlowRecord struct {
	TemplateID uint16                 `json:"template_id,omitempty"`
	Record     map[string]interface{} `json:"record,omitempty"`
}

// CFlowSet is a raw set (negative case: data set without a template).
type CFlowSet struct {
	ID      uint16        `json:"id,omitempty"`
	Records []CFlowRecord `json:"records,omitempty"`
}

// CFlowOptions carries timeout/sampling metadata used by Options Templates
// or v9 options-like fields.
type CFlowOptions struct {
	ActiveTimeout    uint16 `json:"active_timeout,omitempty"`
	InactiveTimeout  uint16 `json:"inactive_timeout,omitempty"`
	SamplingInterval uint16 `json:"sampling_interval,omitempty"`
}

// CFlowExporter describes a second exporter (v9 source ID or IPFIX OD ID).
type CFlowExporter struct {
	SourceID            uint32          `json:"source_id,omitempty"`
	ObservationDomainID uint32          `json:"observation_domain_id,omitempty"`
	Templates           []CFlowTemplate `json:"templates,omitempty"`
	Records             []CFlowRecord   `json:"records,omitempty"`
}

// CFlowSession describes a second UDP session (different src port).
type CFlowSession struct {
	SrcPort   uint16          `json:"src_port,omitempty"`
	SourceID  uint32          `json:"source_id,omitempty"`
	Templates []CFlowTemplate `json:"templates,omitempty"`
	Records   []CFlowRecord   `json:"records,omitempty"`
}

// CFlowFault is a wire fault injection for negative test cases.
type CFlowFault struct {
	Kind     string `json:"kind,omitempty"`
	Value    uint16 `json:"value,omitempty"`
	Declared uint16 `json:"declared,omitempty"`
	Fields   uint16 `json:"fields,omitempty"`
	Version  uint16 `json:"version,omitempty"`
}

// MOXAConfig configures Moxa NPort transparent passthrough (TCP Server mode).
// One flow = an ordered stream of serial byte blocks, each mapped to a
// MessageEvent (direction + bytes) by the terminal generator; TCP semantics
// (handshake/seq-ack/teardown/MSS segmentation) are owned by the tcp layer.
type MOXAConfig struct {
	Stream   []MOXAStreamBlock `json:"stream,omitempty"`
	Pack     uint32            `json:"pack_ms,omitempty"`
	Sessions int               `json:"sessions,omitempty"`
}

// MOXAStreamBlock is one block in a MOXA serial byte stream.
type MOXAStreamBlock struct {
	Direction  string `json:"direction,omitempty"`
	Payload    string `json:"payload,omitempty"`
	PayloadB64 string `json:"payload_b64,omitempty"`
}

// SOMEIPConfig configures a SOME/IP session (AUTOSAR PRS, UDP/TCP carrier).
// Flat keys (spec.SOMEIP.*) drive the message header, SD/TP sub-configs, and
// event lists. Auto-response generates REQUEST→RESPONSE pairs.
type SOMEIPConfig struct {
	ServiceID        uint16          `json:"service_id,omitempty"`
	MethodID         uint16          `json:"method_id,omitempty"`
	ClientID         uint16          `json:"client_id,omitempty"`
	SessionStart     uint16          `json:"session_start,omitempty"`
	SessionInc       uint16          `json:"session_inc,omitempty"`
	ProtocolVersion  uint8           `json:"protocol_version,omitempty"`
	InterfaceVersion uint8           `json:"interface_version,omitempty"`
	MessageType      string          `json:"message_type,omitempty"`
	ReturnCode       uint8           `json:"return_code,omitempty"`
	AutoResponse     *bool           `json:"auto_response,omitempty"`
	Direction        string          `json:"direction,omitempty"`
	Payload          []byte          `json:"payload,omitempty"`
	SD               *SOMEIPSDConfig `json:"sd,omitempty"`
	TP               *SOMEIPTPConfig `json:"tp,omitempty"`
	Events           []SOMEIPEvent   `json:"events,omitempty"`
}

// ThriftConfig configures an Apache Thrift Binary Protocol session (TCP 9090).
type ThriftConfig struct {
	Transport string           `json:"transport,omitempty"`
	Messages  []ThriftMessage  `json:"messages,omitempty"`
	WireFault *ThriftWireFault `json:"wire_fault,omitempty"`
}

// ThriftMessage is one Thrift RPC message.
type ThriftMessage struct {
	Type      string           `json:"type,omitempty"`
	Method    string           `json:"method,omitempty"`
	SeqID     int32            `json:"seqid,omitempty"`
	Args      []ThriftField    `json:"args,omitempty"`
	Result    []ThriftField    `json:"result,omitempty"`
	Exception *ThriftException `json:"exception,omitempty"`
	// TypeCode overrides Type with a raw message-type byte (negative tests:
	// out-of-range codes must be rejected).
	TypeCode int `json:"type_code,omitempty"`
}

// ThriftField is a single struct field in Thrift Binary Protocol.
type ThriftField struct {
	ID    int16       `json:"id,omitempty"`
	Type  string      `json:"type,omitempty"`
	Value interface{} `json:"value,omitempty"`
	// TypeCode overrides Type with a raw TType byte (negative tests).
	TypeCode int `json:"type_code,omitempty"`
	// Container field declarations (LIST/SET/MAP).
	ElemType  string           `json:"elem_type,omitempty"`
	KeyType   string           `json:"key_type,omitempty"`
	ValueType string           `json:"value_type,omitempty"`
	Values    []interface{}    `json:"values,omitempty"`
	Entries   []ThriftMapEntry `json:"entries,omitempty"`
	// ValueB64 carries BINARY field bytes base64-encoded.
	ValueB64 []byte `json:"value_b64,omitempty"`
}

// ThriftMapEntry is one MAP key/value pair.
type ThriftMapEntry struct {
	Key   interface{} `json:"key,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// ThriftWireFault is a negative-test wire fault injection (rejected in
// Validate — the faulted spec must never produce traffic).
type ThriftWireFault struct {
	Kind    string `json:"kind,omitempty"`     // truncate|negative_length|negative_container_count
	At      string `json:"at,omitempty"`       // truncate: string_bytes|...
	FieldID int16  `json:"field_id,omitempty"` // negative_length/negative_container_count
}

// ThriftException carries TApplicationException fields.
type ThriftException struct {
	Message string `json:"message,omitempty"`
	Type    int32  `json:"type,omitempty"`
}

// OpenWireConfig configures an ActiveMQ OpenWire session (TCP 61616, loose
// encoding, non-cached — tshark 3.6.14 的解析口径只支持 loose）。每个连接
// 独立 TCP 四元组与实体表；事件按序产出为 OpenWire command 帧。
type OpenWireConfig struct {
	// Profile names the negotiated wire profile; "" → activemq_openwire_v12.
	// 未知 profile 拒绝（neg_carrier_profile 锚词）。
	Profile string `json:"profile,omitempty"`
	// WireFormat is the negotiated wire format (version/tight/cache)。本版
	// 只生成 loose + 非 cached（tshark 对 tight 直接放弃解析）。
	WireFormat *OpenWireWireFormat `json:"wire_format,omitempty"`
	// Connections 有序连接数组；每连接独立 TCP 连接（事件 SrcPort 边界）。
	Connections []OpenWireConnection `json:"connections,omitempty"`
	// WireFault 负例故障注入口（validator 消费，注入即拒绝）。
	WireFault *OpenWireWireFault `json:"wire_fault,omitempty"`
}

// OpenWireWireFormat is the negotiated wire format block. TightEncoding/
// CacheEnabled 只接受 false（tshark 3.6.14 对 tight 编码放弃解析；cached
// 对象引用启发式误判风险）——true 必须拒绝。
type OpenWireWireFormat struct {
	Version       int  `json:"version,omitempty"`
	TightEncoding bool `json:"tight_encoding,omitempty"`
	CacheEnabled  bool `json:"cache_enabled,omitempty"`
}

// OpenWireConnection is one TCP connection's command sequence. SrcIP/DstIP
// 显式声明时该配置走自驱完整包路径（双栈用例——v6 连接无法经 v4 spec 的
// ip 层）；SrcPort 是该连接的客户端源端口（事件模式经 MessageEvent.SrcPort
// 驱动 TCPGenerator 的会话边界）。
type OpenWireConnection struct {
	ConnectionID int             `json:"connection_id,omitempty"`
	ClientID     string          `json:"client_id,omitempty"`
	SrcPort      uint16          `json:"src_port,omitempty"`
	SrcIP        string          `json:"src_ip,omitempty"`
	DstIP        string          `json:"dst_ip,omitempty"`
	Events       []OpenWireEvent `json:"events,omitempty"`
}

// OpenWireEvent is one OpenWire command in sequence order.
type OpenWireEvent struct {
	// Kind selects the command: wire_format_info|connection_info|connection_ack|
	// session_info|producer_info|consumer_info|message|dispatch|ack|transaction|
	// response|exception|remove|shutdown。未知 kind 拒绝（neg_unknown_command）。
	Kind string `json:"kind,omitempty"`
	// Direction c2s|s2c；缺省按 kind 推导（message/ack/connection_info 等
	// c2s，dispatch/connection_ack/response/exception s2c）。
	Direction string `json:"direction,omitempty"`
	// SessionID/ProducerID/ConsumerID 是连接内实体标识（线上 SessionId.value/
	// ProducerId.value/ConsumerId.value 与其 sessionId 字段）。
	SessionID  uint64 `json:"session_id,omitempty"`
	ProducerID uint64 `json:"producer_id,omitempty"`
	ConsumerID uint64 `json:"consumer_id,omitempty"`
	// Destination is "queue://name" or "topic://name"（其它前缀拒绝）。
	Destination string `json:"destination,omitempty"`
	// MessageID is the logical correlation key across message/dispatch/ack.
	MessageID string `json:"message_id,omitempty"`
	// AckMode auto|client|individual|dups_ok（consumer/ack 事件）。
	AckMode string `json:"ack_mode,omitempty"`
	// Prefetch is the ConsumerInfo prefetch size（缺省 1000）。
	Prefetch int `json:"prefetch,omitempty"`
	// Persistent is the Message persistent flag（显式声明，缺省 false）。
	Persistent bool `json:"persistent,omitempty"`
	// Priority is the Message priority（0-9，缺省 4）。
	Priority int `json:"priority,omitempty"`
	// Body/BodyB64 is the Message content（二选一，Base64 优先）。
	Body    string `json:"body,omitempty"`
	BodyB64 []byte `json:"body_b64,omitempty"`
	// Transaction 边界事件（kind=transaction）。
	Transaction *OpenWireTransaction `json:"transaction,omitempty"`
	// CorrelationID is the explicit Response/ExceptionResponse correlation；
	// 缺省关联最近一条 c2s command。显式值必须命中已发出的客户端命令
	// （neg_correlation）。
	CorrelationID int    `json:"correlation_id,omitempty"`
	Exception     string `json:"exception,omitempty"`
	// Redelivery is the MessageDispatch redelivery counter（显式声明）。
	Redelivery int `json:"redelivery,omitempty"`
	// MessageCount is the MessageAck count（缺省 1）。
	MessageCount int `json:"message_count,omitempty"`
	// CommandID overrides the auto-assigned command id（线上 4 字节命令号）。
	CommandID int `json:"command_id,omitempty"`
	// ResponseRequired overrides the default (c2s→1, s2c→0)。
	ResponseRequired *bool `json:"response_required,omitempty"`
}

// OpenWireTransaction is a transaction boundary (begin/commit/rollback)。
type OpenWireTransaction struct {
	ID   uint64 `json:"id,omitempty"`
	Kind string `json:"kind,omitempty"` // begin|commit|rollback
}

// OpenWireWireFault is a negative-test wire fault injection（validator 消费
// ——注入即拒绝，不是线上字段）。
type OpenWireWireFault struct {
	Kind string `json:"kind,omitempty"` // short_frame|length_overrun|bad_type
}

// AMSConfig configures an ActiveMQ Management Service (AMS) management
// session (TCP 61616，本项目 AMS wire profile——Length|Version|Type|Flags|
// SessionID|CorrelationID|TLV payload|FrameEnd)。帧字段语义见
// docs/protocol-designs/51-ams-design.md §3–§7。
type AMSConfig struct {
	// Profile names the wire profile; "" → ams_management_v1。未知 profile 拒绝。
	Profile string `json:"profile,omitempty"`
	// FrameMax caps the encoded frame size (Length 字段上界，0 = 4096 默认)。
	FrameMax uint32 `json:"frame_max,omitempty"`
	// Heartbeat is the negotiated keepalive seconds (HELLO_OK 回显，0 = 禁用)。
	Heartbeat uint16 `json:"heartbeat,omitempty"`
	// ClientName is the HELLO client_name TLV（缺省 ams-client）。
	ClientName string `json:"client_name,omitempty"`
	// AuthMethod/CredentialRef are the AUTH TLVs（缺省 ref / cred-ref-1；
	// 不在线发送明文密码——设计 §4）。
	AuthMethod    string `json:"auth_method,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	// SessionLimit is the uint16 server session limit（HELLO_OK 回显）。
	SessionLimit uint16 `json:"session_limit,omitempty"`
	// Connections 有序连接数组；每连接独立 TCP 四元组与独立状态。
	Connections []AMSConnection `json:"connections,omitempty"`
	// WireFault 负例故障注入口（validator 消费，注入即拒绝）。
	WireFault string `json:"wire_fault,omitempty"`
}

// AMSConnection is one TCP connection: 连接级握手帧（hello/auth，SessionID=0）
// 加上若干管理会话。
type AMSConnection struct {
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	// Events is the connection-level pre-session sequence（HELLO/AUTH 交换，
	// 线上 SessionID=0）。
	Events []AMSEvent `json:"events,omitempty"`
	// Sessions 有序管理会话；SessionID 在连接内唯一，状态独立。
	Sessions []AMSSession `json:"sessions,omitempty"`
}

// AMSSession is one management session (SessionID 逻辑流键)。
type AMSSession struct {
	SessionID uint32     `json:"session_id,omitempty"`
	Events    []AMSEvent `json:"events,omitempty"`
}

// AMSEvent is one AMS frame in sequence order. Kind selects the frame type;
// 显式 Type/Flags 可覆盖推导值（负例与特殊 fixture 用）。
type AMSEvent struct {
	// Kind: hello|hello_ok|auth|auth_ok|open_session|open_ok|close_session|
	// close_ok|message|message_ack|command|response|ping|pong|error。
	Kind string `json:"kind,omitempty"`
	// Direction c2s|s2c；缺省按 kind 推导（_ok/pong/response/message_ack/
	// error→s2c，其余 c2s）。
	Direction string `json:"direction,omitempty"`
	// Type overrides the kind-derived frame type byte。
	Type int `json:"type,omitempty"`
	// Flags overrides the kind-derived flags (bit0 request/bit1 response/
	// bit2 ack-required)。
	Flags int `json:"flags,omitempty"`
	// CorrelationID is the frame header correlation (COMMAND/RESPONSE 配对)。
	CorrelationID uint64 `json:"correlation_id,omitempty"`
	// MessageID/Sequence/AckFor are MESSAGE/MESSAGE_ACK 关联键。
	MessageID uint64 `json:"message_id,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
	AckFor    uint64 `json:"ack_for,omitempty"`
	// Command/Resource are the COMMAND TLVs；Body 是可选 0x0022 body。
	Command  string `json:"command,omitempty"`
	Resource string `json:"resource,omitempty"`
	Body     []byte `json:"body,omitempty"`
	// Status is the RESPONSE/OPEN_OK uint16 status TLV。
	Status int `json:"status,omitempty"`
	// Message fields：MessageKind (0x0031)、DeliveryMode (0x0032)、
	// Payload (0x0034 opaque)。
	MessageKind  string `json:"message_kind,omitempty"`
	DeliveryMode int    `json:"delivery_mode,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	// Ack fields：AckStatus (0x0041)、AckRangeEnd (0x0042)。
	AckStatus   int    `json:"ack_status,omitempty"`
	AckRangeEnd uint64 `json:"ack_range_end,omitempty"`
	// Error fields：ErrorCode (0x00f0)、ErrorText (0x00f1)。
	ErrorCode int    `json:"error_code,omitempty"`
	ErrorText string `json:"error_text,omitempty"`
	// SessionName is the optional OPEN_SESSION 0x0010 TLV。
	SessionName string `json:"session_name,omitempty"`
}

// SwarmConfig configures the Swarm storage/discovery wire profile (B5)：
// UDP discovery（[ip,udp,swarm]，SWD1 datagram）与 TCP storage（[ip,tcp,swarm]，
// SWS1 frame）两种承载。帧布局见 docs/protocol-designs/52-swarm-design.md §3。
type SwarmConfig struct {
	// Profile names the wire profile; "" → swarm_storage_v1。未知 profile 拒绝。
	Profile string `json:"profile,omitempty"`
	// Discovery is the UDP discovery plane (配置即走 udp 链)。
	Discovery *SwarmDiscovery `json:"discovery,omitempty"`
	// FrameMax caps the storage frame size (Length 上界，0 = 4096 默认)。
	FrameMax uint32 `json:"frame_max,omitempty"`
	// Heartbeat is the negotiated keepalive seconds (HELLO_OK 回显，0 = 禁用)。
	Heartbeat uint16 `json:"heartbeat,omitempty"`
	// NodeIDHex is the 32-byte node identity (discovery 与握手 TLV 共用，
	// 缺省 0102…20；必须是 64 个 hex 字符且非全零)。
	NodeIDHex string `json:"node_id_hex,omitempty"`
	// Capability is the HELLO capability TLV (缺省 chunks,manifest)。
	Capability string `json:"capability,omitempty"`
	// SessionLimit/MaxFrame are the HELLO_OK 协商限制回显 (缺省 8 / 4096)。
	SessionLimit uint16 `json:"session_limit,omitempty"`
	MaxFrame     uint32 `json:"max_frame,omitempty"`
	// Connections 有序 TCP storage 连接 (配置即走 tcp 链)。
	Connections []SwarmConnection `json:"connections,omitempty"`
	// WireFault 负例故障注入口 (validator 消费，注入即拒绝)。
	WireFault string `json:"wire_fault,omitempty"`
}

// SwarmDiscovery is the UDP discovery plane：ping/pong/announcement datagrams。
type SwarmDiscovery struct {
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	// Events is the datagram sequence (每事件一个 UDP datagram)。
	Events []SwarmEvent `json:"events,omitempty"`
}

// SwarmConnection is one TCP storage connection。
type SwarmConnection struct {
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	// Events is the connection-level pre-session sequence (HELLO/AUTH 交换)。
	Events []SwarmEvent `json:"events,omitempty"`
	// Sessions 有序存储会话；SessionID 在连接内唯一。
	Sessions []SwarmSession `json:"sessions,omitempty"`
}

// SwarmSession is one storage session (SessionID 逻辑流键)。
type SwarmSession struct {
	SessionID uint64        `json:"session_id,omitempty"`
	Events    []SwarmEvent  `json:"events,omitempty"`
	Streams   []SwarmStream `json:"streams,omitempty"`
}

// SwarmStream is one multiplexed stream inside a session (StreamID 键)。
type SwarmStream struct {
	StreamID uint32       `json:"stream_id,omitempty"`
	Events   []SwarmEvent `json:"events,omitempty"`
}

// SwarmEvent is one Swarm frame (discovery 或 storage) in sequence order。
type SwarmEvent struct {
	// Kind: discovery—ping|pong|announce；storage—hello|hello_ok|auth|auth_ok|
	// open_session|open_ok|close|close_ok|store|store_ok|retrieve|chunk|
	// manifest|message_ack|ping|pong|error。
	Kind string `json:"kind,omitempty"`
	// Direction c2s|s2c；缺省按 kind 推导（_ok/pong/chunk/store_ok/
	// message_ack/error→s2c，其余 c2s）。
	Direction string `json:"direction,omitempty"`
	// CorrelationID is the storage frame header correlation。
	CorrelationID uint64 `json:"correlation_id,omitempty"`
	// MessageID/Sequence/AckFor/AckStatus are message/ack 关联 TLVs。
	MessageID uint64 `json:"message_id,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
	AckFor    uint64 `json:"ack_for,omitempty"`
	AckStatus int    `json:"ack_status,omitempty"`
	// Chunk fields：ChunkAddress (32B hex)、ChunkSize、ChunkOffset、
	// Payload (chunk_payload / manifest_entry / binary body)。
	ChunkAddress string `json:"chunk_address,omitempty"`
	ChunkSize    uint32 `json:"chunk_size,omitempty"`
	ChunkOffset  uint32 `json:"chunk_offset,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	// Fragment fields (CHUNK 分片)。
	FragmentIndex int `json:"fragment_index,omitempty"`
	FragmentCount int `json:"fragment_count,omitempty"`
	// Manifest fields：ManifestRoot (32B hex)、ManifestEntry (opaque)。
	ManifestRoot  string `json:"manifest_root,omitempty"`
	ManifestEntry []byte `json:"manifest_entry,omitempty"`
	// Discovery fields：Nonce (uint64 request/response 关联)、
	// Endpoints (0x03 announcement / ping 附带)。
	Nonce     uint64          `json:"nonce,omitempty"`
	Endpoints []SwarmEndpoint `json:"endpoints,omitempty"`
	// DeliveryMode 1 = ack-required (STORE/CHUNK flags bit2)。
	DeliveryMode int `json:"delivery_mode,omitempty"`
	// Error fields。
	ErrorCode int    `json:"error_code,omitempty"`
	ErrorText string `json:"error_text,omitempty"`
	// Type/Flags override the kind-derived bytes (特殊 fixture 用)。
	Type  int `json:"type,omitempty"`
	Flags int `json:"flags,omitempty"`
}

// GnutellaConfig configures the Gnutella wire profile (B5)：TCP 6346 上的
// Gnutella 0.6 HTTP-like 握手 + 23 字节二进制消息（MessageID(16)|Descriptor|
// TTL|Hops|PayloadLength(LE, 4)|Payload）。见 docs/protocol-designs/
// 53-gnutella-design.md §3–§5。
type GnutellaConfig struct {
	// Profile names the wire profile; "" → gnutella_v060（IPv4 地址字段
	// 4B）；gnutella_ipv6_v1 → 地址字段 16B。未知 profile 拒绝。
	Profile string `json:"profile,omitempty"`
	// FrameMax caps the message size (PayloadLength 上界，0 = 4096 默认)。
	FrameMax uint32 `json:"frame_max,omitempty"`
	// ClientHeaders/ServerHeaders are the握手能力头（缺省 User-Agent/
	// X-Query-Routing/X-Ultrapeer/X-Node；键按字典序稳定输出）。
	ClientHeaders map[string]string `json:"client_headers,omitempty"`
	ServerHeaders map[string]string `json:"server_headers,omitempty"`
	// Connections 有序连接；每连接独立握手与消息状态。
	Connections []GnutellaConn `json:"connections,omitempty"`
	// WireFault 负例故障注入口 (validator 消费，注入即拒绝)。
	WireFault string `json:"wire_fault,omitempty"`
}

// GnutellaConn is one TCP connection：握手事件 + 业务消息事件。
type GnutellaConn struct {
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	// Events 有序事件（connect/ok + 业务消息）。
	Events []GnutellaEvent `json:"events,omitempty"`
}

// GnutellaResult is one QUERY_HIT result entry (FileIndex(4)|FileSize(4)|
// FileName NUL-terminated)。
type GnutellaResult struct {
	FileIndex uint32 `json:"file_index,omitempty"`
	FileSize  uint32 `json:"file_size,omitempty"`
	Name      string `json:"name,omitempty"`
}

// GnutellaEvent is one handshake frame or binary message in sequence order。
type GnutellaEvent struct {
	// Kind: connect|ok|refuse（握手）|ping|pong|query|query_hit|push|vendor
	//（业务）。未知 kind 拒绝。
	Kind string `json:"kind,omitempty"`
	// Direction c2s|s2c；缺省按 kind 推导（ok/pong/query_hit/refuse→s2c）。
	Direction string `json:"direction,omitempty"`
	// Headers are the handshake capability lines（connect/ok 事件）。
	Headers map[string]string `json:"headers,omitempty"`
	// MessageID is the 16-byte GUID of this message（pong 与 ping 相同）。
	MessageID []byte `json:"message_id,omitempty"`
	// TTL/Hops are the header bytes（转发副本 ttl-1/hops+1）。
	TTL  uint8 `json:"ttl,omitempty"`
	Hops uint8 `json:"hops,omitempty"`
	// QueryID references the QUERY GUID（query_hit 事件）。
	QueryID []byte `json:"query_id,omitempty"`
	// ServentID is the 16-byte servant identity（query_hit/push）。
	ServentID []byte `json:"servent_id,omitempty"`
	// FileIndex is the PUSH file index (uint32 边界可用满)。
	FileIndex uint32 `json:"file_index,omitempty"`
	// Criteria is the QUERY search text（NUL 终止上线）。
	Criteria string `json:"criteria,omitempty"`
	// MinSpeed is the QUERY min speed (uint16)。
	MinSpeed uint16 `json:"min_speed,omitempty"`
	// Pong fields：PongPort/PongAddress/Files/KB。
	PongPort    uint16 `json:"pong_port,omitempty"`
	PongAddress []byte `json:"pong_address,omitempty"`
	Files       uint32 `json:"files,omitempty"`
	KB          uint32 `json:"kb,omitempty"`
	// QueryHit fields：Hits/HitPort/HitAddress/Speed/Results。
	Hits       int              `json:"hits,omitempty"`
	HitPort    uint16           `json:"hit_port,omitempty"`
	HitAddress []byte           `json:"hit_address,omitempty"`
	Speed      uint32           `json:"speed,omitempty"`
	Results    []GnutellaResult `json:"results,omitempty"`
	// Push fields：PushAddress/PushPort。
	PushAddress []byte `json:"push_address,omitempty"`
	PushPort    uint16 `json:"push_port,omitempty"`
	// Vendor fields：VendorID(4 chars)/Selector/Version/Payload。
	VendorID string `json:"vendor_id,omitempty"`
	Selector uint16 `json:"selector,omitempty"`
	Version  uint16 `json:"version,omitempty"`
	Payload  []byte `json:"payload,omitempty"`
}

// SwarmEndpoint is one discovery endpoint (AddressFamily|Port|Address)。
type SwarmEndpoint struct {
	// AddressFamily 1 = IPv4 (4B)，2 = IPv6 (16B)；Address 为裸地址字节
	//（JSON base64）。
	AddressFamily int    `json:"address_family,omitempty"`
	Port          uint16 `json:"port,omitempty"`
	Address       []byte `json:"address,omitempty"`
}

// TNSEvent is one TNS protocol event (CONNECT/ACCEPT/REFUSE/REDIRECT/DATA).
type TNSEvent struct {
	Type           interface{} `json:"type,omitempty"` // string or int for negative tests
	Direction      string      `json:"direction,omitempty"`
	PayloadProfile string      `json:"payload_profile,omitempty"`
	DataFlags      uint16      `json:"data_flags,omitempty"`
}

// TNSSession is a single TNS session with its own source port and events.
type TNSSession struct {
	SrcPort uint16     `json:"src_port,omitempty"`
	Events  []TNSEvent `json:"events,omitempty"`
}

// TNSConfig configures a TNS (Oracle Net, TCP 1521) session.
type TNSConfig struct {
	Events       []TNSEvent      `json:"events,omitempty"`
	Sessions     []TNSSession    `json:"sessions,omitempty"`
	ChecksumMode string          `json:"checksum_mode,omitempty"`
	Reconnect    bool            `json:"reconnect,omitempty"`
	WireFault    json.RawMessage `json:"wire_fault,omitempty"`
}

// MongoDBMessage is one MongoDB wire protocol message.
type MongoDBMessage struct {
	Direction      string                   `json:"direction,omitempty"`
	RequestID      int32                    `json:"request_id,omitempty"`
	ResponseTo     int32                    `json:"response_to,omitempty"`
	Opcode         interface{}              `json:"opcode,omitempty"` // string or int for negative tests
	Namespace      string                   `json:"namespace,omitempty"`
	Flags          int32                    `json:"flags,omitempty"`
	Skip           int32                    `json:"skip,omitempty"`
	ReturnCount    int32                    `json:"return_count,omitempty"`
	Zero           int32                    `json:"zero,omitempty"`
	Documents      []map[string]interface{} `json:"documents,omitempty"`
	Selector       map[string]interface{}   `json:"selector,omitempty"`
	Update         map[string]interface{}   `json:"update,omitempty"`
	Query          map[string]interface{}   `json:"query,omitempty"`
	CursorID       int64                    `json:"cursor_id,omitempty"`
	CursorIDs      []int64                  `json:"cursor_ids,omitempty"`
	StartingFrom   int32                    `json:"starting_from,omitempty"`
	Returned       int32                    `json:"returned,omitempty"`
	BSONFixtureHex string                   `json:"bson_fixture_hex,omitempty"`
}

// MongoDBSession is a single MongoDB session with its own source port and messages.
type MongoDBSession struct {
	SrcPort  uint16           `json:"src_port,omitempty"`
	Messages []MongoDBMessage `json:"messages,omitempty"`
}

// MongoDBConfig configures a MongoDB wire protocol session (TCP 27017).
type MongoDBConfig struct {
	Messages       []MongoDBMessage `json:"messages,omitempty"`
	Sessions       []MongoDBSession `json:"sessions,omitempty"`
	BSONFixtureHex string           `json:"bson_fixture_hex,omitempty"`
	WireFault      json.RawMessage  `json:"wire_fault,omitempty"`
}

// DamengEvent is one Dameng database protocol event.
type DamengEvent struct {
	Kind      string `json:"kind,omitempty"`
	Direction string `json:"direction,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Username  string `json:"username,omitempty"`
	Result    string `json:"result,omitempty"`
	SQL       string `json:"sql,omitempty"`
}

// DamengSession is a single Dameng session with its own source port and events.
type DamengSession struct {
	SrcPort uint16        `json:"src_port,omitempty"`
	Events  []DamengEvent `json:"events,omitempty"`
}

// DamengConfig configures a Dameng database session (TCP 5236).
type DamengConfig struct {
	WireProfile string          `json:"wire_profile,omitempty"`
	Events      []DamengEvent   `json:"events,omitempty"`
	Sessions    []DamengSession `json:"sessions,omitempty"`
	PayloadSize string          `json:"payload_size,omitempty"`
	WireFault   json.RawMessage `json:"wire_fault,omitempty"`
}

// CQLEvent is one CQL/Cassandra native protocol event.
type CQLEvent struct {
	Kind        string                 `json:"kind,omitempty"`
	Direction   string                 `json:"direction,omitempty"`
	Flags       uint8                  `json:"flags,omitempty"`
	Stream      int16                  `json:"stream,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
	Mechanism   string                 `json:"mechanism,omitempty"`
	Bytes       []byte                 `json:"bytes,omitempty"`
	Query       string                 `json:"query,omitempty"`
	Consistency uint16                 `json:"consistency,omitempty"`
	QueryFlags  uint32                 `json:"query_flags,omitempty"`
	ResultKind  string                 `json:"result_kind,omitempty"`
	PreparedID  string                 `json:"prepared_id,omitempty"`
	Code        int32                  `json:"code,omitempty"`
	Message     string                 `json:"message,omitempty"`
}

// CQLSession is a single CQL session with its own source port and events.
type CQLSession struct {
	SrcPort uint16     `json:"src_port,omitempty"`
	Events  []CQLEvent `json:"events,omitempty"`
}

// CQLConfig configures a CQL/Cassandra native protocol session (TCP 9042).
type CQLConfig struct {
	WireProfile string          `json:"wire_profile,omitempty"`
	Events      []CQLEvent      `json:"events,omitempty"`
	Sessions    []CQLSession    `json:"sessions,omitempty"`
	WireFault   json.RawMessage `json:"wire_fault,omitempty"`
}

// SOMEIPSDConfig configures a SOME/IP-SD (Service Discovery) message.
type SOMEIPSDConfig struct {
	Type         string         `json:"type,omitempty"`
	ServiceID    uint16         `json:"service_id,omitempty"`
	InstanceID   uint16         `json:"instance_id,omitempty"`
	MajorVersion uint8          `json:"major_version,omitempty"`
	MinorVersion uint32         `json:"minor_version,omitempty"`
	TTL          uint32         `json:"ttl,omitempty"`
	EventgroupID uint16         `json:"eventgroup_id,omitempty"`
	Counter      uint8          `json:"counter,omitempty"`
	Options      []SOMEIPOption `json:"options,omitempty"`
}

// SOMEIPOption is an SD Option entry.
type SOMEIPOption struct {
	Type  uint8  `json:"type,omitempty"`
	IP    string `json:"ip,omitempty"`
	Port  uint16 `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
}

// SOMEIPTPConfig configures SOME/IP-TP segmentation.
type SOMEIPTPConfig struct {
	Enabled       bool `json:"enabled,omitempty"`
	SegmentSize   int  `json:"segment_size,omitempty"`
	PayloadLength int  `json:"payload_length,omitempty"`
}

// SOMEIPEvent is one message in a multi-method/event sequence.
type SOMEIPEvent struct {
	MethodID    uint16 `json:"method_id,omitempty"`
	MessageType string `json:"message_type,omitempty"`
	ReturnCode  uint8  `json:"return_code,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
}

// DRDAConfig configures a DRDA session (IBM Distributed Relational Database Architecture, TCP 446).
type DRDAConfig struct {
	Transport string `json:"transport,omitempty"`
	// Association bounds the default exchange sequence (case JSON key):
	// "excsat" = EXCSAT pair only, "security" = through SECCHK, "database" =
	// through ACCRDB, "sql" = through SQLDTA/SQLCARD. Empty = full sequence.
	Association string `json:"association,omitempty"`
	// DSSLength is a declared DSS header length override used by negative-path
	// cases (dss_length_mismatch): a declared length smaller than the fixed
	// 6-byte DSS header is a wire fault and is rejected at validation.
	DSSLength       int            `json:"dss_length,omitempty"`
	SessionStart    int            `json:"session_start,omitempty"`
	CCSID           uint16         `json:"ccsid,omitempty"`
	CorrelatorStart uint16         `json:"correlator_start,omitempty"`
	CorrelatorInc   uint16         `json:"correlator_inc,omitempty"`
	SecurityUser    string         `json:"security_user,omitempty"`
	SecurityToken   []byte         `json:"security_token,omitempty"`
	RDBName         string         `json:"rdb_name,omitempty"`
	SQL             *DRDASQLConfig `json:"sql,omitempty"`
	DSSSegments     []DRDASegment  `json:"dss_segments,omitempty"`
	// Sessions enables multi-session expansion (P0a pattern): each session
	// is an independent TCP connection with its own src_port and correlator
	// sequence restarting from CorrelatorStart.
	Sessions []DRDASession `json:"sessions,omitempty"`
}

// DRDASession is one independent TCP session in a multi-session DRDA config.
type DRDASession struct {
	ID              string `json:"id,omitempty"`
	SrcPort         uint16 `json:"src_port,omitempty"`
	CorrelatorStart uint16 `json:"correlator_start,omitempty"`
}

// DRDASQLConfig configures SQLDTA/SQLCARD in DRDA.
type DRDASQLConfig struct {
	Statement  string `json:"statement,omitempty"`
	Data       []byte `json:"data,omitempty"`
	SQLCode    int32  `json:"code,omitempty"`
	SQLState   string `json:"state,omitempty"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

// DRDASegment is a user-defined DSS/DDM segment. Length/Length2 are the
// declared DSS field values; the encoder still computes them from the body,
// and Validate cross-checks them against DSSLength (declared-vs-encoded
// mismatch = wire fault).
type DRDASegment struct {
	Format     uint16      `json:"format,omitempty"`
	Correlator uint16      `json:"correlator,omitempty"`
	Length     int         `json:"length,omitempty"`
	Length2    int         `json:"length2,omitempty"`
	CodePoint  uint16      `json:"code_point,omitempty"`
	Parameters []DRDAParam `json:"parameters,omitempty"`
}

// DRDAParam is a single DDM parameter (length+code_point+data).
type DRDAParam struct {
	CodePoint uint16 `json:"code_point,omitempty"`
	Data      []byte `json:"data,omitempty"`
}

// OPCUAConfig configures a minimal OPC UA TCP session.
type OPCUAConfig struct {
	Transport    string          `json:"transport,omitempty"`
	SecurityMode string          `json:"security_mode,omitempty"`
	Read         []OPCUANodeRead `json:"read,omitempty"`
	Write        []OPCUANodeRead `json:"write,omitempty"`
	Browse       []OPCUANodeRead `json:"browse,omitempty"`
	Subscription *OPCUASubConfig `json:"subscription,omitempty"`
	Sessions     int             `json:"sessions,omitempty"`
	ErrorInject  *OPCUAErrInject `json:"error_inject,omitempty"`
	Close        bool            `json:"close,omitempty"`
	SkipChannel  bool            `json:"skip_channel,omitempty"`
	// BadMessageSize / BadLength are negative-test injections: Validate
	// rejects them (the faulted spec must never produce traffic).
	BadMessageSize bool `json:"bad_message_size,omitempty"`
	BadLength      bool `json:"bad_length,omitempty"`
}

// OPCUANodeRead is one node-scoped service operation (read/write/browse op
// with its target node list and attribute).
type OPCUANodeRead struct {
	NodeIDs     []string `json:"node_ids,omitempty"`
	AttributeID uint32   `json:"attribute_id,omitempty"`
}

// OPCUASubConfig configures the subscription scenario (create + monitored
// items + publish_count publishes + keepalives).
type OPCUASubConfig struct {
	PublishingIntervalMs uint32   `json:"publishing_interval_ms,omitempty"`
	PublishCount         int      `json:"publish_count,omitempty"`
	PublishIntervalMs    uint32   `json:"publish_interval_ms,omitempty"`
	KeepAlive            bool     `json:"keep_alive,omitempty"`
	MaxKeepAliveCount    uint32   `json:"max_keep_alive_count,omitempty"`
	MonitoredNodes       []string `json:"monitored_nodes,omitempty"`
}

// OPCUAErrInject injects a service-level error into the MSG response
// (bad_node → BadNodeIdUnknown, denied → BadUserAccessDenied).
type OPCUAErrInject struct {
	Op   string `json:"op,omitempty"`
	Node string `json:"node,omitempty"`
}

// MMSConfig configures an IEC 61850 MMS session over TCP.
type MMSConfig struct {
	Transport               string                `json:"transport,omitempty"`
	Association             *MMSAssociationConfig `json:"association,omitempty"`
	IEDName                 string                `json:"iedName,omitempty"`
	Objects                 []MMSObjectConfig     `json:"objects,omitempty"`
	EnableRead              bool                  `json:"enableRead,omitempty"`
	EnableWrite             bool                  `json:"enableWrite,omitempty"`
	EnableInformationReport bool                  `json:"enableInformationReport,omitempty"`
	EnableGetNameList       bool                  `json:"enableGetNameList,omitempty"`
	EnableIdentify          bool                  `json:"enableIdentify,omitempty"`
	Sequence                *MMSSequence          `json:"sequence,omitempty"`
	MultiSession            []MMSConfig           `json:"multiSession,omitempty"`
	ErrorClassName          string                `json:"errorClassName,omitempty"`
	ErrorValue              int                   `json:"errorValue,omitempty"`
}

type MMSAssociationConfig struct {
	LocalDetail           uint32 `json:"localDetail,omitempty"`
	MaxOutstandingCalling uint8  `json:"maxOutstandingCalling,omitempty"`
	MaxOutstandingCalled  uint8  `json:"maxOutstandingCalled,omitempty"`
	NestingLevel          uint8  `json:"nestingLevel,omitempty"`
	ServicesSupported     string `json:"servicesSupported,omitempty"`
	NoAssociate           bool   `json:"noAssociate,omitempty"`
}

type MMSObjectConfig struct {
	Domain   string      `json:"domain,omitempty"`
	Name     string      `json:"name"`
	Datatype string      `json:"datatype"`
	Value    interface{} `json:"value,omitempty"`
	Members  []MMSMember `json:"members,omitempty"`
}

type MMSMember struct {
	Name     string      `json:"name,omitempty"`
	Datatype string      `json:"datatype"`
	Value    interface{} `json:"value,omitempty"`
}

type MMSSequence struct {
	Steps    []string `json:"steps"`
	Loop     int      `json:"loop,omitempty"`
	StepGap  int      `json:"stepGap,omitempty"`
	InjectOn int      `json:"injectOn,omitempty"`
}

type S7Config struct {
	Transport string      `json:"transport,omitempty"`
	Sessions  int         `json:"sessions,omitempty"`
	PDURef    uint16      `json:"pdu_ref,omitempty"`
	PDUSize   uint16      `json:"pdu_size,omitempty"`
	Commands  []S7Command `json:"commands,omitempty"`
}

// S7Command describes one S7 job and its optional response.
type S7Command struct {
	Kind   string   `json:"kind,omitempty"`
	ROSCTR uint8    `json:"rosctr,omitempty"`
	PDURef uint16   `json:"pdu_ref,omitempty"`
	Items  []S7Item `json:"items,omitempty"`
	// Value holds per-item write data bytes. JSON shape is [][]byte (one entry
	// per S7ANY item, each entry the value bytes), e.g. [[1]] for a single-bit
	// M100.0 write. Decoded from the case's "value" key.
	Value [][]byte `json:"value,omitempty"`
	// ErrClass/ErrCode are the negative-path Ack_Data error class/code (json
	// keys err_class/err_code per the case files).
	ErrClass *uint8 `json:"err_class,omitempty"`
	ErrCode  *uint8 `json:"err_code,omitempty"`
	// ForceROSCTR injects an illegal ROSCTR for validate-negative cases.
	ForceROSCTR *uint8 `json:"force_rosctr,omitempty"`
	// PadPDULen faults the TPKT/S7 length agreement for validate-negative cases.
	PadPDULen *bool  `json:"pad_pdu_len,omitempty"`
	SzlID     uint16 `json:"szl_id,omitempty"`
	SzlIndex  uint16 `json:"szl_index,omitempty"`
}

// S7Item describes an S7ANY variable specification.
type S7Item struct {
	Area          uint8  `json:"area,omitempty"`
	DBNumber      uint16 `json:"db_number,omitempty"`
	Address       uint32 `json:"address,omitempty"`
	Bit           uint8  `json:"bit,omitempty"`
	TransportSize uint8  `json:"transport_size,omitempty"`
	Length        uint16 `json:"length,omitempty"`
	Data          []byte `json:"data,omitempty"`
}

// GOOSEData describes one supported IEC 61850 GOOSE allData member.
// The minimal generator accepts exactly one boolean member.
type GOOSEData struct {
	Name  string      `json:"name,omitempty"`
	Type  string      `json:"type"`
	Value interface{} `json:"value,omitempty"`
	// BitLength is the number of meaningful bits in a bit_string member
	// (IEC 61850 BIT STRING). Encoded as leading unused-bit count: for
	// bit_length L, the final byte carries 8-(L%8) trailing zeros and the
	// first content byte reports 8-(L%8) unused bits (0 when byte-aligned).
	BitLength int `json:"bit_length,omitempty"`
}

// GOOSEConfig configures a minimal IEC 61850 GOOSE Ethernet frame sequence.
type GOOSEConfig struct {
	APPID        uint16      `json:"appid"`
	GOCBRef      string      `json:"gocb_ref"`
	DatSet       string      `json:"dat_set"`
	GOID         string      `json:"go_id,omitempty"`
	TALMs        uint32      `json:"tal_ms"`
	ConfRev      uint32      `json:"conf_rev"`
	StartSTNum   uint32      `json:"start_stnum,omitempty"`
	StartSQNum   uint32      `json:"start_sqnum,omitempty"`
	Test         bool        `json:"test,omitempty"`
	NDSCom       bool        `json:"nds_com,omitempty"`
	Boolean      bool        `json:"boolean,omitempty"`
	Data         []GOOSEData `json:"data,omitempty"`
	Count        int         `json:"count,omitempty"`
	DstMAC       string      `json:"dst_mac,omitempty"`
	VLANEnabled  bool        `json:"vlan_enabled,omitempty"`
	VLANID       uint16      `json:"vlan_id,omitempty"`
	VLANPriority uint8       `json:"vlan_priority,omitempty"`
	// EventSeq is the GOOSE dataset-change/retransmit sequence. Each entry
	// models one state-change burst: stNum bumps, sqNum resets to 0, then
	// `retransmits` fast-retransmit frames follow (sqNum 0..retransmits).
	// After the burst, heartbeat resumes with sqNum continuing.
	EventSeq []GOOSEEventSeq `json:"event_seq,omitempty"`
}

// GOOSEEventSeq describes one GOOSE dataset-change event and its fast
// retransmit burst (design T-GSE-S2). DataIdx selects the changed allData
// member; DelayMs is the inter-frame delay; Retransmits is the number of
// fast-retransmit frames in the burst; SqNumStep (negative tests) asserts the
// sqNum step — a value != 1 violates monotonicity and must be rejected.
type GOOSEEventSeq struct {
	DataIdx     int `json:"data_idx,omitempty"`
	DelayMs     int `json:"delay_ms,omitempty"`
	Retransmits int `json:"retransmits,omitempty"`
	SqNumStep   int `json:"sqnum_step,omitempty"`
}

// SVData describes one integer sampled-value channel.
type SVData struct {
	Name    string `json:"name,omitempty"`
	Type    string `json:"type"`
	InstMag int32  `json:"inst_mag,omitempty"`
	// InstMagF holds the float value for float32 channels (inst_mag as a
	// float, e.g. 1.5). The encoder emits its IEEE 754 single-precision bits.
	InstMagF float32 `json:"-"`
	Quality  uint32  `json:"quality,omitempty"`
	// HasQuality reports whether the quality field was explicitly provided.
	// When set, the seqData member is 8 bytes (value+quality); when absent,
	// 4 bytes (value only) — non-9-2LE custom datasets omit per-channel
	// quality (sv_custom_dataset).
	HasQuality bool `json:"-"`
}

// SVConfig configures a minimal IEC 61850-9-2 sampled-values stream.
type SVConfig struct {
	SVID            string   `json:"sv_id"`
	DatSet          string   `json:"dat_set,omitempty"`
	APPID           uint16   `json:"appid"`
	ConfRev         uint32   `json:"conf_rev"`
	SamplesPerCycle uint16   `json:"samples_per_cycle"`
	SMPSynch        uint8    `json:"smp_synch"`
	SMPRate         uint16   `json:"smp_rate,omitempty"`
	PeriodUS        int      `json:"period_us,omitempty"`
	Data            []SVData `json:"data,omitempty"`
	Count           int      `json:"count,omitempty"`
	DstMAC          string   `json:"dst_mac,omitempty"`
	DoubleSend      bool     `json:"double_send,omitempty"`
	VLANEnabled     bool     `json:"vlan_enabled,omitempty"`
	VLANID          uint16   `json:"vlan_id,omitempty"`
	VLANPriority    uint8    `json:"vlan_priority,omitempty"`
}

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

	// HopByHop is the IPv6 hop-by-hop extension header option list (RFC 8200
	// §4.3). IPv4 traffic must not set it. The builder appends PadN options to
	// align the header to 8 octets and chains it via NextHeader=0x00.
	HopByHop []IPv6Option `json:"hop_by_hop,omitempty"`

	// Protocol specific configuration
	TCP       *TCPConfig       `json:"tcp,omitempty"`
	UDP       *UDPConfig       `json:"udp,omitempty"`
	HTTP      *HTTPConfig      `json:"http,omitempty"`
	DNS       *DNSConfig       `json:"dns,omitempty"`
	ICMP      *ICMPConfig      `json:"icmp,omitempty"`
	ARP       *ARPConfig       `json:"arp,omitempty"`
	FTP       *FTPConfig       `json:"ftp,omitempty"`
	SIP       *SIPConfig       `json:"sip,omitempty"`
	SCTP      *SCTPConfig      `json:"sctp,omitempty"`
	ICMPv6    *ICMPv6Config    `json:"icmpv6,omitempty"`
	RTSP      *RTSPConfig      `json:"rtsp,omitempty"`
	CoAP      *CoAPConfig      `json:"coap,omitempty"`
	S7        *S7Config        `json:"s7,omitempty"`
	IEC104    *IEC104Config    `json:"iec104,omitempty"`
	BGP       *BGPConfig       `json:"bgp,omitempty"`
	OPCUA     *OPCUAConfig     `json:"opcua,omitempty"`
	MMS       *MMSConfig       `json:"mms,omitempty"`
	GOOSE     *GOOSEConfig     `json:"goose,omitempty"`
	SV        *SVConfig        `json:"sv,omitempty"`
	STUN      *STUNConfig      `json:"stun,omitempty"`
	HTTPFLV   *HTTPFLVConfig   `json:"http_flv,omitempty"`
	HLS       *HLSConfig       `json:"hls,omitempty"`
	HDS       *HDSConfig       `json:"hds,omitempty"`
	MOXA      *MOXAConfig      `json:"moxa,omitempty"`
	SOMEIP    *SOMEIPConfig    `json:"someip,omitempty"`
	DRDA      *DRDAConfig      `json:"drda,omitempty"`
	Thrift    *ThriftConfig    `json:"thrift,omitempty"`
	OpenWire  *OpenWireConfig  `json:"openwire,omitempty"`
	AMS       *AMSConfig       `json:"ams,omitempty"`
	Swarm     *SwarmConfig     `json:"swarm,omitempty"`
	Gnutella  *GnutellaConfig  `json:"gnutella,omitempty"`
	TNS       *TNSConfig       `json:"tns,omitempty"`
	MongoDB   *MongoDBConfig   `json:"mongodb,omitempty"`
	Dameng    *DamengConfig    `json:"dameng,omitempty"`
	CQL       *CQLConfig       `json:"cql,omitempty"`
	LDP       *LDPConfig       `json:"ldp,omitempty"`
	PCEP      *PCEPConfig      `json:"pcep,omitempty"`
	CFlow     *CFlowConfig     `json:"cflow,omitempty"`
	RTMFP     *RTMFPConfig     `json:"rtmfp,omitempty"`
	AMQP      *AMQPConfig      `json:"amqp,omitempty"`
	GBT       *GBTConfig       `json:"gbt,omitempty"`
	GetWork   *GetWorkConfig   `json:"getwork,omitempty"`
	Stratum   *StratumConfig   `json:"stratum,omitempty"`
	ETHMining *ETHMiningConfig `json:"ethmining,omitempty"`
	NMEA      *NMEAConfig      `json:"nmea,omitempty"`
	CWMP      *CWMPConfig      `json:"cwmp,omitempty"`
	DOH       *DOHConfig       `json:"doh,omitempty"`
	ONVIF     *ONVIFConfig     `json:"onvif,omitempty"`

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

	// HasExplicitSrcPort tracks whether the user explicitly provided src_port
	// in the strategy config. Used by multi-flow scenarios to auto-increment
	// src_port (simulating ephemeral ports) only when user didn't specify it.
	HasExplicitSrcPort bool `json:"-"`

	// LayerDyn caches per-flow dynamic strategies parsed from the layers
	// array (D-FTP-3): ip.src/dst, tcp/udp src_port/dst_port, eth src/dst MAC,
	// ip.ttl — each either nil (static scalar or absent) or a StrategyConfig
	// resolved at spec.FlowIndex. Parsed once per task by mapToFlowSpec
	// (parseLayerDyn); read-only afterwards (shared across per-flow copies).
	LayerDyn *LayerDynValues `json:"-"`

	// HasLayerDynIP flags that the layers array writes ip.src/ip.dst as a
	// dynamic object (D-FTP-4: 同键二态，任一端是对象即 true). Set once per
	// task by mapToFlowSpec alongside LayerDyn. validateSpecBase skips the
	// static same-family gate when true — the per-flow resolved addresses
	// share one family by shape validation (mixed families are rejected at
	// create/update + task-start precheck), while the pre-resolution spec
	// still carries flat defaults that must not be family-checked.
	HasLayerDynIP bool `json:"-"`

	// FlowIndex is the zero-based flow sequence number written by the worker
	// loops (strategy worker.go and batch class loop) before Plan. Planners
	// that support per-flow dynamic fields (FTP sessions/transactions,
	// D-FTP-2) resolve them at this index; direct callers leave 0. Read-only
	// for planners — never write back from Plan.
	FlowIndex int `json:"-"`

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
	Megaco      *MegacoConfig      `json:"megaco,omitempty"`
	HL7         *HL7Config         `json:"hl7,omitempty"`
	MMSE        *MMSEConfig        `json:"mmse,omitempty"`
	NTP         *NTPConfig         `json:"ntp,omitempty"`
	OpenVPN     *OpenVPNConfig     `json:"openvpn,omitempty"`
	PostgreSQL  *PostgreSQLConfig  `json:"postgresql,omitempty"`
	POP3        *POP3Config        `json:"pop3,omitempty"`
	PPPoE       *PPPoEConfig       `json:"pppoe,omitempty"`
	PPTP        *PPTPConfig        `json:"pptp,omitempty"`
	RIP         *RIPConfig         `json:"rip,omitempty"`
	H323        *H323Config        `json:"h323,omitempty"`
	GRE         *GREConfig         `json:"gre,omitempty"`
	MPLS        *MPLSConfig        `json:"mpls,omitempty"`
	GTP         *GTPConfig         `json:"gtp,omitempty"`
	RDP         *RDPConfig         `json:"rdp,omitempty"`
	Radius      *RadiusConfig      `json:"radius,omitempty"`
	LDAP        *LDAPConfig        `json:"ldap,omitempty"`
	VNC         *VNCConfig         `json:"vnc,omitempty"`
	Redis       *RedisConfig       `json:"redis,omitempty"`
	Shadowsocks *ShadowsocksConfig `json:"shadowsocks,omitempty"`
	SMTP        *SMTPConfig        `json:"smtp,omitempty"`
	Socks       *SocksConfig       `json:"socks,omitempty"`
	MODBUS      *MODBUSConfig      `json:"modbus,omitempty"`
	RTMP        *RTMPConfig        `json:"rtmp,omitempty"`
	SNMP        *SNMPConfig        `json:"snmp,omitempty"`
	SSDP        *SSDPConfig        `json:"ssdp,omitempty"`
	SSH         *SSHConfig         `json:"ssh,omitempty"`
	Syslog      *SyslogConfig      `json:"syslog,omitempty"`
	Telnet      *TelnetConfig      `json:"telnet,omitempty"`
	TLS         *TLSConfig         `json:"tls,omitempty"`
	Vmess       *VmessConfig       `json:"vmess,omitempty"`
	WireGuard   *WireGuardConfig   `json:"wireguard,omitempty"`
	NGAP        *NGAPConfig        `json:"ngap,omitempty"`
	Xmpp        *XmppConfig        `json:"xmpp,omitempty"`
	JT808       *JT808Config       `json:"jt808,omitempty"`
	JT809       *JT809Config       `json:"jt809,omitempty"`
	JTT905      *JTT905Config      `json:"jtt905,omitempty"`
	DoIP        *DoIPConfig        `json:"doip,omitempty"`
	TFTP        *TFTPConfig        `json:"tftp,omitempty"`
	MQTT        *MQTTConfig        `json:"mqtt,omitempty"`
	ENIP        *ENIPConfig        `json:"enip,omitempty"`
	SRv6        *SRv6Config        `json:"srv6,omitempty"`
	SMB         *SMBConfig         `json:"smb,omitempty"`
	DNP3        *DNP3Config        `json:"dnp3,omitempty"`
	MCP         *MCPConfig         `json:"mcp,omitempty"`
	GBT32960    *GBT32960Config    `json:"gbt32960,omitempty"`

	// Routing protocols (P3 T5; igmp/ospf/pim are raw-IP [ip,<proto>], isis is
	// L2-only LLC [eth,isis]). Appended per flowspec_extension.md §2.3.
	IGMP *IGMPConfig `json:"igmp,omitempty"`
	OSPF *OSPFConfig `json:"ospf,omitempty"`
	PIM  *PIMConfig  `json:"pim,omitempty"`
	ISIS *ISISConfig `json:"isis,omitempty"`

	// Encapsulation terminal layers (B4; vxlan/geneve are UDP-terminal
	// [ip,udp,<proto>], nvgre is raw-IP [ip,nvgre] with self-built outer
	// IP + L2.GRE). See encapsulation.go.
	VXLAN  *VXLANConfig  `json:"vxlan,omitempty"`
	Geneve *GeneveConfig `json:"geneve,omitempty"`
	NVGRE  *NVGREConfig  `json:"nvgre,omitempty"`

	// Metadata is a generic extension map used by protocol packages whose
	// config types live outside core (avoids an import cycle). NFS, for
	// example, stores *nfs.NFSConfig under the key "nfs". Protocol
	// planners that own their config type directly (e.g. SMB via
	// FlowSpec.SMB) do not use this field. nil = no extension config.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MCPConfig holds MCP traffic configuration. MCP is a JSON-RPC 2.0
// application-layer protocol over stdio (line-delimited JSON) or HTTP+SSE /
// Streamable HTTP. Each flow is one TCP session: initialize -> operating
// exchanges -> shutdown. Multi-session uses multi-flow strategy (M
// independent 4-tuples). This config generates wire bytes only; it does NOT
// use the modelcontextprotocol/go-sdk (the SDK drives real sessions).
type MCPConfig struct {
	Transport          string              `json:"transport,omitempty"`           // "stdio"(default)/"http_sse"/"streamable"
	BaseURL            string              `json:"base_url,omitempty"`            // HTTP modes; empty="/mcp"
	SessionID          string              `json:"session_id,omitempty"`          // HTTP modes; Mcp-Session-Id header; empty=auto UUID
	ProtocolVersion    string              `json:"protocol_version,omitempty"`    // empty="2024-11-05"
	ClientInfo         MCPClientInfo       `json:"client_info,omitempty"`         // initialize params.clientInfo
	ServerInfo         MCPServerInfo       `json:"server_info,omitempty"`         // initialize result.serverInfo
	ClientCapabilities json.RawMessage     `json:"client_capabilities,omitempty"` // empty=default {} (no capabilities)
	ServerCapabilities json.RawMessage     `json:"server_capabilities,omitempty"` // empty=default {} (no capabilities)
	Requests           []MCPRequest        `json:"requests,omitempty"`            // client->server requests after initialize
	Responses          []MCPMessage        `json:"responses,omitempty"`           // server->client; empty=synthesize success
	Notifications      []MCPNotification   `json:"notifications,omitempty"`       // standalone notifications with Step position
	Auth               MCPAuth             `json:"auth,omitempty"`                // HTTP auth; empty=no auth header
	State              MCPState            `json:"state,omitempty"`               // long-task state machine
	Parts              []MCPPart           `json:"parts,omitempty"`               // multi-part prompts/sampling
	Metadata           map[string]any      `json:"metadata,omitempty"`            // _meta in requests/responses
	PushNotification   MCPPushNotification `json:"push_notification,omitempty"`   // tools/call callback URL
	IDCounter          int                 `json:"id_counter,omitempty"`          // first request id; 0=auto from 1
	Rounds             int                 `json:"rounds,omitempty"`              // repeat count; 0=1
	Shutdown           *bool               `json:"shutdown,omitempty"`            // nil=true (TCP FIN teardown)
	ContextID          string              `json:"context_id,omitempty"`          // _meta.contextId (call chain)
	ParentID           string              `json:"parent_id,omitempty"`           // notifications/progress parentId
}

// MCPClientInfo describes the MCP client.
type MCPClientInfo struct {
	Name    string `json:"name,omitempty"`    // default "trafficgen-client"
	Version string `json:"version,omitempty"` // default "1.0.0"
}

// MCPServerInfo describes the MCP server.
type MCPServerInfo struct {
	Name    string `json:"name,omitempty"`    // default "trafficgen-server"
	Version string `json:"version,omitempty"` // default "1.0.0"
}

// MCPRequest is one client->server JSON-RPC request.
type MCPRequest struct {
	ID     int            `json:"id"`               // 0=auto from IDCounter; non-zero=user explicit
	Method string         `json:"method"`           // "tools/list", "tools/call", ...
	Params map[string]any `json:"params,omitempty"` // nil=emit {} or omit
}

// MCPMessage is one server->client message (response or notification).
type MCPMessage struct {
	ID     int            `json:"id"`               // 0 for notifications
	Method string         `json:"method,omitempty"` // set for notifications
	Result map[string]any `json:"result,omitempty"` // success response
	Error  *MCPError      `json:"error,omitempty"`  // error response
	Params map[string]any `json:"params,omitempty"` // notifications
}

// MCPError is a JSON-RPC error object.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// MCPNotification is a standalone notification with stream position.
type MCPNotification struct {
	Step   int            `json:"step"`   // 0..len(Requests)
	Method string         `json:"method"` // "notifications/progress", ...
	Params map[string]any `json:"params,omitempty"`
}

// MCPAuth holds HTTP authentication options for MCP.
type MCPAuth struct {
	Schemes       []string `json:"schemes,omitempty"`        // ["Bearer","Basic","OAuth2"]
	Credentials   string   `json:"credentials,omitempty"`    // raw token / user:pass
	OAuth2Token   string   `json:"oauth2_token,omitempty"`   // placeholder
	OAuth2Refresh string   `json:"oauth2_refresh,omitempty"` // placeholder
}

// MCPState is the long-running tools/call state machine.
type MCPState struct {
	Initial string `json:"initial,omitempty"` // default "submitted"
	Final   string `json:"final,omitempty"`   // default "completed"
}

// MCPPart describes one role/content pair for prompts/sampling multi-part.
type MCPPart struct {
	Role    string     `json:"role"` // "user"/"assistant"
	Content MCPContent `json:"content"`
}

// MCPContent is one content block (text/image/audio/resource/resource_link).
type MCPContent struct {
	Type     string `json:"type"` // text/image/audio/resource/resource_link
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"` // base64 for image/audio
	MimeType string `json:"mimeType,omitempty"`
	URI      string `json:"uri,omitempty"` // resource/resource_link
	Name     string `json:"name,omitempty"`
}

// MCPPushNotification is the tools/call callback URL config.
type MCPPushNotification struct {
	URL               string `json:"url,omitempty"`
	VerificationToken string `json:"verification_token,omitempty"`
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

// IPv6Option is one IPv6 extension header option (RFC 8200 §4.2). Encoded as
// Type(1 octet) + Opt Data Len(1 octet, the value octet count) + Value.
// Type 0x00 (Pad1, no Len/Value) and 0x01 (PadN) are emitted by the builder
// for alignment; hop-by-hop options with unknown types are passed through
// as-is.
type IPv6Option struct {
	Type  uint8  `json:"type"`
	Value []byte `json:"value,omitempty"`
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

	// Retransmit enables the TCP retransmission state machine (T3.3)：
	// data segments and peer ACKs drive TCPRetransmissionStateMachine and
	// the final (simulated-lost) segment is re-emitted after the data
	// phase (dup PSH-ACK + recovery ACK). false = legacy stream exactly.
	Retransmit bool `json:"retransmit,omitempty"`
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

	// TransferEncoding governs the HTTP chunked transfer-encoding
	// (RFC 7230 §4.1). When set to "chunked", the planner frames the body
	// as a sequence of length-prefixed chunks:
	//
	//	<hex-size>\r\n<chunk-data>\r\n ... 0\r\n\r\n
	//
	// The chunk-size field is hexadecimal (§4.1: chunk-size = 1*HEXDIG).
	// ChunkSize controls how the body is split into chunks; 0 (default)
	// emits the entire body as a single data chunk. When chunked is active,
	// NO Content-Length header is emitted (§3.3.3: Transfer-Encoding takes
	// precedence over Content-Length), and the auto-emitted
	// "Transfer-Encoding: chunked" header is overridable via the user
	// RequestHeaders/ResponseHeaders (case-insensitive per §3.2).
	//
	// A non-"chunked" value (e.g. "identity") is passed through as a literal
	// header without framing, mirroring the ContentEncoding non-gzip
	// pass-through (caller responsibility).
	//
	// Chunked composes with gzip: the body is gzip-compressed first, then
	// the compressed bytes are chunk-framed (§4: Transfer-Encoding wraps the
	// message body, which may itself be content-encoded).
	RequestTransferEncoding  string `json:"request_transfer_encoding,omitempty"`
	ResponseTransferEncoding string `json:"response_transfer_encoding,omitempty"`
	ChunkSize                int    `json:"chunk_size,omitempty"`

	// Pipelined, when true, reorders the transaction loop so all N requests
	// are emitted before any response (HTTP pipelining, RFC 9112 §6.3.2).
	// Default (false) interleaves request->response per transaction. With
	// Transactions<=1, Pipelined is a no-op. The Connection header still
	// defaults to keep-alive (pipelining requires a persistent connection).
	Pipelined bool `json:"pipelined,omitempty"`

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

	// Transport selects the L4 carriage: "" or "udp" (default, RFC 1035
	// §4.2.1) or "tcp" (DNS over TCP, RFC 1035 §4.2.2 / RFC 7766). When
	// "tcp" the DNS message is prefixed with a 2-byte big-endian length
	// field and carried in a TCP segment (L4 protocol = tcp).
	Transport string `json:"transport,omitempty"`

	// RCode is the DNS response code (RFC 1035 §4.1.1, low 4 bits of the
	// flags). 0=NOERROR (default), 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN,
	// 4=NOTIMP, 5=REFUSED. Only meaningful when IsResponse is true. Values
	// >15 are rejected by Validate (the basic 4-bit rcode field tops out at
	// 15; extended rcodes require EDNS0 which is out of scope here).
	RCode uint8 `json:"rcode,omitempty"`

	// TTL overrides the default 300-second answer/authority TTL. Per-RR
	// TTL (DNSRR.TTL) takes precedence over this value.
	TTL uint32 `json:"ttl,omitempty"`

	// Questions carries multiple questions in one DNS message (rare but
	// valid, RFC 1035 §4.1.2 -- QDCOUNT may be >1). When set, it overrides
	// Domain/QueryType for the query; the response echoes the same list.
	Questions []DNSQuestion `json:"questions,omitempty"`

	// Answers carries multiple answer RRs in the response (RFC 1035
	// §4.1.2), enabling multi-RR responses (e.g. several A records) and
	// CNAME chains (CNAME followed by A). When set, it overrides the
	// single ResponseIP-derived RR.
	Answers []DNSRR `json:"answers,omitempty"`

	// Authority carries authority-section RRs (RFC 1035 §4.1.2), e.g. a
	// SOA record for negative caching on an NXDOMAIN response (RFC 1035
	// §6.2.5).
	Authority []DNSRR `json:"authority,omitempty"`
}

// DNSQuestion is a single DNS question: QNAME + QTYPE + QCLASS (RFC 1035
// §4.1.2). Class defaults to IN (1) when zero.
type DNSQuestion struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class,omitempty"`
}

// DNSRR is a single DNS resource record (RFC 1035 §3.2.1). Type selects
// which RDATA-carrying fields are read; the others are ignored. Class
// defaults to IN (1) and TTL to 300 (or DNSConfig.TTL) when zero.
//
// RDATA field mapping by Type:
//
//	A(1)/AAAA(28)  -> IP
//	CNAME(5)/NS(2)/PTR(12) -> Target (domain name)
//	MX(15)         -> Preference + Target
//	TXT(16)        -> Text (single length-prefixed string)
//	SOA(6)         -> MName, RName, Serial, Refresh, Retry, Expire, Minimum
//	SRV(33)        -> Priority, Weight, Port, Target (RFC 2782)
//	NAPTR(35)      -> Order, Preference, Flags, Service, Regexp, Target (RFC 3401)
//	DS(43)         -> KeyTag, Algorithm, DigestType, Digest(hex) (RFC 4034 §5)
//	DNSKEY(48)     -> KeyFlags, Protocol, Algorithm, PublicKey(base64) (RFC 4034 §2)
type DNSRR struct {
	Name  string `json:"name,omitempty"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`

	// A/AAAA record address.
	IP string `json:"ip,omitempty"`
	// CNAME/NS/PTR/SRV/NAPTR target domain.
	Target string `json:"target,omitempty"`
	// MX preference (RFC 1035 §3.3.9).
	Preference uint16 `json:"preference,omitempty"`
	// TXT text (single character-string; truncated to 255 bytes).
	Text string `json:"text,omitempty"`

	// SOA fields (RFC 1035 §3.3.13).
	MName   string `json:"mname,omitempty"`
	RName   string `json:"rname,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minimum uint32 `json:"minimum,omitempty"`

	// SRV fields (RFC 2782).
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	Port     uint16 `json:"port,omitempty"`

	// NAPTR fields (RFC 3401 §4.1). Flags/Service/Regexp are
	// length-prefixed character-strings; Target is the Replacement domain.
	Order   uint16 `json:"order,omitempty"`
	Flags   string `json:"flags,omitempty"`
	Service string `json:"service,omitempty"`
	Regexp  string `json:"regexp,omitempty"`

	// DS fields (RFC 4034 §5). Digest is hex-encoded.
	KeyTag     uint16 `json:"key_tag,omitempty"`
	Algorithm  uint8  `json:"algorithm,omitempty"`
	DigestType uint8  `json:"digest_type,omitempty"`
	Digest     string `json:"digest,omitempty"`

	// DNSKEY fields (RFC 4034 §2). PublicKey is base64-encoded.
	KeyFlags  uint16 `json:"key_flags,omitempty"`
	Protocol  uint8  `json:"protocol,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
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

// ARPConfig for ARP protocol（D-ARP-1 裁定2：5 键；sender/target 为 RFC 826
// 报文角色地址，缺省在生成器侧补）。
type ARPConfig struct {
	Operation uint16 `json:"operation"` // 1=Request, 2=Reply
	SenderMAC string `json:"sender_mac"`
	SenderIP  string `json:"sender_ip"`
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
	// Sessions 非空时启用多会话静态结构（D-FTP-1 阶段一）：每会话一条独立
	// TCP 连接（独立四元组/序号/握手/teardown），会话内按事务顺序执行；数据流
	// 挂在触发它的事务下（{parent}:sub-{tx-idx}）。空 = 老形状（顶层
	// Banner/Commands/DataChannel 单控制流，行为不变）。
	Sessions []FTPSession `json:"sessions,omitempty"`
	// MSS is governed by TCPConfig.MSS. FTP runs over TCP, so the planner
	// reads spec.TCP.MSS for segmentation of long FTP payloads.
}

// FTPSession is one control TCP connection in the multi-session shape
// (D-FTP-1). SrcPort 0 = inherit spec.SrcPort. Banner is this session's own
// greeting (empty = skip). Transactions run in order on this connection.
//
// Dynamic variants (D-FTP-2): SrcPortDyn/BannerDyn accept a StrategyConfig
// (fixed/inc/rand/list/pattern, or fixed for scalar shorthand). Resolution
// order: static non-zero > dynamic value > inherit/skip. Dyn fields are
// READ-ONLY after parse — the worker copies spec per flow and planSessions
// resolves them at spec.FlowIndex without writing back.
type FTPSession struct {
	SrcPort      uint16           `json:"src_port,omitempty"`
	Banner       string           `json:"banner,omitempty"`
	Transactions []FTPTransaction `json:"transactions,omitempty"`

	SrcPortDyn *StrategyConfig `json:"-"`
	BannerDyn  *StrategyConfig `json:"-"`
}

// FTPTransaction is one FTP business operation on the control connection
// (RETR file, LIST directory, CWD, REST+RETR, ...): 1..M command/response
// pairs plus at most one data channel that the flagged command triggers
// ({parent}:sub-{tx-idx}). Commands may carry dynamic cmd/response variants
// (D-FTP-2) resolved per flow index; see FTPCommand.
type FTPTransaction struct {
	Commands    []FTPCommand    `json:"commands,omitempty"`
	DataChannel *FTPDataChannel `json:"data_channel,omitempty"`
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

	// Dynamic variants (D-FTP-2): resolved per flow index when the static
	// field is empty. READ-ONLY after parse (shared pointers across the
	// worker's per-flow spec copies).
	CmdDyn      *StrategyConfig `json:"-"`
	ResponseDyn *StrategyConfig `json:"-"`
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

	// AbortAfterBytes, when > 0, truncates the data-channel payload to the
	// first N bytes before emitting the sub-flow. This models ABOR (RFC 959
	// §4.1.4): a transfer interrupted mid-stream sends only a prefix of the
	// file, then the data connection tears down. The control-channel dialog
	// carries the ABOR command and 426/226 responses separately. 0 (default)
	// = no truncation, full payload sent.
	AbortAfterBytes int `json:"abort_after_bytes,omitempty"`

	// FileSource, when set, supplies the data-channel file body bytes via
	// PayloadCache.GetOrLoad(src) instead of inline Payload / PayloadB64.
	// nil = use inline payload fields. Takes precedence over
	// FlowSpec.FileSource for FTP data-channel bytes.
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`

	// PayloadDyn (D-FTP-2): dynamic payload variant, resolved per flow index
	// when FileSource is unset. Priority: FileSource > PayloadDyn > Payload.
	// READ-ONLY after parse.
	PayloadDyn *StrategyConfig `json:"-"`
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
	// Sessions carries the multi-session shape (D-SIP-2 WP-A): each entry
	// is one independent TCP signaling connection with its own Call-ID,
	// four-tuple and lifecycle (CORE_MEMORY 3.1-3.3). Mutually exclusive
	// with Dialog (the single-dialog shorthand) — enforced at create time
	// (schema) and re-checked by the planner as a task-time backstop.
	Sessions []SIPSession `json:"sessions,omitempty"`
	// NAT carries the RFC 3581 NAT traversal synthesis switches
	// (D-SIP-2 WP-C): rport=true fills rport=<actual srcport>;
	// received=<srcIP> on outbound requests at emit time. nil/false =
	// verbatim pass-through (zero drift). Applies to dialog and sessions
	// paths alike; responses replay user bytes untouched (RFC 3581 fills
	// happen on the request side only in this synthesizer's contract).
	NAT *SIPNAT `json:"nat,omitempty"`
	// Medias carries the multi-stream media shape (D-SIP-2 WP-B): each
	// entry is one RTP stream (direction up/down); at the EmitMedia
	// message the entries' frames are emitted round-robin (up/down
	// alternating — real RTP is bidirectional per RFC 3550). Mutually
	// exclusive with Media. Interleave schedules the remaining dialog
	// messages into the media stream ("N frames between messages",
	// deterministic even split per CORE_MEMORY 3.12).
	Medias     []SIPMedia `json:"medias,omitempty"`
	Interleave bool       `json:"interleave,omitempty"`
	// MSS is governed by TCPConfig.MSS. SIP runs over TCP (or UDP), so the
	// planner reads spec.TCP.MSS for segmentation of long SIP messages.
}

// SIPSession is one entry of SIPConfig.Sessions (D-SIP-2 WP-A, the
// FTPSession precedent): per-session ports (0 = inherit the chain
// spec ports), optional Call-ID (empty = planner derives
// "{flowIdx}-{sessIdx}@{srcIP}", deterministic per CORE_MEMORY 12.4),
// the session's dialog messages and optional RTP media. SrcPortDyn /
// DstPortDyn / CallIDDyn carry the dynamic-object form of the same
// fields (same-key two-state, resolved at spec.FlowIndex).
type SIPSession struct {
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	CallID  string `json:"call_id,omitempty"`

	Dialog []SIPMessage `json:"dialog,omitempty"`
	Media  *SIPMedia    `json:"media,omitempty"`
	// D-SIP-2 WP-B: per-session multi-stream media + interleave (same
	// semantics as the SIPConfig-level fields).
	Medias     []SIPMedia `json:"medias,omitempty"`
	Interleave bool       `json:"interleave,omitempty"`

	SrcPortDyn *StrategyConfig `json:"-"`
	DstPortDyn *StrategyConfig `json:"-"`
	CallIDDyn  *StrategyConfig `json:"-"`
}

// SIPNAT is the RFC 3581 §4 NAT synthesis switch set (D-SIP-2 WP-C).
// received is bound to rport (the RFC fills both together); exposing one
// switch keeps the contract honest.
type SIPNAT struct {
	RPort bool `json:"rport,omitempty"`
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

	// D-SIP-2 WP-B: dynamic-object forms of the media ports (same-key
	// two-state, resolved at spec.FlowIndex). json:"-" — parsed from the
	// raw map by ParseSIPMedias, never round-tripped.
	SrcPortDyn *StrategyConfig `json:"-"`
	DstPortDyn *StrategyConfig `json:"-"`
}

// RTSPConfig for the RTSP protocol. RTSP (RFC 2326) is a session-level
// control protocol: a single TCP connection on port 554 carries a
// sequence of control messages (DESCRIBE → 200 OK → SETUP → 200 OK →
// PLAY → 200 OK → TEARDOWN → 200 OK); media data flows over a separate
// UDP sub-flow as RTP (RFC 3550) on ports negotiated via the Transport
// header. The planner emits a TCP handshake, each RTSPMessage in Dialog
// (as PSH-ACK payload), then a TCP teardown — all within one flow.
//
// Header completion (user > auto > none, see completeRTSPHeaders):
//   - CSeq is mandatory in every message (RFC 2326 §12.17). Auto-assigned
//     incrementing; a response echoes the CSeq of the request it answers
//     (reference pcaps: DESCRIBE CSeq:1 → 200 CSeq:1).
//   - Session is generated by the server in the first SETUP response and
//     echoed by every later request (§12.37). Reference: 15 hex digits.
//   - SETUP Transport is derived from Media ports (§12.39):
//     request client_port=<DstPort>-<DstPort+1>, response adds
//     server_port=<SrcPort>-<SrcPort+1>.
//   - Content-Length (and Content-Type: application/sdp) auto-appended
//     when Body is non-empty.
//   - PLAY response RTP-Info (§12.33) auto-generated with the same
//     seq/ssrc/rtptime as the RTP frames emitted after it.
//
// Media: when non-nil, the planner emits a UDP sub-flow carrying RTP
// frames after each message flagged EmitMedia (typically the PLAY
// response — the server announces the stream in RTP-Info, then the
// stream flows). The sub-flow shares the parent's GroupID so it routes
// to the same PacketWorker — wire order = emit order, so RTP frames
// land between PLAY and TEARDOWN in the pcap, exactly where real media
// would appear.
type RTSPConfig struct {
	Dialog []RTSPMessage `json:"dialog"`
	Media  *RTSPMedia    `json:"media,omitempty"`
	// MSS is governed by TCPConfig.MSS. RTSP runs over TCP.
}

// RTSPMessage is a single message within an RTSP dialog. A request sets
// Method+URI (e.g. Method="DESCRIBE", URI="rtsp://host/media"); a
// response sets StatusCode+StatusText (e.g. 200, "OK"). Direction "up"
// = client→server (request), "down" = server→client (response).
type RTSPMessage struct {
	Method     string   `json:"method,omitempty"`      // e.g. "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"
	URI        string   `json:"uri,omitempty"`         // e.g. "rtsp://host/media"; empty -> "rtsp://<dstIP>/media" (IPv6 bracketed)
	StatusCode int      `json:"status_code,omitempty"` // e.g. 200; 0 for requests
	StatusText string   `json:"status_text,omitempty"` // e.g. "OK"; empty for requests
	Headers    []string `json:"headers,omitempty"`     // each "Name: Value"; CSeq/Session/Transport auto-added when missing
	Body       string   `json:"body,omitempty"`        // e.g. SDP content; empty = no body
	Direction  string   `json:"direction,omitempty"`   // "up" or "down"; empty -> planner infers from Method/StatusCode

	// EmitMedia, when true on a message, triggers the planner to emit the
	// RTP media sub-flow immediately AFTER this message. For byte-fidelity
	// with real servers (PLAY → 200 OK with RTP-Info → RTP frames), set
	// EmitMedia on the PLAY *response* — the RTP-Info header is then
	// auto-generated with the exact seq/ssrc/rtptime of the frames that
	// follow. When set on a request, the frames are emitted right after
	// the request and the following response gets no auto RTP-Info (the
	// stream it would describe has already gone out).
	EmitMedia bool `json:"emit_media,omitempty"`
}

// RTSPMedia describes the RTP media plane for an RTSP session. RTP (RFC
// 3550) runs over UDP on a separate 4-tuple from the RTSP signaling;
// the ports are negotiated via the SETUP Transport header (the SDP m=
// line carries port 0 — see reference pcap proto_rtsp.pcap). The
// planner emits N RTP frames as a UDP sub-flow, each frame = 12-byte
// RTP header + FrameSize bytes of payload.
//
// SrcPort/DstPort: the server-side RTP send port (server_port) and the
// client-side RTP receive port (client_port). 0 means 5004 (the default
// RTP port). When Media is non-nil these ports also drive the
// auto-generated SETUP Transport headers (client_port=DstPort-DstPort+1,
// server_port=SrcPort-SrcPort+1).
//
// Frames: number of RTP packets to emit. Each is one UDP datagram. At
// 25fps video, Frames=25 models 1 second of one-way media.
//
// PayloadType: RTP payload type. RTSP sessions typically negotiate
// dynamic types 96-127 via the SDP a=rtpmap line (reference: 96/97);
// static types 0/8/9 are valid too. 0 is a valid PT (PCMU) and is
// emitted as-is — no defaulting.
//
// FrameSize: bytes of media payload per RTP packet (G.711 20ms = 160,
// video frames typically 1000-1400).
//
// Direction: which way RTP frames flow. RTSP servers stream media to
// the client, so the default is "down" (server→client: src=spec.DstIP,
// dst=spec.SrcIP). "up" models reverse flows (RTSP push/recording).
type RTSPMedia struct {
	SrcPort     uint16 `json:"src_port,omitempty"`     // 0 = 5004 (server-side RTP send port)
	DstPort     uint16 `json:"dst_port,omitempty"`     // 0 = 5004 (client-side RTP receive port)
	Frames      int    `json:"frames,omitempty"`       // number of RTP packets; 0 = 1
	PayloadType uint8  `json:"payload_type,omitempty"` // RTP payload type; 0 = PCMU (valid, no defaulting)
	SampleRate  uint32 `json:"sample_rate,omitempty"`  // RTP clock rate Hz (8000 audio, 90000 video); informational
	FrameSize   int    `json:"frame_size,omitempty"`   // 0 = 160 (G.711 20ms)
	Direction   string `json:"direction,omitempty"`    // "down" (default, server→client) or "up"

	// FileSource, when set, supplies the RTP frame payload bytes via
	// PayloadCache.GetOrLoad(src) instead of synthesizing zero-filled
	// payload. nil = synthesize per FrameSize.
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
	// FragmentSize, when non-zero, splits each DATA chunk's user payload
	// into multiple DATA chunks of at most this many user-data bytes.
	// Per RFC 4960 §3.3.1, the first fragment carries the B flag
	// (beginning), the last carries E (end), and middle fragments carry
	// neither; all fragments share the same SID/SSN/PPID and have
	// incrementing TSNs. 0 (default) = no fragmentation (each chunk is
	// one B+E DATA chunk), preserving backward compatibility. A
	// FragmentSize below MinFragmentSize is rejected at Validate time.
	FragmentSize int `json:"fragment_size,omitempty"`
}

// SCTPMinFragmentSize is the minimum legal FragmentSize. A fragment must
// carry at least MinFragmentSize bytes of user data; smaller values would
// split payloads into an absurd number of tiny chunks, which is almost
// always a misconfiguration. Set to a practical floor above 1 to catch
// typos like fragment_size=1. Enforced in Planner.Validate.
const SCTPMinFragmentSize = 16

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

	// PPPoE, when non-nil, enables PPP-over-Ethernet encapsulation
	// (RFC 2516). The builder inserts a 6-byte PPPoE header between the
	// Ethernet header (with optional VLAN) and the PPP frame, and forces
	// the EtherType to 0x8863 (Discovery) or 0x8864 (Session Data) based
	// on PPPoE.Code. When PPPoE.PPPProtocol is 0x0021 (IPv4), the builder
	// still writes the L3/L4 headers from L3Config/L4Config after the
	// 2-byte PPP Protocol field; for LCP/IPCP/PAP/CHAP the PPP control
	// message is carried in Payload with no L3/L4. nil = PPPoE disabled
	// (the historical behavior — every existing planner leaves this nil).
	PPPoE *PPPoEConfig `json:"pppoe,omitempty"`

	// GRE, when non-nil, enables GRE encapsulation (RFC 2784/2890). The
	// builder inserts the GRE header (4-byte base + 4 bytes per C/R/K/S
	// option) between the outer IP header (which must carry protocol 47)
	// and the inner payload, and counts it in the outer IP total-length
	// field. The inner packet (IPv4/IPv6 + TCP/UDP, or ARP) is carried
	// verbatim in Payload with its checksums already computed — the
	// builder never interprets it, so L4Config must stay empty. nil = GRE
	// disabled (the historical behavior — every existing planner leaves
	// this nil). Mutually exclusive with PPPoE (both are encapsulations
	// between the Ethernet and IP layers).
	GRE *GREConfig `json:"gre,omitempty"`

	// MPLS, when non-nil, enables MPLS label-stack encapsulation
	// (RFC 3031/3032). The builder inserts one 4-byte label entry per
	// stack level between the Ethernet header (with optional VLAN) and the
	// inner L3 header, and forces the EtherType to 0x8847 (unicast, RFC
	// 3032 §3.10) or 0x8848 (multicast, MPLSConfig.Multicast) — ignoring
	// L2Config.EtherType, which still selects the INNER L3 layout
	// (0x0800 IPv4 / 0x86DD IPv6; 0 or 0x8847/0x8848 = IPv4). The inner
	// L3/L4 are written normally from L3Config/L4Config after the label
	// stack. nil = MPLS disabled (the historical behavior — every existing
	// planner leaves this nil). Mutually exclusive with GRE and PPPoE
	// (all three are encapsulations between the Ethernet and IP layers;
	// their lengths would interleave ambiguously).
	MPLS *MPLSConfig `json:"mpls,omitempty"`

	// Pad controls padding to MinEthernetFrame (60 bytes, excluding FCS).
	// nil = pad (default ON — short frames like ARP or small ICMP are padded
	// so real NICs don't reject them); *true = pad; *false = don't pad
	// (emit at natural size, useful for testing runt-frame handling).
	// Propagated from FlowSpec.PadMinFrame by the worker; planners leave
	// this nil so the builder applies its default.
	Pad *bool `json:"pad,omitempty"`

	// LLC, when non-nil, encodes the frame as IEEE 802.3 with an 802.2 LLC
	// header instead of an EtherType (the ISO 10589 IS-IS LLC carrier). The
	// builder writes DstMAC(6)+SrcMAC(6)+Length(2)+DSAP(1)+SSAP(1)+Control(1)
	// before the PDU (in Payload) — the Length field is 0 (the builder fills
	// the actual PDU length at build time, replacing the EtherType slot). nil
	// = EtherType carrier. Mutually exclusive with PPPoE/GRE/MPLS.
	LLC *LLCConfig `json:"llc,omitempty"`
}

// LLCConfig selects the IEEE 802.3 + 802.2 LLC carrier used by the IS-IS LLC
// wire profile (ISO 10589). The builder replaces the EtherType slot (bytes
// 12-13) with the 802.3 Length field = length of the LLC+PDU bytes that follow,
// then writes DSAP/SSAP/Control. The PDU itself is the PacketConfig Payload.
type LLCConfig struct {
	DSAP    uint8 `json:"dsap,omitempty"` // source/target service access point; ISO 10589 uses 0xFE
	SSAP    uint8 `json:"ssap,omitempty"`
	Control uint8 `json:"control,omitempty"` // 0x03 = unnumbered info; IS-IS uses 0x03
}

// PPPoEConfig configures PPP-over-Ethernet Session Data or Discovery frames
// per RFC 2516. It is attached to L2Config.PPPoE so the builder can emit the
// 6-byte PPPoE header in the same pass as the Ethernet header.
type PPPoEConfig struct {
	// Code is the PPPoE code field (RFC 2516 §5). 0x00 = Session Data,
	// 0x09 = PADI, 0x07 = PADO, 0x19 = PADR, 0x65 = PADS, 0xa7 = PADT.
	// The builder selects the EtherType (0x8864 Session vs 0x8863
	// Discovery) from this field.
	Code uint8 `json:"code"` // 0 = Session Data (default)

	// SessionID is the PPPoE Session ID (RFC 2516 §4). Discovery frames
	// (PADI/PADR) set it to 0x0000; PADS assigns the value that subsequent
	// Session Data frames must echo back to keep the session associated.
	SessionID uint16 `json:"session_id"`

	// PPPProtocol is the 2-byte PPP Protocol field (RFC 1661 §5) carried
	// immediately after the PPPoE header in Session Data frames. 0x0021 =
	// IPv4 (the L3/L4 from L3Config/L4Config follows); 0xc021 = LCP,
	// 0x8021 = IPCP, 0xc023 = PAP, 0xc223 = CHAP (the PPP control message
	// is in Payload with no L3/L4). 0 = IPv4 when Code=Session Data.
	PPPProtocol uint16 `json:"ppp_protocol"`

	// PayloadLength overrides the PPPoE Payload_Length field. When 0, the
	// builder computes it as len(PPP Protocol field) + len(Payload) for
	// Session Data, or len(Payload) for Discovery TLV tags. The field
	// MUST equal the bytes following the PPPoE header (excluding the
	// Ethernet padding), otherwise the receiver mis-frames the stream.
	PayloadLength uint16 `json:"payload_length,omitempty"`

	// DiscoveryTags is the list of PPPoE Tag-Type/Tag-Length/Tag-Value
	// tuples carried in Discovery frames (RFC 2516 §5.1-5.4): Service-Name
	// (0x0101), AC-Name (0x0102), Host-Uniq (0x0103), AC-Cookie (0x0104),
	// Relay-Session-Id (0x0110), etc. Ignored for Session Data frames.
	DiscoveryTags []PPPoETag `json:"discovery_tags,omitempty"`

	// PADT, when true, emits an RFC 2516 §5.6 Active Discovery
	// Terminate frame at session teardown. nil defaults to true
	// (full RFC lifecycle); explicit false skips PADT.
	PADT *bool `json:"padt,omitempty"`

	// Sessions carries the multi-session shape (D-PPPOE-1 P2): each
	// entry runs an independent Discovery→LCP→Auth→Data→PADT lifecycle
	// with its own SessionID. Mutually exclusive with top-level session
	// behavior fields.
	Sessions []PPPoESession `json:"sessions,omitempty"`

	// --- Session-level fields (driven by the internal/protocol/pppoe
	// planner; ignored by the builder, which only reads the wire-level
	// fields above) ---

	// SkipDiscovery, when true, skips the PADI/PADO/PADR/PADS exchange
	// (RFC 2516 §5.1-5.4) and starts directly at the LCP session phase
	// with SessionID. false (default) = full Discovery before LCP.
	SkipDiscovery bool `json:"skip_discovery,omitempty"`

	// ACName is the AC-Name tag (0x0102) the planner puts in PADO.
	// Empty = "trafficgen".
	ACName string `json:"ac_name,omitempty"`

	// ServiceName is the Service-Name tag (0x0101) carried in PADI/PADR
	// and echoed by PADO/PADS. An empty value emits a zero-length
	// Service-Name tag = "any service" (RFC 2516 §5.2).
	ServiceName string `json:"service_name,omitempty"`

	// Cookie is the AC-Cookie tag (0x0104) value. PADO carries it; PADR
	// echoes it verbatim (RFC 2516 §5.4). nil/empty = no cookie tag
	// emitted.
	Cookie []byte `json:"cookie,omitempty"`

	// MRU is the LCP Maximum-Receive-Unit option (RFC 1661 §6.1) in the
	// Configure-Request. 0 = 1492 (the PPPoE payload ceiling per RFC 2516
	// §7: 1500 - 6-byte PPPoE header - 2-byte PPP Protocol field).
	MRU uint16 `json:"mru,omitempty"`

	// MagicNumber is the LCP Magic-Number option (RFC 1661 §6.13) value.
	// 0 = random 4-byte value (RFC 1661: the Magic-Number "MUST be chosen
	// randomly"); set it explicitly for deterministic tests.
	MagicNumber uint32 `json:"magic_number,omitempty"`

	// Auth selects the PPP authentication phase after LCP (RFC 1661 §8):
	// ""/ "none" (default), "pap" (RFC 1334), or "chap" (RFC 1994). PAP
	// emits Authenticate-Request/Ack; CHAP emits Challenge/Response/
	// Success. The selected protocol also appears in the LCP
	// Auth-Protocol option.
	Auth string `json:"auth,omitempty"`

	// Username / Password are the PAP peer ID / CHAP name (and the
	// PAP password). Empty = "trafficgen". The planner synthesizes the
	// CHAP response value (echo of the challenge) — trafficgen does not
	// compute real MD5 digests.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// DataFrames is the number of inner-IPv4 data frames emitted after
	// the session phase (PPP Protocol 0x0021). 0 = 1.
	DataFrames int `json:"data_frames,omitempty"`

	// DataPayload is the payload bytes for the inner IPv4 data packets.
	// nil = spec.Payload.
	DataPayload []byte `json:"data_payload,omitempty"`

	// InnerProto is the inner IP protocol for data frames: 6=TCP, 17=UDP.
	// 0 = UDP (or TCP when spec.TCP is set).
	InnerProto uint8 `json:"inner_proto,omitempty"`

	// DataDirection is the direction of the data frames: "up" (default,
	// client→server) or "down" (server→client, swaps MACs and inner IPs).
	DataDirection string `json:"data_direction,omitempty"`
}

// PPPoETag is a single PPPoE Discovery TLV (RFC 2516 §5.1). Tag-Type (2
// bytes) + Tag-Length (2 bytes, value length only, NOT counting the 4-byte
// TLV header) + Tag-Value. Tag-Length=0 with a non-empty value is invalid;
// Tag-Length>0 with an empty value emits a value-less tag (valid for
// Service-Name requests per RFC 2516 §5.2).
type PPPoETag struct {
	Type  uint16 `json:"type"`
	Value []byte `json:"value,omitempty"`
}

// PPPoE tag type values (RFC 2516 §5.1-5.4, §5.6).
const (
	PPPoETagEndOfList      uint16 = 0x0000
	PPPoETagServiceName    uint16 = 0x0101
	PPPoETagACName         uint16 = 0x0102
	PPPoETagHostUniq       uint16 = 0x0103
	PPPoETagACCookie       uint16 = 0x0104
	PPPoETagVendorSpecific uint16 = 0x0105
	PPPoETagRelaySessionID uint16 = 0x0110
	PPPoETagServiceNameErr uint16 = 0x0201
	PPPoETagACSystemErr    uint16 = 0x0202
	PPPoETagGenericErr     uint16 = 0x0203
)

// GREConfig configures GRE (Generic Routing Encapsulation, RFC 2784/2890)
// tunneling. It is attached to L2Config.GRE so the builder can emit the GRE
// header between the outer IP header and the inner payload. nil = GRE
// disabled.
//
// The builder (outer-IP + GRE + payload layout) writes the outer IP header
// with protocol 47 (IPPROTO_GRE), then the GRE header, then copies the inner
// packet verbatim from PacketConfig.Payload — the inner packet (IPv4/IPv6 +
// TCP/UDP/ICMP with correct checksums, or a 28-byte ARP message) is
// assembled by the internal/protocol/gre planner. L4Config must stay empty
// for GRE frames (the builder rejects it) so writeL4 is never called.
type GREConfig struct {
	// ProtocolType is the inner protocol EtherType carried in the GRE
	// header (RFC 2784 §2): 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6.
	// 0 = auto: the planner resolves it per packet (0x0806 for
	// ARP-over-GRE, 0x86DD for IPv6-over-GRE, 0x0800 otherwise); the
	// builder defaults 0 to 0x0800.
	ProtocolType uint16 `json:"protocol_type,omitempty"`

	// Checksum, when true, sets the C bit and emits the Checksum(2) +
	// Reserved(2) option field (RFC 2784 §2). The checksum is computed per
	// RFC 2784 §3.1 over the GRE header (Checksum field zeroed) plus the
	// payload, padded with zero octets to a 4-byte boundary; a computed
	// 0x0000 is transmitted as 0xFFFF.
	Checksum bool `json:"checksum,omitempty"`

	// KeyPresent / Key: RFC 2890 Key option (4 bytes), selected by the K
	// bit. The Key identifies the GRE tunnel — parallel tunnels use
	// distinct Keys.
	KeyPresent bool   `json:"key_present,omitempty"`
	Key        uint32 `json:"key,omitempty"`

	// SequencePresent / Sequence: RFC 2890 Sequence Number option (4
	// bytes), selected by the S bit. The planner increments the value per
	// emitted frame.
	SequencePresent bool   `json:"sequence_present,omitempty"`
	Sequence        uint32 `json:"sequence,omitempty"`

	// RoutingPresent / Routing: RFC 2784 §2 Routing option, selected by
	// the R bit. The builder emits a 2-byte Routing Length (counting the
	// 2-byte header itself + the routing data) followed by the routing
	// bytes. Routing must be at least 2 bytes and a multiple of 2 bytes —
	// anything else is rejected by the builder rather than emitting a
	// corrupt header.
	RoutingPresent bool   `json:"routing_present,omitempty"`
	Routing        []byte `json:"routing,omitempty"`

	// --- PPTP mode (RFC 2637 §4.1 enhanced GRE) ---
	//
	// PPTP, when true, switches the GRE header to the PPTP-enhanced
	// variant (RFC 2637 §4.1): the flags word becomes C=0 R=0 K=1 S=1
	// s=0 Recur=0 A=(AckPresent) Flags=0 Ver=1 (0x3081 with ack), the
	// Protocol Type is forced to 0x880B (PPP), and the Key field is
	// redefined as Payload Length (high 16 bits, filled after the payload
	// is in place) + Call ID (low 16 bits). Sequence Number and
	// Acknowledgment Number are 32-bit fields. The builder rejects the
	// standard-mode options (Checksum/RoutingPresent/KeyPresent/
	// SequencePresent) in PPTP mode — the K/S flags are managed by the
	// mode itself.
	PPTP bool `json:"pptp,omitempty"`

	// CallID is the 16-bit Call ID carried in the Key field's low half
	// (RFC 2637 §1.3.2: the peer's Call ID, used for mux/demux). The
	// planner sets it per frame.
	CallID uint16 `json:"pptp_call_id,omitempty"`

	// AckPresent selects the A bit (0x0080) and appends the 32-bit
	// Acknowledgment Number field (RFC 2637 §4.1). false yields a 12-byte
	// header (Key+Sequence only). Default true (16-byte header).
	AckPresent bool `json:"pptp_ack_present,omitempty"`

	// Ack is the 32-bit Acknowledgment Number (RFC 2637 §4.2: the highest
	// sequence number received from the peer). The planner sets it per
	// frame; ignored when AckPresent is false.
	Ack uint32 `json:"pptp_ack,omitempty"`

	// --- Tunnel-level fields (driven by the internal/protocol/gre
	// planner; ignored by the builder, which only reads the wire-level
	// fields above) ---

	// InnerSrcIP / InnerDstIP are the inner packet's addresses. Empty =
	// spec.SrcIP / spec.DstIP. In IP modes the inner packet's IP header
	// uses them; in ARP mode they must stay empty (the ARP addresses come
	// from the flow's MAC/IP fields, matching the ARP planner).
	InnerSrcIP string `json:"inner_src_ip,omitempty"`
	InnerDstIP string `json:"inner_dst_ip,omitempty"`

	// InnerProto is the inner L4 protocol: 6=TCP, 17=UDP, 1=ICMP (IPv4
	// mode), 58=ICMPv6 (IPv6 mode). 0 = UDP, or TCP when spec.TCP is set.
	InnerProto uint8 `json:"inner_proto,omitempty"`

	// InnerTTL is the inner IP TTL (IPv4) / hop limit (IPv6). 0 = 64.
	InnerTTL uint8 `json:"inner_ttl,omitempty"`

	// InnerIPID is the inner IPv4 Identification of the first frame (0 =
	// 0; the planner increments it per frame). IPv6 has no IPID — ignored
	// in IPv6 mode.
	InnerIPID uint16 `json:"inner_ipid,omitempty"`

	// InnerPayload is the inner L4 payload. nil = spec.Payload.
	InnerPayload []byte `json:"inner_payload,omitempty"`

	// TCPOptions are the inner TCP options (MSS, Window Scale,
	// SACK-Permitted, Timestamp, ...), encoded after the 20-byte inner TCP
	// header. Only used when the inner protocol is TCP. The flow-level
	// TCPConfig carries Seq/Ack/Flags/WindowSize; the options are
	// tunnel-scoped here (no shared JSON path sets them elsewhere).
	TCPOptions []TCPOption `json:"tcp_options,omitempty"`

	// Frames is the number of inner packets emitted (each gets a distinct
	// inner IPID and GRE sequence). 0 = 1.
	Frames int `json:"frames,omitempty"`

	// Direction is the flow direction: "up" (default) or "down" (swaps
	// outer MACs/IPs and inner addresses).
	Direction string `json:"direction,omitempty"`
}

// MPLSConfig configures MPLS (MultiProtocol Label Switching, RFC 3031/3032)
// label-stack encapsulation. It is attached to L2Config.MPLS so the builder
// can emit the label stack between the Ethernet header (with optional VLAN)
// and the inner L3 header. nil = MPLS disabled.
//
// The builder writes each MPLSLabel as a 4-byte network-order entry (RFC
// 3032 §3.1): Label(20 bits) | TC(3 bits) | S(1 bit) | TTL(8 bits), top of
// stack first. The S bit is auto-corrected: the LAST entry is always written
// with S=1 (bottom of stack, RFC 3032 §2.1: "the stack is one or more
// entries" and the bottom entry carries S=1), so a user who leaves the
// bottom entry's S unset (false) still gets a valid stack; an explicit S=true
// on a NON-bottom entry is a clear contradiction and is rejected by the
// builder. A TTL of 0 is written as 64 (matching the IP TTL default).
//
// The inner L3 is the flow's own packet — L3Config/L4Config select the
// inner IPv4/IPv6 header and TCP/UDP (or ICMP/ICMPv6 message in Payload)
// written right after the label stack. The inner L3 header is written with
// no MPLS awareness: MPLS is a shim between L2 and L3.
type MPLSConfig struct {
	// Labels is the label stack in transmission order (RFC 3032 §2.1):
	// entry 0 = top of stack (the label an ingress LSR pushes first),
	// last entry = bottom of stack (S bit = 1). At least one entry is
	// required — an empty stack is rejected by the builder rather than
	// emitting a bare 0x8847 EtherType with no labels.
	Labels []MPLSLabel `json:"labels"`

	// Multicast, when true, uses the multicast EtherType 0x8848 (RFC 3032
	// §3.10); false (default) uses the unicast EtherType 0x8847. The
	// builder forces the chosen value regardless of L2Config.EtherType.
	Multicast bool `json:"multicast,omitempty"`

	// --- Tunnel-level fields (driven by the internal/protocol/mpls
	// planner; ignored by the builder, which only reads the wire-level
	// fields above) ---

	// InnerProto is the inner L4 protocol: 6=TCP, 17=UDP. 0 = UDP, or TCP
	// when spec.TCP is set.
	InnerProto uint8 `json:"inner_proto,omitempty"`

	// InnerPayload is the inner L4 payload. nil = spec.Payload.
	InnerPayload []byte `json:"inner_payload,omitempty"`

	// Frames is the number of labeled packets emitted (each gets a
	// distinct inner IP ID). 0 = 1.
	Frames int `json:"frames,omitempty"`

	// Direction is the flow direction: "up" (default) or "down" (swaps
	// the MACs and IPs of the labeled packet).
	Direction string `json:"direction,omitempty"`
}

// MPLSLabel is a single 4-byte MPLS label stack entry (RFC 3032 §3.1):
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                Label                  | TC |S|       TTL      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Label(20 bits) + TC(3 bits) + S(1 bit) + TTL(8 bits), serialized as one
// 32-bit big-endian word per RFC 3032 §3.1.
type MPLSLabel struct {
	// Label is the 20-bit label value (RFC 3032 §3.10: 0 = IPv4
	// Explicit-Null, 16-1048575 = usable labels, reserved values 0-15).
	// Values above 0xFFFFF are rejected by the builder.
	Label uint32 `json:"label"`

	// TC is the 3-bit Traffic Class field (RFC 5462, formerly the
	// Experimental/EXP field). Values above 7 are rejected.
	TC uint8 `json:"tc,omitempty"`

	// S is the Bottom-of-Stack bit (RFC 3032 §3.1): 1 only on the bottom
	// entry. The builder auto-corrects the last entry to S=true; an
	// explicit S=true on a non-bottom entry is rejected.
	S bool `json:"s,omitempty"`

	// TTL is the 8-bit Time-To-Live field (RFC 3032 §3.1). 0 = 64
	// (defaulted by the builder, matching the IP TTL default).
	TTL uint8 `json:"ttl,omitempty"`
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

	// HopByHop is the IPv6 hop-by-hop extension header option list (RFC 8200
	// §4.3), mirrored from FlowSpec. Only valid for IPv6.
	HopByHop []IPv6Option `json:"hop_by_hop,omitempty"`

	// SRH is the IPv6 Segment Routing Header (RFC 8754, Routing Type = 4).
	// When non-nil, the builder inserts the SRH between the IPv6 fixed header
	// (NH=43 chaining to the SRH) and the inner L4 payload. Only valid for
	// IPv6. SRH.SegmentList is in wire order (reversed from user-facing
	// order; the planner handles that reversal).
	SRH *SRHConfig `json:"srh,omitempty"`
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

// DNP3Config configures IEEE 1815-2012 DNP3 traffic.
type DNP3Config struct {
	LinkType               string               `json:"link_type,omitempty"`
	Transport              string               `json:"transport,omitempty"`
	SrcAddr                uint16               `json:"src_addr,omitempty"`
	DstAddr                uint16               `json:"dst_addr,omitempty"`
	LinkFCB                uint8                `json:"link_fcb,omitempty"`
	LinkFC                 uint8                `json:"link_fc,omitempty"`
	AppSeq                 uint8                `json:"app_seq,omitempty"`
	AppFunc                string               `json:"app_func,omitempty"`
	AppFuncCode            uint8                `json:"app_func_code,omitempty"`
	AppCON                 uint8                `json:"app_con,omitempty"`
	Objects                []DNP3Object         `json:"objects,omitempty"`
	Scenario               string               `json:"scenario,omitempty"`
	IsEvent                bool                 `json:"is_event,omitempty"`
	IsUnsolicited          bool                 `json:"is_unsolicited,omitempty"`
	ConfirmRequired        bool                 `json:"confirm_required,omitempty"`
	IIN                    uint16               `json:"iin,omitempty"`
	IINClass1              bool                 `json:"iin_class1,omitempty"`
	IINClass2              bool                 `json:"iin_class2,omitempty"`
	IINClass3              bool                 `json:"iin_class3,omitempty"`
	IINAlreadyExecuting    bool                 `json:"iin_already_executing,omitempty"`
	IINEventBufferOverflow bool                 `json:"iin_event_buffer_overflow,omitempty"`
	IINNeedTime            bool                 `json:"iin_need_time,omitempty"`
	IINDeviceTrouble       bool                 `json:"iin_device_trouble,omitempty"`
	IINLocalControl        bool                 `json:"iin_local_control,omitempty"`
	IINBroadcast           bool                 `json:"iin_broadcast,omitempty"`
	IINDeviceRestart       bool                 `json:"iin_device_restart,omitempty"`
	IINConfigCorrupt       bool                 `json:"iin_config_corrupt,omitempty"`
	IINObjectUnknown       bool                 `json:"iin_object_unknown,omitempty"`
	IINParameterError      bool                 `json:"iin_parameter_error,omitempty"`
	IINFuncNotSupported    bool                 `json:"iin_func_not_supported,omitempty"`
	MultiOutstation        *DNP3MultiOutstation `json:"multi_outstation,omitempty"`
	Handshake              *bool                `json:"handshake,omitempty"`
	Termination            *bool                `json:"termination,omitempty"`
	MSS                    uint16               `json:"mss,omitempty"`
	ThinkTime              int                  `json:"think_time,omitempty"`
	MalformedCRC           bool                 `json:"malformed_crc,omitempty"`
	// MalformedLength 显式覆盖 Length 字节（nil=不覆盖, 0=强制 Length=0x00）。
	MalformedLength *uint8 `json:"malformed_length,omitempty"`
	UnknownObject   bool   `json:"unknown_object,omitempty"`
	UnknownFunc     bool   `json:"unknown_func,omitempty"`
}

type DNP3Object struct {
	ObjectType uint8       `json:"object_type"`
	Variation  uint8       `json:"variation"`
	Qualifier  uint8       `json:"qualifier,omitempty"`
	IndexRange [2]uint16   `json:"index_range,omitempty"`
	Count      uint16      `json:"count,omitempty"`
	Points     []DNP3Point `json:"points,omitempty"`
	Flags      []uint8     `json:"flags,omitempty"`
	Times      []uint64    `json:"times,omitempty"`
}

type DNP3Point struct {
	Value float64 `json:"value,omitempty"`
	Index uint16  `json:"index,omitempty"`
	// Status is CROB (Object 12.1) response-only: the 7th byte echoed by the
	// outstation (IEEE 1815-2012 §5.4.2). Requests MUST NOT carry it (design
	// §7.6.5 T66); *uint8 distinguishes "absent" from an explicit 0 so a
	// response echo Status=0 (T68) stays valid.
	Status *uint8 `json:"status,omitempty"`
}
type DNP3MultiOutstation struct {
	OutstationCount     int      `json:"outstation_count,omitempty"`
	OutstationAddrStart uint16   `json:"outstation_addr_start,omitempty"`
	OutstationIPStart   string   `json:"outstation_ip_start,omitempty"`
	OutstationIPList    []string `json:"outstation_ip_list,omitempty"`
	SrcPortStart        uint16   `json:"src_port_start,omitempty"`
}

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

// TupleConfig for generating 4-tuples. Each endpoint accepts a static value
// (string IP / integer port) or a dynamic_value object — scalar shorthand is
// normalized to {strategy:"fixed", value:...} on unmarshal so genIP/genPort
// see one canonical shape. Custom unmarshal is REQUIRED: StrategyConfig is a
// struct, so plain JSON decoding rejects the scalar shorthand that the schema
// (defs.json tuple_config anyOf) explicitly allows.
type TupleConfig struct {
	SrcIP   StrategyConfig `json:"src_ip"`
	DstIP   StrategyConfig `json:"dst_ip"`
	SrcPort StrategyConfig `json:"src_port"`
	DstPort StrategyConfig `json:"dst_port"`
}

// UnmarshalJSON accepts each endpoint as a static scalar or a dynamic_value
// object. Scalars normalize to StrategyConfig{Strategy:"fixed", Value:v};
// unknown shapes fail loudly (caller surfaces the JSON error) instead of
// silently zeroing.
func (tc *TupleConfig) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	type sc StrategyConfig // avoid infinite recursion via type alias
	dec := func(field string, dst *StrategyConfig) error {
		r, ok := raw[field]
		if !ok {
			return nil
		}
		// Object → decode as StrategyConfig (dynamic_value shape).
		if len(r) > 0 && r[0] == '{' {
			return json.Unmarshal(r, (*sc)(dst))
		}
		// Scalar → fixed strategy shorthand.
		var v interface{}
		if err := json.Unmarshal(r, &v); err != nil {
			return err
		}
		*dst = StrategyConfig{Strategy: "fixed", Value: v}
		return nil
	}
	if err := dec("src_ip", &tc.SrcIP); err != nil {
		return fmt.Errorf("tuples.src_ip: %w", err)
	}
	if err := dec("dst_ip", &tc.DstIP); err != nil {
		return fmt.Errorf("tuples.dst_ip: %w", err)
	}
	if err := dec("src_port", &tc.SrcPort); err != nil {
		return fmt.Errorf("tuples.src_port: %w", err)
	}
	if err := dec("dst_port", &tc.DstPort); err != nil {
		return fmt.Errorf("tuples.dst_port: %w", err)
	}
	return nil
}

// LayerIPDyn holds ip-layer dynamic strategies (nil = static/absent).
type LayerIPDyn struct {
	Src *StrategyConfig
	Dst *StrategyConfig
	TTL *StrategyConfig
}

// LayerTransportDyn holds tcp/udp-layer dynamic port strategies.
type LayerTransportDyn struct {
	SrcPort *StrategyConfig
	DstPort *StrategyConfig
}

// LayerEthDyn holds eth-layer dynamic MAC strategies.
type LayerEthDyn struct {
	SrcMAC *StrategyConfig
	DstMAC *StrategyConfig
}

// LayerHTTPDyn holds http-layer dynamic business-field strategies
// (D-HTTP-1 重走步骤 4: string 面 5 + int 面 1; map 型两键关，指针恒 nil)。
type LayerHTTPDyn struct {
	URI                *StrategyConfig
	Body               *StrategyConfig
	BodyB64            *StrategyConfig
	ResponseBody       *StrategyConfig
	ResponseBodyB64    *StrategyConfig
	ResponseStatusCode *StrategyConfig
}

// LayerTLSDyn holds tls-layer dynamic business-field strategies
// (D-TLS-1 步骤 2: sni 开 1 个；alpn/version/role 关，指针恒 nil。
// D-TLS-2: cert.subject/cert.san 开 string 面；cert.key_type/
// cert.not_before/cert.not_after 关，指针恒 nil）。
type LayerTLSDyn struct {
	SNI         *StrategyConfig
	CertSubject *StrategyConfig
	CertSAN     *StrategyConfig
}

// LayerDNSDyn holds dns-layer dynamic business-field strategies
// (D-DNS-1: name 开 string 面；query_type/txid 开 int 面；其余 11 关，
// 指针恒 nil）。
type LayerDNSDyn struct {
	Name      *StrategyConfig
	QueryType *StrategyConfig
	TxID      *StrategyConfig
}

// LayerDynValues is the parsed per-flow dynamic strategy set from a layers
// array (D-FTP-3). All pointers nil-able; nil = that endpoint is static.
type LayerDynValues struct {
	IP   LayerIPDyn
	TCP  LayerTransportDyn
	UDP  LayerTransportDyn
	Eth  LayerEthDyn
	HTTP LayerHTTPDyn
	TLS  LayerTLSDyn
	DNS  LayerDNSDyn
	MQTT LayerMQTTDyn
	// H323 holds h323-layer dynamic port strategies（D-H323-1 决策 E1：
	// src_port/dst_port 2 键开 int 面，逐流端口池；业务 8 键关）。
	H323 LayerTransportDyn
	// MPLS holds mpls-layer dynamic port strategies（D-MPLS-1 决策 E1：
	// 同 h323——端口 2 键开，业务 5 键关）。
	MPLS LayerTransportDyn
	// NGAP holds ngap-layer dynamic port strategies（D-NGAP-1 决策 E1：
	// 同 h323/mpls——端口 2 键开，业务 12 键关）。
	NGAP LayerTransportDyn
	// TELNET holds telnet-layer dynamic port strategies（D-TELNET-1 决策
	// E1：同前三——端口 2 键开，业务 10 键关）。
	TELNET LayerTransportDyn
	// SIP holds sip-layer dynamic port strategies（D-SIP-1 决策 E1：同前
	// 四——端口 2 键开，业务 2 键关）。
	SIP LayerTransportDyn
	// RADIUS holds radius-layer dynamic port strategies（D-RADIUS-1 决策
	// E1：同前六——端口 2 键开，业务 7 键关）。
	RADIUS LayerTransportDyn
}

// LayerMQTTDyn holds mqtt-layer dynamic business-field strategies
// (D-MQTT-1: client_id 开 string 面（层直键）；topic/payload 开 string 面
// （messages[] 槽位键——parse 逐槽下钻存首遇策略，单策略语义）；其余 14 关，
// 指针恒 nil）。
type LayerMQTTDyn struct {
	ClientID *StrategyConfig
	Topic    *StrategyConfig
	Payload  *StrategyConfig
}

// HasAny reports whether any dynamic strategy is present.
func (l *LayerDynValues) HasAny() bool {
	if l == nil {
		return false
	}
	return l.IP.Src != nil || l.IP.Dst != nil || l.IP.TTL != nil ||
		l.TCP.SrcPort != nil || l.TCP.DstPort != nil ||
		l.UDP.SrcPort != nil || l.UDP.DstPort != nil ||
		l.H323.SrcPort != nil || l.H323.DstPort != nil ||
		l.MPLS.SrcPort != nil || l.MPLS.DstPort != nil ||
		l.NGAP.SrcPort != nil || l.NGAP.DstPort != nil ||
		l.TELNET.SrcPort != nil || l.TELNET.DstPort != nil ||
		l.SIP.SrcPort != nil || l.SIP.DstPort != nil ||
		l.RADIUS.SrcPort != nil || l.RADIUS.DstPort != nil ||
		l.Eth.SrcMAC != nil || l.Eth.DstMAC != nil ||
		l.HTTP.URI != nil || l.HTTP.Body != nil || l.HTTP.BodyB64 != nil ||
		l.HTTP.ResponseBody != nil || l.HTTP.ResponseBodyB64 != nil ||
		l.HTTP.ResponseStatusCode != nil ||
		l.TLS.SNI != nil || l.TLS.CertSubject != nil || l.TLS.CertSAN != nil ||
		l.DNS.Name != nil || l.DNS.QueryType != nil || l.DNS.TxID != nil ||
		l.MQTT.ClientID != nil || l.MQTT.Topic != nil || l.MQTT.Payload != nil
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

	// Scenario selects an auto-generated multi-message DHCP dialog
	// (RFC 2131 state-machine sequence) instead of a manual Messages
	// list. When set, the planner synthesizes the full message
	// sequence with correct option chains and shared xid; the user
	// only supplies the parameters (leased IP via DefaultYourIP, server
	// IP via DefaultServerIdentifier, lease time, etc.).
	// Supported values: "dora", "nak", "release", "inform", "renew",
	// "rebind". Empty = manual mode (use Messages).
	Scenario string `json:"scenario,omitempty"`

	// Messages is the ordered sequence of DHCP messages to emit.
	// Each message carries MessageType + per-message field overrides.
	// The planner emits one UDP datagram per message.
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
	DefaultClientIP         string   `json:"default_client_ip,omitempty"`          // ciaddr
	DefaultYourIP           string   `json:"default_your_ip,omitempty"`            // yiaddr
	DefaultServerIP         string   `json:"default_server_ip,omitempty"`          // siaddr
	DefaultRelayAgentIP     string   `json:"default_relay_agent_ip,omitempty"`     // giaddr
	DefaultServerIdentifier string   `json:"default_server_identifier,omitempty"`  // option 54
	DefaultLeaseTime        uint32   `json:"default_lease_time,omitempty"`         // option 51
	DefaultT1               uint32   `json:"default_t1,omitempty"`                 // option 58
	DefaultT2               uint32   `json:"default_t2,omitempty"`                 // option 59
	DefaultSubnetMask       string   `json:"default_subnet_mask,omitempty"`        // option 1
	DefaultRouters          []string `json:"default_routers,omitempty"`            // option 3
	DefaultDNS              []string `json:"default_dns,omitempty"`                // option 6
	DefaultDomainName       string   `json:"default_domain_name,omitempty"`        // option 15
	DefaultHostname         string   `json:"default_hostname,omitempty"`           // option 12
	DefaultDomainSearch     []string `json:"default_domain_search,omitempty"`      // option 119
	DefaultClientID         []byte   `json:"default_client_id,omitempty"`          // option 61
	DefaultRequestedIP      string   `json:"default_requested_ip,omitempty"`       // option 50
	DefaultParamRequestList []uint8  `json:"default_param_request_list,omitempty"` // option 55
	DefaultVendorClass      string   `json:"default_vendor_class,omitempty"`       // option 60
	DefaultRelayAgentInfo   []byte   `json:"default_relay_agent_info,omitempty"`   // option 82
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
	ClientIP         string   `json:"client_ip,omitempty"`      // ciaddr
	YourIP           string   `json:"your_ip,omitempty"`        // yiaddr
	ServerIP         string   `json:"server_ip,omitempty"`      // siaddr
	RelayAgentIP     string   `json:"relay_agent_ip,omitempty"` // giaddr
	Hops             uint8    `json:"hops,omitempty"`
	ServerIdentifier string   `json:"server_identifier,omitempty"`  // option 54
	LeaseTime        uint32   `json:"lease_time,omitempty"`         // option 51
	T1               uint32   `json:"t1,omitempty"`                 // option 58
	T2               uint32   `json:"t2,omitempty"`                 // option 59
	SubnetMask       string   `json:"subnet_mask,omitempty"`        // option 1
	Routers          []string `json:"routers,omitempty"`            // option 3
	DNS              []string `json:"dns,omitempty"`                // option 6
	DomainName       string   `json:"domain_name,omitempty"`        // option 15
	Hostname         string   `json:"hostname,omitempty"`           // option 12
	DomainSearch     []string `json:"domain_search,omitempty"`      // option 119
	ClientID         []byte   `json:"client_id,omitempty"`          // option 61
	RequestedIP      string   `json:"requested_ip,omitempty"`       // option 50
	ParamRequestList []uint8  `json:"param_request_list,omitempty"` // option 55
	VendorClass      string   `json:"vendor_class,omitempty"`       // option 60
	RelayAgentInfo   []byte   `json:"relay_agent_info,omitempty"`   // option 82

	// ExtraOptions is a list of arbitrary options for testing rare or
	// vendor-specific options not covered above.
	ExtraOptions []DHCPOption `json:"extra_options,omitempty"`

	// Broadcast overrides DHCPConfig.BroadcastFlag for this message.
	Broadcast *bool `json:"broadcast,omitempty"`
}

// DHCPOption is a single raw DHCP option (TLV).
type DHCPOption struct {
	Code uint8  `json:"code"`
	Data []byte `json:"data,omitempty"`
}

// DHCPv6Config holds DHCPv6 protocol configuration. Fields populated by
// internal/protocol/dhcpv6 implementer per design_dhcpv6.md.
type DHCPv6Config struct {
	// Messages 是对话中的消息序列，按 wire 顺序输出。每条消息含
	// msg-type/transaction-id/options/direction。
	Messages []DHCPv6Message `json:"messages,omitempty"`

	// Scenario selects an auto-generated multi-message DHCPv6 dialog
	// (RFC 8415 state-machine sequence) instead of a manual Messages
	// list. When set, the planner synthesizes the full message sequence
	// with correct option chains and a shared transaction-id; the user
	// only supplies the parameters (leased IPv6 via DefaultLeasedAddr,
	// lifetimes via DefaultPreferredLifetime/DefaultValidLifetime/T1/T2).
	// Supported values: "sarr", "sarr_rapid", "renew", "rebind",
	// "release", "decline", "confirm", "information_request",
	// "reconfigure", "relay". Empty = manual mode (use Messages).
	Scenario string `json:"scenario,omitempty"`

	// ClientDUID 是客户端标识（用于 ClientID option）。所有客户端消息
	// 共享同一个 DUID。nil = planner 自动生成 DUID-LLT 基于客户端 MAC。
	ClientDUID *DUID `json:"client_duid,omitempty"`

	// ServerDUID 是服务器标识（用于 ServerID option）。所有服务器消息
	// 共享同一个 DUID。nil = planner 自动生成 DUID-EN enterprise=0。
	ServerDUID *DUID `json:"server_duid,omitempty"`

	// RelayConfig 配置中继封装。nil = 不做中继封装（直连 client↔server）。
	RelayConfig *RelayConfig `json:"relay_config,omitempty"`

	// --- Scenario-mode defaults (inherited by synthesized messages) ---

	// DefaultLeasedAddr is the IPv6 address the server assigns in
	// ADVERTISE/REPLY IA_NA IA Address (scenario mode only). Required for
	// sarr/sarr_rapid/renew/rebind/release/decline/confirm.
	DefaultLeasedAddr string `json:"default_leased_addr,omitempty"`

	// DefaultIAID is the IAID used in synthesized IA_NA options (default 1).
	DefaultIAID uint32 `json:"default_iaid,omitempty"`

	// DefaultPreferredLifetime / DefaultValidLifetime are the lifetimes
	// placed in IA Address sub-options in ADVERTISE/REPLY (defaults 3600/7200).
	DefaultPreferredLifetime uint32 `json:"default_preferred_lifetime,omitempty"`
	DefaultValidLifetime     uint32 `json:"default_valid_lifetime,omitempty"`

	// DefaultT1 / DefaultT2 are the T1/T2 values in REPLY IA_NA
	// (defaults 1800/2880 — half and 0.8 of valid lifetime per RFC 8415).
	DefaultT1 uint32 `json:"default_t1,omitempty"`
	DefaultT2 uint32 `json:"default_t2,omitempty"`

	// DefaultPreference is the server Preference in ADVERTISE (default 0).
	DefaultPreference uint8 `json:"default_preference,omitempty"`

	// DefaultStatusCode is the status code placed in REPLY StatusCode option
	// for failure scenarios (e.g. 2=NoAddrsAvail, 3=NoBinding, 4=NotOnLink).
	// 0 = Success (default).
	DefaultStatusCode uint16 `json:"default_status_code,omitempty"`

	// DefaultStatusMessage is the human-readable message in the REPLY
	// StatusCode option (scenario mode). Empty = no message bytes.
	DefaultStatusMessage string `json:"default_status_message,omitempty"`

	// DefaultORO is the Option Request option-code list placed in SOLICIT/
	// REQUEST/INFORMATION-REQUEST (default [23 RDNSS, 24 DNSSL, 31 SNTP]).
	DefaultORO []uint16 `json:"default_oro,omitempty"`

	// DefaultDNSServers / DefaultDNSSearch / DefaultSNTPServers /
	// DefaultInfoRefreshTime are placed in the REPLY for
	// information_request and sarr scenarios when non-empty.
	DefaultDNSServers      []string `json:"default_dns_servers,omitempty"`
	DefaultDNSSearch       []string `json:"default_dns_search,omitempty"`
	DefaultSNTPServers     []string `json:"default_sntp_servers,omitempty"`
	DefaultInfoRefreshTime uint32   `json:"default_info_refresh_time,omitempty"`
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
	Type           uint8  `json:"type"`                      // 1=LLT, 2=EN, 3=LL
	HardwareType   uint16 `json:"hardware_type,omitempty"`   // DUID-LLT/LL 用；1=Ethernet
	Time           uint32 `json:"time,omitempty"`            // DUID-LLT 用；自 2000-01-01 UTC 秒
	EnterpriseNum  uint32 `json:"enterprise_num,omitempty"`  // DUID-EN 用
	VendorSpecific []byte `json:"vendor_specific,omitempty"` // DUID-EN 用
	LinkLayerAddr  string `json:"link_layer_addr,omitempty"` // MAC 地址字符串，如 "00:11:22:33:44:55"
}

// DHCPv6Option 是一个 TLV 选项。Code/LEN 由 planner 自动填，Data 是
// 选项的 OPTION_DATA 字段（已序列化的字节）。
type DHCPv6Option struct {
	Code uint16 `json:"code"`           // OPTION_* 常量，如 1=ClientID
	Data []byte `json:"data,omitempty"` // 已序列化的 OPTION_DATA
}

// RelayConfig 配置中继封装行为。
type RelayConfig struct {
	// RelayIP: 中继代理的全球 IPv6 地址（用于 link-address）。
	RelayIP string `json:"relay_ip"`
	// RelayMAC: 中继代理的 MAC（用于 L2）。
	RelayMAC string `json:"relay_mac"`
	// HopCount: 起始 hop-count，默认 0（RFC 8415 §19.1.1：relay 收到客户端
	// 报文转发时 hop-count 为 0，仅 relay 间多跳转发才递增）。
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
	// WindowUpdateIncrement enables HTTP/2 flow-control WINDOW_UPDATE
	// frame emission per RFC 7540 §6.9. When > 0, the receiver of DATA
	// frames emits a connection-level WINDOW_UPDATE (Stream ID 0) plus a
	// stream-level WINDOW_UPDATE (the call's Stream ID) carrying this
	// increment, modeling window replenishment (design §3.3/§3.7). 0
	// (default) = no WINDOW_UPDATE frames emitted (backward compatible).
	// RFC 7540 §6.9.1 forbids a zero increment; Validate enforces >= 1
	// only when the field is explicitly non-zero (0 means "off").
	WindowUpdateIncrement uint32 `json:"window_update_increment,omitempty"`
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
	// WindowUpdateIncrement overrides the connection-level
	// WindowUpdateIncrement for this call's streams. 0 = inherit the
	// top-level GRPCConfig.WindowUpdateIncrement. See that field's doc.
	WindowUpdateIncrement uint32 `json:"window_update_increment,omitempty"`
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

	// ESPDataPlane configures ESP (Encapsulating Security Payload, 封装安全
	// 载荷) data-plane packets emitted after the IKE control-plane
	// handshake (RFC 4303). When nil, no ESP data-plane packets are
	// emitted (backward-compatible behavior). When set, the planner emits
	// ESP packets immediately after the last IKE control-plane message.
	//
	// The planner performs NO real encryption — ESP PayloadData is filled
	// with deterministic pseudo-bytes (or a synthesized inner IP/L4 packet
	// for tunnel mode). The ESP header (SPI + Seq), trailer (PadLength +
	// NextHeader), and ICV are structurally correct so Wireshark can parse
	// the ESP frame and, in tunnel mode, the encapsulated inner IP packet.
	ESPDataPlane *ESPDataPlaneConfig `json:"esp_data_plane,omitempty"`
}

// ESPDataPlaneConfig configures ESP (Encapsulating Security Payload) data-plane
// packet emission for the IKE planner per RFC 4303. The planner emits ESP
// packets as raw IP-protocol-50 frames (no UDP/L4 wrapper) after the IKE
// control-plane handshake.
//
// Wire format (RFC 4303 §2):
//
//	[Outer IP hdr][SPI(4)][Seq(4)][IV(iv_len)][PayloadData][Padding][PadLen(1)][NextHdr(1)][ICV(icv_len)]
//
// Tunnel mode (RFC 4303 §2.6): PayloadData = inner IP header + inner L4 data;
// NextHeader = 4 (IPv4-in-IPv4, RFC 2003). Transport mode (RFC 4303 §2.4):
// PayloadData = inner L4 header + data; NextHeader = InnerProto.
type ESPDataPlaneConfig struct {
	// SPI is the 32-bit Security Parameter Index (RFC 4303 §2.1). Must be
	// non-zero (SPI=0 is reserved for local use per RFC 4303 §2.1 and is
	// rejected at validation).
	SPI uint32 `json:"spi,omitempty"`

	// Count is the number of ESP packets to emit. 0 = 1. Each packet gets
	// an incrementing sequence number starting at 1.
	Count int `json:"count,omitempty"`

	// Mode is "tunnel" (encrypt entire inner IP packet, RFC 4303 §2.6) or
	// "transport" (encrypt only inner L4+data, RFC 4303 §2.4). Default
	// "tunnel".
	Mode string `json:"mode,omitempty"`

	// Direction is "up" (initiator→responder, default) or "down"
	// (responder→initiator). "down" swaps outer src/dst IPs and MACs.
	Direction string `json:"direction,omitempty"`

	// IVLength is the Initialization Vector length in bytes (default 16,
	// AES-CBC). The IV is filled with deterministic pseudo-bytes.
	IVLength int `json:"iv_length,omitempty"`

	// ICVLength is the Integrity Check Value length in bytes (default 16,
	// HMAC-SHA-256-128). The ICV is filled with deterministic pseudo-bytes.
	ICVLength int `json:"icv_length,omitempty"`

	// --- Tunnel mode fields (ignored in transport mode) ---

	// InnerSrcIP / InnerDstIP are the inner IP addresses for tunnel mode.
	// Required when Mode="tunnel".
	InnerSrcIP string `json:"inner_src_ip,omitempty"`
	InnerDstIP string `json:"inner_dst_ip,omitempty"`

	// --- Inner L4 fields (used in both modes for the inner payload) ---

	// InnerProto is the inner IP protocol number (6=TCP, 17=UDP). In tunnel
	// mode it populates the inner IP header's Protocol field; in transport
	// mode it becomes the ESP NextHeader value.
	InnerProto uint8 `json:"inner_proto,omitempty"`

	// InnerSrcPort / InnerDstPort are the inner L4 ports. Used to build the
	// inner L4 header in both modes.
	InnerSrcPort uint16 `json:"inner_src_port,omitempty"`
	InnerDstPort uint16 `json:"inner_dst_port,omitempty"`

	// InnerPayloadSize is the size of the inner payload data (after the
	// inner L4 header) in bytes. 0 = default 100. The planner fills this
	// with deterministic pseudo-bytes.
	InnerPayloadSize int `json:"inner_payload_size,omitempty"`
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
	Code       uint8  `json:"code"` // 1=Request, 2=Response, 3=Success, 4=Failure
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
	SA     *IKESA         `json:"sa,omitempty"`
	KE     *IKEKE         `json:"ke,omitempty"`
	Nonce  []byte         `json:"nonce,omitempty"`
	Notify *NotifyPayload `json:"notify,omitempty"`

	// Raw 是原始 payload 体（用于故障注入或未知类型）。
	Raw []byte `json:"raw,omitempty"`
}

// NotifyPayload 描述 IKE Notify payload。NAT 检测 Notify 携带 20 字节 SHA-1。
type NotifyPayload struct {
	ProtocolID       uint8  `json:"protocol_id,omitempty"`
	SPISize          uint8  `json:"spi_size,omitempty"`
	NotifyMsgType    uint16 `json:"notify_msg_type"`
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

	// MIMEBody, when non-nil, constructs a MIME (Multipurpose Internet
	// Mail Extensions, 多用途互联网邮件扩展) message and uses it as the
	// literal body, overriding LiteralBody / LiteralBodyB64 / FileSource
	// for the {N} literal placeholder. This enables FETCH BODY[] and
	// APPEND to carry multipart/mixed messages (RFC 2045 §4, RFC 2046
	// §5.1) with text + HTML + attachments without the user manually
	// assembling the wire format.
	//
	// Precedence: MIMEBody > FileSource > LiteralBodyB64 > LiteralBody.
	// MIMEBody is mutually exclusive with LiteralBody and LiteralBodyB64
	// (Validate rejects mixing). When MIMEBody is set, the planner
	// constructs the full RFC 822 message bytes from MIMEBody and uses
	// len(constructed bytes) as the {N} value.
	//
	// When the {N} placeholder appears in a client command (APPEND), the
	// MIME bytes are emitted up (client -> server). When it appears in a
	// server response (FETCH), the MIME bytes are emitted down.
	MIMEBody *IMAPMIMEBody `json:"mime_body,omitempty"`
}

// IMAPMIMEBody constructs a MIME (RFC 2045/2046) email message for use as
// an IMAP literal body (FETCH BODY[] or APPEND). The planner assembles the
// full RFC 822 wire bytes from this struct, then uses those bytes as the
// {N} literal payload.
//
// Wire layout (RFC 2046 §5.1.1 for multipart, RFC 5322 for simple):
//
//	MULTIPART (Parts/Attachments non-empty OR Text + Parts/Attachments):
//	  <top-level Headers>\r\n
//	  MIME-Version: 1.0\r\n
//	  Content-Type: multipart/mixed; boundary="<boundary>"\r\n
//	  \r\n
//	  --<boundary>\r\n
//	  Content-Type: text/plain; charset=utf-8\r\n
//	  Content-Transfer-Encoding: 8bit\r\n
//	  \r\n
//	  <Text>\r\n
//	  --<boundary>\r\n
//	  <each Part headers + \r\n + body + \r\n>
//	  <each Attachment headers + base64 body + \r\n>
//	  --<boundary>--\r\n
//
//	SIMPLE (no Parts and no Attachments):
//	  <top-level Headers>\r\n
//	  Content-Type: text/plain; charset=utf-8\r\n
//	  Content-Transfer-Encoding: 8bit\r\n
//	  \r\n
//	  <Text>\r\n
//
// When Boundary is empty and the message is multipart, the planner
// auto-generates a unique boundary string. When the user provides a
// Boundary, it is used verbatim (RFC 2046 §5.1.1: boundary must not
// appear in any body part).
type IMAPMIMEBody struct {
	// Headers is the list of top-level RFC 5322 headers (e.g.
	// "From: alice@example.com", "To: bob@example.com",
	// "Subject: Test"). Each entry is one header line without the
	// trailing CRLF; the planner appends "\r\n" to each. The planner
	// does NOT add Date/Message-ID automatically (the user is
	// responsible for a syntactically valid RFC 5322 message).
	Headers []string `json:"headers,omitempty"`

	// Boundary is the multipart boundary string (RFC 2046 §5.1.1).
	// When empty and the message is multipart (has Parts or
	// Attachments), the planner auto-generates a unique boundary.
	// When non-empty, used verbatim. Ignored for simple (non-multipart)
	// messages.
	Boundary string `json:"boundary,omitempty"`

	// Text is the plain-text body of the message (or the first
	// multipart part). When the message is simple, this is the entire
	// body. When multipart, this becomes the first body part with
	// Content-Type: text/plain; charset=utf-8.
	Text string `json:"text,omitempty"`

	// Parts is the list of additional MIME body parts (RFC 2046
	// §5.1). Each part has its own Content-Type and body. When non-empty
	// (or Attachments non-empty), the message is multipart/mixed.
	Parts []IMAPMIMEPart `json:"parts,omitempty"`

	// Attachments is the list of file attachments. Each attachment is
	// emitted as a multipart part with Content-Disposition: attachment
	// (RFC 2183) and Content-Transfer-Encoding: base64 (RFC 2045 §6.8)
	// for binary data. When non-empty, the message is multipart/mixed.
	Attachments []IMAPAttachment `json:"attachments,omitempty"`
}

// IMAPMIMEPart is one MIME body part within a multipart message
// (RFC 2046 §5.1). The planner emits it as:
//
//	--<boundary>\r\n
//	<ContentType header (or text/plain default)>\r\n
//	<Content-Transfer-Encoding (8bit default)>\r\n
//	\r\n
//	<Body>\r\n
type IMAPMIMEPart struct {
	// ContentType is the MIME Content-Type for this part (e.g.
	// "text/html; charset=utf-8"). When empty, defaults to
	// "text/plain; charset=utf-8".
	ContentType string `json:"content_type,omitempty"`

	// Body is the raw body content of this part. The planner emits it
	// verbatim (no encoding). For binary content, use Attachments
	// instead (which auto-applies base64).
	Body string `json:"body,omitempty"`

	// Headers is additional part-specific headers (e.g.
	// "Content-ID: <part1@example.com>"). Each entry is one header line
	// without trailing CRLF. When nil, only Content-Type and
	// Content-Transfer-Encoding are emitted.
	Headers []string `json:"headers,omitempty"`
}

// IMAPAttachment is a file attachment within a multipart MIME message.
// The planner emits it as a multipart part with:
//
//	--<boundary>\r\n
//	Content-Type: <ContentType or application/octet-stream>\r\n
//	Content-Transfer-Encoding: base64\r\n
//	Content-Disposition: attachment; filename="<Filename>"\r\n
//	\r\n
//	<base64-encoded Data, wrapped at 76 chars per line (RFC 2045 §6.8)>\r\n
type IMAPAttachment struct {
	// Filename is the attachment filename, emitted in
	// Content-Disposition per RFC 2183.
	Filename string `json:"filename,omitempty"`

	// ContentType is the MIME type (e.g. "application/pdf"). When
	// empty, defaults to "application/octet-stream".
	ContentType string `json:"content_type,omitempty"`

	// Data is the raw binary attachment content. The planner
	// base64-encodes it (RFC 2045 §6.8) and wraps at 76 chars per line
	// per RFC 2045 §6.8 (base64 lines must be <= 76 chars).
	Data []byte `json:"data,omitempty"`
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

// GTPConfig holds GTPv1 (GPRS Tunneling Protocol, 通用分组无线业务隧道协议,
// TS 29.060 / TS 29.281) configuration. GTP is a UDP application-layer
// protocol with two planes:
//
//	GTP-U (user plane, port 2152): T-PDU messages (Type 0xFF) carry an
//	    inner IP packet — the actual user traffic of a tunnel.
//	GTP-C (control plane, port 2123): signaling messages (Echo Request
//	    type 1, Create PDP Context Request type 16, ...) carry Information
//	    Elements instead of a packet.
//
// The GTPv1 message header (TS 29.281 §5.1) is:
//
//	Flags(1) + Message Type(1) + Length(2) + TEID(4)
//	    + [Sequence(2) + N-PDU(1) + Next-Ext-Type(1)]  // iff E|S|PN set
//	    + [extension header(s)]                        // iff E set
//	    + payload (inner packet for T-PDU, IEs for GTP-C)
//
// Flags = Version(3 bits) | PT(1) | spare(1) | E(1) | S(1) | PN(1). The
// Length field counts everything after the first 8 octets (Flags + Message
// Type + Length + TEID) — i.e. the optional block, extension headers and
// payload — and never counts the TEID itself (verified against
// /home/pcap_auto/mypcap/idc3/2.gtp_tunneling_udp.pcap: flags 0x32, Length
// 204 = 4 optional + 200 inner, TEID excluded).
//
// The planner decides which messages to emit: when Scenarios is non-empty
// it emits one GTP-C message per step (a signaling dialog); otherwise it
// emits Frames T-PDU data messages carrying the inner packet. The GTP
// message is carried verbatim in PacketConfig.Payload of an outer UDP
// packet — no builder support is needed (GTP is an L4 application, not an
// L2/L3 encapsulation).
type GTPConfig struct {
	// Mode selects the plane, which sets the default UDP ports: "u" =
	// GTP-U (default, 2152), "c" = GTP-C (2123). Plan defaults
	// spec.SrcPort/DstPort to the mode's port when 0.
	Mode string `json:"mode,omitempty"`

	// Version is the GTP version. GTPv1 = 1 (the default and only
	// supported version — GTPv0 uses a different header layout and GTPv2
	// (TS 29.274) is a different protocol; both are rejected by Validate).
	Version uint8 `json:"version,omitempty"`

	// PT is the Protocol Type flag (bit 4 of Flags): 1 = GTP (default),
	// 0 = GTP' (the charging variant of TS 32.295).
	PT uint8 `json:"pt,omitempty"`

	// TEID is the Tunnel Endpoint Identifier (4 bytes, octets 5-8). The
	// TEID is ALWAYS present in GTPv1 — it is part of the mandatory
	// 8-octet header (there is no TEID-present flag bit in GTPv1; the
	// "spare" bit 3 is reserved and stays 0).
	TEID uint32 `json:"teid,omitempty"`

	// SequencePresent sets the S flag: the 4-octet optional block
	// (Sequence + N-PDU + Next-Ext-Type) follows the TEID. Data-plane
	// frames increment Sequence per frame; scenario steps write their
	// own Sequence verbatim.
	SequencePresent bool   `json:"sequence_present,omitempty"`
	Sequence        uint16 `json:"sequence,omitempty"`

	// NPDUPresent sets the PN flag (N-PDU Number carried in the optional
	// block, TS 29.281 §5.1).
	NPDUPresent bool  `json:"npdu_present,omitempty"`
	NPDUValue   uint8 `json:"npdu_value,omitempty"`

	// ExtensionPresent sets the E flag: one extension header (TS 29.281
	// §5.2.1) follows the optional block:
	// Next-Ext-Type(1) + Length(1, 4-octet units incl. the Length octet,
	// excl. the Next-Ext-Type octet) + content padded to a 4-octet
	// multiple. ExtensionData is the content (max 1018 bytes so the
	// Length octet fits); the header's own Next-Ext-Type is 0x00 (last).
	ExtensionPresent bool   `json:"extension_present,omitempty"`
	ExtensionType    uint8  `json:"extension_type,omitempty"`
	ExtensionData    []byte `json:"extension_data,omitempty"`

	// Scenarios is the ordered list of GTP-C messages for a signaling
	// dialog (Echo Request/Response, Create PDP Context, ...). Each step
	// emits exactly one packet; when non-empty the Frames data plane is
	// skipped. nil = data plane (Frames T-PDU messages).
	Scenarios []GTPStep `json:"scenarios,omitempty"`

	// --- Inner packet fields (GTP-U T-PDU data plane; TS 29.060 §7.1
	// message type 255 carries the user packet verbatim) ---

	// InnerSrcIP / InnerDstIP are the inner packet's addresses. Empty =
	// spec.SrcIP / spec.DstIP.
	InnerSrcIP string `json:"inner_src_ip,omitempty"`
	InnerDstIP string `json:"inner_dst_ip,omitempty"`

	// InnerProto is the inner L4 protocol: 6=TCP, 17=UDP, 1=ICMP (IPv4
	// inner), 58=ICMPv6 (IPv6 inner). 0 = UDP, or TCP when spec.TCP is
	// set.
	InnerProto uint8 `json:"inner_proto,omitempty"`

	// InnerTTL is the inner IP TTL (IPv4) / hop limit (IPv6). 0 = 64.
	InnerTTL uint8 `json:"inner_ttl,omitempty"`

	// InnerIPID is the inner IPv4 Identification of the first frame (0 =
	// 0; the planner increments it per frame). IPv6 has no IPID — ignored
	// in IPv6 mode.
	InnerIPID uint16 `json:"inner_ipid,omitempty"`

	// InnerPayload is the inner L4 payload. nil = spec.Payload.
	InnerPayload []byte `json:"inner_payload,omitempty"`

	// TCPOptions are the inner TCP options (MSS, Window Scale, ...),
	// encoded after the 20-byte inner TCP header like the core builder's
	// encoder.
	TCPOptions []TCPOption `json:"tcp_options,omitempty"`

	// Frames is the number of T-PDU data messages emitted (each gets a
	// distinct inner IP ID and, when SequencePresent, an incremented
	// sequence). 0 = 1.
	Frames int `json:"frames,omitempty"`

	// Direction is the flow direction: "up" (default) or "down" (swaps
	// outer MACs/IPs/ports and inner addresses).
	Direction string `json:"direction,omitempty"`
}

// GTPStep is one GTP-C control-plane message of a signaling dialog. Each
// step emits exactly one packet on the flow's 4-tuple (direction-swapped
// when the step's direction is "down").
type GTPStep struct {
	// MessageType is the GTP message type (TS 29.060 §7.1): 1 = Echo
	// Request, 2 = Echo Response, 16 = Create PDP Context Request, 17 =
	// Create PDP Context Response, ... Required (0 is rejected).
	MessageType uint8 `json:"message_type"`

	// TEIDOverride replaces the config TEID for this step (nil = the
	// config TEID). Needed because control messages often carry a
	// different (or zero, pre-assignment) TEID than the data plane.
	TEIDOverride *uint32 `json:"teid_override,omitempty"`

	// Sequence is the Sequence Number written when SequencePresent is
	// set. Written verbatim (unlike the data plane's per-frame
	// increment) — the dialog's sequence numbers are explicit.
	Sequence uint16 `json:"sequence,omitempty"`

	// Direction is the step's direction: "" = cfg.Direction, then "up".
	// "down" swaps the outer MACs/IPs/ports so the reply comes from the
	// peer.
	Direction string `json:"direction,omitempty"`

	// IEs are the Information Elements of the message (TS 29.060 §7.7.0),
	// serialized per the Type's format bit (bit 8): Types 0x00–0x7F use the
	// TV format (Type + Value, no Length octet, fixed-length IEs such as
	// Recovery); Types 0x80–0xFF use the TLV format (Type + 2-octet
	// big-endian Length + Value, variable-length IEs such as APN). Appended
	// after the GTP header. nil = no IEs (e.g. a bare Echo Request).
	IEs []GTPIE `json:"ies,omitempty"`
}

// GTPIE is one GTP Information Element (TS 29.060 §7.7.0). The encoding is
// chosen by the Type's most significant bit: Types 0x00–0x7F (e.g. 1 =
// Cause, 14 = Recovery, 16 = Tunnel Endpoint Identifier Data I, 17 = TEID
// Control Plane) are TV format — Type(1 octet) + Value, no Length octet;
// Types 0x80–0xFF (e.g. 131 = Access Point Name, 133 = GSN Address) are TLV
// format — Type(1) + Length(2, big-endian, = len(Value)) + Value.
type GTPIE struct {
	// Type is the IE type octet (bit 8 selects TV vs TLV encoding).
	Type uint8 `json:"type"`

	// Value is the IE value. TV IEs have a fixed per-type length (their
	// Length field is absent); TLV IEs take a 2-octet Length, so Values up
	// to 65535 bytes are supported.
	Value []byte `json:"value,omitempty"`
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

	// Scenario selects a built-in multi-message template that expands into
	// Scenarios + PPPFrames at Plan time. When set, Scenarios and PPPFrames
	// MUST be empty (mutual exclusion enforced by Validate). Supported
	// values: "tunnel_with_data" (full tunnel lifecycle: SCCRQ->SCCRP->
	// SCCCN->ICRQ->ICRP->ICCN + inner-IPv4 PPP data frames + StopCCN).
	// Empty = use Scenarios/PPPFrames explicitly (legacy manual mode).
	Scenario string `json:"scenario,omitempty"`

	// InnerIP configures the inner IPv4 packet carried inside PPP data
	// frames when Scenario="tunnel_with_data". This is the dual-IP
	// encapsulation (outer L2TP/UDP, inner IPv4) that is the core
	// production tunnel scenario (RFC 1661 §6 PPP Protocol=0x0021 +
	// RFC 791 IPv4). Nil = planner synthesizes a default inner IPv4
	// packet (10.10.10.1 -> 10.10.10.2, UDP, no payload).
	InnerIP *L2TPInnerIP `json:"inner_ip,omitempty"`
}

// L2TPInnerIP describes the inner IPv4 packet encapsulated in PPP data
// frames for the "tunnel_with_data" scenario. The planner builds a complete
// IPv4 header (with correct checksum) + optional L4 header + payload per
// RFC 791 §3.1 / RFC 768 / RFC 793. Only IPv4 inner packets are supported
// (PPP Protocol 0x0021) per RFC 1661 §6.
type L2TPInnerIP struct {
	// SrcIP is the inner IPv4 source address. Empty = "10.10.10.1".
	SrcIP string `json:"src_ip,omitempty"`
	// DstIP is the inner IPv4 destination address. Empty = "10.10.10.2".
	DstIP string `json:"dst_ip,omitempty"`
	// Proto is the inner IPv4 protocol number (RFC 790). Supported: 1
	// (ICMP), 6 (TCP), 17 (UDP). Default 17 (UDP).
	Proto uint8 `json:"proto,omitempty"`
	// SrcPort is the inner L4 source port (TCP/UDP only).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort is the inner L4 destination port (TCP/UDP only).
	DstPort uint16 `json:"dst_port,omitempty"`
	// TTL is the inner IPv4 TTL (RFC 791 §3.1). 0 = 64.
	TTL uint8 `json:"ttl,omitempty"`
	// Payload is the inner L4 payload bytes. For TCP, prepended after the
	// 20-byte TCP header (no options). For UDP, after the 8-byte header.
	Payload []byte `json:"payload,omitempty"`
	// DataFrames is the number of inner IPv4 packets to emit (each as a
	// separate PPP data frame). Each frame gets a distinct inner IPID.
	// 0 = 1 frame.
	DataFrames int `json:"data_frames,omitempty"`
}

// PPTPConfig configures PPTP (Point-to-Point Tunneling Protocol, RFC 2637).
// It is attached to FlowSpec.PPTP; the internal/protocol/pptp planner emits
// the TCP control plane (default port 1723) and the GRE data plane (outer IP
// protocol 47, PPTP-enhanced GRE header per RFC 2637 §4.1) in one flow.
//
// Control-plane defaults reproduce the reference pcap byte-for-byte
// (/home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-
// 1260-980.pcap, PNS=client/PAC=server): SCCRQ/SCCRP 156B, OCRQ 168B, OCRP
// 32B, SLI 24B, CCRQ 16B, CCDN 148B, StopRQ/StopRP 16B — including the
// reference implementation quirks (SLI-down peer call id = PNS TCP source
// port, merged CCRQ+CCDN segment, CCDN carrying the PNS call id in both
// directions).
type PPTPConfig struct {
	// Role selects which role the flow's source side plays. "pns" (default)
	// = the source side is the PNS (the reference pcap's client, which
	// initiates SCCRQ/OCRQ); "pac" = the source side is the PAC. The role
	// determines each control message's direction and call-ID ownership.
	Role string `json:"role,omitempty"` // "pns" (default) | "pac"

	// Scenario selects the message template: "full" (default: complete
	// control plane + GRE data + teardown), "control_only" (same without
	// the GRE data frames), "tunnel_only" (SCCRQ/SCCRP + OCRQ/OCRP only,
	// no SLI/data), "data_only" (GRE data frames only, no TCP control
	// plane).
	Scenario string `json:"scenario,omitempty"`

	// Calls is the number of concurrent calls (multi-session). 0 = 1. Call
	// i (0-based) uses CallID+i / PeerCallID+i for its messages and data
	// frames.
	Calls int `json:"calls,omitempty"`

	// --- SCCRQ parameters (defaults = reference pcap bytes) ---

	// Version is the SCCRQ/SCCRP Protocol Version field (RFC 2637 §2.1).
	// 0 = 0x0100 (1.0).
	Version uint16 `json:"version,omitempty"`

	// FramingCaps is the SCCRQ Framing Capabilities field (bit 0 = async,
	// bit 1 = sync). 0 = 1 (async, the reference value).
	FramingCaps uint32 `json:"framing_caps,omitempty"`

	// BearerCaps is the SCCRQ Bearer Capabilities field (bit 0 = analog,
	// bit 1 = digital). 0 = 1 (analog, the reference value).
	BearerCaps uint32 `json:"bearer_caps,omitempty"`

	// MaxChannels is the SCCRQ Maximum Channels field (reference = 0).
	MaxChannels uint16 `json:"max_channels,omitempty"`

	// FirmwareRevision is the SCCRQ Firmware Revision field.
	FirmwareRevision uint16 `json:"firmware_revision,omitempty"`

	// HostName is the SCCRQ/SCCRP Host Name field (64-byte fixed field,
	// zero-padded; empty = all zeros, the reference value).
	HostName string `json:"host_name,omitempty"`

	// VendorName is the SCCRQ/SCCRP Vendor Name field (64-byte fixed
	// field). Default "Microsoft" (the reference value).
	VendorName string `json:"vendor_name,omitempty"`

	// --- SCCRP response parameters (defaults = reference pcap bytes) ---

	// ScrpResult is the SCCRP Result Code (1 byte, RFC 2637 §2.2).
	// 0 = 1 (OK).
	ScrpResult uint8 `json:"scrp_result,omitempty"`

	// ScrpError is the SCCRP Error Code (1 byte). 0 = 0.
	ScrpError uint8 `json:"scrp_error,omitempty"`

	// ScrpFramingCaps is the SCCRP Framing Capabilities field.
	// 0 = 2 (sync, the reference value).
	ScrpFramingCaps uint32 `json:"scrp_framing_caps,omitempty"`

	// ScrpBearerCaps is the SCCRP Bearer Capabilities field.
	// 0 = 3 (digital+analog, the reference value).
	ScrpBearerCaps uint32 `json:"scrp_bearer_caps,omitempty"`

	// ScrpFirmwareRev is the SCCRP Firmware Revision field.
	// 0 = 0x0ece (3790, the reference value).
	ScrpFirmwareRev uint16 `json:"scrp_firmware_rev,omitempty"`

	// --- Call parameters (OCRQ/OCRP; defaults = reference pcap bytes) ---

	// CallID is this side's (PNS side's) call ID. The reference pcap's PNS
	// (client) assigns 0xa9c0 in OCRQ; the PAC echoes it back as the Peer
	// Call ID in OCRP.
	CallID uint16 `json:"call_id,omitempty"`

	// PeerCallID is the peer's (PAC side's) call ID, assigned by the PAC
	// in OCRP (reference 0x35c9). Data frames carry the PEER's call ID in
	// the GRE Key field (RFC 2637 §1.3.2), so PNS-side frames use
	// PeerCallID and PAC-side frames use CallID.
	PeerCallID uint16 `json:"peer_call_id,omitempty"`

	// CallSerial is the OCRQ Call Serial Number (reference 3).
	CallSerial uint16 `json:"call_serial,omitempty"`

	// MinBPS is the OCRQ Minimum BPS. 0 = 300 (the reference value).
	MinBPS uint32 `json:"min_bps,omitempty"`

	// MaxBPS is the OCRQ Maximum BPS. 0 = 100000000 (the reference value).
	MaxBPS uint32 `json:"max_bps,omitempty"`

	// BearerType is the OCRQ Bearer Type. 0 = 3 (the reference value).
	BearerType uint32 `json:"bearer_type,omitempty"`

	// FramingType is the OCRQ Framing Type. 0 = 3 (the reference value).
	FramingType uint32 `json:"framing_type,omitempty"`

	// WindowSize is the OCRQ Packet Recv Window Size. 0 = 64 (the
	// reference value).
	WindowSize uint16 `json:"window_size,omitempty"`

	// PacketDelay is the OCRQ Packet Processing Delay (reference 0).
	PacketDelay uint16 `json:"packet_delay,omitempty"`

	// PhoneNumber is the OCRQ Phone Number (64-byte fixed field; empty =
	// all zeros, the reference value). Phone Number Length is auto-filled.
	PhoneNumber string `json:"phone_number,omitempty"`

	// SubAddress is the OCRQ Sub-Address as a hex string (64-byte fixed
	// field, zero-padded). Default reproduces the reference pcap's binary
	// garbage bytes "011f423a6484e94caf72892a29b1d3ab". Empty string = all
	// zeros.
	SubAddress string `json:"sub_address,omitempty"`

	// OcrpResult is the OCRP Result Code (1 byte). 0 = 1 (OK).
	OcrpResult uint8 `json:"ocrp_result,omitempty"`

	// OcrpError is the OCRP Error Code (1 byte). 0 = 0.
	OcrpError uint8 `json:"ocrp_error,omitempty"`

	// CauseCode is the OCRP Cause Code (failure reason, RFC 2637 §2.4.2).
	CauseCode uint16 `json:"cause_code,omitempty"`

	// ConnectSpeed is the OCRP Connect Speed. 0 = 14808325 (the reference
	// value).
	ConnectSpeed uint32 `json:"connect_speed,omitempty"`

	// OcrpWindowSize is the OCRP Packet Recv Window Size.
	// 0 = 16384 (the reference value).
	OcrpWindowSize uint16 `json:"ocrp_window_size,omitempty"`

	// OcrpDelay is the OCRP Packet Processing Delay (reference 0).
	OcrpDelay uint16 `json:"ocrp_delay,omitempty"`

	// PhysicalChannelID is the OCRP Physical Channel ID.
	PhysicalChannelID uint32 `json:"physical_channel_id,omitempty"`

	// --- Link parameters (SLI) ---

	// SendACCM / ReceiveACCM are the SLI ACCM values (RFC 2637 §2.7).
	// 0 = 0xffffffff each (the reference values).
	SendACCM    uint32 `json:"send_accm,omitempty"`
	ReceiveACCM uint32 `json:"receive_accm,omitempty"`

	// SLICount is the number of SLI messages per call. 0 = 5 (the
	// reference pcap alternates up/down/up/down/up).
	SLICount int `json:"sli_count,omitempty"`

	// SliPeerCallID overrides the SLI Peer Call ID for every SLI.
	// 0 = auto: PNS-side SLIs use PeerCallID (the peer's call id);
	// PAC-side SLIs use the PNS side's TCP source port (the reference
	// pcap quirk: 0xc02a = 49194). Call i adds i when set explicitly.
	SliPeerCallID uint16 `json:"sli_peer_call_id,omitempty"`

	// --- Teardown parameters ---

	// StopReason is the StopRQ Reason Code. 0 = 1 (the reference value).
	StopReason uint8 `json:"stop_reason,omitempty"`

	// StopResult / StopError are the StopRP Result/Error Codes.
	// 0 = 1 / 0 (the reference values).
	StopResult uint8 `json:"stop_result,omitempty"`
	StopError  uint8 `json:"stop_error,omitempty"`

	// CcdnResult / CcdnError / CcdnCause are the CCDN Result Code, Error
	// Code and Cause Code (RFC 2637 §2.13). 0 = 0/0/0 (the reference
	// values).
	CcdnResult uint8  `json:"ccdn_result,omitempty"`
	CcdnError  uint8  `json:"ccdn_error,omitempty"`
	CcdnCause  uint16 `json:"ccdn_cause,omitempty"`

	// --- Optional control-message segments ---

	// Echo, when true, appends ECRQ (PAC side) → ECRP (PNS side) after
	// SCCRP (RFC 2637 §2.9: the PAC requests an echo reply).
	Echo bool `json:"echo,omitempty"`

	// WEN, when true, appends a WAN Error Notification (PAC side, RFC
	// 2637 §2.11) after the SLI sequence of each call.
	WEN bool `json:"wen,omitempty"`

	// IncomingCall, when true, appends ICRQ (PAC) → ICRP (PNS) → ICCN
	// (PAC) after OCRP of each call (RFC 2637 §2.9-2.11, PAC-initiated
	// incoming call). The reference pcap has no incoming-call segment;
	// these messages follow the RFC layouts.
	IncomingCall bool `json:"incoming_call,omitempty"`

	// DialedNumber is the ICRQ Dialed Number field (64-byte fixed, RFC
	// 2637 §2.9). Empty = all zeros.
	DialedNumber string `json:"dialed_number,omitempty"`

	// DialingNumber is the ICRQ Dialing Number field (64-byte fixed, RFC
	// 2637 §2.9). Empty = all zeros.
	DialingNumber string `json:"dialing_number,omitempty"`

	// --- Data plane (PPTP-GRE, RFC 2637 §4.1) ---

	// DataFrames is the number of GRE data frames emitted by the PNS side
	// (sequence 0..N-1, ack 0). 0 = 3.
	DataFrames int `json:"data_frames,omitempty"`

	// DownDataFrames is the number of GRE data frames emitted by the PAC
	// side (sequence 0..M-1, ack = N-1). 0 = 2.
	DownDataFrames int `json:"down_data_frames,omitempty"`

	// InnerIP configures the inner IPv4 packet carried in each PPP data
	// frame (PPP protocol 0x0021, RFC 1661 §6). Nil = planner synthesizes
	// a default inner IPv4 packet (10.10.10.1 → 10.10.10.2, UDP).
	InnerIP *PPTPInnerIP `json:"inner_ip,omitempty"`
}

// PPTPInnerIP describes the inner IPv4 packet encapsulated in PPP data
// frames (RFC 2637 §4.1 carries PPP; RFC 1661 §6 PPP Protocol 0x0021 =
// IPv4). The planner builds a complete IPv4 header (with correct checksum)
// + optional L4 header + payload. Only IPv4 inner packets are supported.
type PPTPInnerIP struct {
	// SrcIP is the inner IPv4 source address. Empty = "10.10.10.1".
	SrcIP string `json:"src_ip,omitempty"`
	// DstIP is the inner IPv4 destination address. Empty = "10.10.10.2".
	DstIP string `json:"dst_ip,omitempty"`
	// Proto is the inner IPv4 protocol number (RFC 790). Supported: 1
	// (ICMP), 6 (TCP), 17 (UDP). Default 17 (UDP).
	Proto uint8 `json:"proto,omitempty"`
	// SrcPort is the inner L4 source port (TCP/UDP only).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort is the inner L4 destination port (TCP/UDP only).
	DstPort uint16 `json:"dst_port,omitempty"`
	// TTL is the inner IPv4 TTL (RFC 791 §3.1). 0 = 64.
	TTL uint8 `json:"ttl,omitempty"`
	// Payload is the inner L4 payload bytes. For TCP, prepended after the
	// 20-byte TCP header (no options). For UDP, after the 8-byte header.
	Payload []byte `json:"payload,omitempty"`
}

// H323Config configures H.323 (ITU-T H.225.0/H.245, multimedia over IP). It
// is attached to FlowSpec.H323; the internal/protocol/h323 planner emits the
// three planes in one flow:
//   - Q.931 call signaling on TCP (default port 1720), each message wrapped
//     in a 4-byte TPKT header (RFC 1006) followed by PD 0x08 / 2-byte call
//     reference (MSB = direction flag) / message type / IE chain
//   - H.245 control tunneled inside Q.931 FACILITY (0x62) messages via the
//     h245Control field of the PER-encoded H323-UserInformation
//   - RAS registration on UDP (port 1719, H.225.0 §7) when Ras.Enabled
//   - RTP media on UDP after CONNECT when Media.Enabled
//
// The PER payloads are byte templates extracted from the reference pcap
// (/home/pcap_auto/llcj_pcap/IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-
// 2271-1779.pcap, caller=20.4.2.46:30000 / callee=30.4.2.46:1720, direct
// call without a gatekeeper), reproducing the reference quirks: FACILITY
// carrying [TCS req + TCS Ack + MSD Ack] in one message, missing MSD
// request, CRV 0x2584 in both directions (flag toggles), 1440-byte SETUP
// with 18 fastStart OpenLogicalChannels, "Administrator\0" Display IE.
// RAS has no reference pcap and is PER-encoded per H.225.0 §7.
type H323Config struct {
	// Role selects which role the flow's source side plays. "caller"
	// (default) = the source side is the calling party (the reference
	// pcap's 20.4.2.46:30000, which sends SETUP first); "callee" = the
	// called party (sends CALL PROCEEDING first). The role determines each
	// message's direction and the call-reference flag bit.
	Role string `json:"role,omitempty"` // "caller" (default) | "callee"

	// Scenario selects the message template: "full" (default: complete
	// Q.931 call with the H.245 tunnel + optional RAS/RTP), "tunnel_only"
	// (Q.931 skeleton only: SETUP/CP/ALERT/CONNECT/RELCOMP, no H.245
	// FACILITY tunnel), "ras_only" (RAS message pairs only, no Q.931),
	// "data_only" (RTP media frames only, no signaling).
	Scenario string `json:"scenario,omitempty"`

	// Crv is the Q.931 call reference value (design_h323.md §4.1).
	// 0 = 0x2584 (the reference pcap value). Multi-call sessions increment
	// it per call.
	Crv uint16 `json:"crv,omitempty"`

	// DisplayName is the Q.931 Display IE string; a NUL terminator is
	// appended automatically (reference "Administrator"). It does NOT
	// affect the PER template's embedded h323-ID (kept byte-for-byte).
	DisplayName string `json:"display_name,omitempty"`

	// Calls is the number of sequential calls (multi-session). 0 = 1. Each
	// call runs the full cycle (SETUP..RELEASE COMPLETE) before the next
	// starts; Crv increments per call.
	Calls int `json:"calls,omitempty"`

	// RewriteAddr rewrites the PER templates' embedded IP/port bytes
	// (length-preserving: IP 4B, port 2B) to the flow's src/dst addresses.
	// Off = reproduce the reference pcap bytes exactly.
	RewriteAddr bool `json:"rewrite_addr,omitempty"`

	// Media configures the RTP data plane (nil = disabled).
	Media *H323MediaConfig `json:"media,omitempty"`

	// Ras configures the RAS registration plane (nil = disabled).
	Ras *H323RasConfig `json:"ras,omitempty"`
}

// H323MediaConfig configures the RTP media plane emitted after CONNECT.
type H323MediaConfig struct {
	// Enabled emits Frames RTP frames after CONNECT. Default false.
	Enabled bool `json:"enabled,omitempty"`

	// SrcPort is the RTP source port. 0 = 5062 (reference OLC mediaChannel).
	SrcPort uint16 `json:"src_port,omitempty"`

	// DstPort is the RTP destination port. 0 = 5063 (reference OLC
	// mediaControlChannel).
	DstPort uint16 `json:"dst_port,omitempty"`

	// Frames is the number of RTP frames. 0 = 10.
	Frames int `json:"frames,omitempty"`

	// PayloadType is the RTP payload type. 0 = 0 (G.711 uLaw; the
	// reference speex capability uses dynamic 125).
	PayloadType uint8 `json:"payload_type,omitempty"`

	// FrameSize is the payload bytes per RTP frame (20 ms G.711 = 160).
	// 0 = 160.
	FrameSize int `json:"frame_size,omitempty"`
}

// H323RasConfig configures the RAS plane (H.225.0 §7, UDP 1719).
type H323RasConfig struct {
	// Enabled runs the RAS registration cycle (GRQ→GCF→RRQ→RCF→ARQ→ACF
	// before the call, DRQ→DCF after it). Default false.
	Enabled bool `json:"enabled,omitempty"`

	// GatekeeperIP is the gatekeeper address written into rasAddress.
	// Empty = the reference callee IP 10.12.184.53.
	GatekeeperIP string `json:"gatekeeper_ip,omitempty"`

	// Port is the RAS UDP port. 0 = 1719.
	Port uint16 `json:"port,omitempty"`

	// EndpointType is the endpoint type in GRQ/RRQ: "terminal" (default)
	// or "gateway".
	EndpointType string `json:"endpoint_type,omitempty"`
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
	TunnelIDOverride  *uint16 `json:"tunnel_id_override,omitempty"`
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
	Protocol    uint16 `json:"protocol"`                // 0x0021=IPv4, 0xC021=LCP
	Data        []byte `json:"data,omitempty"`          // PPP Information field
	Direction   string `json:"direction,omitempty"`     // "up" (default) | "down"
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
	//                    When StatusFlags is non-zero, it overrides the default.
	//   "ok-insert"    — like ok but with affected_rows=1 and last_insert_id=42.
	//                    When StatusFlags is non-zero, it overrides the default.
	//   "ok-custom"    — emit OK with user-specified AffectedRows, LastInsertID,
	//                    StatusFlags, Warnings (all from the command fields).
	//   "err"          — emit ERR(1064 #HY000 syntax error).
	//   "err-perm"     — emit ERR(1044 #42000 access denied).
	//   "err-custom"   — emit ERR with user-specified ErrCode, ErrSQLState,
	//                    ErrMessage.
	//   "result-set"   — emit column_count=1, col_defs=[user provided], EOF,
	//                    rows=[user provided], EOF. See ColDefs/Rows.
	//   "binary-result"— for COM_STMT_EXECUTE: column_count + col_defs + EOF
	//                    + binary protocol rows (0x00 header + null bitmap
	//                    offset 2 + typed values) + EOF.
	//   "prepare-ok"   — for COM_STMT_PREPARE: PREPARE_OK(stmt_id, num_cols,
	//                    num_params) + param ColDefs + EOF + column ColDefs
	//                    + EOF. See Params/ColDefs.
	//   "no-reply"     — emit no server reply (for COM_QUIT / COM_STMT_CLOSE
	//                    / COM_STMT_RESET which have no server response).
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

	// For ReplyMode="prepare-ok" (COM_STMT_PREPARE response):
	// Params holds the parameter column definitions (num_params).
	// ColDefs holds the result column definitions (num_columns).
	// WarningCount is the warning_count field in PREPARE_OK.
	Params       []MySQLColDef `json:"params,omitempty"`
	WarningCount uint16        `json:"warning_count,omitempty"`

	// For ReplyMode="err-custom": custom ERR packet with user-specified
	// error code, SQL state, and message. ErrSQLState should be exactly
	// 5 ASCII chars; the planner pads/truncates if not.
	ErrCode     uint16 `json:"err_code,omitempty"`
	ErrSQLState string `json:"err_sqlstate,omitempty"`
	ErrMessage  string `json:"err_message,omitempty"`

	// For ReplyMode="ok-custom": custom OK packet with user-specified
	// affected_rows, last_insert_id, status_flags, and warnings.
	// StatusFlags is also used by "ok" and "ok-insert" modes when non-zero,
	// enabling transaction status (SERVER_STATUS_IN_TRANS) propagation.
	AffectedRows uint64 `json:"affected_rows,omitempty"`
	LastInsertID uint64 `json:"last_insert_id,omitempty"`
	StatusFlags  uint16 `json:"status_flags,omitempty"`
	Warnings     uint16 `json:"warnings,omitempty"`

	// For COM_STMT_EXECUTE request auto-encoding: when Opcode=0x17 and
	// Body is empty, the planner auto-encodes the request from StmtID +
	// StmtFlags + IterationCount + StmtParams. When Body is non-empty,
	// the user-provided Body takes precedence (raw mode).
	StmtFlags  uint8            `json:"stmt_flags,omitempty"`
	StmtParams []MySQLStmtParam `json:"stmt_params,omitempty"`
}

// MySQLStmtParam is a single parameter for COM_STMT_EXECUTE request
// auto-encoding. The planner encodes each parameter's type (2 bytes:
// low byte = enum_field_type, MSB of high byte = unsigned flag) and
// value (Binary Protocol Value format) into the request body.
type MySQLStmtParam struct {
	// Type is the MySQL column type byte (enum_field_types), e.g.
	// 0x08 for MYSQL_TYPE_LONGLONG, 0x0f for MYSQL_TYPE_VARCHAR.
	Type uint8 `json:"type"`

	// Unsigned sets the unsigned flag (MSB of the high byte in the
	// 2-byte parameter_type field).
	Unsigned bool `json:"unsigned,omitempty"`

	// Value is the raw parameter value (decoded per ValueEncoding).
	// For integer types the planner parses this as a decimal integer
	// and emits fixed-width little-endian bytes. For string/blob types
	// the raw bytes are emitted as a length-encoded string.
	Value string `json:"value,omitempty"`

	// ValueEncoding: "text" (default), "hex", or "base64".
	ValueEncoding string `json:"value_encoding,omitempty"`

	// IsNull marks this parameter as SQL NULL (encoded in the null
	// bitmap; no value bytes emitted).
	IsNull bool `json:"is_null,omitempty"`
}

// MySQLColDef is a column definition packet body (without 4-byte header)
// for COM_QUERY / COM_STMT_PREPARE result sets.
type MySQLColDef struct {
	Catalog  string `json:"catalog"`   // usually "def"
	Schema   string `json:"schema"`    // database name
	Table    string `json:"table"`     // table name
	OrgTable string `json:"org_table"` // alias
	Name     string `json:"name"`      // column name
	OrgName  string `json:"org_name"`  // alias
	Charset  uint16 `json:"charset"`   // character set id
	Length   uint32 `json:"length"`    // column display length (e.g. 11 for INT)
	Type     uint8  `json:"type"`      // MySQL type byte (0x03=LONGLONG, 0xf7=GEOMETRY, etc.)
	Flags    uint16 `json:"flags"`     // column flags (NOT_NULL, PRI_KEY, etc.)
	Decimals uint8  `json:"decimals"`  // decimal precision
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
	LeapIndicator  uint8     `json:"leap_indicator"`  // 0-3, 0=none, 3=alarm
	Version        uint8     `json:"version"`         // 3 or 4, default 4
	Mode           uint8     `json:"mode"`            // 1-7, default 3 (client); 0 reserved
	Stratum        uint8     `json:"stratum"`         // 0-16, 0=unspecified/KoD, 16=unsync
	Poll           int8      `json:"poll"`            // 4-17 (log2 seconds), default 6 (64s)
	Precision      int8      `json:"precision"`       // log2 seconds (negative), default -6 (~15ms)
	RootDelay      float64   `json:"root_delay"`      // seconds, 16.16 fixed-point on the wire
	RootDispersion float64   `json:"root_dispersion"` // seconds, 16.16 fixed-point on the wire
	ReferenceID    uint32    `json:"reference_id"`    // Stratum 0: KO ASCII; 1: ref source; 2+: upstream IPv4
	RefTimestamp   time.Time `json:"ref_timestamp"`   // zero = not set (emitted as 0)
	OriginTS       time.Time `json:"origin_ts"`       // zero = not set
	ReceiveTS      time.Time `json:"receive_ts"`      // zero = not set
	TransmitTS     time.Time `json:"transmit_ts"`     // zero = not set

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

	// InnerIPPackets configures the inner IPv4/IPv6 business packets
	// carried inside P_DATA_V2 as the encrypted data-channel payload. Each
	// entry produces one P_DATA_V2 (client->server) carrying that inner IP
	// packet, plus a matching server->client P_DATA_V2. This is the
	// dual-IP encapsulation (outer IP+UDP/TCP + OpenVPN + inner IP) that
	// models the production tunnel scenario: tunneled ping/TCP/UDP traffic
	// flowing through the OpenVPN data channel.
	//
	// When non-empty, this REPLACES the default dataPacketCount loop: the
	// number of P_DATA_V2 packets is driven by len(InnerIPPackets), not
	// DataPacketCount. Each inner IP packet is built with a correct
	// checksum (IPv4, RFC 791 §3.1) and embedded in the encrypted-payload
	// region of P_DATA_V2 (the IV/nonce, packet_id, and AEAD/HMAC tag
	// remain synthetic filler; the inner IP bytes occupy the
	// "ciphertext" slot, representing what the encrypted body decrypts
	// to). Metadata records the inner IP 5-tuple per packet.
	//
	// Empty = legacy mode (DataPacketCount P_DATA_V2 packets with 0xDD
	// synthetic filler). Backward compatible.
	InnerIPPackets []OpenVPNInnerIP `json:"inner_ip_packets,omitempty"`
}

// OpenVPNInnerIP describes a single inner IPv4/IPv6 packet encapsulated
// inside an OpenVPN P_DATA_V2 data-channel message. The planner builds a
// complete inner IP header (with a correct checksum for IPv4, RFC 791
// §3.1) + optional L4 header + payload per RFC 791 (IPv4) / RFC 8200
// (IPv6) / RFC 768 (UDP) / RFC 793 (TCP) / RFC 792 (ICMP). Mirrors the
// WireGuardInnerIP / L2TPInnerIP tunnel patterns.
type OpenVPNInnerIP struct {
	// SrcIP is the inner source IP. Empty = "10.10.10.1" (IPv4 default).
	// May be IPv4 or IPv6; must match DstIP's family.
	SrcIP string `json:"src_ip,omitempty"`
	// DstIP is the inner destination IP. Empty = "10.10.10.2" (IPv4 default).
	DstIP string `json:"dst_ip,omitempty"`
	// Proto is the inner IP protocol number (RFC 790). Supported: 1 (ICMP),
	// 6 (TCP), 17 (UDP). Default 17 (UDP).
	Proto uint8 `json:"proto,omitempty"`
	// SrcPort is the inner L4 source port (TCP/UDP only; ignored for ICMP).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort is the inner L4 destination port (TCP/UDP only; ignored for
	// ICMP).
	DstPort uint16 `json:"dst_port,omitempty"`
	// TTL is the inner IPv4 TTL / IPv6 HopLimit. 0 = 64.
	TTL uint8 `json:"ttl,omitempty"`
	// Payload is the inner L4 payload bytes. For TCP, prepended after the
	// 20-byte TCP header (no options). For UDP, after the 8-byte header.
	// For ICMP, after the 8-byte echo header.
	Payload []byte `json:"payload,omitempty"`
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
// PostgreSQLEvent is a single PostgreSQL v3 wire event for the shared
// postgresql layer's event-driven generator (layer_gen.go). It is the
// terminal-layer event carring the kind/direction/profile that the generator
// turns into PG v3 bytes: it carries the auth sub-type (authtype),
// parameter-status name/value, and backend-key pid/secret so the postgresql
// layer can emit profile-complete events (D-KINGBASE-1：dialect=kingbase 同层
// 复用，protocol 身份已退役).
type PostgreSQLEvent struct {
	Kind      string `json:"kind,omitempty"`
	Direction string `json:"direction,omitempty"`
	Profile   string `json:"profile,omitempty"`
	User      string `json:"user,omitempty"`
	Database  string `json:"database,omitempty"`
	Result    string `json:"result,omitempty"`
	SQL       string `json:"sql,omitempty"`
	Tag       string `json:"tag,omitempty"`
	// Authtype is the int32 auth sub-type for "auth_request" (0=OK, 3=cleartext,
	// 5=md5, 10=sasl). Pointer so an explicit authtype=0 (AuthenticationOk) is
	// distinguishable from an absent default (which the generator maps to
	// cleartext). nil = absent.
	Authtype *int32 `json:"authtype,omitempty"`
	// Name/Value carry ParameterStatus name/value; empty → generator uses a
	// default parameter list (a cycled index).
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	// PID/Secret carry BackendKeyData; 0 → generator default (12345/67890).
	PID    int32 `json:"pid,omitempty"`
	Secret int32 `json:"secret,omitempty"`
}

// PostgreSQLSession is a single postgresql-layer session with its own source
// port and events (dialect=kingbase multi-session case).
type PostgreSQLSession struct {
	SrcPort uint16            `json:"src_port,omitempty"`
	Events  []PostgreSQLEvent `json:"events,omitempty"`
}

// PostgreSQLConfig configures a PostgreSQL v3 wire session (TCP 5432 for
// dialect=postgresql, 54321 for dialect=kingbase). It is the shared config for
// the postgresql terminal layer; kingbase is a dialect variant of the same
// layer (design §2.2/§4.3), so it reuses this config with Dialect="kingbase".
type PostgreSQLConfig struct {
	// Dialect selects the content/port variant of the shared PG v3 wire layer:
	// "postgresql" (default port 5432) or "kingbase" (default port 54321).
	Dialect string `json:"dialect,omitempty"`

	// WireProfile selects the version/compatibility-mode template name. For
	// dialect=postgresql this is "postgresql_v3"; for dialect=kingbase it is a
	// KingBase-compatible profile (e.g. "kingbase_es_v8_pg_compatible"). It is
	// NOT encoded into the wire bytes directly; it selects the event-encoding
	// template set.
	WireProfile string `json:"wire_profile,omitempty"`

	// Events is the ordered application-event sequence (Startup/Auth/Ready/
	// Query/...). Empty with no sessions = TCP-connect-only flow.
	Events []PostgreSQLEvent `json:"events,omitempty"`

	// Sessions, when non-empty, carries independent sessions (each with its own
	// src_port and event flow). Mutually exclusive with Events in practice.
	Sessions []PostgreSQLSession `json:"sessions,omitempty"`

	// WireFault drives the negative-path planner/validator boundary faults
	// (wire_fault). Only for negative cases; not a legal wire frame.
	WireFault json.RawMessage `json:"wire_fault,omitempty"`

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

	// ErrorFields holds ErrorResponse or NoticeResponse fields (the two
	// share the same field structure). Used by:
	//   - "query" kind: when non-empty, the planner emits ErrorResponse
	//     (E) + ReadyForQuery instead of the normal RowDescription /
	//     DataRow / CommandComplete response. If the session is in a
	//     transaction (status 'T'), the ReadyForQuery status flips to
	//     'E' (failed transaction) per PostgreSQL §52.2.
	//   - "error" kind: standalone ErrorResponse + ReadyForQuery.
	//   - "notice" kind: standalone NoticeResponse (server->client push,
	//     no client request, no ReadyForQuery).
	ErrorFields []PGErrorField `json:"error_fields,omitempty"`

	// ErrorSegment (1-indexed) specifies which segment of a multi-statement
	// query the error occurs at. Only meaningful when ErrorFields is
	// non-empty and SQL contains ';'. Segments before ErrorSegment produce
	// their normal result sets; the ErrorSegment and all subsequent
	// segments are cancelled (ErrorResponse + ReadyForQuery).
	// 0 (default) = if SQL contains ';', error at segment 2 (the common
	// "first statement succeeds, second fails" pattern); if no ';',
	// error is immediate.
	ErrorSegment int `json:"error_segment,omitempty"`

	// ExpectNoData: when true on a "describe" kind operation, the planner
	// emits NoData ('n') instead of RowDescription ('T'). This models
	// non-SELECT prepared statements (INSERT/UPDATE/DELETE without
	// RETURNING) per PostgreSQL §52.7 Describe-portal/statement rules.
	// For Mode="statement", the planner also emits ParameterDescription
	// ('t') before NoData/RowDescription regardless of this flag.
	ExpectNoData bool `json:"expect_no_data,omitempty"`
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
	Banner   string        `json:"banner,omitempty"` // server greeting, e.g. "+OK POP3 server ready"; empty = skip
	Commands []POP3Command `json:"commands"`
	Mailbox  *POP3Mailbox  `json:"mailbox,omitempty"`
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

	// EmitTop: when true, the planner synthesizes a TOP-style multi-line
	// response from Mailbox.Messages[MsgNum-1]: the message headers, a
	// blank line, then the first TopLines lines of the body, per
	// RFC 1939 §6 TOP. Requires Mailbox; Validate rejects EmitTop=true
	// with nil Mailbox, out-of-range MsgNum, or when EmitMailDrop is
	// also true (mutually exclusive). The status line is "+OK" (no size,
	// matching RFC 1939 §6 TOP). Dot-stuffing applies per RFC 1939 §3.
	EmitTop bool `json:"emit_top,omitempty"`

	// TopLines: number of body lines to emit for EmitTop (RFC 1939 §6
	// TOP "n" argument). 0 = headers only. Ignored when EmitTop is false.
	TopLines uint32 `json:"top_lines,omitempty"`

	// MsgNum: 1-based message number for EmitMailDrop/EmitTop. Ignored
	// when both are false. Out-of-range -> Validate returns error.
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
	//
	// When MIMEParts is non-empty, Body is ignored: the planner builds a
	// multipart/mixed body from MIMEParts instead (RFC 2046 §5.1.1).
	// This keeps backward compatibility: existing specs using Body keep
	// working, and new specs use MIMEParts for rich mail content.
	Body string `json:"body,omitempty"`

	// MIMEParts: optional MIME multipart parts (RFC 2046 §5.1.1). When
	// non-empty, the planner synthesizes a multipart/mixed body: a
	// "MIME-Version: 1.0" header and a "Content-Type: multipart/mixed;
	// boundary=..." header are added to the message headers, then each
	// part is emitted between "--<boundary>" delimiters, terminated by
	// "--<boundary>--". Each part's Body/BodyB64 is dot-stuffed per
	// RFC 1939 §3 (dot-stuffing applies to the entire message body).
	// When empty, the simple Body field is used (no MIME headers).
	MIMEParts []POP3MIMEPart `json:"mime_parts,omitempty"`

	// Boundary: the multipart boundary string (RFC 2046 §5.1.1). When
	// MIMEParts is non-empty and Boundary is empty, the planner generates
	// a deterministic boundary (e.g. "----=_POP3_BOUND_0001"). The
	// boundary must not appear within any part body (RFC 2046 §5.1.1);
	// the user is responsible for choosing a unique boundary.
	Boundary string `json:"boundary,omitempty"`

	// Size: total size in octets (headers + blank line + body). 0 =
	// planner computes from Headers + Body. Used in the "+OK <size> octets"
	// status line of the RETR response.
	Size uint32 `json:"size,omitempty"`
}

// POP3MIMEPart is a single part within a multipart MIME message
// (RFC 2046 §5.1.1). Each part has its own headers (Content-Type,
// Content-Transfer-Encoding, Content-Disposition, etc.) and a body.
type POP3MIMEPart struct {
	// Headers: part-specific headers as "Name: Value" strings, e.g.
	// "Content-Type: text/plain", "Content-Transfer-Encoding: base64",
	// `Content-Disposition: attachment; filename="x.bin"`. Emitted each
	// followed by CRLF, then a blank line, then the part body.
	Headers []string `json:"headers,omitempty"`

	// Body: the part body as raw text. Used when BodyB64 is empty.
	// Dot-stuffing is applied to the whole message body (including
	// multipart part bodies) per RFC 1939 §3.
	Body string `json:"body,omitempty"`

	// BodyB64: the part body as base64-encoded bytes (RFC 2045 §6.8).
	// When non-empty, takes precedence over Body. Used for binary
	// attachments (images, PDFs, etc.) so the JSON config stays
	// text-safe. The planner does NOT decode it: the base64 text is
	// emitted verbatim as the part body (the client decodes via the
	// Content-Transfer-Encoding: base64 header).
	BodyB64 string `json:"body_b64,omitempty"`
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

	// Scenario selects a built-in end-to-end session template
	// (design_rdp.md §4 + internal/protocol/rdp/scenario.go). When set,
	// the planner auto-populates Channels / DataEvents / ServerResponses
	// with sensible defaults for the named scenario before encoding.
	//
	// Supported scenarios:
	//   ""               - empty Scenario: use whatever Channels /
	//                     DataEvents / ServerResponses the user supplied
	//                     (manual mode, backward compatible).
	//   "full_session"   - complete TLS/NLA/standard RDP session with
	//                     cliprdr/rdpdr/rdpsnd/drdynvc static channels +
	//                     keyboard/mouse input + bitmap output (the
	//                     realistic Win10 mstsc.exe flow).
	//   "multi_channel"  - 4 static virtual channels with Channel-Join
	//                     Confirms but no active-phase payload.
	//   "cliprdr"        - clipboard redirection: cliprdr channel +
	//                     CB_FORMAT_LIST exchange.
	//   "rdpdr"          - device redirection: rdpdr channel +
	//                     PAKID_CORE_DEVICELIST_ANNOUNCE.
	//   "input_events"   - one keyboard and one mouse FastPath Input.
	//   "bitmap_update"  - one FastPath Output Bitmap Update.
	//   "channel_join_failure" - multi-channel session where the server
	//                     rejects the second Channel-Join with
	//                     rt-no-such-channel (result=4).
	//   "disconnect"     - minimal session that ends with Shutdown
	//                     Request + MCS Disconnect Provider Ultimatum
	//                     (reason=user-requested, 0x80) + TCP teardown.
	//
	// When Scenario is set, user-supplied Channels / DataEvents /
	// ServerResponses are PRESERVED (forwarder-style override): the
	// scenario only fills in empty slots. This mirrors the
	// design_rdp.md §6.2 rule "use defaults, override where user
	// supplied".
	Scenario string `json:"scenario,omitempty"`

	// DataEvents are Active-phase payloads (client→server).
	DataEvents []RDPDataEvent `json:"data_events,omitempty"`

	// ServerResponses are simulated server replies during the session.
	ServerResponses []RDPServerResponse `json:"server_responses,omitempty"`
}

// RDPChannel is a single static virtual channel declaration
// (MS-RDPBCGR §2.2.1.3.4 ChannelDef). Name is a 7-char ASCII string
// padded to 8 bytes on the wire. Options bitmask:
//
//	0x00400000 REMOTE, 0x00800000 COMPRESS, 0x01000000 COMPRESS_RDP,
//	0x02000000 SHOW_PROTOCOL, 0x04000000 ENCRYPT_CS, 0x08000000 ENCRYPT_SC.
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
	RedisAutoReplyNone    = "none" // default
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

	// Email, when set, makes the planner auto-construct a complete RFC
	// 5322 / RFC 2045 MIME email body for the DATA phase instead of
	// requiring the user to hand-write the body as a Dialog Cmd. This
	// enables declarative multipart/mixed emails with base64-encoded
	// binary attachments (RFC 2045 §6.8, RFC 2046 §5.1.1).
	//
	// When Email is set, the planner injects a DATA body packet
	// (constructed from Email fields) at the point where a body Cmd
	// would appear, followed by an auto-emitted 250 response. The user
	// must NOT include a body command in Dialog when Email is set (a
	// DATA/354 pair in Dialog is still required; the body is injected
	// after the 354 response).
	//
	// When Email is nil, the planner plays back the Dialog verbatim,
	// preserving backward compatibility (the user hand-writes the body
	// Cmd ending with "\r\n." so the planner's appended "\r\n" completes
	// the "\r\n.\r\n" terminator per RFC 5321 §4.1.1.4).
	Email *SMTPEmail `json:"email,omitempty"`

	// Dialog is the SMTP command/response sequence (executed in order).
	// When nil/empty, the planner emits a default session per §6.6.
	Dialog []SMTPCommand `json:"dialog"`

	// MSS is governed by TCPConfig.MSS. SMTP runs over TCP, so the
	// planner reads spec.TCP.MSS for segmentation of long SMTP payloads.
}

// SMTPEmail describes a declaratively-constructed email body for the
// SMTP DATA phase (RFC 5322 message + RFC 2045 MIME). The planner
// assembles the full DATA body from these fields, applies dot-stuffing
// (RFC 5321 §4.5.2), and terminates with "\r\n.\r\n" (RFC 5321
// §4.1.1.4).
//
// Body precedence when no attachments are present:
//   - HTMLBody set, TextBody empty: a single text/html part (RFC 2046).
//   - TextBody set, HTMLBody empty: simple text body, NOT wrapped in
//     MIME (no MIME-Version/Content-Type emitted). This keeps trivial
//     text emails wire-compatible with non-MIME clients.
//   - Both set: a multipart/alternative part (RFC 2046 §5.1.4).
//
// When Attachments is non-empty, the email is always multipart/mixed
// (RFC 2046 §5.1.1): the first part is either the text body, the HTML
// body, or a multipart/alternative containing both; subsequent parts are
// the attachments, each base64-encoded (RFC 2045 §6.8) unless the user
// provides DataB64 verbatim.
type SMTPEmail struct {
	// Headers: top-level RFC 5322 message headers as "Name: Value"
	// strings (e.g. "From: alice@example.org", "Subject: Hello"). The
	// planner emits each followed by CRLF. MIME-Version and
	// Content-Type (multipart) headers are auto-prepended by the planner
	// when the email is multipart; the user should NOT include them.
	Headers []string `json:"headers,omitempty"`

	// TextBody: the plain-text body (Content-Type: text/plain). When
	// no attachments are present and HTMLBody is empty, the text is
	// emitted as the raw body (no MIME wrapping) for wire compatibility.
	TextBody string `json:"text_body,omitempty"`

	// HTMLBody: the HTML body (Content-Type: text/html). When set
	// without TextBody and without attachments, emitted as a single
	// text/html part (MIME-Version + Content-Type emitted). When set
	// alongside TextBody, both go into a multipart/alternative.
	HTMLBody string `json:"html_body,omitempty"`

	// Attachments: binary attachments, each emitted as a separate
	// multipart/mixed part with base64 Content-Transfer-Encoding (RFC
	// 2045 §6.8). When non-empty, the email becomes multipart/mixed.
	Attachments []SMTPAttachment `json:"attachments,omitempty"`

	// Boundary: the multipart boundary string (RFC 2046 §5.1.1). When
	// empty and the email is multipart, the planner generates a
	// deterministic boundary. The boundary must not contain CRLF and
	// must be <= 70 chars (RFC 2046 §5.1.1); the planner validates
	// these.
	Boundary string `json:"boundary,omitempty"`
}

// SMTPAttachment is a single binary attachment in a multipart/mixed
// email (RFC 2046 §5.1.1). The planner base64-encodes Data (RFC 2045
// §6.8) and wraps it at 76 chars per line. When DataB64 is set, it is
// emitted verbatim (the planner does NOT decode+re-encode).
type SMTPAttachment struct {
	// Filename: the attachment filename, emitted in
	// Content-Disposition: attachment; filename="<Filename>" (RFC 2183).
	Filename string `json:"filename,omitempty"`

	// ContentType: the MIME media type (e.g.
	// "application/octet-stream", "image/png"). Empty defaults to
	// "application/octet-stream" (RFC 2046 §4).
	ContentType string `json:"content_type,omitempty"`

	// Data: the raw attachment bytes. The planner base64-encodes these
	// (RFC 2045 §6.8) and wraps at 76 chars/line. When DataB64 is set,
	// Data is ignored.
	Data []byte `json:"data,omitempty"`

	// DataB64: pre-base64-encoded attachment bytes. Emitted verbatim
	// (the planner does NOT decode+re-encode; it trusts the user's
	// encoding). Takes precedence over Data. Useful for embedding
	// binary data in JSON configs.
	DataB64 string `json:"data_b64,omitempty"`
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

	// v1 Trap-specific fields (RFC 1157 §4.1.6, v1 陷阱专用字段). Used only
	// when PDUType=TrapV1. The v1 Trap PDU has a special layout (enterprise
	// OID + agent-addr + generic-trap + specific-trap + time-stamp +
	// varbinds) that differs from the standard PDU (no request-id /
	// error-status / error-index).
	Enterprise   string `json:"enterprise"`    // v1 Trap enterprise OID (default "1.3.6.1.4.1.3.1.1")
	AgentAddr    string `json:"agent_addr"`    // v1 Trap agent IPv4 address (default "0.0.0.0")
	GenericTrap  uint8  `json:"generic_trap"`  // v1 Trap generic trap code 0-6 (0=coldStart, 2=linkDown, 6=enterpriseSpecific)
	SpecificTrap uint8  `json:"specific_trap"` // v1 Trap enterprise-specific trap code (meaningful when generic_trap=6)
	TimeStamp    uint32 `json:"time_stamp"`    // v1 Trap sysUpTime in centiseconds (TimeTicks)

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

	// Scenario selects an auto-generated complete-session dialog (RFC 4253
	// transport + RFC 4254 connection). When set, the planner synthesizes
	// AuthMethods + Channels from the RFC state machine; the manual
	// AuthMethods/Channels fields are ignored. Empty = manual mode
	// (backward-compatible). One of:
	//   exec            - password auth + exec request + stdout + EOF + close
	//   shell           - password auth + pty-req + shell + interactive data
	//   pty-exec        - password auth + pty-req + exec + stdout
	//   publickey       - publickey auth (probe + signed) + exec session
	//   auth_fail_retry - password failure + retry success + exec session
	//   long_output     - exec with multi-packet stdout + stderr
	Scenario string `json:"scenario,omitempty"`

	// Command is the exec command string used by exec/pty-exec/long_output
	// scenarios. Empty = "uname -a". Ignored in manual mode.
	Command string `json:"command,omitempty"`

	// Stdout is the stdout byte payload emitted as CHANNEL_DATA (server->client)
	// in exec/pty-exec/shell/long_output scenarios. Empty = representative
	// default. Ignored in manual mode.
	Stdout []byte `json:"stdout,omitempty"`

	// Stderr is the stderr byte payload emitted as CHANNEL_EXTENDED_DATA
	// (data_type_code=1) in the long_output scenario. Empty = no stderr.
	// Ignored in manual mode.
	Stderr []byte `json:"stderr,omitempty"`
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
	MethodName         string `json:"method_name,omitempty"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	HasPasswordChange  bool   `json:"has_password_change,omitempty"`
	NewPassword        string `json:"new_password,omitempty"`
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	PublicKeyBlob      []byte `json:"public_key_blob,omitempty"`
	HasSignature       bool   `json:"has_signature,omitempty"`
	Signature          []byte `json:"signature,omitempty"`
	Submethods         string `json:"submethods,omitempty"`
	Prompt             string `json:"prompt,omitempty"`
	Response           string `json:"response,omitempty"`

	// --- USERAUTH_FAILURE fields ---
	AuthMethodsThatCanContinue string `json:"auth_methods_that_can_continue,omitempty"`
	PartialSuccess             bool   `json:"partial_success,omitempty"`

	// --- USERAUTH_BANNER fields ---
	Banner      string `json:"banner,omitempty"`
	LanguageTag string `json:"language_tag,omitempty"`

	// --- USerauth_INFO_REQUEST fields ---
	Name         string `json:"name,omitempty"`
	Instruction  string `json:"instruction,omitempty"`
	PromptCount  uint32 `json:"prompt_count,omitempty"`
	Prompts      string `json:"prompts,omitempty"`
	Echo         bool   `json:"echo,omitempty"`
	NumResponses uint32 `json:"num_responses,omitempty"`
	Responses    string `json:"responses,omitempty"`

	// --- DISCONNECT fields ---
	ReasonCode  uint32 `json:"reason_code,omitempty"`
	Description string `json:"description,omitempty"`

	// --- UNIMPLEMENTED fields ---
	ReceiveSeq uint32 `json:"receive_seq,omitempty"`

	// --- DEBUG fields ---
	AlwaysDisplay bool   `json:"always_display,omitempty"`
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
	// Ignored when Messages is non-empty (Messages drives per-message
	// variation; Count emits N identical copies of the single Msg/SD).
	Count uint32 `json:"count,omitempty"`
	// SignBlocks carries RFC 5848 syslog-sign signature values. Each value
	// is wrapped as `[sign@32473 signature="<value>"]` and appended to
	// STRUCTURED-DATA. The planner escapes `"`, `\`, `]` per RFC 5424 §6.2.8.
	SignBlocks []string `json:"sign_blocks,omitempty"`
	// Messages is a list of per-message overrides (RFC 5424 §3.4 stream).
	// When non-empty, the planner emits one datagram/frame per entry with
	// the entry's Msg/StructuredData/MsgID/MsgHasBOM/Timestamp/AppName/
	// ProcID/Hostname overriding the top-level fields. This enables
	// testcases_syslog.md §3.3.2 (per-message sequenceId) and §3.4.2
	// (per-message MSG length variation) without spawning N flows.
	// Facility/Severity/Version/Format/Transport/TCPFraming are shared
	// across all messages (they are protocol-level, not per-message).
	// Count is ignored when Messages is set.
	Messages []SyslogMessage `json:"messages,omitempty"`
}

// SyslogMessage is a single per-message override entry used when
// SyslogConfig.Messages is non-empty. Each field overrides the
// corresponding top-level SyslogConfig field for this one message.
// Zero-value fields fall back to the top-level config (so an entry
// with only Msg set inherits StructuredData/MsgID/etc from the parent).
type SyslogMessage struct {
	// Timestamp overrides SyslogConfig.Timestamp for this message.
	// Empty = inherit parent Timestamp (which itself may be "" -> NILVALUE).
	Timestamp string `json:"timestamp,omitempty"`
	// Hostname overrides SyslogConfig.Hostname for this message.
	Hostname string `json:"hostname,omitempty"`
	// AppName overrides SyslogConfig.AppName for this message.
	AppName string `json:"app_name,omitempty"`
	// ProcID overrides SyslogConfig.ProcID for this message.
	ProcID string `json:"proc_id,omitempty"`
	// MsgID overrides SyslogConfig.MsgID for this message.
	MsgID string `json:"msg_id,omitempty"`
	// StructuredData overrides SyslogConfig.StructuredData for this
	// message. nil/empty = inherit parent SD (which may be nil -> NILVALUE).
	StructuredData []string `json:"structured_data,omitempty"`
	// Msg overrides SyslogConfig.Msg for this message.
	Msg string `json:"msg,omitempty"`
	// MsgHasBOM overrides SyslogConfig.MsgHasBOM for this message.
	MsgHasBOM bool `json:"msg_has_bom,omitempty"`
	// SignBlocks overrides SyslogConfig.SignBlocks for this message.
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

	// Scenario selects an auto-generated Telnet dialog (RFC 854/855 full
	// interactive session) instead of a manual Dialog list. When set, the
	// planner synthesizes the Dialog at Plan time; the user supplies only
	// session parameters (Username, Password, Commands, TerminalType,
	// WindowCols/Rows). The manual Dialog field is ignored in scenario mode.
	// Empty = manual mode (use Dialog), backward-compatible.
	// Supported values (design_telnet.md §4):
	//   "login_full"    - full session: option negotiation (WILL/DO Echo,
	//                      SGA, TTYPE, NAWS) + SB TTYPE SEND/IS + SB NAWS +
	//                      login (login:/Password:) + multi-command exec +
	//                      logout (exit/logout).
	//   "login_fail"    - authentication failure path: negotiation + login +
	//                      wrong password -> "Login incorrect" + re-prompt.
	//   "multi_command" - post-login multiple command executions, each with
	//                      a server response line + shell prompt.
	//   "long_output"   - server response larger than MSS, forcing multiple
	//                      PSH-ACK segments (tests MSS segmentation).
	//   "option_reject" - option negotiation refusal: server WILL NEW-ENVIRON
	//                      -> client DONT (reject), client WILL LINEMODE ->
	//                      server DONT (reject). RFC 855 §3 refusal path.
	//   "synch"         - SYNCH signal (IAC IP + IAC DM, RFC 854 §3)
	//                      interrupting a long server output.
	Scenario string `json:"scenario,omitempty"`

	// Username is the login username used by login_* scenarios. Default
	// "alice". Only consulted when Scenario != "".
	Username string `json:"username,omitempty"`

	// Password is the login password used by login_* scenarios. Default
	// "secret123". In login_fail this is the wrong password.
	Password string `json:"password,omitempty"`

	// Commands is the list of shell commands executed by multi_command and
	// login_full scenarios. Each command produces a one-line response.
	// Default ["ls -la", "whoami"]. Only consulted when Scenario != "".
	Commands []string `json:"commands,omitempty"`
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
	Subject   string   `json:"subject,omitempty"`    // 自定义 subject (CN=...,O=...)
	San       []string `json:"san,omitempty"`        // DNS SANs
	NotBefore int64    `json:"not_before,omitempty"` // unix seconds; 0 = now
	NotAfter  int64    `json:"not_after,omitempty"`  // unix seconds; 0 = now+30d
	KeyType   string   `json:"key_type,omitempty"`   // "rsa-2048"/"rsa-4096"/"ecdsa-p256"
	// FileSource 提供预生成的 p12/der 证书文件。
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// PSKIdentity (预共享密钥身份) 用于 TLS 1.3 PSK 会话恢复。
type PSKIdentity struct {
	Identity      []byte `json:"identity,omitempty"`       // PSK identity 字节
	ObfuscatedAge uint32 `json:"obfuscated_age,omitempty"` // 混淆年龄 (用于 binder)
}

// AlertStep (警报步骤) 配置服务器在握手某个阶段后发送 Alert。
type AlertStep struct {
	After       string `json:"after,omitempty"`       // "server_hello", "certificate", "server_hello_done"
	Description uint8  `json:"description,omitempty"` // RFC AlertDescription 编码
	Level       uint8  `json:"level,omitempty"`       // 1=warning, 2=fatal
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

	// InnerIP (内层 IP) configures the inner IPv4/IPv6 packet carried inside
	// Transport Data (type=4 enc_payload). When set, the planner builds
	// complete inner IP packets (header + L4 + payload) and uses them as the
	// transport payloads, taking precedence over TransportPayloads (but
	// FileSource still wins over both). This is the dual-encapsulation tunnel
	// scenario (外层 UDP/WG + 内层 IP 双层封装): the inner IP header sits at
	// enc_payload offset 16 of the Transport Data message. WireGuard tunnels
	// both IPv4 and IPv6 (RFC 791 / RFC 8200); the address family is inferred
	// from SrcIP/DstIP.
	InnerIP *WireGuardInnerIP `json:"inner_ip,omitempty"`
}

// WireGuardInnerIP describes the inner IPv4/IPv6 packet encapsulated as
// WireGuard Transport Data payload (type=4 enc_payload). The planner builds
// a complete inner IP header (with a correct checksum for IPv4, RFC 791
// §3.1) + optional L4 header + payload per RFC 791 (IPv4) / RFC 8200
// (IPv6) / RFC 768 (UDP) / RFC 793 (TCP) / RFC 792 (ICMP). Mirrors the
// L2TPInnerIP / ESPDataPlaneConfig tunnel patterns.
type WireGuardInnerIP struct {
	// SrcIP is the inner source IP. Empty = "10.10.10.1" (IPv4 default).
	// May be IPv4 or IPv6; must match DstIP's family.
	SrcIP string `json:"src_ip,omitempty"`
	// DstIP is the inner destination IP. Empty = "10.10.10.2" (IPv4 default).
	DstIP string `json:"dst_ip,omitempty"`
	// Proto is the inner IP protocol number (RFC 790). Supported: 1 (ICMP),
	// 6 (TCP), 17 (UDP). Default 17 (UDP).
	Proto uint8 `json:"proto,omitempty"`
	// SrcPort is the inner L4 source port (TCP/UDP only; ignored for ICMP).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort is the inner L4 destination port (TCP/UDP only; ignored for
	// ICMP).
	DstPort uint16 `json:"dst_port,omitempty"`
	// TTL is the inner IPv4 TTL / IPv6 HopLimit. 0 = 64.
	TTL uint8 `json:"ttl,omitempty"`
	// Payload is the inner L4 payload bytes. For TCP, prepended after the
	// 20-byte TCP header (no options). For UDP, after the 8-byte header.
	// For ICMP, after the 8-byte echo header.
	Payload []byte `json:"payload,omitempty"`
	// DataFrames is the number of inner IP packets to emit (each as a
	// separate Transport Data message with an incrementing counter). Each
	// frame gets a distinct inner IPID (IPv4) / Flow Label (IPv6). 0 = 1
	// frame.
	DataFrames int `json:"data_frames,omitempty"`
}

// SocksConfig holds SOCKS proxy protocol configuration. Two versions are
// supported, selected by Version:
//
//   - "socks5" (default, RFC 1928 + RFC 1929): fixed four/five-phase
//     negotiation on one TCP connection — greeting (up) → method response
//     (down) → [auth request/response when AuthMethod=password] → request
//     (up) → reply (down). After a successful reply (Rep=0), Data messages
//     are tunneled verbatim over the same TCP connection (CONNECT/BIND),
//     or a UDP relay sub-flow is emitted (Cmd=udp_associate).
//   - "socks4" (SOCKS4/4a, no RFC): two-phase — request (up) → reply
//     (down), then tunneled Data. Domain targets use the SOCKS4a
//     extension (DSTIP=0.0.0.1 + domain after the USERID terminator,
//     no length prefix, 0x00-terminated). No auth, no UDP.
//
// Reference pcaps (llcj dport=1080, 24 files) contain both versions:
// SOCKS5 sessions are `05 01 00` / `05 00` / `05 01 00 03 0f
// www.example.com 00 50` / `05 00 00 01 00 00 00 00 00 00` (no data
// plane); SOCKS4 sessions are `04 01 00 50 5d b8 d8 77 00` /
// `00 5a df b2 0a b4 9c f9` followed by tunneled HTTP.
//
// The signaling phase order is protocol-fixed and auto-generated from the
// config (unlike RTSP's user-driven Dialog). Data is a list of tunneled
// application messages emitted after the reply when Rep=0.
type SocksConfig struct {
	// Version (版本): "socks5" (default) or "socks4".
	Version string `json:"version,omitempty"`

	// AuthMethod (认证方法): "no_auth" (default, 0x00) or "password"
	// (0x02, RFC 1929). SOCKS5 only; SOCKS4 has no auth phase. GSSAPI
	// (0x01) is not supported.
	AuthMethod string `json:"auth_method,omitempty"`

	// Username/Password (用户名/密码): used when AuthMethod="password".
	// Defaults "user"/"pass" when empty.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Cmd (命令): "connect" (default, 0x01), "bind" (0x02), or
	// "udp_associate" (0x03, SOCKS5 only).
	Cmd string `json:"cmd,omitempty"`

	// DstAddr/DstPort (目标地址/端口): the CONNECT target. DstAddr may be
	// an IPv4/IPv6 address (ATYP auto-inferred 1/4) or a domain name
	// (ATYP=3 for SOCKS5, SOCKS4a for SOCKS4). Empty defaults
	// "www.example.com":80 (reference pcap target).
	DstAddr string `json:"dst_addr,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	// Rep (回复码): SOCKS5 REP (0-8, 0=success) / SOCKS4 result
	// (0=granted). 0 emits Data/UDP sub-flow; non-zero suppresses them
	// (RFC 1928: connection closes on failure).
	Rep int `json:"rep,omitempty"`

	// BndAddr/BndPort (绑定地址/端口): reply BND.ADDR/BND.PORT. Empty
	// defaults 0.0.0.0:0 (reference pcap reply bytes).
	BndAddr string `json:"bnd_addr,omitempty"`
	BndPort uint16 `json:"bnd_port,omitempty"`

	// UserID (用户标识): SOCKS4 request USERID. Empty emits just the
	// 0x00 terminator (reference pcap).
	UserID string `json:"user_id,omitempty"`

	// Data (隧道数据面): tunneled application messages emitted after the
	// reply when Rep=0, in list order, each as one PSH-ACK segment
	// (MSS-segmented if oversized). Reference SOCKS4 pcaps carry tunneled
	// HTTP GET/200 here.
	Data []SocksDataMessage `json:"data,omitempty"`

	// UDP (UDP中继子面): SOCKS5 udp_associate relay config. When set,
	// the planner emits UDP datagrams after the reply, each prefixed
	// with the RFC 1928 §7 header (RSV+FRAG+ATYP+ADDR+PORT).
	UDP *Socks5UDP `json:"udp,omitempty"`
}

// SocksDataMessage is one tunneled application message on the SOCKS data
// plane. Direction "up" = client→proxy (e.g. reference HTTP GET), "down"
// = proxy→client (HTTP 200 response). Empty Direction defaults "up".
type SocksDataMessage struct {
	Direction  string                 `json:"direction,omitempty"`
	Payload    string                 `json:"payload,omitempty"`
	FileSource *filesystem.FileSource `json:"file_source,omitempty"`
}

// Socks5UDP describes the UDP relay sub-flow for SOCKS5 udp_associate
// (RFC 1928 §7). After the reply, the planner emits Frames UDP datagrams,
// each = 10-byte relay header (RSV 0x0000 + FRAG 0x00 + ATYP + ADDR +
// PORT of the relay target) + FrameSize bytes of payload. SrcPort/DstPort
// are the proxy/relay and client relay ports; Direction "down" (default)
// = proxy→client.
type Socks5UDP struct {
	SrcPort   uint16 `json:"src_port,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	Frames    int    `json:"frames,omitempty"`
	FrameSize int    `json:"frame_size,omitempty"`
	DstAddr   string `json:"dst_addr,omitempty"`
	Direction string `json:"direction,omitempty"`
}

// RTMPConfig holds Adobe RTMP (Real-Time Messaging Protocol) 配置.
// RTMP 是基于 TCP 的流媒体协议 (端口 1935),用于音视频流的推拉.
// 参考 pcap: llcj_mirror/IP-TCP-20.7.1.84-30.7.1.84-50216-1935-...
//
// RTMP 会话流程:
//  1. TCP 三次握手 (SYN/SYN-ACK/ACK) + TCP 选项 (MSS/WinScale/SACK)
//  2. RTMP 握手: C0+C1 (客户端, 1537字节) → S0+S1+S2 (服务端, 3073字节) → C2 (客户端, 1536字节)
//  3. 命令阶段: connect() → Window Ack Size / Set Peer Bandwidth / Stream Begin /
//     Set Chunk Size / _result() → Window Ack Size → createStream() → Set Buffer Length →
//     _result() → play()/publish()
//  4. 数据阶段 (可选): 音视频 chunk 流
//  5. TCP 四次挥手 (FIN/FIN-ACK/ACK)
//
// 所有命令使用 AMF0 (Action Message Format 0) 编码,封装在 RTMP chunk 中.
// Chunk 格式: 基本头部(1字节) + 消息头部(11/7/3字节) + chunk 数据.
// 所有 chunk 均使用 type 0 头部 (12字节完整头部, chunk stream ID=3).
type RTMPConfig struct {
	// App (应用名): RTMP connect 命令中的 app 属性.
	// 空值默认为 "live" (参考 pcap 默认值).
	App string `json:"app,omitempty"`

	// TcURL (TC URL): connect 命令中的 tcUrl 属性.
	// 空值默认为 "rtmp://<DstIP>/<App>" (自动构造).
	TcURL string `json:"tc_url,omitempty"`

	// Command (命令类型): "play" (默认,拉流) 或 "publish" (推流).
	// 决定第三阶段的命令是 play() 还是 publish().
	Command string `json:"command,omitempty"`

	// StreamName (流名称): play/publish 命令中的流名称.
	// 空值默认为 "stream" (参考 pcap).
	StreamName string `json:"stream_name,omitempty"`

	// Data (数据面): 握手和命令阶段完成后的音视频 chunk 列表.
	// 每个 RTMPDataChunk 作为一条独立的 PSH-ACK TCP 段发送.
	// MsgType=8 表示音频, MsgType=9 表示视频 (参考 RTMP 规范 §11.4).
	// 空列表表示无数据面 (仅完成握手和命令).
	Data []RTMPDataChunk `json:"data,omitempty"`
}

// RTMPDataChunk 是 RTMP 数据阶段的一条音视频消息.
// 每条消息封装为一个 RTMP chunk (type 0 头部, 12字节) 通过 TCP 发送.
// MsgType=8 (0x08) = 音频数据 (Audio Data), MsgType=9 (0x09) = 视频数据 (Video Data).
// ChunkStreamID 音频默认 4, 视频默认 6 (参考 pcap chunk stream ID 分配).
type RTMPDataChunk struct {
	// Direction (方向): "up" = 客户端→服务端 (publish推流),
	// "down" = 服务端→客户端 (play拉流). 空值默认为 "down".
	Direction string `json:"direction,omitempty"`

	// MsgType (消息类型): RTMP 消息类型 ID.
	// 8 (0x08) = 音频数据, 9 (0x09) = 视频数据.
	// 空值默认为 9 (视频).
	MsgType uint8 `json:"msg_type,omitempty"`

	// ChunkStreamID (chunk 流 ID): RTMP chunk stream 标识符.
	// 音频默认 4, 视频默认 6. 0 表示自动选择 (按 MsgType).
	ChunkStreamID uint8 `json:"chunk_stream_id,omitempty"`

	// Payload (载荷): chunk 数据字节 (不含 RTMP chunk 头部).
	// 空值自动生成 100 字节随机数据 (模拟音视频帧).
	Payload []byte `json:"payload,omitempty"`
}

// NGAPConfig holds NGAP (Next Generation Application Protocol, 5G核心网信令协议)
// configuration for the NGAP planner. NGAP is defined in 3GPP TS 38.413 and
// runs over SCTP (端口 38412, PPID=60). It carries signaling between gNB
// (基站) and AMF (接入管理功能).
//
// The planner emits:
//  1. SCTP 4-way handshake (INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK)
//  2. NG Setup procedure (NGSetupRequest gNB→AMF, NGSetupResponse AMF→gNB)
//  3. Optional: InitialUEMessage (gNB→AMF)
//  4. Optional: DownlinkNASTransport (AMF→gNB)
//  5. Optional: UplinkNASTransport (gNB→AMF)
//  6. Optional: PDUSessionResourceSetupRequest/Response
//  7. Optional: UEContextReleaseCommand/Complete
//  8. SCTP 3-way teardown (SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE)
//
// Messages use simplified ASN.1 PER encoding patterns — recognizable by DPI
// but not full-compliance with 3GPP TS 38.413 encoding rules. The planner
// builds correct NGAP-PDU structures: choice index + procedureCode +
// criticality + protocolIEs.
//
// Reference pcap: SCTP_NAS.pcap (1 packet: InitialUEMessage with Registration
// Request, PPID=60, SCTP ports 38413→38412).
type NGAPConfig struct {
	// GlobalRANNodeID (全局RAN节点标识): the gNB identifier carried in
	// NGSetupRequest. Default: PLMN MCC=460 MNC=01 + gNB ID=0x000001.
	// The planner builds a simplified but structurally valid
	// GlobalRANNodeID IE (ProtocolIE id=72, criticality=reject).
	GlobalRANNodeID *NGAPGlobalRANNodeID `json:"global_ran_node_id,omitempty"`

	// SupportedTAList (支持的TA列表): Tracking Area list carried in
	// NGSetupRequest. Default: one TAI with PLMN MCC=460 MNC=01, TAC=1.
	// Each entry has a PLMN identity and one or more TACs.
	SupportedTAList []NGAPSupportedTA `json:"supported_ta_list,omitempty"`

	// DefaultPagingDRX (默认寻呼DRX): paging DRX (非连续接收) value in
	// NGSetupRequest. Values: 0=vrf128, 1=vrf256, 2=vrf512, 3=vrf1024.
	// Default 0 (vrf128).
	DefaultPagingDRX int `json:"default_paging_drx,omitempty"`

	// AMFName (AMF名称): the AMF name returned in NGSetupResponse.
	// Default "AMF-TEST-01". Carried as a PrintableString IE.
	AMFName string `json:"amf_name,omitempty"`

	// UplinkNAS (上行NAS消息): optional NAS-PDU bytes to carry in
	// UplinkNASTransport after NG Setup completes. The planner wraps
	// these bytes in a minimal UplinkNASTransport PDU (procedureCode=46).
	// When nil, no UplinkNASTransport is emitted.
	UplinkNAS []byte `json:"uplink_nas,omitempty"`

	// DownlinkNAS (下行NAS消息): optional NAS-PDU bytes to carry in
	// DownlinkNASTransport. The planner emits it as a response from AMF
	// (procedureCode=4). When nil, no DownlinkNASTransport is emitted.
	DownlinkNAS []byte `json:"downlink_nas,omitempty"`

	// PDUSessionSetup (PDU会话建立): when non-nil, the planner emits a
	// PDUSessionResourceSetupRequest (AMF→gNB) followed by a
	// PDUSessionResourceSetupResponse (gNB→AMF) after NG Setup.
	PDUSessionSetup *NGAPPDUSessionSetup `json:"pdu_session_setup,omitempty"`

	// UEContextRelease (UE上下文释放): when true, the planner emits a
	// UEContextReleaseCommand (AMF→gNB) followed by
	// UEContextReleaseComplete (gNB→AMF) at the end of the session,
	// before SCTP teardown. Default false.
	UEContextRelease bool `json:"ue_context_release,omitempty"`

	// RANUENGAPID (RAN UE NGAP ID): the RAN-side UE identifier used in
	// InitialUEMessage, UplinkNAS, PDUSessionSetup, UEContextRelease.
	// Default 1.
	RANUENGAPID uint32 `json:"ran_ue_ngap_id,omitempty"`

	// AMFUENGAPID (AMF UE NGAP ID): the AMF-side UE identifier used in
	// DownlinkNAS and response messages. Default 1.
	AMFUENGAPID uint32 `json:"amf_ue_ngap_id,omitempty"`

	// InitialUEMessage (初始UE消息): when true, emit InitialUEMessage
	// (procedureCode=15) after NG Setup, carrying the NAS-PDU from
	// InitialNAS (when non-nil) or a minimal Registration Request.
	InitialUEMessage bool `json:"initial_ue_message,omitempty"`

	// InitialNAS (初始NAS): NAS-PDU bytes for the InitialUEMessage.
	// When nil and InitialUEMessage=true, the planner builds a minimal
	// Registration Request NAS-PDU (7e 00 41 79 ...).
	InitialNAS []byte `json:"initial_nas,omitempty"`
}

// NGAPGlobalRANNodeID is the gNB identifier (全球RAN节点标识). It carries
// a PLMN Identity (MCC+MNC, 3 bytes) and a gNB ID (gNB标识, variable length).
// Default: PLMN=46001 (MCC 460 China, MNC 01 China Unicom), gNB ID=0x000001.
type NGAPGlobalRANNodeID struct {
	PLMNMCC int    `json:"plmn_mcc,omitempty"` // Mobile Country Code (移动国家码), default 460
	PLMNMNC int    `json:"plmn_mnc,omitempty"` // Mobile Network Code (移动网络码), default 1
	GNBID   uint32 `json:"gnb_id,omitempty"`   // gNB ID (基站标识), default 1
}

// NGAPSupportedTA is one SupportedTA (支持的跟踪区) entry in NGSetupRequest.
// Each carries a PLMN Identity and one or more TACs (Tracking Area Codes, 跟踪区码).
type NGAPSupportedTA struct {
	PLMNMCC int      `json:"plmn_mcc,omitempty"` // MCC, default 460
	PLMNMNC int      `json:"plmn_mnc,omitempty"` // MNC, default 1
	TACs    []uint32 `json:"tacs,omitempty"`     // TAC list, default [1]
}

// NGAPPDUSessionSetup configures PDUSessionResourceSetup (PDU会话资源建立).
// The planner emits a Request (AMF→gNB) and a Response (gNB→AMF).
type NGAPPDUSessionSetup struct {
	// PDUSessionID (PDU会话ID): 0-255, default 1.
	PDUSessionID int `json:"pdu_session_id,omitempty"`
	// NSSAI (网络切片标识): SST (Slice/Service Type, 切片类型) + SD
	// (Slice Differentiator, 切片区分器). Default SST=1 (eMBB), SD=1.
	SST int    `json:"sst,omitempty"`
	SD  uint32 `json:"sd,omitempty"`
}

// RadiusConfig holds RADIUS (RFC 2865/2866) protocol configuration.
// RADIUS is a UDP request/response AAA protocol: the NAS (Network Access
// Server, 网络接入服务器) sends an Access/Accounting request to the server
// and the server answers with a matching response on the same 4-tuple.
//
// Each flow performs Rounds request/response exchanges. The request uses
// Code/Identifier/Authenticator/Attributes; the response echoes the
// request Identifier, uses ResponseCode (0 = auto-derived from the
// request code), and carries ResponseAttributes.
type RadiusConfig struct {
	// Code (请求报文类型): 1=Access-Request (default), 3=Access-Reject,
	// 4=Accounting-Request, 11=Access-Challenge, 12=Status-Server.
	// Response codes 2/5/13 are rejected at Validate (request side only).
	Code int `json:"code,omitempty"`

	// Identifier (标识符): 1-byte request ID (RFC 2865 §3). Round n uses
	// (Identifier+n-1)&0xFF; the response echoes it (reference pcaps echo).
	Identifier uint8 `json:"identifier,omitempty"`

	// Authenticator (认证子): 16-byte request Authenticator as hex string.
	// Empty generates a fresh random 16 bytes per round (reference pcaps
	// vary per packet). The response Authenticator is always random 16
	// bytes: computing the RFC 2865 §3 MD5 response requires the shared
	// secret, which trafficgen does not model.
	Authenticator string `json:"authenticator,omitempty"`

	// Attributes (请求属性): request attribute list, encoded in order.
	// Empty derives a default set from Code (see DefaultRequestAttrs).
	Attributes []RadiusAttribute `json:"attributes,omitempty"`

	// ResponseCode (响应报文类型): 0 = auto by request code
	// (1→2 Access-Accept, 4→5 Accounting-Response, 12→13 Status-Client).
	// Explicit values must be response codes 2/3/5/11/13 (reference
	// ipv6_radius pcap uses 3=Access-Reject as a response).
	ResponseCode uint8 `json:"response_code,omitempty"`

	// ResponseAttributes (响应属性): response attribute list. Reference
	// pcaps' responses carry none (Length=20).
	ResponseAttributes []RadiusAttribute `json:"response_attributes,omitempty"`

	// Rounds (轮数): request/response exchange count on the same
	// 4-tuple (default 1). The reference ipv6_radius pcap performs 3
	// exchanges per flow with a distinct ID per round.
	Rounds int `json:"rounds,omitempty"`
}

// RadiusAttribute is one RADIUS attribute (RFC 2865 §5): Type(1) +
// Length(1) + Value. Format selects the Value encoding:
//   - "string" (default): raw UTF-8 bytes
//   - "ipv4": 4-byte big-endian IPv4 address
//   - "uint32": 4-byte big-endian unsigned integer
//   - "hex": hex-decoded bytes
//
// When VendorID > 0 the attribute is wrapped as Vendor-Specific (type 26):
// outer Type=26, outer Length=8+inner value length, 4-byte big-endian
// VendorID, then inner VSA (VSA Type=Type, VSA Length, VSA Value).
type RadiusAttribute struct {
	Type     uint8  `json:"type"`
	Format   string `json:"format,omitempty"`
	Value    string `json:"value,omitempty"`
	VendorID uint32 `json:"vendor_id,omitempty"`
}

// LDAPConfig holds LDAP (RFC 4511) protocol configuration. LDAP is a
// BER-encoded directory access protocol over TCP (default port 389): each
// flow is one TCP session running a bind → search → unbind signaling
// exchange (the reference pcap is an Active Directory RootDSE query
// session; its SASL GSS-API messages are Kerberos ciphertext and are not
// reproducible, so the planner always emits plain BER with simple
// authentication).
//
// Each round performs bindRequest/bindResponse then
// searchRequest/searchResEntry+searchResDone; unbindRequest is sent once
// at the end of the last round. Message IDs are Base+3r (bind),
// Base+3r+1 (search), Base+3r+2 (unbind); responses echo the request ID.
// Reference pcap wire facts: every BER length uses the long form
// 0x84+4-byte big-endian (Active Directory client behavior); the default
// attribute list mirrors the RootDSE query's 15 attributes; default
// MessageIDBase=2423 + defaults reproduces the 351-byte searchRequest
// byte-for-byte.
type LDAPConfig struct {
	// Rounds (轮数): bind/search exchange count (default 1). unbind is
	// sent once after the last round.
	Rounds int `json:"rounds,omitempty"`

	// MessageIDBase (起始消息号): message ID of the first bindRequest
	// (RFC 4511 §4.1.1 requires a non-zero INTEGER). Must satisfy
	// Base+3×(Rounds-1)+2 ≤ 0x7FFF.
	MessageIDBase uint16 `json:"message_id_base,omitempty"`

	// Version (版本): LDAP protocol version (RFC 4511 §4.2.1), 2 or 3.
	Version int `json:"version,omitempty"`

	// BindDN (绑定名称): bindRequest name; empty = anonymous bind.
	BindDN string `json:"bind_dn,omitempty"`

	// BindPassword (绑定密码): simple authentication password
	// (RFC 4511 §4.2.1 simple [0] OCTET STRING). SASL is not modeled.
	BindPassword string `json:"bind_password,omitempty"`

	// SearchBaseDN (搜索基准): searchRequest baseObject; empty = RootDSE
	// (the reference pcap queries the RootDSE).
	SearchBaseDN string `json:"search_base_dn,omitempty"`

	// SearchScope (搜索范围): RFC 4511 §4.5.1.2 scope ENUMERATED:
	// 0=baseObject (default), 1=singleLevel, 2=wholeSubtree.
	SearchScope int `json:"search_scope,omitempty"`

	// SizeLimit (数量上限): RFC 4511 §4.5.1.3 sizeLimit INTEGER,
	// 0 = unlimited.
	SizeLimit int `json:"size_limit,omitempty"`

	// TimeLimit (时间上限): RFC 4511 §4.5.1.4 timeLimit INTEGER (seconds),
	// 0 = unlimited. Reference pcap uses 120.
	TimeLimit int `json:"time_limit,omitempty"`

	// FilterType (过滤器类型): RFC 4511 §4.5.1.7 Filter CHOICE:
	// "present" (default, tag 0x87) or "equality" (tag 0xa3).
	FilterType string `json:"filter_type,omitempty"`

	// SearchFilter (过滤属性): attribute name for the filter; default
	// "objectclass" (reference pcap present filter).
	SearchFilter string `json:"search_filter,omitempty"`

	// FilterValue (过滤值): equality filter value, forming an
	// attr=value assertion with SearchFilter.
	FilterValue string `json:"filter_value,omitempty"`

	// Attributes (属性列表): searchRequest AttributeSelection; empty
	// defaults to the reference pcap's 15 RootDSE attributes
	// (subschemaSubentry, dsServiceName, namingContexts, ...,
	// supportedCapabilities).
	Attributes []string `json:"attributes,omitempty"`

	// ResultCode (结果码): resultCode for bindResponse and searchResDone
	// (RFC 4511 §4.1.9 ENUMERATED): 0=success (default), 49=
	// invalidCredentials, etc. Must be 0-127.
	ResultCode uint8 `json:"result_code,omitempty"`

	// Unbind (解绑): send unbindRequest (RFC 4511 §4.3, no response)
	// after the last round. nil = send (default true); the JSON parser
	// sets false explicitly when the user writes "unbind": false.
	Unbind *bool `json:"unbind,omitempty"`
}

// VNCConfig holds VNC/RFB (RFC 6143) protocol configuration. VNC is a
// remote-framebuffer protocol over TCP (default port 5900): each flow is
// one session running version negotiation → security handshake → ServerInit
// (signaling plane) followed by client messages and server framebuffer
// updates (data plane).
//
// Three security paths: 16=Tight (default, reference pcap: tunnel caps +
// auth caps + interaction caps), 2=VNC Authentication (challenge/response,
// no caps), 1=None. The reference pcap is a TightVNC session (server name
// "QTMS:1 (ykaul)", 1024×768, 32bpp) whose handshake messages this planner
// reproduces byte-for-byte by default; the auth response is DES ciphertext
// and is emitted as deterministic pseudo-random bytes (default = the
// reference pcap bytes, seedable via ChallengeSeed/ResponseSeed).
//
// Data plane: the client sends key events + SetPixelFormat + SetEncodings +
// a full-screen FramebufferUpdateRequest, then per round a PointerEvent; the
// server answers with FramebufferUpdate messages whose rects use raw (0),
// hextile (5) or xcursor (-240) encodings (reference pcap uses hextile raw
// tiles and an XCursor blob). Reference-pcap garbage padding bytes are not
// reproduced (RFC padding is zero).
type VNCConfig struct {
	// SecurityType (安全类型): RFC 6143 §7.2.1: 16=Tight (default,
	// reference pcap), 2=VNC Authentication, 1=None.
	SecurityType int `json:"security_type,omitempty"`

	// AuthResult (认证结果): SecurityResult u32 (RFC 6143 §7.2.2):
	// 0=OK (default); 1 or 2 = failure, in which case a reasonLen u32 +
	// reason string follows and the session ends (no ServerInit).
	AuthResult int `json:"auth_result,omitempty"`

	// AuthReason (失败原因): failure reason string appended after
	// AuthResult 1/2.
	AuthReason string `json:"auth_reason,omitempty"`

	// ShareDesktop (共享桌面): ClientInit shared-flag byte (RFC 6143
	// §7.3.1). nil = true.
	ShareDesktop *bool `json:"share_desktop,omitempty"`

	// Width (宽度): ServerInit framebuffer width u16 (default 1024,
	// reference pcap `04 00`).
	Width int `json:"width,omitempty"`

	// Height (高度): ServerInit framebuffer height u16 (default 768,
	// reference pcap `03 00`).
	Height int `json:"height,omitempty"`

	// ServerName (服务器名): ServerInit name string (default
	// "QTMS:1 (ykaul)", the reference pcap server); nameLen u32 is
	// computed automatically.
	ServerName string `json:"server_name,omitempty"`

	// PixelFormat (像素格式): ServerInit pixel format (RFC 6143 §7.3.3,
	// 16 bytes). nil = reference pcap default (32bpp/24bit/little-endian
	// true-color/255/16/8/0).
	PixelFormat *VNCPixelFormatConfig `json:"pixel_format,omitempty"`

	// InteractionCaps (交互能力): Tight mode Interaction Caps message
	// (TightVNC extension). nil = reference pcap default (184 bytes: 11
	// capability records).
	InteractionCaps *VNCInteractionCapsConfig `json:"interaction_caps,omitempty"`

	// KeyEvents (按键事件): client key events after the handshake
	// (RFC 6143 §8.4.4). nil = reference pcap's 6 key releases
	// (0xffe9/0xffe3/0xffe1/0xffea/0xffe4/0xffe2); explicitly empty =
	// no key events.
	KeyEvents []VNCKeyEventConfig `json:"key_events,omitempty"`

	// ClientSetPixelFormat (发像素格式): client sends SetPixelFormat
	// (RFC 6143 §8.1) echoing the server pixel format. nil = true.
	ClientSetPixelFormat *bool `json:"client_set_pixel_format,omitempty"`

	// ClientSetEncodings (发编码列表): client sends SetEncodings
	// (RFC 6143 §8.2). nil = true.
	ClientSetEncodings *bool `json:"client_set_encodings,omitempty"`

	// Encodings (编码列表): SetEncodings list (RFC 6143 §8.2, 4 bytes
	// each). nil = reference pcap's 15 values (5, 8, 7, 6, 4, 2, 1, 0,
	// -250, -240, -239, -232, -26, -224, -223).
	Encodings []int `json:"encodings,omitempty"`

	// Rounds (轮数): data-plane rounds. Each round = client PointerEvent
	// (up) → server FramebufferUpdate(s) (down). The client sends one
	// non-incremental full-screen FBU request before the first update and
	// one incremental request after the last (reference pcap structure).
	Rounds int `json:"rounds,omitempty"`

	// PointerX (指针X): PointerEvent x coordinate (default 507,
	// reference pcap `01 fb`).
	PointerX int `json:"pointer_x,omitempty"`

	// PointerY (指针Y): PointerEvent y coordinate (default 320,
	// reference pcap `01 40`).
	PointerY int `json:"pointer_y,omitempty"`

	// PointerButton (指针按钮): PointerEvent button mask (default 0,
	// reference pcap).
	PointerButton int `json:"pointer_button,omitempty"`

	// FBUUpdateInterval (更新间隔): server FramebufferUpdates per round
	// (default 1).
	FBUUpdateInterval int `json:"fbu_update_interval,omitempty"`

	// InitialFBU (首更新): rects of the first server FramebufferUpdate
	// after the handshake. nil = reference pcap FBU#1 structure: XCursor
	// (0,1,12,19) + Hextile full screen (0,0,1024,768).
	InitialFBU []VNCRectConfig `json:"initial_fbu,omitempty"`

	// UpdateRects (轮更新): rects of each round's FramebufferUpdate. nil
	// = reference pcap FBU#2 pattern: 2× Hextile 16×16 raw tiles.
	UpdateRects []VNCRectConfig `json:"update_rects,omitempty"`

	// Bell (铃响): server sends a Bell message (RFC 6143 §9.3, 1 byte)
	// before each FramebufferUpdate. Default false.
	Bell bool `json:"bell,omitempty"`

	// SetColourMapEntries (色表): server SetColourMapEntries message
	// (RFC 6143 §9.2) before each FramebufferUpdate. nil = not sent.
	SetColourMapEntries *VNCColourMapConfig `json:"set_colour_map_entries,omitempty"`

	// ServerCutText (服务器剪贴板): non-empty sends a ServerCutText
	// message (RFC 6143 §9.4) before each FramebufferUpdate.
	ServerCutText string `json:"server_cut_text,omitempty"`

	// ClientCutText (客户端剪贴板): non-empty sends a ClientCutText
	// message (RFC 6143 §8.5) after the initial FBU request.
	ClientCutText string `json:"client_cut_text,omitempty"`

	// ChallengeSeed (挑战种子): seed for the 16-byte server challenge;
	// 0 = reference pcap fixed bytes (byte-exact reproduction).
	ChallengeSeed uint64 `json:"challenge_seed,omitempty"`

	// ResponseSeed (响应种子): seed for the 16-byte client auth response
	// (DES ciphertext, not computable; deterministic pseudo-random).
	// 0 = reference pcap fixed bytes.
	ResponseSeed uint64 `json:"response_seed,omitempty"`
}

// VNCPixelFormatConfig holds the RFC 6143 §7.3.3 pixel format (16 bytes).
type VNCPixelFormatConfig struct {
	// BitsPerPixel (每像素位数): 8, 16 or 32 (reference pcap 32).
	BitsPerPixel int `json:"bits_per_pixel,omitempty"`

	// Depth (深度): color depth (reference pcap 24).
	Depth int `json:"depth,omitempty"`

	// BigEndian (大端): byte-order flag (reference pcap false).
	BigEndian bool `json:"big_endian,omitempty"`

	// TrueColor (真彩色): true-colour flag (reference pcap true).
	TrueColor bool `json:"true_color,omitempty"`

	// RedMax (红最大值): red-max u16 (reference pcap 255).
	RedMax int `json:"red_max,omitempty"`

	// GreenMax (绿最大值): green-max u16 (reference pcap 255).
	GreenMax int `json:"green_max,omitempty"`

	// BlueMax (蓝最大值): blue-max u16 (reference pcap 255).
	BlueMax int `json:"blue_max,omitempty"`

	// RedShift (红移位): red-shift (reference pcap 16).
	RedShift int `json:"red_shift,omitempty"`

	// GreenShift (绿移位): green-shift (reference pcap 8).
	GreenShift int `json:"green_shift,omitempty"`

	// BlueShift (蓝移位): blue-shift (reference pcap 0).
	BlueShift int `json:"blue_shift,omitempty"`
}

// VNCInteractionCapsConfig holds the TightVNC Interaction Caps message:
// a 4×u16 header (nServerMessageTypes, nClientMessageTypes,
// nEncodingTypes, pad) followed by capability records of 16 bytes each
// (code u32 + vendor u8[4] + name u8[8]).
type VNCInteractionCapsConfig struct {
	// ServerMsgTypes (服务器消息数): nServerMessageTypes u16 (reference 0).
	ServerMsgTypes int `json:"server_msg_types,omitempty"`

	// ClientMsgTypes (客户端消息数): nClientMessageTypes u16 (reference
	// pcap 11 — the QTMS synthetic server lists 11 encoding capabilities
	// under this counter; reproduced verbatim).
	ClientMsgTypes int `json:"client_msg_types,omitempty"`

	// EncodingTypes (编码类型数): nEncodingTypes u16 (reference 0).
	EncodingTypes int `json:"encoding_types,omitempty"`

	// Caps (能力记录): capability records; nil = the reference pcap's 11
	// records (RRE/HEXTILE/TIGHT/ZRLE/COPYRECT/COMPRLVL/JPEGQLVL/
	// X11CURSR/RCHCURSR/LASTRECT/NEWFBSIZ).
	Caps []VNCCapabilityConfig `json:"caps,omitempty"`
}

// VNCCapabilityConfig is one 16-byte capability record.
type VNCCapabilityConfig struct {
	// Code (编码值): capability code u32.
	Code int `json:"code,omitempty"`

	// Vendor (厂商): 4-byte vendor signature (e.g. "STDV", "TGHT").
	Vendor string `json:"vendor,omitempty"`

	// Name (名称): 8-byte name signature (e.g. "TIGHT___").
	Name string `json:"name,omitempty"`
}

// VNCKeyEventConfig is one RFC 6143 §8.4.4 KeyEvent message.
type VNCKeyEventConfig struct {
	// Down (按下): 1 = key down, 0 = key release (reference pcap all
	// releases).
	Down bool `json:"down,omitempty"`

	// Key (键值): X11 keysym u32 (e.g. 0xffe9 = Page_Up).
	Key int `json:"key,omitempty"`
}

// VNCRectConfig is one FramebufferUpdate rectangle (RFC 6143 §9.1).
type VNCRectConfig struct {
	// X (X坐标): rect x u16.
	X int `json:"x,omitempty"`

	// Y (Y坐标): rect y u16.
	Y int `json:"y,omitempty"`

	// Width (宽): rect width u16.
	Width int `json:"width,omitempty"`

	// Height (高): rect height u16.
	Height int `json:"height,omitempty"`

	// Encoding (编码): "raw" (0), "hextile" (5) or "xcursor" (-240).
	Encoding string `json:"encoding,omitempty"`

	// HextileTileData (tile数据): hex string of one hextile tile's data
	// (ctrl + payload), repeated for every tile in the rect. Empty =
	// default raw tiles (ctrl 0x01 + w×h×4 pixel bytes, reference pcap
	// FBU#2 pattern).
	HextileTileData string `json:"hextile_tile_data,omitempty"`

	// XCursorBlob (光标数据): hex string of the XCursor encoding data
	// (6-byte colors + w×h pixels + mask). Empty = the reference pcap's
	// fixed 80-byte blob.
	XCursorBlob string `json:"xcursor_blob,omitempty"`
}

// VNCColourMapConfig holds the RFC 6143 §9.2 SetColourMapEntries message.
type VNCColourMapConfig struct {
	// First (起始索引): first colour index u16.
	First int `json:"first,omitempty"`

	// Colors (颜色列表): colour values, each a 6-byte hex string (2-byte
	// red + 2-byte green + 2-byte blue).
	Colors []string `json:"colors,omitempty"`
}

// XmppConfig holds XMPP (Extensible Messaging and Presence Protocol,
// 可扩展消息与存在协议, RFC 6120) configuration. XMPP is a TCP-based
// XML messaging protocol on port 5222. The planner emits a complete
// session: TCP handshake → stream open → features → SASL auth → stream
// restart → resource bind → session → presence → messages → stream close
// → TCP teardown.
//
// Reference pcap: llcj dport=5222 (11 IPv4 + 8 IPv6 sessions, all
// wire-identical SCRAM-SHA-1 sessions that fail with invalid-authzid).
// Trafficgen generates the happy path with PLAIN auth by default.
type XmppConfig struct {
	// From (来源域名): server domain advertised in stream opening
	// (RFC 6120 §4.2). Empty defaults "example.com".
	From string `json:"from,omitempty"`

	// JID (Jabber ID): user identifier for resource binding
	// (RFC 6120 §7.3). Empty defaults "user@example.com".
	JID string `json:"jid,omitempty"`

	// Resource (资源名): resource identifier for binding (RFC 6120 §7.7.2).
	// Empty defaults "trafficgen".
	Resource string `json:"resource,omitempty"`

	// StreamID (流ID): server-assigned stream identifier echoed in stream
	// response (RFC 6120 §4.7.3). Empty defaults "a1b2c3d4e5f6".
	StreamID string `json:"stream_id,omitempty"`

	// AuthMechanism (认证机制): SASL mechanism for authentication
	// (RFC 6120 §6). Supported values:
	//   - "PLAIN" (default, RFC 4616): single auth+success exchange
	//   - "DIGEST-MD5" (RFC 2831): challenge-response exchange
	//   - "SCRAM-SHA-1" (RFC 5802): multi-step exchange
	//   - "ANONYMOUS" (RFC 4505): anonymous auth
	AuthMechanism string `json:"auth_mechanism,omitempty"`

	// Username (用户名): used for PLAIN/DIGEST-MD5/SCRAM-SHA-1 auth.
	// Empty defaults "user".
	Username string `json:"username,omitempty"`

	// Password (密码): used for PLAIN/DIGEST-MD5/SCRAM-SHA-1 auth.
	// Empty defaults "pass".
	Password string `json:"password,omitempty"`

	// Presence (存在状态): when non-nil, the pointed-to value controls
	// whether the client sends initial <presence/> after session
	// establishment (RFC 6121 §4.2). nil = default on (true). Use an
	// explicit false pointer to disable. This mirrors the PadMinFrame
	// pattern (nil=default, non-nil=user-explicit).
	Presence *bool `json:"presence,omitempty"`

	// Messages (消息): XMPP <message> stanzas exchanged after presence,
	// each as one PSH-ACK segment. Direction "up" = client→server
	// (default), "down" = server→client.
	Messages []XmppMessage `json:"messages,omitempty"`
}

// XmppMessage is one XMPP <message> stanza (消息节) on the data plane.
// Direction "up" (default) = client→server, "down" = server→client.
type XmppMessage struct {
	// Direction (方向): "up" (client→server) or "down" (server→client).
	// Empty defaults "up".
	Direction string `json:"direction,omitempty"`

	// To (接收方): JID of the message recipient. Empty defaults
	// "bob@example.com".
	To string `json:"to,omitempty"`

	// Body (消息体): content of the <body> element.
	Body string `json:"body,omitempty"`
}

// TFTPConfig configures the TFTP (RFC 1350) planner. TFTP runs over UDP:
// the client picks an ephemeral source port and sends RRQ/WRQ to server
// port 69; the server picks its own ephemeral TID port for the rest. Both
// directions of the data plane share the same 4-tuple.
type TFTPConfig struct {
	// Mode: "read" (RRQ, 下载, server 发 DATA) or "write" (WRQ, 上传,
	// client 发 DATA). 大小写不敏感; empty defaults to "read".
	Mode string `json:"mode"`

	// Filename: file path in RRQ/WRQ. May contain "/" or "\". Empty rejected
	// by Validate. Max 255 bytes (trafficgen 限制; RFC 1350 未规定上限).
	Filename string `json:"filename"`

	// TransferMode: "netascii" or "octet" (RFC 1350 §4). 大小写不敏感,
	// 输出统一小写. "mail" deprecated, rejected. Empty defaults to "octet".
	TransferMode string `json:"transfer_mode"`

	// BlkSize: blksize option (RFC 2348). 0=do not send (use default 512).
	// Validate enforces 8 <= BlkSize <= 65464. OACK 回显请求值.
	BlkSize uint16 `json:"blksize,omitempty"`

	// Timeout: timeout option in seconds (RFC 2349). 0=do not send.
	// Validate enforces 1 <= Timeout <= 255. 仅语义标记 — trafficgen 不实际
	// 按超时起重传 (只生成重传序列 via RetransmitBlocks, 见 §4.5).
	Timeout uint8 `json:"timeout,omitempty"`

	// ClientTSize: tsize option value written into RRQ/WRQ (RFC 2349 §2).
	// RRQ 模式: RFC 2349 强制客户端写 "0"; 若 ClientTSize>0 或 ServerTSize>0,
	// RRQ 携带 tsize\0 0\0, 否则不发送 tsize 选项.
	// WRQ 模式: 客户端写实际文件大小 (ClientTSize).
	// 同时参与自动追加判定: auto-append 判定 TSize = (ClientTSize>0 ? ClientTSize
	// : ServerTSize) (非零者优先, 见 §5.1 自动追加规则).
	ClientTSize uint32 `json:"client_tsize,omitempty"`

	// ServerTSize: tsize value echoed by server in OACK.
	// RRQ 模式: 服务器回实际文件大小 (ServerTSize).
	// WRQ 模式: 服务器回显 ClientTSize, ServerTSize 应=0 或==ClientTSize.
	// 参与自动追加判定 (ClientTSize=0 时采用).
	ServerTSize uint32 `json:"server_tsize,omitempty"`

	// ServerTID: server's ephemeral port for packets after RRQ/WRQ.
	// 0=planner picks deterministic ephemeral (49152-65535, RFC 6335) via
	// FNV-1a(FlowID) so the same spec always yields the same port
	// (reproducible). When set, Validate enforces 1024 <= ServerTID <= 65535.
	ServerTID uint16 `json:"server_tid,omitempty"`

	// ErrorCode: inject an ERROR packet with ErrCode=ErrorCode at
	// ErrorAfterBlock. 统一语义 (R1-CRITICAL-2 修复):
	//   - ErrorCode>0: 注入 (ErrorAfterBlock=0 → RRQ/WRQ 后立即; >0 → N 块后).
	//   - ErrorCode==0 且 ErrorAfterBlock>0: 注入 code=0 (ErrorAfterBlock 显式
	//     表达了注入意图, S8d/T-227 场景).
	//   - ErrorCode==0 且 ErrorAfterBlock==0: 不注入 (json omitempty 下与"未设置"
	//     不可区分, 约定为不注入, T-228).
	// Wire 类型为 uint16 BE (0-8, 见 §3.6 错误码表, 含 RFC 2347 code=8);
	// Go 类型 uint8. Validate enforces 0 <= ErrorCode <= 8.
	// 互斥: ServerTIDChange=true 时 ErrorCode 必须=0 (见 §5.3).
	ErrorCode uint8 `json:"error_code,omitempty"`

	// ErrorMsg: human-readable text in injected ERROR. Empty allowed —
	// planner then uses the default ErrMsg for ErrCode (见 §5.4 ErrCode→ErrMsg
	// 表, 含 ErrorCode=0 → "Not defined"). Truncated to 255 bytes on wire.
	ErrorMsg string `json:"error_msg,omitempty"`

	// ErrorAfterBlock: DATA block# after which ERROR is injected.
	// 0=immediately after RRQ/WRQ (no DATA). N>0=emit DATA#1..N + ACK#1..N
	// then inject ERROR from ErrorSide. Validate: ErrorAfterBlock>0 时
	// BlocksCount 必须显式设 (不允许 derive), 且 ErrorAfterBlock <= BlocksCount.
	ErrorAfterBlock uint32 `json:"error_after_block,omitempty"`

	// ErrorSide: "server"=server→client (down), "client"=client→server (up).
	// Empty defaults to "server".
	ErrorSide string `json:"error_side,omitempty"`

	// BlocksCount: 实际 DATA 块数 (uint32, 允许 > 65535; wire Block# 按 §3.3
	// 回绕规则编码). 0=derive from data_payload_pattern/payload 数据规模推导
	// (规则见 §5.1). 不含自动追加的 0 字节末块.
	BlocksCount uint32 `json:"blocks_count,omitempty"`

	// AutoAppendFinalBlock: when true (default), planner appends a 0-byte
	// DATA terminator per RFC 1350 §6 whenever the LAST DATA block is a full
	// block (Data length == BlkSize), i.e. the file size is an exact multiple
	// of BlkSize — regardless of whether a tsize decision exists (R1-CRITICAL-3
	// 修复: 无 tsize 满块时默认也追加, 兑现 "默认 true = RFC 1350 §6 合规").
	// 判定: 末块 Data 长度 == BlkSize 即追加; FinalBlockZero=true 时末块为
	// 0 字节, 不满足"末块满块", 自动跳过 (§5.3). When false, no auto-append
	// (非 RFC 合规负向测试). nil = true (默认). 追加后实际块数 > 65535 且
	// 未开 wrap 时 Validate 报错 (V18).
	AutoAppendFinalBlock *bool `json:"auto_append_final_block,omitempty"`

	// FinalBlockZero: when true, the LAST DATA block (Block#=BlocksCount,
	// wire 上按回绕规则计算) carries 0 bytes — 显式 RFC 1350 §6 终止块.
	// 与 AutoAppendFinalBlock=false 搭配生成"半标准"流; 当自动追加条件也满足时
	// 不重复追加 (末块已显式). Validate requires BlocksCount >= 1 (derive 不允许).
	FinalBlockZero bool `json:"final_block_zero,omitempty"`

	// WrapBlockNumber: when true, Block# = (i mod 65536) 回绕 (65535 → 0 → 1),
	// 允许 BlocksCount > 65535. When false (default), Validate rejects
	// BlocksCount > 65535.
	WrapBlockNumber bool `json:"wrap_block_number,omitempty"`

	// DataPayloadPattern: DATA payload bytes. 每块填充为该 slice 循环重复至
	// BlkSize. 空且 BlocksCount>0 时用确定性 0x00..0xFF 模式. 空且 BlocksCount==0
	// (derive) 时要求 Payload/FileSource 提供数据规模 (见 §5.1).
	DataPayloadPattern []byte `json:"data_payload_pattern,omitempty"`

	// IncludeOACK: when true, server sends OACK even with no options
	// (OACK carries only opcode `00 06`, 2 bytes). Default false. RRQ 模式走
	// RRQ+OACK 分支 (client 发 ACK#0 后 server 发 DATA#1); WRQ 模式走 WRQ+OACK
	// 分支 (client 直接发 DATA#1, 无 ACK#0). 见 §4.4.
	IncludeOACK bool `json:"include_oack,omitempty"`

	// RetransmitBlocks: DATA 重传模拟 (S10). 语义: 列表中的 Block# 的 DATA 在
	// 初次发送时"丢失", 仅出现重传版本 (每个重传 DATA 后跟对应 ACK#N).
	// 符合 RFC 1350 §6 重传时序 (重传 DATA 先于其 ACK, 不出现"原 DATA+原 ACK"
	// 后再重传的异常序列). 每项必须在 [1, BlocksCount]. 互斥于 ServerTIDChange.
	RetransmitBlocks []uint32 `json:"retransmit_blocks,omitempty"`

	// ServerTIDChange: when true, simulates server switching to ServerTIDNew
	// at ServerTIDChangeAtBlock. 语义为 trafficgen 扩展行为 (非任何 RFC 标准):
	// 客户端 (接收方) 检测到源 TID 变为 ServerTIDNew 后, 向新 TID 发 ERROR code=5
	// (Unknown TID, 表示"包源 TID 与约定不符, 尚未完成迁移"), 随后继续向新 TID
	// 发 ACK — ERROR code=5 不终止传输 (trafficgen 扩展). 注意: 此行为不符合
	// RFC 1350 §4 的校验语义 (RFC 1350 下客户端应丢弃新 TID 的包并向错误源回
	// ERROR(5) 后继续等待旧 TID 上的重传, 不回 ACK; v2.0.1 曾误引 RFC 1783 为
	// 依据, 但 RFC 1783 实际是 "TFTP Blocksize Option" 与 TID 无关, v2.0.2 已
	// 撤回该引用). 也非任何 RFC 标准, 仅用于生成器字节序列测试 (模拟 NAT/中间件
	// 导致的 TID 漂移场景). 互斥于 ErrorCode>0 与 RetransmitBlocks.
	// 见 §4.3、S9.
	ServerTIDChange        bool   `json:"server_tid_change,omitempty"`
	ServerTIDChangeAtBlock uint32 `json:"server_tid_change_at_block,omitempty"`
	ServerTIDNew           uint16 `json:"server_tid_new,omitempty"`

	// WindowSize: sliding window size for RFC 7440 windowsize option.
	// 0=do not send (default=1, standard lock-step). Validate enforces 1-65535.
	// When >1, DATA blocks are sent in windows of this size before waiting for ACK.
	WindowSize uint16 `json:"windowsize,omitempty"`
}

// MODBUSConfig holds Modbus TCP (莫迪总线 TCP) configuration.
// Modbus TCP is an industrial control protocol on TCP port 502.
// Each transaction = one request PDU + one response PDU, framed by
// the 7-byte MBAP header (Transaction ID + Protocol ID + Length + Unit ID).
// The planner emits: TCP handshake → N transactions (request→response)
// → TCP teardown. Transactions are stateless and independent.
type MODBUSConfig struct {
	// UnitID (从站标识符): 0-247, 0=broadcast. nil → default 1.
	// Uses *uint8 because omitempty on uint8 would swallow 0 (broadcast).
	UnitID *uint8 `json:"unit_id,omitempty"`

	// SuppressBroadcast (抑制广播响应): true omits response packets
	// when UnitID=0 (including exception responses).
	SuppressBroadcast bool `json:"suppress_broadcast,omitempty"`

	// Transactions (事务序列): ordered list of Modbus operations.
	// nil (JSON missing) → planner injects 1 default transaction
	// (FC=0x03, addr=0, qty=1).
	// Explicit empty array [] → only TCP handshake + teardown.
	Transactions []MODBUSOperation `json:"transactions,omitempty"`

	// MasterCount (并发主站数): number of concurrent masters (clients),
	// each with an independent 4-tuple (TCP stream). Default 1.
	MasterCount int `json:"master_count,omitempty"`

	// FlowCount (每主站流数): concurrent flows per master. Default 1.
	FlowCount int `json:"flow_count,omitempty"`

	// SharedTIDSpace (共享 TID 空间): true → all flows share a continuous
	// Transaction ID space (global increment across flows).
	SharedTIDSpace bool `json:"shared_tid_space,omitempty"`
}

// MODBUSOperation describes a single Modbus transaction (one request + one response).
type MODBUSOperation struct {
	// FunctionCode (功能码): 0x01-0x2B, see design §1.3 for the 19-code support set.
	FunctionCode uint8 `json:"function_code"`

	// ExceptionCode (异常码): non-zero triggers FC|0x80 + ExceptionCode response.
	// Mutually exclusive with ResponseValues. 0 means normal response.
	ExceptionCode uint8 `json:"exception_code,omitempty"`

	// StartingAddress (起始地址): 0x0000-0xFFFF. Used by most FCs.
	StartingAddress uint16 `json:"starting_address,omitempty"`

	// Quantity (数量): FC-specific limits (see §2.7). Ignored for FC 0x17.
	Quantity uint16 `json:"quantity,omitempty"`

	// ReadAddress/WriteAddress (读写地址): FC 0x17 specific.
	// WriteAddress=0 falls back to StartingAddress + WriteQuantity (uint16 wrap).
	ReadAddress  uint16 `json:"read_address,omitempty"`
	WriteAddress uint16 `json:"write_address,omitempty"`

	// ReadQuantity/WriteQuantity (读写数量): FC 0x17 specific, must be explicit.
	ReadQuantity  uint16 `json:"read_quantity,omitempty"`
	WriteQuantity uint16 `json:"write_quantity,omitempty"`

	// WriteValue (写单值): FC 0x05 accepts 0/1/0xFF00/0x0000;
	// FC 0x06 accepts 0x0000-0xFFFF.
	WriteValue uint16 `json:"write_value,omitempty"`

	// Values (请求数据): FC-specific request payload after the FC byte.
	Values []byte `json:"values,omitempty"`

	// ResponseValues (响应数据): overrides auto-derived response PDU bytes
	// after the FC byte. Mutually exclusive with ExceptionCode.
	ResponseValues []byte `json:"response_values,omitempty"`

	// SubFunction (子功能): uint16 full width.
	// FC 0x08: diagnostic sub-function 0x0000-0x0015.
	// FC 0x2B: low byte is MEI Type (must be 0x0E), high byte must be 0.
	SubFunction uint16 `json:"sub_function,omitempty"`

	// MaskAnd/MaskOr (掩码): FC 0x16 specific.
	MaskAnd uint16 `json:"mask_and,omitempty"`
	MaskOr  uint16 `json:"mask_or,omitempty"`

	// ResponseMode (响应模式): "normal" (default, generate response) or
	// "no_response" (suppress response packet).
	ResponseMode string `json:"response_mode,omitempty"`

	// Direction is DEPRECATED; planner ignores it.
	Direction string `json:"direction,omitempty"`
}

// RIPConfig holds RIP (Routing Information Protocol) configuration.
// RIP v1 (RFC 1058), RIP v2 (RFC 2453), RIPng (RFC 2080).
type RIPConfig struct {
	// Version: "v1", "v2" (default), "ng". Empty = "v2".
	Version string `json:"version,omitempty"`

	// Command: "request" (1) or "response" (2). Empty = "response".
	Command string `json:"command,omitempty"`

	// Domain: 2-byte RIP header field. Default 0.
	Domain uint16 `json:"domain,omitempty"`

	// Routes: route entries to advertise.
	Routes []RIPRoute `json:"routes,omitempty"`

	// Auth: authentication config. Only valid for v2.
	Auth *RIPAuth `json:"auth,omitempty"`

	// Multicast: true uses multicast (v2: 224.0.0.9, ng: FF02::9, v1: broadcast).
	Multicast bool `json:"multicast,omitempty"`

	// Scenario: controls default route generation ("request_full", "response_default", etc).
	Scenario string `json:"scenario,omitempty"`

	// Routers: multi-router scenario with independent 4-tuples.
	Routers []RIPRouter `json:"routers,omitempty"`

	// Rounds: number of update rounds. Default 1.
	Rounds int `json:"rounds,omitempty"`

	// TriggeredUpdate: true skips Request, sends Response immediately.
	TriggeredUpdate bool `json:"triggered_update,omitempty"`

	// SplitHorizon: true filters routes with NextHop==DstIP.
	SplitHorizon bool `json:"split_horizon,omitempty"`

	// PoisonReverse: true sets metric=16 for routes with NextHop==DstIP.
	PoisonReverse bool `json:"poison_reverse,omitempty"`
}

// RIPRoute describes a route entry for RIP v1/v2/RIPng.
type RIPRoute struct {
	// AFI: Address Family Identifier. 0=auto, 2=IPv4. 0xFFFF reserved for auth.
	AFI uint16 `json:"afi,omitempty"`

	// RouteTag: 2-byte route tag (v2/ng only).
	RouteTag uint16 `json:"route_tag,omitempty"`

	// IPAddr: IPv4 or IPv6 address.
	IPAddr string `json:"ip_addr"`

	// SubnetMask: IPv4 mask (v2 only).
	SubnetMask string `json:"subnet_mask,omitempty"`

	// PrefixLen: IPv6 prefix length (ng only).
	PrefixLen uint8 `json:"prefix_len,omitempty"`

	// NextHop: next hop IP. 0.0.0.0/:: = sender is next hop.
	NextHop string `json:"next_hop,omitempty"`

	// Metric: 1-16 (16 = unreachable).
	Metric uint8 `json:"metric"`
}

// RIPAuth describes RIP v2 authentication. Not valid for v1/ng.
type RIPAuth struct {
	// Type: "simple" (0x0002) or "md5" (0x0003). Empty = "simple".
	Type string `json:"type,omitempty"`

	// Password: simple auth password (max 16 bytes).
	Password string `json:"password,omitempty"`

	// KeyID: MD5 key identifier (1 byte).
	KeyID uint8 `json:"key_id,omitempty"`

	// AuthDataLen: MD5 digest length. nil = default 16.
	AuthDataLen *uint8 `json:"auth_data_len,omitempty"`

	// SequenceNumber: MD5 sequence number (4 bytes).
	SequenceNumber uint32 `json:"sequence_number,omitempty"`
}

// RIPRouter describes a router instance for multi-router scenarios.
type RIPRouter struct {
	// SrcIP: router's source IP. Empty = inherit from FlowSpec.
	SrcIP string `json:"src_ip,omitempty"`

	// SrcPort: router's source port. Empty = inherit from FlowSpec.
	SrcPort uint16 `json:"src_port,omitempty"`

	// DstIP: router's destination IP. Empty = inherit from FlowSpec.
	DstIP string `json:"dst_ip,omitempty"`

	// DstPort: router's destination port. Empty = inherit from FlowSpec.
	DstPort uint16 `json:"dst_port,omitempty"`
}

// DoIPConfig holds DOIP (Diagnostic over IP, ISO 13400-2) protocol configuration.
// DOIP is a vehicle diagnostic protocol over TCP/UDP port 13400, carrying UDS
// (Unified Diagnostic Services) messages between Tester and ECU.
//
// The planner emits:
//  1. UDP Discovery phase: Vehicle Identification Request/Response (0x0001-0x0004)
//  2. UDP Entity Status: DoIP Entity Status Request/Response (0x4001-0x4002)
//  3. UDP Power Mode: Diagnostic Power Mode Request/Response (0x4003-0x4004)
//  4. TCP Routing Activation: Routing Activation Request/Response (0x0005-0x0006)
//  5. TCP Diagnostic Messages: Diagnostic Message/Ack/Nack (0x8001-0x8003)
//  6. TCP Alive Check: Alive Check Request/Response (0x0007-0x0008)
//  7. Generic NACK: Header NACK (0x0000)
type DoIPConfig struct {
	// ProtocolVersion (协议版本): 0x02 for DoIP V2 (default), 0x01 for V1.
	ProtocolVersion uint8 `json:"protocol_version,omitempty"`

	// SrcIP (源IP): Tester IP (IPv4 or IPv6).
	SrcIP string `json:"src_ip,omitempty"`

	// DstIP (目的IP): ECU IP (or broadcast address for discovery).
	DstIP string `json:"dst_ip,omitempty"`

	// SrcPort (源端口): UDP source port (TCP uses ephemeral).
	SrcPort uint16 `json:"src_port,omitempty"`

	// VIN (车辆识别码): 17-byte ASCII string for vehicle identification.
	VIN string `json:"vin,omitempty"`

	// LogicalAddress (逻辑地址): ECU logical address (SLA).
	LogicalAddress uint16 `json:"logical_address,omitempty"`

	// TesterAddress (Tester地址): Tester logical address (SA).
	TesterAddress uint16 `json:"tester_address,omitempty"`

	// EID (实体标识): 6-byte ECU entity identifier (MAC address).
	EID string `json:"eid,omitempty"`

	// GID (组标识): 6-byte group identifier.
	GID string `json:"gid,omitempty"`

	// Discovery (车辆发现): UDP discovery phase configuration.
	Discovery *DoIPDiscovery `json:"discovery,omitempty"`

	// EntityStatus (实体状态): UDP entity status configuration.
	EntityStatus *DoIPEntityStatus `json:"entity_status,omitempty"`

	// PowerMode (电源模式): UDP power mode configuration.
	PowerMode *DoIPPowerMode `json:"power_mode,omitempty"`

	// Activation (路由激活): TCP routing activation configuration.
	Activation *DoIPActivation `json:"activation,omitempty"`

	// Messages (诊断消息): TCP diagnostic message sequence.
	Messages []DoIPMessage `json:"messages,omitempty"`

	// AliveCheck (存活检查): TCP alive check configuration.
	AliveCheck *DoIPAliveCheck `json:"alive_check,omitempty"`

	// GenericNack (通用NACK): Generic header NACK configuration.
	GenericNack *DoIPGenericNack `json:"generic_nack,omitempty"`
}

// DoIPDiscovery describes vehicle discovery phase (UDP, PayloadType 0x0001-0x0004).
type DoIPDiscovery struct {
	// Direction (方向): "up" = Tester→ECU (0x0001/0x0002/0x0003),
	// "down" = ECU→Tester (0x0004 announcement).
	Direction string `json:"direction,omitempty"`

	// RequestType (请求类型): 0x0001=broadcast, 0x0002=with EID, 0x0003=with VIN.
	RequestType uint16 `json:"request_type,omitempty"`

	// Broadcast (广播): true for broadcast/multicast destination.
	Broadcast bool `json:"broadcast,omitempty"`

	// AnnouncementCount (公告次数): Number of 0x0004 announcements (default 3).
	AnnouncementCount uint8 `json:"announcement_count,omitempty"`

	// FurtherActionRequired (后续动作要求): 0x00=none, 0x10=routing activation.
	FurtherActionRequired uint8 `json:"further_action_required,omitempty"`

	// SyncStatus (同步状态): 0x00=synced, 0x10=not synced.
	SyncStatus uint8 `json:"sync_status,omitempty"`
}

// DoIPEntityStatus describes DoIP Entity Status phase (UDP, PayloadType 0x4001-0x4002).
type DoIPEntityStatus struct {
	// Direction (方向): "up" = 0x4001 request, "down" = 0x4002 response.
	Direction string `json:"direction,omitempty"`

	// NodeType (节点类型): 0x00=gateway, 0x01=node.
	NodeType uint8 `json:"node_type,omitempty"`

	// MaxOpenSockets (最大并发socket数): Maximum concurrent TCP sockets.
	MaxOpenSockets uint8 `json:"max_open_sockets,omitempty"`

	// CurOpenSockets (当前打开socket数): Currently open TCP sockets.
	CurOpenSockets uint8 `json:"cur_open_sockets,omitempty"`

	// MaxDataSize (最大数据大小): Maximum single DoIP payload size.
	MaxDataSize uint32 `json:"max_data_size,omitempty"`
}

// DoIPPowerMode describes power mode phase (UDP, PayloadType 0x4003-0x4004).
type DoIPPowerMode struct {
	// Direction (方向): "up" = 0x4003 request, "down" = 0x4004 response.
	Direction string `json:"direction,omitempty"`

	// PowerMode (电源模式): 0x00=not ready, 0x01=ready, 0x02=not supported.
	PowerMode uint8 `json:"power_mode,omitempty"`

	// Broadcast (广播): true for broadcast/multicast.
	Broadcast bool `json:"broadcast,omitempty"`
}

// DoIPActivation describes routing activation phase (TCP, PayloadType 0x0005-0x0006).
type DoIPActivation struct {
	// Direction (方向): "up" = 0x0005 request, "down" = 0x0006 response.
	Direction string `json:"direction,omitempty"`

	// ActivationType (激活类型): 0x00=default, 0x01=WWH-OBD, 0xE0-0xFF=OEM.
	ActivationType uint8 `json:"activation_type,omitempty"`

	// ResponseCode (响应码): 0x10=success, 0x00-0x07=rejected, 0x11=confirmation required.
	ResponseCode uint8 `json:"response_code,omitempty"`

	// OEMSpecific (OEM特定数据): Variable length OEM data.
	OEMSpecific []byte `json:"oem_specific,omitempty"`

	// ConfirmationRequired (需要确认): true for 0x11 response requiring re-activation.
	ConfirmationRequired bool `json:"confirmation_required,omitempty"`
}

// DoIPMessage describes a diagnostic message (TCP, PayloadType 0x8001-0x8003).
type DoIPMessage struct {
	// Direction (方向): "up" = Tester→ECU, "down" = ECU→Tester.
	Direction string `json:"direction,omitempty"`

	// SourceAddress (源地址): SA (TesterAddress for request).
	SourceAddress uint16 `json:"source_address,omitempty"`

	// TargetAddress (目标地址): TA (LogicalAddress for request).
	TargetAddress uint16 `json:"target_address,omitempty"`

	// AckCode (确认码): 0x00=ACK for 0x8002.
	AckCode uint8 `json:"ack_code,omitempty"`

	// NackCode (否定码): nil=send 0x8002, non-nil=send 0x8003.
	NackCode *uint8 `json:"nack_code,omitempty"`

	// UserData (用户数据): Raw UDS bytes for 0x8001 or PreviousDiagnosticMessage.
	UserData []byte `json:"user_data,omitempty"`

	// UDS (UDS报文): Structured UDS data (overrides UserData if set).
	UDS *DoIPUDS `json:"uds,omitempty"`
}

// DoIPUDS describes UDS message embedded in diagnostic message.
type DoIPUDS struct {
	// ServiceID (服务ID): UDS service identifier.
	ServiceID uint8 `json:"service_id,omitempty"`

	// IsResponse (是否响应): true for positive response.
	IsResponse bool `json:"is_response,omitempty"`

	// HasSubFunction (有子功能): auto-detect if nil.
	HasSubFunction *bool `json:"has_sub_function,omitempty"`

	// SubFunction (子功能): Sub-function byte.
	SubFunction uint8 `json:"sub_function,omitempty"`

	// DID (数据标识): Data identifier for 0x22/0x2E.
	DID []byte `json:"did,omitempty"`

	// Data (数据): Service data.
	Data []byte `json:"data,omitempty"`

	// AddressAndLength (地址和长度): For 0x34 RequestDownload.
	AddressAndLength []byte `json:"address_and_length,omitempty"`

	// BlockSequenceCounter (块序列计数器): For 0x36 TransferData.
	BlockSequenceCounter uint8 `json:"block_sequence_counter,omitempty"`

	// TransferData (传输数据): Data block for 0x36.
	TransferData []byte `json:"transfer_data,omitempty"`

	// Seed (种子): SecurityAccess seed for odd subfunction response.
	Seed []byte `json:"seed,omitempty"`

	// Key (密钥): SecurityAccess key for even subfunction request.
	Key []byte `json:"key,omitempty"`

	// NegativeResponseCode (否定响应码): NRC for negative response.
	NegativeResponseCode uint8 `json:"negative_response_code,omitempty"`
}

// DoIPAliveCheck describes alive check phase (TCP, PayloadType 0x0007-0x0008).
type DoIPAliveCheck struct {
	// Direction (方向): "down" = 0x0007 request, "up" = 0x0008 response.
	Direction string `json:"direction,omitempty"`

	// SourceAddress (源地址): Tester address for 0x0008.
	SourceAddress uint16 `json:"source_address,omitempty"`
}

// DoIPGenericNack describes generic header NACK (PayloadType 0x0000).
type DoIPGenericNack struct {
	// NackCode (NACK码): 0x00-0x04 for different error types.
	NackCode uint8 `json:"nack_code,omitempty"`
}

// MQTTConfig configures the MQTT protocol planner (3.1.1 / 5.0). Each
// config drives ONE TCP session (one 4-tuple, one client_id). For multiple
// concurrent clients use Sessions[] — each becomes an independent flow with
// its own 4-tuple and FlowID.
type MQTTConfig struct {
	// Version (版本): 4 = MQTT 3.1.1 (default), 5 = MQTT 5.0.
	Version int `json:"version,omitempty"`

	// ClientID (客户端标识): CONNECT payload Client Identifier. Empty =
	// "trafficgen-<counter6hex>" (deterministic auto-generated per flow via
	// atomic counter, e.g. "trafficgen-000001" — NOT random, ensures
	// reproducibility and uniqueness across concurrent tasks). MQTT allows
	// empty client_id only when Clean Session=true, planner forces Clean
	// when empty. Validate: Sessions内显式重复client_id → 报错; 跨task自动生成保证唯一.
	ClientID string `json:"client_id,omitempty"`

	// KeepAlive (保活间隔, seconds): CONNECT Keep Alive field. nil = default
	// 60 (when both KeepAlive and Sessions are empty). *0 = disable
	// keepalive (server treats as infinite, planner outputs 0x00 0x00).
	// *N (N>0) = N seconds. Pointer type distinguishes "omitted → 60"
	// from "explicit 0 → disabled".
	KeepAlive *int `json:"keep_alive,omitempty"`

	// CleanSession (3.1.1) / CleanStart (5.0): nil = true (default).
	// When false, broker should persist session across reconnects.
	CleanSession *bool `json:"clean_session,omitempty"`

	// Username/Password (认证): CONNECT payload. Empty + non-empty password
	// rejected at Validate. When both empty, Connect Flags bit7/bit6 = 0.
	// 5.0 allows Password without Username; 3.1.1 requires Username Flag=0
	// → Password Flag=0.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Will (遗嘱消息): CONNECT will fields. nil = no will.
	Will *MQTTWill `json:"will,omitempty"`

	// ConnectAckCode (CONNACK Return/Reason Code): 0 = success (default).
	// Non-zero suppresses all downstream publish/subscribe messages.
	// Validate检查取值域: 3.1.1合法值0-5; 5.0精确枚举白名单.
	ConnectAckCode int `json:"connect_ack_code,omitempty"`

	// ConnectAckSessionPresent (CONNACK Session Present bit): false (default).
	// Validate强制: CleanSession=true时此字段必须false;
	// ConnectAckCode≠0时此字段必须false. 违反 → Validate报错.
	ConnectAckSessionPresent bool `json:"connect_ack_session_present,omitempty"`

	// Subscriptions (订阅列表): emitted as one SUBSCRIBE/SUBACK exchange
	// immediately after CONNACK. Empty = skip subscribe phase.
	Subscriptions []MQTTSubscribe `json:"subscriptions,omitempty"`

	// Messages (消息列表): publish/ack exchanges emitted after the subscribe
	// phase (or directly after CONNACK when no subscriptions). Each entry
	// drives QoS 0/1/2 packet exchange per its QoS field. Empty = no publish
	// phase (just CONNECT/CONNACK/PINGREQ/PINGRESP/DISCONNECT).
	Messages []MQTTMessage `json:"messages,omitempty"`

	// PingAfterMessages (心跳触发): when true, emit PINGREQ/PINGRESP after
	// the message phase and before DISCONNECT. false (default) = skip.
	PingAfterMessages bool `json:"ping_after_messages,omitempty"`

	// Disconnect (主动断开): nil = true (default, send DISCONNECT before TCP
	// teardown); *false = TCP RST/FIN without MQTT DISCONNECT (models
	// abnormal disconnect — required for will-message scenarios).
	Disconnect *bool `json:"disconnect,omitempty"`

	// DisconnectReason (5.0 only): Reason Code for the DISCONNECT packet
	// (design §6 S15/T-187). nil = 0 (Normal disconnection). *N = emit
	// Reason Code N (e.g. 0x8D = 141 Keep Alive timeout, 0x94 = 148 Topic
	// Alias invalid). Validate: non-nil on Version=4 → error; value must be
	// in the 5.0 DISCONNECT Reason Code whitelist (§2.11).
	DisconnectReason *int `json:"disconnect_reason,omitempty"`

	// Sessions (多会话列表): when non-empty, the planner emits one flow per
	// entry (each gets a distinct 4-tuple and FlowID via the SubFlow
	// mechanism, mirroring SIP/RTSP multi-stream handling). Inheritance
	// semantics: scalar fields inherit top-level value when session field is
	// zero/nil; slice fields REPLACE (not append) top-level when session
	// field is non-nil, and inherit top-level when nil.
	Sessions []MQTTSession `json:"sessions,omitempty"`

	// Properties (5.0 only): CONNECT-level properties. Ignored when
	// Version=4. nil = no properties entries. IMPORTANT: in 5.0 the
	// Properties Length (VBI) is MANDATORY even when there are no
	// properties — the planner always writes the 0x00 length byte.
	Properties []MQTTProperty `json:"properties,omitempty"`

	// ConnackProperties (5.0 only): CONNACK-level properties (T-198/199/200).
	// nil = no properties (Properties Length=0). Supports Maximum QoS (0x24),
	// Retain Available (0x25), Shared Subscription Available (0x2A), etc.
	// Validate: Version=4 with non-empty → error; each entry must be in the
	// CONNACK whitelist (§8.4).
	ConnackProperties []MQTTProperty `json:"connack_properties,omitempty"`
}

// MQTTWill is the CONNECT Will Message configuration.
type MQTTWill struct {
	// Topic (遗嘱主题): Will Topic. Empty = error at Validate.
	Topic string `json:"topic,omitempty"`

	// Payload (遗嘱负载): Will Payload bytes. Empty = zero-length payload
	// (valid per RFC).
	Payload string `json:"payload,omitempty"`

	// QoS (遗嘱QoS): 0 (default), 1, or 2. Validated against the QoS table.
	QoS int `json:"qos,omitempty"`

	// Retain (遗嘱保留): true = broker caches will as retained message.
	Retain bool `json:"retain,omitempty"`

	// DelayInterval (5.0 only): Will Delay Interval seconds. 0 = publish
	// immediately on disconnect. Validate: Version=4 + DelayInterval≠0 →
	// 报错. 编码为 Will Properties段中的 ID 0x18 (Four Byte Integer).
	DelayInterval int `json:"delay_interval,omitempty"`
}

// MQTTMessage is one PUBLISH exchange. QoS determines the downstream
// ack chain: QoS0 → PUBLISH only; QoS1 → PUBLISH+PUBACK; QoS2 →
// PUBLISH+PUBREC+PUBREL+PUBCOMP. Direction "up" (default) = client→server
// (client publishes), "down" = server→client (server publishes down to the
// subscribing client — models broker forwarding a retained/matched message).
type MQTTMessage struct {
	Topic     string `json:"topic,omitempty"`     // PUBLISH topic; empty = error (除非 Topic Alias已建映射)
	Payload   string `json:"payload,omitempty"`   // application message bytes
	QoS       int    `json:"qos,omitempty"`       // 0 (default), 1, 2
	Retain    bool   `json:"retain,omitempty"`    // PUBLISH retain flag
	DUP       bool   `json:"dup,omitempty"`       // PUBLISH dup flag (QoS>0 only)
	PacketID  uint16 `json:"packet_id,omitempty"` // 0 = auto-increment from 1
	Direction string `json:"direction,omitempty"` // "up" (default) or "down"

	// Properties (5.0 only): PUBLISH-level properties. Ignored when
	// MQTTConfig.Version=4.
	Properties []MQTTProperty `json:"properties,omitempty"`
}

// MQTTSubscribe is one SUBSCRIBE/SUBACK exchange.
type MQTTSubscribe struct {
	// PacketID: SUBSCRIBE packet identifier. 0 = auto-increment.
	PacketID uint16 `json:"packet_id,omitempty"`

	// Filters (订阅过滤器): topic filter list. Each gets one Reason Code in
	// SUBACK payload. Empty = error at Validate.
	Filters []MQTTTopicFilter `json:"filters,omitempty"`

	// AckReasonCodes (SUBACK Reason Codes): one per filter. Empty = all 0x00
	// (QoS0 granted). Length must match Filters; mismatch = error.
	AckReasonCodes []int `json:"ack_reason_codes,omitempty"`

	// Properties (5.0 only): SUBSCRIBE-level properties. Whitelist:
	// 0x0B Subscription Identifier (vbi), 0x26 User Property (stringpair).
	// Ignored when Version != 5. Subscription Identifier value 0 is
	// rejected (MQTT 5.0 §3.3.2.3.8 reserves it as a "no subscription"
	// sentinel).
	Properties []MQTTProperty `json:"properties,omitempty"`
}

// MQTTTopicFilter is one topic filter in a SUBSCRIBE.
type MQTTTopicFilter struct {
	Filter string `json:"filter,omitempty"` // e.g. "sensor/+", "sport/#", "a/b/c"
	QoS    int    `json:"qos,omitempty"`    // 0 (default), 1, 2

	// 5.0订阅选项（3.1.1必须为0/默认）
	NoLocal           bool `json:"no_local,omitempty"`            // bit2, 5.0 only
	RetainAsPublished bool `json:"retain_as_published,omitempty"` // bit3, 5.0 only
	RetainHandling    int  `json:"retain_handling,omitempty"`     // bit4-5, 5.0 only, 0/1/2
}

// MQTTProperty is one MQTT 5.0 property. Identifier is the 5.0 §2.2.2.2
// Property Identifier. Value is encoded by Format:
//
//	"byte"      → 1-byte unsigned (Payload Format Indicator, etc.)
//	"uint16"    → 2-byte big-endian (Topic Alias, Server Keep Alive, etc.)
//	"uint32"    → 4-byte big-endian (Session Expiry, Message Expiry, etc.)
//	"string"    → 2-byte length + UTF-8 bytes (Content Type, Response Topic,
//	              Reason String)
//	"binary"    → 2-byte length + raw bytes (Correlation Data)
//	"stringpair"→ 2-byte len key + 2-byte len value (User Property, repeated)
//	"vbi"       → Variable Byte Integer (Subscription Identifier)
//
// Format "" defaults to "string" (most common).
type MQTTProperty struct {
	Identifier int    `json:"identifier"`
	Format     string `json:"format,omitempty"`
	Value      string `json:"value,omitempty"` // numeric for byte/uint16/uint32/vbi; text for string; hex for binary; "k\x00v" for stringpair
}

// MQTTSession overrides the top-level MQTTConfig fields for one client
// session. Only non-zero/non-empty fields override; absent fields inherit
// from the parent. Each session becomes an independent TCP 4-tuple (SrcPort
// auto-increments when HasExplicitSrcPort=false).
type MQTTSession struct {
	ClientID      string          `json:"client_id,omitempty"`
	KeepAlive     *int            `json:"keep_alive,omitempty"`
	CleanSession  *bool           `json:"clean_session,omitempty"`
	Username      string          `json:"username,omitempty"`
	Password      string          `json:"password,omitempty"`
	Will          *MQTTWill       `json:"will,omitempty"`
	Subscriptions []MQTTSubscribe `json:"subscriptions,omitempty"`
	Messages      []MQTTMessage   `json:"messages,omitempty"`
	Disconnect    *bool           `json:"disconnect,omitempty"`
	// DisconnectReason (5.0 only): per-session override of the top-level
	// DISCONNECT Reason Code. nil = inherit from top-level.
	DisconnectReason *int `json:"disconnect_reason,omitempty"`
	// Bug fix: changed from `bool` to `*bool` so a session can explicitly
	// override top-level PingAfterMessages=true to false. Previously the
	// merge only checked `if s.PingAfterMessages` (true-only), so a
	// session could never turn off the heartbeat once the top-level set
	// it on. nil = inherit from top-level, *false = override off,
	// *true = override on.
	PingAfterMessages *bool          `json:"ping_after_messages,omitempty"`
	Properties        []MQTTProperty `json:"properties,omitempty"`
	// ConnackProperties (5.0 only): per-session override of the top-level
	// CONNACK properties. nil = inherit from top-level.
	ConnackProperties []MQTTProperty `json:"connack_properties,omitempty"`

	// SrcPort/DstPort override: 0 = inherit from FlowSpec / auto-assign.
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
}

// SMBConfig holds SMB2/SMB3 protocol configuration (MS-SMB2). 该配置由
// internal/protocol/smb 规划的 planner 读取，通过 FlowSpec.SMB 挂载。
// 完整的 SMB2/SMB3 会话生命周期（协商/认证/树连接/文件操作/拆解）控制。
type SMBConfig struct {
	// --- 传输层 ---

	// Transport (传输模式): "direct" (默认, 端口 445 Direct TCP) 或
	// "netbios" (端口 139, NBSS 前缀). 空默认 direct.
	Transport string `json:"transport,omitempty"`

	// --- 协商阶段 ---

	// Dialects (方言列表): 客户端支持的 dialect 列表，如
	// ["0x0202","0x0210","0x0300","0x0302","0x0311"]. 空默认
	// ["0x0202","0x0210","0x0300","0x0302","0x0311"] (覆盖
	// SMB2.002/2.1/3.0/3.0.2/3.1.1).
	// 服务端选中 dialect = 列表最后一个 (假设服务端支持最高版本).
	Dialects []string `json:"dialects,omitempty"`

	// SelectedDialect (选中方言): 服务端选中的 dialect; 空默认
	// Dialects 列表最后一个. 用于响应包生成.
	SelectedDialect string `json:"selected_dialect,omitempty"`

	// ClientGuid (客户端 GUID): 16 字节客户端标识; 空默认随机生成.
	ClientGuid [16]byte `json:"client_guid,omitempty"`

	// ServerGuid (服务端 GUID): 16 字节服务端标识; 空默认随机生成.
	ServerGuid [16]byte `json:"server_guid,omitempty"`

	// ClientCapabilities (客户端能力): bitmask; 0 默认
	// SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x03).
	// 注意: SelectedDialect < 0x0300 (0x0202/0x0210) 时自动清 bit0
	// (Encryption 仅 SMB3 有意义).
	ClientCapabilities uint32 `json:"client_capabilities,omitempty"`

	// ServerCapabilities (服务端能力): 同上.
	ServerCapabilities uint32 `json:"server_capabilities,omitempty"`

	// SecurityMode (安全模式): bit0=SigningEnabled, bit1=SigningRequired.
	// 0 默认 SigningEnabled (0x01).
	SecurityMode uint16 `json:"security_mode,omitempty"`

	// SigningRequired (要求签名): true 时 SecurityMode |= 0x02.
	SigningRequired bool `json:"signing_required,omitempty"`

	// --- 认证阶段 ---

	// AuthMechanism (认证机制): "ntlm" (默认) 或 "kerberos" 或 "anonymous"
	// 或 "guest". 决定 SESSION_SETUP SecurityBlob 占位内容.
	AuthMechanism string `json:"auth_mechanism,omitempty"`

	// Username (用户名): NTLM/Kerberos 用户名.
	Username string `json:"username,omitempty"`

	// Domain (域): NTLM 域名或 Kerberos realm.
	Domain string `json:"domain,omitempty"`

	// Password (密码): 仅用于占位字段, 不做真实加密.
	Password string `json:"password,omitempty"`

	// SecurityBlob (安全 Blob): 用户自定义 GSS-API/SPNEGO blob; 设置时
	// 覆盖 AuthMechanism 自动生成的占位.
	SecurityBlob []byte `json:"security_blob,omitempty"`

	// AuthRounds (认证轮数): SESSION_SETUP 交换轮数; 0 表示默认
	// (按机制换算: ntlm→3, kerberos→2, anonymous/guest→1);
	// 显式非 0 必须在 1-3 且与机制匹配 (ntlm 只能 2 或 3).
	AuthRounds int `json:"auth_rounds,omitempty"`

	// --- 树连接阶段 ---

	// TreeConnectShare (树连接共享): UNC 路径, 如 "\\server\share" 或
	// "\\server\IPC$" (命名管道). 空默认 "\\server\share".
	TreeConnectShare string `json:"tree_connect_share,omitempty"`

	// ShareType (共享类型): 0=DISK、1=PIPE、2=PRINT. 空默认 0.
	// IPC$ 自动设为 1.
	ShareType uint8 `json:"share_type,omitempty"`

	// --- 文件操作阶段 ---

	// FilePath (文件路径): CREATE 命令打开的文件名, UTF-8 字符串; planner
	// 自动转 UTF-16LE. 空默认 "file.txt".
	FilePath string `json:"file_path,omitempty"`

	// CreateDisposition (打开方式): 0=supersede、1=open、2=create、
	// 3=open_if、4=overwrite、5=overwrite_if. 空默认 1 (open).
	CreateDisposition uint8 `json:"create_disposition,omitempty"`

	// AccessMask (访问掩码): 0 默认 0x00120089 (GENERIC_READ +
	// FILE_READ_DATA + SYNCHRONIZE).
	AccessMask uint32 `json:"access_mask,omitempty"`

	// FileAttributes (文件属性): 0 默认 0x80 (NORMAL).
	FileAttributes uint32 `json:"file_attributes,omitempty"`

	// ShareAccess (共享访问): bit0=READ、bit1=WRITE、bit2=DELETE.
	// 0 默认 0x07 (RWX).
	ShareAccess uint8 `json:"share_access,omitempty"`

	// CreateOptions (创建选项): 0 默认 0 (普通文件).
	CreateOptions uint32 `json:"create_options,omitempty"`

	// FileId (文件号): CREATE 响应分配的 16 字节 FileId; 用于后续
	// READ/WRITE/CLOSE. 全 0 表示由 planner 在 CREATE 响应时随机分配.
	FileId [16]byte `json:"file_id,omitempty"`

	// --- 操作序列 ---

	// Operations (操作序列): 文件操作列表, 按顺序执行. 每个操作生成
	// 1 对请求/响应. 空默认 [{OpType:"read", Offset:0, Length:4096}].
	Operations []SMBOperation `json:"operations,omitempty"`

	// --- SMB3 高级 ---

	// PreauthIntegrityHashAlgorithms (预认证完整性算法列表): SMB3.1.1 才有;
	// 0x0001=SHA-512. 空默认 [0x0001].
	PreauthIntegrityHashAlgorithms []uint16 `json:"preauth_integrity_hash_algorithms,omitempty"`

	// EncryptionAlgorithm (加密算法): SMB3.1.1 才有; 0x0001=AES-CCM、
	// 0x0002=AES-GCM. 0 默认 0x0001.
	EncryptionAlgorithm uint16 `json:"encryption_algorithm,omitempty"`

	// EncryptionRequired (要求加密): true 时 SessionFlags.EncryptData=1.
	EncryptionRequired bool `json:"encryption_required,omitempty"`

	// --- 业务控制 ---

	// MaxTransactSize (最大事务大小): 默认 65536 (64KB).
	MaxTransactSize uint32 `json:"max_transact_size,omitempty"`

	// MaxReadSize (最大读大小): 默认 1048576 (1MB).
	MaxReadSize uint32 `json:"max_read_size,omitempty"`

	// MaxWriteSize (最大写大小): 默认 1048576 (1MB).
	MaxWriteSize uint32 `json:"max_write_size,omitempty"`

	// IncludeNegotiate (包含协商): true 默认; false 跳过 NEGOTIATE 阶段.
	IncludeNegotiate *bool `json:"include_negotiate,omitempty"`

	// PreviousSessionId (上次会话 ID): SESSION_SETUP 请求 PreviousSessionId
	// 字段（多通道重连时复用上次会话）；0 默认 0（独立会话无重连）.
	PreviousSessionId uint64 `json:"previous_session_id,omitempty"`

	// IncludeAuth (包含认证): true 默认; false 跳过 SESSION_SETUP.
	IncludeAuth *bool `json:"include_auth,omitempty"`

	// IncludeTreeConnect (包含树连接): true 默认; false 跳过 TREE_CONNECT.
	IncludeTreeConnect *bool `json:"include_tree_connect,omitempty"`

	// IncludeTeardown (包含会话拆解): true 默认; false 跳过
	// TREE_DISCONNECT/LOGOFF.
	IncludeTeardown *bool `json:"include_teardown,omitempty"`

	// --- 错误注入 (测试用) ---

	// ErrorResponseStatus (错误响应状态码): 非零时所有命令响应返回
	// 该 NT 状态码 (用于测试异常路径). 0 默认 STATUS_SUCCESS.
	ErrorResponseStatus uint32 `json:"error_response_status,omitempty"`

	// ErrorOnCommand (在指定命令返回错误): 命令名; 该命令的响应返回
	// ErrorResponseStatus, 后续命令按 §4.2 跳过规则表决定.
	ErrorOnCommand string `json:"error_on_command,omitempty"`
}

// SMBOperation describes a single SMB file operation.
type SMBOperation struct {
	OpType        string   `json:"op_type"`
	Offset        uint64   `json:"offset,omitempty"`
	Length        uint32   `json:"length,omitempty"`
	Data          []byte   `json:"data,omitempty"`
	DataB64       string   `json:"data_b64,omitempty"`
	FileName      string   `json:"file_name,omitempty"`
	InfoClass     uint8    `json:"info_class,omitempty"`
	InfoType      uint8    `json:"info_type,omitempty"`
	FileInfoClass uint8    `json:"file_info_class,omitempty"`
	FileId        [16]byte `json:"file_id,omitempty"`
	MinimumCount  uint32   `json:"minimum_count,omitempty"`
	Flags         uint32   `json:"flags,omitempty"`
}

// ENIPConfig holds EtherNet/IP (ENIP, ODVA EtherNet/IP Volume 1 & 2)
// protocol configuration. ENIP encapsulates CIP over TCP/UDP port 44818.
// All multi-byte fields are little-endian.
type ENIPConfig struct {
	Scenario         string        `json:"scenario,omitempty"`
	Transport        string        `json:"transport,omitempty"`
	SessionCount     int           `json:"session_count,omitempty"`
	FlowCount        int           `json:"flow_count,omitempty"`
	Commands         []ENIPCommand `json:"commands,omitempty"`
	IOData           *ENIPIOData   `json:"io_data,omitempty"`
	VendorID         uint16        `json:"vendor_id,omitempty"`
	DeviceType       uint16        `json:"device_type,omitempty"`
	ProductCode      uint16        `json:"product_code,omitempty"`
	FirmwareMajorRev uint8         `json:"firmware_major_rev,omitempty"`
	FirmwareMinorRev uint8         `json:"firmware_minor_rev,omitempty"`
	ProductName      string        `json:"product_name,omitempty"`
	SerialNumber     uint32        `json:"serial_number,omitempty"`
	DeviceStatus     uint16        `json:"device_status,omitempty"`
	DeviceState      uint8         `json:"device_state,omitempty"`
}

// ENIPCommand represents a single ENIP message command configuration.
type ENIPCommand struct {
	Command       uint16 `json:"command"`
	Length        uint16 `json:"length,omitempty"`
	SessionHandle uint32 `json:"session_handle,omitempty"`
	// SessionHandleStrategy 记录 session_handle 配置为策略 map 时的 strategy 键
	// （如 {"strategy":"inc",...}），仅用于 Validate 拒绝非法策略（设计 §7.3 T-090/091）。
	// 该字段仅存在于配置解析层，不参与序列化。
	SessionHandleStrategy string `json:"-"`
	Status                uint32 `json:"status,omitempty"`
	SenderContext         uint64 `json:"sender_context,omitempty"`
	Options               uint32 `json:"options,omitempty"`
	Payload               []byte `json:"payload,omitempty"`
	ProtocolVersion       uint16 `json:"protocol_version,omitempty"`
	OptionFlag            uint16 `json:"option_flag,omitempty"`
	InterfaceHandle       uint32 `json:"interface_handle,omitempty"`
	Timeout               uint16 `json:"timeout,omitempty"`
	// PriorityTimeTick 和 TimeoutTicks 是 Forward_Open/Forward_Close 的 CIP 超时参数。
	PriorityTimeTick            uint8            `json:"priority_time_tick,omitempty"`
	TimeoutTicks                uint8            `json:"timeout_ticks,omitempty"`
	CPFItems                    []CPFItem        `json:"cpf_items,omitempty"`
	CIPService                  uint8            `json:"cip_service,omitempty"`
	ClassID                     uint16           `json:"class_id,omitempty"`
	InstanceID                  uint32           `json:"instance_id,omitempty"`
	AttributeID                 uint16           `json:"attribute_id,omitempty"`
	ConnSerialNum               uint16           `json:"conn_serial_number,omitempty"`
	OrigVendorID                uint16           `json:"originator_vendor_id,omitempty"`
	OrigSerialNum               uint32           `json:"originator_serial_number,omitempty"`
	O2TConnID                   uint32           `json:"o2t_connection_id,omitempty"`
	T2OConnID                   uint32           `json:"t2o_connection_id,omitempty"`
	O2TRPI                      uint32           `json:"o2t_rpi,omitempty"`
	T2ORPI                      uint32           `json:"t2o_rpi,omitempty"`
	O2TConnParams               uint32           `json:"o2t_connection_parameters,omitempty"`
	T2OConnParams               uint32           `json:"t2o_connection_parameters,omitempty"`
	TransportClassTrigger       uint8            `json:"transport_class_trigger,omitempty"`
	ConnectionPath              []byte           `json:"connection_path,omitempty"`
	ConnectionPathSize          uint8            `json:"connection_path_size,omitempty"`
	ConnectionTimeoutMultiplier uint8            `json:"connection_timeout_multiplier,omitempty"`
	SubRequests                 []ENIPSubRequest `json:"sub_requests,omitempty"`
	Direction                   string           `json:"direction,omitempty"`
	GeneralStatus               uint8            `json:"general_status,omitempty"`
	AdditionalStatus            []uint16         `json:"additional_status,omitempty"`
	VendorID                    uint16           `json:"vendor_id,omitempty"`
	DeviceType                  uint16           `json:"device_type,omitempty"`
	ProductCode                 uint16           `json:"product_code,omitempty"`
	FirmwareMajorRev            uint8            `json:"firmware_major_rev,omitempty"`
	FirmwareMinorRev            uint8            `json:"firmware_minor_rev,omitempty"`
	ProductName                 string           `json:"product_name,omitempty"`
	SerialNumber                uint32           `json:"serial_number,omitempty"`
	DeviceStatus                uint16           `json:"device_status,omitempty"`
	DeviceState                 uint8            `json:"device_state,omitempty"`
	SourceCommandIndex          int              `json:"source_command_index,omitempty"`
	FromResponseField           string           `json:"from_response_field,omitempty"`
	// ResponsePayload 携带本命令对应响应的原始 ENIP 数据（含 24B ENIP 头）,
	// 供后续命令通过 FromResponseField/SourceCommandIndex 引用提取字段
	// （session_handle / o2t_connection_id / t2o_connection_id /
	// connection_serial_number，见设计 §5.6.1）。请求场景忽略。
	ResponsePayload []byte `json:"-"`
	// SenderContextPtr 显式强制 SenderContext 值（包括 0）。
	// 非 nil 时直接采用该值；否则按 SenderContext 非零用其值、
	// 为零时使用 flow 内递增默认值（设计 §6.13 S12）。
	SenderContextPtr *uint64 `json:"-"`
}

// CPFItem represents a Common Packet Format item.
type CPFItem struct {
	TypeID uint16 `json:"type_id"`
	Length uint16 `json:"length,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// ENIPSubRequest represents a sub-request within a Multiple_Service_Packet.
type ENIPSubRequest struct {
	Service     uint8  `json:"service"`
	ClassID     uint16 `json:"class_id,omitempty"`
	InstanceID  uint32 `json:"instance_id,omitempty"`
	AttributeID uint16 `json:"attribute_id,omitempty"`
	Data        []byte `json:"data,omitempty"`
}

// ENIPIOData holds implicit I/O messaging configuration.
type ENIPIOData struct {
	O2TConnectionID       uint32 `json:"o2t_connection_id,omitempty"`
	T2OConnectionID       uint32 `json:"t2o_connection_id,omitempty"`
	SequenceStart         uint16 `json:"sequence_start,omitempty"`
	SequenceStep          uint16 `json:"sequence_step,omitempty"`
	FrameCount            int    `json:"frame_count,omitempty"`
	FrameInterval         uint32 `json:"frame_interval,omitempty"`
	FrameSize             uint16 `json:"frame_size,omitempty"`
	Payload               []byte `json:"payload,omitempty"`
	TransportClassTrigger uint8  `json:"transport_class_trigger,omitempty"`
	// SourceCommandIndex 指定 o2t_connection_id 来源命令（本 flow 内
	// source_command_index，设计 §5.6.1）：I/O 帧的 Connection Address
	// Item 使用该命令响应中提取的 O→T Connection ID（Forward_Open 响应
	// CIP body offset 0）。nil 表示不使用 from_response（取
	// O2TConnectionID 字段值）；非 nil 且 O2TConnectionID=0 时由响应提取
	// 填充。flow 隔离：索引相对本 flow 命令序列。
	SourceCommandIndex *int `json:"source_command_index,omitempty"`
	// T2OConnectionID 在 SendUnitData 发包路径（originator→target）不使用
	// （那是 originator 接收方向的 ID，设计 §3.6/§5.5）。
}

// SRv6Config configures the SRv6 Segment Routing Header (RFC 8754, IPv6
// extension header Next Header = 43, Routing Type = 4). When non-nil, the
// planner emits one IPv6 packet per flow carrying an SRH with the
// configured Segment List. SRv6 is NOT a standalone transport protocol —
// it is an IPv6 extension header. See internal/protocol/srv6 for the
// planner, serializer, and validation rules (design §5.1).
type SRv6Config struct {
	// SrcIPv6 is the outer IPv6 source address. Empty = spec.SrcIP.
	SrcIPv6 string `json:"src_ipv6,omitempty"`

	// DstIPv6 is the outer IPv6 destination as written by the source node.
	// Empty = SegmentList[0] (user-facing first segment = first to process;
	// on wire: List[n-1] = highest index). RFC 8754 §4.1: DA = first segment.
	DstIPv6 string `json:"dst_ipv6,omitempty"`

	// SegmentList is the SR Policy in user-facing processing order. Entry 0
	// is FIRST segment processed; entry n-1 is LAST (final destination).
	// Planner REVERSES this list when writing to the wire (RFC 8754 §2).
	// 1..127 entries (uint8 HdrExtLen limit).
	SegmentList []string `json:"segment_list"`

	// SegmentsLeft is the Segments Left field. 0 = reached final segment.
	// Use SegmentsLeftPtr (*uint8) to disambiguate "user explicit 0" from
	// "user did not set": nil = default len-1, non-nil = explicit.
	SegmentsLeft    uint8  `json:"segments_left,omitempty"`
	SegmentsLeftPtr *uint8 `json:"segments_left_ptr,omitempty"`

	// LastEntry is the last Segment List entry index. Source node: len-1
	// (non-reduced) or len-2 (reduced, RFC 8754 §4.1.1).
	LastEntry    uint8  `json:"last_entry,omitempty"`
	LastEntryPtr *uint8 `json:"last_entry_ptr,omitempty"`

	// Reduced indicates reduced SRH (RFC 8754 §4.1.1): omit SegmentList[n-1],
	// LastEntry = len-2. Default: true when SegType == "end.b6.encaps.red",
	// false otherwise (design §5.3 S11). An explicit user value overrides the
	// SegType default.
	//
	// ReducedPtr disambiguates "user did not set reduced" from "user set
	// reduced=false": nil = SegType default, non-nil = explicit value. It is
	// populated by parseSRv6Config from the same "reduced" JSON key as
	// Reduced (json:"-" so encoding/json on SRv6Config never sees two fields
	// with the same tag; SRv6Config is decoded via parseSRv6Config only).
	// resolveReduced (srv6 package) prefers ReducedPtr, falling back to the
	// SegType default and then to Reduced for backward compatibility.
	Reduced    bool  `json:"reduced,omitempty"`
	ReducedPtr *bool `json:"-"`

	// Flags is the SRH Flags byte. RFC 8754 §2.1: ALL 8 bits Unused
	// (MUST be 0). HMAC is carried by TLV Type=5, not by a flag bit.
	Flags uint8 `json:"flags,omitempty"`

	// Tag is the 16-bit SRH Tag. 0 = no tag. Big-endian on wire.
	Tag uint16 `json:"tag,omitempty"`

	// SegType selects which End* behavior to emulate (RFC 8986 §3.4).
	SegType string `json:"seg_type,omitempty"`

	// PayloadProtocol is the inner protocol after SRH.
	// "tcp" / "udp" / "icmpv6" / "ipv6" / "ipv4" / "none".
	// "ipv6" = NH 41 (End.DX6/B6/etc., RFC 8986 §4.4/§4.13).
	// "ipv4" = NH 4 (End.DX4/DT4, RFC 8986 §4.5/§4.8).
	// "none" = NH 59 (No Next Header, RFC 8200 §4.7).
	PayloadProtocol string `json:"payload_protocol,omitempty"`

	// InnerPayload is the inner payload bytes. nil = spec.Payload.
	InnerPayload []byte `json:"inner_payload,omitempty"`

	// InnerSrcPort / InnerDstPort are inner L4 ports. 0 = spec.SrcPort /
	// spec.DstPort.
	InnerSrcPort uint16 `json:"inner_src_port,omitempty"`
	InnerDstPort uint16 `json:"inner_dst_port,omitempty"`

	// TLV is the optional TLV list appended after Segment List. Pad1/PadN
	// are auto-inserted for 8-byte alignment (do not set manually). HMAC
	// TLV (Type=5) requires 8n alignment (RFC 8754 §2.1.2).
	TLV []SRv6TLV `json:"tlv,omitempty"`

	// Frames is the number of SRv6 packets emitted. 0 = 1.
	// Frames does NOT vary SRH content; per-frame SL--/DstIP updates are
	// expressed by multiple FlowSpecs, never by Frames.
	Frames int `json:"frames,omitempty"`

	// Direction is "up" (default) or "down" (swaps MACs/IPs/ports AND
	// reverses SegmentList). Direction=down requires source-node view
	// (SegmentsLeftPtr MUST be nil).
	Direction string `json:"direction,omitempty"`
}

// SRv6TLV is one SRH TLV (RFC 8754 §2.1.1 + §8.2 IANA registry).
//
//	0 = Pad1 (auto-inserted, do not set manually)
//	4 = PadN (auto-inserted, do not set manually)
//	5 = HMAC (8n alignment, RFC 8754 §2.1.2)
//	1, 2, 3, 6 = Reserved (MUST NOT be set; HMAC-Sig TLV does NOT exist)
//	124-126, 252-254 = Experimentation and Test
//	127, 255 = Reserved
type SRv6TLV struct {
	Type  uint8  `json:"type"`
	Value []byte `json:"value,omitempty"`
}

// SRHConfig is the IPv6 Segment Routing Header (RFC 8754) wire-level layout
// that the core builder consumes. The SRv6 planner fills this from the
// user-facing SRv6Config (which carries SegmentList in user order) by
// reversing the list and stripping the reduced first entry.
//
// All IPv6 address fields are written verbatim — the builder does no
// validation; the srv6 planner's Validate step is the contract.
type SRHConfig struct {
	// NextHeader is the protocol number following the SRH (e.g. 17=UDP,
	// 6=TCP, 41=IPv6). The IPv6 fixed header's NH field points to the SRH
	// (43); the SRH's NH carries this value.
	NextHeader uint8

	// HdrExtLen is the SRH Header Extension Length in 8-octet units minus 1
	// (RFC 8754 §2.1). Computed as (totalSrhLen/8) - 1.
	HdrExtLen uint8

	// SegmentsLeft is the segments-left counter (RFC 8754 §4.3.1.1).
	SegmentsLeft uint8

	// LastEntry is the last segment index in the wire SegmentList.
	// Non-reduced SRH: len(SegmentList)-1. Reduced SRH: len-2.
	LastEntry uint8

	// Flags is the SRH Flags byte. RFC 8754 §2.1: ALL 8 bits Unused
	// (MUST be 0). HMAC is carried by TLV Type=5, not by a flag bit.
	Flags uint8

	// Tag is the 16-bit SRH Tag. Big-endian on wire.
	Tag uint16

	// SegmentList is the wire-format Segment List (RFC 8754 §2: REVERSED
	// from user order; the first entry processed is at the highest index,
	// the last entry at index 0). For reduced SRH (RFC 8754 §4.1.1) the
	// first segment (already in DstIP) is omitted, so this list has
	// len(userList)-1 entries.
	SegmentList [][16]byte

	// TLV is the optional TLV list after the Segment List. PadN entries are
	// auto-inserted for 8-byte alignment (RFC 8754 §2.1).
	TLV []SRv6TLV

	// Reduced marks a reduced SRH (RFC 8754 §4.1.1). The srv6 planner sets
	// it; the builder needs it to verify HdrExtLen against the wire bytes
	// (design §7.7 EXC-01) without re-deriving the reduced rule.
	Reduced bool
}

// GBT32960Config configures the GBT32960 protocol (GB/T 32960.3-2016
// 电动汽车远程服务与管理系统技术规范 第3部分：通讯协议). It is
// attached to FlowSpec.GBT32960; the internal/protocol/gbt32960 planner
// emits a TCP handshake, a sequence of GBT32960 messages (each as one
// PSH-ACK payload), and a TCP teardown — all within one flow.
//
// A single GBT32960 flow models ONE vehicle (or one platform-as-client
// session). Multi-vehicle scenarios use multiple FlowSpecs, each with a
// unique VIN and a distinct 4-tuple (see design §7.11).
type GBT32960Config struct {
	// Role (角色) selects the side: "vehicle" (default) or "platform".
	// vehicle = 车载终端 side (上行 0x01/0x02/0x03/0x04);
	// platform = 平台侧作为 client 登入上级平台 (0x05/0x06/0x0B).
	Role string `json:"role,omitempty"`

	// VIN (车辆识别码, Vehicle Identification Number) — 17-byte ASCII.
	// Shorter values are right-padded with VINPadByte (default 0x00);
	// longer values trigger V2 error (no silent truncation).
	// Required when Role="vehicle"; for Role="platform", use PlatformID.
	// Charset: I/O/Q not allowed (V3b).
	VIN string `json:"vin,omitempty"`

	// VINPadByte (VIN 补齐字节) — byte used to right-pad VIN shorter
	// than 17 bytes. Default 0x00; 0x20 supported for some platforms.
	VINPadByte *byte `json:"vin_pad_byte,omitempty"`

	// SIM (车辆 SIM 号 / ICCID) — up to 20-byte ASCII. Right-padded with 0x00.
	// Used as the ICCID field of 0x01 vehicle login data unit.
	SIM string `json:"sim,omitempty"`

	// EncryptRule (数据加密方式): "01"=不加密 (default), "02"=RSA,
	// "03"=AES128, "04"=SM2, "05"=SM4. Only the field value is emitted;
	// the planner does NOT actually encrypt the data unit (see §7.10).
	EncryptRule string `json:"encrypt_rule,omitempty"`

	// LoginSerialNumber (登入流水号) — uint16, range 1-65531. Default 1.
	LoginSerialNumber int `json:"login_serial_number,omitempty"`

	// LogoutSerialNumber (登出流水号) — uint16, range 1-65531. Per spec
	// must equal the LoginSerialNumber of the same session. 0 (empty) =
	// planner uses LoginSerialNumber automatically.
	LogoutSerialNumber int `json:"logout_serial_number,omitempty"`

	// RechargeableSubsysCount (可充电储能子系统数 n) — n >= 1. Default 1.
	RechargeableSubsysCount int `json:"rechargeable_subsys_count,omitempty"`

	// RechargeableSubsysCodeLength (可充电储能系统编码长度 m) — m >= 1.
	// Default 1. Each subsystem code is m bytes.
	RechargeableSubsysCodeLength int `json:"rechargeable_subsys_code_length,omitempty"`

	// RechargeableSubsysCodes (可充电储能系统编码) — string slice, length
	// must equal RechargeableSubsysCount. Each entry is right-padded or
	// truncated to m bytes. Empty = all zeros.
	RechargeableSubsysCodes []string `json:"rechargeable_subsys_codes,omitempty"`

	// LoginTime (登入时间) — RFC3339 string (timezone required). Empty =
	// use time.Now() in local timezone (documented as GMT+8).
	LoginTime string `json:"login_time,omitempty"`

	// LogoutTime (登出时间) — same format as LoginTime. Empty = LoginTime
	// plus Σ(Reports interval) + 60s (or LoginTime + 60s default).
	LogoutTime string `json:"logout_time,omitempty"`

	// Reports (实时上报序列) — list of realtime report entries. Each
	// entry produces one 0x02 message.
	Reports []GBT32960Report `json:"reports,omitempty"`

	// ReissueReports (补报序列) — list of entries to send as 0x03.
	ReissueReports []GBT32960Report `json:"reissue_reports,omitempty"`

	// AlarmData (报警数据) — when set, planner emits one info-type 0x07
	// info body in the next 0x02 message that does not set its own.
	AlarmData *GBT32960AlarmData `json:"alarm_data,omitempty"`

	// RemoteControl (远程控制响应) — when set, planner emits 0x08 from
	// platform → vehicle, then 0x0C acknowledgement from vehicle.
	RemoteControl *GBT32960RemoteControl `json:"remote_control,omitempty"`

	// PlatformLogin (平台登入) — when Role="platform", planner emits
	// 0x05 → 0x0C → 0x0B × N → 0x06.
	PlatformLogin *GBT32960PlatformLogin `json:"platform_login,omitempty"`

	// PlatformID (平台唯一识别码) — 17-byte ASCII used as the VIN field
	// of platform-side messages (0x05/0x06/0x0B). Required when
	// Role="platform"; empty = 17 bytes of 0x00.
	PlatformID string `json:"platform_id,omitempty"`

	// PlatformDomain (平台域名) — stored for logging; not emitted in v1.
	PlatformDomain string `json:"platform_domain,omitempty"`

	// SetPlatformDomain (设置平台域名) — target domain via 0x0A (v1 unused).
	SetPlatformDomain string `json:"set_platform_domain,omitempty"`

	// ConnectID (连接 ID) — empty = planner auto-generates from 4-tuple.
	ConnectID string `json:"connect_id,omitempty"`

	// IsTransBatteryData (是否传输电池数据) — default true. When false,
	// planner emits only vehicle-position info body (0x05).
	IsTransBatteryData *bool `json:"is_trans_battery_data,omitempty"`

	// HeartbeatCount (心跳次数) — number of 0x0B messages to emit.
	// Applies only when Role="platform". 0 = no heartbeat.
	HeartbeatCount int `json:"heartbeat_count,omitempty"`

	// ResponseFlags (应答标志) — overrides 0xFE on the NEXT UPLINK
	// message's resp field. Use "01"/"02"/"03"/"04" (see §3.12, §7.13).
	// Empty = 0xFE (normal uplink behavior).
	ResponseFlags string `json:"response_flags,omitempty"`

	// StatusChangeTrace (状态变更记录) — JSON array of status snapshots
	// to apply sequentially across Reports. See §7.12.
	StatusChangeTrace []GBT32960StatusChange `json:"status_change_trace,omitempty"`

	// CustomFields (自定义信息体) — raw hex string for the info-body
	// portion of 0x02/0x03 data unit. Empty = planner emits a minimal
	// valid info body (整车数据 0x01 + 18 zero bytes, or 0x05 + 9 zero
	// bytes when IsTransBatteryData=false). See §3.2.3.
	CustomFields string `json:"custom_fields,omitempty"`

	// InjectBCCError (注入 BCC 错误) — when true, the planner flips one
	// bit of the BCC byte on the Nth message (BCCErrorIndex). §7.15.
	InjectBCCError bool `json:"inject_bcc_error,omitempty"`

	// BCCErrorIndex (BCC 错误注入索引) — 0-based index into the
	// message sequence. 0 = the first GBT32960 message. Out-of-range
	// triggers V24 error (computed at Plan time).
	BCCErrorIndex int `json:"bcc_error_index,omitempty"`
}

// GBT32960Report is a single realtime or reissue report entry. The
// planner emits one 0x02 message per entry (0x03 when in
// ReissueReports). Time defaults to auto-generated sequential stamps.
type GBT32960Report struct {
	// Time (采集时间) — RFC3339 (timezone required). Empty = auto-sequence
	// (previous + 30s, or LoginTime + 30s for first).
	Time string `json:"time,omitempty"`

	// AlarmData (报警数据) — overrides Config.AlarmData for this entry.
	AlarmData *GBT32960AlarmData `json:"alarm_data,omitempty"`

	// CustomFields (自定义信息体) — overrides Config.CustomFields.
	CustomFields string `json:"custom_fields,omitempty"`
}

// GBT32960AlarmData models the info-type 0x07 alarm data info body.
// Wire layout (5 bytes): MaxAlarmLevel(1B) + GeneralAlarmFlags(4B BE).
type GBT32960AlarmData struct {
	// MaxAlarmLevel (最高报警等级) — 0=无/1=一级/2=二级/3=三级.
	MaxAlarmLevel uint8 `json:"max_alarm_level"`

	// GeneralAlarmFlags (通用报警标志) — 32-bit big-endian, exactly
	// 8 hex chars (e.g. "00000002" for bit1 电池高温). See §3.2.1.
	GeneralAlarmFlags string `json:"general_alarm_flags"`
}

// GBT32960RemoteControl models the 0x08 control command exchange.
type GBT32960RemoteControl struct {
	// ControlType (控制类型): 0x01=远程熄火, 0x02=远程解锁, etc.
	ControlType uint8 `json:"control_type"`

	// Params (命令参数) — raw hex string, appended after ControlType.
	Params string `json:"params,omitempty"`

	// ResponseFlags (应答标志) — vehicle's response: "01"=success,
	// "02"=error, "04"=unsupported. Default "01". Applied to the next
	// uplink message's resp field (see §3.12).
	ResponseFlags string `json:"response_flags,omitempty"`
}

// GBT32960PlatformLogin models the 0x05 platform-as-client login.
type GBT32960PlatformLogin struct {
	User       string `json:"user"`                  // 12-byte ASCII
	Password   string `json:"password"`              // 20-byte ASCII
	EncryptSeq string `json:"encrypt_seq,omitempty"` // 16-byte ASCII (key version)
}

// GBT32960StatusChange is one entry in StatusChangeTrace. When the
// planner processes Reports, each entry first applies the trace's next
// snapshot, then applies per-report overrides. Fields empty in the
// snapshot are left unchanged.
type GBT32960StatusChange struct {
	AtReportIndex int                `json:"at_report_index"` // 0-based; must be unique
	AlarmData     *GBT32960AlarmData `json:"alarm_data,omitempty"`
	CustomFields  string             `json:"custom_fields,omitempty"`
}

// PPPoESession is one entry of PPPoEConfig.Sessions (D-PPPOE-1 P2,
// the SIPSession/FTPSession precedent): per-session SessionID (0 =
// derived DefaultSessionID+i), optional SkipDiscovery, and per-session
// data-plane controls. Template fields (ac_name/auth/cookie...) are
// inherited from the top-level PPPoEConfig.
type PPPoESession struct {
	SessionID     uint16          `json:"session_id,omitempty"`
	SessionIDDyn  *StrategyConfig `json:"-"`
	SkipDiscovery bool            `json:"skip_discovery,omitempty"`
	DataFrames    int             `json:"data_frames,omitempty"`
	DataPayload   []byte          `json:"data_payload,omitempty"`
	InnerProto    uint8           `json:"inner_proto,omitempty"`
	DataDirection string          `json:"data_direction,omitempty"`
}

// JT808Config holds JT/T 808 terminal-platform protocol configuration
// (D-JT808-1 裁定2：配置类型迁 core——vnc/xmpp 先例 core 独占类型；
// json tags 与 protocol/jt808 原 types.go 逐字一致，protocol 包别名承接).
type JT808Config struct {
	// Phone (终端手机号) — 12-digit BCD. Must match ^\d{12}$. Required.
	Phone string `json:"phone"`

	// Version (版本标志) — "2011" | "2013" | "2019" (default). Affects
	// MsgBodyProps bits 10-12.
	Version string `json:"version,omitempty"`

	// EncryptFlag (加密标志) — 0=plain (default), 1=encrypted (placeholder;
	// trafficgen does NOT implement real encryption per design §14).
	EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

	// LicenseColor (车牌颜色) 0-5, 9. 0 means no plate; LicensePlate MUST
	// then be empty.
	LicenseColor uint8 `json:"license_color,omitempty"`

	// LicensePlate (车牌号) GBK-encoded, only when LicenseColor != 0.
	LicensePlate string `json:"license_plate,omitempty"`

	// ProvinceId / CityId (省域/市域 ID) for 0x0100 registration.
	ProvinceId uint16 `json:"province_id,omitempty"`
	CityId     uint16 `json:"city_id,omitempty"`

	// ManufacturerId (制造商ID) 5 ASCII chars, default "TEST".
	ManufacturerId string `json:"manufacturer_id,omitempty"`

	// TerminalModel (终端型号) up to 20 bytes, default "TG-DEMO".
	TerminalModel string `json:"terminal_model,omitempty"`

	// TerminalId (终端ID) 7 bytes, default "0000001".
	TerminalId string `json:"terminal_id,omitempty"`

	// TerminalType (终端类型) for 0x0107 property response, 0-2.
	TerminalType uint8 `json:"terminal_type,omitempty"`

	// InitialSN (起始流水号) for the per-flow MsgSN counter. Each subsequent
	// message increments by 1, wrapping at 65535.
	InitialSN uint16 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (平台侧起始流水号) for platformMsgSN. Default 0.
	// Per-Terminal independent counter; NOT tied to InitialSN (design §6A.2).
	PlatformInitialSN uint16 `json:"platform_initial_sn,omitempty"`

	// AuthCode (鉴权码) for 0x0102. Must be 1-16 bytes GBK after encoding.
	AuthCode string `json:"auth_code,omitempty"`

	// IMEI (终端IMEI) for 0x0102 auth body. 15 ASCII chars.
	IMEI string `json:"imei,omitempty"`

	// SoftwareVersion (软件版本号) for 0x0102. 20 bytes ASCII/GBK.
	SoftwareVersion string `json:"software_version,omitempty"`

	// RegistrationResult (注册应答结果) for 0x8100. 0=success (default),
	// 1-4=fail. When non-zero, AuthCode is omitted.
	RegistrationResult uint8 `json:"registration_result,omitempty"`

	// Procedures (业务流程) ordered list of JT808 messages to emit.
	Procedures []JT808Procedure `json:"procedures"`
}

// JT808Procedure is one step in a JT808 session (design §5A).
type JT808Procedure struct {
	// Type selects the message template (see Proc* constants).
	Type string `json:"type"`

	// ACKFlag (通用应答标志) for general_response / registration_response.
	// 0/1/2/3 only.
	ACKFlag uint8 `json:"ack_flag,omitempty"`

	// LocationData for "location_report" / "location_query_response".
	LocationData *JT808Location `json:"location_data,omitempty"`

	// ResponseSN for general_response / registration_response /
	// location_query_response. When 0, auto-bound to the matching upstream
	// SN (design §5A M-05).
	ResponseSN uint16 `json:"response_sn,omitempty"`

	// ResponseMsgId for "general_response". When 0, auto-bound.
	ResponseMsgId uint16 `json:"response_msg_id,omitempty"`

	// RegistrationResult per-procedure override for "registration_response".
	RegistrationResult *uint8 `json:"registration_result,omitempty"`

	// AuthCode per-procedure override for "registration_response" when
	// result=0.
	AuthCode string `json:"auth_code,omitempty"`

	// IMEI per-procedure override for "auth".
	IMEI *string `json:"imei,omitempty"`

	// SoftwareVersion per-procedure override for "auth".
	SoftwareVersion *string `json:"software_version,omitempty"`

	// Text (文本内容) for "text_down", GBK.
	Text string `json:"text,omitempty"`

	// TextFlag (文本标志) for "text_down", 0-3 (bit flags).
	TextFlag uint8 `json:"text_flag,omitempty"`

	// Params (参数列表) for "set_params": TLV items.
	Params []JT808Param `json:"params,omitempty"`

	// PropertyData (终端属性) for "property_response".
	PropertyData *JT808Property `json:"property_data,omitempty"`
}

// JT808Location models the 0x0200 location body (design §4A.3).
type JT808Location struct {
	AlarmFlag  uint32       `json:"alarm_flag"`
	StatusFlag uint32       `json:"status_flag"`
	Latitude   uint32       `json:"latitude"`  // 1e-6 deg
	Longitude  uint32       `json:"longitude"` // 1e-6 deg
	Altitude   uint16       `json:"altitude"`  // m
	Speed      uint16       `json:"speed"`     // 0.1 km/h
	Direction  uint16       `json:"direction"` // 0-359
	Time       string       `json:"time"`      // "YYMMDDhhmmss" (BCD-encoded by planner)
	ExtraItems []JT808Extra `json:"extra_items,omitempty"`

	// Bit-level convenience fields (扩展表 2). When non-nil, the planner
	// OR-merges them into StatusFlag before encoding (design §5A H-05).
	// StatusFlag (when set directly) takes precedence; these are OR-merged
	// on top. nil = not applied.
	ACC        *bool `json:"acc,omitempty"`         // bit0
	DoorStatus *bool `json:"door_status,omitempty"` // bit1
	OilCircuit *bool `json:"oil_circuit,omitempty"` // bit2
	RunStatus  *bool `json:"run_status,omitempty"`  // alias of ACC
}

// JT808Extra is one TLV extra item (design §4A.3).
type JT808Extra struct {
	Type   uint8  `json:"type"`
	Length uint8  `json:"length,omitempty"` // auto-computed by planner
	Value  []byte `json:"value"`
}

// JT808Param is one 0x8103 param item（JT/T 808 §7.9：参数ID DWORD；
// 隔离复审 F2 勘误——legacy uint8 线上 1 字节）.
type JT808Param struct {
	Id    uint32 `json:"id"`
	Value []byte `json:"value"`
}

// JT808Property models the 0x0107 terminal property response (design §4A.6).
type JT808Property struct {
	DeviceType      uint8  `json:"device_type"`
	ManufacturerId  string `json:"manufacturer_id"`
	TerminalModel   string `json:"terminal_model"`
	TerminalId      string `json:"terminal_id"`
	IccId           string `json:"icc_id"`
	Imei            string `json:"imei"`
	SoftwareVersion string `json:"software_version"`
	GnssModule      uint8  `json:"gnss_module"`
	CommModule      uint8  `json:"comm_module"`
	ProvinceId      uint16 `json:"province_id"`
	CityId          uint16 `json:"city_id"`
	CountyId        uint16 `json:"county_id"`
	TownId          uint16 `json:"town_id"`
	Operator        uint8  `json:"operator"`
	APN             string `json:"apn"`
	HardwareVersion string `json:"hardware_version"`
	MaxSpeed        uint16 `json:"max_speed"`
}

// JT809Config holds JT/T 809-2019 platform-to-platform protocol
// configuration (D-JT809-1 裁定4：类型迁 core + 16 型链路管理族重排；
// 容器族 0x1200-0x1600/0x9200-0x9600 B′ 不编排。json tags 即用例层键).
type JT809Config struct {
	// GNSSCenterId (下级平台接入码) — header 字段，0..999999999。
	GNSSCenterId uint32 `json:"gnss_center_id"`

	// UserId (用户名) — 0x1001/0x1003/0x9003 体字段。0 时缺省=GNSSCenterId。
	UserId uint32 `json:"user_id,omitempty"`

	// Password (密码) — pad 8 字节（0x00 右补）。缺省 "00000000"。
	Password string `json:"password,omitempty"`

	// VersionFlag (协议版本) — 0=2011, 1=2013, 2=2019（2019 头 30B 带 Time
	// 且 0x1001 体含 GNSSCenterId；0/1 头 22B）。缺省 0（22B 形，隔离复审
	// M4：原注释"缺省 2"与链路实际缺省不符——链路 getInt 缺键得 0；要
	// 2019 形必须显式 version_flag=2，T-2/T-3 即显式例）。
	VersionFlag uint8 `json:"version_flag,omitempty"`

	// VersionBytes (版本号字面 3 字节) — 6 个 hex 字符如 "010000"。
	// 缺省 "010000"（金向量钉死的库缺省，各版本同形，可配）。
	VersionBytes string `json:"version_bytes,omitempty"`

	// EncryptFlag (报文加密标识) — 0=明文（缺省），1=加密占位。
	EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

	// EncryptKey (加密密钥) — 缺省 0。
	EncryptKey uint32 `json:"encrypt_key,omitempty"`

	// TimeSec (2019 头 Time) — UTC 秒直发（8B 大端）。0=生成时刻
	// Unix 秒。仅 VersionFlag=2 上线。
	TimeSec uint64 `json:"time_sec,omitempty"`

	// DownLinkIP (0x1001 下级平台从链路服务端 IP) — pad 32 字节。
	// 缺省=spec.SrcIP（从链 SYN 目标一致面）。
	DownLinkIP string `json:"down_link_ip,omitempty"`

	// DownLinkPort (0x1001 从链路端口) — 缺省 8813。
	DownLinkPort uint16 `json:"down_link_port,omitempty"`

	// InitialSN (下级侧起始流水号) — 主链 上行 与 从链 上行（上级→下级）
	// 计数器起点。
	InitialSN uint32 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (上级侧起始流水号) — 主链 下行 与 从链 下行
	// （下级→上级）计数器起点。缺省 0。
	PlatformInitialSN uint32 `json:"platform_initial_sn,omitempty"`

	// Procedures (主链路 0x1xxx 流程)，顺序发射。
	Procedures []JT809Procedure `json:"procedures"`

	// SlaveProcedures (从链路 0x9xxx 流程) — 非空即开从链 TCP（上→下
	// 8813），取代旧 slave_link_enabled 键（裁定4）。
	SlaveProcedures []JT809Procedure `json:"slave_procedures,omitempty"`
}

// JT809Procedure is one step in a JT809 session（16 型链路管理族，D-JT809-1
// 裁定3）。
type JT809Procedure struct {
	// Type selects the message template (main_login…slave_close 16 型).
	Type string `json:"type"`

	// VerifyCode (验证码) for main_login_resp(0x1002)/slave_connect(0x9001)。
	VerifyCode uint32 `json:"verify_code,omitempty"`

	// Result (结果) for main_login_resp(0x1002)/slave_connect_resp(0x9002)。
	// 0=成功，1-4 负路径。
	Result uint8 `json:"result,omitempty"`

	// Password per-procedure override for main_logout(0x1003)/
	// slave_logout(0x9003)。空=cfg.Password。
	Password string `json:"password,omitempty"`

	// DownLinkIP / DownLinkPort per-procedure override for main_login。
	DownLinkIP   string `json:"down_link_ip,omitempty"`
	DownLinkPort uint16 `json:"down_link_port,omitempty"`

	// ErrorCode (错误码) for main_disconnect(0x1007)/slave_disconnect
	// (0x9007)。0-2。
	ErrorCode uint8 `json:"error_code,omitempty"`

	// ReasonCode (关闭原因) for main_close(0x1008)/slave_close(0x9008)。
	// 0-2。
	ReasonCode uint8 `json:"reason_code,omitempty"`
}

// JTT905Position models the JT/T 905-2014 0x0200 位置基本信息（25B 基础位，
// D-JTT905-1 裁定3；方向 1B 由金向量算术钉死；附加列表 B′ 不编排）。
type JTT905Position struct {
	// AlarmFlag (报警标志) 4B。
	AlarmFlag uint32 `json:"alarm_flag"`
	// StatusFlag (状态位标志) 4B。
	StatusFlag uint32 `json:"status_flag"`
	// Lat (纬度) 4B，1e-6 度。
	Lat uint32 `json:"lat"`
	// Lng (经度) 4B，1e-6 度。
	Lng uint32 `json:"lng"`
	// Speed (速度) 2B，km/h。
	Speed uint16 `json:"speed"`
	// Direction (方向) 1B，0-359 取 1B 下位。
	Direction uint8 `json:"direction"`
	// Time (时间) "yyMMddHHmmss" 12 位→BCD6。
	Time string `json:"time"`
}

// JTT905Config holds JT/T 905-2014 taxi ISU protocol configuration
// (D-JTT905-1 裁定4：类型迁 core+体重建；legacy 虚构面 phone/driver_id/
// driver_name/license_color/version/encrypt_flag 等全废弃。json tags 即
// 用例层键). 线面=808 族 7E 信封（jtcommon 复用），头 12B，DataLength=
// 纯体长（裁定1）。
type JTT905Config struct {
	// ISUId (ISU 标识) 12 位数字→BCD6。必填。
	ISUId string `json:"isu_id"`

	// InitialSN (ISU 侧起始流水号) MsgNum 计数器起点。
	InitialSN uint16 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (中心侧起始流水号) 下行 MsgNum 起点。缺省 0。
	PlatformInitialSN uint16 `json:"platform_initial_sn,omitempty"`

	// BusinessLicense (企业经营许可证号) ASCII，\0 右补 16B。
	BusinessLicense string `json:"business_license,omitempty"`

	// QualificationCode (驾驶员从业资格证号) ASCII，\0 右补 19B。
	QualificationCode string `json:"qualification_code,omitempty"`

	// PlateNo (车牌号) ASCII，\0 右补 6B。
	PlateNo string `json:"plate_no,omitempty"`

	// Position (位置基本信息) 可选——非 nil 时 0x0B03/0x0B04 体首携带 25B。
	Position *JTT905Position `json:"position,omitempty"`

	// TaximeterKValue (计价器 K 值) 4 位数字→BCD2（0x0B04）。空="0000"。
	TaximeterKValue string `json:"taximeter_k_value,omitempty"`

	// OnDutyPowerOnTime (当班开机时间) "yyyyMMddHHmm" 12 位→BCD6。空=全 0。
	OnDutyPowerOnTime string `json:"on_duty_power_on_time,omitempty"`

	// OnDutyPowerOffTime (当班关机时间) 同上。
	OnDutyPowerOffTime string `json:"on_duty_power_off_time,omitempty"`

	// OnDutyMileage (当班里程) 6 位数字→BCD3。空="000000"。
	OnDutyMileage string `json:"on_duty_mileage,omitempty"`

	// OnDutyOperationMileage (当班运营里程) 6 位数字→BCD3。空=全 0。
	OnDutyOperationMileage string `json:"on_duty_operation_mileage,omitempty"`

	// TrainNumber (车次) 4 位数字→BCD2。空="0000"。
	TrainNumber string `json:"train_number,omitempty"`

	// TimingTime (计时时间) 6 位数字→BCD3。空=全 0。
	TimingTime string `json:"timing_time,omitempty"`

	// TotalAmount (总计金额) 6 位数字→BCD3。空=全 0。
	TotalAmount string `json:"total_amount,omitempty"`

	// CardAmount (卡收金额) 6 位数字→BCD3。空=全 0。
	CardAmount string `json:"card_amount,omitempty"`

	// CardCount (卡次) 4 位数字→BCD2。空="0000"。
	CardCount string `json:"card_count,omitempty"`

	// OnDutyMileageBetween (班间里程) 4 位数字→BCD2。空="0000"。
	OnDutyMileageBetween string `json:"on_duty_mileage_between,omitempty"`

	// TotalMileage (总计里程) 8 位数字→BCD4。空=全 0。
	TotalMileage string `json:"total_mileage,omitempty"`

	// TotalOperationMileage (总运营里程) 8 位数字→BCD4。空=全 0。
	TotalOperationMileage string `json:"total_operation_mileage,omitempty"`

	// UnitPrice (单价) 4 位数字→BCD2。空="0000"。
	UnitPrice string `json:"unit_price,omitempty"`

	// TotalOperations (总运营次数) u32。
	TotalOperations uint32 `json:"total_operations,omitempty"`

	// SignType (签退方式) 1B。
	SignType uint8 `json:"sign_type,omitempty"`

	// Procedures (业务流程) 显式序列。空=自动生成：签到→应答→(心跳→应答)×N
	// →签退→应答（HeartbeatCount 缺省 1）。
	Procedures []JTT905Procedure `json:"procedures"`

	// HeartbeatCount (心跳次数) 自动会话面。缺省 1。
	HeartbeatCount int `json:"heartbeat_count,omitempty"`
}

// JTT905Procedure is one step in a JTT905 session（D-JTT905-1 裁定2 5 型）。
type JTT905Procedure struct {
	// Type: check_in(0x0B03)/heartbeat(0x0002)/check_out(0x0B04)/
	// isu_general_response(0x0001)/center_general_response(0x8001)。
	Type string `json:"type"`

	// Result (结果) 应答族 0-2（成功/失败/消息有误——真枚举，legacy 0-3 废弃）。
	Result uint8 `json:"result,omitempty"`

	// ReplySN (应答流水号) 应答族绑定；0=自动绑最近上行 SN。
	ReplySN uint16 `json:"reply_sn,omitempty"`

	// ReplyMsgId (应答消息 ID) 0=自动绑最近上行 MsgId。
	ReplyMsgId uint16 `json:"reply_msg_id,omitempty"`
}
