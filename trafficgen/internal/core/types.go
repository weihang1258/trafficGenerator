// Package core provides core data structures for the traffic generator.
package core

import (
	"context"
	"time"
)

// Task represents a traffic generation task.
type Task struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Protocol    string                 `json:"protocol"` // tcp, udp, http, dns, icmp, arp
	Spec        FlowSpec               `json:"spec"`     // single-protocol mode
	Batch       *BatchSpec             `json:"batch,omitempty"` // mixed-traffic mode (Spec XOR Batch)
	ClassID     string                 `json:"class_id"`
	Interface   string                 `json:"interface"`  // output interface name
	OutputMode  string                 `json:"output_mode"` // interface, pcap, both
	PcapFile    string                 `json:"pcap_file,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Ctx         context.Context        `json:"-"` // per-task context for cancellation
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
	TCP  *TCPConfig  `json:"tcp,omitempty"`
	UDP  *UDPConfig  `json:"udp,omitempty"`
	HTTP *HTTPConfig `json:"http,omitempty"`
	DNS  *DNSConfig  `json:"dns,omitempty"`
	ICMP *ICMPConfig `json:"icmp,omitempty"`
	ARP  *ARPConfig  `json:"arp,omitempty"`

	// Common configuration
	Payload  []byte `json:"payload,omitempty"`
	Count    int    `json:"count,omitempty"`
	Duration int    `json:"duration,omitempty"` // seconds
	BPS      string `json:"bps,omitempty"`     // rate limit, e.g., "200k", "1M"
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
type HTTPConfig struct {
	Method       string            `json:"method"`
	URI          string            `json:"uri"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	KeepAlive    bool              `json:"keep_alive"`
	Transactions int               `json:"transactions"`
	ThinkTime    int               `json:"think_time"` // milliseconds
}

// DNSConfig for DNS protocol.
type DNSConfig struct {
	Domain     string `json:"domain"`
	QueryType  uint16 `json:"query_type"` // A=1, AAAA=28
	Response   bool   `json:"response"`
	ResponseIP string `json:"response_ip,omitempty"`
}

// ICMPConfig for ICMP protocol.
type ICMPConfig struct {
	Type     uint8  `json:"type"` // 8=Echo Request, 0=Echo Reply
	Code     uint8  `json:"code"`
	Sequence uint16 `json:"sequence"`
	Data     []byte `json:"data"`
}

// ARPConfig for ARP protocol.
type ARPConfig struct {
	Operation uint16 `json:"operation"` // 1=Request, 2=Reply
	TargetMAC string `json:"target_mac"`
	TargetIP  string `json:"target_ip"`
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
	Strategy string        `json:"strategy"` // fixed, inc, random, pattern, list
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
