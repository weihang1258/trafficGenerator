package core

// Routing protocol configuration types (P3 T5: igmp/ospf/pim/isis).
// Field names mirror the case-JSON contract in test/protocol_pcap/cases/*.json
// (which is the byte-arbitration authority against tshark 3.6.14).

// ---- IGMP (IP proto 2) ----

// IGMPConfig configures one IGMP message (RFC 1112 v1 / RFC 2236 v2 /
// RFC 3376 v3). A single flow emits one query/report/leave, or an event
// sequence when Events is set (top-level `events` in the case JSON).
type IGMPConfig struct {
	Profile         string          `json:"profile,omitempty"`          // v1|v2|v3
	Kind            string          `json:"kind,omitempty"`             // query|report|leave
	Group           string          `json:"group,omitempty"`            // group address
	MaxResponseTime int             `json:"max_response_time,omitempty"`// v2 max resp (deciseconds) or v3 MRC
	MaxResponseCode int             `json:"max_response_code,omitempty"`// v3 raw MRC byte
	SFlag           int             `json:"s_flag,omitempty"`           // v3 S bit (suppress router-side)
	QRV             int             `json:"qrv,omitempty"`              // v3 QRV (robustness var)
	QQIC            int             `json:"qqic,omitempty"`             // v3 QQIC
	Records         []IGMPRecord    `json:"records,omitempty"`          // v3 group records
	Sources         []string        `json:"sources,omitempty"`          // v3 source list (record or top-level)
	SourceCount     int             `json:"source_count,omitempty"`     // v3 explicit source count (wire_fault test)
	ChecksumMode    string          `json:"checksum_mode,omitempty"`    // ""|invalid|zero
	WireFault       *IGMPWireFault  `json:"wire_fault,omitempty"`       // fault injection
	AddressFamily   string          `json:"address_family,omitempty"`   // ipv4|ipv6 (ipv6 rejected)
	Events          []IGMPEvent     `json:"events,omitempty"`           // multi-message sequence
}

// IGMPEvent is one message in an IGMP event sequence (v1/v2/v3
// query/report/leave). `state`/`session`/`retransmit` select the message
// variant; each event is emitted as one full packet.
type IGMPEvent struct {
	Profile         string       `json:"profile,omitempty"`
	Kind            string       `json:"kind,omitempty"`
	Group           string       `json:"group,omitempty"`
	State           string       `json:"state,omitempty"`     // querying|member|leaving
	Session         string       `json:"session,omitempty"`   // multi-group grouping
	Retransmit      bool         `json:"retransmit,omitempty"`// retransmitted report
	Records         []IGMPRecord `json:"records,omitempty"`   // v3 group records
	Sources         []string     `json:"sources,omitempty"`
	MaxResponseTime int          `json:"max_response_time,omitempty"`
	MaxResponseCode int          `json:"max_response_code,omitempty"`
	SFlag           int          `json:"s_flag,omitempty"`
	QRV             int          `json:"qrv,omitempty"`
	QQIC            int          `json:"qqic,omitempty"`
	ChecksumMode    string       `json:"checksum_mode,omitempty"`
}

// IGMPRecord is a v3 Group Record (mode-change/allow/block).
type IGMPRecord struct {
	RecordType int      `json:"record_type,omitempty"` // 1=include,2=exclude,3=change_include,4=change_exclude,5=allow_new,6=block_old
	Group      string   `json:"group,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// IGMPWireFault injects a wire fault for negative tests.
type IGMPWireFault struct {
	Kind  string `json:"kind,omitempty"`  // protocol|checksum|record|source_count|group
	Value int    `json:"value,omitempty"` // e.g. protocol=17 (wrong IP proto)
}

// ---- OSPF (IP proto 89) ----

// OSPFConfig configures one OSPFv2 message (RFC 2328) or an event sequence.
type OSPFConfig struct {
	Version                 int             `json:"version,omitempty"`         // 2
	PacketType              string          `json:"packet_type,omitempty"`     // hello|db_description|link_state_request|link_state_update|link_state_acknowledgment
	RouterID                string          `json:"router_id,omitempty"`       // 1.1.1.1
	AreaID                  string          `json:"area_id,omitempty"`         // 0.0.0.0
	Profile                 string          `json:"profile,omitempty"`         // rfc2328_ipv4
	AuthType                int             `json:"auth_type,omitempty"`       // 0=none
	ChecksumMode            string          `json:"checksum_mode,omitempty"`   // ""|auto|invalid|zero
	NetworkMask             string          `json:"network_mask,omitempty"`    // hello
	HelloInterval           int             `json:"hello_interval,omitempty"`
	DeadInterval            int             `json:"dead_interval,omitempty"`
	Options                 int             `json:"options,omitempty"`
	Priority                int             `json:"priority,omitempty"`
	DesignatedRouter        string          `json:"designated_router,omitempty"`
	BackupDesignatedRouter  string          `json:"backup_designated_router,omitempty"`
	Neighbors               []string        `json:"neighbors,omitempty"`
	InterfaceMTU            int             `json:"interface_mtu,omitempty"`   // DD
	Flags                   *OSPFDDFlags    `json:"flags,omitempty"`           // DD
	DDSequence              int             `json:"dd_sequence,omitempty"`     // DD
	LSAHeaders              []OSPFLSAHeader `json:"lsa_headers,omitempty"`     // DD/ACK
	Requests                []OSPFRequest   `json:"requests,omitempty"`        // LSR
	LSAs                    []OSPFLSA       `json:"lsas,omitempty"`            // LSU
	Events                  []OSPFEvent     `json:"events,omitempty"`          // state machine
	WireFault               *OSPFWireFault  `json:"wire_fault,omitempty"`
}

// OSPFDDFlags are the Database Description flags.
type OSPFDDFlags struct {
	Init   bool `json:"init,omitempty"`
	More   bool `json:"more,omitempty"`
	Master bool `json:"master,omitempty"`
}

// OSPFLSAHeader is a Link State Advertisement header (for DD/LSR/ACK).
type OSPFLSAHeader struct {
	Age              int    `json:"age,omitempty"`
	Options          int    `json:"options,omitempty"`
	LSAType          int    `json:"lsa_type,omitempty"`
	LinkStateID      string `json:"link_state_id,omitempty"`
	AdvertisingRouter string `json:"advertising_router,omitempty"`
	Sequence         string `json:"sequence,omitempty"`       // "0x80000001"
	ChecksumMode     string `json:"checksum_mode,omitempty"`
	Length           int    `json:"length,omitempty"`
}

// OSPFLink is one LSA link.
type OSPFLink struct {
	LinkID   string `json:"link_id,omitempty"`
	LinkData string `json:"link_data,omitempty"`
	LinkType int    `json:"link_type,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

// OSPFLSA is a full Link State Advertisement in a Link State Update.
type OSPFLSA struct {
	Age              int        `json:"age,omitempty"`
	Options          int        `json:"options,omitempty"`
	LSAType          int        `json:"lsa_type,omitempty"`
	LinkStateID      string     `json:"link_state_id,omitempty"`
	AdvertisingRouter string    `json:"advertising_router,omitempty"`
	Sequence         string     `json:"sequence,omitempty"`
	ChecksumMode     string     `json:"checksum_mode,omitempty"`
	Length           int        `json:"length,omitempty"`
	Flags            int        `json:"flags,omitempty"`
	Links            []OSPFLink `json:"links,omitempty"`
}

// OSPFRequest is a Link State Request entry.
type OSPFRequest struct {
	LSAType          int    `json:"lsa_type,omitempty"`
	LinkStateID      string `json:"link_state_id,omitempty"`
	AdvertisingRouter string `json:"advertising_router,omitempty"`
}

// OSPFEvent is one step in the adjacency state machine.
type OSPFEvent struct {
	Kind                    string `json:"kind,omitempty"` // hello|db_description|link_state_request|link_state_update|link_state_acknowledgment
	Direction               string `json:"direction,omitempty"`
	NeighborState           string `json:"neighbor_state,omitempty"`
	RouterID                string `json:"router_id,omitempty"`
	AreaID                  string `json:"area_id,omitempty"`
	NetworkMask             string `json:"network_mask,omitempty"`
	HelloInterval           int    `json:"hello_interval,omitempty"`
	DeadInterval            int    `json:"dead_interval,omitempty"`
	Priority                int    `json:"priority,omitempty"`
	Options                 int    `json:"options,omitempty"`
	DesignatedRouter        string `json:"designated_router,omitempty"`
	BackupDesignatedRouter  string `json:"backup_designated_router,omitempty"`
	Neighbors               []string `json:"neighbors,omitempty"`
	DDSequence              int      `json:"dd_sequence,omitempty"`
	InterfaceMTU            int      `json:"interface_mtu,omitempty"`
	Flags                   *OSPFDDFlags `json:"flags,omitempty"`
	LSAHeaders              []OSPFLSAHeader `json:"lsa_headers,omitempty"`
	Requests                []OSPFRequest `json:"requests,omitempty"`
	LSAs                    []OSPFLSA `json:"lsas,omitempty"`
}

// OSPFWireFault injects a wire fault.
type OSPFWireFault struct {
	Kind  string `json:"kind,omitempty"`  // declared_length|auth|checksum|packet_length
	Value string `json:"value,omitempty"` // e.g. smaller_than_header
}

// ---- PIM (IP proto 103) ----

// PIMConfig configures one PIM-SM message (RFC 7761) or an event sequence.
type PIMConfig struct {
	Profile      string      `json:"profile,omitempty"`       // pim_sm_rfc7761_ipv4
	ChecksumMode string      `json:"checksum_mode,omitempty"` // ""|auto|invalid|zero
	Events       []PIMEvent  `json:"events,omitempty"`
	WireFault    *PIMWireFault `json:"wire_fault,omitempty"`
}

// PIMEvent is one PIM message.
type PIMEvent struct {
	Kind              string   `json:"kind,omitempty"` // hello|join_prune|bootstrap|candidate_rp_adv|register|register_stop|assert|df_election
	Direction         string   `json:"direction,omitempty"`
	Holdtime          int      `json:"holdtime,omitempty"`
	HelloInterval     int      `json:"hello_interval,omitempty"`
	GenerationID      string   `json:"generation_id,omitempty"` // "0x01020304"
	DRPriority        int      `json:"dr_priority,omitempty"`
	UpstreamNeighbor  string   `json:"upstream_neighbor,omitempty"`
	Groups            []PIMGroup `json:"groups,omitempty"`
	State             string   `json:"state,omitempty"` // no_info|join|prune
	BSR               string   `json:"bsr,omitempty"`
	BSRPriority       int      `json:"bsr_priority,omitempty"`
	HashMaskLength    int      `json:"hash_mask_length,omitempty"`
	RPSets            []PIMGroup `json:"rp_sets,omitempty"`
	RP                string   `json:"rp,omitempty"`
	RPPriority        int      `json:"rp_priority,omitempty"`
	GroupPrefixes     []PIMGroup `json:"group_prefixes,omitempty"`
	RegisterFlags     int      `json:"register_flags,omitempty"`
	InnerIPv4         string   `json:"inner_ipv4,omitempty"` // encapsulated packet
	Group             string   `json:"group,omitempty"`
	Source            string   `json:"source,omitempty"`
	RptBit            bool     `json:"rpt_bit,omitempty"`
	MetricPreference  int      `json:"metric_preference,omitempty"`
	RouteMetric       int      `json:"route_metric,omitempty"`
	Neighbor          string   `json:"neighbor,omitempty"` // df_election
}

// PIMGroup is a group/source set in join/prune/bootstrap/RP-set.
type PIMGroup struct {
	Group  string `json:"group,omitempty"`
	Source string `json:"source,omitempty"`
}

// PIMWireFault injects a wire fault.
type PIMWireFault struct {
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value,omitempty"`
}

// ---- ISIS (L2-only, LLC) ----

// ISISConfig configures one IS-IS PDU (ISO 10589) over LLC.
type ISISConfig struct {
	WireProfile       string       `json:"wire_profile,omitempty"` // iso10589_llc
	Level             string       `json:"level,omitempty"`        // l1|l2
	PDUType           string       `json:"pdu_type,omitempty"`     // lan_hello|p2p_hello|lsp|psnp|csnp
	SystemID          string       `json:"system_id,omitempty"`    // 0102.0304.0506
	HoldingTimer      int          `json:"holding_timer,omitempty"`
	Priority          int          `json:"priority,omitempty"`
	LANID             string       `json:"lan_id,omitempty"`       // 01020304050601
	TLVs              []ISISTLV    `json:"tlvs,omitempty"`
	LSPID             string       `json:"lsp_id,omitempty"`       // 0102030405060000
	RemainingLifetime int          `json:"remaining_lifetime,omitempty"`
	Sequence          int          `json:"sequence,omitempty"`
	Partition         int          `json:"partition,omitempty"`
	CircuitType       int          `json:"circuit_type,omitempty"`
	ChecksumMode      string       `json:"checksum_mode,omitempty"`
	AddressProfile    string       `json:"address_profile,omitempty"` // ipv4_basic|ipv6_basic
	AreaAddresses     []string     `json:"area_addresses,omitempty"`
	StartLSPID        string       `json:"start_lsp_id,omitempty"`
	EndLSPID          string       `json:"end_lsp_id,omitempty"`
	Events            []ISISEvent  `json:"events,omitempty"`
	Checksum          int          `json:"checksum,omitempty"`
	LLC               *ISISLLCConfig `json:"llc,omitempty"`
	WireFault         *ISISWireFault `json:"wire_fault,omitempty"`
}

// ISISTLV is one Type-Length-Value.
type ISISTLV struct {
	Type     int    `json:"type,omitempty"`     // 1=Area Addresses, 129=Protocols Supported, 132=IP Int. Reach, 9=...
	ValueHex string `json:"value_hex,omitempty"` // "03 49 00 01"
}

// ISISLLCConfig overrides LLC header fields (SNAP).
type ISISLLCConfig struct {
	DSAP    int `json:"dsap,omitempty"`    // 254
	SSAP    int `json:"ssap,omitempty"`    // 254
	Control int `json:"control,omitempty"` // 3
}

// ISISEvent is one PDU in a state-machine sequence.
type ISISEvent struct {
	Kind              string      `json:"kind,omitempty"` // iih|lsp|psnp|csnp
	PDUType           string      `json:"pdu_type,omitempty"`
	Level             string      `json:"level,omitempty"`
	SystemID          string      `json:"system_id,omitempty"`
	NeighborState     string      `json:"neighbor_state,omitempty"`
	HoldingTimer      int         `json:"holding_timer,omitempty"`
	Priority          int         `json:"priority,omitempty"`
	LANID             string      `json:"lan_id,omitempty"`
	TLVs              []ISISTLV   `json:"tlvs,omitempty"`
	LSPID             string      `json:"lsp_id,omitempty"`
	RemainingLifetime int         `json:"remaining_lifetime,omitempty"`
	Sequence          int         `json:"sequence,omitempty"`
	Partition         int         `json:"partition,omitempty"`
	CircuitType       int         `json:"circuit_type,omitempty"`
	ChecksumMode      string      `json:"checksum_mode,omitempty"`
}

// ISISWireFault injects a wire fault.
type ISISWireFault struct {
	Kind  string `json:"kind,omitempty"` // mixed_carrier|checksum|declared_length
	Value string `json:"value,omitempty"`
}
