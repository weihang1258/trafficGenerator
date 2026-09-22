package core

// HL7 v2 MLLP configuration types, aligned with the design doc
// docs/protocol-designs/68-hl7-{design,testcase}.md.

// HL7Config is the flow's hl7 terminal-layer configuration.
type HL7Config struct {
	// Profile selects the protocol profile: "mllp" (default, TCP port 2575).
	// Boundary profiles (file/pipe) are rejected.
	Profile string `json:"profile,omitempty"`
	// Version sets the HL7 version: "2.5" (default), "2.3", "2.4", "2.8".
	Version string `json:"version,omitempty"`
	// FieldSeparator overrides the field delimiter (default "|").
	FieldSeparator string `json:"field_separator,omitempty"`
	// EncodingChars overrides the encoding characters (default "^~\\&").
	EncodingChars string `json:"encoding_chars,omitempty"`
	// AckMode controls ACK generation: "auto" (default, sends AA ACK after each
	// message), "null" (no response), or an explicit ack code string
	// ("AA"/"AE"/"AR").
	AckMode string `json:"ack_mode,omitempty"`
	// Concurrent enables interleaved multi-session replay: session events are
	// emitted round-robin (per event index) instead of session-by-session.
	Concurrent bool `json:"concurrent,omitempty"`
	// Sessions is the ordered list of HL7 sessions (one session = one TCP
	// connection).
	Sessions []HL7Session `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (33 kinds, design §6.3 /
	// testcase §4): mllp_sob_missing|mllp_eob_missing|mllp_eob_malformed|
	// mllp_control_byte|segment_not_msh|segment_no_cr|segment_after_eob|
	// segment_name_invalid|msh1_invalid|msh2_invalid|separator_mismatch|
	// escape_invalid|msh9_missing|msh10_missing|msh11_missing|msh12_missing|
	// msh9_domain|ack_msa2_mismatch|ack_no_msh9|ack_no_msa|ack_code_invalid|
	// carrier_udp|carrier_tcp_missing|port_invalid|len_msh9|len_msh10|
	// len_msh12|len_msh7|len_msa2|event_mismatch|address_family_mixed|
	// required_segment_missing|z_segment_unconfigured.
	WireFault string `json:"wire_fault,omitempty"`
}

// HL7Session is one TCP connection carrying HL7 messages.
type HL7Session struct {
	// SrcPort overrides the client source port for this session (0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the destination port (0 = flow default 2575).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Role sets the initiator role: "sender" (default, sends first message) or
	// "receiver" (listens first — not implemented in layer-gen, reserved for
	// server-side mode).
	Role string `json:"role,omitempty"`
	// AckMode controls ACK generation for all events of this session:
	// "auto" (default), "null", or an ack code ("AA"/"AE"/"AR"). Per-event
	// Ack overrides; config-level AckMode is the fallback (设计 §6 ack 键：
	// 消息级覆盖会话级)。
	AckMode string `json:"ack_mode,omitempty"`
	// SendingApp is the MSH-3 value (sending application name).
	SendingApp string `json:"sending_app,omitempty"`
	// SendingFac is the MSH-4 value (sending facility).
	SendingFac string `json:"sending_fac,omitempty"`
	// ReceivingApp is the MSH-5 value.
	ReceivingApp string `json:"receiving_app,omitempty"`
	// ReceivingFac is the MSH-6 value.
	ReceivingFac string `json:"receiving_fac,omitempty"`
	// ProcessingID is the MSH-11 value: "P" (default, production), "D" (debug),
	// "T" (training).
	ProcessingID string `json:"processing_id,omitempty"`
	// AllowZSegments enables pass-through of Z-segments (custom extensions).
	// Default false — undeclared Z segments are rejected (design §1 v2.1).
	AllowZSegments bool `json:"allow_z_segments,omitempty"`
	// Events is the ordered list of messages on this session.
	Events []HL7Event `json:"events,omitempty"`
}
type HL7Event struct {
	// Kind is "msg" (the only legal kind).
	Kind string `json:"kind,omitempty"`
	// Direction is "c2s" (default, client→server) or "s2c" (server→client).
	Direction string `json:"direction,omitempty"`
	// MessageType sets MSH-9 and EVN-1 (e.g. "ADT^A01^ADT_A01",
	// "ORU^R01^ORU_R01", "ACK^A01^ACK").
	MessageType string `json:"message_type,omitempty"`
	// Segments is the ordered list of HL7 segments after MSH.
	Segments []HL7Segment `json:"segments,omitempty"`
	// Ack controls ACK generation for this event: "auto" (default, inherits
	// from session/config AckMode), "null" (no ACK), or an explicit ack code
	// string ("AA"/"AE"/"AR").
	Ack string `json:"ack,omitempty"`
	// AllowZSegments enables pass-through of Z-segments for this event
	// only (overrides session default).
	AllowZSegments bool `json:"allow_z_segments,omitempty"`
	// WireFault injects a per-event wire fault.
	WireFault string `json:"wire_fault,omitempty"`
	// Version overrides MSH-12 for this event (raw string, ≤60 chars —
	// boundary cases use long version strings; config-level Version keeps its
	// 2.3/2.4/2.5/2.8 domain).
	Version string `json:"version,omitempty"`
	// ProcessingID overrides MSH-11 for this event ("P"/"T"/"D").
	ProcessingID string `json:"processing_id,omitempty"`
	// MSH8Security populates MSH-8 (security, default empty).
	MSH8Security string `json:"msh8_security,omitempty"`
	// FieldSeparator overrides the field delimiter for this event's message.
	FieldSeparator string `json:"field_separator,omitempty"`
	// EncodingChars overrides the encoding characters for this event's message.
	EncodingChars string `json:"encoding_chars,omitempty"`
	// ControlID pins MSH-10 for this event (empty = auto MSG%04d increment;
	// the inc strategy case uses explicit 1000/1001/1002 values).
	ControlID string `json:"control_id,omitempty"`
	// Timestamp pins MSH-7 for this event (empty = runtime UTC 14-char; the
	// boundary case pins the 24-char textual max form).
	Timestamp string `json:"timestamp,omitempty"`
	// MSA3Text populates MSA-3 (optional text message) of the derived ACK.
	MSA3Text string `json:"msa3_text,omitempty"`
	// ErrSegments are appended after MSA in the derived ACK frame (NAK
	// error-detail segments; each is rendered like a normal segment).
	ErrSegments []HL7Segment `json:"err_segments,omitempty"`
}

// HL7Segment is one HL7 segment (e.g. MSH, PID, PV1, OBR, OBX).
type HL7Segment struct {
	// Name is the segment identifier (3 uppercase letters, e.g. "MSH", "PID").
	Name string `json:"name,omitempty"`
	// Fields is the ordered list of field values. Each value may be:
	//   - string: plain field value
	//   - []interface{}: repetition of field values
	//   - []string: repetition (simpler form)
	// Nested components/subcomponents are encoded as "^"-delimited strings.
	Fields []interface{} `json:"fields,omitempty"`
}
