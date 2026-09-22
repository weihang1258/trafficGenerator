package core

// Megaco/H.248 v1 text encoding configuration types, aligned with the design
// doc docs/protocol-designs/70-megaco-design.md (v1.2.0).
//
// Three entry aliases (megaco / h248 / mgcp) share one planner. The cases
// JSON keeps proto="megaco"; the aliases only differ in default port
// (mgcp→2427, others→2944) and are normalized at the planner/builder.

// MegacoConfig is the flow's megaco terminal-layer configuration.
type MegacoConfig struct {
	// Profile selects the megaco protocol profile: "megaco_v1_text" (default
	// for megaco/h248 entry, text encoding, UDP/TCP 2944), "mgcp_alias"
	// (alias entry mgcp, text encoding, UDP 2427), "megaco_v1_ber" (boundary
	// profile for binary encoding, 2945 — payloads still text).
	Profile string `json:"profile,omitempty"`
	// Encoding declares the wire encoding: "text" (default, this version
	// emits text only — ber is a boundary declaration, not a payload).
	Encoding string `json:"encoding,omitempty"`
	// Version is the start-line version (1*2 DIGIT, default 1). 2-digit
	// forms are boundary carve-out (case 40); 0 and 3-digit are rejected.
	Version int `json:"version,omitempty"`
	// TokenForm picks the wire token form: "long" (default — MEGACO/1,
	// Transaction, Context, Add) or "abbrev" (!/1, T, C, MF, AV, ...).
	TokenForm string `json:"token_form,omitempty"`
	// Whitespace selects the LWSP/EOL rendering variant (RFC 3525 Annex B.2
	// SEP/LWSP/COMMENT; testcase #23): "" single-space SEP (default),
	// "cr" CR-only EOL, "comment" standalone "; ..." comment line after the
	// start line, "lwsp" multi-space padding around the start-line SEP.
	Whitespace string `json:"whitespace,omitempty"`
	// Sessions is the ordered list of megaco sessions (one session = one
	// control association = one UDP/TCP connection).
	Sessions []MegacoSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (31 kinds, design §7 /
	// testcase §4): encoding_text_as_ber|encoding_port_mismatch|
	// syntax_start_line|syntax_version_zero|syntax_version_three_digits|
	// syntax_mid_missing|syntax_mid_invalid|syntax_body_form|
	// syntax_services_missing_params|command_pre_registration|
	// command_modify_nonexistent|command_reply_choose_all|
	// command_uncreated_context|command_first_error_continues|
	// pairing_reply_id_mismatch|pairing_pending_id_mismatch|
	// pairing_duplicate_transid|pairing_ack_unconfirmed|
	// pairing_ia_without_pending|pairing_observed_requestid|
	// length_message_truncated|length_termid_over_64|
	// length_transid_over_uint32|length_digitmap_timer|
	// length_context_reserved|carrier_layer_mismatch|
	// carrier_entry_port_encoding|carrier_invalid_port|
	// carrier_return_address|carrier_udp_mtu_exceeded|
	// services_address_mgcidtotry_conflict.
	WireFault string `json:"wire_fault,omitempty"`
}

// MegacoSession is one Megaco control association carrying message exchanges.
type MegacoSession struct {
	// SrcPort overrides the client source port for this session (0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the destination port for this session (0 = flow default
	// 2944 for text megaco/h248, 2427 for mgcp alias).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Transport sets the carrier: "udp" (default, Annex D.1) or "tcp" (Annex D.2,
	// RFC 1006 TPKT framing). When empty the session-level default (from Config)
	// or the chain-translated transport is used.
	Transport string `json:"transport,omitempty"`
	// Role sets the initiator role: "mg" (default — sends first registration)
	// or "mgc" (no registration duty; all initial state is Registered).
	Role string `json:"role,omitempty"`
	// Mid is the mId of the role entity (four forms: domainAddress,
	// domainName, mtpAddress, deviceName — §3.1). If empty, derived from
	// the role's source address (role=mg → [src_ip], role=mgc → [dst_ip]).
	Mid string `json:"mid,omitempty"`
	// PeerMid is the mId of the peer entity (same form rules). If empty,
	// derived from the role's destination address (role=mg → [dst_ip],
	// role=mgc → [src_ip]).
	PeerMid string `json:"peer_mid,omitempty"`
	// Concurrent interleaves this session with other sessions (v1.2 case 45).
	// Per-association transaction order is preserved; inter-association order
	// may be interleaved at the generator level (round-robin per event index).
	Concurrent bool `json:"concurrent,omitempty"`
	// Events is the ordered list of message exchanges on this session.
	Events []MegacoEvent `json:"events,omitempty"`
}

// MegacoEvent is one full Megaco message (may carry multiple transactions).
type MegacoEvent struct {
	// Kind is "message" (the only legal kind in this version).
	Kind string `json:"kind,omitempty"`
	// Direction is "c2s" (default — client to server / MG→MGC for role=mg)
	// or "s2c" (server to client / MGC→MG for role=mg).
	Direction string `json:"direction,omitempty"`
	// Transactions is the ordered list of transactions inside this message.
	Transactions []MegacoTransaction `json:"transactions,omitempty"`
	// WireFault injects a per-event wire fault (overrides session-level
	// config; used for fault-isolation tests).
	WireFault string `json:"wire_fault,omitempty"`
}

// MegacoTransaction is one transaction (Request/Reply/Pending/ResponseAck).
type MegacoTransaction struct {
	// ID is the transactionId: "auto" (runtime-assigned, default), explicit
	// numeric string (only allowed for boundary cases like 4294967295 or
	// for wire_fault injection), or "same_as_request:<i>" (Reply/Pending/
	// ResponseAck reference to the i-th request of this session).
	ID string `json:"id,omitempty"`
	// Type is the transaction type: "request" (default), "reply", "pending",
	// or "response_ack".
	Type string `json:"type,omitempty"`
	// Actions is the list of Context-Action-Command triples inside this
	// transaction. Empty for pending/response_ack.
	Actions []MegacoAction `json:"actions,omitempty"`
	// Ack declares a response_ack coverage (single id or "a-b" range); only
	// valid for type=response_ack. Validator checks coverage ⊆ confirmed
	// transaction set.
	Ack string `json:"ack,omitempty"`
	// ImmAckRequired marks this reply as IA (only valid for type=reply
	// carrying Pending responses; validator checks there was a prior PN
	// for this transactionId).
	ImmAckRequired bool `json:"imm_ack_required,omitempty"`
	// Error is the transaction-level errorDescriptor (RFC 3525 §8.2.3:
	// transactionReply body is actionReplyList / errorDescriptor — mutually
	// exclusive). Only valid for type=reply with empty Actions.
	Error *MegacoError `json:"error,omitempty"`
}

// MegacoAction is one Context = ContextID { commands... } inside a transaction.
type MegacoAction struct {
	// Context is the ContextID: "-" (NULL), "$" (CHOOSE — request only),
	// "*" (ALL — request only), or decimal UINT32. Reserved values
	// 0/0xFFFFFFFE/0xFFFFFFFF are forbidden as concrete Contexts.
	Context string `json:"context,omitempty"`
	// Commands is the ordered list of commands inside this action.
	Commands []MegacoCommand `json:"commands,omitempty"`
}

// MegacoCommand is one of the 8 RFC 3525 commands.
type MegacoCommand struct {
	// Name is the command token: Add|Modify|Subtract|Move|AuditValue|
	// AuditCapability|Notify|ServiceChange.
	Name string `json:"name,omitempty"`
	// Termination is the TerminationID: "ROOT", pathNAME (≤64 chars), "$"
	// (CHOOSE), or "*" (ALL).
	Termination string `json:"termination,omitempty"`
	// Optional emits an "O-" prefix (failure does not abort the transaction).
	Optional bool `json:"optional,omitempty"`
	// WildcardResponse emits a "W-" prefix (wildcarded commands return a
	// single summary response instead of one per match).
	WildcardResponse bool `json:"wildcard_response,omitempty"`
	// Descriptor is the command's parameter block (depends on command type:
	// media/services/events/signals/digit_map/observed_events/audit/
	// event_buffer/statistics/packages/error/...).
	Descriptor *MegacoDescriptor `json:"descriptor,omitempty"`
}

// MegacoDescriptor carries the named parameter blocks per §3.5. All fields
// are optional; only the ones the command actually needs are filled in.
type MegacoDescriptor struct {
	// Services is the Services block (ServiceChange command).
	Services *MegacoServices `json:"services,omitempty"`
	// Media carries Stream/LocalControl/Local/Remote/TerminationState under
	// one media descriptor.
	Media *MegacoMedia `json:"media,omitempty"`
	// Events is the Events descriptor (programming a notification source).
	Events *MegacoEvents `json:"events,omitempty"`
	// EventBuffer is the EventBuffer descriptor (v1.2).
	EventBuffer *MegacoEventBuffer `json:"event_buffer,omitempty"`
	// Embed nests another eventsDescriptor inside an Events item (v1.2).
	Embed *MegacoEvents `json:"embed,omitempty"`
	// Signals is the Signals descriptor.
	Signals *MegacoSignals `json:"signals,omitempty"`
	// DigitMap is the DigitMap descriptor.
	DigitMap *MegacoDigitMap `json:"digit_map,omitempty"`
	// ObservedEvents is the ObservedEvents descriptor (Notify).
	ObservedEvents *MegacoObservedEvents `json:"observed_events,omitempty"`
	// Statistics is the Statistics descriptor (Subtract reply).
	Statistics []string `json:"statistics,omitempty"`
	// Packages is the Packages descriptor.
	Packages []string `json:"packages,omitempty"`
	// Audit is the Audit descriptor.
	Audit *MegacoAudit `json:"audit,omitempty"`
	// Error is the errorDescriptor (carries code + text in the Reply).
	Error *MegacoError `json:"error,omitempty"`
}

// MegacoServices is the Services parameter block of a ServiceChange command.
// Method and Reason are both REQUIRED; ServiceChangeAddress and MgcIdToTry
// are mutually exclusive (ABNF at most one of either).
type MegacoServices struct {
	Method               string `json:"method,omitempty"`                 // Restart/Graceful/Forced/Disconnected/HandOff/Failover
	Reason               string `json:"reason,omitempty"`                 // quoted reason (e.g. "901 Cold Boot")
	Delay                *int   `json:"delay,omitempty"`                  // delay seconds
	ServiceChangeAddress string `json:"service_change_address,omitempty"` // domainAddress
	MgcIDToTry           string `json:"mgc_id_to_try,omitempty"`          // domainAddress
	ServiceChangeMgcID   string `json:"service_change_mgc_id,omitempty"`  // Reply-only redirect
	Profile              string `json:"profile,omitempty"`                // e.g. "ResGW/1"
	Version              *int   `json:"version,omitempty"`                // 1*2 DIGIT
	Timestamp            string `json:"timestamp,omitempty"`              // ISO 8601 yyyymmddThhmmssss
}

// MegacoMedia holds the streams of a Media descriptor.
type MegacoMedia struct {
	// Streams is the list of stream parameter blocks (Stream = <id> { ... }).
	Streams []MegacoStream `json:"streams,omitempty"`
	// TerminationState embeds a TerminationState descriptor inside Media.
	TerminationState *MegacoTerminationState `json:"termination_state,omitempty"`
}

// MegacoStream is one Stream = <id> { LocalControl, Local, Remote, ... }.
type MegacoStream struct {
	// ID is the StreamID (UINT16, ≤65535).
	ID uint32 `json:"id,omitempty"`
	// LocalControl is the LocalControl descriptor (Mode, RV/RG, pkgdname).
	LocalControl *MegacoLocalControl `json:"local_control,omitempty"`
	// LocalSDP is the Local descriptor body (octetString; SDP content).
	LocalSDP string `json:"local_sdp,omitempty"`
	// RemoteSDP is the Remote descriptor body.
	RemoteSDP string `json:"remote_sdp,omitempty"`
}

// MegacoLocalControl carries Mode / RV / RG / pkgdname=value properties.
type MegacoLocalControl struct {
	// Mode is one of: SendOnly(SO)/ReceiveOnly(RC)/SendReceive(SR)/
	// Inactive(IN)/Loopback(LB). Empty omits the field.
	Mode string `json:"mode,omitempty"`
	// ReservedValue is RV: "ON" or "OFF".
	ReservedValue string `json:"reserved_value,omitempty"`
	// ReservedGroup is RG: "ON" or "OFF".
	ReservedGroup string `json:"reserved_group,omitempty"`
	// Properties is the list of pkgdname=value pairs.
	Properties []string `json:"properties,omitempty"`
}

// MegacoTerminationState carries ServiceStates/EventBufferControl/pkg props.
type MegacoTerminationState struct {
	// ServiceStates is "Test"/"OutOfService"/"InService" (TE/OS/IV).
	ServiceStates string `json:"service_states,omitempty"`
	// EventBufferControl is "OFF" or "LockStep" (SP).
	EventBufferControl string `json:"event_buffer_control,omitempty"`
	// Properties is the list of pkgdname=value pairs.
	Properties []string `json:"properties,omitempty"`
}

// MegacoEvents is the Events descriptor (programming notification sources).
type MegacoEvents struct {
	// RequestID is the optional "= RequestID" prefix (RequestID associated
	// with subsequent Notify ObservedEvents). 0 means "no RequestID" form.
	RequestID uint32 `json:"request_id,omitempty"`
	// Items is the ordered list of events (pkgdName [params]).
	Items []string `json:"items,omitempty"`
	// KeepActive keeps the events active across subsequent events.
	KeepActive bool `json:"keep_active,omitempty"`
}

// MegacoEventBuffer is the EventBuffer descriptor (v1.2).
type MegacoEventBuffer struct {
	// Items is the ordered list of event pkgdname tokens.
	Items []string `json:"items,omitempty"`
}

// MegacoSignals is the Signals descriptor.
type MegacoSignals struct {
	// Items is the list of signal spec tokens (pkgdname [params]).
	Items []string `json:"items,omitempty"`
	// SignalList is the list of SignalList=ID{pkgdname...} entries.
	SignalList []MegacoSignalList `json:"signal_list,omitempty"`
}

// MegacoSignalList is one SignalList=ID { pkgdname, ... } entry.
type MegacoSignalList struct {
	ID    uint32   `json:"id,omitempty"`
	Items []string `json:"items,omitempty"`
}

// MegacoDigitMap is the DigitMap descriptor.
type MegacoDigitMap struct {
	// Name is the DigitMap name token.
	Name string `json:"name,omitempty"`
	// T is the start timer (1-99, or 0 = "disable start timer" — valid per
	// D-4 fix, NOT a boundary violation; >99 is the violation).
	T *int `json:"t,omitempty"`
	// S is the short timer (1-99; 0 is the violation).
	S *int `json:"s,omitempty"`
	// L is the long timer (1-99; 0 is the violation).
	L *int `json:"l,omitempty"`
	// Value is the digit string body (e.g. "(0|00|1xxx)").
	Value string `json:"value,omitempty"`
}

// MegacoObservedEvents is the ObservedEvents descriptor.
type MegacoObservedEvents struct {
	// RequestID is the mandatory RequestID (must match the active Events'
	// RequestID per RFC 3525 §7.1.9/§7.1.17).
	RequestID uint32 `json:"request_id,omitempty"`
	// Items is the list of "[timestamp:] pkgdname [params]" tokens.
	Items []string `json:"items,omitempty"`
}

// MegacoAudit is the Audit descriptor.
type MegacoAudit struct {
	// Items is the list of auditItem tokens (Mux/Modem/Media/Signals/
	// EventBuffer/DigitMap/Statistics/Events/ObservedEvents/Packages).
	Items []string `json:"items,omitempty"`
}

// MegacoError is the errorDescriptor (carries an RFC 3525 error code).
type MegacoError struct {
	// Code is the 1*4 DIGIT error code (e.g. 411, 430, 431, 442).
	Code int `json:"code,omitempty"`
	// Text is the human-readable error text.
	Text string `json:"text,omitempty"`
}
