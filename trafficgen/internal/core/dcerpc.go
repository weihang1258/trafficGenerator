// Package core: DCE/RPC v5 over TCP types（D-DCERPC-1 契约 v2.0.0）。
// 字段名与用例键一致；strict decode 拒绝未知键（bacnet 同款）。
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DCERPCConfig is the dcerpc terminal-layer config.
type DCERPCConfig struct {
	Concurrent bool            `json:"concurrent,omitempty"`
	Sessions   []DCERPCSession `json:"sessions,omitempty"`
	WireFault  string          `json:"wire_fault,omitempty"`
}

// DCERPCSession is one TCP connection（EPM 会话与 dynamic 会话各自声明）。
type DCERPCSession struct {
	SrcPort  uint16        `json:"src_port,omitempty"` // 客户端口（TCP 族会话隔离——edp sessions[].src_port 先例）
	DstPort  uint16        `json:"dst_port,omitempty"` // 0=继承链级 135；dynamic 会话显式
	Prebound bool          `json:"prebound,omitempty"` // fixture 声明已绑定状态（跳 bind 直接调用合法面）
	Events   []DCERPCEvent `json:"events,omitempty"`
}

// DCERPCContext is one p_context_elem_t（abstract + transfer syntaxes）。
type DCERPCContext struct {
	ContextID       int            `json:"context_id"`
	Abstract        string         `json:"abstract"`
	AbstractVersion []int          `json:"abstract_version,omitempty"` // [major, minor]
	Syntaxes        []DCERPCSyntax `json:"syntaxes,omitempty"`
}

// DCERPCSyntax is one transfer syntax offer.
type DCERPCSyntax struct {
	UUID    string `json:"uuid"`
	Version []int  `json:"version,omitempty"` // [major, minor]
}

// DCERPCAuth is the auth verifier（credentials 仅 opaque——安全限制）。
type DCERPCAuth struct {
	Type        int    `json:"type,omitempty"`
	Level       int    `json:"level,omitempty"`
	ContextID   int    `json:"context_id,omitempty"`
	Credentials string `json:"credentials,omitempty"` // hex
	Pad         int    `json:"pad,omitempty"`         // 0-3
}

// DCERPCResult is one bind_ack/alter_ctx_resp result element.
type DCERPCResult struct {
	ContextID int    `json:"context_id"`
	Result    int    `json:"result"` // 0 acceptance / 1 user rejection / 2 provider rejection
	Reason    int    `json:"reason,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	Version   []int  `json:"version,omitempty"`
}

// DCERPCRespond declares the server-side PDU(s) answering an event.
type DCERPCRespond struct {
	Ack         string         `json:"ack"`                 // bind_ack / alter_ctx_resp / response / fault
	CallID      *int           `json:"call_id,omitempty"`   // override → call_mismatch 自然面
	Secondary   string         `json:"secondary,omitempty"` // bind_ack secondary address（端口字符串）
	Results     []DCERPCResult `json:"results,omitempty"`
	AllocHint   *int           `json:"alloc_hint,omitempty"`
	CancelCount int            `json:"cancel_count,omitempty"`
	Status      *int           `json:"status,omitempty"` // fault
	Stub        string         `json:"stub,omitempty"`
	Fragments   int            `json:"fragments,omitempty"`
	Auth        *DCERPCAuth    `json:"auth,omitempty"`
}

// DCERPCEvent is one session event（请求 PDU + respond 应答面）。
type DCERPCEvent struct {
	Kind       string          `json:"kind"` // bind / alter_ctx / request
	CallID     *int            `json:"call_id,omitempty"`
	Contexts   []DCERPCContext `json:"contexts,omitempty"` // bind/alter_ctx
	MaxXmit    int             `json:"max_xmit,omitempty"`
	MaxRecv    int             `json:"max_recv,omitempty"`
	AssocGroup *int            `json:"assoc_group,omitempty"`
	ContextID  *int            `json:"context_id,omitempty"` // request
	Opnum      *int            `json:"opnum,omitempty"`
	AllocHint  *int            `json:"alloc_hint,omitempty"`
	ObjectUUID string          `json:"object_uuid,omitempty"` // PFC_OBJECT_UUID
	Stub       string          `json:"stub,omitempty"`
	Fragments  int             `json:"fragments,omitempty"`
	Auth       *DCERPCAuth     `json:"auth,omitempty"`
	Respond    *DCERPCRespond  `json:"respond,omitempty"`
}

// 32 wire_fault 值（设计 §7 处置表；D-DCERPC-1 裁定10——逐故障单锚词）。
const (
	DCERPCWireFaultVersionNot5           = "version_not5"
	DCERPCWireFaultVersionMinorNot0      = "version_minor_not0"
	DCERPCWireFaultPacketTypeUnknown     = "packet_type_unknown"
	DCERPCWireFaultPacketTypeReserved    = "packet_type_reserved"
	DCERPCWireFaultFlagsFirstNoLast      = "flags_first_no_last"
	DCERPCWireFaultFlagsLastNoFirst      = "flags_last_no_first"
	DCERPCWireFaultDrepNotLE             = "drep_not_le"
	DCERPCWireFaultFragLenLt16           = "frag_len_lt16"
	DCERPCWireFaultFragLenMismatch       = "frag_len_mismatch"
	DCERPCWireFaultAuthLenOver           = "auth_len_over"
	DCERPCWireFaultCallIDReuse           = "call_id_reuse"
	DCERPCWireFaultCallMismatch          = "call_mismatch"
	DCERPCWireFaultStateAckNoCall        = "state_ack_no_call"
	DCERPCWireFaultStateRequestUnbound   = "state_request_unbound"
	DCERPCWireFaultContextDuplicate      = "context_duplicate"
	DCERPCWireFaultContextUnknown        = "context_unknown"
	DCERPCWireFaultSyntaxMismatch        = "syntax_mismatch"
	DCERPCWireFaultUUIDVersionMissing    = "uuid_version_missing"
	DCERPCWireFaultAllocHintNegative     = "alloc_hint_negative"
	DCERPCWireFaultNDRAlignment          = "ndr_alignment"
	DCERPCWireFaultNDRArrayCount         = "ndr_array_count"
	DCERPCWireFaultNDRUnionUnknown       = "ndr_union_unknown"
	DCERPCWireFaultNDRStubOverflow       = "ndr_stub_overflow"
	DCERPCWireFaultAuthPadInvalid        = "auth_pad_invalid"
	DCERPCWireFaultAuthTrailerOver       = "auth_trailer_over"
	DCERPCWireFaultAuthVerifierLen       = "auth_verifier_len"
	DCERPCWireFaultCarrierLayerMissing   = "carrier_layer_missing"
	DCERPCWireFaultCarrierUDP            = "carrier_udp"
	DCERPCWireFaultPortUndeclared        = "port_undeclared"
	DCERPCWireFaultAddressFamilyMismatch = "address_family_mismatch"
	DCERPCWireFaultUUIDWidth             = "uuid_width"
	DCERPCWireFaultAssocGroupWidth       = "assoc_group_width"
)

// UnmarshalJSON strict-decodes the dcerpc layer config（未知键拒绝）。
func (c *DCERPCConfig) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	type alias DCERPCConfig
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = DCERPCConfig(a)
	return nil
}

// DescribeDCERPCWireFault returns the row's 主锚词（error_contains 断言）。
func DescribeDCERPCWireFault(kind string) (string, error) {
	anchors := map[string]string{
		DCERPCWireFaultVersionNot5:           "header",
		DCERPCWireFaultVersionMinorNot0:      "version",
		DCERPCWireFaultPacketTypeUnknown:     "packet",
		DCERPCWireFaultPacketTypeReserved:    "packet",
		DCERPCWireFaultFlagsFirstNoLast:      "fragment",
		DCERPCWireFaultFlagsLastNoFirst:      "fragment",
		DCERPCWireFaultDrepNotLE:             "drep",
		DCERPCWireFaultFragLenLt16:           "frag",
		DCERPCWireFaultFragLenMismatch:       "length",
		DCERPCWireFaultAuthLenOver:           "auth",
		DCERPCWireFaultCallIDReuse:           "call",
		DCERPCWireFaultCallMismatch:          "call",
		DCERPCWireFaultStateAckNoCall:        "state",
		DCERPCWireFaultStateRequestUnbound:   "state",
		DCERPCWireFaultContextDuplicate:      "context",
		DCERPCWireFaultContextUnknown:        "context",
		DCERPCWireFaultSyntaxMismatch:        "syntax",
		DCERPCWireFaultUUIDVersionMissing:    "uuid",
		DCERPCWireFaultAllocHintNegative:     "hint",
		DCERPCWireFaultNDRAlignment:          "ndr",
		DCERPCWireFaultNDRArrayCount:         "array",
		DCERPCWireFaultNDRUnionUnknown:       "union",
		DCERPCWireFaultNDRStubOverflow:       "ndr",
		DCERPCWireFaultAuthPadInvalid:        "trailer",
		DCERPCWireFaultAuthTrailerOver:       "trailer",
		DCERPCWireFaultAuthVerifierLen:       "verifier",
		DCERPCWireFaultCarrierLayerMissing:   "carrier",
		DCERPCWireFaultCarrierUDP:            "carrier",
		DCERPCWireFaultPortUndeclared:        "port",
		DCERPCWireFaultAddressFamilyMismatch: "family",
		DCERPCWireFaultUUIDWidth:             "uuid",
		DCERPCWireFaultAssocGroupWidth:       "width",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("dcerpc: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
