package pcep

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"slices"

	"github.com/trafficgen/trafficgen/internal/core"
)

// PCEP wire format constants.
const (
	pcepVersion = 0x20 // Version=1 in high 3 bits
	hdrLen      = 4
	objHdrLen   = 4
	tlvHdrLen   = 4
	defaultKA   = 30
	defaultDT   = 120
)

// Message types.
const (
	msgOpen       uint8 = 1
	msgKeepalive  uint8 = 2
	msgPCErr      uint8 = 3
	msgPCNtf      uint8 = 4
	msgPCReq      uint8 = 6
	msgPCRep      uint8 = 7
	msgPCUpd      uint8 = 10
	msgPCInitiate uint8 = 12
)

// Object classes (RFC 5440 + RFC 8231).
const (
	objOpen      uint8 = 1
	objRP        uint8 = 2
	objEndpoint  uint8 = 4
	objNotif     uint8 = 12
	objMetric    uint8 = 6
	objERO       uint8 = 7
	objRRO       uint8 = 8
	objLSPA      uint8 = 9
	objError     uint8 = 13
	objLSP       uint8 = 32
	objSRP       uint8 = 33
)

// TLV types for OPEN object.
const (
	tlvStatefulPCE = 16
	tvlSyncCap     = 17
)

// pcepObject is a parsed PCEP object for building.
type pcepObject struct {
	Class             string          `json:"class"`
	ObjectType        uint8           `json:"type,omitempty"`
	ObjectLength      uint16          `json:"object_length,omitempty"`
	RequestedIDNumber uint32          `json:"requested_id_number,omitempty"`
	Flags             json.RawMessage `json:"flags,omitempty"`
	SourceIPv4        string          `json:"source_ipv4,omitempty"`
	DestinationIPv4   string          `json:"destination_ipv4,omitempty"`
	SourceIPv6        string          `json:"source_ipv6,omitempty"`
	DestinationIPv6   string          `json:"destination_ipv6,omitempty"`
	Subobjects        []pcepSubobject `json:"subobjects,omitempty"`
	Value             float64         `json:"value,omitempty"`
	PLSPID            uint32          `json:"plsp_id,omitempty"`
	IDNumber          uint32          `json:"id_number,omitempty"`
	SetupPriority     uint8           `json:"setup_priority,omitempty"`
	HoldingPriority   uint8           `json:"holding_priority,omitempty"`
}

// pcepSubobject is an ERO/RRO subobject.
type pcepSubobject struct {
	Type         string `json:"type"`
	Address      string `json:"address"`
	PrefixLength uint8  `json:"prefix_length"`
	L            bool   `json:"l"`
}

// buildCommonHeader builds a PCEP common header.
func buildCommonHeader(msgType uint8, length uint16) []byte {
	buf := make([]byte, hdrLen)
	buf[0] = pcepVersion
	buf[1] = msgType
	binary.BigEndian.PutUint16(buf[2:4], length)
	return buf
}

// objectFlags parses the flags field from a JSON object.
func objectFlags(raw json.RawMessage) (pFlag, iFlag bool) {
	if raw == nil {
		return false, false
	}
	var m map[string]bool
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, false
	}
	return m["p"], m["i"]
}

// buildObjectHeader builds a PCEP object header.
// Byte 1: Object-Type(4 bits, high nibble) | Flags(4 bits, low nibble).
// Wireshark MASK_OBJ_TYPE=0xF0; P flag=0x2 (bit 1), I flag=0x1 (bit 0).
func buildObjectHeader(objClass, objType uint8, pFlag, iFlag bool, bodyLen uint16) []byte {
	// Round body to 4-byte alignment
	aligned := bodyLen
	if pad := aligned % 4; pad != 0 {
		aligned += 4 - pad
	}
	totalLen := objHdrLen + aligned

	b1 := (objType & 0x0F) << 4 // Object-Type in bits 4-7 (high nibble)
	if pFlag {
		b1 |= 0x02 // P flag in bit 1
	}
	if iFlag {
		b1 |= 0x01 // I flag in bit 0
	}

	buf := make([]byte, objHdrLen)
	buf[0] = objClass
	buf[1] = b1
	binary.BigEndian.PutUint16(buf[2:4], totalLen)
	return buf
}

// buildTLV builds a PCEP TLV (type 2 + length 2 + value).
func buildTLV(tlvType uint16, value []byte) []byte {
	buf := make([]byte, tlvHdrLen+len(value))
	binary.BigEndian.PutUint16(buf[0:2], tlvType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[4:], value)
	return buf
}

// pad4 pads a byte slice to a 4-byte boundary with zeros.
func pad4(buf []byte) []byte {
	rem := len(buf) % 4
	if rem == 0 {
		return buf
	}
	return append(buf, make([]byte, 4-rem)...)
}

// BuildOpenMsg builds an Open message.
func BuildOpenMsg(keepalive, deadtime, sid uint8, capabilities []core.PCEPCapability) []byte {
	// Open 对象体最小 4 字节（Wireshark OPEN_OBJ_MIN_LEN=4）：
	// PCEP-Version(3 bits, mask 0xE0) | Flags(5 bits, mask 0x1F) + Keepalive(1)
	// + DeadTimer(1) + SID(1, 单字节)。SID 为 uint8，只写 1 字节。
	body := make([]byte, 4)
	body[0] = 0x20 // Ver=1 << 5(高3位) | Flags=0 → 0x20
	body[1] = keepalive
	body[2] = deadtime
	body[3] = sid

	// Append capability TLVs
	for _, cap := range capabilities {
		switch cap.Kind {
		case "stateful_pce":
			// RFC 8231 §5.1: Stateful-PCE-Capability TLV (type 16), 4-byte flags.
			// Wireshark: U=0x00000001 (bit0), S=0x00000002 (bit1) of the 32-bit flags.
			flags := make([]byte, 4)
			if cap.LSPUpdate {
				flags[3] |= 0x01 // U (LSP-UPDATE-CAPABILITY)
			}
			if cap.IncludeDBVersion {
				flags[3] |= 0x02 // S (INCLUDE-DB-VERSION)
			}
			body = append(body, buildTLV(tlvStatefulPCE, flags)...)
			// RFC 8231 §5.2: When include_db_version is set, emit TLV 17 (Sync)
			// alongside TLV 16 as a single capability entry.
			if cap.IncludeDBVersion {
				syncFlags := make([]byte, 4)
				syncFlags[3] |= 0x02 // S (INCLUDE-DB-VERSION)
				body = append(body, buildTLV(tvlSyncCap, syncFlags)...)
			}
		case "sync":
			// RFC 8231 §5.2: Stateful-PCE-Capability (Sync) TLV (type 17), 4-byte flags.
			flags := make([]byte, 4)
			if cap.IncludeDBVersion {
				flags[3] |= 0x02 // S (INCLUDE-DB-VERSION)
			}
			body = append(body, buildTLV(tvlSyncCap, flags)...)
		}
	}

	obj := buildObjectHeader(objOpen, 1, false, false, uint16(len(body)))
	obj = append(obj, body...)
	msg := buildCommonHeader(msgOpen, uint16(hdrLen+len(obj)))
	return append(msg, obj...)
}

// BuildKeepAliveMsg builds a Keepalive message (just common header, no object).
func BuildKeepAliveMsg() []byte {
	return buildCommonHeader(msgKeepalive, hdrLen)
}

// BuildPCReqMsg builds a PCReq message.
func BuildPCReqMsg(objs [][]byte) []byte {
	return buildMultiObjMsg(msgPCReq, objs)
}

// BuildPCRepMsg builds a PCRep message.
func BuildPCRepMsg(objs [][]byte) []byte {
	return buildMultiObjMsg(msgPCRep, objs)
}

// BuildPCNtfMsg builds a PCNtf message.
// Notification object body (min 4): Reserved(1) + Flags(1) + Type(1) + Value(1).
func BuildPCNtfMsg(ntype, nvalue uint16) []byte {
	body := make([]byte, 4)
	body[2] = byte(ntype)
	body[3] = byte(nvalue)
	obj := buildObjectHeader(objNotif, 1, false, false, 4)
	obj = append(obj, body...)
	msg := buildCommonHeader(msgPCNtf, uint16(hdrLen+len(obj)))
	return append(msg, obj...)
}

// BuildPCErrMsg builds a PCErr message.
// PCEP-ERROR object body (min 4): Reserved(1) + Flags(1) + Error-Type(1) + Error-Value(1).
func BuildPCErrMsg(etype, evalue uint16) []byte {
	body := make([]byte, 4)
	body[2] = byte(etype)
	body[3] = byte(evalue)
	obj := buildObjectHeader(objError, 1, false, false, 4)
	obj = append(obj, body...)
	msg := buildCommonHeader(msgPCErr, uint16(hdrLen+len(obj)))
	return append(msg, obj...)
}

// buildMultiObjMsg builds a message with multiple objects.
func buildMultiObjMsg(msgType uint8, objs [][]byte) []byte {
	var body []byte
	for _, o := range objs {
		body = append(body, o...)
	}
	msg := buildCommonHeader(msgType, uint16(hdrLen+len(body)))
	return append(msg, body...)
}

// BuildRPObject builds an RP object.
// Wireshark RP_OBJ_MIN_LEN=8: Reserved(1) + Flags(3, P=0x000100) + Request-ID(4).
func BuildRPObject(requestID uint32, pFlag, iFlag bool) []byte {
	body := make([]byte, 8)
	// P flag in 24-bit flags field (body[1:4]); PCEP_RP_P=0x000100 → bit16,
	// which is the MSB of the 3rd byte (body[3] bit0). I flag is not defined
	// in the RP body flags (it lives on the object header), so only P is set.
	if pFlag {
		body[3] |= 0x01 // PCEP_RP_P = 0x000100 → body[3] bit 0
	}
	binary.BigEndian.PutUint32(body[4:8], requestID)
	obj := buildObjectHeader(objRP, 1, pFlag, iFlag, 8)
	obj = append(obj, body...)
	return obj
}

// BuildEndpointObjectIPv4 builds an IPv4 END-POINT object.
// Wireshark END_POINT_IPV4_OBJ_LEN=8: Source(4) + Destination(4). No reserved.
func BuildEndpointObjectIPv4(src, dst string) []byte {
	body := make([]byte, 8)
	if s := net.ParseIP(src).To4(); s != nil {
		copy(body[0:4], s)
	}
	if d := net.ParseIP(dst).To4(); d != nil {
		copy(body[4:8], d)
	}
	obj := buildObjectHeader(objEndpoint, 1, false, false, 8)
	obj = append(obj, body...)
	return obj
}

// BuildEndpointObjectIPv6 builds an IPv6 END-POINT object.
// Wireshark END_POINT_IPV6_OBJ_LEN=32: Source(16) + Destination(16). No reserved.
func BuildEndpointObjectIPv6(src, dst string) []byte {
	body := make([]byte, 32)
	if s := net.ParseIP(src).To16(); s != nil {
		copy(body[0:16], s)
	}
	if d := net.ParseIP(dst).To16(); d != nil {
		copy(body[16:32], d)
	}
	obj := buildObjectHeader(objEndpoint, 2, false, false, 32)
	obj = append(obj, body...)
	return obj
}

// BuildEROObject builds an ERO object with subobjects.
func BuildEROObject(subobjects []pcepSubobject) []byte {
	var body []byte
	for _, sub := range subobjects {
		body = append(body, buildSubobject(sub, true)...)
	}
	body = pad4(body)
	obj := buildObjectHeader(objERO, 1, false, false, uint16(len(body)))
	obj = append(obj, body...)
	return obj
}

// BuildRROObject builds an RRO object with subobjects.
func BuildRROObject(subobjects []pcepSubobject) []byte {
	var body []byte
	for _, sub := range subobjects {
		body = append(body, buildSubobject(sub, false)...)
	}
	body = pad4(body)
	obj := buildObjectHeader(objRRO, 1, false, false, uint16(len(body)))
	obj = append(obj, body...)
	return obj
}

// buildSubobject builds an ERO/RRO subobject.
func buildSubobject(sub pcepSubobject, isERO bool) []byte {
	switch sub.Type {
	case "ipv4":
		// IPv4 subobject: Type(1, mask 0x7f + L=0x80) + Length(1) + Addr(4) +
		// PrefixLen(1) + Padding(1) = 8 bytes. For ERO the L flag (loose/strict)
		// lives in bit 7 of the type byte (Mask_L=0x80).
		buf := make([]byte, 8)
		buf[0] = 1 // IPv4 subobject type (mask 0x7f)
		if sub.L && isERO {
			buf[0] |= 0x80 // L flag (loose hop), Mask_L = 0x80
		}
		buf[1] = 8 // Length
		if a := net.ParseIP(sub.Address).To4(); a != nil {
			copy(buf[2:6], a)
		}
		buf[6] = sub.PrefixLength
		return buf
	case "ipv6":
		// IPv6 subobject: Type(1, mask 0x7f + L=0x80) + Length(1) + Addr(16) +
		// PrefixLen(1) + Padding(1) = 20 bytes.
		buf := make([]byte, 20)
		buf[0] = 2  // IPv6 subobject type (mask 0x7f)
		if sub.L && isERO {
			buf[0] |= 0x80 // L flag (loose hop), Mask_L = 0x80
		}
		buf[1] = 20 // Length
		if a := net.ParseIP(sub.Address).To16(); a != nil {
			copy(buf[2:18], a)
		}
		buf[18] = sub.PrefixLength
		return buf
	default:
		return nil
	}
}

// BuildMetricObject builds a Metric object.
// Wireshark METRIC_OBJ_LEN=8: Reserved(2) + Flags(1, C=0x02, B=0x01) +
// Type(1) + Value(4, IEEE float).
func BuildMetricObject(mtype uint8, cFlag, bFlag bool, value float64) []byte {
	body := make([]byte, 8)
	if cFlag {
		body[2] |= 0x02 // C flag
	}
	if bFlag {
		body[2] |= 0x01 // B flag
	}
	body[3] = mtype
	binary.BigEndian.PutUint32(body[4:8], math.Float32bits(float32(value)))
	obj := buildObjectHeader(objMetric, 1, false, false, 8)
	obj = append(obj, body...)
	return obj
}

// BuildLSPObject builds an LSP object (RFC 8231).
// Wireshark OBJ_LSP_MIN_LEN=4: PLSP-ID(3 bytes, mask 0xFFFFF0 → value<<4) +
// Flags(1 byte: D=0x01, S=0x02, R=0x04, A=0x08, C=0x80).
func BuildLSPObject(plspID uint32, flags map[string]bool) []byte {
	body := make([]byte, 4)
	// PLSP-ID is 20 bits in the high bits of 3 bytes: store value << 4.
	val := (plspID & 0xFFFFF) << 4
	body[0] = byte(val >> 16)
	body[1] = byte(val >> 8)
	body[2] = byte(val)
	if flags["delegate"] {
		body[3] |= 0x01 // D
	}
	if flags["sync"] {
		body[3] |= 0x02 // S
	}
	if flags["remove"] {
		body[3] |= 0x04 // R
	}
	if flags["administrative"] {
		body[3] |= 0x08 // A
	}
	if flags["create"] {
		body[3] |= 0x80 // C
	}
	obj := buildObjectHeader(objLSP, 1, false, false, 4)
	obj = append(obj, body...)
	return obj
}

// BuildSRPObject builds an SRP object (RFC 8231).
// Wireshark OBJ_SRP_MIN_LEN=8: Flags(4, R=0x00000001) + SRP-ID-number(4).
func BuildSRPObject(idNumber uint32, flags map[string]bool) []byte {
	body := make([]byte, 8)
	if flags["remove"] {
		body[3] |= 0x01 // R (bit0 of 32-bit flags field)
	}
	binary.BigEndian.PutUint32(body[4:8], idNumber)
	obj := buildObjectHeader(objSRP, 1, false, false, 8)
	obj = append(obj, body...)
	return obj
}

// BuildLSPAObject builds an LSPA object (RFC 5440).
// Wireshark LSPA_OBJ_MIN_LEN=16: ExcludeAny(4) + IncludeAny(4) + IncludeAll(4) +
// SetupPriority(1) + HoldingPriority(1) + Flags(1, L=0x01) + Reserved(1).
func BuildLSPAObject(lFlag bool, setupPriority, holdingPriority uint8) []byte {
	body := make([]byte, 16)
	body[12] = setupPriority
	body[13] = holdingPriority
	if lFlag {
		body[14] |= 0x01 // PCEP_LSPA_L
	}
	obj := buildObjectHeader(objLSPA, 1, false, false, 16)
	obj = append(obj, body...)
	return obj
}

// parsePCEPConfig parses PCEP events from the config and returns PDU bytes.
func parsePCEPConfig(cfg *core.PCEPConfig) ([][]byte, []bool, error) {
	var payloads [][]byte
	var ups []bool

	for i, ev := range cfg.Events {
		up := ev.Direction == "c2s"
		var pdu []byte

		// Wire fault injection check (before building)
		if ev.WireFault != nil {
			if err := CheckFault(ev.WireFault.Kind); err != nil {
				return nil, nil, fmt.Errorf("pcep: event %d: %w", i, err)
			}
		}
		switch ev.Kind {
		case "open":
			ka := ev.Keepalive
			dt := ev.Deadtime
			if ka == 0 {
				ka = defaultKA
			}
			if dt == 0 {
				dt = defaultDT
			}
			pdu = BuildOpenMsg(ka, dt, ev.SID, ev.Capabilities)

		case "keepalive":
			pdu = BuildKeepAliveMsg()

		case "pcreq":
			objs, err := parseObjects(ev.Objects, ev.Endpoint, ev.RequestID, cfg.Profile)
			if err != nil {
				return nil, nil, fmt.Errorf("pcep: pcreq: %w", err)
			}
			pdu = BuildPCReqMsg(objs)

		case "pcrep":
			objs, err := parseObjects(ev.Objects, ev.Endpoint, ev.RequestID, cfg.Profile)
			if err != nil {
				return nil, nil, fmt.Errorf("pcep: pcrep: %w", err)
			}
			pdu = BuildPCRepMsg(objs)

		case "pcntf":
			ntype, nvalue := parseNotification(ev.Objects)
			pdu = BuildPCNtfMsg(ntype, nvalue)

		case "pcerr":
			etype, evalue := parseError(ev.Objects)
			pdu = BuildPCErrMsg(etype, evalue)

		case "unknown":
			mt := ev.MessageType
			if mt == 0 {
				mt = 99
			}
			pdu = buildCommonHeader(mt, hdrLen) // minimal header

		default:
			return nil, nil, fmt.Errorf("pcep: unknown event kind %q", ev.Kind)
		}

		payloads = append(payloads, pdu)
		ups = append(ups, up)
	}
	return payloads, ups, nil
}

// parseObjects parses the objects array from a PCEP event.
func parseObjects(rawObjs []json.RawMessage, endpoint *core.PCEPEndpoint, requestID uint32, profile string) ([][]byte, error) {
	var objs [][]byte

	// If endpoint is set at the event level, build an RP + END-POINT first.
	hasRP := false
	for _, raw := range rawObjs {
		var obj pcepObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("unmarshal object: %w", err)
		}
		if obj.Class == "rp" {
			hasRP = true
		}
	}

	// Auto-add RP if endpoint is provided and no RP is in objects
	if endpoint != nil && !hasRP && requestID > 0 {
		objs = append(objs, BuildRPObject(requestID, false, false))
	}

	// Now parse each object
	for _, raw := range rawObjs {
		var obj pcepObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("unmarshal object: %w", err)
		}

		pFlag, iFlag := objectFlags(obj.Flags)

		switch obj.Class {
		case "rp":
			rid := obj.RequestedIDNumber
			if rid == 0 && requestID > 0 {
				rid = requestID
			}
			objs = append(objs, BuildRPObject(rid, pFlag, iFlag))

		case "endpoint":
			if obj.SourceIPv4 != "" || obj.DestinationIPv4 != "" {
				objs = append(objs, BuildEndpointObjectIPv4(obj.SourceIPv4, obj.DestinationIPv4))
			} else if obj.SourceIPv6 != "" || obj.DestinationIPv6 != "" {
				objs = append(objs, BuildEndpointObjectIPv6(obj.SourceIPv6, obj.DestinationIPv6))
			} else if endpoint != nil {
				if endpoint.SourceIPv4 != "" || endpoint.DestinationIPv4 != "" {
					objs = append(objs, BuildEndpointObjectIPv4(endpoint.SourceIPv4, endpoint.DestinationIPv4))
				} else if endpoint.SourceIPv6 != "" || endpoint.DestinationIPv6 != "" {
					objs = append(objs, BuildEndpointObjectIPv6(endpoint.SourceIPv6, endpoint.DestinationIPv6))
				}
			}

		case "ero":
			objs = append(objs, BuildEROObject(obj.Subobjects))

		case "rro":
			objs = append(objs, BuildRROObject(obj.Subobjects))

		case "metric":
			// Determine metric type and flags from the object
			mtype := obj.ObjectType
			if mtype == 0 {
				mtype = 1
			}
			cFlag := false
			bFlag := false
			if obj.Flags != nil {
				var fm map[string]bool
				if err := json.Unmarshal(obj.Flags, &fm); err == nil {
					cFlag = fm["c"]
					bFlag = fm["b"]
				}
			}
			objs = append(objs, BuildMetricObject(mtype, cFlag, bFlag, obj.Value))

		case "notification":
			// Already handled at message level, skip

		case "error":
			// Already handled at message level, skip

		case "lsp":
			flags := make(map[string]bool)
			if obj.Flags != nil {
				var fm map[string]bool
				if err := json.Unmarshal(obj.Flags, &fm); err == nil {
					flags = fm
				}
			}
			objs = append(objs, BuildLSPObject(obj.PLSPID, flags))

		case "srp":
			flags := make(map[string]bool)
			if obj.Flags != nil {
				var fm map[string]bool
				if err := json.Unmarshal(obj.Flags, &fm); err == nil {
					flags = fm
				}
			}
			objs = append(objs, BuildSRPObject(obj.IDNumber, flags))

		case "lspa":
			lFlag := false
			if obj.Flags != nil {
				var fm map[string]bool
				if err := json.Unmarshal(obj.Flags, &fm); err == nil {
					lFlag = fm["l"]
				}
			}
			objs = append(objs, BuildLSPAObject(lFlag, obj.SetupPriority, obj.HoldingPriority))

		default:
			return nil, fmt.Errorf("unknown object class %q", obj.Class)
		}
	}

	return objs, nil
}

// parseNotification extracts notification type and value from objects.
func parseNotification(rawObjs []json.RawMessage) (uint16, uint16) {
	for _, raw := range rawObjs {
		var obj struct {
			Class string          `json:"class"`
			NType uint16          `json:"type"`
			Value uint16          `json:"value"`
			Flags json.RawMessage `json:"flags,omitempty"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.Class == "notification" {
			return obj.NType, obj.Value
		}
	}
	return 0, 0
}

// parseError extracts error type and value from objects.
func parseError(rawObjs []json.RawMessage) (uint16, uint16) {
	for _, raw := range rawObjs {
		var obj struct {
			Class string          `json:"class"`
			EType uint16          `json:"type"`
			Value uint16          `json:"value"`
			Flags json.RawMessage `json:"flags,omitempty"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.Class == "error" {
			return obj.EType, obj.Value
		}
	}
	return 0, 0
}

// CheckFault returns an error for fault injection, or nil.
func CheckFault(faultKind string) error {
	switch faultKind {
	case "":
		return nil
	case "length", "type", "object_length", "keepalive", "session", "address_family", "stateful":
		return fmt.Errorf("pcep: fault injection %q", faultKind)
	default:
		return fmt.Errorf("pcep: unknown fault kind %q", faultKind)
	}
}

// ValidateConfig validates the PCEP config.
func ValidateConfig(cfg *core.PCEPConfig) error {
	if cfg == nil {
		return fmt.Errorf("pcep: config is required")
	}
	if len(cfg.Events) == 0 {
		return fmt.Errorf("pcep: at least one event required")
	}

	validProfiles := []string{"pcep_rfc5440_ipv4", "pcep_rfc5440_ipv6", "pcep_rfc8231_stateful", "pcep_rfc8281_delegation", "pcep_unknown_extension", ""}
	if !slices.Contains(validProfiles, cfg.Profile) {
		return fmt.Errorf("pcep: unknown profile %q", cfg.Profile)
	}

	validKinds := []string{"open", "keepalive", "pcreq", "pcrep", "pcntf", "pcerr", "unknown"}
	for i, ev := range cfg.Events {
		if ev.Kind == "" {
			return fmt.Errorf("pcep: event %d: kind is required", i)
		}
		if ev.Direction != "c2s" && ev.Direction != "s2c" {
			return fmt.Errorf("pcep: event %d: direction must be c2s or s2c", i)
		}
		if !slices.Contains(validKinds, ev.Kind) {
			return fmt.Errorf("pcep: event %d: unknown kind %q", i, ev.Kind)
		}
		if ev.Kind == "keepalive" && len(ev.Objects) > 0 {
			return fmt.Errorf("pcep: event %d: keepalive must not have objects", i)
		}
	}

	// Check profile-specific constraints
	isStateful := cfg.Profile == "pcep_rfc8231_stateful" || cfg.Profile == "pcep_rfc8281_delegation"
	for i, ev := range cfg.Events {
		if ev.Kind == "open" {
			continue
		}
		// Wire fault injection check
		if ev.WireFault != nil {
			if err := CheckFault(ev.WireFault.Kind); err != nil {
				return fmt.Errorf("pcep: event %d: %w", i, err)
			}
		}
		// Check for stateful-only objects in base profile
		if !isStateful && ev.Objects != nil {
			for _, raw := range ev.Objects {
				var obj struct {
					Class string `json:"class"`
				}
				if err := json.Unmarshal(raw, &obj); err != nil {
					continue
				}
				if obj.Class == "lsp" || obj.Class == "srp" {
					return fmt.Errorf("pcep: event %d: %s object requires stateful profile", i, obj.Class)
				}
			}
		}
		// Check address family consistency
		if cfg.Profile == "pcep_rfc5440_ipv4" && ev.Endpoint != nil {
			if ev.Endpoint.SourceIPv6 != "" || ev.Endpoint.DestinationIPv6 != "" {
				return fmt.Errorf("pcep: event %d: IPv6 endpoint in IPv4 profile", i)
			}
		}
		if cfg.Profile == "pcep_rfc5440_ipv6" && ev.Endpoint != nil {
			if ev.Endpoint.SourceIPv4 != "" || ev.Endpoint.DestinationIPv4 != "" {
				return fmt.Errorf("pcep: event %d: IPv4 endpoint in IPv6 profile", i)
			}
		}
	}

	return nil
}
