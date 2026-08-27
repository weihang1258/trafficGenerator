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

// Object classes.
const (
	objOpen     uint8 = 1
	objRP       uint8 = 2
	objEndpoint uint8 = 4
	objNotif    uint8 = 5
	objMetric   uint8 = 6
	objERO      uint8 = 7
	objRRO      uint8 = 8
	objLSPA     uint8 = 9
	objError    uint8 = 10
	objLSP      uint8 = 21
	objSRP      uint8 = 24
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
// Byte 1: OT(2 bits, MSB) | R(1) | P(1) | I(1) | R(3)
func buildObjectHeader(objClass, objType uint8, pFlag, iFlag bool, bodyLen uint16) []byte {
	// Round body to 4-byte alignment
	aligned := bodyLen
	if pad := aligned % 4; pad != 0 {
		aligned += 4 - pad
	}
	totalLen := objHdrLen + aligned

	b1 := (objType & 0x03) << 6 // OT in bits 0-1 (MSB)
	if pFlag {
		b1 |= 0x10 // P flag in bit 3
	}
	if iFlag {
		b1 |= 0x08 // I flag in bit 4
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
	// Fixed body: Ver|Flags(1) + Keepalive(1) + DeadTimer(1) + SID(4) = 7 bytes
	body := make([]byte, 0, 7)
	body = append(body, 0x10) // Ver=1 << 4 | Flags=0 → 0x10
	body = append(body, keepalive)
	body = append(body, deadtime)
	sidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sidBytes, uint32(sid))
	body = append(body, sidBytes...)

	// Append capability TLVs
	for _, cap := range capabilities {
		switch cap.Kind {
		case "stateful_pce":
			// RFC 8231 §5.1: Stateful-PCE-Capability TLV (type 16), 4-byte flags.
			flags := make([]byte, 4)
			if cap.LSPUpdate {
				flags[0] |= 0x80 // U bit (LSR): LSP-UPDATE-CAPABILITY
			}
			body = append(body, buildTLV(tlvStatefulPCE, flags)...)
			// RFC 8231 §5.2: When include_db_version is set, emit TLV 17 (Sync)
			// alongside TLV 16 as a single capability entry.
			if cap.IncludeDBVersion {
				syncFlags := make([]byte, 4)
				syncFlags[0] |= 0x80 // D bit: Include-DB-Version
				body = append(body, buildTLV(tvlSyncCap, syncFlags)...)
			}
		case "sync":
			// RFC 8231 §5.2: Stateful-PCE-Capability (Sync) TLV (type 17), 4-byte flags.
			flags := make([]byte, 4)
			if cap.IncludeDBVersion {
				flags[0] |= 0x80 // D bit: Include-DB-Version
			}
			body = append(body, buildTLV(tvlSyncCap, flags)...)
		}
	}

	body = pad4(body)
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
func BuildPCNtfMsg(ntype, nvalue uint16) []byte {
	// Notification object body: Flags(1) + Reserved(1) + Type(2) + Value(4)
	body := make([]byte, 8)
	body[2] = byte(ntype >> 8)
	body[3] = byte(ntype)
	binary.BigEndian.PutUint32(body[4:8], uint32(nvalue))
	obj := buildObjectHeader(objNotif, 1, false, false, 8)
	obj = append(obj, body...)
	msg := buildCommonHeader(msgPCNtf, uint16(hdrLen+len(obj)))
	return append(msg, obj...)
}

// BuildPCErrMsg builds a PCErr message.
func BuildPCErrMsg(etype, evalue uint16) []byte {
	// PCEP-ERROR object body: Reserved(2) + Error-Type(2) + Error-Value(4) = 8 bytes
	body := make([]byte, 8)
	binary.BigEndian.PutUint16(body[2:4], etype)
	binary.BigEndian.PutUint32(body[4:8], uint32(evalue))
	obj := buildObjectHeader(objError, 1, false, false, 8)
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
func BuildRPObject(requestID uint32, pFlag, iFlag bool) []byte {
	// RP body: Flags(1) + Reserved(1) + Request-ID(4) + Reserved(4) + Reserved(2) = 12 bytes
	body := make([]byte, 12)
	if pFlag {
		body[0] |= 0x80 // P flag in bit 0 (MSB)
	}
	if iFlag {
		body[0] |= 0x40 // I flag in bit 1
	}
	binary.BigEndian.PutUint32(body[2:6], requestID)
	obj := buildObjectHeader(objRP, 1, pFlag, iFlag, 12)
	obj = append(obj, body...)
	// Recompute total length with aligned body
	totalLen := objHdrLen + 12 // 12 is already 4-byte aligned
	binary.BigEndian.PutUint16(obj[2:4], uint16(totalLen))
	return obj
}

// BuildEndpointObjectIPv4 builds an IPv4 END-POINT object.
func BuildEndpointObjectIPv4(src, dst string) []byte {
	// Body: Source(4) + Destination(4) + Reserved(4) = 12 bytes
	body := make([]byte, 12)
	if s := net.ParseIP(src).To4(); s != nil {
		copy(body[0:4], s)
	}
	if d := net.ParseIP(dst).To4(); d != nil {
		copy(body[4:8], d)
	}
	obj := buildObjectHeader(objEndpoint, 1, false, false, 12)
	obj = append(obj, body...)
	return obj
}

// BuildEndpointObjectIPv6 builds an IPv6 END-POINT object.
func BuildEndpointObjectIPv6(src, dst string) []byte {
	// Body: Source(16) + Destination(16) + Reserved(4) = 36 bytes
	body := make([]byte, 36)
	if s := net.ParseIP(src).To16(); s != nil {
		copy(body[0:16], s)
	}
	if d := net.ParseIP(dst).To16(); d != nil {
		copy(body[16:32], d)
	}
	obj := buildObjectHeader(objEndpoint, 2, false, false, 36)
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
		// IPv4 subobject: Type(1) + Length(1) + Addr(4) + PrefixLen(1) + Attrib(1) = 8 bytes
		buf := make([]byte, 8)
		buf[0] = 1 // IPv4 subobject type
		buf[1] = 8 // Length
		if a := net.ParseIP(sub.Address).To4(); a != nil {
			copy(buf[2:6], a)
		}
		buf[6] = sub.PrefixLength
		if sub.L {
			buf[7] |= 0x80 // L flag in bit 0 (MSB) of attributes
		}
		return buf
	case "ipv6":
		// IPv6 subobject: Type(1) + Length(1) + Addr(16) + PrefixLen(1) + Attrib(1) = 20 bytes
		buf := make([]byte, 20)
		buf[0] = 2  // IPv6 subobject type
		buf[1] = 20 // Length
		if a := net.ParseIP(sub.Address).To16(); a != nil {
			copy(buf[2:18], a)
		}
		buf[18] = sub.PrefixLength
		if sub.L {
			buf[19] |= 0x80 // L flag in bit 0 (MSB) of attributes
		}
		return buf
	default:
		return nil
	}
}

// BuildMetricObject builds a Metric object.
func BuildMetricObject(mtype uint8, cFlag, bFlag bool, value float64) []byte {
	// Metric body: Flags(1) + Reserved(1) + Metric-Type(2) + Value(4 = IEEE float) = 8 bytes
	body := make([]byte, 8)
	if cFlag {
		body[0] |= 0x80 // C flag in bit 0 (MSB)
	}
	if bFlag {
		body[0] |= 0x40 // B flag in bit 1
	}
	binary.BigEndian.PutUint16(body[2:4], uint16(mtype))
	binary.BigEndian.PutUint32(body[4:8], math.Float32bits(float32(value)))
	obj := buildObjectHeader(objMetric, 1, false, false, 8)
	obj = append(obj, body...)
	return obj
}

// BuildLSPObject builds an LSP object (RFC 8231).
func BuildLSPObject(plspID uint32, flags map[string]bool) []byte {
	// LSP body: PLSP-ID(4 bytes, lower 20 bits) + Reserved(4) + Flags(4) = 12 bytes
	body := make([]byte, 12)
	// PLSP-ID in lower 20 bits of first 4 bytes
	binary.BigEndian.PutUint32(body[0:4], plspID&0x000FFFFF)
	// Flags in bytes 8-11
	f := body[8:]
	if flags["delegate"] {
		f[0] |= 0x80 // bit 0 (MSB)
	}
	if flags["remove"] {
		f[0] |= 0x40 // bit 1
	}
	if flags["administrative"] {
		f[0] |= 0x20 // bit 2
	}
	if flags["sync"] {
		f[0] |= 0x10 // bit 3
	}
	if flags["create"] {
		f[0] |= 0x08 // bit 4
	}
	obj := buildObjectHeader(objLSP, 1, false, false, 12)
	obj = append(obj, body...)
	return obj
}

// BuildSRPObject builds an SRP object (RFC 8231).
func BuildSRPObject(idNumber uint32, flags map[string]bool) []byte {
	// SRP body: SRP-ID(4) + Flags(4) = 8 bytes
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], idNumber)
	if flags["remove"] {
		body[4] |= 0x80 // bit 0 (MSB)
	}
	obj := buildObjectHeader(objSRP, 1, false, false, 8)
	obj = append(obj, body...)
	return obj
}

// BuildLSPAObject builds an LSPA object.
func BuildLSPAObject(lFlag bool, setupPriority, holdingPriority uint8) []byte {
	// LSPA body: Reserved(4) + Setup(1) + Holding(1) + Attributes(2) = 8 bytes
	body := make([]byte, 8)
	body[4] = setupPriority
	body[5] = holdingPriority
	if lFlag {
		body[7] |= 0x80 // L flag in bit 0 (MSB) of attributes
	}
	obj := buildObjectHeader(objLSPA, 1, false, false, 8)
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
