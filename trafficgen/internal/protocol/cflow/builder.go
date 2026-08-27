package cflow

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// cflow wire format constants.
const (
	v9HdrLen            = 20
	ipfixHdrLen         = 16
	setHdrLen           = 4
	templateHdrLen      = 4 // TemplateID(2) + FieldCount(2)
	ipfixTemplateHdrLen = 4 // TemplateID(2) + FieldCount(2)
	ipfixOptionsHdrLen  = 4 // TemplateID(2) + ScopeFieldCount(2) + OptionFieldCount(2)
	enterpriseExtLen    = 4 // PEN(4) appended after standard 4-byte descriptor
)

// v9InfoElement maps known element IDs to their field name for record encoding.
type v9InfoElement struct {
	ID     uint16
	Length uint16
	Name   string
}

// buildV9Header builds a NetFlow v9 Export Packet header (20 bytes).
func buildV9Header(count, sysUptime, unixSecs, sequence, sourceID uint32) []byte {
	buf := make([]byte, v9HdrLen)
	binary.BigEndian.PutUint16(buf[0:2], 9)             // Version
	binary.BigEndian.PutUint16(buf[2:4], uint16(count)) // Count
	binary.BigEndian.PutUint32(buf[4:8], sysUptime)
	binary.BigEndian.PutUint32(buf[8:12], unixSecs)
	binary.BigEndian.PutUint32(buf[12:16], sequence)
	binary.BigEndian.PutUint32(buf[16:20], sourceID)
	return buf
}

// buildIPFIXHeader builds an IPFIX Message header (16 bytes).
func buildIPFIXHeader(length uint16, exportTime, sequence, odID uint32) []byte {
	buf := make([]byte, ipfixHdrLen)
	binary.BigEndian.PutUint16(buf[0:2], 10) // Version
	binary.BigEndian.PutUint16(buf[2:4], length)
	binary.BigEndian.PutUint32(buf[4:8], exportTime)
	binary.BigEndian.PutUint32(buf[8:12], sequence)
	binary.BigEndian.PutUint32(buf[12:16], odID)
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

// buildSetHeader builds a FlowSet/Set header: ID(2) + Length(2).
func buildSetHeader(id, length uint16) []byte {
	buf := make([]byte, setHdrLen)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], length)
	return buf
}

// encodeRecordField encodes a single record field value based on element ID and length.
func encodeRecordField(elementID, length uint16, val interface{}, isIPv6 bool) ([]byte, error) {
	switch elementID {
	case 1, 2: // IN_BYTES, IN_PKTS (uint32 counters)
		v, _ := toUint64(val)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b, nil
	case 4: // PROTOCOL (uint8, but field length is 1)
		v, _ := toUint64(val)
		return []byte{byte(v)}, nil
	case 7, 11: // L4_SRC_PORT, L4_DST_PORT (uint16)
		v, _ := toUint64(val)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		return b, nil
	case 8: // IPV4_SRC_ADDR (4 bytes)
		if isIPv6 {
			// IPv6 address: 16 bytes
			ip := net.ParseIP(fmt.Sprint(val))
			if ip == nil || ip.To16() == nil {
				return nil, fmt.Errorf("invalid IPv6 address: %v", val)
			}
			return ip.To16(), nil
		}
		ip := net.ParseIP(fmt.Sprint(val))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %v", val)
		}
		return ip.To4(), nil
	case 12: // IPV4_DST_ADDR (4 bytes)
		if isIPv6 {
			ip := net.ParseIP(fmt.Sprint(val))
			if ip == nil || ip.To16() == nil {
				return nil, fmt.Errorf("invalid IPv6 address: %v", val)
			}
			return ip.To16(), nil
		}
		ip := net.ParseIP(fmt.Sprint(val))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %v", val)
		}
		return ip.To4(), nil
	case 9, 13: // SRC_MASK, DST_MASK (uint8)
		v, _ := toUint64(val)
		return []byte{byte(v)}, nil
	case 21, 22: // LAST_SWITCHED, FIRST_SWITCHED (uint32 milliseconds)
		v, _ := toUint64(val)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b, nil
	case 27: // IPV6_SRC_ADDR (16 bytes)
		ip := net.ParseIP(fmt.Sprint(val))
		if ip == nil || ip.To16() == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %v", val)
		}
		return ip.To16(), nil
	case 28: // IPV6_DST_ADDR (16 bytes)
		ip := net.ParseIP(fmt.Sprint(val))
		if ip == nil || ip.To16() == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %v", val)
		}
		return ip.To16(), nil
	case 152, 153: // flowStartMilliseconds, flowEndMilliseconds (uint64)
		v, _ := toUint64(val)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
	case 34: // samplingInterval (uint16)
		v, _ := toUint64(val)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		return b, nil
	case 138: // observationPointId (uint64)
		v, _ := toUint64(val)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
	default:
		// Enterprise IE or unknown: encode as raw bytes
		// Try to handle enterprise_private_entry as hex string
		if s, ok := val.(string); ok {
			// If it looks like hex, decode
			if len(s) > 0 && len(s)%2 == 0 && isHex(s) {
				b := make([]byte, len(s)/2)
				for i := 0; i < len(b); i++ {
					fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
				}
				return b, nil
			}
			return []byte(s), nil
		}
		// Fallback: try numeric
		v, _ := toUint64(val)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		if length < 8 {
			return b[:length], nil
		}
		return b, nil
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func toUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		return uint64(n), true
	case uint64:
		return n, true
	case uint32:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint8:
		return uint64(n), true
	case int:
		return uint64(n), true
	case int64:
		return uint64(n), true
	case json.Number:
		if u, err := strconv.ParseUint(string(n), 10, 64); err == nil {
			return u, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// BuildV9ExportPacket builds a complete NetFlow v9 Export Packet.
func BuildV9ExportPacket(cfg *core.CFlowConfig) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cflow: config is required")
	}
	// Validate templates
	for _, tmpl := range cfg.Templates {
		if len(tmpl.Fields) == 0 {
			return nil, fmt.Errorf("cflow: template %d has no fields", tmpl.TemplateID)
		}
	}

	var flowSets [][]byte

	// Template FlowSet (ID=0)
	if len(cfg.Templates) > 0 {
		templateBody := buildV9TemplateSet(cfg.Templates)
		flowSets = append(flowSets, templateBody)
	}

	// Data FlowSets — one per unique template ID
	seenTmpl := make(map[uint16]bool)
	for _, rec := range cfg.Records {
		if seenTmpl[rec.TemplateID] {
			continue
		}
		seenTmpl[rec.TemplateID] = true
		tmpl := findTemplate(cfg.Templates, rec.TemplateID)
		if tmpl == nil {
			return nil, fmt.Errorf("cflow: record references unknown template %d", rec.TemplateID)
		}
		dataBody, err := buildV9DataFlowSet(tmpl, rec, cfg.Records)
		if err != nil {
			return nil, err
		}
		flowSets = append(flowSets, dataBody)
	}

	// Handle options/sampling metadata
	if cfg.Options != nil {
		optBody := buildV9OptionsSet(cfg.Options)
		if optBody != nil {
			flowSets = append(flowSets, optBody)
		}
	}

	// Count = templates + data records + options template + options data (per RFC 3954 §7)
	recordCount := uint32(len(cfg.Templates) + len(cfg.Records))
	if cfg.Options != nil && buildV9OptionsSet(cfg.Options) != nil {
		recordCount += 2 // options template record + options data record
	}
	if recordCount == 0 {
		recordCount = 1
	}

	// Assemble: header + flow sets
	now := uint32(time.Now().Unix())
	sysUptime := cfg.SysUptime
	if sysUptime == 0 {
		sysUptime = 600
	}
	unixSecs := cfg.UnixSecs
	if unixSecs == 0 {
		unixSecs = now
	}
	sequence := cfg.Sequence
	sourceID := cfg.SourceID

	header := buildV9Header(recordCount, sysUptime, unixSecs, sequence, sourceID)

	var body []byte
	for _, fs := range flowSets {
		body = append(body, fs...)
	}

	return append(header, body...), nil
}

// buildV9TemplateSet builds a v9 Template FlowSet (ID=0).
func buildV9TemplateSet(templates []core.CFlowTemplate) []byte {
	var body []byte
	for _, tmpl := range templates {
		tid := tmpl.TemplateID
		fc := uint16(len(tmpl.Fields))
		// TemplateRecord: TemplateID(2) + FieldCount(2) + [FieldType(2) + FieldLength(2)]*
		tRec := make([]byte, 4+4*uint16(len(tmpl.Fields)))
		binary.BigEndian.PutUint16(tRec[0:2], tid)
		binary.BigEndian.PutUint16(tRec[2:4], fc)
		for j, f := range tmpl.Fields {
			binary.BigEndian.PutUint16(tRec[4+4*j:4+4*j+2], f.ElementID)
			binary.BigEndian.PutUint16(tRec[4+4*j+2:4+4*j+4], f.Length)
		}
		body = append(body, tRec...)
	}
	body = pad4(body)
	fsLen := uint16(setHdrLen + len(body))
	hdr := buildSetHeader(0, fsLen)
	return append(hdr, body...)
}

// buildV9DataFlowSet builds a v9 Data FlowSet.
func buildV9DataFlowSet(tmpl *core.CFlowTemplate, firstRec core.CFlowRecord, allRecords []core.CFlowRecord) ([]byte, error) {
	var body []byte
	for _, rec := range allRecords {
		if rec.TemplateID != tmpl.TemplateID {
			continue
		}
		recBytes, err := encodeV9Record(tmpl.Fields, rec.Record)
		if err != nil {
			return nil, err
		}
		body = append(body, recBytes...)
	}
	body = pad4(body)
	fsLen := uint16(setHdrLen + len(body))
	hdr := buildSetHeader(tmpl.TemplateID, fsLen)
	return append(hdr, body...), nil
}

// encodeV9Record encodes a record's fields in template order.
func encodeV9Record(fields []core.CFlowField, record map[string]interface{}) ([]byte, error) {
	// Map field names to element IDs
	fieldMap := map[string]uint16{
		"srcaddr": 8, "dstaddr": 12, "srcaddrv6": 27, "dstaddrv6": 28,
		"srcport": 7, "dstport": 11, "protocol": 4,
		"packets": 2, "octets": 1,
		"timestart": 22, "timeend": 21,
		"src_mask": 9, "dst_mask": 13,
		"enterprise_private_entry":    32769,
		"enterprise_private_entry_2":  32770,
		"sourceIPv4Address":        8, "destinationIPv4Address": 12,
		"sourceIPv6Address": 27, "destinationIPv6Address": 28,
		"sourceTransportPort": 7, "destinationTransportPort": 11,
		"protocolIdentifier": 4,
		"packetDeltaCount":   2, "octetDeltaCount": 1,
		"flowStartMilliseconds": 152, "flowEndMilliseconds": 153,
		"samplingInterval": 34, "observationPointId": 138,
	}

	var data []byte
	for _, f := range fields {
		// Find the value from the record
		val := findRecordValue(f.ElementID, record, fieldMap)
		if val == nil {
			// Zero-fill
			val = uint64(0)
		}
		isIPv6 := f.ElementID == 27 || f.ElementID == 28
		b, err := encodeRecordField(f.ElementID, f.Length, val, isIPv6)
		if err != nil {
			return nil, fmt.Errorf("encoding field %d: %w", f.ElementID, err)
		}
		// Handle variable-length (length=65535) with 1-byte prefix
		if f.Length == 65535 {
			// Variable-length IE: 1-byte length prefix + value
			vl := len(b)
			if vl > 255 {
				// 3-byte length prefix: 0xFF + 2-byte length
				prefix := make([]byte, 3)
				prefix[0] = 0xFF
				binary.BigEndian.PutUint16(prefix[1:3], uint16(vl))
				data = append(data, prefix...)
			} else {
				data = append(data, byte(vl))
			}
			data = append(data, b...)
		} else {
			data = append(data, b...)
		}
	}
	return data, nil
}

// findRecordValue looks up the value for a given element ID from the record.
func findRecordValue(elementID uint16, record map[string]interface{}, fieldMap map[string]uint16) interface{} {
	// Reverse lookup: find which field name maps to this element ID
	for name, id := range fieldMap {
		if id == elementID {
			if v, ok := record[name]; ok {
				return v
			}
		}
	}
	return nil
}

// findTemplate finds a template by ID.
func findTemplate(templates []core.CFlowTemplate, id uint16) *core.CFlowTemplate {
	for i := range templates {
		if templates[i].TemplateID == id {
			return &templates[i]
		}
	}
	return nil
}

// buildV9OptionsSet builds v9 Options Template FlowSet (ID=1) + Options Data FlowSet
// for timeout/sampling metadata (RFC 3954 §3.2).
func buildV9OptionsSet(opts *core.CFlowOptions) []byte {
	if opts == nil {
		return nil
	}
	// Collect option fields with values
	type optField struct {
		id  uint16
		val uint16
	}
	var fields []optField
	if opts.ActiveTimeout > 0 {
		fields = append(fields, optField{161, opts.ActiveTimeout})
	}
	if opts.InactiveTimeout > 0 {
		fields = append(fields, optField{162, opts.InactiveTimeout})
	}
	if opts.SamplingInterval > 0 {
		fields = append(fields, optField{34, opts.SamplingInterval})
	}
	if len(fields) == 0 {
		return nil
	}

	const tplID = uint16(256) // options template ID

	// Options Template Record: TemplateID(2) + OptionScopeLength(2) + OptionLength(2)
	// OptionScopeLength = total bytes of scope field VALUES in the data record (0 = no scope)
	// OptionLength = total bytes of option field descriptors in the template record
	optScopeLen := uint16(0)              // no scope fields (system-wide)
	optLen := uint16(len(fields) * 4)     // each descriptor is 4 bytes (FieldType+FieldLength)
	tRec := make([]byte, 6+len(fields)*4)
	binary.BigEndian.PutUint16(tRec[0:2], tplID)
	binary.BigEndian.PutUint16(tRec[2:4], optScopeLen)
	binary.BigEndian.PutUint16(tRec[4:6], optLen)
	for i, f := range fields {
		binary.BigEndian.PutUint16(tRec[6+i*4:6+i*4+2], f.id)
		binary.BigEndian.PutUint16(tRec[6+i*4+2:6+i*4+4], 2) // each field is 2 bytes
	}
	tRec = pad4(tRec)
	tmplSetLen := uint16(setHdrLen + len(tRec))
	tmplHdr := buildSetHeader(1, tmplSetLen) // FlowSet ID=1 = Options Template

	// Options Data FlowSet
	var data []byte
	for _, f := range fields {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, f.val)
		data = append(data, b...)
	}
	data = pad4(data)
	dataSetLen := uint16(setHdrLen + len(data))
	dataHdr := buildSetHeader(tplID, dataSetLen)

	body := append(tmplHdr, tRec...)
	body = append(body, dataHdr...)
	body = append(body, data...)
	return body
}

// BuildIPFIXMessage builds a complete IPFIX Message.
func BuildIPFIXMessage(cfg *core.CFlowConfig) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cflow: config is required")
	}

	// Validate templates
	for _, tmpl := range cfg.Templates {
		if len(tmpl.Fields) == 0 && tmpl.Kind != "options" {
			return nil, fmt.Errorf("cflow: template %d has no fields", tmpl.TemplateID)
		}
	}

	var sets [][]byte

	// Template Set (ID=2) or Options Template Set (ID=3)
	for _, tmpl := range cfg.Templates {
		var setBody []byte
		if tmpl.Kind == "options" {
			setBody = buildIPFIXOptionsTemplateSet(tmpl)
		} else {
			setBody = buildIPFIXTemplateSet(tmpl)
		}
		sets = append(sets, setBody)
	}

	// Data Sets
	for _, rec := range cfg.Records {
		tmpl := findTemplate(cfg.Templates, rec.TemplateID)
		if tmpl == nil {
			return nil, fmt.Errorf("cflow: record references unknown template %d", rec.TemplateID)
		}
		dataBody, err := buildIPFIXDataSet(tmpl, cfg.Records)
		if err != nil {
			return nil, err
		}
		sets = append(sets, dataBody)
		break // one data set per message
	}

	// Options data (timeout/sampling)
	if cfg.Options != nil {
		optBody := buildIPFIXOptionsData(cfg.Templates, cfg.Options)
		if optBody != nil {
			sets = append(sets, optBody)
		}
	}

	// Assemble
	now := uint32(time.Now().Unix())
	exportTime := cfg.ExportTime
	if exportTime == 0 {
		exportTime = now
	}
	sequence := cfg.Sequence
	odID := cfg.ObservationDomainID

	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	totalLen := uint16(ipfixHdrLen + len(body))

	header := buildIPFIXHeader(totalLen, exportTime, sequence, odID)
	return append(header, body...), nil
}

// buildIPFIXTemplateSet builds an IPFIX Template Set (Set ID=2).
func buildIPFIXTemplateSet(tmpl core.CFlowTemplate) []byte {
	// TemplateRecord: TemplateID(2) + FieldCount(2) + [IE_ID(2) + FieldLength(2)]*
	nFields := len(tmpl.Fields)
	// Enterprise IE uses 4 extra bytes per field
	extraLen := 0
	for _, f := range tmpl.Fields {
		if f.ElementID&0x8000 != 0 {
			extraLen += 4 // PEN
		}
	}
	recLen := 4 + nFields*4 + extraLen
	tRec := make([]byte, recLen)
	binary.BigEndian.PutUint16(tRec[0:2], tmpl.TemplateID)
	binary.BigEndian.PutUint16(tRec[2:4], uint16(nFields))
	pos := 4
	for _, f := range tmpl.Fields {
		id := f.ElementID
		if f.PEN > 0 {
			id |= 0x8000 // enterprise bit
		}
		binary.BigEndian.PutUint16(tRec[pos:pos+2], id)
		binary.BigEndian.PutUint16(tRec[pos+2:pos+4], f.Length)
		pos += 4
		if f.PEN > 0 {
			binary.BigEndian.PutUint32(tRec[pos:pos+4], f.PEN)
			pos += 4
		}
	}

	// Pad to 4-byte boundary
	tRec = pad4(tRec)
	setLen := uint16(setHdrLen + len(tRec))
	hdr := buildSetHeader(2, setLen)
	return append(hdr, tRec...)
}

// buildIPFIXOptionsTemplateSet builds an IPFIX Options Template Set (Set ID=3).
// Per RFC 7011 §3.4.2.2: TemplateID(2) + FieldCount(2) + ScopeFieldCount(2)
// + scope descriptors + option (non-scope) descriptors.
func buildIPFIXOptionsTemplateSet(tmpl core.CFlowTemplate) []byte {
	nScope := len(tmpl.ScopeFields)
	nOption := len(tmpl.OptionFields)
	nTotal := nScope + nOption
	// Header: TemplateID(2) + FieldCount(2) + ScopeFieldCount(2)
	// + ScopeDescriptors[nScope] + OptionDescriptors[nOption]
	recLen := 6 + nScope*4 + nOption*4
	tRec := make([]byte, recLen)
	binary.BigEndian.PutUint16(tRec[0:2], tmpl.TemplateID)
	binary.BigEndian.PutUint16(tRec[2:4], uint16(nTotal)) // total field count
	binary.BigEndian.PutUint16(tRec[4:6], uint16(nScope)) // scope field count
	pos := 6
	for _, f := range tmpl.ScopeFields {
		binary.BigEndian.PutUint16(tRec[pos:pos+2], f.ElementID)
		binary.BigEndian.PutUint16(tRec[pos+2:pos+4], f.Length)
		pos += 4
	}
	for _, f := range tmpl.OptionFields {
		binary.BigEndian.PutUint16(tRec[pos:pos+2], f.ElementID)
		binary.BigEndian.PutUint16(tRec[pos+2:pos+4], f.Length)
		pos += 4
	}

	tRec = pad4(tRec)
	setLen := uint16(setHdrLen + len(tRec))
	hdr := buildSetHeader(3, setLen)
	return append(hdr, tRec...)
}

// buildIPFIXDataSet builds an IPFIX Data Set (Set ID = template ID).
func buildIPFIXDataSet(tmpl *core.CFlowTemplate, allRecords []core.CFlowRecord) ([]byte, error) {
	var body []byte
	for _, rec := range allRecords {
		if rec.TemplateID != tmpl.TemplateID {
			continue
		}
		recBytes, err := encodeV9Record(tmpl.Fields, rec.Record)
		if err != nil {
			return nil, err
		}
		body = append(body, recBytes...)
	}
	body = pad4(body)
	setLen := uint16(setHdrLen + len(body))
	hdr := buildSetHeader(tmpl.TemplateID, setLen)
	return append(hdr, body...), nil
}

// buildIPFIXOptionsData builds IPFIX Options data (timeout/sampling).
func buildIPFIXOptionsData(templates []core.CFlowTemplate, opts *core.CFlowOptions) []byte {
	// Find an options template
	var tmpl *core.CFlowTemplate
	for i := range templates {
		if templates[i].Kind == "options" {
			tmpl = &templates[i]
			break
		}
	}
	if tmpl == nil {
		return nil
	}

	// Encode scope + option values
	var body []byte
	// Scope fields (observationPointId = 138, 8 bytes)
	for _, f := range tmpl.ScopeFields {
		b := make([]byte, f.Length)
		// Zero-filled scope
		body = append(body, b...)
	}
	// Option fields
	for _, f := range tmpl.OptionFields {
		var val uint64
		switch f.ElementID {
		case 34: // samplingInterval
			val = uint64(opts.SamplingInterval)
		case 161: // activeTimeout (not standard IPFIX, but used in v9)
			val = uint64(opts.ActiveTimeout)
		case 162: // inactiveTimeout
			val = uint64(opts.InactiveTimeout)
		}
		b := make([]byte, f.Length)
		if f.Length == 2 {
			binary.BigEndian.PutUint16(b, uint16(val))
		} else if f.Length == 4 {
			binary.BigEndian.PutUint32(b, uint32(val))
		} else if f.Length == 8 {
			binary.BigEndian.PutUint64(b, val)
		}
		body = append(body, b...)
	}

	body = pad4(body)
	setLen := uint16(setHdrLen + len(body))
	hdr := buildSetHeader(tmpl.TemplateID, setLen)
	return append(hdr, body...)
}

// BuildExportPacket builds a cflow export packet based on profile.
func BuildExportPacket(cfg *core.CFlowConfig) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cflow: config is required")
	}
	switch cfg.Profile {
	case "netflow_v9_rfc3954":
		// Handle wire faults
		if cfg.WireFault != nil {
			switch cfg.WireFault.Kind {
			case "version":
				// Build with wrong version
				return buildV9ExportPacketVersion(cfg), nil
			case "length":
				return buildV9ExportPacketLength(cfg, cfg.WireFault.Value), nil
			case "checksum":
				return nil, fmt.Errorf("cflow: checksum fault is not a valid cflow field")
			}
		}
		return BuildV9ExportPacket(cfg)
	case "ipfix_rfc7011":
		if cfg.WireFault != nil {
			switch cfg.WireFault.Kind {
			case "version":
				return buildIPFIXMessageVersion(cfg), nil
			case "length":
				return buildIPFIXMessageLength(cfg, cfg.WireFault.Value), nil
			case "checksum":
				return nil, fmt.Errorf("cflow: checksum fault is not a valid cflow field")
			}
		}
		return BuildIPFIXMessage(cfg)
	default:
		return nil, fmt.Errorf("cflow: unknown profile %q", cfg.Profile)
	}
}

// buildV9ExportPacketVersion builds a v9 packet with wrong version.
func buildV9ExportPacketVersion(cfg *core.CFlowConfig) []byte {
	// Use a different version field
	ver := uint16(8)
	if cfg.Version != 0 {
		ver = cfg.Version
	}
	buf := make([]byte, v9HdrLen)
	binary.BigEndian.PutUint16(buf[0:2], ver)
	return buf
}

// buildV9ExportPacketLength builds a v9 packet with wrong count.
func buildV9ExportPacketLength(cfg *core.CFlowConfig, declared uint16) []byte {
	// Build a normal packet but override the count
	body, _ := BuildV9ExportPacket(cfg)
	if body == nil {
		return nil
	}
	// Override count
	if declared > 0 {
		binary.BigEndian.PutUint16(body[2:4], declared)
	}
	return body
}

// buildIPFIXMessageVersion builds an IPFIX message with wrong version.
func buildIPFIXMessageVersion(cfg *core.CFlowConfig) []byte {
	ver := uint16(9)
	if cfg.Version != 0 {
		ver = cfg.Version
	}
	buf := make([]byte, ipfixHdrLen)
	binary.BigEndian.PutUint16(buf[0:2], ver)
	return buf
}

// buildIPFIXMessageLength builds an IPFIX message with wrong length.
func buildIPFIXMessageLength(cfg *core.CFlowConfig, declared uint16) []byte {
	body, _ := BuildIPFIXMessage(cfg)
	if body == nil {
		return nil
	}
	if declared > 0 {
		binary.BigEndian.PutUint16(body[2:4], declared)
	}
	return body
}

// ValidateConfig validates a cflow config.
func ValidateConfig(cfg *core.CFlowConfig) error {
	if cfg == nil {
		return fmt.Errorf("cflow: config is required")
	}
	switch cfg.Profile {
	case "netflow_v9_rfc3954", "ipfix_rfc7011":
		// valid
	default:
		return fmt.Errorf("cflow: unknown profile %q", cfg.Profile)
	}

	// Check wire faults — all wire fault kinds are rejected at validation
	// (design: wire_fault is negative-only, "拒绝注入").
	if cfg.WireFault != nil {
		switch cfg.WireFault.Kind {
		case "version":
			return fmt.Errorf("cflow: wire fault: version mismatch")
		case "length":
			return fmt.Errorf("cflow: wire fault: invalid length")
		case "field_count":
			return fmt.Errorf("cflow: wire fault: field count mismatch")
		case "template":
			if len(cfg.Sets) == 0 {
				return fmt.Errorf("cflow: wire fault: template not found")
			}
			return fmt.Errorf("cflow: wire fault: template not found")
		case "address_family":
			return fmt.Errorf("cflow: wire fault: address family mismatch")
		case "checksum":
			return fmt.Errorf("cflow: checksum fault is not a valid cflow field")
		default:
			return fmt.Errorf("cflow: unknown wire fault kind %q", cfg.WireFault.Kind)
		}
	}

	// Check version vs profile consistency
	if cfg.Version != 0 {
		switch cfg.Profile {
		case "netflow_v9_rfc3954":
			if cfg.Version != 9 {
				return fmt.Errorf("cflow: profile %q expects version 9, got %d", cfg.Profile, cfg.Version)
			}
		case "ipfix_rfc7011":
			if cfg.Version != 10 {
				return fmt.Errorf("cflow: profile %q expects version 10, got %d", cfg.Profile, cfg.Version)
			}
		}
	}

	// Check templates
	for _, tmpl := range cfg.Templates {
		if tmpl.Kind != "options" && len(tmpl.Fields) == 0 {
			return fmt.Errorf("cflow: template %d has no fields", tmpl.TemplateID)
		}
	}

	// Check records reference existing templates
	for _, rec := range cfg.Records {
		tmpl := findTemplate(cfg.Templates, rec.TemplateID)
		if tmpl == nil {
			return fmt.Errorf("cflow: record references unknown template %d", rec.TemplateID)
		}
	}

	// Data via raw sets (without templates) is rejected
	if len(cfg.Sets) > 0 && len(cfg.Templates) == 0 {
		return fmt.Errorf("cflow: data set without template")
	}

	// Check address family: template with IPv4 fields but record has IPv6 values (or vice versa)
	for _, rec := range cfg.Records {
		tmpl := findTemplate(cfg.Templates, rec.TemplateID)
		if tmpl == nil {
			continue
		}
		for _, f := range tmpl.Fields {
			if f.ElementID == 8 { // IPV4_SRC_ADDR
				if _, ok := rec.Record["srcaddrv6"]; ok {
					return fmt.Errorf("cflow: address family mismatch: IPv4 template with IPv6 record")
				}
			}
			if f.ElementID == 27 { // IPV6_SRC_ADDR
				if _, ok := rec.Record["srcaddr"]; ok {
					return fmt.Errorf("cflow: address family mismatch: IPv6 template with IPv4 record")
				}
			}
		}
	}

	return nil
}

// CheckFault checks for wire fault injection.
func CheckFault(kind string) error {
	switch kind {
	case "":
		return nil
	case "version", "length", "template", "field_count", "address_family", "udp", "checksum":
		return fmt.Errorf("cflow: wire fault: %s", kind)
	default:
		return fmt.Errorf("cflow: unknown wire fault: %s", kind)
	}
}
