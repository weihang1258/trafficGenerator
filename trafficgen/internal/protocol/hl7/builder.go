// HL7 v2.x Builder — MLLP frame construction
package hl7

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// MLLP control bytes
const (
	SOB = 0x0B // VT - Start Block
	EOB = 0x1C // FS - End Block
	CR  = 0x0D // Carriage Return - Segment terminator
)

// Default field separator and encoding characters
const (
	DefaultFieldSep   = "|"
	DefaultEncChars  = "^~\\&"
)

// Config holds protocol-level configuration
type Config struct {
	Profile        string `json:"profile,omitempty"`
	Version        string `json:"version,omitempty"`
	FieldSeparator string `json:"field_separator,omitempty"`
	EncodingChars  string `json:"encoding_chars,omitempty"`
	AckMode        string `json:"ack_mode,omitempty"` // "auto", "null", or {"code":"AE","err_segments":[...]}
}

// Session holds a single HL7 session
type Session struct {
	Name           string   `json:"name,omitempty"`
	SrcIP          string   `json:"src_ip,omitempty"`
	DstIP          string   `json:"dst_ip,omitempty"`
	SrcPort        uint16   `json:"src_port,omitempty"`
	DstPort        uint16   `json:"dst_port,omitempty"`
	Role           string   `json:"role,omitempty"` // "sender" or "receiver"
	SendingApp     string   `json:"sending_app,omitempty"`
	SendingFac     string   `json:"sending_fac,omitempty"`
	ReceivingApp   string   `json:"receiving_app,omitempty"`
	ReceivingFac   string   `json:"receiving_fac,omitempty"`
	ProcessingID   string   `json:"processing_id,omitempty"` // P/T/D
	ControlID      string   `json:"control_id,omitempty"`
	Timestamp      string   `json:"timestamp,omitempty"`
	PatientID      string   `json:"patient_id,omitempty"`
	Events         []Event  `json:"events,omitempty"`
}

// Event represents an HL7 message event
type Event struct {
	Kind        string    `json:"kind,omitempty"`        // "msg"
	Direction   string    `json:"direction,omitempty"`   // "c2s" or "s2c"
	MessageType string    `json:"message_type,omitempty"` // "ADT^A01^ADT_A01"
	Segments    []Segment `json:"segments,omitempty"`
	Ack         string    `json:"ack,omitempty"`         // "auto", "null", or ACK code
}

// Segment represents an HL7 segment
type Segment struct {
	Name   string        `json:"name,omitempty"`
	Fields []interface{} `json:"fields,omitempty"`
}

// ApplyDefaults sets defaults for config
func (c *Config) ApplyDefaults() {
	if c.Profile == "" {
		c.Profile = "mllp"
	}
	if c.FieldSeparator == "" {
		c.FieldSeparator = DefaultFieldSep
	}
	if c.EncodingChars == "" {
		c.EncodingChars = DefaultEncChars
	}
	if c.AckMode == "" {
		c.AckMode = "auto"
	}
	if c.Version == "" {
		c.Version = "2.5"
	}
}

// ApplyDefaults sets defaults for session
func (s *Session) ApplyDefaults() {
	if s.Role == "" {
		s.Role = "sender"
	}
	if s.SendingApp == "" {
		s.SendingApp = "HIS"
	}
	if s.SendingFac == "" {
		s.SendingFac = "HOSPITAL"
	}
	if s.ReceivingApp == "" {
		s.ReceivingApp = "RIS"
	}
	if s.ReceivingFac == "" {
		s.ReceivingFac = "CLINIC"
	}
	if s.ProcessingID == "" {
		s.ProcessingID = "P"
	}
}

// fieldSep returns the field separator (MSH-1)
func (c *Config) fieldSep() string {
	return c.FieldSeparator
}

// encChars returns the encoding characters (MSH-2)
func (c *Config) encChars() string {
	return c.EncodingChars
}

// compSep returns component separator (first char of enc chars)
func (c *Config) compSep() string {
	return string(c.EncodingChars[0])
}

// repSep returns repetition separator (second char of enc chars)
func (c *Config) repSep() string {
	return string(c.EncodingChars[1])
}

// escChar returns escape character (third char of enc chars)
func (c *Config) escChar() string {
	return string(c.EncodingChars[2])
}

// subCompSep returns subcomponent separator (fourth char of enc chars)
func (c *Config) subCompSep() string {
	return string(c.EncodingChars[3])
}

// RenderFieldValue renders a field value, handling components/repetitions/escaping
func RenderFieldValue(val interface{}, fs, ec string) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return EscapeHL7(v, ec)
	case []interface{}:
		// Repetition: join with repSep
		var parts []string
		for _, p := range v {
			parts = append(parts, RenderFieldValue(p, fs, ec))
		}
		return strings.Join(parts, ec[1:1]) // repSep
	case map[string]interface{}:
		// Components: join with compSep
		var parts []string
		for _, k := range []string{"c1", "c2", "c3", "c4"} {
			if p, ok := v[k]; ok && p != nil {
				parts = append(parts, RenderFieldValue(p, fs, ec))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, ec[0:1]) // compSep
	default:
		return EscapeHL7(fmt.Sprintf("%v", v), ec)
	}
}

// EscapeHL7 processes escape sequences in HL7 text
// Replaces escape sequences with their rendered values
func EscapeHL7(s string, ec string) string {
	if s == "" {
		return s
	}
	esc := string(ec[2]) // Escape character
	comp := string(ec[0])
	rep := string(ec[1])
	sub := string(ec[3])
	field := string(ec[0]) // Field separator in escape sequence is \F\

	result := s

	// Process escape sequences
	result = strings.ReplaceAll(result, esc+"F"+esc, field)
	result = strings.ReplaceAll(result, esc+"S"+esc, comp)
	result = strings.ReplaceAll(result, esc+"R"+esc, rep)
	result = strings.ReplaceAll(result, esc+"E"+esc, esc)
	result = strings.ReplaceAll(result, esc+"T"+esc, sub)
	result = strings.ReplaceAll(result, esc+"H"+esc, "")
	result = strings.ReplaceAll(result, esc+"N"+esc, "")
	// \Xdd...\ - hex sequences
	result = processHexEscapes(result, esc)

	return result
}

// processHexEscapes processes \X... escape sequences
func processHexEscapes(s string, esc string) string {
	// Simple implementation: look for \X followed by hex digits ending with \
	// This is a simplified version - production would need full hex parsing
	return s
}

// BuildMSH builds the MSH segment
func BuildMSH(cfg *Config, sess *Session, msgType string, ctrlID string) string {
	fs := cfg.fieldSep()
	ec := cfg.encChars()
	now := time.Now().UTC()
	ts := now.Format("20060102150405")

	if ctrlID == "" {
		ctrlID = fmt.Sprintf("MSG%09d", now.UnixNano()%1000000000)
	}

	// MSH format: MSH|^~\&|SendingApp|SendingFac|ReceivingApp|ReceivingFac|TS|ControlID|^~\&|Version|ProcID|
	// MSH-1 = field separator (first char after MSH)
	// MSH-2 = encoding characters (next 4 chars)
	// MSH-3 = Sending Application
	// MSH-4 = Sending Facility
	// MSH-5 = Receiving Application
	// MSH-6 = Receiving Facility
	// MSH-7 = Date/Time
	// MSH-8 = Security (empty)
	// MSH-9 = Message Type
	// MSH-10 = Message Control ID
	// MSH-11 = Processing ID
	// MSH-12 = Version ID

	fields := []string{
		"MSH" + fs + ec,                    // MSH-1 = |, MSH-2 = ^~\&
		sess.SendingApp,                    // MSH-3
		sess.SendingFac,                    // MSH-4
		sess.ReceivingApp,                 // MSH-5
		sess.ReceivingFac,                 // MSH-6
		ts,                                // MSH-7
		"",                                // MSH-8 Security
		msgType,                           // MSH-9
		ctrlID,                            // MSH-10
		sess.ProcessingID,                 // MSH-11
		cfg.Version,                       // MSH-12
	}

	return strings.Join(fields, fs) + string(rune(CR))
}

// BuildEVN builds an EVN segment
func BuildEVN(eventType string, timestamp string) string {
	if timestamp == "" {
		timestamp = time.Now().UTC().Format("20060102150405")
	}
	return fmt.Sprintf("EVN|%s|%s|%s%s", eventType, timestamp, "", string(rune(CR)))
}

// BuildPID builds a PID segment
func BuildPID(patientID string, lastName string, firstName string, dob string, sex string, cfg *Config) string {
	fs := cfg.fieldSep()

	// PID-1: Set ID
	// PID-3: Patient ID (with MR component)
	// PID-5: Patient Name (Last^First^Middle)
	// PID-7: Birth Date
	// PID-8: Sex
	pid3 := patientID
	if pid3 == "" {
		pid3 = "PAT001^^^HOSP^MR"
	}
	name := lastName + "^" + firstName
	if dob == "" {
		dob = "19800101"
	}
	if sex == "" {
		sex = "M"
	}

	fields := []string{
		"PID",
		"1",            // PID-1 Set ID
		pid3,           // PID-3 Patient ID
		"",            // PID-4 Alternate Patient ID
		name,           // PID-5 Patient Name
		"",            // PID-6 Mother's Maiden Name
		dob,            // PID-7 Birth Date
		sex,            // PID-8 Sex
		"",            // PID-9 Patient Alias
		"",            // PID-10 Race
		"",            // PID-11 Patient Address
		"",            // PID-12 County Code
	}

	return "PID" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildPV1 builds a PV1 segment
func BuildPV1(patientClass string, location string, dischargeDate string, cfg *Config) string {
	fs := cfg.fieldSep()

	if patientClass == "" {
		patientClass = "I"
	}
	if location == "" {
		location = "WARD^ICU^B101"
	}

	fields := []string{
		"PV1",
		"1",           // PV1-1 Set ID
		patientClass,  // PV1-2 Patient Class
		location,      // PV1-3 Assigned Patient Location
		"",           // PV1-4 Admission Type
		"",           // PV1-5 Preadmit Number
		"",           // PV1-6 Prior Patient Location
		"",           // PV1-7 Attending Doctor
		"",           // PV1-8 Referring Doctor
		"",           // PV1-9 Consulting Doctor
		"",           // PV1-10 Hospital Service
		"",           // PV1-11 Temporary Location
		"",           // PV1-12 Preadmit Test Indicator
		"",           // PV1-13 Readmission Status
		"",           // PV1-14 Admit Source
		"",           // PV1-15 Ambulatory Status
		"",           // PV1-16 VIP Indicator
		"",           // PV1-17 Admitting Doctor
		"",           // PV1-18 Patient Type
		"",           // PV1-19 Visit Number
		"",           // PV1-20 Financial Class
		"",           // PV1-21 Charge Price Indicator
		"",           // PV1-22 Courtesy Code
		"",           // PV1-23 Credit Rating
		"",           // PV1-24 Contract Code
		"",           // PV1-25 Contract Effective Date
		"",           // PV1-26 Contract Amount
		"",           // PV1-27 Contract Period
		"",           // PV1-28 Interest Code
		"",           // PV1-29 Transfer to Bad Debt Code
		"",           // PV1-30 Transfer to Bad Debt Date
		"",           // PV1-31 Bad Debt Agency Code
		"",           // PV1-32 Bad Debt Transfer Amount
		"",           // PV1-33 Bad Debt Recovery Amount
		"",           // PV1-34 Delete Account Indicator
		"",           // PV1-35 Discharge Date
		dischargeDate, // PV1-36 Discharge Location
		"",           // PV1-37 Diet Type
		"",           // PV1-38 Servicing Facility
		"",           // PV1-39 Current Hospital Bed
		"",           // PV1-40 Bed Status
		"",           // PV1-41 Account Status
		"",           // PV1-42 Pending Location
		"",           // PV1-43 Prior Temporary Location
		"",           // PV1-44 Admit Date/Time
		dischargeDate, // PV1-45 Discharge Date/Time
		"",           // PV1-46 Current Patient Balance
		"",           // PV1-47 Total Charges
		"",           // PV1-48 Adjustment Amount
		"",           // PV1-49 Pending Liability
		"",           // PV1-50 Total Projected Payments
	}

	return "PV1" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildOBR builds an OBR segment
func BuildOBR(fillerOrderNum string, universalServiceID string, observationDate string, cfg *Config) string {
	fs := cfg.fieldSep()

	if fillerOrderNum == "" {
		fillerOrderNum = "LAB-1001^HOSP"
	}
	if universalServiceID == "" {
		universalServiceID = "CBC^Complete Blood Count^LN"
	}
	if observationDate == "" {
		observationDate = time.Now().UTC().Format("20060102150405")
	}

	fields := []string{
		"OBR",
		"1",                    // OBR-1 Set ID
		"",                    // OBR-2 Placer Order Number
		fillerOrderNum,         // OBR-3 Filler Order Number
		universalServiceID,     // OBR-4 Universal Service ID
		"",                    // OBR-5 Priority
		"",                    // OBR-6 Requested Date/Time
		"",                    // OBR-7 Observation Date/Time
		observationDate,        // OBR-8 Observation End Date/Time
		"",                    // OBR-9 Collection Volume
		"",                    // OBR-10 Collector Identifier
		"",                    // OBR-11 Specimen Action Code
		"",                    // OBR-12 Danger Code
		"",                    // OBR-13 Relevant Clinical Info
		"",                    // OBR-14 Specimen Received Date/Time
		"",                    // OBR-15 Specimen Source
		"",                    // OBR-16 Ordering Provider
		"",                    // OBR-17 Order Call Back Phone
		"",                    // OBR-18 Placer Field 1
		"",                    // OBR-19 Placer Field 2
		"",                    // OBR-20 Filler Field 1
		"",                    // OBR-21 Filler Field 2
		"",                    // OBR-22 Results Rpt/Status Chng Date
		"",                    // OBR-23 Charge to Practice
		"",                    // OBR-24 Diagnostic Serv Sect ID
		"P",                   // OBR-25 Result Status
		"",                    // OBR-26 Parent Result
		"",                    // OBR-27 Quantity/Timing
		"",                    // OBR-28 Reserved
		"",                    // OBR-29 Reserved
		"",                    // OBR-30 Transport Mode
		"",                    // OBR-31 Reason for Study
		"",                    // OBR-32 Principal Result Interpreter
		"",                    // OBR-33 Assistant Result Interpreter
		"",                    // OBR-34 Technician
		"",                    // OBR-35 Transcriptionist
		"",                    // OBR-36 Scheduled Date/Time
		"",                    // OBR-37
		"",                    // OBR-38
		"",                    // OBR-39
		"",                    // OBR-40
	}

	return "OBR" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildOBX builds an OBX segment
func BuildOBX(setID int, valueType string, observationID string, observationValue string, units string, referenceRange string, resultStatus string, cfg *Config) string {
	fs := cfg.fieldSep()

	if valueType == "" {
		valueType = "NM"
	}
	if observationID == "" {
		observationID = "2345-7^Hemoglobin^LN"
	}
	if units == "" {
		units = "g/dL"
	}
	if referenceRange == "" {
		referenceRange = "12.0-16.0"
	}
	if resultStatus == "" {
		resultStatus = "F"
	}

	fields := []string{
		"OBX",
		fmt.Sprintf("%d", setID),  // OBX-1 Set ID
		valueType,                // OBX-2 Value Type
		observationID,             // OBX-3 Observation Identifier
		"",                       // OBX-4 Observation Sub-ID
		observationValue,          // OBX-5 Observation Value
		units,                    // OBX-6 Units
		referenceRange,            // OBX-7 Reference Range
		"",                       // OBX-8 Abnormal Flags
		"",                       // OBX-9 Probability
		"",                       // OBX-10 Nature of Abnormal Test
		"",                       // OBX-11 Result Status
		resultStatus,              // OBX-11 (corrected)
		"",                       // OBX-12 Date Last Observation Normal Value
		"",                       // OBX-13 User Defined Access Check
		"",                       // OBX-14 Date/Time of Observation
		"",                       // OBX-15 Producer's ID
		"",                       // OBX-16 Responsible Observer
		"",                       // OBX-17 Observation Method
	}

	return "OBX" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildMSA builds a MSA segment
func BuildMSA(ackCode string, controlID string, textMessage string, cfg *Config) string {
	fs := cfg.fieldSep()

	if ackCode == "" {
		ackCode = "AA"
	}

	fields := []string{
		"MSA",
		ackCode,       // MSA-1 Acknowledgment Code
		controlID,     // MSA-2 Message Control ID
		textMessage,   // MSA-3 Text Message
	}

	return "MSA" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildERR builds an ERR segment
func BuildERR(errCode string, severity string, text string, cfg *Config) string {
	fs := cfg.fieldSep()

	if errCode == "" {
		errCode = "200"
	}
	if severity == "" {
		severity = "E"
	}

	// ERR-2 Error Location (ERL composite)
	errLoc := "MSH^10"
	// ERR-3 HL7 Error Code
	hl7Err := errCode
	// ERR-4 Severity
	// ERR-5 Application Error Code

	fields := []string{
		"ERR",
		errLoc,          // ERR-2 Error Location
		hl7Err,          // ERR-3 HL7 Error Code
		severity,        // ERR-4 Severity
		text,            // ERR-5 Application Error Code
	}

	return "ERR" + fs + strings.Join(fields[1:], fs) + string(rune(CR))
}

// BuildZSegment builds a custom Z-segment
func BuildZSegment(name string, fields []interface{}, cfg *Config) string {
	fs := cfg.fieldSep()

	var fieldStrs []string
	for _, f := range fields {
		fieldStrs = append(fieldStrs, RenderFieldValue(f, fs, cfg.EncodingChars))
	}

	return name + fs + strings.Join(fieldStrs, fs) + string(rune(CR))
}

// BuildMessage builds an HL7 message from segments
func BuildMessage(segments []string) []byte {
	var buf bytes.Buffer
	for _, seg := range segments {
		buf.WriteString(seg)
	}
	return buf.Bytes()
}

// BuildMLLPFrame wraps an HL7 message in MLLP framing
func BuildMLLPFrame(message []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(SOB)
	buf.Write(message)
	buf.WriteByte(EOB)
	buf.WriteByte(CR)
	return buf.Bytes()
}

// BuildHL7Frame is the main entry point - builds a complete MLLP-framed HL7 message
func BuildHL7Frame(cfg *Config, sess *Session, event *Event) ([]byte, string, error) {
	cfg.ApplyDefaults()
	sess.ApplyDefaults()

	var segments []string
	msgType := event.MessageType
	if msgType == "" {
		msgType = "ADT^A01^ADT_A01"
	}

	// Build segments based on message type
	for _, seg := range event.Segments {
		var segStr string
		switch seg.Name {
		case "MSH":
			ctrlID := sess.ControlID
			if ctrlID == "" {
				ctrlID = fmt.Sprintf("MSG%09d", time.Now().UnixNano()%1000000000)
			}
			segStr = BuildMSH(cfg, sess, msgType, ctrlID)
		case "EVN":
			evnType := "A01"
			if len(seg.Fields) > 0 {
				if t, ok := seg.Fields[0].(string); ok {
					evnType = t
				}
			}
			segStr = BuildEVN(evnType, "")
		case "PID":
			pid := sess.PatientID
			lastName := ""
			firstName := ""
			dob := ""
			sex := ""
			for i, f := range seg.Fields {
				switch i {
				case 0:
					if s, ok := f.(string); ok {
						pid = s
					}
				case 1:
					if s, ok := f.(string); ok {
						lastName = s
					}
				case 2:
					if s, ok := f.(string); ok {
						firstName = s
					}
				case 3:
					if s, ok := f.(string); ok {
						dob = s
					}
				case 4:
					if s, ok := f.(string); ok {
						sex = s
					}
				}
			}
			segStr = BuildPID(pid, lastName, firstName, dob, sex, cfg)
		case "PV1":
			patientClass := "I"
			location := ""
			dischargeDate := ""
			for i, f := range seg.Fields {
				if s, ok := f.(string); ok {
					switch i {
					case 0:
						patientClass = s
					case 1:
						location = s
					case 2:
						dischargeDate = s
					}
				}
			}
			segStr = BuildPV1(patientClass, location, dischargeDate, cfg)
		case "OBR":
			segStr = BuildOBR("", "", "", cfg)
		case "OBX":
			setID := 1
			valueType := "NM"
			obsID := ""
			obsValue := ""
			units := ""
			for i, f := range seg.Fields {
				if s, ok := f.(string); ok {
					switch i {
					case 0:
						fmt.Sscanf(s, "%d", &setID)
					case 1:
						valueType = s
					case 2:
						obsID = s
					case 3:
						obsValue = s
					case 4:
						units = s
					}
				}
			}
			segStr = BuildOBX(setID, valueType, obsID, obsValue, units, "", "F", cfg)
		case "MSA":
			ackCode := "AA"
			ctrlID := ""
			for i, f := range seg.Fields {
				if s, ok := f.(string); ok {
					switch i {
					case 0:
						ackCode = s
					case 1:
						ctrlID = s
					}
				}
			}
			segStr = BuildMSA(ackCode, ctrlID, "", cfg)
		case "ERR":
			segStr = BuildERR("200", "E", "Error", cfg)
		default:
			if len(seg.Name) >= 2 && seg.Name[0] == 'Z' {
				segStr = BuildZSegment(seg.Name, seg.Fields, cfg)
			} else {
				// Generic segment
				segStr = BuildGenericSegment(seg.Name, seg.Fields, cfg)
			}
		}
		segments = append(segments, segStr)
	}

	// If no segments, build default ADT^A01
	if len(segments) == 0 {
		msgType = "ADT^A01^ADT_A01"
		segments = append(segments, BuildMSH(cfg, sess, msgType, fmt.Sprintf("MSG%09d", time.Now().UnixNano()%1000000000)))
		segments = append(segments, BuildEVN("A01", ""))
		segments = append(segments, BuildPID("PAT001^^^HOSP^MR", "Smith", "John", "19800101", "M", cfg))
		segments = append(segments, BuildPV1("I", "WARD^ICU^B101", "", cfg))
	}

	message := BuildMessage(segments)
	frame := BuildMLLPFrame(message)

	return frame, msgType, nil
}

// BuildGenericSegment builds a generic segment
func BuildGenericSegment(name string, fields []interface{}, cfg *Config) string {
	fs := cfg.fieldSep()
	var fieldStrs []string
	for _, f := range fields {
		fieldStrs = append(fieldStrs, RenderFieldValue(f, fs, cfg.EncodingChars))
	}
	return name + fs + strings.Join(fieldStrs, fs) + string(rune(CR))
}

// BuildACKFrame builds an ACK message in response to a request
func BuildACKFrame(reqFrame []byte, ackCode string, reqMsgType string, reqMSH10 string, cfg *Config, sess *Session) ([]byte, error) {
	cfg.ApplyDefaults()
	sess.ApplyDefaults()

	// Extract trigger event from message type
	triggerEvent := "A01"
	if reqMsgType != "" {
		parts := strings.Split(reqMsgType, "^")
		if len(parts) >= 2 {
			triggerEvent = parts[1]
		}
	}

	// ACK message type
	ackMsgType := "ACK^" + triggerEvent + "^ACK"

	// Build ACK MSH
	// MSH-3/4 = original MSH-5/6 (swap)
	// MSH-5/6 = original MSH-3/4 (swap)
	origSendingApp := sess.SendingApp
	origSendingFac := sess.SendingFac
	origReceivingApp := sess.ReceivingApp
	origReceivingFac := sess.ReceivingFac

	ackSess := &Session{
		SendingApp:   origReceivingApp,
		SendingFac:   origReceivingFac,
		ReceivingApp: origSendingApp,
		ReceivingFac: origSendingFac,
		ProcessingID: sess.ProcessingID,
	}

	// Generate new control ID for ACK
	ackCtrlID := fmt.Sprintf("ACK%09d", time.Now().UnixNano()%1000000000)

	segments := []string{
		BuildMSH(cfg, ackSess, ackMsgType, ackCtrlID),
		BuildMSA(ackCode, reqMSH10, "", cfg),
	}

	message := BuildMessage(segments)
	return BuildMLLPFrame(message), nil
}

// BuildNAKFrame builds a NAK message with error segment
func BuildNAKFrame(reqFrame []byte, ackCode string, errCode string, reqMsgType string, reqMSH10 string, cfg *Config, sess *Session) ([]byte, error) {
	cfg.ApplyDefaults()

	// Extract trigger event
	triggerEvent := "A01"
	if reqMsgType != "" {
		parts := strings.Split(reqMsgType, "^")
		if len(parts) >= 2 {
			triggerEvent = parts[1]
		}
	}

	ackMsgType := "ACK^" + triggerEvent + "^ACK"

	// Build sender/receiver swap session
	origSendingApp := sess.SendingApp
	origSendingFac := sess.SendingFac
	origReceivingApp := sess.ReceivingApp
	origReceivingFac := sess.ReceivingFac

	ackSess := &Session{
		SendingApp:   origReceivingApp,
		SendingFac:   origReceivingFac,
		ReceivingApp: origSendingApp,
		ReceivingFac: origSendingFac,
		ProcessingID: sess.ProcessingID,
	}

	ackCtrlID := fmt.Sprintf("NAK%09d", time.Now().UnixNano()%1000000000)

	segments := []string{
		BuildMSH(cfg, ackSess, ackMsgType, ackCtrlID),
		BuildMSA(ackCode, reqMSH10, "", cfg),
		BuildERR(errCode, "E", "Application Error", cfg),
	}

	message := BuildMessage(segments)
	return BuildMLLPFrame(message), nil
}

// ExtractMSH10 extracts Message Control ID from MSH segment
func ExtractMSH10(frame []byte) string {
	text := string(frame)
	// Find MSH segment
	mshIdx := strings.Index(text, "MSH|")
	if mshIdx == -1 {
		return ""
	}

	// Parse fields after MSH|^~\&|
	mshPart := text[mshIdx:]
	fields := strings.SplitN(mshPart, "|", 12)
	if len(fields) < 10 {
		return ""
	}
	// fields[0]=MSH, fields[1]=^~\&, fields[2]=MSH-3, ..., fields[9]=MSH-10
	return fields[9]
}

// ExtractMsgType extracts message type from MSH segment
func ExtractMsgType(frame []byte) string {
	text := string(frame)
	mshIdx := strings.Index(text, "MSH|")
	if mshIdx == -1 {
		return ""
	}

	mshPart := text[mshIdx:]
	fields := strings.SplitN(mshPart, "|", 10)
	if len(fields) < 9 {
		return ""
	}
	// fields[8] = MSH-9 (0-indexed: fields[0]=MSH, ..., fields[8]=MSH-9)
	return fields[8]
}

// WireFaultInject injects a wire fault into a frame
func WireFaultInject(frame []byte, fault string) ([]byte, error) {
	if len(frame) < 3 {
		return frame, nil
	}

	switch fault {
	case "framing_sob_missing":
		// Remove SOB byte
		return frame[1:], nil
	case "framing_eob_missing":
		// Remove EOB (0x1c 0x0d)
		if len(frame) >= 3 && frame[len(frame)-2] == EOB && frame[len(frame)-1] == CR {
			return frame[:len(frame)-2], nil
		}
		return frame, nil
	case "framing_eob_malformed":
		// Replace 0x1c 0x0d with just 0x0d
		if len(frame) >= 3 && frame[len(frame)-2] == EOB && frame[len(frame)-1] == CR {
			result := make([]byte, len(frame)-1)
			copy(result, frame[:len(frame)-2])
			result[len(result)-1] = CR
			return result, nil
		}
		return frame, nil
	case "framing_control_byte":
		// Insert 0x1c in the middle (breaks EOB detection)
		result := make([]byte, len(frame)+1)
		mid := len(frame) / 2
		copy(result[:mid+1], frame[:mid+1])
		result[mid+1] = EOB
		copy(result[mid+2:], frame[mid+1:])
		return result, nil
	default:
		return frame, nil
	}
}
