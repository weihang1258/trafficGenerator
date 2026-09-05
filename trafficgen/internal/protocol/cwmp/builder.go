// Package cwmp implements the CWMP (TR-069 CPE WAN Management Protocol)
// terminal layer (CWMP 终结层, [ip→tcp→http→cwmp] 链).
//
// Wire-format authority: docs/protocol-designs/64-cwmp-design.md v2.2.2 —
// SOAP 1.1 envelope pinned single-line (§3.1: envelope/serialization
// namespaces fixed to the SOAP 1.1 URIs, CWMP top-level elements carry the
// cwmp: prefix while their inner elements are unqualified, arrays encode
// soap-enc:arrayType with member elements named after the member type,
// anySimpleType values carry xsi:type), HTTP carrier header orders pinned
// (§3.3: text/xml content type, SOAPAction present with an empty value on
// SOAP posts, bare empty POST with neither SOAPAction nor Content-Type, 204
// for empty responses, digest auth per RFC 7616). The unit test asserts the
// builder's exact bytes against these pinning rules.
package cwmp

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Fixture constants (design §3/§8 — 钉死基线值).
const (
	// SOAPEnvelopeNS is the pinned SOAP 1.1 envelope namespace (§3.5; SOAP
	// 1.2 namespaces are wire-format errors).
	SOAPEnvelopeNS = "http://schemas.xmlsoap.org/soap/envelope/"
	// FixtureNamespace is the default CWMP data-model namespace (CWMP 1.0
	// baseline; 1-1/1-2 allowed via §3.7.4 negotiation).
	FixtureNamespace = "urn:dslforum-org:cwmp-1-0"
	// FixtureCurrentTime is the default Inform CurrentTime (dateTime with an
	// explicit UTC offset).
	FixtureCurrentTime = "2026-09-05T12:00:00+00:00"
	// FixtureStartTime / FixtureCompleteTime fill Download/Schedule response
	// and TransferComplete dateTime elements when unset (always emitted with
	// a value — testcase #37 requires the <StartTime>/<CompleteTime> bytes on
	// the Status=0 path).
	FixtureStartTime    = "2026-09-05T12:30:00+00:00"
	FixtureCompleteTime = "2026-09-05T12:35:00+00:00"
	// Digest fixture defaults (challenge parameters and their echo).
	FixtureRealm  = "cwmp"
	FixtureNonce  = "0123456789abcdef"
	FixtureOpaque = "fedcba9876543210"
	FixtureCNonce = "0123456789abcdef"
	// DigestNC is the fixed nonce count (first authorization on the
	// connection).
	DigestNC = "00000001"
	// chunkSize frames chunked bodies (deterministic 512-byte chunks).
	chunkSize = 512
)

// fixtureRPCMethods is the GetRPCMethodsResponse MethodList (baseline RPC
// surface, pinned order).
var fixtureRPCMethods = []string{
	"Inform", "GetRPCMethods", "GetParameterValues", "SetParameterValues",
	"GetParameterNames", "SetParameterNames", "GetParameterAttributes",
	"SetParameterAttributes", "AddObject", "DeleteObject", "Reboot",
	"FactoryReset", "Download", "Upload", "ScheduleDownload", "ScheduleUpload",
	"TransferComplete", "RequestDownload", "Kicked",
}

// FixtureDeviceID returns the baseline DeviceIdStruct (design §8 fixture:
// OUI six uppercase hex digits).
func FixtureDeviceID() core.CWMPDeviceID {
	return core.CWMPDeviceID{
		Manufacturer: "Example",
		OUI:          "001122",
		ProductClass: "GW",
		SerialNumber: "SN000001",
	}
}

// EscapeXML escapes the five XML 1.0 predeclared entities (&amp; first so
// later escapes are not double-encoded; testcase #49 asserts all five).
func EscapeXML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// BuildEnvelope wraps one SOAP body payload in the pinned single-line SOAP
// 1.1 envelope (§3.1): fixed envelope/encoding/xsd/xsi namespaces, the
// cwmp prefix bound to the negotiated CWMP namespace, and the cwmp:ID
// mustUnderstand header. id is echoed verbatim (responses repeat the
// request's id — success or Fault alike).
func BuildEnvelope(namespace, id, body string) []byte {
	var b strings.Builder
	b.WriteString(`<soap:Envelope xmlns:soap="` + SOAPEnvelopeNS + `"`)
	b.WriteString(` xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/"`)
	b.WriteString(` xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)
	b.WriteString(` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	b.WriteString(` xmlns:cwmp="` + namespace + `"`)
	b.WriteString(`><soap:Header><cwmp:ID soap:mustUnderstand="1">`)
	b.WriteString(EscapeXML(id))
	b.WriteString(`</cwmp:ID></soap:Header><soap:Body>`)
	b.WriteString(body)
	b.WriteString(`</soap:Body></soap:Envelope>`)
	return []byte(b.String())
}

// xelem renders a simple element: <n>escaped</n>, or the self-closing <n/>
// form when value is empty (empty CommandKey renders `/>` — testcase #44).
func xelem(name, value string) string {
	if value == "" {
		return "<" + name + "/>"
	}
	return "<" + name + ">" + EscapeXML(value) + "</" + name + ">"
}

// xelemRaw renders an element whose inner content is pre-built XML.
func xelemRaw(name, inner string) string {
	return "<" + name + ">" + inner + "</" + name + ">"
}

// bool01 renders a boolean as 0/1 (NextLevel/Writable/IsDownload).
func bool01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// derefInt renders an *int with a default.
func derefInt(v *int, def int) string {
	if v == nil {
		return strconv.Itoa(def)
	}
	return strconv.Itoa(*v)
}

func derefUint(v *uint, def uint) string {
	if v == nil {
		return strconv.FormatUint(uint64(def), 10)
	}
	return strconv.FormatUint(uint64(*v), 10)
}

func derefUint64(v *uint64, def uint64) string {
	if v == nil {
		return strconv.FormatUint(def, 10)
	}
	return strconv.FormatUint(*v, 10)
}

func derefUint32(v *uint32, def uint32) string {
	if v == nil {
		return strconv.FormatUint(uint64(def), 10)
	}
	return strconv.FormatUint(uint64(*v), 10)
}

// BuildInformPayload renders the Inform body (A.3.3.1 Table 37–39):
// DeviceId, Event array (soap-enc:arrayType, members named EventStruct),
// MaxEnvelopes (default 1), CurrentTime, RetryCount, ParameterList
// (ParameterValueStruct members; anySimpleType values carry
// xsi:type="xsd:string").
func BuildInformPayload(dev core.CWMPDeviceID, events []core.CWMPSOAPEvent, maxEnvelopes *int, currentTime string, retryCount *uint, params []core.CWMPParameter) string {
	var b strings.Builder
	b.WriteString(`<cwmp:Inform>`)
	// DeviceIdStruct (inner elements unqualified, §3.5).
	b.WriteString(`<DeviceId>`)
	b.WriteString(xelem("Manufacturer", dev.Manufacturer))
	b.WriteString(xelem("OUI", dev.OUI))
	b.WriteString(xelem("ProductClass", dev.ProductClass))
	b.WriteString(xelem("SerialNumber", dev.SerialNumber))
	b.WriteString(`</DeviceId>`)
	// Event array: member element name = member type name (§3.5).
	b.WriteString(`<Event soap-enc:arrayType="EventStruct[` + strconv.Itoa(len(events)) + `]">`)
	for _, ev := range events {
		b.WriteString(`<EventStruct>`)
		b.WriteString(xelem("EventCode", ev.Code))
		b.WriteString(xelem("CommandKey", ev.CommandKey))
		b.WriteString(`</EventStruct>`)
	}
	b.WriteString(`</Event>`)
	b.WriteString(xelem("MaxEnvelopes", derefInt(maxEnvelopes, 1)))
	if currentTime == "" {
		currentTime = FixtureCurrentTime
	}
	b.WriteString(xelem("CurrentTime", currentTime))
	b.WriteString(xelem("RetryCount", derefUint(retryCount, 0)))
	b.WriteString(BuildParameterList("ParameterList", params))
	b.WriteString(`</cwmp:Inform>`)
	return b.String()
}

// BuildInformResponsePayload renders InformResponse (MaxEnvelopes=1).
func BuildInformResponsePayload(maxEnvelopes *int) string {
	return `<cwmp:InformResponse>` + xelem("MaxEnvelopes", derefInt(maxEnvelopes, 1)) + `</cwmp:InformResponse>`
}

// BuildMethodPayload renders a method element with pre-built inner XML.
func BuildMethodPayload(method, inner string) string {
	return xelemRaw("cwmp:"+method, inner)
}

// BuildParameterList renders a ParameterValueStruct array under the given
// element name (ParameterList). Empty list renders the self-closing array
// element (testcase #30/#34: `/>` 空表合法).
func BuildParameterList(name string, params []core.CWMPParameter) string {
	var b strings.Builder
	b.WriteString(`<` + name + ` soap-enc:arrayType="ParameterValueStruct[` + strconv.Itoa(len(params)) + `]">`)
	for _, p := range params {
		b.WriteString(`<ParameterValueStruct>`)
		b.WriteString(xelem("Name", p.Name))
		b.WriteString(`<Value xsi:type="xsd:string">` + EscapeXML(p.Value) + `</Value>`)
		b.WriteString(`</ParameterValueStruct>`)
	}
	b.WriteString(`</` + name + `>`)
	return b.String()
}

// BuildStringArray renders a xsd:string array (member elements named
// "string" per the arrayType encoding rule).
func BuildStringArray(name string, vals []string) string {
	var b strings.Builder
	b.WriteString(`<` + name + ` soap-enc:arrayType="xsd:string[` + strconv.Itoa(len(vals)) + `]">`)
	for _, v := range vals {
		b.WriteString(xelem("string", v))
	}
	b.WriteString(`</` + name + `>`)
	return b.String()
}

// BuildGetParameterValuesPayload renders GetParameterValues (A.3.2.2).
func BuildGetParameterValuesPayload(names []string) string {
	return `<cwmp:GetParameterValues>` + BuildStringArray("ParameterNames", names) + `</cwmp:GetParameterValues>`
}

// BuildGetParameterNamesPayload renders GetParameterNames (A.3.2.3;
// NextLevel default 0).
func BuildGetParameterNamesPayload(path string, nextLevel *bool) string {
	nl := "0"
	if nextLevel != nil {
		nl = bool01(*nextLevel)
	}
	return `<cwmp:GetParameterNames>` + xelem("ParameterPath", path) + xelem("NextLevel", nl) + `</cwmp:GetParameterNames>`
}

// BuildSetParameterValuesPayload renders SetParameterValues (A.3.2.1).
func BuildSetParameterValuesPayload(params []core.CWMPParameter, parameterKey string) string {
	return `<cwmp:SetParameterValues>` + BuildParameterList("ParameterList", params) + xelem("ParameterKey", parameterKey) + `</cwmp:SetParameterValues>`
}

// BuildGetParameterAttributesPayload renders GetParameterAttributes
// (A.3.2.4).
func BuildGetParameterAttributesPayload(names []string) string {
	return `<cwmp:GetParameterAttributes>` + BuildStringArray("ParameterNames", names) + `</cwmp:GetParameterAttributes>`
}

// BuildSetParameterAttributesPayload renders SetParameterAttributes
// (A.3.2.5): ParameterList entries carry Name + Notification (entry Value
// parsed as the Notification int, default 0); NotificationChange=1,
// AccessListChange=0, empty AccessList.
func BuildSetParameterAttributesPayload(params []core.CWMPParameter) string {
	var b strings.Builder
	b.WriteString(`<cwmp:SetParameterAttributes>`)
	b.WriteString(`<ParameterList soap-enc:arrayType="ParameterAttributeStruct[` + strconv.Itoa(len(params)) + `]">`)
	for _, p := range params {
		notif := 0
		if p.Value != "" {
			if n, err := strconv.Atoi(p.Value); err == nil {
				notif = n
			}
		}
		b.WriteString(`<ParameterAttributeStruct>`)
		b.WriteString(xelem("Name", p.Name))
		b.WriteString(xelem("NotificationChange", "1"))
		b.WriteString(xelem("Notification", strconv.Itoa(notif)))
		b.WriteString(xelem("AccessListChange", "0"))
		b.WriteString(`<AccessList soap-enc:arrayType="xsd:string[0]"/>`)
		b.WriteString(`</ParameterAttributeStruct>`)
	}
	b.WriteString(`</ParameterList></cwmp:SetParameterAttributes>`)
	return b.String()
}

// BuildGetParameterAttributesResponsePayload renders
// GetParameterAttributesResponse (ParameterAttributesList with
// ParameterAttributeStruct members: Name/Notification/AccessList).
func BuildGetParameterAttributesResponsePayload(params []core.CWMPParameter) string {
	var b strings.Builder
	b.WriteString(`<cwmp:GetParameterAttributesResponse>`)
	b.WriteString(`<ParameterAttributesList soap-enc:arrayType="ParameterAttributeStruct[` + strconv.Itoa(len(params)) + `]">`)
	for _, p := range params {
		notif := 0
		if p.Value != "" {
			if n, err := strconv.Atoi(p.Value); err == nil {
				notif = n
			}
		}
		b.WriteString(`<ParameterAttributeStruct>`)
		b.WriteString(xelem("Name", p.Name))
		b.WriteString(xelem("Notification", strconv.Itoa(notif)))
		b.WriteString(`<AccessList soap-enc:arrayType="xsd:string[0]"/>`)
		b.WriteString(`</ParameterAttributeStruct>`)
	}
	b.WriteString(`</ParameterAttributesList></cwmp:GetParameterAttributesResponse>`)
	return b.String()
}

// BuildGetParameterNamesResponsePayload renders GetParameterNamesResponse
// (ParameterInfoStruct members: Name + Writable boolean, default 1).
func BuildGetParameterNamesResponsePayload(params []core.CWMPParameter) string {
	var b strings.Builder
	b.WriteString(`<cwmp:GetParameterNamesResponse>`)
	b.WriteString(`<ParameterList soap-enc:arrayType="ParameterInfoStruct[` + strconv.Itoa(len(params)) + `]">`)
	for _, p := range params {
		w := "1"
		if p.Value == "0" {
			w = "0"
		}
		b.WriteString(`<ParameterInfoStruct>`)
		b.WriteString(xelem("Name", p.Name))
		b.WriteString(xelem("Writable", w))
		b.WriteString(`</ParameterInfoStruct>`)
	}
	b.WriteString(`</ParameterList></cwmp:GetParameterNamesResponse>`)
	return b.String()
}

// BuildAddObjectPayload / BuildDeleteObjectPayload render the object
// management requests (A.3.2.6/A.3.2.7).
func BuildAddObjectPayload(objectName, parameterKey string) string {
	return `<cwmp:AddObject>` + xelem("ObjectName", objectName) + xelem("ParameterKey", parameterKey) + `</cwmp:AddObject>`
}

func BuildDeleteObjectPayload(objectName, parameterKey string) string {
	return `<cwmp:DeleteObject>` + xelem("ObjectName", objectName) + xelem("ParameterKey", parameterKey) + `</cwmp:DeleteObject>`
}

// BuildDownloadPayload renders the Download/Upload request parameter block
// (A.3.2.8): CommandKey/FileType/URL/Username/Password/FileSize/
// TargetFileName/DelaySeconds. fileSize nil = 0 (unknown, legal); delay
// nil = 0.
func BuildDownloadPayload(method, commandKey, fileType, url, username, password string, fileSize *uint64, targetFileName string, delaySeconds *uint32) string {
	var b strings.Builder
	b.WriteString(`<cwmp:` + method + `>`)
	b.WriteString(xelem("CommandKey", commandKey))
	b.WriteString(xelem("FileType", fileType))
	b.WriteString(xelem("URL", url))
	b.WriteString(xelem("Username", username))
	b.WriteString(xelem("Password", password))
	b.WriteString(xelem("FileSize", derefUint64(fileSize, 0)))
	b.WriteString(xelem("TargetFileName", targetFileName))
	b.WriteString(xelem("DelaySeconds", derefUint32(delaySeconds, 0)))
	b.WriteString(`</cwmp:` + method + `>`)
	return b.String()
}

// BuildTransferResponsePayload renders DownloadResponse/UploadResponse
// (Status 0/1 + StartTime/CompleteTime — always emitted with a value).
func BuildTransferResponsePayload(method string, status int, startTime, completeTime string) string {
	if startTime == "" {
		startTime = FixtureStartTime
	}
	if completeTime == "" {
		completeTime = FixtureCompleteTime
	}
	return `<cwmp:` + method + `>` + xelem("Status", strconv.Itoa(status)) +
		xelem("StartTime", startTime) + xelem("CompleteTime", completeTime) +
		`</cwmp:` + method + `>`
}

// BuildScheduleDownloadPayload renders ScheduleDownload (A.3.2.11).
func BuildScheduleDownloadPayload(commandKey, fileType, url, username, password string, fileSize *uint64, targetFileName, startTime, completeTime, successURL, failureURL string, maxRetries *int) string {
	var b strings.Builder
	b.WriteString(`<cwmp:ScheduleDownload>`)
	b.WriteString(xelem("CommandKey", commandKey))
	b.WriteString(xelem("FileType", fileType))
	b.WriteString(xelem("URL", url))
	b.WriteString(xelem("Username", username))
	b.WriteString(xelem("Password", password))
	b.WriteString(xelem("FileSize", derefUint64(fileSize, 0)))
	b.WriteString(xelem("TargetFileName", targetFileName))
	b.WriteString(xelem("StartTime", startTime))
	b.WriteString(xelem("CompleteTime", completeTime))
	b.WriteString(xelem("SuccessURL", successURL))
	b.WriteString(xelem("FailureURL", failureURL))
	b.WriteString(xelem("MaxRetries", derefInt(maxRetries, 0)))
	b.WriteString(`</cwmp:ScheduleDownload>`)
	return b.String()
}

// BuildScheduleDownloadResponsePayload renders ScheduleDownloadResponse
// (Status + StartTime).
func BuildScheduleDownloadResponsePayload(status int, startTime string) string {
	if startTime == "" {
		startTime = FixtureStartTime
	}
	return `<cwmp:ScheduleDownloadResponse>` + xelem("Status", strconv.Itoa(status)) + xelem("StartTime", startTime) + `</cwmp:ScheduleDownloadResponse>`
}

// BuildScheduleUploadPayload renders ScheduleUpload.
func BuildScheduleUploadPayload(commandKey, fileType, url, username, password, startTime, completeTime string) string {
	var b strings.Builder
	b.WriteString(`<cwmp:ScheduleUpload>`)
	b.WriteString(xelem("CommandKey", commandKey))
	b.WriteString(xelem("FileType", fileType))
	b.WriteString(xelem("URL", url))
	b.WriteString(xelem("Username", username))
	b.WriteString(xelem("Password", password))
	b.WriteString(xelem("StartTime", startTime))
	b.WriteString(xelem("CompleteTime", completeTime))
	b.WriteString(`</cwmp:ScheduleUpload>`)
	return b.String()
}

// BuildScheduleUploadResponsePayload renders ScheduleUploadResponse
// (Status + StartTime).
func BuildScheduleUploadResponsePayload(status int, startTime string) string {
	if startTime == "" {
		startTime = FixtureStartTime
	}
	return `<cwmp:ScheduleUploadResponse>` + xelem("Status", strconv.Itoa(status)) + xelem("StartTime", startTime) + `</cwmp:ScheduleUploadResponse>`
}

// faultStruct renders the FaultStruct block (Table 43): FaultCode 0 =
// success.
func faultStruct(faultCode *int, faultString string) string {
	code := 0
	if faultCode != nil {
		code = *faultCode
	}
	return `<FaultStruct>` + xelem("FaultCode", strconv.Itoa(code)) + xelem("FaultString", faultString) + `</FaultStruct>`
}

// BuildTransferCompletePayload renders TransferComplete (A.3.3.2):
// CommandKey/FaultStruct/StartTime/CompleteTime.
func BuildTransferCompletePayload(commandKey string, faultCode *int, faultString, startTime, completeTime string) string {
	if startTime == "" {
		startTime = FixtureStartTime
	}
	if completeTime == "" {
		completeTime = FixtureCompleteTime
	}
	return `<cwmp:TransferComplete>` + xelem("CommandKey", commandKey) +
		faultStruct(faultCode, faultString) +
		xelem("StartTime", startTime) + xelem("CompleteTime", completeTime) +
		`</cwmp:TransferComplete>`
}

// BuildAutonomousTransferCompletePayload renders
// AutonomousTransferComplete (A.3.3.3, cwmp-1-2.xsd full shape — no
// CommandKey): AnnounceURL/TransferURL/IsDownload/FileType/FileSize/
// TargetFileName/FaultStruct/StartTime/CompleteTime.
func BuildAutonomousTransferCompletePayload(announceURL, transferURL string, isDownload *bool, fileType string, fileSize *uint64, targetFileName string, faultCode *int, faultString, startTime, completeTime string) string {
	isDL := true
	if isDownload != nil {
		isDL = *isDownload
	}
	if startTime == "" {
		startTime = FixtureStartTime
	}
	if completeTime == "" {
		completeTime = FixtureCompleteTime
	}
	var b strings.Builder
	b.WriteString(`<cwmp:AutonomousTransferComplete>`)
	b.WriteString(xelem("AnnounceURL", announceURL))
	b.WriteString(xelem("TransferURL", transferURL))
	b.WriteString(xelem("IsDownload", bool01(isDL)))
	b.WriteString(xelem("FileType", fileType))
	b.WriteString(xelem("FileSize", derefUint64(fileSize, 0)))
	b.WriteString(xelem("TargetFileName", targetFileName))
	b.WriteString(faultStruct(faultCode, faultString))
	b.WriteString(xelem("StartTime", startTime))
	b.WriteString(xelem("CompleteTime", completeTime))
	b.WriteString(`</cwmp:AutonomousTransferComplete>`)
	return b.String()
}

// BuildRequestDownloadPayload renders RequestDownload (A.3.3.4 — no
// CommandKey per cwmp-1-2.xsd).
func BuildRequestDownloadPayload(fileType, fileTypeArg string) string {
	return `<cwmp:RequestDownload>` + xelem("FileType", fileType) + xelem("FileTypeArg", fileTypeArg) + `</cwmp:RequestDownload>`
}

// BuildKickedPayload renders the ACS-initiated Kicked request (A.3.2.16).
func BuildKickedPayload(commandKey string) string {
	return `<cwmp:Kicked>` + xelem("CommandKey", commandKey) + `</cwmp:Kicked>`
}

// BuildKickedResponsePayload renders KickedResponse (KickURL/RequestID).
func BuildKickedResponsePayload(kickURL string, requestID *uint) string {
	return `<cwmp:KickedResponse>` + xelem("KickURL", kickURL) + xelem("RequestID", derefUint(requestID, 1)) + `</cwmp:KickedResponse>`
}

// BuildAddObjectResponsePayload renders AddObjectResponse
// (InstanceNumber default 1 + Status default 0).
func BuildAddObjectResponsePayload(instanceNumber *uint, status int) string {
	return `<cwmp:AddObjectResponse>` + xelem("InstanceNumber", derefUint(instanceNumber, 1)) + xelem("Status", strconv.Itoa(status)) + `</cwmp:AddObjectResponse>`
}

// BuildStatusResponsePayload renders the Status-only responses
// (SetParameterValuesResponse/DeleteObjectResponse/RebootResponse — A.3.2.1/
// A.3.2.7/A.3.2.9; Status 0=applied 1=pending reboot; default 0).
func BuildStatusResponsePayload(method string, status int) string {
	return `<cwmp:` + method + `>` + xelem("Status", strconv.Itoa(status)) + `</cwmp:` + method + `>`
}

// BuildGetRPCMethodsPayload renders GetRPCMethods (no parameters).
func BuildGetRPCMethodsPayload() string {
	return `<cwmp:GetRPCMethods/>`
}

// BuildConnectionRequest builds the bare HTTP GET used by an ACS-initiated
// Connection Request (design §3.2.2: ACS sends a GET to the CPE's
// ConnectionRequestURL; the CPE's 200 response carries an empty body, the
// 401 response is a digest challenge). The frame intentionally omits
// SOAPAction and Content-Type (no SOAP envelope rides this request).
func BuildConnectionRequest(uri, host string) []byte {
	var b strings.Builder
	b.WriteString("GET " + uri + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	return []byte(b.String())
}

// BuildGetRPCMethodsResponsePayload renders GetRPCMethodsResponse
// (MethodList string array).
func BuildGetRPCMethodsResponsePayload() string {
	return `<cwmp:GetRPCMethodsResponse>` + BuildStringArray("MethodList", fixtureRPCMethods) + `</cwmp:GetRPCMethodsResponse>`
}

// defaultFaultString maps fixture fault codes to a deterministic inner
// FaultString label (the OUTER faultstring is the fixed "CWMP fault").
func defaultFaultString(code int) string {
	switch code {
	case 8002:
		return "internal error"
	case 8005:
		return "retry request"
	case 9000:
		return "method not supported"
	case 9001:
		return "request denied"
	case 9003:
		return "invalid arguments"
	case 9005:
		return "invalid parameter name"
	case 9007:
		return "invalid parameter value"
	case 9008:
		return "non-writable parameter"
	}
	return "CWMP fault"
}

// pinnedFaultcodes maps numeric FaultCode values to their bare soap
// faultcode (design §3.4: 值域为 Client/Server，不带前缀). The mapping is
// pinned per testcase §4 and is NOT domain-derivable — 9000→Server while
// 9003/9800→Client, both in the 9xxx CPE domain: #13 8000=Server,
// #104 8005=Server, #66 9000=Server, #36 9003=Client, #79 9800=Client.
// Unlisted codes fall back to the domain rule (8xxx ACS-side=Server,
// 9xxx CPE-side=Client).
var pinnedFaultcodes = map[int]string{
	8000: "Server",
	8005: "Server",
	9000: "Server",
	9003: "Client",
	9800: "Client",
}

// BuildFaultPayload renders the SOAP Fault body (§3.4): faultcode is the
// BARE value Client|Server (design §3.4 值域 — no soap: prefix; testcase
// #13/#36 hex-assert 53 65 72 76 65 72 / 43 6C 69 65 6E 74), the FIXED
// outer faultstring "CWMP fault", and detail/cwmp:Fault with
// FaultCode/FaultString plus optional SetParameterValuesFault entries.
func BuildFaultPayload(fault *core.CWMPFault) string {
	if fault == nil {
		fault = &core.CWMPFault{Code: 9002}
	}
	faultcode := fault.FaultCode
	if faultcode == "" {
		faultcode = pinnedFaultcodes[fault.Code]
		if faultcode == "" {
			if fault.Code >= 9000 {
				faultcode = "Client"
			} else {
				faultcode = "Server"
			}
		}
	}
	faultString := fault.FaultString
	if faultString == "" {
		faultString = defaultFaultString(fault.Code)
	}
	var b strings.Builder
	b.WriteString(`<soap:Fault>`)
	b.WriteString(xelem("faultcode", faultcode))
	b.WriteString(xelem("faultstring", "CWMP fault"))
	b.WriteString(`<detail><cwmp:Fault>`)
	b.WriteString(xelem("FaultCode", strconv.Itoa(fault.Code)))
	b.WriteString(xelem("FaultString", faultString))
	for _, spv := range fault.SPVFaults {
		b.WriteString(`<SetParameterValuesFault>`)
		b.WriteString(xelem("ParameterName", spv.ParameterName))
		b.WriteString(xelem("FaultCode", strconv.Itoa(spv.FaultCode)))
		b.WriteString(xelem("FaultString", spv.FaultString))
		b.WriteString(`</SetParameterValuesFault>`)
	}
	b.WriteString(`</cwmp:Fault></detail></soap:Fault>`)
	return b.String()
}

// pascalMethod converts a snake_case RPC name to its PascalCase wire form
// ("get_parameter_values" → "GetParameterValues").
func pascalMethod(snake string) string {
	parts := strings.Split(snake, "_")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

// StatusText maps the fixture's HTTP status codes to reason phrases.
func StatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 204:
		return "No Content"
	case 302:
		return "Found"
	case 307:
		return "Temporary Redirect"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	}
	return "Unknown"
}

// BuildRequest builds a complete HTTP request with the pinned CWMP header
// order (design §3.3): 请求行 → Host → [Authorization] → [Cookie] →
// Content-Type → SOAPAction → Content-Length | Transfer-Encoding →
// Connection → CRLF → body. contentType empty = no Content-Type header
// (the empty POST must carry neither Content-Type nor SOAPAction);
// soapAction empty string = the mandatory empty-value `SOAPAction:` line is
// STILL emitted for SOAP posts — pass soapActionOmit to suppress it.
// contentLengthOverride renders a verbatim Content-Length (negative
// injection; validator rejects mismatches). transferEncoding "chunked"
// replaces Content-Length with the Transfer-Encoding header and frames the
// body as chunks.
func BuildRequest(method, uri, host, authorization, cookie, contentType, soapAction string, body []byte, transferEncoding string, contentLengthOverride *int, connection string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + uri + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	if authorization != "" {
		b.WriteString("Authorization: " + authorization + "\r\n")
	}
	if cookie != "" {
		b.WriteString("Cookie: " + cookie + "\r\n")
	}
	if contentType != "" {
		b.WriteString("Content-Type: " + contentType + "\r\n")
	}
	if soapAction != SOAPActionOmit {
		b.WriteString("SOAPAction: " + soapAction + "\r\n")
	}
	if transferEncoding == "chunked" {
		b.WriteString("Transfer-Encoding: chunked\r\n")
		body = chunkFrame(body)
	} else if contentLengthOverride != nil {
		b.WriteString("Content-Length: " + strconv.Itoa(*contentLengthOverride) + "\r\n")
	} else {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("Connection: " + connection + "\r\n\r\n")
	b.Write(body)
	return []byte(b.String())
}

// SOAPActionOmit suppresses the SOAPAction header (empty POST contract:
// §3.4.1 空请求不得带 SOAPAction/Content-Type).
const SOAPActionOmit = "\x00omit"

// SOAPActionEmpty renders the SOAPAction header with an empty value
// (SOAP POST contract: header MUST be present, value MUST be empty per
// §3.4.1).
const SOAPActionEmpty = ""

// BuildResponse builds a complete HTTP response: 状态行 → [Set-Cookie] →
// [WWW-Authenticate] → [Location] → Content-Type → Content-Length |
// Transfer-Encoding → Connection → CRLF → body. 204 carries no
// Content-Type and no Content-Length (RFC 9110 §8.6 — 204 must not
// include a body or its length). Bodies are emitted verbatim; an empty
// body with a 200/401/302/503 status renders Content-Length: 0.
func BuildResponse(status int, contentType, setCookie, wwwAuthenticate, location string, body []byte, transferEncoding string, connection string) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + StatusText(status) + "\r\n")
	if setCookie != "" {
		b.WriteString("Set-Cookie: " + setCookie + "\r\n")
	}
	if wwwAuthenticate != "" {
		b.WriteString("WWW-Authenticate: " + wwwAuthenticate + "\r\n")
	}
	if location != "" {
		b.WriteString("Location: " + location + "\r\n")
	}
	if status == 204 {
		// 空响应：无 Content-Type/Content-Length（204 不得携带消息体）。
		b.WriteString("Connection: " + connection + "\r\n\r\n")
		return []byte(b.String())
	}
	if contentType != "" {
		b.WriteString("Content-Type: " + contentType + "\r\n")
	}
	if transferEncoding == "chunked" && len(body) > 0 {
		b.WriteString("Transfer-Encoding: chunked\r\n")
		body = chunkFrame(body)
	} else {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("Connection: " + connection + "\r\n\r\n")
	b.Write(body)
	return []byte(b.String())
}

// chunkFrame frames a body as deterministic 512-byte chunks with the
// terminating zero chunk ("0\r\n\r\n").
func chunkFrame(body []byte) []byte {
	var b strings.Builder
	for len(body) > 0 {
		n := chunkSize
		if n > len(body) {
			n = len(body)
		}
		b.WriteString(strconv.FormatInt(int64(n), 16) + "\r\n")
		b.Write(body[:n])
		b.WriteString("\r\n")
		body = body[n:]
	}
	b.WriteString("0\r\n\r\n")
	return []byte(b.String())
}

// DefaultChallenge returns the default digest WWW-Authenticate challenge
// value (§3.4.5: realm/nonce/opaque/qop="auth"/algorithm=MD5).
func DefaultChallenge() string {
	return `Digest realm="` + FixtureRealm + `", nonce="` + FixtureNonce + `", opaque="` + FixtureOpaque + `", qop="auth", algorithm=MD5, stale=false`
}

// md5hex returns the lowercase hex MD5 digest of s.
func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DigestResponse computes the RFC 7616 digest response for qop="auth":
// HA1 = MD5(username:realm:password), HA2 = MD5(method:uri),
// response = MD5(HA1:nonce:nc:cnonce:qop:HA2).
func DigestResponse(username, password, realm, nonce, nc, cnonce, qop, method, uri string) string {
	ha1 := md5hex(username + ":" + realm + ":" + password)
	ha2 := md5hex(method + ":" + uri)
	return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// PercentEncodeUsername percent-encodes a recommended-form username
// ("<OUI>-<ProductClass>-<SerialNumber>", TR-069 §3.4.4) per RFC 3986:
// unreserved characters (ALPHA/DIGIT/-._~) pass through, everything else
// renders as %XX uppercase hex (space → %20 — testcase #111).
func PercentEncodeUsername(s string) string {
	const unreserved = "-._~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case strings.IndexByte(unreserved, c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteString("%")
			const hexDigits = "0123456789ABCDEF"
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// DigestAuthorizationHeader builds the full Authorization header value
// (§3.4.5 answer parameter set: username/realm/nonce/uri/response/cnonce/
// nc/qop="auth"/algorithm, opaque echoed verbatim — pinned order).
// challenge carries the WWW-Authenticate value the credentials answer
// (realm/nonce/opaque are parsed from it when auth leaves them empty).
func DigestAuthorizationHeader(auth core.CWMPAuth, challenge, method, uri string) string {
	realm := auth.Realm
	if realm == "" {
		realm = FixtureRealm
	}
	nonce := auth.Nonce
	if nonce == "" {
		nonce = FixtureNonce
	}
	if challenge != "" {
		if v := challengeParam(challenge, "realm"); v != "" {
			realm = v
		}
		if v := challengeParam(challenge, "nonce"); v != "" {
			nonce = v
		}
	}
	opaque := auth.Opaque
	if opaque == "" {
		opaque = FixtureOpaque
	}
	if challenge != "" {
		if v := challengeParam(challenge, "opaque"); v != "" {
			opaque = v
		}
	}
	cnonce := auth.CNonce
	if cnonce == "" {
		cnonce = FixtureCNonce
	}
	qop := auth.QOP
	if qop == "" {
		qop = "auth"
	}
	algorithm := auth.Algorithm
	if algorithm == "" {
		algorithm = "MD5"
	}
	response := DigestResponse(auth.Username, auth.Password, realm, nonce, DigestNC, cnonce, qop, method, uri)
	return `Digest username="` + auth.Username + `", realm="` + realm + `", nonce="` + nonce +
		`", uri="` + uri + `", response="` + response + `", cnonce="` + cnonce +
		`", nc=` + DigestNC + `, qop=` + qop + `, algorithm=` + algorithm +
		`, opaque="` + opaque + `"`
}

// challengeParam extracts one quoted (or bare) parameter from a
// WWW-Authenticate header value.
func challengeParam(challenge, name string) string {
	i := strings.Index(challenge, name+"=\"")
	if i >= 0 {
		rest := challenge[i+len(name)+2:]
		if j := strings.Index(rest, "\""); j >= 0 {
			return rest[:j]
		}
	}
	// Bare form (qop=auth / algorithm=MD5 / nc=...).
	i = strings.Index(challenge, name+"=")
	if i >= 0 {
		rest := challenge[i+len(name)+1:]
		if j := strings.IndexAny(rest, ","); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	return ""
}
