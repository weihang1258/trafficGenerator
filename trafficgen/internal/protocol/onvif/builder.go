package onvif

// builder.go — SOAP 1.2 envelope renderer (compact canonical XML, fully
// deterministic) + the pinned HTTP frames. 设计 §3 线格式逐项：
//   - §3.1 HTTP 头集合（POST：Host/Content-Type/Content-Length/Connection；
//     2xx 响应：Content-Type/Content-Length；错误响应：状态行 +
//     Content-Length: 0（401 另带 WWW-Authenticate））
//   - §3.2 envelope（xml 声明 + s:Envelope + 可选 Header + 必需 Body）
//   - §3.3 WS-Addressing 头与响应 Action 派生
//   - §3.4 UsernameToken（nonce+created 并存，digest 按 WSS §4.2）
//   - §3.5 十一操作请求/响应形状（WSDL 实测：tds/trt/tptz ver20/tev +
//     tt: 载荷前缀混排规则）
//   - §3.6 SOAP 1.2 Fault（Code/Subcode（可嵌套）/Reason/(Node/Role/Detail)）
import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// XMLDecl is the fixed XML declaration (design §3.2, 38 bytes).
const XMLDecl = `<?xml version="1.0" encoding="UTF-8"?>`

// EnvPrefix renders the envelope opening with the given prefix.
func EnvPrefix(prefix string) string {
	return XMLDecl + `<` + prefix + `:Envelope xmlns:` + prefix + `="` + NSSoapEnv + `"`
}

// BuildRequestEnvelope renders the request SOAP envelope.
// prefix is the envelope XML prefix (default "s"; the prefix-variant fixture
// uses "soapenv").
func BuildRequestEnvelope(prefix string, ev *ReqEvent) []byte {
	var b strings.Builder
	b.WriteString(XMLDecl)
	b.WriteString(`<` + prefix + `:Envelope xmlns:` + prefix + `="` + NSSoapEnv + `"`)
	if ev.FaultNS {
		b.WriteString(` xmlns:ter="` + NSter + `"`)
	}
	b.WriteString(`>`)
	// Header: wsa:Action, wsa:MessageID, wsa:To?, Security?
	b.WriteString(`<` + prefix + `:Header>`)
	b.WriteString(`<wsa:Action xmlns:wsa="` + NSWsa + `">` + esc(ev.Action) + `</wsa:Action>`)
	b.WriteString(`<wsa:MessageID xmlns:wsa="` + NSWsa + `">` + esc(ev.MessageID) + `</wsa:MessageID>`)
	if ev.To != "" {
		b.WriteString(`<wsa:To xmlns:wsa="` + NSWsa + `">` + esc(ev.To) + `</wsa:To>`)
	}
	if ev.Auth != nil {
		b.WriteString(renderSecurity(ev))
	}
	b.WriteString(`</` + prefix + `:Header>`)
	b.WriteString(`<` + prefix + `:Body>`)
	b.WriteString(renderRequestBody(ev))
	b.WriteString(`</` + prefix + `:Body>`)
	b.WriteString(`</` + prefix + `:Envelope>`)
	return []byte(b.String())
}

// BuildResponseEnvelope renders the auto-answer envelope (or the Fault form).
func BuildResponseEnvelope(prefix string, ev *ReqEvent, resp *core.ONVIFResponse) []byte {
	var b strings.Builder
	b.WriteString(XMLDecl)
	b.WriteString(`<` + prefix + `:Envelope xmlns:` + prefix + `="` + NSSoapEnv + `"`)
	b.WriteString(` xmlns:ter="` + NSter + `"`)
	b.WriteString(`>`)
	b.WriteString(`<` + prefix + `:Header>`)
	action := ResponseAction(ev.Action)
	if resp != nil && resp.Fault != nil {
		action = FaultActionURI
	}
	b.WriteString(`<wsa:Action xmlns:wsa="` + NSWsa + `">` + esc(action) + `</wsa:Action>`)
	b.WriteString(`<wsa:RelatesTo xmlns:wsa="` + NSWsa + `">` + esc(ev.MessageID) + `</wsa:RelatesTo>`)
	b.WriteString(`</` + prefix + `:Header>`)
	b.WriteString(`<` + prefix + `:Body>`)
	if resp != nil && resp.Fault != nil {
		b.WriteString(renderFault(resp.Fault))
	} else {
		b.WriteString(renderResponseBody(ev, resp))
	}
	b.WriteString(`</` + prefix + `:Body>`)
	b.WriteString(`</` + prefix + `:Envelope>`)
	return []byte(b.String())
}

// renderSecurity renders the WS-Security UsernameToken (§3.4).
func renderSecurity(ev *ReqEvent) string {
	a := ev.Auth
	nonceRaw := a.NonceRaw
	created := a.Created
	if created == "" {
		created = "2026-09-01T00:00:00Z"
	}
	digest := a.Digest
	nonceB64 := base64.StdEncoding.EncodeToString(nonceRaw)
	if a.NonceB64 != "" {
		nonceB64 = a.NonceB64
	}
	var b strings.Builder
	b.WriteString(`<Security xmlns="` + NSsecext + `"><UsernameToken>`)
	b.WriteString(`<Username>` + esc(a.Username) + `</Username>`)
	b.WriteString(`<Password Type="` + PasswordDigestType + `">` + digest + `</Password>`)
	b.WriteString(`<Nonce EncodingType="` + NonceEncodingType + `">` + nonceB64 + `</Nonce>`)
	b.WriteString(`<Created xmlns="` + NSutility + `">` + created + `</Created>`)
	b.WriteString(`</UsernameToken></Security>`)
	return b.String()
}

// ComputeDigest renders Base64(SHA1(nonce + created + password)) (WSS §4.2).
func ComputeDigest(nonceRaw []byte, created, password string) string {
	h := sha1.New()
	h.Write(nonceRaw)
	h.Write([]byte(created))
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// renderRequestBody renders the operation element + parameters (§3.5 WSDL
// shapes; parameter elements carry the service prefix —
// elementFormDefault=qualified).
func renderRequestBody(ev *ReqEvent) string {
	svc := services[ev.Service]
	p := svc.WirePrefix // element prefix == WSDL wire prefix (tds/trt/tptz/tev)
	tt := ` xmlns:tt="` + NStt + `"`
	op := ev.Operation
	ns := ` xmlns:` + p + `="` + svc.NS + `"`
	var inner string
	switch op {
	case "GetCapabilities":
		for _, c := range ev.Categories {
			inner += `<` + p + `:Category>` + esc(c) + `</` + p + `:Category>`
		}
	case "GetStreamUri":
		ss := ev.StreamSetup
		inner += `<` + p + `:StreamSetup` + tt + `><tt:Stream>` + esc(ss.Stream) +
			`</tt:Stream><tt:Transport><tt:Protocol>` + esc(ss.Protocol) + `</tt:Protocol></tt:Transport></` + p + `:StreamSetup>`
		inner += `<` + p + `:ProfileToken>` + esc(ev.ProfileToken) + `</` + p + `:ProfileToken>`
	case "GetSnapshotUri":
		inner += `<` + p + `:ProfileToken>` + esc(ev.ProfileToken) + `</` + p + `:ProfileToken>`
	case "ContinuousMove":
		inner += `<` + p + `:ProfileToken>` + esc(ev.ProfileToken) + `</` + p + `:ProfileToken>`
		if ev.Velocity != nil {
			inner += `<` + p + `:Velocity` + tt + `><tt:PanTilt x="` + ev.Velocity.X + `" y="` + ev.Velocity.Y + `"></tt:PanTilt></` + p + `:Velocity>`
		}
		if ev.Timeout != "" {
			inner += `<` + p + `:Timeout>` + esc(ev.Timeout) + `</` + p + `:Timeout>`
		}
	case "Stop":
		inner += `<` + p + `:ProfileToken>` + esc(ev.ProfileToken) + `</` + p + `:ProfileToken>`
		if ev.PanTilt != nil {
			inner += `<` + p + `:PanTilt>` + b2s(*ev.PanTilt) + `</` + p + `:PanTilt>`
		}
		if ev.Zoom != nil {
			inner += `<` + p + `:Zoom>` + b2s(*ev.Zoom) + `</` + p + `:Zoom>`
		}
	case "CreatePullPointSubscription":
		if ev.Filter != "" {
			inner += `<` + p + `:Filter><wsnt:TopicExpression xmlns:wsnt="` + NSwsnt +
				`" Dialect="` + ConcreteSetDialect + `">` + esc(ev.Filter) + `</wsnt:TopicExpression></` + p + `:Filter>`
		}
		if ev.InitialTerminationTime != "" {
			inner += `<` + p + `:InitialTerminationTime>` + esc(ev.InitialTerminationTime) + `</` + p + `:InitialTerminationTime>`
		}
	case "PullMessages":
		inner += `<` + p + `:Timeout>` + esc(ev.Timeout) + `</` + p + `:Timeout>`
		inner += `<` + p + `:MessageLimit>` + strconv.FormatInt(ev.MessageLimit, 10) + `</` + p + `:MessageLimit>`
	}
	if inner == "" {
		return `<` + p + `:` + op + ns + `/>`
	}
	return `<` + p + `:` + op + ns + tt + `>` + inner + `</` + p + `:` + op + `>`
}

// renderResponseBody renders the <Op>Response element (§3.5 response
// shapes).
func renderResponseBody(ev *ReqEvent, resp *core.ONVIFResponse) string {
	svc := services[ev.Service]
	p := svc.WirePrefix
	op := ev.Operation
	respElem := `<` + p + `:` + op + `Response xmlns:` + p + `="` + svc.NS + `"`
	ttDecl := ` xmlns:tt="` + NStt + `"`
	var inner string
	switch op {
	case "GetSystemDateAndTime":
		if resp != nil && resp.SystemDateAndTime != nil {
			sd := resp.SystemDateAndTime
			inner = `<` + p + `:SystemDateAndTime` + ttDecl + `>`
			if sd.DateTimeType != "" {
				inner += `<tt:DateTimeType>` + esc(sd.DateTimeType) + `</tt:DateTimeType>`
			}
			if sd.DaylightSavings != nil {
				inner += `<tt:DaylightSavings>` + b2s(*sd.DaylightSavings) + `</tt:DaylightSavings>`
			}
			if sd.TimeZone != "" {
				inner += `<tt:TimeZone><tt:TZ>` + esc(sd.TimeZone) + `</tt:TZ></tt:TimeZone>`
			}
			if sd.UTCDateTime != "" {
				inner += renderDateTime("tt:UTCDateTime", sd.UTCDateTime)
			}
			if sd.LocalDateTime != "" {
				inner += renderDateTime("tt:LocalDateTime", sd.LocalDateTime)
			}
			inner += `</` + p + `:SystemDateAndTime>`
		}
	case "GetCapabilities":
		if resp != nil && resp.Capabilities != nil {
			inner = `<` + p + `:Capabilities` + ttDecl + `>`
			for _, e := range resp.Capabilities.Entries {
				inner += `<` + p + `:` + e.Service + `><tt:XAddr>` + esc(e.XAddr) + `</tt:XAddr></` + p + `:` + e.Service + `>`
			}
			inner += `</` + p + `:Capabilities>`
		}
	case "GetDeviceInformation":
		if resp != nil {
			inner = `<` + p + `:Manufacturer>` + esc(resp.Manufacturer) + `</` + p + `:Manufacturer>` +
				`<` + p + `:Model>` + esc(resp.Model) + `</` + p + `:Model>` +
				`<` + p + `:FirmwareVersion>` + esc(resp.FirmwareVersion) + `</` + p + `:FirmwareVersion>` +
				`<` + p + `:SerialNumber>` + esc(resp.SerialNumber) + `</` + p + `:SerialNumber>` +
				`<` + p + `:HardwareId>` + esc(resp.HardwareID) + `</` + p + `:HardwareId>`
		}
	case "GetNetworkInterfaces":
		for _, ni := range respNetwork(resp) {
			enabled := "true"
			if ni.Enabled != nil && !*ni.Enabled {
				enabled = "false"
			}
			inner += `<` + p + `:NetworkInterfaces` + ttDecl + ` token="` + esc(ni.Token) + `">` +
				`<tt:Enabled>` + enabled + `</tt:Enabled></` + p + `:NetworkInterfaces>`
		}
	case "GetProfiles":
		for _, pr := range respProfiles(resp) {
			inner += `<` + p + `:Profiles` + ttDecl + ` token="` + esc(pr.Token) + `">`
			if pr.Name != "" {
				inner += `<tt:Name>` + esc(pr.Name) + `</tt:Name>`
			}
			if pr.Video != nil {
				inner += `<tt:VideoEncoderConfiguration><tt:Encoding>` + esc(pr.Video.Encoding) +
					`</tt:Encoding><tt:Resolution><tt:Width>` + strconv.Itoa(pr.Video.Width) +
					`</tt:Width><tt:Height>` + strconv.Itoa(pr.Video.Height) +
					`</tt:Height></tt:Resolution><tt:RateControl><tt:FrameRateLimit>` +
					strconv.Itoa(pr.Video.FrameRate) + `</tt:FrameRateLimit></tt:RateControl></tt:VideoEncoderConfiguration>`
			}
			inner += `</` + p + `:Profiles>`
		}
	case "GetStreamUri", "GetSnapshotUri":
		if resp != nil && resp.MediaURI != "" {
			inner = `<` + p + `:MediaUri` + ttDecl + `><tt:Uri>` + esc(resp.MediaURI) + `</tt:Uri></` + p + `:MediaUri>`
		}
	case "CreatePullPointSubscription":
		if resp != nil {
			sub := resp.SubscriptionReference
			ct, tt2 := resp.CurrentTime, resp.TerminationTime
			if sub != "" {
				inner += `<` + p + `:SubscriptionReference><wsa:Address xmlns:wsa="` + NSWsa + `">` +
					esc(sub) + `</wsa:Address></` + p + `:SubscriptionReference>`
			}
			if ct != "" {
				inner += `<wsnt:CurrentTime xmlns:wsnt="` + NSwsnt + `">` + esc(ct) + `</wsnt:CurrentTime>`
			}
			if tt2 != "" {
				inner += `<wsnt:TerminationTime xmlns:wsnt="` + NSwsnt + `">` + esc(tt2) + `</wsnt:TerminationTime>`
			}
		}
	case "PullMessages":
		if resp != nil {
			ct, tt2 := resp.CurrentTime, resp.TerminationTime
			if ct != "" {
				inner += `<` + p + `:CurrentTime>` + esc(ct) + `</` + p + `:CurrentTime>`
			}
			if tt2 != "" {
				inner += `<` + p + `:TerminationTime>` + esc(tt2) + `</` + p + `:TerminationTime>`
			}
			for _, n := range resp.NotificationMessages {
				dialect := n.Dialect
				if dialect == "" {
					dialect = ConcreteSetDialect
				}
				inner += `<wsnt:NotificationMessage xmlns:wsnt="` + NSwsnt + ttDecl2() + `">` +
					`<wsnt:Topic Dialect="` + dialect + `">` + esc(n.Topic) + `</wsnt:Topic>` +
					`<wsnt:Message><tt:SimpleItem Name="` + esc(n.SimpleItemName) + `" Value="` + esc(n.SimpleItemValue) + `"/></wsnt:Message>` +
					`</wsnt:NotificationMessage>`
			}
		}
	}
	if inner == "" {
		return respElem + `/>`
	}
	return respElem + `>` + inner + `</` + p + `:` + op + `Response>`
}

// ttDecl2 renders the tt namespace declaration for use inside a wsnt
// element (SimpleItem is tt:).
func ttDecl2() string { return `" xmlns:tt="` + NStt }

// renderDateTime renders a tt:UTCDateTime/LocalDateTime from the
// "YYYY-MM-DDTHH:MM:SSZ" fixture form into the structured Time/Date shape
// (tt:Time{Hour,Minute,Second} + tt:Date{Year,Month,Day}).
func renderDateTime(elem, value string) string {
	d, t, ok := splitDateTime(value)
	if !ok {
		return `<` + elem + `>` + esc(value) + `</` + elem + `>`
	}
	yp, mp, dp := strings.Split(d, "-")[0], strings.Split(d, "-")[1], strings.Split(d, "-")[2]
	h, mi, se := "00", "00", "00"
	if tp := strings.Split(strings.TrimSuffix(t, "Z"), ":"); len(tp) == 3 {
		h, mi, se = tp[0], tp[1], tp[2]
	}
	return `<` + elem + `><tt:Time><tt:Hour>` + yp0(h) + `</tt:Hour><tt:Minute>` + yp0(mi) +
		`</tt:Minute><tt:Second>` + yp0(se) + `</tt:Second></tt:Time>` +
		`<tt:Date><tt:Year>` + yp + `</tt:Year><tt:Month>` + mp + `</tt:Month><tt:Day>` + dp + `</tt:Day></tt:Date></` + elem + `>`
}

// splitDateTime parses "2026-09-01T00:00:00Z" -> ("2026-09-01", "00:00:00Z").
func splitDateTime(v string) (date, timePart string, ok bool) {
	i := strings.Index(v, "T")
	if i < 8 || len(v) < i+9 {
		return "", "", false
	}
	return v[:i], v[i+1:], true
}

func yp0(s string) string {
	for len(s) < 2 {
		s = "0" + s
	}
	return s
}

// renderFault renders the SOAP 1.2 Fault (§3.6).
func renderFault(f *core.ONVIFFault) string {
	value := f.Value
	if value == "" {
		value = "env:Sender"
	}
	subcode := f.Subcode
	if subcode == "" {
		subcode = "ter:NotAuthorized"
	}
	var b strings.Builder
	b.WriteString(`<s:Fault><s:Code><s:Value>`)
	b.WriteString(esc(value))
	b.WriteString(`</s:Value><s:Subcode><s:Value>`)
	b.WriteString(esc(subcode))
	b.WriteString(`</s:Value>`)
	if f.NestedSubcode != "" {
		b.WriteString(`<s:Subcode><s:Value>`)
		b.WriteString(esc(f.NestedSubcode))
		b.WriteString(`</s:Value></s:Subcode>`)
	}
	b.WriteString(`</s:Subcode></s:Code>`)
	b.WriteString(`<s:Reason><s:Text xml:lang="en">`)
	b.WriteString(esc(f.Reason))
	b.WriteString(`</s:Text></s:Reason>`)
	if f.Node != "" {
		b.WriteString(`<s:Node>` + esc(f.Node) + `</s:Node>`)
	}
	if f.Role != "" {
		b.WriteString(`<s:Role>` + esc(f.Role) + `</s:Role>`)
	}
	if f.Detail != "" {
		b.WriteString(`<s:Detail>` + esc(f.Detail) + `</s:Detail>`)
	}
	b.WriteString(`</s:Fault>`)
	return b.String()
}

func respNetwork(resp *core.ONVIFResponse) []core.ONVIFNetworkInterface {
	if resp == nil {
		return nil
	}
	return resp.NetworkInterfaces
}

func respProfiles(resp *core.ONVIFResponse) []core.ONVIFProfile {
	if resp == nil {
		return nil
	}
	return resp.Profiles
}

// ---- HTTP frames (design §3.1 pinned header sets) ----

// DefaultContentType is the pinned request Content-Type.
const DefaultContentType = "application/soap+xml; charset=utf-8"

// headerList mirrors the doh family's ordered header list semantics.
type headerList struct {
	names  []string
	values map[string]string
}

func newHeaderList(pairs ...[2]string) *headerList {
	h := &headerList{values: map[string]string{}}
	for _, p := range pairs {
		h.set(p[0], p[1])
	}
	return h
}

func (h *headerList) set(name, value string) {
	for _, n := range h.names {
		if strings.EqualFold(n, name) {
			h.values[n] = value
			return
		}
	}
	h.names = append(h.names, name)
	h.values[name] = value
}

// applyOverrides: same-name replace in place, "" removes, new names append
// sorted.
func (h *headerList) applyOverrides(overrides map[string]string) {
	if len(overrides) == 0 {
		return
	}
	for _, n := range h.names {
		for k, v := range overrides {
			if strings.EqualFold(n, k) {
				h.values[n] = v
			}
		}
	}
	kept := h.names[:0]
	for _, n := range h.names {
		if h.values[n] != "" {
			kept = append(kept, n)
		} else {
			delete(h.values, n)
		}
	}
	h.names = kept
	var extras []string
	for k, v := range overrides {
		if v == "" {
			continue
		}
		found := false
		for _, n := range h.names {
			if strings.EqualFold(n, k) {
				found = true
				break
			}
		}
		if !found {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	for _, k := range extras {
		h.set(k, overrides[k])
	}
}

func (h *headerList) render() string {
	var b strings.Builder
	for _, n := range h.names {
		fmt.Fprintf(&b, "%s: %s\r\n", n, h.values[n])
	}
	return b.String()
}

// BuildPOSTFrame renders the complete request HTTP frame. Header order:
// Host, Content-Type, Content-Length, Connection (+ sorted extras; the
// Authorization override replaces/appends per the override semantics).
func BuildPOSTFrame(method, uri, host, contentType string, body []byte, connection string, overrides map[string]string) []byte {
	h := newHeaderList(
		[2]string{"Host", host},
		[2]string{"Content-Type", contentType},
		[2]string{"Content-Length", strconv.Itoa(len(body))},
		[2]string{"Connection", connection},
	)
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, uri)
	b.WriteString(h.render())
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

// Build2xxFrame renders the success response: Content-Type, Content-Length
// (design §3.1 example; no Connection header).
func Build2xxFrame(status int, contentType string, body []byte, overrides map[string]string) []byte {
	h := newHeaderList(
		[2]string{"Content-Type", contentType},
		[2]string{"Content-Length", strconv.Itoa(len(body))},
	)
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, StatusText(status))
	b.WriteString(h.render())
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

// BuildErrorFrame renders the Table 5 error form: status line +
// Content-Length: 0 (+ WWW-Authenticate for 401); no Content-Type, no body
// (fixture decision, design §3.1).
func BuildErrorFrame(status int, wwwAuthenticate string, overrides map[string]string) []byte {
	h := newHeaderList(
		[2]string{"Content-Length", "0"},
	)
	if wwwAuthenticate != "" {
		h.set("WWW-Authenticate", wwwAuthenticate)
	}
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, StatusText(status))
	b.WriteString(h.render())
	b.WriteString("\r\n")
	return []byte(b.String())
}

// StatusText resolves the sanctioned status texts.
func StatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 405:
		return "Method Not Allowed"
	case 415:
		return "Unsupported Media Type"
	case 500:
		return "Internal Server Error"
	}
	return "OK"
}

// esc XML-escapes text content.
func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func b2s(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
