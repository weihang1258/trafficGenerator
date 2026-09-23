// Package mmse builder: WAP-209 §7.1/§7.2 + WAP-230-WSP §8.4.1 编码原语与
// PDU/multipart 渲染（D-MMSE-1，契约 71-mmse v2.1.0 §3）。纯函数、确定性：
// 同一配置必然产出同一字节序列（契约 §5 定性——无墙钟依赖）。HTTP 载体
// 骨架（请求行/状态行/Host/Content-Type/Content-Length）在此产出完整帧，
// http 层透传转发（cwmp/doh/onvif 同款），tcp 层管分段/握手/挥手。
//
// 定宽补零策略（契约 §3.3）：Date-value 恒 4B、Delta-seconds 恒 3B、
// Message-Size 恒 3B——frames hex 逐字节断言的字节形态稳定（与 WSP 最小编
// 码的区别见契约 §3.3）。Connection 头不发送（HTTP/1.1 持久连接缺省，
// RFC 7230 §6.3——用例 #24 的"无 Connection: close"断言自然满足）。
package mmse

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// PDU 类型字节（契约 §3.7 Message-Type 值域，本版产生 8 值）。
const (
	pduSendReq       = 0x80
	pduSendConf      = 0x81
	pduNotifInd      = 0x82
	pduNotifyRespInd = 0x83
	pduRetrieveConf  = 0x84
	pduAckInd        = 0x85
	pduDeliveryInd   = 0x86
	pduReadRecInd    = 0x87
)

// 头字段线码 = 0x80|编号（契约 §3.4 表 8）。
const (
	fBcc              = 0x81
	fCc               = 0x82
	fContentLocation  = 0x83
	fContentType      = 0x84
	fDate             = 0x85
	fDeliveryReport   = 0x86
	fDeliveryTime     = 0x87
	fExpiry           = 0x88
	fFrom             = 0x89
	fMessageClass     = 0x8A
	fMessageID        = 0x8B
	fMessageType      = 0x8C
	fMMSVersion       = 0x8D
	fMessageSize      = 0x8E
	fPriority         = 0x8F
	fReadReply        = 0x90
	fReportAllowed    = 0x91
	fResponseStatus   = 0x92
	fResponseText     = 0x93
	fSenderVisibility = 0x94
	fStatus           = 0x95
	fSubject          = 0x96
	fTo               = 0x97
	fTransactionID    = 0x98
	fReadStatus       = 0x9B
)

// WSP 参数/媒体码（契约 §3.6）。
const (
	mediaMultipartRelated = 0xB3
	mediaTextPlain        = 0x83
	mediaImageJPEG        = 0x9E
	mediaImageGIF         = 0x9D
	mediaImagePNG         = 0xA0
	paramType             = 0x89 // multipart/related type 参数
	paramStart            = 0x8A // start 参数
	// WSP part 头参数（编在 part Content-type-value 的 Value-length 之内
	// ——N-6 实现警告：放在 part 头层会被按头字段码误解析）。
	paramName        = 0x85
	paramCharset     = 0x81
	tokenAbsolute    = 0x80
	tokenRelative    = 0x81
	addrPresentToken = 0x80
	addrInsertToken  = 0x81
	quoteByte        = 0x7F
	charsetUTF8Wire  = 0xEA // 0x80 | 106（MIBEnum UTF-8）
	mmsContentType   = "application/vnd.wap.mms-message"
)

// enumBytes maps config strings to wire enum bytes（契约 §3.7；域外值由
// validator 拒——builder 只接受已校验值，缺省映射给 fixture 缺省面）。
var (
	enumClass = map[string]byte{
		"personal": 0x80, "advertisement": 0x81, "informational": 0x82, "auto": 0x83,
	}
	enumPriority = map[string]byte{"low": 0x80, "normal": 0x81, "high": 0x82}
	enumStatus   = map[string]byte{
		"expired": 0x80, "retrieved": 0x81, "rejected": 0x82, "deferred": 0x83, "unrecognised": 0x84,
	}
	enumResponseStatus = map[string]byte{
		"ok": 0x80, "error_unspecified": 0x81, "error_service_denied": 0x82,
		"error_message_format_corrupt": 0x83, "error_sending_address_unresolved": 0x84,
		"error_message_not_found": 0x85, "error_network_problem": 0x86,
		"error_content_not_accepted": 0x87, "error_unsupported_message": 0x88,
	}
	enumReadStatus = map[string]byte{"read": 0x80, "deleted_without_being_read": 0x81}
	enumVisibility = map[string]byte{"hide": 0x80, "show": 0x81}
)

// versionWire renders MMS-Version wire byte (N-1 口径：线码 = 0x80|(主<<4|次))。
func versionWire(v string) (byte, error) {
	major, minor, ok := strings.Cut(v, ".")
	if !ok {
		return 0, fmt.Errorf("mmse: mms_version %q is not <major>.<minor>", v)
	}
	mj, err := strconv.Atoi(major)
	if err != nil || mj < 1 || mj > 7 {
		return 0, fmt.Errorf("mmse: mms_version major %q out of range", major)
	}
	mn, err := strconv.Atoi(minor)
	if err != nil || mn < 0 || mn > 14 {
		return 0, fmt.Errorf("mmse: mms_version minor %q out of range", minor)
	}
	return byte(0x80 | mj<<4 | mn), nil
}

// appendShortInt appends a WSP Short-integer（0x80|v，v∈0–127）。
func appendShortInt(b []byte, v byte) []byte { return append(b, 0x80|v) }

// appendLongInt appends a WSP Long-integer（长度字节 n + n 字节大端，定宽）。
func appendLongInt(b []byte, n int, v uint64) []byte {
	b = append(b, byte(n))
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*uint(i))))
	}
	return b
}

// appendUintvar appends a WSP Uintvar（WAP-230 §8.1.2：7bit 一组，低组在前，
// 除末组外高位置 1——2097152 → 80 80 80 01）。
func appendUintvar(b []byte, v uint64) []byte {
	if v == 0 {
		return append(b, 0)
	}
	var groups [5]byte
	n := 0
	for v > 0 {
		groups[n] = byte(v & 0x7F)
		v >>= 7
		n++
	}
	for i := 0; i < n; i++ {
		c := groups[i]
		if i != n-1 {
			c |= 0x80
		}
		b = append(b, c)
	}
	return b
}

// appendValueLength appends a WSP Value-length（≤30 单字节；>30 0x1F+Uintvar）。
func appendValueLength(b []byte, n int) []byte {
	if n <= 30 {
		return append(b, byte(n))
	}
	b = append(b, 0x1F)
	return appendUintvar(b, uint64(n))
}

// isTextSeparator reports whether c is an RFC 822 separator（契约 §8 边界：
// Text-string 首字符为分隔符时前置 0x7F Quote）。
func isTextSeparator(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', ' ', '\t':
		return true
	}
	return false
}

// appendTextString appends a WSP Text-string（[0x7F Quote] ASCII + 0x00 终止）。
func appendTextString(b []byte, s string) []byte {
	if len(s) > 0 && isTextSeparator(s[0]) {
		b = append(b, quoteByte)
	}
	b = append(b, s...)
	return append(b, 0)
}

// appendEncodedStringValue appends Encoded-string-value：裸 Text-string
// （charset 0）或 Value-length + Char-set + Text-string（charset 106）。
func appendEncodedStringValue(b []byte, s string, charset int) []byte {
	if charset == 0 {
		return appendTextString(b, s)
	}
	body := appendShortInt(nil, byte(charset)) // Char-set Short-integer
	body = appendTextString(body, s)
	b = appendValueLength(b, len(body))
	return append(b, body...)
}

// appendFrom appends the From header（契约 §3.4：Value-length(0x80 Encoded-
// string-value | 0x81 Insert-address-token)）。
func appendFrom(b []byte, from *core.MMSEFrom) []byte {
	var body []byte
	if from != nil && from.InsertToken {
		body = append(body, addrInsertToken)
	} else {
		addr := ""
		if from != nil {
			addr = from.Address
		}
		body = append(body, addrPresentToken)
		body = appendTextString(body, addr)
	}
	b = append(b, fFrom)
	b = appendValueLength(b, len(body))
	return append(b, body...)
}

// yesNoByte renders Yes/No wire bytes（true=0x80/false=0x81）。
func yesNoByte(v bool) byte {
	if v {
		return 0x80
	}
	return 0x81
}

// mediaCode maps a content type string to its WSP well-known code, or ""
// when the type has no code (extension-media text form).
func mediaCode(ct string) (byte, bool) {
	switch ct {
	case "text/plain":
		return mediaTextPlain, true
	case "image/jpeg":
		return mediaImageJPEG, true
	case "image/gif":
		return mediaImageGIF, true
	case "image/png":
		return mediaImagePNG, true
	case "application/vnd.wap.multipart.related":
		return mediaMultipartRelated, true
	}
	return 0, false
}

// appendContentTypeValue renders a WSP Content-type-value：单媒体码 1B（无
// 参数）或 Value-length(媒体码+参数集)（契约 §3.6；N-6：name/charset 参数
// 编在 Value-length 之内）。
func appendContentTypeValue(b []byte, p *core.MMSEPart) []byte {
	// part CT-value 恒带 Value-length 包裹（B6 夹具同款——裸媒体码/扩展文本
	// 同样包 VL；WSP §8.4.2.1 两可形取 VL 形，part 头长度可复算）。
	var body []byte
	code, wellKnown := mediaCode(p.ContentType)
	if wellKnown {
		body = append(body, code)
	} else {
		// Extension-media 文本形态（application/smil 等无码类型）。
		body = appendTextString(body, p.ContentType)
	}
	if p.Name != "" {
		body = append(body, paramName)
		body = appendTextString(body, p.Name)
	}
	if p.Charset != 0 {
		body = append(body, paramCharset)
		body = appendShortInt(body, byte(p.Charset))
	}
	b = appendValueLength(b, len(body))
	return append(b, body...)
}

// buildMultipartCT renders the parent Content-type-value for
// multipart/related：Value-length(0xB3 [0x89 type] [0x8A start])。
func buildMultipartCT(c *core.MMSEContent) []byte {
	var body []byte
	body = append(body, mediaMultipartRelated)
	if c.Type != "" {
		body = append(body, paramType)
		if code, ok := mediaCode(c.Type); ok {
			body = appendShortInt(body, code)
		} else {
			body = appendTextString(body, c.Type)
		}
	}
	if c.Start != "" {
		body = append(body, paramStart)
		body = appendTextString(body, c.Start)
	}
	var out []byte
	out = appendValueLength(out, len(body))
	return append(out, body...)
}

// partData resolves a part's payload bytes（Data 胜 DataB64）。
func partData(p *core.MMSEPart) ([]byte, error) {
	if p.Data != "" {
		return []byte(p.Data), nil
	}
	if p.DataB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(p.DataB64)
		if err != nil {
			return nil, fmt.Errorf("mmse: part data_b64 invalid base64: %w", err)
		}
		return raw, nil
	}
	return nil, nil
}

// buildMultipartBody renders the WSP binary multipart（契约 §3.6）：
// Uintvar(partNum) *( Uintvar(headersLen) Uintvar(dataLen) part-headers data )。
func buildMultipartBody(c *core.MMSEContent) ([]byte, error) {
	body := appendUintvar(nil, uint64(len(c.Parts)))
	for i := range c.Parts {
		p := &c.Parts[i]
		data, err := partData(p)
		if err != nil {
			return nil, err
		}
		var hdr []byte
		hdr = appendContentTypeValue(hdr, p)
		if p.ContentID != "" {
			hdr = append(hdr, 0xC0) // Content-ID
			hdr = appendTextString(hdr, p.ContentID)
		}
		if p.ContentLocation != "" {
			hdr = append(hdr, 0x8E) // Content-Location
			hdr = appendTextString(hdr, p.ContentLocation)
		}
		body = appendUintvar(body, uint64(len(hdr)))
		body = appendUintvar(body, uint64(len(data)))
		body = append(body, hdr...)
		body = append(body, data...)
	}
	return body, nil
}

// pduFieldAllowance lists the header field codes each PDU type may carry on
// the wire（契约 §3.5 表 1–7——越表头 validator 显式拒，builder 侧同表
// 兜底不渲染）。首三头（8C/98/8D）与 Content-Type（84 收尾）不在此列。
var pduFieldAllowance = map[byte]map[byte]bool{
	pduSendReq: {
		fDate: true, fFrom: true, fTo: true, fCc: true, fBcc: true, fSubject: true,
		fMessageClass: true, fExpiry: true, fDeliveryTime: true, fPriority: true,
		fSenderVisibility: true, fDeliveryReport: true, fReadReply: true,
	},
	pduSendConf: {
		fResponseStatus: true, fResponseText: true, fMessageID: true,
	},
	pduNotifInd: {
		fFrom: true, fSubject: true, fMessageClass: true, fMessageSize: true,
		fExpiry: true, fContentLocation: true,
	},
	pduNotifyRespInd: {fStatus: true, fReportAllowed: true},
	pduRetrieveConf: {
		fDate: true, fMessageID: true, fFrom: true, fTo: true, fCc: true, fSubject: true,
		fMessageClass: true, fPriority: true, fDeliveryReport: true, fReadReply: true,
	},
	pduAckInd:      {fReportAllowed: true},
	pduDeliveryInd: {fMessageID: true, fTo: true, fDate: true, fStatus: true},
	pduReadRecInd:  {fMessageID: true, fReadStatus: true},
}

// buildPDU renders one MMS PDU（契约 §3.2 顺序规则：首三头 8C/98/8D 固定，
// Content-Type 恒最后；delivery-ind 无 Transaction-ID——第三字节即版本
// 字段码）。binding carries the resolved TID/MsgID（sessionTx 权威，planner）。
func buildPDU(cfg *core.MMSEConfig, ev *core.MMSEEvent, tx *txBinding) ([]byte, error) {
	version := cfg.MMSVersion
	if version == "" {
		version = "1.2"
	}
	vw, err := versionWire(version)
	if err != nil {
		return nil, err
	}
	pt := kindShape[ev.Kind].pt

	var b []byte
	b = append(b, fMessageType, pt)
	if pt != pduDeliveryInd { // delivery-ind 无 Transaction-ID（表 7）
		b = append(b, fTransactionID)
		b = appendTextString(b, tx.TID)
	}
	b = append(b, fMMSVersion, vw)

	// 逐 kind 字段序（契约 §3.5 表 1–7 的字段序列，B6 夹具同序——字节钉死
	// 依赖此序；必选性由 validator 执法，builder 忠实渲染；Message-ID 以
	// 解析值为准 tx.MsgID，无分配语义的 kind 被 sessionTx 置空不渲染空头）。
	appendSubject := func() {
		if ev.Subject != nil {
			b = append(b, fSubject)
			b = appendEncodedStringValue(b, ev.Subject.Text, ev.Subject.Charset)
		}
	}
	appendTime := func(code byte, t *core.MMSETime) {
		if t == nil {
			return
		}
		var body []byte
		if t.Absolute != nil {
			body = append(body, tokenAbsolute)
			body = appendLongInt(body, 4, uint64(*t.Absolute))
		} else if t.Relative != nil {
			body = append(body, tokenRelative)
			body = appendLongInt(body, 3, uint64(*t.Relative))
		}
		b = append(b, code)
		b = appendValueLength(b, len(body))
		b = append(b, body...)
	}
	appendCTAndBody := func() error {
		if ev.Content != nil {
			body, err := buildMultipartBody(ev.Content)
			if err != nil {
				return err
			}
			b = append(b, fContentType)
			b = append(b, buildMultipartCT(ev.Content)...)
			b = append(b, body...)
		} else {
			b = append(b, fContentType)
			b = append(b, mediaTextPlain) // 单媒体码最小形态
		}
		return nil
	}
	switch ev.Kind {
	case "send_req": // 表 1
		if ev.Date != nil {
			b = appendLongInt(append(b, fDate), 4, uint64(*ev.Date))
		}
		if ev.From != nil {
			b = appendFrom(b, ev.From)
		}
		for _, a := range ev.To {
			b = appendTextString(append(b, fTo), a)
		}
		for _, a := range ev.Cc {
			b = appendTextString(append(b, fCc), a)
		}
		for _, a := range ev.Bcc {
			b = appendTextString(append(b, fBcc), a)
		}
		appendSubject()
		if ev.MessageClass != "" {
			b = append(b, fMessageClass, enumClass[ev.MessageClass])
		}
		if ev.Priority != "" {
			b = append(b, fPriority, enumPriority[ev.Priority])
		}
		if ev.SenderVisibility != "" {
			b = append(b, fSenderVisibility, enumVisibility[ev.SenderVisibility])
		}
		if ev.DeliveryReport != nil {
			b = append(b, fDeliveryReport, yesNoByte(*ev.DeliveryReport))
		}
		if ev.ReadReply != nil {
			b = append(b, fReadReply, yesNoByte(*ev.ReadReply))
		}
		appendTime(fExpiry, ev.Expiry)
		appendTime(fDeliveryTime, ev.DeliveryTime)
		if err := appendCTAndBody(); err != nil {
			return nil, err
		}
	case "send_conf": // 表 2：ResponseStatus → ResponseText → Message-ID 收尾
		if ev.ResponseStatus != "" {
			b = append(b, fResponseStatus, enumResponseStatus[ev.ResponseStatus])
		}
		if ev.ResponseText != "" {
			b = appendEncodedStringValue(append(b, fResponseText), ev.ResponseText, 0)
		}
		if tx.MsgID != "" {
			b = appendTextString(append(b, fMessageID), tx.MsgID)
		}
	case "notification_ind": // 表 3：From?→Subject?→class→size→expiry→location
		if ev.From != nil {
			b = appendFrom(b, ev.From)
		}
		appendSubject()
		if ev.MessageClass != "" {
			b = append(b, fMessageClass, enumClass[ev.MessageClass])
		}
		if ev.MessageSize != nil {
			b = appendLongInt(append(b, fMessageSize), 3, uint64(*ev.MessageSize))
		}
		appendTime(fExpiry, ev.Expiry)
		if ev.ContentLocation != "" {
			b = appendTextString(append(b, fContentLocation), ev.ContentLocation)
		}
	case "notifyresp_ind": // 表 4：Status → Report-Allowed
		if ev.Status != "" {
			b = append(b, fStatus, enumStatus[ev.Status])
		}
		if ev.ReportAllowed != nil {
			b = append(b, fReportAllowed, yesNoByte(*ev.ReportAllowed))
		}
	case "retrieve_conf": // 表 5：Date→MsgID→From?→To→Subject→class→priority→DR→RR→CT
		if ev.Date != nil {
			b = appendLongInt(append(b, fDate), 4, uint64(*ev.Date))
		}
		if tx.MsgID != "" {
			b = appendTextString(append(b, fMessageID), tx.MsgID)
		}
		if ev.From != nil {
			b = appendFrom(b, ev.From)
		}
		for _, a := range ev.To {
			b = appendTextString(append(b, fTo), a)
		}
		appendSubject()
		if ev.MessageClass != "" {
			b = append(b, fMessageClass, enumClass[ev.MessageClass])
		}
		if ev.Priority != "" {
			b = append(b, fPriority, enumPriority[ev.Priority])
		}
		if ev.DeliveryReport != nil {
			b = append(b, fDeliveryReport, yesNoByte(*ev.DeliveryReport))
		}
		if ev.ReadReply != nil {
			b = append(b, fReadReply, yesNoByte(*ev.ReadReply))
		}
		if err := appendCTAndBody(); err != nil {
			return nil, err
		}
	case "acknowledge_ind": // 表 6：Report-Allowed
		if ev.ReportAllowed != nil {
			b = append(b, fReportAllowed, yesNoByte(*ev.ReportAllowed))
		}
	case "delivery_ind": // 表 7（无 Transaction-ID）：MsgID→To→Date→Status
		if tx.MsgID != "" {
			b = appendTextString(append(b, fMessageID), tx.MsgID)
		}
		for _, a := range ev.To {
			b = appendTextString(append(b, fTo), a)
		}
		if ev.Date != nil {
			b = appendLongInt(append(b, fDate), 4, uint64(*ev.Date))
		}
		if ev.Status != "" {
			b = append(b, fStatus, enumStatus[ev.Status])
		}
	case "read_rec_ind": // 表 7：MsgID→Read-Status
		if tx.MsgID != "" {
			b = appendTextString(append(b, fMessageID), tx.MsgID)
		}
		if ev.ReadStatus != "" {
			b = append(b, fReadStatus, enumReadStatus[ev.ReadStatus])
		}
	}
	return b, nil
}

// buildHTTPRequest renders a complete HTTP/1.1 request frame（契约 §5 自动
// 派生①：请求行/Host/Content-Type/Content-Length 由引擎补齐；GET 无 body 时
// 不发送 CT/CL；Connection 头恒不发送——HTTP/1.1 持久连接缺省，RFC 7230
// §6.3，用例 #24 的"无 Connection: close"断言自然满足）。hdrs 为事件级
// 覆盖（同名替换、异名追加；偏离派生值由 validator 拒）。
func buildHTTPRequest(method, uri, host string, hdrs map[string]string, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(uri)
	sb.WriteString(" HTTP/1.1\r\n")
	writeHeaders(&sb, host, hdrs, body)
	return []byte(sb.String())
}

// buildHTTPResponse renders a complete HTTP/1.1 response frame。
func buildHTTPResponse(status int, host string, hdrs map[string]string, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(strconv.Itoa(status))
	sb.WriteString(" OK\r\n")
	writeHeaders(&sb, host, hdrs, body)
	return []byte(sb.String())
}

// writeHeaders emits the fixed header set：Host；有体时 Content-Type（缺省
// mmsContentType）+ Content-Length（缺省 len(body)）；随后事件级头覆盖
// （同名已在固定集消费的跳过，其余按追加渲染——map 序不影响确定性的事件级
// 覆盖面因覆盖键固定）。
func writeHeaders(sb *strings.Builder, host string, hdrs map[string]string, body []byte) {
	if host != "" {
		sb.WriteString("Host: ")
		sb.WriteString(host)
		sb.WriteString("\r\n")
	}
	if body != nil {
		ct := mmsContentType
		if hdrs != nil {
			if v, ok := hdrs["Content-Type"]; ok {
				ct = v
			}
		}
		sb.WriteString("Content-Type: ")
		sb.WriteString(ct)
		sb.WriteString("\r\n")
		if hdrs != nil {
			if v, ok := hdrs["Content-Length"]; ok {
				sb.WriteString("Content-Length: ")
				sb.WriteString(v)
				sb.WriteString("\r\n")
			} else {
				writeCL(sb, len(body))
			}
		} else {
			writeCL(sb, len(body))
		}
	}
	if hdrs != nil {
		for k, v := range hdrs {
			switch k {
			case "Content-Type", "Content-Length", "Host":
				continue
			}
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("\r\n")
	sb.Write(body)
}

func writeCL(sb *strings.Builder, n int) {
	sb.WriteString("Content-Length: ")
	sb.WriteString(strconv.Itoa(n))
	sb.WriteString("\r\n")
}
