package pcapparser

import "strings"

// L7Detail typed 流级结构（D-PARSE-1 裁定2：单列 typed JSON，shape 按协议族
// 一枚举；L7Metadata 双写保留兼容）。所有键 snake_case（对齐 tshark -T fields
// 词汇）。detail_version 随 shape 演进递增。
const (
	L7DetailVersion = "1"
	// MaxL7Messages 单流消息累积上限（裁定4：有界遍历，超出置
	// messages_truncated，计数不受限）。
	MaxL7Messages = 256
	// maxTitleScan 扫 html title 的 body 前缀上限。
	maxTitleScan = 64 << 10
)

// L7Detail is the typed per-protocol flow detail stored in FlowModel.L7Detail.
type L7Detail struct {
	DetailVersion     string      `json:"detail_version"`
	Type              string      `json:"type"`
	Messages          []L7Message `json:"messages,omitempty"`
	Pair              *L7Pair     `json:"pair,omitempty"`
	ParseError        string      `json:"parse_error,omitempty"`
	Truncated         bool        `json:"truncated,omitempty"`
	MessagesTruncated bool        `json:"messages_truncated,omitempty"`
	// 协议专有标量面（http: html_title；dns: 无——报文面全在 messages；
	// tls: version/negotiated_cipher/certs）
	Extra map[string]any `json:"extra,omitempty"`

	// 超上限后的 Kind 计数（裁定4：messages 有界 256 但配对计数不受限；
	// countKinds 合并两处）。非导出：不进 JSON。
	overflowReq, overflowResp int64
}

// L7Message is one parsed protocol message within the flow.
type L7Message struct {
	Dir     string         `json:"dir"`                // c2s|s2c
	Kind    string         `json:"kind"`               // request|response|query|response|message（协议语义）
	WireLen int            `json:"wire_len"`           // 线上字节（dns-tcp 含 2B 前缀口径？否——不含，前缀是分帧）
	Fields  map[string]any `json:"fields"`             // 协议 shape（snake_case）
}

// L7Pair is the transaction pairing aggregate (D-PARSE-1 §P3 配对键).
type L7Pair struct {
	Requests  int64  `json:"requests"`
	Responses int64  `json:"responses"`
	State     string `json:"state"` // paired|unmatched_request|unmatched_response|none
}

// pairState derives the pairing state from counters.
func pairState(req, resp int64) string {
	switch {
	case req > 0 && resp > 0:
		return "paired"
	case req > 0:
		return "unmatched_request"
	case resp > 0:
		return "unmatched_response"
	default:
		return "none"
	}
}

// appendMessage appends a message honoring the bounded cap; overflow Kind
// still counted（裁定4：计数不受限）.
func (d *L7Detail) appendMessage(m L7Message) {
	if len(d.Messages) >= MaxL7Messages {
		d.MessagesTruncated = true
		switch m.Kind {
		case "request", "query":
			d.overflowReq++
		case "response":
			d.overflowResp++
		}
		return
	}
	d.Messages = append(d.Messages, m)
}

// countKinds tallies request/response kinds (in-cap + overflow) into the Pair
// aggregate.
func (d *L7Detail) countKinds() {
	var req, resp int64
	for _, m := range d.Messages {
		switch m.Kind {
		case "request", "query":
			req++
		case "response":
			resp++
		}
	}
	req += d.overflowReq
	resp += d.overflowResp
	d.Pair = &L7Pair{Requests: req, Responses: resp, State: pairState(req, resp)}
}

// extractHTMLTitle scans the body prefix for <title>...</title> (WHATWG HTML
// §4.2.4); case-insensitive open tag, best-effort.
func extractHTMLTitle(body []byte) string {
	if len(body) > maxTitleScan {
		body = body[:maxTitleScan]
	}
	lower := strings.ToLower(string(body))
	open := "<title>"
	i := strings.Index(lower, open)
	if i < 0 {
		return ""
	}
	start := i + len(open)
	rest := lower[start:]
	close_ := strings.Index(rest, "</title>")
	if close_ < 0 {
		return ""
	}
	title := body[start : start+close_]
	return strings.TrimSpace(string(title))
}
