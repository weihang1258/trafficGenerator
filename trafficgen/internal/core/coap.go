package core

import (
	"encoding/json"
	"time"
)

// CoAPConfig describes a CoAP message exchange over UDP.
type CoAPConfig struct {
	Method                string                `json:"method,omitempty"`
	Path                  []string              `json:"path,omitempty"`
	Query                 []string              `json:"query,omitempty"`
	Payload               []byte                `json:"payload,omitempty"`
	ContentFormat         uint16                `json:"content_format,omitempty"`
	Accept                *uint16               `json:"accept,omitempty"`
	Confirmable           bool                  `json:"confirmable,omitempty"`
	Token                 []byte                `json:"token,omitempty"`
	TokenLength           uint8                 `json:"token_length,omitempty"`
	MessageID             uint16                `json:"message_id,omitempty"`
	Version               uint8                 `json:"version,omitempty"`
	Code                  uint8                 `json:"code,omitempty"`
	Response              *bool                 `json:"response,omitempty"`
	ResponseCode          string                `json:"response_code,omitempty"`
	ResponsePayload       []byte                `json:"response_payload,omitempty"`
	ResponseContentFormat uint16                `json:"response_content_format,omitempty"`
	ResponseBlocks        []ResponseBlockConfig `json:"response_blocks,omitempty"`
	Block1                *BlockConfig          `json:"block1,omitempty"`
	Block2                *BlockConfig          `json:"block2,omitempty"`
	// ResponseBlock2 carries the Block2 option on the *response* of a Block2
	// exchange (the request reads cfg.Block2). Per-block NUM/M/SZX come from a
	// response_blocks entry; the generator sets this per response it builds.
	ResponseBlock2        *BlockConfig          `json:"response_block2,omitempty"`
	Observe               *ObserveConfig        `json:"observe,omitempty"`
	Retransmit            *CoAPRetransmitConfig `json:"retransmit,omitempty"`
	ErrorCode             string                `json:"error_code,omitempty"`
	ErrorPayload          []byte                `json:"error_payload,omitempty"`
	ErrorResponses        []ErrorResponseConfig `json:"error_responses,omitempty"`
	URIMaxLength          uint32                `json:"uri_max_length,omitempty"`
	Tokens                []string              `json:"tokens,omitempty"`
	MessageIDs            []uint16              `json:"message_ids,omitempty"`
	SessionSrcIPs         []string              `json:"session_src_ips,omitempty"`
	SessionSrcPorts       []uint16              `json:"session_src_ports,omitempty"`
}

// ResponseBlockConfig is one chunk of a Block2 (response block) sequence.
// A response_blocks entry carries its own NUM/M/SZX (design 20-coap-design.md
// §5.2) — NOT a nested BlockConfig. Keeping the flat shape means the JSON
// "number"/"size_exp" fields unmarshal directly instead of being dropped.
type ResponseBlockConfig struct {
	Number  uint32 `json:"number,omitempty"`
	More    bool   `json:"more,omitempty"`
	SizeExp uint8  `json:"size_exp,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}

// BlockConfig is a Block1/Block2 option value (design §5.3). The option value
// is (Number<<4)|(More<<3)|SizeExp; block_size = 2^(SizeExp+4).
type BlockConfig struct {
	Number  uint32 `json:"number,omitempty"`
	More    bool   `json:"more,omitempty"`
	SizeExp uint8  `json:"size_exp,omitempty"`
}

// ObserveConfig drives the RFC 7641 observe registration + notifications.
type ObserveConfig struct {
	Register          bool     `json:"register,omitempty"`
	NotifyCount       uint32   `json:"notify_count,omitempty"`
	StartSequence     uint32   `json:"start_sequence,omitempty"`
	Confirmable       bool     `json:"confirmable,omitempty"`
	NotificationTypes []string `json:"notification_types,omitempty"`
}

// CoAPRetransmitConfig drives CON retransmission (RFC 7252 §4.2).
type CoAPRetransmitConfig struct {
	AckTimeout    Duration `json:"ack_timeout,omitempty"`
	RandomFactor  float64  `json:"random_factor,omitempty"`
	MaxRetransmit uint8    `json:"max_retransmit,omitempty"`
	ForceTimeout  bool     `json:"force_timeout,omitempty"`
}

// Duration is a time.Duration that accepts both a Go duration string ("2s",
// "500ms") and a bare numeric nanoseconds value in JSON. time.Duration itself
// fails on "2s" strings (it's an int64 alias), which would make the whole coap
// config unmarshal error out. The design's ack_timeout is authored as a string
// in cases/coap.json.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(time.Duration(n))
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// ErrorResponseConfig is one business error response (4.xx/5.xx) in a sequence.
type ErrorResponseConfig struct {
	Code    string   `json:"code,omitempty"`
	Path    []string `json:"path,omitempty"`
	Token   []byte   `json:"token,omitempty"`
	Payload []byte   `json:"payload,omitempty"`
}
