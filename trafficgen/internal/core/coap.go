package core

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

type ResponseBlockConfig struct {
	Payload []byte       `json:"payload,omitempty"`
	Block2  *BlockConfig `json:"block2,omitempty"`
}

type BlockConfig struct {
	Num  uint32 `json:"num,omitempty"`
	More bool   `json:"more,omitempty"`
	Size uint16 `json:"size,omitempty"`
}

type ObserveConfig struct {
	Sequence      uint32 `json:"sequence,omitempty"`
	Notifications int    `json:"notifications,omitempty"`
}

type CoAPRetransmitConfig struct {
	Count int `json:"count,omitempty"`
}

type ErrorResponseConfig struct {
	Code    string `json:"code,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}
