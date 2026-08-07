// Package a2a implements the A2A (Agent-to-Agent) protocol planner.
//
// A2A is Google's open protocol for agent-to-agent interoperability,
// built on HTTP/JSON-RPC 2.0 with SSE streaming support.
//
// This implementation follows spec v0.2.2+ with 7 core JSON-RPC methods:
//   - message/send
//   - message/stream
//   - tasks/get
//   - tasks/cancel
//   - tasks/resubscribe
//   - tasks/pushNotificationConfig/set
//   - tasks/pushNotificationConfig/get
//
// Plus Agent Card discovery via HTTP GET /.well-known/agent.json
package a2a

import (
	"encoding/json"
)

// A2AConfig describes a group of A2A traffic generation configurations.
type A2AConfig struct {
	BaseURL       string          `json:"baseUrl"`               // Agent's A2A service URL
	AgentCardPath string          `json:"agentCardPath"`         // Agent Card path, default /.well-known/agent.json
	Discover      bool            `json:"discover"`              // Whether to send GET Agent Card before first packet
	AgentCard     *A2AAgentCard   `json:"agentCard"`             // Agent Card content (used as response body when Discover=true)
	Tasks         []A2ATask       `json:"tasks"`                 // Task array (serialized on same TCP connection)
	Auth          A2AAuth         `json:"auth"`                  // Authentication config
	HTTP          A2AHTTP         `json:"http"`                  // HTTP layer config
	TCP           A2ATCP          `json:"tcp"`                   // TCP layer config
	FlowControl   *A2AFlowControl `json:"flowControl,omitempty"` // Flow control
}

// A2AAuth describes authentication configuration.
type A2AAuth struct {
	Scheme     string `json:"scheme"`     // none/bearer/basic/apikey/oauth2/openIdConnect, default none
	Token      string `json:"token"`      // Bearer/oauth2 token
	Username   string `json:"username"`   // Basic auth username
	Password   string `json:"password"`   // Basic auth password
	APIKey     string `json:"apiKey"`     // API key value
	APIKeyName string `json:"apiKeyName"` // API key header/query param name, default X-API-Key
	APIKeyIn   string `json:"apiKeyIn"`   // header/query/cookie, default header
}

// A2AHTTP describes HTTP layer configuration.
type A2AHTTP struct {
	Version      string            `json:"version"`    // HTTP/1.1 (default)
	UserAgent    string            `json:"userAgent"`  // Default trafficgen-a2a/2.0
	Accept       string            `json:"accept"`     // Default application/json, text/event-stream
	Connection   string            `json:"connection"` // keep-alive/close
	ExtraHeaders map[string]string `json:"extraHeaders"`
}

// A2ATCP describes TCP layer configuration.
//
// Handshake 和 Termination 使用 *bool：
//   - nil（未设置）：默认 true，启用握手/挥手
//   - true（显式设置）：启用
//   - false（显式设置）：禁止
type A2ATCP struct {
	Handshake   *bool  `json:"handshake,omitempty"`   // TCP 3-way handshake, default true
	Termination *bool  `json:"termination,omitempty"` // TCP 4-way teardown, default true
	InitialSeq  uint32 `json:"initialSeq"`            // ISN, random when 0
	MSS         uint16 `json:"mss"`                   // Default 1460
	ACKPolicy   string `json:"ackPolicy"`             // lazy/immediate, default immediate
}

// A2AFlowControl describes flow control configuration.
type A2AFlowControl struct {
	BPS        string `json:"bps"`        // Bitrate limit
	Concurrent int    `json:"concurrent"` // Concurrent task count
}

// A2AAgentCard corresponds to spec AgentCard (v0.2.2+).
type A2AAgentCard struct {
	Name                              string                       `json:"name"`            // Required
	Description                       string                       `json:"description"`     // Required
	URL                               string                       `json:"url"`             // Required
	Version                           string                       `json:"version"`         // Required
	ProtocolVersion                   string                       `json:"protocolVersion"` // Required (v0.2.5+), default "0.3.0"
	Provider                          *A2AAgentProvider            `json:"provider,omitempty"`
	IconURL                           string                       `json:"iconUrl,omitempty"`
	DocumentationURL                  string                       `json:"documentationUrl,omitempty"`
	Capabilities                      *A2AAgentCapabilities        `json:"capabilities"`              // Required
	SecuritySchemes                   map[string]A2ASecurityScheme `json:"securitySchemes,omitempty"` // OpenAPI style map
	Security                          []map[string][]string        `json:"security,omitempty"`        // Security requirements array
	DefaultInputModes                 []string                     `json:"defaultInputModes"`         // Required
	DefaultOutputModes                []string                     `json:"defaultOutputModes"`        // Required
	Skills                            []A2AAgentSkill              `json:"skills"`                    // Required (at least 1 for action agents)
	SupportsAuthenticatedExtendedCard bool                         `json:"supportsAuthenticatedExtendedCard,omitempty"`
	AdditionalInterfaces              []A2AAgentInterface          `json:"additionalInterfaces,omitempty"` // v0.2.5+
	PreferredTransport                string                       `json:"preferredTransport,omitempty"`   // v0.2.5+
	Signatures                        []A2AAgentCardSignature      `json:"signatures,omitempty"`           // v0.3.0, reserved for v2
}

// A2AAgentInterface describes an additional interface (v0.2.5+).
type A2AAgentInterface struct {
	URL       string `json:"url"`       // Required
	Transport string `json:"transport"` // Required
}

// A2AAgentCardSignature corresponds to spec AgentCardSignature (v0.3.0, JWS signature).
type A2AAgentCardSignature map[string]any

// A2AAgentProvider describes the service provider.
type A2AAgentProvider struct {
	Organization string `json:"organization"` // Required
	URL          string `json:"url"`          // Required
}

// A2AAgentCapabilities describes agent capabilities.
type A2AAgentCapabilities struct {
	Streaming              bool                `json:"streaming"`
	PushNotifications      bool                `json:"pushNotifications"`
	StateTransitionHistory bool                `json:"stateTransitionHistory"`
	Extensions             []A2AAgentExtension `json:"extensions,omitempty"`
}

// A2AAgentExtension describes an extension.
type A2AAgentExtension struct {
	URI         string         `json:"uri"` // Required
	Required    bool           `json:"required,omitempty"`
	Description string         `json:"description,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}

// A2AAgentSkill describes an agent skill.
type A2AAgentSkill struct {
	ID          string   `json:"id"`          // Required
	Name        string   `json:"name"`        // Required
	Description string   `json:"description"` // Required
	Tags        []string `json:"tags"`        // Required
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// A2ASecurityScheme corresponds to spec SecurityScheme (v0.3.0 anyOf 5 types).
// Uses map[string]any to accommodate all subtypes.
type A2ASecurityScheme map[string]any

// A2ATask describes a single A2A task request and response configuration.
type A2ATask struct {
	Method         string                       `json:"method"`              // See method table, default message/send
	RequestID      json.RawMessage              `json:"requestId,omitempty"` // JSON-RPC envelope id（客户端指定，N2 修复：omitempty 让未设置时不输出）
	Message        A2AMessage                   `json:"message"`             // params.message for message/send and message/stream
	Configuration  *A2AMessageSendConfiguration `json:"configuration,omitempty"`
	ParamsMetadata map[string]any               `json:"paramsMetadata,omitempty"`

	// TaskID is used for tasks/get, tasks/cancel, tasks/resubscribe, tasks/pushNotificationConfig/*
	// Not used in message/send (task id is server-assigned).
	TaskID        string `json:"taskId,omitempty"`
	HistoryLength int    `json:"historyLength,omitempty"`

	// PushNotificationConfig for tasks/pushNotificationConfig/set
	PushNotificationConfig *A2APushNotificationConfig `json:"pushNotificationConfig,omitempty"`

	// Response configuration
	Response  A2ATaskResponse `json:"response"`
	Streaming bool            `json:"streaming"`           // true=message/stream or tasks/resubscribe
	SSEEvents []A2ASSEEvent   `json:"sseEvents,omitempty"` // SSE event sequence for streaming
}

// A2AMessageSendConfiguration describes message send configuration.
type A2AMessageSendConfiguration struct {
	AcceptedOutputModes    []string                   `json:"acceptedOutputModes"`
	Blocking               *bool                      `json:"blocking,omitempty"`
	HistoryLength          *int                       `json:"historyLength,omitempty"`
	PushNotificationConfig *A2APushNotificationConfig `json:"pushNotificationConfig,omitempty"`
}

// A2ATaskResponse describes server response (planner generates downstream packets based on this).
type A2ATaskResponse struct {
	Result     json.RawMessage `json:"result,omitempty"` // 序列化为 Task/Message/TaskPushNotificationConfig；null 视为未设置
	Error      *A2AError       `json:"error,omitempty"`
	StatusCode int             `json:"statusCode"` // HTTP status code, default 200
}

// A2AError describes a JSON-RPC error.
type A2AError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// A2AMessage describes a message.
type A2AMessage struct {
	Role             string         `json:"role"`                // user/agent
	Parts            []A2APart      `json:"parts"`               // Content array (at least 1)
	MessageID        string         `json:"messageId"`           // Message identifier
	TaskID           string         `json:"taskId,omitempty"`    // Associated task id
	ContextID        string         `json:"contextId,omitempty"` // Context identifier for session association
	ReferenceTaskIDs []string       `json:"referenceTaskIds,omitempty"`
	Extensions       []string       `json:"extensions,omitempty"`
	Kind             string         `json:"kind"` // Always "message"
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// A2APart is a union type. Kind determines which content field is valid.
type A2APart struct {
	Kind     string         `json:"kind"`           // text/data/file (only these 3)
	Text     string         `json:"text,omitempty"` // Valid when Kind=text
	Data     map[string]any `json:"data,omitempty"` // Valid when Kind=data
	File     *A2AFile       `json:"file,omitempty"` // Valid when Kind=file
	Metadata map[string]any `json:"metadata,omitempty"`
}

// A2AFile describes file content (FileWithBytes or FileWithUri).
type A2AFile struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Bytes    string `json:"bytes,omitempty"` // base64, valid for FileWithBytes
	URI      string `json:"uri,omitempty"`   // Valid for FileWithUri
}

// A2ASSEEvent describes an SSE event (data: line JSON payload).
type A2ASSEEvent struct {
	Kind           string                      `json:"kind"` // task/message/status-update/artifact-update
	Task           *A2ATaskObject              `json:"task,omitempty"`
	Message        *A2AMessage                 `json:"message,omitempty"`
	StatusUpdate   *A2ATaskStatusUpdateEvent   `json:"statusUpdate,omitempty"`
	ArtifactUpdate *A2ATaskArtifactUpdateEvent `json:"artifactUpdate,omitempty"`
}

// A2ATaskObject corresponds to Task object in spec.
type A2ATaskObject struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId"`
	Status    A2ATaskStatus  `json:"status"`
	Artifacts []A2AArtifact  `json:"artifacts,omitempty"`
	History   []A2AMessage   `json:"history,omitempty"`
	Kind      string         `json:"kind"` // Always "task"
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2ATaskStatus describes task status.
type A2ATaskStatus struct {
	State     string      `json:"state"` // 9 enum values
	Message   *A2AMessage `json:"message,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

// A2AArtifact describes a task artifact.
type A2AArtifact struct {
	ArtifactID  string         `json:"artifactId"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Parts       []A2APart      `json:"parts"`
	Extensions  []string       `json:"extensions,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// A2ATaskStatusUpdateEvent describes a status update event in SSE stream.
type A2ATaskStatusUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId"`
	Kind      string         `json:"kind"` // Always "status-update"
	Status    A2ATaskStatus  `json:"status"`
	Final     bool           `json:"final"` // Required by spec, must output even when false
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2ATaskArtifactUpdateEvent describes an artifact update event in SSE stream.
type A2ATaskArtifactUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId"`
	Kind      string         `json:"kind"` // Always "artifact-update"
	Artifact  A2AArtifact    `json:"artifact"`
	Append    bool           `json:"append,omitempty"`
	LastChunk bool           `json:"lastChunk,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2APushNotificationConfig describes push notification configuration.
type A2APushNotificationConfig struct {
	URL            string                   `json:"url"`          // Required
	ID             string                   `json:"id,omitempty"` // v0.2.2 server-created; v0.3.0+ client-set
	Token          string                   `json:"token,omitempty"`
	Authentication *A2APushNotificationAuth `json:"authentication,omitempty"`
}

// A2APushNotificationAuth corresponds to spec PushNotificationAuthenticationInfo.
type A2APushNotificationAuth struct {
	Schemes     []string `json:"schemes"` // e.g., ["Bearer"], spec examples use uppercase
	Credentials string   `json:"credentials,omitempty"`
}

// TaskState constants - 9 enum values per spec v0.2.2+
const (
	TaskStateSubmitted     = "submitted"
	TaskStateWorking       = "working"
	TaskStateInputRequired = "input-required"
	TaskStateAuthRequired  = "auth-required"
	TaskStateCompleted     = "completed"
	TaskStateCanceled      = "canceled"
	TaskStateFailed        = "failed"
	TaskStateRejected      = "rejected"
	TaskStateUnknown       = "unknown"
)

// JSON-RPC error codes per spec
const (
	JSONRPCParseError                    = -32700
	JSONRPCInvalidRequest                = -32600
	JSONRPCMethodNotFound                = -32601
	JSONRPCInvalidParams                 = -32602
	JSONRPCInternalError                 = -32603
	JSONRPCTaskNotFound                  = -32001
	JSONRPCTaskNotCancelable             = -32002
	JSONRPCPushNotSupported              = -32003
	JSONRPCUnsupportedOperation          = -32004
	JSONRPCContentTypeNotSupported       = -32005
	JSONRPCInvalidAgentResponse          = -32006
	JSONRPCAuthExtendedCardNotConfigured = -32007
)

// Method names per spec v0.2.2+
const (
	MethodMessageSend                    = "message/send"
	MethodMessageStream                  = "message/stream"
	MethodTasksGet                       = "tasks/get"
	MethodTasksCancel                    = "tasks/cancel"
	MethodTasksResubscribe               = "tasks/resubscribe"
	MethodTasksPushNotificationConfigSet = "tasks/pushNotificationConfig/set"
	MethodTasksPushNotificationConfigGet = "tasks/pushNotificationConfig/get"
)

// Default values
const (
	DefaultAgentCardPath      = "/.well-known/agent.json"
	DefaultProtocolVersion    = "0.3.0"
	DefaultUserAgent          = "trafficgen-a2a/2.0"
	DefaultAccept             = "application/json, text/event-stream"
	DefaultConnection         = "keep-alive"
	DefaultAuthScheme         = "none"
	DefaultAPIKeyName         = "X-API-Key"
	DefaultAPIKeyIn           = "header"
	DefaultHTTPVersion        = "HTTP/1.1"
	DefaultMethod             = "message/send"
	DefaultMessageRole        = "user"
	DefaultMessageKind        = "message"
	DefaultTaskKind           = "task"
	DefaultStatusUpdateKind   = "status-update"
	DefaultArtifactUpdateKind = "artifact-update"
	DefaultMSS                = 1460
	DefaultTTL                = 64
)

// Valid methods set
var ValidMethods = map[string]bool{
	MethodMessageSend:                    true,
	MethodMessageStream:                  true,
	MethodTasksGet:                       true,
	MethodTasksCancel:                    true,
	MethodTasksResubscribe:               true,
	MethodTasksPushNotificationConfigSet: true,
	MethodTasksPushNotificationConfigGet: true,
}

// Valid task states set
var ValidTaskStates = map[string]bool{
	TaskStateSubmitted:     true,
	TaskStateWorking:       true,
	TaskStateInputRequired: true,
	TaskStateAuthRequired:  true,
	TaskStateCompleted:     true,
	TaskStateCanceled:      true,
	TaskStateFailed:        true,
	TaskStateRejected:      true,
	TaskStateUnknown:       true,
}

// validTaskTransitions encodes the legal state transitions in design doc §4.2.
// Only transitions listed here are legal, plus "any non-terminal -> unknown"
// (abnormal: taskId expired/invalid). Terminal states and unknown are immutable.
var validTaskTransitions = map[string]map[string]bool{
	TaskStateSubmitted: {
		TaskStateWorking:      true,
		TaskStateCanceled:     true,
		TaskStateFailed:       true,
		TaskStateRejected:     true,
		TaskStateAuthRequired: true,
	},
	TaskStateWorking: {
		TaskStateCompleted:     true,
		TaskStateFailed:        true,
		TaskStateCanceled:      true,
		TaskStateInputRequired: true,
		TaskStateAuthRequired:  true,
	},
	TaskStateInputRequired: {
		TaskStateWorking:  true,
		TaskStateCanceled: true,
		TaskStateFailed:   true,
	},
	TaskStateAuthRequired: {
		TaskStateWorking:  true,
		TaskStateCanceled: true,
		TaskStateFailed:   true,
	},
}

// Streaming methods set
var StreamingMethods = map[string]bool{
	MethodMessageStream:    true,
	MethodTasksResubscribe: true,
}

// Sync methods set (non-streaming)
var SyncMethods = map[string]bool{
	MethodMessageSend:                    true,
	MethodTasksGet:                       true,
	MethodTasksCancel:                    true,
	MethodTasksPushNotificationConfigSet: true,
	MethodTasksPushNotificationConfigGet: true,
}
